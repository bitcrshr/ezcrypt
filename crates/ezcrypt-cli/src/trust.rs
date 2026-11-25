//! Installer for `ezcrypt trust`: makes sshd trust the phone's user CA.
//!
//! Runs as root and edits `/etc/ssh`, so every change is snapshotted first and
//! restored exactly if anything fails. All paths are joined under `root`
//! (`/` in production) so the logic is testable against a temp directory.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use ssh_key::{Algorithm, PublicKey};

const KEY_FILE: &str = "/etc/ssh/ezcrypt/trusted_user_ca_keys";
const DROPIN_FILE: &str = "/etc/ssh/sshd_config.d/50-ezcrypt.conf";
const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const INCLUDE_LINE: &str = "Include /etc/ssh/sshd_config.d/*.conf";

pub trait Sshd {
    /// `sshd -t`
    fn test(&self) -> Result<()>;
    /// `sshd -T` value of TrustedUserCAKeys; `none` becomes `None`.
    fn effective_trusted_user_ca_keys(&self) -> Result<Option<String>>;
    fn reload(&self) -> Result<()>;
}

pub struct SystemSshd;

impl SystemSshd {
    fn run_sshd(args: &[&str]) -> Result<std::process::Output> {
        let mut last = None;
        for bin in ["sshd", "/usr/sbin/sshd"] {
            match Command::new(bin).args(args).output() {
                Ok(o) => return Ok(o),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => last = Some(e),
                Err(e) => return Err(anyhow!(e).context(format!("running {bin}"))),
            }
        }
        Err(anyhow!(last.expect("two candidates tried")).context("could not find sshd"))
    }
}

impl Sshd for SystemSshd {
    fn test(&self) -> Result<()> {
        let out = Self::run_sshd(&["-t"])?;
        if !out.status.success() {
            bail!(
                "sshd rejected the new configuration: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn effective_trusted_user_ca_keys(&self) -> Result<Option<String>> {
        let out = Self::run_sshd(&["-T"])?;
        if !out.status.success() {
            bail!(
                "sshd -T failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(parse_effective(&String::from_utf8_lossy(&out.stdout)))
    }

    fn reload(&self) -> Result<()> {
        let succeeded = |program: &str, args: &[&str]| {
            Command::new(program)
                .args(args)
                .stdin(std::process::Stdio::null())
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        if succeeded("systemctl", &["reload", "ssh"]) || succeeded("systemctl", &["reload", "sshd"])
        {
            return Ok(());
        }
        if let Ok(pid) = fs::read_to_string("/run/sshd.pid") {
            let pid = pid.trim();
            if !pid.is_empty()
                && pid.bytes().all(|b| b.is_ascii_digit())
                && succeeded("kill", &["-HUP", pid])
            {
                return Ok(());
            }
        }
        bail!(
            "could not reload sshd (tried systemctl reload ssh/sshd and SIGHUP via /run/sshd.pid)"
        )
    }
}

fn parse_effective(output: &str) -> Option<String> {
    for line in output.lines() {
        let Some((k, v)) = line.trim().split_once(char::is_whitespace) else {
            continue;
        };
        if k.eq_ignore_ascii_case("trustedusercakeys") {
            let v = v.trim();
            return if v.is_empty() || v.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(v.to_string())
            };
        }
    }
    None
}

#[derive(Debug)]
pub struct Report {
    pub key_file: PathBuf,
    pub already_present: bool,
    pub added_include: bool,
}

fn under(root: &Path, abs: &str) -> PathBuf {
    match abs.strip_prefix('/') {
        Some(rel) => root.join(rel),
        // sshd resolves relative paths against /etc/ssh.
        None => root.join("etc/ssh").join(abs),
    }
}

/// Atomic write: temp file in the same directory, then rename. Keeps the mode
/// of an existing file; new files are 0644.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("path has no parent directory")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o644);
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn read_opt(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!(e).context(format!("reading {}", path.display()))),
    }
}

/// Records originals before the first change to each file and the directories
/// this run created, so everything can be put back exactly.
#[derive(Default)]
struct Txn {
    snaps: Vec<(PathBuf, Option<Vec<u8>>)>,
    dirs: Vec<PathBuf>,
}

impl Txn {
    fn snapshot(&mut self, path: &Path) -> Result<()> {
        if !self.snaps.iter().any(|(p, _)| p == path) {
            self.snaps.push((path.to_path_buf(), read_opt(path)?));
        }
        Ok(())
    }

    fn write(&mut self, path: &Path, bytes: &[u8]) -> Result<()> {
        self.snapshot(path)?;
        write_atomic(path, bytes)
    }

    fn ensure_dir(&mut self, dir: &Path) -> Result<()> {
        let mut missing = vec![];
        let mut cur = dir;
        while !cur.exists() {
            missing.push(cur.to_path_buf());
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
        for d in missing.into_iter().rev() {
            fs::create_dir(&d).with_context(|| format!("creating {}", d.display()))?;
            self.dirs.push(d.clone());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&d, fs::Permissions::from_mode(0o755))?;
            }
        }
        Ok(())
    }

    /// Best effort: attempts every restore and returns the failures.
    fn restore(&mut self) -> Vec<String> {
        let mut failures = vec![];
        for (path, orig) in self.snaps.drain(..).rev() {
            let r = match orig {
                Some(bytes) => write_atomic(&path, &bytes),
                None => match fs::remove_file(&path) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                    _ => Ok(()),
                },
            };
            if let Err(e) = r {
                failures.push(format!("{}: {e:#}", path.display()));
            }
        }
        for dir in self.dirs.drain(..).rev() {
            match fs::remove_dir(&dir) {
                Ok(()) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(e) => failures.push(format!("{}: {e}", dir.display())),
            }
        }
        failures
    }
}

fn parse_ca(ca_line: &str) -> Result<PublicKey> {
    let key = ezcrypt_core::certificate::parse_public(ca_line)
        .map_err(|e| anyhow!("invalid CA public key: {e}"))?;
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => Ok(key),
        _ => bail!("the CA key must be Ed25519 or ECDSA"),
    }
}

fn contains_key(bytes: &[u8], key: &PublicKey) -> bool {
    String::from_utf8_lossy(bytes).lines().any(|l| {
        let l = l.trim();
        !l.is_empty()
            && !l.starts_with('#')
            && PublicKey::from_openssh(l).is_ok_and(|k| k.key_data() == key.key_data())
    })
}

/// Appends `line` unless the key is already in the file. Returns whether it added.
fn append_key(txn: &mut Txn, path: &Path, line: &str, key: &PublicKey) -> Result<bool> {
    let mut out = read_opt(path)?.unwrap_or_default();
    if contains_key(&out, key) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        txn.ensure_dir(parent)?;
    }
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
    txn.write(path, &out)?;
    Ok(true)
}

fn has_include(config: &str) -> bool {
    config.lines().any(|l| {
        let mut toks = l.split_whitespace();
        toks.next()
            .is_some_and(|t| !t.starts_with('#') && t.eq_ignore_ascii_case("Include"))
            && toks.any(|a| {
                let a = a.trim_matches('"');
                a == "/etc/ssh/sshd_config.d/*.conf" || a == "sshd_config.d/*.conf"
            })
    })
}

pub fn install(
    root: &Path,
    ca_line: &str,
    ca_name: &str,
    use_existing: bool,
    sshd: &dyn Sshd,
) -> Result<Report> {
    let mut key = parse_ca(ca_line)?;
    key.set_comment(ca_name);
    let line = key.to_openssh().context("formatting CA key")?;
    let config_path = under(root, SSHD_CONFIG);
    if !config_path.is_file() {
        bail!("{SSHD_CONFIG} not found; is OpenSSH server installed?");
    }

    let mut txn = Txn::default();
    match run(&mut txn, root, &key, &line, use_existing, sshd) {
        Ok(r) => Ok(r),
        Err(e) => {
            let failures = txn.restore();
            if failures.is_empty() {
                Err(e)
            } else {
                Err(e.context(format!(
                    "rollback was incomplete, check these files: {}",
                    failures.join("; ")
                )))
            }
        }
    }
}

fn run(
    txn: &mut Txn,
    root: &Path,
    key: &PublicKey,
    line: &str,
    use_existing: bool,
    sshd: &dyn Sshd,
) -> Result<Report> {
    let key_path = under(root, KEY_FILE);
    let config_path = under(root, SSHD_CONFIG);

    // Read the effective setting before writing anything: an existing
    // TrustedUserCAKeys elsewhere would otherwise be overridden by our drop-in.
    let pre = sshd.effective_trusted_user_ca_keys()?;
    if let Some(existing) = pre.as_deref().filter(|p| *p != KEY_FILE) {
        if !use_existing {
            bail!("{}", shadow_message(Some(existing)));
        }
        return append_existing(txn, root, existing, line, key, sshd);
    }

    let config = fs::read(&config_path).with_context(|| format!("reading {SSHD_CONFIG}"))?;
    let added_include = !has_include(&String::from_utf8_lossy(&config));
    if added_include
        && fs::symlink_metadata(&config_path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    {
        bail!(
            "{SSHD_CONFIG} is a symlink, so it is managed elsewhere (for example NixOS). \
             Add `{INCLUDE_LINE}` to it there and rerun."
        );
    }

    let added_key = append_key(txn, &key_path, line, key)?;

    let dropin = format!("TrustedUserCAKeys {KEY_FILE}\n");
    let dropin_path = under(root, DROPIN_FILE);
    if read_opt(&dropin_path)?.as_deref() != Some(dropin.as_bytes()) {
        txn.ensure_dir(dropin_path.parent().context("no parent")?)?;
        txn.write(&dropin_path, dropin.as_bytes())?;
    }

    if added_include {
        let mut new = format!("{INCLUDE_LINE}\n").into_bytes();
        new.extend_from_slice(&config);
        txn.write(&config_path, &new)?;
    }

    sshd.test().context("validating sshd configuration")?;

    let effective = sshd.effective_trusted_user_ca_keys()?;
    if effective.as_deref() == Some(KEY_FILE) {
        sshd.reload()?;
        return Ok(Report {
            key_file: key_path,
            already_present: !added_key,
            added_include,
        });
    }

    let existing = match (&effective, use_existing) {
        (Some(p), true) => p.clone(),
        _ => bail!("{}", shadow_message(effective.as_deref())),
    };

    // Put back our key file, drop-in and Include, then use the existing file.
    let failures = txn.restore();
    if !failures.is_empty() {
        bail!("could not undo changes: {}", failures.join("; "));
    }
    append_existing(txn, root, &existing, line, key, sshd)
}

fn shadow_message(effective: Option<&str>) -> String {
    format!(
        "TrustedUserCAKeys is already set to {}. Rerun with --use-existing to add this CA there.",
        effective.unwrap_or("none")
    )
}

fn append_existing(
    txn: &mut Txn,
    root: &Path,
    existing: &str,
    line: &str,
    key: &PublicKey,
    sshd: &dyn Sshd,
) -> Result<Report> {
    let target = under(root, existing);
    let added = append_key(txn, &target, line, key)?;
    sshd.test().context("validating sshd configuration")?;
    sshd.reload()?;
    Ok(Report {
        key_file: target,
        already_present: !added,
        added_include: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use ssh_key::{Algorithm, PrivateKey};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    const OURS: &str = "/etc/ssh/ezcrypt/trusted_user_ca_keys";
    const SSHD_CONFIG: &str =
        "# sshd\nPort 22\nPermitRootLogin no\nSubsystem sftp /usr/lib/sftp-server\n";

    struct FakeSshd {
        calls: RefCell<Vec<&'static str>>,
        effective: Option<String>,
        test_fails: Cell<bool>,
        reload_fails: bool,
    }

    impl FakeSshd {
        fn new(effective: Option<&str>) -> Self {
            FakeSshd {
                calls: RefCell::new(vec![]),
                effective: effective.map(String::from),
                test_fails: Cell::new(false),
                reload_fails: false,
            }
        }
        fn ours() -> Self {
            Self::new(Some(OURS))
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl Sshd for FakeSshd {
        fn test(&self) -> anyhow::Result<()> {
            self.calls.borrow_mut().push("test");
            if self.test_fails.get() {
                anyhow::bail!("sshd -t failed");
            }
            Ok(())
        }
        fn effective_trusted_user_ca_keys(&self) -> anyhow::Result<Option<String>> {
            self.calls.borrow_mut().push("effective");
            Ok(self.effective.clone())
        }
        fn reload(&self) -> anyhow::Result<()> {
            self.calls.borrow_mut().push("reload");
            if self.reload_fails {
                anyhow::bail!("reload failed");
            }
            Ok(())
        }
    }

    fn ca_line(comment: &str) -> String {
        let k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut p = k.public_key().clone();
        p.set_comment(comment);
        p.to_openssh().unwrap()
    }

    fn setup(config: &str) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc/ssh")).unwrap();
        std::fs::write(d.path().join("etc/ssh/sshd_config"), config).unwrap();
        d
    }

    fn tree(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                let rel = p.strip_prefix(base).unwrap().display().to_string();
                if p.is_dir() {
                    out.insert(rel, None);
                    walk(base, &p, out);
                } else {
                    out.insert(rel, Some(std::fs::read(&p).unwrap()));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    fn read(root: &Path, p: &str) -> String {
        std::fs::read_to_string(root.join(p)).unwrap()
    }

    const KEYFILE: &str = "etc/ssh/ezcrypt/trusted_user_ca_keys";

    #[test]
    fn fresh_install_writes_key_dropin_and_reloads() {
        let d = setup(SSHD_CONFIG);
        let sshd = FakeSshd::ours();
        let line = ca_line("some comment");
        let r = install(d.path(), &line, "my-ca", false, &sshd).unwrap();
        assert!(!r.already_present);
        assert!(r.added_include);
        assert_eq!(r.key_file, d.path().join(KEYFILE));
        let keys = read(d.path(), KEYFILE);
        let expected = format!(
            "{} my-ca\n",
            line.splitn(3, ' ').take(2).collect::<Vec<_>>().join(" ")
        );
        assert_eq!(keys, expected);
        let dropin = read(d.path(), "etc/ssh/sshd_config.d/50-ezcrypt.conf");
        assert!(dropin.contains(&format!("TrustedUserCAKeys {OURS}")));
        let cfg = read(d.path(), "etc/ssh/sshd_config");
        assert_eq!(
            cfg,
            format!("Include /etc/ssh/sshd_config.d/*.conf\n{SSHD_CONFIG}")
        );
        assert_eq!(
            sshd.calls(),
            vec!["effective", "test", "effective", "reload"]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &str| {
                std::fs::metadata(d.path().join(p))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(KEYFILE), 0o644);
            assert_eq!(mode("etc/ssh/ezcrypt"), 0o755);
            assert_eq!(mode("etc/ssh/sshd_config.d"), 0o755);
        }
    }

    #[test]
    fn rerun_is_a_no_op() {
        let d = setup(SSHD_CONFIG);
        let line = ca_line("c");
        install(d.path(), &line, "my-ca", false, &FakeSshd::ours()).unwrap();
        let before = tree(d.path());
        let r = install(d.path(), &line, "other-name", false, &FakeSshd::ours()).unwrap();
        assert!(r.already_present);
        assert!(!r.added_include);
        assert_eq!(tree(d.path()), before);
    }

    #[test]
    fn second_ca_appends() {
        let d = setup(SSHD_CONFIG);
        let a = ca_line("");
        let b = ca_line("");
        install(d.path(), &a, "a", false, &FakeSshd::ours()).unwrap();
        let r = install(d.path(), &b, "b", false, &FakeSshd::ours()).unwrap();
        assert!(!r.already_present);
        let keys = read(d.path(), KEYFILE);
        let lines: Vec<_> = keys.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with(" a"));
        assert!(lines[1].ends_with(" b"));
    }

    #[test]
    fn missing_dropin_dir_and_include_are_created() {
        let d = setup("Port 22\n");
        assert!(!d.path().join("etc/ssh/sshd_config.d").exists());
        install(d.path(), &ca_line(""), "ca", false, &FakeSshd::ours()).unwrap();
        assert!(
            d.path()
                .join("etc/ssh/sshd_config.d/50-ezcrypt.conf")
                .exists()
        );
        assert!(
            read(d.path(), "etc/ssh/sshd_config")
                .starts_with("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
        );
    }

    #[test]
    fn existing_relative_include_is_not_duplicated() {
        let cfg = "# top\n  include sshd_config.d/*.conf\nPort 22\n";
        let d = setup(cfg);
        let r = install(d.path(), &ca_line(""), "ca", false, &FakeSshd::ours()).unwrap();
        assert!(!r.added_include);
        assert_eq!(read(d.path(), "etc/ssh/sshd_config"), cfg);
    }

    #[test]
    fn shadowed_setting_refuses_and_restores() {
        let d = setup(SSHD_CONFIG);
        let before = tree(d.path());
        let sshd = FakeSshd::new(Some("/etc/ssh/other_ca"));
        let e = install(d.path(), &ca_line(""), "ca", false, &sshd).unwrap_err();
        assert_eq!(
            format!("{e}"),
            "TrustedUserCAKeys is already set to /etc/ssh/other_ca. Rerun with --use-existing to add this CA there."
        );
        assert_eq!(tree(d.path()), before);
        assert!(!sshd.calls().contains(&"reload"));
    }

    #[test]
    fn none_effective_value_is_shadowed() {
        let d = setup(SSHD_CONFIG);
        let before = tree(d.path());
        let sshd = FakeSshd::new(None);
        let e = install(d.path(), &ca_line(""), "ca", false, &sshd).unwrap_err();
        assert!(format!("{e}").contains("already set to none."));
        assert_eq!(tree(d.path()), before);
    }

    #[test]
    fn use_existing_appends_to_effective_file() {
        let d = setup(SSHD_CONFIG);
        let other = d.path().join("etc/ssh/other_ca");
        std::fs::write(&other, "ssh-ed25519 AAAA old-ca-without-newline").unwrap();
        let sshd = FakeSshd::new(Some("/etc/ssh/other_ca"));
        let line = ca_line("");
        let r = install(d.path(), &line, "new", true, &sshd).unwrap();
        assert_eq!(r.key_file, other);
        let content = std::fs::read_to_string(&other).unwrap();
        assert!(content.starts_with("ssh-ed25519 AAAA old-ca-without-newline\nssh-ed25519 "));
        assert!(content.ends_with(" new\n"));
        // our own files were reverted
        assert!(!d.path().join("etc/ssh/ezcrypt").exists());
        assert!(!d.path().join("etc/ssh/sshd_config.d").exists());
        assert_eq!(read(d.path(), "etc/ssh/sshd_config"), SSHD_CONFIG);
        assert_eq!(sshd.calls(), vec!["effective", "test", "reload"]);
        // idempotent
        let r = install(d.path(), &line, "new", true, &sshd).unwrap();
        assert!(r.already_present);
        assert_eq!(std::fs::read_to_string(&other).unwrap(), content);
    }

    #[test]
    fn use_existing_with_none_errors_and_restores() {
        let d = setup(SSHD_CONFIG);
        let before = tree(d.path());
        let sshd = FakeSshd::new(None);
        assert!(install(d.path(), &ca_line(""), "ca", true, &sshd).is_err());
        assert_eq!(tree(d.path()), before);
        assert!(!sshd.calls().contains(&"reload"));
    }

    #[test]
    fn failed_validation_restores_everything() {
        let d = setup(SSHD_CONFIG);
        let before = tree(d.path());
        let sshd = FakeSshd::ours();
        sshd.test_fails.set(true);
        assert!(install(d.path(), &ca_line(""), "ca", false, &sshd).is_err());
        assert_eq!(tree(d.path()), before);
        assert_eq!(sshd.calls(), vec!["effective", "test"]);
    }

    #[test]
    fn failed_reload_restores_everything() {
        let d = setup(SSHD_CONFIG);
        let before = tree(d.path());
        let mut sshd = FakeSshd::ours();
        sshd.reload_fails = true;
        assert!(install(d.path(), &ca_line(""), "ca", false, &sshd).is_err());
        assert_eq!(tree(d.path()), before);
    }

    #[test]
    fn restore_keeps_preexisting_key_file_bytes() {
        let d = setup(SSHD_CONFIG);
        std::fs::create_dir_all(d.path().join("etc/ssh/ezcrypt")).unwrap();
        std::fs::write(d.path().join(KEYFILE), "# mine\nssh-ed25519 junk\n\n").unwrap();
        let before = tree(d.path());
        let sshd = FakeSshd::ours();
        sshd.test_fails.set(true);
        assert!(install(d.path(), &ca_line(""), "ca", false, &sshd).is_err());
        assert_eq!(tree(d.path()), before);
    }

    #[test]
    fn appends_after_comments_and_junk_without_newline() {
        let d = setup(SSHD_CONFIG);
        std::fs::create_dir_all(d.path().join("etc/ssh/ezcrypt")).unwrap();
        std::fs::write(d.path().join(KEYFILE), "# mine\nnot a key").unwrap();
        install(d.path(), &ca_line(""), "ca", false, &FakeSshd::ours()).unwrap();
        let k = read(d.path(), KEYFILE);
        assert!(k.starts_with("# mine\nnot a key\nssh-ed25519 "));
        assert!(k.ends_with(" ca\n"));
    }

    #[test]
    fn invalid_ca_line_touches_nothing() {
        let d = setup(SSHD_CONFIG);
        let before = tree(d.path());
        let sshd = FakeSshd::ours();
        assert!(install(d.path(), "ssh-rsa AAAA nope", "ca", false, &sshd).is_err());
        assert!(install(d.path(), "garbage", "ca", false, &sshd).is_err());
        assert_eq!(tree(d.path()), before);
        assert!(sshd.calls().is_empty());
    }

    #[test]
    fn missing_sshd_config_errors_without_creating() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc/ssh")).unwrap();
        let before = tree(d.path());
        assert!(install(d.path(), &ca_line(""), "ca", false, &FakeSshd::ours()).is_err());
        assert_eq!(tree(d.path()), before);
    }

    #[test]
    fn preexisting_main_config_setting_refuses_untouched() {
        let cfg = format!("{SSHD_CONFIG}TrustedUserCAKeys /etc/ssh/legacy_ca\n");
        let d = setup(&cfg);
        std::fs::write(d.path().join("etc/ssh/legacy_ca"), "ssh-ed25519 AAAA old\n").unwrap();
        let before = tree(d.path());
        let sshd = FakeSshd::new(Some("/etc/ssh/legacy_ca"));
        let e = install(d.path(), &ca_line(""), "ca", false, &sshd).unwrap_err();
        assert!(format!("{e}").contains("already set to /etc/ssh/legacy_ca"));
        assert_eq!(tree(d.path()), before);
        assert_eq!(sshd.calls(), vec!["effective"]);
    }

    #[test]
    fn preexisting_main_config_setting_with_use_existing_appends_only() {
        let cfg = format!("{SSHD_CONFIG}TrustedUserCAKeys /etc/ssh/legacy_ca\n");
        let d = setup(&cfg);
        std::fs::write(d.path().join("etc/ssh/legacy_ca"), "ssh-ed25519 AAAA old\n").unwrap();
        let sshd = FakeSshd::new(Some("/etc/ssh/legacy_ca"));
        install(d.path(), &ca_line(""), "ca", true, &sshd).unwrap();
        assert!(read(d.path(), "etc/ssh/legacy_ca").ends_with(" ca\n"));
        assert_eq!(read(d.path(), "etc/ssh/sshd_config"), cfg);
        assert!(!d.path().join("etc/ssh/sshd_config.d").exists());
        assert!(!d.path().join("etc/ssh/ezcrypt").exists());
        assert_eq!(sshd.calls(), vec!["effective", "test", "reload"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_sshd_config_needing_include_is_refused() {
        let d = setup("");
        let real = d.path().join("real_config");
        std::fs::write(&real, "Port 22\n").unwrap();
        let link = d.path().join("etc/ssh/sshd_config");
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let before = tree(d.path());
        let e = install(d.path(), &ca_line(""), "ca", false, &FakeSshd::ours()).unwrap_err();
        assert!(format!("{e}").contains("managed elsewhere"));
        assert_eq!(tree(d.path()), before);
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_sshd_config_with_include_is_fine() {
        let d = setup("");
        let real = d.path().join("real_config");
        std::fs::write(&real, "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n").unwrap();
        let link = d.path().join("etc/ssh/sshd_config");
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let r = install(d.path(), &ca_line(""), "ca", false, &FakeSshd::ours()).unwrap();
        assert!(!r.added_include);
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
