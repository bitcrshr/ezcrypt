//! `ezcrypt update`: replace this binary with the latest GitHub release.
//!
//! The trust model matches install.sh: HTTPS to github.com, and the download
//! must match the release's SHA256SUMS. The new binary must also report the
//! expected version before it replaces the running one, so a bad download
//! never leaves a broken `ezcrypt` behind.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
#[cfg(any(windows, test))]
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use semver::Version;
use sha2::{Digest, Sha256};

const REPO: &str = "https://github.com/bitcrshr/ezcrypt";
const DPKG_LIST: &str = "/var/lib/dpkg/info/ezcrypt.list";
/// Generous cap on any download or extracted binary (the binary is ~20 MB).
const MAX_BYTES: usize = 128 << 20;
/// The binary's name inside release archives.
const BIN: &str = if cfg!(windows) {
    "ezcrypt.exe"
} else {
    "ezcrypt"
};

pub async fn run(check: bool) -> Result<()> {
    let exe = std::env::current_exe().context("cannot locate the running ezcrypt")?;
    // Follow symlinks (e.g. ~/.local/bin/ezcrypt -> elsewhere) so the real
    // file is replaced, not the link.
    #[cfg(unix)]
    let exe = exe
        .canonicalize()
        .context("cannot locate the running ezcrypt")?;
    let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version is semver");
    let release = Release::new(REPO, true)?;
    let install = Install::detect(&exe, Path::new(DPKG_LIST));
    update(&release, &exe, &current, check, install).await
}

/// How this copy of ezcrypt was installed, which decides how to update it.
#[derive(Debug, PartialEq)]
enum Install {
    /// install.sh, install.ps1, a release archive, or `cargo install`.
    Standalone,
    /// The release .deb; dpkg owns the file.
    Deb,
    /// The Nix store is read-only.
    Nix,
}

impl Install {
    fn detect(exe: &Path, dpkg_list: &Path) -> Install {
        if exe.starts_with("/nix/store") {
            return Install::Nix;
        }
        match fs::read_to_string(dpkg_list) {
            Ok(list) if list.lines().any(|line| Path::new(line) == exe) => Install::Deb,
            _ => Install::Standalone,
        }
    }
}

async fn update(
    release: &Release,
    exe: &Path,
    current: &Version,
    check: bool,
    install: Install,
) -> Result<()> {
    // The copy a previous Windows update moved aside; it was still running
    // then, so it could not be deleted.
    #[cfg(windows)]
    let _ = fs::remove_file(aside_path(exe));

    let (tag, latest) = release.latest().await?;
    if latest == *current {
        println!("ezcrypt {current} is up to date.");
        return Ok(());
    }
    if latest < *current {
        println!("ezcrypt {current} is newer than the latest release ({latest}); nothing to do.");
        return Ok(());
    }
    if check {
        println!(
            "ezcrypt {latest} is available (this is {current}). Run `ezcrypt update` to install it."
        );
        return Ok(());
    }
    match install {
        Install::Nix => bail!(
            "ezcrypt {latest} is available, but this copy is managed by Nix ({}). Update it with Nix.",
            exe.display()
        ),
        Install::Deb => {
            if !crate::trust::is_root()? {
                bail!("ezcrypt was installed from the .deb. Update it with: sudo ezcrypt update");
            }
            let name = deb_name().ok_or_else(|| anyhow!("no .deb is published for this CPU"))?;
            let deb = release.verified(&tag, name).await?;
            let dir = tempfile::tempdir().context("cannot create a temporary directory")?;
            let path = dir.path().join(name);
            fs::write(&path, &deb).with_context(|| format!("cannot write {}", path.display()))?;
            let status = Command::new("dpkg")
                .arg("-i")
                .arg(&path)
                .status()
                .context("cannot run dpkg")?;
            ensure!(
                status.success(),
                "dpkg -i {} failed ({status})",
                path.display()
            );
            check_version(exe, &latest).context("dpkg installed the new package, but")?;
        }
        Install::Standalone => {
            let name = asset_name().ok_or_else(|| anyhow!("no release build for this platform"))?;
            let archive = release.verified(&tag, name).await?;
            let binary = extract(&archive)?;
            replace_exe(exe, &binary, &latest)?;
        }
    }
    println!("Updated ezcrypt {current} → {latest}.");
    Ok(())
}

/// Release archive for the platform this binary was built for.
fn asset_name() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("ezcrypt-x86_64-unknown-linux-musl.tar.gz")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("ezcrypt-aarch64-unknown-linux-musl.tar.gz")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("ezcrypt-aarch64-apple-darwin.tar.gz")
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        Some("ezcrypt-x86_64-pc-windows-msvc.zip")
    } else if cfg!(all(windows, target_arch = "aarch64")) {
        Some("ezcrypt-aarch64-pc-windows-msvc.zip")
    } else {
        None
    }
}

fn deb_name() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("ezcrypt-amd64.deb")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("ezcrypt-arm64.deb")
    } else {
        None
    }
}

/// GitHub releases of one repository.
struct Release {
    base: String,
    client: reqwest::Client,
    no_redirect: reqwest::Client,
}

impl Release {
    fn new(base: &str, https_only: bool) -> Result<Self> {
        let tls = tls_config()?;
        let build = |redirect| {
            reqwest::Client::builder()
                .use_preconfigured_tls(tls.clone())
                .https_only(https_only)
                .redirect(redirect)
                .user_agent(concat!("ezcrypt/", env!("CARGO_PKG_VERSION")))
                .connect_timeout(Duration::from_secs(15))
                .read_timeout(Duration::from_secs(30))
                .build()
                .context("cannot set up HTTPS")
        };
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            client: build(reqwest::redirect::Policy::limited(10))?,
            no_redirect: build(reqwest::redirect::Policy::none())?,
        })
    }

    /// The latest release's tag and version, read from where
    /// `/releases/latest` redirects. No API token or rate limit involved.
    async fn latest(&self) -> Result<(String, Version)> {
        let url = format!("{}/releases/latest", self.base);
        let resp = self
            .no_redirect
            .get(&url)
            .send()
            .await
            .with_context(|| format!("cannot reach {url}"))?;
        ensure!(
            resp.status().is_redirection(),
            "unexpected response from {url}: {}",
            resp.status()
        );
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("{url} did not name a release"))?;
        parse_tag(&self.base, location)
    }

    async fn get(&self, tag: &str, name: &str) -> Result<Vec<u8>> {
        let url = format!("{}/releases/download/{tag}/{name}", self.base);
        let mut resp = self
            .client
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("cannot download {url}"))?;
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .with_context(|| format!("cannot download {url}"))?
        {
            ensure!(
                body.len() + chunk.len() <= MAX_BYTES,
                "{url} is larger than expected"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Download a release file and check it against the release's SHA256SUMS.
    async fn verified(&self, tag: &str, name: &str) -> Result<Vec<u8>> {
        let sums = self.get(tag, "SHA256SUMS").await?;
        let sums = String::from_utf8(sums).context("SHA256SUMS is not text")?;
        let want = checksum_for(&sums, name)?;
        let body = self.get(tag, name).await?;
        ensure!(
            Sha256::digest(&body).as_slice() == want,
            "{name} does not match SHA256SUMS; not installing it"
        );
        Ok(body)
    }
}

fn tls_config() -> Result<rustls::ClientConfig> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("cannot set up TLS")?
        .with_platform_verifier()
        .context("cannot load the system's TLS root certificates (on Debian or Ubuntu: apt install ca-certificates)")?
        .with_no_client_auth())
}

/// Turn `<base>/releases/tag/v1.2.3` into ("v1.2.3", 1.2.3).
fn parse_tag(base: &str, location: &str) -> Result<(String, Version)> {
    let tag = location
        .strip_prefix(base)
        .and_then(|rest| rest.strip_prefix("/releases/tag/"))
        .ok_or_else(|| anyhow!("no published release found (redirected to {location:?})"))?;
    let version = tag
        .strip_prefix('v')
        .and_then(|v| Version::parse(v).ok())
        .ok_or_else(|| anyhow!("the latest release tag {tag:?} is not a version"))?;
    Ok((tag.to_string(), version))
}

/// The SHA-256 listed for `name` in sha256sum output.
fn checksum_for(sums: &str, name: &str) -> Result<[u8; 32]> {
    let mut found = None;
    for line in sums.lines() {
        // "<hash>  <name>" (text mode) or "<hash> *<name>" (binary mode).
        let Some((hash, rest)) = line.split_once(' ') else {
            continue;
        };
        let Some(file) = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*')) else {
            continue;
        };
        if file != name {
            continue;
        }
        ensure!(found.is_none(), "SHA256SUMS lists {name} more than once");
        found = Some(
            decode_hex(hash)
                .ok_or_else(|| anyhow!("SHA256SUMS has a malformed hash for {name}"))?,
        );
    }
    found.ok_or_else(|| anyhow!("SHA256SUMS does not list {name}"))
}

fn decode_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn extract(archive: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    return extract_zip(archive, BIN);
    #[cfg(not(windows))]
    return extract_tar_gz(archive, BIN);
}

#[cfg(any(not(windows), test))]
fn extract_tar_gz(archive: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar
        .entries()
        .context("the archive is not a valid .tar.gz")?
    {
        let entry = entry.context("the archive is not a valid .tar.gz")?;
        if entry.path().context("the archive is not a valid .tar.gz")? != Path::new(name) {
            continue;
        }
        ensure!(
            entry.header().entry_type().is_file(),
            "{name} in the archive is not a regular file"
        );
        return read_capped(entry, name);
    }
    bail!("the archive does not contain {name}")
}

#[cfg(any(windows, test))]
fn extract_zip(archive: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive))
        .context("the archive is not a valid .zip")?;
    let file = zip
        .by_name(name)
        .with_context(|| format!("the archive does not contain {name}"))?;
    ensure!(
        file.is_file(),
        "{name} in the archive is not a regular file"
    );
    read_capped(file, name)
}

fn read_capped(reader: impl Read, name: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .with_context(|| format!("cannot extract {name}"))?;
    ensure!(
        out.len() <= MAX_BYTES,
        "{name} in the archive is larger than expected"
    );
    Ok(out)
}

/// Stage `binary` next to `exe`, check that it runs and reports `version`,
/// then swap it in. Until the final rename, `exe` is untouched.
fn replace_exe(exe: &Path, binary: &[u8], version: &Version) -> Result<()> {
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("cannot locate the directory of {}", exe.display()))?;
    let mut staged = tempfile::Builder::new()
        .prefix(".ezcrypt-update-")
        .suffix(std::env::consts::EXE_SUFFIX)
        .tempfile_in(dir)
        .map_err(|e| not_writable(e, dir))?;
    staged
        .write_all(binary)
        .and_then(|()| staged.as_file().sync_all())
        .with_context(|| format!("cannot write to {}", dir.display()))?;
    #[cfg(unix)]
    fs::set_permissions(staged.path(), fs::metadata(exe)?.permissions())
        .with_context(|| format!("cannot set permissions in {}", dir.display()))?;
    // Close the handle so the staged file can run (Windows refuses otherwise).
    let staged = staged.into_temp_path();
    check_version(&staged, version).context("not installing it")?;

    #[cfg(windows)]
    return swap_aside(exe, staged);
    #[cfg(not(windows))]
    return staged
        .persist(exe)
        .map_err(|e| e.error)
        .with_context(|| format!("cannot replace {}", exe.display()));
}

/// Windows cannot overwrite a running .exe, but it can rename one: move the
/// running copy aside, then move the new one into place.
#[cfg(any(windows, test))]
fn swap_aside(exe: &Path, staged: tempfile::TempPath) -> Result<()> {
    let aside = aside_path(exe);
    let _ = fs::remove_file(&aside);
    fs::rename(exe, &aside).with_context(|| format!("cannot move {} aside", exe.display()))?;
    if let Err(e) = staged.persist(exe) {
        let _ = fs::rename(&aside, exe);
        return Err(e.error).with_context(|| format!("cannot replace {}", exe.display()));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn aside_path(exe: &Path) -> PathBuf {
    let mut path = exe.as_os_str().to_owned();
    path.push(".old");
    PathBuf::from(path)
}

fn not_writable(e: std::io::Error, dir: &Path) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        let how = if cfg!(windows) {
            "Rerun from an elevated terminal."
        } else {
            "Rerun with sudo: sudo ezcrypt update"
        };
        anyhow!("cannot write to {}. {how}", dir.display())
    } else {
        anyhow::Error::new(e).context(format!("cannot write to {}", dir.display()))
    }
}

/// Run `bin --version` and require exactly `ezcrypt <want>`.
fn check_version(bin: &Path, want: &Version) -> Result<()> {
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .with_context(|| format!("cannot run {}", bin.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let got = text
        .trim()
        .strip_prefix("ezcrypt ")
        .and_then(|v| Version::parse(v).ok());
    ensure!(
        out.status.success() && got.as_ref() == Some(want),
        "the new ezcrypt reported {:?}, expected \"ezcrypt {want}\"",
        text.trim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_gz(name: &str, data: &[u8], kind: tar::EntryType) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn zip_with(name: &str, data: &[u8]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file(name, options).unwrap();
        zip.write_all(data).unwrap();
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn checksum_found_in_either_mode() {
        let h = "ab".repeat(32);
        let sums = format!("{}  other.tar.gz\n{h}  ezcrypt.tar.gz\n", "cd".repeat(32));
        assert_eq!(checksum_for(&sums, "ezcrypt.tar.gz").unwrap(), [0xab; 32]);
        let sums = format!("{h} *ezcrypt.tar.gz\n");
        assert_eq!(checksum_for(&sums, "ezcrypt.tar.gz").unwrap(), [0xab; 32]);
    }

    #[test]
    fn checksum_rejects_missing_duplicate_and_malformed() {
        let h = "ab".repeat(32);
        let missing = format!("{h}  other.tar.gz\n");
        assert!(
            checksum_for(&missing, "ezcrypt.tar.gz")
                .unwrap_err()
                .to_string()
                .contains("does not list")
        );
        let dup = format!("{h}  ezcrypt.tar.gz\n{h}  ezcrypt.tar.gz\n");
        assert!(
            checksum_for(&dup, "ezcrypt.tar.gz")
                .unwrap_err()
                .to_string()
                .contains("more than once")
        );
        for bad in [
            "ab".repeat(31),
            format!("+{}", "a".repeat(63)),
            "zz".repeat(32),
        ] {
            let sums = format!("{bad}  ezcrypt.tar.gz\n");
            assert!(
                checksum_for(&sums, "ezcrypt.tar.gz")
                    .unwrap_err()
                    .to_string()
                    .contains("malformed"),
                "{bad}"
            );
        }
        // A name that only ends with the wanted one is a different file.
        let suffix = format!("{h}  x-ezcrypt.tar.gz\n");
        assert!(checksum_for(&suffix, "ezcrypt.tar.gz").is_err());
    }

    #[test]
    fn tag_parsed_from_latest_redirect() {
        let base = "https://github.com/bitcrshr/ezcrypt";
        let (tag, v) = parse_tag(base, &format!("{base}/releases/tag/v1.2.3")).unwrap();
        assert_eq!((tag.as_str(), v), ("v1.2.3", Version::new(1, 2, 3)));
        let (_, v) = parse_tag(base, &format!("{base}/releases/tag/v0.2.0-rc1")).unwrap();
        assert_eq!(v, Version::parse("0.2.0-rc1").unwrap());
    }

    #[test]
    fn tag_rejects_other_places_and_non_versions() {
        let base = "https://github.com/bitcrshr/ezcrypt";
        let none = parse_tag(base, &format!("{base}/releases")).unwrap_err();
        assert!(none.to_string().contains("no published release"));
        assert!(parse_tag(base, "https://github.com/evil/ezcrypt/releases/tag/v9.9.9").is_err());
        assert!(parse_tag(base, &format!("{base}/releases/tag/1.2.3")).is_err());
        assert!(parse_tag(base, &format!("{base}/releases/tag/vnext")).is_err());
        assert!(parse_tag(base, &format!("{base}/releases/tag/v1.2.3/../../x")).is_err());
    }

    #[test]
    fn tar_gz_extracts_only_a_regular_file_with_the_name() {
        let archive = tar_gz("ezcrypt", b"binary", tar::EntryType::Regular);
        assert_eq!(extract_tar_gz(&archive, "ezcrypt").unwrap(), b"binary");
        let other = tar_gz("other", b"binary", tar::EntryType::Regular);
        assert!(
            extract_tar_gz(&other, "ezcrypt")
                .unwrap_err()
                .to_string()
                .contains("does not contain")
        );
        let dir = tar_gz("ezcrypt", b"", tar::EntryType::Directory);
        assert!(
            extract_tar_gz(&dir, "ezcrypt")
                .unwrap_err()
                .to_string()
                .contains("not a regular file")
        );
        assert!(extract_tar_gz(b"not gzip", "ezcrypt").is_err());
    }

    #[test]
    fn zip_extracts_the_named_file() {
        let archive = zip_with("ezcrypt.exe", b"binary");
        assert_eq!(extract_zip(&archive, "ezcrypt.exe").unwrap(), b"binary");
        assert!(
            extract_zip(&archive, "other.exe")
                .unwrap_err()
                .to_string()
                .contains("does not contain")
        );
        assert!(extract_zip(b"not zip", "ezcrypt.exe").is_err());
    }

    #[test]
    fn install_kind_detected_from_path_and_dpkg() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("ezcrypt.list");
        let missing = dir.path().join("missing.list");
        assert_eq!(
            Install::detect(Path::new("/nix/store/abc-ezcrypt/bin/ezcrypt"), &missing),
            Install::Nix
        );
        fs::write(&list, "/.\n/usr\n/usr/bin\n/usr/bin/ezcrypt\n").unwrap();
        assert_eq!(
            Install::detect(Path::new("/usr/bin/ezcrypt"), &list),
            Install::Deb
        );
        assert_eq!(
            Install::detect(Path::new("/usr/local/bin/ezcrypt"), &list),
            Install::Standalone
        );
        assert_eq!(
            Install::detect(Path::new("/usr/bin/ezcrypt"), &missing),
            Install::Standalone
        );
    }

    #[test]
    fn swap_aside_moves_the_old_copy_and_installs_the_new() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("ezcrypt.exe");
        fs::write(&exe, "old").unwrap();
        fs::write(aside_path(&exe), "stale").unwrap();
        let staged = dir.path().join("staged");
        fs::write(&staged, "new").unwrap();
        swap_aside(&exe, tempfile::TempPath::try_from_path(&staged).unwrap()).unwrap();
        assert_eq!(fs::read_to_string(&exe).unwrap(), "new");
        assert_eq!(fs::read_to_string(aside_path(&exe)).unwrap(), "old");
        assert!(!staged.exists());
    }

    /// End to end against a local stand-in for GitHub, with shell scripts
    /// standing in for ezcrypt binaries.
    #[cfg(unix)]
    mod end_to_end {
        use super::*;
        use std::collections::HashMap;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Mutex;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        struct Server {
            base: String,
            requests: Arc<Mutex<Vec<String>>>,
        }

        /// Serve `files` under /releases/download/<tag>/, and redirect
        /// /releases/latest to `latest` (relative to the base).
        async fn serve(latest: &str, files: HashMap<String, Vec<u8>>) -> Server {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}/bitcrshr/ezcrypt", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let (log, location) = (requests.clone(), format!("{base}{latest}"));
            tokio::spawn(async move {
                loop {
                    let (mut sock, _) = listener.accept().await.unwrap();
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        let n = sock.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let request = String::from_utf8_lossy(&buf);
                    let path = request.split(' ').nth(1).unwrap_or("").to_string();
                    let path = path
                        .strip_prefix("/bitcrshr/ezcrypt")
                        .unwrap_or(&path)
                        .to_string();
                    log.lock().unwrap().push(path.clone());
                    let (head, body) = if path == "/releases/latest" {
                        (format!("302 Found\r\nLocation: {location}"), Vec::new())
                    } else if let Some(body) = files.get(&path) {
                        ("200 OK".to_string(), body.clone())
                    } else {
                        ("404 Not Found".to_string(), Vec::new())
                    };
                    let response = format!(
                        "HTTP/1.1 {head}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    sock.write_all(response.as_bytes()).await.unwrap();
                    sock.write_all(&body).await.unwrap();
                    let _ = sock.shutdown().await;
                }
            });
            Server { base, requests }
        }

        fn script(version: &str) -> Vec<u8> {
            format!("#!/bin/sh\necho 'ezcrypt {version}'\n").into_bytes()
        }

        /// A release `tag` whose archive holds `binary`, with SHA256SUMS
        /// listing `listed_hash` (or the real hash).
        fn release(
            tag: &str,
            binary: &[u8],
            listed_hash: Option<String>,
        ) -> HashMap<String, Vec<u8>> {
            let name = asset_name().expect("tests run on a released platform");
            let archive = tar_gz("ezcrypt", binary, tar::EntryType::Regular);
            let hash = listed_hash.unwrap_or_else(|| hex(&Sha256::digest(&archive)));
            HashMap::from([
                (format!("/releases/download/{tag}/{name}"), archive),
                (
                    format!("/releases/download/{tag}/SHA256SUMS"),
                    format!("{}  other.zip\n{hash}  {name}\n", "00".repeat(32)).into_bytes(),
                ),
            ])
        }

        /// A directory holding an installed ezcrypt that reports `version`.
        fn installed(version: &str) -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let exe = dir.path().join("ezcrypt");
            fs::write(&exe, script(version)).unwrap();
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
            (dir, exe)
        }

        fn version_of(exe: &Path) -> String {
            let out = Command::new(exe).arg("--version").output().unwrap();
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        }

        fn files_in(dir: &Path) -> Vec<String> {
            let mut names: Vec<_> = fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }

        async fn run(
            server: &Server,
            exe: &Path,
            current: &str,
            check: bool,
            install: Install,
        ) -> Result<()> {
            let release = Release::new(&server.base, false).unwrap();
            update(
                &release,
                exe,
                &Version::parse(current).unwrap(),
                check,
                install,
            )
            .await
        }

        #[tokio::test]
        async fn updates_to_a_newer_release() {
            let server = serve(
                "/releases/tag/v0.2.0",
                release("v0.2.0", &script("0.2.0"), None),
            )
            .await;
            let (dir, exe) = installed("0.1.0");
            run(&server, &exe, "0.1.0", false, Install::Standalone)
                .await
                .unwrap();
            assert_eq!(version_of(&exe), "ezcrypt 0.2.0");
            assert_eq!(
                fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
                0o755
            );
            assert_eq!(
                files_in(dir.path()),
                ["ezcrypt"],
                "no staging files left behind"
            );
        }

        #[tokio::test]
        async fn up_to_date_or_ahead_downloads_nothing() {
            let server = serve(
                "/releases/tag/v0.1.0",
                release("v0.1.0", &script("0.1.0"), None),
            )
            .await;
            for current in ["0.1.0", "0.2.0-dev"] {
                let (_dir, exe) = installed(current);
                run(&server, &exe, current, false, Install::Standalone)
                    .await
                    .unwrap();
                assert_eq!(version_of(&exe), format!("ezcrypt {current}"));
            }
            assert_eq!(
                *server.requests.lock().unwrap(),
                ["/releases/latest", "/releases/latest"]
            );
        }

        #[tokio::test]
        async fn check_only_reports() {
            let server = serve(
                "/releases/tag/v0.2.0",
                release("v0.2.0", &script("0.2.0"), None),
            )
            .await;
            let (_dir, exe) = installed("0.1.0");
            run(&server, &exe, "0.1.0", true, Install::Standalone)
                .await
                .unwrap();
            assert_eq!(version_of(&exe), "ezcrypt 0.1.0");
            assert_eq!(*server.requests.lock().unwrap(), ["/releases/latest"]);
        }

        #[tokio::test]
        async fn checksum_mismatch_keeps_the_installed_binary() {
            let files = release("v0.2.0", &script("0.2.0"), Some("ab".repeat(32)));
            let server = serve("/releases/tag/v0.2.0", files).await;
            let (dir, exe) = installed("0.1.0");
            let err = run(&server, &exe, "0.1.0", false, Install::Standalone)
                .await
                .unwrap_err();
            assert!(
                format!("{err:#}").contains("does not match SHA256SUMS"),
                "{err:#}"
            );
            assert_eq!(version_of(&exe), "ezcrypt 0.1.0");
            assert_eq!(files_in(dir.path()), ["ezcrypt"]);
        }

        #[tokio::test]
        async fn wrong_or_broken_binary_keeps_the_installed_binary() {
            for binary in [
                script("0.9.9"),
                b"#!/bin/sh\nexit 1\n".to_vec(),
                b"\x7fELF garbage".to_vec(),
            ] {
                let server = serve("/releases/tag/v0.2.0", release("v0.2.0", &binary, None)).await;
                let (dir, exe) = installed("0.1.0");
                let err = run(&server, &exe, "0.1.0", false, Install::Standalone)
                    .await
                    .unwrap_err();
                assert!(format!("{err:#}").contains("not installing it"), "{err:#}");
                assert_eq!(version_of(&exe), "ezcrypt 0.1.0");
                assert_eq!(files_in(dir.path()), ["ezcrypt"]);
            }
        }

        #[tokio::test]
        async fn nix_copy_is_left_to_nix() {
            let server = serve(
                "/releases/tag/v0.2.0",
                release("v0.2.0", &script("0.2.0"), None),
            )
            .await;
            let (_dir, exe) = installed("0.1.0");
            let err = run(&server, &exe, "0.1.0", false, Install::Nix)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("managed by Nix"), "{err}");
            assert_eq!(*server.requests.lock().unwrap(), ["/releases/latest"]);
        }

        #[tokio::test]
        async fn no_release_is_reported() {
            let server = serve("/releases", HashMap::new()).await;
            let (_dir, exe) = installed("0.1.0");
            let err = run(&server, &exe, "0.1.0", false, Install::Standalone)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("no published release"), "{err}");
        }

        #[tokio::test]
        async fn read_only_directory_suggests_sudo() {
            if crate::trust::is_root().unwrap() {
                return; // root can write anywhere
            }
            let server = serve(
                "/releases/tag/v0.2.0",
                release("v0.2.0", &script("0.2.0"), None),
            )
            .await;
            let (dir, exe) = installed("0.1.0");
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
            let err = run(&server, &exe, "0.1.0", false, Install::Standalone)
                .await
                .unwrap_err();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
            assert!(err.to_string().contains("sudo ezcrypt update"), "{err}");
            assert_eq!(version_of(&exe), "ezcrypt 0.1.0");
        }
    }
}
