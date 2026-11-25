//! `ezcrypt enroll`: get a certificate for the user's SSH key from the phone.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use ezcrypt_core::certificate::{Inspected, Purpose, inspect, parse_public};
use ezcrypt_link::{Kind, Payload, Request};
use ssh_key::HashAlg;

use crate::input::Input;
use crate::session;

const CANDIDATES: [&str; 4] = ["id_ed25519", "id_ecdsa", "id_ed25519_sk", "id_ecdsa_sk"];

pub struct KeyChoice {
    pub private: PathBuf,
    pub public_line: String,
    pub cert_path: PathBuf,
}

fn choice_for(private: &Path) -> Result<KeyChoice> {
    let mut public = private.as_os_str().to_owned();
    public.push(".pub");
    let public = PathBuf::from(public);
    let text =
        fs::read_to_string(&public).with_context(|| format!("cannot read {}", public.display()))?;
    let key = parse_public(text.trim())
        .map_err(anyhow::Error::from_boxed)
        .with_context(|| format!("{} is not a supported key", public.display()))?;
    let mut cert = private.as_os_str().to_owned();
    cert.push("-cert.pub");
    Ok(KeyChoice {
        private: private.to_path_buf(),
        public_line: key.to_openssh().context("cannot encode the public key")?,
        cert_path: PathBuf::from(cert),
    })
}

/// An explicit path (the private key or its `.pub`) must be usable. Without
/// one, the first supported key in `ssh_dir` wins.
pub fn find_key(ssh_dir: &Path, explicit: Option<&Path>) -> Result<Option<KeyChoice>> {
    if let Some(path) = explicit {
        let private = match path.extension().and_then(|e| e.to_str()) {
            Some("pub") => path.with_extension(""),
            _ => path.to_path_buf(),
        };
        return choice_for(&private).map(Some);
    }
    for name in CANDIDATES {
        let private = ssh_dir.join(name);
        if private.exists() || private.with_file_name(format!("{name}.pub")).exists() {
            return choice_for(&private)
                .map(Some)
                .with_context(|| {
                    format!(
                        "found {} but cannot use its public key; recreate it with `ssh-keygen -y -f {} > {}.pub`",
                        private.display(),
                        private.display(),
                        private.display()
                    )
                });
        }
    }
    Ok(None)
}

/// The certificate must be one line, a user certificate, valid signature, for this key.
pub fn check_certificate(key: &KeyChoice, certificate: &str) -> Result<Inspected> {
    let certificate = certificate.trim();
    if certificate.is_empty() || certificate.contains(['\n', '\r']) {
        bail!("the certificate must be a single line");
    }
    let inspected = inspect(certificate).map_err(anyhow::Error::from_boxed)?;
    if inspected.purpose != Purpose::User {
        bail!("this is a host certificate, not a user certificate");
    }
    let ours = parse_public(&key.public_line).map_err(anyhow::Error::from_boxed)?;
    if inspected.subject.to_bytes()? != ours.to_bytes()? {
        bail!("this certificate is for a different key");
    }
    Ok(inspected)
}

pub fn write_certificate(path: &Path, certificate: &str) -> Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    writeln!(file, "{}", certificate.trim())?;
    file.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn home() -> Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .context("cannot find your home directory")
}

pub fn suggested_user() -> String {
    let var = if cfg!(windows) { "USERNAME" } else { "USER" };
    std::env::var(var)
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "user".into())
}

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// The answer to the `[Y/n]` create-key prompt. Enter means yes; end of
/// input means no, so nothing is created without someone answering.
fn wants_new_key(answer: Option<&str>) -> bool {
    answer.is_some_and(|a| matches!(a.trim().to_lowercase().as_str(), "" | "y" | "yes"))
}

/// Creates `~/.ssh` if it is missing, private to the user as OpenSSH expects.
fn ensure_ssh_dir(ssh_dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(ssh_dir)
        .with_context(|| format!("cannot create {}", ssh_dir.display()))
}

async fn create_key(ssh_dir: &Path, input: &mut Input) -> Result<Option<KeyChoice>> {
    let path = ssh_dir.join("id_ed25519");
    let answer = input
        .prompt("No SSH key found. Create ~/.ssh/id_ed25519 now? [Y/n] ")
        .await;
    if !wants_new_key(answer.as_deref()) {
        return Ok(None);
    }
    ensure_ssh_dir(ssh_dir)?;
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&path)
        .status()
        .context("cannot run ssh-keygen")?;
    if !status.success() {
        bail!("ssh-keygen failed");
    }
    choice_for(&path).map(Some)
}

fn format_time(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn install(key: &KeyChoice, payload: &Payload) -> Result<(String, Inspected)> {
    let Payload::Certificate { certificate } = payload else {
        bail!("the reply did not contain a certificate");
    };
    let inspected = check_certificate(key, certificate)?;
    write_certificate(&key.cert_path, certificate)?;
    Ok((format!("Installed {}", key.cert_path.display()), inspected))
}

pub async fn run(explicit: Option<PathBuf>, input: &mut Input) -> Result<()> {
    let ssh_dir = home()?.join(".ssh");
    let key = match find_key(&ssh_dir, explicit.as_deref())? {
        Some(key) => key,
        None => match create_key(&ssh_dir, input).await? {
            Some(key) => key,
            None => bail!("no SSH key to enroll"),
        },
    };
    println!("Enrolling {}", key.private.display());
    let parsed = parse_public(&key.public_line).map_err(anyhow::Error::from_boxed)?;
    let request = Request {
        kind: Kind::Enroll,
        host: hostname(),
        user: suggested_user(),
        subject: Some(parsed.to_bytes()?),
    };
    let fingerprint = format!("Key {}", parsed.fingerprint(HashAlg::Sha256));
    let received = session::run(request, Some(fingerprint), input).await?;
    let result = install(&key, received.payload());
    let message = result
        .as_ref()
        .map(|(m, _)| m.clone())
        .map_err(|e| anyhow::anyhow!("{e:#}"));
    session::finish(received, &message).await;
    let (message, inspected) = result?;
    println!("{message}");
    println!("Principals: {}", inspected.principals.join(", "));
    match inspected.valid_before {
        Some(t) => println!("Expires {}", format_time(t)),
        None => println!("Never expires"),
    }
    println!("CA {}", inspected.ca.fingerprint(HashAlg::Sha256));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ezcrypt_core::certificate::{self, Purpose, Request};
    use rand::rngs::OsRng;
    use ssh_key::{Algorithm, PrivateKey};
    use std::collections::BTreeMap;
    use std::fs;

    fn key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    fn pub_line(key: &PrivateKey) -> String {
        format!("{} user@host", key.public_key().to_openssh().unwrap())
    }

    fn rsa_line() -> String {
        // ssh-rsa public key (2048-bit, truncated is fine: it is rejected by type).
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 user@host".to_string()
    }

    fn issue(ca: &PrivateKey, subject: &PrivateKey, purpose: Purpose) -> String {
        let request = Request {
            public_key: subject.public_key().to_openssh().unwrap(),
            purpose,
            key_id: "test".into(),
            serial: "1".into(),
            principals: vec!["alice".into()],
            all_principals: false,
            valid_after: 1_700_000_000,
            valid_before: Some(2_000_000_000),
            critical_options: BTreeMap::new(),
            extensions: BTreeMap::new(),
        };
        certificate::issue(&request, purpose, ca)
            .unwrap()
            .certificate
    }

    fn choice(dir: &std::path::Path, key: &PrivateKey) -> KeyChoice {
        fs::write(dir.join("id_ed25519.pub"), pub_line(key)).unwrap();
        find_key(dir, None).unwrap().unwrap()
    }

    #[test]
    fn finds_keys_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let ed = key();
        fs::write(dir.path().join("id_ecdsa.pub"), pub_line(&key())).unwrap();
        fs::write(dir.path().join("id_ed25519.pub"), pub_line(&ed)).unwrap();
        let found = find_key(dir.path(), None).unwrap().unwrap();
        assert_eq!(found.private, dir.path().join("id_ed25519"));
        assert_eq!(found.cert_path, dir.path().join("id_ed25519-cert.pub"));

        let rsa = tempfile::tempdir().unwrap();
        fs::write(rsa.path().join("id_rsa.pub"), rsa_line()).unwrap();
        assert!(find_key(rsa.path(), None).unwrap().is_none());

        let explicit = rsa.path().join("id_rsa");
        assert!(find_key(rsa.path(), Some(&explicit)).is_err());
    }

    #[test]
    fn existing_private_key_without_pub_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("id_ed25519"), "private").unwrap();
        let e = find_key(dir.path(), None).err().unwrap();
        assert!(format!("{e:#}").contains("id_ed25519"));
    }

    #[test]
    fn accepts_crlf_comment_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let k = key();
        let clean = format!("{}\n", pub_line(&k));
        fs::write(dir.path().join("id_ed25519.pub"), clean).unwrap();
        let a = find_key(dir.path(), None).unwrap().unwrap();
        let messy = format!("  {}\r\n", pub_line(&k));
        fs::write(dir.path().join("id_ed25519.pub"), messy).unwrap();
        let b = find_key(dir.path(), None).unwrap().unwrap();
        assert_eq!(a.public_line, b.public_line);
    }

    #[test]
    fn check_certificate_requires_matching_user_cert() {
        let dir = tempfile::tempdir().unwrap();
        let k = key();
        let ca = key();
        let choice = choice(dir.path(), &k);
        let good = issue(&ca, &k, Purpose::User);
        assert!(check_certificate(&choice, &good).is_ok());
        assert!(check_certificate(&choice, &format!("\n {good} \n")).is_ok());
        assert!(check_certificate(&choice, &issue(&ca, &k, Purpose::Host)).is_err());
        assert!(check_certificate(&choice, &issue(&ca, &key(), Purpose::User)).is_err());
    }

    #[test]
    fn check_certificate_requires_one_line() {
        let dir = tempfile::tempdir().unwrap();
        let k = key();
        let ca = key();
        let choice = choice(dir.path(), &k);
        let good = issue(&ca, &k, Purpose::User);
        assert!(check_certificate(&choice, "").is_err());
        assert!(check_certificate(&choice, "  \n ").is_err());
        assert!(check_certificate(&choice, &format!("{good}\n{good}")).is_err());
        assert!(check_certificate(&choice, &format!("{good}\n# extra")).is_err());
    }

    #[test]
    fn create_key_prompt_defaults_to_yes_but_eof_is_no() {
        assert!(wants_new_key(Some("")));
        assert!(wants_new_key(Some(" Y ")));
        assert!(wants_new_key(Some("yes")));
        assert!(!wants_new_key(Some("n")));
        assert!(!wants_new_key(Some("no")));
        assert!(!wants_new_key(None));
    }

    #[tokio::test]
    async fn create_key_at_end_of_input_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        let mut input = Input::from_reader(std::io::Cursor::new(""));
        assert!(create_key(&ssh, &mut input).await.unwrap().is_none());
        assert!(!ssh.exists());
    }

    #[test]
    fn ssh_dir_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join("home/.ssh");
        ensure_ssh_dir(&ssh).unwrap();
        assert!(ssh.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&ssh).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
            // An existing directory is left as it is.
            fs::set_permissions(&ssh, fs::Permissions::from_mode(0o750)).unwrap();
            ensure_ssh_dir(&ssh).unwrap();
            let mode = fs::metadata(&ssh).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o750);
        }
    }

    #[test]
    fn write_certificate_replaces_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519-cert.pub");
        fs::write(&path, "old").unwrap();
        write_certificate(&path, "new-cert").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new-cert\n");
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }
}
