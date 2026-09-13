use base64::{engine::general_purpose::STANDARD, Engine};
use ezcrypt_core::{
    certificate::{self, Purpose, Request},
    export, vault,
};
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use rand::rngs::OsRng;
use ssh_key::{Algorithm, Certificate, PrivateKey};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
use zeroize::Zeroizing;

fn request() -> Request {
    Request {
        public_key: PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
        purpose: Purpose::User,
        key_id: "workstation".into(),
        serial: "18446744073709551615".into(),
        principals: vec!["alice".into()],
        all_principals: false,
        valid_after: 1_700_000_000,
        valid_before: Some(2_000_000_000),
        critical_options: BTreeMap::from([
            ("force-command".into(), "echo hello".into()),
            ("source-address".into(), "192.0.2.0/24".into()),
        ]),
        extensions: BTreeMap::from([("permit-pty".into(), "".into())]),
    }
}
fn fixture(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.build/interop")
        .join(name);
    fs::create_dir_all(&path).unwrap();
    fs::canonicalize(path).unwrap()
}
fn run(command: &mut Command) -> String {
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn agree(device: &SecretKey, peer: &[u8]) -> ezcrypt_core::Result<Zeroizing<Vec<u8>>> {
    let peer = p256::PublicKey::from_sec1_bytes(peer)?;
    Ok(Zeroizing::new(
        diffie_hellman(device.to_nonzero_scalar(), peer.as_affine())
            .raw_secret_bytes()
            .to_vec(),
    ))
}
#[test]
fn all_algorithms_sign_and_export_to_openssh() {
    let path = fixture("openssh");
    let device = SecretKey::random(&mut OsRng);
    for algorithm in ["ed25519", "p256", "p384", "p521"] {
        let record = vault::create(
            algorithm,
            algorithm,
            Purpose::User,
            device.public_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        vault::with_key(
            &record,
            algorithm,
            Purpose::User,
            |peer| agree(&device, peer),
            |key| {
                for purpose in [Purpose::User, Purpose::Host] {
                    for forever in [false, true] {
                        let mut req = request();
                        req.purpose = purpose;
                        if purpose == Purpose::Host {
                            req.critical_options.clear();
                            req.extensions.clear();
                            req.principals = vec!["host.example.com".into()];
                        }
                        if forever {
                            req.valid_before = None;
                        }
                        let issued = certificate::issue(&req, purpose, key)?;
                        if !forever {
                            Certificate::from_openssh(&issued.certificate)?.validate_at(
                                1_800_000_000,
                                &[key.public_key().fingerprint(ssh_key::HashAlg::Sha256)],
                            )?;
                        }
                        let file = path.join(format!("{algorithm}-{purpose:?}-{forever}-cert.pub"));
                        fs::write(&file, issued.certificate)?;
                        let output = run(Command::new("ssh-keygen").arg("-Lf").arg(file));
                        assert!(output.contains("18446744073709551615"));
                        if forever {
                            assert!(output.contains("Valid: after"), "{output}");
                        }
                        if purpose == Purpose::User {
                            assert!(output.contains("force-command echo hello"));
                        }
                    }
                }
                let encrypted = export::passphrase(key, b"public test passphrase")?;
                let file = path.join(format!("{algorithm}.key"));
                fs::write(&file, encrypted)?;
                fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
                let restored = run(Command::new("ssh-keygen")
                    .args(["-y", "-P", "public test passphrase", "-f"])
                    .arg(&file));
                assert_eq!(
                    ssh_key::PublicKey::from_openssh(&restored)?.key_data(),
                    key.public_key().key_data()
                );
                Ok(())
            },
        )
        .unwrap();
    }
}
#[test]
fn envelope_tampering_and_wrong_device_fail_closed() {
    let device = SecretKey::random(&mut OsRng);
    let record = vault::create(
        "ca",
        "p521",
        Purpose::Host,
        device.public_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    let open = |r: &vault::Record, id: &str, purpose| {
        vault::with_key(r, id, purpose, |peer| agree(&device, peer), |_| Ok(()))
    };
    assert!(open(&record, "other", Purpose::Host).is_err());
    assert!(open(&record, "ca", Purpose::User).is_err());
    for field in 0..6 {
        let mut corrupt = record.clone();
        match field {
            0 => corrupt.ciphertext[0] ^= 1,
            1 => corrupt.nonce[0] ^= 1,
            2 => corrupt.salt[0] ^= 1,
            3 => corrupt.algorithm = "p256".into(),
            4 => corrupt.id = "other".into(),
            _ => corrupt.version = 2,
        }
        assert!(open(&corrupt, "ca", Purpose::Host).is_err());
    }
    let other = SecretKey::random(&mut OsRng);
    assert!(vault::with_key(
        &record,
        "ca",
        Purpose::Host,
        |peer| agree(&other, peer),
        |_| Ok(())
    )
    .is_err());
}
#[test]
fn duplicate_identity_and_validity_boundaries() {
    let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut a = request();
    a.principals = vec!["bob".into(), "alice".into()];
    let mut b = a.clone();
    b.serial = "1".into();
    b.key_id = "new label".into();
    b.valid_before = None;
    b.principals.reverse();
    assert_eq!(
        a.duplicate_id(ca.public_key()).unwrap(),
        b.duplicate_id(ca.public_key()).unwrap()
    );
    b.extensions.clear();
    assert_ne!(
        a.duplicate_id(ca.public_key()).unwrap(),
        b.duplicate_id(ca.public_key()).unwrap()
    );
    assert!(certificate::overlaps(1, None, 2, Some(3)));
    assert!(!certificate::overlaps(1, Some(2), 2, Some(3)));
    b.valid_before = Some(b.valid_after);
    assert!(b.normalized().is_err());
    b = a.clone();
    b.principals.clear();
    assert!(b.normalized().is_err());
    b.all_principals = true;
    assert!(b.normalized().is_ok());
    b.purpose = Purpose::Host;
    assert!(b.normalized().is_err());
}
#[test]
fn source_cidrs_reject_host_bits_without_widening_the_network() {
    let mut req = request();
    for cidr in ["192.0.2.42/24", "2001:db8::1/64", "192.0.2.1/0", "::1/0"] {
        req.critical_options
            .insert("source-address".into(), cidr.into());
        assert!(req.normalized().is_err(), "accepted {cidr}");
    }
    for cidr in [
        "192.0.2.0/24",
        "192.0.2.42/32",
        "2001:db8::/64",
        "2001:db8::1/128",
        "0.0.0.0/0",
        "::/0",
    ] {
        req.critical_options
            .insert("source-address".into(), cidr.into());
        let normalized = req.normalized().unwrap();
        assert_eq!(normalized.critical_options["source-address"], cidr);
    }
}
#[test]
fn gpg_portable_export_and_recipient_validation() {
    let home = fixture("gpg");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let gpg = || {
        let mut c = Command::new("gpg");
        c.arg("--homedir").arg(&home).args([
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ]);
        c
    };
    if !run(gpg().args(["--with-colons", "--list-keys"])).contains("fpr:") {
        run(gpg().args([
            "--quick-generate-key",
            "ezcrypt disposable test <test@example.invalid>",
            "ed25519",
            "cert",
            "0",
        ]));
        let listing = run(gpg().args(["--with-colons", "--list-keys"]));
        let fp = listing
            .lines()
            .find(|s| s.starts_with("fpr:"))
            .unwrap()
            .split(':')
            .nth(9)
            .unwrap();
        run(gpg().args(["--quick-add-key", fp, "cv25519", "encr", "0"]));
    }
    let armor = run(gpg().args(["--armor", "--export"]));
    let (fp, _) = export::recipient_info(&armor).unwrap();
    let bad_checksum = armor
        .lines()
        .map(|line| if line.starts_with('=') { "=AAAA" } else { line })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(export::recipient_info(&bad_checksum).is_err());
    let raw = gpg().arg("--export").output().unwrap().stdout;
    let rearmor = |bytes: &[u8]| {
        format!(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{}\n-----END PGP PUBLIC KEY BLOCK-----",
            STANDARD.encode(bytes)
        )
    };
    let mut unbound = raw.clone();
    unbound.extend_from_slice(&[0xcd, 4, b'b', b'a', b'd', b'!']);
    assert!(export::recipient_info(&rearmor(&unbound)).is_err());
    for tail in [
        vec![0xc6],
        vec![0xc6, 192],
        vec![0xc6, 255],
        vec![0xc6, 255, 0, 0, 0],
        vec![0x98],
        vec![0x99, 0],
        vec![0x9a, 0, 0, 0],
        vec![0xc6, 2, 0],
    ] {
        let mut truncated = raw.clone();
        truncated.extend_from_slice(&tail);
        assert!(
            export::recipient_info(&rearmor(&truncated)).is_err(),
            "accepted truncated tail {tail:?}"
        );
    }
    let mut trailing = raw;
    trailing.extend_from_slice(&[0, 0, 0]);
    assert!(export::recipient_info(&rearmor(&trailing)).is_err());

    assert!(export::recipient_info(&(armor.clone() + &armor)).is_err());
    assert!(export::recipient_info(&(armor.clone() + "junk")).is_err());

    // An unrelated certification must neither reject a usable recipient nor
    // supply its self-signature policy. Keep the certifier in a separate keyring.
    let certifier_home = fixture("gpg-certifier");
    fs::set_permissions(&certifier_home, fs::Permissions::from_mode(0o700)).unwrap();
    let certifier = || {
        let mut c = Command::new("gpg");
        c.arg("--homedir").arg(&certifier_home).args([
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ]);
        c
    };
    if !run(certifier().args(["--with-colons", "--list-secret-keys"])).contains("fpr:") {
        run(certifier().args([
            "--quick-generate-key",
            "ezcrypt certifier <certifier@example.invalid>",
            "ed25519",
            "cert",
            "0",
        ]));
    }
    let public_file = certifier_home.join("recipient.asc");
    let listing = run(certifier().args(["--with-colons", "--list-secret-keys"]));
    let certifier_fp = listing
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .unwrap()
        .split(':')
        .nth(9)
        .unwrap();
    fs::write(&public_file, &armor).unwrap();
    run(certifier().arg("--import").arg(public_file));
    run(certifier().args(["--local-user", certifier_fp, "--quick-sign-key", &fp]));
    let certified = run(certifier().args(["--armor", "--export", &fp]));
    assert_eq!(
        export::recipient_info(&certified).unwrap(),
        export::recipient_info(&armor).unwrap()
    );
    use pgp::{
        composed::{Deserializable, SignedPublicKey},
        types::Tag,
    };
    let (mut no_self_signature, _) = SignedPublicKey::from_string(&certified).unwrap();
    for user in &mut no_self_signature.details.users {
        user.signatures.retain(|sig| {
            sig.verify_certification(&no_self_signature.primary_key, Tag::UserId, &user.id)
                .is_err()
        });
    }
    let untrusted = pgp::ser::Serialize::to_bytes(&no_self_signature).unwrap();
    assert!(export::recipient_info(&rearmor(&untrusted)).is_err());
    for algorithm in ["ed25519", "p256", "p384", "p521"] {
        let key =
            PrivateKey::random(&mut OsRng, certificate::algorithm(algorithm).unwrap()).unwrap();
        assert!(export::gpg(&key, &armor, "wrong recipient").is_err());
        let encrypted = export::gpg(&key, &certified, &fp).unwrap();
        let file = home.join(format!("{algorithm}.gpg"));
        fs::write(&file, encrypted).unwrap();
        let restored = run(gpg().arg("--decrypt").arg(&file));
        let restored = Zeroizing::new(restored);
        assert_eq!(
            PrivateKey::from_openssh(restored.as_bytes())
                .unwrap()
                .public_key(),
            key.public_key()
        );
    }
}
