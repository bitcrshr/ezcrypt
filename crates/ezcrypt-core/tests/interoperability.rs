// These tests run OpenSSH (`ssh-keygen`) and GnuPG, and set Unix file modes.
#![cfg(unix)]

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
fn security_key_subjects_preserve_application_and_validate_in_openssh() {
    let path = fixture("security-keys");
    // Synthetic public fixtures exercise the wire format without a physical
    // authenticator. Enrollment/residency is not encoded in an SSH public key.
    for (subject_alg, primitive, cert_type) in [
        (
            "sk-ssh-ed25519@openssh.com",
            Algorithm::Ed25519,
            "sk-ssh-ed25519-cert-v01@openssh.com",
        ),
        (
            "sk-ecdsa-sha2-nistp256@openssh.com",
            certificate::algorithm("p256").unwrap(),
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
        ),
    ] {
        let key = PrivateKey::random(&mut OsRng, primitive).unwrap();
        let ordinary = key.public_key().to_bytes().unwrap();
        let alg_len = u32::from_be_bytes(ordinary[..4].try_into().unwrap()) as usize;
        let field = |wire: &mut Vec<u8>, value: &[u8]| {
            wire.extend_from_slice(&(value.len() as u32).to_be_bytes());
            wire.extend_from_slice(value);
        };
        for application in ["ssh:", "ssh:ezcrypt-resident-test"] {
            let mut wire = Vec::new();
            field(&mut wire, subject_alg.as_bytes());
            wire.extend_from_slice(&ordinary[4 + alg_len..]);
            let no_application = format!("{subject_alg} {}", STANDARD.encode(&wire));
            assert!(certificate::parse_public(&no_application).is_err());
            field(&mut wire, application.as_bytes());
            let public_line = format!("{subject_alg} {} test", STANDARD.encode(&wire));
            let subject = certificate::parse_public(&public_line).unwrap();
            let mut req = request();
            req.public_key = public_line;
            for ca_alg in ["ed25519", "p256", "p384", "p521"] {
                let ca = PrivateKey::random(&mut OsRng, certificate::algorithm(ca_alg).unwrap())
                    .unwrap();
                for forever in [false, true] {
                    req.valid_before = if forever { None } else { Some(2_000_000_000) };
                    let issued = certificate::issue(&req, Purpose::User, &ca).unwrap();
                    assert!(issued.certificate.starts_with(&format!("{cert_type} ")));
                    assert_eq!(
                        issued.subject_fingerprint,
                        subject.fingerprint(ssh_key::HashAlg::Sha256).to_string()
                    );
                    if !forever {
                        let cert = Certificate::from_openssh(&issued.certificate).unwrap();
                        assert_eq!(cert.public_key(), subject.key_data());
                        cert.validate_at(
                            1_800_000_000,
                            &[ca.public_key().fingerprint(ssh_key::HashAlg::Sha256)],
                        )
                        .unwrap();
                    }
                    let file = path.join(format!("{subject_alg}-{ca_alg}-{forever}-cert.pub"));
                    fs::write(&file, issued.certificate).unwrap();
                    let output = run(Command::new("ssh-keygen").arg("-Lf").arg(file));
                    assert!(output.contains(cert_type), "{output}");
                    assert!(output.contains("force-command echo hello"), "{output}");
                    assert!(!output.contains("no-touch-required"));
                }
            }
            // Applications are part of subject identity, including duplicate checks.
            let mut other = req.clone();
            let mut other_wire = wire[..wire.len() - application.len() - 4].to_vec();
            field(&mut other_wire, b"ssh:different");
            other.public_key = format!("{subject_alg} {}", STANDARD.encode(&other_wire));
            assert_ne!(
                req.duplicate_id(key.public_key()).unwrap(),
                other.duplicate_id(key.public_key()).unwrap()
            );
            wire.pop();
            assert!(certificate::parse_public(&format!(
                "{subject_alg} {}",
                STANDARD.encode(&wire)
            ))
            .is_err());
        }
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
        let armored = std::str::from_utf8(&encrypted).unwrap();
        assert!(armored.is_ascii());
        assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----\n"));
        assert!(armored.trim_end().ends_with("-----END PGP MESSAGE-----"));
        let file = home.join(format!("{algorithm}.asc"));
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

fn assert_inspects(req: &Request, issued: &certificate::Issued) {
    let inspected = certificate::inspect(&issued.certificate).unwrap();
    assert_eq!(inspected.purpose, req.purpose);
    assert_eq!(inspected.serial, req.serial.parse::<u64>().unwrap());
    assert_eq!(inspected.principals, req.principals);
    assert_eq!(inspected.valid_after, req.valid_after);
    assert_eq!(inspected.valid_before, req.valid_before);
    assert_eq!(inspected.key_id, req.key_id);
    assert_eq!(
        inspected.subject.key_data(),
        certificate::parse_public(&req.public_key)
            .unwrap()
            .key_data()
    );
    assert_eq!(
        inspected
            .ca
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        issued.ca_fingerprint
    );
}

#[test]
fn inspect_round_trips_issued_certificates() {
    for algorithm in ["ed25519", "p256", "p384", "p521"] {
        let ca =
            PrivateKey::random(&mut OsRng, certificate::algorithm(algorithm).unwrap()).unwrap();
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
                let issued = certificate::issue(&req, purpose, &ca).unwrap();
                assert_inspects(&req, &issued);
            }
        }
    }
}

#[test]
fn inspect_round_trips_security_key_subjects() {
    for (subject_alg, primitive) in [
        ("sk-ssh-ed25519@openssh.com", Algorithm::Ed25519),
        (
            "sk-ecdsa-sha2-nistp256@openssh.com",
            certificate::algorithm("p256").unwrap(),
        ),
    ] {
        let key = PrivateKey::random(&mut OsRng, primitive).unwrap();
        let ordinary = key.public_key().to_bytes().unwrap();
        let alg_len = u32::from_be_bytes(ordinary[..4].try_into().unwrap()) as usize;
        let mut wire = Vec::new();
        for part in [subject_alg.as_bytes(), &[]] {
            if part.is_empty() {
                wire.extend_from_slice(&ordinary[4 + alg_len..]);
            } else {
                wire.extend_from_slice(&(part.len() as u32).to_be_bytes());
                wire.extend_from_slice(part);
            }
        }
        wire.extend_from_slice(&(b"ssh:test".len() as u32).to_be_bytes());
        wire.extend_from_slice(b"ssh:test");
        let mut req = request();
        req.public_key = format!("{subject_alg} {} test", STANDARD.encode(&wire));
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        for forever in [false, true] {
            req.valid_before = if forever { None } else { Some(2_000_000_000) };
            let issued = certificate::issue(&req, Purpose::User, &ca).unwrap();
            assert_inspects(&req, &issued);
        }
    }
}

#[test]
fn inspect_rejects_tampering() {
    for algorithm in ["ed25519", "p256"] {
        let ca =
            PrivateKey::random(&mut OsRng, certificate::algorithm(algorithm).unwrap()).unwrap();
        let issued = certificate::issue(&request(), Purpose::User, &ca).unwrap();
        certificate::inspect(&issued.certificate).unwrap();
        let (cert_type, rest) = issued.certificate.split_once(' ').unwrap();
        let blob = STANDARD.decode(rest.split(' ').next().unwrap()).unwrap();
        let line = |bytes: &[u8]| format!("{cert_type} {}", STANDARD.encode(bytes));
        for index in 0..blob.len() {
            let mut tampered = blob.clone();
            tampered[index] ^= 1;
            assert!(
                certificate::inspect(&line(&tampered)).is_err(),
                "flip at byte {index} was accepted"
            );
        }
        let mut trailing = blob.clone();
        trailing.push(0);
        assert!(certificate::inspect(&line(&trailing)).is_err());
        assert!(certificate::inspect(&line(&blob[..blob.len() - 1])).is_err());
        assert!(certificate::inspect(&line(&[])).is_err());
        // Line type must agree with the blob.
        assert!(certificate::inspect(&format!(
            "ecdsa-sha2-nistp256-cert-v01@openssh.com {}",
            STANDARD.encode(&blob)
        ))
        .is_err());
        // RSA certificate type is unsupported.
        let rsa = {
            let mut wire = Vec::new();
            let name = b"ssh-rsa-cert-v01@openssh.com";
            wire.extend_from_slice(&(name.len() as u32).to_be_bytes());
            wire.extend_from_slice(name);
            wire.extend_from_slice(
                &blob[4 + u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize..],
            );
            wire
        };
        assert!(certificate::inspect(&format!(
            "ssh-rsa-cert-v01@openssh.com {}",
            STANDARD.encode(&rsa)
        ))
        .is_err());
        let long = format!("{} {}", issued.certificate, "x".repeat(16_400));
        assert!(certificate::inspect(&long).is_err());
    }
}

#[test]
fn inspect_rejects_signature_trailing_bytes() {
    let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let issued = certificate::issue(&request(), Purpose::User, &ca).unwrap();
    let (cert_type, rest) = issued.certificate.split_once(' ').unwrap();
    let blob = STANDARD.decode(rest.split(' ').next().unwrap()).unwrap();
    // Ed25519 signature string: string("ssh-ed25519") || string(sig64) = 83 bytes.
    let start = blob.len() - 83 - 4;
    assert_eq!(&blob[start..start + 4], &83u32.to_be_bytes());
    let mut tampered = blob[..start].to_vec();
    tampered.extend_from_slice(&84u32.to_be_bytes());
    tampered.extend_from_slice(&blob[start + 4..]);
    tampered.push(0);
    assert!(certificate::inspect(&format!("{cert_type} {}", STANDARD.encode(&tampered))).is_err());
}
