use crate::{invalid, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use pgp::{
    composed::{Deserializable, MessageBuilder, SignedPublicKey},
    crypto::sym::SymmetricKeyAlgorithm,
    packet::{Packet, PacketHeader, PacketParser, Signature, SignatureType},
    types::{KeyDetails, PacketLength, Tag},
};
use rand::{rngs::OsRng, RngCore};
use ssh_encoding::Encode;
use ssh_key::{Cipher, Kdf, LineEnding, PrivateKey};
use std::{
    io::Cursor,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// Derive the expensive passphrase key before the CA is decrypted.
pub struct PassphraseExport {
    salt: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
}
impl PassphraseExport {
    pub fn prepare(password: &[u8]) -> Result<Self> {
        let password = std::str::from_utf8(password)?;
        if password.chars().count() < 12 || password.contains('\0') {
            return Err(invalid("Use a passphrase of at least 12 characters"));
        }
        let mut salt = vec![0; 16];
        OsRng.fill_bytes(&mut salt);
        let kdf = Kdf::Bcrypt {
            salt: salt.clone(),
            rounds: 64,
        };
        let (key, iv) = kdf.derive_key_and_iv(Cipher::Aes256Ctr, password.as_bytes())?;
        Ok(Self {
            salt,
            key,
            iv: Zeroizing::new(iv),
        })
    }
    pub fn encrypt(&self, private: &PrivateKey) -> Result<String> {
        // Encode the private block into a preallocated, zeroizing allocation.
        // ssh-key's convenience encryption does its KDF with the CA live and
        // uses an ordinary Vec for this intermediate buffer.
        let mut block = Zeroizing::new(Vec::with_capacity(
            8 + private.key_data().encoded_len()? + 4 + private.comment().len() + 16,
        ));
        let check = OsRng.next_u32();
        block.extend_from_slice(&check.to_be_bytes());
        block.extend_from_slice(&check.to_be_bytes());
        private.key_data().encode(&mut *block)?;
        crate::certificate::string(&mut block, private.comment().as_bytes());
        let padding = (16 - block.len() % 16) % 16;
        for n in 1..=padding {
            block.push(n as u8);
        }
        Cipher::Aes256Ctr
            .encrypt(&self.key, &self.iv, &mut block)
            .map_err(|_| invalid("OpenSSH export encryption failed"))?;
        let mut out = b"openssh-key-v1\0".to_vec();
        crate::certificate::string(&mut out, b"aes256-ctr");
        crate::certificate::string(&mut out, b"bcrypt");
        let mut options = Vec::new();
        crate::certificate::string(&mut options, &self.salt);
        options.extend_from_slice(&64u32.to_be_bytes());
        crate::certificate::string(&mut out, &options);
        out.extend_from_slice(&1u32.to_be_bytes());
        crate::certificate::string(&mut out, &private.public_key().to_bytes()?);
        crate::certificate::string(&mut out, &block);
        let encoded = STANDARD.encode(out);
        let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for line in encoded.as_bytes().chunks(70) {
            pem.push_str(std::str::from_utf8(line)?);
            pem.push('\n');
        }
        pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
        Ok(pem)
    }
}
pub fn passphrase(private: &PrivateKey, password: &[u8]) -> Result<String> {
    PassphraseExport::prepare(password)?.encrypt(private)
}

fn live(sig: &Signature, key_created: u32, now: u64) -> bool {
    let Some(created) = sig.created().map(|v| u64::from(v.as_secs())) else {
        return false;
    };
    if created > now || u64::from(key_created) > now {
        return false;
    }
    for (base, duration) in [
        (created, sig.signature_expiration_time()),
        (u64::from(key_created), sig.key_expiration_time()),
    ] {
        if duration.is_some_and(|d| d.as_secs() != 0 && base + u64::from(d.as_secs()) <= now) {
            return false;
        }
    }
    true
}

fn recipient_packets(bytes: &[u8]) -> Result<Vec<Packet>> {
    // PacketParser treats a truncated header as EOF. Check framing separately,
    // so EOF is accepted only at a packet boundary. Key packets have definite
    // lengths; streaming/indeterminate bodies are not accepted here.
    let mut cursor = Cursor::new(bytes);
    while (cursor.position() as usize) < bytes.len() {
        let header = PacketHeader::try_from_reader(&mut cursor)?;
        let PacketLength::Fixed(length) = header.packet_length() else {
            return Err(invalid("OpenPGP key packets require definite lengths"));
        };
        let end = cursor.position() + u64::from(length);
        if end > bytes.len() as u64 {
            return Err(invalid("Truncated OpenPGP packet body"));
        }
        cursor.set_position(end);
    }
    Ok(PacketParser::new(Cursor::new(bytes)).collect::<std::result::Result<_, _>>()?)
}

// Deliberately accepts one ASCII-armored public certificate only. Validate every
// packet before the convenience parser, which can discard unsupported packets.
fn parse_recipient(armor: &str) -> Result<SignedPublicKey> {
    if armor.len() > 256 * 1024 {
        return Err(invalid("Recipient key is too large"));
    }
    let body = armor
        .trim()
        .strip_prefix("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        .and_then(|s| s.strip_suffix("-----END PGP PUBLIC KEY BLOCK-----"))
        .ok_or_else(|| invalid("Supply one armored OpenPGP public key"))?;
    let mut payload = String::new();
    let mut data_started = false;
    let mut checksum_seen = false;
    let mut checksum = None;
    for line in body.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if !data_started && (line.starts_with("Version:") || line.starts_with("Comment:")) {
            continue;
        }
        data_started = true;
        if let Some(encoded_checksum) = line.strip_prefix('=') {
            if checksum_seen || line.len() != 5 {
                return Err(invalid("Malformed GPG armor checksum"));
            }
            checksum_seen = true;
            checksum = Some(STANDARD.decode(encoded_checksum)?);
        } else {
            if checksum_seen {
                return Err(invalid("Trailing data in GPG armor"));
            }
            payload.push_str(line);
        }
    }
    let bytes = STANDARD.decode(payload)?;
    // CRC is an armor corruption check, not an authenticity check. The pinned
    // pgp reader does not retain incremental CRC state correctly; check the
    // complete decoded buffer directly instead.
    if let Some(checksum) = checksum {
        let crc = crc24::hash_raw(&bytes).to_be_bytes();
        if checksum.as_slice() != &crc[1..] {
            return Err(invalid("Invalid GPG armor checksum"));
        }
    }
    let packets = recipient_packets(&bytes)?;
    let mut primaries = 0;
    for packet in &packets {
        match packet {
            Packet::PublicKey(_) => primaries += 1,
            Packet::PublicSubkey(_) | Packet::UserId(_) | Packet::UserAttribute(_) => {}
            Packet::Signature(sig) => {
                if matches!(
                    sig.typ(),
                    Some(
                        SignatureType::KeyRevocation
                            | SignatureType::SubkeyRevocation
                            | SignatureType::CertRevocation
                    )
                ) {
                    return Err(invalid(
                        "Recipient contains a revocation; use a current public key",
                    ));
                }
            }
            _ => return Err(invalid("Unexpected or secret packet in OpenPGP public key")),
        }
    }
    if primaries != 1 || !matches!(packets.first(), Some(Packet::PublicKey(_))) {
        return Err(invalid("Supply exactly one OpenPGP public key"));
    }
    let mut key = SignedPublicKey::from_bytes(Cursor::new(bytes))?;
    let canonical = pgp::ser::Serialize::to_bytes(&key)?;
    let retained = recipient_packets(&canonical)?;
    if retained.len() != packets.len() {
        return Err(invalid("Unsupported or unbound packets in OpenPGP key"));
    }
    // Third-party certifications are not needed for encryption. Only signatures
    // cryptographically verified under the primary may supply policy metadata;
    // issuer IDs alone are not authentication. Keep the packet-accounting check
    // above, before intentionally discarding unrelated certifications.
    for user in &mut key.details.users {
        user.signatures.retain(|sig| {
            sig.verify_certification(&key.primary_key, Tag::UserId, &user.id)
                .is_ok()
        });
    }
    for attribute in &mut key.details.user_attributes {
        attribute.signatures.retain(|sig| {
            sig.verify_certification(&key.primary_key, Tag::UserAttribute, &attribute.attr)
                .is_ok()
        });
    }
    key.verify_bindings()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut self_sigs: Vec<&Signature> = key.details.direct_signatures.iter().collect();
    for user in &key.details.users {
        self_sigs.extend(user.signatures.iter());
    }
    let latest = self_sigs
        .into_iter()
        .filter(|s| s.created().is_some_and(|t| u64::from(t.as_secs()) <= now))
        .max_by_key(|s| s.created().map(|t| t.as_secs()));
    if !latest.is_some_and(|sig| live(sig, key.created_at().as_secs(), now)) {
        return Err(invalid(
            "Recipient primary key is expired or lacks a current self-signature",
        ));
    }
    Ok(key)
}

fn encryption_subkey(key: &SignedPublicKey) -> Result<&pgp::composed::SignedPublicSubKey> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    key.public_subkeys
        .iter()
        .filter(|sub| sub.algorithm().can_encrypt())
        .filter(|sub| {
            sub.signatures
                .iter()
                .filter(|s| s.created().is_some_and(|t| u64::from(t.as_secs()) <= now))
                .max_by_key(|s| s.created().map(|t| t.as_secs()))
                .is_some_and(|sig| {
                    let flags = sig.key_flags();
                    sig.typ() == Some(SignatureType::SubkeyBinding)
                        && live(sig, sub.created_at().as_secs(), now)
                        && (flags.encrypt_comms() || flags.encrypt_storage())
                })
        })
        .max_by_key(|sub| sub.created_at().as_secs())
        .ok_or_else(|| invalid("No valid encryption subkey in this OpenPGP public key"))
}

pub fn recipient_info(armor: &str) -> Result<(String, String)> {
    let key = parse_recipient(armor)?;
    let subkey = encryption_subkey(&key)?;
    Ok((
        key.fingerprint().to_string(),
        subkey.fingerprint().to_string(),
    ))
}

pub struct GpgExport {
    key: SignedPublicKey,
    subkey: usize,
}
impl GpgExport {
    pub fn prepare(armor: &str, expected_fingerprint: &str) -> Result<Self> {
        let key = parse_recipient(armor)?;
        if key.fingerprint().to_string() != expected_fingerprint {
            return Err(invalid("OpenPGP recipient changed after review"));
        }
        let selected = encryption_subkey(&key)?.fingerprint();
        let subkey = key
            .public_subkeys
            .iter()
            .position(|s| s.fingerprint() == selected)
            .ok_or_else(|| invalid("Encryption subkey missing"))?;
        Ok(Self { key, subkey })
    }
    pub fn encrypt(&self, private: &PrivateKey) -> Result<Vec<u8>> {
        let plaintext = private.to_openssh(LineEnding::LF)?;
        // Borrow the zeroizing buffer; do not copy the plaintext into Bytes.
        let mut message = MessageBuilder::from_reader("ca", Cursor::new(plaintext.as_bytes()))
            .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
        message.encrypt_to_key(OsRng, &self.key.public_subkeys[self.subkey])?;
        Ok(message.to_vec(OsRng)?)
    }
}
pub fn gpg(private: &PrivateKey, armor: &str, expected_fingerprint: &str) -> Result<Vec<u8>> {
    GpgExport::prepare(armor, expected_fingerprint)?.encrypt(private)
}
