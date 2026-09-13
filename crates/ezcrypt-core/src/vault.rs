//! Versioned, per-CA envelopes. The platform supplies only public keys and
//! authenticated ECDH results; CA private material never crosses the FFI.
use crate::{
    certificate::{algorithm, parse_public, Purpose},
    invalid, Result,
};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use ssh_key::{HashAlg, PrivateKey};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    pub id: String,
    pub algorithm: String,
    pub purpose: Purpose,
    pub public_key: String,
    pub device_public: Vec<u8>,
    pub ephemeral_public: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
impl Record {
    fn aad(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "ezcrypt-vault",
            self.version,
            &self.id,
            &self.algorithm,
            self.purpose,
            &self.public_key,
            &self.device_public,
            &self.ephemeral_public,
        ))?)
    }
    pub fn fingerprint(&self) -> Result<String> {
        Ok(parse_public(&self.public_key)?
            .fingerprint(HashAlg::Sha256)
            .to_string())
    }
}

fn derive(shared: &[u8], salt: &[u8], aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if shared.len() != 32 || salt.len() != 32 {
        return Err(invalid("Invalid key agreement result"));
    }
    let mut key = Zeroizing::new([0; 32]);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut info = b"ezcrypt/software-ca/v1\0".to_vec();
    info.extend_from_slice(aad);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| invalid("Key derivation failed"))?;
    Ok(key)
}

pub fn create(id: &str, alg: &str, purpose: Purpose, device_public: &[u8]) -> Result<Record> {
    if id.is_empty() || id.len() > 128 {
        return Err(invalid("Invalid CA identifier"));
    }
    let device = p256::PublicKey::from_sec1_bytes(device_public)?;
    let private = PrivateKey::random(&mut OsRng, algorithm(alg)?)?;
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let shared = ephemeral.diffie_hellman(&device);
    let mut record = Record {
        version: 1,
        id: id.into(),
        algorithm: alg.into(),
        purpose,
        public_key: private.public_key().to_openssh()?,
        device_public: device_public.to_vec(),
        ephemeral_public: ephemeral
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        salt: vec![0; 32],
        nonce: vec![0; 12],
        ciphertext: vec![],
    };
    OsRng.fill_bytes(&mut record.salt);
    OsRng.fill_bytes(&mut record.nonce);
    let aad = record.aad()?;
    let key = derive(shared.raw_secret_bytes(), &record.salt, &aad)?;
    let mut plaintext = private.to_bytes()?; // ssh-key returns Zeroizing<Vec<u8>>.
    Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| invalid("Encryption failed"))?
        .encrypt_in_place(Nonce::from_slice(&record.nonce), &aad, &mut *plaintext)
        .map_err(|_| invalid("Encryption failed"))?;
    record.ciphertext = plaintext.to_vec(); // ciphertext only
    Ok(record)
}

pub fn with_key<T>(
    record: &Record,
    expected_id: &str,
    expected_purpose: Purpose,
    agree: impl FnOnce(&[u8]) -> Result<Zeroizing<Vec<u8>>>,
    operation: impl FnOnce(&PrivateKey) -> Result<T>,
) -> Result<T> {
    if record.version != 1
        || record.id != expected_id
        || record.purpose != expected_purpose
        || record.nonce.len() != 12
        || record.ciphertext.len() > 16_384
    {
        return Err(invalid("Invalid or mismatched CA envelope"));
    }
    p256::PublicKey::from_sec1_bytes(&record.ephemeral_public)?;
    let shared = agree(&record.ephemeral_public)?;
    let aad = record.aad()?;
    let key = derive(&shared, &record.salt, &aad)?;
    drop(shared);
    let mut plaintext = Zeroizing::new(record.ciphertext.clone());
    Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| invalid("Decryption failed"))?
        .decrypt_in_place(Nonce::from_slice(&record.nonce), &aad, &mut *plaintext)
        .map_err(|_| invalid("CA authentication failed"))?;
    drop(key);
    let private = PrivateKey::from_bytes(&plaintext)?;
    drop(plaintext);
    if private.algorithm() != algorithm(&record.algorithm)?
        || private.public_key().key_data() != parse_public(&record.public_key)?.key_data()
    {
        return Err(invalid("CA public key does not match envelope"));
    }
    operation(&private)
}
