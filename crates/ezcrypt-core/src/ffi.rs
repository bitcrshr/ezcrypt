//! Synchronous C boundary: JSON carries public metadata/ciphertext only.
//! Callbacks perform hardware operations; plaintext CA keys remain in Rust.
use crate::{
    certificate::{self, Purpose, Request},
    export, invalid,
    vault::{self, Record},
    Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use signature::Signer;
use ssh_key::{
    public::{EcdsaPublicKey, KeyData},
    HashAlg, PublicKey, Signature, SigningKey,
};
use std::{
    ffi::{c_char, c_void, CString},
    slice,
};
use zeroize::Zeroizing;

type Callback = unsafe extern "C" fn(*mut c_void, u32, *const u8, usize, *mut u8, usize) -> i32;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    CreateSoftware {
        id: String,
        algorithm: String,
        purpose: Purpose,
        device_public: String,
    },
    HardwarePublic {
        public: String,
    },
    Prepare {
        request: Request,
        ca_public: String,
    },
    IssueSoftware {
        record: Record,
        id: String,
        purpose: Purpose,
        request: Request,
    },
    IssueHardware {
        public: String,
        purpose: Purpose,
        request: Request,
    },
    Recipient {
        armor: String,
    },
    Export {
        record: Record,
        id: String,
        purpose: Purpose,
        format: String,
        armor: String,
        fingerprint: String,
    },
}

fn hardware_public(bytes: &[u8]) -> Result<PublicKey> {
    let public = EcdsaPublicKey::from_sec1_bytes(bytes)?;
    if public.curve() != ssh_key::EcdsaCurve::NistP256 {
        return Err(invalid("Hardware CAs require P-256"));
    }
    Ok(PublicKey::new(KeyData::Ecdsa(public), ""))
}
struct Hardware {
    public: PublicKey,
    callback: Callback,
    context: *mut c_void,
}
impl Signer<Signature> for Hardware {
    fn try_sign(&self, message: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let der =
            call(self.callback, self.context, 1, message).map_err(|_| signature::Error::new())?;
        let sig = p256::ecdsa::Signature::from_der(&der).map_err(|_| signature::Error::new())?;
        Signature::try_from(sig).map_err(|_| signature::Error::new())
    }
}
impl SigningKey for Hardware {
    fn public_key(&self) -> KeyData {
        self.public.key_data().clone()
    }
}

fn call(
    callback: Callback,
    context: *mut c_void,
    op: u32,
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(vec![0u8; 256]);
    let len = unsafe {
        callback(
            context,
            op,
            input.as_ptr(),
            input.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if len < 0 || len as usize > out.len() {
        return Err(invalid(
            "Hardware operation failed or authentication was cancelled",
        ));
    }
    out.truncate(len as usize);
    Ok(out)
}
fn dispatch(
    command: Command,
    secret: &[u8],
    callback: Option<Callback>,
    context: *mut c_void,
) -> Result<Value> {
    match command {
        Command::CreateSoftware {
            id,
            algorithm,
            purpose,
            device_public,
        } => {
            let record = vault::create(&id, &algorithm, purpose, &STANDARD.decode(device_public)?)?;
            Ok(
                json!({"fingerprint": record.fingerprint()?, "public_key": record.public_key, "record": record}),
            )
        }
        Command::HardwarePublic { public } => {
            let key = hardware_public(&STANDARD.decode(public)?)?;
            Ok(
                json!({"public_key": key.to_openssh()?, "fingerprint": key.fingerprint(HashAlg::Sha256).to_string()}),
            )
        }
        Command::Prepare { request, ca_public } => {
            let normalized = request.normalized()?;
            let ca = certificate::parse_public(&ca_public)?;
            let subject = certificate::parse_public(&request.public_key)?;
            Ok(
                json!({"request": normalized, "duplicate_id": request.duplicate_id(&ca)?, "subject_fingerprint": subject.fingerprint(HashAlg::Sha256).to_string()}),
            )
        }
        Command::IssueSoftware {
            record,
            id,
            purpose,
            request,
        } => {
            let callback = callback.ok_or_else(|| invalid("Hardware callback missing"))?;
            vault::with_key(
                &record,
                &id,
                purpose,
                |peer| call(callback, context, 2, peer),
                |key| {
                    Ok(serde_json::to_value(certificate::issue(
                        &request, purpose, key,
                    )?)?)
                },
            )
        }
        Command::IssueHardware {
            public,
            purpose,
            request,
        } => {
            let callback = callback.ok_or_else(|| invalid("Hardware callback missing"))?;
            let hardware = Hardware {
                public: hardware_public(&STANDARD.decode(public)?)?,
                callback,
                context,
            };
            Ok(serde_json::to_value(certificate::issue(
                &request, purpose, &hardware,
            )?)?)
        }
        Command::Recipient { armor } => {
            let (fingerprint, subkey) = export::recipient_info(&armor)?;
            Ok(json!({"fingerprint": fingerprint, "subkey": subkey}))
        }
        Command::Export {
            record,
            id,
            purpose,
            format,
            armor,
            fingerprint,
        } => {
            let callback = callback.ok_or_else(|| invalid("Hardware callback missing"))?;
            // Validate public recipient material and do slow KDF work before
            // requesting the device factor or decrypting the CA.
            let passphrase = if format == "passphrase" {
                Some(export::PassphraseExport::prepare(secret)?)
            } else {
                None
            };
            let gpg = if format == "gpg" {
                Some(export::GpgExport::prepare(&armor, &fingerprint)?)
            } else {
                None
            };
            if passphrase.is_none() && gpg.is_none() {
                return Err(invalid("Unsupported export format"));
            }
            vault::with_key(
                &record,
                &id,
                purpose,
                |peer| call(callback, context, 2, peer),
                |key| match format.as_str() {
                    "passphrase" => Ok(
                        json!({"data": STANDARD.encode(passphrase.as_ref().ok_or_else(|| invalid("Passphrase export missing"))?.encrypt(key)?), "extension": "key"}),
                    ),
                    "gpg" => Ok(
                        json!({"data": STANDARD.encode(gpg.as_ref().ok_or_else(|| invalid("GPG export missing"))?.encrypt(key)?), "extension": "asc"}),
                    ),
                    _ => Err(invalid("Unsupported export format")),
                },
            )
        }
    }
}

/// # Safety
/// All non-null inputs must point to valid buffers of the given lengths for this
/// synchronous call. callback/context must remain valid until it returns. Free the
/// returned C string exactly once with ezcrypt_free. Never pass private CA bytes.
#[no_mangle]
pub unsafe extern "C" fn ezcrypt_call(
    input: *const u8,
    len: usize,
    secret: *const u8,
    secret_len: usize,
    callback: Option<Callback>,
    context: *mut c_void,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| -> Result<Value> {
        if input.is_null()
            || len > 1024 * 1024
            || secret_len > 16_384
            || (secret.is_null() && secret_len != 0)
        {
            return Err(invalid("Invalid request buffer"));
        }
        let command = serde_json::from_slice(slice::from_raw_parts(input, len))?;
        let password = Zeroizing::new(if secret_len == 0 {
            vec![]
        } else {
            slice::from_raw_parts(secret, secret_len).to_vec()
        });
        dispatch(command, &password, callback, context)
    });
    let response = match result {
        Ok(Ok(value)) => json!({"ok": value}),
        Ok(Err(error)) => json!({"error": error.to_string()}),
        Err(_) => json!({"error": "Cryptographic operation failed"}),
    };
    CString::new(response.to_string())
        .expect("JSON escapes nul")
        .into_raw()
}
/// # Safety
/// pointer must be returned by ezcrypt_call and not previously freed.
#[no_mangle]
pub unsafe extern "C" fn ezcrypt_free(pointer: *mut c_char) {
    if !pointer.is_null() {
        drop(CString::from_raw(pointer));
    }
}
