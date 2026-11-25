//! OpenSSH certificate framing. Crypto and key formats are supplied by ssh-key.
//! We frame certificates here because ssh-key 0.6 rejects the OpenSSH u64::MAX
//! forever sentinel. Never convert this sentinel through a date/time type.
use crate::{invalid, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::Verifier;
use ssh_encoding::{Decode, Reader};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey, Signature, SigningKey};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    User,
    Host,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub public_key: String,
    pub purpose: Purpose,
    pub key_id: String,
    // Strings at the FFI boundary preserve all 64 bits in JSON consumers.
    pub serial: String,
    pub principals: Vec<String>,
    pub all_principals: bool,
    pub valid_after: u64,
    pub valid_before: Option<u64>,
    pub critical_options: BTreeMap<String, String>,
    pub extensions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Issued {
    pub certificate: String,
    pub subject_fingerprint: String,
    pub ca_fingerprint: String,
    pub duplicate_id: String,
    pub request: Request,
}

pub fn algorithm(name: &str) -> Result<Algorithm> {
    Ok(match name {
        "ed25519" => Algorithm::Ed25519,
        "p256" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        "p384" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        "p521" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        _ => return Err(invalid("Unsupported algorithm")),
    })
}

pub fn parse_public(input: &str) -> Result<PublicKey> {
    if input.len() > 16_384 {
        return Err(invalid("Public key is too large"));
    }
    let key = PublicKey::from_openssh(input.trim())?;
    match key.algorithm() {
        Algorithm::Ed25519
        | Algorithm::Ecdsa { .. }
        | Algorithm::SkEd25519
        | Algorithm::SkEcdsaSha2NistP256 => Ok(key),
        _ => Err(invalid(
            "Use an Ed25519, P-256/384/521, Ed25519-SK, or ECDSA-SK public key",
        )),
    }
}

impl Request {
    pub fn normalized(&self) -> Result<Self> {
        let mut request = self.clone();
        request.public_key = parse_public(&self.public_key)?.to_openssh()?;
        let serial = self
            .serial
            .parse::<u64>()
            .map_err(|_| invalid("Serial must be a positive 64-bit integer"))?;
        if serial == 0 {
            return Err(invalid("Serial must be greater than zero"));
        }
        request.serial = serial.to_string();
        if self.valid_after > i64::MAX as u64
            || self
                .valid_before
                .is_some_and(|end| end <= self.valid_after || end > i64::MAX as u64)
        {
            return Err(invalid("Validity must end after it starts"));
        }
        if self.key_id.len() > 1024 || self.key_id.chars().any(char::is_control) {
            return Err(invalid("Invalid key ID"));
        }
        if self.principals.len() > 256 {
            return Err(invalid("Too many principals"));
        }
        for principal in &self.principals {
            if principal.is_empty()
                || principal.len() > 255
                || principal
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == ',')
            {
                return Err(invalid(
                    "Principals must be nonempty names without whitespace or commas",
                ));
            }
        }
        request.principals.sort();
        request.principals.dedup();
        if self.all_principals != request.principals.is_empty() {
            return Err(invalid(
                "Supply principals, or explicitly select all principals",
            ));
        }
        if self.purpose == Purpose::Host
            && (!self.critical_options.is_empty() || !self.extensions.is_empty())
        {
            return Err(invalid(
                "User permissions cannot be applied to host certificates",
            ));
        }
        for (name, value) in &self.critical_options {
            if value.is_empty() || value.len() > 4096 || value.contains('\0') {
                return Err(invalid("Invalid critical option value"));
            }
            match name.as_str() {
                "force-command" => {}
                "source-address" => {
                    let mut networks = Vec::new();
                    for cidr in value.split(',') {
                        let (ip, prefix) = cidr
                            .trim()
                            .split_once('/')
                            .ok_or_else(|| invalid("Source addresses require CIDR notation"))?;
                        let ip: std::net::IpAddr = ip.parse()?;
                        let prefix: u8 = prefix.parse()?;
                        if prefix > if ip.is_ipv4() { 32 } else { 128 } {
                            return Err(invalid("Invalid network prefix"));
                        }
                        let host_bits = match ip {
                            std::net::IpAddr::V4(ip) => {
                                u32::from(ip) & (u32::MAX.checked_shr(prefix.into()).unwrap_or(0))
                                    != 0
                            }
                            std::net::IpAddr::V6(ip) => {
                                u128::from(ip) & (u128::MAX.checked_shr(prefix.into()).unwrap_or(0))
                                    != 0
                            }
                        };
                        if host_bits {
                            return Err(invalid("Source CIDRs must use the network address (for example, 192.0.2.0/24), or /32 for one IPv4 address and /128 for one IPv6 address"));
                        }
                        networks.push(format!("{ip}/{prefix}"));
                    }
                    networks.sort();
                    networks.dedup();
                    request
                        .critical_options
                        .insert(name.clone(), networks.join(","));
                }
                _ => return Err(invalid("Unsupported critical option")),
            }
        }
        for (name, value) in &self.extensions {
            if !value.is_empty()
                || !matches!(
                    name.as_str(),
                    "permit-pty"
                        | "permit-agent-forwarding"
                        | "permit-port-forwarding"
                        | "permit-X11-forwarding"
                        | "permit-user-rc"
                )
            {
                return Err(invalid("Unsupported certificate permission"));
            }
        }
        Ok(request)
    }

    pub fn duplicate_id(&self, ca: &PublicKey) -> Result<String> {
        let request = self.normalized()?;
        let subject = parse_public(&request.public_key)?;
        let params = serde_json::to_vec(&(
            ca.fingerprint(HashAlg::Sha256).to_string(),
            subject.fingerprint(HashAlg::Sha256).to_string(),
            request.purpose,
            request.principals,
            request.critical_options,
            request.extensions,
        ))?;
        Ok(format!("{:x}", Sha256::digest(params)))
    }
}

pub fn overlaps(a_start: u64, a_end: Option<u64>, b_start: u64, b_end: Option<u64>) -> bool {
    a_start < b_end.unwrap_or(u64::MAX) && b_start < a_end.unwrap_or(u64::MAX)
}

pub fn issue(
    request: &Request,
    expected_purpose: Purpose,
    signer: &impl SigningKey,
) -> Result<Issued> {
    let request = request.normalized()?;
    if request.purpose != expected_purpose {
        return Err(invalid("Certificate purpose differs from this CA"));
    }
    let public = parse_public(&request.public_key)?;
    let ca = PublicKey::new(signer.public_key(), "");
    let ca_bytes = ca.to_bytes()?;
    let public_bytes = public.to_bytes()?;
    let alg_len = u32::from_be_bytes(public_bytes[..4].try_into()?) as usize;
    let cert_alg = public.algorithm().to_certificate_type();
    let mut wire = Vec::new();
    string(&mut wire, cert_alg.as_bytes());
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    string(&mut wire, &nonce);
    wire.extend_from_slice(&public_bytes[4 + alg_len..]);
    wire.extend_from_slice(&request.serial.parse::<u64>()?.to_be_bytes());
    wire.extend_from_slice(
        &(if request.purpose == Purpose::User {
            1u32
        } else {
            2
        })
        .to_be_bytes(),
    );
    string(&mut wire, request.key_id.as_bytes());
    let mut principals = Vec::new();
    for p in &request.principals {
        string(&mut principals, p.as_bytes());
    }
    string(&mut wire, &principals);
    wire.extend_from_slice(&request.valid_after.to_be_bytes());
    wire.extend_from_slice(&request.valid_before.unwrap_or(u64::MAX).to_be_bytes());
    options(&mut wire, &request.critical_options);
    options(&mut wire, &request.extensions);
    string(&mut wire, &[]); // reserved
    string(&mut wire, &ca_bytes);
    let signature = signer.try_sign(&wire)?;
    Verifier::verify(&ca, &wire, &signature)?; // Includes hardware callback output verification.
    string(&mut wire, &Vec::<u8>::try_from(signature)?);
    Ok(Issued {
        certificate: format!("{cert_alg} {} ezcrypt", STANDARD.encode(&wire)),
        subject_fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        ca_fingerprint: ca.fingerprint(HashAlg::Sha256).to_string(),
        duplicate_id: request.duplicate_id(&ca)?,
        request,
    })
}

#[derive(Clone, Debug)]
pub struct Inspected {
    pub purpose: Purpose,
    pub subject: PublicKey,
    pub key_id: String,
    pub serial: u64,
    pub principals: Vec<String>,
    pub valid_after: u64,
    /// `None` is the OpenSSH forever sentinel (`u64::MAX` on the wire).
    pub valid_before: Option<u64>,
    pub ca: PublicKey,
}

/// Parses an OpenSSH certificate line and verifies its CA signature. This is
/// the inverse of `issue` and does not use ssh-key's `Certificate`, which
/// rejects the forever sentinel.
pub fn inspect(certificate: &str) -> Result<Inspected> {
    if certificate.len() > 16_384 {
        return Err(invalid("Certificate is too large"));
    }
    let mut fields = certificate.split_whitespace();
    let (line_type, encoded) = fields
        .next()
        .zip(fields.next())
        .ok_or_else(|| invalid("Malformed certificate"))?;
    let wire = STANDARD.decode(encoded)?;
    let total = wire.len();
    let mut reader = wire.as_slice();
    let cert_type = String::decode(&mut reader)?;
    if cert_type != line_type {
        return Err(invalid("Certificate type does not match its contents"));
    }
    // (base algorithm, number of subject key fields besides the application)
    let (base, key_fields, application) = match cert_type.as_str() {
        "ssh-ed25519-cert-v01@openssh.com" => ("ssh-ed25519", 1, false),
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => ("ecdsa-sha2-nistp256", 2, false),
        "ecdsa-sha2-nistp384-cert-v01@openssh.com" => ("ecdsa-sha2-nistp384", 2, false),
        "ecdsa-sha2-nistp521-cert-v01@openssh.com" => ("ecdsa-sha2-nistp521", 2, false),
        "sk-ssh-ed25519-cert-v01@openssh.com" => ("sk-ssh-ed25519@openssh.com", 1, true),
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => {
            ("sk-ecdsa-sha2-nistp256@openssh.com", 2, true)
        }
        _ => return Err(invalid("Unsupported certificate type")),
    };
    let _nonce = Vec::<u8>::decode(&mut reader)?;
    let mut subject_blob = Vec::new();
    string(&mut subject_blob, base.as_bytes());
    for _ in 0..key_fields + usize::from(application) {
        string(&mut subject_blob, &Vec::<u8>::decode(&mut reader)?);
    }
    let subject = PublicKey::from_bytes(&subject_blob)?;
    let serial = u64::decode(&mut reader)?;
    let purpose = match u32::decode(&mut reader)? {
        1 => Purpose::User,
        2 => Purpose::Host,
        _ => return Err(invalid("Unknown certificate type")),
    };
    let key_id = String::decode(&mut reader)?;
    let principal_blob = Vec::<u8>::decode(&mut reader)?;
    let mut principal_reader = principal_blob.as_slice();
    let mut principals = Vec::new();
    while !principal_reader.is_empty() {
        principals.push(String::decode(&mut principal_reader)?);
    }
    let valid_after = u64::decode(&mut reader)?;
    let valid_before = match u64::decode(&mut reader)? {
        u64::MAX => None,
        end => Some(end),
    };
    let _critical_options = Vec::<u8>::decode(&mut reader)?;
    let _extensions = Vec::<u8>::decode(&mut reader)?;
    let _reserved = Vec::<u8>::decode(&mut reader)?;
    let ca = PublicKey::from_bytes(&Vec::<u8>::decode(&mut reader)?)?;
    if !matches!(ca.algorithm(), Algorithm::Ed25519 | Algorithm::Ecdsa { .. }) {
        return Err(invalid("Unsupported certificate authority key type"));
    }
    let signed = &wire[..total - reader.remaining_len()];
    let signature_bytes = Vec::<u8>::decode(&mut reader)?;
    if !reader.is_empty() {
        return Err(invalid("Trailing data after certificate signature"));
    }
    // Signature::decode ignores trailing bytes, so check the inner reader.
    let mut signature_reader = signature_bytes.as_slice();
    let signature = Signature::decode(&mut signature_reader)?;
    if !signature_reader.is_empty() {
        return Err(invalid("Trailing data inside certificate signature"));
    }
    if signature.algorithm() != ca.algorithm() {
        return Err(invalid(
            "Signature does not match the certificate authority",
        ));
    }
    Verifier::verify(&ca, signed, &signature)?;
    Ok(Inspected {
        purpose,
        subject,
        key_id,
        serial,
        principals,
        valid_after,
        valid_before,
        ca,
    })
}

pub(crate) fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn options(out: &mut Vec<u8>, values: &BTreeMap<String, String>) {
    let mut blob = Vec::new();
    for (name, value) in values {
        string(&mut blob, name.as_bytes());
        let mut data = Vec::new();
        if !value.is_empty() {
            string(&mut data, value.as_bytes());
        }
        string(&mut blob, &data);
    }
    string(out, &blob);
}
