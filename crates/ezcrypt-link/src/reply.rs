use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::offer::check_text;
use crate::{LinkError, VERSION};

const PREFIX: &str = "ezcrypt1:";
pub(crate) const MAX_JSON: usize = 64 * 1024;
const MAX_NAME: usize = 256;
/// Base64 characters per line of `to_text`.
const LINE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Payload {
    CaKey { public_key: String, name: String },
    Certificate { certificate: String },
}

#[derive(Clone)]
pub struct Reply {
    pub secret: [u8; 16],
    pub payload: Payload,
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("secret", &"<redacted>")
            .field("payload", &self.payload)
            .finish()
    }
}

impl PartialEq for Reply {
    fn eq(&self, other: &Self) -> bool {
        let secret: bool = self.secret.ct_eq(&other.secret).into();
        secret && self.payload == other.payload
    }
}

impl Eq for Reply {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Ok { message: String },
    Error { message: String },
}

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u8,
    secret: String,
    payload: Payload,
}

#[derive(Deserialize)]
struct Header {
    v: u8,
}

fn malformed(msg: &str) -> LinkError {
    LinkError::Malformed(msg.to_string())
}

impl Reply {
    /// The paste-fallback text: the prefix and base64 JSON, broken after every
    /// `LINE` characters. Canonical-mode terminal input drops longer lines on
    /// macOS (over 1024 bytes); `from_text` ignores the line breaks.
    pub fn to_text(&self) -> String {
        let body = B64.encode(self.to_json());
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(LINE)
            .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
            .collect();
        format!("{PREFIX}{}", lines.join("\n"))
    }

    /// The reply JSON, as sent over the network and wrapped by `to_text`.
    pub fn to_json(&self) -> Vec<u8> {
        let wire = Wire {
            v: VERSION,
            secret: B64.encode(self.secret),
            payload: self.payload.clone(),
        };
        serde_json::to_vec(&wire).expect("reply serializes")
    }

    pub fn from_text(text: &str) -> Result<Reply, LinkError> {
        let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let body = compact
            .strip_prefix(PREFIX)
            .ok_or_else(|| malformed("missing ezcrypt1: prefix"))?;
        let json = B64.decode(body).map_err(|_| malformed("bad base64"))?;
        Reply::from_json(&json)
    }

    /// Parse and validate reply JSON; every path that reads a Reply from bytes uses this.
    pub fn from_json(json: &[u8]) -> Result<Reply, LinkError> {
        if json.len() > MAX_JSON {
            return Err(malformed("reply is too large"));
        }
        let header: Header = serde_json::from_slice(json).map_err(|_| malformed("bad JSON"))?;
        if header.v != VERSION {
            return Err(LinkError::ReplyVersion { theirs: header.v });
        }
        let wire: Wire = serde_json::from_slice(json).map_err(|_| malformed("bad reply"))?;
        let secret: [u8; 16] = B64
            .decode(wire.secret)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| malformed("bad secret"))?;
        if let Payload::CaKey { name, .. } = &wire.payload {
            check_text("name", name, MAX_NAME)?;
        }
        Ok(Reply {
            secret,
            payload: wire.payload,
        })
    }
}
