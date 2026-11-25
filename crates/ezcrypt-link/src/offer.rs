use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use iroh::EndpointId;
use subtle::ConstantTimeEq;
use url::Url;

use crate::{LinkError, VERSION};

const MAX_URL: usize = 1024;
const MAX_HOST: usize = 253;
const MAX_USER: usize = 64;
const MAX_SUBJECT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Trust,
    Enroll,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Trust => "trust",
            Kind::Enroll => "enroll",
        }
    }
}

#[derive(Clone)]
pub struct Offer {
    pub kind: Kind,
    pub endpoint: EndpointId,
    pub secret: [u8; 16],
    pub host: String,
    pub user: String,
    /// SSH wire public-key blob; required for Enroll, absent for Trust.
    pub subject: Option<Vec<u8>>,
}

impl std::fmt::Debug for Offer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Offer")
            .field("kind", &self.kind)
            .field("endpoint", &self.endpoint)
            .field("secret", &"<redacted>")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("subject", &self.subject)
            .finish()
    }
}

impl PartialEq for Offer {
    fn eq(&self, other: &Self) -> bool {
        let secret: bool = self.secret.ct_eq(&other.secret).into();
        secret
            && self.kind == other.kind
            && self.endpoint == other.endpoint
            && self.host == other.host
            && self.user == other.user
            && self.subject == other.subject
    }
}

impl Eq for Offer {}

fn malformed(msg: &str) -> LinkError {
    LinkError::Malformed(msg.to_string())
}

/// Bidi format characters can make one name look like another.
fn is_bidi_format(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

pub(crate) fn check_text(name: &str, value: &str, max: usize) -> Result<(), LinkError> {
    if value.is_empty() {
        return Err(LinkError::Malformed(format!("{name} is empty")));
    }
    if value.len() > max {
        return Err(LinkError::Malformed(format!("{name} is too long")));
    }
    if value.chars().any(|c| c.is_control() || is_bidi_format(c)) {
        return Err(LinkError::Malformed(format!(
            "{name} contains control characters"
        )));
    }
    Ok(())
}

/// The checks on an offer's host, user and subject, shared by `Offer::from_url`
/// and `Listener::bind` so the URL a listener shows always parses.
pub(crate) fn check_fields(
    kind: Kind,
    host: &str,
    user: &str,
    subject: Option<&[u8]>,
) -> Result<(), LinkError> {
    check_text("host", host, MAX_HOST)?;
    check_text("user", user, MAX_USER)?;
    match (kind, subject) {
        (Kind::Trust, None) => Ok(()),
        (Kind::Trust, Some(_)) => Err(malformed("trust offer must not have a subject")),
        (Kind::Enroll, None) => Err(malformed("enroll offer is missing its subject")),
        (Kind::Enroll, Some(s)) if s.is_empty() || s.len() > MAX_SUBJECT => {
            Err(malformed("subject has a bad size"))
        }
        (Kind::Enroll, Some(_)) => Ok(()),
    }
}

impl Offer {
    pub fn to_url(&self) -> String {
        let mut url = Url::parse("ezcrypt://link").expect("static URL");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("v", &VERSION.to_string())
                .append_pair("k", self.kind.as_str())
                .append_pair("n", &B64.encode(self.endpoint.as_bytes()))
                .append_pair("s", &B64.encode(self.secret))
                .append_pair("h", &self.host)
                .append_pair("u", &self.user);
            if let Some(subject) = &self.subject {
                q.append_pair("p", &B64.encode(subject));
            }
        }
        url.to_string()
    }

    pub fn from_url(input: &str) -> Result<Offer, LinkError> {
        if input.len() > MAX_URL {
            return Err(malformed("link is too long"));
        }
        let url = Url::parse(input).map_err(|_| malformed("not a valid URL"))?;
        if url.scheme() != "ezcrypt" || url.host_str() != Some("link") {
            return Err(malformed("not an ezcrypt link"));
        }

        // Check the version first so a future format reports Version, not Malformed.
        let first_v = url.query_pairs().find(|(key, _)| key == "v");
        let first_v = first_v.ok_or_else(|| malformed("missing parameter v"))?.1;
        let theirs: u8 = first_v.parse().map_err(|_| malformed("bad version"))?;
        if theirs != VERSION {
            return Err(LinkError::Version { theirs });
        }

        let (mut v, mut k, mut n, mut s, mut h, mut u, mut p) =
            (None, None, None, None, None, None, None);
        for (key, value) in url.query_pairs() {
            let slot = match key.as_ref() {
                "v" => &mut v,
                "k" => &mut k,
                "n" => &mut n,
                "s" => &mut s,
                "h" => &mut h,
                "u" => &mut u,
                "p" => &mut p,
                other => return Err(LinkError::Malformed(format!("unknown parameter {other}"))),
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(LinkError::Malformed(format!("duplicate parameter {key}")));
            }
        }

        let missing = |name: &str| LinkError::Malformed(format!("missing parameter {name}"));
        v.ok_or_else(|| missing("v"))?;
        let kind = match k.ok_or_else(|| missing("k"))?.as_str() {
            "trust" => Kind::Trust,
            "enroll" => Kind::Enroll,
            _ => return Err(malformed("unknown kind")),
        };
        let endpoint_bytes: [u8; 32] = B64
            .decode(n.ok_or_else(|| missing("n"))?)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| malformed("bad endpoint"))?;
        let endpoint =
            EndpointId::from_bytes(&endpoint_bytes).map_err(|_| malformed("bad endpoint"))?;
        let secret: [u8; 16] = B64
            .decode(s.ok_or_else(|| missing("s"))?)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| malformed("bad secret"))?;
        let host = h.ok_or_else(|| missing("h"))?;
        let user = u.ok_or_else(|| missing("u"))?;
        let subject = match p {
            Some(p) => Some(B64.decode(p).map_err(|_| malformed("bad subject"))?),
            None => None,
        };
        check_fields(kind, &host, &user, subject.as_deref())?;

        Ok(Offer {
            kind,
            endpoint,
            secret,
            host,
            user,
            subject,
        })
    }
}
