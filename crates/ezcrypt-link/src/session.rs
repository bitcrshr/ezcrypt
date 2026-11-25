//! The Iroh session. The machine listens on an ephemeral endpoint and shows an
//! `Offer`; the phone dials it and sends one `Reply` on a bidirectional stream;
//! the machine checks it and answers with an `Outcome`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iroh::endpoint::{
    Connection, ConnectionError, ReadError, ReadToEndError, SendStream, VarInt, WriteError, presets,
};
use iroh::{Endpoint, EndpointAddr, RelayMode};
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use tokio::time::timeout;

use crate::offer::check_fields;
use crate::reply::MAX_JSON;
use crate::{ALPN, Kind, LinkError, Offer, Outcome, Payload, Reply};

const MAX_OUTCOME: usize = 4 * 1024;
/// How long `bind` waits for a relay before showing the offer anyway.
const ONLINE_WAIT: Duration = Duration::from_secs(10);
/// How long one dialer gets to finish the handshake and send its reply.
const RECEIVE_WAIT: Duration = Duration::from_secs(30);
/// How long to wait for the peer to close after sending an outcome.
const CLOSE_WAIT: Duration = Duration::from_secs(5);
const CONNECT_WAIT: Duration = Duration::from_secs(30);
/// The machine may wait on its user before answering.
const OUTCOME_WAIT: Duration = Duration::from_secs(11 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Number 0's relays and address lookup.
    N0,
    /// Direct addresses only, no relays or lookup. For tests.
    Local,
}

/// What a listener offers to receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub kind: Kind,
    pub host: String,
    pub user: String,
    /// SSH wire public-key blob; required for Enroll, absent for Trust.
    pub subject: Option<Vec<u8>>,
}

async fn bind_endpoint(network: Network, listen: bool) -> Result<Endpoint, LinkError> {
    let builder = match network {
        Network::N0 => Endpoint::builder(presets::N0),
        Network::Local => Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled),
    };
    let builder = if listen {
        builder.alpns(vec![ALPN.to_vec()])
    } else {
        builder
    };
    builder
        .bind()
        .await
        .map_err(|e| LinkError::Network(e.to_string()))
}

/// The machine's side of a session. It hands out at most one successful reply.
pub struct Listener {
    endpoint: Endpoint,
    secret: [u8; 16],
    request: Request,
    claimed: AtomicBool,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("endpoint", &self.endpoint.id())
            .field("secret", &"<redacted>")
            .field("request", &self.request)
            .field("claimed", &self.claimed)
            .finish()
    }
}

impl Listener {
    pub async fn bind(network: Network, request: Request) -> Result<Listener, LinkError> {
        // `Offer::to_url` does not validate, so check here that the offer will parse.
        check_fields(
            request.kind,
            &request.host,
            &request.user,
            request.subject.as_deref(),
        )?;
        let endpoint = bind_endpoint(network, true).await?;
        if network == Network::N0 {
            // Without a relay the phone may not reach us, but pasting still works.
            let _ = timeout(ONLINE_WAIT, endpoint.online()).await;
        }
        let mut secret = [0u8; 16];
        OsRng.fill_bytes(&mut secret);
        Ok(Listener {
            endpoint,
            secret,
            request,
            claimed: AtomicBool::new(false),
        })
    }

    pub fn offer(&self) -> Offer {
        Offer {
            kind: self.request.kind,
            endpoint: self.endpoint.id(),
            secret: self.secret,
            host: self.request.host.clone(),
            user: self.request.user.clone(),
            subject: self.request.subject.clone(),
        }
    }

    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Wait for a delivery that passes the checks. Failed deliveries get an
    /// `Outcome::Error` and the wait continues, so this returns only once per
    /// session; after that, every delivery is refused.
    pub async fn next(&self) -> Result<Incoming, LinkError> {
        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or_else(|| LinkError::Network("the listener has closed".into()))?;
            let Ok(Some((conn, send, body))) = timeout(RECEIVE_WAIT, receive(incoming)).await
            else {
                continue;
            };
            match body.and_then(|json| self.check(Reply::from_json(&json)?)) {
                Ok(payload) => {
                    return Ok(Incoming {
                        payload,
                        conn,
                        send,
                    });
                }
                Err(e) => {
                    let outcome = Outcome::Error {
                        message: e.to_string(),
                    };
                    tokio::spawn(send_outcome(conn, send, outcome));
                }
            }
        }
    }

    /// The paste fallback, with the same checks as `next`.
    pub fn accept_pasted(&self, text: &str) -> Result<Payload, LinkError> {
        self.check(Reply::from_text(text)?)
    }

    pub async fn close(self) {
        self.endpoint.close().await;
    }

    /// Version and shape are checked by `Reply::from_json`.
    fn check(&self, reply: Reply) -> Result<Payload, LinkError> {
        if !bool::from(reply.secret.ct_eq(&self.secret)) {
            return Err(LinkError::WrongSecret);
        }
        match (self.request.kind, &reply.payload) {
            (Kind::Trust, Payload::CaKey { .. }) | (Kind::Enroll, Payload::Certificate { .. }) => {}
            _ => return Err(LinkError::WrongPayload),
        }
        if self.claimed.swap(true, Ordering::SeqCst) {
            return Err(LinkError::Rejected(
                "this session already received a reply".into(),
            ));
        }
        Ok(reply.payload)
    }
}

/// Accept one connection and read its reply. `None` means drop it silently.
async fn receive(
    incoming: iroh::endpoint::Incoming,
) -> Option<(Connection, SendStream, Result<Vec<u8>, LinkError>)> {
    let conn = incoming.await.ok()?;
    let (send, mut recv) = conn.accept_bi().await.ok()?;
    let body = match recv.read_to_end(MAX_JSON).await {
        Ok(json) => Ok(json),
        Err(ReadToEndError::TooLong) => Err(LinkError::Malformed("reply is too large".into())),
        Err(ReadToEndError::Read(_)) => return None,
    };
    Some((conn, send, body))
}

/// A delivery that passed the checks, waiting for the machine's answer.
pub struct Incoming {
    pub payload: Payload,
    conn: Connection,
    send: SendStream,
}

impl std::fmt::Debug for Incoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Incoming")
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

impl Incoming {
    pub async fn respond(self, outcome: Outcome) -> Result<(), LinkError> {
        send_outcome(self.conn, self.send, outcome).await
    }
}

async fn send_outcome(
    conn: Connection,
    mut send: SendStream,
    outcome: Outcome,
) -> Result<(), LinkError> {
    send.write_all(&encode_outcome(outcome))
        .await
        .map_err(write_error)?;
    send.finish().map_err(|_| LinkError::Unreachable)?;
    // Dropping the connection now could discard the outcome; let the peer close it.
    let _ = timeout(CLOSE_WAIT, conn.closed()).await;
    Ok(())
}

fn message_mut(outcome: &mut Outcome) -> &mut String {
    match outcome {
        Outcome::Ok { message } | Outcome::Error { message } => message,
    }
}

/// Serialize an outcome, shortening its message to fit the size limit.
fn encode_outcome(mut outcome: Outcome) -> Vec<u8> {
    let json = serde_json::to_vec(&outcome).expect("outcome serializes");
    if json.len() <= MAX_OUTCOME {
        return json;
    }
    let full = std::mem::take(message_mut(&mut outcome));
    let envelope = serde_json::to_vec(&outcome).expect("outcome serializes");
    let mut budget = MAX_OUTCOME.saturating_sub(envelope.len());
    let kept = message_mut(&mut outcome);
    for c in full.chars() {
        // A char's escaped size inside a JSON string, without the quotes.
        let cost = serde_json::to_string(&c).expect("char serializes").len() - 2;
        if cost > budget {
            break;
        }
        budget -= cost;
        kept.push(c);
    }
    serde_json::to_vec(&outcome).expect("outcome serializes")
}

/// The phone's side: dial the offer's endpoint and deliver the payload.
pub async fn deliver(
    network: Network,
    offer: &Offer,
    payload: Payload,
) -> Result<Outcome, LinkError> {
    deliver_to(
        network,
        EndpointAddr::from(offer.endpoint),
        offer.secret,
        payload,
        CONNECT_WAIT,
    )
    .await
}

pub async fn deliver_to(
    network: Network,
    addr: EndpointAddr,
    secret: [u8; 16],
    payload: Payload,
    connect_timeout: Duration,
) -> Result<Outcome, LinkError> {
    let json = Reply { secret, payload }.to_json();
    if json.len() > MAX_JSON {
        return Err(LinkError::Malformed("reply is too large".into()));
    }
    let endpoint = bind_endpoint(network, false).await?;
    let conn = match timeout(connect_timeout, endpoint.connect(addr, ALPN)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(_)) | Err(_) => {
            // No peer to notify, and draining the abandoned handshake takes
            // seconds, so finish closing in the background.
            tokio::spawn(async move { endpoint.close().await });
            return Err(LinkError::Unreachable);
        }
    };
    let result = exchange(&conn, &json).await;
    drop(conn);
    endpoint.close().await;
    result
}

async fn exchange(conn: &Connection, json: &[u8]) -> Result<Outcome, LinkError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(lost)?;
    send.write_all(json).await.map_err(write_error)?;
    send.finish().map_err(|_| LinkError::Unreachable)?;
    let body = match timeout(OUTCOME_WAIT, recv.read_to_end(MAX_OUTCOME)).await {
        Err(_) => return Err(LinkError::Timeout),
        Ok(Err(ReadToEndError::TooLong)) => {
            return Err(LinkError::Malformed("outcome is too large".into()));
        }
        Ok(Err(ReadToEndError::Read(e))) => return Err(read_error(e)),
        Ok(Ok(body)) => body,
    };
    conn.close(VarInt::from_u32(0), b"done");
    serde_json::from_slice(&body).map_err(|_| LinkError::Malformed("bad outcome".into()))
}

fn lost(_: ConnectionError) -> LinkError {
    LinkError::Unreachable
}

fn write_error(e: WriteError) -> LinkError {
    match e {
        WriteError::ConnectionLost(_) => LinkError::Unreachable,
        other => LinkError::Network(other.to_string()),
    }
}

fn read_error(e: ReadError) -> LinkError {
    match e {
        ReadError::ConnectionLost(_) => LinkError::Unreachable,
        other => LinkError::Network(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_outcomes_are_shortened_to_fit() {
        for message in ["é".repeat(5000), "\u{1}".repeat(5000), "a".repeat(4090)] {
            let json = encode_outcome(Outcome::Error { message });
            assert!(json.len() <= MAX_OUTCOME, "{}", json.len());
            match serde_json::from_slice(&json).unwrap() {
                Outcome::Error { message } => assert!(!message.is_empty()),
                other => panic!("{other:?}"),
            }
        }
        let short = Outcome::Ok {
            message: "done".into(),
        };
        let json = encode_outcome(short.clone());
        assert_eq!(serde_json::from_slice::<Outcome>(&json).unwrap(), short);
    }
}
