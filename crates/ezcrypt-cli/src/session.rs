//! Shows the offer and waits for the phone's reply, from the network or pasted.

use std::future::Future;
use std::time::Duration;

use anyhow::{Result, bail};
use ezcrypt_link::{Incoming, Kind, LinkError, Listener, Network, Outcome, Payload, Request};
use tokio::time::Instant;

use crate::input::Input;
use crate::qr;

const SESSION_WAIT: Duration = Duration::from_secs(10 * 60);
const MAX_URL: usize = 1024;
const MAX_PASTE: usize = 128 * 1024;
const PREFIX: &str = "ezcrypt1:";

pub enum Received {
    Network(Incoming, Listener),
    Pasted(Payload, Listener),
}

impl Received {
    pub fn payload(&self) -> &Payload {
        match self {
            Received::Network(incoming, _) => &incoming.payload,
            Received::Pasted(payload, _) => payload,
        }
    }
}

/// What one pasted line did to the accumulator.
#[derive(Debug, PartialEq)]
pub enum Paste {
    /// Not part of a reply.
    Ignored,
    /// A reply is being collected; more lines may complete it.
    Pending,
    Done(Payload),
    /// The reply failed. The accumulator has been reset.
    Failed(LinkError),
}

/// Collects a pasted reply, which spans several lines: `Reply::to_text` wraps
/// it, and continuation lines are joined until it parses or a blank line ends it.
#[derive(Default)]
pub struct PasteAccumulator {
    text: String,
    last: Option<LinkError>,
}

impl PasteAccumulator {
    pub fn push(
        &mut self,
        line: &str,
        accept: impl Fn(&str) -> Result<Payload, LinkError>,
    ) -> Paste {
        let line = line.trim();
        if line.starts_with(PREFIX) {
            // A reply starts here, even if an unfinished one came before it.
            self.text.clear();
            self.last = None;
        } else if self.text.is_empty() {
            return Paste::Ignored;
        } else if line.is_empty() {
            let error = self
                .last
                .take()
                .unwrap_or_else(|| LinkError::Malformed("incomplete reply".into()));
            self.text.clear();
            return Paste::Failed(error);
        }
        self.text.push_str(line);
        if self.text.len() > MAX_PASTE {
            self.text.clear();
            self.last = None;
            return Paste::Failed(LinkError::Malformed("reply is too large".into()));
        }
        match accept(&self.text) {
            Ok(payload) => {
                self.text.clear();
                Paste::Done(payload)
            }
            // A truncated reply looks malformed; later lines may complete it.
            Err(error @ LinkError::Malformed(_)) => {
                self.last = Some(error);
                Paste::Pending
            }
            Err(error) => {
                self.text.clear();
                self.last = None;
                Paste::Failed(error)
            }
        }
    }
}

pub fn check_url_len(url: &str) -> Result<()> {
    if url.len() > MAX_URL {
        bail!("hostname or username too long for a QR code");
    }
    Ok(())
}

pub async fn run(
    request: Request,
    fingerprint: Option<String>,
    input: &mut Input,
) -> Result<Received> {
    let kind = request.kind;
    let listener = Listener::bind(Network::N0, request).await?;
    let url = listener.offer().to_url();
    if let Err(e) = check_url_len(&url) {
        listener.close().await;
        return Err(e);
    }
    let code = match qr::render(&url) {
        Ok(code) => code,
        Err(e) => {
            listener.close().await;
            return Err(e);
        }
    };
    println!("{code}");
    if let Some(fingerprint) = fingerprint {
        println!("{fingerprint}");
    }
    if cfg!(windows) {
        println!(
            "If the code doesn't display, use Windows Terminal, or open this link on your phone:"
        );
    } else {
        println!("Or open this link on your phone:");
    }
    println!("{url}");
    let what = match kind {
        Kind::Enroll => "the certificate",
        Kind::Trust => "the CA key",
    };
    println!("\nScan the code with the ezcrypt app, or paste its reply here ({what}).");

    let deadline = Instant::now() + SESSION_WAIT;
    let mut paste = PasteAccumulator::default();
    let mut stdin_open = true;
    loop {
        tokio::select! {
            result = listener.next() => match result {
                Ok(incoming) => return Ok(Received::Network(incoming, listener)),
                Err(LinkError::WrongSecret) => {
                    eprintln!("Error: {}", LinkError::WrongSecret);
                }
                Err(e) => {
                    listener.close().await;
                    return Err(e.into());
                }
            },
            line = input.line(), if stdin_open => match line {
                None => stdin_open = false,
                Some(line) => match paste.push(&line, |t| listener.accept_pasted(t)) {
                    Paste::Ignored | Paste::Pending => {}
                    Paste::Done(payload) => return Ok(Received::Pasted(payload, listener)),
                    Paste::Failed(e) => eprintln!("Error: {e}"),
                },
            },
            _ = tokio::time::sleep_until(deadline) => {
                listener.close().await;
                bail!("Timed out after 10 minutes waiting for the phone. Run the command again.");
            }
            _ = tokio::signal::ctrl_c() => {
                listener.close().await;
                cancelled();
            }
        }
    }
}

fn cancelled() -> ! {
    eprintln!("Cancelled");
    std::process::exit(130);
}

/// Runs `future`, exiting with status 130 on Ctrl-C. Once `run` has listened
/// for Ctrl-C, tokio keeps the signal for the rest of the process, so every
/// later wait must race it too or Ctrl-C would do nothing.
pub async fn or_cancel<T>(future: impl Future<Output = T>) -> T {
    tokio::select! {
        biased;
        value = future => value,
        _ = tokio::signal::ctrl_c() => cancelled(),
    }
}

/// Tells the phone the result (network path) and closes the session.
pub async fn finish(received: Received, result: &Result<String>) {
    or_cancel(finish_session(received, result)).await
}

async fn finish_session(received: Received, result: &Result<String>) {
    match received {
        Received::Network(incoming, listener) => {
            let outcome = match result {
                Ok(message) => Outcome::Ok {
                    message: message.clone(),
                },
                Err(e) => Outcome::Error {
                    message: format!("{e:#}"),
                },
            };
            if let Err(e) = incoming.respond(outcome).await {
                eprintln!("Could not tell the phone the result: {e}");
            }
            listener.close().await;
        }
        Received::Pasted(_, listener) => listener.close().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Payload {
        Payload::Certificate {
            certificate: "c".into(),
        }
    }

    fn accept(text: &str) -> Result<Payload, LinkError> {
        match text {
            "ezcrypt1:abcdef" => Ok(payload()),
            "ezcrypt1:wrong" => Err(LinkError::WrongSecret),
            _ => Err(LinkError::Malformed("short".into())),
        }
    }

    #[test]
    fn ignores_stray_lines() {
        let mut p = PasteAccumulator::default();
        assert_eq!(p.push("hello", accept), Paste::Ignored);
        assert_eq!(p.push("", accept), Paste::Ignored);
        assert_eq!(p.push("y", accept), Paste::Ignored);
    }

    #[test]
    fn accepts_single_line_with_whitespace() {
        let mut p = PasteAccumulator::default();
        assert_eq!(
            p.push("  ezcrypt1:abcdef \r", accept),
            Paste::Done(payload())
        );
    }

    #[test]
    fn accumulates_split_lines() {
        let mut p = PasteAccumulator::default();
        assert_eq!(p.push("ezcrypt1:abc", accept), Paste::Pending);
        assert_eq!(p.push("def", accept), Paste::Done(payload()));
    }

    #[test]
    fn blank_line_after_failure_reports_and_resets() {
        let mut p = PasteAccumulator::default();
        assert_eq!(p.push("ezcrypt1:ab", accept), Paste::Pending);
        assert_eq!(
            p.push("", accept),
            Paste::Failed(LinkError::Malformed("short".into()))
        );
        // Reset: a stray line is ignored and a fresh reply works.
        assert_eq!(p.push("def", accept), Paste::Ignored);
        assert_eq!(p.push("ezcrypt1:abcdef", accept), Paste::Done(payload()));
    }

    #[test]
    fn wrong_secret_fails_immediately_and_resets() {
        let mut p = PasteAccumulator::default();
        assert_eq!(
            p.push("ezcrypt1:wrong", accept),
            Paste::Failed(LinkError::WrongSecret)
        );
        assert_eq!(p.push("ezcrypt1:abcdef", accept), Paste::Done(payload()));
    }

    #[test]
    fn a_new_reply_restarts_an_unfinished_one() {
        let mut p = PasteAccumulator::default();
        assert_eq!(p.push("ezcrypt1:ab", accept), Paste::Pending);
        assert_eq!(p.push("ezcrypt1:abc", accept), Paste::Pending);
        assert_eq!(p.push("def", accept), Paste::Done(payload()));
    }

    /// A P-256 CA's certificate for an Ed25519 key makes a reply longer than
    /// the 1024-byte line limit of macOS terminals; wrapped, it pastes intact.
    #[test]
    fn accumulates_a_real_wrapped_reply() {
        use ezcrypt_core::certificate::{self, Purpose};
        use ezcrypt_link::Reply;
        use rand::rngs::OsRng;
        use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};
        use std::collections::BTreeMap;

        let ca = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        let subject = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let request = certificate::Request {
            public_key: subject.public_key().to_openssh().unwrap(),
            purpose: Purpose::User,
            key_id: "alice@workstation".into(),
            serial: "1".into(),
            principals: vec!["alice".into()],
            all_principals: false,
            valid_after: 1_700_000_000,
            valid_before: Some(1_700_086_400),
            critical_options: BTreeMap::new(),
            extensions: [
                "permit-X11-forwarding",
                "permit-agent-forwarding",
                "permit-port-forwarding",
                "permit-pty",
                "permit-user-rc",
            ]
            .into_iter()
            .map(|e| (e.to_string(), String::new()))
            .collect(),
        };
        let issued = certificate::issue(&request, Purpose::User, &ca).unwrap();
        let reply = Reply {
            secret: [7; 16],
            payload: Payload::Certificate {
                certificate: issued.certificate,
            },
        };
        let text = reply.to_text();
        assert!(text.len() > 1024, "{}", text.len());
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|l| l.len() < 1024));

        let accept = |t: &str| {
            let got = Reply::from_text(t)?;
            if got.secret != [7; 16] {
                return Err(LinkError::WrongSecret);
            }
            Ok(got.payload)
        };
        let mut p = PasteAccumulator::default();
        assert_eq!(p.push("stray", accept), Paste::Ignored);
        let (last, rest) = lines.split_last().unwrap();
        for line in rest {
            assert_eq!(p.push(line, accept), Paste::Pending, "{line}");
        }
        assert_eq!(p.push(last, accept), Paste::Done(reply.payload));
    }

    #[test]
    fn url_length_guard() {
        assert!(check_url_len(&"a".repeat(1024)).is_ok());
        let e = check_url_len(&"a".repeat(1025)).unwrap_err();
        assert_eq!(e.to_string(), "hostname or username too long for a QR code");
    }
}
