//! Link delivery for the app: parse a scanned offer, build the paste-fallback
//! reply text, and deliver a payload to the machine's listener over Iroh.
//!
//! `ezcrypt_link_deliver` blocks the calling thread on a process-wide tokio
//! runtime and can be cancelled from any other thread.

use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::OnceLock;
#[cfg(debug_assertions)]
use std::time::Duration;

use ezcrypt_core::certificate::{self, Purpose};
use ezcrypt_core::{invalid, Result};
use ezcrypt_link::{Kind, LinkError, Network, Offer, Outcome, Payload, Reply};
use serde::Deserialize;
use serde_json::{json, Value};
use ssh_key::{HashAlg, PublicKey};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::{respond, MAX_INPUT};

/// How long a test-hook delivery waits to connect; matches `deliver`'s.
#[cfg(debug_assertions)]
const LOCAL_CONNECT_WAIT: Duration = Duration::from_secs(30);

/// The payload as the app sends it. Mirrors `Payload` but refuses unknown
/// fields, which the wire format must keep accepting.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AppPayload {
    CaKey { public_key: String, name: String },
    Certificate { certificate: String },
}

/// The `link_offer` op: what the app shows before the user confirms.
pub(crate) fn offer_info(url: &str) -> Result<Value> {
    let offer = Offer::from_url(url)?;
    let mut info = json!({
        "kind": match offer.kind {
            Kind::Trust => "trust",
            Kind::Enroll => "enroll",
        },
        "host": offer.host,
        "user": offer.user,
    });
    if let Some(blob) = &offer.subject {
        let key = PublicKey::from_bytes(blob)?;
        // Through the core so the app only sees algorithms it can certify.
        let key = certificate::parse_public(&key.to_openssh()?)?;
        info["subject_public_key"] = json!(key.to_openssh()?);
        info["subject_fingerprint"] = json!(key.fingerprint(HashAlg::Sha256).to_string());
    }
    Ok(info)
}

/// Only a CA public key or a user certificate for the offer's subject key may
/// leave the device. Both are normalised to `<type> <base64>` so no free text
/// rides along, and the receiver's checks (size, name) are applied here too.
fn checked(offer: &Offer, payload: AppPayload) -> Result<Payload> {
    let payload = match (offer.kind, payload) {
        (Kind::Trust, AppPayload::CaKey { public_key, name }) => {
            let mut key = certificate::parse_public(&public_key)?;
            key.set_comment("");
            Payload::CaKey {
                public_key: key.to_openssh()?,
                name,
            }
        }
        (Kind::Enroll, AppPayload::Certificate { certificate }) => {
            // `inspect` verifies the CA signature and, unlike ssh-key's
            // `Certificate`, accepts forever certificates.
            let inspected = certificate::inspect(&certificate)?;
            if inspected.purpose != Purpose::User {
                return Err(invalid("Only user certificates can be sent"));
            }
            if offer.subject.as_deref() != Some(inspected.subject.to_bytes()?.as_slice()) {
                return Err(invalid(
                    "This certificate is for a different key than the machine's",
                ));
            }
            let mut fields = certificate.split_whitespace();
            let (kind, body) = fields
                .next()
                .zip(fields.next())
                .ok_or_else(|| invalid("Malformed certificate"))?;
            Payload::Certificate {
                certificate: format!("{kind} {body}"),
            }
        }
        _ => return Err(LinkError::WrongPayload.into()),
    };
    let reply = Reply {
        secret: offer.secret,
        payload,
    };
    Ok(Reply::from_json(&reply.to_json())?.payload)
}

/// The `link_reply_text` op: the reply to paste when the network fails.
pub(crate) fn reply_text(url: &str, payload: AppPayload) -> Result<Value> {
    let offer = Offer::from_url(url)?;
    let payload = checked(&offer, payload)?;
    let text = Reply {
        secret: offer.secret,
        payload,
    }
    .to_text();
    Ok(json!({ "text": text }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliverInput {
    offer: String,
    payload: AppPayload,
    /// Debug-only test hook: `"local"` with `addr` dials directly, without relays.
    #[serde(default)]
    network: Option<String>,
    /// Debug-only test hook: the listener's `EndpointAddr`.
    #[serde(default)]
    addr: Option<Value>,
}

/// Where to dial: the offer's endpoint over N0, or a test listener.
enum Target {
    Offer,
    #[cfg(debug_assertions)]
    Local(iroh::EndpointAddr),
}

fn target(network: Option<String>, addr: Option<Value>) -> Result<Target> {
    if network.is_none() && addr.is_none() {
        return Ok(Target::Offer);
    }
    #[cfg(debug_assertions)]
    {
        match (network.as_deref(), addr) {
            (Some("local"), Some(addr)) => Ok(Target::Local(serde_json::from_value(addr)?)),
            _ => Err(invalid(
                "Test delivery needs \"network\":\"local\" and \"addr\"",
            )),
        }
    }
    #[cfg(not(debug_assertions))]
    {
        Err(invalid("Test delivery is not available in release builds"))
    }
}

/// The process-wide runtime. Never dropped: a failed connect leaves a task
/// closing its endpoint in the background.
fn runtime() -> Result<&'static Runtime> {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ezcrypt-link")
        .build()?;
    // If another thread won the race, its runtime is used and ours is dropped.
    let _ = RUNTIME.set(runtime);
    RUNTIME
        .get()
        .ok_or_else(|| invalid("Network runtime unavailable"))
}

/// Opaque handle for one delivery. Cancelling it is permanent: every later
/// `deliver` on the same handle returns `Cancelled` at once.
pub struct EzcryptLink {
    token: CancellationToken,
}

enum Delivered {
    Outcome(Outcome),
    Cancelled,
}

fn deliver(link: &EzcryptLink, input: &[u8]) -> Result<Delivered> {
    let input: DeliverInput = serde_json::from_slice(input)?;
    let offer = Offer::from_url(&input.offer)?;
    let payload = checked(&offer, input.payload)?;
    let target = target(input.network, input.addr)?;
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(invalid("Link delivery must not run on an async thread"));
    }
    let delivery = async move {
        match target {
            Target::Offer => ezcrypt_link::deliver(Network::N0, &offer, payload).await,
            #[cfg(debug_assertions)]
            Target::Local(addr) => {
                ezcrypt_link::deliver_to(
                    Network::Local,
                    addr,
                    offer.secret,
                    payload,
                    LOCAL_CONNECT_WAIT,
                )
                .await
            }
        }
    };
    let token = link.token.clone();
    // Boxed so the delivery future, with the Iroh endpoint's state, lives on
    // the heap: `block_on` keeps its future on this thread's stack, and the
    // app calls from an NSThread with a 512 KB default stack.
    runtime()?.block_on(Box::pin(async move {
        tokio::select! {
            biased;
            () = token.cancelled() => Ok(Delivered::Cancelled),
            outcome = delivery => Ok(Delivered::Outcome(outcome?)),
        }
    }))
}

/// Create a handle for one delivery. Free it with `ezcrypt_link_free`.
/// Returns null only if allocation panics.
#[no_mangle]
pub extern "C" fn ezcrypt_link_new() -> *mut EzcryptLink {
    catch_unwind(|| {
        Box::into_raw(Box::new(EzcryptLink {
            token: CancellationToken::new(),
        }))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Deliver `{"offer":"<url>","payload":{...}}` and block until the machine
/// answers, the delivery fails, or the handle is cancelled. Returns
/// `{"ok":{"outcome":"ok"|"error","message":...}}` or `{"error":...}`;
/// cancellation gives exactly `{"error":"Cancelled"}`. Free the result with
/// `ezcrypt_free`.
///
/// Call it from a plain background thread, never from an async runtime thread.
///
/// # Safety
/// `link` must come from `ezcrypt_link_new` and not be freed while this call
/// runs. `input` must point to `length` readable bytes for the whole call.
#[no_mangle]
pub unsafe extern "C" fn ezcrypt_link_deliver(
    link: *mut EzcryptLink,
    input: *const u8,
    length: usize,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<Value> {
        if link.is_null() || input.is_null() || length > MAX_INPUT {
            return Err(invalid("Invalid request buffer"));
        }
        // Shared, never `&mut`: `ezcrypt_link_cancel` may run at the same time.
        let link = &*link;
        match deliver(link, slice::from_raw_parts(input, length))? {
            Delivered::Outcome(outcome) => Ok(json!({ "ok": outcome })),
            Delivered::Cancelled => Ok(json!({ "error": "Cancelled" })),
        }
    }));
    let response = match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => json!({ "error": error.to_string() }),
        Err(_) => json!({ "error": "Link delivery failed" }),
    };
    respond(response)
}

/// Cancel any running or later `ezcrypt_link_deliver` on this handle. Safe to
/// call from any thread, before, during or after a delivery.
///
/// # Safety
/// `link` must be null or come from `ezcrypt_link_new` and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn ezcrypt_link_cancel(link: *mut EzcryptLink) {
    if link.is_null() {
        return;
    }
    let link = &*link;
    let _ = catch_unwind(AssertUnwindSafe(|| link.token.cancel()));
}

/// Free a handle.
///
/// # Safety
/// `link` must be null or come from `ezcrypt_link_new` and not be freed
/// already. No `ezcrypt_link_deliver` or `ezcrypt_link_cancel` on this handle
/// may still be running: cancel, wait for the delivery to return, then free.
#[no_mangle]
pub unsafe extern "C" fn ezcrypt_link_free(link: *mut EzcryptLink) {
    if link.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(link))));
}
