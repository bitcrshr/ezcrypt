//! Link delivery and offer parsing through the C ABI.

use std::ffi::{c_char, CStr};
use std::future::Future;
use std::ptr;
use std::time::{Duration, Instant};

use ezcrypt_ffi::{
    ezcrypt_call, ezcrypt_free, ezcrypt_link_cancel, ezcrypt_link_deliver, ezcrypt_link_free,
    ezcrypt_link_new, EzcryptLink,
};
use ezcrypt_link::{Kind, Listener, Network, Offer, Outcome, Payload, Reply, Request};
use serde_json::{json, Value};

/// Known Ed25519 key; the fingerprint is what `ssh-keygen -lf` prints for it.
const SUBJECT: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILajlV6k1C8D+cmvWmdlK6RcTsrUAB0lxaFLZ7/q+1jM";
const SUBJECT_FINGERPRINT: &str = "SHA256:Z9RexxhhtuU0jauCNAmp8C8o/BHeQ9O3aWxA/BMZgHI";

/// Fail the test instead of hanging the suite.
async fn bounded<T>(fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .expect("test timed out")
}

unsafe fn take(output: *mut c_char) -> Value {
    assert!(!output.is_null());
    let text = CStr::from_ptr(output).to_str().unwrap().to_owned();
    ezcrypt_free(output);
    serde_json::from_str(&text).unwrap()
}

fn call(input: Value) -> Value {
    let bytes = input.to_string();
    unsafe {
        take(ezcrypt_call(
            bytes.as_ptr(),
            bytes.len(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        ))
    }
}

/// A handle that can be shared with the thread running `deliver`.
#[derive(Clone, Copy)]
struct Link(*mut EzcryptLink);
unsafe impl Send for Link {}
unsafe impl Sync for Link {}

impl Link {
    fn new() -> Link {
        let link = ezcrypt_link_new();
        assert!(!link.is_null());
        Link(link)
    }

    fn deliver(self, input: &Value) -> Value {
        let bytes = input.to_string();
        unsafe { take(ezcrypt_link_deliver(self.0, bytes.as_ptr(), bytes.len())) }
    }

    fn cancel(self) {
        unsafe { ezcrypt_link_cancel(self.0) }
    }

    /// Only once no `deliver` on this handle is running.
    fn free(self) {
        unsafe { ezcrypt_link_free(self.0) }
    }
}

/// Run `deliver` on a plain thread, as Swift does, and await its result.
async fn deliver_on_thread(link: Link, input: Value) -> Value {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(link.deliver(&input));
    });
    rx.await.expect("deliver thread")
}

fn request(kind: Kind) -> Request {
    Request {
        kind,
        host: "build.example.com".into(),
        user: "alice".into(),
        subject: (kind == Kind::Enroll).then(subject_blob),
    }
}

fn subject_blob() -> Vec<u8> {
    ssh_key::PublicKey::from_openssh(SUBJECT)
        .unwrap()
        .to_bytes()
        .unwrap()
}

fn ca_key_json() -> Value {
    json!({"type": "ca_key", "public_key": SUBJECT, "name": "Home CA"})
}

fn ca_key() -> Payload {
    Payload::CaKey {
        public_key: SUBJECT.into(),
        name: "Home CA".into(),
    }
}

/// An offer for an endpoint that is never dialed.
fn offline_offer(kind: Kind) -> Offer {
    let request = request(kind);
    Offer {
        kind,
        endpoint: iroh::SecretKey::from_bytes(&[7; 32]).public(),
        secret: [9; 16],
        host: request.host,
        user: request.user,
        subject: request.subject,
    }
}

async fn bind(kind: Kind) -> Listener {
    match Listener::bind(Network::Local, request(kind)).await {
        Ok(listener) => listener,
        Err(e) => panic!("bind failed: {e}"),
    }
}

fn local_input(listener: &Listener, payload: Value) -> Value {
    json!({
        "offer": listener.offer().to_url(),
        "payload": payload,
        "network": "local",
        "addr": serde_json::to_value(listener.addr()).unwrap(),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn ffi_delivers_to_local_listener() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let link = Link::new();
        let dial = deliver_on_thread(link, local_input(&listener, ca_key_json()));
        let serve = async {
            let incoming = listener.next().await.expect("next");
            let payload = incoming.payload.clone();
            incoming
                .respond(Outcome::Ok {
                    message: "Trusted on build.example.com".into(),
                })
                .await
                .expect("respond");
            payload
        };
        let (served, dialed) = tokio::join!(serve, dial);
        link.free();
        assert_eq!(served, ca_key());
        assert_eq!(
            dialed,
            json!({"ok": {"outcome": "ok", "message": "Trusted on build.example.com"}})
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ffi_reports_error_outcome() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let link = Link::new();
        let dial = deliver_on_thread(link, local_input(&listener, ca_key_json()));
        let serve = async {
            let incoming = listener.next().await.expect("next");
            incoming
                .respond(Outcome::Error {
                    message: "declined".into(),
                })
                .await
                .expect("respond");
        };
        let ((), dialed) = tokio::join!(serve, dial);
        link.free();
        assert_eq!(
            dialed,
            json!({"ok": {"outcome": "error", "message": "declined"}})
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ffi_cancel_unblocks_deliver() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let link = Link::new();
        let dial = tokio::spawn(deliver_on_thread(
            link,
            local_input(&listener, ca_key_json()),
        ));
        // Receive the delivery but never answer it.
        let incoming = listener.next().await.expect("next");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let cancelled_at = Instant::now();
        link.cancel();
        let out = tokio::time::timeout(Duration::from_secs(2), dial)
            .await
            .expect("deliver did not return within 2 s of cancel")
            .unwrap();
        assert!(cancelled_at.elapsed() < Duration::from_secs(2));
        assert_eq!(out, json!({"error": "Cancelled"}));
        drop(incoming);
        link.free();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_before_deliver_returns_cancelled_promptly() {
    bounded(async {
        let link = Link::new();
        link.cancel();
        let started = Instant::now();
        let input = json!({
            "offer": offline_offer(Kind::Trust).to_url(),
            "payload": ca_key_json(),
        });
        let out = deliver_on_thread(link, input).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(out, json!({"error": "Cancelled"}));
        // Cancelling again, and after delivery, is harmless.
        link.cancel();
        link.free();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deliver_on_an_async_thread_is_an_error() {
    let link = Link::new();
    let input = json!({
        "offer": offline_offer(Kind::Trust).to_url(),
        "payload": ca_key_json(),
    });
    let out = link.deliver(&input);
    assert_eq!(
        out,
        json!({"error": "Link delivery must not run on an async thread"})
    );
    link.free();
}

#[test]
fn null_handles_are_harmless() {
    unsafe {
        ezcrypt_link_cancel(ptr::null_mut());
        ezcrypt_link_free(ptr::null_mut());
        let input = b"{}";
        let out = take(ezcrypt_link_deliver(
            ptr::null_mut(),
            input.as_ptr(),
            input.len(),
        ));
        assert!(out["error"].is_string(), "{out}");
    }
}

#[test]
fn null_or_oversized_input_is_an_error() {
    let link = Link::new();
    unsafe {
        let out = take(ezcrypt_link_deliver(link.0, ptr::null(), 0));
        assert_eq!(out, json!({"error": "Invalid request buffer"}));
        let big = vec![b' '; 1024 * 1024 + 1];
        let out = take(ezcrypt_link_deliver(link.0, big.as_ptr(), big.len()));
        assert_eq!(out, json!({"error": "Invalid request buffer"}));
    }
    let out = link.deliver(&json!({"offer": "ezcrypt://link?v=1"}));
    assert!(out["error"].is_string(), "{out}");
    link.free();
}

#[test]
fn deliver_rejects_unknown_fields() {
    let link = Link::new();
    let offer = offline_offer(Kind::Trust).to_url();
    let extra = link.deliver(&json!({"offer": offer, "payload": ca_key_json(), "extra": 1}));
    assert!(extra["error"].is_string(), "{extra}");
    let mut payload = ca_key_json();
    payload["extra"] = json!(1);
    let out = link.deliver(&json!({"offer": offer, "payload": payload}));
    assert!(out["error"].is_string(), "{out}");
    link.free();
}

#[test]
fn deliver_surfaces_offer_errors() {
    let link = Link::new();
    let url = offline_offer(Kind::Trust).to_url().replace("v=1", "v=2");
    let out = link.deliver(&json!({"offer": url, "payload": ca_key_json()}));
    assert_eq!(
        out,
        json!({"error": "This QR code needs a newer ezcrypt app"})
    );
    link.free();
}

#[cfg(debug_assertions)]
#[test]
fn deliver_test_hooks_need_both_fields() {
    let link = Link::new();
    let offer = offline_offer(Kind::Trust).to_url();
    for extra in [json!({"network": "local"}), json!({"network": "n0"})] {
        let mut input = json!({"offer": offer, "payload": ca_key_json()});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let out = link.deliver(&input);
        assert!(out["error"].is_string(), "{out}");
    }
    link.free();
}

#[cfg(not(debug_assertions))]
#[test]
fn release_refuses_test_hooks() {
    let link = Link::new();
    let offer = offline_offer(Kind::Trust).to_url();
    let addr = json!({"id": "0000", "addrs": []});
    for input in [
        json!({"offer": offer, "payload": ca_key_json(), "network": "local", "addr": addr}),
        json!({"offer": offer, "payload": ca_key_json(), "network": "local"}),
        json!({"offer": offer, "payload": ca_key_json(), "addr": addr}),
    ] {
        let out = link.deliver(&input);
        assert!(out["error"].is_string(), "{out}");
        assert_ne!(out["error"], "Cancelled");
    }
    link.free();
}

#[test]
fn link_offer_op_renders_subject() {
    let offer = offline_offer(Kind::Enroll);
    let out = call(json!({"op": "link_offer", "url": offer.to_url()}));
    assert_eq!(
        out,
        json!({"ok": {
            "kind": "enroll",
            "host": "build.example.com",
            "user": "alice",
            "subject_public_key": SUBJECT,
            "subject_fingerprint": SUBJECT_FINGERPRINT,
        }})
    );
}

#[test]
fn link_offer_op_trust_has_no_subject() {
    let offer = offline_offer(Kind::Trust);
    let out = call(json!({"op": "link_offer", "url": offer.to_url()}));
    assert_eq!(
        out,
        json!({"ok": {"kind": "trust", "host": "build.example.com", "user": "alice"}})
    );
}

#[test]
fn link_offer_op_reports_newer_version() {
    let url = offline_offer(Kind::Trust).to_url().replace("v=1", "v=2");
    let out = call(json!({"op": "link_offer", "url": url}));
    assert_eq!(
        out,
        json!({"error": "This QR code needs a newer ezcrypt app"})
    );
}

#[test]
fn link_reply_text_op_round_trips() {
    let offer = offline_offer(Kind::Trust);
    let out =
        call(json!({"op": "link_reply_text", "url": offer.to_url(), "payload": ca_key_json()}));
    let text = out["ok"]["text"].as_str().expect("text");
    assert!(text.starts_with("ezcrypt1:"), "{text}");
    let reply = Reply::from_text(text).unwrap();
    assert_eq!(reply.secret, offer.secret);
    assert_eq!(reply.payload, ca_key());

    let offer = offline_offer(Kind::Enroll);
    let certificate =
        json!({"type": "certificate", "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA"});
    let out = call(json!({"op": "link_reply_text", "url": offer.to_url(), "payload": certificate}));
    let reply = Reply::from_text(out["ok"]["text"].as_str().expect("text")).unwrap();
    assert_eq!(
        reply.payload,
        Payload::Certificate {
            certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".into()
        }
    );
}

#[test]
fn link_reply_text_op_rejects_bad_payloads() {
    let offer = offline_offer(Kind::Trust).to_url();
    let mut extra = ca_key_json();
    extra["extra"] = json!(1);
    let certificate =
        json!({"type": "certificate", "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA"});
    let control = json!({"type": "ca_key", "public_key": SUBJECT, "name": "Home\nCA"});
    for payload in [extra, certificate, control] {
        let out = call(json!({"op": "link_reply_text", "url": offer, "payload": payload}));
        assert!(out["error"].is_string(), "{payload}: {out}");
    }
}
