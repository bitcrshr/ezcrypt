use std::future::Future;
use std::time::{Duration, Instant};

use ezcrypt_link::{
    Kind, LinkError, Listener, Network, Offer, Outcome, Payload, Reply, Request, deliver_to,
};

const CONNECT: Duration = Duration::from_secs(10);

/// Fail the test instead of hanging the suite.
async fn bounded<T>(fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .expect("test timed out")
}

fn request(kind: Kind) -> Request {
    Request {
        kind,
        host: "build.example.com".into(),
        user: "alice".into(),
        subject: (kind == Kind::Enroll).then(|| vec![0, 0, 0, 11, 1, 2, 3]),
    }
}

fn ca_key() -> Payload {
    Payload::CaKey {
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into(),
        name: "Home CA".into(),
    }
}

fn certificate() -> Payload {
    Payload::Certificate {
        certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".into(),
    }
}

async fn bind(kind: Kind) -> Listener {
    match Listener::bind(Network::Local, request(kind)).await {
        Ok(listener) => listener,
        Err(e) => panic!("bind failed: {e}"),
    }
}

/// Deliver `payload` with `secret` while the listener waits; return what each side saw.
async fn exchange(
    listener: &Listener,
    secret: [u8; 16],
    payload: Payload,
    respond: Outcome,
) -> (Payload, Outcome) {
    let dial = deliver_to(Network::Local, listener.addr(), secret, payload, CONNECT);
    let serve = async {
        let incoming = listener.next().await.expect("next");
        let payload = incoming.payload.clone();
        incoming.respond(respond).await.expect("respond");
        payload
    };
    let (served, dialed) = tokio::join!(serve, dial);
    (served, dialed.expect("deliver"))
}

/// Deliver while `next()` keeps running; `next()` must not return.
async fn deliver_rejected(listener: &Listener, secret: [u8; 16], payload: Payload) -> String {
    let dial = deliver_to(Network::Local, listener.addr(), secret, payload, CONNECT);
    tokio::select! {
        r = listener.next() => panic!("next returned for a bad delivery: {:?}", r.map(|i| i.payload)),
        out = dial => match out.expect("deliver") {
            Outcome::Error { message } => message,
            other => panic!("expected an error outcome, got {other:?}"),
        },
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn trust_session_delivers_ca_key_and_outcome() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let offer = listener.offer();
        assert_eq!(offer.kind, Kind::Trust);
        assert_eq!(offer.endpoint, listener.addr().id);
        assert_eq!(offer.host, "build.example.com");
        assert_eq!(offer.user, "alice");
        assert_eq!(offer.subject, None);
        assert_eq!(Offer::from_url(&offer.to_url()).unwrap(), offer);

        let ok = Outcome::Ok {
            message: "Trusted Home CA".into(),
        };
        let (served, outcome) = exchange(&listener, offer.secret, ca_key(), ok.clone()).await;
        assert_eq!(served, ca_key());
        assert_eq!(outcome, ok);
        listener.close().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn enroll_session_delivers_certificate() {
    bounded(async {
        let listener = bind(Kind::Enroll).await;
        let offer = listener.offer();
        assert_eq!(offer.kind, Kind::Enroll);
        assert_eq!(offer.subject, request(Kind::Enroll).subject);

        let ok = Outcome::Ok {
            message: "Installed".into(),
        };
        let (served, outcome) = exchange(&listener, offer.secret, certificate(), ok.clone()).await;
        assert_eq!(served, certificate());
        assert_eq!(outcome, ok);
        listener.close().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_secret_is_rejected_and_listener_keeps_waiting() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let mut wrong = listener.offer().secret;
        wrong[0] ^= 1;
        let message = deliver_rejected(&listener, wrong, ca_key()).await;
        assert_eq!(message, LinkError::WrongSecret.to_string());

        let ok = Outcome::Ok {
            message: "done".into(),
        };
        let (served, outcome) =
            exchange(&listener, listener.offer().secret, ca_key(), ok.clone()).await;
        assert_eq!(served, ca_key());
        assert_eq!(outcome, ok);
        listener.close().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_payload_type_is_rejected() {
    bounded(async {
        let trust = bind(Kind::Trust).await;
        let message = deliver_rejected(&trust, trust.offer().secret, certificate()).await;
        assert_eq!(message, LinkError::WrongPayload.to_string());
        trust.close().await;

        let enroll = bind(Kind::Enroll).await;
        let message = deliver_rejected(&enroll, enroll.offer().secret, ca_key()).await;
        assert_eq!(message, LinkError::WrongPayload.to_string());
        enroll.close().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pasted_reply_is_accepted_with_same_checks() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let secret = listener.offer().secret;
        let text = |secret, payload| Reply { secret, payload }.to_text();

        let mut wrong = secret;
        wrong[15] ^= 0x80;
        assert_eq!(
            listener.accept_pasted(&text(wrong, ca_key())),
            Err(LinkError::WrongSecret)
        );
        assert_eq!(
            listener.accept_pasted(&text(secret, certificate())),
            Err(LinkError::WrongPayload)
        );
        assert!(matches!(
            listener.accept_pasted("ezcrypt1:not base64!"),
            Err(LinkError::Malformed(_))
        ));
        // A newer app's reply reports a version problem, not a bad secret.
        let newer = serde_json::json!({"v": 2, "secret": "x", "payload": {}}).to_string();
        let newer = format!(
            "ezcrypt1:{}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, newer)
        );
        assert_eq!(
            listener.accept_pasted(&newer),
            Err(LinkError::ReplyVersion { theirs: 2 })
        );

        assert_eq!(
            listener.accept_pasted(&text(secret, ca_key())),
            Ok(ca_key())
        );
        listener.close().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn delivery_to_closed_listener_fails_fast() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let addr = listener.addr();
        let secret = listener.offer().secret;
        listener.close().await;

        let started = Instant::now();
        let result = deliver_to(
            Network::Local,
            addr,
            secret,
            ca_key(),
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(result, Err(LinkError::Unreachable));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_rejects_invalid_request() {
    bounded(async {
        let mut cases = Vec::new();
        for host in ["", "ex\nample.com", "ex\u{202e}ample.com"] {
            cases.push(Request {
                host: host.into(),
                ..request(Kind::Trust)
            });
        }
        cases.push(Request {
            host: "a".repeat(254),
            ..request(Kind::Trust)
        });
        for user in ["", "al\u{1b}ice"] {
            cases.push(Request {
                user: user.into(),
                ..request(Kind::Trust)
            });
        }
        cases.push(Request {
            user: "a".repeat(65),
            ..request(Kind::Trust)
        });
        cases.push(Request {
            subject: Some(vec![1, 2, 3]),
            ..request(Kind::Trust)
        });
        cases.push(Request {
            subject: None,
            ..request(Kind::Enroll)
        });
        for subject in [vec![], vec![1; 257]] {
            cases.push(Request {
                subject: Some(subject),
                ..request(Kind::Enroll)
            });
        }
        for case in cases {
            let shown = format!("{case:?}");
            match Listener::bind(Network::Local, case).await {
                Err(LinkError::Malformed(_)) => {}
                Err(e) => panic!("{shown}: unexpected error {e:?}"),
                Ok(_) => panic!("{shown}: bind accepted an invalid request"),
            }
        }

        // The limits themselves are accepted.
        let edge = Request {
            host: "a".repeat(253),
            user: "a".repeat(64),
            subject: Some(vec![1; 256]),
            kind: Kind::Enroll,
        };
        let listener = Listener::bind(Network::Local, edge).await.ok().unwrap();
        listener.close().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn only_one_reply_is_accepted_per_session() {
    bounded(async {
        // Network first: a second good delivery and a good paste are both refused.
        let listener = bind(Kind::Trust).await;
        let secret = listener.offer().secret;
        let ok = Outcome::Ok {
            message: "done".into(),
        };
        let (_, outcome) = exchange(&listener, secret, ca_key(), ok.clone()).await;
        assert_eq!(outcome, ok);

        let message = deliver_rejected(&listener, secret, ca_key()).await;
        assert!(message.contains("already"), "{message}");
        let pasted = Reply {
            secret,
            payload: ca_key(),
        }
        .to_text();
        assert!(matches!(
            listener.accept_pasted(&pasted),
            Err(LinkError::Rejected(_))
        ));
        listener.close().await;

        // Paste first: a later good network delivery is refused.
        let listener = bind(Kind::Enroll).await;
        let secret = listener.offer().secret;
        let pasted = Reply {
            secret,
            payload: certificate(),
        }
        .to_text();
        assert_eq!(listener.accept_pasted(&pasted), Ok(certificate()));
        assert!(matches!(
            listener.accept_pasted(&pasted),
            Err(LinkError::Rejected(_))
        ));
        let message = deliver_rejected(&listener, secret, certificate()).await;
        assert!(message.contains("already"), "{message}");
        listener.close().await;
    })
    .await;
}

async fn raw_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .expect("raw bind")
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_connections_do_not_block_a_real_delivery() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let secret = listener.offer().secret;
        let ok = Outcome::Ok {
            message: "done".into(),
        };
        let attack = async {
            // Peers that know only the endpoint address connect and stall:
            // some never open a stream, some send part of a reply and never finish.
            let mut held = Vec::new();
            for i in 0..4 {
                let ep = raw_endpoint().await;
                let conn = ep
                    .connect(listener.addr(), ezcrypt_link::ALPN)
                    .await
                    .expect("stalled connect");
                let streams = if i % 2 == 1 {
                    let (mut send, recv) = conn.open_bi().await.expect("open");
                    send.write_all(b"{\"v\":1,").await.expect("write");
                    Some((send, recv))
                } else {
                    None
                };
                held.push((ep, conn, streams));
            }
            let started = Instant::now();
            let out = deliver_to(
                Network::Local,
                listener.addr(),
                secret,
                ca_key(),
                Duration::from_secs(5),
            )
            .await;
            (held, out, started.elapsed())
        };
        let serve = async {
            let incoming = listener.next().await.expect("next");
            let payload = incoming.payload.clone();
            incoming.respond(ok.clone()).await.expect("respond");
            payload
        };
        let (served, (held, out, elapsed)) = tokio::join!(serve, attack);
        assert_eq!(served, ca_key());
        assert_eq!(out, Ok(ok));
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        for (ep, conn, _) in held {
            conn.close(iroh::endpoint::VarInt::from_u32(0), b"");
            ep.close().await;
        }
        listener.close().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_reply_is_rejected() {
    bounded(async {
        let listener = bind(Kind::Trust).await;
        let ep = raw_endpoint().await;
        let attack = async {
            let conn = ep
                .connect(listener.addr(), ezcrypt_link::ALPN)
                .await
                .expect("connect");
            let (mut send, mut recv) = conn.open_bi().await.expect("open");
            let write = async {
                // The listener stops reading at the limit, so this may fail.
                let _ = send.write_all(&vec![b' '; 64 * 1024 + 1]).await;
                let _ = send.finish();
            };
            let (_, body) = tokio::join!(write, recv.read_to_end(4096));
            conn.close(iroh::endpoint::VarInt::from_u32(0), b"");
            body.expect("read outcome")
        };
        let body = tokio::select! {
            r = listener.next() => panic!("next returned for an oversized reply: {:?}", r.map(|i| i.payload)),
            body = attack => body,
        };
        match serde_json::from_slice::<Outcome>(&body).expect("outcome JSON") {
            Outcome::Error { message } => assert!(message.contains("too large"), "{message}"),
            other => panic!("expected an error outcome, got {other:?}"),
        }
        ep.close().await;
        listener.close().await;
    })
    .await;
}
