use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ezcrypt_link::{Kind, LinkError, Offer, Payload, Reply};

fn endpoint() -> iroh::EndpointId {
    iroh::SecretKey::from_bytes(&[7u8; 32]).public()
}

fn offer(kind: Kind) -> Offer {
    Offer {
        kind,
        endpoint: endpoint(),
        secret: [9u8; 16],
        host: "example.com".into(),
        user: "alice smith&co".into(),
        subject: (kind == Kind::Enroll).then(|| vec![1, 2, 3, 4]),
    }
}

/// Build an offer URL from a valid base, replacing or removing parameters.
fn url_with(overrides: &[(&str, Option<String>)]) -> String {
    let mut parts: Vec<(String, String)> = vec![
        ("v".into(), "1".into()),
        ("k".into(), "trust".into()),
        ("n".into(), B64.encode(endpoint().as_bytes())),
        ("s".into(), B64.encode([9u8; 16])),
        ("h".into(), "example.com".into()),
        ("u".into(), "alice".into()),
    ];
    for (k, v) in overrides {
        parts.retain(|(pk, _)| pk != k);
        if let Some(v) = v {
            parts.push((k.to_string(), v.clone()));
        }
    }
    let mut u = url::Url::parse("ezcrypt://link").unwrap();
    u.query_pairs_mut().extend_pairs(parts);
    u.to_string()
}

fn s(x: &str) -> Option<String> {
    Some(x.to_string())
}

#[test]
fn offer_url_round_trips() {
    for kind in [Kind::Trust, Kind::Enroll] {
        let o = offer(kind);
        assert_eq!(Offer::from_url(&o.to_url()).unwrap(), o);
    }
}

#[test]
fn offer_url_accepts_any_order() {
    let o = offer(Kind::Trust);
    let u = url::Url::parse(&o.to_url()).unwrap();
    let mut pairs: Vec<_> = u.query_pairs().into_owned().collect();
    pairs.reverse();
    let mut u2 = url::Url::parse("ezcrypt://link").unwrap();
    u2.query_pairs_mut().extend_pairs(pairs);
    assert_eq!(Offer::from_url(u2.as_str()).unwrap(), o);
}

#[test]
fn offer_url_rejects() {
    Offer::from_url(&url_with(&[])).unwrap();

    for missing in ["v", "k", "n", "s", "h", "u"] {
        assert!(
            Offer::from_url(&url_with(&[(missing, None)])).is_err(),
            "missing {missing}"
        );
    }
    assert!(matches!(
        Offer::from_url(&url_with(&[("v", s("2"))])),
        Err(LinkError::Version { theirs: 2 })
    ));
    assert!(matches!(
        Offer::from_url(&url_with(&[("k", s("bogus"))])),
        Err(LinkError::Malformed(_))
    ));
    let mut bad_point = [0u8; 32];
    bad_point[0] = 2; // y = 2 is not on the curve
    assert!(iroh::EndpointId::from_bytes(&bad_point).is_err());
    assert!(matches!(
        Offer::from_url(&url_with(&[("n", Some(B64.encode(bad_point)))])),
        Err(LinkError::Malformed(_))
    ));
    for len in [15usize, 17] {
        assert!(matches!(
            Offer::from_url(&url_with(&[("s", Some(B64.encode(vec![1u8; len])))])),
            Err(LinkError::Malformed(_))
        ));
    }
    assert!(Offer::from_url(&url_with(&[("h", s(""))])).is_err());
    assert!(Offer::from_url(&url_with(&[("u", s(""))])).is_err());
    assert!(Offer::from_url(&url_with(&[("h", Some("a".repeat(254)))])).is_err());
    Offer::from_url(&url_with(&[("h", Some("a".repeat(253)))])).unwrap();
    assert!(Offer::from_url(&url_with(&[("u", Some("a".repeat(65)))])).is_err());
    Offer::from_url(&url_with(&[("u", Some("a".repeat(64)))])).unwrap();
    assert!(Offer::from_url(&url_with(&[("h", s("ex\u{7}ample"))])).is_err());
    assert!(Offer::from_url(&url_with(&[("u", s("al\nice"))])).is_err());
    assert!(Offer::from_url(&url_with(&[("u", s("al\u{85}ice"))])).is_err());
    for c in [
        '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}',
    ] {
        assert!(Offer::from_url(&url_with(&[("h", Some(format!("ex{c}ample.com")))])).is_err());
        assert!(Offer::from_url(&url_with(&[("u", Some(format!("al{c}ice")))])).is_err());
    }
    // subject limits
    let enroll = |p: Vec<u8>| url_with(&[("k", s("enroll")), ("p", Some(B64.encode(p)))]);
    Offer::from_url(&enroll(vec![1; 600])).unwrap();
    assert!(Offer::from_url(&enroll(vec![1; 1025])).is_err());
    assert!(Offer::from_url(&url_with(&[("k", s("enroll"))])).is_err());
    assert!(Offer::from_url(&url_with(&[("p", Some(B64.encode([1u8; 4])))])).is_err());
    // total length: a 1024-byte subject alone pushes the URL over 1024
    assert!(Offer::from_url(&enroll(vec![1; 1024])).is_err());
    // duplicates, unknown params, wrong scheme
    assert!(Offer::from_url(&format!("{}&h=other.com", url_with(&[]))).is_err());
    assert!(Offer::from_url(&format!("{}&x=1", url_with(&[]))).is_err());
    assert!(Offer::from_url(&url_with(&[]).replace("ezcrypt://link", "https://link")).is_err());
    assert!(Offer::from_url("not a url").is_err());
}

fn replies() -> Vec<Reply> {
    vec![
        Reply {
            secret: [3u8; 16],
            payload: Payload::CaKey {
                public_key: "ssh-ed25519 AAAA".into(),
                name: "My CA".into(),
            },
        },
        Reply {
            secret: [4u8; 16],
            payload: Payload::Certificate {
                certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".into(),
            },
        },
    ]
}

#[test]
fn reply_text_round_trips() {
    for r in replies() {
        let t = r.to_text();
        assert!(t.starts_with("ezcrypt1:"));
        assert_eq!(Reply::from_text(&t).unwrap(), r);
    }
}

#[test]
fn reply_text_tolerates_wrapping() {
    for r in replies() {
        let t = r.to_text();
        let mut wrapped = String::new();
        for (i, c) in t.chars().enumerate() {
            if i > 0 && i % 40 == 0 {
                wrapped.push_str("\n  ");
            }
            wrapped.push(c);
        }
        wrapped.push_str("\r\n");
        assert_eq!(Reply::from_text(&wrapped).unwrap(), r);
    }
}

#[test]
fn reply_text_rejects() {
    let good = replies()[0].to_text();
    assert!(Reply::from_text(&good.replace("ezcrypt1:", "ezcrypt2:")).is_err());
    assert!(Reply::from_text("ezcrypt1:!!!notbase64").is_err());
    let enc = |j: &str| format!("ezcrypt1:{}", B64.encode(j));
    assert!(matches!(
        Reply::from_text(&enc(
            r#"{"v":2,"secret":"AAAAAAAAAAAAAAAAAAAAAA","payload":{"type":"certificate","certificate":"x"}}"#
        )),
        Err(LinkError::Version { theirs: 2 })
    ));
    let big = format!(
        r#"{{"v":1,"secret":"AAAAAAAAAAAAAAAAAAAAAA","payload":{{"type":"certificate","certificate":"{}"}}}}"#,
        "a".repeat(64 * 1024)
    );
    assert!(matches!(
        Reply::from_text(&enc(&big)),
        Err(LinkError::Malformed(_))
    ));
    assert!(
        Reply::from_text(&enc(
            r#"{"v":1,"secret":"AAAA","payload":{"type":"certificate","certificate":"x"}}"#
        ))
        .is_err()
    );
}

#[test]
fn error_display() {
    assert_eq!(
        LinkError::Version { theirs: 2 }.to_string(),
        "This QR code needs a newer ezcrypt app"
    );
    assert_eq!(
        LinkError::Version { theirs: 0 }.to_string(),
        "Update the ezcrypt command-line tool"
    );
    assert_eq!(
        LinkError::Unreachable.to_string(),
        "The terminal session has ended. Run the command again."
    );
}
