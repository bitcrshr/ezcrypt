//! Test helper: `make-reply <ca.pub> <name>` prints a CA-key reply with a zero secret.
use ezcrypt_link::{Payload, Reply};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(name)) = (args.next(), args.next()) else {
        eprintln!("usage: make-reply <ca.pub> <name>");
        std::process::exit(2);
    };
    let public_key = std::fs::read_to_string(&path).expect("cannot read public key");
    let reply = Reply {
        secret: [0; 16],
        payload: Payload::CaKey {
            public_key: public_key.trim().to_string(),
            name,
        },
    };
    println!("{}", reply.to_text());
}
