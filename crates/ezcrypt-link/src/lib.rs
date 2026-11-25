//! Moving a CA public key or certificate between the phone and a machine: the
//! QR offer URL, the reply (sent over Iroh or pasted as text), and the session.

mod error;
mod offer;
mod reply;
mod session;

pub use error::LinkError;
pub use offer::{Kind, Offer};
pub use reply::{Outcome, Payload, Reply};
pub use session::{Incoming, Listener, Network, Request, deliver, deliver_to};

pub const VERSION: u8 = 1;
pub const ALPN: &[u8] = b"ezcrypt/link/1";
