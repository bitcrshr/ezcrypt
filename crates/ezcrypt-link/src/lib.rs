//! Data formats for moving a CA public key or certificate between the phone
//! and a machine: the QR offer URL and the pasted-text reply.

mod error;
mod offer;
mod reply;

pub use error::LinkError;
pub use offer::{Kind, Offer};
pub use reply::{Outcome, Payload, Reply};

pub const VERSION: u8 = 1;
pub const ALPN: &[u8] = b"ezcrypt/link/1";
