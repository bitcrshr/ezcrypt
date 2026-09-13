pub mod certificate;
pub mod export;
mod ffi;
pub mod vault;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) fn invalid(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
    message.to_owned().into()
}
