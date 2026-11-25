pub mod certificate;
pub mod export;
pub mod vault;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn invalid(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
    message.to_owned().into()
}
