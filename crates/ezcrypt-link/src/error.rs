use thiserror::Error;

use crate::VERSION;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("{}", version_message(*.theirs))]
    Version { theirs: u8 },
    #[error("{}", reply_version_message(*.theirs))]
    ReplyVersion { theirs: u8 },
    #[error("Malformed link data: {0}")]
    Malformed(String),
    #[error("The link secret did not match")]
    WrongSecret,
    #[error("The reply did not contain what was expected")]
    WrongPayload,
    #[error(
        "Couldn't reach the computer. If the command is still waiting, try again or use Copy instead."
    )]
    Unreachable,
    #[error("Timed out waiting for the other side")]
    Timeout,
    #[error("Rejected: {0}")]
    Rejected(String),
    #[error("Network error: {0}")]
    Network(String),
}

fn version_message(theirs: u8) -> &'static str {
    if theirs > VERSION {
        "This QR code needs a newer ezcrypt app"
    } else {
        "Update the ezcrypt command-line tool"
    }
}

fn reply_version_message(theirs: u8) -> &'static str {
    if theirs > VERSION {
        "Update the ezcrypt command-line tool to accept this reply"
    } else {
        "Update the ezcrypt app"
    }
}
