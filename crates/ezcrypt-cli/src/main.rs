mod enroll;
mod input;
mod privilege;
mod qr;
mod session;
mod trust;
mod update;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ezcrypt",
    version,
    about = "Use your iPhone as an SSH certificate authority"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Get an SSH certificate for your key from the phone
    Enroll {
        /// The SSH key to enroll (default: the first of ~/.ssh/id_*)
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Trust the phone's CA on this machine
    Trust {
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        use_existing: bool,
        /// Test only: read the reply from a file instead of a phone session.
        #[cfg(feature = "test-hooks")]
        #[arg(long, hide = true)]
        from_reply: Option<PathBuf>,
    },
    /// Update ezcrypt to the latest release
    Update {
        /// Only report whether a newer release exists
        #[arg(long)]
        check: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mut input = input::Input::new();
    let result = match cli.command {
        Command::Enroll { key } => enroll::run(key, &mut input).await,
        Command::Trust {
            yes,
            use_existing,
            #[cfg(feature = "test-hooks")]
            from_reply,
        } => {
            #[cfg(not(feature = "test-hooks"))]
            let from_reply = None;
            trust::command(yes, use_existing, from_reply, &mut input).await
        }
        Command::Update { check } => update::run(check).await,
    };
    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(all(test, not(feature = "test-hooks")))]
mod tests {
    use super::*;

    #[test]
    fn from_reply_flag_absent_without_test_hooks() {
        let r = Cli::try_parse_from(["ezcrypt", "trust", "--from-reply", "x"]);
        assert!(r.is_err());
    }
}
