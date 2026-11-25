mod enroll;
mod input;
mod qr;
mod session;
#[allow(dead_code)]
mod trust;

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
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mut input = input::Input::new();
    let result = match cli.command {
        Command::Enroll { key } => enroll::run(key, &mut input).await,
        Command::Trust { .. } => Err(anyhow::anyhow!("`ezcrypt trust` is not available yet")),
    };
    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
