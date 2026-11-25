use std::io::{BufRead, Write};

use tokio::sync::mpsc;

/// The process's only reader of stdin. A thread feeds lines into a channel so
/// that every prompt and the paste fallback share one stream, and a reader
/// abandoned by `select!` cannot swallow a later answer.
pub struct Input {
    lines: mpsc::UnboundedReceiver<String>,
}

impl Input {
    pub fn new() -> Input {
        let (send, lines) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Input { lines }
    }

    /// The next line without its terminator, or `None` at end of input.
    pub async fn line(&mut self) -> Option<String> {
        self.lines.recv().await
    }

    /// Prints `text` and reads the answer.
    pub async fn prompt(&mut self, text: &str) -> Option<String> {
        print!("{text}");
        let _ = std::io::stdout().flush();
        self.line().await
    }
}
