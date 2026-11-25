use std::io::{BufRead, Write};
use std::sync::mpsc as std_mpsc;

use tokio::sync::mpsc;

/// The process's only reader of stdin. A thread reads one line each time
/// `line()` asks for one, so no read is pending while a child process such as
/// `ssh-keygen` owns the terminal. A request outlives a cancelled `line()`
/// (for example inside `select!`), and its answer is delivered to the next call.
pub struct Input {
    requests: std_mpsc::Sender<()>,
    lines: mpsc::UnboundedReceiver<Option<String>>,
    pending: bool,
    eof: bool,
}

impl Input {
    pub fn new() -> Input {
        Input::from_reader(std::io::BufReader::new(std::io::stdin()))
    }

    pub fn from_reader(mut reader: impl BufRead + Send + 'static) -> Input {
        let (requests, wanted) = std_mpsc::channel::<()>();
        let (send, lines) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            while wanted.recv().is_ok() {
                let mut line = String::new();
                let answer = match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => None,
                    Ok(_) => Some(line.trim_end_matches(['\n', '\r']).to_string()),
                };
                let done = answer.is_none();
                if send.send(answer).is_err() || done {
                    break;
                }
            }
        });
        Input {
            requests,
            lines,
            pending: false,
            eof: false,
        }
    }

    /// The next line without its terminator, or `None` at end of input.
    /// Cancel-safe.
    pub async fn line(&mut self) -> Option<String> {
        if self.eof {
            return None;
        }
        if !self.pending {
            if self.requests.send(()).is_err() {
                self.eof = true;
                return None;
            }
            self.pending = true;
        }
        let answer = self.lines.recv().await.flatten();
        self.pending = false;
        if answer.is_none() {
            self.eof = true;
        }
        answer
    }

    /// Prints `text` and reads the answer.
    pub async fn prompt(&mut self, text: &str) -> Option<String> {
        print!("{text}");
        let _ = std::io::stdout().flush();
        self.line().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct Counting(Arc<AtomicUsize>, std::io::Cursor<&'static str>);

    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.fetch_add(1, Ordering::SeqCst);
            self.1.read(buf)
        }
    }

    #[tokio::test]
    async fn reads_only_when_asked() {
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = std::io::BufReader::new(Counting(
            reads.clone(),
            std::io::Cursor::new("one\r\ntwo\n"),
        ));
        let mut input = Input::from_reader(reader);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(input.line().await.as_deref(), Some("one"));
        assert_eq!(input.line().await.as_deref(), Some("two"));
        assert_eq!(input.line().await, None);
        assert_eq!(input.line().await, None);
    }

    #[tokio::test]
    async fn cancelled_line_keeps_its_answer() {
        let reader = std::io::Cursor::new("one\ntwo\n");
        let mut input = Input::from_reader(reader);
        tokio::select! {
            biased;
            _ = std::future::ready(()) => {}
            _ = input.line() => unreachable!(),
        }
        assert_eq!(input.line().await.as_deref(), Some("one"));
        assert_eq!(input.line().await.as_deref(), Some("two"));
    }
}
