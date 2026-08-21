//! Runtime log hub used by the management SSE endpoint.
//!
//! The Go backend tails a bounded log file and then follows live writes.  The
//! Rust runtime keeps the same observable contract without making the HTTP
//! layer own a file descriptor: a bounded in-memory snapshot is paired with a
//! broadcast stream.  Applications can additionally persist these lines if
//! they want durable logs, while slow HTTP consumers are isolated by the
//! broadcast channel and bounded retention.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::broadcast;

const RETENTION: usize = 4096;
const SUBSCRIBER_CAPACITY: usize = 128;

#[derive(Clone)]
pub struct RuntimeLog {
    state: Arc<Mutex<VecDeque<String>>>,
    events: broadcast::Sender<Vec<String>>,
    console: Arc<AtomicBool>,
}

impl Default for RuntimeLog {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeLog {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(SUBSCRIBER_CAPACITY);
        Self {
            state: Arc::new(Mutex::new(VecDeque::with_capacity(RETENTION))),
            events,
            console: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mirror runtime log records to stderr for a foreground service process.
    ///
    /// The management API still receives the same bounded in-memory stream;
    /// this flag only adds a process-local diagnostic sink. It is disabled by
    /// default so library users and tests do not unexpectedly write to the
    /// terminal.
    pub fn enable_console(&self) {
        self.console.store(true, Ordering::Relaxed);
    }

    /// Publish one or more complete lines in the same `time= level= msg=`
    /// shape consumed by the existing React log parser.
    pub fn push(&self, level: &str, message: impl AsRef<str>) {
        let level = normalize_level(level);
        let lines = message
            .as_ref()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| format_line(level, line))
            .collect::<Vec<_>>();
        self.push_lines(lines);
    }

    /// Publish raw lines for adapters that already have a structured log
    /// formatter. Newlines are split so one SSE item never contains a partial
    /// record.
    pub fn push_raw(&self, message: impl AsRef<str>) {
        let lines = message
            .as_ref()
            .lines()
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        self.push_lines(lines);
    }

    pub fn info(&self, message: impl AsRef<str>) {
        self.push("INFO", message);
    }

    pub fn warn(&self, message: impl AsRef<str>) {
        self.push("WARN", message);
    }

    pub fn error(&self, message: impl AsRef<str>) {
        self.push("ERROR", message);
    }

    /// Subscribe before taking the snapshot. Writers serialize their append
    /// with this lock, so an event cannot be lost between the initial snapshot
    /// and the live stream. An event that races after the snapshot may be
    /// delivered twice; the UI treats log lines as an append-only feed, and
    /// the duplicate is preferable to silently losing a diagnostic.
    pub fn snapshot_and_subscribe(&self) -> (Vec<String>, broadcast::Receiver<Vec<String>>) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let receiver = self.events.subscribe();
        let snapshot = state.iter().cloned().collect();
        (snapshot, receiver)
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    fn push_lines(&self, lines: Vec<String>) {
        if lines.is_empty() {
            return;
        }
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for line in &lines {
                state.push_back(line.clone());
            }
            while state.len() > RETENTION {
                state.pop_front();
            }
        }
        if self.console.load(Ordering::Relaxed) {
            let stderr = std::io::stderr();
            let mut stderr = stderr.lock();
            for line in &lines {
                let _ = writeln!(stderr, "{line}");
            }
        }
        let _ = self.events.send(lines);
    }
}

pub fn log_batch_value(lines: Vec<String>) -> Value {
    serde_json::json!({"log": lines})
}

fn normalize_level(level: &str) -> &str {
    match level.trim().to_ascii_uppercase().as_str() {
        "ERROR" | "FATAL" => "ERROR",
        "WARN" | "WARNING" => "WARN",
        "DEBUG" | "TRACE" => "DEBUG",
        _ => "INFO",
    }
}

fn format_line(level: &str, message: &str) -> String {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let message =
        serde_json::to_string(message).unwrap_or_else(|_| "\"log encoding failed\"".to_owned());
    format!("time={timestamp} level={level} msg={message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_and_live_batches_follow_the_go_tail_contract() {
        let log = RuntimeLog::new();
        log.push_raw("old-1\nold-2\n");
        let (snapshot, mut events) = log.snapshot_and_subscribe();
        assert_eq!(snapshot, ["old-1", "old-2"]);

        log.info("new line");
        assert_eq!(events.recv().await.unwrap().len(), 1);
        assert!(
            log.snapshot()
                .iter()
                .any(|line| line.contains("msg=\"new line\""))
        );
    }

    #[test]
    fn retention_is_bounded_and_levels_are_frontend_compatible() {
        let log = RuntimeLog::new();
        for index in 0..(RETENTION + 10) {
            log.push("warning", format!("line-{index}"));
        }
        let snapshot = log.snapshot();
        assert_eq!(snapshot.len(), RETENTION);
        assert!(!snapshot[0].contains("line-0"));
        assert!(snapshot.last().unwrap().contains("level=WARN"));
        assert!(snapshot.last().unwrap().contains("msg=\"line-4105\""));
    }
}
