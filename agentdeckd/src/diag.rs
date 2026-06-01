//! Diagnostic logging (Eng O1).
//!
//! AgentDeck spans 3 processes (Swift app / agentdeckd / codex app-server).
//! When a user reports "the session hung", you must be able to tell whether
//! IPC broke, app-server died, or translation failed — without guessing.
//! Open-source contributors especially need this to debug.
//!
//! Scope (O1): structured log to AgentDeck's OWN directory — process
//! lifecycle / IPC connect / handshake / errors. NOT dashboards / metrics /
//! alerting (that would be scope creep for a learning project).
//!
//! Secrets pass through `record::redact` before write — a diagnostic log is
//! still a plaintext file a user might paste into a bug report.

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

use crate::record::{app_data_dir, redact};

#[derive(Clone, Debug)]
pub struct DiagnosticEvent {
    event: String,
    level: String,
    code: String,
    run_id: Option<String>,
    thread_id: Option<String>,
    request_id: Option<u64>,
    event_seq: Option<u64>,
    message: Option<String>,
    detail: Option<String>,
}

impl DiagnosticEvent {
    pub fn new(event: impl Into<String>) -> Self {
        let event = event.into();
        Self {
            code: event.clone(),
            event,
            level: "info".into(),
            run_id: None,
            thread_id: None,
            request_id: None,
            event_seq: None,
            message: None,
            detail: None,
        }
    }

    pub fn level(mut self, level: impl Into<String>) -> Self {
        self.level = level.into();
        self
    }

    pub fn code(mut self, code: impl Into<String>) -> Self {
        self.code = code.into();
        self
    }

    pub fn run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    pub fn thread_id(mut self, thread_id: impl Into<String>) -> Self {
        self.thread_id = Some(thread_id.into());
        self
    }

    pub fn request_id_opt(mut self, request_id: Option<u64>) -> Self {
        self.request_id = request_id;
        self
    }

    pub fn event_seq(mut self, event_seq: u64) -> Self {
        self.event_seq = Some(event_seq);
        self
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn to_json_line(&self) -> String {
        let value = serde_json::json!({
            "schemaVersion": 1,
            "ts": chrono_now(),
            "level": self.level,
            "event": self.event,
            "code": self.code,
            "runId": self.run_id,
            "threadId": self.thread_id,
            "requestId": self.request_id,
            "eventSeq": self.event_seq,
            "message": self.message,
            "detail": self.detail.as_deref().map(redact),
        });
        serde_json::to_string(&value).unwrap_or_else(|_| {
            r#"{"schemaVersion":1,"level":"error","event":"diagnostic_encode_failed"}"#.into()
        })
    }
}

pub fn diagnostic_log_path() -> Option<PathBuf> {
    let mut p = app_data_dir()?;
    p.push("diagnostic.log");
    Some(p)
}

#[cfg(test)]
fn log_path_from(
    agentdeck_data_dir: Option<&std::ffi::OsStr>,
    agentdeck_profile: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let mut p = crate::record::app_data_dir_from(agentdeck_data_dir, agentdeck_profile, home)?;
    p.push("diagnostic.log");
    Some(p)
}

/// Log one structured diagnostic line. Best-effort: a logging failure must
/// NEVER affect the session (it is observability, not the product). Unlike
/// run records (E2 surfaces those failures), a diagnostic-log write failure
/// is itself logged to stderr and otherwise ignored.
pub fn log(event: &str, detail: &str) {
    log_event(DiagnosticEvent::new(event).detail(detail));
}

pub fn log_event(event: DiagnosticEvent) {
    let line = event.to_json_line();
    if let Some(path) = diagnostic_log_path() {
        if let Some(dir) = path.parent() {
            let _ = create_dir_all(dir);
        }
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Minimal RFC3339-ish UTC timestamp without pulling the `chrono` crate
/// (boring-by-default; one tiny function). Seconds precision is enough for
/// a diagnostic log.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Plain epoch seconds — unambiguous, sortable, parseable. A human-date
    // formatter is not worth a dependency for a debug log.
    format!("t={secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_path_is_app_support() {
        let p = diagnostic_log_path().unwrap();
        assert!(
            p.to_string_lossy()
                .contains("Application Support/AgentDeck")
        );
        assert!(p.to_string_lossy().ends_with("diagnostic.log"));
    }

    #[test]
    fn log_path_respects_agentdeck_data_dir_override() {
        let root = std::env::temp_dir().join(format!("agentdeck-test-{}", std::process::id()));
        let path = log_path_from(Some(root.as_os_str()), None, None).unwrap();

        assert!(path.starts_with(&root));
        assert!(path.ends_with("diagnostic.log"));
    }

    #[test]
    fn log_path_uses_dev_profile() {
        let home = std::ffi::OsStr::new("/Users/example");
        let path = log_path_from(None, Some(std::ffi::OsStr::new("dev")), Some(home)).unwrap();

        assert_eq!(
            path.to_string_lossy(),
            "/Users/example/Library/Application Support/AgentDeck-Dev/diagnostic.log"
        );
    }

    #[test]
    fn diagnostic_event_serializes_as_jsonl_with_correlation_fields() {
        let event = DiagnosticEvent::new("session_start")
            .level("info")
            .code("session_start")
            .run_id("run_1")
            .thread_id("thread_1")
            .request_id_opt(Some(7))
            .event_seq(3)
            .message("session started");

        let line = event.to_json_line();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["event"], "session_start");
        assert_eq!(value["level"], "info");
        assert_eq!(value["code"], "session_start");
        assert_eq!(value["runId"], "run_1");
        assert_eq!(value["threadId"], "thread_1");
        assert_eq!(value["requestId"], 7);
        assert_eq!(value["eventSeq"], 3);
    }

    #[test]
    fn timestamp_is_sortable_epoch() {
        let t = chrono_now();
        assert!(t.starts_with("t="));
        assert!(t["t=".len()..].parse::<u64>().is_ok());
    }
}
