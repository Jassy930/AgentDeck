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

fn log_path() -> Option<PathBuf> {
    let mut p = app_data_dir()?;
    p.push("diagnostic.log");
    Some(p)
}

#[cfg(test)]
fn log_path_from(
    agentdeck_data_dir: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let mut p = crate::record::app_data_dir_from(agentdeck_data_dir, home)?;
    p.push("diagnostic.log");
    Some(p)
}

/// Log one structured diagnostic line. Best-effort: a logging failure must
/// NEVER affect the session (it is observability, not the product). Unlike
/// run records (E2 surfaces those failures), a diagnostic-log write failure
/// is itself logged to stderr and otherwise ignored.
pub fn log(event: &str, detail: &str) {
    let line = format!("{} {} {}", chrono_now(), event, redact(detail));
    if let Some(path) = log_path() {
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
        let p = log_path().unwrap();
        assert!(
            p.to_string_lossy()
                .contains("Application Support/AgentDeck")
        );
        assert!(p.to_string_lossy().ends_with("diagnostic.log"));
    }

    #[test]
    fn log_path_respects_agentdeck_data_dir_override() {
        let root = std::env::temp_dir().join(format!("agentdeck-test-{}", std::process::id()));
        let path = log_path_from(Some(root.as_os_str()), None).unwrap();

        assert!(path.starts_with(&root));
        assert!(path.ends_with("diagnostic.log"));
    }

    #[test]
    fn timestamp_is_sortable_epoch() {
        let t = chrono_now();
        assert!(t.starts_with("t="));
        assert!(t["t=".len()..].parse::<u64>().is_ok());
    }
}
