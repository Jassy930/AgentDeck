//! Shared Codex app-server process and JSONL RPC primitives.
//!
//! Live sessions keep the child after the handshake, while history queries
//! use [`ShortLivedAppServer`] and tear it down after one bounded operation.
//! Both paths intentionally share binary discovery, PATH repair and wire
//! framing so GUI launches and history refreshes cannot drift apart.

use agentdeck_protocol::ProtocolError;
use serde_json::{Value, json};
use std::path::Path;
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

pub(super) const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(20);
pub(super) const SHORT_LIVED_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const STDERR_WITHHELD_NOTE: &str =
    "\nCodex app-server wrote stderr; content withheld by the vendor-token boundary.";

/// Continuously drain stderr shared by live and short-lived app-server
/// clients. K9 forbids AgentDeck from saving or forwarding vendor tokens, so
/// the bytes are discarded immediately; only a boolean "had output" marker
/// may be attached to a protocol error.
#[derive(Clone, Debug)]
pub(super) struct StderrTail {
    saw_output: Arc<AtomicBool>,
}

impl StderrTail {
    fn start(mut stderr: ChildStderr) -> Self {
        let saw_output = Arc::new(AtomicBool::new(false));
        let drain_marker = Arc::clone(&saw_output);
        let _stderr_drain = tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => drain_marker.store(true, Ordering::Relaxed),
                }
            }
        });
        Self { saw_output }
    }

    pub(super) fn enrich_error(&self, mut error: ProtocolError) -> ProtocolError {
        if self.saw_output.load(Ordering::Relaxed) {
            let base = error
                .message
                .split_once(STDERR_WITHHELD_NOTE)
                .map(|(base, _)| base)
                .unwrap_or(&error.message);
            error.message = format!("{base}{STDERR_WITHHELD_NOTE}");
        }
        error
    }
}

/// Take ownership of the child's stderr pipe and keep draining it. Taking the
/// pipe without a reader closes it and can both hide diagnostics and make a
/// chatty child fail with EPIPE.
pub(super) fn drain_child_stderr(child: &mut Child) -> Result<StderrTail, ProtocolError> {
    let stderr = child.stderr.take().ok_or_else(|| ProtocolError {
        code: "codex-spawn-failed".into(),
        message: "codex child missing stderr pipe".into(),
        diagnostic_ref: None,
    })?;
    Ok(StderrTail::start(stderr))
}

/// Locate the `codex` binary even when a macOS GUI process inherited a
/// stripped PATH.
fn locate_codex() -> Result<String, ProtocolError> {
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            let candidate = directory.join("codex");
            if candidate.is_file() {
                return Ok(candidate.to_string_lossy().into_owned());
            }
        }
    }

    let mut candidates = vec![
        Path::new("/opt/homebrew/bin/codex").to_path_buf(),
        Path::new("/usr/local/bin/codex").to_path_buf(),
        Path::new("/usr/bin/codex").to_path_buf(),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let home = Path::new(&home);
        candidates.push(home.join(".local/bin/codex"));
        candidates.push(home.join(".bun/bin/codex"));
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(ProtocolError {
        code: "codex-not-found".into(),
        message: "codex binary not found on PATH or common locations".into(),
        diagnostic_ref: None,
    })
}

fn child_path_env(base: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = Path::new(&home);
        for path in [home.join(".local/bin"), home.join(".bun/bin")] {
            parts.push(path.to_string_lossy().into_owned());
        }
    }
    for path in [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ] {
        parts.push(path.into());
    }
    if let Some(base) = base {
        for path in base.split(':').filter(|path| !path.is_empty()) {
            if !parts.iter().any(|existing| existing == path) {
                parts.push(path.into());
            }
        }
    }
    parts.join(":")
}

/// Spawn one app-server child in its own process group.
pub(super) fn spawn_child(cwd: &Path) -> Result<Child, ProtocolError> {
    let codex = locate_codex()?;
    let child_path = child_path_env(std::env::var("PATH").ok().as_deref());
    let mut command = Command::new(codex);
    command
        .arg("app-server")
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PATH", child_path)
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    command.spawn().map_err(|error| ProtocolError {
        code: "codex-spawn-failed".into(),
        message: format!("failed to spawn codex app-server: {error}"),
        diagnostic_ref: None,
    })
}

/// Best-effort termination for one app-server child and its process group.
///
/// Codex may spawn MCP helpers below the direct child, so killing only the
/// [`Child`] can leave descendants behind. `spawn_child` gives each app-server
/// its own process group on Unix; a negative pid targets that entire group.
/// We still kill the direct child explicitly on every platform.
pub(super) fn kill_process_group(child: &mut Child) {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            unsafe {
                libc_kill(-(pid as i32), SIGKILL);
            }
        }
    }
    let _ = child.start_kill();
}

/// Write one newline-delimited Codex JSON-RPC frame.
pub(super) async fn write_frame(
    stdin: &mut ChildStdin,
    frame: &Value,
) -> Result<(), ProtocolError> {
    let mut line = serde_json::to_string(frame).map_err(|error| ProtocolError {
        code: "codex-encode-failed".into(),
        message: format!("serialize codex frame: {error}"),
        diagnostic_ref: None,
    })?;
    line.push('\n');
    stdin
        .write_all(line.as_bytes())
        .await
        .map_err(|error| ProtocolError {
            code: "codex-stdin-write-failed".into(),
            message: format!("write to codex stdin: {error}"),
            diagnostic_ref: None,
        })?;
    stdin.flush().await.map_err(|error| ProtocolError {
        code: "codex-stdin-write-failed".into(),
        message: format!("flush codex stdin: {error}"),
        diagnostic_ref: None,
    })?;
    Ok(())
}

async fn read_frame(
    reader: &mut BufReader<ChildStdout>,
    line_buf: &mut String,
) -> Result<Option<Value>, ProtocolError> {
    line_buf.clear();
    let bytes = reader
        .read_line(line_buf)
        .await
        .map_err(|error| ProtocolError {
            code: "codex-stdout-read-failed".into(),
            message: format!("read codex stdout: {error}"),
            diagnostic_ref: None,
        })?;
    if bytes == 0 {
        return Ok(None);
    }
    serde_json::from_str(line_buf.trim())
        .map(Some)
        .map_err(|error| ProtocolError {
            code: "codex-malformed-json".into(),
            // Never echo a vendor frame into AgentDeck IPC: malformed output
            // can still contain credentials or other vendor-private data.
            message: format!("malformed codex frame: {error}"),
            diagnostic_ref: None,
        })
}

/// Send one request and wait for its matching response, ignoring unrelated
/// notifications that may be interleaved by app-server.
pub(super) async fn request_response(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    line_buf: &mut String,
    id: u64,
    method: &str,
    params: Value,
    timeout: Duration,
    stderr_tail: &StderrTail,
) -> Result<Value, ProtocolError> {
    let result = async {
        write_frame(
            stdin,
            &json!({ "id": id, "method": method, "params": params }),
        )
        .await?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(ProtocolError {
                    code: "codex-handshake-timeout".into(),
                    message: format!("timed out waiting for {method} response"),
                    diagnostic_ref: None,
                });
            }
            let frame = match tokio::time::timeout(remaining, read_frame(reader, line_buf)).await {
                Ok(Ok(Some(frame))) => frame,
                Ok(Ok(None)) => {
                    return Err(ProtocolError {
                        code: "codex-disconnected".into(),
                        message: format!("codex closed stdout before {method} response"),
                        diagnostic_ref: None,
                    });
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(ProtocolError {
                        code: "codex-handshake-timeout".into(),
                        message: format!("timed out waiting for {method} response"),
                        diagnostic_ref: None,
                    });
                }
            };
            if frame.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(error) = frame.get("error").filter(|value| !value.is_null()) {
                    let code = error
                        .get("code")
                        .and_then(Value::as_i64)
                        .map(|code| format!(" (code {code})"))
                        .unwrap_or_default();
                    return Err(ProtocolError {
                        code: "codex-protocol-error".into(),
                        // The vendor-provided message is intentionally not
                        // forwarded because it may embed a token.
                        message: format!("codex {method} returned a protocol error{code}"),
                        diagnostic_ref: None,
                    });
                }
                return Ok(frame.get("result").cloned().unwrap_or(Value::Null));
            }
        }
    }
    .await;
    result.map_err(|error| stderr_tail.enrich_error(error))
}

/// A bounded, sequential app-server connection for history and other
/// request/response-only operations.
pub(super) struct ShortLivedAppServer {
    child: Option<Child>,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    line_buf: String,
    next_id: u64,
    stderr_tail: StderrTail,
}

impl ShortLivedAppServer {
    pub(super) fn spawn(cwd: &Path) -> Result<Self, ProtocolError> {
        let mut child = spawn_child(cwd)?;
        let stdin = child.stdin.take().ok_or_else(|| ProtocolError {
            code: "codex-spawn-failed".into(),
            message: "codex child missing stdin pipe".into(),
            diagnostic_ref: None,
        })?;
        let stdout = child.stdout.take().ok_or_else(|| ProtocolError {
            code: "codex-spawn-failed".into(),
            message: "codex child missing stdout pipe".into(),
            diagnostic_ref: None,
        })?;
        let stderr_tail = drain_child_stderr(&mut child)?;
        Ok(Self {
            child: Some(child),
            stdin,
            reader: BufReader::new(stdout),
            line_buf: String::new(),
            next_id: 1,
            stderr_tail,
        })
    }

    pub(super) async fn initialize(&mut self) -> Result<Value, ProtocolError> {
        self.request(
            "initialize",
            json!({
                "clientInfo": {
                    "name": "agentdeck",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }),
        )
        .await
    }

    pub(super) async fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, ProtocolError> {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or_else(|| ProtocolError {
            code: "codex-rpc-id-exhausted".into(),
            message: "codex app-server request id exhausted".into(),
            diagnostic_ref: None,
        })?;
        request_response(
            &mut self.stdin,
            &mut self.reader,
            &mut self.line_buf,
            id,
            method,
            params,
            DEFAULT_RPC_TIMEOUT,
            &self.stderr_tail,
        )
        .await
        .map_err(map_short_lived_error)
    }

    pub(super) fn enrich_error(&self, error: ProtocolError) -> ProtocolError {
        self.stderr_tail.enrich_error(error)
    }

    pub(super) async fn shutdown(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        kill_process_group(&mut child);
        let _ = tokio::time::timeout(SHORT_LIVED_SHUTDOWN_TIMEOUT, child.wait()).await;
    }
}

fn map_short_lived_error(mut error: ProtocolError) -> ProtocolError {
    if error.code == "codex-handshake-timeout" {
        error.code = "codex-rpc-timeout".into();
    }
    error
}

impl Drop for ShortLivedAppServer {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            kill_process_group(child);
        }
    }
}

// Negative pid = every process in the group whose pgid equals pid. Keep this
// minimal binding local rather than pulling in the libc crate for one symbol.
#[cfg(unix)]
const SIGKILL: i32 = 9;
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_contents_are_never_forwarded_through_protocol_error() {
        let tail = StderrTail {
            saw_output: Arc::new(AtomicBool::new(true)),
        };
        let error = tail.enrich_error(ProtocolError {
            code: "codex-disconnected".into(),
            message: "codex closed stdout before initialize response".into(),
            diagnostic_ref: None,
        });

        assert!(error.message.contains("content withheld"));
        assert!(!error.message.contains("sk-secret123456789"));
        assert!(!error.message.contains("access_token"));
    }

    #[test]
    fn refreshing_stderr_marker_does_not_duplicate_the_diagnostic_suffix() {
        let tail = StderrTail {
            saw_output: Arc::new(AtomicBool::new(true)),
        };
        let first = tail.enrich_error(ProtocolError {
            code: "codex-disconnected".into(),
            message: "closed".into(),
            diagnostic_ref: None,
        });
        let second = tail.enrich_error(first);

        assert_eq!(second.message.matches(STDERR_WITHHELD_NOTE).count(), 1);
    }

    #[test]
    fn short_lived_requests_use_rpc_timeout_code() {
        let error = map_short_lived_error(ProtocolError {
            code: "codex-handshake-timeout".into(),
            message: "timed out waiting for thread/list response".into(),
            diagnostic_ref: None,
        });
        assert_eq!(error.code, "codex-rpc-timeout");
        assert!(error.message.contains("thread/list"));
    }

    #[test]
    fn short_lived_requests_preserve_non_timeout_errors() {
        let error = map_short_lived_error(ProtocolError {
            code: "codex-disconnected".into(),
            message: "closed stdout".into(),
            diagnostic_ref: None,
        });
        assert_eq!(error.code, "codex-disconnected");
    }
}
