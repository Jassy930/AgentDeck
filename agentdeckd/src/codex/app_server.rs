//! Shared Codex app-server process and JSONL RPC primitives.
//!
//! Live sessions keep the child after the handshake, while history queries
//! use [`ShortLivedAppServer`] and tear it down after one bounded operation.
//! Both paths intentionally share binary discovery, PATH repair and wire
//! framing so GUI launches and history refreshes cannot drift apart.

use crate::codex::capabilities::probe_codex_version_at;
use agentdeck_protocol::ProtocolError;
use serde_json::{Value, json};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;

pub(super) const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(20);
pub(super) const SHORT_LIVED_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const STDERR_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const STDERR_WITHHELD_NOTE: &str =
    "\nCodex app-server wrote stderr; content withheld by the vendor-token boundary.";

fn unsupported_version_error(message: impl Into<String>) -> ProtocolError {
    ProtocolError {
        code: "codex-version-unsupported".into(),
        message: message.into(),
        diagnostic_ref: None,
    }
}

/// One canonical Codex executable together with its validated pinned version.
///
/// Session owners resolve this once, then pass the same value to capability
/// emission and app-server spawn. This prevents GUI PATH differences from
/// probing one executable and launching another.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexBinary {
    path: PathBuf,
    version: String,
}

impl CodexBinary {
    pub(crate) fn resolve() -> Result<Self, ProtocolError> {
        let path = locate_codex()?;
        let version = probe_codex_version_at(&path)?;
        Ok(Self { path, version })
    }

    /// Resolve and validate an explicitly injected executable. Production
    /// callers use [`Self::resolve`]; deterministic tests use this entrypoint
    /// so they never inspect or execute the user's PATH vendor.
    #[cfg(test)]
    pub(crate) fn resolve_at(path: &Path) -> Result<Self, ProtocolError> {
        let path = path.canonicalize().map_err(|_| {
            unsupported_version_error("supported Codex CLI executable could not be resolved")
        })?;
        if !path.is_file() || !path.is_absolute() {
            return Err(unsupported_version_error(
                "supported Codex CLI executable could not be resolved",
            ));
        }
        let version = probe_codex_version_at(&path)?;
        Ok(Self { path, version })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn version(&self) -> &str {
        &self.version
    }
}

/// Continuously drain stderr shared by live and short-lived app-server
/// clients. K9 forbids AgentDeck from saving or forwarding vendor tokens, so
/// the bytes are discarded immediately; only a boolean "had output" marker
/// may be attached to a protocol error.
#[derive(Clone, Debug)]
pub(super) struct StderrTail {
    saw_output: Arc<AtomicBool>,
}

impl StderrTail {
    fn start<R>(mut stderr: R) -> (Self, JoinHandle<Result<(), ProtocolError>>)
    where
        R: AsyncRead + Send + Unpin + 'static,
    {
        let saw_output = Arc::new(AtomicBool::new(false));
        let drain_marker = Arc::clone(&saw_output);
        let stderr_drain = tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) => return Ok(()),
                    Ok(_) => drain_marker.store(true, Ordering::Relaxed),
                    Err(error) => {
                        return Err(ProtocolError {
                            code: "codex-cleanup-failed".into(),
                            message: format!("failed to drain Codex stderr: {error}"),
                            diagnostic_ref: None,
                        });
                    }
                }
            }
        });
        (Self { saw_output }, stderr_drain)
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
pub(super) fn drain_child_stderr(
    child: &mut Child,
) -> Result<(StderrTail, JoinHandle<Result<(), ProtocolError>>), ProtocolError> {
    let stderr = child.stderr.take().ok_or_else(|| ProtocolError {
        code: "codex-spawn-failed".into(),
        message: "codex child missing stderr pipe".into(),
        diagnostic_ref: None,
    })?;
    Ok(StderrTail::start(stderr))
}

/// Join the stderr pump after the child has been reaped. A reaped process
/// closes the pipe, so a pump that does not stop within this bound means the
/// cleanup proof is incomplete. On any failure the task is aborted and joined
/// before returning so it can never detach past `SessionClosed`.
pub(super) async fn join_stderr_drain(
    stderr_drain: &mut Option<JoinHandle<Result<(), ProtocolError>>>,
    child_reaped: bool,
) -> Result<(), ProtocolError> {
    let Some(mut task) = stderr_drain.take() else {
        return Ok(());
    };

    if !child_reaped {
        task.abort();
        let _ = task.await;
        return Err(ProtocolError {
            code: "codex-cleanup-failed".into(),
            message: "Codex app-server cleanup did not confirm child exit".into(),
            diagnostic_ref: None,
        });
    }

    match tokio::time::timeout(STDERR_DRAIN_TIMEOUT, &mut task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(error),
        Ok(Err(error)) => Err(ProtocolError {
            code: "codex-cleanup-failed".into(),
            message: format!("Codex stderr pump failed to join: {error}"),
            diagnostic_ref: None,
        }),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(ProtocolError {
                code: "codex-cleanup-failed".into(),
                message: "timed out waiting for Codex stderr pump to stop".into(),
                diagnostic_ref: None,
            })
        }
    }
}

/// Locate the `codex` binary even when a macOS GUI process inherited a
/// stripped PATH.
pub(crate) fn locate_codex() -> Result<PathBuf, ProtocolError> {
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            let candidate = directory.join("codex");
            if let Some(path) = canonical_executable(&candidate) {
                return Ok(path);
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
        if let Some(path) = canonical_executable(&candidate) {
            return Ok(path);
        }
    }
    Err(unsupported_version_error(
        "supported Codex CLI executable was not found on PATH or common locations",
    ))
}

fn canonical_executable(candidate: &Path) -> Option<PathBuf> {
    candidate
        .is_file()
        .then(|| candidate.canonicalize().ok())
        .flatten()
        .filter(|path| path.is_absolute())
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

/// Spawn one app-server using the exact executable already version-validated
/// by the session owner.
pub(crate) fn spawn_child_with_binary(
    cwd: &Path,
    codex: &CodexBinary,
) -> Result<Child, ProtocolError> {
    let child_path = child_path_env(std::env::var("PATH").ok().as_deref());
    let mut command = Command::new(codex.path());
    command
        .args(["app-server", "--listen", "stdio://"])
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
/// [`Child`] can leave descendants behind. The app-server spawn path gives each child
/// its own process group on Unix; a negative pid targets that entire group.
/// We still kill the direct child explicitly on every platform.
pub(super) fn kill_process_group(child: &mut Child) {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            let _ = signal_process_group(pid);
        }
    }
    let _ = child.start_kill();
}

/// Signal a previously captured independent process group. `ESRCH` means the
/// group is already gone; a successful signal only confirms delivery, not that
/// every process has exited.
#[cfg(unix)]
pub(super) fn signal_process_group(process_group_id: u32) -> io::Result<()> {
    let result = unsafe { libc_kill(-(process_group_id as i32), SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
pub(super) fn signal_process_group(_process_group_id: u32) -> io::Result<()> {
    Ok(())
}

/// Check whether any process still belongs to a previously captured process
/// group. Live-session cleanup polls this after signaling until `ESRCH`
/// confirms that the group has disappeared.
#[cfg(unix)]
pub(super) fn process_group_exists(process_group_id: u32) -> io::Result<bool> {
    let result = unsafe { libc_kill(-(process_group_id as i32), 0) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
pub(super) fn process_group_exists(_process_group_id: u32) -> io::Result<bool> {
    Ok(false)
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

/// Complete the official Codex initialize handshake. This notification has
/// no response and must be written only after a successful initialize result.
pub(crate) async fn write_initialized(stdin: &mut ChildStdin) -> Result<(), ProtocolError> {
    write_frame(stdin, &json!({ "method": "initialized" })).await
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
    stderr_drain: Option<JoinHandle<Result<(), ProtocolError>>>,
}

impl ShortLivedAppServer {
    pub(super) fn spawn(cwd: &Path) -> Result<Self, ProtocolError> {
        let binary = CodexBinary::resolve()?;
        Self::spawn_with_binary(cwd, &binary)
    }

    pub(crate) fn spawn_with_binary(
        cwd: &Path,
        binary: &CodexBinary,
    ) -> Result<Self, ProtocolError> {
        let mut child = spawn_child_with_binary(cwd, binary)?;
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
        let (stderr_tail, stderr_drain) = drain_child_stderr(&mut child)?;
        Ok(Self {
            child: Some(child),
            stdin,
            reader: BufReader::new(stdout),
            line_buf: String::new(),
            next_id: 1,
            stderr_tail,
            stderr_drain: Some(stderr_drain),
        })
    }

    pub(super) async fn initialize(&mut self) -> Result<Value, ProtocolError> {
        let result = self
            .request(
                "initialize",
                json!({
                    "clientInfo": {
                        "name": "agentdeck",
                        "version": env!("CARGO_PKG_VERSION"),
                    }
                }),
            )
            .await?;
        write_initialized(&mut self.stdin)
            .await
            .map_err(|error| self.stderr_tail.enrich_error(error))?;
        Ok(result)
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
            let _ = join_stderr_drain(&mut self.stderr_drain, false).await;
            return;
        };
        kill_process_group(&mut child);
        let reaped = matches!(
            tokio::time::timeout(SHORT_LIVED_SHUTDOWN_TIMEOUT, child.wait()).await,
            Ok(Ok(_))
        );
        let _ = join_stderr_drain(&mut self.stderr_drain, reaped).await;
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
const ESRCH: i32 = 3;
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    struct FakeCodex {
        root: PathBuf,
        executable: PathBuf,
        log: PathBuf,
    }

    #[cfg(unix)]
    impl FakeCodex {
        fn new(version: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "agentdeck-fake-codex-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).unwrap();
            let executable = root.join("codex");
            let log = root.join("calls.log");
            let script = format!(
                r#"#!/bin/sh
log={log}
if [ "$1" = "--version" ]; then
  printf 'probe|%s|%s\n' "$0" "$*" >> "$log"
  printf '%s\n' {version}
  exit 0
fi

printf 'spawn|%s|%s\n' "$0" "$*" >> "$log"
IFS= read -r frame || exit 10
printf 'frame|%s\n' "$frame" >> "$log"
printf '{{"id":1,"result":{{"fake":true}}}}\n'
IFS= read -r frame || exit 11
printf 'frame|%s\n' "$frame" >> "$log"
IFS= read -r frame || exit 12
printf 'frame|%s\n' "$frame" >> "$log"
printf '{{"id":2,"result":{{"ok":true}}}}\n'
while IFS= read -r frame; do
  printf 'frame|%s\n' "$frame" >> "$log"
done
"#,
                log = shell_quote(&log),
                version = shell_quote(Path::new(version)),
            );
            fs::write(&executable, script).unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&executable, permissions).unwrap();
            Self {
                root,
                executable,
                log,
            }
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(&self.log)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    #[cfg(unix)]
    impl Drop for FakeCodex {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn shell_quote(value: &Path) -> String {
        format!("'{}'", value.to_string_lossy().replace('\'', "'\"'\"'"))
    }

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

    struct FailingStderr;

    impl AsyncRead for FailingStderr {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "synthetic stderr read failure",
            )))
        }
    }

    #[tokio::test]
    async fn stderr_read_error_is_a_cleanup_failure() {
        let (_tail, task) = StderrTail::start(FailingStderr);
        let mut drain = Some(task);

        let error = join_stderr_drain(&mut drain, true).await.unwrap_err();

        assert_eq!(error.code, "codex-cleanup-failed");
        assert!(error.message.contains("failed to drain Codex stderr"));
        assert!(drain.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_binary_is_probed_and_spawned_by_the_same_canonical_path() {
        let fake = FakeCodex::new("codex-cli 0.145.0");
        let binary = CodexBinary::resolve_at(&fake.executable).unwrap();
        let canonical = fake.executable.canonicalize().unwrap();

        assert!(binary.path().is_absolute());
        assert_eq!(binary.path(), canonical);
        assert_eq!(binary.version(), "codex-cli 0.145.0");

        let mut client = ShortLivedAppServer::spawn_with_binary(&fake.root, &binary).unwrap();
        assert_eq!(client.initialize().await.unwrap(), json!({ "fake": true }));
        assert_eq!(
            client.request("fake/ping", json!({})).await.unwrap(),
            json!({ "ok": true })
        );
        client.shutdown().await;

        let calls = fake.calls();
        assert_eq!(calls.len(), 5, "unexpected fake Codex calls: {calls:?}");
        assert_eq!(calls[0], format!("probe|{}|--version", canonical.display()));
        assert_eq!(
            calls[1],
            format!("spawn|{}|app-server --listen stdio://", canonical.display())
        );

        let initialize: Value = serde_json::from_str(
            calls[2]
                .strip_prefix("frame|")
                .expect("initialize frame marker"),
        )
        .unwrap();
        assert_eq!(initialize["id"], 1);
        assert_eq!(initialize["method"], "initialize");

        let initialized: Value = serde_json::from_str(
            calls[3]
                .strip_prefix("frame|")
                .expect("initialized frame marker"),
        )
        .unwrap();
        assert_eq!(initialized, json!({ "method": "initialized" }));

        let next_request: Value = serde_json::from_str(
            calls[4]
                .strip_prefix("frame|")
                .expect("next request frame marker"),
        )
        .unwrap();
        assert_eq!(next_request["id"], 2);
        assert_eq!(next_request["method"], "fake/ping");
    }

    #[cfg(unix)]
    #[test]
    fn injected_missing_or_mismatched_binary_uses_stable_error_code() {
        let root = std::env::temp_dir().join(format!(
            "agentdeck-missing-codex-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let missing = CodexBinary::resolve_at(&root.join("codex")).unwrap_err();
        assert_eq!(missing.code, "codex-version-unsupported");

        let fake = FakeCodex::new("codex-cli 0.146.0");
        let mismatch = CodexBinary::resolve_at(&fake.executable).unwrap_err();
        assert_eq!(mismatch.code, "codex-version-unsupported");
        assert_eq!(fake.calls().len(), 1, "mismatch must not spawn app-server");
        assert!(fake.calls()[0].ends_with("|--version"));
    }
}
