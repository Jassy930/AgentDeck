//! CLI-internal synchronous transport over a spawned `agentdeckd` subprocess.
//!
//! The CLI always speaks to a local daemon child process. Admin commands use a
//! synchronous transport to keep their read loop small; session streaming uses
//! the async process wrapper below.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc;

#[cfg(test)]
use std::collections::VecDeque;

// ── Synchronous internal trait (used by Client) ──────────────────────────────

/// 阻塞式单连接传输缝。`recv` 返回 `Ok(None)` 表示 daemon EOF/断连。
/// 操作 raw JSON strings（JSONL lines），调用方负责 serde。
pub trait SyncTransport {
    fn send_line(&mut self, line: &str) -> std::io::Result<()>;
    fn recv_line(&mut self) -> std::io::Result<Option<String>>;
}

/// 内存测试传输：记录发出的行，按脚本顺序回放收到的行。
#[cfg(test)]
pub struct FakeTransport {
    pub sent: Vec<String>,
    incoming: VecDeque<String>,
}

#[cfg(test)]
impl FakeTransport {
    pub fn new(incoming: Vec<String>) -> Self {
        Self {
            sent: Vec::new(),
            incoming: incoming.into(),
        }
    }
}

#[cfg(test)]
impl SyncTransport for FakeTransport {
    fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        self.sent.push(line.to_string());
        Ok(())
    }
    fn recv_line(&mut self) -> std::io::Result<Option<String>> {
        Ok(self.incoming.pop_front())
    }
}

const DAEMON_BIN_ENV: &str = "AGENTDECK_DAEMON_BIN";

fn is_exec(p: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(p) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }
    true
}

fn explicit_daemon_path(value: OsString) -> std::io::Result<PathBuf> {
    if value.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{DAEMON_BIN_ENV} is set but empty"),
        ));
    }

    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{DAEMON_BIN_ENV} must be an absolute path: {}",
                path.display()
            ),
        ));
    }
    if !is_exec(&path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "{DAEMON_BIN_ENV} does not point to an executable file: {}",
                path.display()
            ),
        ));
    }
    Ok(path)
}

fn locate_daemon_with_override(explicit: Option<OsString>) -> std::io::Result<PathBuf> {
    if let Some(value) = explicit {
        return explicit_daemon_path(value);
    }

    // Production discovery is only allowed when no explicit override was
    // provided. In particular, an invalid test path must never fall through to
    // an older sibling or system installation.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sib = dir.join("agentdeckd");
            if is_exec(&sib) {
                return Ok(sib);
            }
        }
    }
    for c in [
        "target/debug/agentdeckd",
        "target/release/agentdeckd",
        "/usr/local/bin/agentdeckd",
        "/opt/homebrew/bin/agentdeckd",
    ] {
        let p = PathBuf::from(c);
        if is_exec(&p) {
            return Ok(p);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "agentdeckd not found (build it: cargo build -p agentdeckd)",
    ))
}

/// 定位 agentdeckd。`AGENTDECK_DAEMON_BIN` 一旦存在就必须是有效的绝对
/// executable 路径，失败时禁止回退；只有变量未设置时才使用 production locator。
pub fn locate_daemon() -> std::io::Result<PathBuf> {
    locate_daemon_with_override(std::env::var_os(DAEMON_BIN_ENV))
}

pub fn run_daemon_diagnostics_report(
    profile: &str,
    data_dir: Option<&str>,
) -> std::io::Result<String> {
    let path = locate_daemon()?;
    let mut cmd = Command::new(path);
    cmd.arg("--diagnostics-report")
        .arg("--profile")
        .arg(profile);
    if let Some(d) = data_dir {
        cmd.arg("--data-dir").arg(d);
    }
    let out = cmd.output()?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    Err(std::io::Error::other(format!(
        "agentdeckd --diagnostics-report failed: {stderr}{stdout}"
    )))
}

// ── Synchronous ProcessTransport (blocking I/O, used for admin commands) ─────

/// 真实传输：spawn agentdeckd，走其 stdin/stdout JSONL。
/// A1：Drop 时杀子进程，daemon 自身 Drop 级联杀 codex 进程组。
pub struct ProcessTransport {
    child: Child,
    reader: BufReader<ChildStdout>,
    stdin: ChildStdin,
}

impl ProcessTransport {
    pub fn spawn(profile: &str, data_dir: Option<&str>) -> std::io::Result<Self> {
        let path = locate_daemon()?;
        let mut cmd = Command::new(path);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        cmd.env("AGENTDECK_PROFILE", profile);
        if let Some(d) = data_dir {
            cmd.env("AGENTDECK_DATA_DIR", d);
        }
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Self {
            child,
            reader: BufReader::new(stdout),
            stdin,
        })
    }
}

impl SyncTransport for ProcessTransport {
    fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()
    }
    fn recv_line(&mut self) -> std::io::Result<Option<String>> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                return Ok(None);
            }
            let t = line.trim().to_string();
            if !t.is_empty() {
                return Ok(Some(t));
            }
        }
    }
}

impl Drop for ProcessTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Async streaming transport (used for session run/continue) ─────────────────

/// Spawns agentdeckd as a child process and provides async send/recv.
/// Used for session streaming where we need a tokio mpsc receiver.
///
/// Call `into_parts()` to split into a writer (keeps child alive) and
/// a line receiver channel.
pub struct AsyncProcessTransport {
    inner: Option<AsyncTransportInner>,
    line_rx: Option<mpsc::Receiver<String>>,
}

struct AsyncTransportInner {
    child: tokio::process::Child,
    writer: tokio::process::ChildStdin,
    reader_task: tokio::task::JoinHandle<()>,
}

impl AsyncProcessTransport {
    pub async fn spawn(profile: &str, data_dir: Option<&str>) -> std::io::Result<Self> {
        let path = locate_daemon()?;
        let mut cmd = TokioCommand::new(path);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.env("AGENTDECK_PROFILE", profile);
        if let Some(d) = data_dir {
            cmd.env("AGENTDECK_DATA_DIR", d);
        }
        let mut child = cmd.spawn()?;
        let writer = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");

        let (tx, rx) = mpsc::channel::<String>(256);
        let reader_task = tokio::spawn(async move {
            let mut reader = TokioBufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let t = line.trim().to_string();
                if !t.is_empty() {
                    if tx.send(t).await.is_err() {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            inner: Some(AsyncTransportInner {
                child,
                writer,
                reader_task,
            }),
            line_rx: Some(rx),
        })
    }

    pub async fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        let inner = self.inner.as_mut().expect("not split yet");
        inner.writer.write_all(line.as_bytes()).await?;
        inner.writer.write_all(b"\n").await?;
        inner.writer.flush().await
    }

    /// Split into (writer-half that keeps child alive, line receiver channel).
    pub fn into_parts(mut self) -> (AsyncTransportWriter, mpsc::Receiver<String>) {
        let inner = self.inner.take().expect("only call into_parts once");
        let rx = self.line_rx.take().expect("only call into_parts once");
        (
            AsyncTransportWriter {
                child: inner.child,
                _writer: inner.writer,
                reader_task: inner.reader_task,
            },
            rx,
        )
    }
}

/// Split the async transport into (writer half, line receiver channel).
pub fn split_async(
    transport: AsyncProcessTransport,
) -> (AsyncTransportWriter, mpsc::Receiver<String>) {
    transport.into_parts()
}

impl Drop for AsyncProcessTransport {
    fn drop(&mut self) {
        if let Some(ref mut inner) = self.inner {
            inner.reader_task.abort();
            let _ = inner.child.start_kill();
        }
    }
}

/// Writer half after splitting an `AsyncProcessTransport`.
/// Keeps the daemon child alive until dropped.
pub struct AsyncTransportWriter {
    child: tokio::process::Child,
    /// Stdin kept open so daemon doesn't get EOF until we drop.
    _writer: tokio::process::ChildStdin,
    reader_task: tokio::task::JoinHandle<()>,
}

impl Drop for AsyncTransportWriter {
    fn drop(&mut self) {
        self.reader_task.abort();
        let _ = self.child.start_kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_records_sent_and_replays_incoming() {
        let mut t = FakeTransport::new(vec![r#"{"reply":"pong"}"#.to_string()]);
        t.send_line(r#"{"command":"ping"}"#).unwrap();
        assert_eq!(t.sent.len(), 1);
        assert_eq!(t.sent[0], r#"{"command":"ping"}"#);
        assert_eq!(
            t.recv_line().unwrap().as_deref(),
            Some(r#"{"reply":"pong"}"#)
        );
        assert!(t.recv_line().unwrap().is_none());
    }

    #[test]
    fn locate_daemon_returns_path_or_error_without_panic() {
        // Actual fallback availability depends on build state.
        let _ = locate_daemon();
    }

    #[test]
    fn explicit_daemon_path_accepts_current_executable() {
        let current_exe = std::env::current_exe().expect("current test executable");
        let resolved = locate_daemon_with_override(Some(current_exe.clone().into_os_string()))
            .expect("current test executable should be a valid explicit daemon path");
        assert_eq!(resolved, current_exe);
    }

    #[test]
    fn explicit_daemon_path_rejects_relative_path_without_fallback() {
        let error = locate_daemon_with_override(Some(OsString::from("target/debug/agentdeckd")))
            .expect_err("relative override must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(DAEMON_BIN_ENV));
    }

    #[test]
    fn explicit_daemon_path_rejects_missing_absolute_path_without_fallback() {
        let missing =
            std::env::temp_dir().join(format!("agentdeck-missing-daemon-{}", std::process::id()));
        let error = locate_daemon_with_override(Some(missing.into_os_string()))
            .expect_err("missing override must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains(DAEMON_BIN_ENV));
    }

    #[test]
    fn explicit_daemon_path_rejects_empty_value_without_fallback() {
        let error = locate_daemon_with_override(Some(OsString::new()))
            .expect_err("empty override must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(DAEMON_BIN_ENV));
    }
}
