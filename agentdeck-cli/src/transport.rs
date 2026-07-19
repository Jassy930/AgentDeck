//! 显式 legacy/test 的 stdio compatibility transport。
//!
//! The protocol crate defines an *async* `Transport` trait for remote impls
//! (v0.5+). P3.9-A 的 production shared-daemon client 在 `unix_transport.rs`；本文件
//! 只保留需要明确选择的 IPC v2/stdin compatibility 与 one-shot diagnostics。

use agentdeck_protocol::AuthContext;
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

fn is_exec(p: &std::path::Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// 定位 agentdeckd：优先当前可执行文件同目录（同一 target dir），再回退
/// cwd 相对 dev 路径与常见安装位置（与 Swift DaemonClient.locateDaemon 同策略）。
pub fn locate_daemon() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sib = dir.join("agentdeckd");
        if is_exec(&sib) {
            return Some(sib);
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
            return Some(p);
        }
    }
    None
}

pub fn run_daemon_diagnostics_report(
    profile: &str,
    data_dir: Option<&str>,
) -> std::io::Result<String> {
    let path = locate_daemon().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "agentdeckd not found (build it: cargo build -p agentdeckd)",
        )
    })?;
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

const STDIO_DAEMON_ARGS: [&str; 5] = [
    "--stdio-compat",
    "--ephemeral",
    "--no-remote",
    "--profile",
    "dev",
];

fn configure_sync_stdio_daemon(command: &mut Command) {
    command.args(STDIO_DAEMON_ARGS);
    command.env_remove("AGENTDECK_DATA_DIR");
    command.env_remove("AGENTDECK_PROFILE");
}

fn configure_async_stdio_daemon(command: &mut TokioCommand) {
    command.args(STDIO_DAEMON_ARGS);
    command.env_remove("AGENTDECK_DATA_DIR");
    command.env_remove("AGENTDECK_PROFILE");
}

// ── Explicit legacy synchronous stdio compatibility ───────────────────────────

/// 过渡传输：spawn 隔离、无远程能力的 dev agentdeckd，走 stdin/stdout JSONL。
/// `profile` / `data_dir` 仅为兼容旧调用签名保留，不会进入 stable namespace。
/// A1：Drop 时杀子进程，daemon 自身 Drop 级联杀 codex 进程组。
pub struct LegacyStdioProcessTransport {
    child: Child,
    reader: BufReader<ChildStdout>,
    stdin: ChildStdin,
}

impl LegacyStdioProcessTransport {
    pub fn spawn(_profile: &str, _data_dir: Option<&str>) -> std::io::Result<Self> {
        let path = locate_daemon().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "agentdeckd not found (build it: cargo build -p agentdeckd)",
            )
        })?;
        let mut cmd = Command::new(path);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        configure_sync_stdio_daemon(&mut cmd);
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

impl SyncTransport for LegacyStdioProcessTransport {
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

impl Drop for LegacyStdioProcessTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Async streaming transport (used for session run/continue) ─────────────────

/// Spawns an isolated, no-remote dev agentdeckd child and provides async send/recv.
/// The legacy profile/data-dir inputs are intentionally not forwarded.
/// Used for session streaming where we need a tokio mpsc receiver.
///
/// Call `into_parts()` to split into a writer (keeps child alive) and
/// a line receiver channel.
pub struct LegacyAsyncStdioProcessTransport {
    inner: Option<LegacyAsyncTransportInner>,
    line_rx: Option<mpsc::Receiver<String>>,
}

struct LegacyAsyncTransportInner {
    child: tokio::process::Child,
    writer: tokio::process::ChildStdin,
    reader_task: tokio::task::JoinHandle<()>,
    auth: AuthContext,
}

impl LegacyAsyncStdioProcessTransport {
    pub async fn spawn(_profile: &str, _data_dir: Option<&str>) -> std::io::Result<Self> {
        let path = locate_daemon().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "agentdeckd not found (build it: cargo build -p agentdeckd)",
            )
        })?;
        let mut cmd = TokioCommand::new(path);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_async_stdio_daemon(&mut cmd);
        let mut child = cmd.spawn()?;
        let writer = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");

        let (tx, rx) = mpsc::channel::<String>(256);
        let reader_task = tokio::spawn(async move {
            let mut reader = TokioBufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let t = line.trim().to_string();
                if !t.is_empty() && tx.send(t).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            inner: Some(LegacyAsyncTransportInner {
                child,
                writer,
                reader_task,
                auth: AuthContext::Anonymous,
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
    pub fn into_parts(mut self) -> (LegacyAsyncTransportWriter, mpsc::Receiver<String>) {
        let inner = self.inner.take().expect("only call into_parts once");
        let rx = self.line_rx.take().expect("only call into_parts once");
        (
            LegacyAsyncTransportWriter {
                child: inner.child,
                _writer: inner.writer,
                reader_task: inner.reader_task,
                auth: inner.auth,
            },
            rx,
        )
    }
}

/// Split the async transport into (writer half, line receiver channel).
pub fn split_legacy_async_stdio(
    transport: LegacyAsyncStdioProcessTransport,
) -> (LegacyAsyncTransportWriter, mpsc::Receiver<String>) {
    transport.into_parts()
}

impl Drop for LegacyAsyncStdioProcessTransport {
    fn drop(&mut self) {
        if let Some(ref mut inner) = self.inner {
            inner.reader_task.abort();
            let _ = inner.child.start_kill();
        }
    }
}

/// Writer half after splitting an explicit legacy async stdio transport.
/// Keeps the daemon child alive until dropped.
pub struct LegacyAsyncTransportWriter {
    child: tokio::process::Child,
    /// Stdin kept open so daemon doesn't get EOF until we drop.
    _writer: tokio::process::ChildStdin,
    reader_task: tokio::task::JoinHandle<()>,
    #[allow(dead_code)]
    auth: AuthContext,
}

impl LegacyAsyncTransportWriter {
    #[allow(dead_code)]
    pub fn auth_context(&self) -> &AuthContext {
        &self.auth
    }
}

impl Drop for LegacyAsyncTransportWriter {
    fn drop(&mut self) {
        self.reader_task.abort();
        let _ = self.child.start_kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn command_env(command: &Command, key: &str) -> Option<Option<String>> {
        command.get_envs().find_map(|(name, value)| {
            (name == key).then(|| value.map(|value| value.to_string_lossy().into_owned()))
        })
    }

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
    fn locate_daemon_returns_some_or_none_without_panic() {
        // Just ensure it doesn't panic; actual path depends on build state.
        let _ = locate_daemon();
    }

    #[test]
    fn sync_stdio_child_is_explicit_ephemeral_dev_and_drops_legacy_namespace_env() {
        let mut command = Command::new("agentdeckd");
        configure_sync_stdio_daemon(&mut command);

        assert_eq!(
            command_args(&command),
            [
                "--stdio-compat",
                "--ephemeral",
                "--no-remote",
                "--profile",
                "dev"
            ]
        );
        assert_eq!(command_env(&command, "AGENTDECK_DATA_DIR"), Some(None));
        assert_eq!(command_env(&command, "AGENTDECK_PROFILE"), Some(None));
    }

    #[test]
    fn async_stdio_child_uses_the_same_isolated_startup_contract() {
        let mut command = TokioCommand::new("agentdeckd");
        configure_async_stdio_daemon(&mut command);

        assert_eq!(
            command_args(command.as_std()),
            [
                "--stdio-compat",
                "--ephemeral",
                "--no-remote",
                "--profile",
                "dev"
            ]
        );
        assert_eq!(
            command_env(command.as_std(), "AGENTDECK_DATA_DIR"),
            Some(None)
        );
        assert_eq!(
            command_env(command.as_std(), "AGENTDECK_PROFILE"),
            Some(None)
        );
    }
}
