//! 桌面端的 typed local client：每次请求 spawn 一个 `agentdeckd` 子进程，
//! 通过它的 JSONL stdin/stdout 完成一次 admin round-trip 后回收进程。
//!
//! 历史查询在 daemon 内部本来就是短生命周期调用（Codex 每次另起 app-server，
//! Claude Code 每次扫描本地 JSONL），所以这里不维护长连接。一个连接只发一条
//! 命令，历史请求仍按 K11 生成唯一 requestId 并严格匹配回复。会话流式接入需要
//! 长连接时再单独引入。
//!
//! 所有函数都是阻塞的，调用方必须放到 GPUI 的 background executor 上。

use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use agentdeck_protocol::{
    AgentKind, ClientCommand, HistoryListItem, HistoryReply, HistoryRequest, HistoryResponse,
    HistoryTurn, HistoryWarning, ThreadId,
};

/// 与 CLI 一致的显式覆盖入口：一旦设置就必须指向绝对路径的可执行文件，不回退。
const DAEMON_BIN_ENV: &str = "AGENTDECK_DAEMON_BIN";

pub type Result<T> = std::result::Result<T, String>;

fn next_history_request_id() -> String {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    format!(
        "desktop-history-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    )
}

fn is_exec(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
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

/// 定位 daemon：显式覆盖优先，其次是 `.app` bundle 内与本可执行文件同目录的
/// `agentdeckd`，最后才是开发期的 workspace 构建产物。
fn locate_daemon() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os(DAEMON_BIN_ENV) {
        let path = PathBuf::from(value);
        if !path.is_absolute() || !is_exec(&path) {
            return Err(format!(
                "{DAEMON_BIN_ENV} 必须指向可执行的绝对路径：{}",
                path.display()
            ));
        }
        return Ok(path);
    }

    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("agentdeckd"));
        }
    }
    candidates.push(PathBuf::from("target/debug/agentdeckd"));
    candidates.push(PathBuf::from("target/release/agentdeckd"));

    candidates
        .into_iter()
        .find(|path| is_exec(path))
        .ok_or_else(|| "未找到 agentdeckd（构建：cargo build -p agentdeckd）".to_string())
}

/// 进程守卫：无论成功、失败还是提前返回都回收子进程。
struct DaemonChild(Child);

impl DaemonChild {
    fn finish(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self
                .0
                .try_wait()
                .map_err(|source| format!("等待 agentdeckd 退出失败：{source}"))?
            {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("agentdeckd 异常退出：{status}"))
                };
            }
            if Instant::now() >= deadline {
                let _ = self.0.kill();
                let _ = self.0.wait();
                return Err("agentdeckd 回复后未及时退出，已终止进程".to_string());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn daemon_command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // GCD workers block SIGCHLD. Inheriting that mask prevents Tokio in the
        // daemon from observing child exits; reset only in the forked child.
        unsafe {
            command.pre_exec(|| {
                let mut mask = std::mem::zeroed();
                if libc::sigemptyset(&mut mask) != 0
                    || libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    command
}

/// 从一行 daemon 输出里取出目标 admin reply。
///
/// `None` 表示这行不是目标 reply 或 requestId 不匹配，继续读下一行。
fn reply_payload(
    raw: &str,
    expected: &str,
    expected_request_id: Option<&str>,
) -> Option<Result<serde_json::Value>> {
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(source) => return Some(Err(format!("解析 agentdeckd 回复失败：{source}"))),
    };
    if value.get("reply")?.as_str()? != expected {
        return None;
    }
    if expected_request_id
        .is_some_and(|expected| value.get("requestId").and_then(|id| id.as_str()) != Some(expected))
    {
        return None;
    }
    if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
        let message = error
            .get("message")
            .and_then(|message| message.as_str())
            .unwrap_or("daemon 返回未知错误");
        let code = error.get("code").and_then(|code| code.as_str());
        return Some(Err(match code {
            Some(code) => format!("{message}（{code}）"),
            None => message.to_string(),
        }));
    }
    Some(Ok(value))
}

/// 发一条命令并等待对应的 admin reply。
///
/// ponytail: 依赖 daemon 有界的版本探测和历史查询；若需处理整个 daemon 无响应，
/// 再增加客户端 deadline，当前阻塞读取仍会占用一个 background 线程。
fn round_trip(command: &ClientCommand, expected_reply: &str) -> Result<serde_json::Value> {
    let path = locate_daemon()?;
    retry_transport(|| round_trip_once(&path, command, expected_reply))
}

fn retry_transport(
    mut read: impl FnMut() -> io::Result<Result<serde_json::Value>>,
) -> Result<serde_json::Value> {
    let result = match read() {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
            ) =>
        {
            std::thread::sleep(Duration::from_secs(1));
            read()
        }
        result => result,
    };
    result.map_err(|error| error.to_string())?
}

// 外层保留可重试的传输错误；内层的 daemon 回复和解析错误必须直接交给用户。
fn round_trip_once(
    path: &Path,
    command: &ClientCommand,
    expected_reply: &str,
) -> io::Result<Result<serde_json::Value>> {
    let command = match command {
        ClientCommand::History(request) => {
            ClientCommand::History(request.clone().with_request_id(next_history_request_id()))
        }
        command => command.clone(),
    };
    let expected_request_id = match &command {
        ClientCommand::History(request) => request.request_id(),
        _ => None,
    };
    let line = match serde_json::to_string(&command) {
        Ok(line) => line,
        Err(source) => return Ok(Err(format!("序列化命令失败：{source}"))),
    };
    let child = daemon_command(path).spawn().map_err(|source| {
        io::Error::new(source.kind(), format!("启动 agentdeckd 失败：{source}"))
    })?;
    let mut child = DaemonChild(child);

    {
        // 写完即关闭 stdin：daemon 在回完这条 reply 后自行退出。
        let mut stdin = child
            .0
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("agentdeckd stdin 不可用"))?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|source| {
                io::Error::new(source.kind(), format!("写入 agentdeckd 失败：{source}"))
            })?;
    }

    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("agentdeckd stdout 不可用"))?;
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|source| {
            io::Error::new(source.kind(), format!("读取 agentdeckd 失败：{source}"))
        })?;
        if let Some(payload) = reply_payload(&line, expected_reply, expected_request_id) {
            // 回复 flush 后 daemon 还要排空 writer 并记录 daemon_stop。
            let finished = child.finish(Duration::from_secs(2));
            return Ok(payload.and_then(|value| finished.map(|()| value)));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("agentdeckd 在返回 {expected_reply} 前退出"),
    ))
}

/// daemon 当前注册的 agent；侧栏据此逐个查询历史，不硬编码 vendor。
pub fn agent_list() -> Result<Vec<AgentKind>> {
    let mut reply = round_trip(&ClientCommand::AgentList, "agentList")?;
    let agents = reply["agents"].take();
    serde_json::from_value(agents).map_err(|source| format!("解析 agent 列表失败：{source}"))
}

fn decode_history(reply: serde_json::Value) -> Result<HistoryReply> {
    serde_json::from_value(reply).map_err(|source| format!("解析历史响应失败：{source}"))
}

fn history(request: HistoryRequest) -> Result<HistoryReply> {
    decode_history(round_trip(&ClientCommand::History(request), "history")?)
}

pub fn history_list(
    agent_kind: AgentKind,
    limit: usize,
) -> Result<(Vec<HistoryListItem>, Vec<HistoryWarning>)> {
    let reply = history(HistoryRequest::List {
        request_id: None,
        agent_kind: Some(agent_kind),
        cwd_filter: None,
        limit: Some(limit),
    })?;
    match reply.response {
        HistoryResponse::List(items) => Ok((items, reply.warnings)),
        other => Err(format!("历史列表返回了意外的响应：{other:?}")),
    }
}

pub fn history_read(
    agent_kind: AgentKind,
    thread_id: ThreadId,
) -> Result<(Vec<HistoryTurn>, Vec<HistoryWarning>)> {
    let reply = history(HistoryRequest::Read {
        request_id: None,
        thread_id,
        agent_kind,
    })?;
    match reply.response {
        HistoryResponse::Read(response) => Ok((response.turns, reply.warnings)),
        other => Err(format!("历史读取返回了意外的响应：{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{next_history_request_id, reply_payload};

    #[test]
    fn transport_retry_recovers_once_and_stops_after_two_attempts() {
        for failures in 0..=2 {
            let mut calls = 0;
            let result = super::retry_transport(|| {
                calls += 1;
                if calls <= failures {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "daemon 提前退出",
                    ))
                } else {
                    Ok(Ok(
                        serde_json::json!({ "reply": "agentList", "agents": [] }),
                    ))
                }
            });
            assert_eq!(calls, (failures + 1).min(2));
            assert_eq!(result.is_ok(), failures < 2);
        }
    }

    #[test]
    fn daemon_errors_and_invalid_responses_are_not_retried() {
        for code in [
            "history-request-timeout",
            "codex-history-timeout",
            "codex-version-timeout",
            "codex-version-unsupported",
            "codex-history-decode-failed",
        ] {
            let raw = serde_json::json!({
                "reply": "history",
                "requestId": "current",
                "error": { "code": code, "message": "读取失败" }
            })
            .to_string();
            let mut calls = 0;
            let result = super::retry_transport(|| {
                calls += 1;
                Ok(reply_payload(&raw, "history", Some("current")).unwrap())
            });
            assert_eq!(calls, 1);
            assert_eq!(result.unwrap_err(), format!("读取失败（{code}）"));
        }

        let mut calls = 0;
        let result = super::retry_transport(|| {
            calls += 1;
            Ok(reply_payload("{", "history", Some("current")).unwrap())
        });
        assert_eq!(calls, 1);
        assert!(result.unwrap_err().contains("解析 agentdeckd 回复失败"));

        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::TimedOut,
        ] {
            let mut calls = 0;
            let result = super::retry_transport(|| {
                calls += 1;
                Err(std::io::Error::new(kind, "不可重试"))
            });
            assert_eq!(calls, 1);
            assert_eq!(result.unwrap_err(), "不可重试");
        }
    }

    #[cfg(unix)]
    #[test]
    fn daemon_does_not_inherit_blocked_child_exit_signals() {
        use std::os::unix::process::ExitStatusExt;
        const CHILD: &str = "AGENTDECK_TEST_CHILD_SIGNAL_MASK";
        if std::env::var_os(CHILD).is_some() {
            let mut mask = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) },
                0
            );
            assert_eq!(unsafe { libc::sigismember(&mask, libc::SIGCHLD) }, 0);
            return;
        }
        let mut mask = unsafe { std::mem::zeroed() };
        let mut saved = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGCHLD);
            assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut saved), 0);
        }
        let child = super::daemon_command(&std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daemon::tests::daemon_does_not_inherit_blocked_child_exit_signals",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stderr(std::process::Stdio::piped())
            .spawn();
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &saved, std::ptr::null_mut()) },
            0
        );
        let output = child.unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "child status {:?}: {}{}",
            output.status.signal(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn daemon_finish_waits_for_exit_and_reaps_on_timeout() {
        use super::DaemonChild;
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;
        use std::time::Duration;

        for (script, expected_code) in [("sleep 0.05; exit 0", 0), ("exit 7", 7)] {
            let mut child = DaemonChild(
                Command::new("/bin/sh")
                    .args(["-c", script])
                    .spawn()
                    .unwrap(),
            );
            let result = child.finish(Duration::from_secs(2));
            assert_eq!(result.is_ok(), expected_code == 0);
            assert_eq!(
                child.0.try_wait().unwrap().unwrap().code(),
                Some(expected_code)
            );
        }

        let mut child = DaemonChild(
            Command::new("/bin/sh")
                .args(["-c", "exec /bin/sleep 10"])
                .spawn()
                .unwrap(),
        );
        assert!(child.finish(Duration::from_millis(50)).is_err());
        assert_eq!(child.0.try_wait().unwrap().unwrap().signal(), Some(9));
    }

    #[test]
    fn history_request_ids_are_unique() {
        let first = next_history_request_id();
        let second = next_history_request_id();
        assert_ne!(first, second);
        assert!(first.starts_with(&format!("desktop-history-{}-", std::process::id())));
    }

    #[test]
    fn reply_payload_only_accepts_the_expected_reply() {
        let event = r#"{"type":"turnStarted","sessionId":"s","turnId":"t"}"#;
        assert!(reply_payload(event, "history", Some("current")).is_none());

        let other_reply = r#"{"reply":"ping","ok":true}"#;
        assert!(reply_payload(other_reply, "history", Some("current")).is_none());

        let agent_list = r#"{"reply":"agentList","agents":["codex"]}"#;
        assert!(
            reply_payload(agent_list, "agentList", None)
                .unwrap()
                .is_ok()
        );

        let matching =
            r#"{"reply":"history","requestId":"current","response":{"kind":"list","value":[]}}"#;
        let payload = reply_payload(matching, "history", Some("current")).expect("matching reply");
        assert_eq!(payload.expect("ok reply")["response"]["kind"], "list");
    }

    #[test]
    fn history_success_keeps_warnings_and_accepts_extra_envelope_fields() {
        let warning = serde_json::json!({
            "agentKind": "codex",
            "code": "codex-version-unverified",
            "message": "版本未经验证\n路径：/Applications/Codex.app/Contents/Resources/codex\n实际：codex-cli 0.154.0\n已验证：codex-cli 0.155.0-alpha.9.2",
        });
        let mut reply = serde_json::json!({
            "reply": "history",
            "requestId": "current",
            "durationMs": 12,
            "response": { "kind": "list", "value": [] },
            "warnings": [warning.clone()],
        });
        let payload = reply_payload(&reply.to_string(), "history", Some("current"))
            .unwrap()
            .unwrap();
        let decoded = super::decode_history(payload).unwrap();
        assert!(matches!(
            decoded.response,
            agentdeck_protocol::HistoryResponse::List(_)
        ));
        assert_eq!(decoded.warnings.len(), 1);
        assert_eq!(decoded.warnings[0].message, warning["message"]);

        reply.as_object_mut().unwrap().remove("warnings");
        assert!(super::decode_history(reply).unwrap().warnings.is_empty());
    }

    #[test]
    fn history_replies_without_the_expected_request_id_are_ignored() {
        for raw in [
            r#"{"reply":"history","response":{"kind":"list","value":[]}}"#,
            r#"{"reply":"history","requestId":"old","response":{"kind":"list","value":[]}}"#,
            r#"{"reply":"history","error":{"code":"history-timeout","message":"超时"}}"#,
            r#"{"reply":"history","requestId":"old","error":{"code":"history-timeout","message":"超时"}}"#,
        ] {
            assert!(reply_payload(raw, "history", Some("current")).is_none());
        }
    }

    #[test]
    fn reply_payload_surfaces_daemon_errors_with_their_code() {
        let message = "Codex 版本尚未验证\n路径：/Applications/ChatGPT.app/Contents/Resources/codex\n实际：codex-cli 0.154.0\n支持：codex-cli 0.155.0-alpha.16\n请检查 AgentDeck 更新，或指定受支持的 Codex 路径后重试";
        let failed = serde_json::json!({
            "reply": "history",
            "requestId": "current",
            "error": { "code": "codex-version-unsupported", "message": message },
            "warnings": [{
                "agentKind": "codex", "code": "codex-version-unverified", "message": "warning"
            }],
        })
        .to_string();
        let payload = reply_payload(&failed, "history", Some("current")).expect("matching reply");
        assert_eq!(
            payload.expect_err("error reply"),
            format!("{message}（codex-version-unsupported）")
        );
    }
}
