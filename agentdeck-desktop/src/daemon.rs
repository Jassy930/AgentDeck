//! 桌面端的 typed local client：每次请求 spawn 一个 `agentdeckd` 子进程，
//! 通过它的 JSONL stdin/stdout 完成一次 admin round-trip 后回收进程。
//!
//! 历史查询在 daemon 内部本来就是短生命周期调用（Codex 每次另起 app-server，
//! Claude Code 每次扫描本地 JSONL），所以这里不维护长连接，也不需要 requestId
//! 关联：一个连接只发一条命令。会话流式接入需要长连接时再单独引入。
//!
//! 所有函数都是阻塞的，调用方必须放到 GPUI 的 background executor 上。

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use agentdeck_protocol::{
    AgentKind, ClientCommand, HistoryListItem, HistoryRequest, HistoryResponse, HistoryTurn,
    ThreadId,
};

/// 与 CLI 一致的显式覆盖入口：一旦设置就必须指向绝对路径的可执行文件，不回退。
const DAEMON_BIN_ENV: &str = "AGENTDECK_DAEMON_BIN";

pub type Result<T> = std::result::Result<T, String>;

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

impl Drop for DaemonChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 从一行 daemon 输出里取出目标 admin reply。
///
/// `None` 表示这行不是目标 reply（事件行或其他命令的回复），继续读下一行。
fn reply_payload(raw: &str, expected: &str) -> Option<Result<serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    if value.get("reply")?.as_str()? != expected {
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
/// ponytail: 没有客户端侧超时，依赖 daemon 自己的 history 硬超时；daemon 若完全
/// 卡死，这里会一直占着一个 background 线程，等真出现再加客户端 deadline。
fn round_trip(command: &ClientCommand, expected_reply: &str) -> Result<serde_json::Value> {
    let path = locate_daemon()?;
    let child = Command::new(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|source| format!("启动 agentdeckd 失败：{source}"))?;
    let mut child = DaemonChild(child);

    let line =
        serde_json::to_string(command).map_err(|source| format!("序列化命令失败：{source}"))?;
    {
        // 写完即关闭 stdin：daemon 在回完这条 reply 后自行退出。
        let mut stdin = child.0.stdin.take().ok_or("agentdeckd stdin 不可用")?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|source| format!("写入 agentdeckd 失败：{source}"))?;
    }

    let stdout = child.0.stdout.take().ok_or("agentdeckd stdout 不可用")?;
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|source| format!("读取 agentdeckd 失败：{source}"))?;
        if let Some(payload) = reply_payload(&line, expected_reply) {
            return payload;
        }
    }
    Err(format!("agentdeckd 在返回 {expected_reply} 前退出"))
}

/// daemon 当前注册的 agent；侧栏据此逐个查询历史，不硬编码 vendor。
pub fn agent_list() -> Result<Vec<AgentKind>> {
    let reply = round_trip(&ClientCommand::AgentList, "agentList")?;
    let agents = reply.get("agents").cloned().unwrap_or_default();
    serde_json::from_value(agents).map_err(|source| format!("解析 agent 列表失败：{source}"))
}

fn history(request: HistoryRequest) -> Result<HistoryResponse> {
    let reply = round_trip(&ClientCommand::History(request), "history")?;
    let response = reply.get("response").cloned().unwrap_or_default();
    serde_json::from_value(response).map_err(|source| format!("解析历史响应失败：{source}"))
}

pub fn history_list(agent_kind: AgentKind, limit: usize) -> Result<Vec<HistoryListItem>> {
    match history(HistoryRequest::List {
        request_id: None,
        agent_kind: Some(agent_kind),
        cwd_filter: None,
        limit: Some(limit),
    })? {
        HistoryResponse::List(items) => Ok(items),
        other => Err(format!("历史列表返回了意外的响应：{other:?}")),
    }
}

pub fn history_read(agent_kind: AgentKind, thread_id: ThreadId) -> Result<Vec<HistoryTurn>> {
    match history(HistoryRequest::Read {
        request_id: None,
        thread_id,
        agent_kind,
    })? {
        HistoryResponse::Read(response) => Ok(response.turns),
        other => Err(format!("历史读取返回了意外的响应：{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::reply_payload;

    #[test]
    fn reply_payload_only_accepts_the_expected_reply() {
        let event = r#"{"type":"turnStarted","sessionId":"s","turnId":"t"}"#;
        assert!(reply_payload(event, "history").is_none());

        let other_reply = r#"{"reply":"ping","ok":true}"#;
        assert!(reply_payload(other_reply, "history").is_none());

        let matching = r#"{"reply":"history","response":{"kind":"list","value":[]}}"#;
        let payload = reply_payload(matching, "history").expect("matching reply");
        assert_eq!(payload.expect("ok reply")["response"]["kind"], "list");
    }

    #[test]
    fn reply_payload_surfaces_daemon_errors_with_their_code() {
        let failed =
            r#"{"reply":"history","error":{"code":"codex-history-timeout","message":"超时"}}"#;
        let payload = reply_payload(failed, "history").expect("matching reply");
        assert_eq!(
            payload.expect_err("error reply"),
            "超时（codex-history-timeout）"
        );
    }
}
