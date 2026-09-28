//! 桌面端的 typed local client：每台机器维持一个常驻 `agentdeckd` 子进程，
//! 所有请求复用它的 JSONL stdin/stdout。历史请求按 K11 生成唯一 requestId，
//! daemon 并发处理、乱序返回，读线程按 requestId 分发；进程退出后下次请求重连。
//!
//! 每个请求都带目标机器：`None` 是本机，`Some(host)` 经 `ssh <host>` 在远端
//! login shell 里启动 `agentdeckd`，stdio 协议不变，鉴权与加密交给 SSH 密钥。
//!
//! 所有函数都是阻塞的，调用方必须放到 GPUI 的 background executor 上。

use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, mpsc};
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

/// 远端走 login shell：非交互 ssh 的 PATH 通常不含 `codex` / `claude` / `agentdeckd`。
/// ControlMaster 让断线重连免去完整握手；ServerAlive 让对端休眠/断网时 ssh
/// 约 45 秒内退出，读线程据此让等待者失败，而不是永远挂起。
fn remote_args(host: &str) -> Vec<String> {
    [
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ControlMaster=auto",
        "-o",
        "ControlPath=~/.ssh/agentdeck-%C",
        "-o",
        "ControlPersist=60",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "--",
        host,
        "bash -lc 'exec agentdeckd'",
    ]
    .map(String::from)
    .to_vec()
}

/// 界面输入的主机名是信任边界：只接受 ssh 目标形态，拒绝空白和以 `-` 开头的值。
pub fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() || host.starts_with('-') || host.chars().any(char::is_whitespace) {
        return Err(format!("无效的主机名：{host:?}"));
    }
    Ok(())
}

fn build_command(host: Option<&str>) -> Result<Command> {
    match host {
        Some(host) => {
            validate_host(host)?;
            let mut command = daemon_command("ssh");
            command.args(remote_args(host));
            Ok(command)
        }
        None => Ok(daemon_command(locate_daemon()?)),
    }
}

fn daemon_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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

/// 回复对应的等待者：history 按 requestId（daemon 并发处理、可能乱序返回）；
/// 其余 admin reply 由 daemon 在输入循环里就地处理，按 reply 名先进先出。
fn reply_key(value: &serde_json::Value) -> Option<String> {
    match value.get("reply")?.as_str()? {
        "history" => Some(format!("history:{}", value.get("requestId")?.as_str()?)),
        reply => Some(reply.to_string()),
    }
}

/// daemon 回复里的 `error` 直接交给用户，不重试。
fn reply_result(value: serde_json::Value) -> Result<serde_json::Value> {
    if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
        let message = error
            .get("message")
            .and_then(|message| message.as_str())
            .unwrap_or("daemon 返回未知错误");
        let code = error.get("code").and_then(|code| code.as_str());
        return Err(match code {
            Some(code) => format!("{message}（{code}）"),
            None => message.to_string(),
        });
    }
    Ok(value)
}

/// 客户端兜底：daemon 自己的历史超时是 32 秒，超过这里说明管道已不通。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(40);

type Reply = io::Result<Result<serde_json::Value>>;
type Pending = Mutex<HashMap<String, VecDeque<mpsc::Sender<Reply>>>>;

/// 一台机器一条常驻连接：一个 `agentdeckd`（远端即一条 ssh 会话）服务该机器的
/// 全部请求。读线程只持有 stdout 与等待表，不持有 `Connection`，丢弃连接即回收进程。
struct Connection {
    stdin: Mutex<ChildStdin>,
    pending: Arc<Pending>,
    alive: Arc<AtomicBool>,
    child: Option<DaemonChild>,
}

static POOL: LazyLock<Mutex<HashMap<Option<String>, Arc<Connection>>>> =
    LazyLock::new(Default::default);

impl Connection {
    fn spawn(mut command: Command) -> io::Result<Arc<Self>> {
        let child = command.spawn().map_err(|source| {
            io::Error::new(source.kind(), format!("启动 agentdeckd 失败：{source}"))
        })?;
        let mut child = DaemonChild(child);
        let stderr = drain_stderr(&mut child.0);
        let stdin = child
            .0
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("agentdeckd stdin 不可用"))?;
        let stdout = child
            .0
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("agentdeckd stdout 不可用"))?;
        let pending = Arc::<Pending>::default();
        let alive = Arc::new(AtomicBool::new(true));
        {
            let (pending, alive) = (Arc::clone(&pending), Arc::clone(&alive));
            std::thread::spawn(move || read_replies(stdout, stderr, &pending, &alive));
        }
        Ok(Arc::new(Self {
            stdin: Mutex::new(stdin),
            pending,
            alive,
            child: Some(child),
        }))
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn request(&self, command: &ClientCommand, expected_reply: &str) -> Reply {
        let (command, key) = match command {
            ClientCommand::History(request) => {
                let id = next_history_request_id();
                let key = format!("history:{id}");
                (
                    ClientCommand::History(request.clone().with_request_id(id)),
                    key,
                )
            }
            command => (command.clone(), expected_reply.to_string()),
        };
        let mut line = match serde_json::to_string(&command) {
            Ok(line) => line,
            Err(source) => return Ok(Err(format!("序列化命令失败：{source}"))),
        };
        line.push('\n');

        // 先登记再写入，回复不会早于等待者；登记与读线程判活在同一把锁下。
        let (tx, rx) = mpsc::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            if !self.is_alive() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "agentdeckd 连接已断开",
                ));
            }
            pending.entry(key).or_default().push_back(tx);
        }
        if let Err(source) = self.stdin.lock().unwrap().write_all(line.as_bytes()) {
            self.alive.store(false, Ordering::Release);
            return Err(io::Error::new(
                source.kind(),
                format!("写入 agentdeckd 失败：{source}"),
            ));
        }
        match rx.recv_timeout(REQUEST_TIMEOUT) {
            Ok(reply) => reply,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.alive.store(false, Ordering::Release);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "agentdeckd {}s 内未返回 {expected_reply}，已断开连接",
                        REQUEST_TIMEOUT.as_secs()
                    ),
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "agentdeckd 连接已断开",
            )),
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // 字段 stdin 在本函数返回后才关闭，daemon 随即读到 EOF 正常退出；
        // 回收放到后台线程，断开远端时不阻塞 UI。
        if let Some(mut child) = self.child.take() {
            std::thread::spawn(move || {
                let _ = child.finish(Duration::from_secs(2));
            });
        }
    }
}

/// 读线程：把每条回复交给对应等待者；连接结束时让所有等待者带着原因失败。
fn read_replies(
    stdout: ChildStdout,
    stderr: mpsc::Receiver<String>,
    pending: &Pending,
    alive: &AtomicBool,
) {
    let mut lines = BufReader::new(stdout).lines();
    let failure = loop {
        let line = match lines.next() {
            Some(Ok(line)) => line,
            Some(Err(source)) => {
                break io::Error::new(source.kind(), format!("读取 agentdeckd 失败：{source}"));
            }
            None => {
                // ssh 认证/连接失败只在 stderr 里说明原因，带进错误信息方便排查。
                let detail = stderr
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap_or_default();
                let detail = detail.trim();
                break io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    if detail.is_empty() {
                        "agentdeckd 已退出".to_string()
                    } else {
                        format!("agentdeckd 已退出：{detail}")
                    },
                );
            }
        };
        // 非 JSON 行与无人等待的事件（如未来的 ServerEvent）直接跳过。
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let Some(key) = reply_key(&value) else {
            continue;
        };
        let waiter = pending
            .lock()
            .unwrap()
            .get_mut(&key)
            .and_then(VecDeque::pop_front);
        if let Some(waiter) = waiter {
            let _ = waiter.send(Ok(reply_result(value)));
        }
    };
    let mut pending = pending.lock().unwrap();
    alive.store(false, Ordering::Release);
    for waiter in pending.drain().flat_map(|(_, waiters)| waiters) {
        let _ = waiter.send(Err(io::Error::new(failure.kind(), failure.to_string())));
    }
}

/// 取该机器的常驻连接；不存在或已断开时重新建立。
fn connection(host: Option<&str>) -> io::Result<Arc<Connection>> {
    let mut pool = POOL.lock().unwrap();
    let key = host.map(str::to_string);
    if let Some(connection) = pool.get(&key).filter(|connection| connection.is_alive()) {
        return Ok(Arc::clone(connection));
    }
    let command = build_command(host)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    let connection = Connection::spawn(command)?;
    pool.insert(key, Arc::clone(&connection));
    Ok(connection)
}

/// 断开某台机器：进程在后台退出，之后的请求会重新连接。
pub fn disconnect(host: Option<&str>) {
    let connection = POOL.lock().unwrap().remove(&host.map(str::to_string));
    drop(connection);
}

/// 发一条命令并等待对应的 admin reply；连接断了（如远端休眠后 ssh 退出）重连一次。
fn round_trip(
    host: Option<&str>,
    command: &ClientCommand,
    expected_reply: &str,
) -> Result<serde_json::Value> {
    retry_transport(|| connection(host)?.request(command, expected_reply))
}

fn retry_transport(mut read: impl FnMut() -> Reply) -> Result<serde_json::Value> {
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

/// 后台排空 stderr，避免子进程写满管道阻塞；只保留尾部用于错误信息。
fn drain_stderr(child: &mut Child) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf);
            let text = String::from_utf8_lossy(&buf);
            let tail: String = text.chars().rev().take(2000).collect();
            let _ = tx.send(tail.chars().rev().collect());
        });
    }
    rx
}

/// daemon 当前注册的 agent；侧栏据此逐个查询历史，不硬编码 vendor。
pub fn agent_list(host: Option<&str>) -> Result<Vec<AgentKind>> {
    let mut reply = round_trip(host, &ClientCommand::AgentList, "agentList")?;
    let agents = reply["agents"].take();
    serde_json::from_value(agents).map_err(|source| format!("解析 agent 列表失败：{source}"))
}

fn decode_history(reply: serde_json::Value) -> Result<HistoryReply> {
    serde_json::from_value(reply).map_err(|source| format!("解析历史响应失败：{source}"))
}

fn history(host: Option<&str>, request: HistoryRequest) -> Result<HistoryReply> {
    decode_history(round_trip(
        host,
        &ClientCommand::History(request),
        "history",
    )?)
}

pub fn history_list(
    host: Option<&str>,
    agent_kind: AgentKind,
    limit: usize,
) -> Result<(Vec<HistoryListItem>, Vec<HistoryWarning>)> {
    let reply = history(
        host,
        HistoryRequest::List {
            request_id: None,
            agent_kind: Some(agent_kind),
            cwd_filter: None,
            limit: Some(limit),
        },
    )?;
    match reply.response {
        HistoryResponse::List(items) => Ok((items, reply.warnings)),
        other => Err(format!("历史列表返回了意外的响应：{other:?}")),
    }
}

pub fn history_read(
    host: Option<&str>,
    agent_kind: AgentKind,
    thread_id: ThreadId,
) -> Result<(Vec<HistoryTurn>, Vec<HistoryWarning>)> {
    let reply = history(
        host,
        HistoryRequest::Read {
            request_id: None,
            thread_id,
            agent_kind,
        },
    )?;
    match reply.response {
        HistoryResponse::Read(response) => Ok((response.turns, reply.warnings)),
        other => Err(format!("历史读取返回了意外的响应：{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{next_history_request_id, reply_result};

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
            });
            let mut calls = 0;
            let result = super::retry_transport(|| {
                calls += 1;
                Ok(reply_result(raw.clone()))
            });
            assert_eq!(calls, 1);
            assert_eq!(result.unwrap_err(), format!("读取失败（{code}）"));
        }

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
        let child = super::daemon_command(std::env::current_exe().unwrap())
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
    fn remote_runs_daemon_in_login_shell_without_prompting() {
        let args = super::remote_args("dt");
        assert_eq!(args[0], "-T");
        assert!(args.contains(&"BatchMode=yes".to_string()));
        assert_eq!(args[args.len() - 2..], ["dt", "bash -lc 'exec agentdeckd'"]);
    }

    #[test]
    fn hosts_that_could_be_parsed_as_options_are_rejected() {
        for bad in ["", "-oProxyCommand=x", "dt extra", "a\tb"] {
            assert!(super::validate_host(bad).is_err(), "{bad:?}");
        }
        for good in ["dt", "jassy@192.168.1.20", "dt.local"] {
            assert!(super::validate_host(good).is_ok(), "{good:?}");
        }
    }

    fn fake_daemon(script: &str) -> std::sync::Arc<super::Connection> {
        let mut command = super::daemon_command("/bin/sh");
        command.args(["-c", script]);
        super::Connection::spawn(command).unwrap()
    }

    fn list_request() -> agentdeck_protocol::ClientCommand {
        agentdeck_protocol::ClientCommand::History(agentdeck_protocol::HistoryRequest::List {
            request_id: None,
            agent_kind: None,
            cwd_filter: None,
            limit: None,
        })
    }

    #[cfg(unix)]
    #[test]
    fn early_exit_surfaces_stderr_in_the_error() {
        let connection = fake_daemon("read l; echo 'Permission denied (publickey)' >&2; exit 255");
        let error = connection
            .request(&agentdeck_protocol::ClientCommand::AgentList, "agentList")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(error.to_string().contains("Permission denied (publickey)"));
        assert!(!connection.is_alive());
        let error = connection.request(&list_request(), "history").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
    }

    /// 一条连接上的并发请求各自拿到自己 requestId 的回复，即使 daemon 乱序返回。
    #[cfg(unix)]
    #[test]
    fn concurrent_requests_share_one_connection() {
        // 读两条后倒序回复，再按行回显 agentList。
        let connection = fake_daemon(
            r#"id() { printf %s "$1" | sed -n 's/.*"requestId":"\([^"]*\)".*/\1/p'; }
            read -r a; read -r b
            for l in "$b" "$a"; do printf '{"reply":"history","requestId":"%s"}\n' "$(id "$l")"; done
            while read -r l; do echo '{"reply":"agentList","agents":[]}'; done"#,
        );
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let connection = std::sync::Arc::clone(&connection);
                std::thread::spawn(move || {
                    connection
                        .request(&list_request(), "history")
                        .unwrap()
                        .unwrap()
                })
            })
            .collect();
        let ids: Vec<String> = handles
            .into_iter()
            .map(|handle| {
                handle.join().unwrap()["requestId"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_ne!(ids[0], ids[1]);
        for _ in 0..2 {
            let reply = connection
                .request(&agentdeck_protocol::ClientCommand::AgentList, "agentList")
                .unwrap()
                .unwrap();
            assert_eq!(reply["reply"], "agentList");
        }
        assert!(connection.is_alive());
    }

    #[test]
    fn history_request_ids_are_unique() {
        let first = next_history_request_id();
        let second = next_history_request_id();
        assert_ne!(first, second);
        assert!(first.starts_with(&format!("desktop-history-{}-", std::process::id())));
    }

    /// 读线程按 key 分发：history 按 requestId，其余按 reply 名；事件和缺 requestId 的
    /// history 回复不会被任何等待者认领。
    #[test]
    fn replies_are_routed_by_request_id_or_reply_name() {
        let key = |raw: &str| super::reply_key(&serde_json::from_str(raw).unwrap());
        assert_eq!(
            key(r#"{"type":"turnStarted","sessionId":"s","turnId":"t"}"#),
            None
        );
        assert_eq!(
            key(r#"{"reply":"agentList","agents":["codex"]}"#).as_deref(),
            Some("agentList")
        );
        assert_eq!(
            key(
                r#"{"reply":"history","requestId":"current","response":{"kind":"list","value":[]}}"#
            )
            .as_deref(),
            Some("history:current")
        );
        assert_eq!(
            key(r#"{"reply":"history","error":{"code":"history-timeout","message":"超时"}}"#),
            None
        );
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
        let payload = reply_result(reply.clone()).unwrap();
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
    fn reply_result_surfaces_daemon_errors_with_their_code() {
        let message = "Codex 版本尚未验证\n路径：/Applications/ChatGPT.app/Contents/Resources/codex\n实际：codex-cli 0.154.0\n支持：codex-cli 0.155.0-alpha.16\n请检查 AgentDeck 更新，或指定受支持的 Codex 路径后重试";
        let failed = serde_json::json!({
            "reply": "history",
            "requestId": "current",
            "error": { "code": "codex-version-unsupported", "message": message },
            "warnings": [{
                "agentKind": "codex", "code": "codex-version-unverified", "message": "warning"
            }],
        });
        assert_eq!(
            reply_result(failed).expect_err("error reply"),
            format!("{message}（codex-version-unsupported）")
        );
    }
}
