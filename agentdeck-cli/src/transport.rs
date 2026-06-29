use agentdeck_protocol::IpcMessage;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[cfg(test)]
use std::collections::VecDeque;

/// 阻塞式单连接传输缝。`recv` 返回 `Ok(None)` 表示 daemon EOF/断连。
pub trait Transport {
    fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()>;
    fn recv(&mut self) -> std::io::Result<Option<IpcMessage>>;
}

/// 内存测试传输：记录发出的帧，按脚本顺序回放收到的帧。
#[cfg(test)]
pub struct FakeTransport {
    pub sent: Vec<IpcMessage>,
    incoming: VecDeque<IpcMessage>,
}

#[cfg(test)]
impl FakeTransport {
    pub fn new(incoming: Vec<IpcMessage>) -> Self {
        Self { sent: Vec::new(), incoming: incoming.into() }
    }
}

#[cfg(test)]
impl Transport for FakeTransport {
    fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()> {
        self.sent.push(msg.clone());
        Ok(())
    }
    fn recv(&mut self) -> std::io::Result<Option<IpcMessage>> {
        Ok(self.incoming.pop_front())
    }
}

fn is_exec(p: &std::path::Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// 定位 agentdeckd：优先当前可执行文件同目录（同一 target dir），再回退
/// cwd 相对 dev 路径与常见安装位置（与 Swift DaemonClient.locateDaemon 同策略）。
pub fn locate_daemon() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sib = dir.join("agentdeckd");
            if is_exec(&sib) {
                return Some(sib);
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
            return Some(p);
        }
    }
    None
}

/// 真实传输：spawn agentdeckd，走其 stdin/stdout JSONL。
/// A1：Drop 时杀子进程，daemon 自身 Drop 级联杀 codex 进程组。
pub struct ProcessTransport {
    child: Child,
    reader: BufReader<ChildStdout>,
    stdin: ChildStdin,
}

impl ProcessTransport {
    pub fn spawn(profile: &str, data_dir: Option<&str>) -> std::io::Result<Self> {
        let path = locate_daemon().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "agentdeckd not found (build it: cargo build -p agentdeckd)",
            )
        })?;
        let mut cmd = Command::new(path);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        cmd.env("AGENTDECK_PROFILE", profile);
        if let Some(d) = data_dir {
            cmd.env("AGENTDECK_DATA_DIR", d);
        }
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Self { child, reader: BufReader::new(stdout), stdin })
    }
}

impl Transport for ProcessTransport {
    fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()> {
        let mut s = serde_json::to_string(msg).map_err(std::io::Error::other)?;
        s.push('\n');
        self.stdin.write_all(s.as_bytes())?;
        self.stdin.flush()
    }
    fn recv(&mut self) -> std::io::Result<Option<IpcMessage>> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                return Ok(None);
            }
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            match serde_json::from_str::<IpcMessage>(t) {
                Ok(m) => return Ok(Some(m)),
                Err(_) => continue,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_records_sent_and_replays_incoming() {
        let mut t = FakeTransport::new(vec![IpcMessage {
            kind: "pong".into(), id: Some(7), session_id: None, thread_id: None, payload: None,
        }]);
        t.send(&IpcMessage { kind: "ping".into(), id: Some(7), session_id: None, thread_id: None, payload: None }).unwrap();
        assert_eq!(t.sent.len(), 1);
        assert_eq!(t.sent[0].kind, "ping");
        assert_eq!(t.recv().unwrap().unwrap().kind, "pong");
        assert!(t.recv().unwrap().is_none());
    }
}
