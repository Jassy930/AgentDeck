// agentdeck-relay/src/bridge.rs
use std::collections::VecDeque;
use std::path::Path;
use std::process::Stdio;

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, DataEnvelope, MachineDescriptor, RelayControlMsg,
};
use agentdeck_protocol::ClientCommand;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

use crate::relay_link::RelayLink;

/// 把一个真实 agentdeckd 子进程当作 relay 的 machine 接入（不改 daemon）。
/// R0 主要证明 admin（Machine 目标）往返；ServerEvent 为 best-effort 转发，
/// 真实会话身份映射留到 R2。
pub struct StdioMachineBridge {
    child: Child,
    pump: JoinHandle<()>,
}

impl StdioMachineBridge {
    pub async fn spawn(
        daemon_path: &Path,
        profile: &str,
        machine: MachineDescriptor,
        link: impl RelayLink,
    ) -> std::io::Result<StdioMachineBridge> {
        let machine_id = machine.machine_id.clone();
        let mut child = Command::new(daemon_path)
            .env("AGENTDECK_PROFILE", profile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().expect("daemon stdin");
        let stdout = child.stdout.take().expect("daemon stdout");

        link.send(mk_frame(&machine_id, RelayControlMsg::RegisterMachine { machine }))
            .await;

        let pump = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            let mut link = link;
            // admin single-flight：请求 request_id FIFO 队列 + 待写命令行
            let mut admin_queue: VecDeque<(String, String)> = VecDeque::new();
            let mut admin_inflight = false;

            loop {
                tokio::select! {
                    // 来自 relay 的 device 命令
                    frame = link.recv() => {
                        let Some(frame) = frame else { break };
                        if let RelayControlMsg::SendCommand { request_id, target, data } = frame.msg {
                            let Ok(cmd) = data.decode_plaintext::<ClientCommand>() else { continue };
                            let line = match serde_json::to_string(&cmd) {
                                Ok(l) => l,
                                Err(_) => continue,
                            };
                            if is_admin(&cmd) && matches!(target, CommandTarget::Machine { .. }) {
                                admin_queue.push_back((request_id, line));
                                if !admin_inflight
                                    && let Some((_, l)) = admin_queue.front()
                                {
                                    let _ = stdin.write_all(l.as_bytes()).await;
                                    let _ = stdin.write_all(b"\n").await;
                                    let _ = stdin.flush().await;
                                    admin_inflight = true;
                                }
                            } else {
                                // 会话级命令：立即写
                                let _ = stdin.write_all(line.as_bytes()).await;
                                let _ = stdin.write_all(b"\n").await;
                                let _ = stdin.flush().await;
                            }
                        }
                    }
                    // 来自 daemon stdout 的行
                    line = reader.next_line() => {
                        let Ok(Some(raw)) = line else { break };
                        let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else { continue };
                        if val.get("reply").is_some() {
                            // admin reply → 关联队头 request_id
                            if let Some((req, _)) = admin_queue.pop_front() {
                                let data = DataEnvelope::Plaintext {
                                    agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
                                    bytes: raw.into_bytes(),
                                };
                                link.send(mk_frame(&machine_id, RelayControlMsg::AdminReply { in_reply_to: req, data })).await;
                                admin_inflight = false;
                                if let Some((_, l)) = admin_queue.front() {
                                    let _ = stdin.write_all(l.as_bytes()).await;
                                    let _ = stdin.write_all(b"\n").await;
                                    let _ = stdin.flush().await;
                                    admin_inflight = true;
                                }
                            }
                        } else if val.get("type").is_some() {
                            // best-effort ServerEvent 转发（R0 用 sessionId 兜底 conversation）
                            let sid = val.get("sessionId").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                            let conv = val.get("threadId").and_then(|v| v.as_str()).unwrap_or(&sid).to_string();
                            let data = DataEnvelope::Plaintext {
                                agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
                                bytes: raw.into_bytes(),
                            };
                            link.send(mk_frame(&machine_id, RelayControlMsg::PublishEvent {
                                conversation_id: conv, turn_session_id: sid, seq: 0, data,
                            })).await;
                        }
                    }
                }
            }
        });

        Ok(StdioMachineBridge { child, pump })
    }

    pub async fn shutdown(mut self) {
        self.pump.abort();
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}

impl Drop for StdioMachineBridge {
    /// Anti-orphan safety net: `shutdown(self)` is the normal path (abort
    /// pump + kill + reap child), but any path that doesn't reach it (test
    /// assert fails first, panic, early return) must not leak the real
    /// agentdeckd child process or its stdout pump task. Idempotent with
    /// `shutdown`: aborting an already-aborted task and `start_kill`-ing an
    /// already-reaped child are both no-ops (`kill_on_drop(true)` on the
    /// `Command` above is the same belt-and-suspenders pattern used by
    /// `CodexAdapter`).
    fn drop(&mut self) {
        self.pump.abort();
        let _ = self.child.start_kill();
    }
}

fn mk_frame(machine_id: &str, msg: RelayControlMsg) -> agentdeck_protocol::remote::RemoteFrame {
    agentdeck_protocol::remote::RemoteFrame::control(
        ClientRole::Machine { machine_id: machine_id.to_string() },
        "bridge".into(),
        0,
        msg,
    )
}

fn is_admin(cmd: &ClientCommand) -> bool {
    matches!(
        cmd,
        ClientCommand::Ping
            | ClientCommand::Selfcheck
            | ClientCommand::ProtocolSchema
            | ClientCommand::ProtocolVersion
            | ClientCommand::AgentList
            | ClientCommand::AgentCapabilities { .. }
            | ClientCommand::History(_)
    )
}
