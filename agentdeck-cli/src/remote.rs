// agentdeck-cli/src/remote.rs
//! `agentdeck remote <op>` — Relay R0 CLI 命令面。
//!
//! R0 只有 `smoke` 是可执行路径：单进程内起 `FakeRelay` + 一个真实
//! `agentdeckd` 子进程（经 `StdioMachineBridge` 接入），再驱动一个内存
//! device 客户端，证明 machines 快照订阅 + 机器级 admin（Ping）往返可以
//! 端到端跑通，且都经过 relay 的控制面路由（非直连 daemon）。
//!
//! 其余子命令（machines/sessions/watch/send/approve/deny/ping）在 R0
//! 只是语义已冻结的接口基线占位：真实实现需要 R1 的网络 relay endpoint，
//! 这里打印明确提示并返回失败码，不做任何真实连接尝试。

use std::process::ExitCode;
use std::time::Duration;

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, DataEnvelope, DeviceDescriptor, DeviceKind, MachineDescriptor,
    RelayControlMsg, RemoteFrame, SubTarget,
};
use agentdeck_protocol::ClientCommand;
use agentdeck_relay::{FakeRelay, RelayClient, StdioMachineBridge};

use crate::transport::locate_daemon;

/// admin 往返等待每帧超时——避免 relay/daemon 卡死时 smoke 永久挂起。
const ADMIN_REPLY_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

fn machine() -> MachineDescriptor {
    MachineDescriptor {
        machine_id: "local".into(),
        name: "local daemon".into(),
        agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
        is_online: true,
        last_heartbeat_ms: None,
    }
}

fn dev(msg: RelayControlMsg) -> RemoteFrame {
    RemoteFrame::control(
        ClientRole::Device {
            device_id: "cli".into(),
        },
        "smoke".into(),
        0,
        msg,
    )
}

/// R0 单进程冒烟：证明 device 经 relay 看到机器、并 admin 往返到真实 daemon。
pub async fn smoke(profile: &str) -> ExitCode {
    let Some(daemon) = locate_daemon() else {
        eprintln!("remote.daemon.not_found: 找不到 agentdeckd 二进制，请先 `cargo build`");
        return ExitCode::FAILURE;
    };
    let relay = FakeRelay::start();
    let bridge = match StdioMachineBridge::spawn(&daemon, profile, machine(), &relay).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("remote.bridge.spawn_failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut d = relay
        .connect(ClientRole::Device {
            device_id: "cli".into(),
        })
        .await;
    d.send(dev(RelayControlMsg::ConnectDevice {
        device: DeviceDescriptor {
            device_id: "cli".into(),
            kind: DeviceKind::Cli,
        },
    }))
    .await;
    d.send(dev(RelayControlMsg::Subscribe {
        target: SubTarget::Machines,
    }))
    .await;

    // 1) machines 快照
    match tokio::time::timeout(ADMIN_REPLY_FRAME_TIMEOUT, d.recv()).await {
        Ok(Some(frame)) => {
            if let RelayControlMsg::MachineList { machines } = frame.msg {
                println!(
                    "[smoke] machines: {}  (trace={})",
                    machines.len(),
                    frame.trace_id
                );
                for m in machines {
                    println!(
                        "  - {} online={} v{}",
                        m.machine_id, m.is_online, m.agentdeck_protocol_version
                    );
                }
            }
        }
        Ok(None) => {
            eprintln!("remote.smoke.stream_closed: 等待 machines 快照时 relay 流已关闭");
            bridge.shutdown().await;
            return ExitCode::FAILURE;
        }
        Err(_) => {
            eprintln!("remote.smoke.timeout: 等待 machines 快照超时（{ADMIN_REPLY_FRAME_TIMEOUT:?}）");
            bridge.shutdown().await;
            return ExitCode::FAILURE;
        }
    }

    // 2) ping 机器级 admin 往返
    d.send(dev(RelayControlMsg::SendCommand {
        request_id: "smoke-ping".into(),
        target: CommandTarget::Machine {
            machine_id: "local".into(),
        },
        data: DataEnvelope::plaintext(&ClientCommand::Ping).unwrap(),
    }))
    .await;

    let ok = wait_admin_reply(&mut d, "smoke-ping").await;
    bridge.shutdown().await;
    if ok {
        println!("[smoke] ping round-trip OK");
        ExitCode::SUCCESS
    } else {
        eprintln!("[smoke] ping round-trip FAILED");
        ExitCode::FAILURE
    }
}

/// 轮询直到收到关联到 `want` 的 AdminReply，或超时/断流。
/// 每次 `recv().await` 都套 `tokio::time::timeout`：relay/daemon 卡死时
/// 快速返回失败，而不是让 smoke（及其单测）永久挂起。
async fn wait_admin_reply(d: &mut RelayClient, want: &str) -> bool {
    for _ in 0..64 {
        match tokio::time::timeout(ADMIN_REPLY_FRAME_TIMEOUT, d.recv()).await {
            Ok(Some(frame)) => {
                if let RelayControlMsg::AdminReply { in_reply_to, data } = frame.msg {
                    if in_reply_to == want {
                        let v: serde_json::Value = data.decode_plaintext().unwrap_or_default();
                        println!("[smoke] admin reply: {v}");
                        return v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
                    }
                }
            }
            Ok(None) => return false, // relay 流已关闭
            Err(_) => return false,    // 超时：不再重试，快速失败
        }
    }
    false
}

/// R0：非 smoke 子命令是冻结的接口基线，需 R1 的 relay endpoint 才能独立运行。
fn baseline_stub(name: &str) -> ExitCode {
    eprintln!(
        "remote.{name}: 接口基线已冻结；独立运行需 R1 relay endpoint（`--relay ws://…`）。R0 请用 `agentdeck remote smoke`。"
    );
    ExitCode::FAILURE
}

pub async fn run(op: RemoteOpArg, profile: &str, _data_dir: Option<&str>) -> ExitCode {
    match op {
        RemoteOpArg::Smoke => smoke(profile).await,
        RemoteOpArg::Machines => baseline_stub("machines"),
        RemoteOpArg::Sessions => baseline_stub("sessions"),
        RemoteOpArg::Watch => baseline_stub("watch"),
        RemoteOpArg::Send => baseline_stub("send"),
        RemoteOpArg::Approve => baseline_stub("approve"),
        RemoteOpArg::Deny => baseline_stub("deny"),
        RemoteOpArg::Ping => baseline_stub("ping"),
    }
}

/// main.rs 的 `RemoteOp`（clap 类型，携带各子命令的具体参数）到本模块的窄化
/// 映射：R0 的基线占位子命令还不需要读取参数内容，先只保留“选中了哪个操作”，
/// 避免 clap 派生类型泄漏进 remote 的逻辑层（R1 接线时再按需展开取参）。
pub enum RemoteOpArg {
    Smoke,
    Machines,
    Sessions,
    Watch,
    Send,
    Approve,
    Deny,
    Ping,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn smoke_pings_real_daemon_through_relay() {
        // 需要已构建的 daemon 二进制（locate_daemon 查 target/{debug,release}）。
        if locate_daemon().is_none() {
            eprintln!("skip: agentdeckd 未构建");
            return;
        }
        let code = smoke("stable").await;
        assert_eq!(code, ExitCode::SUCCESS);
    }
}
