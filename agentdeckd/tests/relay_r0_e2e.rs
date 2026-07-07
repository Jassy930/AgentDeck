// agentdeckd/tests/relay_r0_e2e.rs
//! 门控 E2E：真实 Codex 会话流经 relay 穿透。默认跳过；需 AGENTDECK_E2E=1 + 已登录。
//!
//! R0 简化：真实会话的 conversation_id（=daemon threadId/sessionId 兜底，见
//! `StdioMachineBridge` best-effort 转发）在 SessionStart 之前未知，device
//! 无法预先按 conversation 精确订阅（`SubTarget::Events` 需要确定
//! conversation_id，relay 也无「订阅全部」的通配目标）。因此本测试改为不
//! 预订阅，直接轮询该 device 连接上出现的所有帧并匹配 `Event` 中的
//! `SessionStarted`。这只是 R0 的验证简化；按 conversation 精确订阅需要
//! R2 的身份 bootstrap（machine 在收到 SessionStart 的 CommandDelivered
//! 前把待定 conversation_id 告知 device，或 relay 提供通配订阅），留待
//! 后续任务。
use std::path::Path;

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, DataEnvelope, MachineDescriptor, RelayControlMsg, RemoteFrame,
};
use agentdeck_protocol::{
    AgentKind, ClientCommand, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
    CodexSessionOptions, ServerEvent, VendorSessionOptions,
};
use agentdeck_relay::{FakeRelay, RelayClient};

fn machine() -> MachineDescriptor {
    MachineDescriptor {
        machine_id: "M1".into(),
        name: "e2e".into(),
        agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
        is_online: true,
        last_heartbeat_ms: None,
    }
}

#[tokio::test]
async fn t4_real_session_stream_transits_relay() {
    if std::env::var("AGENTDECK_E2E").is_err() {
        eprintln!("skip: 设置 AGENTDECK_E2E=1 且已登录 codex 后运行");
        return;
    }
    let daemon = Path::new(env!("CARGO_BIN_EXE_agentdeckd"));
    let relay = FakeRelay::start();
    let bridge = agentdeck_relay::StdioMachineBridge::spawn(daemon, "stable", machine(), &relay)
        .await
        .expect("bridge");

    let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
    // 真实会话经 SendCommand{Machine} 发 SessionStart；bridge 收到后立即写 daemon
    // stdin（非 admin 命令），daemon 产生的 ServerEvent 流经 relay best-effort 转发。
    let start = ClientCommand::SessionStart(agentdeck_protocol::SessionStart {
        agent_kind: AgentKind::Codex,
        cwd: std::env::current_dir().unwrap(),
        prompt: Some("say hi and stop".into()),
        vendor_options: VendorSessionOptions::Codex(CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::Never,
            sandbox: CodexSandboxMode::ReadOnly,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Minimal,
            mcp_overrides: vec![],
        }),
        runtime_options: Default::default(),
    });
    d.send(RemoteFrame::control(
        ClientRole::Device { device_id: "D1".into() },
        "e2e".into(),
        0,
        RelayControlMsg::SendCommand {
            request_id: "e1".into(),
            target: CommandTarget::Machine { machine_id: "M1".into() },
            data: DataEnvelope::plaintext(&start).unwrap(),
        },
    ))
    .await;

    let ok = wait_session_started(&mut d).await;
    bridge.shutdown().await;
    assert!(ok, "未在 relay 上收到 SessionStarted");
}

/// 轮询直到看到穿透 relay 的 `SessionStarted`。每次 recv 都用 timeout 包裹：
/// 断流或 daemon 卡死时快速失败而不是无限期挂起。
async fn wait_session_started(d: &mut RelayClient) -> bool {
    for _ in 0..2000 {
        match tokio::time::timeout(std::time::Duration::from_secs(30), d.recv()).await {
            Ok(Some(frame)) => {
                if let RelayControlMsg::Event { data, .. } = frame.msg
                    && let Ok(ev) = data.decode_plaintext::<ServerEvent>()
                    && matches!(ev, ServerEvent::SessionStarted { .. })
                {
                    return true;
                }
            }
            _ => return false,
        }
    }
    false
}
