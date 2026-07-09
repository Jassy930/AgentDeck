// agentdeck-relay/tests/r0_composition.rs
//
// T2: 合成 machine 全流集成测试（ungated）。一个 RelayClient 扮演 machine，
// 手动 RegisterMachine/AnnounceSession/PublishEvent 真实协议事件序列，
// 断言订阅 conversation 的 device watcher 在跨 turn（S1 → S2，同一
// conversation C1）时仍收全流、seq 单调、turn 身份切换正确——证明 prompt
// 触发新 turn（新 turn_session_id）后订阅 conversation 的 watcher 不丢流。
use agentdeck_protocol::remote::{
    ClientRole, DataEnvelope, MachineDescriptor, RelayControlMsg, RemoteFrame, SessionDescriptor,
    SubTarget,
};
use agentdeck_protocol::{AgentKind, ServerEvent, SessionId, ThreadId};
use agentdeck_relay::{FakeRelay, RelayClient};

fn m_frame(msg: RelayControlMsg) -> RemoteFrame {
    RemoteFrame::control(ClientRole::Machine { machine_id: "M1".into() }, "t".into(), 0, msg)
}
fn d_frame(msg: RelayControlMsg) -> RemoteFrame {
    RemoteFrame::control(ClientRole::Device { device_id: "D1".into() }, "t".into(), 0, msg)
}

fn machine() -> MachineDescriptor {
    MachineDescriptor {
        machine_id: "M1".into(),
        name: "syn".into(),
        agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
        is_online: true,
        last_heartbeat_ms: None,
    }
}
fn session() -> SessionDescriptor {
    SessionDescriptor {
        conversation_id: "C1".into(),
        machine_id: "M1".into(),
        thread_id: Some("C1".into()),
        current_turn_session_id: Some("S1".into()),
        agent_kind: AgentKind::Codex,
        cwd: "/tmp/proj".into(),
        title: None,
    }
}

// 合成 machine 发一条 ServerEvent（真实协议类型），wrap 成 PublishEvent
async fn publish_event(m: &RelayClient, conv: &str, turn: &str, ev: &ServerEvent) {
    m.send(m_frame(RelayControlMsg::PublishEvent {
        conversation_id: conv.into(),
        turn_session_id: turn.into(),
        seq: 0,
        data: DataEnvelope::plaintext(ev).unwrap(),
    }))
    .await;
}

/// 轮询下一条 Event 帧。用 timeout 包裹：回归（丢流/死锁）时快速失败而不是
/// 无限期挂起。
async fn next_event(d: &mut RelayClient) -> (String, u64, ServerEvent) {
    loop {
        let frame = match tokio::time::timeout(std::time::Duration::from_secs(5), d.recv()).await
        {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!("timed out waiting for Event frame: stream closed"),
            Err(_) => panic!("timed out waiting for Event frame after 5s"),
        };
        match frame.msg {
            RelayControlMsg::Event { turn_session_id, seq, data, .. } => {
                return (turn_session_id, seq, data.decode_plaintext().unwrap());
            }
            _ => continue,
        }
    }
}

#[tokio::test]
async fn t2_conversation_stream_survives_new_turn_through_relay() {
    let relay = FakeRelay::start();
    let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
    m.send(m_frame(RelayControlMsg::RegisterMachine { machine: machine() })).await;
    m.send(m_frame(RelayControlMsg::AnnounceSession { session: session() })).await;

    let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
    d.send(d_frame(RelayControlMsg::Subscribe {
        target: SubTarget::Events { conversation_id: "C1".into(), since_seq: None },
    }))
    .await;

    // turn A（session S1）
    publish_event(
        &m,
        "C1",
        "S1",
        &ServerEvent::SessionStarted {
            session_id: SessionId("S1".into()),
            thread_id: Some(ThreadId("C1".into())),
            agent_kind: AgentKind::Codex,
        },
    )
    .await;
    publish_event(
        &m,
        "C1",
        "S1",
        &ServerEvent::TurnComplete {
            session_id: SessionId("S1".into()),
            thread_id: ThreadId("C1".into()),
            agent_kind: AgentKind::Codex,
            summary: agentdeck_protocol::TurnSummary {
                total_input_tokens: None,
                total_output_tokens: None,
                elapsed_ms: 10,
            },
        },
    )
    .await;
    // turn B（session S2，同 conversation C1）——模拟 prompt 触发新 turn
    publish_event(
        &m,
        "C1",
        "S2",
        &ServerEvent::SessionStarted {
            session_id: SessionId("S2".into()),
            thread_id: Some(ThreadId("C1".into())),
            agent_kind: AgentKind::Codex,
        },
    )
    .await;
    publish_event(
        &m,
        "C1",
        "S2",
        &ServerEvent::TurnComplete {
            session_id: SessionId("S2".into()),
            thread_id: ThreadId("C1".into()),
            agent_kind: AgentKind::Codex,
            summary: agentdeck_protocol::TurnSummary {
                total_input_tokens: None,
                total_output_tokens: None,
                elapsed_ms: 20,
            },
        },
    )
    .await;

    // 订阅 conversation 的 device 应收到两个 turn 全部事件，seq 单调，turn 身份切换正确
    let (t0, s0, _) = next_event(&mut d).await;
    let (t1, s1, _) = next_event(&mut d).await;
    let (t2, s2, _) = next_event(&mut d).await;
    let (t3, s3, _) = next_event(&mut d).await;
    assert_eq!((s0, s1, s2, s3), (0, 1, 2, 3));
    assert_eq!(t0, "S1");
    assert_eq!(t1, "S1");
    assert_eq!(t2, "S2"); // 新 turn 的事件仍到达订阅 conversation 的 watcher
    assert_eq!(t3, "S2");
}
