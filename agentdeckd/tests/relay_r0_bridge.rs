// agentdeckd/tests/relay_r0_bridge.rs
//
// T1: 真实 agentdeckd 子进程经 StdioMachineBridge 接入 FakeRelay，
// device 并发发两条 admin Ping，断言各自 AdminReply 正确关联（single-flight
// 不串号）且内容为 `{"reply":"ping","ok":true}`。
use std::path::Path;
use std::time::Duration;

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, DataEnvelope, DeviceDescriptor, DeviceKind, MachineDescriptor,
    RelayControlMsg, RemoteFrame,
};
use agentdeck_protocol::ClientCommand;
use agentdeck_relay::{FakeRelay, RelayClient};

fn machine() -> MachineDescriptor {
    MachineDescriptor {
        machine_id: "M1".into(),
        name: "test".into(),
        agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
        is_online: true,
        last_heartbeat_ms: None,
    }
}

fn device_frame(request_id: &str) -> RemoteFrame {
    RemoteFrame::control(
        ClientRole::Device { device_id: "D1".into() },
        "t".into(),
        0,
        RelayControlMsg::SendCommand {
            request_id: request_id.into(),
            target: CommandTarget::Machine { machine_id: "M1".into() },
            data: DataEnvelope::plaintext(&ClientCommand::Ping).unwrap(),
        },
    )
}

/// 轮询直到收到关联到 `want` 的 AdminReply。用 timeout 包裹：回归时快速失败
/// 而不是无限期挂起（真实 daemon 启动可能稍慢，给宽松的 10s）。
async fn recv_admin_reply(d: &mut RelayClient, want: &str) -> serde_json::Value {
    loop {
        let frame = match tokio::time::timeout(Duration::from_secs(10), d.recv()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!("timed out waiting for AdminReply({want}): stream closed"),
            Err(_) => panic!("timed out waiting for AdminReply({want}) after 10s"),
        };
        match frame.msg {
            RelayControlMsg::AdminReply { in_reply_to, data } if in_reply_to == want => {
                return data.decode_plaintext().unwrap();
            }
            _ => continue,
        }
    }
}

#[tokio::test]
async fn t1_real_daemon_admin_ping_round_trips_through_relay() {
    let daemon = Path::new(env!("CARGO_BIN_EXE_agentdeckd"));
    let relay = FakeRelay::start();
    let link = relay
        .connect(ClientRole::Machine { machine_id: "M1".into() })
        .await;
    let bridge = agentdeck_relay::StdioMachineBridge::spawn(daemon, "stable", machine(), link)
        .await
        .expect("bridge spawn");

    let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
    d.send(RemoteFrame::control(
        ClientRole::Device { device_id: "D1".into() },
        "t".into(),
        0,
        RelayControlMsg::ConnectDevice {
            device: DeviceDescriptor { device_id: "D1".into(), kind: DeviceKind::Cli },
        },
    ))
    .await;

    // 并发两条同类 admin 命令，断言各自正确关联、不串
    d.send(device_frame("r1")).await;
    d.send(device_frame("r2")).await;

    let v1 = recv_admin_reply(&mut d, "r1").await;
    let v2 = recv_admin_reply(&mut d, "r2").await;
    assert_eq!(v1["reply"], "ping");
    assert_eq!(v1["ok"], true);
    assert_eq!(v2["reply"], "ping");
    assert_eq!(v2["ok"], true);

    bridge.shutdown().await;
}
