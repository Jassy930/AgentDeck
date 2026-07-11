// agentdeck-relay/tests/r1b_hardening_e2e.rs
//! R1b Task 10: 真 loopback WS + 真 SQLite 文件端到端集成测试（`server`
//! feature 门内）。风格延续 `r1a_ws_e2e.rs`：每个测试独立 `127.0.0.1:0` 绑定
//! 读回动态端口，`tempfile::tempdir()` 存 `relay.db`，每个 `recv` 套
//! `tokio::time::timeout(5s)`。
//!
//! 覆盖 R1b 收尾的 4 个硬化场景：
//! 1. SQLite 重启恢复——seq 高水位跨进程重启延续 + 已撤销凭据重启后仍被拒。
//! 2. `conv_buffer` 硬上界溢出后，一个 `since_seq` 落在已被丢弃区间的新订阅
//!    必须收到 `Error{code: REPLAY_GAP}`，而不是静默漏发或读到错位数据。
//! 3. machine 断线重连后重新 `AnnounceSession` 同一 `conversation_id`，device
//!    侧 `SessionList` 不重复（upsert-by-conversation_id 幂等）。
//! 4. R1a 遗留 #9：revoke 一个设备身份，① 活连接被断开 ② 同 credential 重连
//!    被拒。见该测试内注释——这条测试同时揭示了一个尚未打通的产品缺口（见
//!    下方 `revoke_closes_active_connection_and_blocks_reconnect` 顶部注释）。

#![cfg(feature = "server")]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ed25519_dalek::Signer;
use serde_json::{Value, json};

use agentdeck_protocol::remote::{
    ClientRole, DataEnvelope, MachineDescriptor, RelayControlMsg, RemoteFrame, SessionDescriptor,
    SubTarget, failure,
};
use agentdeck_relay::RelayLink;
use agentdeck_relay::SqliteRelayStore;
use agentdeck_relay::config::RelayConfig;
use agentdeck_relay_client::{WsError, WsRelayClient};

const RECV_TIMEOUT: Duration = Duration::from_secs(5);

async fn recv<L: RelayLink>(link: &mut L) -> RemoteFrame {
    tokio::time::timeout(RECV_TIMEOUT, link.recv())
        .await
        .expect("timed out waiting for a frame")
        .expect("connection closed while waiting for a frame")
}

/// 起一个真实 server：`127.0.0.1:0` 绑定读回动态端口，`store` 打开在
/// `db_path`（调用方传入 tempdir 路径，支持"关服→同路径重开"模拟重启）。
/// 返回的 `JoinHandle` 供"重启"场景 `.abort()` 后 `.await` 确认任务真正退出。
async fn setup_server_with_db(
    bootstrap_secret: &str,
    db_path: &Path,
    conv_buffer_cap: usize,
) -> (
    SocketAddr,
    SqliteRelayStore,
    String,
    tokio::task::JoinHandle<Result<(), agentdeck_relay::server::ServeError>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig {
        bind: addr,
        bootstrap_secret: bootstrap_secret.to_string(),
        tls: None,
        allow_plaintext: true,
        log_level: "info".to_string(),
        storage_path: db_path.to_path_buf(),
        conv_buffer_cap,
        req_origin_ttl_ms: 300_000,
    };
    let store = SqliteRelayStore::open(db_path).expect("open sqlite store at tempdir path");
    let relay = agentdeck_relay::FakeRelay::start_with_all(store.clone(), 300_000, conv_buffer_cap);
    let store_for_server = store.clone();
    let handle = tokio::spawn(async move {
        agentdeck_relay::server::serve_with_listener(config, store_for_server, relay, listener)
            .await
    });
    let base_url = format!("http://{addr}");
    (addr, store, base_url, handle)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// REST `POST /v1/pair/challenge`（阻塞 ureq，`spawn_blocking` 包裹）。
async fn challenge(base_url: &str, sign_pub: &str) -> Value {
    let base_url = base_url.to_string();
    let sign_pub = sign_pub.to_string();
    tokio::task::spawn_blocking(move || {
        let resp = ureq::post(&format!("{base_url}/v1/pair/challenge"))
            .send_json(json!({ "device_sign_pubkey": sign_pub }))
            .expect("challenge request failed");
        resp.into_json::<Value>()
            .expect("challenge response not JSON")
    })
    .await
    .unwrap()
}

/// REST `POST /v1/pair/complete`（阻塞 ureq）。
async fn complete(
    base_url: &str,
    bootstrap_secret: &str,
    nonce_sig: &str,
    device_id: &str,
    role: &str,
    sign_pub: &str,
    box_pub: &str,
    owner_pubkey: Option<&str>,
) -> Result<Value, (u16, Value)> {
    let base_url = base_url.to_string();
    let bootstrap_secret = bootstrap_secret.to_string();
    let nonce_sig = nonce_sig.to_string();
    let device_id = device_id.to_string();
    let role = role.to_string();
    let sign_pub = sign_pub.to_string();
    let box_pub = box_pub.to_string();
    let owner_pubkey = owner_pubkey.map(|s| s.to_string());
    tokio::task::spawn_blocking(move || {
        let mut body = json!({
            "bootstrap_secret": bootstrap_secret,
            "nonce_sig": nonce_sig,
            "device": {
                "device_id": device_id,
                "role": role,
                "sign_pubkey": sign_pub,
                "box_pubkey": box_pub,
            },
        });
        if let Some(owner_pubkey) = owner_pubkey {
            body["owner_pubkey"] = json!(owner_pubkey);
        }
        match ureq::post(&format!("{base_url}/v1/pair/complete")).send_json(body) {
            Ok(resp) => Ok(resp
                .into_json::<Value>()
                .expect("complete response not JSON")),
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_json::<Value>().unwrap_or(Value::Null);
                Err((code, body))
            }
            Err(ureq::Error::Transport(t)) => panic!("REST transport error: {t}"),
        }
    })
    .await
    .unwrap()
}

struct Enrolled {
    credential: String,
    device_id: String,
}

/// 端到端 enroll 一个凭据：起 challenge → ed25519 签名 nonce → complete。
async fn enroll(
    base_url: &str,
    bootstrap_secret: &str,
    device_id: &str,
    role: &str,
    owner_pubkey: Option<&str>,
) -> Enrolled {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let sign_pub = b64(sk.verifying_key().as_bytes());
    let ch = challenge(base_url, &sign_pub).await;
    let nonce = ch["nonce"].as_str().expect("nonce missing").to_string();
    let sig = b64(&sk.sign(nonce.as_bytes()).to_bytes());
    let resp = complete(
        base_url,
        bootstrap_secret,
        &sig,
        device_id,
        role,
        &sign_pub,
        "box-pub-placeholder",
        owner_pubkey,
    )
    .await
    .expect("enroll complete failed");
    Enrolled {
        credential: resp["credential"].as_str().unwrap().to_string(),
        device_id: resp["device_id"].as_str().unwrap().to_string(),
    }
}

fn ws_url(addr: SocketAddr) -> String {
    format!(
        "ws://{addr}/v1/connect?v={}",
        agentdeck_protocol::remote::RELAY_PROTOCOL_VERSION
    )
}

fn machine_descriptor(machine_id: &str, name: &str) -> MachineDescriptor {
    MachineDescriptor {
        machine_id: machine_id.to_string(),
        name: name.to_string(),
        agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
        is_online: true,
        last_heartbeat_ms: None,
    }
}

fn session_descriptor(conversation_id: &str, machine_id: &str) -> SessionDescriptor {
    SessionDescriptor {
        conversation_id: conversation_id.to_string(),
        machine_id: machine_id.to_string(),
        thread_id: Some(conversation_id.to_string()),
        current_turn_session_id: None,
        agent_kind: agentdeck_protocol::AgentKind::Codex,
        cwd: "/tmp/proj".to_string(),
        title: None,
    }
}

async fn publish_event<L: RelayLink>(
    link: &L,
    machine_id: &str,
    conversation_id: &str,
    turn_session_id: &str,
) {
    link.send(RemoteFrame::control(
        ClientRole::Machine {
            machine_id: machine_id.to_string(),
        },
        format!("t-pub-{turn_session_id}"),
        0,
        RelayControlMsg::PublishEvent {
            conversation_id: conversation_id.to_string(),
            turn_session_id: turn_session_id.to_string(),
            seq: 0, // relay 自行 re-stamp
            data: DataEnvelope::plaintext(&format!("evt-{turn_session_id}")).unwrap(),
        },
    ))
    .await;
}

async fn recv_event<L: RelayLink>(link: &mut L) -> (String, String, u64) {
    loop {
        if let RelayControlMsg::Event {
            conversation_id,
            turn_session_id,
            seq,
            ..
        } = recv(link).await.msg
        {
            return (conversation_id, turn_session_id, seq);
        }
    }
}

async fn recv_error_code<L: RelayLink>(link: &mut L) -> String {
    loop {
        if let RelayControlMsg::Error { code, .. } = recv(link).await.msg {
            return code;
        }
    }
}

// ---------------------------------------------------------------------------
// 测试 1: SQLite 重启恢复——seq 高水位跨进程重启延续 + 已撤销凭据重启后仍被拒。
// ---------------------------------------------------------------------------
#[tokio::test]
async fn restart_preserves_seq_and_revocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("relay.db");

    // ---- round 1 ----
    let (addr1, store1, base_url1, handle1) =
        setup_server_with_db("boot-secret-restart", &db_path, 1000).await;

    let machine = enroll(
        &base_url1,
        "boot-secret-restart",
        "m1",
        "machine",
        Some("owner-1"),
    )
    .await;
    let device = enroll(&base_url1, "boot-secret-restart", "d1", "device", None).await;
    let to_revoke = enroll(
        &base_url1,
        "boot-secret-restart",
        "will-be-revoked",
        "device",
        None,
    )
    .await;

    let m1_link = WsRelayClient::connect(
        &ws_url(addr1),
        &machine.credential,
        ClientRole::Machine {
            machine_id: machine.device_id.clone(),
        },
    )
    .await
    .expect("machine ws connect failed");
    m1_link
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-reg".into(),
            0,
            RelayControlMsg::RegisterMachine {
                machine: machine_descriptor("m1", "Machine One"),
            },
        ))
        .await;
    m1_link
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-announce".into(),
            0,
            RelayControlMsg::AnnounceSession {
                session: session_descriptor("C1", "m1"),
            },
        ))
        .await;

    let mut d1_link = WsRelayClient::connect(
        &ws_url(addr1),
        &device.credential,
        ClientRole::Device {
            device_id: device.device_id.clone(),
        },
    )
    .await
    .expect("device ws connect failed");
    d1_link
        .send(RemoteFrame::control(
            ClientRole::Device {
                device_id: device.device_id.clone(),
            },
            "t-sub-events".into(),
            0,
            RelayControlMsg::Subscribe {
                target: SubTarget::Events {
                    conversation_id: "C1".into(),
                    since_seq: None,
                },
            },
        ))
        .await;

    for i in 0..3u64 {
        publish_event(&m1_link, "m1", "C1", &format!("turn-{i}")).await;
    }
    let mut last_seq = 0u64;
    for _ in 0..3u64 {
        let (_, _, seq) = recv_event(&mut d1_link).await;
        last_seq = last_seq.max(seq);
    }
    assert_eq!(
        last_seq, 2,
        "3 个事件发布后（seq 从 0 起分配）最大 seq 应为 2"
    );

    // round 1 撤销一个凭据（不需要它建立过活连接——本测试只断言"重启后仍被拒"）
    agentdeck_relay::server::revoke_device(&store1, &to_revoke.device_id);

    // ---- 关闭 round 1 server，模拟进程重启 ----
    handle1.abort();
    let _ = handle1.await;
    drop(m1_link);
    drop(d1_link);
    drop(store1);

    // ---- round 2：同一 tempdir 路径重新起 server ----
    // round 2 不需要再走 REST enroll（凭据沿用 round 1 的），故 base_url 无需保留。
    let (addr2, _store2, _base_url2, _handle2) =
        setup_server_with_db("boot-secret-restart", &db_path, 1000).await;

    // 已撤销凭据重启后仍被拒
    match WsRelayClient::connect(
        &ws_url(addr2),
        &to_revoke.credential,
        ClientRole::Device {
            device_id: to_revoke.device_id.clone(),
        },
    )
    .await
    {
        Err(WsError::Rejected { status, code }) => {
            assert_eq!(status, 401);
            assert_eq!(code.as_deref(), Some(failure::AUTH_REVOKED_DEVICE));
        }
        Ok(_) => {
            panic!("expected revoked credential to be rejected after restart, but it connected")
        }
        Err(other) => panic!("expected WsError::Rejected, got a different WsError: {other:?}"),
    }

    // 未撤销凭据重启后仍可正常连接+继续发布；重新 RegisterMachine+AnnounceSession
    // 是必须的——重启是全新 Core，内存态 machines/conv_machine 映射未持久化，
    // 授权检查（owns_conversation）依赖 conv_machine，需要重新 AnnounceSession。
    let m1_link2 = WsRelayClient::connect(
        &ws_url(addr2),
        &machine.credential,
        ClientRole::Machine {
            machine_id: machine.device_id.clone(),
        },
    )
    .await
    .expect("machine ws reconnect after restart failed");
    m1_link2
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-reg-2".into(),
            0,
            RelayControlMsg::RegisterMachine {
                machine: machine_descriptor("m1", "Machine One"),
            },
        ))
        .await;
    m1_link2
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-announce-2".into(),
            0,
            RelayControlMsg::AnnounceSession {
                session: session_descriptor("C1", "m1"),
            },
        ))
        .await;

    let mut d1_link2 = WsRelayClient::connect(
        &ws_url(addr2),
        &device.credential,
        ClientRole::Device {
            device_id: device.device_id.clone(),
        },
    )
    .await
    .expect("device ws reconnect after restart failed");
    d1_link2
        .send(RemoteFrame::control(
            ClientRole::Device {
                device_id: device.device_id.clone(),
            },
            "t-sub-events-2".into(),
            0,
            RelayControlMsg::Subscribe {
                target: SubTarget::Events {
                    conversation_id: "C1".into(),
                    since_seq: None,
                },
            },
        ))
        .await;

    publish_event(&m1_link2, "m1", "C1", "turn-after-restart").await;
    let (_, _, seq_after_restart) = recv_event(&mut d1_link2).await;
    assert_eq!(
        seq_after_restart, 3,
        "重启后 seq 必须从持久化高水位（此前已分配到 2，下一个是 3）延续，而不是从 0 重新开始"
    );
}

// ---------------------------------------------------------------------------
// 测试 2: conv_buffer 硬上界溢出后，since_seq 落在已丢弃区间必须返回
// Error{code: REPLAY_GAP}，而不是静默漏发或读到错位数据。
// ---------------------------------------------------------------------------
#[tokio::test]
async fn ack_then_lagged_subscriber_gets_gap_not_stale_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("relay.db");
    const CAP: usize = 10;
    let (addr, _store, base_url, _handle) =
        setup_server_with_db("boot-secret-gap", &db_path, CAP).await;

    let machine = enroll(
        &base_url,
        "boot-secret-gap",
        "m1",
        "machine",
        Some("owner-1"),
    )
    .await;

    let m1_link = WsRelayClient::connect(
        &ws_url(addr),
        &machine.credential,
        ClientRole::Machine {
            machine_id: machine.device_id.clone(),
        },
    )
    .await
    .expect("machine ws connect failed");
    m1_link
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-reg".into(),
            0,
            RelayControlMsg::RegisterMachine {
                machine: machine_descriptor("m1", "Machine One"),
            },
        ))
        .await;
    m1_link
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-announce".into(),
            0,
            RelayControlMsg::AnnounceSession {
                session: session_descriptor("C2", "m1"),
            },
        ))
        .await;

    // 发布远超硬上界（CAP=10）的事件数量，触发 FIFO 淘汰；buffer 最终只保留
    // 最新 10 条（seq 10..19），seq 0..9 已被丢弃。
    for i in 0..(CAP * 2) {
        publish_event(&m1_link, "m1", "C2", &format!("turn-{i}")).await;
    }

    // 同步屏障（沿用 router.rs 单测的手法）：探针 device 订阅 Machines，发布循环
    // 之后从同一条 m1 连接再发一次 RegisterMachine（幂等，副作用可观测），
    // 收到该广播即可断言此前所有 PublishEvent 均已被 Core 处理完（conv_buffer
    // 已完成硬上界裁剪）——避免"新订阅可能抢在裁剪完成前读到未裁剪 buffer"
    // 的 flaky。
    let mut sync_device = WsRelayClient::connect(
        &ws_url(addr),
        &enroll(&base_url, "boot-secret-gap", "sync-dev", "device", None)
            .await
            .credential,
        ClientRole::Device {
            device_id: "sync-dev".into(),
        },
    )
    .await
    .expect("sync device ws connect failed");
    sync_device
        .send(RemoteFrame::control(
            ClientRole::Device {
                device_id: "sync-dev".into(),
            },
            "t-sub-machines".into(),
            0,
            RelayControlMsg::Subscribe {
                target: SubTarget::Machines,
            },
        ))
        .await;
    let _ = recv(&mut sync_device).await; // 消化订阅时的初始 MachineList 快照

    m1_link
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-reg-barrier".into(),
            0,
            RelayControlMsg::RegisterMachine {
                machine: machine_descriptor("m1", "Machine One"),
            },
        ))
        .await;
    let barrier = recv(&mut sync_device).await; // 屏障广播：之前所有 PublishEvent 均已处理完
    assert!(matches!(barrier.msg, RelayControlMsg::MachineList { .. }));

    // since_seq=3 早于 buffer 最旧保留的 seq（此时 buffer 只剩 seq 10..19）
    let mut d1_link = WsRelayClient::connect(
        &ws_url(addr),
        &enroll(&base_url, "boot-secret-gap", "d1", "device", None)
            .await
            .credential,
        ClientRole::Device {
            device_id: "d1".into(),
        },
    )
    .await
    .expect("device ws connect failed");
    d1_link
        .send(RemoteFrame::control(
            ClientRole::Device {
                device_id: "d1".into(),
            },
            "t-sub-events".into(),
            0,
            RelayControlMsg::Subscribe {
                target: SubTarget::Events {
                    conversation_id: "C2".into(),
                    since_seq: Some(3),
                },
            },
        ))
        .await;
    let code = recv_error_code(&mut d1_link).await;
    assert_eq!(
        code,
        failure::REPLAY_GAP,
        "since_seq=3 已被硬上界 FIFO 丢弃，必须收到 REPLAY_GAP，而不是静默漏发/错位数据"
    );
}

// ---------------------------------------------------------------------------
// 测试 3: machine 断线重连后重新 AnnounceSession 同一 conversation_id，
// device 侧 SessionList 不重复。
// ---------------------------------------------------------------------------
#[tokio::test]
async fn announce_session_idempotent_across_reconnect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("relay.db");
    let (addr, _store, base_url, _handle) =
        setup_server_with_db("boot-secret-idem", &db_path, 1000).await;

    let machine = enroll(
        &base_url,
        "boot-secret-idem",
        "m1",
        "machine",
        Some("owner-1"),
    )
    .await;
    let device = enroll(&base_url, "boot-secret-idem", "d1", "device", None).await;

    // d1 先订阅 Machines（用作下面几步的顺序屏障），消化初始空快照。
    let mut d1_link = WsRelayClient::connect(
        &ws_url(addr),
        &device.credential,
        ClientRole::Device {
            device_id: device.device_id.clone(),
        },
    )
    .await
    .expect("device ws connect failed");
    d1_link
        .send(RemoteFrame::control(
            ClientRole::Device {
                device_id: device.device_id.clone(),
            },
            "t-sub-machines".into(),
            0,
            RelayControlMsg::Subscribe {
                target: SubTarget::Machines,
            },
        ))
        .await;
    let _ = recv(&mut d1_link).await; // 初始空 MachineList 快照

    // machine 第一次连接：注册 + announce C1。
    let m1_link = WsRelayClient::connect(
        &ws_url(addr),
        &machine.credential,
        ClientRole::Machine {
            machine_id: machine.device_id.clone(),
        },
    )
    .await
    .expect("machine ws connect failed");
    m1_link
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-reg-1".into(),
            0,
            RelayControlMsg::RegisterMachine {
                machine: machine_descriptor("m1", "Machine One"),
            },
        ))
        .await;
    let after_reg1 = recv(&mut d1_link).await; // m1 上线广播
    assert!(matches!(
        after_reg1.msg,
        RelayControlMsg::MachineList { .. }
    ));
    m1_link
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-announce-1".into(),
            0,
            RelayControlMsg::AnnounceSession {
                session: session_descriptor("C1", "m1"),
            },
        ))
        .await;

    // 断线：drop 第一条 machine 连接，等待 d1 收到"m1 下线"广播——确认 Core
    // 已经处理完这次断连（同时也是下面重连广播的顺序屏障起点）。
    drop(m1_link);
    let after_disconnect = recv(&mut d1_link).await;
    assert!(matches!(
        after_disconnect.msg,
        RelayControlMsg::MachineList { .. }
    ));

    // machine 重连（同一 credential）：重新 announce 同一个 conversation_id，
    // 随后紧跟一条 RegisterMachine 作为屏障——Core 单任务串行消费同一条连接
    // 发来的消息，屏障广播到达即可断言前面的 AnnounceSession 已经落地。
    let m1_link2 = WsRelayClient::connect(
        &ws_url(addr),
        &machine.credential,
        ClientRole::Machine {
            machine_id: machine.device_id.clone(),
        },
    )
    .await
    .expect("machine ws reconnect failed");
    m1_link2
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-announce-2".into(),
            0,
            RelayControlMsg::AnnounceSession {
                session: session_descriptor("C1", "m1"),
            },
        ))
        .await;
    m1_link2
        .send(RemoteFrame::control(
            ClientRole::Machine {
                machine_id: machine.device_id.clone(),
            },
            "t-reg-2".into(),
            0,
            RelayControlMsg::RegisterMachine {
                machine: machine_descriptor("m1", "Machine One"),
            },
        ))
        .await;
    let barrier = recv(&mut d1_link).await; // m1 重新上线广播——第二次 AnnounceSession 已先于它处理完
    assert!(matches!(barrier.msg, RelayControlMsg::MachineList { .. }));

    d1_link
        .send(RemoteFrame::control(
            ClientRole::Device {
                device_id: device.device_id.clone(),
            },
            "t-sub-sessions".into(),
            0,
            RelayControlMsg::Subscribe {
                target: SubTarget::Sessions {
                    machine_id: "m1".into(),
                },
            },
        ))
        .await;
    loop {
        if let RelayControlMsg::SessionList { sessions, .. } = recv(&mut d1_link).await.msg {
            assert_eq!(
                sessions.len(),
                1,
                "断线重连后重新 AnnounceSession 同一 conversation_id 不应产生重复 session 条目: {sessions:?}"
            );
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// 测试 4（R1a 遗留 #9）: revoke 一个设备身份——① 活连接被断开 ② 同 credential
// 重新发起 WS 连接被拒。
//
// 设计说明（重要，写进 report）：产品代码里"撤销"目前是两条互不打通的路径：
// - `FakeRelay::revoke(device_id)`（Core 内部 API）：断开所有该 device_id 的
//   活连接（`CoreMsg::Revoke` → `handle_disconnect`）；只在持有对应 Core 的
//   `core_tx` 时才能触发，纯 in-process。
// - `server::revoke_device(store, device_id)`（本任务允许调用的最小包装）：
//   只落盘 `devices.revoked`，只在下一次 WS 握手时被 `server/ws.rs::connect`
//   读取拒绝；对已建立的活连接没有任何效果——它不知道、也无法触达任何活跃
//   Core 实例。
// `router.rs` 里 `FakeRelay::revoke` 的文档注释写着"Task 9 server 收到
// RelayStore 的 revoked 事件时调用"，暗示设计意图是两者应该被打通，但当前
// `server::revoke_device` 并未这样接线——这是本测试在编写过程中发现的一个
// 真实产品缺口，而不是测试设计的取舍问题。
//
// 在"不改动任何产品代码"的约束下，`serve_with_listener` 按值吃
// `relay: FakeRelay`（非 `Clone`、无 `core_tx` accessor），测试进程一旦把
// relay 交给真实 server 就再也拿不到同一个 Core 的句柄去调用 `.revoke()`。
// 因此本测试把两个断言分别接到各自最贴近产品代码的验证路径：
// ① 用另一个独立、纯 in-process 的 `FakeRelay`（真实 Core/router 代码，只是
//    不经真实 WS socket/axum）直接验证 `CoreMsg::Revoke` → 活连接被断开这条
//    Core 逻辑本身；WS 层收到 `link.recv()==None` 就关 socket 这段转发代码
//    已被其它测试覆盖，不是这里要验证的重点。
// ② 用真实 WS e2e server + `server::revoke_device`（SQL 落盘）验证"同一
//    credential 重连被拒"——这条是真正的真 WS + 真 SQLite 路径。
#[tokio::test]
async fn revoke_closes_active_connection_and_blocks_reconnect() {
    // ---- 断言①: revoke 断开活连接（纯 in-process Core，验证 CoreMsg::Revoke
    // 产品代码本身） ----
    let probe_store = SqliteRelayStore::open_in_memory().expect("in-memory sqlite open");
    let probe_relay = agentdeck_relay::FakeRelay::start_with_store(probe_store);
    let mut probe_link = probe_relay
        .connect(ClientRole::Device {
            device_id: "probe-dev".into(),
        })
        .await;
    probe_relay.revoke("probe-dev".to_string()).await;
    let after_revoke = tokio::time::timeout(RECV_TIMEOUT, probe_link.recv())
        .await
        .expect("timed out waiting for revoke to close the connection");
    assert!(
        after_revoke.is_none(),
        "revoke 后活连接的 recv() 必须返回 None（连接被断开），got {after_revoke:?}"
    );

    // ---- 断言②: 同 credential 重连被拒（真实 WS e2e server + SQL 落盘 revoke） ----
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("relay.db");
    let (addr, store, base_url, _handle) =
        setup_server_with_db("boot-secret-revoke", &db_path, 1000).await;

    let dev = enroll(
        &base_url,
        "boot-secret-revoke",
        "d-revoke",
        "device",
        Some("owner-revoke"),
    )
    .await;

    // revoke 前：凭据有效，正常连接成功。
    let link1 = WsRelayClient::connect(
        &ws_url(addr),
        &dev.credential,
        ClientRole::Device {
            device_id: dev.device_id.clone(),
        },
    )
    .await
    .expect("initial connect with a not-yet-revoked credential should succeed");
    drop(link1);

    agentdeck_relay::server::revoke_device(&store, &dev.device_id);

    match WsRelayClient::connect(
        &ws_url(addr),
        &dev.credential,
        ClientRole::Device {
            device_id: dev.device_id.clone(),
        },
    )
    .await
    {
        Err(WsError::Rejected { status, code }) => {
            assert_eq!(status, 401);
            assert_eq!(code.as_deref(), Some(failure::AUTH_REVOKED_DEVICE));
        }
        Ok(_) => panic!(
            "expected reconnection with a revoked credential to be rejected, but it connected"
        ),
        Err(other) => panic!("expected WsError::Rejected, got a different WsError: {other:?}"),
    }
}
