// agentdeck-relay/tests/r1a_ws_e2e.rs
//! R1a Task 10: 真 loopback WS 端到端集成测试（`server` feature 门内）。
//!
//! 覆盖 R1a 全部关键路径：REST challenge-response enroll、WS 握手鉴权（bad
//! secret / expired-reused nonce / unknown credential / revoked credential）、
//! 连接身份绑定（伪造 `from` 不生效、跨身份 RegisterMachine 被拒、非目标机器
//! AdminReply 被拒）、哨兵串日志脱敏。
//!
//! 每个测试独立起服务器（`127.0.0.1:0` 绑定后读回动态端口），每个 `recv` 均套
//! `tokio::time::timeout(5s)`，REST 用 `ureq`（阻塞）经 `spawn_blocking` 包裹以
//! 避免阻塞 tokio 运行时。
#![cfg(feature = "server")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::Duration;

use ed25519_dalek::Signer;
use serde_json::{Value, json};

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, DataEnvelope, MachineDescriptor, RelayControlMsg, RemoteFrame,
    SubTarget, failure,
};
use agentdeck_relay::RelayLink;
use agentdeck_relay::auth::store::InMemoryRelayStore;
use agentdeck_relay::config::RelayConfig;
use agentdeck_relay_client::{WsError, WsRelayClient};

const RECV_TIMEOUT: Duration = Duration::from_secs(5);

async fn recv<L: RelayLink>(link: &mut L) -> RemoteFrame {
    tokio::time::timeout(RECV_TIMEOUT, link.recv())
        .await
        .expect("timed out waiting for a frame")
        .expect("connection closed while waiting for a frame")
}

/// 起一个 server：`127.0.0.1:0` 绑定读回动态端口 + 共享 store 句柄（供测试直接
/// 驱动 revoke 场景）。返回的 `JoinHandle` 不需要显式等待——测试进程退出时
/// 自然回收；ephemeral 端口不会跨测试冲突。
async fn setup_server(bootstrap_secret: &str) -> (SocketAddr, Arc<Mutex<InMemoryRelayStore>>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig {
        bind: addr,
        bootstrap_secret: bootstrap_secret.to_string(),
        tls: None,
        allow_plaintext: true,
        log_level: "info".to_string(),
    };
    let store = Arc::new(Mutex::new(InMemoryRelayStore::default()));
    let relay = agentdeck_relay::FakeRelay::start();
    let store_for_server = store.clone();
    tokio::spawn(async move {
        agentdeck_relay::server::serve_with_listener(config, store_for_server, relay, listener)
            .await
    });
    let base_url = format!("http://{addr}");
    (addr, store, base_url)
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
        resp.into_json::<Value>().expect("challenge response not JSON")
    })
    .await
    .unwrap()
}

/// REST `POST /v1/pair/complete`（阻塞 ureq）。成功返回响应体 JSON；失败返回
/// `(http_status, error_body_json)`，让调用方按 `code` 断言而不 panic。
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
            Ok(resp) => Ok(resp.into_json::<Value>().expect("complete response not JSON")),
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
    account_id: String,
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
        account_id: resp["account_id"].as_str().unwrap().to_string(),
        device_id: resp["device_id"].as_str().unwrap().to_string(),
    }
}

fn ws_url(addr: SocketAddr) -> String {
    format!("ws://{addr}/v1/connect?v={}", agentdeck_protocol::remote::RELAY_PROTOCOL_VERSION)
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

/// 轮询 device 连接直到收到一条包含 `machine_id` 的 `MachineList`（消化订阅时
/// 可能先收到的空快照，避免与 RegisterMachine 广播之间的时序假设）。
async fn recv_machine_list_containing(link: &mut WsRelayClient, machine_id: &str) {
    tokio::time::timeout(RECV_TIMEOUT, async {
        loop {
            match link.recv().await.expect("connection closed").msg {
                RelayControlMsg::MachineList { machines } => {
                    if machines.iter().any(|m| m.machine_id == machine_id) {
                        return;
                    }
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("timed out waiting for MachineList containing the registered machine")
}

async fn recv_send_command_request_id(link: &mut WsRelayClient) -> String {
    loop {
        if let RelayControlMsg::SendCommand { request_id, .. } = recv(link).await.msg {
            return request_id;
        }
    }
}

async fn recv_error_code(link: &mut WsRelayClient) -> String {
    loop {
        if let RelayControlMsg::Error { code, .. } = recv(link).await.msg {
            return code;
        }
    }
}

// ---------------------------------------------------------------------------
// 测试 1: 正向路径——enroll machine+device（同 account）→ RegisterMachine →
// device Subscribe{Machines} 看到该 machine → SendCommand → machine 收到 →
// AdminReply → device 收到。
// ---------------------------------------------------------------------------
#[tokio::test]
async fn enroll_then_device_sees_machine_and_admin_ping() {
    let (addr, _store, base_url) = setup_server("boot-secret-1").await;

    let machine_enrolled = enroll(&base_url, "boot-secret-1", "m1", "machine", Some("owner-1")).await;
    let device_enrolled = enroll(&base_url, "boot-secret-1", "d1", "device", None).await;
    assert_eq!(
        device_enrolled.account_id, machine_enrolled.account_id,
        "同 bootstrap secret 加入的第二个设备必须落在同一个 singleton account"
    );

    let mut device_link = WsRelayClient::connect(
        &ws_url(addr),
        &device_enrolled.credential,
        ClientRole::Device { device_id: device_enrolled.device_id.clone() },
    )
    .await
    .expect("device ws connect failed");
    device_link
        .send(RemoteFrame::control(
            ClientRole::Device { device_id: device_enrolled.device_id.clone() },
            "t-sub".into(),
            0,
            RelayControlMsg::Subscribe { target: SubTarget::Machines },
        ))
        .await;

    let mut machine_link = WsRelayClient::connect(
        &ws_url(addr),
        &machine_enrolled.credential,
        ClientRole::Machine { machine_id: machine_enrolled.device_id.clone() },
    )
    .await
    .expect("machine ws connect failed");
    machine_link
        .send(RemoteFrame::control(
            ClientRole::Machine { machine_id: machine_enrolled.device_id.clone() },
            "t-reg".into(),
            0,
            RelayControlMsg::RegisterMachine { machine: machine_descriptor("m1", "Machine One") },
        ))
        .await;

    recv_machine_list_containing(&mut device_link, "m1").await;

    device_link
        .send(RemoteFrame::control(
            ClientRole::Device { device_id: device_enrolled.device_id.clone() },
            "t-cmd".into(),
            0,
            RelayControlMsg::SendCommand {
                request_id: "r1".into(),
                target: CommandTarget::Machine { machine_id: "m1".into() },
                data: DataEnvelope::plaintext(&"ping-cmd").unwrap(),
            },
        ))
        .await;

    let at_machine = recv_send_command_request_id(&mut machine_link).await;
    assert_eq!(at_machine, "r1");

    machine_link
        .send(RemoteFrame::control(
            ClientRole::Machine { machine_id: "m1".into() },
            "t-reply".into(),
            0,
            RelayControlMsg::AdminReply {
                in_reply_to: "r1".into(),
                data: DataEnvelope::plaintext(&"pong-reply").unwrap(),
            },
        ))
        .await;

    loop {
        match recv(&mut device_link).await.msg {
            RelayControlMsg::AdminReply { in_reply_to, data } => {
                assert_eq!(in_reply_to, "r1");
                let payload: String = data.decode_plaintext().unwrap();
                assert_eq!(payload, "pong-reply");
                break;
            }
            RelayControlMsg::CommandDelivered { .. } => continue,
            other => panic!("unexpected frame while waiting for AdminReply: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 测试 2: 负向鉴权——bad secret / expired(重用) nonce / unknown credential /
// revoked credential 均被拒。
// ---------------------------------------------------------------------------
#[tokio::test]
async fn rejects_bad_secret_expired_nonce_revoked_and_unknown_cred() {
    let (addr, store, base_url) = setup_server("boot-secret-2").await;

    // 1) 错 bootstrap secret → 4xx + PAIR_BAD_SECRET
    {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sign_pub = b64(sk.verifying_key().as_bytes());
        let ch = challenge(&base_url, &sign_pub).await;
        let nonce = ch["nonce"].as_str().unwrap().to_string();
        let sig = b64(&sk.sign(nonce.as_bytes()).to_bytes());
        let (status, body) = complete(
            &base_url,
            "WRONG-SECRET",
            &sig,
            "bad-secret-dev",
            "device",
            &sign_pub,
            "box",
            Some("owner-x"),
        )
        .await
        .expect_err("expected bad-secret complete to fail");
        assert!((400..500).contains(&status), "expected 4xx, got {status}");
        assert_eq!(body["code"], failure::PAIR_BAD_SECRET);
    }

    // 2) 过期/重用 nonce：成功 complete 一次后，同一 nonce_sig 再 complete 一次
    // （已消费 = expired 语义），无需真等待 TTL 过期。
    {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sign_pub = b64(sk.verifying_key().as_bytes());
        let ch = challenge(&base_url, &sign_pub).await;
        let nonce = ch["nonce"].as_str().unwrap().to_string();
        let sig = b64(&sk.sign(nonce.as_bytes()).to_bytes());
        complete(
            &base_url,
            "boot-secret-2",
            &sig,
            "reuse-dev",
            "device",
            &sign_pub,
            "box",
            Some("owner-y"),
        )
        .await
        .expect("first complete with a fresh nonce should succeed");
        let (status, body) = complete(
            &base_url,
            "boot-secret-2",
            &sig,
            "reuse-dev",
            "device",
            &sign_pub,
            "box",
            Some("owner-y"),
        )
        .await
        .expect_err("expected reused nonce complete to fail");
        assert!((400..500).contains(&status), "expected 4xx, got {status}");
        assert_eq!(body["code"], failure::PAIR_CHALLENGE_EXPIRED);
    }

    // 3) 未知 credential → WS 连接被拒——R1b Task 1 起 relay-client 能精确解析
    // 握手期 HTTP 4xx（`WsError::Rejected{status,code}`），不再折叠成泛化 Err。
    {
        let result = WsRelayClient::connect(
            &ws_url(addr),
            "totally-unknown-credential",
            ClientRole::Device { device_id: "ghost".into() },
        )
        .await;
        match result {
            Err(WsError::Rejected { status, code }) => {
                assert_eq!(status, 401, "unknown credential must be rejected with 401");
                assert_eq!(code.as_deref(), Some(failure::AUTH_INVALID_DEVICE));
            }
            Ok(_) => panic!("expected ws connect with unknown credential to be rejected, but it succeeded"),
            Err(other) => panic!("expected WsError::Rejected{{401, AUTH_INVALID_DEVICE}}, got {other}"),
        }
    }

    // 4) revoked credential → 先 enroll 成功，再直接标记撤销，随后同凭据连接被拒
    {
        let enrolled = enroll(&base_url, "boot-secret-2", "to-revoke", "device", Some("owner-z")).await;
        agentdeck_relay::server::revoke_device(&store, &enrolled.device_id);
        let result = WsRelayClient::connect(
            &ws_url(addr),
            &enrolled.credential,
            ClientRole::Device { device_id: enrolled.device_id.clone() },
        )
        .await;
        match result {
            Err(WsError::Rejected { status, code }) => {
                assert_eq!(status, 401, "revoked credential must be rejected with 401");
                assert_eq!(code.as_deref(), Some(failure::AUTH_REVOKED_DEVICE));
            }
            Ok(_) => panic!("expected ws connect with a revoked credential to be rejected, but it succeeded"),
            Err(other) => panic!("expected WsError::Rejected{{401, AUTH_REVOKED_DEVICE}}, got {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 测试 3: 身份绑定——伪造 `from` 不生效、跨身份 RegisterMachine 被拒、非目标
// 机器抢答 AdminReply 被拒。
// ---------------------------------------------------------------------------
#[tokio::test]
async fn forged_from_and_cross_identity_and_nontarget_reply_rejected() {
    let (addr, _store, base_url) = setup_server("boot-secret-3").await;

    let device = enroll(&base_url, "boot-secret-3", "d1", "device", Some("owner-3")).await;
    let m1 = enroll(&base_url, "boot-secret-3", "m1", "machine", None).await;
    let m2 = enroll(&base_url, "boot-secret-3", "m2", "machine", None).await;

    // --- 伪造 from：device 连接却在帧里自称 Machine{machine_id: "fake"} ---
    let mut device_link = WsRelayClient::connect(
        &ws_url(addr),
        &device.credential,
        ClientRole::Device { device_id: device.device_id.clone() },
    )
    .await
    .expect("device connect failed");
    device_link
        .send(RemoteFrame::control(
            ClientRole::Machine { machine_id: "fake".into() },
            "t-forge".into(),
            0,
            RelayControlMsg::RegisterMachine { machine: machine_descriptor("fake", "Fake Machine") },
        ))
        .await;
    let code = recv_error_code(&mut device_link).await;
    assert_eq!(
        code,
        failure::MACHINE_IDENTITY_CONFLICT,
        "relay 必须按连接身份（Device）拒绝，伪造的 from=Machine 不应生效"
    );

    // --- 跨身份 RegisterMachine：m2 的连接身份只授权 machine_id=m2，却尝试注册 m1 ---
    let mut m1_link = WsRelayClient::connect(
        &ws_url(addr),
        &m1.credential,
        ClientRole::Machine { machine_id: m1.device_id.clone() },
    )
    .await
    .expect("m1 connect failed");
    m1_link
        .send(RemoteFrame::control(
            ClientRole::Machine { machine_id: "m1".into() },
            "t-reg-m1".into(),
            0,
            RelayControlMsg::RegisterMachine { machine: machine_descriptor("m1", "Machine One") },
        ))
        .await;

    let mut m2_link = WsRelayClient::connect(
        &ws_url(addr),
        &m2.credential,
        ClientRole::Machine { machine_id: m2.device_id.clone() },
    )
    .await
    .expect("m2 connect failed");
    m2_link
        .send(RemoteFrame::control(
            ClientRole::Machine { machine_id: "m1".into() },
            "t-cross".into(),
            0,
            RelayControlMsg::RegisterMachine { machine: machine_descriptor("m1", "Hijacked") },
        ))
        .await;
    let code = recv_error_code(&mut m2_link).await;
    assert_eq!(code, failure::MACHINE_IDENTITY_CONFLICT);

    // --- 非目标机器抢答 AdminReply：device SendCommand 指向 m1，m2 冒充回复 ---
    device_link
        .send(RemoteFrame::control(
            ClientRole::Device { device_id: device.device_id.clone() },
            "t-cmd".into(),
            0,
            RelayControlMsg::SendCommand {
                request_id: "r-x".into(),
                target: CommandTarget::Machine { machine_id: "m1".into() },
                data: DataEnvelope::plaintext(&"ping").unwrap(),
            },
        ))
        .await;
    let at_m1 = recv_send_command_request_id(&mut m1_link).await;
    assert_eq!(at_m1, "r-x");

    m2_link
        .send(RemoteFrame::control(
            ClientRole::Machine { machine_id: "m1".into() },
            "t-nontarget".into(),
            0,
            RelayControlMsg::AdminReply {
                in_reply_to: "r-x".into(),
                data: DataEnvelope::plaintext(&"forged-reply").unwrap(),
            },
        ))
        .await;
    let code = recv_error_code(&mut m2_link).await;
    assert_eq!(code, failure::REPLY_UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// 测试 4: 哨兵串日志脱敏——bootstrap secret / credential / payload 均不得出现
// 在 tracing 日志输出里。
// ---------------------------------------------------------------------------
static LOG_BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
static LOG_INIT: Once = Once::new();

#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 全局 tracing subscriber 只 init 一次（`tracing_subscriber::fmt().init()` 是
/// process-global 的；本测试文件内其它测试不断言日志内容，共用同一个 subscriber
/// 不影响它们的正确性）。返回捕获 buffer 的共享句柄。
fn init_log_capture() -> Arc<Mutex<Vec<u8>>> {
    let buf = LOG_BUF.get_or_init(|| Arc::new(Mutex::new(Vec::new()))).clone();
    LOG_INIT.call_once(|| {
        let writer_buf = buf.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || BufWriter(writer_buf.clone()))
            .init();
    });
    buf
}

#[tokio::test]
async fn sentinel_token_not_in_logs() {
    let buf = init_log_capture();

    const SENTINEL_BOOTSTRAP: &str = "SENTINEL_BOOTSTRAP_XXXX";
    const SENTINEL_PAYLOAD: &str = "SENTINEL_PAYLOAD_YYYY";

    let (addr, _store, base_url) = setup_server(SENTINEL_BOOTSTRAP).await;
    let enrolled = enroll(&base_url, SENTINEL_BOOTSTRAP, "sentinel-dev", "device", Some("owner-s")).await;

    let mut link = WsRelayClient::connect(
        &ws_url(addr),
        &enrolled.credential,
        ClientRole::Device { device_id: enrolled.device_id.clone() },
    )
    .await
    .expect("connect failed");
    link.send(RemoteFrame::control(
        ClientRole::Device { device_id: enrolled.device_id.clone() },
        "t-sentinel".into(),
        0,
        RelayControlMsg::SendCommand {
            request_id: "r-sentinel".into(),
            target: CommandTarget::Machine { machine_id: "no-such-machine".into() },
            data: DataEnvelope::plaintext(&SENTINEL_PAYLOAD).unwrap(),
        },
    ))
    .await;
    // 消化 relay 对该命令的响应（未知目标 → Error），确保帧已被服务端处理完毕
    // 才去检查日志，而不是引入任意 sleep。
    let _ = recv_error_code(&mut link).await;

    // review fix（Critical）：happy-path 流程（enroll + 一次 SendCommand/Error）
    // 全程不经过 `agentdeck-relay/src` 里任何一处 `tracing::*!` 调用点——唯一的
    // instrumentation 是 `server/conn.rs` 里的 `info!("relay: connection closed")`
    // （连接 loop 退出时才打）。之前的写法在这里直接读 buffer，如果 buffer 为空，
    // 三条 sentinel/credential 断言全部对空字符串成立——测试假绿，测不出真正的
    // 日志泄漏。显式 drop 连接触发 close 分支，给 server 端一点时间处理关闭，
    // 再断言 buffer 非空，让"这条测试真的 exercise 了 tracing 路径"本身可验证。
    drop(link);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let captured = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    assert!(!captured.is_empty(), "tracing buffer 为空——log capture 未生效，测试无效");
    assert!(!captured.contains(SENTINEL_BOOTSTRAP), "bootstrap secret leaked into logs");
    assert!(!captured.contains(SENTINEL_PAYLOAD), "opaque payload leaked into logs");
    assert!(!captured.contains(&enrolled.credential), "issued credential leaked into logs");
    // 注：`device_id` 会出现在 `info!(device_id, "relay: connection closed")`
    // 里——这是设计上允许的（identifier 而非 secret，R1a 脱敏语义与 Task 2
    // `AuthContext::Bearer` Debug 一致：保留 device_id、脱敏 token），因此本测试
    // 不对 device_id 做"不得出现"断言。
}

/// review fix（Important）：Task 10 前四个测试覆盖了 bad_secret / expired_nonce /
/// revoked / unknown_cred / cross_identity / forged_from / non_target_reply 等
/// 拒绝路径，但未测 `server/ws.rs::connect` 里 `version != RELAY_PROTOCOL_VERSION
/// → reject(BAD_REQUEST, VERSION_UNSUPPORTED)` 分支。补一条握手带 `?v=999` 的
/// WS 连接。R1b Task 1 起 `WsRelayClient` 能精确解析握手期 HTTP 4xx
/// （`WsError::Rejected{status,code}`，不再折叠成泛化 `WsError::Connect`——Task 7
/// review 遗留在本 task 收编），断言升级到具体 `400 + VERSION_UNSUPPORTED`。
#[tokio::test]
async fn ws_connect_rejects_wrong_protocol_version() {
    let (addr, _store, base_url) = setup_server("boot-version").await;
    let enrolled = enroll(
        &base_url,
        "boot-version",
        "dev-version",
        "device",
        Some("owner-version"),
    )
    .await;

    let bad_url = format!("ws://{addr}/v1/connect?v=999");
    let result = WsRelayClient::connect(
        &bad_url,
        &enrolled.credential,
        ClientRole::Device { device_id: enrolled.device_id.clone() },
    )
    .await;
    match result {
        Err(WsError::Rejected { status, code }) => {
            assert_eq!(status, 400, "unsupported protocol version must be rejected with 400");
            assert_eq!(code.as_deref(), Some(failure::VERSION_UNSUPPORTED));
        }
        Ok(_) => panic!("expected ws connect with unsupported protocol version to be rejected, but it succeeded"),
        Err(other) => panic!("expected WsError::Rejected{{400, VERSION_UNSUPPORTED}}, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// 测试 6（`tls` feature 门内）：`--tls-cert/--tls-key` 真正接通
// `axum-server` + `rustls` 的 TLS 终结（whole-branch review Critical #1
// fix）——REST enroll 走一个明文兄弟监听拿到真实凭据（REST handler 与传输层
// 无关，明文/TLS 复用同一份 `pair::challenge`/`pair::complete`，这里选明文只是
// 避免连 `ureq` 也要去信任测试自签证书），随后用同一个共享 `store` 另起一个
// TLS 监听，验证 WS 握手在真 TLS 终结下依然成立。
//
// **不**经 `agentdeck_relay_client::WsRelayClient`——它 R1a 只支持 `ws://`
// （Task 7 遗留，wss 客户端支持留给 R1b，brief 明确不许为此测试改它的
// 签名）；这里手写 wss:// 直连：`tokio-tungstenite` + 自定义
// `rustls::client::danger::ServerCertVerifier`（只信任测试自签证书、不校验
// 证书链——测试专用，生产客户端不会用这个 verifier）。
// ---------------------------------------------------------------------------
#[cfg(feature = "tls")]
mod tls_e2e {
    use super::*;
    use std::sync::Arc;

    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
    use tokio_tungstenite::{Connector, connect_async_tls_with_config};

    /// 一次性生成的测试自签证书（`openssl req -x509 -newkey ed25519 ...`，
    /// `CN=127.0.0.1`，10 年有效期）——只用于本测试信任链，不代表任何生产
    /// 证书材料。key 文件权限特意放宽到 0644（仓库内测试 fixture，不是真机密）。
    const TEST_CERT_PEM: &[u8] = include_bytes!("fixtures/test_cert.pem");
    const TEST_KEY_PEM: &[u8] = include_bytes!("fixtures/test_key.pem");

    /// 只信任任意证书、跳过证书链校验的 rustls verifier——**仅供本测试**验证
    /// "TLS 握手本身能否成功"，不代表生产客户端的证书信任策略（生产 wss
    /// 客户端支持连同真实证书校验一起留给 R1b）。
    #[derive(Debug)]
    struct AcceptAnyCert;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::CryptoProvider::get_default()
                .map(|p| p.signature_verification_algorithms.supported_schemes())
                .unwrap_or_default()
        }
    }

    /// 本测试进程里同时编译了 `aws-lc-rs`（rustls 默认）与 `ring`
    /// （`tokio-tungstenite` 的 `rustls-tls-native-roots` feature 传递引入）
    /// 两个 rustls crypto provider，rustls 无法自动二选一——首次构造任何
    /// `ServerConfig`/`ClientConfig` 前必须显式 `install_default()`，否则
    /// panic（"Could not automatically determine the process-level
    /// CryptoProvider"）。`Once` 保证多个 `#[tokio::test]` 并发跑本测试文件时
    /// 只装一次；只在这个 TLS 专属子模块调用，不影响其余 5 个不碰 rustls 的
    /// 明文测试。
    fn ensure_crypto_provider_installed() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[tokio::test]
    async fn wss_connect_over_tls() {
        ensure_crypto_provider_installed();

        // 1) 明文兄弟监听：真实 REST challenge/complete enroll 一个 device 凭据。
        let (_plain_addr, store, base_url) = setup_server("boot-tls").await;
        let enrolled =
            enroll(&base_url, "boot-tls", "dev-tls", "device", Some("owner-tls")).await;

        // 2) 用同一个共享 store（已含刚 enroll 的凭据）另起一个 TLS 监听。
        let tls_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
            TEST_CERT_PEM.to_vec(),
            TEST_KEY_PEM.to_vec(),
        )
        .await
        .expect("测试 fixture 自签证书/私钥必须能装载");
        let config = RelayConfig {
            bind: tls_addr,
            bootstrap_secret: "boot-tls".to_string(),
            // `serve_with_listener_tls` 不读 `config.tls`（cert/key 已经作为
            // `tls_config` 参数单独传入）——这里留 `None` 避免误导性地暗示
            // 这两个占位路径会被读取。
            tls: None,
            allow_plaintext: true,
            log_level: "info".to_string(),
        };
        let relay = agentdeck_relay::FakeRelay::start();
        tokio::spawn(agentdeck_relay::server::serve_with_listener_tls(
            config,
            store,
            relay,
            tls_listener,
            tls_config,
        ));

        // 3) 手写 wss:// 直连：自定义 Authorization header + 信任测试自签
        //    证书的 rustls ClientConfig。
        let url = format!(
            "wss://{tls_addr}/v1/connect?v={}",
            agentdeck_protocol::remote::RELAY_PROTOCOL_VERSION
        );
        let mut request = url.into_client_request().expect("valid ws url");
        request.headers_mut().insert(
            AUTHORIZATION,
            format!("Bearer {}", enrolled.credential).parse().unwrap(),
        );

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        let connector = Connector::Rustls(Arc::new(client_config));

        let result = tokio::time::timeout(
            RECV_TIMEOUT,
            connect_async_tls_with_config(request, None, false, Some(connector)),
        )
        .await
        .expect("wss 握手超时");

        assert!(
            result.is_ok(),
            "wss:// 直连必须握手成功——TLS 终结（axum-server + rustls）已真正接通: {:?}",
            result.err().map(|e| e.to_string())
        );
    }
}
