// agentdeck-cli/src/remote.rs
//! `agentdeck remote <op>` — Relay CLI 命令面。
//!
//! `smoke` 是 R0 单进程冒烟：内存 `FakeRelay` + 一个真实 `agentdeckd` 子进程
//! （经 `StdioMachineBridge` 接入），再驱动一个内存 device 客户端，证明
//! machines 快照订阅 + 机器级 admin（Ping）往返可以端到端跑通，且都经过
//! relay 的控制面路由（非直连 daemon）。
//!
//! R1a 起，`pair` 经 REST（`/v1/pair/challenge` + `/v1/pair/complete`）向一个
//! 真联网 relay 注册本机身份并把凭据写入本地文件；`machines/sessions/watch/
//! send/ping/approve/deny` 读回凭据、经 `WsRelayClient` 连接同一 relay 的
//! `/v1/connect` 执行真实往返，取代 R0 的接口基线占位。

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::Signer;
use rand::RngCore;

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, DataEnvelope, DeviceDescriptor, DeviceKind, MachineDescriptor,
    RelayControlMsg, RemoteFrame, SubTarget,
};
use agentdeck_protocol::{ActionDecision, ActionDecisionKind, ClientCommand, SessionId};
use agentdeck_relay::{FakeRelay, RelayClient, RelayLink, StdioMachineBridge};
use agentdeck_relay_client::{WsError, WsRelayClient};

use crate::transport::locate_daemon;

/// admin 往返等待每帧超时——避免 relay/daemon 卡死时 smoke/ping 永久挂起。
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
    run_smoke(&daemon, profile).await
}

/// `smoke` 的可注入驱动：接受调用方定位好的 `daemon` 路径，跑完整条
/// FakeRelay + StdioMachineBridge + device 客户端 冒烟路径。拆出来是为了让
/// 单测能绕开 `locate_daemon()`（其 current_exe sibling 探测在
/// `cargo test` 的 `target/debug/deps/` cwd 下不命中真实二进制所在的
/// workspace 根 `target/debug/`），改用稳健路径注入，而不改变 `smoke`
/// 本身对外的行为。
pub async fn run_smoke(daemon: &std::path::Path, profile: &str) -> ExitCode {
    let relay = FakeRelay::start();
    let link = relay
        .connect(ClientRole::Machine {
            machine_id: "local".into(),
        })
        .await;
    let bridge = match StdioMachineBridge::spawn(daemon, profile, machine(), link).await {
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
            eprintln!(
                "remote.smoke.timeout: 等待 machines 快照超时（{ADMIN_REPLY_FRAME_TIMEOUT:?}）"
            );
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
            Err(_) => return false,   // 超时：不再重试，快速失败
        }
    }
    false
}

// ── 凭据文件 ──────────────────────────────────────────────────────────────────

/// `pair` 落盘、`machines/sessions/watch/send/ping` 读取的凭据 schema。
/// 字段名与形态视为对外稳定（用户可能手工检查/备份此文件）。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct RelayCredentials {
    pub relay_url: String,
    pub account_id: String,
    pub device_id: String,
    /// enrollment 一次性返回的明文 credential（bearer token）；不再重新签发。
    pub credential: String,
    /// `"machine"` 或 `"device"`——存 `String` 而非 enum，凭据文件是长期存在
    /// 的外部 schema，`String` 对未来新增角色向前兼容，不需要跟着改文件格式。
    pub role: String,
}

/// `--role` 的逻辑层类型（`main.rs` 的 `RoleArg` 是 clap 派生的镜像）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairRole {
    Machine,
    Device,
}

impl PairRole {
    fn as_wire(self) -> &'static str {
        match self {
            PairRole::Machine => "machine",
            PairRole::Device => "device",
        }
    }
}

/// `pair`/凭据 IO 的失败原因。message 里绝不包含 credential/bootstrap secret
/// 明文（只报状态码/错误 code，不回显请求体）。
#[derive(thiserror::Error, Debug)]
pub enum PairError {
    #[error("relay http request failed: {0}")]
    Http(String),
    #[error("malformed relay response (missing expected field)")]
    MalformedResp,
    #[error("failed to persist credentials: {0}")]
    Io(String),
    /// 凭据文件里的 `role` 字段既不是 `"machine"` 也不是 `"device"`——多半是凭据
    /// 文件被手工改坏，或未来新增角色但本 CLI 版本还不认识。绝不静默 fallback
    /// 到某个角色继续跑（那会让请求带着错误身份连上 relay）。
    #[error("unrecognized credential role {0:?} (expected \"machine\" or \"device\")")]
    InvalidRole(String),
}

/// 凭据文件路径：`<data_dir>/relay/<profile>.credentials.json`。profile 作为
/// 文件名前缀而非固定的 `relay/credentials.json`，因为一个 CLI 用户可能对
/// 多个 relay 各用一个 profile（例如 `stable` 连生产 relay，`dev` 连自建）。
fn creds_path(data_dir: Option<&str>, profile: &str) -> PathBuf {
    let base = match data_dir {
        Some(d) => PathBuf::from(d),
        None => default_data_dir(),
    };
    base.join("relay")
        .join(format!("{profile}.credentials.json"))
}

#[cfg(target_os = "macos")]
fn default_data_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join("Library/Application Support/AgentDeck")
}

#[cfg(not(target_os = "macos"))]
fn default_data_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/share/agentdeck")
}

fn write_creds(path: &Path, creds: &RelayCredentials) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(creds)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn read_creds(path: &Path) -> std::io::Result<RelayCredentials> {
    let s = std::fs::read_to_string(path)?;
    serde_json::from_str(&s).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ── pair（REST enroll）──────────────────────────────────────────────────────

/// `ws://` → `http://`、`wss://` → `https://`；其它 scheme（已是 http(s) 或
/// 其它）原样保留——REST enroll 端点与 WS `/v1/connect` 共享同一 relay
/// host:port，只是 scheme 不同。
fn to_http_url(relay_url: &str) -> String {
    if let Some(rest) = relay_url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = relay_url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        relay_url.to_string()
    }
}

/// 8 位随机十六进制后缀——只用于凑一个够唯一的本地生成 id（`device_id`/
/// `request_id`），不是安全凭据，不需要密码学级别的抗碰撞强度。
fn short_random_suffix() -> String {
    let mut buf = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn post_json(url: &str, body: serde_json::Value) -> Result<serde_json::Value, PairError> {
    match ureq::post(url).send_json(body) {
        Ok(resp) => resp
            .into_json::<serde_json::Value>()
            .map_err(|e| PairError::Http(e.to_string())),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp
                .into_json::<serde_json::Value>()
                .unwrap_or(serde_json::Value::Null);
            let msg = body
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            Err(PairError::Http(format!("HTTP {code}: {msg}")))
        }
        Err(ureq::Error::Transport(t)) => Err(PairError::Http(t.to_string())),
    }
}

/// 用 CLI 自己生成的 ed25519（签名）/x25519（box，R1a 只登记 pubkey，实际
/// 加密留 R1c）密钥对，走 challenge-response REST enroll，把 relay 签发的
/// 一次性明文 credential 落盘。不依赖 relay 内部 crypto 模块——保持 CLI 与
/// relay 解耦（CLI 树里不出现 `auth::crypto`）。
pub async fn pair(
    relay_url: &str,
    bootstrap_secret: &str,
    role: PairRole,
    profile: &str,
    data_dir: Option<&str>,
) -> Result<RelayCredentials, PairError> {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let sign_pub_b64 = B64.encode(sk.verifying_key().as_bytes());

    let box_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let box_pub = x25519_dalek::PublicKey::from(&box_sk);
    let box_pub_b64 = B64.encode(box_pub.as_bytes());

    // 首个 device 兼当 owner（R1a singleton account 语义）；machine 角色不
    // 提供 owner_pubkey——它总是加入已存在（或由某个 device 先创建）的账户。
    let owner_pubkey = matches!(role, PairRole::Device).then(|| sign_pub_b64.clone());

    let http_url = to_http_url(relay_url);

    let challenge_url = format!("{http_url}/v1/pair/challenge");
    let challenge_body = serde_json::json!({ "device_sign_pubkey": sign_pub_b64 });
    let challenge = tokio::task::spawn_blocking(move || post_json(&challenge_url, challenge_body))
        .await
        .map_err(|e| PairError::Http(format!("challenge task panicked: {e}")))??;
    let nonce = challenge["nonce"]
        .as_str()
        .ok_or(PairError::MalformedResp)?
        .to_string();

    let sig_b64 = B64.encode(sk.sign(nonce.as_bytes()).to_bytes());
    let device_id = format!("cli-{profile}-{}", short_random_suffix());
    let complete_url = format!("{http_url}/v1/pair/complete");
    let complete_body = serde_json::json!({
        "bootstrap_secret": bootstrap_secret,
        "nonce_sig": sig_b64,
        "device": {
            "device_id": device_id,
            "role": role.as_wire(),
            "sign_pubkey": sign_pub_b64,
            "box_pubkey": box_pub_b64,
        },
        "owner_pubkey": owner_pubkey,
    });
    let resp = tokio::task::spawn_blocking(move || post_json(&complete_url, complete_body))
        .await
        .map_err(|e| PairError::Http(format!("complete task panicked: {e}")))??;

    let creds = RelayCredentials {
        relay_url: relay_url.to_string(),
        account_id: resp["account_id"]
            .as_str()
            .ok_or(PairError::MalformedResp)?
            .to_string(),
        device_id: resp["device_id"]
            .as_str()
            .ok_or(PairError::MalformedResp)?
            .to_string(),
        credential: resp["credential"]
            .as_str()
            .ok_or(PairError::MalformedResp)?
            .to_string(),
        role: role.as_wire().to_string(),
    };

    write_creds(&creds_path(data_dir, profile), &creds)
        .map_err(|e| PairError::Io(e.to_string()))?;
    Ok(creds)
}

// ── 已配对 op 的执行（machines/sessions/watch/send/ping）─────────────────────

/// 凭据文件里 `role: String` 字段到 wire `ClientRole` 的映射——未识别的字符串
/// 直接报错，绝不静默 fallback 到某个角色（那会让请求带着错误身份连上
/// relay，且现象是"莫名其妙的权限/授权失败"而不是清楚的报错）。
fn role_for(creds: &RelayCredentials) -> Result<ClientRole, PairError> {
    match creds.role.as_str() {
        "machine" => Ok(ClientRole::Machine {
            machine_id: creds.device_id.clone(),
        }),
        "device" => Ok(ClientRole::Device {
            device_id: creds.device_id.clone(),
        }),
        other => Err(PairError::InvalidRole(other.to_string())),
    }
}

async fn connect_device(
    creds: &RelayCredentials,
    role: ClientRole,
) -> Result<WsRelayClient, WsError> {
    let ws_url = format!(
        "{}/v1/connect?v={}",
        creds.relay_url,
        agentdeck_protocol::remote::RELAY_PROTOCOL_VERSION
    );
    WsRelayClient::connect(&ws_url, &creds.credential, role).await
}

/// 读凭据文件失败时打印统一的提示（先跑 `pair`）并返回失败退出码。
fn load_creds(profile: &str, data_dir: Option<&str>) -> Result<RelayCredentials, ExitCode> {
    read_creds(&creds_path(data_dir, profile)).map_err(|e| {
        eprintln!(
            "remote: 读取凭据失败——先跑 `agentdeck remote pair --relay <url> --bootstrap-secret <secret>`（{e}）"
        );
        ExitCode::FAILURE
    })
}

/// `--relay` 只作为一致性提示：凭据在 `pair` 时已经与具体 relay 账户绑定，
/// 本次连接始终用凭据文件里记录的 `relay_url`，不会跨 relay 复用凭据。
fn warn_relay_mismatch(requested: &str, stored: &str) {
    if requested != stored {
        eprintln!(
            "remote: 提示——`--relay {requested}` 与凭据文件记录的 `{stored}` 不一致；本次仍使用凭据文件绑定的 relay。"
        );
    }
}

/// `wait_admin_reply` 的 `RelayLink` 泛型版本——`smoke`/`run_smoke` 专用的
/// 原函数只接受内存 `RelayClient`，这里独立一份供 `ping` 经 `WsRelayClient`
/// 复用同样的“轮询直到关联 request_id 的 AdminReply”逻辑，不改动前者。
async fn wait_admin_reply_link<L: RelayLink>(d: &mut L, want: &str) -> bool {
    for _ in 0..64 {
        match tokio::time::timeout(ADMIN_REPLY_FRAME_TIMEOUT, d.recv()).await {
            Ok(Some(frame)) => {
                if let RelayControlMsg::AdminReply { in_reply_to, data } = frame.msg {
                    if in_reply_to == want {
                        let v: serde_json::Value = data.decode_plaintext().unwrap_or_default();
                        println!("[ping] admin reply: {v}");
                        return v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
                    }
                }
            }
            Ok(None) => return false,
            Err(_) => return false,
        }
    }
    false
}

async fn cmd_machines(relay: &str, profile: &str, data_dir: Option<&str>) -> ExitCode {
    let creds = match load_creds(profile, data_dir) {
        Ok(c) => c,
        Err(code) => return code,
    };
    warn_relay_mismatch(relay, &creds.relay_url);
    let role = match role_for(&creds) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("remote.machines: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut link = match connect_device(&creds, role.clone()).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("remote.machines: connect 失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    link.send(RemoteFrame::control(
        role,
        "cli-machines".into(),
        0,
        RelayControlMsg::Subscribe {
            target: SubTarget::Machines,
        },
    ))
    .await;
    match tokio::time::timeout(ADMIN_REPLY_FRAME_TIMEOUT, link.recv()).await {
        Ok(Some(frame)) => match frame.msg {
            RelayControlMsg::MachineList { machines } => {
                println!("{}", serde_json::to_string_pretty(&machines).unwrap());
                ExitCode::SUCCESS
            }
            other => {
                eprintln!("remote.machines: unexpected frame: {other:?}");
                ExitCode::FAILURE
            }
        },
        Ok(None) => {
            eprintln!("remote.machines: 连接已关闭");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("remote.machines: 等待 MachineList 超时");
            ExitCode::FAILURE
        }
    }
}

async fn cmd_sessions(
    relay: &str,
    machine_id: &str,
    profile: &str,
    data_dir: Option<&str>,
) -> ExitCode {
    let creds = match load_creds(profile, data_dir) {
        Ok(c) => c,
        Err(code) => return code,
    };
    warn_relay_mismatch(relay, &creds.relay_url);
    let role = match role_for(&creds) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("remote.sessions: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut link = match connect_device(&creds, role.clone()).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("remote.sessions: connect 失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    link.send(RemoteFrame::control(
        role,
        "cli-sessions".into(),
        0,
        RelayControlMsg::Subscribe {
            target: SubTarget::Sessions {
                machine_id: machine_id.to_string(),
            },
        },
    ))
    .await;
    match tokio::time::timeout(ADMIN_REPLY_FRAME_TIMEOUT, link.recv()).await {
        Ok(Some(frame)) => match frame.msg {
            RelayControlMsg::SessionList {
                machine_id,
                sessions,
            } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "machineId": machine_id,
                        "sessions": sessions,
                    }))
                    .unwrap()
                );
                ExitCode::SUCCESS
            }
            other => {
                eprintln!("remote.sessions: unexpected frame: {other:?}");
                ExitCode::FAILURE
            }
        },
        Ok(None) => {
            eprintln!("remote.sessions: 连接已关闭");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("remote.sessions: 等待 SessionList 超时");
            ExitCode::FAILURE
        }
    }
}

/// 持续打印某 conversation 的 `Event` 帧，直到连接关闭（Ctrl-C 中断进程）。
async fn cmd_watch(
    relay: &str,
    conversation_id: &str,
    profile: &str,
    data_dir: Option<&str>,
) -> ExitCode {
    let creds = match load_creds(profile, data_dir) {
        Ok(c) => c,
        Err(code) => return code,
    };
    warn_relay_mismatch(relay, &creds.relay_url);
    let role = match role_for(&creds) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("remote.watch: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut link = match connect_device(&creds, role.clone()).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("remote.watch: connect 失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    link.send(RemoteFrame::control(
        role,
        "cli-watch".into(),
        0,
        RelayControlMsg::Subscribe {
            target: SubTarget::Events {
                conversation_id: conversation_id.to_string(),
                since_seq: None,
            },
        },
    ))
    .await;
    loop {
        match link.recv().await {
            Some(frame) => match frame.msg {
                RelayControlMsg::Event {
                    conversation_id,
                    turn_session_id,
                    seq,
                    data,
                } => {
                    let payload: serde_json::Value =
                        data.decode_plaintext().unwrap_or(serde_json::Value::Null);
                    println!(
                        "{}",
                        serde_json::to_string(&serde_json::json!({
                            "conversationId": conversation_id,
                            "turnSessionId": turn_session_id,
                            "seq": seq,
                            "data": payload,
                        }))
                        .unwrap()
                    );
                }
                other => eprintln!("remote.watch: 非 Event 帧: {other:?}"),
            },
            None => {
                eprintln!("remote.watch: 连接已关闭");
                return ExitCode::SUCCESS;
            }
        }
    }
}

/// 向 conversation 发一段文本；R1a 还没有真实机器侧的“接收会话文本”实现，
/// 这里只发一个通用 `{"text": ...}` 明文 envelope 并等待 relay 的
/// `CommandDelivered` 送达确认（而非业务层回复——业务语义留给未来接住这条
/// 命令的真实 machine 适配器定义）。
async fn cmd_send(
    relay: &str,
    conversation_id: &str,
    text: &str,
    profile: &str,
    data_dir: Option<&str>,
) -> ExitCode {
    let creds = match load_creds(profile, data_dir) {
        Ok(c) => c,
        Err(code) => return code,
    };
    warn_relay_mismatch(relay, &creds.relay_url);
    let role = match role_for(&creds) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("remote.send: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut link = match connect_device(&creds, role.clone()).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("remote.send: connect 失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    let request_id = format!("cli-send-{}", short_random_suffix());
    let data = match DataEnvelope::plaintext(&serde_json::json!({ "text": text })) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("remote.send: 编码消息失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    link.send(RemoteFrame::control(
        role,
        "cli-send".into(),
        0,
        RelayControlMsg::SendCommand {
            request_id: request_id.clone(),
            target: CommandTarget::Conversation {
                conversation_id: conversation_id.to_string(),
            },
            data,
        },
    ))
    .await;
    match tokio::time::timeout(ADMIN_REPLY_FRAME_TIMEOUT, link.recv()).await {
        Ok(Some(frame)) => match frame.msg {
            RelayControlMsg::CommandDelivered { request_id: rid } if rid == request_id => {
                println!("[send] delivered request_id={request_id}");
                ExitCode::SUCCESS
            }
            RelayControlMsg::Error { code, message, .. } => {
                eprintln!("remote.send: relay error {code}: {message}");
                ExitCode::FAILURE
            }
            other => {
                eprintln!("remote.send: unexpected frame: {other:?}");
                ExitCode::FAILURE
            }
        },
        Ok(None) => {
            eprintln!("remote.send: 连接已关闭");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("remote.send: 等待送达确认超时");
            ExitCode::FAILURE
        }
    }
}

async fn cmd_ping(
    relay: &str,
    machine_id: &str,
    profile: &str,
    data_dir: Option<&str>,
) -> ExitCode {
    let creds = match load_creds(profile, data_dir) {
        Ok(c) => c,
        Err(code) => return code,
    };
    warn_relay_mismatch(relay, &creds.relay_url);
    let role = match role_for(&creds) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("remote.ping: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut link = match connect_device(&creds, role.clone()).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("remote.ping: connect 失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    let request_id = format!("cli-ping-{}", short_random_suffix());
    let data = match DataEnvelope::plaintext(&ClientCommand::Ping) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("remote.ping: 编码 Ping 命令失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    link.send(RemoteFrame::control(
        role,
        "cli-ping".into(),
        0,
        RelayControlMsg::SendCommand {
            request_id: request_id.clone(),
            target: CommandTarget::Machine {
                machine_id: machine_id.to_string(),
            },
            data,
        },
    ))
    .await;
    if wait_admin_reply_link(&mut link, &request_id).await {
        println!("[ping] {machine_id} round-trip OK");
        ExitCode::SUCCESS
    } else {
        eprintln!("[ping] {machine_id} round-trip FAILED");
        ExitCode::FAILURE
    }
}

/// `approve`/`deny` 共用实现：批准/拒绝是同一条 `ClientCommand::ActionDecision`
/// 命令（`session_id` = turn_session_id、`decision.request_id` = 审批请求的
/// request_id），只有 `ActionDecisionKind` 不同——`CommandTarget::Turn` +
/// `SendCommand` 是通用命令通道，relay 层不需要专门的 approve/deny 帧类型。
/// 命令是会话级（非 admin），daemon 侧立即处理、不产生 `AdminReply`；这里只
/// 等 relay 自身的 `CommandDelivered` 送达确认，不代表业务层已消费。
async fn cmd_approve_deny(
    relay: &str,
    turn_session_id: &str,
    request_id: &str,
    decision: ActionDecisionKind,
    profile: &str,
    data_dir: Option<&str>,
) -> ExitCode {
    let creds = match load_creds(profile, data_dir) {
        Ok(c) => c,
        Err(code) => return code,
    };
    warn_relay_mismatch(relay, &creds.relay_url);
    let role = match role_for(&creds) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("remote.decision: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut link = match connect_device(&creds, role.clone()).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("remote.decision: connect 失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cmd = ClientCommand::ActionDecision {
        session_id: SessionId(turn_session_id.to_string()),
        decision: ActionDecision {
            request_id: request_id.to_string(),
            decision,
            persist: false,
        },
    };
    let data = match DataEnvelope::plaintext(&cmd) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("remote.decision: 编码 ActionDecision 失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cmd_request_id = format!("cli-decision-{}", short_random_suffix());
    link.send(RemoteFrame::control(
        role,
        "cli-decision".into(),
        0,
        RelayControlMsg::SendCommand {
            request_id: cmd_request_id.clone(),
            target: CommandTarget::Turn {
                turn_session_id: turn_session_id.to_string(),
            },
            data,
        },
    ))
    .await;
    match tokio::time::timeout(ADMIN_REPLY_FRAME_TIMEOUT, link.recv()).await {
        Ok(Some(frame)) => match frame.msg {
            RelayControlMsg::CommandDelivered { request_id: rid } if rid == cmd_request_id => {
                println!("[decision] delivered request_id={request_id}");
                ExitCode::SUCCESS
            }
            RelayControlMsg::Error { code, message, .. } => {
                eprintln!("remote.decision: relay error {code}: {message}");
                ExitCode::FAILURE
            }
            other => {
                eprintln!("remote.decision: unexpected frame: {other:?}");
                ExitCode::FAILURE
            }
        },
        Ok(None) => {
            eprintln!("remote.decision: 连接已关闭");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("remote.decision: 等待送达确认超时");
            ExitCode::FAILURE
        }
    }
}

pub async fn run(op: RemoteOpArg, profile: &str, data_dir: Option<&str>) -> ExitCode {
    match op {
        RemoteOpArg::Smoke => smoke(profile).await,
        RemoteOpArg::Pair {
            relay,
            bootstrap_secret,
            role,
        } => {
            match pair(&relay, &bootstrap_secret, role, profile, data_dir).await {
                Ok(creds) => {
                    // 明文 bearer credential 只落盘（0600 权限保护），绝不打到
                    // stdout/日志——这里只打印人类可读的、不敏感的确认信息。
                    println!("pair ok:");
                    println!("  saved: {}", creds_path(data_dir, profile).display());
                    println!("  account: {}", creds.account_id);
                    println!("  device: {}", creds.device_id);
                    println!("  role: {}", creds.role);
                    println!("  relay: {}", creds.relay_url);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("remote.pair: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        RemoteOpArg::Machines { relay } => cmd_machines(&relay, profile, data_dir).await,
        RemoteOpArg::Sessions { relay, machine_id } => {
            cmd_sessions(&relay, &machine_id, profile, data_dir).await
        }
        RemoteOpArg::Watch {
            relay,
            conversation_id,
        } => cmd_watch(&relay, &conversation_id, profile, data_dir).await,
        RemoteOpArg::Send {
            relay,
            conversation_id,
            text,
        } => cmd_send(&relay, &conversation_id, &text, profile, data_dir).await,
        RemoteOpArg::Approve {
            relay,
            turn_session_id,
            request_id,
        } => {
            cmd_approve_deny(
                &relay,
                &turn_session_id,
                &request_id,
                ActionDecisionKind::Approve,
                profile,
                data_dir,
            )
            .await
        }
        RemoteOpArg::Deny {
            relay,
            turn_session_id,
            request_id,
        } => {
            cmd_approve_deny(
                &relay,
                &turn_session_id,
                &request_id,
                ActionDecisionKind::Deny,
                profile,
                data_dir,
            )
            .await
        }
        RemoteOpArg::Ping { relay, machine_id } => {
            cmd_ping(&relay, &machine_id, profile, data_dir).await
        }
    }
}

/// main.rs 的 `RemoteOp`（clap 类型）到本模块的窄化映射：携带各子命令真正
/// 需要的参数，避免 clap 派生类型泄漏进 remote 的逻辑层。
pub enum RemoteOpArg {
    Smoke,
    Pair {
        relay: String,
        bootstrap_secret: String,
        role: PairRole,
    },
    Machines {
        relay: String,
    },
    Sessions {
        relay: String,
        machine_id: String,
    },
    Watch {
        relay: String,
        conversation_id: String,
    },
    Send {
        relay: String,
        conversation_id: String,
        text: String,
    },
    Approve {
        relay: String,
        turn_session_id: String,
        request_id: String,
    },
    Deny {
        relay: String,
        turn_session_id: String,
        request_id: String,
    },
    Ping {
        relay: String,
        machine_id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn smoke_pings_real_daemon_through_relay() {
        // `cargo test -p agentdeck-cli` 的测试二进制在 workspace 根
        // `target/debug/deps/` 下运行、cwd = 包目录，`locate_daemon()`
        // 的 current_exe sibling 探测与 cwd 相对回退都不命中——真实
        // `agentdeckd` 二进制在 workspace 根 `target/{debug,release}/`
        // 下，不是 `agentdeck-cli/target/...`。因此这里不经
        // `locate_daemon()`，改用 `CARGO_MANIFEST_DIR`（=
        // `.../agentdeck-cli`，其父目录即 workspace 根）稳健定位，
        // 只有真未构建才 skip；已构建时真正跑通 `run_smoke` 的完整
        // relay 路径。
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let candidates = [
            root.join("target/debug/agentdeckd"),
            root.join("target/release/agentdeckd"),
        ];
        let Some(daemon) = candidates.iter().find(|p| p.exists()) else {
            eprintln!(
                "skip: agentdeckd 未构建（在 workspace 根 target/{{debug,release}} 均未找到）"
            );
            return;
        };
        let code = run_smoke(daemon, "stable").await;
        assert_eq!(code, ExitCode::SUCCESS);
    }

    // ── Task 11: creds_path / round-trip / to_http_url ──────────────────────

    #[test]
    fn creds_path_is_deterministic_for_same_inputs() {
        let p1 = creds_path(Some("/tmp/agentdeck-test-dir"), "stable");
        let p2 = creds_path(Some("/tmp/agentdeck-test-dir"), "stable");
        assert_eq!(p1, p2);
        assert!(p1.ends_with("relay/stable.credentials.json"));
    }

    #[test]
    fn creds_path_differs_by_profile_and_data_dir() {
        let a = creds_path(Some("/tmp/agentdeck-test-dir"), "stable");
        let b = creds_path(Some("/tmp/agentdeck-test-dir"), "dev");
        assert_ne!(a, b, "不同 profile 必须落到不同凭据文件");
        let c = creds_path(Some("/tmp/agentdeck-other-dir"), "stable");
        assert_ne!(a, c, "不同 data_dir 必须落到不同凭据文件");
    }

    fn sample_creds() -> RelayCredentials {
        RelayCredentials {
            relay_url: "ws://127.0.0.1:9999".into(),
            account_id: "acc-1".into(),
            device_id: "cli-stable-abcd1234".into(),
            credential: "sekrit-one-time-credential".into(),
            role: "device".into(),
        }
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agentdeck-cli-test-{tag}-{}", std::process::id()))
    }

    #[test]
    fn write_then_read_creds_round_trips() {
        let dir = scratch_dir("roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("relay").join("stable.credentials.json");
        let creds = sample_creds();

        write_creds(&path, &creds).expect("write_creds should succeed");
        let back = read_creds(&path).expect("read_creds should succeed");
        assert_eq!(back, creds);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_creds_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("perms");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("relay").join("stable.credentials.json");
        write_creds(&path, &sample_creds()).expect("write_creds should succeed");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "credentials file must be owner-read/write only"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn to_http_url_maps_ws_schemes_and_leaves_others() {
        assert_eq!(to_http_url("ws://127.0.0.1:8443"), "http://127.0.0.1:8443");
        assert_eq!(
            to_http_url("wss://relay.example.com"),
            "https://relay.example.com"
        );
        assert_eq!(to_http_url("http://already-http"), "http://already-http");
        assert_eq!(
            to_http_url("https://already-https"),
            "https://already-https"
        );
    }
}
