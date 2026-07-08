# Relay R1a（传输 + 鉴权骨架）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 R0 的进程内 FakeRelay 连接换成真 WebSocket（`agentdeck-relay` binary + `agentdeck-relay-client` crate），并落地连接鉴权（Bearer + 服务端派生角色 + account scope + 运营者 bootstrap 的 challenge-response enroll），R0 Core 路由逻辑复用。

**Architecture:** `agentdeck-relay` 从 lib 升级为 lib+binary：axum WS 服务端（`server` feature 后）+ REST enroll + per-conn reader/writer task 喂 R0 Core（Core 加连接身份 + `try_send` HOL 防阻 + handle_frame 授权）。新 `agentdeck-relay-client` crate 提供 `WsRelayClient`（实现 `agentdeck-relay::RelayLink`）+ `InProcRelayClient`。CLI 加 `remote pair`/`--relay`，bridge 改收 `impl RelayLink`。net/axum 严限 relay 的 `server` feature + client crate；daemon 与 CLI 不含 axum。

**Tech Stack:** Rust edition 2024、axum 0.8、tokio-tungstenite 0.26、rustls 0.23/tokio-rustls 0.26（可选 feature）、ed25519-dalek 2 / x25519-dalek 2（rand_core 0.6）、sha2 0.10、rand 0.8、base64 0.22、tracing 0.1 / tracing-subscriber 0.3、dotenvy 0.15、clap 4、serde/serde_json。

设计依据：`docs/plans/2026-07-08-relay-r1a-transport-auth-design.md`（R1a 设计）+ `docs/plans/2026-07-08-relay-r1-design-review.md` §8（决策）。

## Global Constraints

- Rust edition **2024**；新 crate `version.workspace = true` 等继承根 `[workspace.package]`；根无 `[workspace.dependencies]`，各 crate 自声明版本。
- **依赖钉版对齐（避免冲突）**：`thiserror = "1"`（仓库锁 1.0.69，勿引 2.x）；`schemars = "=0.8.22"`；**`rand = "0.8"` + `rand_core = "0.6"`**（ed25519-dalek/x25519-dalek 2.x 绑 rand_core 0.6，引 rand 0.9 会 trait 版本错配编译失败）；serde `"1"`、serde_json `"1"`、uuid `"1"`。
- **net/axum 隔离**：tokio `net` 与 axum 只出现在 `agentdeck-relay` 的 **`server` feature** 后 + `agentdeck-relay-client`。**`agentdeckd` 不依赖 relay 任何 crate、保持无 net**；`agentdeck-cli` 依赖 `agentdeck-relay`（默认无 `server`）+ `agentdeck-relay-client`，**不含 axum**。CI guard 断言 `agentdeckd` 依赖树无 tokio net。
- **依赖方向**：`RelayLink` trait 在 `agentdeck-relay`；`agentdeck-relay-client → agentdeck-relay`（单向无环）。
- 线格式：`DataEnvelope` 字节字段 **base64**；一条 `RemoteFrame` = 一条 WS **text** 帧；`RELAY_PROTOCOL_VERSION` **0→1** + 握手版本协商；`trace_id` 边缘生成、relay 不覆写。
- 鉴权：账户 Ed25519；运营者 bootstrap secret；challenge-response（CSPRNG nonce + TTL + 单次原子消费）；device credential 256-bit 不透明 token **存哈希（sha2）**；**R1a 单账户 singleton**（首次 enroll 建 root account，后续 enroll 凭 bootstrap secret 加入同一 account、不新建）；配对**一次登记 sign+box 双公钥**（box 休眠至 R1c）；machine+device 两侧都 enroll。
- **传输安全门禁**：默认 `--bind 127.0.0.1` 允明文 ws；**非 loopback 绑定必须配 TLS（wss），否则拒绝启动**（`relay.config.plaintext_non_loopback`），除非显式 `--allow-plaintext`（响亮告警）。
- **N6 不动**：不实现 remote `Transport`（用 mpsc/WS）、不削弱 trait 形状；`transport_trait_remote_ready.rs` 保持绿。
- **日志脱敏**：`DataEnvelope`/`AuthContext` 自定义脱敏 Debug；relay 只记控制面元数据；哨兵-token 日志脱敏测试。
- 提交不加 co-author；在 master 直接提交、未经请求不推送；schema 改动后 `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` 重生成快照。

## 文件结构（决策锁定）

```text
agentdeck-protocol/src/remote/{data.rs, mod.rs}   # 改：DataEnvelope base64；RELAY_PROTOCOL_VERSION→1
agentdeck-protocol/src/remote/failure.rs          # 新：类型化失败码常量注册表
agentdeck-protocol/src/transport.rs               # 改：AuthContext 脱敏 Debug
agentdeck-protocol/src/lib.rs                      # 改：挂 failure；schema 快照
agentdeck-relay/src/relay_link.rs                 # 新：RelayLink trait（RelayClient 实现它）
agentdeck-relay/src/router.rs                      # 改：CoreMsg::Connect 带 identity；send_to try_send；handle_frame 授权
agentdeck-relay/src/auth/{mod.rs, store.rs, enroll.rs, crypto.rs}  # 新：身份模型 + RelayStore + enroll + 密码学
agentdeck-relay/src/server/{mod.rs, ws.rs, pair.rs, conn.rs}       # 新（server feature）：axum WS + REST enroll + per-conn task
agentdeck-relay/src/config.rs                      # 新：配置 + TLS 门禁
agentdeck-relay/src/main.rs                        # 新：binary + --selfcheck（server feature）
agentdeck-relay/src/bridge.rs                      # 改：spawn 收 impl RelayLink
agentdeck-relay/Cargo.toml                         # 改：deps + server feature + [[bin]]
agentdeck-relay/tests/r1a_ws_e2e.rs                # 新：真 WS 端到端 + 鉴权 + 脱敏（server feature）
agentdeck-relay-client/{Cargo.toml, src/{lib.rs, ws.rs, inproc.rs}}  # 新 crate
agentdeck-cli/src/{main.rs, remote.rs}             # 改：--relay + pair + 接线 baseline_stub + creds 文件
agentdeck-cli/Cargo.toml                            # 改：加 agentdeck-relay-client + directories(或复用 data_dir)
Cargo.toml                                          # 改：members 加 agentdeck-relay-client
scripts/                                            # 新：daemon-no-net guard
```

---

### Task 1: 协议 DataEnvelope base64 + RELAY_PROTOCOL_VERSION 升 1

**Files:**
- Modify: `agentdeck-protocol/src/remote/data.rs`
- Modify: `agentdeck-protocol/src/remote/mod.rs`（`RELAY_PROTOCOL_VERSION: u16 = 1`）
- Modify: `agentdeck-protocol/Cargo.toml`（加 `base64 = "0.22"`）
- Modify: `protocol/agentdeck/agentdeck-protocol.schema.json`（回写）

**Interfaces:**
- Produces：`DataEnvelope`（wire 上 `bytes` 为 base64 字符串而非 uint8 数组）；`RELAY_PROTOCOL_VERSION == 1`。`plaintext`/`decode_plaintext` 签名不变。

- [ ] **Step 1: 写失败测试（wire 为 base64 字符串）**

在 `agentdeck-protocol/src/remote/data.rs` 底部加：
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plaintext_bytes_serialize_as_base64_string() {
        let env = DataEnvelope::Plaintext { agentdeck_protocol_version: 2, bytes: vec![0xDE, 0xAD, 0xBE, 0xEF] };
        let v = serde_json::to_value(&env).unwrap();
        // bytes 必须是 base64 字符串，不是 JSON 数字数组
        assert_eq!(v["bytes"], serde_json::json!("3q2+7w=="));
        let back: DataEnvelope = serde_json::from_value(v).unwrap();
        assert_eq!(back, env);
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-protocol plaintext_bytes_serialize_as_base64_string`
Expected: FAIL（当前 `bytes` 序列化为 `[222,173,190,239]` 数组，不等于 `"3q2+7w=="`）。

- [ ] **Step 3: 给 bytes 加 base64 serde**

`agentdeck-protocol/Cargo.toml` `[dependencies]` 加 `base64 = "0.22"`。改 `data.rs` 的 `Plaintext.bytes` 字段：
```rust
    Plaintext {
        #[serde(rename = "agentdeckProtocolVersion")]
        agentdeck_protocol_version: u32,
        #[serde(with = "crate::remote::data::b64")]
        bytes: Vec<u8>,
    },
```
并在 `data.rs` 加 base64 serde 模块（schemars 把 `Vec<u8>` 仍视为 string 需手动标注 schema——用 `#[schemars(with = "String")]` 保证 schema 为 string）：
```rust
    Plaintext {
        #[serde(rename = "agentdeckProtocolVersion")]
        agentdeck_protocol_version: u32,
        #[serde(with = "b64")]
        #[schemars(with = "String")]
        bytes: Vec<u8>,
    },
```
```rust
mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}
```
改 `mod.rs`：`pub const RELAY_PROTOCOL_VERSION: u16 = 1;`（注释更新为「R1a：首个联网 wire-stable 版本」）。

- [ ] **Step 4: 跑测试确认通过 + 回写 schema**

Run: `cargo test -p agentdeck-protocol plaintext_bytes_serialize_as_base64_string`
Expected: PASS。
Run: `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`（回写：DataEnvelope.bytes 变 `"type":"string"`）。
Run: `cargo test -p agentdeck-protocol`（全绿，含 remote 往返/中立性/schema 不漂）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-protocol/src/remote/data.rs agentdeck-protocol/src/remote/mod.rs agentdeck-protocol/Cargo.toml protocol/agentdeck/agentdeck-protocol.schema.json
git commit -m "feat(protocol): DataEnvelope 字节改 base64 wire；RELAY_PROTOCOL_VERSION 0→1（R1a）"
```

---

### Task 2: 协议类型化失败码注册表 + AuthContext 脱敏 Debug

**Files:**
- Create: `agentdeck-protocol/src/remote/failure.rs`
- Modify: `agentdeck-protocol/src/remote/mod.rs`（`pub mod failure;` + re-export）
- Modify: `agentdeck-protocol/src/transport.rs`（`AuthContext` 自定义脱敏 `Debug`）

**Interfaces:**
- Produces：`agentdeck_protocol::remote::failure::*` 失败码常量（`&'static str`）；`AuthContext` 的 `Debug` 不再打印 token/device_id 明文。

- [ ] **Step 1: 写失败测试（AuthContext Debug 不泄漏 token）**

在 `transport.rs` 底部加：
```rust
#[cfg(test)]
mod redact_tests {
    use super::*;
    #[test]
    fn auth_context_debug_redacts_token() {
        let a = AuthContext::Bearer { token: "SECRET-TOKEN-123".into(), device_id: "dev-1".into() };
        let s = format!("{a:?}");
        assert!(!s.contains("SECRET-TOKEN-123"), "token must be redacted in Debug: {s}");
        assert!(s.contains("Bearer"), "should still show variant");
    }
}
```

- [ ] **Step 2: 跑确认失败**

Run: `cargo test -p agentdeck-protocol auth_context_debug_redacts_token`
Expected: FAIL（现 `#[derive(Debug)]` 会打印明文 token）。

- [ ] **Step 3: 实现脱敏 Debug + 失败码注册表**

`transport.rs`：把 `AuthContext` 的 `#[derive(Debug, ...)]` 去掉 `Debug`，改手写：
```rust
#[derive(Clone, Serialize, Deserialize)]
pub enum AuthContext {
    Anonymous,
    Bearer { token: String, device_id: String },
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthContext::Anonymous => write!(f, "AuthContext::Anonymous"),
            AuthContext::Bearer { device_id, .. } => {
                // token 脱敏，device_id 保留用于诊断
                write!(f, "AuthContext::Bearer {{ token: <redacted>, device_id: {device_id:?} }}")
            }
        }
    }
}
```
新建 `agentdeck-protocol/src/remote/failure.rs`：
```rust
//! Relay/remote 失败码注册表（类型化常量，取代散落裸字符串）。
//! wire 上仍是 `RelayControlMsg::Error.code: String`；这些常量是产生/匹配的唯一来源。

// relay.auth.*
pub const AUTH_INVALID_DEVICE: &str = "relay.auth.invalid_device";
pub const AUTH_REVOKED_DEVICE: &str = "relay.auth.revoked_device";
pub const AUTH_FORBIDDEN: &str = "relay.auth.forbidden";
// relay.pair.*
pub const PAIR_BAD_SECRET: &str = "relay.pair.bad_secret";
pub const PAIR_CHALLENGE_EXPIRED: &str = "relay.pair.challenge_expired";
pub const PAIR_BAD_SIGNATURE: &str = "relay.pair.bad_signature";
// relay.*
pub const VERSION_UNSUPPORTED: &str = "relay.version.unsupported";
pub const MACHINE_IDENTITY_CONFLICT: &str = "relay.machine.identity_conflict";
pub const REPLY_UNAUTHORIZED: &str = "relay.reply.unauthorized";
pub const CONN_OVERFLOW: &str = "relay.conn.overflow";
pub const FRAME_TOO_LARGE: &str = "relay.frame.too_large";
pub const CONFIG_PLAINTEXT_NON_LOOPBACK: &str = "relay.config.plaintext_non_loopback";
// remote.* (R0 复用)
pub const REMOTE_SESSION_NOT_FOUND: &str = "remote.session.not_found";
```
`mod.rs` 加 `pub mod failure;`。

- [ ] **Step 4: 跑通过**

Run: `cargo test -p agentdeck-protocol auth_context_debug_redacts_token`
Expected: PASS。
Run: `cargo test -p agentdeck-protocol`（全绿；failure 常量无 schema 影响——它们不是 wire 类型）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-protocol/src/remote/failure.rs agentdeck-protocol/src/remote/mod.rs agentdeck-protocol/src/transport.rs
git commit -m "feat(protocol): 类型化 relay 失败码注册表 + AuthContext 脱敏 Debug"
```

---

### Task 3: `RelayLink` trait + RelayClient 实现 + bridge 泛型化

**Files:**
- Create: `agentdeck-relay/src/relay_link.rs`
- Modify: `agentdeck-relay/src/lib.rs`（`mod relay_link; pub use relay_link::RelayLink;`）
- Modify: `agentdeck-relay/src/router.rs`（`impl RelayLink for RelayClient`）
- Modify: `agentdeck-relay/src/bridge.rs`（`spawn` 收 `impl RelayLink` 而非 `&FakeRelay`）

**Interfaces:**
- Produces：
  - `agentdeck_relay::RelayLink`：`#[async_trait] pub trait RelayLink: Send + 'static { async fn send(&self, frame: RemoteFrame); async fn recv(&mut self) -> Option<RemoteFrame>; }`
  - `RelayClient: RelayLink`。
  - `StdioMachineBridge::spawn(daemon_path: &Path, profile: &str, machine: MachineDescriptor, link: impl RelayLink) -> io::Result<StdioMachineBridge>`（不再依赖 `FakeRelay` 具体类型）。
- Consumes：R0 `RelayClient`（`send(&self)`/`recv(&mut self)`）、`RemoteFrame`。

- [ ] **Step 1: 写 relay_link.rs**

```rust
// agentdeck-relay/src/relay_link.rs
use agentdeck_protocol::remote::RemoteFrame;

/// 客户端连接抽象（RemoteFrame 类型）。内存 `RelayClient` 与 R1a 的 `WsRelayClient`
/// 都实现它，bridge/CLI 依赖 trait 而非具体传输——切换零逻辑改。
#[async_trait::async_trait]
pub trait RelayLink: Send + 'static {
    async fn send(&self, frame: RemoteFrame);
    async fn recv(&mut self) -> Option<RemoteFrame>;
}
```
`agentdeck-relay/Cargo.toml` 确认有 `async-trait`（若无则加 `async-trait = "0.1"`；协议 crate 已用）。`lib.rs` 加 `mod relay_link; pub use relay_link::RelayLink;`。

- [ ] **Step 2: RelayClient 实现 RelayLink**

`router.rs`（`RelayClient` 定义处附近）加。注意：trait 方法与 inherent 方法同名，用**全路径 inherent 调用**避免递归：
```rust
#[async_trait::async_trait]
impl crate::relay_link::RelayLink for RelayClient {
    async fn send(&self, frame: RemoteFrame) {
        RelayClient::send(self, frame).await
    }
    async fn recv(&mut self) -> Option<RemoteFrame> {
        RelayClient::recv(self).await
    }
}
```

- [ ] **Step 3: bridge 泛型化**

`bridge.rs`：
- 删 `use crate::router::{FakeRelay, RelayClient};` 中对 `FakeRelay`/`RelayClient` 的具体依赖，改 `use crate::relay_link::RelayLink;`。
- `spawn` 签名改：
```rust
pub async fn spawn(
    daemon_path: &Path,
    profile: &str,
    machine: MachineDescriptor,
    link: impl RelayLink,
) -> std::io::Result<StdioMachineBridge> {
```
- 内部：删掉 `let client = relay.connect(ClientRole::Machine{..}).await;`（连接现由调用方建好并作为 `link` 传入）；把原 `client` 全部替换为 `link`（`link.send(...).await`、pump 里 `let mut client = link;` → 直接 `let mut link = link;` 并 `link.recv()`）。RegisterMachine 首帧仍由 bridge 发（`link.send(mk_frame(&machine_id, RegisterMachine{machine})).await`）。

- [ ] **Step 4: 改 in-proc 调用点（保编译）**

`agentdeck-cli/src/remote.rs` 的 `run_smoke`：把 `StdioMachineBridge::spawn(daemon, profile, machine(), &relay).await` 改为先 `let link = relay.connect(ClientRole::Machine { machine_id: "local".into() }).await;` 再 `StdioMachineBridge::spawn(daemon, profile, machine(), link).await`。
`agentdeckd/tests/relay_r0_bridge.rs` 同步改（`let link = relay.connect(ClientRole::Machine{machine_id:"M1".into()}).await;` 传入）。

- [ ] **Step 5: 跑测试（R0 链路不回归）**

Run: `cargo build -p agentdeckd && cargo test -p agentdeck-relay && cargo test -p agentdeckd --test relay_r0_bridge && cargo test -p agentdeck-cli remote::`
Expected: 全绿（RelayClient 经 RelayLink 驱动，T1/T2/T3 + smoke 不回归）。0 warning。

- [ ] **Step 6: Commit**

```bash
git add agentdeck-relay/src/relay_link.rs agentdeck-relay/src/lib.rs agentdeck-relay/src/router.rs agentdeck-relay/src/bridge.rs agentdeck-cli/src/remote.rs agentdeckd/tests/relay_r0_bridge.rs
git commit -m "feat(relay): RelayLink trait（RelayClient 实现）+ bridge 泛型化收 impl RelayLink，消除对 FakeRelay 的具体耦合"
```

---

### Task 4: Core 连接身份 + `try_send` HOL 防阻

**Files:**
- Modify: `agentdeck-relay/src/router.rs`

**Interfaces:**
- Produces：`ConnIdentity { account_id: String, device_id: String, role: ConnRole }`（`ConnRole { Machine{machine_id}, Device }`，pub）；`FakeRelay::connect_with_identity(identity: ConnIdentity) -> RelayClient`（R0 `connect(role)` 保留为「匿名 dev 身份」便捷包装，供内存测试）；`CoreMsg::Connect` 携带 `identity`；`Conn` 携带 `identity`；`send_to` 用 `try_send`。
- Consumes：Task 3 的 RelayClient/RelayLink。

- [ ] **Step 1: 写失败测试（慢消费者不阻塞 Core）**

在 `router.rs` 的 `#[cfg(test)] mod tests` 加：
```rust
    #[tokio::test]
    async fn slow_consumer_does_not_block_other_connections() {
        let relay = FakeRelay::start();
        // D_slow 订阅 machines 但从不 recv（模拟慢/卡死连接）
        let _d_slow = relay.connect(ClientRole::Device { device_id: "slow".into() }).await;
        _d_slow.send(frame(ClientRole::Device { device_id: "slow".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Machines })).await;
        // 灌满 D_slow 的出站队列（>64）：注册很多机器触发广播
        for i in 0..200 {
            let m = relay.connect(ClientRole::Machine { machine_id: format!("M{i}") }).await;
            m.send(frame(ClientRole::Machine { machine_id: format!("M{i}") },
                RelayControlMsg::RegisterMachine { machine: machine(&format!("M{i}")) })).await;
        }
        // 新 device 订阅仍能及时拿到快照（Core 未被 D_slow 卡死）
        let mut d = relay.connect(ClientRole::Device { device_id: "fast".into() }).await;
        d.send(frame(ClientRole::Device { device_id: "fast".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Machines })).await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), d.recv()).await
            .expect("Core 被慢连接阻塞了（HOL）").expect("frame");
        assert!(matches!(got.msg, RelayControlMsg::MachineList { .. }));
    }
```
（`machine(&str)` 辅助改成接受 id 参数：`fn machine(id: &str) -> MachineDescriptor {...machine_id: id.into()...}`。）

- [ ] **Step 2: 跑确认失败（或挂起→timeout 失败）**

Run: `cargo test -p agentdeck-relay slow_consumer_does_not_block_other_connections`
Expected: FAIL（`send_to` 的 `conn.out.send(frame).await` 在 D_slow 队列满后阻塞整个 Core loop，fast device 拿不到 MachineList → 5s timeout panic）。

- [ ] **Step 3: 加连接身份类型 + try_send 溢出**

`router.rs`：
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnRole { Machine { machine_id: String }, Device }

#[derive(Debug, Clone)]
pub struct ConnIdentity {
    pub account_id: String,
    pub device_id: String,
    pub role: ConnRole,
}
```
`Conn` 加字段 `identity: ConnIdentity` + `lagged: bool`（去掉 `#[allow(dead_code)]`，`role: ClientRole` 可保留用于 from 校验或改为从 identity 派生）。`CoreMsg::Connect` 加 `identity: ConnIdentity`。`connect` 拆两个入口：
```rust
pub async fn connect(&self, role: ClientRole) -> RelayClient {
    // 便捷入口（内存测试/匿名 dev）：合成一个 dev-scope 身份
    let identity = ConnIdentity {
        account_id: "dev".into(),
        device_id: match &role { ClientRole::Device { device_id } => device_id.clone(),
            ClientRole::Machine { machine_id } => machine_id.clone(), ClientRole::Relay => "relay".into() },
        role: match &role { ClientRole::Machine { machine_id } => ConnRole::Machine { machine_id: machine_id.clone() },
            _ => ConnRole::Device },
    };
    self.connect_with_identity(identity).await
}

pub async fn connect_with_identity(&self, identity: ConnIdentity) -> RelayClient {
    // 原 connect 主体，改为把 identity 放进 CoreMsg::Connect
    ...
}
```
`Core::run` 的 Connect 分支：`self.conns.insert(id, Conn { identity, role: /*保留或省*/, out, lagged: false });`。
`send_to` 改 try_send + 溢出：
```rust
async fn send_to(&mut self, id: ClientId, trace_id: &str, msg: RelayControlMsg) {
    let is_control = matches!(msg,
        RelayControlMsg::AdminReply { .. } | RelayControlMsg::CommandDelivered { .. }
        | RelayControlMsg::Error { .. } | RelayControlMsg::MachineList { .. }
        | RelayControlMsg::SessionList { .. });
    if let Some(conn) = self.conns.get_mut(&id) {
        let frame = RemoteFrame::control(ClientRole::Relay, trace_id.to_string(), 0, msg);
        match conn.out.try_send(frame) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                if is_control {
                    // 控制/回执满 → 该连接不可用，断开（下轮 Disconnect 清理）
                    self.disconnect_conns.push(id);
                } else {
                    conn.lagged = true; // 事件丢帧，标记 lagged（R1b 加重放补齐）
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.disconnect_conns.push(id);
            }
        }
    }
}
```
`send_to` 现在需要 `&mut self`——把所有调用处的 `self.send_to(...)` 保持（`handle_frame` 已是 `&mut self`）。加 `Core` 字段 `disconnect_conns: Vec<ClientId>`，在 `handle_frame`/`run` 循环末尾统一 `for id in disconnect_conns.drain(..) { self.handle_disconnect(id).await }`。（注意：`send_to` 内不能直接 `handle_disconnect`——借用冲突；用延迟队列。）

> 实现注意：把 `send_to` 从 `&self` 改 `&mut self` 会触发调用点借用调整（原先 `for dev in devs.clone() { self.send_to(...).await }` 仍成立，因 devs 已 clone）。逐个编译错误按提示改。

- [ ] **Step 4: 跑通过 + 回归**

Run: `cargo test -p agentdeck-relay slow_consumer_does_not_block_other_connections`
Expected: PASS（fast device 及时拿到 MachineList）。
Run: `cargo test -p agentdeck-relay`
Expected: 全绿（T1/T2/T3 不回归——正常消费者 try_send 不满）。0 warning。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/src/router.rs
git commit -m "feat(relay): Core 连接身份(ConnIdentity)+send_to 改 try_send+溢出策略（HOL 防阻）"
```

---

### Task 5: Core handle_frame 授权（scope + RegisterMachine/AdminReply 身份绑定 + Revoke）

**Files:**
- Modify: `agentdeck-relay/src/router.rs`

**Interfaces:**
- Produces：`CoreMsg::Revoke { device_id: String }`（`FakeRelay::revoke(device_id)`）；`req_origin` 值类型改 `{ origin: ClientId, target_machine: String }`；handle_frame 强制授权。
- Consumes：Task 4 的 `ConnIdentity`/`ConnRole`。

- [ ] **Step 1: 写失败测试（跨身份 RegisterMachine 被拒 + AdminReply 非目标被拒）**

```rust
    #[tokio::test]
    async fn register_machine_rejects_cross_identity() {
        let relay = FakeRelay::start();
        // M1 以 machine 身份 machine_id=M1 注册
        let m1 = relay.connect_with_identity(ConnIdentity {
            account_id: "acc".into(), device_id: "m1".into(),
            role: ConnRole::Machine { machine_id: "M1".into() } }).await;
        m1.send(mframe("M1", RelayControlMsg::RegisterMachine { machine: machine("M1") })).await;
        // 攻击者连接以 machine_id=Evil 身份，却试图注册 machine_id=M1（覆盖）
        let mut evil = relay.connect_with_identity(ConnIdentity {
            account_id: "acc".into(), device_id: "evil".into(),
            role: ConnRole::Machine { machine_id: "Evil".into() } }).await;
        evil.send(mframe("M1", RelayControlMsg::RegisterMachine { machine: machine("M1") })).await;
        // evil 应收到 identity_conflict Error
        let e = recv_until_error(&mut evil).await;
        assert_eq!(e, agentdeck_protocol::remote::failure::MACHINE_IDENTITY_CONFLICT);
    }
```
（辅助 `mframe(machine_id, msg)` 构 machine-role RemoteFrame；`recv_until_error` 轮询到 `RelayControlMsg::Error{code,..}` 返回 code，套 5s timeout。）

- [ ] **Step 2: 跑确认失败**

Run: `cargo test -p agentdeck-relay register_machine_rejects_cross_identity`
Expected: FAIL（当前无条件 insert，evil 覆盖成功、无 Error）。

- [ ] **Step 3: 实现授权检查**

`router.rs` `handle_frame`：
- RegisterMachine：先取 `self.conns.get(&id).identity`，要求 `identity.role == ConnRole::Machine { machine_id } && machine.machine_id == machine_id`，否则 `send_to(id, Error{code: failure::MACHINE_IDENTITY_CONFLICT, ...})` 并 return。
- Subscribe/SendCommand：`account scope`——目标 machine/conversation 归属须与 `identity.account_id` 一致（R1a 单账户，machines/sessions 存 `account_id`，跨账户 `failure::AUTH_FORBIDDEN`）。R1a 单账户下默认同 account，但检查点必须在（用 identity.account_id 比对 MachineEntry.account_id）。
- SendCommand：`req_origin.insert(request_id, ReqOrigin { origin: id, target_machine: machine_id.clone() })`。
- AdminReply：取 `ReqOrigin`，要求发送连接 `id` 的 identity.role == Machine{target_machine}，否则 `failure::REPLY_UNAUTHORIZED` 丢弃。
- 加 `CoreMsg::Revoke { device_id }`：遍历 conns 找 identity.device_id==device_id 的连接，`handle_disconnect`。`FakeRelay::revoke` 发该消息。
- `MachineEntry` 加 `account_id: String`（RegisterMachine 时从 identity 填）。

（完整分支代码见设计 §4.3；实现时逐条替换现有 handle_frame 分支。）

- [ ] **Step 4: 跑通过 + 回归**

Run: `cargo test -p agentdeck-relay register_machine_rejects_cross_identity`（PASS）
补一个 `admin_reply_from_non_target_machine_rejected` 测试（machine M2 冒发 AdminReply{in_reply_to=给 M1 的 request} → 被 REPLY_UNAUTHORIZED 丢弃、origin device 收不到），跑 PASS。
Run: `cargo test -p agentdeck-relay`（全绿；T1/T2/T3 用 connect_with_identity 的同 account 身份，不回归——可能需给 T1/T2 的 machine/device 连接改用带匹配身份的 connect_with_identity）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/src/router.rs
git commit -m "feat(relay): handle_frame 授权——account scope+RegisterMachine 身份绑定+AdminReply 回复者绑定+Revoke 断连"
```

---

### Task 6: auth 模块——身份模型 + RelayStore + 密码学 + enroll 逻辑

**Files:**
- Create: `agentdeck-relay/src/auth/mod.rs`、`store.rs`、`crypto.rs`、`enroll.rs`
- Modify: `agentdeck-relay/src/lib.rs`（`mod auth;`）
- Modify: `agentdeck-relay/Cargo.toml`（加 `ed25519-dalek = "2"`, `x25519-dalek = "2"`, `sha2 = "0.10"`, `rand = "0.8"`, `rand_core = "0.6"`, `base64 = "0.22"`）

**Interfaces:**
- Produces：
  - `auth::store::{Account, Device, Challenge, DeviceRole, RelayStore(trait), InMemoryRelayStore}`。
  - `auth::crypto::{new_challenge_nonce() -> String, verify_ed25519(pubkey_b64, msg, sig_b64) -> bool, gen_credential() -> String, hash_credential(&str) -> String}`。
  - `auth::enroll::{ChallengeReq, ChallengeResp, CompleteReq, CompleteResp, start_challenge(store, req, ttl_ms, now_ms) -> ChallengeResp, complete(store, req, bootstrap_secret, now_ms) -> Result<CompleteResp, EnrollError>}`（纯函数，注入 store/时钟/secret；不含网络——REST 由 Task 9 包）。
  - `enroll` 结果含 `{ account_id, credential(明文一次性), device: Device }`。
- Consumes：Task 4 的 `ConnIdentity`（server 层用）。

- [ ] **Step 1: 写失败测试（enroll challenge-response 全路径）**

`auth/enroll.rs` 底部：
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::store::{InMemoryRelayStore, DeviceRole};
    use crate::auth::crypto;

    fn dev_keys() -> (String, ed25519_dalek::SigningKey) {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        (crypto::b64(sk.verifying_key().as_bytes()), sk)
    }

    #[test]
    fn enroll_creates_singleton_account_then_joins_it() {
        let mut store = InMemoryRelayStore::default();
        let secret = "boot-secret";
        // 设备1（device 角色）
        let (dpub, dsk) = dev_keys();
        let ch = start_challenge(&mut store, ChallengeReq { device_sign_pubkey: dpub.clone() }, 60_000, 1_000);
        let sig = crypto::b64(&dsk.sign(ch.nonce.as_bytes()).to_bytes());
        let r1 = complete(&mut store, CompleteReq {
            bootstrap_secret: secret.into(), nonce_sig: sig,
            device: NewDevice { device_id: "d1".into(), role: DeviceRole::Device,
                sign_pubkey: dpub.clone(), box_pubkey: "box1".into() },
            owner_pubkey: Some("owner-pub".into()),
        }, secret, 2_000).unwrap();
        let acc = r1.account_id.clone();
        // 设备2（machine 角色）——同 bootstrap secret，应加入同一 account、不新建
        let (mpub, msk) = dev_keys();
        let ch2 = start_challenge(&mut store, ChallengeReq { device_sign_pubkey: mpub.clone() }, 60_000, 3_000);
        let sig2 = crypto::b64(&msk.sign(ch2.nonce.as_bytes()).to_bytes());
        let r2 = complete(&mut store, CompleteReq {
            bootstrap_secret: secret.into(), nonce_sig: sig2,
            device: NewDevice { device_id: "m1".into(), role: DeviceRole::Machine,
                sign_pubkey: mpub, box_pubkey: "box2".into() },
            owner_pubkey: None,
        }, secret, 4_000).unwrap();
        assert_eq!(r2.account_id, acc, "第二设备必须加入同一 singleton account");
        assert_eq!(store.account_count(), 1);
        assert!(crypto::hash_credential(&r1.credential) == store.device(&r1.device.device_id).unwrap().credential_hash);
    }

    #[test]
    fn enroll_rejects_bad_secret_expired_and_reused_nonce() {
        let mut store = InMemoryRelayStore::default();
        let (dpub, dsk) = dev_keys();
        let ch = start_challenge(&mut store, ChallengeReq { device_sign_pubkey: dpub.clone() }, 60_000, 1_000);
        let sig = crypto::b64(&dsk.sign(ch.nonce.as_bytes()).to_bytes());
        let good = CompleteReq { bootstrap_secret: "boot".into(), nonce_sig: sig.clone(),
            device: NewDevice { device_id: "d1".into(), role: DeviceRole::Device,
                sign_pubkey: dpub.clone(), box_pubkey: "b".into() }, owner_pubkey: Some("o".into()) };
        // 错 secret
        assert!(matches!(complete(&mut store, good.clone(), "WRONG", 2_000), Err(EnrollError::BadSecret)));
        // TTL 过期
        assert!(matches!(complete(&mut store, good.clone(), "boot", 999_999), Err(EnrollError::ChallengeExpired)));
        // 正常一次
        complete(&mut store, good.clone(), "boot", 2_000).unwrap();
        // nonce 重用（已消费）
        assert!(matches!(complete(&mut store, good, "boot", 2_000), Err(EnrollError::ChallengeExpired)));
    }
}
```

- [ ] **Step 2: 跑确认失败**

Run: `cargo test -p agentdeck-relay auth::enroll`
Expected: FAIL（模块不存在）。

- [ ] **Step 3: 实现 store/crypto/enroll**

`Cargo.toml` 加依赖（见 Files）。`auth/crypto.rs`：
```rust
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

pub fn b64(bytes: &[u8]) -> String { STANDARD.encode(bytes) }
pub fn unb64(s: &str) -> Option<Vec<u8>> { STANDARD.decode(s.as_bytes()).ok() }

pub fn new_challenge_nonce() -> String {
    use rand::RngCore;
    let mut n = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut n);
    b64(&n)
}
pub fn gen_credential() -> String {
    use rand::RngCore;
    let mut c = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut c);
    b64(&c)
}
pub fn hash_credential(cred: &str) -> String {
    let mut h = Sha256::new();
    h.update(cred.as_bytes());
    b64(&h.finalize())
}
pub fn verify_ed25519(pubkey_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let (Some(pk), Some(sig)) = (unb64(pubkey_b64), unb64(sig_b64)) else { return false };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk.as_slice()) else { return false };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig.as_slice()) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else { return false };
    vk.verify_strict(msg, &Signature::from_bytes(&sig_arr)).is_ok()
}
```
`auth/store.rs`：`DeviceRole{Machine,Device}`, `Account{account_id, owner_sign_pubkey}`, `Device{device_id, account_id, role, credential_hash, sign_pubkey, box_pubkey, revoked}`, `Challenge{device_sign_pubkey, nonce, expires_at_ms, used}`；`RelayStore` trait（`put_challenge/take_challenge/singleton_account/create_account/put_device/device/account_count/mark_revoked`）；`InMemoryRelayStore`（HashMap 实现 + `account_id: Option<String>` singleton 槽）。
`auth/enroll.rs`：`ChallengeReq/Resp`, `CompleteReq{bootstrap_secret, nonce_sig, device: NewDevice, owner_pubkey: Option<String>}`, `NewDevice`, `CompleteResp{account_id, credential, device}`, `EnrollError{BadSecret, ChallengeExpired, BadSignature}`；`start_challenge`（存 challenge、返回 nonce）；`complete`（校 secret→取并单次消费 challenge（`take_challenge` 遇 used/过期返 None→ChallengeExpired）→verify_ed25519(device.sign_pubkey, nonce, nonce_sig)→singleton account 建/取→put_device(credential_hash)→返回明文 credential 一次性）。`account_id` 派生：首次用 `crypto::hash_credential(owner_pubkey)` 前缀之类（确定性）。

- [ ] **Step 4: 跑通过**

Run: `cargo test -p agentdeck-relay auth::`
Expected: PASS（两个测试）。`cargo build -p agentdeck-relay` 0 warning。确认 `cargo tree -p agentdeck-relay | grep rand_core` 只有 0.6（dalek 对齐，无 0.9）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/src/auth agentdeck-relay/src/lib.rs agentdeck-relay/Cargo.toml Cargo.lock
git commit -m "feat(relay): auth 模块——身份模型/RelayStore(内存)/ed25519+sha2 密码学/challenge-response enroll(单账户 singleton)"
```

---

### Task 7: `agentdeck-relay-client` crate（WsTransport + WsRelayClient + InProcRelayClient）

**Files:**
- Modify: `Cargo.toml`（members 加 `agentdeck-relay-client`）
- Create: `agentdeck-relay-client/Cargo.toml`、`src/lib.rs`、`src/ws.rs`、`src/inproc.rs`

**Interfaces:**
- Produces：
  - `InProcRelayClient`（`new(RelayClient) -> Self`，实现 `agentdeck_relay::RelayLink`）。
  - `WsRelayClient`（`async connect(url: &str, bearer: &str, from: ClientRole) -> Result<Self, WsError>`，实现 `RelayLink`；内部 tokio-tungstenite，RemoteFrame↔WS text，reconnect 重放已记录 Subscribe）。
  - `WsTransport: agentdeck_protocol::Transport`（字节层 String↔WS text；`reconnect` 真重连）。
- Consumes：Task 3 `RelayLink`、`RemoteFrame`、Task 1 base64 DataEnvelope。

- [ ] **Step 1: crate 脚手架 + InProcRelayClient + 测试**

`Cargo.toml` members 加 `"agentdeck-relay-client"`。`agentdeck-relay-client/Cargo.toml`：
```toml
[package]
name = "agentdeck-relay-client"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
agentdeck-relay = { path = "../agentdeck-relay" }        # 取 RelayLink（无 server feature）
agentdeck-protocol = { path = "../agentdeck-protocol" }
tokio = { version = "1", features = ["rt", "macros", "sync", "time", "net", "io-util"] }
tokio-tungstenite = "0.26"
futures-util = "0.3"
async-trait = "0.1"
serde_json = "1"
thiserror = "1"
```
`src/lib.rs`：`mod inproc; mod ws; pub use inproc::InProcRelayClient; pub use ws::{WsRelayClient, WsError};`。
`src/inproc.rs`：
```rust
use agentdeck_protocol::remote::RemoteFrame;
use agentdeck_relay::{RelayClient, RelayLink};

pub struct InProcRelayClient(RelayClient);
impl InProcRelayClient { pub fn new(c: RelayClient) -> Self { Self(c) } }

#[async_trait::async_trait]
impl RelayLink for InProcRelayClient {
    async fn send(&self, frame: RemoteFrame) { self.0.send(frame).await }
    async fn recv(&mut self) -> Option<RemoteFrame> { self.0.recv().await }
}
```
测试（`src/inproc.rs` 底部）：起 `FakeRelay`、`connect` 拿 RelayClient、包 `InProcRelayClient`，发 Subscribe{Machines} 收 MachineList（确定性）。

- [ ] **Step 2: 跑 InProc 测试**

Run: `cargo test -p agentdeck-relay-client inproc`
Expected: PASS。

- [ ] **Step 3: WsTransport + WsRelayClient（tokio-tungstenite）**

`src/ws.rs`：实现 `WsTransport`（持 tungstenite `WebSocketStream` 分半，`send(String)` 发 `Message::Text`、`recv()` 读 text、`reconnect()` 重连并带 `Authorization: Bearer` header）+ `WsRelayClient`（在 WsTransport 上编解码 `RemoteFrame`（serde_json text）、记录 `Subscribe` 以便 reconnect 重放）。connect 用 `tokio_tungstenite::connect_async` + 自定义 request（`http::Request` 带 `Authorization` header）。`WsError`（thiserror）。
> 库 API 细节（`connect_async`、`Message::Text`、split sink/stream）以 tokio-tungstenite 0.26 文档为准；本步给出结构与 trait 实现签名，实现者填库调用。

- [ ] **Step 4: 编译 + client 单测（尽量确定性）**

Run: `cargo build -p agentdeck-relay-client`（0 warning）。WsRelayClient 的真连接测试放 Task 9 的服务端集成测（需要真 server）；本步只保证编译 + InProc 测试绿。

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml agentdeck-relay-client Cargo.lock
git commit -m "feat(relay-client): 新 crate——RelayLink 的 WsRelayClient(tungstenite)+InProcRelayClient+WsTransport"
```

---

### Task 8: relay 配置 + TLS 门禁

**Files:**
- Create: `agentdeck-relay/src/config.rs`
- Modify: `agentdeck-relay/Cargo.toml`（加 `clap = { version="4", features=["derive"] }`, `dotenvy = "0.15"`；`server`/`tls` feature 声明见 Task 9）

**Interfaces:**
- Produces：`config::RelayConfig { bind: SocketAddr, bootstrap_secret: String, tls: Option<TlsPaths>, log_level: String }`；`RelayConfig::load() -> Result<Self, ConfigError>`（dotenvy + clap + env `AGENTDECK_RELAY_*`）；`RelayConfig::validate_transport_gate() -> Result<(), ConfigError>`（非 loopback 无 TLS 且无 `--allow-plaintext` → Err `relay.config.plaintext_non_loopback`）。

- [ ] **Step 1: 写失败测试（TLS 门禁）**

`config.rs` 底部：
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    fn cfg(bind: &str, tls: bool, allow: bool) -> RelayConfig {
        RelayConfig { bind: bind.parse().unwrap(), bootstrap_secret: "s".into(),
            tls: if tls { Some(TlsPaths { cert: "c".into(), key: "k".into() }) } else { None },
            allow_plaintext: allow, log_level: "info".into() }
    }
    #[test]
    fn loopback_plaintext_ok() { assert!(cfg("127.0.0.1:8080", false, false).validate_transport_gate().is_ok()); }
    #[test]
    fn non_loopback_plaintext_rejected() {
        let e = cfg("0.0.0.0:8080", false, false).validate_transport_gate().unwrap_err();
        assert_eq!(e.code(), agentdeck_protocol::remote::failure::CONFIG_PLAINTEXT_NON_LOOPBACK);
    }
    #[test]
    fn non_loopback_with_tls_ok() { assert!(cfg("0.0.0.0:8080", true, false).validate_transport_gate().is_ok()); }
    #[test]
    fn non_loopback_allow_plaintext_ok() { assert!(cfg("0.0.0.0:8080", false, true).validate_transport_gate().is_ok()); }
}
```

- [ ] **Step 2: 跑确认失败** → **Step 3: 实现 config + 门禁**（`ip().is_loopback()` 判定；`ConfigError` 带 `code()`）→ **Step 4: 跑通过** → **Step 5: Commit**

Run（Step2）: `cargo test -p agentdeck-relay config::` → FAIL。
Run（Step4）: `cargo test -p agentdeck-relay config::` → PASS（4 测试）。
```bash
git add agentdeck-relay/src/config.rs agentdeck-relay/Cargo.toml agentdeck-relay/src/lib.rs
git commit -m "feat(relay): 配置层 + 非 loopback 强制 TLS 传输门禁"
```

---

### Task 9: relay 服务端 + binary（axum WS + REST enroll + 握手鉴权，server feature）

**Files:**
- Create: `agentdeck-relay/src/server/{mod.rs, pair.rs, ws.rs, conn.rs}`、`agentdeck-relay/src/main.rs`
- Modify: `agentdeck-relay/Cargo.toml`（`server` feature：axum 0.8、tokio `net`、tracing、tracing-subscriber、可选 `tls`：rustls 0.23 + tokio-rustls 0.26；`[[bin]] name="agentdeck-relay" required-features=["server"]`）
- Modify: `agentdeck-relay/src/lib.rs`（`#[cfg(feature="server")] pub mod server;`）

**Interfaces:**
- Produces：`server::serve(config: RelayConfig, store: impl RelayStore, relay: FakeRelay) -> Result<(), ServeError>`（起 axum）；REST `POST /v1/pair/challenge`、`POST /v1/pair/complete`（包 Task 6 的 enroll 纯函数）；WS `GET /v1/connect`（Bearer→解析 device→`ConnIdentity`→`relay.connect_with_identity` + per-conn reader/writer task）；`--selfcheck`。
- Consumes：Task 4 `connect_with_identity`/`ConnIdentity`、Task 6 `enroll`/`RelayStore`、Task 8 `RelayConfig`、Task 1 `RELAY_PROTOCOL_VERSION`/base64。

- [ ] **Step 1: server 骨架 + REST enroll + WS 握手 + per-conn task**

`Cargo.toml` 加 server feature 与依赖（axum="0.8"、tokio 补 "net"、tracing="0.1"、tracing-subscriber="0.3"；tls feature：rustls="0.23"、tokio-rustls="0.26"）。
`server/pair.rs`：两个 axum handler，反序列化 `ChallengeReq`/`CompleteReq`（Task 6 DTO），调 `start_challenge`/`complete`（注入 store + config.bootstrap_secret + `now_ms`），`EnrollError`→HTTP 4xx + `failure::*` code JSON。
`server/ws.rs`：`GET /v1/connect` 的 `WebSocketUpgrade`——先从 header 取 `Authorization: Bearer <cred>` + 版本参数，`hash_credential` 查 store → 得 `Device`（未知/撤销→拒，`failure::AUTH_INVALID_DEVICE`/`AUTH_REVOKED_DEVICE`；版本不符→`VERSION_UNSUPPORTED`）→构 `ConnIdentity`。
`server/conn.rs`：`on_upgrade` 后 `relay.connect_with_identity(identity)` 拿 `RelayClient`；spawn reader（WS text→`serde_json::from_str::<RemoteFrame>`→`client.send`... 实际是把 device→relay 帧喂进 relay：`link.send`）+ writer（`client.recv()`→`Message::Text(serde_json::to_string(frame))`）。`trace_id` 不覆写（用帧自带）。`max_message_size` 设上限。
`main.rs`：`#[tokio::main]`，`RelayConfig::load()?` → `validate_transport_gate()?` → tracing_subscriber init（EnvFilter）→ `server::serve(...)`。`--selfcheck`（clap flag）：load+validate+构 store/relay 后打印 ok 退出。

> axum 0.8 / tungstenite 0.26 的 handler、`ws.on_upgrade`、`Message::Text` API 以库文档为准；本步给出路由、握手鉴权流程、per-conn 任务结构。

- [ ] **Step 2: 编译 + selfcheck**

Run: `cargo build -p agentdeck-relay --features server`（0 warning）。
Run: `cargo run -p agentdeck-relay --features server -- --selfcheck --bootstrap-secret x`
Expected: 打印 selfcheck ok、退出 0。
Run: `cargo tree -p agentdeckd | grep -c 'tokio.*net\|axum'`
Expected: `0`（daemon 不沾 net/axum——server 在独立 feature+crate）。

- [ ] **Step 3: Commit**

```bash
git add agentdeck-relay/src/server agentdeck-relay/src/main.rs agentdeck-relay/src/lib.rs agentdeck-relay/Cargo.toml Cargo.lock
git commit -m "feat(relay): axum WS 服务端 + REST enroll + 握手鉴权派生身份 + per-conn task + binary/--selfcheck（server feature）"
```

---

### Task 10: WS 端到端 + 鉴权 + 脱敏 集成测试（server feature）

**Files:**
- Create: `agentdeck-relay/tests/r1a_ws_e2e.rs`
- Modify: `agentdeck-relay/Cargo.toml`（`[dev-dependencies]`：agentdeck-relay-client(path)、tokio test-util、tracing-subscriber(测试捕获)）

**Interfaces:** Consumes Task 6/8/9 的 server + enroll + client。

- [ ] **Step 1: 写端到端测试**

`tests/r1a_ws_e2e.rs`（bind `127.0.0.1:0` 读回端口、`oneshot` 就绪同步、每步 5s timeout）：
1. `enroll_then_device_sees_machine_and_admin_ping`：起 server；REST enroll 一个 machine 凭据 + 一个 device 凭据（同 bootstrap secret、断言同 account_id）；`WsRelayClient::connect(machine cred, role Machine)` 发 RegisterMachine；`WsRelayClient::connect(device cred, role Device)` Subscribe{Machines}→收含该 machine 的 MachineList；device `SendCommand{Machine, Ping}`（合成 machine 侧回 AdminReply，或接真实 daemon bridge over ws）→device 收 AdminReply。
2. `rejects_bad_secret_expired_nonce_revoked_and_unknown_cred`：REST 错 secret→4xx bad_secret；过期/重用 nonce→challenge_expired；无 credential WS 连接→拒；enroll 后 revoke→WS 连接被拒。
3. `forged_from_and_cross_identity_and_nontarget_reply_rejected`：device 连接发 `from: Machine{...}`（伪造角色）→relay 按凭据派生的 Device 角色处理、伪造 from 不生效；跨身份 RegisterMachine→identity_conflict；非目标 machine 抢发 AdminReply→被拒。
4. `sentinel_token_not_in_logs`：用 tracing-subscriber 捕获日志到内存 buffer，全程把哨兵串塞进 credential 与 payload，断言日志不含哨兵。
辅助 recv 全套 `tokio::time::timeout`。

- [ ] **Step 2: 跑测试**

Run: `cargo build -p agentdeckd && cargo test -p agentdeck-relay --features server --test r1a_ws_e2e`
Expected: 全 PASS（真 WS loopback，鉴权/身份/脱敏全绿）。

- [ ] **Step 3: Commit**

```bash
git add agentdeck-relay/tests/r1a_ws_e2e.rs agentdeck-relay/Cargo.toml
git commit -m "test(relay): R1a WS 端到端 + challenge-response 鉴权 + 身份绑定 + 哨兵日志脱敏（真 loopback）"
```

---

### Task 11: CLI——`remote pair` + `--relay` + 接线 baseline_stub + 凭据文件

**Files:**
- Modify: `agentdeck-cli/src/main.rs`（`RemoteOp` 加 `Pair`、各子命令加 `--relay`；`RemoteOpArg` 携参）
- Modify: `agentdeck-cli/src/remote.rs`（`pair`/连接实现取代 baseline_stub；凭据文件读写）
- Modify: `agentdeck-cli/Cargo.toml`（加 `agentdeck-relay-client`(path)、`ed25519-dalek="2"`、`x25519-dalek="2"`、`rand="0.8"`、`rand_core="0.6"`、`base64="0.22"`、`directories="5"` 或复用 data_dir）

**Interfaces:** Consumes Task 7 `WsRelayClient`、Task 6 crypto（或复用 relay 的 pub crypto helpers）、Task 2 failure。

- [ ] **Step 1: 加 clap 命令面 + RemoteOpArg 携参**

`main.rs`：`RemoteOp` 加 `Pair { #[arg(long)] relay: String, #[arg(long)] bootstrap_secret: String, #[arg(long, value_enum, default_value="device")] role: RoleArg }`；给 Machines/Sessions/Watch/Send/Approve/Deny/Ping 各加 `#[arg(long)] relay: String` 及原位置参数。`RemoteOpArg` 改为携带这些参数（枚举变体带字段）。dispatch（304-322）把参数与 `--relay` 传进 `RemoteOpArg`；`remote::run` 的 `_data_dir` 改真名 `data_dir`（用于定位凭据文件）。

- [ ] **Step 2: 实现 remote.rs（pair + 连接执行 + 凭据文件）**

`remote.rs`：`creds_path(data_dir, profile) -> PathBuf`（`<data_dir>/relay/credentials.json`，默认 data_dir = `~/Library/Application Support/AgentDeck/`）；`pair(...)`（**用 CLI 自己加的 `ed25519-dalek`/`x25519-dalek`/`base64` 生成账户 owner + 设备 sign/box 密钥、签 nonce**，不依赖 relay 内部 crypto 模块——保持 CLI 与 relay 解耦）；REST challenge+complete + 写凭据文件（0600）；`connect_device(creds) -> WsRelayClient`；`machines/watch/send/...` 用它执行（取代 `baseline_stub`）；`smoke --relay` = device 连外部 relay 跑 machines+ping。REST enroll 客户端用轻量同步 `ureq = "2"`（阻塞、无 async 依赖冲突；在 `pair` 里用，其余走 `WsRelayClient`）——Cargo.toml 相应加 `ureq = "2"`。

- [ ] **Step 3: 测试（gated——需 relay + daemon）**

`remote.rs` 测试：沿用 CARGO_MANIFEST_DIR 定位；起进程内不行（CLI 无 server feature）——故 CLI 侧 pair/connect 的真实验证归 Task 10 的 relay 集成测（那里已覆盖 WsRelayClient）。CLI 层加**单测**：`creds_path` 计算、凭据文件 round-trip（写后读回一致）、RemoteOpArg 参数传递。真实 `remote pair --relay` 手动验证记入验收。

- [ ] **Step 4: 编译 + 单测 + 手动**

Run: `cargo build -p agentdeck-cli`（0 warning，**不含 axum**：`cargo tree -p agentdeck-cli | grep -c axum` = 0）。
Run: `cargo test -p agentdeck-cli remote::`（凭据/参数单测 PASS）。
手动（记入验收）：起 `agentdeck-relay --features server --bootstrap-secret s`，`agentdeck-cli remote pair --relay ws://127.0.0.1:PORT --bootstrap-secret s` → 写凭据；`agentdeck-cli remote machines --relay ws://...` → 列机器。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-cli/src/main.rs agentdeck-cli/src/remote.rs agentdeck-cli/Cargo.toml Cargo.lock
git commit -m "feat(cli): remote pair + --relay + 接线 machines/watch/send 等取代 baseline_stub + 凭据文件"
```

---

### Task 12: daemon-no-net guard + 文档收口 + 全量验证

**Files:**
- Create: `scripts/check-daemon-no-net.sh`
- Modify: `AGENTS.md`、`ARCHITECTURE.md`、`docs/index.md`、`docs/plans/2026-07-08-relay-r1-design-review.md`（§6 标 R1a 落地）

**Interfaces:** 无代码接口。

- [ ] **Step 1: 写 guard 脚本**

`scripts/check-daemon-no-net.sh`：
```bash
#!/usr/bin/env bash
set -euo pipefail
if cargo tree -p agentdeckd -e features 2>/dev/null | grep -qiE 'tokio .*\bnet\b|axum'; then
  echo "FAIL: agentdeckd 依赖树含 tokio net / axum（R1a 不变量：daemon 无 net 至 R2）"; exit 1
fi
echo "ok: agentdeckd 无 tokio net / axum"
```
`chmod +x`。

- [ ] **Step 2: 跑 guard**

Run: `bash scripts/check-daemon-no-net.sh`
Expected: `ok: agentdeckd 无 tokio net / axum`。

- [ ] **Step 3: 文档**

- `AGENTS.md` 验证入口补：`cargo test -p agentdeck-relay --features server`、`cargo run -p agentdeck-relay --features server -- --selfcheck`、`bash scripts/check-daemon-no-net.sh`、`remote pair`/`--relay` 用法、`RELAY_PROTOCOL_VERSION` 变更后 `UPDATE_SCHEMA=1`。
- `ARCHITECTURE.md` 补不变量：relay 独立数据目录、只存不透明数据 + 公钥材料 + credential 哈希；net/axum 仅限 relay `server` feature + relay-client；daemon 无 net 至 R2；非 loopback 强制 TLS。
- `docs/index.md` 登记 R1a design + implementation。
- R1 评审 §6 标注 R1a 已落地。

- [ ] **Step 4: 全量验证**

Run: `cargo test`（默认 features 全绿）
Run: `cargo test -p agentdeck-relay --features server`（server 测试全绿）
Run: `cargo build -p agentdeckd && cargo test -p agentdeckd`（无回归）
Run: `cargo run -q -p agentdeck-cli -- protocol schema | diff - protocol/agentdeck/agentdeck-protocol.schema.json && echo "schema in sync"`
Run: `bash scripts/check-daemon-no-net.sh` / `bash scripts/verify-agent-docs.sh`
Expected: 全通过。

- [ ] **Step 5: Commit**

```bash
git add scripts/check-daemon-no-net.sh AGENTS.md ARCHITECTURE.md docs/index.md docs/plans/2026-07-08-relay-r1-design-review.md
git commit -m "chore(relay): daemon-no-net guard + R1a 文档收口（AGENTS/ARCHITECTURE/index）"
```

---

## 完成标准（对齐 R1a 设计 §6）

- `cargo test`（默认）+ `cargo test -p agentdeck-relay --features server` 全绿；schema 无漂移；`verify-agent-docs.sh` + `check-daemon-no-net.sh` 通过。
- relay binary 启动（默认 bind 127.0.0.1）；device+machine 各经 bootstrap secret + challenge-response enroll 成功、挂**同一 singleton account**、拿到 credential。
- CLI `remote pair`/`machines`/`ping` 经真 ws 连外部 relay 跑通；`remote smoke` in-proc 保留。
- 错 bootstrap/过期或重用 nonce/撤销设备/无 credential/版本不符 均被拒并回对应 `failure::*` 码。
- 伪造 `from`、跨身份 RegisterMachine、非目标 AdminReply 均被拒；慢连接不冻住 relay（HOL）；日志无 token/明文（哨兵测试）。
- 非 loopback 未配 TLS 拒启动（除非 `--allow-plaintext`）。
- **不变量**：`agentdeckd` 无 tokio net（guard）；`agentdeck-cli` 无 axum；N6 `transport_trait_remote_ready` 绿；`thiserror` 单版本 1.x、`rand_core` 单版本 0.6。

## 后续（非 R1a）
- **R1b**：RelayStore 的 SQLite 实现（持久化 accounts/devices/revocation/seq 高水位/加密事件队列）+ conv_buffer 上界/Ack-trim/重放补拉/AnnounceSession 去重/req_origin TTL 清理。
- **R1c**：`DataEnvelope::Encrypted`（IETF ChaCha20-Poly1305 + X25519/HKDF）+ 用 R1a 已登记 box 公钥封装 DEK + seal 策略 + 跨语言测试向量。
- **R2**：agentdeckd remote-mode 取代外部 bridge。
