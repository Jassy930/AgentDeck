# Relay R0 Contract Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 证明控制面/数据面分层的 remote frame 能包住现有 agentdeck-protocol，并用内存 fake relay + 单进程 CLI smoke 打通「协议组合 + 转发 + 稳定身份」，为后续 R1-R3 铺底。

**Architecture:** 在 `agentdeck-protocol` 新增 `remote` 模块（relay 可读控制面 `RemoteFrame`/`RelayControlMsg` + relay 不可见数据面 `DataEnvelope`）；新建 `agentdeck-relay` lib crate 提供内存异步 `FakeRelay` 路由器与 `StdioMachineBridge`（把真实 `agentdeckd` 当 machine 接入，零改 daemon）；`agentdeck-cli` 加 `remote` 命令面（接口基线）与单进程 `remote smoke`。真实 daemon 测试放 `agentdeckd/tests/`（`CARGO_BIN_EXE_agentdeckd` 保证可用）。

**Tech Stack:** Rust edition 2024、tokio（sync/process/io-util/macros，**无 net**）、serde/serde_json、schemars 0.8.22、clap v4 derive。

**设计事实源：** `docs/plans/2026-07-07-relay-r0-contract-spike-design.md`。本计划实现其 §4-§7。

## Global Constraints

- Rust edition **2024**；新 crate 用 `version.workspace = true` 等继承根 `[workspace.package]`。根 `Cargo.toml` **无 `[workspace.dependencies]`**，每个 crate 自声明依赖版本。
- **任何 crate 不得启用 tokio `net` feature**（R0 无网络，编译期强制）。
- 内层协议版本常量 `agentdeck_protocol::PROTOCOL_VERSION: u32 = 2`；relay 线协议 `RELAY_PROTOCOL_VERSION: u16 = 0`。
- 所有 wire 类型派生 `Serialize, Deserialize, JsonSchema`，加 `#[serde(deny_unknown_fields)]`；字段命名 `rename_all = "camelCase"`（与现有 trunk 一致）。
- `AgentKind` 序列化为 `"codex"` / `"claude_code"`（snake_case）；`ServerEvent` 用 `#[serde(tag="type")]`，`ClientCommand` 用 `#[serde(tag="command")]`，`AgentItem` 用 `#[serde(tag="kind")]`，均 camelCase 值。`SessionId`/`ThreadId` 是 `#[serde(transparent)]` newtype，序列化为裸字符串。
- 不变量：**N1** remote 类型属性名不得以 `codex/openai/anthropic/claude` 开头；**K9/N8** relay/bridge 绝不读/存/转发 vendor token，只搬 opaque 数据面字节，不建 `cc-meta/`；**N6** 不实现也不削弱 `Transport` trait；**K5** R0 纯内存不写数据目录。
- schema 快照路径 `protocol/agentdeck/agentdeck-protocol.schema.json`，改协议后用 `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` 回写并提交。
- 提交不加 co-author；在 master 直接提交，未经请求不推送。

## 构建顺序说明（CLI-first 的落地含义）

设计把「CLI remote 命令面作为接口基线」列为最高优先。落到 TDD 任务时：CLI 命令面的**语义**（§4.3 的 `MobileSessionSource` 映射表）在设计阶段已冻结，是本计划所有代码对齐的目标；但可执行的单进程 `remote smoke`（Task 7）依赖 router（Task 3-5）与 bridge（Task 6）先存在。因此任务顺序为「类型 → router → bridge → CLI smoke → 测试固化」，router 各任务是**为服务 smoke 而建**。这不违背 CLI-first：命令面是全程的对齐锚点，smoke 是最早的人工验证路径，二者都在 iOS `RelaySessionSource` 之前就位。

---

### Task 1: 协议 `remote` 模块（控制面/数据面类型）

**Files:**
- Create: `agentdeck-protocol/src/remote/mod.rs`
- Create: `agentdeck-protocol/src/remote/data.rs`
- Create: `agentdeck-protocol/src/remote/frame.rs`
- Create: `agentdeck-protocol/src/remote/fleet.rs`
- Create: `agentdeck-protocol/src/remote/control.rs`
- Modify: `agentdeck-protocol/src/lib.rs`（加 `pub mod remote;` + 根 re-export）
- Test: `agentdeck-protocol/src/remote/mod.rs`（`#[cfg(test)]` 内联）

**Interfaces:**
- Produces（后续所有任务依赖）：
  - `agentdeck_protocol::remote::RELAY_PROTOCOL_VERSION: u16`
  - `DataEnvelope`（`plaintext<T: Serialize>(&T) -> Result<Self, serde_json::Error>`、`decode_plaintext<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error>`）
  - `ClientRole { Relay, Machine{machine_id}, Device{device_id} }`
  - `RemoteFrame`（`control(from: ClientRole, trace_id: String, created_at_ms: i64, msg: RelayControlMsg) -> Self`）
  - `RelayControlMsg`（见下全部变体）、`SubTarget`、`CommandTarget`
  - `MachineDescriptor`、`DeviceDescriptor`、`DeviceKind`、`SessionDescriptor`

- [ ] **Step 1: 写 data.rs（数据面 + 加密接缝）**

```rust
// agentdeck-protocol/src/remote/data.rs
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// 数据面 payload：relay 不可见。R0 携带明文字节（内层 ClientCommand /
/// ServerEvent / HistoryResponse 的序列化 JSON）；R1/R2 追加 `Encrypted`
/// 变体，控制面与路由器零改动。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "seal", rename_all = "camelCase", deny_unknown_fields)]
pub enum DataEnvelope {
    Plaintext {
        agentdeck_protocol_version: u32,
        bytes: Vec<u8>,
    },
    // Encrypted { alg, nonce, ciphertext, tag }  // R1/R2
}

impl DataEnvelope {
    /// 把可序列化的内层 payload 包成明文字节。
    pub fn plaintext<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        Ok(DataEnvelope::Plaintext {
            agentdeck_protocol_version: crate::PROTOCOL_VERSION,
            bytes: serde_json::to_vec(value)?,
        })
    }

    /// 解出内层 payload（仅接收端使用）。
    pub fn decode_plaintext<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        match self {
            DataEnvelope::Plaintext { bytes, .. } => serde_json::from_slice(bytes),
        }
    }
}
```

- [ ] **Step 2: 写 fleet.rs（fleet 数据类型）**

```rust
// agentdeck-protocol/src/remote/fleet.rs
use crate::AgentKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineDescriptor {
    pub machine_id: String,
    pub name: String,
    pub agentdeck_protocol_version: u32,
    pub is_online: bool,
    pub last_heartbeat_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum DeviceKind {
    Cli,
    Mobile,
    Desktop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceDescriptor {
    pub device_id: String,
    pub kind: DeviceKind,
}

/// 稳定身份：conversation_id（= daemon thread_id 已知时）与 per-turn
/// current_turn_session_id 分离，填上 sendPrompt→SessionContinue 需要的
/// thread_id/agent_kind/cwd。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionDescriptor {
    pub conversation_id: String,
    pub machine_id: String,
    pub thread_id: Option<String>,
    pub current_turn_session_id: Option<String>,
    pub agent_kind: AgentKind,
    pub cwd: String,
    pub title: Option<String>,
}
```

- [ ] **Step 3: 写 control.rs（控制面消息 + 寻址）**

```rust
// agentdeck-protocol/src/remote/control.rs
use crate::remote::data::DataEnvelope;
use crate::remote::fleet::{DeviceDescriptor, MachineDescriptor, SessionDescriptor};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum SubTarget {
    Machines,
    Sessions { machine_id: String },
    Events { conversation_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum CommandTarget {
    Conversation { conversation_id: String },
    Turn { turn_session_id: String },
    Machine { machine_id: String },
}

/// 控制面消息：relay 完整可读；携带 agent 内容的变体用嵌套 DataEnvelope（opaque）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "msg", rename_all = "camelCase", deny_unknown_fields)]
pub enum RelayControlMsg {
    // machine → relay
    RegisterMachine { machine: MachineDescriptor },
    Heartbeat { machine_id: String },
    AnnounceSession { session: SessionDescriptor },
    RetireSession { conversation_id: String },
    PublishEvent { conversation_id: String, turn_session_id: String, seq: u64, data: DataEnvelope },
    AdminReply { in_reply_to: String, data: DataEnvelope },
    // device → relay
    ConnectDevice { device: DeviceDescriptor },
    Subscribe { target: SubTarget },
    Unsubscribe { target: SubTarget },
    SendCommand { request_id: String, target: CommandTarget, data: DataEnvelope },
    Ack { up_to_seq: u64, conversation_id: Option<String> },
    // relay → client
    MachineList { machines: Vec<MachineDescriptor> },
    SessionList { machine_id: String, sessions: Vec<SessionDescriptor> },
    Event { conversation_id: String, turn_session_id: String, seq: u64, data: DataEnvelope },
    CommandDelivered { request_id: String },
    Error { code: String, message: String, in_reply_to: Option<String> },
}
```

- [ ] **Step 4: 写 frame.rs（控制面外壳）**

```rust
// agentdeck-protocol/src/remote/frame.rs
use crate::remote::control::RelayControlMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "role", rename_all = "camelCase", deny_unknown_fields)]
pub enum ClientRole {
    Relay,
    Machine { machine_id: String },
    Device { device_id: String },
}

/// 控制面帧：relay 完整可读（路由元数据 + 控制消息）。仅控制消息内嵌的
/// DataEnvelope 对 relay 不可见。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteFrame {
    pub relay_protocol_version: u16,
    pub trace_id: String,
    pub created_at_ms: i64,
    pub from: ClientRole,
    pub msg: RelayControlMsg,
}

impl RemoteFrame {
    pub fn control(from: ClientRole, trace_id: String, created_at_ms: i64, msg: RelayControlMsg) -> Self {
        RemoteFrame {
            relay_protocol_version: super::RELAY_PROTOCOL_VERSION,
            trace_id,
            created_at_ms,
            from,
            msg,
        }
    }
}
```

- [ ] **Step 5: 写 mod.rs（模块根 + 版本常量 + re-export + 往返测试）**

```rust
// agentdeck-protocol/src/remote/mod.rs
//! Remote (relay) wire types — R0 契约 spike。
//!
//! 控制面（`RemoteFrame` + `RelayControlMsg`）relay 完整可读，用于路由；
//! 数据面（`DataEnvelope`）对 relay 不可见，R0 明文、R1/R2 换加密，控制面不动。

pub mod control;
pub mod data;
pub mod fleet;
pub mod frame;

/// relay 线协议版本，独立于内层 `PROTOCOL_VERSION`。R0 草案 = 0。
pub const RELAY_PROTOCOL_VERSION: u16 = 0;

pub use control::{CommandTarget, RelayControlMsg, SubTarget};
pub use data::DataEnvelope;
pub use fleet::{DeviceDescriptor, DeviceKind, MachineDescriptor, SessionDescriptor};
pub use frame::{ClientRole, RemoteFrame};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientCommand;

    #[test]
    fn plaintext_data_envelope_round_trips_a_client_command() {
        let env = DataEnvelope::plaintext(&ClientCommand::Ping).unwrap();
        let back: ClientCommand = env.decode_plaintext().unwrap();
        assert!(matches!(back, ClientCommand::Ping));
    }

    #[test]
    fn remote_frame_serializes_control_plane_readably() {
        let frame = RemoteFrame::control(
            ClientRole::Device { device_id: "D1".into() },
            "trace-1".into(),
            0,
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into() } },
        );
        let json = serde_json::to_value(&frame).unwrap();
        // 控制面字段对 relay 明文可读：
        assert_eq!(json["relayProtocolVersion"], 0);
        assert_eq!(json["from"]["role"], "device");
        assert_eq!(json["msg"]["msg"], "subscribe");
        assert_eq!(json["msg"]["target"]["kind"], "events");
        assert_eq!(json["msg"]["target"]["conversationId"], "C1");
        // 完整往返：
        let back: RemoteFrame = serde_json::from_value(json).unwrap();
        assert_eq!(back, frame);
    }
}
```

- [ ] **Step 6: 改 lib.rs（挂模块 + 根 re-export）**

在 `agentdeck-protocol/src/lib.rs` 现有 `pub use trunk::{...};` 区块之后、`#[cfg(test)] mod neutrality_tests;` 之前，加入：

```rust
pub mod remote;
pub use remote::{
    ClientRole, CommandTarget, DataEnvelope, DeviceDescriptor, DeviceKind, MachineDescriptor,
    RelayControlMsg, RemoteFrame, SessionDescriptor, SubTarget, RELAY_PROTOCOL_VERSION,
};
```

- [ ] **Step 7: 跑测试**

Run: `cargo test -p agentdeck-protocol remote::tests`
Expected: 2 个测试 PASS（`plaintext_data_envelope_round_trips_a_client_command`、`remote_frame_serializes_control_plane_readably`）。

- [ ] **Step 8: Commit**

```bash
git add agentdeck-protocol/src/remote agentdeck-protocol/src/lib.rs
git commit -m "feat(protocol): 新增 remote 模块（控制面 RemoteFrame/RelayControlMsg + 数据面 DataEnvelope + fleet 类型）"
```

---

### Task 2: schema 快照 + 中立性守护纳入 remote 类型

**Files:**
- Modify: `agentdeck-protocol/src/lib.rs`（`protocol_schema()` 加 remote 类型）
- Modify: `agentdeck-protocol/src/neutrality_tests.rs`（加 remote 中立性扫描）
- Modify: `protocol/agentdeck/agentdeck-protocol.schema.json`（回写快照）

**Interfaces:**
- Consumes: Task 1 的 `remote::{RemoteFrame, RelayControlMsg, DataEnvelope, MachineDescriptor, SessionDescriptor, DeviceDescriptor}`。
- Produces: 无新符号；扩展既有快照与中立性门禁覆盖面。

- [ ] **Step 1: 在 protocol_schema() 加 remote 条目**

在 `agentdeck-protocol/src/lib.rs` 的 `protocol_schema()` 里，`"HistoryResponse": ...` 之后（`}` 之前）加入：

```rust
            "RemoteFrame": serde_json::to_value(schema_for!(remote::RemoteFrame)).unwrap(),
            "RelayControlMsg": serde_json::to_value(schema_for!(remote::RelayControlMsg)).unwrap(),
            "DataEnvelope": serde_json::to_value(schema_for!(remote::DataEnvelope)).unwrap(),
            "MachineDescriptor": serde_json::to_value(schema_for!(remote::MachineDescriptor)).unwrap(),
            "SessionDescriptor": serde_json::to_value(schema_for!(remote::SessionDescriptor)).unwrap(),
            "DeviceDescriptor": serde_json::to_value(schema_for!(remote::DeviceDescriptor)).unwrap(),
```

- [ ] **Step 2: 加 remote 中立性测试**

在 `agentdeck-protocol/src/neutrality_tests.rs` 末尾加入（`use schemars::schema_for;` 已在文件顶部）：

```rust
/// N1 扩展：remote 类型属性名不得以 vendor 前缀开头（递归扫描所有 properties）。
#[test]
fn protocol_neutrality_remote() {
    use crate::remote::{
        DataEnvelope, DeviceDescriptor, MachineDescriptor, RelayControlMsg, RemoteFrame,
        SessionDescriptor,
    };
    const FORBIDDEN_PREFIXES: &[&str] = &["codex", "openai", "anthropic", "claude"];

    fn assert_no_vendor_prefix(schema: &serde_json::Value, forbidden: &[&str]) {
        match schema {
            serde_json::Value::Object(map) => {
                if let Some(props) = map.get("properties").and_then(|p| p.as_object()) {
                    for key in props.keys() {
                        let lower = key.to_lowercase();
                        for prefix in forbidden {
                            assert!(
                                !lower.starts_with(prefix),
                                "remote property `{key}` starts with vendor prefix `{prefix}`"
                            );
                        }
                    }
                }
                for v in map.values() {
                    assert_no_vendor_prefix(v, forbidden);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    assert_no_vendor_prefix(v, forbidden);
                }
            }
            _ => {}
        }
    }

    for schema in [
        serde_json::to_value(schema_for!(RemoteFrame)).unwrap(),
        serde_json::to_value(schema_for!(RelayControlMsg)).unwrap(),
        serde_json::to_value(schema_for!(DataEnvelope)).unwrap(),
        serde_json::to_value(schema_for!(MachineDescriptor)).unwrap(),
        serde_json::to_value(schema_for!(SessionDescriptor)).unwrap(),
        serde_json::to_value(schema_for!(DeviceDescriptor)).unwrap(),
    ] {
        assert_no_vendor_prefix(&schema, FORBIDDEN_PREFIXES);
    }
}
```

- [ ] **Step 3: 跑中立性测试（先验证通过）**

Run: `cargo test -p agentdeck-protocol protocol_neutrality_remote`
Expected: PASS（remote 属性名全部中立）。

- [ ] **Step 4: 回写 schema 快照**

Run: `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`
Expected: PASS（该次运行会写回 `protocol/agentdeck/agentdeck-protocol.schema.json`，新增 6 个 remote 类型）。

- [ ] **Step 5: 验证快照已同步（不带 UPDATE_SCHEMA 再跑一次）**

Run: `cargo test -p agentdeck-protocol schema_matches_committed_snapshot`
Expected: PASS（快照与生成一致，无漂移）。

- [ ] **Step 6: Commit**

```bash
git add agentdeck-protocol/src/lib.rs agentdeck-protocol/src/neutrality_tests.rs protocol/agentdeck/agentdeck-protocol.schema.json
git commit -m "feat(protocol): remote 类型纳入 schema 快照与 N1 中立性守护"
```

---

### Task 3: `agentdeck-relay` crate + FakeRelay 核心（连接/注册/订阅机器）

**Files:**
- Modify: `Cargo.toml`（workspace members 加 `agentdeck-relay`）
- Create: `agentdeck-relay/Cargo.toml`
- Create: `agentdeck-relay/src/lib.rs`
- Create: `agentdeck-relay/src/router.rs`
- Test: `agentdeck-relay/src/router.rs`（`#[cfg(test)]` 内联）

**Interfaces:**
- Consumes: `agentdeck_protocol::remote::*`（Task 1）。
- Produces（后续任务依赖）：
  - `agentdeck_relay::FakeRelay`（`start() -> Self`、`async connect(&self, role: ClientRole) -> RelayClient`）
  - `agentdeck_relay::RelayClient`（`async send(&self, frame: RemoteFrame)`、`async recv(&mut self) -> Option<RemoteFrame>`）

- [ ] **Step 1: workspace 加成员**

把 `Cargo.toml` 根的 members 改为：

```toml
[workspace]
members = ["agentdeckd", "agentdeck-protocol", "agentdeck-cli", "agentdeck-relay"]
resolver = "3"
```

- [ ] **Step 2: 写 agentdeck-relay/Cargo.toml**

```toml
[package]
name = "agentdeck-relay"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "AgentDeck self-hostable relay — R0 in-memory fake relay + stdio machine bridge (no network)"

[dependencies]
agentdeck-protocol = { path = "../agentdeck-protocol" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros", "sync", "process", "io-util", "time"] }
thiserror = "1"
```

（注意：**无 `net` feature**。）

- [ ] **Step 3: 写 lib.rs**

```rust
// agentdeck-relay/src/lib.rs
//! AgentDeck relay — R0 内存 fake relay + stdio machine bridge（无网络）。
//!
//! 控制面（RelayControlMsg）relay 可读用于路由；数据面（DataEnvelope）不可见。

mod router;

pub use router::{FakeRelay, RelayClient};
```

- [ ] **Step 4: 写 router.rs（核心：连接 + 注册机器 + 订阅机器列表）**

```rust
// agentdeck-relay/src/router.rs
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use agentdeck_protocol::remote::{
    ClientRole, MachineDescriptor, RelayControlMsg, RemoteFrame, SessionDescriptor, SubTarget,
};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClientId(u64);

/// 客户端（machine/device）与 relay 之间的内存双工连接。
pub struct RelayClient {
    tx: mpsc::Sender<RemoteFrame>,
    rx: mpsc::Receiver<RemoteFrame>,
}

impl RelayClient {
    pub async fn send(&self, frame: RemoteFrame) {
        let _ = self.tx.send(frame).await;
    }
    pub async fn recv(&mut self) -> Option<RemoteFrame> {
        self.rx.recv().await
    }
}

enum CoreMsg {
    Connect { id: ClientId, role: ClientRole, out: mpsc::Sender<RemoteFrame> },
    Frame { id: ClientId, frame: RemoteFrame },
    Disconnect { id: ClientId },
}

/// 内存内容不可见转发器（有状态）。
pub struct FakeRelay {
    core_tx: mpsc::Sender<CoreMsg>,
    next_id: Arc<AtomicU64>,
}

impl FakeRelay {
    pub fn start() -> Self {
        let (core_tx, core_rx) = mpsc::channel::<CoreMsg>(256);
        tokio::spawn(Core::default().run(core_rx));
        FakeRelay { core_tx, next_id: Arc::new(AtomicU64::new(1)) }
    }

    pub async fn connect(&self, role: ClientRole) -> RelayClient {
        let id = ClientId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (to_relay_tx, mut to_relay_rx) = mpsc::channel::<RemoteFrame>(64);
        let (from_relay_tx, from_relay_rx) = mpsc::channel::<RemoteFrame>(64);
        let _ = self
            .core_tx
            .send(CoreMsg::Connect { id, role, out: from_relay_tx })
            .await;
        let core_tx = self.core_tx.clone();
        tokio::spawn(async move {
            while let Some(f) = to_relay_rx.recv().await {
                if core_tx.send(CoreMsg::Frame { id, frame: f }).await.is_err() {
                    break;
                }
            }
            let _ = core_tx.send(CoreMsg::Disconnect { id }).await;
        });
        RelayClient { tx: to_relay_tx, rx: from_relay_rx }
    }
}

struct Conn {
    role: ClientRole,
    out: mpsc::Sender<RemoteFrame>,
}

struct MachineEntry {
    conn: ClientId,
    descriptor: MachineDescriptor,
}

#[derive(Default)]
struct Core {
    conns: HashMap<ClientId, Conn>,
    machines: HashMap<String, MachineEntry>,
    conv_machine: HashMap<String, String>,
    turn_conv: HashMap<String, String>,
    sessions: HashMap<String, Vec<SessionDescriptor>>,
    conv_seq: HashMap<String, u64>,
    conv_buffer: HashMap<String, Vec<RelayControlMsg>>,
    req_origin: HashMap<String, ClientId>,
    subs_machines: HashSet<ClientId>,
    subs_sessions: HashMap<String, HashSet<ClientId>>,
    subs_events: HashMap<String, HashSet<ClientId>>,
}

impl Core {
    async fn run(mut self, mut rx: mpsc::Receiver<CoreMsg>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                CoreMsg::Connect { id, role, out } => {
                    self.conns.insert(id, Conn { role, out });
                }
                CoreMsg::Disconnect { id } => {
                    self.handle_disconnect(id).await;
                }
                CoreMsg::Frame { id, frame } => {
                    self.handle_frame(id, frame).await;
                }
            }
        }
    }

    /// relay → 指定连接 发一帧（from = Relay）。
    async fn send_to(&self, id: ClientId, trace_id: &str, msg: RelayControlMsg) {
        if let Some(conn) = self.conns.get(&id) {
            let frame = RemoteFrame::control(ClientRole::Relay, trace_id.to_string(), 0, msg);
            let _ = conn.out.send(frame).await;
        }
    }

    fn machine_list(&self) -> Vec<MachineDescriptor> {
        self.machines.values().map(|m| m.descriptor.clone()).collect()
    }

    async fn handle_frame(&mut self, id: ClientId, frame: RemoteFrame) {
        let trace = frame.trace_id.clone();
        match frame.msg {
            RelayControlMsg::RegisterMachine { machine } => {
                let mid = machine.machine_id.clone();
                self.machines.insert(mid, MachineEntry { conn: id, descriptor: machine });
                let list = self.machine_list();
                for dev in self.subs_machines.clone() {
                    self.send_to(dev, &trace, RelayControlMsg::MachineList { machines: list.clone() }).await;
                }
            }
            RelayControlMsg::ConnectDevice { .. } => {
                // R0：设备描述暂不持久化；连接已在 Connect 建立。
            }
            RelayControlMsg::Subscribe { target: SubTarget::Machines } => {
                self.subs_machines.insert(id);
                let list = self.machine_list();
                self.send_to(id, &trace, RelayControlMsg::MachineList { machines: list }).await;
            }
            // 其余变体在 Task 4 / Task 5 加入
            _ => {}
        }
    }

    async fn handle_disconnect(&mut self, id: ClientId) {
        self.conns.remove(&id);
        self.subs_machines.remove(&id);
        for set in self.subs_sessions.values_mut() {
            set.remove(&id);
        }
        for set in self.subs_events.values_mut() {
            set.remove(&id);
        }
        // 机器断开 → 标记离线并广播
        let offline: Vec<String> = self
            .machines
            .iter()
            .filter(|(_, m)| m.conn == id)
            .map(|(k, _)| k.clone())
            .collect();
        for mid in offline {
            if let Some(m) = self.machines.get_mut(&mid) {
                m.descriptor.is_online = false;
            }
        }
        if !self.machines.is_empty() || !self.subs_machines.is_empty() {
            let list = self.machine_list();
            for dev in self.subs_machines.clone() {
                self.send_to(dev, "disconnect", RelayControlMsg::MachineList { machines: list.clone() }).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::remote::{DeviceDescriptor, DeviceKind};

    fn machine(id: &str) -> MachineDescriptor {
        MachineDescriptor {
            machine_id: id.into(),
            name: format!("machine-{id}"),
            agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
            is_online: true,
            last_heartbeat_ms: None,
        }
    }

    fn frame(from: ClientRole, msg: RelayControlMsg) -> RemoteFrame {
        RemoteFrame::control(from, "t".into(), 0, msg)
    }

    #[tokio::test]
    async fn device_subscribing_to_machines_gets_snapshot_after_register() {
        let relay = FakeRelay::start();

        // machine 接入并注册
        let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") },
        ))
        .await;

        // device 接入并订阅机器列表
        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::ConnectDevice { device: DeviceDescriptor { device_id: "D1".into(), kind: DeviceKind::Cli } },
        ))
        .await;
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Machines },
        ))
        .await;

        // 订阅后应立即收到含 M1 的 MachineList 快照
        let got = d.recv().await.expect("frame");
        match got.msg {
            RelayControlMsg::MachineList { machines } => {
                assert_eq!(machines.len(), 1);
                assert_eq!(machines[0].machine_id, "M1");
            }
            other => panic!("expected MachineList, got {other:?}"),
        }
    }
}
```

- [ ] **Step 5: 跑测试**

Run: `cargo test -p agentdeck-relay device_subscribing_to_machines_gets_snapshot_after_register`
Expected: PASS。

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml agentdeck-relay
git commit -m "feat(relay): 新建 agentdeck-relay crate + FakeRelay 核心（连接/注册机器/订阅机器列表）"
```

---

### Task 4: FakeRelay 事件面（会话广告 + 事件转发 + seq + 补拉）

**Files:**
- Modify: `agentdeck-relay/src/router.rs`（`handle_frame` 加事件面 arms）
- Test: `agentdeck-relay/src/router.rs`（新增测试，证明稳定身份 + 补拉）

**Interfaces:**
- Consumes: Task 3 的 `Core`、`FakeRelay`、`RelayClient`。
- Produces: `AnnounceSession`/`PublishEvent`/`Subscribe{Sessions,Events}` 语义。

- [ ] **Step 1: 写失败测试（稳定身份 + 补拉）**

在 `agentdeck-relay/src/router.rs` 的 `#[cfg(test)] mod tests` 内新增：

```rust
    use agentdeck_protocol::remote::DataEnvelope;

    fn session(conv: &str, machine: &str) -> SessionDescriptor {
        SessionDescriptor {
            conversation_id: conv.into(),
            machine_id: machine.into(),
            thread_id: Some(conv.into()),
            current_turn_session_id: None,
            agent_kind: agentdeck_protocol::AgentKind::Codex,
            cwd: "/tmp/proj".into(),
            title: None,
        }
    }

    // 从 machine 发一条 PublishEvent（payload 用一个字符串占位内层字节）
    async fn publish(m: &RelayClient, conv: &str, turn: &str) {
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::PublishEvent {
                conversation_id: conv.into(),
                turn_session_id: turn.into(),
                seq: 0, // relay 自行 re-stamp
                data: DataEnvelope::plaintext(&format!("evt-{turn}")).unwrap(),
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn events_keyed_on_conversation_survive_new_turn_and_replay_for_late_subscriber() {
        let relay = FakeRelay::start();
        let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") },
        ))
        .await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::AnnounceSession { session: session("C1", "M1") },
        ))
        .await;

        // device 订阅 conversation C1
        let mut d1 = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d1.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into() } },
        ))
        .await;

        // turn A（session S1）发一条事件；随后 turn B（session S2，同 conversation）
        publish(&m, "C1", "S1").await;
        publish(&m, "C1", "S2").await;

        // D1 应按序收到两个 turn 的事件，seq 单调 0,1
        let e0 = recv_event(&mut d1).await;
        let e1 = recv_event(&mut d1).await;
        assert_eq!(e0, ("C1".to_string(), "S1".to_string(), 0));
        assert_eq!(e1, ("C1".to_string(), "S2".to_string(), 1));

        // 晚订阅的 D2 应补拉到已缓冲的两条
        let mut d2 = relay.connect(ClientRole::Device { device_id: "D2".into() }).await;
        d2.send(frame(
            ClientRole::Device { device_id: "D2".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into() } },
        ))
        .await;
        let r0 = recv_event(&mut d2).await;
        let r1 = recv_event(&mut d2).await;
        assert_eq!(r0, ("C1".to_string(), "S1".to_string(), 0));
        assert_eq!(r1, ("C1".to_string(), "S2".to_string(), 1));
    }

    async fn recv_event(c: &mut RelayClient) -> (String, String, u64) {
        loop {
            match c.recv().await.expect("frame").msg {
                RelayControlMsg::Event { conversation_id, turn_session_id, seq, .. } => {
                    return (conversation_id, turn_session_id, seq)
                }
                _ => continue,
            }
        }
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay events_keyed_on_conversation_survive_new_turn_and_replay_for_late_subscriber`
Expected: FAIL（`_ => {}` catch-all 丢弃了 AnnounceSession/PublishEvent/Subscribe{Events}，收不到 Event）。

- [ ] **Step 3: 实现事件面 arms**

在 `handle_frame` 的 `_ => {}` 之前插入：

```rust
            RelayControlMsg::AnnounceSession { session } => {
                let mid = session.machine_id.clone();
                self.conv_machine.insert(session.conversation_id.clone(), mid.clone());
                self.sessions.entry(mid.clone()).or_default().push(session);
                let list = self.sessions.get(&mid).cloned().unwrap_or_default();
                if let Some(devs) = self.subs_sessions.get(&mid) {
                    for dev in devs.clone() {
                        self.send_to(dev, &trace, RelayControlMsg::SessionList { machine_id: mid.clone(), sessions: list.clone() }).await;
                    }
                }
            }
            RelayControlMsg::RetireSession { conversation_id } => {
                self.conv_machine.remove(&conversation_id);
            }
            RelayControlMsg::PublishEvent { conversation_id, turn_session_id, seq: _, data } => {
                let seq = {
                    let s = self.conv_seq.entry(conversation_id.clone()).or_insert(0);
                    let cur = *s;
                    *s += 1;
                    cur
                };
                self.turn_conv.insert(turn_session_id.clone(), conversation_id.clone());
                let ev = RelayControlMsg::Event {
                    conversation_id: conversation_id.clone(),
                    turn_session_id,
                    seq,
                    data,
                };
                self.conv_buffer.entry(conversation_id.clone()).or_default().push(ev.clone());
                if let Some(devs) = self.subs_events.get(&conversation_id) {
                    for dev in devs.clone() {
                        self.send_to(dev, &trace, ev.clone()).await;
                    }
                }
            }
            RelayControlMsg::Subscribe { target: SubTarget::Sessions { machine_id } } => {
                self.subs_sessions.entry(machine_id.clone()).or_default().insert(id);
                let list = self.sessions.get(&machine_id).cloned().unwrap_or_default();
                self.send_to(id, &trace, RelayControlMsg::SessionList { machine_id, sessions: list }).await;
            }
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id } } => {
                self.subs_events.entry(conversation_id.clone()).or_default().insert(id);
                if let Some(buf) = self.conv_buffer.get(&conversation_id).cloned() {
                    for ev in buf {
                        self.send_to(id, &trace, ev).await;
                    }
                }
            }
            RelayControlMsg::Ack { .. } | RelayControlMsg::Heartbeat { .. } => {}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cargo test -p agentdeck-relay events_keyed_on_conversation_survive_new_turn_and_replay_for_late_subscriber`
Expected: PASS。

- [ ] **Step 5: 全 crate 回归**

Run: `cargo test -p agentdeck-relay`
Expected: 全 PASS（Task 3 的机器订阅测试不回归）。

- [ ] **Step 6: Commit**

```bash
git add agentdeck-relay/src/router.rs
git commit -m "feat(relay): 事件面——会话广告/事件转发/单调 seq/晚订阅补拉，事件键在稳定 conversation"
```

---

### Task 5: FakeRelay 命令面（SendCommand 路由 + AdminReply 关联 + 内容不可见）

**Files:**
- Modify: `agentdeck-relay/src/router.rs`（命令面 arms + 内容不可见测试）

**Interfaces:**
- Consumes: Task 3/4 的 `Core`。
- Produces: `SendCommand{Conversation/Turn/Machine}` 路由、`AdminReply` 关联、`CommandDelivered`、`Error(remote.session.not_found)`。

- [ ] **Step 1: 写失败测试（命令往返 + 内容不可见）**

在 tests 模块新增：

```rust
    use agentdeck_protocol::remote::CommandTarget;

    #[tokio::test]
    async fn send_command_routes_to_machine_and_admin_reply_returns_to_origin_device() {
        let relay = FakeRelay::start();
        let mut m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") },
        ))
        .await;

        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        // device → machine 的机器级命令（内层用占位字符串，relay 不解码）
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::SendCommand {
                request_id: "r1".into(),
                target: CommandTarget::Machine { machine_id: "M1".into() },
                data: DataEnvelope::plaintext(&"ping-cmd").unwrap(),
            },
        ))
        .await;

        // machine 收到该 SendCommand（relay 未解码 data）
        let at_machine = recv_send_command(&mut m).await;
        assert_eq!(at_machine, "r1");

        // machine 回 AdminReply
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::AdminReply { in_reply_to: "r1".into(), data: DataEnvelope::plaintext(&"pong").unwrap() },
        ))
        .await;

        // 发起 device 应收到该 AdminReply
        loop {
            match d.recv().await.expect("frame").msg {
                RelayControlMsg::AdminReply { in_reply_to, data } => {
                    assert_eq!(in_reply_to, "r1");
                    let s: String = data.decode_plaintext().unwrap();
                    assert_eq!(s, "pong");
                    break;
                }
                RelayControlMsg::CommandDelivered { .. } => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    async fn recv_send_command(c: &mut RelayClient) -> String {
        loop {
            match c.recv().await.expect("frame").msg {
                RelayControlMsg::SendCommand { request_id, .. } => return request_id,
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn unknown_conversation_command_returns_not_found_error() {
        let relay = FakeRelay::start();
        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::SendCommand {
                request_id: "r9".into(),
                target: CommandTarget::Conversation { conversation_id: "NOPE".into() },
                data: DataEnvelope::plaintext(&"x").unwrap(),
            },
        ))
        .await;
        match d.recv().await.expect("frame").msg {
            RelayControlMsg::Error { code, in_reply_to, .. } => {
                assert_eq!(code, "remote.session.not_found");
                assert_eq!(in_reply_to.as_deref(), Some("r9"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay send_command_routes_to_machine_and_admin_reply_returns_to_origin_device`
Expected: FAIL（命令面 arms 未实现）。

- [ ] **Step 3: 实现命令面 arms**

在 `handle_frame` 的 `_ => {}` 之前插入：

```rust
            RelayControlMsg::SendCommand { request_id, target, data } => {
                let machine_id = match &target {
                    CommandTarget::Machine { machine_id } => Some(machine_id.clone()),
                    CommandTarget::Conversation { conversation_id } => {
                        self.conv_machine.get(conversation_id).cloned()
                    }
                    CommandTarget::Turn { turn_session_id } => self
                        .turn_conv
                        .get(turn_session_id)
                        .and_then(|c| self.conv_machine.get(c))
                        .cloned(),
                };
                match machine_id.and_then(|m| self.machines.get(&m).map(|e| e.conn)) {
                    Some(machine_conn) => {
                        self.req_origin.insert(request_id.clone(), id);
                        self.send_to(
                            machine_conn,
                            &trace,
                            RelayControlMsg::SendCommand {
                                request_id: request_id.clone(),
                                target,
                                data,
                            },
                        )
                        .await;
                        self.send_to(id, &trace, RelayControlMsg::CommandDelivered { request_id }).await;
                    }
                    None => {
                        self.send_to(
                            id,
                            &trace,
                            RelayControlMsg::Error {
                                code: "remote.session.not_found".into(),
                                message: "no online machine for command target".into(),
                                in_reply_to: Some(request_id),
                            },
                        )
                        .await;
                    }
                }
            }
            RelayControlMsg::AdminReply { in_reply_to, data } => {
                if let Some(&dev) = self.req_origin.get(&in_reply_to) {
                    self.send_to(dev, &trace, RelayControlMsg::AdminReply { in_reply_to: in_reply_to.clone(), data }).await;
                    self.req_origin.remove(&in_reply_to);
                }
            }
```

需要 `use agentdeck_protocol::remote::CommandTarget;` 加到 router.rs 顶部的 use（与其它 remote 类型合并）。

- [ ] **Step 4: 跑测试确认通过**

Run: `cargo test -p agentdeck-relay`
Expected: 全 PASS（含 `send_command_routes...` 与 `unknown_conversation_command_returns_not_found_error`）。

- [ ] **Step 5: 内容不可见（T3）测试**

在 tests 模块新增，断言路由器从不解码 data（喂随机字节仍能按控制面路由）：

```rust
    #[tokio::test]
    async fn relay_routes_opaque_data_without_decoding_it() {
        let relay = FakeRelay::start();
        let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") },
        ))
        .await;
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::AnnounceSession { session: session("C1", "M1") },
        ))
        .await;
        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d.send(frame(
            ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into() } },
        ))
        .await;

        // 不可解码为任何协议类型的随机字节
        let garbage = DataEnvelope::Plaintext { agentdeck_protocol_version: 2, bytes: vec![0xFF, 0x00, 0x13, 0x37] };
        m.send(frame(
            ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::PublishEvent { conversation_id: "C1".into(), turn_session_id: "S1".into(), seq: 0, data: garbage.clone() },
        ))
        .await;

        // device 仍按控制面元数据收到，data 原样透传（relay 未解码）
        loop {
            match d.recv().await.expect("frame").msg {
                RelayControlMsg::Event { data, .. } => {
                    assert_eq!(data, garbage);
                    break;
                }
                _ => continue,
            }
        }
    }
```

- [ ] **Step 6: 跑测试**

Run: `cargo test -p agentdeck-relay relay_routes_opaque_data_without_decoding_it`
Expected: PASS。

- [ ] **Step 7: Commit**

```bash
git add agentdeck-relay/src/router.rs
git commit -m "feat(relay): 命令面——SendCommand 路由(Conversation/Turn/Machine)+AdminReply 关联+not_found；T3 内容不可见"
```

---

### Task 6: StdioMachineBridge + T1（真实 daemon admin 往返 + single-flight）

**Files:**
- Create: `agentdeck-relay/src/bridge.rs`
- Modify: `agentdeck-relay/src/lib.rs`（`mod bridge; pub use bridge::StdioMachineBridge;`）
- Modify: `agentdeckd/Cargo.toml`（`[dev-dependencies]` 加 agentdeck-relay + agentdeck-protocol）
- Test: `agentdeckd/tests/relay_r0_bridge.rs`

**Interfaces:**
- Consumes: `FakeRelay`、`RelayClient`、`agentdeck_protocol::{ClientCommand, remote::*}`。
- Produces: `StdioMachineBridge`（`async spawn(daemon_path: &Path, profile: &str, machine: MachineDescriptor, relay: &FakeRelay) -> std::io::Result<StdioMachineBridge>`、`async shutdown(self)`）。

- [ ] **Step 1: 写 bridge.rs**

```rust
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

use crate::router::{FakeRelay, RelayClient};

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
        relay: &FakeRelay,
    ) -> std::io::Result<StdioMachineBridge> {
        let machine_id = machine.machine_id.clone();
        let mut child = Command::new(daemon_path)
            .env("AGENTDECK_PROFILE", profile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("daemon stdin");
        let stdout = child.stdout.take().expect("daemon stdout");

        let client = relay.connect(ClientRole::Machine { machine_id: machine_id.clone() }).await;
        client
            .send(mk_frame(&machine_id, RelayControlMsg::RegisterMachine { machine }))
            .await;

        let pump = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            let mut client: RelayClient = client;
            // admin single-flight：请求 request_id FIFO 队列 + 待写命令行
            let mut admin_queue: VecDeque<(String, String)> = VecDeque::new();
            let mut admin_inflight = false;

            loop {
                tokio::select! {
                    // 来自 relay 的 device 命令
                    frame = client.recv() => {
                        let Some(frame) = frame else { break };
                        if let RelayControlMsg::SendCommand { request_id, target, data } = frame.msg {
                            let Ok(cmd) = data.decode_plaintext::<ClientCommand>() else { continue };
                            let line = match serde_json::to_string(&cmd) {
                                Ok(l) => l,
                                Err(_) => continue,
                            };
                            if is_admin(&cmd) && matches!(target, CommandTarget::Machine { .. }) {
                                admin_queue.push_back((request_id, line));
                                if !admin_inflight {
                                    if let Some((_, l)) = admin_queue.front() {
                                        let _ = stdin.write_all(l.as_bytes()).await;
                                        let _ = stdin.write_all(b"\n").await;
                                        let _ = stdin.flush().await;
                                        admin_inflight = true;
                                    }
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
                                client.send(mk_frame(&machine_id, RelayControlMsg::AdminReply { in_reply_to: req, data })).await;
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
                            client.send(mk_frame(&machine_id, RelayControlMsg::PublishEvent {
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
```

- [ ] **Step 2: 挂 bridge 模块**

改 `agentdeck-relay/src/lib.rs`：

```rust
mod bridge;
mod router;

pub use bridge::StdioMachineBridge;
pub use router::{FakeRelay, RelayClient};
```

- [ ] **Step 3: agentdeckd 加 dev-dependency**

在 `agentdeckd/Cargo.toml` 加（若无 `[dev-dependencies]` 段则新建）：

```toml
[dev-dependencies]
agentdeck-relay = { path = "../agentdeck-relay" }
```

（`agentdeckd` 已在 `[dependencies]` 依赖 `agentdeck-protocol`、`tokio`（含 rt/macros/sync/io-util）、`serde_json`，集成测试可直接复用，无需在 dev-deps 重复声明；只需新增对 `agentdeck-relay` 的 dev 依赖。）

- [ ] **Step 4: 写 T1 集成测试**

```rust
// agentdeckd/tests/relay_r0_bridge.rs
use std::path::Path;

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

async fn recv_admin_reply(d: &mut RelayClient, want: &str) -> serde_json::Value {
    loop {
        match d.recv().await.expect("frame").msg {
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
    let bridge = agentdeck_relay::StdioMachineBridge::spawn(daemon, "stable", machine(), &relay)
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
```

- [ ] **Step 5: 跑 T1（先构建 daemon 保证二进制存在）**

Run: `cargo test -p agentdeckd --test relay_r0_bridge`
Expected: PASS（`CARGO_BIN_EXE_agentdeckd` 由 cargo 自动构建并注入；真实 daemon 的 `{"reply":"ping","ok":true}` 经 bridge single-flight + relay 回到 device，r1/r2 各自关联）。

- [ ] **Step 6: Commit**

```bash
git add agentdeck-relay/src/bridge.rs agentdeck-relay/src/lib.rs agentdeckd/Cargo.toml agentdeckd/tests/relay_r0_bridge.rs
git commit -m "feat(relay): StdioMachineBridge（真实 daemon 接入 + admin single-flight）+ T1 admin 往返集成测试"
```

---

### Task 7: CLI `remote` 命令面（接口基线）+ 单进程 `remote smoke`

**Files:**
- Modify: `agentdeck-cli/Cargo.toml`（deps 加 agentdeck-relay + tokio 若缺）
- Modify: `agentdeck-cli/src/main.rs`（`Cmd` 加 `Remote` 变体 + `RemoteOp` 枚举 + 分发）
- Create: `agentdeck-cli/src/remote.rs`（smoke 驱动 + 命令面骨架）
- Test: `agentdeck-cli/src/remote.rs`（`#[cfg(test)]` 单进程 smoke 断言）

**Interfaces:**
- Consumes: `agentdeck_relay::{FakeRelay, StdioMachineBridge, RelayClient}`、`agentdeck-cli` 的 `transport::locate_daemon()`。
- Produces: CLI 子命令 `agentdeck remote <op>`，其中 `smoke` 为 R0 唯一可执行路径；`machines/sessions/watch/send/approve/deny/ping` 为冻结的语义基线，R0 对非 `smoke` 打印「需 R1 relay endpoint」提示。

- [ ] **Step 1: CLI 依赖**

在 `agentdeck-cli/Cargo.toml` `[dependencies]` 加：

```toml
agentdeck-relay = { path = "../agentdeck-relay" }
```

（`agentdeck-cli` 已有 tokio；若 `remote.rs` 用到的 feature 缺失，补 `sync`/`macros`。）

- [ ] **Step 2: main.rs 加 Remote 子命令**

在 `enum Cmd` 加变体（放 `History { op: HistoryOp }` 之后）：

```rust
    /// Remote relay 客户端（R0：仅 `smoke` 可执行；其余为接口基线占位）
    Remote {
        #[command(subcommand)]
        op: RemoteOp,
    },
```

在 `HistoryOp` 等子枚举附近新增：

```rust
#[derive(clap::Subcommand)]
enum RemoteOp {
    /// 单进程 R0 冒烟：内存 FakeRelay + 真实 daemon bridge + device 驱动
    Smoke,
    /// 列出机器（R1 relay endpoint 就绪后可独立运行）
    Machines,
    /// 列出某机器的会话
    Sessions { machine_id: String },
    /// 流式查看某 conversation
    Watch { conversation_id: String },
    /// 向 conversation 发 prompt
    Send { conversation_id: String, text: String },
    /// 批准某 turn 的审批
    Approve { turn_session_id: String, request_id: String },
    /// 拒绝某 turn 的审批
    Deny { turn_session_id: String, request_id: String },
    /// 机器级 admin 往返
    Ping { machine_id: String },
}
```

在 async `main()` 的命令分发处（Session 命令旁）加：

```rust
        Cmd::Remote { op } => crate::remote::run(op, &cli.profile, cli.data_dir.as_deref()).await,
```

并在 main.rs 顶部 `mod` 声明区加 `mod remote;`。

- [ ] **Step 3: 写 remote.rs（smoke 驱动 + 基线占位）**

```rust
// agentdeck-cli/src/remote.rs
use std::process::ExitCode;

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, DataEnvelope, DeviceDescriptor, DeviceKind, MachineDescriptor,
    RelayControlMsg, RemoteFrame, SubTarget,
};
use agentdeck_protocol::ClientCommand;
use agentdeck_relay::{FakeRelay, RelayClient, StdioMachineBridge};

use crate::transport::locate_daemon;

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
    RemoteFrame::control(ClientRole::Device { device_id: "cli".into() }, "smoke".into(), 0, msg)
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

    let mut d = relay.connect(ClientRole::Device { device_id: "cli".into() }).await;
    d.send(dev(RelayControlMsg::ConnectDevice {
        device: DeviceDescriptor { device_id: "cli".into(), kind: DeviceKind::Cli },
    }))
    .await;
    d.send(dev(RelayControlMsg::Subscribe { target: SubTarget::Machines })).await;

    // 1) machines 快照
    if let Some(frame) = d.recv().await {
        if let RelayControlMsg::MachineList { machines } = frame.msg {
            println!("[smoke] machines: {}  (trace={})", machines.len(), frame.trace_id);
            for m in machines {
                println!("  - {} online={} v{}", m.machine_id, m.is_online, m.agentdeck_protocol_version);
            }
        }
    }

    // 2) ping 机器级 admin 往返
    d.send(dev(RelayControlMsg::SendCommand {
        request_id: "smoke-ping".into(),
        target: CommandTarget::Machine { machine_id: "local".into() },
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

async fn wait_admin_reply(d: &mut RelayClient, want: &str) -> bool {
    for _ in 0..64 {
        match d.recv().await {
            Some(frame) => {
                if let RelayControlMsg::AdminReply { in_reply_to, data } = frame.msg {
                    if in_reply_to == want {
                        let v: serde_json::Value = data.decode_plaintext().unwrap_or_default();
                        println!("[smoke] admin reply: {v}");
                        return v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
                    }
                }
            }
            None => return false,
        }
    }
    false
}

/// R0：非 smoke 子命令是冻结的接口基线，需 R1 的 relay endpoint 才能独立运行。
fn baseline_stub(name: &str) -> ExitCode {
    eprintln!("remote.{name}: 接口基线已冻结；独立运行需 R1 relay endpoint（`--relay ws://…`）。R0 请用 `agentdeck remote smoke`。");
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

/// main.rs 的 RemoteOp 到本模块的窄化映射（避免 clap 类型泄漏进逻辑层）。
pub enum RemoteOpArg { Smoke, Machines, Sessions, Watch, Send, Approve, Deny, Ping }
```

> 注：为保持 `main.rs` 与 `remote.rs` 解耦，在 `main.rs` 的分发处把 `RemoteOp` 映射成 `remote::RemoteOpArg` 再调 `remote::run`。即把 Step 2 的分发行改为：
> ```rust
>         Cmd::Remote { op } => {
>             let arg = match op {
>                 RemoteOp::Smoke => crate::remote::RemoteOpArg::Smoke,
>                 RemoteOp::Machines => crate::remote::RemoteOpArg::Machines,
>                 RemoteOp::Sessions { .. } => crate::remote::RemoteOpArg::Sessions,
>                 RemoteOp::Watch { .. } => crate::remote::RemoteOpArg::Watch,
>                 RemoteOp::Send { .. } => crate::remote::RemoteOpArg::Send,
>                 RemoteOp::Approve { .. } => crate::remote::RemoteOpArg::Approve,
>                 RemoteOp::Deny { .. } => crate::remote::RemoteOpArg::Deny,
>                 RemoteOp::Ping { .. } => crate::remote::RemoteOpArg::Ping,
>             };
>             crate::remote::run(arg, &cli.profile, cli.data_dir.as_deref()).await
>         }
> ```
> （`main()` 返回 `ExitCode`；若现有 `main` 返回 `()`，用 `std::process::exit(code)` 收口，与既有 Session 分支风格一致。）

- [ ] **Step 4: 写 smoke 单测**

在 `agentdeck-cli/src/remote.rs` 末尾加：

```rust
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
```

- [ ] **Step 5: 构建并跑 smoke（人工 + 单测）**

Run: `cargo build -p agentdeckd && cargo run -p agentdeck-cli -- remote smoke`
Expected: 打印 `[smoke] machines: 1 …`、`[smoke] admin reply: {"reply":"ping","ok":true}`、`[smoke] ping round-trip OK`，退出码 0。

Run: `cargo build -p agentdeckd && cargo test -p agentdeck-cli remote::tests::smoke_pings_real_daemon_through_relay`
Expected: PASS（daemon 已构建时）。

- [ ] **Step 6: Commit**

```bash
git add agentdeck-cli/Cargo.toml agentdeck-cli/src/main.rs agentdeck-cli/src/remote.rs
git commit -m "feat(cli): remote 命令面（接口基线）+ 单进程 remote smoke（FakeRelay+bridge+device 驱动）"
```

---

### Task 8: T2 合成会话全流集成测试 + T4 gated 真实会话 E2E

**Files:**
- Create: `agentdeck-relay/tests/r0_composition.rs`（T2 合成机器全流，ungated）
- Create: `agentdeckd/tests/relay_r0_e2e.rs`（T4 真实 Codex/CC 全流，`AGENTDECK_E2E=1` gated）

**Interfaces:**
- Consumes: `FakeRelay`、`RelayClient`、`agentdeck_protocol::{ServerEvent, ClientCommand, remote::*}`。
- Produces: 无新符号；固化验收。

- [ ] **Step 1: 写 T2 合成全流测试**

```rust
// agentdeck-relay/tests/r0_composition.rs
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
        machine_id: "M1".into(), name: "syn".into(),
        agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
        is_online: true, last_heartbeat_ms: None,
    }
}
fn session() -> SessionDescriptor {
    SessionDescriptor {
        conversation_id: "C1".into(), machine_id: "M1".into(),
        thread_id: Some("C1".into()), current_turn_session_id: Some("S1".into()),
        agent_kind: AgentKind::Codex, cwd: "/tmp/proj".into(), title: None,
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

async fn next_event(d: &mut RelayClient) -> (String, u64, ServerEvent) {
    loop {
        match d.recv().await.expect("frame").msg {
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
    d.send(d_frame(RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into() } })).await;

    // turn A（session S1）
    publish_event(&m, "C1", "S1", &ServerEvent::SessionStarted {
        session_id: SessionId("S1".into()), thread_id: Some(ThreadId("C1".into())), agent_kind: AgentKind::Codex,
    }).await;
    publish_event(&m, "C1", "S1", &ServerEvent::TurnComplete {
        session_id: SessionId("S1".into()), thread_id: ThreadId("C1".into()), agent_kind: AgentKind::Codex,
        summary: agentdeck_protocol::TurnSummary { total_input_tokens: None, total_output_tokens: None, elapsed_ms: 10 },
    }).await;
    // turn B（session S2，同 conversation C1）——模拟 prompt 触发新 turn
    publish_event(&m, "C1", "S2", &ServerEvent::SessionStarted {
        session_id: SessionId("S2".into()), thread_id: Some(ThreadId("C1".into())), agent_kind: AgentKind::Codex,
    }).await;
    publish_event(&m, "C1", "S2", &ServerEvent::TurnComplete {
        session_id: SessionId("S2".into()), thread_id: ThreadId("C1".into()), agent_kind: AgentKind::Codex,
        summary: agentdeck_protocol::TurnSummary { total_input_tokens: None, total_output_tokens: None, elapsed_ms: 20 },
    }).await;

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
```

- [ ] **Step 2: 跑 T2**

Run: `cargo test -p agentdeck-relay --test r0_composition`
Expected: PASS。

- [ ] **Step 3: 写 T4 gated E2E**

```rust
// agentdeckd/tests/relay_r0_e2e.rs
//! 门控 E2E：真实 Codex/CC 会话流经 relay 穿透。默认跳过；需 AGENTDECK_E2E=1 + 已登录。
use std::path::Path;

use agentdeck_protocol::remote::{
    ClientRole, CommandTarget, DataEnvelope, MachineDescriptor, RelayControlMsg, RemoteFrame,
};
use agentdeck_protocol::{AgentKind, ClientCommand, ServerEvent};
use agentdeck_relay::{FakeRelay, RelayClient};

fn machine() -> MachineDescriptor {
    MachineDescriptor {
        machine_id: "M1".into(), name: "e2e".into(),
        agentdeck_protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
        is_online: true, last_heartbeat_ms: None,
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
    // 用 best-effort 订阅（真实 daemon 的 conversation=thread/session）；本测试断言至少收到一个
    // SessionStarted 事件穿透 relay。真实会话经 SendCommand{Machine} 发 SessionStart。
    let start = ClientCommand::SessionStart(agentdeck_protocol::SessionStart {
        agent_kind: AgentKind::Codex,
        cwd: std::env::current_dir().unwrap(),
        prompt: Some("say hi and stop".into()),
        vendor_options: agentdeck_protocol::VendorSessionOptions::Codex(Default::default()),
        runtime_options: Default::default(),
    });
    // R0 e2e 简化：直接把 SessionStart 作为机器级命令写给 daemon（bridge 会写 stdin）。
    d.send(RemoteFrame::control(
        ClientRole::Device { device_id: "D1".into() },
        "e2e".into(), 0,
        RelayControlMsg::SendCommand {
            request_id: "e1".into(),
            target: CommandTarget::Machine { machine_id: "M1".into() },
            data: DataEnvelope::plaintext(&start).unwrap(),
        },
    ))
    .await;
    // 但 SessionStart 不是 admin；bridge 会立即写 stdin，daemon 产生 ServerEvent 流经 relay。
    // 订阅所有事件（best-effort：conversation=thread/session）——这里轮询 Event 帧。
    let ok = wait_session_started(&mut d).await;
    bridge.shutdown().await;
    assert!(ok, "未在 relay 上收到 SessionStarted");
}

async fn wait_session_started(d: &mut RelayClient) -> bool {
    for _ in 0..2000 {
        match tokio::time::timeout(std::time::Duration::from_secs(30), d.recv()).await {
            Ok(Some(frame)) => {
                if let RelayControlMsg::Event { data, .. } = frame.msg {
                    if let Ok(ev) = data.decode_plaintext::<ServerEvent>() {
                        if matches!(ev, ServerEvent::SessionStarted { .. }) {
                            return true;
                        }
                    }
                }
            }
            _ => return false,
        }
    }
    false
}
```

> 注：T4 的 device 需订阅事件。因 bridge 对 real daemon 用 best-effort（conversation=threadId 或 sessionId），本测试直接轮询任意 `Event` 帧并匹配 `SessionStarted`。若需按 conversation 订阅，可先不订阅、依赖 relay 对已 buffer 的 conversation 无 subscriber 时不推送——故本测试改为：在发命令前对 `SubTarget::Events` 用通配不可行，遂采用「bridge 发 PublishEvent 时 relay 仍写入 buffer」+「订阅所有出现的 conversation」。R0 gated 测试允许这一简化，真实按 conversation 精确订阅留待 R2 身份 bootstrap。

- [ ] **Step 4: 跑 T4（默认跳过 + 手动 gated）**

Run: `cargo test -p agentdeckd --test relay_r0_e2e`
Expected: 打印 skip、PASS（默认无 AGENTDECK_E2E）。

Run（手动，需登录）: `AGENTDECK_E2E=1 cargo test -p agentdeckd --test relay_r0_e2e -- --nocapture`
Expected: PASS（真实 SessionStarted 经 relay 穿透）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/tests/r0_composition.rs agentdeckd/tests/relay_r0_e2e.rs
git commit -m "test(relay): T2 合成会话全流(稳定身份穿透) + T4 gated 真实会话 E2E"
```

---

### Task 9: 文档收口 + 全量验证

**Files:**
- Modify: `README.md`（v0.5/v0.4+ 处加 R 阶段交叉引用）
- Modify: `docs/plans/2026-06-30-unified-shell-v02-design.md`（同上交叉引用）
- Modify: `docs/index.md`（登记 R0 design + implementation）
- Modify: `docs/plans/2026-07-01-agentdeck-mobile-relay-design.md`（状态更新 + RemoteEnvelope 细化注记）

**Interfaces:** 无代码接口。

- [ ] **Step 1: README/unified-shell 交叉引用**

在 `README.md` 路线图表「v0.5 daemon 远程化」条目后加：`（= Relay 母设计 R1 Relay MVP + R2 remote mode；R0 契约 spike 见 docs/plans/2026-07-07-relay-r0-contract-spike-design.md）`；「移动伴侣 v0.4+」后加：`（= Relay R3）`。在 `docs/plans/2026-06-30-unified-shell-v02-design.md` 对应 daemon 远程化处加同一行交叉引用。

- [ ] **Step 2: docs/index.md 登记**

在 `docs/index.md` 计划文档索引处加两行：R0 design 与 R0 implementation 的条目（路径 + 一句话）。

- [ ] **Step 3: 更新母设计状态**

把 `docs/plans/2026-07-01-agentdeck-mobile-relay-design.md` 元数据表 `状态` 改为 `Design - R0 落地中`；在 §6 `RemoteEnvelope` 处加注记：`R0 已将其细化为控制面（RemoteFrame + RelayControlMsg，relay 可读）+ 数据面（DataEnvelope，relay 不可见）两层，见 2026-07-07-relay-r0-contract-spike-design.md`。

- [ ] **Step 4: 文档结构校验**

Run: `bash scripts/verify-agent-docs.sh`
Expected: `verify-agent-docs: ok`。

- [ ] **Step 5: 全量验证**

Run: `cargo test`
Expected: 全 workspace 绿（含 protocol remote 往返/中立性/schema 快照、relay 单测、T1 bridge、T2 composition、T4 默认跳过；agentdeck-cli remote smoke 单测在 daemon 已构建时通过）。

Run: `cargo run -q -p agentdeck-cli -- protocol schema | diff - protocol/agentdeck/agentdeck-protocol.schema.json && echo "schema in sync"`
Expected: `schema in sync`。

Run: `git status --short --branch`
Expected: 工作区干净（除既有无关改动），无未跟踪产物。

- [ ] **Step 6: Commit**

```bash
git add README.md docs/plans/2026-06-30-unified-shell-v02-design.md docs/index.md docs/plans/2026-07-01-agentdeck-mobile-relay-design.md
git commit -m "docs(relay): R0 落地收口——版本↔阶段交叉引用、index 登记、母设计状态更新"
```

---

## 完成标准（对齐设计 §7 验收）

- `cargo test` 全绿：协议 remote 往返 + N1 中立性 + schema 快照无漂移；relay 机器/事件/命令面单测；T1 真实 daemon admin 往返（含并发关联）；T2 合成会话稳定身份穿透 + 补拉；T3 内容不可见；T4 默认跳过。
- `agentdeck remote smoke` 单进程打印 machines 快照 + `{"reply":"ping","ok":true}` + round-trip OK。
- gated `AGENTDECK_E2E=1 cargo test -p agentdeckd --test relay_r0_e2e` 下 T4 **编译 + 默认 skip 通过**；真实穿透留 R2——R0 订阅模型需已知 conversation_id 精确订阅（无通配目标），真实 daemon 场景下 device 无法预知 conversation_id，即使手动设置 `AGENTDECK_E2E=1` 运行也会超时失败，非 R0 验收项（详见设计文档 §7 实现偏差记录）。
- 无任何 crate 启用 tokio `net`；relay/bridge 不经手 vendor token、不写数据目录。
- relay 明文不入日志：R0 的 `FakeRelay`/`StdioMachineBridge` 不引入 `tracing`、不打印数据面内容，日志边界由「零日志构造」保证（R1 引入日志时再补明文脱敏断言）。
- `scripts/verify-agent-docs.sh` 通过；schema 快照与生成一致。
