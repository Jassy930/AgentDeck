# 统一接口层（CLI 契约）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把中立 IPC 协议抽成版本化、从 Rust 类型生成 schema 的 `agentdeck-protocol` crate，并新增参考客户端 `agentdeck` CLI 作为契约的可执行体现与门控 E2E 驱动；前端实时通路与 Swift 代码本轮不动。

**Architecture:** 新增两个 cargo crate：`agentdeck-protocol`（中立类型 + schemars，协议事实源，daemon 与 CLI 共用）与 `agentdeck-cli`（binary `agentdeck`，spawn `agentdeckd` 并讲同一套 JSONL，暴露与协议 1:1 的子命令 + 稳定 JSON/退出码契约）。`agentdeckd` 仅把 `ipc` 模块改成 re-export 壳，对外 stdio 行为字节级不变。

**Tech Stack:** Rust（edition 2024，workspace）、serde / serde_json、schemars 0.8（schema 生成）、clap 4（CLI 参数）。Rust 工具用 cargo；门控 E2E 用 Rust 集成测试。

## Global Constraints

- 设计依据：`docs/plans/2026-06-29-unified-interface-cli-design.md`（本计划逐条覆盖它）。
- 中立性：`agentdeck-protocol` 与 `agentdeck-cli` 的序列化产物**不得出现 `codex` / `openai`**（guard test 强制）。
- 本轮**不改 Swift 代码**、**不加 mock adapter**、**不新增后端能力**、**不改 `IpcMessage` 线格式**。
- A1 生命周期：CLI 进程退出时不得留下孤儿 `agentdeckd` / codex 子进程；正常路径优先发 `shutdown` 优雅退出，Drop 杀进程作为兜底。
- profile / 数据目录：CLI 透传 `--profile`→`AGENTDECK_PROFILE`，`--data-dir`→`AGENTDECK_DATA_DIR`（后者优先，沿用 daemon 现状）。
- 不读不存不转发 token；CLI 不新增任何持久化通道。
- `agentdeckd` 既有 `cargo test` 与 `swift test` 全程保持绿；daemon 对外 stdio JSONL 字节级不变。
- 退出码契约：`0` 成功 / `2` 用法错误 / `3` 协议错误 / `4` 传输错误 / `5` 会话或自检失败。
- 提交信息用 conventional commit 前缀，**不含任何协作者 / co-author 信息**。
- 每个阶段性收口运行 `scripts/verify-agent-docs.sh`，并 `git status --short --branch` 查看状态。
- `Cargo.lock` 必须提交（锁定 schemars 等版本，保证 schema drift 测试跨机一致）。

---

### Task 1: 抽出 `agentdeck-protocol` crate（纯重构，行为不变）

把 `agentdeckd/src/ipc.rs` 整体迁移为独立 crate，daemon 用 re-export 壳保持所有现有引用零改动。

**Files:**
- Create: `agentdeck-protocol/Cargo.toml`
- Create: `agentdeck-protocol/src/lib.rs`（内容 = 现 `agentdeckd/src/ipc.rs` 全文，含其 `#[cfg(test)] mod tests`）
- Modify: `Cargo.toml`（workspace members 增加 `agentdeck-protocol`）
- Modify: `agentdeckd/Cargo.toml`（dependencies 增加 `agentdeck-protocol`）
- Modify: `agentdeckd/src/ipc.rs`（清空为 re-export 壳）

**Interfaces:**
- Produces: crate `agentdeck_protocol` 导出现有全部公开类型与 `impl`：`IpcMessage`（含 `pong/error/agent_item/session_state/session_event/action_request`）、`SessionState`、`Lifecycle`、`ActionRequest`、`ActionDecision`、`AgentItem`、`AgentItemKind`、`AgentReference`、`HookFragment`、`FileEditChange`、`ToolAction`、`HistoryThreadSummary`、`HistoryThreadList`、`HistoryThreadDetail`。
- Consumes（保持不变）：`agentdeckd` 中 `main.rs` 的 `use ipc::{...}` / `ipc::Lifecycle`、`codex.rs` 的 `use crate::ipc::{...}` 全部继续编译。

- [ ] **Step 1: 创建 protocol crate 的 Cargo.toml**

`agentdeck-protocol/Cargo.toml`：
```toml
[package]
name = "agentdeck-protocol"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "AgentDeck neutral IPC protocol — agent-neutral contract, source of truth for daemon and clients"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 2: 迁移 ipc.rs 内容到 lib.rs**

把 `agentdeckd/src/ipc.rs` 的**全文**（含文件头 doc 注释、所有类型、`impl IpcMessage`、以及 `#[cfg(test)] mod tests`）原样写入 `agentdeck-protocol/src/lib.rs`，不改任何代码。

- [ ] **Step 3: 把 daemon 的 ipc.rs 改成 re-export 壳**

把 `agentdeckd/src/ipc.rs` 全文替换为：
```rust
//! Neutral IPC protocol — now sourced from the `agentdeck-protocol` crate.
//!
//! The types live in `agentdeck-protocol` so daemon and CLI/clients share one
//! source of truth. This re-export keeps `crate::ipc::X` / `ipc::X` references
//! (main.rs, codex.rs) compiling unchanged.
pub use agentdeck_protocol::*;
```

- [ ] **Step 4: 注册 workspace member 与依赖**

`Cargo.toml`（根）members 改为：
```toml
[workspace]
members = ["agentdeckd", "agentdeck-protocol"]
resolver = "3"
```

`agentdeckd/Cargo.toml` 的 `[dependencies]` 增加一行：
```toml
agentdeck-protocol = { path = "../agentdeck-protocol" }
```

- [ ] **Step 5: 运行测试验证零行为变化**

Run: `cargo test`
Expected: PASS。`agentdeck-protocol` 跑迁移过去的协议 / 中立性 / per-kind 测试；`agentdeckd` 全部既有测试仍通过（dispatch、runtime hub 等）。

- [ ] **Step 6: 提交**

```bash
git add Cargo.toml Cargo.lock agentdeck-protocol agentdeckd/Cargo.toml agentdeckd/src/ipc.rs
git commit -m "refactor(protocol): extract neutral IPC types into agentdeck-protocol crate"
```

---

### Task 2: 协议版本 + schemars schema 生成 + 快照漂移测试

给 protocol crate 加版本常量、`schemars` 派生与 schema 生成函数，落地提交快照并加 drift 测试。

**Files:**
- Modify: `agentdeck-protocol/Cargo.toml`（加 `schemars`）
- Modify: `agentdeck-protocol/src/lib.rs`（加 `JsonSchema` 派生、`PROTOCOL_VERSION`、`protocol_schema()`、drift 测试）
- Create: `protocol/agentdeck/agentdeck-protocol.schema.json`（生成的快照）
- Create: `protocol/agentdeck/README.md`

**Interfaces:**
- Produces: `agentdeck_protocol::PROTOCOL_VERSION: u32`（= 1）、`agentdeck_protocol::protocol_schema() -> serde_json::Value`。
- Consumes: 无新增外部消费。

- [ ] **Step 1: 加 schemars 依赖**

`agentdeck-protocol/Cargo.toml` 的 `[dependencies]` 增加：
```toml
schemars = "0.8"
```

- [ ] **Step 2: 给所有协议类型派生 JsonSchema**

在 `agentdeck-protocol/src/lib.rs` 顶部 `use` 区加：
```rust
use schemars::JsonSchema;
```
给**每个**会序列化上线的 struct / enum 的 `#[derive(...)]` 追加 `JsonSchema`：`IpcMessage`、`SessionState`、`ActionRequest`、`Lifecycle`、`AgentItem`、`AgentItemKind`、`AgentReference`、`HookFragment`、`FileEditChange`、`ToolAction`、`HistoryThreadSummary`、`HistoryThreadList`、`HistoryThreadDetail`。
（`ActionDecision` 不上线为 typed 结构、且字段名与 wire 不一致，**不派生、不纳入 schema**，其 wire 形态在 protocol README 用文字说明。）

- [ ] **Step 3: 加版本常量与 schema 生成函数**

在 `agentdeck-protocol/src/lib.rs` 末尾（`#[cfg(test)]` 之前）加：
```rust
/// 契约产物版本。改动协议形态时手动 +1，并重生成快照。
pub const PROTOCOL_VERSION: u32 = 1;

/// 生成版本化 JSON Schema 文档（聚合各 typed 协议组件）。
/// 这是 `agentdeck protocol schema` 与 drift 测试的唯一来源。
pub fn protocol_schema() -> serde_json::Value {
    let mut defs = serde_json::Map::new();
    macro_rules! add {
        ($t:ty) => {
            defs.insert(
                stringify!($t).to_string(),
                serde_json::to_value(schemars::schema_for!($t)).expect("schema serializes"),
            );
        };
    }
    add!(IpcMessage);
    add!(SessionState);
    add!(ActionRequest);
    add!(Lifecycle);
    add!(AgentItem);
    add!(AgentItemKind);
    add!(AgentReference);
    add!(HookFragment);
    add!(FileEditChange);
    add!(ToolAction);
    add!(HistoryThreadSummary);
    add!(HistoryThreadList);
    add!(HistoryThreadDetail);

    serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "AgentDeck Neutral Protocol",
        "protocolVersion": PROTOCOL_VERSION,
        "definitions": serde_json::Value::Object(defs),
    })
}
```

- [ ] **Step 4: 写 drift 测试（支持 UPDATE_SCHEMA 落盘模式）**

在 `agentdeck-protocol/src/lib.rs` 的 `#[cfg(test)] mod tests` 内追加：
```rust
#[test]
fn protocol_version_is_positive() {
    assert!(super::PROTOCOL_VERSION >= 1);
}

#[test]
fn schema_matches_committed_snapshot() {
    let generated = serde_json::to_string_pretty(&super::protocol_schema()).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol/agentdeck/agentdeck-protocol.schema.json");
    if std::env::var("UPDATE_SCHEMA").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("schema snapshot missing; run `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`")
    });
    assert_eq!(
        generated, committed,
        "protocol schema drifted; run `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` to regenerate"
    );
}

#[test]
fn protocol_schema_has_no_vendor_names() {
    let wire = serde_json::to_string(&super::protocol_schema()).unwrap().to_lowercase();
    assert!(!wire.contains("codex"), "vendor name leaked into schema");
    assert!(!wire.contains("openai"), "vendor name leaked into schema");
}
```

- [ ] **Step 5: 先确认测试在缺快照时失败**

Run: `cargo test -p agentdeck-protocol schema_matches_committed_snapshot`
Expected: FAIL（panic：`schema snapshot missing; run UPDATE_SCHEMA=1 ...`）。

- [ ] **Step 6: 生成并落盘快照**

Run: `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`
Expected: PASS，并生成 `protocol/agentdeck/agentdeck-protocol.schema.json`。

- [ ] **Step 7: 复跑确认 drift 测试稳定通过**

Run: `cargo test -p agentdeck-protocol`
Expected: PASS（含 drift / version / 中立性 / 既有协议测试）。

- [ ] **Step 8: 写 protocol/agentdeck/README.md**

`protocol/agentdeck/README.md`：
```markdown
# AgentDeck 中立协议 schema

`agentdeck-protocol.schema.json` 是**生成产物**，由 `agentdeck-protocol::protocol_schema()`
从 Rust 类型生成，**不要手写**。

## 重新生成
- 推荐：`agentdeck protocol schema > protocol/agentdeck/agentdeck-protocol.schema.json`
- 或：`UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`

## 版本
`protocolVersion` = `agentdeck-protocol::PROTOCOL_VERSION`。改动协议形态时 +1 并重生成快照，
`cargo test` 的 drift 测试会在类型与快照脱节时失败。

## actionDecision 线形态（非 typed 结构，故不在 schema）
`{ "kind": "actionDecision", "id": <u64>, "sessionId": <string>,
   "payload": { "requestId": <u64>, "decision": "approve"|"deny"|"cancel" } }`
```

- [ ] **Step 9: 提交**

```bash
git add agentdeck-protocol Cargo.lock protocol/agentdeck
git commit -m "feat(protocol): version constant, schemars schema generation, snapshot + drift test"
```

---

### Task 3: 脚手架 `agentdeck-cli` crate + 本地 `protocol` 子命令 + 输出契约

建 CLI crate 与 clap 骨架、全局参数、输出/退出码模块，先实现不需要 daemon 的 `protocol version|schema`。

**Files:**
- Create: `agentdeck-cli/Cargo.toml`
- Create: `agentdeck-cli/src/main.rs`（clap 定义 + dispatch）
- Create: `agentdeck-cli/src/output.rs`（退出码、JSON 打印、错误信封）
- Modify: `Cargo.toml`（members 增加 `agentdeck-cli`）

**Interfaces:**
- Produces:
  - `output::CliError`（变体 `Usage(String)` / `Protocol(String)` / `Transport(String)` / `Session(String)`）与 `output::CliError::exit_code(&self) -> i32`。
  - `output::print_json(value: &serde_json::Value, pretty: bool)`、`output::print_error(err: &CliError, pretty: bool)`。
  - `output::req(kind: &str, payload: Option<serde_json::Value>) -> agentdeck_protocol::IpcMessage`。
  - clap 全局参数：`--profile <stable|dev>`（默认 `stable`）、`--data-dir <path>`、`--pretty`。
- Consumes: `agentdeck_protocol::{protocol_schema, PROTOCOL_VERSION, IpcMessage}`。

- [ ] **Step 1: 创建 CLI crate 的 Cargo.toml**

`agentdeck-cli/Cargo.toml`：
```toml
[package]
name = "agentdeck-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "AgentDeck unified CLI — reference client and contract conformance / E2E driver"

[[bin]]
name = "agentdeck"
path = "src/main.rs"

[dependencies]
agentdeck-protocol = { path = "../agentdeck-protocol" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
```

- [ ] **Step 2: 注册 workspace member**

`Cargo.toml`（根）members 改为：
```toml
members = ["agentdeckd", "agentdeck-protocol", "agentdeck-cli"]
```

- [ ] **Step 3: 写 output.rs（含失败测试）**

`agentdeck-cli/src/output.rs`：
```rust
//! 稳定的输出与退出码契约。E2E 断言对象。
use agentdeck_protocol::IpcMessage;

#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Protocol(String),
    Transport(String),
    Session(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 2,
            CliError::Protocol(_) => 3,
            CliError::Transport(_) => 4,
            CliError::Session(_) => 5,
        }
    }
    pub fn code_str(&self) -> &'static str {
        match self {
            CliError::Usage(_) => "usage",
            CliError::Protocol(_) => "protocol",
            CliError::Transport(_) => "transport",
            CliError::Session(_) => "session",
        }
    }
    pub fn message(&self) -> &str {
        match self {
            CliError::Usage(m) | CliError::Protocol(m) | CliError::Transport(m) | CliError::Session(m) => m,
        }
    }
}

pub fn req(kind: &str, payload: Option<serde_json::Value>) -> IpcMessage {
    IpcMessage { kind: kind.to_string(), id: None, session_id: None, thread_id: None, payload }
}

pub fn render(value: &serde_json::Value, pretty: bool) -> String {
    if pretty {
        serde_json::to_string_pretty(value).expect("json")
    } else {
        serde_json::to_string(value).expect("json")
    }
}

pub fn error_envelope(err: &CliError) -> serde_json::Value {
    serde_json::json!({ "error": { "code": err.code_str(), "message": err.message() } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_contract() {
        assert_eq!(CliError::Usage("x".into()).exit_code(), 2);
        assert_eq!(CliError::Protocol("x".into()).exit_code(), 3);
        assert_eq!(CliError::Transport("x".into()).exit_code(), 4);
        assert_eq!(CliError::Session("x".into()).exit_code(), 5);
    }

    #[test]
    fn error_envelope_has_code_and_message() {
        let v = error_envelope(&CliError::Protocol("boom".into()));
        assert_eq!(v["error"]["code"], "protocol");
        assert_eq!(v["error"]["message"], "boom");
    }

    #[test]
    fn req_builds_neutral_message() {
        let m = req("ping", None);
        assert_eq!(m.kind, "ping");
        assert!(m.id.is_none() && m.payload.is_none());
    }
}
```

- [ ] **Step 4: 写 main.rs（clap 骨架 + protocol 子命令）**

`agentdeck-cli/src/main.rs`：
```rust
mod output;

use clap::{Parser, Subcommand};
use output::{render, CliError};

#[derive(Parser)]
#[command(name = "agentdeck", about = "AgentDeck unified interface CLI")]
struct Cli {
    /// AgentDeck profile（仅影响 AgentDeck 自管理数据目录）
    #[arg(long, global = true, default_value = "stable")]
    profile: String,
    /// 覆盖数据目录（优先于 profile）
    #[arg(long, global = true)]
    data_dir: Option<String>,
    /// 人读 pretty 输出（E2E 不依赖）
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 协议自省
    Protocol {
        #[command(subcommand)]
        what: ProtocolCmd,
    },
}

#[derive(Subcommand)]
enum ProtocolCmd {
    /// 输出版本化 JSON Schema
    Schema,
    /// 输出协议版本号
    Version,
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Protocol { what } => match what {
            ProtocolCmd::Schema => {
                // schema 始终 pretty（它是文档产物），与 drift 快照一致
                println!("{}", serde_json::to_string_pretty(&agentdeck_protocol::protocol_schema()).expect("json"));
                Ok(())
            }
            ProtocolCmd::Version => {
                let v = serde_json::json!({ "protocolVersion": agentdeck_protocol::PROTOCOL_VERSION });
                println!("{}", render(&v, cli.pretty));
                Ok(())
            }
        },
    }
}

fn main() {
    let cli = Cli::parse();
    let pretty = cli.pretty;
    if let Err(err) = run(cli) {
        eprintln!("agentdeck: {}", err.message());
        println!("{}", render(&output::error_envelope(&err), pretty));
        std::process::exit(err.exit_code());
    }
}
```

- [ ] **Step 5: 运行测试 + 手验 protocol 子命令**

Run: `cargo test -p agentdeck-cli`
Expected: PASS（output 模块单元测试）。

Run: `cargo run -p agentdeck-cli -- protocol version`
Expected: 输出 `{"protocolVersion":1}`。

Run: `diff <(cargo run -q -p agentdeck-cli -- protocol schema) <(sed '$d' protocol/agentdeck/agentdeck-protocol.schema.json)`
Expected: 无差异（CLI schema 输出与快照仅差末尾换行；`sed '$d'` 去掉快照末行空行后逐字相同）。

- [ ] **Step 6: 提交**

```bash
git add agentdeck-cli Cargo.toml Cargo.lock
git commit -m "feat(cli): scaffold agentdeck CLI with output contract and protocol introspection"
```

---

### Task 4: `Transport` 抽象 + 内存 Fake（可测的传输缝）

引入传输 trait，使客户端关联/流式逻辑可在无 daemon 下单测。

**Files:**
- Create: `agentdeck-cli/src/transport.rs`
- Modify: `agentdeck-cli/src/main.rs`（加 `mod transport;`）

**Interfaces:**
- Produces:
  - `trait transport::Transport { fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()>; fn recv(&mut self) -> std::io::Result<Option<IpcMessage>>; }`（`recv` 返回 `Ok(None)` 表示 EOF/断连）。
  - `transport::FakeTransport`（字段 `pub sent: Vec<IpcMessage>`；构造 `FakeTransport::new(incoming: Vec<IpcMessage>)`）。
- Consumes: `agentdeck_protocol::IpcMessage`。

- [ ] **Step 1: 写 transport.rs（trait + Fake + 测试）**

`agentdeck-cli/src/transport.rs`：
```rust
use agentdeck_protocol::IpcMessage;
use std::collections::VecDeque;

/// 阻塞式单连接传输缝。`recv` 返回 `Ok(None)` 表示 daemon EOF/断连。
pub trait Transport {
    fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()>;
    fn recv(&mut self) -> std::io::Result<Option<IpcMessage>>;
}

/// 内存测试传输：记录发出的帧，按脚本顺序回放收到的帧。
pub struct FakeTransport {
    pub sent: Vec<IpcMessage>,
    incoming: VecDeque<IpcMessage>,
}

impl FakeTransport {
    pub fn new(incoming: Vec<IpcMessage>) -> Self {
        Self { sent: Vec::new(), incoming: incoming.into() }
    }
}

impl Transport for FakeTransport {
    fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()> {
        self.sent.push(msg.clone());
        Ok(())
    }
    fn recv(&mut self) -> std::io::Result<Option<IpcMessage>> {
        Ok(self.incoming.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_records_sent_and_replays_incoming() {
        let mut t = FakeTransport::new(vec![IpcMessage {
            kind: "pong".into(), id: Some(7), session_id: None, thread_id: None, payload: None,
        }]);
        t.send(&IpcMessage { kind: "ping".into(), id: Some(7), session_id: None, thread_id: None, payload: None }).unwrap();
        assert_eq!(t.sent.len(), 1);
        assert_eq!(t.sent[0].kind, "ping");
        assert_eq!(t.recv().unwrap().unwrap().kind, "pong");
        assert!(t.recv().unwrap().is_none());
    }
}
```

- [ ] **Step 2: 在 main.rs 注册模块**

在 `agentdeck-cli/src/main.rs` 顶部 `mod output;` 下加：
```rust
mod transport;
```

- [ ] **Step 3: 测试**

Run: `cargo test -p agentdeck-cli`
Expected: PASS。

- [ ] **Step 4: 提交**

```bash
git add agentdeck-cli/src/transport.rs agentdeck-cli/src/main.rs
git commit -m "feat(cli): add Transport trait and in-memory FakeTransport"
```

---

### Task 5: `Client` — id 分配 + round-trip 关联

实现一次性请求的关联逻辑，用 FakeTransport 单测。

**Files:**
- Create: `agentdeck-cli/src/client.rs`
- Modify: `agentdeck-cli/src/main.rs`（加 `mod client;`）

**Interfaces:**
- Produces:
  - `struct client::Client<T: Transport>`，构造 `Client::new(transport: T) -> Self`。
  - `Client::round_trip(&mut self, req: IpcMessage) -> Result<IpcMessage, CliError>`（自动分配并写入 `id`，循环 `recv` 直到返回 `id` 匹配的帧；`recv` 返回 `None` → `CliError::Transport`）。
  - `Client::expect_kind(reply: IpcMessage, expected: &str) -> Result<serde_json::Value, CliError>`（`kind==expected` 返回 payload；`kind=="error"` 取 `payload.message` 返回 `CliError::Protocol`；否则 `CliError::Protocol("expected X, got Y")`）。
  - `Client::shutdown(&mut self)`（best-effort 发 `shutdown` 优雅退出，忽略错误）。
- Consumes: `transport::Transport`、`output::CliError`、`agentdeck_protocol::IpcMessage`。

- [ ] **Step 1: 写 client.rs round-trip 的失败测试**

`agentdeck-cli/src/client.rs`：
```rust
use crate::output::CliError;
use crate::transport::Transport;
use agentdeck_protocol::IpcMessage;

pub struct Client<T: Transport> {
    transport: T,
    next_id: u64,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self { transport, next_id: 1000 }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn round_trip(&mut self, mut req: IpcMessage) -> Result<IpcMessage, CliError> {
        let id = self.alloc_id();
        req.id = Some(id);
        self.transport.send(&req).map_err(|e| CliError::Transport(e.to_string()))?;
        loop {
            match self.transport.recv().map_err(|e| CliError::Transport(e.to_string()))? {
                None => return Err(CliError::Transport("agentdeckd disconnected".into())),
                Some(msg) if msg.id == Some(id) => return Ok(msg),
                Some(_) => continue, // 忽略无关帧
            }
        }
    }

    pub fn expect_kind(reply: IpcMessage, expected: &str) -> Result<serde_json::Value, CliError> {
        if reply.kind == expected {
            return Ok(reply.payload.unwrap_or(serde_json::Value::Null));
        }
        if reply.kind == "error" {
            let msg = reply.payload.as_ref()
                .and_then(|p| p.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(CliError::Protocol(msg));
        }
        Err(CliError::Protocol(format!("expected {expected}, got {}", reply.kind)))
    }

    pub fn shutdown(&mut self) {
        let id = self.alloc_id();
        let bye = IpcMessage { kind: "shutdown".into(), id: Some(id), session_id: None, thread_id: None, payload: None };
        let _ = self.transport.send(&bye);
        // best-effort：读到对应 pong 或 EOF 即止
        while let Ok(Some(msg)) = self.transport.recv() {
            if msg.id == Some(id) { break; }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FakeTransport;

    fn msg(kind: &str, id: Option<u64>, payload: Option<serde_json::Value>) -> IpcMessage {
        IpcMessage { kind: kind.into(), id, session_id: None, thread_id: None, payload }
    }

    #[test]
    fn round_trip_matches_reply_by_id_and_skips_strays() {
        // 第一帧 id 不匹配（stray），第二帧匹配分配的 id 1000。
        let t = FakeTransport::new(vec![
            msg("noise", Some(1), None),
            msg("pong", Some(1000), None),
        ]);
        let mut client = Client::new(t);
        let reply = client.round_trip(msg("ping", None, None)).unwrap();
        assert_eq!(reply.kind, "pong");
        assert_eq!(reply.id, Some(1000));
    }

    #[test]
    fn round_trip_disconnect_is_transport_error() {
        let t = FakeTransport::new(vec![]); // 立即 EOF
        let mut client = Client::new(t);
        let err = client.round_trip(msg("ping", None, None)).unwrap_err();
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn expect_kind_maps_error_frame_to_protocol_error() {
        let reply = msg("error", Some(1000), Some(serde_json::json!({"message": "boom"})));
        let err = Client::<FakeTransport>::expect_kind(reply, "pong").unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert_eq!(err.message(), "boom");
    }
}
```

- [ ] **Step 2: 注册模块**

在 `agentdeck-cli/src/main.rs` 顶部加：
```rust
mod client;
```

- [ ] **Step 3: 先确认测试覆盖到（运行并通过）**

Run: `cargo test -p agentdeck-cli client::`
Expected: PASS（3 个测试）。

- [ ] **Step 4: 提交**

```bash
git add agentdeck-cli/src/client.rs agentdeck-cli/src/main.rs
git commit -m "feat(cli): client round-trip correlation over transport seam"
```

---

### Task 6: `Client::run_stream` — 流式会话 + 审批策略

实现 `session run/continue` 的全双工流式与审批处理，用 FakeTransport 单测。

**Files:**
- Modify: `agentdeck-cli/src/client.rs`（加 `ApprovalPolicy`、`run_stream`、测试）

**Interfaces:**
- Produces:
  - `enum client::ApprovalPolicy { Prompt, AutoApprove, AutoDeny }`。
  - `Client::run_stream(&mut self, mut req: IpcMessage, session_id: &str, policy: ApprovalPolicy, emit: &mut dyn FnMut(&serde_json::Value)) -> Result<(), CliError>`：
    发送带 id 的 `req`（`session_id` 写入 `req.session_id`）；循环 `recv`：
    - `turnAccepted`（id 匹配）→ 继续；
    - `error`（id 匹配，流前错误如 busy）→ `CliError::Protocol`；
    - `session/event` → 取 `payload.event` 内层事件，调用 `emit(&inner)`；按内层 `kind`：`actionRequest` → 依 `policy` 决策并发 `actionDecision`；`turnComplete` → `Ok(())`；`error` → `CliError::Session(message)`；其它 → 继续；
    - `None`（EOF）→ `CliError::Transport`。
    `policy == Prompt` 时从 stdin 读一行 `{"requestId":N,"decision":"..."}`。
- Consumes: Task 5 的 `Client`。

- [ ] **Step 1: 加 ApprovalPolicy 与 run_stream（含决策辅助）**

在 `agentdeck-cli/src/client.rs` 的 `impl<T: Transport> Client<T>` 内追加方法，并在文件内加枚举与 stdin 决策辅助：
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalPolicy {
    Prompt,
    AutoApprove,
    AutoDeny,
}

impl<T: Transport> Client<T> {
    pub fn run_stream(
        &mut self,
        mut req: IpcMessage,
        session_id: &str,
        policy: ApprovalPolicy,
        emit: &mut dyn FnMut(&serde_json::Value),
    ) -> Result<(), CliError> {
        let id = self.alloc_id();
        req.id = Some(id);
        req.session_id = Some(session_id.to_string());
        self.transport.send(&req).map_err(|e| CliError::Transport(e.to_string()))?;

        loop {
            let msg = match self.transport.recv().map_err(|e| CliError::Transport(e.to_string()))? {
                None => return Err(CliError::Transport("agentdeckd disconnected mid-session".into())),
                Some(m) => m,
            };
            if msg.id == Some(id) {
                if msg.kind == "turnAccepted" {
                    continue;
                }
                if msg.kind == "error" {
                    let m = msg.payload.as_ref()
                        .and_then(|p| p.get("message")).and_then(|v| v.as_str())
                        .unwrap_or("session rejected").to_string();
                    return Err(CliError::Protocol(m));
                }
            }
            if msg.kind != "session/event" {
                continue;
            }
            let Some(inner) = msg.payload.as_ref().and_then(|p| p.get("event")).cloned() else {
                continue;
            };
            emit(&inner);
            let inner_kind = inner.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            match inner_kind {
                "actionRequest" => {
                    let request_id = inner.get("payload")
                        .and_then(|p| p.get("requestId"))
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| CliError::Protocol("actionRequest missing requestId".into()))?;
                    let decision = self.decide(policy, request_id)?;
                    let did = self.alloc_id();
                    let dec = IpcMessage {
                        kind: "actionDecision".into(),
                        id: Some(did),
                        session_id: Some(session_id.to_string()),
                        thread_id: None,
                        payload: Some(serde_json::json!({ "requestId": request_id, "decision": decision })),
                    };
                    self.transport.send(&dec).map_err(|e| CliError::Transport(e.to_string()))?;
                }
                "turnComplete" => return Ok(()),
                "error" => {
                    let m = inner.get("payload")
                        .and_then(|p| p.get("message")).and_then(|v| v.as_str())
                        .unwrap_or("session failed").to_string();
                    return Err(CliError::Session(m));
                }
                _ => continue,
            }
        }
    }

    fn decide(&self, policy: ApprovalPolicy, _request_id: u64) -> Result<String, CliError> {
        match policy {
            ApprovalPolicy::AutoApprove => Ok("approve".into()),
            ApprovalPolicy::AutoDeny => Ok("deny".into()),
            ApprovalPolicy::Prompt => {
                use std::io::BufRead;
                let stdin = std::io::stdin();
                let mut line = String::new();
                stdin.lock().read_line(&mut line).map_err(|e| CliError::Transport(e.to_string()))?;
                let v: serde_json::Value = serde_json::from_str(line.trim())
                    .map_err(|e| CliError::Usage(format!("invalid decision line: {e}")))?;
                let d = v.get("decision").and_then(|x| x.as_str()).unwrap_or("");
                match d {
                    "approve" | "deny" | "cancel" => Ok(d.to_string()),
                    _ => Err(CliError::Usage("decision must be approve|deny|cancel".into())),
                }
            }
        }
    }
}
```

- [ ] **Step 2: 写 run_stream 的失败/通过测试**

在 `agentdeck-cli/src/client.rs` 的 `#[cfg(test)] mod tests` 内追加：
```rust
fn session_event(inner: serde_json::Value) -> IpcMessage {
    IpcMessage {
        kind: "session/event".into(),
        id: None,
        session_id: Some("cli-1".into()),
        thread_id: None,
        payload: Some(serde_json::json!({ "event": inner })),
    }
}

#[test]
fn run_stream_auto_approve_sends_decision_and_completes() {
    let t = FakeTransport::new(vec![
        msg("turnAccepted", Some(1000), None),
        session_event(serde_json::json!({ "kind": "agentItem", "payload": { "id": "a1" } })),
        session_event(serde_json::json!({ "kind": "actionRequest", "payload": { "requestId": 5 } })),
        session_event(serde_json::json!({ "kind": "turnComplete" })),
    ]);
    let mut client = Client::new(t);
    let mut events = Vec::new();
    let mut emit = |e: &serde_json::Value| events.push(e.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string());
    let req = msg("startSession", None, Some(serde_json::json!({"cwd":"/tmp","prompt":"hi"})));
    client.run_stream(req, "cli-1", ApprovalPolicy::AutoApprove, &mut emit).unwrap();

    assert_eq!(events, vec!["agentItem", "actionRequest", "turnComplete"]);
    let sent = client.into_sent();
    let decision = sent.iter().find(|m| m.kind == "actionDecision").expect("decision sent");
    assert_eq!(decision.payload.as_ref().unwrap()["requestId"], 5);
    assert_eq!(decision.payload.as_ref().unwrap()["decision"], "approve");
    assert_eq!(decision.session_id.as_deref(), Some("cli-1"));
}

#[test]
fn run_stream_inner_error_is_session_failure() {
    let t = FakeTransport::new(vec![
        msg("turnAccepted", Some(1000), None),
        session_event(serde_json::json!({ "kind": "error", "payload": { "message": "boom" } })),
    ]);
    let mut client = Client::new(t);
    let mut emit = |_: &serde_json::Value| {};
    let req = msg("startSession", None, Some(serde_json::json!({"cwd":"/tmp","prompt":"hi"})));
    let err = client.run_stream(req, "cli-1", ApprovalPolicy::AutoApprove, &mut emit).unwrap_err();
    assert_eq!(err.exit_code(), 5);
    assert_eq!(err.message(), "boom");
}
```

- [ ] **Step 3: 加测试辅助 `into_sent`（暴露 Fake 已发帧）**

在 `agentdeck-cli/src/client.rs` 的 `impl<T: Transport> Client<T>` 内追加（仅测试用，置于 `#[cfg(test)]`）：
```rust
#[cfg(test)]
impl<T: Transport> Client<T> {
    fn into_sent(self) -> Vec<IpcMessage>
    where
        T: IntoSent,
    {
        self.transport.into_sent()
    }
}

#[cfg(test)]
pub trait IntoSent {
    fn into_sent(self) -> Vec<IpcMessage>;
}

#[cfg(test)]
impl IntoSent for crate::transport::FakeTransport {
    fn into_sent(self) -> Vec<IpcMessage> {
        self.sent
    }
}
```

- [ ] **Step 4: 运行测试**

Run: `cargo test -p agentdeck-cli client::`
Expected: PASS（含 run_stream 两个新测试）。

- [ ] **Step 5: 提交**

```bash
git add agentdeck-cli/src/client.rs
git commit -m "feat(cli): streaming session run_stream with approval policy"
```

---

### Task 7: 接线 round-trip 子命令（ping / selfcheck / diagnostics / history）

把一次性命令映射到 `Client::round_trip`，用 FakeTransport 单测请求构造与回包解释。

**Files:**
- Create: `agentdeck-cli/src/commands.rs`（命令 → IpcMessage 的纯映射 + 回包解释）
- Modify: `agentdeck-cli/src/main.rs`（扩展 clap 子命令 + dispatch + `mod commands;`）

**Interfaces:**
- Produces（纯函数，便于单测，全部返回 `IpcMessage` 或解释结果）：
  - `commands::ping_request() -> IpcMessage`
  - `commands::selfcheck_request() -> IpcMessage`
  - `commands::diagnostics_request(limit: Option<u64>, since_seconds: Option<u64>, run_id: Option<String>) -> IpcMessage`
  - `commands::history_list_request(cwd: Option<String>, search: Option<String>, cursor: Option<String>, limit: Option<u64>) -> IpcMessage`
  - `commands::history_read_request(thread_id: &str) -> IpcMessage`
  - `commands::history_manage_request(kind: &str, thread_id: &str, name: Option<&str>) -> IpcMessage`（`kind` ∈ `history/archiveThread|history/unarchiveThread|history/renameThread`）
  - `commands::interpret_selfcheck(payload: &serde_json::Value) -> Result<(), CliError>`（`recordOk&&diagnosticOk&&redactionOk` 否则 `CliError::Session`）
- Consumes: `output::req`、`client::Client`。

- [ ] **Step 1: 写 commands.rs（请求构造 + selfcheck 解释 + 测试）**

`agentdeck-cli/src/commands.rs`：
```rust
use crate::output::{req, CliError};
use agentdeck_protocol::IpcMessage;

pub fn ping_request() -> IpcMessage {
    req("ping", None)
}

pub fn selfcheck_request() -> IpcMessage {
    req("selfcheck/logging", None)
}

pub fn diagnostics_request(limit: Option<u64>, since_seconds: Option<u64>, run_id: Option<String>) -> IpcMessage {
    let mut p = serde_json::Map::new();
    if let Some(l) = limit { p.insert("limit".into(), l.into()); }
    if let Some(s) = since_seconds { p.insert("sinceSeconds".into(), s.into()); }
    if let Some(r) = run_id { p.insert("runId".into(), r.into()); }
    req("diagnostics/report", if p.is_empty() { None } else { Some(p.into()) })
}

pub fn history_list_request(cwd: Option<String>, search: Option<String>, cursor: Option<String>, limit: Option<u64>) -> IpcMessage {
    let mut p = serde_json::Map::new();
    if let Some(c) = cwd { p.insert("cwd".into(), c.into()); }
    if let Some(s) = search { p.insert("searchTerm".into(), s.into()); }
    if let Some(c) = cursor { p.insert("cursor".into(), c.into()); }
    if let Some(l) = limit { p.insert("limit".into(), l.into()); }
    req("history/listThreads", if p.is_empty() { None } else { Some(p.into()) })
}

pub fn history_read_request(thread_id: &str) -> IpcMessage {
    req("history/readThread", Some(serde_json::json!({ "threadId": thread_id })))
}

pub fn history_manage_request(kind: &str, thread_id: &str, name: Option<&str>) -> IpcMessage {
    let mut p = serde_json::Map::new();
    p.insert("threadId".into(), thread_id.into());
    if let Some(n) = name { p.insert("name".into(), n.into()); }
    req(kind, Some(p.into()))
}

pub fn interpret_selfcheck(payload: &serde_json::Value) -> Result<(), CliError> {
    let ok = |k: &str| payload.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    if ok("recordOk") && ok("diagnosticOk") && ok("redactionOk") {
        Ok(())
    } else {
        Err(CliError::Session("selfcheck failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_list_request_omits_empty_payload() {
        let m = history_list_request(None, None, None, None);
        assert_eq!(m.kind, "history/listThreads");
        assert!(m.payload.is_none());
    }

    #[test]
    fn history_rename_request_carries_name() {
        let m = history_manage_request("history/renameThread", "t1", Some("New"));
        assert_eq!(m.payload.as_ref().unwrap()["threadId"], "t1");
        assert_eq!(m.payload.as_ref().unwrap()["name"], "New");
    }

    #[test]
    fn diagnostics_request_includes_filters() {
        let m = diagnostics_request(Some(10), Some(60), Some("run-1".into()));
        let p = m.payload.as_ref().unwrap();
        assert_eq!(p["limit"], 10);
        assert_eq!(p["sinceSeconds"], 60);
        assert_eq!(p["runId"], "run-1");
    }

    #[test]
    fn selfcheck_all_ok_passes_else_fails() {
        assert!(interpret_selfcheck(&serde_json::json!({"recordOk":true,"diagnosticOk":true,"redactionOk":true})).is_ok());
        let err = interpret_selfcheck(&serde_json::json!({"recordOk":false,"diagnosticOk":true,"redactionOk":true})).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }
}
```

- [ ] **Step 2: 扩展 main.rs 的 clap 子命令与 dispatch**

在 `agentdeck-cli/src/main.rs`：顶部加 `mod commands;`；`enum Command` 增加分支；`run()` 中接线。完整新增/修改：

`enum Command` 增加：
```rust
    /// 往返自检
    Ping,
    /// IPC 生命周期 + logging 自检
    Selfcheck,
    /// 诊断报告
    Diagnostics {
        #[command(subcommand)]
        what: DiagnosticsCmd,
    },
    /// 历史操作
    History {
        #[command(subcommand)]
        what: HistoryCmd,
    },
```

新增枚举：
```rust
#[derive(Subcommand)]
enum DiagnosticsCmd {
    Report {
        #[arg(long)] limit: Option<u64>,
        #[arg(long)] since_seconds: Option<u64>,
        #[arg(long)] run_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum HistoryCmd {
    List {
        #[arg(long)] cwd: Option<String>,
        #[arg(long)] search: Option<String>,
        #[arg(long)] cursor: Option<String>,
        #[arg(long)] limit: Option<u64>,
    },
    Read { #[arg(long)] thread_id: String },
    Archive { #[arg(long)] thread_id: String },
    Unarchive { #[arg(long)] thread_id: String },
    Rename { #[arg(long)] thread_id: String, #[arg(long)] name: String },
}
```

`run()` 中（在 `Command::Protocol` 分支后）加 round-trip 命令处理。先加一个建立连接 + round-trip 的本地辅助（用 `ProcessTransport`，Task 8 实现；本任务先以编译期占位 `connect()?` 调用，Task 8 落地）：
```rust
    Command::Ping => {
        let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
        let reply = client.round_trip(commands::ping_request())?;
        let payload = client::Client::<transport::ProcessTransport>::expect_kind(reply, "pong")?;
        client.shutdown();
        println!("{}", render(&serde_json::json!({"kind":"pong","payload":payload}), cli.pretty));
        Ok(())
    }
    Command::Selfcheck => {
        let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
        let reply = client.round_trip(commands::selfcheck_request())?;
        let payload = client::Client::<transport::ProcessTransport>::expect_kind(reply, "loggingSelfcheck")?;
        client.shutdown();
        println!("{}", render(&payload, cli.pretty));
        commands::interpret_selfcheck(&payload)
    }
    Command::Diagnostics { what } => {
        let DiagnosticsCmd::Report { limit, since_seconds, run_id } = what;
        let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
        let reply = client.round_trip(commands::diagnostics_request(limit, since_seconds, run_id))?;
        let payload = client::Client::<transport::ProcessTransport>::expect_kind(reply, "diagnosticsReport")?;
        client.shutdown();
        println!("{}", render(&payload, cli.pretty));
        Ok(())
    }
    Command::History { what } => {
        let (request, expected) = match what {
            HistoryCmd::List { cwd, search, cursor, limit } =>
                (commands::history_list_request(cwd, search, cursor, limit), "historyThreads"),
            HistoryCmd::Read { thread_id } =>
                (commands::history_read_request(&thread_id), "historyThread"),
            HistoryCmd::Archive { thread_id } =>
                (commands::history_manage_request("history/archiveThread", &thread_id, None), "historyThreadUpdated"),
            HistoryCmd::Unarchive { thread_id } =>
                (commands::history_manage_request("history/unarchiveThread", &thread_id, None), "historyThreadUpdated"),
            HistoryCmd::Rename { thread_id, name } =>
                (commands::history_manage_request("history/renameThread", &thread_id, Some(&name)), "historyThreadUpdated"),
        };
        let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
        let reply = client.round_trip(request)?;
        let payload = client::Client::<transport::ProcessTransport>::expect_kind(reply, expected)?;
        client.shutdown();
        println!("{}", render(&payload, cli.pretty));
        Ok(())
    }
```

> 注：`connect()` 与 `transport::ProcessTransport` 在 Task 8 落地。本任务结束时 `cargo build -p agentdeck-cli` 不要求通过（依赖 Task 8）；本任务的验证只跑**库单元测试**。

- [ ] **Step 3: 运行 commands 单元测试**

Run: `cargo test -p agentdeck-cli commands::`
Expected: PASS（4 个测试）。

- [ ] **Step 4: 提交**

```bash
git add agentdeck-cli/src/commands.rs agentdeck-cli/src/main.rs
git commit -m "feat(cli): round-trip command request builders and dispatch wiring"
```

---

### Task 8: `ProcessTransport` + `connect()`（真实 daemon spawn + A1 生命周期）

落地真实传输：定位并 spawn `agentdeckd`、注入 env、Drop 杀进程；接通 Task 7 的 `connect()`，使 CLI 可整体编译运行。

**Files:**
- Modify: `agentdeck-cli/src/transport.rs`（加 `ProcessTransport` + `locate_daemon`）
- Modify: `agentdeck-cli/src/main.rs`（加 `connect()`）

**Interfaces:**
- Produces:
  - `transport::ProcessTransport`（实现 `Transport`；构造 `ProcessTransport::spawn(profile: &str, data_dir: Option<&str>) -> std::io::Result<Self>`；`Drop` 杀子进程）。
  - `transport::locate_daemon() -> Option<std::path::PathBuf>`。
  - `main::connect(profile: &str, data_dir: Option<&str>) -> Result<client::Client<transport::ProcessTransport>, CliError>`。
- Consumes: Task 4 `Transport`、Task 5 `Client`。

- [ ] **Step 1: 加 ProcessTransport 与 locate_daemon**

在 `agentdeck-cli/src/transport.rs` 顶部 `use` 区补：
```rust
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
```
文件内追加：
```rust
fn is_exec(p: &std::path::Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// 定位 agentdeckd：优先当前可执行文件同目录（同一 target dir），再回退
/// cwd 相对 dev 路径与常见安装位置（与 Swift DaemonClient.locateDaemon 同策略）。
pub fn locate_daemon() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sib = dir.join("agentdeckd");
            if is_exec(&sib) {
                return Some(sib);
            }
        }
    }
    for c in [
        "target/debug/agentdeckd",
        "target/release/agentdeckd",
        "/usr/local/bin/agentdeckd",
        "/opt/homebrew/bin/agentdeckd",
    ] {
        let p = PathBuf::from(c);
        if is_exec(&p) {
            return Some(p);
        }
    }
    None
}

/// 真实传输：spawn agentdeckd，走其 stdin/stdout JSONL。
/// A1：Drop 时杀子进程，daemon 自身 Drop 级联杀 codex 进程组。
pub struct ProcessTransport {
    child: Child,
    reader: BufReader<ChildStdout>,
    stdin: ChildStdin,
}

impl ProcessTransport {
    pub fn spawn(profile: &str, data_dir: Option<&str>) -> std::io::Result<Self> {
        let path = locate_daemon().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "agentdeckd not found (build it: cargo build -p agentdeckd)",
            )
        })?;
        let mut cmd = Command::new(path);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        cmd.env("AGENTDECK_PROFILE", profile);
        if let Some(d) = data_dir {
            cmd.env("AGENTDECK_DATA_DIR", d);
        }
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Self { child, reader: BufReader::new(stdout), stdin })
    }
}

impl Transport for ProcessTransport {
    fn send(&mut self, msg: &IpcMessage) -> std::io::Result<()> {
        let mut s = serde_json::to_string(msg).map_err(std::io::Error::other)?;
        s.push('\n');
        self.stdin.write_all(s.as_bytes())?;
        self.stdin.flush()
    }
    fn recv(&mut self) -> std::io::Result<Option<IpcMessage>> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                return Ok(None);
            }
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            match serde_json::from_str::<IpcMessage>(t) {
                Ok(m) => return Ok(Some(m)),
                Err(_) => continue,
            }
        }
    }
}

impl Drop for ProcessTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
```

- [ ] **Step 2: 在 main.rs 加 connect()**

在 `agentdeck-cli/src/main.rs`（`run()` 之上）加：
```rust
fn connect(profile: &str, data_dir: Option<&str>) -> Result<client::Client<transport::ProcessTransport>, CliError> {
    let transport = transport::ProcessTransport::spawn(profile, data_dir)
        .map_err(|e| CliError::Transport(e.to_string()))?;
    Ok(client::Client::new(transport))
}
```

- [ ] **Step 3: 整体编译 + 单元测试**

Run: `cargo build -p agentdeck-cli && cargo test -p agentdeck-cli`
Expected: 编译通过；全部库单元测试 PASS。

- [ ] **Step 4: 手验真实 round-trip（无需 codex login）**

Run: `cargo build -p agentdeckd -p agentdeck-cli && cargo run -q -p agentdeck-cli -- ping`
Expected: 输出含 `"kind":"pong"`，进程干净退出。

Run: `pgrep -f agentdeckd || echo "no orphan daemon"`
Expected: `no orphan daemon`（A1：无孤儿 daemon）。

- [ ] **Step 5: 提交**

```bash
git add agentdeck-cli/src/transport.rs agentdeck-cli/src/main.rs
git commit -m "feat(cli): ProcessTransport spawning agentdeckd with A1 lifecycle"
```

---

### Task 9: 接线流式子命令 `session run` / `session continue`

把流式会话接到 `connect()` + `run_stream`，逐行输出中立事件。

**Files:**
- Modify: `agentdeck-cli/src/main.rs`（加 `Session` 子命令 + dispatch + sessionId 生成）

**Interfaces:**
- Consumes: `client::Client::run_stream`、`commands`、`connect()`。
- Produces: clap 子命令 `session run` / `session continue`，全局沿用 `--profile/--data-dir/--pretty`，会话专属 `--approval-policy`。

- [ ] **Step 1: 加 Session 子命令枚举**

在 `agentdeck-cli/src/main.rs` 的 `enum Command` 加：
```rust
    /// 流式会话
    Session {
        #[command(subcommand)]
        what: SessionCmd,
    },
```
新增：
```rust
#[derive(Subcommand)]
enum SessionCmd {
    /// 新会话
    Run {
        #[arg(long)] cwd: String,
        #[arg(long)] prompt: String,
        #[arg(long, value_enum, default_value_t = ApprovalArg::Prompt)]
        approval_policy: ApprovalArg,
    },
    /// 在既有 thread 上继续
    Continue {
        #[arg(long)] thread_id: String,
        #[arg(long)] prompt: String,
        #[arg(long, value_enum, default_value_t = ApprovalArg::Prompt)]
        approval_policy: ApprovalArg,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ApprovalArg { Prompt, AutoApprove, AutoDeny }

impl From<ApprovalArg> for client::ApprovalPolicy {
    fn from(a: ApprovalArg) -> Self {
        match a {
            ApprovalArg::Prompt => client::ApprovalPolicy::Prompt,
            ApprovalArg::AutoApprove => client::ApprovalPolicy::AutoApprove,
            ApprovalArg::AutoDeny => client::ApprovalPolicy::AutoDeny,
        }
    }
}
```

- [ ] **Step 2: 加 dispatch**

在 `run()` 中加分支：
```rust
    Command::Session { what } => {
        let session_id = format!("cli-{}", std::process::id());
        let (request, policy) = match what {
            SessionCmd::Run { cwd, prompt, approval_policy } => (
                output::req("startSession", Some(serde_json::json!({"cwd": cwd, "prompt": prompt}))),
                approval_policy.into(),
            ),
            SessionCmd::Continue { thread_id, prompt, approval_policy } => (
                output::req("startTurn", Some(serde_json::json!({"threadId": thread_id, "prompt": prompt}))),
                approval_policy.into(),
            ),
        };
        let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
        let pretty = cli.pretty;
        let mut emit = |inner: &serde_json::Value| println!("{}", render(inner, pretty));
        let result = client.run_stream(request, &session_id, policy, &mut emit);
        client.shutdown();
        result
    }
```

- [ ] **Step 3: 编译 + 单元测试 + 用法自检**

Run: `cargo build -p agentdeck-cli && cargo test -p agentdeck-cli`
Expected: PASS。

Run: `cargo run -q -p agentdeck-cli -- session run --help`
Expected: 显示 `--cwd --prompt --approval-policy` 帮助，无 panic。

- [ ] **Step 4: 提交**

```bash
git add agentdeck-cli/src/main.rs
git commit -m "feat(cli): streaming session run/continue subcommands"
```

---

### Task 10: 门控 E2E 集成测试（真实 codex，默认跳过）

新增 `AGENTDECK_E2E=1` 门控的集成测试，spawn 真实 `agentdeck` binary，断言契约形态不变量与退出码。

**Files:**
- Create: `agentdeck-cli/tests/e2e.rs`

**Interfaces:**
- Consumes: 已构建的 `agentdeck` 与 `agentdeckd` binary（通过 `CARGO_BIN_EXE_agentdeck`）。
- Produces: 集成测试（默认 skip；`AGENTDECK_E2E=1` 时运行）。

- [ ] **Step 1: 写 e2e.rs**

`agentdeck-cli/tests/e2e.rs`：
```rust
//! 契约级 E2E：直打真实 codex（需 `codex login`）。默认跳过；
//! `AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e` 才运行。
//! 断言收敛到契约形态（事件 kind / JSON 字段 / 退出码），不断言 agent 文本。

use std::process::Command;

fn gated() -> bool {
    std::env::var("AGENTDECK_E2E").is_ok()
}

fn agentdeck() -> Command {
    // cargo 为本 crate 的 bin 注入此 env；agentdeckd 由 ProcessTransport
    // 按同目录/target 路径定位（需先 `cargo build`）。
    Command::new(env!("CARGO_BIN_EXE_agentdeck"))
}

#[test]
fn ping_returns_pong() {
    if !gated() {
        eprintln!("skipped: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = agentdeck().arg("ping").output().expect("spawn");
    assert!(out.status.success(), "ping exit: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"kind\":\"pong\""), "stdout: {stdout}");
}

#[test]
fn protocol_version_is_json() {
    if !gated() {
        eprintln!("skipped: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = agentdeck().args(["protocol", "version"]).output().expect("spawn");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v["protocolVersion"].as_u64().is_some());
}

#[test]
fn session_run_streams_to_turn_complete() {
    if !gated() {
        eprintln!("skipped: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = agentdeck()
        .args(["session", "run", "--cwd", ".", "--prompt", "say hello in one word", "--approval-policy", "auto-approve"])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 契约形态：流以 turnComplete 收尾，进程退出码 0。
    assert!(out.status.success(), "exit: {:?} stderr: {}", out.status, String::from_utf8_lossy(&out.stderr));
    assert!(stdout.lines().any(|l| l.contains("\"kind\":\"turnComplete\"")), "stdout: {stdout}");
    // 每行应是合法 JSON（逐行中立事件）。
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|_| panic!("non-JSON line: {line}"));
    }
}
```
（`agentdeck-cli` 已依赖 `serde_json`，集成测试可直接用。）

- [ ] **Step 2: 默认运行确认跳过**

Run: `cargo test -p agentdeck-cli --test e2e`
Expected: PASS（全部打印 `skipped: ...` 并返回；不接触 codex）。

- [ ] **Step 3: （本地、需 codex login）门控运行**

Run: `cargo build && AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e -- --nocapture`
Expected: 真实 Codex 下 PASS；若未 `codex login` 则 `session_run` 失败（这是预期的环境约束，不在 CI 默认路径）。

- [ ] **Step 4: 提交**

```bash
git add agentdeck-cli/tests/e2e.rs
git commit -m "test(cli): gated real-codex E2E driving the agentdeck binary"
```

---

### Task 11: 文档与收口

同步更新仓库文档入口、验证规则，跑文档结构检查与全量验证。

**Files:**
- Modify: `ARCHITECTURE.md`、`README.md`、`AGENTS.md`、`docs/QUALITY.md`、`docs/index.md`

**Interfaces:** 无代码接口。

- [ ] **Step 1: 更新 ARCHITECTURE.md**

在「总体结构」「分层边界」「依赖方向」中加入：`agentdeck-protocol` crate（协议事实源）、`agentdeck-cli`（参考客户端 / E2E 驱动，不在前端实时通路上）、daemon `ipc` 模块改为 re-export 壳。明确「协议即契约 + CLI 参考客户端」边界。

- [ ] **Step 2: 更新 README.md**

加 `agentdeck` CLI 章节：构建（`cargo build`）、命令目录（`ping/session/history/selfcheck/diagnostics/protocol`）、输出与退出码契约摘要、`protocol schema/version` 用法。

- [ ] **Step 3: 更新 AGENTS.md「验证入口」**

补：
```bash
cargo run -p agentdeck-cli -- protocol schema   # 协议 schema（可与快照核对）
cargo run -p agentdeck-cli -- selfcheck         # 经 CLI 的 IPC + logging 自检
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e   # 本地、需 codex login
```
并说明 schema drift 测试随 `cargo test` 运行。

- [ ] **Step 4: 更新 docs/QUALITY.md**

补两条验证规则：(1) schema drift 测试（改协议类型须 `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol` 重生成快照）；(2) 门控 E2E（前置 `codex login` + `AGENTDECK_E2E=1`；断言收敛到契约形态，不断言 agent 文本；默认 CI 跳过）。

- [ ] **Step 5: 更新 docs/index.md**

「协议资料」补 `protocol/agentdeck/`（AgentDeck 自身中立协议 schema 与说明）。

- [ ] **Step 6: 跑文档结构检查与全量验证**

Run: `bash scripts/verify-agent-docs.sh`
Expected: `verify-agent-docs: ok`。

Run: `cargo test`
Expected: PASS（protocol drift / 中立性 / CLI 单元 / daemon 既有测试；默认不触发需登录的 E2E）。

Run: `cargo run -q -p agentdeck-cli -- protocol schema | diff - <(sed '$d' protocol/agentdeck/agentdeck-protocol.schema.json) && echo "schema in sync"`
Expected: `schema in sync`。

- [ ] **Step 7: 提交**

```bash
git add ARCHITECTURE.md README.md AGENTS.md docs/QUALITY.md docs/index.md
git commit -m "docs: document unified interface CLI, protocol schema, and gated E2E"
```

---

## Self-Review

**Spec 覆盖核对（对照 design 各节）：**
- 协议事实源（schemars 生成 + 漂移测试）→ Task 2。
- `agentdeck-protocol` crate 抽取、daemon 不变 → Task 1。
- CLI 命令目录（ping/session/history/selfcheck/diagnostics/protocol）→ Task 3/7/9。
- 审批脚本化（stdin + `--approval-policy`）→ Task 6/9。
- 输出 + 退出码契约 → Task 3（output.rs）+ 各命令任务。
- A1 生命周期、profile/data-dir 透传、中立性 → Task 8（ProcessTransport）+ Global Constraints + Task 1/2 中立性测试。
- 门控 Rust E2E（真实 codex、默认跳过）→ Task 10。
- 文档更新（ARCHITECTURE/README/AGENTS/QUALITY/index/protocol README）→ Task 2 Step 8 + Task 11。
- 非目标（不动 Swift、不做 mock、不加后端能力、不改线格式）→ 全程遵守，无对应任务即为不做。

**占位符扫描：** 无 TBD/TODO；每个代码步骤含完整代码；Task 7 对 `connect()` 的前向依赖已显式标注由 Task 8 落地，并把该任务验证限定在库单元测试，非占位。

**类型一致性核对：** `Transport::{send,recv}`、`Client::{round_trip,expect_kind,run_stream,shutdown}`、`ApprovalPolicy`、`output::{CliError,req,render,error_envelope}`、`commands::*_request`、`ProcessTransport::spawn`、`connect()`、`protocol_schema()/PROTOCOL_VERSION` 在定义与使用处签名一致。退出码（2/3/4/5）在 `CliError::exit_code` 与 design 表一致。
