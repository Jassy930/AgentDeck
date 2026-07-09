# AgentDeck 架构（v0.2）

本文件记录稳定架构边界。产品定位、使用方式和构建命令见 `README.md`；具体功能设计和实施历史见 `docs/plans/`。

## 北极星

AgentDeck 是 Coding Agent 的统一原生桌面客户端。它把 OpenAI Codex 和 Anthropic Claude Code 作为绝对一等公民，两家的功能、概念和原始语义都被完整保留——AgentDeck 不强行统一它们，而是为它们提供同一个工作台。

AgentDeck 不做 IDE，不做通用多 agent 聊天界面，不是 Codex Desktop 替代品。

## 总体结构（v0.2）

```text
┌─────────────────────────────────────────────────────────────────┐
│  AgentDeck.app (macOS, AppKit)                                  │
│                                                                 │
│  SessionViewController                                          │
│   ├─ StatusBarView（当前 agentKind + auth）                      │
│   ├─ HistorySidebarVC（跨 agent 合并列表）                         │
│   ├─ AgentControlBar（capability 路由 → vendor SubView）          │
│   ├─ ConversationVC（虚拟化 NSTableView，中立 AgentItem）          │
│   ├─ ApprovalCardView（主干壳 + vendor 高级区 SubView）            │
│   └─ AgentTokenAuthMiniPanel                                    │
│                                                                 │
│  CapabilityRouter  ← 新增：UI 渲染按 SessionCapabilities 派发    │
│  ObservationBinder ← 保留：@Observable 模型绑定                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Layer A 中立事件主干（AgentItem）
                           │ Layer B Vendor 控件命名空间
                           │ Layer C 启动配置（SessionStart）
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  agentdeckd (Rust daemon)                                       │
│  RuntimeHub（stdin loop, stdout writer, per-session lock）       │
│       │                                                         │
│       └─→ AgentRouter（按 sessionId.agentKind 路由）              │
│            ├─ CodexAdapter      (capabilities = {...})          │
│            └─ ClaudeCodeAdapter (capabilities = {...})          │
│                                                                 │
│  共享层：record / diag / profile / capabilities registry         │
└─────────────────────────────────────────────────────────────────┘
   ▼ spawn (turn-scoped)                  ▼ spawn (turn-scoped)
codex app-server                       claude CLI (--print --stream-json)

agentdeck-cli  (参考客户端 / 门控 E2E 驱动，不在 GUI 实时通路上)
      │  通过 stdio JSONL 与 agentdeckd 交互（Transport trait）
      ▼
agentdeckd
```

## 分层边界

- `Sources/AgentDeck/`：macOS 原生 UI、会话模型、历史回放和本地交互。UI 只能通过 `CapabilityRouter` 消费 `SessionCapabilities` 决定渲染路径，禁止直接读 vendor 字段或硬编码 `if agentKind == .codex` 分支。
- `agentdeck-protocol/`：IPC 协议事实源 crate。分 trunk / capabilities / vendor / transport 四个模块，`PROTOCOL_VERSION` = 2，`protocol_schema()` 聚合所有 v2 类型。
- `agentdeckd/src/ipc.rs`：re-export `agentdeck-protocol::*` 壳，保持 daemon 内 `crate::ipc::X` 引用不变。
- `agentdeckd/src/agent.rs`：`Agent` trait + `AgentKind` 枚举。两个 adapter 共享的逻辑在此，不得让 adapter 相互引用。
- `agentdeckd/src/runtime/`：`RuntimeHub`（stdin loop + stdout writer）+ `AgentRouter`（sessionId → agentKind → adapter）。
- `agentdeckd/src/codex/`：Codex app-server adapter。Codex vendor JSON、方法名和 schema 翻译只能留在此子模块。
- `agentdeckd/src/claude_code/`：ClaudeCodeAdapter。`claude` CLI 子进程接入，stream-json 解析，CC 特色能力（auth / history / permission / hooks）实现在此。
- `agentdeckd/src/record.rs`：run record 写入与脱敏，写入包含 `agent_kind` 字段。
- `agentdeckd/src/diag.rs`：诊断日志、自检和机器可读诊断报告，诊断事件带 `agent_kind`。
- `agentdeck-cli/`：参考客户端与门控 E2E 驱动。提供 `agentdeck` 二进制，不在 Swift GUI 实时通路上。
- `protocol/`：官方 Codex app-server schema 快照和 spike 事实源。
- `protocol/agentdeck/`：AgentDeck 自身中立协议 JSON Schema 快照（schemars 派生，`cargo test` 漂移测试守护）。
- `docs/plans/`：设计、实施计划和决策历史。

## 不变量

### 废止的旧不变量（v0.1，v0.2 起不再适用）

| # | 旧不变量 | 废止理由 |
|---|---|---|
| W1 | Swift 层不得解析 Codex vendor JSON | 新方向要求 vendor SubView 直接消费 vendor 类型 |
| W2 | 中立 IPC 中不出现 vendor 字样 | 改成「主干中立 + vendor 命名空间允许 vendor 前缀」 |
| W3 | Codex 持久化策略字段只能留在 daemon adapter | persistence 必须在 UI 暴露 |

### 保留的不变量（K 系列，v0.1–v0.2）

- **K1**：daemon 的 stdin 主循环不得被单个 turn 阻塞；长时间工作放到 worker。
- **K2**：`RuntimeHub` 必须按 `sessionId` 阻止同一 runtime 并发 turn；session 创建时 `agentKind` 不可变，整个生命周期固定到一个 adapter。
- **K3**：turn 成功完成时，worker 必须先释放 session 占用，再向 Swift 发出可触发下一条 prompt 的 ready / `turnComplete` 事件。
- **K4**（加强）：所有事件主干消息必须带 `agentKind` 字段。
- **K5**：run record 与 diagnostic log 写入 `~/Library/Application Support/AgentDeck/`（stable）或 `AgentDeck-Dev/`（dev），不得写入用户项目 git。
- **K6**：`AGENTDECK_DATA_DIR` / `--profile` / `AGENTDECK_PROFILE` 控制数据目录隔离，不影响 vendor 登录状态或 vendor 历史。
- **K7**：写入前做 best-effort 密钥脱敏；写失败不能静默，必须在可诊断位置暴露。
- **K8**：vendor schema 不手写，Codex 协议来自官方 `codex app-server generate-json-schema`。
- **K9**：AgentDeck 不读取、不保存、不转发任何 vendor token（Codex 或 Claude Code）。
- **K10**：`schema_matches_committed_snapshot` 漂移测试随 `cargo test` 运行；协议类型变更未重生成快照则失败。

### 新增不变量（N 系列，v0.2 起）

| # | 不变量 | 守护方式 |
|---|---|---|
| **N1** | **两层协议**：`AgentItem` / `TurnComplete` / `SessionStarted` / `SessionCapabilities` / `Error` 主干必须 vendor 中立；vendor 字段默认只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 三个命名空间下。唯一例外是 `ActionRequest.vendor`，用于 typed approval detail，禁止任意 JSON 透传 | schemars 派生 + `neutrality_tests.rs` 静态断言 |
| **N2** | **Capabilities Handshake**：每个 session 启动时 daemon 必须先发 `SessionCapabilities`；UI 必须按它路由控件渲染；禁止 UI 硬编码 `if agentKind == .codex` 分支 | Swift 端 `NoVendorBranchInUITests` grep + AST 扫描 |
| **N3** | **Adapter 互不知晓**：`agentdeckd/src/codex/` 不依赖 `claude_code/` 任何类型，反之亦然；共享逻辑下沉到 `agent.rs` trait | cargo 模块依赖检查 |
| **N4** | **Adapter 内 vendor JSON 不外泄**：被 IPC 推到 UI 的 vendor 字段必须经 adapter 显式建模，禁止 `serde_json::Value` 透传 | `capabilities_namespace_is_typed` 测试断言 |
| **N5** | **一等公民对称约束**：`CodexAdapter` 实现的每个非独有 capability，`ClaudeCodeAdapter` 必须有等价实现或文档化"不适用"原因 | capability 矩阵文档 + cargo test |
| **N6** | **Transport trait 远程预留**：v0.2 实现 `Transport` trait（仅 stdio），但 trait 必须能支持 remote（异步、可重连、可携带 auth context） | 编译期 trait 定义 |
| **N7** | **`SessionCapabilities` 必须先于该 session 任何 `AgentItem`** | 集成测试断言序 |
| **N8** | **CC 数据事实唯一来源**：AgentDeck 不为 CC 维护任何元数据层；不在 `~/Library/Application Support/AgentDeck/` 下创建 `cc-meta/` 目录 | code review + 文件存在性断言 |

### Relay R1a 不变量（传输 + 鉴权骨架）

- **R1a-1**：`agentdeckd` 依赖树无 `tokio net` 或 `axum`——保证 daemon 至 R2 前始终无网络代码；guard `scripts/check-daemon-no-net.sh`
- **R1a-2**：`agentdeck-cli` 依赖树无 `axum`——CLI 只走 WS client 不做 server
- **R1a-3**：net/axum 仅限 `agentdeck-relay` 的 `server` feature + `agentdeck-relay-client` crate
- **R1a-4**：`relay` 数据目录独立于 daemon/CLI，只存不透明数据 + 公钥材料 + credential 哈希（**不**存明文 credential）
- **R1a-5**：非 loopback 绑定强制 TLS（`RelayConfig::validate_transport_gate`），除非显式 `--allow-plaintext` 明文告警
- **R1a-6**：`thiserror` 单版本 1.x、`rand_core` 单版本 0.6（与 dalek 2.x 对齐）
- **R1a-7**：一条 `RemoteFrame` = 一条 WS text 帧（`serde_json` 序列化）；`RELAY_PROTOCOL_VERSION` 变更需协商
- **R1a-8**：`DataEnvelope` bytes wire 为 base64 string（**不**是数字数组）

### Relay R1b 不变量（SQLite 持久化 + Router 健壮化）

- **R1b-1**：relay 持久化状态（accounts/devices/challenges/seq 高水位/事件元数据）全部落 SQLite（`rusqlite` + `bundled`），单一 `--storage` 路径文件；**事件内容（`payload`）本期恒为 NULL，不落盘明文**（R1c 引入加密后翻转）。
- **R1b-2**：`conv_buffer` 每 conversation 有硬上界（默认 1000，可配置），独立于 Ack 生效，防 OOM。
- **R1b-3**：重放补拉（`since_seq`）语义为 **relay 进程存活期内** 的有界补拉，不是跨重启完整历史重放；窗口外返回 `relay.replay.gap`。
- **R1b-4**：`RelayLink::recv` 仍不返回 `Result`（R2 defer，见 R1b 设计 §4.1）。

### R1a 隐含约束（供 R2 参考）

- **R1a machine_id ≡ device_id**：`server/ws.rs::connect` 用 `device.device_id` 作 `ConnRole::Machine.machine_id`，`router.rs` RegisterMachine 授权强制 `machine.machine_id == connection.machine_id`——**enrolled 的 machine 设备的 `machine_id` 严格等于 `device_id`**。CLI 生成的随机 `device_id = "cli-<profile>-<random>"` 会锁定 R2 daemon remote-mode 里对应 machine 的 identifier；R2 设计需评估是否解耦 machine_id 与 device_id（例如 machine 元数据里显式携带独立 machine_id）。

## 依赖方向

```text
Swift UI
  -> CapabilityRouter（按 SessionCapabilities 派发）
  -> WorkbenchModel / ThreadRuntimeModel / SessionModel / HistoryModel
  -> AgentDeck IPC models（来自 agentdeck-protocol v2）
  -> daemon stdio

daemon main
  -> ipc（re-export agentdeck-protocol）
  -> AgentRouter → CodexAdapter / ClaudeCodeAdapter
  -> record / diag
  -> codex app-server child process / claude CLI child process

agentdeck-cli（参考客户端 / E2E 驱动，与 GUI 互相独立）
  -> agentdeck-protocol（共享类型）
  -> Transport trait（ProcessTransport → daemon stdio）
  -> daemon child process
```

允许的跨层访问应沿上图向下：
- UI 不允许跳过 `CapabilityRouter` 直读 vendor 字段。
- `CodexAdapter` 不允许调 `ClaudeCodeAdapter`，反之亦然。
- 新增功能如需反向依赖，先把接口下沉到 `agent.rs` trait 或 `agentdeck-protocol`。

## 协议即契约

`agentdeck-protocol` crate 是 IPC 协议的唯一事实源：

- `PROTOCOL_VERSION`：当前为 2（v0.2 起）。
- `protocol_schema()`：schemars 从 Rust 类型派生的 JSON Schema，聚合所有 v2 公共类型。
- 快照：`protocol/agentdeck/agentdeck-protocol.schema.json`（`UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` 重生成）。
- 漂移测试随 `cargo test` 运行。
- 中立性测试（`neutrality_tests.rs`）守护 N1/N4。

## 变更指引

- **改 UI 行为**：先看相关 `Sources/AgentDeck/*ViewController.swift` / `*Model.swift` 与最近的 `docs/plans/*design.md`。确认 `CapabilityRouter` 路由路径是否需同步更新。
- **改 IPC**：同步更新 Swift/Rust 两侧模型、测试、schema 快照和 README/架构文档。
- **改 Codex 协议翻译**：先看 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt`，再改 `agentdeckd/src/codex/` 子模块。
- **改 CC 协议翻译**：先看 `docs/plans/2026-06-30-unified-shell-v02-design.md` § 5，再改 `agentdeckd/src/claude_code/` 子模块。
- **改诊断或记录**：同步更新 `docs/AGENT_DIAGNOSTICS.md` 和 `docs/QUALITY.md`。
- **新增 adapter**：在 `agentdeckd/src/<vendor>/` 下建子模块，实现 `Agent` trait；在 `AgentRouter` 注册；在 `agentdeck-protocol` 的 `VendorCapabilities` / `VendorSessionOptions` 枚举中添加对应 variant；更新 `agentdeck-cli` 的 `--agent` 可选值。新 adapter 不得要求 Swift 侧知道该 adapter 的 vendor JSON（N2），也不得修改现有 adapter capability（N5）。
