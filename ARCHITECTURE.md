# AgentDeck 架构（GPUI 重启基线）

本文件记录稳定架构边界。产品定位、使用方式和构建命令见 `README.md`；具体功能设计和实施历史见 `docs/plans/`。

## 北极星

AgentDeck 是 Coding Agent 的统一原生桌面客户端。它把 OpenAI Codex 和 Anthropic Claude Code 作为绝对一等公民，两家的功能、概念和原始语义都被完整保留——AgentDeck 不强行统一它们，而是为它们提供同一个工作台。

AgentDeck 不做 IDE，不做通用多 agent 聊天界面，不是 Codex Desktop 替代品。

## 当前总体结构

```text
AgentDeck.app
└─ agentdeck-desktop（Rust / GPUI / gpui-component）
   ├─ Application + Window
   ├─ Root + 最小组件树
   └─ --selfcheck

agentdeckd / agentdeck-protocol / agentdeck-cli
└─ 现有后端与协议，当前尚未接入 GPUI 桌面端

AgentDeckMobileCore + ios/
└─ iOS companion 使用的 Swift 共享模型和 UIKit 前端
```

下一阶段唯一允许的本机桌面通路是
`agentdeck-desktop → typed local client → agentdeckd`。在该通路真正落地前，文档和
selfcheck 都必须明确桌面端没有 backend 能力。

Codex 本地 transport 已决定为 `agentdeckd` 直接持有 session-scoped
`codex app-server --listen stdio://` 子进程；不依赖用户全局 managed daemon/proxy。
该生命周期和 desktop 解锁门禁仍是已接受、未落地的设计，现状以
`docs/AGENTDECKD_STATUS.md` 为准。

## 分层边界

- `agentdeck-desktop/`：macOS GPUI executable。当前只负责窗口、组件根节点和桌面 selfcheck；不得解析 vendor JSON。
- `Sources/AgentDeckMobileCore/`：iOS 使用的平台无关 Swift 模型，禁止 import AppKit/UIKit。
- `agentdeck-protocol/`：本地 IPC 协议事实源 crate。分 trunk / capabilities / vendor 三个模块，`PROTOCOL_VERSION` = 2，`protocol_schema()` 聚合本地 v2 类型。
- `agentdeckd/src/ipc.rs`：re-export `agentdeck-protocol::*` 壳，保持 daemon 内 `crate::ipc::X` 引用不变。
- `agentdeckd/src/agent.rs`：`Agent` trait + `AgentKind` 枚举。两个 adapter 共享的逻辑在此，不得让 adapter 相互引用。
- `agentdeckd/src/runtime/`：`RuntimeHub`（stdin loop + stdout writer）+ `AgentRouter`（sessionId → agentKind → adapter）。
- `agentdeckd/src/codex/`：Codex app-server adapter。Codex vendor JSON、方法名和 schema 翻译只能留在此子模块。
- `agentdeckd/src/claude_code/`：ClaudeCodeAdapter。`claude` CLI 子进程接入，stream-json 解析，CC 特色能力（auth / history / permission / hooks）实现在此。
- `agentdeckd/src/record.rs`：run record 写入与脱敏，写入包含 `agent_kind` 字段。
- `agentdeckd/src/diag.rs`：诊断日志、自检和机器可读诊断报告，诊断事件带 `agent_kind`。
- `agentdeck-cli/`：参考客户端与门控 E2E 驱动。提供 `agentdeck` 二进制，不在 GUI 实时通路上。
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
- **K3**：每个 turn 的成功、失败或取消 terminal 发出前，worker 必须先释放 turn-local 占用；连接仍健康时 session 回到 Ready 并保留 session-scoped child。只有 `SessionClosed` 表示 session 已结束，且必须在 child wait 和路由清理后发送。
- **K4**（加强）：所有事件主干消息必须带 `agentKind` 字段。
- **K5**：run record 与 diagnostic log 写入 `~/Library/Application Support/AgentDeck/`（stable）或 `AgentDeck-Dev/`（dev），不得写入用户项目 git。
- **K6**：`AGENTDECK_DATA_DIR` / `--profile` / `AGENTDECK_PROFILE` 控制数据目录隔离，不影响 vendor 登录状态或 vendor 历史。
- **K7**：写入前做 best-effort 密钥脱敏；写失败不能静默，必须在可诊断位置暴露。
- **K8**：vendor schema 不手写，Codex 协议来自官方 `codex app-server generate-json-schema`。
- **K9**：AgentDeck 不读取、不保存、不转发任何 vendor token（Codex 或 Claude Code）。
- **K10**：`schema_matches_committed_snapshot` 漂移测试随 `cargo test` 运行；协议类型变更未重生成快照则失败。
- **K11**：历史管理请求的 `requestId` 在线协议中保持可选以兼容旧客户端；生产桌面与 CLI 客户端必须始终发送唯一值，daemon 必须在成功和错误终态回复中原样回显。客户端只接受与当前请求严格匹配的回复，并忽略其他请求或已超时请求的迟到回复。

### 新增不变量（N 系列，v0.2 起）

| # | 不变量 | 守护方式 |
|---|---|---|
| **N1** | **两层协议**：`AgentItem`、turn/session terminal、`SessionStarted`、`SessionCapabilities`、`Error` 等主干必须 vendor 中立；vendor 字段默认只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 三个命名空间下。唯一例外是 `ActionRequest.vendor`，用于 typed approval detail，禁止任意 JSON 透传 | schemars 派生 + `neutrality_tests.rs` 静态断言 |
| **N2** | **Capabilities Handshake**：daemon 在 `SessionStarted` 后必须立即发 `SessionCapabilities`，且早于该 session 的 `TurnStarted` / `AgentItem` / approval 等运行事件；UI 必须按它路由控件渲染；禁止 UI 硬编码 vendor 分支 | daemon M0 集成测试 + GPUI 会话切片的 Rust router 单测与静态边界测试；当前 P0 无 session UI |
| **N3** | **Adapter 互不知晓**：`agentdeckd/src/codex/` 不依赖 `claude_code/` 任何类型，反之亦然；共享逻辑下沉到 `agent.rs` trait | cargo 模块依赖检查 |
| **N4** | **Adapter 内 vendor JSON 不外泄**：被 IPC 推到 UI 的 vendor 字段必须经 adapter 显式建模，禁止 `serde_json::Value` 透传 | `capabilities_namespace_is_typed` 测试断言 |
| **N5** | **一等公民对称约束**：`CodexAdapter` 实现的每个非独有 capability，`ClaudeCodeAdapter` 必须有等价实现或文档化"不适用"原因 | capability 矩阵文档 + cargo test |
| **N7** | **`SessionCapabilities` 必须先于该 session 任何 `AgentItem`** | 集成测试断言序 |
| **N8** | **CC 数据事实唯一来源**：AgentDeck 不为 CC 维护任何元数据层；不在 `~/Library/Application Support/AgentDeck/` 下创建 `cc-meta/` 目录 | code review + 文件存在性断言 |

## 依赖方向

```text
agentdeck-desktop（当前）
  -> GPUI / gpui-component

agentdeck-desktop（下一阶段）
  -> typed local client
  -> agentdeck-protocol
  -> agentdeckd

daemon main
  -> ipc（re-export agentdeck-protocol）
  -> AgentRouter → CodexAdapter / ClaudeCodeAdapter
  -> record / diag
  -> codex app-server child process / claude CLI child process

agentdeck-cli（参考客户端 / E2E 驱动，与 GUI 互相独立）
  -> agentdeck-protocol（共享类型）
  -> ProcessTransport → daemon stdio child process
```

允许的跨层访问应沿上图向下：
- UI 不允许跳过按 `SessionCapabilities` 建立的 typed capability routing 直读 vendor 字段。
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

- **改 UI 行为**：改 `agentdeck-desktop/`，并对照当前 GPUI 设计计划；不要从历史 AppKit 计划复制实现。
- **改 IPC**：同步更新 Rust 协议、仍由 iOS 消费的 Swift Core mirror、测试、schema 快照和 README/架构文档。
- **改 Codex 协议翻译**：先看 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt`，再改 `agentdeckd/src/codex/` 子模块。
- **改 daemon session 生命周期**：先看 `docs/AGENTDECKD_STATUS.md`、Codex 生命周期 ADR 和 agentdeckd M0 设计；状态升级必须同步更新能力矩阵。
- **改 CC 协议翻译**：先看 `docs/plans/2026-06-30-unified-shell-v02-design.md` § 5，再改 `agentdeckd/src/claude_code/` 子模块。
- **改诊断或记录**：同步更新 `docs/AGENT_DIAGNOSTICS.md` 和 `docs/QUALITY.md`。
- **新增 adapter**：在 `agentdeckd/src/<vendor>/` 下建子模块，实现 `Agent` trait；在 `AgentRouter` 注册；在 `agentdeck-protocol` 的 `VendorCapabilities` / `VendorSessionOptions` 枚举中添加对应 variant；更新 `agentdeck-cli` 的 `--agent` 可选值。新 adapter 不得要求 UI 知道该 adapter 的 vendor JSON（N2），也不得修改现有 adapter capability（N5）。
