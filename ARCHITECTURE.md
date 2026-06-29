# AgentDeck 架构

本文件记录稳定架构边界。产品定位、使用方式和构建命令见 `README.md`；具体功能设计和实施历史见 `docs/plans/`。

## 北极星

AgentDeck 是 macOS 原生的本地 Coding Agent 工作台。它不替代 Codex Desktop，不做 IDE，也不做通用多 agent 聊天界面。

v0.1 只验证两个核心能力：

1. 原生流式会话：实时展示 reasoning、shell、file edit 等 agent 工作过程，并在高风险操作前让用户 approve / deny。
2. agent-中立适配器边界：Swift UI 不知道 Codex 存在，社区未来可以平行贡献 Claude Code、SSH 或云端 adapter。

## 总体结构

```text
AgentDeck.app  (macOS, 纯 AppKit)
      │                     前端为 AppKit NSViewController 树：
      │   SessionViewController
      │     ├── StatusBarView
      │     └── NSSplitView
      │           ├── HistorySidebarViewController（NSOutlineView）
      │           └── ConversationViewController（虚拟化 NSTableView）
      │                 └── TurnJumpRailView（叠加层）
      │   Markdown 渲染：原生 NSAttributedString（已移除 Textual 依赖）
      │   模型层：经 ObservationBinder 消费 @Observable 模型
      │
      │  stdio JSONL IPC，中立 AgentItem / ActionRequest / ActionDecision
      ▼
agentdeckd  (Rust daemon)
      │  ├── RuntimeHub（stdin main loop + stdout writer）
      │  ├── stdout writer
      │  ├── turn/history workers
      │  ├── run record / diagnostic log
      │  └── CodexAdapter
      ▼
codex app-server  (子进程, JSON-RPC over stdio)

agentdeck-cli  (参考客户端 / 门控 E2E 驱动，独立二进制，不在 GUI 实时通路上)
      │  通过 stdio JSONL 与 agentdeckd 交互（Transport trait）
      ▼
agentdeckd
```

## 分层边界

- `Sources/AgentDeck/`：macOS 原生 UI、会话模型、历史回放和本地交互。这里只能依赖中立 IPC shape。
- `agentdeck-protocol/`：中立 IPC 协议的事实源 crate。`PROTOCOL_VERSION` 版本常量、所有消息类型和 `protocol_schema()` JSON Schema 生成均定义于此。daemon 与 CLI 共用这个 crate，保证双边类型一致。
- `agentdeckd/src/ipc.rs`：仅作为 `agentdeck-protocol` 的 re-export 壳（`pub use agentdeck_protocol::*`），保持 daemon 内部的 `crate::ipc::X` 引用不变。
- `agentdeckd/src/codex.rs`：Codex app-server adapter。Codex vendor JSON、方法名和 schema 翻译只能留在这里或紧邻模块。
- `agentdeckd/src/record.rs`：AgentDeck 管理的 run record 写入与脱敏。
- `agentdeckd/src/diag.rs`：诊断日志、自检和机器可读诊断报告。
- `agentdeck-cli/`：参考客户端与门控 E2E 驱动。提供 `agentdeck` 二进制，供脚本化调用和本地验证使用；**不在 Swift GUI 的实时通路上**——Swift app 仍直接与 daemon 通过 stdio JSONL 交互。
- `protocol/`：官方 Codex app-server schema 快照和 spike 事实源。
- `protocol/agentdeck/`：AgentDeck 自身中立协议的 JSON Schema 快照（由 `agentdeck-protocol` 的 schemars 派生生成）。`cargo test` 会执行漂移测试，若协议类型变更而未重新生成快照则失败。
- `docs/plans/`：设计、实施计划和决策历史。

## 不变量

- Swift 层不得解析 Codex vendor JSON，也不得出现需要理解 Codex schema 才能工作的 UI 分支。
- 中立 IPC 中面向 Swift 的核心事件使用 `AgentItem`，不要把供应商特定字段扩散到 UI。
- 高风险动作审批必须走中立 `ActionRequest` / `ActionDecision`；Codex server request、response shape 和持久化策略字段只能留在 daemon adapter 层。
- daemon 的 stdin 主循环不得被单个 turn 阻塞；长时间工作放到 worker。
- daemon 的 RuntimeHub 必须按 `sessionId` 阻止同一 runtime 并发 turn，并对 history worker 保持有界并发；超限时返回可诊断 busy error。
- turn 成功完成时，worker 必须先释放 RuntimeHub 的 session 占用，再向 Swift 发出可触发下一条 prompt 的 ready / `turnComplete` 事件。
- streaming event 必须携带 `sessionId/threadId`，避免历史读取和正在运行的 turn 串流互相抢 reader。
- run record 与 diagnostic log 是 AgentDeck 管理的数据，stable profile 写入 `~/Library/Application Support/AgentDeck/`，dev profile 写入 `~/Library/Application Support/AgentDeck-Dev/`，不得写入用户项目仓库。
- SwiftPM/debug 构建未显式传 `--profile` 时默认使用 dev profile；release 构建默认使用 stable profile。
- profile 只影响 AgentDeck 管理的数据目录；不影响 Codex 登录状态、token 或 Codex app-server 历史。
- 写入前必须做 best-effort 密钥脱敏；写失败不能静默，必须在可诊断位置暴露。
- `protocol/` 里的 schema 必须来自官方 `codex app-server generate-json-schema`，不要手写或逆向猜测协议。
- AgentDeck 不读取、不保存、不转发 Codex token，只沿用用户已有 `codex login` 状态。

## 当前权衡

- Codex adapter 是 turn 级生命周期：每次新会话或继续历史 thread 都会 spawn
  `codex app-server`、initialize，并在 turn 结束时由 `Drop` kill 整个进程组。
  v0.1 暂无 adapter 复用池或 session 级常驻 adapter；连续对话依靠
  `thread/resume(threadId)` 保持 Codex 上下文。
- Codex app-server 的 stderr 只保留 daemon 内存中的有限尾部摘要，并在断连错误进入
  diagnostic log / UI error 时附带；它不是长期日志，也不写入用户项目仓库。

## 依赖方向

```text
Swift UI
  -> WorkbenchModel / ThreadRuntimeModel / SessionModel
  -> AgentDeck IPC models（来自 agentdeck-protocol）
  -> daemon stdio

daemon main
  -> ipc（re-export agentdeck-protocol）
  -> codex adapter
  -> record / diag
  -> codex app-server child process

agentdeck-cli（参考客户端 / E2E 驱动，与 GUI 互相独立）
  -> agentdeck-protocol（共享类型）
  -> Transport trait（ProcessTransport → daemon stdio）
  -> daemon child process
```

允许的跨层访问应沿上图向下。新增功能如果需要反向依赖，先把接口下沉到中立模型或 daemon adapter，不要让 UI 穿透到供应商协议。

## 协议即契约

`agentdeck-protocol` crate 是 IPC 协议的唯一事实源：

- `PROTOCOL_VERSION`：协议版本整数（`u32`，当前为 1），用于 `protocol version` 子命令输出（`{"protocolVersion": 1}`）与漂移检测。
- `protocol_schema()`：通过 schemars 从 Rust 类型派生的 JSON Schema，输出即 `protocol schema` 子命令所印内容。
- 快照文件：`protocol/agentdeck/agentdeck-protocol.schema.json`（由 `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` 重新生成）。
- 漂移测试随 `cargo test` 运行：协议类型变更而未重新生成快照则失败。
- 可验证中立性：协议 crate 中不得出现任何供应商字样（`Codex`、`OpenAI` 等）；中立性测试同步断言此约束。

## 变更指引

- 改 UI 行为：先看相关 `Sources/AgentDeck/*ViewController.swift` / `*Model.swift` 与最近的 `docs/plans/*design.md`。
- 改 IPC：同步更新 Swift/Rust 两侧模型、测试和 README/架构文档。
- 改 Codex 协议翻译：先看 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt`，再改 adapter。
- 改诊断或记录：同步更新 `docs/AGENT_DIAGNOSTICS.md` 和 `docs/QUALITY.md`。
- 新增 adapter：不得要求 Swift 侧知道该 adapter 的 vendor JSON。
