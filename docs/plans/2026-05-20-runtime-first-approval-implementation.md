# Runtime-First Conversation and Approval Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 收敛 AgentDeck v0.1 的普通新会话上下文、Swift runtime 模型和 Codex approval 双向路径，确保连续对话和 approve / deny 都有可测试闭环。

**Architecture:** Swift 侧以 `WorkbenchModel` / `ThreadRuntimeModel` 为唯一会话运行时入口，普通 live session 与历史 thread 统一消费 `session/event`。Rust daemon 先抽出轻量 runtime hub 和 turn runner，按 `sessionId` 管理状态与队列，再把 Codex server request approval 映射为中立 `ActionRequest`，由 Swift 回写 `ActionDecision`。

**Tech Stack:** Swift 6 / SwiftUI / Observation / Testing，Rust 2024 / serde / serde_json / std::sync::mpsc，JSONL IPC，Codex app-server schema。

---

## 背景

当前审查结论显示主架构方向正确：Codex-aware 细节位于 Rust daemon / adapter，Swift 面向中立 IPC。但 v0.1 的两个北极星能力还存在缺口：

- 普通新会话仍走 legacy `startSession(cwd:onLine:)` raw-line 流，后续 prompt 可能新建 thread，导致 UI 连续但 Codex 上下文不连续。
- Codex app-server 的 approval 是带 `id` 的 server request，当前 `turn_start` 只消费 notification 和 `turn/completed`，没有中立审批请求和决策回写。

本计划只做渐进式收敛，不引入新 UI 大改、不重做协议 schema、不新增非 Codex adapter。

## 总体验收

- 普通 live session 首次 submit 创建 runtime，并在 daemon 返回真实 `threadId` 后写回 runtime；后续 submit 一律走 `startTurn` 续接同一 thread。
- Swift 不再依赖 legacy raw-line stream 处理正在运行的会话事件；新旧历史回放都走 `session/event` / runtime reducer。
- 未知中立 `raw` item 和 daemon `warning` 不被静默丢弃。
- daemon 对同一 `sessionId` 具备最小队列和互斥，不再无限制直接 thread-per-request。
- Codex `item/commandExecution/requestApproval`、`item/fileChange/requestApproval`、`item/permissions/requestApproval` 至少能映射成中立 `ActionRequest`，Swift approve / deny 后能回写 Codex response。
- 验证命令通过：`cargo test`、`swift test`、`swift run AgentDeck -- --selfcheck`、`swift run AgentDeck -- --diagnostics-report --json`、`scripts/verify-agent-docs.sh`。

## Task 1: Runtime-First 普通新会话

**Files:**
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/WorkbenchModel.swift`
- Modify: `Sources/AgentDeck/ThreadRuntimeModel.swift`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试**

新增 Swift 测试覆盖：

- `SessionModel.submit` 在没有 selected runtime 但有 `cwd` 时，会创建 live runtime。
- 首次 submit 发送带 `sessionId` 的 runtime `startSession`。
- 收到 `session/event` 外层 `threadId` 后，runtime.threadId 被写回。
- 第二次 submit 复用同一 runtime 并发送 `startTurn(threadId)`，不再新建 `startSession`。

建议测试名：

```swift
@Test("live session continues on returned thread id")
func liveSessionContinuesOnReturnedThreadId()
```

**Step 2: 运行失败测试**

```bash
swift test --filter liveSessionContinuesOnReturnedThreadId
```

Expected: FAIL，原因应指向当前 `SessionModel.submit` 仍走 legacy `client.startSession(cwd:onLine:)`。

**Step 3: 最小实现**

- 在 `SessionModel.submit(_:)` 中，如果 `workbench.selectedRuntime == nil` 且 `cwd != nil`，创建一个 live runtime。
- runtime id 使用稳定生成值，例如 `live-<UUID>`；不要继续依赖 `"session_1"`。
- 统一调用 `workbench.submit(prompt)`。
- `WorkbenchModel.ingestSessionEvent(_:)` 已能从外层 `threadId` 写回 runtime，保留这个路径。
- `DaemonClient.startTurn(sessionId:threadId:cwd:prompt:onEvent:)` 已具备按 `threadId` 选择 `startTurn` / `startSession` 的形态，优先复用它。

**Step 4: 运行验证**

```bash
swift test --filter liveSessionContinuesOnReturnedThreadId
swift test
```

Expected: PASS。

**Step 5: 文档更新**

更新 `README.md` 的历史会话 / runtime 描述：普通新会话和历史 thread 都进入同一个 runtime 模型，后续 prompt 续接 daemon 返回的真实 `threadId`。

**Step 6: Commit**

```bash
git add Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/WorkbenchModel.swift Sources/AgentDeck/ThreadRuntimeModel.swift Sources/AgentDeck/DaemonClient.swift Tests/AgentDeckTests/IpcTests.swift README.md
git commit -m "fix: continue live sessions on runtime thread ids"
```

## Task 2: 隔离并下线 legacy raw-line stream

**Files:**
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试**

新增测试覆盖：

- `DaemonMessageRouter` 对 `session/event` 的主路径只投递 `IpcMessage`，不需要 legacy raw line 才能驱动 runtime。
- runtime 模式下收到其他 runtime 的 `session/event` 不会进入当前 runtime。
- legacy API 被标记为 deprecated 或只保留给测试兼容，不再被 `SessionModel.submit` 调用。

**Step 2: 运行失败测试**

```bash
swift test --filter sessionEventsDriveRuntimeWithoutRawLines
```

Expected: FAIL，当前仍有 raw-line handler 路径。

**Step 3: 最小实现**

- 保留 `DaemonClient.startSession(cwd:prompt:onLine:)` 和 `startTurn(threadId:prompt:onLine:)` 作为临时 deprecated 私有兼容入口，避免一次性删除造成大 diff。
- `SessionModel` 不再调用 raw-line API。
- `DaemonMessageRouter.encodeLegacySessionEventRawLine` 相关逻辑只服务 deprecated 测试，新增注释说明后续删除条件。

**Step 4: 修复 raw / warning 可见性**

- 删除 `ThreadRuntimeModel.upsert(_:)` 里 `if kind == "raw" { return }`。
- 增加测试：runtime 收到 `raw` item 后 `items` 包含 `kind == "raw"` 且 `descriptionText` 可见。
- 确认 `warning` session event 能在 runtime 或 selected warning facade 中显示；如果当前只在 legacy `SessionModel` 可见，给 `ThreadRuntimeModel` 增加 `warningMessage`。

**Step 5: 运行验证**

```bash
swift test --filter raw
swift test --filter warning
swift test
```

Expected: PASS。

**Step 6: 文档更新**

更新 `docs/AGENT_DIAGNOSTICS.md`：未知 adapter item 应显示为 `raw`，run record 和 UI 都不能静默丢弃。

**Step 7: Commit**

```bash
git add Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/ThreadRuntimeModel.swift Tests/AgentDeckTests/IpcTests.swift docs/AGENT_DIAGNOSTICS.md
git commit -m "fix: route runtime events without legacy raw streams"
```

## Task 3: 抽 Swift AgentItemReducer / RuntimeItemStore

**Files:**
- Create: `Sources/AgentDeck/AgentItemReducer.swift`
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/ThreadRuntimeModel.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试**

新增 reducer 单元测试覆盖：

- message / reasoning delta 追加。
- shell output delta 追加。
- fileEdit completed 更新 diff。
- raw item 保留 description。
- 大 output / diff replay 仍按阈值 deferred。

**Step 2: 运行失败测试**

```bash
swift test --filter AgentItemReducer
```

Expected: FAIL，因为 reducer 还不存在。

**Step 3: 最小实现**

把 `ThreadRuntimeModel.upsert(_:)` 的纯数据逻辑搬到 `AgentItemReducer`：

```swift
struct AgentItemStore {
    var items: [UIItem] = []
    var itemIndexById: [String: Int] = [:]
}

enum AgentItemReducer {
    static func upsert(_ payload: [String: Any], into store: inout AgentItemStore)
}
```

`ThreadRuntimeModel` 持有 `AgentItemStore` 或用 store 同步 `items/itemIndexById`。`SessionModel` legacy path 若尚未删除，也调用同一个 reducer。

**Step 4: 运行验证**

```bash
swift test --filter AgentItemReducer
swift test
```

Expected: PASS。

**Step 5: Commit**

```bash
git add Sources/AgentDeck/AgentItemReducer.swift Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/ThreadRuntimeModel.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "refactor: share agent item reduction across runtimes"
```

## Task 4: Rust turn runner 去重

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/main.rs`

**Step 1: 写失败测试**

新增 Rust 单元测试覆盖 turn action 构造，不直接调用真实 Codex：

- new session runner 在 `cwd` 模式下先发 `Starting`，再写 start record。
- resumed thread runner 在 `threadId` 模式下先发 `Starting`，并带 `threadId`。
- turn failure 统一发 `error` + `Failed`。

如需要，先抽纯函数生成事件序列，避免测试真实 app-server。

**Step 2: 运行失败测试**

```bash
cargo test turn_runner
```

Expected: FAIL。

**Step 3: 最小实现**

抽内部 helper，例如：

```rust
struct TurnRunContext<'a> {
    id: Option<u64>,
    session_id: &'a str,
    thread_id: Option<&'a str>,
    cwd: Option<&'a str>,
    prompt: &'a str,
}
```

把 `run_session` 和 `run_turn_on_existing_thread` 共享的：

- run id / event seq
- state emit
- record append
- adapter spawn / initialize
- `turn_start` streaming callback
- success / failure state

收敛到一个 helper。保留 `run_session` / `run_turn_on_existing_thread` 作为薄 wrapper。

**Step 4: 运行验证**

```bash
cargo test
```

Expected: PASS。

**Step 5: Commit**

```bash
git add agentdeckd/src/main.rs
git commit -m "refactor: share daemon turn runner"
```

## Task 5: 轻量 RuntimeHub 与并发上限

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/main.rs`
- Update: `ARCHITECTURE.md`

**Step 1: 写失败测试**

新增 Rust 测试覆盖：

- 同一 `sessionId` 的第二个 `SpawnTurn` 不会直接启动第二个 worker，而是进入队列或返回明确 busy。
- 不同 `sessionId` 可以并行。
- history worker 有简单并发上限，超限时排队或返回可诊断错误。

**Step 2: 运行失败测试**

```bash
cargo test runtime_hub
```

Expected: FAIL。

**Step 3: 最小实现**

在 `main.rs` 引入轻量 `RuntimeHub` 数据结构，先保持进程内、无持久化：

- `HashMap<String, RuntimeSlot>`
- `RuntimeSlot { phase, queued_turns }`
- `max_history_workers: usize`
- `handle_spawn_turn(...) -> HubDispatch`

第一版不做取消、不做 interrupt，只保证同一 `sessionId` 互斥和有界 history worker。

**Step 4: 运行验证**

```bash
cargo test
swift test
```

Expected: PASS。

**Step 5: 文档更新**

更新 `ARCHITECTURE.md` 和 `README.md` 的 daemon hub 描述：stdin main loop 通过 RuntimeHub 管理 per-session 状态，不再是无界 thread-per-request。

**Step 6: Commit**

```bash
git add agentdeckd/src/main.rs ARCHITECTURE.md README.md
git commit -m "refactor: add bounded runtime hub"
```

## Task 6: 中立 ActionRequest / ActionDecision 协议

**Files:**
- Modify: `agentdeckd/src/ipc.rs`
- Modify: `agentdeckd/src/codex.rs`
- Modify: `agentdeckd/src/main.rs`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: `Sources/AgentDeck/ThreadRuntimeModel.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`
- Test: `agentdeckd/src/codex.rs`
- Update: `docs/AGENT_DIAGNOSTICS.md`
- Update: `ARCHITECTURE.md`

**Step 1: 核对协议事实源**

只读检查：

```bash
rg -n "requestApproval|approvalId|approve|deny" protocol/ServerRequest.json protocol/codex_app_server_protocol.v2.schemas.json
```

确认至少覆盖：

- `item/commandExecution/requestApproval`
- `item/fileChange/requestApproval`
- `item/permissions/requestApproval`

**Step 2: 写 Rust 失败测试**

在 `codex.rs` 新增 fixture 测试：

- 带 `id` 的 approval server request 不应被当成普通 response 忽略。
- request 映射成中立 action request，包含 `requestId`、`itemId`、`approvalId`、`actionKind`、摘要字段。
- decision 回写时能生成 Codex response，approve / deny 均覆盖。

**Step 3: 写 Swift 失败测试**

新增 Swift 测试：

- runtime 收到 `actionRequest` 进入 `.waitingApproval`。
- UI model 能存储 pending action request。
- 调用 approve / deny 会发送 `actionDecision`，且 runtime 回到 running/draining 等 daemon 后续状态。

**Step 4: 运行失败测试**

```bash
cargo test approval
swift test --filter approval
```

Expected: FAIL。

**Step 5: 实现中立 IPC**

在 `ipc.rs` 增加中立类型，避免 Codex vocabulary 出现在 Swift 协议字段名：

```rust
pub struct ActionRequest {
    pub request_id: u64,
    pub item_id: String,
    pub approval_id: Option<String>,
    pub action_kind: String,
    pub title: String,
    pub detail: String,
}
```

IPC kind 建议：

- daemon -> Swift: `actionRequest`
- Swift -> daemon: `actionDecision`

decision payload:

```json
{
  "requestId": 42,
  "decision": "approve"
}
```

**Step 6: Codex adapter 支持 server request**

调整 `turn_start` 读取循环：

- `msg.id == turn_start_id`：仍按 turn/start ack 处理。
- `msg.id` 存在且 `method` 是 approval request：映射并 emit `ActionRequest`，然后等待 Swift decision。
- 收到 decision 后向 Codex app-server 写回对应 response。

注意：这一步需要 daemon worker 能接收 Swift 后续 `actionDecision`，所以必须在 Task 5 的 RuntimeHub 基础上做，避免 worker 只单向输出。

**Step 7: Swift UI 最小闭环**

`SessionView` 先做最小 approve / deny 控件：

- 显示 action title/detail。
- 两个按钮：Approve / Deny。
- 不做复杂 policy、不做记忆审批、不做自动审批。

**Step 8: 运行验证**

```bash
cargo test approval
swift test --filter approval
cargo test
swift test
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
```

Expected: PASS，selfcheck 和 diagnostics report 无新增 failure。

**Step 9: 文档更新**

- `README.md`：补 v0.1 approve / deny 当前支持范围。
- `ARCHITECTURE.md`：补 `ActionRequest` / `ActionDecision` 在 IPC 中立边界的位置。
- `docs/AGENT_DIAGNOSTICS.md`：补 approval 卡住时的 failure code / 下一步排查。
- `docs/QUALITY.md`：补涉及 approval 必跑 Rust + Swift + selfcheck。

**Step 10: Commit**

```bash
git add agentdeckd/src/ipc.rs agentdeckd/src/codex.rs agentdeckd/src/main.rs Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/ThreadRuntimeModel.swift Sources/AgentDeck/SessionView.swift Tests/AgentDeckTests/IpcTests.swift docs/AGENT_DIAGNOSTICS.md docs/QUALITY.md ARCHITECTURE.md README.md
git commit -m "feat: add neutral approval requests"
```

## 不建议现在动

- 不要在 approval 闭环前继续叠大型 UI 功能、云端 adapter 或多 agent 聊天能力。
- 不要现在引入 async runtime / tokio 重写 daemon；先用轻量 hub 把状态边界立住。
- 不要手写或猜测 `protocol/` schema；approval 字段必须来自官方 schema 快照和 fixture。
- 不要一次性删除所有 legacy 代码；先让 runtime-first 路径全量覆盖，再删 deprecated raw-line 兼容层。
- 不要把 Codex token、run record、diagnostic log 或用户项目数据写入仓库。

## 最终收口

完成全部任务后运行：

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
swift test
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
scripts/verify-agent-docs.sh
git status --short --branch
```

如果 `cargo clippy` 当前仓库尚未纳入质量门，第一次失败时先按真实输出修复或记录到本计划的实施偏差，不要绕过。
