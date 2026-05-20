# Codex Permissions Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 让 AgentDeck 支持 Codex 权限管理的可视化、审批请求转发和用户决策回写，同时保持 Codex 作为权限执行与 sandbox 真相源。

**Architecture:** AgentDeck 不自行执行 sandbox，也不在 Swift 侧解析 Codex 原始协议。`agentdeckd` 在 Codex app-server 和 Swift UI 之间做中立 broker：识别 `ServerRequest` approval，映射为中立 `ActionRequest` 发给 Swift，等待 Swift 的 `ActionDecision` 后再回写 Codex JSON-RPC response。该计划依赖 `docs/plans/2026-05-20-agentdeck-async-runtime-hub-implementation.md` 的 daemon 双向事件循环能力；在当前同步 daemon 模型未收口前不得实施审批 UI 闭环。

**Tech Stack:** Rust 2024 / serde / serde_json / std::sync::mpsc，Swift 6 / SwiftUI / Observation / Testing，JSONL IPC，Codex app-server schema。

---

## 执行前置条件

- 先完成或至少稳定 `docs/plans/2026-05-20-agentdeck-async-runtime-hub-implementation.md` 中的 daemon runtime hub 改造。
- 执行前重新 review 当前 daemon 事件循环，不要基于旧同步主循环假设实现 approval。
- 执行前重新生成或核对 `protocol/` schema，确认 Codex 版本仍与 `protocol/CODEX_VERSION.txt` 一致。
- 不要添加 co-author / codex 合作者信息。
- Python 不涉及；JS/TS 不涉及。
- Rust 使用 `cargo test` / `cargo fmt --check` / `cargo clippy --all-targets -- -D warnings`。
- Swift 使用 `swift test` 和 `swift run AgentDeck -- --selfcheck`。
- 本计划必须 TDD 执行：先写失败测试，再做最小实现。

## 当前代码事实

- `agentdeckd/src/codex.rs` 的 `turn_start` 当前只发送 `threadId` 和 text `input`，没有显式传 `approvalPolicy`、`approvalsReviewer` 或 permission profile。
- `turn_start` 当前把 Codex `method` 当作 notification 翻译为 `AgentItem`；approval 是带 `id` 的 `ServerRequest`，需要回 JSON-RPC response。
- `agentdeckd/src/ipc.rs` 已有 `SessionState::WaitingApproval`，Swift `SessionModel.statusText` 也能显示等待审批，但还没有 pending approval 模型和决策回写。
- `README.md` 里的交互式 approve / deny 在代码闭环完成前只能作为目标能力，不能当作已完成事实扩写。

## 协议事实

- `turn/start` 可携带 `approvalPolicy` 和 `approvalsReviewer`，用于覆盖当前 turn 和后续 turn 的审批策略。
- `AskForApproval` 支持 `untrusted`、`on-failure`、`on-request`、`never`，以及 granular 模式。
- `ApprovalsReviewer` 支持 `user`、`auto_review` 和 legacy `guardian_subagent`。
- Codex 会通过 `ServerRequest` 发起：
  - `item/commandExecution/requestApproval`
  - `item/fileChange/requestApproval`
  - `item/permissions/requestApproval`
- `CommandExecutionApprovalDecision` 包含 `accept`、`acceptForSession`、`decline`、`cancel`，以及 execpolicy / network policy 持久化类决策。第一版不暴露持久化策略按钮。

## 非目标

- 不让 AgentDeck 自己执行 sandbox。
- 不让 Swift 解析 Codex 原始 JSON。
- 第一版不做 `acceptWithExecpolicyAmendment` 或 `applyNetworkPolicyAmendment`。
- 第一版不把 `approvalPolicy=never` 放进普通 UI；如果必须保留，只能放高级/调试入口并显式标红。
- 不在 daemon runtime hub 稳定前实现审批弹窗。

---

### Task 1: Approval 协议 spike 与 fixture 固化

**Files:**
- Create: `spike/approval-command-request.jsonl`
- Create: `spike/approval-file-change-request.jsonl`
- Create: `spike/approval-permissions-request.jsonl`
- Create: `spike/approval-response-shapes.md`
- Modify: `protocol/SPIKE_FINDINGS.md`

**Step 1: 构造或捕获三类 Codex approval request**

用真实 Codex app-server 或最小 fixture 捕获三类 request：

```text
item/commandExecution/requestApproval
item/fileChange/requestApproval
item/permissions/requestApproval
```

每个 fixture 必须保留：

- JSON-RPC `id`
- `method`
- `threadId`
- `turnId`
- `itemId`
- `approvalId`（如果存在）
- `reason`
- 类型特有字段，例如 `command`、`commandActions`、`cwd`、`grantRoot`、`permissions`

**Step 2: 实测 response envelope**

分别确认以下决策的 wire shape：

```json
{"id": "<request id>", "result": "accept"}
```

是否成立；如果不成立，把真实 shape 写入 `spike/approval-response-shapes.md`。

至少验证：

- command approval: `accept` / `decline` / `cancel`
- command approval: `acceptForSession`
- file change approval: 允许 / 拒绝的真实 result shape
- permissions approval: 允许 / 拒绝的真实 result shape

**Step 3: 更新 spike 文档**

在 `protocol/SPIKE_FINDINGS.md` 增加“approval response”小节，写清：

- 哪些 request method 已验证。
- 每类 request 的 response result shape。
- 哪些决策暂不支持。
- 哪些字段是 routing key，不能丢。

**Step 4: 提交**

```bash
git add spike/approval-*.jsonl spike/approval-response-shapes.md protocol/SPIKE_FINDINGS.md
git commit -m "docs: capture codex approval protocol fixtures"
```

---

### Task 2: 设计中立 ActionRequest / ActionDecision IPC

**Files:**
- Modify: `agentdeckd/src/ipc.rs`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Test: `agentdeckd/src/ipc.rs`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败的 Rust 序列化测试**

在 `agentdeckd/src/ipc.rs` 中新增中立 request 样例测试：

```rust
#[test]
fn action_request_serializes_without_vendor_names() {
    let req = ActionRequest {
        request_id: "42".into(),
        approval_id: Some("approval-1".into()),
        item_id: "item-1".into(),
        thread_id: "thread-1".into(),
        turn_id: "turn-1".into(),
        kind: ActionRequestKind::CommandExecution,
        title: "Run command".into(),
        reason: Some("needs network".into()),
        cwd: Some("/tmp/project".into()),
        command: Some("bun test".into()),
        command_actions: vec![ToolAction {
            kind: "run".into(),
            command: "bun test".into(),
            path: None,
            name: None,
            query: None,
        }],
        files: Vec::new(),
        network_target: None,
        permission_summary: None,
        supported_decisions: vec![
            ActionDecisionKind::Accept,
            ActionDecisionKind::Decline,
            ActionDecisionKind::Cancel,
        ],
    };

    let wire = serde_json::to_string(&req).unwrap();
    assert!(wire.contains(r#""kind":"commandExecution""#));
    assert!(!wire.to_lowercase().contains("codex"));
}
```

**Step 2: 实现中立 Rust 类型**

在 `agentdeckd/src/ipc.rs` 增加：

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActionRequest {
    pub request_id: String,
    pub approval_id: Option<String>,
    pub item_id: String,
    pub thread_id: String,
    pub turn_id: String,
    pub kind: ActionRequestKind,
    pub title: String,
    pub reason: Option<String>,
    pub cwd: Option<String>,
    pub command: Option<String>,
    pub command_actions: Vec<ToolAction>,
    pub files: Vec<FileEditChange>,
    pub network_target: Option<String>,
    pub permission_summary: Option<String>,
    pub supported_decisions: Vec<ActionDecisionKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ActionRequestKind {
    CommandExecution,
    FileChange,
    Permissions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ActionDecisionKind {
    Accept,
    AcceptForSession,
    Decline,
    Cancel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActionDecision {
    pub request_id: String,
    pub decision: ActionDecisionKind,
}
```

新增 helper：

```rust
impl IpcMessage {
    pub fn action_request(req: &ActionRequest) -> Self {
        Self {
            kind: "actionRequest".into(),
            id: None,
            payload: Some(serde_json::to_value(req).expect("action request serializes")),
        }
    }
}
```

**Step 3: 写 Swift decode / encode 测试**

在 `Tests/AgentDeckTests/IpcTests.swift` 增加：

```swift
@Test("ActionRequest decodes neutral command approval")
func actionRequestDecodesNeutralCommandApproval() throws {
    let data = Data("""
    {
      "requestId": "42",
      "approvalId": "approval-1",
      "itemId": "item-1",
      "threadId": "thread-1",
      "turnId": "turn-1",
      "kind": "commandExecution",
      "title": "Run command",
      "reason": "needs network",
      "cwd": "/tmp/project",
      "command": "bun test",
      "commandActions": [],
      "files": [],
      "networkTarget": null,
      "permissionSummary": null,
      "supportedDecisions": ["accept", "decline", "cancel"]
    }
    """.utf8)

    let req = try JSONDecoder().decode(ActionRequest.self, from: data)

    #expect(req.requestId == "42")
    #expect(req.kind == .commandExecution)
    #expect(req.supportedDecisions == [.accept, .decline, .cancel])
}

@Test("ActionDecision encodes neutral decision")
func actionDecisionEncodesNeutralDecision() throws {
    let decision = ActionDecision(requestId: "42", decision: .decline)
    let data = try JSONEncoder().encode(decision)
    let text = String(decoding: data, as: UTF8.self)

    #expect(text.contains(#""requestId":"42""#))
    #expect(text.contains(#""decision":"decline""#))
}
```

**Step 4: 实现 Swift 类型**

在合适的 Swift model 文件中增加同名 `Codable` 类型。若后续拆文件，优先建 `Sources/AgentDeck/ActionRequestModel.swift`。

**Step 5: 验证**

```bash
cargo test action_request_serializes_without_vendor_names
swift test --filter ActionRequest
```

**Step 6: 提交**

```bash
git add agentdeckd/src/ipc.rs Sources/AgentDeck/ActionRequestModel.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: add neutral action approval IPC"
```

---

### Task 3: daemon broker 支持 pending approval 生命周期

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Modify: `agentdeckd/src/codex.rs`
- Test: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/codex.rs`

**Step 1: 先 review runtime hub 当前实现**

执行本任务前先复核：

```bash
rg -n "RuntimeHub|session/event|mpsc|startTurn|startSession|actionDecision|roundTrip" agentdeckd/src Sources/AgentDeck
```

确认 daemon 在 turn 运行期间仍能读取 Swift stdin。若不能，本任务停止，先回到 async runtime hub 计划。

**Step 2: 写 pending approval 生命周期测试**

新增测试覆盖：

- 收到 Codex approval request 后建立 pending entry。
- pending entry 包含原始 JSON-RPC request id。
- 收到 Swift `actionDecision` 后移除 pending entry。
- session 结束 / interrupt / error 时 pending entry 失效。

示例测试名：

```rust
#[test]
fn pending_approval_tracks_original_request_id_until_decision() {
    // 构造 approval request，映射 pending，再用 action decision 消除。
}
```

**Step 3: CodexAdapter 暴露 request 分类**

把当前只返回 `AgentItem` 的 notification 翻译拆成两类事件：

```rust
enum CodexStreamEvent {
    AgentItem(AgentItem),
    ApprovalRequest {
        request_id: String,
        method: String,
        params: serde_json::Value,
    },
    TurnCompleted,
}
```

识别逻辑：

- 有 `id` 且有 `method`，并且 method 是三类 approval request -> `ApprovalRequest`
- 无 `id` 且有 `method` -> notification -> 走现有 `translate`
- response id == turn/start id -> ack 或 error

**Step 4: broker 等待 Swift 决策**

runtime hub 中收到 `ApprovalRequest` 后：

1. 建立 pending map：`requestId -> PendingApproval`
2. 发 `sessionState(waitingApproval)`
3. 发中立 `actionRequest`
4. 等 Swift `actionDecision`
5. 按 spike 的真实 response shape 回写 Codex
6. 发 `sessionState(running)`

**Step 5: 决策超时和取消**

第一版不自动批准。若用户取消 session 或 daemon shutdown：

- 向 Codex 回 `cancel` 或按 spike 规定的取消 shape。
- 清掉 pending map。
- 发可见 error 或 warning。

**Step 6: 验证**

```bash
cargo test pending_approval
cargo test approval_request
cargo test
```

**Step 7: 提交**

```bash
git add agentdeckd/src/main.rs agentdeckd/src/codex.rs agentdeckd/src/ipc.rs
git commit -m "feat: route codex approval requests through daemon broker"
```

---

### Task 4: Swift 展示最小审批面板

**Files:**
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写 SessionModel 测试**

新增测试：

```swift
@Test("action request enters waiting approval state")
func actionRequestEntersWaitingApprovalState() throws {
    let model = SessionModel()
    model.phase = .running

    let payload: [String: Any] = [
        "requestId": "42",
        "approvalId": NSNull(),
        "itemId": "item-1",
        "threadId": "thread-1",
        "turnId": "turn-1",
        "kind": "commandExecution",
        "title": "Run command",
        "reason": "needs network",
        "cwd": "/tmp/project",
        "command": "bun test",
        "commandActions": [],
        "files": [],
        "supportedDecisions": ["accept", "decline", "cancel"]
    ]

    model.ingest(IpcMessage(kind: "actionRequest", payload: AnyCodable(payload)))

    #expect(model.phase == .waitingApproval)
    #expect(model.pendingActionRequest?.requestId == "42")
}
```

**Step 2: 实现 SessionModel 状态**

新增：

```swift
var pendingActionRequest: ActionRequest?
```

`ingest(_:)` 增加：

- `case "actionRequest"` 解码 payload 到 `ActionRequest`
- 设置 `pendingActionRequest`
- 设置 `phase = .waitingApproval`

新增方法：

```swift
func decidePendingAction(_ decision: ActionDecisionKind) {
    guard let request = pendingActionRequest else { return }
    client.sendActionDecision(ActionDecision(requestId: request.requestId, decision: decision))
    pendingActionRequest = nil
    phase = .running
}
```

**Step 3: DaemonClient 编码 actionDecision**

新增：

```swift
func sendActionDecision(_ decision: ActionDecision) {
    let payload = try? JSONEncoder().encode(decision)
    // 转成 AnyCodable 后发 kind = "actionDecision"
}
```

具体实现需沿用现有 JSONL IPC writer，避免再起第二个 stdout reader。

**Step 4: 最小 UI**

`SessionView` 在输入框上方或会话底部固定显示审批面板：

- 标题：按 `ActionRequest.kind` 显示“命令需要审批”“文件变更需要审批”“请求更多权限”
- 主体：
  - command approval: command / cwd / reason / action chips
  - file change approval: files / reason / grant root
  - permissions approval: permission summary / reason
- 按钮：
  - `允许一次` -> `.accept`
  - `本次会话允许` -> `.acceptForSession`，仅当 `supportedDecisions` 包含该值
  - `拒绝` -> `.decline`
  - `拒绝并停止` -> `.cancel`

**Step 5: 验证**

```bash
swift test --filter actionRequest
swift test
```

**Step 6: 提交**

```bash
git add Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/SessionView.swift Sources/AgentDeck/DaemonClient.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: show codex approval requests in session UI"
```

---

### Task 5: 权限策略预设与运行态展示

**Files:**
- Modify: `agentdeckd/src/ipc.rs`
- Modify: `agentdeckd/src/codex.rs`
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Test: `agentdeckd/src/codex.rs`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 定义第一版预设**

第一版普通 UI 只暴露：

- `codexDefault`: 不覆盖 Codex config
- `conservativeUserReview`: `approvalPolicy = "on-request"`，`approvalsReviewer = "user"`
- `autoReview`: `approvalsReviewer = "auto_review"`，不强行覆盖 `approvalPolicy`

`never` 不进入普通 UI。

**Step 2: Rust turn/start 参数测试**

新增测试确认预设转成正确 JSON：

```rust
#[test]
fn conservative_user_review_adds_approval_policy_and_reviewer() {
    let params = turn_start_params(
        "thread-1",
        "hello",
        Some(PermissionPreset::ConservativeUserReview),
    );

    assert_eq!(params["approvalPolicy"], "on-request");
    assert_eq!(params["approvalsReviewer"], "user");
}
```

**Step 3: 实现参数构造**

从 `CodexAdapter::turn_start` 抽出参数构造函数。不要在 UI 中直接拼 Codex 字段；Swift 发中立 preset，Rust adapter 翻译为 Codex 字段。

**Step 4: 运行态展示**

从 `thread/start` / `thread/resume` response 中读取实际值：

- `approvalPolicy`
- `approvalsReviewer`
- `sandbox`
- 后续如 schema 稳定，可补 `permissionProfile`

映射成中立 `permissionState` IPC，Swift 顶部状态区展示：

- 审批策略
- 审批人
- sandbox / permission profile 摘要

**Step 5: 验证**

```bash
cargo test conservative_user_review
swift test --filter PermissionState
cargo test
swift test
```

**Step 6: 提交**

```bash
git add agentdeckd/src/ipc.rs agentdeckd/src/codex.rs Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/SessionView.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: expose codex permission presets and state"
```

---

### Task 6: 文档同步与复审

**Files:**
- Modify: `README.md`
- Modify: `protocol/SPIKE_FINDINGS.md`
- Modify: `docs/plans/2026-05-20-codex-permissions-implementation.md`
- Optional Create: `docs/CODEX_PERMISSIONS.md`

**Step 1: README 只写高层事实**

README 的权限段落必须保持简短：

- Codex 是权限执行真相源。
- AgentDeck 展示权限状态并转发审批请求。
- Swift 只消费中立 IPC。
- 详细协议与实现计划链接到本计划或 `docs/CODEX_PERMISSIONS.md`。

**Step 2: 详细文档写边界**

如果新增 `docs/CODEX_PERMISSIONS.md`，内容限制为：

- 用户可见概念：审批策略、审批人、sandbox / permission profile、审批请求。
- 实现边界：Codex 执行，AgentDeck 审查与留痕。
- 不承诺未实现的持久化策略按钮。

**Step 3: 跑完整验证**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
swift test
cargo build && swift run AgentDeck -- --selfcheck
git diff --check
```

**Step 4: 最终 review 检查清单**

实现完成后再次 review，重点检查：

- daemon turn 运行中是否仍能读 Swift `actionDecision`。
- pending approval 是否能正确过期。
- 是否把 Codex 原始 JSON 泄漏到 Swift。
- 是否把 `approvalPolicy=never` 暴露给普通 UI。
- README 是否把目标能力写成已完成事实。
- approval response shape 是否来自 fixture，而不是猜测。

**Step 5: 提交**

```bash
git add README.md protocol/SPIKE_FINDINGS.md docs/plans/2026-05-20-codex-permissions-implementation.md docs/CODEX_PERMISSIONS.md
git commit -m "docs: document codex permissions support"
```

---

## 下一轮 review 触发条件

在以下条件之一满足后，再对本计划做一次实施前 review：

- `docs/plans/2026-05-20-agentdeck-async-runtime-hub-implementation.md` 已完成并通过测试。
- daemon 主循环已能在 turn 运行期间同时处理 Swift stdin 与 Codex stdout。
- 已经有新的 daemon runtime hub 分支或提交可审查。

下一轮 review 不看 UI 细节，先看两个阻塞点：

1. approval request 到达时 daemon 是否会因为同步主循环无法读取 Swift decision 而死锁。
2. 三类 approval response shape 是否已经用 fixture 或真实 spike 固化。
