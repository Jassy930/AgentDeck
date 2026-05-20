# AgentDeck Async Runtime Hub Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把 AgentDeck 从单会话、单阻塞 IPC 运行模型升级为单 `agentdeckd` runtime hub，支持多个后台会话并行运行，同时前台历史列表、读取、重命名和归档操作不被后台 turn 阻塞。

**Architecture:** `agentdeckd` 作为 workbench runtime hub：stdin reader 始终接收请求，stdout writer 统一输出 reply 和 session event，session worker 独立持有 `CodexAdapter` 并通过 channel 回传事件。Swift 端只有一个 `DaemonClient` stdout reader dispatcher，按 `id` 分发 request/reply，按 `sessionId/threadId` 分发 streaming event 到多个 `ThreadRuntimeModel`。

**Tech Stack:** Swift 6 / SwiftUI / Observation / Testing，Rust 2024 / serde / serde_json / std::thread / std::sync::mpsc，JSONL IPC，Codex app-server adapter。

---

## 执行前置条件

- 当前仓库已有未提交改动。执行本计划前先确认这些改动的归属，避免覆盖他人工作。
- 不要添加 co-author / codex 合作者信息。
- Python 不涉及；JS/TS 不涉及。Swift 使用 `swift test`，Rust 使用 `cargo test` / `cargo fmt` / `cargo clippy`。
- 本计划按 TDD 执行；每个任务先写失败测试，再做最小实现，再提交。

## 目标行为

- 可以同时运行多个历史 thread 或新 thread。
- 前台切换历史 thread 只改变展示，不停止后台会话。
- history list/read/archive/rename 在任意 turn 运行中仍能响应。
- stdout 只有一个 reader；不存在 `roundTrip()` 和 streaming thread 抢同一个 `BufferedLineReader` 的情况。
- 每条 session event 都可路由到确定的 `sessionId`，必要时也带 `threadId`。

## 非目标

- 不做跨进程共享 daemon。
- 不引入数据库。
- 不重做 Codex 协议翻译层的 item 语义。
- 不在本轮实现复杂资源限额、取消/暂停 UI、跨 provider 适配。

---

### Task 1: 给中立 IPC 增加路由字段和 session event envelope

**Files:**
- Modify: `agentdeckd/src/ipc.rs`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Test: `agentdeckd/src/ipc.rs`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败的 Rust 协议测试**

在 `agentdeckd/src/ipc.rs` 的 `mod tests` 中新增：

```rust
#[test]
fn ipc_message_can_carry_session_and_thread_routing() {
    let msg = IpcMessage {
        kind: "session/event".into(),
        id: None,
        session_id: Some("session_1".into()),
        thread_id: Some("thread_1".into()),
        payload: Some(serde_json::json!({
            "event": { "kind": "turnComplete" }
        })),
    };

    let wire = serde_json::to_string(&msg).unwrap();
    assert!(wire.contains(r#""sessionId":"session_1""#));
    assert!(wire.contains(r#""threadId":"thread_1""#));
    assert!(!wire.to_lowercase().contains("codex"));
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test ipc_message_can_carry_session_and_thread_routing
```

Expected: FAIL，`IpcMessage` 没有 `session_id` / `thread_id` 字段。

**Step 3: 实现最小 Rust 协议字段**

修改 `agentdeckd/src/ipc.rs`：

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpcMessage {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "threadId", skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}
```

更新现有构造函数 `pong`、`error`、`agent_item`、`session_state`，补上 `session_id: None` 和 `thread_id: None`。

新增 helper：

```rust
impl IpcMessage {
    pub fn session_event(session_id: &str, thread_id: Option<&str>, event: IpcMessage) -> Self {
        Self {
            kind: "session/event".into(),
            id: None,
            session_id: Some(session_id.to_string()),
            thread_id: thread_id.map(str::to_string),
            payload: Some(serde_json::json!({ "event": event })),
        }
    }
}
```

**Step 4: 写失败的 Swift decode 测试**

在 `Tests/AgentDeckTests/IpcTests.swift` 的 `IpcMessageTests` 中新增：

```swift
@Test("IpcMessage decodes session and thread routing fields")
func decodesRoutingFields() throws {
    let data = Data("""
    {"kind":"session/event","sessionId":"session_1","threadId":"thread_1","payload":{"event":{"kind":"turnComplete"}}}
    """.utf8)

    let msg = try JSONDecoder().decode(IpcMessage.self, from: data)

    #expect(msg.kind == "session/event")
    #expect(msg.sessionId == "session_1")
    #expect(msg.threadId == "thread_1")
}
```

**Step 5: 实现 Swift 协议字段**

修改 `Sources/AgentDeck/DaemonClient.swift` 的 `IpcMessage`：

```swift
struct IpcMessage: Codable {
    let kind: String
    var id: UInt64?
    var sessionId: String?
    var threadId: String?
    var payload: AnyCodable?
}
```

更新所有直接构造 `IpcMessage(...)` 的调用点，必要时显式传 `sessionId: nil, threadId: nil`，或依靠 memberwise initializer 的默认值。若需要默认值，添加自定义 init：

```swift
init(kind: String, id: UInt64? = nil, sessionId: String? = nil, threadId: String? = nil, payload: AnyCodable? = nil) {
    self.kind = kind
    self.id = id
    self.sessionId = sessionId
    self.threadId = threadId
    self.payload = payload
}
```

**Step 6: 验证**

Run:

```bash
cargo test ipc_message_can_carry_session_and_thread_routing
swift test --filter IpcMessageTests
```

Expected: PASS。

**Step 7: 提交**

```bash
git add agentdeckd/src/ipc.rs Sources/AgentDeck/DaemonClient.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: add routed IPC message fields"
```

---

### Task 2: 把 Swift DaemonClient 改成唯一 reader dispatcher

**Files:**
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试：dispatcher 按 id 匹配 reply，stream event 不会被 request 吞掉**

新增一个纯函数测试，先抽出可测试路由器类型：

```swift
@Suite("Daemon message routing")
struct DaemonMessageRoutingTests {
    @Test("routes replies by id and session events by session id")
    func routesRepliesAndSessionEventsSeparately() {
        let router = DaemonMessageRouter()
        var events: [IpcMessage] = []
        router.onSessionEvent = { events.append($0) }

        router.registerPending(id: 31)
        router.route(IpcMessage(kind: "session/event", sessionId: "s1", payload: AnyCodable([
            "event": ["kind": "agentItem"]
        ])))
        router.route(IpcMessage(kind: "historyThread", id: 31, payload: AnyCodable(["thread": [:], "items": []])))

        #expect(events.count == 1)
        #expect(router.takeReply(id: 31)?.kind == "historyThread")
    }
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter DaemonMessageRoutingTests
```

Expected: FAIL，`DaemonMessageRouter` 不存在。

**Step 3: 实现 `DaemonMessageRouter`**

在 `Sources/AgentDeck/DaemonClient.swift` 中新增：

```swift
@MainActor
final class DaemonMessageRouter {
    var onSessionEvent: ((IpcMessage) -> Void)?
    var onUnmatchedMessage: ((IpcMessage) -> Void)?

    private var pendingIds = Set<UInt64>()
    private var replies: [UInt64: IpcMessage] = [:]

    func registerPending(id: UInt64) {
        pendingIds.insert(id)
    }

    func route(_ msg: IpcMessage) {
        if let id = msg.id, pendingIds.contains(id) {
            replies[id] = msg
            return
        }
        if msg.kind == "session/event" {
            onSessionEvent?(msg)
            return
        }
        onUnmatchedMessage?(msg)
    }

    func takeReply(id: UInt64) -> IpcMessage? {
        pendingIds.remove(id)
        return replies.removeValue(forKey: id)
    }
}
```

**Step 4: 将 reader 所有权集中到 `DaemonClient`**

替换 `roundTrip()` 直接 `reader.nextLine()` 的模型。最小实现可以先保持同步等待，但等待对象必须来自 router：

```swift
private let router = DaemonMessageRouter()
private let routerLock = NSLock()
private var pendingReplies: [UInt64: Result<IpcMessage, Error>] = [:]
private let pendingCondition = NSCondition()
private var nextRequestId: UInt64 = 1
```

新增单 reader loop：

```swift
private func startReaderLoopIfNeeded() {
    guard readerLoopStarted, let reader else { return }
    readerLoopStarted = true
    Thread.detachNewThread { [weak self, reader] in
        while let raw = reader.nextLine() {
            guard !raw.isEmpty else { continue }
            guard let msg = try? JSONDecoder().decode(IpcMessage.self, from: Data(raw.utf8)) else {
                continue
            }
            Task { @MainActor in
                self?.handleIncoming(msg)
            }
        }
    }
}
```

`handleIncoming(_:)` 中按 `id` 唤醒 pending reply，否则分发 session event。

**Step 5: 废弃 streaming 方法里的 `Thread.detachNewThread`**

`startSession` / `startTurn` 只负责发送 request，不再自己开 reader：

```swift
func startTurn(sessionId: String, threadId: String, prompt: String) throws {
    let msg = IpcMessage(
        kind: "startTurn",
        id: nextId(),
        sessionId: sessionId,
        threadId: threadId,
        payload: AnyCodable(["threadId": threadId, "prompt": prompt])
    )
    try send(msg)
}
```

**Step 6: 验证**

Run:

```bash
swift test --filter DaemonMessageRoutingTests
swift test --filter IpcMessageTests
```

Expected: PASS。

**Step 7: 提交**

```bash
git add Sources/AgentDeck/DaemonClient.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "fix: route daemon replies through a single reader"
```

---

### Task 3: daemon 引入 hub channel 和非阻塞 writer

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/main.rs`

**Step 1: 写失败的 Rust 单元测试：hub command 可以生成立即 ack**

在 `agentdeckd/src/main.rs` tests 中新增纯函数测试：

```rust
#[test]
fn start_turn_request_builds_session_started_ack() {
    let msg = IpcMessage {
        kind: "startTurn".into(),
        id: Some(42),
        session_id: Some("session_1".into()),
        thread_id: Some("thread_1".into()),
        payload: Some(serde_json::json!({
            "threadId": "thread_1",
            "prompt": "continue"
        })),
    };

    let ack = start_turn_ack(&msg).unwrap();

    assert_eq!(ack.kind, "turnAccepted");
    assert_eq!(ack.id, Some(42));
    assert_eq!(ack.session_id.as_deref(), Some("session_1"));
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test start_turn_request_builds_session_started_ack
```

Expected: FAIL，`start_turn_ack` 不存在。

**Step 3: 实现 hub 基础类型**

在 `agentdeckd/src/main.rs` 新增：

```rust
#[derive(Debug, Clone)]
struct HubSession {
    session_id: String,
    thread_id: Option<String>,
}

fn start_turn_ack(msg: &IpcMessage) -> Result<IpcMessage, String> {
    let session_id = msg
        .session_id
        .clone()
        .ok_or_else(|| "startTurn requires sessionId".to_string())?;
    Ok(IpcMessage {
        kind: "turnAccepted".into(),
        id: msg.id,
        session_id: Some(session_id),
        thread_id: msg.thread_id.clone(),
        payload: None,
    })
}
```

**Step 4: 引入 stdout writer channel**

在 `main()` 中创建：

```rust
let (out_tx, out_rx) = std::sync::mpsc::channel::<IpcMessage>();
let writer = std::thread::spawn(move || {
    let mut stdout = std::io::stdout();
    for msg in out_rx {
        if write_msg(&mut stdout, &msg).is_err() {
            break;
        }
    }
});
```

主循环不再直接持有 `stdout` 写入所有路径，而是 `out_tx.send(msg)`。

**Step 5: 保持历史请求同步但经 writer channel 回复**

先不并发化 history 内部实现，只把回复写入 `out_tx`，避免多个线程直接写 stdout。

**Step 6: 验证**

Run:

```bash
cargo test start_turn_request_builds_session_started_ack
cargo test
```

Expected: PASS。

**Step 7: 提交**

```bash
git add agentdeckd/src/main.rs
git commit -m "feat: add daemon hub output channel"
```

---

### Task 4: startTurn/startSession 改为 worker 线程并立即返回 ack

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/main.rs`

**Step 1: 写失败测试：startTurn 不应直接进入阻塞执行路径**

新增可测试 dispatch 函数：

```rust
#[test]
fn dispatch_start_turn_returns_ack_without_running_turn_inline() {
    let msg = IpcMessage {
        kind: "startTurn".into(),
        id: Some(7),
        session_id: Some("session_7".into()),
        thread_id: Some("thread_7".into()),
        payload: Some(serde_json::json!({
            "threadId": "thread_7",
            "prompt": "hello"
        })),
    };

    let action = classify_request(&msg).unwrap();

    assert!(matches!(action, HubAction::SpawnTurn { .. }));
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test dispatch_start_turn_returns_ack_without_running_turn_inline
```

Expected: FAIL，`HubAction` / `classify_request` 不存在。

**Step 3: 实现 request classifier**

```rust
enum HubAction {
    Reply(IpcMessage),
    SpawnTurn {
        id: Option<u64>,
        session_id: String,
        thread_id: Option<String>,
        cwd: Option<String>,
        prompt: String,
    },
    Shutdown,
}
```

`startSession` 映射到 `SpawnTurn { thread_id: None, cwd: Some(cwd), prompt }`。  
`startTurn` 映射到 `SpawnTurn { thread_id: Some(thread_id), cwd: None, prompt }`。

**Step 4: 实现 worker spawn**

主循环收到 `HubAction::SpawnTurn`：

```rust
let ack = IpcMessage {
    kind: "turnAccepted".into(),
    id,
    session_id: Some(session_id.clone()),
    thread_id: thread_id.clone(),
    payload: None,
};
let _ = out_tx.send(ack);

let worker_tx = out_tx.clone();
std::thread::spawn(move || {
    if let Err(err) = run_turn_worker(worker_tx.clone(), id, &session_id, thread_id.as_deref(), cwd.as_deref(), &prompt) {
        let _ = worker_tx.send(IpcMessage {
            kind: "session/event".into(),
            id: None,
            session_id: Some(session_id),
            thread_id,
            payload: Some(serde_json::json!({
                "event": { "kind": "error", "payload": { "message": err.to_string() } }
            })),
        });
    }
});
```

**Step 5: 改造 worker 输出**

新增 `emit_session_event()`：

```rust
fn emit_session_event(
    tx: &std::sync::mpsc::Sender<IpcMessage>,
    session_id: &str,
    thread_id: Option<&str>,
    event: IpcMessage,
) {
    let _ = tx.send(IpcMessage::session_event(session_id, thread_id, event));
}
```

把 `run_session` / `run_turn_on_existing_thread` 中的 `write_msg(stdout, ...)` 改成向 `tx` 发送 session event。保留历史请求 reply 为顶层 reply。

**Step 6: 验证**

Run:

```bash
cargo test dispatch_start_turn_returns_ack_without_running_turn_inline
cargo test
```

Expected: PASS。

**Step 7: 提交**

```bash
git add agentdeckd/src/main.rs
git commit -m "feat: run turns as daemon hub workers"
```

---

### Task 5: Swift 引入 ThreadRuntimeModel 和 WorkbenchModel

**实施记录（2026-05-20）：** 已完成 Swift 多 runtime 状态层的第一步。`WorkbenchModel` 负责按 `sessionId` 查找并路由到既有 `ThreadRuntimeModel`；`ThreadRuntimeModel` 暂时复制 `SessionModel` 的 item 合并逻辑，UI 和历史读取切换留给 Task 6。

**Files:**
- Create: `Sources/AgentDeck/ThreadRuntimeModel.swift`
- Create: `Sources/AgentDeck/WorkbenchModel.swift`
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试：两个 runtime 独立接收事件**

```swift
@Suite("Workbench runtime model")
@MainActor
struct WorkbenchRuntimeModelTests {
    @Test("routes session events to the matching runtime")
    func routesEventsToMatchingRuntime() {
        let workbench = WorkbenchModel()
        workbench.ensureRuntime(sessionId: "s1", threadId: "t1", cwd: URL(fileURLWithPath: "/tmp/a"))
        workbench.ensureRuntime(sessionId: "s2", threadId: "t2", cwd: URL(fileURLWithPath: "/tmp/b"))

        workbench.ingestSessionEvent(IpcMessage(
            kind: "session/event",
            sessionId: "s2",
            threadId: "t2",
            payload: AnyCodable([
                "event": [
                    "kind": "agentItem",
                    "payload": [
                        "id": "m1",
                        "lifecycle": "completed",
                        "kind": "message",
                        "text": "B done"
                    ]
                ]
            ])
        ))

        #expect(workbench.runtime(sessionId: "s1")?.items.isEmpty == true)
        #expect(workbench.runtime(sessionId: "s2")?.items.count == 1)
    }
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter WorkbenchRuntimeModelTests
```

Expected: FAIL，`WorkbenchModel` 不存在。

**Step 3: 创建 `ThreadRuntimeModel`**

从现有 `SessionModel` 迁移单会话字段：

```swift
@MainActor
@Observable
final class ThreadRuntimeModel: Identifiable {
    let id: String
    var threadId: String?
    var cwd: URL
    var phase: SessionModel.Phase = .ready
    var items: [UIItem] = []
    var queuedPrompts: [String] = []
    var errorMessage: String?
    var unreadEventCount = 0
    var itemIndexById: [String: Int] = [:]
    var pendingAgentItems: [[String: Any]] = []
}
```

先把 `upsert` / `flushPendingAgentItems` 复制到 runtime，后续再从 `SessionModel` 删除重复逻辑。

**Step 4: 创建 `WorkbenchModel`**

```swift
@MainActor
@Observable
final class WorkbenchModel {
    private(set) var runtimes: [String: ThreadRuntimeModel] = [:]
    var selectedSessionId: String?

    func ensureRuntime(sessionId: String, threadId: String?, cwd: URL) {
        if runtimes[sessionId] == nil {
            runtimes[sessionId] = ThreadRuntimeModel(id: sessionId, threadId: threadId, cwd: cwd)
        }
    }

    func runtime(sessionId: String) -> ThreadRuntimeModel? {
        runtimes[sessionId]
    }
}
```

**Step 5: 实现 session event 解包**

`WorkbenchModel.ingestSessionEvent(_:)` 从 payload 中拿 `event`，再调用对应 runtime 的 `ingest(_:)`。

**Step 6: 验证**

Run:

```bash
swift test --filter WorkbenchRuntimeModelTests
swift test --filter SessionRenderThrottlingTests
```

Expected: PASS。

**Step 7: 提交**

```bash
git add Sources/AgentDeck/ThreadRuntimeModel.swift Sources/AgentDeck/WorkbenchModel.swift Sources/AgentDeck/SessionModel.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: add multi-thread workbench runtime model"
```

---

### Task 6: 让历史读取使用 WorkbenchModel，不中断后台 runtime

**Files:**
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Modify: `Sources/AgentDeck/WorkbenchModel.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试：running runtime 存在时打开历史 thread 不改 running phase**

```swift
@Test("opening history does not change an existing running runtime")
@MainActor
func openingHistoryDoesNotChangeRunningRuntime() {
    let workbench = WorkbenchModel()
    workbench.ensureRuntime(sessionId: "running", threadId: "thread_running", cwd: URL(fileURLWithPath: "/tmp/a"))
    workbench.runtime(sessionId: "running")?.phase = .running

    let detail = HistoryThreadDetail(
        thread: HistoryThreadSummary(id: "thread_b", name: nil, preview: "B", cwd: "/tmp/b", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli"),
        items: [HistoryReplayItem(id: "m1", lifecycle: "completed", kind: "message", text: "old")]
    )

    workbench.applyHistoryThreadDetail(detail)

    #expect(workbench.runtime(sessionId: "running")?.phase == .running)
    #expect(workbench.selectedSessionId == "thread_b")
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter openingHistoryDoesNotChangeRunningRuntime
```

Expected: FAIL，`applyHistoryThreadDetail` 不存在或仍覆盖单 `SessionModel.items`。

**Step 3: 实现 history detail 到 runtime 的映射**

在 `WorkbenchModel` 中：

```swift
func applyHistoryThreadDetail(_ detail: HistoryThreadDetail) {
    let sessionId = detail.thread.id
    let runtime = ThreadRuntimeModel(
        id: sessionId,
        threadId: detail.thread.id,
        cwd: URL(fileURLWithPath: detail.thread.cwd)
    )
    runtime.applyReplayItems(detail.items)
    runtimes[sessionId] = runtime
    selectedSessionId = sessionId
}
```

**Step 4: 改 `SessionView` 读取 selected runtime**

将 `conversationStream` 的 `model.items` 改为 `model.selectedRuntime.items`。如果暂时保留 `SessionModel` 作为 facade，则新增：

```swift
var selectedItems: [UIItem] {
    workbench.selectedRuntime?.items ?? []
}
```

**Step 5: 保留历史侧栏可操作**

不要在 `.running` 时禁用 history row。历史 row 点击仍调用 `openHistoryThread`，但该方法只更新 workbench selected runtime，不触碰其他 runtime。

**Step 6: 验证**

Run:

```bash
swift test --filter WorkbenchRuntimeModelTests
swift test --filter TextualCompatibilityTests
```

Expected: PASS。

**Step 7: 提交**

```bash
git add Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/SessionView.swift Sources/AgentDeck/WorkbenchModel.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: open history threads without interrupting runtimes"
```

**规格复核修正（2026-05-20）：** `SessionModel.applyHistoryThreadDetail(_:)` 只能同步当前选中的 history thread 元数据并委托 `WorkbenchModel.applyHistoryThreadDetail(_:)` 切换 selected runtime；不得 flush 或覆盖 legacy `items/itemIndexById/errorMessage/phase`。实际 `SessionModel` 路径新增回归测试：当 legacy `phase == .running` 时打开 history 后仍保持 `.running`，legacy `items` 保持当前 stream，`selectedItems` 切到 history replay。

---

### Task 7: 多 runtime submit 和队列行为

**Files:**
- Modify: `Sources/AgentDeck/ThreadRuntimeModel.swift`
- Modify: `Sources/AgentDeck/WorkbenchModel.swift`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: 写失败测试：同一 runtime running 时只排队，不影响其他 runtime**

```swift
@Test("submitting to running runtime queues only that runtime")
@MainActor
func submittingToRunningRuntimeQueuesOnlyThatRuntime() {
    let workbench = WorkbenchModel()
    workbench.ensureRuntime(sessionId: "a", threadId: "thread_a", cwd: URL(fileURLWithPath: "/tmp/a"))
    workbench.ensureRuntime(sessionId: "b", threadId: "thread_b", cwd: URL(fileURLWithPath: "/tmp/b"))
    workbench.runtime(sessionId: "a")?.phase = .running
    workbench.selectedSessionId = "a"

    workbench.submit("continue A")

    #expect(workbench.runtime(sessionId: "a")?.queuedPrompts == ["continue A"])
    #expect(workbench.runtime(sessionId: "b")?.queuedPrompts.isEmpty == true)
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter submittingToRunningRuntimeQueuesOnlyThatRuntime
```

Expected: FAIL，`WorkbenchModel.submit` 不存在。

**Step 3: 实现 `WorkbenchModel.submit`**

```swift
func submit(_ prompt: String) {
    guard let runtime = selectedRuntime else { return }
    let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return }

    if runtime.phase == .running || runtime.phase == .starting || runtime.phase == .waitingApproval {
        runtime.queuedPrompts.append(trimmed)
        return
    }

    runtime.appendUserPrompt(trimmed)
    runtime.phase = .starting
    daemonClient.startTurn(
        sessionId: runtime.id,
        threadId: runtime.threadId,
        cwd: runtime.cwd,
        prompt: trimmed
    )
}
```

**Step 4: 让 `turnComplete` 只 drain 对应 runtime 队列**

在 `ThreadRuntimeModel.ingest(_:)` 处理 `turnComplete` 后返回一个 `RuntimeAction.drainNextPrompt(String)`，由 `WorkbenchModel` 再发起下一次 turn。

**Step 5: 验证**

Run:

```bash
swift test --filter WorkbenchRuntimeModelTests
swift test
```

Expected: PASS。

**Step 6: 提交**

```bash
git add Sources/AgentDeck/ThreadRuntimeModel.swift Sources/AgentDeck/WorkbenchModel.swift Sources/AgentDeck/DaemonClient.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: queue prompts per runtime"
```

---

### Task 8: daemon history 请求在 turn 运行中仍可响应

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/main.rs`

**Step 1: 写失败测试：history 请求分类为同步 reply action，而不是 session worker**

```rust
#[test]
fn classify_history_read_as_foreground_request() {
    let msg = IpcMessage {
        kind: "history/readThread".into(),
        id: Some(9),
        session_id: None,
        thread_id: None,
        payload: Some(serde_json::json!({ "threadId": "thread_1" })),
    };

    let action = classify_request(&msg).unwrap();

    assert!(matches!(action, HubAction::HistoryRead { .. }));
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
cargo test classify_history_read_as_foreground_request
```

Expected: FAIL。

**Step 3: 实现 History action**

扩展 `HubAction`：

```rust
HistoryList { id: Option<u64>, params: HistoryListParams },
HistoryRead { id: Option<u64>, thread_id: String },
ThreadManagement { id: Option<u64>, action: String, thread_id: String, name: Option<String> },
```

**Step 4: 让 history action 使用短 worker**

为了避免 history 读取阻塞 stdin 主循环，history action 也 spawn 一个短 worker：

```rust
let tx = out_tx.clone();
std::thread::spawn(move || {
    let reply = run_history_read_message(id, &thread_id);
    let _ = tx.send(reply);
});
```

新增 `run_history_read_message()` 返回 `IpcMessage`，不要直接写 stdout。

**Step 5: 验证并手工模拟**

Run:

```bash
cargo test classify_history_read_as_foreground_request
cargo test
```

Expected: PASS。

**Step 6: 提交**

```bash
git add agentdeckd/src/main.rs
git commit -m "feat: keep history requests responsive during turns"
```

---

### Task 9: UI 展示多个后台 runtime 状态

**Files:**
- Modify: `Sources/AgentDeck/SessionView.swift`
- Modify: `Sources/AgentDeck/WorkbenchModel.swift`
- Test: `Tests/AgentDeckTests/TextualCompatibilityTests.swift`

**Step 1: 写失败测试：runtime selector view 可创建**

```swift
@Test("runtime selector view can be created")
@MainActor
func runtimeSelectorViewCanBeCreated() {
    let workbench = WorkbenchModel()
    workbench.ensureRuntime(sessionId: "s1", threadId: "t1", cwd: URL(fileURLWithPath: "/tmp/a"))
    _ = RuntimeSelectorView(workbench: workbench)
}
```

**Step 2: 运行测试确认失败**

Run:

```bash
swift test --filter runtimeSelectorViewCanBeCreated
```

Expected: FAIL，`RuntimeSelectorView` 不存在。

**Step 3: 创建 runtime selector**

在 `Sources/AgentDeck/SessionView.swift` 或新文件 `Sources/AgentDeck/RuntimeSelectorView.swift` 中：

```swift
struct RuntimeSelectorView: View {
    @Bindable var workbench: WorkbenchModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(workbench.runtimeList) { runtime in
                Button {
                    workbench.selectedSessionId = runtime.id
                    runtime.unreadEventCount = 0
                } label: {
                    HStack {
                        Circle().frame(width: 7, height: 7)
                        Text(runtime.displayTitle)
                            .lineLimit(1)
                        Spacer()
                        if runtime.unreadEventCount > 0 {
                            Text("\(runtime.unreadEventCount)")
                        }
                    }
                }
                .buttonStyle(.plain)
            }
        }
    }
}
```

**Step 4: 接入主窗口**

在 history sidebar 和 conversation stream 之间或 history sidebar 顶部加入 compact runtime selector。不要做 landing page，不要做大卡片。

**Step 5: 验证**

Run:

```bash
swift test --filter TextualCompatibilityTests
swift test
```

Expected: PASS。

**Step 6: 提交**

```bash
git add Sources/AgentDeck/SessionView.swift Sources/AgentDeck/RuntimeSelectorView.swift Tests/AgentDeckTests/TextualCompatibilityTests.swift
git commit -m "feat: show concurrent runtime selector"
```

---

### Task 10: 端到端回归 malformed reply 场景

**Files:**
- Modify: `Tests/AgentDeckTests/IpcTests.swift`
- Modify: `agentdeckd/src/main.rs`
- Modify: `Sources/AgentDeck/DaemonClient.swift`

**Step 1: 写 Swift 路由回归测试**

```swift
@Test("history reply is not confused with streaming agent item")
func historyReplyIsNotConfusedWithAgentItem() {
    let router = DaemonMessageRouter()
    router.registerPending(id: 99)
    var events: [IpcMessage] = []
    router.onSessionEvent = { events.append($0) }

    router.route(IpcMessage(
        kind: "session/event",
        sessionId: "s1",
        payload: AnyCodable([
            "event": [
                "kind": "agentItem",
                "payload": ["id": "a1", "lifecycle": "delta", "kind": "message", "text": "hi"]
            ]
        ])
    ))
    router.route(IpcMessage(kind: "historyThread", id: 99, payload: AnyCodable([
        "thread": [
            "id": "thread_b", "preview": "B", "cwd": "/tmp/b",
            "createdAt": 1, "updatedAt": 2, "status": "ready",
            "modelProvider": "openai", "source": "cli"
        ],
        "items": []
    ])))

    #expect(events.count == 1)
    #expect(router.takeReply(id: 99)?.kind == "historyThread")
}
```

**Step 2: 写 daemon dispatch 回归测试**

测试 `startTurn` 被分类为 `SpawnTurn`，随后 `history/readThread` 仍可分类为 `HistoryRead`，不依赖前一个 turn 完成。

**Step 3: 运行确认失败或通过**

Run:

```bash
swift test --filter historyReplyIsNotConfusedWithAgentItem
cargo test classify_history_read_as_foreground_request
```

Expected: 如果前面任务实现完整，这里 PASS；如果失败，修正 router 或 classifier。

**Step 4: 全量验证**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
swift test
cargo build
swift build
```

Expected: 全部 PASS。

**Step 5: 手工验证**

Run:

```bash
cargo build
swift run AgentDeck
```

手工步骤：

1. 打开一个历史 thread。
2. 提交一个需要等待的 prompt。
3. 等待 Codex 回复时点击另一个历史 thread。
4. 确认不会出现 `malformed reply from agentdeckd: expected historyThread, got agentItem`。
5. 切回第一个 thread，确认后台回复继续增长或完成。
6. 刷新历史列表，确认 UI 不被后台 turn 阻塞。

**Step 6: 提交**

```bash
git add Tests/AgentDeckTests/IpcTests.swift agentdeckd/src/main.rs Sources/AgentDeck/DaemonClient.swift
git commit -m "test: cover concurrent history and stream routing"
```

---

### Task 11: 更新项目文档

**Files:**
- Modify: `README.md`
- Modify: `docs/plans/2026-05-20-codex-thread-history-design.md`
- Create: `docs/plans/2026-05-20-agentdeck-async-runtime-hub-design.md`

**Step 1: 写设计文档**

新增 `docs/plans/2026-05-20-agentdeck-async-runtime-hub-design.md`，包含：

- 当前单 reader / 单 daemon 阻塞模型的问题。
- runtime hub 架构图。
- IPC 路由字段。
- Swift `WorkbenchModel` / `ThreadRuntimeModel` / `DaemonClient` 分工。
- daemon stdin reader / stdout writer / session worker 分工。
- 不做项。

**Step 2: 更新 README**

在 `README.md` 架构段落补充：

```markdown
AgentDeck 使用一个 `agentdeckd` 作为 runtime hub。daemon 的 stdin 主循环不被单个 turn 阻塞；每个后台会话由独立 worker 持有 adapter，所有 worker 通过统一 stdout writer 输出带 `sessionId/threadId` 的中立事件。
```

**Step 3: 更新历史设计文档**

在 `docs/plans/2026-05-20-codex-thread-history-design.md` 标记：历史读写不再与 streaming turn 共享直接 reader，所有历史 reply 通过 request id 分发。

**Step 4: 验证文档没有过时说法**

Run:

```bash
rg -n "single reader|roundTrip|one consumer|startTurn.*阻塞|disable history|禁用历史|expected historyThread" README.md docs Sources agentdeckd
```

Expected: 只保留解释旧问题或测试名，不出现把旧阻塞模型描述为当前架构的正文。

**Step 5: 提交**

```bash
git add README.md docs/plans/2026-05-20-codex-thread-history-design.md docs/plans/2026-05-20-agentdeck-async-runtime-hub-design.md
git commit -m "docs: describe async runtime hub architecture"
```

---

### Task 12: 最终质量门和工作区收口

**Files:**
- No source changes expected.

**Step 1: 全量验证**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
swift test
cargo build
swift build
git diff --check
```

Expected: 全部 PASS，无 whitespace error。

**Step 2: selfcheck**

Run:

```bash
cargo build && swift run AgentDeck -- --selfcheck
```

Expected: `selfcheck OK`，或输出更新后的明确成功文案。

**Step 3: 查看 git 状态**

Run:

```bash
git status --short --branch
```

Expected: 工作区干净，分支领先远端若干提交。

**Step 4: 最终提交或整理**

如果还有只属于本功能的未提交文件：

```bash
git add <files>
git commit -m "chore: finish async runtime hub"
```

不要提交无关用户改动。
