# Codex Thread History Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 让 AgentDeck 可以扫描、导入、浏览并恢复 Codex app-server 已有的历史 thread。

**Architecture:** Rust daemon 继续作为唯一 Codex-aware 边界，新增 history IPC 请求并调用 `thread/list`、`thread/read`、`thread/resume`。Swift 只消费中立历史模型，按项目分组展示，并在恢复 thread 后继续发送 turn。

**Tech Stack:** Swift 6 / SwiftUI / Swift Testing，Rust 2024 / serde_json，Codex app-server JSONL IPC。

---

### Task 0: 修复当前 Swift 测试基线

**Files:**
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: Run current failing test**

Run:

```bash
swift test
```

Expected: FAIL at `SessionModel.deinit` because a nonisolated deinitializer reads MainActor-isolated timer properties.

**Step 2: Write the smallest fix**

Remove direct timer invalidation from `deinit`, and rely on explicit `teardown()` for lifecycle cleanup. Keep `teardown()` invalidating timers and shutting down the daemon.

Implementation shape:

```swift
func teardown() {
    flushPendingAgentItems()
    renderFlushTimer?.invalidate()
    renderFlushTimer = nil
    tickTimer?.invalidate()
    tickTimer = nil
    client.shutdown()
}
```

**Step 3: Verify Swift tests pass**

Run:

```bash
swift test
```

Expected: PASS.

**Step 4: Verify Rust tests still pass**

Run:

```bash
cargo test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/SessionModel.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "test: restore Swift session model baseline"
```

Only commit these files if the existing render-throttling changes are intended to be part of this baseline fix. If they are unrelated user work, do not include them; ask before staging.

### Task 1: Define neutral history IPC types

**Files:**
- Modify: `agentdeckd/src/ipc.rs`
- Test: `agentdeckd/src/ipc.rs`

**Step 1: Write failing tests**

Add tests that serialize a history thread summary and assert the JSON has no vendor vocabulary.

Test shape:

```rust
#[test]
fn history_thread_summary_serializes_without_vendor_names() {
    let summary = HistoryThreadSummary {
        id: "thread_1".into(),
        name: Some("Fix tests".into()),
        preview: "please fix tests".into(),
        cwd: "/tmp/project".into(),
        created_at: 1,
        updated_at: 2,
        status: "completed".into(),
        model_provider: "openai".into(),
        source: "cli".into(),
    };
    let wire = serde_json::to_string(&summary).unwrap().to_lowercase();
    assert!(!wire.contains("codex"));
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
cargo test history_thread_summary_serializes_without_vendor_names
```

Expected: FAIL because `HistoryThreadSummary` is not defined.

**Step 3: Implement minimal IPC structs**

Add:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryThreadSummary {
    pub id: String,
    pub name: Option<String>,
    pub preview: String,
    pub cwd: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub status: String,
    pub model_provider: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryThreadList {
    pub threads: Vec<HistoryThreadSummary>,
    pub next_cursor: Option<String>,
}
```

Keep these names agent-neutral. No Swift changes yet.

**Step 4: Verify**

Run:

```bash
cargo test history_thread_summary_serializes_without_vendor_names
cargo test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add agentdeckd/src/ipc.rs
git commit -m "feat: add neutral history thread IPC types"
```

### Task 2: Add CodexAdapter thread/list with fixture tests

**Files:**
- Modify: `agentdeckd/src/codex.rs`
- Test: `agentdeckd/src/codex.rs`

**Step 1: Write failing parser test**

Add a pure parser test that converts a `thread/list` response JSON into `HistoryThreadList`.

Test shape:

```rust
#[test]
fn thread_list_response_maps_to_history_summaries() {
    let value = json!({
        "data": [{
            "id": "thread_1",
            "name": "Fix tests",
            "preview": "please fix tests",
            "cwd": "/tmp/project",
            "createdAt": 10,
            "updatedAt": 20,
            "status": "ready",
            "modelProvider": "openai",
            "source": {"kind": "cli"},
            "cliVersion": "0.0.0",
            "ephemeral": false,
            "sessionId": "session_1",
            "turns": []
        }],
        "nextCursor": "cursor_2"
    });
    let list = thread_list_to_history(&value).unwrap();
    assert_eq!(list.threads[0].id, "thread_1");
    assert_eq!(list.threads[0].cwd, "/tmp/project");
    assert_eq!(list.next_cursor.as_deref(), Some("cursor_2"));
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
cargo test thread_list_response_maps_to_history_summaries
```

Expected: FAIL because `thread_list_to_history` is missing.

**Step 3: Implement minimal parser and adapter method**

Add a helper:

```rust
fn thread_list_to_history(value: &Value) -> Result<HistoryThreadList, CodexError>
```

Add adapter method:

```rust
pub fn thread_list(
    &mut self,
    cwd: Option<&str>,
    search_term: Option<&str>,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<HistoryThreadList, CodexError>
```

It sends `thread/list` with `archived: false`, optional `cwd`, `searchTerm`, `cursor`, `limit`, and returns the neutral list.

**Step 4: Verify**

Run:

```bash
cargo test thread_list_response_maps_to_history_summaries
cargo test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add agentdeckd/src/codex.rs agentdeckd/src/ipc.rs
git commit -m "feat: list Codex history threads through neutral adapter"
```

### Task 3: Wire history/listThreads through daemon IPC

**Files:**
- Modify: `agentdeckd/src/main.rs`
- Test: `agentdeckd/src/main.rs` or `agentdeckd/src/ipc.rs`

**Step 1: Write failing dispatch test or helper test**

Extract payload parsing into a helper such as:

```rust
fn history_list_params(payload: Option<&serde_json::Value>) -> HistoryListParams
```

Test expected parsing:

```rust
#[test]
fn history_list_params_reads_optional_filters() {
    let p = json!({"cwd": "/tmp/project", "searchTerm": "fix", "limit": 20});
    let params = history_list_params(Some(&p));
    assert_eq!(params.cwd.as_deref(), Some("/tmp/project"));
    assert_eq!(params.search_term.as_deref(), Some("fix"));
    assert_eq!(params.limit, Some(20));
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
cargo test history_list_params_reads_optional_filters
```

Expected: FAIL because helper does not exist.

**Step 3: Implement daemon handler**

Add a `history/listThreads` branch in `main.rs`:

```rust
"history/listThreads" => {
    // spawn adapter, initialize, call thread_list, write kind historyThreads
}
```

Response shape:

```json
{"kind":"historyThreads","id":1,"payload":{"threads":[...],"nextCursor":"..."}}
```

Failures use existing visible `error` response.

**Step 4: Verify**

Run:

```bash
cargo test history_list_params_reads_optional_filters
cargo test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add agentdeckd/src/main.rs agentdeckd/src/codex.rs agentdeckd/src/ipc.rs
git commit -m "feat: expose history thread listing over IPC"
```

### Task 4: Add Swift history models and grouping tests

**Files:**
- Create: `Sources/AgentDeck/HistoryModel.swift`
- Modify: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: Write failing Swift tests**

Add a `HistoryThreadSummary` Swift struct decode test and cwd grouping test.

Test shape:

```swift
@Suite("History model")
struct HistoryModelTests {
    @Test("decodes neutral history thread summary")
    func decodesSummary() throws {
        let data = Data("""
        {"id":"thread_1","name":"Fix tests","preview":"please fix tests","cwd":"/tmp/project","createdAt":10,"updatedAt":20,"status":"ready","modelProvider":"openai","source":"cli"}
        """.utf8)
        let item = try JSONDecoder().decode(HistoryThreadSummary.self, from: data)
        #expect(item.cwd == "/tmp/project")
    }

    @Test("groups threads by project cwd")
    func groupsByProject() {
        let groups = HistoryProjectGroup.group([...])
        #expect(groups.count == 2)
    }
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter HistoryModelTests
```

Expected: FAIL because types do not exist.

**Step 3: Implement minimal Swift models**

Create neutral Swift structs:

```swift
struct HistoryThreadSummary: Identifiable, Codable, Equatable {
    let id: String
    var name: String?
    var preview: String
    var cwd: String
    var createdAt: Int
    var updatedAt: Int
    var status: String
    var modelProvider: String
    var source: String
}
```

Add grouping helper:

```swift
struct HistoryProjectGroup: Identifiable, Equatable {
    var id: String { cwd }
    let cwd: String
    let threads: [HistoryThreadSummary]

    static func group(_ threads: [HistoryThreadSummary]) -> [HistoryProjectGroup]
}
```

**Step 4: Verify**

Run:

```bash
swift test --filter HistoryModelTests
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/HistoryModel.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: add Swift history thread model"
```

### Task 5: Add DaemonClient history/listThreads

**Files:**
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: Write failing encode/decode test**

Add a test for the request payload:

```swift
@Test("history list request encodes neutral filters")
func historyListRequestEncodesFilters() throws {
    let msg = DaemonClient.historyListRequest(id: 7, cwd: "/tmp/project", searchTerm: "fix")
    let s = String(data: try JSONEncoder().encode(msg), encoding: .utf8)!
    #expect(s.contains("\"kind\":\"history/listThreads\""))
    #expect(s.contains("\"cwd\":\"/tmp/project\""))
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter historyListRequestEncodesFilters
```

Expected: FAIL because factory is missing.

**Step 3: Implement minimal client method**

Add:

```swift
static func historyListRequest(id: UInt64, cwd: String?, searchTerm: String?) -> IpcMessage
```

Then add a blocking method for first version:

```swift
func listHistoryThreads(cwd: String?, searchTerm: String?) throws -> [HistoryThreadSummary]
```

It starts the daemon if needed at the caller level, sends request, decodes `historyThreads`.

**Step 4: Verify**

Run:

```bash
swift test --filter historyListRequestEncodesFilters
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Sources/AgentDeck/DaemonClient.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: request history threads from daemon"
```

### Task 6: Render history list in SessionView

**Files:**
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: Write failing model test**

Add a test that injecting history summaries produces project groups and preserves current session items.

```swift
@Test("loading history groups threads without clearing current stream")
@MainActor
func loadingHistoryDoesNotClearCurrentStream() {
    let model = SessionModel()
    model.ingest(...)
    model.setHistoryThreads([...])
    #expect(model.items.count == 1)
    #expect(model.historyGroups.count == 1)
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter loadingHistoryDoesNotClearCurrentStream
```

Expected: FAIL because history state APIs do not exist.

**Step 3: Implement model state and simple UI**

Add to `SessionModel`:

```swift
var historyThreads: [HistoryThreadSummary] = []
var historyGroups: [HistoryProjectGroup] { HistoryProjectGroup.group(historyThreads) }
var historyErrorMessage: String?
```

Add `loadHistory()` that calls `DaemonClient.listHistoryThreads`.

In `SessionView`, add a compact history panel or sidebar with:

- Refresh button.
- Project group heading from `cwd`.
- Thread title from `name ?? preview`.
- Updated timestamp.

Use restrained macOS system styling; no nested cards.

**Step 4: Verify**

Run:

```bash
swift test --filter loadingHistoryDoesNotClearCurrentStream
swift test
```

Expected: PASS.

**Step 5: Manual check**

Run:

```bash
cargo build
swift run AgentDeck
```

Expected: App opens, history panel can request a list without crashing. If Codex app-server has no history, show an empty state.

**Step 6: Commit**

```bash
git add Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/SessionView.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: show Codex history threads by project"
```

### Task 7: Read a historical thread and replay turns

**Files:**
- Modify: `agentdeckd/src/ipc.rs`
- Modify: `agentdeckd/src/codex.rs`
- Modify: `agentdeckd/src/main.rs`
- Modify: `Sources/AgentDeck/HistoryModel.swift`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Test: `agentdeckd/src/codex.rs`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: Write failing Rust fixture test**

Test that `thread/read` response with `turns[].items[]` maps to a neutral detail model with replayable items.

Expected: FAIL because detail parser does not exist.

**Step 2: Implement neutral detail structs**

Rust:

```rust
pub struct HistoryThreadDetail {
    pub thread: HistoryThreadSummary,
    pub items: Vec<AgentItem>,
}
```

Swift:

```swift
struct HistoryThreadDetail: Codable, Equatable {
    let thread: HistoryThreadSummary
    let items: [HistoryReplayItem]
}
```

For first version, map only `agentMessage`, `reasoning`, `commandExecution`, and `fileChange` using existing translation helpers. Unknown items should be omitted from replay but still counted later if needed.

**Step 3: Wire IPC**

Add `history/readThread` request and `historyThread` response.

**Step 4: Add Swift model action**

`SessionModel.openHistoryThread(_:)` calls daemon, sets `items` from detail, sets `cwd`, and marks a `selectedHistoryThreadId`.

**Step 5: Verify**

Run:

```bash
cargo test
swift test
```

Expected: PASS.

**Step 6: Commit**

```bash
git add agentdeckd/src/ipc.rs agentdeckd/src/codex.rs agentdeckd/src/main.rs Sources/AgentDeck/HistoryModel.swift Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/SessionModel.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: read and replay historical Codex threads"
```

### Task 8: Resume a historical thread and continue context

**Files:**
- Modify: `agentdeckd/src/codex.rs`
- Modify: `agentdeckd/src/main.rs`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Test: `agentdeckd/src/codex.rs`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: Write failing Rust test**

Add parser test for `thread/resume` response mapping to a neutral summary and preserving returned `cwd`.

Expected: FAIL because resume parser does not exist.

**Step 2: Implement `CodexAdapter::thread_resume`**

Call:

```json
{"method":"thread/resume","params":{"threadId":"..."}}
```

Return the resumed thread summary.

**Step 3: Wire daemon state**

Add daemon-level active thread state:

```rust
struct ActiveThread {
    id: String,
    cwd: String,
}
```

For first version, keep it process-local. `history/resumeThread` sets active thread. A follow-up `startSession` with `threadId` or a new `startTurn` should use the active thread instead of `thread/start`.

Prefer adding a new neutral request:

```json
{"kind":"startTurn","payload":{"threadId":"...","prompt":"..."}}
```

This avoids changing `startSession` semantics.

**Step 4: Write failing Swift test**

Test that `SessionModel` with `selectedHistoryThreadId` sends a continue-turn request instead of a start-session request. If direct send is hard to test, extract request factory in `DaemonClient`.

**Step 5: Implement Swift continue path**

After `openHistoryThread`, show restored items. When the user submits a prompt:

- If `selectedHistoryThreadId != nil`, call `client.startTurn(threadId:prompt:onLine:)`.
- Else keep existing `startSession(cwd:prompt:onLine:)`.

**Step 6: Verify**

Run:

```bash
cargo test
swift test
```

Expected: PASS.

**Step 7: Manual end-to-end**

Run:

```bash
cargo build
swift run AgentDeck
```

Manual expected:

- History list loads.
- Opening an old thread shows prior context.
- Continuing the thread sends a new turn on the resumed thread.
- The app still streams new `agentItem` deltas.

**Step 8: Commit**

```bash
git add agentdeckd/src/codex.rs agentdeckd/src/main.rs Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/SessionView.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: resume Codex history threads"
```

### Task 9: Add low-risk management actions

**Files:**
- Modify: `agentdeckd/src/codex.rs`
- Modify: `agentdeckd/src/main.rs`
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: `Sources/AgentDeck/SessionModel.swift`
- Modify: `Sources/AgentDeck/SessionView.swift`
- Test: `Tests/AgentDeckTests/IpcTests.swift`

**Step 1: Add request factory tests**

Test encoding for:

- `history/archiveThread`
- `history/unarchiveThread`
- `history/renameThread`

Expected: FAIL because factories do not exist.

**Step 2: Implement adapter calls**

Map to app-server:

- `thread/archive`
- `thread/unarchive`
- `thread/name/set`

**Step 3: Implement UI actions**

Add context menu or compact buttons on selected thread:

- Rename.
- Archive.
- Unarchive if viewing archived list later.

Keep first version explicit and visible; do not auto-delete anything.

**Step 4: Verify**

Run:

```bash
cargo test
swift test
```

Expected: PASS.

**Step 5: Commit**

```bash
git add agentdeckd/src/codex.rs agentdeckd/src/main.rs Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/SessionView.swift Tests/AgentDeckTests/IpcTests.swift
git commit -m "feat: manage Codex history threads"
```

### Task 10: Update documentation and final verification

**Files:**
- Modify: `README.md`
- Modify: `AgentDeck_v0.1_Product_Definition_Workbench.md`

**Step 1: Update README**

Add a concise section:

- AgentDeck can scan Codex app-server historical threads.
- Threads are grouped by project cwd.
- Restoring uses `thread/resume`.
- AgentDeck does not copy credentials and does not make itself the context truth source.

**Step 2: Update product definition**

Update Runs / Project Workbench sections to mention imported Codex history threads.

**Step 3: Full verification**

Run:

```bash
cargo test
swift test
cargo build
swift build
git diff --check
git status --short
```

Expected:

- All tests pass.
- Builds pass.
- No whitespace errors.
- Only intended files are dirty.

**Step 4: Commit**

```bash
git add README.md AgentDeck_v0.1_Product_Definition_Workbench.md
git commit -m "docs: document Codex history thread management"
```

### Task 11: Push

**Files:**
- None.

**Step 1: Review commits**

Run:

```bash
git log --oneline -10
git status --short --branch
```

Expected: branch has intended commits and clean worktree, except any pre-existing user changes that were intentionally left out.

**Step 2: Push**

Run:

```bash
git push
```

Expected: push succeeds.
