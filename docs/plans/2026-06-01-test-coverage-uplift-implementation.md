# Test Coverage Uplift Implementation Plan — 阶段 1

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** 把仓库加权行覆盖率从 ~40% 提升到 ≥ 60%（阶段 1 单独目标；阶段 2 视实测决定）。Rust ≥ 75%、Swift ≥ 50%。

**Architecture:** 三块组合执行，顺序 C → D → B。块 C 纯补测试（不动源码）；块 D 把 `main.rs` 切成 `parse_args` + `run(cmd, deps)` + 薄壳；块 B 给 `DaemonClient` 抽 `DaemonTransport` 协议，生产实现保留 Process/Socket，测试用内存 stub。所有改动只重排结构与补测试，不改用户可见行为。

**Tech Stack:** Rust（cargo test、cargo-llvm-cov）、Swift（swift test --enable-code-coverage、Testing framework、xcrun llvm-cov）。无新外部依赖。

**关联设计文档：** `docs/plans/2026-06-01-test-coverage-uplift-design.md`

**Worktree：** `.worktrees/test-coverage-uplift`，分支 `feature/test-coverage-uplift`。所有命令都在此目录运行（绝对路径：`/Users/jassy/Documents/glm/AgentDeck/.worktrees/test-coverage-uplift`）。

---

## 通用约定

**每个任务的步骤模板（除非有特殊原因）**：

1. 写失败测试
2. 运行测试确认失败（除非是补测既有功能，则跳到 4）
3. 写最小实现 / 仅补测试
4. 运行测试确认通过
5. 运行变更范围对应的最小验证（参考 `AGENTS.md` 第 39 行）
6. 提交

**提交风格**（沿用仓库现有约定，参考 `git log --oneline -20`）：

- 测试新增：`test(coverage): <scope> ...`
- 重构：`refactor(<scope>): ...`
- 文档：`docs(quality): ...`

**通用命令**：

```bash
cargo test
swift test
cargo llvm-cov --summary-only
swift test --enable-code-coverage
xcrun llvm-cov report \
  .build/x86_64-apple-macosx/debug/AgentDeckPackageTests.xctest/Contents/MacOS/AgentDeckPackageTests \
  -instr-profile=.build/x86_64-apple-macosx/debug/codecov/default.profdata \
  $(pwd)/Sources
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
scripts/verify-agent-docs.sh
```

---

## 块 C — `codex.rs` 协议适配器补测

不动源码。所有任务在 `agentdeckd/src/codex.rs` 末尾的 `#[cfg(test)] mod tests` 内追加。

**任务前置：先读懂当前文件结构**

执行：

```bash
sed -n '1,80p' agentdeckd/src/codex.rs
grep -n "^fn\|^pub fn\|^impl\|^struct\|^enum" agentdeckd/src/codex.rs | head -40
grep -n "#\[test\]\|#\[tokio::test\]" agentdeckd/src/codex.rs | head -20
```

阅读 `protocol/SPIKE_FINDINGS.md` 中关于事件帧格式的章节，确定 fixture 取值。**所有 fixture 必须基于真实协议样例，不得编造字段名。**

### Task C1: 协议错误路径测试组

**Files:**
- Modify: `agentdeckd/src/codex.rs`（在 `mod tests` 内追加）

**测试用例清单**（每个独立 #[test]）：

1. `missing_thread_id_event_is_logged_not_panicked` — 构造一个缺 `thread_id` 字段的事件帧；断言：翻译返回 `Err`/`None`，`diag::*` 收到 warning，进程不 panic。
2. `unknown_event_type_falls_back_to_unknown_variant` — 构造 `{"type": "totally_made_up_event_42"}`；断言：被归类为 unknown variant，turn 不丢失。
3. `jsonrpc_error_frame_maps_to_agent_item_error` — 构造合法 JSON-RPC error 帧（含 `code`、`message`）；断言：上层收到 `AgentItem::Error`，含原始 message。
4. `partial_sse_chunk_is_buffered_until_complete` — 第一帧含 `data: {"part`，第二帧含 `ial":"json"}`；断言：buffer 累积，第二帧到达时才 emit 一个完整事件。
5. `invalid_utf8_in_event_payload_is_rejected_gracefully` — 含非法 UTF-8 字节；断言：返回错误且 diag 有记录，不 panic。

**Step 1**: 一次性新增上述 5 个测试函数。每个测试用 `tokio::test` 或同步 `#[test]`（与文件现有风格一致）。

**Step 2**: 运行：
```bash
cargo test --package agentdeckd codex::tests:: 2>&1 | tail -30
```
预期：5 个新测试可能全部失败或部分失败（取决于现有适配器对错误路径的处理）。

**Step 3**: 阅读测试失败信息。**对每个失败：**
- 如果失败是因为现有代码确实有 bug（如对缺字段 panic）：在 design 文档的"风险与权衡"里记录该 bug，本次只先 fix 让测试通过；fix 范围限制在该路径的最小防御。
- 如果失败是因为测试期望与实际行为不符：调整测试期望以匹配真实行为（前提是真实行为是合理的；否则上面那条）。

**Step 4**: 全部通过：
```bash
cargo test 2>&1 | tail -5
```
预期：`62 + 5 = 67 passed`（或更多，取决于嵌套）。

**Step 5**: 提交：
```bash
git add agentdeckd/src/codex.rs
git commit -m "test(coverage): cover codex.rs protocol error paths"
```

### Task C2: approval 状态机测试组

**Files:**
- Modify: `agentdeckd/src/codex.rs`

**前置阅读**：
```bash
grep -n -i "approval\|approve\|deny" agentdeckd/src/codex.rs
grep -rn -i "approval" protocol/SPIKE_FINDINGS.md
```

**测试用例**：

1. `approval_pending_then_approved_then_applied_full_chain` — 模拟事件序列 `approval.requested` → `approval.approved` → `action.applied`；断言：状态机走到 applied 终态，每步 `AgentItem` 正确。
2. `approval_pending_then_denied_blocks_action` — 模拟 `approval.requested` → `approval.denied`；断言：后续 `action_request` 被拒绝且 diag 记录。
3. `concurrent_approval_ids_do_not_collide` — 同一 turn 内并发两个 approval（不同 `approval_id`）；断言：两个独立终态，互不影响。
4. `approval_state_recovers_after_daemon_restart` — 模拟 daemon 中断（drop adapter）后重启，重发同 turn 的 approval 事件；断言：状态机能从重启后的事件流恢复（不重复 applied，不丢 deny）。

Steps 同 C1（写测试 → 跑失败 → 修/对齐 → 跑通过 → 提交）。

**关键命令**：`cargo test approval`（AGENTS.md 第 24 行专门保留的过滤入口）必须能跑通这些。

**Step 5 提交**：
```bash
git add agentdeckd/src/codex.rs
git commit -m "test(coverage): cover codex.rs approval state machine"
```

### Task C3: turn 边界测试组

**测试用例**：

1. `turn_started_then_completed_groups_user_items_correctly` — 多 user_item 落到同 turn；断言：turn 聚合正确。
2. `stale_event_after_turn_completed_is_dropped_with_diag` — `turn.completed` 之后到达的 `delta` 事件；断言：被丢弃 + diag 警告。
3. `client_id_not_leaking_across_turns` — turn1 的 client_id 与 turn2 的不同；断言：无串。
4. `delta_after_turn_completed_emits_warning_once_per_turn` — 多次 stale delta；断言：diag 警告每 turn 只一次（沿用 `record_failure_warning_is_emitted_once_per_turn` 的不变量）。

提交：
```bash
git add agentdeckd/src/codex.rs
git commit -m "test(coverage): cover codex.rs turn boundary cases"
```

### Task C4: session 边界测试组

**测试用例**：

1. `events_before_session_started_are_buffered` — `session.started` 前的事件；断言：被缓冲，不丢失。
2. `session_ended_triggers_graceful_transport_close` — `session.ended` 后；断言：上层收到 close signal。
3. `multiple_session_started_for_same_thread_uses_latest` — 重复 `session.started`（如重连）；断言：以最新为准，旧 session 状态被清理。

提交：
```bash
git add agentdeckd/src/codex.rs
git commit -m "test(coverage): cover codex.rs session boundary cases"
```

### Task C5: 实测 Rust 覆盖率

**Step 1**: 跑覆盖率：
```bash
cargo llvm-cov --summary-only 2>&1 | tail -10
```

**Step 2**: 验证：
- `codex.rs` 行覆盖 ≥ 88%
- Rust 整体行覆盖 ≥ 64%（保守：原 60% + codex 提升带来的部分）

**Step 3**: 如果未达标，回溯哪些分支仍未覆盖：
```bash
cargo llvm-cov --html
open target/llvm-cov/html/index.html
```
针对未覆盖区域补 1-2 个测试，回到 Task C1-C4 风格补完。

**Step 4**: 记录数字（暂存到 design 文档的"实测记录"附录，最终在收尾任务统一更新 `QUALITY.md`）。

**无提交**（覆盖率数字不入库，统一在收尾提交）。

---

## 块 D — `main.rs` JSONL 派发循环重构

**修订说明（2026-06-02）**：原计划"抽 `parse_args` + `CliCommand`"在 D1+D2 实施前被 implementer 拒绝并报回——CLI 解析在 Swift 侧 `Sources/AgentDeck/main.swift`，Rust daemon 通过 stdin JSONL 派发循环工作，无 CLI flag。修订后 D 块重构 `fn main()` 的 JSONL 派发循环，让 stdin/stdout 与 RuntimeHub/worker spawn 可注入测试。详见 design 文档 风险与权衡 末尾的 2026-06-02 修订记录。

**前置阅读**：
```bash
wc -l agentdeckd/src/main.rs
grep -n "^fn\|^pub fn\|^async fn\|^impl\|^struct\|^enum" agentdeckd/src/main.rs | head -40
grep -n "fn main\|HubAction\|classify_request\|RuntimeHub\|run_logging_selfcheck\|run_diagnostics_report\|run_history_worker\|run_turn_worker" agentdeckd/src/main.rs | head -40
sed -n '1690,1830p' agentdeckd/src/main.rs   # 当前 fn main() 主体
```

**关键约束**：
- 重构期间不改变 daemon 对外 JSONL 输出格式（逐字节稳定）。
- 现有 78 个 Rust 测试全过，无回归。
- `swift run AgentDeck -- --selfcheck`、`--diagnostics-report --json`、`--profile dev` 变体 4 种命令输出与重构前完全一致（CLI 解析在 Swift 侧不变；daemon JSONL 不变即足以保证）。
- 不引入 `tokio`、`async-trait` 等新依赖。RuntimeHub/worker 现是同步 + `std::thread::spawn`，保持同步风格。

### Task D1: 抽 `run<R, W>(stdin, stdout, deps)` + 薄壳 main

**目的**：让 `fn main()` 变成"建 stdin/stdout + 构造 LiveDeps + 调用 `run`"三行，把派发循环主体搬到一个签名为 `pub(crate) fn run<R, W>(stdin: R, stdout: W, deps: impl RuntimeDeps) -> std::io::Result<()>` 的可测函数里。

**Files:**
- Modify: `agentdeckd/src/main.rs`

**Step 1**: 定义最小 `RuntimeDeps` trait + `LiveDeps` 默认实现。注入面仅两件事：
- RuntimeHub 容量参数（生产 4，测试可设 1 或 2）
- worker spawn（生产 `std::thread::spawn`，测试可同步执行）

```rust
pub(crate) trait RuntimeDeps {
    fn hub_capacity(&self) -> usize;

    /// 启动一个新工作线程（生产）或同步执行 closure（测试）。
    /// 闭包负责完成后向 done_tx 发信号。
    fn spawn_worker(&self, work: Box<dyn FnOnce() + Send + 'static>);
}

pub(crate) struct LiveDeps;

impl RuntimeDeps for LiveDeps {
    fn hub_capacity(&self) -> usize { 4 }
    fn spawn_worker(&self, work: Box<dyn FnOnce() + Send + 'static>) {
        std::thread::spawn(work);
    }
}
```

**Step 2**: 把 `fn main()` 主体（建管道、起 writer 线程、stdin lines 循环、`classify_request` 分派、关闭清理）整体搬到 `run<R: BufRead, W: Write + Send + 'static>(stdin: R, stdout: W, deps: impl RuntimeDeps)`。修改要点：
- 原 `let stdin = std::io::stdin();` → 用参数 `stdin: R`
- 原 `let stdout = std::io::stdout();` → 用参数 `stdout: W`
- 原 `let mut runtime_hub = RuntimeHub::new(4);` → `RuntimeHub::new(deps.hub_capacity())`
- 原 `std::thread::spawn(move || { ... })` → `deps.spawn_worker(Box::new(move || { ... }))`（适用于 history worker 与 turn worker 两处）

**Step 3**: `fn main()` 改为薄壳：

```rust
fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run(stdin.lock(), stdout, LiveDeps)
}
```

**Step 4**: 跑全量 Rust 测试：
```bash
cargo test 2>&1 | tail -5
```
预期：`78 passed; 0 failed`（无新测试，只重构）。

**Step 5**: 跑 selfcheck/diagnostics 4 个变体验证 daemon JSONL 输出不变：
```bash
swift run AgentDeck -- --selfcheck 2>&1 | tail -10
swift run AgentDeck -- --diagnostics-report --json 2>&1 | tail -10
swift run AgentDeck -- --selfcheck --profile dev 2>&1 | tail -10
swift run AgentDeck -- --diagnostics-report --json --profile dev 2>&1 | tail -10
```
任一输出与重构前不一致 → STOP and report，不要 commit。

**Step 6**: 提交：
```bash
git add agentdeckd/src/main.rs
git commit -m "refactor(daemon): extract run() with RuntimeDeps injection"
```

### Task D2: 写 JSONL 派发测试（FakeDeps）

**Files:**
- Modify: `agentdeckd/src/main.rs`（追加 `#[cfg(test)] mod dispatch_tests`）

**Step 1**: 写 `FakeDeps`（仅 cfg test），同步执行 worker 闭包：

```rust
#[cfg(test)]
struct FakeDeps {
    workers: std::sync::Mutex<Vec<()>>,
}

#[cfg(test)]
impl FakeDeps {
    fn new() -> Self { Self { workers: std::sync::Mutex::new(Vec::new()) } }
}

#[cfg(test)]
impl RuntimeDeps for FakeDeps {
    fn hub_capacity(&self) -> usize { 1 }
    fn spawn_worker(&self, work: Box<dyn FnOnce() + Send + 'static>) {
        // 同步执行：测试可直接断言 stdout 中 worker 输出
        work();
        self.workers.lock().unwrap().push(());
    }
}
```

**Step 2**: 测试用例（每个独立 `#[test]`）：
1. `dispatch_empty_lines_are_skipped` — stdin 含若干空行 + 一行 `{"method":"shutdown","id":1}`；断言：stdout 只含 1 个 pong + writer_stop_msg，无 error 帧。
2. `dispatch_malformed_jsonl_emits_error_and_continues` — 一行 `"not json"` + 一行 ping；断言：stdout 含一个 `malformed JSONL` error 帧 + 1 个 pong。
3. `dispatch_ping_returns_pong_with_same_id` — 一行 `{"method":"ping","id":42}`；断言：stdout 含 `{"id":42,"result":...,"method":"pong"}`（按真实 IpcMessage::pong 格式）。
4. `dispatch_shutdown_terminates_loop` — 一行 shutdown；断言：stdout 含 pong + writer_stop_msg，loop 提前结束（stdin 后续行不被消费）。
5. `dispatch_logging_selfcheck_emits_completed_message` — 一行 `selfcheck/logging`；断言：stdout 至少含一个 logging selfcheck 完成的 IPC message。
6. `dispatch_diagnostics_report_emits_payload` — 一行 `diagnostics/report`；断言：stdout 含 diagnostics 输出帧。
7. `dispatch_classify_error_emits_error_with_msg_id` — 一行 method 不识别 `{"method":"bogus/whatever","id":99}`；断言：stdout 含 `{"id":99,"error":...}`。

每个测试构造 `Cursor::new(b"…\n")` 当 stdin，`Vec::<u8>` 当 stdout（包到 `Arc<Mutex<Vec<u8>>>` 通过 `Write` impl 让 writer 线程能拿到），调用 `run(stdin, stdout_handle, FakeDeps::new())`，断言 join 之后的 `stdout_handle` 内容。

注意：原 writer 是单独线程，测试里要么改 writer 接受任意 `Write + Send`（已通过签名），要么用 `Arc<Mutex<Vec<u8>>>` 的写入适配器。挑选 implementer 觉得最干净的方式。

**Step 3**: 跑：
```bash
cargo test --package agentdeckd dispatch_tests 2>&1 | tail -15
cargo test 2>&1 | tail -5
```
预期：78 + 7 = 85 passed。

**Step 4**: 提交：
```bash
git add agentdeckd/src/main.rs
git commit -m "test(coverage): JSONL dispatch with FakeDeps"
```

### Task D3: 实测 Rust 总覆盖率

**Step 1**:
```bash
cargo llvm-cov --summary-only 2>&1 | tail -10
```

**Step 2**: 验证：
- `main.rs` 行覆盖 ≥ 65%（从 34.83% 提升）
- `codex.rs` 维持 ≥ 82%（C5 修订目标）
- Rust 整体 ≥ 75%

**Step 3**: 未达标：
- 用 `cargo llvm-cov --html && open target/llvm-cov/html/index.html` 看 main.rs 哪些分支仍未覆盖
- 优先补 `HubAction::SpawnTurn` / `ActionDecision` 路径（最复杂的 dispatch 分支），按 D2 模式追加 1-3 个测试

无提交（覆盖率数字暂存到 design 文档 阶段 1 实测记录附录；最终在 F2 一起写进 QUALITY.md）。

---

## 块 B — `DaemonClient` 协议化

**前置阅读**：
```bash
wc -l Sources/AgentDeck/DaemonClient.swift  # 或实际路径
find Sources -name "DaemonClient.swift"
grep -n "^class\|^struct\|^actor\|^func\|^private func" $(find Sources -name "DaemonClient.swift") | head -30
grep -rn "DaemonClient(" Sources Tests
```

**前置规约**：本块改动的是 Swift 侧 IPC 边界。沿用 AGENTS.md 第 20-21 行约束：transport 只搬运中立 `AgentItem`，不解析 Codex vendor JSON。

### Task B1: 写 DaemonClient 当前行为的钉死测试

**目的**：在重构前先抓现状作为回归基线，确保抽协议后行为不变。

**Files:**
- Create: `Tests/AgentDeck/DaemonClientBaselineTests.swift`

**Step 1**: 选 3-5 个最关键的 happy path 行为作为快照（不深入细节，只为防止重构破坏外部接口）。例如：
- 初始化后能 `initialize` 成功
- 发 prompt 能拿到流式 delta
- shutdown 后再发请求立刻被拒

**Step 2**: 跑 `swift test`，确认全过：
```bash
swift test 2>&1 | tail -5
```

如果某测试需要真实 daemon 才能跑，先标 `.disabled` 或 skip，本任务只写"可在重构后用 stub 验证"的测试草稿；正式断言在 B6/B7/B8 写。

**Step 3**: 提交：
```bash
git add Tests/AgentDeck/DaemonClientBaselineTests.swift
git commit -m "test(coverage): baseline DaemonClient behavior snapshot"
```

### Task B2: 定义 DaemonTransport 协议

**Files:**
- Create: `Sources/AgentDeck/DaemonTransport.swift`

**Step 1**: 写协议：

```swift
import Foundation

/// 中立 IPC 传输层。只搬运帧，不解析 vendor JSON。
public protocol DaemonTransport: AnyObject, Sendable {
    /// 发送一帧请求或事件。
    func send(_ frame: IpcFrame) async throws

    /// 来自 daemon 的所有入站帧。AsyncStream 在 shutdown 后结束。
    var incoming: AsyncStream<IpcFrame> { get }

    /// 触发关闭。已发出的 incoming 流应在合理时间内结束。重复调用安全。
    func shutdown() async
}

public enum TransportError: Error, Equatable {
    case notConnected
    case writeFailed(String)
    case cancelled
}
```

如果 `IpcFrame` 还未存在或不是公开类型，先确认现有 `DaemonClient.swift` 里它叫什么；可能叫 `IpcMessage` / `DaemonFrame` 等。**不要改它的名字或字段**，只在协议中引用。

**Step 2**: 跑 `swift build` 确认编译：
```bash
swift build 2>&1 | tail -5
```

**Step 3**: 提交：
```bash
git add Sources/AgentDeck/DaemonTransport.swift
git commit -m "feat(ipc): introduce DaemonTransport protocol"
```

### Task B3: 创建 ProcessDaemonTransport（生产实现）

**Files:**
- Create: `Sources/AgentDeck/ProcessDaemonTransport.swift`
- Modify: `Sources/AgentDeck/DaemonClient.swift`

**Step 1**: 把现有 `DaemonClient` 里管理 `Process` spawn、socket 读写的代码搬到 `ProcessDaemonTransport`。约束：

- 实现 `DaemonTransport` 协议
- 构造接受 daemon 可执行路径 / profile / env（沿用现有逻辑）
- `incoming` AsyncStream 在 `shutdown()` 或 process 退出时 finish

**Step 2**: 跑 `swift build`，修编译错误。

**Step 3**: 跑 `swift test`，所有现有 89 测试 + B1 的 baseline 全过：
```bash
swift test 2>&1 | tail -5
```

**Step 4**: 跑 selfcheck + diagnostics：
```bash
swift run AgentDeck -- --selfcheck 2>&1 | tail -5
swift run AgentDeck -- --diagnostics-report --json 2>&1 | tail -5
```

**Step 5**: 提交：
```bash
git add Sources/AgentDeck/ProcessDaemonTransport.swift Sources/AgentDeck/DaemonClient.swift
git commit -m "refactor(ipc): extract ProcessDaemonTransport from DaemonClient"
```

### Task B4: 改 DaemonClient 构造接受 transport 注入

**Files:**
- Modify: `Sources/AgentDeck/DaemonClient.swift`
- Modify: 引用 `DaemonClient` 的所有文件（用 grep 找）

**Step 1**: 加新 init：
```swift
public init(transport: DaemonTransport, ...) { ... }

/// 工厂：生产路径。
public static func live(profile: ProfileSelector, ...) -> DaemonClient {
    DaemonClient(transport: ProcessDaemonTransport(profile: profile, ...), ...)
}
```

旧的 `init(profile:...)` 保留作为 deprecated convenience 调用 `.live`，或直接替换调用点。AGENTS.md 第 24 行的规则允许"不留无用兼容残留"，所以**优先直接替换调用点**。

**Step 2**: 用 grep 找调用点：
```bash
grep -rn "DaemonClient(" Sources Tests
```

逐个改为 `DaemonClient.live(...)`，或在测试里改为注入 stub（B5 之后）。

**Step 3**: 跑 build + test + selfcheck：
```bash
swift build 2>&1 | tail -5
swift test 2>&1 | tail -5
swift run AgentDeck -- --selfcheck 2>&1 | tail -5
```

**Step 4**: 提交：
```bash
git add Sources/AgentDeck/DaemonClient.swift Sources/AgentDeck/SessionModel.swift Sources/AgentDeck/WorkbenchModel.swift  # 实际改了的文件
git commit -m "refactor(ipc): inject DaemonTransport into DaemonClient"
```

### Task B5: 创建 StubDaemonTransport

**Files:**
- Create: `Tests/AgentDeck/StubDaemonTransport.swift`

**Step 1**: 写 stub：
```swift
import Foundation
@testable import AgentDeck

final class StubDaemonTransport: DaemonTransport, @unchecked Sendable {
    private(set) var sent: [IpcFrame] = []
    private var continuation: AsyncStream<IpcFrame>.Continuation?
    let incoming: AsyncStream<IpcFrame>
    var sendError: TransportError?
    private var isShutdown = false

    init() {
        var cont: AsyncStream<IpcFrame>.Continuation!
        self.incoming = AsyncStream { c in cont = c }
        self.continuation = cont
    }

    func send(_ frame: IpcFrame) async throws {
        if let e = sendError { throw e }
        if isShutdown { throw TransportError.cancelled }
        sent.append(frame)
    }

    func push(_ frame: IpcFrame) { continuation?.yield(frame) }

    func shutdown() async {
        isShutdown = true
        continuation?.finish()
    }
}
```

**Step 2**: 跑 build：
```bash
swift build 2>&1 | tail -5
```

**Step 3**: 提交：
```bash
git add Tests/AgentDeck/StubDaemonTransport.swift
git commit -m "test(coverage): StubDaemonTransport for DaemonClient tests"
```

### Task B6-B9: DaemonClient 测试组

**Files:**
- Create: `Tests/AgentDeck/DaemonClientTests.swift`

每组测试一个独立任务，每个任务 5 步（写 → 跑失败 → 修/对齐 → 跑通过 → 提交）。

**B6: 请求-响应配对**
1. `request_resolves_when_matching_response_arrives`
2. `request_timeout_does_not_resolve_with_late_response`
3. `duplicate_response_id_is_ignored`

提交消息：`test(coverage): DaemonClient request-response pairing`

**B7: 流式事件分发**
1. `incoming_event_routes_to_correct_thread_listener`
2. `event_for_unknown_thread_is_dropped_with_diag`
3. `multiple_listeners_on_same_thread_all_receive`

提交消息：`test(coverage): DaemonClient streaming event dispatch`

**B8: 错误路径**
1. `transport_send_error_propagates_as_daemon_error`
2. `reconnect_backoff_does_not_starve_pending_requests`
3. `incoming_stream_finish_triggers_disconnected_state`

提交消息：`test(coverage): DaemonClient error paths`

**B9: 关闭语义**
1. `shutdown_returns_pending_requests_with_cancelled`
2. `send_after_shutdown_immediately_throws_cancelled`
3. `shutdown_is_idempotent`

提交消息：`test(coverage): DaemonClient shutdown semantics`

每组都跑：
```bash
swift test --filter DaemonClientTests 2>&1 | tail -15
```

### Task B10: 实测 Swift 覆盖率

**Step 1**:
```bash
swift test --enable-code-coverage 2>&1 | tail -5
xcrun llvm-cov report \
  .build/x86_64-apple-macosx/debug/AgentDeckPackageTests.xctest/Contents/MacOS/AgentDeckPackageTests \
  -instr-profile=.build/x86_64-apple-macosx/debug/codecov/default.profdata \
  $(pwd)/Sources 2>&1 | tail -20
```

**Step 2**: 验证：
- `DaemonClient.swift` 行覆盖 ≥ 70%
- Swift 整体 ≥ 50%

**Step 3**: 未达标继续补。

---

## 收尾任务（阶段 1 收口）

### Task F1: 整体覆盖率实测

**Step 1**:
```bash
cargo llvm-cov --summary-only > /tmp/rust-cov.txt 2>&1
swift test --enable-code-coverage 2>&1 | tail -3
xcrun llvm-cov report \
  .build/x86_64-apple-macosx/debug/AgentDeckPackageTests.xctest/Contents/MacOS/AgentDeckPackageTests \
  -instr-profile=.build/x86_64-apple-macosx/debug/codecov/default.profdata \
  $(pwd)/Sources > /tmp/swift-cov.txt 2>&1
```

**Step 2**: 计算加权整体：
- 拿 Rust TOTAL 的 Lines + Cover
- 拿 Swift TOTAL 的 Lines + Cover
- 加权 = (rust_covered + swift_covered) / (rust_total + swift_total)

**Step 3**: 判断决策：
- ≥ 70%：进入 F2 + F3 + F4 收尾。
- 60-70%：进入 F2 + F3 + F4 收尾，并标记"需要阶段 2"。
- < 60%：补测继续直到 ≥ 60%（回到块 B 或块 C 的薄弱点）。

### Task F2: 更新 docs/QUALITY.md

**Files:**
- Modify: `docs/QUALITY.md`

**Step 1**: 在"常用验证命令"和"按变更范围选择验证"之间插入新章节"测试覆盖率"，内容按 design 文档 §6 给出（命令、基线表、显式不测清单、失败处理）。

**Step 2**: 基线表填实测数字（F1 拿到的）。

**Step 3**: 提交：
```bash
git add docs/QUALITY.md
git commit -m "docs(quality): add coverage baseline and measurement commands"
```

### Task F3: 跑文档结构检查 + 最终验证

**Step 1**:
```bash
scripts/verify-agent-docs.sh
cargo test
swift test
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```
每个都应该通过/成功。

**Step 2**: `git status --short --branch`，确认工作树干净。

### Task F4: 阶段 1 收口报告

**Step 1**: 在 `docs/plans/2026-06-01-test-coverage-uplift-design.md` 末尾追加"阶段 1 实测记录"小节：

```markdown
## 阶段 1 实测记录（YYYY-MM-DD）

| 范围 | 起始 | 阶段 1 后 | 目标 |
| --- | --- | --- | --- |
| Rust 整体 | 59.95% | XX.XX% | ≥75% |
| Swift 整体 | 27.46% | XX.XX% | ≥50% |
| 加权整体 | 40% | XX.XX% | ≥60% (阶段 1) / ≥70% (阶段 2 后) |

决策：进入阶段 2 / 停在阶段 1 / 需要补测。
```

**Step 2**: 提交：
```bash
git add docs/plans/2026-06-01-test-coverage-uplift-design.md
git commit -m "docs(plans): record stage 1 coverage uplift results"
```

**Step 3**: 报告给用户阶段 1 结果，并问下一步（PR / 进阶段 2 / 停）。

---

## 阶段 1 完成定义

- 所有 Task C1-C5、D1-D6、B1-B10、F1-F4 完成
- `cargo test`、`swift test`、`--selfcheck`、`--diagnostics-report --json`、`--selfcheck --profile dev`、`--diagnostics-report --json --profile dev` 全通过
- `scripts/verify-agent-docs.sh` 通过
- `docs/QUALITY.md` 含覆盖率章节与最新基线
- 工作树干净
- 已经决定是否进入阶段 2

---

## 风险与回退

- **块 C 发现既有 bug**：本计划允许做最小 fix（仅该路径），但不做大范围修复；记录到 design 文档。
- **块 D 重构破坏现有 selfcheck 输出格式**：通过对比重构前/后的 `--selfcheck` 与 `--diagnostics-report --json` 输出捕获；如有差异，回退该次提交（`git revert`），重新做。
- **块 B `DaemonTransport` 接口设计不充分**：B1 的 baseline 测试是回退基线；如发现接口缺关键方法，回到 B2 修接口，B3-B9 跟着改。
- **整体目标未达成**：F1 判断后进入阶段 2 或补测；不强行提前结束。

---

## 跨任务的 token / 时间预算（粗估）

- 块 C：4-6 小时（纯加测试）
- 块 D：6-10 小时（重构 + 测试）
- 块 B：8-12 小时（重构 + 测试，最大块）
- 收尾：1-2 小时
- 总计：约 4-5 天工程时间

如果某块明显超预算（>1.5x），暂停并报告，避免无控扩展。
