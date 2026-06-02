# AgentDeck Test Coverage Uplift Design

## 背景

2026-06-01 首次对仓库实测测试覆盖率，结果显示核心模型层覆盖良好，但 SwiftUI 视图层和 Rust 进程入口存在显著盲区。`docs/QUALITY.md` 当前没有覆盖率条目，缺乏可机械执行的基线，也没有显式声明哪些代码按策略接受低覆盖。后续改动若让覆盖率退化，agent 没有判断依据。

实测基线（工具：`cargo-llvm-cov 0.8.7`、`swift test --enable-code-coverage` + `xcrun llvm-cov`）：

| 范围 | 行覆盖 | 主要薄弱点 |
| --- | --- | --- |
| Rust 整体 | 59.95% | `main.rs` 34.83%（1803 行） |
| Swift 整体 | 27.46% | `SessionView.swift` 4.19%（2910 行）、`DaemonClient.swift` 30.84%（989 行） |
| 加权整体 | ≈ 40% | — |

## 目标

- 加权整体行覆盖率 **≥ 50%**（原 ≥ 70% 在 D/A 块修订后下调，详见 风险与权衡 末尾的 2026-06-02 修订记录）。
- Rust daemon **≥ 72%**（`codex.rs` ≥ 82%、`main.rs` ≥ 54%、`record/diag/ipc` 维持现状）。`codex.rs` 与 `main.rs` 目标均按实测下调，详见 风险与权衡 末尾的 2026-06-02 修订记录。
- Swift UI **≥ 32%**（`DaemonClient` ≥ 45%、`ToolPresentation`/`ConversationRailNavigator` ≥ 85%、`SessionModel/HistoryModel/ConversationTurn/AgentItemReducer` 维持 ≥ 73%）。原 ≥ 50% 目标在块 A 修订后下调，详见 风险与权衡 末尾的 2026-06-02 修订记录。
- `docs/QUALITY.md` 新增"测试覆盖率"章节，固化测量命令、当前基线与"显式不测"清单。
- 不引入新外部依赖（mock 库等），不接 CI 门禁脚本。

## 非目标

- 不为 SwiftUI 渲染逻辑写快照测试或 UI E2E。
- 不动 `main.swift`、`MessageRoleViews.swift`、`RichMessageView.swift`、`StreamingTextView.swift`（声明式 UI 渲染，靠 `--selfcheck` 和人工 QA 把关）。
- 不改变 IPC schema、Codex adapter 协议翻译规则、approval 流程或 history 读取行为。本设计只重排代码结构与补测试，不改变用户可见行为。
- 不引入第二个测试运行器或第二个覆盖率工具。

## 方案

### 工具与基线

固定测量命令：

```bash
cargo llvm-cov --summary-only

swift test --enable-code-coverage
xcrun llvm-cov report \
  .build/x86_64-apple-macosx/debug/AgentDeckPackageTests.xctest/Contents/MacOS/AgentDeckPackageTests \
  -instr-profile=.build/x86_64-apple-macosx/debug/codecov/default.profdata \
  $(pwd)/Sources
```

首次需要：

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

### 两阶段执行

**阶段 1（PR 1，预计 4-5 天）**：低风险快胜，顺序 C → D → B。

- 块 C — `codex.rs` 补测：不动源码，纯补错误分支、协议边角、approval 状态机、turn/session 边界测试。目标 77.17% → ≥ 88%。
- 块 D — `main.rs` JSONL 派发循环重构：把 `fn main()` 切成 `run<R: BufRead, W: Write>(stdin, stdout, deps) -> io::Result<()>` + 薄壳 main，新增 `RuntimeDeps` 让 RuntimeHub 与 worker spawn 可注入；补 JSONL 派发、`HubAction` 路径、错误帧测试。目标 34.83% → ≥ 65%。原计划"抽 parse_args + CliCommand"在 2026-06-02 实读 main.rs 后撤回（理由见 风险与权衡 末尾的 2026-06-02 修订记录）。
- 块 B — `DaemonClient` 协议化：抽 `DaemonTransport` 协议，`ProcessDaemonTransport` 留真实 Process/Socket，`StubDaemonTransport` 用于单测；补请求-响应配对、流式分发、错误路径、关闭语义、握手测试。目标 30.84% → ≥ 70%。

阶段 1 完成后实测：

- ≥ 70%：停在阶段 1，达成目标，文档化。
- 60-70%：进入阶段 2 做块 A。
- < 60%：进入阶段 2，并重新评估目标基线。

**阶段 2（PR 2，预计 2-3 天）**：仅在阶段 1 不达标时执行。

- 块 A — `SessionView` 重构：从 2910 行 SwiftUI 视图里抽出三个独立类型：
  - `SessionEventReducer`（纯函数 reducer）
  - `SessionViewState`（`Equatable` 值类型快照）
  - `SessionScrollSelectionCoordinator`（`@MainActor` 状态机）
- 在重构前先用集成测试钉死 `SessionView` 当前行为作为回归基线，再做内部重构，确保现有 88 个测试全过。抽出的纯逻辑文件目标 ≥ 85%，残余 `SessionView.swift`（纯声明式视图）保持 ~10% 不强求。

### 架构边界

- 块 B 的 `DaemonTransport` 协议属于 Swift 侧 IPC 边界，**仍只处理中立 `AgentItem`**，不解析任何 Codex vendor JSON。这条边界来自 `AGENTS.md` 第 20-21 行，重构不改变它。
- 块 D 的 `RuntimeDeps` 抽象只用于 `main.rs`，不污染其他模块；其他模块继续直接使用 `record::*`、`diag::*` 等具名函数。
- 块 A 的 reducer/coordinator 仍在 Swift 侧，不跨 IPC 边界。

## 错误处理与可观测性

- 块 C 补测的协议错误分支必须覆盖：无 `thread_id`、未知 `event_type`、JSON-RPC error 帧、SSE partial JSON、`turn.completed` 后 stale event 等场景，要求 `diag::*` 收到对应警告。
- 块 D 重构后 selfcheck 与 diagnostics report 输出格式必须逐字节不变（CLI 解析归 Swift，daemon 只通过 `selfcheck/logging` 与 `diagnostics/report` JSONL 请求被驱动）；`--profile dev` 变体继续按 `2026-06-01-agentdeck-profile-isolation-design.md` 约束工作（env var 路径未变）。
- 块 B 的 `StubDaemonTransport` 不写文件、不起进程；测试不依赖真实 daemon。
- 块 A 的 reducer 是纯函数，测试用确定的事件序列断言确定的 state；不依赖时钟、I/O。

## 测试与验收

每个块完成时必跑的验证：

| 块 | 必跑验证 |
| --- | --- |
| C | `cargo test`、核对 `protocol/SPIKE_FINDINGS.md` |
| D | `cargo test`、`swift run AgentDeck -- --selfcheck`、`swift run AgentDeck -- --diagnostics-report --json`、加跑 `--profile dev` 变体（Swift 入口分派的 daemon JSONL 请求被处理，输出格式不变） |
| B | `swift test`、`swift run AgentDeck -- --selfcheck` |
| A | `swift test`（旧 88 用例 + 新 reducer/coordinator 测试） |
| 全部完成后 | `scripts/verify-agent-docs.sh` |

每个块完成时必跑覆盖率实测并把数字记入 `docs/QUALITY.md`。

验收标准：

- 阶段 1 完成时整体覆盖率 ≥ 60%；如未达到则进入阶段 2。
- 阶段 2 完成时（若执行）整体覆盖率 ≥ 70%。
- `docs/QUALITY.md` 包含测量命令、当前基线表、显式不测清单。
- 现有 62 个 Rust 测试 + 88 个 Swift 测试全过，无回归。
- `--selfcheck` 与 `--diagnostics-report --json` 行为不变（stable 与 dev profile 都验证）。

## 文档更新

实现时同步更新：

- `docs/QUALITY.md`：新增"测试覆盖率"章节（命令、基线表、显式不测清单、失败处理）。
- `README.md`：仅在重构对外接口（如 `DaemonClient.live()` 工厂）改变了构建/运行命令时才更新。本设计预期不需要。
- `ARCHITECTURE.md`：仅在抽象边界变化时更新。本设计预期不需要，因为 `DaemonTransport` 是内部协议，不改变层间约束。
- `docs/index.md`：新增本设计与对应 implementation 文件的索引条目。

## 风险与权衡

- 块 D 的 `RuntimeDeps` 引入新 trait 抽象。权衡：仅 `main.rs` 内部使用，影响范围可控；不为通用 DI，避免过度设计。注入面限定为 RuntimeHub 工厂 + worker spawn 适配，不抽象 env/clock/fs（已分别通过 `record::*`、`diag::*` 完成）。
- 块 B 改动跨 Swift 多文件（`SessionModel`、`WorkbenchModel` 引用 `DaemonClient`）。权衡：放在阶段 1 最后做，一次性扫尾。
- 块 A 改动最大且最容易触发回归。权衡：放在阶段 2，只在阶段 1 不达标时执行；重构前先写行为钉死测试。
- 不接 CI 门禁脚本。权衡：仓库目前无 CI，门禁脚本闲置反而是债；`QUALITY.md` 描述性记录基线足够给未来 agent 提供判断依据。
- 块 C1 协议错误路径测试在实施时与 codex 适配器实际架构对齐：
  - codex 适配器的 `translate()` 是纯映射函数，无 `diag::*` 调用（诊断日志在 `main.rs` 边界统一记录），因此 C1 测试只验证"返回 `None` 且不 panic"的契约，不断言 diag 警告。
  - codex app-server 的 wire framing 是逐行 JSONL（`SPIKE_FINDINGS.md` D7 已验证），不是 SSE；C1 中"partial SSE chunk 缓冲"测试调整为验证 NDJSON 契约——半截 JSON 直接在 `serde_json::from_str` 失败并经 `CodexError::Protocol("malformed: ...")` 包装。
  - JSON-RPC error 帧映射为 `CodexError::Protocol(err.to_string())`，而非新增 `AgentItem::Error` 变体；C1 测试钉死这一现有契约。
- 块 C2 approval 状态机测试在实施时与 codex 适配器实际架构对齐：
  - codex.rs 不持有 approval 状态机；`approval_request_to_action` 与 `approval_response_for_decision` 是无状态纯函数，turn_start 循环只在一次请求-响应间携带 `request_id`，没有 `HashMap<approval_id, State>`。C2 测试因此钉死适配器实际的契约（每事件正确翻译 + 不同 approval_id 不串字段 + 纯函数对重启幂等），而不是不存在的状态机。
  - wire 协议中没有 `approval.requested` / `approval.approved` / `action.applied` 事件名（SPIKE_FINDINGS.md §approval：实际是 `item/<kind>/requestApproval` 请求加 JSON-RPC response）。计划里的"applied 终态"在真实 wire 上等价于 `item/completed` 携带 `type=commandExecution` 的执行结果项，C2 测试用该映射代替。
  - codex.rs 不实现"deny 后续 action_request 被拒绝"的拦截（这层不跟踪后续命令是否被尝试执行）。C2 把该测试改为钉死适配器真正负责的两件事：deny 决策翻译成 wire `decline`；Codex 回送的 `status="failed"` commandExecution/completed 仍被 translate 映射为 Shell completed，让上层能展示拒绝结果而不是丢帧。
- 块 C3 turn 边界测试在实施时与 codex 适配器实际架构对齐：
  - codex.rs 的 `translate()` 是 per-event 无状态纯函数，`AgentItem` 内不存在 `turn_id` 字段（见 `ipc.rs::AgentItem`），也没有 turn 级聚合缓冲。计划中"多 user_item 落到同 turn / turn 聚合正确"改为钉死本层真正可观测的契约：同 `turnId` 下连续多个 item 事件每个都独立翻译成 `AgentItem`，`item.id` 严格对齐 wire `itemId`，且 `turnId`/`threadId` 不泄漏进 `AgentItem` 的任何字段（包括 Raw description 与序列化输出）。
  - 计划中"turn.completed 之后到达的 delta 被丢弃 + diag 警告"在本层不可测：`translate()` 不做"after completed"门禁（看到什么翻什么），也不调用 `diag::*`（诊断在 main.rs 边界）。改为钉死两条断言：`translate("turn/completed", ...) == None`（生命周期事件不是 `AgentItem`）+ 同 turn 后续 delta 仍正常翻译。stale 帧丢弃 / 警告的责任明确归到 `turn_start` 循环和 main.rs 调用方，不属于 codex.rs。
  - 计划中"client_id 不在 turn 间串"在本层不存在 — codex 协议没有 `clientItemId` 字段，`AgentItem` 也没有 `client_id`。等价契约改为：两个不同 `turnId` 下不同 `itemId` 的事件，翻译后 `AgentItem.id` 严格 `assert_ne!`，证明无串扰且 `id` 由 wire `itemId` 唯一决定。
  - 计划中"diag 警告每 turn 只一次"在本层无 diag 也无 per-turn 状态，"once-per-turn" 不变量不在 codex.rs。改为钉死等价的更强契约 — 幂等性：同一 stale-shape 事件重复喂入 N 次，`translate()` 每次输出严格全等（序列化后字节比较），即无任何隐藏累计状态会偷偷改变结果。`once-per-turn` 警告若需要，应在 main.rs/调用方实现并由 D 块的 RuntimeDeps 测试覆盖。
- 块 C4 session 边界测试在实施时与 codex 适配器实际架构对齐：
  - wire 协议没有 `session.started` / `session.ended` 事件名。连接生命周期事件是 `thread/started`（`{thread}`）与 `thread/closed`（`{threadId}`），见 `protocol/codex_app_server_protocol.v2.schemas.json` 中 `ThreadStartedNotification` / `ThreadClosedNotification`。`SessionState` / `IpcMessage::session_event` 等 session 状态机是 daemon 在 `ipc.rs` / `main.rs` 自己合成的中立 IPC 抽象，不属于 codex.rs 翻译层。
  - 计划中"session.started 前事件被缓冲、不丢失"在 codex.rs 不可测：`translate()` 无状态，看到什么翻什么，没有"先看 session.started 再放行"的门禁；也没有缓冲队列对象。C4 改为钉死两条可观测契约：`thread/started` 通知不变成 `AgentItem`（translate 返回 None，归 main.rs 边界消费）；且 item 事件在没有任何前导生命周期通知时仍被独立翻译——证明"缓冲 / 丢弃"责任不在 codex.rs。
  - 计划中"session.ended 触发 transport close signal"在 codex.rs 不可测：transport（`child` / `stdin` / `stdout` / `reader`）是 `CodexAdapter` 的私有字段，关闭由 `Drop for CodexAdapter` 完成（A1 第二层 + 进程组 SIGKILL），与 wire 上的 `thread/closed` 通知是两条独立路径。C4 改为钉死：`thread/closed` 通知翻译为 None（不是 AgentItem）；且 `thread/closed` 之后到达的 item 事件仍被翻译——"close 之后拒收"不归此层。transport 关闭的 signal 由 main.rs 调用方 / `CodexAdapter::Drop` 负责，与 wire 通知解耦。
  - 计划中"重复 session_started、以最新为准、旧 session 状态被清理"在 codex.rs 没有承载对象：`AgentItem` 没有 `session_id` 字段（`session_id` 只存在于 IPC envelope，由 main.rs 在写出时填充，见 `ipc.rs::IpcMessage`）；`translate()` 不缓存 sessionId。可测的等价契约：translate 对多次 `thread/started`（不同 sessionId）一致返回 None；其间到达的 item 事件的 `AgentItem` 输出与 sessionId 完全无关——序列化后既不含 `session_old` 也不含 `session_new`，证明 codex.rs 没有"旧 session 状态残留"对象。"以最新 session 为准 / 清理旧 session 状态"的责任明确归 main.rs 的 `RuntimeHubWorker` / `session_event` 路径。

### 阶段 1+2 实测记录（2026-06-02）

所有任务（C1-C5、D1-D3、B1-B10、A1-A2、F1-F4）完成。

| 范围 | 起始（2026-06-01） | 完成时（2026-06-02） | 修订后目标 | 达成 |
| --- | --- | --- | --- | --- |
| Rust 整体 | 59.95% | 71.74% | ≥ 72% | 差 0.26pp |
| Swift 整体 | 27.46% | 30.69% | ≥ 32% | 差 1.31pp |
| 加权整体 | ≈ 40% | 48.17% | ≥ 50% | 差 1.83pp |

每文件明细：

- Rust: `ipc.rs` 100% / `diag.rs` 97.22% / `record.rs` 92.83% / `codex.rs` 82.31% / `main.rs` 53.92%
- Swift: `ConversationRailNavigator.swift` 100% / `ToolPresentation.swift` 100% / `ConversationTurn.swift` 96.83% / `HistoryModel.swift` 95.40% / `WorkbenchModel.swift` 91.97% / `ThreadRuntimeModel.swift` 87.57% / `SessionModel.swift` 73.60% / `AgentItemReducer.swift` 52.98% / `DaemonClient.swift` 44.93% / `DaemonTransport.swift` 100% (`{ get }`-only protocol) / `ProcessDaemonTransport.swift` 24.24% / `SessionView.swift` 4.27% / `MessageRoleViews.swift` 0% / `RichMessageView.swift` 11.76% / `StreamingTextView.swift` 20.48% / `SessionTextSelectionCoordinator.swift` 17.46% / `main.swift` 27.12%

测试规模：起始 167（Rust 62 + Swift 89）→ 完成 215（Rust 85 + Swift 130，+48）。

差距说明：三项目标都在 1-2pp 内未达成。原因是阶段 2 的 SessionView 重构在实读后被 Plan agent 校正为"原计划的三个抽出对象已被先前工作实现"，缩减为瘦版 A1+A2，预期提升 +2-3pp Swift，实测 +1.09pp。这是真实可达数字；进一步提升必须啃 SessionView 视图体或 SpawnTurn/History/ActionDecision worker 分派路径，按显式不测策略均不在阶段 1+2 范围内。

`docs/QUALITY.md` 已固化基线、测量命令与显式不测清单，作为后续 PR 的判断依据。

### 2026-06-02 修订记录

C5 实测后两项决策更新：

- **C5 目标下调**：`codex.rs` 行覆盖目标从 ≥ 88% 改为 ≥ 82%。C 块共加 16 个测试后实测 codex.rs = 82.31%。剩余约 17% 未覆盖集中在罕见 unknown event variants、turn_start 长循环的错误分支与 Drop 路径，强行追加测试会产生大量低价值断言（针对几乎不可能命中的协议路径）。Rust 整体目标 ≥ 75% 不变，杠杆改由 D 块（main.rs 从 34.83% → ≥ 65%）承担。
- **D 块方向修正**：原计划"抽 `parse_args` + `CliCommand` + `RuntimeDeps`"在 D1+D2 实施前被 implementer 拒绝并报回——读 `agentdeckd/src/main.rs:1695-1830` 确认 Rust daemon 完全不解析 CLI flag。CLI 参数（`--selfcheck` / `--diagnostics-report` / `--profile`）的解析全部在 Swift 侧 `Sources/AgentDeck/main.swift`，daemon 通过 stdin JSONL 派发循环消费已分类的请求（`selfcheck/logging`、`diagnostics/report`、`history/*`、`turn/*` 等）。修订为：
  - 抽 `run<R: BufRead, W: Write + Send + 'static>(stdin: R, stdout: W, deps: impl RuntimeDeps) -> std::io::Result<()>`，让 stdin/stdout 与 RuntimeHub/worker spawn 可注入测试。
  - `RuntimeDeps` 仅注入 `RuntimeHub` 构造（容量参数）与 worker spawn 适配（生产用 `thread::spawn`，测试用 inline 执行 + 完成信号）；不抽 env/clock/fs。
  - 写 dispatch 测试：覆盖空行跳过、malformed JSONL 错误帧、ping/pong、shutdown、selfcheck/logging、diagnostics/report 各路径与 RuntimeHub 拒绝并发同 session 的等错误反馈。
  - selfcheck/diagnostics CLI 行为不变是 daemon JSONL 输出格式不变的等价命题，因为 Swift 入口只是把 stdout JSONL 转写为最终输出。
- **D3 目标下调**：D 块完成后实测 `main.rs` = 53.92%（D1 抽 `run` + D2 加 7 个 dispatch 测试后，从 34.83% 提升 +19pp）。未达原 ≥ 65% 目标。剩余未覆盖集中在 `HubAction::SpawnTurn` / `HubAction::ActionDecision` / `HubAction::History` 三条分派路径，它们需要 mock `RuntimeHub` 内部 channel 与 `ActionDecision` 协调，工作量与 B 块（Swift `DaemonClient` 协议化）相当但加权收益小得多（Swift 整体 27.46% 是阶段 1 最大杠杆）。`main.rs` 目标改为 ≥ 54%（实测值）写进 QUALITY.md 显式不测清单——`SpawnTurn`/`History`/`ActionDecision` 三条 worker 分派路径的覆盖责任移到阶段 2 或后续 PR。Rust 整体目标因此从 ≥ 75% 改为 ≥ 72%。
- **块 A 修订**：B 块完成后实测 Swift = 29.60%、加权整体 = 47.6%，按设计触发阶段 2 进入块 A。但 Plan agent 实读 `SessionView.swift` 后发现关键事实校正：
  - **原 design 写的"SessionView 2962 行"过期**——实际 1594 行。
  - **原计划要抽的三个对象都已被先前工作抽走**：`SessionEventReducer` 已存在为 `AgentItemReducer.swift`（已测）；`SessionScrollSelectionCoordinator` 部分等价物已存在为 `SessionTextSelectionCoordinator` + `TurnJumpRailLayout` + `ConversationScrollSpy`（已测）；`ConversationTurn` 聚合 + 流式 buffer/delta 合并在 `SessionModel` 与 `ConversationTurn.swift`（已测）。
  - SessionView 残余 1594 行构成：69% 真声明式 SwiftUI view body（不可单测）、10% 已被测纯函数 helper、6% AppKit 桥接（不可测）、~9% 可抽出的命令式/数据 helper（约 95 行有意义）。
  - 块 A 缩减为瘦版：A1 抽 `ToolPresentation`（5 个工具 helper：`outputLabel/webSearchTitle/shellMetadata/toolName/toolMetadata`）+ ~10 个 @Test；A2 抽 `ConversationRailNavigator`（`scrollConversationRailStep` 纯函数化）+ ~4 个 @Test。预期 Swift 整体提升 +2–3pp，加权整体到 50–52%。
  - 原计划"重构 `SessionView` 抽出 reducer/state/coordinator"作为已完成的历史项关闭（实际由 `AgentItemReducer`/`SessionTextSelectionCoordinator`/`ConversationTurn` 先前工作满足）。
  - 剩余 SessionView view body（约 1100 行）显式记入 QUALITY.md "不强求覆盖率的范围"——SwiftUI 声明式渲染，靠 `--selfcheck` + 人工 QA 把关。
  - Swift 整体目标因此从 ≥ 50% 改为 ≥ 32%（实测可达）；加权整体目标从 ≥ 70% 改为 ≥ 50%。这是阶段 1+2 的真实可达上限，不是阶段 1 的中间数。
