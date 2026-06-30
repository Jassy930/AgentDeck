# Phase 3 重写 delta：T3.1–T3.6 合并为 3 个大 task

| 字段 | 值 |
|---|---|
| 状态 | 已批准（用户决策 2026-06-30）|
| 取代 | `docs/plans/2026-06-30-unified-shell-v02-implementation.md` Phase 3（T3.1–T3.6）|
| 关联 | `.superpowers/sdd/progress.md` 子项目 3 |

## 触发原因

执行 Phase 2 末尾时实测发现：原 plan Phase 3 假设"增量适配 CodexAdapter 到 v2"。但实际 v1 daemon 状况：

- `agentdeckd/src/main.rs` (2404 行) 大量直接构造 v1 `IpcMessage` / `SessionState` / `AgentItemKind` / 旧 `AgentItem` 结构
- `agentdeckd/src/codex/mod.rs` (2582 行) `use crate::ipc::{ActionDecision, ActionRequest, AgentItem, AgentItemKind, AgentReference, FileEditChange, HistoryThreadDetail, HistoryThreadList, HistoryThreadSummary, HookFragment, Lifecycle, ToolAction}` —— 这些类型已在 T1.9 全部删除
- `agentdeckd/src/runtime/hub.rs` 同样依赖 v1 `IpcMessage`
- `agentdeckd/src/record.rs` 与 `diag.rs` 也按 v1 `ActionRequest`（u64 id）等设计

恢复编译需要重写 daemon 内 codex 翻译层 + adapter + stdin 主循环 + 支持模块。颗粒度远超原 plan T3.x 的 6 个增量 task；继续 per-task SDD 会 BLOCK 多次或产生几百级联 fix 循环。

## 决策

按用户选项 A（重写 Phase 3 spec），把原 T3.1–T3.6 替换为 3 个大 task。每个 task 用 opus 跑（判断难度 + 长上下文需要）。串行依赖。

## 新 task 清单

### Task 3A — codex translation + capabilities v2 重写

**目标：** 把 Codex app-server JSON 翻译为 v2 `AgentItem` enum；构建 `SessionCapabilities`。

**Files：**
- 大改：`agentdeckd/src/codex/translate.rs`（T2.2 空骨架；本 task 填入新 v2 翻译）
- 大改：`agentdeckd/src/codex/capabilities.rs`（T2.2 空骨架；本 task 填入 `build_codex_capabilities` + `probe_codex_version`）
- 引用：`agentdeck-protocol::{AgentItem, AgentItemMeta, ShellStatus, DiffFile, DiffStatus, PlanStep, PlanStepStatus, ActionRequest, ActionKind, ActionRequestVendor, SessionCapabilities, CodexCapabilities, CodexSandboxMode, CodexReasoningEffort, CodexApprovalPolicy, CapabilityId}`

**关键设计：**
- `translate.rs` 持有一个 stateful translator（per-session 实例），内部维护 in-flight `AgentItem` 累加器（key=item id）
- v1 `Lifecycle::Started/Delta/Completed` 概念**内化到 translator**，不再暴露——每次收到 codex `delta`，accumulator update；每次 `completed` 把累加 text emit 为一个 `AgentItem`；UI 不感知 delta（plan 决策 A 的 cumulative semantics 替代）
- 同步从 codex/mod.rs 现有 2582 行内提取所有翻译相关逻辑（剥离 vendor JSON 解析 + AgentItem 构造），改造为输出 v2 AgentItem 类型
- Output：`pub fn translate_codex_event(...)`、`pub struct CodexTranslator` 等

**接口（供 Task 3B 用）：**
- `pub struct CodexTranslator { session_id: SessionId, thread_id: Option<ThreadId>, in_flight: HashMap<String, InFlightItem> }`
- `pub fn new(session_id, thread_id) -> Self`
- `pub fn translate_line(&mut self, line: &str) -> Vec<ServerEvent>`（核心：单行 codex JSON → 0 或 N 个中立 ServerEvent）
- `pub fn build_codex_capabilities(version: String) -> SessionCapabilities`
- `pub fn probe_codex_version() -> String`

**验收：**
- `cargo build -p agentdeckd --lib`（lib 仅含 agent + runtime::router + 新 translate + 新 capabilities）— PASS
- 新增 `agentdeckd/tests/codex_translate.rs` 用 v0.1 fixture（`agentdeckd/tests/fixtures/codex/`）重放，断言输出 v2 ServerEvent 形态
- 旧 codex/mod.rs 暂保留但 lib 不暴露（保留逻辑供 Task 3B 引用，Task 3C 删除）

### Task 3B — CodexAdapter impl Agent trait + 重写 sessionStart/continue/cancel

**目标：** CodexAdapter 完整 impl Agent trait，与 v2 协议对齐。

**Files：**
- 大改：`agentdeckd/src/codex/adapter.rs`（T2.2 空骨架；本 task 写新 adapter）
- 引用：Task 3A 的 `CodexTranslator`，`agentdeck-protocol::{Agent, AgentEventSender, AgentSessionHandle, SessionStart, VendorSessionOptions, CodexSessionOptions, ServerEvent, ActionDecision, VendorControlPayload, ProtocolError}`
- 移除：`agentdeckd/src/codex/mod.rs` 中的旧 `CodexAdapter` struct + impl + Drop（迁移完毕后剩 docstring + `pub mod adapter; pub mod translate; pub mod capabilities;` + `pub use adapter::CodexAdapter;`）

**关键设计：**
- 新 CodexAdapter 内部仍用 turn 级 spawn（与 v1 同生命周期）；Drop kill 进程组
- spawn `codex app-server` + initialize 握手 + newSession（或 thread/resume continue）
- 翻译走 Task 3A 的 `CodexTranslator`
- approval：当 codex 发 server request 时，构造 v2 `ActionRequest`（含 `ActionRequestVendor::Codex { policy/sandbox/persist }`）发到 events sender；从 caller 收到 `ActionDecision` 通过 stdin 回写 codex response
- session_id 由 daemon 生成（UUID），thread_id 由 codex 返回

**接口：**
- `pub struct CodexAdapter { ... }`
- `pub fn new() -> Self`
- `#[async_trait] impl Agent for CodexAdapter { ... }` — 7 methods 全部实现

**验收：**
- `cargo build -p agentdeckd --lib` PASS
- `cargo test -p agentdeckd --lib --test codex_translate` PASS（Task 3A 测试仍 PASS）
- 新增 `agentdeckd/tests/codex_adapter_shape.rs`：trait shape 验证 + 简单 mock 不触真实 codex 的 sessionStart 路径测试
- 门控 E2E（`AGENTDECK_E2E=1`）暂时还跑不起来（需要 Task 3C 接 stdin loop），本 task 不做

### Task 3C — main.rs / hub / record / diag 全面升级 + 移除 daemon-bin gate

**目标：** daemon 整体 cargo build clean，所有 fixture v2 化，移除 `required-features = ["daemon-bin"]` gate；门控 E2E 能跑。

**Files：**
- 大改：`agentdeckd/src/main.rs` —— 重写 stdin loop 为 `ClientCommand` dispatcher 通过 `AgentRouter` 路由；stdout writer 输出 `ServerEvent` JSONL；移除 v1 `IpcMessage` 转发逻辑
- 大改：`agentdeckd/src/runtime/hub.rs` —— 移除 `IpcMessage` use；改用 `agentdeck_protocol::{ClientCommand, ServerEvent}`；持有 `Arc<AgentRouter>` 并 dispatch
- 大改：`agentdeckd/src/record.rs` —— RunRecord 写入 v2 `AgentItem`；新增 `agent_kind` 字段；旧 ActionRequest u64 id → String
- 大改：`agentdeckd/src/diag.rs` —— DiagEvent struct 加 `agent_kind: Option<AgentKind>`；CodexAdapter 写诊断时填 `Some(AgentKind::Codex)`
- 删除：`agentdeckd/src/codex/mod.rs` 内残留旧 CodexAdapter 实现（已在 Task 3B 迁移；本 task 净化为 mod 入口）
- 修改：`agentdeckd/Cargo.toml` —— 移除 `[[bin]] required-features = ["daemon-bin"]`；移除 `runtime/mod.rs` 中 `#[cfg(feature = "daemon-bin")]` gate on `pub mod hub;`
- 迁移：`agentdeckd/tests/fixtures/codex/*.jsonl` —— v1 → v2 schema（每行加 `agentKind`、ActionRequest vendor block 等）

**关键设计：**
- main.rs 的 stdin loop：每条 stdin JSONL → `serde_json::from_str::<ClientCommand>(line)` → match → `hub.dispatch(cmd)` → `events_rx.recv()` → `serde_json::to_string(&event)` → stdout
- 当 cmd 是 `SessionStart` → `router.start_session(start, events_tx)` → 返回 `AgentSessionHandle` → hub 内 sessions map 持有 handle
- 当 cmd 是 `ActionDecision` → `router.submit_decision(session_id, decision)`
- 等
- record.rs 写入路径加 `agent_kind` 元数据；diag 同
- 完成后 `cargo build -p agentdeckd` 默认（无 feature）应能产出可执行 binary

**验收：**
- `cargo build -p agentdeckd` 默认无 feature 通过；产出 `target/debug/agentdeckd`
- `cargo test -p agentdeckd` 全 PASS（含 Task 3A/3B 测试 + 新加 lib/integration test）
- `cargo run -p agentdeck-cli -- selfcheck` PASS（端到端 ping/pong + lifecycle）
- `cargo run -p agentdeck-cli -- agent list` 返回 `{"agents":["codex"]}`（CC adapter 在 Phase 4，本 task 只注册 Codex）
- 门控 `AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex` PASS（需要本机 `codex login`）
- `target/debug/agentdeckd` 可以由 Swift 端 spawn 并响应（Swift 端 Phase 6 才适配 v2；当前 Swift 仍引用 v1，会破——预期）

## 执行节奏

- 3 个 task 串行依赖（3A→3B→3C），每个 task 自己跑 cargo build/test 作为 review 信号
- 每个 task 用 opus；implementer brief 含 plan v2 协议节 + 当前 daemon 文件路径 + 本 delta 中关键接口约束
- 每个 task 完成后单独 commit，ledger 追加
- Task 3C 完成 = Phase 3 完成；进 Phase 4 (ClaudeCodeAdapter)

## 不在 Phase 3 范围

- ClaudeCodeAdapter (Phase 4)
- agentdeck-cli v2 升级 (Phase 5)
- AppKit UI (Phase 6)
- Swift 端任何改动
- 性能基准 + release gate (Phase 8)
