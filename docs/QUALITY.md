# AgentDeck 质量与验证

本页把可机械执行的质量入口集中起来。新增规则时优先补测试或脚本，让 agent 能在仓库内直接验证，而不是依赖口头记忆。

## 常用验证命令

```bash
cargo test
swift test
swift run AgentDeck -- --selfcheck
swift run AgentDeck -- --diagnostics-report --json
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
scripts/verify-agent-docs.sh
```

## 测试覆盖率

测量命令：

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

### 当前基线（2026-06-02 实测）

| 范围 | 行覆盖 | 目标 | 备注 |
| --- | --- | --- | --- |
| Rust 整体 | 71.74% | ≥ 70% | `ipc.rs` 100% / `diag.rs` 97.22% / `record.rs` 92.83% / `codex.rs` 82.31% / `main.rs` 53.92% |
| Swift 整体 | 30.69% | ≥ 30% | 模型层 ≥ 73%；视图层按策略接受低覆盖（见下） |
| 加权整体 | 48.17% | ≥ 45% | (Rust 3175 + Swift 1831) / 10394 |

### 显式不强求覆盖率的范围

下列文件按策略接受低覆盖，靠 `swift run AgentDeck -- --selfcheck`、`--diagnostics-report --json` 和人工 QA 把关。新加代码不得借此豁免；只有声明式 UI 渲染、进程入口、AppKit 桥接才合规。

- `Sources/AgentDeck/SessionView.swift`（声明式 SwiftUI 视图体；可抽出的纯逻辑已在 `ToolPresentation` / `ConversationRailNavigator` / `ConversationTurn` / `AgentItemReducer` / `SessionTextSelectionCoordinator` / `TurnJumpRailLayout` / `ConversationScrollSpy` 等先前工作中完成测试）
- `Sources/AgentDeck/MessageRoleViews.swift`、`Sources/AgentDeck/RichMessageView.swift`、`Sources/AgentDeck/StreamingTextView.swift`（SwiftUI 视图渲染）
- `Sources/AgentDeck/main.swift`（应用 bootstrapping）
- `Sources/AgentDeck/ProcessDaemonTransport.swift`（真实 `Process` / `Pipe` / reader 线程；测试用 `Tests/AgentDeckTests/StubDaemonTransport.swift` 走 `DaemonTransport` 协议路径）
- `agentdeckd/src/main.rs` 中 `HubAction::SpawnTurn` / `HubAction::ActionDecision` / `HubAction::History` 三条 worker 分派路径（需要 mock `RuntimeHub` 内部 channel 与 `ActionDecision` 协调，工作量与产出比偏低；其余 `fn run` 分派路径已由 `dispatch_tests` 覆盖）

### 失败处理

如果某次改动让覆盖率显著下降（如 Rust < 70% 或 Swift < 30%），先评估：

- 是否新增了视图层 / 进程入口 / AppKit 桥接代码（按策略接受）→ 在显式不测清单里追加该文件。
- 是否新增了核心路径代码（IPC、adapter、模型层）→ 补测试或拒绝该改动。

不接 CI 门禁脚本。仓库目前无 CI；门禁脚本闲置反而是债。`docs/QUALITY.md` 描述性记录基线足够给未来 agent 提供判断依据。

## 按变更范围选择验证

| 变更范围 | 最小验证 |
| --- | --- |
| Rust daemon、IPC、Codex adapter、run record、diagnostics | `cargo test`；涉及运行态再跑 `swift run AgentDeck -- --selfcheck` |
| Swift UI、会话模型、历史回放、富文本渲染、选择/滚动行为 | `swift test` |
| approval / action request / action decision | `cargo test approval`；`swift test --filter approval`；再跑完整 `cargo test`、`swift test`、`swift run AgentDeck -- --selfcheck` |
| 诊断日志、自检、数据目录、profile、密钥脱敏 | `cargo test`；`swift run AgentDeck -- --selfcheck`；`swift run AgentDeck -- --diagnostics-report --json`；涉及 profile 时加跑 `swift run AgentDeck -- --selfcheck --profile dev` 和 `swift run AgentDeck -- --diagnostics-report --json --profile dev` |
| 文档结构、AGENTS 入口、计划规则 | `scripts/verify-agent-docs.sh` |
| 协议 schema 或 app-server 方法 | `cargo test`；核对 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt` |
| agentdeck-protocol 类型变更 | `cargo test`（漂移测试自动运行）；若漂移测试失败须先重新生成快照（见下） |
| 参考客户端 CLI（agentdeck-cli）、Transport、Client | `cargo test -p agentdeck-cli`；再跑完整 `cargo test` |
| 测试覆盖率回归怀疑 | `cargo llvm-cov --summary-only`；`swift test --enable-code-coverage` + `xcrun llvm-cov report ...`；对照 `当前基线` 表 |

## 协议 schema 漂移测试

`cargo test` 会在 `agentdeck-protocol` 测试套件中运行 `schema_matches_committed_snapshot`：比较 schemars 从 Rust 类型实时生成的 JSON Schema 与 `protocol/agentdeck/agentdeck-protocol.schema.json` 快照。若两者不一致，说明协议类型已变更但快照未更新，测试失败。

重新生成快照：

```bash
UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot
```

重新生成后须将快照提交进仓库（`git add protocol/agentdeck/agentdeck-protocol.schema.json`）。

核对快照与当前代码是否同步（独立验证，无需构建测试二进制）：

```bash
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"
```

## 门控 E2E 测试

`agentdeck-cli/tests/e2e.rs` 是真实 daemon 的 E2E 集成测试。启用方式：

```bash
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e
```

**门控机制：** 每个测试在未设置环境变量 `AGENTDECK_E2E` 时 `eprintln!("skipped...")` 后直接早返回（不是 `#[ignore]`，因此不能用 `--ignored` 启用；标准 `cargo test` 中显示为 passed 而非 ignored）。设 `AGENTDECK_E2E=1`（需 `codex login`）才真正运行。

**前置条件：** `codex login` 已完成（测试会真实 spawn daemon 并发送 IPC）。

**断言策略：** E2E 测试只断言响应的契约形态（消息 kind、必要字段存在、退出码等），不断言 agent 返回的具体文本内容，以避免测试因模型输出变化而 flaky。

**CI 默认跳过：** 不设置 `AGENTDECK_E2E=1` 时，标准 `cargo test` 不触发真实 E2E，不需要 `codex login`。

## 文档结构检查

`scripts/verify-agent-docs.sh` 是当前最小 doc-gardening 检查。它验证：

- 关键文档入口存在。
- `AGENTS.md` 链接到项目北极星、README、架构、诊断、质量、计划和协议事实源。
- `README.md` 链接到架构、文档索引和质量文档。
- 项目没有重新引入已剥离的外部 skill 强制绑定。
- `docs/plans/README.md` 存在，计划文档不再只是散落文件。

后续接入 CI 时，先把这个脚本作为独立 job，再逐步增加更严格的结构检查。

## 失败处理

- 验证失败时，不要只重跑。先读失败输出，定位是哪条不变量被破坏。
- 如果失败来自文档漂移，优先更新真实文档或检查脚本，不要绕过规则。
- 如果失败来自 flaky 外部条件，记录命令、错误和复验结果到对应计划文档。

## 收口清单

阶段性工作结束前至少完成：

1. 更新相关文档。
2. 运行与变更范围匹配的验证命令。
3. 运行 `git status --short --branch`。
4. 摘要说明哪些验证已跑、哪些未跑以及原因。
