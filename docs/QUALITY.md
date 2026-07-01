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

## AppKit 重写后的验证清单

前端已完成 SwiftUI→AppKit 全量重写（Tasks 1–12）。以下验证项应在每次涉及前端改动后运行，也是里程碑收口的最低门控。

### 必跑验证命令

```bash
# 零 SwiftUI / Textual import（必须为空输出）
grep -rn "import SwiftUI" Sources Tests

# 构建与测试
swift build
swift test   # 覆盖：markdown builder、display-row、observation binder、
             #         行高缓存、契约一致性、rail 几何、smoke tests

# headless 自检（IPC 生命周期 + 日志/脱敏）
swift run AgentDeck -- --selfcheck

# 文档结构检查
bash scripts/verify-agent-docs.sh

# Rust 后端（确认后端/协议未被牵动）
cargo test
```

### 手动 `swift run AgentDeck` 核验清单

下列项目无法通过单元测试覆盖，须每次发布前人工验证：

- [ ] 应用正常启动，窗口标题显示 `AgentDeck Dev`（debug 构建）
- [ ] 左侧历史侧栏（NSOutlineView）宽度约 260pt，可自由拖动分割线
- [ ] 历史列表刷新后按项目 `cwd` 分组展示
- [ ] 新建会话（点击项目旁加号）→ 右侧显示空状态视图
- [ ] 发送第一条 prompt → 会话流开始流式渲染（reasoning / shell / file-edit 行）
- [ ] 高风险操作触发 approve / deny 控件
- [ ] TurnJumpRail 导航点随轮次更新；点击可跳转
- [ ] 继续历史会话：点击历史行 → 右侧回放历史 items
- [ ] Cmd-Q 正常退出
- [ ] 选中一段会话文字 → 点击会话区空白处 → 选区清除；点击另一段文字 → 选区切换（跨 cell 单选）

### 已知功能对等差异

- 当前无已知差异。（曾遗落的「点击空白处清除文字选中」已补回：`SessionTextSelectionCoordinator.clearActiveSelection()` 配合 `ConversationViewController` 的 leftMouseDown 本地监视器；跨 cell 的 active selection 仍由 `SessionTextSelectionCoordinator` 维护。）

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

下列文件按策略接受低覆盖，靠 `swift run AgentDeck -- --selfcheck`、`--diagnostics-report --json` 和人工 QA 把关。新加代码不得借此豁免；只有进程入口、AppKit 视图控制器装配、真实 IO 桥接才合规。

- `Sources/AgentDeck/SessionViewController.swift`（AppKit 视图控制器装配；纯逻辑已在 `ObservationBinder` / `TurnJumpRailLayout` / `ConversationRailNavigator` / `SessionTextSelectionCoordinator` 等测试中覆盖）
- `Sources/AgentDeck/HistorySidebarViewController.swift`、`Sources/AgentDeck/ConversationViewController.swift`（NSOutlineView / NSTableView delegate 与数据源；与 AppKit 运行时强耦合）
- `Sources/AgentDeck/ConversationRowFactory.swift`、`Sources/AgentDeck/ConversationRowViews.swift`（AppKit NSView 行视图）
- `Sources/AgentDeck/StatusBarView.swift`、`Sources/AgentDeck/TurnJumpRailView.swift`、`Sources/AgentDeck/EmptyStateView.swift`（AppKit 视图渲染）
- `Sources/AgentDeck/main.swift`（应用 bootstrapping）
- `Sources/AgentDeck/AppDelegate.swift`（NSApplication 生命周期）
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

`agentdeck-cli/tests/e2e_codex.rs`、`e2e_claude_code.rs` 和
`e2e_cross_agent_history.rs` 是真实 daemon / vendor CLI 的 E2E 集成测试。
启用方式：

```bash
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code -- --nocapture
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history -- --nocapture --test-threads=1
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

## v0.2 手动 QA 清单（每次 v0.2 发布前必须勾选）

下列项目须人工验证，在 `swift run AgentDeck` 真实运行时逐项确认：

- [ ] 同窗口可启动 Codex 会话 / CC 会话 / 在两者间切换
- [ ] CC 流式消息、reasoning、shell、diff 渲染对等于 Codex
- [ ] CC permission mode（6 种）下拉可切换，新 turn 生效
- [ ] Plan mode 进入后 UI 显示 Plan 内容并可批准/拒绝
- [ ] CC tool use 触发 approval 时显示卡片，底部 vendor 区显示"当前 permission mode + tool name"
- [ ] Codex tool use 触发 approval 时显示卡片，底部 vendor 区显示 sandbox + policy + persist
- [ ] CC 历史 thread 在侧栏与 Codex 历史共存，左侧默认合并显示且不提供 agent 切换
- [ ] CC 历史 thread 点开可回放 + 继续
- [ ] CC archive（`claude rm` 调用）后侧栏不可见，且不影响 Codex 历史显示
- [ ] CC rename 后侧栏标题更新；终端 `claude --resume <id>` 看到同名
- [ ] CC 未登录 → 明确诊断错误，不静默
- [ ] CC 二进制不存在 → 明确诊断错误，附 `npm install` 提示
- [ ] Token usage 在 mini 面板显示
- [ ] Output Style 下拉可见
- [ ] CC capability、Codex 没的，UI 仅在 CC session 显示对应控件
- [ ] Codex capability、CC 没的，UI 仅在 Codex session 显示对应控件
- [ ] AgentDeck 创建的 CC 会话，在终端 `claude --resume <id>` 能看见且能继续（事实唯一来源验证）
- [ ] `cargo test` + `swift test` + `agentdeck selfcheck` + `scripts/verify-agent-docs.sh` 全绿

## 收口清单

阶段性工作结束前至少完成：

1. 更新相关文档。
2. 运行与变更范围匹配的验证命令。
3. 运行 `git status --short --branch`。
4. 摘要说明哪些验证已跑、哪些未跑以及原因。
