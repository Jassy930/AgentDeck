# AgentDeck 质量与验证

本页把可机械执行的质量入口集中起来。新增规则时优先补测试或脚本，让 agent 能在仓库内直接验证，而不是依赖口头记忆。

## 常用验证命令

```bash
cargo test
swift test
./script/build_and_run.sh --verify
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
             #         行高缓存、契约一致性、rail 几何、Codex chrome smoke tests

# GUI bundle 启动验证（同时检查 bundle 内 agentdeckd 子进程）
./script/build_and_run.sh --verify

# headless 自检（IPC 生命周期 + 日志/脱敏）
swift run AgentDeck -- --selfcheck

# 文档结构检查
bash scripts/verify-agent-docs.sh

# Rust 后端（确认后端/协议未被牵动）
cargo test
```

### 手动 `swift run AgentDeck` 核验清单

下列项目无法通过单元测试覆盖，须每次发布前人工验证：

- [ ] `./script/build_and_run.sh --verify` 读回 App/daemon 实际 executable path、
      SwiftPM 图标资源 bundle、`Info.plist` 与 Mach-O `minos=15.0`，再确认目标 bundle 两个进程均已启动
      （不能只以进程名、PPID 或 App 进程存在作为成功）
- [ ] 应用正常启动，窗口标题显示 `AgentDeck Dev`（debug 构建）
- [ ] 空态首屏对齐 Codex Desktop：透明标题栏、全高左侧侧栏、居中大标题、圆角 composer、连接卡片和底部速率提示
- [ ] 会话态对齐 Codex Desktop：右侧 thread header、右上环境信息面板、底部悬浮 composer
- [ ] 左侧历史侧栏（NSOutlineView）默认宽度约 216pt，可在 200–280pt 间拖动分割线
- [ ] 项目加号与会话尾部图标紧邻分割线，右侧没有明显无效留白
- [ ] 侧栏「新对话」可进入新会话空态；「搜索」可展开输入框并实时过滤；未实现入口不显示
- [ ] 拖动左侧历史侧栏分割线后，点击/切换会话时分割线保持在用户拖动后的宽度
- [ ] 历史列表刷新后按项目 `cwd` 分组展示
- [ ] 加载数百条真实历史时，侧栏不因逐行重复查找/解码 agent SVG 图标而卡在上一帧转圈；图标资源只加载一次
- [ ] 新建会话（点击项目旁加号）→ 右侧显示空状态视图
- [ ] 发送第一条 prompt → 会话流开始流式渲染（reasoning / shell / file-edit 行）
- [ ] 1280×820 标准窗口下会话流、工具摘要与 composer 共用水平内容轴，不再由每行额外 20pt 缩进制造宽度断层；每个回合最后一行保留 20pt 语义尾距，同一回合内部仍保持紧凑
- [ ] 用户消息使用 `surface2 + border + radius-md`，水平/垂直内距为 14/11pt，短消息按内容收缩、长消息最大不超过正文轴 82%，窄窗下不产生负宽度或约束冲突
- [ ] 会话流 assistant 正文使用 14pt `body`，reasoning 正文使用 13pt `callout` + `text2` 并正确渲染 Markdown，shell / diff 使用 12.5pt `mono`；各类 assistant item 上下内距统一为 4pt，连续内容密度自然且无忽松忽紧
- [ ] assistant / reasoning Markdown 的纯拉丁段落按 `1.45`、CJK 或中西混排段落按 `1.72` 行高渲染；渲染与表格测高一致，等字节中西文替换也须刷新行高，空 reasoning 不虚构正文行；仅 Markdown 属性变化时保留当前文字选区，展开/收起及流式更新后均无裁切、覆盖或异常留白
- [ ] Markdown 标题、列表与 fenced code 不显示 `##` 或 fence 等字面语法；行内代码为低对比圆角代码胶囊，fenced code 为独立代码容器，长路径换行后每段背景连续且不遮挡相邻正文
- [ ] `<local-command-stdout>` / `<local-command-stderr>` 等本地命令包装和 ANSI 内容不得进入用户气泡；纯包装轮次从会话流隐藏，真实用户正文仍原样保留
- [ ] 没有环境/变更数据时右上面板完全折叠且不保留宽度；有数据但空间不足时也优先折叠以保留至少 252pt composer，窗口恢复后自动显示
- [ ] 顶栏只显示已接通的打开目录动作；composer 使用 `surface2` 悬浮背景，输入与占位符使用 14pt `body`，单行整体高度约 100pt，只显示已接通的发送动作且按钮命中区不小于 44pt
- [ ] 工具调用默认以紧凑单行显示 MCP server/tool、中文动作标题或关键路径、真实状态与耗时；展开后再看参数与结果，禁止把不同操作都退化成重复的 `js / completed`；同一 Claude Code `toolUseId` 从进行中更新为单个终态行，不残留重复状态
- [ ] 同一回合连续 2 条及以上执行记录默认聚合为“已读取文件并运行命令”等自然语言摘要；失败/进行中状态紧跟摘要且保留语义色，日常完成态只在有完整耗时时显示低权重耗时，不重复显示“数量 · 已完成”或亮绿色；允许把仅位于两次执行之间的 reasoning 收进组内，但正文、媒体、子任务及回合边界必须截断；展开后按原顺序恢复全部工具、命令、文件修改、中间 reasoning 和各自 payload，文件路径须使用正文可用宽度而非竖向碎裂；收起期间 payload 继续增长后再展开，行高和单项状态仍须刷新且各行不得重叠
- [ ] 真实 Codex `subAgentActivity` 不得显示 `unsupported item type`，须以独立紧凑协作行显示可读任务名及“已开始工作 / 已更新 / 已中断”；该活动不能进入普通工具聚合，也不能把历史 `started` 事件误标成当前进行中
- [ ] 真实 Codex `contextCompaction` 不得显示 `unsupported item type`，须以独立“上下文已压缩”系统行呈现并截断前后工具聚合
- [ ] reasoning 默认折叠，但折叠头必须完整显示「思考过程」，不能因 disclosure 压缩只剩单个 `R` 字符；切换会话时不得继承上一会话同名 item 的展开/收起状态
- [ ] 展开后的 reasoning 正文（包括工具聚合内的中间 reasoning）必须使用会话正文可用宽度，不能收缩成标题宽度或逐词换行；渲染宽度须与行高测量宽度一致，不得裁切或覆盖相邻行
- [ ] 高风险操作触发 approve / deny 控件
- [ ] TurnJumpRail 是独立 44pt 尾列，不覆盖会话正文、composer 或环境面板；尾列最右 8pt 交还 macOS 原生窗口缩放，从右侧中部和右下角均可自然拉宽，剩余 36pt 保持轨道点击、滚轮、↑↓/Home/End 与 VoiceOver 自定义动作可用
- [ ] 开启 macOS「减少动态效果」后 TurnJumpRail 直接跳变，不运行滚动或悬停定时动画
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
| Rust daemon、IPC、Codex adapter、history list 性能、run record、diagnostics | `cargo test`；涉及运行态再跑 `swift run AgentDeck -- --selfcheck` |
| macOS App 打包、daemon 定位或启动错误传播 | `swift test --filter 'DaemonLocatorTests|HistoryDaemonLaunchTests'`；`bash -n script/build_and_run.sh`；`./script/build_and_run.sh --verify` |
| Swift UI、会话模型、历史回放、live session 侧栏可见性、富文本渲染、选择/滚动行为 | `swift test` |
| approval / action request / action decision | `cargo test approval`；`swift test --filter approval`；再跑完整 `cargo test`、`swift test`、`swift run AgentDeck -- --selfcheck` |
| 诊断日志、自检、数据目录、profile、密钥脱敏 | `cargo test`；`swift run AgentDeck -- --selfcheck`；`swift run AgentDeck -- --diagnostics-report --json`；涉及 profile 时加跑 `swift run AgentDeck -- --selfcheck --profile dev` 和 `swift run AgentDeck -- --diagnostics-report --json --profile dev` |
| 文档结构、AGENTS 入口、计划规则 | `scripts/verify-agent-docs.sh` |
| Codex vendor schema 或 app-server 方法 | 按下方“Codex vendor schema 快照”重新生成；独立快照逐字比较、聚合 schema 规范化比较；再运行 `cargo test` |
| agentdeck-protocol 类型变更 | `cargo test`（漂移测试自动运行）；若漂移测试失败须先重新生成快照（见下） |
| 参考客户端 CLI（agentdeck-cli）、Transport、Client | `cargo test -p agentdeck-cli`；再跑完整 `cargo test` |
| 测试覆盖率回归怀疑 | `cargo llvm-cov --summary-only`；`swift test --enable-code-coverage` + `xcrun llvm-cov report ...`；对照 `当前基线` 表 |

## Codex vendor schema 快照

`protocol/ClientRequest.json` 等文件是 Codex app-server 的 vendor 协议快照，
与 AgentDeck 自身 schemars 生成的
`protocol/agentdeck/agentdeck-protocol.schema.json` 是两套独立门禁。
`cargo test` 通过不能证明本机 Codex 版本与 vendor 快照一致。

升级刷新或同版本复验时，都先在临时目录 fail-closed 生成，并记录本机
Codex 的实际版本：

```bash
CODEX_BIN="$(command -v codex)"
ACTUAL_VERSION="$("$CODEX_BIN" --version)"
SCHEMA_DIR="$(mktemp -d /tmp/agentdeck-codex-schema.XXXXXX)"
"$CODEX_BIN" app-server generate-json-schema --out "$SCHEMA_DIR"

jq -er '
  .oneOf as $requests
  | if (($requests | type) != "array") or (($requests | length) == 0) then
      error("ClientRequest.oneOf missing or empty")
    elif any($requests[];
      ((.properties.method.enum | type) != "array")
      or ((.properties.method.enum | length) != 1)
      or ((.properties.method.enum[0] | type) != "string")) then
      error("unexpected ClientRequest method schema")
    else
      [$requests[].properties.method.enum[0]] as $methods
      | if (($methods | length) != ($methods | unique | length)) then
          error("duplicate ClientRequest methods")
        else $methods | sort[] end
    end
' "$SCHEMA_DIR/ClientRequest.json" > "$SCHEMA_DIR/client-methods.txt"
```

升级刷新时，将 `ClientRequest.json`、`JSONRPCMessage.json`、
`ServerNotification.json`、`ServerRequest.json`、
`codex_app_server_protocol.v2.schemas.json` 与 `client-methods.txt` 复制到
`protocol/`，再把 `ACTUAL_VERSION` 写入 `CODEX_VERSION.txt`。同版本复验时先运行：

```bash
test "$ACTUAL_VERSION" = "$(cat protocol/CODEX_VERSION.txt)"
```

四个独立 schema 与 `client-methods.txt` 的输出顺序稳定，提交前逐文件运行
`cmp`。聚合的 `codex_app_server_protocol.v2.schemas.json` 中 definitions 顺序
可能在相同版本的两次官方生成之间变化，必须用 `jq -S` 规范化后比较，不能把
raw byte 顺序差异误判成协议漂移：

```bash
jq -S . protocol/codex_app_server_protocol.v2.schemas.json \
  > "$SCHEMA_DIR/committed-v2.normalized.json"
jq -S . "$SCHEMA_DIR/codex_app_server_protocol.v2.schemas.json" \
  > "$SCHEMA_DIR/generated-v2.normalized.json"
cmp "$SCHEMA_DIR/committed-v2.normalized.json" \
  "$SCHEMA_DIR/generated-v2.normalized.json"
```

确认 method 表行数和内容一致后，再运行 `cargo test`、
`scripts/verify-agent-docs.sh` 和 `git diff --check`。当前稳定合约不使用
`--experimental`；只有客户端显式启用 `experimentalApi` 时才建立独立实验基线。

## AgentDeck IPC schema 漂移测试

`cargo test` 会在 `agentdeck-protocol` 测试套件中运行
`schema_matches_committed_snapshot`：比较 schemars 从 Rust 类型实时生成的
JSON Schema 与 `protocol/agentdeck/agentdeck-protocol.schema.json` 快照。若两者
不一致，说明 AgentDeck IPC 类型已变更但快照未更新，测试失败。

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
