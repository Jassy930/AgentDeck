# 前端预览测试台（mock daemon）设计

日期：2026-07-04

## 背景和用户问题

macOS 前端要对照设计稿（目标图1）做视觉与交互对齐，但当前只能连真实 `agentdeckd` 才能填充会话/历史内容。真实链路需要 daemon、vendor CLI（Codex / Claude Code）、登录态和真实项目，既慢又不可控，无法稳定复现设计稿里的固定内容（项目树、命令块、diff 卡、运行中状态、右上环境面板数值）。

用户诉求：给本地运行界面增加一个专门测试前端的预览页，会话内容是 mock 的，并且**前端要完全真实**——不要在 UI 层塞 mock 分支，而是"后台跑一个 mock daemon，前端照常跑"。

## 目标与非目标

### 目标

- `swift run AgentDeck -- --preview` 启动一个用 mock 后端驱动的窗口，内容复刻图1（侧栏项目/会话 + 选中会话的对话内容 + 右上环境面板）。
- 前端从 `SessionModel → DaemonClient → IPC v2 编解码 → 事件路由 → 乐观插入 → 流式渲染` 全部走真实代码；唯一被替换的是"到子进程的字节传输"。
- 可交互：点击侧栏会话真实触发 `history read` 并渲染；输入发送真实触发 `sessionStart/continue`，mock 异步回吐脚本化 live turn，走真实流式渲染。
- 右上环境面板重构为图1 的只读 Changes/Git 布局并改为数据驱动，preview 注入 mock 值。

### 非目标

- 不改 daemon（Rust）、不改 IPC v2 协议类型、不改 history 数据结构（保持 v0.2 统一壳边界 N1–N8）。
- 不做真·mock daemon 子进程（不在 `agentdeckd` 里加 `--mock` 模式）。
- 不做前端各组件的逐像素对齐（用户气泡「You」标签、输入占位符、侧栏刷新按钮、标题清洗等）——这些属于对齐工作，用本预览台作为可视基准迭代，不在本设计内。
- 不在 UI 渲染层引入任何 `if preview` 分支。

## 架构方案和边界

### 后端唯一替换点

`DaemonClient(profile:transport:)` 本身支持注入 `transport: DaemonTransport?`（`Sources/AgentDeck/DaemonClient.swift:177`）。preview 模式注入进程内 `MockDaemonTransport`，其余前端零改动。

```
SessionModel ──真实──> DaemonClient ──真实 IPC──> MockDaemonTransport（进程内脚本后端）
     ^                      |
     └──真实 ServerEvent────┘
```

`DaemonTransport` 协议（`Sources/AgentDeck/DaemonTransport.swift`）只收发原始 JSONL 帧：`send(_ line:)` 进、`setIncomingHandler` 出、`start()/shutdown()`、`isStarted/isAlive`。mock 实现全部这些。

### 新增文件（仅 preview 路径引用，不进生产流程）

- `Sources/AgentDeck/Preview/MockDaemonTransport.swift`
  - 实现 `DaemonTransport`。`send(line)` 解码 `ClientCommand`，按类型走 admin 或 streaming 分支，经后台队列异步调用 incoming handler 回帧（模拟真实传输的异步性，避免重入）。
  - admin：`.ping` → `{"reply":"ping"}`；`.history(.list)` → `{"reply":"history","response":{kind:list,value:[...]}}`；`.history(.read)` → `{"reply":"history","response":{kind:read,value:{turns:[...]}}}`；`.history(.rename/.archive/.unarchive)` → `{"reply":"history","response":{kind:ack}}`。
  - streaming：`.sessionStart` / `.sessionContinue` → 异步 emit 一串真实 `ServerEvent`（`sessionStarted` →（可选 `sessionCapabilities`）→ `agentItem × N` → `turnComplete`），每帧之间加小延时模拟流式。
  - `.actionDecision` / `.vendorControl` → 静默 ack（不回或回一个良性事件）。
- `Sources/AgentDeck/Preview/MockDaemonScript.swift`
  - mock 数据源（复刻图1）：历史列表（`refactor-auth` 组：「把登录模块拆分为独立 service」「修复 token 刷新竞态」；`agentdeck-docs` 组：「补充部署章节」等），选中会话的 turns（用户 prompt + `reasoning` + `shell`：`rg "login" src/ -l` 带输出 + `diff`：`auth/service.ts +64 -12` + 运行中项），提交后的 live turn 脚本，以及环境面板 mock 值（`+128 -34`、`3 文件`、分支 `main`、提交 `a1b2c3d`）。
  - 用真实协议类型（`HistoryListItem`、`HistoryReadResponse`、`HistoryTurn`、`ServerEvent`、`AgentItem`）构造，`Codable` 编码为 JSONL。

### 改动文件

- `Sources/AgentDeck/main.swift`：解析 `--preview` flag（仿现有 `--selfcheck` 模式），透传给 `AppDelegate`。
- `Sources/AgentDeck/AppDelegate.swift`：preview 分支用 `SessionModel(client: DaemonClient(transport: MockDaemonTransport(script:)), environmentInfo: ...)` 构造；非 preview 路径不变。
- `Sources/AgentDeck/SessionModel.swift`：新增可注入的只读 `environmentInfo: EnvironmentInfo?`（`@Observable`），默认 `nil`；真实 app 优雅降级（面板显示空态/零值）。
- `Sources/AgentDeck/CodexDesktopChrome.swift`：`CodexEnvironmentPanelView` 重构为图1 只读 Changes/Git 布局（标题「变更 Changes」+ 大号 `+128 -34  3 文件` + 分组「Git」+ 右对齐键值 `分支 / 提交`），改为绑定 `SessionModel.environmentInfo`；移除「本地/master/提交或推送/来源」交互骨架。

### 数据模型

新增 `EnvironmentInfo`（放前端本地，因它是 macOS UI chrome、只被环境面板与 `SessionModel` 使用，不进 `AgentDeckCore` 共享层）：`added: Int`、`removed: Int`、`fileCount: Int`、`branch: String?`、`commit: String?`。默认/空值时面板显示 `+0 -0` 与占位。

### 边界说明

环境面板当前无 daemon 后端，IPC 协议里没有 changes/git 字段（设计文档 `2026-07-01-codex-desktop-chrome-sync.md` 已注明是静态占位，后续接 git 服务）。因此其 mock 值在 preview 引导层直接注入 `SessionModel.environmentInfo`，**不经 IPC**——这不违反"前端真实"，因为真实 app 里它本就不经 daemon。会话/历史/live turn 仍全部经真实 IPC。

## 错误处理与可观测性

- mock 收到无法解码的 `ClientCommand` 行：回一条 `ServerEvent.error`（与真实 router 对未知行的处理一致），不静默吞。
- mock 对未脚本化的 `history read`（未知 threadId）：回 `{kind:read,value:{turns:[]}}` 空会话，不崩。
- preview 模式在窗口标题或日志打一行 `[AgentDeck] preview mode: mock daemon`，便于识别当前不是真实链路。

## 测试和验收标准

### 自动化

- `Tests/AgentDeckTests/MockDaemonTransportTests.swift`：
  - 发 `history(.list)` → 收到合法 `HistoryResponse.list`，条目非空且含预期项目。
  - 发 `sessionStart` → 依次收到 `sessionStarted` 与 `turnComplete`（用 expectation 等异步帧）。
  - 发未知行 → 收到 `ServerEvent.error`。
- 现有 `swift test` 全绿，无回归。

### 手动

- `swift run AgentDeck -- --preview`：启动后侧栏自动填充 mock 项目/会话；点击「把登录模块拆分为独立 service」渲染出命令块 + diff 卡 + 运行中项；右上环境面板显示 `+128 -34 / 3 文件 / 分支 main / 提交 a1b2c3d`；在输入框发送一条 prompt，界面出现乐观插入并流式渲染 mock 回复。目视对照图1。

### 验收

- 前端渲染路径无 `if preview` 分支；mock 全部收敛在 `Preview/` 两个文件 + 注入点。
- 非 preview 启动行为完全不变。

实现已落地
