# AgentDeck

**Codex 写代码，AgentDeck 组织工作。**

AgentDeck 是一个 macOS 原生的本地 Coding Agent 工作台，通过官方
[Codex app-server](https://developers.openai.com/codex/app-server) 协议连接
OpenAI Codex，让你在原生界面里实时看到 agent 在做什么、并掌控它。

> 状态：v0.1 开发中。这是一个开源 / 学习项目。

## 这是什么

每次你让 Codex 干活，AgentDeck 在一个 macOS 原生窗口里流式展示它的
工作过程 —— 它在想什么（reasoning）、跑了什么命令（shell）、改了哪些
文件（file-edit）—— 并在它要执行有风险的操作前让你 approve / deny。

AgentDeck **不是** IDE，**不是** Codex Desktop 替代品，**不是**通用多
agent 聊天界面。它是本地代码项目的 agent 工作台。

## v0.1 范围

v0.1 验收两件事（"双拍"）：

1. **原生流式会话**：macOS 原生界面，流式渲染 Codex 的
   reasoning / shell / file-edit item，带交互式 approve / deny。这是
   "为什么必须 macOS 原生"的证明。
2. **agent-中立的适配器边界**：daemon 内翻译，IPC 协议本身就是中立的
   `AgentItem`。Swift 永远不知道 Codex 存在。这是社区能平行贡献
   Claude Code / SSH / 云端 adapter 的地基 —— 官方产品结构上做不了
   agent 中立。

稳定架构边界见 [ARCHITECTURE.md](ARCHITECTURE.md)。完整设计与三层评审记录见
[docs/plans/](docs/plans/)；文档导航见 [docs/index.md](docs/index.md)。

## 架构

```
AgentDeck.app  (macOS, SwiftUI + AppKit)
      │  stdio JSONL IPC（中立 AgentItem，无 Codex 字样）
      ▼
agentdeckd  (Rust daemon)
      │  ├── async runtime hub（stdin main loop + stdout writer）
      │  ├── turn/history workers（带 sessionId/threadId 路由）
      │  ├── CodexAdapter（Codex item → 中立 AgentItem 翻译）
      │  └── 进程组拥有 app-server，退出连带 kill
      ▼
codex app-server  (子进程, JSON-RPC over stdio)
```

中立边界的物理位置 = IPC 协议本身。可验证事实：IPC schema 里不出现
任何 Codex 字样。

AgentDeck 使用一个 `agentdeckd` 作为 runtime hub。daemon 的 stdin 主循环不被
单个 turn 阻塞；每个后台 turn 由独立 worker 持有 turn 级 adapter，turn 结束即
释放，所有 worker 通过统一 stdout writer 输出带 `sessionId/threadId` 的中立事件。历史请求按 request id
分发 reply，不和 streaming `agentItem` 抢 reader。RuntimeHub 会阻止同一
`sessionId` 同时启动多个 turn，并限制并发 history worker；超限时返回明确
busy error，而不是继续无界创建线程。需要用户确认的高风险动作会由 Codex
app-server 的 server request 映射成中立 `actionRequest`，Swift 只显示
`title/detail/actionKind` 并回写 `actionDecision`；daemon 再把 approve / deny
翻译回 app-server response。

流式性能边界：daemon 不合并 Codex delta，而是忠实转发中立
`agentItem`；Swift 端的 `SessionModel` 按约 30fps 合并待渲染 delta，并把
message / reasoning / shell / diff 长文本交给 AppKit `NSTextView` +
`NSTextStorage` 增量追加，避免 SwiftUI `Text` 在 token 流中反复测量整段文本。

## 历史会话

AgentDeck 可以通过 Codex app-server 扫描 Codex 已持久化的历史
thread，并按项目 `cwd` 分组显示。点击历史 thread 后，AgentDeck 会读取
`thread/read(includeTurns: true)` 返回的 turns/items，并用同一套中立
`AgentItem` stream 回放到右侧。

历史回放会保留 Codex app-server schema 里的已知 `ThreadItem`：用户消息
（含图片、skill、mention 引用）、模型回复、reasoning 摘要、计划、hook
prompt、shell（含 cwd、状态、耗时、来源、解析出的 command actions）、
多文件变更、MCP / dynamic tool call、协作子代理调用、web search、图片查看 /
生成、review mode 事件和 context compaction。未知块仍以可见的 `raw` 记录
出现，避免静默丢失。

图片查看 / 生成事件会优先使用中立 `AgentItem` 的 `savedPath`，回退到 `path`，
在会话流里直接显示本地图片预览，同时保留路径 metadata 便于定位原文件。

继续历史会话时，AgentDeck 走 `thread/resume(threadId)` 后再执行
`turn/start`，因此新 prompt 会进入原有 Codex 上下文，而不是创建新
thread。历史详情读取在后台完成，点击后先标记正在打开，详情返回后再回放到
右侧，并记录 read / apply 耗时，便于继续定位慢点。大段 shell output 和
diff 默认只保留摘要与原文，展开时才填充 TextKit buffer，避免大历史
thread 阻塞主界面。AgentDeck 只做轻量索引、回放和管理入口；Codex
持久化历史仍是上下文真相源。

历史详情回放会进入 Swift 端 `WorkbenchModel` 中独立的 `ThreadRuntimeModel`。
打开历史 thread 只切换当前选中的 runtime 和右侧视图，不会把其他正在运行的
runtime 标记为 ready 或停止其后台事件处理。runtime 自身按约 30fps 刷新
streaming delta，避免视图切到 runtime 后出现长时间不刷新的流式文本。
普通新会话也会先创建 live runtime；daemon 返回真实 `threadId` 后写回该
runtime，后续 prompt 继续走同一个 thread，而不是在 UI 上伪装成连续对话。
提交 prompt 时，正在运行、启动中或等待 approval 的 runtime 只会排入自己的
队列；对应 runtime 收到 `turnComplete` 后才 drain 自己的下一条 prompt，不会
把队列发送到当前选中的其他 history/runtime。
当 runtime 进入 `waitingApproval` 时，会话流里显示最小 approve / deny 控件。
第一版支持命令执行、文件变更和额外权限三类请求；不暴露持久化策略按钮，
也不让 Swift 解析 Codex 原始 JSON。
左侧 History 面板不再单独显示 runtime selector。已在当前窗口缓存的历史
thread 会在对应历史行内显示小状态点：普通缓存态保持低调，运行中或启动中显示
系统 accent，等待审批显示橙色，失败显示红色；如果后台 runtime 有未读事件，
对应历史行上显示一个更醒目的小彩色点。点击历史行仍只切换右侧视图，不会中断
对应后台会话。

第一版管理动作保持低风险：刷新、搜索、重命名和归档。AgentDeck 不读取、
保存或转发 Codex token。

应用窗口打开时会自动刷新一次历史列表；之后可以通过左侧 History 面板的刷新
按钮手动重新扫描。History 列表中的每个 thread 都是整行块级点击目标，
每个项目文件夹标题右侧提供加号按钮，可在对应 `cwd` 下开启新的空白会话；
新 thread 仍等用户发送第一条 prompt 后才创建。标题前会显示 agent 来源小图标；当前历史会话来自 Codex，因此显示 Codex
透明背景图标。该 SVG 来自 LobeHub Icons 的 `codex.svg`，并在本地 bundle 中使用。
列表项同时提供 hover、正在打开和已选中状态，避免只点标题文字才有响应。
打开或切换历史会话时，右侧会话视图区会重置滚动身份并从顶部显示，避免沿用
上一个长会话的滚动位置导致短会话首屏空白。
右侧会话区提供无背板的竖排轮次导航点：每个点对应一条用户消息，hover 时点位会临时放大并显示摘要，
放大造成的额外间距会向上下两侧累积传播，让整条 rail 产生类似 Dock 的整体拉伸效果。
点击可跳到该轮；底部“最新”点可跳到会话末尾。导航点固定间距并整体居中，
点数超过高度时 rail 会跟随当前轮次自动揭示点位；鼠标停在导航点区域滚轮可连续按轮次快速跳转，不会先停下来只滚 rail，
触达顶部或底部后继续滚动不会循环。用户手动滚动右侧会话区时，高亮点会被动跟随当前阅读位置。
用户主动发送新消息后，右侧会话区会自动滚到最新消息位置，
以便立即看到自己的输入和随后到达的 agent 输出。

## 构建

前置：Rust（`cargo`）、Swift 6 / Xcode（macOS 15+）、`codex` CLI 已
`codex login`（AgentDeck 不碰 / 不存 / 不转发任何 token —— 沿用 codex
已有认证）。

```bash
# Rust daemon
cargo build --release            # 产出 target/release/agentdeckd

# Swift app
swift build -c release           # 产出 .build/release/AgentDeck
```

运行（Swift app 会自动 spawn 同目录或 PATH 上的 agentdeckd）：

```bash
swift run AgentDeck               # 本地 debug 构建默认使用 dev profile
swift run AgentDeck -- --selfcheck  # 无窗口自检: IPC lifecycle + logging/redaction probe
swift run AgentDeck -- --diagnostics-report --json  # 输出机器可读诊断报告
```

Profile（用于拆分稳定工作实例和开发调试实例）：

```bash
swift run AgentDeck -- --profile stable
swift run AgentDeck -- --profile dev
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

- release 构建未显式传 `--profile` 时默认使用 `stable`，写入
  `~/Library/Application Support/AgentDeck/`。
- SwiftPM/debug 构建未显式传 `--profile` 时默认使用 `dev`，适合本地迭代。
- `dev` 写入 `~/Library/Application Support/AgentDeck-Dev/`，窗口标题显示
  `AgentDeck Dev`。
- profile 只隔离 AgentDeck 管理的数据，不隔离 Codex 登录状态或 Codex
  app-server 历史。

测试：

```bash
cargo test        # daemon: ipc/codex/record/diag/report(含 fixture 回放)
swift test        # app: 中立协议 + 分行成帧 + headless 请求编码
```

### 协议

`protocol/` 是从官方 `codex app-server generate-json-schema` 生成的
协议 schema（非逆向）。`protocol/SPIKE_FINDINGS.md` 记录实测的 wire
framing（逐行 JSONL）。codex 版本固定在 `protocol/CODEX_VERSION.txt`。

### 本地数据（AgentDeck 管理，绝不进你的 git）

- run record：`~/Library/Application Support/AgentDeck/runs/*.jsonl`
  - 每次 turn 的中立 `AgentItem` 留痕，可按 `runId` 回放和排查。
- diagnostic log：`~/Library/Application Support/AgentDeck/diagnostic.log`
  - 结构化 JSONL，记录进程、IPC、adapter、run record 写入和自检异常。
  - Codex app-server 断连时会附带其 stderr 尾部摘要，便于定位启动失败或崩溃根因。
- dev profile 数据：`~/Library/Application Support/AgentDeck-Dev/`
  - 用于快速迭代和调试，避免污染 stable 的工作记录。

Agent 自查流程见 [docs/AGENT_DIAGNOSTICS.md](docs/AGENT_DIAGNOSTICS.md)。
质量门禁和文档结构检查见 [docs/QUALITY.md](docs/QUALITY.md)。

写入前做 best-effort 密钥脱敏。写失败不阻塞会话，但会在界面可见
警告（绝不静默）。`AGENTDECK_DATA_DIR` 只用于测试/诊断时覆盖数据目录，
不是普通用户配置；它优先于 `--profile` / `AGENTDECK_PROFILE`。

### 回滚

未签名 `.app`：删除应用即可。GitHub Releases 保留旧版本 zip。无
数据库迁移、无 feature flag。首次打开需在系统设置允许（Gatekeeper）。

## 贡献

AgentDeck 的核心是那条 agent-中立适配器接口。今天它只有一个
`CodexAdapter`；社区可以平行贡献新 adapter（Claude Code、SSH 远程、
云端 agent）。贡献指南待补（adapter 接口稳定后）。

## License

MIT — 见 [LICENSE](LICENSE)。
