# AgentDeck

**Codex 写代码，Claude Code 写代码，AgentDeck 是工作台。**

AgentDeck 是 Coding Agent 的统一原生桌面客户端。它把 OpenAI Codex 和
Anthropic Claude Code 作为**绝对一等公民**，两家的功能、概念和原始语义
都被完整保留——AgentDeck 不强行统一它们，而是为它们提供同一个工作台。

> 状态：v0.2 开发中（统一壳）。这是一个开源 / 学习项目。

## 这是什么

每次你让 Codex 或 Claude Code 干活，AgentDeck 在一个 macOS 原生窗口里
流式展示它的工作过程 —— 它在想什么（reasoning）、跑了什么命令（shell）、
改了哪些文件（file-edit）—— 并在它要执行有风险的操作前让你 approve / deny。
两家 agent 的 vendor 原词（如 Codex approval policy、CC permission mode）
在 UI 上保留原始语义，不强译为中立词。

AgentDeck **不是** IDE，**不是** Codex Desktop 替代品，**不是**通用多
agent 聊天界面。它是 Coding Agent 的工作台、控制台、管理面。

## v0.2 范围（统一壳）

v0.2 在 macOS AppKit 上端到端验证「统一壳」架构：

1. **IPC 协议 v2**：两层结构（事件主干中立 + Vendor 控件命名空间）、
   agent capabilities 握手、Transport trait 预留。
2. **ClaudeCodeAdapter MVP**：`claude` CLI 子进程接入，CC 特色能力
   （permission mode、hooks、output-style 等）完整可用。
3. **UI 整体范式统一**：`CapabilityRouter` 按 `SessionCapabilities` 路由
   vendor SubView，禁止 UI 硬编码 `if agentKind == .codex` 分支。
4. **跨 agent 历史聚合**：侧栏默认同时显示 Codex 和 CC 的历史 thread，
   不提供 agent 切换或过滤入口。

稳定架构边界见 [ARCHITECTURE.md](ARCHITECTURE.md)。完整设计见
[docs/plans/2026-06-30-unified-shell-v02-design.md](docs/plans/2026-06-30-unified-shell-v02-design.md)；
文档导航见 [docs/index.md](docs/index.md)。

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│  AgentDeck.app (macOS, AppKit)                                  │
│                                                                 │
│  SessionViewController                                          │
│   ├─ StatusBarView（当前 agentKind + auth）                      │
│   ├─ HistorySidebarVC（跨 agent 合并列表）                         │
│   ├─ AgentControlBar（capability 路由 → vendor SubView）          │
│   ├─ ConversationVC（虚拟化 NSTableView，中立 AgentItem）          │
│   └─ ApprovalCardView（主干壳 + vendor 高级区 SubView）            │
│                                                                 │
│  CapabilityRouter  ← UI 渲染按 SessionCapabilities 派发          │
│  ObservationBinder ← @Observable 模型绑定                        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Layer A 中立事件主干（AgentItem）
                           │ Layer B Vendor 控件命名空间
                           │ Layer C 启动配置（SessionStart）
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  agentdeckd (Rust daemon)                                       │
│  RuntimeHub（stdin loop, stdout writer, per-session lock）       │
│       │                                                         │
│       └─→ AgentRouter（按 sessionId.agentKind 路由）              │
│            ├─ CodexAdapter      (capabilities = {...})          │
│            └─ ClaudeCodeAdapter (capabilities = {...})          │
│                                                                 │
│  共享层：record / diag / profile / capabilities registry         │
└─────────────────────────────────────────────────────────────────┘
   ▼ spawn (turn-scoped)                  ▼ spawn (turn-scoped)
codex app-server                       claude CLI (--print --stream-json)

agentdeck-cli  (参考客户端 / 门控 E2E 驱动，不在 GUI 实时通路上)
      │  通过 stdio JSONL 与 agentdeckd 交互（Transport trait）
      ▼
agentdeckd
```

IPC 协议两层：Layer A 事件主干严禁出现 vendor 字样（N1 不变量守护）；
Layer B Vendor 控件命名空间允许 vendor 前缀但类型化（禁 `serde_json::Value`
透传，N4 守护）。UI 通过 `CapabilityRouter` 消费 `SessionCapabilities`
选择渲染路径，不得硬编码 `if agentKind == .codex` 分支（N2 守护）。

目标架构由每个 macOS 登录用户唯一的 stable `agentdeckd` 作为 runtime hub。P3.1
已经建立固定 namespace、进程锁与 StorageKEK 启动边界；当前 GUI/CLI 仍处于 stdio
过渡期，每个调用方只会显式启动一个 `--ephemeral --no-remote --profile dev` 子进程，
多个客户端共享同一 daemon 要到 P3.9 的 UDS cutover 后才成立。daemon 的 stdin 主循环不被
单个 turn 阻塞；每个后台 turn 由独立 worker 持有 turn 级 adapter，turn 结束即
释放，所有 worker 通过统一 stdout writer 输出带 `sessionId/threadId/agentKind`
的中立事件。RuntimeHub 会阻止同一 `sessionId` 同时启动多个 turn；超限时
返回明确 busy error。`AgentRouter` 按 session 创建时绑定的 `agentKind` 路由
到对应 adapter，`agentKind` 一旦绑定不可变（K2）。

流式性能边界：Swift 端的 `SessionModel` 按约 30fps 合并待渲染 delta，并把
message / reasoning / shell / diff 长文本交给 AppKit `NSTextView` +
`NSTextStorage` 增量追加；会话流由虚拟化 NSTableView 按需渲染可见行，
避免在 token 流中反复布局整个视图树。

## 历史会话（跨 agent）

v0.2 起历史侧栏聚合 **Codex + Claude Code** 两家历史 thread，左侧不区分
agent 来源、不提供 agent 切换或过滤入口，默认按项目和更新时间合并展示。
`agentKind` 仍保留在数据模型中，用于读取、继续、归档和重命名时路由到正确
adapter。

**Codex 历史**：v0.2 仍是显式 stub，`history list --agent codex` 返回空列表，
`history read --agent codex` 返回 `codex-history-read-not-implemented`。Codex
app-server 的 `thread/list` / `thread/read(includeTurns: true)` 接入留到 v0.3；
文档和 UI 不应把 Codex 历史回放说成已接通。

**Claude Code 历史**：通过 `claude agents --json` 及直读
`~/.claude/projects/<encoded_cwd>/<id>.jsonl` 获取，事实唯一来源在 CC 原生
接口（N8 不变量：AgentDeck 不建 `cc-meta/` 目录）。Archive 走 `claude rm`
（软删，`--resume` 仍能找回）；Rename 走 `claude --resume <id> --name`；
Unarchive 等同 no-op（CC 不区分 unarchive）。历史列表默认返回最新 500 条；
daemon 先按 `.jsonl` mtime 排序并截断，再只为最终返回条目扫描标题，避免大型
`~/.claude/projects` 历史库拖慢左侧侧栏刷新。`claude-mem` observer 会话属于
后台记忆工具噪声：project dir 匹配 `.claude-mem/observer-sessions`，或开头为
`Hello memory agent` / `You are a Claude-Mem` 的会话，会在 history list 阶段过滤，
不进入 CLI 输出或左侧侧栏。

继续历史会话时，Codex 走 `thread/resume(threadId)`；CC 走
`claude --resume <id>`。历史读取操作必须带 `agent_kind`（两家持久化结构不同）。

历史详情读取在后台完成，点击后先标记正在打开，详情返回后再回放到右侧。大段
shell output 和 diff 展开时才填充 TextKit buffer，避免大历史 thread 阻塞主界面。

历史详情回放会进入 Swift 端 `WorkbenchModel` 中独立的 `ThreadRuntimeModel`。
打开历史 thread 只切换当前选中的 runtime 和右侧视图，不会把其他正在运行的
runtime 标记为 ready 或停止其后台事件处理。runtime 自身按约 30fps 刷新
streaming delta，避免视图切到 runtime 后出现长时间不刷新的流式文本。
普通新会话也会先创建 live runtime，并立即合并进左侧历史侧栏，避免当前会话
只能在右侧可见。daemon 返回真实 `sessionId` / `threadId` 后写回该 runtime，
后续 prompt 继续走同一个 thread，而不是在 UI 上伪装成连续对话。
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
新 thread 仍等用户发送第一条 prompt 后才创建。
列表项同时提供 hover、正在打开和已选中状态，避免只点标题文字才有响应。
History 面板的分组结果在历史线程列表更新时一次性计算，滚动列表时不会反复排序分组。
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

# 参考客户端 CLI
cargo build --release -p agentdeck-cli  # 产出 target/release/agentdeck

# Swift app
swift build -c release           # 产出 .build/release/AgentDeck
```

## iOS Companion（fixture 驱动，先前端后链路）

AgentDeck Mobile 是与 macOS 主客户端配套的 iPhone companion，用协议对齐的 fixture 回放代替真实链路，在模拟器上完整跑通 R3 companion 界面骨架，接 Relay 时 UI 层零迁移。

`ios/` 目录结构：

```
ios/
├── project.yml                  # XcodeGen 声明式工程（xcodeproj 不入库）
├── AgentDeckMobile/
│   ├── App/                     # AppDelegate / SceneDelegate / 导航
│   ├── Screens/                 # 各屏 VC + @Observable view model
│   ├── DataSource/              # MobileSessionSource 协议 + FixtureSessionSource
│   ├── DesignTokens.swift       # 生成物：UIKit 版 token（禁止手改）
│   └── Fixtures/                # 协议语义对齐的 JSON fixture（见 ios/Fixtures/）
└── AgentDeckMobileTests/
```

前置依赖：Xcode 16+（iOS 17 模拟器），`brew install xcodegen`。

```bash
# iOS 工程生成 + 构建 + 单测（fixture 驱动，无真实链路）
cd ios && xcodegen generate && \
  xcodebuild -project AgentDeckMobile.xcodeproj -scheme AgentDeckMobile \
    -destination 'platform=iOS Simulator,name=iPhone 17' test
```

iOS 端唯一数据入口是 `MobileSessionSource` 协议（本期实现为 `FixtureSessionSource`，bundle 内 JSON 回放）；杀 app 重置 fixture 状态，不依赖 daemon 或网络。

## Relay Companion MVP 实施状态（P2.10 完成，P3.1 进行中）

Relay production binary 已原子切换到 **Relay v2**。公开数据面只接受
`/v2/connect`、`/v2/pair` 与 enrollment 所需的 `POST /v2/machine-enroll`；
Relay v1 的协议、server、client、daemon bridge 与测试源码已经物理删除。
`/v1/connect` 只保留无状态 HTTP 426 tombstone：不升级 WebSocket，不进入鉴权、
Core 或 Store，也不存在 v1 兼容 feature 或自动降级路径。R0/R1 文档仅记录历史
探索与迁移依据，不代表当前可执行接口。

生产部署只使用 Direct TLS/WSS。证书、hostname/CA 与配置 SPKI pin 必须在发送
enrollment code、MachineRoot 或任何密文前全部验证通过；loopback 明文和 loopback
proxy 都需要显式选择，只用于受控开发。公开 listener 只接收 canonical binary v2
frame，并对连接数、握手/HTTP upgrade deadline、header、单帧/消息、队列与 ingress
bytes 分层设硬上界。SQLite 由单 Store actor 串行写入，仅保存随机 route、公开
trust material、单调元数据和 opaque sealed bytes；PairRoute、challenge、在线 writer
与业务目录不落盘。授权变更、replay、quota、disk-low、Store fault 与 shutdown 都有
fail-closed 门禁，慢连接只隔离自身。

Relay host 的 machine 管理面只存在于同 UID、0600 的本机 JSONL admin UDS；
`machine-enroll create`、`machine inventory`、fingerprint-bound `machine readback` 与
`machine purge` 已可用。MachineRoot 丢失不做恢复：完成带 fingerprint 的 purge/readback
后重新 enrollment、重新配对。具体配置与命令见
[`docs/RELAY_RUNBOOK.md`](docs/RELAY_RUNBOOK.md)。

`agentdeck remote synthetic --bundle FILE` 会连接一个真实、外部运行的 Direct TLS
Relay，严格校验 CA/hostname/SPKI，并以临时 machine/device key 完成 enrollment、fresh
challenge 鉴权、InstallGrant、register/publish/subscribe replay、Send/Reply、signed revoke
以及终态重连验证。测试同时扫描 SQLite/outer wire，证明应用 sentinel 只以真实 AEAD 密文
存在。这个命令不会建立持久配对；P4 完成前，`remote pair/machines/sessions/watch/send/...`
统一返回 typed `remote.persistent.unsupported`。`agentdeckd` 仍由 no-net guard 保证不含
网络依赖，因此 P2.10 不能被描述为 daemon/iOS Companion 已经接通。

P2.10 的完整安全/故障门禁覆盖真实 Direct TLS/SPKI 链路、跨重启逐字节 replay、gap、
quota、disk-low、fault injection、shutdown、撤销/退役和多 sentinel 持久化扫描。统一验证入口：

```bash
bash scripts/verify-relay-companion-mvp.sh p2
```

旧 Relay v1 开发状态不会被当前 production binary 读取、迁移、删除或用于拨号。
CLI 对旧 credential marker 只做 `symlink_metadata` 存在性探测；存在、悬空 symlink
或无法安全判定时都返回 `remote.v1.reset_required`。若要清理，必须先停止旧 Relay，
再显式运行受控 reset：

```bash
bash scripts/reset-relay-v1-dev-state.sh \
  --storage /absolute/path/to/relay.db \
  --credentials /absolute/path/to/relay/dev.credentials.json \
  --confirm DELETE-RELAY-V1-DEV-STATE
```

只有该 reset 脚本拥有删除权限。它在第一次 unlink 前一次性验证四个精确删除路径、Relay v1 schema、credential
canonical Base64（解码恰好 32 bytes）、DB 行关联和 unlink preflight（父目录权限、
macOS immutable flags）；删除前任一 validation/preflight 失败都零删除。preflight
之后 OS unlink 仍失败时可能部分删除：脚本非零退出、列出全部 remaining exact
paths、不打印成功、不承诺 rollback，需人工清理残留后重新配对。成功时只删除
DB、精确 `-wal`、`-shm` 和指定 credential，不使用 glob。此开发 reset 没有恢复
路径，后续使用前必须重新配对。脚本需要 `awk`、`sqlite3`、`jq`、`openssl`、
`realpath` 和 `stat`。

### P3.1 singleton namespace / StorageKEK 当前边界

stable daemon 的资源名不可覆盖：data root 固定为当前 EUID 通过 `getpwuid_r`
取得的 OS account home 下 `Library/Application Support/AgentDeck`，其内固定使用
`runtime.db`、`agentdeckd.sock` 与 `agentdeckd.lock`。启动不信任 `HOME`、
`AGENTDECK_DATA_DIR` 或运行时注入的 Keychain access group；`--data-dir` 只保留给
不启动 daemon 的 diagnostics one-shot。开发实例必须同时显式传
`--ephemeral --no-remote`，`--profile dev` 单独使用也会 fail-close。

namespace 以 0700 原子建立。固定 stable 目录若来自旧版本，只允许权限精确为 0755
且是当前 UID 拥有的真实目录时，经 `O_NOFOLLOW` 打开的 directory fd 收紧到 0700；
0775、0777、01755 及 ephemeral 宽权限目录直接拒绝。singleton lock 只通过该 dirfd 的 `openat`
创建/打开，并在 `flock` 前后复核目录和 lock 的 owner、mode、nlink、dev/ino，避免
路径替换或 symlink/hardlink 绕过。

stable `storage-kek.v1` 只允许存入 macOS Data Protection Keychain。access group
必须是 release helper entitlement 中真实展开的
`<TeamIdentifier>.com.agentdeck.agentdeckd.stable`，且在编译时注入；backend 或
entitlement 不可用时立即失败，没有 memory 或明文 key 文件回退。item 使用 protected、
non-synchronizable、`AccessibleAfterFirstUnlockThisDeviceOnly` 且不要求 user presence。
只有完全 fresh、DB/WAL/SHM 都不存在或为空的 namespace 才能生成一次 32-byte
StorageKEK；写入后必须立即读回并逐字节一致。既有 Runtime artifact 缺 key、长度错误
或读回不一致都 fail-close；secret 的 Debug 脱敏并在 Drop 时清零。

当前自动测试已覆盖 namespace 18/18、binary startup 4/4、StorageKEK 14 PASS，另有
1 个真实签名 Keychain `set → load → delete` roundtrip 保持 ignored gate。该真实 gate
**尚未通过**：本机没有匹配 access group 的 provisioning profile；Apple Development
和本地 self-signed helper 虽然都通过 `codesign --verify`，启动仍被 AMFI 以 exit 137
终止。因此 P3.1/P3 还不能声明完成，必须在具备匹配 provisioning/entitlement 的已签名
helper 上补齐证据。

### P3.2 Runtime journal 当前边界

daemon 的 canonical Runtime state 现在由单一 blocking worker 独占 `runtime.db` connection。
worker 使用 `shutdown > safety > read > normal` 四级裁决；三条业务 lane 分别有 count 上界，
normal/safety 另有 256 MiB retained-allocation 上界。shutdown 是单槽状态机，先 interrupt
当前 SQLite 操作，再在下一 dequeue 边界关闭并拒绝剩余队列；connection、行密钥和 path
lease 全部释放后才返回。

`conversationId` 与 `adapterStateKey` 在调用 store 前由 daemon 生成并随
`NewConversation` 持久化。相同 ID/descriptor 的重试返回同一 catalog record；不同内容
返回 typed conflict。command/event/catalog high-water 使用完整 u64 的固定 20 位文本，
首次为 0、跨重启单调、`u64::MAX` fail-close。command idempotency 绑定
conversation + stable principal owner + key；本地 owner 不含临时 connection，远程 owner
不含可续期 grant serial。

Accepted、Started + ExecutionIntent + started event、ExecutionFence、release authorization、
terminal state + event 都以事务为边界。任何 before-COMMIT failure 完整回滚；任何
真实 COMMIT 失败若无法确认 rollback、以及任何 after-COMMIT response loss，都返回
`CommitOutcomeUnknown`；完全相同的重试只读回原 record。
同一 conversation 在 store 层最多存在一个 Started，completion 必须先存在 matching fence
且 `releaseAuthorizedAt` 已提交。24 小时未启动的
Accepted command 由可注入 daemon clock 在 accept/start/recovery 前 sweep 为 Expired，并写入
同 conversation 的 canonical expiry event；idempotency ledger 至少保留 30 天。

schema v1 仍严格只有七张表。descriptor、owner/idempotency key、prompt、execution nonce/
intent、fence payload、event 与 terminal result 都使用 StorageKEK 包装的行密钥加密；blind
token 会从已认证明文重算。command/conversation/event 的 canonical 明文元数据另有行 MAC，
`runtime_meta` 保存经过 MAC 的 queue/safety ledger；open 与 recovery begin 都以常量峰值内存
流式验证 conversation descriptor 与 command/execution/event 密文、全部 canonical 元数据、
逐 conversation command/event HWM、审计 linkage，以及 conversation/command/event/intent/fence
总数与 queue/safety 计数。DB/WAL/SHM 换列、删空 catalog row、删整组 terminal audit 或伪造
reserve 都会 fail-close。唯一故意不加密的是 root 丢失时仍需定位旧 route/fingerprint 的非秘密
`machine_enrollment_receipts` rescue index；它不是授权证据，P4 purge 必须独立验证 Relay/admin
签名回执，不能仅凭该 locator 删除远端状态。

恢复不再返回全库 `RecoveryState`。`begin_recovery_scan` 先完成 integrity validation 与一次
expiry sweep，再冻结 authenticated catalog high-water；`load_recovery_page` 使用 opaque
keyset cursor，每页恰好一个 conversation（最多 32 Accepted + 一个 Started），retained-memory
硬上界 80 MiB。丢失的 begin/page/finish 回执都可用完全相同 token 精确重试。扫描期间只允许
inspect/shutdown，全部 durable mutation 返回 `daemon.runtime.recovering`；只有终页累计计数与
冻结 ledger 一致、finish 再次完成全库 integrity readback 且 RuntimeCore 显式确认后才恢复写入。
P3.4 必须逐页消费，禁止重新 collect
成全库 Vec 或在完成全扫描前启动 Accepted。

普通 create/accept/start 写入按 main DB + WAL + SHM observed footprint、保守 projected
growth、SQLite `max_page_count=2 GiB/page_size` 与文件系统 reserve
`max(512 MiB, 5%)` 做准入，并为 Accepted expiry 及 Started 的 fence/release/最大 terminal
尾预留空间。SQLite `wal_autocheckpoint=0` 且启用/读回 persistent WAL，所有 checkpoint 只能
走显式预算路径；执行 `PASSIVE` 前还按 main+WAL 同时存在的 copy peak 预检。接近水位或
WAL ≥64 MiB 时只执行 bounded `PASSIVE` checkpoint；reader 阻塞且仍接近水位时停止普通写。
非 DiskLow 越界后 latch `SafetyOnly`，DiskLow 可在空间恢复后重试；inspect 仍可继续，
fence、release、terminal
与 rescue 只有在剩余 safety tail 再次校验通过时才写入。标准 SQLite 无 custom quota VFS，
因此这里不声称 active WAL 在任意瞬间绝不短暂超冲 2 GiB；precheck、有界 checkpoint、
逐次 safety 校验与写后读回是当前 MVP 的 fail-closed 边界。

行 MAC 能检测局部换列/删除/篡改，但“把 main+WAL 整体回滚到更早且内部自洽的有效快照”必须
由 P4 的 Keychain `CounterGuard` / generation high-water 绑定后才能检测。该门禁属于 P4/P6，
P3.2 不能宣称已防住整库历史回滚。

本节描述已经验证的持久化组件契约，不表示当前 stdio `RuntimeHub` 已改走该 store。
P3.3 先接 adapter 私有映射，P3.4 再由 `RuntimeCore` 把真实本地/远程请求接入 journal；在此之前
不能把 store unit/integration tests 当成 Companion 端到端完成证据。

## agentdeck CLI（参考客户端 / E2E 驱动）

`agentdeck` 是一个 Rust 二进制参考客户端，**不在 Swift GUI 的实时通路上**。Swift app 仍直接通过 stdio JSONL 与 daemon 通信；`agentdeck` 用于脚本化调用、本地验证以及门控 E2E 测试驱动。

### 全局标志

| 标志 | 说明 |
| --- | --- |
| `--profile stable\|dev` | 保留给 CLI/diagnostics 的 profile 选择；P3.1 stdio 子进程固定显式 ephemeral dev，不据此进入 stable namespace |
| `--data-dir <path>` | diagnostics one-shot 的旧数据目录读取；不能覆盖 daemon namespace |
| `--pretty` | 人读格式输出（E2E 不依赖此标志） |

### 子命令目录

```bash
agentdeck ping                          # 往返自检（ping → pong）
agentdeck selfcheck                     # IPC 生命周期 + logging 自检
agentdeck diagnostics report            # 输出机器可读诊断报告（JSON）
agentdeck protocol schema               # 打印 IPC 协议 JSON Schema
agentdeck protocol version              # 打印协议版本号

# v0.2 新增：agent 子命令组
agentdeck agent list                           # 列出可用 adapter
agentdeck agent capabilities --agent <kind>    # 列某 adapter capabilities（JSON）

# session 子命令（v0.2 起须带 --agent）
agentdeck session run --agent codex \
  --cwd <path> --prompt "..."           # Codex 新会话（--cwd 必填）
agentdeck session run --agent claude-code \
  --cwd <path> --prompt "..."           # Claude Code 新会话
agentdeck session continue \
  --agent <kind> --cwd <path> \
  --thread-id <id> --prompt "..."       # 继续历史 thread

# history 子命令（v0.2 起跨 agent；--agent 可选过滤）
agentdeck history list                         # 跨 agent 列出历史 threads（默认限流）
agentdeck history list --agent claude-code --limit 200  # 仅 CC 历史
agentdeck history read <id> --agent <kind>     # 读取历史 thread（必须带 --agent）
agentdeck history archive <id> --agent <kind>  # 归档 thread
agentdeck history unarchive <id> --agent <kind># 取消归档
agentdeck history rename <id> --agent <kind> <title>  # 重命名 thread
```

`session run` 的 Codex 选项使用 `--approval on-request|never|always`、`--sandbox read-only|workspace-write|full-access`、`--reasoning-effort minimal|low|medium|high`；Claude Code 选项使用 `--permission default|accept-edits|plan|auto|dont-ask|bypass-permissions`。`--agent` 取值 `codex` 或 `claude-code`（wire 值为 `claude_code`）。

### 输出与退出码契约

所有输出为稳定 JSON / JSONL，机器可解析。退出码：

| 码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 2 | 用法错误（参数缺失等） |
| 3 | 协议错误（类型不符或意外消息） |
| 4 | 传输错误（daemon 未启动、连接失败） |
| 5 | 会话或自检失败 |

### 协议 schema / version 用法示例

```bash
# 打印当前协议 JSON Schema
agentdeck protocol schema

# 核对快照是否与代码同步
cargo run -q -p agentdeck-cli -- protocol schema \
  | diff - protocol/agentdeck/agentdeck-protocol.schema.json \
  && echo "schema in sync"

# 打印协议版本号
agentdeck protocol version
```

运行（Swift app 会自动 spawn 同目录或 PATH 上的 agentdeckd）：

```bash
./script/build_and_run.sh        # 构建 SwiftPM 产物，临时打包 dist/AgentDeck.app 并启动
./script/build_and_run.sh --verify  # 启动后确认 AgentDeck 进程存在
swift run AgentDeck               # 本地 debug 构建默认使用 dev profile
swift run AgentDeck -- --selfcheck  # 无窗口自检: IPC lifecycle + logging/redaction probe
swift run AgentDeck -- --diagnostics-report --json  # 输出机器可读诊断报告
swift run AgentDeck -- --preview  # 前端 mock 预览，不连真实 daemon

# 直接验证 P3.1 daemon 启动边界（unsigned 开发构建只能使用完整 ephemeral pair）
cargo run -p agentdeckd -- --ephemeral --no-remote --profile dev --selfcheck
```

macOS 前端使用纯 AppKit。当前主窗口外壳对齐 Codex Desktop：透明标题栏、
全高左侧历史/项目侧栏、右侧 thread header、Codex 风格空态 composer、
会话态悬浮 composer 和右侧环境信息面板。外观层仍保持 v0.2 统一壳边界：
vendor 控件由 `CapabilityRouter` 装配，daemon / IPC / history 模型不因视觉同步而改动。

Profile（P3.1 过渡行为）：

```bash
swift run AgentDeck -- --profile stable
swift run AgentDeck -- --profile dev
swift run AgentDeck -- --selfcheck --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

- App 的 profile 仍可控制窗口标题和 diagnostics 读取；它不隔离 vendor 登录状态或
  vendor 原生历史。
- 在 P3.9 UDS cutover 前，Swift `ProcessDaemonTransport` 与 Rust CLI 的 sync/async
  stdio transport 都忽略旧 profile/data-dir spawn 参数，移除继承的
  `AGENTDECK_PROFILE` / `AGENTDECK_DATA_DIR`，固定传
  `--ephemeral --no-remote --profile dev`。因此这些子进程不会读取或创建 stable Runtime
  信任域，也还不能让多个客户端共享同一 daemon。
- stable 模式只面向带 daemon-only entitlement、编译进真实 access group 的 release-signed
  helper；普通 unsigned SwiftPM/Cargo 构建直接启动 stable 必须返回
  `daemon.keystore.access_group_unconfigured`，不能靠运行时环境变量绕过。

测试：

```bash
cargo test        # daemon: ipc/codex/record/diag/report(含 fixture 回放)
swift test        # app: 中立协议 + 分行成帧 + headless 请求编码

# P3.1 聚焦门禁
cargo test -p agentdeckd --test daemon_namespace --test storage_kek \
  --test daemon_startup -- --test-threads=1
bash scripts/check-daemon-no-net.sh
```

### 门控 E2E 测试

E2E 测试需要真实 vendor 二进制，默认 `cargo test` 会跳过它们。

运行前置条件：`codex login` 和 `claude auth login` 均已完成。

```bash
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_codex
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_claude_code
AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history
```

若某个 vendor 二进制不在 PATH，对应测试会打印 `SKIP:` 并退出 0（不算失败）。

### 协议

`protocol/` 是从官方 `codex app-server generate-json-schema` 生成的
协议 schema（非逆向）。`protocol/SPIKE_FINDINGS.md` 记录实测的 wire
framing（逐行 JSONL）。codex 版本固定在 `protocol/CODEX_VERSION.txt`。

### 本地数据（AgentDeck 管理，绝不进你的 git）

- stable run record：`<OS account home>/Library/Application Support/AgentDeck/runs/*.jsonl`
  - 每次 turn 的中立 `AgentItem` 留痕，可按 `runId` 回放和排查。
- stable diagnostic log：`<OS account home>/Library/Application Support/AgentDeck/diagnostic.log`
  - 结构化 JSONL，记录进程、IPC、adapter、run record 写入和自检异常。
  - Codex app-server 断连时会附带其 stderr 尾部摘要，便于定位启动失败或崩溃根因。
- P3.1 stdio 开发实例：位于 OS temp root 下随机的 0700 `ad-<instance-id>/`，每次
  spawn 独立，且 remote disabled；旧 `AgentDeck-Dev/` 只可能被 diagnostics one-shot
  作为历史 profile 读取，不再是 daemon 启动 namespace。

Agent 自查流程见 [docs/AGENT_DIAGNOSTICS.md](docs/AGENT_DIAGNOSTICS.md)。
质量门禁和文档结构检查见 [docs/QUALITY.md](docs/QUALITY.md)。

写入前做 best-effort 密钥脱敏。写失败不阻塞会话，但会在界面可见
警告（绝不静默）。`AGENTDECK_DATA_DIR` / `AGENTDECK_PROFILE` 只用于尚未启动
daemon 的 diagnostics one-shot；daemon startup 不读取它们，也不允许它们改变
stable ownership。

### 回滚

未签名 `.app`：删除应用即可。GitHub Releases 保留旧版本 zip。无
数据库迁移、无 feature flag。首次打开需在系统设置允许（Gatekeeper）。

## 贡献

AgentDeck 的核心是 `Agent` trait + `CapabilityRouter` 组成的一等公民
适配器接口。v0.2 已有 `CodexAdapter` 和 `ClaudeCodeAdapter` 两家实现；
社区可以按同样标准平行贡献新 adapter（SSH 远程、云端 agent 等）。
新增 adapter 不得要求 Swift 侧知道该 adapter 的 vendor JSON，
也不得阉割已有 adapter 的 capability（N5 对称约束）。贡献指南待补。

## License

MIT — 见 [LICENSE](LICENSE)。
