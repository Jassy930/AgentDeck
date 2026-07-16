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
                           │ Layer C 旧 SessionStart 模型（production stdio 拒绝）
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  agentdeckd (Rust daemon)                                       │
│  RuntimeHub（admin/read stdio compatibility）                   │
│       └─ production 拒绝 SessionStart / SessionContinue          │
│  local::listener（recovery 后 canonical UDS + graceful join）    │
│  RuntimeCore（exec-gate + RuntimeEnvelope UDS 已接线）            │
│       └─→ AgentRouter（按 conversation.agentKind 路由）           │
│            ├─ CodexAdapter      (capabilities = {...})          │
│            └─ ClaudeCodeAdapter (capabilities = {...})          │
│                                                                 │
│  共享层：record / diag / profile / capabilities registry         │
└─────────────────────────────────────────────────────────────────┘
   ▼ spawn (turn-scoped)                  ▼ spawn (turn-scoped)
codex app-server                       claude CLI (--print --stream-json)

agentdeck-cli  (参考客户端 / 门控 E2E 驱动，不在 GUI 实时通路上)
      │  stdio compatibility 仅 admin/read/selfcheck；不执行真实会话
      ▼
agentdeckd
```

IPC 协议两层：Layer A 事件主干严禁出现 vendor 字样（N1 不变量守护）；
Layer B Vendor 控件命名空间允许 vendor 前缀但类型化（禁 `serde_json::Value`
透传，N4 守护）。UI 通过 `CapabilityRouter` 消费 `SessionCapabilities`
选择渲染路径，不得硬编码 `if agentKind == .codex` 分支（N2 守护）。

目标架构由每个 macOS 登录用户唯一的 stable `agentdeckd` 作为 runtime hub。P3.1
已经建立固定 namespace、进程锁与 StorageKEK 启动边界；P3.7 已把 production execution 收口到
`RuntimeCore → per-conversation actor → exec-gate → typed driver`。P3.8-B（`1e7f9ea` / `459f32a`）把 production bootstrap 固定为
`recovery permit → retained-dirfd secure bind/readback → canonical RuntimeEnvelope UDS → signal-driven graceful join`；
默认 ephemeral/no-remote 也从私有 `TMPDIR/ad-*/s` 派生 UDS，stdin EOF 不再结束 daemon。Swift/Rust 的
旧进程 transport 只有显式 `--stdio-compat --ephemeral --no-remote --profile dev` 才能继续走
admin/read allowlist，并明确拒绝 execution/control 命令。因此当前 App/CLI 的真实新建/继续会话仍不可用；
两者默认连接同一个 singleton daemon 要到 P3.9 cutover 后才成立。

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
`~/.claude/projects/<encoded_cwd>/<id>.jsonl` 获取，事实唯一来源仍在 CC 原生
接口。Runtime DB 只允许在 `claude_code_adapter_state` 私有 namespace 保存 StorageKEK
保护的 `adapterStateKey → session id` 派生索引；它不保存 title/archive/status/transcript，
不进入 common catalog、日志、Relay 或客户端 wire，也不创建 `cc-meta/`。重建只接受本机
projects root 中恰好一个 regular、非 memory-agent JSONL；不会按 title/cwd/mtime 猜回旧随机
key。无法确认旧映射时 fail-close 或导入为新 conversation。Archive 走 `claude rm`
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

## Relay Companion MVP 实施状态（P3.8 与 P3.9-C0-A1a 已完成，P3 整体未完成）

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
统一返回 typed `remote.persistent.unsupported`。`agentdeckd` 当前只放行 same-UID local UDS，
network-boundary guard 仍禁止 TCP/UDP/HTTP/WSS stack，因此 P2.10 不能被描述为 daemon/iOS
Companion 已经接通。

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

P3.3 的 Runtime schema v2 在最初七表基础上新增 `codex_adapter_state` 与
`claude_code_adapter_state` 两张互斥私表。resume reference 以 namespace-specific blind
index + row AEAD 保存，整行删除由 authenticated table totals 检测；同 key/ref 重试幂等，
跨 namespace 或改写 ref fail-close。物理 schema 升级不会改变冻结的 crypto context v1，
因此 v1 journal 无需重加密或重包 key bundle。

common catalog 不再接受调用方任意 `Vec<u8>` descriptor；`NewConversation` 只能携带固定字段的
`ConversationDescriptor(agentKind,title,cwd)`，并以 deny-unknown canonical JSON 加密。open、
recovery 和 v1→v2 migration 都会解密后逐字节重编码；带 `threadId`/`sessionId`/resume 扩展的
authenticated v1 row 也会在零写入阶段拒绝。migration 在 legacy journal mode 中做 DDL，
before-COMMIT fault 显式 rollback 并核对 main/WAL/SHM/`-journal` 原件；只有 schema COMMIT 后
才切换并读回 WAL/PERSIST_WAL，post-COMMIT 配置错误按 unknown outcome 重开收敛。

P3.3 同时把 adapter 的 canonical contract 与 stdio compatibility 分开：canonical handle/event/
history 只携带 neutral `adapterStateKey` 和中立业务内容，不含 `ThreadId`；旧 translator 产生的
`ServerEvent` 只在各 vendor 模块内部经过 bridge，routing identity 被剥离，未建模 Raw frame
直接变成 typed failure。Codex 在首个 turn 前绑定 `thread/start` 结果，resume response 也必须
返回与私有映射完全一致的 `thread.id`；CC 首次使用已持久化的 `--session-id`，只有唯一、经
`O_NOFOLLOW` 打开并有界读回为有效 JSONL 的 native history 已存在时才 `--resume`，fresh home
缺少 projects root 视为尚未 materialize。CC 在 authoritative `system.init.session_id` 匹配前不
返回 canonical handle、不发布事件。state repository/module 不再公开；只有 runtime
composition 能把 singleton store 分裂成固定 namespace 的 typed vault，具体 adapter 不持有
`RuntimeStoreHandle`，也无法构造另一 adapter 的 vault。

Accepted、Started + ExecutionIntent + started event、ExecutionFence、release authorization、
terminal state + event 都以事务为边界。任何 before-COMMIT failure 完整回滚；任何
真实 COMMIT 失败若无法确认 rollback、以及任何 after-COMMIT response loss，都返回
`CommitOutcomeUnknown`；完全相同的重试只读回原 record。
同一 conversation 在 store 层最多存在一个 Started，completion 必须先存在 matching fence
且 `releaseAuthorizedAt` 已提交。24 小时未启动的
Accepted command 由可注入 daemon clock 在 accept/start/recovery 前 sweep 为 Expired，并写入
同 conversation 的 canonical expiry event；idempotency ledger 至少保留 30 天。

P3.2 最初的 schema v1 严格只有七张表。descriptor、owner/idempotency key、prompt、execution nonce/
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

### P3.4 RuntimeCore 当前边界

transport-neutral `RuntimeCore` 与 production UDS framing 当前使用 Runtime v2：A1a1 由 `3b83391`
冻结 additive configuration/metadata/upgrade DTO，A1a2 main cutover 与真实 v1/schema v4 reader
分别由 `c28a968` / `c36a4f9` 收口。已落地的纯幂等 Start、显式
CancelQueued/CancelActive 与精确 QueryReceipt 接到 Runtime journal。Start 不再携带首 prompt；
相同 owner+start key 由 StorageKEK 域分离 capability 稳定派生，跨重启返回同一
公共 `conversationId` 和准确 replay bit；Start receipt、Catalog 与 snapshot wire 已删除
daemon-private adapter handle。C0-B configuration store 落地前，production `SendPrompt` 对所有 revision
typed `feature_unavailable`；只有 `#[cfg(test)]` legacy harness 可使用显式 revision 0，新增 mutation
同样 fail-closed。prompt
actor 以 journal `commandSeq` 为唯一 FIFO，同 conversation 只有一个 active，不同 conversation
可由全局 semaphore 并行；control 使用有界优先批次，ReadPool 满时立即 overload，不排无界
waiter。

进入 Core 的 principal 是字段私有的认证 capability；同一完整身份共享强 authorization lease，
Accepted→Started 前会重新取得 guard，revoke 与 start 由该 guard + SQLite transition 线性化。
P4 auth ledger 前没有 production remote issuer，恢复出的 remote Accepted 明确
RecoveryBlocked。durable conversation/actor 固定最多 1,024，connection writer 最多 128，
principal lease（含 revoked tombstone）最多 1,024；满载均 fail-closed，不做活跃对象驱逐。
每连接 outbox 只接收保留 version/messageId 的完整 RuntimeEnvelope，并固定
512 frames/16 MiB；预算保持到 transport 完成 socket
write/flush ACK；慢 writer、drop 未 ACK work 只清理自身连接。Store Safety lane 可原子终止
Accepted 为 Canceled/RevokedBeforeStart，Read lane 的 compact receipt 同时校验
conversation+owner。

P3.4 的 side-effect-free fake 仍只用于 contract tests；production 构造已经固定安装
`GatedExecutionCoordinator`。actor 先提交 Started/ExecutionIntent，再启动同一已签名 daemon binary 的
`--exec-gate` 子模式；gate 在独立 PGID 内经私有 FD 收取 spec，并在 ExecutionFence 与 release
authorization 都 durable COMMIT 后才 exec vendor。permit 精确绑定 command、daemon boot、nonce、
PID/start-time、token commitment；completion 成功还必须证明整个进程组已经 reap/fence。关停会先用
内部 Closing 拒绝新请求并封住 actor start lease，再公开 Draining，因而 Draining 后不会新增 durable
Started。显式 stdio `RuntimeHub` 只保留 admin/read compatibility 面；默认 daemon 已走 UDS，但 App/CLI
尚未迁到 singleton UDS，
所以 production exec-gate 通过不等于本地或远程 Companion 已端到端完成。

### P3.5 approval、P3.6 canonical stream 与 P3.7 exec-gate 当前边界

P3.5 已把 approval ledger、SQLite first-wins CAS、Applied/DeliveryFailed/Expired 精确回执、
daemon-owned delivery single-flight 与 terminal+expiry Safety transaction 接入 RuntimeCore；
对应提交为 `0609152`。P3.7 canonical Claude Code driver 已用真实筛选
`control_request(can_use_tool)` fixture 验证，canonical argv 使用 `--permission-prompt-tool stdio`，并只在
typed builder 广告 Approval；legacy compatibility
builder 对 speculative permission wire 仍隐藏 Approval。P3.7 已接通 production execution owner、
`RuntimeExecutionEvent` 和 orphan process-group fencing，但筛选录制与无副作用 helper 不是已登录
vendor 的 live approval 证据，不能用 fixture/shape test 冒充。

canonical approval 不能退化为只显示 vendor/tool 名称的“盲签”：Codex 只从官方
`command/commandActions/networkApprovalContext`、绑定 `itemId` 的 proposed file changes、permission
profile 及可选上下文字段生成摘要；Claude Code 只从按 tool kind 选择的最小动作字段生成摘要。两者都
先限制 source 并脱敏；Codex 把自由文本编码成可见 JSON 字符串以保留换行/控制符边界，若不能在固定
上限内完整展示动作则 fail-close，不截断后继续批准；Claude Code 折叠控制字符并按 UTF-8 边界截断。
完整 raw frame、CC
permission suggestions、未选中的 input 与 blocked path 不进入 durable `ActionRequest`。Codex
`item/completed` 还必须与 started item kind 完全一致，`declined` 映射 Canceled；`inProgress`、未知或
缺失 terminal status 均 fail-close 且保留 in-flight state。CC `tool_result` 只有 `is_error` 而没有权威
进程退出码，因此 canonical、legacy 与 history 的 Shell `exit_code` 都保持 `None`，不能伪造 0/1。
canonical CC 对 2.1.207 已核实的 status/hook/task/tool progress 先做封闭 shape 校验再非持久化消费；
未知 lifecycle 仍 fail-close。`result` 还必须精确证明 `success + is_error=false + duration_ms +
terminal_reason=completed` 且没有 deferred tool，才会写 TurnComplete。
Codex command approval 缺少具体 command、完整 `commandActions` 或已验证 network target 时拒绝；file
approval 必须用 `itemId` 绑定同一 in-flight `fileChange`，并完整展示非空 proposed changes，可选
`grantRoot/reason` 只补充上下文，不能单独构成动作。permission profile 为空或无法在 1 KiB 内完整
展示时同样拒绝；permission summary 复用 adapter 的 validator，完整展示同一已验证
read/write/entries/glob/network profile 的字段结构与脱敏投影，adapter 响应仍回送已验证的原始字段值。
CC 缺少 tool-specific 动作字段或 tool 未建模时同样 fail-close，
不再退回 description/display name/tool name。approval route 的 Debug 明确隐藏 request 与 raw params。

P3.6-A 已由 `7731d1e` 冻结 Runtime stream/transfer 的 Rust、Swift、schema 与 fixture contract；
P3.6-B 已由 `02cc640` 把 Runtime DB 迁到 schema v4。v4 在 v3 approval schema 上增加
`event_stream_index`、`event_retention`、`catalog_journal`、`snapshots`、
`publication_streams`、`publication_outbox` 六表，既有 `event_journal` 继续作为 append-only
authenticated audit，不承诺物理删除历史 audit row。独立 ReadPool 使用 8 个
`mode=ro/query_only=ON` WAL connection，整个池保留页内存 128 MiB，单页 64 rows/8 MiB；
短事务复制完成后才把页交给 reply pump。

P3.6-C 已由 `694f2d9` 提交 transport-neutral StoreCommitHub、Catalog/conversation 共用的
SubscriptionBarrier、连续 backfill/snapshot-required、authenticated snapshot、paced JSON
TransferPart、transfer reducer 与 publication freeze/COMMIT/ACK 状态机。每个 connection 的 egress
gate 串行化所有 directed snapshot/backfill/sync 与 live catchup，顺序固定为
`snapshot/backfill → SyncComplete → catchup/live`；watch 只 coalesce durable HWM，不缓存
payload，actor/Core/SQLite transaction 都不跨 transport flush wait。subscription `commit` 只登记
可取消后台 job 并立即返回；terminal Failure 持有 gate 到 flush ACK/cancel，disconnect/Unsubscribe/
shutdown 仍可从 registry 精确取消 sibling job，不等待该 ACK。
subscription、barrier、snapshot sender/build、transfer、read page、writer 与 publication outbox
均有代码固定的 count/byte/absolute-TTL 上界，满载返回 typed failure，不扩成无界队列。
同 target replacement 只有最新 generation 发 receipt/snapshot/sync，superseded pending job 不发 stale
receipt；未来客户端发起 replacement 时必须取消旧 request waiter。pending capture 在 Store capture/
spawn 前受 4/connection、128/global 硬上界，disconnect 胜出后的 stale prepare 不能重建 slot。

本阶段 publication 测试使用注入的 fake sealed blob，只证明 exact blob/hash/inner range 的冻结、
COMMIT-unknown 逐字节重试、ACK 和重启恢复算法；transfer 测试只证明 Runtime DTO 的 bounded
重组与 inner cursor 单次推进。`TransferStateMachine` 与 publication dispatcher 尚无 production
remote owner。真实 MachineDataSign/E2EE seal、Keychain CounterGuard、Relay
Publish 和远程设备解密属于 P4；iOS 仍是 fixture 驱动 Simulator 前端，不是当前链路证据。
App/CLI 仍未迁到 singleton UDS，RemoteLink 也没有 production owner，因此 P3、Companion MVP
和 P3.1 的 provisioned signed Keychain 外部门禁都不能声明完成。

当前 P3.6 组件门禁已确认 `runtime_stream` 45/45、`runtime_transfer` 17/17、subscription
36/36、daemon lib 464/464（其中 `runtime::` 366 项）、默认并发 `cargo test -p agentdeckd` exit 0，
Swift 256 XCTest + 35 Swift Testing，以及 protocol/schema、fmt、clippy、daemon network-boundary 和 diff gate
全通过。真实签名 Keychain roundtrip 仍有 1 项 ignored/BLOCKED，ignored 不计 PASS。

为让默认并发门禁在 macOS soft FD limit 256 下稳定复现业务行为，test-only admission 将每个 unit/
integration test 进程同时存活的真实 RuntimeStore fixture 限为 4；每份 Store 仍真实打开 1 个 writer
与 8 个只读 WAL reader。该限制只防止测试进程在断言前耗尽 FD，不改变 production Store、ReadPool
或运行时配额。

P3.7 的 typed journal 前置分片把 `ExecutionId`、`AgentTurnRequest`、
`AdapterStateHandle` 和有界脱敏 `ExecSpec` 绑定到 daemon-owned cold prepare。adapter hook 只能由
不可构造的 daemon capability 调用；prepared handle 在真正读取 spec 时再次核对 exact execution/state，
恶意虚 getter 不能在首次校验后切换到另一 execution。fresh Item/Error/approval 只允许在 matching
Started + Fence + durable release 之后由 Store-owned builder 写入；release 失败会丢弃整个 prepared
event receiver，不会把未越过 gate 的 approval 持久化。event row、HWM、stream index、ledger 和 watcher
在同一 COMMIT，open-time audit 会验证 dynamic rows 与
`startedAt <= releaseAuthorizedAt <= terminalAt`，Error 只保存固定脱敏 failure。
该前置分片的 fixture、typed adapter prepare 与 typed execution journal 已分别提交为
`819aa5e` / `1acf8b8` / `3f22cf0`。

OS gate 实现已加入 current-binary `--exec-gate`、有界 ADGX 私有 FD codec、独立 PGID 与
PID/start-time、随机 release token commitment、Codex/Claude Code typed production driver、私有
stdin prompt、neutral `AdapterItemKey` 以及 durable AdapterEvent ACK terminal barrier。adapter 只从
与 gate 最终环境一致的固定目录集合解析 vendor binary：系统目录固定，macOS 追加由
`getpwuid_r(geteuid())` 得到的 OS account `~/.local/bin`，拒绝继承 HOME/PATH 与带路径的程序名；gate/vendor
均 `env_clear` 后只恢复非秘密 allowlist。这里的信任根是正确的 OS account、当前签名 daemon binary、
固定 vendor 安装目录及其中预期的 vendor binary；同一 OS account 主动替换该 binary 不在本机制的证明
边界内。

P3.7 已裁决采用 cooperative-descendant 边界：exec-gate 保证 release 前 vendor/tool 副作用为零，
并收割始终留在继承 PGID 内的 vendor 及其同组子孙。vendor/tool 主动 `setsid`/`setpgid`，或通过
`launchd`/launch service 等 supervisor 显式自守护/逃逸，属于流程外不支持行为；当前机制不声称检测、
枚举或收割该类进程，也不能声称逃逸会触发 `RecoveryBlocked`。需要此类工具时必须另行使用真正执行域
隔离。

启动顺序固定为 singleton lock → Keychain/DB 两遍 recovery → orphan group exact fencing →
`RecoveryReadyPermit`；Accepted 在恢复期间不调度。release 前 crash 会关闭并清理 blocked group；release
后 crash 写 Interrupted/unknown outcome 且不自动重放。approval durable Expired 不合成 Deny，只做 exact
fence；正常 terminal 为 Interrupted，若 fence 后 pipeline 仍卡死则 watchdog 将 conversation 标
RecoveryBlocked 且不启动 queued work。PID 复用、TERM→KILL 后仍无法证明已知 PGID 内进程退出，
以及陈旧 boot/nonce/fence CAS 都 fail-close 为 conversation-scoped `RecoveryBlocked`。blocked gate
还必须从 prepare 起由唯一 reaper 持有，release 前 cancel/cleanup 也要 KILL 后 await，避免 zombie
sentinel 被误判为未退出；确认没有创建 child 的普通 prepare failure 必须直接 Interrupted，不能错误
升级为 RecoveryBlocked。当前实现从 gate Ready 起启动唯一 abort-on-drop reaper；`current_exe`、
socketpair/timeout 配置等明确发生在调用 Tokio `Command::spawn()` 前、可证明无 child 的错误才可标记
`PrepareFailedClean`；从调用 Tokio spawn 起的错误和任一无法证明 exact kill/reap 的 attach cleanup
都 fail-close 为 `RecoveryBlocked`。production stdio 已收窄为 admin-only，不能再通过 legacy
SessionStart/Continue 绕开 gate。

Codex 与 Claude Code 回归使用当前树内的筛选脱敏真实录制片段；来源、筛选、hash 和边界见
`agentdeckd/tests/fixtures/README.md`。未消费且含不适合入库材料的 CC `plan_mode.jsonl` 已从当前树
删除，但祖先 `68b6cfd` 仍有历史 security debt，不能宣称完整 Git history 已清理。

P3.7 的主体代码、prepare disposition 与 translator 终审修复已经落到候选树；fresh 完整 package、
all-target check/clippy、schema、Swift、自检、no-net/docs/fmt/diff 门禁均已通过，独立终审 Approved，
并由 `5568e93` 完成主体 scoped commit；`c9d2146` / `5713be4` 进一步让同一 production probe 在
真实 current-binary gate 的 Ready→release 窗口发起 RuntimeCore Cancel，读回 Canceled、零 vendor
副作用与 exact PGID 退出，并统一内部故障取消 bookkeeping；sentinel leader 已退出但同组 child 仍在的
短窗口只等待 PGID 自然消失，持续 Unknown 仍 fail-close。production wiring probe 会真实穿过
`RuntimeCore/actor → GatedExecutionCoordinator → AgentRouter → current-binary gate → typed driver →`
durable event ACK → terminal，并在 reopen/backfill 后读回 canonical item 与唯一 terminal。probe 不接受
binary/root 注入，内部原子创建随机临时目录并 RAII 清理；它使用
`/bin/sh` 无副作用 helper，不替代真实 Codex/Claude Code 登录、真实 approval 或 P6 跨设备证据。
P3.8-B production UDS/bootstrap 已由 `1e7f9ea` / `459f32a` 完成；P3.9-C0-A1a Runtime v2 Rust
cutover 已完成，但 A1b 旧签名材料拒绝门禁、A2 Swift v2 mirror、App/CLI 默认 UDS cutover、P3.10 LaunchAgent、
P4 RemoteLink、P5/P6 客户端与实机证据仍未完成；
P3.1 provisioned signed Keychain roundtrip 也仍是外部 BLOCKED gate。
具体命令与资源矩阵见 [docs/QUALITY.md](docs/QUALITY.md)。

## agentdeck CLI（参考客户端 / E2E 驱动）

`agentdeck` 是一个 Rust 二进制参考客户端，**不在 Swift GUI 的实时通路上**。P3.9 前 Swift app 与 CLI
仍由过渡 `ProcessDaemonTransport` 显式启动 stdio compatibility daemon；该入口拒绝全部
execution/control 命令，不能执行真实会话。`agentdeck` 现阶段用于 admin/read 脚本、本地验证和门控
E2E 驱动；默认连接 stable singleton UDS 与真实本地会话属于 P3.9。

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

运行（会构建/启动 App 或执行自检；当前自动 spawn 的仅是 ephemeral stdio compatibility daemon，真实
会话启动会返回 `daemon.runtime.stdio_command_forbidden`；默认 shared-daemon UDS client cutover 属于 P3.9）：

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
  `--stdio-compat --ephemeral --no-remote --profile dev`。因此这些子进程不会读取或创建 stable Runtime
  信任域，也还不能让多个客户端共享同一 daemon；production `RuntimeHub::admin_only` 会拒绝
  `SessionStart/SessionContinue`，这条 compatibility path 不能用于真实会话执行。
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
bash scripts/check-daemon-network-boundary.sh
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
