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
                           │ RuntimeEnvelope v2（OS-account canonical UDS）
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
      │  RuntimeEnvelope v2 canonical UDS（无 spawn/fallback）
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
默认 ephemeral/no-remote 也从私有 `TMPDIR/ad-*/s` 派生 UDS，stdin EOF 不再结束 daemon。P3.9-C3
已由 `b4e9565` 把普通非 preview GUI 的 `SessionModel` / App composition 切到惰性的
`OSAccountRuntimeWireSession → LocalRuntimeWireSession.forOSAccount()`：第一次使用时从当前 OS account
installation 派生 canonical singleton UDS，且没有 daemon spawn、stdio 或 fallback。P3.9-D 又由
`b818f81` 把 Rust CLI 默认 dispatcher 与 Swift `main.swift --selfcheck` 切到同一 shared daemon：普通
`ping/selfcheck/agent/session/history/metadata` 全部使用 canonical Runtime v2，socket 失败 typed 返回且零
fallback；显式 diagnostics one-shot 与 compatibility stdio 只保留为隔离运维入口。

流式性能边界：Swift 端的 `SessionModel` 按约 30fps 合并待渲染 delta，并把
message / reasoning / shell / diff 长文本交给 AppKit `NSTextView` +
`NSTextStorage` 增量追加；会话流由虚拟化 NSTableView 按需渲染可见行，
避免在 token 流中反复布局整个视图树。

## 历史会话（跨 agent）

v0.2 的历史侧栏与 CLI 都消费 Runtime `Catalog`。公开身份只有 daemon 签发的
`conversationId`；`agentKind` 保留在 descriptor/capabilities 中供 daemon 路由和 UI 展示，不要求
`history read` 或 `session continue` 重新传 agent，也不向客户端暴露 vendor thread/session ID。
`history list` 可在客户端按 agent/cwd 筛选 Catalog，`history read <conversationId>` 通过
`Subscribe(BeforeFirst) → Snapshot?/Backfill* → SyncComplete` 回放，continue 只接受
`conversationId + prompt + stable idempotency key`。

Runtime 管理的新 Codex/Claude Code conversation 都能进入 canonical Catalog/list/read。**既有 Codex
app-server 原生历史导入**尚未接通；这只表示升级前的 Codex thread 不会被扫描导入，不表示 Runtime 管理的
Codex conversation 恒为空。daemon 仅在 adapter 私域把 conversation 绑定到已验证的 Codex thread 或
Claude Code session；后续 adapter 可内部调用 `thread/resume` / `--resume`，但 raw vendor identity 永不进入
common wire、日志、Relay 或 CLI 参数。

**既有 Claude Code 历史**的事实源仍是当前 OS account 的
`~/.claude/projects/<encoded_cwd>/<id>.jsonl`。C0-C production projector 逐层执行
no-follow/current-UID/regular-file 与有界 JSONL 验证，再把 neutral descriptor 和稳定 identity 原子投影到
Runtime Catalog；正文不复制进 Runtime DB。每次 Snapshot 都重新读取已验证原生历史，并从 canonical
turn/item key 派生稳定 command/item/entity identity；`QueryReceipt` 对本次已验证的历史 command 返回
`daemon.command.history_only`，不冒充 command journal Accepted。Runtime DB 的 adapter 私表只保存
StorageKEK 保护、可重建的 private binding，也不创建 `cc-meta/`。

native metadata 必须经过 Runtime authorization、幂等 ledger 与 gate。MVP production 对 native Rename
仍在 claim 前返回 `daemon.conversation.metadata_unsupported`，因此不会产生 ledger/fence/vendor 副作用；
current-binary synthetic roundtrip 只证明安全 substrate，真实 Claude binary mutation 留在 post-MVP。
`claude-mem` observer 会话会在 native scan 阶段过滤，不进入 Catalog、CLI 或侧栏。

历史详情读取在后台完成，完整 synchronization barrier 验证后才原子发布到右侧。大段 shell output 和 diff
展开时才填充 TextKit buffer，避免大历史 conversation 阻塞主界面。每个 conversation 在 Swift
`WorkbenchModel` 中拥有独立 `ThreadRuntimeModel`；切换选中项不会停止其他后台 runtime。新会话在
`ConversationStart` 返回前只保存 draft context，取得 canonical `conversationId` 后才进入 Catalog，后续
prompt 继续使用同一 conversation。正在运行、启动中或等待 approval 的 runtime 只 drain 自己的 FIFO；
approval 控件使用完整 conversation/turn/command/approval/request binding，不解析 Codex 原始 JSON。
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

## Relay Companion MVP 实施状态（P3.9-D complete，P3.9-E next）

2026-07-18 纠偏后，主线恢复 Task 粒度门禁；Runtime store 只承诺缺 KEK 且无法通过当前
KEK/database/domain 认证的离线篡改 fail-close，同 UID 在线攻击作为 residual risk 不再扩展。P3.1
采用方案 b：MVP 接受 dev/ephemeral Keychain 路径，provisioned signed roundtrip 移入 post-MVP
ignored/BLOCKED 槽位，不阻塞 MVP/P3 exit，也不表示 stable production signing 已完成。P4 功能全保留，P5/P6 的物理设备、
公网与干净 Linux 证据改为 post-MVP BLOCKED 槽位。详见
[`docs/plans/2026-07-18-relay-companion-mvp-course-correction.md`](docs/plans/2026-07-18-relay-companion-mvp-course-correction.md)。

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
终止。因此 signed roundtrip 与 P3.1 Step 4 不能记为 PASS。2026-07-18 已采用方案 b：MVP/P3 exit
验收完整 dev/ephemeral 路径，该 signed roundtrip 移入 post-MVP BLOCKED 证据槽位，不再阻塞 P3/P4
主线或 phase closeout，也不再尝试代码绕过 AMFI；stable production signing 仍未完成。

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
缺 KEK 且无法通过当前 KEK/database/domain 认证的离线磁盘篡改、删除或跨库移植，会在
open/recovery 全库认证审计中 fail-close，拒绝路径保持 artifact 零改写。同 UID 在线攻击者能够读取
daemon 内存密钥或替换进程，不属于 SQLite 层安全边界；`974f9b1` 是该方向最后一笔。

### P3.4 RuntimeCore 当前边界

transport-neutral `RuntimeCore` 与 production UDS framing 当前使用 Runtime v2：A1a1 由 `3b83391`
冻结 additive configuration/metadata/upgrade DTO，A1a2 main cutover 与真实 v1/schema v4 reader
分别由 `c28a968` / `c36a4f9` 收口；`ef830cd` 又证明 Runtime v1 TBS 签发的 persisted cert/grant、
control grant/revocation/retirement 与 enrollment Link/Data cert 均在 v2 verifier 写 Store 前拒绝。
Swift 共享层已由 `bea4c13` / `3e019ed` / `0dd58de` 完成 configuration/metadata/upgrade/receipt、
catalog/strict vendor-panel/canonical event 与 snapshot/backfill 的 v2 strict mirror；`c2d2c28` 又完成
request/reply/message/stream/envelope 与 JSON/UDS 94-part transfer model，并对 97 条 JSON fixture 做 typed
readback；`e419d84` 再完成 `ADRT1` version 2 compact carrier、current facade、98-fixture 全量、严格
`<1 MiB` JSON 与 `<4 MiB` compact frame gate。A2-0 的 0600/128-byte 真实 UDS Hello 样本也已由
current Swift codec 以 1 test / 0 skipped 读回并删除。A2 当时只冻结共享 wire/API；普通 GUI 后续由
P3.9-C3 切到 UDS，Rust CLI 与 Swift `main.swift --selfcheck` 又由 P3.9-D 完成 canonical cutover。
已落地的纯幂等 Start、显式
CancelQueued/CancelActive 与精确 QueryReceipt 接到 Runtime journal。Start 不再携带首 prompt；
相同 owner+start key 由 StorageKEK 域分离 capability 稳定派生，跨重启返回同一
公共 `conversationId` 和准确 replay bit；Start receipt、Catalog 与 snapshot wire 已删除
daemon-private adapter handle。C0-B1b 已把 production Runtime DB 升到 schema v5，并为 fresh/迁移
conversation 物化 authenticated `conversation_state`；C0-B2 已接通 append-only
`configuration_journal`、frozen-cursor snapshot selector 与 RuntimeCore `ConfigureConversation`，每次
Applied 只写一条 commandless `ConfigurationChanged`，不推进 activity/catalog/entry revision，也不产生
`CatalogDelta`。exact retry 返回 Replayed，stale/future CAS 返回 Conflict；after-COMMIT unknown 仍从
authenticated readback 通知一次，后续 exact retry 不重复广播。caller 被取消后，authorization guard
由 Store command 保持到 durable outcome、通知和 reply 完成，不创建 detached task。
`DescribeAgents` 对任意已认证 Runtime principal 返回按 `AgentKind` 稳定排序的 capabilities + adapter-owned
default configuration；Codex 默认为 `OnRequest + WorkspaceWrite + Medium`，Claude Code 默认为
`Default + null model/effort/outputStyle`，任一 adapter 错误或 kind/vendor 不匹配整批 fail-close。
`command_configuration_pins` 已由 B3a writer 接通：fresh v5 `SendPrompt` 必须携带 nonzero expected
revision，Accepted command 与 exact configuration pin 在同一 Store transaction 提交；exact replay 先认证
原 command/pin，receipt/status/Started/terminal/recovery 始终返回原 pinned revision。未配置与 revision
mismatch 分别返回 `daemon.conversation.configuration_required` 与
`daemon.conversation.configuration_conflict`，不再误报 `daemon.runtime.feature_unavailable`。Core 将
authorization guard 移交 Store command，覆盖 durable outcome、通知、reply 与成功后的 actor queue
registration；caller 取消或 actor shutdown timeout 不能在 Store 完成前提前释放。
B4 已接通 managed `Rename` / `SetArchived`：Store 在同一 transaction 写入 authenticated
`metadata_mutation_ledger` terminal outcome、descriptor/lifecycle、conversation-local entry revision、全局
catalog revision 与唯一 `CatalogDelta`，不写 conversation event，也不改变 last-active 时间。same
owner/key/request 精确重试返回原 Replayed，same owner/key/different request 返回 durable Conflict；
RecoveryBlocked conversation 只允许 rename，archive/unarchive 零写拒绝。C0-C 已补齐 native claim/fence/
readback 状态机与 Runtime-owned current-binary exec-gate substrate，但 MVP production native Rename 明确在
claim 前返回 `daemon.conversation.metadata_unsupported`；synthetic gate 不冒充真实 Claude side effect。
B3b 又让 Start 在同一 SQLite transaction 中认证 command、pin 与完整 `1...head` configuration chain，选择
command 固定的历史 revision，而不是 current head；`StartOutcome → RuntimeExecutionContext →` crate-private
`AgentTurnRequest` 始终携带同一 exact revision/value。rev0 只允许真实 v4→v5 migration cutoff 内的 command
在 startup recovery 使用冻结的 P3.7 defaults，普通 live queue、exact replay 与同进程恢复都不得回退默认值；
configuration 的 agent kind/vendor variant 也会在 spawn 前校验。

Codex 将 approval policy、sandbox 写入 fresh/resume 的 `thread/start` / `thread/resume`，reasoning effort
写入 `turn/start`；Claude Code 将 permission mode、model、effort、output style 固定到 fresh/resume argv。
其中 Runtime/UI 的 `ClaudeCodePermissionMode::Default` 表达常规人工确认语义，当前 Claude Code CLI 的
vendor argv 必须映射为 `--permission-mode manual`，不得发送已不接受的 `default`。Codex approval 的
policy/sandbox 与 Claude Code approval 的 permission mode at-decision metadata 均来自同一冻结配置。
prompt actor 以 journal `commandSeq` 为唯一 FIFO，同 conversation 只有一个 active，不同 conversation
可由全局 semaphore 并行；control 使用有界优先批次，ReadPool 满时立即 overload，不排无界
waiter。

B3a2-C 已由 `48594e8` 提交，B3a3 已由 `09a14b0` 提交；B3b exact execution 与 restart probe 由
`c0ed6cd` / `f4141f0` 完成，Claude Code `Default → manual` vendor 映射由 `fb1629a` 收紧。B3b production
additions 合计 658。已读回 daemon lib `691 passed / 1 ignored`、1,024 × 256 KiB 容量 target `5/5`
（278.46 秒）、4,096 行 configuration chain `1/1`（55.97 秒）、完整 daemon package exit 0 且
`1150 passed / 6 ignored`（共 1,156 tests）、protocol `170/170`、Swift `333/333`，以及
schema/selfcheck/Clippy/fmt/network/docs/diff 静态门禁全绿。6 个 ignored 均保持显式 gated/manual，其中 P3.1
provisioned signed Keychain 继续作为 post-MVP 槽位 BLOCKED、未计 PASS，也不阻塞 MVP/P3 exit。仓库内 recorded argv/control/translator fixture 只证明
builder/translator 字段映射，不是 live vendor login、真实 vendor approval 或 P4 RemoteLink 证据。

B4 code/test 由 `5f1ca1c` 完成，`347a0f0` 对齐完整 open/recovery 审计的密文错误分类；production
additions 为 1,983，低于 2,000 硬线。focused metadata/Core/Catalog/完整性/容量矩阵全绿；完整 daemon
package 为 `1172 passed / 6 ignored`，其中 lib `696 passed / 1 ignored`，1,024 × 256 KiB 容量 target
`5/5`（276.71 秒）。protocol `170/170`、Swift `298 XCTest + 35 Swift Testing`、schema/selfcheck/
Clippy/fmt/network/docs/diff 均通过。两路独立终审无 P0/P1/P2；B4 不证明 native projector、P4
CounterGuard/RemoteLink 或 Companion E2E。

B5 由 `aebc8d0` 以纯测试增量收口，production additions 为 0，测试 additions 为 1,283。真实 UDS
双 installation principal 同时推进 configuration 与 managed metadata，并跨 shutdown/reopen 验证两条独立
revision 轴、owner-scoped idempotency、receipt、Catalog delta、conversation snapshot 与 backfill 收敛；
metadata authorization guard 还覆盖 revoke、caller cancellation 与 after-COMMIT unknown 的单次通知。
跨层主测试及三条并发/故障专项各稳定重复 `20/20`，完整 daemon package
`1176 passed / 6 ignored`，其中 lib `699 passed / 1 ignored`，1,024 × 256 KiB 容量 target `5/5`
（280.10 秒）；protocol `170/170`、Swift `298 XCTest + 35 Swift Testing`、iOS Simulator `20/20`，
schema/selfcheck/Clippy/fmt/network/docs/diff 全绿。独立 spec/security 与 quality 终审无 P0/P1/P2。
C0-B configuration store/execution 至此完成。C0-C 已完成 schema v6、secure native
source、原子 import/reconcile/retire、Core projector lifecycle、dynamic snapshot 与 history-only receipt。
projector 遇到 Store hard cap 会保留 candidate pending、零 ACK，并以 typed diagnostic 进入固定 30 秒
refresh；source unavailable、坏或不完整 generation、read failure 同样避免热循环。真实当前账号 JSONL
只读 list→import→Catalog→Snapshot smoke 已 PASS；Swift `298 XCTest + 35 Swift Testing` 与 iOS Simulator
`20/20` 已 PASS。P3.9-A Rust shared-daemon client component 已由 `c29faa4` 完成；P3.9-B Swift
installation/UDS/RuntimeEnvelope client component 已由 `397ef9d` / `94adf92` / `913a156` / `deb0e1b`
完成。B 的 focused `53/53`、完整 Swift `344 XCTest + 35 Swift Testing`、普通 build 与双路终审已通过；
当时 `-warnings-as-errors` 全包仍被未修改 Preview mock 的既有 Sendable warning 阻断，未记为 B 的 PASS。
P3.9-C3 随后由 `b4e9565` 完成 App model/composition 的 Runtime v2 cutover：普通 GUI 默认连接当前 OS account
shared-daemon canonical UDS，且不 spawn daemon、不回退 stdio。收口修复覆盖 snapshot→backfill 原子归并、
replayed receipt 必须由 exact canonical terminal 收口、preview 独立 Runtime stream，以及同步 terminal 与 live
cursor 交接竞态。完整 Swift `435 XCTest + 35 Swift Testing`、iOS Simulator `20/20`、warnings-as-errors build
均通过，两路独立终审无 P0/P1/P2。P3.9-D 由 `b818f81` 完成 Rust CLI / Swift `--selfcheck` canonical
cutover、30 秒 reply-sequence absolute deadline、typed usage error 与真实双客户端 smoke；两个稳定且不同的
installation 在同一 conversation 各自提交/重放并只查询自己的 receipt，共同 backfill 收敛，daemon PID
保持不变且 endpoint 缺失零 fallback。双路终审无 P0/P1/P2；下一 Task 为 P3.9-E scope/phase 收口。
P4 CounterGuard/RemoteLink 与真实 vendor metadata mutation 仍未完成。

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
Started。显式 stdio `RuntimeHub` 只保留 admin/read compatibility 面；普通 GUI、Rust CLI 与 Swift
`main.swift --selfcheck` 均已走 OS-account singleton UDS。P3.9-D 的真实双客户端 smoke 通过仍不等于
RemoteLink、远程 Companion 或真实 vendor login 已完成。

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

当前 production physical schema 已由 C0-C 单调推进到 v6/22 表。v5 先新增
`conversation_state`、`configuration_journal`、`command_configuration_pins` 与
`metadata_mutation_ledger` 四张 authenticated sidecar；v6 再新增 authenticated
`native_projection_state` 与 `native_metadata_effect_fences`，并增加 projection present/tombstone/retired/
physical/charged-bytes 及 fence total/unreleased/released 共 8 项 totals。crypto context 仍保持 v1。
v1/v2/v3/v4/v5 migration 在 `BEGIN IMMEDIATE` 后、任何 DDL 前重新认证
exact legacy meta/token/全部行，只为既有 conversation 物化 rev0、`entryRevision=0`、Managed origin 与
nullable/BeforeFirst legacy cutoff，不重封旧 ciphertext、不重包 wrapped key。fresh conversation 与
`conversation_state` 在同一事务写入；B2 configuration、B3a command pin 与 B4 managed metadata writer
均已落地。v6 open/recovery 会认证 projection/fence、private binding、generation、effect identity 与全部
totals；production native mutation 虽已有完整 claim/apply/readback substrate，仍按 MVP 边界在 claim 前
typed gated。

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
P3.6 收口时 App/CLI 均未迁到 singleton UDS；普通 GUI 后续由 P3.9-C3 迁移，Rust CLI 与 Swift
`main.swift --selfcheck` 又由 P3.9-D 迁移。RemoteLink 仍未完成，因此该 P3.6 历史阶段不构成
P3/Companion 完成。
P3.1 provisioned signed Keychain 仍是不得记 PASS 的 BLOCKED 槽位，但 2026-07-18
方案 b 已将其移入 post-MVP；它不再阻塞 MVP/P3/P4 主线，但也不表示 stable production signing 已完成。

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
`/bin/sh` 无副作用 helper。B3b probe 还用非默认 rev1 Accept command、随后把 configuration head 推进到
rev2，跨越真实 Store shutdown/reopen 与 startup recovery 后断言 synthetic `ProbeAgent` 仍只观察 rev1；
它证明 production wiring 的 exact pin，不替代真实 Codex/Claude Code 登录、真实 approval 或 P6 跨设备证据。
P3.8-B production UDS/bootstrap 已由 `1e7f9ea` / `459f32a` 完成；P3.9-C0-A1 Runtime v2 Rust
cutover 与旧签名材料拒绝门禁已完成，A2a/A2b Swift v2 strict mirror 也已由 `bea4c13` / `3e019ed` /
`0dd58de` 收口，A2c outer + JSON/UDS/compact/current codec 已由 `c2d2c28` / `e419d84` 收口；
C0-B1a/B1b schema freeze 与真实 migration 已由 `e48248a` / `3d0002d` 收口；B2 configuration/Core 与
B3a admission pin 已完成，后者由 `48594e8` / `09a14b0` 提交并通过 Task 门禁与双路终审；B3b exact
execution 已由 `c0ed6cd` / `f4141f0` / `fb1629a` 完成，B4 managed metadata 已由
`5f1ca1c` / `347a0f0` 完成，B5 cross-layer closeout 已由 `aebc8d0` 完成。C0-C 自动实现与跨语言/
Simulator 门禁已通过；C0-C、P3.9-A/B/C3 与 P3.9-D Task 已完成，D code/test 提交为 `b818f81`。
普通 GUI、Rust CLI 与 Swift `--selfcheck` 已默认走 OS-account shared-daemon UDS；下一项是 P3.9-E
scope/phase 收口。P3.10 LaunchAgent 与 P4–P6 仍未完成。P3.1 provisioned signed Keychain
roundtrip 继续是 post-MVP BLOCKED 槽位，不阻塞 MVP/P3 exit；P5/P6 物理设备/公网/Linux 证据也是
post-MVP，不冒充 PASS。
具体命令与资源矩阵见 [docs/QUALITY.md](docs/QUALITY.md)。

## agentdeck CLI（参考客户端 / E2E 驱动）

`agentdeck` 是一个 Rust 二进制参考客户端，**不在 Swift GUI 的实时通路上**。P3.9-A 已提供 production
`RuntimeUnixClient` component：stable constructor 从 OS account home 读回 CLI installation identity，连接
canonical singleton UDS，且没有 spawn/fallback；reply/stream/transfer 都是有界 typed pump。P3.9-B 也已
提供 Swift `LocalClientInstallation`、`UnixSocketDaemonTransport` 与 actor-owned
`RuntimeEnvelopeClient`。P3.9-C3 已让普通 GUI 的 App model/composition 默认使用
`OSAccountRuntimeWireSession` 连接 shared-daemon UDS；P3.9-D 又把 Rust binary main 与 Swift
`main.swift --selfcheck` 切到相同 canonical UDS。三者连接失败都 typed 返回，不 spawn daemon、也不回退
legacy stdio；diagnostics one-shot 仍是用户显式选择的隔离运维路径。

P3.9-D 的 canonical CLI 映射固定如下：`ping` 只做 `Hello` 并输出 `{"ok":true}`；`selfcheck` 做
`Hello → DescribeAgents`；`agent list/capabilities` 读取 `DescribeAgents`；`session run` 固定执行
`DescribeAgents → Start → Configure(rev0) → Subscribe → SendPrompt(rev1)`；`session continue` 只接受
canonical `conversationId` 并执行 `Subscribe/SendPrompt`，不得使用 vendor `threadId`；`history list` 分页
读取 `Catalog` 并在客户端筛选，`history read` 固定执行
`Subscribe(BeforeFirst) → Snapshot/Backfill* → SyncComplete → Unsubscribe`；rename/archive/unarchive 统一使用
`UpdateConversationMetadata`，并携带 expected entry revision 与稳定 idempotency key。输出身份只允许
`conversationId`、`commandId`、`turnId`、`eventId`、`itemId`、`entityId`，不得合成 legacy session/thread
identity；`protocol` / `remote` 不连接 Runtime，diagnostics one-shot 也不得成为 UDS 失败 fallback。
`persistApproval` 不再是启动配置；没有 Runtime v2 映射的 CC `worktree/sessionName` 必须删除或 typed reject。

### 全局标志

| 标志 | 说明 |
| --- | --- |
| `--profile stable\|dev` | Runtime 命令只接受 `stable` canonical namespace；`dev` 仅用于 diagnostics/显式隔离运维，不覆盖 Runtime endpoint |
| `--data-dir <path>` | diagnostics/Relay 数据目录；Runtime 命令在连接前 typed reject，不能覆盖 daemon namespace |
| `--pretty` | 人读格式输出（E2E 不依赖此标志） |

### 子命令目录

```bash
agentdeck ping                          # UDS preface + Hello
agentdeck selfcheck                     # Hello + DescribeAgents
agentdeck diagnostics report            # 输出机器可读诊断报告（JSON）
agentdeck protocol schema               # 打印 IPC 协议 JSON Schema
agentdeck protocol version              # 打印协议版本号

# v0.2 新增：agent 子命令组
agentdeck agent list                           # 列出可用 adapter
agentdeck agent capabilities --agent <kind>    # 列某 adapter capabilities（JSON）

# canonical session 子命令
agentdeck session run --agent codex \
  --cwd <path> --prompt "..." \
  --idempotency-key <stable-key>        # Codex 新 conversation
agentdeck session run --agent claude-code \
  --cwd <path> --prompt "..." \
  --idempotency-key <stable-key>        # Claude Code 新 conversation
agentdeck session continue \
  --conversation-id <id> --prompt "..." \
  --idempotency-key <stable-key>        # 继续 canonical conversation

# history 子命令（Catalog list 可按 agent 过滤）
agentdeck history list                         # 列出 canonical conversations
agentdeck history list --agent claude-code --limit 200  # 仅 CC 历史
agentdeck history read <conversation-id>       # Snapshot/Backfill 读回
agentdeck history archive <conversation-id> \
  --expected-entry-revision <n> --idempotency-key <key>
agentdeck history rename <conversation-id> <title> \
  --expected-entry-revision <n> --idempotency-key <key>
```

`session run` 的 Codex 选项使用 `--approval on-request|never|always`、`--sandbox read-only|workspace-write|full-access`、`--reasoning-effort minimal|low|medium|high`；Claude Code 选项使用 `--permission default|accept-edits|plan|auto|dont-ask|bypass-permissions`。`--agent` 取值 `codex` 或 `claude-code`（wire 值为 `claude_code`）。

### 输出与退出码契约

除 `--help` 的人读文本外，业务与错误输出为稳定 JSON / JSONL，机器可解析。退出码：

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

运行（普通 GUI、Swift `--selfcheck` 与 Rust CLI 默认连接 OS-account shared-daemon canonical UDS，均没有
daemon spawn/fallback；使用前须已有 canonical stable daemon。P3.10 尚未提供正式 install/start 命令，当前
自动开发链路使用 `scripts/run-local-runtime-smoke.sh` 的私有 ephemeral harness）：

```bash
./script/build_and_run.sh        # 构建 SwiftPM 产物，临时打包 dist/AgentDeck.app 并启动
./script/build_and_run.sh --verify  # 启动后确认 AgentDeck 进程存在
swift run AgentDeck               # 本地 debug 构建默认使用 dev profile
swift run AgentDeck -- --selfcheck  # 无窗口自检: Hello + DescribeAgents，失败不 fallback
swift run AgentDeck -- --diagnostics-report --json  # 输出机器可读诊断报告
swift run AgentDeck -- --preview  # 前端 mock 预览，不连真实 daemon

# 直接验证 P3.1 daemon 启动边界（unsigned 开发构建只能使用完整 ephemeral pair）
cargo run -p agentdeckd -- --ephemeral --no-remote --profile dev --selfcheck
```

macOS 前端使用纯 AppKit。当前主窗口外壳对齐 Codex Desktop：透明标题栏、
全高左侧历史/项目侧栏、右侧 thread header、Codex 风格空态 composer、
会话态悬浮 composer 和右侧环境信息面板。外观层仍保持 v0.2 统一壳边界：
vendor 控件由 `CapabilityRouter` 装配，daemon / IPC / history 模型不因视觉同步而改动。

Profile：

```bash
swift run AgentDeck -- --profile stable
swift run AgentDeck -- --profile dev
swift run AgentDeck -- --diagnostics-report --json --profile dev
```

- App 的 profile 仍可控制窗口标题和 diagnostics 读取；它不隔离 vendor 登录状态或
  vendor 原生历史。
- Rust CLI Runtime 命令与 Swift `--selfcheck` 只发现 canonical stable UDS；缺失或不安全 endpoint 直接返回
  `daemon.client.*` typed failure。两者不会读取任意 socket env override，也不会转入 diagnostics/stdio spawn。
- `ProcessDaemonTransport` / legacy stdio 只保留 preview/test 与用户显式 diagnostics/bootstrap compatibility；
  production `RuntimeHub::admin_only` 继续拒绝 `SessionStart/SessionContinue`，不能用于真实会话执行。
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
