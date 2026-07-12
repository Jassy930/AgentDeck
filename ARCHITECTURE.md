# AgentDeck 架构（v0.2）

本文件记录稳定架构边界。产品定位、使用方式和构建命令见 `README.md`；具体功能设计和实施历史见 `docs/plans/`。

## 北极星

AgentDeck 是 Coding Agent 的统一原生桌面客户端。它把 OpenAI Codex 和 Anthropic Claude Code 作为绝对一等公民，两家的功能、概念和原始语义都被完整保留——AgentDeck 不强行统一它们，而是为它们提供同一个工作台。

AgentDeck 不做 IDE，不做通用多 agent 聊天界面，不是 Codex Desktop 替代品。

## 总体结构（v0.2）

```text
┌─────────────────────────────────────────────────────────────────┐
│  AgentDeck.app (macOS, AppKit)                                  │
│                                                                 │
│  SessionViewController                                          │
│   ├─ StatusBarView（当前 agentKind + auth）                      │
│   ├─ HistorySidebarVC（跨 agent 合并列表）                         │
│   ├─ AgentControlBar（capability 路由 → vendor SubView）          │
│   ├─ ConversationVC（虚拟化 NSTableView，中立 AgentItem）          │
│   ├─ ApprovalCardView（主干壳 + vendor 高级区 SubView）            │
│   └─ AgentTokenAuthMiniPanel                                    │
│                                                                 │
│  CapabilityRouter  ← 新增：UI 渲染按 SessionCapabilities 派发    │
│  ObservationBinder ← 保留：@Observable 模型绑定                  │
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

## 分层边界

- `Sources/AgentDeck/`：macOS 原生 UI、会话模型、历史回放和本地交互。UI 只能通过 `CapabilityRouter` 消费 `SessionCapabilities` 决定渲染路径，禁止直接读 vendor 字段或硬编码 `if agentKind == .codex` 分支。
- `agentdeck-protocol/`：IPC 协议事实源 crate。分 trunk / capabilities / vendor / transport 四个模块，`PROTOCOL_VERSION` = 2，`protocol_schema()` 聚合所有 v2 类型。
- `agentdeckd/src/ipc.rs`：re-export `agentdeck-protocol::*` 壳，保持 daemon 内 `crate::ipc::X` 引用不变。
- `agentdeckd/src/agent.rs`：`Agent` trait + `AgentKind` 枚举。两个 adapter 共享的逻辑在此，不得让 adapter 相互引用。
- `agentdeckd/src/runtime/`：`RuntimeHub`（stdin loop + stdout writer）+ `AgentRouter`（sessionId → agentKind → adapter）。
- `agentdeckd/src/codex/`：Codex app-server adapter。Codex vendor JSON、方法名和 schema 翻译只能留在此子模块。
- `agentdeckd/src/claude_code/`：ClaudeCodeAdapter。`claude` CLI 子进程接入，stream-json 解析，CC 特色能力（auth / history / permission / hooks）实现在此。
- `agentdeckd/src/record.rs`：run record 写入与脱敏，写入包含 `agent_kind` 字段。
- `agentdeckd/src/diag.rs`：诊断日志、自检和机器可读诊断报告，诊断事件带 `agent_kind`。
- `agentdeck-cli/`：参考客户端与门控 E2E 驱动。提供 `agentdeck` 二进制，不在 Swift GUI 实时通路上。
- `protocol/`：官方 Codex app-server schema 快照和 spike 事实源。
- `protocol/agentdeck/`：AgentDeck 自身中立协议 JSON Schema 快照（schemars 派生，`cargo test` 漂移测试守护）。
- `docs/plans/`：设计、实施计划和决策历史。

## 不变量

### 废止的旧不变量（v0.1，v0.2 起不再适用）

| # | 旧不变量 | 废止理由 |
|---|---|---|
| W1 | Swift 层不得解析 Codex vendor JSON | 新方向要求 vendor SubView 直接消费 vendor 类型 |
| W2 | 中立 IPC 中不出现 vendor 字样 | 改成「主干中立 + vendor 命名空间允许 vendor 前缀」 |
| W3 | Codex 持久化策略字段只能留在 daemon adapter | persistence 必须在 UI 暴露 |

### 保留的不变量（K 系列，v0.1–v0.2）

- **K1**：daemon 的 stdin 主循环不得被单个 turn 阻塞；长时间工作放到 worker。
- **K2**：`RuntimeHub` 必须按 `sessionId` 阻止同一 runtime 并发 turn；session 创建时 `agentKind` 不可变，整个生命周期固定到一个 adapter。
- **K3**：turn 成功完成时，worker 必须先释放 session 占用，再向 Swift 发出可触发下一条 prompt 的 ready / `turnComplete` 事件。
- **K4**（加强）：所有事件主干消息必须带 `agentKind` 字段。
- **K5**：run record 与 diagnostic log 写入 `~/Library/Application Support/AgentDeck/`（stable）或 `AgentDeck-Dev/`（dev），不得写入用户项目 git。
- **K6**：`AGENTDECK_DATA_DIR` / `--profile` / `AGENTDECK_PROFILE` 控制数据目录隔离，不影响 vendor 登录状态或 vendor 历史。
- **K7**：写入前做 best-effort 密钥脱敏；写失败不能静默，必须在可诊断位置暴露。
- **K8**：vendor schema 不手写，Codex 协议来自官方 `codex app-server generate-json-schema`。
- **K9**：AgentDeck 不读取、不保存、不转发任何 vendor token（Codex 或 Claude Code）。
- **K10**：`schema_matches_committed_snapshot` 漂移测试随 `cargo test` 运行；协议类型变更未重生成快照则失败。

### 新增不变量（N 系列，v0.2 起）

| # | 不变量 | 守护方式 |
|---|---|---|
| **N1** | **两层协议**：`AgentItem` / `TurnComplete` / `SessionStarted` / `SessionCapabilities` / `Error` 主干必须 vendor 中立；vendor 字段默认只能出现在 `capabilities.*` / `vendorControl.*` / `vendorPanel.*` 三个命名空间下。唯一例外是 `ActionRequest.vendor`，用于 typed approval detail，禁止任意 JSON 透传 | schemars 派生 + `neutrality_tests.rs` 静态断言 |
| **N2** | **Capabilities Handshake**：每个 session 启动时 daemon 必须先发 `SessionCapabilities`；UI 必须按它路由控件渲染；禁止 UI 硬编码 `if agentKind == .codex` 分支 | Swift 端 `NoVendorBranchInUITests` grep + AST 扫描 |
| **N3** | **Adapter 互不知晓**：`agentdeckd/src/codex/` 不依赖 `claude_code/` 任何类型，反之亦然；共享逻辑下沉到 `agent.rs` trait | cargo 模块依赖检查 |
| **N4** | **Adapter 内 vendor JSON 不外泄**：被 IPC 推到 UI 的 vendor 字段必须经 adapter 显式建模，禁止 `serde_json::Value` 透传 | `capabilities_namespace_is_typed` 测试断言 |
| **N5** | **一等公民对称约束**：`CodexAdapter` 实现的每个非独有 capability，`ClaudeCodeAdapter` 必须有等价实现或文档化"不适用"原因 | capability 矩阵文档 + cargo test |
| **N6** | **Transport trait 远程预留**：v0.2 实现 `Transport` trait（仅 stdio），但 trait 必须能支持 remote（异步、可重连、可携带 auth context） | 编译期 trait 定义 |
| **N7** | **`SessionCapabilities` 必须先于该 session 任何 `AgentItem`** | 集成测试断言序 |
| **N8** | **CC 数据事实唯一来源**：AgentDeck 不为 CC 维护任何元数据层；不在 `~/Library/Application Support/AgentDeck/` 下创建 `cc-meta/` 目录 | code review + 文件存在性断言 |

### Relay R1a 不变量（传输 + 鉴权骨架，历史）

本节只记录 v1 探索期约束；相关协议、server/client 与生产路径已在 P2.9 物理删除，
不得据此实现兼容或启动当前 Relay。

- **R1a-1**：`agentdeckd` 依赖树无 `tokio net` 或 `axum`——保证 daemon 至 R2 前始终无网络代码；guard `scripts/check-daemon-no-net.sh`
- **R1a-2**：`agentdeck-cli` 依赖树无 `axum`——CLI 只走 WS client 不做 server
- **R1a-3**：net/axum 仅限 `agentdeck-relay` 的 `server` feature + `agentdeck-relay-client` crate
- **R1a-4**：`relay` 数据目录独立于 daemon/CLI，只存不透明数据 + 公钥材料 + credential 哈希（**不**存明文 credential）
- **R1a-5**：非 loopback 绑定强制 TLS（`RelayConfig::validate_transport_gate`），除非显式 `--allow-plaintext` 明文告警
- **R1a-6**：`thiserror` 单版本 1.x、`rand_core` 单版本 0.6（与 dalek 2.x 对齐）
- **R1a-7**：一条 `RemoteFrame` = 一条 WS text 帧（`serde_json` 序列化）；`RELAY_PROTOCOL_VERSION` 变更需协商
- **R1a-8**：`DataEnvelope` bytes wire 为 base64 string（**不**是数字数组）

### Relay R1b 不变量（SQLite 持久化 + Router 健壮化，历史）

- **R1b-1**：relay 持久化状态（accounts/devices/challenges/seq 高水位/事件元数据）全部落 SQLite（`rusqlite` + `bundled`），单一 `--storage` 路径文件；**事件内容（`payload`）本期恒为 NULL，不落盘明文**（R1c 引入加密后翻转）。
- **R1b-2**：`conv_buffer` 每 conversation 有硬上界（默认 1000，可配置），独立于 Ack 生效，防 OOM。
- **R1b-3**：重放补拉（`since_seq`）语义为 **relay 进程存活期内** 的有界补拉，不是跨重启完整历史重放；窗口外返回 `relay.replay.gap`。
- **R1b-4**：`RelayLink::recv` 仍不返回 `Result`（R2 defer，见 R1b 设计 §4.1）。

### Relay Companion MVP P0 迁移边界（历史）

- P0 冻结上述 Relay v1 schema 与行为基线，不扩展 v1 产品能力，也不改变现有
  Rust/Swift 生产路径。
- `scripts/reset-relay-v1-dev-state.sh` 只是 v1 开发状态的显式 trust reset：调用方
  必须先停止 Relay，并提供 canonical absolute DB 与 credential 路径及固定确认串。
- reset 的删除集合固定为 DB、同路径精确 `-wal` / `-shm` 与指定 bearer JSON。
  path/schema/credential/DB 行关联与 unlink preflight 全部通过前不开始 unlink；
  删除前任一 validation/preflight 失败都零删除。preflight 后 OS unlink 仍失败时
  允许部分删除，但必须非零退出并列出全部 remaining exact paths，不宣称成功、
  不承诺 rollback；残留需人工清理后重新配对。
- reset 不提供开发状态恢复或迁移；成功后只能重新配对。P0 统一门禁入口是
  `bash scripts/verify-relay-companion-mvp.sh p0`。

### Relay Companion MVP P2.1 v2 Store actor 边界

- P2.1 当时在 `agentdeck-relay::v2::store` 建立与 v1 并列的 library；该阶段隔离
  已于 P2.9 的原子切换结束，当前 production binary 只走 v2。
- 一个 bounded async command queue 只通向一个 blocking worker；队列满时立即返回
  typed busy，不保留任意数量的等待请求。该 worker 独占
  唯一 `rusqlite::Connection`。async router 不持有 connection，也不能绕过 actor
  直接执行 SQL。worker 停止或未回复必须返回 typed `StoreError`。
- machine/grant/stream/enrollment、Publish/HWM/retention、subscription/ACK、revoke
  tombstone 与 purge readback 分别在 `BEGIN IMMEDIATE` 事务中完成；需要持久化的
  成功只能在 COMMIT 后返回。fault injection tests 固定 COMMIT 前 rollback 与
  COMMIT 后结果未知的 exact canonical retry/重启幂等语义；成功 COMMIT 后不再执行会被
  上层误判为 rollback 的普通可失败 readback。
- startup/显式 full maintenance 用 keyset 常量内存遍历并收敛所有硬配额；replay
  只检查并清理目标 stream 的逻辑过期行，正常无过期 replay 不开启写事务。
  P2.6 只负责 full maintenance 周期调度与 lifecycle，不在 actor 内藏永久 timer。
- Relay 只保存随机 route、公钥/证书 hash、单调 generation/serial、sequence、
  Relay 计算的 receive time/size 与 opaque sealed bytes；challenge、PairRoute、
  active writer 和业务目录不进入 v2 SQLite。
- `RelayV2StoreSettings` 是独立运行配置面，覆盖 stream/machine/global retention、
  bounded replay、enrollment code count 与磁盘 reserve；显式转换在 worker 启动前校验生产绝对路径与
  hard maxima。它不复用 v1 的相对 `--storage` 默认值，也不改变 v1 行为。
- Store 打开必须读回 WAL/FULL/foreign_keys/5s busy timeout；existing/new
  目录与 DB 都必须由当前 uid 持有且权限为 0700/0600。schema
  family/version/DDL signature 不匹配、legacy v1、高版本或损坏
  DB 均 fail-closed，不自动恢复或降级。
- hot-WAL inspection snapshot 在复制前持久化 source-bound marker 并持有排他锁；
  restart cleanup 只接受 exact marker、owner/mode、child allowlist 与 unlocked 四重
  证明，逐文件删除后 `remove_dir`，禁止前缀 `remove_dir_all`。

### Relay Companion MVP P2.2 v2 链路鉴权边界

- P2.2 当时以隔离 library 建立链路鉴权；当前 production listener 已在 P2.9 接管。
  Relay v2 的签名字节事实源
  位于 `agentdeck-protocol::relay_v2::auth`：credential unsigned/full canonical bytes、
  root-signed `ToBeSignedV1` 与 `AuthenticationTranscriptV1` 都使用独立 domain、长度前缀
  和大端数字，禁止复用明确声明“不参与签名”的 outer frame codec。
- `agentdeck-crypto` 只暴露 typed authentication-transcript sign/verify；Relay 复用该 crate
  的 Ed25519 实现，不建立第二套 raw-sign API。challenge transcript 逐字节绑定 nonce、
  connection instance、relayServerId、Relay version、machine/device route、generation/
  serial 与包含 root signature 的 credential hash。
- `ChallengeRegistry` 只存在于内存：30 秒起精确过期、全局最多 4,096、同一 mutex 内
  one-shot consume。source 与目标 route 分别使用可配置 token bucket，pending/source/
  route 三类 map 都有 hard count；bucket idle TTL 只能在 30 秒到 5 分钟内配置，禁止
  用 `u64::MAX` 实际关闭清理。Registry 不保存原始 source identity，
  不写 SQLite。
- 鉴权顺序固定为：消费 challenge → 读取 machine/device trust snapshot → 验
  MachineRoot cert/grant signature → 验 endpoint challenge signature →
  `AuthorizationCoordinator` 把 principal route fence 为 `Transitioning` → Store 串行
  `commit_machine_link_auth` / `confirm_device_auth` → 在同一个无 await 的 actor poll 中提交
  active generation。`Transitioning` 对数据面等价于非 current；Store 失败只恢复仍未断开的
  previous entry，COMMIT 成功后不得出现旧 generation 可见窗口。Device Authenticate 不能
  绕过 `InstallGrant` 自行安装 higher serial。
- 同一 `RelayStoreHandle` 的共享 ownership 只允许启动一个 `AuthorizationCoordinator`；claim
  与 raw/authorized trust command 的 `try_send` admission 共用 mutex，保证 admission 顺序即
  Store worker FIFO 顺序。owner 存活期间，raw register/install/auth-confirm/revoke/purge
  mutator 与 raw Store shutdown 固定 fail-closed；P2.3/P2.5 Core 必须把所有 trust mutation
  送入该 coordinator。相同 platform-normalized DB path 在同一进程只能有一个 live Store
  worker，第二次 `open` 直接拒绝，避免多 worker 破坏 admission FIFO。P2.6 又在数据库同目录
  持有 `<db>.agentdeck.lock` 的 0600、`O_NOFOLLOW` OS 排他锁，覆盖不同进程；锁文件可持久存在，
  锁的所有权只随 Store worker 生命周期持有和释放。
- active replacement / invalidation 还必须先写入独立 bounded lifecycle channel，再回复
  caller oneshot。普通槽 512；overflow 使用不依赖普通队列的单独 emergency slot，并把普通
  backlog 中的 connection IDs 去重合并成 terminal `FailClosedAll`，之后不再返回 stale
  `Activated`。P2.3 Core 必须持续 drain 并关闭列出的全部 writer/control slot；caller future
  cancellation 不取消已入队转换，也不能吞掉 writer ID。receiver Drop 同步 poison 并清空
  registry；coordinator shutdown 也必须先清 active/投递 lifecycle，再释放 owner，随后才允许
  raw Store shutdown。
- coordinator public admission 在进入 256-command queue 前先校验 enrollment/revocation
  control blob 的 64 KiB hard bound；不能只在 actor 出队时校验而让 queue bytes 无界。
- active registry 以 machine route 或 `(machine route, device route)` 为 key；same authority
  + same credential 可重连替换，lower 或 same/different 均拒绝。旧连接退出只能
  `remove_if_current`；P2.3 Core 还必须在 command 出队时调用 `is_current`，防止 replacement
  前排队的旧 frame 污染新 connection 状态。
- P2.2 的 `PairingHello` 起初只定义 auth library 元数据而未固定 carrier；P2.6 将最小
  `relayServerId + pairRoute` 追加为 TLS 建立后的 canonical binary frame。route 不进入
  URL/query/access log；server 自行绑定 connection instance 与 protocol version。
  `PairingAccess` 仅允许 active、未过期 route 上的同 route `PairData` /
  `ClosePairRoute`，其他 frame 统一拒绝。
- auth access、challenge、credential、public key/signature 等 `Debug` 输出必须脱敏；route
  关联标识使用带类型域 SHA-256 的 32-bit 截断，不得直接打印 route 原始前缀。failure 只
  返回稳定通用 code/message，不泄漏完整 route、key、hash、signature 或验签步骤。

### Relay Companion MVP P2.3 v2 Stream Core 边界

- P2.3 当时以隔离 library 建立 Stream Core；当前 production listener 已在 P2.9 接管。唯一
  `RelayCore` actor 线性裁决 stream mutation；公开入口只有有界 command count 与
  64 MiB ingress byte admission，队列满立即返回 typed quota；所有可配置容量还有不可调高的
  代码级 hard maximum（command 4,096、ingress 256 MiB、connection 4,096、每连接
  subscription 4,096、replay staging page 16）。actor 可以等待 Store，但绝不等待 socket；
  每次命令出队、Store 返回和 replay page 入队前都重新验证当前 `AccessContext` 与
  authorization generation。所有 live/replay Publish、Gap 与 ReplayComplete 的授权检查和
  writer enqueue 都在 `with_current` 的同一 active-registry 临界区内线性化；transition fence
  之后旧 generation 不得再跨出任何一帧。
- `RegisterStream` / `Publish` 只接受 MachineAccess，`Subscribe` / `Unsubscribe` / `Ack`
  只接受 DeviceAccess；PairingAccess 和 endpoint 伪造的 server-only frame 固定拒绝。
  Publish 只有在 SQLite COMMIT 后才允许 fan-out 和向 origin 入队 `RouteAccepted`；COMMIT
  后先为 origin acceptance 占聚合 normal permit，再投递 readers，避免慢读者反向关闭健康的
  machine writer。COMMIT 后响应丢失的 canonical retry 会修复 fan-out，但已经推进的订阅
  不会重复交付。
- 每条 connection 只有一个 actor-owned runtime subscription map 和一个 active replay。
  多个 stream 可同时订阅，额外 replay 进入受每连接 subscription hard cap 约束的 FIFO；
  当前 replay、catch-up、gap 或 unsubscribe 终结后才启动下一项。这样 Companion 可同时
  观察多个会话，又不会让单连接并发物化多页 ciphertext。
- `Subscribe` 的 `replay_through` 与 durable lease 在同一 SQLite transaction 冻结。
  replay 的每次请求取 writer 当前可用预算、Store 配置与协议 hard maximum 三者最小值，
  上限仍为 64 frames / 8 MiB；拉取前必须原子预留整页 writer normal 预算，全局同时最多
  物化 2 页。Store 瞬时 `WorkerBusy` 释放 writer/staging 预算后做三次可取消退避，不把合法
  reader 误判为失效。每页重新校验 canonical size/hash/sequence/boundary；最后一页全部进入
  同一 FIFO 后异步等待 control reserve，再发送唯一 `ReplayComplete`，因此 tiny writer 与
  同时排队超过 16 个空 replay 都不会被误断。
- 冻结边界后的并发 Publish 只推进 `missed_hwm`，由 post-terminal catch-up 串行追赶；
  `ReplayComplete` 不移动。hot stream 每完成一个 catch-up quantum 就轮转到 replay FIFO 尾部，
  不能饿死其他 stream。live sequence 跳跃或 retention gap 会发送保留容量内的 `Gap` 并暂停
  该 stream，显式同 generation re-Subscribe 前不得继续交付更高 sequence。
- writer normal 默认 512 frames / 16 MiB，control reserve 为 16 frames / 1 MiB；两类预算
  共用一条 FIFO，socket flush 前一直占用；全 Core 另有独立的聚合 normal 16,384 frames /
  256 MiB 与 control 4,096 frames / 16 MiB 默认预算，normal 不能消耗 control reserve。
  per-writer 或 global normal/control 耗尽、delivery 丢失或 receiver 退出均 fail-closed，且只
  清理对应慢连接。heartbeat 每 20 秒发送 Ping，仅 exact pending Pong 刷新；60 秒边界关闭。
  replacement、revoke、lifecycle terminal 与 shutdown 都取消 replay、关闭 writer、清 runtime
  并确定性 join 后台 task；registry entry 还有 Drop guard，覆盖 Core future 被 runtime 取消或
  panic 的最后关闭路径。durable subscription/ACK 仅由显式 Store mutation 改变。
- 空 stream 与 durable subscription 同样是受限元数据：默认每 machine 4,096 streams、全局
  65,536 streams、每 device 4,096 subscriptions、全局 262,144 subscriptions；新增 row 还需
  额外 64 KiB 磁盘增长余量。幂等 retry 不重复占容量，配置下调或旧 DB 已超限时在 Store
  ready 前 typed fail-closed，不静默删除 durable state。
- Core、writer、replay 的 Debug 只能打印计数、failure code 和带类型域的 route 短 hash；
  不格式化 sealed bytes 或完整 route/generation。本节单元测试本身不等于部署证据；
  production cutover 与真实 Direct TLS synthetic 分别由 P2.9/P2.10 门禁证明。

### Relay Companion MVP P2.4 PairRoute 与在线请求边界

- P2.4 当时以隔离 library 建立 PairRoute 与在线请求；当前 production listener 已在 P2.9
  接管。`PairRouteRegistry` 只由
  `RelayCore` actor 修改且不落 SQLite：默认/不可调高上限为每 machine 8、全局 1,024、
  每 route lifetime 32 frames / 1 MiB、absolute TTL 300 秒；每 route 独立 burst 8、
  refill 2 frames/s。Close 后保留到 absolute expiry 的 bounded tombstone 并继续占容量，
  防止迟到 Open 复活；Core 重建则按设计清空全部 active/tombstone，由 daemon 以同一
  route/absolute expiry 重开。
- 只有 current `MachineAccess` 可以 Open；owner/route/expiry 完全相同才是幂等 retry。
  Pairing handshake 先读取单 route view，activate 时在 actor 内二次验证并绑定唯一 pairing
  writer，封住 view→activate TOCTOU。Pairing 数据面只允许同 route `PairData` /
  `ClosePairRoute`，另有 exact outstanding `Pong` 这一 transport-control 例外；每帧都重验
  active、expiry 与 binding。断线只解绑，close/expiry 才终结 route。
- `PairData` 使用 canonical outer frame bytes 计 lifetime 容量，并采用 reserve→target writer
  enqueue→commit 两阶段计数。目标背压会 rollback lifetime 计数、关闭目标并向 origin 返回
  typed quota；rate token 不退，避免离线目标被无限探测。目标成功入队后才向 origin 入队
  `RouteAccepted(PairFrame)`；origin ACK 背压只关闭 origin，不回滚已发生的目标入队。
- `Send/Reply` 是纯在线、无状态路由：Device 只能声明自身 device route 并 Send 到所属
  machine，Machine 只能 Reply 到同 trust domain 的 current device；`requestRoute` 只作 opaque
  correlation ID，不建立 `req_origin`、seen-map 或 TTL-map，也不写 frames/subscriptions/HWM。
  target 和 origin 两个普通 principal 的 current-generation 检查与 target enqueue 在同一
  active-registry 临界区内完成；任一 replacement/revoke transition fence 建立后，旧
  generation 都不能再跨出 frame，且旧 origin 不能借失败请求关闭健康 target。
- PairData/Send/Reply 都遵循 target-first：只有目标 bounded writer 接纳后才产生
  `RouteAccepted`；该回执不代表 socket flush、解密、journal、执行或 PairResponse delivered。
  PairRoute/online request 的 Debug 与 failure 同样只暴露通用 code、计数和脱敏短 hash。

### Relay Companion MVP P2.5 授权撤销与退役边界

- P2.5 当时以隔离 library 建立撤销/退役 contract；当前 production listener 已在 P2.9
  接管。`DeviceRevocation` 与
  `RetireMachine` 的 unsigned/full canonical bytes、SHA-256 和 MachineRoot `ToBeSignedV1`
  由 `agentdeck-protocol` 唯一定义；`RetireMachine` 显式绑定 `rootKeyId`。既有 wire kind
  0–27 保持不动，严格最小的 `RetirementCommitted(machineRoute, trustEpoch, retireHash)`
  追加为 kind 28，Rust/Swift 共用 golden fixture。
- 只有 current、同 trust domain 的 `MachineAccess` 可以 InstallGrant/Revoke/Retire。
  AuthorizationCoordinator 在同一 active-registry 锁内复核 origin 并建立 device/整机
  transition fence；然后才读取持久 trust、验 MachineRoot signature 并进入 Store。
  fault/rollback 恢复旧 generation；只有 SQLite COMMIT 后才永久失效旧 generation。
- production control path 只接受 typed wire object并自行派生 grant/revocation/retirement
  hash 与 canonical terminal blob；Store raw mutator只作为事务级测试入口，
  `AuthorizationCoordinator` 不公开 raw install/revoke/purge 旁路。Install duplicate
  使用 same serial/same full hash，higher serial才替换；显式 revoke 后同 device route永久
  tombstone，不能靠 higher serial复活。device metadata硬上限为每 machine 256、全局 65,536。
- writer 在既有 Data/Control 预算外拥有每连接一个、全 Core 4,096 frames / 16 MiB 的独立
  terminal reserve。COMMIT 后原子拒绝新普通 enqueue、丢弃尚未出队的 Data/Control、取消
  replay/subscription，并发送唯一 terminal；最多一个已经交给 socket 的旧 frame可自然完成。
  terminal flush 后立即关闭，未 flush 从 COMMIT-observed 起最多 2 秒关闭。普通
  `Invalidated` 不得抢先清掉 terminal；`FailClosedAll`、shutdown、receiver/delivery failure
  仍立即覆盖。terminal state 与 queued/in-flight delivery 共享一份 immutable bytes；幂等
  admission 复用既有唯一 drain token，不重复 spawn deadline，connection ID 复用则分配新 epoch。
- Revocation row保存 exact `RevocationCommitted` outer bytes。只有完整验证 current root-signed
  grant 与 DeviceSign challenge proof 后才返回该 terminal；伪造者仍只见
  `relay.auth.invalid_grant`。retired machine tombstone保留公开 root/link proof material、
  `retirementHash` 与 exact terminal bytes，清除 device grants、revocations、subscriptions、
  streams、frames、PairRoute 与 data cert active material；旧 exact MachineLink proof只读回
  retirement terminal，绝不恢复 active route。
- terminal-only auth outcome 是 coordinator 独占构造的不可克隆 capability；Core 只允许它绑定
  尚未 active 且 principal 匹配的 pending writer，并复核 terminal kind/route/serial 或 trust epoch。
  active entry 不能借该 API 被伪造 terminal 关闭。
- purge 在 COMMIT 前的同一事务内按删除前冻结的 stream key 直查 frame、核对 foreign keys、
  retirement hash/exact terminal 与
  `active/retired/grants/revocations/streams/frames/subscriptions = 0/1/0/0/0/0/0`；成功 COMMIT
  后不再执行可返回普通 rollback error 的 I/O。若 COMMIT/回执结果未知，Store 以同一 canonical
  request 精确重试；恢复仍失败则不恢复旧 generation，整机 retirement 会终止 Core 以清空
  PairRoute。未知 route
  不是成功。admin root-lost purge沿用同一 primitive但 terminal hash为空，详细 authority 与
  root fingerprint 确认已由 P2.7 本机 0600 admin UDS 承载。

### Relay Companion MVP P2.6 TLS、可用性与生命周期边界

- P2.6 建立的 v2 server 已在 P2.9 成为唯一 production dispatch。公开面只有固定
  `/v2/connect` 与 `/v2/pair` WebSocket path；配对 route 由
  TLS 后 canonical binary `PairingHello` 传入，query 不承载 route。public listener 不挂
  health、inventory、purge 或 redirect。
- WebSocket 聚合前先受 4 MiB max-frame/max-message 限制，协议层只接受 binary canonical
  v2 frame。全服务另有 64 MiB ingress semaphore；每次 poll 前预留 raw+decoded 最坏预算，
  得到小 frame 后缩到实际 encoded size 的两倍，并持有到 Core 完成本次处理。公开 accept
  queue、连接、Core command、writer 与 Store 都保持独立 hard bound。TCP accept 前还必须
  取得全局 1,024 物理连接 permit；permit 随底层 IO 穿过 HTTP upgrade 到 WebSocket 关闭。
  从 accept 起 5 秒内必须完成 TLS handshake、完整 HTTP/1 header 与成功 101 upgrade，解密后
  request line + headers 最多 64 KiB。只有 handler 确认返回 101 才解除 deadline；全部非 101
  响应强制 `Connection: close`，避免慢连接或普通 HTTP keep-alive 绕过已认证连接上界。
- direct 模式在任何 bind 和 DB side effect 前读取最多 1 MiB 的 cert/key PEM、校验 keypair，
  并要求 binary 含 `tls` feature；任一失败都不回退明文。明文只允许显式
  `InsecureLoopback`，proxy 模式也只允许 loopback backend；health listener 永远 loopback。
  config 逐字段遵循 CLI > env > TOML > defaults，TLS pair 按层原子选择，storage 必须绝对路径。
  `ProxyLoopback` 唯一接受的来源元数据是恰好一个 canonical
  `x-agentdeck-client-ip: <IP>`；可信反代必须先删除外部同名 header，再用实际 TCP peer IP
  覆写。backend 只绑定 loopback，因此同主机进程属于部署信任/DoS 边界；direct 模式忽略该
  header 并始终采用 TCP peer。
- `/healthz` 只表达进程存活；`/readyz` 只读周期探针缓存。Store readiness 会验证 schema/
  PRAGMA、磁盘 reserve，并用 metadata no-op COMMIT 实际经过 WAL/FULL 写路径；disk-low、
  Store fault、Core tick压力或 drain 均使 readiness typed fail-closed，HTTP 请求本身不占 Store
  queue。full maintenance 每 60 秒调度，readiness 每 5 秒，Core tick 每 1 秒。
- drain fence 顺序固定为：原子停止新 accept/connection登记，向 snapshot 中所有 writer 发送
  `ServerRestarting`，再对 AuthorizationCoordinator 与 RelayCore 建立 FIFO drain fence。
  网络最多等待 5 秒，超时强制 abort listener/connection；随后仍必须真正 shutdown
  Core/Auth/Store并释放 OS process lock，不能用超时返回伪装 quiesce。Core shutdown 即使
  返回错误也不得跳过 Store shutdown；Store shutdown 回执必须晚于 DB connection、OS lock
  与进程内 lease 的释放。SIGTERM、Ctrl-C、显式
  cancellation 和 handle Drop 最终进入同一资源回收路径。
- 日志只允许稳定 event/failure code和计数；source 只保存进程随机 key 的 hash，TLS path、
  route、key、signature、sealed bytes 与输入 sentinel 不进入日志。测试必须同时覆盖正向事件
  存在与敏感值零命中，不能用“完全没有日志”冒充 redaction。

### Relay Companion MVP P2.7–P2.10 production 边界

- P2.7 的 host 管理面只存在于本机 0600、同 UID、有界 JSONL admin UDS；公开网络
  只新增 `POST /v2/machine-enroll`。enrollment code 为一次性 256 bit / 5 分钟，SQLite
  只保存 hash。code 消费、machine trust 写入、canonical request hash 与冻结 response/
  receipt 在一个 transaction 内提交；inventory、fingerprint-bound readback/purge 从不
  暴露到网络 listener。MachineRoot 丢失只支持 purge 后重新 enroll/配对，不提供恢复。
- P2.8 的 outbound client 默认不依赖 Relay server/store。principal 与 pairing 各有严格
  typed 状态机，fresh challenge、CA/hostname/SPKI、bounded single reader/writer、heartbeat、
  outcome-unknown、signed terminal 原字节都 fail-closed。TLS/SPKI 完整验证前绝不发送
  enrollment code、MachineRoot 或其他秘密材料。
- P2.9 原子删除 Relay v1 protocol/server/client/daemon bridge 与测试源码，production binary
  只装配 v2 Store/Auth/Core/Admin/Server。`/v1/connect` 唯一遗留行为是无状态 HTTP 426：
  不升级 WebSocket、不查询 Auth/Store、不协商降级。production 只允许 Direct TLS/WSS；
  loopback 明文与 proxy 需要显式配置且只用于受控开发。
- 旧 v1 credential marker 不属于自动迁移输入。CLI 只用 `symlink_metadata` 判断 marker
  是否存在；存在、悬空 symlink 或 metadata 错误均返回 `remote.v1.reset_required`，绝不打开、
  解析、删除或拨号。清理只能由显式 reset 脚本执行，之后重新配对。
- `agentdeck remote synthetic --bundle FILE` 驱动一个真实外部 Direct TLS listener，使用
  临时 machine/device identity 完成 enrollment、fresh challenge auth、InstallGrant、stream
  replay、Send/Reply、signed revoke 与终态重连；它不保存身份。P4 前持久 remote 命令固定
  返回 `remote.persistent.unsupported`。
- P2.10 hardening/security suites 以真实 Store/Core/server 证明跨重启逐字节 replay、gap、
  quota、disk-low、fault、drain/shutdown、撤销/退役和多 sentinel 密文扫描；Relay 可见
  outer/response、tracing、health/ready/metrics HTTP surface 与 SQLite DB/WAL 均不得出现
  应用明文。`scripts/check-daemon-no-net.sh` 继续守护
  `agentdeckd` 无网络依赖，P2.10 不越界声称 daemon/iOS 已接入。

### R1a 隐含约束（历史参考）

- **R1a machine_id ≡ device_id**：`server/ws.rs::connect` 用 `device.device_id` 作 `ConnRole::Machine.machine_id`，`router.rs` RegisterMachine 授权强制 `machine.machine_id == connection.machine_id`——**enrolled 的 machine 设备的 `machine_id` 严格等于 `device_id`**。CLI 生成的随机 `device_id = "cli-<profile>-<random>"` 会锁定 R2 daemon remote-mode 里对应 machine 的 identifier；R2 设计需评估是否解耦 machine_id 与 device_id（例如 machine 元数据里显式携带独立 machine_id）。

## 依赖方向

```text
Swift UI
  -> CapabilityRouter（按 SessionCapabilities 派发）
  -> WorkbenchModel / ThreadRuntimeModel / SessionModel / HistoryModel
  -> AgentDeck IPC models（来自 agentdeck-protocol v2）
  -> daemon stdio

daemon main
  -> ipc（re-export agentdeck-protocol）
  -> AgentRouter → CodexAdapter / ClaudeCodeAdapter
  -> record / diag
  -> codex app-server child process / claude CLI child process

agentdeck-cli（参考客户端 / E2E 驱动，与 GUI 互相独立）
  -> agentdeck-protocol（共享类型）
  -> Transport trait（ProcessTransport → daemon stdio）
  -> daemon child process
```

允许的跨层访问应沿上图向下：
- UI 不允许跳过 `CapabilityRouter` 直读 vendor 字段。
- `CodexAdapter` 不允许调 `ClaudeCodeAdapter`，反之亦然。
- 新增功能如需反向依赖，先把接口下沉到 `agent.rs` trait 或 `agentdeck-protocol`。

## 协议即契约

`agentdeck-protocol` crate 是 IPC 协议的唯一事实源：

- `PROTOCOL_VERSION`：当前为 2（v0.2 起）。
- `protocol_schema()`：schemars 从 Rust 类型派生的 JSON Schema，聚合所有 v2 公共类型。
- 快照：`protocol/agentdeck/agentdeck-protocol.schema.json`（`UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` 重生成）。
- 漂移测试随 `cargo test` 运行。
- 中立性测试（`neutrality_tests.rs`）守护 N1/N4。

## 变更指引

- **改 UI 行为**：先看相关 `Sources/AgentDeck/*ViewController.swift` / `*Model.swift` 与最近的 `docs/plans/*design.md`。确认 `CapabilityRouter` 路由路径是否需同步更新。
- **改 IPC**：同步更新 Swift/Rust 两侧模型、测试、schema 快照和 README/架构文档。
- **改 Codex 协议翻译**：先看 `protocol/SPIKE_FINDINGS.md` 和 `protocol/CODEX_VERSION.txt`，再改 `agentdeckd/src/codex/` 子模块。
- **改 CC 协议翻译**：先看 `docs/plans/2026-06-30-unified-shell-v02-design.md` § 5，再改 `agentdeckd/src/claude_code/` 子模块。
- **改诊断或记录**：同步更新 `docs/AGENT_DIAGNOSTICS.md` 和 `docs/QUALITY.md`。
- **新增 adapter**：在 `agentdeckd/src/<vendor>/` 下建子模块，实现 `Agent` trait；在 `AgentRouter` 注册；在 `agentdeck-protocol` 的 `VendorCapabilities` / `VendorSessionOptions` 枚举中添加对应 variant；更新 `agentdeck-cli` 的 `--agent` 可选值。新 adapter 不得要求 Swift 侧知道该 adapter 的 vendor JSON（N2），也不得修改现有 adapter capability（N5）。
