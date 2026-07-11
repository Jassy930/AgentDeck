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

### Relay R1a 不变量（传输 + 鉴权骨架）

- **R1a-1**：`agentdeckd` 依赖树无 `tokio net` 或 `axum`——保证 daemon 至 R2 前始终无网络代码；guard `scripts/check-daemon-no-net.sh`
- **R1a-2**：`agentdeck-cli` 依赖树无 `axum`——CLI 只走 WS client 不做 server
- **R1a-3**：net/axum 仅限 `agentdeck-relay` 的 `server` feature + `agentdeck-relay-client` crate
- **R1a-4**：`relay` 数据目录独立于 daemon/CLI，只存不透明数据 + 公钥材料 + credential 哈希（**不**存明文 credential）
- **R1a-5**：非 loopback 绑定强制 TLS（`RelayConfig::validate_transport_gate`），除非显式 `--allow-plaintext` 明文告警
- **R1a-6**：`thiserror` 单版本 1.x、`rand_core` 单版本 0.6（与 dalek 2.x 对齐）
- **R1a-7**：一条 `RemoteFrame` = 一条 WS text 帧（`serde_json` 序列化）；`RELAY_PROTOCOL_VERSION` 变更需协商
- **R1a-8**：`DataEnvelope` bytes wire 为 base64 string（**不**是数字数组）

### Relay R1b 不变量（SQLite 持久化 + Router 健壮化）

- **R1b-1**：relay 持久化状态（accounts/devices/challenges/seq 高水位/事件元数据）全部落 SQLite（`rusqlite` + `bundled`），单一 `--storage` 路径文件；**事件内容（`payload`）本期恒为 NULL，不落盘明文**（R1c 引入加密后翻转）。
- **R1b-2**：`conv_buffer` 每 conversation 有硬上界（默认 1000，可配置），独立于 Ack 生效，防 OOM。
- **R1b-3**：重放补拉（`since_seq`）语义为 **relay 进程存活期内** 的有界补拉，不是跨重启完整历史重放；窗口外返回 `relay.replay.gap`。
- **R1b-4**：`RelayLink::recv` 仍不返回 `Result`（R2 defer，见 R1b 设计 §4.1）。

### Relay Companion MVP P0 迁移边界

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

- P2.1 在 `agentdeck-relay::v2::store` 建立与 v1 并列的 library；生产 binary、
  listener 与 CLI 仍走 v1，直到 P2.9 原子切换，禁止提前形成双栈生产入口。
- 一个 bounded async command queue 只通向一个 blocking worker；队列满时立即返回
  typed busy，不保留任意数量的等待请求。该 worker 独占
  唯一 `rusqlite::Connection`。async router 不持有 connection，也不能绕过 actor
  直接执行 SQL。worker 停止或未回复必须返回 typed `StoreError`。
- machine/grant/stream/enrollment、Publish/HWM/retention、subscription/ACK、revoke
  tombstone 与 purge readback 分别在 `BEGIN IMMEDIATE` 事务中完成；需要持久化的
  成功只能在 COMMIT 后返回。fault injection tests 固定 COMMIT 前 rollback 与
  重试/重启幂等语义。
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

- P2.2 仍是与 v1 listener 并列的 library，不接管生产 WS。Relay v2 的签名字节事实源
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
  worker，第二次 `open` 直接拒绝，避免多 worker 破坏 admission FIFO；P2.6 再负责跨进程
  server lock。
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
- `PairingHello` 是后续 pairing transport 传给 auth library 的连接元数据，不是新增
  ADRV2 frame；P2.2 不提前写死 URL/path carrier。`PairingAccess` 仅允许 active、未过期
  route 上的同 route `PairData` / `ClosePairRoute`，其他 frame 统一拒绝。
- auth access、challenge、credential、public key/signature 等 `Debug` 输出必须脱敏；route
  关联标识使用带类型域 SHA-256 的 32-bit 截断，不得直接打印 route 原始前缀。failure 只
  返回稳定通用 code/message，不泄漏完整 route、key、hash、signature 或验签步骤。

### Relay Companion MVP P2.3 v2 Stream Core 边界

- P2.3 仍是与 v1 listener 并列的 library，不接管生产 WebSocket。唯一
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
  不格式化 sealed bytes 或完整 route/generation。P2.4 才加入 PairRoute 与在线 Send/Reply，
  P2.9 前仍不能把本节测试通过描述为 v2 公网 listener 已上线。

### R1a 隐含约束（供 R2 参考）

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
