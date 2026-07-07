# AgentDeck Relay R0 契约 spike 设计

| 字段 | 值 |
|---|---|
| 状态 | Design - 待评审 |
| 日期 | 2026-07-07 |
| 主题 | Relay 远程访问第一阶段（R0）：证明 RemoteEnvelope 能包住现有 agentdeck-protocol，并用内存 fake relay + CLI remote 客户端打通「协议组合 + 转发」 |
| 关联 | `docs/plans/2026-07-01-agentdeck-mobile-relay-design.md`（母设计，R0-R4 路线）、`docs/plans/2026-07-03-ios-uikit-frontend-design.md`（MobileSessionSource 接口）、`ARCHITECTURE.md`（N1/N6/K5/K9/N8）、`NORTH_STAR.md` |

## 1. 背景和用户问题

AgentDeck 的北极星把「移动端伴侣」列为跨 agent 自带能力，并明确「所有客户端通过统一协议消费同一个 daemon」。母设计 `2026-07-01-agentdeck-mobile-relay-design.md` 已确认方向：**自托管薄 Relay + agentdeckd remote mode + iOS companion**，分 R0-R4 五阶段，参考 happier（零知识有状态 relay + E2EE + 二维码配对）。

当前事实：

- daemon 与客户端之间**只有 stdio 子进程管道**（JSONL 分帧），无 socket/端口/鉴权；`agentdeckd` 编译层面连 tokio `net` feature 都没开，完全假设本机、单客户端、单管道。
- 协议层已为远程预留：`agentdeck-protocol/src/transport.rs` 有异步 `Transport` trait + `AuthContext::Bearer{token,device_id}` + 重连配置（不变量 N6 编译期锁死），但全是 v0.5 占位、无实现。
- `agentdeckd` 主循环 `hub.run<R:AsyncRead, W:AsyncWrite>(stdin, stdout)` 是泛型的——**换成任意流即为 relay 注入缝**。
- iOS 侧唯一数据入口 `MobileSessionSource`（4 只读流 + 2 写指令）已就绪，当前只有 `FixtureSessionSource`；`SceneDelegate` 硬编码注入，未来换 `RelaySessionSource` 视图层零改动。
- 母设计 §6 的 `RemoteEnvelope` 与 fleet 对象（Machine/Device/Subscription…）目前只是伪代码，仓库无对应 Rust 类型、无 `agentdeck-relay` crate。**R0 尚未落地。**

用户问题：完整 relay 横跨 5 个子系统（协议信封、relay 服务器、daemon remote mode、iOS 网络数据源、加密/配对），不适合一次做完。需要一个**最小但有真实证明力**的第一步，把后续阶段的最大风险提前拆掉：协议能否组合、daemon 协议缺失的 fleet 概念（机器/会话列表）怎么补、加密与网络的接缝留在哪。

## 2. 目标与非目标

### 目标

- 证明 `RemoteEnvelope` 能包住现有 `ClientCommand` / `ServerEvent` / admin-reply / `HistoryResponse` 并原样解出，语义无损。
- 证明一个「有状态但内容不可见」的转发器能在 machine（真实 `agentdeckd`）与 device（第二个客户端）之间路由/转发/排序/补发，会话生命周期完整穿透。
- 在 R0 就定义**最小 relay 控制协议（fleet 层）**，补齐 daemon 协议没有的「机器列表 / 会话列表 / 事件订阅」，并与 `MobileSessionSource` 一一对齐。
- 交付一个**人工可驱动的 CLI remote 客户端作为接口基线**：它是 iOS `RelaySessionSource` 与集成测试共同对齐的参照面，且在 iOS 出现之前持续验证 relay 链路。
- 留好加密接缝（`Sealed`）和网络接缝，使 R1（真加密/真网络）对路由器与信封形状零破坏。
- 全部进默认 `cargo test`（**不需要真实 codex/claude 登录**）。

### 非目标

- 不做真实端到端加密（R1/R2 决定库与落地）。
- 不做真实网络传输 / WebSocket / TLS（R1）——R0 任何 crate 都不新增 tokio `net` feature，让「无网络」边界字面可强制。
- 不改 `agentdeckd`，不做 agentdeckd remote mode（R2）。
- 不做扫码配对、相机、device credential、撤销流程（R2/R3）。
- 不做持久化存储（SQLite/Postgres，R1）；R0 纯内存。
- 不做 APNs 通知（R3+）。
- 不做 iOS `RelaySessionSource`（R3）；R0 只保证接口面对齐，不写 iOS 网络代码。
- 不做 SaaS/多租户/团队（R4）。

## 3. 已确认决策

本设计经头脑风暴对齐，以下决策已确认：

1. **落地范围 = R0 契约 spike**（横跨 5 子系统的完整 relay 切片推进，先做 R0）。
2. **R0 方案 = 方案 B**：内存 fake relay + 真实 daemon 组合 + CLI smoke；新建 `agentdeck-relay` lib crate，`agentdeckd` 零改动，进默认 `cargo test`，为 R1 生长。
3. **relay 控制协议（fleet 消息）在 R0 就定义**（不压到 R1），因为它正是「证明协议能组合」的核心，并当场填上 iOS `sendPrompt` 缺 threadId 的坑。
4. **CLI remote 客户端最优先、最早做，并作为验证与接口基线**：R0 的构建从 CLI device 客户端起步，其命令面镜像 `MobileSessionSource`，冻结为跨 R0-R2 稳定的接口基线。
5. **阶段↔版本映射修订要做**：在本 spec 记录 R0-R4 与 v0.4+/v0.5 的映射，并顺手修 README/unified-shell 一行交叉引用消歧（文档一致性，非代码）。

## 4. 架构方案和边界

### 4.1 crate / 模块布局

```text
agentdeck-protocol/src/remote/        # 契约事实源（受 schema 快照 + 中立性约束）
  mod.rs        # 模块根 + RELAY_PROTOCOL_VERSION 常量 + re-export
  envelope.rs   # RemoteEnvelope + Sealed（加密接缝）+ EnvelopeKind
  relay.rs      # relay 控制协议：RelayClientMsg / RelayServerMsg / SubTarget
  fleet.rs      # MachineDescriptor / DeviceDescriptor / SessionDescriptor
  # lib.rs 加 `pub mod remote;` 并把 remote 类型纳入 protocol_schema()

agentdeck-relay/                       # 新 lib crate（R0 无 binary，R1 生长为 relay 服务）
  Cargo.toml    # deps: agentdeck-protocol, tokio(sync/io-util/time/macros，**不含 net**),
                #       serde, serde_json, thiserror, tracing
  src/
    lib.rs
    router.rs   # FakeRelay：内存异步路由器核心
    bridge.rs   # StdioMachineBridge：把 spawn 的真实 agentdeckd 当 machine 接入
  tests/
    r0_composition.rs

agentdeck-cli/                         # 扩 remote 子命令组（接口基线，最优先）
  src/remote/   # remote 客户端：连接（R0 仅 in-proc fake）、订阅、发指令、打印
```

remote 类型放 `agentdeck-protocol` 与已有 `transport.rs` 远程预留同源；路由运行时逻辑放 `agentdeck-relay`；人工驱动面放 `agentdeck-cli`。

### 4.2 RemoteEnvelope + 「暂无加密」接缝

```rust
pub const RELAY_PROTOCOL_VERSION: u16 = 0; // R0 草案

pub struct RemoteEnvelope {
    pub relay_protocol_version: u16,
    pub agentdeck_protocol_version: u16,   // == PROTOCOL_VERSION (2)
    pub account_or_profile_id: String,
    pub device_id: String,
    pub machine_id: String,
    pub session_id: Option<String>,
    pub stream_seq: u64,                   // per-session 单调，供断线补拉（R1+）
    pub kind: EnvelopeKind,
    pub created_at_ms: i64,                // 外部传入，不在协议内取时钟（确定性/可测）
    pub trace_id: String,                  // 三端关联（母设计 §8）
    pub payload: Sealed,                   // 接缝
}

pub enum EnvelopeKind { Command, Event, AdminReply, History, RelayControl }

pub enum Sealed {
    Plaintext { bytes: Vec<u8> },          // R0：明文字节 = 内层 JSON 序列化
    // Encrypted { alg, nonce, ciphertext, tag }  // R1/R2 追加；路由器零改动
}
```

**接缝语义**：relay 只读**外层元数据**（ids/seq/kind/trace_id）做路由、排序、补发；`Sealed` 对它永远不透明。R0 里 payload 是明文（好让测试解码断言），但路由器代码把它当不透明字节处理——从而证明 R1 把 `Plaintext` 换成 `Encrypted` 时路由器与信封形状零改动。内层字节按 `kind` 解码为对应 trunk 类型，信封本身不需要认识内层类型。

`created_at_ms` 由调用方传入（不在协议内调用时钟），保证测试确定性并对齐「时间戳外部注入」的工程约束。

### 4.3 relay 控制协议（fleet 层）与 MobileSessionSource 映射

daemon 协议只到「单会话 events + history」，没有「机器列表 / 会话列表 / 收件箱」。R0 定义最小 relay 控制协议补齐：

```rust
// 装在 RemoteEnvelope{kind: RelayControl} 里
pub enum RelayClientMsg {
    // machine 侧
    RegisterMachine { machine: MachineDescriptor },
    Heartbeat { machine_id: String },
    AnnounceSession { session: SessionDescriptor },
    RetireSession { session_id: String },
    PublishEvent { session_id: String, seq: u64, sealed: Sealed }, // 转发一条 ServerEvent
    // device 侧
    ConnectDevice { device: DeviceDescriptor },
    Subscribe { target: SubTarget },     // Machines | Sessions{machine_id} | Events{session_id}
    Unsubscribe { target: SubTarget },
    SendCommand { target: CommandTarget, sealed: Sealed }, // device→machine 的 ClientCommand
    Ack { up_to_seq: u64, session_id: Option<String> },
}

// SendCommand 寻址：会话级命令走 Session（relay 用 AnnounceSession 建的 session→machine 索引解析），
// 机器级 admin 命令（Ping/ProtocolVersion/Selfcheck/History 等无 session）走 Machine。
pub enum CommandTarget { Session { session_id: String }, Machine { machine_id: String } }

pub enum RelayServerMsg {
    MachineList { machines: Vec<MachineDescriptor> },              // → machines()
    SessionList { machine_id: String, sessions: Vec<SessionDescriptor> }, // → sessions()
    Event { session_id: String, seq: u64, sealed: Sealed },       // → events()
    CommandDelivered { session_id: String },
    Error { code: String, message: String },                      // relay.* / remote.* 失败码
}

pub enum SubTarget { Machines, Sessions { machine_id: String }, Events { session_id: String } }
```

`MobileSessionSource` 映射（接口基线的核心对齐关系）：

| MobileSessionSource 方法 | relay 控制协议 | CLI 命令（基线） |
|---|---|---|
| `machines()` | `Subscribe{Machines}` → `MachineList` | `agentdeck-cli remote machines` |
| `sessions(machineID:)` | `Subscribe{Sessions{id}}` → `SessionList` | `agentdeck-cli remote sessions <machine_id>` |
| `events(sessionID:)` | `Subscribe{Events{id}}` → `Event` 流 | `agentdeck-cli remote watch <session_id>` |
| `sendPrompt(sessionID:text:)` | `SendCommand`（内层 `SessionContinue`/`SessionStart`） | `agentdeck-cli remote send <session_id> <text>` |
| `resolveApproval(sessionID:requestID:approve:)` | `SendCommand`（内层 `ActionDecision`） | `agentdeck-cli remote approve/deny <session_id> <request_id>` |
| `inbox()` | **后置**（可由事件派生） | 后置 |

`inbox()` 明确后置：它可由事件派生（`actionRequest`→待审批 / `turnComplete`→完成 / `error`→失败，`FixtureSessionSource` 已在这么做），R3 移植该派生逻辑。

fleet 数据类型填上探索发现的缺口：

```rust
pub struct MachineDescriptor {
    pub machine_id: String, pub name: String,
    pub agentdeck_protocol_version: u16,
    pub is_online: bool, pub last_heartbeat_ms: Option<i64>,
}
pub struct DeviceDescriptor { pub device_id: String, pub kind: DeviceKind } // Cli | Mobile | Desktop
pub struct SessionDescriptor {
    pub session_id: String, pub machine_id: String,
    pub thread_id: Option<String>,   // ← 填坑：sendPrompt→SessionContinue 需要
    pub agent_kind: AgentKind,       // ← 填坑：SessionContinue 需要
    pub cwd: String,                 // ← 填坑：SessionContinue 需要（CC --resume 指向 per-cwd）
    pub title: Option<String>,
}
```

`SessionDescriptor` 携带 `thread_id + agent_kind + cwd`，正好补上探索发现的坑：`sendPrompt` 要构造 `ClientCommand::SessionContinue{thread_id, agent_kind, cwd, prompt}`，而现有 iOS `SessionSummary` 缺 `thread_id`。`resolveApproval` 的 `persist` 标志在 R0 默认 `false`（Codex 可持久化审批的语义在 R2 device 侧补显式开关）。

### 4.4 FakeRelay 路由器 + stdio bridge

**FakeRelay（router.rs）**：内存异步 actor。

- 状态：`machines: HashMap<machine_id, MachineConn>`、`devices: HashMap<device_id, DeviceConn>`、`subscriptions`、per-session `seq` 计数、per-session 近期 sealed 事件环形缓冲（R0 内存版「按 seq 补拉」，对齐 happier 的单调 seq 思路）。
- 连接：`tokio::sync::mpsc`（内存双工，**无 socket**）。每个接入方持 `RelayHandle{ tx, rx }`。
- 路由规则：machine 的 `PublishEvent/AnnounceSession` → 扇出给订阅 device 的 `Event/SessionList`；device 的 `SendCommand` → 按 `CommandTarget` 解析目标 machine（`Session` 经 `AnnounceSession` 建的 session→machine 索引，`Machine` 直接寻址）后转发；machine 的 admin reply 以 `EnvelopeKind::AdminReply` 经 `trace_id` 关联回发起 device；`Subscribe` → 先发当前快照（`MachineList`/`SessionList`）再流增量（对齐 `FixtureSessionSource`「先快照后增量」与 happier 的 update/ephemeral 分离）。
- **路由器永不 match `Sealed` 内层**——证明内容不可见（content-agnostic）。

**StdioMachineBridge（bridge.rs）**：把 spawn 的真实 `agentdeckd` 当 machine 接入，**不改 daemon**。

- 复用 `agentdeck-cli` 的 daemon 定位思路 spawn `agentdeckd`，持 stdin/stdout。
- machine→relay：读 daemon stdout 每行 JSONL（`ServerEvent` 或 admin `{"reply":...}`），原样字节包进 `Sealed::Plaintext`，据 `session_id`（ServerEvent 已带）发 `PublishEvent`；admin reply 走 `EnvelopeKind::AdminReply`。
- relay→machine：收 `SendCommand`，解出原始 `ClientCommand` JSON 行写 daemon stdin。
- 这是 R2 真实 remote mode 的 R0 替身，且作为 R2 in-daemon 实现的参照可复用。

### 4.5 CLI remote 客户端（接口基线，最优先）

`agentdeck-cli` 新增 `remote` 子命令组，是 R0 **最先落地**的部分，作为验证与接口基线：

```text
agentdeck-cli remote --relay <endpoint> machines
agentdeck-cli remote --relay <endpoint> sessions <machine_id>
agentdeck-cli remote --relay <endpoint> watch <session_id>          # 流式打印
agentdeck-cli remote --relay <endpoint> send <session_id> <text>
agentdeck-cli remote --relay <endpoint> approve <session_id> <request_id>
agentdeck-cli remote --relay <endpoint> deny <session_id> <request_id>
agentdeck-cli remote --relay <endpoint> ping <machine_id>          # 机器级 admin 往返（T1 的 CLI 驱动）
```

- **endpoint 抽象**：R0 唯一支持 `fake:inproc`（进程内起 FakeRelay + `StdioMachineBridge` 到本地真实 daemon，或接合成 machine）；R1 追加 `ws://...`。命令面在 R0-R2 保持不变——这就是「接口基线」的含义：iOS `RelaySessionSource` 与集成测试都对齐这套命令语义。
- 每条命令输出信封元数据（machine_id/session_id/seq/trace_id）+ 解出的内层内容，便于人工诊断三端链路。
- 冻结点：`remote` 命令与 `MobileSessionSource` 方法的映射（见 §4.3 表）作为契约冻结，后续阶段只允许追加、不允许破坏语义。

### 4.6 边界与不变量守护

- **N1 中立性**：所有 remote 类型 Layer-A 中立（无 Codex/OpenAI/Anthropic/Claude 字样），扩 `neutrality_tests`。
- **N6**：R0 用 mpsc 通道，不实现 remote `Transport`（那是 R1/R2），也**不削弱** `Transport` trait 形状；`transport_trait_remote_ready.rs` 保持绿。
- **K9/N8**：relay/bridge 绝不读/存/转发 vendor token；bridge 只搬不透明 daemon I/O 字节；不建 `cc-meta/`。
- **K5**：R0 纯内存，不新增数据目录写入；daemon 诊断仍写 `~/Library/Application Support/AgentDeck/`。
- **无 `net` feature**：R0 任何 crate 都不加 tokio `net`，编译层面强制「无网络」。
- **schema 快照**：`agentdeck-protocol` schema 重生成纳入 `remote::*`，漂移测试随 `cargo test` 运行。

## 5. 构建顺序（CLI-first）

按「CLI 最优先、作为接口基线」的决策，R0 实现顺序：

1. **协议 remote 类型骨架**（envelope + Sealed + relay 控制协议 + fleet），能编译、能序列化，schema 快照先建。
2. **CLI remote 客户端 + 最小 FakeRelay**：先让 `agentdeck-cli remote --relay fake:inproc machines/watch/...` 能跑起来，用最小 FakeRelay（可先接合成 machine）驱动，**冻结 §4.3 映射表为接口基线**。
3. **StdioMachineBridge 接真实 daemon**：把 CLI 的 `send Ping/ProtocolVersion` 打到真实 `agentdeckd` 并经 relay 收回。
4. **集成测试** `r0_composition.rs` 把上面的链路固化为断言（T1/T2/T3，见 §7）。
5. **中立性 + schema 快照 + 文档收口**（含 §9 的 README 映射修订）。

先有可人工驱动的 CLI，再用测试固化——CLI 既是最早的验证手段，又是 iOS 与测试共同对齐的接口面。

## 6. 错误处理与可观测性

- **失败码（R0 可达子集，常量化）**：`relay.machine.offline`、`remote.session.not_found`、`relay.envelope.bad_kind`（kind 与内层解码不匹配）。全集（`relay.auth.*`、`relay.envelope.decrypt_failed`、`remote.daemon.busy` 等）随 R1/R2 引入。
- **trace_id**：每条 relay 路由消息都带；CLI/relay/（未来 daemon）三端可关联。
- **日志边界**：relay 只记外层信封元数据与失败码，**禁止**输出 prompt/shell output/diff/路径片段/token-like 字符串。R0 用一个日志捕获测试或按构造断言这一点。
- **断流语义**：R0 用内存环形缓冲支持晚订阅重放；真实断线重连（游标/背压）留到 R1 网络实现。

## 7. 测试和验收标准

### 集成测试（全部 ungated，进默认 `cargo test`）

- **T1 admin 往返（真实 daemon）**：FakeRelay + 真实 `agentdeckd`(machine M1) + device D1。D1 发 `SendCommand{ target: Machine{M1}, sealed: Ping/ProtocolVersion/Selfcheck }`（机器级 admin，不需 vendor 登录），断言 daemon admin reply 以 `AdminReply` 信封经 `trace_id` 关联回到 D1、解码正确、与直连 stdio 基线语义一致；等价可用 `agentdeck-cli remote ping <machine_id>` 人工驱动。→ 证明真实 daemon 组合 + 双向路由。
- **T2 会话流转发（合成 machine）**：合成 machine 发脚本化 `ServerEvent` 序列（`SessionStarted`→`SessionCapabilities`→`AgentItem`→`ActionRequest`→[device 发 `ActionDecision`]→`AgentItem`→`TurnComplete`），复用真实协议类型。device 订阅，断言有序收全、seq 单调、晚订阅第二 device 能重放缓冲序列。→ 证明 fleet 层转发 + 排序 + 补发，无需登录。
- **T3 内容不可见**：喂路由器随机不透明 `Sealed::Plaintext`，断言仅凭外层元数据仍能路由。→ 证明加密接缝。
- **schema/中立性**：protocol schema 快照纳入 `remote::*` 并同步；中立性测试断言 remote 类型无 vendor 字样。

### 验收标准（R0，母设计 §10 的子集）

- `cargo test` 全绿，含 `r0_composition` + schema 漂移 + 中立性。
- 第二个客户端经 relay 看到某 machine 广告的 session 与其流式 `ServerEvent`，有序；晚订阅者得到缓冲重放。
- device→machine 命令（Ping/ProtocolVersion）经 relay 往返到**真实** `agentdeckd`。
- 路由器可证明从不检视 `Sealed` 内层（内容不可见）。
- relay 日志中不出现 prompt/shell/diff 明文或 token-like 串。
- `agentdeck-cli remote --relay fake:inproc` 的 machines/watch/send 能人工跑通，打印经 relay 转发的 reply/事件 + 信封元数据。
- `scripts/verify-agent-docs.sh` 通过；协议变更后 `cargo test` 与 schema 漂移测试通过；文档同步更新。

## 8. 后置项与开放问题

R0 显式将以下决定为「后置」，并记录倾向以便后续复用：

- **E2EE 库（R1 决定）**：倾向 daemon/relay 侧 Rust `crypto_box` + `chacha20poly1305`（对齐 happier 的 libsodium 语义），iOS 侧 CryptoKit `Curve25519` + `ChaChaPoly`，R1 做互操作验证。不手写密码学。
- **存储（R1）**：先 SQLite，公开托管前再评估 Postgres；R0 纯内存。
- **APNs（R3+）**：R0 无，R3 用 app 内在线通知先闭环。
- **配对安全（R2/R3 硬性要求）**：challenge nonce 必须服务端生成带 TTL（借鉴 happy issue #669 重放隐患教训），一开始就做对。
- **macOS 是否也经 relay 接远端 machine**：后置，第一版 AppKit 仍优先本地 daemon。
- **`resolveApproval` 的 `persist` 语义**：R0 默认 `false`，R2 device 侧补显式开关。

## 9. 阶段↔版本映射（含 README 修订）

母设计用 R0-R4 阶段编号，README/unified-shell 用 v0.4+/v0.5 版本号，二者此前未对齐。本 spec 记录映射，并在 README/unified-shell 加一行交叉引用消歧：

| Relay 阶段 | 内容 | 版本锚点 |
|---|---|---|
| R0（本 spec） | 契约 spike：RemoteEnvelope + fleet 协议 + 内存 relay + CLI 基线 | v0.5 前置铺垫 |
| R1 | Relay MVP（`agentdeck-relay` binary、WS、SQLite、E2EE 落地） | v0.5 |
| R2 | agentdeckd remote mode（`--remote --relay-url`） | v0.5 |
| R3 | iOS Mobile Companion MVP（`RelaySessionSource`、扫码配对） | v0.4+ 移动伴侣 |
| R4 | Hosted / team mode 评估 | 后置 |

README/unified-shell 的修订仅为文档一致性（在「v0.5 daemon 远程化」「v0.4+ 移动伴侣」处加「= Relay 母设计 R1/R2 / R3」的交叉引用），不改代码。

## 10. 落地后文档更新清单

- `AGENTS.md`：必读顺序补本 spec 与母设计的关系（若需要）。
- `README.md` / `docs/plans/2026-06-30-unified-shell-v02-design.md`：§9 的版本映射交叉引用。
- `docs/index.md`：登记本 spec。
- `ARCHITECTURE.md`：R0 落地后如引入新不变量（如「relay 内容不可见」）再补；R0 本身不新增不变量，仅复用 N1/N6/K5/K9/N8。
- 母设计 `2026-07-01-agentdeck-mobile-relay-design.md`：状态从「方向已确认」更新为「R0 落地中」。
