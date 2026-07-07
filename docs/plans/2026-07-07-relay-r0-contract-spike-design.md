# AgentDeck Relay R0 契约 spike 设计

| 字段 | 值 |
|---|---|
| 状态 | Design - 已按代码评审修订，待复审 |
| 日期 | 2026-07-07 |
| 主题 | Relay 远程访问第一阶段（R0）：证明控制面/数据面分层的 remote frame 能包住现有 agentdeck-protocol，并用内存 fake relay + CLI 单进程 smoke 打通「协议组合 + 转发」 |
| 关联 | `docs/plans/2026-07-01-agentdeck-mobile-relay-design.md`（母设计，R0-R4 路线）、`docs/plans/2026-07-03-ios-uikit-frontend-design.md`（MobileSessionSource 接口）、`ARCHITECTURE.md`（N1/N6/K5/K9/N8）、`NORTH_STAR.md` |

## 1. 背景和用户问题

AgentDeck 的北极星把「移动端伴侣」列为跨 agent 自带能力，并明确「所有客户端通过统一协议消费同一个 daemon」。母设计 `2026-07-01-agentdeck-mobile-relay-design.md` 已确认方向：**自托管薄 Relay + agentdeckd remote mode + iOS companion**，分 R0-R4 五阶段，参考 happier（零知识有状态 relay + E2EE + 二维码配对）。

当前事实：

- daemon 与客户端之间**只有 stdio 子进程管道**（JSONL 分帧），无 socket/端口/鉴权；`agentdeckd` 编译层面连 tokio `net` feature 都没开，完全假设本机、单客户端、单管道。
- 协议层已为远程预留：`agentdeck-protocol/src/transport.rs` 有异步 `Transport` trait + `AuthContext::Bearer{token,device_id}` + 重连配置（不变量 N6 编译期锁死），但全是 v0.5 占位、无实现。
- `agentdeckd` 主循环 `hub.run<R:AsyncRead, W:AsyncWrite>(stdin, stdout)` 是泛型的——**换成任意流即为 relay 注入缝**。
- **会话身份现实**：`codex/adapter.rs` 与 `claude_code/adapter.rs` 的 `start_inner`（`start_session` 与 `continue_thread` 共用）每次调用都 `SessionId(uuid::v4())` **新铸一个 session_id**；`ServerEvent::SessionStarted{session_id, thread_id: resume_thread_id, agent_kind}` 表明 **`thread_id` 才是跨 turn 稳定的会话身份，`session_id` 是 per-turn/per-invocation 的**。`ClientCommand::SessionContinue{thread_id, agent_kind, cwd, prompt}` 只吃 `thread_id`，不吃旧 `session_id`。
- **admin reply 现实**：daemon 的 7 个 admin 命令（Ping/Selfcheck/ProtocolSchema/ProtocolVersion/AgentList/AgentCapabilities/History）走 `{"reply":"..."}` 侧通道，**无 request id**；CLI 按 `"reply"` 字段值匹配等待（`agentdeck-cli/src/client.rs`），同类并发会误关联。
- iOS 侧唯一数据入口 `MobileSessionSource`（4 只读流 + 2 写指令）已就绪，当前只有 `FixtureSessionSource`；未来换 `RelaySessionSource` 视图层零改动。
- 母设计 §6 的 `RemoteEnvelope` 与 fleet 对象目前只是伪代码，仓库无对应 Rust 类型、无 `agentdeck-relay` crate。**R0 尚未落地。**

用户问题：完整 relay 横跨 5 个子系统，不适合一次做完。需要一个**最小但有真实证明力**的第一步，把后续阶段的最大风险提前拆掉：协议能否组合、daemon 协议缺失的 fleet 概念怎么补、会话身份怎么稳定、加密与网络的接缝留在哪。

## 2. 目标与非目标

### 目标

- 证明**控制面/数据面分层的 remote frame** 能包住现有 `ClientCommand` / `ServerEvent` / admin-reply / `HistoryResponse`：relay 可读控制面做路由，agent 内容作为 opaque 数据面穿透、relay 不可见。
- 证明一个「控制面可读、数据面不可见」的转发器能在 machine（真实 `agentdeckd`）与 device（第二个客户端）之间路由/转发/排序/补发。
- 在 R0 就定义**稳定远程身份模型**：`conversation_id`（映射 daemon `thread_id`）与 `turn_session_id`（每次 start/continue 新铸的 `session_id`）分离；事件订阅键在 `conversation_id`，approval 定位当前 `turn_session_id`。
- 在 R0 定义**最小 relay 控制协议（fleet 层）**，补齐 daemon 没有的「机器列表 / 会话列表 / 事件订阅」，并与 `MobileSessionSource` 一一对齐。
- 交付**可人工驱动的 CLI remote 命令面作为接口基线**（语义冻结、跨 R0-R2 稳定），R0 用**单进程 `remote smoke`** 提供可执行证明。
- 留好数据面加密接缝（`DataEnvelope`）和网络接缝，使 R1（真加密/真网络）对控制面协议与路由器零破坏。
- 默认 `cargo test` 覆盖「真实 daemon admin 双向组合 + 合成 session lifecycle 穿透」，**不需要 vendor 登录**；真实 Codex/CC 全流穿透由 **gated E2E**（`AGENTDECK_E2E=1`）覆盖。

### 非目标

- 不做真实端到端加密（R1/R2 决定库与落地）。
- 不做真实网络传输 / WebSocket / TLS（R1）——R0 任何 crate 都不新增 tokio `net` feature，编译层面强制「无网络」。
- 不改 `agentdeckd`，不做 agentdeckd remote mode（R2）；R0 用 bridge 从外部把真实 daemon 当 machine 接入。
- 不解决真实 daemon「首个 turn 之前 thread_id 尚未确定」的 bootstrap（R2 remote mode 处理）；R0 合成 machine 直接分配 `conversation_id`。
- 不做扫码配对、相机、device credential、撤销流程（R2/R3）。
- 不做持久化存储（R1）；R0 纯内存。不做 APNs（R3+）。
- 不做 iOS `RelaySessionSource`（R3）；R0 只保证接口面对齐。
- 不做 SaaS/多租户/团队（R4）。

## 3. 已确认决策

本设计经头脑风暴对齐 + 一轮代码评审修订，决策如下：

1. **落地范围 = R0 契约 spike**（先做 R0，后续切片推进）。
2. **R0 方案 = 方案 B**：内存 fake relay + 真实 daemon 组合 + CLI smoke；新建 `agentdeck-relay` lib crate，`agentdeckd` 零改动，进默认 `cargo test`，为 R1 生长。
3. **relay 控制协议（fleet 消息）在 R0 就定义**，并当场填上 iOS `sendPrompt` 缺 thread_id 的坑。
4. **CLI remote 命令面最优先、作为接口基线**（语义冻结）；R0 的可执行证明是单进程 `remote smoke`。
5. **阶段↔版本映射修订要做**（§9）。

代码评审引入的 5 处修订（见对应章节）：

- **R1 控制面/数据面分离**：control plane（`RemoteFrame`/`RelayControlMsg`）relay 可读，仅 agent payload 走 opaque `DataEnvelope`（§4.2/§4.3）。
- **R2 稳定远程身份**：`conversation_id`(=thread_id) 与 `turn_session_id`(=session_id) 分离（§4.3）。
- **R3 CLI 基线可执行性**：R0 用单进程 `remote smoke`，独立子命令语义冻结但独立可运行始于 R1（§4.5/§5）。
- **R4 admin reply single-flight**：bridge 对 machine admin 命令串行化 + FIFO 关联（§4.4/§6）。
- **R5 验收口径校正**：默认 CI 覆盖「真实 admin + 合成 lifecycle」，真实全流走 gated E2E（§2/§7）。

## 4. 架构方案和边界

### 4.1 crate / 模块布局

```text
agentdeck-protocol/src/remote/        # 契约事实源（受 schema 快照 + 中立性约束）
  mod.rs        # 模块根 + RELAY_PROTOCOL_VERSION + re-export
  frame.rs      # RemoteFrame（控制面外壳，relay 可读）+ ClientRole
  control.rs    # RelayControlMsg（控制面消息，relay 可读）+ SubTarget + CommandTarget
  data.rs       # DataEnvelope（数据面，relay 不可见）+ 加密接缝
  fleet.rs      # MachineDescriptor / DeviceDescriptor / SessionDescriptor
  # lib.rs 加 `pub mod remote;` 并把 remote 类型纳入 protocol_schema()

agentdeck-relay/                       # 新 lib crate（R0 无 binary，R1 生长为 relay 服务）
  Cargo.toml    # deps: agentdeck-protocol, tokio(sync/io-util/time/macros，**不含 net**),
                #       serde, serde_json, thiserror, tracing
  src/{lib.rs, router.rs, bridge.rs}
  tests/r0_composition.rs

agentdeck-cli/src/remote/              # remote 命令面（接口基线）+ 单进程 smoke
```

### 4.2 控制面/数据面分层（评审修订 R1）

关键更正：relay 必须能读控制消息（Subscribe/SendCommand/…）才能路由，所以**控制面不能是 opaque 的**；只有 agent 的 `ClientCommand`/`ServerEvent` 内容才是 relay 不可见的数据面。

```rust
pub const RELAY_PROTOCOL_VERSION: u16 = 0; // R0 草案

// 控制面外壳：relay 完整可读。
pub struct RemoteFrame {
    pub relay_protocol_version: u16,
    pub trace_id: String,          // 三端关联
    pub created_at_ms: i64,        // 外部传入，不在协议内取时钟（确定性/可测）
    pub from: ClientRole,          // Machine{machine_id} | Device{device_id}
    pub msg: RelayControlMsg,      // relay 可读的控制消息
}
pub enum ClientRole { Machine { machine_id: String }, Device { device_id: String } }

// 数据面：relay 不可见。R0 = 明文字节；R1/R2 换 Encrypted，控制面与路由器零改动。
pub enum DataEnvelope {
    Plaintext { agentdeck_protocol_version: u16, bytes: Vec<u8> }, // 内层 ClientCommand/ServerEvent/HistoryResponse JSON
    // Encrypted { alg, nonce, ciphertext, tag }  // R1/R2
}
```

与母设计 §6 的对应：母设计的 `RemoteEnvelope.ciphertext` 即本设计的 **`DataEnvelope`**（数据面）；母设计未显式区分的路由元数据被提升为 relay 可读的 **`RemoteFrame` + `RelayControlMsg`**（控制面）。母设计文档在 R0 落地后据此更新。

### 4.3 relay 控制协议、稳定身份与 MobileSessionSource 映射（评审修订 R1+R2）

`RelayControlMsg` 是 relay 可读的控制面消息；凡携带 agent 内容的变体，用**嵌套 `DataEnvelope`** 承载 opaque payload：

```rust
pub enum RelayControlMsg {
    // ── machine → relay ──
    RegisterMachine { machine: MachineDescriptor },
    Heartbeat { machine_id: String },
    AnnounceSession { session: SessionDescriptor },
    RetireSession { conversation_id: String },
    PublishEvent { conversation_id: String, turn_session_id: String, seq: u64, data: DataEnvelope },
    AdminReply { in_reply_to: String, data: DataEnvelope },   // in_reply_to = SendCommand.request_id
    // ── device → relay ──
    ConnectDevice { device: DeviceDescriptor },
    Subscribe { target: SubTarget },
    Unsubscribe { target: SubTarget },
    SendCommand { request_id: String, target: CommandTarget, data: DataEnvelope },
    Ack { up_to_seq: u64, conversation_id: Option<String> },
    // ── relay → client ──
    MachineList { machines: Vec<MachineDescriptor> },                        // → machines()
    SessionList { machine_id: String, sessions: Vec<SessionDescriptor> },    // → sessions()
    Event { conversation_id: String, turn_session_id: String, seq: u64, data: DataEnvelope }, // → events()
    CommandDelivered { request_id: String },
    Error { code: String, message: String, in_reply_to: Option<String> },    // relay.* / remote.* 失败码
}

pub enum SubTarget {
    Machines,
    Sessions { machine_id: String },
    Events { conversation_id: String },     // ← 订阅键在稳定 conversation，而非 per-turn session
}

// 命令寻址：会话级命令走 Conversation（发新 prompt→续接稳定会话）；
// 审批定位当前活跃 turn；机器级 admin（Ping/History 等，无会话）走 Machine。
pub enum CommandTarget {
    Conversation { conversation_id: String },   // sendPrompt → 内层 SessionContinue{thread_id=conversation_id}
    Turn { turn_session_id: String },           // resolveApproval → 内层 ActionDecision{session_id=turn_session_id}
    Machine { machine_id: String },             // 机器级 admin（Ping/ProtocolVersion/Selfcheck/History）
}
```

**稳定身份模型（修订 R2 的核心）**：daemon 每次 start/continue 新铸 `session_id`，故：

- `conversation_id`（remote 稳定）↔ daemon `thread_id`（`SessionContinue` 用的持久会话句柄）。
- `turn_session_id`（per-turn）↔ 每次新铸的 `session_id`。
- device **订阅 `conversation_id`**；每条 `Event` 带 `(conversation_id, turn_session_id, seq)`，故发 prompt 触发新 turn（新 turn_session_id）后，订阅同一 conversation 的 watcher 仍持续收流。
- `sendPrompt` → `SendCommand{ target: Conversation }` → bridge/remote-mode 发 `SessionContinue{ thread_id=conversation_id }`。
- `resolveApproval` → `SendCommand{ target: Turn{turn_session_id} }` → `ActionDecision{ session_id=turn_session_id, persist:false }`（persist 默认 false，R2 补显式开关）。
- bridge 维护 `thread_id ↔ conversation_id` 映射与每 conversation 的当前 `turn_session_id`（随 `SessionStarted` 更新）。真实 daemon 首个 turn 之前 thread_id 未定的 bootstrap 是 R2 事项；R0 合成 machine 直接分配 conversation_id。

`MobileSessionSource` 映射（接口基线冻结点）：

| MobileSessionSource 方法 | relay 控制协议 | CLI 命令（语义基线） |
|---|---|---|
| `machines()` | `Subscribe{Machines}` → `MachineList` | `remote machines` |
| `sessions(machineID:)` | `Subscribe{Sessions{id}}` → `SessionList` | `remote sessions <machine_id>` |
| `events(sessionID:)`（键=conversation） | `Subscribe{Events{conversation_id}}` → `Event` 流 | `remote watch <conversation_id>` |
| `sendPrompt(...)` | `SendCommand{Conversation}`（内层 `SessionContinue`） | `remote send <conversation_id> <text>` |
| `resolveApproval(...)` | `SendCommand{Turn}`（内层 `ActionDecision`） | `remote approve/deny <turn_session_id> <request_id>` |
| （机器级 admin） | `SendCommand{Machine}`（内层 Ping 等） | `remote ping <machine_id>` |
| `inbox()` | **后置**（可由事件派生） | 后置 |

`inbox()` 后置：可由事件派生（`actionRequest`→待审批 / `turnComplete`→完成 / `error`→失败，`FixtureSessionSource` 已在这么做），R3 移植。

fleet 数据类型：

```rust
pub struct MachineDescriptor {
    pub machine_id: String, pub name: String,
    pub agentdeck_protocol_version: u16,
    pub is_online: bool, pub last_heartbeat_ms: Option<i64>,
}
pub struct DeviceDescriptor { pub device_id: String, pub kind: DeviceKind } // Cli | Mobile | Desktop
pub struct SessionDescriptor {
    pub conversation_id: String,               // 稳定身份（= thread_id 已知时）
    pub machine_id: String,
    pub thread_id: Option<String>,             // daemon 持久会话句柄
    pub current_turn_session_id: Option<String>, // 当前活跃 turn 的 session_id
    pub agent_kind: AgentKind,                 // SessionContinue 需要
    pub cwd: String,                           // SessionContinue 需要（CC --resume 指向 per-cwd）
    pub title: Option<String>,
}
```

### 4.4 FakeRelay 路由器 + stdio bridge（评审修订 R1+R4）

**FakeRelay（router.rs）**：内存异步 actor。

- 状态：`machines/devices/subscriptions`、per-conversation `seq` 计数、per-conversation 近期事件环形缓冲（R0 内存版「按 seq 补拉」）、`conversation_id → machine_id` 与 `request_id → device` 路由索引（由 `AnnounceSession`/`SendCommand` 建立）。
- 连接：`tokio::sync::mpsc`（内存双工，**无 socket**）。
- 路由规则：读 `RemoteFrame.msg`（**控制面可读**）路由——`PublishEvent/AnnounceSession` 扇出给订阅 device；`SendCommand` 按 `CommandTarget` 解析目标 machine（Conversation→索引，Turn→其 conversation→machine，Machine→直接）转发；`AdminReply` 按 `in_reply_to`→发起 device 回送；`Subscribe` 先发快照再流增量。
- **路由器只读控制面，永不解码 `DataEnvelope`**——这是「agent 内容不可见」的证明点（数据面 opaque，控制面可读）。

**StdioMachineBridge（bridge.rs）**：把 spawn 的真实 `agentdeckd` 当 machine 接入，**不改 daemon**。

- machine→relay：读 daemon stdout 每行 JSONL。`ServerEvent` → 提取 `session_id`/`thread_id`，按 bridge 维护的映射解析 `conversation_id` 与 `turn_session_id`，原样字节包进 `DataEnvelope::Plaintext` 发 `PublishEvent`；admin `{"reply":...}` 行 → 发 `AdminReply{in_reply_to}`（见下 single-flight）。
- relay→machine：收 `SendCommand`，据 `CommandTarget` + 内层解出的 `ClientCommand`（Conversation→SessionContinue、Turn→ActionDecision、Machine→admin）写 daemon stdin。
- **admin reply single-flight（修订 R4）**：daemon admin reply 无 request id，故 bridge 对同一 machine 的 admin 命令**串行化**：维护 FIFO pending 队列，同一时刻至多一个在途 admin 命令，收到下一行 `{"reply":...}` 关联到队头，再据队头的 `request_id` 生成 `AdminReply`。会话级命令（SessionContinue/ActionDecision）不受此限（它们的回执走 `ServerEvent` 流）。R2 引入真实 reply envelope + request id 后可解除串行化。

### 4.5 CLI remote 命令面（接口基线）+ 单进程 smoke（评审修订 R3）

`agentdeck-cli remote` 子命令组是**语义接口基线**（冻结、跨 R0-R2 稳定，iOS `RelaySessionSource` 与测试都对齐它）：

```text
remote --relay <endpoint> machines
remote --relay <endpoint> sessions <machine_id>
remote --relay <endpoint> watch <conversation_id>          # 流式打印
remote --relay <endpoint> send <conversation_id> <text>
remote --relay <endpoint> approve <turn_session_id> <request_id>
remote --relay <endpoint> deny <turn_session_id> <request_id>
remote --relay <endpoint> ping <machine_id>                # 机器级 admin 往返
```

**可执行性更正**：这些独立子命令需要**长驻 relay endpoint** 才能跨进程共享状态。R0 不引入网络/socket，进程内 FakeRelay 状态不跨命令保留，故：

- **R0 的可执行证明 = 单进程 `remote smoke`**：`agentdeck-cli remote smoke` 在一个进程里同时起 FakeRelay + `StdioMachineBridge`（接真实本地 daemon）+ device，按序驱动 `machines → sessions → watch → ping →（合成 machine 时）send/approve`，逐步打印信封元数据 + 解出内容 + trace_id。这是 R0 唯一保证可跑通的 CLI 路径。
- **独立子命令**（`machines`/`watch`/`send`/…）语义在 R0 冻结为基线，但**独立可运行始于 R1**（`--relay ws://…` 长驻 endpoint）。R0 spec 不把「独立子命令跨进程跑通」列为验收项。

### 4.6 边界与不变量守护

- **N1 中立性**：所有 remote 类型 Layer-A 中立（无 vendor 字样），扩 `neutrality_tests`。
- **N6**：R0 用 mpsc 通道，不实现 remote `Transport`，也**不削弱** trait 形状；`transport_trait_remote_ready.rs` 保持绿。
- **K9/N8**：relay/bridge 绝不读/存/转发 vendor token；bridge 只搬 opaque 数据面字节；不建 `cc-meta/`。
- **K5**：R0 纯内存，不新增数据目录写入；daemon 诊断仍写 `~/Library/Application Support/AgentDeck/`。
- **无 `net` feature**：R0 任何 crate 都不加 tokio `net`，编译层面强制「无网络」。
- **schema 快照**：`agentdeck-protocol` schema 重生成纳入 `remote::*`，漂移测试随 `cargo test` 运行。

## 5. 构建顺序（CLI-first）

1. **协议 remote 类型骨架**（frame + control + data + fleet），编译、序列化通过，schema 快照先建。（CLI 依赖这些类型，是薄前置。）
2. **CLI `remote smoke`（单进程）+ 最小 FakeRelay**：先让 `agentdeck-cli remote smoke` 跑起来（可先接合成 machine），**冻结 §4.3 映射表为接口基线**。
3. **StdioMachineBridge 接真实 daemon**：把 `remote smoke` 的 `ping` 打到真实 `agentdeckd` 并经 relay 收回（含 admin single-flight）。
4. **集成测试** `r0_composition.rs` 固化链路为断言（T1/T2/T3，见 §7）；补 gated T4。
5. **中立性 + schema 快照 + 文档收口**（含 §9 的 README 映射修订）。

先有可人工驱动的单进程 smoke，再用测试固化——smoke 既是最早验证手段，又是 iOS 与测试对齐的接口面。

## 6. 错误处理与可观测性

- **失败码（R0 可达子集，常量化）**：`relay.machine.offline`、`remote.session.not_found`（含未知 conversation_id）、`relay.frame.bad_kind`（控制面解析失败）、`relay.data.bad_inner`（数据面内层解码失败，仅接收端遇到）。全集随 R1/R2。
- **trace_id + request_id**：每条 `RemoteFrame` 带 `trace_id`（三端关联）；`SendCommand`/`AdminReply`/`CommandDelivered`/`Error` 用 `request_id`/`in_reply_to` 做可实现的请求-应答关联（修订 R4，解决 admin reply 无 id 的误配）。
- **日志边界**：relay 只记控制面元数据与失败码，**禁止**输出数据面明文（prompt/shell/diff）或 token-like 串。R0 用日志捕获测试或按构造断言。
- **断流语义**：R0 用内存环形缓冲支持晚订阅重放（键 conversation_id + seq）；真实断线重连（游标/背压）留到 R1。

## 7. 测试和验收标准

### 集成测试

- **T1 admin 往返（真实 daemon，ungated）**：FakeRelay + 真实 `agentdeckd`(machine M1) + device D1。D1 发 `SendCommand{ request_id, target: Machine{M1}, data: Ping/ProtocolVersion/Selfcheck }`（不需 vendor 登录），断言 daemon admin reply 经 bridge single-flight → `AdminReply{in_reply_to=request_id}` → relay 回到 D1、解码正确、与直连 stdio 基线语义一致。并发两条同类 admin 命令断言各自 request_id 正确关联、不串。→ 证明真实 daemon 组合 + 双向路由 + single-flight 关联。
- **T2 会话流转发 + 稳定身份（合成 machine，ungated）**：合成 machine 发脚本化流：turn A（`SessionStarted{session_id=S1, thread_id=T1}`→…→`ActionRequest`→[device 发 `SendCommand{Turn{S1}}` ActionDecision]→…→`TurnComplete`），随后 device 发 `SendCommand{Conversation{T1}}`（prompt），合成 machine 起 turn B（`SessionStarted{session_id=S2, thread_id=T1}`→`AgentItem`→`TurnComplete`）。device **订阅 `Events{conversation_id=T1}`**，断言：A、B 两个 turn 的事件都收到（**证明 prompt 触发新 turn_session_id 后 watcher 不丢流**）、seq 单调、`(conversation_id, turn_session_id)` 标注正确、晚订阅的第二 device 重放缓冲。→ 证明 fleet 转发 + 稳定身份 + 排序 + 补发。
- **T3 数据面不可见 / 控制面可读**：断言路由器仅凭控制面（`RemoteFrame.msg` 的 target/subscription）路由，喂随机不透明 `DataEnvelope::Plaintext` 仍正确路由且**从不解码内层**；反证控制面必须可读（把控制消息也 opaque 会导致无法路由）。→ 证明分层正确。
- **T4 真实会话全流穿透（gated，`AGENTDECK_E2E=1`）**：真实 `agentdeckd` 跑一次真实 Codex 或 CC 会话，device 订阅 conversation，断言 `SessionStarted→AgentItem 流→TurnComplete` 经 relay 完整穿透。默认 `cargo test` 跳过，对齐 AGENTS.md 门控 E2E 约定。

> **实现偏差记录（Task 8/9 落地后）**：R0 的订阅模型要求 device 已知 conversation_id 才能精确订阅（`SubTarget::Events` 无通配目标），而真实 daemon 场景下 conversation_id 在 SessionStart 之前不可预知，device 无法提前订阅。因此 T4 在 R0 阶段**只是编译校验 + 默认 skip 的意图占位**，即使设置 `AGENTDECK_E2E=1` 手动运行也会因收不到事件而超时失败（非 hang，30s 轮询超时后断言失败）。真实会话全流穿透的证明推迟到 **R2**（需身份 bootstrap，让 device 能在会话真正开始前按 conversation 精确订阅真实 daemon 会话）。R0 阶段的真实穿透证明改由 **T1（真实 daemon admin 双向往返）+ T2（合成会话全生命周期穿透，含稳定身份与补拉）+ T3（数据面内容不可见）** 三项 ungated 测试共同承担。
- **schema/中立性（ungated）**：protocol schema 快照纳入 `remote::*` 并同步；中立性测试断言 remote 类型无 vendor 字样。

### 验收标准（R0）

- 默认 `cargo test` 全绿，含 T1/T2/T3 + schema 漂移 + 中立性。
- 第二个客户端经 relay 看到某 machine 广告的 session 与其流式 `ServerEvent`（键 conversation_id）；prompt 触发的新 turn 事件不丢；晚订阅者得到缓冲重放。
- device→machine 命令（Ping/ProtocolVersion）经 relay 往返到**真实** `agentdeckd`，并发同类命令正确关联。
- 路由器可证明只读控制面、从不解码数据面内层。
- relay 日志中不出现数据面明文或 token-like 串。
- `agentdeck-cli remote smoke` 单进程跑通 machines/sessions/watch/ping（合成 machine 时含 send/approve），打印经 relay 转发的内容 + 信封元数据 + trace_id。
- gated `AGENTDECK_E2E=1` 下 T4 **编译通过、默认 skip**；真实会话穿透证明推迟到 R2（见上方实现偏差记录），R0 不要求 T4 手动运行通过。
- `scripts/verify-agent-docs.sh` 通过；协议变更后 schema 漂移测试通过；文档同步更新。

## 8. 后置项与开放问题

- **E2EE 库（R1 决定）**：倾向 daemon/relay 侧 Rust `crypto_box` + `chacha20poly1305`（对齐 happier 的 libsodium 语义），iOS 侧 CryptoKit `Curve25519` + `ChaChaPoly`，R1 互操作验证。不手写密码学。数据面 `DataEnvelope::Encrypted` 落在这里。
- **存储（R1）**：先 SQLite，公开托管前再评估 Postgres；R0 纯内存。
- **APNs（R3+）**：R0 无，R3 用 app 内在线通知先闭环。
- **配对安全（R2/R3 硬性要求）**：challenge nonce 必须服务端生成带 TTL（借鉴 happy issue #669 重放隐患教训）。
- **真实 daemon 会话身份 bootstrap（R2）**：首个 turn 前 thread_id 未定时，conversation_id 如何 bootstrap（临时以首个 turn_session_id 占位、thread_id 到达后回填）。R0 合成 machine 绕开。
- **macOS 是否也经 relay 接远端 machine**：后置，第一版 AppKit 仍优先本地 daemon。
- **`resolveApproval` 的 `persist` 语义**：R0 默认 `false`，R2 device 侧补显式开关。

## 9. 阶段↔版本映射（含 README 修订）

母设计用 R0-R4 阶段编号，README/unified-shell 用 v0.4+/v0.5 版本号，此前未对齐。本 spec 记录映射，并在 README/unified-shell 加一行交叉引用消歧：

| Relay 阶段 | 内容 | 版本锚点 |
|---|---|---|
| R0（本 spec） | 契约 spike：分层 remote frame + fleet 协议 + 稳定身份 + 内存 relay + CLI 基线 | v0.5 前置铺垫 |
| R1 | Relay MVP（`agentdeck-relay` binary、WS、SQLite、E2EE 落地） | v0.5 |
| R2 | agentdeckd remote mode（`--remote --relay-url`、身份 bootstrap、真实 reply envelope） | v0.5 |
| R3 | iOS Mobile Companion MVP（`RelaySessionSource`、扫码配对） | v0.4+ 移动伴侣 |
| R4 | Hosted / team mode 评估 | 后置 |

README/unified-shell 的修订仅为文档一致性（在「v0.5 daemon 远程化」「v0.4+ 移动伴侣」处加「= Relay 母设计 R1/R2 / R3」交叉引用），不改代码。

## 10. 落地后文档更新清单

- `README.md` / `docs/plans/2026-06-30-unified-shell-v02-design.md`：§9 版本映射交叉引用。
- `docs/index.md`：登记本 spec。
- 母设计 `2026-07-01-agentdeck-mobile-relay-design.md`：状态更新为「R0 落地中」，§6 `RemoteEnvelope` 标注被 R0 的控制面/数据面分层细化（`RemoteFrame`+`RelayControlMsg` / `DataEnvelope`）。
- `ARCHITECTURE.md`：R0 落地后如引入新不变量（如「relay 控制面可读、数据面不可见」）再补；R0 本身不新增不变量，仅复用 N1/N6/K5/K9/N8。
