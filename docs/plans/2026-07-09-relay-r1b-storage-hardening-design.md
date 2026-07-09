# AgentDeck Relay R1b 设计：SQLite 持久化 + Router 健壮化

| 字段 | 值 |
|---|---|
| 状态 | Design - §9 关键决策已拍板（2026-07-09）；实施计划见 `2026-07-09-relay-r1b-storage-hardening-implementation.md` |
| 日期 | 2026-07-09 |
| 主题 | Relay R1 第二子片（R1b）：`RelayStore` 的 SQLite 落地 + conv_buffer 上界/Ack-trim/重放补拉/AnnounceSession 去重/req_origin TTL 清理；并对 R1a whole-branch review 遗留的 10 条技术债逐条 triage |
| 关联 | `docs/plans/2026-07-08-relay-r1a-transport-auth-design.md`（R1a，已落地 12 任务）、`docs/plans/2026-07-08-relay-r1-design-review.md`（R1 决策评审 §8 D5-D8、§9 R1b 主线）、`ARCHITECTURE.md`（R1a-1~R1a-5 relay 不变量） |

## 0 摘要

**Goal**：把 R1a 的 `InMemoryRelayStore` 换成真 SQLite 实现（accounts/devices/challenges/revocation/per-conversation seq 高水位，persist-before-deliver），并把 R0 遗留、R1a 明确记账的 router 健壮化四项（conv_buffer 上界、Ack-trim、重放补拉、AnnounceSession 去重、req_origin TTL 清理）一并做掉，使 relay 具备**跨重启的 seq 单调性**与**有界内存**。同时把 R1a whole-branch review 标注的 10 条技术债逐条判定去向（进 R1b / 留 R1c-R2 / Won't Fix）。

**Non-Goals**：
- **不做 `DataEnvelope::Encrypted` 真加解密**（R1c；R1b 数据面仍是 `Plaintext`，机密性继续靠 R1a 已接通的 TLS 门禁）。
- **不做 daemon remote-mode**（R2）、**不做多账户/team ACL**（R4，`Subscribe{Machines}` account scope 过滤留到那时）。
- **不做 QR 扫码配对**（R3）。
- 任务拆分、TDD 顺序、subagent 排期不在本文——见配套的 `2026-07-09-relay-r1b-storage-hardening-implementation.md`。

## 1 R1a 遗留 triage

R1a 交付时记录了 10 条技术债（见 R1 决策评审文档「R1a 落地状态」小节）。逐条判定：

| # | 债务 | 判定 | 理由 |
|---|---|---|---|
| 1 | `WsRelayClient::recv` 把 IO 错误吞成 `None`（`RelayLink::recv` 无 `Result`） | **R2 defer**（有条件：见 §9-4） | 触及 `RelayLink` trait 签名，牵连 3 处 impl（`router.rs::RelayClient`、`relay-client::WsRelayClient`、`relay-client::InProcRelayClient`）+ `bridge.rs::spawn` 的消费循环。R1a 落地时自己的记账已写明"R2 wire trait 时统一"——R2 daemon remote-mode 本就要重新审视这层接口，此时一次性做比 R1b 单独做减少改两次的成本。R1b 若不做，`recv` 返回 `None` 时上层（bridge/CLI watch loop）仍只能表现为"连接结束"，无法区分是正常 Close 还是网络错误——这是可观测性缺口，不是正确性缺口，可以容忍到 R2。 |
| 2 | `Subscribe` replay 无 dedup（`WsRelayClient.subscriptions: Vec` 无界增长） | **R1b 做** | 纯客户端（`agentdeck-relay-client`）改动，不牵扯 SQLite/协议，风险低、体量小（把 `Vec<RemoteFrame>` 换成按 `SubTarget` 去重的映射）。放这里顺手做掉，避免和 R1b 的"重放补拉"改动产生认知混淆（都在讨论"订阅态"）。 |
| 3 | `EnrollError::MissingOwnerPubkey` 硬编码 failure code 未注册 | **R1b 做** | 一行常量 + 一处替换（`agentdeck-protocol/src/remote/failure.rs` 加 `PAIR_MISSING_OWNER_PUBKEY`，`server/pair.rs` 换用）。failure code 是字符串字面量不是 schema 里的枚举，**不触发 `UPDATE_SCHEMA`**。 |
| 4 | `Subscribe{Machines}` 无 account scope 过滤 | **R4 defer（多账户上线前）** | 与遗留清单本身的注记一致："只在升级到多账户后才有意义"。R1b/R1a 都是单 singleton account，没有第二个账户可供泄漏，做了也无法测试出真实收益，纯粹增加无法验证的代码。 |
| 5 | `Challenge.used` 死字段 | **随 §2.2 schema 设计顺带解决，非独立任务** | 现状 `take_challenge` 用"原子 remove"实现单次消费，`used` 字段从未被置 true（`store.rs` 已核实：`still_valid` 只读它、写路径只在 `Challenge` 构造时置 `false`）。SQLite 版 `challenges` 表设计时不引入 `used` 列（继续用"命中即 DELETE"的原子消费语义），死字段随内存 struct 一起被替换，不必单开票。 |
| 6 | `remote.rs`（`agentdeck-cli/src/remote.rs`，实测 955 行）拆子模块 | **待用户裁决，见 §6/§9-3** | 与 SQLite/router 无关，纯 CLI 整理债。 |
| 7 | `main.rs` 用 `env::args` 字面串 `== "--selfcheck"` 而非 `RawArgs.selfcheck: bool` | **待用户裁决，见 §6/§9-3** | 已核实：`agentdeck-relay/src/config.rs` 的 `RawArgs` 确有 `#[allow(dead_code)] selfcheck: bool` 字段（只为让 clap 不拒绝该参数），`main.rs` 却用 `std::env::args().iter().any(|a| a == "--selfcheck")` 重新扫一遍——两套解析并存，纯内部一致性债，不影响行为。 |
| 8 | `WsError::Connect(String)` 折叠所有 4xx | **R1b 做（小、独立、提升测试精度）** | 只改 `agentdeck-relay-client/src/ws.rs::dial`——`connect_async` 失败时若是 `tungstenite::Error::Http(response)`，取 `response.status()` 构造新变体 `WsError::Rejected { status, code }`；否则保留 `Connect(String)` 兜底。收益：R1a e2e 测试 `rejects_bad_secret_expired_nonce_revoked_and_unknown_cred` 目前只能断言 `.is_err()`，做完后可断言具体 4xx 语义。 |
| 9 | 无独立 Revoke 单测 | **R1b 做（测试项，见 §7）** | 一个新增 `#[tokio::test]` 直接调 `FakeRelay::revoke()` 断言活连接被关闭+后续同 credential 连接被拒，成本是十几行代码。 |
| 10 | `ureq` default features 拉 TLS stack 到 dev/CLI deps | **Won't Fix（本期）/ 待用户裁决，见 §6/§9-3** | 已核实：`ureq` 只出现在 `agentdeck-cli/Cargo.toml`（运行时依赖，REST enroll 用）与 `agentdeck-relay/Cargo.toml`（`[dev-dependencies]`，仅 e2e 测试用）——**均不传播进 daemon 依赖树**（daemon 不依赖 relay/relay-client/cli 任何 crate），不违反 daemon-no-net 不变量。纯编译时间/依赖面 nit。 |

R1 决策评审 §9 R1b 主线的 5 条（RelayStore SQLite、conv_buffer 上界+Ack-trim+重放补拉、AnnounceSession 去重、req_origin TTL 清理、persist-before-deliver）**全部纳入 R1b**，详见 §2/§3。

## 2 SQLite 存储层设计

### 2.1 Crate 选型（**已决策，2026-07-09**）

**已决策：`rusqlite` + `features = ["bundled"]`**（同步 API；Core 每次持久化调用用 `tokio::task::spawn_blocking` 包一层再 `await`，不维护独立的 mpsc Store 任务/线程，见 §2.3）。

理由：dep 面小（~2 crate）、`bundled` 静态编译 libsqlite3 进二进制不依赖系统库，与 rustls 选型同源的"薄单二进制、交叉编译友好"哲学一致；relay 是单写者、查询集合小且固定的自托管场景，`sqlx`（~40 crates，与拒绝把 axum 拉进 CLI/daemon 同样的重量级依赖理由）与 `deadpool-sqlite`（池化对写无帮助，反而引入 WAL 多连接可见性心智负担）都不划算。若未来转向多租户 hosted 服务（R4+），再评估切 sqlx/连接池。

### 2.2 Schema

relay 独立 `--data-dir`（R1a-4 不变量：与 daemon/CLI 数据目录隔离），SQLite 文件路径由新增 `--storage <path>` / `AGENTDECK_RELAY_STORAGE` 配置（默认如 `<data-dir>/relay/relay.db`，具体默认值留实施计划）。启动时打开 `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`（WAL 允许 1 写者+N 读者并发；`synchronous=NORMAL` 在 WAL 下是官方推荐的性能/持久性平衡点，courier 崩溃只可能丢**最后一次未提交的事务**，不会破坏已提交数据完整性）。

一次性建库（无历史数据迁移，见 §8），但为 R1c 及以后的 schema 演进预置一个轻量迁移框架：`PRAGMA user_version` 记录当前 schema 版本 + 一段有序迁移 SQL 数组，启动时 `while user_version < migrations.len() { apply next; bump user_version }`，幂等可重复运行。

```sql
-- accounts：R1b 仍是 singleton（应用层强制只插入一行，schema 本身不限制行数，
-- 为 R4 多账户预留——到时只是放开这条应用层约束，schema 不用改）。
CREATE TABLE accounts (
    account_id          TEXT PRIMARY KEY,
    owner_sign_pubkey   TEXT NOT NULL,
    created_at_ms       INTEGER NOT NULL
);

CREATE TABLE devices (
    device_id           TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(account_id),
    role                TEXT NOT NULL CHECK (role IN ('machine', 'device')),
    credential_hash     TEXT NOT NULL UNIQUE,
    sign_pubkey         TEXT NOT NULL,
    box_pubkey          TEXT NOT NULL,
    revoked             INTEGER NOT NULL DEFAULT 0,
    created_at_ms       INTEGER NOT NULL
);
CREATE INDEX idx_devices_credential_hash ON devices(credential_hash);
-- WS 握手鉴权的高频路径（R1a 内存实现是线性扫描 devices，注释里已自述
-- "内存 fake relay 场景设备规模小，可接受"）；SQLite 版靠这个索引替换线性扫描。

CREATE TABLE challenges (
    device_sign_pubkey  TEXT PRIMARY KEY,
    nonce               TEXT NOT NULL,
    expires_at_ms       INTEGER NOT NULL
    -- 不设 used 列：消费语义 = "命中未过期即 DELETE"（原子单次消费），
    -- 延续 R1a `take_challenge` 的实现，不引入 R1a 遗留 #5 的死字段。
);

-- 每个 conversation 的 seq 高水位——独立于事件内容表，保证"seq 单调"这个
-- 最关键的不变量即使不落盘事件内容也能兑现（见 §2.3 的分层讨论）。
CREATE TABLE seq_high_water_marks (
    conversation_id     TEXT PRIMARY KEY,
    next_seq            INTEGER NOT NULL DEFAULT 0,
    acked_seq           INTEGER NOT NULL DEFAULT -1  -- 见 §3.1 Ack-trim
);

-- 事件内容表：R1b 默认只在 `content_persisted=0` 时留空 payload（见 §2.4 的
-- 关键待决策）；R1c Encrypted 落地后可安全地把 content_persisted 翻 1。
-- encryption_version 现在就加，避免 R1c 再 ALTER TABLE。
CREATE TABLE conv_events (
    conversation_id     TEXT NOT NULL,
    seq                 INTEGER NOT NULL,
    turn_session_id     TEXT NOT NULL,
    encryption_version  INTEGER NOT NULL DEFAULT 0,   -- 0=Plaintext；R1c 引入 1=Encrypted，同表不迁移
    payload             BLOB,                          -- NULL 表示本行只记账不留内容（见 §2.4）
    created_at_ms       INTEGER NOT NULL,
    PRIMARY KEY (conversation_id, seq)
);
```

`Device`/`Account`/`Challenge` 的 Rust 结构体形状与 R1a 内存版基本一致（见 `agentdeck-relay/src/auth/store.rs`），只是 `impl RelayStore for InMemoryRelayStore` 换成 `impl RelayStore for SqliteRelayStore`，trait 签名不变——**触及面小**（`server/mod.rs::AppState.store` 的具体类型换掉，`main.rs` 换构造函数，其余调用方不感知）。

### 2.3 Persist-before-deliver seq 高水位

**语义**：`PublishEvent` 到达 Core 时，**先**让 Store 任务把该事件的 `(conversation_id, seq)` 落盘（至少高水位，见 §2.4 的内容落盘可选项），**确认持久化后**才 `send_to` 广播给订阅方；relay 崩溃重启后，任一 conversation 的下一个可用 `seq` 从 SQLite 的 `next_seq` 恢复，绝不回退或重复发放。

**架构**（延续 D8 "rusqlite + 专用 Store 任务"）：

```
Core actor (async, 单线程串行)
   │  PublishEvent 到达
   │  StoreMsg::ReservePersist { conversation_id, turn_session_id, payload, reply: oneshot }
   ▼
Store 任务（专用 OS 线程或 spawn_blocking，跑同步 rusqlite 调用）
   │  BEGIN; UPSERT seq_high_water_marks SET next_seq=next_seq+1 RETURNING (next_seq-1) AS seq;
   │         INSERT INTO conv_events(conversation_id, seq, ..., payload) VALUES (...);
   │  COMMIT;
   │  reply.send(seq)
   ▼
Core 收到 seq → 构造 Event{seq, ...} → send_to 订阅方广播（原 conv_buffer 内存 append 逻辑保留，见 §3.1）
```

关键点：
- **Core 本身不做同步 IO**——它把请求丢进 mpsc 给 Store 任务，`.await` 一个 oneshot 回执，实际的阻塞式 rusqlite 调用发生在别的 OS 线程，不占用 tokio 工作线程（延续 R1a 已经确立的"Core 绝不被慢操作 await 阻塞"精神，只是这里"慢操作"从"慢连接"换成"磁盘 IO"）。
- **写全程串行化**：所有 conversation 的持久化请求都过同一个 Store 任务的 mpsc 队列，天然保证"同一 conversation 内 seq 严格递增"且"跨 conversation 无锁竞争假象"（SQLite 单写者本来也不允许并发写事务，用单任务天然对齐这个约束，不需要额外加锁）。
- **延迟成本**：本地 SQLite（WAL + `synchronous=NORMAL`）单行 upsert+insert 提交通常在个位数毫秒内；对自托管单运营者场景（不是高频 SaaS 网关）可接受。若未来 profiling 发现是瓶颈，优化方向是 Hi-Lo 式批量预留 seq 区间（一次 DB 往返领一段 `[lo, hi)`，区间内 seq 发放不用等 DB），**本设计不预先引入这个复杂度**——先用最简单、正确性最直观的"一事件一事务"，需要时再做局部优化（`seq_high_water_marks` 表已经是这套优化天然的落点，不需要改 schema）。

### 2.4 事件内容是否落盘（**已决策，2026-07-09**）

**已决策：选项 2**——R1b 只落盘 seq 高水位（§2.3 的 `seq_high_water_marks`）+ 事件元数据行（`conv_events` 每条事件占一行，用于 debug/审计与未来 Ack 游标对齐），**`payload` 列本期恒为 `NULL`**（记账不留内容）；事件内容继续只活在内存有界 `conv_buffer`（见 §3.1）。R1c 引入 `DataEnvelope::Encrypted` 后，把 `payload` 列写入策略从"恒 NULL"翻转为"写入密文字节"（schema 不变，`encryption_version` 列已预留）。

选择理由：忠实于 R1a 已拍板的"R1b 保持 Plaintext"边界，不在磁盘上扩大明文暴露面（内存瞬时 vs 磁盘持久取证/备份复制风险不同）；不需要在 R1c 做 schema 迁移或数据回填。

**直接影响**："重放补拉"（§3.1）语义收紧为**relay 进程存活期内**的有界补拉（因背压/短暂断线导致的 lagged 订阅方补齐），而非跨 relay 崩溃重启的完整历史重放——真正需要跨重启找回完整历史的场景，由客户端向对应 machine/daemon 重新拉取历史。

## 3 Router 健壮化

### 3.1 conv_buffer 上界 + Ack-trim + 重放补拉

现状（`router.rs`）：`conv_buffer: HashMap<String, Vec<RelayControlMsg>>` 无界增长，每条 `PublishEvent` 都 `push`，`Subscribe{Events}` 时把整个 Vec 回放给新订阅者。`RelayControlMsg::Ack { up_to_seq, conversation_id }`（注意：**这个变体 R1a 就已经在协议里**，见 `agentdeck-protocol/src/remote/control.rs`，只是 Core 里当前是 no-op：`RelayControlMsg::Ack { .. } | RelayControlMsg::Heartbeat { .. } => {}`）——R1b 是**接上已有变体的真实语义**，不是新增协议帧。

设计：
- **硬上界**：`conv_buffer` 每个 conversation 保留最近 N 条（配置项，默认值待定，见 §9-6），超过 N 条时从头丢弃最旧的（FIFO），不管有没有被 ack。这是防 OOM 的最后防线，独立于 Ack 机制生效。
- **Ack 驱动的提前 trim**：Core 收到 `Ack{up_to_seq, conversation_id}` 后，更新 `seq_high_water_marks.acked_seq`（走 §2.3 同一 Store 任务，或允许异步落后写入——ack 不是关键正确性路径，可以放宽持久化时序要求，不必 persist-before-ack-effect）；同时**在内存里**推进"该 conversation 当前所有活跃订阅连接里最小的已知 acked_seq"，`conv_buffer` 裁到这个 min-acked 之前的条目可以安全丢弃（因为所有还在线的订阅方都已确认收到）。注意：这是**优化**（让内存更早释放），硬上界（上一条）才是**正确性保证**（防止某个连接从不 ack 时内存无限增长）。
- **重放补拉**（受 §2.4 选项 2 影响，语义收紧为进程存活期内）：`Subscribe{Events{conversation_id}, since_seq: Option<u64>}`（`Subscribe` 帧的 `SubTarget::Events` 变体需要新增 `since_seq` 字段——**协议变更**，触发 `UPDATE_SCHEMA`）。收到订阅时：若请求的 `since_seq` 仍在当前内存 `conv_buffer` 覆盖范围内，直接从内存回放；若 `since_seq` 早于内存最旧条目（已被 FIFO 丢弃）但仍 `<= seq_high_water_marks.next_seq`，说明存在"已确认发生但当前不可重放"的 gap——按 §2.4 选项 2，relay 明确告知客户端"补拉不可用，请求所需 seq 已超出保留窗口"（新失败码，如 `relay.replay.gap`），客户端据此转向"向对应 machine 重新拉取完整历史"而不是死等 relay。

### 3.2 AnnounceSession 去重

现状：`Core::sessions: HashMap<String /* machine_id */, Vec<SessionDescriptor>>`，`AnnounceSession` 处理逻辑是无条件 `push`——同一 machine 重启后重新 `AnnounceSession` 同一个 `conversation_id`，`sessions` 里会出现重复条目（`SessionList` 广播给订阅方时看到同一会话两次）。

设计：把 `sessions` 的内层从 `Vec<SessionDescriptor>` 换成按 `conversation_id` 去重的映射（`IndexMap<String, SessionDescriptor>` 或等价的"upsert by key"结构，保留插入顺序供 `SessionList` 展示稳定），`AnnounceSession` 处理逻辑改为"存在同 `conversation_id` 则覆盖，否则插入新条目"——一行逻辑变化即可解决重复展示，`conv_machine` 映射（`insert` 覆盖语义）本身已经是幂等的，不需要改。

关于模板提到的 `session_started_at_ms` 字段：这是给未来"同一 `conversation_id` 被不同实际会话复用"场景的消歧字段（理论场景：daemon 侧 `conversation_id` 生成策略变化导致碰撞）。**当前无证据表明这是 R1b 要解决的真实场景**（`conversation_id` 目前由 daemon 生成，具体唯一性保证在 daemon 侧文档中记录），加这个字段需要改 `SessionDescriptor`（协议类型，触发 `UPDATE_SCHEMA`）却没有消费方。**建议不加**，除非用户认为有具体已知的碰撞场景需要现在防御——upsert-by-`conversation_id` 已经解决了"R1a 遗留 #13 重复展示"这个已确认的真实 bug，消歧字段是防御性的、无已知触发条件的额外复杂度。

### 3.3 req_origin TTL 清理

现状：`Core::req_origin: HashMap<String /* request_id */, ReqOrigin>`，只在 `AdminReply` 成功匹配时 `remove`；若 `SendCommand` 的目标 machine 从未回复（离线/崩溃/命令语义就是 fire-and-forget），该 `request_id` 永久滞留，长驻进程会缓慢泄漏。

设计：
- `ReqOrigin` 加 `created_at_ms: i64` 字段（frame 落地时的边缘时间戳，延续"边缘 ingest 点 stamp、relay 不覆写"的既有约定）。
- 引入周期性清扫：不给 Core 的单 actor 循环加独立定时器（会打破"只有 `rx.recv().await` 一处等待点"的简单心智模型），而是用一个独立的 `tokio::spawn` 心跳任务，每 N 秒（TTL 的一个合理分数，如 TTL/2）向 Core 的 `core_tx` 发一条新的 `CoreMsg::SweepReqOrigin { now_ms }` 消息——**清扫逻辑仍在 Core 单线程里执行**，不引入额外的锁或借用冲突，只是触发源从"处理某个 frame 顺带检查"换成"独立定时消息"。
- 默认 TTL 建议 5 分钟（模板建议值，具体默认见 §9-6 一并决定，或作为独立小项）。

## 4 RelayLink trait 演化（**R1b 范围内做 §4.2/§4.3，§4.1 defer 见 §1/§9-4**）

### 4.1 recv 返回 Result — R2 defer（不在 R1b 范围）

`RelayLink::recv` 目前把连接层 IO 错误吞成 `None`（无法区分正常 Close 与网络错误）。R1a 落地时已自述"R2 wire trait 时统一"，且改签名会牵连 3 处 impl（`router.rs::RelayClient`、`relay-client::WsRelayClient`、`relay-client::InProcRelayClient`）+ `bridge.rs::spawn` 的消费循环——与 R1b 的 SQLite/router 主线无直接耦合。R2 daemon remote-mode 本就要重新审视这层接口，此时一次性做比 R1b 单独做再改一次成本更低，故推迟到 R2。这是可观测性缺口（上层无法区分断连原因），不是正确性缺口，可以容忍到 R2。

### 4.2 Subscribe replay dedup（R1a 遗留 #2）

`agentdeck-relay-client/src/ws.rs::WsRelayClient`：`subscriptions: Mutex<Vec<RemoteFrame>>` 换成按 `SubTarget` 去重的存储（如 `Mutex<HashMap<SubTargetKey, RemoteFrame>>`，`SubTargetKey` 从 `SubTarget` 派生一个可 `Hash`/`Eq` 的 key——`SubTarget` 本身已是 `#[derive(PartialEq, Eq)]`，若补 `Hash` 派生即可直接当 key，不需要额外 wrapper 类型）。`reconnect()` 时按去重后的集合重放，不再重复重放同一目标的历史订阅帧。

### 4.3 WsError 4xx 精细化（R1a 遗留 #8）

`agentdeck-relay-client/src/ws.rs::dial`：`connect_async` 失败时，若错误是 `tungstenite::Error::Http(response)`，提取 `response.status()`（如可用，`response.body()` 里的失败码 JSON）构造新增变体：

```rust
#[derive(thiserror::Error, Debug)]
pub enum WsError {
    #[error("ws connect: {0}")]
    Connect(String),
    #[error("ws rejected: status={status} code={code:?}")]
    Rejected { status: u16, code: Option<String> },
    #[error("ws io: {0}")]
    Io(String),
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
}
```

非 HTTP 4xx 的连接失败（DNS 解析失败、TCP 拒连等）仍归入 `Connect(String)`。R1a e2e 测试 `rejects_bad_secret_expired_nonce_revoked_and_unknown_cred` 从只能断言 `.is_err()` 升级为可断言具体 `status`/`code`。

## 5 协议扩展

### 5.1 `failure::PAIR_MISSING_OWNER_PUBKEY` 常量注册（R1a 遗留 #3）

`agentdeck-protocol/src/remote/failure.rs` 加：

```rust
pub const PAIR_MISSING_OWNER_PUBKEY: &str = "relay.pair.missing_owner_pubkey";
```

`agentdeck-relay/src/server/pair.rs` 里 `EnrollError::MissingOwnerPubkey` 的错误响应换用该常量（当前具体映射方式待实施阶段看代码现状，本设计只锁定常量名与语义）。不触发 `UPDATE_SCHEMA`（failure code 是自由字符串，不在 schema 的类型枚举里）。

### 5.2 Ack 语义落地（**不是新增协议帧——修正模板假设**）

`RelayControlMsg::Ack { up_to_seq: u64, conversation_id: Option<String> }` **R1a 就已经在协议里**（`control.rs` 已确认），Core 当前把它当 no-op 丢弃。R1b 的工作是：

1. **把 `conversation_id` 从 `Option<String>` 收紧为 `String`（必填）**——这是 R1 决策评审 G4 条目点名的遗留歧义（"`None` 语义未定义"），既然 R1b 要第一次真正实现 Ack 消费逻辑，顺手把这个字段紧上是最低成本的时机：目前**没有任何客户端真的发送过有意义的 Ack 帧**（Core 侧是 no-op，没有消费方倒逼语义），收紧它是纯内部改动、不破坏任何现存真实流量。这个协议改动触发 `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`。
2. Core 的 `handle_frame` 给 `Ack` 分支接上 §3.1 描述的 trim 逻辑（替换当前的 `RelayControlMsg::Ack { .. } => {}` 分支）。
3. **客户端侧发送方**：目前没有任何客户端代码发送 Ack（CLI `remote watch`/`send` 等命令目前只消费 `Event`，不回 Ack）。R1b 若要让 Ack-trim 在真实链路里产生效果（而不是只有 Core 侧逻辑就绪、无人触发），需要在 CLI 的事件消费循环里补一处"处理完一批事件后发 `Ack{up_to_seq}`"。这个 CLI 侧改动体量不大，但**是否属于 R1b 范围**留给用户在 §9 拍板（见 §9-6 附带项）——若不做，硬上界（§3.1 第一条）仍然独立生效，只是 Ack 提前 trim 这个优化路径在 R1b 完成时暂时"有骨架无调用方"，等 R2/CLI 后续迭代接上。

## 6 CLI 侧收尾（**已决策：整章 defer 到独立 CLI polish PR，2026-07-09**）

R1b 专注 relay 侧 SQLite + router 健壮化；以下三项 R1a whole-branch review 标的债与 SQLite/router 主线无直接耦合，全部推到独立的 CLI polish PR，供该 PR 参考：

- **6.1** `agentdeck-cli/src/remote.rs` 拆子模块（已核实实测 955 行）——建议拆为按子命令分组的模块（如 `remote/pair.rs`、`remote/machines.rs`、`remote/session.rs`，具体切法留该 PR 决定）。
- **6.2** `agentdeck-relay/src/main.rs` 改用 `RawArgs.selfcheck: bool`（已核实字段存在但 `#[allow(dead_code)]`）替换 `env::args` 字面串匹配。
- **6.3** `ureq` 加 `default-features = false` 精简 TLS 依赖面（已核实不影响 daemon 树，纯 dev-dep/CLI-dep 编译时间 nit）。

## 7 测试策略

- **SQLite 层**：
  - unit tests：schema 建库幂等（重复调用 migration 不报错）、`SqliteRelayStore` 对 `RelayStore` trait 每个方法的 CRUD 覆盖（含 `device_by_credential_hash` 走索引命中）、`seq_high_water_marks` 的 upsert-and-return 原子性（并发/顺序调用不产生重复 seq）。
  - 集成测试：起 `tempdir` 里的真实 SQLite 文件，模拟"relay 进程重启"（关闭+重新打开同一文件的 `SqliteRelayStore`），断言 `next_seq` 从持久化值恢复、已 revoke 的设备重启后依然被拒。
- **Router 健壮化**：新增 3-5 组 unit test：conv_buffer 命中硬上界后旧事件被丢弃（且不影响 seq 单调）、Ack 收到后 min-acked 之上的内容仍可给新订阅者重放而之下的被裁剪、AnnounceSession 重复调用后 `SessionList` 不重复、req_origin 超 TTL 被清扫（用 `tokio::time` paused-time 断言，避免真实 sleep）；+ 1 组 e2e：lagged 连接重连后按 `since_seq` 补拉（覆盖"内存窗口内可补"与"§2.4 选项 2 下窗口外返回 `relay.replay.gap`"两个分支）。
- **RelayLink 演化**：更新现有 5/6 e2e 里断言 `.is_err()` 的处改为断言具体 `WsError::Rejected{status,...}`；`Subscribe` dedup 加一个"重复 subscribe 同一 target N 次，`subscriptions` 集合大小恒为 1"的单测。
- **Revoke 独立单测**（R1a 遗留 #9）：直接调 `FakeRelay::revoke(device_id)` 断言活连接被关闭。
- 沿用 R1a 已确立的分层原则：逻辑测留内存确定性（Core 单测不需要真 SQLite，`RelayStore` trait 在测试里可继续用一个内存假实现或直接指向 `tempdir` SQLite，两者皆可，具体选择留实施计划）；WS/网络面测试保持 loopback + ephemeral port + bounded timeout 的既有模式。

## 8 Migration 与 backward compat

- **R1a → R1b**：R1a 是纯内存 store，无持久数据可迁移。R1b 首次启动时，`SqliteRelayStore::open(path)` 若目标文件不存在则建库（`PRAGMA user_version = 0` → 跑第一版 migration → `user_version = 1`）；若文件已存在（比如同一份 R1b 二进制重启），跳过已应用的 migration。**无历史数据迁移脚本需要**。
- **Ack 帧字段收紧（§5.2 第 1 条）对旧 client 的兼容**：**这不是新增变体，模板原先假设的"旧 client 收到 unknown variant 该 log-and-skip 还是 error close"这个问题在这里不成立**（Ack 变体本身 R1a 就有，不是新加的）。真正的兼容问题窄化为："把 `conversation_id` 从 `Option` 收紧为必填，是否会让现存的、真的发送过 `Ack{conversation_id: None}` 的调用方在升级后被 `deny_unknown_fields`/反序列化拒绝？" ——已核实代码库里**没有任何生产路径发送 Ack**（Core 侧是 no-op，CLI 侧未见发送方），这是一次**零真实调用方影响**的 breaking wire tweak，可以直接做、用 schema 快照测试兜底即可，不需要设计兼容策略。
- **`Subscribe{Events}` 新增 `since_seq` 字段**（§3.1）：这是给现有变体加一个新字段，若走 `#[serde(default)]` 可保持向后兼容（旧客户端不传该字段时按 `None` 处理，relay 侧语义等价于"从当前订阅时刻起收，不补拉历史"，即 R1a 现状行为）；但 `RelayControlMsg` 顶层是 `deny_unknown_fields`——新增字段本身不受这个约束影响（`deny_unknown_fields` 拒绝的是**未声明**字段，`since_seq` 一旦声明进 struct 就是已知字段，旧版本 relay 收到带 `since_seq` 的新版客户端请求才会因为"relay 不认识这个字段"报错，但这属于"relay 版本落后于 client"场景，由既有的 `RELAY_PROTOCOL_VERSION` 握手协商兜底，不是本设计需要新解决的问题）。

## 9 关键待决策项汇总

**已决策（2026-07-09）**：

1. **SQLite crate 选型**：**已决策** `rusqlite` + `bundled` feature。理由见 §2.1。
2. **事件内容是否落盘**：**已决策** 选项 2——R1b 只落盘 seq 高水位/元数据，`payload` 列本期恒为 `NULL`，内容仍只活在内存有界 buffer；重放补拉语义收紧为"relay 进程存活期内"。见 §2.4。
3. **CLI 侧收尾（§6.1-6.3）**：**已决策** 全部 defer 到独立 CLI polish PR，R1b 不做。见 §6。
4. **`RelayLink::recv` 返回 `Result`（R1a 遗留 #1）**：**已决策** R2 defer（牵连 3 处 impl + bridge 消费循环，与 R1b 的 SQLite/router 主线无直接耦合，R2 wire trait 统一时同期处理）。见 §4.1。

**实施计划阶段确定，本期无阻塞**：

5. **Ack 提前 trim 的 CLI 侧发送方（§5.2 第 3 条）**：Core 侧 trim 逻辑纳入 R1b，但 CLI 侧是否随行补发送逻辑留给实施计划评估（不影响本设计的架构结论——硬上界始终独立生效，Ack 优化路径即使暂无调用方也不影响正确性）。
6. **conv_buffer 硬上界数值** + **req_origin TTL 数值**：做成 `RelayConfig` 可配置项这一点已确定（延续 R1a 已有配置模式），具体 default 数值留给实施计划给出建议值。

## 10 R1b 范围外（明确 defer）

- **R1c**：`DataEnvelope::Encrypted`（IETF ChaCha20-Poly1305 + X25519/HKDF）+ 跨语言测试向量；用 R1a 已登记 box 公钥封装 per-session DEK；`conv_events.payload` 落盘策略翻转为写入密文（见 §2.4）；seal 策略（required_e2ee/optional/plaintext_only）；机器侧 box 私钥托管。
- **R2**：`RelayLink::recv` 返回 `Result`（本文 §9-4 待用户 override）；agentdeckd remote-mode（daemon 直连 relay，取代外部 bridge）；outbound reconnect/backoff。
- **R3**：QR 扫码配对 UX；iOS `RelaySessionSource`；跨平台密码学互操作验证；APNs。
- **R4**：`Subscribe{Machines}` account scope 过滤（多账户上线前无实际意义）；hosted/多租户/team ACL；scoped 凭据。
- **Won't Fix（本期不做，非永久搁置）**：`ureq` default-features 精简（待 §9-3 裁决，倾向可做但非阻塞）；`session_started_at_ms` 消歧字段（无已知触发场景，见 §3.2）。
