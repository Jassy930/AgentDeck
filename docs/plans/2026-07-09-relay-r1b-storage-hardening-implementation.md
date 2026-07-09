# Relay R1b（SQLite 持久化 + Router 健壮化）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 R1a 的 `InMemoryRelayStore` 换成真 SQLite 实现（accounts/devices/challenges + per-conversation seq 高水位，persist-before-deliver），并把 router 健壮化四项（conv_buffer 上界、Ack-trim、重放补拉、AnnounceSession 去重、req_origin TTL 清理）一并做掉，使 relay 具备**跨重启的 seq 单调性**与**有界内存**；同时收编 R1a whole-branch review 里判定"R1b 做"的小额技术债（`PAIR_MISSING_OWNER_PUBKEY` 注册、`Subscribe` replay 客户端去重、`WsError` 4xx 精细化、Revoke 独立单测）。CLI 侧收尾（remote.rs 拆模块/selfcheck bool/ureq features）与 `RelayLink::recv` 返回 `Result` 均已在设计文档 lock-in 为 defer，本计划不含对应任务。

**Architecture:** 新增 `agentdeck-relay/src/store.rs`：`SqliteRelayStore`（`Arc<Mutex<rusqlite::Connection>>` 包裹，`Clone` 廉价）——① 实现 `auth::store::RelayStore` trait（accounts/devices/challenges CRUD，替换 `InMemoryRelayStore` 供 server 生产路径使用；`InMemoryRelayStore` 保留供 `auth::enroll` 纯函数单测）；② 额外提供 inherent 方法做 seq 高水位与事件元数据持久化（`reserve_and_persist_event`/`record_ack`/`load_next_seq`），供 Core（`router.rs`）在 `tokio::task::spawn_blocking` 里调用——accounts/devices/challenges/seq_high_water_marks/conv_events 共享同一份 schema/文件，`FakeRelay::start_with_store(store)` 把同一个 `SqliteRelayStore` 实例同时接到 Core 与（生产路径下）`AppState`，避免维护两套持久化通道。`FakeRelay::start()`（既有 15+ 处调用点）保持签名不变，内部默认开 `SqliteRelayStore::open_in_memory()`，测试无感知、无需真实磁盘 IO。

Core 侧加：`Ack` 分支从 no-op 接上语义（`conversation_id` 收紧为必填 + trim `conv_buffer` 到 min-acked）、`conv_buffer` 硬上界 FIFO（独立于 Ack 生效，防 OOM）、`Subscribe{Events}` 新增 `since_seq` 字段驱动的重放补拉（内存命中直接回放；gap 时返回新失败码 `relay.replay.gap`）、`sessions: HashMap<String, Vec<SessionDescriptor>>` 改按 `conversation_id` upsert 去重、`req_origin` 加 `created_at_ms` + 独立心跳任务触发 `CoreMsg::SweepReqOrigin` 做 TTL 清扫。协议加 `failure::PAIR_MISSING_OWNER_PUBKEY`、`SubTarget::Events.since_seq: Option<u64>`、`WsError::Rejected{status, code}`；relay-client 的 `WsRelayClient.subscriptions` 从 `Vec` 换成按 `SubTarget` 去重的映射。`RelayConfig` 加 `storage_path`/`conv_buffer_cap`/`req_origin_ttl_ms` 可配置项，`main.rs`/`server::serve` 接入 `SqliteRelayStore`。e2e 加 SQLite 重启恢复 + Ack-trim + 重放补拉 gap + AnnounceSession 幂等 + req_origin TTL + Revoke 独立单测。

**Tech Stack:** Rust edition 2024；新增 `rusqlite = { version = "0.32", features = ["bundled"] }`（同步 API，写路径全部包 `tokio::task::spawn_blocking`，不手写 SQL↔struct 映射 crate——查询集合小且固定，手写 mapping 避免扩大 dep 面）；`tempfile = "3"`（dev-dep，测试用真实文件路径验证重启恢复）。沿用 R1a 已钉版的 `thiserror = "1"`、`rand_core = "0.6"`、`serde`/`serde_json`。

设计依据：`docs/plans/2026-07-09-relay-r1b-storage-hardening-design.md`（R1b 设计，§9 四项决策已 lock-in）+ `docs/plans/2026-07-08-relay-r1a-transport-auth-implementation.md`（R1a，已落地 12 任务，本计划延续其 SDD workflow 与文件/依赖钉版风格）。

## Global Constraints

- Rust edition **2024**；新文件延续既有 `agentdeck-relay` crate 结构（无独立新 crate）。
- **依赖钉版**：`rusqlite = "0.32"` + `features = ["bundled"]`（bundled 静态编译 sqlite3 C 码，不依赖系统库，交叉编译友好，与 rustls 选型同一哲学）；`tempfile = "3"`（dev-dep）。不引入 `sqlx`/`deadpool-sqlite`/任何 ORM 或 SQL builder。
- **CI-grade invariants 延续 R1a**：`agentdeckd` 依赖树无 `tokio net`/`axum`（`scripts/check-daemon-no-net.sh` 继续绿）；`agentdeck-cli` 不含 axum；`thiserror` 单版本 1.x、`rand_core` 单版本 0.6 不因新依赖被打破（`cargo tree` 校验）。
- **N6/`RelayLink` trait 签名不动**：`recv` 返回 `Result` 已在设计 §4.1 lock-in R2 defer，本计划不做、不预留过渡代码。
- **`RelayStore` trait（auth/store.rs）签名不变**：`InMemoryRelayStore` 保留不删——`auth::enroll` 现有单测（R1a Task 6）继续用它，不改造为必须过 SQLite。
- **Schema 一次性建库、无历史数据迁移**（R1a 是纯内存 store）；schema 变更走 `PRAGMA user_version` + 有序迁移数组，新增迁移只 append 不改写已提交的迁移 SQL。
- **协议改动后**：`UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` 重生成快照并提交。
- 提交不加 co-author；直接在 master 提交、未经请求不推送；`Cargo.lock` 随依赖变更一并 `git add`。
- **CLI 侧不动**：本计划任何 task 都不改 `agentdeck-cli/src/remote.rs` 的 Ack 发送逻辑或拆模块——两者均已 lock-in defer（见设计 §6、本计划 Task 5 说明）。
- 遵循 R1a 已确立的 SDD workflow：每 task 独立 review、5 步 TDD（写测试→确认 FAIL→实现→确认 PASS→Commit）。

## 文件结构（决策锁定）

```text
agentdeck-protocol/src/remote/failure.rs          # 改：加 PAIR_MISSING_OWNER_PUBKEY + REPLAY_GAP
agentdeck-protocol/src/remote/control.rs          # 改：SubTarget::Events 加 since_seq；Ack.conversation_id 收紧非 Option
protocol/agentdeck/agentdeck-protocol.schema.json # 改：UPDATE_SCHEMA 回写
agentdeck-relay-client/src/ws.rs                  # 改：WsError::Rejected 变体；dial 解析 tungstenite::Error::Http
agentdeck-relay-client/src/lib.rs                 # 改（如需要）：subscriptions 去重相关 re-export
agentdeck-relay/src/server/pair.rs                # 改：MissingOwnerPubkey 换用注册的失败码常量
agentdeck-relay/Cargo.toml                        # 改：加 rusqlite（bundled）+ tempfile(dev-dep)
agentdeck-relay/src/store.rs                      # 新：SqliteRelayStore（RelayStore 实现 + seq/事件持久化方法）+ schema/migration
agentdeck-relay/src/lib.rs                        # 改：mod store;
agentdeck-relay/src/router.rs                     # 改：Ack 语义、conv_buffer 上界+trim、重放补拉、AnnounceSession 去重、req_origin TTL、FakeRelay::start_with_store
agentdeck-relay/src/config.rs                     # 改：storage_path/conv_buffer_cap/req_origin_ttl_ms 字段 + env
agentdeck-relay/src/server/mod.rs                 # 改：AppState.store 类型换 SqliteRelayStore；serve 签名接入
agentdeck-relay/src/main.rs                       # 改：构造 SqliteRelayStore、接线 Core + server
agentdeck-relay/tests/r1a_ws_e2e.rs               # 改：InMemoryRelayStore 构造点换 SqliteRelayStore（in-memory）；WsError 断言升级
agentdeck-relay/tests/r1b_hardening_e2e.rs        # 新：Ack-trim/重放补拉 gap/AnnounceSession 幂等/req_origin TTL/SQLite 重启恢复 e2e
AGENTS.md / ARCHITECTURE.md / docs/index.md       # 改：R1b 验证入口 + 不变量 + 索引登记
docs/plans/2026-07-08-relay-r1-design-review.md   # 改：§6 补 R1b 落地状态
```

---

### Task 1: 协议扩展——`PAIR_MISSING_OWNER_PUBKEY` 注册 + `Subscribe{Events}.since_seq` + `WsError::Rejected`

**Files:**
- Modify: `agentdeck-protocol/src/remote/failure.rs`
- Modify: `agentdeck-protocol/src/remote/control.rs`（`SubTarget::Events { conversation_id, since_seq: Option<u64> }`）
- Modify: `agentdeck-relay/src/server/pair.rs`（替换硬编码字符串 `"relay.pair.missing_owner_pubkey"`）
- Modify: `agentdeck-relay-client/src/ws.rs`（`WsError` 加 `Rejected` 变体 + `dial()` 解析 4xx）
- Modify: `agentdeck-relay/tests/r1a_ws_e2e.rs`（`rejects_bad_secret_expired_nonce_revoked_and_unknown_cred` 断言从 `.is_err()` 升级为具体 `status`/`code`）
- Update: `protocol/agentdeck/agentdeck-protocol.schema.json`

**Interfaces:**
- Produces：`failure::PAIR_MISSING_OWNER_PUBKEY: &str = "relay.pair.missing_owner_pubkey"`；`SubTarget::Events { conversation_id: String, #[serde(default)] since_seq: Option<u64> }`（`#[serde(default)]` 保证旧客户端不传字段时向后兼容）；`WsError::Rejected { status: u16, code: Option<String> }`。
- Consumes：无新依赖。

- [ ] **Step 1: 写失败测试**

`failure.rs` 顶部加常量后，`agentdeck-relay/src/server/pair.rs` 底部 `#[cfg(test)]` 加：
```rust
#[test]
fn missing_owner_pubkey_uses_registered_failure_code() {
    assert_eq!(
        map_enroll_error(EnrollError::MissingOwnerPubkey).1.0.code,
        agentdeck_protocol::remote::failure::PAIR_MISSING_OWNER_PUBKEY
    );
}
```
`agentdeck-protocol/src/remote/control.rs` 加：
```rust
#[test]
fn subtarget_events_since_seq_defaults_to_none_for_old_wire() {
    let v = serde_json::json!({"kind": "events", "conversationId": "C1"});
    let t: SubTarget = serde_json::from_value(v).unwrap();
    assert_eq!(t, SubTarget::Events { conversation_id: "C1".into(), since_seq: None });
}
```
`agentdeck-relay-client/src/ws.rs` 加（构造 mock `tungstenite::Error::Http` 或直接在 e2e 里用真实 401 响应体断言——本单测先断言类型形状可构造）：
```rust
#[test]
fn ws_error_rejected_carries_status_and_code() {
    let e = WsError::Rejected { status: 401, code: Some("relay.pair.bad_secret".into()) };
    assert!(e.to_string().contains("401"));
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay missing_owner_pubkey_uses_registered_failure_code`
Run: `cargo test -p agentdeck-protocol subtarget_events_since_seq_defaults_to_none_for_old_wire`
Run: `cargo test -p agentdeck-relay-client ws_error_rejected_carries_status_and_code`
Expected: 三个全 FAIL（常量/字段/变体均不存在，编译错误或断言不匹配）。

- [ ] **Step 3: 实现**

`failure.rs` 加 `pub const PAIR_MISSING_OWNER_PUBKEY: &str = "relay.pair.missing_owner_pubkey";` + `pub const REPLAY_GAP: &str = "relay.replay.gap";`（后者供 Task 6 用，此处一并注册避免二次改动 failure.rs）。
`server/pair.rs`：`map_enroll_error` 里 `EnrollError::MissingOwnerPubkey` 分支换用 `failure::PAIR_MISSING_OWNER_PUBKEY` 替代内联字符串。
`control.rs`：`SubTarget::Events` 加 `#[serde(default)] since_seq: Option<u64>` 字段。
`ws.rs`：`WsError` 加 `Rejected { status: u16, code: Option<String> }` 变体；`dial()` 里 `connect_async` 失败分支，若 `err` 可 downcast/match 为 `tungstenite::Error::Http(response)`，取 `response.status().as_u16()` 与（若有）body JSON 里的 `code` 字段构造 `Rejected`，否则回落 `Connect(e.to_string())`。
更新 `tests/r1a_ws_e2e.rs` 里 `rejects_bad_secret_expired_nonce_revoked_and_unknown_cred`：把 `.is_err()` 断言换成匹配 `WsError::Rejected { status, .. }` 并断言 `status` 落在预期 4xx（`401`/`400`）。

- [ ] **Step 4: 跑测试确认通过 + 回写 schema**

Run: `cargo test -p agentdeck-relay -p agentdeck-protocol -p agentdeck-relay-client`
Expected: 新增三测 PASS。
Run: `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`（回写 `SubTarget.Events.sinceSeq` 为可选字段）。
Run: `cargo test -p agentdeck-relay --features server --test r1a_ws_e2e`
Expected: 全绿，含升级后的 4xx 断言。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-protocol/src/remote/failure.rs agentdeck-protocol/src/remote/control.rs \
  agentdeck-relay/src/server/pair.rs agentdeck-relay-client/src/ws.rs \
  agentdeck-relay/tests/r1a_ws_e2e.rs protocol/agentdeck/agentdeck-protocol.schema.json
git commit -m "feat(relay): 注册 PAIR_MISSING_OWNER_PUBKEY/REPLAY_GAP 失败码 + Subscribe.since_seq 字段 + WsError::Rejected 4xx 精细化"
```

---

### Task 2: relay-client `Subscribe` replay 去重（R1a 遗留 #2）

**Files:**
- Modify: `agentdeck-protocol/src/remote/control.rs`（`SubTarget` 补 `Hash` derive）
- Modify: `agentdeck-relay-client/src/ws.rs`（`WsRelayClient.subscriptions` 从 `Mutex<Vec<RemoteFrame>>` 换成按 `SubTarget` 去重的映射）

**Interfaces:**
- Produces：`SubTarget: Hash`（新增 derive，不改字段/序列化）；`WsRelayClient::subscriptions: Mutex<HashMap<SubTarget, RemoteFrame>>`（内部实现细节，公开 API `send`/`recv`/`reconnect` 签名不变）。

- [ ] **Step 1: 写失败测试（重复 subscribe 同一 target N 次，集合大小恒为 1）**

`agentdeck-relay-client/src/ws.rs` 测试模块加（需要一种方式检查内部去重后的集合大小——加一个 `#[cfg(test)] pub(crate) fn subscription_count(&self) -> usize` 便于断言，或直接测试 `reconnect()` 重放帧数）：
```rust
#[tokio::test]
async fn duplicate_subscribe_same_target_deduped() {
    // 构造一个不真正连接的 WsRelayClient 测试替身，或复用现有 in-proc 测试基础设施
    // （若现有测试基础设施只支持真实 WS，改为在 tests/ 集成测试里对真 relay 连续
    //  Subscribe 同一 target 3 次，reconnect 后只重放 1 条 Subscribe 帧）
}
```
> 实现者按 crate 现有测试基础设施（`agentdeck-relay-client` 目前无 in-proc 测试替身，Task 7/R1a 只有 `agentdeck-relay/src/auth`/`agentdeck-relay-client/src/inproc.rs` 有测试）选择：优先加一个纯内存单测（不建立真实 socket，直接测 `subscriptions` 映射的 push/去重逻辑，可以把去重逻辑拆成一个不依赖 socket 的私有辅助函数 `fn record_subscription(map: &mut HashMap<SubTarget, RemoteFrame>, frame: RemoteFrame)`，对该辅助函数直接单测）。

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay-client duplicate_subscribe_same_target_deduped`
Expected: FAIL（当前 `subscriptions` 是 `Vec`，重复 push 不去重）。

- [ ] **Step 3: 实现**

`control.rs`：`SubTarget` 的 derive 列表加 `Hash`（`SubTarget` 已是 `PartialEq, Eq`，补 `Hash` 后可直接当 `HashMap` key，不需要额外 wrapper 类型）。
`ws.rs`：`subscriptions: Mutex<Vec<RemoteFrame>>` 改 `subscriptions: Mutex<HashMap<SubTarget, RemoteFrame>>`；`send()` 里判断 `RelayControlMsg::Subscribe { target }` 时 `subscriptions.lock().await.insert(target.clone(), frame.clone())`（覆盖旧的同 target 记录，而非追加）；`reconnect()` 遍历 `subscriptions.lock().await.values()` 重放（顺序不再保证与原发送顺序完全一致，若需要保序改用 `IndexMap`——本任务用 `HashMap` 即可，去重是核心诉求，顺序非关键不变量）。

- [ ] **Step 4: 跑测试确认通过 + 回归**

Run: `cargo test -p agentdeck-relay-client duplicate_subscribe_same_target_deduped`
Expected: PASS。
Run: `cargo test -p agentdeck-relay-client && cargo test -p agentdeck-protocol`
Expected: 全绿（`SubTarget` 加 `Hash` 不影响 schema/序列化）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-protocol/src/remote/control.rs agentdeck-relay-client/src/ws.rs
git commit -m "fix(relay-client): Subscribe replay 按 SubTarget 去重（R1a 遗留#2，无界 Vec 换 HashMap）"
```

---

### Task 3: `rusqlite` dep + schema/migration 框架 + `SqliteRelayStore`（`RelayStore` trait 实现）

**Files:**
- Modify: `agentdeck-relay/Cargo.toml`（加 `rusqlite = { version = "0.32", features = ["bundled"] }`；`[dev-dependencies]` 加 `tempfile = "3"`）
- Create: `agentdeck-relay/src/store.rs`
- Modify: `agentdeck-relay/src/lib.rs`（`mod store; pub use store::SqliteRelayStore;`，`pub` 因 Task 9 main.rs 需要跨模块构造）
- Modify: `agentdeck-relay/src/auth/store.rs`（把 `RelayStore` trait 可见性从 `pub(crate)` 视需要调整——若 `SqliteRelayStore` 定义在新 `store.rs` 模块里实现该 trait，`pub(crate)` 足够，同 crate 内可见，不需要放宽）

**Interfaces:**
- Produces：
  - `SqliteRelayStore`（`Clone`，内部 `Arc<Mutex<rusqlite::Connection>>`）：`open(path: &Path) -> rusqlite::Result<Self>`（建库/跑 migration/`PRAGMA journal_mode=WAL; synchronous=NORMAL`）、`open_in_memory() -> rusqlite::Result<Self>`（测试用，同 schema，不落盘）。
  - `impl RelayStore for SqliteRelayStore`：把 §2.2 schema 的 `accounts`/`devices`/`challenges` 三表接上 `put_challenge`/`take_challenge`/`singleton_account`/`create_account`/`put_device`/`device`/`device_by_credential_hash`（走 `idx_devices_credential_hash` 索引）/`account_count`/`mark_revoked`，语义与 `InMemoryRelayStore` 对齐（`take_challenge` 命中未过期即 `DELETE`，不设 `used` 列）。
  - 迁移框架：`const MIGRATIONS: &[&str]`（v1 = 建 5 张表：accounts/devices/challenges/seq_high_water_marks/conv_events，DDL 抄 §2.2）；`fn run_migrations(conn: &Connection) -> rusqlite::Result<()>`（读 `PRAGMA user_version`，循环 apply 未跑过的迁移，`user_version` 递增，幂等）。
- Consumes：`auth::store::{RelayStore, Account, Device, DeviceRole, Challenge}`。

- [ ] **Step 1: 写失败测试（schema 幂等 + CRUD 覆盖 + 重启恢复）**

`store.rs` 底部：
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::store::{Account, Device, DeviceRole, Challenge, RelayStore};

    #[test]
    fn migration_is_idempotent() {
        let store = SqliteRelayStore::open_in_memory().unwrap();
        // 重复跑 migration 不报错（open 内部已跑一次；这里直接调 run_migrations 复跑）
        store.with_conn(|conn| run_migrations(conn)).unwrap();
    }

    #[test]
    fn device_crud_and_credential_hash_lookup() {
        let mut store = SqliteRelayStore::open_in_memory().unwrap();
        store.create_account(Account { account_id: "acc1".into(), owner_sign_pubkey: "opk".into() });
        store.put_device(Device {
            device_id: "d1".into(), account_id: "acc1".into(), role: DeviceRole::Device,
            credential_hash: "hash1".into(), sign_pubkey: "spk".into(), box_pubkey: "bpk".into(), revoked: false,
        });
        assert_eq!(store.device("d1").unwrap().credential_hash, "hash1");
        assert_eq!(store.device_by_credential_hash("hash1").unwrap().device_id, "d1");
        assert_eq!(store.account_count(), 1);
        store.mark_revoked("d1");
        assert!(store.device("d1").unwrap().revoked);
    }

    #[test]
    fn challenge_take_is_single_use_and_respects_ttl() {
        let mut store = SqliteRelayStore::open_in_memory().unwrap();
        store.put_challenge(Challenge { device_sign_pubkey: "pk1".into(), nonce: "n1".into(), expires_at_ms: 10_000, used: false });
        assert!(store.take_challenge("pk1", 5_000).is_some());
        // 已消费：第二次 take 必须 None（即便时间仍在 TTL 内）
        store.put_challenge(Challenge { device_sign_pubkey: "pk1".into(), nonce: "n1".into(), expires_at_ms: 10_000, used: false });
        assert!(store.take_challenge("pk1", 20_000).is_none(), "过期后不应命中");
    }

    #[test]
    fn survives_restart_reopening_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        {
            let mut store = SqliteRelayStore::open(&path).unwrap();
            store.create_account(Account { account_id: "acc1".into(), owner_sign_pubkey: "opk".into() });
            store.put_device(Device {
                device_id: "d1".into(), account_id: "acc1".into(), role: DeviceRole::Machine,
                credential_hash: "hash1".into(), sign_pubkey: "spk".into(), box_pubkey: "bpk".into(), revoked: true,
            });
        }
        // 重新打开同一文件（模拟 relay 进程重启）
        let store2 = SqliteRelayStore::open(&path).unwrap();
        assert_eq!(store2.account_count(), 1);
        assert!(store2.device("d1").unwrap().revoked, "撤销状态必须跨重启保留");
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay store::`
Expected: FAIL（`agentdeck-relay/src/store.rs` 不存在，`rusqlite` 未加依赖）。

- [ ] **Step 3: 实现**

`Cargo.toml` 加 `rusqlite = { version = "0.32", features = ["bundled"] }`（`[dependencies]`，非 optional——Core/`router.rs` 无 `server` feature 门也要用它，见 Task 4）；`[dev-dependencies]` 加 `tempfile = "3"`。
`store.rs`：定义 schema DDL 常量（抄设计 §2.2 五张表）、`run_migrations`、`SqliteRelayStore::open`/`open_in_memory`（`open_in_memory` 用 `Connection::open_in_memory()`）、`impl RelayStore for SqliteRelayStore` 逐方法用参数化 SQL 实现（`take_challenge` 用一个事务内 `SELECT` + 条件 `DELETE` 保证原子单次消费）。`lib.rs` 加 `mod store; pub use store::SqliteRelayStore;`。

- [ ] **Step 4: 跑测试确认通过**

Run: `cargo test -p agentdeck-relay store::`
Expected: PASS（4 测试）。
Run: `cargo build -p agentdeck-relay && cargo tree -p agentdeck-relay | grep -c rusqlite`
Expected: 编译通过，`rusqlite` 依赖存在且非重复版本。
Run: `bash scripts/check-daemon-no-net.sh`（确认 `agentdeckd` 不因 relay 加依赖被拉进 rusqlite——`agentdeckd` 本就不依赖 relay 任何 crate，预期无影响，仅作双重确认）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/Cargo.toml agentdeck-relay/src/store.rs agentdeck-relay/src/lib.rs Cargo.lock
git commit -m "feat(relay): SqliteRelayStore——rusqlite+bundled，schema/migration 框架 + RelayStore trait 实现（accounts/devices/challenges）"
```

---

### Task 4: Core 持久化接入——seq 高水位管理 + `PublishEvent` persist-before-deliver（payload 恒 NULL）

**Files:**
- Modify: `agentdeck-relay/src/store.rs`（加 `reserve_and_persist_event`/`load_next_seq` 等 inherent 方法，供 Core 用，不属于 `RelayStore` trait）
- Modify: `agentdeck-relay/src/router.rs`（`Core` 加 `store: SqliteRelayStore` 字段；`FakeRelay::start_with_store`；`PublishEvent` 分支改为先持久化再广播）

**Interfaces:**
- Produces：
  - `SqliteRelayStore::reserve_and_persist_event(&self, conversation_id: &str, turn_session_id: &str, now_ms: i64) -> rusqlite::Result<u64>`（同事务内 `UPSERT seq_high_water_marks` 取号 + `INSERT conv_events(payload=NULL)`，返回新分配的 `seq`）。
  - `SqliteRelayStore::load_next_seq(&self, conversation_id: &str) -> rusqlite::Result<u64>`（重启恢复用，供测试断言）。
  - `FakeRelay::start_with_store(store: SqliteRelayStore) -> Self`；`FakeRelay::start()` 保持签名不变，内部委托 `start_with_store(SqliteRelayStore::open_in_memory().expect(...))`。
  - Core 里 `conv_seq: HashMap<String, u64>` 内存字段**移除**（改为每次持久化调用返回的 `seq` 就是权威值，内存不再自行 `+=1`）——`self.conv_seq` 及其所有读写点删除。
- Consumes：Task 3 的 `SqliteRelayStore`。

- [ ] **Step 1: 写失败测试（relay 重启后 seq 不回退不重复）**

`router.rs` 测试模块加：
```rust
#[tokio::test]
async fn seq_survives_relay_restart_via_same_sqlite_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");

    // 第一次"启动"：发布两条事件，seq 应为 0, 1
    {
        let store = crate::SqliteRelayStore::open(&path).unwrap();
        let relay = FakeRelay::start_with_store(store);
        let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") })).await;
        m.send(frame(ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::AnnounceSession { session: session("C1", "M1") })).await;
        publish(&m, "C1", "S1").await;
        publish(&m, "C1", "S2").await;
        // 给持久化 spawn_blocking 一点时间落盘（无直接回执可等时用短 sleep 或后续引入的确认信号）
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // 模拟进程重启：重开同一文件的新 FakeRelay，第三条事件的 seq 必须是 2（不回退到 0）
    {
        let store = crate::SqliteRelayStore::open(&path).unwrap();
        let relay = FakeRelay::start_with_store(store);
        let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
        m.send(frame(ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::RegisterMachine { machine: machine("M1") })).await;
        m.send(frame(ClientRole::Machine { machine_id: "M1".into() },
            RelayControlMsg::AnnounceSession { session: session("C1", "M1") })).await;
        let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
        d.send(frame(ClientRole::Device { device_id: "D1".into() },
            RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into(), since_seq: None } })).await;
        publish(&m, "C1", "S3").await;
        let (_, _, seq) = recv_event(&mut d).await;
        assert_eq!(seq, 2, "重启后 seq 必须从持久化高水位延续，不回退");
    }
}
```
（需要给 `session`/`publish`/`recv_event`/`frame`/`machine` 等既有测试辅助函数加 `pub(crate)` 或保持同 mod 可见；`publish` 辅助里的 `RelayControlMsg::PublishEvent { seq: 0, .. }` 不变——`seq` 字段本就是"relay 自行 re-stamp"的占位值。）

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay seq_survives_relay_restart_via_same_sqlite_file`
Expected: FAIL（`FakeRelay::start_with_store` 不存在；即便临时改造，当前 `conv_seq` 是纯内存 `HashMap`，重启后清零，第三条事件 seq 会是 0 而非 2）。

- [ ] **Step 3: 实现**

`store.rs` 加：
```rust
impl SqliteRelayStore {
    pub(crate) fn reserve_and_persist_event(&self, conversation_id: &str, turn_session_id: &str, now_ms: i64) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO seq_high_water_marks(conversation_id, next_seq) VALUES (?1, 1)
             ON CONFLICT(conversation_id) DO UPDATE SET next_seq = next_seq + 1",
            rusqlite::params![conversation_id],
        )?;
        let next_seq: u64 = tx.query_row(
            "SELECT next_seq FROM seq_high_water_marks WHERE conversation_id = ?1",
            rusqlite::params![conversation_id], |r| r.get(0),
        )?;
        let seq = next_seq - 1;
        tx.execute(
            "INSERT INTO conv_events(conversation_id, seq, turn_session_id, encryption_version, payload, created_at_ms)
             VALUES (?1, ?2, ?3, 0, NULL, ?4)",
            rusqlite::params![conversation_id, seq, turn_session_id, now_ms],
        )?;
        tx.commit()?;
        Ok(seq)
    }
    pub(crate) fn load_next_seq(&self, conversation_id: &str) -> rusqlite::Result<u64> { /* SELECT，无行返回 0 */ }
}
```
`router.rs`：`Core` 加 `store: SqliteRelayStore` 字段（移除 `#[derive(Default)]`，改手写 `Core::new(store: SqliteRelayStore) -> Self`）；`FakeRelay::start()` → 内部 `Self::start_with_store(SqliteRelayStore::open_in_memory().expect("in-memory sqlite open"))`；`start_with_store(store)` 把 `store` 传进 `Core::new(store)` 再 `tokio::spawn(core.run(core_rx))`。`PublishEvent` 分支：删除 `conv_seq` 相关两行，替换为：
```rust
let store = self.store.clone();
let conv = conversation_id.clone();
let turn = turn_session_id.clone();
let now_ms = now_ms(); // 复用 crate 内既有的边缘时间戳获取方式，或 std::time
let seq = match tokio::task::spawn_blocking(move || store.reserve_and_persist_event(&conv, &turn, now_ms)).await {
    Ok(Ok(seq)) => seq,
    _ => { /* 持久化失败：拒绝该事件，回 Error 给发起 machine，不广播（正确性优先于可用性） */ ... return; }
};
```
（persist-before-deliver：只有 `reserve_and_persist_event` 成功返回 `seq` 后才构造 `Event` 并 `push` 进 `conv_buffer`/广播，失败时不 push、不广播、给发起方回错误。）

- [ ] **Step 4: 跑测试确认通过 + 回归**

Run: `cargo test -p agentdeck-relay seq_survives_relay_restart_via_same_sqlite_file`
Expected: PASS。
Run: `cargo test -p agentdeck-relay`
Expected: 全绿（既有 `events_keyed_on_conversation_survive_new_turn_and_replay_for_late_subscriber` 等测试因 `FakeRelay::start()` 签名不变而不回归；确认无测试因新增的 `spawn_blocking` 延迟而变得 flaky——若有，加合理 timeout 而非 sleep 轮询）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/src/store.rs agentdeck-relay/src/router.rs
git commit -m "feat(relay): Core 接入 SqliteRelayStore——persist-before-deliver，seq 高水位跨重启单调（payload 恒 NULL）"
```

---

### Task 5: Ack 语义接通 + `conv_buffer` 硬上界 + Ack-trim（本任务不改 CLI）

**Files:**
- Modify: `agentdeck-protocol/src/remote/control.rs`（`Ack.conversation_id` 从 `Option<String>` 收紧为 `String`）
- Modify: `protocol/agentdeck/agentdeck-protocol.schema.json`
- Modify: `agentdeck-relay/src/store.rs`（加 `record_ack` 方法，更新 `seq_high_water_marks.acked_seq`）
- Modify: `agentdeck-relay/src/router.rs`（`conv_buffer` 硬上界 FIFO + `Ack` 分支实现 + `RelayConfig` 之外先用 Core 内常量占位，Task 9 再接可配置项）

**Interfaces:**
- Produces：`RelayControlMsg::Ack { up_to_seq: u64, conversation_id: String }`（breaking wire tweak，已确认零真实调用方，见设计 §8）；`SqliteRelayStore::record_ack(&self, conversation_id: &str, up_to_seq: u64) -> rusqlite::Result<()>`；Core 里 `conv_buffer` 每 conversation 保留最近 `N` 条（本任务先用 `const DEFAULT_CONV_BUFFER_CAP: usize = 1000` 占位，Task 9 换成 `RelayConfig` 传入值）。
- **本任务不改 `agentdeck-cli`**：CLI 事件消费循环不补发 Ack（设计 §9-5 建议：CLI 是"用户交互驱动、短命连接"场景，Ack 语义留给未来 programmatic client——iOS companion/daemon remote-mode；见本计划文末"关键实施决策"）。硬上界 FIFO 独立于 Ack 生效，即使暂无客户端发 Ack，OOM 防线仍然成立。
- Consumes：Task 4 的持久化管线。

- [ ] **Step 1: 写失败测试（硬上界 FIFO + Ack-trim min-acked）**

`router.rs` 测试模块加：
```rust
#[tokio::test]
async fn conv_buffer_hard_cap_drops_oldest_regardless_of_ack() {
    let relay = FakeRelay::start();
    let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
    m.send(frame(ClientRole::Machine { machine_id: "M1".into() }, RelayControlMsg::RegisterMachine { machine: machine("M1") })).await;
    m.send(frame(ClientRole::Machine { machine_id: "M1".into() }, RelayControlMsg::AnnounceSession { session: session("C1", "M1") })).await;
    // 发布超过硬上界（DEFAULT_CONV_BUFFER_CAP=1000）的事件数——用较小可配置值测试更快；
    // 若本任务尚未接 RelayConfig，先用一个测试专用的小上界常量（Task 9 再切换为可配置）。
    for i in 0..(DEFAULT_CONV_BUFFER_CAP + 10) {
        publish(&m, "C1", &format!("S{i}")).await;
    }
    let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
    d.send(frame(ClientRole::Device { device_id: "D1".into() },
        RelayControlMsg::Subscribe { target: SubTarget::Events { conversation_id: "C1".into(), since_seq: Some(0) } })).await;
    let (_, _, first_seq) = recv_event(&mut d).await;
    assert!(first_seq >= 10, "硬上界应已丢弃最旧的至少 10 条（不管有没有 ack）");
}

#[tokio::test]
async fn ack_trims_buffer_up_to_min_acked_seq() {
    // 两个订阅方 d1/d2 都订阅 C1；d1 发 Ack{up_to_seq: 1}，d2 未 ack；
    // 断言 conv_buffer 仍保留 seq>=?（下一订阅方按 since_seq=0 补拉时，
    // 至少能拿到 d2 尚未确认的部分——本测试聚焦"trim 不早于 min-acked"这一正确性边界，
    // 而非具体丢弃时机的强断言，避免测试和实现细节过度耦合）。
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay conv_buffer_hard_cap_drops_oldest_regardless_of_ack ack_trims_buffer_up_to_min_acked_seq`
Expected: FAIL（当前 `conv_buffer` 无界，`Ack` 分支是 no-op）。

- [ ] **Step 3: 实现**

`control.rs`：`Ack.conversation_id` 字段类型 `Option<String>` → `String`（去掉 `Option` 包裹）。
`store.rs`：加 `record_ack`（`UPDATE seq_high_water_marks SET acked_seq = MAX(acked_seq, ?) WHERE conversation_id = ?`，`MAX` 防止乱序/重复 Ack 回退游标）。
`router.rs`：
- `conv_buffer` push 后立即检查长度，超过 `cap` 时 `drain(..len-cap)` 丢最旧（不管 ack 状态）——独立于 Ack 生效的正确性防线。
- `RelayControlMsg::Ack { up_to_seq, conversation_id }` 分支：`self.owns_conversation` 之外还需允许 Device 侧 Ack（Ack 发起方是订阅方 Device，不是 machine，鉴权检查改为"该连接确实订阅了该 conversation"而非"拥有"）；调 `spawn_blocking` 落 `record_ack`（放宽持久化时序，允许 fire-and-forget，不 `.await` 阻塞后续处理——用 `tokio::spawn` 而非 inline `await`）；内存侧更新"该 conversation 当前活跃订阅连接里最小 acked_seq"，据此 trim `conv_buffer`（只裁到 min-acked，不裁到 `up_to_seq` 本身——防止某个连接尚未来得及看到更新前的 min-acked 计算就被裁没）。

- [ ] **Step 4: 跑测试确认通过 + 回归**

Run: `cargo test -p agentdeck-relay conv_buffer_hard_cap_drops_oldest_regardless_of_ack ack_trims_buffer_up_to_min_acked_seq`
Expected: PASS。
Run: `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`
Run: `cargo test -p agentdeck-relay -p agentdeck-protocol`
Expected: 全绿（`Ack.conversation_id` 收紧不影响任何现存调用方——已在设计 §8 核实零真实发送方）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-protocol/src/remote/control.rs protocol/agentdeck/agentdeck-protocol.schema.json \
  agentdeck-relay/src/store.rs agentdeck-relay/src/router.rs
git commit -m "feat(relay): Ack 语义接通（conversation_id 收紧必填）+ conv_buffer 硬上界 FIFO + Ack-trim（min-acked）"
```

---

### Task 6: 重放补拉——`Subscribe{Events, since_seq}` 语义

**Files:**
- Modify: `agentdeck-relay/src/router.rs`（`Subscribe{Events}` 分支消费 `since_seq`）

**Interfaces:**
- Produces：`Subscribe{Events{conversation_id, since_seq: Some(n)}}` 时：若 `n` 仍在当前内存 `conv_buffer` 覆盖范围内（`conv_buffer` 最旧一条的 `seq <= n`），从内存回放 `seq > n` 的部分（或 `since_seq` 语义定为"从 n（含）之后"——本任务钉死为**不含** n 本身，即回放 `seq > since_seq`，与 Ack 的 `up_to_seq` 含义对称：Ack 意为"n 及之前都确认"，Subscribe 的 `since_seq` 意为"我已有 n 及之前，请给我之后的"）；若 `n` 早于内存最旧条目（已被硬上界丢弃）但 `<= seq_high_water_marks.next_seq`（即"存在但不可重放"的 gap），relay 回 `Error { code: failure::REPLAY_GAP, .. }`（Task 1 已注册该常量）。`since_seq: None` 保持 R1a 现状行为（从当前订阅时刻起收，不补拉历史）。
- Consumes：Task 1 `failure::REPLAY_GAP`、Task 4/5 的 `conv_buffer`/持久化状态。

- [ ] **Step 1: 写失败测试（内存命中补拉 + gap 报错两分支）**

```rust
#[tokio::test]
async fn since_seq_within_buffer_replays_missed_events() {
    // 发布 3 条事件（seq 0,1,2），新订阅带 since_seq=0 只应收到 seq=1,2（不重复 seq=0）
}

#[tokio::test]
async fn since_seq_beyond_buffer_window_returns_replay_gap_error() {
    // 触发硬上界丢弃后，订阅方请求一个早已被丢弃的 since_seq，应收到 Error{code: REPLAY_GAP}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay since_seq_within_buffer_replays_missed_events since_seq_beyond_buffer_window_returns_replay_gap_error`
Expected: FAIL（当前 `Subscribe{Events}` 忽略 `since_seq`，总是回放整个 `conv_buffer`）。

- [ ] **Step 3: 实现**

`router.rs` 的 `Subscribe{Events{conversation_id, since_seq}}` 分支：先做既有 account scope 检查（不变），再分支：
```rust
match since_seq {
    None => { /* 现状：回放整个 conv_buffer（等价于"从当前起订阅"，因为 buffer 本就只装未裁剪部分）*/ }
    Some(n) => {
        let buf = self.conv_buffer.get(&conversation_id);
        let oldest_seq_in_buffer = buf.and_then(|b| b.first()).map(|ev| event_seq(ev));
        match oldest_seq_in_buffer {
            Some(oldest) if oldest <= n + 1 => {
                // 命中：回放 buffer 中 seq > n 的部分
                for ev in buf.unwrap().iter().filter(|ev| event_seq(ev) > n) { self.send_to(id, &trace, ev.clone()).await; }
            }
            _ => {
                self.deny(id, &trace, failure::REPLAY_GAP,
                    format!("since_seq {n} is outside the retained replay window for {conversation_id}"), None).await;
                return;
            }
        }
    }
}
self.subs_events.entry(conversation_id.clone()).or_default().insert(id);
```
（`event_seq` 是从 `RelayControlMsg::Event { seq, .. }` 取值的小辅助函数。）

- [ ] **Step 4: 跑测试确认通过 + 回归**

Run: `cargo test -p agentdeck-relay since_seq_within_buffer_replays_missed_events since_seq_beyond_buffer_window_returns_replay_gap_error`
Expected: PASS。
Run: `cargo test -p agentdeck-relay`
Expected: 全绿（既有 `events_keyed_on_conversation_survive_new_turn_and_replay_for_late_subscriber` 用 `since_seq: None`，行为不变）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/src/router.rs
git commit -m "feat(relay): Subscribe{Events}.since_seq 重放补拉——内存命中回放 / 窗口外返回 relay.replay.gap"
```

---

### Task 7: AnnounceSession 去重（sessions upsert by conversation_id）

**Files:**
- Modify: `agentdeck-relay/src/router.rs`

**Interfaces:**
- Produces：`Core::sessions: HashMap<String /* machine_id */, IndexMap<String /* conversation_id */, SessionDescriptor>>`（或等价"按 conversation_id upsert 保留插入顺序"的结构）；`AnnounceSession` 处理逻辑改为存在同 `conversation_id` 则覆盖，否则插入。`agentdeck-relay/Cargo.toml` 若选 `IndexMap` 需加 `indexmap = "2"` 依赖（也可用 `Vec` + 手写"先找位置再覆盖/插入"避免新依赖——本任务优先不加新依赖，用 `Vec<SessionDescriptor>` + 线性查找覆盖，因单 machine 的会话数通常是几十量级，线性扫描可接受，避免为一个小改动新增 crate）。

- [ ] **Step 1: 写失败测试（重复 AnnounceSession 同一 conversation_id 后 SessionList 不重复）**

```rust
#[tokio::test]
async fn announce_session_same_conversation_twice_does_not_duplicate_in_session_list() {
    let relay = FakeRelay::start();
    let m = relay.connect(ClientRole::Machine { machine_id: "M1".into() }).await;
    m.send(frame(ClientRole::Machine { machine_id: "M1".into() }, RelayControlMsg::RegisterMachine { machine: machine("M1") })).await;
    m.send(frame(ClientRole::Machine { machine_id: "M1".into() }, RelayControlMsg::AnnounceSession { session: session("C1", "M1") })).await;
    // 同一 machine 重启后重新 announce 同一 conversation_id（模拟 machine 侧重连场景）
    m.send(frame(ClientRole::Machine { machine_id: "M1".into() }, RelayControlMsg::AnnounceSession { session: session("C1", "M1") })).await;

    let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
    d.send(frame(ClientRole::Device { device_id: "D1".into() },
        RelayControlMsg::Subscribe { target: SubTarget::Sessions { machine_id: "M1".into() } })).await;
    let got = d.recv().await.expect("frame");
    match got.msg {
        RelayControlMsg::SessionList { sessions, .. } => assert_eq!(sessions.len(), 1, "重复 announce 同一 conversation 不应产生重复条目"),
        other => panic!("expected SessionList, got {other:?}"),
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay announce_session_same_conversation_twice_does_not_duplicate_in_session_list`
Expected: FAIL（当前无条件 `push`，`sessions.len() == 2`）。

- [ ] **Step 3: 实现**

`router.rs` 的 `AnnounceSession` 分支：把 `self.sessions.entry(mid.clone()).or_default().push(session);` 换成：
```rust
let list = self.sessions.entry(mid.clone()).or_default();
if let Some(existing) = list.iter_mut().find(|s| s.conversation_id == session.conversation_id) {
    *existing = session;
} else {
    list.push(session);
}
```

- [ ] **Step 4: 跑测试确认通过 + 回归**

Run: `cargo test -p agentdeck-relay announce_session_same_conversation_twice_does_not_duplicate_in_session_list`
Expected: PASS。
Run: `cargo test -p agentdeck-relay`
Expected: 全绿。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/src/router.rs
git commit -m "fix(relay): AnnounceSession 按 conversation_id upsert 去重（R1a 遗留：重复展示 bug）"
```

---

### Task 8: req_origin TTL 清理

**Files:**
- Modify: `agentdeck-relay/src/router.rs`

**Interfaces:**
- Produces：`ReqOrigin` 加 `created_at_ms: i64`；`CoreMsg::SweepReqOrigin { now_ms: i64 }`（由一个独立 `tokio::spawn` 心跳任务周期性发送，不给 Core 主循环加计时器）；`Core::handle_sweep_req_origin(now_ms, ttl_ms)` 清扫超 TTL 条目。`FakeRelay::start_with_store` 内附带起该心跳任务（周期取 TTL 的一个分数，如 `ttl_ms / 2`，本任务先用测试可控的短 TTL 验证，Task 9 再接 `RelayConfig::req_origin_ttl_ms`）。

- [ ] **Step 1: 写失败测试（超 TTL 的 req_origin 被清扫，用 `tokio::time::pause` 避免真实 sleep）**

```rust
#[tokio::test(start_paused = true)]
async fn stale_req_origin_is_swept_after_ttl() {
    let relay = FakeRelay::start();
    let mut d = relay.connect(ClientRole::Device { device_id: "D1".into() }).await;
    d.send(RemoteFrame::control(ClientRole::Device { device_id: "D1".into() }, "t".into(), 0,
        RelayControlMsg::SendCommand { request_id: "r1".into(), target: CommandTarget::Machine { machine_id: "NOPE".into() },
            data: DataEnvelope::plaintext(&"x").unwrap() })).await;
    // 目标 machine 从不回复；推进虚拟时间超过 TTL
    tokio::time::advance(std::time::Duration::from_secs(400)).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await; // 让 sweep 心跳任务有机会跑一轮
    // 之后即便"NOPE"注册上线，早已过期的 req_origin 也不应再被匹配到（用一个白盒探测或
    // 行为断言：此时若 NOPE 伪造回复 r1，device 不应再收到——间接验证条目已被清扫）
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay stale_req_origin_is_swept_after_ttl`
Expected: FAIL（当前 `req_origin` 只在 `AdminReply` 命中时移除，从不超时清扫）。

- [ ] **Step 3: 实现**

`router.rs`：`ReqOrigin` 加 `created_at_ms: i64`（`SendCommand` 分支写入时用边缘时间戳）。`CoreMsg` 加 `SweepReqOrigin { now_ms: i64 }`。`Core::run` 的 `match msg` 加分支调用清扫逻辑：
```rust
CoreMsg::SweepReqOrigin { now_ms } => {
    self.req_origin.retain(|_, origin| now_ms - origin.created_at_ms < self.req_origin_ttl_ms);
}
```
`FakeRelay::start_with_store` 里，除已有的 Core actor `tokio::spawn` 外，再起一个心跳任务：
```rust
let sweep_tx = core_tx.clone();
let ttl_ms = req_origin_ttl_ms; // 本任务先用一个 Core 内常量/构造参数占位
tokio::spawn(async move {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis((ttl_ms / 2).max(1000) as u64));
    loop {
        ticker.tick().await;
        let now_ms = /* 复用既有边缘时间戳获取方式 */;
        if sweep_tx.send(CoreMsg::SweepReqOrigin { now_ms }).await.is_err() { break; }
    }
});
```

- [ ] **Step 4: 跑测试确认通过 + 回归**

Run: `cargo test -p agentdeck-relay stale_req_origin_is_swept_after_ttl`
Expected: PASS。
Run: `cargo test -p agentdeck-relay`
Expected: 全绿（`tokio::test(start_paused = true)` 不影响其它未用虚拟时间的测试）。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/src/router.rs
git commit -m "feat(relay): req_origin TTL 清理——独立心跳任务驱动 CoreMsg::SweepReqOrigin，防长驻内存泄漏"
```

---

### Task 9: `RelayConfig` 新增可配置项 + relay binary/server 接入 `SqliteRelayStore`

**Files:**
- Modify: `agentdeck-relay/src/config.rs`（加 `storage_path: PathBuf`、`conv_buffer_cap: usize`、`req_origin_ttl_ms: u64` 字段 + `AGENTDECK_RELAY_STORAGE`/`AGENTDECK_RELAY_CONV_BUFFER_CAP`/`AGENTDECK_RELAY_REQ_ORIGIN_TTL_MS` env）
- Modify: `agentdeck-relay/src/router.rs`（`Core::new`/`FakeRelay::start_with_store` 接收 `conv_buffer_cap`/`req_origin_ttl_ms` 参数，替换 Task 5/8 的占位常量）
- Modify: `agentdeck-relay/src/server/mod.rs`（`AppState.store` 类型 `Arc<Mutex<InMemoryRelayStore>>` → `SqliteRelayStore`；`serve`/`serve_with_listener` 签名参数类型同步换）
- Modify: `agentdeck-relay/src/main.rs`（构造 `SqliteRelayStore::open(&config.storage_path)`，`--selfcheck` 走 `SqliteRelayStore::open_in_memory()` 或 tempdir，避免污染真实数据文件）
- Modify: `agentdeck-relay/tests/r1a_ws_e2e.rs`（`InMemoryRelayStore::default()` 构造点换 `SqliteRelayStore::open_in_memory()`）

**Interfaces:**
- Produces：`RelayConfig { .., storage_path: PathBuf, conv_buffer_cap: usize, req_origin_ttl_ms: u64 }`；默认值 `storage_path` = `./agentdeck-relay-data/relay.db`（相对 CWD，可被 `--storage`/env 覆盖）、`conv_buffer_cap` = **1000**（每 conversation，假设约 10 events/s、100s 缓冲窗口）、`req_origin_ttl_ms` = **300_000**（5 分钟，对齐典型 RPC timeout）。
- Consumes：Task 3-8 全部产出。

- [ ] **Step 1: 写失败测试（config 默认值 + env 覆盖 + selfcheck 不落盘真实路径）**

`config.rs` 测试模块加：
```rust
#[test]
fn defaults_match_documented_values() {
    // 通过一个不依赖 clap 解析全流程的最小构造路径断言默认值
    // （或直接读 RelayConfig::load 在无 env/无 CLI 参数时的 storage_path/conv_buffer_cap/req_origin_ttl_ms）
    assert_eq!(default_conv_buffer_cap(), 1000);
    assert_eq!(default_req_origin_ttl_ms(), 300_000);
}
```
`main.rs`（或一个新的集成测试）加：`--selfcheck` 场景下不应在 CWD 创建 `agentdeck-relay-data/relay.db` 文件（避免每次 selfcheck 污染工作目录）。

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p agentdeck-relay defaults_match_documented_values`
Expected: FAIL（字段/函数不存在）。

- [ ] **Step 3: 实现**

`config.rs`：`RelayConfig` 加三字段；`RawArgs` 加 `#[arg(long)] storage: Option<String>`、`#[arg(long)] conv_buffer_cap: Option<usize>`、`#[arg(long)] req_origin_ttl_ms: Option<u64>`；`load()` 里补齐 CLI > env(`AGENTDECK_RELAY_STORAGE`/`AGENTDECK_RELAY_CONV_BUFFER_CAP`/`AGENTDECK_RELAY_REQ_ORIGIN_TTL_MS`) > 默认值 三层 fallback（沿用既有 `bind`/`bootstrap_secret` 的模式）。
`router.rs`：`Core::new`/`FakeRelay::start_with_store` 签名加 `conv_buffer_cap: usize, req_origin_ttl_ms: u64` 参数，`FakeRelay::start()` 便捷入口传入文档默认值 1000/300_000。
`server/mod.rs`：`AppState.store` 类型换 `SqliteRelayStore`（`SqliteRelayStore` 自带内部同步，`Arc<Mutex<_>>` 外层包裹可去掉——按 Task 3 的设计，`SqliteRelayStore` 本身 `Clone` 且线程安全）；`serve`/`serve_with_listener` 参数类型同步改。
`main.rs`：正常启动路径 `SqliteRelayStore::open(&config.storage_path)?`（父目录不存在时先 `create_dir_all`）；`--selfcheck` 路径改用 `SqliteRelayStore::open_in_memory()`。

- [ ] **Step 4: 跑测试确认通过 + 全量回归**

Run: `cargo test -p agentdeck-relay defaults_match_documented_values`
Expected: PASS。
Run: `cargo build -p agentdeck-relay --features server`
Run: `cargo run -p agentdeck-relay --features server -- --selfcheck --bootstrap-secret x`
Expected: selfcheck ok、退出 0，且不在 CWD 留下 `agentdeck-relay-data/`。
Run: `cargo test -p agentdeck-relay && cargo test -p agentdeck-relay --features server --test r1a_ws_e2e`
Expected: 全绿。

- [ ] **Step 5: Commit**

```bash
git add agentdeck-relay/src/config.rs agentdeck-relay/src/router.rs agentdeck-relay/src/server/mod.rs \
  agentdeck-relay/src/main.rs agentdeck-relay/tests/r1a_ws_e2e.rs
git commit -m "feat(relay): RelayConfig 加 storage/conv-buffer-cap/req-origin-ttl 可配置项，relay binary 接入 SqliteRelayStore"
```

---

### Task 10: R1b e2e 集成测试（Ack-trim + 重放补拉 gap + AnnounceSession 幂等 + req_origin TTL + SQLite 重启恢复）+ Revoke 独立单测（R1a 遗留 #9）

**Files:**
- Create: `agentdeck-relay/tests/r1b_hardening_e2e.rs`

**Interfaces:** Consumes Task 1-9 全部产出（真 WS + 真 SQLite 文件，非 in-proc 单测）。

- [ ] **Step 1: 写端到端测试**

`tests/r1b_hardening_e2e.rs`（bind `127.0.0.1:0`、tempdir 存 `relay.db`、每步 5s timeout，风格延续 `r1a_ws_e2e.rs`）：
1. `restart_preserves_seq_and_revocation`：起 server（tempdir 路径） → enroll machine+device → 发布若干事件、撤销一个凭据 → 关闭 server → 用同一 tempdir 路径重新起 server → 断言新事件 seq 从持久化高水位延续 + 已撤销凭据仍被拒。
2. `ack_then_lagged_subscriber_gets_gap_not_stale_data`：制造硬上界溢出场景（发布超过 cap 条事件）→ 新订阅带一个已被丢弃的 `since_seq` → 断言收到 `relay.replay.gap` Error，而不是收到错误/过期数据。
3. `announce_session_idempotent_across_reconnect`：machine 断线重连后重新 `AnnounceSession` 同一 `conversation_id` → device 侧 `SessionList` 长度不变（不重复）。
4. `revoke_closes_active_connection_and_blocks_reconnect`（R1a 遗留 #9 补测）：一个已连接的 device/machine 被 `revoke` 后，① 活连接被断开（`recv()` 返回 `None` 或连接层错误）；② 用同一 credential 重新发起 WS 连接被拒（`WsError::Rejected`，`AUTH_REVOKED_DEVICE`）。

- [ ] **Step 2: 跑测试**

Run: `cargo test -p agentdeck-relay --features server --test r1b_hardening_e2e`
Expected: 全 PASS（真 WS loopback + 真 SQLite tempdir 文件）。

- [ ] **Step 3: Commit**

```bash
git add agentdeck-relay/tests/r1b_hardening_e2e.rs
git commit -m "test(relay): R1b e2e——SQLite 重启恢复 + 重放补拉 gap + AnnounceSession 幂等 + Revoke 独立场景"
```

---

### Task 11: 文档收口

**Files:**
- Modify: `AGENTS.md`
- Modify: `ARCHITECTURE.md`
- Modify: `docs/index.md`
- Modify: `docs/plans/2026-07-08-relay-r1-design-review.md`（§6「R1a 落地状态」旁补 R1b 落地状态）

**Interfaces:** 无代码接口。

- [ ] **Step 1: AGENTS.md 补验证入口**

在既有 relay 验证命令块（`cargo test -p agentdeck-relay --features server` 等，约第 92-108 行附近）补：`cargo test -p agentdeck-relay --test r1b_hardening_e2e --features server`、`--storage`/`--conv-buffer-cap`/`--req-origin-ttl-ms` 用法说明、schema 变更后 `UPDATE_SCHEMA=1` 提醒（沿用既有措辞）。

- [ ] **Step 2: ARCHITECTURE.md 补不变量**

在「Relay R1a 不变量」小节后新增「Relay R1b 不变量」小节，补：
- **R1b-1**：relay 持久化状态（accounts/devices/challenges/seq 高水位/事件元数据）全部落 SQLite（`rusqlite` + `bundled`），单一 `--storage` 路径文件；**事件内容（`payload`）本期恒为 NULL，不落盘明文**（R1c 引入加密后翻转）。
- **R1b-2**：`conv_buffer` 每 conversation 有硬上界（默认 1000，可配置），独立于 Ack 生效，防 OOM。
- **R1b-3**：重放补拉（`since_seq`）语义为 **relay 进程存活期内** 的有界补拉，不是跨重启完整历史重放；窗口外返回 `relay.replay.gap`。
- **R1b-4**：`RelayLink::recv` 仍不返回 `Result`（R2 defer，见 R1b 设计 §4.1）。

- [ ] **Step 3: docs/index.md 登记**

「Relay R1a 传输 + 鉴权骨架」小节后加「Relay R1b 存储 + Router 健壮化（2026-07-09）」小节，登记本设计文档 + 本实施计划文档路径。

- [ ] **Step 4: R1 设计评审文档补 R1b 状态**

`docs/plans/2026-07-08-relay-r1-design-review.md` §6「R1a 落地状态（2026-07-09）」旁/后加一句"R1b（SQLite 持久化 + router 健壮化）设计已 lock-in，实施计划见 `2026-07-09-relay-r1b-storage-hardening-implementation.md`"，不改动既有 R1a 状态描述内容本身。

- [ ] **Step 5: 全量验证 + Commit**

Run: `cargo test`（默认 features 全绿）
Run: `cargo test -p agentdeck-relay --features server`（含 r1a/r1b 两个 e2e 全绿）
Run: `cargo build -p agentdeckd && cargo test -p agentdeckd`（无回归）
Run: `bash scripts/check-daemon-no-net.sh` / `bash scripts/verify-agent-docs.sh`
Expected: 全通过。
```bash
git add AGENTS.md ARCHITECTURE.md docs/index.md docs/plans/2026-07-08-relay-r1-design-review.md
git commit -m "docs(relay): R1b 文档收口——AGENTS/ARCHITECTURE 不变量/index 登记/R1 评审状态更新"
```

---

## 完成标准

- `cargo test`（默认）+ `cargo test -p agentdeck-relay --features server` 全绿；schema 无漂移；`verify-agent-docs.sh` + `check-daemon-no-net.sh` 通过。
- relay 重启（同一 `--storage` 路径）后：账户/设备/撤销状态、per-conversation seq 高水位均从 SQLite 正确恢复，不回退不重复。
- `conv_buffer` 硬上界独立于 Ack 生效；Ack 收到后 min-acked 之上内容仍可重放、之下的被裁剪。
- `Subscribe{Events, since_seq}`：窗口内命中直接回放；窗口外（relay 进程存活期内已被硬上界丢弃）返回 `relay.replay.gap`，不返回错误数据或静默丢弃。
- `AnnounceSession` 重复调用同一 `conversation_id` 不再产生重复 `SessionList` 条目。
- `req_origin` 超 TTL 被独立心跳任务清扫，长驻 relay 进程内存不再随未回复的命令无限增长。
- Revoke 独立单测覆盖：活连接被断开 + 同 credential 重连被拒（R1a 遗留 #9 收口）。
- `Subscribe` 重放去重（`WsRelayClient.subscriptions` 从无界 `Vec` 换去重映射，R1a 遗留 #2 收口）；`WsError::Rejected` 精细化 4xx（R1a 遗留 #8 收口）；`PAIR_MISSING_OWNER_PUBKEY` 走注册的失败码常量（R1a 遗留 #3 收口）。
- **不变量延续**：`agentdeckd` 无 tokio net（guard）；`agentdeck-cli` 无 axum；`thiserror` 单版本 1.x、`rand_core` 单版本 0.6；`RelayLink` trait 签名不变（`recv` 仍不返回 `Result`，R2 defer）。
- **本计划明确不做**（已在设计文档 lock-in defer）：CLI 侧收尾（`remote.rs` 拆模块/`selfcheck` bool/`ureq` features）；CLI 侧 Ack 发送逻辑。

## 关键实施决策（本计划已给出的 default，供 review 时核对）

- **§9-5 Ack CLI 端**：Core 侧 Ack 接语义纳入 R1b（Task 5），**CLI 发送端不做**——CLI 场景是"用户交互驱动、短命连接"（用完即断连），Ack 更适合 programmatic client（iOS companion R3、daemon remote-mode R2）在长驻连接上定期确认。R1b 硬上界防线独立生效，不依赖任何客户端发 Ack 才能保证内存有界。
- **§9-6 数值 default**：`conv_buffer_cap` 默认 **1000**（每 conversation，约 10 events/s × 100s 缓冲的保守估计）；`req_origin_ttl_ms` 默认 **300_000**（5 分钟，对齐典型 RPC timeout）。两者均做成 `RelayConfig` 可配置项（`--conv-buffer-cap`/`--req-origin-ttl-ms` + 对应 `AGENTDECK_RELAY_*` env），非硬编码常量。

## 后续（非 R1b）

- **R1c**：`DataEnvelope::Encrypted`（IETF ChaCha20-Poly1305 + X25519/HKDF）+ 跨语言测试向量；用 R1a 已登记 box 公钥封装 per-session DEK；`conv_events.payload` 落盘策略翻转为写入密文（schema 不变，见本设计 §2.4）；seal 策略（required_e2ee/optional/plaintext_only）；机器侧 box 私钥托管。
- **R2**：`RelayLink::recv` 返回 `Result`（本 R1b 设计 §4.1 defer）；agentdeckd remote-mode（daemon 直连 relay，取代外部 bridge）；outbound reconnect/backoff；评估 machine_id 与 device_id 解耦（R1a 隐含约束，见 `ARCHITECTURE.md`）。
- **R3**：QR 扫码配对 UX；iOS `RelaySessionSource`；跨平台密码学互操作验证；APNs。
- **R4**：`Subscribe{Machines}` account scope 过滤（多账户上线前无实际意义）；hosted/多租户/team ACL；scoped 凭据。
- **CLI polish PR（独立，非 R1b/R1c/R2 序列）**：`agentdeck-cli/src/remote.rs` 拆子模块；`agentdeck-relay/src/main.rs` 改用 `RawArgs.selfcheck: bool`；`ureq` 加 `default-features = false`。
