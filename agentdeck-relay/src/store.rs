// agentdeck-relay/src/store.rs
//! SQLite-backed `RelayStore`（R1b Task 3）——`rusqlite` bundled，无系统 lib 依赖。
//!
//! 布局：`Arc<Mutex<Connection>>`（Clone 共享连接，Task 4 Core 会把 handle clone
//! 给 `spawn_blocking` 任务）。用 `PRAGMA user_version` 驱动 forward-only 迁移
//! 数组，v1 一次性建 5 张表（本 task 只用 accounts/devices/challenges，
//! seq_high_water_marks/conv_events 预置留给 Task 4 消费——避免 Task 4 撞
//! migration 版本递增）。
//!
//! 语义与 `InMemoryRelayStore` 对齐：`put_challenge`/`put_device`/`create_account`
//! 都是"存在则覆盖"（HashMap 语义 → `INSERT ... ON CONFLICT DO UPDATE`），
//! `take_challenge` 是"命中未过期即原子删除"（一个事务内 `SELECT` + 条件
//! `DELETE`，无 `used` 列——延续 R1a Task 6 `take_challenge` 的实现，不引入
//! R1a 遗留 #5 的死字段）。

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

use crate::auth::store::{Account, Challenge, Device, DeviceRole, RelayStore};

/// 有序 forward-only migration 数组。启动时读 `PRAGMA user_version`，从当前
/// 版本递增 apply 未跑过的 SQL 块（每块可含多条 DDL，`execute_batch` 单事务），
/// 应用完后把 `user_version` bump 到 `MIGRATIONS.len()`。幂等（重复调用不重跑）。
///
/// v1：一次性建 5 张表（DDL 抄设计 §2.2）。
/// - accounts：singleton 应用层强制（schema 不限制行数，为 R4 多账户预留）
/// - devices：`credential_hash UNIQUE` + 专用索引，替换 R1a 内存版的线性扫描
/// - challenges：无 `used` 列，消费语义 = 命中未过期即 `DELETE`
/// - seq_high_water_marks / conv_events：本 task 只建表结构，Task 4
///   persist-before-deliver 才写入
const MIGRATIONS: &[&str] = &[
    // v1: initial schema (5 tables + index)
    r#"
        CREATE TABLE IF NOT EXISTS accounts (
            account_id          TEXT PRIMARY KEY,
            owner_sign_pubkey   TEXT NOT NULL,
            created_at_ms       INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id           TEXT PRIMARY KEY,
            account_id          TEXT NOT NULL REFERENCES accounts(account_id),
            role                TEXT NOT NULL CHECK (role IN ('machine', 'device')),
            credential_hash     TEXT NOT NULL UNIQUE,
            sign_pubkey         TEXT NOT NULL,
            box_pubkey          TEXT NOT NULL,
            revoked             INTEGER NOT NULL DEFAULT 0,
            created_at_ms       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_devices_credential_hash ON devices(credential_hash);

        CREATE TABLE IF NOT EXISTS challenges (
            device_sign_pubkey  TEXT PRIMARY KEY,
            nonce               TEXT NOT NULL,
            expires_at_ms       INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS seq_high_water_marks (
            conversation_id     TEXT PRIMARY KEY,
            next_seq            INTEGER NOT NULL DEFAULT 0,
            acked_seq           INTEGER NOT NULL DEFAULT -1
        );

        CREATE TABLE IF NOT EXISTS conv_events (
            conversation_id     TEXT NOT NULL,
            seq                 INTEGER NOT NULL,
            turn_session_id     TEXT NOT NULL,
            encryption_version  INTEGER NOT NULL DEFAULT 0,
            payload             BLOB,
            created_at_ms       INTEGER NOT NULL,
            PRIMARY KEY (conversation_id, seq)
        );
    "#,
];

/// 幂等执行未跑过的 migration。`current == target` 时循环体不跑；`IF NOT EXISTS`
/// 是二次保险。允许 `pub(crate)` 是为了单测直接调用验证幂等性。
pub(crate) fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    let current: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let target = MIGRATIONS.len() as u32;
    for v in current..target {
        conn.execute_batch(MIGRATIONS[v as usize])?;
    }
    if target > current {
        // `PRAGMA user_version = N` 不接受参数绑定；用 pragma_update 走 SQLite 内建路径。
        conn.pragma_update(None, "user_version", target)?;
    }
    Ok(())
}

/// SQLite 落盘的 `RelayStore` 实现。
///
/// `Clone` 语义：多个 handle 共享同一 `Connection`（Task 4 Core 需要 clone 给
/// `spawn_blocking` 任务）。所有方法先拿 `Mutex` 锁再操作，`Mutex` poisoned
/// 用 `.expect` 直接 panic——存储层 poisoning 属不可恢复的编程 bug。
#[derive(Clone)]
pub struct SqliteRelayStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteRelayStore {
    /// 打开或创建落盘 SQLite 文件；启动时配 WAL/synchronous NORMAL + 跑 migration。
    /// 调用方需保证父目录已存在（Task 9 main.rs 会 mkdir_p）。
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::configure_and_migrate(conn)
    }

    /// in-memory 变体，测试用；schema 相同，不落盘。WAL pragma 对 in-memory db
    /// SQLite 会静默保持 "memory" journal mode，不报错。
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::configure_and_migrate(conn)
    }

    fn configure_and_migrate(conn: Connection) -> rusqlite::Result<Self> {
        // WAL 允许 1 写者+N 读者并发；synchronous=NORMAL 在 WAL 下是官方推荐的
        // 性能/持久性平衡点（见设计 §2.2）。in-memory db SQLite 会保持 "memory"
        // journal mode，pragma_update 不返错。
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        run_migrations(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// 测试专用 helper：让单测直接对 `Connection` 跑校验（例如复跑 `run_migrations`
    /// 验证幂等）。生产代码只用 trait 方法。
    #[cfg(test)]
    pub(crate) fn with_conn<F, R>(&self, f: F) -> rusqlite::Result<R>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<R>,
    {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        f(&*conn)
    }

    /// Task 4：persist-before-deliver 的核心方法——同一事务内 UPSERT
    /// `seq_high_water_marks` 取号（`next_seq` 自增，返回值即新分配的 `seq`）
    /// + `INSERT conv_events`（`payload` 恒 NULL，见 §2.4 决策——R1c 才写密文）。
    /// 不属于 `RelayStore` trait（trait 只覆盖 accounts/devices/challenges），
    /// 是 Core 专用的 inherent 方法。事务保证"取号"与"落盘事件"原子——不会出现
    /// 号已分配但事件未落盘（或反之）的中间态。
    pub(crate) fn reserve_and_persist_event(
        &self,
        conversation_id: &str,
        turn_session_id: &str,
        now_ms: i64,
    ) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO seq_high_water_marks(conversation_id, next_seq) VALUES (?1, 1)
             ON CONFLICT(conversation_id) DO UPDATE SET next_seq = next_seq + 1",
            params![conversation_id],
        )?;
        let next_seq: u64 = tx.query_row(
            "SELECT next_seq FROM seq_high_water_marks WHERE conversation_id = ?1",
            params![conversation_id],
            |r| r.get(0),
        )?;
        let seq = next_seq - 1;
        tx.execute(
            "INSERT INTO conv_events(conversation_id, seq, turn_session_id, encryption_version, payload, created_at_ms)
             VALUES (?1, ?2, ?3, 0, NULL, ?4)",
            params![conversation_id, seq, turn_session_id, now_ms],
        )?;
        tx.commit()?;
        Ok(seq)
    }

    /// 重启恢复用：返回持久化的高水位（下一个将分配的 seq）。无该 conversation
    /// 记录时返回 0（与内存版 `conv_seq` 首次 `entry().or_insert(0)` 语义对齐）。
    /// 供测试断言；生产路径本身不消费（`reserve_and_persist_event` 自足）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn load_next_seq(&self, conversation_id: &str) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.query_row(
            "SELECT next_seq FROM seq_high_water_marks WHERE conversation_id = ?1",
            params![conversation_id],
            |r| r.get(0),
        )
        .optional()
        .map(|opt| opt.unwrap_or(0))
    }

    /// Task 5：记录一次 Ack 的落盘游标。`MAX(acked_seq, ?2)` 防止乱序/重复 Ack
    /// 回退游标（Ack 乱序或重复到达时保守取最大，不允许倒退）。该行必须已由
    /// `reserve_and_persist_event` 创建（即至少发布过一条事件）——Ack 早于任何
    /// 事件发布时此 `UPDATE` 影响 0 行，静默无操作（该场景无意义：没有 seq 可
    /// ack）。
    pub(crate) fn record_ack(&self, conversation_id: &str, up_to_seq: u64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "UPDATE seq_high_water_marks SET acked_seq = MAX(acked_seq, ?2) WHERE conversation_id = ?1",
            params![conversation_id, up_to_seq],
        )?;
        Ok(())
    }

    /// 测试断言用：读回 `record_ack` 落盘的 `acked_seq`。无该 conversation 记录
    /// 时返回 `None`（与 `load_next_seq` 的"未知即 0"不同——`acked_seq` 的默认
    /// 值 `-1` 语义是"尚未 ack"，用 `Option` 更诚实地表达"行不存在"与"已 ack 到
    /// -1（从未 ack）"的区别）。
    #[cfg(test)]
    pub(crate) fn load_acked_seq(&self, conversation_id: &str) -> rusqlite::Result<Option<i64>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.query_row(
            "SELECT acked_seq FROM seq_high_water_marks WHERE conversation_id = ?1",
            params![conversation_id],
            |r| r.get(0),
        )
        .optional()
    }
}

fn role_to_str(role: DeviceRole) -> &'static str {
    match role {
        DeviceRole::Machine => "machine",
        DeviceRole::Device => "device",
    }
}

/// 反向映射；DDL 的 `CHECK` 已限制列值集合，正常路径不会走到 unreachable，
/// 但保守用 `Result` 避免 panic 传染到 `query_row` 的 row-mapper。
fn role_from_str(s: &str) -> rusqlite::Result<DeviceRole> {
    match s {
        "machine" => Ok(DeviceRole::Machine),
        "device" => Ok(DeviceRole::Device),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("unknown device role: {other:?}").into(),
        )),
    }
}

/// row → Device 反序列化（`revoked` INTEGER→bool；`role` TEXT→enum）。
fn row_to_device(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    let role_str: String = row.get("role")?;
    Ok(Device {
        device_id: row.get("device_id")?,
        account_id: row.get("account_id")?,
        role: role_from_str(&role_str)?,
        credential_hash: row.get("credential_hash")?,
        sign_pubkey: row.get("sign_pubkey")?,
        box_pubkey: row.get("box_pubkey")?,
        revoked: row.get::<_, i64>("revoked")? != 0,
    })
}

impl RelayStore for SqliteRelayStore {
    /// 存在则覆盖同 device_sign_pubkey 的旧 challenge（R1a 语义：同一 pubkey
    /// 重复 start_challenge 覆盖旧的）。用 `INSERT OR REPLACE` 匹配 PK 冲突。
    fn put_challenge(&mut self, challenge: Challenge) {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO challenges (device_sign_pubkey, nonce, expires_at_ms)
             VALUES (?1, ?2, ?3)",
            params![
                challenge.device_sign_pubkey,
                challenge.nonce,
                challenge.expires_at_ms
            ],
        )
        .expect("sqlite put_challenge failed");
    }

    /// 原子单次消费：一个事务里 SELECT（带未过期条件）+ DELETE，命中就返回并删除，
    /// 否则 None。不设 `used` 列（见 §2.2 决策）。
    fn take_challenge(&mut self, device_sign_pubkey: &str, now_ms: i64) -> Option<Challenge> {
        let mut conn = self.conn.lock().expect("sqlite store mutex poisoned");
        let tx = conn.transaction().expect("sqlite tx begin failed");
        let ch: Option<Challenge> = tx
            .query_row(
                "SELECT device_sign_pubkey, nonce, expires_at_ms
                 FROM challenges
                 WHERE device_sign_pubkey = ?1 AND expires_at_ms > ?2",
                params![device_sign_pubkey, now_ms],
                |row| {
                    Ok(Challenge {
                        device_sign_pubkey: row.get(0)?,
                        nonce: row.get(1)?,
                        expires_at_ms: row.get(2)?,
                        // SQLite 层不存 `used`（见 §2.2）；返回的 Challenge 是
                        // 内存镜像值，used=false 表示"刚从 store 拿到、未消费"，
                        // 但本方法调用即视为消费（下一行 DELETE），value 只对
                        // 调用方语义占位。
                        used: false,
                    })
                },
            )
            .optional()
            .expect("sqlite take_challenge query failed");
        if ch.is_some() {
            tx.execute(
                "DELETE FROM challenges WHERE device_sign_pubkey = ?1",
                params![device_sign_pubkey],
            )
            .expect("sqlite take_challenge delete failed");
        }
        tx.commit().expect("sqlite take_challenge commit failed");
        ch
    }

    /// singleton 应用层约束：schema 允许多行，但 R1b 只插一行；用 `LIMIT 1`
    /// 幂等返回。
    fn singleton_account(&self) -> Option<Account> {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        conn.query_row(
            "SELECT account_id, owner_sign_pubkey FROM accounts LIMIT 1",
            [],
            |row| {
                Ok(Account {
                    account_id: row.get(0)?,
                    owner_sign_pubkey: row.get(1)?,
                })
            },
        )
        .optional()
        .expect("sqlite singleton_account query failed")
    }

    /// 存在则覆盖同 account_id 的旧 account（HashMap-like 语义）；schema 的
    /// `created_at_ms NOT NULL` 由 trait 层不提供时间戳、这里填 0 兜底
    /// （R1b 无消费方；R4 多账户扩展时若需真时间戳可在 trait 加参数）。
    fn create_account(&mut self, account: Account) {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        conn.execute(
            "INSERT INTO accounts (account_id, owner_sign_pubkey, created_at_ms)
             VALUES (?1, ?2, 0)
             ON CONFLICT(account_id) DO UPDATE SET owner_sign_pubkey = excluded.owner_sign_pubkey",
            params![account.account_id, account.owner_sign_pubkey],
        )
        .expect("sqlite create_account failed");
    }

    /// 存在则覆盖同 device_id 的旧 device（HashMap-like 语义）。仅走 PK 冲突路径，
    /// 避免 `INSERT OR REPLACE` 在 `credential_hash UNIQUE` 冲突时误删其它设备。
    /// `created_at_ms` 与 `create_account` 同理填 0 兜底。
    fn put_device(&mut self, device: Device) {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        conn.execute(
            "INSERT INTO devices
                (device_id, account_id, role, credential_hash, sign_pubkey, box_pubkey, revoked, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)
             ON CONFLICT(device_id) DO UPDATE SET
                account_id = excluded.account_id,
                role = excluded.role,
                credential_hash = excluded.credential_hash,
                sign_pubkey = excluded.sign_pubkey,
                box_pubkey = excluded.box_pubkey,
                revoked = excluded.revoked",
            params![
                device.device_id,
                device.account_id,
                role_to_str(device.role),
                device.credential_hash,
                device.sign_pubkey,
                device.box_pubkey,
                device.revoked as i64,
            ],
        )
        .expect("sqlite put_device failed");
    }

    fn device(&self, device_id: &str) -> Option<Device> {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        conn.query_row(
            "SELECT device_id, account_id, role, credential_hash, sign_pubkey, box_pubkey, revoked
             FROM devices WHERE device_id = ?1",
            params![device_id],
            row_to_device,
        )
        .optional()
        .expect("sqlite device query failed")
    }

    /// 走 `idx_devices_credential_hash` 索引（见 §2.2）；替换 R1a 内存版的
    /// 线性扫描。
    fn device_by_credential_hash(&self, credential_hash: &str) -> Option<Device> {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        conn.query_row(
            "SELECT device_id, account_id, role, credential_hash, sign_pubkey, box_pubkey, revoked
             FROM devices WHERE credential_hash = ?1",
            params![credential_hash],
            row_to_device,
        )
        .optional()
        .expect("sqlite device_by_credential_hash query failed")
    }

    fn account_count(&self) -> usize {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))
            .expect("sqlite account_count query failed");
        n as usize
    }

    fn mark_revoked(&mut self, device_id: &str) {
        let conn = self.conn.lock().expect("sqlite store mutex poisoned");
        conn.execute(
            "UPDATE devices SET revoked = 1 WHERE device_id = ?1",
            params![device_id],
        )
        .expect("sqlite mark_revoked failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::store::{Account, Challenge, Device, DeviceRole, RelayStore};

    #[test]
    fn migration_is_idempotent() {
        let store = SqliteRelayStore::open_in_memory().unwrap();
        // 重复跑 migration 不报错（open 内部已跑一次；这里直接调 run_migrations 复跑）
        store.with_conn(run_migrations).unwrap();
    }

    #[test]
    fn device_crud_and_credential_hash_lookup() {
        let mut store = SqliteRelayStore::open_in_memory().unwrap();
        store.create_account(Account {
            account_id: "acc1".into(),
            owner_sign_pubkey: "opk".into(),
        });
        store.put_device(Device {
            device_id: "d1".into(),
            account_id: "acc1".into(),
            role: DeviceRole::Device,
            credential_hash: "hash1".into(),
            sign_pubkey: "spk".into(),
            box_pubkey: "bpk".into(),
            revoked: false,
        });
        assert_eq!(store.device("d1").unwrap().credential_hash, "hash1");
        assert_eq!(
            store.device_by_credential_hash("hash1").unwrap().device_id,
            "d1"
        );
        assert_eq!(store.account_count(), 1);
        store.mark_revoked("d1");
        assert!(store.device("d1").unwrap().revoked);
    }

    #[test]
    fn challenge_take_is_single_use_and_respects_ttl() {
        let mut store = SqliteRelayStore::open_in_memory().unwrap();
        store.put_challenge(Challenge {
            device_sign_pubkey: "pk1".into(),
            nonce: "n1".into(),
            expires_at_ms: 10_000,
            used: false,
        });
        assert!(store.take_challenge("pk1", 5_000).is_some());
        // 已消费：第二次 take 必须 None（即便时间仍在 TTL 内）
        assert!(
            store.take_challenge("pk1", 5_000).is_none(),
            "已消费的 challenge 不应再次命中（仍在 TTL 内）"
        );
        store.put_challenge(Challenge {
            device_sign_pubkey: "pk1".into(),
            nonce: "n1".into(),
            expires_at_ms: 10_000,
            used: false,
        });
        assert!(
            store.take_challenge("pk1", 20_000).is_none(),
            "过期后不应命中"
        );
    }

    #[test]
    fn survives_restart_reopening_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        {
            let mut store = SqliteRelayStore::open(&path).unwrap();
            store.create_account(Account {
                account_id: "acc1".into(),
                owner_sign_pubkey: "opk".into(),
            });
            store.put_device(Device {
                device_id: "d1".into(),
                account_id: "acc1".into(),
                role: DeviceRole::Machine,
                credential_hash: "hash1".into(),
                sign_pubkey: "spk".into(),
                box_pubkey: "bpk".into(),
                revoked: true,
            });
        }
        // 重新打开同一文件（模拟 relay 进程重启）
        let store2 = SqliteRelayStore::open(&path).unwrap();
        assert_eq!(store2.account_count(), 1);
        assert!(
            store2.device("d1").unwrap().revoked,
            "撤销状态必须跨重启保留"
        );
    }
}
