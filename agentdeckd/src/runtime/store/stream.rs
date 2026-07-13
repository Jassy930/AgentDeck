//! Runtime v4 canonical replay window、snapshot 与 publication store。
//!
//! `event_journal` 仍是 P3.2/P3.5 authenticated audit；本模块只裁剪
//! `event_stream_index` membership，绝不删除或改写 audit ciphertext。

use agentdeck_protocol::runtime::{CatalogDelta, RuntimeEvent};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::runtime::model::RuntimeStoreError;
use crate::runtime::read_pool::{
    MAX_RUNTIME_READ_PAGE_BYTES, MAX_RUNTIME_READ_PAGE_ROWS, ReadMemoryLease,
};

use super::cipher::{RowAad, RuntimeKeyBundle};
use super::persisted_event::{PersistedRuntimeEvent, decode_persisted_runtime_event};
use super::sequence::{SequenceScope, decode_sequence};
use super::sqlite::RuntimeLedger;
use super::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};

pub(crate) const MAX_EVENT_STREAM_EVENTS_PER_CONVERSATION: u64 = 10_000;
pub(crate) const MAX_EVENT_STREAM_BYTES_PER_CONVERSATION: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_EVENT_STREAM_EVENTS_GLOBAL: u64 = 131_072;
pub(crate) const MAX_EVENT_STREAM_BYTES_GLOBAL: u64 = 512 * 1024 * 1024;
pub(crate) const BACKFILL_PIN_TTL_MS: u64 = 5 * 60 * 1_000;
pub(crate) const MAX_ACTIVE_BACKFILL_PINS: u64 = 4_096;

const EVENT_STREAM_INDEX_TOKEN_DOMAIN: &[u8] = b"event.stream-index.v1";
const EVENT_RETENTION_TOKEN_DOMAIN: &[u8] = b"event.retention.v1";
const V4_SCHEMA_FIXED_PROJECTION_BYTES: u64 = 66 * 1024 * 1024;
const V4_EVENT_INDEX_PROJECTION_BYTES: u64 = 256;
const V4_RETENTION_PROJECTION_BYTES: u64 = 256;

#[derive(Clone)]
struct MigrationEventIndex {
    event_seq: String,
    event_id: Vec<u8>,
    logical_event_bytes: u64,
    created_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeBackfillTarget {
    Catalog,
    Conversation(super::RuntimeId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeBackfillPin {
    pub pin_id: [u8; 16],
    pub target: RuntimeBackfillTarget,
    pub after: Option<u64>,
    pub through: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeBackfillPlan {
    Current { high_water: Option<u64> },
    Pinned(RuntimeBackfillPin),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSnapshotBuildPin {
    pin_id: [u8; 16],
    conversation_id: super::RuntimeId,
    base_event_seq: Option<u64>,
    expires_at_ms: u64,
}

impl RuntimeSnapshotBuildPin {
    pub(super) const fn pin_id(&self) -> [u8; 16] {
        self.pin_id
    }

    #[must_use]
    pub const fn conversation_id(&self) -> super::RuntimeId {
        self.conversation_id
    }

    #[must_use]
    pub const fn base_event_seq(&self) -> Option<u64> {
        self.base_event_seq
    }
}

#[derive(Debug)]
pub struct RuntimeEventBackfillPage {
    pub events: Vec<RuntimeEvent>,
    pub next_after: u64,
    pub through: u64,
    pub complete: bool,
    pub(crate) memory_lease: Option<ReadMemoryLease>,
}

#[derive(Debug, PartialEq)]
pub struct RuntimeCatalogBackfillPage {
    pub deltas: Vec<CatalogDelta>,
    pub next_after: u64,
    pub through: u64,
    pub complete: bool,
    pub(crate) memory_lease: Option<ReadMemoryLease>,
}

#[derive(Clone, Debug)]
pub(super) struct RuntimeBackfillReadPlan {
    pin: RuntimeBackfillPin,
    requested_after: Option<u64>,
    first: u64,
}

/// v4 migration 的写入 projection 随实际 conversation/event 数量增长，禁止继续使用
/// 固定 2 MiB 伪预算。这里按最终 retained membership 上界计算 B-tree/WAL 闭包；
/// audit payload 本身不复制。
pub(super) fn migration_projection_bytes(
    connection: &Connection,
) -> Result<u64, RuntimeStoreError> {
    let conversation_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM conversations", [], |row| row.get(0))?;
    let event_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))?;
    let conversation_count =
        u64::try_from(conversation_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let event_count =
        u64::try_from(event_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let peak_global_batch = MAX_EVENT_STREAM_EVENTS_GLOBAL
        .checked_add(MAX_EVENT_STREAM_EVENTS_PER_CONVERSATION)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "v4 migration peak event index count",
        })?;
    let peak_index_count = event_count.min(peak_global_batch).min(
        conversation_count
            .checked_mul(MAX_EVENT_STREAM_EVENTS_PER_CONVERSATION)
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "v4 migration retained event count",
            })?,
    );
    V4_SCHEMA_FIXED_PROJECTION_BYTES
        .checked_add(
            peak_index_count
                .checked_mul(V4_EVENT_INDEX_PROJECTION_BYTES)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "v4 migration event index bytes",
                })?,
        )
        .and_then(|value| {
            conversation_count
                .checked_mul(V4_RETENTION_PROJECTION_BYTES)
                .and_then(|retention| value.checked_add(retention))
        })
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "v4 migration projection bytes",
        })
}

/// 在已经执行 v4 DDL 的同一 IMMEDIATE transaction 内，流式建立 logical replay
/// suffix 和 authenticated retention rows。每次最多物化单 conversation 的 10k
/// compact index records，不持有 payload，也不全库 collect。
pub(super) fn migrate_v4_rows(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    current: &RuntimeLedger,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let audit_event_logical_bytes: i64 = transaction.query_row(
        "SELECT COALESCE(SUM(logical_event_bytes), 0) FROM event_journal",
        [],
        |row| row.get(0),
    )?;
    let audit_event_logical_bytes = u64::try_from(audit_event_logical_bytes)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;

    let mut conversation_statement = transaction.prepare(
        "SELECT conversation_id, event_high_water
         FROM conversations ORDER BY conversation_id",
    )?;
    let conversations = conversation_statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    for conversation in conversations {
        let (conversation_id, event_high_water) = conversation?;
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(
                usize::try_from(MAX_EVENT_STREAM_EVENTS_PER_CONVERSATION)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        let mut retained_bytes = 0_u64;
        let mut statement = transaction.prepare(
            "SELECT event_seq, event_id, logical_event_bytes, created_at_ms
             FROM event_journal
             WHERE conversation_id = ?1
             ORDER BY event_seq DESC
             LIMIT 10000",
        )?;
        let rows = statement.query_map([&conversation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (event_seq, event_id, logical_event_bytes, created_at_ms) = row?;
            let event_id_value = runtime_event_id(&event_id)?;
            let event =
                super::journal::load_event(transaction, key_bundle, database_id, event_id_value)?;
            if matches!(
                decode_persisted_runtime_event(&event)?,
                PersistedRuntimeEvent::NonCanonical
            ) {
                break;
            }
            let logical_event_bytes = u64::try_from(logical_event_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let projected = retained_bytes.checked_add(logical_event_bytes).ok_or(
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "v4 conversation retained event bytes",
                },
            )?;
            if projected > MAX_EVENT_STREAM_BYTES_PER_CONVERSATION {
                break;
            }
            retained_bytes = projected;
            retained.push(MigrationEventIndex {
                event_seq,
                event_id,
                logical_event_bytes,
                created_at_ms: u64::try_from(created_at_ms)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            });
        }
        drop(statement);
        retained.reverse();
        for event in &retained {
            let token = event_stream_index_token(
                key_bundle,
                &conversation_id,
                &event.event_seq,
                &event.event_id,
                event.logical_event_bytes,
                event.created_at_ms,
            )?;
            transaction.execute(
                "INSERT INTO event_stream_index (
                     conversation_id, event_seq, event_id, logical_event_bytes,
                     created_at_ms, metadata_token
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &conversation_id,
                    &event.event_seq,
                    &event.event_id,
                    sqlite_u64(event.logical_event_bytes)?,
                    sqlite_u64(event.created_at_ms)?,
                    &token[..],
                ],
            )?;
        }
        let oldest = retained.first().map(|event| event.event_seq.as_str());
        let count =
            u64::try_from(retained.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        insert_or_replace_retention(
            transaction,
            key_bundle,
            &conversation_id,
            event_high_water.as_deref(),
            oldest,
            count,
            retained_bytes,
        )?;
        // 迁移也必须约束 transaction 内的物理峰值：不等所有 conversation
        // 都物化后才做 global trim，否则容量预检只投影 global cap 却可能
        // 短暂写入数百万个 index row。每个 conversation 完成后立即裁剪，
        // 中间态最多只比 global cap 多一个已有 per-conversation cap 的批次。
        trim_global_event_window(transaction, key_bundle, false)?;
    }
    drop(conversation_statement);

    // 保留终态校验式 trim，便于未来调整批次时仍不依赖循环细节。
    trim_global_event_window(transaction, key_bundle, false)?;
    let (event_stream_count, event_stream_bytes): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
         FROM event_stream_index",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut next = current.clone();
    next.audit_event_logical_bytes = audit_event_logical_bytes;
    next.event_stream_count =
        u64::try_from(event_stream_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.event_stream_bytes =
        u64::try_from(event_stream_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.catalog_delta_count = 0;
    next.catalog_delta_bytes = 0;
    next.catalog_retention_floor = None;
    next.snapshot_count = 0;
    next.snapshot_bytes = 0;
    next.publication_stream_count = 0;
    next.publication_outbox_count = 0;
    next.publication_outbox_bytes = 0;
    super::snapshot::migrate_catalog_snapshot_baseline(
        transaction,
        key_bundle,
        database_id,
        &mut next,
    )?;
    Ok(next)
}

/// 所有 v4 audit event mutation 在更新 runtime ledger 前经过此处。它只把
/// `indexed_through_event_seq` 之后的新 audit suffix 加入 replay index；已经因 retention
/// 被裁掉的旧 membership 永远不会被重新加入。
pub(super) fn reconcile_event_stream(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &RuntimeLedger,
    requested_next: &RuntimeLedger,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let mut next = requested_next.clone();
    let event_delta = requested_next
        .event_count
        .checked_sub(previous.event_count)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;

    // 新建 conversation 即建立零窗口 retention row；最多 1,024 个 compact ids。
    let mut missing_retention = Vec::new();
    let mut statement = transaction.prepare(
        "SELECT c.conversation_id, c.event_high_water
         FROM conversations c
         LEFT JOIN event_retention r ON r.conversation_id = c.conversation_id
         WHERE r.conversation_id IS NULL
         ORDER BY c.conversation_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    for row in rows {
        missing_retention.push(row?);
        if missing_retention.len() > 1_024 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);
    for (conversation_id, high_water) in missing_retention {
        insert_or_replace_retention(
            transaction,
            key_bundle,
            &conversation_id,
            high_water.as_deref(),
            None,
            0,
            0,
        )?;
    }

    if event_delta == 0 {
        return Ok(next);
    }

    let mut changed = Vec::new();
    let mut statement = transaction.prepare(
        "SELECT c.conversation_id, c.event_high_water, r.indexed_through_event_seq
         FROM conversations c
         JOIN event_retention r ON r.conversation_id = c.conversation_id
         WHERE (c.event_high_water IS NULL AND r.indexed_through_event_seq IS NOT NULL)
            OR (c.event_high_water IS NOT NULL AND r.indexed_through_event_seq IS NULL)
            OR c.event_high_water <> r.indexed_through_event_seq
         ORDER BY c.conversation_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        changed.push(row?);
        if changed.len() > 1_024 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);

    let mut processed_delta = 0_u64;
    let mut audit_bytes_delta = 0_u64;
    for (conversation_id, high_water, indexed_through) in changed {
        let high_water = high_water.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let mut statement = transaction.prepare(
            "SELECT event_seq, event_id, logical_event_bytes, created_at_ms
             FROM event_journal
             WHERE conversation_id = ?1
               AND (?2 IS NULL OR event_seq > ?2)
               AND event_seq <= ?3
             ORDER BY event_seq",
        )?;
        let rows = statement.query_map(
            params![&conversation_id, indexed_through.as_deref(), &high_water],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        for row in rows {
            let (event_seq, event_id, logical_event_bytes, created_at_ms) = row?;
            let logical_event_bytes = u64::try_from(logical_event_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let created_at_ms = u64::try_from(created_at_ms)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let event = super::journal::load_event(
                transaction,
                key_bundle,
                database_id,
                runtime_event_id(&event_id)?,
            )?;
            processed_delta = processed_delta.checked_add(1).ok_or(
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "event stream processed delta",
                },
            )?;
            audit_bytes_delta = audit_bytes_delta.checked_add(logical_event_bytes).ok_or(
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "audit event byte delta",
                },
            )?;
            if matches!(
                decode_persisted_runtime_event(&event)?,
                PersistedRuntimeEvent::NonCanonical
            ) {
                // 旧 fixed/internal audit row 不是 RuntimeEvent wire。它形成 logical replay
                // 断点：不改写 audit ciphertext，只丢弃断点及其之前的 membership。
                revoke_all_stream_pins(transaction, "event", Some(&conversation_id))?;
                transaction.execute(
                    "DELETE FROM event_stream_index WHERE conversation_id = ?1",
                    [&conversation_id],
                )?;
                continue;
            }
            let token = event_stream_index_token(
                key_bundle,
                &conversation_id,
                &event_seq,
                &event_id,
                logical_event_bytes,
                created_at_ms,
            )?;
            transaction.execute(
                "INSERT INTO event_stream_index (
                     conversation_id, event_seq, event_id, logical_event_bytes,
                     created_at_ms, metadata_token
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &conversation_id,
                    &event_seq,
                    &event_id,
                    sqlite_u64(logical_event_bytes)?,
                    sqlite_u64(created_at_ms)?,
                    &token[..],
                ],
            )?;
        }
        drop(statement);
        trim_unrecorded_conversation_window(
            transaction,
            &conversation_id,
            true,
            MAX_EVENT_STREAM_EVENTS_PER_CONVERSATION,
            MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
        )?;
        refresh_retention(transaction, key_bundle, &conversation_id)?;
    }
    if processed_delta != event_delta {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    trim_global_event_window(transaction, key_bundle, true)?;
    let (stream_count, stream_bytes): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
         FROM event_stream_index",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    next.audit_event_logical_bytes = previous
        .audit_event_logical_bytes
        .checked_add(audit_bytes_delta)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "audit event logical bytes",
        })?;
    next.event_stream_count =
        u64::try_from(stream_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.event_stream_bytes =
        u64::try_from(stream_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(next)
}

pub(super) fn acquire_backfill_pin(
    state: &super::sqlite::RuntimeSqlite,
    target: RuntimeBackfillTarget,
    after: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeBackfillPlan, RuntimeStoreError> {
    state.connection.execute(
        "DELETE FROM temp.active_stream_pins WHERE expires_at_ms <= ?1",
        [sqlite_u64(now_ms)?],
    )?;
    let (scope, target_id, high_water, retained_floor) = match target {
        RuntimeBackfillTarget::Catalog => {
            let ledger = super::sqlite::load_runtime_ledger(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            )?;
            let high_water = ledger
                .catalog_high_water
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
                .transpose()?;
            let floor = ledger
                .catalog_retention_floor
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
                .transpose()?;
            ("catalog", None, high_water, floor)
        }
        RuntimeBackfillTarget::Conversation(conversation_id) => {
            if conversation_id.kind() != super::RuntimeIdKind::Conversation {
                return Err(RuntimeStoreError::IdKindMismatch {
                    expected: super::RuntimeIdKind::Conversation,
                    actual: conversation_id.kind(),
                });
            }
            let raw = state
                .connection
                .query_row(
                    "SELECT c.event_high_water, r.oldest_retained_event_seq,
                            r.indexed_through_event_seq
                     FROM conversations c
                     JOIN event_retention r ON r.conversation_id = c.conversation_id
                     WHERE c.conversation_id = ?1",
                    [&conversation_id.as_bytes()[..]],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::ConversationNotFound,
                    other => RuntimeStoreError::Sqlite(other),
                })?;
            if raw.0 != raw.2 {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let high_water = raw
                .0
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::EventSeq, value))
                .transpose()?;
            let floor = raw
                .1
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::EventSeq, value))
                .transpose()?;
            (
                "event",
                Some(conversation_id.as_bytes().to_vec()),
                high_water,
                floor,
            )
        }
    };
    let Some(through) = high_water else {
        return if after.is_none() {
            Ok(RuntimeBackfillPlan::Current { high_water: None })
        } else {
            Err(RuntimeStoreError::BackfillCursorAhead)
        };
    };
    if after == Some(through) {
        return Ok(RuntimeBackfillPlan::Current {
            high_water: Some(through),
        });
    }
    if after.is_some_and(|value| value > through) {
        return Err(RuntimeStoreError::BackfillCursorAhead);
    }
    let first = after
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or(RuntimeStoreError::BackfillCursorAhead)?;
    let retained = retained_floor.is_some_and(|floor| first >= floor);
    if !retained {
        return Err(RuntimeStoreError::BackfillNeedSnapshot);
    }
    let first_encoded = super::sequence::encode_sequence(first);
    let through_encoded = super::sequence::encode_sequence(through);
    let actual_count: i64 = match target {
        RuntimeBackfillTarget::Catalog => state.connection.query_row(
            "SELECT COUNT(*) FROM catalog_journal
             WHERE catalog_revision BETWEEN ?1 AND ?2",
            params![&first_encoded, &through_encoded],
            |row| row.get(0),
        )?,
        RuntimeBackfillTarget::Conversation(conversation_id) => state.connection.query_row(
            "SELECT COUNT(*) FROM event_stream_index
             WHERE conversation_id = ?1 AND event_seq BETWEEN ?2 AND ?3",
            params![
                &conversation_id.as_bytes()[..],
                &first_encoded,
                &through_encoded,
            ],
            |row| row.get(0),
        )?,
    };
    let expected_count = through
        .checked_sub(first)
        .and_then(|value| value.checked_add(1))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if u64::try_from(actual_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != expected_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let active_pin_count: i64 = state.connection.query_row(
        "SELECT COUNT(*) FROM temp.active_stream_pins WHERE state = 'active'",
        [],
        |row| row.get(0),
    )?;
    if u64::try_from(active_pin_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        >= MAX_ACTIVE_BACKFILL_PINS
    {
        return Err(RuntimeStoreError::WorkerBusy {
            lane: crate::runtime::model::RuntimeStoreLane::Read,
        });
    }
    let expires_at_ms = now_ms
        .checked_add(BACKFILL_PIN_TTL_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let next_after = after.map(super::sequence::encode_sequence);
    for _ in 0..16 {
        let mut pin_id = [0_u8; 16];
        getrandom::fill(&mut pin_id)
            .map_err(|_| RuntimeStoreError::InvalidConfig("OS entropy unavailable"))?;
        if pin_id == [0; 16] {
            continue;
        }
        let inserted = state.connection.execute(
            "INSERT OR IGNORE INTO temp.active_stream_pins (
                 pin_id, scope, target_id, first_seq, through_seq, next_after_seq,
                 expires_at_ms, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
            params![
                &pin_id[..],
                scope,
                target_id.as_deref(),
                &first_encoded,
                &through_encoded,
                next_after.as_deref(),
                sqlite_u64(expires_at_ms)?,
            ],
        )?;
        if inserted == 1 {
            return Ok(RuntimeBackfillPlan::Pinned(RuntimeBackfillPin {
                pin_id,
                target,
                after,
                through,
                expires_at_ms,
            }));
        }
    }
    Err(RuntimeStoreError::InvalidConfig(
        "backfill pin identity allocation exhausted",
    ))
}

pub(super) fn acquire_snapshot_build_pin(
    state: &super::sqlite::RuntimeSqlite,
    conversation_id: super::RuntimeId,
    now_ms: u64,
) -> Result<RuntimeSnapshotBuildPin, RuntimeStoreError> {
    if conversation_id.kind() != super::RuntimeIdKind::Conversation {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: super::RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        });
    }
    state.connection.execute(
        "DELETE FROM temp.active_stream_pins WHERE expires_at_ms <= ?1",
        [sqlite_u64(now_ms)?],
    )?;
    let high_water: Option<String> = state
        .connection
        .query_row(
            "SELECT event_high_water FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::ConversationNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let base_event_seq = high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()?;
    let expires_at_ms = now_ms
        .checked_add(BACKFILL_PIN_TTL_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let active_pin_count: i64 = state.connection.query_row(
        "SELECT COUNT(*) FROM temp.active_stream_pins WHERE state = 'active'",
        [],
        |row| row.get(0),
    )?;
    if u64::try_from(active_pin_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        >= MAX_ACTIVE_BACKFILL_PINS
    {
        return Err(RuntimeStoreError::WorkerBusy {
            lane: crate::runtime::model::RuntimeStoreLane::Read,
        });
    }
    for _ in 0..16 {
        let mut pin_id = [0_u8; 16];
        getrandom::fill(&mut pin_id)
            .map_err(|_| RuntimeStoreError::InvalidConfig("OS entropy unavailable"))?;
        if pin_id == [0; 16] {
            continue;
        }
        let inserted = state.connection.execute(
            "INSERT OR IGNORE INTO temp.active_stream_pins (
                 pin_id, scope, target_id, first_seq, through_seq, next_after_seq,
                 expires_at_ms, state
             ) VALUES (?1, 'snapshot', ?2, ?3, ?4, NULL, ?5, 'active')",
            params![
                &pin_id[..],
                &conversation_id.as_bytes()[..],
                high_water.as_deref(),
                high_water.as_deref(),
                sqlite_u64(expires_at_ms)?,
            ],
        )?;
        if inserted == 1 {
            return Ok(RuntimeSnapshotBuildPin {
                pin_id,
                conversation_id,
                base_event_seq,
                expires_at_ms,
            });
        }
    }
    Err(RuntimeStoreError::InvalidConfig(
        "snapshot build pin identity allocation exhausted",
    ))
}

pub(super) fn release_snapshot_build_pin(
    state: &super::sqlite::RuntimeSqlite,
    pin: &RuntimeSnapshotBuildPin,
) -> Result<(), RuntimeStoreError> {
    state.connection.execute(
        "DELETE FROM temp.active_stream_pins
         WHERE pin_id = ?1 AND scope = 'snapshot' AND target_id = ?2",
        params![&pin.pin_id[..], &pin.conversation_id.as_bytes()[..]],
    )?;
    Ok(())
}

pub(super) fn validate_snapshot_build_pin(
    connection: &Connection,
    pin: &RuntimeSnapshotBuildPin,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT target_id, through_seq, expires_at_ms, state
             FROM temp.active_stream_pins
             WHERE pin_id = ?1 AND scope = 'snapshot'",
            [&pin.pin_id[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    let stored_base = raw
        .1
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()?;
    let stored_expiry =
        u64::try_from(raw.2).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if raw.0.as_slice() != pin.conversation_id.as_bytes()
        || stored_base != pin.base_event_seq
        || stored_expiry != pin.expires_at_ms
        || raw.3 != "active"
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    validate_pin_clock_lower_bound(now_ms, stored_expiry)?;
    if now_ms >= stored_expiry {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(())
}

pub(super) fn consume_snapshot_build_pin(
    connection: &Connection,
    pin: &RuntimeSnapshotBuildPin,
) -> Result<(), RuntimeStoreError> {
    if connection.execute(
        "DELETE FROM temp.active_stream_pins
         WHERE pin_id = ?1 AND scope = 'snapshot' AND target_id = ?2 AND state = 'active'",
        params![&pin.pin_id[..], &pin.conversation_id.as_bytes()[..]],
    )? != 1
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn load_event_backfill_page(
    state: &super::sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    requested_after: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeEventBackfillPage, RuntimeStoreError> {
    let plan = prepare_backfill_page(state, pin, requested_after, now_ms)?;
    let read_crypto = state.key_bundle.read_only_capability();
    let page = read_event_backfill_page(&state.connection, &read_crypto, state.database_id, &plan)?;
    finish_backfill_page(state, &plan, page.next_after, page.complete, now_ms)?;
    Ok(page)
}

pub(super) fn prepare_backfill_page(
    state: &super::sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    requested_after: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeBackfillReadPlan, RuntimeStoreError> {
    validate_active_pin(state, pin, requested_after, now_ms)?;
    let first = requested_after
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or(RuntimeStoreError::InvalidBackfillPin)?;
    Ok(RuntimeBackfillReadPlan {
        pin: pin.clone(),
        requested_after,
        first,
    })
}

pub(super) fn read_event_backfill_page(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    plan: &RuntimeBackfillReadPlan,
) -> Result<RuntimeEventBackfillPage, RuntimeStoreError> {
    debug_assert_eq!(MAX_RUNTIME_READ_PAGE_ROWS, 64);
    let RuntimeBackfillTarget::Conversation(conversation_id) = plan.pin.target else {
        return Err(RuntimeStoreError::InvalidBackfillPin);
    };
    let first = super::sequence::encode_sequence(plan.first);
    let through = super::sequence::encode_sequence(plan.pin.through);
    let mut compact = Vec::new();
    let mut total_bytes = 0_u64;
    let mut statement = connection.prepare(
        "SELECT event_seq, event_id, logical_event_bytes
         FROM event_stream_index
         WHERE conversation_id = ?1 AND event_seq BETWEEN ?2 AND ?3
         ORDER BY event_seq LIMIT 64",
    )?;
    let rows = statement.query_map(
        params![&conversation_id.as_bytes()[..], &first, &through],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    for row in rows {
        let row = row?;
        let logical_bytes =
            u64::try_from(row.2).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if logical_bytes > u64::from(MAX_RUNTIME_READ_PAGE_BYTES) {
            return Err(RuntimeStoreError::BackfillNeedSnapshot);
        }
        if !compact.is_empty()
            && total_bytes
                .checked_add(logical_bytes)
                .ok_or(RuntimeStoreError::PayloadTooLarge)?
                > u64::from(MAX_RUNTIME_READ_PAGE_BYTES)
        {
            break;
        }
        total_bytes = total_bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        compact.push((row.0, row.1));
    }
    drop(statement);
    if compact.is_empty() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut events = Vec::new();
    events
        .try_reserve_exact(compact.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut expected = decode_sequence(SequenceScope::EventSeq, &first)?;
    for (event_seq, event_id) in compact {
        let actual = decode_sequence(SequenceScope::EventSeq, &event_seq)?;
        if actual != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let event = super::journal::load_event_read(
            connection,
            read_crypto,
            database_id,
            runtime_event_id(&event_id)?,
        )?;
        let PersistedRuntimeEvent::Canonical(event) = decode_persisted_runtime_event(&event)?
        else {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        };
        events.push(*event);
        expected = expected
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    let next_after = expected
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let complete = next_after == plan.pin.through;
    Ok(RuntimeEventBackfillPage {
        events,
        next_after,
        through: plan.pin.through,
        complete,
        memory_lease: None,
    })
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) fn load_catalog_backfill_page(
    state: &super::sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    requested_after: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeCatalogBackfillPage, RuntimeStoreError> {
    let plan = prepare_backfill_page(state, pin, requested_after, now_ms)?;
    let read_crypto = state.key_bundle.read_only_capability();
    let page =
        read_catalog_backfill_page(&state.connection, &read_crypto, state.database_id, &plan)?;
    finish_backfill_page(state, &plan, page.next_after, page.complete, now_ms)?;
    Ok(page)
}

pub(super) fn read_catalog_backfill_page(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    plan: &RuntimeBackfillReadPlan,
) -> Result<RuntimeCatalogBackfillPage, RuntimeStoreError> {
    debug_assert_eq!(MAX_RUNTIME_READ_PAGE_ROWS, 64);
    if plan.pin.target != RuntimeBackfillTarget::Catalog {
        return Err(RuntimeStoreError::InvalidBackfillPin);
    }
    let first_value = plan.first;
    let first = super::sequence::encode_sequence(first_value);
    let through = super::sequence::encode_sequence(plan.pin.through);
    let mut revisions = Vec::new();
    let mut total_bytes = 0_u64;
    let mut statement = connection.prepare(
        "SELECT catalog_revision, logical_delta_bytes
         FROM catalog_journal
         WHERE catalog_revision BETWEEN ?1 AND ?2
         ORDER BY catalog_revision LIMIT 64",
    )?;
    let rows = statement.query_map(params![&first, &through], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (revision, logical_bytes) = row?;
        let logical_bytes =
            u64::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if logical_bytes > u64::from(MAX_RUNTIME_READ_PAGE_BYTES) {
            return Err(RuntimeStoreError::BackfillNeedSnapshot);
        }
        if !revisions.is_empty()
            && total_bytes
                .checked_add(logical_bytes)
                .ok_or(RuntimeStoreError::PayloadTooLarge)?
                > u64::from(MAX_RUNTIME_READ_PAGE_BYTES)
        {
            break;
        }
        total_bytes = total_bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        revisions.push(revision);
    }
    drop(statement);
    if revisions.is_empty() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut deltas = Vec::new();
    deltas
        .try_reserve_exact(revisions.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut expected = first_value;
    for revision in revisions {
        let actual = decode_sequence(SequenceScope::CatalogRevision, &revision)?;
        if actual != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        deltas.push(super::catalog::load_delta(
            connection,
            read_crypto,
            database_id,
            &revision,
        )?);
        expected = expected
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    let next_after = expected
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let complete = next_after == plan.pin.through;
    Ok(RuntimeCatalogBackfillPage {
        deltas,
        next_after,
        through: plan.pin.through,
        complete,
        memory_lease: None,
    })
}

pub(super) fn finish_backfill_page(
    state: &super::sqlite::RuntimeSqlite,
    plan: &RuntimeBackfillReadPlan,
    next_after: u64,
    complete: bool,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    // writer/GC 可在 read transaction 期间 revoke pin；必须在把 page 交给调用方前
    // 重新验证。revoked page 直接丢弃并要求 snapshot，绝不把过期 range 冒充 live。
    validate_active_pin(state, &plan.pin, plan.requested_after, now_ms)?;
    if next_after < plan.first || next_after > plan.pin.through {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if complete != (next_after == plan.pin.through) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    advance_or_release_pin(state, &plan.pin, next_after, complete)
}

pub(super) fn release_backfill_pin(
    state: &super::sqlite::RuntimeSqlite,
    pin_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    state.connection.execute(
        "DELETE FROM temp.active_stream_pins WHERE pin_id = ?1",
        [&pin_id[..]],
    )?;
    Ok(())
}

fn validate_active_pin(
    state: &super::sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    requested_after: Option<u64>,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let raw = state
        .connection
        .query_row(
            "SELECT scope, target_id, through_seq, next_after_seq, expires_at_ms, state
             FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin.pin_id[..]],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(RuntimeStoreError::InvalidBackfillPin)?;
    let expected_target: (&str, Option<[u8; 16]>) = match pin.target {
        RuntimeBackfillTarget::Catalog => ("catalog", None),
        RuntimeBackfillTarget::Conversation(conversation_id) => {
            ("event", Some(*conversation_id.as_bytes()))
        }
    };
    let stored_after = raw
        .3
        .as_deref()
        .map(|value| decode_sequence(sequence_scope(pin.target), value))
        .transpose()?;
    let stored_expiry =
        u64::try_from(raw.4).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if raw.5 == "revoked" {
        return Err(RuntimeStoreError::BackfillNeedSnapshot);
    }
    if raw.5 != "active"
        || raw.0 != expected_target.0
        || raw.1.as_deref() != expected_target.1.as_ref().map(<[u8; 16]>::as_slice)
        || decode_sequence(sequence_scope(pin.target), &raw.2)? != pin.through
        || stored_expiry != pin.expires_at_ms
        || requested_after != stored_after
    {
        return Err(RuntimeStoreError::InvalidBackfillPin);
    }
    validate_pin_clock_lower_bound(now_ms, stored_expiry)?;
    if now_ms >= stored_expiry {
        state.connection.execute(
            "DELETE FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin.pin_id[..]],
        )?;
        return Err(RuntimeStoreError::InvalidBackfillPin);
    }
    Ok(())
}

fn validate_pin_clock_lower_bound(
    now_ms: u64,
    expires_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let issued_at_ms = expires_at_ms
        .checked_sub(BACKFILL_PIN_TTL_MS)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if now_ms < issued_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: issued_at_ms,
            observed_ms: now_ms,
        });
    }
    Ok(())
}

fn advance_or_release_pin(
    state: &super::sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    next_after: u64,
    complete: bool,
) -> Result<(), RuntimeStoreError> {
    let changed = if complete {
        state.connection.execute(
            "DELETE FROM temp.active_stream_pins WHERE pin_id = ?1 AND state = 'active'",
            [&pin.pin_id[..]],
        )?
    } else {
        state.connection.execute(
            "UPDATE temp.active_stream_pins SET next_after_seq = ?1
             WHERE pin_id = ?2 AND state = 'active'",
            params![
                super::sequence::encode_sequence(next_after),
                &pin.pin_id[..]
            ],
        )?
    };
    if changed != 1 {
        return Err(RuntimeStoreError::InvalidBackfillPin);
    }
    Ok(())
}

const fn sequence_scope(target: RuntimeBackfillTarget) -> SequenceScope {
    match target {
        RuntimeBackfillTarget::Catalog => SequenceScope::CatalogRevision,
        RuntimeBackfillTarget::Conversation(_) => SequenceScope::EventSeq,
    }
}

fn trim_unrecorded_conversation_window(
    transaction: &Transaction<'_>,
    conversation_id: &[u8],
    respect_pins: bool,
    max_events: u64,
    max_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    loop {
        let (count, bytes): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
             FROM event_stream_index WHERE conversation_id = ?1",
            [conversation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let count = u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let bytes = u64::try_from(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if count <= max_events && bytes <= max_bytes {
            return Ok(());
        }
        let oldest: String = transaction.query_row(
            "SELECT MIN(event_seq) FROM event_stream_index
             WHERE conversation_id = ?1",
            [conversation_id],
            |row| row.get(0),
        )?;
        if respect_pins {
            revoke_stream_pins_covering(transaction, "event", Some(conversation_id), &oldest)?;
        }
        if transaction.execute(
            "DELETE FROM event_stream_index
             WHERE conversation_id = ?1 AND event_seq = ?2",
            params![conversation_id, oldest],
        )? != 1
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
}

/// open/recovery integrity scan：逐 conversation/row 流式认证 replay suffix；不解密或
/// 收集 audit payload。其它 v4 sealed tables由各自 loader逐行认证。
pub(super) fn validate_v4_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let table_exists: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'event_stream_index'
         )",
        [],
        |row| row.get(0),
    )?;
    if table_exists == 0 {
        return if ledger.audit_event_logical_bytes == 0
            && ledger.event_stream_count == 0
            && ledger.event_stream_bytes == 0
            && ledger.catalog_delta_count == 0
            && ledger.catalog_delta_bytes == 0
            && ledger.catalog_retention_floor.is_none()
            && ledger.snapshot_count == 0
            && ledger.snapshot_bytes == 0
            && ledger.publication_stream_count == 0
            && ledger.publication_outbox_count == 0
            && ledger.publication_outbox_bytes == 0
        {
            Ok(())
        } else {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        };
    }
    super::catalog::validate_integrity(connection, key_bundle, database_id, ledger)?;
    super::snapshot::validate_integrity(connection, key_bundle, database_id, ledger)?;
    super::publication::validate_integrity(connection, key_bundle, database_id, ledger)?;
    let mut total_stream_count = 0_u64;
    let mut total_stream_bytes = 0_u64;
    let mut conversation_statement = connection.prepare(
        "SELECT conversation_id, event_high_water
         FROM conversations ORDER BY conversation_id",
    )?;
    let conversations = conversation_statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    for conversation in conversations {
        let (conversation_id, event_high_water) = conversation?;
        let retention = connection
            .query_row(
                "SELECT oldest_retained_event_seq, indexed_through_event_seq,
                        retained_event_count, retained_logical_bytes, range_digest,
                        metadata_token
                 FROM event_retention WHERE conversation_id = ?1",
                [&conversation_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if retention.1 != event_high_water {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let retained_count =
            u64::try_from(retention.2).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let retained_bytes =
            u64::try_from(retention.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let expected_retention_token = event_retention_token(
            key_bundle,
            &conversation_id,
            event_high_water.as_deref(),
            retention.0.as_deref(),
            retained_count,
            retained_bytes,
            &fixed_digest(&retention.4)?,
        )?;
        let actual_range_digest = event_range_digest(connection, &conversation_id)?;
        if retention.4.as_slice() != actual_range_digest
            || retention.5.as_slice() != expected_retention_token
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }

        let mut actual_count = 0_u64;
        let mut actual_bytes = 0_u64;
        let mut first = None;
        let mut previous = None;
        let mut last = None;
        let mut statement = connection.prepare(
            "SELECT i.event_seq, i.event_id, i.logical_event_bytes,
                    i.created_at_ms, i.metadata_token,
                    e.logical_event_bytes, e.created_at_ms
             FROM event_stream_index i
             JOIN event_journal e
               ON e.conversation_id = i.conversation_id
              AND e.event_seq = i.event_seq
              AND e.event_id = i.event_id
             WHERE i.conversation_id = ?1
             ORDER BY i.event_seq",
        )?;
        let rows = statement.query_map([&conversation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        for row in rows {
            let row = row?;
            if row.2 != row.5 || row.3 != row.6 {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let seq = decode_sequence(SequenceScope::EventSeq, &row.0)?;
            if previous.is_some_and(|previous| seq != previous + 1) {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let logical_bytes =
                u64::try_from(row.2).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let created_at_ms =
                u64::try_from(row.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let expected = event_stream_index_token(
                key_bundle,
                &conversation_id,
                &row.0,
                &row.1,
                logical_bytes,
                created_at_ms,
            )?;
            if row.4.as_slice() != expected {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            first.get_or_insert_with(|| row.0.clone());
            previous = Some(seq);
            last = Some(row.0);
            actual_count = actual_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            actual_bytes = actual_bytes
                .checked_add(logical_bytes)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        if actual_count != retained_count
            || actual_bytes != retained_bytes
            || first != retention.0
            || (actual_count > 0 && last != event_high_water)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        total_stream_count = total_stream_count
            .checked_add(actual_count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        total_stream_bytes = total_stream_bytes
            .checked_add(actual_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    drop(conversation_statement);

    let (direct_stream_count, direct_stream_bytes, orphan_conversation_count, orphan_audit_count): (
        i64,
        i64,
        i64,
        i64,
    ) = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM event_stream_index),
             (SELECT COALESCE(SUM(logical_event_bytes), 0) FROM event_stream_index),
             (SELECT COUNT(*) FROM event_stream_index i
                LEFT JOIN conversations c ON c.conversation_id = i.conversation_id
                WHERE c.conversation_id IS NULL),
             (SELECT COUNT(*) FROM event_stream_index i
                LEFT JOIN event_journal e
                  ON e.conversation_id = i.conversation_id
                 AND e.event_seq = i.event_seq
                 AND e.event_id = i.event_id
                WHERE e.event_id IS NULL)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if u64::try_from(direct_stream_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != total_stream_count
        || u64::try_from(direct_stream_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            != total_stream_bytes
        || orphan_conversation_count != 0
        || orphan_audit_count != 0
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let (retention_count, orphan_count): (i64, i64) = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM event_retention),
             (SELECT COUNT(*) FROM event_retention r
                LEFT JOIN conversations c ON c.conversation_id = r.conversation_id
                WHERE c.conversation_id IS NULL)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if u64::try_from(retention_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != ledger.conversation_count
        || orphan_count != 0
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let audit_event_logical_bytes: i64 = connection.query_row(
        "SELECT COALESCE(SUM(logical_event_bytes), 0) FROM event_journal",
        [],
        |row| row.get(0),
    )?;
    if ledger.audit_event_logical_bytes
        != u64::try_from(audit_event_logical_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || ledger.event_stream_count != total_stream_count
        || ledger.event_stream_bytes != total_stream_bytes
        || total_stream_count > MAX_EVENT_STREAM_EVENTS_GLOBAL
        || total_stream_bytes > MAX_EVENT_STREAM_BYTES_GLOBAL
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let (
        catalog_count,
        catalog_bytes,
        snapshot_count,
        snapshot_bytes,
        stream_count,
        outbox_count,
        outbox_bytes,
    ): (i64, i64, i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM catalog_journal),
             (SELECT COALESCE(SUM(logical_delta_bytes), 0) FROM catalog_journal),
             (SELECT COUNT(*) FROM snapshots),
             (SELECT COALESCE(SUM(logical_snapshot_bytes), 0) FROM snapshots),
             (SELECT COUNT(*) FROM publication_streams),
             (SELECT COUNT(*) FROM publication_outbox),
             (SELECT COALESCE(SUM(logical_blob_bytes), 0) FROM publication_outbox)",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        },
    )?;
    for (actual, expected) in [
        (catalog_count, ledger.catalog_delta_count),
        (catalog_bytes, ledger.catalog_delta_bytes),
        (snapshot_count, ledger.snapshot_count),
        (snapshot_bytes, ledger.snapshot_bytes),
        (stream_count, ledger.publication_stream_count),
        (outbox_count, ledger.publication_outbox_count),
        (outbox_bytes, ledger.publication_outbox_bytes),
    ] {
        if u64::try_from(actual).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)? != expected
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Ok(())
}

fn trim_global_event_window(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    respect_pins: bool,
) -> Result<(), RuntimeStoreError> {
    loop {
        let (count, bytes): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
             FROM event_stream_index",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let count = u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let bytes = u64::try_from(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if count <= MAX_EVENT_STREAM_EVENTS_GLOBAL && bytes <= MAX_EVENT_STREAM_BYTES_GLOBAL {
            return Ok(());
        }
        let victim = transaction
            .query_row(
                "SELECT i.conversation_id, i.event_seq, i.logical_event_bytes
                 FROM event_stream_index i
                 JOIN event_retention r
                   ON r.conversation_id = i.conversation_id
                  AND r.oldest_retained_event_seq = i.event_seq
                 ORDER BY i.created_at_ms, i.conversation_id, i.event_seq
                 LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if respect_pins {
            revoke_stream_pins_covering(transaction, "event", Some(&victim.0), &victim.1)?;
        }
        transaction.execute(
            "DELETE FROM event_stream_index
             WHERE conversation_id = ?1 AND event_seq = ?2",
            params![&victim.0, &victim.1],
        )?;
        refresh_retention(transaction, key_bundle, &victim.0)?;
    }
}

/// active backfill pin 只存在于本进程 TEMP schema；daemon restart 后客户端必须
/// 重新建立 barrier。GC 遇到覆盖 victim 的 pin 时先原子标记 revoked 再继续
/// trim；后续 page 读取以 NeedSnapshot fail-closed，但 writer 不阻塞。
pub(super) fn initialize_ephemeral_state(connection: &Connection) -> Result<(), RuntimeStoreError> {
    connection.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS active_stream_pins (
             pin_id BLOB PRIMARY KEY CHECK(typeof(pin_id) = 'blob' AND length(pin_id) = 16),
         scope TEXT NOT NULL CHECK(scope IN ('catalog', 'event', 'snapshot')),
             target_id BLOB CHECK(target_id IS NULL OR
                 (typeof(target_id) = 'blob' AND length(target_id) = 16)),
             first_seq TEXT CHECK(first_seq IS NULL OR length(first_seq) = 20),
             through_seq TEXT CHECK(through_seq IS NULL OR length(through_seq) = 20),
             next_after_seq TEXT CHECK(next_after_seq IS NULL OR length(next_after_seq) = 20),
             expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
             state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active', 'revoked')),
             CHECK(first_seq IS NULL OR through_seq IS NULL OR first_seq <= through_seq),
             CHECK((scope = 'catalog' AND target_id IS NULL
                    AND first_seq IS NOT NULL AND through_seq IS NOT NULL) OR
                   (scope = 'event' AND target_id IS NOT NULL
                    AND first_seq IS NOT NULL AND through_seq IS NOT NULL) OR
                   (scope = 'snapshot' AND target_id IS NOT NULL
                    AND ((first_seq IS NULL AND through_seq IS NULL) OR
                         first_seq = through_seq)))
         ) STRICT;
         CREATE INDEX IF NOT EXISTS temp.idx_active_stream_pin_range
             ON active_stream_pins(scope, target_id, first_seq, through_seq);",
    )?;
    Ok(())
}

pub(super) fn revoke_stream_pins_covering(
    connection: &Connection,
    scope: &str,
    target_id: Option<&[u8]>,
    sequence: &str,
) -> Result<u64, RuntimeStoreError> {
    let changed = connection.execute(
        "UPDATE temp.active_stream_pins SET state = 'revoked'
         WHERE scope = ?1
           AND ((?2 IS NULL AND target_id IS NULL) OR target_id = ?2)
           AND state = 'active'
           AND first_seq <= ?3 AND through_seq >= ?3",
        params![scope, target_id, sequence],
    )?;
    u64::try_from(changed).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn revoke_all_stream_pins(
    connection: &Connection,
    scope: &str,
    target_id: Option<&[u8]>,
) -> Result<u64, RuntimeStoreError> {
    let changed = connection.execute(
        "UPDATE temp.active_stream_pins SET state = 'revoked'
         WHERE scope = ?1
           AND ((?2 IS NULL AND target_id IS NULL) OR target_id = ?2)
           AND state = 'active'",
        params![scope, target_id],
    )?;
    u64::try_from(changed).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn refresh_retention(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8],
) -> Result<(), RuntimeStoreError> {
    let event_high_water: Option<String> = transaction.query_row(
        "SELECT event_high_water FROM conversations WHERE conversation_id = ?1",
        [conversation_id],
        |row| row.get(0),
    )?;
    let (oldest, count, bytes): (Option<String>, i64, i64) = transaction.query_row(
        "SELECT MIN(event_seq), COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
         FROM event_stream_index WHERE conversation_id = ?1",
        [conversation_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    insert_or_replace_retention(
        transaction,
        key_bundle,
        conversation_id,
        event_high_water.as_deref(),
        oldest.as_deref(),
        u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        u64::try_from(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )
}

fn insert_or_replace_retention(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8],
    event_high_water: Option<&str>,
    oldest_retained_event_seq: Option<&str>,
    count: u64,
    bytes: u64,
) -> Result<(), RuntimeStoreError> {
    let range_digest = event_range_digest(transaction, conversation_id)?;
    let token = event_retention_token(
        key_bundle,
        conversation_id,
        event_high_water,
        oldest_retained_event_seq,
        count,
        bytes,
        &range_digest,
    )?;
    transaction.execute(
        "INSERT INTO event_retention (
             conversation_id, oldest_retained_event_seq, indexed_through_event_seq,
             retained_event_count, retained_logical_bytes, range_digest, metadata_token
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(conversation_id) DO UPDATE SET
             oldest_retained_event_seq = excluded.oldest_retained_event_seq,
             indexed_through_event_seq = excluded.indexed_through_event_seq,
             retained_event_count = excluded.retained_event_count,
             retained_logical_bytes = excluded.retained_logical_bytes,
             range_digest = excluded.range_digest,
             metadata_token = excluded.metadata_token",
        params![
            conversation_id,
            oldest_retained_event_seq,
            event_high_water,
            sqlite_u64(count)?,
            sqlite_u64(bytes)?,
            &range_digest[..],
            &token[..],
        ],
    )?;
    Ok(())
}

fn event_stream_index_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8],
    event_seq: &str,
    event_id: &[u8],
    logical_event_bytes: u64,
    created_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    metadata_mac(
        key_bundle,
        EVENT_STREAM_INDEX_TOKEN_DOMAIN,
        &[
            conversation_id,
            event_seq.as_bytes(),
            event_id,
            &logical_event_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
    )
}

fn event_retention_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8],
    event_high_water: Option<&str>,
    oldest_retained_event_seq: Option<&str>,
    count: u64,
    bytes: u64,
    range_digest: &[u8; 32],
) -> Result<[u8; 32], RuntimeStoreError> {
    let event_high_water = optional_field(event_high_water.map(str::as_bytes));
    let oldest = optional_field(oldest_retained_event_seq.map(str::as_bytes));
    metadata_mac(
        key_bundle,
        EVENT_RETENTION_TOKEN_DOMAIN,
        &[
            conversation_id,
            &event_high_water,
            &oldest,
            &count.to_be_bytes(),
            &bytes.to_be_bytes(),
            range_digest,
        ],
    )
}

fn event_range_digest(
    connection: &Connection,
    conversation_id: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut digest = Sha256::new();
    digest.update(b"agentdeck.event-retention.range.v1");
    let mut statement = connection.prepare(
        "SELECT event_seq, event_id, logical_event_bytes, created_at_ms, metadata_token
         FROM event_stream_index WHERE conversation_id = ?1 ORDER BY event_seq",
    )?;
    let rows = statement.query_map([conversation_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    for row in rows {
        let (event_seq, event_id, logical_bytes, created_at_ms, token) = row?;
        for field in [
            event_seq.as_bytes(),
            event_id.as_slice(),
            &logical_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
            token.as_slice(),
        ] {
            let length = u32::try_from(field.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            digest.update(length.to_be_bytes());
            digest.update(field);
        }
    }
    Ok(digest.finalize().into())
}

fn fixed_digest(value: &[u8]) -> Result<[u8; 32], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn metadata_mac(
    key_bundle: &RuntimeKeyBundle,
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.extend_from_slice(b"ADF1");
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        encoded.extend_from_slice(&len.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    let token = key_bundle.blind_index(domain, encoded.as_ref())?;
    Ok(*token.as_bytes())
}

pub(super) fn verify_metadata_mac(
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    domain: &[u8],
    fields: &[&[u8]],
    expected: &[u8],
) -> Result<bool, RuntimeStoreError> {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.extend_from_slice(b"ADF1");
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        encoded.extend_from_slice(&len.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    Ok(read_crypto.verify_blind_index(domain, encoded.as_ref(), expected)?)
}

pub(super) fn optional_field(value: Option<&[u8]>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(1 + value.map_or(0, <[u8]>::len));
    match value {
        None => encoded.push(0),
        Some(value) => {
            encoded.push(1);
            encoded.extend_from_slice(value);
        }
    }
    encoded
}

pub(super) fn sqlite_u64(value: u64) -> Result<i64, RuntimeStoreError> {
    i64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn runtime_event_id(bytes: &[u8]) -> Result<super::RuntimeId, RuntimeStoreError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(super::RuntimeId::from_bytes(
        super::RuntimeIdKind::Event,
        bytes,
    )?)
}

#[allow(dead_code)]
fn validate_sequence(value: &str, scope: SequenceScope) -> Result<u64, RuntimeStoreError> {
    Ok(decode_sequence(scope, value)?)
}

pub(super) fn seal_v4_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8],
    column: &[u8],
    plaintext: &[u8],
    maximum_plaintext_len: usize,
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        plaintext,
        maximum_plaintext_len,
    )?)
}

pub(super) fn open_v4_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8],
    column: &[u8],
    ciphertext: &[u8],
    maximum_plaintext_len: usize,
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        ciphertext,
        maximum_plaintext_len,
    )?)
}

pub(super) fn open_v4_row_read(
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8],
    column: &[u8],
    ciphertext: &[u8],
    maximum_plaintext_len: usize,
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(read_crypto.open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        ciphertext,
        maximum_plaintext_len,
    )?)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use agentdeck_protocol::AgentKind;
    use agentdeck_protocol::runtime::event::RuntimeEventBody;
    use agentdeck_protocol::runtime::identity::{ConversationId, EventId};
    use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeFailure};
    use rusqlite::{Connection, TransactionBehavior, params};

    use super::*;
    use crate::runtime::model::{
        ConversationDescriptor, MAX_CONVERSATION_DESCRIPTOR_BYTES, MAX_RUNTIME_EVENT_BYTES,
    };
    use crate::runtime::store::schema::{
        RUNTIME_DDL_V1, RUNTIME_MIGRATION_V2, RUNTIME_MIGRATION_V3, RUNTIME_MIGRATION_V4,
    };
    use crate::runtime::store::sequence::encode_sequence;

    fn fixture() -> (
        Connection,
        RuntimeKeyBundle,
        [u8; 16],
        super::super::RuntimeId,
    ) {
        let connection = Connection::open_in_memory().expect("open fixture");
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable FKs");
        connection.execute_batch(RUNTIME_DDL_V1).expect("v1 DDL");
        connection
            .execute_batch(RUNTIME_MIGRATION_V2)
            .expect("v2 DDL");
        connection
            .execute_batch(RUNTIME_MIGRATION_V3)
            .expect("v3 DDL");
        connection
            .execute_batch(RUNTIME_MIGRATION_V4)
            .expect("v4 DDL");
        initialize_ephemeral_state(&connection).expect("TEMP pins");
        let key_bundle = RuntimeKeyBundle::fresh(1).expect("row keys");
        let database_id = [0x91; 16];
        let conversation_id = super::super::RuntimeId::from_bytes(
            super::super::RuntimeIdKind::Conversation,
            [0x11; 16],
        )
        .expect("conversation id");
        let adapter_state_key = super::super::RuntimeId::from_bytes(
            super::super::RuntimeIdKind::AdapterState,
            [0x22; 16],
        )
        .expect("adapter state key");
        let descriptor = ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some("stream fixture".into()),
            cwd: PathBuf::from("/tmp/stream-fixture"),
        };
        let descriptor_bytes =
            super::super::journal::canonical_conversation_descriptor(&descriptor)
                .expect("canonical descriptor");
        let catalog_revision = encode_sequence(0);
        let metadata_token = super::super::journal::conversation_metadata_token_for_test(
            &key_bundle,
            conversation_id,
            adapter_state_key,
            0,
            None,
            None,
            0,
            crate::runtime::model::ConversationLifecycle::Active,
            1,
            1,
        )
        .expect("conversation metadata token");
        let sealed_descriptor = seal_v4_row(
            &key_bundle,
            database_id,
            b"conversations",
            conversation_id.as_bytes(),
            b"sealed_descriptor",
            &descriptor_bytes,
            MAX_CONVERSATION_DESCRIPTOR_BYTES,
        )
        .expect("sealed conversation descriptor");
        connection
            .execute(
                "INSERT INTO conversations (
                     conversation_id, adapter_state_key, catalog_revision,
                     command_high_water, event_high_water, lifecycle,
                     created_at_ms, updated_at_ms, accepted_count,
                     metadata_token, sealed_descriptor
                 ) VALUES (?1, ?2, ?3, NULL, NULL, 'active', 1, 1, 0, ?4, ?5)",
                params![
                    &conversation_id.as_bytes()[..],
                    &adapter_state_key.as_bytes()[..],
                    &catalog_revision,
                    &metadata_token[..],
                    sealed_descriptor,
                ],
            )
            .expect("conversation row");
        super::super::journal::load_conversation(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
        )
        .expect("fixture conversation must satisfy the production authenticated decoder");
        {
            let transaction = connection
                .unchecked_transaction()
                .expect("retention transaction");
            insert_or_replace_retention(
                &transaction,
                &key_bundle,
                conversation_id.as_bytes(),
                None,
                None,
                0,
                0,
            )
            .expect("empty retention row");
            transaction.commit().expect("commit retention row");
        }
        (connection, key_bundle, database_id, conversation_id)
    }

    fn canonical_event(
        conversation_id: super::super::RuntimeId,
        event_id: super::super::RuntimeId,
        event_seq: u64,
    ) -> Vec<u8> {
        let event = RuntimeEvent::new(
            ConversationId::new(conversation_id.to_canonical_string()),
            EventId::new(event_id.to_canonical_string()),
            event_seq,
            None,
            None,
            None,
            RuntimeEventBody::Error {
                failure: RuntimeFailure::new("daemon.test", "fixture"),
            },
        )
        .expect("canonical event");
        serde_json::to_vec(&event).expect("encode canonical event")
    }

    fn legacy_event(
        conversation_id: super::super::RuntimeId,
        event_id: super::super::RuntimeId,
        event_seq: u64,
    ) -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&canonical_event(conversation_id, event_id, event_seq))
                .expect("event value");
        let object = value.as_object_mut().expect("event object");
        object.remove("commandId");
        object.remove("itemId");
        object.remove("entityId");
        serde_json::to_vec(&value).expect("legacy bytes")
    }

    fn insert_audit_event(
        connection: &Connection,
        key_bundle: &RuntimeKeyBundle,
        database_id: [u8; 16],
        conversation_id: super::super::RuntimeId,
        event_seq: u64,
        payload: &[u8],
    ) -> super::super::RuntimeId {
        let mut id = [0x60; 16];
        id[15] = u8::try_from(event_seq + 1).expect("small event seq");
        let event_id = super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
            .expect("event id");
        let event_seq_encoded = encode_sequence(event_seq);
        let logical_bytes = u64::try_from(payload.len()).expect("payload length");
        let created_at_ms = 10 + event_seq;
        let sealed = seal_v4_row(
            key_bundle,
            database_id,
            b"event_journal",
            event_id.as_bytes(),
            b"sealed_event",
            payload,
            MAX_RUNTIME_EVENT_BYTES,
        )
        .expect("seal audit event");
        let command = optional_field(None);
        let token = metadata_mac(
            key_bundle,
            b"event.metadata.v1",
            &[
                conversation_id.as_bytes(),
                event_id.as_bytes(),
                event_seq_encoded.as_bytes(),
                &command,
                &logical_bytes.to_be_bytes(),
                &created_at_ms.to_be_bytes(),
            ],
        )
        .expect("audit event token");
        connection
            .execute(
                "INSERT INTO event_journal (
                     conversation_id, event_seq, event_id, command_id,
                     logical_event_bytes, created_at_ms, metadata_token, sealed_event
                 ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7)",
                params![
                    &conversation_id.as_bytes()[..],
                    &event_seq_encoded,
                    &event_id.as_bytes()[..],
                    sqlite_u64(logical_bytes).expect("logical bytes"),
                    sqlite_u64(created_at_ms).expect("created time"),
                    &token[..],
                    sealed,
                ],
            )
            .expect("audit event row");
        let adapter_state_key = super::super::RuntimeId::from_bytes(
            super::super::RuntimeIdKind::AdapterState,
            [0x22; 16],
        )
        .expect("adapter state key");
        let conversation_token = super::super::journal::conversation_metadata_token_for_test(
            key_bundle,
            conversation_id,
            adapter_state_key,
            0,
            None,
            Some(event_seq),
            0,
            crate::runtime::model::ConversationLifecycle::Active,
            1,
            1,
        )
        .expect("conversation metadata token");
        connection
            .execute(
                "UPDATE conversations
                 SET event_high_water = ?1, metadata_token = ?2
                 WHERE conversation_id = ?3",
                params![
                    &event_seq_encoded,
                    &conversation_token[..],
                    &conversation_id.as_bytes()[..],
                ],
            )
            .expect("advance audit HWM");
        event_id
    }

    fn sealed_audit_bytes(connection: &Connection) -> Vec<Vec<u8>> {
        connection
            .prepare("SELECT sealed_event FROM event_journal ORDER BY event_seq")
            .expect("prepare audit evidence")
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query audit evidence")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect audit evidence")
    }

    #[test]
    fn migration_indexes_only_maximum_publishable_suffix_across_legacy_and_fixed_rows() {
        let (mut connection, key_bundle, database_id, conversation_id) = fixture();
        let id0 = {
            let mut id = [0x60; 16];
            id[15] = 1;
            super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
                .expect("legacy id shape")
        };
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            0,
            &legacy_event(conversation_id, id0, 0),
        );
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            1,
            b"opaque-fixed-event",
        );
        let id2 = super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, {
            let mut id = [0x60; 16];
            id[15] = 3;
            id
        })
        .expect("canonical id shape");
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            2,
            &canonical_event(conversation_id, id2, 2),
        );
        let before = sealed_audit_bytes(&connection);
        let current = RuntimeLedger {
            catalog_high_water: Some(encode_sequence(0)),
            conversation_count: 1,
            event_count: 3,
            ..RuntimeLedger::default()
        };
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("migration transaction");
        let migrated = migrate_v4_rows(&transaction, &key_bundle, database_id, &current)
            .expect("migrate v4 rows");
        transaction.commit().expect("commit migration fixture");
        let indexed: Vec<String> = connection
            .prepare("SELECT event_seq FROM event_stream_index ORDER BY event_seq")
            .expect("prepare index")
            .query_map([], |row| row.get(0))
            .expect("query index")
            .collect::<Result<_, _>>()
            .expect("collect index");
        assert_eq!(indexed, [encode_sequence(2)]);
        assert_eq!(migrated.event_stream_count, 1);
        assert_eq!(sealed_audit_bytes(&connection), before);
    }

    #[test]
    fn opaque_last_event_migrates_to_empty_suffix_without_rewriting_audit() {
        let (mut connection, key_bundle, database_id, conversation_id) = fixture();
        let id0 = {
            let mut id = [0x60; 16];
            id[15] = 1;
            super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
                .expect("event id")
        };
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            0,
            &canonical_event(conversation_id, id0, 0),
        );
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            1,
            b"opaque-last",
        );
        let before = sealed_audit_bytes(&connection);
        let current = RuntimeLedger {
            catalog_high_water: Some(encode_sequence(0)),
            conversation_count: 1,
            event_count: 2,
            ..RuntimeLedger::default()
        };
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("migration transaction");
        let migrated = migrate_v4_rows(&transaction, &key_bundle, database_id, &current)
            .expect("migrate v4 rows");
        transaction.commit().expect("commit migration fixture");
        assert_eq!(migrated.event_stream_count, 0);
        assert_eq!(sealed_audit_bytes(&connection), before);
    }

    #[test]
    fn canonical_event_after_opaque_break_starts_a_new_contiguous_suffix() {
        let (mut connection, key_bundle, database_id, conversation_id) = fixture();
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            0,
            b"opaque-zero",
        );
        let requested = RuntimeLedger {
            catalog_high_water: Some(encode_sequence(0)),
            conversation_count: 1,
            event_count: 1,
            ..RuntimeLedger::default()
        };
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("first writer transaction");
        let first = reconcile_event_stream(
            &transaction,
            &key_bundle,
            database_id,
            &RuntimeLedger::default(),
            &requested,
        )
        .expect("reconcile opaque row");
        transaction.commit().expect("commit opaque row");
        assert_eq!(first.event_stream_count, 0);

        let id1 = {
            let mut id = [0x60; 16];
            id[15] = 2;
            super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
                .expect("event id")
        };
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            1,
            &canonical_event(conversation_id, id1, 1),
        );
        let mut requested = first.clone();
        requested.event_count = 2;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("second writer transaction");
        let second =
            reconcile_event_stream(&transaction, &key_bundle, database_id, &first, &requested)
                .expect("reconcile canonical suffix");
        transaction.commit().expect("commit canonical suffix");
        assert_eq!(second.event_stream_count, 1);
        let only: String = connection
            .query_row("SELECT event_seq FROM event_stream_index", [], |row| {
                row.get(0)
            })
            .expect("new suffix row");
        assert_eq!(only, encode_sequence(1));

        let state = super::super::sqlite::RuntimeSqlite {
            connection,
            key_bundle: std::sync::Arc::new(key_bundle),
            storage_path: PathBuf::from("/tmp/stream-unit-fixture.db"),
            database_id,
            admission_state: super::super::admission::RuntimeAdmissionState::Normal,
            recovery_scan: None,
            last_finished_recovery: None,
        };
        assert!(matches!(
            acquire_backfill_pin(
                &state,
                RuntimeBackfillTarget::Conversation(conversation_id),
                None,
                100,
            ),
            Err(RuntimeStoreError::BackfillNeedSnapshot)
        ));
        let RuntimeBackfillPlan::Pinned(pin) = acquire_backfill_pin(
            &state,
            RuntimeBackfillTarget::Conversation(conversation_id),
            Some(0),
            100,
        )
        .expect("pin suffix after opaque boundary") else {
            panic!("event one is a non-empty retained suffix");
        };
        let page = load_event_backfill_page(&state, &pin, Some(0), 100)
            .expect("load retained canonical suffix");
        assert!(page.complete);
        assert_eq!(page.next_after, 1);
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event_seq, 1);
    }

    #[test]
    fn pinned_reader_is_revoked_before_writer_trim_commits() {
        let (mut connection, key_bundle, database_id, conversation_id) = fixture();
        let mut ledger = RuntimeLedger {
            catalog_high_water: Some(encode_sequence(0)),
            conversation_count: 1,
            ..RuntimeLedger::default()
        };
        for seq in 0..2 {
            let event_id = {
                let mut id = [0x60; 16];
                id[15] = u8::try_from(seq + 1).expect("small seq");
                super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
                    .expect("event id")
            };
            insert_audit_event(
                &connection,
                &key_bundle,
                database_id,
                conversation_id,
                seq,
                &canonical_event(conversation_id, event_id, seq),
            );
            let mut requested = ledger.clone();
            requested.event_count += 1;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("append transaction");
            ledger =
                reconcile_event_stream(&transaction, &key_bundle, database_id, &ledger, &requested)
                    .expect("reconcile canonical event");
            transaction.commit().expect("commit canonical event");
        }
        let pin_id = [0x77; 16];
        connection
            .execute(
                "INSERT INTO temp.active_stream_pins (
                     pin_id, scope, target_id, first_seq, through_seq,
                     next_after_seq, expires_at_ms, state
                 ) VALUES (?1, 'event', ?2, ?3, ?4, NULL, 999999, 'active')",
                params![
                    &pin_id[..],
                    &conversation_id.as_bytes()[..],
                    encode_sequence(0),
                    encode_sequence(1),
                ],
            )
            .expect("active reader pin");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("writer trim transaction");
        trim_unrecorded_conversation_window(
            &transaction,
            conversation_id.as_bytes(),
            true,
            1,
            MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
        )
        .expect("writer revokes reader and trims");
        refresh_retention(&transaction, &key_bundle, conversation_id.as_bytes())
            .expect("refresh retention");
        transaction.commit().expect("writer commit is not blocked");
        let state: String = connection
            .query_row(
                "SELECT state FROM temp.active_stream_pins WHERE pin_id = ?1",
                [&pin_id[..]],
                |row| row.get(0),
            )
            .expect("revoked pin tombstone");
        assert_eq!(state, "revoked");
        let retained: Vec<String> = connection
            .prepare("SELECT event_seq FROM event_stream_index ORDER BY event_seq")
            .expect("prepare retained rows")
            .query_map([], |row| row.get(0))
            .expect("query retained rows")
            .collect::<Result<_, _>>()
            .expect("collect retained rows");
        assert_eq!(retained, [encode_sequence(1)]);
    }

    #[test]
    fn event_stream_index_token_tamper_is_rejected_by_v4_integrity_scan() {
        let (mut connection, key_bundle, database_id, conversation_id) = fixture();
        let event_id = {
            let mut id = [0x60; 16];
            id[15] = 1;
            super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
                .expect("event id")
        };
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            0,
            &canonical_event(conversation_id, event_id, 0),
        );
        let current = RuntimeLedger {
            catalog_high_water: Some(encode_sequence(0)),
            conversation_count: 1,
            event_count: 1,
            ..RuntimeLedger::default()
        };
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("migration transaction");
        let migrated = migrate_v4_rows(&transaction, &key_bundle, database_id, &current)
            .expect("migrate event index");
        transaction.commit().expect("commit event index");
        connection
            .execute(
                "UPDATE event_stream_index SET metadata_token = zeroblob(32)",
                [],
            )
            .expect("tamper index token");
        assert!(matches!(
            validate_v4_integrity(&connection, &key_bundle, database_id, &migrated),
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));
    }

    #[test]
    fn every_v4_ledger_count_bytes_and_floor_is_recomputed() {
        let (mut connection, key_bundle, database_id, conversation_id) = fixture();
        let event_id = {
            let mut id = [0x60; 16];
            id[15] = 1;
            super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
                .expect("event id")
        };
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            0,
            &canonical_event(conversation_id, event_id, 0),
        );
        let current = RuntimeLedger {
            catalog_high_water: Some(encode_sequence(0)),
            conversation_count: 1,
            event_count: 1,
            ..RuntimeLedger::default()
        };
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("migration transaction");
        let ledger = migrate_v4_rows(&transaction, &key_bundle, database_id, &current)
            .expect("migrate v4 ledger");
        transaction.commit().expect("commit v4 ledger");
        assert_eq!(
            ledger.catalog_retention_floor, None,
            "legacy catalog state is represented by the ready baseline snapshot, not a retained delta"
        );
        validate_v4_integrity(&connection, &key_bundle, database_id, &ledger)
            .expect("baseline ledger is coherent");

        let mut corruptions = Vec::new();
        let mut corrupted = ledger.clone();
        corrupted.audit_event_logical_bytes += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.event_stream_count += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.event_stream_bytes += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.catalog_delta_count += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.catalog_delta_bytes += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.catalog_retention_floor = Some(encode_sequence(0));
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.snapshot_count += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.snapshot_bytes += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.publication_stream_count += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.publication_outbox_count += 1;
        corruptions.push(corrupted);
        let mut corrupted = ledger.clone();
        corrupted.publication_outbox_bytes += 1;
        corruptions.push(corrupted);

        for corrupted in corruptions {
            assert!(matches!(
                validate_v4_integrity(&connection, &key_bundle, database_id, &corrupted),
                Err(RuntimeStoreError::UnknownOrCorruptSchema)
            ));
        }
    }
}
