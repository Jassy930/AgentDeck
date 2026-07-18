//! Runtime v4 canonical replay window、snapshot 与 publication store。
//!
//! `event_journal` 仍是 P3.2/P3.5 authenticated audit；本模块只裁剪
//! `event_stream_index` membership，绝不删除或改写 audit ciphertext。

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::runtime::events::{PendingStreamTargets, RuntimeStreamTarget};
use crate::runtime::model::{MAX_RUNTIME_PHYSICAL_CONVERSATIONS, RuntimeStoreError};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedTargetCut {
    pub high_water: agentdeck_protocol::runtime::StreamCursor,
    pub retained_floor: Option<u64>,
}

/// StoreCommitHub 在唯一 worker 上使用的短 authenticated readback。
pub(super) fn load_authenticated_target_cut(
    state: &super::sqlite::RuntimeSqlite,
    target: crate::runtime::events::RuntimeStreamTarget,
) -> Result<AuthenticatedTargetCut, RuntimeStoreError> {
    let ledger = super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )?;
    load_authenticated_target_cut_in(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &ledger,
        target,
    )
}

/// Barrier capture 在调用方持有的同一个 Deferred transaction/ledger cut 内读取。
pub(super) fn load_authenticated_target_cut_in(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    target: crate::runtime::events::RuntimeStreamTarget,
) -> Result<AuthenticatedTargetCut, RuntimeStoreError> {
    match target {
        crate::runtime::events::RuntimeStreamTarget::Catalog => {
            let high_water = ledger
                .catalog_high_water
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
                .transpose()?;
            let retained_floor = ledger
                .catalog_retention_floor
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
                .transpose()?;
            Ok(AuthenticatedTargetCut {
                high_water: agentdeck_protocol::runtime::StreamCursor::from_high_water(high_water),
                retained_floor,
            })
        }
        crate::runtime::events::RuntimeStreamTarget::Conversation(conversation_id) => {
            let conversation = super::journal::load_conversation(
                connection,
                key_bundle,
                database_id,
                conversation_id,
            )?;
            let retention = connection.query_row(
                "SELECT oldest_retained_event_seq, indexed_through_event_seq,
                        retained_event_count, retained_logical_bytes, range_digest,
                        metadata_token
                 FROM event_retention WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
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
            )?;
            let indexed_through = retention
                .1
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::EventSeq, value))
                .transpose()?;
            if indexed_through != conversation.event_high_water {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let retained_count = u64::try_from(retention.2)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let retained_bytes = u64::try_from(retention.3)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let range_digest = fixed_digest(&retention.4)?;
            let expected = event_retention_token(
                key_bundle,
                conversation_id.as_bytes(),
                retention.1.as_deref(),
                retention.0.as_deref(),
                retained_count,
                retained_bytes,
                &range_digest,
            )?;
            if retention.5.as_slice() != expected {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let retained_floor = retention
                .0
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::EventSeq, value))
                .transpose()?;
            Ok(AuthenticatedTargetCut {
                high_water: agentdeck_protocol::runtime::StreamCursor::from_high_water(
                    conversation.event_high_water,
                ),
                retained_floor,
            })
        }
    }
}

impl RuntimeSnapshotBuildPin {
    pub(super) const fn pin_id(&self) -> [u8; 16] {
        self.pin_id
    }

    #[cfg(test)]
    #[cfg(test)]
    pub(super) const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    #[must_use]
    pub const fn conversation_id(&self) -> super::RuntimeId {
        self.conversation_id
    }

    #[must_use]
    pub const fn base_event_seq(&self) -> Option<u64> {
        self.base_event_seq
    }

    /// Snapshot materializer 的 crate-private exact binding identity。不会暴露到
    /// integration/public API；只用于防止同 conversation/base 的另一枚 pin 错绑。
    pub(crate) const fn build_binding_id(&self) -> [u8; 16] {
        self.pin_id
    }
}

mod page;

#[allow(unused_imports)]
pub(super) use page::RuntimeSnapshotEventPage;
pub use page::{
    RuntimeBackfillPageCompletion, RuntimeCatalogBackfillPage, RuntimeEventBackfillPage,
};
pub(super) use page::{
    RuntimeBackfillReadPlan, complete_backfill_page, prepare_backfill_page,
    read_catalog_backfill_page, read_event_backfill_page, read_oversized_event_backfill_page,
    read_oversized_snapshot_event_page, read_snapshot_event_page, release_backfill_pin,
    validate_backfill_page,
};
#[cfg(test)]
pub(super) use page::{load_catalog_backfill_page, load_event_backfill_page};

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
        trim_global_event_window(transaction, key_bundle, false, 0)?;
    }
    drop(conversation_statement);

    // 保留终态校验式 trim，便于未来调整批次时仍不依赖循环细节。
    trim_global_event_window(transaction, key_bundle, false, 0)?;
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
#[cfg(test)]
pub(super) fn reconcile_event_stream(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &RuntimeLedger,
    requested_next: &RuntimeLedger,
) -> Result<(RuntimeLedger, PendingStreamTargets), RuntimeStoreError> {
    reconcile_event_stream_with_trim_clock(
        transaction,
        key_bundle,
        database_id,
        previous,
        requested_next,
        None,
    )
}

pub(super) fn reconcile_event_stream_with_trim_clock(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &RuntimeLedger,
    requested_next: &RuntimeLedger,
    trim_now_ms: Option<u64>,
) -> Result<(RuntimeLedger, PendingStreamTargets), RuntimeStoreError> {
    let mut next = requested_next.clone();
    let mut pending_targets = PendingStreamTargets::default();
    let event_delta = requested_next
        .event_count
        .checked_sub(previous.event_count)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;

    // 新建 conversation 即建立零窗口 retention row；v6 的 compact ids 上界包含
    // native tombstone/retired physical identities。
    let conversation_candidate_limit = usize::try_from(MAX_RUNTIME_PHYSICAL_CONVERSATIONS)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
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
        if missing_retention.len() > conversation_candidate_limit {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);
    for (conversation_id, _high_water) in missing_retention {
        insert_or_replace_retention(transaction, key_bundle, &conversation_id, None, None, 0, 0)?;
    }

    if event_delta == 0 {
        return Ok((next, pending_targets));
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
        if changed.len() > conversation_candidate_limit {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);

    let mut processed_delta = 0_u64;
    let mut audit_bytes_delta = 0_u64;
    let mut global_trim_now_ms = 0_u64;
    for (conversation_id, high_water, indexed_through) in changed {
        let mut conversation_trim_now_ms = 0_u64;
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
            conversation_trim_now_ms = conversation_trim_now_ms.max(created_at_ms);
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
            key_bundle,
            &conversation_id,
            true,
            effective_trim_now_ms(conversation_trim_now_ms, trim_now_ms),
            MAX_EVENT_STREAM_EVENTS_PER_CONVERSATION,
            MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
        )?;
        refresh_retention(transaction, key_bundle, &conversation_id)?;
        global_trim_now_ms = global_trim_now_ms.max(conversation_trim_now_ms);
        let conversation_id = super::RuntimeId::from_bytes(
            super::RuntimeIdKind::Conversation,
            conversation_id
                .as_slice()
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        pending_targets.insert(RuntimeStreamTarget::Conversation(conversation_id));
    }
    if processed_delta != event_delta {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    trim_global_event_window(
        transaction,
        key_bundle,
        true,
        effective_trim_now_ms(global_trim_now_ms, trim_now_ms),
    )?;
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
    Ok((next, pending_targets))
}

fn effective_trim_now_ms(event_created_at_ms: u64, trim_now_ms: Option<u64>) -> u64 {
    trim_now_ms.unwrap_or(event_created_at_ms)
}

pub(super) fn acquire_backfill_pin(
    state: &super::sqlite::RuntimeSqlite,
    target: RuntimeBackfillTarget,
    after: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeBackfillPlan, RuntimeStoreError> {
    acquire_backfill_pin_through(state, target, after, None, now_ms)
}

/// StoreCommitHub barrier capture 在同一个 worker command 内固定 exact through，
/// 防止 capture 后的新 COMMIT 被误并入旧 generation 的 snapshot/backfill。
pub(super) fn acquire_backfill_pin_at(
    state: &super::sqlite::RuntimeSqlite,
    target: RuntimeBackfillTarget,
    after: Option<u64>,
    through: u64,
    now_ms: u64,
) -> Result<RuntimeBackfillPlan, RuntimeStoreError> {
    acquire_backfill_pin_through(state, target, after, Some(through), now_ms)
}

fn acquire_backfill_pin_through(
    state: &super::sqlite::RuntimeSqlite,
    target: RuntimeBackfillTarget,
    after: Option<u64>,
    exact_through: Option<u64>,
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
    let Some(current_high_water) = high_water else {
        return if after.is_none() {
            Ok(RuntimeBackfillPlan::Current { high_water: None })
        } else {
            Err(RuntimeStoreError::BackfillCursorAhead)
        };
    };
    let through = exact_through.unwrap_or(current_high_water);
    if through > current_high_water {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
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

#[cfg(test)]
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
    acquire_snapshot_build_pin_at(&state.connection, conversation_id, base_event_seq, now_ms)
}

/// 使用调用方已认证的 explicit H 创建 snapshot TEMP pin；本函数绝不重读
/// conversation 当前 high-water。StoreCommitHub barrier capture 与普通 acquire
/// 共用同一插入/配额实现，但只有后者会在调用前读取最新 H。
pub(super) fn acquire_snapshot_build_pin_at(
    connection: &Connection,
    conversation_id: super::RuntimeId,
    base_event_seq: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeSnapshotBuildPin, RuntimeStoreError> {
    if conversation_id.kind() != super::RuntimeIdKind::Conversation {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: super::RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        });
    }
    connection.execute(
        "DELETE FROM temp.active_stream_pins WHERE expires_at_ms <= ?1",
        [sqlite_u64(now_ms)?],
    )?;
    let base_encoded = base_event_seq.map(super::sequence::encode_sequence);
    let expires_at_ms = now_ms
        .checked_add(BACKFILL_PIN_TTL_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let active_pin_count: i64 = connection.query_row(
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
        let inserted = connection.execute(
            "INSERT OR IGNORE INTO temp.active_stream_pins (
                 pin_id, scope, target_id, first_seq, through_seq, next_after_seq,
                 expires_at_ms, state
             ) VALUES (?1, 'snapshot', ?2, ?3, ?4, NULL, ?5, 'active')",
            params![
                &pin_id[..],
                &conversation_id.as_bytes()[..],
                base_encoded.as_deref(),
                base_encoded.as_deref(),
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

#[cfg(test)]
pub(super) fn active_snapshot_build_pin_count(
    state: &super::sqlite::RuntimeSqlite,
) -> Result<u64, RuntimeStoreError> {
    let count: i64 = state.connection.query_row(
        "SELECT COUNT(*) FROM temp.active_stream_pins
         WHERE scope = 'snapshot' AND state = 'active'",
        [],
        |row| row.get(0),
    )?;
    u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
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
        if connection.execute(
            "DELETE FROM temp.active_stream_pins
             WHERE pin_id = ?1 AND scope = 'snapshot' AND target_id = ?2
               AND expires_at_ms = ?3 AND state = 'active'",
            params![
                &pin.pin_id[..],
                &pin.conversation_id.as_bytes()[..],
                sqlite_u64(stored_expiry)?,
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
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

fn trim_unrecorded_conversation_window(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8],
    respect_pins: bool,
    now_ms: u64,
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
            super::retention::authorize_trim(
                transaction,
                key_bundle,
                super::retention::RetentionTarget::Conversation(conversation_id),
                &oldest,
                now_ms,
            )?;
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
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    trim_global_event_window_with_limits(
        transaction,
        key_bundle,
        respect_pins,
        now_ms,
        MAX_EVENT_STREAM_EVENTS_GLOBAL,
        MAX_EVENT_STREAM_BYTES_GLOBAL,
    )
}

fn trim_global_event_window_with_limits(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    respect_pins: bool,
    now_ms: u64,
    max_events: u64,
    max_bytes: u64,
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
        if count <= max_events && bytes <= max_bytes {
            return Ok(());
        }
        // 最多每个 conversation 只看 oldest retained row，因此候选数量由生产
        // conversation cap 严格约束。不能让全局最老但被 pin/缺 replacement 的
        // conversation 阻塞其它已有 durable replacement 的 eligible target。
        let candidate_limit = i64::try_from(MAX_RUNTIME_PHYSICAL_CONVERSATIONS)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let mut statement = transaction.prepare(
            "SELECT i.conversation_id, i.event_seq
             FROM event_stream_index i
             JOIN event_retention r
               ON r.conversation_id = i.conversation_id
              AND r.oldest_retained_event_seq = i.event_seq
             ORDER BY i.created_at_ms, i.conversation_id, i.event_seq
             LIMIT ?1",
        )?;
        let candidates = statement
            .query_map([candidate_limit], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if candidates.is_empty() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }

        let mut first_block = None;
        let mut victim = None;
        for candidate in candidates {
            if !respect_pins {
                victim = Some(candidate);
                break;
            }
            match super::retention::authorize_trim(
                transaction,
                key_bundle,
                super::retention::RetentionTarget::Conversation(&candidate.0),
                &candidate.1,
                now_ms,
            ) {
                Ok(()) => {
                    victim = Some(candidate);
                    break;
                }
                Err(error @ RuntimeStoreError::WorkerBusy { .. })
                | Err(error @ RuntimeStoreError::PublicationNeedsSnapshot) => {
                    if first_block.is_none() {
                        first_block = Some(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let victim = match victim {
            Some(victim) => victim,
            None => return Err(first_block.unwrap_or(RuntimeStoreError::UnknownOrCorruptSchema)),
        };
        if transaction.execute(
            "DELETE FROM event_stream_index
             WHERE conversation_id = ?1 AND event_seq = ?2",
            params![&victim.0, &victim.1],
        )? != 1
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        refresh_retention(transaction, key_bundle, &victim.0)?;
    }
}

/// active backfill/snapshot pin 只存在于本进程 TEMP schema；daemon restart 后客户端
/// 必须重新建立 barrier。Retention 只读这些 pin，绝不把撤销 reader 当成获得 trim
/// 授权的手段。
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
#[path = "stream/tests.rs"]
mod tests;
