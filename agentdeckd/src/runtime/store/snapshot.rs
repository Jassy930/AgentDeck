//! Runtime v4 frozen conversation snapshot repository。

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use agentdeck_protocol::runtime::ConversationEntry;
use agentdeck_protocol::runtime::identity::{AdapterStateKey, ConversationId};
use agentdeck_protocol::runtime::sync::StreamCursor;

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};
use crate::runtime::read_pool::ReadMemoryLease;

use super::cipher::RuntimeKeyBundle;
use super::identity::{RuntimeId, RuntimeIdKind};
use super::sequence::{SequenceScope, decode_sequence, encode_sequence};
use super::sqlite::{RuntimeLedger, RuntimeSqlite};
use super::stream::{metadata_mac, open_v4_row, optional_field, seal_v4_row, sqlite_u64};

pub(crate) const MAX_SNAPSHOT_ITEMS: u64 = 10_000;
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_SNAPSHOT_BYTES_GLOBAL: u64 = 512 * 1024 * 1024;
const SNAPSHOT_TOKEN_DOMAIN: &[u8] = b"snapshot.metadata.v1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogBaselineV1 {
    version: u8,
    base_catalog_cursor: StreamCursor,
    entries: Vec<ConversationEntry>,
}

struct StoredCatalogSnapshot {
    base_catalog_revision: Option<u64>,
    item_count: u64,
    payload: Vec<u8>,
}

#[derive(Clone, Copy)]
struct SnapshotLimits {
    max_items: u64,
    max_snapshot_bytes: usize,
    max_global_bytes: u64,
}

const PRODUCTION_LIMITS: SnapshotLimits = SnapshotLimits {
    max_items: MAX_SNAPSHOT_ITEMS,
    max_snapshot_bytes: MAX_SNAPSHOT_BYTES,
    max_global_bytes: MAX_SNAPSHOT_BYTES_GLOBAL,
};

#[derive(Debug)]
pub struct StoredConversationSnapshot {
    pub conversation_id: RuntimeId,
    pub snapshot_id: [u8; 16],
    source_build_pin_id: [u8; 16],
    pub base_event_seq: Option<u64>,
    pub item_count: u64,
    pub content_sha256: [u8; 32],
    pub created_at_ms: u64,
    pub payload: Vec<u8>,
    pub(crate) memory_lease: Option<ReadMemoryLease>,
}

impl PartialEq for StoredConversationSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.conversation_id == other.conversation_id
            && self.snapshot_id == other.snapshot_id
            && self.base_event_seq == other.base_event_seq
            && self.item_count == other.item_count
            && self.content_sha256 == other.content_sha256
            && self.created_at_ms == other.created_at_ms
            && self.payload == other.payload
    }
}

impl Eq for StoredConversationSnapshot {}

pub(super) fn migrate_catalog_snapshot_baseline(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut entries = Vec::new();
    let mut created_at_ms = 0_u64;
    let mut statement = transaction.prepare(
        "SELECT conversation_id FROM conversations ORDER BY catalog_revision, conversation_id",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    for row in rows {
        let conversation_id = runtime_conversation_id(&row?)?;
        let conversation = super::journal::load_conversation(
            transaction,
            key_bundle,
            database_id,
            conversation_id,
        )?;
        created_at_ms = created_at_ms.max(conversation.updated_at_ms);
        entries.push(ConversationEntry {
            conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
            adapter_state_key: AdapterStateKey::new(
                conversation.adapter_state_key.to_canonical_string(),
            ),
            agent_kind: conversation.descriptor.agent_kind,
            title: conversation.descriptor.title,
            cwd: Some(conversation.descriptor.cwd),
            last_active_ms: conversation.updated_at_ms,
            archived: conversation.lifecycle
                == crate::runtime::model::ConversationLifecycle::Archived,
        });
        if entries.len() > MAX_SNAPSHOT_ITEMS as usize {
            return Err(RuntimeStoreError::PayloadTooLarge);
        }
    }
    drop(statement);
    if u64::try_from(entries.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != ledger.conversation_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let base_value = ledger
        .catalog_high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    let payload = serde_json::to_vec(&CatalogBaselineV1 {
        version: 1,
        base_catalog_cursor: StreamCursor::from_high_water(base_value),
        entries,
    })
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if payload.is_empty() || payload.len() > MAX_SNAPSHOT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let logical_bytes =
        u64::try_from(payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let snapshot_id = allocate_snapshot_id(transaction)?;
    let content_sha256: [u8; 32] = Sha256::digest(&payload).into();
    let sealed = seal_v4_row(
        key_bundle,
        database_id,
        b"snapshots",
        &snapshot_id,
        b"sealed_snapshot",
        &payload,
        MAX_SNAPSHOT_BYTES,
    )?;
    let token = snapshot_token(
        key_bundle,
        "catalog",
        None,
        &snapshot_id,
        None,
        ledger.catalog_high_water.as_deref(),
        ledger.conversation_count,
        logical_bytes,
        &content_sha256,
        created_at_ms,
    )?;
    transaction.execute(
        "INSERT INTO snapshots (
             snapshot_id, target_scope, conversation_id, source_build_pin_id,
             base_cursor, build_state,
             item_count, logical_snapshot_bytes, content_sha256, created_at_ms,
             metadata_token, sealed_snapshot
         ) VALUES (?1, 'catalog', NULL, NULL, ?2, 'ready', ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &snapshot_id[..],
            ledger.catalog_high_water.as_deref(),
            sqlite_u64(ledger.conversation_count)?,
            sqlite_u64(logical_bytes)?,
            &content_sha256[..],
            sqlite_u64(created_at_ms)?,
            &token[..],
            sealed,
        ],
    )?;
    ledger.snapshot_count = 1;
    ledger.snapshot_bytes = logical_bytes;
    Ok(())
}

pub(super) fn store_conversation_snapshot(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pin: super::stream::RuntimeSnapshotBuildPin,
    item_count: u64,
    payload: Vec<u8>,
    created_at_ms: u64,
) -> Result<StoredConversationSnapshot, RuntimeStoreError> {
    store_conversation_snapshot_with_limits(
        state,
        config,
        pin,
        item_count,
        payload,
        created_at_ms,
        PRODUCTION_LIMITS,
    )
}

#[allow(clippy::too_many_arguments)]
fn store_conversation_snapshot_with_limits(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pin: super::stream::RuntimeSnapshotBuildPin,
    item_count: u64,
    payload: Vec<u8>,
    created_at_ms: u64,
    limits: SnapshotLimits,
) -> Result<StoredConversationSnapshot, RuntimeStoreError> {
    let conversation_id = pin.conversation_id();
    let source_build_pin_id = pin.pin_id();
    let base_event_seq = pin.base_event_seq();
    if conversation_id.kind() != RuntimeIdKind::Conversation {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        });
    }
    if item_count == 0 || item_count > limits.max_items {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    if payload.is_empty() || payload.len() > limits.max_snapshot_bytes {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let base_encoded = base_event_seq.map(encode_sequence);
    let content_sha256: [u8; 32] = Sha256::digest(&payload).into();
    if let Some(existing) = load_conversation_snapshot(state, conversation_id)?
        && existing.base_event_seq == base_event_seq
        && existing.item_count == item_count
        && existing.content_sha256 == content_sha256
        && existing.payload == payload
    {
        return replay_exact_conversation_snapshot(state, config, &pin, existing, created_at_ms);
    }
    let logical_bytes =
        u64::try_from(payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let projected_write_bytes = logical_bytes.checked_add(2 * 1024 * 1024).ok_or(
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "snapshot projected write bytes",
        },
    )?;
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        super::sqlite::SafetyReserveProjection::Current,
    )?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let event_high_water: Option<String> = transaction
        .query_row(
            "SELECT event_high_water FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::ConversationNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let current_high_water = event_high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()?;
    if base_event_seq > current_high_water {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    super::stream::validate_snapshot_build_pin(&transaction, &pin, created_at_ms)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let previous = transaction
        .query_row(
            "SELECT base_cursor, logical_snapshot_bytes, created_at_ms
             FROM snapshots
             WHERE target_scope = 'conversation' AND conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .map(|(base, bytes, created)| {
            Ok::<_, RuntimeStoreError>((
                base.as_deref()
                    .map(|value| decode_sequence(SequenceScope::EventSeq, value))
                    .transpose()?,
                u64::try_from(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
                u64::try_from(created).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            ))
        })
        .transpose()?;
    if let Some((previous_base, _, previous_created_at_ms)) = previous {
        if base_event_seq < previous_base {
            return Err(RuntimeStoreError::InvalidStateTransition);
        }
        if created_at_ms < previous_created_at_ms {
            return Err(RuntimeStoreError::ClockRegressed {
                persisted_ms: previous_created_at_ms,
                observed_ms: created_at_ms,
            });
        }
    }
    let previous_bytes = previous.map(|(_, bytes, _)| bytes);
    let projected_bytes = ledger
        .snapshot_bytes
        .checked_sub(previous_bytes.unwrap_or(0))
        .and_then(|value| value.checked_add(logical_bytes))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "snapshot global logical bytes",
        })?;
    if projected_bytes > limits.max_global_bytes {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let projected_count = if previous_bytes.is_some() {
        ledger.snapshot_count
    } else {
        ledger
            .snapshot_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
    };
    let snapshot_id = allocate_snapshot_id(&transaction)?;
    let sealed = seal_v4_row(
        key_bundle,
        database_id,
        b"snapshots",
        &snapshot_id,
        b"sealed_snapshot",
        &payload,
        MAX_SNAPSHOT_BYTES,
    )?;
    let token = snapshot_token(
        key_bundle,
        "conversation",
        Some(conversation_id.as_bytes()),
        &snapshot_id,
        Some(&source_build_pin_id),
        base_encoded.as_deref(),
        item_count,
        logical_bytes,
        &content_sha256,
        created_at_ms,
    )?;
    transaction.execute(
        "DELETE FROM snapshots WHERE target_scope = 'conversation' AND conversation_id = ?1",
        [&conversation_id.as_bytes()[..]],
    )?;
    super::stream::consume_snapshot_build_pin(&transaction, &pin)?;
    transaction.execute(
        "INSERT INTO snapshots (
             snapshot_id, target_scope, conversation_id, source_build_pin_id,
             base_cursor, build_state, item_count, logical_snapshot_bytes,
             content_sha256, created_at_ms, metadata_token, sealed_snapshot
         ) VALUES (?1, 'conversation', ?2, ?3, ?4, 'ready', ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            &snapshot_id[..],
            &conversation_id.as_bytes()[..],
            &source_build_pin_id[..],
            base_encoded.as_deref(),
            sqlite_u64(item_count)?,
            sqlite_u64(logical_bytes)?,
            &content_sha256[..],
            sqlite_u64(created_at_ms)?,
            &token[..],
            sealed,
        ],
    )?;
    let mut next = ledger.clone();
    next.snapshot_count = projected_count;
    next.snapshot_bytes = projected_bytes;
    super::sqlite::update_runtime_ledger(&transaction, key_bundle, database_id, &ledger, &next)?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::StoreSnapshotBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::StoreSnapshot)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::StoreSnapshotAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::StoreSnapshot,
        });
    }
    Ok(StoredConversationSnapshot {
        conversation_id,
        snapshot_id,
        source_build_pin_id,
        base_event_seq,
        item_count,
        content_sha256,
        created_at_ms,
        payload,
        memory_lease: None,
    })
}

fn replay_exact_conversation_snapshot(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pin: &super::stream::RuntimeSnapshotBuildPin,
    mut existing: StoredConversationSnapshot,
    now_ms: u64,
) -> Result<StoredConversationSnapshot, RuntimeStoreError> {
    let source_build_pin_id = pin.pin_id();
    if existing.source_build_pin_id == source_build_pin_id {
        // 只有 durable row 认证过的 source pin 可以在 TEMP pin 已随 COMMIT
        // 消失后直接回放；这是 StoreSnapshot outcome unknown 的幂等证据。
        return Ok(existing);
    }

    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    super::stream::validate_snapshot_build_pin(&transaction, pin, now_ms)?;
    let base = existing.base_event_seq.map(encode_sequence);
    let logical_bytes = u64::try_from(existing.payload.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let token = snapshot_token(
        key_bundle,
        "conversation",
        Some(existing.conversation_id.as_bytes()),
        &existing.snapshot_id,
        Some(&source_build_pin_id),
        base.as_deref(),
        existing.item_count,
        logical_bytes,
        &existing.content_sha256,
        existing.created_at_ms,
    )?;
    super::stream::consume_snapshot_build_pin(&transaction, pin)?;
    if transaction.execute(
        "UPDATE snapshots
         SET source_build_pin_id = ?1, metadata_token = ?2
         WHERE snapshot_id = ?3 AND target_scope = 'conversation'
           AND conversation_id = ?4 AND source_build_pin_id = ?5",
        params![
            &source_build_pin_id[..],
            &token[..],
            &existing.snapshot_id[..],
            &existing.conversation_id.as_bytes()[..],
            &existing.source_build_pin_id[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::StoreSnapshotBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::StoreSnapshot)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::StoreSnapshotAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::StoreSnapshot,
        });
    }
    existing.source_build_pin_id = source_build_pin_id;
    Ok(existing)
}

pub(super) fn load_conversation_snapshot(
    state: &RuntimeSqlite,
    conversation_id: RuntimeId,
) -> Result<Option<StoredConversationSnapshot>, RuntimeStoreError> {
    if conversation_id.kind() != RuntimeIdKind::Conversation {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        });
    }
    let exists: i64 = state.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id = ?1)",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Err(RuntimeStoreError::ConversationNotFound);
    }
    load_snapshot_row(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        conversation_id,
    )
}

pub(super) fn load_conversation_snapshot_read(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<Option<StoredConversationSnapshot>, RuntimeStoreError> {
    if conversation_id.kind() != RuntimeIdKind::Conversation {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        });
    }
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id = ?1)",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Err(RuntimeStoreError::ConversationNotFound);
    }
    load_snapshot_row_read(connection, read_crypto, database_id, conversation_id)
}

pub(super) fn validate_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut count = 0_u64;
    let mut bytes = 0_u64;
    let mut catalog_count = 0_u64;
    let mut statement = connection.prepare(
        "SELECT target_scope, conversation_id FROM snapshots
         ORDER BY target_scope, conversation_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
    })?;
    for row in rows {
        let (target_scope, conversation_id) = row?;
        if target_scope == "catalog" {
            if conversation_id.is_some() {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let snapshot = load_catalog_snapshot_row(connection, key_bundle, database_id)?
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            let catalog_high_water = ledger
                .catalog_high_water
                .as_deref()
                .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
                .transpose()?;
            if snapshot.base_catalog_revision > catalog_high_water
                || snapshot.item_count > ledger.conversation_count
                || catalog_count != 0
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            catalog_count = 1;
            count = count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            bytes = bytes
                .checked_add(
                    u64::try_from(snapshot.payload.len())
                        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
                )
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            continue;
        }
        if target_scope != "conversation" {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let conversation_id = runtime_conversation_id(
            conversation_id
                .as_deref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        let snapshot = load_snapshot_row(connection, key_bundle, database_id, conversation_id)?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let high_water: Option<String> = connection.query_row(
            "SELECT event_high_water FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )?;
        let high_water = high_water
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::EventSeq, value))
            .transpose()?;
        if snapshot.base_event_seq > high_water {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        count = count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        bytes = bytes
            .checked_add(
                u64::try_from(snapshot.payload.len())
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    if count != ledger.snapshot_count
        || bytes != ledger.snapshot_bytes
        || bytes > MAX_SNAPSHOT_BYTES_GLOBAL
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn load_snapshot_row(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<Option<StoredConversationSnapshot>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT snapshot_id, source_build_pin_id, base_cursor, item_count,
                    logical_snapshot_bytes, content_sha256, created_at_ms,
                    metadata_token, sealed_snapshot
             FROM snapshots
             WHERE target_scope = 'conversation' AND conversation_id = ?1
               AND build_state = 'ready'",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let snapshot_id: [u8; 16] = raw
        .0
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let source_build_pin_id: [u8; 16] = raw
        .1
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if source_build_pin_id == [0; 16] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let item_count = u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_bytes =
        u64::try_from(raw.4).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let content_sha256: [u8; 32] = raw
        .5
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.6).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected = snapshot_token(
        key_bundle,
        "conversation",
        Some(conversation_id.as_bytes()),
        &snapshot_id,
        Some(&source_build_pin_id),
        raw.2.as_deref(),
        item_count,
        logical_bytes,
        &content_sha256,
        created_at_ms,
    )?;
    if raw.7.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open_v4_row(
        key_bundle,
        database_id,
        b"snapshots",
        &snapshot_id,
        b"sealed_snapshot",
        &raw.8,
        MAX_SNAPSHOT_BYTES,
    )?;
    if plaintext.expose_secret().len()
        != usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(plaintext.expose_secret())) != content_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let base_event_seq = raw
        .2
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()?;
    drop(raw);
    Ok(Some(StoredConversationSnapshot {
        conversation_id,
        snapshot_id,
        source_build_pin_id,
        base_event_seq,
        item_count,
        content_sha256,
        created_at_ms,
        payload: plaintext.expose_secret().to_vec(),
        memory_lease: None,
    }))
}

fn load_catalog_snapshot_row(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<StoredCatalogSnapshot>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT snapshot_id, source_build_pin_id, base_cursor, item_count,
                    logical_snapshot_bytes, content_sha256, created_at_ms,
                    metadata_token, sealed_snapshot
             FROM snapshots
             WHERE target_scope = 'catalog' AND conversation_id IS NULL
               AND build_state = 'ready'",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let snapshot_id: [u8; 16] = raw
        .0
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if raw.1.is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let item_count = u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_bytes =
        u64::try_from(raw.4).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let content_sha256: [u8; 32] = raw
        .5
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.6).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected = snapshot_token(
        key_bundle,
        "catalog",
        None,
        &snapshot_id,
        None,
        raw.2.as_deref(),
        item_count,
        logical_bytes,
        &content_sha256,
        created_at_ms,
    )?;
    if raw.7.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open_v4_row(
        key_bundle,
        database_id,
        b"snapshots",
        &snapshot_id,
        b"sealed_snapshot",
        &raw.8,
        MAX_SNAPSHOT_BYTES,
    )?;
    if plaintext.expose_secret().len()
        != usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(plaintext.expose_secret())) != content_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let baseline: CatalogBaselineV1 = serde_json::from_slice(plaintext.expose_secret())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let base = raw
        .2
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    if baseline.version != 1
        || baseline.base_catalog_cursor.high_water() != base
        || baseline.entries.len() as u64 != item_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(StoredCatalogSnapshot {
        base_catalog_revision: base,
        item_count,
        payload: plaintext.expose_secret().to_vec(),
    }))
}

fn load_snapshot_row_read(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<Option<StoredConversationSnapshot>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT snapshot_id, source_build_pin_id, base_cursor, item_count,
                    logical_snapshot_bytes, content_sha256, created_at_ms,
                    metadata_token, sealed_snapshot
             FROM snapshots
             WHERE target_scope = 'conversation' AND conversation_id = ?1
               AND build_state = 'ready'",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let snapshot_id: [u8; 16] = raw
        .0
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let source_build_pin_id: [u8; 16] = raw
        .1
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if source_build_pin_id == [0; 16] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let item_count = u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_bytes =
        u64::try_from(raw.4).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let content_sha256: [u8; 32] = raw
        .5
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.6).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let source = optional_field(Some(&source_build_pin_id));
    let base = optional_field(raw.2.as_deref().map(str::as_bytes));
    let conversation = optional_field(Some(conversation_id.as_bytes()));
    if !super::stream::verify_metadata_mac(
        read_crypto,
        SNAPSHOT_TOKEN_DOMAIN,
        &[
            b"conversation",
            &conversation,
            &snapshot_id,
            &source,
            &base,
            b"ready",
            &item_count.to_be_bytes(),
            &logical_bytes.to_be_bytes(),
            &content_sha256,
            &created_at_ms.to_be_bytes(),
        ],
        &raw.7,
    )? {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = super::stream::open_v4_row_read(
        read_crypto,
        database_id,
        b"snapshots",
        &snapshot_id,
        b"sealed_snapshot",
        &raw.8,
        MAX_SNAPSHOT_BYTES,
    )?;
    if plaintext.expose_secret().len()
        != usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(plaintext.expose_secret())) != content_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let base_event_seq = raw
        .2
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()?;
    drop(raw);
    Ok(Some(StoredConversationSnapshot {
        conversation_id,
        snapshot_id,
        source_build_pin_id,
        base_event_seq,
        item_count,
        content_sha256,
        created_at_ms,
        payload: plaintext.expose_secret().to_vec(),
        memory_lease: None,
    }))
}

#[allow(clippy::too_many_arguments)]
fn snapshot_token(
    key_bundle: &RuntimeKeyBundle,
    target_scope: &str,
    conversation_id: Option<&[u8]>,
    snapshot_id: &[u8; 16],
    source_build_pin_id: Option<&[u8]>,
    base_event_seq: Option<&str>,
    item_count: u64,
    logical_bytes: u64,
    content_sha256: &[u8; 32],
    created_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let base = optional_field(base_event_seq.map(str::as_bytes));
    let conversation = optional_field(conversation_id);
    let source = optional_field(source_build_pin_id);
    metadata_mac(
        key_bundle,
        SNAPSHOT_TOKEN_DOMAIN,
        &[
            target_scope.as_bytes(),
            &conversation,
            snapshot_id,
            &source,
            &base,
            b"ready",
            &item_count.to_be_bytes(),
            &logical_bytes.to_be_bytes(),
            content_sha256,
            &created_at_ms.to_be_bytes(),
        ],
    )
}

fn allocate_snapshot_id(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<[u8; 16], RuntimeStoreError> {
    for _ in 0..16 {
        let mut candidate = [0_u8; 16];
        getrandom::fill(&mut candidate)
            .map_err(|_| RuntimeStoreError::InvalidConfig("OS entropy unavailable"))?;
        if candidate == [0; 16] {
            continue;
        }
        let exists: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM snapshots WHERE snapshot_id = ?1)",
            [&candidate[..]],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Ok(candidate);
        }
    }
    Err(RuntimeStoreError::InvalidConfig(
        "snapshot identity allocation exhausted",
    ))
}

fn runtime_conversation_id(bytes: &[u8]) -> Result<RuntimeId, RuntimeStoreError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(RuntimeId::from_bytes(RuntimeIdKind::Conversation, bytes)?)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use agentdeck_protocol::AgentKind;

    use super::*;
    use crate::runtime::model::{ConversationDescriptor, NewConversation};
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn snapshot_global_cap_rejects_new_conversation_without_evicting_ready_snapshot() {
        let root = std::env::temp_dir().join(format!(
            "agentdeck-snapshot-cap-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create snapshot cap root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("secure snapshot cap root");
        }
        let config = RuntimeStoreConfig::new(root.join("runtime.db"));
        let keys = MemoryKeyStore::new();
        let kek =
            load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("create test KEK");
        let mut state = super::super::sqlite::open(&config, kek).expect("open test store");
        let mut conversations = Vec::new();
        for seed in [0x31_u8, 0x32] {
            let input = NewConversation {
                conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
                    .expect("conversation id"),
                adapter_state_key: RuntimeId::from_bytes(
                    RuntimeIdKind::AdapterState,
                    [seed.wrapping_add(0x40); 16],
                )
                .expect("adapter id"),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::Codex,
                    title: Some(format!("snapshot-{seed}")),
                    cwd: PathBuf::from("/tmp/snapshot-cap"),
                },
            };
            let id = input.conversation_id;
            let descriptor =
                super::super::journal::canonical_conversation_descriptor(&input.descriptor)
                    .expect("canonical descriptor");
            super::super::journal::create_conversation(&mut state, &config, input, descriptor)
                .expect("create conversation");
            conversations.push(id);
        }
        let limits = SnapshotLimits {
            max_items: MAX_SNAPSHOT_ITEMS,
            max_snapshot_bytes: MAX_SNAPSHOT_BYTES,
            max_global_bytes: 5,
        };
        let first_pin =
            super::super::stream::acquire_snapshot_build_pin(&state, conversations[0], 10)
                .expect("capture first snapshot");
        let first = store_conversation_snapshot_with_limits(
            &mut state,
            &config,
            first_pin,
            1,
            vec![1; 4],
            10,
            limits,
        )
        .expect("store first snapshot");
        let rejected_pin =
            super::super::stream::acquire_snapshot_build_pin(&state, conversations[1], 11)
                .expect("capture rejected snapshot");
        assert!(matches!(
            store_conversation_snapshot_with_limits(
                &mut state,
                &config,
                rejected_pin,
                1,
                vec![2; 4],
                11,
                limits,
            ),
            Err(RuntimeStoreError::PayloadTooLarge)
        ));
        assert_eq!(
            load_conversation_snapshot(&state, conversations[0])
                .expect("load retained snapshot")
                .expect("snapshot exists"),
            first
        );
        assert!(
            load_conversation_snapshot(&state, conversations[1])
                .expect("load rejected snapshot target")
                .is_none()
        );
        let replacement_pin =
            super::super::stream::acquire_snapshot_build_pin(&state, conversations[0], 12)
                .expect("capture replacement snapshot");
        let replacement = store_conversation_snapshot_with_limits(
            &mut state,
            &config,
            replacement_pin,
            1,
            vec![3; 5],
            12,
            limits,
        )
        .expect("replace same conversation within global cap");
        assert_eq!(
            load_conversation_snapshot(&state, conversations[0])
                .expect("load replacement")
                .expect("replacement exists"),
            replacement
        );
        drop(state);
        let _ = fs::remove_dir_all(root);
    }
}
