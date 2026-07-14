//! Runtime v4 frozen conversation snapshot repository。

use std::collections::BTreeMap;
use std::mem::size_of;

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
use crate::runtime::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES;

use super::cipher::{
    ROW_BLOB_V1_OVERHEAD_LEN, RowAad, RuntimeKeyBundle, RuntimeReadCryptoCapability,
};
use super::identity::{RuntimeId, RuntimeIdKind};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sequence::{SequenceScope, decode_sequence, encode_sequence};
use super::sqlite::{RuntimeLedger, RuntimeSqlite};
use super::stream::{metadata_mac, optional_field, seal_v4_row, sqlite_u64};

mod authenticated;

#[cfg(test)]
use authenticated::snapshot_parent_error;
pub(super) use authenticated::{
    authenticate_directory, authenticated_catalog_snapshot_covers,
    authenticated_conversation_snapshot_covers, load_catalog_snapshot_reference_read,
    load_conversation_snapshot_read, load_conversation_snapshot_reference_read,
};
use authenticated::{
    load_catalog_snapshot_metadata, load_conversation_snapshot_metadata, snapshot_ciphertext_sha256,
};

pub(crate) const MAX_SNAPSHOT_ITEMS: u64 = 10_000;
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_SNAPSHOT_BYTES_GLOBAL: u64 = 512 * 1024 * 1024;
const MAX_DIRECTORY_ROWS: u64 = 1_024;
const SNAPSHOT_TOKEN_DOMAIN: &[u8] = b"snapshot.metadata.v1";

/// raw JSON + decoded catalog DTO（或 decoded DTO + 新 canonical payload）的
/// conservative retained-memory bound。provider 与 store refresh/read 共用，避免
/// 一边只计算 read-pool lease、另一边在 worker 内静默越过 128 MiB。
pub(crate) fn catalog_materialization_peak_bound(
    logical_bytes: u64,
    item_count: u64,
) -> Result<usize, RuntimeStoreError> {
    let logical = usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let rows = usize::try_from(item_count).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    logical
        .checked_mul(2)
        .and_then(|value| {
            rows.checked_mul(size_of::<ConversationEntry>() * 2 + 256)
                .and_then(|row_bytes| value.checked_add(row_bytes))
        })
        .and_then(|value| value.checked_add(64 * 1024))
        .filter(|value| *value <= SNAPSHOT_BUILD_MEMORY_BYTES)
        .ok_or(RuntimeStoreError::PayloadTooLarge)
}

fn seal_snapshot_payload_in_place(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    snapshot_id: &[u8; 16],
    payload: &mut Vec<u8>,
) -> Result<(), RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded_in_place(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: b"snapshots",
            primary_key: snapshot_id,
            column: b"sealed_snapshot",
        },
        payload,
        MAX_SNAPSHOT_BYTES,
    )?)
}

fn open_snapshot_payload_in_place(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    snapshot_id: &[u8; 16],
    payload: &mut Vec<u8>,
) -> Result<(), RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded_in_place(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: b"snapshots",
            primary_key: snapshot_id,
            column: b"sealed_snapshot",
        },
        payload,
        MAX_SNAPSHOT_BYTES,
    )?)
}

fn open_snapshot_payload_read_in_place(
    read_crypto: &RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    snapshot_id: &[u8; 16],
    payload: &mut Vec<u8>,
) -> Result<(), RuntimeStoreError> {
    Ok(read_crypto.open_bounded_in_place(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: b"snapshots",
            primary_key: snapshot_id,
            column: b"sealed_snapshot",
        },
        payload,
        MAX_SNAPSHOT_BYTES,
    )?)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SnapshotReadAllocationProbeState {
    active: bool,
    materialized_blob_bytes: usize,
    retained_bytes: usize,
    peak_retained_bytes: usize,
}

#[cfg(test)]
thread_local! {
    static SNAPSHOT_READ_ALLOCATION_PROBE: std::cell::Cell<SnapshotReadAllocationProbeState> =
        const { std::cell::Cell::new(SnapshotReadAllocationProbeState {
            active: false,
            materialized_blob_bytes: 0,
            retained_bytes: 0,
            peak_retained_bytes: 0,
        }) };
}

#[cfg(test)]
fn begin_snapshot_read_allocation_probe() {
    begin_snapshot_read_allocation_probe_with_retained(0);
}

#[cfg(test)]
fn begin_snapshot_read_allocation_probe_with_retained(retained_bytes: usize) {
    SNAPSHOT_READ_ALLOCATION_PROBE.with(|probe| {
        assert!(
            !probe.get().active,
            "snapshot read allocation probes cannot nest"
        );
        probe.set(SnapshotReadAllocationProbeState {
            active: true,
            materialized_blob_bytes: 0,
            retained_bytes,
            peak_retained_bytes: retained_bytes,
        });
    });
}

#[cfg(test)]
fn finish_snapshot_read_allocation_probe() -> SnapshotReadAllocationProbeState {
    SNAPSHOT_READ_ALLOCATION_PROBE.with(|probe| {
        let state = probe.get();
        assert!(
            state.active,
            "snapshot read allocation probe must be active"
        );
        probe.set(SnapshotReadAllocationProbeState::default());
        state
    })
}

#[cfg(test)]
fn observe_snapshot_blob_materialized(capacity: usize) {
    SNAPSHOT_READ_ALLOCATION_PROBE.with(|probe| {
        let mut state = probe.get();
        if state.active {
            state.materialized_blob_bytes = state
                .materialized_blob_bytes
                .checked_add(capacity)
                .expect("snapshot blob materialization accounting overflow");
            probe.set(state);
        }
    });
}

#[cfg(test)]
fn observe_snapshot_read_peak(retained_bytes: usize) {
    SNAPSHOT_READ_ALLOCATION_PROBE.with(|probe| {
        let mut state = probe.get();
        if state.active {
            state.peak_retained_bytes = state
                .peak_retained_bytes
                .max(state.retained_bytes.saturating_add(retained_bytes));
            probe.set(state);
        }
    });
}

#[cfg(test)]
fn observe_snapshot_retained_released(capacity: usize) {
    SNAPSHOT_READ_ALLOCATION_PROBE.with(|probe| {
        let mut state = probe.get();
        if state.active {
            state.retained_bytes = state
                .retained_bytes
                .checked_sub(capacity)
                .expect("snapshot retained release accounting underflow");
            probe.set(state);
        }
    });
}

#[cfg(test)]
struct ObservedSnapshotAllocation {
    capacity: usize,
    active: bool,
}

#[cfg(test)]
impl Drop for ObservedSnapshotAllocation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        SNAPSHOT_READ_ALLOCATION_PROBE.with(|probe| {
            let mut state = probe.get();
            state.retained_bytes = state
                .retained_bytes
                .checked_sub(self.capacity)
                .expect("snapshot allocation probe accounting underflow");
            probe.set(state);
        });
    }
}

#[cfg(test)]
fn observe_snapshot_allocation(
    capacity: usize,
    materialized_blob: bool,
) -> ObservedSnapshotAllocation {
    let active = SNAPSHOT_READ_ALLOCATION_PROBE.with(|probe| {
        let mut state = probe.get();
        if !state.active {
            return false;
        }
        state.retained_bytes = state
            .retained_bytes
            .checked_add(capacity)
            .expect("snapshot allocation probe accounting overflow");
        state.peak_retained_bytes = state.peak_retained_bytes.max(state.retained_bytes);
        if materialized_blob {
            state.materialized_blob_bytes = state
                .materialized_blob_bytes
                .checked_add(capacity)
                .expect("snapshot BLOB accounting overflow");
        }
        probe.set(state);
        true
    });
    ObservedSnapshotAllocation { capacity, active }
}

/// Barrier 在同一个 authenticated directory cut 内冻结的 ready snapshot 坐标。
/// 后续读取必须逐字段匹配本引用，不能按 conversation 重新选择更新后的 ready row。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadySnapshotReference {
    pub snapshot_id: [u8; 16],
    pub target: crate::runtime::events::RuntimeStreamTarget,
    pub base: StreamCursor,
    pub item_count: u64,
    pub logical_bytes: u64,
    pub content_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CatalogSnapshotRefreshPreflight {
    pub(crate) peak_retained_bytes: usize,
    pub(crate) refresh_required: bool,
    current_reference: Option<ReadySnapshotReference>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CatalogBaselineV1 {
    pub(crate) version: u8,
    pub(crate) base_catalog_cursor: StreamCursor,
    pub(crate) entries: Vec<ConversationEntry>,
}

struct BoundedCatalogJsonCounter {
    bytes: usize,
    exceeded: bool,
}

impl std::io::Write for BoundedCatalogJsonCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next) = self.bytes.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::other("catalog JSON length overflow"));
        };
        if next > MAX_SNAPSHOT_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::other("catalog JSON exceeds snapshot limit"));
        }
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_catalog_baseline_bounded(
    baseline: &CatalogBaselineV1,
    item_count: u64,
) -> Result<Vec<u8>, RuntimeStoreError> {
    let mut counter = BoundedCatalogJsonCounter {
        bytes: 0,
        exceeded: false,
    };
    if serde_json::to_writer(&mut counter, baseline).is_err() {
        return if counter.exceeded {
            Err(RuntimeStoreError::PayloadTooLarge)
        } else {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        };
    }
    if counter.bytes == 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    catalog_materialization_peak_bound(
        u64::try_from(counter.bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        item_count,
    )?;
    let required_capacity = counter
        .bytes
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(required_capacity)
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    catalog_materialization_peak_bound(
        u64::try_from(payload.capacity()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        item_count,
    )?;
    serde_json::to_writer(&mut payload, baseline)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if payload.len() != counter.bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(payload)
}

pub(crate) struct StoredCatalogSnapshot {
    pub(crate) snapshot_id: [u8; 16],
    pub(crate) base_catalog_revision: Option<u64>,
    pub(crate) item_count: u64,
    pub(crate) content_sha256: [u8; 32],
    pub(crate) created_at_ms: u64,
    pub(crate) payload: Vec<u8>,
    pub(crate) memory_lease: Option<ReadMemoryLease>,
}

#[derive(Clone, Debug)]
struct ConversationSnapshotRowMetadata {
    snapshot_id: [u8; 16],
    source_build_pin_id: [u8; 16],
    base_event_seq: Option<u64>,
    item_count: u64,
    logical_bytes: u64,
    content_sha256: [u8; 32],
    sealed_snapshot_sha256: [u8; 32],
    created_at_ms: u64,
    sealed_blob_len: usize,
}

#[derive(Clone, Debug)]
struct CatalogSnapshotRowMetadata {
    snapshot_id: [u8; 16],
    base_catalog_revision: Option<u64>,
    item_count: u64,
    logical_bytes: u64,
    content_sha256: [u8; 32],
    sealed_snapshot_sha256: [u8; 32],
    created_at_ms: u64,
    sealed_blob_len: usize,
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

struct SnapshotStoreAttemptError {
    error: RuntimeStoreError,
    retry_payload: Option<Vec<u8>>,
}

impl SnapshotStoreAttemptError {
    fn retryable(error: RuntimeStoreError, payload: Vec<u8>) -> Self {
        Self {
            error,
            retry_payload: Some(payload),
        }
    }

    fn consumed(error: RuntimeStoreError) -> Self {
        Self {
            error,
            retry_payload: None,
        }
    }
}

enum SnapshotReplacementError {
    Retryable(RuntimeStoreError),
    Consumed(RuntimeStoreError),
}

impl From<RuntimeStoreError> for SnapshotReplacementError {
    fn from(error: RuntimeStoreError) -> Self {
        Self::Retryable(error)
    }
}

impl From<rusqlite::Error> for SnapshotReplacementError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Retryable(RuntimeStoreError::Sqlite(error))
    }
}

impl From<super::sequence::SequenceError> for SnapshotReplacementError {
    fn from(error: super::sequence::SequenceError) -> Self {
        Self::Retryable(RuntimeStoreError::Sequence(error))
    }
}

fn validate_snapshot_build_pin_for_store(
    connection: &Connection,
    pin: &super::stream::RuntimeSnapshotBuildPin,
    now_ms: u64,
) -> Result<(), SnapshotReplacementError> {
    super::stream::validate_snapshot_build_pin(connection, pin, now_ms).map_err(|error| {
        match error {
            // 失效或时钟回拨后的 exact capability 不能返还给调用方重试；
            // exact-expiry 删除必须发生在 store transaction 之外才不会随 Err rollback。
            RuntimeStoreError::InvalidStateTransition
            | RuntimeStoreError::ClockRegressed { .. } => SnapshotReplacementError::Consumed(error),
            other => SnapshotReplacementError::Retryable(other),
        }
    })
}

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
    let content_sha256: [u8; 32] = Sha256::digest(payload.as_slice()).into();
    let sealed = seal_v4_row(
        key_bundle,
        database_id,
        b"snapshots",
        &snapshot_id,
        b"sealed_snapshot",
        &payload,
        MAX_SNAPSHOT_BYTES,
    )?;
    let sealed_snapshot_sha256 = snapshot_ciphertext_sha256(&sealed);
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
        &sealed_snapshot_sha256,
        created_at_ms,
    )?;
    transaction.execute(
        "INSERT INTO snapshots (
             snapshot_id, target_scope, conversation_id, source_build_pin_id,
             base_cursor, build_state,
             item_count, logical_snapshot_bytes, content_sha256,
             sealed_snapshot_sha256, created_at_ms, metadata_token, sealed_snapshot
         ) VALUES (?1, 'catalog', NULL, NULL, ?2, 'ready', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &snapshot_id[..],
            ledger.catalog_high_water.as_deref(),
            sqlite_u64(ledger.conversation_count)?,
            sqlite_u64(logical_bytes)?,
            &content_sha256[..],
            &sealed_snapshot_sha256[..],
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
    write: super::PreparedConversationSnapshotWrite,
    created_at_ms: u64,
) -> Result<StoredConversationSnapshot, super::StoreConversationSnapshotError> {
    let (pin, item_count, payload, mut cleanup) = write.into_parts();
    let result = store_conversation_snapshot_owned(
        state,
        config,
        &pin,
        item_count,
        payload,
        created_at_ms,
        PRODUCTION_LIMITS,
    );
    match result {
        Ok(stored) => {
            cleanup.disarm();
            Ok(stored)
        }
        Err(failure) => match failure.retry_payload {
            Some(payload) => Err(super::StoreConversationSnapshotError::with_retry_write(
                failure.error,
                super::PreparedConversationSnapshotWrite::new(pin, item_count, payload, cleanup),
            )),
            None => Err(super::StoreConversationSnapshotError::without_retry_write(
                failure.error,
            )),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn store_conversation_snapshot_owned(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pin: &super::stream::RuntimeSnapshotBuildPin,
    item_count: u64,
    payload: Vec<u8>,
    created_at_ms: u64,
    limits: SnapshotLimits,
) -> Result<StoredConversationSnapshot, SnapshotStoreAttemptError> {
    let conversation_id = pin.conversation_id();
    if conversation_id.kind() != RuntimeIdKind::Conversation {
        return Err(SnapshotStoreAttemptError::retryable(
            RuntimeStoreError::IdKindMismatch {
                expected: RuntimeIdKind::Conversation,
                actual: conversation_id.kind(),
            },
            payload,
        ));
    }
    if item_count == 0
        || item_count > limits.max_items
        || payload.is_empty()
        || payload.len() > limits.max_snapshot_bytes
    {
        return Err(SnapshotStoreAttemptError::retryable(
            RuntimeStoreError::PayloadTooLarge,
            payload,
        ));
    }
    let logical_bytes = match u64::try_from(payload.len()) {
        Ok(logical_bytes) => logical_bytes,
        Err(_) => {
            return Err(SnapshotStoreAttemptError::retryable(
                RuntimeStoreError::PayloadTooLarge,
                payload,
            ));
        }
    };
    let content_sha256: [u8; 32] = Sha256::digest(payload.as_slice()).into();
    let existing = match load_conversation_snapshot_metadata(
        &state.connection,
        &state.key_bundle,
        conversation_id,
    ) {
        Ok(existing) => existing,
        Err(error) => return Err(SnapshotStoreAttemptError::retryable(error, payload)),
    };
    if let Some(metadata) = existing
        && metadata.base_event_seq == pin.base_event_seq()
        && metadata.item_count == item_count
        && metadata.logical_bytes == logical_bytes
        && metadata.content_sha256 == content_sha256
    {
        #[cfg(test)]
        observe_snapshot_retained_released(payload.capacity());
        drop(payload);
        let authenticated_payload = load_conversation_snapshot_payload(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            conversation_id,
            &metadata,
        )
        .map_err(SnapshotStoreAttemptError::consumed)?;
        let mut stored = StoredConversationSnapshot {
            conversation_id,
            snapshot_id: metadata.snapshot_id,
            source_build_pin_id: metadata.source_build_pin_id,
            base_event_seq: metadata.base_event_seq,
            item_count: metadata.item_count,
            content_sha256: metadata.content_sha256,
            created_at_ms: metadata.created_at_ms,
            payload: authenticated_payload,
            memory_lease: None,
        };
        if let Err(error) =
            replay_exact_conversation_snapshot(state, config, pin, &mut stored, created_at_ms)
        {
            return Err(match error {
                SnapshotReplacementError::Retryable(error) => {
                    SnapshotStoreAttemptError::retryable(error, stored.payload)
                }
                SnapshotReplacementError::Consumed(error) => {
                    SnapshotStoreAttemptError::consumed(error)
                }
            });
        }
        return Ok(stored);
    }

    let mut payload = payload;
    match store_conversation_snapshot_in_place(
        state,
        config,
        pin,
        item_count,
        &mut payload,
        created_at_ms,
        limits,
    ) {
        Ok(mut stored) => {
            stored.payload = payload;
            Ok(stored)
        }
        Err(SnapshotReplacementError::Retryable(error)) => {
            Err(SnapshotStoreAttemptError::retryable(error, payload))
        }
        Err(SnapshotReplacementError::Consumed(error)) => {
            Err(SnapshotStoreAttemptError::consumed(error))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn store_conversation_snapshot_in_place(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pin: &super::stream::RuntimeSnapshotBuildPin,
    item_count: u64,
    payload: &mut Vec<u8>,
    created_at_ms: u64,
    limits: SnapshotLimits,
) -> Result<StoredConversationSnapshot, SnapshotReplacementError> {
    let conversation_id = pin.conversation_id();
    let source_build_pin_id = pin.pin_id();
    let base_event_seq = pin.base_event_seq();
    if conversation_id.kind() != RuntimeIdKind::Conversation {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        }
        .into());
    }
    if item_count == 0 || item_count > limits.max_items {
        return Err(RuntimeStoreError::PayloadTooLarge.into());
    }
    if payload.is_empty() || payload.len() > limits.max_snapshot_bytes {
        return Err(RuntimeStoreError::PayloadTooLarge.into());
    }
    let base_encoded = base_event_seq.map(encode_sequence);
    let content_sha256: [u8; 32] = Sha256::digest(&payload).into();
    let logical_bytes =
        u64::try_from(payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    validate_snapshot_build_pin_for_store(&state.connection, pin, created_at_ms)?;
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
        return Err(RuntimeStoreError::InvalidStateTransition.into());
    }
    validate_snapshot_build_pin_for_store(&transaction, pin, created_at_ms)?;
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
            return Err(RuntimeStoreError::InvalidStateTransition.into());
        }
        if created_at_ms < previous_created_at_ms {
            return Err(RuntimeStoreError::ClockRegressed {
                persisted_ms: previous_created_at_ms,
                observed_ms: created_at_ms,
            }
            .into());
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
        return Err(RuntimeStoreError::PayloadTooLarge.into());
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
    seal_snapshot_payload_in_place(key_bundle, database_id, &snapshot_id, payload)?;
    let sealed_snapshot_sha256 = snapshot_ciphertext_sha256(payload.as_slice());
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
        &sealed_snapshot_sha256,
        created_at_ms,
    )?;
    let commit_result = (|| -> Result<(), RuntimeStoreError> {
        transaction.execute(
            "DELETE FROM snapshots WHERE target_scope = 'conversation' AND conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
        )?;
        super::stream::consume_snapshot_build_pin(&transaction, pin)?;
        transaction.execute(
            "INSERT INTO snapshots (
                 snapshot_id, target_scope, conversation_id, source_build_pin_id,
                 base_cursor, build_state, item_count, logical_snapshot_bytes,
                 content_sha256, sealed_snapshot_sha256, created_at_ms,
                 metadata_token, sealed_snapshot
             ) VALUES (?1, 'conversation', ?2, ?3, ?4, 'ready',
                       ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                &snapshot_id[..],
                &conversation_id.as_bytes()[..],
                &source_build_pin_id[..],
                base_encoded.as_deref(),
                sqlite_u64(item_count)?,
                sqlite_u64(logical_bytes)?,
                &content_sha256[..],
                &sealed_snapshot_sha256[..],
                sqlite_u64(created_at_ms)?,
                &token[..],
                payload.as_slice(),
            ],
        )?;
        let mut next = ledger.clone();
        next.snapshot_count = projected_count;
        next.snapshot_bytes = projected_bytes;
        let _pending_targets = super::sqlite::update_runtime_ledger(
            &transaction,
            key_bundle,
            database_id,
            &ledger,
            &next,
        )?;
        config
            .fault_injector
            .before_operation(RuntimeStoreOperation::StoreSnapshotBeforeCommit)?;
        super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::StoreSnapshot)
    })();
    if let Err(error) =
        open_snapshot_payload_in_place(&state.key_bundle, database_id, &snapshot_id, payload)
    {
        return Err(SnapshotReplacementError::Consumed(error));
    }
    commit_result?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::StoreSnapshotAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::StoreSnapshot,
        }
        .into());
    }
    Ok(StoredConversationSnapshot {
        conversation_id,
        snapshot_id,
        source_build_pin_id,
        base_event_seq,
        item_count,
        content_sha256,
        created_at_ms,
        payload: Vec::new(),
        memory_lease: None,
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn store_conversation_snapshot_with_limits(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pin: super::stream::RuntimeSnapshotBuildPin,
    item_count: u64,
    mut payload: Vec<u8>,
    created_at_ms: u64,
    limits: SnapshotLimits,
) -> Result<StoredConversationSnapshot, RuntimeStoreError> {
    let required_capacity = payload
        .len()
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    if payload.capacity() < required_capacity {
        payload
            .try_reserve_exact(required_capacity - payload.capacity())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    }
    store_conversation_snapshot_owned(
        state,
        config,
        &pin,
        item_count,
        payload,
        created_at_ms,
        limits,
    )
    .map_err(|failure| failure.error)
}

fn replay_exact_conversation_snapshot(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pin: &super::stream::RuntimeSnapshotBuildPin,
    existing: &mut StoredConversationSnapshot,
    now_ms: u64,
) -> Result<(), SnapshotReplacementError> {
    let source_build_pin_id = pin.pin_id();
    if existing.source_build_pin_id == source_build_pin_id {
        // 只有 durable row 认证过的 source pin 可以在 TEMP pin 已随 COMMIT
        // 消失后直接回放；这是 StoreSnapshot outcome unknown 的幂等证据。
        return Ok(());
    }

    validate_snapshot_build_pin_for_store(&state.connection, pin, now_ms)?;
    let key_bundle = &state.key_bundle;
    let persisted_metadata = load_conversation_snapshot_metadata(
        &state.connection,
        key_bundle,
        existing.conversation_id,
    )?
    .filter(|metadata| metadata.snapshot_id == existing.snapshot_id)
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_snapshot_build_pin_for_store(&transaction, pin, now_ms)?;
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
        &persisted_metadata.sealed_snapshot_sha256,
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
        return Err(RuntimeStoreError::UnknownOrCorruptSchema.into());
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
        }
        .into());
    }
    existing.source_build_pin_id = source_build_pin_id;
    Ok(())
}

#[cfg(test)]
fn load_conversation_snapshot(
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
    let Some(metadata) =
        load_conversation_snapshot_metadata(connection, key_bundle, conversation_id)?
    else {
        return Ok(None);
    };
    let payload = load_conversation_snapshot_payload(
        connection,
        key_bundle,
        database_id,
        conversation_id,
        &metadata,
    )?;
    Ok(Some(StoredConversationSnapshot {
        conversation_id,
        snapshot_id: metadata.snapshot_id,
        source_build_pin_id: metadata.source_build_pin_id,
        base_event_seq: metadata.base_event_seq,
        item_count: metadata.item_count,
        content_sha256: metadata.content_sha256,
        created_at_ms: metadata.created_at_ms,
        payload,
        memory_lease: None,
    }))
}

fn load_conversation_snapshot_payload(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    metadata: &ConversationSnapshotRowMetadata,
) -> Result<Vec<u8>, RuntimeStoreError> {
    let mut payload = connection
        .query_row(
            "SELECT sealed_snapshot
             FROM snapshots
             WHERE snapshot_id = ?1 AND target_scope = 'conversation'
               AND conversation_id = ?2 AND build_state = 'ready'",
            params![&metadata.snapshot_id[..], &conversation_id.as_bytes()[..]],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    #[cfg(test)]
    let _payload_allocation = observe_snapshot_allocation(payload.capacity(), true);
    if payload.len() != metadata.sealed_blob_len {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if snapshot_ciphertext_sha256(&payload) != metadata.sealed_snapshot_sha256 {
        return Err(super::cipher::CipherError::AuthenticationFailed.into());
    }
    open_snapshot_payload_in_place(key_bundle, database_id, &metadata.snapshot_id, &mut payload)?;
    if payload.len()
        != usize::try_from(metadata.logical_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(payload.as_slice())) != metadata.content_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(payload)
}

fn load_catalog_snapshot_row(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<StoredCatalogSnapshot>, RuntimeStoreError> {
    let Some(metadata) = load_catalog_snapshot_metadata(connection, key_bundle)? else {
        return Ok(None);
    };
    let mut payload = connection
        .query_row(
            "SELECT sealed_snapshot
             FROM snapshots
             WHERE snapshot_id = ?1 AND target_scope = 'catalog'
               AND conversation_id IS NULL AND build_state = 'ready'",
            [&metadata.snapshot_id[..]],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    #[cfg(test)]
    let _payload_allocation = observe_snapshot_allocation(payload.capacity(), true);
    if payload.len() != metadata.sealed_blob_len {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if snapshot_ciphertext_sha256(&payload) != metadata.sealed_snapshot_sha256 {
        return Err(super::cipher::CipherError::AuthenticationFailed.into());
    }
    open_snapshot_payload_in_place(key_bundle, database_id, &metadata.snapshot_id, &mut payload)?;
    if payload.len()
        != usize::try_from(metadata.logical_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(payload.as_slice())) != metadata.content_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    catalog_materialization_peak_bound(metadata.logical_bytes, metadata.item_count)?;
    let baseline: CatalogBaselineV1 = serde_json::from_slice(payload.as_slice())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if baseline.version != 1
        || baseline.base_catalog_cursor.high_water() != metadata.base_catalog_revision
        || baseline.entries.len() as u64 != metadata.item_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(StoredCatalogSnapshot {
        snapshot_id: metadata.snapshot_id,
        base_catalog_revision: metadata.base_catalog_revision,
        item_count: metadata.item_count,
        content_sha256: metadata.content_sha256,
        created_at_ms: metadata.created_at_ms,
        payload,
        memory_lease: None,
    }))
}

/// 在 catalog refresh materialize 任何 snapshot/delta payload 前，认证 exact
/// current reference、frozen base、ledger HWM 与完整 delta metadata 区间，并给出
/// refresh 的 conservative retained-memory peak。
pub(super) fn preflight_catalog_snapshot_refresh(
    state: &RuntimeSqlite,
    source: Option<&ReadySnapshotReference>,
    frozen_base: StreamCursor,
) -> Result<CatalogSnapshotRefreshPreflight, RuntimeStoreError> {
    if source
        .is_some_and(|source| source.target != crate::runtime::events::RuntimeStreamTarget::Catalog)
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let current_metadata =
        load_catalog_snapshot_metadata(&state.connection, state.key_bundle.as_ref())?;
    let current_reference = current_metadata
        .as_ref()
        .map(catalog_snapshot_metadata_reference)
        .transpose()?;
    if current_reference.as_ref() != source
        || current_reference
            .as_ref()
            .is_some_and(|reference| cursor_after(reference.base, frozen_base))
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }

    let ledger = super::sqlite::load_runtime_ledger(
        &state.connection,
        state.key_bundle.as_ref(),
        state.database_id,
    )?;
    let ledger_high_water = ledger
        .catalog_high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    match (frozen_base.high_water(), ledger_high_water) {
        (None, None) => {}
        (Some(through), Some(high_water)) if high_water >= through => {}
        _ => return Err(RuntimeStoreError::InvalidStateTransition),
    }

    let source_base = current_reference
        .as_ref()
        .map_or(StreamCursor::BeforeFirst, |reference| reference.base);
    let range = match (source_base == frozen_base, frozen_base.high_water()) {
        (true, _) | (_, None) => None,
        (false, Some(through)) => {
            let first = source_base
                .checked_next()
                .map_err(|_| RuntimeStoreError::InvalidStateTransition)?;
            Some(super::catalog::summarize_authenticated_delta_range(
                &state.connection,
                state.key_bundle.as_ref(),
                first,
                through,
            )?)
        }
    };
    let source_logical_bytes = current_reference
        .as_ref()
        .map_or(0, |reference| reference.logical_bytes);
    let source_item_count = current_reference
        .as_ref()
        .map_or(0, |reference| reference.item_count);
    let projected_logical_bytes = source_logical_bytes
        .checked_add(range.map_or(0, |range| range.logical_bytes))
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    // 每条 delta 最多新增一条 entry；实际目录又受 MAX_SNAPSHOT_ITEMS 硬约束。
    // 在不知道 upsert/remove 净效应的 metadata-only preflight 中取两者较小值，
    // 仍覆盖 refresh 可能持有的最大 decoded DTO 数量。
    let projected_item_count = source_item_count
        .checked_add(range.map_or(0, |range| range.count))
        .ok_or(RuntimeStoreError::PayloadTooLarge)?
        .min(MAX_SNAPSHOT_ITEMS);
    let peak_retained_bytes =
        catalog_materialization_peak_bound(projected_logical_bytes, projected_item_count)?;
    let refresh_required = current_reference
        .as_ref()
        .is_none_or(|reference| reference.base != frozen_base);
    Ok(CatalogSnapshotRefreshPreflight {
        peak_retained_bytes,
        refresh_required,
        current_reference,
    })
}

pub(super) fn refresh_catalog_snapshot(
    state: &mut RuntimeSqlite,
    config: &crate::runtime::model::RuntimeStoreConfig,
    source: Option<&ReadySnapshotReference>,
    frozen_base: StreamCursor,
) -> Result<ReadySnapshotReference, RuntimeStoreError> {
    let preflight = preflight_catalog_snapshot_refresh(state, source, frozen_base)?;
    if preflight
        .current_reference
        .as_ref()
        .is_some_and(|reference| reference.base == frozen_base)
    {
        return preflight
            .current_reference
            .ok_or(RuntimeStoreError::InvalidStateTransition);
    }
    let current =
        load_catalog_snapshot_row(&state.connection, &state.key_bundle, state.database_id)?;
    let current_reference = current
        .as_ref()
        .map(catalog_snapshot_reference)
        .transpose()?;
    if current_reference != preflight.current_reference {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }

    let had_current = current.is_some();
    let previous_bytes = current
        .as_ref()
        .map(|current| u64::try_from(current.payload.len()))
        .transpose()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let previous_created_at_ms = current.as_ref().map(|current| current.created_at_ms);

    let baseline = match &current {
        Some(current) => serde_json::from_slice::<CatalogBaselineV1>(&current.payload)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        None => CatalogBaselineV1 {
            version: 1,
            base_catalog_cursor: StreamCursor::BeforeFirst,
            entries: Vec::new(),
        },
    };
    // baseline 已拥有 decoded entries；尽早释放旧 raw plaintext，避免后续
    // BTreeMap reducer 与新 canonical payload 形成 raw+DTO+payload 三份共驻。
    drop(current);
    let source_base = current_reference
        .as_ref()
        .map_or(StreamCursor::BeforeFirst, |reference| reference.base);
    if baseline.version != 1 || baseline.base_catalog_cursor != source_base {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut entries = BTreeMap::new();
    for entry in baseline.entries {
        let key = entry.conversation_id.as_str().to_owned();
        if entries.insert(key, entry).is_some() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    if let Some(through) = frozen_base.high_water() {
        let first = source_base
            .checked_next()
            .map_err(|_| RuntimeStoreError::InvalidStateTransition)?;
        let delta_count = through
            .checked_sub(first)
            .and_then(|value| value.checked_add(1))
            .ok_or(RuntimeStoreError::InvalidStateTransition)?;
        if delta_count > super::catalog::MAX_CATALOG_DELTAS {
            return Err(RuntimeStoreError::BackfillNeedSnapshot);
        }
        let read_crypto = state.key_bundle.read_only_capability();
        for revision in first..=through {
            let encoded = encode_sequence(revision);
            let delta = super::catalog::load_delta(
                &state.connection,
                &read_crypto,
                state.database_id,
                &encoded,
            )?;
            match delta.changes.as_slice() {
                [agentdeck_protocol::runtime::CatalogChange::Upserted { entry }] => {
                    entries.insert(entry.conversation_id.as_str().to_owned(), entry.clone());
                }
                [agentdeck_protocol::runtime::CatalogChange::Removed { conversation_id }] => {
                    if entries.remove(conversation_id.as_str()).is_none() {
                        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                    }
                }
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            }
        }
    }
    let entries = entries.into_values().collect::<Vec<_>>();
    let item_count =
        u64::try_from(entries.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    if item_count > MAX_SNAPSHOT_ITEMS {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let baseline = CatalogBaselineV1 {
        version: 1,
        base_catalog_cursor: frozen_base,
        entries,
    };
    let mut payload = encode_catalog_baseline_bounded(&baseline, item_count)?;
    drop(baseline);
    let logical_bytes =
        u64::try_from(payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let projected_write_bytes = logical_bytes.checked_add(2 * 1024 * 1024).ok_or(
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "catalog snapshot projected write bytes",
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
    let created_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    if previous_created_at_ms.is_some_and(|persisted| created_at_ms < persisted) {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: previous_created_at_ms.unwrap_or(0),
            observed_ms: created_at_ms,
        });
    }
    let content_sha256: [u8; 32] = Sha256::digest(payload.as_slice()).into();
    let key_bundle = &state.key_bundle;
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let persisted = load_catalog_snapshot_metadata(&transaction, key_bundle)?;
    let persisted_matches = match (&persisted, &current_reference) {
        (None, None) => true,
        (Some(persisted), Some(current)) => {
            persisted.snapshot_id == current.snapshot_id
                && StreamCursor::from_high_water(persisted.base_catalog_revision) == current.base
                && persisted.content_sha256 == current.content_sha256
        }
        _ => false,
    };
    if !persisted_matches {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let ledger = super::sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let ledger_high_water = ledger
        .catalog_high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    match (frozen_base.high_water(), ledger_high_water) {
        (None, None) => {}
        (Some(through), Some(high_water)) if high_water >= through => {}
        _ => return Err(RuntimeStoreError::InvalidStateTransition),
    }
    let projected_bytes = ledger
        .snapshot_bytes
        .checked_sub(previous_bytes.unwrap_or(0))
        .and_then(|value| value.checked_add(logical_bytes))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "catalog snapshot global logical bytes",
        })?;
    if projected_bytes > MAX_SNAPSHOT_BYTES_GLOBAL {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let projected_count = if had_current {
        ledger.snapshot_count
    } else {
        ledger
            .snapshot_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
    };
    let snapshot_id = allocate_snapshot_id(&transaction)?;
    let base = frozen_base.high_water().map(encode_sequence);
    seal_snapshot_payload_in_place(key_bundle, database_id, &snapshot_id, &mut payload)?;
    let sealed_snapshot_sha256 = snapshot_ciphertext_sha256(&payload);
    let token = snapshot_token(
        key_bundle,
        "catalog",
        None,
        &snapshot_id,
        None,
        base.as_deref(),
        item_count,
        logical_bytes,
        &content_sha256,
        &sealed_snapshot_sha256,
        created_at_ms,
    )?;
    transaction.execute("DELETE FROM snapshots WHERE target_scope = 'catalog'", [])?;
    transaction.execute(
        "INSERT INTO snapshots (
             snapshot_id, target_scope, conversation_id, source_build_pin_id,
             base_cursor, build_state, item_count, logical_snapshot_bytes,
             content_sha256, sealed_snapshot_sha256, created_at_ms,
             metadata_token, sealed_snapshot
         ) VALUES (?1, 'catalog', NULL, NULL, ?2, 'ready',
                   ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &snapshot_id[..],
            base.as_deref(),
            sqlite_u64(item_count)?,
            sqlite_u64(logical_bytes)?,
            &content_sha256[..],
            &sealed_snapshot_sha256[..],
            sqlite_u64(created_at_ms)?,
            &token[..],
            payload,
        ],
    )?;
    let mut next = ledger.clone();
    next.snapshot_count = projected_count;
    next.snapshot_bytes = projected_bytes;
    let _pending_targets = super::sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
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
    Ok(ReadySnapshotReference {
        snapshot_id,
        target: crate::runtime::events::RuntimeStreamTarget::Catalog,
        base: frozen_base,
        item_count,
        logical_bytes,
        content_sha256,
    })
}

fn cursor_after(candidate: StreamCursor, other: StreamCursor) -> bool {
    match (candidate.high_water(), other.high_water()) {
        (Some(_), None) => true,
        (Some(candidate), Some(other)) => candidate > other,
        _ => false,
    }
}

fn catalog_snapshot_reference(
    snapshot: &StoredCatalogSnapshot,
) -> Result<ReadySnapshotReference, RuntimeStoreError> {
    Ok(ReadySnapshotReference {
        snapshot_id: snapshot.snapshot_id,
        target: crate::runtime::events::RuntimeStreamTarget::Catalog,
        base: StreamCursor::from_high_water(snapshot.base_catalog_revision),
        item_count: snapshot.item_count,
        logical_bytes: u64::try_from(snapshot.payload.len())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        content_sha256: snapshot.content_sha256,
    })
}

fn catalog_snapshot_metadata_reference(
    snapshot: &CatalogSnapshotRowMetadata,
) -> Result<ReadySnapshotReference, RuntimeStoreError> {
    Ok(ReadySnapshotReference {
        snapshot_id: snapshot.snapshot_id,
        target: crate::runtime::events::RuntimeStreamTarget::Catalog,
        base: StreamCursor::from_high_water(snapshot.base_catalog_revision),
        item_count: snapshot.item_count,
        logical_bytes: snapshot.logical_bytes,
        content_sha256: snapshot.content_sha256,
    })
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
                    logical_snapshot_bytes, content_sha256, sealed_snapshot_sha256,
                    created_at_ms, metadata_token, length(sealed_snapshot)
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
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let sealed_blob_len =
        usize::try_from(raw.9).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let maximum_blob_len = MAX_SNAPSHOT_BYTES
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    if sealed_blob_len > maximum_blob_len {
        return Err(super::cipher::CipherError::InputTooLarge.into());
    }
    if sealed_blob_len < ROW_BLOB_V1_OVERHEAD_LEN {
        return Err(super::cipher::CipherError::InvalidEncoding.into());
    }
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
    let sealed_snapshot_sha256: [u8; 32] = raw
        .6
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.7).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
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
            &sealed_snapshot_sha256,
            &created_at_ms.to_be_bytes(),
        ],
        &raw.8,
    )? {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut payload = connection
        .query_row(
            "SELECT sealed_snapshot
             FROM snapshots
             WHERE snapshot_id = ?1 AND target_scope = 'conversation'
               AND conversation_id = ?2 AND build_state = 'ready'",
            params![&snapshot_id[..], &conversation_id.as_bytes()[..]],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    #[cfg(test)]
    observe_snapshot_blob_materialized(payload.capacity());
    if payload.len() != sealed_blob_len {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if snapshot_ciphertext_sha256(&payload) != sealed_snapshot_sha256 {
        return Err(super::cipher::CipherError::AuthenticationFailed.into());
    }
    open_snapshot_payload_read_in_place(read_crypto, database_id, &snapshot_id, &mut payload)?;
    #[cfg(test)]
    observe_snapshot_read_peak(payload.capacity());
    if payload.len()
        != usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(payload.as_slice())) != content_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let base_event_seq = raw
        .2
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()?;
    Ok(Some(StoredConversationSnapshot {
        conversation_id,
        snapshot_id,
        source_build_pin_id,
        base_event_seq,
        item_count,
        content_sha256,
        created_at_ms,
        payload,
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
    sealed_snapshot_sha256: &[u8; 32],
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
            sealed_snapshot_sha256,
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
mod tests;
