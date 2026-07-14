//! Runtime v4 transport-neutral durable publication outbox。

mod directory;
mod rotation;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};
use crate::runtime::read_pool::ReadMemoryLease;

use super::cipher::RuntimeKeyBundle;
use super::identity::{RuntimeId, RuntimeIdKind};
use super::sequence::{SequenceScope, decode_sequence, encode_sequence, next_sequence};
use super::sqlite::{RuntimeLedger, RuntimeSqlite};
use super::stream::{metadata_mac, open_v4_row, optional_field, seal_v4_row, sqlite_u64};

pub(super) use directory::{authenticate_directory, load_pending_publication_stream_ids};
pub(super) use rotation::rotate_publication_stream;

pub(crate) const MAX_PUBLICATION_BLOB_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_PUBLICATION_ROWS_PER_STREAM: u64 = 2_000;
pub(crate) const MAX_PUBLICATION_BYTES_PER_STREAM: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_PUBLICATION_ROWS_GLOBAL: u64 = 10_000;
pub(crate) const MAX_PUBLICATION_BYTES_GLOBAL: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_PENDING_PUBLICATION_PAGE_BYTES: u64 = 8 * 1024 * 1024;
const STREAM_TOKEN_DOMAIN: &[u8] = b"publication.stream.v1";
const OUTBOX_TOKEN_DOMAIN: &[u8] = b"publication.outbox.v1";
const FREEZE_REQUEST_DIGEST_DOMAIN: &[u8] = b"publication.freeze-request.v1";

#[derive(Clone, Copy)]
struct PublicationLimits {
    rows_per_stream: u64,
    bytes_per_stream: u64,
    rows_global: u64,
    bytes_global: u64,
}

const PRODUCTION_LIMITS: PublicationLimits = PublicationLimits {
    rows_per_stream: MAX_PUBLICATION_ROWS_PER_STREAM,
    bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
    rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
    bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublicationScope {
    Catalog,
    Conversation(RuntimeId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationStreamState {
    Active,
    NeedsSnapshot,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationPayloadKind {
    Event,
    Catalog,
    Snapshot,
    Control,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationStreamRecord {
    pub publication_stream_id: [u8; 16],
    pub scope: PublicationScope,
    pub stream_route: [u8; 16],
    pub generation: [u8; 16],
    pub counter_scope_token: Option<[u8; 32]>,
    pub sender_counter_high_water: Option<u64>,
    pub reserved_high_water: Option<u64>,
    pub committed_high_water: Option<u64>,
    pub committed_inner_cursor: Option<u64>,
    pub last_committed_blob_hash: Option<[u8; 32]>,
    pub acknowledged_high_water: Option<u64>,
    pub acknowledged_inner_cursor: Option<u64>,
    pub last_acknowledged_blob_hash: Option<[u8; 32]>,
    /// 威胁场景：dispatcher 在 ACK 后因 COMMIT unknown 重放同一 publicationId，若删除
    /// outbox 后没有认证 tombstone，就会把已消费 frame 当成新发布再次发送。
    /// 有界 MVP 只保留最新一次 delivery ACK 的 publication identity。
    pub last_acknowledged_publication_id: Option<[u8; 16]>,
    pub last_acknowledged_request_digest: Option<[u8; 32]>,
    /// 只保留最近一次原地 rollover 请求，用于 COMMIT unknown exact retry。
    pub last_rotation_request_digest: Option<[u8; 32]>,
    /// store-authenticated 单调 lineage；0 表示 caller 提供的初始 identity。
    pub rotation_serial: u64,
    pub state: PublicationStreamState,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezePublicationRequest {
    pub publication_id: [u8; 16],
    pub publication_stream_id: [u8; 16],
    pub generation: [u8; 16],
    pub counter_scope_token: [u8; 32],
    pub sender_counter: u64,
    /// exclusive；`None` 表示 BeforeFirst。
    pub inner_after: Option<u64>,
    /// inclusive；control frame 可与 after 同时为 None。
    pub inner_through: Option<u64>,
    pub payload_kind: PublicationPayloadKind,
    /// P3 可注入 fake sealed blob；P4 只传已 seal 一次的 exact bytes。
    pub blob: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotatePublicationStreamRequest {
    pub publication_stream_id: [u8; 16],
    pub expected_generation: [u8; 16],
}

#[derive(Debug)]
pub struct FrozenPublication {
    pub publication_id: [u8; 16],
    pub publication_stream_id: [u8; 16],
    pub generation: [u8; 16],
    pub stream_seq: u64,
    pub counter_scope_token: [u8; 32],
    pub sender_counter: u64,
    pub inner_after: Option<u64>,
    pub inner_through: Option<u64>,
    pub payload_kind: PublicationPayloadKind,
    pub blob_sha256: [u8; 32],
    pub created_at_ms: u64,
    pub blob: Vec<u8>,
    pub(crate) memory_lease: Option<ReadMemoryLease>,
}

impl PartialEq for FrozenPublication {
    fn eq(&self, other: &Self) -> bool {
        self.publication_id == other.publication_id
            && self.publication_stream_id == other.publication_stream_id
            && self.generation == other.generation
            && self.stream_seq == other.stream_seq
            && self.counter_scope_token == other.counter_scope_token
            && self.sender_counter == other.sender_counter
            && self.inner_after == other.inner_after
            && self.inner_through == other.inner_through
            && self.payload_kind == other.payload_kind
            && self.blob_sha256 == other.blob_sha256
            && self.created_at_ms == other.created_at_ms
            && self.blob == other.blob
    }
}

impl Eq for FrozenPublication {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationBarrierCut {
    pub publication_stream_id: [u8; 16],
    pub generation: [u8; 16],
    pub committed_outer_cursor: Option<u64>,
    pub committed_inner_cursor: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationAcknowledgement {
    pub publication_stream_id: [u8; 16],
    pub generation: [u8; 16],
    pub acknowledged_outer_cursor: Option<u64>,
    pub acknowledged_inner_cursor: Option<u64>,
}

pub(super) fn create_publication_stream(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    publication_stream_id: [u8; 16],
    scope: PublicationScope,
    stream_route: [u8; 16],
    generation: [u8; 16],
    now_ms: u64,
) -> Result<PublicationStreamRecord, RuntimeStoreError> {
    validate_nonzero_id(publication_stream_id)?;
    validate_nonzero_id(stream_route)?;
    validate_nonzero_id(generation)?;
    validate_scope(scope)?;
    if let Some(existing) =
        load_optional_stream(&state.connection, &state.key_bundle, publication_stream_id)?
    {
        if existing.scope == scope
            && existing.stream_route == stream_route
            && existing.generation == generation
        {
            return Ok(existing);
        }
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        1024 * 1024,
        super::sqlite::SafetyReserveProjection::Current,
    )?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let PublicationScope::Conversation(conversation_id) = scope {
        let exists: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id = ?1)",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Err(RuntimeStoreError::ConversationNotFound);
        }
    }
    let ledger = super::sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let next_count = ledger
        .publication_stream_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if next_count > 1_025 {
        return Err(RuntimeStoreError::ConversationLimit);
    }
    let record = PublicationStreamRecord {
        publication_stream_id,
        scope,
        stream_route,
        generation,
        counter_scope_token: None,
        sender_counter_high_water: None,
        reserved_high_water: None,
        committed_high_water: None,
        committed_inner_cursor: None,
        last_committed_blob_hash: None,
        acknowledged_high_water: None,
        acknowledged_inner_cursor: None,
        last_acknowledged_blob_hash: None,
        last_acknowledged_publication_id: None,
        last_acknowledged_request_digest: None,
        last_rotation_request_digest: None,
        rotation_serial: 0,
        state: PublicationStreamState::Active,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    insert_stream(&transaction, key_bundle, &record)?;
    let mut next = ledger.clone();
    next.publication_stream_count = next_count;
    let _pending_targets = super::sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    commit_with_faults(
        transaction,
        config,
        RuntimeStoreOperation::CreatePublicationStreamBeforeCommit,
        RuntimeCommitOperation::CreatePublicationStream,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::CreatePublicationStreamAfterCommit,
        RuntimeCommitOperation::CreatePublicationStream,
    )?;
    Ok(record)
}

pub(super) fn freeze_publication(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    request: FreezePublicationRequest,
    now_ms: u64,
) -> Result<FrozenPublication, RuntimeStoreError> {
    freeze_publication_with_limits(state, config, request, now_ms, PRODUCTION_LIMITS)
}

fn freeze_publication_with_limits(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    request: FreezePublicationRequest,
    now_ms: u64,
    limits: PublicationLimits,
) -> Result<FrozenPublication, RuntimeStoreError> {
    validate_nonzero_id(request.publication_id)?;
    validate_nonzero_id(request.publication_stream_id)?;
    validate_nonzero_id(request.generation)?;
    if request.counter_scope_token == [0; 32]
        || request.blob.is_empty()
        || request.blob.len() > MAX_PUBLICATION_BLOB_BYTES
    {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    validate_inner_range(
        request.inner_after,
        request.inner_through,
        request.payload_kind,
    )?;
    let blob_sha256: [u8; 32] = Sha256::digest(&request.blob).into();
    let logical_bytes =
        u64::try_from(request.blob.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let request_digest = freeze_request_digest(
        request.publication_stream_id,
        request.generation,
        request.counter_scope_token,
        request.sender_counter,
        request.inner_after,
        request.inner_through,
        request.payload_kind,
        blob_sha256,
        logical_bytes,
    );
    if let Some(stream) = load_optional_stream(
        &state.connection,
        &state.key_bundle,
        request.publication_stream_id,
    )? {
        reject_acknowledged_freeze(&stream, request.publication_id, request_digest)?;
    }
    if let Some(existing) = load_optional_outbox(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        request.publication_id,
    )? {
        if frozen_matches_request(&existing, &request) {
            return Ok(existing);
        }
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let projected_write_bytes = u64::try_from(request.blob.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
        .checked_add(1024 * 1024)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "publication projected write bytes",
        })?;
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
    let mut stream = load_stream(&transaction, key_bundle, request.publication_stream_id)?;
    reject_acknowledged_freeze(&stream, request.publication_id, request_digest)?;
    if stream.generation != request.generation || stream.state != PublicationStreamState::Active {
        return Err(if stream.state == PublicationStreamState::NeedsSnapshot {
            RuntimeStoreError::PublicationNeedsSnapshot
        } else {
            RuntimeStoreError::PublicationMismatch
        });
    }
    if now_ms < stream.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: stream.updated_at_ms,
            observed_ms: now_ms,
        });
    }
    let bound_stream: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT publication_stream_id FROM publication_streams
             WHERE counter_scope_token = ?1",
            [&request.counter_scope_token[..]],
            |row| row.get(0),
        )
        .optional()?;
    if bound_stream
        .as_deref()
        .is_some_and(|bound| bound != request.publication_stream_id)
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    match (stream.counter_scope_token, stream.sender_counter_high_water) {
        (None, None) => {}
        (Some(scope), Some(high_water))
            if scope == request.counter_scope_token && request.sender_counter > high_water => {}
        _ => return Err(RuntimeStoreError::PublicationMismatch),
    }
    let ledger = super::sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let reserved_high_water = stream.reserved_high_water.map(encode_sequence);
    let stream_seq = next_sequence(SequenceScope::EventSeq, reserved_high_water.as_deref())?;
    let expected_inner_after = latest_reserved_inner_cursor(&transaction, &stream)?;
    if request.inner_through.is_some() && request.inner_after != expected_inner_after {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let (stream_count, stream_bytes): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(logical_blob_bytes), 0)
         FROM publication_outbox WHERE publication_stream_id = ?1",
        [&request.publication_stream_id[..]],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let projected_stream_count = u64::try_from(stream_count)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let projected_stream_bytes = u64::try_from(stream_bytes)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        .checked_add(logical_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let projected_global_count = ledger
        .publication_outbox_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let projected_global_bytes = ledger
        .publication_outbox_bytes
        .checked_add(logical_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if projected_stream_count > limits.rows_per_stream
        || projected_stream_bytes > limits.bytes_per_stream
        || projected_global_count > limits.rows_global
        || projected_global_bytes > limits.bytes_global
    {
        stream.state = PublicationStreamState::NeedsSnapshot;
        stream.updated_at_ms = now_ms;
        update_stream(&transaction, key_bundle, &stream)?;
        let _pending_targets = super::sqlite::update_runtime_ledger(
            &transaction,
            key_bundle,
            database_id,
            &ledger,
            &ledger,
        )?;
        commit_with_faults(
            transaction,
            config,
            RuntimeStoreOperation::FreezePublicationBeforeCommit,
            RuntimeCommitOperation::FreezePublication,
        )?;
        super::sqlite::latch_post_commit_capacity(state, config);
        after_commit(
            config,
            RuntimeStoreOperation::FreezePublicationAfterCommit,
            RuntimeCommitOperation::FreezePublication,
        )?;
        return Err(RuntimeStoreError::PublicationNeedsSnapshot);
    }
    let stream_seq_encoded = stream_seq.encoded.clone();
    let inner_after = request.inner_after.map(encode_sequence);
    let inner_through = request.inner_through.map(encode_sequence);
    let sealed = seal_v4_row(
        key_bundle,
        database_id,
        b"publication_outbox",
        &request.publication_id,
        b"sealed_publication",
        &request.blob,
        MAX_PUBLICATION_BLOB_BYTES,
    )?;
    let token = outbox_token(
        key_bundle,
        request.publication_id,
        request.publication_stream_id,
        request.generation,
        &stream_seq_encoded,
        request.counter_scope_token,
        request.sender_counter,
        inner_after.as_deref(),
        inner_through.as_deref(),
        request.payload_kind,
        blob_sha256,
        logical_bytes,
        now_ms,
    )?;
    transaction.execute(
        "INSERT INTO publication_outbox (
             publication_id, publication_stream_id, generation, stream_seq,
             counter_scope_token, sender_counter, inner_after_seq, inner_through_seq,
             payload_kind, blob_sha256, logical_blob_bytes, created_at_ms,
             metadata_token, sealed_publication
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            &request.publication_id[..],
            &request.publication_stream_id[..],
            &request.generation[..],
            &stream_seq_encoded,
            &request.counter_scope_token[..],
            encode_sequence(request.sender_counter),
            inner_after.as_deref(),
            inner_through.as_deref(),
            payload_kind_text(request.payload_kind),
            &blob_sha256[..],
            sqlite_u64(logical_bytes)?,
            sqlite_u64(now_ms)?,
            &token[..],
            sealed,
        ],
    )?;
    stream.counter_scope_token = Some(request.counter_scope_token);
    stream.sender_counter_high_water = Some(request.sender_counter);
    stream.reserved_high_water = Some(stream_seq.value);
    if stream_seq.value == u64::MAX || request.sender_counter == u64::MAX {
        stream.state = PublicationStreamState::NeedsSnapshot;
    }
    stream.updated_at_ms = now_ms;
    update_stream(&transaction, key_bundle, &stream)?;
    let mut next = ledger.clone();
    next.publication_outbox_count = projected_global_count;
    next.publication_outbox_bytes = projected_global_bytes;
    let _pending_targets = super::sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    commit_with_faults(
        transaction,
        config,
        RuntimeStoreOperation::FreezePublicationBeforeCommit,
        RuntimeCommitOperation::FreezePublication,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::FreezePublicationAfterCommit,
        RuntimeCommitOperation::FreezePublication,
    )?;
    Ok(FrozenPublication {
        publication_id: request.publication_id,
        publication_stream_id: request.publication_stream_id,
        generation: request.generation,
        stream_seq: stream_seq.value,
        counter_scope_token: request.counter_scope_token,
        sender_counter: request.sender_counter,
        inner_after: request.inner_after,
        inner_through: request.inner_through,
        payload_kind: request.payload_kind,
        blob_sha256,
        created_at_ms: now_ms,
        blob: request.blob,
        memory_lease: None,
    })
}

/// Relay RouteAccepted/COMMIT 只推进严格对应的 committed outer+inner cut。
/// exact blob 必须继续留在 outbox，直到 device ACK；COMMIT 绝不具备 retention
/// eligibility，也不能与终端消费 ACK 合并。
pub(super) fn acknowledge_publication_commit(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    stream_seq: u64,
    blob_sha256: [u8; 32],
    now_ms: u64,
) -> Result<PublicationBarrierCut, RuntimeStoreError> {
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut stream = load_stream(&transaction, key_bundle, publication_stream_id)?;
    if stream.generation != generation {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if stream.committed_high_water == Some(stream_seq)
        && stream.last_committed_blob_hash == Some(blob_sha256)
    {
        return Ok(barrier_cut(&stream));
    }
    if now_ms < stream.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: stream.updated_at_ms,
            observed_ms: now_ms,
        });
    }
    let expected = stream
        .committed_high_water
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if stream_seq != expected {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let publication = load_outbox_by_stream_seq(
        &transaction,
        key_bundle,
        database_id,
        publication_stream_id,
        generation,
        stream_seq,
    )?;
    if publication.blob_sha256 != blob_sha256 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let committed_inner_cursor = match publication.inner_through {
        Some(through) if publication.inner_after == stream.committed_inner_cursor => Some(through),
        None if publication.payload_kind == PublicationPayloadKind::Control
            && publication.inner_after.is_none() =>
        {
            stream.committed_inner_cursor
        }
        _ => return Err(RuntimeStoreError::PublicationMismatch),
    };
    stream.committed_high_water = Some(stream_seq);
    stream.committed_inner_cursor = committed_inner_cursor;
    stream.last_committed_blob_hash = Some(blob_sha256);
    stream.updated_at_ms = now_ms;
    update_stream(&transaction, key_bundle, &stream)?;
    commit_with_faults(
        transaction,
        config,
        RuntimeStoreOperation::CommitPublicationBeforeCommit,
        RuntimeCommitOperation::CommitPublication,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::CommitPublicationAfterCommit,
        RuntimeCommitOperation::CommitPublication,
    )?;
    Ok(barrier_cut(&stream))
}

/// device 对已 Relay-COMMIT frame 的 exact consumption ACK。只有本事务成功后，
/// 对应 outbox row 才 retention eligible 并删除；错误 generation/seq/hash 一律
/// fail-closed，exact retry 由 stream 上的 acknowledged cursor/hash 回放。
pub(super) fn acknowledge_publication_delivery(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    stream_seq: u64,
    blob_sha256: [u8; 32],
    now_ms: u64,
) -> Result<PublicationAcknowledgement, RuntimeStoreError> {
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut stream = load_stream(&transaction, key_bundle, publication_stream_id)?;
    if stream.generation != generation {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if stream.acknowledged_high_water == Some(stream_seq)
        && stream.last_acknowledged_blob_hash == Some(blob_sha256)
    {
        return Ok(acknowledgement_cut(&stream));
    }
    if now_ms < stream.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: stream.updated_at_ms,
            observed_ms: now_ms,
        });
    }
    let expected = stream
        .acknowledged_high_water
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if stream_seq != expected
        || stream
            .committed_high_water
            .is_none_or(|cut| stream_seq > cut)
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let publication = load_outbox_by_stream_seq(
        &transaction,
        key_bundle,
        database_id,
        publication_stream_id,
        generation,
        stream_seq,
    )?;
    if publication.blob_sha256 != blob_sha256 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let request_digest = frozen_request_digest(&publication)?;
    let acknowledged_inner_cursor = match publication.inner_through {
        Some(through) if publication.inner_after == stream.acknowledged_inner_cursor => {
            Some(through)
        }
        None if publication.payload_kind == PublicationPayloadKind::Control
            && publication.inner_after.is_none() =>
        {
            stream.acknowledged_inner_cursor
        }
        _ => return Err(RuntimeStoreError::PublicationMismatch),
    };
    let ledger = super::sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    if transaction.execute(
        "DELETE FROM publication_outbox WHERE publication_id = ?1",
        [&publication.publication_id[..]],
    )? != 1
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    stream.acknowledged_high_water = Some(stream_seq);
    stream.acknowledged_inner_cursor = acknowledged_inner_cursor;
    stream.last_acknowledged_blob_hash = Some(blob_sha256);
    stream.last_acknowledged_publication_id = Some(publication.publication_id);
    stream.last_acknowledged_request_digest = Some(request_digest);
    stream.updated_at_ms = now_ms;
    update_stream(&transaction, key_bundle, &stream)?;
    let logical_bytes = u64::try_from(publication.blob.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let mut next = ledger.clone();
    next.publication_outbox_count = next
        .publication_outbox_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.publication_outbox_bytes = next
        .publication_outbox_bytes
        .checked_sub(logical_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _pending_targets = super::sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    commit_with_faults(
        transaction,
        config,
        RuntimeStoreOperation::AcknowledgePublicationBeforeCommit,
        RuntimeCommitOperation::AcknowledgePublication,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::AcknowledgePublicationAfterCommit,
        RuntimeCommitOperation::AcknowledgePublication,
    )?;
    Ok(acknowledgement_cut(&stream))
}

#[cfg(test)]
pub(super) fn load_pending_publications(
    state: &RuntimeSqlite,
    publication_stream_id: [u8; 16],
) -> Result<Vec<FrozenPublication>, RuntimeStoreError> {
    let read_crypto = state.key_bundle.read_only_capability();
    load_pending_publications_read(
        &state.connection,
        &read_crypto,
        state.database_id,
        publication_stream_id,
    )
}

pub(super) fn load_pending_publications_read(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    publication_stream_id: [u8; 16],
) -> Result<Vec<FrozenPublication>, RuntimeStoreError> {
    let stream = load_stream_read(connection, read_crypto, publication_stream_id)?;
    let mut ids = Vec::new();
    let mut bytes = 0_u64;
    let mut statement = connection.prepare(
        "SELECT publication_id, logical_blob_bytes FROM publication_outbox
         WHERE publication_stream_id = ?1 AND generation = ?2
           AND (?3 IS NULL OR stream_seq > ?3)
         ORDER BY stream_seq LIMIT 64",
    )?;
    let rows = statement.query_map(
        params![
            &publication_stream_id[..],
            &stream.generation[..],
            stream.committed_high_water.map(encode_sequence),
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    for row in rows {
        let (id, logical_bytes) = row?;
        let logical_bytes =
            u64::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if !ids.is_empty()
            && bytes
                .checked_add(logical_bytes)
                .ok_or(RuntimeStoreError::PayloadTooLarge)?
                > MAX_PENDING_PUBLICATION_PAGE_BYTES
        {
            break;
        }
        bytes = bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        ids.push(id);
    }
    drop(statement);
    let mut rows = Vec::new();
    rows.try_reserve_exact(ids.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for id in ids {
        let id = fixed::<16>(&id)?;
        rows.push(
            load_optional_outbox_read(connection, read_crypto, database_id, id)?
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
    }
    Ok(rows)
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) fn load_publication_barrier(
    state: &RuntimeSqlite,
    publication_stream_id: [u8; 16],
) -> Result<PublicationBarrierCut, RuntimeStoreError> {
    let read_crypto = state.key_bundle.read_only_capability();
    load_publication_barrier_read(&state.connection, &read_crypto, publication_stream_id)
}

pub(super) fn load_publication_barrier_read(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    publication_stream_id: [u8; 16],
) -> Result<PublicationBarrierCut, RuntimeStoreError> {
    Ok(barrier_cut(&load_stream_read(
        connection,
        read_crypto,
        publication_stream_id,
    )?))
}

pub(super) fn validate_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut ids = Vec::new();
    let mut statement = connection.prepare(
        "SELECT publication_stream_id FROM publication_streams
         ORDER BY publication_stream_id",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    for row in rows {
        ids.push(fixed::<16>(&row?)?);
        if ids.len() > 1_025 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);
    let mut outbox_count = 0_u64;
    let mut outbox_bytes = 0_u64;
    for id in &ids {
        let stream = load_stream(connection, key_bundle, *id)?;
        if let PublicationScope::Conversation(conversation_id) = stream.scope {
            let exists: i64 = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id = ?1)",
                [&conversation_id.as_bytes()[..]],
                |row| row.get(0),
            )?;
            if exists == 0 {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        let mut pending_ids = Vec::new();
        let mut statement = connection.prepare(
            "SELECT publication_id FROM publication_outbox
             WHERE publication_stream_id = ?1 AND generation = ?2
             ORDER BY stream_seq",
        )?;
        let rows = statement.query_map(params![&id[..], &stream.generation[..]], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        for row in rows {
            pending_ids.push(fixed::<16>(&row?)?);
            if pending_ids.len()
                > usize::try_from(MAX_PUBLICATION_ROWS_PER_STREAM)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        drop(statement);
        let mut expected_outer = stream
            .acknowledged_high_water
            .map_or(Some(0), |value| value.checked_add(1))
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let mut expected_inner = stream.acknowledged_inner_cursor;
        let mut stream_bytes = 0_u64;
        let mut last_outer = stream.acknowledged_high_water;
        let mut committed_hash_in_outbox = None;
        let mut previous_pending_counter = None;
        for publication_id in pending_ids {
            let publication =
                load_optional_outbox(connection, key_bundle, database_id, publication_id)?
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            if publication.publication_stream_id != *id
                || publication.generation != stream.generation
                || publication.stream_seq != expected_outer
                || Some(publication.counter_scope_token) != stream.counter_scope_token
                || previous_pending_counter
                    .is_some_and(|previous| publication.sender_counter <= previous)
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            previous_pending_counter = Some(publication.sender_counter);
            if let Some(through) = publication.inner_through {
                if publication.inner_after != expected_inner
                    || publication
                        .inner_after
                        .is_some_and(|after| through <= after)
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                expected_inner = Some(through);
            } else if publication.inner_after.is_some()
                || publication.payload_kind != PublicationPayloadKind::Control
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            expected_outer = expected_outer
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            last_outer = Some(publication.stream_seq);
            if Some(publication.stream_seq) == stream.committed_high_water {
                committed_hash_in_outbox = Some(publication.blob_sha256);
            }
            outbox_count = outbox_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            let row_bytes = u64::try_from(publication.blob.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            stream_bytes = stream_bytes
                .checked_add(row_bytes)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            outbox_bytes = outbox_bytes
                .checked_add(row_bytes)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        if stream.reserved_high_water != last_outer
            || previous_pending_counter
                .is_some_and(|counter| Some(counter) != stream.sender_counter_high_water)
            || stream_bytes > MAX_PUBLICATION_BYTES_PER_STREAM
            || (stream.committed_high_water > stream.acknowledged_high_water
                && committed_hash_in_outbox != stream.last_committed_blob_hash)
            || (stream.committed_high_water == stream.acknowledged_high_water
                && stream.committed_high_water.is_some()
                && stream.last_committed_blob_hash != stream.last_acknowledged_blob_hash)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    if u64::try_from(ids.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != ledger.publication_stream_count
        || outbox_count != ledger.publication_outbox_count
        || outbox_bytes != ledger.publication_outbox_bytes
        || outbox_count > MAX_PUBLICATION_ROWS_GLOBAL
        || outbox_bytes > MAX_PUBLICATION_BYTES_GLOBAL
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn insert_stream(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    stream: &PublicationStreamRecord,
) -> Result<(), RuntimeStoreError> {
    let token = stream_token(key_bundle, stream)?;
    let conversation_id = match stream.scope {
        PublicationScope::Catalog => None,
        PublicationScope::Conversation(conversation_id) => Some(*conversation_id.as_bytes()),
    };
    transaction.execute(
        "INSERT INTO publication_streams (
             publication_stream_id, scope, conversation_id, stream_route, generation,
             counter_scope_token, sender_counter_high_water,
             reserved_high_water, committed_high_water, committed_inner_cursor,
             last_committed_blob_hash, acknowledged_high_water,
             acknowledged_inner_cursor, last_acknowledged_blob_hash,
             last_acknowledged_publication_id, last_acknowledged_request_digest,
             last_rotation_request_digest, rotation_serial, state, created_at_ms,
             updated_at_ms, metadata_token
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, NULL, NULL, NULL,
                   NULL, NULL, NULL, NULL, NULL, NULL, '00000000000000000000',
                   ?6, ?7, ?7, ?8)",
        params![
            &stream.publication_stream_id[..],
            scope_text(stream.scope),
            conversation_id.as_ref().map(<[u8; 16]>::as_slice),
            &stream.stream_route[..],
            &stream.generation[..],
            stream_state_text(stream.state),
            sqlite_u64(stream.created_at_ms)?,
            &token[..],
        ],
    )?;
    Ok(())
}

fn update_stream(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    stream: &PublicationStreamRecord,
) -> Result<(), RuntimeStoreError> {
    let token = stream_token(key_bundle, stream)?;
    if transaction.execute(
        "UPDATE publication_streams SET
             counter_scope_token = ?1, sender_counter_high_water = ?2,
             reserved_high_water = ?3, committed_high_water = ?4,
             committed_inner_cursor = ?5, last_committed_blob_hash = ?6,
             acknowledged_high_water = ?7, acknowledged_inner_cursor = ?8,
             last_acknowledged_blob_hash = ?9,
             last_acknowledged_publication_id = ?10,
             last_acknowledged_request_digest = ?11,
             last_rotation_request_digest = ?12,
             rotation_serial = ?13,
             state = ?14, updated_at_ms = ?15, metadata_token = ?16
         WHERE publication_stream_id = ?17 AND generation = ?18",
        params![
            stream
                .counter_scope_token
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            stream.sender_counter_high_water.map(encode_sequence),
            stream.reserved_high_water.map(encode_sequence),
            stream.committed_high_water.map(encode_sequence),
            stream.committed_inner_cursor.map(encode_sequence),
            stream
                .last_committed_blob_hash
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            stream.acknowledged_high_water.map(encode_sequence),
            stream.acknowledged_inner_cursor.map(encode_sequence),
            stream
                .last_acknowledged_blob_hash
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            stream
                .last_acknowledged_publication_id
                .as_ref()
                .map(<[u8; 16]>::as_slice),
            stream
                .last_acknowledged_request_digest
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            stream
                .last_rotation_request_digest
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            encode_sequence(stream.rotation_serial),
            stream_state_text(stream.state),
            sqlite_u64(stream.updated_at_ms)?,
            &token[..],
            &stream.publication_stream_id[..],
            &stream.generation[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn load_optional_stream(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    publication_stream_id: [u8; 16],
) -> Result<Option<PublicationStreamRecord>, RuntimeStoreError> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM publication_streams WHERE publication_stream_id = ?1)",
        [&publication_stream_id[..]],
        |row| row.get(0),
    )?;
    if exists == 0 {
        Ok(None)
    } else {
        load_stream(connection, key_bundle, publication_stream_id).map(Some)
    }
}

fn load_stream(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    publication_stream_id: [u8; 16],
) -> Result<PublicationStreamRecord, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT scope, conversation_id, stream_route, generation, counter_scope_token,
                    sender_counter_high_water, reserved_high_water, committed_high_water,
                    committed_inner_cursor, last_committed_blob_hash, acknowledged_high_water,
                    acknowledged_inner_cursor, last_acknowledged_blob_hash,
                    last_acknowledged_publication_id, last_acknowledged_request_digest,
                    last_rotation_request_digest, rotation_serial, state, created_at_ms,
                    updated_at_ms, metadata_token
             FROM publication_streams WHERE publication_stream_id = ?1",
            [&publication_stream_id[..]],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<Vec<u8>>>(12)?,
                    row.get::<_, Option<Vec<u8>>>(13)?,
                    row.get::<_, Option<Vec<u8>>>(14)?,
                    row.get::<_, Option<Vec<u8>>>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, i64>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::PublicationMismatch,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let scope = parse_scope(&raw.0, raw.1.as_deref())?;
    let record = PublicationStreamRecord {
        publication_stream_id,
        scope,
        stream_route: fixed::<16>(&raw.2)?,
        generation: fixed::<16>(&raw.3)?,
        counter_scope_token: raw.4.as_deref().map(fixed::<32>).transpose()?,
        sender_counter_high_water: decode_optional(&raw.5)?,
        reserved_high_water: decode_optional(&raw.6)?,
        committed_high_water: decode_optional(&raw.7)?,
        committed_inner_cursor: decode_optional(&raw.8)?,
        last_committed_blob_hash: raw.9.as_deref().map(fixed::<32>).transpose()?,
        acknowledged_high_water: decode_optional(&raw.10)?,
        acknowledged_inner_cursor: decode_optional(&raw.11)?,
        last_acknowledged_blob_hash: raw.12.as_deref().map(fixed::<32>).transpose()?,
        last_acknowledged_publication_id: raw.13.as_deref().map(fixed::<16>).transpose()?,
        last_acknowledged_request_digest: raw.14.as_deref().map(fixed::<32>).transpose()?,
        last_rotation_request_digest: raw.15.as_deref().map(fixed::<32>).transpose()?,
        rotation_serial: decode_sequence(SequenceScope::EventSeq, &raw.16)?,
        state: parse_stream_state(&raw.17)?,
        created_at_ms: u64::try_from(raw.18)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        updated_at_ms: u64::try_from(raw.19)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    };
    let expected = stream_token(key_bundle, &record)?;
    if raw.20.as_slice() != expected
        || record.counter_scope_token.is_some() != record.sender_counter_high_water.is_some()
        || record.counter_scope_token == Some([0; 32])
        || record.updated_at_ms < record.created_at_ms
        || record.committed_high_water > record.reserved_high_water
        || record.committed_high_water.is_some() != record.last_committed_blob_hash.is_some()
        || record.acknowledged_high_water > record.committed_high_water
        || record.acknowledged_high_water.is_some() != record.last_acknowledged_blob_hash.is_some()
        || record.last_acknowledged_publication_id.is_some()
            != record.last_acknowledged_request_digest.is_some()
        || (record.rotation_serial == 0) != record.last_rotation_request_digest.is_none()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(record)
}

fn load_stream_read(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    publication_stream_id: [u8; 16],
) -> Result<PublicationStreamRecord, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT scope, conversation_id, stream_route, generation, counter_scope_token,
                    sender_counter_high_water, reserved_high_water, committed_high_water,
                    committed_inner_cursor, last_committed_blob_hash, acknowledged_high_water,
                    acknowledged_inner_cursor, last_acknowledged_blob_hash,
                    last_acknowledged_publication_id, last_acknowledged_request_digest,
                    last_rotation_request_digest, rotation_serial, state, created_at_ms,
                    updated_at_ms, metadata_token
             FROM publication_streams WHERE publication_stream_id = ?1",
            [&publication_stream_id[..]],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<Vec<u8>>>(12)?,
                    row.get::<_, Option<Vec<u8>>>(13)?,
                    row.get::<_, Option<Vec<u8>>>(14)?,
                    row.get::<_, Option<Vec<u8>>>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, i64>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::PublicationMismatch,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let scope = parse_scope(&raw.0, raw.1.as_deref())?;
    let record = PublicationStreamRecord {
        publication_stream_id,
        scope,
        stream_route: fixed::<16>(&raw.2)?,
        generation: fixed::<16>(&raw.3)?,
        counter_scope_token: raw.4.as_deref().map(fixed::<32>).transpose()?,
        sender_counter_high_water: decode_optional(&raw.5)?,
        reserved_high_water: decode_optional(&raw.6)?,
        committed_high_water: decode_optional(&raw.7)?,
        committed_inner_cursor: decode_optional(&raw.8)?,
        last_committed_blob_hash: raw.9.as_deref().map(fixed::<32>).transpose()?,
        acknowledged_high_water: decode_optional(&raw.10)?,
        acknowledged_inner_cursor: decode_optional(&raw.11)?,
        last_acknowledged_blob_hash: raw.12.as_deref().map(fixed::<32>).transpose()?,
        last_acknowledged_publication_id: raw.13.as_deref().map(fixed::<16>).transpose()?,
        last_acknowledged_request_digest: raw.14.as_deref().map(fixed::<32>).transpose()?,
        last_rotation_request_digest: raw.15.as_deref().map(fixed::<32>).transpose()?,
        rotation_serial: decode_sequence(SequenceScope::EventSeq, &raw.16)?,
        state: parse_stream_state(&raw.17)?,
        created_at_ms: u64::try_from(raw.18)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        updated_at_ms: u64::try_from(raw.19)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    };
    if !verify_stream_token(read_crypto, &record, &raw.20)?
        || record.counter_scope_token.is_some() != record.sender_counter_high_water.is_some()
        || record.counter_scope_token == Some([0; 32])
        || record.updated_at_ms < record.created_at_ms
        || record.committed_high_water > record.reserved_high_water
        || record.committed_high_water.is_some() != record.last_committed_blob_hash.is_some()
        || record.acknowledged_high_water > record.committed_high_water
        || record.acknowledged_high_water.is_some() != record.last_acknowledged_blob_hash.is_some()
        || record.last_acknowledged_publication_id.is_some()
            != record.last_acknowledged_request_digest.is_some()
        || (record.rotation_serial == 0) != record.last_rotation_request_digest.is_none()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(record)
}

fn load_outbox_by_stream_seq(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    stream_seq: u64,
) -> Result<FrozenPublication, RuntimeStoreError> {
    let id: Vec<u8> = connection
        .query_row(
            "SELECT publication_id FROM publication_outbox
             WHERE publication_stream_id = ?1 AND generation = ?2 AND stream_seq = ?3",
            params![
                &publication_stream_id[..],
                &generation[..],
                encode_sequence(stream_seq),
            ],
            |row| row.get(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::PublicationMismatch,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    load_optional_outbox(connection, key_bundle, database_id, fixed::<16>(&id)?)?
        .ok_or(RuntimeStoreError::PublicationMismatch)
}

fn load_optional_outbox(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    publication_id: [u8; 16],
) -> Result<Option<FrozenPublication>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT publication_stream_id, generation, stream_seq, counter_scope_token,
                    sender_counter, inner_after_seq, inner_through_seq, payload_kind,
                    blob_sha256, logical_blob_bytes, created_at_ms, metadata_token,
                    sealed_publication
             FROM publication_outbox WHERE publication_id = ?1",
            [&publication_id[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let publication_stream_id = fixed::<16>(&raw.0)?;
    let generation = fixed::<16>(&raw.1)?;
    let stream_seq = decode_sequence(SequenceScope::EventSeq, &raw.2)?;
    let counter_scope_token = fixed::<32>(&raw.3)?;
    let sender_counter = decode_sequence(SequenceScope::EventSeq, &raw.4)?;
    let inner_after = decode_optional(&raw.5)?;
    let inner_through = decode_optional(&raw.6)?;
    let payload_kind = parse_payload_kind(&raw.7)?;
    validate_inner_range(inner_after, inner_through, payload_kind)?;
    let blob_sha256 = fixed::<32>(&raw.8)?;
    let logical_bytes =
        u64::try_from(raw.9).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.10).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected = outbox_token(
        key_bundle,
        publication_id,
        publication_stream_id,
        generation,
        &raw.2,
        counter_scope_token,
        sender_counter,
        raw.5.as_deref(),
        raw.6.as_deref(),
        payload_kind,
        blob_sha256,
        logical_bytes,
        created_at_ms,
    )?;
    if raw.11.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open_v4_row(
        key_bundle,
        database_id,
        b"publication_outbox",
        &publication_id,
        b"sealed_publication",
        &raw.12,
        MAX_PUBLICATION_BLOB_BYTES,
    )?;
    if plaintext.expose_secret().len()
        != usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(plaintext.expose_secret())) != blob_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    drop(raw);
    Ok(Some(FrozenPublication {
        publication_id,
        publication_stream_id,
        generation,
        stream_seq,
        counter_scope_token,
        sender_counter,
        inner_after,
        inner_through,
        payload_kind,
        blob_sha256,
        created_at_ms,
        blob: plaintext.expose_secret().to_vec(),
        memory_lease: None,
    }))
}

fn load_optional_outbox_read(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    publication_id: [u8; 16],
) -> Result<Option<FrozenPublication>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT publication_stream_id, generation, stream_seq, counter_scope_token,
                    sender_counter, inner_after_seq, inner_through_seq, payload_kind,
                    blob_sha256, logical_blob_bytes, created_at_ms, metadata_token,
                    sealed_publication
             FROM publication_outbox WHERE publication_id = ?1",
            [&publication_id[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let publication_stream_id = fixed::<16>(&raw.0)?;
    let generation = fixed::<16>(&raw.1)?;
    let stream_seq = decode_sequence(SequenceScope::EventSeq, &raw.2)?;
    let counter_scope_token = fixed::<32>(&raw.3)?;
    let sender_counter = decode_sequence(SequenceScope::EventSeq, &raw.4)?;
    let inner_after = decode_optional(&raw.5)?;
    let inner_through = decode_optional(&raw.6)?;
    let payload_kind = parse_payload_kind(&raw.7)?;
    validate_inner_range(inner_after, inner_through, payload_kind)?;
    let blob_sha256 = fixed::<32>(&raw.8)?;
    let logical_bytes =
        u64::try_from(raw.9).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.10).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let after = optional_field(raw.5.as_deref().map(str::as_bytes));
    let through = optional_field(raw.6.as_deref().map(str::as_bytes));
    if !super::stream::verify_metadata_mac(
        read_crypto,
        OUTBOX_TOKEN_DOMAIN,
        &[
            &publication_id,
            &publication_stream_id,
            &generation,
            raw.2.as_bytes(),
            &counter_scope_token,
            &sender_counter.to_be_bytes(),
            &after,
            &through,
            payload_kind_text(payload_kind).as_bytes(),
            &blob_sha256,
            &logical_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
        &raw.11,
    )? {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = super::stream::open_v4_row_read(
        read_crypto,
        database_id,
        b"publication_outbox",
        &publication_id,
        b"sealed_publication",
        &raw.12,
        MAX_PUBLICATION_BLOB_BYTES,
    )?;
    if plaintext.expose_secret().len()
        != usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(plaintext.expose_secret())) != blob_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    drop(raw);
    Ok(Some(FrozenPublication {
        publication_id,
        publication_stream_id,
        generation,
        stream_seq,
        counter_scope_token,
        sender_counter,
        inner_after,
        inner_through,
        payload_kind,
        blob_sha256,
        created_at_ms,
        blob: plaintext.expose_secret().to_vec(),
        memory_lease: None,
    }))
}

fn latest_reserved_inner_cursor(
    transaction: &Transaction<'_>,
    stream: &PublicationStreamRecord,
) -> Result<Option<u64>, RuntimeStoreError> {
    let latest: Option<Option<String>> = transaction
        .query_row(
            "SELECT inner_through_seq FROM publication_outbox
             WHERE publication_stream_id = ?1 AND generation = ?2
               AND inner_through_seq IS NOT NULL
             ORDER BY stream_seq DESC LIMIT 1",
            params![&stream.publication_stream_id[..], &stream.generation[..]],
            |row| row.get(0),
        )
        .optional()?;
    match latest {
        Some(Some(value)) => Ok(Some(decode_sequence(SequenceScope::EventSeq, &value)?)),
        Some(None) => Ok(stream.committed_inner_cursor),
        None => Ok(stream.committed_inner_cursor),
    }
}

fn frozen_matches_request(frozen: &FrozenPublication, request: &FreezePublicationRequest) -> bool {
    frozen.publication_id == request.publication_id
        && frozen.publication_stream_id == request.publication_stream_id
        && frozen.generation == request.generation
        && frozen.counter_scope_token == request.counter_scope_token
        && frozen.sender_counter == request.sender_counter
        && frozen.inner_after == request.inner_after
        && frozen.inner_through == request.inner_through
        && frozen.payload_kind == request.payload_kind
        && frozen.blob == request.blob
}

fn reject_acknowledged_freeze(
    stream: &PublicationStreamRecord,
    publication_id: [u8; 16],
    request_digest: [u8; 32],
) -> Result<(), RuntimeStoreError> {
    if stream.last_acknowledged_publication_id != Some(publication_id) {
        return Ok(());
    }
    if stream.last_acknowledged_request_digest == Some(request_digest) {
        Err(RuntimeStoreError::PublicationAlreadyAcknowledged)
    } else {
        Err(RuntimeStoreError::PublicationMismatch)
    }
}

fn frozen_request_digest(publication: &FrozenPublication) -> Result<[u8; 32], RuntimeStoreError> {
    let logical_bytes = u64::try_from(publication.blob.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(freeze_request_digest(
        publication.publication_stream_id,
        publication.generation,
        publication.counter_scope_token,
        publication.sender_counter,
        publication.inner_after,
        publication.inner_through,
        publication.payload_kind,
        publication.blob_sha256,
        logical_bytes,
    ))
}

#[allow(clippy::too_many_arguments)]
fn freeze_request_digest(
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    counter_scope_token: [u8; 32],
    sender_counter: u64,
    inner_after: Option<u64>,
    inner_through: Option<u64>,
    payload_kind: PublicationPayloadKind,
    blob_sha256: [u8; 32],
    logical_blob_bytes: u64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(FREEZE_REQUEST_DIGEST_DOMAIN);
    digest.update(publication_stream_id);
    digest.update(generation);
    digest.update(counter_scope_token);
    digest.update(sender_counter.to_be_bytes());
    update_optional_cursor_digest(&mut digest, inner_after);
    update_optional_cursor_digest(&mut digest, inner_through);
    digest.update([payload_kind_tag(payload_kind)]);
    digest.update(blob_sha256);
    digest.update(logical_blob_bytes.to_be_bytes());
    digest.finalize().into()
}

fn update_optional_cursor_digest(digest: &mut Sha256, cursor: Option<u64>) {
    match cursor {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

const fn payload_kind_tag(kind: PublicationPayloadKind) -> u8 {
    match kind {
        PublicationPayloadKind::Event => 1,
        PublicationPayloadKind::Catalog => 2,
        PublicationPayloadKind::Snapshot => 3,
        PublicationPayloadKind::Control => 4,
    }
}

fn barrier_cut(stream: &PublicationStreamRecord) -> PublicationBarrierCut {
    PublicationBarrierCut {
        publication_stream_id: stream.publication_stream_id,
        generation: stream.generation,
        committed_outer_cursor: stream.committed_high_water,
        committed_inner_cursor: stream.committed_inner_cursor,
    }
}

fn acknowledgement_cut(stream: &PublicationStreamRecord) -> PublicationAcknowledgement {
    PublicationAcknowledgement {
        publication_stream_id: stream.publication_stream_id,
        generation: stream.generation,
        acknowledged_outer_cursor: stream.acknowledged_high_water,
        acknowledged_inner_cursor: stream.acknowledged_inner_cursor,
    }
}

fn stream_token(
    key_bundle: &RuntimeKeyBundle,
    stream: &PublicationStreamRecord,
) -> Result<[u8; 32], RuntimeStoreError> {
    let conversation_id = match stream.scope {
        PublicationScope::Catalog => None,
        PublicationScope::Conversation(conversation_id) => Some(*conversation_id.as_bytes()),
    };
    let conversation = optional_field(conversation_id.as_ref().map(<[u8; 16]>::as_slice));
    let counter_scope = optional_field(
        stream
            .counter_scope_token
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    let counter_high_water = stream.sender_counter_high_water.map(encode_sequence);
    let counter_high_water = optional_field(counter_high_water.as_deref().map(str::as_bytes));
    let reserved = stream.reserved_high_water.map(encode_sequence);
    let committed = stream.committed_high_water.map(encode_sequence);
    let inner = stream.committed_inner_cursor.map(encode_sequence);
    let acknowledged = stream.acknowledged_high_water.map(encode_sequence);
    let acknowledged_inner = stream.acknowledged_inner_cursor.map(encode_sequence);
    let reserved = optional_field(reserved.as_deref().map(str::as_bytes));
    let committed = optional_field(committed.as_deref().map(str::as_bytes));
    let inner = optional_field(inner.as_deref().map(str::as_bytes));
    let acknowledged = optional_field(acknowledged.as_deref().map(str::as_bytes));
    let acknowledged_inner = optional_field(acknowledged_inner.as_deref().map(str::as_bytes));
    let hash = optional_field(
        stream
            .last_committed_blob_hash
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    let acknowledged_hash = optional_field(
        stream
            .last_acknowledged_blob_hash
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    let acknowledged_publication_id = optional_field(
        stream
            .last_acknowledged_publication_id
            .as_ref()
            .map(<[u8; 16]>::as_slice),
    );
    let acknowledged_request_digest = optional_field(
        stream
            .last_acknowledged_request_digest
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    let rotation_request_digest = optional_field(
        stream
            .last_rotation_request_digest
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    metadata_mac(
        key_bundle,
        STREAM_TOKEN_DOMAIN,
        &[
            &stream.publication_stream_id,
            scope_text(stream.scope).as_bytes(),
            &conversation,
            &stream.stream_route,
            &stream.generation,
            &counter_scope,
            &counter_high_water,
            &reserved,
            &committed,
            &inner,
            &hash,
            &acknowledged,
            &acknowledged_inner,
            &acknowledged_hash,
            &acknowledged_publication_id,
            &acknowledged_request_digest,
            &rotation_request_digest,
            &stream.rotation_serial.to_be_bytes(),
            stream_state_text(stream.state).as_bytes(),
            &stream.created_at_ms.to_be_bytes(),
            &stream.updated_at_ms.to_be_bytes(),
        ],
    )
}

fn verify_stream_token(
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    stream: &PublicationStreamRecord,
    expected: &[u8],
) -> Result<bool, RuntimeStoreError> {
    let conversation_id = match stream.scope {
        PublicationScope::Catalog => None,
        PublicationScope::Conversation(conversation_id) => Some(*conversation_id.as_bytes()),
    };
    let conversation = optional_field(conversation_id.as_ref().map(<[u8; 16]>::as_slice));
    let counter_scope = optional_field(
        stream
            .counter_scope_token
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    let counter_high_water = stream.sender_counter_high_water.map(encode_sequence);
    let counter_high_water = optional_field(counter_high_water.as_deref().map(str::as_bytes));
    let reserved = stream.reserved_high_water.map(encode_sequence);
    let committed = stream.committed_high_water.map(encode_sequence);
    let inner = stream.committed_inner_cursor.map(encode_sequence);
    let acknowledged = stream.acknowledged_high_water.map(encode_sequence);
    let acknowledged_inner = stream.acknowledged_inner_cursor.map(encode_sequence);
    let reserved = optional_field(reserved.as_deref().map(str::as_bytes));
    let committed = optional_field(committed.as_deref().map(str::as_bytes));
    let inner = optional_field(inner.as_deref().map(str::as_bytes));
    let acknowledged = optional_field(acknowledged.as_deref().map(str::as_bytes));
    let acknowledged_inner = optional_field(acknowledged_inner.as_deref().map(str::as_bytes));
    let hash = optional_field(
        stream
            .last_committed_blob_hash
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    let acknowledged_hash = optional_field(
        stream
            .last_acknowledged_blob_hash
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    let acknowledged_publication_id = optional_field(
        stream
            .last_acknowledged_publication_id
            .as_ref()
            .map(<[u8; 16]>::as_slice),
    );
    let acknowledged_request_digest = optional_field(
        stream
            .last_acknowledged_request_digest
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    let rotation_request_digest = optional_field(
        stream
            .last_rotation_request_digest
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    );
    super::stream::verify_metadata_mac(
        read_crypto,
        STREAM_TOKEN_DOMAIN,
        &[
            &stream.publication_stream_id,
            scope_text(stream.scope).as_bytes(),
            &conversation,
            &stream.stream_route,
            &stream.generation,
            &counter_scope,
            &counter_high_water,
            &reserved,
            &committed,
            &inner,
            &hash,
            &acknowledged,
            &acknowledged_inner,
            &acknowledged_hash,
            &acknowledged_publication_id,
            &acknowledged_request_digest,
            &rotation_request_digest,
            &stream.rotation_serial.to_be_bytes(),
            stream_state_text(stream.state).as_bytes(),
            &stream.created_at_ms.to_be_bytes(),
            &stream.updated_at_ms.to_be_bytes(),
        ],
        expected,
    )
}

#[allow(clippy::too_many_arguments)]
fn outbox_token(
    key_bundle: &RuntimeKeyBundle,
    publication_id: [u8; 16],
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    stream_seq: &str,
    counter_scope_token: [u8; 32],
    sender_counter: u64,
    inner_after: Option<&str>,
    inner_through: Option<&str>,
    payload_kind: PublicationPayloadKind,
    blob_sha256: [u8; 32],
    logical_bytes: u64,
    created_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let after = optional_field(inner_after.map(str::as_bytes));
    let through = optional_field(inner_through.map(str::as_bytes));
    metadata_mac(
        key_bundle,
        OUTBOX_TOKEN_DOMAIN,
        &[
            &publication_id,
            &publication_stream_id,
            &generation,
            stream_seq.as_bytes(),
            &counter_scope_token,
            &sender_counter.to_be_bytes(),
            &after,
            &through,
            payload_kind_text(payload_kind).as_bytes(),
            &blob_sha256,
            &logical_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
    )
}

fn validate_scope(scope: PublicationScope) -> Result<(), RuntimeStoreError> {
    if let PublicationScope::Conversation(conversation_id) = scope
        && conversation_id.kind() != RuntimeIdKind::Conversation
    {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        });
    }
    Ok(())
}

fn validate_inner_range(
    after: Option<u64>,
    through: Option<u64>,
    kind: PublicationPayloadKind,
) -> Result<(), RuntimeStoreError> {
    match (after, through) {
        (None, None) if kind == PublicationPayloadKind::Control => Ok(()),
        (None, Some(_)) => Ok(()),
        (Some(after), Some(through)) if after < through => Ok(()),
        _ => Err(RuntimeStoreError::PublicationMismatch),
    }
}

fn validate_nonzero_id(id: [u8; 16]) -> Result<(), RuntimeStoreError> {
    if id == [0; 16] {
        Err(RuntimeStoreError::PublicationMismatch)
    } else {
        Ok(())
    }
}

const fn scope_text(scope: PublicationScope) -> &'static str {
    match scope {
        PublicationScope::Catalog => "catalog",
        PublicationScope::Conversation(_) => "conversation",
    }
}

fn parse_scope(
    scope: &str,
    conversation_id: Option<&[u8]>,
) -> Result<PublicationScope, RuntimeStoreError> {
    match (scope, conversation_id) {
        ("catalog", None) => Ok(PublicationScope::Catalog),
        ("conversation", Some(id)) => Ok(PublicationScope::Conversation(RuntimeId::from_bytes(
            RuntimeIdKind::Conversation,
            fixed::<16>(id)?,
        )?)),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn stream_state_text(state: PublicationStreamState) -> &'static str {
    match state {
        PublicationStreamState::Active => "active",
        PublicationStreamState::NeedsSnapshot => "needsSnapshot",
        PublicationStreamState::Retired => "retired",
    }
}

fn parse_stream_state(value: &str) -> Result<PublicationStreamState, RuntimeStoreError> {
    match value {
        "active" => Ok(PublicationStreamState::Active),
        "needsSnapshot" => Ok(PublicationStreamState::NeedsSnapshot),
        "retired" => Ok(PublicationStreamState::Retired),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn payload_kind_text(kind: PublicationPayloadKind) -> &'static str {
    match kind {
        PublicationPayloadKind::Event => "event",
        PublicationPayloadKind::Catalog => "catalog",
        PublicationPayloadKind::Snapshot => "snapshot",
        PublicationPayloadKind::Control => "control",
    }
}

fn parse_payload_kind(value: &str) -> Result<PublicationPayloadKind, RuntimeStoreError> {
    match value {
        "event" => Ok(PublicationPayloadKind::Event),
        "catalog" => Ok(PublicationPayloadKind::Catalog),
        "snapshot" => Ok(PublicationPayloadKind::Snapshot),
        "control" => Ok(PublicationPayloadKind::Control),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

fn decode_optional(value: &Option<String>) -> Result<Option<u64>, RuntimeStoreError> {
    value
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()
        .map_err(RuntimeStoreError::from)
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn commit_with_faults(
    transaction: Transaction<'_>,
    config: &RuntimeStoreConfig,
    before: RuntimeStoreOperation,
    commit_operation: RuntimeCommitOperation,
) -> Result<(), RuntimeStoreError> {
    config.fault_injector.before_operation(before)?;
    super::sqlite::commit_transaction(transaction, commit_operation)
}

fn after_commit(
    config: &RuntimeStoreConfig,
    after: RuntimeStoreOperation,
    commit_operation: RuntimeCommitOperation,
) -> Result<(), RuntimeStoreError> {
    if config.fault_injector.before_operation(after).is_err() {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: commit_operation,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
