//! Publication stream 的原地 generation rollover 与幂等 identity。

use super::*;

const ROTATION_REQUEST_DIGEST_DOMAIN: &[u8] = b"publication.rotation-request.v1";
const ROTATION_ROUTE_DERIVATION_DOMAIN: &[u8] = b"publication.rotation-route.v1";
const ROTATION_GENERATION_DERIVATION_DOMAIN: &[u8] = b"publication.rotation-generation.v1";

/// Relay v2 将 `u64::MAX` 保留为不可发送边界；daemon 最后可冻结的 outer
/// sequence 是 `MAX - 1`。到达该值的 stream 必须先完成 exact COMMIT/ACK，
/// 再走完整 generation rotation，绝不能先冻结一个无法发送的 MAX row。
pub(crate) const LAST_RELAY_STREAM_SEQ: u64 = u64::MAX - 1;

/// 兼容旧版本可能留下的 authenticated Active/MAX-1 stream：在任何 sealer、
/// outbox 或 counter mutation 前把它转为 NeedsSnapshot。正常新路径在成功冻结
/// MAX-1 时就会直接进入相同状态。
pub(super) fn mark_relay_sequence_exhausted(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    stream: &mut PublicationStreamRecord,
    next_stream_seq: u64,
    now_ms: u64,
) -> Result<bool, RuntimeStoreError> {
    if next_stream_seq <= LAST_RELAY_STREAM_SEQ {
        return Ok(false);
    }
    if next_stream_seq != u64::MAX || stream.reserved_high_water != Some(LAST_RELAY_STREAM_SEQ) {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    stream.state = PublicationStreamState::NeedsSnapshot;
    stream.updated_at_ms = now_ms;
    super::update_stream(transaction, key_bundle, stream)?;
    Ok(true)
}

/// 威胁场景：正常运行持续创建历史 generation，单机最终累计 1,025 rows 并永久
/// 撞上 directory cap；因此只在旧 generation 已完整消费且有 snapshot 覆盖时原地轮换。
/// 将已完整消费、且已有 authenticated ready snapshot 覆盖的 publication
/// stream 原地轮换到新 route/generation。该操作不新增 directory row，避免历史
/// NeedsSnapshot generation 永久占用 1,025 stream 配额。
pub(in crate::runtime::store) fn rotate_publication_stream(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    request: RotatePublicationStreamRequest,
    now_ms: u64,
) -> Result<PublicationStreamRecord, RuntimeStoreError> {
    validate_nonzero_id(request.publication_stream_id)?;
    validate_nonzero_id(request.expected_generation)?;
    let request_digest = rotation_request_digest(request);
    if let Some(current) = load_optional_stream(
        &state.connection,
        &state.key_bundle,
        request.publication_stream_id,
    )? && current.generation != request.expected_generation
    {
        return if rotated_record_matches(&current, request, request_digest) {
            Ok(current)
        } else {
            Err(RuntimeStoreError::PublicationMismatch)
        };
    }

    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger =
        super::super::sqlite::load_runtime_ledger(&transaction, key_bundle, state.database_id)?;
    let mut stream =
        super::directory::authenticate_directory_records(&transaction, key_bundle, &ledger)?
            .into_iter()
            .find(|stream| stream.publication_stream_id == request.publication_stream_id)
            .ok_or(RuntimeStoreError::PublicationMismatch)?;

    if stream.generation != request.expected_generation {
        return if rotated_record_matches(&stream, request, request_digest) {
            Ok(stream)
        } else {
            Err(RuntimeStoreError::PublicationMismatch)
        };
    }
    if stream.state != PublicationStreamState::NeedsSnapshot {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if now_ms < stream.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: stream.updated_at_ms,
            observed_ms: now_ms,
        });
    }
    if stream.reserved_high_water != stream.committed_high_water
        || stream.committed_high_water != stream.acknowledged_high_water
        || stream.committed_inner_cursor != stream.acknowledged_inner_cursor
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let (outbox_count, outbox_bytes): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(logical_blob_bytes), 0)
         FROM publication_outbox WHERE publication_stream_id = ?1",
        [&request.publication_stream_id[..]],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if outbox_count != 0 || outbox_bytes != 0 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if stream.sender_counter_high_water == Some(u64::MAX) {
        return Err(RuntimeStoreError::PublicationCounterExhausted);
    }
    let snapshot_covers = match (stream.scope, stream.committed_inner_cursor) {
        (_, None) => true,
        (PublicationScope::Catalog, Some(committed)) => {
            super::super::snapshot::authenticated_catalog_snapshot_covers(
                &transaction,
                key_bundle,
                committed,
            )?
        }
        (PublicationScope::Conversation(conversation_id), Some(committed)) => {
            super::super::snapshot::authenticated_conversation_snapshot_covers(
                &transaction,
                key_bundle,
                conversation_id,
                committed,
            )?
        }
    };
    if !snapshot_covers {
        return Err(RuntimeStoreError::PublicationNeedsSnapshot);
    }

    let next_rotation_serial = stream
        .rotation_serial
        .checked_add(1)
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    let (next_stream_route, next_generation) = derive_rotation_identity(
        key_bundle,
        stream.publication_stream_id,
        next_rotation_serial,
    )?;
    if next_stream_route == stream.stream_route || next_generation == stream.generation {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let previous_generation = stream.generation;
    stream.stream_route = next_stream_route;
    stream.generation = next_generation;
    stream.rotation_serial = next_rotation_serial;
    // Rollover 只重置 Relay generation 的 outer cursor，不是业务 journal 或
    // data-key rotation。ready snapshot 已认证覆盖 committed inner H，因此新
    // generation 必须从 `(BeforeFirst, H)` 继续；清空 inner 会让首个 seq=0
    // publication 错误地回退到 BeforeFirst。保留 counter scope 与 HWM，避免新
    // generation 复用旧 scope 并从低 counter 重新开始；真正换 scope 留给 P4.5
    // 的持久 CounterGuard/key-rotation 流程。
    stream.reserved_high_water = None;
    stream.committed_high_water = None;
    stream.last_committed_blob_hash = None;
    stream.acknowledged_high_water = None;
    stream.last_acknowledged_blob_hash = None;
    stream.last_rotation_request_digest = Some(request_digest);
    stream.state = PublicationStreamState::Active;
    stream.updated_at_ms = now_ms;
    update_rotated_stream(&transaction, key_bundle, previous_generation, &stream)?;
    commit_with_faults(
        transaction,
        config,
        RuntimeStoreOperation::RotatePublicationStreamBeforeCommit,
        RuntimeCommitOperation::RotatePublicationStream,
    )?;
    super::super::sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::RotatePublicationStreamAfterCommit,
        RuntimeCommitOperation::RotatePublicationStream,
    )?;
    Ok(stream)
}

fn update_rotated_stream(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    expected_generation: [u8; 16],
    stream: &PublicationStreamRecord,
) -> Result<(), RuntimeStoreError> {
    let token = stream_token(key_bundle, stream)?;
    if transaction.execute(
        "UPDATE publication_streams SET
             stream_route = ?1, generation = ?2,
             counter_scope_token = ?3, sender_counter_high_water = ?4,
             reserved_high_water = ?5, committed_high_water = ?6,
             committed_inner_cursor = ?7, last_committed_blob_hash = ?8,
             acknowledged_high_water = ?9, acknowledged_inner_cursor = ?10,
             last_acknowledged_blob_hash = ?11,
             last_acknowledged_publication_id = ?12,
             last_acknowledged_request_digest = ?13,
             last_rotation_request_digest = ?14,
             rotation_serial = ?15,
             state = ?16, updated_at_ms = ?17, metadata_token = ?18
         WHERE publication_stream_id = ?19 AND generation = ?20",
        params![
            &stream.stream_route[..],
            &stream.generation[..],
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
            &expected_generation[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

/// Machine trust-reset 已取得 Relay terminal/readback 且所有业务 owner 已静默后，
/// 原地冻结 publication directory 的稳定本机 identity，并丢弃旧 trust domain 的
/// 全部 Relay/crypto projection。caller 与其余 remote security row 在同一事务更新
/// Runtime ledger；本 helper 不自行 COMMIT。
pub(in crate::runtime::store) fn reset_for_machine_purge(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut streams =
        super::directory::authenticate_directory_records(transaction, key_bundle, ledger)?;
    let expected_outbox = ledger.publication_outbox_count;
    let deleted = transaction.execute("DELETE FROM publication_outbox", [])?;
    if u64::try_from(deleted).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != expected_outbox
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    for stream in &mut streams {
        let previous_generation = stream.generation;
        let next_rotation_serial = stream
            .rotation_serial
            .checked_add(1)
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
        let (next_stream_route, next_generation) = derive_rotation_identity(
            key_bundle,
            stream.publication_stream_id,
            next_rotation_serial,
        )?;
        if next_stream_route == stream.stream_route || next_generation == stream.generation {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        stream.stream_route = next_stream_route;
        stream.generation = next_generation;
        stream.counter_scope_token = None;
        stream.sender_counter_high_water = None;
        stream.reserved_high_water = None;
        stream.committed_high_water = None;
        stream.committed_inner_cursor = None;
        stream.last_committed_blob_hash = None;
        stream.acknowledged_high_water = None;
        stream.acknowledged_inner_cursor = None;
        stream.last_acknowledged_blob_hash = None;
        stream.last_acknowledged_publication_id = None;
        stream.last_acknowledged_request_digest = None;
        stream.last_rotation_request_digest = None;
        stream.rotation_serial = next_rotation_serial;
        stream.state = PublicationStreamState::NeedsSnapshot;
        update_rotated_stream(transaction, key_bundle, previous_generation, stream)?;
    }

    ledger.publication_outbox_count = 0;
    ledger.publication_outbox_bytes = 0;
    super::validate_integrity(transaction, key_bundle, database_id, ledger)
}

fn rotated_record_matches(
    stream: &PublicationStreamRecord,
    request: RotatePublicationStreamRequest,
    request_digest: [u8; 32],
) -> bool {
    // 威胁场景：rotation 已 COMMIT 但回复丢失，随后同一串行 owner 已推进新
    // generation；若 exact retry 仍要求新 stream 完全空白，会把已提交操作误报为
    // mismatch。authenticated request digest 与 generation lineage 已足以证明该次
    // rotation，后续合法进展不应抹掉其幂等读回能力。
    stream.publication_stream_id == request.publication_stream_id
        && stream.generation != request.expected_generation
        && stream.last_rotation_request_digest == Some(request_digest)
        && stream.rotation_serial > 0
}

fn rotation_request_digest(request: RotatePublicationStreamRequest) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ROTATION_REQUEST_DIGEST_DOMAIN);
    digest.update(request.publication_stream_id);
    digest.update(request.expected_generation);
    digest.finalize().into()
}

fn derive_rotation_identity(
    key_bundle: &RuntimeKeyBundle,
    publication_stream_id: [u8; 16],
    rotation_serial: u64,
) -> Result<([u8; 16], [u8; 16]), RuntimeStoreError> {
    if rotation_serial == 0 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let serial = rotation_serial.to_be_bytes();
    let route_digest = metadata_mac(
        key_bundle,
        ROTATION_ROUTE_DERIVATION_DOMAIN,
        &[&publication_stream_id, &serial],
    )?;
    let generation_digest = metadata_mac(
        key_bundle,
        ROTATION_GENERATION_DERIVATION_DOMAIN,
        &[&publication_stream_id, &serial],
    )?;
    let stream_route = fixed::<16>(&route_digest[..16])?;
    let generation = fixed::<16>(&generation_digest[..16])?;
    if stream_route == [0; 16] || generation == [0; 16] || stream_route == generation {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok((stream_route, generation))
}
