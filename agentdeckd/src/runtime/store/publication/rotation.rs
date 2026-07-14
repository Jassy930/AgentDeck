//! Publication stream 的原地 generation rollover 与幂等 identity。

use super::*;

const ROTATION_REQUEST_DIGEST_DOMAIN: &[u8] = b"publication.rotation-request.v1";
const ROTATION_ROUTE_DERIVATION_DOMAIN: &[u8] = b"publication.rotation-route.v1";
const ROTATION_GENERATION_DERIVATION_DOMAIN: &[u8] = b"publication.rotation-generation.v1";

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
    // Rollover 只重置 Relay stream 的 outer/inner cursor，不是 data-key rotation。
    // 保留 counter scope 与 HWM，避免新 generation 复用旧 scope 并从低 counter
    // 重新开始；真正换 scope 留给 P4.5 的持久 CounterGuard/key-rotation 流程。
    stream.reserved_high_water = None;
    stream.committed_high_water = None;
    stream.committed_inner_cursor = None;
    stream.last_committed_blob_hash = None;
    stream.acknowledged_high_water = None;
    stream.acknowledged_inner_cursor = None;
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
