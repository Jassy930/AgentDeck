//! `ActivateConversation` zero-cut transition 的 Catalog revision-advance publication 授权与
//! durable COMMIT 证明。

use agentdeck_protocol::e2ee::{
    DirectoryRevisionAdvanceV1, KeyControlV1, KeyId, KeyPurpose, SignedSealedBlobV1,
};

use super::*;

/// preflight 与最终 freeze transaction 都调用本入口。只有 exact active
/// `ActivateConversation/BarriersFrozen`、当前 Catalog stream/key 与 canonical
/// `from -> to` control 可以越过 ordinary business fence。
pub(crate) fn authorize_directory_advance_identity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    identity: super::super::publication::DirectoryAdvanceJournalIdentity,
    advance: Option<&DirectoryRevisionAdvanceV1>,
) -> Result<(), RuntimeStoreError> {
    let transition = load_active_transition(connection, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    validate_transition_identity(
        &transition.record,
        identity,
        KeyTransitionPhase::BarriersFrozen,
    )?;
    validate_current_catalog_axes(connection, key_bundle, database_id, identity)?;
    if let Some(advance) = advance {
        validate_control(identity, advance)?;
    }
    Ok(())
}

/// `mark_key_barriers_committed` 与 reopen integrity 共用的 operation-aware proof。
/// notice 仍在 outbox 时要求 exact Relay COMMIT；device 已 ACK 并删除 outbox 时要求
/// deterministic publication tombstone。两条路径都保持 Catalog inner cursor 不变。
pub(super) fn verify_directory_advance_commit(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    transition: &KeyTransitionRecord,
) -> Result<(), RuntimeStoreError> {
    if !matches!(
        transition.phase,
        KeyTransitionPhase::BarriersFrozen | KeyTransitionPhase::BarriersCommitted
    ) {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let (stream, key_id, advance, identity) =
        derive_current_identity(connection, key_bundle, database_id, transition)?;
    validate_transition_identity(transition, identity, transition.phase)?;
    validate_control(identity, &advance)?;

    let publication_id = identity.publication_id();
    let frozen = super::super::publication::load_optional_outbox(
        connection,
        key_bundle,
        database_id,
        publication_id,
    )?;
    if let Some(frozen) = frozen {
        let frozen_key_id = super::super::remote_counter::load_frozen_key_id_for_publication(
            connection,
            key_bundle,
            database_id,
            &frozen,
        )?;
        let signed = SignedSealedBlobV1::from_wire_bytes(&frozen.blob)
            .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
        if frozen.publication_id != publication_id
            || frozen.publication_stream_id != stream.publication_stream_id
            || frozen.stream_route != stream.stream_route
            || frozen.generation != stream.generation
            || frozen.payload_kind != super::super::publication::PublicationPayloadKind::Control
            || frozen.inner_after.is_some()
            || frozen.inner_through.is_some()
            || stream.reserved_high_water != Some(frozen.stream_seq)
            || stream.committed_high_water != Some(frozen.stream_seq)
            || stream.last_committed_blob_hash != Some(frozen.blob_sha256)
            || frozen_key_id != key_id
            || signed.inner.key_id != key_id
            || signed.inner.key_epoch != key_id.epoch
            || signed.inner.key_directory_revision != transition.from_revision
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        return Ok(());
    }

    if stream.last_acknowledged_publication_id != Some(publication_id)
        || stream.last_acknowledged_request_digest.is_none()
        || stream.reserved_high_water.is_none()
        || stream.reserved_high_water != stream.committed_high_water
        || stream.committed_high_water != stream.acknowledged_high_water
        || stream.last_committed_blob_hash.is_none()
        || stream.last_committed_blob_hash != stream.last_acknowledged_blob_hash
        || stream.committed_inner_cursor != stream.acknowledged_inner_cursor
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn derive_current_identity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    transition: &KeyTransitionRecord,
) -> Result<
    (
        super::super::publication::PublicationStreamRecord,
        KeyId,
        DirectoryRevisionAdvanceV1,
        super::super::publication::DirectoryAdvanceJournalIdentity,
    ),
    RuntimeStoreError,
> {
    let ledger = super::super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let streams =
        super::super::publication::authenticate_directory_records(connection, key_bundle, &ledger)?;
    // 最后一条可发送 outer sequence 或最后一个 sender counter 会在成功 freeze
    // 后把同一 generation 标成 NeedsSnapshot。notice 的 exact COMMIT/ACK 证明仍须
    // 能在该合法终态重开；真正的 rotation 会改变 route/generation，并在下方 identity
    // 对账中继续 fail-close。
    let mut catalog = streams.into_iter().filter(|stream| {
        stream.scope == super::super::publication::PublicationScope::Catalog
            && matches!(
                stream.state,
                super::super::publication::PublicationStreamState::Active
                    | super::super::publication::PublicationStreamState::NeedsSnapshot
            )
    });
    let stream = catalog
        .next()
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if catalog.next().is_some() {
        return Err(RuntimeStoreError::PublicationMismatch);
    }

    let global =
        super::super::pairing_grant::load_global_key_state(connection, key_bundle, database_id)?
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if global.revision != transition.to_revision
        || global.state.revision().value() != transition.to_revision
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let mut catalog_keys = global
        .state
        .current_shared_keys()?
        .into_iter()
        .filter(|view| view.purpose == KeyPurpose::Catalog && view.stream_route.is_none());
    let catalog_key = catalog_keys
        .next()
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if catalog_keys.next().is_some() || catalog_key.epoch == 0 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let key_id = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: catalog_key.epoch,
    };
    let advance = DirectoryRevisionAdvanceV1 {
        from_key_directory_revision: agentdeck_protocol::relay_v2::KeyDirectoryRevision::new(
            transition.from_revision,
        ),
        to_key_directory_revision: agentdeck_protocol::relay_v2::KeyDirectoryRevision::new(
            transition.to_revision,
        ),
    };
    advance
        .validate()
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    let control = KeyControlV1::directory_revision_advance(advance.clone());
    let control_sha256 = control
        .canonical_sha256()
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    let identity = super::super::publication::DirectoryAdvanceJournalIdentity {
        operation_id: transition.operation_id,
        publication_stream_id: stream.publication_stream_id,
        stream_route: stream.stream_route,
        generation: stream.generation,
        from_revision: transition.from_revision,
        to_revision: transition.to_revision,
        key_id,
        control_sha256,
    };
    Ok((stream, key_id, advance, identity))
}

fn validate_transition_identity(
    transition: &KeyTransitionRecord,
    identity: super::super::publication::DirectoryAdvanceJournalIdentity,
    expected_phase: KeyTransitionPhase,
) -> Result<(), RuntimeStoreError> {
    if transition.operation_id != identity.operation_id
        || transition.operation != KeyTransitionOperation::ActivateConversation
        || !matches!(transition.target, KeyTransitionTarget::Conversation { .. })
        || transition.phase != expected_phase
        || transition.terminal.is_some()
        || !transition.cuts.is_empty()
        || transition.from_revision != identity.from_revision
        || transition.to_revision != identity.to_revision
        || transition.from_revision.checked_add(1) != Some(transition.to_revision)
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn validate_current_catalog_axes(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    identity: super::super::publication::DirectoryAdvanceJournalIdentity,
) -> Result<(), RuntimeStoreError> {
    let transition = load_active_transition(connection, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    let (stream, key_id, _, expected) =
        derive_current_identity(connection, key_bundle, database_id, &transition.record)?;
    if identity != expected
        || stream.publication_stream_id != identity.publication_stream_id
        || key_id != identity.key_id
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn validate_control(
    identity: super::super::publication::DirectoryAdvanceJournalIdentity,
    advance: &DirectoryRevisionAdvanceV1,
) -> Result<(), RuntimeStoreError> {
    advance
        .validate()
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    let control = KeyControlV1::directory_revision_advance(advance.clone());
    if advance.from_key_directory_revision.value() != identity.from_revision
        || advance.to_key_directory_revision.value() != identity.to_revision
        || control
            .canonical_sha256()
            .map_err(|_| RuntimeStoreError::PublicationMismatch)?
            != identity.control_sha256
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}
