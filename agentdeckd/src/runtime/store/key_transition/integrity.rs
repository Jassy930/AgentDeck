use std::collections::BTreeMap;

use super::super::sqlite::RuntimeLedger;
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedPublicationProjection {
    scope: KeyTransitionStreamScope,
    stream_route: [u8; 16],
    reserved_high_water: Option<u64>,
    barrier: super::super::publication::PublicationBarrierCut,
}

pub(super) fn verify_exact_committed_cuts(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    transition: &KeyTransitionRecord,
    cuts: &[KeyTransitionStreamCut],
) -> Result<(), RuntimeStoreError> {
    validate_transition_stream_cuts(transition, cuts)?;
    let projections = load_active_publication_projections(connection, key_bundle, transition)?;
    if projections.len() != cuts.len() {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    for (projection, cut) in projections.iter().zip(cuts) {
        if projection.reserved_high_water != projection.barrier.committed_outer_cursor
            || projection.scope != cut.scope
            || projection.stream_route != cut.stream_route
            || projection.barrier.publication_stream_id != cut.publication_stream_id
            || projection.barrier.generation != cut.generation
            || projection.barrier.committed_outer_cursor != cut.relay_committed_outer
            || projection.barrier.committed_inner_cursor != cut.relay_committed_inner
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    }
    Ok(())
}

pub(super) fn verify_barrier_commit(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    transition: &KeyTransitionRecord,
    cuts: &[KeyTransitionStreamCut],
) -> Result<(), RuntimeStoreError> {
    validate_transition_stream_cuts(transition, cuts)?;
    let projections = load_active_publication_projections(connection, key_bundle, transition)?;
    if projections.len() != cuts.len() {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    for (projection, cut) in projections.iter().zip(cuts) {
        if projection.reserved_high_water != projection.barrier.committed_outer_cursor
            || projection.scope != cut.scope
            || projection.stream_route != cut.stream_route
            || projection.barrier.publication_stream_id != cut.publication_stream_id
            || projection.barrier.generation != cut.generation
            || projection.barrier.committed_inner_cursor != cut.relay_committed_inner
            || !matches!(
                projection.barrier.committed_outer_cursor,
                Some(committed) if committed >= cut.barrier_sequence
            )
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    }
    Ok(())
}

pub(super) fn verify_transition_publication_commit(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    transition: &KeyTransitionRecord,
) -> Result<(), RuntimeStoreError> {
    if transition.operation == KeyTransitionOperation::ActivateConversation {
        super::directory_advance::verify_directory_advance_commit(
            connection,
            key_bundle,
            database_id,
            transition,
        )
    } else {
        verify_barrier_commit(connection, key_bundle, transition, &transition.cuts)
    }
}

fn load_active_publication_projections(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    transition: &KeyTransitionRecord,
) -> Result<Vec<AuthenticatedPublicationProjection>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT publication_stream_id FROM publication_streams
         WHERE state = 'active' ORDER BY publication_stream_id",
    )?;
    let ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if ids.len() > MAX_KEY_TRANSITION_CONVERSATIONS + 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let read_crypto = key_bundle.read_only_capability();
    let mut projections = Vec::new();
    projections
        .try_reserve_exact(ids.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for id in ids {
        let publication_stream_id = fixed(&id)?;
        let stream = super::super::publication::load_stream_read(
            connection,
            &read_crypto,
            publication_stream_id,
        )?;
        let scope = match stream.scope {
            super::super::publication::PublicationScope::Catalog => {
                KeyTransitionStreamScope::Catalog
            }
            super::super::publication::PublicationScope::Conversation(conversation_id) => {
                KeyTransitionStreamScope::Conversation(*conversation_id.as_bytes())
            }
        };
        if stream.state != super::super::publication::PublicationStreamState::Active {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        projections.push(AuthenticatedPublicationProjection {
            scope,
            stream_route: stream.stream_route,
            reserved_high_water: stream.reserved_high_water,
            barrier: super::super::publication::PublicationBarrierCut {
                publication_stream_id: stream.publication_stream_id,
                generation: stream.generation,
                committed_outer_cursor: stream.committed_high_water,
                committed_inner_cursor: stream.committed_inner_cursor,
            },
        });
    }
    projections
        .sort_by_key(|projection| (projection.scope, projection.barrier.publication_stream_id));
    projections.retain(|projection| transition_requires_projection(transition, projection));
    Ok(projections)
}

fn transition_requires_projection(
    transition: &KeyTransitionRecord,
    projection: &AuthenticatedPublicationProjection,
) -> bool {
    match (transition.operation, transition.target) {
        (KeyTransitionOperation::Add | KeyTransitionOperation::Revoke, _) => true,
        (KeyTransitionOperation::Renew, _) => projection.scope == KeyTransitionStreamScope::Catalog,
        (KeyTransitionOperation::ActivateConversation, _)
        | (KeyTransitionOperation::CounterRecovery, KeyTransitionTarget::Device(_)) => false,
        (
            KeyTransitionOperation::CounterRecovery,
            KeyTransitionTarget::Conversation {
                conversation_id,
                stream_route,
            },
        ) => {
            projection.stream_route == stream_route
                && match projection.scope {
                    KeyTransitionStreamScope::Catalog => {
                        projection.barrier.publication_stream_id == conversation_id
                    }
                    KeyTransitionStreamScope::Conversation(active_conversation_id) => {
                        active_conversation_id == conversation_id
                    }
                }
        }
    }
}

pub(crate) fn validate_v12_integrity(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let transitions = load_all_transitions(connection, key_bundle, database_id)?;
    let updates = load_all_updates(connection, key_bundle, database_id)?;
    let mut updates_by_operation: BTreeMap<[u8; 16], Vec<AuthenticatedUpdate>> = BTreeMap::new();
    let mut update_sealed_bytes = 0_u64;
    for update in updates {
        update_sealed_bytes = checked_add(update_sealed_bytes, update.sealed_bytes)?;
        updates_by_operation
            .entry(update.record.operation_id)
            .or_default()
            .push(update);
    }
    let mut transition_sealed_bytes = 0_u64;
    let mut active_count = 0_u64;
    for transition in &transitions {
        transition_sealed_bytes = checked_add(transition_sealed_bytes, transition.sealed_bytes)?;
        if transition.record.phase != KeyTransitionPhase::Complete {
            active_count = checked_add(active_count, 1)?;
        }
        let operation_updates = updates_by_operation
            .remove(&transition.record.operation_id)
            .unwrap_or_default();
        if let Some(proof) = transition.record.bootstrap_install_proof.as_ref() {
            ensure_bootstrap_global_lineage_matches(
                connection,
                key_bundle,
                database_id,
                &transition.record,
                &proof.binding,
            )
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        validate_transition_updates(&transition.record, &operation_updates)?;
        if transition.record.phase == KeyTransitionPhase::BarriersCommitted {
            verify_transition_publication_commit(
                connection,
                key_bundle,
                database_id,
                &transition.record,
            )
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
    }
    let transition_count =
        u64::try_from(transitions.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let update_count = ledger_row_count(connection, "remote_key_update_outbox")?;
    if !updates_by_operation.is_empty()
        || transition_count != ledger.remote_key_transition_count
        || active_count != ledger.remote_key_transition_active_count
        || transition_sealed_bytes != ledger.remote_key_transition_sealed_bytes
        || update_count != ledger.remote_key_update_outbox_count
        || update_sealed_bytes != ledger.remote_key_update_outbox_sealed_bytes
        || transition_count > MAX_KEY_TRANSITIONS
        || active_count > 1
        || transition_sealed_bytes > MAX_KEY_TRANSITION_SEALED_BYTES
        || update_count > MAX_KEY_UPDATE_ROWS
        || update_sealed_bytes > MAX_KEY_UPDATE_SEALED_BYTES
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn load_all_transitions(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedTransition>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT operation_id, database_id, operation_kind, target_device_route,
                target_grant_serial, target_conversation_id, target_stream_route,
                from_revision, to_revision, phase, terminal_kind, recipient_count,
                stream_count, update_count, created_at_ms, state_changed_at_ms,
                terminal_at_ms, retain_until_ms, sealed_state, sealed_state_bytes,
                metadata_token
         FROM remote_key_transitions ORDER BY operation_id",
    )?;
    let mut rows = statement.query([])?;
    let mut transitions = Vec::new();
    while let Some(row) = rows.next()? {
        if transitions.len() >= usize::try_from(MAX_KEY_TRANSITIONS).unwrap_or(usize::MAX) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        transitions.push(authenticate_transition(
            key_bundle,
            database_id,
            RawTransition {
                operation_id: row.get(0)?,
                database_id: row.get(1)?,
                operation_kind: row.get(2)?,
                target_device_route: row.get(3)?,
                target_grant_serial: row.get(4)?,
                target_conversation_id: row.get(5)?,
                target_stream_route: row.get(6)?,
                from_revision: row.get(7)?,
                to_revision: row.get(8)?,
                phase: row.get(9)?,
                terminal_kind: row.get(10)?,
                recipient_count: row.get(11)?,
                stream_count: row.get(12)?,
                update_count: row.get(13)?,
                created_at_ms: row.get(14)?,
                state_changed_at_ms: row.get(15)?,
                terminal_at_ms: row.get(16)?,
                retain_until_ms: row.get(17)?,
                sealed_state: row.get(18)?,
                sealed_state_bytes: row.get(19)?,
                metadata_token: row.get(20)?,
            },
        )?);
    }
    Ok(transitions)
}

fn load_all_updates(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedUpdate>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT operation_id, device_route, grant_serial, database_id, key_revision,
                lifecycle, update_hash, canonical_update_bytes, ack_hash,
                applied_ack_count, applied_ack_set_hash, created_at_ms,
                state_changed_at_ms, sealed_state, sealed_state_bytes, metadata_token
         FROM remote_key_update_outbox ORDER BY operation_id, device_route, grant_serial",
    )?;
    let mut rows = statement.query([])?;
    let mut updates = Vec::new();
    while let Some(row) = rows.next()? {
        if updates.len() >= usize::try_from(MAX_KEY_UPDATE_ROWS).unwrap_or(usize::MAX) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        updates.push(authenticate_update(
            key_bundle,
            database_id,
            RawUpdate {
                operation_id: row.get(0)?,
                device_route: row.get(1)?,
                grant_serial: row.get(2)?,
                database_id: row.get(3)?,
                key_revision: row.get(4)?,
                lifecycle: row.get(5)?,
                update_hash: row.get(6)?,
                canonical_update_bytes: row.get(7)?,
                ack_hash: row.get(8)?,
                applied_ack_count: row.get(9)?,
                applied_ack_set_hash: row.get(10)?,
                created_at_ms: row.get(11)?,
                state_changed_at_ms: row.get(12)?,
                sealed_state: row.get(13)?,
                sealed_state_bytes: row.get(14)?,
                metadata_token: row.get(15)?,
            },
        )?);
    }
    Ok(updates)
}

fn validate_transition_updates(
    transition: &KeyTransitionRecord,
    updates: &[AuthenticatedUpdate],
) -> Result<(), RuntimeStoreError> {
    if u64::try_from(updates.len()).unwrap_or(u64::MAX) != transition.update_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if let Some(proof) = transition.bootstrap_install_proof.as_ref()
        && transition.phase.rank() >= KeyTransitionPhase::UpdatesFrozen.rank()
    {
        let target = bootstrap_target(&proof.binding);
        let update = updates
            .iter()
            .find(|update| update.record.recipient == target)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if update.record.lifecycle != KeyUpdateLifecycle::Acked {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        ensure_bootstrap_update_matches(&proof.binding, &update.record)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    for (index, update) in updates.iter().enumerate() {
        let recipient = transition
            .recipients
            .get(index)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if update.record.operation_id != transition.operation_id
            || update.record.recipient != *recipient
            || update.record.key_revision != transition.to_revision
            || update.record.created_at_ms < transition.created_at_ms
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if transition.phase.rank() < KeyTransitionPhase::BarriersCommitted.rank()
            && (!update.record.snapshot_flushes.is_empty()
                || !update.record.stream_applied_acks.is_empty())
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if update.record.snapshot_flushes.iter().any(|marker| {
            !snapshot_permit::marker_matches_transition_cut(transition, &update.record, marker)
        }) || update
            .record
            .snapshot_flushes
            .windows(2)
            .any(|pair| pair[0].authorization_hash != pair[1].authorization_hash)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        for ack in &update.record.stream_applied_acks {
            let matching_cut = transition.cuts.iter().find(|cut| {
                ack.scope == cut.scope
                    && ack.stream_route == cut.stream_route
                    && ack.stream_generation == cut.generation
                    && ack.applied_stream_seq == cut.barrier_sequence
                    && ack.inner_cursor == cut.relay_committed_inner
                    && ack.key_revision == transition.to_revision
                    && ack.key_epoch == cut.new_epoch
                    && ack.epoch_barrier_sha256 == cut.epoch_barrier_sha256
            });
            let Some(cut) = matching_cut else {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            };
            let legacy_completed = update.codec_version == LEGACY_UPDATE_CODEC_VERSION
                && transition.phase == KeyTransitionPhase::Complete
                && transition.terminal == Some(KeyTransitionTerminal::Completed);
            if snapshot_permit::snapshot_delivery_required(transition, update.record.recipient)
                && !legacy_completed
                && !snapshot_permit::has_snapshot_flush_before_ack(
                    transition,
                    &update.record,
                    cut,
                    ack.acknowledged_at_ms,
                )
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
    }
    match (transition.phase, transition.terminal) {
        (KeyTransitionPhase::Complete, Some(KeyTransitionTerminal::Completed))
            if updates.iter().all(|update| {
                update.record.lifecycle == KeyUpdateLifecycle::Acked
                    && (update.codec_version == LEGACY_UPDATE_CODEC_VERSION
                        || snapshot_permit::has_all_required_snapshot_flushes(
                            transition,
                            &update.record,
                        ))
                    && has_all_stream_applied_acks(transition, &update.record)
            }) =>
        {
            Ok(())
        }
        (KeyTransitionPhase::Complete, Some(KeyTransitionTerminal::Cancelled))
            if updates
                .iter()
                .all(|update| update.record.lifecycle == KeyUpdateLifecycle::Cancelled) =>
        {
            Ok(())
        }
        (KeyTransitionPhase::Complete, _) => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        (_, None)
            if updates.iter().all(|update| {
                matches!(
                    update.record.lifecycle,
                    KeyUpdateLifecycle::Frozen | KeyUpdateLifecycle::Acked
                )
            }) =>
        {
            Ok(())
        }
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

fn ledger_row_count(connection: &Connection, table: &str) -> Result<u64, RuntimeStoreError> {
    let sql = match table {
        "remote_key_update_outbox" => "SELECT COUNT(*) FROM remote_key_update_outbox",
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    nonnegative(connection.query_row(sql, [], |row| row.get(0))?)
}
