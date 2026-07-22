//! `BarriersFrozen` transition 对 EpochBarrier publication 的只读授权。

use agentdeck_protocol::e2ee::{EpochBarrierV1, KeyPurpose};
use agentdeck_protocol::relay_v2::StreamRouteId;
use agentdeck_protocol::runtime::RuntimeInnerCursor;

use super::*;

/// EpochBarrier 是 active transition fence 的唯一 publication 旁路。preflight 与最终
/// freeze transaction 都调用本 helper，把 journal identity、`BarriersFrozen` exact cut
/// 及当前 ADGK2 revision/key 重新认证；传入 canonical barrier 时还会逐轴核对旧 COMMIT
/// cursor，禁止 generic Control 或伪造 route/hash 借道。
pub(crate) fn authorize_epoch_barrier_identity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    identity: super::super::publication::EpochBarrierJournalIdentity,
    barrier: Option<&EpochBarrierV1>,
) -> Result<(), RuntimeStoreError> {
    let transition = load_active_transition(connection, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if transition.record.operation_id != identity.operation_id
        || transition.record.phase != KeyTransitionPhase::BarriersFrozen
        || transition.record.terminal.is_some()
        || transition.record.to_revision != identity.key_directory_revision
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let cut = transition
        .record
        .cuts
        .iter()
        .find(|cut| {
            cut.scope == identity.scope
                && cut.publication_stream_id == identity.publication_stream_id
        })
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    let expected_purpose = match cut.scope {
        KeyTransitionStreamScope::Catalog => KeyPurpose::Catalog,
        KeyTransitionStreamScope::Conversation(_) => KeyPurpose::ConversationDek,
    };
    if cut.stream_route != identity.stream_route
        || cut.generation != identity.generation
        || cut.barrier_sequence != identity.barrier_sequence
        || cut.new_epoch != identity.key_id.epoch
        || identity.key_id.purpose != expected_purpose
        || cut.epoch_barrier_sha256 != identity.barrier_sha256
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }

    let global =
        super::super::pairing_grant::load_global_key_state(connection, key_bundle, database_id)?
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if global.revision != identity.key_directory_revision
        || global.state.revision().value() != identity.key_directory_revision
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let expected_route = match cut.scope {
        KeyTransitionStreamScope::Catalog => None,
        KeyTransitionStreamScope::Conversation(_) => {
            Some(StreamRouteId::from_bytes(identity.stream_route))
        }
    };
    let current_key_matches = global.state.current_shared_keys()?.into_iter().any(|view| {
        view.purpose == identity.key_id.purpose
            && view.stream_route == expected_route
            && view.epoch == identity.key_id.epoch
    });
    if !current_key_matches {
        return Err(RuntimeStoreError::PublicationMismatch);
    }

    if let Some(barrier) = barrier {
        let inner_matches = match (&barrier.inner_cursor, cut.scope) {
            (RuntimeInnerCursor::Catalog { cursor }, KeyTransitionStreamScope::Catalog) => {
                cursor.high_water() == cut.relay_committed_inner
            }
            (
                RuntimeInnerCursor::Conversation {
                    conversation_id,
                    cursor,
                },
                KeyTransitionStreamScope::Conversation(expected),
            ) => {
                super::super::identity::RuntimeId::parse_canonical(
                    super::super::identity::RuntimeIdKind::Conversation,
                    conversation_id.as_str(),
                )
                .is_ok_and(|conversation| conversation.as_bytes() == &expected)
                    && cursor.high_water() == cut.relay_committed_inner
            }
            _ => false,
        };
        if barrier.stream_generation.as_bytes() != &cut.generation
            || barrier.stream_cursor.high_water() != cut.relay_committed_outer
            || barrier
                .stream_cursor
                .checked_next()
                .map_err(|_| RuntimeStoreError::PublicationMismatch)?
                != cut.barrier_sequence
            || !inner_matches
            || barrier.old_epoch != cut.old_epoch
            || barrier.new_epoch != cut.new_epoch
            || barrier.key_directory_revision.value() != transition.record.to_revision
            || barrier
                .canonical_sha256()
                .map_err(|_| RuntimeStoreError::PublicationMismatch)?
                != cut.epoch_barrier_sha256
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    }
    Ok(())
}
