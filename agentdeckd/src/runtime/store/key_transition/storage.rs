use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::super::cipher::RowAad;
use super::super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::super::sqlite::RuntimeLedger;
use super::*;

pub(super) fn load_transition(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    operation_id: [u8; 16],
) -> Result<Option<AuthenticatedTransition>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT operation_id, database_id, operation_kind, target_device_route,
                    target_grant_serial, target_conversation_id, target_stream_route,
                    from_revision, to_revision, phase, terminal_kind, recipient_count,
                    stream_count, update_count, created_at_ms, state_changed_at_ms,
                    terminal_at_ms, retain_until_ms, sealed_state, sealed_state_bytes,
                    metadata_token
             FROM remote_key_transitions WHERE operation_id = ?1",
            [&operation_id[..]],
            |row| {
                Ok(RawTransition {
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
                })
            },
        )
        .optional()?;
    raw.map(|row| authenticate_transition(key_bundle, database_id, row))
        .transpose()
}

pub(super) fn load_active_transition(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<AuthenticatedTransition>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT operation_id FROM remote_key_transitions
         WHERE phase <> 'Complete' ORDER BY operation_id LIMIT 2",
    )?;
    let ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if ids.len() > 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    ids.first()
        .map(|id| {
            load_transition(connection, key_bundle, database_id, fixed(id)?)?
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
        })
        .transpose()
}

pub(super) fn load_pairing_bootstrap_transition(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    recipient: KeyTransitionRecipient,
    key_revision: u64,
) -> Result<Option<AuthenticatedTransition>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT operation_id FROM remote_key_transitions
         WHERE operation_kind IN ('Add', 'Renew')
           AND target_device_route = ?1 AND target_grant_serial = ?2
           AND to_revision = ?3
         ORDER BY operation_id LIMIT 2",
    )?;
    let ids = statement
        .query_map(
            params![
                &recipient.device_route[..],
                super::super::sequence::encode_sequence(recipient.grant_serial),
                super::super::sequence::encode_sequence(key_revision),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if ids.len() > 1 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    ids.first()
        .map(|id| {
            load_transition(connection, key_bundle, database_id, fixed(id)?)?
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
        })
        .transpose()
}

pub(super) fn pairing_bootstrap_update_exists(
    connection: &Connection,
    recipient: KeyTransitionRecipient,
    key_revision: u64,
) -> Result<bool, RuntimeStoreError> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM remote_key_update_outbox
             WHERE device_route = ?1 AND grant_serial = ?2 AND key_revision = ?3
         )",
        params![
            &recipient.device_route[..],
            super::super::sequence::encode_sequence(recipient.grant_serial),
            super::super::sequence::encode_sequence(key_revision),
        ],
        |row| row.get(0),
    )?;
    match exists {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

pub(super) fn load_expired_transition_ids(
    connection: &Connection,
    now_ms: u64,
) -> Result<Vec<[u8; 16]>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT operation_id FROM remote_key_transitions
         WHERE phase = 'Complete' AND retain_until_ms <= ?1
         ORDER BY retain_until_ms, operation_id",
    )?;
    let raw = statement
        .query_map([sql_time(now_ms)?], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if raw.len() > usize::try_from(MAX_KEY_TRANSITIONS).unwrap_or(usize::MAX) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    raw.into_iter().map(|id| fixed(&id)).collect()
}

pub(super) fn load_update(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    operation_id: [u8; 16],
    recipient: KeyTransitionRecipient,
) -> Result<Option<AuthenticatedUpdate>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT operation_id, device_route, grant_serial, database_id, key_revision,
                    lifecycle, update_hash, canonical_update_bytes, ack_hash,
                    applied_ack_count, applied_ack_set_hash, created_at_ms,
                    state_changed_at_ms, sealed_state, sealed_state_bytes, metadata_token
             FROM remote_key_update_outbox
             WHERE operation_id = ?1 AND device_route = ?2 AND grant_serial = ?3",
            params![
                &operation_id[..],
                &recipient.device_route[..],
                super::super::sequence::encode_sequence(recipient.grant_serial),
            ],
            |row| {
                Ok(RawUpdate {
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
                })
            },
        )
        .optional()?;
    raw.map(|row| authenticate_update(key_bundle, database_id, row))
        .transpose()
}

pub(super) fn load_updates_for_operation(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    operation_id: [u8; 16],
) -> Result<Vec<AuthenticatedUpdate>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT device_route, grant_serial FROM remote_key_update_outbox
         WHERE operation_id = ?1 ORDER BY device_route, grant_serial",
    )?;
    let identities = statement
        .query_map([&operation_id[..]], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if identities.len() > MAX_KEY_TRANSITION_RECIPIENTS {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut updates = Vec::new();
    updates
        .try_reserve_exact(identities.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for (device_route, grant_serial) in identities {
        let recipient = KeyTransitionRecipient {
            device_route: fixed(&device_route)?,
            grant_serial: canonical_sequence(&grant_serial, false)?,
        };
        updates.push(
            load_update(connection, key_bundle, database_id, operation_id, recipient)?
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
    }
    Ok(updates)
}

pub(super) fn load_ack_candidate_operation_ids(
    connection: &Connection,
    recipient: KeyTransitionRecipient,
    key_revision: u64,
) -> Result<Vec<[u8; 16]>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT operation_id FROM remote_key_update_outbox
         WHERE device_route = ?1 AND grant_serial = ?2 AND key_revision = ?3
         ORDER BY operation_id",
    )?;
    let raw_ids = statement
        .query_map(
            params![
                &recipient.device_route[..],
                super::super::sequence::encode_sequence(recipient.grant_serial),
                super::super::sequence::encode_sequence(key_revision),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if raw_ids.len() > usize::try_from(MAX_KEY_TRANSITIONS).unwrap_or(usize::MAX) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    raw_ids
        .into_iter()
        .map(|operation_id| fixed(&operation_id))
        .collect()
}

pub(super) fn updates_match(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    transition: &KeyTransitionRecord,
    updates: &[FrozenKeyUpdate],
    frozen_at_ms: u64,
) -> Result<bool, RuntimeStoreError> {
    let persisted =
        load_updates_for_operation(connection, key_bundle, database_id, transition.operation_id)?;
    if persisted.len() != updates.len() {
        return Ok(false);
    }
    Ok(persisted.iter().zip(updates).all(|(existing, requested)| {
        existing.record.operation_id == transition.operation_id
            && existing.record.recipient == requested.recipient
            && existing.record.key_revision == requested.key_revision
            && existing.record.canonical_update_set == requested.canonical_update_set
            && existing.record.created_at_ms == frozen_at_ms
    }))
}

pub(super) fn authenticate_transition(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawTransition,
) -> Result<AuthenticatedTransition, RuntimeStoreError> {
    let operation_id = fixed(&raw.operation_id)?;
    let database_id = fixed(&raw.database_id)?;
    let sealed_bytes = nonnegative(raw.sealed_state_bytes)?;
    if database_id != expected_database_id
        || sealed_bytes != u64::try_from(raw.sealed_state.len()).unwrap_or(u64::MAX)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open_transition(key_bundle, database_id, operation_id, &raw.sealed_state)?;
    let canonical = plaintext.expose_secret();
    let record = decode_transition(canonical)?;
    let codec_version = canonical
        .get(TRANSITION_MAGIC.len())
        .copied()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let metadata_token = fixed(&raw.metadata_token)?;
    if !transition_outer_matches(operation_id, &record, &raw)?
        || metadata_token
            != transition_metadata_token_from_canonical(
                key_bundle,
                database_id,
                operation_id,
                canonical,
                &raw.sealed_state,
            )?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedTransition {
        record,
        codec_version,
        sealed_bytes,
        metadata_token,
    })
}

pub(super) fn transition_outer_matches(
    operation_id: [u8; 16],
    record: &KeyTransitionRecord,
    raw: &RawTransition,
) -> Result<bool, RuntimeStoreError> {
    let operation = parse_operation(&raw.operation_kind)?;
    let target = match operation {
        KeyTransitionOperation::Add
        | KeyTransitionOperation::Renew
        | KeyTransitionOperation::Revoke => {
            if raw.target_conversation_id.is_some() || raw.target_stream_route.is_some() {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            KeyTransitionTarget::Device(KeyTransitionRecipient {
                device_route: fixed(
                    raw.target_device_route
                        .as_deref()
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                )?,
                grant_serial: canonical_sequence(
                    raw.target_grant_serial
                        .as_deref()
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                    false,
                )?,
            })
        }
        KeyTransitionOperation::ActivateConversation => {
            if raw.target_device_route.is_some() || raw.target_grant_serial.is_some() {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            KeyTransitionTarget::Conversation {
                conversation_id: fixed(
                    raw.target_conversation_id
                        .as_deref()
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                )?,
                stream_route: fixed(
                    raw.target_stream_route
                        .as_deref()
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                )?,
            }
        }
        KeyTransitionOperation::CounterRecovery => match (
            raw.target_device_route.as_deref(),
            raw.target_grant_serial.as_deref(),
            raw.target_conversation_id.as_deref(),
            raw.target_stream_route.as_deref(),
        ) {
            (Some(device_route), Some(grant_serial), None, None) => {
                KeyTransitionTarget::Device(KeyTransitionRecipient {
                    device_route: fixed(device_route)?,
                    grant_serial: canonical_sequence(grant_serial, false)?,
                })
            }
            (None, None, Some(conversation_id), Some(stream_route)) => {
                KeyTransitionTarget::Conversation {
                    conversation_id: fixed(conversation_id)?,
                    stream_route: fixed(stream_route)?,
                }
            }
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        },
    };
    let phase = parse_phase(&raw.phase)?;
    let terminal = raw
        .terminal_kind
        .as_deref()
        .map(parse_terminal)
        .transpose()?;
    let recipient_count = usize::try_from(nonnegative(raw.recipient_count)?)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let stream_count = usize::try_from(nonnegative(raw.stream_count)?)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(record.operation_id == operation_id
        && record.operation == operation
        && record.target == target
        && record.from_revision == canonical_sequence(&raw.from_revision, true)?
        && record.to_revision == canonical_sequence(&raw.to_revision, false)?
        && record.phase == phase
        && record.terminal == terminal
        && record.recipients.len() == recipient_count
        && record.cuts.len() == stream_count
        && record.update_count == nonnegative(raw.update_count)?
        && record.created_at_ms == nonnegative(raw.created_at_ms)?
        && record.state_changed_at_ms == nonnegative(raw.state_changed_at_ms)?
        && record.terminal_at_ms == raw.terminal_at_ms.map(nonnegative).transpose()?
        && record.retain_until_ms == raw.retain_until_ms.map(nonnegative).transpose()?)
}

pub(super) fn authenticate_update(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawUpdate,
) -> Result<AuthenticatedUpdate, RuntimeStoreError> {
    let operation_id = fixed(&raw.operation_id)?;
    let device_route = fixed(&raw.device_route)?;
    let grant_serial = canonical_sequence(&raw.grant_serial, false)?;
    let database_id = fixed(&raw.database_id)?;
    let sealed_bytes = nonnegative(raw.sealed_state_bytes)?;
    if database_id != expected_database_id
        || sealed_bytes != u64::try_from(raw.sealed_state.len()).unwrap_or(u64::MAX)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let primary_key = update_primary_key(operation_id, device_route, grant_serial);
    let plaintext = open_update(key_bundle, database_id, &primary_key, &raw.sealed_state)?;
    let canonical = plaintext.expose_secret();
    let record = decode_update(canonical)?;
    let codec_version = canonical
        .get(4)
        .copied()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let update_hash = fixed(&raw.update_hash)?;
    let ack_hash = raw.ack_hash.as_deref().map(fixed).transpose()?;
    let applied_ack_set_hash = raw.applied_ack_set_hash.as_deref().map(fixed).transpose()?;
    let expected_ack_hash = match record.lifecycle {
        KeyUpdateLifecycle::Acked => Some(
            Sha256::digest(
                record
                    .canonical_ack
                    .as_deref()
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .into(),
        ),
        KeyUpdateLifecycle::Frozen | KeyUpdateLifecycle::Cancelled => None,
    };
    let metadata_token = fixed(&raw.metadata_token)?;
    if record.operation_id != operation_id
        || record.recipient.device_route != device_route
        || record.recipient.grant_serial != grant_serial
        || record.key_revision != canonical_sequence(&raw.key_revision, false)?
        || record.lifecycle != parse_lifecycle(&raw.lifecycle)?
        || canonical_update_hash(&record.canonical_update_set)? != update_hash
        || nonnegative(raw.canonical_update_bytes)?
            != u64::try_from(record.canonical_update_set.len()).unwrap_or(u64::MAX)
        || record.created_at_ms != nonnegative(raw.created_at_ms)?
        || record.state_changed_at_ms != nonnegative(raw.state_changed_at_ms)?
        || ack_hash != expected_ack_hash
        || nonnegative(raw.applied_ack_count)?
            != u64::try_from(record.stream_applied_acks.len()).unwrap_or(u64::MAX)
        || applied_ack_set_hash != projected_applied_ack_set_hash(&record)?
        || metadata_token
            != update_metadata_token_from_canonical(
                key_bundle,
                database_id,
                &primary_key,
                canonical,
                &raw.sealed_state,
            )?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedUpdate {
        record,
        codec_version,
        sealed_bytes,
        metadata_token,
    })
}

pub(super) fn insert_transition(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &KeyTransitionRecord,
    ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let (sealed, metadata_token) = seal_transition_row(key_bundle, database_id, record)?;
    let sealed_bytes =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let TransitionTargetColumns {
        device: target_device,
        grant_serial: target_grant,
        conversation: target_conversation,
        stream_route: target_route,
    } = target_columns(record);
    if transaction.execute(
        "INSERT INTO remote_key_transitions(
             operation_id, active_slot, database_id, operation_kind, target_device_route,
             target_grant_serial, target_conversation_id, target_stream_route, from_revision,
             to_revision, phase, terminal_kind, recipient_count, stream_count, update_count,
             created_at_ms, state_changed_at_ms, terminal_at_ms, retain_until_ms, sealed_state,
             sealed_state_bytes, metadata_token)
         VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            &record.operation_id[..],
            &database_id[..],
            operation_text(record.operation),
            target_device,
            target_grant,
            target_conversation,
            target_route,
            super::super::sequence::encode_sequence(record.from_revision),
            super::super::sequence::encode_sequence(record.to_revision),
            phase_text(record.phase),
            record.terminal.map(terminal_text),
            sql_count(record.recipients.len())?,
            sql_count(record.cuts.len())?,
            i64::try_from(record.update_count).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            sql_time(record.created_at_ms)?,
            sql_time(record.state_changed_at_ms)?,
            record.terminal_at_ms.map(sql_time).transpose()?,
            record.retain_until_ms.map(sql_time).transpose()?,
            &sealed,
            i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    ledger.remote_key_transition_count = checked_add(ledger.remote_key_transition_count, 1)?;
    ledger.remote_key_transition_active_count =
        checked_add(ledger.remote_key_transition_active_count, 1)?;
    ledger.remote_key_transition_sealed_bytes =
        checked_add(ledger.remote_key_transition_sealed_bytes, sealed_bytes)?;
    validate_ledger_caps(ledger)
}

pub(super) fn replace_transition(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &AuthenticatedTransition,
    record: &KeyTransitionRecord,
    ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    if previous.record.operation_id != record.operation_id
        || previous.record.phase.rank() > record.phase.rank()
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let (sealed, metadata_token) = seal_transition_row(key_bundle, database_id, record)?;
    let sealed_bytes =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let TransitionTargetColumns {
        device: target_device,
        grant_serial: target_grant,
        conversation: target_conversation,
        stream_route: target_route,
    } = target_columns(record);
    if transaction.execute(
        "UPDATE remote_key_transitions
         SET operation_kind = ?1, target_device_route = ?2, target_grant_serial = ?3,
             target_conversation_id = ?4, target_stream_route = ?5, from_revision = ?6,
             to_revision = ?7, phase = ?8, terminal_kind = ?9, recipient_count = ?10,
             stream_count = ?11, update_count = ?12, created_at_ms = ?13,
             state_changed_at_ms = ?14, terminal_at_ms = ?15, retain_until_ms = ?16,
             sealed_state = ?17, sealed_state_bytes = ?18, metadata_token = ?19
         WHERE operation_id = ?20 AND metadata_token = ?21",
        params![
            operation_text(record.operation),
            target_device,
            target_grant,
            target_conversation,
            target_route,
            super::super::sequence::encode_sequence(record.from_revision),
            super::super::sequence::encode_sequence(record.to_revision),
            phase_text(record.phase),
            record.terminal.map(terminal_text),
            sql_count(record.recipients.len())?,
            sql_count(record.cuts.len())?,
            i64::try_from(record.update_count).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            sql_time(record.created_at_ms)?,
            sql_time(record.state_changed_at_ms)?,
            record.terminal_at_ms.map(sql_time).transpose()?,
            record.retain_until_ms.map(sql_time).transpose()?,
            &sealed,
            i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &metadata_token[..],
            &record.operation_id[..],
            &previous.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    ledger.remote_key_transition_sealed_bytes = ledger
        .remote_key_transition_sealed_bytes
        .checked_sub(previous.sealed_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    ledger.remote_key_transition_sealed_bytes =
        checked_add(ledger.remote_key_transition_sealed_bytes, sealed_bytes)?;
    if previous.record.phase != KeyTransitionPhase::Complete
        && record.phase == KeyTransitionPhase::Complete
    {
        ledger.remote_key_transition_active_count = ledger
            .remote_key_transition_active_count
            .checked_sub(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    validate_ledger_caps(ledger)
}

pub(super) fn insert_update(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &KeyUpdateRecord,
    ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let (sealed, metadata_token) = seal_update_row(key_bundle, database_id, record)?;
    let sealed_bytes =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let update_hash = canonical_update_hash(&record.canonical_update_set)?;
    let ack_hash = projected_ack_hash(record)?;
    let applied_ack_set_hash = projected_applied_ack_set_hash(record)?;
    if transaction.execute(
        "INSERT INTO remote_key_update_outbox(
             operation_id, device_route, grant_serial, database_id, key_revision, lifecycle,
             update_hash, canonical_update_bytes, ack_hash, applied_ack_count,
             applied_ack_set_hash, created_at_ms, state_changed_at_ms, sealed_state,
             sealed_state_bytes, metadata_token)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16)",
        params![
            &record.operation_id[..],
            &record.recipient.device_route[..],
            super::super::sequence::encode_sequence(record.recipient.grant_serial),
            &database_id[..],
            super::super::sequence::encode_sequence(record.key_revision),
            lifecycle_text(record.lifecycle),
            &update_hash[..],
            sql_count(record.canonical_update_set.len())?,
            ack_hash.as_ref().map(<[u8; 32]>::as_slice),
            sql_count(record.stream_applied_acks.len())?,
            applied_ack_set_hash.as_ref().map(<[u8; 32]>::as_slice),
            sql_time(record.created_at_ms)?,
            sql_time(record.state_changed_at_ms)?,
            &sealed,
            i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    ledger.remote_key_update_outbox_count = checked_add(ledger.remote_key_update_outbox_count, 1)?;
    ledger.remote_key_update_outbox_sealed_bytes =
        checked_add(ledger.remote_key_update_outbox_sealed_bytes, sealed_bytes)?;
    validate_ledger_caps(ledger)
}

pub(super) fn replace_update(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &AuthenticatedUpdate,
    record: &KeyUpdateRecord,
    ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    if previous.record.operation_id != record.operation_id
        || previous.record.recipient != record.recipient
        || previous.record.key_revision != record.key_revision
        || previous.record.canonical_update_set != record.canonical_update_set
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let (sealed, metadata_token) = seal_update_row(key_bundle, database_id, record)?;
    let sealed_bytes =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let update_hash = canonical_update_hash(&record.canonical_update_set)?;
    let ack_hash = projected_ack_hash(record)?;
    let applied_ack_set_hash = projected_applied_ack_set_hash(record)?;
    if transaction.execute(
        "UPDATE remote_key_update_outbox
         SET key_revision = ?1, lifecycle = ?2, update_hash = ?3,
             canonical_update_bytes = ?4, ack_hash = ?5, applied_ack_count = ?6,
             applied_ack_set_hash = ?7, created_at_ms = ?8, state_changed_at_ms = ?9,
             sealed_state = ?10, sealed_state_bytes = ?11, metadata_token = ?12
         WHERE operation_id = ?13 AND device_route = ?14 AND grant_serial = ?15
           AND metadata_token = ?16",
        params![
            super::super::sequence::encode_sequence(record.key_revision),
            lifecycle_text(record.lifecycle),
            &update_hash[..],
            sql_count(record.canonical_update_set.len())?,
            ack_hash.as_ref().map(<[u8; 32]>::as_slice),
            sql_count(record.stream_applied_acks.len())?,
            applied_ack_set_hash.as_ref().map(<[u8; 32]>::as_slice),
            sql_time(record.created_at_ms)?,
            sql_time(record.state_changed_at_ms)?,
            &sealed,
            i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &metadata_token[..],
            &record.operation_id[..],
            &record.recipient.device_route[..],
            super::super::sequence::encode_sequence(record.recipient.grant_serial),
            &previous.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    ledger.remote_key_update_outbox_sealed_bytes = ledger
        .remote_key_update_outbox_sealed_bytes
        .checked_sub(previous.sealed_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    ledger.remote_key_update_outbox_sealed_bytes =
        checked_add(ledger.remote_key_update_outbox_sealed_bytes, sealed_bytes)?;
    validate_ledger_caps(ledger)
}

pub(super) fn delete_authenticated_update(
    transaction: &Transaction<'_>,
    update: &AuthenticatedUpdate,
) -> Result<(), RuntimeStoreError> {
    if transaction.execute(
        "DELETE FROM remote_key_update_outbox
         WHERE operation_id = ?1 AND device_route = ?2 AND grant_serial = ?3
           AND metadata_token = ?4 AND sealed_state_bytes = ?5",
        params![
            &update.record.operation_id[..],
            &update.record.recipient.device_route[..],
            super::super::sequence::encode_sequence(update.record.recipient.grant_serial),
            &update.metadata_token[..],
            i64::try_from(update.sealed_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(())
}

pub(super) fn delete_authenticated_transition(
    transaction: &Transaction<'_>,
    transition: &AuthenticatedTransition,
) -> Result<(), RuntimeStoreError> {
    if transaction.execute(
        "DELETE FROM remote_key_transitions
         WHERE operation_id = ?1 AND metadata_token = ?2 AND sealed_state_bytes = ?3",
        params![
            &transition.record.operation_id[..],
            &transition.metadata_token[..],
            i64::try_from(transition.sealed_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(())
}

pub(super) fn seal_transition_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &KeyTransitionRecord,
) -> Result<(Vec<u8>, [u8; 32]), RuntimeStoreError> {
    let plaintext = encode_transition(record)?;
    let sealed = key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: TRANSITION_TABLE,
            primary_key: &record.operation_id,
            column: SEALED_COLUMN,
        },
        plaintext.as_ref(),
        MAX_TRANSITION_PLAINTEXT_BYTES,
    )?;
    let token = transition_metadata_token(key_bundle, database_id, record, &sealed)?;
    Ok((sealed, token))
}

#[cfg(test)]
pub(super) fn seal_transition_row_legacy_for_test(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &KeyTransitionRecord,
    version: u8,
) -> Result<(Vec<u8>, [u8; 32]), RuntimeStoreError> {
    let plaintext = super::codec::encode_transition_legacy_for_test(record, version)?;
    let sealed = key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: TRANSITION_TABLE,
            primary_key: &record.operation_id,
            column: SEALED_COLUMN,
        },
        plaintext.as_ref(),
        MAX_TRANSITION_PLAINTEXT_BYTES,
    )?;
    let token = transition_metadata_token_from_canonical(
        key_bundle,
        database_id,
        record.operation_id,
        plaintext.as_slice(),
        &sealed,
    )?;
    Ok((sealed, token))
}

pub(super) fn open_transition(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    operation_id: [u8; 16],
    sealed: &[u8],
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: TRANSITION_TABLE,
            primary_key: &operation_id,
            column: SEALED_COLUMN,
        },
        sealed,
        MAX_TRANSITION_PLAINTEXT_BYTES,
    )?)
}

pub(super) fn seal_update_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &KeyUpdateRecord,
) -> Result<(Vec<u8>, [u8; 32]), RuntimeStoreError> {
    let primary_key = update_primary_key(
        record.operation_id,
        record.recipient.device_route,
        record.recipient.grant_serial,
    );
    let plaintext = encode_update(record)?;
    let sealed = key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: UPDATE_TABLE,
            primary_key: &primary_key,
            column: SEALED_COLUMN,
        },
        plaintext.as_ref(),
        MAX_UPDATE_PLAINTEXT_BYTES,
    )?;
    let token = update_metadata_token(key_bundle, database_id, record, &sealed)?;
    Ok((sealed, token))
}

pub(super) fn open_update(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    primary_key: &[u8],
    sealed: &[u8],
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: UPDATE_TABLE,
            primary_key,
            column: SEALED_COLUMN,
        },
        sealed,
        MAX_UPDATE_PLAINTEXT_BYTES,
    )?)
}

pub(super) fn transition_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &KeyTransitionRecord,
    sealed: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let canonical = encode_transition(record)?;
    transition_metadata_token_from_canonical(
        key_bundle,
        database_id,
        record.operation_id,
        canonical.as_slice(),
        sealed,
    )
}

fn transition_metadata_token_from_canonical(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    operation_id: [u8; 16],
    canonical: &[u8],
    sealed: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let sealed_len = u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let sealed_len = sealed_len.to_be_bytes();
    let sealed_hash = Sha256::digest(sealed);
    super::super::stream::metadata_mac(
        key_bundle,
        TRANSITION_METADATA_DOMAIN,
        &[
            database_id.as_slice(),
            operation_id.as_slice(),
            canonical,
            sealed_len.as_slice(),
            sealed_hash.as_slice(),
        ],
    )
}

pub(super) fn update_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &KeyUpdateRecord,
    sealed: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let canonical = encode_update(record)?;
    let primary_key = update_primary_key(
        record.operation_id,
        record.recipient.device_route,
        record.recipient.grant_serial,
    );
    update_metadata_token_from_canonical(
        key_bundle,
        database_id,
        &primary_key,
        canonical.as_slice(),
        sealed,
    )
}

fn update_metadata_token_from_canonical(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    primary_key: &[u8],
    canonical: &[u8],
    sealed: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let sealed_len = u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let sealed_len = sealed_len.to_be_bytes();
    let sealed_hash = Sha256::digest(sealed);
    super::super::stream::metadata_mac(
        key_bundle,
        UPDATE_METADATA_DOMAIN,
        &[
            database_id.as_slice(),
            primary_key,
            canonical,
            sealed_len.as_slice(),
            sealed_hash.as_slice(),
        ],
    )
}

pub(super) fn update_primary_key(
    operation_id: [u8; 16],
    device_route: [u8; 16],
    grant_serial: u64,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&operation_id);
    key.extend_from_slice(&device_route);
    key.extend_from_slice(&grant_serial.to_be_bytes());
    key
}

pub(super) fn projected_ack_hash(
    record: &KeyUpdateRecord,
) -> Result<Option<[u8; 32]>, RuntimeStoreError> {
    match record.lifecycle {
        KeyUpdateLifecycle::Acked => {
            let hash: [u8; 32] = Sha256::digest(
                record
                    .canonical_ack
                    .as_deref()
                    .ok_or(RuntimeStoreError::PublicationMismatch)?,
            )
            .into();
            if hash == [0; 32] {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
            Ok(Some(hash))
        }
        KeyUpdateLifecycle::Frozen | KeyUpdateLifecycle::Cancelled => Ok(None),
    }
}

pub(super) fn projected_applied_ack_set_hash(
    record: &KeyUpdateRecord,
) -> Result<Option<[u8; 32]>, RuntimeStoreError> {
    if record.stream_applied_acks.is_empty() {
        return Ok(None);
    }
    let mut digest = Sha256::new();
    digest.update(b"runtime.remote.stream-applied-ack-set.v1");
    digest.update(
        u32::try_from(record.stream_applied_acks.len())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    for ack in &record.stream_applied_acks {
        match ack.scope {
            KeyTransitionStreamScope::Catalog => digest.update([1]),
            KeyTransitionStreamScope::Conversation(conversation_id) => {
                digest.update([2]);
                digest.update(conversation_id);
            }
        }
        digest.update(ack.stream_route);
        digest.update(ack.stream_generation);
        digest.update(ack.applied_stream_seq.to_be_bytes());
        match ack.inner_cursor {
            None => digest.update([0]),
            Some(cursor) => {
                digest.update([1]);
                digest.update(cursor.to_be_bytes());
            }
        }
        digest.update(ack.key_revision.to_be_bytes());
        digest.update(ack.key_epoch.to_be_bytes());
        digest.update(ack.epoch_barrier_sha256);
        digest.update(
            u32::try_from(ack.canonical_ack.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
                .to_be_bytes(),
        );
        digest.update(&ack.canonical_ack);
        digest.update(ack.acknowledged_at_ms.to_be_bytes());
    }
    let hash: [u8; 32] = digest.finalize().into();
    if hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(hash))
}

struct TransitionTargetColumns<'a> {
    device: Option<&'a [u8]>,
    grant_serial: Option<String>,
    conversation: Option<&'a [u8]>,
    stream_route: Option<&'a [u8]>,
}

fn target_columns(record: &KeyTransitionRecord) -> TransitionTargetColumns<'_> {
    match &record.target {
        KeyTransitionTarget::Device(target) => TransitionTargetColumns {
            device: Some(&target.device_route),
            grant_serial: Some(super::super::sequence::encode_sequence(target.grant_serial)),
            conversation: None,
            stream_route: None,
        },
        KeyTransitionTarget::Conversation {
            conversation_id,
            stream_route,
        } => TransitionTargetColumns {
            device: None,
            grant_serial: None,
            conversation: Some(conversation_id),
            stream_route: Some(stream_route),
        },
    }
}

const fn operation_text(operation: KeyTransitionOperation) -> &'static str {
    match operation {
        KeyTransitionOperation::Add => "Add",
        KeyTransitionOperation::Renew => "Renew",
        KeyTransitionOperation::Revoke => "Revoke",
        KeyTransitionOperation::ActivateConversation => "ActivateConversation",
        KeyTransitionOperation::CounterRecovery => "CounterRecovery",
    }
}

pub(super) fn parse_operation(value: &str) -> Result<KeyTransitionOperation, RuntimeStoreError> {
    match value {
        "Add" => Ok(KeyTransitionOperation::Add),
        "Renew" => Ok(KeyTransitionOperation::Renew),
        "Revoke" => Ok(KeyTransitionOperation::Revoke),
        "ActivateConversation" => Ok(KeyTransitionOperation::ActivateConversation),
        "CounterRecovery" => Ok(KeyTransitionOperation::CounterRecovery),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn phase_text(phase: KeyTransitionPhase) -> &'static str {
    match phase {
        KeyTransitionPhase::DrainingOld => "DrainingOld",
        KeyTransitionPhase::RotatedPreparingUpdates => "RotatedPreparingUpdates",
        KeyTransitionPhase::UpdatesFrozen => "UpdatesFrozen",
        KeyTransitionPhase::BarriersFrozen => "BarriersFrozen",
        KeyTransitionPhase::BarriersCommitted => "BarriersCommitted",
        KeyTransitionPhase::Complete => "Complete",
    }
}

pub(super) fn parse_phase(value: &str) -> Result<KeyTransitionPhase, RuntimeStoreError> {
    match value {
        "DrainingOld" => Ok(KeyTransitionPhase::DrainingOld),
        "RotatedPreparingUpdates" => Ok(KeyTransitionPhase::RotatedPreparingUpdates),
        "UpdatesFrozen" => Ok(KeyTransitionPhase::UpdatesFrozen),
        "BarriersFrozen" => Ok(KeyTransitionPhase::BarriersFrozen),
        "BarriersCommitted" => Ok(KeyTransitionPhase::BarriersCommitted),
        "Complete" => Ok(KeyTransitionPhase::Complete),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn terminal_text(terminal: KeyTransitionTerminal) -> &'static str {
    match terminal {
        KeyTransitionTerminal::Completed => "Completed",
        KeyTransitionTerminal::Cancelled => "Cancelled",
    }
}

pub(super) fn parse_terminal(value: &str) -> Result<KeyTransitionTerminal, RuntimeStoreError> {
    match value {
        "Completed" => Ok(KeyTransitionTerminal::Completed),
        "Cancelled" => Ok(KeyTransitionTerminal::Cancelled),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn lifecycle_text(lifecycle: KeyUpdateLifecycle) -> &'static str {
    match lifecycle {
        KeyUpdateLifecycle::Frozen => "Frozen",
        KeyUpdateLifecycle::Acked => "Acked",
        KeyUpdateLifecycle::Cancelled => "Cancelled",
    }
}

pub(super) fn parse_lifecycle(value: &str) -> Result<KeyUpdateLifecycle, RuntimeStoreError> {
    match value {
        "Frozen" => Ok(KeyUpdateLifecycle::Frozen),
        "Acked" => Ok(KeyUpdateLifecycle::Acked),
        "Cancelled" => Ok(KeyUpdateLifecycle::Cancelled),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

pub(super) fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn canonical_sequence(value: &str, allow_zero: bool) -> Result<u64, RuntimeStoreError> {
    if value.len() != super::super::sequence::SEQUENCE_TEXT_WIDTH
        || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let decoded = value
        .parse::<u64>()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if (!allow_zero && decoded == 0) || super::super::sequence::encode_sequence(decoded) != value {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(decoded)
}

pub(super) fn sql_count(value: usize) -> Result<i64, RuntimeStoreError> {
    i64::try_from(value).map_err(|_| RuntimeStoreError::PayloadTooLarge)
}

pub(super) fn sql_time(value: u64) -> Result<i64, RuntimeStoreError> {
    i64::try_from(value).map_err(|_| RuntimeStoreError::TimeOutOfRange)
}

pub(super) fn checked_add(left: u64, right: u64) -> Result<u64, RuntimeStoreError> {
    left.checked_add(right)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn validate_ledger_caps(ledger: &RuntimeLedger) -> Result<(), RuntimeStoreError> {
    if ledger.remote_key_transition_count > MAX_KEY_TRANSITIONS
        || ledger.remote_key_transition_active_count > 1
        || ledger.remote_key_transition_sealed_bytes > MAX_KEY_TRANSITION_SEALED_BYTES
        || ledger.remote_key_update_outbox_count > MAX_KEY_UPDATE_ROWS
        || ledger.remote_key_update_outbox_sealed_bytes > MAX_KEY_UPDATE_SEALED_BYTES
    {
        return Err(RuntimeStoreError::StoreFull {
            projected_footprint_bytes: ledger
                .remote_key_transition_sealed_bytes
                .saturating_add(ledger.remote_key_update_outbox_sealed_bytes),
            hard_limit_bytes: MAX_KEY_TRANSITION_SEALED_BYTES
                .saturating_add(MAX_KEY_UPDATE_SEALED_BYTES),
        });
    }
    Ok(())
}
