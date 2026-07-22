use zeroize::Zeroizing;

use super::*;

pub(super) fn validate_transition_record(
    record: &KeyTransitionRecord,
) -> Result<(), RuntimeStoreError> {
    validate_begin(&BeginKeyTransition {
        operation_id: record.operation_id,
        operation: record.operation,
        target: record.target,
        from_revision: record.from_revision,
        to_revision: record.to_revision,
        recipients: record.recipients.clone(),
        replay_retirement: record.replay_retirement.map(|mut retirement| {
            retirement.lifecycle = ReplayRetirementLifecycle::Pending;
            retirement
        }),
        created_at_ms: record.created_at_ms,
    })?;
    if record.state_changed_at_ms < record.created_at_ms
        || record.state_changed_at_ms > MAX_TERMINAL_BASE_MS
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let recipient_count =
        u64::try_from(record.recipients.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    if record.update_count > recipient_count {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if matches!(
        record.replay_retirement,
        Some(ReplayRetirement {
            lifecycle: ReplayRetirementLifecycle::Applied,
            ..
        })
    ) && record.phase != KeyTransitionPhase::Complete
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if record.counter_retirement == CounterRetirementLifecycle::Applied
        && record.phase != KeyTransitionPhase::Complete
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    match record.phase {
        KeyTransitionPhase::DrainingOld | KeyTransitionPhase::RotatedPreparingUpdates => {
            if record.update_count != 0 || !record.cuts.is_empty() {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
        }
        KeyTransitionPhase::UpdatesFrozen => {
            if record.update_count != recipient_count || !record.cuts.is_empty() {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
        }
        KeyTransitionPhase::BarriersFrozen | KeyTransitionPhase::BarriersCommitted => {
            if record.update_count != recipient_count {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
            validate_transition_stream_cuts(record, &record.cuts)?;
        }
        KeyTransitionPhase::Complete => match record.terminal {
            Some(KeyTransitionTerminal::Completed) => {
                if record.update_count != recipient_count {
                    return Err(RuntimeStoreError::PublicationMismatch);
                }
                validate_transition_stream_cuts(record, &record.cuts)?;
            }
            Some(KeyTransitionTerminal::Cancelled) => {
                if record.update_count != 0 && record.update_count != recipient_count {
                    return Err(RuntimeStoreError::PublicationMismatch);
                }
                if !record.cuts.is_empty() {
                    validate_transition_stream_cuts(record, &record.cuts)?;
                }
            }
            None => return Err(RuntimeStoreError::PublicationMismatch),
        },
    }
    match (
        record.phase,
        record.terminal,
        record.terminal_at_ms,
        record.retain_until_ms,
    ) {
        (KeyTransitionPhase::Complete, Some(_), Some(terminal_at), Some(retain_until))
            if terminal_at == record.state_changed_at_ms
                && retain_until
                    == terminal_at
                        .checked_add(KEY_TRANSITION_TOMBSTONE_RETENTION_MS)
                        .ok_or(RuntimeStoreError::TimeOutOfRange)? =>
        {
            Ok(())
        }
        (phase, None, None, None) if phase != KeyTransitionPhase::Complete => Ok(()),
        _ => Err(RuntimeStoreError::PublicationMismatch),
    }
}

pub(super) fn validate_update_record(record: &KeyUpdateRecord) -> Result<(), RuntimeStoreError> {
    validate_nonzero(record.operation_id)?;
    validate_nonzero(record.recipient.device_route)?;
    if record.recipient.grant_serial == 0
        || record.key_revision == 0
        || record.canonical_update_set.is_empty()
        || record.canonical_update_set.len() > MAX_CANONICAL_KEY_UPDATE_BYTES
        || record.created_at_ms > MAX_TERMINAL_BASE_MS
        || record.state_changed_at_ms < record.created_at_ms
        || record.state_changed_at_ms > MAX_TERMINAL_BASE_MS
        || canonical_update_hash(&record.canonical_update_set)? == [0; 32]
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    match (record.lifecycle, record.canonical_ack.as_deref()) {
        (KeyUpdateLifecycle::Frozen, None) => Ok(()),
        (KeyUpdateLifecycle::Acked, Some(ack))
            if !ack.is_empty() && ack.len() <= MAX_CANONICAL_KEY_ACK_BYTES =>
        {
            Ok(())
        }
        (KeyUpdateLifecycle::Cancelled, None) => Ok(()),
        (KeyUpdateLifecycle::Cancelled, Some(ack))
            if !ack.is_empty() && ack.len() <= MAX_CANONICAL_KEY_ACK_BYTES =>
        {
            Ok(())
        }
        _ => Err(RuntimeStoreError::PublicationMismatch),
    }?;
    if record.snapshot_flushes.len() > MAX_KEY_TRANSITION_CONVERSATIONS + 1
        || record.stream_applied_acks.len() > MAX_KEY_TRANSITION_CONVERSATIONS + 1
        || record.lifecycle != KeyUpdateLifecycle::Acked
            && (!record.snapshot_flushes.is_empty() || !record.stream_applied_acks.is_empty())
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let mut previous_flush = None;
    for flush in &record.snapshot_flushes {
        let identity = snapshot_flush_identity(flush);
        let expected_barrier = match flush.relay_committed_outer {
            None => 0,
            Some(value) => value
                .checked_add(1)
                .ok_or(RuntimeStoreError::PublicationCounterExhausted)?,
        };
        if flush.publication_stream_id == [0; 16]
            || flush.stream_route == [0; 16]
            || flush.generation == [0; 16]
            || matches!(flush.scope, KeyTransitionStreamScope::Conversation(id) if id == [0; 16])
            || flush.barrier_sequence != expected_barrier
            || flush.key_directory_revision != record.key_revision
            || flush.key_epoch == 0
            || flush.epoch_barrier_sha256 == [0; 32]
            || flush.authorization_hash == [0; 32]
            || flush.sync_complete_sha256 == [0; 32]
            || flush.flushed_at_ms < record.created_at_ms
            || flush.flushed_at_ms > record.state_changed_at_ms
            || previous_flush.is_some_and(|value| value >= identity)
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        previous_flush = Some(identity);
    }
    let mut previous = None;
    for ack in &record.stream_applied_acks {
        let identity = applied_ack_identity(ack);
        if ack.stream_route == [0; 16]
            || matches!(ack.scope, KeyTransitionStreamScope::Conversation(id) if id == [0; 16])
            || ack.stream_generation == [0; 16]
            || ack.applied_stream_seq == u64::MAX
            || ack.key_revision != record.key_revision
            || ack.key_epoch == 0
            || ack.epoch_barrier_sha256 == [0; 32]
            || ack.canonical_ack.is_empty()
            || ack.canonical_ack.len() > MAX_CANONICAL_KEY_ACK_BYTES
            || ack.acknowledged_at_ms < record.created_at_ms
            || ack.acknowledged_at_ms > record.state_changed_at_ms
            || previous.is_some_and(|value| value >= identity)
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        previous = Some(identity);
    }
    Ok(())
}

pub(super) fn encode_transition(
    record: &KeyTransitionRecord,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    encode_transition_version(record, TRANSITION_CODEC_VERSION)
}

fn encode_transition_version(
    record: &KeyTransitionRecord,
    version: u8,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    validate_transition_record(record)?;
    if version == LEGACY_TRANSITION_CODEC_VERSION && record.replay_retirement.is_some()
        || !matches!(
            version,
            LEGACY_TRANSITION_CODEC_VERSION | TRANSITION_CODEC_VERSION
        )
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(16 * 1024));
    encoded.extend_from_slice(TRANSITION_MAGIC);
    encoded.push(version);
    encoded.extend_from_slice(&record.operation_id);
    encoded.push(operation_tag(record.operation));
    match record.target {
        KeyTransitionTarget::Device(target) => {
            encoded.push(1);
            encoded.extend_from_slice(&target.device_route);
            encoded.extend_from_slice(&target.grant_serial.to_be_bytes());
        }
        KeyTransitionTarget::Conversation {
            conversation_id,
            stream_route,
        } => {
            encoded.push(2);
            encoded.extend_from_slice(&conversation_id);
            encoded.extend_from_slice(&stream_route);
        }
    }
    encoded.extend_from_slice(&record.from_revision.to_be_bytes());
    encoded.extend_from_slice(&record.to_revision.to_be_bytes());
    encoded.push(phase_tag(record.phase));
    encoded.push(terminal_tag(record.terminal));
    push_count(&mut encoded, record.recipients.len())?;
    for recipient in &record.recipients {
        encoded.extend_from_slice(&recipient.device_route);
        encoded.extend_from_slice(&recipient.grant_serial.to_be_bytes());
    }
    push_count(&mut encoded, record.cuts.len())?;
    for cut in &record.cuts {
        match cut.scope {
            KeyTransitionStreamScope::Catalog => encoded.push(1),
            KeyTransitionStreamScope::Conversation(conversation_id) => {
                encoded.push(2);
                encoded.extend_from_slice(&conversation_id);
            }
        }
        encoded.extend_from_slice(&cut.publication_stream_id);
        encoded.extend_from_slice(&cut.stream_route);
        encoded.extend_from_slice(&cut.generation);
        match (cut.relay_committed_outer, cut.relay_committed_inner) {
            (None, None) => encoded.push(0),
            (Some(outer), Some(inner)) => {
                encoded.push(1);
                encoded.extend_from_slice(&outer.to_be_bytes());
                encoded.extend_from_slice(&inner.to_be_bytes());
            }
            (None, Some(inner)) if version == TRANSITION_CODEC_VERSION => {
                encoded.push(2);
                encoded.extend_from_slice(&inner.to_be_bytes());
            }
            (Some(outer), None) if version == TRANSITION_CODEC_VERSION => {
                encoded.push(3);
                encoded.extend_from_slice(&outer.to_be_bytes());
            }
            _ => return Err(RuntimeStoreError::PublicationMismatch),
        }
        encoded.extend_from_slice(&cut.barrier_sequence.to_be_bytes());
        encoded.extend_from_slice(&cut.old_epoch.to_be_bytes());
        encoded.extend_from_slice(&cut.new_epoch.to_be_bytes());
        encoded.extend_from_slice(&cut.epoch_barrier_sha256);
    }
    encoded.extend_from_slice(&record.update_count.to_be_bytes());
    encoded.extend_from_slice(&record.created_at_ms.to_be_bytes());
    encoded.extend_from_slice(&record.state_changed_at_ms.to_be_bytes());
    encoded.extend_from_slice(&record.terminal_at_ms.unwrap_or(0).to_be_bytes());
    encoded.extend_from_slice(&record.retain_until_ms.unwrap_or(0).to_be_bytes());
    if version == TRANSITION_CODEC_VERSION {
        encoded.push(match record.counter_retirement {
            CounterRetirementLifecycle::Pending => 1,
            CounterRetirementLifecycle::Applied => 2,
        });
        match record.replay_retirement {
            None => encoded.push(0),
            Some(retirement) => {
                encoded.push(1);
                encoded.extend_from_slice(&retirement.scope);
                encoded.extend_from_slice(&retirement.old_reply_key_epoch.to_be_bytes());
                encoded.push(match retirement.lifecycle {
                    ReplayRetirementLifecycle::Pending => 1,
                    ReplayRetirementLifecycle::Applied => 2,
                });
            }
        }
    }
    if encoded.len() > MAX_TRANSITION_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

pub(super) fn decode_transition(bytes: &[u8]) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4)? != TRANSITION_MAGIC {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let version = decoder.u8()?;
    if !matches!(
        version,
        LEGACY_TRANSITION_CODEC_VERSION | TRANSITION_CODEC_VERSION
    ) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let operation_id = decoder.fixed()?;
    let operation = operation_from_tag(decoder.u8()?)?;
    let target = match decoder.u8()? {
        1 => KeyTransitionTarget::Device(KeyTransitionRecipient {
            device_route: decoder.fixed()?,
            grant_serial: decoder.u64()?,
        }),
        2 => KeyTransitionTarget::Conversation {
            conversation_id: decoder.fixed()?,
            stream_route: decoder.fixed()?,
        },
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    let from_revision = decoder.u64()?;
    let to_revision = decoder.u64()?;
    let phase = phase_from_tag(decoder.u8()?)?;
    let terminal = terminal_from_tag(decoder.u8()?)?;
    let recipient_count = decoder.count(MAX_KEY_TRANSITION_RECIPIENTS)?;
    let mut recipients = Vec::new();
    recipients
        .try_reserve_exact(recipient_count)
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for _ in 0..recipient_count {
        recipients.push(KeyTransitionRecipient {
            device_route: decoder.fixed()?,
            grant_serial: decoder.u64()?,
        });
    }
    let cut_count = decoder.count(MAX_KEY_TRANSITION_CONVERSATIONS + 1)?;
    let mut cuts = Vec::new();
    cuts.try_reserve_exact(cut_count)
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for _ in 0..cut_count {
        let scope = match decoder.u8()? {
            1 => KeyTransitionStreamScope::Catalog,
            2 => KeyTransitionStreamScope::Conversation(decoder.fixed()?),
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let publication_stream_id = decoder.fixed()?;
        let stream_route = decoder.fixed()?;
        let generation = decoder.fixed()?;
        let (relay_committed_outer, relay_committed_inner) = match decoder.u8()? {
            0 => (None, None),
            1 => (Some(decoder.u64()?), Some(decoder.u64()?)),
            2 if version == TRANSITION_CODEC_VERSION => (None, Some(decoder.u64()?)),
            3 if version == TRANSITION_CODEC_VERSION => (Some(decoder.u64()?), None),
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        cuts.push(KeyTransitionStreamCut {
            scope,
            publication_stream_id,
            stream_route,
            generation,
            relay_committed_outer,
            relay_committed_inner,
            barrier_sequence: decoder.u64()?,
            old_epoch: decoder.u64()?,
            new_epoch: decoder.u64()?,
            epoch_barrier_sha256: decoder.fixed()?,
        });
    }
    let update_count = decoder.u64()?;
    let created_at_ms = decoder.u64()?;
    let state_changed_at_ms = decoder.u64()?;
    let terminal_at = decoder.u64()?;
    let retain_until = decoder.u64()?;
    let counter_retirement = if version == TRANSITION_CODEC_VERSION {
        match decoder.u8()? {
            1 => CounterRetirementLifecycle::Pending,
            2 => CounterRetirementLifecycle::Applied,
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    } else {
        // ADKT v1 没有已完成 guard-first GC 的证据；升级只能保守地视为
        // Pending，禁止把旧 tombstone 当作可回收证据。
        CounterRetirementLifecycle::Pending
    };
    let replay_retirement = if version == TRANSITION_CODEC_VERSION {
        match decoder.u8()? {
            0 => None,
            1 => Some(ReplayRetirement {
                scope: decoder.fixed()?,
                old_reply_key_epoch: decoder.u64()?,
                lifecycle: match decoder.u8()? {
                    1 => ReplayRetirementLifecycle::Pending,
                    2 => ReplayRetirementLifecycle::Applied,
                    _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
                },
            }),
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    } else {
        None
    };
    if !decoder.finished() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let record = KeyTransitionRecord {
        operation_id,
        operation,
        target,
        from_revision,
        to_revision,
        phase,
        terminal,
        recipients,
        replay_retirement,
        counter_retirement,
        cuts,
        update_count,
        created_at_ms,
        state_changed_at_ms,
        terminal_at_ms: terminal.map(|_| terminal_at),
        retain_until_ms: terminal.map(|_| retain_until),
    };
    validate_transition_record(&record).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if encode_transition_version(&record, version)?.as_slice() != bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(record)
}

pub(super) fn encode_update(
    record: &KeyUpdateRecord,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    encode_update_version(record, UPDATE_CODEC_VERSION)
}

fn encode_update_version(
    record: &KeyUpdateRecord,
    version: u8,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    validate_update_record(record)?;
    if !matches!(version, LEGACY_UPDATE_CODEC_VERSION | UPDATE_CODEC_VERSION)
        || version == LEGACY_UPDATE_CODEC_VERSION && !record.snapshot_flushes.is_empty()
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        record.canonical_update_set.len()
            + record.canonical_ack.as_ref().map_or(0, Vec::len)
            + record.snapshot_flushes.len() * 256
            + 128,
    ));
    encoded.extend_from_slice(UPDATE_MAGIC);
    encoded.push(version);
    encoded.extend_from_slice(&record.operation_id);
    encoded.extend_from_slice(&record.recipient.device_route);
    encoded.extend_from_slice(&record.recipient.grant_serial.to_be_bytes());
    encoded.extend_from_slice(&record.key_revision.to_be_bytes());
    encoded.push(lifecycle_tag(record.lifecycle));
    push_bytes(&mut encoded, &record.canonical_update_set)?;
    match &record.canonical_ack {
        None => encoded.push(0),
        Some(ack) => {
            encoded.push(1);
            push_bytes(&mut encoded, ack)?;
        }
    }
    push_count(&mut encoded, record.stream_applied_acks.len())?;
    for ack in &record.stream_applied_acks {
        match ack.scope {
            KeyTransitionStreamScope::Catalog => encoded.push(1),
            KeyTransitionStreamScope::Conversation(conversation_id) => {
                encoded.push(2);
                encoded.extend_from_slice(&conversation_id);
            }
        }
        encoded.extend_from_slice(&ack.stream_route);
        encoded.extend_from_slice(&ack.stream_generation);
        encoded.extend_from_slice(&ack.applied_stream_seq.to_be_bytes());
        match ack.inner_cursor {
            None => encoded.push(0),
            Some(cursor) => {
                encoded.push(1);
                encoded.extend_from_slice(&cursor.to_be_bytes());
            }
        }
        encoded.extend_from_slice(&ack.key_revision.to_be_bytes());
        encoded.extend_from_slice(&ack.key_epoch.to_be_bytes());
        encoded.extend_from_slice(&ack.epoch_barrier_sha256);
        push_bytes(&mut encoded, &ack.canonical_ack)?;
        encoded.extend_from_slice(&ack.acknowledged_at_ms.to_be_bytes());
    }
    if version >= UPDATE_CODEC_VERSION {
        push_count(&mut encoded, record.snapshot_flushes.len())?;
        for marker in &record.snapshot_flushes {
            match marker.scope {
                KeyTransitionStreamScope::Catalog => encoded.push(1),
                KeyTransitionStreamScope::Conversation(conversation_id) => {
                    encoded.push(2);
                    encoded.extend_from_slice(&conversation_id);
                }
            }
            encoded.extend_from_slice(&marker.publication_stream_id);
            encoded.extend_from_slice(&marker.stream_route);
            encoded.extend_from_slice(&marker.generation);
            match marker.relay_committed_outer {
                None => encoded.push(0),
                Some(cursor) => {
                    encoded.push(1);
                    encoded.extend_from_slice(&cursor.to_be_bytes());
                }
            }
            match marker.relay_committed_inner {
                None => encoded.push(0),
                Some(cursor) => {
                    encoded.push(1);
                    encoded.extend_from_slice(&cursor.to_be_bytes());
                }
            }
            encoded.extend_from_slice(&marker.barrier_sequence.to_be_bytes());
            encoded.extend_from_slice(&marker.key_directory_revision.to_be_bytes());
            encoded.extend_from_slice(&marker.key_epoch.to_be_bytes());
            encoded.extend_from_slice(&marker.epoch_barrier_sha256);
            encoded.extend_from_slice(&marker.authorization_hash);
            encoded.extend_from_slice(&marker.sync_complete_sha256);
            encoded.extend_from_slice(&marker.flushed_at_ms.to_be_bytes());
        }
    }
    encoded.extend_from_slice(&record.created_at_ms.to_be_bytes());
    encoded.extend_from_slice(&record.state_changed_at_ms.to_be_bytes());
    if encoded.len() > MAX_UPDATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

pub(super) fn decode_update(bytes: &[u8]) -> Result<KeyUpdateRecord, RuntimeStoreError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4)? != UPDATE_MAGIC {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let version = decoder.u8()?;
    if !matches!(version, LEGACY_UPDATE_CODEC_VERSION | UPDATE_CODEC_VERSION) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let operation_id = decoder.fixed()?;
    let recipient = KeyTransitionRecipient {
        device_route: decoder.fixed()?,
        grant_serial: decoder.u64()?,
    };
    let key_revision = decoder.u64()?;
    let lifecycle = lifecycle_from_tag(decoder.u8()?)?;
    let canonical_update_set = decoder.bytes(MAX_CANONICAL_KEY_UPDATE_BYTES)?;
    let canonical_ack = match decoder.u8()? {
        0 => None,
        1 => Some(decoder.bytes(MAX_CANONICAL_KEY_ACK_BYTES)?),
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    let applied_count = decoder.count(MAX_KEY_TRANSITION_CONVERSATIONS + 1)?;
    let mut stream_applied_acks = Vec::new();
    stream_applied_acks
        .try_reserve_exact(applied_count)
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for _ in 0..applied_count {
        let scope = match decoder.u8()? {
            1 => KeyTransitionStreamScope::Catalog,
            2 => KeyTransitionStreamScope::Conversation(decoder.fixed()?),
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let stream_route = decoder.fixed()?;
        let stream_generation = decoder.fixed()?;
        let applied_stream_seq = decoder.u64()?;
        let inner_cursor = match decoder.u8()? {
            0 => None,
            1 => Some(decoder.u64()?),
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        stream_applied_acks.push(StreamAppliedAckRecord {
            scope,
            stream_route,
            stream_generation,
            applied_stream_seq,
            inner_cursor,
            key_revision: decoder.u64()?,
            key_epoch: decoder.u64()?,
            epoch_barrier_sha256: decoder.fixed()?,
            canonical_ack: decoder.bytes(MAX_CANONICAL_KEY_ACK_BYTES)?,
            acknowledged_at_ms: decoder.u64()?,
        });
    }
    let mut snapshot_flushes = Vec::new();
    if version >= UPDATE_CODEC_VERSION {
        let flush_count = decoder.count(MAX_KEY_TRANSITION_CONVERSATIONS + 1)?;
        snapshot_flushes
            .try_reserve_exact(flush_count)
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        for _ in 0..flush_count {
            let scope = match decoder.u8()? {
                1 => KeyTransitionStreamScope::Catalog,
                2 => KeyTransitionStreamScope::Conversation(decoder.fixed()?),
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            };
            let publication_stream_id = decoder.fixed()?;
            let stream_route = decoder.fixed()?;
            let generation = decoder.fixed()?;
            let relay_committed_outer = match decoder.u8()? {
                0 => None,
                1 => Some(decoder.u64()?),
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            };
            let relay_committed_inner = match decoder.u8()? {
                0 => None,
                1 => Some(decoder.u64()?),
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            };
            snapshot_flushes.push(TransitionSnapshotFlushRecord {
                scope,
                publication_stream_id,
                stream_route,
                generation,
                relay_committed_outer,
                relay_committed_inner,
                barrier_sequence: decoder.u64()?,
                key_directory_revision: decoder.u64()?,
                key_epoch: decoder.u64()?,
                epoch_barrier_sha256: decoder.fixed()?,
                authorization_hash: decoder.fixed()?,
                sync_complete_sha256: decoder.fixed()?,
                flushed_at_ms: decoder.u64()?,
            });
        }
    }
    let created_at_ms = decoder.u64()?;
    let state_changed_at_ms = decoder.u64()?;
    if !decoder.finished() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let record = KeyUpdateRecord {
        operation_id,
        recipient,
        key_revision,
        lifecycle,
        canonical_update_set,
        canonical_ack,
        snapshot_flushes,
        stream_applied_acks,
        created_at_ms,
        state_changed_at_ms,
    };
    validate_update_record(&record).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if encode_update_version(&record, version)?.as_slice() != bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(record)
}

pub(super) fn push_count(encoded: &mut Vec<u8>, count: usize) -> Result<(), RuntimeStoreError> {
    encoded.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

pub(super) fn push_bytes(encoded: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RuntimeStoreError> {
    push_count(encoded, bytes.len())?;
    encoded.extend_from_slice(bytes);
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RuntimeStoreError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RuntimeStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }

    fn u8(&mut self) -> Result<u8, RuntimeStoreError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, RuntimeStoreError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, RuntimeStoreError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, RuntimeStoreError> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if count > maximum {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(count)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, RuntimeStoreError> {
        let count = self.count(maximum)?;
        Ok(self.take(count)?.to_vec())
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

const fn operation_tag(operation: KeyTransitionOperation) -> u8 {
    match operation {
        KeyTransitionOperation::Add => 1,
        KeyTransitionOperation::Revoke => 2,
        KeyTransitionOperation::ActivateConversation => 3,
        KeyTransitionOperation::Renew => 4,
        KeyTransitionOperation::CounterRecovery => 5,
    }
}

pub(super) fn operation_from_tag(tag: u8) -> Result<KeyTransitionOperation, RuntimeStoreError> {
    match tag {
        1 => Ok(KeyTransitionOperation::Add),
        2 => Ok(KeyTransitionOperation::Revoke),
        3 => Ok(KeyTransitionOperation::ActivateConversation),
        4 => Ok(KeyTransitionOperation::Renew),
        5 => Ok(KeyTransitionOperation::CounterRecovery),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn phase_tag(phase: KeyTransitionPhase) -> u8 {
    phase.rank() + 1
}

pub(super) fn phase_from_tag(tag: u8) -> Result<KeyTransitionPhase, RuntimeStoreError> {
    match tag {
        1 => Ok(KeyTransitionPhase::DrainingOld),
        2 => Ok(KeyTransitionPhase::RotatedPreparingUpdates),
        3 => Ok(KeyTransitionPhase::UpdatesFrozen),
        4 => Ok(KeyTransitionPhase::BarriersFrozen),
        5 => Ok(KeyTransitionPhase::BarriersCommitted),
        6 => Ok(KeyTransitionPhase::Complete),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn terminal_tag(terminal: Option<KeyTransitionTerminal>) -> u8 {
    match terminal {
        None => 0,
        Some(KeyTransitionTerminal::Completed) => 1,
        Some(KeyTransitionTerminal::Cancelled) => 2,
    }
}

pub(super) fn terminal_from_tag(
    tag: u8,
) -> Result<Option<KeyTransitionTerminal>, RuntimeStoreError> {
    match tag {
        0 => Ok(None),
        1 => Ok(Some(KeyTransitionTerminal::Completed)),
        2 => Ok(Some(KeyTransitionTerminal::Cancelled)),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn lifecycle_tag(lifecycle: KeyUpdateLifecycle) -> u8 {
    match lifecycle {
        KeyUpdateLifecycle::Frozen => 1,
        KeyUpdateLifecycle::Acked => 2,
        KeyUpdateLifecycle::Cancelled => 3,
    }
}

pub(super) fn lifecycle_from_tag(tag: u8) -> Result<KeyUpdateLifecycle, RuntimeStoreError> {
    match tag {
        1 => Ok(KeyUpdateLifecycle::Frozen),
        2 => Ok(KeyUpdateLifecycle::Acked),
        3 => Ok(KeyUpdateLifecycle::Cancelled),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_with_scope(scope: KeyTransitionStreamScope) -> KeyUpdateRecord {
        KeyUpdateRecord {
            operation_id: [0x11; 16],
            recipient: KeyTransitionRecipient {
                device_route: [0x12; 16],
                grant_serial: 3,
            },
            key_revision: 4,
            lifecycle: KeyUpdateLifecycle::Acked,
            canonical_update_set: b"canonical-key-update".to_vec(),
            canonical_ack: Some(b"canonical-key-ack".to_vec()),
            snapshot_flushes: Vec::new(),
            stream_applied_acks: vec![StreamAppliedAckRecord {
                scope,
                stream_route: [0x13; 16],
                stream_generation: [0x14; 16],
                applied_stream_seq: 5,
                inner_cursor: Some(6),
                key_revision: 4,
                key_epoch: 7,
                epoch_barrier_sha256: [0x15; 32],
                canonical_ack: b"canonical-stream-ack".to_vec(),
                acknowledged_at_ms: 9,
            }],
            created_at_ms: 8,
            state_changed_at_ms: 9,
        }
    }

    #[test]
    fn stream_applied_scope_is_canonical_in_codec_and_ack_set_hash() {
        let catalog = update_with_scope(KeyTransitionStreamScope::Catalog);
        let conversation = update_with_scope(KeyTransitionStreamScope::Conversation([0x16; 16]));
        let catalog_bytes = encode_update(&catalog).expect("encode catalog StreamAppliedAck");
        let conversation_bytes =
            encode_update(&conversation).expect("encode conversation StreamAppliedAck");
        assert_ne!(catalog_bytes.as_slice(), conversation_bytes.as_slice());
        assert_eq!(
            decode_update(catalog_bytes.as_slice()).expect("decode catalog StreamAppliedAck"),
            catalog
        );
        assert_eq!(
            decode_update(conversation_bytes.as_slice())
                .expect("decode conversation StreamAppliedAck"),
            conversation
        );
        assert_ne!(
            super::super::storage::projected_applied_ack_set_hash(&catalog)
                .expect("hash catalog ACK set"),
            super::super::storage::projected_applied_ack_set_hash(&conversation)
                .expect("hash conversation ACK set")
        );
        assert!(
            encode_update(&update_with_scope(KeyTransitionStreamScope::Conversation(
                [0; 16]
            )))
            .is_err()
        );
    }

    #[test]
    fn adku_v1_remains_canonical_and_v2_roundtrips_snapshot_flush_marker() {
        let legacy = update_with_scope(KeyTransitionStreamScope::Catalog);
        let legacy_bytes = encode_update_version(&legacy, LEGACY_UPDATE_CODEC_VERSION)
            .expect("encode canonical ADKU v1");
        assert_eq!(legacy_bytes[4], LEGACY_UPDATE_CODEC_VERSION);
        assert_eq!(
            decode_update(legacy_bytes.as_slice()).expect("decode canonical ADKU v1"),
            legacy
        );

        let mut current = legacy;
        current
            .snapshot_flushes
            .push(TransitionSnapshotFlushRecord {
                scope: KeyTransitionStreamScope::Catalog,
                publication_stream_id: [0x17; 16],
                stream_route: [0x13; 16],
                generation: [0x14; 16],
                relay_committed_outer: Some(4),
                relay_committed_inner: Some(6),
                barrier_sequence: 5,
                key_directory_revision: 4,
                key_epoch: 7,
                epoch_barrier_sha256: [0x15; 32],
                authorization_hash: [0x18; 32],
                sync_complete_sha256: [0x19; 32],
                flushed_at_ms: 9,
            });
        assert!(
            encode_update_version(&current, LEGACY_UPDATE_CODEC_VERSION).is_err(),
            "ADKU v1 cannot silently drop a v2 flush marker"
        );
        let current_bytes = encode_update(&current).expect("encode canonical ADKU v2");
        assert_eq!(current_bytes[4], UPDATE_CODEC_VERSION);
        assert_eq!(
            decode_update(current_bytes.as_slice()).expect("decode canonical ADKU v2"),
            current
        );
    }

    #[test]
    fn adkt_v1_decodes_without_replay_retirement_and_keeps_counter_gc_fail_closed() {
        let recipient = KeyTransitionRecipient {
            device_route: [0x41; 16],
            grant_serial: 1,
        };
        let record = KeyTransitionRecord {
            operation_id: [0x31; 16],
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(recipient),
            from_revision: 0,
            to_revision: 1,
            phase: KeyTransitionPhase::DrainingOld,
            terminal: None,
            recipients: vec![recipient],
            replay_retirement: None,
            counter_retirement: CounterRetirementLifecycle::Pending,
            cuts: Vec::new(),
            update_count: 0,
            created_at_ms: 10,
            state_changed_at_ms: 10,
            terminal_at_ms: None,
            retain_until_ms: None,
        };
        let legacy = encode_transition_version(&record, LEGACY_TRANSITION_CODEC_VERSION)
            .expect("encode canonical ADKT v1 fixture");
        assert_eq!(decode_transition(&legacy).expect("decode ADKT v1"), record);
        assert_ne!(
            encode_transition(&record)
                .expect("encode ADKT v2")
                .as_slice(),
            legacy.as_slice(),
        );
    }

    #[test]
    fn adkt_v2_roundtrips_first_member_authenticated_inner_cut() {
        let recipient = KeyTransitionRecipient {
            device_route: [0x51; 16],
            grant_serial: 1,
        };
        let record = KeyTransitionRecord {
            operation_id: [0x52; 16],
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(recipient),
            from_revision: 0,
            to_revision: 1,
            phase: KeyTransitionPhase::BarriersFrozen,
            terminal: None,
            recipients: vec![recipient],
            replay_retirement: None,
            counter_retirement: CounterRetirementLifecycle::Pending,
            cuts: vec![KeyTransitionStreamCut {
                scope: KeyTransitionStreamScope::Catalog,
                publication_stream_id: [0x53; 16],
                stream_route: [0x54; 16],
                generation: [0x55; 16],
                relay_committed_outer: None,
                relay_committed_inner: Some(7),
                barrier_sequence: 0,
                old_epoch: 0,
                new_epoch: 1,
                epoch_barrier_sha256: [0x56; 32],
            }],
            update_count: 1,
            created_at_ms: 10,
            state_changed_at_ms: 11,
            terminal_at_ms: None,
            retain_until_ms: None,
        };

        let encoded = encode_transition(&record).expect("encode ADKT v2 genesis cut");
        assert!(
            encoded
                .windows(9)
                .any(|window| window == [2, 0, 0, 0, 0, 0, 0, 0, 7]),
            "ADKT v2 keeps the inner-only cursor tag byte-stable"
        );
        assert_eq!(
            decode_transition(encoded.as_slice()).expect("decode ADKT v2 genesis cut"),
            record
        );
        assert!(
            encode_transition_version(&record, LEGACY_TRANSITION_CODEC_VERSION).is_err(),
            "ADKT v1 grammar remains closed to the new inner-only cut tag"
        );
    }

    #[test]
    fn adkt_v2_roundtrips_control_only_outer_cut_and_rejects_tag_tamper() {
        let recipient = KeyTransitionRecipient {
            device_route: [0x61; 16],
            grant_serial: 2,
        };
        let record = KeyTransitionRecord {
            operation_id: [0x62; 16],
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(recipient),
            from_revision: 1,
            to_revision: 2,
            phase: KeyTransitionPhase::BarriersFrozen,
            terminal: None,
            recipients: vec![recipient],
            replay_retirement: None,
            counter_retirement: CounterRetirementLifecycle::Pending,
            cuts: vec![KeyTransitionStreamCut {
                scope: KeyTransitionStreamScope::Catalog,
                publication_stream_id: [0x63; 16],
                stream_route: [0x64; 16],
                generation: [0x65; 16],
                relay_committed_outer: Some(7),
                relay_committed_inner: None,
                barrier_sequence: 8,
                old_epoch: 1,
                new_epoch: 2,
                epoch_barrier_sha256: [0x66; 32],
            }],
            update_count: 1,
            created_at_ms: 10,
            state_changed_at_ms: 11,
            terminal_at_ms: None,
            retain_until_ms: None,
        };

        let encoded = encode_transition(&record).expect("encode ADKT v2 outer-only cut");
        let marker = [3, 0, 0, 0, 0, 0, 0, 0, 7];
        let marker_offset = encoded
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("ADKT v2 outer-only cursor tag");
        assert_eq!(
            decode_transition(encoded.as_slice()).expect("decode ADKT v2 outer-only cut"),
            record
        );
        assert!(
            encode_transition_version(&record, LEGACY_TRANSITION_CODEC_VERSION).is_err(),
            "ADKT v1 grammar remains closed to the new outer-only cut tag"
        );

        let mut tampered = encoded.to_vec();
        tampered[marker_offset] = 4;
        assert!(matches!(
            decode_transition(&tampered),
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));
    }
}
