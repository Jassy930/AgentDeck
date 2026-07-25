use super::*;

pub(crate) fn complete_key_transition(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    completed_at_ms: u64,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    finish_transition(
        state,
        config,
        operation_id,
        completed_at_ms,
        KeyTransitionTerminal::Completed,
    )
}

/// 在 authenticated transition 已满足全部 device ACK 条件时释放唯一 active slot。
///
/// 调用方可以在每个 ACK 或 business-ready readback 后无条件重试：尚未到
/// `BarriersCommitted`、仍缺 KeyUpdateAck/StreamAppliedAck 时只返回 `Pending`；exact
/// completed tombstone 返回原记录，不使用新的时钟覆盖首次 terminal 时间。
pub(crate) fn try_complete_key_transition(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    completed_at_ms: u64,
) -> Result<KeyTransitionCompletion, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    let authenticated = load_transition(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        operation_id,
    )?
    .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if authenticated.record.phase == KeyTransitionPhase::Complete {
        return if authenticated.record.terminal == Some(KeyTransitionTerminal::Completed) {
            Ok(KeyTransitionCompletion::Completed(Box::new(
                authenticated.record,
            )))
        } else {
            Err(RuntimeStoreError::InvalidStateTransition)
        };
    }
    if authenticated.record.terminal.is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if authenticated.record.phase != KeyTransitionPhase::BarriersCommitted {
        return Ok(KeyTransitionCompletion::Pending);
    }
    let updates = load_updates_for_operation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        operation_id,
    )?;
    if updates.len() != authenticated.record.recipients.len()
        || authenticated.record.update_count != updates.len() as u64
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if updates.iter().any(|update| {
        update.record.lifecycle != KeyUpdateLifecycle::Acked
            || !snapshot_permit::has_all_required_snapshot_flushes(
                &authenticated.record,
                &update.record,
            )
            || !has_all_stream_applied_acks(&authenticated.record, &update.record)
    }) {
        return Ok(KeyTransitionCompletion::Pending);
    }
    complete_key_transition(state, config, operation_id, completed_at_ms)
        .map(Box::new)
        .map(KeyTransitionCompletion::Completed)
}

pub(crate) fn cancel_key_transition(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    cancelled_at_ms: u64,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    finish_transition(
        state,
        config,
        operation_id,
        cancelled_at_ms,
        KeyTransitionTerminal::Cancelled,
    )
}

fn finish_transition(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    terminal_at_ms: u64,
    terminal: KeyTransitionTerminal,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    if terminal_at_ms > MAX_TERMINAL_BASE_MS {
        return Err(RuntimeStoreError::TimeOutOfRange);
    }
    super::super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated = load_transition(&transaction, &key_bundle, database_id, operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if authenticated.record.phase == KeyTransitionPhase::Complete {
        if authenticated.record.terminal == Some(terminal)
            && authenticated.record.terminal_at_ms == Some(terminal_at_ms)
        {
            transaction.rollback()?;
            return Ok(authenticated.record);
        }
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    require_monotonic_time(authenticated.record.state_changed_at_ms, terminal_at_ms)?;
    let updates = load_updates_for_operation(&transaction, &key_bundle, database_id, operation_id)?;
    match terminal {
        KeyTransitionTerminal::Completed => {
            if authenticated.record.phase != KeyTransitionPhase::BarriersCommitted
                || updates.iter().any(|update| {
                    update.record.lifecycle != KeyUpdateLifecycle::Acked
                        || !snapshot_permit::has_all_required_snapshot_flushes(
                            &authenticated.record,
                            &update.record,
                        )
                        || !has_all_stream_applied_acks(&authenticated.record, &update.record)
                })
                || updates.len() != authenticated.record.recipients.len()
            {
                return Err(RuntimeStoreError::InvalidStateTransition);
            }
            for update in &updates {
                // terminal 必须晚于最后一条 durable KeyUpdate/StreamApplied ACK；墙钟
                // 回拨只能 typed fail-close，不能制造早于因果前件的完成时间。
                require_monotonic_time(update.record.state_changed_at_ms, terminal_at_ms)?;
            }
        }
        KeyTransitionTerminal::Cancelled => {
            // 取消只属于尚未轮换 key-directory 的 staged transition。轮换一旦完成，
            // 旧 revision 已不可恢复；任何后续 phase 都必须保留 active fence，由
            // recovery/forward completion 收口，不能靠取消释放业务入口。
            if authenticated.record.phase != KeyTransitionPhase::DrainingOld
                || authenticated.record.bootstrap_install_proof.is_some()
                || !updates.is_empty()
            {
                return Err(RuntimeStoreError::InvalidStateTransition);
            }
        }
    }
    let mut next = ledger.clone();
    if terminal == KeyTransitionTerminal::Cancelled {
        for update in updates {
            require_monotonic_time(update.record.state_changed_at_ms, terminal_at_ms)?;
            let mut changed = update.record.clone();
            changed.lifecycle = KeyUpdateLifecycle::Cancelled;
            changed.state_changed_at_ms = terminal_at_ms;
            replace_update(
                &transaction,
                &key_bundle,
                database_id,
                &update,
                &changed,
                &mut next,
            )?;
        }
    }
    let retain_until_ms = terminal_at_ms
        .checked_add(KEY_TRANSITION_TOMBSTONE_RETENTION_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let mut changed = authenticated.record.clone();
    changed.phase = KeyTransitionPhase::Complete;
    changed.terminal = Some(terminal);
    changed.state_changed_at_ms = terminal_at_ms;
    changed.terminal_at_ms = Some(terminal_at_ms);
    changed.retain_until_ms = Some(retain_until_ms);
    replace_transition(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated,
        &changed,
        &mut next,
    )?;
    let _ = super::super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::super::sqlite::latch_post_commit_capacity(state, config);
    Ok(changed)
}

pub(super) fn has_all_stream_applied_acks(
    transition: &KeyTransitionRecord,
    update: &KeyUpdateRecord,
) -> bool {
    update.stream_applied_acks.len() == transition.cuts.len()
        && transition.cuts.iter().all(|cut| {
            update.stream_applied_acks.iter().any(|ack| {
                ack.stream_route == cut.stream_route
                    && ack.scope == cut.scope
                    && ack.stream_generation == cut.generation
                    && ack.applied_stream_seq == cut.barrier_sequence
                    && ack.inner_cursor == cut.relay_committed_inner
                    && ack.key_revision == transition.to_revision
                    && ack.key_epoch == cut.new_epoch
                    && ack.epoch_barrier_sha256 == cut.epoch_barrier_sha256
            })
        })
}
