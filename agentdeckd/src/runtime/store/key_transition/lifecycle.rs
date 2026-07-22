use std::collections::BTreeSet;

use agentdeck_protocol::relay_v2::{DeviceRouteId, GrantSerial, MachineRouteId, TrustEpoch};
use rusqlite::{Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::remote::counter::CounterScope;
use crate::runtime::model::{
    MachineEnrollmentState, MachineIdentityBinding, MachineIdentityLifecycle,
    RuntimeCommitOperation, RuntimeStoreOperation,
};

use super::super::sqlite::RuntimeLedger;
use super::*;

pub(crate) fn canonical_update_hash(bytes: &[u8]) -> Result<[u8; 32], RuntimeStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_KEY_UPDATE_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(Sha256::digest(bytes).into())
}

pub(crate) fn begin_key_transition(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: BeginKeyTransition,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    validate_begin(&input)?;
    let projected = KeyTransitionRecord::from(input.clone());
    admit_transition_write(state, config, encoded_transition_len(&projected)?)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let mut next = ledger.clone();
    let record = stage_key_transition_in_transaction(
        &transaction,
        &key_bundle,
        database_id,
        &mut next,
        input,
    )?;
    if next == ledger {
        transaction.rollback()?;
        return Ok(record);
    }
    let _ = super::super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::super::sqlite::latch_post_commit_capacity(state, config);
    Ok(record)
}

/// 删除超过 authenticated 30 天 retention 的 transition/update tombstone。
///
/// 候选顺序固定为 `(retain_until_ms, operation_id)`；整个 v12 transition/outbox 集合在
/// 第一笔 DELETE 前完成认证。子 update 必须先于 parent transition 删除，四个 ledger
/// count/bytes 轴与删除在同一 transaction 提交，active count 始终保持不变。
pub(crate) fn gc_expired_key_transitions(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    now_ms: u64,
    limits: KeyTransitionGcLimits,
) -> Result<KeyTransitionGcOutcome, RuntimeStoreError> {
    if limits.max_rows == 0 || limits.max_sealed_bytes == 0 {
        return Err(RuntimeStoreError::InvalidConfig(
            "key-transition GC limits must be nonzero",
        ));
    }
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    validate_v12_integrity(&transaction, &key_bundle, database_id, &ledger)?;
    let candidates = load_expired_transition_ids(&transaction, now_ms)?;
    let mut outcome = KeyTransitionGcOutcome::default();
    let mut next = ledger.clone();
    let mut rows_deleted = 0_u64;
    let mut sealed_bytes_deleted = 0_u64;

    for operation_id in candidates {
        let transition = load_transition(&transaction, &key_bundle, database_id, operation_id)?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if transition.record.phase != KeyTransitionPhase::Complete
            || transition
                .record
                .retain_until_ms
                .is_none_or(|deadline| deadline > now_ms)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if matches!(
            transition.record.replay_retirement,
            Some(ReplayRetirement {
                lifecycle: ReplayRetirementLifecycle::Pending,
                ..
            })
        ) {
            outcome.replay_retirement_blocked = checked_add(outcome.replay_retirement_blocked, 1)?;
            continue;
        }
        if transition.record.counter_retirement == CounterRetirementLifecycle::Pending {
            if transition.record.operation == KeyTransitionOperation::CounterRecovery {
                outcome.counter_recovery_blocked =
                    checked_add(outcome.counter_recovery_blocked, 1)?;
            } else {
                outcome.counter_retirement_blocked =
                    checked_add(outcome.counter_retirement_blocked, 1)?;
            }
            continue;
        }
        let updates = load_updates_for_operation(
            &transaction,
            &key_bundle,
            database_id,
            transition.record.operation_id,
        )?;
        let candidate_rows = 1_u64
            .checked_add(
                u64::try_from(updates.len())
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let update_bytes = updates.iter().try_fold(0_u64, |total, update| {
            checked_add(total, update.sealed_bytes)
        })?;
        let candidate_bytes = checked_add(transition.sealed_bytes, update_bytes)?;
        if rows_deleted
            .checked_add(candidate_rows)
            .is_none_or(|rows| rows > limits.max_rows)
            || sealed_bytes_deleted
                .checked_add(candidate_bytes)
                .is_none_or(|bytes| bytes > limits.max_sealed_bytes)
        {
            outcome.limit_reached = true;
            break;
        }

        for update in &updates {
            delete_authenticated_update(&transaction, update)?;
        }
        delete_authenticated_transition(&transaction, &transition)?;

        outcome.transitions_deleted = checked_add(outcome.transitions_deleted, 1)?;
        outcome.updates_deleted = checked_add(
            outcome.updates_deleted,
            u64::try_from(updates.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        outcome.transition_sealed_bytes_deleted = checked_add(
            outcome.transition_sealed_bytes_deleted,
            transition.sealed_bytes,
        )?;
        outcome.update_sealed_bytes_deleted =
            checked_add(outcome.update_sealed_bytes_deleted, update_bytes)?;
        rows_deleted = checked_add(rows_deleted, candidate_rows)?;
        sealed_bytes_deleted = checked_add(sealed_bytes_deleted, candidate_bytes)?;
    }

    if outcome.transitions_deleted == 0 {
        transaction.rollback()?;
        return Ok(outcome);
    }
    next.remote_key_transition_count = next
        .remote_key_transition_count
        .checked_sub(outcome.transitions_deleted)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_key_transition_sealed_bytes = next
        .remote_key_transition_sealed_bytes
        .checked_sub(outcome.transition_sealed_bytes_deleted)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_key_update_outbox_count = next
        .remote_key_update_outbox_count
        .checked_sub(outcome.updates_deleted)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_key_update_outbox_sealed_bytes = next
        .remote_key_update_outbox_sealed_bytes
        .checked_sub(outcome.update_sealed_bytes_deleted)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if next.remote_key_transition_active_count != ledger.remote_key_transition_active_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_ledger_caps(&next)?;
    let _ = super::super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::GcKeyTransitionsBeforeCommit)?;
    super::super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::GcKeyTransitions,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::GcKeyTransitionsAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::GcKeyTransitions,
        })?;
    Ok(outcome)
}

impl From<BeginKeyTransition> for KeyTransitionRecord {
    fn from(input: BeginKeyTransition) -> Self {
        Self {
            operation_id: input.operation_id,
            operation: input.operation,
            target: input.target,
            from_revision: input.from_revision,
            to_revision: input.to_revision,
            phase: KeyTransitionPhase::DrainingOld,
            terminal: None,
            recipients: input.recipients,
            replay_retirement: input.replay_retirement,
            counter_retirement: CounterRetirementLifecycle::Pending,
            cuts: Vec::new(),
            update_count: 0,
            created_at_ms: input.created_at_ms,
            state_changed_at_ms: input.created_at_ms,
            terminal_at_ms: None,
            retain_until_ms: None,
        }
    }
}

/// 验证 authenticated ledger 与物理 active row 同时为空。
///
/// membership/conversation transaction 在产生任何 DML 前调用本 gate；每次 global
/// revision advance 都必须与唯一 active transition 同事务建立。
pub(crate) fn ensure_key_transition_slot_available(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    validate_v12_integrity(transaction, key_bundle, database_id, ledger)?;
    if ledger.remote_key_transition_active_count != 0
        || load_active_transition(transaction, key_bundle, database_id)?.is_some()
        || load_pending_replay_retirement(transaction, key_bundle, database_id)?.is_some()
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(())
}

fn load_pending_replay_retirement(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<AuthenticatedTransition>, RuntimeStoreError> {
    let mut statement = connection
        .prepare("SELECT operation_id FROM remote_key_transitions ORDER BY operation_id")?;
    let raw_ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if raw_ids.len() > usize::try_from(MAX_KEY_TRANSITIONS).unwrap_or(usize::MAX) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut pending = None;
    for raw_id in raw_ids {
        let operation_id = fixed(&raw_id)?;
        let authenticated = load_transition(connection, key_bundle, database_id, operation_id)?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if matches!(
            authenticated.record.replay_retirement,
            Some(ReplayRetirement {
                lifecycle: ReplayRetirementLifecycle::Pending,
                ..
            })
        ) && authenticated.record.phase == KeyTransitionPhase::Complete
        {
            if pending.is_some() {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            pending = Some(authenticated);
        }
    }
    Ok(pending)
}

/// 在同一 Runtime DB transaction 内完成 replay row 退役与 transition
/// lifecycle 收口。Completed 的 scope 从未观测到或已退役均是幂等成功；
/// Cancelled 证明 membership 未生效，只单调标记 Applied，绝不退役仍可能 active 的
/// replay scope。任一写入失败则整个 transaction 回滚，不会留下半状态。
pub(crate) fn apply_pending_replay_retirement(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
) -> Result<ReplayRetirementApplyOutcome, RuntimeStoreError> {
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
    validate_v12_integrity(&transaction, &key_bundle, database_id, &ledger)?;
    let Some(authenticated) =
        load_pending_replay_retirement(&transaction, &key_bundle, database_id)?
    else {
        transaction.rollback()?;
        return Ok(ReplayRetirementApplyOutcome::NoPending);
    };
    if authenticated.record.phase != KeyTransitionPhase::Complete {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let retired_at_ms = authenticated
        .record
        .terminal_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let retirement = authenticated
        .record
        .replay_retirement
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if retirement.lifecycle != ReplayRetirementLifecycle::Pending {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut next = ledger.clone();
    let replay_scope_observed = match authenticated.record.terminal {
        Some(KeyTransitionTerminal::Completed) => {
            super::super::remote_replay::retire_scope_if_present_in_transaction(
                &transaction,
                &key_bundle,
                database_id,
                &mut next,
                retirement.scope,
                retired_at_ms,
            )?
        }
        Some(KeyTransitionTerminal::Cancelled) => false,
        None => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    let mut changed = authenticated.record.clone();
    changed.replay_retirement = Some(ReplayRetirement {
        lifecycle: ReplayRetirementLifecycle::Applied,
        ..retirement
    });
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
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ApplyReplayRetirementBeforeCommit)?;
    super::super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::ApplyReplayRetirement,
    )?;
    super::super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ApplyReplayRetirementAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ApplyReplayRetirement,
        })?;
    Ok(ReplayRetirementApplyOutcome::Applied {
        transition: Box::new(changed),
        replay_scope_observed,
    })
}

/// 返回一笔可执行的 guard-first counter retirement exact plan，不写 DB。
///
/// 只有 authenticated `Complete` transition、至少 25 小时 retention、已收口的
/// replay retirement、且所有派生 scope 均不在当前 authenticated sender inventory
/// 中时才返回。`Retired/RecoveryStaged` counter lineage 只会保持 blocked，不会给
/// caller Keychain 删除 authority。
pub(crate) fn load_pending_counter_retirement_plan(
    state: &RuntimeSqlite,
    machine_trust_domain: [u8; 32],
    now_ms: u64,
) -> Result<Option<CounterRetirementPlan>, RuntimeStoreError> {
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Deferred)?;
    let ledger = super::super::sqlite::load_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
    )?;
    validate_counter_retirement_substrate(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
    )?;
    let active_tokens = active_sender_scope_tokens(
        super::super::remote_counter::load_active_sender_counter_bindings_against_ledger(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &ledger,
            machine_trust_domain,
        )?,
        machine_trust_domain,
    )?;
    let transitions =
        load_counter_retirement_transitions(&transaction, &state.key_bundle, state.database_id)?;
    for authenticated in transitions {
        if !counter_retention_elapsed(&authenticated.record, now_ms)? {
            continue;
        }
        let Some(expectations) = derive_counter_collection_expectations(
            &transaction,
            &state.key_bundle,
            state.database_id,
            machine_trust_domain,
            &authenticated.record,
        )?
        else {
            continue;
        };
        if !super::super::remote_counter::collection_expectations_are_ready(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &expectations,
        )? {
            continue;
        }
        ensure_counter_scopes_inactive(&expectations, &active_tokens)?;
        let plan = plan_from_expectations(authenticated.record.operation_id, &expectations);
        transaction.commit()?;
        return Ok(Some(plan));
    }
    transaction.commit()?;
    Ok(None)
}

/// caller 已按 exact plan 对每个 token 完成 Keychain existing-only delete + absent
/// readback 后的唯一 DB mutation。函数在 `BEGIN IMMEDIATE` 内重新认证 transition、
/// active sender inventory、counter row 与 manifest；随后同一事务删除 exact counter/
/// manifest rows、精确扣 ledger，并把 `counter_retirement Pending→Applied`。
pub(crate) fn apply_counter_retirement_after_guard_readback(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    machine_trust_domain: [u8; 32],
    plan: &CounterRetirementPlan,
    now_ms: u64,
) -> Result<CounterRetirementApplyOutcome, RuntimeStoreError> {
    validate_nonzero(plan.operation_id)?;
    validate_scope_token_order(&plan.scope_tokens)?;
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
    validate_counter_retirement_substrate(&transaction, &key_bundle, database_id, &ledger)?;
    let authenticated = load_transition(&transaction, &key_bundle, database_id, plan.operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if authenticated.record.phase != KeyTransitionPhase::Complete {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if authenticated.record.counter_retirement == CounterRetirementLifecycle::Applied {
        transaction.rollback()?;
        return Ok(CounterRetirementApplyOutcome::AlreadyCollected {
            operation_id: plan.operation_id,
        });
    }
    if !counter_retention_elapsed(&authenticated.record, now_ms)? {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let expectations = derive_counter_collection_expectations(
        &transaction,
        &key_bundle,
        database_id,
        machine_trust_domain,
        &authenticated.record,
    )?
    .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if plan_from_expectations(plan.operation_id, &expectations) != *plan
        || !super::super::remote_counter::collection_expectations_are_ready(
            &transaction,
            &key_bundle,
            database_id,
            &expectations,
        )?
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let active_tokens = active_sender_scope_tokens(
        super::super::remote_counter::load_active_sender_counter_bindings_against_ledger(
            &transaction,
            &key_bundle,
            database_id,
            &ledger,
            machine_trust_domain,
        )?,
        machine_trust_domain,
    )?;
    ensure_counter_scopes_inactive(&expectations, &active_tokens)?;

    let mut next = ledger.clone();
    let counter = super::super::remote_counter::collect_after_guard_readback_in_transaction(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &mut next,
        &expectations,
    )?;
    let manifest_rows_deleted =
        super::super::remote_counter_guard_manifest::remove_scopes_after_guard_readback(
            &transaction,
            &key_bundle,
            database_id,
            &ledger,
            &mut next,
            &plan.scope_tokens,
        )?;
    let mut changed = authenticated.record.clone();
    changed.counter_retirement = CounterRetirementLifecycle::Applied;
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
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ApplyCounterRetirementBeforeCommit)?;
    super::super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::ApplyCounterRetirement,
    )?;
    super::super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ApplyCounterRetirementAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ApplyCounterRetirement,
        })?;
    Ok(CounterRetirementApplyOutcome::Applied {
        operation_id: plan.operation_id,
        counter_rows_deleted: counter.rows_deleted,
        manifest_rows_deleted,
    })
}

fn validate_counter_retirement_substrate(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    validate_v12_integrity(connection, key_bundle, database_id, ledger)?;
    super::super::remote_counter::validate_full_integrity(
        connection,
        key_bundle,
        database_id,
        ledger,
    )?;
    super::super::remote_counter_guard_manifest::validate_v12_integrity(
        connection,
        key_bundle,
        database_id,
        ledger,
    )
}

fn load_counter_retirement_transitions(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedTransition>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT operation_id FROM remote_key_transitions
         WHERE phase = 'Complete' ORDER BY terminal_at_ms, operation_id",
    )?;
    let ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if ids.len() > usize::try_from(MAX_KEY_TRANSITIONS).unwrap_or(usize::MAX) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut transitions = Vec::new();
    transitions
        .try_reserve_exact(ids.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for id in ids {
        let operation_id = fixed(&id)?;
        let authenticated = load_transition(connection, key_bundle, database_id, operation_id)?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if authenticated.record.phase != KeyTransitionPhase::Complete {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if authenticated.record.counter_retirement == CounterRetirementLifecycle::Pending {
            transitions.push(authenticated);
        }
    }
    Ok(transitions)
}

fn counter_retention_elapsed(
    record: &KeyTransitionRecord,
    now_ms: u64,
) -> Result<bool, RuntimeStoreError> {
    if record.phase != KeyTransitionPhase::Complete || record.terminal.is_none() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let terminal_at_ms = record
        .terminal_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let eligible_at_ms = terminal_at_ms
        .checked_add(COUNTER_RETIREMENT_RETENTION_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    Ok(now_ms >= eligible_at_ms)
}

fn derive_counter_collection_expectations(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    machine_trust_domain: [u8; 32],
    record: &KeyTransitionRecord,
) -> Result<
    Option<Vec<super::super::remote_counter::CounterCollectionExpectation>>,
    RuntimeStoreError,
> {
    use super::super::remote_counter::CounterCollectionExpectation;

    if record.terminal == Some(KeyTransitionTerminal::Cancelled) {
        return Ok(Some(Vec::new()));
    }
    if record.terminal != Some(KeyTransitionTerminal::Completed) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if matches!(
        record.replay_retirement,
        Some(ReplayRetirement {
            lifecycle: ReplayRetirementLifecycle::Pending,
            ..
        })
    ) {
        return Ok(None);
    }
    let mut expectations = Vec::new();
    if record.operation == KeyTransitionOperation::CounterRecovery {
        let Some(recovered) =
            super::super::remote_counter::counter_recovery_collection_expectation(
                connection,
                key_bundle,
                database_id,
                record.operation_id,
            )?
        else {
            return Ok(None);
        };
        expectations.push(recovered);
    } else {
        expectations
            .try_reserve_exact(record.cuts.len() + usize::from(record.replay_retirement.is_some()))
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        for cut in &record.cuts {
            // `old_epoch=0` 只表示首个 remote member 前不存在 shared sender
            // scope；不得为 sentinel 派生或回收一个伪造的旧 CounterScope。
            if cut.old_epoch == 0 {
                continue;
            }
            let key_id = KeyId {
                purpose: match cut.scope {
                    KeyTransitionStreamScope::Catalog => KeyPurpose::Catalog,
                    KeyTransitionStreamScope::Conversation(_) => KeyPurpose::ConversationDek,
                },
                epoch: cut.old_epoch,
            };
            let scope_token =
                CounterScope::publication(machine_trust_domain, key_id, cut.publication_stream_id)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                    .token();
            expectations.push(CounterCollectionExpectation::Ordinary {
                scope_token,
                key_id,
            });
        }
        if let Some(retirement) = record.replay_retirement {
            let axes = super::super::remote_replay::device_command_scope_axes(&retirement.scope)?;
            let key_id = KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: retirement.old_reply_key_epoch,
            };
            let scope_token = CounterScope::directed_reply_for_trust_epoch(
                machine_trust_domain,
                MachineRouteId::from_bytes(axes.machine_route),
                TrustEpoch::new(axes.trust_epoch),
                DeviceRouteId::from_bytes(axes.device_route),
                GrantSerial::new(axes.grant_serial),
                key_id.epoch,
            )
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            .token();
            expectations.push(CounterCollectionExpectation::Ordinary {
                scope_token,
                key_id,
            });
        }
    }
    expectations.sort_by_key(|expectation| expectation.scope_token());
    if expectations
        .windows(2)
        .any(|pair| pair[0].scope_token() == pair[1].scope_token())
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(expectations))
}

fn active_sender_scope_tokens(
    bindings: Vec<super::super::remote_counter::ActiveSenderCounterBinding>,
    machine_trust_domain: [u8; 32],
) -> Result<BTreeSet<[u8; 32]>, RuntimeStoreError> {
    let mut tokens = BTreeSet::new();
    for binding in bindings {
        let token = match binding {
            super::super::remote_counter::ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id,
                key_id,
            } => CounterScope::publication(machine_trust_domain, key_id, publication_stream_id),
            super::super::remote_counter::ActiveSenderCounterBinding::DirectedReply {
                authorization,
            } => {
                if authorization.machine_trust_domain() != machine_trust_domain {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                CounterScope::directed_reply_for_trust_epoch(
                    machine_trust_domain,
                    authorization.machine_route(),
                    authorization.trust_epoch(),
                    authorization.device_route(),
                    authorization.grant_serial(),
                    authorization.reply_key_epoch(),
                )
            }
        }
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        .token();
        if !tokens.insert(token) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Ok(tokens)
}

fn ensure_counter_scopes_inactive(
    expectations: &[super::super::remote_counter::CounterCollectionExpectation],
    active_tokens: &BTreeSet<[u8; 32]>,
) -> Result<(), RuntimeStoreError> {
    if expectations
        .iter()
        .any(|expectation| active_tokens.contains(&expectation.scope_token()))
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(())
}

fn plan_from_expectations(
    operation_id: [u8; 16],
    expectations: &[super::super::remote_counter::CounterCollectionExpectation],
) -> CounterRetirementPlan {
    CounterRetirementPlan {
        operation_id,
        scope_tokens: expectations
            .iter()
            .map(|expectation| expectation.scope_token())
            .collect(),
    }
}

fn validate_scope_token_order(scope_tokens: &[[u8; 32]]) -> Result<(), RuntimeStoreError> {
    if scope_tokens.iter().any(|token| token == &[0; 32])
        || scope_tokens.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

/// 在调用方现有的 `BEGIN IMMEDIATE` 内原子建立 `DrainingOld` transition。
///
/// 本 helper 不 admission、不取 clock、不 commit，也不单独更新 authenticated ledger；
/// 外层 membership/conversation transaction 必须传入由同一 authenticated old/new global
/// revision 构造的 input，并只在所有行都 staged 后一次写回 `next_ledger`。
pub(crate) fn stage_key_transition_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    next_ledger: &mut RuntimeLedger,
    input: BeginKeyTransition,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    validate_begin(&input)?;
    let record = KeyTransitionRecord::from(input);
    if let Some(existing) =
        load_transition(transaction, key_bundle, database_id, record.operation_id)?
    {
        if same_begin(&existing.record, &record) {
            return Ok(existing.record);
        }
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    ensure_key_transition_slot_available(transaction, key_bundle, database_id, next_ledger)?;
    insert_transition(transaction, key_bundle, database_id, &record, next_ledger)?;
    Ok(record)
}

#[cfg(test)]
pub(crate) fn mark_rotated_preparing_updates(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    changed_at_ms: u64,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    advance_exact_phase(
        state,
        config,
        operation_id,
        KeyTransitionPhase::DrainingOld,
        KeyTransitionPhase::RotatedPreparingUpdates,
        changed_at_ms,
    )
}

enum KeyDirectoryRotationFinalizeState {
    Pending {
        transition: AuthenticatedTransition,
        identity_binding: Box<MachineIdentityBinding>,
        machine_route: [u8; 16],
    },
    Completed(KeyTransitionRecord),
}

/// 在 guard CAS 已 durable 推进后，原子完成 Runtime DB 的三个公开轴。
///
/// 只接受唯一 active `DrainingOld(from -> from+1)`，且 authenticated global 已在
/// `to`、Active identity/remote binding 仍精确位于 `from`。同一事务重写 identity、
/// sealed enrollment binding 与 transition phase；已完成的 exact retry 只读返回，
/// 不重新取 clock，也不产生第二笔写入。
pub(crate) fn finalize_key_directory_rotation(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    match classify_key_directory_rotation_finalize(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        operation_id,
    )? {
        KeyDirectoryRotationFinalizeState::Completed(record) => return Ok(record),
        KeyDirectoryRotationFinalizeState::Pending { .. } => {}
    }

    let changed_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
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
    let pending = match classify_key_directory_rotation_finalize(
        &transaction,
        &key_bundle,
        database_id,
        operation_id,
    )? {
        KeyDirectoryRotationFinalizeState::Completed(record) => {
            transaction.rollback()?;
            return Ok(record);
        }
        pending @ KeyDirectoryRotationFinalizeState::Pending { .. } => pending,
    };
    let KeyDirectoryRotationFinalizeState::Pending {
        transition,
        identity_binding,
        machine_route,
    } = pending
    else {
        unreachable!("completed finalize state returned above")
    };
    require_monotonic_time(transition.record.state_changed_at_ms, changed_at_ms)?;
    let ledger = super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let identity =
        super::super::machine_identity::advance_active_key_directory_revision_in_transaction(
            &transaction,
            &key_bundle,
            database_id,
            &identity_binding,
            transition.record.to_revision,
        )?;
    let remote_binding =
        super::super::machine_remote::advance_active_key_directory_revision_in_transaction(
            &transaction,
            &key_bundle,
            database_id,
            machine_route,
            &identity_binding,
            transition.record.to_revision,
        )?;
    if remote_binding != identity.binding {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }

    let mut changed = transition.record.clone();
    changed.phase = KeyTransitionPhase::RotatedPreparingUpdates;
    changed.state_changed_at_ms = changed_at_ms;
    let mut next = ledger.clone();
    replace_transition(
        &transaction,
        &key_bundle,
        database_id,
        &transition,
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
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::FinalizeKeyDirectoryRotationBeforeCommit)?;
    super::super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::FinalizeKeyDirectoryRotation,
    )?;
    super::super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::FinalizeKeyDirectoryRotationAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::FinalizeKeyDirectoryRotation,
        })?;

    match classify_key_directory_rotation_finalize(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        operation_id,
    )? {
        KeyDirectoryRotationFinalizeState::Completed(record) => Ok(record),
        KeyDirectoryRotationFinalizeState::Pending { .. } => {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        }
    }
}

fn classify_key_directory_rotation_finalize(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    operation_id: [u8; 16],
) -> Result<KeyDirectoryRotationFinalizeState, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    let transition = load_active_transition(connection, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if transition.record.operation_id != operation_id
        || transition.record.to_revision
            != transition
                .record
                .from_revision
                .checked_add(1)
                .ok_or(RuntimeStoreError::PublicationMismatch)?
        || transition.record.terminal.is_some()
        || transition.record.update_count != 0
        || !transition.record.cuts.is_empty()
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let global =
        super::super::pairing_grant::load_global_key_state(connection, key_bundle, database_id)?
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if global.revision != transition.record.to_revision {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let identity = super::super::machine_identity::load_machine_identity_state(
        connection,
        key_bundle,
        database_id,
    )?
    .ok_or(RuntimeStoreError::MachineIdentityMissing)?;
    if identity.lifecycle != MachineIdentityLifecycle::Active {
        return Err(RuntimeStoreError::MachineIdentityConflict);
    }
    let remote = super::super::machine_remote::load_machine_enrollment_state(
        connection,
        key_bundle,
        database_id,
    )?
    .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    let MachineEnrollmentState::Active(remote) = remote else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    if remote.record.machine_route == [0; 16]
        || remote.record.root_key_id != identity.binding.root_key_id
        || remote.record.root_fingerprint != identity.binding.root_fingerprint
        || remote.record.trust_epoch != identity.binding.trust_epoch
        || remote.binding != identity.binding
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }

    match (
        transition.record.phase,
        identity.binding.key_directory_revision,
    ) {
        (KeyTransitionPhase::DrainingOld, revision)
            if revision == transition.record.from_revision =>
        {
            Ok(KeyDirectoryRotationFinalizeState::Pending {
                transition,
                identity_binding: Box::new(identity.binding),
                machine_route: remote.record.machine_route,
            })
        }
        (KeyTransitionPhase::RotatedPreparingUpdates, revision)
            if revision == transition.record.to_revision =>
        {
            Ok(KeyDirectoryRotationFinalizeState::Completed(
                transition.record,
            ))
        }
        _ => Err(RuntimeStoreError::InvalidStateTransition),
    }
}
