//! 新设备 membership transition 的 exact directed snapshot capability。
//!
//! RemoteLink 不能自行构造或缓存该 capability；Store 在同一次 current authorization
//! 复核中签发 frozen cut，Runtime 只消费它生成 snapshot/SyncComplete，真实 writer flush
//! 后再把 capability 一次性换成 authenticated durable marker。

use agentdeck_protocol::runtime::sync::StreamCursor;

use super::*;

/// RemoteLink 只能用 Store-current opaque proof 构造的 transition snapshot 请求。
/// requested cursor 也进入同一次 Store 决策，避免调用方把普通 Backfill/After 游标
/// 偷换成 transition-bound snapshot。
pub(crate) struct TransitionSnapshotRequest {
    authorization: super::super::pairing_authorization::CurrentRemoteAuthorizationProof,
    scope: KeyTransitionStreamScope,
    requested_cursor: StreamCursor,
}

impl TransitionSnapshotRequest {
    pub(crate) fn new(
        authorization: super::super::pairing_authorization::CurrentRemoteAuthorizationProof,
        scope: KeyTransitionStreamScope,
        requested_cursor: StreamCursor,
    ) -> Self {
        Self {
            authorization,
            scope,
            requested_cursor,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransitionSnapshotQuery {
    pub recipient: KeyTransitionRecipient,
    pub key_revision: u64,
    pub authorization_hash: [u8; 32],
    pub scope: KeyTransitionStreamScope,
    pub requested_cursor: StreamCursor,
}

/// Store-issued、不可由 wire 构造的单次 transition snapshot capability。
/// 字段保持私有；Runtime 只能读取 frozen axes，最终消费 capability 写入 flush marker。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransitionSnapshotPermit {
    operation_id: [u8; 16],
    recipient: KeyTransitionRecipient,
    authorization_hash: [u8; 32],
    scope: KeyTransitionStreamScope,
    publication_stream_id: [u8; 16],
    stream_route: [u8; 16],
    generation: [u8; 16],
    relay_committed_outer: Option<u64>,
    relay_committed_inner: Option<u64>,
    barrier_sequence: u64,
    key_directory_revision: u64,
    key_epoch: u64,
    epoch_barrier_sha256: [u8; 32],
}

impl TransitionSnapshotPermit {
    #[cfg(test)]
    pub(crate) fn for_authorization_precedence_test(scope: KeyTransitionStreamScope) -> Self {
        Self {
            operation_id: [0x11; 16],
            recipient: KeyTransitionRecipient {
                device_route: [0x22; 16],
                grant_serial: 1,
            },
            authorization_hash: [0x33; 32],
            scope,
            publication_stream_id: [0x44; 16],
            stream_route: [0x55; 16],
            generation: [0x66; 16],
            relay_committed_outer: None,
            relay_committed_inner: None,
            barrier_sequence: 0,
            key_directory_revision: 1,
            key_epoch: 1,
            epoch_barrier_sha256: [0x77; 32],
        }
    }

    pub(crate) const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    pub(crate) const fn recipient(&self) -> KeyTransitionRecipient {
        self.recipient
    }

    pub(crate) const fn authorization_hash(&self) -> [u8; 32] {
        self.authorization_hash
    }

    pub(crate) const fn scope(&self) -> KeyTransitionStreamScope {
        self.scope
    }

    pub(crate) const fn publication_stream_id(&self) -> [u8; 16] {
        self.publication_stream_id
    }

    pub(crate) const fn stream_route(&self) -> [u8; 16] {
        self.stream_route
    }

    pub(crate) const fn generation(&self) -> [u8; 16] {
        self.generation
    }

    pub(crate) const fn relay_committed_outer(&self) -> Option<u64> {
        self.relay_committed_outer
    }

    pub(crate) const fn relay_committed_inner(&self) -> Option<u64> {
        self.relay_committed_inner
    }

    pub(crate) const fn barrier_sequence(&self) -> u64 {
        self.barrier_sequence
    }

    pub(crate) const fn key_directory_revision(&self) -> u64 {
        self.key_directory_revision
    }

    pub(crate) const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub(crate) const fn epoch_barrier_sha256(&self) -> [u8; 32] {
        self.epoch_barrier_sha256
    }

    pub(crate) fn into_flush(
        self,
        sync_complete_sha256: [u8; 32],
    ) -> Result<TransitionSnapshotFlush, RuntimeStoreError> {
        validate_nonzero(sync_complete_sha256)?;
        Ok(TransitionSnapshotFlush {
            permit: self,
            sync_complete_sha256,
        })
    }
}

/// `SyncComplete` 已穿透 DeviceReplyTx seal 与 Relay Reply writer 后才可消费。
pub(crate) struct TransitionSnapshotFlush {
    permit: TransitionSnapshotPermit,
    sync_complete_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct TransitionSnapshotFlushRecord {
    pub scope: KeyTransitionStreamScope,
    pub publication_stream_id: [u8; 16],
    pub stream_route: [u8; 16],
    pub generation: [u8; 16],
    pub relay_committed_outer: Option<u64>,
    pub relay_committed_inner: Option<u64>,
    pub barrier_sequence: u64,
    pub key_directory_revision: u64,
    pub key_epoch: u64,
    pub epoch_barrier_sha256: [u8; 32],
    pub authorization_hash: [u8; 32],
    pub sync_complete_sha256: [u8; 32],
    pub flushed_at_ms: u64,
}

/// 对 Store-current authorization 做第二次 exact 复核，并从同一 authenticated
/// transition/update/cut 读取 capability 的全部轴。proof 在进入本函数前即使有效，
/// 本次复核失败也不得降级为 query-only admission。
pub(crate) fn resolve_transition_snapshot_permit(
    state: &RuntimeSqlite,
    machine_trust_domain: [u8; 32],
    request: TransitionSnapshotRequest,
) -> Result<TransitionSnapshotPermit, RuntimeStoreError> {
    let current = super::super::pairing_authorization::recheck_active_remote_ingress(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        machine_trust_domain,
        request.authorization.active(),
    )?;
    let active = current.active();
    resolve_bound_transition_snapshot_permit(
        state,
        TransitionSnapshotQuery {
            recipient: KeyTransitionRecipient {
                device_route: *active.device_route().as_bytes(),
                grant_serial: active.grant_serial().value(),
            },
            key_revision: active.key_directory_revision().value(),
            authorization_hash: active.authorization_hash(),
            scope: request.scope,
            requested_cursor: request.requested_cursor,
        },
    )
}

/// `DeviceReplyTx` 的窄授权复核。调用方必须已经持有 `BEGIN IMMEDIATE`，使
/// transition/update/cut、current reply authorization、counter Gap 与 reply key
/// 都属于同一个 SQLite 线性化点。permit 仅是待复核 capability，不能替代本次
/// authenticated Store lookup。
pub(in crate::runtime::store) fn validate_transition_snapshot_permit_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    permit: &TransitionSnapshotPermit,
    authorization: &super::super::pairing_authorization::RemoteReplyAuthorization,
) -> Result<(), RuntimeStoreError> {
    let recipient = KeyTransitionRecipient {
        device_route: *authorization.device_route().as_bytes(),
        grant_serial: authorization.grant_serial().value(),
    };
    if permit.recipient != recipient
        || permit.authorization_hash != authorization.authorization_hash()
        || permit.key_directory_revision != authorization.key_directory_revision().value()
    {
        return Err(RuntimeStoreError::PairingConflict);
    }

    validate_transition_snapshot_permit_axes_in_transaction(
        transaction,
        key_bundle,
        database_id,
        permit,
    )
}

/// Store special snapshot barrier 没有可外带的 reply authorization 对象；它仍必须
/// 在自己的 SQLite transaction 内把 opaque permit 重新绑定到 authenticated
/// transition/update/cut 全轴。authorization 与 recipient/revision/hash 的绑定已在
/// permit 签发事务中冻结，reply path 还会在调用本 helper 前额外复核 current auth。
pub(in crate::runtime::store) fn validate_transition_snapshot_permit_axes_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    permit: &TransitionSnapshotPermit,
) -> Result<(), RuntimeStoreError> {
    let transition = load_active_transition(transaction, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if transition.record.operation_id != permit.operation_id
        || transition.record.operation != KeyTransitionOperation::Add
        || transition.record.target != KeyTransitionTarget::Device(permit.recipient)
        || transition.record.phase != KeyTransitionPhase::BarriersCommitted
        || transition.record.terminal.is_some()
        || transition.record.to_revision != permit.key_directory_revision
        || !transition.record.recipients.contains(&permit.recipient)
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let update = load_update(
        transaction,
        key_bundle,
        database_id,
        permit.operation_id,
        permit.recipient,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if update.record.lifecycle != KeyUpdateLifecycle::Acked
        || update.record.key_revision != permit.key_directory_revision
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let _ = exact_permit_cut(&transition.record, permit)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn resolve_transition_snapshot_permit_for_test(
    state: &RuntimeSqlite,
    query: TransitionSnapshotQuery,
) -> Result<TransitionSnapshotPermit, RuntimeStoreError> {
    resolve_bound_transition_snapshot_permit(state, query)
}

fn resolve_bound_transition_snapshot_permit(
    state: &RuntimeSqlite,
    query: TransitionSnapshotQuery,
) -> Result<TransitionSnapshotPermit, RuntimeStoreError> {
    validate_nonzero(query.recipient.device_route)?;
    validate_nonzero(query.authorization_hash)?;
    if query.recipient.grant_serial == 0
        || query.key_revision == 0
        || query.requested_cursor != StreamCursor::BeforeFirst
        || matches!(query.scope, KeyTransitionStreamScope::Conversation(id) if id == [0; 16])
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let transition =
        load_active_transition(&state.connection, &state.key_bundle, state.database_id)?
            .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if transition.record.operation != KeyTransitionOperation::Add
        || transition.record.target != KeyTransitionTarget::Device(query.recipient)
        || transition.record.phase != KeyTransitionPhase::BarriersCommitted
        || transition.record.terminal.is_some()
        || transition.record.to_revision != query.key_revision
        || !transition.record.recipients.contains(&query.recipient)
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let update = load_update(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        transition.record.operation_id,
        query.recipient,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if update.record.lifecycle != KeyUpdateLifecycle::Acked
        || update.record.key_revision != query.key_revision
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let mut cuts = transition
        .record
        .cuts
        .iter()
        .filter(|cut| cut.scope == query.scope);
    let cut = cuts.next().ok_or(RuntimeStoreError::PublicationMismatch)?;
    if cuts.next().is_some()
        || checked_next_outer(cut.relay_committed_outer)? != cut.barrier_sequence
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(TransitionSnapshotPermit {
        operation_id: transition.record.operation_id,
        recipient: query.recipient,
        authorization_hash: query.authorization_hash,
        scope: cut.scope,
        publication_stream_id: cut.publication_stream_id,
        stream_route: cut.stream_route,
        generation: cut.generation,
        relay_committed_outer: cut.relay_committed_outer,
        relay_committed_inner: cut.relay_committed_inner,
        barrier_sequence: cut.barrier_sequence,
        key_directory_revision: transition.record.to_revision,
        key_epoch: cut.new_epoch,
        epoch_barrier_sha256: cut.epoch_barrier_sha256,
    })
}

/// 真实 directed snapshot 与 canonical RuntimeSyncComplete 已经通过 Relay writer
/// flush 后记录 durable marker。`sync_complete_sha256` 必须只覆盖稳定 canonical
/// RuntimeSyncComplete payload，不得包含 message/request id、Relay outer 或 ciphertext。
pub(crate) fn mark_transition_snapshot_flushed(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    flush: TransitionSnapshotFlush,
    flushed_at_ms: u64,
) -> Result<TransitionSnapshotFlushRecord, RuntimeStoreError> {
    admit_transition_write(state, config, 128 * 1024)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let transition = load_transition(
        &transaction,
        &key_bundle,
        database_id,
        flush.permit.operation_id,
    )?
    .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if transition.record.operation != KeyTransitionOperation::Add
        || transition.record.target != KeyTransitionTarget::Device(flush.permit.recipient)
        || transition.record.to_revision != flush.permit.key_directory_revision
        || !matches!(
            (transition.record.phase, transition.record.terminal),
            (KeyTransitionPhase::BarriersCommitted, None)
                | (
                    KeyTransitionPhase::Complete,
                    Some(KeyTransitionTerminal::Completed)
                )
        )
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let cut = exact_permit_cut(&transition.record, &flush.permit)?;
    let authenticated = load_update(
        &transaction,
        &key_bundle,
        database_id,
        flush.permit.operation_id,
        flush.permit.recipient,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if authenticated.record.lifecycle != KeyUpdateLifecycle::Acked
        || authenticated.record.key_revision != flush.permit.key_directory_revision
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let marker = TransitionSnapshotFlushRecord {
        scope: cut.scope,
        publication_stream_id: cut.publication_stream_id,
        stream_route: cut.stream_route,
        generation: cut.generation,
        relay_committed_outer: cut.relay_committed_outer,
        relay_committed_inner: cut.relay_committed_inner,
        barrier_sequence: cut.barrier_sequence,
        key_directory_revision: transition.record.to_revision,
        key_epoch: cut.new_epoch,
        epoch_barrier_sha256: cut.epoch_barrier_sha256,
        authorization_hash: flush.permit.authorization_hash,
        sync_complete_sha256: flush.sync_complete_sha256,
        flushed_at_ms,
    };
    let identity = snapshot_flush_identity(&marker);
    if let Some(existing) = authenticated
        .record
        .snapshot_flushes
        .iter()
        .find(|record| snapshot_flush_identity(record) == identity)
    {
        if same_snapshot_flush(existing, &marker) {
            transaction.rollback()?;
            return Ok(existing.clone());
        }
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if transition.record.phase != KeyTransitionPhase::BarriersCommitted
        || transition.record.terminal.is_some()
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    require_monotonic_time(authenticated.record.state_changed_at_ms, flushed_at_ms)?;
    let mut changed = authenticated.record.clone();
    changed.snapshot_flushes.push(marker.clone());
    changed
        .snapshot_flushes
        .sort_by_key(snapshot_flush_identity);
    changed.state_changed_at_ms = flushed_at_ms;
    let mut next = ledger.clone();
    replace_update(
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
    Ok(marker)
}

fn exact_permit_cut<'a>(
    transition: &'a KeyTransitionRecord,
    permit: &TransitionSnapshotPermit,
) -> Result<&'a KeyTransitionStreamCut, RuntimeStoreError> {
    let mut cuts = transition.cuts.iter().filter(|cut| {
        cut.scope == permit.scope
            && cut.publication_stream_id == permit.publication_stream_id
            && cut.stream_route == permit.stream_route
            && cut.generation == permit.generation
            && cut.relay_committed_outer == permit.relay_committed_outer
            && cut.relay_committed_inner == permit.relay_committed_inner
            && cut.barrier_sequence == permit.barrier_sequence
            && transition.to_revision == permit.key_directory_revision
            && cut.new_epoch == permit.key_epoch
            && cut.epoch_barrier_sha256 == permit.epoch_barrier_sha256
    });
    let cut = cuts.next().ok_or(RuntimeStoreError::PublicationMismatch)?;
    if cuts.next().is_some()
        || checked_next_outer(cut.relay_committed_outer)? != cut.barrier_sequence
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(cut)
}

pub(super) fn snapshot_delivery_required(
    transition: &KeyTransitionRecord,
    recipient: KeyTransitionRecipient,
) -> bool {
    transition.operation == KeyTransitionOperation::Add
        && transition.target == KeyTransitionTarget::Device(recipient)
        && !transition.cuts.is_empty()
}

pub(super) fn has_exact_snapshot_flush(
    transition: &KeyTransitionRecord,
    update: &KeyUpdateRecord,
    cut: &KeyTransitionStreamCut,
    authorization_hash: [u8; 32],
) -> bool {
    update.snapshot_flushes.iter().any(|marker| {
        marker.scope == cut.scope
            && marker.publication_stream_id == cut.publication_stream_id
            && marker.stream_route == cut.stream_route
            && marker.generation == cut.generation
            && marker.relay_committed_outer == cut.relay_committed_outer
            && marker.relay_committed_inner == cut.relay_committed_inner
            && marker.barrier_sequence == cut.barrier_sequence
            && marker.key_directory_revision == transition.to_revision
            && marker.key_epoch == cut.new_epoch
            && marker.epoch_barrier_sha256 == cut.epoch_barrier_sha256
            && marker.authorization_hash == authorization_hash
            && marker.sync_complete_sha256 != [0; 32]
    })
}

pub(super) fn marker_matches_transition_cut(
    transition: &KeyTransitionRecord,
    update: &KeyUpdateRecord,
    marker: &TransitionSnapshotFlushRecord,
) -> bool {
    snapshot_delivery_required(transition, update.recipient)
        && marker.authorization_hash != [0; 32]
        && transition.cuts.iter().any(|cut| {
            marker.scope == cut.scope
                && marker.publication_stream_id == cut.publication_stream_id
                && marker.stream_route == cut.stream_route
                && marker.generation == cut.generation
                && marker.relay_committed_outer == cut.relay_committed_outer
                && marker.relay_committed_inner == cut.relay_committed_inner
                && marker.barrier_sequence == cut.barrier_sequence
                && marker.key_directory_revision == transition.to_revision
                && marker.key_epoch == cut.new_epoch
                && marker.epoch_barrier_sha256 == cut.epoch_barrier_sha256
                && marker.sync_complete_sha256 != [0; 32]
        })
}

pub(super) fn has_all_required_snapshot_flushes(
    transition: &KeyTransitionRecord,
    update: &KeyUpdateRecord,
) -> bool {
    if !snapshot_delivery_required(transition, update.recipient) {
        return update.snapshot_flushes.is_empty();
    }
    let Some(first) = update.snapshot_flushes.first() else {
        return false;
    };
    update.snapshot_flushes.len() == transition.cuts.len()
        && transition
            .cuts
            .iter()
            .all(|cut| has_exact_snapshot_flush(transition, update, cut, first.authorization_hash))
        && update
            .snapshot_flushes
            .iter()
            .all(|marker| marker.authorization_hash == first.authorization_hash)
}

pub(super) fn has_snapshot_flush_before_ack(
    transition: &KeyTransitionRecord,
    update: &KeyUpdateRecord,
    cut: &KeyTransitionStreamCut,
    acknowledged_at_ms: u64,
) -> bool {
    let Some(authorization_hash) = update
        .snapshot_flushes
        .first()
        .map(|marker| marker.authorization_hash)
    else {
        return false;
    };
    has_exact_snapshot_flush(transition, update, cut, authorization_hash)
        && update.snapshot_flushes.iter().any(|marker| {
            marker.scope == cut.scope
                && marker.publication_stream_id == cut.publication_stream_id
                && marker.stream_route == cut.stream_route
                && marker.generation == cut.generation
                && marker.relay_committed_outer == cut.relay_committed_outer
                && marker.relay_committed_inner == cut.relay_committed_inner
                && marker.barrier_sequence == cut.barrier_sequence
                && marker.key_directory_revision == transition.to_revision
                && marker.key_epoch == cut.new_epoch
                && marker.epoch_barrier_sha256 == cut.epoch_barrier_sha256
                && marker.authorization_hash == authorization_hash
                && marker.flushed_at_ms <= acknowledged_at_ms
        })
}

fn checked_next_outer(value: Option<u64>) -> Result<u64, RuntimeStoreError> {
    match value {
        None => Ok(0),
        Some(value) => value
            .checked_add(1)
            .ok_or(RuntimeStoreError::PublicationCounterExhausted),
    }
}

fn same_snapshot_flush(
    left: &TransitionSnapshotFlushRecord,
    right: &TransitionSnapshotFlushRecord,
) -> bool {
    snapshot_flush_identity(left) == snapshot_flush_identity(right)
        && left.publication_stream_id == right.publication_stream_id
        && left.relay_committed_outer == right.relay_committed_outer
        && left.relay_committed_inner == right.relay_committed_inner
        && left.barrier_sequence == right.barrier_sequence
        && left.key_directory_revision == right.key_directory_revision
        && left.key_epoch == right.key_epoch
        && left.epoch_barrier_sha256 == right.epoch_barrier_sha256
        && left.authorization_hash == right.authorization_hash
        && left.sync_complete_sha256 == right.sync_complete_sha256
}
