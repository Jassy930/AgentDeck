//! P4.5 Runtime Store 侧 authenticated CounterGuard 投影。
//!
//! Keychain guard 永远先进入 `Pending`；本模块随后在 Store transaction 内把完整
//! reservation、publication identity 与 exact DB anchor 冻结到一行。plaintext 使用
//! canonical binary codec，outer projection、row AEAD 与 Runtime ledger 三层交叉认证。

mod codec;
mod integrity;

pub(super) use integrity::validate_full_integrity;

use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use agentdeck_protocol::relay_v2::StreamRouteId;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};

use super::cipher::RuntimeKeyBundle;
use super::sqlite::{RuntimeLedger, RuntimeSqlite};
use super::{PublicationScope, RemoteReplyAuthorization};

use codec::{
    canonical_sequence, derive_anchor, fixed, fresh_counter_recovery_key, genesis_anchor,
    lifecycle_text, open_state, parse_purpose, purpose_text, recovery_request_matches_binding,
    request_uniquely_matches_active_binding, seal_state, trust_reset_required, validate_identity,
    validate_nonzero, validate_recovery_stage_request,
};

const MAX_COUNTER_STATES: u64 = 4_096;
const MAX_COUNTER_SEALED_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteCounterRecordKind {
    Genesis,
    Gap,
    Frozen,
    Retired,
    RecoveryStaged,
    Recovered,
}

impl RemoteCounterRecordKind {
    const fn is_blocking_retirement(self) -> bool {
        matches!(self, Self::Retired | Self::RecoveryStaged)
    }

    pub(crate) const fn is_retirement_lineage(self) -> bool {
        matches!(self, Self::Retired | Self::RecoveryStaged | Self::Recovered)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActiveSenderCounterBinding {
    SharedPublication {
        publication_stream_id: [u8; 16],
        key_id: KeyId,
    },
    DirectedReply {
        authorization: RemoteReplyAuthorization,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CounterRecoveryStageTarget {
    SharedPublication {
        publication_stream_id: [u8; 16],
    },
    DirectedReply {
        authorization: RemoteReplyAuthorization,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CounterRecoveryStageRequest {
    pub operation_id: [u8; 16],
    pub retired_scope_token: [u8; 32],
    pub retired_key_id: KeyId,
    pub replacement_scope_token: [u8; 32],
    pub target: CounterRecoveryStageTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemoteCounterRecoveryBinding {
    pub operation_id: [u8; 16],
    pub retired_scope_token: [u8; 32],
    pub retired_key_id: KeyId,
    pub replacement_scope_token: [u8; 32],
    pub replacement_key_id: KeyId,
    pub from_revision: u64,
    pub to_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CounterRecoveryDisposition {
    Staged,
    AlreadyStaged,
    TrustResetRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CounterRecoveryStageOutcome {
    pub disposition: CounterRecoveryDisposition,
    pub binding: Option<RemoteCounterRecoveryBinding>,
}

/// guard-first counter GC 在 Keychain existing-only 删除并读回 absent 后，交给
/// Runtime Store 复核的 exact scope 期望。普通轮换只允许删除不再 active 的
/// `Gap/Frozen` 行；CounterRecovery 则必须仍是绑定同一 operation 的 `Recovered` 行。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CounterCollectionExpectation {
    Ordinary {
        scope_token: [u8; 32],
        key_id: KeyId,
    },
    Recovered {
        scope_token: [u8; 32],
        key_id: KeyId,
        operation_id: [u8; 16],
    },
}

impl CounterCollectionExpectation {
    pub(super) const fn scope_token(self) -> [u8; 32] {
        match self {
            Self::Ordinary { scope_token, .. } | Self::Recovered { scope_token, .. } => scope_token,
        }
    }

    const fn key_id(self) -> KeyId {
        match self {
            Self::Ordinary { key_id, .. } | Self::Recovered { key_id, .. } => key_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CounterCollectionOutcome {
    pub rows_deleted: u64,
    pub sealed_bytes_deleted: u64,
}

/// RemoteLink admission 的单一 authenticated read snapshot。完整 publication/outbox
/// directory、global key state 与 authorization ledger 都先通过现有 AEAD/MAC/ledger
/// 交叉认证，再只投影当前确实能发送的 shared/directed scope identity。
pub(super) fn load_active_sender_counter_bindings(
    state: &RuntimeSqlite,
    machine_trust_domain: [u8; 32],
) -> Result<Vec<ActiveSenderCounterBinding>, RuntimeStoreError> {
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Deferred)?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    let bindings = load_active_sender_counter_bindings_against_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        machine_trust_domain,
    )?;
    transaction.commit()?;
    Ok(bindings)
}

/// 调用方现有 transaction 内的 active sender inventory。counter retirement 的
/// guard 删除与 DB 收口之间可能跨 await/restart，故最终事务必须用本 helper 重读
/// authenticated directory，而不能信任之前返回候选时的快照。
pub(super) fn load_active_sender_counter_bindings_against_ledger(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    machine_trust_domain: [u8; 32],
) -> Result<Vec<ActiveSenderCounterBinding>, RuntimeStoreError> {
    let streams =
        super::publication::authenticate_directory_records(connection, key_bundle, ledger)?;
    let pairing = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let mut bindings = Vec::new();
    if let Some(global) = pairing.grants.global.as_ref() {
        let shared_keys = global.state.current_shared_keys()?;
        for stream in streams
            .iter()
            .filter(|stream| stream.state == super::publication::PublicationStreamState::Active)
        {
            let stream_route = StreamRouteId::from_bytes(stream.stream_route);
            let key = shared_keys.iter().find(|key| match stream.scope {
                PublicationScope::Catalog => {
                    key.purpose == KeyPurpose::Catalog && key.stream_route.is_none()
                }
                PublicationScope::Conversation(_) => {
                    key.purpose == KeyPurpose::ConversationDek
                        && key.stream_route == Some(stream_route)
                }
            });
            let Some(key) = key else {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            };
            bindings.push(ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id: stream.publication_stream_id,
                key_id: KeyId {
                    purpose: key.purpose,
                    epoch: key.epoch,
                },
            });
        }
    }
    if pairing.grants.authorizations.iter().any(|authorization| {
        authorization.lifecycle == super::pairing_authorization::AuthorizationLifecycle::Active
    }) {
        let active_machine = super::pairing::active_machine(connection, key_bundle, database_id)?;
        bindings.extend(
            super::pairing_authorization::active_remote_reply_authorizations_from_directory(
                database_id,
                machine_trust_domain,
                &active_machine,
                &pairing,
            )?
            .into_iter()
            .map(|authorization| ActiveSenderCounterBinding::DirectedReply { authorization }),
        );
    }
    Ok(bindings)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemoteCounterRecord {
    pub scope_token: [u8; 32],
    pub key_id: KeyId,
    pub reserved_end: u64,
    pub reservation_id: Option<[u8; 16]>,
    pub publication_id: Option<[u8; 16]>,
    pub db_anchor: [u8; 32],
    pub kind: RemoteCounterRecordKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemoteCounterReservation {
    pub scope_token: [u8; 32],
    pub key_id: KeyId,
    pub previous_reserved_end: u64,
    pub reserved_end: u64,
    pub previous_db_anchor: [u8; 32],
    pub reservation_id: [u8; 16],
    pub publication_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemoteCounterGapRequest {
    pub scope_token: [u8; 32],
    pub key_id: KeyId,
    pub expected_reserved_end: u64,
    pub expected_db_anchor: [u8; 32],
    pub abandoned_through: u64,
    pub reservation_id: [u8; 16],
    pub publication_id: [u8; 16],
}

/// CounterGuard 对账判定旧 scope/epoch 不可再使用后提交的 durable tombstone。
/// `retired_through` 来自 authenticated secure-store guard high-water；Store 仍以
/// expected DB anchor 做 CAS，绝不让调用方覆盖一个已经变化的 counter head。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemoteCounterRetirementRequest {
    pub scope_token: [u8; 32],
    pub key_id: KeyId,
    pub expected_reserved_end: u64,
    pub expected_db_anchor: [u8; 32],
    pub retired_through: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RemoteCounterFreezeAxes {
    pub publication_stream_id: [u8; 16],
    pub generation: [u8; 16],
    pub stream_seq: u64,
    pub sender_counter: u64,
    pub blob_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterState {
    record: RemoteCounterRecord,
    previous_db_anchor: [u8; 32],
    publication_stream_id: Option<[u8; 16]>,
    generation: Option<[u8; 16]>,
    stream_seq: Option<u64>,
    sender_counter: Option<u64>,
    blob_sha256: Option<[u8; 32]>,
    recovery: Option<RemoteCounterRecoveryBinding>,
}

struct AuthenticatedCounterRow {
    record: RemoteCounterRecord,
    state: CounterState,
    sealed_bytes: u64,
    metadata_token: [u8; 32],
}

type RawCounterRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    Option<Vec<u8>>,
    Vec<u8>,
    String,
    Vec<u8>,
    i64,
    Vec<u8>,
);

pub(super) fn load_record(
    state: &RuntimeSqlite,
    scope_token: [u8; 32],
    key_id: KeyId,
) -> Result<RemoteCounterRecord, RuntimeStoreError> {
    validate_identity(scope_token, key_id)?;
    match load_optional_record(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        scope_token,
    )? {
        Some(row) if row.record.key_id == key_id => Ok(row.record),
        Some(_) => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        None => Ok(RemoteCounterRecord {
            scope_token,
            key_id,
            reserved_end: 0,
            reservation_id: None,
            publication_id: None,
            db_anchor: genesis_anchor(&state.key_bundle, state.database_id, scope_token, key_id)?,
            kind: RemoteCounterRecordKind::Genesis,
        }),
    }
}

/// membership EpochBarrier 在同一 Store transaction 内解绑旧 publication scope 前的
/// authenticated identity check。旧 scope 必须真实存在、绑定 exact old key，且不能已经
///进入 retirement lineage；不存在的 genesis 不能被当作曾经使用过的 sender scope。
pub(super) fn require_existing_scope_key_identity(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    key_id: KeyId,
) -> Result<(), RuntimeStoreError> {
    validate_identity(scope_token, key_id)?;
    let row = load_optional_record(connection, key_bundle, database_id, scope_token)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if row.record.key_id != key_id || row.record.kind.is_retirement_lineage() {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

/// shared publisher preflight 的 exact frozen readback。只在整行 counter AEAD、metadata
/// 与 outbox 五轴完全一致时返回 key identity；不能从未认证 outer columns 猜 key。
pub(super) fn load_frozen_key_id_for_publication(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    publication: &super::publication::FrozenPublication,
) -> Result<KeyId, RuntimeStoreError> {
    let row = load_optional_record(
        connection,
        key_bundle,
        database_id,
        publication.counter_scope_token,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if row.record.kind != RemoteCounterRecordKind::Frozen
        || row.record.publication_id != Some(publication.publication_id)
        || row.state.publication_stream_id != Some(publication.publication_stream_id)
        || row.state.generation != Some(publication.generation)
        || row.state.stream_seq != Some(publication.stream_seq)
        || row.state.sender_counter != Some(publication.sender_counter)
        || row.state.blob_sha256 != Some(publication.blob_sha256)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(row.record.key_id)
}

pub(super) fn record_gap(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    request: RemoteCounterGapRequest,
) -> Result<RemoteCounterRecord, RuntimeStoreError> {
    validate_identity(request.scope_token, request.key_id)?;
    validate_nonzero(request.expected_db_anchor)?;
    validate_nonzero(request.reservation_id)?;
    validate_nonzero(request.publication_id)?;
    if request.abandoned_through <= request.expected_reserved_end {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    super::sqlite::admit_safety_write(
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
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let mut next = ledger.clone();
    let record =
        record_gap_in_transaction(&transaction, &key_bundle, database_id, request, &mut next)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(record)
}

/// 把旧 counter scope/epoch 单调改写为 authenticated `Retired`，COMMIT 后再做一次
/// exact authenticated readback。重复请求只返回原 tombstone，不滚动 anchor。
pub(super) fn retire(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    request: RemoteCounterRetirementRequest,
) -> Result<RemoteCounterRecord, RuntimeStoreError> {
    validate_identity(request.scope_token, request.key_id)?;
    validate_nonzero(request.expected_db_anchor)?;
    if request.retired_through < request.expected_reserved_end {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    super::sqlite::admit_safety_write(
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
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let mut next = ledger.clone();
    let previous = load_exact(
        &transaction,
        &key_bundle,
        database_id,
        request.scope_token,
        request.key_id,
        request.expected_reserved_end,
        request.expected_db_anchor,
    )?;
    if let Some(previous) = &previous
        && previous.record.kind == RemoteCounterRecordKind::Retired
    {
        let record = previous.record;
        transaction.commit()?;
        return Ok(record);
    }
    let mut retired = CounterState {
        record: RemoteCounterRecord {
            scope_token: request.scope_token,
            key_id: request.key_id,
            reserved_end: request.retired_through,
            reservation_id: previous.as_ref().and_then(|row| row.record.reservation_id),
            publication_id: previous.as_ref().and_then(|row| row.record.publication_id),
            db_anchor: request.expected_db_anchor,
            kind: RemoteCounterRecordKind::Retired,
        },
        previous_db_anchor: request.expected_db_anchor,
        publication_stream_id: None,
        generation: None,
        stream_seq: None,
        sender_counter: None,
        blob_sha256: None,
        recovery: None,
    };
    retired.record.db_anchor = derive_anchor(&key_bundle, database_id, &retired)?;
    persist_state(
        &transaction,
        &key_bundle,
        database_id,
        previous.as_ref(),
        &retired,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);

    let readback = load_record(state, request.scope_token, request.key_id)?;
    if readback != retired.record || readback.kind != RemoteCounterRecordKind::Retired {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(readback)
}

/// 把一个已认证 `Retired` sender scope 原子提升为受控 rekey transition。
///
/// 第一笔 DML 前会重新认证 active sender inventory、唯一 transition slot、ADGK2、
/// publication/authorization directory 与旧 tombstone。成功事务同时提交：新 sender
/// key epoch、directory/authorization revision、`CounterRecovery` transition 与旧 scope
/// 的 durable replacement binding。无法唯一绑定 canonical sender 或 transition slot 已占用
/// 时不改写任何行，保留原 `Retired` fence 并返回 typed trust-reset requirement。
pub(super) fn stage_recovery(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    machine_trust_domain: [u8; 32],
    request: CounterRecoveryStageRequest,
) -> Result<CounterRecoveryStageOutcome, RuntimeStoreError> {
    validate_recovery_stage_request(&request)?;
    let existing = load_optional_record(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        request.retired_scope_token,
    )?
    .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if existing.record.key_id != request.retired_key_id {
        return Ok(trust_reset_required());
    }
    if matches!(
        existing.record.kind,
        RemoteCounterRecordKind::RecoveryStaged | RemoteCounterRecordKind::Recovered
    ) {
        let binding = existing
            .state
            .recovery
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        return if recovery_request_matches_binding(&request, binding) {
            Ok(CounterRecoveryStageOutcome {
                disposition: CounterRecoveryDisposition::AlreadyStaged,
                binding: Some(binding),
            })
        } else {
            Ok(trust_reset_required())
        };
    }
    let active_bindings = load_active_sender_counter_bindings(state, machine_trust_domain)?;
    if !request_uniquely_matches_active_binding(&request, &active_bindings) {
        return Ok(trust_reset_required());
    }
    if existing.record.kind != RemoteCounterRecordKind::Retired {
        return Ok(trust_reset_required());
    }

    let ledger = super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )?;
    if ledger.remote_key_transition_active_count != 0
        || super::key_transition::load_active_key_transition(state)?.is_some()
    {
        return Ok(trust_reset_required());
    }
    let now_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    if now_ms == 0 {
        return Ok(trust_reset_required());
    }
    let replacement_key = fresh_counter_recovery_key()?;
    super::sqlite::admit_safety_write(
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
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    if ledger.remote_key_transition_active_count != 0 {
        transaction.rollback()?;
        return Ok(trust_reset_required());
    }
    let retired = load_optional_record(
        &transaction,
        &key_bundle,
        database_id,
        request.retired_scope_token,
    )?
    .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if retired.record.key_id != request.retired_key_id
        || retired.record.kind != RemoteCounterRecordKind::Retired
    {
        transaction.rollback()?;
        return Ok(trust_reset_required());
    }
    if load_optional_record(
        &transaction,
        &key_bundle,
        database_id,
        request.replacement_scope_token,
    )?
    .is_some()
    {
        transaction.rollback()?;
        return Ok(trust_reset_required());
    }
    let previous_global =
        super::pairing_grant::load_global_key_state(&transaction, &key_bundle, database_id)?
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if ledger.remote_key_directory_count != 1
        || ledger.remote_key_directory_sealed_bytes != previous_global.sealed_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let from_revision = previous_global.revision;
    let to_revision = from_revision
        .checked_add(1)
        .ok_or(RuntimeStoreError::PublicationCounterExhausted)?;
    let authorizations =
        super::pairing_authorization::load_authorizations(&transaction, &key_bundle, database_id)?;
    let recipients =
        super::conversation_activation::current_recipients(&authorizations, from_revision)?;
    if recipients.is_empty() {
        transaction.rollback()?;
        return Ok(trust_reset_required());
    }

    let (next_global, transition_target, replacement_key_id) = match &request.target {
        CounterRecoveryStageTarget::SharedPublication {
            publication_stream_id,
        } => {
            let streams = super::publication::authenticate_directory_records(
                &transaction,
                &key_bundle,
                &ledger,
            )?;
            let mut matches = streams.iter().filter(|stream| {
                stream.publication_stream_id == *publication_stream_id
                    && stream.state == super::publication::PublicationStreamState::Active
            });
            let stream = matches
                .next()
                .ok_or(RuntimeStoreError::PublicationMismatch)?;
            if matches.next().is_some() {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
            let (purpose, shared_route, conversation_id) = match stream.scope {
                PublicationScope::Catalog => {
                    (KeyPurpose::Catalog, None, stream.publication_stream_id)
                }
                PublicationScope::Conversation(conversation_id) => (
                    KeyPurpose::ConversationDek,
                    Some(StreamRouteId::from_bytes(stream.stream_route)),
                    *conversation_id.as_bytes(),
                ),
            };
            if request.retired_key_id.purpose != purpose {
                transaction.rollback()?;
                return Ok(trust_reset_required());
            }
            let (next, rotation) = previous_global.state.rotate_counter_recovery_shared(
                purpose,
                shared_route,
                replacement_key,
                now_ms,
            )?;
            if rotation.old_epoch != request.retired_key_id.epoch
                || rotation.new_epoch
                    != request
                        .retired_key_id
                        .epoch
                        .checked_add(1)
                        .ok_or(RuntimeStoreError::PublicationCounterExhausted)?
            {
                transaction.rollback()?;
                return Ok(trust_reset_required());
            }
            (
                next,
                super::key_transition::KeyTransitionTarget::Conversation {
                    conversation_id,
                    stream_route: stream.stream_route,
                },
                KeyId {
                    purpose,
                    epoch: rotation.new_epoch,
                },
            )
        }
        CounterRecoveryStageTarget::DirectedReply { authorization } => {
            let recipient = super::key_transition::KeyTransitionRecipient {
                device_route: *authorization.device_route().as_bytes(),
                grant_serial: authorization.grant_serial().value(),
            };
            if request.retired_key_id.purpose != KeyPurpose::DeviceReplyTx
                || authorization.reply_key_epoch() != request.retired_key_id.epoch
                || !recipients.contains(&recipient)
            {
                transaction.rollback()?;
                return Ok(trust_reset_required());
            }
            let (next, old_epoch, new_epoch) = previous_global
                .state
                .rotate_counter_recovery_reply(authorization.device_route(), replacement_key)?;
            if old_epoch != request.retired_key_id.epoch
                || new_epoch
                    != old_epoch
                        .checked_add(1)
                        .ok_or(RuntimeStoreError::PublicationCounterExhausted)?
            {
                transaction.rollback()?;
                return Ok(trust_reset_required());
            }
            (
                next,
                super::key_transition::KeyTransitionTarget::Device(recipient),
                KeyId {
                    purpose: KeyPurpose::DeviceReplyTx,
                    epoch: new_epoch,
                },
            )
        }
    };
    if next_global.revision().value() != to_revision
        || replacement_key_id.purpose != request.retired_key_id.purpose
        || replacement_key_id.epoch
            != request
                .retired_key_id
                .epoch
                .checked_add(1)
                .ok_or(RuntimeStoreError::PublicationCounterExhausted)?
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }

    let binding = RemoteCounterRecoveryBinding {
        operation_id: request.operation_id,
        retired_scope_token: request.retired_scope_token,
        retired_key_id: request.retired_key_id,
        replacement_scope_token: request.replacement_scope_token,
        replacement_key_id,
        from_revision,
        to_revision,
    };
    let canonical = next_global.canonical_bytes()?;
    let directory_hash = agentdeck_crypto::sha256(canonical.as_slice());
    let sealed = super::pairing_grant::seal_row(
        &key_bundle,
        database_id,
        super::pairing_grant::GLOBAL_KEY_TABLE,
        b"1",
        super::pairing_grant::GLOBAL_KEY_COLUMN,
        canonical.as_slice(),
        super::pairing_grant::MAX_GLOBAL_KEY_STATE_BYTES,
    )?;
    let metadata_token = super::pairing_grant::global_key_token(
        &key_bundle,
        database_id,
        to_revision,
        directory_hash,
        &sealed,
    )?;
    let mut next_ledger = ledger.clone();
    super::conversation_activation::replace_global_key_bytes(
        &mut next_ledger,
        previous_global.sealed_bytes,
        sealed.len(),
    )?;
    super::key_transition::stage_key_transition_in_transaction(
        &transaction,
        &key_bundle,
        database_id,
        &mut next_ledger,
        super::key_transition::BeginKeyTransition {
            operation_id: request.operation_id,
            operation: super::key_transition::KeyTransitionOperation::CounterRecovery,
            target: transition_target,
            from_revision,
            to_revision,
            recipients,
            replay_retirement: None,
            created_at_ms: now_ms,
        },
    )?;
    super::conversation_activation::align_current_authorizations(
        &transaction,
        &key_bundle,
        database_id,
        &authorizations,
        from_revision,
        to_revision,
    )?;
    if transaction.execute(
        "UPDATE remote_key_directory
         SET revision = ?1, directory_hash = ?2, sealed_directory = ?3,
             sealed_directory_bytes = ?4, metadata_token = ?5
         WHERE singleton = 1 AND revision = ?6 AND directory_hash = ?7
           AND metadata_token = ?8",
        params![
            super::sequence::encode_sequence(to_revision),
            &directory_hash[..],
            &sealed,
            i64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &metadata_token[..],
            super::sequence::encode_sequence(from_revision),
            &previous_global.directory_hash[..],
            &previous_global.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let mut staged = CounterState {
        record: RemoteCounterRecord {
            kind: RemoteCounterRecordKind::RecoveryStaged,
            db_anchor: retired.record.db_anchor,
            ..retired.record
        },
        previous_db_anchor: retired.record.db_anchor,
        publication_stream_id: None,
        generation: None,
        stream_seq: None,
        sender_counter: None,
        blob_sha256: None,
        recovery: Some(binding),
    };
    staged.record.db_anchor = derive_anchor(&key_bundle, database_id, &staged)?;
    persist_state(
        &transaction,
        &key_bundle,
        database_id,
        Some(&retired),
        &staged,
        &mut next_ledger,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);

    let readback = load_optional_record(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        request.retired_scope_token,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if readback.record.kind != RemoteCounterRecordKind::RecoveryStaged
        || readback.state.recovery != Some(binding)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(CounterRecoveryStageOutcome {
        disposition: CounterRecoveryDisposition::Staged,
        binding: Some(binding),
    })
}

/// 只在 exact `CounterRecovery` transition 已到 `BarriersCommitted` 时把旧 sender
/// tombstone 标为 `Recovered`。调用过早、operation 漂移或 transition 已消失均 fail-close。
pub(super) fn mark_recovery_business_ready(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
) -> Result<RemoteCounterRecord, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    let transition = super::key_transition::load_active_key_transition(state)?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if transition.transition.operation_id != operation_id
        || transition.transition.operation
            != super::key_transition::KeyTransitionOperation::CounterRecovery
        || transition.transition.phase
            != super::key_transition::KeyTransitionPhase::BarriersCommitted
        || transition.transition.terminal.is_some()
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let staged = find_counter_recovery_by_operation(state, operation_id)?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if staged.record.kind == RemoteCounterRecordKind::Recovered {
        return Ok(staged.record);
    }
    if staged.record.kind != RemoteCounterRecordKind::RecoveryStaged {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let binding = staged
        .state
        .recovery
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if binding.from_revision != transition.transition.from_revision
        || binding.to_revision != transition.transition.to_revision
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    super::sqlite::admit_safety_write(
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
    let current = load_optional_record(
        &transaction,
        &key_bundle,
        database_id,
        binding.retired_scope_token,
    )?
    .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if current.record.kind != RemoteCounterRecordKind::RecoveryStaged
        || current.state.recovery != Some(binding)
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let mut next_ledger = ledger.clone();
    let mut recovered = CounterState {
        record: RemoteCounterRecord {
            kind: RemoteCounterRecordKind::Recovered,
            db_anchor: current.record.db_anchor,
            ..current.record
        },
        previous_db_anchor: current.record.db_anchor,
        publication_stream_id: None,
        generation: None,
        stream_seq: None,
        sender_counter: None,
        blob_sha256: None,
        recovery: Some(binding),
    };
    recovered.record.db_anchor = derive_anchor(&key_bundle, database_id, &recovered)?;
    persist_state(
        &transaction,
        &key_bundle,
        database_id,
        Some(&current),
        &recovered,
        &mut next_ledger,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    let readback = load_record(state, binding.retired_scope_token, binding.retired_key_id)?;
    if readback.kind != RemoteCounterRecordKind::Recovered {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(readback)
}

/// manager/Pre-Core gate 的 authenticated durable read。任一 Retired counter 都会把
/// remote business 全局保持 fail-close，直到受控 rekey/repair 清理该 tombstone。
pub(super) fn has_retired(state: &RuntimeSqlite) -> Result<bool, RuntimeStoreError> {
    has_retired_in_connection(&state.connection, &state.key_bundle, state.database_id)
}

fn has_retired_in_connection(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<bool, RuntimeStoreError> {
    Ok(load_retirement_rows(connection, key_bundle, database_id)?
        .iter()
        .any(|row| row.record.kind.is_blocking_retirement()))
}

fn scope_allowed_in_connection(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
) -> Result<bool, RuntimeStoreError> {
    let rows = load_retirement_rows(connection, key_bundle, database_id)?;
    if rows.iter().any(|row| row.record.scope_token == scope_token) {
        return Ok(false);
    }
    let blocking = rows
        .iter()
        .filter(|row| row.record.kind.is_blocking_retirement())
        .collect::<Vec<_>>();
    match blocking.as_slice() {
        [] => Ok(true),
        [staged] if staged.record.kind == RemoteCounterRecordKind::RecoveryStaged => {
            let binding = staged
                .state
                .recovery
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            if binding.replacement_scope_token != scope_token {
                return Ok(false);
            }
            super::key_transition::validate_counter_recovery_transition_binding(
                connection,
                key_bundle,
                database_id,
                binding.operation_id,
                binding.from_revision,
                binding.to_revision,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// RecoveryStaged 期间仅 exact replacement scope 可用于 key-update/barrier recovery；
/// 原 scope 与所有无关 sender 继续 fail-close。BusinessReady 后没有 blocking row，但旧
/// retirement lineage 仍永久不可重新成为 active scope。
pub(super) fn scope_allowed(
    state: &RuntimeSqlite,
    scope_token: [u8; 32],
) -> Result<bool, RuntimeStoreError> {
    validate_nonzero(scope_token)?;
    let rows = load_retirement_rows(&state.connection, &state.key_bundle, state.database_id)?;
    if rows.iter().any(|row| row.record.scope_token == scope_token) {
        return Ok(false);
    }
    let blocking = rows
        .iter()
        .filter(|row| row.record.kind.is_blocking_retirement())
        .collect::<Vec<_>>();
    if blocking.is_empty() {
        return Ok(true);
    }
    let [staged] = blocking.as_slice() else {
        return Ok(false);
    };
    if staged.record.kind != RemoteCounterRecordKind::RecoveryStaged {
        return Ok(false);
    }
    let binding = staged
        .state
        .recovery
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if binding.replacement_scope_token != scope_token {
        return Ok(false);
    }
    let Some(transition) = super::key_transition::load_active_key_transition(state)? else {
        return Ok(false);
    };
    Ok(transition.transition.operation_id == binding.operation_id
        && transition.transition.operation
            == super::key_transition::KeyTransitionOperation::CounterRecovery
        && transition.transition.from_revision == binding.from_revision
        && transition.transition.to_revision == binding.to_revision
        && transition.transition.terminal.is_none())
}

/// 调用方已持有 `BEGIN IMMEDIATE`；把整个预留 block 记成永久跳号，并更新同一份
/// ledger next image。directed reply 使用首个 counter，block 其余部分仍不可复用。
pub(super) fn record_gap_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    request: RemoteCounterGapRequest,
    next_ledger: &mut RuntimeLedger,
) -> Result<RemoteCounterRecord, RuntimeStoreError> {
    if !scope_allowed_in_connection(transaction, key_bundle, database_id, request.scope_token)? {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    validate_identity(request.scope_token, request.key_id)?;
    validate_nonzero(request.expected_db_anchor)?;
    validate_nonzero(request.reservation_id)?;
    validate_nonzero(request.publication_id)?;
    if request.abandoned_through <= request.expected_reserved_end {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let previous = load_expected(
        transaction,
        key_bundle,
        database_id,
        request.scope_token,
        request.key_id,
        request.expected_reserved_end,
        request.expected_db_anchor,
    )?;
    let mut state = CounterState {
        record: RemoteCounterRecord {
            scope_token: request.scope_token,
            key_id: request.key_id,
            reserved_end: request.abandoned_through,
            reservation_id: Some(request.reservation_id),
            publication_id: Some(request.publication_id),
            db_anchor: request.expected_db_anchor,
            kind: RemoteCounterRecordKind::Gap,
        },
        previous_db_anchor: request.expected_db_anchor,
        publication_stream_id: None,
        generation: None,
        stream_seq: None,
        sender_counter: None,
        blob_sha256: None,
        recovery: None,
    };
    state.record.db_anchor = derive_anchor(key_bundle, database_id, &state)?;
    persist_state(
        transaction,
        key_bundle,
        database_id,
        previous.as_ref(),
        &state,
        next_ledger,
    )?;
    Ok(state.record)
}

/// 调用方已经持有 publication `BEGIN IMMEDIATE` transaction；本函数只在同一事务
/// 冻结 counter row并更新同一份 ledger next image，不自行 COMMIT。
pub(super) fn freeze_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    reservation: RemoteCounterReservation,
    axes: RemoteCounterFreezeAxes,
    next_ledger: &mut RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    if !scope_allowed_in_connection(
        transaction,
        key_bundle,
        database_id,
        reservation.scope_token,
    )? {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    validate_identity(reservation.scope_token, reservation.key_id)?;
    validate_nonzero(reservation.previous_db_anchor)?;
    validate_nonzero(reservation.reservation_id)?;
    validate_nonzero(reservation.publication_id)?;
    validate_nonzero(axes.publication_stream_id)?;
    validate_nonzero(axes.generation)?;
    validate_nonzero(axes.blob_sha256)?;
    if reservation.reserved_end <= reservation.previous_reserved_end
        || axes.sender_counter != reservation.previous_reserved_end
        || axes.sender_counter >= reservation.reserved_end
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let previous = load_expected(
        transaction,
        key_bundle,
        database_id,
        reservation.scope_token,
        reservation.key_id,
        reservation.previous_reserved_end,
        reservation.previous_db_anchor,
    )?;
    let mut state = CounterState {
        record: RemoteCounterRecord {
            scope_token: reservation.scope_token,
            key_id: reservation.key_id,
            reserved_end: reservation.reserved_end,
            reservation_id: Some(reservation.reservation_id),
            publication_id: Some(reservation.publication_id),
            db_anchor: reservation.previous_db_anchor,
            kind: RemoteCounterRecordKind::Frozen,
        },
        previous_db_anchor: reservation.previous_db_anchor,
        publication_stream_id: Some(axes.publication_stream_id),
        generation: Some(axes.generation),
        stream_seq: Some(axes.stream_seq),
        sender_counter: Some(axes.sender_counter),
        blob_sha256: Some(axes.blob_sha256),
        recovery: None,
    };
    state.record.db_anchor = derive_anchor(key_bundle, database_id, &state)?;
    persist_state(
        transaction,
        key_bundle,
        database_id,
        previous.as_ref(),
        &state,
        next_ledger,
    )?;
    Ok(state.record.db_anchor)
}

/// 在调用一次性 sealer 前认证 reservation 的 DB head。publication transaction
/// 随后仍会在真正写 counter row 时再次带同一 expected anchor 做 CAS 式校验。
pub(super) fn validate_reservation_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    reservation: RemoteCounterReservation,
) -> Result<(), RuntimeStoreError> {
    if !scope_allowed_in_connection(
        transaction,
        key_bundle,
        database_id,
        reservation.scope_token,
    )? {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if reservation.reserved_end <= reservation.previous_reserved_end
        || reservation.publication_id == [0; 16]
        || reservation.reservation_id == [0; 16]
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let _ = load_expected(
        transaction,
        key_bundle,
        database_id,
        reservation.scope_token,
        reservation.key_id,
        reservation.previous_reserved_end,
        reservation.previous_db_anchor,
    )?;
    Ok(())
}

/// caller 已按 authenticated transition plan 对每个 scope 执行 Keychain
/// existing-only delete 并逐项读回 absent 后，才可调用本函数。全部候选 counter
/// row 会在第一笔 DELETE 前完成 AEAD/metadata/lineage 复核；删除与 ledger 精确扣减
/// 留在 caller 的同一 transaction 中，不在这里 COMMIT。
pub(super) fn collect_after_guard_readback_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    next_ledger: &mut RuntimeLedger,
    expectations: &[CounterCollectionExpectation],
) -> Result<CounterCollectionOutcome, RuntimeStoreError> {
    if next_ledger.remote_counter_state_count != ledger.remote_counter_state_count
        || next_ledger.remote_counter_state_sealed_bytes != ledger.remote_counter_state_sealed_bytes
        || expectations
            .windows(2)
            .any(|pair| pair[0].scope_token() >= pair[1].scope_token())
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let mut authenticated = Vec::new();
    authenticated
        .try_reserve_exact(expectations.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for expectation in expectations.iter().copied() {
        validate_identity(expectation.scope_token(), expectation.key_id())?;
        let row = load_optional_record(
            transaction,
            key_bundle,
            database_id,
            expectation.scope_token(),
        )?;
        match (expectation, row.as_ref()) {
            (CounterCollectionExpectation::Ordinary { key_id, .. }, Some(row))
                if row.record.key_id == key_id
                    && matches!(
                        row.record.kind,
                        RemoteCounterRecordKind::Gap | RemoteCounterRecordKind::Frozen
                    ) => {}
            (CounterCollectionExpectation::Ordinary { .. }, None) => {}
            (
                CounterCollectionExpectation::Recovered {
                    key_id,
                    operation_id,
                    ..
                },
                Some(row),
            ) if row.record.key_id == key_id
                && row.record.kind == RemoteCounterRecordKind::Recovered
                && row
                    .state
                    .recovery
                    .is_some_and(|binding| binding.operation_id == operation_id) => {}
            // Retired/RecoveryStaged 永不因时间经过而变成 GC authority；普通
            // transition 也不能消费一个属于 CounterRecovery 的 Recovered lineage。
            _ => return Err(RuntimeStoreError::InvalidStateTransition),
        }
        authenticated.push(row);
    }

    let mut outcome = CounterCollectionOutcome::default();
    for row in authenticated.into_iter().flatten() {
        let deleted = transaction.execute(
            "DELETE FROM remote_counter_states
             WHERE scope_token = ?1 AND database_id = ?2
               AND metadata_token = ?3 AND sealed_state_bytes = ?4",
            params![
                &row.record.scope_token[..],
                &database_id[..],
                &row.metadata_token[..],
                i64::try_from(row.sealed_bytes)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            ],
        )?;
        if deleted != 1 {
            return Err(RuntimeStoreError::SchemaInspectionRaced);
        }
        outcome.rows_deleted = outcome
            .rows_deleted
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        outcome.sealed_bytes_deleted = outcome
            .sealed_bytes_deleted
            .checked_add(row.sealed_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    next_ledger.remote_counter_state_count = next_ledger
        .remote_counter_state_count
        .checked_sub(outcome.rows_deleted)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.remote_counter_state_sealed_bytes = next_ledger
        .remote_counter_state_sealed_bytes
        .checked_sub(outcome.sealed_bytes_deleted)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(outcome)
}

/// read-only candidate 阶段使用的 exact row readiness。`Retired` 与
/// `RecoveryStaged` 只返回 blocked，确保 caller 尚未取得 DB finalize authority 时绝不
/// 先删 Keychain guard；身份/lineage 漂移仍 fail-close 为错误。
pub(super) fn collection_expectations_are_ready(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    expectations: &[CounterCollectionExpectation],
) -> Result<bool, RuntimeStoreError> {
    if expectations
        .windows(2)
        .any(|pair| pair[0].scope_token() >= pair[1].scope_token())
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    for expectation in expectations.iter().copied() {
        validate_identity(expectation.scope_token(), expectation.key_id())?;
        let row = load_optional_record(
            connection,
            key_bundle,
            database_id,
            expectation.scope_token(),
        )?;
        match (expectation, row.as_ref()) {
            (CounterCollectionExpectation::Ordinary { key_id, .. }, Some(row))
                if row.record.key_id == key_id
                    && matches!(
                        row.record.kind,
                        RemoteCounterRecordKind::Gap | RemoteCounterRecordKind::Frozen
                    ) => {}
            (CounterCollectionExpectation::Ordinary { .. }, None) => {}
            (CounterCollectionExpectation::Ordinary { key_id, .. }, Some(row))
                if row.record.key_id == key_id
                    && matches!(
                        row.record.kind,
                        RemoteCounterRecordKind::Retired | RemoteCounterRecordKind::RecoveryStaged
                    ) =>
            {
                return Ok(false);
            }
            (
                CounterCollectionExpectation::Recovered {
                    key_id,
                    operation_id,
                    ..
                },
                Some(row),
            ) if row.record.key_id == key_id
                && row.record.kind == RemoteCounterRecordKind::Recovered
                && row
                    .state
                    .recovery
                    .is_some_and(|binding| binding.operation_id == operation_id) => {}
            (CounterCollectionExpectation::Recovered { key_id, .. }, Some(row))
                if row.record.key_id == key_id
                    && matches!(
                        row.record.kind,
                        RemoteCounterRecordKind::Retired | RemoteCounterRecordKind::RecoveryStaged
                    ) =>
            {
                return Ok(false);
            }
            (CounterCollectionExpectation::Recovered { .. }, None) => return Ok(false),
            _ => return Err(RuntimeStoreError::InvalidStateTransition),
        }
    }
    Ok(true)
}

/// CounterRecovery transition 的旧 scope/key identity 只能来自 authenticated
/// retirement lineage；transition 自身不重复保存这份 counter binding。
pub(super) fn counter_recovery_collection_expectation(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    operation_id: [u8; 16],
) -> Result<Option<CounterCollectionExpectation>, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    let mut found = None;
    for row in load_retirement_rows(connection, key_bundle, database_id)? {
        let Some(binding) = row.state.recovery else {
            continue;
        };
        if binding.operation_id != operation_id {
            continue;
        }
        if found.is_some() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if row.record.scope_token != binding.retired_scope_token
            || row.record.key_id != binding.retired_key_id
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if row.record.kind == RemoteCounterRecordKind::Recovered {
            found = Some(CounterCollectionExpectation::Recovered {
                scope_token: row.record.scope_token,
                key_id: row.record.key_id,
                operation_id,
            });
        } else if row.record.kind == RemoteCounterRecordKind::RecoveryStaged {
            return Ok(None);
        } else {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Ok(found)
}

fn load_expected(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    key_id: KeyId,
    expected_reserved_end: u64,
    expected_anchor: [u8; 32],
) -> Result<Option<AuthenticatedCounterRow>, RuntimeStoreError> {
    let current = load_exact(
        connection,
        key_bundle,
        database_id,
        scope_token,
        key_id,
        expected_reserved_end,
        expected_anchor,
    )?;
    if current
        .as_ref()
        .is_some_and(|row| row.record.kind.is_retirement_lineage())
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(current)
}

fn load_exact(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    key_id: KeyId,
    expected_reserved_end: u64,
    expected_anchor: [u8; 32],
) -> Result<Option<AuthenticatedCounterRow>, RuntimeStoreError> {
    let current = load_optional_record(connection, key_bundle, database_id, scope_token)?;
    match &current {
        Some(row)
            if row.record.key_id == key_id
                && row.record.reserved_end == expected_reserved_end
                && row.record.db_anchor == expected_anchor =>
        {
            Ok(current)
        }
        None if expected_reserved_end == 0
            && expected_anchor == genesis_anchor(key_bundle, database_id, scope_token, key_id)? =>
        {
            Ok(None)
        }
        _ => Err(RuntimeStoreError::PublicationMismatch),
    }
}

fn persist_state(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: Option<&AuthenticatedCounterRow>,
    state: &CounterState,
    ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let encoded = state.encode()?;
    let sealed = seal_state(
        key_bundle,
        database_id,
        state.record.scope_token,
        encoded.as_ref(),
    )?;
    let sealed_bytes =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let purpose = purpose_text(state.record.key_id.purpose);
    let lifecycle = lifecycle_text(state.record.kind);
    let metadata_token = super::remote_replay::counter_metadata_token(
        key_bundle,
        database_id,
        state.record.scope_token,
        purpose,
        state.record.key_id.epoch,
        state.record.reserved_end,
        state.record.reservation_id,
        state.record.db_anchor,
        lifecycle,
        &sealed,
    )?;
    let changed = match previous {
        None => transaction.execute(
            "INSERT INTO remote_counter_states (
                 scope_token, database_id, purpose, key_epoch, reserved_end,
                 reservation_id, db_anchor, lifecycle, sealed_state,
                 sealed_state_bytes, metadata_token
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                &state.record.scope_token[..],
                &database_id[..],
                purpose,
                super::sequence::encode_sequence(state.record.key_id.epoch),
                super::sequence::encode_sequence(state.record.reserved_end),
                state
                    .record
                    .reservation_id
                    .as_ref()
                    .map(<[u8; 16]>::as_slice),
                &state.record.db_anchor[..],
                lifecycle,
                &sealed,
                i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                &metadata_token[..],
            ],
        )?,
        Some(previous) => transaction.execute(
            "UPDATE remote_counter_states
             SET purpose = ?1, key_epoch = ?2, reserved_end = ?3,
                 reservation_id = ?4, db_anchor = ?5, lifecycle = ?6,
                 sealed_state = ?7, sealed_state_bytes = ?8, metadata_token = ?9
             WHERE scope_token = ?10 AND metadata_token = ?11",
            params![
                purpose,
                super::sequence::encode_sequence(state.record.key_id.epoch),
                super::sequence::encode_sequence(state.record.reserved_end),
                state
                    .record
                    .reservation_id
                    .as_ref()
                    .map(<[u8; 16]>::as_slice),
                &state.record.db_anchor[..],
                lifecycle,
                &sealed,
                i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                &metadata_token[..],
                &state.record.scope_token[..],
                &previous.metadata_token[..],
            ],
        )?,
    };
    if changed != 1 {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    match previous {
        None => {
            ledger.remote_counter_state_count = ledger
                .remote_counter_state_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        Some(previous) => {
            ledger.remote_counter_state_sealed_bytes = ledger
                .remote_counter_state_sealed_bytes
                .checked_sub(previous.sealed_bytes)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
    }
    ledger.remote_counter_state_sealed_bytes = ledger
        .remote_counter_state_sealed_bytes
        .checked_add(sealed_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if ledger.remote_counter_state_count > MAX_COUNTER_STATES
        || ledger.remote_counter_state_sealed_bytes > MAX_COUNTER_SEALED_BYTES
    {
        return Err(RuntimeStoreError::StoreFull {
            projected_footprint_bytes: ledger.remote_counter_state_sealed_bytes,
            hard_limit_bytes: MAX_COUNTER_SEALED_BYTES,
        });
    }
    Ok(())
}

fn load_optional_record(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
) -> Result<Option<AuthenticatedCounterRow>, RuntimeStoreError> {
    let raw: Option<RawCounterRow> = connection
        .query_row(
            "SELECT scope_token, database_id, purpose, key_epoch, reserved_end,
                    reservation_id, db_anchor, lifecycle, sealed_state,
                    sealed_state_bytes, metadata_token
             FROM remote_counter_states WHERE scope_token = ?1",
            [&scope_token[..]],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| authenticate_raw(key_bundle, database_id, raw))
        .transpose()
}

fn load_retirement_rows(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedCounterRow>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT scope_token, database_id, purpose, key_epoch, reserved_end,
                reservation_id, db_anchor, lifecycle, sealed_state,
                sealed_state_bytes, metadata_token
         FROM remote_counter_states
         WHERE lifecycle = 'retired'
         ORDER BY purpose, key_epoch, scope_token",
    )?;
    let mut rows = statement.query([])?;
    let mut authenticated = Vec::new();
    while let Some(row) = rows.next()? {
        let raw: RawCounterRow = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
        );
        authenticated.push(authenticate_raw(key_bundle, database_id, raw)?);
    }
    Ok(authenticated)
}

fn find_counter_recovery_by_operation(
    state: &RuntimeSqlite,
    operation_id: [u8; 16],
) -> Result<Option<AuthenticatedCounterRow>, RuntimeStoreError> {
    let mut found = None;
    for row in load_retirement_rows(&state.connection, &state.key_bundle, state.database_id)? {
        if row
            .state
            .recovery
            .is_some_and(|binding| binding.operation_id == operation_id)
            && found.replace(row).is_some()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Ok(found)
}

fn authenticate_raw(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawCounterRow,
) -> Result<AuthenticatedCounterRow, RuntimeStoreError> {
    let scope_token = fixed(raw.0)?;
    let database_id: [u8; 16] = fixed(raw.1)?;
    let key_id = KeyId {
        purpose: parse_purpose(&raw.2)?,
        epoch: canonical_sequence(&raw.3, false)?,
    };
    let reserved_end = canonical_sequence(&raw.4, true)?;
    let reservation_id = raw.5.map(fixed).transpose()?;
    let db_anchor = fixed(raw.6)?;
    let sealed_bytes =
        u64::try_from(raw.9).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let metadata_token = fixed(raw.10)?;
    if database_id != expected_database_id
        || sealed_bytes != u64::try_from(raw.8.len()).unwrap_or(u64::MAX)
        || metadata_token
            != super::remote_replay::counter_metadata_token(
                key_bundle,
                database_id,
                scope_token,
                &raw.2,
                key_id.epoch,
                reserved_end,
                reservation_id,
                db_anchor,
                &raw.7,
                &raw.8,
            )?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open_state(key_bundle, database_id, scope_token, &raw.8)?;
    let state = CounterState::decode(plaintext.expose_secret())?;
    if state.record.scope_token != scope_token
        || state.record.key_id != key_id
        || state.record.reserved_end != reserved_end
        || state.record.reservation_id != reservation_id
        || state.record.db_anchor != db_anchor
        || lifecycle_text(state.record.kind) != raw.7
        || derive_anchor(key_bundle, database_id, &state)? != db_anchor
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedCounterRow {
        record: state.record,
        state,
        sealed_bytes,
        metadata_token,
    })
}
