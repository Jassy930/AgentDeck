//! `DeviceReplyTx` 的 authenticated Store lookup 与 transaction-bound seal。
//!
//! reply key 只在 blocking worker 的 `BEGIN IMMEDIATE` 内解开，并被封装进一次性 axes；
//! manager/link 永远拿不到 raw key。counter Gap、Runtime ledger 与 seal closure 在同一事务
//! 线性化，closure 失败会回滚 DB，而已经 durable 的 CounterGuard Pending 迫使恢复跳号。

use agentdeck_crypto::{AeadSendingKey, SenderCounter, derive_nonce_prefix, seal_symmetric};
use agentdeck_protocol::e2ee::{
    KeyId, KeyPurpose, OuterContextV1, SealedPayloadKind, SignedSealedBlobV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::{DeviceRouteId, MachineRouteId, RequestRouteId};
use rusqlite::TransactionBehavior;

use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};

use super::key_transition::{
    TransitionSnapshotPermit, validate_transition_snapshot_permit_in_transaction,
};
use super::pairing_authorization::{
    RemoteReplyAuthorization, remote_reply_authorization_from_authenticated,
};
use super::remote_counter::{
    RemoteCounterGapRequest, RemoteCounterRecord, record_gap_in_transaction,
};
use super::sqlite::RuntimeSqlite;

pub(crate) trait TransactionDirectedReplySealer: Send {
    fn seal_once(
        self: Box<Self>,
        axes: TransactionDirectedReplyAxes,
    ) -> Result<SignedSealedBlobV1, RuntimeStoreError>;
}

impl<F> TransactionDirectedReplySealer for F
where
    F: FnOnce(TransactionDirectedReplyAxes) -> Result<SignedSealedBlobV1, RuntimeStoreError>
        + Send
        + 'static,
{
    fn seal_once(
        self: Box<Self>,
        axes: TransactionDirectedReplyAxes,
    ) -> Result<SignedSealedBlobV1, RuntimeStoreError> {
        (*self)(axes)
    }
}

pub(crate) struct DirectedReplyTransactionRequest {
    pub authorization: RemoteReplyAuthorization,
    pub authorization_policy: DirectedReplyAuthorizationPolicy,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub request_route: RequestRouteId,
    pub counter: RemoteCounterGapRequest,
    pub sealer_retained_bytes: usize,
    pub sealer: Box<dyn TransactionDirectedReplySealer>,
}

pub(crate) struct DirectedReplyTransactionOutcome {
    pub authorization_used: RemoteReplyAuthorization,
    pub sealed: SignedSealedBlobV1,
    pub counter: RemoteCounterRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DirectedReplyAuthorizationPolicy {
    /// 普通 Runtime reply 可以在业务重新开放后，沿同一 authorization lineage
    /// 单调刷新到 Store 当前 revision。
    BusinessSameLineageCurrent,
    /// KeySync/DirectoryCurrent payload 自身绑定 exact revision，禁止静默刷新。
    KeyControlExact,
    /// Active Add 的 snapshot/SyncComplete 只能消费 Store-issued capability；该
    /// capability 必须在 counter/reply-key 所在事务内重新绑定到 exact transition。
    TransitionSnapshotExact(Box<TransitionSnapshotPermit>),
    /// SubscriptionBarrier 捕获的 publication row/cut/shared-key identity 必须在
    /// counter/reply-key 所在事务内保持 exact；任何 publish advance/rotation/rekey
    /// 都拒绝迟到 binding。
    StreamBindingExact(Box<super::publication::StreamBindingPermit>),
}

pub(crate) struct TransactionDirectedReplyAxes {
    context: OuterContextV1,
    sending_key: AeadSendingKey,
    sender_counter: u64,
    key_directory_revision: u64,
}

impl TransactionDirectedReplyAxes {
    pub(crate) const fn key_directory_revision(&self) -> u64 {
        self.key_directory_revision
    }

    /// 唯一消费 reply key 的入口；返回 unsigned blob + exact AAD context 供窄
    /// MachineData authority 签名，不提供 key getter。
    pub(crate) fn seal(
        self,
        payload_kind: SealedPayloadKind,
        plaintext: &[u8],
    ) -> Result<(UnsignedSealedBlobV1, OuterContextV1), RuntimeStoreError> {
        let unsigned = seal_symmetric(
            &self.sending_key,
            &self.context,
            payload_kind,
            plaintext,
            SenderCounter(self.sender_counter),
        )
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
        Ok((unsigned, self.context))
    }
}

pub(super) fn seal_transaction(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    machine_trust_domain: [u8; 32],
    request: DirectedReplyTransactionRequest,
) -> Result<DirectedReplyTransactionOutcome, RuntimeStoreError> {
    validate_request(machine_trust_domain, &request)?;
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
    let directory = super::pairing::load_directory(&transaction, &key_bundle, database_id)?;
    let active_machine = super::pairing::active_machine(&transaction, &key_bundle, database_id)?;
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|row| {
            row.device_route == request.device_route
                && row.grant_serial == request.authorization.grant_serial()
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let global = directory
        .grants
        .global
        .as_ref()
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let reply_key = global
        .state
        .device_transport_key(request.device_route, KeyPurpose::DeviceReplyTx)?;
    let authorization_used = remote_reply_authorization_from_authenticated(
        database_id,
        machine_trust_domain,
        active_machine.as_ref(),
        authorization,
        global,
    )?;
    let authorization_allowed = match &request.authorization_policy {
        DirectedReplyAuthorizationPolicy::BusinessSameLineageCurrent => {
            super::key_transition::ensure_business_revision_refresh_ready(
                &transaction,
                &key_bundle,
                database_id,
                request.authorization.key_directory_revision().value(),
                authorization_used.key_directory_revision().value(),
            )?;
            authorization_used.is_same_lineage_at_or_after(&request.authorization)
        }
        DirectedReplyAuthorizationPolicy::KeyControlExact => {
            authorization_used == request.authorization
        }
        DirectedReplyAuthorizationPolicy::TransitionSnapshotExact(permit) => {
            if authorization_used != request.authorization {
                false
            } else {
                validate_transition_snapshot_permit_in_transaction(
                    &transaction,
                    &key_bundle,
                    database_id,
                    permit,
                    &authorization_used,
                )?;
                true
            }
        }
        DirectedReplyAuthorizationPolicy::StreamBindingExact(permit) => {
            if authorization_used != request.authorization
                || permit.key_directory_revision()
                    != authorization_used.key_directory_revision().value()
            {
                false
            } else {
                super::publication::validate_stream_binding_permit_in_transaction(
                    &transaction,
                    &key_bundle,
                    database_id,
                    permit,
                )?;
                true
            }
        }
    };
    if !authorization_allowed
        || authorization_used.machine_route() != request.machine_route
        || authorization_used.device_route() != request.device_route
        || reply_key.epoch != authorization_used.reply_key_epoch()
    {
        return Err(RuntimeStoreError::PairingConflict);
    }

    let ledger = directory.ledger;
    let mut next = ledger.clone();
    // 先在当前未提交事务中固定 Gap；closure 失败会回滚，而 Keychain Pending 已迫使跳号。
    let counter = record_gap_in_transaction(
        &transaction,
        &key_bundle,
        database_id,
        request.counter,
        &mut next,
    )?;
    let context = OuterContextV1::directed_reply(
        request.machine_route,
        request.device_route,
        request.request_route,
        reply_key.epoch,
    );
    let expected_nonce_prefix = derive_nonce_prefix(&reply_key.key);
    let axes = TransactionDirectedReplyAxes {
        context,
        sending_key: AeadSendingKey::with_derived_nonce_prefix(
            request.counter.key_id,
            reply_key.epoch,
            global.revision,
            reply_key.key,
        ),
        sender_counter: request.counter.expected_reserved_end,
        key_directory_revision: authorization_used.key_directory_revision().value(),
    };
    let expected_key_id = request.counter.key_id;
    let expected_counter = request.counter.expected_reserved_end;
    let expected_key_epoch = authorization_used.reply_key_epoch();
    let expected_revision = authorization_used.key_directory_revision().value();
    let sealed = request.sealer.seal_once(axes)?;
    validate_sealed(
        &sealed,
        expected_key_id,
        expected_counter,
        expected_key_epoch,
        expected_revision,
        expected_nonce_prefix,
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
    Ok(DirectedReplyTransactionOutcome {
        authorization_used,
        sealed,
        counter,
    })
}

fn validate_request(
    machine_trust_domain: [u8; 32],
    request: &DirectedReplyTransactionRequest,
) -> Result<(), RuntimeStoreError> {
    let authorization = &request.authorization;
    if machine_trust_domain == [0; 32]
        || authorization.machine_trust_domain() != machine_trust_domain
        || authorization.machine_route() != request.machine_route
        || authorization.device_route() != request.device_route
        || request.request_route.as_bytes() == &[0; 16]
        || authorization.reply_key_epoch() == 0
        || authorization.key_directory_revision().value() == 0
        || request.counter.key_id
            != (KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: authorization.reply_key_epoch(),
            })
        || request.counter.expected_reserved_end >= request.counter.abandoned_through
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

fn validate_sealed(
    sealed: &SignedSealedBlobV1,
    expected_key_id: KeyId,
    expected_counter: u64,
    expected_key_epoch: u64,
    expected_revision: u64,
    expected_nonce_prefix: [u8; 4],
) -> Result<(), RuntimeStoreError> {
    let expected_counter = expected_counter.to_be_bytes();
    if sealed.inner.key_id != expected_key_id
        || sealed.inner.key_epoch != expected_key_epoch
        || sealed.inner.key_directory_revision != expected_revision
        || sealed.inner.nonce[..4] != expected_nonce_prefix
        || sealed.inner.nonce[4..] != expected_counter
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}
