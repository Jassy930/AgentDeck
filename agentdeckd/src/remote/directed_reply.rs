//! `DeviceReplyTx` 的 transaction-bound directed reply sealer。
//!
//! 每次 reply 都先 durable reserve CounterGuard，再由 Runtime Store 在同一
//! `BEGIN IMMEDIATE` 内认证 exact Active authorization/key directory、暂存整块 Gap、
//! AEAD seal 并调用 Weak MachineData authority 签名。directed reply 没有 shared outbox；
//! 任一失败只允许跳号，绝不返回未 durable-accounted blob。

use std::{mem::size_of, sync::Arc};

use agentdeck_crypto::HpkePublicKey;
use agentdeck_protocol::e2ee::{
    DeviceKeyRecoveryReplyV1, DirectoryCurrentV1, KeyControlV1, KeyId, KeyPurpose, KeyUpdateSetV1,
    OuterContextV1, SealedPayloadKind, SignedSealedBlobV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::KeyDirectoryRevision;
use agentdeck_protocol::runtime::{
    MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeInnerCursor,
    RuntimeMessage, RuntimeReply, RuntimeTransferCarrierV1, RuntimeTransferChannel,
    SubscriptionReceipt,
};
use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::runtime::store::directed_reply::{
    DirectedReplyAuthorizationPolicy, DirectedReplyTransactionRequest, TransactionDirectedReplyAxes,
};
use crate::runtime::store::key_transition::{KeyTransitionStreamScope, TransitionSnapshotPermit};
use crate::runtime::store::remote_counter::{
    RemoteCounterGapRequest, RemoteCounterRecord, RemoteCounterRecordKind,
    RemoteCounterRetirementRequest,
};
use crate::runtime::store::{RemoteReplyAuthorization, RuntimeStoreError, RuntimeStoreHandle};
use crate::security::KeyStore;
#[cfg(test)]
use crate::security::MemoryKeyStore;

use super::counter::{
    COUNTER_BLOCK_SIZE, CounterDbState, CounterError, CounterGuardBackend, CounterGuardCas,
    CounterGuardPhase, CounterGuardState, CounterRecovery, CounterScope,
    reconcile_counter_recovery,
};
use super::identity::KeyStoreCounterGuardBackend;
use super::link::{DirectedReplyRoute, DirectedReplySeal, DirectedReplySealer, RemoteLinkError};
use super::transport::{DeviceKeyRecoverySealRequest, MachineDataAuthority};

pub(super) trait DirectedDataAuthority: Send + Sync {
    fn sign_sealed(
        &self,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, ()>;

    fn seal_device_key_recovery_reply(
        &self,
        _request: DeviceKeyRecoverySealRequest<'_>,
    ) -> Result<DeviceKeyRecoveryReplyV1, ()> {
        Err(())
    }
}

impl DirectedDataAuthority for MachineDataAuthority {
    fn sign_sealed(
        &self,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, ()> {
        MachineDataAuthority::sign_sealed(self, unsigned, context).map_err(|_| ())
    }

    fn seal_device_key_recovery_reply(
        &self,
        request: DeviceKeyRecoverySealRequest<'_>,
    ) -> Result<DeviceKeyRecoveryReplyV1, ()> {
        MachineDataAuthority::seal_device_key_recovery_reply(self, request).map_err(|_| ())
    }
}

pub(crate) struct DeviceReplyTxSealer {
    store: RuntimeStoreHandle,
    key_store: Arc<dyn KeyStore>,
    authority: Arc<dyn DirectedDataAuthority>,
    serial: Mutex<()>,
}

enum DirectedReplyPayload {
    Runtime(Arc<[u8]>),
    Prepared {
        kind: SealedPayloadKind,
        plaintext: Arc<[u8]>,
    },
}

impl DirectedReplyPayload {
    fn resolve(
        self,
        key_directory_revision: u64,
    ) -> Result<(SealedPayloadKind, Arc<[u8]>), DirectedReplySealError> {
        match self {
            Self::Runtime(bytes) => directed_payload(bytes, Some(key_directory_revision)),
            Self::Prepared { kind, plaintext } => Ok((kind, plaintext)),
        }
    }
}

impl DeviceReplyTxSealer {
    #[must_use]
    pub(crate) fn new(
        store: RuntimeStoreHandle,
        key_store: Arc<dyn KeyStore>,
        authority: MachineDataAuthority,
    ) -> Self {
        Self::with_authority(store, key_store, Arc::new(authority))
    }

    fn with_authority(
        store: RuntimeStoreHandle,
        key_store: Arc<dyn KeyStore>,
        authority: Arc<dyn DirectedDataAuthority>,
    ) -> Self {
        Self {
            store,
            key_store,
            authority,
            serial: Mutex::new(()),
        }
    }

    async fn seal_internal(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        authorization_policy: DirectedReplyAuthorizationPolicy,
        payload: DirectedReplyPayload,
        retained_bytes: usize,
    ) -> Result<DirectedReplySeal, DirectedReplySealError> {
        if route.machine_route != authorization.machine_route()
            || route.device_route != authorization.device_route()
        {
            return Err(DirectedReplySealError::AuthorizationMismatch);
        }
        self.precheck_current_authorization(authorization, &authorization_policy)
            .await?;
        let _serial = self.serial.lock().await;
        let key_id = KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: authorization.reply_key_epoch(),
        };
        let scope = CounterScope::directed_reply_for_trust_epoch(
            authorization.machine_trust_domain(),
            authorization.machine_route(),
            authorization.trust_epoch(),
            authorization.device_route(),
            authorization.grant_serial(),
            authorization.reply_key_epoch(),
        )?;
        if !self
            .store
            .remote_counter_scope_allowed(scope.token())
            .await?
        {
            return Err(DirectedReplySealError::RetireKey);
        }
        self.store
            .register_remote_counter_guard_scope(scope.token())
            .await?;
        let backend = KeyStoreCounterGuardBackend::new(self.key_store.as_ref());
        let mut guard = backend
            .load_guard(&scope)
            .map_err(|_| DirectedReplySealError::GuardUnavailable)?;
        if guard.is_some() {
            self.store
                .mark_remote_counter_guard_scope_materialized(scope.token())
                .await?;
        }
        let mut database = self
            .store
            .load_remote_counter_record(scope.token(), key_id)
            .await?;
        if database.kind.is_retirement_lineage() {
            return Err(DirectedReplySealError::RetireKey);
        }
        reconcile_pending(
            &self.store,
            &backend,
            scope,
            key_id,
            &mut guard,
            &mut database,
        )
        .await?;
        if let Err(error) = validate_stable_head(guard, &database) {
            retire_counter(&self.store, scope, key_id, guard, &database).await?;
            return Err(error);
        }

        let previous_end = database.reserved_end;
        let Some(reserved_end) = previous_end.checked_add(COUNTER_BLOCK_SIZE) else {
            retire_counter(&self.store, scope, key_id, guard, &database).await?;
            return Err(DirectedReplySealError::RetireKey);
        };
        let reservation_id = random_id()?;
        let operation_id = random_id()?;
        let pending = CounterGuardState::pending(
            scope.token(),
            previous_end,
            reserved_end,
            reservation_id,
            operation_id,
            database.db_anchor,
        )?;
        swap_guard(&backend, scope, guard, pending)?;
        self.store
            .mark_remote_counter_guard_scope_materialized(scope.token())
            .await?;

        let authority = self.authority.clone();
        let outcome_result = self
            .store
            .seal_directed_reply_transaction(DirectedReplyTransactionRequest {
                authorization: authorization.clone(),
                authorization_policy,
                machine_route: route.machine_route,
                device_route: route.device_route,
                request_route: route.request_route,
                counter: RemoteCounterGapRequest {
                    scope_token: scope.token(),
                    key_id,
                    expected_reserved_end: previous_end,
                    expected_db_anchor: database.db_anchor,
                    abandoned_through: reserved_end,
                    reservation_id,
                    publication_id: operation_id,
                },
                sealer_retained_bytes: retained_bytes,
                sealer: Box::new(move |axes: TransactionDirectedReplyAxes| {
                    let (payload_kind, plaintext) = payload
                        .resolve(axes.key_directory_revision())
                        .map_err(|_| RuntimeStoreError::PairingConflict)?;
                    let (unsigned, context) = axes.seal(payload_kind, &plaintext)?;
                    authority
                        .sign_sealed(unsigned, &context)
                        .map_err(|_| RuntimeStoreError::PairingConflict)
                }),
            })
            .await;
        let outcome = match outcome_result {
            Ok(outcome) => outcome,
            Err(RuntimeStoreError::InvalidStateTransition)
                if !self
                    .store
                    .remote_counter_scope_allowed(scope.token())
                    .await? =>
            {
                return Err(DirectedReplySealError::RetireKey);
            }
            Err(error) => return Err(error.into()),
        };
        let stable =
            CounterGuardState::stable(scope.token(), reserved_end, outcome.counter.db_anchor)?;
        swap_guard(&backend, scope, Some(pending), stable)?;
        Ok(DirectedReplySeal {
            authorization_used: outcome.authorization_used,
            sealed: outcome.sealed,
        })
    }

    /// 无副作用的快速拒绝：已撤销 authorization 不能先落 CounterGuard manifest。
    /// 这不是授权线性化点；真正的 current auth、transition、reply key 与 counter Gap
    /// 仍由后续 `BEGIN IMMEDIATE` 一次复核。
    async fn precheck_current_authorization(
        &self,
        authorization: &RemoteReplyAuthorization,
        policy: &DirectedReplyAuthorizationPolicy,
    ) -> Result<(), DirectedReplySealError> {
        let current = self
            .store
            .load_active_remote_ingress(authorization.machine_route(), authorization.device_route())
            .await?
            .remote_reply_authorization();
        let allowed = match policy {
            DirectedReplyAuthorizationPolicy::BusinessSameLineageCurrent => {
                current.is_same_lineage_at_or_after(authorization)
            }
            DirectedReplyAuthorizationPolicy::KeyControlExact => current == *authorization,
            DirectedReplyAuthorizationPolicy::TransitionSnapshotExact(permit) => {
                current == *authorization
                    && validate_transition_snapshot_binding(&current, permit).is_ok()
            }
        };
        if !allowed {
            return Err(RuntimeStoreError::PairingConflict.into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn with_authority_for_test(
        store: RuntimeStoreHandle,
        key_store: Arc<MemoryKeyStore>,
        authority: Arc<dyn DirectedDataAuthority>,
    ) -> Self {
        Self::with_authority(store, key_store, authority)
    }
}

#[async_trait]
impl DirectedReplySealer for DeviceReplyTxSealer {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn seal_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        directed_payload(runtime_bytes.clone(), None).map_err(map_seal_error)?;
        let retained_bytes = runtime_bytes.len();
        self.seal_internal(
            authorization,
            route,
            DirectedReplyAuthorizationPolicy::BusinessSameLineageCurrent,
            DirectedReplyPayload::Runtime(runtime_bytes),
            retained_bytes,
        )
        .await
        .map_err(map_seal_error)
    }

    async fn seal_transfer_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        if carrier.channel != RuntimeTransferChannel::Reply {
            return Err(RemoteLinkError::InvalidCoreEgress);
        }
        let plaintext: Arc<[u8]> = carrier
            .encode()
            .map_err(|_| RemoteLinkError::InvalidCoreEgress)?
            .into();
        let retained_bytes = plaintext.len();
        self.seal_internal(
            authorization,
            route,
            DirectedReplyAuthorizationPolicy::BusinessSameLineageCurrent,
            DirectedReplyPayload::Prepared {
                kind: SealedPayloadKind::TransferPart,
                plaintext,
            },
            retained_bytes,
        )
        .await
        .map_err(map_seal_error)
    }

    async fn seal_transition_snapshot_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        permit: &TransitionSnapshotPermit,
        runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        validate_transition_snapshot_binding(authorization, permit).map_err(map_seal_error)?;
        validate_transition_snapshot_runtime(&runtime_bytes, permit).map_err(map_seal_error)?;
        let retained_bytes = transition_sealer_retained_bytes(runtime_bytes.len())?;
        self.seal_internal(
            authorization,
            route,
            DirectedReplyAuthorizationPolicy::TransitionSnapshotExact(Box::new(permit.clone())),
            DirectedReplyPayload::Runtime(runtime_bytes),
            retained_bytes,
        )
        .await
        .map_err(map_seal_error)
    }

    async fn seal_transition_snapshot_transfer_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        permit: &TransitionSnapshotPermit,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        validate_transition_snapshot_binding(authorization, permit).map_err(map_seal_error)?;
        if carrier.channel != RuntimeTransferChannel::Reply {
            return Err(RemoteLinkError::InvalidCoreEgress);
        }
        let plaintext: Arc<[u8]> = carrier
            .encode()
            .map_err(|_| RemoteLinkError::InvalidCoreEgress)?
            .into();
        let retained_bytes = transition_sealer_retained_bytes(plaintext.len())?;
        self.seal_internal(
            authorization,
            route,
            DirectedReplyAuthorizationPolicy::TransitionSnapshotExact(Box::new(permit.clone())),
            DirectedReplyPayload::Prepared {
                kind: SealedPayloadKind::TransferPart,
                plaintext,
            },
            retained_bytes,
        )
        .await
        .map_err(map_seal_error)
    }

    async fn mark_transition_snapshot_flushed(
        &self,
        permit: TransitionSnapshotPermit,
        sync_complete_sha256: [u8; 32],
    ) -> Result<(), RemoteLinkError> {
        let flush = permit
            .into_flush(sync_complete_sha256)
            .map_err(|_| RemoteLinkError::ReplySealUnavailable)?;
        self.store
            .mark_transition_snapshot_flushed(flush)
            .await
            .map(|_| ())
            .map_err(|_| RemoteLinkError::ReplySealUnavailable)
    }

    async fn seal_key_update_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        update_set: KeyUpdateSetV1,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        if update_set.device_route != route.device_route
            || update_set.key_directory_revision != authorization.key_directory_revision()
        {
            return Err(RemoteLinkError::InvalidKeyControlReply);
        }
        let control = KeyControlV1::update_set(update_set);
        let payload_kind = control.sealed_payload_kind();
        let plaintext: Arc<[u8]> = control
            .canonical_bytes()
            .map_err(|_| RemoteLinkError::InvalidKeyControlReply)?
            .into();
        let retained_bytes = plaintext.len();
        self.seal_internal(
            authorization,
            route,
            DirectedReplyAuthorizationPolicy::KeyControlExact,
            DirectedReplyPayload::Prepared {
                kind: payload_kind,
                plaintext,
            },
            retained_bytes,
        )
        .await
        .map(|reply| reply.sealed)
        .map_err(map_seal_error)
    }

    async fn seal_directory_current_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        status: DirectoryCurrentV1,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        if status.machine_route != route.machine_route
            || status.device_route != route.device_route
            || status.grant_serial != authorization.grant_serial()
            || status.root_trust_epoch != authorization.trust_epoch()
            || status.current_key_directory_revision != authorization.key_directory_revision()
        {
            return Err(RemoteLinkError::InvalidKeyControlReply);
        }
        let control = KeyControlV1::directory_current(status);
        let payload_kind = control.sealed_payload_kind();
        let plaintext: Arc<[u8]> = control
            .canonical_bytes()
            .map_err(|_| RemoteLinkError::InvalidKeyControlReply)?
            .into();
        let retained_bytes = plaintext.len();
        self.seal_internal(
            authorization,
            route,
            DirectedReplyAuthorizationPolicy::KeyControlExact,
            DirectedReplyPayload::Prepared {
                kind: payload_kind,
                plaintext,
            },
            retained_bytes,
        )
        .await
        .map(|reply| reply.sealed)
        .map_err(map_seal_error)
    }

    async fn seal_device_key_recovery_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        known_revision: KeyDirectoryRevision,
        update_set: KeyUpdateSetV1,
    ) -> Result<DeviceKeyRecoveryReplyV1, RemoteLinkError> {
        if route.machine_route != authorization.machine_route()
            || route.device_route != authorization.device_route()
            || update_set.device_route != authorization.device_route()
            || update_set.key_directory_revision != authorization.key_directory_revision()
            || known_revision
                .next()
                .map_err(|_| RemoteLinkError::InvalidKeyControlReply)?
                != authorization.key_directory_revision()
        {
            return Err(RemoteLinkError::InvalidKeyControlReply);
        }
        let current = self
            .store
            .load_active_remote_ingress(route.machine_route, route.device_route)
            .await
            .map_err(|_| RemoteLinkError::ReplyAuthorizationMismatch)?;
        if current.remote_reply_authorization() != *authorization {
            return Err(RemoteLinkError::ReplyAuthorizationMismatch);
        }
        self.store
            .check_remote_transition_ingress(
                crate::runtime::store::key_transition::RemoteTransitionIngressClass::KeySync,
            )
            .await
            .map_err(|_| RemoteLinkError::ReplySealUnavailable)?;
        let recipient = HpkePublicKey::from_bytes(&authorization.device_hpke_public_key())
            .map_err(|_| RemoteLinkError::ReplyAuthorizationMismatch)?;
        let reply = self
            .authority
            .seal_device_key_recovery_reply(DeviceKeyRecoverySealRequest {
                recipient: &recipient,
                machine_route: route.machine_route,
                device_route: route.device_route,
                request_route: route.request_route,
                grant_serial: authorization.grant_serial(),
                root_trust_epoch: authorization.trust_epoch(),
                known_revision,
                update_set: &update_set,
            })
            .map_err(|_| RemoteLinkError::ReplySealUnavailable)?;
        let current = self
            .store
            .load_active_remote_ingress(route.machine_route, route.device_route)
            .await
            .map_err(|_| RemoteLinkError::ReplyAuthorizationMismatch)?;
        if current.remote_reply_authorization() != *authorization {
            return Err(RemoteLinkError::ReplyAuthorizationMismatch);
        }
        Ok(reply)
    }
}

fn map_seal_error(error: DirectedReplySealError) -> RemoteLinkError {
    match error {
        DirectedReplySealError::InvalidRuntime => RemoteLinkError::InvalidCoreEgress,
        DirectedReplySealError::AuthorizationMismatch => {
            RemoteLinkError::ReplyAuthorizationMismatch
        }
        DirectedReplySealError::RetireKey => RemoteLinkError::CounterRetired,
        _ => RemoteLinkError::ReplySealUnavailable,
    }
}

fn validate_transition_snapshot_binding(
    authorization: &RemoteReplyAuthorization,
    permit: &TransitionSnapshotPermit,
) -> Result<(), DirectedReplySealError> {
    if permit.recipient().device_route != *authorization.device_route().as_bytes()
        || permit.recipient().grant_serial != authorization.grant_serial().value()
        || permit.authorization_hash() != authorization.authorization_hash()
        || permit.key_directory_revision() != authorization.key_directory_revision().value()
    {
        return Err(DirectedReplySealError::AuthorizationMismatch);
    }
    Ok(())
}

fn transition_sealer_retained_bytes(payload_bytes: usize) -> Result<usize, RemoteLinkError> {
    payload_bytes
        .checked_add(size_of::<TransitionSnapshotPermit>())
        .ok_or(RemoteLinkError::InvalidCoreEgress)
}

fn validate_transition_snapshot_runtime(
    runtime_bytes: &[u8],
    permit: &TransitionSnapshotPermit,
) -> Result<(), DirectedReplySealError> {
    if runtime_bytes.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
        return Err(DirectedReplySealError::InvalidRuntime);
    }
    let envelope: RuntimeEnvelope = serde_json::from_slice(runtime_bytes)
        .map_err(|_| DirectedReplySealError::InvalidRuntime)?;
    if envelope.version != RUNTIME_PROTOCOL_VERSION {
        return Err(DirectedReplySealError::InvalidRuntime);
    }
    match &envelope.body {
        RuntimeMessage::Reply(RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
            stream_generation,
        })) if canonical_uuid_matches(stream_generation.as_str(), permit.generation()) => Ok(()),
        RuntimeMessage::Reply(RuntimeReply::Catalog(snapshot))
            if permit.scope() == KeyTransitionStreamScope::Catalog
                && snapshot.base_catalog_cursor
                    == agentdeck_protocol::runtime::StreamCursor::from_high_water(
                        permit.relay_committed_inner(),
                    ) =>
        {
            Ok(())
        }
        RuntimeMessage::Reply(RuntimeReply::Snapshot(snapshot))
            if matches!(
                permit.scope(),
                KeyTransitionStreamScope::Conversation(expected)
                    if canonical_uuid_matches(snapshot.conversation_id.as_str(), expected)
            ) && snapshot.base_event_cursor
                == agentdeck_protocol::runtime::StreamCursor::from_high_water(
                    permit.relay_committed_inner(),
                ) =>
        {
            Ok(())
        }
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync))
            if transition_sync_complete_matches(sync, permit) =>
        {
            Ok(())
        }
        _ => Err(DirectedReplySealError::InvalidRuntime),
    }
}

fn transition_sync_complete_matches(
    sync: &agentdeck_protocol::runtime::RuntimeSyncComplete,
    permit: &TransitionSnapshotPermit,
) -> bool {
    canonical_uuid_matches(sync.stream_generation.as_str(), permit.generation())
        && sync.stream_cursor.high_water() == permit.relay_committed_outer()
        && sync.key_directory_revision == permit.key_directory_revision()
        && match (&sync.inner_cursor, permit.scope()) {
            (RuntimeInnerCursor::Catalog { cursor }, KeyTransitionStreamScope::Catalog) => {
                cursor.high_water() == permit.relay_committed_inner()
            }
            (
                RuntimeInnerCursor::Conversation {
                    conversation_id,
                    cursor,
                },
                KeyTransitionStreamScope::Conversation(expected),
            ) => {
                canonical_uuid_matches(conversation_id.as_str(), expected)
                    && cursor.high_water() == permit.relay_committed_inner()
            }
            _ => false,
        }
}

fn canonical_uuid_matches(value: &str, expected: [u8; 16]) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
        parsed.as_bytes() == &expected && parsed.hyphenated().to_string() == value
    })
}

async fn reconcile_pending<B: CounterGuardBackend>(
    store: &RuntimeStoreHandle,
    backend: &B,
    scope: CounterScope,
    key_id: KeyId,
    guard: &mut Option<CounterGuardState>,
    database: &mut RemoteCounterRecord,
) -> Result<(), DirectedReplySealError> {
    let Some(pending) = *guard else {
        return Ok(());
    };
    if pending.phase() != CounterGuardPhase::Pending {
        return Ok(());
    }
    if database.kind == RemoteCounterRecordKind::Gap
        && database.reservation_id == pending.reservation_id()
        && database.publication_id == pending.publication_id()
        && database.reserved_end == pending.reserved_through()
    {
        let stable =
            CounterGuardState::stable(scope.token(), database.reserved_end, database.db_anchor)?;
        swap_guard(backend, scope, Some(pending), stable)?;
        *guard = Some(stable);
        return Ok(());
    }
    if !matches!(
        database.kind,
        RemoteCounterRecordKind::Genesis | RemoteCounterRecordKind::Gap
    ) {
        retire_counter(store, scope, key_id, Some(pending), database).await?;
        return Err(DirectedReplySealError::RetireKey);
    }
    let db = CounterDbState::unchanged(scope.token(), database.reserved_end, database.db_anchor)?;
    match reconcile_counter_recovery(&pending, &db)? {
        CounterRecovery::GuardAheadGap { abandoned_through } => {
            let gap_result = store
                .record_remote_counter_gap(RemoteCounterGapRequest {
                    scope_token: scope.token(),
                    key_id,
                    expected_reserved_end: database.reserved_end,
                    expected_db_anchor: database.db_anchor,
                    abandoned_through,
                    reservation_id: pending
                        .reservation_id()
                        .ok_or(DirectedReplySealError::RetireKey)?,
                    publication_id: pending
                        .publication_id()
                        .ok_or(DirectedReplySealError::RetireKey)?,
                })
                .await;
            let gap = match gap_result {
                Ok(gap) => gap,
                Err(RuntimeStoreError::InvalidStateTransition)
                    if !store.remote_counter_scope_allowed(scope.token()).await? =>
                {
                    return Err(DirectedReplySealError::RetireKey);
                }
                Err(error) => return Err(error.into()),
            };
            let stable = CounterGuardState::stable(scope.token(), gap.reserved_end, gap.db_anchor)?;
            swap_guard(backend, scope, Some(pending), stable)?;
            *guard = Some(stable);
            *database = gap;
            Ok(())
        }
        CounterRecovery::ReserveNextBlock { .. } | CounterRecovery::RetryFrozen { .. } => {
            retire_counter(store, scope, key_id, Some(pending), database).await?;
            Err(DirectedReplySealError::RetireKey)
        }
        CounterRecovery::RetireKey => {
            retire_counter(store, scope, key_id, Some(pending), database).await?;
            Err(DirectedReplySealError::RetireKey)
        }
    }
}

async fn retire_counter(
    store: &RuntimeStoreHandle,
    scope: CounterScope,
    key_id: KeyId,
    guard: Option<CounterGuardState>,
    database: &RemoteCounterRecord,
) -> Result<(), DirectedReplySealError> {
    if database.kind.is_retirement_lineage() {
        return Ok(());
    }
    let retired_through = guard
        .filter(|guard| guard.token() == scope.token())
        .map_or(database.reserved_end, |guard| {
            database.reserved_end.max(guard.reserved_through())
        });
    let retired = store
        .retire_remote_counter(RemoteCounterRetirementRequest {
            scope_token: scope.token(),
            key_id,
            expected_reserved_end: database.reserved_end,
            expected_db_anchor: database.db_anchor,
            retired_through,
        })
        .await?;
    if retired.kind != RemoteCounterRecordKind::Retired {
        return Err(DirectedReplySealError::RetireKey);
    }
    Ok(())
}

fn validate_stable_head(
    guard: Option<CounterGuardState>,
    database: &RemoteCounterRecord,
) -> Result<(), DirectedReplySealError> {
    match guard {
        None if database.kind == RemoteCounterRecordKind::Genesis && database.reserved_end == 0 => {
            Ok(())
        }
        Some(guard)
            if guard.phase() == CounterGuardPhase::Stable
                && guard.token() == database.scope_token
                && guard.reserved_through() == database.reserved_end
                && guard.database_anchor() == database.db_anchor
                && matches!(database.kind, RemoteCounterRecordKind::Gap) =>
        {
            Ok(())
        }
        _ => Err(DirectedReplySealError::RetireKey),
    }
}

fn swap_guard<B: CounterGuardBackend>(
    backend: &B,
    scope: CounterScope,
    expected: Option<CounterGuardState>,
    next: CounterGuardState,
) -> Result<(), DirectedReplySealError> {
    match backend
        .compare_and_swap_guard(&scope, expected, next)
        .map_err(|_| DirectedReplySealError::GuardUnavailable)?
    {
        CounterGuardCas::Swapped(persisted) if persisted == next => Ok(()),
        CounterGuardCas::Swapped(_) | CounterGuardCas::Conflict(_) => {
            Err(DirectedReplySealError::GuardConflict)
        }
    }
}

fn random_id() -> Result<[u8; 16], DirectedReplySealError> {
    let mut id = [0_u8; 16];
    getrandom::fill(&mut id).map_err(|_| DirectedReplySealError::EntropyUnavailable)?;
    id[0] |= 0x80;
    Ok(id)
}

#[cfg(test)]
pub(super) fn directed_payload_kind(
    runtime_bytes: &[u8],
) -> Result<SealedPayloadKind, DirectedReplySealError> {
    Ok(directed_payload(Arc::from(runtime_bytes), None)?.0)
}

fn directed_payload(
    runtime_bytes: Arc<[u8]>,
    expected_key_directory_revision: Option<u64>,
) -> Result<(SealedPayloadKind, Arc<[u8]>), DirectedReplySealError> {
    if runtime_bytes.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
        return Err(DirectedReplySealError::InvalidRuntime);
    }
    let envelope: RuntimeEnvelope = serde_json::from_slice(runtime_bytes.as_ref())
        .map_err(|_| DirectedReplySealError::InvalidRuntime)?;
    let RuntimeEnvelope {
        version,
        message_id,
        body,
    } = envelope;
    if version != RUNTIME_PROTOCOL_VERSION {
        return Err(DirectedReplySealError::InvalidRuntime);
    }
    match body {
        RuntimeMessage::Reply(RuntimeReply::Catalog(_)) => {
            Ok((SealedPayloadKind::CatalogSnapshot, runtime_bytes))
        }
        RuntimeMessage::Reply(RuntimeReply::Snapshot(_)) => {
            Ok((SealedPayloadKind::ConversationSnapshot, runtime_bytes))
        }
        RuntimeMessage::Reply(RuntimeReply::Backfill(_)) => {
            Ok((SealedPayloadKind::BackfillChunk, runtime_bytes))
        }
        RuntimeMessage::Reply(RuntimeReply::TransferPart(transfer)) => {
            let carrier =
                RuntimeTransferCarrierV1::new(message_id, RuntimeTransferChannel::Reply, transfer)
                    .encode()
                    .map_err(|_| DirectedReplySealError::InvalidRuntime)?;
            Ok((SealedPayloadKind::TransferPart, Arc::from(carrier)))
        }
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(mut sync)) => {
            let Some(expected) = expected_key_directory_revision else {
                return Ok((SealedPayloadKind::CommandReceipt, runtime_bytes));
            };
            if expected == 0
                || (sync.key_directory_revision != 0 && sync.key_directory_revision != expected)
            {
                return Err(DirectedReplySealError::InvalidRuntime);
            }
            sync.key_directory_revision = expected;
            let normalized = RuntimeEnvelope {
                version,
                message_id,
                body: RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync)),
            }
            .to_json_bytes_checked()
            .map_err(|_| DirectedReplySealError::InvalidRuntime)?;
            Ok((SealedPayloadKind::CommandReceipt, Arc::from(normalized)))
        }
        RuntimeMessage::Reply(_) => Ok((SealedPayloadKind::CommandReceipt, runtime_bytes)),
        RuntimeMessage::Request(_) | RuntimeMessage::Stream(_) => {
            Err(DirectedReplySealError::InvalidRuntime)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum DirectedReplySealError {
    #[error("directed reply Runtime envelope is invalid")]
    InvalidRuntime,
    #[error("directed reply authorization does not match its route")]
    AuthorizationMismatch,
    #[error("directed reply counter state is invalid: {0}")]
    Counter(#[from] CounterError),
    #[error("directed reply Store operation failed: {0}")]
    Store(#[from] RuntimeStoreError),
    #[error("directed reply CounterGuard backend is unavailable")]
    GuardUnavailable,
    #[error("directed reply CounterGuard compare-and-swap conflicted")]
    GuardConflict,
    #[error("directed reply key must be retired")]
    RetireKey,
    #[error("directed reply reservation entropy is unavailable")]
    EntropyUnavailable,
}
