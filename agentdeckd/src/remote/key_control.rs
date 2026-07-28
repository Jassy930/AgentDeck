//! RemoteLink 在 RuntimeCore 前消费的 authenticated key-control 接缝。
//!
//! 本模块不持有 canonical key transition state。DeviceSign/AAD/replay/AEAD 与本机
//! authorization ledger 的完整验证仍由 dispatch 链完成；这里仅携带验证后的 control
//! 与 opaque Current proof，并把业务 fence/控制消费委托给 Store-backed handler。

use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::e2ee::{
    DirectoryCurrentV1, E2EE_FORMAT_VERSION, KeyControlRequestV1, KeyUpdateSetV1,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION, RequestRouteId,
};
use agentdeck_protocol::runtime::{
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeRequest, StreamCursor,
    sync::RuntimeInnerCursor,
};
use async_trait::async_trait;

use crate::runtime::model::{RuntimeClock, SystemRuntimeClock};
use crate::runtime::store::key_transition::{
    AcknowledgeKeyUpdate, AcknowledgeStreamApplied, KeySyncRead, KeyTransitionOperation,
    KeyTransitionPhase, KeyTransitionRecipient, KeyTransitionStreamScope, KeyTransitionTarget,
    KeyUpdateAckResolve, KeyUpdateLifecycle, RemoteTransitionIngressClass, StreamAppliedAckResolve,
    TransitionSnapshotPermit, TransitionSnapshotRequest,
};
use crate::runtime::store::{
    ActiveRemoteIngressProof, CurrentRemoteAuthorizationProof, RemoteReplyAuthorization, RuntimeId,
    RuntimeIdKind, RuntimeStoreError, RuntimeStoreHandle,
};

use super::transition_owner::KeyTransitionRecoveryHandle;

const TRANSITION_SNAPSHOT_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Relay outer 在完整 authenticated admission 后冻结的 exact directed reply 路由。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyControlReplyRoute {
    pub(crate) machine_route: MachineRouteId,
    pub(crate) device_route: DeviceRouteId,
    pub(crate) request_route: RequestRouteId,
}

/// Store-backed KeySync 唯一允许交给 RemoteLink egress 的 typed 结果。
pub(crate) enum KeyControlDirectedPayload {
    DirectoryCurrent(DirectoryCurrentV1),
    UpdateSet(KeyUpdateSetV1),
    DeviceKeyRecovery {
        known_revision: KeyDirectoryRevision,
        update_set: KeyUpdateSetV1,
    },
}

pub(crate) struct KeyControlDirectedReply {
    authorization: RemoteReplyAuthorization,
    route: KeyControlReplyRoute,
    payload: KeyControlDirectedPayload,
}

impl KeyControlDirectedReply {
    #[cfg(test)]
    pub(crate) const fn route(&self) -> KeyControlReplyRoute {
        self.route
    }

    #[cfg(test)]
    pub(crate) const fn update_set(&self) -> Option<&KeyUpdateSetV1> {
        match &self.payload {
            KeyControlDirectedPayload::UpdateSet(update_set)
            | KeyControlDirectedPayload::DeviceKeyRecovery { update_set, .. } => Some(update_set),
            KeyControlDirectedPayload::DirectoryCurrent(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn directory_current(&self) -> Option<&DirectoryCurrentV1> {
        match &self.payload {
            KeyControlDirectedPayload::DirectoryCurrent(status) => Some(status),
            KeyControlDirectedPayload::UpdateSet(_)
            | KeyControlDirectedPayload::DeviceKeyRecovery { .. } => None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn device_key_recovery(
        &self,
    ) -> Option<(KeyDirectoryRevision, &KeyUpdateSetV1)> {
        match &self.payload {
            KeyControlDirectedPayload::DeviceKeyRecovery {
                known_revision,
                update_set,
            } => Some((*known_revision, update_set)),
            KeyControlDirectedPayload::DirectoryCurrent(_)
            | KeyControlDirectedPayload::UpdateSet(_) => None,
        }
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        RemoteReplyAuthorization,
        KeyControlReplyRoute,
        KeyControlDirectedPayload,
    ) {
        (self.authorization, self.route, self.payload)
    }
}

/// authenticated key-control consumer 的 typed pre-Core 结果。
#[allow(
    dead_code,
    reason = "P4.5 manager composition installs the Store-backed KeySync/ACK consumer"
)]
pub(crate) enum KeyControlIngressOutcome {
    Consumed,
    DirectedReply(Box<KeyControlDirectedReply>),
}

/// Store 对单个 authenticated business request 的 typed admission。transition snapshot
/// capability 只存在于进程内，不能从 wire 构造；它既不提升整个 link，也不授权其他业务请求。
pub(crate) enum BusinessIngressAdmission {
    BusinessReady,
    TransitionSnapshot(Box<TransitionSnapshotPermit>),
}

/// 完整 ingress 验证链与 durable replay admission 后才可构造的 key-control capability。
pub(crate) struct AuthenticatedKeyControlIngress {
    #[allow(
        dead_code,
        reason = "P4.5 Store-backed transition handler consumes the opaque Current proof"
    )]
    authorization: CurrentRemoteAuthorizationProof,
    route: KeyControlReplyRoute,
    control: KeyControlRequestV1,
}

impl std::fmt::Debug for AuthenticatedKeyControlIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedKeyControlIngress")
            .field("control", &self.control)
            .field("route", &self.route)
            .field("authorization", &"[REDACTED]")
            .finish()
    }
}

impl AuthenticatedKeyControlIngress {
    pub(super) fn new(
        authorization: CurrentRemoteAuthorizationProof,
        route: KeyControlReplyRoute,
        control: KeyControlRequestV1,
    ) -> Self {
        Self {
            authorization,
            route,
            control,
        }
    }

    #[allow(
        dead_code,
        reason = "Store-backed P4.5 handler consumes the authenticated control"
    )]
    pub(crate) const fn control(&self) -> &KeyControlRequestV1 {
        &self.control
    }

    #[allow(
        dead_code,
        reason = "P4.5 Store-backed transition handler consumes the opaque Current proof"
    )]
    pub(crate) const fn authorization(&self) -> &CurrentRemoteAuthorizationProof {
        &self.authorization
    }

    const fn route(&self) -> KeyControlReplyRoute {
        self.route
    }
}

/// Store-backed transition consumer 的窄错误面。任何错误都必须在 RuntimeCore 前 fail-close。
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub(crate) enum KeyControlIngressError {
    #[error("remote key-control authority is invalid")]
    InvalidAuthority,
    #[error("remote business ingress is fenced by an active key transition")]
    #[allow(
        dead_code,
        reason = "Store-backed P4.5 handler returns the active-transition fence"
    )]
    TransitionFenced,
    #[error("remote business ingress is fenced by a durably retired counter scope")]
    CounterRetired,
    #[cfg(test)]
    #[error("authenticated remote key-control consumer is not installed")]
    ConsumerUnavailable,
    #[error("remote key-control Store operation was rejected")]
    #[allow(
        dead_code,
        reason = "P4.5 manager composition installs the Store-backed KeySync consumer"
    )]
    StoreRejected,
    #[error("remote KeySync frozen update is invalid")]
    #[allow(
        dead_code,
        reason = "P4.5 manager composition installs the Store-backed KeySync consumer"
    )]
    InvalidFrozenUpdate,
    #[error("remote authenticated ACK binding is invalid")]
    InvalidAckBinding,
}

impl KeyControlIngressError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidAuthority => "daemon.remote.key_control.invalid_authority",
            Self::TransitionFenced => "daemon.remote.key_control.transition_fenced",
            Self::CounterRetired => "daemon.remote.counter.retired",
            #[cfg(test)]
            Self::ConsumerUnavailable => "daemon.remote.key_control.consumer_unavailable",
            Self::StoreRejected => "daemon.remote.key_control.store_rejected",
            Self::InvalidFrozenUpdate => "daemon.remote.key_control.invalid_frozen_update",
            Self::InvalidAckBinding => "daemon.remote.key_control.invalid_ack_binding",
        }
    }
}

/// canonical transition state 的挂载点；RemoteLink 自身不得缓存或裁决 transition。
#[async_trait]
pub(crate) trait AuthenticatedKeyControlIngressHandler: Send + Sync {
    /// 每个 business ingress 在任何 RuntimeCore registration 前调用。
    async fn authorize_business_ingress(
        &self,
        authorization: &CurrentRemoteAuthorizationProof,
        envelope: &RuntimeEnvelope,
    ) -> Result<BusinessIngressAdmission, KeyControlIngressError>;

    /// 消费已经完成 DeviceSign/AAD/replay/AEAD/current-ledger 全链的 control。
    async fn consume(
        &self,
        ingress: AuthenticatedKeyControlIngress,
    ) -> Result<KeyControlIngressOutcome, KeyControlIngressError>;
}

/// P4.4 兼容入口使用的 fail-close handler：业务保持原行为，control 不会被静默丢弃。
#[cfg(test)]
pub(super) struct BusinessOnlyKeyControlIngressHandler;

#[cfg(test)]
#[async_trait]
impl AuthenticatedKeyControlIngressHandler for BusinessOnlyKeyControlIngressHandler {
    async fn authorize_business_ingress(
        &self,
        _authorization: &CurrentRemoteAuthorizationProof,
        _envelope: &RuntimeEnvelope,
    ) -> Result<BusinessIngressAdmission, KeyControlIngressError> {
        Ok(BusinessIngressAdmission::BusinessReady)
    }

    async fn consume(
        &self,
        _ingress: AuthenticatedKeyControlIngress,
    ) -> Result<KeyControlIngressOutcome, KeyControlIngressError> {
        Err(KeyControlIngressError::ConsumerUnavailable)
    }
}

/// Store-backed KeySync/ACK consumer。RemoteLink 只拿 typed outcome，不缓存 transition。
#[allow(
    dead_code,
    reason = "P4.5 manager composition installs this handler after transition recovery"
)]
pub(crate) struct StoreBackedKeyControlIngressHandler {
    store: RuntimeStoreHandle,
    clock: Arc<dyn RuntimeClock>,
    transition: Option<KeyTransitionRecoveryHandle>,
}

impl StoreBackedKeyControlIngressHandler {
    #[allow(
        dead_code,
        reason = "P4.5 manager composition installs this handler after transition recovery"
    )]
    pub(crate) fn new(store: RuntimeStoreHandle) -> Self {
        Self::with_clock(store, Arc::new(SystemRuntimeClock), None)
    }

    pub(crate) fn with_transition_owner(
        store: RuntimeStoreHandle,
        transition: KeyTransitionRecoveryHandle,
    ) -> Self {
        Self::with_clock(store, Arc::new(SystemRuntimeClock), Some(transition))
    }

    fn with_clock(
        store: RuntimeStoreHandle,
        clock: Arc<dyn RuntimeClock>,
        transition: Option<KeyTransitionRecoveryHandle>,
    ) -> Self {
        Self {
            store,
            clock,
            transition,
        }
    }

    fn observed_at_ms(&self) -> Result<u64, KeyControlIngressError> {
        self.clock
            .now_ms()
            .map_err(|_| KeyControlIngressError::StoreRejected)
    }

    async fn resolve_transition_snapshot(
        &self,
        authorization: &CurrentRemoteAuthorizationProof,
        scope: KeyTransitionStreamScope,
        cursor: StreamCursor,
    ) -> Result<TransitionSnapshotPermit, RuntimeStoreError> {
        self.store
            .resolve_transition_snapshot_permit(TransitionSnapshotRequest::new(
                authorization.clone(),
                scope,
                cursor,
            ))
            .await
    }

    async fn authorize_business_ingress_inner(
        &self,
        authorization: &CurrentRemoteAuthorizationProof,
        envelope: &RuntimeEnvelope,
    ) -> Result<BusinessIngressAdmission, KeyControlIngressError> {
        match self.store.has_retired_remote_counter().await {
            Ok(true) => return Err(KeyControlIngressError::CounterRetired),
            Ok(false) => {}
            Err(_) => return Err(KeyControlIngressError::StoreRejected),
        }
        match self
            .store
            .check_remote_transition_ingress(RemoteTransitionIngressClass::Business)
            .await
        {
            Ok(()) => Ok(BusinessIngressAdmission::BusinessReady),
            Err(RuntimeStoreError::InvalidStateTransition) => {
                // Active Add transition 只例外放行 exact Subscribe(BeforeFirst)。permit
                // 冻结 target/cut/revision；CatalogRequest、Backfill、prompt 与 At(H)
                // 都不能借这条窄 capability 进入 Core。
                let (scope, cursor) = transition_snapshot_axes(envelope)
                    .ok_or(KeyControlIngressError::TransitionFenced)?;
                let permit = match self
                    .resolve_transition_snapshot(authorization, scope, cursor)
                    .await
                {
                    Ok(permit) => permit,
                    Err(RuntimeStoreError::InvalidStateTransition) => {
                        let transition = self
                            .transition
                            .as_ref()
                            .ok_or(KeyControlIngressError::TransitionFenced)?;
                        tokio::time::timeout(
                            TRANSITION_SNAPSHOT_READINESS_TIMEOUT,
                            transition.drive_to_business_ready(),
                        )
                        .await
                        .map_err(|_| KeyControlIngressError::TransitionFenced)?
                        .map_err(|_| KeyControlIngressError::TransitionFenced)?;

                        // owner 完成幂等推进后必须重新走 Store-current 决策。zero-cut
                        // transition 可能已经完成，此时该 Subscribe 是普通业务；有 cut
                        // 的 Add 则只能凭本次 freshly resolved opaque permit 进入 Core。
                        match self
                            .store
                            .check_remote_transition_ingress(RemoteTransitionIngressClass::Business)
                            .await
                        {
                            Ok(()) => return Ok(BusinessIngressAdmission::BusinessReady),
                            Err(RuntimeStoreError::InvalidStateTransition) => self
                                .resolve_transition_snapshot(authorization, scope, cursor)
                                .await
                                .map_err(|error| match error {
                                    RuntimeStoreError::InvalidStateTransition
                                    | RuntimeStoreError::PublicationMismatch => {
                                        KeyControlIngressError::TransitionFenced
                                    }
                                    _ => KeyControlIngressError::StoreRejected,
                                })?,
                            Err(_) => {
                                return Err(KeyControlIngressError::StoreRejected);
                            }
                        }
                    }
                    Err(RuntimeStoreError::PublicationMismatch) => {
                        return Err(KeyControlIngressError::TransitionFenced);
                    }
                    Err(_) => {
                        return Err(KeyControlIngressError::StoreRejected);
                    }
                };
                Ok(BusinessIngressAdmission::TransitionSnapshot(Box::new(
                    permit,
                )))
            }
            Err(_) => Err(KeyControlIngressError::StoreRejected),
        }
    }

    async fn consume_key_sync(
        &self,
        ingress: &AuthenticatedKeyControlIngress,
    ) -> Result<KeyControlIngressOutcome, KeyControlIngressError> {
        let KeyControlRequestV1::KeySync { request } = ingress.control() else {
            return Err(KeyControlIngressError::InvalidAckBinding);
        };
        self.store
            .check_remote_transition_ingress(RemoteTransitionIngressClass::KeySync)
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        let route = ingress.route();
        let authorization = ingress.authorization().remote_reply_authorization();
        if route.machine_route != request.machine_route
            || route.device_route != request.device_route
            || authorization.machine_route() != route.machine_route
            || authorization.device_route() != route.device_route
            || authorization.grant_serial() != request.grant_serial
        {
            return Err(KeyControlIngressError::InvalidFrozenUpdate);
        }
        if authorization.key_directory_revision() == request.known_key_directory_revision {
            let status = DirectoryCurrentV1 {
                format_version: E2EE_FORMAT_VERSION,
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                relay_protocol_version: RELAY_PROTOCOL_VERSION,
                machine_route: route.machine_route,
                device_route: route.device_route,
                grant_serial: authorization.grant_serial(),
                root_trust_epoch: authorization.trust_epoch(),
                current_key_directory_revision: authorization.key_directory_revision(),
                requested_key_directory_revision: request.requested_key_directory_revision,
            };
            status
                .validate()
                .map_err(|_| KeyControlIngressError::InvalidFrozenUpdate)?;
            return Ok(KeyControlIngressOutcome::DirectedReply(Box::new(
                KeyControlDirectedReply {
                    authorization,
                    route,
                    payload: KeyControlDirectedPayload::DirectoryCurrent(status),
                },
            )));
        }
        let frozen = self
            .store
            .load_key_update_for_sync(KeySyncRead {
                recipient: KeyTransitionRecipient {
                    device_route: *request.device_route.as_bytes(),
                    grant_serial: request.grant_serial.value(),
                },
                known_revision: request.known_key_directory_revision.value(),
                requested_revision: request.requested_key_directory_revision.value(),
            })
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        let update_set = KeyUpdateSetV1::from_canonical_bytes(&frozen.canonical_update_set)
            .map_err(|_| KeyControlIngressError::InvalidFrozenUpdate)?;
        if frozen.recipient.device_route != *request.device_route.as_bytes()
            || frozen.recipient.grant_serial != request.grant_serial.value()
            || frozen.key_revision != request.requested_key_directory_revision.value()
            || update_set.device_route != request.device_route
            || update_set.key_directory_revision != request.requested_key_directory_revision
            || route.machine_route != request.machine_route
            || route.device_route != request.device_route
            || authorization.machine_route() != route.machine_route
            || authorization.device_route() != route.device_route
            || authorization.grant_serial() != request.grant_serial
            || request.known_key_directory_revision.value()
                >= request.requested_key_directory_revision.value()
            || authorization.key_directory_revision() != request.requested_key_directory_revision
        {
            return Err(KeyControlIngressError::InvalidFrozenUpdate);
        }
        let payload = self
            .classify_update_reply(request, &authorization, update_set)
            .await?;
        Ok(KeyControlIngressOutcome::DirectedReply(Box::new(
            KeyControlDirectedReply {
                authorization,
                route,
                payload,
            },
        )))
    }

    async fn classify_update_reply(
        &self,
        request: &agentdeck_protocol::e2ee::KeySyncRequestV1,
        authorization: &RemoteReplyAuthorization,
        update_set: KeyUpdateSetV1,
    ) -> Result<KeyControlDirectedPayload, KeyControlIngressError> {
        let transition = self
            .store
            .load_active_key_transition()
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?
            .ok_or(KeyControlIngressError::StoreRejected)?;
        let recipient = key_transition_recipient(
            authorization.device_route(),
            authorization.grant_serial().value(),
        );
        let directed_recovery = transition.transition.operation
            == KeyTransitionOperation::CounterRecovery
            && transition.transition.target == KeyTransitionTarget::Device(recipient);
        if !directed_recovery {
            return Ok(KeyControlDirectedPayload::UpdateSet(update_set));
        }
        let known_reply_epoch = authorization
            .reply_key_epoch()
            .checked_sub(1)
            .ok_or(KeyControlIngressError::InvalidFrozenUpdate)?;
        let mut replacement_entries = update_set.updates.iter().filter(|update| {
            update.key_id.purpose == agentdeck_protocol::e2ee::KeyPurpose::DeviceReplyTx
        });
        let replacement = replacement_entries
            .next()
            .ok_or(KeyControlIngressError::InvalidFrozenUpdate)?;
        if replacement_entries.next().is_some()
            || request.key_id.purpose != agentdeck_protocol::e2ee::KeyPurpose::DeviceReplyTx
            || request.key_id.epoch != known_reply_epoch
            || request.stream_route.is_some()
            || replacement.key_id.epoch != authorization.reply_key_epoch()
            || replacement.device_route != authorization.device_route()
            || replacement.stream_route.is_some()
            || replacement.key_directory_revision != authorization.key_directory_revision()
        {
            return Err(KeyControlIngressError::InvalidFrozenUpdate);
        }
        if transition.transition.phase != KeyTransitionPhase::BarriersCommitted
            || transition.transition.from_revision != request.known_key_directory_revision.value()
            || transition.transition.to_revision != request.requested_key_directory_revision.value()
            || transition.transition.terminal.is_some()
            || self
                .store
                .has_retired_remote_counter()
                .await
                .map_err(|_| KeyControlIngressError::StoreRejected)?
        {
            return Err(KeyControlIngressError::StoreRejected);
        }
        Ok(KeyControlDirectedPayload::DeviceKeyRecovery {
            known_revision: request.known_key_directory_revision,
            update_set,
        })
    }

    async fn consume_key_update_ack(
        &self,
        ingress: &AuthenticatedKeyControlIngress,
    ) -> Result<KeyControlIngressOutcome, KeyControlIngressError> {
        let KeyControlRequestV1::KeyUpdateAck { ack } = ingress.control() else {
            return Err(KeyControlIngressError::InvalidAckBinding);
        };
        validate_ingress_route(ingress, ack.machine_route, ack.device_route)?;
        self.store
            .check_remote_transition_ingress(RemoteTransitionIngressClass::KeyUpdateAck)
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        let recipient = key_transition_recipient(ack.device_route, ack.grant_serial.value());
        let binding = self
            .store
            .resolve_key_update_ack(KeyUpdateAckResolve {
                recipient,
                key_revision: ack.key_directory_revision.value(),
                update_hash: ack.update_set_sha256,
            })
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        let canonical_ack = ack
            .canonical_bytes()
            .map_err(|_| KeyControlIngressError::InvalidAckBinding)?;
        let observed_at_ms = self.observed_at_ms()?;
        let record = self
            .store
            .acknowledge_key_update(AcknowledgeKeyUpdate {
                operation_id: binding.operation_id,
                recipient,
                key_revision: ack.key_directory_revision.value(),
                update_hash: ack.update_set_sha256,
                canonical_ack: canonical_ack.clone(),
                acknowledged_at_ms: observed_at_ms,
            })
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        if record.operation_id != binding.operation_id
            || record.recipient != recipient
            || record.key_revision != ack.key_directory_revision.value()
            || record.lifecycle != KeyUpdateLifecycle::Acked
            || record.canonical_ack.as_deref() != Some(canonical_ack.as_slice())
        {
            return Err(KeyControlIngressError::InvalidAckBinding);
        }
        let _ = self
            .store
            .try_complete_key_transition(binding.operation_id)
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        Ok(KeyControlIngressOutcome::Consumed)
    }

    async fn consume_stream_applied_ack(
        &self,
        ingress: &AuthenticatedKeyControlIngress,
    ) -> Result<KeyControlIngressOutcome, KeyControlIngressError> {
        let KeyControlRequestV1::StreamAppliedAck { ack } = ingress.control() else {
            return Err(KeyControlIngressError::InvalidAckBinding);
        };
        validate_ingress_route(ingress, ack.machine_route, ack.device_route)?;
        self.store
            .check_remote_transition_ingress(RemoteTransitionIngressClass::StreamAppliedAck)
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        let recipient = key_transition_recipient(ack.device_route, ack.grant_serial.value());
        let (scope, inner_cursor) = stream_ack_axes(&ack.inner_cursor)?;
        let query = StreamAppliedAckResolve {
            recipient,
            key_revision: ack.key_directory_revision.value(),
            scope,
            stream_route: *ack.stream_route.as_bytes(),
            stream_generation: *ack.stream_generation.as_bytes(),
            applied_stream_seq: ack.applied_stream_seq,
            inner_cursor,
            key_epoch: ack.key_epoch,
            epoch_barrier_sha256: ack.epoch_barrier_sha256,
            authorization_hash: ingress.authorization().authorization_hash(),
        };
        let binding = self
            .store
            .resolve_stream_applied_ack(query)
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        let canonical_ack = ack
            .canonical_bytes()
            .map_err(|_| KeyControlIngressError::InvalidAckBinding)?;
        let observed_at_ms = self.observed_at_ms()?;
        let record = self
            .store
            .acknowledge_stream_applied(AcknowledgeStreamApplied {
                operation_id: binding.operation_id,
                recipient,
                key_revision: ack.key_directory_revision.value(),
                scope,
                stream_route: *ack.stream_route.as_bytes(),
                stream_generation: *ack.stream_generation.as_bytes(),
                applied_stream_seq: ack.applied_stream_seq,
                inner_cursor,
                key_epoch: ack.key_epoch,
                epoch_barrier_sha256: ack.epoch_barrier_sha256,
                authorization_hash: ingress.authorization().authorization_hash(),
                canonical_ack: canonical_ack.clone(),
                acknowledged_at_ms: observed_at_ms,
            })
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        let exact = record.stream_applied_acks.iter().any(|stored| {
            stored.scope == scope
                && stored.stream_route == *ack.stream_route.as_bytes()
                && stored.stream_generation == *ack.stream_generation.as_bytes()
                && stored.applied_stream_seq == ack.applied_stream_seq
                && stored.inner_cursor == inner_cursor
                && stored.key_revision == ack.key_directory_revision.value()
                && stored.key_epoch == ack.key_epoch
                && stored.epoch_barrier_sha256 == ack.epoch_barrier_sha256
                && stored.canonical_ack == canonical_ack
        });
        if record.operation_id != binding.operation_id
            || record.recipient != recipient
            || record.key_revision != ack.key_directory_revision.value()
            || record.lifecycle != KeyUpdateLifecycle::Acked
            || !exact
        {
            return Err(KeyControlIngressError::InvalidAckBinding);
        }
        let _ = self
            .store
            .try_complete_key_transition(binding.operation_id)
            .await
            .map_err(|_| KeyControlIngressError::StoreRejected)?;
        Ok(KeyControlIngressOutcome::Consumed)
    }
}

#[async_trait]
impl AuthenticatedKeyControlIngressHandler for StoreBackedKeyControlIngressHandler {
    async fn authorize_business_ingress(
        &self,
        authorization: &CurrentRemoteAuthorizationProof,
        envelope: &RuntimeEnvelope,
    ) -> Result<BusinessIngressAdmission, KeyControlIngressError> {
        self.authorize_business_ingress_inner(authorization, envelope)
            .await
    }

    async fn consume(
        &self,
        ingress: AuthenticatedKeyControlIngress,
    ) -> Result<KeyControlIngressOutcome, KeyControlIngressError> {
        match ingress.control() {
            KeyControlRequestV1::KeySync { .. } => self.consume_key_sync(&ingress).await,
            KeyControlRequestV1::KeyUpdateAck { .. } => self.consume_key_update_ack(&ingress).await,
            KeyControlRequestV1::StreamAppliedAck { .. } => {
                self.consume_stream_applied_ack(&ingress).await
            }
        }
    }
}

fn transition_snapshot_axes(
    envelope: &RuntimeEnvelope,
) -> Option<(KeyTransitionStreamScope, StreamCursor)> {
    let RuntimeMessage::Request(RuntimeRequest::Subscribe { inner_cursor }) = &envelope.body else {
        return None;
    };
    match inner_cursor {
        RuntimeInnerCursor::Catalog { cursor } => {
            Some((KeyTransitionStreamScope::Catalog, *cursor))
        }
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } => {
            let runtime_id =
                RuntimeId::parse_canonical(RuntimeIdKind::Conversation, conversation_id.as_str())
                    .ok()?;
            Some((
                KeyTransitionStreamScope::Conversation(*runtime_id.as_bytes()),
                *cursor,
            ))
        }
    }
}

fn key_transition_recipient(
    device_route: DeviceRouteId,
    grant_serial: u64,
) -> KeyTransitionRecipient {
    KeyTransitionRecipient {
        device_route: *device_route.as_bytes(),
        grant_serial,
    }
}

fn validate_ingress_route(
    ingress: &AuthenticatedKeyControlIngress,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
) -> Result<(), KeyControlIngressError> {
    let route = ingress.route();
    if route.machine_route == machine_route && route.device_route == device_route {
        Ok(())
    } else {
        Err(KeyControlIngressError::InvalidAuthority)
    }
}

fn stream_ack_axes(
    inner: &RuntimeInnerCursor,
) -> Result<(KeyTransitionStreamScope, Option<u64>), KeyControlIngressError> {
    match inner {
        RuntimeInnerCursor::Catalog { cursor } => {
            Ok((KeyTransitionStreamScope::Catalog, cursor.high_water()))
        }
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } => {
            let conversation =
                RuntimeId::parse_canonical(RuntimeIdKind::Conversation, conversation_id.as_str())
                    .map_err(|_| KeyControlIngressError::InvalidAckBinding)?;
            Ok((
                KeyTransitionStreamScope::Conversation(*conversation.as_bytes()),
                cursor.high_water(),
            ))
        }
    }
}

/// control 自带的 authority 必须与签发解密/验签能力的 exact Active proof 一致。
/// 该检查发生在 durable replay COMMIT 前。
pub(super) fn validate_control_authority(
    control: &KeyControlRequestV1,
    active: &ActiveRemoteIngressProof,
) -> Result<(), KeyControlIngressError> {
    let matches = match control {
        KeyControlRequestV1::KeySync { request } => {
            request.machine_route == active.machine_route()
                && request.device_route == active.device_route()
                && request.grant_serial == active.grant_serial()
                && request.root_trust_epoch == active.trust_epoch()
        }
        KeyControlRequestV1::KeyUpdateAck { ack } => {
            ack.machine_route == active.machine_route()
                && ack.device_route == active.device_route()
                && ack.grant_serial == active.grant_serial()
                && ack.root_trust_epoch == active.trust_epoch()
        }
        KeyControlRequestV1::StreamAppliedAck { ack } => {
            ack.machine_route == active.machine_route()
                && ack.device_route == active.device_route()
                && ack.grant_serial == active.grant_serial()
                && ack.root_trust_epoch == active.trust_epoch()
        }
    };
    if matches {
        Ok(())
    } else {
        Err(KeyControlIngressError::InvalidAuthority)
    }
}
