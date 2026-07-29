//! 唯一 MachineLink 上的 Runtime dispatch actor。
//!
//! RemoteLink 只拥有易失的 generation、connection 与 reply-route 映射；
//! canonical conversation/command/receipt 状态始终留在 [`RuntimeCore`] / Runtime Store。

use std::future::poll_fn;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;
use std::time::Duration;

use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::{
    DeviceKeyRecoveryReplyV1, DirectoryCurrentV1, KeyPurpose, KeyUpdateSetV1, SignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::KeyDirectoryRevision;
use agentdeck_protocol::relay_v2::frame::{Reply, SealedBlob, Send as RouteSend};
use agentdeck_protocol::relay_v2::{DeviceRouteId, MachineRouteId, RequestRouteId};
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    BackfillRequest, MAX_RUNTIME_JSON_FRAME_BYTES, RuntimeEnvelope, RuntimeInnerCursor,
    RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeTransferCarrierV1, RuntimeTransferChannel,
};
use async_trait::async_trait;
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::runtime::events::RuntimeStreamTarget;
use crate::runtime::store::key_transition::TransitionSnapshotPermit;
use crate::runtime::store::{
    RemoteReplyAuthorization, RuntimeId, RuntimeIdKind, RuntimeStoreHandle, StreamBindingPermit,
};
use crate::runtime::{
    ConnectionFramingProfile, ConnectionId, ConnectionSink, ConnectionWrite,
    EncodedRuntimeFrameKind, RemotePrincipalActivation, RuntimeCore,
};

use super::dispatch::{
    ActivatedRemoteIngress, RemoteDispatchError, RemoteIngressDispatcher, RemoteIngressRoute,
};
#[cfg(test)]
use super::key_control::BusinessOnlyKeyControlIngressHandler;
use super::key_control::{
    AuthenticatedKeyControlIngressHandler, BusinessIngressAdmission, KeyControlDirectedPayload,
    KeyControlDirectedReply, KeyControlIngressError, KeyControlIngressOutcome,
};
use super::replay::ReplayError;
use super::transport::{BusinessTransportEvent, BusinessTransportLane, RemoteTransportError};

const REPLY_ROUTE_CAPACITY: usize = 512;
const REMOTE_CONNECTION_CAPACITY: usize = 128;
const CORE_WRITER_HANDOFF_CAPACITY: usize = 8;
const CORE_DISPATCH_CAPACITY: usize = 128;
const REMOTE_LINK_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
const REMOTE_LINK_ACTOR_EXITED: &str = "daemon.remote.link.actor_exited";

/// RemoteLink 启动时的 ingress capability。ControlPlaneOnly 只允许 authenticated
/// KeyControl；首个 business frame 必须先从 Store 读回 transition 已释放，才能把
/// actor 单向提升为 BusinessReady。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteLinkIngressMode {
    ControlPlaneOnly,
    BusinessReady,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct DirectedReplyRoute {
    pub(crate) machine_route: MachineRouteId,
    pub(crate) device_route: DeviceRouteId,
    pub(crate) request_route: RequestRouteId,
}

#[derive(Debug)]
pub(crate) struct DirectedReplySeal {
    pub(crate) authorization_used: RemoteReplyAuthorization,
    pub(crate) sealed: SignedSealedBlobV1,
}

/// P4.5 directed reply sealer 的挂载点。P4.4 production 默认实现严格 fail-close，
/// 不预留 counter、不 seal、不写 outbox。
#[async_trait]
pub(crate) trait DirectedReplySealer: Send + Sync {
    fn admission_ready(&self) -> bool;

    async fn seal_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError>;

    /// Compact `Reply` carrier 仍属于单设备定向通道，必须使用 DeviceReplyTx；
    /// 它不能因体积较大而误入 shared publication outbox。
    async fn seal_transfer_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _carrier: RuntimeTransferCarrierV1,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }

    /// Active Add transition 的 exact snapshot route。普通 business revision refresh
    /// 在此时必须保持 fenced；只有 Store-issued permit 可以授权这组 directed replies。
    async fn seal_transition_snapshot_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _permit: &TransitionSnapshotPermit,
        _runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }

    async fn seal_transition_snapshot_transfer_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _permit: &TransitionSnapshotPermit,
        _carrier: RuntimeTransferCarrierV1,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }

    /// Store-issued publication permit 的 exact directed key-control terminal。
    async fn seal_stream_binding_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _permit: StreamBindingPermit,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }

    /// 仅在 exact SyncComplete 已通过 Relay writer 且 Core write 已 ACK 后调用。
    async fn mark_transition_snapshot_flushed(
        &self,
        _permit: TransitionSnapshotPermit,
        _sync_complete_sha256: [u8; 32],
    ) -> Result<(), RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }

    /// KeySync 的 typed KeyUpdateSet 使用同一 DeviceReplyTx counter/key transaction，
    /// 但不伪装成 Runtime reply envelope。
    async fn seal_key_update_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _update_set: KeyUpdateSetV1,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }

    /// daemon 尚停在 known revision 时，以当前 DeviceReplyTx key 返回 authenticated
    /// `DirectoryCurrent(r)`；不得误用 requested revision 的 replacement key。
    async fn seal_directory_current_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _status: DirectoryCurrentV1,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }

    /// DeviceReplyTx rollback 的独立 DeviceHPKE + MachineDataSign recovery carrier。
    /// 该路径不得调用 reply AEAD sealer 或预留 sender counter。
    async fn seal_device_key_recovery_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _known_revision: KeyDirectoryRevision,
        _update_set: KeyUpdateSetV1,
    ) -> Result<DeviceKeyRecoveryReplyV1, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }
}

/// P4.5 publication/outbox 的最小挂载点。成功必须表示 publisher 自己的 durable/Relay
/// 边界已经完成；P4.4 默认实现永远失败，因此不会提前 ACK Stream。
#[async_trait]
pub(crate) trait RemoteStreamPublisher: Send + Sync {
    fn admission_ready(&self) -> bool;

    async fn prepare_subscription(
        &self,
        _target: RuntimeStreamTarget,
    ) -> Result<(), RemoteLinkError> {
        Err(RemoteLinkError::StreamPublisherUnavailable)
    }

    async fn publish_exact(&self, runtime_bytes: Arc<[u8]>) -> Result<(), RemoteLinkError>;

    async fn publish_transfer_exact(
        &self,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<(), RemoteLinkError>;

    /// transport generation 替换后唤醒 durable outbox。默认实现只服务不持久化
    /// publication 的测试 double；production shared publisher 必须转发到唯一 drive owner。
    async fn notify_reconnected(&self) -> Result<(), RemoteLinkError> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) struct UnavailableDirectedReplySealer;

#[cfg(test)]
#[async_trait]
impl DirectedReplySealer for UnavailableDirectedReplySealer {
    fn admission_ready(&self) -> bool {
        false
    }

    async fn seal_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealUnavailable)
    }
}

pub(crate) struct UnavailableRemoteStreamPublisher;

#[async_trait]
impl RemoteStreamPublisher for UnavailableRemoteStreamPublisher {
    fn admission_ready(&self) -> bool {
        false
    }

    async fn publish_exact(&self, _runtime_bytes: Arc<[u8]>) -> Result<(), RemoteLinkError> {
        Err(RemoteLinkError::StreamPublisherUnavailable)
    }

    async fn publish_transfer_exact(
        &self,
        _carrier: RuntimeTransferCarrierV1,
    ) -> Result<(), RemoteLinkError> {
        Err(RemoteLinkError::StreamPublisherUnavailable)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RemoteLinkError {
    #[error("remote ingress failed: {0}")]
    Dispatch(#[from] RemoteDispatchError),
    #[error("remote replay admission failed: {0}")]
    Replay(#[from] ReplayError),
    #[error("remote key-control ingress failed: {0}")]
    KeyControl(#[from] KeyControlIngressError),
    #[error("remote transport failed: {0}")]
    Transport(#[from] RemoteTransportError),
    #[error("RuntimeCore is unavailable")]
    CoreUnavailable,
    #[error("RuntimeCore rejected the connection or request")]
    CoreRejected,
    #[error("remote reply route is unknown or stale")]
    UnknownReplyRoute,
    #[error("remote reply route capacity is exhausted")]
    ReplyRouteCapacity,
    #[error("remote connection capacity is exhausted")]
    ConnectionCapacity,
    #[error("remote Core dispatch capacity is exhausted")]
    CoreDispatchCapacity,
    #[error("remote reply authorization does not match its route")]
    ReplyAuthorizationMismatch,
    #[error("directed reply sealer returned an invalid reply binding")]
    InvalidReplySeal,
    #[error("RuntimeCore emitted an invalid envelope")]
    InvalidCoreEgress,
    #[error("Store-backed KeySync emitted an invalid key update")]
    InvalidKeyControlReply,
    #[cfg(test)]
    #[error("directed reply sealing failed")]
    ReplySealFailed,
    #[error("directed reply sealing is not installed")]
    ReplySealUnavailable,
    #[error("stream publisher is not installed")]
    StreamPublisherUnavailable,
    #[error("shared stream publication failed before exact Relay COMMIT")]
    StreamPublishFailed,
    #[error("remote sender counter scope is durably retired")]
    CounterRetired,
    #[error("remote link actor is closed")]
    Closed,
    #[error("remote link did not quiesce before the shutdown deadline")]
    ShutdownTimedOut,
}

impl RemoteLinkError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Dispatch(error) => error.code(),
            Self::Replay(error) => error.code(),
            Self::KeyControl(error) => error.code(),
            Self::Transport(error) => match error {
                RemoteTransportError::BusinessGenerationReplaced => {
                    "daemon.remote.link.generation_replaced"
                }
                _ => "daemon.remote.link.transport_failed",
            },
            Self::CoreUnavailable => "daemon.remote.link.core_unavailable",
            Self::CoreRejected => "daemon.remote.link.core_rejected",
            Self::UnknownReplyRoute => "daemon.remote.link.reply_route_unknown",
            Self::ReplyRouteCapacity => "daemon.remote.link.reply_route_capacity",
            Self::ConnectionCapacity => "daemon.remote.link.connection_capacity",
            Self::CoreDispatchCapacity => "daemon.remote.link.core_dispatch_capacity",
            Self::ReplyAuthorizationMismatch => "daemon.remote.link.reply_authorization_mismatch",
            Self::InvalidReplySeal => "daemon.remote.link.reply_seal_invalid",
            Self::InvalidCoreEgress => "daemon.remote.link.invalid_core_egress",
            Self::InvalidKeyControlReply => "daemon.remote.link.invalid_key_control_reply",
            #[cfg(test)]
            Self::ReplySealFailed => "daemon.remote.link.reply_seal_failed",
            Self::ReplySealUnavailable => "daemon.remote.link.reply_seal_unavailable",
            Self::StreamPublisherUnavailable => "daemon.remote.link.stream_publisher_unavailable",
            Self::StreamPublishFailed => "daemon.remote.link.stream_publish_failed",
            Self::CounterRetired => "daemon.remote.counter.retired",
            Self::Closed => "daemon.remote.link.closed",
            Self::ShutdownTimedOut => "daemon.remote.link.shutdown_timed_out",
        }
    }

    fn requires_device_isolation(&self) -> bool {
        matches!(self, Self::Dispatch(error) if error.requires_connection_isolation())
            || matches!(self, Self::Replay(error) if error.requires_connection_isolation())
    }
}

#[derive(Clone)]
struct ReplyRouteBinding {
    connection_id: ConnectionId,
    message_id: MessageId,
    generation: u64,
    route: DirectedReplyRoute,
    authorization: RemoteReplyAuthorization,
    lifecycle: ReplyRouteLifecycle,
    transition_snapshot: Option<TransitionSnapshotPermit>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReplyRouteLifecycle {
    OneShot,
    UntilSyncComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyRouteBind {
    Inserted,
    ExistingExact,
}

impl ReplyRouteLifecycle {
    fn for_request(request: &RuntimeRequest) -> Self {
        match request {
            RuntimeRequest::Subscribe { .. } | RuntimeRequest::Backfill(_) => {
                Self::UntilSyncComplete
            }
            _ => Self::OneShot,
        }
    }

    fn completes(self, reply: &RuntimeReply) -> bool {
        match self {
            Self::OneShot => match reply {
                RuntimeReply::TransferPart(part) => part.part_index + 1 == part.part_count,
                _ => true,
            },
            Self::UntilSyncComplete => {
                matches!(
                    reply,
                    RuntimeReply::SyncComplete(_) | RuntimeReply::Failure(_)
                )
            }
        }
    }

    fn completes_transfer(self, carrier: &RuntimeTransferCarrierV1) -> bool {
        match self {
            Self::OneShot => carrier
                .transfer
                .part_index
                .checked_add(1)
                .is_some_and(|next| next == carrier.transfer.part_count),
            Self::UntilSyncComplete => false,
        }
    }
}

/// 单个 MachineLink 的 central egress pump。route key 必须同时包含 connection identity
/// 与 message identity；两个设备可合法复用相同 MessageId，绝不能串到彼此 route。
pub(crate) struct RemoteReplyPump {
    lane: BusinessTransportLane,
    sealer: Arc<dyn DirectedReplySealer>,
    stream_publisher: Arc<dyn RemoteStreamPublisher>,
    routes: Vec<ReplyRouteBinding>,
}

impl RemoteReplyPump {
    pub(crate) fn new(lane: BusinessTransportLane, sealer: Arc<dyn DirectedReplySealer>) -> Self {
        Self {
            lane,
            sealer,
            stream_publisher: Arc::new(UnavailableRemoteStreamPublisher),
            routes: Vec::new(),
        }
    }

    pub(crate) fn with_stream_publisher(
        mut self,
        publisher: Arc<dyn RemoteStreamPublisher>,
    ) -> Self {
        self.stream_publisher = publisher;
        self
    }

    pub(crate) fn bind(
        &mut self,
        connection_id: ConnectionId,
        message_id: MessageId,
        route: DirectedReplyRoute,
        authorization: RemoteReplyAuthorization,
        lifecycle: ReplyRouteLifecycle,
    ) -> Result<ReplyRouteBind, RemoteLinkError> {
        self.bind_with_transition_snapshot(
            connection_id,
            message_id,
            route,
            authorization,
            lifecycle,
            None,
        )
    }

    pub(crate) fn bind_transition_snapshot(
        &mut self,
        connection_id: ConnectionId,
        message_id: MessageId,
        route: DirectedReplyRoute,
        authorization: RemoteReplyAuthorization,
        lifecycle: ReplyRouteLifecycle,
        permit: TransitionSnapshotPermit,
    ) -> Result<ReplyRouteBind, RemoteLinkError> {
        self.bind_with_transition_snapshot(
            connection_id,
            message_id,
            route,
            authorization,
            lifecycle,
            Some(permit),
        )
    }

    fn bind_with_transition_snapshot(
        &mut self,
        connection_id: ConnectionId,
        message_id: MessageId,
        route: DirectedReplyRoute,
        authorization: RemoteReplyAuthorization,
        lifecycle: ReplyRouteLifecycle,
        transition_snapshot: Option<TransitionSnapshotPermit>,
    ) -> Result<ReplyRouteBind, RemoteLinkError> {
        if authorization.machine_route() != route.machine_route
            || authorization.device_route() != route.device_route
        {
            return Err(RemoteLinkError::ReplyAuthorizationMismatch);
        }
        let generation = self.lane.current_generation();
        if let Some(existing) = self.routes.iter_mut().find(|candidate| {
            candidate.connection_id == connection_id && candidate.message_id == message_id
        }) {
            if existing.generation != generation
                || existing.route != route
                || existing.authorization != authorization
                || existing.lifecycle != lifecycle
                || existing.transition_snapshot != transition_snapshot
            {
                return Err(RemoteLinkError::ReplyAuthorizationMismatch);
            }
            return Ok(ReplyRouteBind::ExistingExact);
        }
        if self.routes.len() >= REPLY_ROUTE_CAPACITY {
            return Err(RemoteLinkError::ReplyRouteCapacity);
        }
        self.routes.push(ReplyRouteBinding {
            connection_id,
            message_id,
            generation,
            route,
            authorization,
            lifecycle,
            transition_snapshot,
        });
        Ok(ReplyRouteBind::Inserted)
    }

    pub(crate) fn remove_connection(&mut self, connection_id: ConnectionId) {
        self.routes
            .retain(|binding| binding.connection_id != connection_id);
    }

    fn remove_exact(
        &mut self,
        connection_id: ConnectionId,
        message_id: &MessageId,
        generation: u64,
    ) {
        self.routes.retain(|binding| {
            binding.connection_id != connection_id
                || binding.message_id != *message_id
                || binding.generation != generation
        });
    }

    fn refresh_exact_authorization(
        &mut self,
        connection_id: ConnectionId,
        message_id: &MessageId,
        generation: u64,
        authorization: RemoteReplyAuthorization,
    ) -> Result<(), RemoteLinkError> {
        let binding = self
            .routes
            .iter_mut()
            .find(|binding| {
                binding.connection_id == connection_id
                    && binding.message_id == *message_id
                    && binding.generation == generation
            })
            .ok_or(RemoteLinkError::UnknownReplyRoute)?;
        if !authorization.is_same_lineage_at_or_after(&binding.authorization) {
            return Err(RemoteLinkError::ReplyAuthorizationMismatch);
        }
        binding.authorization = authorization;
        Ok(())
    }

    pub(crate) async fn next_transport_event(
        &mut self,
    ) -> Result<Option<BusinessTransportEvent>, RemoteLinkError> {
        let event = self.lane.next_event().await?;
        if matches!(
            event,
            Some(BusinessTransportEvent::GenerationReplaced { .. })
        ) {
            self.routes.clear();
        }
        Ok(event)
    }

    /// authenticated KeySync 的 exact request route 定向回复。Relay flush 失败或
    /// generation 更换都会返回错误；`RouteAccepted` 从不参与此 terminal。
    pub(crate) async fn forward_key_control(
        &mut self,
        reply: KeyControlDirectedReply,
    ) -> Result<(), RemoteLinkError> {
        let generation = self.lane.current_generation();
        let (authorization, route, payload) = reply.into_parts();
        let route = DirectedReplyRoute {
            machine_route: route.machine_route,
            device_route: route.device_route,
            request_route: route.request_route,
        };
        if authorization.machine_route() != route.machine_route
            || authorization.device_route() != route.device_route
        {
            return Err(RemoteLinkError::ReplyAuthorizationMismatch);
        }
        let wire = match payload {
            KeyControlDirectedPayload::DirectoryCurrent(status) => {
                let sealed = self
                    .sealer
                    .seal_directory_current_exact(&authorization, route, status)
                    .await?;
                validated_reply_wire(&authorization, sealed)?
            }
            KeyControlDirectedPayload::UpdateSet(update_set) => {
                let sealed = self
                    .sealer
                    .seal_key_update_exact(&authorization, route, update_set)
                    .await?;
                validated_reply_wire(&authorization, sealed)?
            }
            KeyControlDirectedPayload::DeviceKeyRecovery {
                known_revision,
                update_set,
            } => {
                let expected_update = update_set.clone();
                let reply = self
                    .sealer
                    .seal_device_key_recovery_exact(
                        &authorization,
                        route,
                        known_revision,
                        update_set,
                    )
                    .await?;
                validated_key_recovery_wire(
                    &authorization,
                    route,
                    known_revision,
                    &expected_update,
                    reply,
                )?
            }
        };
        self.lane
            .send_reply(
                generation,
                Reply {
                    device_route: route.device_route,
                    request_route: route.request_route,
                    sealed_blob: SealedBlob(wire),
                },
            )
            .await?;
        Ok(())
    }

    /// ACK 是严格的末端边界：Reply 只有 seal + 同 generation Relay flush 成功后 ACK；
    /// Stream 只有 publisher 成功后 ACK；未知 route、Request、任何错误都 drop write。
    pub(crate) async fn forward(
        &mut self,
        connection_id: ConnectionId,
        write: ConnectionWrite,
    ) -> Result<(), RemoteLinkError> {
        let bytes = write.shared_bytes();
        let stream_binding = write.stream_binding();
        if write.kind() == EncodedRuntimeFrameKind::CompactTransfer {
            let carrier = RuntimeTransferCarrierV1::decode(&bytes)
                .map_err(|_| RemoteLinkError::InvalidCoreEgress)?;
            match carrier.channel {
                RuntimeTransferChannel::Stream => {
                    self.stream_publisher
                        .publish_transfer_exact(carrier)
                        .await?;
                    return write.acknowledge().map_err(|_| RemoteLinkError::Closed);
                }
                RuntimeTransferChannel::Reply => {
                    let message_id = carrier.message_id.clone();
                    let binding = self
                        .routes
                        .iter()
                        .find(|candidate| {
                            candidate.connection_id == connection_id
                                && candidate.message_id == message_id
                                && candidate.generation == self.lane.current_generation()
                        })
                        .cloned()
                        .ok_or(RemoteLinkError::UnknownReplyRoute)?;
                    let completes_route = binding.lifecycle.completes_transfer(&carrier);
                    let sealed = match &binding.transition_snapshot {
                        Some(permit) => {
                            self.sealer
                                .seal_transition_snapshot_transfer_exact(
                                    &binding.authorization,
                                    binding.route,
                                    permit,
                                    carrier,
                                )
                                .await?
                        }
                        None => {
                            self.sealer
                                .seal_transfer_exact(&binding.authorization, binding.route, carrier)
                                .await?
                        }
                    };
                    let (authorization_used, sealed) =
                        validated_refreshed_reply_wire(&binding.authorization, sealed)?;
                    self.lane
                        .send_reply(
                            binding.generation,
                            Reply {
                                device_route: binding.route.device_route,
                                request_route: binding.route.request_route,
                                sealed_blob: SealedBlob(sealed),
                            },
                        )
                        .await?;
                    write.acknowledge().map_err(|_| RemoteLinkError::Closed)?;
                    if completes_route {
                        self.remove_exact(connection_id, &message_id, binding.generation);
                    } else {
                        self.refresh_exact_authorization(
                            connection_id,
                            &message_id,
                            binding.generation,
                            authorization_used,
                        )?;
                    }
                    return Ok(());
                }
            }
        }
        if bytes.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
            return Err(RemoteLinkError::InvalidCoreEgress);
        }
        let envelope: RuntimeEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| RemoteLinkError::InvalidCoreEgress)?;
        match envelope.body {
            RuntimeMessage::Reply(reply) => {
                let binding = self
                    .routes
                    .iter()
                    .find(|candidate| {
                        candidate.connection_id == connection_id
                            && candidate.message_id == envelope.message_id
                            && candidate.generation == self.lane.current_generation()
                    })
                    .cloned()
                    .ok_or(RemoteLinkError::UnknownReplyRoute)?;
                let stream_binding = match &reply {
                    RuntimeReply::SyncComplete(sync)
                        if binding.lifecycle == ReplyRouteLifecycle::UntilSyncComplete =>
                    {
                        let permit = stream_binding.ok_or(RemoteLinkError::InvalidCoreEgress)?;
                        if !permit.matches_runtime_sync(sync) {
                            return Err(RemoteLinkError::InvalidCoreEgress);
                        }
                        Some(permit)
                    }
                    _ if stream_binding.is_some() => {
                        return Err(RemoteLinkError::InvalidCoreEgress);
                    }
                    _ => None,
                };
                let completes_route = binding.lifecycle.completes(&reply);
                let sync_complete_sha256 = match (&binding.transition_snapshot, &reply) {
                    (Some(_), RuntimeReply::SyncComplete(sync)) => {
                        let canonical = serde_json::to_vec(sync)
                            .map_err(|_| RemoteLinkError::InvalidCoreEgress)?;
                        Some(sha256(&canonical))
                    }
                    _ => None,
                };
                let sealed = match &binding.transition_snapshot {
                    Some(permit) => {
                        self.sealer
                            .seal_transition_snapshot_exact(
                                &binding.authorization,
                                binding.route,
                                permit,
                                bytes,
                            )
                            .await?
                    }
                    None => {
                        self.sealer
                            .seal_exact(&binding.authorization, binding.route, bytes)
                            .await?
                    }
                };
                let (authorization_used, sealed) =
                    validated_refreshed_reply_wire(&binding.authorization, sealed)?;
                self.lane
                    .send_reply(
                        binding.generation,
                        Reply {
                            device_route: binding.route.device_route,
                            request_route: binding.route.request_route,
                            sealed_blob: SealedBlob(sealed),
                        },
                    )
                    .await?;
                if let Some(permit) = stream_binding {
                    if permit.key_directory_revision()
                        != authorization_used.key_directory_revision().value()
                    {
                        return Err(RemoteLinkError::ReplyAuthorizationMismatch);
                    }
                    let sealed = self
                        .sealer
                        .seal_stream_binding_exact(&authorization_used, binding.route, permit)
                        .await?;
                    let sealed = validated_reply_wire(&authorization_used, sealed)?;
                    self.lane
                        .send_reply(
                            binding.generation,
                            Reply {
                                device_route: binding.route.device_route,
                                request_route: binding.route.request_route,
                                sealed_blob: SealedBlob(sealed),
                            },
                        )
                        .await?;
                }
                write.acknowledge().map_err(|_| RemoteLinkError::Closed)?;
                if let (Some(permit), Some(sync_complete_sha256)) =
                    (binding.transition_snapshot.clone(), sync_complete_sha256)
                {
                    self.sealer
                        .mark_transition_snapshot_flushed(permit, sync_complete_sha256)
                        .await?;
                }
                if completes_route {
                    self.remove_exact(connection_id, &envelope.message_id, binding.generation);
                } else {
                    self.refresh_exact_authorization(
                        connection_id,
                        &envelope.message_id,
                        binding.generation,
                        authorization_used,
                    )?;
                }
                Ok(())
            }
            RuntimeMessage::Stream(_) => {
                self.stream_publisher.publish_exact(bytes).await?;
                write.acknowledge().map_err(|_| RemoteLinkError::Closed)
            }
            RuntimeMessage::Request(_) => Err(RemoteLinkError::InvalidCoreEgress),
        }
    }
}

#[cfg(test)]
pub(crate) async fn send_directed_reply_for_test(
    lane: BusinessTransportLane,
    sealer: Arc<dyn DirectedReplySealer>,
    authorization: RemoteReplyAuthorization,
    route: DirectedReplyRoute,
    write: ConnectionWrite,
) -> Result<(), RemoteLinkError> {
    let generation = lane.current_generation();
    let bytes = write.shared_bytes();
    let sealed = sealer.seal_exact(&authorization, route, bytes).await?;
    let (_, sealed) = validated_refreshed_reply_wire(&authorization, sealed)?;
    lane.send_reply(
        generation,
        Reply {
            device_route: route.device_route,
            request_route: route.request_route,
            sealed_blob: SealedBlob(sealed),
        },
    )
    .await?;
    write.acknowledge().map_err(|_| RemoteLinkError::Closed)
}

fn validated_refreshed_reply_wire(
    frozen: &RemoteReplyAuthorization,
    reply: DirectedReplySeal,
) -> Result<(RemoteReplyAuthorization, Vec<u8>), RemoteLinkError> {
    if !reply.authorization_used.is_same_lineage_at_or_after(frozen) {
        return Err(RemoteLinkError::ReplyAuthorizationMismatch);
    }
    let wire = validated_reply_wire(&reply.authorization_used, reply.sealed)?;
    Ok((reply.authorization_used, wire))
}

fn validated_reply_wire(
    authorization: &RemoteReplyAuthorization,
    sealed: SignedSealedBlobV1,
) -> Result<Vec<u8>, RemoteLinkError> {
    if sealed.inner.key_id.purpose != KeyPurpose::DeviceReplyTx
        || sealed.inner.key_id.epoch != authorization.reply_key_epoch()
        || sealed.inner.key_epoch != authorization.reply_key_epoch()
        || sealed.inner.key_directory_revision != authorization.key_directory_revision().value()
    {
        return Err(RemoteLinkError::InvalidReplySeal);
    }
    let wire = sealed.to_wire_bytes();
    let decoded = SignedSealedBlobV1::from_wire_bytes(&wire)
        .map_err(|_| RemoteLinkError::InvalidReplySeal)?;
    if decoded != sealed {
        return Err(RemoteLinkError::InvalidReplySeal);
    }
    Ok(wire)
}

fn validated_key_recovery_wire(
    authorization: &RemoteReplyAuthorization,
    route: DirectedReplyRoute,
    known_revision: KeyDirectoryRevision,
    update_set: &KeyUpdateSetV1,
    reply: DeviceKeyRecoveryReplyV1,
) -> Result<Vec<u8>, RemoteLinkError> {
    reply
        .validate()
        .map_err(|_| RemoteLinkError::InvalidKeyControlReply)?;
    let info = &reply.info;
    if route.machine_route != authorization.machine_route()
        || route.device_route != authorization.device_route()
        || info.machine_route != route.machine_route
        || info.device_route != route.device_route
        || info.request_route != route.request_route
        || info.grant_serial != authorization.grant_serial()
        || info.root_trust_epoch != authorization.trust_epoch()
        || info.known_key_directory_revision != known_revision
        || info.target_key_directory_revision != authorization.key_directory_revision()
        || update_set.device_route != route.device_route
        || update_set.key_directory_revision != authorization.key_directory_revision()
        || update_set
            .canonical_sha256()
            .map_err(|_| RemoteLinkError::InvalidKeyControlReply)?
            != info.update_set_sha256
    {
        return Err(RemoteLinkError::InvalidKeyControlReply);
    }
    let wire = reply
        .canonical_bytes()
        .map_err(|_| RemoteLinkError::InvalidKeyControlReply)?;
    let decoded = DeviceKeyRecoveryReplyV1::from_canonical_bytes(&wire)
        .map_err(|_| RemoteLinkError::InvalidKeyControlReply)?;
    if decoded != reply {
        return Err(RemoteLinkError::InvalidKeyControlReply);
    }
    Ok(wire)
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct DeviceConnectionKey {
    machine_trust_domain: [u8; 32],
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: u64,
    device_sign_fingerprint: [u8; 32],
}

struct RemoteConnection {
    key: DeviceConnectionKey,
    id: ConnectionId,
    core_rx: mpsc::Receiver<ConnectionWrite>,
}

struct RemoteLinkConnectionCleanup {
    core: Weak<RuntimeCore>,
    connection_ids: Mutex<Vec<ConnectionId>>,
}

impl RemoteLinkConnectionCleanup {
    fn new(core: Weak<RuntimeCore>) -> Self {
        Self {
            core,
            connection_ids: Mutex::new(Vec::new()),
        }
    }

    fn register(&self, connection_id: ConnectionId) {
        let mut ids = self
            .connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !ids.contains(&connection_id) {
            ids.push(connection_id);
        }
    }

    fn unregister(&self, connection_id: ConnectionId) {
        self.connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|candidate| *candidate != connection_id);
    }

    fn snapshot(&self) -> Vec<ConnectionId> {
        self.connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn fail_close_all(&self) {
        if let Some(core) = self.core.upgrade() {
            for connection_id in self.snapshot() {
                core.fail_close_connection_for_transport(connection_id);
            }
        }
    }

    async fn disconnect_all(&self) {
        let Some(core) = self.core.upgrade() else {
            self.connection_ids
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
            return;
        };
        for connection_id in self.snapshot() {
            core.disconnect(connection_id).await;
            self.unregister(connection_id);
        }
    }
}

enum TaggedCoreEvent {
    Write {
        connection_id: ConnectionId,
        write: ConnectionWrite,
    },
    Closed {
        connection_id: ConnectionId,
    },
}

struct CoreDispatchCompletion {
    connection_id: ConnectionId,
    message_id: MessageId,
    generation: u64,
    succeeded: bool,
}

#[derive(Default)]
struct RemoteLinkTaskTracker {
    active: AtomicUsize,
    quiesced: Notify,
}

impl RemoteLinkTaskTracker {
    fn track(self: &Arc<Self>) -> RemoteLinkTaskGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        RemoteLinkTaskGuard {
            tracker: Arc::clone(self),
        }
    }

    async fn wait_for_quiescence(&self) {
        loop {
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            let notified = self.quiesced.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct RemoteLinkTaskGuard {
    tracker: Arc<RemoteLinkTaskTracker>,
}

impl Drop for RemoteLinkTaskGuard {
    fn drop(&mut self) {
        if self.tracker.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.quiesced.notify_waiters();
        }
    }
}

/// manager 持有的 cancel+join owner；内部 actor 只保存 Weak Core。
pub(crate) struct RemoteLinkOwner {
    cancel: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    health_rx: watch::Receiver<Option<String>>,
    cleanup: Arc<RemoteLinkConnectionCleanup>,
    tasks: Arc<RemoteLinkTaskTracker>,
    shutdown_timeout: Duration,
}

impl RemoteLinkOwner {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        machine_route: MachineRouteId,
        store: RuntimeStoreHandle,
        lane: BusinessTransportLane,
        core: Weak<RuntimeCore>,
        sealer: Arc<dyn DirectedReplySealer>,
        publisher: Arc<dyn RemoteStreamPublisher>,
    ) -> Result<Self, RemoteLinkError> {
        Self::start_with_key_control_handler(
            machine_route,
            store,
            lane,
            core,
            sealer,
            publisher,
            Arc::new(BusinessOnlyKeyControlIngressHandler),
        )
    }

    /// production 只允许显式安装 Store-backed transition consumer；authenticated
    /// key-control 不存在静默降级路径。
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_with_key_control_handler(
        machine_route: MachineRouteId,
        store: RuntimeStoreHandle,
        lane: BusinessTransportLane,
        core: Weak<RuntimeCore>,
        sealer: Arc<dyn DirectedReplySealer>,
        publisher: Arc<dyn RemoteStreamPublisher>,
        key_control: Arc<dyn AuthenticatedKeyControlIngressHandler>,
    ) -> Result<Self, RemoteLinkError> {
        Self::start_with_ingress_mode_and_key_control_handler(
            machine_route,
            store,
            lane,
            core,
            sealer,
            publisher,
            key_control,
            RemoteLinkIngressMode::BusinessReady,
        )
    }

    /// manager admission 唯一可指定初始 ingress mode 的 production 构造；mode 只在
    /// actor 内单向提升，不形成第二份业务状态或绕过 Store transition fence。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_with_ingress_mode_and_key_control_handler(
        machine_route: MachineRouteId,
        store: RuntimeStoreHandle,
        lane: BusinessTransportLane,
        core: Weak<RuntimeCore>,
        sealer: Arc<dyn DirectedReplySealer>,
        publisher: Arc<dyn RemoteStreamPublisher>,
        key_control: Arc<dyn AuthenticatedKeyControlIngressHandler>,
        ingress_mode: RemoteLinkIngressMode,
    ) -> Result<Self, RemoteLinkError> {
        if !sealer.admission_ready() {
            return Err(RemoteLinkError::ReplySealUnavailable);
        }
        if !publisher.admission_ready() {
            return Err(RemoteLinkError::StreamPublisherUnavailable);
        }
        let (cancel, cancel_rx) = watch::channel(false);
        let (health_tx, health_rx) = watch::channel(None);
        let health_cancel = cancel_rx.clone();
        let cleanup = Arc::new(RemoteLinkConnectionCleanup::new(core.clone()));
        let tasks = Arc::new(RemoteLinkTaskTracker::default());
        let task = tokio::spawn({
            let cleanup = Arc::clone(&cleanup);
            let tasks = Arc::clone(&tasks);
            async move {
                run_remote_link(
                    machine_route,
                    store,
                    lane,
                    core,
                    sealer,
                    publisher,
                    key_control,
                    ingress_mode,
                    cancel_rx,
                    cleanup,
                    tasks,
                )
                .await;
                if !*health_cancel.borrow() {
                    health_tx.send_replace(Some(REMOTE_LINK_ACTOR_EXITED.to_owned()));
                }
            }
        });
        Ok(Self {
            cancel,
            task: Some(task),
            health_rx,
            cleanup,
            tasks,
            shutdown_timeout: REMOTE_LINK_SHUTDOWN_DEADLINE,
        })
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), RemoteLinkError> {
        self.cancel.send_replace(true);
        let deadline = tokio::time::Instant::now() + self.shutdown_timeout;
        let shutdown = async {
            if let Some(task) = self.task.as_mut() {
                let _ = (&mut *task).await;
            }
            self.tasks.wait_for_quiescence().await;
            self.cleanup.disconnect_all().await;
        };
        match tokio::time::timeout_at(deadline, shutdown).await {
            Ok(()) => {
                self.task.take();
                Ok(())
            }
            Err(_) => {
                // deadline 已耗尽后，安全状态必须立即可见；abort 只发取消，不能再
                // 无界 await 一个不协作的 main/child task。
                self.cleanup.fail_close_all();
                if let Some(task) = self.task.take() {
                    task.abort();
                }
                Err(RemoteLinkError::ShutdownTimedOut)
            }
        }
    }

    pub(crate) fn observed_failure_code(&self) -> Option<String> {
        self.health_rx.borrow().clone().or_else(|| {
            (!*self.cancel.borrow()
                && self
                    .task
                    .as_ref()
                    .is_some_and(tokio::task::JoinHandle::is_finished))
            .then(|| REMOTE_LINK_ACTOR_EXITED.to_owned())
        })
    }

    #[cfg(test)]
    pub(crate) fn with_shutdown_timeout_for_test(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub(crate) fn pending_for_shutdown_test(core: Weak<RuntimeCore>, timeout: Duration) -> Self {
        let (cancel, _cancel_rx) = watch::channel(false);
        let (_health_tx, health_rx) = watch::channel(None);
        Self {
            cancel,
            task: Some(tokio::spawn(std::future::pending())),
            health_rx,
            cleanup: Arc::new(RemoteLinkConnectionCleanup::new(core)),
            tasks: Arc::new(RemoteLinkTaskTracker::default()),
            shutdown_timeout: REMOTE_LINK_SHUTDOWN_DEADLINE,
        }
        .with_shutdown_timeout_for_test(timeout)
    }

    #[cfg(test)]
    pub(crate) async fn slow_main_for_shutdown_test(
        core: Weak<RuntimeCore>,
        timeout: Duration,
        drop_delay: Duration,
    ) -> Self {
        let (cancel, _cancel_rx) = watch::channel(false);
        let (_health_tx, health_rx) = watch::channel(None);
        let cleanup = Arc::new(RemoteLinkConnectionCleanup::new(core));
        let tasks = Arc::new(RemoteLinkTaskTracker::default());
        let started = Arc::new(Notify::new());
        let task = tokio::spawn({
            let tasks = Arc::clone(&tasks);
            let started = Arc::clone(&started);
            async move {
                let _task_guard = tasks.track();
                let _slow_drop = SlowShutdownDrop(drop_delay);
                started.notify_one();
                std::future::pending::<()>().await;
            }
        });
        started.notified().await;
        Self {
            cancel,
            task: Some(task),
            health_rx,
            cleanup,
            tasks,
            shutdown_timeout: timeout,
        }
    }

    #[cfg(test)]
    pub(crate) async fn slow_child_for_shutdown_test(
        core: Weak<RuntimeCore>,
        timeout: Duration,
        drop_delay: Duration,
    ) -> Self {
        let (cancel, mut cancel_rx) = watch::channel(false);
        let (_health_tx, health_rx) = watch::channel(None);
        let cleanup = Arc::new(RemoteLinkConnectionCleanup::new(core));
        let tasks = Arc::new(RemoteLinkTaskTracker::default());
        let started = Arc::new(Notify::new());
        let task = tokio::spawn({
            let tasks = Arc::clone(&tasks);
            let started = Arc::clone(&started);
            async move {
                let mut children = JoinSet::new();
                let task_guard = tasks.track();
                children.spawn(async move {
                    let _task_guard = task_guard;
                    let _slow_drop = SlowShutdownDrop(drop_delay);
                    started.notify_one();
                    std::future::pending::<()>().await;
                });
                while !*cancel_rx.borrow() {
                    if cancel_rx.changed().await.is_err() {
                        break;
                    }
                }
            }
        });
        started.notified().await;
        Self {
            cancel,
            task: Some(task),
            health_rx,
            cleanup,
            tasks,
            shutdown_timeout: timeout,
        }
    }

    #[cfg(test)]
    pub(crate) fn connection_ids_for_test(&self) -> Vec<ConnectionId> {
        self.cleanup.snapshot()
    }
}

#[cfg(test)]
struct SlowShutdownDrop(Duration);

#[cfg(test)]
impl Drop for SlowShutdownDrop {
    fn drop(&mut self) {
        std::thread::sleep(self.0);
    }
}

impl Drop for RemoteLinkOwner {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.cleanup.fail_close_all();
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_remote_link(
    machine_route: MachineRouteId,
    store: RuntimeStoreHandle,
    lane: BusinessTransportLane,
    core: Weak<RuntimeCore>,
    sealer: Arc<dyn DirectedReplySealer>,
    publisher: Arc<dyn RemoteStreamPublisher>,
    key_control: Arc<dyn AuthenticatedKeyControlIngressHandler>,
    mut ingress_mode: RemoteLinkIngressMode,
    mut cancel: watch::Receiver<bool>,
    cleanup: Arc<RemoteLinkConnectionCleanup>,
    tasks: Arc<RemoteLinkTaskTracker>,
) {
    let dispatcher = RemoteIngressDispatcher::new(machine_route, store);
    let mut pump = RemoteReplyPump::new(lane, sealer).with_stream_publisher(Arc::clone(&publisher));
    let mut connections = Vec::<RemoteConnection>::new();
    let mut core_cursor = 0_usize;
    let mut dispatches = JoinSet::<CoreDispatchCompletion>::new();

    'actor: loop {
        if *cancel.borrow() {
            break;
        }
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            }
            event = pump.next_transport_event() => {
                match event {
                    Ok(Some(BusinessTransportEvent::Send(send))) => {
                        let device_route = send.device_route;
                        let dispatch = tokio::select! {
                            biased;
                            changed = cancel.changed() => {
                                if changed.is_err() || *cancel.borrow() {
                                    break 'actor;
                                }
                                continue;
                            }
                            dispatch = dispatch_send(
                                machine_route,
                                &dispatcher,
                                &core,
                                &mut pump,
                                &mut connections,
                                &mut dispatches,
                                &cleanup,
                                &tasks,
                                publisher.as_ref(),
                                key_control.as_ref(),
                                &mut ingress_mode,
                                send,
                            ) => dispatch,
                        };
                        if let Err(error) = dispatch {
                            if error.requires_device_isolation()
                                && let Some(core) = core.upgrade()
                            {
                                disconnect_device(
                                    core.as_ref(),
                                    &cleanup,
                                    &mut pump,
                                    &mut connections,
                                    device_route,
                                )
                                .await;
                            }
                            // Untrusted frame errors are per-frame fail-close; the authenticated
                            // MachineLink remains available for other devices/conversations.
                            crate::diag::log(
                                "remote_link_ingress",
                                &format!("status=rejected code={}", error.code()),
                            );
                        }
                    }
                    Ok(Some(BusinessTransportEvent::RouteAccepted(_))) => {
                        // Transport-only state: never synthesize Runtime success.
                    }
                    Ok(Some(BusinessTransportEvent::GenerationReplaced { .. })) => {
                        if let Err(error) = publisher.notify_reconnected().await {
                            crate::diag::log(
                                "remote_link_publication_reconnect",
                                &format!("status=blocked code={}", error.code()),
                            );
                            break 'actor;
                        }
                        abort_and_join_dispatches(&mut dispatches).await;
                        disconnect_all(&core, &cleanup, &mut connections).await;
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            tagged = next_core_event(&mut connections, &mut core_cursor), if !connections.is_empty() => {
                let forwarded = tokio::select! {
                    biased;
                    changed = cancel.changed() => {
                        if changed.is_err() || *cancel.borrow() {
                            break 'actor;
                        }
                        continue;
                    }
                    forwarded = forward_core_event(&mut pump, tagged) => forwarded,
                };
                if let Err((connection_id, error)) = forwarded {
                    crate::diag::log(
                        "remote_link_egress",
                        &format!("status=disconnected code={}", error.code()),
                    );
                    pump.remove_connection(connection_id);
                    disconnect_one(&core, &cleanup, &mut connections, connection_id).await;
                }
            }
            completion = dispatches.join_next(), if !dispatches.is_empty() => {
                match completion {
                    Some(Ok(completion)) => {
                        if !completion.succeeded
                            || completion.generation != pump.lane.current_generation()
                        {
                            pump.remove_exact(
                                completion.connection_id,
                                &completion.message_id,
                                completion.generation,
                            );
                            pump.remove_connection(completion.connection_id);
                            disconnect_one(
                                &core,
                                &cleanup,
                                &mut connections,
                                completion.connection_id,
                            )
                            .await;
                        }
                    }
                    Some(Err(error)) => {
                        crate::diag::log(
                            "remote_link_dispatch",
                            &format!("status=panicked error={error}"),
                        );
                        break 'actor;
                    }
                    None => {}
                }
            }
        }
    }
    abort_and_join_dispatches(&mut dispatches).await;
    disconnect_all(&core, &cleanup, &mut connections).await;
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_send(
    machine_route: MachineRouteId,
    dispatcher: &RemoteIngressDispatcher,
    core: &Weak<RuntimeCore>,
    pump: &mut RemoteReplyPump,
    connections: &mut Vec<RemoteConnection>,
    dispatches: &mut JoinSet<CoreDispatchCompletion>,
    cleanup: &RemoteLinkConnectionCleanup,
    tasks: &Arc<RemoteLinkTaskTracker>,
    publisher: &dyn RemoteStreamPublisher,
    key_control: &dyn AuthenticatedKeyControlIngressHandler,
    ingress_mode: &mut RemoteLinkIngressMode,
    send: RouteSend,
) -> Result<(), RemoteLinkError> {
    let verified = dispatcher.verify_send(send).await?;
    let current = dispatcher.recheck_current(verified).await?;
    let admitted = dispatcher.admit_replay(current).await?;
    let route = admitted
        .into_route()?
        .ok_or(RemoteDispatchError::ReplayRejected)?;
    let admitted_business =
        match route_ingress_before_core_with_mode(route, key_control, core, ingress_mode).await? {
            PreCoreIngressOutcome::Business(activated) => *activated,
            PreCoreIngressOutcome::KeyControl(KeyControlIngressOutcome::Consumed) => return Ok(()),
            PreCoreIngressOutcome::KeyControl(KeyControlIngressOutcome::DirectedReply(reply)) => {
                return pump.forward_key_control(*reply).await;
            }
        };
    let (activated, business_admission) = admitted_business.into_parts();
    let core = core.upgrade().ok_or(RemoteLinkError::CoreUnavailable)?;

    let message_id = activated.envelope().message_id.clone();
    let RuntimeMessage::Request(request) = &activated.envelope().body else {
        return Err(RemoteLinkError::CoreRejected);
    };
    let route_lifecycle = ReplyRouteLifecycle::for_request(request);
    if let Some(target) = subscription_target(request)? {
        publisher.prepare_subscription(target).await?;
    }
    let (principal, authorization, envelope, device_route, request_route, replay) =
        activated.into_parts();
    let request_principal = principal.request_principal();
    let connection_key = connection_key(&authorization);
    let mut created_connection = false;
    let connection_id = match connections
        .iter()
        .find(|connection| connection.key == connection_key)
    {
        Some(connection) => {
            drop(principal);
            connection.id
        }
        None => {
            disconnect_device(core.as_ref(), cleanup, pump, connections, device_route).await;
            if connections.len() >= REMOTE_CONNECTION_CAPACITY {
                return Err(RemoteLinkError::ConnectionCapacity);
            }
            let (core_tx, core_rx) = mpsc::channel(CORE_WRITER_HANDOFF_CAPACITY);
            let sink = ConnectionSink::new(core_tx)
                .with_framing_profile(ConnectionFramingProfile::CompactTransfer);
            let connection_id = match principal {
                RemotePrincipalActivation::NewOrExisting(principal) => {
                    core.connect(principal, sink)
                }
                RemotePrincipalActivation::SelfRevocationRetry(admission) => {
                    core.connect_remote_self_revocation_retry(admission, sink)
                }
            }
            .map_err(|_| RemoteLinkError::CoreRejected)?;
            connections.push(RemoteConnection {
                key: connection_key,
                id: connection_id,
                core_rx,
            });
            cleanup.register(connection_id);
            created_connection = true;
            connection_id
        }
    };
    let directed_route = DirectedReplyRoute {
        machine_route,
        device_route,
        request_route,
    };
    let (route_bind_result, transition_snapshot) = match business_admission {
        BusinessIngressAdmission::BusinessReady => (
            pump.bind(
                connection_id,
                message_id.clone(),
                directed_route,
                authorization,
                route_lifecycle,
            ),
            None,
        ),
        BusinessIngressAdmission::TransitionSnapshot(permit) => (
            pump.bind_transition_snapshot(
                connection_id,
                message_id.clone(),
                directed_route,
                authorization,
                route_lifecycle,
                permit.as_ref().clone(),
            ),
            Some(*permit),
        ),
    };
    let route_bind = match route_bind_result {
        Ok(route_bind) => route_bind,
        Err(error) => {
            if created_connection {
                disconnect_one(&Arc::downgrade(&core), cleanup, connections, connection_id).await;
            }
            return Err(error);
        }
    };
    if route_bind == ReplyRouteBind::ExistingExact {
        // 同 generation 的 exact in-flight Relay retry 复用现有 Core dispatch。首个
        // terminal reply 完成后 route 才释放；随后到达的 exact retry会重新进入
        // RuntimeCore durable idempotency，而不会在此并发生成第二份 reply writer。
        return Ok(());
    }
    if dispatches.len() >= CORE_DISPATCH_CAPACITY {
        pump.remove_exact(connection_id, &message_id, pump.lane.current_generation());
        if created_connection {
            disconnect_one(&Arc::downgrade(&core), cleanup, connections, connection_id).await;
        }
        return Err(RemoteLinkError::CoreDispatchCapacity);
    }
    let generation = pump.lane.current_generation();
    let task_guard = tasks.track();
    dispatches.spawn(async move {
        let _task_guard = task_guard;
        let succeeded = match transition_snapshot {
            Some(permit) => core
                .handle_transition_snapshot_envelope(
                    connection_id,
                    request_principal,
                    envelope,
                    permit,
                )
                .await
                .is_ok(),
            None => core
                .handle_remote_envelope(connection_id, request_principal, envelope, replay)
                .await
                .is_ok(),
        };
        CoreDispatchCompletion {
            connection_id,
            message_id,
            generation,
            succeeded,
        }
    });
    Ok(())
}

fn subscription_target(
    request: &RuntimeRequest,
) -> Result<Option<RuntimeStreamTarget>, RemoteLinkError> {
    let conversation = |conversation_id: &agentdeck_protocol::runtime::ConversationId| {
        RuntimeId::parse_canonical(RuntimeIdKind::Conversation, conversation_id.as_str())
            .map(RuntimeStreamTarget::Conversation)
            .map_err(|_| RemoteLinkError::CoreRejected)
    };
    match request {
        RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Catalog { .. },
        }
        | RuntimeRequest::Backfill(BackfillRequest::Catalog { .. }) => {
            Ok(Some(RuntimeStreamTarget::Catalog))
        }
        RuntimeRequest::Subscribe {
            inner_cursor:
                RuntimeInnerCursor::Conversation {
                    conversation_id, ..
                },
        }
        | RuntimeRequest::Backfill(BackfillRequest::Conversation {
            conversation_id, ..
        }) => conversation(conversation_id).map(Some),
        _ => Ok(None),
    }
}

/// authenticated ingress 的最后一道 pre-Core 边界。Control 在这里消费且永远不调用
/// RuntimeCore；business 必须先通过 transition fence，才允许 upgrade/register/activate。
pub(crate) enum PreCoreIngressOutcome {
    Business(Box<AdmittedBusinessIngress>),
    KeyControl(KeyControlIngressOutcome),
}

/// 单个 request 的 Store-issued admission 与已规范化 Core ingress。transition snapshot
/// capability 不会提升 actor mode，也不会缓存为整个 connection 的业务权限。
pub(crate) struct AdmittedBusinessIngress {
    activated: ActivatedRemoteIngress,
    admission: BusinessIngressAdmission,
}

impl AdmittedBusinessIngress {
    fn into_parts(self) -> (ActivatedRemoteIngress, BusinessIngressAdmission) {
        (self.activated, self.admission)
    }
}

#[cfg(test)]
pub(crate) async fn route_ingress_before_core(
    route: RemoteIngressRoute,
    key_control: &dyn AuthenticatedKeyControlIngressHandler,
    core: &Weak<RuntimeCore>,
) -> Result<PreCoreIngressOutcome, RemoteLinkError> {
    let mut mode = RemoteLinkIngressMode::BusinessReady;
    route_ingress_before_core_with_mode(route, key_control, core, &mut mode).await
}

pub(crate) async fn route_ingress_before_core_with_mode(
    route: RemoteIngressRoute,
    key_control: &dyn AuthenticatedKeyControlIngressHandler,
    core: &Weak<RuntimeCore>,
    mode: &mut RemoteLinkIngressMode,
) -> Result<PreCoreIngressOutcome, RemoteLinkError> {
    match route {
        RemoteIngressRoute::KeyControl(ingress) => {
            let outcome = key_control.consume(ingress).await?;
            Ok(PreCoreIngressOutcome::KeyControl(outcome))
        }
        RemoteIngressRoute::Business(dispatchable) => {
            // ControlPlaneOnly 是 actor-local 的第一道 capability gate。只有 Store
            // 明确返回 BusinessReady 才能单向提升；TransitionSnapshot 是 exact request
            // capability，消费后仍保持 control-only。
            let admission = key_control
                .authorize_business_ingress(dispatchable.authorization(), dispatchable.envelope())
                .await?;
            if matches!(admission, BusinessIngressAdmission::BusinessReady)
                && matches!(*mode, RemoteLinkIngressMode::ControlPlaneOnly)
            {
                *mode = RemoteLinkIngressMode::BusinessReady;
            }
            let core = core.upgrade().ok_or(RemoteLinkError::CoreUnavailable)?;
            Ok(PreCoreIngressOutcome::Business(Box::new(
                AdmittedBusinessIngress {
                    activated: dispatchable.activate(&core)?,
                    admission,
                },
            )))
        }
    }
}

pub(super) fn connection_key(authorization: &RemoteReplyAuthorization) -> DeviceConnectionKey {
    DeviceConnectionKey {
        machine_trust_domain: authorization.machine_trust_domain(),
        machine_route: authorization.machine_route(),
        device_route: authorization.device_route(),
        grant_serial: authorization.grant_serial().value(),
        device_sign_fingerprint: authorization.device_sign_fingerprint(),
    }
}

async fn next_core_event(
    connections: &mut [RemoteConnection],
    cursor: &mut usize,
) -> TaggedCoreEvent {
    poll_fn(|context| {
        let len = connections.len();
        if len == 0 {
            return Poll::Pending;
        }
        let start = *cursor % len;
        for offset in 0..len {
            let index = (start + offset) % len;
            let connection_id = connections[index].id;
            match connections[index].core_rx.poll_recv(context) {
                Poll::Ready(Some(write)) => {
                    *cursor = (index + 1) % len;
                    return Poll::Ready(TaggedCoreEvent::Write {
                        connection_id,
                        write,
                    });
                }
                Poll::Ready(None) => {
                    *cursor = index % len;
                    return Poll::Ready(TaggedCoreEvent::Closed { connection_id });
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    })
    .await
}

async fn forward_core_event(
    pump: &mut RemoteReplyPump,
    event: TaggedCoreEvent,
) -> Result<(), (ConnectionId, RemoteLinkError)> {
    match event {
        TaggedCoreEvent::Write {
            connection_id,
            write,
        } => pump
            .forward(connection_id, write)
            .await
            .map_err(|error| (connection_id, error)),
        TaggedCoreEvent::Closed { connection_id } => {
            Err((connection_id, RemoteLinkError::CoreUnavailable))
        }
    }
}

async fn abort_and_join_dispatches(dispatches: &mut JoinSet<CoreDispatchCompletion>) {
    dispatches.abort_all();
    while dispatches.join_next().await.is_some() {}
}

async fn disconnect_device(
    core: &RuntimeCore,
    cleanup: &RemoteLinkConnectionCleanup,
    pump: &mut RemoteReplyPump,
    connections: &mut Vec<RemoteConnection>,
    device_route: DeviceRouteId,
) {
    let mut index = 0;
    while index < connections.len() {
        if connections[index].key.device_route != device_route {
            index += 1;
            continue;
        }
        let connection = connections.swap_remove(index);
        let connection_id = connection.id;
        pump.remove_connection(connection_id);
        drop(connection);
        core.disconnect(connection_id).await;
        cleanup.unregister(connection_id);
    }
}

async fn disconnect_one(
    core: &Weak<RuntimeCore>,
    cleanup: &RemoteLinkConnectionCleanup,
    connections: &mut Vec<RemoteConnection>,
    connection_id: ConnectionId,
) {
    if let Some(index) = connections
        .iter()
        .position(|connection| connection.id == connection_id)
    {
        drop(connections.swap_remove(index));
    }
    if let Some(core) = core.upgrade() {
        core.disconnect(connection_id).await;
    }
    cleanup.unregister(connection_id);
}

async fn disconnect_all(
    core: &Weak<RuntimeCore>,
    cleanup: &RemoteLinkConnectionCleanup,
    connections: &mut Vec<RemoteConnection>,
) {
    let core = core.upgrade();
    for connection in connections.drain(..) {
        let connection_id = connection.id;
        drop(connection);
        if let Some(core) = core.as_ref() {
            core.disconnect(connection_id).await;
        }
        cleanup.unregister(connection_id);
    }
}
