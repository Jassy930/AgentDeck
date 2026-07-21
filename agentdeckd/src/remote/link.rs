//! 唯一 MachineLink 上的 Runtime dispatch actor。
//!
//! RemoteLink 只拥有易失的 generation、replay window、connection 与 reply-route 映射；
//! canonical conversation/command/receipt 状态始终留在 [`RuntimeCore`] / Runtime Store。

use std::future::poll_fn;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;
use std::time::Duration;

use agentdeck_crypto::replay::ReplayWindow;
use agentdeck_protocol::e2ee::{KeyPurpose, SignedSealedBlobV1};
use agentdeck_protocol::relay_v2::frame::{Reply, SealedBlob, Send as RouteSend};
use agentdeck_protocol::relay_v2::{DeviceRouteId, MachineRouteId, RequestRouteId};
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    MAX_RUNTIME_JSON_FRAME_BYTES, RuntimeEnvelope, RuntimeMessage, RuntimeReply, RuntimeRequest,
};
use async_trait::async_trait;
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::runtime::store::{RemoteReplyAuthorization, RuntimeStoreHandle};
use crate::runtime::{ConnectionId, ConnectionSink, ConnectionWrite, RuntimeCore};

use super::dispatch::{RemoteDispatchError, RemoteIngressDispatcher};
use super::transport::{BusinessTransportEvent, BusinessTransportLane, RemoteTransportError};

const REPLY_ROUTE_CAPACITY: usize = 512;
const REMOTE_CONNECTION_CAPACITY: usize = 128;
const REMOTE_REPLAY_KEY_CAPACITY: usize = 256;
const CORE_WRITER_HANDOFF_CAPACITY: usize = 8;
const CORE_DISPATCH_CAPACITY: usize = 128;
const REMOTE_LINK_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct DirectedReplyRoute {
    pub(crate) machine_route: MachineRouteId,
    pub(crate) device_route: DeviceRouteId,
    pub(crate) request_route: RequestRouteId,
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
    ) -> Result<SignedSealedBlobV1, RemoteLinkError>;
}

/// P4.5 publication/outbox 的最小挂载点。成功必须表示 publisher 自己的 durable/Relay
/// 边界已经完成；P4.4 默认实现永远失败，因此不会提前 ACK Stream。
#[async_trait]
pub(crate) trait RemoteStreamPublisher: Send + Sync {
    fn admission_ready(&self) -> bool;

    async fn publish_exact(&self, runtime_bytes: Arc<[u8]>) -> Result<(), RemoteLinkError>;
}

pub(crate) struct UnavailableDirectedReplySealer;

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
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
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
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RemoteLinkError {
    #[error("remote ingress failed: {0}")]
    Dispatch(#[from] RemoteDispatchError),
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
    #[error("remote replay-key capacity is exhausted")]
    ReplayCapacity,
    #[error("remote Core dispatch capacity is exhausted")]
    CoreDispatchCapacity,
    #[error("remote reply authorization does not match its route")]
    ReplyAuthorizationMismatch,
    #[error("directed reply sealer returned an invalid reply binding")]
    InvalidReplySeal,
    #[error("RuntimeCore emitted an invalid envelope")]
    InvalidCoreEgress,
    #[cfg(test)]
    #[error("directed reply sealing failed")]
    ReplySealFailed,
    #[error("directed reply sealing is not installed")]
    ReplySealUnavailable,
    #[error("stream publisher is not installed")]
    StreamPublisherUnavailable,
    #[error("remote link actor is closed")]
    Closed,
    #[error("remote link did not quiesce before the shutdown deadline")]
    ShutdownTimedOut,
}

impl RemoteLinkError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Dispatch(error) => error.code(),
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
            Self::ReplayCapacity => "daemon.remote.link.replay_capacity",
            Self::CoreDispatchCapacity => "daemon.remote.link.core_dispatch_capacity",
            Self::ReplyAuthorizationMismatch => "daemon.remote.link.reply_authorization_mismatch",
            Self::InvalidReplySeal => "daemon.remote.link.reply_seal_invalid",
            Self::InvalidCoreEgress => "daemon.remote.link.invalid_core_egress",
            #[cfg(test)]
            Self::ReplySealFailed => "daemon.remote.link.reply_seal_failed",
            Self::ReplySealUnavailable => "daemon.remote.link.reply_seal_unavailable",
            Self::StreamPublisherUnavailable => "daemon.remote.link.stream_publisher_unavailable",
            Self::Closed => "daemon.remote.link.closed",
            Self::ShutdownTimedOut => "daemon.remote.link.shutdown_timed_out",
        }
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
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReplyRouteLifecycle {
    OneShot,
    UntilSyncComplete,
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
    ) -> Result<(), RemoteLinkError> {
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
            {
                return Err(RemoteLinkError::ReplyAuthorizationMismatch);
            }
            return Ok(());
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
        });
        Ok(())
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

    /// ACK 是严格的末端边界：Reply 只有 seal + 同 generation Relay flush 成功后 ACK；
    /// Stream 只有 publisher 成功后 ACK；未知 route、Request、任何错误都 drop write。
    pub(crate) async fn forward(
        &mut self,
        connection_id: ConnectionId,
        write: ConnectionWrite,
    ) -> Result<(), RemoteLinkError> {
        let bytes = write.shared_bytes();
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
                let completes_route = binding.lifecycle.completes(&reply);
                let sealed = self
                    .sealer
                    .seal_exact(&binding.authorization, binding.route, bytes)
                    .await?;
                let sealed = validated_reply_wire(&binding.authorization, sealed)?;
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
                    self.remove_exact(connection_id, &envelope.message_id, binding.generation);
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
    let sealed = validated_reply_wire(&authorization, sealed)?;
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

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReplayKey {
    device_route: DeviceRouteId,
    key_epoch: u64,
    key_directory_revision: u64,
}

struct ReplayEntry {
    key: ReplayKey,
    window: ReplayWindow,
}

#[derive(Clone, Eq, PartialEq)]
struct DeviceConnectionKey {
    device_route: DeviceRouteId,
    grant_serial: u64,
    authorization_hash: [u8; 32],
    key_directory_revision: u64,
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
    cleanup: Arc<RemoteLinkConnectionCleanup>,
    tasks: Arc<RemoteLinkTaskTracker>,
    shutdown_timeout: Duration,
}

impl RemoteLinkOwner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        machine_route: MachineRouteId,
        store: RuntimeStoreHandle,
        lane: BusinessTransportLane,
        core: Weak<RuntimeCore>,
        sealer: Arc<dyn DirectedReplySealer>,
        publisher: Arc<dyn RemoteStreamPublisher>,
    ) -> Result<Self, RemoteLinkError> {
        if !sealer.admission_ready() {
            return Err(RemoteLinkError::ReplySealUnavailable);
        }
        if !publisher.admission_ready() {
            return Err(RemoteLinkError::StreamPublisherUnavailable);
        }
        let (cancel, cancel_rx) = watch::channel(false);
        let cleanup = Arc::new(RemoteLinkConnectionCleanup::new(core.clone()));
        let tasks = Arc::new(RemoteLinkTaskTracker::default());
        let task = tokio::spawn(run_remote_link(
            machine_route,
            store,
            lane,
            core,
            sealer,
            publisher,
            cancel_rx,
            Arc::clone(&cleanup),
            Arc::clone(&tasks),
        ));
        Ok(Self {
            cancel,
            task: Some(task),
            cleanup,
            tasks,
            shutdown_timeout: REMOTE_LINK_SHUTDOWN_DEADLINE,
        })
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), RemoteLinkError> {
        self.cancel.send_replace(true);
        let deadline = tokio::time::Instant::now() + self.shutdown_timeout;
        if let Some(task) = self.task.as_mut()
            && tokio::time::timeout_at(deadline, &mut *task).await.is_err()
        {
            task.abort();
            let _ = task.await;
            self.task.take();
            self.tasks.wait_for_quiescence().await;
            self.cleanup.fail_close_all();
            return Err(RemoteLinkError::ShutdownTimedOut);
        }
        self.task.take();
        self.tasks.wait_for_quiescence().await;
        if tokio::time::timeout_at(deadline, self.cleanup.disconnect_all())
            .await
            .is_err()
        {
            self.cleanup.fail_close_all();
            return Err(RemoteLinkError::ShutdownTimedOut);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_shutdown_timeout_for_test(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub(crate) fn pending_for_shutdown_test(core: Weak<RuntimeCore>, timeout: Duration) -> Self {
        let (cancel, _cancel_rx) = watch::channel(false);
        Self {
            cancel,
            task: Some(tokio::spawn(std::future::pending())),
            cleanup: Arc::new(RemoteLinkConnectionCleanup::new(core)),
            tasks: Arc::new(RemoteLinkTaskTracker::default()),
            shutdown_timeout: REMOTE_LINK_SHUTDOWN_DEADLINE,
        }
        .with_shutdown_timeout_for_test(timeout)
    }

    #[cfg(test)]
    pub(crate) fn connection_ids_for_test(&self) -> Vec<ConnectionId> {
        self.cleanup.snapshot()
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
    mut cancel: watch::Receiver<bool>,
    cleanup: Arc<RemoteLinkConnectionCleanup>,
    tasks: Arc<RemoteLinkTaskTracker>,
) {
    let dispatcher = RemoteIngressDispatcher::new(machine_route, store);
    let mut pump = RemoteReplyPump::new(lane, sealer).with_stream_publisher(publisher);
    let mut replays = Vec::<ReplayEntry>::new();
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
                                &mut replays,
                                &mut connections,
                                &mut dispatches,
                                &cleanup,
                                &tasks,
                                send,
                            ) => dispatch,
                        };
                        if let Err(error) = dispatch {
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
    replays: &mut Vec<ReplayEntry>,
    connections: &mut Vec<RemoteConnection>,
    dispatches: &mut JoinSet<CoreDispatchCompletion>,
    cleanup: &RemoteLinkConnectionCleanup,
    tasks: &Arc<RemoteLinkTaskTracker>,
    send: RouteSend,
) -> Result<(), RemoteLinkError> {
    if dispatches.len() >= CORE_DISPATCH_CAPACITY {
        return Err(RemoteLinkError::CoreDispatchCapacity);
    }
    let replay_key = replay_key(&send)?;
    let mut candidate = replays
        .iter()
        .find(|entry| entry.key == replay_key)
        .map(|entry| entry.window.clone())
        .unwrap_or_default();
    let verified = dispatcher.verify_send(send.clone(), &candidate).await?;
    let current = dispatcher.recheck_current(verified).await?;
    let core = core.upgrade().ok_or(RemoteLinkError::CoreUnavailable)?;
    let activated = current.activate(&core, &mut candidate)?;

    let message_id = activated.envelope().message_id.clone();
    let RuntimeMessage::Request(request) = &activated.envelope().body else {
        return Err(RemoteLinkError::CoreRejected);
    };
    let route_lifecycle = ReplyRouteLifecycle::for_request(request);
    let (principal, authorization, envelope, device_route, request_route) = activated.into_parts();
    let connection_key = connection_key(&authorization);
    let mut created_connection = false;
    let connection_id = match connections
        .iter()
        .find(|connection| connection.key == connection_key)
    {
        Some(connection) => connection.id,
        None => {
            disconnect_device(core.as_ref(), cleanup, pump, connections, device_route).await;
            if connections.len() >= REMOTE_CONNECTION_CAPACITY {
                return Err(RemoteLinkError::ConnectionCapacity);
            }
            let (core_tx, core_rx) = mpsc::channel(CORE_WRITER_HANDOFF_CAPACITY);
            let connection_id = core
                .connect(principal, ConnectionSink::new(core_tx))
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
    if let Err(error) = pump.bind(
        connection_id,
        message_id.clone(),
        DirectedReplyRoute {
            machine_route,
            device_route,
            request_route,
        },
        authorization,
        route_lifecycle,
    ) {
        if created_connection {
            disconnect_one(&Arc::downgrade(&core), cleanup, connections, connection_id).await;
        }
        return Err(error);
    }
    if let Err(error) = commit_replay(replays, replay_key, candidate) {
        pump.remove_exact(connection_id, &message_id, pump.lane.current_generation());
        if created_connection {
            disconnect_one(&Arc::downgrade(&core), cleanup, connections, connection_id).await;
        }
        return Err(error);
    }
    let generation = pump.lane.current_generation();
    let task_guard = tasks.track();
    dispatches.spawn(async move {
        let _task_guard = task_guard;
        let succeeded = core.handle_envelope(connection_id, envelope).await.is_ok();
        CoreDispatchCompletion {
            connection_id,
            message_id,
            generation,
            succeeded,
        }
    });
    Ok(())
}

fn replay_key(send: &RouteSend) -> Result<ReplayKey, RemoteLinkError> {
    let signed = SignedSealedBlobV1::from_wire_bytes(&send.sealed_blob.0)
        .map_err(|_| RemoteDispatchError::InvalidSealedBlob)?;
    if signed.inner.key_id.purpose != KeyPurpose::DeviceCommandTx
        || signed.inner.key_epoch == 0
        || signed.inner.key_directory_revision == 0
    {
        return Err(RemoteDispatchError::InvalidKeyBinding.into());
    }
    Ok(ReplayKey {
        device_route: send.device_route,
        key_epoch: signed.inner.key_epoch,
        key_directory_revision: signed.inner.key_directory_revision,
    })
}

fn commit_replay(
    replays: &mut Vec<ReplayEntry>,
    key: ReplayKey,
    window: ReplayWindow,
) -> Result<(), RemoteLinkError> {
    if let Some(existing) = replays.iter_mut().find(|entry| entry.key == key) {
        existing.window = window;
        return Ok(());
    }
    // A validated new key revision makes prior keys for the same device non-current; removing
    // those volatile windows is safe because Store final recheck already rejects their frames.
    replays.retain(|entry| entry.key.device_route != key.device_route);
    if replays.len() >= REMOTE_REPLAY_KEY_CAPACITY {
        return Err(RemoteLinkError::ReplayCapacity);
    }
    replays.push(ReplayEntry { key, window });
    Ok(())
}

fn connection_key(authorization: &RemoteReplyAuthorization) -> DeviceConnectionKey {
    DeviceConnectionKey {
        device_route: authorization.device_route(),
        grant_serial: authorization.grant_serial().value(),
        authorization_hash: authorization.authorization_hash(),
        key_directory_revision: authorization.key_directory_revision().value(),
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
