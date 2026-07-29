//! Relay v2 单 actor 路由入口。
//!
//! 所有 stream mutation 都在本 actor 中线性裁决；SQLite 可以 await，per-connection
//! socket 永远不能。每条命令在出队和 Store 返回后都重新验证 active authorization，
//! replay page 则由短生命周期 task 拉取、回到 actor 后再做 epoch/current 复核与 FIFO 入队。

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_INVALID_GRANT, RELAY_AUTH_REVOKED, RELAY_DISK_LOW, RELAY_FRAME_TOO_LARGE,
    RELAY_QUOTA_EXCEEDED, RELAY_REPLAY_CURSOR_INVALID, RELAY_ROUTE_CONFLICT, RELAY_ROUTE_FORBIDDEN,
    RELAY_ROUTE_NOT_FOUND, RELAY_STORE_UNAVAILABLE, RELAY_STREAM_GENERATION_STALE,
    RELAY_STREAM_OUT_OF_ORDER, RELAY_VERSION_UNSUPPORTED,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Ack, ClosePairRoute, Gap, GrantCommitted, InstallGrant, OpenPairRoute, PairData,
    Ping, Pong, Publish, RegisterStream, ReplayComplete, Reply, RetireMachine, RouteAccepted, Send,
    Subscribe, Unsubscribe,
};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, MAX_FRAME_BYTES, MachineRouteId,
    OpaqueRouteFrame, PairRouteId, RELAY_PROTOCOL_VERSION, RelayFailure, RelayFrameBody,
    StreamCursor, StreamGenerationId, StreamRouteId, decode, encode,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

use crate::v2::auth::{
    AccessContext, AuthenticationOutcome, AuthorizationCoordinator, AuthorizationLifecycle,
    AuthorizationLifecycleEvent, PairRouteView, PrincipalRoute,
};
use crate::v2::store::{
    AdminPurgeCommit, AdminPurgeCommitRequest, PersistAck, PersistPublish, PersistSubscription,
    PersistUnsubscribe, RelayStoreHandle, StoreError, StreamRegistration, SubscriptionLease,
};

use super::connection::{
    ConnectionCleanup, ConnectionRegistry, ConnectionStateError, LiveDeliveryKind, ReplayAdmission,
    ReplayStart, ReplayStartMode, StreamKey, SubscriptionPhase, TerminalToken,
};
use super::lifecycle::CoreTasks;
use super::pair_route::{PairRouteLimits, PairRouteRegistry};
use super::replay::{
    REPLAY_PAGE_MAX_BYTES, REPLAY_PAGE_MAX_FRAMES, ReplayFetchError, ReplayFetchTicket, ReplayMode,
    ReplayPageReady, fetch_replay_page, initial_replay_ticket, post_terminal_replay_ticket,
};
use super::request_route::{RequestTarget, resolve_reply, resolve_send};
use super::revocation::close_on_terminal_deadline;
use super::writer::{
    ControlWriterReservation, GlobalWriterBudget, NormalWriterReservation, TerminalAdmission,
    TryReserveWriterError, WaitForBudgetError, WriterCloseReason, WriterHandle,
};

pub const DEFAULT_CORE_COMMAND_CAPACITY: usize = 256;
pub const DEFAULT_CORE_INGRESS_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_CONNECTIONS: usize = 4_096;
pub const DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 1024;
pub const DEFAULT_REPLAY_STAGING_PAGES: usize = 2;
pub const DEFAULT_GLOBAL_NORMAL_MAX_FRAMES: usize = 16_384;
pub const DEFAULT_GLOBAL_NORMAL_MAX_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_GLOBAL_CONTROL_MAX_FRAMES: usize = 4_096;
pub const DEFAULT_GLOBAL_CONTROL_MAX_BYTES: usize = 16 * 1024 * 1024;
const CORE_COMMAND_CAPACITY_HARD_MAX: usize = 4_096;
const CORE_INGRESS_BYTES_HARD_MAX: usize = 256 * 1024 * 1024;
const CORE_CONNECTIONS_HARD_MAX: usize = 4_096;
const CORE_SUBSCRIPTIONS_PER_CONNECTION_HARD_MAX: usize = 4_096;
const CORE_REPLAY_STAGING_PAGES_HARD_MAX: usize = 16;
const CORE_GLOBAL_NORMAL_FRAMES_HARD_MAX: usize = 65_536;
const CORE_GLOBAL_NORMAL_BYTES_HARD_MAX: usize = 1024 * 1024 * 1024;
const CORE_GLOBAL_CONTROL_FRAMES_HARD_MAX: usize = 16_384;
const CORE_GLOBAL_CONTROL_BYTES_HARD_MAX: usize = 64 * 1024 * 1024;
const MAX_REPLAY_STORE_BUSY_RETRIES: u8 = 3;
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 20_000;
pub const DEFAULT_HEARTBEAT_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreConfig {
    pub command_capacity: usize,
    pub ingress_bytes: usize,
    pub max_connections: usize,
    pub max_subscriptions_per_connection: usize,
    /// 每个 permit 最多对应 64 frames / 8 MiB 的已物化 replay page。
    pub replay_staging_pages: usize,
    /// 所有 writer queued + in-flight canonical frames 的聚合 hard bound；normal 不能
    /// 消耗 control reserve。
    pub global_normal_max_frames: usize,
    pub global_normal_max_bytes: usize,
    pub global_control_max_frames: usize,
    pub global_control_max_bytes: usize,
    pub pair_route_limits: PairRouteLimits,
    pub heartbeat_interval_ms: u64,
    pub heartbeat_timeout_ms: u64,
    pub initial_now_ms: u64,
    pub nonce_seed: u64,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            command_capacity: DEFAULT_CORE_COMMAND_CAPACITY,
            ingress_bytes: DEFAULT_CORE_INGRESS_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_subscriptions_per_connection: DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION,
            replay_staging_pages: DEFAULT_REPLAY_STAGING_PAGES,
            global_normal_max_frames: DEFAULT_GLOBAL_NORMAL_MAX_FRAMES,
            global_normal_max_bytes: DEFAULT_GLOBAL_NORMAL_MAX_BYTES,
            global_control_max_frames: DEFAULT_GLOBAL_CONTROL_MAX_FRAMES,
            global_control_max_bytes: DEFAULT_GLOBAL_CONTROL_MAX_BYTES,
            pair_route_limits: PairRouteLimits::default(),
            heartbeat_interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS,
            heartbeat_timeout_ms: DEFAULT_HEARTBEAT_TIMEOUT_MS,
            initial_now_ms: 0,
            nonce_seed: 1,
        }
    }
}

impl CoreConfig {
    fn validate(self) -> Result<(), RelayFailure> {
        self.pair_route_limits.validate()?;
        if self.command_capacity == 0
            || self.command_capacity > CORE_COMMAND_CAPACITY_HARD_MAX
            || self.ingress_bytes == 0
            || self.ingress_bytes > CORE_INGRESS_BYTES_HARD_MAX
            || self.max_connections == 0
            || self.max_connections > CORE_CONNECTIONS_HARD_MAX
            || self.max_subscriptions_per_connection == 0
            || self.max_subscriptions_per_connection > CORE_SUBSCRIPTIONS_PER_CONNECTION_HARD_MAX
            || self.replay_staging_pages == 0
            || self.replay_staging_pages > CORE_REPLAY_STAGING_PAGES_HARD_MAX
            || self.global_normal_max_frames == 0
            || self.global_normal_max_frames > CORE_GLOBAL_NORMAL_FRAMES_HARD_MAX
            || self.global_normal_max_bytes == 0
            || self.global_normal_max_bytes > CORE_GLOBAL_NORMAL_BYTES_HARD_MAX
            || self.global_control_max_frames == 0
            || self.global_control_max_frames > CORE_GLOBAL_CONTROL_FRAMES_HARD_MAX
            || self.global_control_max_bytes == 0
            || self.global_control_max_bytes > CORE_GLOBAL_CONTROL_BYTES_HARD_MAX
            || self.heartbeat_interval_ms == 0
            || self.heartbeat_timeout_ms <= self.heartbeat_interval_ms
        {
            return Err(unavailable("invalid Relay Core configuration"));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReplayTicket {
    pub stream: StreamRouteId,
    pub generation: StreamGenerationId,
    /// 客户端提交的 resume cursor；不是把下一序号伪装成 `StreamCursor::At`。
    pub next: StreamCursor,
    /// Subscribe transaction 内冻结的初始 replay high-water。
    pub terminal: StreamCursor,
}

impl fmt::Debug for ReplayTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayTicket")
            .field("stream", &self.stream.redacted())
            .field("generation", &self.generation.redacted())
            .field("next", &self.next)
            .field("terminal", &self.terminal)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    /// Store/state mutation 已完成，但协议没有对应 ACK frame。
    Applied,
    /// `RouteAccepted` 已进入 origin 的有界 FIFO。
    Queued(RouteAccepted),
    /// 初始 replay 边界已冻结并被连接内 FIFO 接纳；frame/terminal 由同一 writer FIFO 输出。
    Replay(ReplayTicket),
    /// Gap frame 已进入 writer，runtime subscription 已暂停。
    Gap(Gap),
    /// mutation 可能已持久化，但 origin writer 无法有界接收结果，连接已关闭。
    Closed,
}

impl fmt::Debug for RouteOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied => formatter.write_str("Applied"),
            Self::Queued(RouteAccepted { accepted }) => match accepted {
                AcceptedRef::Request { request_route } => formatter
                    .debug_struct("QueuedRequest")
                    .field("request", &request_route.redacted())
                    .finish(),
                AcceptedRef::StreamFrame {
                    stream_route,
                    stream_seq,
                } => formatter
                    .debug_struct("QueuedStreamFrame")
                    .field("stream", &stream_route.redacted())
                    .field("stream_seq", stream_seq)
                    .finish(),
                AcceptedRef::PairFrame { pair_route } => formatter
                    .debug_struct("QueuedPairFrame")
                    .field("pair", &pair_route.redacted())
                    .finish(),
            },
            Self::Replay(ticket) => formatter.debug_tuple("Replay").field(ticket).finish(),
            Self::Gap(gap) => formatter
                .debug_struct("Gap")
                .field("stream", &gap.stream_route.redacted())
                .field("generation", &gap.generation.redacted())
                .field("needed", &gap.need_stream_seq)
                .field("oldest", &gap.oldest_stream_seq)
                .finish(),
            Self::Closed => formatter.write_str("Closed"),
        }
    }
}

#[derive(Clone)]
pub struct RelayCore {
    tx: mpsc::Sender<CoreCommand>,
    ingress: Arc<Semaphore>,
}

impl fmt::Debug for RelayCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RelayCore").finish_non_exhaustive()
    }
}

enum CoreCommand {
    Attach {
        connection: ConnectionInstanceId,
        writer: WriterHandle,
        reply: oneshot::Sender<Result<(), RelayFailure>>,
    },
    Activate {
        access: AccessContext,
        reply: oneshot::Sender<Result<(), RelayFailure>>,
    },
    ActivateAuthentication {
        outcome: AuthenticationOutcome,
        reply: oneshot::Sender<Result<(), RelayFailure>>,
    },
    PairRouteView {
        pair_route: PairRouteId,
        reply: oneshot::Sender<Result<PairRouteView, RelayFailure>>,
    },
    Handle {
        access: AccessContext,
        frame: OpaqueRouteFrame,
        _permit: OwnedSemaphorePermit,
        reply: oneshot::Sender<Result<RouteOutcome, RelayFailure>>,
    },
    ReplayReady {
        ticket: ReplayFetchTicket,
        result: Result<ReplayPageReady, ReplayFetchError>,
        reservation: Option<NormalWriterReservation>,
        _staging: Option<OwnedSemaphorePermit>,
    },
    InitialTerminalReady {
        ticket: InitialTerminalTicket,
        result: Result<ControlWriterReservation, WaitForBudgetError>,
    },
    Tick {
        now_ms: u64,
        reply: oneshot::Sender<Result<(), RelayFailure>>,
    },
    Disconnect {
        connection: ConnectionInstanceId,
        reply: oneshot::Sender<Result<(), RelayFailure>>,
    },
    TerminalClosed {
        connection: ConnectionInstanceId,
        token: TerminalToken,
    },
    AdminPurgeMachine {
        request: AdminPurgeCommitRequest,
        reply: oneshot::Sender<Result<AdminPurgeCommit, StoreError>>,
    },
    BeginDrain {
        reply: oneshot::Sender<Result<(), RelayFailure>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), RelayFailure>>,
    },
}

#[derive(Clone)]
struct InitialTerminalTicket {
    connection: ConnectionInstanceId,
    access: AccessContext,
    key: StreamKey,
    replay_id: u64,
    cursor: StreamCursor,
    cancel: tokio_util::sync::CancellationToken,
}

impl RelayCore {
    pub fn start(
        store: RelayStoreHandle,
        authorization: AuthorizationCoordinator,
        lifecycle: AuthorizationLifecycle,
        config: CoreConfig,
    ) -> Result<Self, RelayFailure> {
        config.validate()?;
        let relay_server_id = store.relay_server_id();
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| unavailable("Relay Core requires a Tokio runtime"))?;
        let (tx, rx) = mpsc::channel(config.command_capacity);
        let actor = RelayCoreActor {
            store,
            authorization,
            lifecycle,
            connections: ConnectionRegistry::new(config.max_subscriptions_per_connection),
            device_refresh_pending: HashSet::new(),
            pair_routes: PairRouteRegistry::new(relay_server_id, config.pair_route_limits)?,
            draining: false,
            config,
            now_ms: config.initial_now_ms,
            next_nonce: config.nonce_seed,
            replay_staging: Arc::new(Semaphore::new(config.replay_staging_pages)),
            outbound_budget: Arc::new(GlobalWriterBudget::new(
                super::writer::WriterBudget::new(
                    config.global_normal_max_frames,
                    config.global_normal_max_bytes,
                ),
                super::writer::WriterBudget::new(
                    config.global_control_max_frames,
                    config.global_control_max_bytes,
                ),
            )),
            weak_tx: tx.downgrade(),
            tasks: CoreTasks::new(),
        };
        runtime.spawn(actor.run(rx));
        Ok(Self {
            tx,
            ingress: Arc::new(Semaphore::new(config.ingress_bytes)),
        })
    }

    /// 必须在 challenge/auth 前登记 writer，确保 Activated lifecycle 永远有关闭目标。
    pub async fn attach_pending(
        &self,
        connection: ConnectionInstanceId,
        writer: WriterHandle,
    ) -> Result<(), RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.try_send(CoreCommand::Attach {
            connection,
            writer,
            reply,
        })?;
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    pub async fn register_pending(
        &self,
        connection: ConnectionInstanceId,
        writer: WriterHandle,
    ) -> Result<(), RelayFailure> {
        self.attach_pending(connection, writer).await
    }

    pub async fn activate(&self, access: AccessContext) -> Result<(), RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.try_send(CoreCommand::Activate { access, reply })?;
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    /// 把 authentication actor 的 active 或 terminal-only 结果绑定到已 attach writer。
    pub async fn activate_authentication(
        &self,
        outcome: AuthenticationOutcome,
    ) -> Result<(), RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.try_send(CoreCommand::ActivateAuthentication { outcome, reply })?;
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    /// PairingHello 鉴权只读取 actor 在当前时刻冻结的单 route 快照；真正 activate 时
    /// 仍会在同一 actor 内二次校验并绑定唯一 pairing writer。
    pub async fn pair_route_view(
        &self,
        pair_route: PairRouteId,
    ) -> Result<PairRouteView, RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.try_send(CoreCommand::PairRouteView { pair_route, reply })?;
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    pub async fn handle(
        &self,
        access: &AccessContext,
        frame: OpaqueRouteFrame,
    ) -> Result<RouteOutcome, RelayFailure> {
        if variable_payload_bytes(&frame.body).is_none_or(|bytes| bytes > MAX_FRAME_BYTES) {
            return Err(failure(
                RELAY_FRAME_TOO_LARGE,
                "Relay frame exceeds the public limit",
            ));
        }
        let encoded_len = encode(&frame).len();
        if encoded_len > MAX_FRAME_BYTES {
            return Err(failure(
                RELAY_FRAME_TOO_LARGE,
                "Relay frame exceeds the public limit",
            ));
        }
        let permit_count = u32::try_from(encoded_len.max(1))
            .map_err(|_| unavailable("Relay Core ingress is unavailable"))?;
        let permit = Arc::clone(&self.ingress)
            .try_acquire_many_owned(permit_count)
            .map_err(|_| quota("Relay Core ingress capacity is exhausted"))?;
        let (reply, response) = oneshot::channel();
        self.try_send(CoreCommand::Handle {
            access: access.clone(),
            frame,
            _permit: permit,
            reply,
        })?;
        // caller cancellation 只丢 reply；actor 已接纳的 mutation 仍必须完成。
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    pub async fn tick(&self, now_ms: u64) -> Result<(), RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.try_send(CoreCommand::Tick { now_ms, reply })?;
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    pub async fn disconnect(&self, connection: ConnectionInstanceId) -> Result<(), RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.try_send(CoreCommand::Disconnect { connection, reply })?;
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    /// root-lost 本机管理面唯一 purge 入口。请求与所有 route/PairRoute 操作在同一 Core
    /// actor FIFO 中线性化，且 caller cancellation 不取消已经接纳的 purge。
    pub async fn purge_machine_admin(
        &self,
        request: AdminPurgeCommitRequest,
    ) -> Result<AdminPurgeCommit, StoreError> {
        let (reply, response) = oneshot::channel();
        match self
            .tx
            .try_send(CoreCommand::AdminPurgeMachine { request, reply })
        {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => return Err(StoreError::WorkerBusy),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(StoreError::WorkerUnavailable);
            }
        }
        response.await.map_err(|_| StoreError::WorkerStopped)?
    }

    /// 与所有 attach/activate/route 命令在同一 actor FIFO 中线性化 Core shutdown
    /// fence。server 必须先等待 AuthorizationCoordinator 的独立 fence；本方法返回后，
    /// 后续 Core 命令不再建立连接或产生 route Store/Core mutation。
    pub async fn begin_drain(&self) -> Result<(), RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(CoreCommand::BeginDrain { reply })
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?;
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    pub async fn shutdown(&self) -> Result<(), RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(CoreCommand::Shutdown { reply })
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?;
        response
            .await
            .map_err(|_| unavailable("Relay Core stopped"))?
    }

    fn try_send(&self, command: CoreCommand) -> Result<(), RelayFailure> {
        self.tx.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => quota("Relay Core command capacity is exhausted"),
            mpsc::error::TrySendError::Closed(_) => unavailable("Relay Core stopped"),
        })
    }
}

struct RelayCoreActor {
    store: RelayStoreHandle,
    authorization: AuthorizationCoordinator,
    lifecycle: AuthorizationLifecycle,
    connections: ConnectionRegistry,
    /// 有 device 的 machine generation 消失后保留到下一次 machine activation。
    /// 关闭窗口内抢先重连的 device，随后立即删除；不持久化 grant/stream 状态。
    device_refresh_pending: HashSet<MachineRouteId>,
    pair_routes: PairRouteRegistry,
    draining: bool,
    config: CoreConfig,
    now_ms: u64,
    next_nonce: u64,
    replay_staging: Arc<Semaphore>,
    outbound_budget: Arc<GlobalWriterBudget>,
    weak_tx: mpsc::WeakSender<CoreCommand>,
    tasks: CoreTasks,
}

enum PairDataTarget {
    Machine {
        connection: ConnectionInstanceId,
        access: AccessContext,
        writer: WriterHandle,
    },
    Pairing {
        connection: ConnectionInstanceId,
        writer: WriterHandle,
    },
}

impl RelayCoreActor {
    async fn run(mut self, mut rx: mpsc::Receiver<CoreCommand>) {
        loop {
            tokio::select! {
                biased;
                event = self.lifecycle.recv() => {
                    if self.handle_lifecycle(event) {
                        self.fail_closed_shutdown().await;
                        return;
                    }
                }
                // 已完成/已 panic 的 child 必须先于持续可读的 command backlog 回收；
                // 否则攻击者可用满队列长期掩盖 task failure。
                joined = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    if joined.is_some_and(|result| result.is_err()) {
                        self.fail_closed_shutdown().await;
                        return;
                    }
                }
                command = rx.recv() => {
                    let Some(command) = command else {
                        let _ = self.graceful_shutdown().await;
                        return;
                    };
                    if self.handle_command(command).await {
                        return;
                    }
                }
            }
        }
    }

    async fn handle_command(&mut self, command: CoreCommand) -> bool {
        match command {
            CoreCommand::Attach {
                connection,
                writer,
                reply,
            } => {
                let result = if self.draining {
                    writer.close(WriterCloseReason::Shutdown);
                    Err(draining_failure())
                } else if !self.connections.contains(connection)
                    && self.connections.len() >= self.config.max_connections
                {
                    writer.close(WriterCloseReason::Disconnected);
                    Err(quota("Relay connection capacity is exhausted"))
                } else if writer
                    .bind_global_budget(Arc::clone(&self.outbound_budget))
                    .is_err()
                {
                    writer.close(WriterCloseReason::Disconnected);
                    Err(unavailable("Relay writer must be unused before attach"))
                } else {
                    self.connections
                        .attach_pending(connection, writer, self.now_ms)
                        .map_err(|(error, writer)| {
                            writer.close(WriterCloseReason::Disconnected);
                            connection_failure(error)
                        })
                };
                let _ = reply.send(result);
            }
            CoreCommand::Activate { access, reply } => {
                let result = if self.draining {
                    Err(draining_failure())
                } else {
                    self.activate(access)
                };
                let _ = reply.send(result);
            }
            CoreCommand::ActivateAuthentication { outcome, reply } => {
                let result = if self.draining {
                    Err(draining_failure())
                } else {
                    self.activate_authentication(outcome)
                };
                let _ = reply.send(result);
            }
            CoreCommand::PairRouteView { pair_route, reply } => {
                let _ = reply.send(Ok(self.pair_routes.view(pair_route, self.now_ms)));
            }
            CoreCommand::Handle {
                access,
                frame,
                _permit,
                reply,
            } => {
                let result = if self.draining {
                    Err(draining_failure())
                } else {
                    self.route(access, frame).await
                };
                let _ = reply.send(result);
            }
            CoreCommand::ReplayReady {
                ticket,
                result,
                reservation,
                _staging,
            } => {
                if !self.draining {
                    self.handle_replay_ready(ticket, result, reservation);
                }
            }
            CoreCommand::InitialTerminalReady { ticket, result } => {
                if !self.draining {
                    self.handle_initial_terminal_ready(ticket, result)
                }
            }
            CoreCommand::Tick { now_ms, reply } => {
                let result = self.tick(now_ms);
                let _ = reply.send(result);
            }
            CoreCommand::Disconnect { connection, reply } => {
                self.close_connection(connection, WriterCloseReason::Disconnected);
                let _ = reply.send(Ok(()));
            }
            CoreCommand::TerminalClosed { connection, token } => {
                if let Some(cleanup) = self.connections.finish_terminal(connection, token) {
                    self.finish_cleanup(cleanup);
                }
            }
            CoreCommand::AdminPurgeMachine { request, reply } => {
                let result = if self.draining {
                    Err(StoreError::WorkerUnavailable)
                } else {
                    self.admin_purge_machine(request).await
                };
                let _ = reply.send(result);
            }
            CoreCommand::BeginDrain { reply } => {
                self.draining = true;
                let _ = reply.send(Ok(()));
            }
            CoreCommand::Shutdown { reply } => {
                let result = self.graceful_shutdown().await;
                let _ = reply.send(result);
                return true;
            }
        }
        false
    }

    fn activate(&mut self, access: AccessContext) -> Result<(), RelayFailure> {
        let activated_machine = match access.principal_route() {
            Some(PrincipalRoute::Machine(machine)) => Some(machine),
            _ => None,
        };
        if access.machine_link_is_expired_at(self.now_ms) {
            self.close_connection(
                access.connection_instance(),
                WriterCloseReason::AuthorizationInvalidated,
            );
            return Err(invalid_access());
        }
        if let AccessContext::Pairing(pairing) = access.clone() {
            if let Err(error) = self.pair_routes.bind_pairing(&pairing, self.now_ms) {
                self.close_connection(
                    pairing.connection_instance,
                    WriterCloseReason::AuthorizationInvalidated,
                );
                return Err(error);
            }
            let activated =
                self.connections
                    .activate(access, self.now_ms, WriterCloseReason::Replaced);
            match activated {
                Ok(cleanup) => {
                    if let Some(cleanup) = cleanup {
                        self.finish_cleanup(cleanup);
                    }
                    return Ok(());
                }
                Err(error) => {
                    self.pair_routes.unbind_pairing(pairing.connection_instance);
                    self.close_connection(
                        pairing.connection_instance,
                        WriterCloseReason::AuthorizationInvalidated,
                    );
                    return Err(connection_failure(error));
                }
            }
        }
        if !self.authorization.is_current(&access)? {
            self.close_connection(
                access.connection_instance(),
                WriterCloseReason::AuthorizationInvalidated,
            );
            return Err(invalid_access());
        }
        let cleanup = self
            .connections
            .activate(access, self.now_ms, WriterCloseReason::Replaced)
            .map_err(connection_failure)?;
        if let Some(cleanup) = cleanup {
            self.finish_cleanup(cleanup);
        }
        if let Some(machine) = activated_machine
            && self.device_refresh_pending.remove(&machine)
        {
            self.close_dependent_devices(machine, WriterCloseReason::Disconnected);
        }
        Ok(())
    }

    fn activate_authentication(
        &mut self,
        outcome: AuthenticationOutcome,
    ) -> Result<(), RelayFailure> {
        match outcome {
            AuthenticationOutcome::Activated(activation) => self.activate(activation.access),
            AuthenticationOutcome::RevokedTerminal(terminal) => self.begin_terminal_reauth(
                AccessContext::Device(terminal.access),
                terminal.terminal,
                WriterCloseReason::Revoked,
            ),
            AuthenticationOutcome::RetiredTerminal(terminal) => self.begin_terminal_reauth(
                AccessContext::Machine(terminal.access),
                terminal.terminal,
                WriterCloseReason::Retired,
            ),
        }
    }

    fn begin_terminal_reauth(
        &mut self,
        access: AccessContext,
        frame: OpaqueRouteFrame,
        close_reason: WriterCloseReason,
    ) -> Result<(), RelayFailure> {
        if !terminal_matches_access(&access, &frame, close_reason) {
            self.close_connection(
                access.connection_instance(),
                WriterCloseReason::AuthorizationInvalidated,
            );
            return Err(invalid_access());
        }
        let connection = access.connection_instance();
        let staged = self
            .connections
            .begin_terminal_reauth(&access, frame, close_reason)
            .map_err(connection_failure)?;
        self.spawn_terminal_deadline(connection, staged, close_reason);
        Ok(())
    }

    fn begin_terminal(
        &mut self,
        connection: ConnectionInstanceId,
        frame: OpaqueRouteFrame,
        close_reason: WriterCloseReason,
    ) -> Result<(), RelayFailure> {
        if !terminal_matches_reason(&frame, close_reason) {
            return Err(invalid_access());
        }
        let staged = self
            .connections
            .begin_terminal(connection, frame, close_reason)
            .map_err(connection_failure)?;
        self.spawn_terminal_deadline(connection, staged, close_reason);
        Ok(())
    }

    fn spawn_terminal_deadline(
        &mut self,
        connection: ConnectionInstanceId,
        staged: super::connection::TerminalStage,
        close_reason: WriterCloseReason,
    ) {
        if staged.admission == TerminalAdmission::Existing {
            return;
        }
        let token = staged.token;
        let writer = staged.writer;
        let weak_tx = self.weak_tx.clone();
        self.tasks.spawn(async move {
            let _ = close_on_terminal_deadline(writer, close_reason).await;
            if let Some(tx) = weak_tx.upgrade() {
                let _ = tx
                    .send(CoreCommand::TerminalClosed { connection, token })
                    .await;
            }
        });
    }

    async fn route(
        &mut self,
        access: AccessContext,
        frame: OpaqueRouteFrame,
    ) -> Result<RouteOutcome, RelayFailure> {
        if access.machine_link_is_expired_at(self.now_ms) {
            self.close_connection(
                access.connection_instance(),
                WriterCloseReason::AuthorizationInvalidated,
            );
            return Err(invalid_access());
        }
        if frame.version != RELAY_PROTOCOL_VERSION {
            return Err(failure(
                RELAY_VERSION_UNSUPPORTED,
                "unsupported Relay protocol version",
            ));
        }
        if let AccessContext::Pairing(pairing) = access.clone() {
            if let RelayFrameBody::Pong(Pong { nonce }) = &frame.body {
                self.pair_routes.validate_pairing(&pairing, self.now_ms)?;
                if !self.connections.validates(&access) {
                    return Err(invalid_access());
                }
                return self.pairing_pong(&access, *nonce);
            }
            pairing.authorize_frame(&frame, self.now_ms)?;
            if !self.connections.validates(&access) {
                return Err(invalid_access());
            }
            return match frame.body {
                RelayFrameBody::PairData(frame) => {
                    self.pair_routes.validate_pairing(&pairing, self.now_ms)?;
                    self.pair_data(&access, frame)
                }
                RelayFrameBody::ClosePairRoute(frame) => {
                    self.pair_routes
                        .validate_pairing_close(&pairing, self.now_ms)?;
                    self.close_pair_route(&access, frame)
                }
                _ => Err(forbidden()),
            };
        }
        self.ensure_current(&access)?;
        match frame.body {
            RelayFrameBody::OpenPairRoute(frame) => self.open_pair_route(&access, frame),
            RelayFrameBody::ClosePairRoute(frame) => self.close_pair_route(&access, frame),
            RelayFrameBody::PairData(frame) => self.pair_data(&access, frame),
            RelayFrameBody::RegisterStream(frame) => self.register_stream(&access, frame).await,
            RelayFrameBody::Publish(frame) => self.publish(&access, frame).await,
            RelayFrameBody::Subscribe(frame) => self.subscribe(&access, frame).await,
            RelayFrameBody::Unsubscribe(frame) => self.unsubscribe(&access, frame).await,
            RelayFrameBody::Ack(frame) => self.ack(&access, frame).await,
            RelayFrameBody::Send(frame) => self.send(&access, frame),
            RelayFrameBody::Reply(frame) => self.reply(&access, frame),
            RelayFrameBody::InstallGrant(frame) => self.install_grant(&access, frame).await,
            RelayFrameBody::RevokeDevice(frame) => {
                self.revoke_device(&access, frame.revocation).await
            }
            RelayFrameBody::RetireMachine(frame) => self.retire_machine(&access, frame).await,
            RelayFrameBody::Pong(Pong { nonce }) => self.pong(&access, nonce),
            _ => Err(forbidden()),
        }
    }

    async fn install_grant(
        &mut self,
        access: &AccessContext,
        frame: InstallGrant,
    ) -> Result<RouteOutcome, RelayFailure> {
        let machine = machine_access(access)?;
        if frame.grant.machine_route != machine {
            return Err(forbidden());
        }
        let mutation = self
            .authorization
            .install_grant_from(access.clone(), frame.grant)
            .await?;
        let commit = mutation.commit();
        let ack = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::GrantCommitted(GrantCommitted {
                device_route: commit.device_route,
                grant_serial: commit.grant_serial,
                grant_hash: commit.grant_hash,
            }),
        };
        self.enqueue_origin_control(access, ack)
    }

    async fn revoke_device(
        &mut self,
        access: &AccessContext,
        revocation: agentdeck_protocol::relay_v2::DeviceRevocation,
    ) -> Result<RouteOutcome, RelayFailure> {
        let machine = machine_access(access)?;
        if revocation.machine_route != machine {
            return Err(forbidden());
        }
        let mutation = self
            .authorization
            .revoke_from(access.clone(), revocation)
            .await?;
        let (commit, targets) = mutation.into_parts();
        let terminal = decode(&commit.signed_revocation_blob)
            .map_err(|_| unavailable("persisted revocation terminal is unavailable"))?;
        for connection in targets {
            if self
                .begin_terminal(connection, terminal.clone(), WriterCloseReason::Revoked)
                .is_err()
            {
                self.close_connection(connection, WriterCloseReason::AuthorizationInvalidated);
            }
        }
        self.enqueue_origin_control(access, terminal)
    }

    async fn retire_machine(
        &mut self,
        access: &AccessContext,
        retirement: RetireMachine,
    ) -> Result<RouteOutcome, RelayFailure> {
        let machine = machine_access(access)?;
        if retirement.machine_route != machine {
            return Err(forbidden());
        }
        let origin = access.connection_instance();
        let mutation = self
            .authorization
            .retire_machine_from(access.clone(), retirement)
            .await?;
        let (commit, invalidated) = mutation.into_parts();
        let terminal = decode(&commit.retirement_terminal_blob)
            .map_err(|_| unavailable("persisted retirement terminal is unavailable"))?;

        let removed = self.pair_routes.remove_machine(machine);
        for connection in removed.detached_pairings {
            self.close_connection(connection, WriterCloseReason::Retired);
        }
        for connection in invalidated {
            if connection == origin {
                if self
                    .begin_terminal(connection, terminal.clone(), WriterCloseReason::Retired)
                    .is_err()
                {
                    self.close_connection(connection, WriterCloseReason::Retired);
                }
            } else {
                self.close_connection(connection, WriterCloseReason::Retired);
            }
        }
        Ok(RouteOutcome::Applied)
    }

    async fn admin_purge_machine(
        &mut self,
        request: AdminPurgeCommitRequest,
    ) -> Result<AdminPurgeCommit, StoreError> {
        let machine = request.purge.machine_route;
        let mutation = self.authorization.purge_machine_admin(request).await?;
        let (commit, invalidated) = mutation.into_parts();

        let removed = self.pair_routes.remove_machine(machine);
        for connection in removed.detached_pairings {
            self.close_connection(connection, WriterCloseReason::Retired);
        }
        for connection in invalidated {
            self.close_connection(connection, WriterCloseReason::Retired);
        }
        Ok(commit)
    }

    fn enqueue_origin_control(
        &mut self,
        access: &AccessContext,
        frame: OpaqueRouteFrame,
    ) -> Result<RouteOutcome, RelayFailure> {
        let Some(writer) = self.connections.writer_for(access) else {
            return Ok(RouteOutcome::Closed);
        };
        match self
            .authorization
            .with_current(access, || writer.try_enqueue_control(frame))
        {
            Ok(Some(Ok(()))) => Ok(RouteOutcome::Applied),
            Ok(Some(Err(_))) => {
                self.close_connection(
                    access.connection_instance(),
                    WriterCloseReason::CriticalBackpressure,
                );
                Ok(RouteOutcome::Closed)
            }
            Ok(None) | Err(_) => {
                self.close_connection(
                    access.connection_instance(),
                    WriterCloseReason::AuthorizationInvalidated,
                );
                Ok(RouteOutcome::Closed)
            }
        }
    }

    async fn register_stream(
        &mut self,
        access: &AccessContext,
        frame: RegisterStream,
    ) -> Result<RouteOutcome, RelayFailure> {
        let machine = machine_access(access)?;
        if frame.machine_route != machine {
            return Err(forbidden());
        }
        self.store
            .register_stream(StreamRegistration {
                machine_route: machine,
                stream_route: frame.stream_route,
                generation: frame.generation,
            })
            .await
            .map_err(map_store_error)?;
        self.ensure_current(access)?;
        Ok(RouteOutcome::Applied)
    }

    async fn publish(
        &mut self,
        access: &AccessContext,
        frame: Publish,
    ) -> Result<RouteOutcome, RelayFailure> {
        let machine = machine_access(access)?;
        if frame.stream_seq == u64::MAX {
            return Err(failure(
                RELAY_STREAM_GENERATION_STALE,
                "stream generation is exhausted",
            ));
        }
        let outbound = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Publish(frame.clone()),
        };
        self.store
            .publish(PersistPublish {
                machine_route: machine,
                frame: outbound.clone(),
            })
            .await
            .map_err(map_store_error)?;
        self.ensure_current(access)?;

        let key = StreamKey::new(frame.stream_route, frame.generation);
        // Store COMMIT 后优先为 origin 的 RouteAccepted 占用聚合 normal permit。否则一组
        // 慢读者可以先吃光全局预算，反过来关闭仍然健康的唯一 machine writer。origin
        // 即使已失效/背压关闭，后续 fanout 仍需继续尝试，因为 Publish 已持久化。
        let accepted = RouteAccepted {
            accepted: AcceptedRef::StreamFrame {
                stream_route: frame.stream_route,
                stream_seq: frame.stream_seq,
            },
        };
        let accepted_frame = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RouteAccepted(accepted.clone()),
        };
        let origin_outcome = match self.connections.writer_for(access) {
            Some(writer) => match self
                .authorization
                .with_current(access, || writer.try_enqueue_data(accepted_frame))
            {
                Ok(Some(Ok(()))) => RouteOutcome::Queued(accepted),
                Ok(Some(Err(_))) => {
                    self.close_connection(access.connection_instance(), WriterCloseReason::Lagged);
                    RouteOutcome::Closed
                }
                Ok(None) | Err(_) => {
                    self.close_connection(
                        access.connection_instance(),
                        WriterCloseReason::AuthorizationInvalidated,
                    );
                    RouteOutcome::Closed
                }
            },
            None => RouteOutcome::Closed,
        };

        let deliveries = self
            .connections
            .note_committed_publish(machine, key, frame.stream_seq);
        for delivery in deliveries {
            let writer = delivery.writer.clone();
            let close_reason = match delivery.kind {
                LiveDeliveryKind::Frame => WriterCloseReason::Lagged,
                LiveDeliveryKind::Gap { .. } => WriterCloseReason::CriticalBackpressure,
            };
            let routed =
                self.authorization
                    .with_current(&delivery.access, || match delivery.kind {
                        LiveDeliveryKind::Frame => writer.try_enqueue_data(outbound.clone()),
                        LiveDeliveryKind::Gap { needed, oldest } => {
                            writer.try_enqueue_control(OpaqueRouteFrame {
                                version: RELAY_PROTOCOL_VERSION,
                                body: RelayFrameBody::Gap(Gap {
                                    stream_route: key.stream_route,
                                    generation: key.generation,
                                    need_stream_seq: needed,
                                    oldest_stream_seq: oldest,
                                }),
                            })
                        }
                    });
            match routed {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(_))) => self.close_connection(delivery.connection, close_reason),
                Ok(None) | Err(_) => self.close_connection(
                    delivery.connection,
                    WriterCloseReason::AuthorizationInvalidated,
                ),
            }
        }
        Ok(origin_outcome)
    }

    fn open_pair_route(
        &mut self,
        access: &AccessContext,
        frame: OpenPairRoute,
    ) -> Result<RouteOutcome, RelayFailure> {
        let machine_route = machine_access(access)?;
        let opened = match self.authorization.with_current(access, || {
            self.pair_routes.open(machine_route, frame, self.now_ms)
        })? {
            Some(result) => result?,
            None => {
                self.close_connection(
                    access.connection_instance(),
                    WriterCloseReason::AuthorizationInvalidated,
                );
                return Err(invalid_access());
            }
        };
        let Some(writer) = self.connections.writer_for(access) else {
            return Ok(RouteOutcome::Closed);
        };
        let queued = self.enqueue_if_current(
            access,
            access.connection_instance(),
            WriterCloseReason::CriticalBackpressure,
            || {
                writer.try_enqueue_control(OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION,
                    body: RelayFrameBody::PairRouteOpened(opened),
                })
            },
        );
        Ok(if queued {
            RouteOutcome::Applied
        } else {
            RouteOutcome::Closed
        })
    }

    fn close_pair_route(
        &mut self,
        access: &AccessContext,
        frame: ClosePairRoute,
    ) -> Result<RouteOutcome, RelayFailure> {
        let machine_route = match access {
            AccessContext::Machine(machine) => machine.machine_route,
            AccessContext::Pairing(pairing) => pairing.machine_route,
            AccessContext::Device(_) => return Err(forbidden()),
        };
        // Pairing requester 自己也可能在 close 时从 registry 解绑，因此先冻结 writer。
        let writer = self.connections.writer_for(access);
        let closed = match access {
            AccessContext::Machine(_) => match self.authorization.with_current(access, || {
                self.pair_routes.close(machine_route, frame, self.now_ms)
            })? {
                Some(result) => result?,
                None => {
                    self.close_connection(
                        access.connection_instance(),
                        WriterCloseReason::AuthorizationInvalidated,
                    );
                    return Err(invalid_access());
                }
            },
            AccessContext::Pairing(_) => {
                self.pair_routes.close(machine_route, frame, self.now_ms)?
            }
            AccessContext::Device(_) => return Err(forbidden()),
        };
        // Machine 关闭通常是 daemon durable 接收 PairResponseReceived 后的 terminal ACK。
        // route registry 已冻结 exact pairing connection；先把同一 PairRouteClosed 放入对端
        // control FIFO，再保持 route tombstone，使 requester 能区分 durable success 与
        // expiry/transport EOF。Pairing 自己关闭时 origin 与 detached id 相同，不能重复入队。
        let pair_route = closed.frame.pair_route;
        let outbound = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::PairRouteClosed(closed.frame),
        };
        if let Some(pairing_connection) = closed
            .detached_pairing
            .filter(|connection| *connection != access.connection_instance())
            && let Some(pairing_writer) = self
                .connections
                .pairing_writer_for(pairing_connection, pair_route)
            && pairing_writer
                .try_enqueue_control(outbound.clone())
                .is_err()
        {
            self.close_connection(pairing_connection, WriterCloseReason::CriticalBackpressure);
        }
        let Some(writer) = writer else {
            return Ok(RouteOutcome::Closed);
        };
        let queued = match access {
            AccessContext::Machine(_) => self.enqueue_if_current(
                access,
                access.connection_instance(),
                WriterCloseReason::CriticalBackpressure,
                || writer.try_enqueue_control(outbound),
            ),
            AccessContext::Pairing(_) => match writer.try_enqueue_control(outbound) {
                Ok(()) => true,
                Err(_) => {
                    self.close_connection(
                        access.connection_instance(),
                        WriterCloseReason::CriticalBackpressure,
                    );
                    false
                }
            },
            AccessContext::Device(_) => return Err(forbidden()),
        };
        Ok(if queued {
            RouteOutcome::Applied
        } else {
            RouteOutcome::Closed
        })
    }

    fn pair_data(
        &mut self,
        access: &AccessContext,
        frame: PairData,
    ) -> Result<RouteOutcome, RelayFailure> {
        let machine_route = match access {
            AccessContext::Machine(machine) => {
                self.pair_routes.validate_machine(
                    machine.machine_route,
                    frame.pair_route,
                    self.now_ms,
                )?;
                machine.machine_route
            }
            AccessContext::Pairing(pairing) => {
                self.pair_routes.validate_pairing(pairing, self.now_ms)?;
                pairing.machine_route
            }
            AccessContext::Device(_) => return Err(forbidden()),
        };
        let outbound = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::PairData(frame.clone()),
        };
        let canonical_bytes = encode(&outbound).len();
        let reservation = match access {
            AccessContext::Machine(_) => match self.authorization.with_current(access, || {
                self.pair_routes.reserve_frame(
                    machine_route,
                    frame.pair_route,
                    canonical_bytes,
                    self.now_ms,
                )
            })? {
                Some(result) => result?,
                None => {
                    self.close_connection(
                        access.connection_instance(),
                        WriterCloseReason::AuthorizationInvalidated,
                    );
                    return Err(invalid_access());
                }
            },
            AccessContext::Pairing(_) => self.pair_routes.reserve_frame(
                machine_route,
                frame.pair_route,
                canonical_bytes,
                self.now_ms,
            )?,
            AccessContext::Device(_) => return Err(forbidden()),
        };
        let target = match self.resolve_pair_data_target(access, machine_route, frame.pair_route) {
            Ok(target) => target,
            Err(error) => {
                let _ = self.pair_routes.rollback_frame(reservation);
                return Err(error);
            }
        };

        let delivered = match target {
            PairDataTarget::Machine {
                connection,
                access: target_access,
                writer,
            } => match self
                .authorization
                .with_current(&target_access, || writer.try_enqueue_data(outbound))
            {
                Ok(Some(Ok(()))) => true,
                Ok(Some(Err(_))) => {
                    self.close_connection(connection, WriterCloseReason::Lagged);
                    false
                }
                Ok(None) | Err(_) => {
                    self.close_connection(connection, WriterCloseReason::AuthorizationInvalidated);
                    let _ = self.pair_routes.rollback_frame(reservation);
                    return Err(route_not_found());
                }
            },
            PairDataTarget::Pairing { connection, writer } => match self
                .authorization
                .with_current(access, || writer.try_enqueue_data(outbound))
            {
                Ok(Some(Ok(()))) => true,
                Ok(Some(Err(_))) => {
                    self.close_connection(connection, WriterCloseReason::Lagged);
                    false
                }
                Ok(None) | Err(_) => {
                    self.close_connection(
                        access.connection_instance(),
                        WriterCloseReason::AuthorizationInvalidated,
                    );
                    let _ = self.pair_routes.rollback_frame(reservation);
                    return Err(invalid_access());
                }
            },
        };
        if !delivered {
            let _ = self.pair_routes.rollback_frame(reservation);
            return Err(quota("Relay target writer capacity is exhausted"));
        }
        self.pair_routes.commit_frame(reservation)?;

        let accepted = RouteAccepted {
            accepted: AcceptedRef::PairFrame {
                pair_route: frame.pair_route,
            },
        };
        let accepted_frame = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RouteAccepted(accepted.clone()),
        };
        let Some(origin_writer) = self.connections.writer_for(access) else {
            return Ok(RouteOutcome::Closed);
        };
        let queued = match access {
            AccessContext::Machine(_) => self.enqueue_if_current(
                access,
                access.connection_instance(),
                WriterCloseReason::Lagged,
                || origin_writer.try_enqueue_data(accepted_frame),
            ),
            AccessContext::Pairing(_) => match origin_writer.try_enqueue_data(accepted_frame) {
                Ok(()) => true,
                Err(_) => {
                    self.close_connection(access.connection_instance(), WriterCloseReason::Lagged);
                    false
                }
            },
            AccessContext::Device(_) => return Err(forbidden()),
        };
        Ok(if queued {
            RouteOutcome::Queued(accepted)
        } else {
            RouteOutcome::Closed
        })
    }

    fn resolve_pair_data_target(
        &mut self,
        origin: &AccessContext,
        machine_route: MachineRouteId,
        pair_route: PairRouteId,
    ) -> Result<PairDataTarget, RelayFailure> {
        match origin {
            AccessContext::Machine(_) => {
                let connection =
                    self.pair_routes
                        .pairing_connection(machine_route, pair_route, self.now_ms)?;
                let candidate = self.connections.entries.get(&connection).and_then(|entry| {
                    let AccessContext::Pairing(pairing) = entry.access.as_ref()? else {
                        return None;
                    };
                    (pairing.machine_route == machine_route
                        && pairing.pair_route == pair_route
                        && pairing.connection_instance == connection)
                        .then(|| (pairing.clone(), entry.writer.clone()))
                });
                let Some((pairing, writer)) = candidate else {
                    self.close_connection(connection, WriterCloseReason::AuthorizationInvalidated);
                    return Err(route_not_found());
                };
                if self
                    .pair_routes
                    .validate_pairing(&pairing, self.now_ms)
                    .is_err()
                {
                    self.close_connection(connection, WriterCloseReason::AuthorizationInvalidated);
                    return Err(route_not_found());
                }
                Ok(PairDataTarget::Pairing { connection, writer })
            }
            AccessContext::Pairing(_) => {
                let principal = PrincipalRoute::Machine(machine_route);
                let Some(connection) = self.authorization.current(principal)? else {
                    return Err(route_not_found());
                };
                let candidate = self.connections.entries.get(&connection).and_then(|entry| {
                    let target_access = entry.access.clone()?;
                    (target_access.principal_route() == Some(principal))
                        .then(|| (target_access, entry.writer.clone()))
                });
                let Some((target_access, writer)) = candidate else {
                    self.close_connection(connection, WriterCloseReason::AuthorizationInvalidated);
                    return Err(route_not_found());
                };
                Ok(PairDataTarget::Machine {
                    connection,
                    access: target_access,
                    writer,
                })
            }
            AccessContext::Device(_) => Err(forbidden()),
        }
    }

    fn send(&mut self, access: &AccessContext, frame: Send) -> Result<RouteOutcome, RelayFailure> {
        let target = resolve_send(access, &frame)?;
        self.route_online_request(
            access,
            target,
            OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Send(frame),
            },
        )
    }

    fn reply(
        &mut self,
        access: &AccessContext,
        frame: Reply,
    ) -> Result<RouteOutcome, RelayFailure> {
        let target = resolve_reply(access, &frame)?;
        self.route_online_request(
            access,
            target,
            OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Reply(frame),
            },
        )
    }

    /// Send/Reply 只做 active generation 在线转发，不创建 request/origin map，也不访问
    /// Store。目标先成功进入 bounded writer，origin 才得到 RouteAccepted。
    fn route_online_request(
        &mut self,
        origin: &AccessContext,
        target: RequestTarget,
        outbound: OpaqueRouteFrame,
    ) -> Result<RouteOutcome, RelayFailure> {
        let principal = target.principal();
        let Some(target_connection) = self.authorization.current(principal)? else {
            return Err(route_not_found());
        };
        let Some(entry) = self.connections.entries.get(&target_connection) else {
            return Err(route_not_found());
        };
        let Some(target_access) = entry.access.clone() else {
            return Err(route_not_found());
        };
        if target_access.principal_route() != Some(principal) {
            self.close_connection(
                target_connection,
                WriterCloseReason::AuthorizationInvalidated,
            );
            return Err(route_not_found());
        }
        let target_writer = entry.writer.clone();
        match self
            .authorization
            .with_both_current(origin, &target_access, || {
                target_writer.try_enqueue_data(outbound)
            }) {
            Ok((true, true, Some(Ok(())))) => {}
            Ok((true, true, Some(Err(_)))) => {
                self.close_connection(target_connection, WriterCloseReason::Lagged);
                return Err(quota("Relay target writer capacity is exhausted"));
            }
            Ok((origin_current, target_current, None)) => {
                if !origin_current {
                    self.close_connection(
                        origin.connection_instance(),
                        WriterCloseReason::AuthorizationInvalidated,
                    );
                }
                if !target_current {
                    self.close_connection(
                        target_connection,
                        WriterCloseReason::AuthorizationInvalidated,
                    );
                }
                return Err(if origin_current {
                    route_not_found()
                } else {
                    invalid_access()
                });
            }
            Ok(_) => {
                self.close_connection(
                    origin.connection_instance(),
                    WriterCloseReason::AuthorizationInvalidated,
                );
                self.close_connection(
                    target_connection,
                    WriterCloseReason::AuthorizationInvalidated,
                );
                return Err(unavailable("authorization state is unavailable"));
            }
            Err(error) => {
                self.close_connection(
                    origin.connection_instance(),
                    WriterCloseReason::AuthorizationInvalidated,
                );
                self.close_connection(
                    target_connection,
                    WriterCloseReason::AuthorizationInvalidated,
                );
                return Err(error);
            }
        }

        let accepted = target.accepted();
        let accepted_frame = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RouteAccepted(accepted.clone()),
        };
        let Some(origin_writer) = self.connections.writer_for(origin) else {
            return Ok(RouteOutcome::Closed);
        };
        if !self.enqueue_if_current(
            origin,
            origin.connection_instance(),
            WriterCloseReason::Lagged,
            || origin_writer.try_enqueue_data(accepted_frame),
        ) {
            return Ok(RouteOutcome::Closed);
        }
        Ok(RouteOutcome::Queued(accepted))
    }

    async fn subscribe(
        &mut self,
        access: &AccessContext,
        frame: Subscribe,
    ) -> Result<RouteOutcome, RelayFailure> {
        let (machine, device, serial) = device_access(access)?;
        let connection = access.connection_instance();
        let key = StreamKey::new(frame.stream_route, frame.generation);
        self.check_subscription_capacity(connection, key)?;

        let lease = match self
            .store
            .subscribe(PersistSubscription {
                machine_route: machine,
                device_route: device,
                grant_serial: serial,
                stream_route: frame.stream_route,
                generation: frame.generation,
                start: frame.cursor,
            })
            .await
        {
            Ok(lease) => lease,
            Err(StoreError::ReplayGap { needed, oldest }) => {
                self.ensure_current(access)?;
                return self.pause_gap(access, key, needed, oldest);
            }
            Err(error) => return Err(map_store_error(error)),
        };
        self.ensure_current(access)?;

        // 同 connection 的显式 re-Subscribe 替换旧 runtime epoch；Store lease 已先 COMMIT。
        let (_, replacement_next) = self
            .connections
            .unsubscribe_runtime(connection, key)
            .map_err(connection_failure)?;
        let admission = self
            .connections
            .begin_initial_replay(connection, key, lease.start, lease.replay_through)
            .map_err(connection_failure)?;
        let public = ReplayTicket {
            stream: frame.stream_route,
            generation: frame.generation,
            next: lease.start,
            terminal: lease.replay_through,
        };
        if let Some(start) = replacement_next {
            self.launch_replay_start(access, start)?;
        }
        if let ReplayAdmission::Started(start) = admission {
            self.launch_replay_start(access, start)?;
        }
        Ok(RouteOutcome::Replay(public))
    }

    async fn unsubscribe(
        &mut self,
        access: &AccessContext,
        frame: Unsubscribe,
    ) -> Result<RouteOutcome, RelayFailure> {
        let (machine, device, serial) = device_access(access)?;
        let key = StreamKey::new(frame.stream_route, frame.generation);
        self.store
            .unsubscribe(PersistUnsubscribe {
                machine_route: machine,
                device_route: device,
                grant_serial: serial,
                stream_route: frame.stream_route,
                generation: frame.generation,
            })
            .await
            .map_err(map_store_error)?;
        self.ensure_current(access)?;
        let (_, next) = self
            .connections
            .unsubscribe_runtime(access.connection_instance(), key)
            .map_err(connection_failure)?;
        if let Some(next) = next {
            self.launch_replay_start(access, next)?;
        }
        Ok(RouteOutcome::Applied)
    }

    async fn ack(
        &mut self,
        access: &AccessContext,
        frame: Ack,
    ) -> Result<RouteOutcome, RelayFailure> {
        let (machine, device, serial) = device_access(access)?;
        self.store
            .ack(PersistAck {
                machine_route: machine,
                device_route: device,
                grant_serial: serial,
                stream_route: frame.stream_route,
                generation: frame.generation,
                up_to_seq: frame.up_to_seq,
            })
            .await
            .map_err(map_store_error)?;
        self.ensure_current(access)?;
        Ok(RouteOutcome::Applied)
    }

    fn pong(&mut self, access: &AccessContext, nonce: u64) -> Result<RouteOutcome, RelayFailure> {
        self.connections
            .accept_pong(access.connection_instance(), nonce, self.now_ms)
            .map_err(connection_failure)?;
        Ok(RouteOutcome::Applied)
    }

    fn pairing_pong(
        &mut self,
        access: &AccessContext,
        nonce: u64,
    ) -> Result<RouteOutcome, RelayFailure> {
        if self
            .connections
            .accept_pong(access.connection_instance(), nonce, self.now_ms)
            .map_err(connection_failure)?
        {
            Ok(RouteOutcome::Applied)
        } else {
            Err(forbidden())
        }
    }

    fn pause_gap(
        &mut self,
        access: &AccessContext,
        key: StreamKey,
        needed: u64,
        oldest: u64,
    ) -> Result<RouteOutcome, RelayFailure> {
        let gap = Gap {
            stream_route: key.stream_route,
            generation: key.generation,
            need_stream_seq: needed,
            oldest_stream_seq: oldest,
        };
        let next = self
            .connections
            .pause_gap(access.connection_instance(), key, needed, oldest)
            .map_err(connection_failure)?;
        let Some(writer) = self.connections.writer_for(access) else {
            return Ok(RouteOutcome::Closed);
        };
        if !self.enqueue_if_current(
            access,
            access.connection_instance(),
            WriterCloseReason::CriticalBackpressure,
            || {
                writer.try_enqueue_control(OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION,
                    body: RelayFrameBody::Gap(gap.clone()),
                })
            },
        ) {
            return Ok(RouteOutcome::Closed);
        }
        if let Some(next) = next {
            self.launch_replay_start(access, next)?;
        }
        Ok(RouteOutcome::Gap(gap))
    }

    /// authorization transition fence 与 writer enqueue 必须在同一 active-registry 临界区内
    /// 线性化。`is_current` 只适合无副作用预检，不能单独保护任何出站 frame。
    fn enqueue_if_current<E>(
        &mut self,
        access: &AccessContext,
        connection: ConnectionInstanceId,
        backpressure_reason: WriterCloseReason,
        enqueue: impl FnOnce() -> Result<(), E>,
    ) -> bool {
        let routed = self.authorization.with_current(access, enqueue);
        match routed {
            Ok(Some(Ok(()))) => true,
            Ok(Some(Err(_))) => {
                self.close_connection(connection, backpressure_reason);
                false
            }
            Ok(None) | Err(_) => {
                self.close_connection(connection, WriterCloseReason::AuthorizationInvalidated);
                false
            }
        }
    }

    fn advance_after_initial_terminal(
        &mut self,
        access: &AccessContext,
        key: StreamKey,
        replay_epoch: u64,
    ) -> Result<(), RelayFailure> {
        let completed = self
            .connections
            .complete_initial_replay(access.connection_instance(), key, replay_epoch)
            .map_err(connection_failure)?;
        if let Some(catchup) = completed.catchup {
            let ticket = self.catchup_ticket(access, catchup)?;
            self.spawn_replay(ticket)?;
        } else if let Some(next) = completed.next_queued {
            self.launch_replay_start(access, next)?;
        }
        Ok(())
    }

    /// ReplayComplete 也必须先取得 control budget，再推进 runtime state。等待发生在
    /// connection-owned task，不阻塞 Core actor；取消/replacement 会终止等待。
    fn schedule_initial_terminal(
        &mut self,
        access: AccessContext,
        key: StreamKey,
        replay_epoch: u64,
        cursor: StreamCursor,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), RelayFailure> {
        let connection = access.connection_instance();
        let Some(writer) = self.connections.writer_for(&access) else {
            return Err(invalid_access());
        };
        let terminal_bytes = encode(&replay_complete(key, cursor)).len();
        let weak_tx = self.weak_tx.clone();
        let ticket = InitialTerminalTicket {
            connection,
            access,
            key,
            replay_id: replay_epoch,
            cursor,
            cancel: cancel.clone(),
        };
        self.tasks.spawn(async move {
            let result = loop {
                if cancel.is_cancelled() {
                    return;
                }
                match writer.try_reserve_control(1, terminal_bytes) {
                    Ok(reservation) => break Ok(reservation),
                    Err(TryReserveWriterError::Unavailable) => {
                        if let Err(error) = writer
                            .wait_for_control_budget(1, terminal_bytes, &cancel)
                            .await
                        {
                            if error == WaitForBudgetError::Cancelled {
                                return;
                            }
                            break Err(error);
                        }
                    }
                    Err(TryReserveWriterError::RequestExceedsLimit) => {
                        break Err(WaitForBudgetError::RequestExceedsLimit);
                    }
                    Err(TryReserveWriterError::Closed(reason)) => {
                        break Err(WaitForBudgetError::Closed(reason));
                    }
                }
            };
            let Some(tx) = weak_tx.upgrade() else {
                return;
            };
            let command = CoreCommand::InitialTerminalReady { ticket, result };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = tx.send(command) => {}
            }
        });
        Ok(())
    }

    /// 启动一个已由 ConnectionRegistry 串行裁决的 initial replay。空区间不访问 Store，
    /// 但仍异步等待 control budget，不能在 actor 内一次耗尽 queued terminals。
    fn launch_replay_start(
        &mut self,
        access: &AccessContext,
        start: ReplayStart,
    ) -> Result<(), RelayFailure> {
        if start.mode == ReplayStartMode::PostTerminal {
            let ticket = self.catchup_ticket(access, start)?;
            return self.spawn_replay(ticket);
        }
        let lease = SubscriptionLease {
            start: start.cursor,
            replay_through: start.terminal,
            ack: None,
            duplicate: false,
        };
        let ticket = initial_replay_ticket(
            start.connection,
            access.clone(),
            start.key,
            start.replay_epoch,
            &lease,
            start.cancel.clone(),
        )
        .map_err(map_store_error)?;
        if let Some(ticket) = ticket {
            self.spawn_replay(ticket)
        } else {
            self.schedule_initial_terminal(
                access.clone(),
                start.key,
                start.replay_epoch,
                start.terminal,
                start.cancel,
            )
        }
    }

    fn spawn_replay(&mut self, ticket: ReplayFetchTicket) -> Result<(), RelayFailure> {
        let Some(writer) = self.connections.writer_for(&ticket.access) else {
            return Err(invalid_access());
        };
        let store = self.store.clone();
        let staging = Arc::clone(&self.replay_staging);
        let weak_tx = self.weak_tx.clone();
        let cancel = ticket.cancel.clone();
        let normal_budget = writer.normal_budget();
        let page_max_frames = REPLAY_PAGE_MAX_FRAMES.min(normal_budget.max_frames);
        let page_max_bytes = REPLAY_PAGE_MAX_BYTES.min(normal_budget.max_bytes);
        self.tasks.spawn(async move {
            if ticket.busy_retries > 0 {
                let backoff_ms = 1_u64 << ticket.busy_retries.min(6);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                }
            }
            // 在占用全局 staging 前，先原子预留整页 writer 预算。live fanout 无法在
            // Store fetch 与 Core enqueue 之间抢走该预算；不足时不占 staging 等待并重试。
            let reservation = loop {
                if cancel.is_cancelled() {
                    return;
                }
                match writer.try_reserve_normal(page_max_frames, page_max_bytes) {
                    Ok(reservation) => break reservation,
                    Err(TryReserveWriterError::Unavailable) => {
                        if let Err(error) = writer
                            .wait_for_normal_budget(page_max_frames, page_max_bytes, &cancel)
                            .await
                        {
                            if error == WaitForBudgetError::Cancelled {
                                return;
                            }
                            if let Some(tx) = weak_tx.upgrade() {
                                let command = CoreCommand::ReplayReady {
                                    ticket,
                                    result: Err(ReplayFetchError::WriterUnavailable(error)),
                                    reservation: None,
                                    _staging: None,
                                };
                                tokio::select! {
                                    biased;
                                    _ = cancel.cancelled() => {}
                                    _ = tx.send(command) => {}
                                }
                            }
                            return;
                        }
                    }
                    Err(TryReserveWriterError::RequestExceedsLimit) => {
                        if let Some(tx) = weak_tx.upgrade() {
                            let command = CoreCommand::ReplayReady {
                                ticket,
                                result: Err(ReplayFetchError::WriterUnavailable(
                                    WaitForBudgetError::RequestExceedsLimit,
                                )),
                                reservation: None,
                                _staging: None,
                            };
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => {}
                                _ = tx.send(command) => {}
                            }
                        }
                        return;
                    }
                    Err(TryReserveWriterError::Closed(reason)) => {
                        if let Some(tx) = weak_tx.upgrade() {
                            let command = CoreCommand::ReplayReady {
                                ticket,
                                result: Err(ReplayFetchError::WriterUnavailable(
                                    WaitForBudgetError::Closed(reason),
                                )),
                                reservation: None,
                                _staging: None,
                            };
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => {}
                                _ = tx.send(command) => {}
                            }
                        }
                        return;
                    }
                }
            };
            let permit = tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                permit = staging.acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return,
                },
            };
            let result = fetch_replay_page(&store, &ticket, page_max_frames, page_max_bytes).await;
            if cancel.is_cancelled() {
                return;
            }
            let Some(tx) = weak_tx.upgrade() else {
                return;
            };
            let command = CoreCommand::ReplayReady {
                ticket,
                result,
                reservation: Some(reservation),
                _staging: Some(permit),
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = tx.send(command) => {}
            }
        });
        Ok(())
    }

    fn handle_replay_ready(
        &mut self,
        ticket: ReplayFetchTicket,
        result: Result<ReplayPageReady, ReplayFetchError>,
        reservation: Option<NormalWriterReservation>,
    ) {
        if !self.replay_ticket_is_current(&ticket) {
            return;
        }
        match result {
            Err(ReplayFetchError::Cancelled) => {}
            Err(ReplayFetchError::WriterUnavailable(_)) => {
                self.close_connection(ticket.connection, WriterCloseReason::Lagged);
            }
            Err(ReplayFetchError::Gap(gap)) => {
                let next = self.connections.pause_gap(
                    ticket.connection,
                    ticket.key,
                    gap.need_stream_seq,
                    gap.oldest_stream_seq,
                );
                match next {
                    Ok(next) => {
                        let Some(writer) = self.connections.writer_for(&ticket.access) else {
                            self.close_connection(
                                ticket.connection,
                                WriterCloseReason::Disconnected,
                            );
                            return;
                        };
                        if !self.enqueue_if_current(
                            &ticket.access,
                            ticket.connection,
                            WriterCloseReason::CriticalBackpressure,
                            || {
                                writer.try_enqueue_control(OpaqueRouteFrame {
                                    version: RELAY_PROTOCOL_VERSION,
                                    body: RelayFrameBody::Gap(gap),
                                })
                            },
                        ) {
                            return;
                        }
                        if let Some(next) = next
                            && self.launch_replay_start(&ticket.access, next).is_err()
                        {
                            self.close_connection(
                                ticket.connection,
                                WriterCloseReason::Disconnected,
                            );
                        }
                    }
                    Err(_) => {
                        self.close_connection(ticket.connection, WriterCloseReason::Disconnected)
                    }
                }
            }
            Err(ReplayFetchError::Store(StoreError::WorkerBusy))
                if ticket.busy_retries < MAX_REPLAY_STORE_BUSY_RETRIES =>
            {
                // WorkerBusy 是 Store actor 的瞬时入口背压，不等于 reader grant 失效。
                // 重试前显式释放 writer/staging 预算，且由原 ticket cancellation 约束。
                drop(reservation);
                let retry = ReplayFetchTicket {
                    busy_retries: ticket.busy_retries + 1,
                    ..ticket
                };
                if self.spawn_replay(retry).is_err() {
                    self.close_connection(ticket.connection, WriterCloseReason::Disconnected);
                }
            }
            Err(ReplayFetchError::Store(StoreError::ReplayPageLimitExceeded)) => {
                self.close_connection(ticket.connection, WriterCloseReason::Lagged);
            }
            Err(ReplayFetchError::Store(_)) => {
                self.close_connection(ticket.connection, WriterCloseReason::Disconnected);
            }
            Ok(page) => {
                let Some(reservation) = reservation else {
                    self.close_connection(ticket.connection, WriterCloseReason::Disconnected);
                    return;
                };
                self.enqueue_replay_page(ticket, page, reservation);
            }
        }
    }

    fn handle_initial_terminal_ready(
        &mut self,
        ticket: InitialTerminalTicket,
        result: Result<ControlWriterReservation, WaitForBudgetError>,
    ) {
        if !self.replay_context_is_current(
            ticket.connection,
            &ticket.access,
            ticket.key,
            ticket.replay_id,
            &ticket.cancel,
        ) {
            return;
        }
        let mut reservation = match result {
            Ok(reservation) => reservation,
            Err(WaitForBudgetError::Cancelled) => return,
            Err(WaitForBudgetError::Closed(reason)) => {
                self.close_connection(ticket.connection, reason);
                return;
            }
            Err(WaitForBudgetError::RequestExceedsLimit) => {
                self.close_connection(ticket.connection, WriterCloseReason::CriticalBackpressure);
                return;
            }
        };
        if !self.enqueue_if_current(
            &ticket.access,
            ticket.connection,
            WriterCloseReason::CriticalBackpressure,
            || reservation.try_enqueue_control(replay_complete(ticket.key, ticket.cursor)),
        ) {
            return;
        }
        drop(reservation);
        if self
            .advance_after_initial_terminal(&ticket.access, ticket.key, ticket.replay_id)
            .is_err()
        {
            self.close_connection(ticket.connection, WriterCloseReason::Disconnected);
        }
    }

    fn enqueue_replay_page(
        &mut self,
        ticket: ReplayFetchTicket,
        page: ReplayPageReady,
        mut reservation: NormalWriterReservation,
    ) {
        for frame in page.frames {
            if !self.replay_ticket_is_current(&ticket) {
                return;
            }
            if !self.enqueue_if_current(
                &ticket.access,
                ticket.connection,
                WriterCloseReason::Lagged,
                || reservation.try_enqueue_data(frame),
            ) {
                return;
            }
        }
        // 后续页开始前先释放本页未使用的最坏预算；已入 FIFO 的实际 bytes/frames 继续
        // 由 delivery.flush 持有。
        drop(reservation);

        if let Some(position) = page.next {
            let next = ReplayFetchTicket {
                position,
                busy_retries: 0,
                ..ticket
            };
            if self.spawn_replay(next).is_err() {
                self.close_connection(ticket.connection, WriterCloseReason::Disconnected);
            }
            return;
        }

        match page.mode {
            ReplayMode::Initial { terminal } => {
                if self
                    .schedule_initial_terminal(
                        ticket.access.clone(),
                        ticket.key,
                        ticket.replay_id,
                        terminal,
                        ticket.cancel.clone(),
                    )
                    .is_err()
                {
                    self.close_connection(ticket.connection, WriterCloseReason::Disconnected);
                }
            }
            ReplayMode::PostTerminal => {
                let completed = self.connections.complete_catchup(
                    ticket.connection,
                    ticket.key,
                    ticket.replay_id,
                    page.replay_through,
                );
                match completed {
                    Ok(completed) => {
                        match (completed.next, completed.live_cursor, completed.next_queued) {
                            (Some(next), None, None) => {
                                let launched = self
                                    .catchup_ticket(&ticket.access, next)
                                    .and_then(|next| self.spawn_replay(next));
                                if launched.is_err() {
                                    self.close_connection(
                                        ticket.connection,
                                        WriterCloseReason::Disconnected,
                                    );
                                }
                            }
                            (None, Some(_), Some(next)) | (None, None, Some(next)) => {
                                if self.launch_replay_start(&ticket.access, next).is_err() {
                                    self.close_connection(
                                        ticket.connection,
                                        WriterCloseReason::Disconnected,
                                    );
                                }
                            }
                            (None, Some(_), None) => {}
                            _ => self.close_connection(
                                ticket.connection,
                                WriterCloseReason::Disconnected,
                            ),
                        }
                    }
                    Err(_) => {
                        self.close_connection(ticket.connection, WriterCloseReason::Disconnected)
                    }
                }
            }
        }
    }

    fn catchup_ticket(
        &self,
        access: &AccessContext,
        start: ReplayStart,
    ) -> Result<ReplayFetchTicket, RelayFailure> {
        if start.mode != ReplayStartMode::PostTerminal
            || !cursor_at_or_before(start.cursor, start.terminal)
        {
            return Err(unavailable("Relay replay state is unavailable"));
        }
        post_terminal_replay_ticket(
            start.connection,
            access.clone(),
            start.key,
            start.replay_epoch,
            start.cursor,
            start.cancel,
        )
        .map_err(map_store_error)
    }

    fn replay_identity_is_current(
        &self,
        connection: ConnectionInstanceId,
        key: StreamKey,
        replay_id: u64,
    ) -> bool {
        matches!(
            self.connections
                .subscription_phase(connection, key),
            Some(SubscriptionPhase::Replaying { replay_epoch, .. })
                | Some(SubscriptionPhase::PostTerminalCatchup { replay_epoch, .. })
                if *replay_epoch == replay_id
        )
    }

    /// 这里只校验 connection/replay epoch/cancellation；authorization 必须在真正 enqueue
    /// 时由 `enqueue_if_current` 原子校验，避免重新引入 check/use 窗口。
    fn replay_context_is_current(
        &self,
        connection: ConnectionInstanceId,
        access: &AccessContext,
        key: StreamKey,
        replay_id: u64,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> bool {
        !(cancel.is_cancelled()
            || !self.connections.validates(access)
            || !self.replay_identity_is_current(connection, key, replay_id))
    }

    fn replay_ticket_is_current(&self, ticket: &ReplayFetchTicket) -> bool {
        self.replay_context_is_current(
            ticket.connection,
            &ticket.access,
            ticket.key,
            ticket.replay_id,
            &ticket.cancel,
        )
    }

    fn check_subscription_capacity(
        &self,
        connection: ConnectionInstanceId,
        key: StreamKey,
    ) -> Result<(), RelayFailure> {
        let entry = self
            .connections
            .entries
            .get(&connection)
            .ok_or_else(invalid_access)?;
        if !entry.subscriptions.contains_key(&key)
            && entry.subscriptions.len() >= self.config.max_subscriptions_per_connection
        {
            return Err(quota("subscription capacity is exhausted"));
        }
        Ok(())
    }

    fn tick(&mut self, now_ms: u64) -> Result<(), RelayFailure> {
        if now_ms < self.now_ms {
            return Err(unavailable("heartbeat clock moved backwards"));
        }
        self.now_ms = now_ms;

        // 威胁场景：被窃取的短期 MachineLink 私钥在证书到期前建连，并用持续 Pong
        // 绕过 heartbeat timeout；absolute expiry 必须先于下一轮 heartbeat 强制断连。
        for connection in self.connections.expired_machine_links(now_ms) {
            self.close_connection(connection, WriterCloseReason::AuthorizationInvalidated);
        }

        let expired = self.pair_routes.tick(now_ms);
        for connection in expired.detached_pairings {
            self.close_connection(connection, WriterCloseReason::Disconnected);
        }

        let closed: Vec<_> = self
            .connections
            .entries
            .iter()
            .filter_map(|(connection, entry)| entry.writer.is_closed().then_some(*connection))
            .collect();
        for connection in closed {
            self.close_connection(connection, WriterCloseReason::Disconnected);
        }
        for connection in self
            .connections
            .timed_out(now_ms, self.config.heartbeat_timeout_ms)
        {
            self.close_connection(connection, WriterCloseReason::HeartbeatTimeout);
        }
        for connection in self
            .connections
            .heartbeat_candidates(now_ms, self.config.heartbeat_interval_ms)
        {
            let nonce = self.next_nonce;
            self.next_nonce = self.next_nonce.wrapping_add(1);
            let writer = self
                .connections
                .record_ping(connection, nonce, now_ms)
                .map_err(connection_failure)?;
            if writer
                .try_enqueue_control(OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION,
                    body: RelayFrameBody::Ping(Ping { nonce }),
                })
                .is_err()
            {
                self.close_connection(connection, WriterCloseReason::CriticalBackpressure);
            }
        }
        Ok(())
    }

    fn handle_lifecycle(&mut self, event: Option<AuthorizationLifecycleEvent>) -> bool {
        match event {
            Some(AuthorizationLifecycleEvent::Activated(activation)) => {
                if let Some(replaced) = activation.replaced {
                    self.close_connection(replaced, WriterCloseReason::Replaced);
                }
                if !self.connections.contains(activation.connection_instance) {
                    let _ = self
                        .authorization
                        .disconnect(activation.route, activation.connection_instance);
                } else if self
                    .connections
                    .note_activation(activation.connection_instance, activation.route)
                    .is_err()
                {
                    self.close_connection(
                        activation.connection_instance,
                        WriterCloseReason::AuthorizationInvalidated,
                    );
                }
                false
            }
            Some(AuthorizationLifecycleEvent::Invalidated { connections }) => {
                for connection in connections {
                    if !self.connections.is_terminal(connection) {
                        self.close_connection(
                            connection,
                            WriterCloseReason::AuthorizationInvalidated,
                        );
                    }
                }
                false
            }
            Some(AuthorizationLifecycleEvent::FailClosedAll { connections }) => {
                for connection in connections {
                    self.close_connection(connection, WriterCloseReason::AuthorizationInvalidated);
                }
                for cleanup in self
                    .connections
                    .close_all(WriterCloseReason::AuthorizationInvalidated)
                {
                    self.finish_cleanup(cleanup);
                }
                true
            }
            None => true,
        }
    }

    fn ensure_current(&mut self, access: &AccessContext) -> Result<(), RelayFailure> {
        if self.connections.is_terminal(access.connection_instance()) {
            return Err(invalid_access());
        }
        match self.authorization.is_current(access) {
            Ok(true) if self.connections.validates(access) => Ok(()),
            Ok(_) => {
                if let Some(cleanup) = self
                    .connections
                    .remove_if_access_and_close(access, WriterCloseReason::AuthorizationInvalidated)
                {
                    self.finish_cleanup(cleanup);
                }
                Err(invalid_access())
            }
            Err(error) => {
                self.close_connection(
                    access.connection_instance(),
                    WriterCloseReason::AuthorizationInvalidated,
                );
                Err(error)
            }
        }
    }

    fn close_connection(&mut self, connection: ConnectionInstanceId, reason: WriterCloseReason) {
        self.pair_routes.unbind_pairing(connection);
        if let Some(cleanup) = self.connections.remove_and_close(connection, reason) {
            self.finish_cleanup(cleanup);
        }
    }

    fn finish_cleanup(&mut self, cleanup: ConnectionCleanup) {
        let dependent_machine = match cleanup.principal {
            Some(PrincipalRoute::Machine(machine))
                if machine_disconnect_requires_device_reconnect(cleanup.close_reason) =>
            {
                Some(machine)
            }
            _ => None,
        };
        if let Some(principal) = cleanup.principal {
            let _ = self.authorization.disconnect(principal, cleanup.connection);
        }
        if let Some(machine) = dependent_machine
            && self.close_dependent_devices(machine, cleanup.close_reason) > 0
        {
            // 旧 device 关闭后可能在 machine downtime 内先于新 generation 重连；
            // 下一次该 machine activation 必须再关闭一次，fresh subscribe 才会
            // 严格发生在新 machine writer 已激活之后。
            self.device_refresh_pending.insert(machine);
        }
    }

    fn close_dependent_devices(
        &mut self,
        machine: MachineRouteId,
        reason: WriterCloseReason,
    ) -> usize {
        let devices = self.connections.close_devices_for_machine(machine, reason);
        let closed = devices.len();
        for device in devices {
            self.finish_cleanup(device);
        }
        closed
    }

    async fn graceful_shutdown(&mut self) -> Result<(), RelayFailure> {
        for cleanup in self.connections.close_all(WriterCloseReason::Shutdown) {
            self.finish_cleanup(cleanup);
        }
        let task_failures = self.tasks.shutdown().await;
        let auth_result = self.authorization.shutdown().await;
        if !task_failures.is_empty() {
            return Err(unavailable("Relay Core replay task failed during shutdown"));
        }
        auth_result
    }

    async fn fail_closed_shutdown(&mut self) {
        for cleanup in self
            .connections
            .close_all(WriterCloseReason::AuthorizationInvalidated)
        {
            self.finish_cleanup(cleanup);
        }
        let _ = self.tasks.abort_and_join().await;
        let _ = self.authorization.shutdown().await;
    }
}

/// 只把已证明旧 machine transport 不再可用的关闭原因向 device 级联。
/// `Replaced` 也会出现在首次 grant transition 的同进程 re-auth；此时关闭 device
/// 会截断尚未完成的 transition snapshot，因此不能把普通 activation replacement
/// 等同于 daemon/process generation 丢失。
fn machine_disconnect_requires_device_reconnect(reason: WriterCloseReason) -> bool {
    match reason {
        WriterCloseReason::Disconnected
        | WriterCloseReason::AuthorizationInvalidated
        | WriterCloseReason::HeartbeatTimeout => true,
        WriterCloseReason::Explicit
        | WriterCloseReason::Replaced
        | WriterCloseReason::Shutdown
        | WriterCloseReason::Lagged
        | WriterCloseReason::CriticalBackpressure
        | WriterCloseReason::ReceiverDropped
        | WriterCloseReason::DeliveryDropped
        | WriterCloseReason::AllWritersDropped
        | WriterCloseReason::Revoked
        | WriterCloseReason::Retired
        | WriterCloseReason::PairRouteUnavailable => false,
    }
}

fn replay_complete(key: StreamKey, cursor: StreamCursor) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: key.stream_route,
            generation: key.generation,
            current_cursor: cursor,
        }),
    }
}

fn cursor_at_or_before(cursor: StreamCursor, terminal: StreamCursor) -> bool {
    match (cursor, terminal) {
        (StreamCursor::BeforeFirst, _) => true,
        (StreamCursor::At(_), StreamCursor::BeforeFirst) => false,
        (StreamCursor::At(cursor), StreamCursor::At(terminal)) => cursor <= terminal,
    }
}

/// 先对所有可变长 wire 字段做无分配上界检查，避免为了判断 4 MiB 上限先复制攻击者
/// 提供的超大 Vec/String。固定长度字段随后再由 canonical encode 给出精确长度。
fn variable_payload_bytes(body: &RelayFrameBody) -> Option<usize> {
    match body {
        RelayFrameBody::PairData(frame) => Some(frame.sealed_blob.0.len()),
        RelayFrameBody::Publish(frame) => Some(frame.sealed_blob.0.len()),
        RelayFrameBody::Send(frame) => Some(frame.sealed_blob.0.len()),
        RelayFrameBody::Reply(frame) => Some(frame.sealed_blob.0.len()),
        RelayFrameBody::Error(error) => error
            .code
            .len()
            .checked_add(error.message.len())?
            .checked_add(error.in_reply_to.as_ref().map_or(0, String::len)),
        _ => Some(0),
    }
}

fn machine_access(access: &AccessContext) -> Result<MachineRouteId, RelayFailure> {
    match access {
        AccessContext::Machine(access) => Ok(access.machine_route),
        AccessContext::Device(_) | AccessContext::Pairing(_) => Err(forbidden()),
    }
}

fn device_access(
    access: &AccessContext,
) -> Result<(MachineRouteId, DeviceRouteId, GrantSerial), RelayFailure> {
    match access {
        AccessContext::Device(access) => Ok((
            access.machine_route,
            access.device_route,
            access.grant_serial,
        )),
        AccessContext::Machine(_) | AccessContext::Pairing(_) => Err(forbidden()),
    }
}

fn terminal_matches_reason(frame: &OpaqueRouteFrame, reason: WriterCloseReason) -> bool {
    if frame.version != RELAY_PROTOCOL_VERSION {
        return false;
    }
    match (&frame.body, reason) {
        (RelayFrameBody::RevocationCommitted(committed), WriterCloseReason::Revoked) => {
            committed.device_route == committed.signed_revocation.device_route
                && committed.grant_serial == committed.signed_revocation.grant_serial
        }
        (RelayFrameBody::RetirementCommitted(_), WriterCloseReason::Retired) => true,
        _ => false,
    }
}

fn terminal_matches_access(
    access: &AccessContext,
    frame: &OpaqueRouteFrame,
    reason: WriterCloseReason,
) -> bool {
    if !terminal_matches_reason(frame, reason) {
        return false;
    }
    match (access, &frame.body) {
        (AccessContext::Device(access), RelayFrameBody::RevocationCommitted(committed)) => {
            let signed = &committed.signed_revocation;
            signed.machine_route == access.machine_route
                && signed.device_route == access.device_route
                && signed.grant_serial == access.grant_serial
        }
        (AccessContext::Machine(access), RelayFrameBody::RetirementCommitted(committed)) => {
            committed.machine_route == access.machine_route
                && committed.trust_epoch == access.trust_epoch
        }
        _ => false,
    }
}

fn map_store_error(error: StoreError) -> RelayFailure {
    match error {
        StoreError::StreamOwnerConflict
        | StoreError::StreamNotFound
        | StoreError::GrantNotFound
        | StoreError::MachineNotFound => {
            failure(RELAY_ROUTE_NOT_FOUND, "opaque route is unavailable")
        }
        StoreError::StreamBindingConflict => failure(
            RELAY_STREAM_GENERATION_STALE,
            "stream generation does not match the route",
        ),
        StoreError::SequenceConflict { .. } | StoreError::IdempotencyConflict { .. } => failure(
            RELAY_STREAM_OUT_OF_ORDER,
            "stream sequence is not the expected next value",
        ),
        StoreError::InvalidReplayCursor => {
            failure(RELAY_REPLAY_CURSOR_INVALID, "replay cursor is invalid")
        }
        StoreError::FrameTooLarge => failure(
            RELAY_FRAME_TOO_LARGE,
            "Relay frame exceeds the public limit",
        ),
        StoreError::QuotaExceeded { .. } => quota("Relay storage quota is exhausted"),
        StoreError::DiskSpaceLow => failure(RELAY_DISK_LOW, "Relay disk reserve is low"),
        StoreError::Revoked => failure(RELAY_AUTH_REVOKED, "device grant is revoked"),
        StoreError::AuthenticationMismatch { .. } => invalid_access(),
        StoreError::InvalidValue {
            field: "stream_seq",
            ..
        } => failure(
            RELAY_STREAM_GENERATION_STALE,
            "stream generation is exhausted",
        ),
        _ => unavailable("Relay storage is unavailable"),
    }
}

fn connection_failure(error: ConnectionStateError) -> RelayFailure {
    match error {
        ConnectionStateError::SubscriptionLimit => quota("Relay connection capacity is exhausted"),
        ConnectionStateError::DuplicateConnection => failure(
            RELAY_ROUTE_CONFLICT,
            "connection instance is already registered",
        ),
        ConnectionStateError::ConnectionNotFound
        | ConnectionStateError::ConnectionNotActive
        | ConnectionStateError::AccessMismatch => invalid_access(),
        ConnectionStateError::ReplayEpochExhausted | ConnectionStateError::ReplayMismatch => {
            unavailable("Relay replay state is unavailable")
        }
        ConnectionStateError::HeartbeatAlreadyPending => {
            unavailable("Relay heartbeat state is unavailable")
        }
        ConnectionStateError::TerminalRejected => {
            unavailable("Relay terminal writer state is unavailable")
        }
    }
}

fn forbidden() -> RelayFailure {
    failure(
        RELAY_ROUTE_FORBIDDEN,
        "frame is not allowed for this access",
    )
}

fn route_not_found() -> RelayFailure {
    failure(RELAY_ROUTE_NOT_FOUND, "opaque route is unavailable")
}

fn invalid_access() -> RelayFailure {
    failure(
        RELAY_AUTH_INVALID_GRANT,
        "authenticated connection is no longer current",
    )
}

fn draining_failure() -> RelayFailure {
    RelayFailure::new(
        "relay.server.draining",
        "Relay server is draining and no longer accepts mutations",
    )
}

fn quota(message: &'static str) -> RelayFailure {
    failure(RELAY_QUOTA_EXCEEDED, message)
}

fn unavailable(message: &'static str) -> RelayFailure {
    failure(RELAY_STORE_UNAVAILABLE, message)
}

fn failure(code: &'static str, message: &'static str) -> RelayFailure {
    RelayFailure::new(code, message)
}

#[cfg(test)]
mod tests {
    use agentdeck_crypto::{SigningKey, ValidatedRelayReceiptSignerIdentityV1};

    use super::*;

    #[tokio::test]
    async fn fail_closed_all_overrides_terminal_grace_and_reaps_core_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let receipt_identity = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(
            &SigningKey::from_seed(&[0x71; 32]),
        )
        .expect("valid test receipt signer");
        let store = RelayStoreHandle::open(crate::v2::store::RelayV2StoreConfig::new(
            temp.path().join("relay-private").join("relay.db"),
            receipt_identity,
        ))
        .await
        .expect("open store");
        let (authorization, lifecycle) =
            AuthorizationCoordinator::start(store.clone(), 8).expect("authorization coordinator");
        let config = CoreConfig::default();
        let (tx, _rx) = mpsc::channel(config.command_capacity);
        let mut actor = RelayCoreActor {
            store: store.clone(),
            authorization,
            lifecycle,
            connections: ConnectionRegistry::new(config.max_subscriptions_per_connection),
            device_refresh_pending: HashSet::new(),
            pair_routes: PairRouteRegistry::new(store.relay_server_id(), config.pair_route_limits)
                .expect("pair registry"),
            draining: false,
            config,
            now_ms: config.initial_now_ms,
            next_nonce: config.nonce_seed,
            replay_staging: Arc::new(Semaphore::new(config.replay_staging_pages)),
            outbound_budget: Arc::new(GlobalWriterBudget::new(
                super::super::writer::WriterBudget::new(
                    config.global_normal_max_frames,
                    config.global_normal_max_bytes,
                ),
                super::super::writer::WriterBudget::new(
                    config.global_control_max_frames,
                    config.global_control_max_bytes,
                ),
            )),
            weak_tx: tx.downgrade(),
            tasks: CoreTasks::new(),
        };
        let connection = ConnectionInstanceId::from_bytes([0x41; 16]);
        let (writer, _receiver) = super::super::writer::OutboundWriter::channel();
        actor
            .connections
            .attach_pending(connection, writer.clone(), 0)
            .expect("attach terminalizing writer");
        actor
            .connections
            .begin_terminal(
                connection,
                OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION,
                    body: RelayFrameBody::Pong(Pong { nonce: 1 }),
                },
                WriterCloseReason::Retired,
            )
            .expect("stage terminal grace");
        actor.tasks.spawn(std::future::pending());

        assert!(
            actor.handle_lifecycle(Some(AuthorizationLifecycleEvent::FailClosedAll {
                connections: vec![connection],
            },))
        );
        assert_eq!(
            writer.close_reason(),
            Some(WriterCloseReason::AuthorizationInvalidated),
            "emergency fail-close must override terminal grace"
        );
        assert_eq!(actor.connections.len(), 0);

        actor.fail_closed_shutdown().await;
        assert!(actor.tasks.is_empty());
        assert!(actor.tasks.is_cancelled());
        store.shutdown().await.expect("shutdown store");
    }

    #[test]
    fn core_config_accepts_exact_hard_maxima_and_rejects_every_unbounded_dimension() {
        let at_max = CoreConfig {
            command_capacity: CORE_COMMAND_CAPACITY_HARD_MAX,
            ingress_bytes: CORE_INGRESS_BYTES_HARD_MAX,
            max_connections: CORE_CONNECTIONS_HARD_MAX,
            max_subscriptions_per_connection: CORE_SUBSCRIPTIONS_PER_CONNECTION_HARD_MAX,
            replay_staging_pages: CORE_REPLAY_STAGING_PAGES_HARD_MAX,
            global_normal_max_frames: CORE_GLOBAL_NORMAL_FRAMES_HARD_MAX,
            global_normal_max_bytes: CORE_GLOBAL_NORMAL_BYTES_HARD_MAX,
            global_control_max_frames: CORE_GLOBAL_CONTROL_FRAMES_HARD_MAX,
            global_control_max_bytes: CORE_GLOBAL_CONTROL_BYTES_HARD_MAX,
            ..CoreConfig::default()
        };
        assert!(at_max.validate().is_ok());

        macro_rules! rejects_over_max {
            ($field:ident, $max:expr) => {{
                let mut invalid = CoreConfig::default();
                invalid.$field = $max + 1;
                assert!(
                    invalid.validate().is_err(),
                    "{} must have a hard maximum",
                    stringify!($field)
                );
            }};
        }
        rejects_over_max!(command_capacity, CORE_COMMAND_CAPACITY_HARD_MAX);
        rejects_over_max!(ingress_bytes, CORE_INGRESS_BYTES_HARD_MAX);
        rejects_over_max!(max_connections, CORE_CONNECTIONS_HARD_MAX);
        rejects_over_max!(
            max_subscriptions_per_connection,
            CORE_SUBSCRIPTIONS_PER_CONNECTION_HARD_MAX
        );
        rejects_over_max!(replay_staging_pages, CORE_REPLAY_STAGING_PAGES_HARD_MAX);
        rejects_over_max!(global_normal_max_frames, CORE_GLOBAL_NORMAL_FRAMES_HARD_MAX);
        rejects_over_max!(global_normal_max_bytes, CORE_GLOBAL_NORMAL_BYTES_HARD_MAX);
        rejects_over_max!(
            global_control_max_frames,
            CORE_GLOBAL_CONTROL_FRAMES_HARD_MAX
        );
        rejects_over_max!(global_control_max_bytes, CORE_GLOBAL_CONTROL_BYTES_HARD_MAX);
    }
}
