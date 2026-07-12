//! Relay v2 网络服务：binary-only WebSocket、TLS fail-closed、健康检查与结构化关闭。

mod connection;
mod enrollment;
mod health;
mod preupgrade;
pub mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_protocol::relay_v2::failure::RELAY_VERSION_UNSUPPORTED;
use agentdeck_protocol::relay_v2::frame::ServerRestarting;
use agentdeck_protocol::relay_v2::{OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody};
use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, Request, State};
use axum::http::header::CONNECTION;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::instrument::WithSubscriber;

use crate::config::{
    RelayV2AdminConfig, RelayV2ConfigError, RelayV2ServerConfig, RelayV2TlsPaths,
    RelayV2TransportMode,
};
use crate::v2::admin::{AdminCommandExecutor, AdminRuntimeConfig, AdminServer, AdminServerError};
use crate::v2::auth::{
    AuthorizationCoordinator, ChallengeLimits, ChallengeRegistry, SystemMonotonicClock,
};
use crate::v2::core::{CoreConfig, RelayCore, WriterCloseReason};
use crate::v2::store::{RelayStoreHandle, StoreError};

use connection::{
    AcceptedConnection, ConnectionBook, ConnectionMode, ConnectionServices,
    GLOBAL_WS_INGRESS_BYTES, MAX_WS_MESSAGE_BYTES, run_connection,
};
use enrollment::{EnrollmentError, EnrollmentService, MAX_ENROLLMENT_BODY_BYTES};
use health::{HealthState, ReadinessCache};
use preupgrade::{BoundedTcpListener, PublicConnectInfo};
use tls::{LoadedTlsIdentity, TlsIdentityError, TlsIdentityPaths, load_tls_identity};

pub use preupgrade::{MAX_PUBLIC_CONNECTIONS, MAX_PUBLIC_HEADER_BYTES, PUBLIC_UPGRADE_DEADLINE};

pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPTED_CONNECTION_CAPACITY: usize = 256;
const TRUSTED_PROXY_SOURCE_HEADER: &str = "x-agentdeck-client-ip";

#[derive(Debug, thiserror::Error)]
pub enum RelayV2ServerError {
    #[error("Relay v2 configuration is invalid: {0}")]
    Config(#[from] RelayV2ConfigError),
    #[error("Relay v2 TLS identity is invalid: {0}")]
    Tls(#[from] TlsIdentityError),
    #[error("Relay v2 admin service failed: {0}")]
    Admin(#[from] AdminServerError),
    #[error("Relay v2 store failed: {0}")]
    Store(#[from] StoreError),
    #[error("Relay v2 core failed: {code}")]
    Core { code: String },
    #[error("Relay v2 listener failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Relay v2 shutdown signal adapter failed")]
    Signal,
    #[error("Relay v2 server task failed")]
    Task,
    #[error("Relay v2 drain deadline elapsed")]
    DrainTimeout,
}

impl RelayV2ServerError {
    /// 二进制只向 stderr 暴露稳定 failure code，不回显路径、证书或 Store 细节。
    pub fn code(&self) -> &str {
        match self {
            Self::Config(error) => error.code(),
            Self::Tls(error) => error.code(),
            Self::Admin(error) => error.code(),
            Self::Store(error) => error.diagnostic_code(),
            Self::Core { code } => code,
            Self::Io(_) => "relay.server.io",
            Self::Signal => "relay.server.signal_failed",
            Self::Task => "relay.server.task_failed",
            Self::DrainTimeout => "relay.server.drain_timeout",
        }
    }
}

fn core_error(error: agentdeck_protocol::relay_v2::RelayFailure) -> RelayV2ServerError {
    RelayV2ServerError::Core { code: error.code }
}

#[derive(Clone)]
struct PublicState {
    accepted: tokio::sync::mpsc::Sender<AcceptedConnection>,
    draining: Arc<AtomicBool>,
    source_policy: SourcePolicy,
    enrollment: Option<EnrollmentService>,
    enrollment_ingress: Arc<tokio::sync::Semaphore>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourcePolicy {
    DirectPeer,
    TrustedLoopbackProxy,
}

fn resolve_source(
    policy: SourcePolicy,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<SocketAddr, &'static str> {
    if policy == SourcePolicy::DirectPeer {
        return Ok(peer);
    }
    if !peer.ip().is_loopback() {
        return Err("relay.transport.proxy_requires_loopback");
    }
    let mut values = headers.get_all(TRUSTED_PROXY_SOURCE_HEADER).iter();
    let value = values.next().ok_or("relay.proxy.source_required")?;
    if values.next().is_some() {
        return Err("relay.proxy.source_invalid");
    }
    let source = value
        .to_str()
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or("relay.proxy.source_invalid")?;
    Ok(SocketAddr::new(source, peer.port()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rejection {
    code: &'static str,
}

async fn accept_websocket(
    State(state): State<PublicState>,
    ConnectInfo(connect_info): ConnectInfo<PublicConnectInfo>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    mode: ConnectionMode,
) -> Response {
    if state.draining.load(Ordering::Acquire) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Rejection {
                code: "relay.server.draining",
            }),
        )
            .into_response();
    }
    // 配对 bearer route 绝不能进入 URL/access log。固定 path 上任何 query 都拒绝，
    // pairing selector 只能作为 TLS 建立后的 canonical binary PairingHello 出现。
    if uri.query().is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(Rejection {
                code: "relay.frame.invalid",
            }),
        )
            .into_response();
    }
    let source = match resolve_source(state.source_policy, connect_info.source(), &headers) {
        Ok(source) => source,
        Err(code) => {
            return (StatusCode::BAD_REQUEST, Json(Rejection { code })).into_response();
        }
    };
    let accepted = state.accepted;
    // 只有走到这里的 WebSocketUpgrade 才会返回 101；此信号解除底层 accept→upgrade
    // deadline。所有 rejection/404/405 保持 deadline armed，并由 middleware 强制 close。
    connect_info.mark_upgraded();
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            if accepted
                .try_send(AcceptedConnection {
                    socket,
                    source,
                    mode,
                })
                .is_err()
            {
                tracing::warn!(
                    failure_code = "relay.quota.exceeded",
                    event = "relay.connection.rejected",
                    "Relay v2 accepted-connection queue is full"
                );
            }
        })
}

async fn connect_principal(
    state: State<PublicState>,
    source: ConnectInfo<PublicConnectInfo>,
    uri: OriginalUri,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    accept_websocket(state, source, uri, headers, ws, ConnectionMode::Principal).await
}

async fn connect_pairing(
    state: State<PublicState>,
    source: ConnectInfo<PublicConnectInfo>,
    uri: OriginalUri,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    accept_websocket(state, source, uri, headers, ws, ConnectionMode::Pairing).await
}

async fn enroll_machine(
    State(state): State<PublicState>,
    ConnectInfo(connect_info): ConnectInfo<PublicConnectInfo>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if state.draining.load(Ordering::Acquire) {
        return enrollment_rejection(StatusCode::SERVICE_UNAVAILABLE, "relay.server.draining");
    }
    if uri.query().is_some() {
        return enrollment_rejection(StatusCode::BAD_REQUEST, "relay.enrollment.request_invalid");
    }
    if resolve_source(state.source_policy, connect_info.source(), &headers).is_err() {
        return enrollment_rejection(StatusCode::BAD_REQUEST, "relay.enrollment.request_invalid");
    }
    let Some(service) = state.enrollment else {
        return enrollment_rejection(StatusCode::NOT_FOUND, "relay.route.not_found");
    };
    let Ok(_permit) = state.enrollment_ingress.try_acquire() else {
        return enrollment_rejection(StatusCode::SERVICE_UNAVAILABLE, "relay.quota.exceeded");
    };
    let request = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return enrollment_rejection(
                StatusCode::BAD_REQUEST,
                "relay.enrollment.request_invalid",
            );
        }
    };
    match service.enroll(request).await {
        Ok(response) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            response,
        )
            .into_response(),
        Err(error) => {
            let status = match error {
                EnrollmentError::Rejected => StatusCode::FORBIDDEN,
                EnrollmentError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            };
            enrollment_rejection(status, error.code())
        }
    }
}

fn enrollment_rejection(status: StatusCode, code: &'static str) -> Response {
    (status, Json(Rejection { code })).into_response()
}

/// 已删除的 v1 固定入口只保留无状态 HTTP tombstone：不升级 WebSocket、不读取
/// Authorization，也不触达 challenge/auth/store。旧客户端因此能在拨号边界得到稳定
/// reset 信号，而不是被误导为临时网络故障。
async fn legacy_v1_tombstone() -> Response {
    (
        StatusCode::UPGRADE_REQUIRED,
        Json(Rejection {
            code: RELAY_VERSION_UNSUPPORTED,
        }),
    )
        .into_response()
}

/// 公开 listener 不是通用 HTTP 服务。只有成功的 WebSocket 101 可以把物理连接 permit
/// 转成长期 WS 生命周期；所有 400/404/405 与 extractor rejection 都必须显式关闭，避免
/// 完整 HTTP/1.1 keep-alive 在完成 header 后、101 deadline 到达前持续占住 permit。
async fn close_non_switching_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

fn public_router(state: PublicState) -> Router {
    // health/readiness 故意不挂到公开 listener；未知 path 只返回 404，不 redirect。
    Router::new()
        .route("/v1/connect", any(legacy_v1_tombstone))
        .route("/v2/connect", get(connect_principal))
        .route("/v2/pair", get(connect_pairing))
        .route("/v2/machine-enroll", post(enroll_machine))
        .layer(DefaultBodyLimit::max(MAX_ENROLLMENT_BODY_BYTES))
        .layer(middleware::from_fn(close_non_switching_response))
        .with_state(state)
}

struct RelayV2Service {
    store: RelayStoreHandle,
    authorization: AuthorizationCoordinator,
    core: RelayCore,
    challenges: Arc<ChallengeRegistry>,
    source_hash_key: [u8; 32],
    connections: Arc<ConnectionBook>,
    draining: Arc<AtomicBool>,
    readiness: ReadinessCache,
    network_ingress: Arc<tokio::sync::Semaphore>,
    connection_shutdown: CancellationToken,
}

impl RelayV2Service {
    async fn open(
        config: crate::v2::store::RelayV2StoreConfig,
    ) -> Result<Self, RelayV2ServerError> {
        let store = RelayStoreHandle::open(config).await?;
        let relay_server_id = store.relay_server_id();
        let core_config = CoreConfig {
            initial_now_ms: unix_now_ms(),
            ..CoreConfig::default()
        };
        let (authorization, lifecycle) =
            AuthorizationCoordinator::start(store.clone(), core_config.max_connections)
                .map_err(core_error)?;
        let core = RelayCore::start(store.clone(), authorization.clone(), lifecycle, core_config)
            .map_err(core_error)?;
        let challenges = Arc::new(
            ChallengeRegistry::new(
                relay_server_id,
                Arc::new(SystemMonotonicClock::default()),
                ChallengeLimits::default(),
            )
            .map_err(core_error)?,
        );
        let mut source_hash_key = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut source_hash_key)
            .map_err(|_| RelayV2ServerError::Task)?;
        let readiness = ReadinessCache::ready();
        if let Err(error) = store.probe_readiness().await {
            readiness.mark_not_ready(error.diagnostic_code());
        }
        Ok(Self {
            store,
            authorization,
            core,
            challenges,
            source_hash_key,
            connections: Arc::new(ConnectionBook::default()),
            draining: Arc::new(AtomicBool::new(false)),
            readiness,
            network_ingress: Arc::new(tokio::sync::Semaphore::new(GLOBAL_WS_INGRESS_BYTES)),
            connection_shutdown: CancellationToken::new(),
        })
    }

    fn connection_services(&self) -> ConnectionServices {
        ConnectionServices {
            core: self.core.clone(),
            authorization: self.authorization.clone(),
            challenges: Arc::clone(&self.challenges),
            relay_server_id: self.store.relay_server_id(),
            source_hash_key: self.source_hash_key,
            book: Arc::clone(&self.connections),
            draining: Arc::clone(&self.draining),
            network_ingress: Arc::clone(&self.network_ingress),
            shutdown: self.connection_shutdown.clone(),
        }
    }

    fn health_state(&self) -> HealthState {
        HealthState::new(self.readiness.clone(), Arc::clone(&self.draining))
    }

    async fn begin_drain(&self, timeout: Duration) -> Result<(), RelayV2ServerError> {
        let started = tokio::time::Instant::now();
        self.draining.store(true, Ordering::Release);
        self.readiness.mark_not_ready("relay.server.draining");
        let deadline_ms =
            unix_now_ms().saturating_add(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX));
        let restart = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::ServerRestarting(ServerRestarting {
                drain_deadline_ms: deadline_ms,
            }),
        };
        let writers = self.connections.begin_drain();
        for writer in writers {
            if writer.try_enqueue_control(restart.clone()).is_err() {
                let _ = writer.close_unless_terminalizing(WriterCloseReason::CriticalBackpressure);
            }
        }
        let fence_result = tokio::time::timeout(timeout, async {
            self.authorization.begin_drain().await.map_err(core_error)?;
            self.core.begin_drain().await.map_err(core_error)
        })
        .await
        .map_err(|_| RelayV2ServerError::DrainTimeout)
        .and_then(std::convert::identity);
        let remaining = timeout.saturating_sub(started.elapsed());
        let _ = tokio::time::timeout(remaining, self.connections.wait_empty()).await;
        for writer in self.connections.writers() {
            writer.close(WriterCloseReason::Shutdown);
        }
        self.connection_shutdown.cancel();
        fence_result
    }

    async fn shutdown(self) -> Result<(), RelayV2ServerError> {
        let core_result = self.core.shutdown().await.map_err(core_error);
        if core_result.is_err() {
            // Core actor异常退出时不能假设它已走到 authorization shutdown；由 service
            // 保留的 clone 再做一次 best-effort 收口，确保 Store owner gate 可释放。
            let _ = self.authorization.shutdown().await;
        }
        // 无论 Core/Auth 结果如何都必须 await Store。cleanup 失败优先返回，因为它意味着
        // DB/process lock 仍可能存活；Core 错误只在 Store 已确定 quiesce 后返回。
        let store_result = self.store.shutdown().await.map_err(Into::into);
        match (core_result, store_result) {
            (_, Err(store_error)) => Err(store_error),
            (Err(core_error), Ok(())) => Err(core_error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

async fn run_monitor(
    core: RelayCore,
    store: RelayStoreHandle,
    readiness: ReadinessCache,
    shutdown: CancellationToken,
) -> Result<(), RelayV2ServerError> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut maintenance_ticks = 0_u8;
    let mut readiness_ticks = 4_u8;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let tick_result = tokio::select! {
                    _ = shutdown.cancelled() => return Ok(()),
                    result = core.tick(unix_now_ms()) => result,
                };
                if let Err(error) = tick_result {
                    if error.code == agentdeck_protocol::relay_v2::failure::RELAY_QUOTA_EXCEEDED {
                        readiness.mark_not_ready("relay.quota.exceeded");
                        tracing::warn!(
                            event = "relay.core.tick_deferred",
                            failure_code = %error.code,
                            "Relay v2 Core tick was deferred by bounded command pressure"
                        );
                        continue;
                    }
                    readiness.mark_not_ready("relay.store.unavailable");
                    return Err(core_error(error));
                }
                readiness_ticks = readiness_ticks.saturating_add(1);
                if readiness_ticks >= 5 {
                    readiness_ticks = 0;
                    let readiness_result = tokio::select! {
                        _ = shutdown.cancelled() => return Ok(()),
                        result = store.probe_readiness() => result,
                    };
                    match readiness_result {
                        Ok(()) => readiness.mark_ready(),
                        Err(error) => readiness.mark_not_ready(error.diagnostic_code()),
                    }
                }
                maintenance_ticks = maintenance_ticks.wrapping_add(1);
                if maintenance_ticks == 0 || maintenance_ticks == 60 {
                    maintenance_ticks = 0;
                    let maintenance = tokio::select! {
                        _ = shutdown.cancelled() => return Ok(()),
                        result = store.run_maintenance() => result,
                    };
                    if let Err(error) = maintenance {
                        tracing::warn!(
                            event = "relay.store.maintenance_failed",
                            failure_code = error.diagnostic_code(),
                            "Relay v2 periodic maintenance failed"
                        );
                    }
                }
            }
        }
    }
}

async fn preflight_tls(
    transport: &RelayV2TransportMode,
) -> Result<Option<LoadedTlsIdentity>, RelayV2ServerError> {
    match transport {
        RelayV2TransportMode::DirectTls(RelayV2TlsPaths { cert, key }) => {
            let paths = TlsIdentityPaths::new(cert, key);
            Ok(Some(load_tls_identity(&paths).await?))
        }
        RelayV2TransportMode::InsecureLoopback | RelayV2TransportMode::ProxyLoopback => Ok(None),
    }
}

fn validate_admin_tls_pin(
    admin: Option<&RelayV2AdminConfig>,
    identity: Option<&LoadedTlsIdentity>,
) -> Result<(), RelayV2ServerError> {
    let (Some(admin), Some(identity)) = (admin, identity) else {
        return Ok(());
    };
    #[cfg(feature = "tls")]
    if admin.spki_pins.first().copied() != Some(identity.leaf_spki_sha256()) {
        return Err(TlsIdentityError::PinMismatch.into());
    }
    #[cfg(not(feature = "tls"))]
    let _ = (admin, identity);
    Ok(())
}

/// library-level selfcheck：TLS 先于 DB 校验，随后真实 migration/readiness/Core 构造与重开。
pub async fn selfcheck(config: RelayV2ServerConfig) -> Result<(), RelayV2ServerError> {
    config.validate()?;
    let identity = preflight_tls(&config.transport).await?;
    validate_admin_tls_pin(config.admin.as_ref(), identity.as_ref())?;
    let store_config = config.store.clone().into_store_config()?;
    let reopen_config = store_config.clone();
    let service = RelayV2Service::open(store_config).await?;
    service.store.inspect().await?;
    service.store.probe_readiness().await?;
    service.shutdown().await?;

    // 重开必须沿用与首次启动完全相同的 retention、metadata、磁盘预留和探针配置，
    // 否则 selfcheck 可能验证的是另一套默认配置。
    let reopened = RelayStoreHandle::open(reopen_config).await?;
    reopened.inspect().await?;
    reopened.shutdown().await?;
    Ok(())
}

/// 完整 v2 library server。TLS identity 在任何 bind/DB side effect 前验证。
pub async fn serve(
    config: RelayV2ServerConfig,
    shutdown: CancellationToken,
) -> Result<(), RelayV2ServerError> {
    let mut handle = RelayV2ServerHandle::start(config).await?;
    let completed = {
        let task = handle.task.as_mut().ok_or(RelayV2ServerError::Task)?;
        tokio::select! {
            _ = shutdown.cancelled() => None,
            result = task => Some(result.map_err(|_| RelayV2ServerError::Task)?),
        }
    };
    let result = match completed {
        Some(result) => result,
        None => {
            handle.shutdown.cancel();
            handle
                .task
                .as_mut()
                .ok_or(RelayV2ServerError::Task)?
                .await
                .map_err(|_| RelayV2ServerError::Task)?
        }
    };
    handle.task.take();
    result
}

/// production signal adapter；P2.9 binary cutover 直接复用同一 CancellationToken 路径。
pub async fn serve_until_signal(config: RelayV2ServerConfig) -> Result<(), RelayV2ServerError> {
    let shutdown = CancellationToken::new();
    let server = serve(config, shutdown.clone());
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result,
        result = wait_for_shutdown_signal() => {
            result.map_err(|_| RelayV2ServerError::Signal)?;
            shutdown.cancel();
            server.await
        }
    }
}

async fn wait_for_shutdown_signal() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

/// 已绑定的 v2 server，供 binary adapter 与 loopback integration test 使用。
pub struct RelayV2ServerHandle {
    public_addr: SocketAddr,
    health_addr: SocketAddr,
    admin_socket_path: Option<std::path::PathBuf>,
    shutdown: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<(), RelayV2ServerError>>>,
}

impl RelayV2ServerHandle {
    pub async fn start(config: RelayV2ServerConfig) -> Result<Self, RelayV2ServerError> {
        config.validate()?;
        let identity = preflight_tls(&config.transport).await?;
        validate_admin_tls_pin(config.admin.as_ref(), identity.as_ref())?;
        let source_policy = match config.transport {
            RelayV2TransportMode::ProxyLoopback => SourcePolicy::TrustedLoopbackProxy,
            RelayV2TransportMode::DirectTls(_) | RelayV2TransportMode::InsecureLoopback => {
                SourcePolicy::DirectPeer
            }
        };
        let store_config = config.store.clone().into_store_config()?;
        let service = RelayV2Service::open(store_config).await?;
        let enrollment = config.admin.as_ref().map(|_| {
            EnrollmentService::new(
                service.authorization.clone(),
                service.store.relay_server_id(),
            )
        });
        let (admin_server, admin_socket_path) = if let Some(admin) = config.admin.clone() {
            let executor = AdminCommandExecutor::new(
                service.store.clone(),
                service.authorization.clone(),
                service.core.clone(),
                AdminRuntimeConfig {
                    public_wss_url: admin.public_wss_url,
                    spki_pins: admin.spki_pins,
                },
            );
            let path = admin.socket_path.clone();
            match AdminServer::bind(admin.socket_path, executor).await {
                Ok(server) => (Some(server), Some(path)),
                Err(error) => {
                    service.shutdown().await?;
                    return Err(error.into());
                }
            }
        } else {
            (None, None)
        };
        let public_listener = match TcpListener::bind(config.bind).await {
            Ok(listener) => listener,
            Err(error) => {
                service.shutdown().await?;
                return Err(RelayV2ServerError::Io(error));
            }
        };
        let health_listener = match TcpListener::bind(config.health_bind).await {
            Ok(listener) => listener,
            Err(error) => {
                service.shutdown().await?;
                return Err(RelayV2ServerError::Io(error));
            }
        };
        let public_addr = match public_listener.local_addr() {
            Ok(address) => address,
            Err(error) => {
                service.shutdown().await?;
                return Err(error.into());
            }
        };
        let health_addr = match health_listener.local_addr() {
            Ok(address) => address,
            Err(error) => {
                service.shutdown().await?;
                return Err(error.into());
            }
        };
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(
            serve_with_listeners(
                service,
                BoundRelayV2 {
                    public_listener,
                    health_listener,
                    identity,
                    source_policy,
                    enrollment,
                    admin_server,
                },
                task_shutdown,
            )
            .with_current_subscriber(),
        );
        Ok(Self {
            public_addr,
            health_addr,
            admin_socket_path,
            shutdown,
            task: Some(task),
        })
    }

    pub fn public_addr(&self) -> SocketAddr {
        self.public_addr
    }

    pub fn health_addr(&self) -> SocketAddr {
        self.health_addr
    }

    pub fn admin_socket_path(&self) -> Option<&std::path::Path> {
        self.admin_socket_path.as_deref()
    }

    pub fn trigger_shutdown(&self) {
        self.shutdown.cancel();
    }

    pub async fn wait(mut self) -> Result<(), RelayV2ServerError> {
        let task = self.task.take().ok_or(RelayV2ServerError::Task)?;
        task.await.map_err(|_| RelayV2ServerError::Task)?
    }

    pub async fn shutdown(self) -> Result<(), RelayV2ServerError> {
        self.shutdown.cancel();
        self.wait().await
    }
}

impl Drop for RelayV2ServerHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
        let Some(task) = self.task.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = task.await;
            });
        } else {
            task.abort();
        }
    }
}

struct BoundRelayV2 {
    public_listener: TcpListener,
    health_listener: TcpListener,
    identity: Option<LoadedTlsIdentity>,
    source_policy: SourcePolicy,
    enrollment: Option<EnrollmentService>,
    admin_server: Option<AdminServer>,
}

async fn serve_with_listeners(
    service: RelayV2Service,
    bound: BoundRelayV2,
    shutdown: CancellationToken,
) -> Result<(), RelayV2ServerError> {
    let BoundRelayV2 {
        public_listener,
        health_listener,
        identity,
        source_policy,
        enrollment,
        admin_server,
    } = bound;
    if !health_listener.local_addr()?.ip().is_loopback() {
        return Err(RelayV2ServerError::Config(
            RelayV2ConfigError::HealthNonLoopback,
        ));
    }
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(ACCEPTED_CONNECTION_CAPACITY);
    let public = public_router(PublicState {
        accepted: accepted_tx,
        draining: Arc::clone(&service.draining),
        source_policy,
        enrollment,
        enrollment_ingress: Arc::new(tokio::sync::Semaphore::new(32)),
    });
    let health = health::router(service.health_state());
    let public_shutdown = CancellationToken::new();
    let health_shutdown = CancellationToken::new();
    let mut listeners = JoinSet::new();

    match identity {
        Some(identity) => {
            #[cfg(feature = "tls")]
            {
                let listener = BoundedTcpListener::tls(public_listener, identity.server_config());
                let tls_shutdown = public_shutdown.clone();
                listeners.spawn(async move {
                    axum::serve(
                        listener,
                        public.into_make_service_with_connect_info::<PublicConnectInfo>(),
                    )
                    .with_graceful_shutdown(tls_shutdown.cancelled_owned())
                    .await
                    .map_err(RelayV2ServerError::Io)
                });
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (identity, public_listener, public, public_shutdown.clone());
                return Err(RelayV2ServerError::Tls(TlsIdentityError::FeatureMissing));
            }
        }
        None => {
            let token = public_shutdown.clone();
            listeners.spawn(async move {
                axum::serve(
                    BoundedTcpListener::plaintext(public_listener),
                    public.into_make_service_with_connect_info::<PublicConnectInfo>(),
                )
                .with_graceful_shutdown(token.cancelled_owned())
                .await
                .map_err(RelayV2ServerError::Io)
            });
        }
    }
    let health_token = health_shutdown.clone();
    listeners.spawn(async move {
        axum::serve(health_listener, health)
            .with_graceful_shutdown(health_token.cancelled_owned())
            .await
            .map_err(RelayV2ServerError::Io)
    });
    let monitor_shutdown = CancellationToken::new();
    listeners.spawn(
        run_monitor(
            service.core.clone(),
            service.store.clone(),
            service.readiness.clone(),
            monitor_shutdown.clone(),
        )
        .with_current_subscriber(),
    );
    let admin_shutdown = CancellationToken::new();
    let mut admin_task = admin_server.map(|server| {
        let token = admin_shutdown.clone();
        tokio::spawn(async move { server.run(token).await })
    });

    let mut connections = JoinSet::new();
    let run_result = loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break Ok(()),
            joined = connections.join_next(), if !connections.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    break Err(RelayV2ServerError::Task);
                }
            }
            result = listeners.join_next() => {
                match result {
                    Some(Ok(Ok(()))) | None => break Err(RelayV2ServerError::Task),
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(_)) => break Err(RelayV2ServerError::Task),
                }
            }
            result = wait_admin_task(&mut admin_task), if admin_task.is_some() => {
                let _ = admin_task.take();
                break match result {
                    Ok(Ok(())) => Err(RelayV2ServerError::Task),
                    Ok(Err(error)) => Err(error.into()),
                    Err(_) => Err(RelayV2ServerError::Task),
                };
            }
            accepted = accepted_rx.recv() => {
                let Some(accepted) = accepted else {
                    break Err(RelayV2ServerError::Task);
                };
                let services = service.connection_services();
                connections.spawn(run_connection(accepted, services).with_current_subscriber());
            }
        }
    };

    // 先停止公开 accept，再发 restarting 并 drain；health 保持存活并返回 not-ready。
    let shutdown_deadline = tokio::time::Instant::now() + DEFAULT_DRAIN_TIMEOUT;
    service.draining.store(true, Ordering::Release);
    public_shutdown.cancel();
    admin_shutdown.cancel();
    accepted_rx.close();
    while accepted_rx.try_recv().is_ok() {}
    monitor_shutdown.cancel();
    let mut admin_result = Ok(());
    if let Some(task) = admin_task.take() {
        let mut task = task;
        match tokio::time::timeout(DEFAULT_DRAIN_TIMEOUT, &mut task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => admin_result = Err(error.into()),
            Ok(Err(_)) => admin_result = Err(RelayV2ServerError::Task),
            Err(_) => {
                task.abort();
                let _ = task.await;
                admin_result = Err(RelayV2ServerError::DrainTimeout);
            }
        }
    }
    let drain_result = service.begin_drain(DEFAULT_DRAIN_TIMEOUT).await;
    health_shutdown.cancel();

    let join_deadline = tokio::time::sleep_until(shutdown_deadline);
    tokio::pin!(join_deadline);
    loop {
        if connections.is_empty() {
            break;
        }
        tokio::select! {
            _ = &mut join_deadline => {
                connections.abort_all();
                break;
            }
            _ = connections.join_next() => {}
        }
    }
    while connections.join_next().await.is_some() {}
    let mut listener_result = Ok(());
    let listener_deadline = tokio::time::sleep_until(shutdown_deadline);
    tokio::pin!(listener_deadline);
    while !listeners.is_empty() {
        tokio::select! {
            _ = &mut listener_deadline => {
                listeners.abort_all();
                if listener_result.is_ok() {
                    listener_result = Err(RelayV2ServerError::DrainTimeout);
                }
                break;
            }
            result = listeners.join_next() => {
                match result {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => {
                        if listener_result.is_ok() {
                            listener_result = Err(error);
                        }
                    }
                    Some(Err(_)) => {
                        if listener_result.is_ok() {
                            listener_result = Err(RelayV2ServerError::Task);
                        }
                    }
                    None => break,
                }
            }
        }
    }
    while listeners.join_next().await.is_some() {}
    // 5 秒只约束网络 drain；超时后已强制 abort listener/connection。Core/Auth/Store
    // 仍必须真正 quiesce，不能以“超时返回”伪装 DB lock 和已入队 COMMIT 已回收。
    let shutdown_result = service.shutdown().await;
    run_result
        .and(admin_result)
        .and(drain_result)
        .and(listener_result)
        .and(shutdown_result)
}

async fn wait_admin_task(
    task: &mut Option<tokio::task::JoinHandle<Result<(), AdminServerError>>>,
) -> Result<Result<(), AdminServerError>, tokio::task::JoinError> {
    match task.as_mut() {
        Some(task) => task.await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{Arc, Mutex, mpsc as std_mpsc};
    use std::time::Duration;

    use agentdeck_protocol::relay_v2::failure::RELAY_QUOTA_EXCEEDED;
    use agentdeck_protocol::relay_v2::{ConnectionInstanceId, RelayServerId};
    use axum::http::{HeaderMap, HeaderValue};
    use tempfile::TempDir;

    use super::{RelayV2ServerError, RelayV2Service, SourcePolicy, resolve_source};
    use crate::config::RelayV2StoreSettings;
    use crate::v2::auth::{ChallengeLimits, ChallengeRegistry, MonotonicClock, TokenBucketLimits};
    use crate::v2::store::{FaultInjector, FaultPoint, RelayStoreHandle, StoreError};

    #[derive(Debug)]
    struct FixedMonotonicClock;

    impl MonotonicClock for FixedMonotonicClock {
        fn now_ms(&self) -> u64 {
            0
        }
    }

    #[derive(Debug)]
    struct ShutdownReplyBarrier {
        entered: Mutex<Option<std_mpsc::Sender<()>>>,
        release: Mutex<std_mpsc::Receiver<()>>,
    }

    impl FaultInjector for ShutdownReplyBarrier {
        fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
            if point != FaultPoint::ShutdownAfterReply {
                return Ok(());
            }
            if let Some(entered) = self
                .entered
                .lock()
                .map_err(|_| StoreError::InjectedFault(point))?
                .take()
            {
                entered
                    .send(())
                    .map_err(|_| StoreError::InjectedFault(point))?;
                self.release
                    .lock()
                    .map_err(|_| StoreError::InjectedFault(point))?
                    .recv()
                    .map_err(|_| StoreError::InjectedFault(point))?;
            }
            Ok(())
        }
    }

    #[test]
    fn trusted_loopback_proxy_source_is_required_and_keeps_attackers_in_separate_buckets() {
        let peer: SocketAddr = "127.0.0.1:43123".parse().unwrap();
        let mut first_headers = HeaderMap::new();
        first_headers.insert(
            "x-agentdeck-client-ip",
            HeaderValue::from_static("203.0.113.10"),
        );
        let mut second_headers = HeaderMap::new();
        second_headers.insert(
            "x-agentdeck-client-ip",
            HeaderValue::from_static("203.0.113.11"),
        );

        assert!(
            resolve_source(SourcePolicy::TrustedLoopbackProxy, peer, &HeaderMap::new()).is_err()
        );
        let first = resolve_source(SourcePolicy::TrustedLoopbackProxy, peer, &first_headers)
            .expect("trusted proxy source");
        let second = resolve_source(SourcePolicy::TrustedLoopbackProxy, peer, &second_headers)
            .expect("second trusted proxy source");
        assert_eq!(first.ip(), "203.0.113.10".parse::<IpAddr>().unwrap());
        assert_eq!(second.ip(), "203.0.113.11".parse::<IpAddr>().unwrap());
        assert_ne!(first.ip(), second.ip());

        let key = [0x5a; 32];
        let first_source = super::connection::source_hash(&key, first.ip());
        let second_source = super::connection::source_hash(&key, second.ip());
        let registry = ChallengeRegistry::new(
            RelayServerId::from_bytes([0x61; 16]),
            Arc::new(FixedMonotonicClock),
            ChallengeLimits {
                max_pending: 4,
                source_bucket: TokenBucketLimits {
                    capacity: 1,
                    refill_tokens_per_second: 1,
                },
                route_bucket: TokenBucketLimits {
                    capacity: 1,
                    refill_tokens_per_second: 1,
                },
                max_source_buckets: 4,
                max_route_buckets: 4,
                bucket_idle_ttl_ms: 30_000,
            },
        )
        .expect("challenge registry");
        registry
            .issue(ConnectionInstanceId::from_bytes([1; 16]), first_source)
            .expect("first attacker challenge");
        assert_eq!(
            registry
                .issue(ConnectionInstanceId::from_bytes([2; 16]), first_source)
                .expect_err("same source bucket is exhausted")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
        registry
            .issue(ConnectionInstanceId::from_bytes([3; 16]), second_source)
            .expect("another proxy source retains its own challenge budget");

        // direct TLS/dev loopback must ignore spoofed forwarding metadata.
        assert_eq!(
            resolve_source(SourcePolicy::DirectPeer, peer, &first_headers)
                .expect("direct peer source"),
            peer
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn core_shutdown_error_still_awaits_store_shutdown_and_lock_release() {
        let temp = TempDir::new().expect("tempdir");
        let storage_path = temp.path().join("service-error").join("relay.db");
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let barrier = Arc::new(ShutdownReplyBarrier {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
        });
        let mut settings = RelayV2StoreSettings::new(storage_path.clone());
        settings.disk_reserve_bytes = 0;
        settings.disk_reserve_percent = 0;
        let store_config = settings
            .clone()
            .into_store_config()
            .expect("service Store config")
            .with_fault_injector(barrier);
        let service = RelayV2Service::open(store_config)
            .await
            .expect("open service");

        // 先结束 Core，强制 service.shutdown 的第二次 Core shutdown 返回错误。
        service.core.shutdown().await.expect("pre-shutdown Core");
        let shutdown = tokio::spawn(async move { service.shutdown().await });
        tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .expect("join Store shutdown boundary")
            .expect("Core error path must still issue and await explicit Store shutdown");
        let result = tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("service shutdown must not wait for worker function return")
            .expect("join service shutdown");
        assert!(matches!(result, Err(RelayV2ServerError::Core { .. })));

        let mut reopen_settings = RelayV2StoreSettings::new(storage_path);
        reopen_settings.disk_reserve_bytes = 0;
        reopen_settings.disk_reserve_percent = 0;
        let reopened = RelayStoreHandle::open(
            reopen_settings
                .into_store_config()
                .expect("reopen Store config"),
        )
        .await;
        release_tx
            .send(())
            .expect("release old Store worker return");
        let reopened = reopened.expect("service error return must happen after Store lock release");
        reopened.shutdown().await.expect("shutdown reopened Store");
    }
}
