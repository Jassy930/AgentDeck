//! 授权状态的唯一线性化 actor。
//!
//! Store worker 负责 SQLite 原子性；本 actor 在它之上把 trust mutation 与 active
//! generation 变更串成一个不可被 caller future cancellation 打断的状态转换。生产 Core
//! 必须只经这里执行 Authenticate、InstallGrant、Revoke、RegisterMachine 与 PurgeMachine。

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_protocol::relay_v2::failure::{RELAY_QUOTA_EXCEEDED, RELAY_STORE_UNAVAILABLE};
use agentdeck_protocol::relay_v2::frame::Authenticate;
use agentdeck_protocol::relay_v2::{ConnectionInstanceId, RelayFailure};
use tokio::sync::{mpsc, oneshot};

use super::access::{
    AccessContext, Activation, ActiveConnectionRegistry, PrincipalRoute, RouteTransition,
};
use super::challenge::ConsumedChallenge;
use super::verify::{AuthenticationActivation, AuthenticationService};
use crate::v2::store::{
    GrantCommit, InstallGrantRecord, MAX_CONTROL_BLOB_BYTES, MachineRecord, PersistRevocation,
    PurgeMachine, PurgeReadback, RegisterMachine, RelayStoreHandle, RevocationCommit, StoreError,
};

const AUTHORIZATION_COMMAND_CAPACITY: usize = 256;
const AUTHORIZATION_LIFECYCLE_CAPACITY: usize = 512;

/// COMMIT 后被原子失效的连接也会走独立 lifecycle channel；oneshot 只承载调用结果，
/// caller cancellation 不会吞掉必须关闭的 writer ID。
pub struct AuthorizationMutation<T> {
    commit: T,
    invalidated_connections: Vec<ConnectionInstanceId>,
}

impl<T> AuthorizationMutation<T> {
    pub fn commit(&self) -> &T {
        &self.commit
    }

    pub fn invalidated_connections(&self) -> &[ConnectionInstanceId] {
        &self.invalidated_connections
    }

    pub fn into_parts(self) -> (T, Vec<ConnectionInstanceId>) {
        (self.commit, self.invalidated_connections)
    }
}

impl<T> fmt::Debug for AuthorizationMutation<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationMutation")
            .field("commit", &"<redacted>")
            .field(
                "invalidated_connection_count",
                &self.invalidated_connections.len(),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizationLifecycleEvent {
    Activated(Activation),
    Invalidated {
        connections: Vec<ConnectionInstanceId>,
    },
    /// 普通 lifecycle queue 满时使用独立 emergency slot；Core 必须关闭列出的全部 writer。
    FailClosedAll {
        connections: Vec<ConnectionInstanceId>,
    },
}

impl fmt::Debug for AuthorizationLifecycleEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Activated(activation) => formatter
                .debug_tuple("Activated")
                .field(activation)
                .finish(),
            Self::Invalidated { connections } => formatter
                .debug_struct("Invalidated")
                .field("connection_count", &connections.len())
                .finish(),
            Self::FailClosedAll { connections } => formatter
                .debug_struct("FailClosedAll")
                .field("connection_count", &connections.len())
                .finish(),
        }
    }
}

/// P2.3 Core 必须持续 drain；容量满或 receiver 消失时 coordinator fail-closed。
pub struct AuthorizationLifecycle {
    rx: mpsc::Receiver<AuthorizationLifecycleEvent>,
    emergency_rx: mpsc::Receiver<AuthorizationLifecycleEvent>,
    coordinator_tx: mpsc::Sender<AuthorizationCommand>,
    active: Arc<ActiveConnectionRegistry>,
    poisoned: Arc<AtomicBool>,
    terminal: bool,
}

impl AuthorizationLifecycle {
    pub async fn recv(&mut self) -> Option<AuthorizationLifecycleEvent> {
        if self.terminal {
            return None;
        }
        let mut event = tokio::select! {
            biased;
            event = self.emergency_rx.recv() => {
                match event {
                    Some(event) => Some(event),
                    None => self.rx.recv().await,
                }
            }
            event = self.rx.recv() => event,
        };
        if let Some(AuthorizationLifecycleEvent::FailClosedAll { connections }) = &mut event {
            while let Ok(queued) = self.rx.try_recv() {
                append_event_connections(connections, queued);
            }
            self.terminal = true;
        }
        event
    }
}

impl Drop for AuthorizationLifecycle {
    fn drop(&mut self) {
        self.poisoned.store(true, Ordering::Release);
        let _ = self.active.fail_closed_all();
        let _ = self
            .coordinator_tx
            .try_send(AuthorizationCommand::LifecycleDropped);
    }
}

fn append_event_connections(
    connections: &mut Vec<ConnectionInstanceId>,
    event: AuthorizationLifecycleEvent,
) {
    let mut append = |connection| {
        if !connections.contains(&connection) {
            connections.push(connection);
        }
    };
    match event {
        AuthorizationLifecycleEvent::Activated(activation) => {
            append(activation.connection_instance);
            if let Some(replaced) = activation.replaced {
                append(replaced);
            }
        }
        AuthorizationLifecycleEvent::Invalidated {
            connections: invalidated,
        }
        | AuthorizationLifecycleEvent::FailClosedAll {
            connections: invalidated,
        } => {
            for connection in invalidated {
                append(connection);
            }
        }
    }
}

impl fmt::Debug for AuthorizationLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationLifecycle")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct AuthorizationCoordinator {
    tx: mpsc::Sender<AuthorizationCommand>,
    active: Arc<ActiveConnectionRegistry>,
    poisoned: Arc<AtomicBool>,
}

impl fmt::Debug for AuthorizationCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCoordinator")
            .finish_non_exhaustive()
    }
}

impl AuthorizationCoordinator {
    /// 对同一个 Store-scoped ownership 只能成功一次；第二个 coordinator 与 coordinator
    /// 存活期间的 raw trust mutator 均 fail-closed。
    pub fn start(
        store: RelayStoreHandle,
        max_active: usize,
    ) -> Result<(Self, AuthorizationLifecycle), RelayFailure> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| unavailable())?;
        let active = Arc::new(ActiveConnectionRegistry::new(max_active)?);
        let owner = store
            .claim_authorization_owner()
            .map_err(|_| unavailable())?;
        let service = AuthenticationService::new(store, owner);
        let (tx, rx) = mpsc::channel(AUTHORIZATION_COMMAND_CAPACITY);
        let (lifecycle_tx, lifecycle_rx) = mpsc::channel(AUTHORIZATION_LIFECYCLE_CAPACITY);
        let (emergency_tx, emergency_rx) = mpsc::channel(1);
        let poisoned = Arc::new(AtomicBool::new(false));
        runtime.spawn(run(
            rx,
            LifecycleSink {
                regular: lifecycle_tx,
                emergency: emergency_tx,
                poisoned: poisoned.clone(),
            },
            active.clone(),
            service,
        ));
        Ok((
            Self {
                tx: tx.clone(),
                active: active.clone(),
                poisoned: poisoned.clone(),
            },
            AuthorizationLifecycle {
                rx: lifecycle_rx,
                emergency_rx,
                coordinator_tx: tx,
                active,
                poisoned,
                terminal: false,
            },
        ))
    }

    pub async fn authenticate(
        &self,
        frame: Authenticate,
        challenge: ConsumedChallenge,
        now_ms: u64,
    ) -> Result<AuthenticationActivation, RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.send_auth(AuthorizationCommand::Authenticate {
            frame,
            challenge,
            now_ms,
            reply,
        })?;
        response.await.map_err(|_| unavailable())?
    }

    pub async fn register_machine(
        &self,
        request: RegisterMachine,
    ) -> Result<AuthorizationMutation<MachineRecord>, StoreError> {
        if request.response_blob.len() > MAX_CONTROL_BLOB_BYTES {
            return Err(StoreError::InvalidValue {
                field: "register_machine.response_blob",
                reason: "control blob exceeds 64 KiB",
            });
        }
        self.dispatch_store(|reply| AuthorizationCommand::RegisterMachine { request, reply })
            .await
    }

    pub async fn install_grant(
        &self,
        request: InstallGrantRecord,
    ) -> Result<AuthorizationMutation<GrantCommit>, StoreError> {
        self.dispatch_store(|reply| AuthorizationCommand::InstallGrant { request, reply })
            .await
    }

    pub async fn revoke(
        &self,
        request: PersistRevocation,
    ) -> Result<AuthorizationMutation<RevocationCommit>, StoreError> {
        if request.signed_revocation_blob.len() > MAX_CONTROL_BLOB_BYTES {
            return Err(StoreError::InvalidValue {
                field: "revocation.signed_blob",
                reason: "control blob exceeds 64 KiB",
            });
        }
        self.dispatch_store(|reply| AuthorizationCommand::Revoke { request, reply })
            .await
    }

    pub async fn purge_machine(
        &self,
        request: PurgeMachine,
    ) -> Result<AuthorizationMutation<PurgeReadback>, StoreError> {
        self.dispatch_store(|reply| AuthorizationCommand::PurgeMachine { request, reply })
            .await
    }

    pub fn is_current(&self, access: &AccessContext) -> Result<bool, RelayFailure> {
        if self.poisoned.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.active.is_current(access)
    }

    /// 把 current access 检查与一个短小、无 await 的数据面动作线性化；主要供 Core
    /// 在 revoke/replacement transition 与 writer enqueue 之间建立原子先后关系。
    pub(crate) fn with_current<T>(
        &self,
        access: &AccessContext,
        action: impl FnOnce() -> T,
    ) -> Result<Option<T>, RelayFailure> {
        if self.poisoned.load(Ordering::Acquire) {
            return Ok(None);
        }
        self.active.with_current(access, action)
    }

    /// 把两个普通 principal 的 generation 检查与一个短小无等待动作共同线性化。
    pub(crate) fn with_both_current<T>(
        &self,
        first: &AccessContext,
        second: &AccessContext,
        action: impl FnOnce() -> T,
    ) -> Result<(bool, bool, Option<T>), RelayFailure> {
        if self.poisoned.load(Ordering::Acquire) {
            return Ok((false, false, None));
        }
        self.active.with_both_current(first, second, action)
    }

    pub fn current(
        &self,
        route: PrincipalRoute,
    ) -> Result<Option<ConnectionInstanceId>, RelayFailure> {
        if self.poisoned.load(Ordering::Acquire) {
            return Ok(None);
        }
        self.active.current(route)
    }

    pub fn disconnect(
        &self,
        route: PrincipalRoute,
        connection_instance: ConnectionInstanceId,
    ) -> Result<bool, RelayFailure> {
        self.active.remove_if_current(route, connection_instance)
    }

    /// 排在本命令前的授权状态转换全部完成、Store ownership 已释放后才返回。
    pub async fn shutdown(&self) -> Result<(), RelayFailure> {
        let (reply, response) = oneshot::channel();
        match self.tx.try_send(AuthorizationCommand::Shutdown { reply }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(RelayFailure::new(
                    RELAY_QUOTA_EXCEEDED,
                    "authorization command capacity is exhausted",
                ));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(unavailable()),
        }
        response.await.map_err(|_| unavailable())??;
        Ok(())
    }

    async fn dispatch_store<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T, StoreError>>) -> AuthorizationCommand,
    ) -> Result<T, StoreError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(StoreError::WorkerUnavailable);
        }
        let (reply, response) = oneshot::channel();
        match self.tx.try_send(command(reply)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => return Err(StoreError::WorkerBusy),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(StoreError::WorkerUnavailable);
            }
        }
        response.await.map_err(|_| StoreError::WorkerStopped)?
    }

    fn send_auth(&self, command: AuthorizationCommand) -> Result<(), RelayFailure> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        match self.tx.try_send(command) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(RelayFailure::new(
                RELAY_QUOTA_EXCEEDED,
                "authorization command capacity is exhausted",
            )),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(unavailable()),
        }
    }
}

enum AuthorizationCommand {
    Authenticate {
        frame: Authenticate,
        challenge: ConsumedChallenge,
        now_ms: u64,
        reply: oneshot::Sender<Result<AuthenticationActivation, RelayFailure>>,
    },
    RegisterMachine {
        request: RegisterMachine,
        reply: oneshot::Sender<Result<AuthorizationMutation<MachineRecord>, StoreError>>,
    },
    InstallGrant {
        request: InstallGrantRecord,
        reply: oneshot::Sender<Result<AuthorizationMutation<GrantCommit>, StoreError>>,
    },
    Revoke {
        request: PersistRevocation,
        reply: oneshot::Sender<Result<AuthorizationMutation<RevocationCommit>, StoreError>>,
    },
    PurgeMachine {
        request: PurgeMachine,
        reply: oneshot::Sender<Result<AuthorizationMutation<PurgeReadback>, StoreError>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), RelayFailure>>,
    },
    LifecycleDropped,
}

struct LifecycleSink {
    regular: mpsc::Sender<AuthorizationLifecycleEvent>,
    emergency: mpsc::Sender<AuthorizationLifecycleEvent>,
    poisoned: Arc<AtomicBool>,
}

async fn run(
    mut rx: mpsc::Receiver<AuthorizationCommand>,
    lifecycle: LifecycleSink,
    active: Arc<ActiveConnectionRegistry>,
    service: AuthenticationService,
) {
    let mut shutdown_reply = None;
    while let Some(command) = rx.recv().await {
        if lifecycle.poisoned.load(Ordering::Acquire)
            && !matches!(command, AuthorizationCommand::Shutdown { .. })
        {
            break;
        }
        match command {
            AuthorizationCommand::Authenticate {
                frame,
                challenge,
                now_ms,
                reply,
            } => {
                let result =
                    authenticate(&service, &active, &lifecycle, frame, challenge, now_ms).await;
                let _ = reply.send(result);
            }
            AuthorizationCommand::RegisterMachine { request, reply } => {
                let result = register_machine(&service, &active, &lifecycle, request).await;
                let _ = reply.send(result);
            }
            AuthorizationCommand::InstallGrant { request, reply } => {
                let result = install_grant(&service, &active, &lifecycle, request).await;
                let _ = reply.send(result);
            }
            AuthorizationCommand::Revoke { request, reply } => {
                let result = revoke(&service, &active, &lifecycle, request).await;
                let _ = reply.send(result);
            }
            AuthorizationCommand::PurgeMachine { request, reply } => {
                let result = purge_machine(&service, &active, &lifecycle, request).await;
                let _ = reply.send(result);
            }
            AuthorizationCommand::Shutdown { reply } => {
                let result = shutdown_active(&active, &lifecycle);
                shutdown_reply = Some((reply, result));
                break;
            }
            AuthorizationCommand::LifecycleDropped => break,
        }
        if lifecycle.poisoned.load(Ordering::Acquire) {
            break;
        }
    }
    drop(service);
    if let Some((reply, result)) = shutdown_reply {
        let _ = reply.send(result);
    }
}

async fn authenticate(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    frame: Authenticate,
    challenge: ConsumedChallenge,
    now_ms: u64,
) -> Result<AuthenticationActivation, RelayFailure> {
    let prepared = service.prepare(&frame, &challenge, now_ms).await?;
    let route = prepared.access.principal_route().ok_or_else(unavailable)?;
    let transition = active.begin_transition(route, true)?;
    if let Err(error) = service.commit(&prepared).await {
        active.abort_transition(transition)?;
        return Err(error);
    }
    let activation = active.commit_transition(transition, &prepared.access)?;
    let mut affected_connections = vec![activation.connection_instance];
    if let Some(replaced) = activation.replaced {
        affected_connections.push(replaced);
    }
    if emit_lifecycle(
        active,
        lifecycle,
        AuthorizationLifecycleEvent::Activated(activation),
        &affected_connections,
    )
    .is_err()
    {
        return Err(unavailable());
    }
    Ok(AuthenticationActivation {
        access: prepared.access,
        activation,
    })
}

async fn register_machine(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    request: RegisterMachine,
) -> Result<AuthorizationMutation<MachineRecord>, StoreError> {
    let transitions = active
        .begin_machine_transition(request.machine_route)
        .map_err(|_| StoreError::WorkerUnavailable)?;
    match service.register_machine(request).await {
        Ok(commit) if commit.duplicate => {
            active
                .abort_machine_transition(&transitions)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            Ok(AuthorizationMutation {
                commit,
                invalidated_connections: Vec::new(),
            })
        }
        Ok(commit) => {
            let connections = active
                .complete_machine_invalidation(&transitions)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            emit_invalidated(active, lifecycle, &connections)?;
            Ok(AuthorizationMutation {
                commit,
                invalidated_connections: connections,
            })
        }
        Err(error) => {
            active
                .abort_machine_transition(&transitions)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            Err(error)
        }
    }
}

async fn install_grant(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    request: InstallGrantRecord,
) -> Result<AuthorizationMutation<GrantCommit>, StoreError> {
    let route = PrincipalRoute::Device {
        machine_route: request.grant.machine_route,
        device_route: request.grant.device_route,
    };
    let transition = active
        .begin_transition(route, false)
        .map_err(|_| StoreError::WorkerUnavailable)?;
    match service.install_grant(request).await {
        Ok(commit) if commit.duplicate => {
            active
                .abort_transition(transition)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            Ok(AuthorizationMutation {
                commit,
                invalidated_connections: Vec::new(),
            })
        }
        Ok(commit) => finish_invalidation(active, lifecycle, transition, commit),
        Err(error) => {
            active
                .abort_transition(transition)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            Err(error)
        }
    }
}

async fn revoke(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    request: PersistRevocation,
) -> Result<AuthorizationMutation<RevocationCommit>, StoreError> {
    let route = PrincipalRoute::Device {
        machine_route: request.revocation.machine_route,
        device_route: request.revocation.device_route,
    };
    let transition = active
        .begin_transition(route, false)
        .map_err(|_| StoreError::WorkerUnavailable)?;
    match service.revoke(request).await {
        Ok(commit) => finish_invalidation(active, lifecycle, transition, commit),
        Err(error) => {
            active
                .abort_transition(transition)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            Err(error)
        }
    }
}

async fn purge_machine(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    request: PurgeMachine,
) -> Result<AuthorizationMutation<PurgeReadback>, StoreError> {
    let transitions = active
        .begin_machine_transition(request.machine_route)
        .map_err(|_| StoreError::WorkerUnavailable)?;
    match service.purge_machine(request).await {
        Ok(commit) => {
            let connections = active
                .complete_machine_invalidation(&transitions)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            emit_invalidated(active, lifecycle, &connections)?;
            Ok(AuthorizationMutation {
                commit,
                invalidated_connections: connections,
            })
        }
        Err(error) => {
            active
                .abort_machine_transition(&transitions)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            Err(error)
        }
    }
}

fn finish_invalidation<T>(
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    transition: RouteTransition,
    commit: T,
) -> Result<AuthorizationMutation<T>, StoreError> {
    let connections = active
        .complete_invalidation(transition)
        .map_err(|_| StoreError::WorkerUnavailable)?
        .into_iter()
        .collect::<Vec<_>>();
    emit_invalidated(active, lifecycle, &connections)?;
    Ok(AuthorizationMutation {
        commit,
        invalidated_connections: connections,
    })
}

fn emit_invalidated(
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    connections: &[ConnectionInstanceId],
) -> Result<(), StoreError> {
    if connections.is_empty() {
        return Ok(());
    }
    let result = emit_lifecycle(
        active,
        lifecycle,
        AuthorizationLifecycleEvent::Invalidated {
            connections: connections.to_vec(),
        },
        connections,
    );
    result.map_err(|error| match error {
        LifecycleError::Full => StoreError::WorkerBusy,
        LifecycleError::Closed => StoreError::WorkerUnavailable,
    })
}

enum LifecycleError {
    Full,
    Closed,
}

fn emit_lifecycle(
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    event: AuthorizationLifecycleEvent,
    emergency_extra: &[ConnectionInstanceId],
) -> Result<(), LifecycleError> {
    lifecycle.regular.try_send(event).map_err(|error| {
        let kind = match error {
            mpsc::error::TrySendError::Full(_) => LifecycleError::Full,
            mpsc::error::TrySendError::Closed(_) => LifecycleError::Closed,
        };
        trigger_fail_closed(active, lifecycle, emergency_extra);
        kind
    })
}

fn trigger_fail_closed(
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    extra: &[ConnectionInstanceId],
) {
    let mut connections = extra.to_vec();
    if let Ok(remaining) = active.fail_closed_all() {
        for connection in remaining {
            if !connections.contains(&connection) {
                connections.push(connection);
            }
        }
    }
    lifecycle.poisoned.store(true, Ordering::Release);
    let _ = lifecycle
        .emergency
        .try_send(AuthorizationLifecycleEvent::FailClosedAll { connections });
}

fn shutdown_active(
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
) -> Result<(), RelayFailure> {
    let connections = active.fail_closed_all()?;
    if !connections.is_empty()
        && lifecycle
            .regular
            .try_send(AuthorizationLifecycleEvent::Invalidated {
                connections: connections.clone(),
            })
            .is_err()
    {
        lifecycle.poisoned.store(true, Ordering::Release);
        let _ = lifecycle
            .emergency
            .try_send(AuthorizationLifecycleEvent::FailClosedAll { connections });
        return Ok(());
    }
    lifecycle.poisoned.store(true, Ordering::Release);
    Ok(())
}

fn unavailable() -> RelayFailure {
    RelayFailure::new(
        RELAY_STORE_UNAVAILABLE,
        "authentication state is unavailable",
    )
}
