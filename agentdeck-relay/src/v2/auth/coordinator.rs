//! 授权状态的唯一线性化 actor。
//!
//! Store worker 负责 SQLite 原子性；本 actor 在它之上把 trust mutation 与 active
//! generation 变更串成一个不可被 caller future cancellation 打断的状态转换。生产 Core
//! 必须只经这里执行 Authenticate、InstallGrant、Revoke、RegisterMachine 与 PurgeMachine。

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_INVALID_GRANT, RELAY_AUTH_REVOKED, RELAY_QUOTA_EXCEEDED, RELAY_STORE_UNAVAILABLE,
};
use agentdeck_protocol::relay_v2::frame::{Authenticate, RetireMachine};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, DeviceRevocation, RelayFailure, RelayGrant,
};
use tokio::sync::{mpsc, oneshot};

use super::access::{
    AccessContext, Activation, ActiveConnectionRegistry, PrincipalRoute, RouteTransition,
};
use super::challenge::ConsumedChallenge;
use super::verify::{
    AuthenticationActivation, AuthenticationCommitError, AuthenticationOutcome,
    AuthenticationService, PreparedTerminal,
};
use crate::v2::store::{
    EnrollmentCodeSeed, GrantCommit, MAX_CONTROL_BLOB_BYTES, MachineRecord, PurgeMachine,
    PurgeReadback, RegisterMachine, RelayStoreHandle, RetirementCommit, RevocationCommit,
    StoreError,
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
        match self.authenticate_outcome(frame, challenge, now_ms).await? {
            AuthenticationOutcome::Activated(activation) => Ok(activation),
            AuthenticationOutcome::RevokedTerminal(_) => Err(RelayFailure::new(
                RELAY_AUTH_REVOKED,
                "authentication credential is revoked",
            )),
            AuthenticationOutcome::RetiredTerminal(_) => Err(RelayFailure::new(
                RELAY_AUTH_INVALID_GRANT,
                "authentication credential is invalid",
            )),
        }
    }

    pub async fn authenticate_outcome(
        &self,
        frame: Authenticate,
        challenge: ConsumedChallenge,
        now_ms: u64,
    ) -> Result<AuthenticationOutcome, RelayFailure> {
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

    pub async fn seed_enrollment_code(
        &self,
        request: EnrollmentCodeSeed,
    ) -> Result<(), StoreError> {
        self.dispatch_store(|reply| AuthorizationCommand::SeedEnrollmentCode { request, reply })
            .await
    }

    pub async fn purge_machine_admin(
        &self,
        request: PurgeMachine,
    ) -> Result<AuthorizationMutation<PurgeReadback>, StoreError> {
        self.dispatch_store(|reply| AuthorizationCommand::PurgeMachineAdmin { request, reply })
            .await
    }

    pub async fn install_grant_from(
        &self,
        origin: AccessContext,
        grant: RelayGrant,
    ) -> Result<AuthorizationMutation<GrantCommit>, RelayFailure> {
        self.dispatch_control(|reply| AuthorizationCommand::InstallGrantFrom {
            origin,
            grant,
            reply,
        })
        .await
    }

    pub async fn revoke_from(
        &self,
        origin: AccessContext,
        revocation: DeviceRevocation,
    ) -> Result<AuthorizationMutation<RevocationCommit>, RelayFailure> {
        self.dispatch_control(|reply| AuthorizationCommand::RevokeFrom {
            origin,
            revocation,
            reply,
        })
        .await
    }

    pub async fn retire_machine_from(
        &self,
        origin: AccessContext,
        retirement: RetireMachine,
    ) -> Result<AuthorizationMutation<RetirementCommit>, RelayFailure> {
        self.dispatch_control(|reply| AuthorizationCommand::RetireMachineFrom {
            origin,
            retirement,
            reply,
        })
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
        self.tx
            .send(AuthorizationCommand::Shutdown { reply })
            .await
            .map_err(|_| unavailable())?;
        response.await.map_err(|_| unavailable())??;
        Ok(())
    }

    /// 在 authorization actor FIFO 中建立 shutdown fence。返回后不再执行新的
    /// authenticate/register/grant/revoke/retire Store mutation；既有 active 状态留给
    /// Relay Core 的 drain/shutdown 顺序统一关闭。
    pub async fn begin_drain(&self) -> Result<(), RelayFailure> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        let (reply, response) = oneshot::channel();
        self.tx
            .send(AuthorizationCommand::BeginDrain { reply })
            .await
            .map_err(|_| unavailable())?;
        response.await.map_err(|_| unavailable())?
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

    async fn dispatch_control<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T, RelayFailure>>) -> AuthorizationCommand,
    ) -> Result<T, RelayFailure> {
        let (reply, response) = oneshot::channel();
        self.send_auth(command(reply))?;
        response.await.map_err(|_| unavailable())?
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
        reply: oneshot::Sender<Result<AuthenticationOutcome, RelayFailure>>,
    },
    RegisterMachine {
        request: RegisterMachine,
        reply: oneshot::Sender<Result<AuthorizationMutation<MachineRecord>, StoreError>>,
    },
    SeedEnrollmentCode {
        request: EnrollmentCodeSeed,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    PurgeMachineAdmin {
        request: PurgeMachine,
        reply: oneshot::Sender<Result<AuthorizationMutation<PurgeReadback>, StoreError>>,
    },
    InstallGrantFrom {
        origin: AccessContext,
        grant: RelayGrant,
        reply: oneshot::Sender<Result<AuthorizationMutation<GrantCommit>, RelayFailure>>,
    },
    RevokeFrom {
        origin: AccessContext,
        revocation: DeviceRevocation,
        reply: oneshot::Sender<Result<AuthorizationMutation<RevocationCommit>, RelayFailure>>,
    },
    RetireMachineFrom {
        origin: AccessContext,
        retirement: RetireMachine,
        reply: oneshot::Sender<Result<AuthorizationMutation<RetirementCommit>, RelayFailure>>,
    },
    BeginDrain {
        reply: oneshot::Sender<Result<(), RelayFailure>>,
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
    let mut draining = false;
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
                let result = if draining {
                    Err(draining_failure())
                } else {
                    authenticate(&service, &active, &lifecycle, frame, challenge, now_ms).await
                };
                let _ = reply.send(result);
            }
            AuthorizationCommand::RegisterMachine { request, reply } => {
                let result = if draining {
                    Err(StoreError::WorkerUnavailable)
                } else {
                    register_machine(&service, &active, &lifecycle, request).await
                };
                let _ = reply.send(result);
            }
            AuthorizationCommand::SeedEnrollmentCode { request, reply } => {
                let result = if draining {
                    Err(StoreError::WorkerUnavailable)
                } else {
                    service.seed_enrollment_code(request).await
                };
                let _ = reply.send(result);
            }
            AuthorizationCommand::PurgeMachineAdmin { request, reply } => {
                let result = if draining {
                    Err(StoreError::WorkerUnavailable)
                } else {
                    purge_machine_admin(&service, &active, &lifecycle, request).await
                };
                let _ = reply.send(result);
            }
            AuthorizationCommand::InstallGrantFrom {
                origin,
                grant,
                reply,
            } => {
                let result = if draining {
                    Err(draining_failure())
                } else {
                    install_grant_from(&service, &active, &lifecycle, origin, grant).await
                };
                let _ = reply.send(result);
            }
            AuthorizationCommand::RevokeFrom {
                origin,
                revocation,
                reply,
            } => {
                let result = if draining {
                    Err(draining_failure())
                } else {
                    revoke_from(&service, &active, &lifecycle, origin, revocation).await
                };
                let _ = reply.send(result);
            }
            AuthorizationCommand::RetireMachineFrom {
                origin,
                retirement,
                reply,
            } => {
                let result = if draining {
                    Err(draining_failure())
                } else {
                    retire_machine_from(&service, &active, &lifecycle, origin, retirement).await
                };
                let _ = reply.send(result);
            }
            AuthorizationCommand::BeginDrain { reply } => {
                draining = true;
                let _ = reply.send(Ok(()));
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
) -> Result<AuthenticationOutcome, RelayFailure> {
    let mut prepared = service.prepare(&frame, &challenge, now_ms).await?;
    if let Some(terminal) = prepared.terminal.take() {
        return Ok(match terminal {
            PreparedTerminal::Revoked(terminal) => AuthenticationOutcome::RevokedTerminal(terminal),
            PreparedTerminal::Retired(terminal) => AuthenticationOutcome::RetiredTerminal(terminal),
        });
    }
    let route = prepared.access.principal_route().ok_or_else(unavailable)?;
    let transition = active.begin_transition(route, true)?;
    match service.commit(&prepared).await {
        Ok(()) => {}
        Err(AuthenticationCommitError::Rollback(error)) => {
            active.abort_transition(transition)?;
            return Err(error);
        }
        Err(AuthenticationCommitError::OutcomeUnknown(error)) => {
            finish_uncertain_invalidation(active, lifecycle, transition)?;
            return Err(error);
        }
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
    Ok(AuthenticationOutcome::Activated(AuthenticationActivation {
        access: prepared.access,
        activation,
    }))
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

async fn purge_machine_admin(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    request: PurgeMachine,
) -> Result<AuthorizationMutation<PurgeReadback>, StoreError> {
    let transitions = active
        .begin_machine_transition(request.machine_route)
        .map_err(|_| StoreError::WorkerUnavailable)?;
    match service.purge_machine_admin(request).await {
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
        Err(error @ StoreError::CommitOutcomeUnknown { .. }) => {
            let connections = active
                .complete_machine_invalidation(&transitions)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            // SQLite COMMIT 可能已经完成。此时绝不能恢复旧 generation：让 emergency
            // lifecycle 停止整个 Core，PairRoute 与 writer 都随之 fail-closed。
            trigger_fail_closed(active, lifecycle, &connections);
            Err(error)
        }
        Err(error) => {
            active
                .abort_machine_transition(&transitions)
                .map_err(|_| StoreError::WorkerUnavailable)?;
            Err(error)
        }
    }
}

async fn install_grant_from(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    origin: AccessContext,
    grant: RelayGrant,
) -> Result<AuthorizationMutation<GrantCommit>, RelayFailure> {
    let route = PrincipalRoute::Device {
        machine_route: grant.machine_route,
        device_route: grant.device_route,
    };
    let transition = active.begin_transition_from_machine(&origin, route)?;
    let request = match service.prepare_install_grant(grant).await {
        Ok(request) => request,
        Err(error) => {
            active.abort_transition(transition)?;
            return Err(error);
        }
    };
    match service.install_grant(request).await {
        Ok(commit) if commit.duplicate => {
            active.abort_transition(transition)?;
            Ok(AuthorizationMutation {
                commit,
                invalidated_connections: Vec::new(),
            })
        }
        Ok(commit) => finish_committed_invalidation(active, lifecycle, transition, commit),
        Err(error @ StoreError::CommitOutcomeUnknown { .. }) => {
            finish_uncertain_invalidation(active, lifecycle, transition)?;
            Err(map_control_store_error(error))
        }
        Err(error) => {
            active.abort_transition(transition)?;
            Err(map_control_store_error(error))
        }
    }
}

async fn revoke_from(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    origin: AccessContext,
    revocation: DeviceRevocation,
) -> Result<AuthorizationMutation<RevocationCommit>, RelayFailure> {
    let route = PrincipalRoute::Device {
        machine_route: revocation.machine_route,
        device_route: revocation.device_route,
    };
    let transition = active.begin_transition_from_machine(&origin, route)?;
    let request = match service.prepare_revocation(revocation).await {
        Ok(request) => request,
        Err(error) => {
            active.abort_transition(transition)?;
            return Err(error);
        }
    };
    match service.revoke(request).await {
        Ok(commit) => finish_committed_invalidation(active, lifecycle, transition, commit),
        Err(error @ StoreError::CommitOutcomeUnknown { .. }) => {
            finish_uncertain_invalidation(active, lifecycle, transition)?;
            Err(map_control_store_error(error))
        }
        Err(error) => {
            active.abort_transition(transition)?;
            Err(map_control_store_error(error))
        }
    }
}

async fn retire_machine_from(
    service: &AuthenticationService,
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    origin: AccessContext,
    retirement: RetireMachine,
) -> Result<AuthorizationMutation<RetirementCommit>, RelayFailure> {
    let transitions = active.begin_machine_transition_from(&origin, retirement.machine_route)?;
    let request = match service.prepare_retirement(retirement).await {
        Ok(request) => request,
        Err(error) => {
            active.abort_machine_transition(&transitions)?;
            return Err(error);
        }
    };
    match service.retire_machine(request).await {
        Ok(commit) => {
            let connections = active.complete_machine_invalidation(&transitions)?;
            let _ = emit_invalidated(active, lifecycle, &connections);
            Ok(AuthorizationMutation {
                commit,
                invalidated_connections: connections,
            })
        }
        Err(error @ StoreError::CommitOutcomeUnknown { .. }) => {
            let connections = active.complete_machine_invalidation(&transitions)?;
            // 精确幂等恢复也失败时无法判断 retirement 是否 durable；停止整个 Core，
            // 让 PairRoute registry 与全部 writer 一并 fail-closed，绝不恢复旧 machine。
            trigger_fail_closed(active, lifecycle, &connections);
            Err(map_control_store_error(error))
        }
        Err(error) => {
            active.abort_machine_transition(&transitions)?;
            Err(map_control_store_error(error))
        }
    }
}

fn finish_uncertain_invalidation(
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    transition: RouteTransition,
) -> Result<(), RelayFailure> {
    let connections = active
        .complete_invalidation(transition)?
        .into_iter()
        .collect::<Vec<_>>();
    let _ = emit_invalidated(active, lifecycle, &connections);
    Ok(())
}

fn finish_committed_invalidation<T>(
    active: &ActiveConnectionRegistry,
    lifecycle: &LifecycleSink,
    transition: RouteTransition,
    commit: T,
) -> Result<AuthorizationMutation<T>, RelayFailure> {
    let connections = active
        .complete_invalidation(transition)?
        .into_iter()
        .collect::<Vec<_>>();
    // Store COMMIT 已完成后，lifecycle overflow 会触发 emergency fail-close，但不能把
    // durable commit 伪装成“未提交”错误；Core 仍需拿到精确 target 以先尝试 terminal。
    let _ = emit_invalidated(active, lifecycle, &connections);
    Ok(AuthorizationMutation {
        commit,
        invalidated_connections: connections,
    })
}

fn map_control_store_error(error: StoreError) -> RelayFailure {
    match error {
        StoreError::QuotaExceeded { .. } => RelayFailure::new(
            RELAY_QUOTA_EXCEEDED,
            "authorization metadata capacity is exhausted",
        ),
        StoreError::MachineNotFound
        | StoreError::GrantNotFound
        | StoreError::Revoked
        | StoreError::MonotonicRollback { .. }
        | StoreError::IdempotencyConflict { .. }
        | StoreError::AuthenticationMismatch { .. } => RelayFailure::new(
            RELAY_AUTH_INVALID_GRANT,
            "authentication credential is invalid",
        ),
        _ => unavailable(),
    }
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

fn draining_failure() -> RelayFailure {
    RelayFailure::new(
        "relay.server.draining",
        "Relay server is draining and no longer accepts authorization mutations",
    )
}
