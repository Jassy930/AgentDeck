//! 每个 conversation 一个 durable journal actor。
//!
//! prompt mailbox 只负责把请求提交到 SQLite；真正顺序由 store 分配的
//! `command_seq` 决定。control mailbox 独立且优先，actor 不读取 transport、
//! 不 await connection writer。不同 actor 可并行，同一 actor 最多一个 active turn。

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use serde_json::json;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};

use super::connection::{
    AuthenticatedPrincipal, AuthorizationGuard, PrincipalAccessError, PrincipalAuthorizationKey,
};
use super::execution::{
    ExecutionReleasePermit, RuntimeExecutionCompletion, RuntimeExecutionContext,
    RuntimeExecutionControl, RuntimeExecutionCoordinator, RuntimeExecutionError,
};
use super::store::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, AuthorizeExecutionRelease,
    CommandRecord, CommandState, CompleteCommand, ConversationRecord, ExecutionFence, RuntimeId,
    RuntimeStoreError, RuntimeStoreHandle, StartCommand, StartOutcome,
    StartedBeforeReleaseTermination, TerminalState, TerminateAcceptedCommand,
    TerminateAcceptedOutcome, TerminateStartedBeforeRelease, TerminateStartedBeforeReleaseOutcome,
};

const PROMPT_MAILBOX_CAPACITY: usize = 32;
const CONTROL_MAILBOX_CAPACITY: usize = 64;
const RUNNER_MAILBOX_CAPACITY: usize = 8;
const EXECUTION_NONCE_BYTES: usize = 32;
const ACTOR_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const CONTROL_CANCEL_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_PRIORITY_BURST: usize = 8;
const MAX_RUNTIME_CONVERSATION_ACTORS: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PromptAcceptResult {
    Accepted {
        command: CommandRecord,
        queue_position: u32,
    },
    Replayed {
        command: CommandRecord,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum QueuedCancelResult {
    Canceled { command: CommandRecord },
    Replayed { command: CommandRecord },
    AlreadyStarted { command: CommandRecord },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActiveCancelResult {
    Requested,
    Stale,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConversationError {
    #[error("conversation actor is not installed")]
    NotFound,
    #[error("runtime conversation actor limit reached")]
    ActorLimit,
    #[error("conversation actor mailbox is full")]
    MailboxFull,
    #[error("conversation actor is unavailable")]
    ActorUnavailable,
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error(transparent)]
    Execution(#[from] RuntimeExecutionError),
    #[error(transparent)]
    Principal(#[from] PrincipalAccessError),
}

pub(crate) struct ConversationRegistry {
    actors: Mutex<HashMap<RuntimeId, ActorRegistration>>,
    store: RuntimeStoreHandle,
    execution: Arc<dyn RuntimeExecutionCoordinator>,
    daemon_boot_id: RuntimeId,
    adapter_permits: Arc<Semaphore>,
    scheduling_gate: watch::Sender<bool>,
    start_transition: Arc<RwLock<()>>,
    actor_limit: usize,
    shutdown_grace: Duration,
}

struct ActorRegistration {
    handle: ConversationHandle,
    task: AbortOnDropTask<()>,
}

#[derive(Clone)]
struct ConversationHandle {
    prompt_ingress: Arc<PromptIngress>,
    control_tx: mpsc::Sender<ControlCommand>,
    shutdown: watch::Sender<bool>,
}

struct PromptIngress {
    state: StdMutex<PromptIngressState>,
    open: watch::Sender<bool>,
}

struct PromptIngressState {
    accepting: bool,
    prompt_tx: mpsc::Sender<PromptCommand>,
}

impl PromptIngress {
    fn new(prompt_tx: mpsc::Sender<PromptCommand>) -> (Arc<Self>, watch::Receiver<bool>) {
        let (open, receiver) = watch::channel(true);
        (
            Arc::new(Self {
                state: StdMutex::new(PromptIngressState {
                    accepting: true,
                    prompt_tx,
                }),
                open,
            }),
            receiver,
        )
    }

    fn try_send(
        &self,
        command: PromptCommand,
    ) -> Result<(), mpsc::error::TrySendError<PromptCommand>> {
        let state = self.state.lock().expect("prompt ingress lock poisoned");
        if !state.accepting {
            return Err(mpsc::error::TrySendError::Closed(command));
        }
        state.prompt_tx.try_send(command)
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("prompt ingress lock poisoned");
        if state.accepting {
            state.accepting = false;
            self.open.send_replace(false);
        }
    }
}

struct AbortOnDropTask<T> {
    task: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropTask<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    fn abort(&self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }

    async fn join(&mut self) -> Result<T, JoinError> {
        let result = self
            .task
            .as_mut()
            .expect("owned task can only be joined once")
            .await;
        self.task.take();
        result
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        self.abort();
    }
}

fn map_mailbox_error<T>(error: mpsc::error::TrySendError<T>) -> ConversationError {
    match error {
        mpsc::error::TrySendError::Full(_) => ConversationError::MailboxFull,
        mpsc::error::TrySendError::Closed(_) => ConversationError::ActorUnavailable,
    }
}

impl ConversationRegistry {
    pub(crate) fn new(
        store: RuntimeStoreHandle,
        execution: Arc<dyn RuntimeExecutionCoordinator>,
        daemon_boot_id: RuntimeId,
        adapter_concurrency: usize,
    ) -> Result<Self, ConversationError> {
        Self::with_actor_limit(
            store,
            execution,
            daemon_boot_id,
            adapter_concurrency,
            MAX_RUNTIME_CONVERSATION_ACTORS,
        )
    }

    fn with_actor_limit(
        store: RuntimeStoreHandle,
        execution: Arc<dyn RuntimeExecutionCoordinator>,
        daemon_boot_id: RuntimeId,
        adapter_concurrency: usize,
        actor_limit: usize,
    ) -> Result<Self, ConversationError> {
        Self::with_limits(
            store,
            execution,
            daemon_boot_id,
            adapter_concurrency,
            actor_limit,
            ACTOR_SHUTDOWN_GRACE,
        )
    }

    fn with_limits(
        store: RuntimeStoreHandle,
        execution: Arc<dyn RuntimeExecutionCoordinator>,
        daemon_boot_id: RuntimeId,
        adapter_concurrency: usize,
        actor_limit: usize,
        shutdown_grace: Duration,
    ) -> Result<Self, ConversationError> {
        if adapter_concurrency == 0 {
            return Err(ConversationError::ActorUnavailable);
        }
        if actor_limit == 0 {
            return Err(ConversationError::ActorLimit);
        }
        let (scheduling_gate, _) = watch::channel(false);
        Ok(Self {
            actors: Mutex::new(HashMap::new()),
            store,
            execution,
            daemon_boot_id,
            adapter_permits: Arc::new(Semaphore::new(adapter_concurrency)),
            scheduling_gate,
            start_transition: Arc::new(RwLock::new(())),
            actor_limit,
            shutdown_grace,
        })
    }

    /// 安装一个新建或逐页恢复出的 conversation。重复安装只接受相同 durable
    /// identity；同一 actor 的创建由 registry mutex single-flight 串行化。
    pub(crate) async fn install(
        &self,
        conversation: ConversationRecord,
        mut recovered: Vec<CommandRecord>,
    ) -> Result<(), ConversationError> {
        let mut actors = self.actors.lock().await;
        if actors.contains_key(&conversation.conversation_id) {
            return Ok(());
        }
        if actors.len() >= self.actor_limit {
            return Err(ConversationError::ActorLimit);
        }
        let conversation_id = conversation.conversation_id;
        recovered.sort_by_key(|command| command.command_seq);
        let (prompt_tx, prompt_rx) = mpsc::channel(PROMPT_MAILBOX_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_MAILBOX_CAPACITY);
        let (runner_tx, runner_rx) = mpsc::channel(RUNNER_MAILBOX_CAPACITY);
        let (admission_tx, admission_rx) = mpsc::channel(PROMPT_MAILBOX_CAPACITY);
        let (prompt_ingress, prompt_open) = PromptIngress::new(prompt_tx);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let handle = ConversationHandle {
            prompt_ingress: prompt_ingress.clone(),
            control_tx,
            shutdown,
        };
        let prompt_worker = AbortOnDropTask::new(tokio::spawn(prompt_admission_worker(
            conversation_id,
            self.store.clone(),
            prompt_rx,
            prompt_open,
            admission_tx,
        )));
        let actor = ConversationActor {
            conversation,
            store: self.store.clone(),
            execution: self.execution.clone(),
            daemon_boot_id: self.daemon_boot_id,
            adapter_permits: self.adapter_permits.clone(),
            scheduling_gate: self.scheduling_gate.subscribe(),
            start_transition: self.start_transition.clone(),
            prompt_ingress,
            shutdown_rx,
            shutdown_requested: false,
            shutdown_grace: self.shutdown_grace,
            admission_rx,
            admission_open: true,
            prompt_worker,
            control_rx,
            runner_tx,
            runner_rx,
            pending: recovered
                .into_iter()
                .map(|command| QueuedCommand {
                    command,
                    authorization_key: None,
                    principal: None,
                })
                .collect(),
            active: None,
            recovery_blocked: false,
        };
        let task = AbortOnDropTask::new(tokio::spawn(actor.run()));
        actors.insert(conversation_id, ActorRegistration { handle, task });
        Ok(())
    }

    async fn handle(
        &self,
        conversation_id: RuntimeId,
    ) -> Result<ConversationHandle, ConversationError> {
        self.actors
            .lock()
            .await
            .get(&conversation_id)
            .map(|entry| entry.handle.clone())
            .ok_or(ConversationError::NotFound)
    }

    pub(crate) async fn submit_prompt(
        &self,
        conversation_id: RuntimeId,
        principal: AuthenticatedPrincipal,
        authorization_guard: AuthorizationGuard,
        idempotency_key: String,
        payload: Vec<u8>,
    ) -> Result<PromptAcceptResult, ConversationError> {
        let handle = self.handle(conversation_id).await?;
        let (reply, result) = oneshot::channel();
        handle
            .prompt_ingress
            .try_send(PromptCommand {
                principal,
                _authorization_guard: authorization_guard,
                idempotency_key,
                payload,
                reply,
            })
            .map_err(map_mailbox_error)?;
        result
            .await
            .map_err(|_| ConversationError::ActorUnavailable)?
    }

    pub(crate) async fn cancel_queued(
        &self,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        principal: AuthenticatedPrincipal,
        authorization_guard: AuthorizationGuard,
    ) -> Result<QueuedCancelResult, ConversationError> {
        let handle = self.handle(conversation_id).await?;
        let (reply, result) = oneshot::channel();
        handle
            .control_tx
            .try_send(ControlCommand::CancelQueued {
                command_id,
                principal,
                _authorization_guard: authorization_guard,
                reply,
            })
            .map_err(map_mailbox_error)?;
        result
            .await
            .map_err(|_| ConversationError::ActorUnavailable)?
    }

    pub(crate) async fn cancel_active(
        &self,
        conversation_id: RuntimeId,
        turn_id: RuntimeId,
        _authorization_guard: AuthorizationGuard,
    ) -> Result<ActiveCancelResult, ConversationError> {
        let handle = self.handle(conversation_id).await?;
        let (reply, result) = oneshot::channel();
        handle
            .control_tx
            .try_send(ControlCommand::CancelActive { turn_id, reply })
            .map_err(map_mailbox_error)?;
        result
            .await
            .map_err(|_| ConversationError::ActorUnavailable)?
    }

    #[allow(dead_code)] // P4 durable auth ledger 接线后由 RuntimeCore revoke 调用。
    pub(crate) async fn revoke_principal(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<usize, ConversationError> {
        principal.begin_revoke().await?;
        let key = principal.authorization_key();
        let handles: Vec<_> = self
            .actors
            .lock()
            .await
            .values()
            .map(|entry| entry.handle.clone())
            .collect();
        let mut terminated = 0;
        let mut first_error = None;
        for handle in handles {
            let (reply, result) = oneshot::channel();
            if handle
                .control_tx
                .try_send(ControlCommand::Revoke {
                    authorization_key: key.clone(),
                    reply,
                })
                .is_err()
            {
                first_error.get_or_insert(ConversationError::ActorUnavailable);
                continue;
            }
            match tokio::time::timeout(CONTROL_CANCEL_TIMEOUT, result).await {
                Ok(Ok(Ok(count))) => terminated += count,
                Ok(Ok(Err(error))) => {
                    first_error.get_or_insert(error);
                }
                Ok(Err(_)) => {
                    first_error.get_or_insert(ConversationError::ActorUnavailable);
                }
                Err(_) => {
                    first_error.get_or_insert(ConversationError::ActorUnavailable);
                }
            }
        }
        // 即使个别 actor 已损坏也完成共享 lease 的 revoked 发布；runner 在 Started
        // 前会重新 acquire 同一 lease，因此剩余 Accepted 保持 fail-closed。
        principal.finish_revoke();
        match first_error {
            Some(error) => Err(error),
            None => Ok(terminated),
        }
    }

    /// RuntimeCore 只有在逐页 recovery 完成并由 store 确认 `finish` 后才调用。
    /// retained watch gate 原子发布且不丢 wake；不存在“部分 actor 已唤醒、Core
    /// 仍处于 RECOVERING”的 fail-open 窗口。
    pub(crate) async fn enable_scheduling(&self) -> Result<(), ConversationError> {
        let actors = self.actors.lock().await;
        if self.adapter_permits.is_closed() {
            return Err(ConversationError::ActorUnavailable);
        }
        self.scheduling_gate.send_replace(true);
        drop(actors);
        Ok(())
    }

    pub(crate) async fn shutdown(&self) -> Result<(), ConversationError> {
        self.begin_draining().await;

        let mut actors = std::mem::take(&mut *self.actors.lock().await);
        for registration in actors.values() {
            registration.handle.prompt_ingress.close();
        }
        for registration in actors.values() {
            registration.handle.shutdown.send_replace(true);
        }

        let joined = tokio::time::timeout(self.shutdown_grace, async {
            for registration in actors.values_mut() {
                let _ = registration.task.join().await;
            }
        })
        .await;
        if joined.is_err() {
            for registration in actors.values() {
                registration.task.abort();
            }
            for registration in actors.values_mut() {
                let _ = registration.task.join().await;
            }
        }
        Ok(())
    }

    /// 必须在 RuntimeCore 发布 Draining 前调用；返回时所有已取得 start lease 的
    /// Accepted→Started COMMIT 已退出，之后也无法再取得新 lease。
    pub(crate) async fn begin_draining(&self) {
        self.scheduling_gate.send_replace(false);
        self.adapter_permits.close();
        let start_fence = self.start_transition.write().await;
        drop(start_fence);
    }

    #[cfg(test)]
    pub(crate) async fn len(&self) -> usize {
        self.actors.lock().await.len()
    }
}

struct PromptCommand {
    principal: AuthenticatedPrincipal,
    _authorization_guard: AuthorizationGuard,
    idempotency_key: String,
    payload: Vec<u8>,
    reply: oneshot::Sender<Result<PromptAcceptResult, ConversationError>>,
}

struct PromptAdmission {
    principal: AuthenticatedPrincipal,
    authorization_key: PrincipalAuthorizationKey,
    _authorization_guard: AuthorizationGuard,
    outcome: Result<AcceptOutcome, RuntimeStoreError>,
    reply: oneshot::Sender<Result<PromptAcceptResult, ConversationError>>,
}

enum ControlCommand {
    CancelQueued {
        command_id: RuntimeId,
        principal: AuthenticatedPrincipal,
        _authorization_guard: AuthorizationGuard,
        reply: oneshot::Sender<Result<QueuedCancelResult, ConversationError>>,
    },
    CancelActive {
        turn_id: RuntimeId,
        reply: oneshot::Sender<Result<ActiveCancelResult, ConversationError>>,
    },
    #[allow(dead_code)] // P4 durable auth ledger 接线后成为 production control。
    Revoke {
        authorization_key: PrincipalAuthorizationKey,
        reply: oneshot::Sender<Result<usize, ConversationError>>,
    },
}

struct QueuedCommand {
    command: CommandRecord,
    authorization_key: Option<PrincipalAuthorizationKey>,
    principal: Option<AuthenticatedPrincipal>,
}

struct ActiveCommand {
    command: CommandRecord,
    authorization_key: Option<PrincipalAuthorizationKey>,
    turn_id: Option<RuntimeId>,
    control: Option<Arc<dyn RuntimeExecutionControl>>,
    execution_gate: Arc<Mutex<ActiveExecutionGate>>,
    task: AbortOnDropTask<()>,
}

#[derive(Default)]
struct ActiveExecutionGate {
    cancel_requested: bool,
    cancel_fenced: bool,
    release_authorized: bool,
}

enum RunnerEvent {
    Started {
        command_id: RuntimeId,
        turn_id: RuntimeId,
        acknowledged: oneshot::Sender<()>,
    },
    Prepared {
        command_id: RuntimeId,
        turn_id: RuntimeId,
        control: Arc<dyn RuntimeExecutionControl>,
        acknowledged: oneshot::Sender<Result<PreparedDecision, RuntimeExecutionError>>,
    },
    Finished {
        command_id: RuntimeId,
    },
    RecoveryBlocked {
        command_id: RuntimeId,
    },
    RunnerExited {
        command_id: RuntimeId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedDecision {
    Proceed,
    CanceledBeforeRelease,
}

struct ConversationActor {
    conversation: ConversationRecord,
    store: RuntimeStoreHandle,
    execution: Arc<dyn RuntimeExecutionCoordinator>,
    daemon_boot_id: RuntimeId,
    adapter_permits: Arc<Semaphore>,
    scheduling_gate: watch::Receiver<bool>,
    start_transition: Arc<RwLock<()>>,
    prompt_ingress: Arc<PromptIngress>,
    shutdown_rx: watch::Receiver<bool>,
    shutdown_requested: bool,
    shutdown_grace: Duration,
    admission_rx: mpsc::Receiver<PromptAdmission>,
    admission_open: bool,
    prompt_worker: AbortOnDropTask<()>,
    control_rx: mpsc::Receiver<ControlCommand>,
    runner_tx: mpsc::Sender<RunnerEvent>,
    runner_rx: mpsc::Receiver<RunnerEvent>,
    pending: VecDeque<QueuedCommand>,
    active: Option<ActiveCommand>,
    recovery_blocked: bool,
}

impl ConversationActor {
    async fn run(mut self) {
        let mut control_burst = 0_usize;
        loop {
            if self.shutdown_requested && self.active.is_none() && !self.admission_open {
                break;
            }
            if control_burst < CONTROL_PRIORITY_BURST {
                match self.control_rx.try_recv() {
                    Ok(command) => {
                        control_burst += 1;
                        self.handle_control(command).await;
                        continue;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.begin_shutdown().await;
                        continue;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {}
                }
            }
            if self.should_start_next() {
                self.start_next();
            }

            tokio::select! {
                command = self.control_rx.recv() => match command {
                    Some(command) => {
                        control_burst = control_burst.saturating_add(1);
                        self.handle_control(command).await;
                    },
                    None => self.begin_shutdown().await,
                },
                event = self.runner_rx.recv(), if self.active.is_some() => {
                    control_burst = 0;
                    match event {
                        Some(event) => self.handle_runner_event(event).await,
                        None => {
                            self.enter_recovery_blocked();
                        }
                    }
                },
                admission = self.admission_rx.recv(), if self.admission_open => match admission {
                    Some(admission) => {
                        control_burst = 0;
                        self.handle_admission(admission)
                    },
                    None => {
                        control_burst = 0;
                        self.admission_open = false;
                        if !self.shutdown_requested && !self.recovery_blocked {
                            self.enter_recovery_blocked();
                        }
                    },
                },
                changed = self.scheduling_gate.changed() => {
                    control_burst = 0;
                    if changed.is_err() {
                        self.enter_recovery_blocked();
                    }
                },
                changed = self.shutdown_rx.changed(), if !self.shutdown_requested => {
                    control_burst = 0;
                    if changed.is_err() || *self.shutdown_rx.borrow_and_update() {
                        self.begin_shutdown().await;
                    }
                },
            }
        }
        self.stop_active().await;
        self.prompt_ingress.close();
        let _ = self.prompt_worker.join().await;
    }

    fn should_start_next(&self) -> bool {
        !self.shutdown_requested
            && !self.recovery_blocked
            && self.active.is_none()
            && !self.pending.is_empty()
            && *self.scheduling_gate.borrow()
            && self.execution.is_ready()
    }

    fn handle_admission(&mut self, admission: PromptAdmission) {
        let reply = match admission.outcome {
            Ok(AcceptOutcome::Accepted {
                command,
                queue_position,
            }) => {
                let queued = QueuedCommand {
                    command: command.clone(),
                    authorization_key: Some(admission.authorization_key),
                    principal: Some(admission.principal),
                };
                let position = self
                    .pending
                    .iter()
                    .position(|existing| existing.command.command_seq > queued.command.command_seq)
                    .unwrap_or(self.pending.len());
                self.pending.insert(position, queued);
                Ok(PromptAcceptResult::Accepted {
                    command,
                    queue_position,
                })
            }
            Ok(AcceptOutcome::Replayed { command }) => {
                if command.state == CommandState::Accepted
                    && !self.pending.iter().any(|queued| {
                        queued.command.command_id == command.command_id
                            || queued.command.command_seq == command.command_seq
                    })
                    && self
                        .active
                        .as_ref()
                        .is_none_or(|active| active.command.command_id != command.command_id)
                {
                    let queued = QueuedCommand {
                        command: command.clone(),
                        authorization_key: Some(admission.authorization_key),
                        principal: Some(admission.principal),
                    };
                    let position = self
                        .pending
                        .iter()
                        .position(|existing| {
                            existing.command.command_seq > queued.command.command_seq
                        })
                        .unwrap_or(self.pending.len());
                    self.pending.insert(position, queued);
                }
                Ok(PromptAcceptResult::Replayed { command })
            }
            Err(error) => Err(ConversationError::Store(error)),
        };
        // `_authorization_guard` lives through journal commit and queue registration, then drops.
        let _ = admission.reply.send(reply);
    }

    async fn handle_control(&mut self, command: ControlCommand) {
        match command {
            ControlCommand::CancelQueued {
                command_id,
                principal,
                reply,
                ..
            } => {
                let outcome = self
                    .store
                    .terminate_accepted_command(TerminateAcceptedCommand {
                        conversation_id: self.conversation.conversation_id,
                        command_id,
                        expected_owner: principal.idempotency_owner(),
                        reason: AcceptedTerminationReason::Canceled,
                        event_payload: cancellation_event(command_id),
                    })
                    .await
                    .map_err(ConversationError::Store)
                    .map(|outcome| match outcome {
                        TerminateAcceptedOutcome::Transitioned { command, .. } => {
                            self.remove_pending(command.command_id);
                            QueuedCancelResult::Canceled { command }
                        }
                        TerminateAcceptedOutcome::Replayed { command, .. } => {
                            self.remove_pending(command.command_id);
                            QueuedCancelResult::Replayed { command }
                        }
                        TerminateAcceptedOutcome::AlreadyStarted { command } => {
                            QueuedCancelResult::AlreadyStarted { command }
                        }
                    });
                let _ = reply.send(outcome);
            }
            ControlCommand::CancelActive { turn_id, reply } => {
                let result = match self.active.as_mut() {
                    Some(active) if active.turn_id == Some(turn_id) => {
                        request_active_cancel(&active.execution_gate, active.control.clone())
                            .await
                            .map(|()| ActiveCancelResult::Requested)
                            .map_err(ConversationError::Execution)
                    }
                    _ => Ok(ActiveCancelResult::Stale),
                };
                let _ = reply.send(result);
            }
            ControlCommand::Revoke {
                authorization_key,
                reply,
            } => {
                let result = self.revoke_accepted(authorization_key).await;
                let _ = reply.send(result);
            }
        }
    }

    fn enter_recovery_blocked(&mut self) {
        self.recovery_blocked = true;
        self.prompt_ingress.close();
    }

    async fn begin_shutdown(&mut self) {
        if self.shutdown_requested {
            return;
        }
        self.shutdown_requested = true;
        self.prompt_ingress.close();
        if let Some(active) = &mut self.active {
            let _ = request_active_cancel(&active.execution_gate, active.control.clone()).await;
        }
    }

    async fn revoke_accepted(
        &mut self,
        authorization_key: PrincipalAuthorizationKey,
    ) -> Result<usize, ConversationError> {
        let mut targets: Vec<_> = self
            .pending
            .iter()
            .filter(|queued| queued.authorization_key.as_ref() == Some(&authorization_key))
            .map(|queued| queued.command.clone())
            .collect();
        if let Some(active) = &self.active
            && active.turn_id.is_none()
            && active.authorization_key.as_ref() == Some(&authorization_key)
        {
            targets.push(active.command.clone());
        }
        let mut terminated = 0;
        for target in targets {
            match self
                .store
                .terminate_accepted_command(TerminateAcceptedCommand {
                    conversation_id: self.conversation.conversation_id,
                    command_id: target.command_id,
                    expected_owner: target.owner,
                    reason: AcceptedTerminationReason::RevokedBeforeStart,
                    event_payload: revocation_event(target.command_id),
                })
                .await?
            {
                TerminateAcceptedOutcome::Transitioned { command, .. } => {
                    terminated += 1;
                    self.remove_pending(command.command_id);
                }
                TerminateAcceptedOutcome::Replayed { command, .. } => {
                    self.remove_pending(command.command_id);
                }
                TerminateAcceptedOutcome::AlreadyStarted { .. } => {}
            }
        }
        Ok(terminated)
    }

    fn remove_pending(&mut self, command_id: RuntimeId) {
        self.pending
            .retain(|queued| queued.command.command_id != command_id);
    }

    fn start_next(&mut self) {
        let Some(queued) = self.pending.pop_front() else {
            return;
        };
        let command = queued.command;
        let principal = queued.principal;
        let execution_gate = Arc::new(Mutex::new(ActiveExecutionGate::default()));
        let execution_task = AbortOnDropTask::new(tokio::spawn(execute_command(
            self.conversation.clone(),
            command.clone(),
            principal,
            self.store.clone(),
            self.execution.clone(),
            self.daemon_boot_id,
            self.adapter_permits.clone(),
            self.scheduling_gate.clone(),
            self.start_transition.clone(),
            execution_gate.clone(),
            self.runner_tx.clone(),
        )));
        let command_id = command.command_id;
        let runner_tx = self.runner_tx.clone();
        let task = AbortOnDropTask::new(tokio::spawn(supervise_execution_task(
            command_id,
            execution_task,
            runner_tx,
        )));
        self.active = Some(ActiveCommand {
            command,
            authorization_key: queued.authorization_key,
            turn_id: None,
            control: None,
            execution_gate,
            task,
        });
    }

    async fn handle_runner_event(&mut self, event: RunnerEvent) {
        match event {
            RunnerEvent::Started {
                command_id,
                turn_id,
                acknowledged,
            } => {
                if let Some(active) = self
                    .active
                    .as_mut()
                    .filter(|active| active.command.command_id == command_id)
                {
                    active.turn_id = Some(turn_id);
                    let _ = acknowledged.send(());
                }
            }
            RunnerEvent::Prepared {
                command_id,
                turn_id,
                control,
                acknowledged,
            } => {
                let result = if let Some(active) = self.active.as_mut().filter(|active| {
                    active.command.command_id == command_id && active.turn_id == Some(turn_id)
                }) {
                    active.control = Some(control.clone());
                    fence_pre_release_cancel_if_requested(&active.execution_gate, control)
                        .await
                        .map(|canceled| {
                            if canceled {
                                PreparedDecision::CanceledBeforeRelease
                            } else {
                                PreparedDecision::Proceed
                            }
                        })
                } else {
                    Err(RuntimeExecutionError::PrepareFailed)
                };
                let _ = acknowledged.send(result);
            }
            RunnerEvent::Finished { command_id } => {
                if self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.command.command_id == command_id)
                    && let Some(mut active) = self.active.take()
                {
                    let _ = active.task.join().await;
                }
            }
            RunnerEvent::RecoveryBlocked { command_id } => {
                if self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.command.command_id == command_id)
                {
                    self.enter_recovery_blocked();
                    if let Some(active) = self.active.take() {
                        let mut active = active;
                        let _ = active.task.join().await;
                    }
                }
            }
            RunnerEvent::RunnerExited { command_id } => {
                if self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.command.command_id == command_id)
                {
                    self.enter_recovery_blocked();
                    if let Some(mut active) = self.active.take() {
                        let _ = active.task.join().await;
                    }
                }
            }
        }
    }

    async fn stop_active(&mut self) {
        let Some(mut active) = self.active.take() else {
            return;
        };
        let _ = request_active_cancel(&active.execution_gate, active.control.take()).await;
        if tokio::time::timeout(self.shutdown_grace, active.task.join())
            .await
            .is_err()
        {
            active.task.abort();
            let _ = active.task.join().await;
        }
    }
}

async fn supervise_execution_task(
    command_id: RuntimeId,
    mut execution_task: AbortOnDropTask<()>,
    runner_tx: mpsc::Sender<RunnerEvent>,
) {
    let _ = execution_task.join().await;
    let _ = runner_tx
        .send(RunnerEvent::RunnerExited { command_id })
        .await;
}

async fn cancel_control(
    control: Arc<dyn RuntimeExecutionControl>,
) -> Result<(), RuntimeExecutionError> {
    tokio::time::timeout(CONTROL_CANCEL_TIMEOUT, control.cancel_and_wait_fenced())
        .await
        .map_err(|_| RuntimeExecutionError::CancelFailed)?
}

async fn request_active_cancel(
    execution_gate: &Mutex<ActiveExecutionGate>,
    control: Option<Arc<dyn RuntimeExecutionControl>>,
) -> Result<(), RuntimeExecutionError> {
    let mut gate = execution_gate.lock().await;
    gate.cancel_requested = true;
    if let Some(control) = control {
        cancel_control(control).await?;
        gate.cancel_fenced = true;
    }
    Ok(())
}

async fn fence_pre_release_cancel_if_requested(
    execution_gate: &Mutex<ActiveExecutionGate>,
    control: Arc<dyn RuntimeExecutionControl>,
) -> Result<bool, RuntimeExecutionError> {
    let mut gate = execution_gate.lock().await;
    if !gate.cancel_requested {
        return Ok(false);
    }
    cancel_control(control).await?;
    gate.cancel_fenced = true;
    Ok(true)
}

async fn pre_release_cancel_won(
    execution_gate: &Mutex<ActiveExecutionGate>,
) -> Result<bool, RuntimeExecutionError> {
    let gate = execution_gate.lock().await;
    if !gate.cancel_requested {
        return Ok(false);
    }
    if !gate.cancel_fenced {
        return Err(RuntimeExecutionError::CancelFailed);
    }
    Ok(true)
}

async fn prompt_admission_worker(
    conversation_id: RuntimeId,
    store: RuntimeStoreHandle,
    mut prompt_rx: mpsc::Receiver<PromptCommand>,
    mut prompt_open: watch::Receiver<bool>,
    admission_tx: mpsc::Sender<PromptAdmission>,
) {
    loop {
        if !*prompt_open.borrow() {
            prompt_rx.close();
        }
        let command = tokio::select! {
            changed = prompt_open.changed(), if *prompt_open.borrow() => {
                if changed.is_err() || !*prompt_open.borrow_and_update() {
                    prompt_rx.close();
                }
                continue;
            }
            command = prompt_rx.recv() => command,
        };
        let Some(command) = command else {
            break;
        };
        let authorization_key = command.principal.authorization_key();
        let outcome = store
            .accept_command(AcceptCommand {
                conversation_id,
                owner: command.principal.idempotency_owner(),
                idempotency_key: command.idempotency_key,
                payload: command.payload,
            })
            .await;
        if admission_tx
            .send(PromptAdmission {
                principal: command.principal,
                authorization_key,
                _authorization_guard: command._authorization_guard,
                outcome,
                reply: command.reply,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_command(
    conversation: ConversationRecord,
    accepted: CommandRecord,
    principal: Option<AuthenticatedPrincipal>,
    store: RuntimeStoreHandle,
    execution: Arc<dyn RuntimeExecutionCoordinator>,
    daemon_boot_id: RuntimeId,
    adapter_permits: Arc<Semaphore>,
    scheduling_gate: watch::Receiver<bool>,
    start_transition: Arc<RwLock<()>>,
    execution_gate: Arc<Mutex<ActiveExecutionGate>>,
    runner_tx: mpsc::Sender<RunnerEvent>,
) {
    let Ok(_adapter_permit) = adapter_permits.acquire_owned().await else {
        let _ = runner_tx
            .send(RunnerEvent::RecoveryBlocked {
                command_id: accepted.command_id,
            })
            .await;
        return;
    };
    let authorization_guard = match principal {
        Some(principal) => match principal.try_enter() {
            Ok(guard) => Some(guard),
            Err(_) => {
                let outcome = store
                    .terminate_accepted_command(TerminateAcceptedCommand {
                        conversation_id: conversation.conversation_id,
                        command_id: accepted.command_id,
                        expected_owner: accepted.owner.clone(),
                        reason: AcceptedTerminationReason::RevokedBeforeStart,
                        event_payload: revocation_event(accepted.command_id),
                    })
                    .await;
                let event = if matches!(
                    outcome,
                    Ok(TerminateAcceptedOutcome::Transitioned { .. })
                        | Ok(TerminateAcceptedOutcome::Replayed { .. })
                ) {
                    RunnerEvent::Finished {
                        command_id: accepted.command_id,
                    }
                } else {
                    RunnerEvent::RecoveryBlocked {
                        command_id: accepted.command_id,
                    }
                };
                let _ = runner_tx.send(event).await;
                return;
            }
        },
        // 恢复命令要到 P4 durable auth 才能重绑具体 grant；P3.4 production
        // coordinator 为 disabled，因此这里不会越过副作用门禁。
        None => None,
    };
    let Ok(execution_nonce) = random_execution_nonce() else {
        let _ = runner_tx
            .send(RunnerEvent::RecoveryBlocked {
                command_id: accepted.command_id,
            })
            .await;
        return;
    };
    let start_guard = start_transition.read().await;
    if !*scheduling_gate.borrow() {
        drop(start_guard);
        let _ = runner_tx
            .send(RunnerEvent::Finished {
                command_id: accepted.command_id,
            })
            .await;
        return;
    }
    let started = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: accepted.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            intent_payload: execution_intent(&conversation, &accepted),
            event_payload: started_event(accepted.command_id),
        })
        .await;
    drop(start_guard);
    // begin_revoke 只有在 Accepted→Started durable transition 完成后才可继续；
    // 若 revoke CAS 先赢，try_enter 已在上方 fail-closed。
    drop(authorization_guard);
    let (command, turn_id) = match started {
        Ok(StartOutcome::Started {
            command, intent, ..
        })
        | Ok(StartOutcome::Replayed {
            command, intent, ..
        }) => (command, intent.turn_id),
        // queued cancel/revoke 可能先赢得同一 SQLite transition；这不是 recovery block。
        Err(RuntimeStoreError::InvalidStateTransition) | Err(RuntimeStoreError::CommandExpired) => {
            let _ = runner_tx
                .send(RunnerEvent::Finished {
                    command_id: accepted.command_id,
                })
                .await;
            return;
        }
        Err(_) => {
            let _ = runner_tx
                .send(RunnerEvent::RecoveryBlocked {
                    command_id: accepted.command_id,
                })
                .await;
            return;
        }
    };

    let (started_ack, started_ready) = oneshot::channel();
    if runner_tx
        .send(RunnerEvent::Started {
            command_id: command.command_id,
            turn_id,
            acknowledged: started_ack,
        })
        .await
        .is_err()
        || started_ready.await.is_err()
    {
        return;
    }

    let prepared = match execution
        .prepare(RuntimeExecutionContext {
            conversation: conversation.clone(),
            command: command.clone(),
            turn_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(_) => {
            let _ = runner_tx
                .send(RunnerEvent::RecoveryBlocked {
                    command_id: command.command_id,
                })
                .await;
            return;
        }
    };

    let process = prepared.process;
    let control = prepared.control;
    let release = prepared.release;
    let (prepared_ack, prepared_ready) = oneshot::channel();
    if runner_tx
        .send(RunnerEvent::Prepared {
            command_id: command.command_id,
            turn_id,
            control: control.clone(),
            acknowledged: prepared_ack,
        })
        .await
        .is_err()
    {
        let _ = cancel_control(control).await;
        return;
    }
    match prepared_ready.await {
        Ok(Ok(PreparedDecision::Proceed)) => {}
        Ok(Ok(PreparedDecision::CanceledBeforeRelease)) => {
            let termination = TerminateStartedBeforeRelease {
                conversation_id: conversation.conversation_id,
                command_id: command.command_id,
                turn_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                reason: StartedBeforeReleaseTermination::Canceled,
                terminal_payload: b"execution canceled before release".to_vec(),
                event_payload: canceled_before_release_event(command.command_id),
            };
            let event = if terminate_started_before_release_exact(&store, termination).await {
                RunnerEvent::Finished {
                    command_id: command.command_id,
                }
            } else {
                RunnerEvent::RecoveryBlocked {
                    command_id: command.command_id,
                }
            };
            let _ = runner_tx.send(event).await;
            return;
        }
        Ok(Err(_)) | Err(_) => {
            let _ = cancel_control(control).await;
            let _ = runner_tx
                .send(RunnerEvent::RecoveryBlocked {
                    command_id: command.command_id,
                })
                .await;
            return;
        }
    }

    match pre_release_cancel_won(&execution_gate).await {
        Ok(true) => {
            let termination = TerminateStartedBeforeRelease {
                conversation_id: conversation.conversation_id,
                command_id: command.command_id,
                turn_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                reason: StartedBeforeReleaseTermination::Canceled,
                terminal_payload: b"execution canceled before release".to_vec(),
                event_payload: canceled_before_release_event(command.command_id),
            };
            let event = if terminate_started_before_release_exact(&store, termination).await {
                RunnerEvent::Finished {
                    command_id: command.command_id,
                }
            } else {
                RunnerEvent::RecoveryBlocked {
                    command_id: command.command_id,
                }
            };
            let _ = runner_tx.send(event).await;
            return;
        }
        Ok(false) => {}
        Err(_) => {
            let _ = runner_tx
                .send(RunnerEvent::RecoveryBlocked {
                    command_id: command.command_id,
                })
                .await;
            return;
        }
    }

    let fence = store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: process.process_group_id,
            leader_pid: process.leader_pid,
            leader_start_time: process.leader_start_time,
            payload: process.fence_payload,
        })
        .await;
    if fence.is_err() {
        let _ = cancel_control(control).await;
        let _ = runner_tx
            .send(RunnerEvent::RecoveryBlocked {
                command_id: command.command_id,
            })
            .await;
        return;
    }

    let release_request = AuthorizeExecutionRelease {
        command_id: command.command_id,
        daemon_boot_id,
        execution_nonce,
    };
    let release_record = {
        let mut gate = execution_gate.lock().await;
        if gate.cancel_requested {
            if !gate.cancel_fenced {
                let _ = runner_tx
                    .send(RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
                    })
                    .await;
                return;
            }
            drop(gate);
            let termination = TerminateStartedBeforeRelease {
                conversation_id: conversation.conversation_id,
                command_id: command.command_id,
                turn_id,
                daemon_boot_id,
                execution_nonce: release_request.execution_nonce.clone(),
                reason: StartedBeforeReleaseTermination::Canceled,
                terminal_payload: b"execution canceled before release".to_vec(),
                event_payload: canceled_before_release_event(command.command_id),
            };
            let event = if terminate_started_before_release_exact(&store, termination).await {
                RunnerEvent::Finished {
                    command_id: command.command_id,
                }
            } else {
                RunnerEvent::RecoveryBlocked {
                    command_id: command.command_id,
                }
            };
            let _ = runner_tx.send(event).await;
            return;
        }
        match store
            .authorize_execution_release(release_request.clone())
            .await
        {
            Ok(record) => {
                gate.release_authorized = true;
                record
            }
            Err(_) => {
                drop(gate);
                let _ = cancel_control(control).await;
                let _ = runner_tx
                    .send(RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
                    })
                    .await;
                return;
            }
        }
    };
    let permit =
        match ExecutionReleasePermit::from_committed_store(&release_request, &release_record) {
            Ok(permit) => permit,
            Err(_) => {
                let _ = cancel_control(control).await;
                let _ = runner_tx
                    .send(RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
                    })
                    .await;
                return;
            }
        };
    let completion_future = match release.release(permit).await {
        Ok(completion) => completion,
        Err(_) => {
            if cancel_control(control.clone()).await.is_err() {
                let _ = runner_tx
                    .send(RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
                    })
                    .await;
                return;
            }
            Box::pin(async move {
                Ok(RuntimeExecutionCompletion {
                    terminal_state: TerminalState::Interrupted,
                    terminal_payload: b"execution release failed after authorization".to_vec(),
                    event_payload: interrupted_event(command.command_id),
                })
            })
        }
    };

    // completion future 只有消费 committed release permit 后才能取得。
    let completion = match completion_future.await {
        Ok(completion) => completion,
        Err(_) => {
            if cancel_control(control).await.is_err() {
                let _ = runner_tx
                    .send(RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
                    })
                    .await;
                return;
            }
            RuntimeExecutionCompletion {
                terminal_state: TerminalState::Interrupted,
                terminal_payload: b"execution completion unavailable".to_vec(),
                event_payload: interrupted_event(command.command_id),
            }
        }
    };
    if store
        .complete_command_with_event(CompleteCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            turn_id,
            terminal_state: completion.terminal_state,
            terminal_payload: completion.terminal_payload,
            event_payload: completion.event_payload,
        })
        .await
        .is_err()
    {
        let _ = runner_tx
            .send(RunnerEvent::RecoveryBlocked {
                command_id: command.command_id,
            })
            .await;
        return;
    }
    let _ = runner_tx
        .send(RunnerEvent::Finished {
            command_id: command.command_id,
        })
        .await;
}

async fn terminate_started_before_release_exact(
    store: &RuntimeStoreHandle,
    input: TerminateStartedBeforeRelease,
) -> bool {
    match store.terminate_started_before_release(input.clone()).await {
        Ok(
            TerminateStartedBeforeReleaseOutcome::Transitioned { .. }
            | TerminateStartedBeforeReleaseOutcome::Replayed { .. },
        ) => true,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: super::store::RuntimeCommitOperation::TerminateStartedBeforeRelease,
        }) => matches!(
            store.terminate_started_before_release(input).await,
            Ok(TerminateStartedBeforeReleaseOutcome::Transitioned { .. }
                | TerminateStartedBeforeReleaseOutcome::Replayed { .. })
        ),
        Err(_) => false,
    }
}

fn random_execution_nonce() -> Result<Vec<u8>, getrandom::Error> {
    let mut nonce = vec![0_u8; EXECUTION_NONCE_BYTES];
    getrandom::fill(&mut nonce)?;
    Ok(nonce)
}

fn execution_intent(conversation: &ConversationRecord, command: &CommandRecord) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "kind": "runtimeExecutionIntent",
        "version": 1,
        "conversationId": conversation.conversation_id.to_canonical_string(),
        "commandId": command.command_id.to_canonical_string(),
        "commandSeq": command.command_seq,
    }))
    .expect("fixed runtime intent is serializable")
}

fn started_event(command_id: RuntimeId) -> Vec<u8> {
    fixed_event("commandStarted", command_id)
}

fn cancellation_event(command_id: RuntimeId) -> Vec<u8> {
    fixed_event("commandCanceledBeforeStart", command_id)
}

fn revocation_event(command_id: RuntimeId) -> Vec<u8> {
    fixed_event("commandRevokedBeforeStart", command_id)
}

fn interrupted_event(command_id: RuntimeId) -> Vec<u8> {
    fixed_event("commandInterrupted", command_id)
}

fn canceled_before_release_event(command_id: RuntimeId) -> Vec<u8> {
    fixed_event("commandCanceledBeforeRelease", command_id)
}

fn fixed_event(kind: &str, command_id: RuntimeId) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "kind": kind,
        "commandId": command_id.to_canonical_string(),
    }))
    .expect("fixed runtime event is serializable")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex as StdMutex, OnceLock};

    use agentdeck_protocol::AgentKind;

    use super::*;
    use crate::runtime::connection::PrincipalIssuer;
    use crate::runtime::execution::{
        DisabledExecutionCoordinator, PreparedRuntimeExecution, RuntimeExecutionRelease,
        RuntimeProcessIdentity,
    };
    use crate::runtime::store::{
        CommandReceiptSelector, CommandState, ConversationDescriptor, NewConversation,
        QueryCommandReceipt, RecoveryCursor, RuntimeClock, RuntimeClockError,
        RuntimeCommitOperation, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreFaultInjector,
        RuntimeStoreOperation,
    };
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone, Debug)]
    struct ManualClock(Arc<AtomicU64>);

    impl ManualClock {
        fn new(now_ms: u64) -> Self {
            Self(Arc::new(AtomicU64::new(now_ms)))
        }

        fn set(&self, now_ms: u64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl RuntimeClock for ManualClock {
        fn now_ms(&self) -> Result<u64, RuntimeClockError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct FailAcceptReplyOnce(AtomicBool);

    impl RuntimeStoreFaultInjector for FailAcceptReplyOnce {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::AcceptCommandAfterCommit
                && self.0.swap(false, Ordering::SeqCst)
            {
                return Err(RuntimeStoreError::WorkerStopped);
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct BlockFenceCommit {
        entered: AtomicBool,
        released: StdMutex<bool>,
        released_changed: Condvar,
    }

    impl BlockFenceCommit {
        fn new() -> Self {
            Self {
                entered: AtomicBool::new(false),
                released: StdMutex::new(false),
                released_changed: Condvar::new(),
            }
        }

        fn release(&self) {
            *self.released.lock().expect("fence blocker lock") = true;
            self.released_changed.notify_all();
        }
    }

    impl RuntimeStoreFaultInjector for BlockFenceCommit {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::PersistFenceBeforeCommit {
                self.entered.store(true, Ordering::SeqCst);
                let mut released = self.released.lock().expect("fence blocker lock");
                while !*released {
                    released = self
                        .released_changed
                        .wait(released)
                        .expect("fence blocker wait");
                }
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct BlockNextAcceptCommit {
        armed: AtomicBool,
        entered: AtomicBool,
        released: StdMutex<bool>,
        released_changed: Condvar,
    }

    impl BlockNextAcceptCommit {
        fn new() -> Self {
            Self {
                armed: AtomicBool::new(false),
                entered: AtomicBool::new(false),
                released: StdMutex::new(false),
                released_changed: Condvar::new(),
            }
        }

        fn arm(&self) {
            self.armed.store(true, Ordering::SeqCst);
        }

        fn release(&self) {
            *self.released.lock().expect("accept blocker lock") = true;
            self.released_changed.notify_all();
        }
    }

    impl RuntimeStoreFaultInjector for BlockNextAcceptCommit {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::AcceptCommandBeforeCommit
                && self.armed.swap(false, Ordering::SeqCst)
            {
                self.entered.store(true, Ordering::SeqCst);
                let mut released = self.released.lock().expect("accept blocker lock");
                while !*released {
                    released = self
                        .released_changed
                        .wait(released)
                        .expect("accept blocker wait");
                }
            }
            Ok(())
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = Path::new("/tmp").join(format!(
                "agentdeck-runtime-actor-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create actor test root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure actor test root");
            }
            Self(path)
        }

        async fn open(&self) -> RuntimeStoreHandle {
            let keys = MemoryKeyStore::new();
            let kek = load_or_create_storage_kek(&keys, &self.0.join("key-state.db"))
                .expect("actor test StorageKEK");
            RuntimeStoreHandle::open(RuntimeStoreConfig::new(self.0.join("runtime.db")), kek)
                .await
                .expect("open actor test store")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StartObservation {
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        command_seq: u64,
        turn_id: RuntimeId,
    }

    #[derive(Clone)]
    struct FakeCoordinator {
        inner: Arc<FakeCoordinatorInner>,
    }

    struct FakeCoordinatorInner {
        held: bool,
        prepare_gate: Option<Arc<Semaphore>>,
        behavior: FakeBehavior,
        starts: StdMutex<Vec<StartObservation>>,
        completions: StdMutex<Vec<(RuntimeId, TerminalState)>>,
        controls: StdMutex<HashMap<RuntimeId, Arc<FakeControl>>>,
        changed: tokio::sync::Notify,
        next_pid: AtomicI64,
        active: Arc<AtomicUsize>,
        peak: AtomicUsize,
        releases: AtomicUsize,
    }

    struct FakeControl {
        gate: Arc<Semaphore>,
        canceled: AtomicBool,
        cancel_count: AtomicUsize,
        cancel_fails: bool,
    }

    #[derive(Clone, Copy, Default)]
    struct FakeBehavior {
        completion_error: bool,
        release_error: bool,
        cancel_fails: bool,
        panic_prepare: bool,
    }

    struct FakeRelease {
        expected_command_id: RuntimeId,
        expected_daemon_boot_id: RuntimeId,
        expected_execution_nonce: Vec<u8>,
        control: Arc<FakeControl>,
        inner: Arc<FakeCoordinatorInner>,
        active_guard: Option<ActiveCounterGuard>,
    }

    #[async_trait::async_trait]
    impl RuntimeExecutionControl for FakeControl {
        async fn cancel_and_wait_fenced(&self) -> Result<(), RuntimeExecutionError> {
            self.canceled.store(true, Ordering::SeqCst);
            self.cancel_count.fetch_add(1, Ordering::SeqCst);
            if self.cancel_fails {
                return Err(RuntimeExecutionError::CancelFailed);
            }
            self.gate.add_permits(1);
            Ok(())
        }
    }

    struct ActiveCounterGuard(Arc<AtomicUsize>);

    impl Drop for ActiveCounterGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl RuntimeExecutionRelease for FakeRelease {
        async fn release(
            mut self: Box<Self>,
            permit: ExecutionReleasePermit,
        ) -> Result<super::super::execution::RuntimeCompletionFuture, RuntimeExecutionError>
        {
            if permit.command_id() != self.expected_command_id
                || permit.daemon_boot_id() != self.expected_daemon_boot_id
                || permit.execution_nonce() != self.expected_execution_nonce
                || permit.release_authorized_at_ms() == 0
            {
                return Err(RuntimeExecutionError::ReleaseAuthorizationInvalid);
            }
            self.inner.releases.fetch_add(1, Ordering::SeqCst);
            if self.inner.behavior.release_error {
                return Err(RuntimeExecutionError::ReleaseFailed);
            }
            let command_id = self.expected_command_id;
            let inner = self.inner.clone();
            let completion_control = self.control.clone();
            let active_guard = self
                .active_guard
                .take()
                .ok_or(RuntimeExecutionError::ReleaseFailed)?;
            Ok(Box::pin(async move {
                let _active_guard = active_guard;
                let _release = completion_control
                    .gate
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| RuntimeExecutionError::CompletionClosed)?;
                if inner.behavior.completion_error {
                    return Err(RuntimeExecutionError::CompletionClosed);
                }
                let terminal_state = if completion_control.canceled.load(Ordering::SeqCst) {
                    TerminalState::Canceled
                } else {
                    TerminalState::Completed
                };
                inner
                    .completions
                    .lock()
                    .expect("completions lock")
                    .push((command_id, terminal_state));
                inner.changed.notify_waiters();
                Ok(RuntimeExecutionCompletion {
                    terminal_state,
                    terminal_payload: b"fake-result".to_vec(),
                    event_payload: fixed_event("fakeTerminal", command_id),
                })
            }))
        }
    }

    impl FakeCoordinator {
        fn held() -> Self {
            Self::new(true, false, FakeBehavior::default())
        }

        fn automatic() -> Self {
            Self::new(false, false, FakeBehavior::default())
        }

        fn blocked_prepare() -> Self {
            Self::new(true, true, FakeBehavior::default())
        }

        fn completion_error(cancel_fails: bool) -> Self {
            Self::new(
                false,
                false,
                FakeBehavior {
                    completion_error: true,
                    cancel_fails,
                    ..FakeBehavior::default()
                },
            )
        }

        fn release_error(cancel_fails: bool) -> Self {
            Self::new(
                false,
                false,
                FakeBehavior {
                    release_error: true,
                    cancel_fails,
                    ..FakeBehavior::default()
                },
            )
        }

        fn panicking() -> Self {
            Self::new(
                false,
                false,
                FakeBehavior {
                    panic_prepare: true,
                    ..FakeBehavior::default()
                },
            )
        }

        fn blocked_panicking() -> Self {
            Self::new(
                false,
                true,
                FakeBehavior {
                    panic_prepare: true,
                    ..FakeBehavior::default()
                },
            )
        }

        fn new(held: bool, block_prepare: bool, behavior: FakeBehavior) -> Self {
            Self {
                inner: Arc::new(FakeCoordinatorInner {
                    held,
                    prepare_gate: block_prepare.then(|| Arc::new(Semaphore::new(0))),
                    behavior,
                    starts: StdMutex::new(Vec::new()),
                    completions: StdMutex::new(Vec::new()),
                    controls: StdMutex::new(HashMap::new()),
                    changed: tokio::sync::Notify::new(),
                    next_pid: AtomicI64::new(10_000),
                    active: Arc::new(AtomicUsize::new(0)),
                    peak: AtomicUsize::new(0),
                    releases: AtomicUsize::new(0),
                }),
            }
        }

        fn starts(&self) -> Vec<StartObservation> {
            self.inner.starts.lock().expect("starts lock").clone()
        }

        fn completions(&self) -> Vec<(RuntimeId, TerminalState)> {
            self.inner
                .completions
                .lock()
                .expect("completions lock")
                .clone()
        }

        fn peak(&self) -> usize {
            self.inner.peak.load(Ordering::SeqCst)
        }

        fn active(&self) -> usize {
            self.inner.active.load(Ordering::SeqCst)
        }

        fn release_count(&self) -> usize {
            self.inner.releases.load(Ordering::SeqCst)
        }

        fn cancel_count(&self, command_id: RuntimeId) -> usize {
            self.inner
                .controls
                .lock()
                .expect("controls lock")
                .get(&command_id)
                .map_or(0, |control| control.cancel_count.load(Ordering::SeqCst))
        }

        fn allow_prepare(&self) {
            self.inner
                .prepare_gate
                .as_ref()
                .expect("blocked prepare coordinator")
                .add_permits(1);
        }

        fn release(&self, command_id: RuntimeId) {
            self.inner
                .controls
                .lock()
                .expect("controls lock")
                .get(&command_id)
                .expect("known fake command")
                .gate
                .add_permits(1);
        }

        async fn wait_for_starts(&self, expected: usize) {
            wait_until(|| self.starts().len() >= expected).await;
        }

        async fn wait_for_completions(&self, expected: usize) {
            wait_until(|| self.completions().len() >= expected).await;
        }
    }

    #[async_trait::async_trait]
    impl RuntimeExecutionCoordinator for FakeCoordinator {
        fn is_ready(&self) -> bool {
            true
        }

        async fn prepare(
            &self,
            context: RuntimeExecutionContext,
        ) -> Result<PreparedRuntimeExecution, RuntimeExecutionError> {
            let now = self.inner.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.inner.peak.fetch_max(now, Ordering::SeqCst);
            let control = Arc::new(FakeControl {
                gate: Arc::new(Semaphore::new(usize::from(!self.inner.held))),
                canceled: AtomicBool::new(false),
                cancel_count: AtomicUsize::new(0),
                cancel_fails: self.inner.behavior.cancel_fails,
            });
            let active_guard = ActiveCounterGuard(self.inner.active.clone());
            self.inner
                .starts
                .lock()
                .expect("starts lock")
                .push(StartObservation {
                    conversation_id: context.conversation.conversation_id,
                    command_id: context.command.command_id,
                    command_seq: context.command.command_seq,
                    turn_id: context.turn_id,
                });
            self.inner
                .controls
                .lock()
                .expect("controls lock")
                .insert(context.command.command_id, control.clone());
            self.inner.changed.notify_waiters();

            if let Some(gate) = &self.inner.prepare_gate {
                let _permit = gate
                    .acquire()
                    .await
                    .map_err(|_| RuntimeExecutionError::PrepareFailed)?;
            }

            assert!(!self.inner.behavior.panic_prepare, "injected prepare panic");

            let process_id = self.inner.next_pid.fetch_add(1, Ordering::SeqCst);
            Ok(PreparedRuntimeExecution {
                process: RuntimeProcessIdentity {
                    process_group_id: process_id,
                    leader_pid: process_id,
                    leader_start_time: u64::try_from(process_id).expect("positive fake pid"),
                    fence_payload: b"side-effect-free-test-fence".to_vec(),
                },
                control,
                release: Box::new(FakeRelease {
                    expected_command_id: context.command.command_id,
                    expected_daemon_boot_id: context.daemon_boot_id,
                    expected_execution_nonce: context.execution_nonce,
                    control: self
                        .inner
                        .controls
                        .lock()
                        .expect("controls lock")
                        .get(&context.command.command_id)
                        .expect("inserted fake control")
                        .clone(),
                    inner: self.inner.clone(),
                    active_guard: Some(active_guard),
                }),
            })
        }
    }

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("nonzero runtime id")
    }

    async fn finish_recovery(store: &RuntimeStoreHandle) {
        let mut cursor: RecoveryCursor = store.begin_recovery_scan().await.expect("begin recovery");
        loop {
            let page = store
                .load_recovery_page(cursor)
                .await
                .expect("load recovery page");
            assert!(page.conversation.is_none(), "test store starts empty");
            if let Some(next) = page.next_cursor {
                cursor = next;
                continue;
            }
            store
                .finish_recovery_scan(page.completion.expect("terminal completion"))
                .await
                .expect("finish recovery");
            return;
        }
    }

    async fn create_conversation(store: &RuntimeStoreHandle, seed: u8) -> ConversationRecord {
        store
            .create_conversation(NewConversation {
                conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::Codex,
                    title: Some(format!("actor-{seed}")),
                    cwd: PathBuf::from(format!("/tmp/actor-{seed}")),
                },
            })
            .await
            .expect("create actor conversation")
    }

    fn local_principal(seed: u8) -> AuthenticatedPrincipal {
        PrincipalIssuer::local_only([0xA1; 32])
            .issue_verified_local(501, [seed; 16])
            .expect("issue actor test principal")
    }

    async fn submit(
        registry: &ConversationRegistry,
        conversation_id: RuntimeId,
        principal: &AuthenticatedPrincipal,
        key: &str,
        payload: &str,
    ) -> PromptAcceptResult {
        registry
            .submit_prompt(
                conversation_id,
                principal.clone(),
                principal.try_enter().expect("active principal"),
                key.to_owned(),
                payload.as_bytes().to_vec(),
            )
            .await
            .expect("submit prompt")
    }

    fn command(result: &PromptAcceptResult) -> CommandRecord {
        match result {
            PromptAcceptResult::Accepted { command, .. }
            | PromptAcceptResult::Replayed { command } => command.clone(),
        }
    }

    async fn wait_until(mut predicate: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !predicate() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("actor condition timed out");
    }

    async fn wait_for_receipt_state(
        store: &RuntimeStoreHandle,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        principal: &AuthenticatedPrincipal,
        expected: CommandState,
    ) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let receipt = store
                    .query_command_receipt(QueryCommandReceipt {
                        expected_owner: principal.idempotency_owner(),
                        selector: CommandReceiptSelector::Command {
                            conversation_id,
                            command_id,
                        },
                    })
                    .await
                    .expect("query command receipt");
                if receipt.state == expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("receipt state timed out");
    }

    #[tokio::test]
    async fn same_conversation_is_fifo_while_different_conversations_run_in_parallel() {
        let root = TestRoot::new("fifo-parallel");
        let store = root.open().await;
        finish_recovery(&store).await;
        let left = create_conversation(&store, 1).await;
        let right = create_conversation(&store, 2).await;
        let fake = FakeCoordinator::held();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD1),
            2,
        )
        .expect("registry");
        registry
            .install(left.clone(), Vec::new())
            .await
            .expect("left actor");
        registry
            .install(right.clone(), Vec::new())
            .await
            .expect("right actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(1);

        let l0 = command(&submit(&registry, left.conversation_id, &principal, "l0", "L0").await);
        let l1 = command(&submit(&registry, left.conversation_id, &principal, "l1", "L1").await);
        let r0 = command(&submit(&registry, right.conversation_id, &principal, "r0", "R0").await);
        let r1 = command(&submit(&registry, right.conversation_id, &principal, "r1", "R1").await);

        fake.wait_for_starts(2).await;
        assert_eq!(fake.peak(), 2, "different actors must run concurrently");
        let initial = fake.starts();
        assert_eq!(
            initial
                .iter()
                .filter(|start| start.conversation_id == left.conversation_id)
                .map(|start| start.command_seq)
                .collect::<Vec<_>>(),
            vec![0]
        );
        assert_eq!(
            initial
                .iter()
                .filter(|start| start.conversation_id == right.conversation_id)
                .map(|start| start.command_seq)
                .collect::<Vec<_>>(),
            vec![0]
        );

        fake.release(l0.command_id);
        fake.wait_for_starts(3).await;
        assert_eq!(
            fake.starts()
                .iter()
                .filter(|start| start.conversation_id == left.conversation_id)
                .map(|start| start.command_seq)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        fake.release(r0.command_id);
        fake.wait_for_starts(4).await;
        fake.release(l1.command_id);
        fake.release(r1.command_id);
        fake.wait_for_completions(4).await;
        assert_eq!(fake.active(), 0);

        registry.shutdown().await.expect("shutdown actors");
        assert_eq!(registry.len().await, 0);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn queued_and_active_cancel_use_exact_distinct_targets() {
        let root = TestRoot::new("cancel");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 3).await;
        let fake = FakeCoordinator::held();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD2),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(2);
        let first = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "first",
                "first",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        let second = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "second",
                "second",
            )
            .await,
        );

        let canceled = registry
            .cancel_queued(
                conversation.conversation_id,
                second.command_id,
                principal.clone(),
                principal.try_enter().expect("cancel guard"),
            )
            .await
            .expect("cancel queued");
        assert!(matches!(canceled, QueuedCancelResult::Canceled { .. }));

        let active = fake.starts()[0];
        assert_eq!(active.command_id, first.command_id);
        let stale_turn = runtime_id(RuntimeIdKind::Turn, 0xEE);
        assert_eq!(
            registry
                .cancel_active(
                    conversation.conversation_id,
                    stale_turn,
                    principal.try_enter().expect("stale cancel guard"),
                )
                .await
                .expect("stale cancel"),
            ActiveCancelResult::Stale
        );
        assert_eq!(
            registry
                .cancel_active(
                    conversation.conversation_id,
                    active.turn_id,
                    principal.try_enter().expect("active cancel guard"),
                )
                .await
                .expect("active cancel"),
            ActiveCancelResult::Requested
        );
        fake.wait_for_completions(1).await;
        assert_eq!(fake.completions()[0].1, TerminalState::Canceled);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            fake.starts().len(),
            1,
            "canceled queued command must not start"
        );

        let queued_receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: second.command_id,
                },
            })
            .await
            .expect("query queued cancellation");
        assert_eq!(queued_receipt.state, CommandState::Canceled);
        let active_receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: first.command_id,
                },
            })
            .await
            .expect("query active cancellation");
        assert_eq!(active_receipt.state, CommandState::Canceled);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn revocation_terminates_only_matching_accepted_work_before_start() {
        let root = TestRoot::new("revoke");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 4).await;
        let fake = FakeCoordinator::held();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD3),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let active_principal = local_principal(3);
        let revoked_principal = local_principal(4);
        let active = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &active_principal,
                "active",
                "active",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        let revoked = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &revoked_principal,
                "revoked",
                "revoked",
            )
            .await,
        );

        assert_eq!(
            registry
                .revoke_principal(&revoked_principal)
                .await
                .expect("revoke"),
            1
        );
        assert!(revoked_principal.try_enter().is_err());
        fake.release(active.command_id);
        fake.wait_for_completions(1).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(fake.starts().len(), 1);
        let receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: revoked_principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: revoked.command_id,
                },
            })
            .await
            .expect("query revoked command");
        assert_eq!(receipt.state, CommandState::RevokedBeforeStart);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn grant_renewal_replays_same_owner_command_without_second_execution() {
        let root = TestRoot::new("renewal-replay");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 5).await;
        let fake = FakeCoordinator::held();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD4),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let issuer = PrincipalIssuer::local_only([0xB2; 32]);
        let old = issuer
            .issue_test_remote([1; 16], [2; 16], 7, [3; 32])
            .expect("issue old grant");
        let renewed = issuer
            .issue_test_remote([1; 16], [2; 16], 8, [3; 32])
            .expect("issue renewed grant");
        let first = submit(
            &registry,
            conversation.conversation_id,
            &old,
            "lost-receipt",
            "same payload",
        )
        .await;
        let replay = submit(
            &registry,
            conversation.conversation_id,
            &renewed,
            "lost-receipt",
            "same payload",
        )
        .await;
        assert!(matches!(first, PromptAcceptResult::Accepted { .. }));
        assert!(matches!(replay, PromptAcceptResult::Replayed { .. }));
        assert_eq!(command(&first).command_id, command(&replay).command_id);
        fake.wait_for_starts(1).await;
        fake.release(command(&first).command_id);
        fake.wait_for_completions(1).await;
        assert_eq!(fake.starts().len(), 1);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn accept_commit_unknown_exact_retry_requeues_the_persisted_command_once() {
        let root = TestRoot::new("accept-reply-loss");
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("actor test StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.0.join("runtime.db"))
                .with_fault_injector(Arc::new(FailAcceptReplyOnce(AtomicBool::new(true)))),
            kek,
        )
        .await
        .expect("open actor test store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 8).await;
        let fake = FakeCoordinator::held();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD7),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(8);

        let first = registry
            .submit_prompt(
                conversation.conversation_id,
                principal.clone(),
                principal.try_enter().expect("first prompt guard"),
                "reply-loss".to_owned(),
                b"persist exactly once".to_vec(),
            )
            .await
            .expect_err("post-commit reply loss is unknown");
        assert!(matches!(
            first,
            ConversationError::Store(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::AcceptCommand
            })
        ));
        let replay = submit(
            &registry,
            conversation.conversation_id,
            &principal,
            "reply-loss",
            "persist exactly once",
        )
        .await;
        assert!(matches!(replay, PromptAcceptResult::Replayed { .. }));
        let command = command(&replay);
        fake.wait_for_starts(1).await;
        fake.release(command.command_id);
        fake.wait_for_completions(1).await;
        assert_eq!(fake.starts().len(), 1);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn cancel_during_prepare_never_mints_or_consumes_release_capability() {
        let root = TestRoot::new("cancel-before-release");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 7).await;
        let fake = FakeCoordinator::blocked_prepare();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD6),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(7);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "cancel-prepare",
                "cancel before release",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        let turn_id = fake.starts()[0].turn_id;
        assert_eq!(
            registry
                .cancel_active(
                    conversation.conversation_id,
                    turn_id,
                    principal.try_enter().expect("cancel guard"),
                )
                .await
                .expect("cancel during prepare"),
            ActiveCancelResult::Requested
        );
        fake.allow_prepare();
        wait_until(|| fake.cancel_count(command.command_id) == 1 && fake.active() == 0).await;
        assert_eq!(
            fake.release_count(),
            0,
            "cancel before release must not authorize gate release"
        );
        let receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: command.command_id,
                },
            })
            .await
            .expect("query prepared cancellation");
        assert_eq!(receipt.state, CommandState::Canceled);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn cancel_after_prepared_proceed_but_before_authorize_stays_pre_release() {
        let root = TestRoot::new("cancel-between-prepare-and-authorize");
        let keys = MemoryKeyStore::new();
        let blocker = Arc::new(BlockFenceCommit::new());
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("actor test StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.0.join("runtime.db")).with_fault_injector(blocker.clone()),
            kek,
        )
        .await
        .expect("open actor test store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 13).await;
        let fake = FakeCoordinator::held();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xDC),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(13);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "cancel-race",
                "cancel after prepared ack",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_until(|| blocker.entered.load(Ordering::SeqCst)).await;
        let turn_id = fake.starts()[0].turn_id;
        assert_eq!(
            registry
                .cancel_active(
                    conversation.conversation_id,
                    turn_id,
                    principal.try_enter().expect("cancel race guard"),
                )
                .await
                .expect("cancel wins before authorize"),
            ActiveCancelResult::Requested
        );
        blocker.release();
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &principal,
            CommandState::Canceled,
        )
        .await;
        assert_eq!(fake.release_count(), 0);
        assert_eq!(fake.cancel_count(command.command_id), 1);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn shutdown_waits_for_prepared_control_to_fence_instead_of_detaching_it() {
        let root = TestRoot::new("shutdown-during-prepare");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 20).await;
        let fake = FakeCoordinator::blocked_prepare();
        let registry = Arc::new(
            ConversationRegistry::new(
                store.clone(),
                Arc::new(fake.clone()),
                runtime_id(RuntimeIdKind::DaemonBoot, 0xE0),
                1,
            )
            .expect("registry"),
        );
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(16);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "shutdown-prepare",
                "shutdown while prepare blocked",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        let prompt_ingress = registry
            .handle(conversation.conversation_id)
            .await
            .expect("actor handle")
            .prompt_ingress;
        let shutting_registry = registry.clone();
        let shutdown = tokio::spawn(async move { shutting_registry.shutdown().await });
        wait_until(|| !*prompt_ingress.open.borrow()).await;
        fake.allow_prepare();
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("shutdown must not wait for hard deadline")
            .expect("shutdown task")
            .expect("shutdown actors");
        assert_eq!(fake.cancel_count(command.command_id), 1);
        assert_eq!(fake.release_count(), 0);
        assert_eq!(fake.active(), 0);
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &principal,
            CommandState::Canceled,
        )
        .await;

        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn shutdown_drains_an_accept_already_dispatched_to_the_store() {
        let root = TestRoot::new("shutdown-admission-drain");
        let keys = MemoryKeyStore::new();
        let blocker = Arc::new(BlockNextAcceptCommit::new());
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("actor test StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.0.join("runtime.db")).with_fault_injector(blocker.clone()),
            kek,
        )
        .await
        .expect("open actor test store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 21).await;
        let registry = Arc::new(
            ConversationRegistry::new(
                store.clone(),
                Arc::new(DisabledExecutionCoordinator),
                runtime_id(RuntimeIdKind::DaemonBoot, 0xE1),
                1,
            )
            .expect("registry"),
        );
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        let prompt_ingress = registry
            .handle(conversation.conversation_id)
            .await
            .expect("actor handle")
            .prompt_ingress;
        let principal = local_principal(17);
        blocker.arm();
        let submitting_registry = registry.clone();
        let submitting_principal = principal.clone();
        let submit = tokio::spawn(async move {
            submitting_registry
                .submit_prompt(
                    conversation.conversation_id,
                    submitting_principal.clone(),
                    submitting_principal.try_enter().expect("prompt guard"),
                    "shutdown-inflight".to_owned(),
                    b"must be drained".to_vec(),
                )
                .await
        });
        wait_until(|| blocker.entered.load(Ordering::SeqCst)).await;
        let shutting_registry = registry.clone();
        let shutdown = tokio::spawn(async move { shutting_registry.shutdown().await });
        wait_until(|| !*prompt_ingress.open.borrow()).await;
        blocker.release();
        let admitted = tokio::time::timeout(Duration::from_secs(1), submit)
            .await
            .expect("in-flight admission reply must drain")
            .expect("submit task")
            .expect("committed admission reply");
        let command = command(&admitted);
        shutdown
            .await
            .expect("shutdown task")
            .expect("shutdown actors");
        let receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: command.conversation_id,
                    command_id: command.command_id,
                },
            })
            .await
            .expect("query drained admission");
        assert_eq!(receipt.state, CommandState::Accepted);

        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn recovery_blocked_drains_an_accept_already_dispatched_to_the_store() {
        let root = TestRoot::new("recovery-admission-drain");
        let keys = MemoryKeyStore::new();
        let blocker = Arc::new(BlockNextAcceptCommit::new());
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("actor test StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.0.join("runtime.db")).with_fault_injector(blocker.clone()),
            kek,
        )
        .await
        .expect("open actor test store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 22).await;
        let fake = FakeCoordinator::blocked_panicking();
        let registry = Arc::new(
            ConversationRegistry::new(
                store.clone(),
                Arc::new(fake.clone()),
                runtime_id(RuntimeIdKind::DaemonBoot, 0xE2),
                1,
            )
            .expect("registry"),
        );
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(18);
        let _active = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "panics",
                "panics after prepare",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        let prompt_ingress = registry
            .handle(conversation.conversation_id)
            .await
            .expect("actor handle")
            .prompt_ingress;
        blocker.arm();
        let submitting_registry = registry.clone();
        let submitting_principal = principal.clone();
        let submit = tokio::spawn(async move {
            submitting_registry
                .submit_prompt(
                    conversation.conversation_id,
                    submitting_principal.clone(),
                    submitting_principal.try_enter().expect("prompt guard"),
                    "inflight-while-panic".to_owned(),
                    b"must be drained after recovery block".to_vec(),
                )
                .await
        });
        wait_until(|| blocker.entered.load(Ordering::SeqCst)).await;
        fake.allow_prepare();
        wait_until(|| fake.active() == 0).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !*prompt_ingress.open.borrow(),
            "runner exit must close prompt ingress before admission completes"
        );
        blocker.release();
        let admitted = tokio::time::timeout(Duration::from_secs(1), submit)
            .await
            .expect("recovery-blocked admission reply must drain")
            .expect("submit task")
            .expect("committed admission reply");
        let command = command(&admitted);
        let receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: command.conversation_id,
                    command_id: command.command_id,
                },
            })
            .await
            .expect("query drained admission");
        assert_eq!(receipt.state, CommandState::Accepted);
        assert_eq!(fake.starts().len(), 1);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn completion_error_fences_group_before_writing_interrupted() {
        let root = TestRoot::new("completion-error-fenced");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 9).await;
        let fake = FakeCoordinator::completion_error(false);
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD8),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(9);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "completion-error",
                "completion error",
            )
            .await,
        );
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &principal,
            CommandState::Interrupted,
        )
        .await;
        assert_eq!(fake.cancel_count(command.command_id), 1);
        assert_eq!(fake.active(), 0, "Interrupted requires a reaped group");

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn completion_error_without_fence_proof_blocks_recovery_and_keeps_started() {
        let root = TestRoot::new("completion-error-unfenced");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 10).await;
        let fake = FakeCoordinator::completion_error(true);
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD9),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(10);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "completion-error-unfenced",
                "must block",
            )
            .await,
        );
        wait_until(|| fake.cancel_count(command.command_id) == 1).await;
        let receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: command.command_id,
                },
            })
            .await
            .expect("query blocked receipt");
        assert_eq!(receipt.state, CommandState::Started);
        assert!(matches!(
            registry
                .submit_prompt(
                    conversation.conversation_id,
                    principal.clone(),
                    principal.try_enter().expect("second prompt guard"),
                    "must-not-start".to_owned(),
                    b"must not start".to_vec(),
                )
                .await,
            Err(ConversationError::ActorUnavailable)
        ));
        assert_eq!(fake.starts().len(), 1);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn release_error_after_authorization_fences_then_writes_interrupted() {
        let root = TestRoot::new("release-error-fenced");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 11).await;
        let fake = FakeCoordinator::release_error(false);
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xDA),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(11);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "release-error",
                "release error",
            )
            .await,
        );
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &principal,
            CommandState::Interrupted,
        )
        .await;
        assert_eq!(fake.release_count(), 1);
        assert_eq!(fake.cancel_count(command.command_id), 1);
        assert_eq!(fake.active(), 0);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn panicked_runner_is_supervised_into_recovery_blocked() {
        let root = TestRoot::new("runner-panic");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 12).await;
        let fake = FakeCoordinator::panicking();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xDB),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(12);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "panic",
                "panic runner",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_until(|| fake.active() == 0).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        let receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: command.command_id,
                },
            })
            .await
            .expect("query panicked runner receipt");
        assert_eq!(receipt.state, CommandState::Started);
        assert!(matches!(
            registry
                .submit_prompt(
                    conversation.conversation_id,
                    principal.clone(),
                    principal.try_enter().expect("post-panic guard"),
                    "post-panic".to_owned(),
                    b"must stay closed".to_vec(),
                )
                .await,
            Err(ConversationError::ActorUnavailable)
        ));

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn supervisor_reports_even_a_normal_runner_exit_without_terminal_event() {
        let command_id = runtime_id(RuntimeIdKind::Command, 0xEE);
        let (runner_tx, mut runner_rx) = mpsc::channel(1);
        let execution_task = AbortOnDropTask::new(tokio::spawn(async {}));
        supervise_execution_task(command_id, execution_task, runner_tx).await;
        assert!(matches!(
            runner_rx.recv().await,
            Some(RunnerEvent::RunnerExited { command_id: observed }) if observed == command_id
        ));
    }

    #[tokio::test]
    async fn disabled_production_coordinator_leaves_accepted_work_durable_and_unstarted() {
        let root = TestRoot::new("disabled-gate");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 6).await;
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(DisabledExecutionCoordinator),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xD5),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(6);
        let accepted = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "gate-disabled",
                "must remain accepted",
            )
            .await,
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
        let receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: accepted.command_id,
                },
            })
            .await
            .expect("query disabled gate command");
        assert_eq!(receipt.state, CommandState::Accepted);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn expired_queue_head_is_normal_terminal_and_next_command_starts() {
        const QUEUE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
        let root = TestRoot::new("expired-head");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(10);
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("actor test StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.0.join("runtime.db")).with_clock(clock.clone()),
            kek,
        )
        .await
        .expect("open actor test store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 19).await;
        let fake = FakeCoordinator::automatic();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xDF),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        let principal = local_principal(15);
        let expired = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "expires-first",
                "expires first",
            )
            .await,
        );
        clock.set(20);
        let successor = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "survives",
                "survives",
            )
            .await,
        );
        clock.set(10 + QUEUE_TTL_MS);
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        fake.wait_for_starts(1).await;
        fake.wait_for_completions(1).await;
        assert_eq!(fake.starts()[0].command_id, successor.command_id);
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            expired.command_id,
            &principal,
            CommandState::Expired,
        )
        .await;
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            successor.command_id,
            &principal,
            CommandState::Completed,
        )
        .await;

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn actor_limit_rejects_before_spawning_a_third_actor() {
        let root = TestRoot::new("actor-limit");
        let store = root.open().await;
        finish_recovery(&store).await;
        let first = create_conversation(&store, 14).await;
        let second = create_conversation(&store, 15).await;
        let rejected = create_conversation(&store, 16).await;
        let registry = ConversationRegistry::with_actor_limit(
            store.clone(),
            Arc::new(DisabledExecutionCoordinator),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xDD),
            1,
            2,
        )
        .expect("limited registry");
        registry
            .install(first, Vec::new())
            .await
            .expect("first actor");
        registry
            .install(second, Vec::new())
            .await
            .expect("second actor");
        assert!(matches!(
            registry.install(rejected, Vec::new()).await,
            Err(ConversationError::ActorLimit)
        ));
        assert_eq!(registry.len().await, 2);

        registry.shutdown().await.expect("shutdown actors");
        assert_eq!(registry.len().await, 0);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn multi_actor_shutdown_uses_one_deadline_and_starts_no_queued_successor() {
        let root = TestRoot::new("global-shutdown-deadline");
        let store = root.open().await;
        finish_recovery(&store).await;
        let left = create_conversation(&store, 17).await;
        let right = create_conversation(&store, 18).await;
        let fake = FakeCoordinator::blocked_prepare();
        let registry = ConversationRegistry::with_limits(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xDE),
            2,
            4,
            Duration::from_millis(75),
        )
        .expect("short-deadline registry");
        registry
            .install(left.clone(), Vec::new())
            .await
            .expect("left actor");
        registry
            .install(right.clone(), Vec::new())
            .await
            .expect("right actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(14);
        let _left_active =
            command(&submit(&registry, left.conversation_id, &principal, "la", "la").await);
        let left_queued =
            command(&submit(&registry, left.conversation_id, &principal, "lq", "lq").await);
        let _right_active =
            command(&submit(&registry, right.conversation_id, &principal, "ra", "ra").await);
        let right_queued =
            command(&submit(&registry, right.conversation_id, &principal, "rq", "rq").await);
        fake.wait_for_starts(2).await;

        let started_at = std::time::Instant::now();
        registry.shutdown().await.expect("global shutdown");
        assert!(
            started_at.elapsed() < Duration::from_millis(200),
            "two actors must share one shutdown deadline"
        );
        assert_eq!(fake.starts().len(), 2);
        assert_eq!(fake.active(), 0, "forced ownership drop reaps both tasks");
        for (conversation_id, command_id) in [
            (left.conversation_id, left_queued.command_id),
            (right.conversation_id, right_queued.command_id),
        ] {
            let receipt = store
                .query_command_receipt(QueryCommandReceipt {
                    expected_owner: principal.idempotency_owner(),
                    selector: CommandReceiptSelector::Command {
                        conversation_id,
                        command_id,
                    },
                })
                .await
                .expect("query queued successor");
            assert_eq!(receipt.state, CommandState::Accepted);
        }

        store.shutdown().await.expect("shutdown store");
    }

    #[test]
    fn fake_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<FakeCoordinator>();
        assert_send_sync::<ConversationRegistry>();
        let _ = OnceLock::<FakeCoordinator>::new();
        let _ = FakeCoordinator::automatic();
    }
}
