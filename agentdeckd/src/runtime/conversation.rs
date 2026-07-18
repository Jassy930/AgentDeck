//! 每个 conversation 一个 durable journal actor。
//!
//! prompt mailbox 只负责把请求提交到 SQLite；真正顺序由 store 分配的
//! `command_seq` 决定。control mailbox 独立且优先，actor 不读取 transport、
//! 不 await connection writer。不同 actor 可并行，同一 actor 最多一个 active turn。

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use agentdeck_protocol::runtime::identity::{ApprovalId, EntityId, ItemId};
use agentdeck_protocol::runtime::{
    ApprovalDeliveryState, ApprovalReceipt, ClaudeCodeConversationConfiguration,
    CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    AgentKind, ClaudeCodePermissionMode, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode,
};
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};

use super::approval::{
    ApprovalBackoff, ApprovalDeliveryJournal, ApprovalSleeper, ApprovalWorkerResult,
    FixedApprovalBackoff, SharedApprovalDelivery, TokioApprovalSleeper, run_approval_deadline,
    run_approval_delivery_round,
};
use super::connection::{
    ApprovalAuthorizationGuard, AuthenticatedPrincipal, AuthorizationGuard, PrincipalAccessError,
    PrincipalAuthorizationKey,
};
use super::execution::{
    EXECUTION_CANCEL_FENCE_BUDGET, ExecutionReleasePermit, RuntimeCancelDisposition,
    RuntimeCompletionFuture, RuntimeExecutionCompletion, RuntimeExecutionContext,
    RuntimeExecutionControl, RuntimeExecutionCoordinator, RuntimeExecutionError,
    RuntimeExecutionEvent, RuntimeExecutionEventReceiver,
};
use super::model::{
    ApprovalMutationOutcome, ApprovalRecord, ApprovalState, ClaimApproval, ExpireApproval,
    RegisterApproval, RegisterApprovalOutcome, RetryApprovalDelivery,
};
use super::recovery::RecoveryReadyPermit;
use super::store::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, AuthorizeExecutionRelease,
    AuthorizedAcceptOutcome, CommandExecutionConfiguration, CommandRecord, CommandState,
    CommandTerminal, CompleteCommand, ConversationRecord, ExecutionFence, ExecutionFenceRecord,
    MarkConversationRecoveryBlocked, RecoveryBlockedCommandBinding, RecoveryFenceBinding,
    RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeStoreError, RuntimeStoreHandle,
    StartCommand, StartOutcome, StartedBeforeReleaseTermination, SystemRuntimeClock,
    TerminateAcceptedCommand, TerminateAcceptedOutcome, TerminateStartedBeforeRelease,
    TerminateStartedBeforeReleaseOutcome,
};
use crate::agent::{AdapterEvent, AdapterItemKey};

const PROMPT_MAILBOX_CAPACITY: usize = 32;
const CONTROL_MAILBOX_CAPACITY: usize = 64;
const RUNNER_MAILBOX_CAPACITY: usize = 8;
const EXECUTION_NONCE_BYTES: usize = 32;
const ACTOR_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
// 威胁场景：vendor/tool 忽略 TERM 时，若 actor 的外层 timeout 不覆盖完整
// TERM grace -> KILL grace -> readback，cancel 会在发出 KILL 前被取消并错误进入
// RecoveryBlocked。保留两秒调度/readback 余量，并用 execution 层预算防止两处漂移。
const CONTROL_CANCEL_TIMEOUT: Duration = Duration::from_secs(6);
const _: () = assert!(CONTROL_CANCEL_TIMEOUT.as_secs() > EXECUTION_CANCEL_FENCE_BUDGET.as_secs());
// 威胁场景：approval 已 durable Expired 且 exact group 已 fenced，但 driver/forwarder/
// terminal pipeline 因内部故障不返回；若没有有界监督，当前 actor 与后续 Accepted queue
// 会再次无限占用。watchdog 只把该 conversation fail-close，不伪造 vendor decision。
const APPROVAL_EXPIRY_TERMINAL_GRACE: Duration = Duration::from_secs(10);
const _: () = assert!(APPROVAL_EXPIRY_TERMINAL_GRACE.as_secs() > CONTROL_CANCEL_TIMEOUT.as_secs());
const CONTROL_PRIORITY_BURST: usize = 8;
const MAX_RUNTIME_CONVERSATION_ACTORS: usize = 1024;
const MAX_ADAPTER_ITEM_KEYS_PER_TURN: usize = 10_000;

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
    approval_clock: Arc<dyn super::store::RuntimeClock>,
    approval_sleeper: Arc<dyn ApprovalSleeper>,
    approval_backoff: Arc<dyn ApprovalBackoff>,
    approval_expiry_terminal_grace: Duration,
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
            approval_clock: Arc::new(SystemRuntimeClock),
            approval_sleeper: Arc::new(TokioApprovalSleeper),
            approval_backoff: Arc::new(FixedApprovalBackoff),
            approval_expiry_terminal_grace: APPROVAL_EXPIRY_TERMINAL_GRACE,
            actor_limit,
            shutdown_grace,
        })
    }

    #[cfg(test)]
    fn with_approval_runtime(
        mut self,
        clock: Arc<dyn super::store::RuntimeClock>,
        sleeper: Arc<dyn ApprovalSleeper>,
        backoff: Arc<dyn ApprovalBackoff>,
    ) -> Self {
        self.approval_clock = clock;
        self.approval_sleeper = sleeper;
        self.approval_backoff = backoff;
        self
    }

    #[cfg(test)]
    fn with_approval_expiry_terminal_grace(mut self, grace: Duration) -> Self {
        assert!(
            !grace.is_zero(),
            "approval expiry watchdog grace must be positive"
        );
        self.approval_expiry_terminal_grace = grace;
        self
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
            approval_clock: self.approval_clock.clone(),
            approval_sleeper: self.approval_sleeper.clone(),
            approval_backoff: self.approval_backoff.clone(),
            approval_expiry_terminal_grace: self.approval_expiry_terminal_grace,
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
                    provenance: QueuedCommandProvenance::StartupRecovery,
                })
                .collect(),
            active: None,
            approval_deliveries: HashMap::new(),
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
        expected_configuration_revision: u64,
        payload: Vec<u8>,
    ) -> Result<PromptAcceptResult, ConversationError> {
        let handle = self.handle(conversation_id).await?;
        let (reply, result) = oneshot::channel();
        handle
            .prompt_ingress
            .try_send(PromptCommand {
                principal,
                authorization_guard,
                idempotency_key,
                expected_configuration_revision,
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

    pub(crate) async fn resolve_approval(
        &self,
        conversation_id: RuntimeId,
        turn_id: RuntimeId,
        approval_id: RuntimeId,
        decision: agentdeck_protocol::ActionDecision,
        authorization_guard: ApprovalAuthorizationGuard,
    ) -> Result<ApprovalReceipt, ConversationError> {
        authorization_guard.require_resolve()?;
        let handle = self.handle(conversation_id).await?;
        let claimant_binding = authorization_guard.claimant_binding();
        let (reply, result) = oneshot::channel();
        handle
            .control_tx
            .try_send(ControlCommand::ResolveApproval {
                input: ClaimApproval {
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision,
                    claimant_binding,
                },
                _authorization_guard: authorization_guard,
                reply,
            })
            .map_err(map_mailbox_error)?;
        result
            .await
            .map_err(|_| ConversationError::ActorUnavailable)?
    }

    pub(crate) async fn retry_approval(
        &self,
        conversation_id: RuntimeId,
        approval_id: RuntimeId,
        authorization_guard: ApprovalAuthorizationGuard,
    ) -> Result<ApprovalReceipt, ConversationError> {
        authorization_guard.require_retry()?;
        let handle = self.handle(conversation_id).await?;
        let (reply, result) = oneshot::channel();
        handle
            .control_tx
            .try_send(ControlCommand::RetryApproval {
                input: RetryApprovalDelivery {
                    conversation_id,
                    approval_id,
                },
                _authorization_guard: authorization_guard,
                reply,
            })
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
    /// 获取 actor registry 锁可能 await，但锁取得后 `publish_core_ready` 与 retained
    /// scheduling gate 在同一次不可取消 poll 中依次发布；actor 绝不能先于 Core READY
    /// 被唤醒。
    pub(crate) async fn publish_ready_and_enable_scheduling(
        &self,
        _permit: &RecoveryReadyPermit,
        publish_core_ready: impl FnOnce(),
    ) -> Result<(), ConversationError> {
        let actors = self.actors.lock().await;
        if self.adapter_permits.is_closed() {
            return Err(ConversationError::ActorUnavailable);
        }
        publish_core_ready();
        self.scheduling_gate.send_replace(true);
        drop(actors);
        Ok(())
    }

    #[cfg(test)]
    async fn enable_scheduling(&self) -> Result<(), ConversationError> {
        self.enable_scheduling_inner().await
    }

    #[cfg(test)]
    async fn enable_scheduling_inner(&self) -> Result<(), ConversationError> {
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
    authorization_guard: AuthorizationGuard,
    idempotency_key: String,
    expected_configuration_revision: u64,
    payload: Vec<u8>,
    reply: oneshot::Sender<Result<PromptAcceptResult, ConversationError>>,
}

struct PromptAdmission {
    principal: AuthenticatedPrincipal,
    authorization_key: PrincipalAuthorizationKey,
    outcome: Result<AuthorizedAcceptOutcome, RuntimeStoreError>,
    reply: oneshot::Sender<Result<PromptAcceptResult, ConversationError>>,
}

enum ControlCommand {
    ResolveApproval {
        input: ClaimApproval,
        _authorization_guard: ApprovalAuthorizationGuard,
        reply: oneshot::Sender<Result<ApprovalReceipt, ConversationError>>,
    },
    RetryApproval {
        input: RetryApprovalDelivery,
        _authorization_guard: ApprovalAuthorizationGuard,
        reply: oneshot::Sender<Result<ApprovalReceipt, ConversationError>>,
    },
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
    provenance: QueuedCommandProvenance,
}

/// command 进入 actor queue 的可信来源。只有 authenticated 两遍 startup
/// reconciliation 安装的 command 才能取得 `StartupRecovery`；live accept 与
/// idempotent replay 永远保持 `Live`，不能借 revision zero 触发迁移默认值。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueuedCommandProvenance {
    Live,
    StartupRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartFailureDisposition {
    Finished,
    RecoveryBlocked,
}

struct ActiveCommand {
    command: CommandRecord,
    authorization_key: Option<PrincipalAuthorizationKey>,
    turn_id: Option<RuntimeId>,
    recovery_binding: RecoveryBlockedCommandBinding,
    control: Option<Arc<dyn RuntimeExecutionControl>>,
    execution_gate: Arc<Mutex<ActiveExecutionGate>>,
    approval_expiry_watchdog: Option<AbortOnDropTask<()>>,
    task: AbortOnDropTask<()>,
}

struct ApprovalRoute {
    turn_id: RuntimeId,
    delivery: SharedApprovalDelivery,
    deadline_task: Option<AbortOnDropTask<()>>,
    delivery_task: Option<AbortOnDropTask<()>>,
    delivery_generation: u64,
}

#[derive(Default)]
struct ActiveExecutionGate {
    cancel_requested: bool,
    cancel_fenced: bool,
    user_cancel_accepted: bool,
    user_cancel_fenced: bool,
    completion_won: bool,
    release_authorized: bool,
    claimed_terminal: Option<CommandTerminal>,
}

enum RunnerEvent {
    ApprovalRequested {
        command_id: RuntimeId,
        turn_id: RuntimeId,
        request: agentdeck_protocol::ActionRequest,
        delivery: SharedApprovalDelivery,
        acknowledged: oneshot::Sender<Result<(), ConversationError>>,
    },
    ApprovalTaskFinished {
        approval_id: RuntimeId,
        task_kind: ApprovalTaskKind,
        generation: u64,
        result: ApprovalWorkerResult,
    },
    ApprovalExpiryTerminalWatchdog {
        command_id: RuntimeId,
        turn_id: RuntimeId,
    },
    Started {
        command_id: RuntimeId,
        turn_id: RuntimeId,
        daemon_boot_id: RuntimeId,
        execution_nonce: Vec<u8>,
        acknowledged: oneshot::Sender<()>,
    },
    FenceUpdated {
        command_id: RuntimeId,
        turn_id: RuntimeId,
        fence: ExecutionFenceRecord,
        acknowledged: oneshot::Sender<Result<(), RuntimeExecutionError>>,
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
enum ApprovalTaskKind {
    Deadline,
    Delivery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovalTaskCompletionDisposition {
    IgnoreStale,
    RecoveryBlocked,
    Continue,
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
    approval_clock: Arc<dyn super::store::RuntimeClock>,
    approval_sleeper: Arc<dyn ApprovalSleeper>,
    approval_backoff: Arc<dyn ApprovalBackoff>,
    approval_expiry_terminal_grace: Duration,
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
    approval_deliveries: HashMap<RuntimeId, ApprovalRoute>,
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
                event = self.runner_rx.recv(), if self.active.is_some() || !self.approval_deliveries.is_empty() => {
                    control_burst = 0;
                    match event {
                        Some(event) => self.handle_runner_event(event).await,
                        None => {
                            self.enter_recovery_blocked_and_stop_approvals().await;
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
                            self.enter_recovery_blocked_and_stop_approvals().await;
                        }
                    },
                },
                changed = self.scheduling_gate.changed() => {
                    control_burst = 0;
                    if changed.is_err() {
                        self.enter_recovery_blocked_and_stop_approvals().await;
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
        let PromptAdmission {
            principal,
            authorization_key,
            outcome,
            reply,
        } = admission;
        match outcome {
            Ok(authorized) => {
                let (outcome, authorization_guard) = authorized.into_parts();
                let reply_outcome = match outcome {
                    AcceptOutcome::Accepted {
                        command,
                        queue_position,
                    } => {
                        let queued = QueuedCommand {
                            command: command.clone(),
                            authorization_key: Some(authorization_key),
                            principal: Some(principal),
                            provenance: QueuedCommandProvenance::Live,
                        };
                        let position = self
                            .pending
                            .iter()
                            .position(|existing| {
                                existing.command.command_seq > queued.command.command_seq
                            })
                            .unwrap_or(self.pending.len());
                        self.pending.insert(position, queued);
                        Ok(PromptAcceptResult::Accepted {
                            command,
                            queue_position,
                        })
                    }
                    AcceptOutcome::Replayed { command } => {
                        if command.state == CommandState::Accepted
                            && !self.pending.iter().any(|queued| {
                                queued.command.command_id == command.command_id
                                    || queued.command.command_seq == command.command_seq
                            })
                            && self.active.as_ref().is_none_or(|active| {
                                active.command.command_id != command.command_id
                            })
                        {
                            let queued = QueuedCommand {
                                command: command.clone(),
                                authorization_key: Some(authorization_key),
                                principal: Some(principal),
                                provenance: QueuedCommandProvenance::Live,
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
                };
                // Store 把 guard 随 durable success 返还；actor 完成 queue registration
                // 与 caller reply 后才允许 revoke 观察到 quiesced。
                let _ = reply.send(reply_outcome);
                drop(authorization_guard);
            }
            Err(error) => {
                let _ = reply.send(Err(ConversationError::Store(error)));
            }
        }
    }

    async fn handle_control(&mut self, command: ControlCommand) {
        match command {
            ControlCommand::ResolveApproval {
                input,
                _authorization_guard,
                reply,
            } => {
                let outcome = self
                    .resolve_approval_control(input, &_authorization_guard)
                    .await;
                // Explicit binding keeps the shared lease alive through first-wins CAS COMMIT and
                // exact receipt mapping. Adapter delivery is never awaited in this handler.
                drop(_authorization_guard);
                let _ = reply.send(outcome);
            }
            ControlCommand::RetryApproval {
                input,
                _authorization_guard,
                reply,
            } => {
                let outcome = self.retry_approval_control(input).await;
                // Retry permission capability likewise covers the exact round-transition COMMIT;
                // the spawned daemon worker is independent of the client/connection afterwards.
                drop(_authorization_guard);
                let _ = reply.send(outcome);
            }
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
                        request_user_active_cancel(&active.execution_gate, active.control.clone())
                            .await
                            .map(|accepted| {
                                if accepted {
                                    ActiveCancelResult::Requested
                                } else {
                                    ActiveCancelResult::Stale
                                }
                            })
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

    /// 威胁场景：actor 已遇到无法确认 durable completion 或 process fencing 的 fatal
    /// failure，而一个已派发给 SQLite worker 的 Accept 正阻塞 durable lifecycle mutation；
    /// 若等待 store 后才关入口，新 prompt 仍可在未知 execution outcome 下进入队列。因此先
    /// 同步关闭进程内 admission，再 exact 持久化当前 command/turn；持久化失败则升级为
    /// actor shutdown，不能重新开放入口。
    async fn enter_recovery_blocked(&mut self) {
        self.recovery_blocked = true;
        self.prompt_ingress.close();
        let input = MarkConversationRecoveryBlocked {
            conversation_id: self.conversation.conversation_id,
            expected_command: self
                .active
                .as_ref()
                .map(|active| active.recovery_binding.clone()),
        };
        match mark_conversation_recovery_blocked_exact(&self.store, input).await {
            Ok(conversation) => self.conversation = conversation,
            Err(_) => self.begin_shutdown().await,
        }
    }

    async fn enter_recovery_blocked_and_stop_approvals(&mut self) {
        let turn_id = self.active.as_ref().and_then(|active| active.turn_id);
        self.enter_recovery_blocked().await;
        if let Some(turn_id) = turn_id {
            // RecoveryBlocked 尚无 process fence 证据，不能伪造 durable Expired；但必须先
            // 移除 bound route 并停止所有 adapter delivery，防止未知 execution 继续副作用。
            self.finish_approval_turn(turn_id).await;
        }
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
        let provenance = queued.provenance;
        let execution_gate = Arc::new(Mutex::new(ActiveExecutionGate::default()));
        let execution_task = AbortOnDropTask::new(tokio::spawn(execute_command(
            self.conversation.clone(),
            command.clone(),
            principal,
            provenance,
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
            recovery_binding: RecoveryBlockedCommandBinding::Accepted {
                command_id: command.command_id,
            },
            command,
            authorization_key: queued.authorization_key,
            turn_id: None,
            control: None,
            execution_gate,
            approval_expiry_watchdog: None,
            task,
        });
    }

    async fn handle_runner_event(&mut self, event: RunnerEvent) {
        match event {
            RunnerEvent::ApprovalRequested {
                command_id,
                turn_id,
                request,
                delivery,
                acknowledged,
            } => {
                let result = self
                    .register_action_request(command_id, turn_id, request, delivery)
                    .await;
                if result.is_err() {
                    if let Some(active) = self.active.as_mut().filter(|active| {
                        active.command.command_id == command_id && active.turn_id == Some(turn_id)
                    }) {
                        let _ =
                            request_active_cancel(&active.execution_gate, active.control.clone())
                                .await;
                    }
                    self.enter_recovery_blocked_and_stop_approvals().await;
                }
                let _ = acknowledged.send(result);
            }
            RunnerEvent::ApprovalTaskFinished {
                approval_id,
                task_kind,
                generation,
                result,
            } => {
                self.finish_approval_task(approval_id, task_kind, generation, result)
                    .await;
            }
            RunnerEvent::ApprovalExpiryTerminalWatchdog {
                command_id,
                turn_id,
            } => {
                let exact_active = self.active.as_ref().is_some_and(|active| {
                    active.command.command_id == command_id && active.turn_id == Some(turn_id)
                });
                if exact_active {
                    self.enter_recovery_blocked().await;
                    self.finish_approval_turn(turn_id).await;
                    if let Some(mut active) = self.active.take() {
                        stop_approval_expiry_watchdog(&mut active).await;
                        active.task.abort();
                        let _ = active.task.join().await;
                    }
                }
            }
            RunnerEvent::Started {
                command_id,
                turn_id,
                daemon_boot_id,
                execution_nonce,
                acknowledged,
            } => {
                if let Some(active) = self
                    .active
                    .as_mut()
                    .filter(|active| active.command.command_id == command_id)
                {
                    active.turn_id = Some(turn_id);
                    active.recovery_binding = RecoveryBlockedCommandBinding::Started {
                        command_id,
                        turn_id,
                        daemon_boot_id,
                        execution_nonce,
                        fence: None,
                    };
                    let _ = acknowledged.send(());
                }
            }
            RunnerEvent::FenceUpdated {
                command_id,
                turn_id,
                fence,
                acknowledged,
            } => {
                let result = if let Some(active) = self.active.as_mut().filter(|active| {
                    active.command.command_id == command_id && active.turn_id == Some(turn_id)
                }) {
                    match &mut active.recovery_binding {
                        RecoveryBlockedCommandBinding::Started {
                            command_id: bound_command_id,
                            turn_id: bound_turn_id,
                            daemon_boot_id,
                            execution_nonce,
                            fence: bound_fence,
                        } if *bound_command_id == command_id
                            && *bound_turn_id == turn_id
                            && *daemon_boot_id == fence.daemon_boot_id
                            && *execution_nonce == fence.execution_nonce =>
                        {
                            *bound_fence =
                                Some(Box::new(RecoveryFenceBinding::from_record(&fence)));
                            Ok(())
                        }
                        _ => Err(RuntimeExecutionError::ReleaseAuthorizationInvalid),
                    }
                } else {
                    Err(RuntimeExecutionError::ReleaseAuthorizationInvalid)
                };
                let _ = acknowledged.send(result);
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
                    stop_approval_expiry_watchdog(&mut active).await;
                    if let Some(turn_id) = active.turn_id {
                        // CompleteCommand 的 safety transaction 已先把所有 non-Applied
                        // approvals durable Expired；此处才取消/等待 daemon workers。
                        self.finish_approval_turn(turn_id).await;
                    }
                    let _ = active.task.join().await;
                }
            }
            RunnerEvent::RecoveryBlocked { command_id } => {
                if self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.command.command_id == command_id)
                {
                    let turn_id = self.active.as_ref().and_then(|active| active.turn_id);
                    self.enter_recovery_blocked().await;
                    if let Some(turn_id) = turn_id {
                        self.finish_approval_turn(turn_id).await;
                    }
                    if let Some(active) = self.active.take() {
                        let mut active = active;
                        stop_approval_expiry_watchdog(&mut active).await;
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
                    let turn_id = self.active.as_ref().and_then(|active| active.turn_id);
                    self.enter_recovery_blocked().await;
                    if let Some(turn_id) = turn_id {
                        self.finish_approval_turn(turn_id).await;
                    }
                    if let Some(mut active) = self.active.take() {
                        stop_approval_expiry_watchdog(&mut active).await;
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
        stop_approval_expiry_watchdog(&mut active).await;
        let _ = request_active_cancel(&active.execution_gate, active.control.take()).await;
        if tokio::time::timeout(self.shutdown_grace, active.task.join())
            .await
            .is_err()
        {
            active.task.abort();
            let _ = active.task.join().await;
        }
    }

    async fn resolve_approval_control(
        &mut self,
        input: ClaimApproval,
        authorization_guard: &ApprovalAuthorizationGuard,
    ) -> Result<ApprovalReceipt, ConversationError> {
        if self.recovery_blocked {
            return Err(ConversationError::ActorUnavailable);
        }
        let ClaimApproval {
            conversation_id,
            turn_id,
            approval_id,
            decision,
            ..
        } = input;
        let mut outcome = loop {
            match self
                .store
                .claim_approval(ClaimApproval {
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision: decision.clone(),
                    claimant_binding: authorization_guard.claimant_binding(),
                })
                .await
            {
                Ok(outcome) => break outcome,
                Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: super::store::RuntimeCommitOperation::ClaimApproval,
                }) => tokio::task::yield_now().await,
                Err(error) => return Err(ConversationError::Store(error)),
            }
        };
        if matches!(
            &outcome,
            ApprovalMutationOutcome::ExpiredOrStale { approval }
                if approval.state != ApprovalState::Expired
        ) {
            let approval = approval_from_mutation(&outcome).clone();
            outcome = self
                .expire_stale_approval_store_only(approval.conversation_id, approval.approval_id)
                .await?;
        }
        let approval = approval_from_mutation(&outcome).clone();
        let receipt = approval_receipt_for_resolve(outcome)?;
        if matches!(
            approval.state,
            ApprovalState::Claimed | ApprovalState::Applying
        ) {
            self.start_approval_delivery(approval).await?;
        }
        Ok(receipt)
    }

    async fn retry_approval_control(
        &mut self,
        input: RetryApprovalDelivery,
    ) -> Result<ApprovalReceipt, ConversationError> {
        if self.recovery_blocked {
            return Err(ConversationError::ActorUnavailable);
        }
        let RetryApprovalDelivery {
            conversation_id,
            approval_id,
        } = input;
        let mut outcome = loop {
            match self
                .store
                .retry_approval_delivery(RetryApprovalDelivery {
                    conversation_id,
                    approval_id,
                })
                .await
            {
                Ok(outcome) => break outcome,
                Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: super::store::RuntimeCommitOperation::RetryApprovalDelivery,
                }) => tokio::task::yield_now().await,
                Err(error) => return Err(ConversationError::Store(error)),
            }
        };
        if matches!(
            &outcome,
            ApprovalMutationOutcome::ExpiredOrStale { approval }
                if approval.state != ApprovalState::Expired
        ) {
            let approval = approval_from_mutation(&outcome).clone();
            outcome = self
                .expire_stale_approval_store_only(approval.conversation_id, approval.approval_id)
                .await?;
        }
        let approval = approval_from_mutation(&outcome).clone();
        let receipt = approval_receipt_for_retry(&approval)?;
        if approval.state == ApprovalState::Applying {
            self.start_approval_delivery(approval).await?;
        }
        Ok(receipt)
    }

    async fn expire_stale_approval_store_only(
        &self,
        conversation_id: RuntimeId,
        approval_id: RuntimeId,
    ) -> Result<ApprovalMutationOutcome, ConversationError> {
        loop {
            match self
                .store
                .expire_approval(ExpireApproval {
                    conversation_id,
                    approval_id,
                })
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: super::store::RuntimeCommitOperation::ExpireApproval,
                }) => tokio::task::yield_now().await,
                Err(error) => return Err(ConversationError::Store(error)),
            }
        }
    }

    async fn start_approval_delivery(
        &mut self,
        approval: ApprovalRecord,
    ) -> Result<(), ConversationError> {
        let route = self
            .approval_deliveries
            .get_mut(&approval.approval_id)
            .ok_or(ConversationError::ActorUnavailable)?;
        if route.turn_id != approval.turn_id {
            return Err(corrupt_approval_state());
        }
        if route.delivery_task.is_some() {
            if approval.state == ApprovalState::Applying && approval.attempts_in_round == 0 {
                // Manual Retry 已 durable 开启新 round，旧 worker 必然已写入
                // DeliveryFailed；其 completion 可能仍在 bounded runner lane。先收掉旧
                // supervisor，并用 generation 阻止陈旧 completion 清掉新 worker。
                if let Some(mut old_task) = route.delivery_task.take() {
                    old_task.abort();
                    let _ = old_task.join().await;
                }
            } else {
                return Ok(());
            }
        }
        route.delivery_generation = route
            .delivery_generation
            .checked_add(1)
            .ok_or_else(corrupt_approval_state)?;
        let generation = route.delivery_generation;
        let approval_id = approval.approval_id;
        let journal: Arc<dyn ApprovalDeliveryJournal> = Arc::new(self.store.clone());
        let delivery = route.delivery.clone();
        let clock = self.approval_clock.clone();
        let sleeper = self.approval_sleeper.clone();
        let backoff = self.approval_backoff.clone();
        let runner_tx = self.runner_tx.clone();
        route.delivery_task = Some(spawn_approval_task(
            approval_id,
            ApprovalTaskKind::Delivery,
            generation,
            runner_tx,
            run_approval_delivery_round(journal, delivery, approval, clock, sleeper, backoff),
        ));
        Ok(())
    }

    async fn finish_approval_task(
        &mut self,
        approval_id: RuntimeId,
        task_kind: ApprovalTaskKind,
        generation: u64,
        result: ApprovalWorkerResult,
    ) {
        let current_delivery_generation = self
            .approval_deliveries
            .get(&approval_id)
            .map(|route| route.delivery_generation);
        match classify_approval_task_completion(
            task_kind,
            generation,
            current_delivery_generation,
            result,
        ) {
            ApprovalTaskCompletionDisposition::IgnoreStale => return,
            ApprovalTaskCompletionDisposition::RecoveryBlocked => {
                if let Some(active) = &mut self.active {
                    let _ =
                        request_active_cancel(&active.execution_gate, active.control.clone()).await;
                }
                self.enter_recovery_blocked_and_stop_approvals().await;
                return;
            }
            ApprovalTaskCompletionDisposition::Continue => {}
        }
        if result == ApprovalWorkerResult::Expired {
            let expired_turn_id = self
                .approval_deliveries
                .get(&approval_id)
                .map(|route| route.turn_id);
            let active_expiry = expired_turn_id.and_then(|turn_id| {
                self.active
                    .as_ref()
                    .filter(|active| active.turn_id == Some(turn_id))
                    .map(|active| {
                        (
                            active.command.command_id,
                            turn_id,
                            active.execution_gate.clone(),
                            active.control.clone(),
                        )
                    })
            });
            if let Some((command_id, turn_id, execution_gate, control)) = active_expiry {
                if interrupt_active_for_approval_expiry(&execution_gate, control)
                    .await
                    .is_err()
                {
                    self.enter_recovery_blocked_and_stop_approvals().await;
                    return;
                }
                let runner_tx = self.runner_tx.clone();
                let grace = self.approval_expiry_terminal_grace;
                if let Some(active) = self.active.as_mut().filter(|active| {
                    active.command.command_id == command_id && active.turn_id == Some(turn_id)
                }) && active.approval_expiry_watchdog.is_none()
                {
                    active.approval_expiry_watchdog = Some(spawn_approval_expiry_watchdog(
                        command_id, turn_id, grace, runner_tx,
                    ));
                }
            }
        }
        if matches!(
            result,
            ApprovalWorkerResult::Applied | ApprovalWorkerResult::Expired
        ) {
            if let Some(mut route) = self.approval_deliveries.remove(&approval_id) {
                if task_kind != ApprovalTaskKind::Deadline
                    && let Some(task) = &route.deadline_task
                {
                    task.abort();
                }
                if task_kind != ApprovalTaskKind::Delivery
                    && let Some(task) = &route.delivery_task
                {
                    task.abort();
                }
                if let Some(mut task) = route.deadline_task.take() {
                    let _ = task.join().await;
                }
                if let Some(mut task) = route.delivery_task.take() {
                    let _ = task.join().await;
                }
            }
            return;
        }
        let Some(route) = self.approval_deliveries.get_mut(&approval_id) else {
            return;
        };
        let task = match task_kind {
            ApprovalTaskKind::Deadline => route.deadline_task.take(),
            ApprovalTaskKind::Delivery => route.delivery_task.take(),
        };
        if let Some(mut task) = task {
            let _ = task.join().await;
        }
    }

    async fn finish_approval_turn(&mut self, turn_id: RuntimeId) {
        let approval_ids: Vec<_> = self
            .approval_deliveries
            .iter()
            .filter_map(|(approval_id, route)| (route.turn_id == turn_id).then_some(*approval_id))
            .collect();
        for approval_id in approval_ids {
            if let Some(mut route) = self.approval_deliveries.remove(&approval_id) {
                if let Some(task) = &route.deadline_task {
                    task.abort();
                }
                if let Some(task) = &route.delivery_task {
                    task.abort();
                }
                if let Some(mut task) = route.deadline_task.take() {
                    let _ = task.join().await;
                }
                if let Some(mut task) = route.delivery_task.take() {
                    let _ = task.join().await;
                }
            }
        }
    }

    async fn register_action_request(
        &mut self,
        command_id: RuntimeId,
        turn_id: RuntimeId,
        request: agentdeck_protocol::ActionRequest,
        delivery: SharedApprovalDelivery,
    ) -> Result<(), ConversationError> {
        if self.recovery_blocked {
            return Err(ConversationError::ActorUnavailable);
        }
        if self.active.as_ref().is_none_or(|active| {
            active.command.command_id != command_id || active.turn_id != Some(turn_id)
        }) {
            return Err(ConversationError::ActorUnavailable);
        }
        delivery
            .policy()
            .validate_request(&request)
            .map_err(|_| ConversationError::ActorUnavailable)?;
        let route_full = self.approval_deliveries.len()
            >= usize::try_from(super::model::MAX_ACTIVE_APPROVALS_PER_TURN)
                .expect("approval per-turn bound fits usize");
        let conversation_id = self.conversation.conversation_id;
        let policy = delivery.policy().clone();
        let outcome = loop {
            match self
                .store
                .register_approval(RegisterApproval {
                    conversation_id,
                    command_id,
                    turn_id,
                    request: request.clone(),
                    policy: policy.clone(),
                })
                .await
            {
                Ok(outcome) => break outcome,
                Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: super::store::RuntimeCommitOperation::RegisterApproval,
                }) => tokio::task::yield_now().await,
                Err(RuntimeStoreError::InvalidStateTransition) if route_full => {
                    return Err(ConversationError::MailboxFull);
                }
                Err(error) => return Err(ConversationError::Store(error)),
            }
        };
        let approval = match outcome {
            RegisterApprovalOutcome::Registered { approval, .. }
            | RegisterApprovalOutcome::Replayed { approval, .. } => approval,
        };
        if approval.state.is_terminal() {
            if let Some(mut route) = self.approval_deliveries.remove(&approval.approval_id) {
                if let Some(task) = &route.deadline_task {
                    task.abort();
                }
                if let Some(task) = &route.delivery_task {
                    task.abort();
                }
                if let Some(mut task) = route.deadline_task.take() {
                    let _ = task.join().await;
                }
                if let Some(mut task) = route.delivery_task.take() {
                    let _ = task.join().await;
                }
            }
            return Ok(());
        }
        if let Some(route) = self.approval_deliveries.get(&approval.approval_id) {
            return if route.turn_id == approval.turn_id {
                Ok(())
            } else {
                Err(corrupt_approval_state())
            };
        }
        if !approval.state.is_active() {
            return Err(corrupt_approval_state());
        }

        let approval_id = approval.approval_id;
        let journal: Arc<dyn ApprovalDeliveryJournal> = Arc::new(self.store.clone());
        let clock = self.approval_clock.clone();
        let sleeper = self.approval_sleeper.clone();
        let runner_tx = self.runner_tx.clone();
        let deadline_approval = approval.clone();
        let deadline_task = spawn_approval_task(
            approval_id,
            ApprovalTaskKind::Deadline,
            0,
            runner_tx,
            run_approval_deadline(journal, deadline_approval, clock, sleeper),
        );
        self.approval_deliveries.insert(
            approval.approval_id,
            ApprovalRoute {
                turn_id,
                delivery,
                deadline_task: Some(deadline_task),
                delivery_task: None,
                delivery_generation: 0,
            },
        );
        Ok(())
    }
}

fn classify_approval_task_completion(
    task_kind: ApprovalTaskKind,
    generation: u64,
    current_delivery_generation: Option<u64>,
    result: ApprovalWorkerResult,
) -> ApprovalTaskCompletionDisposition {
    if task_kind == ApprovalTaskKind::Delivery && current_delivery_generation != Some(generation) {
        ApprovalTaskCompletionDisposition::IgnoreStale
    } else if result == ApprovalWorkerResult::FatalClosure {
        ApprovalTaskCompletionDisposition::RecoveryBlocked
    } else {
        ApprovalTaskCompletionDisposition::Continue
    }
}

async fn forward_execution_events(
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    store: RuntimeStoreHandle,
    mut events: RuntimeExecutionEventReceiver,
    runner_tx: mpsc::Sender<RunnerEvent>,
) -> Result<(), ExecutionEventForwardError> {
    let mut item_identities = HashMap::<AdapterItemKey, (ItemId, EntityId)>::new();
    while let Some(event) = events.recv().await {
        match event {
            RuntimeExecutionEvent::Adapter { delivery } => {
                let (event, acknowledge) = delivery.into_parts();
                let committed = append_adapter_event(
                    &store,
                    conversation_id,
                    command_id,
                    turn_id,
                    &mut item_identities,
                    event,
                )
                .await;
                acknowledge.acknowledge(committed);
                if committed.is_err() {
                    return Err(ExecutionEventForwardError::EventDurabilityLost);
                }
            }
            RuntimeExecutionEvent::ActionRequest {
                request,
                delivery,
                registration_ack,
            } => {
                let (acknowledged, registered) = oneshot::channel();
                if runner_tx
                    .send(RunnerEvent::ApprovalRequested {
                        command_id,
                        turn_id,
                        request,
                        delivery,
                        acknowledged,
                    })
                    .await
                    .is_err()
                {
                    if let Some(registration_ack) = registration_ack {
                        registration_ack.acknowledge(Err(()));
                    }
                    return Err(ExecutionEventForwardError::ApprovalBridgeClosed);
                }
                let registration = match registered.await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) | Err(_) => Err(()),
                };
                if let Some(registration_ack) = registration_ack {
                    registration_ack.acknowledge(registration);
                }
                if registration.is_err() {
                    return Err(ExecutionEventForwardError::ApprovalDurabilityLost);
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionEventForwardError {
    EventDurabilityLost,
    ApprovalDurabilityLost,
    ApprovalBridgeClosed,
}

async fn append_adapter_event(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    item_identities: &mut HashMap<AdapterItemKey, (ItemId, EntityId)>,
    event: AdapterEvent,
) -> Result<(), ()> {
    let event_id = random_event_id()?;
    let input = match event {
        AdapterEvent::Item { key, item } => {
            let (item_id, entity_id) = match item_identities.get(&key) {
                Some(identity) => identity.clone(),
                None => {
                    if item_identities.len() >= MAX_ADAPTER_ITEM_KEYS_PER_TURN {
                        return Err(());
                    }
                    let item_id = ItemId::new(random_event_id()?.to_canonical_string());
                    let entity_id = EntityId::new(random_event_id()?.to_canonical_string());
                    item_identities.insert(key, (item_id.clone(), entity_id.clone()));
                    (item_id, entity_id)
                }
            };
            super::store::AppendExecutionEvent::item(
                conversation_id,
                command_id,
                turn_id,
                event_id,
                item_id,
                entity_id,
                item,
            )
        }
        AdapterEvent::Error(_) => super::store::AppendExecutionEvent::execution_failed(
            conversation_id,
            command_id,
            turn_id,
            event_id,
        ),
        AdapterEvent::TurnComplete(_)
        | AdapterEvent::VendorControl(_)
        | AdapterEvent::VendorPanelEvent(_) => return Err(()),
    };
    match store.append_execution_event(input.clone()).await {
        Ok(_) => Ok(()),
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AppendExecutionEvent,
        }) => store
            .append_execution_event(input)
            .await
            .map(|_| ())
            .map_err(|_| ()),
        Err(_) => Err(()),
    }
}

fn random_event_id() -> Result<RuntimeId, ()> {
    for _ in 0..16 {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| ())?;
        if let Ok(id) = RuntimeId::from_bytes(RuntimeIdKind::Event, bytes) {
            return Ok(id);
        }
    }
    Err(())
}

#[cfg(test)]
#[path = "runtime_execution_fixture_tests.rs"]
mod runtime_execution_fixture_tests;

fn spawn_approval_expiry_watchdog(
    command_id: RuntimeId,
    turn_id: RuntimeId,
    grace: Duration,
    runner_tx: mpsc::Sender<RunnerEvent>,
) -> AbortOnDropTask<()> {
    AbortOnDropTask::new(tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        let _ = runner_tx
            .send(RunnerEvent::ApprovalExpiryTerminalWatchdog {
                command_id,
                turn_id,
            })
            .await;
    }))
}

async fn stop_approval_expiry_watchdog(active: &mut ActiveCommand) {
    if let Some(mut watchdog) = active.approval_expiry_watchdog.take() {
        watchdog.abort();
        let _ = watchdog.join().await;
    }
}

fn spawn_approval_task<F>(
    approval_id: RuntimeId,
    task_kind: ApprovalTaskKind,
    generation: u64,
    runner_tx: mpsc::Sender<RunnerEvent>,
    future: F,
) -> AbortOnDropTask<()>
where
    F: Future<Output = ApprovalWorkerResult> + Send + 'static,
{
    let worker = AbortOnDropTask::new(tokio::spawn(future));
    AbortOnDropTask::new(tokio::spawn(async move {
        let mut worker = worker;
        let result = match worker.join().await {
            Ok(result) => result,
            Err(_) => ApprovalWorkerResult::StoreBlocked,
        };
        let _ = runner_tx
            .send(RunnerEvent::ApprovalTaskFinished {
                approval_id,
                task_kind,
                generation,
                result,
            })
            .await;
    }))
}

fn approval_receipt_for_resolve(
    outcome: ApprovalMutationOutcome,
) -> Result<ApprovalReceipt, ConversationError> {
    match outcome {
        ApprovalMutationOutcome::Transitioned { approval, .. } => {
            receipt_for_exact_winner(approval, true)
        }
        ApprovalMutationOutcome::Replayed { approval, .. } => {
            receipt_for_exact_winner(approval, true)
        }
        ApprovalMutationOutcome::AlreadyHandled { approval } => {
            receipt_for_exact_winner(approval, false)
        }
        ApprovalMutationOutcome::ExpiredOrStale { approval } => {
            if approval.state == ApprovalState::Expired {
                expired_approval_receipt(&approval)
            } else {
                Err(corrupt_approval_state())
            }
        }
    }
}

fn approval_from_mutation(outcome: &ApprovalMutationOutcome) -> &ApprovalRecord {
    match outcome {
        ApprovalMutationOutcome::Transitioned { approval, .. }
        | ApprovalMutationOutcome::Replayed { approval, .. }
        | ApprovalMutationOutcome::AlreadyHandled { approval }
        | ApprovalMutationOutcome::ExpiredOrStale { approval } => approval,
    }
}

fn approval_receipt_for_retry(
    approval: &ApprovalRecord,
) -> Result<ApprovalReceipt, ConversationError> {
    let approval_id = wire_approval_id(approval.approval_id);
    match approval.state {
        ApprovalState::Applied => Ok(ApprovalReceipt::Applied { approval_id }),
        ApprovalState::DeliveryFailed => Ok(ApprovalReceipt::DeliveryFailed { approval_id }),
        ApprovalState::Expired => expired_approval_receipt(approval),
        ApprovalState::Claimed | ApprovalState::Applying => {
            let decision = approval
                .decision
                .as_ref()
                .map(|decision| decision.decision)
                .ok_or_else(corrupt_approval_state)?;
            Ok(ApprovalReceipt::AlreadyHandled {
                approval_id,
                decision,
                state: wire_approval_delivery_state(approval.state)?,
            })
        }
        ApprovalState::Pending => Err(corrupt_approval_state()),
    }
}

fn receipt_for_exact_winner(
    approval: ApprovalRecord,
    exact_replay: bool,
) -> Result<ApprovalReceipt, ConversationError> {
    let approval_id = wire_approval_id(approval.approval_id);
    match approval.state {
        ApprovalState::Claimed if exact_replay => Ok(ApprovalReceipt::Claimed { approval_id }),
        ApprovalState::Applied if exact_replay => Ok(ApprovalReceipt::Applied { approval_id }),
        ApprovalState::DeliveryFailed if exact_replay => {
            Ok(ApprovalReceipt::DeliveryFailed { approval_id })
        }
        ApprovalState::Expired if exact_replay => expired_approval_receipt(&approval),
        ApprovalState::Pending => Err(corrupt_approval_state()),
        state => {
            let decision = approval
                .decision
                .as_ref()
                .map(|decision| decision.decision)
                .ok_or_else(corrupt_approval_state)?;
            Ok(ApprovalReceipt::AlreadyHandled {
                approval_id,
                decision,
                state: wire_approval_delivery_state(state)?,
            })
        }
    }
}

fn expired_approval_receipt(
    approval: &ApprovalRecord,
) -> Result<ApprovalReceipt, ConversationError> {
    let approval_id = wire_approval_id(approval.approval_id);
    match approval.decision.as_ref() {
        Some(decision) => Ok(ApprovalReceipt::AlreadyHandled {
            approval_id,
            decision: decision.decision,
            state: ApprovalDeliveryState::Expired,
        }),
        None => Ok(ApprovalReceipt::Expired { approval_id }),
    }
}

fn wire_approval_delivery_state(
    state: ApprovalState,
) -> Result<ApprovalDeliveryState, ConversationError> {
    match state {
        ApprovalState::Claimed => Ok(ApprovalDeliveryState::Claimed),
        ApprovalState::Applying => Ok(ApprovalDeliveryState::Applying),
        ApprovalState::Applied => Ok(ApprovalDeliveryState::Applied),
        ApprovalState::DeliveryFailed => Ok(ApprovalDeliveryState::DeliveryFailed),
        ApprovalState::Expired => Ok(ApprovalDeliveryState::Expired),
        ApprovalState::Pending => Err(corrupt_approval_state()),
    }
}

fn corrupt_approval_state() -> ConversationError {
    ConversationError::Store(RuntimeStoreError::UnknownOrCorruptSchema)
}

fn wire_approval_id(value: RuntimeId) -> ApprovalId {
    ApprovalId::new(value.to_canonical_string())
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
) -> Result<RuntimeCancelDisposition, RuntimeExecutionError> {
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
        let disposition = cancel_control(control).await?;
        gate.cancel_fenced = true;
        match disposition {
            RuntimeCancelDisposition::UserCancelWon => {
                if gate.user_cancel_accepted {
                    gate.user_cancel_fenced = true;
                }
            }
            RuntimeCancelDisposition::AlreadyCompleting => {
                gate.completion_won = true;
            }
        }
    }
    Ok(())
}

async fn request_user_active_cancel(
    execution_gate: &Mutex<ActiveExecutionGate>,
    control: Option<Arc<dyn RuntimeExecutionControl>>,
) -> Result<bool, RuntimeExecutionError> {
    let mut gate = execution_gate.lock().await;
    if gate.claimed_terminal.is_some() || gate.completion_won {
        return Ok(false);
    }
    gate.cancel_requested = true;
    if gate.cancel_fenced {
        return Ok(gate.user_cancel_accepted && gate.user_cancel_fenced);
    }
    if let Some(control) = control {
        match cancel_control(control).await? {
            RuntimeCancelDisposition::UserCancelWon => {
                gate.cancel_fenced = true;
                gate.user_cancel_fenced = true;
            }
            RuntimeCancelDisposition::AlreadyCompleting => {
                gate.cancel_fenced = true;
                gate.completion_won = true;
                return Ok(false);
            }
        }
    }
    gate.user_cancel_accepted = true;
    Ok(true)
}

async fn interrupt_active_for_approval_expiry(
    execution_gate: &Mutex<ActiveExecutionGate>,
    control: Option<Arc<dyn RuntimeExecutionControl>>,
) -> Result<(), RuntimeExecutionError> {
    // 威胁场景：approval durable Expired 后若只删除 route，Codex/CC 仍在等待一个
    // daemon 永远不会投递的决定并永久占用 actor。expiry 不能伪造用户 Deny；它必须
    // fence exact execution group，并让同一 command 以 Interrupted 正常收口。
    claim_interrupted_after_exact_fence(execution_gate, control)
        .await
        .map(|_| ())
}

async fn claim_interrupted_after_exact_fence(
    execution_gate: &Mutex<ActiveExecutionGate>,
    control: Option<Arc<dyn RuntimeExecutionControl>>,
) -> Result<Option<CommandTerminal>, RuntimeExecutionError> {
    let mut gate = execution_gate.lock().await;
    if let Some(claimed_terminal) = &gate.claimed_terminal {
        return Ok(Some(claimed_terminal.clone()));
    }
    if gate.completion_won {
        return Ok(None);
    }
    if !gate.release_authorized {
        return Err(RuntimeExecutionError::CancelFailed);
    }
    gate.cancel_requested = true;
    if !gate.cancel_fenced {
        match cancel_control(control.ok_or(RuntimeExecutionError::CancelFailed)?).await? {
            RuntimeCancelDisposition::UserCancelWon => {
                gate.cancel_fenced = true;
            }
            RuntimeCancelDisposition::AlreadyCompleting => {
                gate.cancel_fenced = true;
                gate.completion_won = true;
                return Ok(None);
            }
        }
    }
    let terminal = if gate.user_cancel_accepted && gate.user_cancel_fenced {
        CommandTerminal::canceled()
    } else {
        CommandTerminal::interrupted()
    };
    gate.claimed_terminal = Some(terminal.clone());
    Ok(Some(terminal))
}

async fn claim_clean_prepare_failure_terminal(
    execution_gate: &Mutex<ActiveExecutionGate>,
) -> Result<StartedBeforeReleaseTermination, RuntimeExecutionError> {
    // 威胁场景：用户在 prepare 阻塞期间已收到 Requested，随后 prepare 以
    // PrepareFailedClean 返回；若 clean failure 不与 Cancel 共用同一个 claim，
    // durable terminal 会错误写成 Interrupted，且 COMMIT 窗口内的晚到 Cancel
    // 还会再次返回 Requested。clean disposition 已证明没有存活 child，因此可在
    // 同一 gate 下把已接受的用户取消视为 exact fence，并先 claim terminal。
    let mut gate = execution_gate.lock().await;
    if gate.claimed_terminal.is_some() || gate.completion_won || gate.release_authorized {
        return Err(RuntimeExecutionError::PrepareFailed);
    }
    if gate.user_cancel_accepted {
        gate.cancel_requested = true;
        gate.cancel_fenced = true;
        gate.user_cancel_fenced = true;
        gate.claimed_terminal = Some(CommandTerminal::canceled());
        Ok(StartedBeforeReleaseTermination::Canceled)
    } else {
        gate.claimed_terminal = Some(CommandTerminal::interrupted());
        Ok(StartedBeforeReleaseTermination::Interrupted)
    }
}

async fn fence_pre_release_cancel_if_requested(
    execution_gate: &Mutex<ActiveExecutionGate>,
    control: Arc<dyn RuntimeExecutionControl>,
) -> Result<bool, RuntimeExecutionError> {
    let mut gate = execution_gate.lock().await;
    if !gate.cancel_requested {
        return Ok(false);
    }
    if cancel_control(control).await? != RuntimeCancelDisposition::UserCancelWon {
        return Err(RuntimeExecutionError::CancelFailed);
    }
    gate.cancel_fenced = true;
    if gate.user_cancel_accepted {
        gate.user_cancel_fenced = true;
    }
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

async fn claim_post_release_terminal(
    execution_gate: &Mutex<ActiveExecutionGate>,
    terminal: CommandTerminal,
) -> CommandTerminal {
    let mut gate = execution_gate.lock().await;
    if let Some(claimed) = &gate.claimed_terminal {
        return claimed.clone();
    }
    let claimed = if gate.release_authorized && gate.user_cancel_accepted && gate.user_cancel_fenced
    {
        CommandTerminal::canceled()
    } else {
        terminal
    };
    gate.claimed_terminal = Some(claimed.clone());
    claimed
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
        let PromptCommand {
            principal,
            authorization_guard,
            idempotency_key,
            expected_configuration_revision,
            payload,
            reply,
        } = command;
        let authorization_key = principal.authorization_key();
        let outcome = store
            .accept_command_authorized(
                AcceptCommand {
                    conversation_id,
                    owner: principal.idempotency_owner(),
                    idempotency_key,
                    expected_configuration_revision,
                    payload,
                },
                authorization_guard,
            )
            .await;
        if admission_tx
            .send(PromptAdmission {
                principal,
                authorization_key,
                outcome,
                reply,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

fn resolve_execution_configuration(
    conversation: &ConversationRecord,
    execution_configuration: CommandExecutionConfiguration,
) -> Result<(u64, ConversationConfiguration), ()> {
    if execution_configuration.agent_kind() != conversation.descriptor.agent_kind {
        return Err(());
    }
    match execution_configuration {
        CommandExecutionConfiguration::Pinned {
            configuration_revision,
            configuration,
        } if configuration_revision != 0 => Ok((configuration_revision, configuration)),
        CommandExecutionConfiguration::LegacyRevisionZero { agent_kind } => {
            frozen_p37_legacy_configuration(agent_kind).map(|configuration| (0, configuration))
        }
        CommandExecutionConfiguration::Pinned { .. } => Err(()),
    }
}

/// schema v4→v5 前已 Accepted command 的唯一解释。该值在 daemon 层显式冻结，
/// 不调用 adapter 的 current default，避免未来默认值漂移改变旧 command 的执行语义。
fn frozen_p37_legacy_configuration(agent_kind: AgentKind) -> Result<ConversationConfiguration, ()> {
    match agent_kind {
        AgentKind::Codex => Ok(ConversationConfiguration::new(
            VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                CodexApprovalPolicy::OnRequest,
                CodexSandboxMode::WorkspaceWrite,
                CodexReasoningEffort::Medium,
            )),
        )),
        AgentKind::ClaudeCode => ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .map(VendorConfigurationSnapshot::ClaudeCode)
        .map(ConversationConfiguration::new)
        .map_err(|_| ()),
    }
}

fn classify_start_failure(
    provenance: QueuedCommandProvenance,
    configuration_revision: u64,
    error: &RuntimeStoreError,
) -> StartFailureDisposition {
    match error {
        // 普通 live/replay queue 没有资格解释 migration rev0；Store 的拒绝不是
        // cancel/revoke race，不能把仍 durable Accepted 的 command 静默移出 actor。
        RuntimeStoreError::InvalidStateTransition
            if provenance == QueuedCommandProvenance::Live && configuration_revision == 0 =>
        {
            StartFailureDisposition::RecoveryBlocked
        }
        // 非零 revision 的 InvalidStateTransition 与 expiry 仍表示 queued
        // cancel/revoke/expiry 抢先赢得 durable transition。
        RuntimeStoreError::InvalidStateTransition | RuntimeStoreError::CommandExpired => {
            StartFailureDisposition::Finished
        }
        _ => StartFailureDisposition::RecoveryBlocked,
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_command(
    conversation: ConversationRecord,
    accepted: CommandRecord,
    principal: Option<AuthenticatedPrincipal>,
    provenance: QueuedCommandProvenance,
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
    let start_input = StartCommand {
        conversation_id: conversation.conversation_id,
        command_id: accepted.command_id,
        daemon_boot_id,
        execution_nonce: execution_nonce.clone(),
    };
    let started = match provenance {
        QueuedCommandProvenance::Live => store.mark_started_with_event(start_input.clone()).await,
        QueuedCommandProvenance::StartupRecovery => {
            store
                .mark_started_for_startup_recovery(start_input.clone())
                .await
        }
    };
    let started = match started {
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: super::store::RuntimeCommitOperation::StartCommand,
        }) => match provenance {
            QueuedCommandProvenance::Live => store.mark_started_with_event(start_input).await,
            QueuedCommandProvenance::StartupRecovery => {
                store.mark_started_for_startup_recovery(start_input).await
            }
        },
        outcome => outcome,
    };
    drop(start_guard);
    // begin_revoke 只有在 Accepted→Started durable transition 完成后才可继续；
    // 若 revoke CAS 先赢，try_enter 已在上方 fail-closed。
    drop(authorization_guard);
    let (command, execution_configuration, turn_id) = match started {
        Ok(StartOutcome::Started {
            command,
            execution_configuration,
            intent,
            ..
        })
        | Ok(StartOutcome::Replayed {
            command,
            execution_configuration,
            intent,
            ..
        }) => (command, execution_configuration, intent.turn_id),
        Err(error) => {
            let event =
                match classify_start_failure(provenance, accepted.configuration_revision, &error) {
                    StartFailureDisposition::Finished => RunnerEvent::Finished {
                        command_id: accepted.command_id,
                    },
                    StartFailureDisposition::RecoveryBlocked => RunnerEvent::RecoveryBlocked {
                        command_id: accepted.command_id,
                    },
                };
            let _ = runner_tx.send(event).await;
            return;
        }
    };
    let (configuration_revision, execution_configuration) =
        match resolve_execution_configuration(&conversation, execution_configuration) {
            Ok(configuration) => configuration,
            Err(()) => {
                let _ = runner_tx
                    .send(RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
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
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
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
            configuration_revision,
            execution_configuration,
            turn_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            // 威胁场景：固定 vendor binary 不存在，prepare 在 release 前失败且已证明
            // 没有存活 gate/vendor child；若仍无条件 RecoveryBlocked，同一 conversation
            // 会被永久封死。只有 typed clean failure 可复用 pre-release terminal；任何
            // child outcome/cleanup 未知的错误继续 fail-close。
            let event = if error == RuntimeExecutionError::PrepareFailedClean {
                let reason = match claim_clean_prepare_failure_terminal(&execution_gate).await {
                    Ok(reason) => reason,
                    Err(_) => {
                        let _ = runner_tx
                            .send(RunnerEvent::RecoveryBlocked {
                                command_id: command.command_id,
                            })
                            .await;
                        return;
                    }
                };
                let termination = TerminateStartedBeforeRelease {
                    conversation_id: conversation.conversation_id,
                    command_id: command.command_id,
                    turn_id,
                    daemon_boot_id,
                    execution_nonce: execution_nonce.clone(),
                    reason,
                };
                if terminate_started_before_release_exact(&store, termination).await {
                    RunnerEvent::Finished {
                        command_id: command.command_id,
                    }
                } else {
                    RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
                    }
                }
            } else {
                RunnerEvent::RecoveryBlocked {
                    command_id: command.command_id,
                }
            };
            let _ = runner_tx.send(event).await;
            return;
        }
    };

    // Prepared adapters hand us a bounded receiver before the durable release boundary, but
    // no event reaches the actor/store until release has committed and the cold capability has
    // been consumed. The production attach path then holds every AdapterEvent on an explicit
    // durable-ACK barrier, and terminal completion joins both event and approval bridges.
    let execution_events = prepared.events;
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
        let _ = request_active_cancel(&execution_gate, Some(control)).await;
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
            let _ = request_active_cancel(&execution_gate, Some(control)).await;
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

    let fence_input = ExecutionFence {
        command_id: command.command_id,
        daemon_boot_id,
        execution_nonce: execution_nonce.clone(),
        process_group_id: process.process_group_id,
        leader_pid: process.leader_pid,
        leader_start_time: process.leader_start_time,
        payload: process.fence_payload,
    };
    let fence = match store.persist_execution_fence(fence_input.clone()).await {
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PersistFence,
        }) => store.persist_execution_fence(fence_input).await,
        outcome => outcome,
    };
    let fence = match fence {
        Ok(fence) => fence,
        Err(_) => {
            let _ = request_active_cancel(&execution_gate, Some(control)).await;
            let _ = runner_tx
                .send(RunnerEvent::RecoveryBlocked {
                    command_id: command.command_id,
                })
                .await;
            return;
        }
    };
    let (fence_ack, fence_ready) = oneshot::channel();
    if runner_tx
        .send(RunnerEvent::FenceUpdated {
            command_id: command.command_id,
            turn_id,
            fence,
            acknowledged: fence_ack,
        })
        .await
        .is_err()
        || !matches!(fence_ready.await, Ok(Ok(())))
    {
        let _ = request_active_cancel(&execution_gate, Some(control)).await;
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
        let authorization = match store
            .authorize_execution_release(release_request.clone())
            .await
        {
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::AuthorizeExecutionRelease,
            }) => {
                store
                    .authorize_execution_release(release_request.clone())
                    .await
            }
            outcome => outcome,
        };
        match authorization {
            Ok(record) => {
                gate.release_authorized = true;
                record
            }
            Err(_) => {
                drop(gate);
                let _ = request_active_cancel(&execution_gate, Some(control)).await;
                let _ = runner_tx
                    .send(RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
                    })
                    .await;
                return;
            }
        }
    };
    let (release_ack, release_ready) = oneshot::channel();
    if runner_tx
        .send(RunnerEvent::FenceUpdated {
            command_id: command.command_id,
            turn_id,
            fence: release_record.clone(),
            acknowledged: release_ack,
        })
        .await
        .is_err()
        || !matches!(release_ready.await, Ok(Ok(())))
    {
        let _ = request_active_cancel(&execution_gate, Some(control)).await;
        return;
    }
    let permit =
        match ExecutionReleasePermit::from_committed_store(&release_request, &release_record) {
            Ok(permit) => permit,
            Err(_) => {
                let _ = request_active_cancel(&execution_gate, Some(control)).await;
                let _ = runner_tx
                    .send(RunnerEvent::RecoveryBlocked {
                        command_id: command.command_id,
                    })
                    .await;
                return;
            }
        };
    let (completion_future, mut execution_events_task) = match release.release(permit).await {
        Ok(completion) => {
            let forwarder = AbortOnDropTask::new(tokio::spawn(forward_execution_events(
                conversation.conversation_id,
                command.command_id,
                turn_id,
                store.clone(),
                execution_events,
                runner_tx.clone(),
            )));
            (completion, Some(forwarder))
        }
        Err(_) => {
            // Release 未成功消费 cold capability 时，prepared receiver 中即使已有
            // adapter 预排事件也必须丢弃，不能把未越过 gate 的 approval 持久化。
            drop(execution_events);
            if request_active_cancel(&execution_gate, Some(control.clone()))
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
            let interrupted =
                claim_post_release_terminal(&execution_gate, CommandTerminal::interrupted()).await;
            let completion: RuntimeCompletionFuture = Box::pin(async move {
                Ok(RuntimeExecutionCompletion {
                    terminal: interrupted,
                })
            });
            (completion, None)
        }
    };

    // completion future 只有消费 committed release permit 后才能取得。terminal 还必须
    // 等待 durable forwarder 自然 drain；negative ACK/bridge close 不能伪装成 Failed
    // 或 Interrupted，而要由 actor 写入 exact RecoveryBlocked。
    let completion = completion_future.await;
    // vendor completion 一旦返回就先 claim terminal，阻止随后在 durable ACK 排空窗口
    // 到达的用户 Cancel 改写已经发生的结果；真正的 Store terminal 仍在 forwarder
    // 完全 drain 后才提交。
    let claimed_terminal = match &completion {
        Ok(completion) => {
            Some(claim_post_release_terminal(&execution_gate, completion.terminal.clone()).await)
        }
        Err(_) => None,
    };
    let forwarding = match execution_events_task.as_mut() {
        Some(forwarder) => forwarder.join().await,
        None => Ok(Ok(())),
    };
    if !matches!(forwarding, Ok(Ok(()))) {
        let _ = request_active_cancel(&execution_gate, Some(control.clone())).await;
        let _ = runner_tx
            .send(RunnerEvent::RecoveryBlocked {
                command_id: command.command_id,
            })
            .await;
        return;
    }
    let terminal = match claimed_terminal {
        Some(terminal) => terminal,
        None => {
            // 威胁场景：vendor completion channel 已失败，但 durable event forwarder 已
            // 完整排空；若不先 exact fence process group 就写 Interrupted，残留子进程仍可
            // 继续产生副作用。只有取得 fence 证明后才允许该 terminal 收口。
            match claim_interrupted_after_exact_fence(&execution_gate, Some(control.clone())).await
            {
                Ok(Some(terminal)) => terminal,
                Ok(None) | Err(_) => {
                    let _ = runner_tx
                        .send(RunnerEvent::RecoveryBlocked {
                            command_id: command.command_id,
                        })
                        .await;
                    return;
                }
            }
        }
    };
    let completion = CompleteCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        turn_id,
        terminal,
    };
    if !complete_command_with_event_exact(&store, completion).await {
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

async fn mark_conversation_recovery_blocked_exact(
    store: &RuntimeStoreHandle,
    input: MarkConversationRecoveryBlocked,
) -> Result<ConversationRecord, RuntimeStoreError> {
    match store
        .mark_conversation_recovery_blocked(input.clone())
        .await
    {
        Ok(conversation) => Ok(conversation),
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::MarkConversationRecoveryBlocked,
        }) => store.mark_conversation_recovery_blocked(input).await,
        Err(error) => Err(error),
    }
}

async fn complete_command_with_event_exact(
    store: &RuntimeStoreHandle,
    input: CompleteCommand,
) -> bool {
    match store.complete_command_with_event(input.clone()).await {
        Ok(_) => true,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: super::store::RuntimeCommitOperation::CompleteCommand,
        }) => store.complete_command_with_event(input).await.is_ok(),
        Err(_) => false,
    }
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

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex as StdMutex, OnceLock};

    use crate::runtime::store::{SanitizedTerminalFailure, TerminalState};
    use agentdeck_protocol::runtime::{
        CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{
        ActionDecision, ActionKind, ActionRequest, ActionRequestVendor, AgentItem, AgentItemMeta,
        AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode, TurnSummary,
    };

    use super::*;
    use crate::agent::adapter_event_channel;
    use crate::runtime::approval::{
        ApprovalAttemptKey, ApprovalDeliveryOutcome, ApprovalPolicySnapshot,
        ApprovalPrincipalCapability, BoundApprovalDelivery,
    };
    use crate::runtime::connection::{ApprovalPermissionGrant, PrincipalIssuer};
    use crate::runtime::execution::{
        DisabledExecutionCoordinator, PreparedRuntimeExecution, RuntimeExecutionEvent,
        RuntimeExecutionRelease, RuntimeProcessIdentity, runtime_execution_event_channel,
    };
    use crate::runtime::store::{
        CommandReceiptSelector, CommandState, ConfigurationRecord, ConfigureConversation,
        ConfigureConversationOutcome, ConversationDescriptor, IdempotencyOwner, NewConversation,
        QueryCommandReceipt, RecoveryCursor, RuntimeClock, RuntimeClockError,
        RuntimeCommitOperation, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreFaultInjector,
        RuntimeStoreOperation,
    };
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    fn configuration_test_conversation(agent_kind: AgentKind) -> ConversationRecord {
        ConversationRecord {
            conversation_id: runtime_id(RuntimeIdKind::Conversation, 0xF1),
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0xF2),
            catalog_revision: 1,
            command_high_water: Some(0),
            event_high_water: None,
            accepted_command_count: 1,
            lifecycle: crate::runtime::store::ConversationLifecycle::Active,
            created_at_ms: 1,
            updated_at_ms: 1,
            descriptor: ConversationDescriptor {
                agent_kind,
                title: None,
                cwd: PathBuf::from("/tmp"),
            },
        }
    }

    #[test]
    fn pinned_execution_configuration_preserves_exact_revision_and_value() {
        let conversation = configuration_test_conversation(AgentKind::Codex);
        let configuration = ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
            CodexConversationConfiguration::new(
                CodexApprovalPolicy::Never,
                CodexSandboxMode::ReadOnly,
                CodexReasoningEffort::High,
            ),
        ));

        assert_eq!(
            resolve_execution_configuration(
                &conversation,
                CommandExecutionConfiguration::Pinned {
                    configuration_revision: 7,
                    configuration: configuration.clone(),
                },
            ),
            Ok((7, configuration))
        );
    }

    #[test]
    fn execution_configuration_agent_mismatch_is_rejected() {
        let conversation = configuration_test_conversation(AgentKind::Codex);
        let configuration =
            ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
                ClaudeCodeConversationConfiguration::new(
                    ClaudeCodePermissionMode::Plan,
                    None,
                    None,
                    None,
                )
                .expect("bounded Claude Code configuration"),
            ));

        assert_eq!(
            resolve_execution_configuration(
                &conversation,
                CommandExecutionConfiguration::Pinned {
                    configuration_revision: 2,
                    configuration,
                },
            ),
            Err(())
        );
    }

    #[test]
    fn legacy_revision_zero_materializes_frozen_p37_defaults_for_both_agents() {
        let codex = resolve_execution_configuration(
            &configuration_test_conversation(AgentKind::Codex),
            CommandExecutionConfiguration::LegacyRevisionZero {
                agent_kind: AgentKind::Codex,
            },
        )
        .expect("Codex legacy default");
        assert_eq!(codex.0, 0);
        assert_eq!(
            codex.1,
            ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                CodexConversationConfiguration::new(
                    CodexApprovalPolicy::OnRequest,
                    CodexSandboxMode::WorkspaceWrite,
                    CodexReasoningEffort::Medium,
                ),
            ))
        );

        let claude_code = resolve_execution_configuration(
            &configuration_test_conversation(AgentKind::ClaudeCode),
            CommandExecutionConfiguration::LegacyRevisionZero {
                agent_kind: AgentKind::ClaudeCode,
            },
        )
        .expect("Claude Code legacy default");
        assert_eq!(claude_code.0, 0);
        assert_eq!(
            claude_code.1,
            ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
                ClaudeCodeConversationConfiguration::new(
                    ClaudeCodePermissionMode::Default,
                    None,
                    None,
                    None,
                )
                .expect("bounded Claude Code configuration"),
            ))
        );
    }

    #[test]
    fn regular_revision_zero_start_rejection_blocks_without_reclassifying_cancel_races() {
        assert_eq!(
            classify_start_failure(
                QueuedCommandProvenance::Live,
                0,
                &RuntimeStoreError::InvalidStateTransition,
            ),
            StartFailureDisposition::RecoveryBlocked
        );
        assert_eq!(
            classify_start_failure(
                QueuedCommandProvenance::Live,
                1,
                &RuntimeStoreError::InvalidStateTransition,
            ),
            StartFailureDisposition::Finished
        );
        assert_eq!(
            classify_start_failure(
                QueuedCommandProvenance::StartupRecovery,
                0,
                &RuntimeStoreError::InvalidStateTransition,
            ),
            StartFailureDisposition::Finished
        );
        assert_eq!(
            classify_start_failure(
                QueuedCommandProvenance::Live,
                0,
                &RuntimeStoreError::CommandExpired,
            ),
            StartFailureDisposition::Finished
        );
    }

    struct NoopApprovalDelivery {
        policy: ApprovalPolicySnapshot,
    }

    struct DeadlineApprovalDelivery {
        policy: ApprovalPolicySnapshot,
        deliver_calls: AtomicUsize,
    }

    struct GatedApprovalDelivery {
        policy: ApprovalPolicySnapshot,
        calls: AtomicUsize,
        entered: tokio::sync::Notify,
        gate: Semaphore,
        active: AtomicUsize,
        completed: AtomicUsize,
    }

    impl GatedApprovalDelivery {
        fn new() -> Self {
            Self {
                policy: ApprovalPolicySnapshot {
                    agent_kind: AgentKind::Codex,
                    action_kind: ActionKind::ExecuteCommand,
                    allow_approve: true,
                    allow_deny: true,
                    allow_persist: false,
                    deadline_at_ms: None,
                },
                calls: AtomicUsize::new(0),
                entered: tokio::sync::Notify::new(),
                gate: Semaphore::new(0),
                active: AtomicUsize::new(0),
                completed: AtomicUsize::new(0),
            }
        }

        async fn wait_until_called(&self) {
            tokio::time::timeout(Duration::from_secs(2), async {
                while self.calls.load(Ordering::SeqCst) == 0 {
                    self.entered.notified().await;
                }
            })
            .await
            .expect("approval delivery starts");
        }

        fn release(&self) {
            self.gate.add_permits(1);
        }
    }

    #[async_trait::async_trait]
    impl BoundApprovalDelivery for GatedApprovalDelivery {
        fn policy(&self) -> &ApprovalPolicySnapshot {
            &self.policy
        }

        async fn deliver(
            &self,
            _key: ApprovalAttemptKey,
            _decision: &ActionDecision,
        ) -> ApprovalDeliveryOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.active.fetch_add(1, Ordering::SeqCst);
            struct ActiveDeliveryGuard<'a>(&'a AtomicUsize);
            impl Drop for ActiveDeliveryGuard<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _active = ActiveDeliveryGuard(&self.active);
            self.entered.notify_waiters();
            let _permit = self
                .gate
                .acquire()
                .await
                .expect("gated delivery remains open");
            self.completed.fetch_add(1, Ordering::SeqCst);
            ApprovalDeliveryOutcome::AppliedAck
        }
    }

    struct SequencedApprovalDelivery {
        policy: ApprovalPolicySnapshot,
        outcomes: StdMutex<VecDeque<ApprovalDeliveryOutcome>>,
        decisions: StdMutex<Vec<(String, agentdeck_protocol::ActionDecisionKind, bool)>>,
    }

    impl SequencedApprovalDelivery {
        fn fail_then_apply() -> Self {
            Self {
                policy: ApprovalPolicySnapshot {
                    agent_kind: AgentKind::Codex,
                    action_kind: ActionKind::ExecuteCommand,
                    allow_approve: true,
                    allow_deny: true,
                    allow_persist: false,
                    deadline_at_ms: None,
                },
                outcomes: StdMutex::new(VecDeque::from([
                    ApprovalDeliveryOutcome::PermanentlyRejected,
                    ApprovalDeliveryOutcome::AppliedAck,
                ])),
                decisions: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl BoundApprovalDelivery for SequencedApprovalDelivery {
        fn policy(&self) -> &ApprovalPolicySnapshot {
            &self.policy
        }

        async fn deliver(
            &self,
            _key: ApprovalAttemptKey,
            decision: &ActionDecision,
        ) -> ApprovalDeliveryOutcome {
            self.decisions
                .lock()
                .expect("approval decisions lock")
                .push((
                    decision.request_id.clone(),
                    decision.decision,
                    decision.persist,
                ));
            self.outcomes
                .lock()
                .expect("approval outcomes lock")
                .pop_front()
                .expect("one outcome per delivery round")
        }
    }

    struct PanicsThenAppliesDelivery {
        policy: ApprovalPolicySnapshot,
        calls: AtomicUsize,
    }

    impl PanicsThenAppliesDelivery {
        fn new() -> Self {
            Self {
                policy: ApprovalPolicySnapshot {
                    agent_kind: AgentKind::Codex,
                    action_kind: ActionKind::ExecuteCommand,
                    allow_approve: true,
                    allow_deny: true,
                    allow_persist: false,
                    deadline_at_ms: None,
                },
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl BoundApprovalDelivery for PanicsThenAppliesDelivery {
        fn policy(&self) -> &ApprovalPolicySnapshot {
            &self.policy
        }

        async fn deliver(
            &self,
            _key: ApprovalAttemptKey,
            _decision: &ActionDecision,
        ) -> ApprovalDeliveryOutcome {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("injected bound delivery panic");
            }
            ApprovalDeliveryOutcome::AppliedAck
        }
    }

    #[async_trait::async_trait]
    impl BoundApprovalDelivery for NoopApprovalDelivery {
        fn policy(&self) -> &ApprovalPolicySnapshot {
            &self.policy
        }

        async fn deliver(
            &self,
            _key: ApprovalAttemptKey,
            _decision: &ActionDecision,
        ) -> ApprovalDeliveryOutcome {
            ApprovalDeliveryOutcome::PermanentlyRejected
        }
    }

    #[async_trait::async_trait]
    impl BoundApprovalDelivery for DeadlineApprovalDelivery {
        fn policy(&self) -> &ApprovalPolicySnapshot {
            &self.policy
        }

        async fn deliver(
            &self,
            _key: ApprovalAttemptKey,
            _decision: &ActionDecision,
        ) -> ApprovalDeliveryOutcome {
            self.deliver_calls.fetch_add(1, Ordering::SeqCst);
            ApprovalDeliveryOutcome::AppliedAck
        }
    }

    fn approval_request() -> ActionRequest {
        approval_request_with_id("actor-request-1")
    }

    fn approval_request_with_id(request_id: impl Into<String>) -> ActionRequest {
        ActionRequest {
            request_id: request_id.into(),
            kind: ActionKind::ExecuteCommand,
            summary: "actor approval request".to_owned(),
            vendor: ActionRequestVendor::Codex {
                approval_policy_at_decision: CodexApprovalPolicy::OnRequest,
                sandbox_at_decision: CodexSandboxMode::WorkspaceWrite,
                can_persist: false,
            },
        }
    }

    fn approval_delivery() -> Arc<dyn BoundApprovalDelivery> {
        Arc::new(NoopApprovalDelivery {
            policy: ApprovalPolicySnapshot {
                agent_kind: AgentKind::Codex,
                action_kind: ActionKind::ExecuteCommand,
                allow_approve: true,
                allow_deny: true,
                allow_persist: false,
                deadline_at_ms: None,
            },
        })
    }

    fn expired_approval_record(with_winner: bool) -> ApprovalRecord {
        ApprovalRecord {
            approval_id: runtime_id(RuntimeIdKind::Approval, 0x61),
            conversation_id: runtime_id(RuntimeIdKind::Conversation, 0x62),
            command_id: runtime_id(RuntimeIdKind::Command, 0x63),
            turn_id: runtime_id(RuntimeIdKind::Turn, 0x64),
            state: ApprovalState::Expired,
            request: approval_request(),
            policy: approval_delivery().policy().clone(),
            decision: with_winner.then(|| ActionDecision {
                request_id: "actor-request-1".to_owned(),
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                persist: false,
            }),
            requested_at_ms: 1,
            deadline_at_ms: 2,
            claimed_at_ms: with_winner.then_some(1),
            state_changed_at_ms: 2,
            delivery_round: u32::from(with_winner),
            attempts_in_round: u8::from(with_winner),
            round_started_at_ms: with_winner.then_some(1),
            last_attempt_at_ms: with_winner.then_some(1),
            state_version: if with_winner { 4 } else { 2 },
            last_event_id: runtime_id(RuntimeIdKind::Event, 0x65),
            status_detail: None,
        }
    }

    #[test]
    fn expired_receipt_preserves_claimed_winner_but_pending_expiry_has_none() {
        let pending = approval_receipt_for_resolve(ApprovalMutationOutcome::ExpiredOrStale {
            approval: expired_approval_record(false),
        })
        .expect("pending expiry receipt");
        assert!(matches!(pending, ApprovalReceipt::Expired { .. }));

        let claimed = approval_receipt_for_resolve(ApprovalMutationOutcome::ExpiredOrStale {
            approval: expired_approval_record(true),
        })
        .expect("claimed expiry receipt");
        assert!(matches!(
            claimed,
            ApprovalReceipt::AlreadyHandled {
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                state: ApprovalDeliveryState::Expired,
                ..
            }
        ));

        let exact_replay = receipt_for_exact_winner(expired_approval_record(true), true)
            .expect("exact claimed expiry replay");
        assert!(matches!(
            exact_replay,
            ApprovalReceipt::AlreadyHandled {
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                state: ApprovalDeliveryState::Expired,
                ..
            }
        ));

        // A later opposing resolve is represented by AlreadyHandled; the receipt must still
        // expose the immutable persisted winner rather than the caller's attempted decision.
        let opposing = approval_receipt_for_resolve(ApprovalMutationOutcome::AlreadyHandled {
            approval: expired_approval_record(true),
        })
        .expect("opposing resolve observes expired winner");
        assert!(matches!(
            opposing,
            ApprovalReceipt::AlreadyHandled {
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                state: ApprovalDeliveryState::Expired,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn execution_action_request_is_forwarded_to_the_bounded_actor_lane() {
        let root = TestRoot::new("execution-action-forwarder");
        let store = root.open().await;
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x30);
        let command_id = runtime_id(RuntimeIdKind::Command, 0x31);
        let turn_id = runtime_id(RuntimeIdKind::Turn, 0x32);
        let (execution_tx, execution_rx) = runtime_execution_event_channel();
        let (runner_tx, mut runner_rx) = mpsc::channel(1);
        let forwarder = tokio::spawn(forward_execution_events(
            conversation_id,
            command_id,
            turn_id,
            store.clone(),
            execution_rx,
            runner_tx,
        ));

        execution_tx
            .send(RuntimeExecutionEvent::ActionRequest {
                request: approval_request(),
                delivery: approval_delivery(),
                registration_ack: None,
            })
            .await
            .expect("send bounded execution event");

        match runner_rx.recv().await.expect("forwarded actor event") {
            RunnerEvent::ApprovalRequested {
                command_id: observed_command,
                turn_id: observed_turn,
                request,
                acknowledged,
                ..
            } => {
                assert_eq!(observed_command, command_id);
                assert_eq!(observed_turn, turn_id);
                assert_eq!(request.request_id, "actor-request-1");
                acknowledged.send(Ok(())).expect("ack registration");
            }
            _ => panic!("expected approval request runner event"),
        }
        drop(execution_tx);
        assert_eq!(forwarder.await.expect("join event forwarder"), Ok(()));
        store.shutdown().await.expect("shutdown forwarder store");
    }

    #[tokio::test]
    async fn execution_event_store_failure_is_a_negative_ack_and_forwarder_failure() {
        // 威胁场景：event append 失败后 adapter 只看到普通 completion error；若 daemon
        // 不保留独立 forwarder barrier，仍可能把同一 turn 写成 Failed/Interrupted terminal。
        let root = TestRoot::new("execution-event-negative-ack");
        let store = root.open().await;
        let (execution_tx, execution_rx) = runtime_execution_event_channel();
        let (runner_tx, _runner_rx) = mpsc::channel(1);
        let forwarder = tokio::spawn(forward_execution_events(
            runtime_id(RuntimeIdKind::Conversation, 0x70),
            runtime_id(RuntimeIdKind::Command, 0x71),
            runtime_id(RuntimeIdKind::Turn, 0x72),
            store.clone(),
            execution_rx,
            runner_tx,
        ));
        let (sink, mut adapter_rx) = adapter_event_channel();
        let adapter = tokio::spawn(async move {
            sink.send(AdapterEvent::Item {
                key: AdapterItemKey::new("negative-ack-item").unwrap(),
                item: AgentItem::AssistantMessage {
                    text: "must not become a terminal".to_owned(),
                    meta: AgentItemMeta::default(),
                },
            })
            .await
        });
        let delivery = adapter_rx.recv().await.expect("adapter event delivery");
        execution_tx
            .send(RuntimeExecutionEvent::Adapter { delivery })
            .await
            .expect("forward failing adapter event");
        drop(execution_tx);
        assert_eq!(
            forwarder.await.expect("join failed event forwarder"),
            Err(ExecutionEventForwardError::EventDurabilityLost)
        );
        assert!(
            adapter.await.expect("join negative ACK adapter").is_err(),
            "store failure must be observed by the adapter sink"
        );
        store.shutdown().await.expect("shutdown negative ACK store");
    }

    #[test]
    fn stale_fatal_delivery_completion_cannot_block_the_new_generation() {
        assert_eq!(
            classify_approval_task_completion(
                ApprovalTaskKind::Delivery,
                1,
                None,
                ApprovalWorkerResult::FatalClosure,
            ),
            ApprovalTaskCompletionDisposition::IgnoreStale
        );
        assert_eq!(
            classify_approval_task_completion(
                ApprovalTaskKind::Delivery,
                1,
                Some(2),
                ApprovalWorkerResult::FatalClosure,
            ),
            ApprovalTaskCompletionDisposition::IgnoreStale
        );
        assert_eq!(
            classify_approval_task_completion(
                ApprovalTaskKind::Delivery,
                2,
                Some(2),
                ApprovalWorkerResult::FatalClosure,
            ),
            ApprovalTaskCompletionDisposition::RecoveryBlocked
        );
    }

    #[tokio::test]
    async fn panicking_approval_worker_is_reported_and_does_not_panic_the_actor_lane() {
        let approval_id = runtime_id(RuntimeIdKind::Approval, 0x39);
        let (runner_tx, mut runner_rx) = mpsc::channel(1);
        let mut supervisor = spawn_approval_task(
            approval_id,
            ApprovalTaskKind::Delivery,
            1,
            runner_tx,
            async move {
                panic!("injected bound delivery panic");
            },
        );

        assert!(matches!(
            runner_rx.recv().await,
            Some(RunnerEvent::ApprovalTaskFinished {
                approval_id: observed,
                task_kind: ApprovalTaskKind::Delivery,
                result: ApprovalWorkerResult::StoreBlocked,
                ..
            }) if observed == approval_id
        ));
        supervisor.join().await.expect("supervisor contains panic");
    }

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

    #[derive(Clone, Copy, Debug)]
    struct ZeroApprovalBackoff;

    impl ApprovalBackoff for ZeroApprovalBackoff {
        fn delay_before_attempt(&self, _attempt: u8) -> Option<Duration> {
            Some(Duration::ZERO)
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

    #[derive(Clone, Copy, Debug)]
    enum InjectedStoreFailure {
        WorkerStopped,
        Corrupt,
    }

    #[derive(Debug)]
    struct FailStoreOperationOnce {
        operation: RuntimeStoreOperation,
        failure: InjectedStoreFailure,
        armed: AtomicBool,
    }

    impl FailStoreOperationOnce {
        fn new(operation: RuntimeStoreOperation, failure: InjectedStoreFailure) -> Self {
            Self {
                operation,
                failure,
                armed: AtomicBool::new(true),
            }
        }
    }

    impl RuntimeStoreFaultInjector for FailStoreOperationOnce {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation != self.operation || !self.armed.swap(false, Ordering::SeqCst) {
                return Ok(());
            }
            Err(match self.failure {
                InjectedStoreFailure::WorkerStopped => RuntimeStoreError::WorkerStopped,
                InjectedStoreFailure::Corrupt => RuntimeStoreError::UnknownOrCorruptSchema,
            })
        }
    }

    #[derive(Debug)]
    struct BlockStoreOperation {
        operation: RuntimeStoreOperation,
        entered: AtomicBool,
        released: StdMutex<bool>,
        released_changed: Condvar,
    }

    impl BlockStoreOperation {
        fn new(operation: RuntimeStoreOperation) -> Self {
            Self {
                operation,
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

    impl RuntimeStoreFaultInjector for BlockStoreOperation {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == self.operation {
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

    #[derive(Debug)]
    struct BlockClaimCommit {
        entered: AtomicBool,
        released: StdMutex<bool>,
        released_changed: Condvar,
    }

    impl BlockClaimCommit {
        fn new() -> Self {
            Self {
                entered: AtomicBool::new(false),
                released: StdMutex::new(false),
                released_changed: Condvar::new(),
            }
        }

        fn release(&self) {
            *self.released.lock().expect("claim blocker lock") = true;
            self.released_changed.notify_all();
        }
    }

    impl RuntimeStoreFaultInjector for BlockClaimCommit {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::ClaimApprovalBeforeCommit {
                self.entered.store(true, Ordering::SeqCst);
                let mut released = self.released.lock().expect("claim blocker lock");
                while !*released {
                    released = self
                        .released_changed
                        .wait(released)
                        .expect("claim blocker wait");
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
    pub(crate) struct FakeCoordinator {
        inner: Arc<FakeCoordinatorInner>,
    }

    struct FakeCoordinatorInner {
        held: bool,
        prepare_gate: Option<Arc<Semaphore>>,
        release_gate: Option<Arc<Semaphore>>,
        behavior: FakeBehavior,
        starts: StdMutex<Vec<StartObservation>>,
        completions: StdMutex<Vec<(RuntimeId, TerminalState)>>,
        controls: StdMutex<HashMap<RuntimeId, Arc<FakeControl>>>,
        changed: tokio::sync::Notify,
        next_pid: AtomicI64,
        active: Arc<AtomicUsize>,
        peak: AtomicUsize,
        releases: AtomicUsize,
        approval_delivery: StdMutex<Option<SharedApprovalDelivery>>,
        approval_events: StdMutex<Option<mpsc::Sender<RuntimeExecutionEvent>>>,
        approval_emission_enabled: AtomicBool,
        prepare_failed_clean_once: AtomicBool,
        prepare_failed_once: AtomicBool,
    }

    struct FakeControl {
        gate: Arc<Semaphore>,
        canceled: AtomicBool,
        cancel_count: AtomicUsize,
        cancel_fails: bool,
    }

    struct AlreadyCompletingControl {
        cancel_count: AtomicUsize,
    }

    #[derive(Clone, Copy, Default)]
    struct FakeBehavior {
        completion_error: bool,
        release_error: bool,
        cancel_fails: bool,
        panic_prepare: bool,
        emit_approval: bool,
        block_release: bool,
        stall_completion_after_fence: bool,
        prepare_failed_clean_once: bool,
        prepare_failed_once: bool,
    }

    struct FakeRelease {
        expected_command_id: RuntimeId,
        expected_daemon_boot_id: RuntimeId,
        expected_execution_nonce: Vec<u8>,
        expected_process: RuntimeProcessIdentity,
        control: Arc<FakeControl>,
        inner: Arc<FakeCoordinatorInner>,
        active_guard: Option<ActiveCounterGuard>,
    }

    #[async_trait::async_trait]
    impl RuntimeExecutionControl for FakeControl {
        async fn cancel_and_wait_fenced(
            &self,
        ) -> Result<RuntimeCancelDisposition, RuntimeExecutionError> {
            self.canceled.store(true, Ordering::SeqCst);
            self.cancel_count.fetch_add(1, Ordering::SeqCst);
            if self.cancel_fails {
                return Err(RuntimeExecutionError::CancelFailed);
            }
            self.gate.add_permits(1);
            Ok(RuntimeCancelDisposition::UserCancelWon)
        }
    }

    #[async_trait::async_trait]
    impl RuntimeExecutionControl for AlreadyCompletingControl {
        async fn cancel_and_wait_fenced(
            &self,
        ) -> Result<RuntimeCancelDisposition, RuntimeExecutionError> {
            self.cancel_count.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeCancelDisposition::AlreadyCompleting)
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
                || permit.process_group_id() != self.expected_process.process_group_id
                || permit.leader_pid() != self.expected_process.leader_pid
                || permit.leader_start_time() != self.expected_process.leader_start_time
                || permit.fence_payload() != self.expected_process.fence_payload
                || permit.release_authorized_at_ms() == 0
            {
                return Err(RuntimeExecutionError::ReleaseAuthorizationInvalid);
            }
            self.inner.releases.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.inner.release_gate {
                let _permit = gate
                    .acquire()
                    .await
                    .map_err(|_| RuntimeExecutionError::ReleaseFailed)?;
            }
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
                // Fake completion mirrors production adapter drop: the execution event sender
                // must close so the durable forwarder can drain before terminal COMMIT.
                inner
                    .approval_events
                    .lock()
                    .expect("approval events lock")
                    .take();
                if inner.behavior.stall_completion_after_fence {
                    std::future::pending::<()>().await;
                }
                if inner.behavior.completion_error {
                    return Err(RuntimeExecutionError::CompletionClosed);
                }
                let terminal = if completion_control.canceled.load(Ordering::SeqCst) {
                    // Production driver 在 exact-group cancel 后从 vendor stdout 读到 EOF，
                    // release owner 只能先给出 Failed；用户取消语义必须由 actor 的 typed
                    // race state 覆盖，fake 不能替 production 偷做这个判断。
                    CommandTerminal::failed(SanitizedTerminalFailure::execution_failed())
                } else {
                    CommandTerminal::completed(TurnSummary {
                        total_input_tokens: None,
                        total_output_tokens: None,
                        elapsed_ms: 0,
                    })
                };
                inner
                    .completions
                    .lock()
                    .expect("completions lock")
                    .push((command_id, terminal.terminal_state()));
                inner.changed.notify_waiters();
                Ok(RuntimeExecutionCompletion { terminal })
            }))
        }
    }

    impl FakeCoordinator {
        pub(crate) fn held() -> Self {
            Self::new(true, false, FakeBehavior::default())
        }

        fn automatic() -> Self {
            Self::new(false, false, FakeBehavior::default())
        }

        fn blocked_prepare() -> Self {
            Self::new(true, true, FakeBehavior::default())
        }

        fn clean_prepare_failure_once() -> Self {
            Self::new(
                false,
                false,
                FakeBehavior {
                    prepare_failed_clean_once: true,
                    ..FakeBehavior::default()
                },
            )
        }

        fn blocked_clean_prepare_failure_once() -> Self {
            Self::new(
                false,
                true,
                FakeBehavior {
                    prepare_failed_clean_once: true,
                    ..FakeBehavior::default()
                },
            )
        }

        fn prepare_failure_once() -> Self {
            Self::new(
                false,
                false,
                FakeBehavior {
                    prepare_failed_once: true,
                    ..FakeBehavior::default()
                },
            )
        }

        fn held_with_approval(delivery: SharedApprovalDelivery) -> Self {
            let fake = Self::new(
                true,
                false,
                FakeBehavior {
                    emit_approval: true,
                    ..FakeBehavior::default()
                },
            );
            *fake
                .inner
                .approval_delivery
                .lock()
                .expect("approval delivery lock") = Some(delivery);
            fake
        }

        fn held_with_approval_stalled_after_fence(delivery: SharedApprovalDelivery) -> Self {
            let fake = Self::new(
                true,
                false,
                FakeBehavior {
                    emit_approval: true,
                    stall_completion_after_fence: true,
                    ..FakeBehavior::default()
                },
            );
            *fake
                .inner
                .approval_delivery
                .lock()
                .expect("approval delivery lock") = Some(delivery);
            fake
        }

        fn held_with_approval_and_blocked_release(delivery: SharedApprovalDelivery) -> Self {
            let fake = Self::new(
                true,
                false,
                FakeBehavior {
                    emit_approval: true,
                    block_release: true,
                    ..FakeBehavior::default()
                },
            );
            *fake
                .inner
                .approval_delivery
                .lock()
                .expect("approval delivery lock") = Some(delivery);
            fake
        }

        fn recovery_blocked_with_approval(delivery: SharedApprovalDelivery) -> Self {
            let fake = Self::new(
                true,
                false,
                FakeBehavior {
                    completion_error: true,
                    cancel_fails: true,
                    emit_approval: true,
                    ..FakeBehavior::default()
                },
            );
            *fake
                .inner
                .approval_delivery
                .lock()
                .expect("approval delivery lock") = Some(delivery);
            fake
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

        fn release_error_with_approval(delivery: SharedApprovalDelivery) -> Self {
            let fake = Self::new(
                false,
                false,
                FakeBehavior {
                    release_error: true,
                    emit_approval: true,
                    ..FakeBehavior::default()
                },
            );
            *fake
                .inner
                .approval_delivery
                .lock()
                .expect("approval delivery lock") = Some(delivery);
            fake
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
                    release_gate: behavior.block_release.then(|| Arc::new(Semaphore::new(0))),
                    behavior,
                    starts: StdMutex::new(Vec::new()),
                    completions: StdMutex::new(Vec::new()),
                    controls: StdMutex::new(HashMap::new()),
                    changed: tokio::sync::Notify::new(),
                    next_pid: AtomicI64::new(10_000),
                    active: Arc::new(AtomicUsize::new(0)),
                    peak: AtomicUsize::new(0),
                    releases: AtomicUsize::new(0),
                    approval_delivery: StdMutex::new(None),
                    approval_events: StdMutex::new(None),
                    approval_emission_enabled: AtomicBool::new(behavior.emit_approval),
                    prepare_failed_clean_once: AtomicBool::new(behavior.prepare_failed_clean_once),
                    prepare_failed_once: AtomicBool::new(behavior.prepare_failed_once),
                }),
            }
        }

        async fn emit_approval(&self, request: ActionRequest, delivery: SharedApprovalDelivery) {
            let sender = self
                .inner
                .approval_events
                .lock()
                .expect("approval events lock")
                .clone()
                .expect("approval execution stream is installed");
            sender
                .send(RuntimeExecutionEvent::ActionRequest {
                    request,
                    delivery,
                    registration_ack: None,
                })
                .await
                .expect("send fake approval event");
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

        pub(crate) fn active(&self) -> usize {
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

        fn allow_release(&self) {
            self.inner
                .release_gate
                .as_ref()
                .expect("blocked release coordinator")
                .add_permits(1);
        }

        pub(crate) fn release(&self, command_id: RuntimeId) {
            self.inner
                .controls
                .lock()
                .expect("controls lock")
                .get(&command_id)
                .expect("known fake command")
                .gate
                .add_permits(1);
        }

        fn disable_approval_emission(&self) {
            self.inner
                .approval_emission_enabled
                .store(false, Ordering::SeqCst);
        }

        pub(crate) async fn wait_for_starts(&self, expected: usize) {
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
            if self
                .inner
                .prepare_failed_clean_once
                .swap(false, Ordering::SeqCst)
            {
                if let Some(gate) = &self.inner.prepare_gate {
                    let _permit = gate
                        .acquire()
                        .await
                        .map_err(|_| RuntimeExecutionError::PrepareFailed)?;
                }
                return Err(RuntimeExecutionError::PrepareFailedClean);
            }
            if self.inner.prepare_failed_once.swap(false, Ordering::SeqCst) {
                return Err(RuntimeExecutionError::PrepareFailed);
            }
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
            let events = if self.inner.approval_emission_enabled.load(Ordering::SeqCst) {
                let (sender, receiver) = runtime_execution_event_channel();
                sender
                    .try_send(RuntimeExecutionEvent::ActionRequest {
                        request: approval_request(),
                        delivery: self
                            .inner
                            .approval_delivery
                            .lock()
                            .expect("approval delivery lock")
                            .clone()
                            .unwrap_or_else(approval_delivery),
                        registration_ack: None,
                    })
                    .expect("fake approval event fits bounded channel");
                *self
                    .inner
                    .approval_events
                    .lock()
                    .expect("approval events lock") = Some(sender);
                receiver
            } else {
                crate::runtime::execution::closed_execution_events()
            };
            let process = RuntimeProcessIdentity {
                process_group_id: process_id,
                leader_pid: process_id,
                leader_start_time: u64::try_from(process_id).expect("positive fake pid"),
                fence_payload: b"side-effect-free-test-fence".to_vec(),
            };
            Ok(PreparedRuntimeExecution {
                process: process.clone(),
                control,
                release: Box::new(FakeRelease {
                    expected_command_id: context.command.command_id,
                    expected_daemon_boot_id: context.daemon_boot_id,
                    expected_execution_nonce: context.execution_nonce,
                    expected_process: process,
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
                events,
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
        let conversation = store
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
            .expect("create actor conversation");
        let configured = store
            .configure_conversation(ConfigureConversation {
                conversation_id: conversation.conversation_id,
                owner: IdempotencyOwner::Local {
                    machine_trust_domain: [0xA1; 32],
                    uid: 501,
                    client_installation_id: [seed; 16],
                },
                idempotency_key: format!("actor-configuration-{seed}"),
                expected_configuration_revision: 0,
                configuration: ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                    CodexConversationConfiguration::new(
                        CodexApprovalPolicy::OnRequest,
                        CodexSandboxMode::WorkspaceWrite,
                        CodexReasoningEffort::Medium,
                    ),
                )),
            })
            .await
            .expect("configure actor conversation");
        assert!(
            matches!(
                configured,
                ConfigureConversationOutcome::Applied {
                    configuration: ConfigurationRecord {
                        configuration_revision: 1,
                        ..
                    }
                }
            ),
            "actor fixture must apply configuration revision one"
        );
        conversation
    }

    async fn wait_for_approval_count(path: &Path, expected: i64) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let connection = rusqlite::Connection::open_with_flags(
                    path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .expect("open runtime DB read-only");
                let count: i64 = connection
                    .query_row(
                        "SELECT approval_count FROM runtime_meta WHERE singleton = 1",
                        [],
                        |row| row.get(0),
                    )
                    .expect("read approval count");
                if count == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("approval count reaches expected value");
    }

    fn read_only_approval_count(path: &Path) -> i64 {
        let connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open runtime DB read-only");
        connection
            .query_row(
                "SELECT approval_count FROM runtime_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read approval count")
    }

    fn read_only_approval_id(path: &Path) -> RuntimeId {
        let connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open runtime DB read-only");
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT approval_id FROM approval_ledger ORDER BY requested_at_ms LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("read approval id");
        RuntimeId::from_bytes(
            RuntimeIdKind::Approval,
            <[u8; 16]>::try_from(bytes.as_slice()).expect("approval id is 16 bytes"),
        )
        .expect("valid approval id")
    }

    fn read_only_command_turn_id(path: &Path, command_id: RuntimeId) -> RuntimeId {
        let connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open runtime DB read-only");
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT turn_id FROM commands WHERE command_id = ?1",
                rusqlite::params![command_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("read command turn id");
        RuntimeId::from_bytes(
            RuntimeIdKind::Turn,
            <[u8; 16]>::try_from(bytes.as_slice()).expect("turn id is 16 bytes"),
        )
        .expect("valid turn id")
    }

    async fn wait_for_approval_state(path: &Path, expected: &str) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let connection = rusqlite::Connection::open_with_flags(
                    path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .expect("open runtime DB read-only");
                let state: String = connection
                    .query_row(
                        "SELECT state FROM approval_ledger ORDER BY requested_at_ms LIMIT 1",
                        [],
                        |row| row.get(0),
                    )
                    .expect("read approval state");
                if state == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("approval reaches expected state");
    }

    fn read_only_approval_state(path: &Path) -> String {
        let connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open runtime DB read-only");
        connection
            .query_row(
                "SELECT state FROM approval_ledger ORDER BY requested_at_ms LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("read approval state")
    }

    fn read_only_conversation_lifecycle(path: &Path) -> String {
        let connection =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open runtime DB read-only");
        connection
            .query_row(
                "SELECT lifecycle FROM conversations ORDER BY created_at_ms LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("read conversation lifecycle")
    }

    #[tokio::test]
    async fn execution_action_request_is_registered_durably_before_actor_acknowledges() {
        let root = TestRoot::new("approval-action-request");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 33).await;
        let fake = FakeCoordinator::held_with_approval_and_blocked_release(approval_delivery());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA3),
            1,
        )
        .expect("registry")
        .with_approval_runtime(
            Arc::new(SystemRuntimeClock),
            Arc::new(TokioApprovalSleeper),
            Arc::new(FixedApprovalBackoff),
        );
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(33);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "approval-event",
                "emit one action request",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_until(|| fake.release_count() == 1).await;
        assert_eq!(
            read_only_approval_count(&root.0.join("runtime.db")),
            0,
            "a prepared adapter event cannot cross the cold-release consumption boundary"
        );
        fake.allow_release();
        wait_for_approval_count(&root.0.join("runtime.db"), 1).await;
        assert_eq!(fake.cancel_count(command.command_id), 0);

        // The focused test deliberately leaves the held fake unfinished; dropping the registry
        // aborts its side-effect-free task after the durable assertion.
        drop(registry);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn delivery_transitions_to_applied_after_resolver_capability_is_dropped() {
        let root = TestRoot::new("approval-disconnect");
        let database = root.0.join("runtime.db");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 34).await;
        let delivery = Arc::new(GatedApprovalDelivery::new());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA4),
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
        let prompt_principal = local_principal(34);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-disconnect",
                "hold execution while approval applies",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xB4; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xB4; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve principal");
        let guard = resolver
            .try_enter_approval()
            .expect("enter approval resolve");
        guard.require_resolve().expect("resolve permission");
        let receipt = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                guard,
            )
            .await
            .expect("claim approval");
        assert!(matches!(receipt, ApprovalReceipt::Claimed { .. }));
        delivery.wait_until_called().await;

        // The route/worker is actor-owned. Dropping the resolver capability (the same lifetime
        // consequence as disconnecting its transport connection) must not cancel daemon delivery.
        drop(resolver);
        delivery.release();
        wait_for_approval_state(&database, "applied").await;
        assert_eq!(delivery.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fake.cancel_count(command.command_id), 0);

        drop(registry);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn approval_guard_covers_claim_commit_then_revoke_does_not_cancel_delivery() {
        let root = TestRoot::new("approval-guard-commit");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let blocker = Arc::new(BlockClaimCommit::new());
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("approval guard StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_fault_injector(blocker.clone()),
            kek,
        )
        .await
        .expect("open approval guard store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 37).await;
        let delivery = Arc::new(GatedApprovalDelivery::new());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = Arc::new(
            ConversationRegistry::new(
                store.clone(),
                Arc::new(fake.clone()),
                runtime_id(RuntimeIdKind::DaemonBoot, 0xA7),
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
        let prompt_principal = local_principal(37);
        let _command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-guard-commit",
                "block claim commit while revoking",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xB7; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xB7; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve principal");
        let guard = resolver
            .try_enter_approval()
            .expect("enter approval resolve");
        let resolving_registry = registry.clone();
        let resolve = tokio::spawn(async move {
            resolving_registry
                .resolve_approval(
                    conversation.conversation_id,
                    turn_id,
                    approval_id,
                    ActionDecision {
                        request_id: "actor-request-1".to_owned(),
                        decision: agentdeck_protocol::ActionDecisionKind::Approve,
                        persist: false,
                    },
                    guard,
                )
                .await
        });
        wait_until(|| blocker.entered.load(Ordering::SeqCst)).await;

        let revoking = resolver.clone();
        let revoke = tokio::spawn(async move { revoking.begin_revoke().await });
        tokio::task::yield_now().await;
        assert!(
            !revoke.is_finished(),
            "revoke must wait while actor owns the approval guard across COMMIT"
        );
        blocker.release();
        assert!(matches!(
            resolve
                .await
                .expect("join resolve")
                .expect("claim after blocker release"),
            ApprovalReceipt::Claimed { .. }
        ));
        revoke
            .await
            .expect("join revoke")
            .expect("revoke after claim COMMIT");
        resolver.finish_revoke();

        delivery.wait_until_called().await;
        delivery.release();
        wait_for_approval_state(&database, "applied").await;
        assert_eq!(delivery.calls.load(Ordering::SeqCst), 1);

        drop(registry);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn recovery_blocked_aborts_bound_delivery_without_fabricating_expiry() {
        let root = TestRoot::new("approval-recovery-blocked");
        let database = root.0.join("runtime.db");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 38).await;
        let delivery = Arc::new(GatedApprovalDelivery::new());
        let fake = FakeCoordinator::recovery_blocked_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA8),
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
        let prompt_principal = local_principal(38);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-recovery-blocked",
                "unknown execution outcome must stop approval",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xB8; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xB8; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve principal");
        let guard = resolver
            .try_enter_approval()
            .expect("enter approval resolve");
        let _ = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                guard,
            )
            .await
            .expect("claim approval");
        delivery.wait_until_called().await;
        assert_eq!(read_only_approval_state(&database), "applying");

        fake.release(command.command_id);
        wait_until(|| {
            fake.cancel_count(command.command_id) == 1
                && delivery.active.load(Ordering::SeqCst) == 0
        })
        .await;
        assert_eq!(delivery.completed.load(Ordering::SeqCst), 0);
        assert_eq!(
            read_only_approval_state(&database),
            "applying",
            "RecoveryBlocked lacks fence evidence and must not fabricate Expired"
        );

        drop(registry);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn panicking_bound_delivery_is_cleared_and_explicit_retry_can_apply() {
        let root = TestRoot::new("approval-panic-retry");
        let database = root.0.join("runtime.db");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 39).await;
        let delivery = Arc::new(PanicsThenAppliesDelivery::new());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA9),
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
        let prompt_principal = local_principal(39);
        let _command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-panic-retry",
                "panic is contained by approval supervisor",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xB9; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xB9; 16],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("resolve and retry principal");
        let resolve_guard = resolver
            .try_enter_approval()
            .expect("enter resolve capability");
        let _ = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolve_guard,
            )
            .await
            .expect("claim approval");
        wait_for_approval_state(&database, "applying").await;
        wait_until(|| delivery.calls.load(Ordering::SeqCst) == 1).await;
        // Give the bounded completion lane a fairness point to reap the panicked child task.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let retry_guard = resolver
            .try_enter_approval()
            .expect("enter retry capability");
        let retry = registry
            .retry_approval(conversation.conversation_id, approval_id, retry_guard)
            .await
            .expect("explicit retry after contained panic");
        assert!(matches!(
            retry,
            ApprovalReceipt::AlreadyHandled {
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                state: ApprovalDeliveryState::Applying,
                ..
            }
        ));
        wait_for_approval_state(&database, "applied").await;
        assert_eq!(delivery.calls.load(Ordering::SeqCst), 2);

        drop(registry);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn fatal_applied_closure_blocks_conversation_and_prevents_redelivery() {
        let root = TestRoot::new("approval-fatal-closure");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("fatal closure StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_fault_injector(Arc::new(
                FailStoreOperationOnce::new(
                    RuntimeStoreOperation::MarkApprovalAppliedBeforeCommit,
                    InjectedStoreFailure::Corrupt,
                ),
            )),
            kek,
        )
        .await
        .expect("open fatal closure store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 40).await;
        let delivery = Arc::new(GatedApprovalDelivery::new());
        let fake = FakeCoordinator::recovery_blocked_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xAA),
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
        let prompt_principal = local_principal(40);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-fatal-closure",
                "fatal applied closure must fence delivery",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xBA; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xBA; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve principal");
        let receipt = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolver
                    .try_enter_approval()
                    .expect("first resolve capability"),
            )
            .await
            .expect("claim approval");
        assert!(matches!(receipt, ApprovalReceipt::Claimed { .. }));
        delivery.wait_until_called().await;
        delivery.release();
        wait_until(|| fake.cancel_count(command.command_id) == 1).await;

        let replay = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolver
                    .try_enter_approval()
                    .expect("second resolve capability"),
            )
            .await;
        assert!(matches!(replay, Err(ConversationError::ActorUnavailable)));
        assert_eq!(delivery.calls.load(Ordering::SeqCst), 1);
        assert_eq!(read_only_approval_state(&database), "applying");

        drop(registry);
        store
            .shutdown()
            .await
            .expect("shutdown fatal closure store");
    }

    #[tokio::test]
    async fn claim_after_commit_unknown_converges_before_starting_one_worker() {
        let root = TestRoot::new("approval-claim-after-commit");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("claim after commit StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_fault_injector(Arc::new(
                FailStoreOperationOnce::new(
                    RuntimeStoreOperation::ClaimApprovalAfterCommit,
                    InjectedStoreFailure::WorkerStopped,
                ),
            )),
            kek,
        )
        .await
        .expect("open claim after commit store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 41).await;
        let delivery = Arc::new(GatedApprovalDelivery::new());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xAB),
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
        let prompt_principal = local_principal(41);
        let _command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-claim-after-commit",
                "claim reply fault must not orphan delivery",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xBB; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xBB; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve principal");
        let receipt = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolver.try_enter_approval().expect("resolve capability"),
            )
            .await
            .expect("claim converges after unknown outcome");
        assert!(matches!(receipt, ApprovalReceipt::Claimed { .. }));
        delivery.wait_until_called().await;
        assert_eq!(delivery.calls.load(Ordering::SeqCst), 1);
        delivery.release();
        wait_for_approval_state(&database, "applied").await;

        drop(registry);
        store
            .shutdown()
            .await
            .expect("shutdown claim after commit store");
    }

    #[tokio::test]
    async fn register_after_commit_unknown_installs_the_original_route() {
        let root = TestRoot::new("approval-register-after-commit");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("register after commit StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_fault_injector(Arc::new(
                FailStoreOperationOnce::new(
                    RuntimeStoreOperation::RegisterApprovalAfterCommit,
                    InjectedStoreFailure::WorkerStopped,
                ),
            )),
            kek,
        )
        .await
        .expect("open register after commit store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 42).await;
        let delivery = Arc::new(GatedApprovalDelivery::new());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xAC),
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
        let prompt_principal = local_principal(42);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-register-after-commit",
                "register reply fault must keep route",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xBC; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xBC; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve principal");
        let receipt = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolver.try_enter_approval().expect("resolve capability"),
            )
            .await
            .expect("registered route accepts resolve");
        assert!(matches!(receipt, ApprovalReceipt::Claimed { .. }));
        delivery.wait_until_called().await;
        assert_eq!(fake.cancel_count(command.command_id), 0);
        assert_eq!(delivery.calls.load(Ordering::SeqCst), 1);
        delivery.release();
        wait_for_approval_state(&database, "applied").await;

        drop(registry);
        store
            .shutdown()
            .await
            .expect("shutdown register after commit store");
    }

    #[tokio::test]
    async fn exact_action_request_replay_at_route_capacity_keeps_the_existing_route() {
        let root = TestRoot::new("approval-replay-at-route-capacity");
        let database = root.0.join("runtime.db");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 44).await;
        let fake = FakeCoordinator::held_with_approval(approval_delivery());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xAE),
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
        let principal = local_principal(44);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "approval-replay-at-route-capacity",
                "fill route capacity then replay the first request",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;

        for index in 2..=crate::runtime::model::MAX_ACTIVE_APPROVALS_PER_TURN {
            fake.emit_approval(
                approval_request_with_id(format!("actor-request-{index}")),
                approval_delivery(),
            )
            .await;
            wait_for_approval_count(&database, i64::from(index)).await;
        }

        let replay_delivery = approval_delivery();
        let replay_delivery_dropped = Arc::downgrade(&replay_delivery);
        fake.emit_approval(approval_request(), replay_delivery)
            .await;
        wait_until(|| replay_delivery_dropped.upgrade().is_none()).await;

        let issuer = PrincipalIssuer::local_only([0xBE; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xBE; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve principal");
        let receipt = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolver.try_enter_approval().expect("resolve capability"),
            )
            .await
            .expect("exact replay must preserve the original route");
        assert!(matches!(receipt, ApprovalReceipt::Claimed { .. }));
        assert_eq!(fake.cancel_count(command.command_id), 0);

        drop(registry);
        store
            .shutdown()
            .await
            .expect("shutdown route capacity store");
    }

    #[tokio::test]
    async fn applied_action_request_replay_does_not_resurrect_or_occupy_a_route() {
        let root = TestRoot::new("approval-terminal-replay-route");
        let database = root.0.join("runtime.db");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 45).await;
        let delivery = Arc::new(GatedApprovalDelivery::new());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xAF),
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
        let principal = local_principal(45);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "approval-terminal-replay-route",
                "apply then replay the terminal action request",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xBF; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xBF; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve principal");
        let receipt = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolver.try_enter_approval().expect("resolve capability"),
            )
            .await
            .expect("claim approval");
        assert!(matches!(receipt, ApprovalReceipt::Claimed { .. }));
        delivery.wait_until_called().await;
        delivery.release();
        wait_for_approval_state(&database, "applied").await;

        let replay_delivery = approval_delivery();
        let replay_delivery_dropped = Arc::downgrade(&replay_delivery);
        fake.emit_approval(approval_request(), replay_delivery)
            .await;
        wait_until(|| replay_delivery_dropped.upgrade().is_none()).await;

        for index in 0..crate::runtime::model::MAX_ACTIVE_APPROVALS_PER_TURN {
            fake.emit_approval(
                approval_request_with_id(format!("terminal-replay-fill-{index}")),
                approval_delivery(),
            )
            .await;
            wait_for_approval_count(&database, i64::from(index) + 2).await;
        }
        assert_eq!(fake.cancel_count(command.command_id), 0);

        drop(registry);
        store
            .shutdown()
            .await
            .expect("shutdown terminal replay store");
    }

    #[tokio::test]
    async fn retry_after_commit_unknown_starts_the_new_round_once() {
        let root = TestRoot::new("approval-retry-after-commit");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("retry after commit StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_fault_injector(Arc::new(
                FailStoreOperationOnce::new(
                    RuntimeStoreOperation::RetryApprovalDeliveryAfterCommit,
                    InjectedStoreFailure::WorkerStopped,
                ),
            )),
            kek,
        )
        .await
        .expect("open retry after commit store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 43).await;
        let delivery = Arc::new(SequencedApprovalDelivery::fail_then_apply());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xAD),
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
        let prompt_principal = local_principal(43);
        let _command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-retry-after-commit",
                "retry reply fault must keep new round",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xBD; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xBD; 16],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("resolve and retry principal");
        registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolver.try_enter_approval().expect("resolve capability"),
            )
            .await
            .expect("claim approval");
        wait_for_approval_state(&database, "deliveryFailed").await;
        let receipt = registry
            .retry_approval(
                conversation.conversation_id,
                approval_id,
                resolver.try_enter_approval().expect("retry capability"),
            )
            .await
            .expect("retry converges after unknown outcome");
        assert!(matches!(
            receipt,
            ApprovalReceipt::AlreadyHandled {
                state: ApprovalDeliveryState::Applying,
                ..
            }
        ));
        wait_for_approval_state(&database, "applied").await;
        assert_eq!(
            delivery
                .decisions
                .lock()
                .expect("approval decisions lock")
                .len(),
            2
        );

        drop(registry);
        store
            .shutdown()
            .await
            .expect("shutdown retry after commit store");
    }

    #[tokio::test]
    async fn retry_delivery_reuses_exact_winner_after_old_completion_races_control_lane() {
        let root = TestRoot::new("approval-retry");
        let database = root.0.join("runtime.db");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 35).await;
        let delivery = Arc::new(SequencedApprovalDelivery::fail_then_apply());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA5),
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
        let prompt_principal = local_principal(35);
        let _command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-retry",
                "fail one delivery round then retry",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xB5; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xB5; 16],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("resolve and retry principal");
        let resolve_guard = resolver
            .try_enter_approval()
            .expect("enter resolve capability");
        resolve_guard.require_resolve().expect("resolve permission");
        let resolved = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolve_guard,
            )
            .await
            .expect("claim approval");
        assert!(matches!(resolved, ApprovalReceipt::Claimed { .. }));
        wait_for_approval_state(&database, "deliveryFailed").await;

        // Control has priority over runner completion. Retry immediately after durable state is
        // visible to exercise the stale completion/new-worker generation race.
        let retry_guard = resolver
            .try_enter_approval()
            .expect("enter retry capability");
        retry_guard.require_retry().expect("retry permission");
        let retried = registry
            .retry_approval(conversation.conversation_id, approval_id, retry_guard)
            .await
            .expect("retry exact sealed winner");
        assert!(matches!(
            retried,
            ApprovalReceipt::AlreadyHandled {
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                state: ApprovalDeliveryState::Applying,
                ..
            }
        ));
        wait_for_approval_state(&database, "applied").await;
        {
            let decisions = delivery.decisions.lock().expect("approval decisions lock");
            assert_eq!(decisions.len(), 2);
            assert_eq!(decisions[0], decisions[1]);
        }

        drop(registry);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn retry_at_deadline_durably_expires_before_returning_expired_receipt() {
        let root = TestRoot::new("approval-retry-deadline");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(40_000);
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("approval deadline StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
            kek,
        )
        .await
        .expect("open approval deadline store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 36).await;
        let delivery = Arc::new(SequencedApprovalDelivery::fail_then_apply());
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA6),
            1,
        )
        .expect("registry")
        .with_approval_runtime(
            Arc::new(clock.clone()),
            Arc::new(TokioApprovalSleeper),
            Arc::new(FixedApprovalBackoff),
        );
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let prompt_principal = local_principal(36);
        let _command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-retry-deadline",
                "deadline blocks manual retry",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let issuer = PrincipalIssuer::local_only([0xB6; 32]);
        let resolver = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xB6; 16],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("resolve and retry principal");
        let resolve_guard = resolver
            .try_enter_approval()
            .expect("enter resolve capability");
        let _ = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolve_guard,
            )
            .await
            .expect("claim approval");
        wait_for_approval_state(&database, "deliveryFailed").await;

        clock.set(40_000 + crate::runtime::approval::DEFAULT_APPROVAL_DEADLINE_MS);
        let retry_guard = resolver
            .try_enter_approval()
            .expect("enter retry capability");
        let receipt = registry
            .retry_approval(conversation.conversation_id, approval_id, retry_guard)
            .await
            .expect("deadline retry closes expiry");
        assert!(matches!(
            receipt,
            ApprovalReceipt::AlreadyHandled {
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                state: ApprovalDeliveryState::Expired,
                ..
            }
        ));
        wait_for_approval_state(&database, "expired").await;
        assert_eq!(
            delivery
                .decisions
                .lock()
                .expect("approval decisions lock")
                .len(),
            1,
            "deadline retry must not call adapter again"
        );

        drop(registry);
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn pending_approval_deadline_fences_vendor_and_releases_actor_for_successor() {
        // 威胁场景：真实 vendor 在等待 Pending approval 时 deadline 到达；若 actor 只删除
        // durable route 而不 fence execution，vendor 与 actor 会永久占用且后续 prompt 不会启动。
        const NOW_MS: u64 = 70_000;
        const DEADLINE_MS: u64 = NOW_MS + 50;
        let root = TestRoot::new("approval-deadline-fences-turn");
        let database = root.0.join("runtime.db");
        let clock = ManualClock::new(NOW_MS);
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("approval expiry StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
            kek,
        )
        .await
        .expect("open approval expiry store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 37).await;
        let delivery = Arc::new(DeadlineApprovalDelivery {
            policy: ApprovalPolicySnapshot {
                agent_kind: AgentKind::Codex,
                action_kind: ActionKind::ExecuteCommand,
                allow_approve: true,
                allow_deny: true,
                allow_persist: false,
                deadline_at_ms: Some(DEADLINE_MS),
            },
            deliver_calls: AtomicUsize::new(0),
        });
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA7),
            1,
        )
        .expect("registry")
        .with_approval_runtime(
            Arc::new(clock.clone()),
            Arc::new(TokioApprovalSleeper),
            Arc::new(FixedApprovalBackoff),
        );
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(37);
        let first = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "approval-deadline-first",
                "must be interrupted at approval deadline",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;

        // successor 必须在 deadline 前已经 durable queued；这样才能证明 expiry 自动
        // 释放 actor，而不是只证明 terminal 之后还能接受一个全新的 prompt。
        fake.disable_approval_emission();
        let successor = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "approval-deadline-successor",
                "must already be queued when the approval expires",
            )
            .await,
        );
        assert_eq!(fake.starts().len(), 1);

        clock.set(DEADLINE_MS);
        wait_for_approval_state(&database, "expired").await;
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            first.command_id,
            &principal,
            CommandState::Interrupted,
        )
        .await;
        assert_eq!(fake.cancel_count(first.command_id), 1);
        assert_eq!(
            delivery.deliver_calls.load(Ordering::SeqCst),
            0,
            "deadline expiry must not fabricate a vendor Deny delivery"
        );
        fake.wait_for_starts(2).await;
        fake.release(successor.command_id);
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
    async fn approval_expiry_watchdog_fail_closes_a_stalled_terminal_pipeline() {
        // 威胁场景：expiry 已 exact fence vendor，但 daemon 内部 completion future 永久
        // pending；watchdog 必须释放进程内 task，并把 exact conversation 标记
        // RecoveryBlocked，而不是让 active/queued command 永久卡住或伪造 Interrupted COMMIT。
        const NOW_MS: u64 = 80_000;
        const DEADLINE_MS: u64 = NOW_MS + 30;
        let root = TestRoot::new("approval-expiry-terminal-watchdog");
        let database = root.0.join("runtime.db");
        let clock = ManualClock::new(NOW_MS);
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("approval watchdog StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
            kek,
        )
        .await
        .expect("open approval watchdog store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 38).await;
        let delivery = Arc::new(DeadlineApprovalDelivery {
            policy: ApprovalPolicySnapshot {
                agent_kind: AgentKind::Codex,
                action_kind: ActionKind::ExecuteCommand,
                allow_approve: true,
                allow_deny: true,
                allow_persist: false,
                deadline_at_ms: Some(DEADLINE_MS),
            },
            deliver_calls: AtomicUsize::new(0),
        });
        let fake = FakeCoordinator::held_with_approval_stalled_after_fence(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA8),
            1,
        )
        .expect("registry")
        .with_approval_runtime(
            Arc::new(clock.clone()),
            Arc::new(TokioApprovalSleeper),
            Arc::new(FixedApprovalBackoff),
        )
        .with_approval_expiry_terminal_grace(Duration::from_millis(50));
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let principal = local_principal(38);
        let first = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "approval-watchdog-first",
                "stall after expiry fence",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        fake.disable_approval_emission();
        let queued = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "approval-watchdog-queued",
                "must remain queued after fail-close",
            )
            .await,
        );

        clock.set(DEADLINE_MS);
        wait_for_approval_state(&database, "expired").await;
        wait_until(|| fake.cancel_count(first.command_id) == 1).await;
        wait_until(|| {
            read_only_conversation_lifecycle(&database) == "recoveryBlocked" && fake.active() == 0
        })
        .await;
        assert_eq!(
            fake.starts().len(),
            1,
            "fail-close must not start queued work"
        );
        let first_receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: first.command_id,
                },
            })
            .await
            .expect("query watchdog command");
        assert_eq!(first_receipt.state, CommandState::Started);
        let queued_receipt = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: principal.idempotency_owner(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: conversation.conversation_id,
                    command_id: queued.command_id,
                },
            })
            .await
            .expect("query queued watchdog command");
        assert_eq!(queued_receipt.state, CommandState::Accepted);
        assert_eq!(delivery.deliver_calls.load(Ordering::SeqCst), 0);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn outcome_unknown_approve_expiry_never_sends_a_synthetic_deny() {
        // 威胁场景：Approve 已写入 durable winner，但 adapter 返回 OutcomeUnknown；deadline
        // 到达后若 daemon 合成 Deny，会让 vendor 同时观察互相冲突的决定。expiry 只能
        // exact fence turn，不能调用 transient route 第二次。
        const NOW_MS: u64 = 90_000;
        const DEADLINE_MS: u64 = NOW_MS + 200;
        let root = TestRoot::new("approval-outcome-unknown-expiry");
        let database = root.0.join("runtime.db");
        let clock = ManualClock::new(NOW_MS);
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("outcome-unknown expiry StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
            kek,
        )
        .await
        .expect("open outcome-unknown expiry store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 39).await;
        let delivery = Arc::new(SequencedApprovalDelivery {
            policy: ApprovalPolicySnapshot {
                agent_kind: AgentKind::Codex,
                action_kind: ActionKind::ExecuteCommand,
                allow_approve: true,
                allow_deny: true,
                allow_persist: false,
                deadline_at_ms: Some(DEADLINE_MS),
            },
            outcomes: StdMutex::new(VecDeque::from([ApprovalDeliveryOutcome::OutcomeUnknown])),
            decisions: StdMutex::new(Vec::new()),
        });
        let fake = FakeCoordinator::held_with_approval(delivery.clone());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xA9),
            1,
        )
        .expect("registry")
        .with_approval_runtime(
            Arc::new(clock.clone()),
            Arc::new(TokioApprovalSleeper),
            Arc::new(ZeroApprovalBackoff),
        );
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        let prompt_principal = local_principal(39);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &prompt_principal,
                "approval-outcome-unknown",
                "approve delivery becomes outcome unknown",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let approval_id = read_only_approval_id(&database);
        let turn_id = fake.starts()[0].turn_id;
        let resolver = PrincipalIssuer::local_only([0xC9; 32])
            .issue_verified_local_with_approval_permissions(
                501,
                [0xC9; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("outcome-unknown resolver");
        let receipt = registry
            .resolve_approval(
                conversation.conversation_id,
                turn_id,
                approval_id,
                ActionDecision {
                    request_id: "actor-request-1".to_owned(),
                    decision: agentdeck_protocol::ActionDecisionKind::Approve,
                    persist: false,
                },
                resolver
                    .try_enter_approval()
                    .expect("enter outcome-unknown resolve"),
            )
            .await
            .expect("claim outcome-unknown approval");
        assert!(matches!(receipt, ApprovalReceipt::Claimed { .. }));
        wait_for_approval_state(&database, "deliveryFailed").await;
        assert_eq!(
            delivery
                .decisions
                .lock()
                .expect("outcome-unknown decisions lock")
                .as_slice(),
            &[(
                "actor-request-1".to_owned(),
                agentdeck_protocol::ActionDecisionKind::Approve,
                false,
            )]
        );

        clock.set(DEADLINE_MS);
        wait_for_approval_state(&database, "expired").await;
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &prompt_principal,
            CommandState::Interrupted,
        )
        .await;
        assert_eq!(fake.cancel_count(command.command_id), 1);
        assert_eq!(
            delivery
                .decisions
                .lock()
                .expect("post-expiry decisions lock")
                .len(),
            1,
            "expiry must never send a synthetic Deny after OutcomeUnknown Approve"
        );

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn complete_after_commit_unknown_replays_terminal_cleanup_and_starts_successor() {
        let root = TestRoot::new("complete-after-commit");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("complete after commit StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_fault_injector(Arc::new(
                FailStoreOperationOnce::new(
                    RuntimeStoreOperation::CompleteCommandAfterCommit,
                    InjectedStoreFailure::WorkerStopped,
                ),
            )),
            kek,
        )
        .await
        .expect("open complete after commit store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 44).await;
        let fake = FakeCoordinator::held_with_approval(approval_delivery());
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xAE),
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
        let principal = local_principal(44);
        let first = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "complete-after-commit-first",
                "first",
            )
            .await,
        );
        fake.wait_for_starts(1).await;
        wait_for_approval_count(&database, 1).await;
        let first_approval_id = read_only_approval_id(&database);
        let second = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "complete-after-commit-second",
                "second",
            )
            .await,
        );

        fake.release(first.command_id);
        fake.wait_for_starts(2).await;
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            first.command_id,
            &principal,
            CommandState::Completed,
        )
        .await;
        let first_approval_state: String = rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open runtime DB read-only")
        .query_row(
            "SELECT state FROM approval_ledger WHERE approval_id = ?1",
            [&first_approval_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read first approval state");
        assert_eq!(first_approval_state, "expired");

        fake.release(second.command_id);
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            second.command_id,
            &principal,
            CommandState::Completed,
        )
        .await;
        assert_eq!(fake.starts().len(), 2);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
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
                1,
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
        // 威胁场景：release 后用户 Cancel 已成功 fence exact PGID，但 production driver
        // 随后 EOF→Failed；若 fake coordinator 直接返回 Canceled，durable terminal 断裂
        // 会被掩盖。这里要求 fake 保留 production Failed，actor 再凭 typed user-cancel
        // state 写出唯一 Canceled terminal。
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
        assert_eq!(fake.completions()[0].1, TerminalState::Failed);
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
    async fn post_release_terminal_claim_only_user_cancel_with_fence_can_override() {
        let internal_gate = Mutex::new(ActiveExecutionGate {
            release_authorized: true,
            ..ActiveExecutionGate::default()
        });
        let internal_control = Arc::new(FakeControl {
            gate: Arc::new(Semaphore::new(0)),
            canceled: AtomicBool::new(false),
            cancel_count: AtomicUsize::new(0),
            cancel_fails: false,
        });
        request_active_cancel(&internal_gate, Some(internal_control))
            .await
            .expect("shutdown/recovery exact-group fence");
        let late_user_control = Arc::new(FakeControl {
            gate: Arc::new(Semaphore::new(0)),
            canceled: AtomicBool::new(false),
            cancel_count: AtomicUsize::new(0),
            cancel_fails: false,
        });
        assert!(
            !request_user_active_cancel(&internal_gate, Some(late_user_control.clone()))
                .await
                .expect("an internal fence cannot be retroactively claimed by a user cancel")
        );
        assert_eq!(late_user_control.cancel_count.load(Ordering::SeqCst), 0);
        let internal_terminal = claim_post_release_terminal(
            &internal_gate,
            CommandTerminal::failed(SanitizedTerminalFailure::execution_failed()),
        )
        .await;
        assert_eq!(internal_terminal.terminal_state(), TerminalState::Failed);

        let failed_user_gate = Mutex::new(ActiveExecutionGate {
            release_authorized: true,
            ..ActiveExecutionGate::default()
        });
        let failing_control = Arc::new(FakeControl {
            gate: Arc::new(Semaphore::new(0)),
            canceled: AtomicBool::new(false),
            cancel_count: AtomicUsize::new(0),
            cancel_fails: true,
        });
        assert!(
            request_user_active_cancel(&failed_user_gate, Some(failing_control))
                .await
                .is_err()
        );
        let failed_user_terminal = claim_post_release_terminal(
            &failed_user_gate,
            CommandTerminal::failed(SanitizedTerminalFailure::execution_failed()),
        )
        .await;
        assert_eq!(
            failed_user_terminal.terminal_state(),
            TerminalState::Failed,
            "a user request without exact fence proof must not become Canceled"
        );
    }

    #[tokio::test]
    async fn completion_claim_wins_before_late_user_cancel() {
        let gate = Mutex::new(ActiveExecutionGate {
            release_authorized: true,
            ..ActiveExecutionGate::default()
        });
        let completed = claim_post_release_terminal(
            &gate,
            CommandTerminal::completed(TurnSummary {
                total_input_tokens: None,
                total_output_tokens: None,
                elapsed_ms: 1,
            }),
        )
        .await;
        assert_eq!(completed.terminal_state(), TerminalState::Completed);
        let replayed = claim_post_release_terminal(
            &gate,
            CommandTerminal::failed(SanitizedTerminalFailure::execution_failed()),
        )
        .await;
        assert_eq!(
            replayed.terminal_state(),
            TerminalState::Completed,
            "the first terminal claim remains authoritative"
        );

        let late_control = Arc::new(FakeControl {
            gate: Arc::new(Semaphore::new(0)),
            canceled: AtomicBool::new(false),
            cancel_count: AtomicUsize::new(0),
            cancel_fails: false,
        });
        assert!(
            !request_user_active_cancel(&gate, Some(late_control.clone()))
                .await
                .expect("late cancel is classified without touching the process group")
        );
        assert_eq!(late_control.cancel_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn normal_completion_fence_winner_makes_preclaim_cancel_stale() {
        // 威胁场景：adapter 已返回 Completed，但 normal process-group cleanup 仍在进行；
        // 此时用户 Cancel 若只复用一个无类型的 fence Ok，会在 completion claim 前抢写
        // user flags 并把真实 Completed 改成 Canceled。typed winner 必须让该 Cancel stale。
        let gate = Mutex::new(ActiveExecutionGate {
            release_authorized: true,
            ..ActiveExecutionGate::default()
        });
        let control = Arc::new(AlreadyCompletingControl {
            cancel_count: AtomicUsize::new(0),
        });

        assert!(
            !request_user_active_cancel(&gate, Some(control.clone()))
                .await
                .expect("normal completion winner is a safe stale cancel")
        );
        assert_eq!(control.cancel_count.load(Ordering::SeqCst), 1);
        {
            let state = gate.lock().await;
            assert!(state.completion_won);
            assert!(state.cancel_fenced);
            assert!(!state.user_cancel_accepted);
            assert!(!state.user_cancel_fenced);
        }

        request_active_cancel(&gate, Some(control.clone()))
            .await
            .expect("shutdown accepts an already-fenced normal completion");
        assert_eq!(control.cancel_count.load(Ordering::SeqCst), 2);
        interrupt_active_for_approval_expiry(&gate, Some(control.clone()))
            .await
            .expect("approval expiry leaves an already-completing terminal authoritative");
        assert_eq!(
            control.cancel_count.load(Ordering::SeqCst),
            2,
            "completion winner makes expiry a no-op without another control call"
        );

        let completed = claim_post_release_terminal(
            &gate,
            CommandTerminal::completed(TurnSummary {
                total_input_tokens: Some(2),
                total_output_tokens: Some(3),
                elapsed_ms: 5,
            }),
        )
        .await;
        assert_eq!(completed.terminal_state(), TerminalState::Completed);

        assert!(
            !request_user_active_cancel(&gate, Some(control.clone()))
                .await
                .expect("claimed completion remains stale")
        );
        assert_eq!(
            control.cancel_count.load(Ordering::SeqCst),
            2,
            "claimed completion must reject without another control call"
        );
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
                1,
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
        let blocker = Arc::new(BlockStoreOperation::new(
            RuntimeStoreOperation::PersistFenceBeforeCommit,
        ));
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
                    1,
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
    async fn shutdown_timeout_aborts_prompt_worker_without_releasing_store_owned_authorization() {
        let root = TestRoot::new("shutdown-admission-authorization");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let blocker = Arc::new(BlockNextAcceptCommit::new());
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("shutdown authorization StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_fault_injector(blocker.clone()),
            kek,
        )
        .await
        .expect("open shutdown authorization store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 23).await;
        let registry = Arc::new(
            ConversationRegistry::with_limits(
                store.clone(),
                Arc::new(DisabledExecutionCoordinator),
                runtime_id(RuntimeIdKind::DaemonBoot, 0xE3),
                1,
                1,
                Duration::from_millis(75),
            )
            .expect("short-deadline registry"),
        );
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");

        let principal = local_principal(19);
        let idempotency_key = "shutdown-authorization";
        let payload = b"authorization must remain store-owned";
        blocker.arm();
        let submitting_registry = registry.clone();
        let submitting_principal = principal.clone();
        let mut submit = tokio::spawn(async move {
            submitting_registry
                .submit_prompt(
                    conversation.conversation_id,
                    submitting_principal.clone(),
                    submitting_principal.try_enter().expect("prompt guard"),
                    idempotency_key.to_owned(),
                    1,
                    payload.to_vec(),
                )
                .await
        });
        wait_until(|| blocker.entered.load(Ordering::SeqCst)).await;

        let revoking = principal.clone();
        let mut revoke = tokio::spawn(async move { revoking.begin_revoke().await });
        wait_until(|| !principal.is_active()).await;
        let revoke_was_pending_before_shutdown = !revoke.is_finished();

        let shutting_registry = registry.clone();
        let mut shutdown = tokio::spawn(async move { shutting_registry.shutdown().await });
        let shutdown_before_release =
            tokio::time::timeout(Duration::from_secs(1), &mut shutdown).await;
        let revoke_finished_before_release =
            tokio::time::timeout(Duration::from_millis(250), async {
                while !revoke.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();

        // 所有断言都放在 barrier 释放与任务回收之后，避免失败路径把 Store worker
        // 永久留在 AcceptCommandBeforeCommit。
        blocker.release();
        let shutdown_result = match shutdown_before_release {
            Ok(result) => result,
            Err(_) => shutdown.await,
        };
        let submit_result = match tokio::time::timeout(Duration::from_secs(1), &mut submit).await {
            Ok(result) => Some(result),
            Err(_) => {
                submit.abort();
                let _ = submit.await;
                None
            }
        };
        let replay = store
            .accept_command(AcceptCommand {
                conversation_id: conversation.conversation_id,
                owner: principal.idempotency_owner(),
                idempotency_key: idempotency_key.to_owned(),
                expected_configuration_revision: 1,
                payload: payload.to_vec(),
            })
            .await;
        let revoke_result = match tokio::time::timeout(Duration::from_secs(1), &mut revoke).await {
            Ok(result) => Some(result),
            Err(_) => {
                revoke.abort();
                let _ = revoke.await;
                None
            }
        };
        principal.finish_revoke();

        let replayed_command = match &replay {
            Ok(AcceptOutcome::Replayed { command }) => Some(command),
            _ => None,
        };
        let pinned_rows: i64 = replayed_command
            .map(|command| {
                rusqlite::Connection::open_with_flags(
                    &database,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .expect("open runtime DB read-only")
                .query_row(
                    "SELECT COUNT(*)
                     FROM command_configuration_pins AS pin
                     JOIN commands AS command
                       ON command.conversation_id = pin.conversation_id
                      AND command.command_seq = pin.command_seq
                     WHERE command.command_id = ?1",
                    [&command.command_id.as_bytes()[..]],
                    |row| row.get(0),
                )
                .expect("count committed command configuration pin")
            })
            .unwrap_or_default();
        store.shutdown().await.expect("shutdown store");

        assert!(
            revoke_was_pending_before_shutdown,
            "revoke must initially wait for the in-flight prompt authorization"
        );
        assert!(
            !revoke_finished_before_release,
            "shutdown timeout must not release authorization while the Store owns the blocked accept"
        );
        shutdown_result
            .expect("shutdown task")
            .expect("shutdown actors");
        assert!(submit_result.is_some(), "submit task must be reaped");
        let command = replayed_command.expect("blocked accept must commit before exact replay");
        assert_eq!(command.state, CommandState::Accepted);
        assert_eq!(command.configuration_revision, 1);
        assert_eq!(pinned_rows, 1, "accepted command must retain its exact pin");
        revoke_result
            .expect("revoke task must finish after barrier release")
            .expect("join revoke")
            .expect("revoke after Store commit");
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
                    1,
                    b"must be drained after recovery block".to_vec(),
                )
                .await
        });
        wait_until(|| blocker.entered.load(Ordering::SeqCst)).await;
        fake.allow_prepare();
        wait_until(|| fake.active() == 0).await;
        wait_until(|| !*prompt_ingress.open.borrow()).await;
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
    async fn clean_prepare_failure_writes_interrupted_and_starts_queued_successor() {
        // 威胁场景：固定 vendor binary 不存在，prepare 尚未创建 child 或产生副作用便
        // 返回已证明 clean 的错误；若 actor 把它当 RecoveryBlocked，会永久封死 durable
        // queue。它必须以 exact pre-release Interrupted 收口，并继续 FIFO successor。
        let root = TestRoot::new("clean-prepare-failure");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 46).await;
        let fake = FakeCoordinator::clean_prepare_failure_once();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xE4),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        let principal = local_principal(46);
        let failed = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "clean-prepare-failure",
                "fixed vendor binary is absent",
            )
            .await,
        );
        let successor = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "clean-prepare-successor",
                "must execute after clean failure",
            )
            .await,
        );

        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            failed.command_id,
            &principal,
            CommandState::Interrupted,
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
        assert_eq!(
            fake.starts().len(),
            1,
            "clean failure creates no fake child"
        );
        assert_eq!(fake.starts()[0].command_id, successor.command_id);
        assert_eq!(fake.release_count(), 1);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn accepted_cancel_during_clean_prepare_failure_writes_canceled() {
        // 威胁场景：用户在尚无 control 的 blocked prepare 期间收到 Requested，随后
        // adapter 证明 prepare clean failure；durable terminal 必须保持用户取消赢家，
        // 不能降级成 Interrupted。
        let root = TestRoot::new("clean-prepare-user-cancel");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 49).await;
        let fake = FakeCoordinator::blocked_clean_prepare_failure_once();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xE7),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        let principal = local_principal(49);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "clean-prepare-user-cancel",
                "cancel must win the clean failure race",
            )
            .await,
        );
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &principal,
            CommandState::Started,
        )
        .await;
        let turn_id = read_only_command_turn_id(&root.0.join("runtime.db"), command.command_id);
        assert_eq!(
            registry
                .cancel_active(
                    conversation.conversation_id,
                    turn_id,
                    principal.try_enter().expect("cancel guard"),
                )
                .await
                .expect("cancel accepted during prepare"),
            ActiveCancelResult::Requested
        );
        fake.allow_prepare();
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &principal,
            CommandState::Canceled,
        )
        .await;
        assert!(
            fake.starts().is_empty(),
            "clean failure creates no fake child"
        );

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn late_cancel_after_clean_prepare_terminal_claim_is_stale() {
        // 威胁场景：clean failure 已 claim Interrupted、但 SQLite terminal COMMIT 仍阻塞；
        // 若 claim 发生在 COMMIT 之后，晚到 Cancel 会错误返回 Requested，随后却读到
        // Interrupted。terminal 必须先在 execution gate 线性化。
        let root = TestRoot::new("clean-prepare-late-cancel");
        let keys = MemoryKeyStore::new();
        let blocker = Arc::new(BlockStoreOperation::new(
            RuntimeStoreOperation::TerminateStartedBeforeReleaseBeforeCommit,
        ));
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("late cancel StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.0.join("runtime.db")).with_fault_injector(blocker.clone()),
            kek,
        )
        .await
        .expect("open late cancel store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 50).await;
        let fake = FakeCoordinator::blocked_clean_prepare_failure_once();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xE8),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        let principal = local_principal(50);
        let command = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "clean-prepare-late-cancel",
                "late cancel must observe the terminal claim",
            )
            .await,
        );
        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &principal,
            CommandState::Started,
        )
        .await;
        let turn_id = read_only_command_turn_id(&root.0.join("runtime.db"), command.command_id);
        fake.allow_prepare();
        wait_until(|| blocker.entered.load(Ordering::SeqCst)).await;
        assert_eq!(
            registry
                .cancel_active(
                    conversation.conversation_id,
                    turn_id,
                    principal.try_enter().expect("late cancel guard"),
                )
                .await
                .expect("late cancel result"),
            ActiveCancelResult::Stale
        );
        blocker.release();
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            command.command_id,
            &principal,
            CommandState::Interrupted,
        )
        .await;

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn clean_prepare_failure_commit_unknown_retries_exact_terminal_and_starts_successor() {
        // 威胁场景：clean prepare failure 的 Interrupted 已 COMMIT，但 SQLite worker 在
        // 回复前停止；actor 必须只用同一 TerminateStartedBeforeRelease 输入重试，不能
        // 把已落盘 terminal 误判为 RecoveryBlocked，也不能重复启动首命令。
        let root = TestRoot::new("clean-prepare-commit-unknown");
        let database = root.0.join("runtime.db");
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("clean prepare commit-unknown StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database).with_fault_injector(Arc::new(
                FailStoreOperationOnce::new(
                    RuntimeStoreOperation::TerminateStartedBeforeReleaseAfterCommit,
                    InjectedStoreFailure::WorkerStopped,
                ),
            )),
            kek,
        )
        .await
        .expect("open clean prepare commit-unknown store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 47).await;
        let fake = FakeCoordinator::clean_prepare_failure_once();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xE5),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        let principal = local_principal(47);
        let failed = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "clean-prepare-commit-unknown-first",
                "must converge through exact terminal retry",
            )
            .await,
        );
        let successor = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "clean-prepare-commit-unknown-successor",
                "must execute exactly once",
            )
            .await,
        );

        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            failed.command_id,
            &principal,
            CommandState::Interrupted,
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
        assert_eq!(fake.starts().len(), 1);
        assert_eq!(fake.starts()[0].command_id, successor.command_id);
        assert_eq!(fake.release_count(), 1);

        registry.shutdown().await.expect("shutdown actors");
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn uncertain_prepare_failure_blocks_conversation_and_keeps_successor_accepted() {
        // 威胁场景：gate spawn/handshake 已开始但 cleanup outcome 不确定；若 actor 把
        // 普通 PrepareFailed 当 clean Interrupted，queued successor 可能与残留 PGID 并行。
        let root = TestRoot::new("uncertain-prepare-failure");
        let database = root.0.join("runtime.db");
        let store = root.open().await;
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 48).await;
        let fake = FakeCoordinator::prepare_failure_once();
        let registry = ConversationRegistry::new(
            store.clone(),
            Arc::new(fake.clone()),
            runtime_id(RuntimeIdKind::DaemonBoot, 0xE6),
            1,
        )
        .expect("registry");
        registry
            .install(conversation.clone(), Vec::new())
            .await
            .expect("actor");
        let principal = local_principal(48);
        let blocked = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "uncertain-prepare-first",
                "must remain Started",
            )
            .await,
        );
        let successor = command(
            &submit(
                &registry,
                conversation.conversation_id,
                &principal,
                "uncertain-prepare-successor",
                "must remain Accepted",
            )
            .await,
        );

        registry
            .enable_scheduling()
            .await
            .expect("enable scheduling");
        wait_until(|| read_only_conversation_lifecycle(&database) == "recoveryBlocked").await;
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            blocked.command_id,
            &principal,
            CommandState::Started,
        )
        .await;
        wait_for_receipt_state(
            &store,
            conversation.conversation_id,
            successor.command_id,
            &principal,
            CommandState::Accepted,
        )
        .await;
        assert!(
            fake.starts().is_empty(),
            "uncertain prepare creates no fake owner"
        );
        assert_eq!(fake.release_count(), 0);
        assert!(matches!(
            registry
                .submit_prompt(
                    conversation.conversation_id,
                    principal.clone(),
                    principal.try_enter().expect("blocked ingress guard"),
                    "must-be-rejected".to_owned(),
                    1,
                    b"must stay closed".to_vec(),
                )
                .await,
            Err(ConversationError::ActorUnavailable)
        ));

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
                    1,
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
        let keys = MemoryKeyStore::new();
        let blocker = Arc::new(BlockStoreOperation::new(
            RuntimeStoreOperation::CompleteCommandBeforeCommit,
        ));
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("release error StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.0.join("runtime.db")).with_fault_injector(blocker.clone()),
            kek,
        )
        .await
        .expect("open release error store");
        finish_recovery(&store).await;
        let conversation = create_conversation(&store, 11).await;
        let fake = FakeCoordinator::release_error_with_approval(approval_delivery());
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
        fake.wait_for_starts(1).await;
        wait_until(|| blocker.entered.load(Ordering::SeqCst)).await;
        assert_eq!(
            registry
                .cancel_active(
                    conversation.conversation_id,
                    fake.starts()[0].turn_id,
                    principal
                        .try_enter()
                        .expect("late release-error cancel guard"),
                )
                .await
                .expect("late release-error cancel"),
            ActiveCancelResult::Stale,
            "an internal release-error fence cannot be retroactively claimed by user cancel"
        );
        blocker.release();
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
        assert_eq!(
            read_only_approval_count(&root.0.join("runtime.db")),
            0,
            "release failure must discard every prepared approval event"
        );

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
                    1,
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
