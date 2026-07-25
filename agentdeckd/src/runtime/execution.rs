//! RuntimeCore 与副作用执行边界之间的两阶段 capability contract。
//!
//! RuntimeCore 先提交 `Started + ExecutionIntent`，再调用 `prepare`。返回的
//! completion future 在 RuntimeCore 完成 Fence + release authorization COMMIT 前
//! 不会被 poll。production 使用当前 binary 的 `agentdeckd --exec-gate`；显式 fake/disabled
//! coordinator 只服务于较早阶段的 side-effect-free contract tests。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(test, debug_assertions))]
use std::path::PathBuf;

use agentdeck_protocol::ActionRequest;
use agentdeck_protocol::runtime::{ConversationConfiguration, PromptPayload};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::agent::{
    AdapterApprovalAcknowledgement, AdapterEventDelivery, AdapterStateHandle, AgentTurnRequest,
    ExecutionId, adapter_approval_channel, adapter_event_channel,
};
use crate::exec_gate::{GatedChild, GatedChildOwner, GatedChildRelease, GatedChildSpawnError};
use crate::runtime::approval::SharedApprovalDelivery;
use crate::runtime::process_identity::{
    ProcessGroupController, ProcessIdentity, ProcessObservation, ProcessSignal,
    SystemProcessGroupController,
};
use crate::runtime::router::AgentRouter;
use crate::runtime::store::{
    AuthorizeExecutionRelease, CommandRecord, CommandTerminal, ConversationRecord,
    ExecutionFenceRecord, RuntimeId, SanitizedTerminalFailure,
};

const EXECUTION_TERM_GRACE: Duration = Duration::from_secs(2);
const EXECUTION_KILL_GRACE: Duration = Duration::from_secs(2);
pub(super) const EXECUTION_CANCEL_FENCE_BUDGET: Duration = Duration::from_secs(4);

#[allow(dead_code)] // P3.5 conversation ApprovalSupervisor 接线后成为 production path。
pub(crate) const RUNTIME_EXECUTION_EVENT_CAPACITY: usize = 64;

#[allow(dead_code)] // P3.5 conversation ApprovalSupervisor 接线后成为 production path。
pub(crate) enum RuntimeExecutionEvent {
    Adapter {
        delivery: AdapterEventDelivery,
    },
    ActionRequest {
        request: ActionRequest,
        delivery: SharedApprovalDelivery,
        registration_ack: Option<AdapterApprovalAcknowledgement>,
    },
}

#[allow(dead_code)] // P3.5 conversation ApprovalSupervisor 接线后成为 production path。
pub(crate) struct RuntimeExecutionEventReceiver {
    receiver: mpsc::Receiver<RuntimeExecutionEvent>,
}

#[allow(dead_code)] // P3.5 conversation ApprovalSupervisor 接线后成为 production path。
impl RuntimeExecutionEventReceiver {
    pub(crate) async fn recv(&mut self) -> Option<RuntimeExecutionEvent> {
        self.receiver.recv().await
    }
}

#[allow(dead_code)] // P3.7 exec-gate coordinator mints the production sender。
pub(crate) fn runtime_execution_event_channel() -> (
    mpsc::Sender<RuntimeExecutionEvent>,
    RuntimeExecutionEventReceiver,
) {
    let (sender, receiver) = mpsc::channel(RUNTIME_EXECUTION_EVENT_CAPACITY);
    (sender, RuntimeExecutionEventReceiver { receiver })
}

#[allow(dead_code)] // side-effect-free coordinators use a closed stream。
pub(crate) fn closed_execution_events() -> RuntimeExecutionEventReceiver {
    let (sender, receiver) = runtime_execution_event_channel();
    drop(sender);
    receiver
}

#[allow(dead_code)] // 字段由 P3.7 production exec-gate coordinator 读取。
#[derive(Clone, Debug)]
pub(crate) struct RuntimeExecutionContext {
    pub(crate) conversation: ConversationRecord,
    pub(crate) command: CommandRecord,
    pub(crate) configuration_revision: u64,
    pub(crate) execution_configuration: ConversationConfiguration,
    pub(crate) turn_id: RuntimeId,
    pub(crate) daemon_boot_id: RuntimeId,
    pub(crate) execution_nonce: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeProcessIdentity {
    pub(crate) process_group_id: i64,
    pub(crate) leader_pid: i64,
    pub(crate) leader_start_time: u64,
    pub(crate) fence_payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeExecutionCompletion {
    pub(crate) terminal: CommandTerminal,
}

#[async_trait::async_trait]
pub(crate) trait RuntimeExecutionControl: Send + Sync + 'static {
    /// 请求终止并等待整个 execution process group 已不可再产生副作用。
    ///
    /// `Ok(())` 是 durable terminal transition 的 safety 前提；实现必须幂等，
    /// 不得只表示“已发送 cancel”。
    async fn cancel_and_wait_fenced(
        &self,
    ) -> Result<RuntimeCancelDisposition, RuntimeExecutionError>;
}

/// 用户 Cancel 与 adapter terminal cleanup 共用同一个 exact-group fence。
/// disposition 明确指出谁在线性化点先取得 fence ownership，避免后到 Cancel
/// 复用 normal cleanup 的 `Ok` 后把已完成的 turn 改写成 Canceled。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeCancelDisposition {
    UserCancelWon,
    AlreadyCompleting,
}

/// `Ok(RuntimeExecutionCompletion)` 是一个 safety capability：它必须表示本次
/// execution 的精确 process group 已被 reap，或已被同等强度的 OS fence 证明不再
/// 能产生副作用。仅收到 vendor terminal event、child exit notification，或发送了
/// cancel 都不满足该契约；无法证明时必须返回 `Err`，由 actor 进入 RecoveryBlocked。
pub(crate) type RuntimeCompletionFuture = Pin<
    Box<
        dyn Future<Output = Result<RuntimeExecutionCompletion, RuntimeExecutionError>>
            + Send
            + 'static,
    >,
>;

/// 只有 durable `authorize_execution_release` 返回后才能构造的 release capability。
/// coordinator 的 `prepare` 只返回 blocked gate；真正 release 必须消费本类型。
pub(crate) struct ExecutionReleasePermit {
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
    process_group_id: i64,
    leader_pid: i64,
    leader_start_time: u64,
    fence_payload: Vec<u8>,
    release_authorized_at_ms: u64,
}

#[allow(dead_code)] // accessors 由 P3.7 release token implementation 读取。
impl ExecutionReleasePermit {
    pub(super) fn from_committed_store(
        request: &AuthorizeExecutionRelease,
        record: &ExecutionFenceRecord,
    ) -> Result<Self, RuntimeExecutionError> {
        let release_authorized_at_ms = record
            .release_authorized_at_ms
            .ok_or(RuntimeExecutionError::ReleaseAuthorizationInvalid)?;
        if record.command_id != request.command_id
            || record.daemon_boot_id != request.daemon_boot_id
            || record.execution_nonce != request.execution_nonce
            || request.execution_nonce.is_empty()
            || record.process_group_id <= 1
            || record.leader_pid <= 1
            || record.process_group_id != record.leader_pid
            || record.leader_start_time == 0
            || record.payload.is_empty()
        {
            return Err(RuntimeExecutionError::ReleaseAuthorizationInvalid);
        }
        Ok(Self {
            command_id: request.command_id,
            daemon_boot_id: request.daemon_boot_id,
            execution_nonce: record.execution_nonce.clone(),
            process_group_id: record.process_group_id,
            leader_pid: record.leader_pid,
            leader_start_time: record.leader_start_time,
            fence_payload: record.payload.clone(),
            release_authorized_at_ms,
        })
    }

    pub(crate) fn command_id(&self) -> RuntimeId {
        self.command_id
    }

    pub(crate) fn daemon_boot_id(&self) -> RuntimeId {
        self.daemon_boot_id
    }

    pub(crate) fn execution_nonce(&self) -> &[u8] {
        &self.execution_nonce
    }

    pub(crate) fn release_authorized_at_ms(&self) -> u64 {
        self.release_authorized_at_ms
    }

    pub(crate) fn process_group_id(&self) -> i64 {
        self.process_group_id
    }

    pub(crate) fn leader_pid(&self) -> i64 {
        self.leader_pid
    }

    pub(crate) fn leader_start_time(&self) -> u64 {
        self.leader_start_time
    }

    pub(crate) fn fence_payload(&self) -> &[u8] {
        &self.fence_payload
    }
}

impl std::fmt::Debug for ExecutionReleasePermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionReleasePermit")
            .field("command_id", &self.command_id)
            .field("daemon_boot_id", &self.daemon_boot_id)
            .field("execution_nonce", &"[REDACTED]")
            .field("process_identity", &"[REDACTED]")
            .field("fence_payload", &"[REDACTED]")
            .field("release_authorized_at_ms", &self.release_authorized_at_ms)
            .finish()
    }
}

#[async_trait::async_trait]
pub(crate) trait RuntimeExecutionRelease: Send + 'static {
    /// 消费 committed permit 后才允许 gate release，并且只在 release 成功后返回
    /// completion future。实现不得在本调用前越过 vendor/tool 副作用边界。
    async fn release(
        self: Box<Self>,
        permit: ExecutionReleasePermit,
    ) -> Result<RuntimeCompletionFuture, RuntimeExecutionError>;
}

pub(crate) struct PreparedRuntimeExecution {
    pub(crate) process: RuntimeProcessIdentity,
    pub(crate) control: Arc<dyn RuntimeExecutionControl>,
    pub(crate) release: Box<dyn RuntimeExecutionRelease>,
    #[allow(dead_code)] // P3.5 conversation ApprovalSupervisor consumes this stream。
    pub(crate) events: RuntimeExecutionEventReceiver,
}

/// P3.7 production execution owner。它只调用 typed router prepare，并把 current-binary
/// gate 的 release/process capabilities 留在 daemon；adapter 只取得私有 stdio。
pub(crate) struct GatedExecutionCoordinator {
    router: Arc<AgentRouter>,
    processes: Arc<dyn ProcessGroupController>,
    #[cfg(debug_assertions)]
    gate_binary: Option<PathBuf>,
}

impl GatedExecutionCoordinator {
    pub(crate) fn new(router: Arc<AgentRouter>) -> Self {
        Self {
            router,
            processes: Arc::new(SystemProcessGroupController),
            #[cfg(debug_assertions)]
            gate_binary: None,
        }
    }

    /// debug-only automatic E2E 仍运行 production coordinator，但显式把 gate 指向
    /// Cargo 构建出的真实 `agentdeckd` binary；integration-test harness 自身不实现
    /// `--exec-gate`，不能被误当成 current daemon executable。
    #[cfg(debug_assertions)]
    pub(crate) fn for_synthetic_e2e(router: Arc<AgentRouter>, gate_binary: PathBuf) -> Self {
        Self {
            router,
            processes: Arc::new(SystemProcessGroupController),
            gate_binary: Some(gate_binary),
        }
    }
}

#[async_trait::async_trait]
impl RuntimeExecutionCoordinator for GatedExecutionCoordinator {
    fn is_ready(&self) -> bool {
        true
    }

    async fn prepare(
        &self,
        context: RuntimeExecutionContext,
    ) -> Result<PreparedRuntimeExecution, RuntimeExecutionError> {
        let execution_id = ExecutionId::from_command_id(context.command.command_id)
            .map_err(|_| RuntimeExecutionError::PrepareFailedClean)?;
        let prompt = String::from_utf8(context.command.payload.clone())
            .map_err(|_| RuntimeExecutionError::PrepareFailedClean)?;
        let request = AgentTurnRequest::new(
            execution_id,
            context.conversation.descriptor.cwd.clone(),
            PromptPayload::new(prompt).map_err(|_| RuntimeExecutionError::PrepareFailedClean)?,
            context.configuration_revision,
            context.execution_configuration,
        )
        .map_err(|_| RuntimeExecutionError::PrepareFailedClean)?;
        let state = AdapterStateHandle::new(context.conversation.adapter_state_key)
            .map_err(|_| RuntimeExecutionError::PrepareFailedClean)?;
        let prepared = self
            .router
            .prepare_turn(context.conversation.descriptor.agent_kind, request, state)
            .await
            .map_err(|_| RuntimeExecutionError::PrepareFailedClean)?;
        let mut gate = {
            let spec = prepared
                .checked_exec_spec()
                .map_err(|_| RuntimeExecutionError::PrepareFailedClean)?;
            #[cfg(debug_assertions)]
            let spawned = match self.gate_binary.as_deref() {
                Some(binary) => {
                    GatedChild::spawn_with_binary(
                        binary,
                        context.daemon_boot_id,
                        context.execution_nonce.clone(),
                        spec,
                    )
                    .await
                }
                None => {
                    GatedChild::spawn_current(
                        context.daemon_boot_id,
                        context.execution_nonce.clone(),
                        spec,
                    )
                    .await
                }
            };
            #[cfg(not(debug_assertions))]
            let spawned = GatedChild::spawn_current(
                context.daemon_boot_id,
                context.execution_nonce.clone(),
                spec,
            )
            .await;
            spawned.map_err(classify_gate_spawn_failure)?
        };
        let process = gate.runtime_process_identity();
        let identity = gate.process_identity();
        let control = Arc::new(GatedExecutionControl {
            identity,
            processes: self.processes.clone(),
            fence_state: Mutex::new(ExecutionFenceState::Unclaimed),
        });
        let (adapter_events, adapter_receiver) = adapter_event_channel();
        let (adapter_approvals, approval_receiver) = adapter_approval_channel();
        let completion = match prepared.attach(&mut gate, adapter_events, adapter_approvals) {
            Ok(completion) => completion,
            Err(_) => {
                return Err(cleanup_failed_blocked_gate(gate, self.processes.clone()).await);
            }
        };
        let (gate_release, gate_owner) = start_gate_owner(gate, self.processes.clone());
        let (runtime_sender, runtime_receiver) = runtime_execution_event_channel();
        let event_bridge = spawn_adapter_event_bridge(adapter_receiver, runtime_sender.clone());
        let approval_bridge = spawn_adapter_approval_bridge(approval_receiver, runtime_sender);
        Ok(PreparedRuntimeExecution {
            process,
            control: control.clone(),
            release: Box::new(GatedExecutionRelease {
                gate_release: Some(gate_release),
                gate_owner: Some(gate_owner),
                completion: Some(completion),
                event_bridge: Some(event_bridge),
                approval_bridge: Some(approval_bridge),
                control,
            }),
            events: runtime_receiver,
        })
    }
}

fn classify_gate_spawn_failure(error: GatedChildSpawnError) -> RuntimeExecutionError {
    if error.permits_clean_prepare_failure() {
        RuntimeExecutionError::PrepareFailedClean
    } else {
        // Ready handshake 及其后的失败已经取得 Child；内部 cleanup 仅 best-effort，
        // 没有 exact PGID absence proof，因此必须继续 fail-close。
        RuntimeExecutionError::PrepareFailed
    }
}

struct GatedExecutionControl {
    identity: ProcessIdentity,
    processes: Arc<dyn ProcessGroupController>,
    fence_state: Mutex<ExecutionFenceState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionFenceMode {
    UserCancel,
    NormalCompletion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionFenceState {
    Unclaimed,
    InFlight(ExecutionFenceMode),
    Finished(Result<ExecutionFenceMode, RuntimeExecutionError>),
}

#[async_trait::async_trait]
impl RuntimeExecutionControl for GatedExecutionControl {
    async fn cancel_and_wait_fenced(
        &self,
    ) -> Result<RuntimeCancelDisposition, RuntimeExecutionError> {
        // 用户 Cancel 与 adapter EOF cleanup 可能同时抵达。只允许一个 owner 操作
        // exact group；其余调用复用同一个已证明结果，避免 leader 已退出、tool child
        // 尚留 PGID 时第二个调用把 Unknown 误判成新的 fencing failure。
        match self.fence_and_wait(ExecutionFenceMode::UserCancel).await? {
            ExecutionFenceMode::UserCancel => Ok(RuntimeCancelDisposition::UserCancelWon),
            ExecutionFenceMode::NormalCompletion => Ok(RuntimeCancelDisposition::AlreadyCompleting),
        }
    }
}

impl GatedExecutionControl {
    async fn fence_and_wait(
        &self,
        mode: ExecutionFenceMode,
    ) -> Result<ExecutionFenceMode, RuntimeExecutionError> {
        let mut fence_state = self.fence_state.lock().await;
        match *fence_state {
            ExecutionFenceState::Finished(result) => return result,
            // 威胁场景：首个 fence future 在 OS await 中被取消；若后到调用接管同一
            // 整数 PGID，就会丢失原 owner 的结果并可能误判 PID reuse。owner mode 在
            // await 前写入，取消后统一 fail-close，不能静默换赢家。
            ExecutionFenceState::InFlight(_) => {
                return Err(RuntimeExecutionError::CancelFailed);
            }
            ExecutionFenceState::Unclaimed => {
                *fence_state = ExecutionFenceState::InFlight(mode);
            }
        }
        let result = match mode {
            ExecutionFenceMode::UserCancel => {
                terminate_exact_group(
                    self.processes.as_ref(),
                    self.identity,
                    EXECUTION_TERM_GRACE,
                    EXECUTION_KILL_GRACE,
                )
                .await
            }
            // adapter 已给出 terminal 后不再需要 vendor/tool 做清理；立即 KILL exact
            // sentinel group，避免正常 turn 平白等待 TERM grace。
            ExecutionFenceMode::NormalCompletion => {
                kill_exact_group(self.processes.as_ref(), self.identity, EXECUTION_KILL_GRACE).await
            }
        }
        .map(|_| mode);
        *fence_state = ExecutionFenceState::Finished(result);
        result
    }
}

struct GatedExecutionRelease {
    gate_release: Option<GatedChildRelease>,
    gate_owner: Option<AbortOnDropGateOwner<Result<(), ()>>>,
    completion: Option<crate::agent::AdapterCompletionFuture>,
    event_bridge: Option<JoinHandle<Result<(), ()>>>,
    approval_bridge: Option<JoinHandle<Result<(), ()>>>,
    control: Arc<GatedExecutionControl>,
}

/// `JoinHandle` 默认在 drop 时 detach。completion future 是 gate owner 的唯一上层 owner，
/// 因而必须把 drop 变成 abort；task 被 abort 后会 drop `GatedChildOwner`，由其 exact
/// PID/start-time/PGID guard 对整组做 best-effort KILL 并 reap direct child。
struct AbortOnDropGateOwner<T> {
    task: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropGateOwner<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    async fn join(&mut self) -> Result<T, tokio::task::JoinError> {
        let result = self
            .task
            .as_mut()
            .expect("gate owner can only be joined once")
            .await;
        self.task.take();
        result
    }
}

impl<T> Drop for AbortOnDropGateOwner<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn start_gate_owner(
    gate: GatedChild,
    processes: Arc<dyn ProcessGroupController>,
) -> (GatedChildRelease, AbortOnDropGateOwner<Result<(), ()>>) {
    // 威胁场景：blocked sentinel 在 release 前被 Cancel 杀死；若此时尚无唯一 Child
    // waiter，它会作为 zombie 持续占用 PGID，使只读 absence probe 永远无法成功。
    let (release, mut owner): (GatedChildRelease, GatedChildOwner) = gate.into_owner_parts();
    let task = tokio::spawn(async move {
        owner
            .wait_and_verify_group_exit(processes.as_ref(), EXECUTION_KILL_GRACE)
            .await
            .map(|_| ())
            .map_err(|_| ())
    });
    (release, AbortOnDropGateOwner::new(task))
}

async fn cleanup_failed_blocked_gate(
    gate: GatedChild,
    processes: Arc<dyn ProcessGroupController>,
) -> RuntimeExecutionError {
    let identity = gate.process_identity();
    let (_release, mut owner) = start_gate_owner(gate, processes.clone());
    // 威胁场景：adapter attach 在 blocked sentinel 已 spawn 后失败；若直接返回普通
    // prepare error，actor 可能继续下一条命令，而未收割的 gate 仍占用可复用 PID/PGID。
    // 只有 exact KILL 与唯一 Child owner 的 wait 都成功，才可把失败分类为 clean。
    let (fenced, reaped) = tokio::join!(
        kill_exact_group(processes.as_ref(), identity, EXECUTION_KILL_GRACE),
        tokio::time::timeout(EXECUTION_CANCEL_FENCE_BUDGET, owner.join()),
    );
    if fenced.is_ok() && matches!(reaped, Ok(Ok(Ok(())))) {
        RuntimeExecutionError::PrepareFailedClean
    } else {
        RuntimeExecutionError::PrepareFailed
    }
}

#[async_trait::async_trait]
impl RuntimeExecutionRelease for GatedExecutionRelease {
    async fn release(
        mut self: Box<Self>,
        permit: ExecutionReleasePermit,
    ) -> Result<RuntimeCompletionFuture, RuntimeExecutionError> {
        // 威胁场景：内部 owner/bridge capability 缺失却先写 Release，vendor 会短暂越过
        // 副作用边界且没有完整 completion owner；因此先取齐全部一次性 capability。
        let gate_release = self
            .gate_release
            .take()
            .ok_or(RuntimeExecutionError::ReleaseFailed)?;
        let mut gate_owner = self
            .gate_owner
            .take()
            .ok_or(RuntimeExecutionError::ReleaseFailed)?;
        let completion = self
            .completion
            .take()
            .ok_or(RuntimeExecutionError::ReleaseFailed)?;
        let event_bridge = self
            .event_bridge
            .take()
            .ok_or(RuntimeExecutionError::ReleaseFailed)?;
        let approval_bridge = self
            .approval_bridge
            .take()
            .ok_or(RuntimeExecutionError::ReleaseFailed)?;
        let control = self.control.clone();
        gate_release
            .release(permit)
            .await
            .map_err(|_| RuntimeExecutionError::ReleaseFailed)?;
        // sentinel 被 KILL 后会先成为这个 exact Child owner 的 zombie；prepare-time
        // owner task 已在 gate Ready 后立即等待，必须在 release 前后都复用同一个 task，
        // 否则 pre-release cancel 会把 zombie PGID 误判成仍存活。
        // 威胁场景：actor shutdown/error 丢弃 completion future 时，普通 JoinHandle 会
        // detach 并继续持有已 release 的 GatedChild，vendor/tool group 可在 daemon 失去
        // owner 后继续产生副作用；abort-on-drop owner 把 future 生命周期绑定到整组清理。
        Ok(Box::pin(async move {
            let adapter_result = completion.await;
            if adapter_result.is_ok() {
                control
                    .fence_and_wait(ExecutionFenceMode::NormalCompletion)
                    .await?;
            } else {
                control.cancel_and_wait_fenced().await?;
            }
            let group_exit = tokio::time::timeout(EXECUTION_KILL_GRACE, gate_owner.join()).await;
            if !matches!(group_exit, Ok(Ok(Ok(())))) {
                return Err(RuntimeExecutionError::CompletionClosed);
            }
            match event_bridge.await {
                Ok(Ok(())) => {}
                Ok(Err(())) | Err(_) => return Err(RuntimeExecutionError::CompletionClosed),
            }
            match approval_bridge.await {
                Ok(Ok(())) => {}
                Ok(Err(())) | Err(_) => return Err(RuntimeExecutionError::CompletionClosed),
            }
            let terminal = match adapter_result {
                Ok(summary) => CommandTerminal::completed(summary),
                Err(_) => CommandTerminal::failed(SanitizedTerminalFailure::execution_failed()),
            };
            Ok(RuntimeExecutionCompletion { terminal })
        }))
    }
}

fn spawn_adapter_event_bridge(
    mut receiver: crate::agent::AdapterEventReceiver,
    sender: mpsc::Sender<RuntimeExecutionEvent>,
) -> JoinHandle<Result<(), ()>> {
    tokio::spawn(async move {
        while let Some(delivery) = receiver.recv().await {
            if let Err(error) = sender
                .send(RuntimeExecutionEvent::Adapter { delivery })
                .await
            {
                if let RuntimeExecutionEvent::Adapter { delivery } = error.0 {
                    let (_, acknowledge) = delivery.into_parts();
                    acknowledge.acknowledge(Err(()));
                }
                return Err(());
            }
        }
        Ok(())
    })
}

fn spawn_adapter_approval_bridge(
    mut receiver: crate::agent::AdapterApprovalReceiver,
    sender: mpsc::Sender<RuntimeExecutionEvent>,
) -> JoinHandle<Result<(), ()>> {
    tokio::spawn(async move {
        while let Some(delivery) = receiver.recv().await {
            let (request, delivery, registration_ack) = delivery.into_parts();
            if let Err(error) = sender
                .send(RuntimeExecutionEvent::ActionRequest {
                    request,
                    delivery,
                    registration_ack: Some(registration_ack),
                })
                .await
            {
                if let RuntimeExecutionEvent::ActionRequest {
                    registration_ack: Some(registration_ack),
                    ..
                } = error.0
                {
                    registration_ack.acknowledge(Err(()));
                }
                return Err(());
            }
        }
        Ok(())
    })
}

async fn terminate_exact_group(
    processes: &dyn ProcessGroupController,
    identity: ProcessIdentity,
    term_grace: Duration,
    kill_grace: Duration,
) -> Result<(), RuntimeExecutionError> {
    match processes.probe(identity).await {
        Ok(ProcessObservation::Exited) => return Ok(()),
        Ok(ProcessObservation::ExactAlive) => {}
        Ok(ProcessObservation::Unknown) => {
            return match processes.wait_for_exit(identity, kill_grace).await {
                Ok(ProcessObservation::Exited) => Ok(()),
                _ => Err(RuntimeExecutionError::CancelFailed),
            };
        }
        Ok(ProcessObservation::IdentityMismatch) | Err(_) => {
            return Err(RuntimeExecutionError::CancelFailed);
        }
    }
    processes
        .signal(identity, ProcessSignal::Terminate)
        .await
        .map_err(|_| RuntimeExecutionError::CancelFailed)?;
    match processes.wait_for_exit(identity, term_grace).await {
        Ok(ProcessObservation::Exited) => return Ok(()),
        Ok(ProcessObservation::ExactAlive) => {}
        Ok(ProcessObservation::Unknown) => {
            return match processes.wait_for_exit(identity, kill_grace).await {
                Ok(ProcessObservation::Exited) => Ok(()),
                _ => Err(RuntimeExecutionError::CancelFailed),
            };
        }
        Ok(ProcessObservation::IdentityMismatch) | Err(_) => {
            return Err(RuntimeExecutionError::CancelFailed);
        }
    }
    processes
        .signal(identity, ProcessSignal::Kill)
        .await
        .map_err(|_| RuntimeExecutionError::CancelFailed)?;
    match processes.wait_for_exit(identity, kill_grace).await {
        Ok(ProcessObservation::Exited) => Ok(()),
        _ => Err(RuntimeExecutionError::CancelFailed),
    }
}

async fn kill_exact_group(
    processes: &dyn ProcessGroupController,
    identity: ProcessIdentity,
    kill_grace: Duration,
) -> Result<(), RuntimeExecutionError> {
    match processes.probe(identity).await {
        Ok(ProcessObservation::Exited) => return Ok(()),
        Ok(ProcessObservation::ExactAlive) => {}
        // 威胁场景：sentinel leader 在 normal completion 与 direct-KILL probe 之间自然
        // 退出，而 cooperative tool child 仍短暂持有 PGID；此时身份只能是 Unknown。
        // 不能向失去 exact leader proof 的整数 PGID 发信号，但也不能把短暂退出窗口
        // 立即升级为 RecoveryBlocked，因此只在既有 KILL grace 内等待 group 自然消失。
        Ok(ProcessObservation::Unknown) => {
            return match processes.wait_for_exit(identity, kill_grace).await {
                Ok(ProcessObservation::Exited) => Ok(()),
                _ => Err(RuntimeExecutionError::CancelFailed),
            };
        }
        Ok(ProcessObservation::IdentityMismatch) | Err(_) => {
            return Err(RuntimeExecutionError::CancelFailed);
        }
    }
    processes
        .signal(identity, ProcessSignal::Kill)
        .await
        .map_err(|_| RuntimeExecutionError::CancelFailed)?;
    match processes.wait_for_exit(identity, kill_grace).await {
        Ok(ProcessObservation::Exited) => Ok(()),
        _ => Err(RuntimeExecutionError::CancelFailed),
    }
}

#[async_trait::async_trait]
pub(crate) trait RuntimeExecutionCoordinator: Send + Sync + 'static {
    /// P3.7 两阶段 gate 尚未安装时必须返回 false。RuntimeCore 据此让已经
    /// Accepted 的命令留在 durable queue，禁止为了得到测试绿灯而写入 Started
    /// 或伪造 process fence。
    fn is_ready(&self) -> bool;

    /// 必须只准备 blocked child / side-effect-free fake；在 completion future 被
    /// poll 前不得越过 vendor/tool 副作用边界。
    async fn prepare(
        &self,
        context: RuntimeExecutionContext,
    ) -> Result<PreparedRuntimeExecution, RuntimeExecutionError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DisabledExecutionCoordinator;

#[async_trait::async_trait]
impl RuntimeExecutionCoordinator for DisabledExecutionCoordinator {
    fn is_ready(&self) -> bool {
        false
    }

    async fn prepare(
        &self,
        _context: RuntimeExecutionContext,
    ) -> Result<PreparedRuntimeExecution, RuntimeExecutionError> {
        Err(RuntimeExecutionError::GateUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RuntimeExecutionError {
    #[error("the two-phase execution gate is not installed")]
    GateUnavailable,
    /// 仅表示 release 前失败，且 coordinator 从未取得 child，或已用唯一 owner 证明
    /// exact gate process group 全部退出；actor 才能据此安全启动 successor。
    #[error("execution preparation failed before release with no surviving child")]
    PrepareFailedClean,
    #[error("execution preparation failed")]
    PrepareFailed,
    #[error("execution cancel failed")]
    CancelFailed,
    #[error("execution completion channel closed")]
    #[allow(dead_code)] // P3.7 gate IPC completion path。
    CompletionClosed,
    #[error("durable execution release authorization is invalid")]
    ReleaseAuthorizationInvalid,
    #[error("execution gate release failed")]
    #[allow(dead_code)] // P3.7 gate IPC release path。
    ReleaseFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use agentdeck_protocol::runtime::{
        CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{
        AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode, TurnSummary,
    };
    use tokio::process::Command;

    use crate::exec_gate::ExecGateError;
    use crate::runtime::process_identity::ProcessControlError;
    use crate::runtime::store::{
        AcceptCommand, AcceptOutcome, ConfigurationRecord, ConfigureConversation,
        ConfigureConversationOutcome, ConversationDescriptor, ExecutionFence, IdempotencyOwner,
        NewConversation, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreHandle, StartCommand,
    };
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    static NEXT_TYPED_GATE_ROOT: AtomicU64 = AtomicU64::new(1);

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
    }

    #[test]
    fn gate_spawn_disposition_maps_only_proven_no_child_to_clean_failure() {
        // 威胁场景：spawn 层已经准确分类，但 coordinator 映射漂移时仍会把普通
        // no-child failure 永久 RecoveryBlocked，或把 uncertain child 错放行 successor。
        assert_eq!(
            classify_gate_spawn_failure(GatedChildSpawnError::NoSurvivingChild(
                ExecGateError::Rejected,
            )),
            RuntimeExecutionError::PrepareFailedClean
        );
        assert_eq!(
            classify_gate_spawn_failure(GatedChildSpawnError::ChildOutcomeUnknown(
                ExecGateError::Rejected,
            )),
            RuntimeExecutionError::PrepareFailed
        );
    }

    #[tokio::test]
    async fn committed_store_permit_drives_the_typed_release_and_completion_path() {
        // 威胁场景：live-binary tests 直接写 raw Release frame，导致 store COMMIT 后的
        // permit wiring、production release encoder 或 consuming owner 转移损坏却仍绿灯；
        // prepare-time owner 拆分后，release 也必须复用该 owner，不能再创建第二个 waiter。
        let root = Path::new("/tmp").join(format!(
            "agentdeckd-typed-gate-release-{}-{}",
            std::process::id(),
            NEXT_TYPED_GATE_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create typed gate root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure typed gate root");
        let keys = MemoryKeyStore::new();
        let storage_kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
            .expect("create typed gate StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.join("runtime.db")),
            storage_kek,
        )
        .await
        .expect("open typed gate store");

        let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x31);
        store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x32),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::Codex,
                    title: Some("typed release".to_owned()),
                    cwd: root.clone(),
                },
            })
            .await
            .expect("create typed gate conversation");
        assert!(matches!(
            store
                .configure_conversation(ConfigureConversation {
                    conversation_id,
                    owner: IdempotencyOwner::Local {
                        machine_trust_domain: [0x33; 32],
                        uid: 501,
                        client_installation_id: [0x34; 16],
                    },
                    idempotency_key: "typed-gate-release-configuration".to_owned(),
                    expected_configuration_revision: 0,
                    configuration: ConversationConfiguration::new(
                        VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                            CodexApprovalPolicy::OnRequest,
                            CodexSandboxMode::WorkspaceWrite,
                            CodexReasoningEffort::Medium,
                        ),),
                    ),
                })
                .await
                .expect("configure typed gate conversation"),
            ConfigureConversationOutcome::Applied {
                configuration: ConfigurationRecord {
                    configuration_revision: 1,
                    event_seq: 0,
                    ..
                }
            }
        ));
        let command = match store
            .accept_command(AcceptCommand {
                conversation_id,
                owner: IdempotencyOwner::Local {
                    machine_trust_domain: [0x33; 32],
                    uid: 501,
                    client_installation_id: [0x34; 16],
                },
                idempotency_key: "typed-gate-release".to_owned(),
                expected_configuration_revision: 1,
                payload: b"typed release prompt".to_vec(),
            })
            .await
            .expect("accept typed gate command")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh typed gate command replayed"),
        };
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x35);
        let execution_nonce = b"typed-release-nonce".to_vec();
        store
            .mark_started_with_event(StartCommand {
                conversation_id,
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
            })
            .await
            .expect("commit Started before typed gate release");

        let ready = root.join("vendor.ready");
        let mut command_process = Command::new("/bin/sh");
        command_process
            .arg("-c")
            // `exec` 保留 exact leader PID/start-time/PGID，且不创建短命 sleep
            // grandchild。旧 fixture 在 full-suite 负载下偶尔让 shell 与 sleep 同时
            // 退出成尚未被 init 回收的 group，误把测试夹具竞态报告成 CancelFailed。
            .arg("printf ready > \"$1\"; exec /bin/sleep 3600")
            .arg("typed-release-vendor")
            .arg(&ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // SAFETY: process 尚未 spawn；setpgid(0, 0) 只创建本测试独占的 process group。
        unsafe {
            command_process.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let child = command_process.spawn().expect("spawn typed release vendor");
        let leader_pid = i64::from(child.id().expect("typed vendor pid"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "typed release vendor did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let process = ProcessIdentity::for_process_group_leader(leader_pid)
            .expect("read exact typed release process identity");
        let (parent_control, mut child_control) =
            std::os::unix::net::UnixStream::pair().expect("create typed release control pair");
        child_control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bound typed release read");
        let release_token = [0x36; crate::exec_gate::RELEASE_TOKEN_BYTES];
        let token_commitment = [0x37; crate::exec_gate::TOKEN_COMMITMENT_BYTES];
        let gate = GatedChild::new_for_test(
            (
                ExecutionId::from_command_id(command.command_id).unwrap(),
                daemon_boot_id,
                execution_nonce.clone(),
                process,
            ),
            (release_token, token_commitment),
            parent_control,
            child,
        );
        store
            .persist_execution_fence(ExecutionFence {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                process_group_id: process.process_group_id(),
                leader_pid: process.leader_pid(),
                leader_start_time: process.leader_start_time(),
                payload: token_commitment.to_vec(),
            })
            .await
            .expect("commit exact typed release fence");
        let authorization = AuthorizeExecutionRelease {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        };
        let committed = store
            .authorize_execution_release(authorization.clone())
            .await
            .expect("commit typed release authorization");
        let permit = ExecutionReleasePermit::from_committed_store(&authorization, &committed)
            .expect("mint permit only from committed store record");

        let processes: Arc<dyn ProcessGroupController> = Arc::new(SystemProcessGroupController);
        let control = Arc::new(GatedExecutionControl {
            identity: process,
            processes: processes.clone(),
            fence_state: Mutex::new(ExecutionFenceState::Unclaimed),
        });
        let (gate_release, gate_owner) = start_gate_owner(gate, processes.clone());
        // 让 prepare-time owner 先进入 direct-child wait，再验证 release 仍复用同一 owner。
        tokio::task::yield_now().await;
        let release: Box<dyn RuntimeExecutionRelease> = Box::new(GatedExecutionRelease {
            gate_release: Some(gate_release),
            gate_owner: Some(gate_owner),
            completion: Some(Box::pin(async {
                Ok(TurnSummary {
                    total_input_tokens: Some(1),
                    total_output_tokens: Some(2),
                    elapsed_ms: 3,
                })
            })),
            event_bridge: Some(tokio::spawn(async { Ok(()) })),
            approval_bridge: Some(tokio::spawn(async { Ok(()) })),
            control,
        });
        let completion = release
            .release(permit)
            .await
            .expect("consume committed permit through production release owner");
        let frame = crate::exec_gate::read_parent_frame_for_test(&mut child_control)
            .expect("read production release frame");
        let crate::exec_gate::ParentFrame::Release {
            command_id,
            daemon_boot_id: encoded_boot_id,
            execution_nonce: encoded_nonce,
            process_group_id,
            leader_pid: encoded_leader_pid,
            leader_start_time,
            release_token: encoded_release_token,
            token_commitment: encoded_commitment,
            release_authorized_at_ms,
        } = frame
        else {
            panic!("typed release emitted a non-release frame");
        };
        assert_eq!(command_id, command.command_id.to_canonical_string());
        assert_eq!(encoded_boot_id, daemon_boot_id.to_canonical_string());
        assert_eq!(encoded_nonce, execution_nonce);
        assert_eq!(process_group_id, process.process_group_id());
        assert_eq!(encoded_leader_pid, process.leader_pid());
        assert_eq!(leader_start_time, process.leader_start_time());
        assert_eq!(encoded_release_token, release_token);
        assert_eq!(encoded_commitment, token_commitment);
        assert_eq!(
            Some(release_authorized_at_ms),
            committed.release_authorized_at_ms
        );

        let completed = tokio::time::timeout(Duration::from_secs(5), completion)
            .await
            .expect("typed completion timeout")
            .expect("typed completion result");
        assert_eq!(
            completed.terminal.terminal_state(),
            crate::runtime::store::TerminalState::Completed
        );
        store.shutdown().await.expect("shutdown typed gate store");
        let _ = fs::remove_dir_all(&root);
    }

    struct SingleFlightFenceController {
        first_observation: ProcessObservation,
        probe_count: AtomicUsize,
        signals: std::sync::Mutex<Vec<ProcessSignal>>,
        wait_entered: tokio::sync::Notify,
        release_wait: tokio::sync::Notify,
    }

    impl SingleFlightFenceController {
        fn new(first_observation: ProcessObservation) -> Self {
            Self {
                first_observation,
                probe_count: AtomicUsize::new(0),
                signals: std::sync::Mutex::new(Vec::new()),
                wait_entered: tokio::sync::Notify::new(),
                release_wait: tokio::sync::Notify::new(),
            }
        }

        fn signals(&self) -> Vec<ProcessSignal> {
            self.signals.lock().expect("fence signals lock").clone()
        }
    }

    #[async_trait::async_trait]
    impl ProcessGroupController for SingleFlightFenceController {
        async fn probe(
            &self,
            _identity: ProcessIdentity,
        ) -> Result<ProcessObservation, ProcessControlError> {
            if self.probe_count.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(self.first_observation)
            } else {
                Ok(ProcessObservation::Unknown)
            }
        }

        async fn signal(
            &self,
            _identity: ProcessIdentity,
            signal: ProcessSignal,
        ) -> Result<(), ProcessControlError> {
            self.signals
                .lock()
                .expect("fence signals lock")
                .push(signal);
            Ok(())
        }

        async fn wait_for_exit(
            &self,
            _identity: ProcessIdentity,
            _timeout: Duration,
        ) -> Result<ProcessObservation, ProcessControlError> {
            self.wait_entered.notify_one();
            self.release_wait.notified().await;
            Ok(ProcessObservation::Exited)
        }
    }

    #[tokio::test]
    async fn user_cancel_wins_eof_cleanup_race_and_shares_one_exact_fence_result() {
        // 威胁场景：用户 Cancel 正在等待 exact PGID 退出时，driver EOF cleanup 再次
        // 请求 normal completion direct-KILL。第二个调用必须等待并复用先到的用户
        // TERM→KILL 模式，不能发起第二套 probe/signal 或升级为 RecoveryBlocked。
        let processes = Arc::new(SingleFlightFenceController::new(
            ProcessObservation::ExactAlive,
        ));
        let control = Arc::new(GatedExecutionControl {
            identity: ProcessIdentity::new(42, 42, 43).expect("valid test process identity"),
            processes: processes.clone(),
            fence_state: Mutex::new(ExecutionFenceState::Unclaimed),
        });
        let first = tokio::spawn({
            let control = control.clone();
            async move { control.cancel_and_wait_fenced().await }
        });
        processes.wait_entered.notified().await;
        let second = tokio::spawn({
            let control = control.clone();
            async move {
                control
                    .fence_and_wait(ExecutionFenceMode::NormalCompletion)
                    .await
            }
        });
        tokio::task::yield_now().await;
        processes.release_wait.notify_one();

        assert_eq!(
            first.await.expect("first fence task"),
            Ok(RuntimeCancelDisposition::UserCancelWon)
        );
        assert_eq!(
            second.await.expect("EOF cleanup task"),
            Ok(ExecutionFenceMode::UserCancel)
        );
        assert_eq!(
            processes.probe_count.load(Ordering::SeqCst),
            1,
            "only the single-flight owner may probe/signal the exact group"
        );
        assert_eq!(processes.signals(), vec![ProcessSignal::Terminate]);
    }

    #[tokio::test]
    async fn normal_completion_wins_cancel_race_with_direct_kill() {
        // 威胁场景：adapter 已提交 terminal/EOF，若 normal cleanup 平白等待 TERM grace，
        // 忽略 TERM 的 tool child 会继续副作用两秒；normal 模式先到时必须直接 KILL，
        // 随后的用户 Cancel 只能复用该结果。
        let processes = Arc::new(SingleFlightFenceController::new(
            ProcessObservation::ExactAlive,
        ));
        let control = Arc::new(GatedExecutionControl {
            identity: ProcessIdentity::new(52, 52, 53).expect("valid normal fence identity"),
            processes: processes.clone(),
            fence_state: Mutex::new(ExecutionFenceState::Unclaimed),
        });
        let normal = tokio::spawn({
            let control = control.clone();
            async move {
                control
                    .fence_and_wait(ExecutionFenceMode::NormalCompletion)
                    .await
            }
        });
        processes.wait_entered.notified().await;
        let cancel = tokio::spawn({
            let control = control.clone();
            async move { control.cancel_and_wait_fenced().await }
        });
        tokio::task::yield_now().await;
        processes.release_wait.notify_one();

        assert_eq!(
            normal.await.expect("normal fence task"),
            Ok(ExecutionFenceMode::NormalCompletion)
        );
        assert_eq!(
            cancel.await.expect("cancel follower task"),
            Ok(RuntimeCancelDisposition::AlreadyCompleting)
        );
        assert_eq!(processes.probe_count.load(Ordering::SeqCst), 1);
        assert_eq!(processes.signals(), vec![ProcessSignal::Kill]);
    }

    #[tokio::test]
    async fn normal_completion_waits_when_leader_exits_before_group() {
        let processes = Arc::new(SingleFlightFenceController::new(
            ProcessObservation::Unknown,
        ));
        let control = Arc::new(GatedExecutionControl {
            identity: ProcessIdentity::new(57, 57, 58).expect("valid exited-leader identity"),
            processes: processes.clone(),
            fence_state: Mutex::new(ExecutionFenceState::Unclaimed),
        });
        let normal = tokio::spawn({
            let control = control.clone();
            async move {
                control
                    .fence_and_wait(ExecutionFenceMode::NormalCompletion)
                    .await
            }
        });
        processes.wait_entered.notified().await;
        assert!(
            processes.signals().is_empty(),
            "Unknown identity must never authorize an integer-PGID signal"
        );
        processes.release_wait.notify_one();
        assert_eq!(
            normal.await.expect("normal unknown fence task"),
            Ok(ExecutionFenceMode::NormalCompletion)
        );
        assert!(processes.signals().is_empty());
    }

    #[tokio::test]
    async fn sentinel_identity_mismatch_never_signals_and_result_is_sticky() {
        // 威胁场景：sentinel PID/start-time 已不匹配；无论 normal completion 还是随后
        // Cancel，都不能把整数 PGID 当作 owner token 发信号。
        let processes = Arc::new(SingleFlightFenceController::new(
            ProcessObservation::IdentityMismatch,
        ));
        let control = GatedExecutionControl {
            identity: ProcessIdentity::new(62, 62, 63).expect("valid mismatch identity"),
            processes: processes.clone(),
            fence_state: Mutex::new(ExecutionFenceState::Unclaimed),
        };

        assert_eq!(
            control
                .fence_and_wait(ExecutionFenceMode::NormalCompletion)
                .await,
            Err(RuntimeExecutionError::CancelFailed)
        );
        assert_eq!(
            control.cancel_and_wait_fenced().await,
            Err(RuntimeExecutionError::CancelFailed)
        );
        assert_eq!(processes.probe_count.load(Ordering::SeqCst), 1);
        assert!(processes.signals().is_empty());
    }

    async fn spawn_term_resistant_test_gate(
        label: &str,
    ) -> (PathBuf, GatedChild, ProcessIdentity, i32) {
        let root = Path::new("/tmp").join(format!(
            "agentdeckd-{label}-{}-{}",
            std::process::id(),
            NEXT_TYPED_GATE_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create real gate root");
        let child_pid_path = root.join("tool.pid");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(concat!(
                "trap '' TERM; ",
                "/bin/sh -c 'trap \"\" HUP TERM; while :; do /bin/sleep 1; done' & tool=$!; ",
                "printf '%s' \"$tool\" > \"$1\"; ",
                "while :; do /bin/sleep 1; done"
            ))
            .arg(label)
            .arg(&child_pid_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // SAFETY: child 尚未 spawn；setpgid(0, 0) 只建立本测试独占 process group。
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let child = command.spawn().expect("spawn real gate group");
        let leader_pid = i64::from(child.id().expect("real gate leader pid"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !child_pid_path.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "real gate tool did not start"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let tool_pid = fs::read_to_string(&child_pid_path)
            .expect("read real gate tool pid")
            .parse::<i32>()
            .expect("parse real gate tool pid");
        let identity =
            ProcessIdentity::for_process_group_leader(leader_pid).expect("read real gate identity");
        let execution_id = ExecutionId::from_command_id(runtime_id(RuntimeIdKind::Command, 0x91))
            .expect("real gate execution id");
        let (control_socket, peer_socket) =
            std::os::unix::net::UnixStream::pair().expect("create real gate owner socket");
        drop(peer_socket);
        let gate = GatedChild::new_for_test(
            (
                execution_id,
                runtime_id(RuntimeIdKind::DaemonBoot, 0x92),
                b"real-cancel-owner-nonce".to_vec(),
                identity,
            ),
            ([0x93; 32], [0x94; 32]),
            control_socket,
            child,
        );
        (root, gate, identity, tool_pid)
    }

    #[tokio::test]
    async fn pre_release_cancel_reuses_prepare_time_owner_to_reap_term_resistant_gate() {
        // 威胁场景：gate Ready 后、release 前收到 Cancel，且 sentinel/tool 都忽略 TERM；
        // 若 Child owner 直到 release 才启动，KILL 后的 zombie sentinel 会让 exact PGID
        // absence readback 超时并误报 CancelFailed。此测试故意从不调用 release。
        let (root, gate, identity, tool_pid) =
            spawn_term_resistant_test_gate("real-cancel-reap").await;
        let processes: Arc<dyn ProcessGroupController> = Arc::new(SystemProcessGroupController);
        let (_unused_release, mut gate_owner) = start_gate_owner(gate, processes.clone());
        let control = GatedExecutionControl {
            identity,
            processes: processes.clone(),
            fence_state: Mutex::new(ExecutionFenceState::Unclaimed),
        };

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(8), control.cancel_and_wait_fenced())
                .await
                .expect("real cancel fence timed out")
                .expect("real cancel fence succeeds after owner reap"),
            RuntimeCancelDisposition::UserCancelWon
        );
        gate_owner
            .join()
            .await
            .expect("join real cancel gate owner")
            .expect("prepare-time owner proves exact group exit");
        assert_eq!(
            processes
                .wait_for_exit(identity, Duration::from_secs(2))
                .await
                .expect("verify real cancel group exit"),
            ProcessObservation::Exited
        );
        // SAFETY: signal 0 only checks that the exact fixture tool PID is gone.
        assert!(
            unsafe { libc::kill(tool_pid, 0) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "real cancel left the tool child alive"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn post_spawn_prepare_failure_is_clean_only_after_exact_kill_and_owner_reap() {
        // 威胁场景：adapter attach 在 gate spawn 后失败；若仅因 vendor 尚未 release 就
        // 回报 clean，遗留 sentinel zombie 会让 actor 启动 successor 并丢失旧 PID/PGID
        // 的可靠 ownership。clean 分类必须等待真实 process group 消失。
        let (root, gate, identity, tool_pid) =
            spawn_term_resistant_test_gate("attach-failure-cleanup").await;
        let processes: Arc<dyn ProcessGroupController> = Arc::new(SystemProcessGroupController);

        assert_eq!(
            cleanup_failed_blocked_gate(gate, processes.clone()).await,
            RuntimeExecutionError::PrepareFailedClean
        );
        assert_eq!(
            processes
                .wait_for_exit(identity, Duration::from_secs(2))
                .await
                .expect("verify failed-attach group exit"),
            ProcessObservation::Exited
        );
        // SAFETY: signal 0 only checks that the exact fixture tool PID was reaped/removed.
        assert!(
            unsafe { libc::kill(tool_pid, 0) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "post-spawn clean prepare failure left the tool child alive"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct KillThenReportSignalFailure;

    #[async_trait::async_trait]
    impl ProcessGroupController for KillThenReportSignalFailure {
        async fn probe(
            &self,
            identity: ProcessIdentity,
        ) -> Result<ProcessObservation, ProcessControlError> {
            SystemProcessGroupController.probe(identity).await
        }

        async fn signal(
            &self,
            identity: ProcessIdentity,
            signal: ProcessSignal,
        ) -> Result<(), ProcessControlError> {
            SystemProcessGroupController
                .signal(identity, signal)
                .await?;
            Err(ProcessControlError::Signal(io::Error::other(
                "injected post-signal failure",
            )))
        }

        async fn wait_for_exit(
            &self,
            identity: ProcessIdentity,
            timeout: Duration,
        ) -> Result<ProcessObservation, ProcessControlError> {
            SystemProcessGroupController
                .wait_for_exit(identity, timeout)
                .await
        }
    }

    #[tokio::test]
    async fn post_spawn_prepare_failure_stays_blocked_when_exact_kill_reports_failure() {
        // 威胁场景：attach 失败后的 KILL 已送达，但 controller 无法证明 signal 结果；
        // 即使唯一 owner 随后成功 reap，也不能把不完整的 fencing 证据降级为 clean。
        let (root, gate, identity, tool_pid) =
            spawn_term_resistant_test_gate("attach-failure-signal-unknown").await;
        let cleanup: Arc<dyn ProcessGroupController> = Arc::new(KillThenReportSignalFailure);

        assert_eq!(
            cleanup_failed_blocked_gate(gate, cleanup).await,
            RuntimeExecutionError::PrepareFailed
        );
        assert_eq!(
            SystemProcessGroupController
                .wait_for_exit(identity, Duration::from_secs(2))
                .await
                .expect("verify failed cleanup fixture is gone"),
            ProcessObservation::Exited
        );
        // SAFETY: signal 0 only checks that the exact fixture tool PID is gone.
        assert!(
            unsafe { libc::kill(tool_pid, 0) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "failed cleanup classification left the fixture tool alive"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn dropping_completion_owned_gate_task_kills_and_reaps_the_whole_group() {
        // 威胁场景：actor shutdown 或错误路径 drop completion future 时，若 gate owner
        // JoinHandle detach，已 release 的 TERM-resistant vendor/tool group 会脱离 daemon
        // 生命周期继续运行；owner guard drop 必须触发整组 KILL 与 direct-child reap。
        let (root, gate, identity, tool_pid) =
            spawn_term_resistant_test_gate("completion-drop-reap").await;
        let processes: Arc<dyn ProcessGroupController> = Arc::new(SystemProcessGroupController);
        let (_unused_release, gate_owner) = start_gate_owner(gate, processes.clone());

        drop(gate_owner);
        assert_eq!(
            processes
                .wait_for_exit(identity, Duration::from_secs(5))
                .await
                .expect("verify completion-drop group exit"),
            ProcessObservation::Exited
        );
        // SAFETY: signal 0 only checks that the exact fixture tool PID is gone.
        assert!(
            unsafe { libc::kill(tool_pid, 0) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "completion drop left the tool child alive"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn release_permit_requires_the_exact_committed_execution_nonce() {
        let command_id = runtime_id(RuntimeIdKind::Command, 1);
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 2);
        let request = AuthorizeExecutionRelease {
            command_id,
            daemon_boot_id,
            execution_nonce: b"request-nonce".to_vec(),
        };
        let mismatched = ExecutionFenceRecord {
            command_id,
            daemon_boot_id,
            execution_nonce: b"other-nonce".to_vec(),
            process_group_id: 42,
            leader_pid: 42,
            leader_start_time: 43,
            release_authorized_at_ms: Some(44),
            payload: vec![45; 32],
        };
        assert!(matches!(
            ExecutionReleasePermit::from_committed_store(&request, &mismatched),
            Err(RuntimeExecutionError::ReleaseAuthorizationInvalid)
        ));

        let committed = ExecutionFenceRecord {
            execution_nonce: request.execution_nonce.clone(),
            ..mismatched
        };
        let permit = ExecutionReleasePermit::from_committed_store(&request, &committed)
            .expect("exact committed nonce mints permit");
        assert_eq!(permit.command_id(), command_id);
        assert_eq!(permit.daemon_boot_id(), daemon_boot_id);
        assert_eq!(permit.execution_nonce(), request.execution_nonce);
        assert_eq!(permit.process_group_id(), 42);
        assert_eq!(permit.leader_pid(), 42);
        assert_eq!(permit.leader_start_time(), 43);
        assert_eq!(permit.fence_payload(), &[45; 32]);
        assert_eq!(permit.release_authorized_at_ms(), 44);
    }

    #[tokio::test]
    async fn execution_approval_event_channel_is_bounded_and_closed_stream_terminates() {
        assert_eq!(RUNTIME_EXECUTION_EVENT_CAPACITY, 64);
        let mut events = closed_execution_events();
        assert!(events.recv().await.is_none());
    }
}
