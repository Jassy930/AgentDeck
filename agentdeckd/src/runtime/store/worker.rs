//! 单 blocking worker 独占 Runtime SQLite connection 的 async handle。

use std::collections::HashMap;
use std::fmt;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

use crate::runtime::adapter_state::AdapterStateNamespace;
use crate::runtime::model::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CompleteCommand, CompleteOutcome,
    ConversationRecord, ExecutionFence, ExecutionFenceRecord, MAX_ADAPTER_STATE_REFERENCE_BYTES,
    MAX_COMMAND_PAYLOAD_BYTES, MAX_COMMAND_RESULT_BYTES, MAX_CONVERSATION_DESCRIPTOR_BYTES,
    MAX_EXECUTION_FENCE_BYTES, MAX_EXECUTION_INTENT_BYTES, MAX_EXECUTION_NONCE_BYTES,
    MAX_IDEMPOTENCY_KEY_BYTES, MAX_RUNTIME_BUSY_TIMEOUT_MS, MAX_RUNTIME_EVENT_BYTES,
    MAX_RUNTIME_STORE_COMMAND_CAPACITY, MAX_RUNTIME_STORE_LANE_BYTE_CAPACITY,
    MachineEnrollmentReceiptRecord, NewConversation, RUNTIME_STORE_SHUTDOWN_GRACE_MS,
    RecoveryCompletion, RecoveryCursor, RecoveryPage, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreLane, RuntimeStoreOperation, RuntimeStoreSnapshot, StartCommand, StartOutcome,
};
use crate::security::{SecretBytes, StorageKek};

use super::{journal, sqlite};

const LIFECYCLE_RUNNING: u8 = 0;
const LIFECYCLE_SHUTTING_DOWN: u8 = 1;
const LIFECYCLE_STOPPED: u8 = 2;

pub(crate) struct StoreOpenLease;

pub(crate) fn claim_store_path(path: &Path) -> Result<Arc<StoreOpenLease>, RuntimeStoreError> {
    static OPEN_STORES: OnceLock<Mutex<HashMap<PathBuf, Weak<StoreOpenLease>>>> = OnceLock::new();
    let registry = OPEN_STORES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut stores = registry
        .lock()
        .map_err(|_| RuntimeStoreError::WorkerStopped)?;
    stores.retain(|_, lease| lease.strong_count() > 0);
    if stores.get(path).and_then(Weak::upgrade).is_some() {
        return Err(RuntimeStoreError::StoreAlreadyOpen);
    }
    let lease = Arc::new(StoreOpenLease);
    stores.insert(path.to_path_buf(), Arc::downgrade(&lease));
    Ok(lease)
}

#[derive(Clone)]
pub struct RuntimeStoreHandle {
    normal_tx: mpsc::Sender<Queued<NormalCommand>>,
    safety_tx: mpsc::Sender<Queued<SafetyCommand>>,
    read_tx: mpsc::Sender<ReadCommand>,
    control_tx: mpsc::Sender<ControlCommand>,
    normal_budget: Arc<Semaphore>,
    safety_budget: Arc<Semaphore>,
    lifecycle: Arc<AtomicU8>,
    interrupt: Arc<rusqlite::InterruptHandle>,
    shutdown_timeout: Duration,
}

/// 固定绑定到 Codex 私有 namespace 的能力句柄。
///
/// adapter 只能拿到与自身类型对应的 vault；namespace 枚举和通用明文入口不跨出
/// runtime/store 边界。
#[derive(Clone, Debug)]
pub(crate) struct CodexAdapterStateVault {
    store: RuntimeStoreHandle,
}

impl CodexAdapterStateVault {
    pub(crate) async fn bind(
        &self,
        adapter_state_key: super::RuntimeId,
        state_reference: SecretBytes,
    ) -> Result<(), RuntimeStoreError> {
        self.store
            .bind_adapter_state(
                AdapterStateNamespace::Codex,
                adapter_state_key,
                state_reference,
            )
            .await
    }

    pub(crate) async fn resolve(
        &self,
        adapter_state_key: super::RuntimeId,
    ) -> Result<Option<SecretBytes>, RuntimeStoreError> {
        self.store
            .resolve_adapter_state(AdapterStateNamespace::Codex, adapter_state_key)
            .await
    }
}

/// 固定绑定到 Claude Code 私有 namespace 的能力句柄。
#[derive(Clone, Debug)]
pub(crate) struct ClaudeCodeAdapterStateVault {
    store: RuntimeStoreHandle,
}

impl ClaudeCodeAdapterStateVault {
    pub(crate) async fn bind(
        &self,
        adapter_state_key: super::RuntimeId,
        state_reference: SecretBytes,
    ) -> Result<(), RuntimeStoreError> {
        self.store
            .bind_adapter_state(
                AdapterStateNamespace::ClaudeCode,
                adapter_state_key,
                state_reference,
            )
            .await
    }

    pub(crate) async fn resolve(
        &self,
        adapter_state_key: super::RuntimeId,
    ) -> Result<Option<SecretBytes>, RuntimeStoreError> {
        self.store
            .resolve_adapter_state(AdapterStateNamespace::ClaudeCode, adapter_state_key)
            .await
    }
}

impl fmt::Debug for RuntimeStoreHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeStoreHandle")
            .finish_non_exhaustive()
    }
}

impl RuntimeStoreHandle {
    pub async fn open(
        config: RuntimeStoreConfig,
        storage_kek: StorageKek,
    ) -> Result<Self, RuntimeStoreError> {
        if config.command_capacity == 0
            || config.command_capacity > MAX_RUNTIME_STORE_COMMAND_CAPACITY
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "command capacity must be between 1 and 1024",
            ));
        }
        if config.busy_timeout_ms == 0 || config.busy_timeout_ms > MAX_RUNTIME_BUSY_TIMEOUT_MS {
            return Err(RuntimeStoreError::InvalidConfig(
                "busy timeout must be between 1 and 30000 milliseconds",
            ));
        }
        if config.lane_byte_capacity == 0
            || config.lane_byte_capacity > MAX_RUNTIME_STORE_LANE_BYTE_CAPACITY
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "lane byte capacity must be between 1 and 268435456",
            ));
        }
        let shutdown_timeout = Duration::from_millis(
            config
                .busy_timeout_ms
                .saturating_add(RUNTIME_STORE_SHUTDOWN_GRACE_MS),
        );
        let normalized = sqlite::normalize_storage_path(&config.storage_path)?;
        let lease = claim_store_path(&normalized)?;
        let (normal_tx, normal_rx) = mpsc::channel(config.command_capacity);
        let (safety_tx, safety_rx) = mpsc::channel(config.command_capacity);
        let (read_tx, read_rx) = mpsc::channel(config.command_capacity);
        let (control_tx, control_rx) = mpsc::channel(1);
        let normal_budget = Arc::new(Semaphore::new(config.lane_byte_capacity));
        let safety_budget = Arc::new(Semaphore::new(config.lane_byte_capacity));
        let lifecycle = Arc::new(AtomicU8::new(LIFECYCLE_RUNNING));
        let worker_lifecycle = lifecycle.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("agentdeck-runtime-store".to_owned())
            .spawn(move || {
                run(
                    config,
                    storage_kek,
                    WorkerReceivers {
                        normal: normal_rx,
                        safety: safety_rx,
                        read: read_rx,
                        control: control_rx,
                        ready: ready_tx,
                    },
                    lease,
                    worker_lifecycle,
                );
            })?;
        match ready_rx.await {
            Ok(Ok(interrupt)) => Ok(Self {
                normal_tx,
                safety_tx,
                read_tx,
                control_tx,
                normal_budget,
                safety_budget,
                lifecycle,
                interrupt,
                shutdown_timeout,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(RuntimeStoreError::WorkerStopped),
        }
    }

    pub async fn inspect(&self) -> Result<RuntimeStoreSnapshot, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::Inspect { reply },
        )
        .await?
    }

    pub(in crate::runtime) fn codex_adapter_state_vault(&self) -> CodexAdapterStateVault {
        CodexAdapterStateVault {
            store: self.clone(),
        }
    }

    pub(in crate::runtime) fn claude_code_adapter_state_vault(
        &self,
    ) -> ClaudeCodeAdapterStateVault {
        ClaudeCodeAdapterStateVault {
            store: self.clone(),
        }
    }

    pub async fn record_machine_enrollment_receipt(
        &self,
        receipt: MachineEnrollmentReceiptRecord,
    ) -> Result<MachineEnrollmentReceiptRecord, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::RecordEnrollmentReceipt { receipt, reply },
        )
        .await?
    }

    pub async fn create_conversation(
        &self,
        input: NewConversation,
    ) -> Result<ConversationRecord, RuntimeStoreError> {
        let descriptor_bytes = journal::canonical_conversation_descriptor(&input.descriptor)?;
        validate_maximum(descriptor_bytes.len(), MAX_CONVERSATION_DESCRIPTOR_BYTES)?;
        let charge = memory_charge(
            size_of::<NormalCommand>(),
            &[
                input.descriptor.title.as_ref().map_or(0, String::capacity),
                input.descriptor.cwd.capacity(),
                descriptor_bytes.capacity(),
            ],
        )?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::CreateConversation {
                input,
                descriptor_bytes,
                reply,
            },
        )
        .await?
    }

    async fn bind_adapter_state(
        &self,
        namespace: AdapterStateNamespace,
        adapter_state_key: super::RuntimeId,
        state_reference: SecretBytes,
    ) -> Result<(), RuntimeStoreError> {
        if state_reference.expose_secret().is_empty()
            || state_reference.expose_secret().len() > MAX_ADAPTER_STATE_REFERENCE_BYTES
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "adapter state reference must contain 1 to 4096 bytes",
            ));
        }
        // SecretBytes 不暴露原 Vec capacity；先复制到本调用自有的 exact-reserve
        // buffer 并立即销毁调用方 allocation，避免 short-len/huge-capacity 绕过
        // normal lane retained-allocation 预算。
        let mut canonical_reference = Vec::new();
        canonical_reference
            .try_reserve_exact(state_reference.expose_secret().len())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        canonical_reference.extend_from_slice(state_reference.expose_secret());
        drop(state_reference);
        let retained_capacity = canonical_reference.capacity();
        let state_reference = SecretBytes::new(canonical_reference);
        let charge = memory_charge(size_of::<NormalCommand>(), &[retained_capacity])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::BindAdapterState {
                namespace,
                adapter_state_key,
                state_reference,
                reply,
            },
        )
        .await?
    }

    async fn resolve_adapter_state(
        &self,
        namespace: AdapterStateNamespace,
        adapter_state_key: super::RuntimeId,
    ) -> Result<Option<SecretBytes>, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::ResolveAdapterState {
                namespace,
                adapter_state_key,
                reply,
            },
        )
        .await?
    }

    pub async fn accept_command(
        &self,
        input: AcceptCommand,
    ) -> Result<AcceptOutcome, RuntimeStoreError> {
        if input.idempotency_key.is_empty()
            || input.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "idempotency key must contain 1 to 1024 UTF-8 bytes",
            ));
        }
        validate_maximum(input.payload.len(), MAX_COMMAND_PAYLOAD_BYTES)?;
        let charge = memory_charge(
            size_of::<NormalCommand>(),
            &[input.idempotency_key.capacity(), input.payload.capacity()],
        )?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::AcceptCommand { input, reply },
        )
        .await?
    }

    pub async fn mark_started_with_event(
        &self,
        input: StartCommand,
    ) -> Result<StartOutcome, RuntimeStoreError> {
        validate_nonempty_maximum(&input.execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
        validate_maximum(input.intent_payload.len(), MAX_EXECUTION_INTENT_BYTES)?;
        validate_maximum(input.event_payload.len(), MAX_RUNTIME_EVENT_BYTES)?;
        let charge = memory_charge(
            size_of::<NormalCommand>(),
            &[
                input.execution_nonce.capacity(),
                input.intent_payload.capacity(),
                input.event_payload.capacity(),
            ],
        )?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::StartCommand { input, reply },
        )
        .await?
    }

    pub async fn persist_execution_fence(
        &self,
        input: ExecutionFence,
    ) -> Result<ExecutionFenceRecord, RuntimeStoreError> {
        validate_nonempty_maximum(&input.execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
        validate_maximum(input.payload.len(), MAX_EXECUTION_FENCE_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[input.execution_nonce.capacity(), input.payload.capacity()],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::PersistFence { input, reply },
        )
        .await?
    }

    pub async fn authorize_execution_release(
        &self,
        input: AuthorizeExecutionRelease,
    ) -> Result<ExecutionFenceRecord, RuntimeStoreError> {
        validate_nonempty_maximum(&input.execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[input.execution_nonce.capacity()],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::AuthorizeRelease { input, reply },
        )
        .await?
    }

    pub async fn complete_command_with_event(
        &self,
        input: CompleteCommand,
    ) -> Result<CompleteOutcome, RuntimeStoreError> {
        validate_maximum(input.terminal_payload.len(), MAX_COMMAND_RESULT_BYTES)?;
        validate_maximum(input.event_payload.len(), MAX_RUNTIME_EVENT_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[
                input.terminal_payload.capacity(),
                input.event_payload.capacity(),
            ],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::CompleteCommand { input, reply },
        )
        .await?
    }

    /// 校验全库、先清扫过期 Accepted，再冻结本次 recovery catalog high-water。
    ///
    /// begin reply 丢失且尚未读取任何页时，重复调用会返回同一 opaque cursor。
    pub async fn begin_recovery_scan(&self) -> Result<RecoveryCursor, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::BeginRecoveryScan { reply },
        )
        .await?
    }

    /// 每次只物化一个 conversation；只能原样重试当前页或使用上一页返回的 cursor。
    pub async fn load_recovery_page(
        &self,
        cursor: RecoveryCursor,
    ) -> Result<RecoveryPage, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadRecoveryPage { cursor, reply },
        )
        .await?
    }

    /// RuntimeCore 已消费终页后显式完成扫描；此前所有 durable mutation 均 fail-closed。
    pub async fn finish_recovery_scan(
        &self,
        completion: RecoveryCompletion,
    ) -> Result<(), RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::FinishRecoveryScan { completion, reply },
        )
        .await?
    }

    /// 成功回执只在 connection、row keys 和 path lease 全部释放后发送。
    ///
    /// `ShutdownTimedOut` 只表示调用方未在 deadline 前观察到该回执；worker 仍处于
    /// shutting-down，资源继续由 worker 持有，直到 `run` 真正退出。
    pub async fn shutdown(self) -> Result<(), RuntimeStoreError> {
        match self.lifecycle.compare_exchange(
            LIFECYCLE_RUNNING,
            LIFECYCLE_SHUTTING_DOWN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(LIFECYCLE_SHUTTING_DOWN) => return Err(RuntimeStoreError::ShutdownInProgress),
            Err(_) => return Err(RuntimeStoreError::WorkerStopped),
        }
        self.interrupt.interrupt();
        let (reply, result) = oneshot::channel();
        self.control_tx
            .try_send(ControlCommand::Shutdown { reply })
            .map_err(|_| RuntimeStoreError::WorkerStopped)?;
        await_shutdown_quiescence(result, self.shutdown_timeout).await
    }
}

/// 只为 shutdown 调用方设置等待上界；deadline 到达不会改变 worker 生命周期，
/// 也不会释放仍由 worker 持有的 SQLite connection、row keys 或 path lease。
async fn await_shutdown_quiescence(
    result: oneshot::Receiver<()>,
    timeout: Duration,
) -> Result<(), RuntimeStoreError> {
    match tokio::time::timeout(timeout, result).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(RuntimeStoreError::WorkerStopped),
        Err(_) => Err(RuntimeStoreError::ShutdownTimedOut),
    }
}

async fn dispatch<T, C>(
    sender: &mpsc::Sender<C>,
    lifecycle: &AtomicU8,
    lane: RuntimeStoreLane,
    build: impl FnOnce(oneshot::Sender<T>) -> C,
) -> Result<T, RuntimeStoreError> {
    ensure_running(lifecycle)?;
    let (reply, result) = oneshot::channel();
    sender
        .try_send(build(reply))
        .map_err(|error| map_try_send(error, lane))?;
    result.await.map_err(|_| RuntimeStoreError::WorkerStopped)
}

async fn dispatch_with_budget<T, C>(
    sender: &mpsc::Sender<Queued<C>>,
    budget: &Arc<Semaphore>,
    lifecycle: &AtomicU8,
    lane: RuntimeStoreLane,
    memory_bytes: u32,
    build: impl FnOnce(oneshot::Sender<T>) -> C,
) -> Result<T, RuntimeStoreError> {
    ensure_running(lifecycle)?;
    let permit = budget
        .clone()
        .try_acquire_many_owned(memory_bytes)
        .map_err(|error| match error {
            tokio::sync::TryAcquireError::NoPermits => RuntimeStoreError::WorkerBusy { lane },
            tokio::sync::TryAcquireError::Closed => RuntimeStoreError::WorkerStopped,
        })?;
    let (reply, result) = oneshot::channel();
    sender
        .try_send(Queued {
            command: build(reply),
            memory_permit: permit,
        })
        .map_err(|error| map_try_send(error, lane))?;
    result.await.map_err(|_| RuntimeStoreError::WorkerStopped)
}

fn ensure_running(lifecycle: &AtomicU8) -> Result<(), RuntimeStoreError> {
    match lifecycle.load(Ordering::Acquire) {
        LIFECYCLE_RUNNING => Ok(()),
        LIFECYCLE_SHUTTING_DOWN => Err(RuntimeStoreError::ShutdownInProgress),
        _ => Err(RuntimeStoreError::WorkerStopped),
    }
}

fn map_try_send<T>(
    error: mpsc::error::TrySendError<T>,
    lane: RuntimeStoreLane,
) -> RuntimeStoreError {
    match error {
        mpsc::error::TrySendError::Full(_) => RuntimeStoreError::WorkerBusy { lane },
        mpsc::error::TrySendError::Closed(_) => RuntimeStoreError::WorkerStopped,
    }
}

struct Queued<C> {
    command: C,
    memory_permit: OwnedSemaphorePermit,
}

enum NormalCommand {
    CreateConversation {
        input: NewConversation,
        descriptor_bytes: zeroize::Zeroizing<Vec<u8>>,
        reply: oneshot::Sender<Result<ConversationRecord, RuntimeStoreError>>,
    },
    AcceptCommand {
        input: AcceptCommand,
        reply: oneshot::Sender<Result<AcceptOutcome, RuntimeStoreError>>,
    },
    StartCommand {
        input: StartCommand,
        reply: oneshot::Sender<Result<StartOutcome, RuntimeStoreError>>,
    },
    BindAdapterState {
        namespace: AdapterStateNamespace,
        adapter_state_key: super::RuntimeId,
        state_reference: SecretBytes,
        reply: oneshot::Sender<Result<(), RuntimeStoreError>>,
    },
}

enum SafetyCommand {
    RecordEnrollmentReceipt {
        receipt: MachineEnrollmentReceiptRecord,
        reply: oneshot::Sender<Result<MachineEnrollmentReceiptRecord, RuntimeStoreError>>,
    },
    PersistFence {
        input: ExecutionFence,
        reply: oneshot::Sender<Result<ExecutionFenceRecord, RuntimeStoreError>>,
    },
    AuthorizeRelease {
        input: AuthorizeExecutionRelease,
        reply: oneshot::Sender<Result<ExecutionFenceRecord, RuntimeStoreError>>,
    },
    CompleteCommand {
        input: CompleteCommand,
        reply: oneshot::Sender<Result<CompleteOutcome, RuntimeStoreError>>,
    },
}

enum ReadCommand {
    Inspect {
        reply: oneshot::Sender<Result<RuntimeStoreSnapshot, RuntimeStoreError>>,
    },
    BeginRecoveryScan {
        reply: oneshot::Sender<Result<RecoveryCursor, RuntimeStoreError>>,
    },
    LoadRecoveryPage {
        cursor: RecoveryCursor,
        reply: oneshot::Sender<Result<RecoveryPage, RuntimeStoreError>>,
    },
    FinishRecoveryScan {
        completion: RecoveryCompletion,
        reply: oneshot::Sender<Result<(), RuntimeStoreError>>,
    },
    ResolveAdapterState {
        namespace: AdapterStateNamespace,
        adapter_state_key: super::RuntimeId,
        reply: oneshot::Sender<Result<Option<SecretBytes>, RuntimeStoreError>>,
    },
}

enum ControlCommand {
    Shutdown { reply: oneshot::Sender<()> },
}

struct WorkerReceivers {
    normal: mpsc::Receiver<Queued<NormalCommand>>,
    safety: mpsc::Receiver<Queued<SafetyCommand>>,
    read: mpsc::Receiver<ReadCommand>,
    control: mpsc::Receiver<ControlCommand>,
    ready: oneshot::Sender<Result<Arc<rusqlite::InterruptHandle>, RuntimeStoreError>>,
}

fn run(
    config: RuntimeStoreConfig,
    storage_kek: StorageKek,
    receivers: WorkerReceivers,
    lease: Arc<StoreOpenLease>,
    lifecycle: Arc<AtomicU8>,
) {
    let WorkerReceivers {
        normal: mut normal_commands,
        safety: mut safety_commands,
        read: mut read_commands,
        control: mut controls,
        ready,
    } = receivers;
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = ready.send(Err(RuntimeStoreError::InvalidConfig(
                "failed to initialize runtime store worker",
            )));
            return;
        }
    };
    let mut state = match sqlite::open(&config, storage_kek) {
        Ok(state) => state,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let interrupt = Arc::new(state.connection.get_interrupt_handle());
    if ready.send(Ok(interrupt)).is_err() {
        return;
    }

    let shutdown_reply = runtime.block_on(async {
        let mut control_open = true;
        let mut safety_open = true;
        let mut read_open = true;
        let mut normal_open = true;
        loop {
            if !control_open && !safety_open && !read_open && !normal_open {
                break None;
            }
            tokio::select! {
                biased;
                control = controls.recv(), if control_open => {
                    match control {
                        Some(ControlCommand::Shutdown { reply }) => break Some(reply),
                        None => control_open = false,
                    }
                }
                command = safety_commands.recv(), if safety_open => {
                    match command {
                        Some(command) => handle_safety(command, &mut state, &config),
                        None => safety_open = false,
                    }
                }
                command = read_commands.recv(), if read_open => {
                    match command {
                        Some(command) => handle_read(command, &mut state, &config),
                        None => read_open = false,
                    }
                }
                command = normal_commands.recv(), if normal_open => {
                    match command {
                        Some(command) => handle_normal(command, &mut state, &config),
                        None => normal_open = false,
                    }
                }
            }
        }
    });

    normal_commands.close();
    safety_commands.close();
    read_commands.close();
    while normal_commands.try_recv().is_ok() {}
    while safety_commands.try_recv().is_ok() {}
    while read_commands.try_recv().is_ok() {}
    controls.close();
    drop(state);
    drop(lease);
    lifecycle.store(LIFECYCLE_STOPPED, Ordering::Release);
    if let Some(reply) = shutdown_reply {
        let _ = reply.send(());
    }
}

fn handle_normal(
    queued: Queued<NormalCommand>,
    state: &mut sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
) {
    let Queued {
        command,
        memory_permit,
    } = queued;
    if state.recovery_scan.is_some() {
        match command {
            NormalCommand::CreateConversation { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::AcceptCommand { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::StartCommand { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::BindAdapterState { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
        }
        drop(memory_permit);
        return;
    }
    match command {
        NormalCommand::CreateConversation {
            input,
            descriptor_bytes,
            reply,
        } => {
            let _ = reply.send(journal::create_conversation(
                state,
                config,
                input,
                descriptor_bytes,
            ));
        }
        NormalCommand::AcceptCommand { input, reply } => {
            let _ = reply.send(journal::accept_command(state, config, input));
        }
        NormalCommand::StartCommand { input, reply } => {
            let _ = reply.send(journal::mark_started_with_event(state, config, input));
        }
        NormalCommand::BindAdapterState {
            namespace,
            adapter_state_key,
            state_reference,
            reply,
        } => {
            let _ = reply.send(journal::bind_adapter_state(
                state,
                config,
                namespace,
                adapter_state_key,
                state_reference,
            ));
        }
    }
    drop(memory_permit);
}

fn handle_safety(
    queued: Queued<SafetyCommand>,
    state: &mut sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
) {
    let Queued {
        command,
        memory_permit,
    } = queued;
    if state.recovery_scan.is_some() {
        match command {
            SafetyCommand::RecordEnrollmentReceipt { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::PersistFence { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::AuthorizeRelease { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::CompleteCommand { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
        }
        drop(memory_permit);
        return;
    }
    match command {
        SafetyCommand::RecordEnrollmentReceipt { receipt, reply } => {
            let _ = reply.send(sqlite::record_machine_enrollment_receipt(
                state, config, receipt,
            ));
        }
        SafetyCommand::PersistFence { input, reply } => {
            let _ = reply.send(journal::persist_execution_fence(state, config, input));
        }
        SafetyCommand::AuthorizeRelease { input, reply } => {
            let _ = reply.send(journal::authorize_execution_release(state, config, input));
        }
        SafetyCommand::CompleteCommand { input, reply } => {
            let _ = reply.send(journal::complete_command_with_event(state, config, input));
        }
    }
    drop(memory_permit);
}

fn handle_read(
    command: ReadCommand,
    state: &mut sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
) {
    match command {
        ReadCommand::Inspect { reply } => {
            let result = config
                .fault_injector
                .before_operation(RuntimeStoreOperation::Inspect)
                .and_then(|()| sqlite::snapshot(&state.connection, config.busy_timeout_ms));
            let _ = reply.send(result);
        }
        ReadCommand::BeginRecoveryScan { reply } => {
            let _ = reply.send(journal::begin_recovery_scan(state, config));
        }
        ReadCommand::LoadRecoveryPage { cursor, reply } => {
            let _ = reply.send(journal::load_recovery_page(state, cursor));
        }
        ReadCommand::FinishRecoveryScan { completion, reply } => {
            let _ = reply.send(journal::finish_recovery_scan(state, completion));
        }
        ReadCommand::ResolveAdapterState {
            namespace,
            adapter_state_key,
            reply,
        } => {
            let _ = reply.send(journal::resolve_adapter_state(
                state,
                namespace,
                adapter_state_key,
            ));
        }
    }
}

fn memory_charge(base_bytes: usize, allocations: &[usize]) -> Result<u32, RuntimeStoreError> {
    let total = allocations
        .iter()
        .try_fold(base_bytes, |total, allocation| {
            total
                .checked_add(*allocation)
                .ok_or(RuntimeStoreError::PayloadTooLarge)
        })?;
    u32::try_from(total).map_err(|_| RuntimeStoreError::PayloadTooLarge)
}

fn validate_maximum(actual: usize, maximum: usize) -> Result<(), RuntimeStoreError> {
    if actual > maximum {
        Err(RuntimeStoreError::PayloadTooLarge)
    } else {
        Ok(())
    }
}

fn validate_nonempty_maximum(value: &[u8], maximum: usize) -> Result<(), RuntimeStoreError> {
    if value.is_empty() {
        Err(RuntimeStoreError::InvalidConfig(
            "execution nonce must not be empty",
        ))
    } else {
        validate_maximum(value.len(), maximum)
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::time::Instant;

    use crate::runtime::store::{RuntimeId, RuntimeIdKind};
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agentdeckd-runtime-shutdown-unit-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create isolated runtime store root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure runtime store root");
            }
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("runtime.db")
        }

        fn storage_kek(&self, store: &MemoryKeyStore) -> StorageKek {
            load_or_create_storage_kek(store, &self.0.join("key-state.db"))
                .expect("create or reload test StorageKEK")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct BlockingAfterCommit {
        blocked: AtomicBool,
        entered: SyncSender<()>,
        release: Mutex<Receiver<()>>,
    }

    impl crate::runtime::model::RuntimeStoreFaultInjector for BlockingAfterCommit {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::CreateConversationAfterCommit
                && !self.blocked.swap(true, Ordering::SeqCst)
            {
                self.entered
                    .send(())
                    .map_err(|_| RuntimeStoreError::WorkerStopped)?;
                self.release
                    .lock()
                    .map_err(|_| RuntimeStoreError::WorkerStopped)?
                    .recv()
                    .map_err(|_| RuntimeStoreError::WorkerStopped)?;
            }
            Ok(())
        }
    }

    fn conversation_input() -> NewConversation {
        NewConversation {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x41; 16])
                .expect("conversation id"),
            adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x42; 16])
                .expect("adapter state key"),
            descriptor: crate::runtime::model::ConversationDescriptor {
                agent_kind: agentdeck_protocol::AgentKind::Codex,
                title: Some("shutdown-timeout".to_owned()),
                cwd: PathBuf::from("/tmp/agentdeck-runtime-test"),
            },
        }
    }

    #[tokio::test]
    async fn shutdown_deadline_only_reports_that_quiescence_was_not_observed() {
        let (_reply, result) = oneshot::channel();

        let error = await_shutdown_quiescence(result, Duration::from_millis(1))
            .await
            .expect_err("held reply must cross the observation deadline");

        assert!(matches!(error, RuntimeStoreError::ShutdownTimedOut));
    }

    #[tokio::test]
    async fn timeout_and_handle_drop_keep_the_path_lease_until_the_worker_exits() {
        let root = TestRoot::new();
        let keys = MemoryKeyStore::new();
        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let mut store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                BlockingAfterCommit {
                    blocked: AtomicBool::new(false),
                    entered: entered_tx,
                    release: Mutex::new(release_rx),
                },
            )),
            root.storage_kek(&keys),
        )
        .await
        .expect("open runtime store");
        store.shutdown_timeout = Duration::from_millis(10);
        let stale = store.clone();
        let in_flight = tokio::spawn({
            let store = store.clone();
            async move { store.create_conversation(conversation_input()).await }
        });
        tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(2)))
            .await
            .expect("join entered wait")
            .expect("operation blocks after commit");

        let error = store
            .shutdown()
            .await
            .expect_err("blocked worker must cross the short observation deadline");
        assert!(matches!(error, RuntimeStoreError::ShutdownTimedOut));
        assert!(matches!(
            stale.clone().shutdown().await,
            Err(RuntimeStoreError::ShutdownInProgress)
        ));

        drop(stale);
        let reopen_error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("timeout and handle drop must not release the live worker lease");
        assert!(matches!(reopen_error, RuntimeStoreError::StoreAlreadyOpen));

        release_tx.send(()).expect("release blocked worker");
        in_flight
            .await
            .expect("join in-flight operation")
            .expect("operation committed before shutdown won arbitration");

        let deadline = Instant::now() + Duration::from_secs(2);
        let reopened = loop {
            match RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(root.database()),
                root.storage_kek(&keys),
            )
            .await
            {
                Ok(reopened) => break reopened,
                Err(RuntimeStoreError::StoreAlreadyOpen) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => panic!("worker did not release resources after exit: {error}"),
            }
        };
        reopened
            .shutdown()
            .await
            .expect("shutdown the single explicitly reopened worker");
    }
}
