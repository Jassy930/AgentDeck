//! 单 blocking worker 独占 Runtime SQLite connection 的 async handle。

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::runtime::model::{
    MAX_RUNTIME_BUSY_TIMEOUT_MS, MAX_RUNTIME_STORE_COMMAND_CAPACITY,
    MachineEnrollmentReceiptRecord, RUNTIME_STORE_SHUTDOWN_GRACE_MS, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreOperation, RuntimeStoreSnapshot,
};
use crate::security::StorageKek;

use super::sqlite;

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
    tx: mpsc::Sender<StoreCommand>,
    control_tx: mpsc::UnboundedSender<ControlCommand>,
    interrupt: Arc<rusqlite::InterruptHandle>,
    shutdown_timeout: Duration,
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
        let shutdown_timeout = Duration::from_millis(
            config
                .busy_timeout_ms
                .saturating_add(RUNTIME_STORE_SHUTDOWN_GRACE_MS),
        );
        let normalized = sqlite::normalize_storage_path(&config.storage_path)?;
        let lease = claim_store_path(&normalized)?;
        let (tx, rx) = mpsc::channel(config.command_capacity);
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("agentdeck-runtime-store".to_owned())
            .spawn(move || run(config, storage_kek, rx, control_rx, ready_tx, lease))?;
        match ready_rx.await {
            Ok(Ok(interrupt)) => Ok(Self {
                tx,
                control_tx,
                interrupt,
                shutdown_timeout,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(RuntimeStoreError::WorkerStopped),
        }
    }

    pub async fn inspect(&self) -> Result<RuntimeStoreSnapshot, RuntimeStoreError> {
        self.dispatch(|reply| StoreCommand::Inspect { reply })
            .await?
    }

    pub async fn record_machine_enrollment_receipt(
        &self,
        receipt: MachineEnrollmentReceiptRecord,
    ) -> Result<MachineEnrollmentReceiptRecord, RuntimeStoreError> {
        self.dispatch(|reply| StoreCommand::RecordEnrollmentReceipt { receipt, reply })
            .await?
    }

    /// 回执只在 connection、row keys 和 path lease 全部释放后发送。
    pub async fn shutdown(self) -> Result<(), RuntimeStoreError> {
        self.interrupt.interrupt();
        let (reply, result) = oneshot::channel();
        self.control_tx
            .send(ControlCommand::Shutdown { reply })
            .map_err(|_| RuntimeStoreError::WorkerStopped)?;
        match tokio::time::timeout(self.shutdown_timeout, result).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(RuntimeStoreError::WorkerStopped),
            Err(_) => Err(RuntimeStoreError::ShutdownTimedOut),
        }
    }

    async fn dispatch<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<T>) -> StoreCommand,
    ) -> Result<T, RuntimeStoreError> {
        let (reply, result) = oneshot::channel();
        self.tx.try_send(build(reply)).map_err(map_try_send)?;
        result.await.map_err(|_| RuntimeStoreError::WorkerStopped)
    }
}

fn map_try_send<T>(error: mpsc::error::TrySendError<T>) -> RuntimeStoreError {
    match error {
        mpsc::error::TrySendError::Full(_) => RuntimeStoreError::WorkerBusy,
        mpsc::error::TrySendError::Closed(_) => RuntimeStoreError::WorkerStopped,
    }
}

enum StoreCommand {
    Inspect {
        reply: oneshot::Sender<Result<RuntimeStoreSnapshot, RuntimeStoreError>>,
    },
    RecordEnrollmentReceipt {
        receipt: MachineEnrollmentReceiptRecord,
        reply: oneshot::Sender<Result<MachineEnrollmentReceiptRecord, RuntimeStoreError>>,
    },
}

enum ControlCommand {
    Shutdown { reply: oneshot::Sender<()> },
}

fn run(
    config: RuntimeStoreConfig,
    storage_kek: StorageKek,
    mut commands: mpsc::Receiver<StoreCommand>,
    mut controls: mpsc::UnboundedReceiver<ControlCommand>,
    ready: oneshot::Sender<Result<Arc<rusqlite::InterruptHandle>, RuntimeStoreError>>,
    lease: Arc<StoreOpenLease>,
) {
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
        loop {
            tokio::select! {
                biased;
                control = controls.recv() => {
                    match control {
                        Some(ControlCommand::Shutdown { reply }) => break Some(reply),
                        None if commands.is_closed() => break None,
                        None => {}
                    }
                }
                command = commands.recv() => {
                    let Some(command) = command else { break None };
                    match command {
                        StoreCommand::Inspect { reply } => {
                            let result = config
                                .fault_injector
                                .before_operation(RuntimeStoreOperation::Inspect)
                                .and_then(|()| {
                                    sqlite::snapshot(&state.connection, config.busy_timeout_ms)
                                });
                            let _ = reply.send(result);
                        }
                        StoreCommand::RecordEnrollmentReceipt { receipt, reply } => {
                            let result = config
                                .fault_injector
                                .before_operation(RuntimeStoreOperation::RecordEnrollmentReceipt)
                                .and_then(|()| {
                                    sqlite::record_machine_enrollment_receipt(
                                        &mut state.connection,
                                        receipt,
                                    )
                                });
                            let _ = reply.send(result);
                        }
                    }
                }
            }
        }
    });

    commands.close();
    while commands.try_recv().is_ok() {}
    controls.close();
    drop(state);
    drop(lease);
    if let Some(reply) = shutdown_reply {
        let _ = reply.send(());
    }
}
