//! 可持有、可重复触发且可有界关闭的 key-transition recovery owner。

use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agentdeck_protocol::relay_v2::MachineRouteId;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::runtime::store::key_transition::{
    KeyTransitionCompletion, KeyTransitionOperation, RemoteTransitionIngressClass,
};
use crate::runtime::store::{RuntimeStoreError, RuntimeStoreHandle};
use crate::security::KeyStore;

use super::bootstrap::{
    KeyDirectoryRotationRecoveryOutcome, RemoteBootstrapBlock, recover_key_directory_rotation,
};
use super::publication_transport::{PublicationDriveError, PublicationDriveHandle};
use super::transition::{
    TransitionAdvance, TransitionBackend, TransitionCoordinator, TransitionCoordinatorError,
};
use super::transition_backend::{
    RuntimeStoreTransitionBackend, map_publication_drive_progress_error,
    store_error_allows_transition_retry,
};
use super::transport::{AuthenticatedBusinessReconnects, MachineDataAuthority};

const TRANSITION_COMMAND_CAPACITY: usize = 8;
const MAX_TRANSITION_ADVANCES: usize = 8;
const TRANSITION_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
const TRANSITION_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(250);
const TRANSITION_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionReadiness {
    NoActiveTransition,
    ControlPlaneReady { barrier_count: usize },
    BusinessReady { barrier_count: usize },
}

/// 唯一 owner 每次完整 drive 后发布的窄状态。canonical transition 仍只在 Store；
/// manager 只借此等待 owner 已有 retry/reconnect 生命周期，绝不自己轮询 coordinator。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionProgress {
    Idle,
    Pending,
    Ready(TransitionReadiness),
    Blocked(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionStoreStage {
    Rotation,
    Completion,
    ReplayRetirement,
    CatalogProvision,
}

impl TransitionStoreStage {
    const fn code(self) -> &'static str {
        match self {
            Self::Rotation => "daemon.remote.transition.rotation_store_failed",
            Self::Completion => "daemon.remote.transition.completion_store_failed",
            Self::ReplayRetirement => "daemon.remote.transition.replay_retirement_store_failed",
            Self::CatalogProvision => "daemon.remote.transition.catalog_provision_store_failed",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum KeyTransitionRecoveryError {
    #[error(transparent)]
    Coordinator(#[from] TransitionCoordinatorError),
    #[error("key-directory rotation Store recovery failed")]
    RotationStore,
    #[error("key-transition completion Store recovery failed")]
    CompletionStore,
    #[error("device-command replay retirement Store recovery failed")]
    ReplayRetirementStore,
    #[error("remote Catalog provisioning after transition failed")]
    CatalogProvisionStore,
    #[error("key-transition {0:?} Store progress is temporarily unavailable")]
    RetryableStore(TransitionStoreStage),
    #[error("key-transition publication is waiting for an authenticated Relay reconnect")]
    ReconnectPending,
    #[error("key-directory rotation recovery is blocked: {0:?}")]
    RotationBlocked(RemoteBootstrapBlock),
    #[error("key-transition recovery exceeded its bounded phase advances")]
    AdvanceExhausted,
    #[error("key-transition recovery owner is closed")]
    Closed,
    #[error("key-transition recovery owner task failed")]
    TaskFailed,
    #[error("key-transition recovery owner did not quiesce before its deadline")]
    ShutdownTimedOut,
}

impl KeyTransitionRecoveryError {
    #[must_use]
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Coordinator(error) => error.code(),
            Self::RotationStore => "daemon.remote.transition.rotation_store_failed",
            Self::CompletionStore => "daemon.remote.transition.completion_store_failed",
            Self::ReplayRetirementStore => {
                "daemon.remote.transition.replay_retirement_store_failed"
            }
            Self::CatalogProvisionStore => {
                "daemon.remote.transition.catalog_provision_store_failed"
            }
            Self::RetryableStore(stage) => stage.code(),
            Self::ReconnectPending => "daemon.remote.transition.reconnect_pending",
            Self::RotationBlocked(block) => block.code(),
            Self::AdvanceExhausted => "daemon.remote.transition.advance_exhausted",
            Self::Closed => "daemon.remote.transition.owner_closed",
            Self::TaskFailed => "daemon.remote.transition.owner_task_failed",
            Self::ShutdownTimedOut => "daemon.remote.transition.shutdown_timed_out",
        }
    }

    /// 只有可能由 Relay generation、outcome-unknown 或短暂 Store 可用性恢复的
    /// 错误才允许 owner 定时重驱。认证/crypto/readback mismatch 保持 LocalBlocked，
    /// 避免把永久安全失败变成后台热循环。
    const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Coordinator(TransitionCoordinatorError::ProgressPending)
                | Self::RetryableStore(_)
        )
    }
}

fn map_transition_store_recovery_error(
    stage: TransitionStoreStage,
    error: RuntimeStoreError,
) -> KeyTransitionRecoveryError {
    if store_error_allows_transition_retry(&error) {
        return KeyTransitionRecoveryError::RetryableStore(stage);
    }
    match stage {
        TransitionStoreStage::Rotation => KeyTransitionRecoveryError::RotationStore,
        TransitionStoreStage::Completion => KeyTransitionRecoveryError::CompletionStore,
        TransitionStoreStage::ReplayRetirement => KeyTransitionRecoveryError::ReplayRetirementStore,
        TransitionStoreStage::CatalogProvision => KeyTransitionRecoveryError::CatalogProvisionStore,
    }
}

enum TransitionCommand {
    DriveToBusinessReady {
        response: oneshot::Sender<Result<TransitionReadiness, KeyTransitionRecoveryError>>,
    },
    DriveToControlPlaneReady,
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub(crate) struct KeyTransitionRecoveryHandle {
    command_tx: mpsc::Sender<TransitionCommand>,
    control_plane_progress_requested: Arc<AtomicBool>,
    progress_rx: watch::Receiver<TransitionProgress>,
}

impl KeyTransitionRecoveryHandle {
    pub(crate) fn subscribe_progress(&self) -> watch::Receiver<TransitionProgress> {
        self.progress_rx.clone()
    }

    /// Pairing/revocation 的 durable receipt 不能等待 Relay barrier 或 endpoint ACK。
    /// 这里只把幂等推进请求交给已有 owner task；独立 pending bit 保证队列已满时
    /// 也不会丢失唤醒，并允许多个请求合并，绝不创建 detached task。
    pub(crate) fn request_control_plane_progress(&self) -> Result<(), KeyTransitionRecoveryError> {
        self.control_plane_progress_requested
            .store(true, Ordering::Release);
        match self
            .command_tx
            .try_send(TransitionCommand::DriveToControlPlaneReady)
        {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(KeyTransitionRecoveryError::Closed),
        }
    }

    /// 只返回最终 ready state；所有 coordinator 中间态都在唯一 owner task 内消化。
    pub(crate) async fn drive_to_business_ready(
        &self,
    ) -> Result<TransitionReadiness, KeyTransitionRecoveryError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(TransitionCommand::DriveToBusinessReady {
                response: response_tx,
            })
            .await
            .map_err(|_| KeyTransitionRecoveryError::Closed)?;
        response_rx
            .await
            .map_err(|_| KeyTransitionRecoveryError::Closed)?
    }
}

pub(crate) struct KeyTransitionRecoveryOwner {
    handle: KeyTransitionRecoveryHandle,
    task: Option<JoinHandle<()>>,
    health_rx: watch::Receiver<Option<String>>,
    shutdown_timeout: Duration,
    #[cfg(test)]
    attempt_count: Arc<AtomicUsize>,
}

impl KeyTransitionRecoveryOwner {
    /// 复用 manager 已持有的 Store、KeyStore、MachineData authority 与唯一
    /// PublicationDrive handle；本构造不拨号、不创建第二 dispatcher。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn start(
        store: RuntimeStoreHandle,
        key_store: Arc<dyn KeyStore>,
        machine_route: MachineRouteId,
        authority: MachineDataAuthority,
        publication_drive: PublicationDriveHandle,
    ) -> Result<Self, KeyTransitionRecoveryError> {
        Self::start_inner(
            store,
            key_store,
            machine_route,
            authority,
            publication_drive,
            None,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn start_with_delivery_commits(
        store: RuntimeStoreHandle,
        key_store: Arc<dyn KeyStore>,
        machine_route: MachineRouteId,
        authority: MachineDataAuthority,
        publication_drive: PublicationDriveHandle,
        delivery_commit_rx: watch::Receiver<u64>,
    ) -> Result<Self, KeyTransitionRecoveryError> {
        Self::start_inner(
            store,
            key_store,
            machine_route,
            authority,
            publication_drive,
            None,
            Some(delivery_commit_rx),
        )
    }

    /// startup 在 RemoteLink 取得唯一 event lane 之前也必须有真实 reconnect wake。
    /// 该 receiver 只能来自同一 `MachinePublicationHandle` 的 authenticated generation。
    pub(crate) fn start_with_authenticated_reconnect(
        store: RuntimeStoreHandle,
        key_store: Arc<dyn KeyStore>,
        machine_route: MachineRouteId,
        authority: MachineDataAuthority,
        publication_drive: PublicationDriveHandle,
        authenticated_reconnect_rx: AuthenticatedBusinessReconnects,
        delivery_commit_rx: Option<watch::Receiver<u64>>,
    ) -> Result<Self, KeyTransitionRecoveryError> {
        Self::start_inner(
            store,
            key_store,
            machine_route,
            authority,
            publication_drive,
            Some(authenticated_reconnect_rx),
            delivery_commit_rx,
        )
    }

    fn start_inner(
        store: RuntimeStoreHandle,
        key_store: Arc<dyn KeyStore>,
        machine_route: MachineRouteId,
        authority: MachineDataAuthority,
        publication_drive: PublicationDriveHandle,
        authenticated_reconnect_rx: Option<AuthenticatedBusinessReconnects>,
        mut delivery_commit_rx: Option<watch::Receiver<u64>>,
    ) -> Result<Self, KeyTransitionRecoveryError> {
        let backend = RuntimeStoreTransitionBackend::new(
            store.clone(),
            Arc::clone(&key_store),
            machine_route,
            authority,
            publication_drive.clone(),
        )?;
        let (command_tx, command_rx) = mpsc::channel(TRANSITION_COMMAND_CAPACITY);
        let (health_tx, health_rx) = watch::channel(None);
        let (progress_tx, progress_rx) = watch::channel(TransitionProgress::Idle);
        // Pairing owner 的根 receiver 可能在 transition owner 启动前已经观察到
        // durable delivery commit。subscribe() 会继承 seen version，因此这里必须
        // 显式读取 sticky generation，不能只等待后续 changed()。
        let initially_requested = delivery_commit_rx
            .as_mut()
            .is_some_and(|receiver| *receiver.borrow_and_update() > 0);
        let control_plane_progress_requested = Arc::new(AtomicBool::new(initially_requested));
        #[cfg(test)]
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_transition_owner(
            backend,
            store,
            key_store,
            publication_drive,
            authenticated_reconnect_rx,
            delivery_commit_rx,
            command_rx,
            Arc::clone(&control_plane_progress_requested),
            #[cfg(test)]
            Arc::clone(&attempt_count),
            health_tx,
            progress_tx,
        ));
        Ok(Self {
            handle: KeyTransitionRecoveryHandle {
                command_tx,
                control_plane_progress_requested,
                progress_rx,
            },
            task: Some(task),
            health_rx,
            shutdown_timeout: TRANSITION_SHUTDOWN_DEADLINE,
            #[cfg(test)]
            attempt_count,
        })
    }

    pub(crate) fn handle(&self) -> KeyTransitionRecoveryHandle {
        self.handle.clone()
    }

    #[must_use]
    pub(crate) fn observed_failure_code(&self) -> Option<String> {
        self.health_rx.borrow().clone().or_else(|| {
            self.task
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
                .then(|| KeyTransitionRecoveryError::TaskFailed.code().to_owned())
        })
    }

    #[cfg(test)]
    pub(crate) fn attempt_count_for_test(&self) -> usize {
        self.attempt_count.load(Ordering::Acquire)
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), KeyTransitionRecoveryError> {
        let deadline = tokio::time::Instant::now() + self.shutdown_timeout;
        let handle = self.handle;
        let mut task = self.task.take().expect("transition owner task is present");
        let shutdown = async {
            let (response_tx, response_rx) = oneshot::channel();
            handle
                .command_tx
                .send(TransitionCommand::Shutdown {
                    response: response_tx,
                })
                .await
                .map_err(|_| KeyTransitionRecoveryError::Closed)?;
            response_rx
                .await
                .map_err(|_| KeyTransitionRecoveryError::Closed)?;
            drop(handle);
            (&mut task)
                .await
                .map_err(|_| KeyTransitionRecoveryError::TaskFailed)
        };
        match tokio::time::timeout_at(deadline, shutdown).await {
            Ok(result) => result,
            Err(_) => {
                task.abort();
                Err(KeyTransitionRecoveryError::ShutdownTimedOut)
            }
        }
    }

    #[cfg(test)]
    async fn slow_task_for_shutdown_test(timeout: Duration, drop_delay: Duration) -> Self {
        let (command_tx, command_rx) = mpsc::channel(TRANSITION_COMMAND_CAPACITY);
        let (_health_tx, health_rx) = watch::channel(None);
        let started = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let started = Arc::clone(&started);
            async move {
                let _command_rx = command_rx;
                let _slow_drop = SlowTransitionShutdownDrop(drop_delay);
                started.notify_one();
                std::future::pending::<()>().await;
            }
        });
        started.notified().await;
        Self {
            handle: KeyTransitionRecoveryHandle {
                command_tx,
                control_plane_progress_requested: Arc::new(AtomicBool::new(false)),
                progress_rx: watch::channel(TransitionProgress::Idle).1,
            },
            task: Some(task),
            health_rx,
            shutdown_timeout: timeout,
            attempt_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[cfg(test)]
struct SlowTransitionShutdownDrop(Duration);

#[cfg(test)]
impl Drop for SlowTransitionShutdownDrop {
    fn drop(&mut self) {
        std::thread::sleep(self.0);
    }
}

async fn wait_delivery_commit(
    receiver: Option<&mut watch::Receiver<u64>>,
) -> Result<(), watch::error::RecvError> {
    match receiver {
        Some(receiver) => receiver.changed().await,
        None => std::future::pending().await,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "唯一 owner task 显式取得全部 durable backend、wake、health、progress 与 shutdown ownership 轴"
)]
async fn run_transition_owner(
    backend: RuntimeStoreTransitionBackend,
    store: RuntimeStoreHandle,
    key_store: Arc<dyn KeyStore>,
    publication_drive: PublicationDriveHandle,
    mut authenticated_reconnect_rx: Option<AuthenticatedBusinessReconnects>,
    mut delivery_commit_rx: Option<watch::Receiver<u64>>,
    mut command_rx: mpsc::Receiver<TransitionCommand>,
    control_plane_progress_requested: Arc<AtomicBool>,
    #[cfg(test)] attempt_count: Arc<AtomicUsize>,
    health_tx: watch::Sender<Option<String>>,
    progress_tx: watch::Sender<TransitionProgress>,
) {
    let mut retry_at = None;
    let mut retry_delay = TRANSITION_RETRY_INITIAL_DELAY;
    let mut reconnect_waiting = false;
    loop {
        let command = match command_rx.try_recv() {
            Ok(command) => Some(command),
            Err(mpsc::error::TryRecvError::Disconnected) => break,
            Err(mpsc::error::TryRecvError::Empty) => {
                if !reconnect_waiting
                    && control_plane_progress_requested.swap(false, Ordering::AcqRel)
                {
                    #[cfg(test)]
                    attempt_count.fetch_add(1, Ordering::AcqRel);
                    let result = drive_owner_attempt(
                        &backend,
                        &store,
                        key_store.as_ref(),
                        authenticated_reconnect_rx.as_mut(),
                    )
                    .await;
                    update_attempt_state(
                        &result,
                        &mut retry_at,
                        &mut retry_delay,
                        &mut reconnect_waiting,
                        &health_tx,
                        &progress_tx,
                    );
                    continue;
                }
                if let Some(deadline) = retry_at {
                    tokio::select! {
                        biased;
                        command = command_rx.recv() => command,
                        changed = wait_delivery_commit(delivery_commit_rx.as_mut()) => {
                            if changed.is_ok() {
                                control_plane_progress_requested.store(true, Ordering::Release);
                            } else {
                                delivery_commit_rx = None;
                            }
                            continue;
                        }
                        () = tokio::time::sleep_until(deadline) => {
                            retry_at = None;
                            // OutcomeUnknown/Store busy 保持 Ready/commit-pending，可直接按
                            // exact frozen state 重驱；Offline 仍由 dispatcher park，只有真实
                            // MachineLink reconnect 才会调用 notify_reconnected。
                            #[cfg(test)]
                            attempt_count.fetch_add(1, Ordering::AcqRel);
                            let result = drive_owner_attempt(
                                &backend,
                                &store,
                                key_store.as_ref(),
                                authenticated_reconnect_rx.as_mut(),
                            )
                            .await;
                            update_attempt_state(
                                &result,
                                &mut retry_at,
                                &mut retry_delay,
                                &mut reconnect_waiting,
                                &health_tx,
                                &progress_tx,
                            );
                            continue;
                        }
                    }
                } else if reconnect_waiting {
                    match authenticated_reconnect_rx.as_mut() {
                        Some(reconnect_rx) => {
                            tokio::select! {
                                biased;
                                command = command_rx.recv() => command,
                                delivery = wait_delivery_commit(delivery_commit_rx.as_mut()) => {
                                    if delivery.is_ok() {
                                        // Offline receipt 只锁存 Store 进展；它不能替代同一
                                        // MachineLink supervisor 的 authenticated reconnect。
                                        control_plane_progress_requested.store(true, Ordering::Release);
                                    } else {
                                        delivery_commit_rx = None;
                                    }
                                    continue;
                                }
                                changed = reconnect_rx.changed() => {
                                    if changed.is_err() {
                                        let result = Err(KeyTransitionRecoveryError::Coordinator(
                                            TransitionCoordinatorError::BackendRejected,
                                        ));
                                        update_attempt_state(
                                            &result,
                                            &mut retry_at,
                                            &mut retry_delay,
                                            &mut reconnect_waiting,
                                            &health_tx,
                                            &progress_tx,
                                        );
                                        authenticated_reconnect_rx = None;
                                        continue;
                                    }
                                    reconnect_waiting = false;
                                    // 同一 reconnect drive 会读取全部已提交 proof；把当前
                                    // sticky generation 一并标记 seen，避免随后重复重驱。
                                    if let Some(receiver) = delivery_commit_rx.as_mut() {
                                        let _ = *receiver.borrow_and_update();
                                    }
                                    control_plane_progress_requested.store(false, Ordering::Release);
                                    #[cfg(test)]
                                    attempt_count.fetch_add(1, Ordering::AcqRel);
                                    let result = match publication_drive.notify_reconnected().await {
                                        Ok(()) => drive_owner_attempt(
                                            &backend,
                                            &store,
                                            key_store.as_ref(),
                                            authenticated_reconnect_rx.as_mut(),
                                        )
                                        .await,
                                        Err(error) => Err(publication_reconnect_error(error)),
                                    };
                                    update_attempt_state(
                                        &result,
                                        &mut retry_at,
                                        &mut retry_delay,
                                        &mut reconnect_waiting,
                                        &health_tx,
                                        &progress_tx,
                                    );
                                    continue;
                                }
                            }
                        }
                        None => {
                            tokio::select! {
                                biased;
                                command = command_rx.recv() => command,
                                delivery = wait_delivery_commit(delivery_commit_rx.as_mut()) => {
                                    if delivery.is_ok() {
                                        control_plane_progress_requested.store(true, Ordering::Release);
                                    } else {
                                        delivery_commit_rx = None;
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        biased;
                        command = command_rx.recv() => command,
                        delivery = wait_delivery_commit(delivery_commit_rx.as_mut()) => {
                            if delivery.is_ok() {
                                control_plane_progress_requested.store(true, Ordering::Release);
                            } else {
                                delivery_commit_rx = None;
                            }
                            continue;
                        }
                    }
                }
            }
        };
        let Some(command) = command else {
            break;
        };
        match command {
            TransitionCommand::DriveToBusinessReady { response } if reconnect_waiting => {
                // Offline park 期间普通 caller 不能绕过 authenticated generation wake。
                // 直接回报同一中间态；唯一 owner 与原 reconnect receiver 保持不变。
                let _ = response.send(Err(KeyTransitionRecoveryError::ReconnectPending));
            }
            TransitionCommand::DriveToBusinessReady { response } => {
                #[cfg(test)]
                attempt_count.fetch_add(1, Ordering::AcqRel);
                let result = drive_owner_attempt(
                    &backend,
                    &store,
                    key_store.as_ref(),
                    authenticated_reconnect_rx.as_mut(),
                )
                .await;
                update_attempt_state(
                    &result,
                    &mut retry_at,
                    &mut retry_delay,
                    &mut reconnect_waiting,
                    &health_tx,
                    &progress_tx,
                );
                let _ = response.send(result);
            }
            // request_control_plane_progress 先设置独立 pending bit；本命令只负责
            // 唤醒 owner。队列中无论合并了多少 marker，pending bit 都是权威源。
            TransitionCommand::DriveToControlPlaneReady => {}
            TransitionCommand::Shutdown { response } => {
                let _ = response.send(());
                break;
            }
        }
    }
}

fn update_attempt_state(
    result: &Result<TransitionReadiness, KeyTransitionRecoveryError>,
    retry_at: &mut Option<tokio::time::Instant>,
    retry_delay: &mut Duration,
    reconnect_waiting: &mut bool,
    health_tx: &watch::Sender<Option<String>>,
    progress_tx: &watch::Sender<TransitionProgress>,
) {
    let progress = match result {
        Ok(readiness) => TransitionProgress::Ready(*readiness),
        Err(KeyTransitionRecoveryError::ReconnectPending) => TransitionProgress::Pending,
        Err(error) if error.retryable() => TransitionProgress::Pending,
        Err(error) => TransitionProgress::Blocked(error.code()),
    };
    progress_tx.send_replace(progress);
    match result {
        Ok(TransitionReadiness::NoActiveTransition | TransitionReadiness::BusinessReady { .. }) => {
            *reconnect_waiting = false;
            *retry_at = None;
            *retry_delay = TRANSITION_RETRY_INITIAL_DELAY;
            health_tx.send_replace(None);
        }
        Ok(TransitionReadiness::ControlPlaneReady { .. }) => {
            *reconnect_waiting = false;
            // BarriersCommitted 只表示控制面可接收 ACK；active transition 尚未
            // 释放时 status 不能冒充 business Active。继续有界轮询，以便 ACK
            // 路径直接完成 Store transition 后自动清除 health fence。
            let scheduled_delay = *retry_delay;
            *retry_at = Some(tokio::time::Instant::now() + scheduled_delay);
            *retry_delay = retry_delay
                .saturating_mul(2)
                .min(TRANSITION_RETRY_MAX_DELAY);
            let code = TransitionCoordinatorError::BusinessFenced.code();
            health_tx.send_replace(Some(code.to_owned()));
            crate::diag::log(
                "remote_transition_progress",
                &format!(
                    "status=control_plane_ready code={code} retry_delay_ms={}",
                    scheduled_delay.as_millis()
                ),
            );
        }
        Err(KeyTransitionRecoveryError::ReconnectPending) => {
            // Offline 已在 publication dispatcher 内 park；timer 重驱只会重复 Store
            // 审计，不能证明网络 generation 已替换。唯一唤醒来自同一 MachineLink
            // supervisor 在 authenticated reconnect 后发布的 generation watch。
            *retry_at = None;
            *retry_delay = TRANSITION_RETRY_INITIAL_DELAY;
            *reconnect_waiting = true;
            let code = KeyTransitionRecoveryError::ReconnectPending.code();
            health_tx.send_replace(Some(code.to_owned()));
            crate::diag::log(
                "remote_transition_progress",
                &format!("status=reconnect_wait code={code}"),
            );
        }
        Err(error) if error.retryable() => {
            *reconnect_waiting = false;
            let scheduled_delay = *retry_delay;
            *retry_at = Some(tokio::time::Instant::now() + scheduled_delay);
            *retry_delay = retry_delay
                .saturating_mul(2)
                .min(TRANSITION_RETRY_MAX_DELAY);
            health_tx.send_replace(Some(error.code().to_owned()));
            crate::diag::log(
                "remote_transition_progress",
                &format!(
                    "status=retry_scheduled code={} delay_ms={}",
                    error.code(),
                    scheduled_delay.as_millis()
                ),
            );
        }
        Err(error) => {
            *reconnect_waiting = false;
            *retry_at = None;
            *retry_delay = TRANSITION_RETRY_INITIAL_DELAY;
            health_tx.send_replace(Some(error.code().to_owned()));
            crate::diag::log(
                "remote_transition_progress",
                &format!("status=local_blocked code={}", error.code()),
            );
        }
    }
}

fn publication_reconnect_error(error: PublicationDriveError) -> KeyTransitionRecoveryError {
    KeyTransitionRecoveryError::Coordinator(map_publication_drive_progress_error(error))
}

async fn drive_owner_attempt(
    backend: &RuntimeStoreTransitionBackend,
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
    reconnect_rx: Option<&mut AuthenticatedBusinessReconnects>,
) -> Result<TransitionReadiness, KeyTransitionRecoveryError> {
    if let Some(reconnect_rx) = reconnect_rx {
        reconnect_rx.mark_attempt_baseline().map_err(|_| {
            KeyTransitionRecoveryError::Coordinator(TransitionCoordinatorError::BackendRejected)
        })?;
    }
    drive_to_business_ready(backend, store, key_store).await
}

async fn drive_to_business_ready(
    backend: &RuntimeStoreTransitionBackend,
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
) -> Result<TransitionReadiness, KeyTransitionRecoveryError> {
    backend.begin_progress_attempt();
    apply_pending_replay_retirement(store).await?;
    let completion_operation_id = store
        .load_active_key_transition()
        .await
        .map_err(|error| {
            map_transition_store_recovery_error(TransitionStoreStage::Completion, error)
        })?
        .and_then(|recovery| {
            (recovery.transition.operation != KeyTransitionOperation::CounterRecovery)
                .then_some(recovery.transition.operation_id)
        });
    for _ in 0..MAX_TRANSITION_ADVANCES {
        let advance = match TransitionCoordinator::new(backend, backend.authority())
            .advance_once()
            .await
        {
            Ok(advance) => advance,
            Err(TransitionCoordinatorError::ProgressPending)
                if backend.take_reconnect_waiting() =>
            {
                return Err(KeyTransitionRecoveryError::ReconnectPending);
            }
            Err(error) => return Err(error.into()),
        };
        match advance {
            TransitionAdvance::NoActiveTransition => {
                // transition 可能在首次 recovery read 后被另一 ACK 路径收口；
                // 返回 business permit 前必须再做一次幂等 retirement readback。
                apply_pending_replay_retirement(store).await?;
                ensure_remote_catalog_publication_after_transition(store).await?;
                backend.check_business_ingress_allowed().await?;
                return Ok(TransitionReadiness::NoActiveTransition);
            }
            TransitionAdvance::AwaitingKeyRotation => {
                match recover_key_directory_rotation(store, key_store)
                    .await
                    .map_err(|error| {
                        map_transition_store_recovery_error(TransitionStoreStage::Rotation, error)
                    })? {
                    KeyDirectoryRotationRecoveryOutcome::Recovered(_) => {}
                    KeyDirectoryRotationRecoveryOutcome::Blocked(block) => {
                        return Err(KeyTransitionRecoveryError::RotationBlocked(block));
                    }
                }
            }
            TransitionAdvance::UpdatesFrozen { .. } => {}
            TransitionAdvance::ControlPlaneReady { barrier_count } => {
                let Some(operation_id) = completion_operation_id else {
                    return Ok(TransitionReadiness::ControlPlaneReady { barrier_count });
                };
                match store
                    .try_complete_key_transition(operation_id)
                    .await
                    .map_err(|error| {
                        map_transition_store_recovery_error(TransitionStoreStage::Completion, error)
                    })? {
                    KeyTransitionCompletion::Pending => {
                        return Ok(TransitionReadiness::ControlPlaneReady { barrier_count });
                    }
                    KeyTransitionCompletion::Completed(_) => {
                        apply_pending_replay_retirement(store).await?;
                        ensure_remote_catalog_publication_after_transition(store).await?;
                        store
                            .check_remote_transition_ingress(RemoteTransitionIngressClass::Business)
                            .await
                            .map_err(|error| {
                                map_transition_store_recovery_error(
                                    TransitionStoreStage::Completion,
                                    error,
                                )
                            })?;
                        return Ok(TransitionReadiness::BusinessReady { barrier_count });
                    }
                }
            }
        }
    }
    Err(KeyTransitionRecoveryError::AdvanceExhausted)
}

async fn apply_pending_replay_retirement(
    store: &RuntimeStoreHandle,
) -> Result<(), KeyTransitionRecoveryError> {
    let _ = store
        .apply_pending_replay_retirement()
        .await
        .map_err(|error| {
            map_transition_store_recovery_error(TransitionStoreStage::ReplayRetirement, error)
        })?;
    Ok(())
}

async fn ensure_remote_catalog_publication_after_transition(
    store: &RuntimeStoreHandle,
) -> Result<(), KeyTransitionRecoveryError> {
    let _ = store
        .ensure_remote_catalog_publication_after_transition()
        .await
        .map_err(|error| {
            map_transition_store_recovery_error(TransitionStoreStage::CatalogProvision, error)
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        KeyTransitionRecoveryError, KeyTransitionRecoveryOwner, TRANSITION_RETRY_INITIAL_DELAY,
        TransitionReadiness, TransitionStoreStage, map_transition_store_recovery_error,
        update_attempt_state,
    };

    #[test]
    fn full_command_queue_retains_the_control_plane_progress_bit() {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(1);
        command_tx
            .try_send(super::TransitionCommand::DriveToControlPlaneReady)
            .expect("fill the bounded transition command queue");
        let requested = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = super::KeyTransitionRecoveryHandle {
            command_tx,
            control_plane_progress_requested: std::sync::Arc::clone(&requested),
            progress_rx: tokio::sync::watch::channel(super::TransitionProgress::Idle).1,
        };

        handle
            .request_control_plane_progress()
            .expect("a full marker queue must still retain the authoritative pending bit");
        assert!(requested.load(std::sync::atomic::Ordering::Acquire));
        assert!(matches!(
            command_rx.try_recv(),
            Ok(super::TransitionCommand::DriveToControlPlaneReady)
        ));
        assert!(matches!(
            command_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn control_plane_ready_keeps_health_fenced_until_business_is_rechecked() {
        let (health_tx, health_rx) = tokio::sync::watch::channel(None);
        let mut retry_at = None;
        let mut retry_delay = TRANSITION_RETRY_INITIAL_DELAY;
        let mut reconnect_waiting = false;
        let (progress_tx, _progress_rx) =
            tokio::sync::watch::channel(super::TransitionProgress::Idle);

        update_attempt_state(
            &Ok(TransitionReadiness::ControlPlaneReady { barrier_count: 1 }),
            &mut retry_at,
            &mut retry_delay,
            &mut reconnect_waiting,
            &health_tx,
            &progress_tx,
        );
        assert!(
            retry_at.is_some(),
            "control-only state must schedule a recheck"
        );
        assert_eq!(
            health_rx.borrow().as_deref(),
            Some("daemon.remote.transition.business_fenced")
        );

        update_attempt_state(
            &Ok(TransitionReadiness::NoActiveTransition),
            &mut retry_at,
            &mut retry_delay,
            &mut reconnect_waiting,
            &health_tx,
            &progress_tx,
        );
        assert!(retry_at.is_none());
        assert!(health_rx.borrow().is_none());
    }

    #[test]
    fn reconnect_wait_is_visible_but_never_schedules_a_timer_retry() {
        let (health_tx, health_rx) = tokio::sync::watch::channel(None);
        let mut retry_at = None;
        let mut retry_delay = TRANSITION_RETRY_INITIAL_DELAY;
        let mut reconnect_waiting = false;
        let (progress_tx, _progress_rx) =
            tokio::sync::watch::channel(super::TransitionProgress::Idle);

        update_attempt_state(
            &Err(KeyTransitionRecoveryError::ReconnectPending),
            &mut retry_at,
            &mut retry_delay,
            &mut reconnect_waiting,
            &health_tx,
            &progress_tx,
        );

        assert!(retry_at.is_none());
        assert_eq!(retry_delay, TRANSITION_RETRY_INITIAL_DELAY);
        assert_eq!(
            health_rx.borrow().as_deref(),
            Some("daemon.remote.transition.reconnect_pending")
        );
    }

    #[test]
    fn permanent_backend_and_store_failures_never_schedule_background_retry() {
        for error in [
            KeyTransitionRecoveryError::Coordinator(
                super::TransitionCoordinatorError::BackendRejected,
            ),
            map_transition_store_recovery_error(
                TransitionStoreStage::Rotation,
                crate::runtime::store::RuntimeStoreError::UnknownOrCorruptSchema,
            ),
            map_transition_store_recovery_error(
                TransitionStoreStage::Completion,
                crate::runtime::store::RuntimeStoreError::SafetyOnly,
            ),
            map_transition_store_recovery_error(
                TransitionStoreStage::ReplayRetirement,
                crate::runtime::store::RuntimeStoreError::InvalidStateTransition,
            ),
        ] {
            let (health_tx, health_rx) = tokio::sync::watch::channel(None);
            let mut retry_at = None;
            let mut retry_delay = TRANSITION_RETRY_INITIAL_DELAY;
            let mut reconnect_waiting = false;
            let (progress_tx, _progress_rx) =
                tokio::sync::watch::channel(super::TransitionProgress::Idle);

            update_attempt_state(
                &Err(error),
                &mut retry_at,
                &mut retry_delay,
                &mut reconnect_waiting,
                &health_tx,
                &progress_tx,
            );

            assert!(
                retry_at.is_none(),
                "permanent authenticated failure must latch LocalBlocked"
            );
            assert!(health_rx.borrow().is_some());
        }
    }

    #[test]
    fn only_typed_relay_and_store_transients_schedule_background_retry() {
        for error in [
            KeyTransitionRecoveryError::Coordinator(
                super::TransitionCoordinatorError::ProgressPending,
            ),
            map_transition_store_recovery_error(
                TransitionStoreStage::Completion,
                crate::runtime::store::RuntimeStoreError::WorkerBusy {
                    lane: crate::runtime::store::RuntimeStoreLane::Normal,
                },
            ),
        ] {
            let (health_tx, health_rx) = tokio::sync::watch::channel(None);
            let mut retry_at = None;
            let mut retry_delay = TRANSITION_RETRY_INITIAL_DELAY;
            let mut reconnect_waiting = false;
            let (progress_tx, _progress_rx) =
                tokio::sync::watch::channel(super::TransitionProgress::Idle);

            update_attempt_state(
                &Err(error),
                &mut retry_at,
                &mut retry_delay,
                &mut reconnect_waiting,
                &health_tx,
                &progress_tx,
            );

            assert!(retry_at.is_some());
            assert!(health_rx.borrow().is_some());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_timeout_does_not_await_non_cooperative_aborted_transition_task() {
        let owner = KeyTransitionRecoveryOwner::slow_task_for_shutdown_test(
            std::time::Duration::from_millis(20),
            std::time::Duration::from_millis(400),
        )
        .await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(150), owner.shutdown())
            .await
            .expect("transition owner must return at its absolute deadline");
        assert!(matches!(
            result,
            Err(KeyTransitionRecoveryError::ShutdownTimedOut)
        ));
    }
}
