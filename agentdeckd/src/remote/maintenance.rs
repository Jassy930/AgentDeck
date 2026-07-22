//! 长寿 Remote business stack 的有界 retention maintenance owner。
//!
//! startup 先同步跑一轮；随后本 owner 以固定周期重复执行。manager 在 trust-reset、
//! uninstall purge 或进程 shutdown 前必须 cancel + join，保证 retention 删除不会与
//! machine scrub 并发。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::runtime::store::key_transition::KeyTransitionGcLimits;
use crate::runtime::store::{RuntimeStoreError, RuntimeStoreHandle};
use crate::security::KeyStore;

use super::identity::{MachineIdentityError, delete_scoped_counter_guards_for_tokens};

const REMOTE_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const REMOTE_MAINTENANCE_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub(crate) enum RemoteMaintenanceError {
    #[error("remote maintenance Store operation failed: {0}")]
    Store(#[from] RuntimeStoreError),
    #[error("remote maintenance CounterGuard operation failed: {0}")]
    CounterGuard(#[from] MachineIdentityError),
    #[error("remote maintenance task failed")]
    TaskFailed,
    #[error("remote maintenance shutdown timed out")]
    ShutdownTimedOut,
}

impl RemoteMaintenanceError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Store(error) => error.code(),
            Self::CounterGuard(error) => error.code(),
            Self::TaskFailed => "daemon.remote.maintenance.task_failed",
            Self::ShutdownTimedOut => "daemon.remote.maintenance.shutdown_timed_out",
        }
    }
}

/// 单轮顺序刻意固定：先处理仍被 retention owner 引用的 replay/key material，最后
/// 才清 transition tombstone。CounterGuard-first counter GC 接入后必须放在本函数
/// 最前，且只有它的 authenticated terminal proof 才能解除 CounterRecovery block。
pub(crate) async fn run_remote_maintenance_once(
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
    now_ms: u64,
) -> Result<(), RemoteMaintenanceError> {
    if let Some(plan) = store.load_pending_counter_retirement_plan().await? {
        delete_scoped_counter_guards_for_tokens(key_store, &plan.scope_tokens)?;
        let _ = store
            .apply_counter_retirement_after_guard_readback(plan)
            .await?;
    }
    store.gc_retired_remote_replay(now_ms).await?;
    if store.load_global_key_state().await?.is_some() {
        store.gc_expired_retired_shared_keys(now_ms).await?;
    }
    store
        .gc_expired_key_transitions(KeyTransitionGcLimits::default())
        .await?;
    Ok(())
}

#[async_trait]
trait MaintenanceCollector: Send + Sync {
    async fn collect(&self, now_ms: u64) -> Result<(), RemoteMaintenanceError>;
}

struct RuntimeStoreMaintenanceCollector {
    store: RuntimeStoreHandle,
    key_store: Arc<dyn KeyStore>,
}

#[async_trait]
impl MaintenanceCollector for RuntimeStoreMaintenanceCollector {
    async fn collect(&self, now_ms: u64) -> Result<(), RemoteMaintenanceError> {
        run_remote_maintenance_once(&self.store, self.key_store.as_ref(), now_ms).await
    }
}

pub(crate) struct RemoteMaintenanceOwner {
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
}

impl RemoteMaintenanceOwner {
    pub(crate) fn start(store: RuntimeStoreHandle, key_store: Arc<dyn KeyStore>) -> Self {
        Self::start_with(
            Arc::new(RuntimeStoreMaintenanceCollector { store, key_store }),
            REMOTE_MAINTENANCE_INTERVAL,
            REMOTE_MAINTENANCE_SHUTDOWN_DEADLINE,
        )
    }

    fn start_with(
        collector: Arc<dyn MaintenanceCollector>,
        interval: Duration,
        shutdown_timeout: Duration,
    ) -> Self {
        debug_assert!(!interval.is_zero());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_maintenance_loop(collector, interval, shutdown_rx));
        Self {
            shutdown_tx,
            task: Some(task),
            shutdown_timeout,
        }
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), RemoteMaintenanceError> {
        self.shutdown_tx.send_replace(true);
        let mut task = self.task.take().expect("maintenance task is present");
        match tokio::time::timeout(self.shutdown_timeout, &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(RemoteMaintenanceError::TaskFailed),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(RemoteMaintenanceError::ShutdownTimedOut)
            }
        }
    }
}

async fn run_maintenance_loop(
    collector: Arc<dyn MaintenanceCollector>,
    interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval_at(Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                let now_ms = match unix_now_ms() {
                    Some(now_ms) => now_ms,
                    None => {
                        crate::diag::log(
                            "remote_maintenance_cycle",
                            "status=blocked code=daemon.remote.clock_invalid",
                        );
                        continue;
                    }
                };
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return;
                        }
                    }
                    result = collector.collect(now_ms) => {
                        if let Err(error) = result {
                            // retention GC 先全库认证且失败零删除；保留 business owner 并在下一
                            // tick 重试，比把一次暂态 Store 错误升级为 detached shutdown 更安全。
                            crate::diag::log(
                                "remote_maintenance_cycle",
                                &format!("status=blocked code={}", error.code()),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn unix_now_ms() -> Option<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    u64::try_from(millis).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    #[derive(Default)]
    struct CountingCollector {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl MaintenanceCollector for CountingCollector {
        async fn collect(&self, _now_ms: u64) -> Result<(), RemoteMaintenanceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn long_running_owner_repeats_without_restart_and_stops_after_join() {
        let collector = Arc::new(CountingCollector::default());
        let owner = RemoteMaintenanceOwner::start_with(
            collector.clone(),
            Duration::from_secs(60),
            Duration::from_secs(1),
        );
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert_eq!(collector.calls.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(collector.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert_eq!(collector.calls.load(Ordering::SeqCst), 2);

        owner.shutdown().await.expect("join maintenance owner");
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert_eq!(collector.calls.load(Ordering::SeqCst), 2);
    }

    struct BlockingCollector {
        entered: Notify,
        active: AtomicBool,
    }

    struct ActiveCall<'a>(&'a AtomicBool);

    impl Drop for ActiveCall<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl MaintenanceCollector for BlockingCollector {
        async fn collect(&self, _now_ms: u64) -> Result<(), RemoteMaintenanceError> {
            self.active.store(true, Ordering::SeqCst);
            let _active = ActiveCall(&self.active);
            self.entered.notify_one();
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancels_inflight_collection_before_returning() {
        let collector = Arc::new(BlockingCollector {
            entered: Notify::new(),
            active: AtomicBool::new(false),
        });
        let owner = RemoteMaintenanceOwner::start_with(
            collector.clone(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        collector.entered.notified().await;
        assert!(collector.active.load(Ordering::SeqCst));

        owner.shutdown().await.expect("shutdown cancels collector");
        assert!(!collector.active.load(Ordering::SeqCst));
    }
}
