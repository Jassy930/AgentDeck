//! Subscription job 的 prepare/commit/cleanup 编排。
//!
//! 威胁场景：resubscribe 与 disconnect 若在旧 pump 仍可入队时直接安装新 generation，
//! 迟到 snapshot/live frame 会污染新 reducer；因此先冻结 store barrier，再原子安装
//! registry lease，并通过每 connection 单 gate 取消、收割旧 job 后才发布新 receipt。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_protocol::runtime::command::CatalogRequest;
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{RuntimeFailure, RuntimeReply};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::oneshot;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use super::super::AgentRouter;
use super::super::backfill::{BarrierDecision, BarrierRequest};
use super::super::catalog_snapshot::{
    CatalogOneShotPermit, CatalogSnapshotProvider, CatalogSnapshotProviderError,
};
use super::super::connection::{
    AuthenticatedPrincipal, ConnectionError, ConnectionId, ConnectionRegistry,
};
use super::super::events::{RegisterStreamBarrier, RuntimeStreamTarget, WatchGeneration};
use super::super::history_receipt::HistoryOnlyReceiptRegistry;
use super::super::model::RuntimeStoreError;
#[cfg(test)]
use super::super::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES;
use super::super::store::RuntimeStoreHandle;
use super::super::store::key_transition::TransitionSnapshotPermit;
use super::budget::{
    MAX_PENDING_SUBSCRIPTION_JOBS_GLOBAL, MAX_PENDING_SUBSCRIPTION_JOBS_PER_CONNECTION,
};
use super::egress::TransferEgressControl;
use super::{
    SubscriptionLease, SubscriptionRegistry, SubscriptionRegistryError, TransientSubscriptionLease,
};

const BARRIER_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SubscriptionPumpError {
    #[error(transparent)]
    Registry(#[from] SubscriptionRegistryError),
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    Catalog(#[from] CatalogSnapshotProviderError),
    #[error("runtime snapshot recovery failed: {0}")]
    Snapshot(String),
    #[error("one-shot catalog job identity is exhausted")]
    CatalogJobIdentityExhausted,
    #[error("one-shot catalog admission reached its absolute deadline")]
    CatalogJobExpired,
    #[error("subscription wall clock is outside the representable range")]
    Clock,
    #[error("subscription watch generation is invalid")]
    InvalidGeneration,
    #[error("subscription coordinator lock is poisoned")]
    Poisoned,
}

impl SubscriptionPumpError {
    pub(crate) fn into_failure(self) -> RuntimeFailure {
        use agentdeck_protocol::runtime::failure::{
            DAEMON_RUNTIME_CONNECTION_UNAVAILABLE, DAEMON_RUNTIME_IDENTITY_UNAVAILABLE,
            DAEMON_RUNTIME_READ_UNAVAILABLE,
        };
        let code = match self {
            Self::Connection(_) => DAEMON_RUNTIME_CONNECTION_UNAVAILABLE,
            Self::Registry(SubscriptionRegistryError::EntropyUnavailable)
            | Self::Registry(SubscriptionRegistryError::GenerationExhausted)
            | Self::InvalidGeneration
            | Self::Catalog(CatalogSnapshotProviderError::EntropyUnavailable)
            | Self::Catalog(CatalogSnapshotProviderError::GenerationExhausted)
            | Self::CatalogJobIdentityExhausted => DAEMON_RUNTIME_IDENTITY_UNAVAILABLE,
            _ => DAEMON_RUNTIME_READ_UNAVAILABLE,
        };
        RuntimeFailure::new(code, self.to_string())
    }
}

struct JobEntry {
    generation: super::SubscriptionGeneration,
    control: TransferEgressControl,
    handle: JoinHandle<()>,
}

struct CatalogJobEntry {
    control: TransferEgressControl,
    handle: JoinHandle<()>,
}

struct CoordinatorInner {
    store: RuntimeStoreHandle,
    router: Arc<AgentRouter>,
    connections: ConnectionRegistry,
    registry: SubscriptionRegistry,
    snapshot_build_budget: Arc<Semaphore>,
    snapshot_build_gate: Arc<AsyncMutex<()>>,
    catalog_snapshots: CatalogSnapshotProvider,
    history_receipts: HistoryOnlyReceiptRegistry,
    jobs: Mutex<HashMap<(ConnectionId, RuntimeStreamTarget), JobEntry>>,
    catalog_jobs: Mutex<HashMap<(ConnectionId, u64), CatalogJobEntry>>,
    next_catalog_job_id: AtomicU64,
    gates: Mutex<HashMap<ConnectionId, Arc<AsyncMutex<()>>>>,
    coordination_gates: Mutex<HashMap<ConnectionId, Arc<AsyncMutex<()>>>>,
    pending_job_slots: Arc<Semaphore>,
    pending_job_connection_slots: Mutex<HashMap<ConnectionId, Arc<Semaphore>>>,
    barrier_ttl_ms: AtomicU64,
}

pub(super) struct PendingSubscriptionPermit {
    _global: OwnedSemaphorePermit,
    _connection: OwnedSemaphorePermit,
}

enum SubscriptionBarrierPreparation {
    Standard {
        target: RuntimeStreamTarget,
        request: BarrierRequest,
    },
    TransitionSnapshot {
        target: RuntimeStreamTarget,
        permit: Box<TransitionSnapshotPermit>,
    },
}

impl SubscriptionBarrierPreparation {
    const fn target(&self) -> RuntimeStreamTarget {
        match self {
            Self::Standard { target, .. } | Self::TransitionSnapshot { target, .. } => *target,
        }
    }

    fn transition_snapshot(&self) -> Option<TransitionSnapshotPermit> {
        match self {
            Self::Standard { .. } => None,
            Self::TransitionSnapshot { permit, .. } => Some(permit.as_ref().clone()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct SubscriptionCoordinator {
    inner: Arc<CoordinatorInner>,
}

impl SubscriptionCoordinator {
    pub(crate) fn new(
        store: RuntimeStoreHandle,
        router: Arc<AgentRouter>,
        connections: ConnectionRegistry,
        snapshot_build_budget: Arc<Semaphore>,
        catalog_snapshots: CatalogSnapshotProvider,
        history_receipts: HistoryOnlyReceiptRegistry,
    ) -> Self {
        Self {
            inner: Arc::new(CoordinatorInner {
                store,
                router,
                connections,
                registry: SubscriptionRegistry::new(),
                snapshot_build_budget,
                snapshot_build_gate: Arc::new(AsyncMutex::new(())),
                catalog_snapshots,
                history_receipts,
                jobs: Mutex::new(HashMap::new()),
                catalog_jobs: Mutex::new(HashMap::new()),
                next_catalog_job_id: AtomicU64::new(1),
                gates: Mutex::new(HashMap::new()),
                coordination_gates: Mutex::new(HashMap::new()),
                pending_job_slots: Arc::new(Semaphore::new(MAX_PENDING_SUBSCRIPTION_JOBS_GLOBAL)),
                pending_job_connection_slots: Mutex::new(HashMap::new()),
                barrier_ttl_ms: AtomicU64::new(BARRIER_TTL_MS),
            }),
        }
    }

    /// fresh first-member pairing 的内部 durable baseline 恢复。Catalog 与全部当前
    /// 缺失的 managed conversation 都复用同一个 128 MiB budget/build gate；conversation
    /// 逐个 capture + materialize，因而即使目录达到上限，也不会无界创建 task/pin 或
    /// 同时保留多份大 DTO。该路径不建立订阅、不发送 frame。
    pub(crate) async fn refresh_snapshots_for_remote_membership(
        &self,
    ) -> Result<(), SubscriptionPumpError> {
        let missing = self
            .inner
            .store
            .load_first_remote_member_missing_snapshot_conversations()
            .await?;
        // 先完成 authenticated publication/conversation 只读计划，再允许第一笔
        // snapshot write；authority/NeedsSnapshot/corruption 失败不得顺手刷新 Catalog。
        self.inner
            .catalog_snapshots
            .refresh_current_durable_baseline()
            .await?;
        for conversation_id in missing {
            let source = self
                .inner
                .store
                .acquire_snapshot_build_source(conversation_id)
                .await?;
            let reduced = super::reducer::materialize(
                &self.inner.store,
                self.inner.router.clone(),
                source,
                self.inner.snapshot_build_budget.clone(),
                self.inner.snapshot_build_gate.clone(),
            )
            .await
            .map_err(|error| SubscriptionPumpError::Snapshot(error.to_string()))?;
            let (_snapshot, payload, _history_command_ids, _memory_permit) = reduced.into_parts();
            if matches!(
                &payload,
                super::reducer::ReducedSnapshotPayload::Durable { .. }
            ) {
                continue;
            }
            // NativeProjected/transition-only materialization 不能伪装成 durable baseline。
            // 先精确释放 TEMP pin，再保持 typed snapshot prerequisite fail-close。
            payload
                .release_after_flush(&self.inner.store, self.inner.router.clone())
                .await
                .map_err(|error| SubscriptionPumpError::Snapshot(error.to_string()))?;
            return Err(RuntimeStoreError::PublicationNeedsSnapshot.into());
        }
        Ok(())
    }

    pub(crate) async fn prepare(
        &self,
        connection_id: ConnectionId,
        message_id: MessageId,
        target: RuntimeStreamTarget,
        request: BarrierRequest,
        emit_subscription_receipt: bool,
    ) -> Result<PreparedSubscription, SubscriptionPumpError> {
        self.prepare_inner(
            connection_id,
            message_id,
            SubscriptionBarrierPreparation::Standard { target, request },
            emit_subscription_receipt,
        )
        .await
    }

    pub(crate) async fn prepare_transition_snapshot(
        &self,
        connection_id: ConnectionId,
        message_id: MessageId,
        target: RuntimeStreamTarget,
        permit: TransitionSnapshotPermit,
    ) -> Result<PreparedSubscription, SubscriptionPumpError> {
        self.prepare_inner(
            connection_id,
            message_id,
            SubscriptionBarrierPreparation::TransitionSnapshot {
                target,
                permit: Box::new(permit),
            },
            true,
        )
        .await
    }

    async fn prepare_inner(
        &self,
        connection_id: ConnectionId,
        message_id: MessageId,
        preparation: SubscriptionBarrierPreparation,
        emit_subscription_receipt: bool,
    ) -> Result<PreparedSubscription, SubscriptionPumpError> {
        let target = preparation.target();
        // 快速拒绝明显不存在的连接，避免为伪造 ID 创建 coordination slot；随后
        // 仍在 connection 的 coordination gate 内重查并取得同一 pending semaphore。
        let _ = self.inner.connections.principal(connection_id)?;
        let coordination_gate = self.coordination_gate(connection_id)?;
        let coordination_guard = coordination_gate.lock().await;
        let _ = self.inner.connections.principal(connection_id)?;
        let pending_connection_slots = self.pending_connection_slots(connection_id)?;
        drop(coordination_guard);
        // 威胁场景：terminal sibling 持 gate 时快速 resubscribe 会把 previous
        // handle/registration 链进新 task；必须在 Store capture/spawn 前先占硬上界。
        // slot capture 与 disconnect 在同一 coordination gate 线性化：prepare 先赢
        // 就共享旧 semaphore；disconnect 先赢则 principal recheck 失败，不能重建槽。
        let pending_permit = self.reserve_pending_job(pending_connection_slots)?;
        let generation = self.inner.registry.allocate_generation()?;
        let watch_generation = WatchGeneration::new(generation.watch_generation())
            .ok_or(SubscriptionPumpError::InvalidGeneration)?;
        let transition_snapshot = preparation.transition_snapshot();
        let registration = match preparation {
            SubscriptionBarrierPreparation::Standard { target, request } => {
                self.inner
                    .store
                    .register_stream_barrier(RegisterStreamBarrier {
                        target,
                        generation: watch_generation,
                        request,
                    })
                    .await?
            }
            SubscriptionBarrierPreparation::TransitionSnapshot { permit, .. } => {
                self.inner
                    .store
                    .register_transition_snapshot_barrier(*permit, watch_generation)
                    .await?
            }
        };
        let needs_snapshot = matches!(registration.decision, BarrierDecision::Snapshot { .. });
        let now_ms = epoch_ms()?;
        let coordination_guard = coordination_gate.lock().await;
        let principal = self.inner.connections.principal(connection_id)?;
        let lease = self.inner.registry.install(
            connection_id,
            target,
            generation,
            needs_snapshot,
            now_ms,
        )?;
        drop(coordination_guard);
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(
                self.inner.barrier_ttl_ms.load(Ordering::Acquire),
            ))
            .ok_or(SubscriptionPumpError::Clock)?;
        let gate = self.gate(connection_id)?;
        Ok(PreparedSubscription {
            coordinator: self.clone(),
            connection_id,
            message_id,
            target,
            registration,
            lease,
            control: TransferEgressControl::new(deadline),
            gate: gate.clone(),
            emit_subscription_receipt,
            transition_snapshot,
            principal,
            coordination_gate,
            pending_permit,
        })
    }

    /// 启动一次 directed CatalogRequest。null page 与 subscription 原子共享
    /// barrier+snapshot-sender 配额；cursor page 至少共享 snapshot-sender 配额。
    /// page build 和 socket flush 都在后台 job 的同一 per-connection gate 内执行，
    /// 因此 envelope caller 不等待 SQLite I/O、writer permit 或 transport ACK。
    pub(crate) async fn start_catalog_request(
        &self,
        connection_id: ConnectionId,
        message_id: MessageId,
        request: CatalogRequest,
    ) -> Result<(), SubscriptionPumpError> {
        let _ = self.inner.connections.principal(connection_id)?;
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(
                self.inner.barrier_ttl_ms.load(Ordering::Acquire),
            ))
            .ok_or(SubscriptionPumpError::Clock)?;
        let coordination_gate = self.coordination_gate(connection_id)?;
        let _coordination_guard = tokio::time::timeout_at(deadline, coordination_gate.lock())
            .await
            .map_err(|_| SubscriptionPumpError::CatalogJobExpired)?;
        // disconnect 在同一 gate 内先撤销 ConnectionRegistry admission；因此这里
        // 的第二次 principal 读取与 quota/task publish 对 disconnect 原子排序。
        let principal = self.inner.connections.principal(connection_id)?;
        let budget = self.inner.registry.reserve_transient(
            connection_id,
            request.page_cursor.is_none(),
            true,
            epoch_ms()?,
        )?;
        let one_shot = self.inner.catalog_snapshots.reserve_one_shot()?;
        let control = TransferEgressControl::new(deadline);
        let job_id = self
            .inner
            .next_catalog_job_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| SubscriptionPumpError::CatalogJobIdentityExhausted)?;
        let key = (connection_id, job_id);
        let gate = self.gate(connection_id)?;
        let (published, published_rx) = oneshot::channel();
        let coordinator = self.clone();
        let completion = self.clone();
        let task_control = control.clone();
        let handle = tokio::spawn(async move {
            if published_rx.await.is_err() {
                return;
            }
            let cancellation = task_control.clone();
            let result = run_catalog_job(CatalogJob {
                provider: coordinator.inner.catalog_snapshots.clone(),
                connections: coordinator.inner.connections.clone(),
                connection_id,
                message_id,
                request,
                principal,
                one_shot,
                budget,
                control: task_control,
                gate,
            })
            .await;
            let fail_closed = if let Err(error) = result
                && !error.is_cancelled()
                && !cancellation.is_cancelled()
            {
                crate::diag::log("runtime_catalog_job_failed", &error.to_string());
                // TransferPart 已经可见后不得再发送另一份 terminal reply；所有
                // egress/build terminal failure 都关闭该 connection，partial path
                // 因而必定 fail-close。
                let _ = completion.inner.connections.fail_close(connection_id);
                true
            } else {
                false
            };
            if let Err(error) = completion.finish_catalog_job_exact(key) {
                crate::diag::log("runtime_catalog_job_cleanup_failed", &error.to_string());
            }
            if fail_closed {
                spawn_disconnect_cleanup(completion, connection_id);
            }
        });
        let replaced = self
            .inner
            .catalog_jobs
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .insert(key, CatalogJobEntry { control, handle });
        debug_assert!(replaced.is_none());
        if published.send(()).is_err() {
            let _ = self.finish_catalog_job_exact(key);
            return Err(SubscriptionPumpError::Connection(
                ConnectionError::WriterTaskFailed,
            ));
        }
        Ok(())
    }

    pub(crate) async fn unsubscribe(
        &self,
        connection_id: ConnectionId,
        target: RuntimeStreamTarget,
    ) -> Result<bool, SubscriptionPumpError> {
        let coordination_gate = self.coordination_gate(connection_id)?;
        let coordination_guard = coordination_gate.lock().await;
        let released = self.inner.registry.unsubscribe(connection_id, target)?;
        let entry = self
            .inner
            .jobs
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .remove(&(connection_id, target));
        if let Some(entry) = &entry {
            entry.control.cancel();
        }
        // coordination gate 只保护 admission/job-map 线性化，绝不能跨 egress
        // gate 或 JoinHandle wait；否则另一个 target 的 commit 可形成锁序环。
        drop(coordination_guard);
        if let Some(entry) = entry {
            let _ = entry.handle.await;
        }
        Ok(released)
    }

    pub(crate) async fn disconnect(
        &self,
        connection_id: ConnectionId,
    ) -> Result<(), SubscriptionPumpError> {
        let coordination_gate = self.coordination_gate(connection_id)?;
        let coordination_guard = coordination_gate.lock().await;
        // 先撤销 connection admission，再收割 registry/jobs。等待同一 gate 的
        // Catalog start 随后必在二次 principal 检查处失败，不能 post-disconnect spawn。
        self.inner.connections.fail_close(connection_id)?;
        let _ = self.inner.registry.disconnect(connection_id)?;
        let entries = {
            let mut jobs = self
                .inner
                .jobs
                .lock()
                .map_err(|_| SubscriptionPumpError::Poisoned)?;
            let keys = jobs
                .keys()
                .filter(|(id, _)| *id == connection_id)
                .copied()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| jobs.remove(&key))
                .collect::<Vec<_>>()
        };
        let catalog_entries = {
            let mut jobs = self
                .inner
                .catalog_jobs
                .lock()
                .map_err(|_| SubscriptionPumpError::Poisoned)?;
            let keys = jobs
                .keys()
                .filter(|(id, _)| *id == connection_id)
                .copied()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| jobs.remove(&key))
                .collect::<Vec<_>>()
        };
        for entry in &entries {
            entry.control.cancel();
        }
        for entry in &catalog_entries {
            entry.control.cancel();
        }
        self.inner
            .pending_job_connection_slots
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .remove(&connection_id);
        // fail-close、registry 清理与 job detach 已在 coordination gate 内完成；
        // 后续只等待已取消且已登记的 job，不能继续持有 coordination gate，
        // 也不能先等全 connection egress gate（exact handle 已证明自己的 guard 退出）。
        drop(coordination_guard);
        for entry in entries {
            let _ = entry.handle.await;
        }
        for entry in catalog_entries {
            let _ = entry.handle.await;
        }
        self.inner
            .gates
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .remove(&connection_id);
        self.inner
            .coordination_gates
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .remove(&connection_id);
        Ok(())
    }

    pub(crate) async fn shutdown(&self) -> Result<(), SubscriptionPumpError> {
        let mut connections = self
            .inner
            .jobs
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .keys()
            .map(|(connection_id, _)| *connection_id)
            .collect::<HashSet<_>>();
        connections.extend(
            self.inner
                .catalog_jobs
                .lock()
                .map_err(|_| SubscriptionPumpError::Poisoned)?
                .keys()
                .map(|(connection_id, _)| *connection_id),
        );
        for connection_id in connections {
            self.disconnect(connection_id).await?;
        }
        self.inner.catalog_snapshots.clear_cache()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn metrics_for_test(
        &self,
    ) -> Result<(usize, usize, usize, usize), SubscriptionPumpError> {
        let (usage, _) = self.inner.registry.metrics()?;
        let jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .len();
        Ok((usage.live, usage.barriers, usage.snapshot_senders, jobs))
    }

    #[cfg(test)]
    pub(crate) fn catalog_metrics_for_test(&self) -> Result<(usize, usize), SubscriptionPumpError> {
        let active = self.inner.registry.transient_count_for_test()?;
        let jobs = self
            .inner
            .catalog_jobs
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .len();
        Ok((active, jobs))
    }

    #[cfg(test)]
    pub(crate) fn catalog_resource_usage_for_test(&self) -> (usize, usize) {
        self.inner.catalog_snapshots.resource_usage_for_test()
    }

    #[cfg(test)]
    pub(crate) fn exhaust_catalog_global_quota_for_test(
        &self,
    ) -> tokio::sync::OwnedSemaphorePermit {
        self.inner
            .catalog_snapshots
            .exhaust_one_shot_slots_for_test()
    }

    #[cfg(test)]
    pub(crate) fn set_barrier_ttl_for_test(&self, ttl: Duration) {
        let millis = u64::try_from(ttl.as_millis()).expect("test barrier TTL fits u64");
        assert!(millis > 0);
        self.inner.barrier_ttl_ms.store(millis, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) async fn hold_coordination_gate_for_test(
        &self,
        connection_id: ConnectionId,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.coordination_gate(connection_id)
            .expect("test coordination gate")
            .lock_owned()
            .await
    }

    #[cfg(test)]
    pub(crate) async fn exhaust_snapshot_budget_for_test(
        &self,
    ) -> tokio::sync::OwnedSemaphorePermit {
        self.inner
            .snapshot_build_budget
            .clone()
            .acquire_many_owned(SNAPSHOT_BUILD_MEMORY_BYTES as u32)
            .await
            .expect("snapshot build budget is open")
    }

    #[cfg(test)]
    pub(crate) fn snapshot_budget_available_for_test(&self) -> usize {
        self.inner.snapshot_build_budget.available_permits()
    }

    #[cfg(test)]
    pub(crate) fn pending_job_usage_for_test(
        &self,
        connection_id: ConnectionId,
    ) -> Result<(usize, usize), SubscriptionPumpError> {
        let global =
            MAX_PENDING_SUBSCRIPTION_JOBS_GLOBAL - self.inner.pending_job_slots.available_permits();
        let connection = self
            .inner
            .pending_job_connection_slots
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .get(&connection_id)
            .map_or(0, |slots| {
                MAX_PENDING_SUBSCRIPTION_JOBS_PER_CONNECTION - slots.available_permits()
            });
        Ok((connection, global))
    }

    #[cfg(test)]
    pub(crate) fn pending_job_connection_slot_count_for_test(
        &self,
    ) -> Result<usize, SubscriptionPumpError> {
        Ok(self
            .inner
            .pending_job_connection_slots
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .len())
    }

    fn gate(
        &self,
        connection_id: ConnectionId,
    ) -> Result<Arc<AsyncMutex<()>>, SubscriptionPumpError> {
        Ok(self
            .inner
            .gates
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .entry(connection_id)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone())
    }

    fn coordination_gate(
        &self,
        connection_id: ConnectionId,
    ) -> Result<Arc<AsyncMutex<()>>, SubscriptionPumpError> {
        Ok(self
            .inner
            .coordination_gates
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .entry(connection_id)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone())
    }

    fn pending_connection_slots(
        &self,
        connection_id: ConnectionId,
    ) -> Result<Arc<Semaphore>, SubscriptionPumpError> {
        Ok(self
            .inner
            .pending_job_connection_slots
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .entry(connection_id)
            .or_insert_with(|| {
                Arc::new(Semaphore::new(MAX_PENDING_SUBSCRIPTION_JOBS_PER_CONNECTION))
            })
            .clone())
    }

    fn reserve_pending_job(
        &self,
        connection_slots: Arc<Semaphore>,
    ) -> Result<PendingSubscriptionPermit, SubscriptionPumpError> {
        let global = self
            .inner
            .pending_job_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| SubscriptionRegistryError::Overloaded("global pending job"))?;
        let connection = connection_slots
            .try_acquire_owned()
            .map_err(|_| SubscriptionRegistryError::Overloaded("connection pending job"))?;
        Ok(PendingSubscriptionPermit {
            _global: global,
            _connection: connection,
        })
    }

    fn finish_job_exact(
        &self,
        key: (ConnectionId, RuntimeStreamTarget),
        generation: super::SubscriptionGeneration,
    ) -> Result<bool, SubscriptionPumpError> {
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?;
        if jobs
            .get(&key)
            .is_some_and(|entry| entry.generation == generation)
        {
            jobs.remove(&key);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn finish_catalog_job_exact(
        &self,
        key: (ConnectionId, u64),
    ) -> Result<bool, SubscriptionPumpError> {
        Ok(self
            .inner
            .catalog_jobs
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?
            .remove(&key)
            .is_some())
    }
}

struct CatalogJob {
    provider: CatalogSnapshotProvider,
    connections: ConnectionRegistry,
    connection_id: ConnectionId,
    message_id: MessageId,
    request: CatalogRequest,
    principal: AuthenticatedPrincipal,
    one_shot: CatalogOneShotPermit,
    budget: TransientSubscriptionLease,
    control: TransferEgressControl,
    gate: Arc<AsyncMutex<()>>,
}

#[derive(Debug, thiserror::Error)]
enum CatalogJobRunError {
    #[error("one-shot catalog job was cancelled")]
    Cancelled,
    #[error("one-shot catalog job reached its absolute deadline")]
    Expired,
    #[error(transparent)]
    Send(#[from] super::pump::OneShotSendError),
}

impl CatalogJobRunError {
    fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

async fn run_catalog_job(job: CatalogJob) -> Result<(), CatalogJobRunError> {
    let CatalogJob {
        provider,
        connections,
        connection_id,
        message_id,
        request,
        principal,
        one_shot,
        budget,
        control,
        gate,
    } = job;
    // shared budget 与 page/global permit 都必须先于 jobs-map cleanup drop，测试与生产
    // disconnect 因而不会观察到“job 已消失但 quota/memory 尚未归还”的窗口。
    let _budget = budget;
    let _gate = controlled_catalog(&control, gate.lock()).await?;
    let page = match controlled_catalog(
        &control,
        provider.prepare_page_for_request(&request, &principal, one_shot),
    )
    .await?
    {
        Ok(page) => page,
        Err(error) => {
            super::pump::send_one_shot_reply(
                &connections,
                connection_id,
                message_id,
                RuntimeReply::Failure(SubscriptionPumpError::Catalog(error).into_failure()),
                None,
                &control,
            )
            .await?;
            return Ok(());
        }
    };
    super::pump::send_one_shot_reply(
        &connections,
        connection_id,
        message_id,
        RuntimeReply::Catalog(page.snapshot().clone()),
        Some(page.payload()),
        &control,
    )
    .await?;
    drop(page);
    Ok(())
}

async fn controlled_catalog<T>(
    control: &TransferEgressControl,
    operation: impl std::future::Future<Output = T>,
) -> Result<T, CatalogJobRunError> {
    if let Some(deadline) = control.absolute_deadline() {
        tokio::select! {
            biased;
            _ = control.cancelled() => Err(CatalogJobRunError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(CatalogJobRunError::Expired),
            value = operation => Ok(value),
        }
    } else {
        tokio::select! {
            biased;
            _ = control.cancelled() => Err(CatalogJobRunError::Cancelled),
            value = operation => Ok(value),
        }
    }
}

pub(crate) struct PreparedSubscription {
    coordinator: SubscriptionCoordinator,
    connection_id: ConnectionId,
    message_id: MessageId,
    target: RuntimeStreamTarget,
    registration: super::super::events::StreamBarrierRegistration,
    lease: SubscriptionLease,
    control: TransferEgressControl,
    gate: Arc<AsyncMutex<()>>,
    emit_subscription_receipt: bool,
    transition_snapshot: Option<TransitionSnapshotPermit>,
    principal: super::super::connection::AuthenticatedPrincipal,
    coordination_gate: Arc<AsyncMutex<()>>,
    pending_permit: PendingSubscriptionPermit,
}

impl PreparedSubscription {
    pub(crate) async fn commit(self) -> Result<(), SubscriptionPumpError> {
        let key = (self.connection_id, self.target);
        let _coordination_guard = self.coordination_gate.lock().await;
        self.coordinator
            .inner
            .registry
            .require_current(&self.lease)?;
        let _ = self
            .coordinator
            .inner
            .connections
            .principal(self.connection_id)?;
        let mut jobs = self
            .coordinator
            .inner
            .jobs
            .lock()
            .map_err(|_| SubscriptionPumpError::Poisoned)?;
        let previous = jobs.remove(&key);
        if let Some(previous) = &previous {
            previous.control.cancel();
        }
        let pump_gate = self.gate.clone();
        let pump_coordination_gate = self.coordination_gate.clone();
        let control = self.control.clone();
        let coordinator = self.coordinator.clone();
        let generation = self.lease.generation();
        let (published, published_rx) = oneshot::channel();
        let pump_coordinator = coordinator.clone();
        let completion_coordinator = coordinator.clone();
        let handle = tokio::spawn(async move {
            if published_rx.await.is_err() {
                return;
            }
            // replacement 先通过 exact handle 收割旧 generation；新 job 已经在 map
            // 中可被 unsubscribe/disconnect/shutdown 取消，因此这里不会成为隐形 waiter。
            if let Some(previous) = previous {
                let _ = previous.handle.await;
            }
            let fail_closed = super::pump::run(super::pump::PumpJob {
                store: pump_coordinator.inner.store.clone(),
                router: pump_coordinator.inner.router.clone(),
                connections: pump_coordinator.inner.connections.clone(),
                connection_id: self.connection_id,
                message_id: self.message_id,
                target: self.target,
                registration: Some(self.registration),
                lease: self.lease,
                registry: pump_coordinator.inner.registry.clone(),
                control: self.control,
                gate: pump_gate,
                coordination_gate: pump_coordination_gate,
                snapshot_build_budget: pump_coordinator.inner.snapshot_build_budget.clone(),
                snapshot_build_gate: pump_coordinator.inner.snapshot_build_gate.clone(),
                catalog_snapshots: pump_coordinator.inner.catalog_snapshots.clone(),
                history_receipts: pump_coordinator.inner.history_receipts.clone(),
                principal: self.principal,
                flushed_business_frame: false,
                emit_subscription_receipt: self.emit_subscription_receipt,
                transition_snapshot: self.transition_snapshot,
                pending_permit: Some(self.pending_permit),
                publication_overlap: None,
            })
            .await;
            if let Err(error) = completion_coordinator.finish_job_exact(key, generation) {
                crate::diag::log(
                    "runtime_subscription_job_cleanup_failed",
                    &error.to_string(),
                );
            }
            if fail_closed {
                spawn_disconnect_cleanup(completion_coordinator, self.connection_id);
            }
        });
        let replaced = jobs.insert(
            key,
            JobEntry {
                generation,
                control,
                handle,
            },
        );
        debug_assert!(replaced.is_none());
        drop(jobs);
        if published.send(()).is_err() {
            let _ = coordinator.finish_job_exact(key, generation);
            return Err(SubscriptionPumpError::Connection(
                ConnectionError::WriterTaskFailed,
            ));
        }
        Ok(())
    }
}

fn spawn_disconnect_cleanup(coordinator: SubscriptionCoordinator, connection_id: ConnectionId) {
    tokio::spawn(async move {
        if let Err(error) = coordinator.disconnect(connection_id).await {
            crate::diag::log(
                "runtime_connection_sibling_cleanup_failed",
                &error.to_string(),
            );
        }
    });
}

fn epoch_ms() -> Result<u64, SubscriptionPumpError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SubscriptionPumpError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| SubscriptionPumpError::Clock)
}
