//! Frozen catalog cache 的可替换 absolute-expiry task owner。
//!
//! 威胁场景：已认证客户端在 cursor TTL 内重复翻页或刷新同一 durable cut；若每次
//! touch 都留下一个 5 分钟 sleeper，单个 cache 即可制造无界 Tokio task DoS。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::CatalogSnapshotProviderError;
use super::cache::{CatalogCacheExpiry, CatalogMemoryState};

struct ScheduledExpiry {
    identity: Arc<()>,
    handle: JoinHandle<()>,
}

pub(super) struct CatalogExpiryTasks {
    tasks: Mutex<HashMap<[u8; 16], ScheduledExpiry>>,
    #[cfg(test)]
    active_tasks: Arc<std::sync::atomic::AtomicUsize>,
}

impl CatalogExpiryTasks {
    pub(super) fn new() -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            #[cfg(test)]
            active_tasks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub(super) fn replace(
        self: &Arc<Self>,
        memory: Weak<Mutex<CatalogMemoryState>>,
        snapshot_id: [u8; 16],
        expiry: CatalogCacheExpiry,
        observed_now_ms: u64,
    ) -> Result<(), CatalogSnapshotProviderError> {
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
        if let Some(previous) = tasks.remove(&snapshot_id) {
            previous.handle.abort();
        }

        let identity = Arc::new(());
        let task_identity = identity.clone();
        let owner = Arc::downgrade(self);
        let delay = Duration::from_millis(expiry.expires_at_ms.saturating_sub(observed_now_ms));
        let (publish, published) = oneshot::channel();
        #[cfg(test)]
        let active_tasks = self.active_tasks.clone();
        let handle = tokio::spawn(async move {
            #[cfg(test)]
            let _active = ActiveExpiryTask::new(active_tasks);
            if published.await.is_err() {
                return;
            }
            tokio::time::sleep(delay).await;
            if let Some(memory) = memory.upgrade()
                && let Ok(mut state) = memory.lock()
            {
                state.expire_exact(snapshot_id, expiry);
            }
            if let Some(owner) = owner.upgrade() {
                owner.finish_exact(snapshot_id, &task_identity);
            }
        });
        let replaced = tasks.insert(snapshot_id, ScheduledExpiry { identity, handle });
        debug_assert!(replaced.is_none());
        drop(tasks);
        let _ = publish.send(());
        Ok(())
    }

    pub(super) fn clear(&self) -> Result<(), CatalogSnapshotProviderError> {
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
        for (_, task) in tasks.drain() {
            task.handle.abort();
        }
        Ok(())
    }

    pub(super) fn cancel(&self, snapshot_id: [u8; 16]) -> Result<(), CatalogSnapshotProviderError> {
        let task = self
            .tasks
            .lock()
            .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?
            .remove(&snapshot_id);
        if let Some(task) = task {
            task.handle.abort();
        }
        Ok(())
    }

    fn finish_exact(&self, snapshot_id: [u8; 16], identity: &Arc<()>) {
        let Ok(mut tasks) = self.tasks.lock() else {
            return;
        };
        if tasks
            .get(&snapshot_id)
            .is_some_and(|task| Arc::ptr_eq(&task.identity, identity))
        {
            tasks.remove(&snapshot_id);
        }
    }

    #[cfg(test)]
    pub(super) fn metrics(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering;

        let scheduled = self.tasks.lock().map_or(usize::MAX, |tasks| tasks.len());
        (scheduled, self.active_tasks.load(Ordering::Acquire))
    }
}

impl Drop for CatalogExpiryTasks {
    fn drop(&mut self) {
        let tasks = match self.tasks.get_mut() {
            Ok(tasks) => tasks,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (_, task) in tasks.drain() {
            task.handle.abort();
        }
    }
}

#[cfg(test)]
struct ActiveExpiryTask(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl ActiveExpiryTask {
    fn new(active: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        use std::sync::atomic::Ordering;

        active.fetch_add(1, Ordering::AcqRel);
        Self(active)
    }
}

#[cfg(test)]
impl Drop for ActiveExpiryTask {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
