//! 旧分页 cursor 的进程内冻结快照与 128 MiB 硬预算。
//!
//! 威胁场景：并发 refresh 会替换唯一 durable catalog row；若已签发 cursor 再按
//! “最新 row”读取，会混入另一个 H。这里仅缓存已签发后续页所需的 decoded baseline，
//! 绝对 TTL 到期即回收。cursor HMAC key 每次进程启动随机生成，因此重启后旧 cursor
//! 会在进入 cache 前认证失败，不需要把 cache 变成第二套持久化存储。

use std::collections::HashMap;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use agentdeck_protocol::runtime::ConversationEntry;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::CatalogSnapshotProviderError;
use crate::runtime::snapshot::{SNAPSHOT_BUILD_MEMORY_BYTES, SharedSnapshotBuildPermit};
use crate::runtime::store::ReadySnapshotReference;

pub(super) struct CachedCatalog {
    pub(super) reference: ReadySnapshotReference,
    pub(super) entries: Vec<ConversationEntry>,
    pub(super) expires_at_ms: u64,
    pub(super) expiry_version: u64,
    pub(super) retained_bytes: usize,
    pub(super) memory_permit: Option<OwnedSemaphorePermit>,
}

impl CachedCatalog {
    pub(super) fn matches(&self, reference: &ReadySnapshotReference) -> bool {
        self.reference == *reference
    }

    pub(super) fn expiry_token(&self) -> CatalogCacheExpiry {
        CatalogCacheExpiry {
            expires_at_ms: self.expires_at_ms,
            version: self.expiry_version,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CatalogCacheExpiry {
    pub(super) expires_at_ms: u64,
    pub(super) version: u64,
}

#[derive(Default)]
pub(super) struct CatalogMemoryState {
    pub(super) catalogs: HashMap<[u8; 16], CachedCatalog>,
    cache_bytes: usize,
    active_bytes: usize,
    last_now_ms: Option<u64>,
}

impl CatalogMemoryState {
    pub(super) fn observe_and_purge(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<[u8; 16]>, CatalogSnapshotProviderError> {
        if self.last_now_ms.is_some_and(|previous| now_ms < previous) {
            return Err(CatalogSnapshotProviderError::ClockRegressed);
        }
        self.last_now_ms = Some(now_ms);
        Ok(self.purge_expired(now_ms))
    }

    fn purge_expired(&mut self, now_ms: u64) -> Vec<[u8; 16]> {
        let expired = self
            .catalogs
            .iter()
            .filter_map(|(id, cached)| (now_ms >= cached.expires_at_ms).then_some(*id))
            .collect::<Vec<_>>();
        let mut removed = Vec::with_capacity(expired.len());
        for id in expired {
            if let Some(cached) = self.catalogs.remove(&id) {
                self.cache_bytes = self
                    .cache_bytes
                    .checked_sub(cached.retained_bytes)
                    .expect("catalog cache accounting cannot underflow");
                removed.push(id);
            }
        }
        removed
    }

    /// 威胁场景：共享预算在 cache match 后耗尽会让 page build 失败；若提前续期，
    /// 旧 timer 随即失效且失败路径不会安装新 timer，decoded cache permit 会被孤儿化。
    /// 因此只有成功构造 page 后才能用 match 时读到的 version 原子续期。
    pub(super) fn touch_expiry(
        &mut self,
        reference: &ReadySnapshotReference,
        matched_version: u64,
        extend_expiry_to: u64,
    ) -> Result<CatalogCacheExpiry, CatalogSnapshotProviderError> {
        let cached = self
            .catalogs
            .get_mut(&reference.snapshot_id)
            .filter(|cached| cached.matches(reference))
            .ok_or(CatalogSnapshotProviderError::InvalidCursor)?;
        if cached.expiry_version != matched_version {
            return Err(CatalogSnapshotProviderError::InvalidCursor);
        }
        if extend_expiry_to > cached.expires_at_ms {
            let next_version = cached
                .expiry_version
                .checked_add(1)
                .ok_or(CatalogSnapshotProviderError::InvalidCursor)?;
            cached.expires_at_ms = extend_expiry_to;
            cached.expiry_version = next_version;
        }
        Ok(cached.expiry_token())
    }

    pub(super) fn expire_exact(&mut self, snapshot_id: [u8; 16], expiry: CatalogCacheExpiry) {
        let expired = self
            .catalogs
            .get(&snapshot_id)
            .is_some_and(|cached| cached.expiry_token() == expiry);
        if expired && let Some(cached) = self.catalogs.remove(&snapshot_id) {
            self.cache_bytes = self
                .cache_bytes
                .checked_sub(cached.retained_bytes)
                .expect("catalog cache accounting cannot underflow");
        }
    }

    pub(super) fn clear_cache(&mut self) {
        self.catalogs.clear();
        self.cache_bytes = 0;
    }

    pub(super) fn used_bytes(&self) -> usize {
        self.cache_bytes + self.active_bytes
    }
}

pub(super) struct CatalogMemoryLease {
    state: Arc<Mutex<CatalogMemoryState>>,
    budget: Arc<Semaphore>,
    permit: Option<SharedSnapshotBuildPermit>,
    bytes: usize,
}

impl CatalogMemoryLease {
    pub(super) fn reserve(
        state: Arc<Mutex<CatalogMemoryState>>,
        budget: Arc<Semaphore>,
        bytes: usize,
    ) -> Result<Self, CatalogSnapshotProviderError> {
        if bytes == 0 || bytes > SNAPSHOT_BUILD_MEMORY_BYTES {
            return Err(CatalogSnapshotProviderError::MemoryBudgetExceeded);
        }
        let permits =
            u32::try_from(bytes).map_err(|_| CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        let permit = budget
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        {
            let mut guard = state
                .lock()
                .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
            let projected = guard
                .used_bytes()
                .checked_add(bytes)
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
            if projected > SNAPSHOT_BUILD_MEMORY_BYTES {
                return Err(CatalogSnapshotProviderError::MemoryBudgetExceeded);
            }
            guard.active_bytes = guard
                .active_bytes
                .checked_add(bytes)
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        }
        Ok(Self {
            state,
            budget,
            permit: Some(SharedSnapshotBuildPermit::new(permit)),
            bytes,
        })
    }

    pub(super) fn shared_permit(
        &self,
    ) -> Result<SharedSnapshotBuildPermit, CatalogSnapshotProviderError> {
        self.permit
            .clone()
            .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)
    }

    pub(super) fn transition(
        &mut self,
        active_bytes: usize,
        mut cached: Option<CachedCatalog>,
    ) -> Result<(), CatalogSnapshotProviderError> {
        if active_bytes == 0 || active_bytes > SNAPSHOT_BUILD_MEMORY_BYTES {
            return Err(CatalogSnapshotProviderError::MemoryBudgetExceeded);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
        if cached
            .as_ref()
            .is_some_and(|entry| state.catalogs.contains_key(&entry.reference.snapshot_id))
        {
            return Err(CatalogSnapshotProviderError::InvalidCursor);
        }
        let added_cache = cached.as_ref().map_or(0, |entry| entry.retained_bytes);
        let projected = state
            .used_bytes()
            .checked_sub(self.bytes)
            .and_then(|value| value.checked_add(active_bytes))
            .and_then(|value| value.checked_add(added_cache))
            .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        if projected > SNAPSHOT_BUILD_MEMORY_BYTES {
            return Err(CatalogSnapshotProviderError::MemoryBudgetExceeded);
        }
        let target_bytes = active_bytes
            .checked_add(added_cache)
            .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        if target_bytes > self.bytes {
            let additional = target_bytes - self.bytes;
            let additional = u32::try_from(additional)
                .map_err(|_| CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
            let permit = self
                .budget
                .clone()
                .try_acquire_many_owned(additional)
                .map_err(|_| CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
            self.permit
                .as_ref()
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?
                .merge(permit)
                .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
        } else if target_bytes < self.bytes {
            let release = self.bytes - target_bytes;
            let release = self
                .permit
                .as_ref()
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?
                .split(release)
                .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
            drop(release);
        }
        if let Some(cached) = cached.as_mut() {
            let cache_permit = self
                .permit
                .as_ref()
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?
                .split(cached.retained_bytes)
                .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
            cached.memory_permit = Some(cache_permit);
        }
        state.active_bytes = state
            .active_bytes
            .checked_sub(self.bytes)
            .and_then(|value| value.checked_add(active_bytes))
            .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        self.bytes = active_bytes;
        if let Some(cached) = cached {
            state.cache_bytes = state
                .cache_bytes
                .checked_add(cached.retained_bytes)
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
            state.catalogs.insert(cached.reference.snapshot_id, cached);
        }
        Ok(())
    }
}

impl Drop for CatalogMemoryLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.active_bytes = state
                .active_bytes
                .checked_sub(self.bytes)
                .expect("catalog active memory accounting cannot underflow");
        }
    }
}

pub(super) fn cache_retained_bound(
    logical_bytes: u64,
    entries: &[ConversationEntry],
) -> Result<usize, CatalogSnapshotProviderError> {
    let logical = usize::try_from(logical_bytes)
        .map_err(|_| CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
    logical
        .checked_add(
            entries
                .len()
                .checked_mul(size_of::<ConversationEntry>() * 2 + 128)
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?,
        )
        .and_then(|value| value.checked_add(4096))
        .filter(|value| *value <= SNAPSHOT_BUILD_MEMORY_BYTES)
        .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)
}

pub(super) fn page_memory_bound(
    entries: &[ConversationEntry],
    cursor_bytes: usize,
) -> Result<usize, CatalogSnapshotProviderError> {
    let mut strings = cursor_bytes;
    for entry in entries {
        strings = strings
            .checked_add(entry.conversation_id.as_str().len())
            .and_then(|value| value.checked_add(entry.adapter_state_key.as_str().len()))
            .and_then(|value| value.checked_add(entry.title.as_ref().map_or(0, String::len)))
            .and_then(|value| {
                value.checked_add(
                    entry
                        .cwd
                        .as_ref()
                        .map_or(0, |path| path.to_string_lossy().len()),
                )
            })
            .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
    }
    let dto = entries
        .len()
        .checked_mul(size_of::<ConversationEntry>() * 2 + 256)
        .and_then(|value| value.checked_add(strings.saturating_mul(2)))
        .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
    let json = strings
        .checked_mul(6)
        .and_then(|value| value.checked_add(entries.len().saturating_mul(512)))
        .and_then(|value| value.checked_add(4096))
        .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
    dto.checked_add(json)
        .and_then(|value| value.checked_add(json))
        .filter(|value| *value > 0 && *value <= SNAPSHOT_BUILD_MEMORY_BYTES)
        .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)
}

pub(super) fn actual_page_retained_bound(
    entries: &[ConversationEntry],
    payload_capacity: usize,
    cursor_bytes: usize,
) -> Result<usize, CatalogSnapshotProviderError> {
    let dto_and_peak = page_memory_bound(entries, cursor_bytes)?;
    // page_memory_bound 已含构造期临时 JSON；返回后只保留 DTO + canonical payload。
    // 保守保留不大于构造峰值的 charge，避免在 writer flush 前提前归还额度。
    dto_and_peak
        .max(
            payload_capacity
                .checked_add(4096)
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?,
        )
        .checked_add(0)
        .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)
}
