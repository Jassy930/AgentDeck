//! Catalog snapshot 的 durable refresh、authenticated opaque cursor 与 500-row 分页。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_protocol::runtime::catalog::{CatalogError, CatalogSnapshot};
use agentdeck_protocol::runtime::command::CatalogRequest;
use agentdeck_protocol::runtime::identity::CatalogPageCursor;
use agentdeck_protocol::runtime::{ConversationEntry, StreamCursor};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

use super::connection::{AuthenticatedPrincipal, PrincipalAccessError};
use super::events::{
    CatalogSnapshotMaterializationMode, RegisterStreamBarrier, RuntimeStreamTarget,
    StreamBarrierRegistration, WatchGeneration,
};
use super::model::{RuntimeClock, RuntimeClockError, SystemRuntimeClock};
use super::store::{
    ReadySnapshotReference, RuntimeStoreError, RuntimeStoreHandle,
    catalog_materialization_peak_bound,
};

use self::cache::{
    CachedCatalog, CatalogCacheExpiry, CatalogMemoryLease, CatalogMemoryState,
    cache_retained_bound, page_memory_bound,
};
use self::cursor::{CursorMacKey, decode_cursor, principal_binding};
use self::expiry::CatalogExpiryTasks;
use self::page::{construct_page, page_range, validate_stored};

mod cache;
mod cursor;
mod expiry;
mod page;

pub(crate) const ONE_SHOT_CATALOG_BARRIERS: usize = 128;
pub const CATALOG_PAGE_CURSOR_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum CatalogPageSourceKind {
    Durable,
    Ephemeral,
}

impl CatalogPageSourceKind {
    const fn wire(self) -> u8 {
        match self {
            Self::Durable => 0,
            Self::Ephemeral => 1,
        }
    }

    fn from_wire(value: u8) -> Result<Self, CatalogSnapshotProviderError> {
        match value {
            0 => Ok(Self::Durable),
            1 => Ok(Self::Ephemeral),
            _ => Err(CatalogSnapshotProviderError::InvalidCursor),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct CatalogCacheKey {
    pub(super) kind: CatalogPageSourceKind,
    pub(super) snapshot_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CatalogPageReference {
    pub(super) kind: CatalogPageSourceKind,
    pub(super) snapshot: ReadySnapshotReference,
}

impl CatalogPageReference {
    fn durable(snapshot: ReadySnapshotReference) -> Self {
        Self {
            kind: CatalogPageSourceKind::Durable,
            snapshot,
        }
    }

    fn ephemeral(snapshot: ReadySnapshotReference) -> Self {
        Self {
            kind: CatalogPageSourceKind::Ephemeral,
            snapshot,
        }
    }

    fn cache_key(&self) -> CatalogCacheKey {
        CatalogCacheKey {
            kind: self.kind,
            snapshot_id: self.snapshot.snapshot_id,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CatalogSnapshotProvider {
    store: RuntimeStoreHandle,
    clock: Arc<dyn RuntimeClock>,
    cursor_key: Arc<CursorMacKey>,
    operation_gate: Arc<AsyncMutex<()>>,
    memory: Arc<Mutex<CatalogMemoryState>>,
    expiry_tasks: Arc<CatalogExpiryTasks>,
    global_memory: Arc<Semaphore>,
    one_shot_slots: Arc<Semaphore>,
    next_one_shot_generation: Arc<AtomicU64>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CatalogSnapshotProviderError {
    #[error("catalog cursor entropy is unavailable")]
    EntropyUnavailable,
    #[error("catalog snapshot registration target is invalid")]
    InvalidRegistration,
    #[error("catalog snapshot registration has no exact durable source")]
    MissingSnapshotSource,
    #[error("catalog page cursor is malformed or unauthenticated")]
    InvalidCursor,
    #[error("catalog page cursor belongs to another authenticated principal")]
    PrincipalMismatch,
    #[error("catalog page cursor expired")]
    CursorExpired,
    #[error("catalog page cursor was observed before its issue time")]
    ClockRegressed,
    #[error("catalog decoded snapshot/page exceeds the 128 MiB global budget")]
    MemoryBudgetExceeded,
    #[error("catalog memory accounting state is poisoned")]
    MemoryStatePoisoned,
    #[error("catalog one-shot barrier quota is exhausted")]
    OneShotQuotaExhausted,
    #[error("catalog one-shot watch generation is exhausted")]
    GenerationExhausted,
    #[error(transparent)]
    Principal(#[from] PrincipalAccessError),
    #[error(transparent)]
    Clock(#[from] RuntimeClockError),
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error(transparent)]
    Protocol(#[from] CatalogError),
}

pub(crate) struct CatalogSnapshotPage {
    snapshot: CatalogSnapshot,
    payload: Vec<u8>,
    _memory: CatalogMemoryLease,
    _one_shot: Option<CatalogOneShotPermit>,
}

/// 在创建一次性 catalog barrier 前取得的全局许可。许可从 page build 开始一直
/// 留在最终 `CatalogSnapshotPage` 中，只有真实 transport flush 完成或 job 被取消
/// 后才会释放；subscription 自己的内部分页不构造此 capability。
pub(crate) struct CatalogOneShotPermit {
    _permit: OwnedSemaphorePermit,
}

impl std::fmt::Debug for CatalogSnapshotPage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CatalogSnapshotPage")
            .field("snapshot", &self.snapshot)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl CatalogSnapshotPage {
    pub(crate) fn snapshot(&self) -> &CatalogSnapshot {
        &self.snapshot
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Copy)]
struct PageIssue {
    observed_now_ms: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    binding: [u8; 32],
}

impl CatalogSnapshotProvider {
    pub(crate) fn new(
        store: RuntimeStoreHandle,
        global_memory: Arc<Semaphore>,
    ) -> Result<Self, CatalogSnapshotProviderError> {
        Self::with_clock(store, Arc::new(SystemRuntimeClock), global_memory)
    }

    pub(crate) fn with_clock(
        store: RuntimeStoreHandle,
        clock: Arc<dyn RuntimeClock>,
        global_memory: Arc<Semaphore>,
    ) -> Result<Self, CatalogSnapshotProviderError> {
        Ok(Self {
            store,
            clock,
            cursor_key: Arc::new(CursorMacKey::random()?),
            operation_gate: Arc::new(AsyncMutex::new(())),
            memory: Arc::new(Mutex::new(CatalogMemoryState::default())),
            expiry_tasks: Arc::new(CatalogExpiryTasks::new()),
            global_memory,
            one_shot_slots: Arc::new(Semaphore::new(ONE_SHOT_CATALOG_BARRIERS)),
            next_one_shot_generation: Arc::new(AtomicU64::new(1)),
        })
    }

    #[cfg(test)]
    fn with_test_key(
        store: RuntimeStoreHandle,
        clock: Arc<dyn RuntimeClock>,
        key: [u8; 32],
        global_memory: Arc<Semaphore>,
    ) -> Self {
        Self {
            store,
            clock,
            cursor_key: Arc::new(CursorMacKey::for_test(key)),
            operation_gate: Arc::new(AsyncMutex::new(())),
            memory: Arc::new(Mutex::new(CatalogMemoryState::default())),
            expiry_tasks: Arc::new(CatalogExpiryTasks::new()),
            global_memory,
            one_shot_slots: Arc::new(Semaphore::new(ONE_SHOT_CATALOG_BARRIERS)),
            next_one_shot_generation: Arc::new(AtomicU64::new(1)),
        }
    }

    /// 消费 registration 的 exact snapshot source，在其冻结 H 上持久化 catalog
    /// baseline，并返回第一页。SQLite transaction 在本 future 返回前已经结束。
    pub(crate) async fn first_page(
        &self,
        registration: &mut StreamBarrierRegistration,
        principal: &AuthenticatedPrincipal,
    ) -> Result<CatalogSnapshotPage, CatalogSnapshotProviderError> {
        let _authorization = principal.try_enter()?;
        if registration.target != RuntimeStreamTarget::Catalog {
            return Err(CatalogSnapshotProviderError::InvalidRegistration);
        }
        let source = registration
            .take_catalog_snapshot_source()
            .ok_or(CatalogSnapshotProviderError::MissingSnapshotSource)?;
        let (mode, source, frozen) = source.into_parts();
        if frozen != registration.high_water
            || source
                .as_ref()
                .is_some_and(|reference| reference.target != RuntimeStreamTarget::Catalog)
        {
            return Err(CatalogSnapshotProviderError::InvalidRegistration);
        }
        let _operation = self.operation_gate.lock().await;
        let now_ms = self.clock.now_ms()?;
        self.purge_expired(now_ms)?;
        let expires_at_ms = now_ms
            .checked_add(CATALOG_PAGE_CURSOR_TTL_MS)
            .ok_or(CatalogSnapshotProviderError::InvalidCursor)?;
        let binding = principal_binding(principal);
        let issue = PageIssue {
            observed_now_ms: now_ms,
            issued_at_ms: now_ms,
            expires_at_ms,
            binding,
        };
        if mode == CatalogSnapshotMaterializationMode::TransitionEphemeral {
            // Transition H 绝不能调用 durable refresh：D > H 时只认证 D identity，
            // 从 retained delta 只读重建 ephemeral H；cache miss/restart 不得回退 D。
            let preflight = self
                .store
                .preflight_transition_catalog_snapshot(source, frozen)
                .await?;
            let memory = CatalogMemoryLease::reserve(
                self.memory.clone(),
                self.global_memory.clone(),
                preflight.peak_retained_bytes,
            )?;
            let mut ephemeral_id = [0_u8; 16];
            getrandom::fill(&mut ephemeral_id)
                .map_err(|_| CatalogSnapshotProviderError::EntropyUnavailable)?;
            if ephemeral_id == [0; 16] {
                return Err(CatalogSnapshotProviderError::EntropyUnavailable);
            }
            let materialized = self
                .store
                .materialize_transition_catalog_snapshot(
                    preflight,
                    ephemeral_id,
                    memory.shared_permit()?,
                )
                .await?;
            if materialized.reference.base != frozen
                || materialized.reference.target != RuntimeStreamTarget::Catalog
            {
                return Err(CatalogSnapshotProviderError::InvalidRegistration);
            }
            return self.build_owned_page(
                CatalogPageReference::ephemeral(materialized.reference),
                materialized.entries,
                None,
                None,
                issue,
                memory,
            );
        }

        // Generic path 仍只接受 D <= H，并可在 exact H 持久 refresh。该 reservation
        // 贯穿 refresh、exact load、page/cache transition 与 transport flush。
        let refresh = self
            .store
            .preflight_catalog_snapshot_refresh(source.clone(), frozen)
            .await?;
        if !refresh.refresh_required {
            let reference = source.ok_or(CatalogSnapshotProviderError::MissingSnapshotSource)?;
            let page_reference = CatalogPageReference::durable(reference.clone());
            if let Some(cache_version) = self.cached_matches(&page_reference)? {
                return self.build_cached_page(&page_reference, cache_version, None, None, issue);
            }
            let memory = CatalogMemoryLease::reserve(
                self.memory.clone(),
                self.global_memory.clone(),
                refresh.peak_retained_bytes,
            )?;
            return self
                .page_from_reference_with_memory(reference, None, None, issue, memory)
                .await;
        }
        let memory = CatalogMemoryLease::reserve(
            self.memory.clone(),
            self.global_memory.clone(),
            refresh.peak_retained_bytes,
        )?;
        let reference = self
            .store
            .refresh_catalog_snapshot(source, frozen, memory.shared_permit()?)
            .await?;
        self.page_from_reference_with_memory(reference, None, None, issue, memory)
            .await
    }

    /// fresh first-member pairing 在冻结 Catalog genesis cut 前，只需要把当前 exact H
    /// 持久化成 authenticated durable baseline，不需要签发页面 cursor 或向任何 principal
    /// 暴露内容。该内部刷新与普通 Catalog page 共用同一个 operation gate、Store barrier
    /// 和全局 128 MiB build budget，不能另建一套不计费的 snapshot 路径。
    pub(crate) async fn refresh_current_durable_baseline(
        &self,
    ) -> Result<ReadySnapshotReference, CatalogSnapshotProviderError> {
        let generation = self
            .next_one_shot_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CatalogSnapshotProviderError::GenerationExhausted)?;
        let mut registration = self
            .store
            .register_stream_barrier(RegisterStreamBarrier {
                target: RuntimeStreamTarget::Catalog,
                generation: WatchGeneration::new(generation)
                    .ok_or(CatalogSnapshotProviderError::GenerationExhausted)?,
                request: super::backfill::BarrierRequest::Subscribe {
                    cursor: StreamCursor::BeforeFirst,
                },
            })
            .await?;
        let source = registration
            .take_catalog_snapshot_source()
            .ok_or(CatalogSnapshotProviderError::MissingSnapshotSource)?;
        let (mode, source, frozen) = source.into_parts();
        if mode != CatalogSnapshotMaterializationMode::DurableRefresh
            || registration.target != RuntimeStreamTarget::Catalog
            || frozen != registration.high_water
            || source
                .as_ref()
                .is_some_and(|reference| reference.target != RuntimeStreamTarget::Catalog)
        {
            return Err(CatalogSnapshotProviderError::InvalidRegistration);
        }

        let _operation = self.operation_gate.lock().await;
        let refresh = self
            .store
            .preflight_catalog_snapshot_refresh(source.clone(), frozen)
            .await?;
        let reference = if refresh.refresh_required {
            let memory = CatalogMemoryLease::reserve(
                self.memory.clone(),
                self.global_memory.clone(),
                refresh.peak_retained_bytes,
            )?;
            self.store
                .refresh_catalog_snapshot(source, frozen, memory.shared_permit()?)
                .await?
        } else {
            source.ok_or(CatalogSnapshotProviderError::MissingSnapshotSource)?
        };
        if reference.target != RuntimeStreamTarget::Catalog || reference.base != frozen {
            return Err(CatalogSnapshotProviderError::InvalidRegistration);
        }
        Ok(reference)
    }

    /// 在建 barrier/watch/task 前同步预留全局 one-shot quota。调用方必须先同时
    /// 预留 per-connection quota；失败路径不会产生 store side effect。
    pub(crate) fn reserve_one_shot(
        &self,
    ) -> Result<CatalogOneShotPermit, CatalogSnapshotProviderError> {
        let permit = self
            .one_shot_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CatalogSnapshotProviderError::OneShotQuotaExhausted)?;
        Ok(CatalogOneShotPermit { _permit: permit })
    }

    /// 已预留 quota 的一次性请求。`pageCursor = null` 才建立 fresh barrier；非空
    /// cursor 读取首次签发时的 exact baseline。许可覆盖整个 build 并被移入 page，
    /// 因而异步 egress 等待 FlushReceipt 时仍不会被并发请求复用。
    pub(crate) async fn prepare_page_for_request(
        &self,
        request: &CatalogRequest,
        principal: &AuthenticatedPrincipal,
        one_shot: CatalogOneShotPermit,
    ) -> Result<CatalogSnapshotPage, CatalogSnapshotProviderError> {
        let _authorization = principal.try_enter()?;
        let mut page = if let Some(cursor) = request.page_cursor.as_ref() {
            self.page_for_cursor(cursor, principal).await?
        } else {
            self.fresh_one_shot_page(principal).await?
        };
        page._one_shot = Some(one_shot);
        Ok(page)
    }

    /// Subscription snapshot 内部翻页已经由 subscription barrier/job 预算覆盖，
    /// 不能再次占用 one-shot quota。
    pub(crate) async fn page_for_cursor(
        &self,
        cursor: &agentdeck_protocol::runtime::identity::CatalogPageCursor,
        principal: &AuthenticatedPrincipal,
    ) -> Result<CatalogSnapshotPage, CatalogSnapshotProviderError> {
        let _authorization = principal.try_enter()?;
        let binding = principal_binding(principal);
        let _operation = self.operation_gate.lock().await;
        let now_ms = self.clock.now_ms()?;
        // purge/monotonic clock observation 必须先于 cursor decode；否则 exact-expiry
        // 错误会绕过 purge，随后时钟回拨还能让同一 cursor 复活。
        self.purge_expired(now_ms)?;
        let claims = decode_cursor(&self.cursor_key, cursor, binding, now_ms)?;
        self.page_from_page_reference(
            claims.reference,
            Some(claims.next_key),
            Some(cursor.clone()),
            PageIssue {
                observed_now_ms: now_ms,
                issued_at_ms: claims.issued_at_ms,
                expires_at_ms: claims.expires_at_ms,
                binding,
            },
        )
        .await
    }

    async fn fresh_one_shot_page(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<CatalogSnapshotPage, CatalogSnapshotProviderError> {
        let generation = self
            .next_one_shot_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CatalogSnapshotProviderError::GenerationExhausted)?;
        let mut registration = self
            .store
            .register_stream_barrier(RegisterStreamBarrier {
                target: RuntimeStreamTarget::Catalog,
                generation: WatchGeneration::new(generation)
                    .ok_or(CatalogSnapshotProviderError::GenerationExhausted)?,
                request: super::backfill::BarrierRequest::Subscribe {
                    cursor: StreamCursor::BeforeFirst,
                },
            })
            .await?;
        // registration 与未消费的 backfill pin 由本栈 RAII 回收；全局 one-shot
        // permit 由 prepare_page_for_request 持有并在返回后附着到 page。
        self.first_page(&mut registration, principal).await
    }

    async fn page_from_page_reference(
        &self,
        reference: CatalogPageReference,
        after: Option<String>,
        current_page_cursor: Option<CatalogPageCursor>,
        issue: PageIssue,
    ) -> Result<CatalogSnapshotPage, CatalogSnapshotProviderError> {
        if let Some(cache_version) = self.cached_matches(&reference)? {
            return self.build_cached_page(
                &reference,
                cache_version,
                after.as_deref(),
                current_page_cursor,
                issue,
            );
        }

        if reference.kind == CatalogPageSourceKind::Ephemeral {
            return Err(CatalogSnapshotProviderError::InvalidCursor);
        }

        let peak = catalog_materialization_peak_bound(
            reference.snapshot.logical_bytes,
            reference.snapshot.item_count,
        )
        .map_err(|_| CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        let memory =
            CatalogMemoryLease::reserve(self.memory.clone(), self.global_memory.clone(), peak)?;
        self.page_from_reference_with_memory(
            reference.snapshot,
            after,
            current_page_cursor,
            issue,
            memory,
        )
        .await
    }

    async fn page_from_reference_with_memory(
        &self,
        reference: ReadySnapshotReference,
        after: Option<String>,
        current_page_cursor: Option<CatalogPageCursor>,
        issue: PageIssue,
        mut memory: CatalogMemoryLease,
    ) -> Result<CatalogSnapshotPage, CatalogSnapshotProviderError> {
        let peak =
            catalog_materialization_peak_bound(reference.logical_bytes, reference.item_count)
                .map_err(|_| CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        memory.transition(peak, None)?;
        let mut stored = self
            .store
            .load_catalog_snapshot_by_reference(reference.clone())
            .await?;
        validate_stored(&stored, &reference)?;
        let baseline = crate::runtime::store::decode_catalog_baseline(&stored.payload)
            .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;
        if baseline.version != 1
            || baseline.base_catalog_cursor != reference.base
            || baseline.entries.len() as u64 != reference.item_count
        {
            return Err(CatalogSnapshotProviderError::InvalidCursor);
        }
        // read-pool raw lease 与 plaintext 在 decoded baseline 建成后立即释放；之后的
        // cache/page transition 只保留被 128 MiB provider budget 计费的对象。
        stored.memory_lease.take();
        drop(stored);
        let mut entries = baseline.entries;
        entries.sort_by(|left, right| {
            left.conversation_id
                .as_str()
                .cmp(right.conversation_id.as_str())
        });
        if entries
            .windows(2)
            .any(|pair| pair[0].conversation_id.as_str() == pair[1].conversation_id.as_str())
        {
            return Err(CatalogSnapshotProviderError::InvalidCursor);
        }
        self.build_owned_page(
            CatalogPageReference::durable(reference),
            entries,
            after.as_deref(),
            current_page_cursor,
            issue,
            memory,
        )
    }

    fn build_owned_page(
        &self,
        reference: CatalogPageReference,
        entries: Vec<ConversationEntry>,
        after: Option<&str>,
        current_page_cursor: Option<CatalogPageCursor>,
        issue: PageIssue,
        mut memory: CatalogMemoryLease,
    ) -> Result<CatalogSnapshotPage, CatalogSnapshotProviderError> {
        let (start, end) = page_range(&entries, after)?;
        let retained_bytes = cache_retained_bound(reference.snapshot.logical_bytes, &entries)?;
        let cursor_bound = current_page_cursor
            .as_ref()
            .map_or(0, |cursor| cursor.as_str().len())
            .checked_add(if end < entries.len() { 512 } else { 0 })
            .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        let page_build_bytes = page_memory_bound(&entries[start..end], cursor_bound)?;
        let build_peak = retained_bytes
            .checked_add(page_build_bytes)
            .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
        // raw plaintext 已释放；在 clone/constructor JSON 前把 reservation 切换为
        // “完整 decoded baseline + page DTO + constructor/payload JSON”的真实峰值。
        memory.transition(build_peak, None)?;
        let (snapshot, payload, page_bytes) = construct_page(
            &self.cursor_key,
            &reference,
            &entries[start..end],
            current_page_cursor,
            end < entries.len(),
            issue,
        )?;
        let cached = snapshot
            .next_page_cursor()
            .is_some()
            .then(|| {
                Ok::<_, CatalogSnapshotProviderError>(CachedCatalog {
                    reference,
                    entries,
                    expires_at_ms: issue.expires_at_ms,
                    expiry_version: 1,
                    retained_bytes,
                    memory_permit: None,
                })
            })
            .transpose()?;
        let cache_expiry = cached
            .as_ref()
            .map(|cached| (cached.reference.cache_key(), cached.expiry_token()));
        memory.transition(page_bytes, cached)?;
        if let Some((cache_key, expiry)) = cache_expiry {
            self.schedule_cache_expiry(cache_key, expiry, issue.observed_now_ms)?;
        }
        Ok(CatalogSnapshotPage {
            snapshot,
            payload,
            _memory: memory,
            _one_shot: None,
        })
    }

    fn build_cached_page(
        &self,
        reference: &CatalogPageReference,
        matched_version: u64,
        after: Option<&str>,
        current_page_cursor: Option<CatalogPageCursor>,
        issue: PageIssue,
    ) -> Result<CatalogSnapshotPage, CatalogSnapshotProviderError> {
        let (start, end, preallocation) = {
            let state = self
                .memory
                .lock()
                .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
            let cached = state
                .catalogs
                .get(&reference.cache_key())
                .filter(|cached| cached.matches(reference))
                .ok_or(CatalogSnapshotProviderError::InvalidCursor)?;
            let (start, end) = page_range(&cached.entries, after)?;
            let cursor_bytes = current_page_cursor
                .as_ref()
                .map_or(0, |cursor| cursor.as_str().len())
                .checked_add(if end < cached.entries.len() { 512 } else { 0 })
                .ok_or(CatalogSnapshotProviderError::MemoryBudgetExceeded)?;
            (
                start,
                end,
                page_memory_bound(&cached.entries[start..end], cursor_bytes)?,
            )
        };
        let mut memory = CatalogMemoryLease::reserve(
            self.memory.clone(),
            self.global_memory.clone(),
            preallocation,
        )?;
        let (snapshot, payload, page_bytes) = {
            let state = self
                .memory
                .lock()
                .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
            let cached = state
                .catalogs
                .get(&reference.cache_key())
                .filter(|cached| cached.matches(reference))
                .ok_or(CatalogSnapshotProviderError::InvalidCursor)?;
            construct_page(
                &self.cursor_key,
                reference,
                &cached.entries[start..end],
                current_page_cursor,
                end < cached.entries.len(),
                issue,
            )?
        };
        memory.transition(page_bytes, None)?;
        let expiry = self
            .memory
            .lock()
            .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?
            .touch_expiry(reference, matched_version, issue.expires_at_ms)?;
        self.schedule_cache_expiry(reference.cache_key(), expiry, issue.observed_now_ms)?;
        Ok(CatalogSnapshotPage {
            snapshot,
            payload,
            _memory: memory,
            _one_shot: None,
        })
    }

    fn cached_matches(
        &self,
        reference: &CatalogPageReference,
    ) -> Result<Option<u64>, CatalogSnapshotProviderError> {
        let state = self
            .memory
            .lock()
            .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?;
        let Some(cached) = state.catalogs.get(&reference.cache_key()) else {
            return Ok(None);
        };
        if !cached.matches(reference) {
            return Err(CatalogSnapshotProviderError::InvalidCursor);
        }
        Ok(Some(cached.expiry_version))
    }

    fn purge_expired(&self, now_ms: u64) -> Result<(), CatalogSnapshotProviderError> {
        let expired = self
            .memory
            .lock()
            .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?
            .observe_and_purge(now_ms)?;
        for cache_key in expired {
            self.expiry_tasks.cancel(cache_key)?;
        }
        Ok(())
    }

    fn schedule_cache_expiry(
        &self,
        cache_key: CatalogCacheKey,
        expiry: CatalogCacheExpiry,
        observed_now_ms: u64,
    ) -> Result<(), CatalogSnapshotProviderError> {
        self.expiry_tasks.replace(
            Arc::downgrade(&self.memory),
            cache_key,
            expiry,
            observed_now_ms,
        )
    }

    pub(crate) fn clear_cache(&self) -> Result<(), CatalogSnapshotProviderError> {
        self.expiry_tasks.clear()?;
        self.memory
            .lock()
            .map_err(|_| CatalogSnapshotProviderError::MemoryStatePoisoned)?
            .clear_cache();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn resource_usage_for_test(&self) -> (usize, usize) {
        let state = self.memory.lock().expect("catalog memory state");
        (state.used_bytes(), self.one_shot_slots.available_permits())
    }

    #[cfg(test)]
    fn expiry_task_metrics_for_test(&self) -> (usize, usize) {
        self.expiry_tasks.metrics()
    }

    #[cfg(test)]
    pub(crate) fn exhaust_one_shot_slots_for_test(&self) -> OwnedSemaphorePermit {
        self.one_shot_slots
            .clone()
            .try_acquire_many_owned(ONE_SHOT_CATALOG_BARRIERS as u32)
            .expect("test owns all one-shot catalog permits")
    }
}

#[cfg(test)]
mod tests;
