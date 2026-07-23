use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::identity::CatalogPageCursor;
use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::{ConversationEntry, StreamCursor};

use super::*;
use crate::runtime::backfill::{BarrierDecision, BarrierRequest};
use crate::runtime::connection::PrincipalIssuer;
use crate::runtime::events::{RegisterStreamBarrier, WatchGeneration};
use crate::runtime::model::{
    ConversationDescriptor, NewConversation, RuntimeCapacityObservation, RuntimeCapacityProbe,
    RuntimeCapacityProbeError, RuntimeClockError, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreOperation,
};
use crate::runtime::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES;
use crate::runtime::store::{RuntimeId, RuntimeIdKind, RuntimeStoreHandle};
use crate::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct GenerousCapacity;

impl RuntimeCapacityProbe for GenerousCapacity {
    fn observe(
        &self,
        database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        let bytes = |path: &Path| fs::metadata(path).map_or(0, |metadata| metadata.len());
        Ok(RuntimeCapacityObservation {
            main_bytes: bytes(database),
            wal_bytes: bytes(&PathBuf::from(format!("{}-wal", database.display()))),
            shm_bytes: bytes(&PathBuf::from(format!("{}-shm", database.display()))),
            filesystem_total_bytes: 1024 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 1024 * 1024 * 1024 * 1024,
        })
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-catalog-snapshot-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create catalog snapshot test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure catalog snapshot test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("catalog snapshot StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
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

#[derive(Default)]
struct BlockingCatalogRefreshFault {
    state: Mutex<BlockingCatalogRefreshState>,
    changed: Condvar,
}

#[derive(Default)]
struct BlockingCatalogRefreshState {
    reached: bool,
    released: bool,
}

impl BlockingCatalogRefreshFault {
    fn wait_until_reached(&self) {
        let mut state = self.state.lock().expect("lock catalog refresh fault");
        while !state.reached {
            state = self
                .changed
                .wait(state)
                .expect("wait for catalog refresh fault");
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("lock catalog refresh release");
        state.released = true;
        self.changed.notify_all();
    }
}

impl RuntimeStoreFaultInjector for BlockingCatalogRefreshFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation != RuntimeStoreOperation::StoreSnapshotBeforeCommit {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeStoreError::InvalidConfig("catalog refresh fault poisoned"))?;
        state.reached = true;
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .map_err(|_| RuntimeStoreError::InvalidConfig("catalog refresh wait poisoned"))?;
        }
        Err(RuntimeStoreError::InvalidConfig(
            "injected blocked catalog refresh",
        ))
    }
}

fn principal(seed: u8) -> AuthenticatedPrincipal {
    PrincipalIssuer::local_only([0xA5; 32])
        .issue_verified_local(501, [seed; 16])
        .expect("issue verified local principal")
}

#[test]
fn remote_cursor_binding_changes_with_grant_serial() {
    let issuer = PrincipalIssuer::local_only([0xA5; 32]);
    let old = issuer
        .issue_test_remote([0x11; 16], [0x22; 16], 7, [0x33; 32])
        .expect("issue old remote grant");
    let renewed = issuer
        .issue_test_remote([0x11; 16], [0x22; 16], 8, [0x33; 32])
        .expect("issue renewed remote grant");
    assert_ne!(principal_binding(&old), principal_binding(&renewed));
}

fn runtime_id(kind: RuntimeIdKind, value: u128) -> RuntimeId {
    RuntimeId::from_bytes(kind, value.to_be_bytes()).expect("nonzero runtime id")
}

fn conversation(index: u16) -> NewConversation {
    let value = u128::from(index) + 1;
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, value),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, (1_u128 << 127) | value),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some(format!("catalog-{index:04}")),
            cwd: PathBuf::from("/tmp/catalog-snapshot"),
        },
    }
}

fn conversation_with_title_bytes(index: u16, title_bytes: usize) -> NewConversation {
    let mut value = conversation(index);
    value.descriptor.title = Some("x".repeat(title_bytes));
    value
}

fn provider(
    store: RuntimeStoreHandle,
    clock: ManualClock,
    key: [u8; 32],
) -> CatalogSnapshotProvider {
    CatalogSnapshotProvider::with_test_key(
        store,
        Arc::new(clock),
        key,
        Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES)),
    )
}

async fn open_store(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    clock: ManualClock,
) -> RuntimeStoreHandle {
    RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_conversation_capacity(1_024)
            .with_capacity_probe(GenerousCapacity)
            .with_clock(clock),
        root.storage_kek(keys),
    )
    .await
    .expect("open catalog snapshot store")
}

async fn create_rows(store: &RuntimeStoreHandle, first: u16, count: u16) {
    for index in first..first + count {
        store
            .create_conversation(conversation(index))
            .await
            .expect("create real catalog row");
    }
}

async fn register_catalog(
    store: &RuntimeStoreHandle,
    generation: u64,
) -> StreamBarrierRegistration {
    store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(generation).expect("nonzero watch generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register catalog snapshot barrier")
}

#[tokio::test]
async fn cancelled_catalog_refresh_keeps_shared_budget_until_store_command_finishes() {
    let root = TestRoot::new("cancelled-refresh-command-budget");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(9_000);
    let fault = Arc::new(BlockingCatalogRefreshFault::default());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_conversation_capacity(1_024)
            .with_clock(clock.clone())
            .with_fault_injector(fault.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open blocked catalog refresh store");
    create_rows(&store, 0, 1).await;
    let budget = Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES));
    let provider = CatalogSnapshotProvider::with_test_key(
        store.clone(),
        Arc::new(clock),
        [0x30; 32],
        budget.clone(),
    );
    let mut registration = register_catalog(&store, 1).await;
    let owner = principal(1);
    let provider_for_task = provider.clone();
    let task = tokio::spawn(async move {
        provider_for_task
            .first_page(&mut registration, &owner)
            .await
    });
    let waiter = fault.clone();
    tokio::task::spawn_blocking(move || waiter.wait_until_reached())
        .await
        .expect("join catalog refresh fault waiter");
    let available_while_blocked = budget.available_permits();
    assert!(
        available_while_blocked < SNAPSHOT_BUILD_MEMORY_BYTES,
        "blocked refresh must own part of the shared build budget"
    );

    task.abort();
    assert!(
        task.await
            .expect_err("cancelled refresh caller must stop")
            .is_cancelled()
    );
    assert_eq!(
        budget.available_permits(),
        available_while_blocked,
        "caller cancellation must not release the permit owned by the queued Store command"
    );

    fault.release();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while budget.available_permits() != SNAPSHOT_BUILD_MEMORY_BYTES {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Store command completion returns catalog build budget");
    store
        .shutdown()
        .await
        .expect("shutdown cancelled catalog refresh store");
}

#[tokio::test]
async fn fresh_empty_catalog_builds_and_reads_a_durable_page() {
    let root = TestRoot::new("fresh-empty");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let provider = provider(store.clone(), clock, [0x31; 32]);
    let mut registration = register_catalog(&store, 1).await;

    let page = provider
        .first_page(&mut registration, &principal(1))
        .await
        .expect("read fresh empty catalog snapshot");

    assert_eq!(
        page.snapshot().base_catalog_cursor,
        StreamCursor::BeforeFirst
    );
    assert!(page.snapshot().entries().is_empty());
    assert!(page.snapshot().current_page_cursor().is_none());
    assert!(page.snapshot().next_page_cursor().is_none());
    drop(page);
    let durable = register_catalog(&store, 2).await;
    assert_eq!(durable.ready_snapshot_base, Some(StreamCursor::BeforeFirst));
    drop(provider);
    store.shutdown().await.expect("shutdown fresh store");
}

#[tokio::test]
async fn existing_501_rows_page_exactly_and_cursor_is_bound_authenticated_and_expiring() {
    let root = TestRoot::new("existing-501");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(20_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    create_rows(&store, 0, 501).await;
    store.shutdown().await.expect("close preexisting store");

    let store = open_store(&root, &keys, clock.clone()).await;
    let provider = provider(store.clone(), clock.clone(), [0x42; 32]);
    let owner = principal(2);
    let mut registration = register_catalog(&store, 3).await;
    assert_eq!(registration.high_water, StreamCursor::At(500));
    assert!(matches!(
        registration.decision,
        BarrierDecision::Snapshot { .. }
    ));

    let first = provider
        .first_page(&mut registration, &owner)
        .await
        .expect("build exact frozen catalog snapshot");
    assert_eq!(first.snapshot().base_catalog_cursor, StreamCursor::At(500));
    assert_eq!(first.snapshot().entries().len(), 500);
    assert!(first.snapshot().current_page_cursor().is_none());
    let cursor = first
        .snapshot()
        .next_page_cursor()
        .cloned()
        .expect("501 rows require a second page");

    let mut tampered = cursor.as_str().as_bytes().to_vec();
    let last = tampered.last_mut().expect("nonempty opaque cursor");
    *last = if *last == b'0' { b'1' } else { b'0' };
    let tampered = CatalogPageCursor::new(String::from_utf8(tampered).expect("ASCII cursor"));
    let error = provider
        .page_for_cursor(&tampered, &owner)
        .await
        .expect_err("tampered cursor must fail");
    assert!(matches!(error, CatalogSnapshotProviderError::InvalidCursor));

    let error = provider
        .page_for_cursor(&cursor, &principal(3))
        .await
        .expect_err("cursor cannot cross principals");
    assert!(matches!(
        error,
        CatalogSnapshotProviderError::PrincipalMismatch
    ));

    clock.set(20_001);
    let second = provider
        .page_for_cursor(&cursor, &owner)
        .await
        .expect("read second frozen page");
    assert_eq!(second.snapshot().base_catalog_cursor, StreamCursor::At(500));
    assert_eq!(second.snapshot().entries().len(), 1);
    assert_eq!(second.snapshot().current_page_cursor(), Some(&cursor));
    assert!(second.snapshot().next_page_cursor().is_none());
    assert_ne!(
        first
            .snapshot()
            .entries()
            .last()
            .expect("first page tail")
            .conversation_id,
        second.snapshot().entries()[0].conversation_id
    );

    // 威胁场景：cursor 在拿到 operation gate 前读取时钟，排队期间越过绝对
    // expiry 后仍可能按陈旧时间放行，并让 decoded cache 多存活一段排队时间。
    // 先持有 gate，再用 biased select 确保 page future 至少 poll 到锁等待点；
    // exact expiry 必须以真正进入线性化 operation 时的时钟为准。
    clock.set(20_000 + CATALOG_PAGE_CURSOR_TTL_MS - 1);
    let operation = provider.operation_gate.lock().await;
    let mut queued = Box::pin(provider.page_for_cursor(&cursor, &owner));
    tokio::select! {
        biased;
        result = &mut queued => panic!("cursor page unexpectedly bypassed held gate: {result:?}"),
        () = tokio::task::yield_now() => {}
    }
    clock.set(20_000 + CATALOG_PAGE_CURSOR_TTL_MS);
    drop(operation);
    let error = queued
        .await
        .expect_err("queued cursor expires at the exact absolute deadline");
    assert!(matches!(error, CatalogSnapshotProviderError::CursorExpired));

    clock.set(20_001);
    let error = provider
        .page_for_cursor(&cursor, &owner)
        .await
        .expect_err("clock rollback cannot revive an expired cursor");
    assert!(matches!(
        error,
        CatalogSnapshotProviderError::ClockRegressed
    ));
    clock.set(20_001 + CATALOG_PAGE_CURSOR_TTL_MS);

    let durable = register_catalog(&store, 4).await;
    assert_eq!(durable.ready_snapshot_base, Some(StreamCursor::At(500)));
    create_rows(&store, 501, 1).await;
    let mut refreshed = register_catalog(&store, 5).await;
    assert_eq!(refreshed.high_water, StreamCursor::At(501));
    provider
        .first_page(&mut refreshed, &owner)
        .await
        .expect("refresh durable catalog snapshot for retention progress");
    let durable = register_catalog(&store, 6).await;
    assert_eq!(durable.ready_snapshot_base, Some(StreamCursor::At(501)));

    drop(provider);
    store.shutdown().await.expect("shutdown refreshed store");
    let reopened = open_store(&root, &keys, clock).await;
    let durable = register_catalog(&reopened, 7).await;
    assert_eq!(durable.ready_snapshot_base, Some(StreamCursor::At(501)));
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn catalog_cursor_keeps_exact_frozen_snapshot_across_concurrent_refresh() {
    let root = TestRoot::new("cursor-concurrent-refresh");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(25_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    create_rows(&store, 0, 501).await;
    let provider = provider(store.clone(), clock, [0x49; 32]);
    let owner = principal(9);

    let mut initial = register_catalog(&store, 10).await;
    let old_first = provider
        .first_page(&mut initial, &owner)
        .await
        .expect("build old frozen catalog page");
    assert_eq!(
        old_first.snapshot().base_catalog_cursor,
        StreamCursor::At(500)
    );
    let old_cursor = old_first
        .snapshot()
        .next_page_cursor()
        .cloned()
        .expect("501 rows freeze an old second-page cursor");
    drop(old_first);

    create_rows(&store, 501, 1).await;
    let mut refreshed = register_catalog(&store, 11).await;
    let refreshed_first = provider
        .first_page(&mut refreshed, &owner)
        .await
        .expect("small concurrent refresh must fit beside old cursor cache");
    assert_eq!(
        refreshed_first.snapshot().base_catalog_cursor,
        StreamCursor::At(501)
    );

    let mut same_cut = register_catalog(&store, 12).await;
    let repeated_first = provider
        .first_page(&mut same_cut, &owner)
        .await
        .expect("same durable cut reuses its frozen cache without a duplicate insertion");
    assert_eq!(
        repeated_first.snapshot().base_catalog_cursor,
        StreamCursor::At(501)
    );

    let old_second = provider
        .page_for_cursor(&old_cursor, &owner)
        .await
        .expect("old cursor still reads the exact frozen pre-refresh baseline");
    assert_eq!(
        old_second.snapshot().base_catalog_cursor,
        StreamCursor::At(500)
    );
    assert_eq!(old_second.snapshot().entries().len(), 1);
    assert_eq!(
        old_second.snapshot().entries()[0].conversation_id.as_str(),
        conversation(500).conversation_id.to_canonical_string()
    );

    drop(old_second);
    drop(repeated_first);
    drop(refreshed_first);
    provider.clear_cache().expect("clear frozen catalog caches");
    assert_eq!(provider.resource_usage_for_test().0, 0);
    store
        .shutdown()
        .await
        .expect("shutdown concurrent refresh store");
}

#[tokio::test]
async fn ephemeral_cursor_never_falls_back_to_same_id_durable_snapshot_after_cache_loss() {
    let root = TestRoot::new("ephemeral-cursor-no-durable-fallback");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(25_500);
    let store = open_store(&root, &keys, clock.clone()).await;
    create_rows(&store, 0, 501).await;
    let provider = provider(store.clone(), clock, [0x4E; 32]);
    let owner = principal(14);

    let mut registration = register_catalog(&store, 20).await;
    let durable_first = provider
        .first_page(&mut registration, &owner)
        .await
        .expect("persist a durable catalog row with a second page");
    drop(durable_first);
    let durable_reference = provider
        .memory
        .lock()
        .expect("catalog memory state")
        .catalogs
        .values()
        .next()
        .expect("durable first page installs a cache")
        .reference
        .snapshot
        .clone();
    provider.clear_cache().expect("clear durable decoded cache");

    let entries = (0..501_u16)
        .map(|index| {
            let input = conversation(index);
            ConversationEntry {
                conversation_id: ConversationId::new(input.conversation_id.to_canonical_string()),
                agent_kind: input.descriptor.agent_kind,
                title: input.descriptor.title,
                cwd: Some(input.descriptor.cwd),
                last_active_ms: 0,
                archived: false,
                entry_revision: 0,
            }
        })
        .collect::<Vec<_>>();
    let peak = catalog_materialization_peak_bound(
        durable_reference.logical_bytes,
        durable_reference.item_count,
    )
    .expect("ephemeral fixture fits shared catalog budget");
    let memory = CatalogMemoryLease::reserve(
        provider.memory.clone(),
        provider.global_memory.clone(),
        peak,
    )
    .expect("reserve ephemeral catalog build memory");
    let first = provider
        .build_owned_page(
            CatalogPageReference::ephemeral(durable_reference),
            entries,
            None,
            None,
            PageIssue {
                observed_now_ms: 25_500,
                issued_at_ms: 25_500,
                expires_at_ms: 25_500 + CATALOG_PAGE_CURSOR_TTL_MS,
                binding: principal_binding(&owner),
            },
            memory,
        )
        .expect("build transition-only ephemeral first page");
    let cursor = first
        .snapshot()
        .next_page_cursor()
        .cloned()
        .expect("501 ephemeral rows require a second page");
    drop(first);

    let second = provider
        .page_for_cursor(&cursor, &owner)
        .await
        .expect("ephemeral cursor may read its exact in-process cache");
    assert_eq!(second.snapshot().entries().len(), 1);
    drop(second);
    provider
        .clear_cache()
        .expect("simulate cache loss/restart boundary");
    let error = provider
        .page_for_cursor(&cursor, &owner)
        .await
        .expect_err("ephemeral cursor must not load the same-id durable snapshot");
    assert!(matches!(error, CatalogSnapshotProviderError::InvalidCursor));

    store
        .shutdown()
        .await
        .expect("shutdown ephemeral cursor store");
}

#[tokio::test]
async fn failed_cached_page_reservation_does_not_extend_or_orphan_cache_ttl() {
    let root = TestRoot::new("failed-cached-page-reservation-ttl");
    let keys = MemoryKeyStore::new();
    let initial_now_ms = 26_000;
    let clock = ManualClock::new(initial_now_ms);
    let store = open_store(&root, &keys, clock.clone()).await;
    create_rows(&store, 0, 501).await;
    let budget = Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES));
    let provider = CatalogSnapshotProvider::with_test_key(
        store.clone(),
        Arc::new(clock.clone()),
        [0x4B; 32],
        budget.clone(),
    );
    let owner = principal(11);

    let mut initial = register_catalog(&store, 12).await;
    let first = provider
        .first_page(&mut initial, &owner)
        .await
        .expect("first page creates a frozen cache for its second page");
    assert!(first.snapshot().next_page_cursor().is_some());
    drop(first);
    let cached_bytes = provider.resource_usage_for_test().0;
    assert!(
        cached_bytes > 0,
        "fixture must retain a frozen catalog cache"
    );
    let (snapshot_id, initial_expiry) = {
        let state = provider.memory.lock().expect("catalog memory state");
        let (snapshot_id, cached) = state
            .catalogs
            .iter()
            .next()
            .expect("fixture retains exactly one cache");
        (*snapshot_id, cached.expiry_token())
    };

    let remaining = budget.available_permits();
    let budget_blocker = budget
        .clone()
        .try_acquire_many_owned(u32::try_from(remaining).expect("remaining budget fits u32"))
        .expect("test owns every permit not retained by the cache");
    clock.set(initial_now_ms + 1);
    let mut same_cut = register_catalog(&store, 13).await;
    let error = provider
        .first_page(&mut same_cut, &owner)
        .await
        .expect_err("cached page cannot reserve its page-build memory");
    assert!(matches!(
        error,
        CatalogSnapshotProviderError::MemoryBudgetExceeded
    ));

    let expiry_after_failure = provider
        .memory
        .lock()
        .expect("catalog memory state")
        .catalogs
        .get(&snapshot_id)
        .expect("failed page build must leave the original cache intact")
        .expiry_token();
    assert_eq!(
        expiry_after_failure, initial_expiry,
        "failed page reservation must not mutate expiry or its timer version"
    );
    provider
        .memory
        .lock()
        .expect("catalog memory state")
        .expire_exact(snapshot_id, initial_expiry);
    assert_eq!(
        provider.resource_usage_for_test().0,
        0,
        "failed page reservation must not extend the cache beyond its old timer deadline"
    );

    drop(budget_blocker);
    assert_eq!(budget.available_permits(), SNAPSHOT_BUILD_MEMORY_BYTES);
    store
        .shutdown()
        .await
        .expect("shutdown failed cached-page reservation store");
}

#[tokio::test]
async fn successful_cached_page_touch_makes_the_old_expiry_timer_stale() {
    let root = TestRoot::new("successful-cache-touch-stale-timer");
    let keys = MemoryKeyStore::new();
    let initial_now_ms = 27_000;
    let clock = ManualClock::new(initial_now_ms);
    let store = open_store(&root, &keys, clock.clone()).await;
    create_rows(&store, 0, 501).await;
    let provider = provider(store.clone(), clock.clone(), [0x4C; 32]);
    let owner = principal(12);

    let mut initial = register_catalog(&store, 14).await;
    let first = provider
        .first_page(&mut initial, &owner)
        .await
        .expect("first page creates a frozen cache");
    drop(first);
    let (snapshot_id, reference, initial_expiry) = {
        let state = provider.memory.lock().expect("catalog memory state");
        let (snapshot_id, cached) = state
            .catalogs
            .iter()
            .next()
            .expect("fixture retains exactly one cache");
        (
            *snapshot_id,
            cached.reference.clone(),
            cached.expiry_token(),
        )
    };

    clock.set(initial_now_ms + 1);
    let mut same_cut = register_catalog(&store, 15).await;
    let repeated = provider
        .first_page(&mut same_cut, &owner)
        .await
        .expect("successful cached page extends its frozen cache");
    drop(repeated);
    let extended_expiry = provider
        .memory
        .lock()
        .expect("catalog memory state")
        .catalogs
        .get(&snapshot_id)
        .filter(|cached| cached.matches(&reference))
        .expect("same exact frozen cache remains installed")
        .expiry_token();
    assert_eq!(
        extended_expiry.expires_at_ms,
        initial_expiry.expires_at_ms + 1
    );
    assert_eq!(extended_expiry.version, initial_expiry.version + 1);

    {
        let mut state = provider.memory.lock().expect("catalog memory state");
        state.expire_exact(snapshot_id, initial_expiry);
        assert!(
            state.catalogs.contains_key(&snapshot_id),
            "old timer/version must not evict a successfully extended cache"
        );
        state.expire_exact(snapshot_id, extended_expiry);
    }
    assert_eq!(provider.resource_usage_for_test().0, 0);
    store
        .shutdown()
        .await
        .expect("shutdown successful cache-touch store");
}

#[tokio::test]
async fn repeated_cursor_and_time_extension_keep_one_replaceable_expiry_task_per_cache() {
    // 威胁场景：已认证客户端在 5 分钟 TTL 内反复读取同一 cursor 或刷新同一
    // durable cut；若每次都遗留一个 sleeper，单个小 cache 也能制造无界 task DoS。
    let root = TestRoot::new("bounded-replaceable-expiry-task");
    let keys = MemoryKeyStore::new();
    let initial_now_ms = 28_000;
    let clock = ManualClock::new(initial_now_ms);
    let store = open_store(&root, &keys, clock.clone()).await;
    create_rows(&store, 0, 501).await;
    let provider = provider(store.clone(), clock.clone(), [0x4D; 32]);
    let owner = principal(13);

    let mut initial = register_catalog(&store, 16).await;
    let first = provider
        .first_page(&mut initial, &owner)
        .await
        .expect("first page creates one frozen cache and one expiry task");
    let cursor = first
        .snapshot()
        .next_page_cursor()
        .cloned()
        .expect("501 rows require a second-page cursor");
    drop(first);
    tokio::task::yield_now().await;
    assert_eq!(provider.expiry_task_metrics_for_test(), (1, 1));

    for _ in 0..32 {
        let page = provider
            .page_for_cursor(&cursor, &owner)
            .await
            .expect("repeated exact cursor remains valid before its absolute expiry");
        drop(page);
        tokio::task::yield_now().await;
        assert_eq!(
            provider.expiry_task_metrics_for_test(),
            (1, 1),
            "replacing an equal-version timer must abort the previous sleeper"
        );
    }

    for offset in 1..=32_u64 {
        clock.set(initial_now_ms + offset);
        let mut same_cut = register_catalog(&store, 16 + offset).await;
        let page = provider
            .first_page(&mut same_cut, &owner)
            .await
            .expect("same durable cut extends the cache at advancing wall time");
        drop(page);
        tokio::task::yield_now().await;
        assert_eq!(
            provider.expiry_task_metrics_for_test(),
            (1, 1),
            "new expiry versions must replace rather than accumulate sleepers"
        );
    }

    clock.set(initial_now_ms + 32 + CATALOG_PAGE_CURSOR_TTL_MS);
    provider
        .purge_expired(initial_now_ms + 32 + CATALOG_PAGE_CURSOR_TTL_MS)
        .expect("exact wall-clock expiry purges cache and its task owner");
    tokio::task::yield_now().await;
    assert_eq!(provider.expiry_task_metrics_for_test(), (0, 0));
    assert_eq!(provider.resource_usage_for_test().0, 0);

    let mut rebuilt = register_catalog(&store, 100).await;
    let page = provider
        .first_page(&mut rebuilt, &owner)
        .await
        .expect("same durable cut can rebuild one managed cache after expiry");
    drop(page);
    tokio::task::yield_now().await;
    assert_eq!(provider.expiry_task_metrics_for_test(), (1, 1));
    provider
        .clear_cache()
        .expect("clear cache aborts every managed expiry task");
    tokio::task::yield_now().await;
    assert_eq!(provider.expiry_task_metrics_for_test(), (0, 0));
    assert_eq!(provider.resource_usage_for_test().0, 0);

    clock.set(initial_now_ms + 33 + CATALOG_PAGE_CURSOR_TTL_MS);
    let mut final_cache = register_catalog(&store, 101).await;
    let page = provider
        .first_page(&mut final_cache, &owner)
        .await
        .expect("provider drop fixture installs one final managed task");
    drop(page);
    tokio::task::yield_now().await;
    assert_eq!(provider.expiry_task_metrics_for_test(), (1, 1));
    let expiry_owner = Arc::downgrade(&provider.expiry_tasks);
    drop(provider);
    tokio::task::yield_now().await;
    assert!(
        expiry_owner.upgrade().is_none(),
        "last provider drop must abort tasks without a scheduler retain cycle"
    );

    store
        .shutdown()
        .await
        .expect("shutdown bounded expiry task store");
}

#[tokio::test]
async fn large_old_cursor_cache_overloads_new_refresh_before_materialization() {
    const LARGE_TITLE_BYTES: usize = 800 * 1024;
    const LARGE_ROWS: u16 = 60;

    let root = TestRoot::new("large-old-cache-overload");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(27_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    create_rows(&store, 0, 500).await;
    for index in 500..500 + LARGE_ROWS {
        store
            .create_conversation(conversation_with_title_bytes(index, LARGE_TITLE_BYTES))
            .await
            .expect("create real large catalog row");
    }
    let budget = Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES));
    let provider = CatalogSnapshotProvider::with_test_key(
        store.clone(),
        Arc::new(clock),
        [0x4A; 32],
        budget.clone(),
    );
    let owner = principal(10);
    let mut initial = register_catalog(&store, 12).await;
    let first = provider
        .first_page(&mut initial, &owner)
        .await
        .expect("large baseline itself remains below the shared build cap");
    assert!(first.snapshot().next_page_cursor().is_some());
    drop(first);
    let cached_bytes = provider.resource_usage_for_test().0;
    assert!(
        cached_bytes > 40 * 1024 * 1024,
        "fixture must retain a genuinely large old decoded cache, got {cached_bytes} bytes"
    );

    create_rows(&store, 500 + LARGE_ROWS, 1).await;
    let mut refreshed = register_catalog(&store, 13).await;
    let error = provider
        .first_page(&mut refreshed, &owner)
        .await
        .expect_err("old cache plus a second large materialization must exceed 128 MiB");
    assert!(matches!(
        error,
        CatalogSnapshotProviderError::MemoryBudgetExceeded
    ));
    assert_eq!(
        provider.resource_usage_for_test().0,
        cached_bytes,
        "typed overload must not materialize or leak a second catalog"
    );
    assert_eq!(
        budget.available_permits(),
        SNAPSHOT_BUILD_MEMORY_BYTES - cached_bytes
    );

    drop(refreshed);
    provider.clear_cache().expect("release large old cache");
    assert_eq!(budget.available_permits(), SNAPSHOT_BUILD_MEMORY_BYTES);
    store
        .shutdown()
        .await
        .expect("shutdown large cache overload store");
}

#[tokio::test]
async fn failed_exact_load_releases_decoded_memory_reservation() {
    let root = TestRoot::new("failed-load-memory-raii");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(30_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let provider = provider(store.clone(), clock, [0x53; 32]);
    let missing = ReadySnapshotReference {
        snapshot_id: [0x61; 16],
        target: RuntimeStreamTarget::Catalog,
        base: StreamCursor::BeforeFirst,
        item_count: 0,
        logical_bytes: 128,
        content_sha256: [0x62; 32],
    };

    provider
        .page_from_page_reference(
            CatalogPageReference::durable(missing),
            None,
            None,
            PageIssue {
                observed_now_ms: 30_000,
                issued_at_ms: 30_000,
                expires_at_ms: 330_000,
                binding: principal_binding(&principal(4)),
            },
        )
        .await
        .expect_err("missing exact row must fail after reserving decoded memory");
    assert_eq!(
        provider.resource_usage_for_test(),
        (0, ONE_SHOT_CATALOG_BARRIERS),
        "failure path leaked active memory or one-shot quota"
    );

    store.shutdown().await.expect("shutdown failed-load store");
}
