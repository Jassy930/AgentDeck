use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, ConversationConfiguration, ConversationMetadataMutation,
    RuntimeFailure, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentKind, ClaudeCodePermissionMode};
use rusqlite::Connection;
use tokio::sync::watch;

use super::*;
use crate::agent::{
    NativeProjectionAcknowledgement, NativeProjectionScan, NativeProjectionScanIssuer,
    NativeProjectionSource,
};
use crate::runtime::execution::DisabledExecutionCoordinator;
use crate::runtime::store::{
    ClaimNativeMetadataMutationOutcome, IdempotencyOwner, RuntimeId, RuntimeIdKind,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreOperation,
    UpdateManagedConversationMetadata,
};
use crate::security::{MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "agentdeck-native-projector-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create native projector test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure native projector test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct FakeGeneration {
    candidates: Vec<u8>,
    yield_after: Option<usize>,
    fail_after: Option<usize>,
    next_delay: Option<Duration>,
    incomplete_completion: bool,
}

impl FakeGeneration {
    fn candidate(marker: u8) -> Self {
        Self {
            candidates: vec![marker],
            yield_after: None,
            fail_after: None,
            next_delay: None,
            incomplete_completion: false,
        }
    }

    fn empty() -> Self {
        Self {
            candidates: Vec::new(),
            yield_after: None,
            fail_after: None,
            next_delay: None,
            incomplete_completion: false,
        }
    }

    fn partial() -> Self {
        Self {
            candidates: Vec::new(),
            yield_after: Some(0),
            fail_after: None,
            next_delay: None,
            incomplete_completion: false,
        }
    }
}

struct FakeSource {
    plans: StdMutex<VecDeque<FakeGeneration>>,
    begins: AtomicUsize,
    deliveries: Arc<AtomicUsize>,
    acknowledgements: Arc<AtomicUsize>,
    completions: Arc<AtomicUsize>,
    database: PathBuf,
}

#[derive(Debug)]
struct CountedStoreFault {
    target: RuntimeStoreOperation,
    remaining: AtomicUsize,
}

impl CountedStoreFault {
    fn new(target: RuntimeStoreOperation, count: usize) -> Self {
        Self {
            target,
            remaining: AtomicUsize::new(count),
        }
    }

    fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Acquire)
    }
}

impl RuntimeStoreFaultInjector for CountedStoreFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation != self.target {
            return Ok(());
        }
        let failed = self
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok();
        if failed {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

impl FakeSource {
    fn new(database: PathBuf, plans: impl IntoIterator<Item = FakeGeneration>) -> Self {
        Self {
            plans: StdMutex::new(plans.into_iter().collect()),
            begins: AtomicUsize::new(0),
            deliveries: Arc::new(AtomicUsize::new(0)),
            acknowledgements: Arc::new(AtomicUsize::new(0)),
            completions: Arc::new(AtomicUsize::new(0)),
            database,
        }
    }
}

impl NativeProjectionSource for FakeSource {
    fn agent_kind(&self) -> AgentKind {
        AgentKind::ClaudeCode
    }

    fn begin_native_projection_scan(
        &self,
        issuer: NativeProjectionScanIssuer,
    ) -> Result<DynNativeProjectionScan, NativeProjectionSourceError> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        let plan = self
            .plans
            .lock()
            .expect("fake source plan lock poisoned")
            .pop_front()
            .ok_or(NativeProjectionSourceError::Unavailable)?;
        Ok(Box::new(FakeScan {
            generation: issuer.generation(),
            issuer: Some(issuer),
            plan,
            next_index: 0,
            pending_token: None,
            paused: false,
            yielded: false,
            complete: false,
            source_acknowledgements: self.acknowledgements.clone(),
            source_deliveries: self.deliveries.clone(),
            source_completions: self.completions.clone(),
            database: self.database.clone(),
        }))
    }
}

struct FakeScan {
    generation: [u8; 16],
    issuer: Option<NativeProjectionScanIssuer>,
    plan: FakeGeneration,
    next_index: usize,
    pending_token: Option<[u8; 16]>,
    paused: bool,
    yielded: bool,
    complete: bool,
    source_acknowledgements: Arc<AtomicUsize>,
    source_deliveries: Arc<AtomicUsize>,
    source_completions: Arc<AtomicUsize>,
    database: PathBuf,
}

impl FakeScan {
    fn delivery(&mut self) -> Result<NativeProjectionStep, NativeProjectionSourceError> {
        self.source_deliveries.fetch_add(1, Ordering::SeqCst);
        let marker = self.plan.candidates[self.next_index];
        let token = self.pending_token.unwrap_or_else(|| {
            let token = [marker.max(1); 16];
            self.pending_token = Some(token);
            token
        });
        self.issuer
            .as_ref()
            .expect("fake issuer remains until completion")
            .issue_candidate(
                crate::runtime::store::ConversationDescriptor {
                    agent_kind: AgentKind::ClaudeCode,
                    title: Some(format!("native-{marker}")),
                    cwd: PathBuf::from(format!("/tmp/native-projector-{marker}")),
                },
                claude_configuration(),
                SecretBytes::new(vec![marker.max(1); 32]),
                token,
            )
            .map(Box::new)
            .map(NativeProjectionStep::Candidate)
    }
}

impl NativeProjectionScan for FakeScan {
    fn next(&mut self) -> Result<NativeProjectionStep, NativeProjectionSourceError> {
        if let Some(delay) = self.plan.next_delay.take() {
            std::thread::sleep(delay);
        }
        if self.paused {
            return Ok(NativeProjectionStep::Yielded(
                crate::agent::NativeProjectionYieldReason::Deadline,
            ));
        }
        if self.pending_token.is_some() {
            return self.delivery();
        }
        if !self.yielded && self.plan.yield_after == Some(self.next_index) {
            self.yielded = true;
            self.paused = true;
            return Ok(NativeProjectionStep::Yielded(
                crate::agent::NativeProjectionYieldReason::Deadline,
            ));
        }
        if self.plan.fail_after == Some(self.next_index) {
            return Err(NativeProjectionSourceError::ReadUnavailable);
        }
        if self.next_index == self.plan.candidates.len() {
            self.complete = true;
            return Ok(NativeProjectionStep::Complete);
        }
        self.delivery()
    }

    fn acknowledge(
        &mut self,
        acknowledgement: NativeProjectionAcknowledgement,
    ) -> Result<(), NativeProjectionSourceError> {
        let token = self
            .pending_token
            .take()
            .ok_or(NativeProjectionSourceError::InvalidAcknowledgement)?;
        if !self
            .issuer
            .as_ref()
            .expect("fake issuer remains until completion")
            .matches_acknowledgement(&acknowledgement, &token)
        {
            self.pending_token = Some(token);
            return Err(NativeProjectionSourceError::InvalidAcknowledgement);
        }
        let projection_rows: i64 = Connection::open(&self.database)
            .expect("open Store before fake ACK")
            .query_row("SELECT COUNT(*) FROM native_projection_state", [], |row| {
                row.get(0)
            })
            .expect("read Store before fake ACK");
        assert!(projection_rows > 0, "Store import must converge before ACK");
        self.next_index += 1;
        self.source_acknowledgements.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn resume_after_yield(&mut self) -> Result<(), NativeProjectionSourceError> {
        if !self.paused {
            return Err(NativeProjectionSourceError::InvalidState);
        }
        self.paused = false;
        Ok(())
    }

    fn into_completed(
        mut self: Box<Self>,
    ) -> Result<CompletedNativeProjectionScan, NativeProjectionSourceError> {
        if !self.complete || self.pending_token.is_some() || self.paused {
            return Err(NativeProjectionSourceError::ScanIncomplete);
        }
        if self.plan.incomplete_completion {
            return Err(NativeProjectionSourceError::ScanIncomplete);
        }
        self.source_completions.fetch_add(1, Ordering::SeqCst);
        self.issuer.take().expect("fake completed issuer").complete(
            self.generation,
            self.next_index as u64,
            self.next_index as u64,
        )
    }
}

fn claude_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .expect("valid fake Claude configuration"),
    ))
}

struct Harness {
    _root: TestRoot,
    store: RuntimeStoreHandle,
    router: Arc<AgentRouter>,
    conversations: Arc<ConversationRegistry>,
    history_receipts: HistoryOnlyReceiptRegistry,
    source: Arc<FakeSource>,
}

impl Harness {
    async fn new(label: &str, plans: impl IntoIterator<Item = FakeGeneration>) -> Self {
        Self::with_fault_injector(label, plans, None).await
    }

    async fn with_fault_injector(
        label: &str,
        plans: impl IntoIterator<Item = FakeGeneration>,
        fault_injector: Option<Arc<dyn RuntimeStoreFaultInjector>>,
    ) -> Self {
        Self::with_options(label, plans, fault_injector, None).await
    }

    async fn with_conversation_capacity(
        label: &str,
        plans: impl IntoIterator<Item = FakeGeneration>,
        conversation_capacity: u64,
    ) -> Self {
        Self::with_options(label, plans, None, Some(conversation_capacity)).await
    }

    async fn with_options(
        label: &str,
        plans: impl IntoIterator<Item = FakeGeneration>,
        fault_injector: Option<Arc<dyn RuntimeStoreFaultInjector>>,
        conversation_capacity: Option<u64>,
    ) -> Self {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let mut config = RuntimeStoreConfig::new(root.database());
        if let Some(conversation_capacity) = conversation_capacity {
            config = config.with_conversation_capacity(conversation_capacity);
        }
        if let Some(fault_injector) = fault_injector {
            config = config.with_fault_injector(fault_injector);
        }
        let store = RuntimeStoreHandle::open(
            config,
            load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
                .expect("native projector StorageKEK"),
        )
        .await
        .expect("open native projector Store");
        let source = Arc::new(FakeSource::new(root.database(), plans));
        let mut router = AgentRouter::with_runtime_store(store.clone());
        router.register_native_projection_source(source.clone());
        let router = Arc::new(router);
        let conversations = Arc::new(
            ConversationRegistry::new(
                store.clone(),
                Arc::new(DisabledExecutionCoordinator),
                RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0xA1; 16])
                    .expect("fake daemon boot id"),
                2,
            )
            .expect("fake conversation registry"),
        );
        let history_receipts = HistoryOnlyReceiptRegistry::default();
        Self {
            _root: root,
            store,
            router,
            conversations,
            history_receipts,
            source,
        }
    }

    fn projector(&self) -> NativeProjector {
        self.projector_with_timings(NativeProjectorTimings {
            retry_delay: Duration::from_millis(1),
            refresh_delay: Duration::from_secs(60),
        })
    }

    fn projector_with_timings(&self, timings: NativeProjectorTimings) -> NativeProjector {
        NativeProjector::with_timings(
            self.router.clone(),
            self.store.clone(),
            self.conversations.clone(),
            self.history_receipts.clone(),
            timings,
        )
    }

    async fn finish(projector: &NativeProjector) {
        let (_cancel, mut receiver) = watch::channel(false);
        projector
            .shared
            .finish_completed_generation(&mut receiver)
            .await;
    }

    async fn close(self) {
        self.conversations
            .shutdown()
            .await
            .expect("shutdown fake actors");
        self.store
            .shutdown()
            .await
            .expect("shutdown native projector Store");
    }
}

fn only_conversation_id(database: &Path) -> RuntimeId {
    let bytes: Vec<u8> = Connection::open(database)
        .expect("open native projector database")
        .query_row(
            "SELECT conversation_id FROM conversations LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("read projected conversation id");
    RuntimeId::from_bytes(
        RuntimeIdKind::Conversation,
        bytes.try_into().expect("16-byte conversation id"),
    )
    .expect("non-zero projected conversation id")
}

fn projection_state(database: &Path) -> String {
    Connection::open(database)
        .expect("open projection state database")
        .query_row(
            "SELECT projection_state FROM native_projection_state LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("read projection state")
}

#[test]
fn production_projector_limits_remain_fixed() {
    assert_eq!(crate::agent::NATIVE_PROJECTION_ROUND_CANDIDATE_LIMIT, 2_000);
    assert_eq!(crate::agent::NATIVE_PROJECTION_ROUND_IMPORT_LIMIT, 500);
    assert_eq!(
        crate::agent::NATIVE_PROJECTION_ROUND_BYTE_LIMIT,
        64 * 1024 * 1024
    );
    assert_eq!(
        crate::agent::NATIVE_PROJECTION_ROUND_TIME_LIMIT,
        Duration::from_secs(2)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_source_waits_for_refresh_instead_of_spinning_on_retry_delay() {
    let harness = Harness::new("unavailable-refresh", []).await;
    let projector = harness.projector_with_timings(NativeProjectorTimings {
        retry_delay: Duration::from_millis(1),
        refresh_delay: Duration::from_millis(50),
    });

    projector.run_initial_round().await;
    assert_eq!(harness.source.begins.load(Ordering::SeqCst), 1);
    assert!(matches!(
        &*projector.shared.work.lock().await,
        ProjectorWork::Dormant
    ));

    projector.start_background();
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        harness.source.begins.load(Ordering::SeqCst),
        1,
        "unavailable source must not use the 1ms transient retry lane"
    );
    tokio::time::timeout(Duration::from_millis(250), async {
        while harness.source.begins.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh delay eventually retries source discovery");

    projector.shutdown().await;
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_generation_uses_refresh_backoff_instead_of_retry_spin() {
    let incomplete = FakeGeneration {
        candidates: Vec::new(),
        yield_after: None,
        fail_after: None,
        next_delay: None,
        incomplete_completion: true,
    };
    let harness = Harness::new(
        "incomplete-refresh",
        [incomplete.clone(), incomplete.clone(), incomplete],
    )
    .await;
    let projector = harness.projector_with_timings(NativeProjectorTimings {
        retry_delay: Duration::from_millis(1),
        refresh_delay: Duration::from_millis(50),
    });

    projector.run_initial_round().await;
    projector.start_background();
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        harness.source.begins.load(Ordering::SeqCst),
        2,
        "bootstrap may hand off once, but incomplete scan must not enter the 1ms retry lane"
    );
    tokio::time::timeout(Duration::from_millis(250), async {
        while harness.source.begins.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh backoff eventually starts a fresh generation");

    projector.shutdown().await;
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_unavailable_generation_uses_refresh_backoff_instead_of_retry_spin() {
    let unavailable = FakeGeneration {
        candidates: Vec::new(),
        yield_after: None,
        fail_after: Some(0),
        next_delay: None,
        incomplete_completion: false,
    };
    let harness = Harness::new(
        "read-unavailable-refresh",
        [unavailable.clone(), unavailable.clone(), unavailable],
    )
    .await;
    let projector = harness.projector_with_timings(NativeProjectorTimings {
        retry_delay: Duration::from_millis(1),
        refresh_delay: Duration::from_millis(50),
    });

    projector.run_initial_round().await;
    projector.start_background();
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        harness.source.begins.load(Ordering::SeqCst),
        2,
        "bootstrap may hand off once, but a read failure must not enter the 1ms retry lane"
    );
    tokio::time::timeout(Duration::from_millis(250), async {
        while harness.source.begins.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh backoff eventually retries a transient source read");

    projector.shutdown().await;
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_projection_limit_keeps_candidate_unacked_and_uses_refresh_backoff() {
    let harness = Harness::with_conversation_capacity(
        "limit-refresh",
        [FakeGeneration {
            candidates: vec![0x71, 0x72],
            yield_after: None,
            fail_after: None,
            next_delay: None,
            incomplete_completion: false,
        }],
        1,
    )
    .await;
    let projector = harness.projector_with_timings(NativeProjectorTimings {
        retry_delay: Duration::from_millis(1),
        refresh_delay: Duration::from_millis(50),
    });

    projector.run_initial_round().await;
    assert_eq!(harness.source.acknowledgements.load(Ordering::SeqCst), 1);
    assert_eq!(harness.source.deliveries.load(Ordering::SeqCst), 2);
    assert_eq!(harness.source.completions.load(Ordering::SeqCst), 0);
    assert!(matches!(
        &*projector.shared.work.lock().await,
        ProjectorWork::Scanning { .. }
    ));

    projector.start_background();
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        harness.source.deliveries.load(Ordering::SeqCst),
        3,
        "bootstrap handoff may retry once, then hard cap must use refresh rather than 1ms retry"
    );
    assert_eq!(
        harness.source.acknowledgements.load(Ordering::SeqCst),
        1,
        "capacity-rejected candidate must remain pending and unacknowledged"
    );
    tokio::time::timeout(Duration::from_millis(250), async {
        while harness.source.deliveries.load(Ordering::SeqCst) < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh backoff eventually retries the exact pending candidate");

    projector.shutdown().await;
    harness.close().await;
}

#[tokio::test]
async fn native_metadata_reuses_bounded_adapter_process_permits() {
    let harness = Harness::new("native-adapter-permits", []).await;
    let first = harness
        .conversations
        .acquire_native_adapter_permit()
        .await
        .expect("first native adapter permit");
    let second = harness
        .conversations
        .acquire_native_adapter_permit()
        .await
        .expect("second native adapter permit");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            harness.conversations.acquire_native_adapter_permit(),
        )
        .await
        .is_err(),
        "native metadata must not exceed the shared adapter process budget"
    );
    drop(first);
    let replacement = tokio::time::timeout(
        Duration::from_secs(1),
        harness.conversations.acquire_native_adapter_permit(),
    )
    .await
    .expect("released shared permit wakes one waiter")
    .expect("adapter permit remains open");
    drop(replacement);
    drop(second);
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_round_preserves_continuation_and_shutdown_joins_background() {
    let harness = Harness::new(
        "initial-continuation",
        [FakeGeneration {
            candidates: vec![0x31],
            yield_after: Some(1),
            fail_after: None,
            next_delay: None,
            incomplete_completion: false,
        }],
    )
    .await;
    let projector = harness.projector();
    projector.run_initial_round().await;
    assert_eq!(harness.source.begins.load(Ordering::SeqCst), 1);
    assert_eq!(harness.source.acknowledgements.load(Ordering::SeqCst), 1);
    assert_eq!(harness.source.completions.load(Ordering::SeqCst), 0);
    assert_eq!(harness.conversations.len().await, 1);

    projector.start_background();
    tokio::time::timeout(Duration::from_secs(2), async {
        while harness.source.completions.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("background resumes exact opaque continuation");
    tokio::time::timeout(Duration::from_secs(2), projector.shutdown())
        .await
        .expect("projector cancellation joins sleeping background");
    assert_eq!(harness.source.begins.load(Ordering::SeqCst), 1);
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_deadline_keeps_slow_blocking_owner_tracked_until_shutdown_join() {
    let harness = Harness::new(
        "startup-hard-bound",
        [FakeGeneration {
            candidates: Vec::new(),
            yield_after: None,
            fail_after: None,
            next_delay: Some(Duration::from_secs(3)),
            incomplete_completion: false,
        }],
    )
    .await;
    let projector = harness.projector();
    let started = std::time::Instant::now();
    projector.run_initial_round().await;
    assert!(
        started.elapsed() < Duration::from_millis(2_250),
        "Core readiness waiter must remain bounded by the fixed 2s round"
    );

    projector.start_background();
    tokio::time::timeout(Duration::from_secs(2), projector.shutdown())
        .await
        .expect("shutdown joins the still-running blocking owner");
    assert_eq!(
        harness.source.completions.load(Ordering::SeqCst),
        1,
        "joined owner must finish in place rather than detach an orphan"
    );
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_reconciliation_preserves_completed_witness_until_owner_is_joined() {
    // Store apply 前收到 shutdown/cancel 时不能消费 completed witness 或卸载 actor；
    // 这里先证明零 reconciliation，再解除测试 cancel 精确消费同一 witness。
    let harness = Harness::new(
        "reconcile-cancel",
        [FakeGeneration::candidate(0x61), FakeGeneration::empty()],
    )
    .await;
    let imported = harness.projector();
    imported.run_initial_round().await;
    Harness::finish(&imported).await;
    imported.shutdown().await;
    let conversation_id = only_conversation_id(&harness._root.database());
    let history_command_id =
        RuntimeId::from_bytes(RuntimeIdKind::Command, [0x42; 16]).expect("history command id");
    harness
        .history_receipts
        .replace(conversation_id, [history_command_id])
        .expect("install verified history-only receipt before reconciliation");
    assert!(harness.conversations.contains(conversation_id).await);

    let removed = harness.projector();
    removed.run_initial_round().await;
    let (cancel, mut receiver) = watch::channel(true);
    removed
        .shared
        .finish_completed_generation(&mut receiver)
        .await;
    assert!(
        harness.conversations.contains(conversation_id).await,
        "cancel before Store apply keeps actor installed"
    );
    assert_eq!(projection_state(&harness._root.database()), "present");
    assert!(
        harness
            .history_receipts
            .contains(conversation_id, history_command_id)
            .expect("canceled reconciliation preserves history receipt")
    );
    assert!(
        matches!(
            &*removed.shared.work.lock().await,
            ProjectorWork::Completed { .. }
        ),
        "cancel before apply retains the exact completed witness"
    );

    cancel.send_replace(false);
    removed
        .shared
        .finish_completed_generation(&mut receiver)
        .await;
    assert!(!harness.conversations.contains(conversation_id).await);
    assert_eq!(projection_state(&harness._root.database()), "tombstone");
    tokio::time::timeout(Duration::from_secs(1), removed.shutdown())
        .await
        .expect("projector owner joins after canceled reconciliation retry");
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_reconciliation_apply_preserves_actor_and_history_receipt() {
    // 三次 before-COMMIT failure 覆盖 projector 的 exact retry 上限。只要 Store
    // 没有 durable Applied/Replayed，就不能 clear volatile receipt 或卸载 actor。
    let faults = Arc::new(CountedStoreFault::new(
        RuntimeStoreOperation::ReconcileNativeProjectionBeforeCommit,
        EXACT_STORE_RETRY_LIMIT,
    ));
    let harness = Harness::with_fault_injector(
        "reconcile-apply-failure-receipt",
        [FakeGeneration::candidate(0x62), FakeGeneration::empty()],
        Some(faults.clone()),
    )
    .await;
    let imported = harness.projector();
    imported.run_initial_round().await;
    Harness::finish(&imported).await;
    imported.shutdown().await;
    let conversation_id = only_conversation_id(&harness._root.database());
    let history_command_id =
        RuntimeId::from_bytes(RuntimeIdKind::Command, [0x43; 16]).expect("history command id");
    harness
        .history_receipts
        .replace(conversation_id, [history_command_id])
        .expect("install history receipt before failed reconciliation");

    let removed = harness.projector();
    removed.run_initial_round().await;
    Harness::finish(&removed).await;
    removed.shutdown().await;

    assert_eq!(faults.remaining(), 0, "all exact retries must be exercised");
    assert_eq!(projection_state(&harness._root.database()), "present");
    assert!(harness.conversations.contains(conversation_id).await);
    assert!(
        harness
            .history_receipts
            .contains(conversation_id, history_command_id)
            .expect("failed apply preserves last successful receipt"),
        "receipt clear must remain strictly after durable reconciliation"
    );
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_commit_unknown_replays_before_clearing_receipt_and_uninstalling_actor() {
    // 第一次 reply 在 COMMIT 后丢失；exact retry 必须读回 Replayed，随后才 clear
    // receipt 和卸载 actor。不能把 CommitOutcomeUnknown 本身当成 durable witness。
    let faults = Arc::new(CountedStoreFault::new(
        RuntimeStoreOperation::ReconcileNativeProjectionAfterCommit,
        1,
    ));
    let harness = Harness::with_fault_injector(
        "reconcile-after-commit-receipt",
        [FakeGeneration::candidate(0x63), FakeGeneration::empty()],
        Some(faults.clone()),
    )
    .await;
    let imported = harness.projector();
    imported.run_initial_round().await;
    Harness::finish(&imported).await;
    imported.shutdown().await;
    let conversation_id = only_conversation_id(&harness._root.database());
    let history_command_id =
        RuntimeId::from_bytes(RuntimeIdKind::Command, [0x44; 16]).expect("history command id");
    harness
        .history_receipts
        .replace(conversation_id, [history_command_id])
        .expect("install history receipt before unknown reconciliation");

    let removed = harness.projector();
    removed.run_initial_round().await;
    Harness::finish(&removed).await;
    removed.shutdown().await;

    assert_eq!(faults.remaining(), 0);
    assert_eq!(projection_state(&harness._root.database()), "tombstone");
    assert!(!harness.conversations.contains(conversation_id).await);
    assert!(
        !harness
            .history_receipts
            .contains(conversation_id, history_command_id)
            .expect("inspect receipt after exact replay"),
        "durable Replayed removal must invalidate the stale receipt"
    );
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_native_mutation_defers_reobserve_without_ack_then_exactly_retries() {
    let harness = Harness::new(
        "metadata-race",
        [
            FakeGeneration::candidate(0x52),
            FakeGeneration::candidate(0x52),
        ],
    )
    .await;
    let imported = harness.projector();
    imported.run_initial_round().await;
    Harness::finish(&imported).await;
    imported.shutdown().await;
    let conversation_id = only_conversation_id(&harness._root.database());

    let claim = match harness
        .store
        .claim_native_conversation_metadata(UpdateManagedConversationMetadata {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0x52; 32],
                uid: 501,
                client_installation_id: [0x53; 16],
            },
            idempotency_key: "projector-metadata-race".to_owned(),
            expected_entry_revision: 0,
            mutation: ConversationMetadataMutation::Rename {
                title: Some("metadata-wins-first".to_owned()),
            },
        })
        .await
        .expect("claim native mutation before refresh")
    {
        ClaimNativeMetadataMutationOutcome::Claimed { mutation } => mutation,
        ClaimNativeMetadataMutationOutcome::Replayed { .. } => {
            panic!("fresh native mutation must be claimed")
        }
    };

    let refresh = harness.projector();
    refresh.run_initial_round().await;
    assert_eq!(
        harness.source.acknowledgements.load(Ordering::SeqCst),
        1,
        "active mutation must keep the exact scanner candidate pending"
    );
    harness
        .store
        .fail_claimed_native_metadata_mutation(
            claim,
            RuntimeFailure::new("test.native.failed", "release projector race fixture"),
        )
        .await
        .expect("terminalize synthetic native mutation");

    refresh.start_background();
    tokio::time::timeout(Duration::from_secs(2), async {
        while harness.source.acknowledgements.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending candidate retries after mutation terminalizes");
    refresh.shutdown().await;
    assert_eq!(projection_state(&harness._root.database()), "present");
    harness.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_busy_removed_and_reappeared_paths_manage_actor_exactly() {
    let harness = Harness::new(
        "lifecycle",
        [
            FakeGeneration::candidate(0x41),
            FakeGeneration::empty(),
            FakeGeneration::partial(),
            FakeGeneration::empty(),
            FakeGeneration::candidate(0x41),
        ],
    )
    .await;

    let imported = harness.projector();
    imported.run_initial_round().await;
    Harness::finish(&imported).await;
    imported.shutdown().await;
    let conversation_id = only_conversation_id(&harness._root.database());
    let history_command_id =
        RuntimeId::from_bytes(RuntimeIdKind::Command, [0x42; 16]).expect("history command id");
    harness
        .history_receipts
        .replace(conversation_id, [history_command_id])
        .expect("install verified history-only receipt before lifecycle reconciliation");
    assert!(harness.conversations.contains(conversation_id).await);
    assert_eq!(projection_state(&harness._root.database()), "present");

    let busy_guard = harness
        .conversations
        .acquire_native_mutation_guard(conversation_id)
        .await
        .expect("hold metadata/projector serialization guard");
    let busy = harness.projector();
    busy.run_initial_round().await;
    Harness::finish(&busy).await;
    busy.shutdown().await;
    assert!(harness.conversations.contains(conversation_id).await);
    assert_eq!(projection_state(&harness._root.database()), "present");
    assert!(
        harness
            .history_receipts
            .contains(conversation_id, history_command_id)
            .expect("busy generation preserves history receipt")
    );
    drop(busy_guard);

    let partial = harness.projector();
    partial.run_initial_round().await;
    partial.shutdown().await;
    assert!(harness.conversations.contains(conversation_id).await);
    assert_eq!(projection_state(&harness._root.database()), "present");
    assert!(
        harness
            .history_receipts
            .contains(conversation_id, history_command_id)
            .expect("partial generation preserves history receipt")
    );

    let removed = harness.projector();
    removed.run_initial_round().await;
    Harness::finish(&removed).await;
    removed.shutdown().await;
    assert!(!harness.conversations.contains(conversation_id).await);
    assert_eq!(projection_state(&harness._root.database()), "tombstone");
    assert!(
        !harness
            .history_receipts
            .contains(conversation_id, history_command_id)
            .expect("Removed generation clears stale history receipt")
    );

    let reappeared = harness.projector();
    reappeared.run_initial_round().await;
    Harness::finish(&reappeared).await;
    reappeared.shutdown().await;
    assert!(harness.conversations.contains(conversation_id).await);
    assert_eq!(projection_state(&harness._root.database()), "present");
    assert!(
        !harness
            .history_receipts
            .contains(conversation_id, history_command_id)
            .expect("reappearance waits for a fresh dynamic read before rebuilding receipts")
    );
    assert_eq!(harness.source.acknowledgements.load(Ordering::SeqCst), 2);
    harness.close().await;
}
