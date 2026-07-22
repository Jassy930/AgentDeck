use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use agentdeck_protocol::runtime::{
    CatalogChange, ClaudeCodeConversationConfiguration, ConversationConfiguration, StreamCursor,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentKind, ClaudeCodePermissionMode};
use rusqlite::{Connection, OpenFlags};
use tokio::sync::Semaphore;

use super::admission::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use super::native_projection::{
    NativeProjectionCandidateDisposition, ReconcileNativeProjectionOutcome,
    RetireNativeProjectionOutcome,
};
use super::{
    AcceptCommand, AcceptOutcome, ConfigureConversation, ConversationDescriptor, IdempotencyOwner,
    ImportNativeProjection, ImportNativeProjectionOutcome, NewConversation,
    PreparedConversationSnapshotWrite, RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeClock,
    RuntimeClockError, RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use crate::agent::{CompletedNativeProjectionScan, native_projection_scan_issuer_for_test};
use crate::runtime::AgentRouter;
use crate::runtime::backfill::BarrierRequest;
use crate::runtime::catalog_snapshot::CatalogSnapshotProvider;
use crate::runtime::connection::{AuthenticatedPrincipal, PrincipalIssuer};
use crate::runtime::events::{
    RegisterStreamBarrier, RuntimeStreamTarget, SnapshotBarrierSource,
    SnapshotMaterializationSource, WatchGeneration,
};
use crate::runtime::snapshot::{
    SNAPSHOT_BUILD_MEMORY_BYTES, SnapshotMaterialization, SnapshotMaterializationError,
    SnapshotMaterializer,
};
use crate::security::{MemoryKeyStore, SecretBytes, StorageKek, load_or_create_storage_kek};

const TOMBSTONE_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentdeck-native-projection-lifecycle-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create native projection lifecycle root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure native projection lifecycle root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load native projection lifecycle StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Debug)]
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

#[derive(Debug)]
struct OneShotFault {
    target: RuntimeStoreOperation,
    armed: AtomicBool,
}

impl OneShotFault {
    fn new(target: RuntimeStoreOperation) -> Self {
        Self {
            target,
            armed: AtomicBool::new(true),
        }
    }
}

impl RuntimeStoreFaultInjector for OneShotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.target && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct OperationGate {
    target: RuntimeStoreOperation,
    armed: AtomicBool,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl OperationGate {
    fn new(target: RuntimeStoreOperation) -> (Self, Arc<Barrier>, Arc<Barrier>) {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        (
            Self {
                target,
                armed: AtomicBool::new(false),
                entered: entered.clone(),
                release: release.clone(),
            },
            entered,
            release,
        )
    }

    fn arm(&self) {
        assert!(!self.armed.swap(true, Ordering::SeqCst));
    }
}

impl RuntimeStoreFaultInjector for OperationGate {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.target && self.armed.swap(false, Ordering::SeqCst) {
            self.entered.wait();
            self.release.wait();
        }
        Ok(())
    }
}

async fn cross_operation_gate(barrier: Arc<Barrier>) {
    tokio::task::spawn_blocking(move || {
        barrier.wait();
    })
    .await
    .expect("operation gate participant must not panic");
}

#[derive(Clone, Debug)]
struct SwitchableCapacityProbe {
    rejected: Arc<AtomicBool>,
    calls: Arc<AtomicU64>,
}

impl SwitchableCapacityProbe {
    fn new() -> Self {
        Self {
            rejected: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicU64::new(0)),
        }
    }

    fn reject(&self) {
        self.rejected.store(true, Ordering::SeqCst);
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl RuntimeCapacityProbe for SwitchableCapacityProbe {
    fn observe(
        &self,
        _database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.rejected.load(Ordering::SeqCst) {
            return Ok(RuntimeCapacityObservation {
                main_bytes: 2 * 1024 * 1024 * 1024 + 1,
                wal_bytes: 0,
                shm_bytes: 0,
                filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
                filesystem_available_bytes: 8 * 1024 * 1024 * 1024,
            });
        }
        Ok(RuntimeCapacityObservation {
            main_bytes: 8 * 1024 * 1024,
            wal_bytes: 2 * 1024 * 1024,
            shm_bytes: 32 * 1024,
            filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 4 * 1024 * 1024 * 1024,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LifecycleEvidence {
    present: i64,
    tombstone: i64,
    retired: i64,
    vault_rows: i64,
    configuration_rows: i64,
    event_rows: i64,
    catalog_rows: i64,
    catalog_high_water: Option<String>,
}

fn lifecycle_evidence(database: &Path) -> LifecycleEvidence {
    let connection = Connection::open(database).expect("open lifecycle evidence database");
    let projection_count = |state: &str| {
        connection
            .query_row(
                "SELECT COUNT(*) FROM native_projection_state WHERE projection_state = ?1",
                [state],
                |row| row.get(0),
            )
            .expect("count lifecycle projection state")
    };
    let scalar = |query: &str| {
        connection
            .query_row(query, [], |row| row.get(0))
            .expect("read lifecycle scalar evidence")
    };
    let catalog_high_water = connection
        .query_row(
            "SELECT catalog_high_water FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read lifecycle catalog high-water");
    LifecycleEvidence {
        present: projection_count("present"),
        tombstone: projection_count("tombstone"),
        retired: projection_count("retired"),
        vault_rows: scalar("SELECT COUNT(*) FROM claude_code_adapter_state"),
        configuration_rows: scalar("SELECT COUNT(*) FROM configuration_journal"),
        event_rows: scalar("SELECT COUNT(*) FROM event_journal"),
        catalog_rows: scalar("SELECT COUNT(*) FROM catalog_journal"),
        catalog_high_water,
    }
}

fn projection_state(database: &Path, conversation_id: RuntimeId) -> String {
    Connection::open(database)
        .expect("open projection state evidence")
        .query_row(
            "SELECT projection_state FROM native_projection_state WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read projection state evidence")
}

fn durable_artifact_bytes(database: &Path) -> (Vec<u8>, Option<Vec<u8>>) {
    let main = fs::read(database).expect("read runtime database bytes");
    let wal_path = PathBuf::from(format!("{}-wal", database.display()));
    let wal = fs::read(wal_path).ok();
    (main, wal)
}

#[derive(Debug, Eq, PartialEq)]
struct SnapshotDurableEvidence {
    snapshot_rows: i64,
    event_rows: i64,
    ledger_event_count: i64,
    ledger_snapshot_count: i64,
    ledger_snapshot_bytes: i64,
    ledger_token: Vec<u8>,
    artifacts: (Vec<u8>, Option<Vec<u8>>),
}

fn snapshot_durable_evidence(database: &Path) -> SnapshotDurableEvidence {
    let connection = Connection::open(database).expect("open snapshot durable evidence database");
    let scalar = |query: &str| {
        connection
            .query_row(query, [], |row| row.get(0))
            .expect("read snapshot durable scalar evidence")
    };
    let (ledger_event_count, ledger_snapshot_count, ledger_snapshot_bytes, ledger_token) =
        connection
            .query_row(
                "SELECT event_count, snapshot_count, snapshot_bytes, metadata_token
             FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read snapshot durable ledger evidence");
    let evidence = SnapshotDurableEvidence {
        snapshot_rows: scalar("SELECT COUNT(*) FROM snapshots"),
        event_rows: scalar("SELECT COUNT(*) FROM event_journal"),
        ledger_event_count,
        ledger_snapshot_count,
        ledger_snapshot_bytes,
        ledger_token,
        artifacts: (Vec::new(), None),
    };
    drop(connection);
    SnapshotDurableEvidence {
        artifacts: durable_artifact_bytes(database),
        ..evidence
    }
}

fn accepted_command_count(database: &Path, conversation_id: RuntimeId) -> i64 {
    Connection::open(database)
        .expect("open accepted command evidence")
        .query_row(
            "SELECT COUNT(*) FROM commands
             WHERE conversation_id = ?1 AND state = 'accepted'",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("count accepted command evidence")
}

#[derive(Debug, Eq, PartialEq)]
struct CommandAdmissionEvidence {
    command_rows: i64,
    pin_rows: i64,
    event_rows: i64,
    command_high_water: Option<String>,
    conversation_accepted_count: i64,
    conversation_metadata_token: Vec<u8>,
    ledger_command_count: i64,
    ledger_pin_count: i64,
    ledger_event_count: i64,
    ledger_accepted_count: i64,
    ledger_accepted_payload_bytes: i64,
    ledger_metadata_token: Vec<u8>,
    artifacts: (Vec<u8>, Option<Vec<u8>>),
}

fn command_admission_evidence(
    database: &Path,
    conversation_id: RuntimeId,
) -> CommandAdmissionEvidence {
    let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only command admission evidence database");
    let target = &conversation_id.as_bytes()[..];
    let command_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM commands WHERE conversation_id = ?1",
            [target],
            |row| row.get(0),
        )
        .expect("count command admission command rows");
    let pin_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM command_configuration_pins WHERE conversation_id = ?1",
            [target],
            |row| row.get(0),
        )
        .expect("count command admission configuration pins");
    let event_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM event_journal WHERE conversation_id = ?1",
            [target],
            |row| row.get(0),
        )
        .expect("count command admission event rows");
    let (command_high_water, conversation_accepted_count, conversation_metadata_token) = connection
        .query_row(
            "SELECT command_high_water, accepted_count, metadata_token
                 FROM conversations WHERE conversation_id = ?1",
            [target],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read command admission conversation evidence");
    let (
        ledger_command_count,
        ledger_pin_count,
        ledger_event_count,
        ledger_accepted_count,
        ledger_accepted_payload_bytes,
        ledger_metadata_token,
    ) = connection
        .query_row(
            "SELECT command_count, command_configuration_pin_count, event_count,
                    accepted_count, accepted_payload_bytes, metadata_token
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("read command admission ledger evidence");
    drop(connection);
    CommandAdmissionEvidence {
        command_rows,
        pin_rows,
        event_rows,
        command_high_water,
        conversation_accepted_count,
        conversation_metadata_token,
        ledger_command_count,
        ledger_pin_count,
        ledger_event_count,
        ledger_accepted_count,
        ledger_accepted_payload_bytes,
        ledger_metadata_token,
        artifacts: durable_artifact_bytes(database),
    }
}

fn configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .expect("valid native lifecycle configuration"),
    ))
}

fn descriptor() -> ConversationDescriptor {
    ConversationDescriptor {
        agent_kind: AgentKind::ClaudeCode,
        title: None,
        cwd: PathBuf::new(),
    }
}

fn reference(index: usize) -> Vec<u8> {
    format!("native-lifecycle-reference-{index:04}").into_bytes()
}

fn owner(marker: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [marker; 32],
        uid: u32::from(marker),
        client_installation_id: [marker.wrapping_add(1); 16],
    }
}

fn import_input(reference: &[u8], scan_generation: [u8; 16]) -> ImportNativeProjection {
    ImportNativeProjection {
        descriptor: descriptor(),
        default_configuration: configuration(),
        private_reference: SecretBytes::new(reference.to_vec()),
        scan_generation,
    }
}

fn completed_scan(
    generation: [u8; 16],
    acknowledged_candidates: u64,
) -> CompletedNativeProjectionScan {
    native_projection_scan_issuer_for_test(generation)
        .expect("valid neutral projection generation")
        .complete(generation, acknowledged_candidates, acknowledged_candidates)
        .expect("completed neutral projection witness")
}

async fn open_store(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    clock: ManualClock,
) -> RuntimeStoreHandle {
    RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(keys),
    )
    .await
    .expect("open native projection lifecycle store")
}

async fn catalog_changes(store: &RuntimeStoreHandle) -> Vec<CatalogChange> {
    let RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("pin lifecycle catalog")
    else {
        return Vec::new();
    };
    let mut after = None;
    let mut changes = Vec::new();
    loop {
        let page = store
            .load_catalog_backfill_page(pin.clone(), after)
            .await
            .expect("load lifecycle catalog page");
        let completion = page.completion().clone();
        let complete = page.complete;
        after = Some(page.next_after);
        for delta in page.deltas {
            assert_eq!(delta.changes.len(), 1);
            changes.extend(delta.changes);
        }
        store
            .complete_backfill_page(completion)
            .await
            .expect("complete lifecycle catalog page");
        if complete {
            break;
        }
    }
    store
        .release_backfill_pin(pin.pin_id)
        .await
        .expect("release lifecycle catalog pin");
    changes
}

async fn native_catalog_snapshot_ids(
    store: &RuntimeStoreHandle,
    provider: &CatalogSnapshotProvider,
    principal: &AuthenticatedPrincipal,
    generation: u64,
) -> Vec<String> {
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(generation).expect("nonzero catalog watch generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register native lifecycle catalog snapshot barrier");
    let page = provider
        .first_page(&mut registration, principal)
        .await
        .expect("materialize native lifecycle catalog snapshot");
    assert!(
        page.snapshot().next_page_cursor().is_none(),
        "single native lifecycle row must fit one catalog page"
    );
    page.snapshot()
        .entries()
        .iter()
        .map(|entry| entry.conversation_id.as_str().to_owned())
        .collect()
}

async fn tombstone_single(
    store: &RuntimeStoreHandle,
    absent_generation: [u8; 16],
) -> (
    RuntimeId,
    super::native_projection::NativeProjectionReconcilePlan,
) {
    let projector = store.claude_code_native_projection_store();
    let completed = projector
        .accept_completed_scan(completed_scan(absent_generation, 0))
        .await
        .expect("accept complete native scan");
    let plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("plan absent native projection page");
    let ids = plan.candidate_ids().collect::<Vec<_>>();
    assert_eq!(
        ids.len(),
        1,
        "single projection fixture must yield one candidate"
    );
    let outcome = projector
        .apply_completed_page(
            plan.clone(),
            vec![NativeProjectionCandidateDisposition::Quiescent(ids[0])],
        )
        .await
        .expect("tombstone quiescent native projection");
    assert!(matches!(
        outcome,
        ReconcileNativeProjectionOutcome::Applied {
            removed: 1,
            deferred_busy: 0,
            next_cursor: None,
        }
    ));
    (ids[0], plan)
}

#[tokio::test]
async fn partial_scan_cannot_remove_but_complete_scan_removes_once_and_exact_retry_replays() {
    let root = TestRoot::new("complete-partial-replay");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let observed = reference(1);
    let absent = reference(2);

    let first = projector
        .import(import_input(&observed, [0x11; 16]))
        .await
        .expect("import first native projection");
    let second = projector
        .import(import_input(&absent, [0x11; 16]))
        .await
        .expect("import second native projection");
    let ImportNativeProjectionOutcome::Imported {
        conversation: first_conversation,
        ..
    } = first
    else {
        panic!("first projection must import");
    };
    let ImportNativeProjectionOutcome::Imported {
        conversation: absent_conversation,
        ..
    } = second
    else {
        panic!("second projection must import");
    };

    clock.set(10_001);
    assert!(matches!(
        projector
            .import(import_input(&observed, [0x12; 16]))
            .await
            .expect("partial scan imports observed projection"),
        ImportNativeProjectionOutcome::Reobserved { .. }
    ));
    assert_eq!(
        lifecycle_evidence(&root.database()),
        LifecycleEvidence {
            present: 2,
            tombstone: 0,
            retired: 0,
            vault_rows: 2,
            configuration_rows: 2,
            event_rows: 2,
            catalog_rows: 2,
            catalog_high_water: Some("00000000000000000001".to_owned()),
        },
        "partial generation has no deletion capability"
    );

    clock.set(10_002);
    assert!(matches!(
        projector
            .import(import_input(&observed, [0x13; 16]))
            .await
            .expect("complete scan imports observed projection"),
        ImportNativeProjectionOutcome::Reobserved { .. }
    ));
    let completed = projector
        .accept_completed_scan(completed_scan([0x13; 16], 1))
        .await
        .expect("accept exhausted complete scan");
    let plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("plan authenticated absent page");
    let ids = plan.candidate_ids().collect::<Vec<_>>();
    assert_eq!(ids, [absent_conversation.conversation_id]);
    let dispositions = vec![NativeProjectionCandidateDisposition::Quiescent(ids[0])];
    let applied = projector
        .apply_completed_page(plan.clone(), dispositions.clone())
        .await
        .expect("apply complete-generation reconciliation");
    assert!(matches!(
        applied,
        ReconcileNativeProjectionOutcome::Applied {
            removed: 1,
            deferred_busy: 0,
            next_cursor: None,
        }
    ));
    let committed = lifecycle_evidence(&root.database());
    assert_eq!(committed.present, 1);
    assert_eq!(committed.tombstone, 1);
    assert_eq!(committed.catalog_rows, 3);
    assert_eq!(projection_state(&root.database(), ids[0]), "tombstone");

    let replayed = projector
        .apply_completed_page(plan, dispositions)
        .await
        .expect("exact reconciliation retry reads committed post-state");
    assert!(matches!(
        replayed,
        ReconcileNativeProjectionOutcome::Replayed {
            removed: 1,
            deferred_busy: 0,
            next_cursor: None,
        }
    ));
    assert_eq!(lifecycle_evidence(&root.database()), committed);

    let changes = catalog_changes(&store).await;
    assert_eq!(changes.len(), 3);
    assert!(matches!(changes[0], CatalogChange::Upserted { .. }));
    assert!(matches!(changes[1], CatalogChange::Upserted { .. }));
    let CatalogChange::Removed { conversation_id } = &changes[2] else {
        panic!("complete absent reconciliation must emit one Removed");
    };
    assert_eq!(
        conversation_id.as_str(),
        absent_conversation.conversation_id.to_canonical_string()
    );
    assert_eq!(
        projection_state(&root.database(), first_conversation.conversation_id),
        "present"
    );
    store
        .shutdown()
        .await
        .expect("shutdown complete scan store");
}

#[tokio::test]
async fn busy_candidate_is_deferred_and_a_later_complete_generation_can_remove_it() {
    let root = TestRoot::new("busy-then-quiescent");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(20_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&reference(3), [0x21; 16]))
        .await
        .expect("import busy projection fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("busy fixture must import");
    };

    clock.set(20_001);
    let completed = projector
        .accept_completed_scan(completed_scan([0x22; 16], 0))
        .await
        .expect("accept first complete absent scan");
    let busy_plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("plan busy absent projection");
    assert_eq!(
        busy_plan.candidate_ids().collect::<Vec<_>>(),
        [conversation.conversation_id]
    );
    let changed_disposition_plan = busy_plan.clone();
    let busy = projector
        .apply_completed_page(
            busy_plan,
            vec![NativeProjectionCandidateDisposition::Busy(
                conversation.conversation_id,
            )],
        )
        .await
        .expect("defer busy native projection");
    assert!(matches!(
        busy,
        ReconcileNativeProjectionOutcome::Applied {
            removed: 0,
            deferred_busy: 1,
            next_cursor: None,
        }
    ));
    assert_eq!(
        projection_state(&root.database(), conversation.conversation_id),
        "present"
    );
    assert_eq!(lifecycle_evidence(&root.database()).catalog_rows, 1);

    let busy_evidence = lifecycle_evidence(&root.database());
    let busy_artifacts = durable_artifact_bytes(&root.database());
    let changed_error = projector
        .apply_completed_page(
            changed_disposition_plan,
            vec![NativeProjectionCandidateDisposition::Quiescent(
                conversation.conversation_id,
            )],
        )
        .await
        .expect_err("a cloned plan cannot change its frozen Busy disposition");
    assert!(matches!(
        changed_error,
        RuntimeStoreError::InvalidStateTransition
    ));
    assert_eq!(durable_artifact_bytes(&root.database()), busy_artifacts);
    assert_eq!(lifecycle_evidence(&root.database()), busy_evidence);

    clock.set(20_002);
    let completed = projector
        .accept_completed_scan(completed_scan([0x23; 16], 0))
        .await
        .expect("accept next complete absent scan");
    let quiescent_plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("replan formerly busy projection");
    let quiescent = projector
        .apply_completed_page(
            quiescent_plan,
            vec![NativeProjectionCandidateDisposition::Quiescent(
                conversation.conversation_id,
            )],
        )
        .await
        .expect("remove now-quiescent native projection");
    assert!(matches!(
        quiescent,
        ReconcileNativeProjectionOutcome::Applied {
            removed: 1,
            deferred_busy: 0,
            next_cursor: None,
        }
    ));
    assert_eq!(
        projection_state(&root.database(), conversation.conversation_id),
        "tombstone"
    );
    assert_eq!(lifecycle_evidence(&root.database()).catalog_rows, 2);
    store
        .shutdown()
        .await
        .expect("shutdown busy lifecycle store");
}

#[tokio::test]
async fn newer_reappearance_invalidates_an_older_completed_generation_capability() {
    let root = TestRoot::new("stale-completed-after-reappear");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(30_000);
    let private_reference = reference(14);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&private_reference, [0x24; 16]))
        .await
        .expect("import stale completed-generation fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("stale completed-generation fixture must import");
    };

    clock.set(30_001);
    let (tombstoned_id, _) = tombstone_single(&store, [0x25; 16]).await;
    assert_eq!(tombstoned_id, conversation.conversation_id);
    clock.set(30_002);
    let stale_completed = projector
        .accept_completed_scan(completed_scan([0x26; 16], 0))
        .await
        .expect("accept generation before native reappearance");

    clock.set(30_003);
    let reappeared = projector
        .import(import_input(&private_reference, [0x27; 16]))
        .await
        .expect("reappear native projection in a newer generation");
    let ImportNativeProjectionOutcome::Reappeared {
        conversation: reappeared,
        ..
    } = reappeared
    else {
        panic!("newer generation must reappear tombstoned projection");
    };
    assert_eq!(reappeared.conversation_id, conversation.conversation_id);
    let committed = lifecycle_evidence(&root.database());
    let committed_artifacts = durable_artifact_bytes(&root.database());
    let error = projector
        .plan_completed_page(stale_completed, None)
        .await
        .expect_err("newer import must invalidate the older completed generation");
    assert!(matches!(error, RuntimeStoreError::InvalidStateTransition));
    assert_eq!(
        durable_artifact_bytes(&root.database()),
        committed_artifacts
    );
    assert_eq!(lifecycle_evidence(&root.database()), committed);
    assert_eq!(committed.present, 1);
    assert_eq!(committed.tombstone, 0);
    assert_eq!(committed.catalog_rows, 3);
    assert_eq!(
        projection_state(&root.database(), conversation.conversation_id),
        "present"
    );
    store
        .shutdown()
        .await
        .expect("shutdown stale completed-generation fixture");
}

#[tokio::test]
async fn catalog_snapshot_reducer_removes_tombstone_and_restores_same_id_on_reappearance() {
    let root = TestRoot::new("catalog-snapshot-lifecycle");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(35_000);
    let private_reference = reference(141);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&private_reference, [0x71; 16]))
        .await
        .expect("import catalog snapshot lifecycle fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("catalog snapshot lifecycle fixture must import");
    };
    let conversation_id = conversation.conversation_id;
    let canonical_id = conversation_id.to_canonical_string();
    let provider = CatalogSnapshotProvider::with_clock(
        store.clone(),
        Arc::new(clock.clone()),
        Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES)),
    )
    .expect("construct authenticated catalog snapshot provider");
    let principal = PrincipalIssuer::local_only([0x72; 32])
        .issue_verified_local(501, [0x73; 16])
        .expect("issue catalog snapshot lifecycle principal");

    assert_eq!(
        native_catalog_snapshot_ids(&store, &provider, &principal, 1).await,
        std::slice::from_ref(&canonical_id),
        "present native projection must be visible in the catalog snapshot"
    );

    clock.set(35_001);
    let (tombstoned_id, _) = tombstone_single(&store, [0x74; 16]).await;
    assert_eq!(tombstoned_id, conversation_id);
    assert!(
        native_catalog_snapshot_ids(&store, &provider, &principal, 2)
            .await
            .is_empty(),
        "authenticated Removed delta must delete the tombstoned projection from refresh"
    );

    clock.set(35_002);
    let reappeared = projector
        .import(import_input(&private_reference, [0x75; 16]))
        .await
        .expect("reappear catalog snapshot lifecycle fixture");
    let ImportNativeProjectionOutcome::Reappeared {
        conversation: reappeared,
        ..
    } = reappeared
    else {
        panic!("tombstoned projection must reappear");
    };
    assert_eq!(reappeared.conversation_id, conversation_id);
    assert_eq!(
        native_catalog_snapshot_ids(&store, &provider, &principal, 3).await,
        [canonical_id],
        "same-id reappearance Upsert must restore the catalog snapshot entry"
    );

    provider
        .clear_cache()
        .expect("clear native lifecycle catalog snapshot cache");
    store
        .shutdown()
        .await
        .expect("shutdown catalog snapshot lifecycle store");
}

#[tokio::test]
async fn native_subscription_captures_dynamic_source_without_durable_snapshot_write() {
    let root = TestRoot::new("native-dynamic-source");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(37_000);
    let store = open_store(&root, &keys, clock).await;
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&reference(37), [0x76; 16]))
        .await
        .expect("import native dynamic source fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("native dynamic source fixture must import");
    };
    let conversation_id = conversation.conversation_id;
    assert!(
        store
            .load_conversation_snapshot(conversation_id)
            .await
            .expect("read absent native ready snapshot")
            .is_none()
    );
    let durable_before = durable_artifact_bytes(&root.database());

    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(37).expect("nonzero native dynamic generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture native dynamic barrier source");
    assert!(registration.ready_snapshot_base.is_none());
    let source = registration
        .take_snapshot_source()
        .expect("native subscribe must carry a dynamic source");
    assert!(matches!(
        source.source(),
        SnapshotBarrierSource::Dynamic(pin)
            if pin.conversation_id() == conversation_id
                && pin.base_event_seq() == conversation.event_high_water
    ));
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active native dynamic TEMP pin"),
        1
    );
    drop(source);
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count released native dynamic TEMP pin"),
        0
    );
    assert!(
        store
            .load_conversation_snapshot(conversation_id)
            .await
            .expect("read native snapshot after dynamic source release")
            .is_none()
    );
    assert_eq!(durable_artifact_bytes(&root.database()), durable_before);
    store
        .shutdown()
        .await
        .expect("shutdown native dynamic source fixture");
}

#[tokio::test]
async fn native_direct_snapshot_capabilities_cannot_reach_durable_writer() {
    let root = TestRoot::new("native-durable-snapshot-gate");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(38_000);
    let store = open_store(&root, &keys, clock).await;
    let imported = store
        .claude_code_native_projection_store()
        .import(import_input(&reference(38), [0x77; 16]))
        .await
        .expect("import native durable snapshot gate fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("native durable snapshot gate fixture must import");
    };
    let conversation_id = conversation.conversation_id;
    let durable_before = snapshot_durable_evidence(&root.database());
    let materializer = SnapshotMaterializer::new(
        store.clone(),
        Arc::new(AgentRouter::with_runtime_store(store.clone())),
    );

    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire typed native snapshot source");
    assert!(matches!(
        source.source(),
        SnapshotBarrierSource::Dynamic(pin)
            if pin.conversation_id() == conversation_id
                && pin.base_event_seq() == conversation.event_high_water
    ));
    let SnapshotMaterialization::Dynamic(dynamic) = materializer
        .materialize(source)
        .await
        .expect("materialize native snapshot as ephemeral Dynamic input")
    else {
        panic!("native snapshot source must never materialize a durable Build input");
    };
    assert_eq!(dynamic.conversation_id(), conversation_id);
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count live Dynamic TEMP pin"),
        1
    );
    assert_eq!(snapshot_durable_evidence(&root.database()), durable_before);
    materializer
        .release_dynamic_input(dynamic)
        .await
        .expect("release typed Dynamic TEMP pin");
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count released Dynamic TEMP pin"),
        0
    );

    // 模拟 stale/cross-layer capability 把同一 authenticated native pin 错标成 Build；
    // materializer 必须在产生可 bind 的 SnapshotBuildInput 前拒绝并回收 pin。
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire native source for forged Build test");
    let (source, cleanup) = source.into_parts();
    let SnapshotBarrierSource::Dynamic(pin) = source else {
        panic!("direct native acquire must remain Dynamic");
    };
    let forged = SnapshotMaterializationSource::new(SnapshotBarrierSource::Build(pin), cleanup);
    let error = materializer
        .materialize(forged)
        .await
        .expect_err("native parent must reject a forged durable Build source");
    assert!(matches!(error, SnapshotMaterializationError::InvalidState));
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count pin after forged Build rejection"),
        0
    );
    assert_eq!(snapshot_durable_evidence(&root.database()), durable_before);

    // 最终 writer 必须独立复核 origin；即使 crate 内旁路伪造 opaque write，也不能
    // seal/DELETE/INSERT/consume durable state。
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire native source for forged writer test");
    let (source, cleanup) = source.into_parts();
    let SnapshotBarrierSource::Dynamic(pin) = source else {
        panic!("writer bypass fixture must start from Dynamic");
    };
    let cleanup = cleanup.expect("direct native source owns exact cleanup");
    let mut payload = br#"{"native":"must-not-persist"}"#.to_vec();
    payload
        .try_reserve_exact(super::cipher::ROW_BLOB_V1_OVERHEAD_LEN)
        .expect("reserve forged writer payload capacity");
    let failure = store
        .store_conversation_snapshot(PreparedConversationSnapshotWrite::new(
            pin, 1, payload, cleanup,
        ))
        .await
        .expect_err("native parent must fail before durable snapshot write");
    assert!(matches!(
        failure.error(),
        RuntimeStoreError::InvalidStateTransition
    ));
    drop(failure.into_retry_write());
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count pin after forged writer rejection"),
        0
    );
    assert_eq!(snapshot_durable_evidence(&root.database()), durable_before);
    assert!(
        store
            .load_conversation_snapshot(conversation_id)
            .await
            .expect("read native snapshot after all durable gate attempts")
            .is_none()
    );

    store
        .shutdown()
        .await
        .expect("shutdown native durable snapshot gate fixture");
}

#[tokio::test]
async fn recovery_rejects_authenticated_native_snapshot_row_without_rewrite() {
    let root = TestRoot::new("native-resealed-snapshot-recovery");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(39_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let imported = store
        .claude_code_native_projection_store()
        .import(import_input(&reference(39), [0x78; 16]))
        .await
        .expect("import native resealed snapshot recovery fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("native resealed snapshot recovery fixture must import");
    };
    store
        .shutdown()
        .await
        .expect("close native store before offline reseal fixture");

    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
    let mut raw = super::sqlite::open(&config, root.storage_kek(&keys))
        .expect("open raw store before authenticated native snapshot injection");
    super::snapshot::inject_authenticated_native_snapshot_row_for_test(
        &mut raw,
        conversation.conversation_id,
        39_001,
    )
    .expect("inject authenticated-but-semantically-invalid native snapshot row");
    let victim = conversation
        .event_high_water
        .expect("native import has an initial configuration event");
    assert!(
        !super::snapshot::authenticated_conversation_snapshot_covers(
            &raw.connection,
            &raw.key_bundle,
            conversation.conversation_id,
            victim,
        )
        .expect("authenticate native snapshot trim evidence"),
        "NativeProjected durable row must never authorize event trim"
    );
    let trim_error = super::retention::authorize_trim(
        &raw.connection,
        &raw.key_bundle,
        raw.database_id,
        super::retention::RetentionTarget::Conversation(conversation.conversation_id.as_bytes()),
        &super::sequence::encode_sequence(victim),
        39_001,
    )
    .expect_err("NativeProjected durable row cannot serve as replacement evidence");
    assert!(matches!(
        trim_error,
        RuntimeStoreError::PublicationNeedsSnapshot
    ));
    drop(raw);
    let before_reopen = snapshot_durable_evidence(&root.database());
    assert_eq!(before_reopen.snapshot_rows, 1);
    assert_eq!(before_reopen.ledger_snapshot_count, 1);

    let failure = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await;
    match failure {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(other) => panic!("native snapshot recovery returned wrong error: {other:?}"),
        Ok(store) => {
            store
                .shutdown()
                .await
                .expect("shutdown unexpectedly accepted native snapshot store");
            panic!("recovery accepted authenticated NativeProjected snapshot row");
        }
    }
    assert_eq!(
        snapshot_durable_evidence(&root.database()),
        before_reopen,
        "rejected recovery must leave snapshots/events/ledger/main+WAL byte-exact"
    );
}

#[tokio::test]
async fn completed_generation_and_plan_capabilities_cannot_cross_store_reopen() {
    let root = TestRoot::new("capability-cross-reopen");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(40_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&reference(15), [0x28; 16]))
        .await
        .expect("import cross-reopen capability fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("cross-reopen capability fixture must import");
    };
    clock.set(40_001);
    let old_completed = projector
        .accept_completed_scan(completed_scan([0x29; 16], 0))
        .await
        .expect("accept completed generation before reopen");
    let old_plan = projector
        .plan_completed_page(old_completed.clone(), None)
        .await
        .expect("plan reconciliation before reopen");
    assert_eq!(
        old_plan.candidate_ids().collect::<Vec<_>>(),
        [conversation.conversation_id]
    );
    drop(projector);
    store
        .shutdown()
        .await
        .expect("shutdown old capability owner");

    let reopened = open_store(&root, &keys, clock).await;
    let reopened_projector = reopened.claude_code_native_projection_store();
    let before = lifecycle_evidence(&root.database());
    let before_artifacts = durable_artifact_bytes(&root.database());
    let token_error = reopened_projector
        .plan_completed_page(old_completed, None)
        .await
        .expect_err("old completed generation must not cross store reopen");
    assert!(matches!(
        token_error,
        RuntimeStoreError::InvalidStateTransition
    ));
    let plan_error = reopened_projector
        .apply_completed_page(
            old_plan,
            vec![NativeProjectionCandidateDisposition::Quiescent(
                conversation.conversation_id,
            )],
        )
        .await
        .expect_err("old reconciliation plan must not cross store reopen");
    assert!(matches!(
        plan_error,
        RuntimeStoreError::InvalidStateTransition
    ));
    assert_eq!(durable_artifact_bytes(&root.database()), before_artifacts);
    assert_eq!(lifecycle_evidence(&root.database()), before);
    assert_eq!(
        projection_state(&root.database(), conversation.conversation_id),
        "present"
    );
    drop(reopened_projector);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened capability owner");
}

#[tokio::test]
async fn tombstone_and_retired_reappearance_reuse_identity_and_configuration() {
    let root = TestRoot::new("reappearance-retirement");
    let keys = MemoryKeyStore::new();
    let tombstoned_at = 100_000;
    let clock = ManualClock::new(tombstoned_at - 1);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let private_reference = reference(4);
    let imported = projector
        .import(import_input(&private_reference, [0x31; 16]))
        .await
        .expect("import reappearance fixture");
    let ImportNativeProjectionOutcome::Imported {
        conversation: original_conversation,
        configuration: original_configuration,
    } = imported
    else {
        panic!("reappearance fixture must import");
    };

    clock.set(tombstoned_at);
    let (conversation_id, _) = tombstone_single(&store, [0x32; 16]).await;
    assert_eq!(conversation_id, original_conversation.conversation_id);
    let tombstone_evidence = lifecycle_evidence(&root.database());
    assert_eq!(tombstone_evidence.catalog_rows, 2);
    assert_eq!(tombstone_evidence.vault_rows, 1);

    clock.set(tombstoned_at + 1);
    let tombstone_reappearance = projector
        .import(import_input(&private_reference, [0x33; 16]))
        .await
        .expect("reimport tombstoned native projection");
    let ImportNativeProjectionOutcome::Reappeared {
        conversation: tombstone_conversation,
        configuration: tombstone_configuration,
    } = tombstone_reappearance
    else {
        panic!("tombstone reimport must be Reappeared");
    };
    assert_eq!(tombstone_conversation.conversation_id, conversation_id);
    assert_eq!(tombstone_configuration, original_configuration);
    assert_eq!(
        projection_state(&root.database(), conversation_id),
        "present"
    );
    assert_eq!(lifecycle_evidence(&root.database()).catalog_rows, 3);
    assert_eq!(lifecycle_evidence(&root.database()).vault_rows, 1);

    let second_tombstone_at = 200_000;
    clock.set(second_tombstone_at);
    let (second_id, _) = tombstone_single(&store, [0x34; 16]).await;
    assert_eq!(second_id, conversation_id);
    let catalog_before_retirement = lifecycle_evidence(&root.database());
    assert_eq!(catalog_before_retirement.catalog_rows, 4);
    let deadline = second_tombstone_at + TOMBSTONE_RETENTION_MS;

    clock.set(deadline - 1);
    let early_plan = projector
        .plan_retirement_page(None)
        .await
        .expect("plan retirement one millisecond before deadline");
    let early = projector
        .apply_retirement_page(early_plan)
        .await
        .expect("early retirement page is a no-op");
    assert!(matches!(
        early,
        RetireNativeProjectionOutcome::Applied {
            retired: 0,
            next_cursor: None,
        }
    ));
    assert_eq!(
        lifecycle_evidence(&root.database()),
        catalog_before_retirement
    );

    clock.set(deadline);
    let retirement_plan = projector
        .plan_retirement_page(None)
        .await
        .expect("plan retirement at exact deadline");
    let retired = projector
        .apply_retirement_page(retirement_plan.clone())
        .await
        .expect("retire native projection at exact deadline");
    assert!(matches!(
        retired,
        RetireNativeProjectionOutcome::Applied {
            retired: 1,
            next_cursor: None,
        }
    ));
    let retired_evidence = lifecycle_evidence(&root.database());
    assert_eq!(retired_evidence.present, 0);
    assert_eq!(retired_evidence.tombstone, 0);
    assert_eq!(retired_evidence.retired, 1);
    assert_eq!(retired_evidence.vault_rows, 0);
    assert_eq!(
        retired_evidence.catalog_rows,
        catalog_before_retirement.catalog_rows
    );
    assert_eq!(
        retired_evidence.catalog_high_water, catalog_before_retirement.catalog_high_water,
        "retirement must not advance Catalog"
    );
    assert!(
        store
            .claude_code_adapter_state_vault()
            .resolve(original_conversation.adapter_state_key)
            .await
            .expect("resolve retired private binding")
            .is_none(),
        "exact-deadline retirement deletes the private binding"
    );
    let retirement_replay = projector
        .apply_retirement_page(retirement_plan)
        .await
        .expect("exact retirement retry reads committed post-state");
    assert!(matches!(
        retirement_replay,
        RetireNativeProjectionOutcome::Replayed {
            retired: 1,
            next_cursor: None,
        }
    ));
    assert_eq!(lifecycle_evidence(&root.database()), retired_evidence);

    clock.set(deadline + 1);
    let retired_reappearance = projector
        .import(import_input(&private_reference, [0x35; 16]))
        .await
        .expect("reimport retired native projection");
    let ImportNativeProjectionOutcome::Reappeared {
        conversation: retired_conversation,
        configuration: retired_configuration,
    } = retired_reappearance
    else {
        panic!("retired reimport must be Reappeared");
    };
    assert_eq!(retired_conversation.conversation_id, conversation_id);
    assert_eq!(retired_configuration, original_configuration);
    let restored = store
        .claude_code_adapter_state_vault()
        .resolve(original_conversation.adapter_state_key)
        .await
        .expect("resolve restored retired binding")
        .expect("retired reappearance restores exact private binding");
    assert_eq!(restored.expose_secret(), private_reference.as_slice());
    let reappeared_evidence = lifecycle_evidence(&root.database());
    assert_eq!(reappeared_evidence.present, 1);
    assert_eq!(reappeared_evidence.tombstone, 0);
    assert_eq!(reappeared_evidence.retired, 0);
    assert_eq!(reappeared_evidence.vault_rows, 1);
    assert_eq!(reappeared_evidence.catalog_rows, 5);

    let changes = catalog_changes(&store).await;
    assert_eq!(changes.len(), 5);
    for (index, change) in changes.iter().enumerate() {
        match (index, change) {
            (0 | 2 | 4, CatalogChange::Upserted { entry }) => assert_eq!(
                entry.conversation_id.as_str(),
                conversation_id.to_canonical_string(),
                "reappearance must Upsert the same native identity"
            ),
            (
                1 | 3,
                CatalogChange::Removed {
                    conversation_id: removed,
                },
            ) => assert_eq!(
                removed.as_str(),
                conversation_id.to_canonical_string(),
                "tombstone must Remove the same native identity"
            ),
            _ => panic!("Catalog backfill must preserve Upsert/Removed/reappear ordering"),
        }
    }
    store
        .shutdown()
        .await
        .expect("shutdown reappearance lifecycle store");
}

#[tokio::test]
async fn nonlive_projection_blocks_public_command_and_generic_vault_mutations_across_reopen() {
    let root = TestRoot::new("nonlive-public-api-guards");
    let keys = MemoryKeyStore::new();
    let tombstoned_at = 250_000;
    let clock = ManualClock::new(tombstoned_at - 1);
    let private_reference = reference(13);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&private_reference, [0x53; 16]))
        .await
        .expect("import nonlive public API fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("nonlive public API fixture must import");
    };

    clock.set(tombstoned_at);
    let (conversation_id, _) = tombstone_single(&store, [0x54; 16]).await;
    assert_eq!(conversation_id, conversation.conversation_id);
    let tombstone_evidence = lifecycle_evidence(&root.database());
    let tombstone_artifacts = durable_artifact_bytes(&root.database());
    let accept_error = store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(0x55),
            idempotency_key: "native-tombstone-must-not-accept".to_owned(),
            expected_configuration_revision: 1,
            payload: b"must remain zero write".to_vec(),
        })
        .await
        .expect_err("tombstone must reject public command acceptance");
    assert!(matches!(
        accept_error,
        RuntimeStoreError::InvalidStateTransition
    ));
    assert_eq!(accepted_command_count(&root.database(), conversation_id), 0);
    assert_eq!(
        durable_artifact_bytes(&root.database()),
        tombstone_artifacts
    );
    assert_eq!(lifecycle_evidence(&root.database()), tombstone_evidence);

    let resolve_error = store
        .claude_code_adapter_state_vault()
        .resolve(conversation.adapter_state_key)
        .await
        .expect_err("generic vault must not reveal a retained tombstone reference");
    assert!(matches!(
        resolve_error,
        RuntimeStoreError::InvalidStateTransition
    ));
    assert_eq!(
        durable_artifact_bytes(&root.database()),
        tombstone_artifacts
    );
    assert_eq!(lifecycle_evidence(&root.database()), tombstone_evidence);
    store
        .shutdown()
        .await
        .expect("shutdown tombstone public API fixture");

    let store = open_store(&root, &keys, clock.clone()).await;
    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin tombstone recovery after reopen");
    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load tombstone recovery page");
    assert!(page.conversation.is_none());
    assert!(page.next_cursor.is_none());
    store
        .finish_recovery_scan(
            page.completion
                .expect("tombstone recovery signs terminal completion"),
        )
        .await
        .expect("finish tombstone recovery after reopen");

    let deadline = tombstoned_at + TOMBSTONE_RETENTION_MS;
    clock.set(deadline);
    let projector = store.claude_code_native_projection_store();
    let retirement_plan = projector
        .plan_retirement_page(None)
        .await
        .expect("plan nonlive public API retirement");
    let retired = projector
        .apply_retirement_page(retirement_plan)
        .await
        .expect("retire nonlive public API fixture");
    assert!(matches!(
        retired,
        RetireNativeProjectionOutcome::Applied {
            retired: 1,
            next_cursor: None,
        }
    ));
    let retired_evidence = lifecycle_evidence(&root.database());
    assert_eq!(retired_evidence.retired, 1);
    assert_eq!(retired_evidence.vault_rows, 0);
    let retired_artifacts = durable_artifact_bytes(&root.database());
    let bind_error = store
        .claude_code_adapter_state_vault()
        .bind(
            conversation.adapter_state_key,
            SecretBytes::new(private_reference.clone()),
        )
        .await
        .expect_err("generic vault must not resurrect a retired native binding");
    assert!(matches!(
        bind_error,
        RuntimeStoreError::InvalidStateTransition
    ));
    assert_eq!(durable_artifact_bytes(&root.database()), retired_artifacts);
    assert_eq!(lifecycle_evidence(&root.database()), retired_evidence);
    store
        .shutdown()
        .await
        .expect("shutdown retired public API fixture");

    let reopened = open_store(&root, &keys, clock).await;
    assert_eq!(lifecycle_evidence(&root.database()), retired_evidence);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened retired public API fixture");
}

#[tokio::test]
async fn reconciliation_before_and_after_commit_faults_converge_on_exact_plan_retry() {
    for (label, fault, expected_error) in [
        (
            "before-commit",
            RuntimeStoreOperation::ReconcileNativeProjectionBeforeCommit,
            None,
        ),
        (
            "after-commit",
            RuntimeStoreOperation::ReconcileNativeProjectionAfterCommit,
            Some(RuntimeCommitOperation::ReconcileNativeProjection),
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(300_000);
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database())
                .with_clock(clock.clone())
                .with_fault_injector(Arc::new(OneShotFault::new(fault))),
            root.storage_kek(&keys),
        )
        .await
        .expect("open reconciliation fault fixture");
        let projector = store.claude_code_native_projection_store();
        let imported = projector
            .import(import_input(&reference(5), [0x41; 16]))
            .await
            .expect("import reconciliation fault fixture");
        let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
            panic!("fault fixture must import");
        };
        clock.set(300_001);
        let completed = projector
            .accept_completed_scan(completed_scan([0x42; 16], 0))
            .await
            .expect("accept reconciliation fault complete scan");
        let plan = projector
            .plan_completed_page(completed, None)
            .await
            .expect("plan reconciliation fault page");
        let dispositions = vec![NativeProjectionCandidateDisposition::Quiescent(
            conversation.conversation_id,
        )];
        let error = projector
            .apply_completed_page(plan.clone(), dispositions.clone())
            .await
            .expect_err("injected reconciliation fault must fail first reply");
        match expected_error {
            None => {
                assert!(matches!(error, RuntimeStoreError::WorkerStopped));
                assert_eq!(
                    projection_state(&root.database(), conversation.conversation_id),
                    "present"
                );
                assert_eq!(lifecycle_evidence(&root.database()).catalog_rows, 1);
                let retry = projector
                    .apply_completed_page(plan, dispositions)
                    .await
                    .expect("before-COMMIT exact plan retry applies once");
                assert!(matches!(
                    retry,
                    ReconcileNativeProjectionOutcome::Applied {
                        removed: 1,
                        deferred_busy: 0,
                        next_cursor: None,
                    }
                ));
            }
            Some(operation) => {
                assert!(matches!(
                    error,
                    RuntimeStoreError::CommitOutcomeUnknown { operation: actual }
                        if actual == operation
                ));
                assert_eq!(
                    projection_state(&root.database(), conversation.conversation_id),
                    "tombstone"
                );
                assert_eq!(lifecycle_evidence(&root.database()).catalog_rows, 2);
                let newer_completed = projector
                    .accept_completed_scan(completed_scan([0x43; 16], 0))
                    .await
                    .expect("advance scan epoch after reconciliation commit");
                drop(newer_completed);
                let committed = lifecycle_evidence(&root.database());
                let retry = projector
                    .apply_completed_page(plan, dispositions)
                    .await
                    .expect("after-COMMIT exact plan retry replays");
                assert!(matches!(
                    retry,
                    ReconcileNativeProjectionOutcome::Replayed {
                        removed: 1,
                        deferred_busy: 0,
                        next_cursor: None,
                    }
                ));
                assert_eq!(lifecycle_evidence(&root.database()), committed);
            }
        }
        assert_eq!(
            projection_state(&root.database(), conversation.conversation_id),
            "tombstone"
        );
        assert_eq!(lifecycle_evidence(&root.database()).catalog_rows, 2);
        store
            .shutdown()
            .await
            .expect("shutdown reconciliation fault fixture");
    }
}

#[tokio::test]
async fn reconciliation_exact_post_state_replays_before_capacity_admission() {
    let root = TestRoot::new("reconcile-post-before-admission");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(325_000);
    let probe = SwitchableCapacityProbe::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_capacity_probe(probe.clone())
            .with_fault_injector(Arc::new(OneShotFault::new(
                RuntimeStoreOperation::ReconcileNativeProjectionAfterCommit,
            ))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open post-state admission ordering fixture");
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&reference(12), [0x4D; 16]))
        .await
        .expect("import post-state admission ordering fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("post-state admission ordering fixture must import");
    };
    clock.set(325_001);
    let completed = projector
        .accept_completed_scan(completed_scan([0x4E; 16], 0))
        .await
        .expect("accept post-state admission complete scan");
    let plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("plan post-state admission reconciliation");
    let dispositions = vec![NativeProjectionCandidateDisposition::Quiescent(
        conversation.conversation_id,
    )];
    let error = projector
        .apply_completed_page(plan.clone(), dispositions.clone())
        .await
        .expect_err("after-COMMIT response loss must report unknown outcome");
    assert!(matches!(
        error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ReconcileNativeProjection,
        }
    ));
    assert_eq!(
        projection_state(&root.database(), conversation.conversation_id),
        "tombstone"
    );

    let calls_after_commit = probe.calls();
    let committed = lifecycle_evidence(&root.database());
    let committed_artifacts = durable_artifact_bytes(&root.database());
    probe.reject();
    let replay = projector
        .apply_completed_page(plan, dispositions)
        .await
        .expect("exact post-state retry must bypass rejected capacity probe");
    assert!(matches!(
        replay,
        ReconcileNativeProjectionOutcome::Replayed {
            removed: 1,
            deferred_busy: 0,
            next_cursor: None,
        }
    ));
    assert_eq!(
        probe.calls(),
        calls_after_commit,
        "exact post-state replay must occur before capacity admission"
    );
    assert_eq!(
        durable_artifact_bytes(&root.database()),
        committed_artifacts
    );
    assert_eq!(lifecycle_evidence(&root.database()), committed);
    store
        .shutdown()
        .await
        .expect("shutdown post-state admission ordering fixture");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_linearizes_reconciliation_before_a_later_reappearance() {
    let root = TestRoot::new("worker-reconcile-before-import");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(340_000);
    let (gate, entered, release) =
        OperationGate::new(RuntimeStoreOperation::ReconcileNativeProjectionBeforeCommit);
    let gate = Arc::new(gate);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(gate.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open reconcile-first worker ordering fixture");
    let projector = store.claude_code_native_projection_store();
    let native_reference = reference(340);
    let imported = projector
        .import(import_input(&native_reference, [0x71; 16]))
        .await
        .expect("import reconcile-first worker ordering fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("reconcile-first worker ordering fixture must import");
    };

    clock.set(340_001);
    let completed = projector
        .accept_completed_scan(completed_scan([0x72; 16], 0))
        .await
        .expect("accept reconcile-first completed scan");
    let plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("plan reconcile-first page");
    let dispositions = vec![NativeProjectionCandidateDisposition::Quiescent(
        conversation.conversation_id,
    )];

    gate.arm();
    let applying_projector = projector.clone();
    let apply_task = tokio::spawn(async move {
        applying_projector
            .apply_completed_page(plan, dispositions)
            .await
    });
    cross_operation_gate(entered).await;

    let later_import = projector.import(import_input(&native_reference, [0x72; 16]));
    tokio::pin!(later_import);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), &mut later_import)
            .await
            .is_err(),
        "later import must remain queued while reconciliation owns the worker"
    );
    cross_operation_gate(release).await;

    let applied = apply_task
        .await
        .expect("reconcile-first task must not panic")
        .expect("reconcile-first page must commit");
    assert!(matches!(
        applied,
        ReconcileNativeProjectionOutcome::Applied {
            removed: 1,
            deferred_busy: 0,
            next_cursor: None,
        }
    ));
    let reappeared = later_import
        .await
        .expect("later import must reappear after reconciliation");
    assert!(matches!(
        reappeared,
        ImportNativeProjectionOutcome::Reappeared {
            conversation: ref restored,
            ..
        } if restored.conversation_id == conversation.conversation_id
    ));
    assert_eq!(
        projection_state(&root.database(), conversation.conversation_id),
        "present"
    );
    store
        .shutdown()
        .await
        .expect("shutdown reconcile-first worker ordering fixture");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_linearizes_import_before_a_stale_reconciliation_plan() {
    let root = TestRoot::new("worker-import-before-reconcile");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(350_000);
    let (gate, entered, release) =
        OperationGate::new(RuntimeStoreOperation::ImportNativeProjectionBeforeCommit);
    let gate = Arc::new(gate);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(gate.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open import-first worker ordering fixture");
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&reference(350), [0x73; 16]))
        .await
        .expect("import original import-first fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("import-first worker ordering fixture must import");
    };

    clock.set(350_001);
    let completed = projector
        .accept_completed_scan(completed_scan([0x74; 16], 0))
        .await
        .expect("accept import-first completed scan");
    let plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("plan import-first stale page");
    let dispositions = vec![NativeProjectionCandidateDisposition::Quiescent(
        conversation.conversation_id,
    )];

    gate.arm();
    let importing_projector = projector.clone();
    let import_task = tokio::spawn(async move {
        importing_projector
            .import(import_input(&reference(351), [0x74; 16]))
            .await
    });
    cross_operation_gate(entered).await;

    let stale_apply = projector.apply_completed_page(plan, dispositions);
    tokio::pin!(stale_apply);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), &mut stale_apply)
            .await
            .is_err(),
        "stale apply must remain queued while import owns the worker"
    );
    cross_operation_gate(release).await;

    assert!(matches!(
        import_task
            .await
            .expect("import-first task must not panic")
            .expect("import-first command must commit"),
        ImportNativeProjectionOutcome::Imported { .. }
    ));
    let stale_error = stale_apply
        .await
        .expect_err("later reconciliation must reject the import-advanced epoch");
    assert!(matches!(
        stale_error,
        RuntimeStoreError::InvalidStateTransition
    ));
    assert_eq!(
        projection_state(&root.database(), conversation.conversation_id),
        "present"
    );
    assert_eq!(lifecycle_evidence(&root.database()).present, 2);
    store
        .shutdown()
        .await
        .expect("shutdown import-first worker ordering fixture");
}

#[tokio::test]
async fn retirement_before_and_after_commit_faults_converge_on_exact_plan_retry() {
    for (label, fault, expected_error) in [
        (
            "retire-before-commit",
            RuntimeStoreOperation::RetireNativeProjectionBeforeCommit,
            None,
        ),
        (
            "retire-after-commit",
            RuntimeStoreOperation::RetireNativeProjectionAfterCommit,
            Some(RuntimeCommitOperation::RetireNativeProjection),
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let tombstoned_at = 350_000;
        let clock = ManualClock::new(tombstoned_at - 1);
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database())
                .with_clock(clock.clone())
                .with_fault_injector(Arc::new(OneShotFault::new(fault))),
            root.storage_kek(&keys),
        )
        .await
        .expect("open retirement fault fixture");
        let projector = store.claude_code_native_projection_store();
        let imported = projector
            .import(import_input(&reference(9), [0x43; 16]))
            .await
            .expect("import retirement fault fixture");
        let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
            panic!("retirement fault fixture must import");
        };
        clock.set(tombstoned_at);
        let (tombstoned_id, _) = tombstone_single(&store, [0x44; 16]).await;
        assert_eq!(tombstoned_id, conversation.conversation_id);
        let deadline = tombstoned_at + TOMBSTONE_RETENTION_MS;
        clock.set(deadline);
        let plan = projector
            .plan_retirement_page(None)
            .await
            .expect("plan retirement fault page");
        let before = lifecycle_evidence(&root.database());
        let before_artifacts = durable_artifact_bytes(&root.database());
        let error = projector
            .apply_retirement_page(plan.clone())
            .await
            .expect_err("injected retirement fault must fail first reply");
        match expected_error {
            None => {
                assert!(matches!(error, RuntimeStoreError::WorkerStopped));
                assert_eq!(durable_artifact_bytes(&root.database()), before_artifacts);
                assert_eq!(lifecycle_evidence(&root.database()), before);
                assert_eq!(
                    projection_state(&root.database(), conversation.conversation_id),
                    "tombstone"
                );
                let retry = projector
                    .apply_retirement_page(plan)
                    .await
                    .expect("before-COMMIT exact retirement retry applies once");
                assert!(matches!(
                    retry,
                    RetireNativeProjectionOutcome::Applied {
                        retired: 1,
                        next_cursor: None,
                    }
                ));
            }
            Some(operation) => {
                assert!(matches!(
                    error,
                    RuntimeStoreError::CommitOutcomeUnknown { operation: actual }
                        if actual == operation
                ));
                assert_eq!(
                    projection_state(&root.database(), conversation.conversation_id),
                    "retired"
                );
                let committed = lifecycle_evidence(&root.database());
                assert_eq!(committed.catalog_rows, before.catalog_rows);
                assert_eq!(committed.catalog_high_water, before.catalog_high_water);
                let committed_artifacts = durable_artifact_bytes(&root.database());
                let retry = projector
                    .apply_retirement_page(plan)
                    .await
                    .expect("after-COMMIT exact retirement retry replays");
                assert!(matches!(
                    retry,
                    RetireNativeProjectionOutcome::Replayed {
                        retired: 1,
                        next_cursor: None,
                    }
                ));
                assert_eq!(
                    durable_artifact_bytes(&root.database()),
                    committed_artifacts
                );
                assert_eq!(lifecycle_evidence(&root.database()), committed);
            }
        }
        let retired = lifecycle_evidence(&root.database());
        assert_eq!(retired.present, 0);
        assert_eq!(retired.tombstone, 0);
        assert_eq!(retired.retired, 1);
        assert_eq!(retired.vault_rows, 0);
        assert_eq!(retired.catalog_rows, 2);
        store
            .shutdown()
            .await
            .expect("shutdown retirement fault fixture");
    }
}

#[tokio::test]
async fn reconciliation_clock_regression_is_zero_write_and_preserves_exact_evidence() {
    let root = TestRoot::new("clock-regression");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(100);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&reference(8), [0x48; 16]))
        .await
        .expect("import clock-regression fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("clock-regression fixture must import");
    };
    // 该测试需要在 plan 之后推进某个 authenticated conversation 的 updatedAt，
    // 但 NativeProjected 已不允许用 SendPrompt 达成。先创建并配置独立 Managed
    // conversation，之后只在它上面接受 command，保持 native origin 边界不被破坏。
    let managed_conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x6a; 16]).expect("managed id");
    let managed_adapter_state_key =
        RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x6b; 16]).expect("managed state key");
    store
        .create_conversation(NewConversation {
            conversation_id: managed_conversation_id,
            adapter_state_key: managed_adapter_state_key,
            descriptor: descriptor(),
        })
        .await
        .expect("create managed clock-regression control");
    store
        .configure_conversation(ConfigureConversation {
            conversation_id: managed_conversation_id,
            owner: owner(0x6c),
            idempotency_key: "managed-clock-regression-configuration".to_owned(),
            expected_configuration_revision: 0,
            configuration: configuration(),
        })
        .await
        .expect("configure managed clock-regression control");

    clock.set(150);
    let completed = projector
        .accept_completed_scan(completed_scan([0x49; 16], 0))
        .await
        .expect("accept complete scan after the target observation");
    let plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("plan absent projection before a newer durable update");
    assert_eq!(
        plan.candidate_ids().collect::<Vec<_>>(),
        [conversation.conversation_id]
    );

    clock.set(200);
    assert!(matches!(
        store
            .accept_command(AcceptCommand {
                conversation_id: managed_conversation_id,
                owner: owner(0x49),
                idempotency_key: "managed-clock-regression-accepted".to_owned(),
                expected_configuration_revision: 1,
                payload: b"advance authenticated conversation time".to_vec(),
            })
            .await
            .expect("persist a newer authenticated conversation update"),
        AcceptOutcome::Accepted { .. }
    ));
    let before_cardinality = lifecycle_evidence(&root.database());
    let before_artifacts = durable_artifact_bytes(&root.database());
    let error = projector
        .apply_completed_page(
            plan,
            vec![NativeProjectionCandidateDisposition::Quiescent(
                conversation.conversation_id,
            )],
        )
        .await
        .expect_err("regressed reconciliation clock must fail closed");
    assert!(matches!(
        error,
        RuntimeStoreError::ClockRegressed {
            persisted_ms: 200,
            observed_ms: 150,
        }
    ));
    assert_eq!(durable_artifact_bytes(&root.database()), before_artifacts);
    assert_eq!(lifecycle_evidence(&root.database()), before_cardinality);
    assert_eq!(
        projection_state(&root.database(), conversation.conversation_id),
        "present"
    );
    store
        .shutdown()
        .await
        .expect("shutdown clock-regression lifecycle store");
}

#[tokio::test]
async fn native_present_command_admission_is_zero_write_across_reopen() {
    let root = TestRoot::new("native-command-admission-gate");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(375_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let imported = projector
        .import(import_input(&reference(11), [0x4A; 16]))
        .await
        .expect("import native command admission fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("native command admission fixture must import");
    };
    let before = command_admission_evidence(&root.database(), conversation.conversation_id);
    let error = store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: owner(0x4B),
            idempotency_key: "native-command-must-not-persist".to_owned(),
            expected_configuration_revision: 1,
            payload: b"native command must remain history-only".to_vec(),
        })
        .await
        .expect_err("present NativeProjected conversation must reject durable command");
    assert_eq!(
        error.code(),
        agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_FEATURE_UNAVAILABLE
    );
    assert!(matches!(
        error,
        RuntimeStoreError::CommandAdmissionUnsupported
    ));
    assert_eq!(
        command_admission_evidence(&root.database(), conversation.conversation_id),
        before,
        "native rejection must not change command/pin/event/HWM/ledger/main+WAL"
    );
    store
        .shutdown()
        .await
        .expect("shutdown native command admission fixture");

    let reopened = open_store(&root, &keys, clock).await;
    let reopened_before =
        command_admission_evidence(&root.database(), conversation.conversation_id);
    let reopened_error = reopened
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: owner(0x4C),
            idempotency_key: "native-command-must-not-persist-after-reopen".to_owned(),
            expected_configuration_revision: 1,
            payload: b"restart must preserve the origin admission gate".to_vec(),
        })
        .await
        .expect_err("reopened NativeProjected conversation must reject durable command");
    assert!(matches!(
        reopened_error,
        RuntimeStoreError::CommandAdmissionUnsupported
    ));
    assert_eq!(
        command_admission_evidence(&root.database(), conversation.conversation_id),
        reopened_before,
        "reopened native rejection must remain byte-exact and side-effect-free"
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened native command admission fixture");
}

#[tokio::test]
async fn reconciliation_uses_bounded_five_hundred_item_keyset_pages() {
    let root = TestRoot::new("five-hundred-plus-one");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(400_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();

    for index in 0..501 {
        let outcome = projector
            .import(import_input(&reference(10_000 + index), [0x51; 16]))
            .await
            .expect("import pagination projection fixture");
        assert!(matches!(
            outcome,
            ImportNativeProjectionOutcome::Imported { .. }
        ));
    }
    clock.set(400_001);
    let completed = projector
        .accept_completed_scan(completed_scan([0x52; 16], 0))
        .await
        .expect("accept paginated complete scan");
    let first = projector
        .plan_completed_page(completed.clone(), None)
        .await
        .expect("plan first bounded reconciliation page");
    let first_ids = first.candidate_ids().collect::<Vec<_>>();
    assert_eq!(first_ids.len(), 500);
    let cursor = first
        .next_cursor()
        .expect("full five-hundred-item page has keyset cursor");
    let second = projector
        .plan_completed_page(completed, Some(cursor))
        .await
        .expect("plan final one-item reconciliation page");
    let second_ids = second.candidate_ids().collect::<Vec<_>>();
    assert_eq!(second_ids.len(), 1);
    assert!(second.next_cursor().is_none());
    assert!(!first_ids.contains(&second_ids[0]));
    assert_eq!(lifecycle_evidence(&root.database()).present, 501);
    assert_eq!(lifecycle_evidence(&root.database()).catalog_rows, 501);
    store
        .shutdown()
        .await
        .expect("shutdown pagination lifecycle store");
}

#[tokio::test]
async fn recovery_yields_native_present_but_skips_nonlive_projection_rows() {
    let root = TestRoot::new("recovery-skips-nonlive");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(500_000);
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();
    let present = projector
        .import(import_input(&reference(6), [0x61; 16]))
        .await
        .expect("import present recovery projection");
    let nonlive = projector
        .import(import_input(&reference(7), [0x61; 16]))
        .await
        .expect("import nonlive recovery projection");
    let ImportNativeProjectionOutcome::Imported {
        conversation: present,
        ..
    } = present
    else {
        panic!("present recovery fixture must import");
    };
    let ImportNativeProjectionOutcome::Imported {
        conversation: nonlive,
        ..
    } = nonlive
    else {
        panic!("nonlive recovery fixture must import");
    };

    clock.set(500_001);
    assert!(matches!(
        projector
            .import(import_input(&reference(6), [0x62; 16]))
            .await
            .expect("observe retained present projection in complete scan"),
        ImportNativeProjectionOutcome::Reobserved { .. }
    ));
    let completed = projector
        .accept_completed_scan(completed_scan([0x62; 16], 1))
        .await
        .expect("accept recovery fixture complete scan");
    let plan = projector
        .plan_completed_page(completed, None)
        .await
        .expect("plan recovery fixture absent projection");
    assert_eq!(
        plan.candidate_ids().collect::<Vec<_>>(),
        [nonlive.conversation_id]
    );
    projector
        .apply_completed_page(
            plan,
            vec![NativeProjectionCandidateDisposition::Quiescent(
                nonlive.conversation_id,
            )],
        )
        .await
        .expect("tombstone nonlive recovery projection");

    let mut cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin native lifecycle recovery scan");
    let mut yielded = Vec::new();
    loop {
        let page = store
            .load_recovery_page(cursor)
            .await
            .expect("load native lifecycle recovery page");
        if let Some(record) = page.conversation {
            yielded.push(record.conversation.conversation_id);
        }
        if let Some(next) = page.next_cursor {
            cursor = next;
            continue;
        }
        store
            .finish_recovery_scan(
                page.completion
                    .expect("terminal native lifecycle page signs completion"),
            )
            .await
            .expect("finish native lifecycle recovery scan");
        break;
    }
    assert_eq!(yielded, [present.conversation_id]);
    assert!(!yielded.contains(&nonlive.conversation_id));
    store
        .shutdown()
        .await
        .expect("shutdown recovery lifecycle store");
}
