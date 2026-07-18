use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    CatalogChange, ClaudeCodeConversationConfiguration, ConversationConfiguration,
    ConversationConfigurationState, RuntimeEventBody, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentKind, ClaudeCodePermissionMode};
use rusqlite::Connection;

use super::identity::{MAX_RUNTIME_ID_COLLISION_ATTEMPTS, RuntimeIdError};
use super::{
    ConversationDescriptor, ImportNativeProjection, ImportNativeProjectionOutcome, NewConversation,
    RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeClock, RuntimeClockError,
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreHandle, RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, SecretBytes, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentdeck-native-projection-import-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create native projection import root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure native projection import root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load native projection import StorageKEK")
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImportCardinality {
    conversation_rows: i64,
    vault_rows: i64,
    configuration_rows: i64,
    event_rows: i64,
    event_stream_rows: i64,
    projection_rows: i64,
    catalog_rows: i64,
    ledger_conversations: i64,
    ledger_vault_rows: i64,
    ledger_configurations: i64,
    ledger_events: i64,
    ledger_event_stream_rows: i64,
    ledger_projection_present: i64,
    ledger_projection_physical: i64,
    ledger_catalog_rows: i64,
    catalog_high_water: Option<String>,
}

fn scalar(connection: &Connection, query: &str) -> i64 {
    connection
        .query_row(query, [], |row| row.get(0))
        .expect("read native projection import cardinality")
}

fn import_cardinality(database: &Path) -> ImportCardinality {
    let connection = Connection::open(database).expect("open native projection import evidence");
    let (
        ledger_conversations,
        ledger_vault_rows,
        ledger_configurations,
        ledger_events,
        ledger_event_stream_rows,
        ledger_projection_present,
        ledger_projection_physical,
        ledger_catalog_rows,
        catalog_high_water,
    ) = connection
        .query_row(
            "SELECT conversation_count, claude_code_adapter_state_count,
                    configuration_count, event_count, event_stream_count,
                    native_projection_present_count, native_projection_physical_count,
                    catalog_delta_count, catalog_high_water
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
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .expect("read authenticated native projection ledger totals");
    ImportCardinality {
        conversation_rows: scalar(&connection, "SELECT COUNT(*) FROM conversations"),
        vault_rows: scalar(
            &connection,
            "SELECT COUNT(*) FROM claude_code_adapter_state",
        ),
        configuration_rows: scalar(&connection, "SELECT COUNT(*) FROM configuration_journal"),
        event_rows: scalar(&connection, "SELECT COUNT(*) FROM event_journal"),
        event_stream_rows: scalar(&connection, "SELECT COUNT(*) FROM event_stream_index"),
        projection_rows: scalar(&connection, "SELECT COUNT(*) FROM native_projection_state"),
        catalog_rows: scalar(&connection, "SELECT COUNT(*) FROM catalog_journal"),
        ledger_conversations,
        ledger_vault_rows,
        ledger_configurations,
        ledger_events,
        ledger_event_stream_rows,
        ledger_projection_present,
        ledger_projection_physical,
        ledger_catalog_rows,
        catalog_high_water,
    }
}

fn empty_cardinality() -> ImportCardinality {
    ImportCardinality {
        conversation_rows: 0,
        vault_rows: 0,
        configuration_rows: 0,
        event_rows: 0,
        event_stream_rows: 0,
        projection_rows: 0,
        catalog_rows: 0,
        ledger_conversations: 0,
        ledger_vault_rows: 0,
        ledger_configurations: 0,
        ledger_events: 0,
        ledger_event_stream_rows: 0,
        ledger_projection_present: 0,
        ledger_projection_physical: 0,
        ledger_catalog_rows: 0,
        catalog_high_water: None,
    }
}

fn single_import_cardinality() -> ImportCardinality {
    ImportCardinality {
        conversation_rows: 1,
        vault_rows: 1,
        configuration_rows: 1,
        event_rows: 1,
        event_stream_rows: 1,
        projection_rows: 1,
        catalog_rows: 1,
        ledger_conversations: 1,
        ledger_vault_rows: 1,
        ledger_configurations: 1,
        ledger_events: 1,
        ledger_event_stream_rows: 1,
        ledger_projection_present: 1,
        ledger_projection_physical: 1,
        ledger_catalog_rows: 1,
        catalog_high_water: Some("00000000000000000000".to_owned()),
    }
}

fn projection_generation(database: &Path) -> Vec<u8> {
    Connection::open(database)
        .expect("open projection generation evidence")
        .query_row(
            "SELECT scan_generation FROM native_projection_state",
            [],
            |row| row.get(0),
        )
        .expect("read projection scan generation")
}

fn assert_artifacts_do_not_contain(database: &Path, sentinel: &[u8]) {
    assert!(!sentinel.is_empty());
    let mut observed = 0;
    for path in [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ] {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        observed += 1;
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel),
            "private native sentinel leaked into {}",
            path.display()
        );
    }
    assert!(observed >= 1, "runtime main/WAL/SHM artifacts are missing");
}

fn private_reference(length: usize, marker: &[u8]) -> Vec<u8> {
    assert!((20..=523).contains(&length));
    assert!(marker.len() <= length);
    let mut reference = vec![b'x'; length];
    reference[..marker.len()].copy_from_slice(marker);
    reference
}

fn neutral_descriptor() -> ConversationDescriptor {
    ConversationDescriptor {
        agent_kind: AgentKind::ClaudeCode,
        title: None,
        cwd: PathBuf::new(),
    }
}

fn changed_descriptor() -> ConversationDescriptor {
    ConversationDescriptor {
        agent_kind: AgentKind::ClaudeCode,
        title: Some("must not overwrite imported descriptor".to_owned()),
        cwd: PathBuf::from("/tmp/must-not-overwrite-native-projection"),
    }
}

fn claude_code_configuration(
    permission_mode: ClaudeCodePermissionMode,
    model: Option<&str>,
) -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            permission_mode,
            model.map(str::to_owned),
            None,
            None,
        )
        .expect("valid Claude Code configuration fixture"),
    ))
}

fn import_input(
    descriptor: ConversationDescriptor,
    default_configuration: ConversationConfiguration,
    reference: &[u8],
    scan_generation: [u8; 16],
) -> ImportNativeProjection {
    ImportNativeProjection {
        descriptor,
        default_configuration,
        private_reference: SecretBytes::new(reference.to_vec()),
        scan_generation,
    }
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
    .expect("open native projection import store")
}

async fn assert_initial_native_backfill(
    store: &RuntimeStoreHandle,
    conversation_id: super::RuntimeId,
    expected_configuration: &ConversationConfiguration,
) {
    let RuntimeBackfillPlan::Pinned(catalog_pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("pin native catalog import")
    else {
        panic!("native catalog revision zero must require backfill");
    };
    let catalog_page = store
        .load_catalog_backfill_page(catalog_pin.clone(), None)
        .await
        .expect("read native catalog import");
    assert_eq!(catalog_page.deltas.len(), 1);
    assert_eq!(catalog_page.deltas[0].catalog_revision, 0);
    assert_eq!(catalog_page.deltas[0].changes.len(), 1);
    let CatalogChange::Upserted { entry } = &catalog_page.deltas[0].changes[0] else {
        panic!("fresh native import must emit one Catalog Upsert");
    };
    assert_eq!(
        entry.conversation_id.as_str(),
        conversation_id.to_canonical_string()
    );
    assert_eq!(entry.agent_kind, AgentKind::ClaudeCode);
    assert_eq!(entry.title, None);
    assert_eq!(
        entry.cwd, None,
        "native Catalog must not expose the private cwd"
    );
    assert_eq!(entry.entry_revision, 0);
    let catalog_completion = catalog_page.completion().clone();
    drop(catalog_page);
    store
        .complete_backfill_page(catalog_completion)
        .await
        .expect("complete native catalog page");
    store
        .release_backfill_pin(catalog_pin.pin_id)
        .await
        .expect("release native catalog pin");

    let RuntimeBackfillPlan::Pinned(event_pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Conversation(conversation_id), None)
        .await
        .expect("pin native configuration event")
    else {
        panic!("native configuration event zero must require backfill");
    };
    let event_page = store
        .load_event_backfill_page(event_pin.clone(), None)
        .await
        .expect("read native configuration event");
    assert_eq!(event_page.events.len(), 1);
    assert_eq!(event_page.events[0].event_seq, 0);
    let RuntimeEventBody::ConfigurationChanged { state } = &event_page.events[0].body else {
        panic!("fresh native import must emit one ConfigurationChanged event");
    };
    assert_eq!(
        state,
        &ConversationConfigurationState::new(1, Some(expected_configuration.clone()))
            .expect("valid expected native configuration state")
    );
    let event_completion = event_page.completion().clone();
    drop(event_page);
    store
        .complete_backfill_page(event_completion)
        .await
        .expect("complete native event page");
    store
        .release_backfill_pin(event_pin.pin_id)
        .await
        .expect("release native event pin");
}

#[tokio::test]
async fn fresh_import_replay_reobserve_and_reopen_preserve_identity_configuration_and_privacy() {
    const PRIVATE_SENTINEL: &[u8; 20] = b"NPVT_SENTINEL_000001";
    let root = TestRoot::new("fresh-replay-reobserve");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10_000);
    let reference = private_reference(20, PRIVATE_SENTINEL);
    let default_configuration = claude_code_configuration(ClaudeCodePermissionMode::Default, None);
    let changed_configuration =
        claude_code_configuration(ClaudeCodePermissionMode::Plan, Some("different-model"));
    let store = open_store(&root, &keys, clock.clone()).await;
    let projector = store.claude_code_native_projection_store();

    let imported = projector
        .import(import_input(
            neutral_descriptor(),
            default_configuration.clone(),
            &reference,
            [0x11; 16],
        ))
        .await
        .expect("fresh native projection import");
    let ImportNativeProjectionOutcome::Imported {
        conversation,
        configuration,
    } = imported
    else {
        panic!("fresh native projection must be Imported");
    };
    assert_eq!(conversation.descriptor, neutral_descriptor());
    assert_eq!(conversation.catalog_revision, 0);
    assert_eq!(conversation.event_high_water, Some(0));
    assert_eq!(configuration.conversation_id, conversation.conversation_id);
    assert_eq!(configuration.configuration_revision, 1);
    assert_eq!(configuration.base_configuration_revision, 0);
    assert_eq!(configuration.event_seq, 0);
    assert_eq!(configuration.configuration, default_configuration);
    assert_initial_native_backfill(
        &store,
        conversation.conversation_id,
        &configuration.configuration,
    )
    .await;
    assert_eq!(
        import_cardinality(&root.database()),
        single_import_cardinality()
    );
    assert_eq!(projection_generation(&root.database()), vec![0x11; 16]);

    let replayed = projector
        .import(import_input(
            changed_descriptor(),
            changed_configuration.clone(),
            &reference,
            [0x11; 16],
        ))
        .await
        .expect("same-generation native projection replay");
    let ImportNativeProjectionOutcome::Replayed {
        conversation: replayed_conversation,
        configuration: replayed_configuration,
    } = replayed
    else {
        panic!("same generation must be Replayed");
    };
    assert_eq!(replayed_conversation, conversation);
    assert_eq!(replayed_configuration, configuration);
    assert_ne!(replayed_configuration.configuration, changed_configuration);
    assert_eq!(
        import_cardinality(&root.database()),
        single_import_cardinality()
    );
    assert_eq!(projection_generation(&root.database()), vec![0x11; 16]);

    clock.set(10_001);
    let reobserved = projector
        .import(import_input(
            changed_descriptor(),
            changed_configuration,
            &reference,
            [0x12; 16],
        ))
        .await
        .expect("different-generation native projection observation");
    let ImportNativeProjectionOutcome::Reobserved {
        conversation: reobserved_conversation,
        configuration: reobserved_configuration,
    } = reobserved
    else {
        panic!("different generation must be Reobserved");
    };
    assert_eq!(reobserved_conversation, conversation);
    assert_eq!(reobserved_configuration, configuration);
    assert_eq!(
        import_cardinality(&root.database()),
        single_import_cardinality()
    );
    assert_eq!(projection_generation(&root.database()), vec![0x12; 16]);
    assert_artifacts_do_not_contain(&root.database(), PRIVATE_SENTINEL);

    store
        .shutdown()
        .await
        .expect("shutdown imported native projection store");
    assert_artifacts_do_not_contain(&root.database(), PRIVATE_SENTINEL);

    let reopened = open_store(&root, &keys, clock).await;
    let reopened_projector = reopened.claude_code_native_projection_store();
    let reopened_replay = reopened_projector
        .import(import_input(
            changed_descriptor(),
            claude_code_configuration(ClaudeCodePermissionMode::BypassPermissions, None),
            &reference,
            [0x12; 16],
        ))
        .await
        .expect("authenticated reopen reads exact native projection");
    let ImportNativeProjectionOutcome::Replayed {
        conversation: reopened_conversation,
        configuration: reopened_configuration,
    } = reopened_replay
    else {
        panic!("same generation after reopen must replay");
    };
    assert_eq!(reopened_conversation, conversation);
    assert_eq!(reopened_configuration, configuration);
    let resolved = reopened
        .claude_code_adapter_state_vault()
        .resolve(conversation.adapter_state_key)
        .await
        .expect("resolve authenticated native private binding")
        .expect("native private binding exists");
    assert_eq!(resolved.expose_secret(), reference.as_slice());
    assert_eq!(
        import_cardinality(&root.database()),
        single_import_cardinality()
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened native projection store");
}

#[tokio::test]
async fn before_commit_fault_is_zero_write_and_identical_retry_imports_once() {
    let root = TestRoot::new("before-commit");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(20_000);
    let reference = private_reference(523, b"native-before-commit-private-sentinel");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock)
            .with_fault_injector(Arc::new(OneShotFault::new(
                RuntimeStoreOperation::ImportNativeProjectionBeforeCommit,
            ))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open before-COMMIT native projection store");
    let projector = store.claude_code_native_projection_store();

    let error = projector
        .import(import_input(
            neutral_descriptor(),
            claude_code_configuration(ClaudeCodePermissionMode::Default, None),
            &reference,
            [0x21; 16],
        ))
        .await
        .expect_err("before-COMMIT fault must roll back the native import");
    assert!(matches!(error, RuntimeStoreError::WorkerStopped));
    assert_eq!(import_cardinality(&root.database()), empty_cardinality());

    let retry = projector
        .import(import_input(
            neutral_descriptor(),
            claude_code_configuration(ClaudeCodePermissionMode::Default, None),
            &reference,
            [0x21; 16],
        ))
        .await
        .expect("identical retry imports after before-COMMIT rollback");
    assert!(matches!(
        retry,
        ImportNativeProjectionOutcome::Imported { .. }
    ));
    assert_eq!(
        import_cardinality(&root.database()),
        single_import_cardinality()
    );
    store
        .shutdown()
        .await
        .expect("shutdown before-COMMIT native projection store");
}

#[tokio::test]
async fn after_commit_unknown_exact_retry_is_read_only_replay_with_one_atomic_import() {
    let root = TestRoot::new("after-commit");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(30_000);
    let reference = private_reference(96, b"native-after-commit-private-sentinel");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock)
            .with_fault_injector(Arc::new(OneShotFault::new(
                RuntimeStoreOperation::ImportNativeProjectionAfterCommit,
            ))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open after-COMMIT native projection store");
    let projector = store.claude_code_native_projection_store();

    let error = projector
        .import(import_input(
            neutral_descriptor(),
            claude_code_configuration(ClaudeCodePermissionMode::Default, None),
            &reference,
            [0x31; 16],
        ))
        .await
        .expect_err("after-COMMIT response loss must be outcome unknown");
    assert!(matches!(
        error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ImportNativeProjection
        }
    ));
    let committed = import_cardinality(&root.database());
    assert_eq!(committed, single_import_cardinality());

    let retry = projector
        .import(import_input(
            changed_descriptor(),
            claude_code_configuration(ClaudeCodePermissionMode::Plan, Some("must-not-overwrite")),
            &reference,
            [0x31; 16],
        ))
        .await
        .expect("exact after-COMMIT rescan reads back the committed import");
    let ImportNativeProjectionOutcome::Replayed {
        conversation,
        configuration,
    } = retry
    else {
        panic!("exact after-COMMIT retry must be Replayed");
    };
    assert_eq!(conversation.descriptor, neutral_descriptor());
    assert_eq!(configuration.configuration_revision, 1);
    assert_eq!(configuration.event_seq, 0);
    assert_eq!(
        configuration.configuration,
        claude_code_configuration(ClaudeCodePermissionMode::Default, None)
    );
    assert_eq!(import_cardinality(&root.database()), committed);
    assert_eq!(projection_generation(&root.database()), vec![0x31; 16]);
    store
        .shutdown()
        .await
        .expect("shutdown after-COMMIT native projection store");
}

#[tokio::test]
async fn sixteen_occupied_identity_pairs_fail_without_partial_native_rows() {
    let root = TestRoot::new("identity-collision");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(40_000);
    let reference = private_reference(96, b"native-collision-private-sentinel");
    let generation = [0x41; 16];
    let store = open_store(&root, &keys, clock).await;
    let candidates = store
        .native_projection_identity_candidates_for_test(&reference, generation)
        .expect("derive bounded native identity candidates");
    assert_eq!(candidates.len(), MAX_RUNTIME_ID_COLLISION_ATTEMPTS);
    for (conversation_id, adapter_state_key) in candidates {
        store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key,
                descriptor: neutral_descriptor(),
            })
            .await
            .expect("occupy derived native identity pair with authenticated managed row");
    }
    let baseline_conversations = scalar(
        &Connection::open(root.database()).expect("open collision evidence"),
        "SELECT COUNT(*) FROM conversations",
    );
    assert_eq!(
        baseline_conversations,
        MAX_RUNTIME_ID_COLLISION_ATTEMPTS as i64
    );

    let error = store
        .claude_code_native_projection_store()
        .import(import_input(
            neutral_descriptor(),
            claude_code_configuration(ClaudeCodePermissionMode::Default, None),
            &reference,
            generation,
        ))
        .await
        .expect_err("all sixteen occupied pairs must exhaust native identity derivation");
    assert!(matches!(
        error,
        RuntimeStoreError::IdGeneration(RuntimeIdError::CollisionExhausted {
            attempts: MAX_RUNTIME_ID_COLLISION_ATTEMPTS,
            ..
        })
    ));
    let evidence = Connection::open(root.database()).expect("reopen collision evidence");
    assert_eq!(
        scalar(&evidence, "SELECT COUNT(*) FROM conversations"),
        baseline_conversations
    );
    assert_eq!(
        scalar(&evidence, "SELECT COUNT(*) FROM claude_code_adapter_state"),
        0
    );
    assert_eq!(
        scalar(&evidence, "SELECT COUNT(*) FROM configuration_journal"),
        0
    );
    assert_eq!(scalar(&evidence, "SELECT COUNT(*) FROM event_journal"), 0);
    assert_eq!(
        scalar(&evidence, "SELECT COUNT(*) FROM native_projection_state"),
        0
    );
    drop(evidence);
    store.shutdown().await.expect("shutdown collision store");
}

#[tokio::test]
async fn live_cap_rejects_new_reference_but_not_exact_replay() {
    let root = TestRoot::new("live-cap");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(50_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock)
            .with_conversation_capacity(1),
        root.storage_kek(&keys),
    )
    .await
    .expect("open one-live-conversation store");
    let projector = store.claude_code_native_projection_store();
    let first_reference = private_reference(64, b"native-live-cap-first");
    let second_reference = private_reference(64, b"native-live-cap-second");
    let input = || {
        import_input(
            neutral_descriptor(),
            claude_code_configuration(ClaudeCodePermissionMode::Default, None),
            &first_reference,
            [0x51; 16],
        )
    };
    assert!(matches!(
        projector.import(input()).await.expect("first live slot"),
        ImportNativeProjectionOutcome::Imported { .. }
    ));
    let baseline = import_cardinality(&root.database());
    assert!(matches!(
        projector
            .import(input())
            .await
            .expect("exact replay at live cap"),
        ImportNativeProjectionOutcome::Replayed { .. }
    ));
    let error = projector
        .import(import_input(
            neutral_descriptor(),
            claude_code_configuration(ClaudeCodePermissionMode::Default, None),
            &second_reference,
            [0x52; 16],
        ))
        .await
        .expect_err("second reference must be rejected at live cap");
    assert!(matches!(error, RuntimeStoreError::ConversationLimit));
    assert_eq!(import_cardinality(&root.database()), baseline);
    store.shutdown().await.expect("shutdown live cap store");
}
