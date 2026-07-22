#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentdeck_protocol::AgentKind;
use agentdeckd::runtime::store::{
    ConversationDescriptor, MAX_CONVERSATION_DESCRIPTOR_BYTES, MachineEnrollmentReceiptRecord,
    NewConversation, RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION, RuntimeId, RuntimeIdKind,
    RuntimeRescueIndex, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
    _permit: store_admission::Permit,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let permit = store_admission::acquire();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-store-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create isolated runtime store root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure runtime store root");
        }
        Self {
            path,
            _permit: permit,
        }
    }

    fn database(&self) -> PathBuf {
        self.path.join("runtime.db")
    }

    fn storage_kek(&self, store: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(store, &self.path.join("key-state.db"))
            .expect("create or reload test StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn conversation_descriptor_is_canonical_typed_and_rejects_vendor_identity_fields() {
    let descriptor = ConversationDescriptor {
        agent_kind: AgentKind::Codex,
        title: Some("neutral title".to_owned()),
        cwd: PathBuf::from("/tmp/neutral-project"),
    };
    let canonical = serde_json::to_vec(&descriptor).expect("serialize neutral descriptor");
    assert_eq!(
        canonical,
        br#"{"agentKind":"codex","title":"neutral title","cwd":"/tmp/neutral-project"}"#
    );

    for forbidden in ["threadId", "sessionId", "resumeReference", "vendorRef"] {
        let mut value = serde_json::to_value(&descriptor).expect("descriptor JSON value");
        value
            .as_object_mut()
            .expect("descriptor object")
            .insert(forbidden.to_owned(), serde_json::json!("private-sentinel"));
        assert!(
            serde_json::from_value::<ConversationDescriptor>(value).is_err(),
            "descriptor must reject {forbidden}"
        );
    }

    let input = NewConversation {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x21; 16])
            .expect("conversation id"),
        adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x22; 16])
            .expect("adapter state key"),
        descriptor: descriptor.clone(),
    };
    let _: &ConversationDescriptor = &input.descriptor;
    assert_eq!(input.descriptor, descriptor);
}

#[tokio::test]
async fn conversation_descriptor_canonical_bytes_have_an_exact_one_mib_limit() {
    let root = TestRoot::new("descriptor-size");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open descriptor size store");
    let mut descriptor = ConversationDescriptor {
        agent_kind: AgentKind::Codex,
        title: Some(String::new()),
        cwd: PathBuf::from("/tmp/descriptor-size"),
    };
    let fixed_bytes = serde_json::to_vec(&descriptor)
        .expect("serialize empty descriptor")
        .len();
    descriptor.title = Some("x".repeat(MAX_CONVERSATION_DESCRIPTOR_BYTES - fixed_bytes));
    assert_eq!(
        serde_json::to_vec(&descriptor)
            .expect("serialize exact descriptor")
            .len(),
        MAX_CONVERSATION_DESCRIPTOR_BYTES
    );
    store
        .create_conversation(NewConversation {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x31; 16])
                .expect("exact descriptor conversation id"),
            adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x32; 16])
                .expect("exact descriptor state key"),
            descriptor: descriptor.clone(),
        })
        .await
        .expect("exact one MiB descriptor is accepted");

    descriptor.title.as_mut().expect("title").push('x');
    let error = store
        .create_conversation(NewConversation {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x33; 16])
                .expect("oversized descriptor conversation id"),
            adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x34; 16])
                .expect("oversized descriptor state key"),
            descriptor,
        })
        .await
        .expect_err("one MiB plus one byte descriptor must be rejected");
    assert!(matches!(error, RuntimeStoreError::PayloadTooLarge));
    store
        .shutdown()
        .await
        .expect("shutdown descriptor size store");
}

fn conversation_input(seed: u8, descriptor: &[u8]) -> agentdeckd::runtime::store::NewConversation {
    agentdeckd::runtime::store::NewConversation {
        conversation_id: agentdeckd::runtime::store::RuntimeId::from_bytes(
            agentdeckd::runtime::store::RuntimeIdKind::Conversation,
            [seed; 16],
        )
        .expect("conversation id"),
        adapter_state_key: agentdeckd::runtime::store::RuntimeId::from_bytes(
            agentdeckd::runtime::store::RuntimeIdKind::AdapterState,
            [seed.wrapping_add(0x40); 16],
        )
        .expect("adapter state key"),
        descriptor: runtime_descriptor::descriptor(descriptor),
    }
}

struct BlockingFirstOperation {
    operation: RuntimeStoreOperation,
    blocked: AtomicBool,
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
    observed: Mutex<Vec<RuntimeStoreOperation>>,
}

struct FailBeforePublish;

impl RuntimeStoreFaultInjector for FailBeforePublish {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::InitializeBeforePublish {
            Err(RuntimeStoreError::InvalidConfig(
                "injected initialization failure",
            ))
        } else {
            Ok(())
        }
    }
}

impl RuntimeStoreFaultInjector for BlockingFirstOperation {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        self.observed
            .lock()
            .map_err(|_| RuntimeStoreError::WorkerStopped)?
            .push(operation);
        if operation == self.operation && !self.blocked.swap(true, Ordering::SeqCst) {
            self.entered
                .send(())
                .map_err(|_| RuntimeStoreError::WorkerStopped)?;
            self.release
                .lock()
                .map_err(|_| RuntimeStoreError::WorkerStopped)?
                .recv()
                .map_err(|_| RuntimeStoreError::WorkerStopped)?;
        }
        Ok(())
    }
}

fn artifact_bytes(database: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ]
    .into_iter()
    .map(|path| {
        let bytes = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read {}: {error}", path.display()),
        };
        (path, bytes)
    })
    .collect()
}

fn assert_artifacts_unchanged(
    before: &[(PathBuf, Option<Vec<u8>>)],
    after: &[(PathBuf, Option<Vec<u8>>)],
) {
    for ((before_path, before_bytes), (after_path, after_bytes)) in before.iter().zip(after) {
        assert_eq!(before_path, after_path);
        assert_eq!(
            before_bytes.as_ref().map(Vec::len),
            after_bytes.as_ref().map(Vec::len),
            "artifact length changed: {}",
            before_path.display()
        );
        if let (Some(before_bytes), Some(after_bytes)) = (before_bytes, after_bytes)
            && let Some((offset, (before_byte, after_byte))) = before_bytes
                .iter()
                .zip(after_bytes)
                .enumerate()
                .find(|(_, (before_byte, after_byte))| before_byte != after_byte)
        {
            panic!(
                "artifact changed at {} offset {offset}: {before_byte} -> {after_byte}",
                before_path.display()
            );
        }
    }
}

#[tokio::test]
async fn fresh_store_is_ready_only_after_exact_schema_and_pragmas_read_back() {
    let root = TestRoot::new("fresh");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open fresh runtime store");

    let snapshot = store.inspect().await.expect("inspect runtime store");
    assert_eq!(snapshot.schema_family, RUNTIME_SCHEMA_FAMILY);
    assert_eq!(snapshot.schema_version, RUNTIME_SCHEMA_VERSION);
    assert_eq!(snapshot.journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(snapshot.wal_autocheckpoint_pages, 0);
    assert_eq!(snapshot.synchronous, 2);
    assert!(snapshot.foreign_keys);
    assert_eq!(snapshot.busy_timeout_ms, 5_000);
    assert_eq!(snapshot.key_generation, 1);
    assert_eq!(snapshot.database_id.len(), 16);
    assert_eq!(
        snapshot.table_names,
        [
            "admin_commands",
            "approval_ledger",
            "catalog_journal",
            "claude_code_adapter_state",
            "codex_adapter_state",
            "command_configuration_pins",
            "commands",
            "configuration_journal",
            "conversation_state",
            "conversations",
            "event_journal",
            "event_retention",
            "event_stream_index",
            "execution_fences",
            "execution_intents",
            "machine_enrollment_receipts",
            "machine_identity_state",
            "machine_remote_state",
            "metadata_mutation_ledger",
            "native_metadata_effect_fences",
            "native_projection_state",
            "publication_outbox",
            "publication_streams",
            "remote_authorization_ledger",
            "remote_control_outbox",
            "remote_counter_guard_manifest",
            "remote_counter_states",
            "remote_key_directory",
            "remote_key_transitions",
            "remote_key_update_outbox",
            "remote_pairing_receipts",
            "remote_pairings",
            "remote_replay_states",
            "runtime_meta",
            "snapshots",
        ]
    );

    store.shutdown().await.expect("shutdown runtime store");
}

#[tokio::test]
async fn schema_v5_preserves_the_v4_idempotency_and_execution_linkage_contract() {
    let root = TestRoot::new("journal-schema-contract");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("create schema fixture");
    store.shutdown().await.expect("shutdown schema fixture");

    let connection = rusqlite::Connection::open(database).expect("open schema fixture");
    let table_columns = |table: &str| {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("prepare table_info");
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query table_info")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect columns")
    };
    let command_columns = table_columns("commands");
    for required in [
        "owner_token",
        "idempotency_token",
        "payload_token",
        "terminal_token",
        "turn_id",
        "started_event_id",
        "terminal_event_id",
    ] {
        assert!(
            command_columns.iter().any(|column| column == required),
            "commands is missing {required}"
        );
    }
    let intent_columns = table_columns("execution_intents");
    for required in ["turn_id", "started_event_id"] {
        assert!(
            intent_columns.iter().any(|column| column == required),
            "execution_intents is missing {required}"
        );
    }
    let indexes = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'index' AND tbl_name = 'commands' ORDER BY name",
        )
        .expect("prepare indexes")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query indexes")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect indexes");
    assert!(
        indexes
            .iter()
            .any(|name| name == "idx_commands_one_started")
    );
    assert!(
        indexes
            .iter()
            .any(|name| name == "idx_commands_owner_state")
    );
}

#[tokio::test]
async fn one_process_cannot_open_the_same_store_twice_and_shutdown_releases_the_lease() {
    let root = TestRoot::new("single-open");
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(root.database());
    let first = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("first open");

    let error = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect_err("second open must fail");
    assert!(matches!(error, RuntimeStoreError::StoreAlreadyOpen));

    first.shutdown().await.expect("shutdown first store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen after shutdown");
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[cfg(unix)]
#[tokio::test]
async fn database_and_live_sidecars_are_private_regular_single_link_files() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = TestRoot::new("private-files");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .record_machine_enrollment_receipt(MachineEnrollmentReceiptRecord {
            relay_server_id: [1; 16],
            machine_route: [2; 16],
            root_fingerprint: [3; 32],
        })
        .await
        .expect("force a WAL write");

    for path in [
        database.clone(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ] {
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("{} must exist: {error}", path.display()));
        assert!(metadata.file_type().is_file(), "{}", path.display());
        assert!(!metadata.file_type().is_symlink(), "{}", path.display());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn newer_schema_is_rejected_before_any_migration_write() {
    let root = TestRoot::new("newer-schema");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("create current store");
    store.shutdown().await.expect("shutdown current store");

    let connection = rusqlite::Connection::open(&database).expect("open fixture database");
    connection
        .execute(
            "UPDATE runtime_meta SET schema_version = ?1 WHERE singleton = 1",
            [i64::from(RUNTIME_SCHEMA_VERSION) + 1],
        )
        .expect("raise schema version");
    drop(connection);
    let before = fs::read(&database).expect("read newer fixture before open");

    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("newer schema must fail closed");
    assert!(matches!(error, RuntimeStoreError::SchemaTooNew { .. }));
    assert_eq!(
        fs::read(&database).expect("read newer fixture after rejection"),
        before
    );
}

#[tokio::test]
async fn unknown_nonempty_database_is_rejected_without_rewriting_it() {
    let root = TestRoot::new("unknown-schema");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let connection = rusqlite::Connection::open(&database).expect("create unknown database");
    connection
        .execute_batch("CREATE TABLE foreign_product(value TEXT); INSERT INTO foreign_product VALUES ('keep-me');")
        .expect("write unknown schema");
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
            .expect("secure unknown fixture");
    }
    let before = fs::read(&database).expect("read unknown fixture before open");

    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("unknown schema must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(
        fs::read(&database).expect("read unknown fixture after rejection"),
        before
    );
}

#[cfg(unix)]
#[tokio::test]
async fn database_symlink_is_rejected_before_sqlite_follows_it() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new("symlink");
    let keys = MemoryKeyStore::new();
    let target = root.path.join("target.db");
    fs::write(&target, []).expect("create symlink target");
    symlink(&target, root.database()).expect("create runtime DB symlink");

    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("symlink must fail closed");
    assert!(matches!(error, RuntimeStoreError::SymlinkRejected { .. }));
}

#[tokio::test]
async fn command_queue_is_bounded_and_reports_busy_without_blocking_the_caller() {
    let root = TestRoot::new("bounded-queue");
    let keys = MemoryKeyStore::new();
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let injector = Arc::new(BlockingFirstOperation {
        operation: RuntimeStoreOperation::CreateConversationBeforeCommit,
        blocked: AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
        observed: Mutex::new(Vec::new()),
    });
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_command_capacity(1)
            .with_fault_injector(injector),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    let first = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create_conversation(conversation_input(1, b"first"))
                .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .expect("join entered wait")
        .expect("first command reached worker");

    // timeout 会取消等待者，但已发送的 normal command 仍占据容量为 1 的队列。
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            store.create_conversation(conversation_input(2, b"second"))
        )
        .await
        .is_err()
    );
    let error = store
        .create_conversation(conversation_input(3, b"third"))
        .await
        .expect_err("third normal command must observe the full queue");
    assert!(matches!(
        error,
        RuntimeStoreError::WorkerBusy {
            lane: agentdeckd::runtime::store::RuntimeStoreLane::Normal
        }
    ));

    release_tx.send(()).expect("release worker");
    first
        .await
        .expect("join first command")
        .expect("first command succeeds");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn safety_and_read_lanes_bypass_normal_saturation_in_priority_order() {
    let root = TestRoot::new("priority-lanes");
    let keys = MemoryKeyStore::new();
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let injector = Arc::new(BlockingFirstOperation {
        operation: RuntimeStoreOperation::CreateConversationBeforeCommit,
        blocked: AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
        observed: Mutex::new(Vec::new()),
    });
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_command_capacity(1)
            .with_fault_injector(injector.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    let first_normal = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create_conversation(conversation_input(11, b"first"))
                .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .expect("join entered wait")
        .expect("first normal command reached worker");

    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            store.create_conversation(conversation_input(12, b"queued"))
        )
        .await
        .is_err(),
        "a polled normal command is queued behind the blocked command"
    );
    assert!(matches!(
        store
            .create_conversation(conversation_input(13, b"normal-full-probe"))
            .await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: agentdeckd::runtime::store::RuntimeStoreLane::Normal
        })
    ));

    let receipt = MachineEnrollmentReceiptRecord {
        relay_server_id: [0x11; 16],
        machine_route: [0x22; 16],
        root_fingerprint: [0x33; 32],
    };
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            store.record_machine_enrollment_receipt(receipt.clone())
        )
        .await
        .is_err(),
        "a polled safety command is accepted independently"
    );
    assert!(matches!(
        store.record_machine_enrollment_receipt(receipt).await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: agentdeckd::runtime::store::RuntimeStoreLane::Safety
        })
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(25), store.inspect())
            .await
            .is_err(),
        "a polled read command is accepted independently"
    );
    assert!(matches!(
        store.inspect().await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: agentdeckd::runtime::store::RuntimeStoreLane::Read
        })
    ));

    release_tx.send(()).expect("release worker");
    first_normal
        .await
        .expect("join first normal")
        .expect("first normal succeeds");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let second_normal_seen = injector
                .observed
                .lock()
                .expect("read observed operations")
                .iter()
                .filter(|operation| {
                    **operation == RuntimeStoreOperation::CreateConversationBeforeCommit
                })
                .count()
                >= 2;
            if second_normal_seen {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all queued lanes are serviced");

    let (first, safety_index, read_index, second_normal) = {
        let observed = injector.observed.lock().expect("read observed operations");
        let first = observed
            .iter()
            .position(|operation| {
                *operation == RuntimeStoreOperation::CreateConversationBeforeCommit
            })
            .expect("first normal observation");
        let safety_index = observed
            .iter()
            .position(|operation| {
                *operation == RuntimeStoreOperation::RecordEnrollmentReceiptBeforeCommit
            })
            .expect("safety observation");
        let read_index = observed
            .iter()
            .position(|operation| *operation == RuntimeStoreOperation::Inspect)
            .expect("read observation");
        let second_normal = observed
            .iter()
            .enumerate()
            .skip(first + 1)
            .find_map(|(index, operation)| {
                (*operation == RuntimeStoreOperation::CreateConversationBeforeCommit)
                    .then_some(index)
            })
            .expect("second normal observation");
        (first, safety_index, read_index, second_normal)
    };
    assert!(first < safety_index);
    assert!(safety_index < read_index, "safety is preferred over read");
    assert!(read_index < second_normal, "read is preferred over normal");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn shutdown_control_lane_remains_available_when_the_normal_queue_is_full() {
    let root = TestRoot::new("shutdown-control-lane");
    let keys = MemoryKeyStore::new();
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_command_capacity(1)
            .with_fault_injector(Arc::new(BlockingFirstOperation {
                operation: RuntimeStoreOperation::CreateConversationAfterCommit,
                blocked: AtomicBool::new(false),
                entered: entered_tx,
                release: Mutex::new(release_rx),
                observed: Mutex::new(Vec::new()),
            })),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let stale_handle = store.clone();
    let first = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create_conversation(conversation_input(21, b"first"))
                .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .expect("join entered wait")
        .expect("first command reached worker");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            store.create_conversation(conversation_input(22, b"queued"))
        )
        .await
        .is_err(),
        "second command fills the normal queue"
    );

    let mut shutdown = Box::pin(store.shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut shutdown)
            .await
            .is_err(),
        "shutdown control is accepted but waits for the in-flight operation"
    );
    release_tx.send(()).expect("release worker");
    first
        .await
        .expect("join in-flight command")
        .expect("in-flight command committed before shutdown won arbitration");
    shutdown.await.expect("shutdown survives normal saturation");
    assert!(matches!(
        stale_handle.inspect().await,
        Err(RuntimeStoreError::WorkerStopped)
    ));

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen after shutdown");
    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("read shutdown result");
    assert_eq!(recovery.conversations.len(), 1);
    assert_eq!(
        recovery.conversations[0].descriptor,
        runtime_descriptor::descriptor(b"first")
    );
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn shutdown_request_is_single_slot_and_second_clone_is_rejected() {
    let root = TestRoot::new("bounded-shutdown");
    let keys = MemoryKeyStore::new();
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
            BlockingFirstOperation {
                operation: RuntimeStoreOperation::CreateConversationAfterCommit,
                blocked: AtomicBool::new(false),
                entered: entered_tx,
                release: Mutex::new(release_rx),
                observed: Mutex::new(Vec::new()),
            },
        )),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let in_flight = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create_conversation(conversation_input(31, b"committed"))
                .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .expect("join entered wait")
        .expect("operation blocks after commit");

    let mut first_shutdown = Box::pin(store.clone().shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut first_shutdown)
            .await
            .is_err(),
        "first shutdown owns the single control slot"
    );
    assert!(matches!(
        store.shutdown().await,
        Err(RuntimeStoreError::ShutdownInProgress)
    ));

    release_tx.send(()).expect("release committed operation");
    in_flight
        .await
        .expect("join committed operation")
        .expect("committed operation returns");
    first_shutdown.await.expect("first shutdown completes");
}

#[tokio::test]
async fn queued_memory_is_bounded_independently_from_command_count() {
    let root = TestRoot::new("lane-byte-budget");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_lane_byte_capacity(1_024),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    let mut oversized_allocation = String::with_capacity(2_048);
    oversized_allocation.push('x');
    let error = store
        .create_conversation(agentdeckd::runtime::store::NewConversation {
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some(oversized_allocation),
                cwd: PathBuf::from("/tmp/agentdeck-runtime-test"),
            },
            ..conversation_input(32, b"")
        })
        .await
        .expect_err("retained heap capacity must count against the lane budget");
    assert!(matches!(
        error,
        RuntimeStoreError::WorkerBusy {
            lane: agentdeckd::runtime::store::RuntimeStoreLane::Normal
        }
    ));

    store.inspect().await.expect("read lane remains available");
    store
        .create_conversation(conversation_input(33, b"small"))
        .await
        .expect("rejected allocation releases its permit");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn excessive_command_capacity_is_rejected_before_creating_a_database() {
    let root = TestRoot::new("capacity-limit");
    let keys = MemoryKeyStore::new();
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_command_capacity(1_025),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("capacity above the hard limit must fail");
    assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
    assert!(!root.database().exists());
}

#[tokio::test]
async fn excessive_lane_byte_capacity_is_rejected_before_creating_a_database() {
    let root = TestRoot::new("lane-byte-capacity-limit");
    let keys = MemoryKeyStore::new();
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_lane_byte_capacity(256 * 1024 * 1024 + 1),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("lane byte capacity above the hard limit must fail");
    assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
    assert!(!root.database().exists());
}

#[tokio::test]
async fn excessive_busy_timeout_is_rejected_before_creating_a_database() {
    let root = TestRoot::new("busy-timeout-limit");
    let keys = MemoryKeyStore::new();
    let mut config = RuntimeStoreConfig::new(root.database());
    config.busy_timeout_ms = 30_001;
    let error = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect_err("unbounded SQLite busy timeout must fail");
    assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
    assert!(!root.database().exists());
}

#[tokio::test]
async fn failed_fresh_initialization_never_publishes_a_partial_database() {
    let root = TestRoot::new("fresh-atomic-publish");
    let keys = MemoryKeyStore::new();
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(FailBeforePublish)),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("injected failure must abort fresh initialization");
    assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
    assert!(!root.database().exists());
    assert!(
        fs::read_dir(&root.path)
            .expect("read runtime root")
            .all(|entry| !entry
                .expect("read runtime root entry")
                .file_name()
                .to_string_lossy()
                .contains(".init-")),
        "failed initialization must clean its private temporary database"
    );

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("normal retry creates a complete store");
    reopened.shutdown().await.expect("shutdown retry");
}

#[cfg(unix)]
#[tokio::test]
async fn fresh_open_cleans_only_valid_private_crash_initializer_artifacts() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("stale-initializer");
    let keys = MemoryKeyStore::new();
    let stale = root
        .path
        .join(".runtime.db.init-0123456789abcdef0123456789abcdef");
    let stale_wal = PathBuf::from(format!("{}-wal", stale.display()));
    for path in [&stale, &stale_wal] {
        fs::write(path, b"crash residue").expect("create stale initializer artifact");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure stale initializer artifact");
    }
    let unrelated = root.path.join(".runtime.db.init-not-ours");
    fs::write(&unrelated, b"keep").expect("create unrelated file");

    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("fresh open after crash residue");
    assert!(!stale.exists());
    assert!(!stale_wal.exists());
    assert_eq!(
        fs::read(unrelated).expect("unrelated file remains"),
        b"keep"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn live_schema_manifest_rejects_missing_indexes_even_when_meta_and_tables_match() {
    let root = TestRoot::new("schema-manifest");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("create current store");
    store.shutdown().await.expect("shutdown store");

    let connection = rusqlite::Connection::open(&database).expect("open tamper fixture");
    connection
        .execute_batch("DROP INDEX idx_commands_recovery;")
        .expect("remove required live schema object");
    drop(connection);
    let before = artifact_bytes(&database);

    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("live manifest drift must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_artifacts_unchanged(&before, &artifact_bytes(&database));
}

#[tokio::test]
async fn wrong_storage_kek_rejects_the_current_database_without_writing_any_artifact() {
    let root = TestRoot::new("wrong-kek");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("create current store");
    store.shutdown().await.expect("shutdown store");
    let before = artifact_bytes(&database);

    let wrong_root = TestRoot::new("wrong-kek-source");
    let wrong_keys = MemoryKeyStore::new();
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        wrong_root.storage_kek(&wrong_keys),
    )
    .await
    .expect_err("wrong KEK must fail closed");
    assert!(matches!(error, RuntimeStoreError::Cipher(_)));
    assert_artifacts_unchanged(&before, &artifact_bytes(&database));
}

#[cfg(unix)]
#[tokio::test]
async fn wrong_storage_kek_does_not_rebuild_shm_for_an_uncheckpointed_wal() {
    let root = TestRoot::new("wrong-kek-wal");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("create current store");
    store.shutdown().await.expect("shutdown current store");

    let connection = rusqlite::Connection::open(&database).expect("open crash WAL fixture");
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .expect("enable WAL");
    connection
        .pragma_update(None, "wal_autocheckpoint", 0_i64)
        .expect("disable checkpoint");
    connection
        .execute(
            "INSERT INTO machine_enrollment_receipts (
                 relay_server_id, machine_route, root_fingerprint
             ) VALUES (?1, ?2, ?3)",
            rusqlite::params![&[7_u8; 16][..], &[8_u8; 16][..], &[9_u8; 32][..]],
        )
        .expect("commit WAL fixture");
    assert!(
        fs::metadata(format!("{}-wal", database.display()))
            .expect("WAL exists")
            .len()
            > 0
    );
    std::mem::forget(connection);
    let shm = PathBuf::from(format!("{}-shm", database.display()));
    if let Err(error) = fs::remove_file(&shm) {
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
    let before = artifact_bytes(&database);

    let wrong_root = TestRoot::new("wrong-kek-wal-source");
    let wrong_keys = MemoryKeyStore::new();
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        wrong_root.storage_kek(&wrong_keys),
    )
    .await
    .expect_err("wrong KEK must fail before RW open");
    assert!(matches!(error, RuntimeStoreError::Cipher(_)));
    assert_artifacts_unchanged(&before, &artifact_bytes(&database));
}

#[cfg(unix)]
#[tokio::test]
async fn unsafe_database_mode_and_hardlinks_are_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("unsafe-database");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("create current store");
    store.shutdown().await.expect("shutdown store");

    fs::set_permissions(&database, fs::Permissions::from_mode(0o640))
        .expect("make database unsafe");
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("wide database mode must fail");
    assert!(matches!(error, RuntimeStoreError::UnsafeFile { .. }));

    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
        .expect("restore database mode");
    let alias = root.path.join("runtime-alias.db");
    fs::hard_link(&database, &alias).expect("create hardlink");
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("multiply-linked database must fail");
    assert!(matches!(error, RuntimeStoreError::UnsafeFile { .. }));
}

#[cfg(unix)]
#[tokio::test]
async fn preexisting_sidecar_symlink_is_rejected_before_any_sqlite_open() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new("sidecar-symlink");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("create current store");
    store.shutdown().await.expect("shutdown store");
    let wal = PathBuf::from(format!("{}-wal", database.display()));
    let wal_metadata = fs::symlink_metadata(&wal).expect("persistent WAL exists after shutdown");
    assert!(
        wal_metadata.file_type().is_file(),
        "fixture only replaces the store-created regular WAL"
    );
    fs::remove_file(&wal).expect("remove store-created WAL before hostile fixture");
    let target = root.path.join("sidecar-target");
    fs::write(&target, b"must-not-be-touched").expect("create sidecar target");
    symlink(&target, &wal).expect("create WAL symlink");

    let before = fs::read(&target).expect("read target before rejection");
    let error =
        RuntimeStoreHandle::open(RuntimeStoreConfig::new(database), root.storage_kek(&keys))
            .await
            .expect_err("preexisting sidecar symlink must fail closed");
    assert!(matches!(error, RuntimeStoreError::SymlinkRejected { .. }));
    assert_eq!(
        fs::read(&target).expect("read target after rejection"),
        before
    );
}

#[cfg(unix)]
#[tokio::test]
async fn orphan_sidecar_rejects_a_fresh_or_empty_database() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("orphan-sidecar");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    fs::write(format!("{}-shm", database.display()), []).expect("create orphan SHM");
    fs::set_permissions(
        format!("{}-shm", database.display()),
        fs::Permissions::from_mode(0o600),
    )
    .expect("secure orphan SHM");

    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("fresh store with sidecar must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert!(!database.exists());
}

#[tokio::test]
async fn nonsecret_enrollment_rescue_index_survives_keychain_loss_without_a_kek() {
    let root = TestRoot::new("rescue-index");
    let database = root.database();
    let receipt = MachineEnrollmentReceiptRecord {
        relay_server_id: [0x11; 16],
        machine_route: [0x22; 16],
        root_fingerprint: [0x33; 32],
    };
    {
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open store");
        assert_eq!(
            store
                .record_machine_enrollment_receipt(receipt.clone())
                .await
                .expect("record receipt"),
            receipt
        );
        assert_eq!(
            store
                .record_machine_enrollment_receipt(receipt.clone())
                .await
                .expect("idempotent receipt"),
            receipt
        );
        store.shutdown().await.expect("drop row keys and KEK");
        // `keys` 在此 scope 结束时模拟 Keychain 全部丢失。
    }

    let before = artifact_bytes(&database);
    assert_eq!(
        RuntimeRescueIndex::read(&database).expect("read rescue index without KEK"),
        vec![receipt.clone()]
    );
    assert_artifacts_unchanged(&before, &artifact_bytes(&database));

    let keys = MemoryKeyStore::new();
    assert!(
        load_or_create_storage_kek(&keys, &database).is_err(),
        "rescue read must not generate a replacement StorageKEK"
    );
}

#[tokio::test]
async fn rescue_index_refuses_to_race_an_open_runtime_store() {
    let root = TestRoot::new("rescue-open-store");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    assert!(matches!(
        RuntimeRescueIndex::read(root.database()),
        Err(RuntimeStoreError::StoreAlreadyOpen)
    ));
    store.shutdown().await.expect("shutdown store");
}

#[cfg(unix)]
#[tokio::test]
async fn rescue_index_reads_a_committed_receipt_from_wal_without_touching_original_artifacts() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("rescue-wal");
    let database = root.database();
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("create current store");
    store.shutdown().await.expect("shutdown initial store");

    let connection = rusqlite::Connection::open(&database).expect("open WAL fixture");
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .expect("enable WAL");
    connection
        .pragma_update(None, "wal_autocheckpoint", 0_i64)
        .expect("disable automatic checkpoint");
    connection
        .execute(
            "INSERT INTO machine_enrollment_receipts (
                 relay_server_id, machine_route, root_fingerprint
             ) VALUES (?1, ?2, ?3)",
            rusqlite::params![&[0x41_u8; 16][..], &[0x42_u8; 16][..], &[0x43_u8; 32][..]],
        )
        .expect("commit receipt only into WAL");
    let wal = PathBuf::from(format!("{}-wal", database.display()));
    assert!(fs::metadata(&wal).expect("WAL exists").len() > 0);
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o600)).expect("secure fixture WAL");
    // 模拟 daemon 因 Keychain 丢失无法正常重开；保留已提交 WAL，不执行 close checkpoint。
    std::mem::forget(connection);

    let before = artifact_bytes(&database);
    assert_eq!(
        RuntimeRescueIndex::read(&database).expect("read committed WAL receipt without KEK"),
        vec![MachineEnrollmentReceiptRecord {
            relay_server_id: [0x41; 16],
            machine_route: [0x42; 16],
            root_fingerprint: [0x43; 32],
        }]
    );
    assert_artifacts_unchanged(&before, &artifact_bytes(&database));
}

#[tokio::test]
async fn enrollment_rescue_index_rejects_root_fingerprint_rebinding() {
    let root = TestRoot::new("rescue-conflict");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let first = MachineEnrollmentReceiptRecord {
        relay_server_id: [1; 16],
        machine_route: [2; 16],
        root_fingerprint: [3; 32],
    };
    store
        .record_machine_enrollment_receipt(first.clone())
        .await
        .expect("record first fingerprint");
    let error = store
        .record_machine_enrollment_receipt(MachineEnrollmentReceiptRecord {
            root_fingerprint: [4; 32],
            ..first
        })
        .await
        .expect_err("same route cannot be rebound to another root");
    assert!(matches!(error, RuntimeStoreError::RescueReceiptConflict));
    store.shutdown().await.expect("shutdown store");
}
