use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    ActivateMachineIdentityOutcome, MachineIdentityBinding, MachineIdentityLifecycle,
    PrepareMachineIdentityOutcome, RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use sha2::{Digest, Sha256};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-machine-identity-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create machine identity test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure machine identity test root");
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

#[cfg(unix)]
#[derive(Debug, Eq, PartialEq)]
struct ArtifactIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(not(unix))]
#[derive(Debug, Eq, PartialEq)]
struct ArtifactIdentity {
    length: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct ArtifactEvidence {
    path: PathBuf,
    identity: Option<ArtifactIdentity>,
    bytes: Option<Vec<u8>>,
}

fn artifact_evidence(database: &Path) -> Vec<ArtifactEvidence> {
    [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
        PathBuf::from(format!("{}-journal", database.display())),
    ]
    .into_iter()
    .map(|path| match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            #[cfg(unix)]
            let identity = {
                use std::os::unix::fs::MetadataExt;
                ArtifactIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    length: metadata.len(),
                    modified_seconds: metadata.mtime(),
                    modified_nanoseconds: metadata.mtime_nsec(),
                    changed_seconds: metadata.ctime(),
                    changed_nanoseconds: metadata.ctime_nsec(),
                }
            };
            #[cfg(not(unix))]
            let identity = ArtifactIdentity {
                length: metadata.len(),
            };
            ArtifactEvidence {
                bytes: Some(fs::read(&path).expect("read runtime artifact")),
                path,
                identity: Some(identity),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ArtifactEvidence {
            path,
            identity: None,
            bytes: None,
        },
        Err(error) => panic!("inspect runtime artifact: {error}"),
    })
    .collect()
}

fn fingerprint(public_key: [u8; 32]) -> [u8; 32] {
    Sha256::digest(public_key).into()
}

fn binding(seed: u8) -> MachineIdentityBinding {
    let root_public_key = [seed; 32];
    let machine_hpke_public_key = [seed.wrapping_add(1); 32];
    let link_sign_public_key = [seed.wrapping_add(2); 32];
    let data_sign_public_key = [seed.wrapping_add(3); 32];
    MachineIdentityBinding {
        root_key_id: [seed.wrapping_add(4); 16],
        trust_epoch: 1,
        link_generation: 1,
        data_generation: 1,
        key_directory_revision: 0,
        root_public_key,
        root_fingerprint: fingerprint(root_public_key),
        machine_hpke_public_key,
        machine_hpke_fingerprint: fingerprint(machine_hpke_public_key),
        link_sign_public_key,
        link_sign_fingerprint: fingerprint(link_sign_public_key),
        data_sign_public_key,
        data_sign_fingerprint: fingerprint(data_sign_public_key),
    }
}

async fn open_store(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    faults: Option<Arc<dyn RuntimeStoreFaultInjector>>,
) -> RuntimeStoreHandle {
    let mut config = RuntimeStoreConfig::new(root.database());
    if let Some(faults) = faults {
        config = config.with_fault_injector(faults);
    }
    RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(keys, &root.database()).expect("load test StorageKEK"),
    )
    .await
    .expect("open machine identity store")
}

#[tokio::test]
async fn prepare_and_activate_machine_identity_are_exactly_idempotent() {
    let root = TestRoot::new("idempotent");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys, None).await;
    let expected = binding(0x21);

    assert_eq!(
        store
            .load_machine_identity_state()
            .await
            .expect("load empty identity"),
        None
    );
    let prepared = store
        .prepare_machine_identity(expected.clone())
        .await
        .expect("prepare identity");
    let PrepareMachineIdentityOutcome::Prepared { state } = prepared else {
        panic!("first prepare must create the singleton")
    };
    assert_eq!(state.lifecycle, MachineIdentityLifecycle::Preparing);
    assert_eq!(state.binding, expected);
    assert_ne!(state.database_id, [0; 16]);

    assert!(matches!(
        store
            .prepare_machine_identity(expected.clone())
            .await
            .expect("replay prepare"),
        PrepareMachineIdentityOutcome::Replayed { state }
            if state.lifecycle == MachineIdentityLifecycle::Preparing
    ));
    assert!(matches!(
        store
            .activate_machine_identity(expected.clone())
            .await
            .expect("activate identity"),
        ActivateMachineIdentityOutcome::Activated { state }
            if state.lifecycle == MachineIdentityLifecycle::Active
    ));
    assert!(matches!(
        store
            .activate_machine_identity(expected.clone())
            .await
            .expect("replay activate"),
        ActivateMachineIdentityOutcome::Replayed { state }
            if state.lifecycle == MachineIdentityLifecycle::Active
    ));
    assert!(matches!(
        store
            .prepare_machine_identity(expected)
            .await
            .expect("late exact prepare replay"),
        PrepareMachineIdentityOutcome::Replayed { state }
            if state.lifecycle == MachineIdentityLifecycle::Active
    ));

    store.shutdown().await.expect("shutdown identity store");
}

#[tokio::test]
async fn machine_identity_payload_or_state_conflicts_fail_closed() {
    let root = TestRoot::new("conflict");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys, None).await;
    let first = binding(0x31);
    let different = binding(0x41);

    let missing = store
        .activate_machine_identity(first.clone())
        .await
        .expect_err("activate without Preparing must fail");
    assert!(matches!(missing, RuntimeStoreError::MachineIdentityMissing));

    store
        .prepare_machine_identity(first.clone())
        .await
        .expect("prepare first identity");
    let before = store
        .load_machine_identity_state()
        .await
        .expect("load prepared identity")
        .expect("prepared identity exists");

    for error in [
        store
            .prepare_machine_identity(different.clone())
            .await
            .expect_err("different prepare must conflict"),
        store
            .activate_machine_identity(different)
            .await
            .expect_err("different activate must conflict"),
    ] {
        assert!(matches!(error, RuntimeStoreError::MachineIdentityConflict));
    }
    assert_eq!(
        store
            .load_machine_identity_state()
            .await
            .expect("load identity after conflicts"),
        Some(before)
    );

    store.shutdown().await.expect("shutdown conflict store");
}

#[tokio::test]
async fn machine_identity_binding_rejects_zero_monotonic_or_public_key_fields() {
    let root = TestRoot::new("invalid-binding");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys, None).await;

    let mut invalid = Vec::new();
    let mut zero_trust = binding(0x71);
    zero_trust.trust_epoch = 0;
    invalid.push(zero_trust);
    let mut zero_link_generation = binding(0x72);
    zero_link_generation.link_generation = 0;
    invalid.push(zero_link_generation);
    let mut zero_data_generation = binding(0x73);
    zero_data_generation.data_generation = 0;
    invalid.push(zero_data_generation);
    let mut zero_root_id = binding(0x74);
    zero_root_id.root_key_id = [0; 16];
    invalid.push(zero_root_id);
    let mut zero_public_key = binding(0x75);
    zero_public_key.root_public_key = [0; 32];
    zero_public_key.root_fingerprint = fingerprint([0; 32]);
    invalid.push(zero_public_key);

    for invalid in invalid {
        assert!(matches!(
            store.prepare_machine_identity(invalid).await,
            Err(RuntimeStoreError::MachineIdentityConflict)
        ));
    }
    assert_eq!(
        store
            .load_machine_identity_state()
            .await
            .expect("load after invalid bindings"),
        None
    );
    store
        .shutdown()
        .await
        .expect("shutdown invalid binding store");
}

async fn create_active_identity(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    expected: &MachineIdentityBinding,
) {
    let store = open_store(root, keys, None).await;
    store
        .prepare_machine_identity(expected.clone())
        .await
        .expect("prepare active fixture identity");
    store
        .activate_machine_identity(expected.clone())
        .await
        .expect("activate fixture identity");
    store
        .shutdown()
        .await
        .expect("shutdown active fixture store");
}

async fn assert_tampered_store_rejected_without_rewrite(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    label: &str,
) {
    let before = artifact_evidence(&root.database());
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(keys, &root.database()).expect("reload tampered StorageKEK"),
    )
    .await
    .expect_err("tampered machine identity store must fail closed");
    assert!(matches!(
        error,
        RuntimeStoreError::UnknownOrCorruptSchema | RuntimeStoreError::Cipher(_)
    ));
    assert_eq!(
        artifact_evidence(&root.database()),
        before,
        "{label} rejection must preserve main/WAL/SHM bytes and file identity"
    );
}

#[tokio::test]
async fn machine_identity_row_field_or_metadata_token_tamper_fails_closed_without_rewrite() {
    for (label, column) in [
        ("public-field", "root_public_key"),
        ("metadata-token", "metadata_token"),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        create_active_identity(&root, &keys, &binding(0x81)).await;
        let connection =
            rusqlite::Connection::open(root.database()).expect("open identity row tamper fixture");
        let sql = format!("UPDATE machine_identity_state SET {column} = ?1 WHERE singleton = 1");
        assert_eq!(
            connection
                .execute(&sql, [&[0xE1_u8; 32][..]])
                .expect("tamper authenticated identity row"),
            1
        );
        drop(connection);
        assert_tampered_store_rejected_without_rewrite(&root, &keys, label).await;
    }
}

#[tokio::test]
async fn machine_identity_ledger_count_physical_divergence_fails_closed_without_rewrite() {
    let root = TestRoot::new("ledger-count");
    let keys = MemoryKeyStore::new();
    create_active_identity(&root, &keys, &binding(0x91)).await;
    let connection =
        rusqlite::Connection::open(root.database()).expect("open identity count tamper fixture");
    assert_eq!(
        connection
            .execute(
                "UPDATE runtime_meta SET machine_identity_count = 0 WHERE singleton = 1",
                [],
            )
            .expect("diverge authenticated identity count"),
        1
    );
    drop(connection);
    assert_tampered_store_rejected_without_rewrite(&root, &keys, "ledger-count").await;
}

#[tokio::test]
async fn machine_identity_physical_delete_with_authenticated_count_fails_closed_without_rewrite() {
    let root = TestRoot::new("physical-delete");
    let keys = MemoryKeyStore::new();
    create_active_identity(&root, &keys, &binding(0x92)).await;
    let connection =
        rusqlite::Connection::open(root.database()).expect("open identity physical-delete fixture");
    assert_eq!(
        connection
            .execute("DELETE FROM machine_identity_state WHERE singleton = 1", [],)
            .expect("delete authenticated identity row without updating ledger count"),
        1
    );
    drop(connection);
    assert_tampered_store_rejected_without_rewrite(&root, &keys, "physical-delete").await;
}

#[derive(Clone, Copy, Debug)]
struct DiskLowProbe;

impl RuntimeCapacityProbe for DiskLowProbe {
    fn observe(
        &self,
        _database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        Ok(RuntimeCapacityObservation {
            main_bytes: 0,
            wal_bytes: 0,
            shm_bytes: 0,
            filesystem_total_bytes: 10 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 0,
        })
    }
}

#[tokio::test]
async fn machine_identity_prepare_obeys_safety_capacity_and_leaves_count_zero() {
    let root = TestRoot::new("capacity");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(DiskLowProbe),
        load_or_create_storage_kek(&keys, &root.database()).expect("load capacity StorageKEK"),
    )
    .await
    .expect("open capacity fixture");

    assert!(matches!(
        store.prepare_machine_identity(binding(0xA1)).await,
        Err(RuntimeStoreError::DiskLow { .. })
    ));
    assert_eq!(
        store
            .load_machine_identity_state()
            .await
            .expect("load after rejected capacity write"),
        None
    );
    store.shutdown().await.expect("shutdown capacity fixture");
}

struct BlockingBeforeCommit {
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
}

impl RuntimeStoreFaultInjector for BlockingBeforeCommit {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::PrepareMachineIdentityBeforeCommit {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_prepare_caller_does_not_cancel_the_queued_safety_commit() {
    let root = TestRoot::new("caller-cancel");
    let keys = MemoryKeyStore::new();
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let blocker = Arc::new(BlockingBeforeCommit {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let store = open_store(&root, &keys, Some(blocker)).await;
    let expected = binding(0xB1);
    let task_store = store.clone();
    let task_binding = expected.clone();
    let task = tokio::spawn(async move { task_store.prepare_machine_identity(task_binding).await });
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("prepare reached before-commit boundary");
    task.abort();
    release_tx.send(()).expect("release blocked store worker");
    assert!(
        task.await
            .expect_err("caller task must be canceled")
            .is_cancelled()
    );

    let state = store
        .load_machine_identity_state()
        .await
        .expect("load committed state after caller cancellation")
        .expect("canceled caller does not cancel worker commit");
    assert_eq!(state.lifecycle, MachineIdentityLifecycle::Preparing);
    assert_eq!(state.binding, expected);
    store
        .shutdown()
        .await
        .expect("shutdown caller cancellation fixture");
}

#[tokio::test]
async fn stopped_worker_rejects_machine_identity_read_and_safety_dispatch() {
    let root = TestRoot::new("stopped-worker");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys, None).await;
    let stale = store.clone();
    store.shutdown().await.expect("shutdown worker");

    assert!(matches!(
        stale.load_machine_identity_state().await,
        Err(RuntimeStoreError::WorkerStopped | RuntimeStoreError::ShutdownInProgress)
    ));
    assert!(matches!(
        stale.prepare_machine_identity(binding(0xC1)).await,
        Err(RuntimeStoreError::WorkerStopped | RuntimeStoreError::ShutdownInProgress)
    ));
}

#[derive(Debug)]
struct FailOnce {
    remaining: Mutex<Vec<RuntimeStoreOperation>>,
}

impl FailOnce {
    fn new(operations: Vec<RuntimeStoreOperation>) -> Self {
        Self {
            remaining: Mutex::new(operations),
        }
    }
}

impl RuntimeStoreFaultInjector for FailOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        let mut remaining = self.remaining.lock().expect("lock fault list");
        if let Some(index) = remaining.iter().position(|entry| *entry == operation) {
            remaining.remove(index);
            Err(RuntimeStoreError::InvalidConfig(
                "injected machine identity fault",
            ))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn machine_identity_before_commit_rolls_back_and_exact_retry_succeeds() {
    let root = TestRoot::new("before-commit");
    let keys = MemoryKeyStore::new();
    let faults = Arc::new(FailOnce::new(vec![
        RuntimeStoreOperation::PrepareMachineIdentityBeforeCommit,
    ]));
    let store = open_store(&root, &keys, Some(faults)).await;
    let expected = binding(0x51);

    store
        .prepare_machine_identity(expected.clone())
        .await
        .expect_err("before-commit fault must fail prepare");
    assert_eq!(
        store
            .load_machine_identity_state()
            .await
            .expect("load after rolled-back prepare"),
        None
    );
    assert!(matches!(
        store
            .prepare_machine_identity(expected)
            .await
            .expect("retry rolled-back prepare"),
        PrepareMachineIdentityOutcome::Prepared { .. }
    ));

    store
        .shutdown()
        .await
        .expect("shutdown before-commit store");
}

#[tokio::test]
async fn machine_identity_after_commit_unknown_replays_exact_state() {
    let root = TestRoot::new("after-commit");
    let keys = MemoryKeyStore::new();
    let faults = Arc::new(FailOnce::new(vec![
        RuntimeStoreOperation::PrepareMachineIdentityAfterCommit,
        RuntimeStoreOperation::ActivateMachineIdentityAfterCommit,
    ]));
    let store = open_store(&root, &keys, Some(faults)).await;
    let expected = binding(0x61);

    let prepare_error = store
        .prepare_machine_identity(expected.clone())
        .await
        .expect_err("after-commit prepare must surface unknown outcome");
    assert!(matches!(
        prepare_error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PrepareMachineIdentity
        }
    ));
    assert!(matches!(
        store
            .prepare_machine_identity(expected.clone())
            .await
            .expect("replay committed prepare"),
        PrepareMachineIdentityOutcome::Replayed { .. }
    ));

    let activate_error = store
        .activate_machine_identity(expected.clone())
        .await
        .expect_err("after-commit activate must surface unknown outcome");
    assert!(matches!(
        activate_error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ActivateMachineIdentity
        }
    ));
    assert!(matches!(
        store
            .activate_machine_identity(expected)
            .await
            .expect("replay committed activate"),
        ActivateMachineIdentityOutcome::Replayed { state }
            if state.lifecycle == MachineIdentityLifecycle::Active
    ));

    store.shutdown().await.expect("shutdown after-commit store");
}
