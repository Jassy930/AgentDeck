use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agentdeck_crypto::sha256;
use agentdeckd::remote::bootstrap::{RemoteBootstrapOutcome, reconcile_machine_identity};
use agentdeckd::remote::identity::{
    KEY_DIRECTORY_GUARD_ACCOUNT, KeyDirectoryGuard, MACHINE_DATA_SIGN_ACCOUNT,
    MACHINE_HPKE_ACCOUNT, MACHINE_LINK_SIGN_ACCOUNT, MACHINE_ROOT_SIGN_ACCOUNT,
    install_key_directory_guard, load_key_directory_guard, load_machine_key_material,
};
use agentdeckd::runtime::store::{
    MachineIdentityBinding, MachineIdentityLifecycle, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{
    KeyStore, KeyStoreError, MemoryKeyStore, SecretBytes, load_or_create_storage_kek,
};

#[derive(Debug)]
struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-remote-bootstrap-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create bootstrap test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure bootstrap test root");
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum KeyOperation {
    Load(String),
    Store(String),
    Delete(String),
}

#[derive(Default)]
struct RecordingKeyStore {
    values: Mutex<HashMap<String, Vec<u8>>>,
    operations: Mutex<Vec<KeyOperation>>,
}

impl RecordingKeyStore {
    fn clear_operations(&self) {
        self.operations.lock().unwrap().clear();
    }

    fn operations(&self) -> Vec<KeyOperation> {
        self.operations.lock().unwrap().clone()
    }

    fn store_accounts(&self) -> Vec<String> {
        self.operations()
            .into_iter()
            .filter_map(|operation| match operation {
                KeyOperation::Store(account) => Some(account),
                KeyOperation::Load(_) | KeyOperation::Delete(_) => None,
            })
            .collect()
    }

    fn value(&self, account: &str) -> Option<Vec<u8>> {
        self.values.lock().unwrap().get(account).cloned()
    }

    fn insert_material(&self, seed: u8) {
        for (offset, account) in [
            MACHINE_ROOT_SIGN_ACCOUNT,
            MACHINE_HPKE_ACCOUNT,
            MACHINE_LINK_SIGN_ACCOUNT,
            MACHINE_DATA_SIGN_ACCOUNT,
        ]
        .into_iter()
        .enumerate()
        {
            self.store(
                account,
                &SecretBytes::new(vec![seed.wrapping_add(offset as u8); 32]),
            )
            .expect("insert fixture material");
        }
    }
}

impl KeyStore for RecordingKeyStore {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
        self.operations
            .lock()
            .unwrap()
            .push(KeyOperation::Load(account.to_owned()));
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(account)
            .map(|value| SecretBytes::new(value.clone())))
    }

    fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
        self.operations
            .lock()
            .unwrap()
            .push(KeyOperation::Store(account.to_owned()));
        self.values
            .lock()
            .unwrap()
            .insert(account.to_owned(), value.expose_secret().to_vec());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        self.operations
            .lock()
            .unwrap()
            .push(KeyOperation::Delete(account.to_owned()));
        self.values.lock().unwrap().remove(account);
        Ok(())
    }
}

async fn open_store(
    root: &TestRoot,
    faults: Option<Arc<dyn RuntimeStoreFaultInjector>>,
) -> RuntimeStoreHandle {
    let storage_keys = MemoryKeyStore::new();
    let mut config = RuntimeStoreConfig::new(root.database());
    if let Some(faults) = faults {
        config = config.with_fault_injector(faults);
    }
    RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&storage_keys, &root.database()).expect("create StorageKEK"),
    )
    .await
    .expect("open bootstrap store")
}

fn binding_for_material(keys: &dyn KeyStore, root_key_id: [u8; 16]) -> MachineIdentityBinding {
    let material = load_machine_key_material(keys).expect("load fixture material");
    let public = material.public_identity();
    MachineIdentityBinding {
        root_key_id,
        trust_epoch: 1,
        link_generation: 1,
        data_generation: 1,
        key_directory_revision: 0,
        root_public_key: *public.root().public_key(),
        root_fingerprint: public.root().fingerprint(),
        machine_hpke_public_key: *public.hpke().public_key(),
        machine_hpke_fingerprint: public.hpke().fingerprint(),
        link_sign_public_key: *public.link().public_key(),
        link_sign_fingerprint: public.link().fingerprint(),
        data_sign_public_key: *public.data().public_key(),
        data_sign_fingerprint: public.data().fingerprint(),
    }
}

fn arbitrary_binding(seed: u8) -> MachineIdentityBinding {
    let root = [seed; 32];
    let hpke = [seed.wrapping_add(1); 32];
    let link = [seed.wrapping_add(2); 32];
    let data = [seed.wrapping_add(3); 32];
    MachineIdentityBinding {
        root_key_id: [seed.wrapping_add(4); 16],
        trust_epoch: 1,
        link_generation: 1,
        data_generation: 1,
        key_directory_revision: 0,
        root_public_key: root,
        root_fingerprint: sha256(&root),
        machine_hpke_public_key: hpke,
        machine_hpke_fingerprint: sha256(&hpke),
        link_sign_public_key: link,
        link_sign_fingerprint: sha256(&link),
        data_sign_public_key: data,
        data_sign_fingerprint: sha256(&data),
    }
}

#[derive(Debug)]
struct FailOnce {
    operation: RuntimeStoreOperation,
    fired: Mutex<bool>,
}

impl FailOnce {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            fired: Mutex::new(false),
        }
    }
}

impl RuntimeStoreFaultInjector for FailOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        let mut fired = self.fired.lock().unwrap();
        if operation == self.operation && !*fired {
            *fired = true;
            return Err(RuntimeStoreError::InvalidConfig(
                "injected remote bootstrap fault",
            ));
        }
        Ok(())
    }
}

#[test]
fn bootstrap_source_owns_no_p4_2_network_or_injection_surface() {
    let bootstrap = include_str!("../src/remote/bootstrap.rs");
    let main = include_str!("../src/main.rs");
    let production = format!("{bootstrap}\n{main}");

    for forbidden in [
        "SignedCertificate",
        "MachineEnrollmentRequest",
        "MachineEnrollmentResponse",
        "RelayEnrollmentClient",
        "RemoteLink",
        "record_enrollment_receipt",
        "load_enrollment_receipt",
        "machine_enrollment_receipts",
        "WebSocket",
        "tokio_tungstenite",
        "--file-keystore",
        "--machine-key-file",
        "AGENTDECK_MACHINE_KEY",
        "AGENTDECK_KEY_DIRECTORY_GUARD",
    ] {
        assert!(
            !production.contains(forbidden),
            "P4.1-C production source must not own {forbidden}"
        );
    }
}

#[tokio::test]
async fn disabled_bootstrap_performs_zero_machine_account_io() {
    let root = TestRoot::new("disabled");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();

    let outcome = reconcile_machine_identity(false, &store, &keys)
        .await
        .expect("disabled bootstrap");
    assert!(matches!(outcome, RemoteBootstrapOutcome::Disabled));
    assert!(keys.operations().is_empty());
    assert_eq!(
        store.load_machine_identity_state().await.unwrap(),
        None,
        "disabled bootstrap must not create the DB singleton"
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_bootstrap_is_active_nonzero_and_restart_stable() {
    let root = TestRoot::new("fresh");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();

    let first = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("fresh bootstrap");
    let RemoteBootstrapOutcome::Active(first) = first else {
        panic!("fresh bootstrap must become active");
    };
    let first_binding = first.binding().clone();
    assert_ne!(first_binding.root_key_id, [0; 16]);
    assert_eq!(first_binding.trust_epoch, 1);
    assert_eq!(first_binding.link_generation, 1);
    assert_eq!(first_binding.data_generation, 1);
    assert_eq!(first_binding.key_directory_revision, 0);
    assert_eq!(
        keys.store_accounts(),
        vec![
            MACHINE_ROOT_SIGN_ACCOUNT,
            MACHINE_HPKE_ACCOUNT,
            MACHINE_LINK_SIGN_ACCOUNT,
            MACHINE_DATA_SIGN_ACCOUNT,
            KEY_DIRECTORY_GUARD_ACCOUNT,
        ]
    );
    let state = store
        .load_machine_identity_state()
        .await
        .unwrap()
        .expect("active DB singleton");
    assert_eq!(state.lifecycle, MachineIdentityLifecycle::Active);
    assert_eq!(state.binding, first_binding);
    let guard = load_key_directory_guard(&keys)
        .unwrap()
        .expect("installed guard");
    assert_eq!(guard.database_id(), state.database_id);
    assert_eq!(guard.root_fingerprint(), state.binding.root_fingerprint);
    assert_eq!(guard.key_directory_revision(), 0);

    drop(first);
    keys.clear_operations();
    let second = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("restart bootstrap");
    let RemoteBootstrapOutcome::Active(second) = second else {
        panic!("restart must remain active");
    };
    assert_eq!(second.binding(), &first_binding);
    assert!(keys.store_accounts().is_empty());
    drop(second);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn partial_fresh_material_only_fills_missing_accounts() {
    let root = TestRoot::new("partial-fresh");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();
    let root_seed = vec![0x31; 32];
    let hpke_ikm = vec![0x32; 32];
    keys.store(
        MACHINE_ROOT_SIGN_ACCOUNT,
        &SecretBytes::new(root_seed.clone()),
    )
    .unwrap();
    keys.store(MACHINE_HPKE_ACCOUNT, &SecretBytes::new(hpke_ikm.clone()))
        .unwrap();
    keys.clear_operations();

    let outcome = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("resume partial pre-Preparing material");
    assert!(matches!(outcome, RemoteBootstrapOutcome::Active(_)));
    assert_eq!(
        keys.store_accounts(),
        vec![
            MACHINE_LINK_SIGN_ACCOUNT,
            MACHINE_DATA_SIGN_ACCOUNT,
            KEY_DIRECTORY_GUARD_ACCOUNT,
        ]
    );
    assert_eq!(keys.value(MACHINE_ROOT_SIGN_ACCOUNT), Some(root_seed));
    assert_eq!(keys.value(MACHINE_HPKE_ACCOUNT), Some(hpke_ikm));
    drop(outcome);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn guard_without_db_identity_is_rollback_blocked_and_zero_write() {
    let root = TestRoot::new("rollback");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();
    let guard = KeyDirectoryGuard::new([0x41; 16], [0x42; 32], 0);
    install_key_directory_guard(&keys, guard).unwrap();
    keys.clear_operations();

    let outcome = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("rollback is remote-only blocked");
    let RemoteBootstrapOutcome::Blocked(block) = outcome else {
        panic!("rollback must be blocked");
    };
    assert_eq!(block.code(), "daemon.remote.identity.database_rollback");
    assert!(keys.store_accounts().is_empty());
    assert!(
        !keys
            .operations()
            .iter()
            .any(|operation| matches!(operation, KeyOperation::Delete(_)))
    );
    assert_eq!(store.load_machine_identity_state().await.unwrap(), None);
    assert_eq!(load_key_directory_guard(&keys).unwrap(), Some(guard));
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_guard_without_db_identity_blocks_before_key_io() {
    let root = TestRoot::new("invalid-guard");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();
    keys.store(
        KEY_DIRECTORY_GUARD_ACCOUNT,
        &SecretBytes::new(vec![0x45; 7]),
    )
    .unwrap();
    keys.clear_operations();

    let outcome = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("invalid guard is remote-only blocked");
    let RemoteBootstrapOutcome::Blocked(block) = outcome else {
        panic!("invalid guard must block");
    };
    assert_eq!(block.code(), "daemon.remote.identity.guard_invalid");
    assert_eq!(
        keys.operations(),
        vec![KeyOperation::Load(KEY_DIRECTORY_GUARD_ACCOUNT.to_owned())]
    );
    assert_eq!(store.load_machine_identity_state().await.unwrap(), None);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn preparing_missing_material_blocks_without_repair() {
    let root = TestRoot::new("preparing-missing");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();
    let expected = arbitrary_binding(0x51);
    store
        .prepare_machine_identity(expected.clone())
        .await
        .unwrap();

    let outcome = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("missing material is remote-only blocked");
    let RemoteBootstrapOutcome::Blocked(block) = outcome else {
        panic!("missing Preparing material must block");
    };
    assert_eq!(block.code(), "daemon.remote.identity.key_missing");
    assert!(keys.store_accounts().is_empty());
    let state = store.load_machine_identity_state().await.unwrap().unwrap();
    assert_eq!(state.lifecycle, MachineIdentityLifecycle::Preparing);
    assert_eq!(state.binding, expected);
    assert_eq!(load_key_directory_guard(&keys).unwrap(), None);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn preparing_exact_state_installs_guard_then_activates_without_rekey() {
    let root = TestRoot::new("preparing-resume");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();
    keys.insert_material(0x61);
    let expected = binding_for_material(&keys, [0x62; 16]);
    store
        .prepare_machine_identity(expected.clone())
        .await
        .unwrap();
    keys.clear_operations();

    let outcome = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("resume Preparing");
    let RemoteBootstrapOutcome::Active(active) = outcome else {
        panic!("exact Preparing state must activate");
    };
    assert_eq!(active.binding(), &expected);
    assert_eq!(keys.store_accounts(), vec![KEY_DIRECTORY_GUARD_ACCOUNT]);
    let state = store.load_machine_identity_state().await.unwrap().unwrap();
    assert_eq!(state.lifecycle, MachineIdentityLifecycle::Active);
    drop(active);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn preparing_with_exact_guard_only_activates() {
    let root = TestRoot::new("preparing-with-guard");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();
    keys.insert_material(0x65);
    let expected = binding_for_material(&keys, [0x66; 16]);
    let prepared = match store
        .prepare_machine_identity(expected.clone())
        .await
        .unwrap()
    {
        agentdeckd::runtime::store::PrepareMachineIdentityOutcome::Prepared { state }
        | agentdeckd::runtime::store::PrepareMachineIdentityOutcome::Replayed { state } => state,
    };
    install_key_directory_guard(
        &keys,
        KeyDirectoryGuard::new(
            prepared.database_id,
            expected.root_fingerprint,
            expected.key_directory_revision,
        ),
    )
    .unwrap();
    keys.clear_operations();

    let outcome = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("resume exact Preparing guard");
    assert!(matches!(outcome, RemoteBootstrapOutcome::Active(_)));
    assert!(keys.store_accounts().is_empty());
    assert_eq!(
        store
            .load_machine_identity_state()
            .await
            .unwrap()
            .unwrap()
            .lifecycle,
        MachineIdentityLifecycle::Active
    );
    drop(outcome);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn active_missing_guard_and_public_fork_are_blocked_without_write() {
    for (label, binding_matches) in [("guard-missing", true), ("public-fork", false)] {
        let root = TestRoot::new(label);
        let store = open_store(&root, None).await;
        let keys = RecordingKeyStore::default();
        keys.insert_material(0x71);
        let expected = if binding_matches {
            binding_for_material(&keys, [0x72; 16])
        } else {
            arbitrary_binding(0x73)
        };
        store
            .prepare_machine_identity(expected.clone())
            .await
            .unwrap();
        store.activate_machine_identity(expected).await.unwrap();
        keys.clear_operations();

        let outcome = reconcile_machine_identity(true, &store, &keys)
            .await
            .expect("Active inconsistency is remote-only blocked");
        let RemoteBootstrapOutcome::Blocked(block) = outcome else {
            panic!("Active inconsistency must block");
        };
        assert_eq!(
            block.code(),
            if binding_matches {
                "daemon.remote.identity.guard_missing"
            } else {
                "daemon.remote.identity.state_fork"
            }
        );
        assert!(keys.store_accounts().is_empty());
        assert_eq!(load_key_directory_guard(&keys).unwrap(), None);
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn active_missing_each_key_blocks_without_recreation() {
    for (index, missing_account) in [
        MACHINE_ROOT_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_DATA_SIGN_ACCOUNT,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TestRoot::new(&format!("active-missing-key-{index}"));
        let store = open_store(&root, None).await;
        let keys = RecordingKeyStore::default();
        keys.insert_material(0x75_u8.wrapping_add(index as u8));
        let expected = binding_for_material(&keys, [0x76_u8.wrapping_add(index as u8); 16]);
        let prepared = match store
            .prepare_machine_identity(expected.clone())
            .await
            .unwrap()
        {
            agentdeckd::runtime::store::PrepareMachineIdentityOutcome::Prepared { state }
            | agentdeckd::runtime::store::PrepareMachineIdentityOutcome::Replayed { state } => {
                state
            }
        };
        store
            .activate_machine_identity(expected.clone())
            .await
            .unwrap();
        let guard = KeyDirectoryGuard::new(
            prepared.database_id,
            expected.root_fingerprint,
            expected.key_directory_revision,
        );
        install_key_directory_guard(&keys, guard).unwrap();
        keys.delete(missing_account).unwrap();
        keys.clear_operations();

        let outcome = reconcile_machine_identity(true, &store, &keys)
            .await
            .expect("missing Active key is remote-only blocked");
        let RemoteBootstrapOutcome::Blocked(block) = outcome else {
            panic!("missing Active key must block");
        };
        assert_eq!(block.code(), "daemon.remote.identity.key_missing");
        assert!(keys.store_accounts().is_empty());
        assert_eq!(load_key_directory_guard(&keys).unwrap(), Some(guard));
        assert_eq!(
            store
                .load_machine_identity_state()
                .await
                .unwrap()
                .unwrap()
                .lifecycle,
            MachineIdentityLifecycle::Active
        );
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn active_guard_revision_or_database_fork_is_blocked_without_overwrite() {
    for (label, fork_revision) in [
        ("guard-revision-fork", true),
        ("guard-database-fork", false),
    ] {
        let root = TestRoot::new(label);
        let store = open_store(&root, None).await;
        let keys = RecordingKeyStore::default();
        keys.insert_material(0x85);
        let expected = binding_for_material(&keys, [0x86; 16]);
        let prepared = match store
            .prepare_machine_identity(expected.clone())
            .await
            .unwrap()
        {
            agentdeckd::runtime::store::PrepareMachineIdentityOutcome::Prepared { state }
            | agentdeckd::runtime::store::PrepareMachineIdentityOutcome::Replayed { state } => {
                state
            }
        };
        store
            .activate_machine_identity(expected.clone())
            .await
            .unwrap();
        let mut database_id = prepared.database_id;
        let revision = if fork_revision { 1 } else { 0 };
        if !fork_revision {
            database_id[0] ^= 0xff;
        }
        let guard = KeyDirectoryGuard::new(database_id, expected.root_fingerprint, revision);
        install_key_directory_guard(&keys, guard).unwrap();
        keys.clear_operations();

        let outcome = reconcile_machine_identity(true, &store, &keys)
            .await
            .expect("guard fork is remote-only blocked");
        let RemoteBootstrapOutcome::Blocked(block) = outcome else {
            panic!("guard fork must block");
        };
        assert_eq!(block.code(), "daemon.remote.identity.state_fork");
        assert!(keys.store_accounts().is_empty());
        assert_eq!(load_key_directory_guard(&keys).unwrap(), Some(guard));
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn commit_unknown_is_retried_exactly_through_active_readback() {
    let root = TestRoot::new("commit-unknown");
    let faults = Arc::new(FailOnce::new(
        RuntimeStoreOperation::PrepareMachineIdentityAfterCommit,
    ));
    let store = open_store(&root, Some(faults)).await;
    let keys = RecordingKeyStore::default();

    let outcome = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("prepare COMMIT-unknown exact retry");
    assert!(matches!(outcome, RemoteBootstrapOutcome::Active(_)));
    assert_eq!(
        store
            .load_machine_identity_state()
            .await
            .unwrap()
            .unwrap()
            .lifecycle,
        MachineIdentityLifecycle::Active
    );
    drop(outcome);
    store.shutdown().await.unwrap();

    let root = TestRoot::new("activate-commit-unknown");
    let faults = Arc::new(FailOnce::new(
        RuntimeStoreOperation::ActivateMachineIdentityAfterCommit,
    ));
    let store = open_store(&root, Some(faults)).await;
    let keys = RecordingKeyStore::default();
    let outcome = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("activate COMMIT-unknown exact retry");
    assert!(matches!(outcome, RemoteBootstrapOutcome::Active(_)));
    drop(outcome);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn frozen_write_order_stops_before_guard_or_active_on_store_failure() {
    let root = TestRoot::new("prepare-failure-order");
    let store = open_store(
        &root,
        Some(Arc::new(FailOnce::new(
            RuntimeStoreOperation::PrepareMachineIdentityBeforeCommit,
        ))),
    )
    .await;
    let keys = RecordingKeyStore::default();
    assert!(matches!(
        reconcile_machine_identity(true, &store, &keys).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    assert_eq!(
        keys.store_accounts(),
        vec![
            MACHINE_ROOT_SIGN_ACCOUNT,
            MACHINE_HPKE_ACCOUNT,
            MACHINE_LINK_SIGN_ACCOUNT,
            MACHINE_DATA_SIGN_ACCOUNT,
        ]
    );
    assert_eq!(store.load_machine_identity_state().await.unwrap(), None);
    assert_eq!(load_key_directory_guard(&keys).unwrap(), None);
    keys.clear_operations();
    let retry = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("retry prepare before-COMMIT failure");
    assert!(matches!(retry, RemoteBootstrapOutcome::Active(_)));
    assert_eq!(keys.store_accounts(), vec![KEY_DIRECTORY_GUARD_ACCOUNT]);
    drop(retry);
    store.shutdown().await.unwrap();

    let root = TestRoot::new("activate-failure-order");
    let store = open_store(
        &root,
        Some(Arc::new(FailOnce::new(
            RuntimeStoreOperation::ActivateMachineIdentityBeforeCommit,
        ))),
    )
    .await;
    let keys = RecordingKeyStore::default();
    assert!(matches!(
        reconcile_machine_identity(true, &store, &keys).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    let state = store.load_machine_identity_state().await.unwrap().unwrap();
    assert_eq!(state.lifecycle, MachineIdentityLifecycle::Preparing);
    assert!(load_key_directory_guard(&keys).unwrap().is_some());
    keys.clear_operations();
    let retry = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect("retry activate before-COMMIT failure");
    assert!(matches!(retry, RemoteBootstrapOutcome::Active(_)));
    assert!(keys.store_accounts().is_empty());
    drop(retry);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn authenticated_store_failures_remain_runtime_fatal() {
    let root = TestRoot::new("store-fatal");
    let store = open_store(&root, None).await;
    let keys = RecordingKeyStore::default();
    store.clone().shutdown().await.unwrap();

    let error = reconcile_machine_identity(true, &store, &keys)
        .await
        .expect_err("closed authenticated store must remain fatal");
    assert!(matches!(
        error,
        RuntimeStoreError::WorkerStopped | RuntimeStoreError::ShutdownInProgress
    ));
    assert!(keys.operations().is_empty());
}
