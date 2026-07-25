use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use agentdeck_crypto::sha256;
use agentdeck_protocol::runtime::command::HelloParams;
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeReply, RuntimeRequest,
};
use agentdeckd::config::{DaemonConfig, DaemonStartupOptions};
use agentdeckd::local::listener::BoundLocalListener;
use agentdeckd::remote::bootstrap::{RemoteBootstrapOutcome, reconcile_machine_identity};
use agentdeckd::remote::identity::{
    KEY_DIRECTORY_GUARD_ACCOUNT, KeyDirectoryGuard, MACHINE_DATA_SIGN_ACCOUNT,
    MACHINE_HPKE_ACCOUNT, MACHINE_LINK_SIGN_ACCOUNT, MACHINE_ROOT_SIGN_ACCOUNT,
    install_key_directory_guard, load_key_directory_guard, load_machine_key_material,
};
use agentdeckd::runtime::singleton::SingletonGuard;
use agentdeckd::runtime::store::{
    MachineIdentityBinding, MachineIdentityLifecycle, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::runtime::{AgentRouter, RuntimeCore};
use agentdeckd::security::{
    KeyStore, KeyStoreError, MemoryKeyStore, SecretBytes, load_or_create_storage_kek,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const LOCAL_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PARALLEL_BOOTSTRAP_FIXTURES: usize = 4;
static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);
static AVAILABLE_BOOTSTRAP_FIXTURES: Mutex<usize> = Mutex::new(MAX_PARALLEL_BOOTSTRAP_FIXTURES);
static BOOTSTRAP_FIXTURE_AVAILABLE: Condvar = Condvar::new();

#[derive(Debug)]
struct BootstrapFixtureSlot;

impl BootstrapFixtureSlot {
    fn acquire() -> Self {
        let available = AVAILABLE_BOOTSTRAP_FIXTURES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut available = BOOTSTRAP_FIXTURE_AVAILABLE
            .wait_while(available, |available| *available == 0)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *available -= 1;
        Self
    }
}

impl Drop for BootstrapFixtureSlot {
    fn drop(&mut self) {
        let mut available = AVAILABLE_BOOTSTRAP_FIXTURES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(*available < MAX_PARALLEL_BOOTSTRAP_FIXTURES);
        *available += 1;
        BOOTSTRAP_FIXTURE_AVAILABLE.notify_one();
    }
}

#[derive(Debug)]
struct TestRoot(PathBuf, BootstrapFixtureSlot);

impl TestRoot {
    fn new(_label: &str) -> Self {
        // macOS 的默认进程 fd 上限通常只有 256。每个真实 runtime store 会同时保留
        // writer、8 个只读 WAL connection 及其 DB/WAL/SHM 描述符；libtest 默认并行
        // 启动全部 18 项时会先耗尽 fd，掩盖成 read-only pool 初始化失败。这里只约束
        // integration fixture 的并行驻留量，不改变 production read pool 的容量或校验。
        let fixture_slot = BootstrapFixtureSlot::acquire();
        let path = Path::new("/tmp").join(format!(
            "adb-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create bootstrap test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure bootstrap test root");
        }
        Self(path, fixture_slot)
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

fn ephemeral_config(root: &TestRoot) -> DaemonConfig {
    DaemonConfig::resolve_with_roots(
        DaemonStartupOptions {
            ephemeral: true,
            no_remote: true,
            stdio_compat: false,
            profile: None,
            stable_keychain_access_group: None,
        },
        &root.0,
        &root.0,
    )
    .expect("resolve ephemeral bootstrap config")
}

fn stable_config(root: &TestRoot) -> DaemonConfig {
    let home = root.0.join("home");
    fs::create_dir_all(home.join("Library/Application Support"))
        .expect("create stable bootstrap home");
    DaemonConfig::resolve_with_roots(
        DaemonStartupOptions {
            ephemeral: false,
            no_remote: false,
            stdio_compat: false,
            profile: None,
            stable_keychain_access_group: Some(
                "A1B2C3D4E5.com.agentdeck.agentdeckd.stable".to_owned(),
            ),
        },
        &home,
        &root.0,
    )
    .expect("resolve stable bootstrap config")
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

    fn values_snapshot(&self) -> HashMap<String, Vec<u8>> {
        self.values.lock().unwrap().clone()
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

struct PoisonKeyStore;

impl KeyStore for PoisonKeyStore {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
        panic!("disabled bootstrap unexpectedly loaded {account}")
    }

    fn store(&self, account: &str, _value: &SecretBytes) -> Result<(), KeyStoreError> {
        panic!("disabled bootstrap unexpectedly stored {account}")
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        panic!("disabled bootstrap unexpectedly deleted {account}")
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

async fn reconcile_stable(
    root: &TestRoot,
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
) -> Result<RemoteBootstrapOutcome, RuntimeStoreError> {
    let config = stable_config(root);
    reconcile_machine_identity(&config, store, key_store).await
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
        "RelayEnrollmentClient",
        "RemoteLink",
        "record_enrollment_receipt",
        "load_enrollment_receipt",
        "machine_enrollment_receipts",
        "WebSocket",
        "tokio_tungstenite",
        "TcpStream",
        "TcpListener",
        "--file-keystore",
        "--machine-key-file",
        "AGENTDECK_MACHINE_KEY",
        "AGENTDECK_KEY_DIRECTORY_GUARD",
    ] {
        assert!(
            !production.contains(forbidden),
            "bootstrap/main production source must not own {forbidden}"
        );
    }
}

#[tokio::test]
async fn disabled_bootstrap_performs_zero_machine_account_io() {
    let root = TestRoot::new("disabled");
    let store = open_store(&root, None).await;
    let config = ephemeral_config(&root);

    let outcome = reconcile_machine_identity(&config, &store, &PoisonKeyStore)
        .await
        .expect("disabled bootstrap");
    assert!(matches!(outcome, RemoteBootstrapOutcome::Disabled));
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

    let first = reconcile_stable(&root, &store, &keys)
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
    let second = reconcile_stable(&root, &store, &keys)
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

    let outcome = reconcile_stable(&root, &store, &keys)
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

    let outcome = reconcile_stable(&root, &store, &keys)
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

    let outcome = reconcile_stable(&root, &store, &keys)
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

    let outcome = reconcile_stable(&root, &store, &keys)
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

    let outcome = reconcile_stable(&root, &store, &keys)
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

    let outcome = reconcile_stable(&root, &store, &keys)
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
async fn preparing_guard_forks_block_without_mutating_any_identity_artifact() {
    for axis in ["database", "root", "revision"] {
        let root = TestRoot::new(&format!("preparing-guard-{axis}-fork"));
        let store = open_store(&root, None).await;
        let keys = RecordingKeyStore::default();
        keys.insert_material(0x6A);
        let expected = binding_for_material(&keys, [0x6B; 16]);
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
        let mut database_id = prepared.database_id;
        let mut root_fingerprint = expected.root_fingerprint;
        let mut revision = expected.key_directory_revision;
        match axis {
            "database" => database_id[0] ^= 0x80,
            "root" => root_fingerprint[0] ^= 0x40,
            "revision" => revision += 1,
            _ => unreachable!(),
        }
        let guard = KeyDirectoryGuard::new(database_id, root_fingerprint, revision);
        install_key_directory_guard(&keys, guard).unwrap();
        let values_before = keys.values_snapshot();
        keys.clear_operations();

        let outcome = reconcile_stable(&root, &store, &keys)
            .await
            .expect("Preparing guard fork is remote-only blocked");
        let RemoteBootstrapOutcome::Blocked(block) = outcome else {
            panic!("Preparing guard fork must block");
        };
        assert_eq!(block.code(), "daemon.remote.identity.state_fork");
        assert!(
            keys.operations()
                .iter()
                .all(|operation| matches!(operation, KeyOperation::Load(_)))
        );
        assert_eq!(keys.values_snapshot(), values_before);
        let state = store.load_machine_identity_state().await.unwrap().unwrap();
        assert_eq!(state.lifecycle, MachineIdentityLifecycle::Preparing);
        assert_eq!(state.binding, expected);
        assert_eq!(load_key_directory_guard(&keys).unwrap(), Some(guard));
        store.shutdown().await.unwrap();
    }
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

        let outcome = reconcile_stable(&root, &store, &keys)
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

        let outcome = reconcile_stable(&root, &store, &keys)
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

        let outcome = reconcile_stable(&root, &store, &keys)
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

    let outcome = reconcile_stable(&root, &store, &keys)
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
    let outcome = reconcile_stable(&root, &store, &keys)
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
        reconcile_stable(&root, &store, &keys).await,
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
    let retry = reconcile_stable(&root, &store, &keys)
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
        reconcile_stable(&root, &store, &keys).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    let state = store.load_machine_identity_state().await.unwrap().unwrap();
    assert_eq!(state.lifecycle, MachineIdentityLifecycle::Preparing);
    assert!(load_key_directory_guard(&keys).unwrap().is_some());
    keys.clear_operations();
    let retry = reconcile_stable(&root, &store, &keys)
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

    let error = reconcile_stable(&root, &store, &keys)
        .await
        .expect_err("closed authenticated store must remain fatal");
    assert!(matches!(
        error,
        RuntimeStoreError::WorkerStopped | RuntimeStoreError::ShutdownInProgress
    ));
    assert!(keys.operations().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_stable_identity_still_recovers_and_serves_real_local_hello() {
    let root = TestRoot::new("blocked-stable-local");
    let config = stable_config(&root);
    let singleton = SingletonGuard::acquire(config.paths()).expect("acquire stable singleton");
    let keys = RecordingKeyStore::default();
    let storage_kek = load_or_create_storage_kek(&keys, &config.paths().runtime_db)
        .expect("create stable composition StorageKEK");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(config.paths().runtime_db.clone()),
        storage_kek,
    )
    .await
    .expect("open stable composition store");
    keys.clear_operations();

    let active = reconcile_machine_identity(&config, &store, &keys)
        .await
        .expect("create active stable identity");
    assert!(matches!(active, RemoteBootstrapOutcome::Active(_)));
    drop(active);
    keys.delete(MACHINE_ROOT_SIGN_ACCOUNT).unwrap();
    keys.delete(KEY_DIRECTORY_GUARD_ACCOUNT).unwrap();
    keys.clear_operations();

    let blocked = reconcile_machine_identity(&config, &store, &keys)
        .await
        .expect("missing active artifacts only block remote");
    let RemoteBootstrapOutcome::Blocked(block) = &blocked else {
        panic!("deleted active key/guard must block remote");
    };
    assert_eq!(block.code(), "daemon.remote.identity.key_missing");
    assert!(keys.store_accounts().is_empty());

    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0x9A; 32])
            .expect("construct blocked-identity RuntimeCore"),
    );
    let (_, recovery_ready) = core
        .recover_for_startup()
        .await
        .expect("blocked remote identity must not block Runtime recovery");
    let mut listener =
        BoundLocalListener::bind_after_recovery(recovery_ready, &config, &singleton, core.clone())
            .await
            .expect("blocked remote identity must not block stable local bind");
    let remote_permit = listener.take_remote_start_permit();
    assert!(
        remote_permit.is_some(),
        "stable listener must mint its permit"
    );
    let armed_remote = match (blocked, remote_permit) {
        (RemoteBootstrapOutcome::Active(identity), Some(permit)) => Some(identity.arm(permit)),
        (RemoteBootstrapOutcome::Blocked(_), _discarded_permit) => None,
        (RemoteBootstrapOutcome::Disabled, _discarded_permit) => None,
        (RemoteBootstrapOutcome::Active(_), None) => None,
    };
    assert!(
        armed_remote.is_none(),
        "Blocked identity must discard the permit instead of arming remote"
    );

    let socket = config.paths().socket.clone();
    let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(listener.serve_until(async move {
        let _ = shutdown_receiver.await;
        Ok(())
    }));
    let mut stream = UnixStream::connect(&socket)
        .await
        .expect("connect blocked-identity local UDS");
    let preface = serde_json::to_vec(&serde_json::json!({
        "localProtocolVersion": 1,
        "clientInstallationId": "123e4567-e89b-12d3-a456-426614174401",
    }))
    .expect("encode local preface");
    stream
        .write_all(&preface)
        .await
        .expect("write local preface");
    stream.write_all(b"\n").await.expect("terminate preface");
    let hello = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("blocked-identity-local-hello"),
        body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };
    stream
        .write_all(&hello.to_json_bytes_checked().expect("encode local Hello"))
        .await
        .expect("write local Hello");
    stream.write_all(b"\n").await.expect("terminate Hello");
    stream.flush().await.expect("flush local Hello");
    let mut reader = BufReader::new(stream);
    let mut reply = Vec::new();
    tokio::time::timeout(LOCAL_IO_TIMEOUT, reader.read_until(b'\n', &mut reply))
        .await
        .expect("local Hello reply timeout")
        .expect("read local Hello reply");
    assert_eq!(reply.pop(), Some(b'\n'));
    let reply: RuntimeEnvelope = serde_json::from_slice(&reply).expect("decode local Hello reply");
    assert_eq!(reply.message_id.as_str(), "blocked-identity-local-hello");
    assert!(matches!(
        reply.body,
        RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
    drop(reader);
    shutdown.send(()).expect("request local listener shutdown");
    tokio::time::timeout(LOCAL_IO_TIMEOUT, server)
        .await
        .expect("local listener shutdown timeout")
        .expect("join local listener")
        .expect("stop local listener");
    drop(armed_remote);
    core.shutdown()
        .await
        .expect("shutdown blocked-identity RuntimeCore");
}

#[tokio::test]
async fn stable_private_material_never_enters_runtime_artifacts_or_identity_logs() {
    let root = TestRoot::new("private-material-sentinel");
    let config = stable_config(&root);
    let _singleton =
        SingletonGuard::acquire(config.paths()).expect("acquire sentinel stable singleton");
    let identity_keys = RecordingKeyStore::default();
    let private_values: [[u8; 32]; 4] = [
        std::array::from_fn(|index| 0x10_u8.wrapping_add(index as u8)),
        std::array::from_fn(|index| 0x40_u8.wrapping_add(index as u8)),
        std::array::from_fn(|index| 0x70_u8.wrapping_add(index as u8)),
        std::array::from_fn(|index| 0xA0_u8.wrapping_add(index as u8)),
    ];
    for (account, private_value) in [
        MACHINE_ROOT_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_DATA_SIGN_ACCOUNT,
    ]
    .into_iter()
    .zip(private_values)
    {
        identity_keys
            .store(account, &SecretBytes::new(private_value.to_vec()))
            .expect("store deterministic private sentinel");
    }
    let storage_keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(config.paths().runtime_db.clone()),
        load_or_create_storage_kek(&storage_keys, &config.paths().runtime_db)
            .expect("create sentinel StorageKEK"),
    )
    .await
    .expect("open sentinel stable store");

    let outcome = reconcile_machine_identity(&config, &store, &identity_keys)
        .await
        .expect("activate deterministic stable identity");
    assert_eq!(
        format!("{outcome:?}"),
        "RemoteBootstrapOutcome::Active([REDACTED])"
    );
    let RemoteBootstrapOutcome::Active(active) = outcome else {
        panic!("deterministic stable identity must become Active");
    };
    assert_eq!(format!("{active:?}"), "ActiveMachineIdentity([REDACTED])");
    drop(active);
    store.shutdown().await.expect("shutdown sentinel store");

    for path in [
        config.paths().runtime_db.clone(),
        PathBuf::from(format!("{}-wal", config.paths().runtime_db.display())),
        PathBuf::from(format!("{}-shm", config.paths().runtime_db.display())),
        PathBuf::from(format!("{}-journal", config.paths().runtime_db.display())),
    ] {
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("read raw runtime artifact {}: {error}", path.display()),
        };
        for private_value in private_values {
            assert!(
                !bytes
                    .windows(private_value.len())
                    .any(|window| window == private_value),
                "private sentinel appeared in raw runtime artifact {}",
                path.display()
            );
        }
    }

    let main_source = include_str!("../src/main.rs");
    let start = main_source
        .find("fn run_main_loop(")
        .expect("find production main-loop composition");
    let end = main_source[start..]
        .find("\nfn main()")
        .map(|offset| start + offset)
        .expect("find production main-loop end");
    let main_loop = &main_source[start..end];
    assert_eq!(main_loop.matches("\"remote_identity\"").count(), 3);
    assert_eq!(main_loop.matches("\"remote_manager\"").count(), 3);
    for allowed in ["status=disabled", "status=active", "status=blocked code={}"] {
        assert!(
            main_loop.contains(allowed),
            "remote identity log call graph must retain code-only fragment {allowed}"
        );
    }
    for forbidden in [
        "binding()",
        "public_identity",
        "root_fingerprint",
        "MachineKeyMaterial",
        "{remote_identity:?}",
        "{identity:?}",
    ] {
        assert!(
            !main_loop.contains(forbidden),
            "remote identity log call graph must not format {forbidden}"
        );
    }
}
