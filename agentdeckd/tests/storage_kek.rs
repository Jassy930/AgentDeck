use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentdeckd::config::{DaemonConfig, DaemonStartupOptions};
use agentdeckd::security::{
    KeyStore, KeyStoreError, MemoryKeyStore, STORAGE_KEK_ACCOUNT, SecretBytes, StorageKekError,
    key_store_for_config, load_or_create_storage_kek,
};

struct TestDir(PathBuf);

#[cfg(target_os = "macos")]
struct KeychainTestCleanup<'a> {
    store: &'a dyn KeyStore,
    account: String,
}

#[cfg(target_os = "macos")]
impl Drop for KeychainTestCleanup<'_> {
    fn drop(&mut self) {
        let _ = self.store.delete(&self.account);
    }
}

impl TestDir {
    fn new(name: &str) -> Self {
        #[cfg(unix)]
        let temp_base = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let temp_base = std::env::temp_dir();
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let path = temp_base.join(format!(
            "adk-{name}-{}-{}",
            std::process::id(),
            &unique[..8]
        ));
        fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn runtime_db(&self) -> PathBuf {
        self.0.join("runtime.db")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct RecordingStore {
    values: Mutex<HashMap<String, Vec<u8>>>,
    loads: AtomicUsize,
    stores: AtomicUsize,
    deletes: AtomicUsize,
    fail_load: bool,
    fail_store: bool,
    discard_store: bool,
}

impl RecordingStore {
    fn with_value(account: &str, value: Vec<u8>) -> Self {
        Self {
            values: Mutex::new(HashMap::from([(account.to_owned(), value)])),
            ..Self::default()
        }
    }
}

impl KeyStore for RecordingStore {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if self.fail_load {
            return Err(KeyStoreError::Backend {
                operation: "load",
                status: -1,
            });
        }
        Ok(self
            .values
            .lock()
            .expect("recording store lock")
            .get(account)
            .map(|value| SecretBytes::new(value.clone())))
    }

    fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
        self.stores.fetch_add(1, Ordering::SeqCst);
        if self.fail_store {
            return Err(KeyStoreError::Backend {
                operation: "store",
                status: -2,
            });
        }
        if self.discard_store {
            return Ok(());
        }
        self.values
            .lock()
            .expect("recording store lock")
            .insert(account.to_owned(), value.expose_secret().to_vec());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.values
            .lock()
            .expect("recording store lock")
            .remove(account);
        Ok(())
    }
}

#[test]
fn fresh_namespace_generates_once_then_loads_the_same_storage_kek() {
    let dir = TestDir::new("fresh");
    let store = RecordingStore::default();

    let first = load_or_create_storage_kek(&store, &dir.runtime_db()).expect("first load");
    let second = load_or_create_storage_kek(&store, &dir.runtime_db()).expect("second load");

    assert_eq!(first.expose_secret(), second.expose_secret());
    assert_eq!(first.expose_secret().len(), 32);
    assert_eq!(store.stores.load(Ordering::SeqCst), 1);
    assert_eq!(store.loads.load(Ordering::SeqCst), 3);
}

#[test]
fn any_nonempty_runtime_artifact_with_missing_key_fails_without_writing() {
    for suffix in ["", "-wal", "-shm"] {
        let dir = TestDir::new(if suffix.is_empty() {
            "db"
        } else {
            &suffix[1..]
        });
        let runtime_db = dir.runtime_db();
        fs::write(
            PathBuf::from(format!("{}{}", runtime_db.display(), suffix)),
            b"x",
        )
        .expect("write runtime artifact");
        let store = RecordingStore::default();

        let error = load_or_create_storage_kek(&store, &runtime_db).unwrap_err();

        assert!(matches!(error, StorageKekError::StorageKeyMissing));
        assert_eq!(error.code(), "daemon.storage.key_missing");
        assert_eq!(store.stores.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn empty_runtime_artifacts_do_not_block_first_key_creation() {
    let dir = TestDir::new("empty-artifacts");
    let runtime_db = dir.runtime_db();
    for path in runtime_artifacts(&runtime_db) {
        fs::write(path, []).expect("create empty artifact");
    }
    let store = RecordingStore::default();

    load_or_create_storage_kek(&store, &runtime_db).expect("create key");

    assert_eq!(store.stores.load(Ordering::SeqCst), 1);
}

#[test]
fn malformed_stored_key_fails_closed_without_replacement_write() {
    let dir = TestDir::new("bad-length");
    let store = RecordingStore::with_value(STORAGE_KEK_ACCOUNT, vec![7; 31]);

    let error = load_or_create_storage_kek(&store, &dir.runtime_db()).unwrap_err();

    assert!(matches!(
        error,
        StorageKekError::InvalidKeyLength { actual: 31 }
    ));
    assert_eq!(store.stores.load(Ordering::SeqCst), 0);
}

#[test]
fn keystore_load_and_store_errors_fail_closed() {
    let dir = TestDir::new("backend-errors");
    let load_failure = RecordingStore {
        fail_load: true,
        ..RecordingStore::default()
    };
    let error = load_or_create_storage_kek(&load_failure, &dir.runtime_db()).unwrap_err();
    assert!(matches!(
        error,
        StorageKekError::KeyStore(KeyStoreError::Backend {
            operation: "load",
            status: -1
        })
    ));
    assert_eq!(load_failure.stores.load(Ordering::SeqCst), 0);

    let store_failure = RecordingStore {
        fail_store: true,
        ..RecordingStore::default()
    };
    let error = load_or_create_storage_kek(&store_failure, &dir.runtime_db()).unwrap_err();
    assert!(matches!(
        error,
        StorageKekError::KeyStore(KeyStoreError::Backend {
            operation: "store",
            status: -2
        })
    ));
}

#[test]
fn successful_store_must_be_readable_before_the_key_is_returned() {
    let dir = TestDir::new("store-readback");
    let store = RecordingStore {
        discard_store: true,
        ..RecordingStore::default()
    };

    let error = load_or_create_storage_kek(&store, &dir.runtime_db()).unwrap_err();

    assert!(matches!(error, StorageKekError::PersistedKeyMissing));
    assert_eq!(error.code(), "daemon.storage.key_persistence_failed");
    assert_eq!(store.stores.load(Ordering::SeqCst), 1);
    assert_eq!(store.loads.load(Ordering::SeqCst), 2);
}

#[test]
fn secrets_never_render_key_material_in_debug() {
    let marker = vec![0xa5; 32];
    let secret = SecretBytes::new(marker.clone());
    let store = RecordingStore::with_value(STORAGE_KEK_ACCOUNT, marker);
    let dir = TestDir::new("debug");
    let kek = load_or_create_storage_kek(&store, &dir.runtime_db()).expect("load key");

    assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
    assert_eq!(format!("{kek:?}"), "StorageKek([REDACTED])");
    assert!(!format!("{secret:?}{kek:?}").contains("165"));
}

#[test]
fn memory_store_delete_of_missing_account_is_idempotent() {
    let store = MemoryKeyStore::new();

    store.delete("does-not-exist").expect("first delete");
    store.delete("does-not-exist").expect("second delete");
    assert!(store.load("does-not-exist").expect("load").is_none());
}

#[test]
fn independent_memory_stores_do_not_share_ephemeral_secrets() {
    let first = MemoryKeyStore::new();
    let second = MemoryKeyStore::new();
    let secret = SecretBytes::new(vec![0x5a; 32]);
    first.store(STORAGE_KEK_ACCOUNT, &secret).expect("store");

    assert!(
        first
            .load(STORAGE_KEK_ACCOUNT)
            .expect("first load")
            .is_some()
    );
    assert!(
        second
            .load(STORAGE_KEK_ACCOUNT)
            .expect("second load")
            .is_none()
    );
}

#[test]
fn config_factory_uses_memory_only_for_ephemeral_and_rejects_uncompiled_stable() {
    let dir = TestDir::new("factory");
    let ephemeral = DaemonConfig::resolve_with_roots(
        DaemonStartupOptions {
            ephemeral: true,
            no_remote: true,
            profile: None,
            stable_keychain_access_group: None,
        },
        &dir.0,
        &dir.0,
    )
    .expect("ephemeral config");
    let store = key_store_for_config(&ephemeral).expect("ephemeral memory store");
    store
        .store(STORAGE_KEK_ACCOUNT, &SecretBytes::new(vec![0x33; 32]))
        .expect("store ephemeral key");
    assert!(store.load(STORAGE_KEK_ACCOUNT).expect("load").is_some());

    let compiled_group = agentdeckd::config::compiled_stable_keychain_access_group();
    let stable_group = compiled_group
        .clone()
        .unwrap_or_else(|| "A1B2C3D4E5.com.agentdeck.agentdeckd.stable".to_owned());
    let stable = DaemonConfig::resolve_with_roots(
        DaemonStartupOptions {
            ephemeral: false,
            no_remote: false,
            profile: None,
            stable_keychain_access_group: Some(stable_group),
        },
        &dir.0,
        &dir.0,
    )
    .expect("stable config");
    let stable_store = key_store_for_config(&stable);
    if !cfg!(target_os = "macos") {
        assert!(matches!(
            stable_store,
            Err(KeyStoreError::UnsupportedPlatform)
        ));
    } else if compiled_group.is_none() {
        assert!(matches!(
            stable_store,
            Err(KeyStoreError::AccessGroupMissing)
        ));
    } else {
        assert!(stable_store.is_ok());
    }
}

#[test]
fn macos_keychain_rejects_documentation_placeholder_before_backend_io() {
    use agentdeckd::security::MacOsKeychainStore;

    let error = MacOsKeychainStore::new(
        "com.agentdeck.agentdeckd.stable",
        Some("TEAMID.com.agentdeck.agentdeckd.stable".to_owned()),
    )
    .unwrap_err();
    assert!(matches!(error, KeyStoreError::AccessGroupInvalid));
    assert_eq!(error.code(), "daemon.keystore.access_group_invalid");
}

#[test]
fn macos_keychain_does_not_accept_an_uncompiled_access_group() {
    use agentdeckd::security::MacOsKeychainStore;

    if agentdeckd::config::compiled_stable_keychain_access_group().is_some() {
        return;
    }
    let error = MacOsKeychainStore::new(
        "com.agentdeck.agentdeckd.stable",
        Some("A1B2C3D4E5.com.agentdeck.agentdeckd.stable".to_owned()),
    )
    .unwrap_err();
    assert!(matches!(error, KeyStoreError::AccessGroupMissing));
}

/// 该测试必须在带 daemon-only Keychain entitlement 的已签名 test helper 上运行：
/// `AGENTDECK_DAEMON_KEYCHAIN_ACCESS_GROUP` 在编译时注入同一展开值，运行时再由
/// `AGENTDECK_TEST_KEYCHAIN_ACCESS_GROUP` 明确选择。默认忽略，避免 unsigned CI 把
/// `errSecMissingEntitlement` 误判成实现回归。
#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires a codesigned helper with the daemon-only Keychain access group"]
fn macos_keychain_signed_set_load_delete_roundtrip() {
    use agentdeckd::security::MacOsKeychainStore;

    let access_group = std::env::var("AGENTDECK_TEST_KEYCHAIN_ACCESS_GROUP")
        .expect("AGENTDECK_TEST_KEYCHAIN_ACCESS_GROUP must name the signed entitlement");
    assert_eq!(
        agentdeckd::config::compiled_stable_keychain_access_group().as_deref(),
        Some(access_group.as_str()),
        "runtime test group must equal the group compiled into agentdeckd"
    );
    let unique = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4());
    let service = format!("com.agentdeck.agentdeckd.keychain-test.{unique}");
    let account = format!("storage-kek-test.{unique}");
    let store = MacOsKeychainStore::new(service, Some(access_group)).expect("construct store");
    let _ = store.delete(&account);
    let cleanup = KeychainTestCleanup {
        store: &store,
        account: account.clone(),
    };

    let expected = SecretBytes::new((0_u8..32).collect());
    store
        .store(&account, &expected)
        .expect("store protected item");
    let loaded = store
        .load(&account)
        .expect("load protected item")
        .expect("stored item exists");
    assert_eq!(loaded.expose_secret(), expected.expose_secret());

    store.delete(&account).expect("delete protected item");
    assert!(store.load(&account).expect("load after delete").is_none());
    drop(cleanup);
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_wal_artifact_cannot_be_missed() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = TestDir::new("non-utf8");
    let runtime_db = dir.0.join(OsString::from_vec(vec![b'r', 0xff, b'd', b'b']));
    fs::write(sidecar(&runtime_db, "-wal"), b"existing encrypted state")
        .expect("write non-UTF-8 WAL");
    let store = RecordingStore::default();
    assert!(matches!(
        load_or_create_storage_kek(&store, &runtime_db),
        Err(StorageKekError::StorageKeyMissing)
    ));
    assert_eq!(store.stores.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[test]
fn runtime_artifact_symlink_is_treated_as_existing_state() {
    use std::os::unix::fs::symlink;

    let dir = TestDir::new("symlink");
    let symlink_db = dir.0.join("symlink.db");
    let target = dir.0.join("empty-target");
    fs::write(&target, []).expect("write empty target");
    symlink(&target, &symlink_db).expect("create runtime DB symlink");
    assert!(matches!(
        load_or_create_storage_kek(&RecordingStore::default(), &symlink_db),
        Err(StorageKekError::StorageKeyMissing)
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_keychain_requires_a_provisioned_access_group() {
    use agentdeckd::security::MacOsKeychainStore;

    let error = MacOsKeychainStore::new("com.agentdeck.agentdeckd.stable", None).unwrap_err();
    assert!(matches!(error, KeyStoreError::AccessGroupMissing));
    assert_eq!(error.code(), "daemon.keystore.access_group_unconfigured");
}

fn runtime_artifacts(runtime_db: &Path) -> [PathBuf; 3] {
    [
        runtime_db.to_path_buf(),
        sidecar(runtime_db, "-wal"),
        sidecar(runtime_db, "-shm"),
    ]
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}
