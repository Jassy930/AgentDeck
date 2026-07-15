//! P3.8-B1 secure bind、typed permit 与 graceful supervisor 行为门禁。

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agentdeckd::config::{DaemonConfig, DaemonStartupOptions};
use agentdeckd::local::listener::{BoundLocalListener, LocalListenerError};
use agentdeckd::runtime::recovery::RecoveryReadyPermit;
use agentdeckd::runtime::singleton::SingletonGuard;
use agentdeckd::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
use agentdeckd::runtime::{AgentRouter, RuntimeCore};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use tokio::net::UnixStream;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "adl-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create local listener root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure local listener root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
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
        root.path(),
        root.path(),
    )
    .expect("resolve ephemeral listener config")
}

fn stable_config(root: &TestRoot) -> DaemonConfig {
    let home = root.path().join("h");
    fs::create_dir(&home).expect("create stable home");
    fs::create_dir_all(home.join("Library/Application Support"))
        .expect("create stable data parent");
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
        root.path(),
    )
    .expect("resolve stable listener config")
}

async fn recovered_core(config: &DaemonConfig) -> (Arc<RuntimeCore>, RecoveryReadyPermit) {
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &config.paths().runtime_db)
        .expect("create listener StorageKEK");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(config.paths().runtime_db.clone()),
        kek,
    )
    .await
    .expect("open listener Runtime store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xB1; 32]).expect("construct listener RuntimeCore"),
    );
    let (_, permit) = core
        .recover_for_startup()
        .await
        .expect("recover listener RuntimeCore");
    (core, permit)
}

async fn shutdown_core(core: &RuntimeCore) {
    core.shutdown()
        .await
        .expect("shutdown listener RuntimeCore");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ephemeral_bind_is_private_local_only_and_preserves_replacement() {
    // 威胁场景：listener 存活期 pathname 被同 UID 流程替换；RAII cleanup 不得
    // 删除替换物，ephemeral bind 也绝不能签发 remote start capability。
    let root = TestRoot::new("ep");
    let config = ephemeral_config(&root);
    let singleton = SingletonGuard::acquire(config.paths()).expect("acquire singleton");
    let (core, permit) = recovered_core(&config).await;
    let mut bound =
        BoundLocalListener::bind_after_recovery(permit, &config, &singleton, core.clone())
            .await
            .expect("secure ephemeral bind");

    let socket = config.paths().socket.clone();
    let metadata = fs::symlink_metadata(&socket).expect("inspect bound socket");
    // SAFETY: geteuid reads only the current process credential.
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(bound.local_ready_permit().socket_path(), socket);
    assert!(bound.take_remote_start_permit().is_none());

    fs::remove_file(&socket).expect("unlink owned socket for replacement fixture");
    fs::write(&socket, b"replacement").expect("create replacement");
    drop(bound);
    assert_eq!(
        fs::read(&socket).expect("read preserved replacement"),
        b"replacement"
    );
    shutdown_core(&core).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stable_canonical_bind_mints_remote_start_exactly_once() {
    let root = TestRoot::new("st");
    let config = stable_config(&root);
    let singleton = SingletonGuard::acquire(config.paths()).expect("acquire stable singleton");
    let (core, permit) = recovered_core(&config).await;
    let mut bound =
        BoundLocalListener::bind_after_recovery(permit, &config, &singleton, core.clone())
            .await
            .expect("secure stable bind");

    assert!(bound.take_remote_start_permit().is_some());
    assert!(bound.take_remote_start_permit().is_none());
    let socket = config.paths().socket.clone();
    drop(bound);
    assert!(
        !socket.exists(),
        "exact socket must be cleaned after listener drop"
    );
    shutdown_core(&core).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_core_recovery_permit_cannot_bind_or_mint_remote_start() {
    // 威胁场景：已恢复 Core A 的 permit 若能被 Core B 洗用，B 可以在自身
    // recovery 证明之外开放 stable UDS，并进一步签发 remote start capability。
    let root_a = TestRoot::new("core-a");
    let config_a = stable_config(&root_a);
    let _singleton_a = SingletonGuard::acquire(config_a.paths()).expect("acquire Core A singleton");
    let (core_a, permit_a) = recovered_core(&config_a).await;

    let root_b = TestRoot::new("core-b");
    let config_b = stable_config(&root_b);
    let singleton_b = SingletonGuard::acquire(config_b.paths()).expect("acquire Core B singleton");
    let (core_b, _permit_b) = recovered_core(&config_b).await;

    let error =
        BoundLocalListener::bind_after_recovery(permit_a, &config_b, &singleton_b, core_b.clone())
            .await
            .expect_err("foreign recovery permit must not produce a bound listener");
    assert!(matches!(error, LocalListenerError::RecoveryPermitMismatch));
    assert!(
        !config_b.paths().socket.exists(),
        "foreign permit must not create a socket or make remote permit minting reachable"
    );

    shutdown_core(&core_a).await;
    shutdown_core(&core_b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_socket_is_replaced_but_active_socket_is_preserved() {
    let stale_root = TestRoot::new("stale");
    let stale_config = ephemeral_config(&stale_root);
    let stale_singleton =
        SingletonGuard::acquire(stale_config.paths()).expect("acquire stale singleton");
    let stale_socket = stale_config.paths().socket.clone();
    let stale = std::os::unix::net::UnixListener::bind(&stale_socket).expect("bind stale fixture");
    // 0700 parent 已隔离其他 UID；允许清理由 bind→chmod 窗口崩溃留下的宽 mode，
    // 新 listener 的 permit 前 readback 仍必须收紧到 exact 0600。
    fs::set_permissions(&stale_socket, fs::Permissions::from_mode(0o755))
        .expect("set pre-chmod stale fixture mode");
    let stale_inode = fs::symlink_metadata(&stale_socket)
        .expect("stale metadata")
        .ino();
    drop(stale);
    let (stale_core, stale_permit) = recovered_core(&stale_config).await;
    let bound = BoundLocalListener::bind_after_recovery(
        stale_permit,
        &stale_config,
        &stale_singleton,
        stale_core.clone(),
    )
    .await
    .expect("replace verified stale socket");
    assert_ne!(
        fs::symlink_metadata(&stale_socket)
            .expect("new socket metadata")
            .ino(),
        stale_inode
    );
    drop(bound);
    shutdown_core(&stale_core).await;

    let active_root = TestRoot::new("active");
    let active_config = ephemeral_config(&active_root);
    let active_singleton =
        SingletonGuard::acquire(active_config.paths()).expect("acquire active singleton");
    let active_socket = active_config.paths().socket.clone();
    let active =
        std::os::unix::net::UnixListener::bind(&active_socket).expect("bind active fixture");
    fs::set_permissions(&active_socket, fs::Permissions::from_mode(0o600))
        .expect("secure active fixture");
    let active_inode = fs::symlink_metadata(&active_socket)
        .expect("active metadata")
        .ino();
    let (active_core, active_permit) = recovered_core(&active_config).await;
    let error = BoundLocalListener::bind_after_recovery(
        active_permit,
        &active_config,
        &active_singleton,
        active_core.clone(),
    )
    .await
    .expect_err("active socket must reject second listener");
    assert!(matches!(error, LocalListenerError::SocketInUse { .. }));
    assert_eq!(
        fs::symlink_metadata(&active_socket)
            .expect("preserved active metadata")
            .ino(),
        active_inode
    );
    drop(active);
    fs::remove_file(&active_socket).expect("clean active fixture");
    shutdown_core(&active_core).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regular_file_and_symlink_entries_are_preserved_and_rejected() {
    // 威胁场景：预置普通文件或 symlink 若被 stale cleanup 当作 socket unlink，
    // daemon 会破坏同 UID 数据并可能把控制面绑定到未经审计的对象。
    for fixture in ["regular", "symlink"] {
        let root = TestRoot::new(fixture);
        let config = ephemeral_config(&root);
        let singleton = SingletonGuard::acquire(config.paths()).expect("acquire fixture singleton");
        let socket = config.paths().socket.clone();
        match fixture {
            "regular" => fs::write(&socket, b"preserve").expect("create regular fixture"),
            "symlink" => std::os::unix::fs::symlink("missing-target", &socket)
                .expect("create symlink fixture"),
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&socket)
            .expect("fixture metadata")
            .ino();
        let (core, permit) = recovered_core(&config).await;
        let error =
            BoundLocalListener::bind_after_recovery(permit, &config, &singleton, core.clone())
                .await
                .expect_err("non-socket entry must fail closed");
        assert!(matches!(error, LocalListenerError::UnsafeSocket { .. }));
        assert_eq!(
            fs::symlink_metadata(&socket)
                .expect("preserved fixture metadata")
                .ino(),
            before
        );
        fs::remove_file(&socket).expect("remove preserved fixture");
        shutdown_core(&core).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_data_directory_swap_rejects_bind_without_side_effect() {
    let root = TestRoot::new("swap");
    let config = ephemeral_config(&root);
    let singleton = SingletonGuard::acquire(config.paths()).expect("acquire swap singleton");
    let (core, permit) = recovered_core(&config).await;
    let original = config.paths().data_dir.with_extension("original");
    fs::rename(&config.paths().data_dir, &original).expect("move retained data directory");
    fs::create_dir(&config.paths().data_dir).expect("create replacement data directory");
    fs::set_permissions(&config.paths().data_dir, fs::Permissions::from_mode(0o700))
        .expect("secure replacement data directory");

    let error = BoundLocalListener::bind_after_recovery(permit, &config, &singleton, core.clone())
        .await
        .expect_err("retained directory swap must fail closed");
    assert!(matches!(error, LocalListenerError::Singleton(_)));
    assert!(
        !config.paths().socket.exists(),
        "replacement directory must see no socket side effect"
    );
    shutdown_core(&core).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_gracefully_joins_a_stalled_preface_connection() {
    let root = TestRoot::new("stop");
    let config = ephemeral_config(&root);
    let singleton = SingletonGuard::acquire(config.paths()).expect("acquire stop singleton");
    let (core, permit) = recovered_core(&config).await;
    let bound = BoundLocalListener::bind_after_recovery(permit, &config, &singleton, core.clone())
        .await
        .expect("bind supervisor listener");
    let socket = config.paths().socket.clone();
    let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(bound.serve_until(async move {
        let _ = shutdown_receiver.await;
        Ok(())
    }));

    let client = UnixStream::connect(&socket)
        .await
        .expect("connect stalled preface client");
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.send(()).expect("request listener shutdown");
    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("listener shutdown timed out")
        .expect("join listener supervisor")
        .expect("listener supervisor shutdown");
    drop(client);
    assert!(
        !socket.exists(),
        "socket cleanup must follow connection joins"
    );
    shutdown_core(&core).await;
}
