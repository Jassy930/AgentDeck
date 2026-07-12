use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeckd::config::{DaemonConfig, DaemonConfigError, DaemonProfile, DaemonStartupOptions};
use agentdeckd::runtime::namespace::{DaemonMode, DaemonPaths, NamespaceError};
use agentdeckd::runtime::singleton::{SingletonError, SingletonGuard};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        #[cfg(unix)]
        let temp_base = Path::new("/tmp").to_path_buf();
        #[cfg(not(unix))]
        let temp_base = std::env::temp_dir();
        let path = temp_base.join(format!(
            "agentdeckd-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create isolated test root");
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

fn options(ephemeral: bool, no_remote: bool) -> DaemonStartupOptions {
    DaemonStartupOptions {
        ephemeral,
        no_remote,
        profile: None,
        stable_keychain_access_group: None,
    }
}

fn stable_options() -> DaemonStartupOptions {
    DaemonStartupOptions {
        stable_keychain_access_group: Some("A1B2C3D4E5.com.agentdeck.agentdeckd.stable".to_owned()),
        ..options(false, false)
    }
}

#[test]
fn stable_namespace_uses_the_exact_product_paths() {
    let root = TestRoot::new("stable-paths");
    let home = root.path().join("home");
    fs::create_dir(&home).expect("create home");

    let data_dir = home.join("Library/Application Support/AgentDeck");
    let paths = DaemonPaths::stable(&home, None).expect("stable paths");
    assert_eq!(paths.data_dir, data_dir);
    assert_eq!(paths.runtime_db, data_dir.join("runtime.db"));
    assert_eq!(paths.socket, data_dir.join("agentdeckd.sock"));
    assert_eq!(paths.lock, data_dir.join("agentdeckd.lock"));
    assert_eq!(paths.keychain_service, "com.agentdeck.agentdeckd.stable");
    assert_eq!(paths.keychain_access_group, None);
}

#[test]
fn stable_namespace_preserves_an_expanded_provisioned_access_group() {
    let root = TestRoot::new("stable-group");
    let home = root.path().join("home");
    fs::create_dir(&home).expect("create home");
    let mut startup = options(false, false);
    startup.stable_keychain_access_group =
        Some("A1B2C3D4E5.com.agentdeck.agentdeckd.stable".into());

    let config = DaemonConfig::resolve_with_roots(startup, &home, root.path().join("tmp"))
        .expect("stable config");

    assert_eq!(
        config.paths().keychain_access_group.as_deref(),
        Some("A1B2C3D4E5.com.agentdeck.agentdeckd.stable")
    );
}

#[test]
fn stable_daemon_config_requires_a_compiled_access_group() {
    let root = TestRoot::new("stable-missing-group");
    assert!(matches!(
        DaemonConfig::resolve_with_roots(options(false, false), root.path(), root.path()),
        Err(DaemonConfigError::StableAccessGroupMissing)
    ));
    assert_eq!(
        DaemonConfigError::StableAccessGroupMissing.code(),
        "daemon.keystore.access_group_unconfigured"
    );
}

#[test]
fn ephemeral_namespace_isolates_all_four_filesystem_resources_and_keychain_service() {
    let root = TestRoot::new("ephemeral");
    let home = root.path().join("home");
    let temp = root.path().join("tmp");
    fs::create_dir(&home).expect("create home");
    fs::create_dir(&temp).expect("create temp");

    let first = DaemonConfig::resolve_with_roots(options(true, true), &home, &temp)
        .expect("first ephemeral config");
    let second = DaemonConfig::resolve_with_roots(options(true, true), &home, &temp)
        .expect("second ephemeral config");

    let DaemonMode::Ephemeral { instance_id } = first.mode() else {
        panic!("expected ephemeral mode");
    };
    assert!(!instance_id.is_empty());
    for value in [
        first.paths().data_dir.to_string_lossy().as_ref(),
        first.paths().runtime_db.to_string_lossy().as_ref(),
        first.paths().socket.to_string_lossy().as_ref(),
        first.paths().lock.to_string_lossy().as_ref(),
        first.paths().keychain_service.as_str(),
    ] {
        assert!(
            value.contains(instance_id),
            "resource omitted instance id: {value}"
        );
    }
    assert_eq!(first.paths().keychain_access_group, None);
    assert!(!first.remote_enabled());
    assert_ne!(first.mode(), second.mode());
    assert_ne!(first.paths().data_dir, second.paths().data_dir);
    assert_ne!(first.paths().runtime_db, second.paths().runtime_db);
    assert_ne!(first.paths().socket, second.paths().socket);
    assert_ne!(first.paths().lock, second.paths().lock);
    assert_ne!(
        first.paths().keychain_service,
        second.paths().keychain_service
    );
}

#[test]
fn ephemeral_and_no_remote_must_be_enabled_together() {
    let root = TestRoot::new("matrix");
    let home = root.path().join("home");
    let temp = root.path().join("tmp");

    assert!(DaemonConfig::resolve_with_roots(stable_options(), &home, &temp).is_ok());
    assert!(DaemonConfig::resolve_with_roots(options(true, true), &home, &temp).is_ok());
    assert!(matches!(
        DaemonConfig::resolve_with_roots(options(true, false), &home, &temp),
        Err(DaemonConfigError::EphemeralRequiresNoRemote)
    ));
    assert_eq!(
        DaemonConfigError::EphemeralRequiresNoRemote.code(),
        "daemon.config.ephemeral_requires_no_remote"
    );
    assert!(matches!(
        DaemonConfig::resolve_with_roots(options(false, true), &home, &temp),
        Err(DaemonConfigError::NoRemoteRequiresEphemeral)
    ));
    assert_eq!(
        DaemonConfigError::NoRemoteRequiresEphemeral.code(),
        "daemon.config.no_remote_requires_ephemeral"
    );
}

#[test]
fn production_ephemeral_resolution_uses_a_socket_safe_namespace() {
    let config = DaemonConfig::resolve(options(true, true))
        .expect("production ephemeral namespace must fit sockaddr_un");
    assert!(matches!(config.mode(), DaemonMode::Ephemeral { .. }));
    assert!(!config.remote_enabled());
    assert!(
        config.paths().socket.as_os_str().len()
            <= agentdeckd::runtime::namespace::UNIX_SOCKET_PATH_MAX_BYTES
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn production_stable_resolution_is_typed_unsupported_off_macos() {
    assert!(matches!(
        DaemonConfig::resolve(stable_options()),
        Err(DaemonConfigError::StableUnsupportedPlatform)
    ));
    assert_eq!(
        DaemonConfigError::StableUnsupportedPlatform.code(),
        "daemon.keystore.unsupported_platform"
    );
}

#[test]
fn namespace_rejects_a_socket_path_that_does_not_fit_sockaddr_un() {
    let root = TestRoot::new("socket-length");
    let long_component = "x".repeat(180);
    let temp = root.path().join(long_component);

    assert!(matches!(
        DaemonPaths::ephemeral_with_instance_id(&temp, "instance-1"),
        Err(NamespaceError::SocketPathTooLong { .. })
    ));
}

#[test]
fn namespace_roots_must_be_absolute() {
    assert!(matches!(
        DaemonPaths::stable("relative-home", None),
        Err(NamespaceError::RootNotAbsolute { .. })
    ));
    assert!(matches!(
        DaemonPaths::ephemeral_with_instance_id("relative-temp", "instance"),
        Err(NamespaceError::RootNotAbsolute { .. })
    ));
}

#[test]
fn namespace_rejects_instance_id_traversal_and_ephemeral_access_group() {
    let root = TestRoot::new("invalid-instance");
    assert!(matches!(
        DaemonPaths::ephemeral_with_instance_id(root.path(), "../stable"),
        Err(NamespaceError::InvalidInstanceId)
    ));
    assert_eq!(
        NamespaceError::InvalidInstanceId.code(),
        "daemon.namespace.invalid_instance"
    );

    let startup = DaemonStartupOptions {
        ephemeral: true,
        no_remote: true,
        profile: None,
        stable_keychain_access_group: Some("A1B2C3D4E5.com.agentdeck.agentdeckd.stable".to_owned()),
    };
    assert!(matches!(
        DaemonConfig::resolve_with_roots(startup, root.path(), root.path()),
        Err(DaemonConfigError::StableAccessGroupNotAllowedForEphemeral)
    ));
}

#[test]
fn dev_profile_requires_the_fully_isolated_ephemeral_mode() {
    let root = TestRoot::new("dev-profile");
    let dev_stable = DaemonStartupOptions {
        profile: Some(DaemonProfile::Dev),
        ..options(false, false)
    };
    assert!(matches!(
        DaemonConfig::resolve_with_roots(dev_stable, root.path(), root.path()),
        Err(DaemonConfigError::DevProfileRequiresEphemeral)
    ));

    let dev_ephemeral = DaemonStartupOptions {
        profile: Some(DaemonProfile::Dev),
        ..options(true, true)
    };
    assert!(DaemonConfig::resolve_with_roots(dev_ephemeral, root.path(), root.path()).is_ok());

    let stable_ephemeral = DaemonStartupOptions {
        profile: Some(DaemonProfile::Stable),
        ..options(true, true)
    };
    assert!(matches!(
        DaemonConfig::resolve_with_roots(stable_ephemeral, root.path(), root.path()),
        Err(DaemonConfigError::StableProfileForbidsEphemeral)
    ));
}

#[cfg(unix)]
#[test]
fn singleton_refuses_preexisting_wide_namespace_or_lock_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("wide-permissions");
    let paths =
        DaemonPaths::ephemeral_with_instance_id(root.path(), "wide").expect("ephemeral paths");
    fs::create_dir_all(&paths.data_dir).expect("create namespace");
    fs::set_permissions(&paths.data_dir, fs::Permissions::from_mode(0o755))
        .expect("widen namespace");
    assert!(matches!(
        SingletonGuard::acquire(&paths),
        Err(SingletonError::Namespace(
            NamespaceError::UnsafeDataDirectory { .. }
        ))
    ));

    fs::set_permissions(&paths.data_dir, fs::Permissions::from_mode(0o700))
        .expect("restore namespace mode");
    fs::write(&paths.lock, []).expect("create lock");
    fs::set_permissions(&paths.lock, fs::Permissions::from_mode(0o644)).expect("widen lock");
    assert!(matches!(
        SingletonGuard::acquire(&paths),
        Err(SingletonError::UnsafeLockFile { .. })
    ));
}

#[cfg(unix)]
#[test]
fn stable_namespace_safely_tightens_legacy_permissions_without_losing_data() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("stable-migrate");
    let home = root.path().join("home");
    fs::create_dir_all(home.join("Library/Application Support")).expect("create stable parent");
    let paths = DaemonPaths::stable(&home, None).expect("stable paths");
    fs::create_dir(&paths.data_dir).expect("create legacy stable directory");
    fs::set_permissions(&paths.data_dir, fs::Permissions::from_mode(0o755))
        .expect("set legacy permissions");
    let marker = paths.data_dir.join("diagnostic.log");
    fs::write(&marker, b"legacy-record").expect("write legacy marker");

    let guard = SingletonGuard::acquire(&paths).expect("migrate and lock stable namespace");

    assert_eq!(
        fs::metadata(&paths.data_dir)
            .expect("stable directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::read(&marker).expect("read legacy marker"),
        b"legacy-record"
    );
    drop(guard);
}

#[cfg(unix)]
#[test]
fn stable_namespace_refuses_non_legacy_wide_or_special_permissions() {
    use std::os::unix::fs::PermissionsExt;

    for mode in [0o775, 0o777, 0o1755] {
        let root = TestRoot::new(&format!("sm-{mode:o}"));
        let home = root.path().join("home");
        fs::create_dir_all(home.join("Library/Application Support")).expect("create stable parent");
        let paths = DaemonPaths::stable(&home, None).expect("stable paths");
        fs::create_dir(&paths.data_dir).expect("create unsafe stable directory");
        fs::set_permissions(&paths.data_dir, fs::Permissions::from_mode(mode))
            .expect("set unsafe permissions");

        assert!(matches!(
            SingletonGuard::acquire(&paths),
            Err(SingletonError::Namespace(
                NamespaceError::UnsafeDataDirectory { .. }
            ))
        ));
        assert_eq!(
            fs::metadata(&paths.data_dir)
                .expect("unsafe directory metadata")
                .permissions()
                .mode()
                & 0o7777,
            mode,
            "rejected directory must not be silently chmodded"
        );
    }
}

#[test]
fn concurrent_fresh_namespace_creation_converges_on_one_private_directory() {
    use std::sync::{Arc, Barrier};

    let root = TestRoot::new("concurrent-create");
    let paths = Arc::new(
        DaemonPaths::ephemeral_with_instance_id(root.path(), "concurrent")
            .expect("ephemeral paths"),
    );
    let start = Arc::new(Barrier::new(17));
    let finish = Arc::new(Barrier::new(17));
    let mut workers = Vec::new();
    for _ in 0..16 {
        let paths = Arc::clone(&paths);
        let start = Arc::clone(&start);
        let finish = Arc::clone(&finish);
        workers.push(std::thread::spawn(move || {
            start.wait();
            let result = SingletonGuard::acquire(&paths);
            // 成功者在所有 loser 都完成 nonblocking acquire 前一直持有 guard。
            finish.wait();
            result
        }));
    }
    start.wait();
    finish.wait();
    let mut acquired = 0;
    let mut already_running = 0;
    for worker in workers {
        match worker.join().expect("namespace worker did not panic") {
            Ok(_guard) => acquired += 1,
            Err(SingletonError::AlreadyRunning { .. }) => already_running += 1,
            Err(error) => panic!("unexpected concurrent startup error: {error:?}"),
        }
    }
    assert_eq!(acquired, 1);
    assert_eq!(already_running, 15);
    SingletonGuard::acquire(&paths).expect("lock converged namespace after winner exits");
}

#[cfg(unix)]
#[test]
fn namespace_directory_and_lock_have_private_modes_and_close_on_exec() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = TestRoot::new("lock-mode");
    let paths = DaemonPaths::ephemeral_with_instance_id(root.path(), "mode-check")
        .expect("ephemeral paths");
    let guard = SingletonGuard::acquire(&paths).expect("acquire singleton");

    let data_metadata = fs::symlink_metadata(&paths.data_dir).expect("data dir metadata");
    let lock_metadata = fs::symlink_metadata(&paths.lock).expect("lock metadata");
    // SAFETY: geteuid has no preconditions and only reads process identity.
    let uid = unsafe { libc::geteuid() };
    assert!(data_metadata.file_type().is_dir());
    assert!(!data_metadata.file_type().is_symlink());
    assert_eq!(data_metadata.uid(), uid);
    assert_eq!(data_metadata.permissions().mode() & 0o777, 0o700);
    assert!(lock_metadata.file_type().is_file());
    assert_eq!(lock_metadata.uid(), uid);
    assert_eq!(lock_metadata.permissions().mode() & 0o777, 0o600);

    // SAFETY: fcntl(F_GETFD) only inspects the live fd owned by guard.
    let fd_flags = unsafe { libc::fcntl(guard.as_raw_fd(), libc::F_GETFD) };
    assert!(fd_flags >= 0, "F_GETFD failed");
    assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
}

#[test]
fn singleton_is_nonblocking_and_releases_only_when_guard_drops() {
    let root = TestRoot::new("singleton");
    let paths = DaemonPaths::ephemeral_with_instance_id(root.path(), "same-instance")
        .expect("ephemeral paths");

    let first = SingletonGuard::acquire(&paths).expect("first lock");
    assert!(matches!(
        SingletonGuard::acquire(&paths),
        Err(SingletonError::AlreadyRunning { .. })
    ));
    assert_eq!(
        SingletonError::AlreadyRunning {
            path: paths.lock.clone()
        }
        .code(),
        "daemon.singleton.already_running"
    );
    drop(first);
    let reacquired = SingletonGuard::acquire(&paths).expect("reacquire after drop");
    drop(reacquired);
}

#[cfg(unix)]
#[test]
fn singleton_rejects_symlinks_and_non_regular_lock_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = TestRoot::new("unsafe-lock");
    let symlink_paths = DaemonPaths::ephemeral_with_instance_id(root.path(), "symlink-instance")
        .expect("ephemeral paths");
    fs::create_dir(&symlink_paths.data_dir).expect("prepare namespace");
    fs::set_permissions(&symlink_paths.data_dir, fs::Permissions::from_mode(0o700))
        .expect("set namespace permissions");
    let target = symlink_paths.data_dir.join("target");
    fs::write(&target, b"not a lock").expect("create target");
    symlink(&target, &symlink_paths.lock).expect("create lock symlink");
    assert!(matches!(
        SingletonGuard::acquire(&symlink_paths),
        Err(SingletonError::UnsafeLockFile { .. }) | Err(SingletonError::Io { .. })
    ));

    let directory_paths =
        DaemonPaths::ephemeral_with_instance_id(root.path(), "directory-instance")
            .expect("ephemeral paths");
    fs::create_dir(&directory_paths.data_dir).expect("prepare namespace");
    fs::set_permissions(&directory_paths.data_dir, fs::Permissions::from_mode(0o700))
        .expect("set namespace permissions");
    fs::create_dir_all(&directory_paths.lock).expect("create directory at lock path");
    assert!(matches!(
        SingletonGuard::acquire(&directory_paths),
        Err(SingletonError::UnsafeLockFile { .. }) | Err(SingletonError::Io { .. })
    ));

    let hardlink_paths = DaemonPaths::ephemeral_with_instance_id(root.path(), "hardlink-instance")
        .expect("ephemeral paths");
    fs::create_dir(&hardlink_paths.data_dir).expect("prepare namespace");
    fs::set_permissions(&hardlink_paths.data_dir, fs::Permissions::from_mode(0o700))
        .expect("set namespace permissions");
    let hardlink_target = hardlink_paths.data_dir.join("shared-inode");
    fs::write(&hardlink_target, []).expect("create hardlink target");
    fs::set_permissions(&hardlink_target, fs::Permissions::from_mode(0o600))
        .expect("set hardlink target permissions");
    fs::hard_link(&hardlink_target, &hardlink_paths.lock).expect("create lock hardlink");
    assert!(matches!(
        SingletonGuard::acquire(&hardlink_paths),
        Err(SingletonError::UnsafeLockFile { .. })
    ));
}

#[test]
fn stable_and_ephemeral_namespaces_can_hold_independent_locks() {
    let root = TestRoot::new("coexist");
    let home = root.path().join("home");
    fs::create_dir_all(home.join("Library/Application Support"))
        .expect("create stable namespace parent");
    let stable = DaemonPaths::stable(&home, None).expect("stable paths");
    let ephemeral = DaemonPaths::ephemeral_with_instance_id(root.path(), "dev-instance")
        .expect("ephemeral paths");

    let stable_guard = SingletonGuard::acquire(&stable).expect("stable guard");
    let ephemeral_guard = SingletonGuard::acquire(&ephemeral).expect("ephemeral guard");
    drop((stable_guard, ephemeral_guard));
}
