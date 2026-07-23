#![cfg(unix)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use agentdeck_cli::remote::device_lock::{
    RemoteDeviceLease, RemoteDeviceLockError, RemoteDeviceLockKey,
};
use agentdeck_protocol::relay_v2::MachineRouteId;
use agentdeck_protocol::runtime::MachineRootFingerprint;
use uuid::Uuid;

const HELPER_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_PROCESS_HELPER";
const HELPER_ROOT_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_ROOT";
const HELPER_INSTALLATION_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_INSTALLATION";
const HELPER_FINGERPRINT_BYTE_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_FINGERPRINT_BYTE";
const HELPER_ROUTE_BYTE_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_ROUTE_BYTE";
const HELPER_RESULT_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_RESULT";
const HELPER_AUDIT_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_AUDIT";
const HELPER_HOLD_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_HOLD";
const HELPER_RESTRICTIVE_UMASK_ENV: &str = "AGENTDECK_REMOTE_DEVICE_LOCK_RESTRICTIVE_UMASK";

const PROCESS_DEADLINE: Duration = Duration::from_secs(5);
const HELPER_HOLD_LIMIT: Duration = Duration::from_secs(30);
const ACQUIRED: &str = "acquired";
const ALREADY_IN_USE: &str = "remote.device.already_in_use";

fn key(installation_byte: u8, fingerprint_byte: u8, route_byte: u8) -> RemoteDeviceLockKey {
    RemoteDeviceLockKey::new(
        Uuid::from_bytes([installation_byte; 16]),
        MachineRootFingerprint::from_bytes([fingerprint_byte; 32]),
        MachineRouteId::from_bytes([route_byte; 16]),
    )
}

fn lock_root(temp: &tempfile::TempDir) -> PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical private harness root")
        .join("locks")
}

fn helper_key() -> RemoteDeviceLockKey {
    let installation = env::var(HELPER_INSTALLATION_ENV)
        .expect("helper installation UUID")
        .parse::<Uuid>()
        .expect("canonical helper installation UUID");
    let fingerprint_byte = env::var(HELPER_FINGERPRINT_BYTE_ENV)
        .expect("helper fingerprint byte")
        .parse::<u8>()
        .expect("decimal helper fingerprint byte");
    let route_byte = env::var(HELPER_ROUTE_BYTE_ENV)
        .expect("helper route byte")
        .parse::<u8>()
        .expect("decimal helper route byte");
    RemoteDeviceLockKey::new(
        installation,
        MachineRootFingerprint::from_bytes([fingerprint_byte; 32]),
        MachineRouteId::from_bytes([route_byte; 16]),
    )
}

fn write_helper_result(path: &Path, result: &str) {
    fs::write(path, format!("{result}\n")).expect("publish helper result");
}

fn append_acquisition_audit(path: &Path) {
    let mut audit = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open acquisition audit");
    writeln!(audit, "acquired:{}", std::process::id()).expect("append acquisition audit");
    audit.flush().expect("flush acquisition audit");
}

fn lock_error_code(error: &RemoteDeviceLockError) -> &'static str {
    error.code()
}

/// 只由本 integration-test binary 以 `current_exe() --exact` 启动。
/// acquisition audit 是测试侧成功标记：失败分支绝不追加，用来证明竞争者未进入 active lifecycle。
#[test]
fn remote_device_lock_process_helper() {
    if env::var_os(HELPER_ENV).is_none() {
        return;
    }

    let root = PathBuf::from(env::var_os(HELPER_ROOT_ENV).expect("helper lock root"));
    let result = PathBuf::from(env::var_os(HELPER_RESULT_ENV).expect("helper result path"));
    let audit = PathBuf::from(env::var_os(HELPER_AUDIT_ENV).expect("helper audit path"));
    let hold = env::var_os(HELPER_HOLD_ENV).is_some();

    let previous_umask = env::var_os(HELPER_RESTRICTIVE_UMASK_ENV)
        .is_some()
        // SAFETY: this helper is a dedicated child process and has no sibling test threads.
        .then(|| unsafe { libc::umask(0o777) });
    let acquired = RemoteDeviceLease::acquire_in(&root, helper_key());
    if let Some(previous_umask) = previous_umask {
        // SAFETY: restore the child process umask before publishing the result.
        unsafe { libc::umask(previous_umask) };
    }

    match acquired {
        Ok(_lease) => {
            append_acquisition_audit(&audit);
            write_helper_result(&result, ACQUIRED);
            if hold {
                thread::sleep(HELPER_HOLD_LIMIT);
            }
        }
        Err(error) => write_helper_result(&result, lock_error_code(&error)),
    }
}

struct HelperChild {
    child: Child,
}

impl HelperChild {
    fn spawn(
        root: &Path,
        installation_byte: u8,
        fingerprint_byte: u8,
        route_byte: u8,
        result: &Path,
        audit: &Path,
        hold: bool,
    ) -> Self {
        Self::spawn_config(
            root,
            installation_byte,
            fingerprint_byte,
            route_byte,
            result,
            audit,
            hold,
            false,
        )
    }

    fn spawn_with_restrictive_umask(
        root: &Path,
        installation_byte: u8,
        fingerprint_byte: u8,
        route_byte: u8,
        result: &Path,
        audit: &Path,
    ) -> Self {
        Self::spawn_config(
            root,
            installation_byte,
            fingerprint_byte,
            route_byte,
            result,
            audit,
            false,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_config(
        root: &Path,
        installation_byte: u8,
        fingerprint_byte: u8,
        route_byte: u8,
        result: &Path,
        audit: &Path,
        hold: bool,
        restrictive_umask: bool,
    ) -> Self {
        let installation = Uuid::from_bytes([installation_byte; 16]);
        let mut command =
            Command::new(env::current_exe().expect("current integration-test binary"));
        command
            .arg("--exact")
            .arg("remote_device_lock_process_helper")
            .arg("--nocapture")
            .env(HELPER_ENV, "1")
            .env(HELPER_ROOT_ENV, root)
            .env(
                HELPER_INSTALLATION_ENV,
                installation.hyphenated().to_string(),
            )
            .env(HELPER_FINGERPRINT_BYTE_ENV, fingerprint_byte.to_string())
            .env(HELPER_ROUTE_BYTE_ENV, route_byte.to_string())
            .env(HELPER_RESULT_ENV, result)
            .env(HELPER_AUDIT_ENV, audit)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if hold {
            command.env(HELPER_HOLD_ENV, "1");
        } else {
            command.env_remove(HELPER_HOLD_ENV);
        }
        if restrictive_umask {
            command.env(HELPER_RESTRICTIVE_UMASK_ENV, "1");
        } else {
            command.env_remove(HELPER_RESTRICTIVE_UMASK_ENV);
        }
        Self {
            child: command.spawn().expect("spawn device-lock helper process"),
        }
    }

    fn wait_bounded(&mut self) -> ExitStatus {
        let deadline = Instant::now() + PROCESS_DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll helper process") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "device-lock helper {} did not exit before deadline",
                self.child.id()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_with_sigkill(&mut self) {
        let pid = i32::try_from(self.child.id()).expect("helper PID fits pid_t");
        // SAFETY: pid came from this live Child and SIGKILL has no pointer arguments.
        let status = unsafe { libc::kill(pid, libc::SIGKILL) };
        assert_eq!(status, 0, "send SIGKILL to helper {pid}");
        let exit = self.wait_bounded();
        assert!(!exit.success(), "SIGKILLed helper unexpectedly succeeded");
    }
}

impl Drop for HelperChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait_for_result(path: &Path) -> String {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        match fs::read_to_string(path) {
            Ok(value) if !value.trim().is_empty() => return value.trim().to_owned(),
            Ok(_) | Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(_) => panic!("empty helper result at {}", path.display()),
            Err(error) => panic!(
                "helper result {} was not published before deadline: {error}",
                path.display()
            ),
        }
    }
}

fn acquisition_count(path: &Path) -> usize {
    fs::read_to_string(path).unwrap_or_default().lines().count()
}

#[test]
fn same_device_is_exclusive_across_processes_and_sigkill_releases_the_lease() {
    let temp = tempfile::tempdir().expect("private device-lock harness");
    let lock_root = lock_root(&temp);
    let audit = temp.path().join("acquisitions.log");
    let holder_result = temp.path().join("holder.result");
    let contender_result = temp.path().join("contender.result");
    let recovery_result = temp.path().join("recovery.result");

    let mut holder = HelperChild::spawn(&lock_root, 0x11, 0x22, 0x33, &holder_result, &audit, true);
    assert_eq!(wait_for_result(&holder_result), ACQUIRED);
    assert_eq!(acquisition_count(&audit), 1);

    let mut contender = HelperChild::spawn(
        &lock_root,
        0x11,
        0x22,
        0x33,
        &contender_result,
        &audit,
        false,
    );
    assert_eq!(wait_for_result(&contender_result), ALREADY_IN_USE);
    assert!(contender.wait_bounded().success());
    assert_eq!(
        acquisition_count(&audit),
        1,
        "rejected contender must not append acquisition audit"
    );

    holder.kill_with_sigkill();

    let mut recovery = HelperChild::spawn(
        &lock_root,
        0x11,
        0x22,
        0x33,
        &recovery_result,
        &audit,
        false,
    );
    assert_eq!(wait_for_result(&recovery_result), ACQUIRED);
    assert!(recovery.wait_bounded().success());
    assert_eq!(acquisition_count(&audit), 2);
}

#[test]
fn every_identity_axis_selects_an_independent_cross_process_lease() {
    let temp = tempfile::tempdir().expect("private device-lock harness");
    let lock_root = lock_root(&temp);
    let audit = temp.path().join("acquisitions.log");
    let first_result = temp.path().join("first.result");
    let other_fingerprint_result = temp.path().join("other-fingerprint.result");
    let other_route_result = temp.path().join("other-route.result");
    let other_installation_result = temp.path().join("other-installation.result");

    let mut first = HelperChild::spawn(&lock_root, 0x11, 0x22, 0x33, &first_result, &audit, true);
    assert_eq!(wait_for_result(&first_result), ACQUIRED);

    let mut other_fingerprint = HelperChild::spawn(
        &lock_root,
        0x11,
        0x44,
        0x33,
        &other_fingerprint_result,
        &audit,
        true,
    );
    let mut other_route = HelperChild::spawn(
        &lock_root,
        0x11,
        0x22,
        0x55,
        &other_route_result,
        &audit,
        true,
    );
    let mut other_installation = HelperChild::spawn(
        &lock_root,
        0x66,
        0x22,
        0x33,
        &other_installation_result,
        &audit,
        true,
    );

    assert_eq!(wait_for_result(&other_fingerprint_result), ACQUIRED);
    assert_eq!(wait_for_result(&other_route_result), ACQUIRED);
    assert_eq!(wait_for_result(&other_installation_result), ACQUIRED);
    assert_eq!(acquisition_count(&audit), 4);

    first.kill_with_sigkill();
    other_fingerprint.kill_with_sigkill();
    other_route.kill_with_sigkill();
    other_installation.kill_with_sigkill();
}

fn collect_lock_tree(path: &Path, directories: &mut Vec<PathBuf>, files: &mut Vec<PathBuf>) {
    let metadata = fs::symlink_metadata(path).expect("inspect lock tree entry");
    assert!(
        !metadata.file_type().is_symlink(),
        "lock tree contains symlink"
    );
    if metadata.is_dir() {
        directories.push(path.to_path_buf());
        for entry in fs::read_dir(path).expect("read lock tree") {
            collect_lock_tree(
                &entry.expect("read lock tree entry").path(),
                directories,
                files,
            );
        }
    } else {
        assert!(metadata.is_file(), "lock entry must be a regular file");
        files.push(path.to_path_buf());
    }
}

fn one_lock_file(lock_root: &Path) -> PathBuf {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    collect_lock_tree(lock_root, &mut directories, &mut files);
    assert_eq!(files.len(), 1, "one device key must map to one lock file");
    for directory in directories {
        let mode = fs::symlink_metadata(&directory)
            .expect("lock directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o700,
            "private lock directory {}",
            directory.display()
        );
    }
    files.pop().expect("single lock file")
}

fn assert_security_failure(error: RemoteDeviceLockError) {
    let code = lock_error_code(&error);
    assert!(
        code.starts_with("remote.device.") && code != ALREADY_IN_USE,
        "unsafe filesystem entry must return a typed security error, got {code}"
    );
}

fn expect_security_failure(
    result: Result<RemoteDeviceLease, RemoteDeviceLockError>,
    context: &str,
) -> RemoteDeviceLockError {
    match result {
        Ok(_lease) => panic!("{context}"),
        Err(error) => error,
    }
}

#[test]
fn lock_storage_is_exact_0700_parent_and_0600_regular_file() {
    let temp = tempfile::tempdir().expect("private device-lock harness");
    let lock_root = lock_root(&temp);
    let lease = RemoteDeviceLease::acquire_in(&lock_root, key(0x11, 0x22, 0x33))
        .expect("acquire first device lease");

    let lock_file = one_lock_file(&lock_root);
    let metadata = fs::symlink_metadata(&lock_file).expect("lock file metadata");
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    // SAFETY: F_GETFD only reads flags from the live lease fd.
    let flags = unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0, "read device lease fd flags");
    assert_ne!(flags & libc::FD_CLOEXEC, 0, "lease must close on exec");
}

#[test]
fn restrictive_umask_still_creates_exact_private_entries_in_a_child_process() {
    let temp = tempfile::tempdir().expect("private device-lock harness");
    let lock_root = lock_root(&temp);
    let result = temp.path().join("restrictive-umask.result");
    let audit = temp.path().join("restrictive-umask.audit");
    let mut child =
        HelperChild::spawn_with_restrictive_umask(&lock_root, 0x11, 0x22, 0x33, &result, &audit);
    assert_eq!(wait_for_result(&result), ACQUIRED);
    assert!(child.wait_bounded().success());
    assert_eq!(acquisition_count(&audit), 1);
    let lock_file = one_lock_file(&lock_root);
    assert_eq!(
        fs::symlink_metadata(lock_file)
            .expect("restrictive-umask lock metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn symlinked_lock_root_ancestor_fails_before_creating_in_the_target() {
    let temp = tempfile::tempdir().expect("private device-lock harness");
    let base = fs::canonicalize(temp.path()).expect("canonical harness root");
    let target_parent = base.join("target-parent");
    fs::create_dir(&target_parent).expect("create target parent");
    fs::set_permissions(&target_parent, fs::Permissions::from_mode(0o700))
        .expect("secure target parent");
    let alias = base.join("ancestor-alias");
    symlink(&target_parent, &alias).expect("create ancestor symlink");
    let redirected_root = alias.join("locks");

    let error = expect_security_failure(
        RemoteDeviceLease::acquire_in(&redirected_root, key(0x11, 0x22, 0x33)),
        "symlinked ancestor must fail closed",
    );
    assert_security_failure(error);
    assert!(
        !target_parent.join("locks").exists(),
        "rejected ancestor symlink must not create a redirected tree"
    );
}

#[test]
fn symlink_lock_file_fails_closed_without_touching_its_target() {
    let temp = tempfile::tempdir().expect("private device-lock harness");
    let lock_root = lock_root(&temp);
    let lease = RemoteDeviceLease::acquire_in(&lock_root, key(0x11, 0x22, 0x33))
        .expect("seed safe lock file");
    let lock_file = one_lock_file(&lock_root);
    drop(lease);

    let target = temp.path().join("symlink-target");
    fs::write(&target, b"must-not-change").expect("seed symlink target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("secure symlink target");
    fs::remove_file(&lock_file).expect("replace lock file with symlink");
    symlink(&target, &lock_file).expect("create hostile lock symlink");

    let error = expect_security_failure(
        RemoteDeviceLease::acquire_in(&lock_root, key(0x11, 0x22, 0x33)),
        "symlink lock file must fail closed",
    );
    assert_security_failure(error);
    assert!(
        fs::symlink_metadata(&lock_file)
            .expect("symlink remains present")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(&target).expect("read untouched target"),
        b"must-not-change"
    );
}

#[test]
fn hardlinked_lock_file_fails_closed_without_unlinking_either_name() {
    let temp = tempfile::tempdir().expect("private device-lock harness");
    let lock_root = lock_root(&temp);
    let lease = RemoteDeviceLease::acquire_in(&lock_root, key(0x11, 0x22, 0x33))
        .expect("seed safe lock file");
    let lock_file = one_lock_file(&lock_root);
    drop(lease);

    let alias = temp.path().join("hostile-hardlink");
    fs::hard_link(&lock_file, &alias).expect("create hostile lock hardlink");
    let error = RemoteDeviceLease::acquire_in(&lock_root, key(0x11, 0x22, 0x33))
        .expect_err("hardlinked lock file must fail closed");
    assert_security_failure(error);
    assert_eq!(
        fs::symlink_metadata(&lock_file)
            .expect("lock metadata")
            .nlink(),
        2
    );
    assert_eq!(
        fs::symlink_metadata(&alias)
            .expect("hardlink alias metadata")
            .nlink(),
        2
    );
}

#[test]
fn broad_parent_or_lock_file_permissions_fail_closed_without_repair() {
    let temp = tempfile::tempdir().expect("private device-lock harness");
    let lock_root = lock_root(&temp);
    let lease = RemoteDeviceLease::acquire_in(&lock_root, key(0x11, 0x22, 0x33))
        .expect("seed safe lock file");
    let lock_file = one_lock_file(&lock_root);
    drop(lease);
    let original = fs::read(&lock_file).expect("read original lock file");

    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o755))
        .expect("widen lock parent permissions");
    let error = expect_security_failure(
        RemoteDeviceLease::acquire_in(&lock_root, key(0x11, 0x22, 0x33)),
        "broad lock parent must fail closed",
    );
    assert_security_failure(error);
    assert_eq!(
        fs::symlink_metadata(&lock_root)
            .expect("broad parent remains")
            .permissions()
            .mode()
            & 0o777,
        0o755,
        "fail-close must not silently repair an unsafe parent"
    );
    assert_eq!(
        fs::read(&lock_file).expect("read unchanged lock file"),
        original
    );

    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700))
        .expect("restore parent to isolate file-mode check");
    fs::set_permissions(&lock_file, fs::Permissions::from_mode(0o644))
        .expect("widen lock file permissions");
    let error = expect_security_failure(
        RemoteDeviceLease::acquire_in(&lock_root, key(0x11, 0x22, 0x33)),
        "broad lock file must fail closed",
    );
    assert_security_failure(error);
    assert_eq!(
        fs::symlink_metadata(&lock_file)
            .expect("broad lock file remains")
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "fail-close must not silently repair an unsafe lock file"
    );
    assert_eq!(
        fs::read(&lock_file).expect("read unchanged lock file"),
        original
    );
}
