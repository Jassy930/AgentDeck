#![cfg(unix)]

use std::env;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};

use agentdeck_cli::remote::crypto_state::{
    CRYPTO_STATE_V1_HEADER_LEN, CRYPTO_STATE_V1_OVERHEAD_LEN, CryptoStateCommit, CryptoStateError,
    CryptoStateIdentity, CryptoStateReplaceObserver, CryptoStateReplaceStage, CryptoStateSnapshot,
    DeviceStorageKek, FileCryptoStateStore, InitialCryptoStateCommitObserver,
    MAX_CRYPTO_STATE_PLAINTEXT_LEN,
};
use agentdeck_protocol::relay_v2::MachineRouteId;
use agentdeck_protocol::runtime::MachineRootFingerprint;
use uuid::Uuid;

const HEADER_MAGIC: &[u8; 4] = b"ADCS";
const FORMAT_VERSION: u8 = 1;
const ALGORITHM_CHACHA20_POLY1305: u8 = 1;
const AUTHENTICATION_TAG_LEN: usize = 16;
const REPLACE_CRASH_CHILD_ENV: &str = "AGENTDECK_CRYPTO_STATE_REPLACE_CRASH_CHILD";
const REPLACE_CRASH_ROOT_ENV: &str = "AGENTDECK_CRYPTO_STATE_REPLACE_CRASH_ROOT";
const REPLACE_CRASH_STAGE_ENV: &str = "AGENTDECK_CRYPTO_STATE_REPLACE_CRASH_STAGE";
const REPLACE_CRASH_EXIT_CODE: i32 = 91;

fn identity(
    installation_byte: u8,
    root_fingerprint_byte: u8,
    machine_route_byte: u8,
) -> CryptoStateIdentity {
    CryptoStateIdentity::new(
        Uuid::from_bytes([installation_byte; 16]),
        MachineRootFingerprint::from_bytes([root_fingerprint_byte; 32]),
        MachineRouteId::from_bytes([machine_route_byte; 16]),
    )
}

fn storage_kek(byte: u8) -> DeviceStorageKek {
    DeviceStorageKek::new([byte; 32])
}

fn snapshot(bytes: &[u8]) -> CryptoStateSnapshot {
    CryptoStateSnapshot::new(bytes.to_vec())
}

fn private_root(temp: &tempfile::TempDir, label: &str) -> PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical private crypto-state harness")
        .join(label)
}

fn open_store(
    root: &Path,
    state_identity: CryptoStateIdentity,
    kek: DeviceStorageKek,
) -> FileCryptoStateStore {
    match FileCryptoStateStore::new_in(root, state_identity, kek) {
        Ok(store) => store,
        Err(error) => panic!("open injected crypto-state store: {error}"),
    }
}

fn expect_store_error<T>(result: Result<T, CryptoStateError>, context: &str) -> CryptoStateError {
    match result {
        Ok(_) => panic!("{context}"),
        Err(error) => error,
    }
}

fn assert_crypto_failure(error: &CryptoStateError) {
    assert!(
        error.code().starts_with("remote.crypto_state."),
        "crypto-state failures must stay typed: {error}"
    );
}

#[derive(Debug, Eq, PartialEq)]
struct SmallFileEvidence {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
}

fn small_file_evidence(path: &Path) -> SmallFileEvidence {
    let metadata = fs::symlink_metadata(path).expect("crypto-state file metadata");
    SmallFileEvidence {
        bytes: fs::read(path).expect("read bounded crypto-state fixture"),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        links: metadata.nlink(),
    }
}

fn assert_failed_load_preserves_exact_file(
    store: &FileCryptoStateStore,
    path: &Path,
) -> CryptoStateError {
    let before = small_file_evidence(path);
    let error = expect_store_error(store.load(), "invalid sealed state must fail closed");
    assert_crypto_failure(&error);
    assert_eq!(
        small_file_evidence(path),
        before,
        "load failure must not rewrite, repair, replace, or unlink the state file"
    );
    error
}

fn collect_tree(path: &Path, directories: &mut Vec<PathBuf>, files: &mut Vec<PathBuf>) {
    let metadata = fs::symlink_metadata(path).expect("inspect crypto-state tree entry");
    assert!(
        !metadata.file_type().is_symlink(),
        "committed crypto-state tree must not contain symlinks"
    );
    if metadata.is_dir() {
        directories.push(path.to_path_buf());
        for entry in fs::read_dir(path).expect("read crypto-state tree") {
            collect_tree(
                &entry.expect("read crypto-state tree entry").path(),
                directories,
                files,
            );
        }
    } else {
        assert!(metadata.is_file(), "state entry must be a regular file");
        files.push(path.to_path_buf());
    }
}

fn assert_one_private_state_file(root: &Path, expected_file: &Path) {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    collect_tree(root, &mut directories, &mut files);

    assert_eq!(files, [expected_file.to_path_buf()]);
    let current_uid = unsafe { libc::geteuid() };
    for directory in directories {
        let metadata = fs::symlink_metadata(&directory).expect("state directory metadata");
        assert_eq!(
            metadata.permissions().mode() & 0o7777,
            0o700,
            "private crypto-state directory {}",
            directory.display()
        );
        assert_eq!(metadata.uid(), current_uid, "state directory owner");
    }

    let metadata = fs::symlink_metadata(expected_file).expect("state file metadata");
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), current_uid);
    assert_eq!(metadata.nlink(), 1);
}

#[derive(Debug, Eq, PartialEq)]
struct TreeEntryEvidence {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
}

fn exact_tree_evidence(root: &Path) -> Vec<TreeEntryEvidence> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    collect_tree(root, &mut directories, &mut files);
    directories.sort();
    files.sort();

    directories
        .into_iter()
        .map(|path| {
            let metadata = fs::symlink_metadata(&path).expect("tree directory metadata");
            TreeEntryEvidence {
                path,
                bytes: None,
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                links: metadata.nlink(),
            }
        })
        .chain(files.into_iter().map(|path| {
            let metadata = fs::symlink_metadata(&path).expect("tree file metadata");
            let bytes = fs::read(&path).expect("read bounded tree file");
            TreeEntryEvidence {
                path,
                bytes: Some(bytes),
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                links: metadata.nlink(),
            }
        }))
        .collect()
}

struct DeterministicCommitBarrier(Barrier);

impl InitialCryptoStateCommitObserver for DeterministicCommitBarrier {
    fn after_preflight_absent(&self) {
        self.0.wait();
    }
}

fn open_store_with_commit_barrier(
    root: &Path,
    state_identity: CryptoStateIdentity,
    kek: DeviceStorageKek,
    barrier: Arc<DeterministicCommitBarrier>,
) -> FileCryptoStateStore {
    FileCryptoStateStore::new_in_with_initial_commit_observer(root, state_identity, kek, barrier)
        .expect("open crypto-state store with deterministic commit barrier")
}

struct ExitAtReplaceStage(CryptoStateReplaceStage);

impl CryptoStateReplaceObserver for ExitAtReplaceStage {
    fn after_stage(&self, stage: CryptoStateReplaceStage) {
        if stage == self.0 {
            std::process::exit(REPLACE_CRASH_EXIT_CODE);
        }
    }
}

fn replace_stage_name(stage: CryptoStateReplaceStage) -> &'static str {
    match stage {
        CryptoStateReplaceStage::TempCreated => "temp-created",
        CryptoStateReplaceStage::TempWritten => "temp-written",
        CryptoStateReplaceStage::BackupExcluded => "backup-excluded",
        CryptoStateReplaceStage::FileSynced => "file-synced",
        CryptoStateReplaceStage::Renamed => "renamed",
        CryptoStateReplaceStage::ParentSynced => "parent-synced",
    }
}

fn parse_replace_stage(value: &str) -> CryptoStateReplaceStage {
    match value {
        "temp-created" => CryptoStateReplaceStage::TempCreated,
        "temp-written" => CryptoStateReplaceStage::TempWritten,
        "backup-excluded" => CryptoStateReplaceStage::BackupExcluded,
        "file-synced" => CryptoStateReplaceStage::FileSynced,
        "renamed" => CryptoStateReplaceStage::Renamed,
        "parent-synced" => CryptoStateReplaceStage::ParentSynced,
        _ => panic!("unknown replace crash stage: {value}"),
    }
}

#[test]
fn sealed_file_has_fixed_chacha20poly1305_header_private_storage_and_backup_exclusion() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let root = private_root(&temp, "state-a");
    let state = snapshot(b"opaque key-directory, cursors, counters, and replay state");
    let store = open_store(&root, identity(0x11, 0x22, 0x33), storage_kek(0x44));

    assert_eq!(
        store
            .commit_initial(&state)
            .expect("commit first sealed crypto state"),
        CryptoStateCommit::Created
    );
    let path = store.state_path().to_path_buf();
    let sealed = fs::read(&path).expect("read sealed crypto-state file");

    assert_eq!(CRYPTO_STATE_V1_HEADER_LEN, 24);
    assert_eq!(
        CRYPTO_STATE_V1_OVERHEAD_LEN,
        CRYPTO_STATE_V1_HEADER_LEN + AUTHENTICATION_TAG_LEN
    );
    assert_eq!(
        sealed.len(),
        CRYPTO_STATE_V1_OVERHEAD_LEN + state.expose_secret().len()
    );
    assert_eq!(&sealed[..4], HEADER_MAGIC);
    assert_eq!(sealed[4], FORMAT_VERSION);
    assert_eq!(sealed[5], ALGORITHM_CHACHA20_POLY1305);
    assert_eq!(&sealed[6..8], &[0, 0]);
    assert_eq!(
        &sealed[8..12],
        &u32::try_from(state.expose_secret().len())
            .expect("bounded snapshot length fits u32")
            .to_be_bytes()
    );
    assert!(
        !sealed
            .windows(state.expose_secret().len())
            .any(|window| window == state.expose_secret()),
        "opaque snapshot bytes must never be persisted in plaintext"
    );
    assert_one_private_state_file(&root, &path);
    assert!(
        store.backup_excluded().expect("read back backup exclusion"),
        "committed crypto state must be excluded from backup"
    );

    let loaded = store
        .load()
        .expect("load committed crypto state")
        .expect("committed state is present");
    assert_eq!(loaded.expose_secret(), state.expose_secret());

    let reopened = open_store(&root, identity(0x11, 0x22, 0x33), storage_kek(0x44));
    assert!(
        reopened
            .backup_excluded()
            .expect("read back backup exclusion after reopening")
    );
    assert_eq!(
        reopened
            .load()
            .expect("load after reopening")
            .expect("state survives reopening")
            .expose_secret(),
        state.expose_secret()
    );

    let second_root = private_root(&temp, "state-b");
    let second = open_store(&second_root, identity(0x11, 0x22, 0x33), storage_kek(0x44));
    second
        .commit_initial(&snapshot(state.expose_secret()))
        .expect("seal same snapshot in an independent store");
    let second_sealed = fs::read(second.state_path()).expect("read second sealed state");
    assert_ne!(
        &sealed[12..24],
        &second_sealed[12..24],
        "each new file must use a fresh 96-bit nonce"
    );

    assert!(format!("{:?}", storage_kek(0xa5)).contains("REDACTED"));
    assert!(format!("{state:?}").contains("REDACTED"));
}

#[test]
fn device_storage_kek_and_every_identity_axis_are_authenticated() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let source_root = private_root(&temp, "source");
    let source = open_store(&source_root, identity(0x10, 0x20, 0x30), storage_kek(0x40));
    source
        .commit_initial(&snapshot(b"identity-bound opaque state"))
        .expect("commit source state");
    let source_bytes = fs::read(source.state_path()).expect("read source sealed state");

    let wrong_kek = open_store(&source_root, identity(0x10, 0x20, 0x30), storage_kek(0x41));
    assert_failed_load_preserves_exact_file(&wrong_kek, source.state_path());

    for (label, relocated_identity) in [
        ("other-installation", identity(0x11, 0x20, 0x30)),
        ("other-root", identity(0x10, 0x21, 0x30)),
        ("other-route", identity(0x10, 0x20, 0x31)),
    ] {
        let destination_root = private_root(&temp, label);
        let destination = open_store(&destination_root, relocated_identity, storage_kek(0x40));
        destination
            .commit_initial(&snapshot(b"destination placeholder"))
            .expect("create safe relocation destination");
        fs::write(destination.state_path(), &source_bytes)
            .expect("relocate source bytes into another identity path");

        assert_failed_load_preserves_exact_file(&destination, destination.state_path());
    }
}

#[test]
fn malformed_exact_total_header_ciphertext_and_tag_fail_closed_without_rewrite() {
    type Mutation = fn(&mut Vec<u8>);
    let mutations: [(&str, Mutation); 9] = [
        ("magic", |bytes| bytes[0] ^= 1),
        ("version", |bytes| bytes[4] = FORMAT_VERSION + 1),
        ("algorithm", |bytes| {
            bytes[5] = ALGORITHM_CHACHA20_POLY1305 + 1
        }),
        ("reserved", |bytes| bytes[6] = 1),
        ("plaintext-length", |bytes| bytes[11] ^= 1),
        ("nonce", |bytes| bytes[12] ^= 1),
        ("ciphertext", |bytes| bytes[CRYPTO_STATE_V1_HEADER_LEN] ^= 1),
        ("tag", |bytes| *bytes.last_mut().expect("tag byte") ^= 1),
        ("trailing", |bytes| bytes.push(0)),
    ];

    for (index, (label, mutate)) in mutations.into_iter().enumerate() {
        let temp = tempfile::tempdir().expect("private crypto-state harness");
        let root = private_root(&temp, label);
        let store = open_store(
            &root,
            identity(
                0x31,
                0x32,
                u8::try_from(index).expect("small mutation index"),
            ),
            storage_kek(0x33),
        );
        store
            .commit_initial(&snapshot(b"nonempty opaque state"))
            .expect("seed sealed state");

        let mut malformed = fs::read(store.state_path()).expect("read sealed fixture");
        mutate(&mut malformed);
        fs::write(store.state_path(), &malformed).expect("write malformed fixture");
        assert_failed_load_preserves_exact_file(&store, store.state_path());
    }

    for remove_count in [1, AUTHENTICATION_TAG_LEN, CRYPTO_STATE_V1_OVERHEAD_LEN] {
        let temp = tempfile::tempdir().expect("private crypto-state harness");
        let root = private_root(&temp, &format!("truncated-{remove_count}"));
        let store = open_store(
            &root,
            identity(
                0x41,
                0x42,
                u8::try_from(remove_count).expect("small truncate count"),
            ),
            storage_kek(0x43),
        );
        store
            .commit_initial(&snapshot(b"strict exact total length"))
            .expect("seed sealed state");
        let mut truncated = fs::read(store.state_path()).expect("read sealed fixture");
        truncated.truncate(truncated.len() - remove_count);
        fs::write(store.state_path(), &truncated).expect("write truncated fixture");
        assert_failed_load_preserves_exact_file(&store, store.state_path());
    }
}

#[test]
fn sparse_file_over_plaintext_cap_is_rejected_before_unbounded_state_is_accepted() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let root = private_root(&temp, "oversized");
    let store = open_store(&root, identity(0x51, 0x52, 0x53), storage_kek(0x54));
    store
        .commit_initial(&snapshot(b"bounded seed"))
        .expect("seed state path");

    assert_eq!(MAX_CRYPTO_STATE_PLAINTEXT_LEN, 128 * 1024 * 1024);
    let oversized_total =
        u64::try_from(MAX_CRYPTO_STATE_PLAINTEXT_LEN + CRYPTO_STATE_V1_OVERHEAD_LEN + 1)
            .expect("crypto-state bound fits u64");
    OpenOptions::new()
        .write(true)
        .open(store.state_path())
        .expect("open state fixture without following an attacker-controlled path")
        .set_len(oversized_total)
        .expect("create sparse oversized state fixture");
    let before = fs::symlink_metadata(store.state_path()).expect("oversized fixture metadata");

    let error = expect_store_error(
        store.load(),
        "file above the pre-allocation cap must fail closed",
    );
    assert_crypto_failure(&error);
    assert_eq!(error.code(), "remote.crypto_state.input_too_large");

    let after = fs::symlink_metadata(store.state_path()).expect("oversized fixture remains");
    assert_eq!(after.len(), oversized_total);
    assert_eq!(after.dev(), before.dev());
    assert_eq!(after.ino(), before.ino());
    assert_eq!(after.mode(), before.mode());
    assert_eq!(after.nlink(), before.nlink());
}

#[test]
fn commit_initial_is_create_only_with_plaintext_exact_retry_and_conflict() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let root = private_root(&temp, "immutable");
    let store = open_store(&root, identity(0x61, 0x62, 0x63), storage_kek(0x64));
    let original = snapshot(b"first opaque snapshot");

    assert_eq!(
        store
            .commit_initial(&original)
            .expect("commit first snapshot"),
        CryptoStateCommit::Created
    );
    let first_file = small_file_evidence(store.state_path());

    assert_eq!(
        store
            .commit_initial(&snapshot(b"first opaque snapshot"))
            .expect("retry exact plaintext snapshot"),
        CryptoStateCommit::AlreadyPresent
    );
    assert_eq!(
        small_file_evidence(store.state_path()),
        first_file,
        "same-plaintext retry must retain the originally sealed file and nonce"
    );

    let conflict = expect_store_error(
        store.commit_initial(&snapshot(b"different opaque snapshot")),
        "different initial plaintext must conflict",
    );
    assert_eq!(conflict.code(), "remote.crypto_state.immutable_conflict");
    assert_eq!(small_file_evidence(store.state_path()), first_file);
    assert_eq!(
        store
            .load()
            .expect("load after conflict")
            .expect("original state remains")
            .expose_secret(),
        original.expose_secret()
    );
}

#[test]
fn concurrent_initial_commits_have_one_no_replace_winner_and_no_temp_artifacts() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let root = private_root(&temp, "concurrent");
    let commit_barrier = Arc::new(DeterministicCommitBarrier(Barrier::new(2)));
    let first = Arc::new(open_store_with_commit_barrier(
        &root,
        identity(0x71, 0x72, 0x73),
        storage_kek(0x74),
        Arc::clone(&commit_barrier),
    ));
    let second = Arc::new(open_store_with_commit_barrier(
        &root,
        identity(0x71, 0x72, 0x73),
        storage_kek(0x74),
        commit_barrier,
    ));

    let workers = [(first, 0x81_u8), (second, 0x82_u8)]
        .into_iter()
        .map(|(store, byte)| {
            std::thread::spawn(move || {
                (
                    byte,
                    store.commit_initial(&CryptoStateSnapshot::new(vec![byte; 32])),
                )
            })
        })
        .collect::<Vec<_>>();

    let results = workers
        .into_iter()
        .map(|worker| {
            worker
                .join()
                .expect("crypto-state commit worker did not panic")
        })
        .collect::<Vec<_>>();
    let winner = results
        .iter()
        .find_map(|(byte, result)| {
            matches!(result, Ok(CryptoStateCommit::Created)).then_some(*byte)
        })
        .expect("one initial commit wins");
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(result, Ok(CryptoStateCommit::Created)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| {
                matches!(
                    result,
                    Err(error) if error.code() == "remote.crypto_state.immutable_conflict"
                )
            })
            .count(),
        1
    );

    let reopened = open_store(&root, identity(0x71, 0x72, 0x73), storage_kek(0x74));
    assert_eq!(
        reopened
            .load()
            .expect("load concurrent winner")
            .expect("winner is durable")
            .expose_secret(),
        &[winner; 32]
    );
    assert_one_private_state_file(&root, reopened.state_path());
    assert!(
        reopened
            .backup_excluded()
            .expect("winner backup exclusion readback")
    );

    let same_root = private_root(&temp, "concurrent-same");
    let same_barrier = Arc::new(DeterministicCommitBarrier(Barrier::new(2)));
    let same_stores = [
        Arc::new(open_store_with_commit_barrier(
            &same_root,
            identity(0x75, 0x76, 0x77),
            storage_kek(0x78),
            Arc::clone(&same_barrier),
        )),
        Arc::new(open_store_with_commit_barrier(
            &same_root,
            identity(0x75, 0x76, 0x77),
            storage_kek(0x78),
            same_barrier,
        )),
    ];
    let same_results = same_stores
        .into_iter()
        .map(|store| {
            std::thread::spawn(move || {
                store.commit_initial(&CryptoStateSnapshot::new(vec![0x83; 32]))
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|worker| worker.join().expect("same-state worker did not panic"))
        .collect::<Vec<_>>();
    assert_eq!(
        same_results
            .iter()
            .filter(|result| matches!(result, Ok(CryptoStateCommit::Created)))
            .count(),
        1
    );
    assert_eq!(
        same_results
            .iter()
            .filter(|result| matches!(result, Ok(CryptoStateCommit::AlreadyPresent)))
            .count(),
        1
    );
    let same_reopened = open_store(&same_root, identity(0x75, 0x76, 0x77), storage_kek(0x78));
    assert_eq!(
        same_reopened
            .load()
            .expect("load same-state winner")
            .expect("same-state winner is durable")
            .expose_secret(),
        &[0x83; 32]
    );
    assert_one_private_state_file(&same_root, same_reopened.state_path());
}

#[test]
fn symlink_and_hardlink_entries_fail_closed_without_touching_targets_or_links() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let root = private_root(&temp, "entry-attacks");
    let store = open_store(&root, identity(0x91, 0x92, 0x93), storage_kek(0x94));
    store
        .commit_initial(&snapshot(b"safe initial state"))
        .expect("seed safe state file");
    let state_path = store.state_path().to_path_buf();

    // 对一份本来可以成功认证的 sealed file 增加第二个链接；若实现漏掉
    // nlink=1 检查，下面的 load 会成功，不能被 encoding/tag 失败误掩盖。
    let hardlink_alias = temp.path().join("hostile-hardlink");
    fs::hard_link(&state_path, &hardlink_alias).expect("create hostile state hardlink");
    let before = small_file_evidence(&state_path);
    let error = expect_store_error(store.load(), "hardlinked state must fail closed");
    assert_crypto_failure(&error);
    assert_eq!(small_file_evidence(&state_path), before);
    assert_eq!(fs::symlink_metadata(&hardlink_alias).unwrap().nlink(), 2);
    assert_eq!(fs::symlink_metadata(&state_path).unwrap().nlink(), 2);
    fs::remove_file(&hardlink_alias).expect("remove hardlink alias fixture");

    let target = temp.path().join("symlink-target");
    fs::write(&target, b"must remain untouched").expect("seed symlink target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .expect("private symlink target");
    fs::remove_file(&state_path).expect("replace state file with hostile symlink");
    symlink(&target, &state_path).expect("create hostile state symlink");

    let error = expect_store_error(store.load(), "state symlink must fail closed");
    assert_crypto_failure(&error);
    assert!(
        fs::symlink_metadata(&state_path)
            .expect("state symlink remains")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(&target).expect("read untouched symlink target"),
        b"must remain untouched"
    );
}

#[test]
fn symlinked_ancestor_and_broad_permissions_fail_closed_without_repair() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let base = fs::canonicalize(temp.path()).expect("canonical harness root");
    let target_parent = base.join("redirect-target");
    fs::create_dir(&target_parent).expect("create redirect target");
    fs::set_permissions(&target_parent, fs::Permissions::from_mode(0o700))
        .expect("private redirect target");
    let alias = base.join("redirect-alias");
    symlink(&target_parent, &alias).expect("create ancestor symlink");
    let redirected_root = alias.join("crypto-state");

    let ancestor_error = match FileCryptoStateStore::new_in(
        &redirected_root,
        identity(0xa1, 0xa2, 0xa3),
        storage_kek(0xa4),
    ) {
        Err(error) => error,
        Ok(store) => expect_store_error(
            store.commit_initial(&snapshot(b"must not reach symlink target")),
            "symlinked ancestor must fail before commit",
        ),
    };
    assert_crypto_failure(&ancestor_error);
    assert!(
        !target_parent.join("crypto-state").exists(),
        "rejected ancestor symlink must not create redirected state"
    );

    let root = base.join("broad-permissions");
    let store = open_store(&root, identity(0xb1, 0xb2, 0xb3), storage_kek(0xb4));
    store
        .commit_initial(&snapshot(b"permissions must not be repaired"))
        .expect("seed safe state");
    let original = small_file_evidence(store.state_path());

    fs::set_permissions(store.state_path(), fs::Permissions::from_mode(0o644))
        .expect("widen state permissions");
    let widened_file = small_file_evidence(store.state_path());
    let error = assert_failed_load_preserves_exact_file(&store, store.state_path());
    assert_crypto_failure(&error);
    assert_eq!(small_file_evidence(store.state_path()), widened_file);
    assert_eq!(
        small_file_evidence(store.state_path()).bytes,
        original.bytes
    );

    fs::set_permissions(store.state_path(), fs::Permissions::from_mode(0o600))
        .expect("restore file mode to isolate directory check");
    let state_parent = store
        .state_path()
        .parent()
        .expect("state file has a private parent");
    fs::set_permissions(state_parent, fs::Permissions::from_mode(0o755))
        .expect("widen state parent permissions");
    let before_directory_failure = small_file_evidence(store.state_path());
    let error = assert_failed_load_preserves_exact_file(&store, store.state_path());
    assert_crypto_failure(&error);
    assert_eq!(
        fs::symlink_metadata(state_parent)
            .expect("broad state parent remains")
            .permissions()
            .mode()
            & 0o7777,
        0o755,
        "fail-close must not silently repair an unsafe directory"
    );
    assert_eq!(
        small_file_evidence(store.state_path()),
        before_directory_failure
    );
}

#[test]
fn compare_and_replace_is_existing_only_bounded_and_expected_exact() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let absent_root = private_root(&temp, "replace-absent");
    let absent = open_store(&absent_root, identity(0xc1, 0xc2, 0xc3), storage_kek(0xc4));
    let missing = expect_store_error(
        absent.compare_and_replace(
            &snapshot(b"expected state"),
            &snapshot(b"replacement state"),
        ),
        "replace must not create a missing CryptoState",
    );
    assert_eq!(missing.code(), "remote.crypto_state.missing");
    assert!(
        !absent_root.exists(),
        "existing-only replace must not create directories on missing state"
    );

    let root = private_root(&temp, "replace-cas");
    let store = open_store(&root, identity(0xc5, 0xc6, 0xc7), storage_kek(0xc8));
    let original = snapshot(b"authenticated old runtime state");
    store
        .commit_initial(&original)
        .expect("seed replace CAS state");
    let baseline = exact_tree_evidence(&root);

    let mut wrong_expected = original.expose_secret().to_vec();
    *wrong_expected.last_mut().expect("nonempty expected state") ^= 1;
    let conflict = expect_store_error(
        store.compare_and_replace(
            &CryptoStateSnapshot::new(wrong_expected),
            &snapshot(b"must not publish"),
        ),
        "wrong expected hash/bytes must fail closed",
    );
    assert_eq!(conflict.code(), "remote.crypto_state.cas_conflict");
    assert_eq!(
        exact_tree_evidence(&root),
        baseline,
        "expected mismatch must not create temp files or rewrite durable state"
    );

    let oversized = CryptoStateSnapshot::new(vec![0xa5; MAX_CRYPTO_STATE_PLAINTEXT_LEN + 1]);
    let too_large = expect_store_error(
        store.compare_and_replace(&original, &oversized),
        "replacement above 128 MiB must fail before publication",
    );
    assert_eq!(too_large.code(), "remote.crypto_state.input_too_large");
    assert_eq!(exact_tree_evidence(&root), baseline);
}

#[test]
fn compare_and_replace_authenticates_old_state_and_never_repairs_offline_tamper() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let root = private_root(&temp, "replace-tamper");
    let store = open_store(&root, identity(0xd1, 0xd2, 0xd3), storage_kek(0xd4));
    let original = snapshot(b"authenticated old runtime state");
    store
        .commit_initial(&original)
        .expect("seed tamper fixture");

    let mut tampered = fs::read(store.state_path()).expect("read sealed state fixture");
    *tampered.last_mut().expect("sealed state has a tag") ^= 1;
    fs::write(store.state_path(), tampered).expect("tamper sealed state offline");
    let before = exact_tree_evidence(&root);

    let error = expect_store_error(
        store.compare_and_replace(&original, &snapshot(b"must not replace tampered state")),
        "unauthenticated old state must fail before replace",
    );
    assert_eq!(error.code(), "remote.crypto_state.authentication_failed");
    assert_eq!(
        exact_tree_evidence(&root),
        before,
        "offline tamper failure must perform zero rewrite, repair, or cleanup"
    );
}

#[test]
fn compare_and_replace_publishes_one_private_authenticated_file_and_survives_restart() {
    let temp = tempfile::tempdir().expect("private crypto-state harness");
    let root = private_root(&temp, "replace-success");
    let state_identity = identity(0xe1, 0xe2, 0xe3);
    let store = open_store(&root, state_identity, storage_kek(0xe4));
    let original = snapshot(b"old cursor, replay, and receipt state");
    let replacement = snapshot(b"new cursor, replay, and terminal receipt state");
    store
        .commit_initial(&original)
        .expect("seed replace success state");
    let original_file = small_file_evidence(store.state_path());

    store
        .compare_and_replace(&original, &replacement)
        .expect("authenticated compare-and-replace");

    let replaced_file = small_file_evidence(store.state_path());
    assert_ne!(
        replaced_file.inode, original_file.inode,
        "replace must publish a fresh fully written inode"
    );
    assert!(
        !replaced_file
            .bytes
            .windows(replacement.expose_secret().len())
            .any(|window| window == replacement.expose_secret()),
        "replacement snapshot must stay sealed at rest"
    );
    assert_one_private_state_file(&root, store.state_path());
    assert!(
        store
            .backup_excluded()
            .expect("replacement backup exclusion")
    );

    let reopened = open_store(&root, state_identity, storage_kek(0xe4));
    assert_eq!(
        reopened
            .load()
            .expect("load replaced state after restart")
            .expect("replacement remains present")
            .expose_secret(),
        replacement.expose_secret()
    );
}

#[test]
fn compare_and_replace_crash_child() {
    if env::var_os(REPLACE_CRASH_CHILD_ENV).is_none() {
        return;
    }
    let root = PathBuf::from(
        env::var_os(REPLACE_CRASH_ROOT_ENV).expect("replace crash child root environment"),
    );
    let stage = parse_replace_stage(
        &env::var(REPLACE_CRASH_STAGE_ENV).expect("replace crash child stage environment"),
    );
    let store = FileCryptoStateStore::new_in_with_replace_observer(
        &root,
        identity(0xf1, 0xf2, 0xf3),
        storage_kek(0xf4),
        Arc::new(ExitAtReplaceStage(stage)),
    )
    .expect("open crash-injected replace store");
    store
        .compare_and_replace(
            &snapshot(b"durable old state"),
            &snapshot(b"durable new state"),
        )
        .expect("configured observer must terminate before replace returns");
    panic!("replace crash observer did not terminate the child");
}

#[test]
fn every_replace_crash_boundary_restarts_with_complete_old_or_new_state_without_repair() {
    let stages = [
        (CryptoStateReplaceStage::TempCreated, false),
        (CryptoStateReplaceStage::TempWritten, false),
        (CryptoStateReplaceStage::BackupExcluded, false),
        (CryptoStateReplaceStage::FileSynced, false),
        (CryptoStateReplaceStage::Renamed, true),
        (CryptoStateReplaceStage::ParentSynced, true),
    ];

    for (stage, expects_new) in stages {
        let temp = tempfile::tempdir().expect("private crypto-state crash harness");
        let root = private_root(&temp, replace_stage_name(stage));
        let store = open_store(&root, identity(0xf1, 0xf2, 0xf3), storage_kek(0xf4));
        store
            .commit_initial(&snapshot(b"durable old state"))
            .expect("seed crash-boundary old state");

        let status = Command::new(env::current_exe().expect("current integration test executable"))
            .args(["--exact", "compare_and_replace_crash_child", "--nocapture"])
            .env(REPLACE_CRASH_CHILD_ENV, "1")
            .env(REPLACE_CRASH_ROOT_ENV, &root)
            .env(REPLACE_CRASH_STAGE_ENV, replace_stage_name(stage))
            .status()
            .expect("run replace crash child");
        assert_eq!(
            status.code(),
            Some(REPLACE_CRASH_EXIT_CODE),
            "child must terminate at {}",
            replace_stage_name(stage)
        );

        let reopened = open_store(&root, identity(0xf1, 0xf2, 0xf3), storage_kek(0xf4));
        let before_load = exact_tree_evidence(&root);
        let loaded = reopened
            .load()
            .expect("restart must load one complete authenticated state")
            .expect("replace must never make existing state disappear");
        let expected = if expects_new {
            b"durable new state".as_slice()
        } else {
            b"durable old state".as_slice()
        };
        assert_eq!(
            loaded.expose_secret(),
            expected,
            "restart state at {}",
            replace_stage_name(stage)
        );
        assert!(
            reopened
                .backup_excluded()
                .expect("surviving state backup exclusion"),
            "surviving old/new inode must remain excluded from backup"
        );
        assert_eq!(
            exact_tree_evidence(&root),
            before_load,
            "restart load at {} must not repair or delete crash artifacts",
            replace_stage_name(stage)
        );

        let state_metadata = fs::symlink_metadata(reopened.state_path())
            .expect("surviving state file metadata after crash");
        assert_eq!(state_metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(state_metadata.nlink(), 1);
        for entry in fs::read_dir(reopened.state_path().parent().expect("state path parent"))
            .expect("list crash-boundary state directory")
        {
            let path = entry.expect("crash artifact entry").path();
            let metadata = fs::symlink_metadata(&path).expect("crash artifact metadata");
            assert!(
                metadata.is_file(),
                "crash artifact must not redirect through a link"
            );
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
    }
}
