use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::{ArtifactSha256, UninstallPurgePlanV1};

use crate::remote::counter::CounterGuardState;
use crate::remote::identity::scoped_counter_guard_account_from_token;
use crate::runtime::model::RuntimeStoreConfig;
use crate::runtime::singleton::SingletonGuard;
use crate::runtime::store::RuntimeStoreHandle;
use crate::security::load_or_create_storage_kek;

use super::*;

const TEAM: &str = "TEAM123";
const ACCESS_GROUP: &str = "TEAM123.com.agentdeck.agentdeckd.stable";
const VERSION: &str = "1.2.3";
const OLD_VERSION: &str = "1.1.0";
const HELPER_BYTES: &[u8] = b"signed helper fixture";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
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
    fn insert(&self, account: &str, bytes: &[u8]) {
        self.values
            .lock()
            .expect("values")
            .insert(account.to_owned(), bytes.to_vec());
    }

    fn contains(&self, account: &str) -> bool {
        self.values.lock().expect("values").contains_key(account)
    }

    fn operations(&self) -> Vec<KeyOperation> {
        self.operations.lock().expect("operations").clone()
    }

    fn clear_operations(&self) {
        self.operations.lock().expect("operations").clear();
    }

    fn values_snapshot(&self) -> HashMap<String, Vec<u8>> {
        self.values.lock().expect("values").clone()
    }

    fn clear_values(&self) {
        self.values.lock().expect("values").clear();
    }

    fn deletes(&self) -> Vec<String> {
        self.operations()
            .into_iter()
            .filter_map(|operation| match operation {
                KeyOperation::Delete(account) => Some(account),
                KeyOperation::Load(_) | KeyOperation::Store(_) => None,
            })
            .collect()
    }
}

impl KeyStore for RecordingKeyStore {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
        self.operations
            .lock()
            .map_err(|_| KeyStoreError::Poisoned)?
            .push(KeyOperation::Load(account.to_owned()));
        Ok(self
            .values
            .lock()
            .map_err(|_| KeyStoreError::Poisoned)?
            .get(account)
            .map(|bytes| SecretBytes::new(bytes.clone())))
    }

    fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
        self.operations
            .lock()
            .map_err(|_| KeyStoreError::Poisoned)?
            .push(KeyOperation::Store(account.to_owned()));
        self.values
            .lock()
            .map_err(|_| KeyStoreError::Poisoned)?
            .insert(account.to_owned(), value.expose_secret().to_vec());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        self.operations
            .lock()
            .map_err(|_| KeyStoreError::Poisoned)?
            .push(KeyOperation::Delete(account.to_owned()));
        self.values
            .lock()
            .map_err(|_| KeyStoreError::Poisoned)?
            .remove(account);
        Ok(())
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "ad-purge-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create test root");
        set_mode(&path, 0o700);
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _root: TestRoot,
    paths: DaemonPaths,
    helper: PathBuf,
    old_directory: PathBuf,
    plist: PathBuf,
    plan: UninstallPurgePlanV1,
    identity: RunningFinalizerIdentity,
    keys: RecordingKeyStore,
    database_id: [u8; 16],
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = TestRoot::new(label);
        let home = root.0.join("home");
        fs::create_dir(&home).expect("home");
        set_mode(&home, 0o700);
        let paths = DaemonPaths::stable(&home, Some(ACCESS_GROUP.to_owned())).expect("paths");
        fs::create_dir_all(&paths.data_dir).expect("data dir");
        set_mode(&paths.data_dir, 0o700);
        write_mode(&paths.lock, b"", 0o600);
        let bin = paths.data_dir.join("bin");
        fs::create_dir(&bin).expect("bin");
        set_mode(&bin, 0o700);
        let current_directory = bin.join(VERSION);
        let old_directory = bin.join(OLD_VERSION);
        for directory in [&current_directory, &old_directory] {
            fs::create_dir(directory).expect("version dir");
            set_mode(directory, 0o700);
        }
        write_mode(&old_directory.join(DAEMON_BASENAME), b"old helper", 0o500);
        let helper = current_directory.join(DAEMON_BASENAME);
        write_mode(&helper, HELPER_BYTES, 0o500);
        symlink(VERSION, bin.join(CURRENT_BASENAME)).expect("current symlink");

        let launch_agents = home.join("Library/LaunchAgents");
        fs::create_dir_all(&launch_agents).expect("LaunchAgents");
        let plist = launch_agents.join(PLIST_BASENAME);
        write_mode(&plist, b"plist", 0o600);
        let helper_hash = ArtifactSha256::new(hex(&sha256(HELPER_BYTES))).expect("hash");
        let plan = UninstallPurgePlanV1::new(
            helper.clone(),
            VERSION.to_owned(),
            helper_hash,
            TEAM.to_owned(),
            ACCESS_GROUP.to_owned(),
        )
        .expect("plan");
        let identity = RunningFinalizerIdentity::injected_for_test(
            helper.clone(),
            VERSION.to_owned(),
            TEAM.to_owned(),
            ACCESS_GROUP.to_owned(),
        )
        .expect("identity");
        let keys = RecordingKeyStore::default();
        keys.insert(STORAGE_KEK_ACCOUNT, &[0x91; 32]);
        for (index, account) in machine_accounts().iter().enumerate() {
            keys.insert(account, &[0x40 + index as u8; 32]);
        }
        let storage_kek =
            load_or_create_storage_kek(&keys, &paths.runtime_db).expect("load fixture StorageKEK");
        let database_id = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("build purge fixture runtime");
                    runtime.block_on(async {
                        let store = RuntimeStoreHandle::open(
                            RuntimeStoreConfig::new(paths.runtime_db.clone()),
                            storage_kek,
                        )
                        .await
                        .expect("create authenticated purge fixture database");
                        let database_id = store.authenticated_database_id();
                        store
                            .shutdown()
                            .await
                            .expect("shutdown purge fixture store");
                        database_id
                    })
                })
                .join()
                .expect("join purge fixture runtime")
        });
        Self {
            _root: root,
            paths,
            helper,
            old_directory,
            plist,
            plan,
            identity,
            keys,
            database_id,
        }
    }

    fn authorization(&self) -> AuthenticatedPurgeAuthorization {
        AuthenticatedPurgeAuthorization {
            binding: PurgeAuthorizationBinding::Remote {
                database_id: self.database_id,
                relay_server_id: [0x12; 16],
                machine_route: [0x13; 16],
                root_key_id: [0x14; 16],
                root_fingerprint: [0x22; 32],
                trust_epoch: 7,
                reset_kind: 1,
                purge_proof_hash: [0x33; 32],
                cleanup_witness_hash: None,
            },
        }
    }

    fn local_deleted_authorization(&self) -> AuthenticatedPurgeAuthorization {
        AuthenticatedPurgeAuthorization {
            binding: PurgeAuthorizationBinding::Remote {
                database_id: self.database_id,
                relay_server_id: [0x12; 16],
                machine_route: [0x13; 16],
                root_key_id: [0x14; 16],
                root_fingerprint: [0x22; 32],
                trust_epoch: 7,
                reset_kind: 2,
                purge_proof_hash: [0x33; 32],
                cleanup_witness_hash: Some([0x34; 32]),
            },
        }
    }

    fn unenrolled_authorization(&self) -> AuthenticatedPurgeAuthorization {
        AuthenticatedPurgeAuthorization {
            binding: PurgeAuthorizationBinding::Unenrolled {
                database_id: self.database_id,
                root_key_id: [0x14; 16],
                root_fingerprint: [0x22; 32],
                trust_epoch: 1,
                key_directory_revision: 1,
                identity_binding_hash: [0x35; 32],
            },
        }
    }

    fn prepare(&self) {
        assert_eq!(
            prepare_purge_marker(
                &self.keys,
                &self.paths,
                &self.identity,
                PurgeMarkerRequest::Uninstall {
                    authorization: self.authorization(),
                    plan: &self.plan,
                },
            )
            .expect("prepare marker"),
            PreparePurgeMarkerOutcome::Prepared {
                phase: PurgeFinalizerPhase::Prepared,
            }
        );
    }

    fn reserve(&self) -> PurgeMarkerReservation {
        reserve_purge_marker(&self.keys, &self.paths, &self.identity, &self.plan)
            .expect("reserve marker")
    }

    fn authorize(&self, reservation: &PurgeMarkerReservation) {
        assert!(matches!(
            authorize_reserved_purge_marker(
                &self.keys,
                &self.paths,
                &self.identity,
                reservation,
                self.authorization(),
            )
            .expect("authorize marker"),
            PreparePurgeMarkerOutcome::Prepared { .. } | PreparePurgeMarkerOutcome::Replayed { .. }
        ));
    }

    fn stopped(&self) -> PurgeStoppedPermit {
        PurgeStoppedPermit::acquire(&self.paths).expect("stopped permit")
    }

    fn plan_id(&self) -> [u8; 16] {
        *self.plan.plan_id()
    }

    fn make_terminal_absent(&self) {
        if self.plist.exists() {
            fs::remove_file(&self.plist).expect("remove plist");
        }
        let bin = self.paths.data_dir.join("bin");
        if bin.exists() {
            fs::remove_dir_all(&bin).expect("remove bin tree");
        }
        let anchor = self.paths.data_dir.join(PURGE_RETAINED_HELPER_BASENAME);
        if anchor.exists() {
            fs::remove_file(anchor).expect("remove anchor");
        }
        for path in runtime_artifact_paths(&self.paths.runtime_db) {
            if path.exists() {
                fs::remove_file(path).expect("remove runtime artifact");
            }
        }
        self.keys.clear_values();
        self.keys.clear_operations();
    }

    fn seed_counter_guard_manifest(&self, entries: &[([u8; 32], bool, bool)]) {
        let storage_kek = load_or_create_storage_kek(&self.keys, &self.paths.runtime_db)
            .expect("reload fixture StorageKEK");
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("build guard fixture runtime");
                    runtime.block_on(async {
                        let store = RuntimeStoreHandle::open(
                            RuntimeStoreConfig::new(self.paths.runtime_db.clone()),
                            storage_kek,
                        )
                        .await
                        .expect("open guard fixture database");
                        for (scope_token, materialized, _) in entries.iter().copied() {
                            store
                                .register_remote_counter_guard_scope(scope_token)
                                .await
                                .expect("register purge guard scope");
                            if materialized {
                                store
                                    .mark_remote_counter_guard_scope_materialized(scope_token)
                                    .await
                                    .expect("materialize purge guard scope");
                            }
                        }
                        assert_eq!(store.authenticated_database_id(), self.database_id);
                        store
                            .shutdown()
                            .await
                            .expect("shutdown guard fixture store");
                    });
                })
                .join()
                .expect("join guard fixture runtime");
        });
        for (index, (scope_token, _, present)) in entries.iter().copied().enumerate() {
            if present {
                let guard = CounterGuardState::stable(
                    scope_token,
                    1_024 + index as u64,
                    [0x81 + index as u8; 32],
                )
                .expect("build purge guard");
                self.keys.insert(
                    &scoped_counter_guard_account_from_token(scope_token)
                        .expect("derive purge guard account"),
                    &guard.encode(),
                );
            }
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("write fixture");
    set_mode(path, mode);
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DiskNode {
    Directory { mode: u32 },
    File { mode: u32, bytes: Vec<u8> },
    Symlink { mode: u32, target: PathBuf },
}

fn disk_snapshot(root: &Path) -> BTreeMap<PathBuf, DiskNode> {
    fn visit(root: &Path, path: &Path, nodes: &mut BTreeMap<PathBuf, DiskNode>) {
        let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
        let relative = path
            .strip_prefix(root)
            .expect("snapshot relative")
            .to_path_buf();
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            nodes.insert(
                relative,
                DiskNode::Symlink {
                    mode,
                    target: fs::read_link(path).expect("snapshot symlink"),
                },
            );
        } else if metadata.is_dir() {
            nodes.insert(relative, DiskNode::Directory { mode });
            let mut children = fs::read_dir(path)
                .expect("snapshot directory")
                .collect::<Result<Vec<_>, _>>()
                .expect("snapshot entries");
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                visit(root, &child.path(), nodes);
            }
        } else if metadata.is_file() {
            nodes.insert(
                relative,
                DiskNode::File {
                    mode,
                    bytes: fs::read(path).expect("snapshot file"),
                },
            );
        } else {
            panic!("unsupported snapshot entry: {}", path.display());
        }
    }

    let mut nodes = BTreeMap::new();
    visit(root, root, &mut nodes);
    nodes
}

struct CrashOnce {
    target: PurgeFinalizerEvent,
    fired: AtomicBool,
}

impl CrashOnce {
    fn new(target: PurgeFinalizerEvent) -> Self {
        Self {
            target,
            fired: AtomicBool::new(false),
        }
    }
}

impl PurgeFinalizerObserver for CrashOnce {
    fn observe(&self, event: PurgeFinalizerEvent) -> Result<(), PurgeFinalizerError> {
        if event == self.target && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(PurgeFinalizerError::InjectedCrash);
        }
        Ok(())
    }
}

fn assert_no_deletes_since(keys: &RecordingKeyStore, baseline: &[KeyOperation]) {
    assert!(
        keys.operations()[baseline.len()..]
            .iter()
            .all(|operation| !matches!(operation, KeyOperation::Delete(_)))
    );
}

fn assert_no_key_writes(keys: &RecordingKeyStore) {
    assert!(
        keys.operations()
            .iter()
            .all(|operation| matches!(operation, KeyOperation::Load(_))),
        "rejected path must perform Keychain reads only: {:?}",
        keys.operations()
    );
}

#[test]
fn ordinary_trust_reset_performs_zero_marker_io() {
    let fixture = Fixture::new("ordinary-reset");
    fixture.keys.clear_operations();
    assert_eq!(
        prepare_purge_marker(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            PurgeMarkerRequest::NotRequested,
        )
        .unwrap(),
        PreparePurgeMarkerOutcome::NotRequested
    );
    assert!(fixture.keys.operations().is_empty());
}

#[test]
fn marker_intent_probe_is_read_only_and_malformed_state_fails_closed() {
    let absent = Fixture::new("intent-probe-absent");
    absent.keys.clear_operations();
    assert!(!purge_marker_intent_present(&absent.keys).expect("absent marker probe"));
    assert_no_key_writes(&absent.keys);

    let present = Fixture::new("intent-probe-present");
    present.reserve();
    present.keys.clear_operations();
    assert!(purge_marker_intent_present(&present.keys).expect("present marker probe"));
    assert_no_key_writes(&present.keys);

    present
        .keys
        .insert(PURGE_FINALIZER_MARKER_ACCOUNT, b"not-canonical-marker");
    present.keys.clear_operations();
    let error = purge_marker_intent_present(&present.keys)
        .expect_err("malformed marker cannot be treated as absent");
    assert_eq!(error.code(), "daemon.purge.marker_invalid");
    assert_no_key_writes(&present.keys);
}

#[test]
fn legacy_v1_marker_is_typed_fail_closed_and_never_rewritten() {
    for (index, phase) in ["prepared", "runtimeRemoved"].into_iter().enumerate() {
        let fixture = Fixture::new(&format!("legacy-v1-marker-{index}"));
        fixture.reserve();
        let current = fixture
            .keys
            .values_snapshot()
            .remove(PURGE_FINALIZER_MARKER_ACCOUNT)
            .expect("current marker bytes");
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&current).expect("decode current marker fixture");
        let object = legacy.as_object_mut().expect("marker object");
        object.insert("marker_version".to_owned(), serde_json::json!(1));
        object.insert("phase".to_owned(), serde_json::json!(phase));
        object.remove("counter_guard_manifest");
        let legacy_bytes = serde_json::to_vec(&legacy).expect("encode legacy marker fixture");
        fixture
            .keys
            .insert(PURGE_FINALIZER_MARKER_ACCOUNT, &legacy_bytes);
        fixture.keys.clear_operations();

        let error = purge_marker_intent_present(&fixture.keys)
            .expect_err("legacy marker must remain a visible fail-closed intent");
        assert_eq!(error.code(), "daemon.purge.marker_version_unsupported");
        assert_eq!(
            fixture
                .keys
                .values_snapshot()
                .get(PURGE_FINALIZER_MARKER_ACCOUNT),
            Some(&legacy_bytes),
            "unsupported marker bytes must remain exact"
        );
        assert_no_key_writes(&fixture.keys);
    }
}

#[test]
fn current_alias_identity_accepts_exact_target_and_rejects_wrong_target() {
    let fixture = Fixture::new("current-alias");
    let current_executable = fixture
        .paths
        .data_dir
        .join("bin/current")
        .join(DAEMON_BASENAME);
    let identity = RunningFinalizerIdentity::injected_for_test(
        current_executable,
        VERSION.to_owned(),
        TEAM.to_owned(),
        ACCESS_GROUP.to_owned(),
    )
    .expect("current alias identity");
    reserve_purge_marker(&fixture.keys, &fixture.paths, &identity, &fixture.plan)
        .expect("exact current alias");

    fixture.keys.delete(PURGE_FINALIZER_MARKER_ACCOUNT).unwrap();
    fs::remove_file(fixture.paths.data_dir.join("bin/current")).unwrap();
    symlink(OLD_VERSION, fixture.paths.data_dir.join("bin/current")).unwrap();
    fixture.keys.clear_operations();
    let error = reserve_purge_marker(&fixture.keys, &fixture.paths, &identity, &fixture.plan)
        .expect_err("wrong current target");
    assert_eq!(error.code(), "daemon.purge.plan_mismatch");
    assert!(!fixture.keys.contains(PURGE_FINALIZER_MARKER_ACCOUNT));
}

#[test]
fn reserved_marker_is_not_executable_and_authorization_is_monotonic() {
    let fixture = Fixture::new("reserved");
    let reservation = fixture.reserve();
    let replay = fixture.reserve();
    assert_eq!(replay.plan_id, reservation.plan_id);
    let stopped = fixture.stopped();
    fixture.keys.clear_operations();
    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("reserved marker must not authorize deletion");
    assert_eq!(error.code(), "daemon.purge.marker_unauthorized");
    assert!(fixture.keys.deletes().is_empty());
    drop(stopped);

    fixture.authorize(&reservation);
    assert!(matches!(
        authorize_reserved_purge_marker(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &reservation,
            fixture.authorization(),
        )
        .unwrap(),
        PreparePurgeMarkerOutcome::Replayed { .. }
    ));
}

#[test]
fn late_local_deleted_and_unenrolled_authorizations_require_exact_key_presence_shapes() {
    let local_conflict = Fixture::new("late-local-present");
    let reservation = local_conflict.reserve();
    local_conflict.keys.clear_operations();
    let error = authorize_reserved_purge_marker(
        &local_conflict.keys,
        &local_conflict.paths,
        &local_conflict.identity,
        &reservation,
        local_conflict.local_deleted_authorization(),
    )
    .expect_err("LocalDeleted authorization requires all machine items already absent");
    assert_eq!(error.code(), "daemon.purge.authorization_invalid");
    assert_no_key_writes(&local_conflict.keys);

    let local_ready = Fixture::new("late-local-absent");
    for account in machine_accounts() {
        local_ready
            .keys
            .delete(account)
            .expect("remove machine item");
    }
    let reservation = local_ready.reserve();
    assert!(matches!(
        authorize_reserved_purge_marker(
            &local_ready.keys,
            &local_ready.paths,
            &local_ready.identity,
            &reservation,
            local_ready.local_deleted_authorization(),
        )
        .expect("authenticated LocalDeleted with absent items authorizes"),
        PreparePurgeMarkerOutcome::Prepared { .. }
    ));

    let unenrolled_ready = Fixture::new("unenrolled-present");
    let reservation = unenrolled_ready.reserve();
    assert!(matches!(
        authorize_reserved_purge_marker(
            &unenrolled_ready.keys,
            &unenrolled_ready.paths,
            &unenrolled_ready.identity,
            &reservation,
            unenrolled_ready.unenrolled_authorization(),
        )
        .expect("authenticated unenrolled identity with complete items authorizes"),
        PreparePurgeMarkerOutcome::Prepared { .. }
    ));

    let unenrolled_conflict = Fixture::new("unenrolled-missing");
    unenrolled_conflict
        .keys
        .delete(MACHINE_DATA_SIGN_ACCOUNT)
        .expect("remove one machine item");
    let reservation = unenrolled_conflict.reserve();
    let error = authorize_reserved_purge_marker(
        &unenrolled_conflict.keys,
        &unenrolled_conflict.paths,
        &unenrolled_conflict.identity,
        &reservation,
        unenrolled_conflict.unenrolled_authorization(),
    )
    .expect_err("unenrolled authorization cannot delete a partial identity");
    assert_eq!(error.code(), "daemon.purge.authorization_invalid");
}

#[test]
fn reserve_rejects_preexisting_flat_anchor_before_marker_write() {
    let fixture = Fixture::new("reserve-anchor");
    let anchor = fixture.paths.data_dir.join(PURGE_RETAINED_HELPER_BASENAME);
    write_mode(&anchor, b"offline extra anchor", 0o500);
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();

    let error = reserve_purge_marker(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &fixture.plan,
    )
    .expect_err("flat anchor must be absent before marker reserve");

    assert_eq!(error.code(), "daemon.purge.install_layout_invalid");
    assert!(!fixture.keys.contains(PURGE_FINALIZER_MARKER_ACCOUNT));
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn reserved_resume_rejects_offline_flat_anchor_without_authorizing() {
    let fixture = Fixture::new("resume-anchor");
    fixture.reserve();
    let anchor = fixture.paths.data_dir.join(PURGE_RETAINED_HELPER_BASENAME);
    write_mode(&anchor, b"offline extra anchor", 0o500);
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();

    let error = resume_reserved_purge_marker(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        fixture.authorization(),
    )
    .expect_err("reserved recovery must reject an injected flat anchor");

    assert_eq!(error.code(), "daemon.purge.install_layout_invalid");
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn missing_marker_and_absent_database_never_authorize_deletion() {
    let fixture = Fixture::new("missing-marker");
    for path in runtime_artifact_paths(&fixture.paths.runtime_db) {
        fs::remove_file(path).expect("remove runtime fixture");
    }
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();
    let stopped = fixture.stopped();
    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("missing marker must fail closed");
    assert_eq!(error.code(), "daemon.purge.install_layout_invalid");
    assert!(fixture.keys.deletes().is_empty());
    assert!(fixture.helper.exists());
    assert!(fixture.plist.exists());
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn full_finalizer_order_keeps_recovery_helper_and_deletes_marker_last() {
    let fixture = Fixture::new("full-order");
    fixture.prepare();
    fixture.keys.clear_operations();
    let stopped = fixture.stopped();
    assert_eq!(
        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .unwrap(),
        PurgeFinalizerOutcome::Completed
    );
    assert!(
        fixture.helper.exists(),
        "retained helper is CLI cleanup anchor"
    );
    assert!(!fixture.old_directory.exists());
    assert!(!fixture.plist.exists());
    assert!(!fixture.paths.data_dir.join("bin/current").exists());
    for path in runtime_artifact_paths(&fixture.paths.runtime_db) {
        assert!(!path.exists());
    }
    for account in machine_accounts() {
        assert!(!fixture.keys.contains(account));
    }
    assert!(!fixture.keys.contains(STORAGE_KEK_ACCOUNT));
    assert!(!fixture.keys.contains(PURGE_FINALIZER_MARKER_ACCOUNT));
    let deletes = fixture.keys.deletes();
    let storage_index = deletes
        .iter()
        .position(|account| account == STORAGE_KEK_ACCOUNT)
        .expect("StorageKEK deletion");
    let marker_index = deletes
        .iter()
        .position(|account| account == PURGE_FINALIZER_MARKER_ACCOUNT)
        .expect("marker deletion");
    assert!(machine_accounts().iter().all(|account| {
        deletes
            .iter()
            .position(|deleted| deleted == account)
            .is_some_and(|index| index < storage_index)
    }));
    assert!(storage_index < marker_index);
    assert_eq!(marker_index, deletes.len() - 1);
}

#[test]
fn counter_guard_phase_removes_authenticated_v2_inventory_before_runtime_and_machine_secrets() {
    let fixture = Fixture::new("counter-guard-order");
    let entries = [
        ([0x11; 32], false, false),
        ([0x22; 32], true, true),
        ([0x33; 32], true, true),
    ];
    fixture.seed_counter_guard_manifest(&entries);
    fixture.prepare();
    fixture.keys.clear_operations();
    let stopped = fixture.stopped();

    let error = run_purge_finalizer_with_observer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
        &CrashOnce::new(PurgeFinalizerEvent::BeforePhase(
            PurgeFinalizerPhase::CounterGuardsRemoved,
        )),
    )
    .expect_err("stop after CounterGuard cleanup phase commit");
    assert_eq!(error.code(), "daemon.purge.injected_crash");
    assert!(fixture.paths.runtime_db.exists());
    for (scope_token, _, _) in entries {
        assert!(!fixture.keys.contains(
            &scoped_counter_guard_account_from_token(scope_token).expect("guard account")
        ));
    }
    for account in machine_accounts() {
        assert!(fixture.keys.contains(account));
    }
    let deletes = fixture.keys.deletes();
    assert_eq!(
        deletes,
        vec![
            scoped_counter_guard_account_from_token([0x22; 32]).unwrap(),
            scoped_counter_guard_account_from_token([0x33; 32]).unwrap(),
        ]
    );

    assert_eq!(
        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .expect("resume after CounterGuard phase commit"),
        PurgeFinalizerOutcome::Completed
    );
}

#[test]
fn counter_guard_batch_preflight_rejects_late_corruption_before_first_delete() {
    let fixture = Fixture::new("cg-preflight");
    fixture.seed_counter_guard_manifest(&[([0x41; 32], true, true), ([0x42; 32], true, true)]);
    fixture.prepare();
    let later = scoped_counter_guard_account_from_token([0x42; 32]).unwrap();
    fixture.keys.insert(&later, b"corrupt-later-guard");
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();
    let stopped = fixture.stopped();

    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("all guards must validate before the first delete");
    assert_eq!(error.code(), "daemon.purge.counter_guard_cleanup_failed");
    assert!(fixture.keys.deletes().is_empty());
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert!(fixture.paths.runtime_db.exists());
}

#[test]
fn counter_guard_delete_before_phase_commit_is_exactly_retryable() {
    let fixture = Fixture::new("cg-crash");
    fixture.seed_counter_guard_manifest(&[
        ([0x51; 32], false, false),
        ([0x52; 32], true, true),
        ([0x53; 32], true, true),
    ]);
    fixture.prepare();
    let stopped = fixture.stopped();

    let error = run_purge_finalizer_with_observer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
        &CrashOnce::new(PurgeFinalizerEvent::AfterPhaseAction(
            PurgeFinalizerPhase::InstallDetached,
        )),
    )
    .expect_err("crash after guard readback but before phase marker commit");
    assert_eq!(error.code(), "daemon.purge.injected_crash");
    assert!(fixture.paths.runtime_db.exists());
    assert_eq!(
        load_marker(&fixture.keys)
            .expect("load retry marker")
            .expect("retry marker remains")
            .phase,
        PurgeFinalizerPhase::InstallDetached
    );

    assert_eq!(
        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .expect("retry converges from guard delete crash gap"),
        PurgeFinalizerOutcome::Completed
    );
}

#[test]
fn marker_freezes_constant_size_counter_guard_commitment_not_token_inventory() {
    let empty = Fixture::new("cg-empty");
    empty.reserve();
    let empty_marker = load_marker(&empty.keys)
        .expect("load empty marker")
        .expect("empty marker exists");
    assert_eq!(empty_marker.counter_guard_manifest.count, 0);

    let populated = Fixture::new("cg-populated");
    populated.seed_counter_guard_manifest(&[
        ([0x61; 32], false, false),
        ([0x62; 32], true, true),
        ([0x63; 32], true, true),
    ]);
    populated.reserve();
    let populated_bytes = populated.keys.values_snapshot();
    let populated_marker = populated_bytes
        .get(PURGE_FINALIZER_MARKER_ACCOUNT)
        .expect("populated marker");
    let decoded = load_marker(&populated.keys)
        .expect("load populated marker")
        .expect("populated marker exists");
    assert_eq!(decoded.counter_guard_manifest.count, 3);
    assert_ne!(
        decoded.counter_guard_manifest.digest,
        empty_marker.counter_guard_manifest.digest
    );
    for token in [[0x61; 32], [0x62; 32], [0x63; 32]] {
        assert!(
            !populated_marker
                .windows(token.len())
                .any(|window| window == token),
            "marker must not embed the manifest token list"
        );
    }
}

#[test]
fn every_nonterminal_phase_before_action_and_commit_crash_is_retryable() {
    let events = [
        PurgeFinalizerEvent::BeforePhase(PurgeFinalizerPhase::Prepared),
        PurgeFinalizerEvent::AfterPlistDetach,
        PurgeFinalizerEvent::AfterRemovableVersionDetach(0),
        PurgeFinalizerEvent::AfterCurrentDetach,
        PurgeFinalizerEvent::AfterPhaseAction(PurgeFinalizerPhase::Prepared),
        PurgeFinalizerEvent::AfterPhaseCommit(PurgeFinalizerPhase::InstallDetached),
        PurgeFinalizerEvent::BeforePhase(PurgeFinalizerPhase::InstallDetached),
        PurgeFinalizerEvent::AfterPhaseAction(PurgeFinalizerPhase::InstallDetached),
        PurgeFinalizerEvent::AfterPhaseCommit(PurgeFinalizerPhase::CounterGuardsRemoved),
        PurgeFinalizerEvent::BeforePhase(PurgeFinalizerPhase::CounterGuardsRemoved),
        PurgeFinalizerEvent::AfterPhaseAction(PurgeFinalizerPhase::CounterGuardsRemoved),
        PurgeFinalizerEvent::AfterPhaseCommit(PurgeFinalizerPhase::RuntimeRemoved),
        PurgeFinalizerEvent::BeforePhase(PurgeFinalizerPhase::RuntimeRemoved),
        PurgeFinalizerEvent::AfterPhaseAction(PurgeFinalizerPhase::RuntimeRemoved),
        PurgeFinalizerEvent::AfterPhaseCommit(PurgeFinalizerPhase::MachineSecretsRemoved),
        PurgeFinalizerEvent::BeforePhase(PurgeFinalizerPhase::MachineSecretsRemoved),
        PurgeFinalizerEvent::AfterPhaseAction(PurgeFinalizerPhase::MachineSecretsRemoved),
        PurgeFinalizerEvent::AfterPhaseCommit(PurgeFinalizerPhase::StorageKekRemoved),
        PurgeFinalizerEvent::BeforePhase(PurgeFinalizerPhase::StorageKekRemoved),
    ];
    for (index, event) in events.into_iter().enumerate() {
        let fixture = Fixture::new(&format!("crash-{index}"));
        fixture.prepare();
        let stopped = fixture.stopped();
        let error = run_purge_finalizer_with_observer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
            &CrashOnce::new(event),
        )
        .expect_err("injected crash");
        assert_eq!(error.code(), "daemon.purge.injected_crash");
        assert!(fixture.helper.exists());
        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .unwrap_or_else(|error| panic!("same exact helper resumes {event:?}: {error:?}"));
        assert!(!fixture.keys.contains(PURGE_FINALIZER_MARKER_ACCOUNT));
    }
}

#[test]
fn marker_deleted_terminal_crash_leaves_only_cli_cleanup_anchor() {
    let fixture = Fixture::new("terminal-crash");
    fixture.prepare();
    let stopped = fixture.stopped();
    let error = run_purge_finalizer_with_observer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
        &CrashOnce::new(PurgeFinalizerEvent::AfterMarkerDelete),
    )
    .expect_err("crash after marker readback");
    assert_eq!(error.code(), "daemon.purge.injected_crash");
    assert!(!fixture.keys.contains(PURGE_FINALIZER_MARKER_ACCOUNT));
    assert!(!fixture.keys.contains(STORAGE_KEK_ACCOUNT));
    assert!(fixture.helper.exists());
    assert_eq!(
        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .unwrap(),
        PurgeFinalizerOutcome::AlreadyCompleted
    );
}

#[test]
fn marker_missing_flat_anchor_proves_empty_or_absent_bin_without_rewrite() {
    for (index, remove_bin_prefix) in [false, true].into_iter().enumerate() {
        let fixture = Fixture::new(&format!("anchor-term-{index}"));
        fixture.prepare();
        let stopped = fixture.stopped();
        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .expect("reach marker-missing retained helper layout");
        drop(stopped);

        let anchor = fixture.paths.data_dir.join(PURGE_RETAINED_HELPER_BASENAME);
        fs::rename(&fixture.helper, &anchor).expect("publish flat retained anchor");
        if remove_bin_prefix {
            fs::remove_dir(fixture.helper.parent().unwrap()).expect("remove empty version");
            fs::remove_dir(fixture.paths.data_dir.join("bin")).expect("remove empty bin");
        }
        let anchor_identity = RunningFinalizerIdentity::injected_for_test(
            anchor,
            VERSION.to_owned(),
            TEAM.to_owned(),
            ACCESS_GROUP.to_owned(),
        )
        .expect("anchor identity");
        fixture.keys.clear_operations();
        let disk_before = disk_snapshot(&fixture._root.0);
        let keys_before = fixture.keys.values_snapshot();

        let stopped = fixture.stopped();
        assert_eq!(
            run_purge_finalizer(
                &fixture.keys,
                &fixture.paths,
                &anchor_identity,
                &stopped,
                fixture.plan_id(),
            )
            .expect("anchor proves exact terminal state"),
            PurgeFinalizerOutcome::AlreadyCompleted
        );
        drop(stopped);
        assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
        assert_eq!(fixture.keys.values_snapshot(), keys_before);
        assert_no_key_writes(&fixture.keys);
    }
}

#[test]
fn marker_present_rejects_flat_anchor_without_rewrite() {
    let fixture = Fixture::new("anchor-marker");
    fixture.prepare();
    let anchor = fixture.paths.data_dir.join(PURGE_RETAINED_HELPER_BASENAME);
    fs::rename(&fixture.helper, &anchor).expect("offline premature anchor");
    let anchor_identity = RunningFinalizerIdentity::injected_for_test(
        anchor,
        VERSION.to_owned(),
        TEAM.to_owned(),
        ACCESS_GROUP.to_owned(),
    )
    .expect("anchor identity");
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();

    let stopped = fixture.stopped();
    run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &anchor_identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("anchor may only enter marker-missing terminal proof");
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn marker_present_extra_flat_anchor_rejects_before_first_deletion() {
    let fixture = Fixture::new("marker-extra-anchor");
    fixture.prepare();
    let anchor = fixture.paths.data_dir.join(PURGE_RETAINED_HELPER_BASENAME);
    write_mode(&anchor, b"offline extra anchor", 0o500);
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();

    let stopped = fixture.stopped();
    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("marker-present finalizer must reject an extra flat anchor");

    assert_eq!(error.code(), "daemon.purge.install_layout_invalid");
    assert!(fixture.plist.exists());
    assert!(fixture.paths.runtime_db.exists());
    assert!(fixture.keys.contains(STORAGE_KEK_ACCOUNT));
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn terminal_absence_proof_is_read_only_and_requires_every_protected_item_absent() {
    let fixture = Fixture::new("terminal-proof-ok");
    fixture.make_terminal_absent();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();
    let stopped = fixture.stopped();
    assert_eq!(
        prove_purge_terminal_absence(&fixture.keys, &fixture.paths, &stopped)
            .expect("strict all-absent proof"),
        PurgeTerminalAbsenceOutcome::Proven
    );
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);

    for (index, residual) in [
        "plist",
        "current",
        "bin",
        "anchor",
        "runtime-db",
        "runtime-wal",
        "runtime-shm",
        MACHINE_DATA_SIGN_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        KEY_DIRECTORY_GUARD_ACCOUNT,
        MACHINE_ROOT_SIGN_ACCOUNT,
        STORAGE_KEK_ACCOUNT,
        "marker-valid",
        "marker-malformed",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("absence-{index}"));
        let valid_marker = if residual == "marker-valid" {
            fixture.prepare();
            fixture
                .keys
                .values_snapshot()
                .remove(PURGE_FINALIZER_MARKER_ACCOUNT)
        } else {
            None
        };
        fixture.make_terminal_absent();
        match residual {
            "plist" => write_mode(&fixture.plist, b"residual", 0o600),
            "current" => {
                let bin = fixture.paths.data_dir.join("bin");
                fs::create_dir(&bin).expect("residual bin");
                set_mode(&bin, 0o700);
                symlink(VERSION, bin.join(CURRENT_BASENAME)).expect("residual current");
            }
            "bin" => {
                let bin = fixture.paths.data_dir.join("bin");
                fs::create_dir(&bin).expect("residual bin");
                set_mode(&bin, 0o700);
            }
            "anchor" => write_mode(
                &fixture.paths.data_dir.join(PURGE_RETAINED_HELPER_BASENAME),
                b"residual",
                0o500,
            ),
            "runtime-db" => write_mode(&fixture.paths.runtime_db, b"residual", 0o600),
            "runtime-wal" => write_mode(
                &runtime_artifact_paths(&fixture.paths.runtime_db)[1],
                b"residual",
                0o600,
            ),
            "runtime-shm" => write_mode(
                &runtime_artifact_paths(&fixture.paths.runtime_db)[2],
                b"residual",
                0o600,
            ),
            "marker-valid" => fixture.keys.insert(
                PURGE_FINALIZER_MARKER_ACCOUNT,
                &valid_marker.expect("saved valid marker"),
            ),
            "marker-malformed" => fixture
                .keys
                .insert(PURGE_FINALIZER_MARKER_ACCOUNT, b"not canonical marker"),
            account => fixture.keys.insert(account, b"residual secret"),
        }
        fixture.keys.clear_operations();
        let disk_before = disk_snapshot(&fixture._root.0);
        let keys_before = fixture.keys.values_snapshot();
        let stopped = fixture.stopped();

        if prove_purge_terminal_absence(&fixture.keys, &fixture.paths, &stopped).is_ok() {
            panic!("residual must reject: {residual}");
        }

        drop(stopped);
        assert_eq!(
            disk_snapshot(&fixture._root.0),
            disk_before,
            "residual={residual}"
        );
        assert_eq!(
            fixture.keys.values_snapshot(),
            keys_before,
            "residual={residual}"
        );
        assert_no_key_writes(&fixture.keys);
    }
}

#[test]
fn marker_missing_requires_strict_terminal_state_and_exact_plan() {
    for (case_index, case) in [
        "plist",
        "current",
        "runtime",
        "machine-key",
        "storage-kek",
        "extra-version",
        "helper-changed",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("term-{case_index}"));
        fixture.prepare();
        let stopped = fixture.stopped();
        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .expect("reach marker-missing terminal layout");
        drop(stopped);
        match case {
            "plist" => write_mode(&fixture.plist, b"residual", 0o600),
            "current" => symlink(
                VERSION,
                fixture.paths.data_dir.join("bin").join(CURRENT_BASENAME),
            )
            .unwrap(),
            "runtime" => write_mode(&fixture.paths.runtime_db, b"residual", 0o600),
            "machine-key" => fixture.keys.insert(MACHINE_DATA_SIGN_ACCOUNT, b"residual"),
            "storage-kek" => fixture.keys.insert(STORAGE_KEK_ACCOUNT, b"residual"),
            "extra-version" => {
                let extra = fixture.paths.data_dir.join("bin/9.9.9");
                fs::create_dir(&extra).unwrap();
                set_mode(&extra, 0o700);
                write_mode(&extra.join(DAEMON_BASENAME), b"residual", 0o500);
            }
            "helper-changed" => {
                fs::remove_file(&fixture.helper).unwrap();
                write_mode(&fixture.helper, b"changed helper", 0o500);
            }
            _ => unreachable!(),
        }
        fixture.keys.clear_operations();
        let disk_before = disk_snapshot(&fixture._root.0);
        let keys_before = fixture.keys.values_snapshot();
        let stopped = fixture.stopped();
        let error = run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .expect_err("protected residual must reject marker-missing completion");
        assert_ne!(error.code(), "daemon.purge.marker_missing");
        assert!(fixture.keys.deletes().is_empty());
        drop(stopped);
        assert_eq!(disk_snapshot(&fixture._root.0), disk_before, "case={case}");
        assert_eq!(fixture.keys.values_snapshot(), keys_before, "case={case}");
        assert_no_key_writes(&fixture.keys);
    }

    let fixture = Fixture::new("terminal-wrong-plan");
    fixture.prepare();
    let stopped = fixture.stopped();
    run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
    )
    .unwrap();
    drop(stopped);
    let mut wrong_plan = fixture.plan_id();
    wrong_plan[0] ^= 0xff;
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();
    let stopped = fixture.stopped();
    assert_eq!(
        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            wrong_plan,
        )
        .unwrap_err()
        .code(),
        "daemon.purge.plan_mismatch"
    );
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn conflicting_plan_and_wrong_running_identity_are_zero_mutation() {
    let fixture = Fixture::new("plan-conflict");
    fixture.prepare();
    let baseline = fixture.keys.operations();
    let conflicting = UninstallPurgePlanV1::new(
        fixture.helper.clone(),
        VERSION.to_owned(),
        ArtifactSha256::new("aa".repeat(32)).unwrap(),
        TEAM.to_owned(),
        ACCESS_GROUP.to_owned(),
    )
    .unwrap();
    let error = prepare_purge_marker(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        PurgeMarkerRequest::Uninstall {
            authorization: fixture.authorization(),
            plan: &conflicting,
        },
    )
    .expect_err("different attestation conflicts");
    assert_eq!(error.code(), "daemon.purge.marker_conflict");
    assert_no_deletes_since(&fixture.keys, &baseline);

    let mut wrong_plan_id = fixture.plan_id();
    wrong_plan_id[0] ^= 0xff;
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();
    let stopped = fixture.stopped();
    let baseline = fixture.keys.operations();
    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        wrong_plan_id,
    )
    .expect_err("wrong one-shot plan id");
    assert_eq!(error.code(), "daemon.purge.plan_mismatch");
    assert_no_deletes_since(&fixture.keys, &baseline);
    assert!(fixture.plist.exists());
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);

    let wrong_identity = RunningFinalizerIdentity::injected_for_test(
        fixture.helper.clone(),
        VERSION.to_owned(),
        TEAM.to_owned(),
        "OTHERTEAM.com.agentdeck.agentdeckd.stable".to_owned(),
    )
    .unwrap();
    let stopped = fixture.stopped();
    let baseline = fixture.keys.operations();
    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &wrong_identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("wrong entitlement identity");
    assert_eq!(error.code(), "daemon.purge.plan_mismatch");
    assert_no_deletes_since(&fixture.keys, &baseline);
    assert!(fixture.plist.exists());
}

#[test]
fn bin_root_replacement_and_runtime_symlink_fail_before_any_deletion() {
    let fixture = Fixture::new("replacement");
    fixture.prepare();
    let original_bin = fixture.paths.data_dir.join("bin-original");
    fs::rename(fixture.paths.data_dir.join("bin"), &original_bin).expect("move original bin");
    let replacement_bin = fixture.paths.data_dir.join("bin");
    fs::create_dir(&replacement_bin).expect("replacement bin");
    set_mode(&replacement_bin, 0o700);
    let version = replacement_bin.join(VERSION);
    fs::create_dir(&version).expect("replacement version");
    set_mode(&version, 0o700);
    write_mode(&version.join(DAEMON_BASENAME), HELPER_BYTES, 0o500);
    symlink(VERSION, replacement_bin.join(CURRENT_BASENAME)).expect("replacement current");
    let identity = RunningFinalizerIdentity::injected_for_test(
        version.join(DAEMON_BASENAME),
        VERSION.to_owned(),
        TEAM.to_owned(),
        ACCESS_GROUP.to_owned(),
    )
    .unwrap();
    fixture.keys.clear_operations();
    let stopped = fixture.stopped();
    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("bin inode replacement");
    assert_eq!(error.code(), "daemon.purge.filesystem_unsafe");
    assert!(fixture.keys.deletes().is_empty());
    assert!(fixture.plist.exists());

    drop(stopped);
    fs::remove_dir_all(&replacement_bin).expect("remove replacement");
    fs::rename(&original_bin, fixture.paths.data_dir.join("bin")).expect("restore bin");
    fs::remove_file(&fixture.paths.runtime_db).expect("remove db");
    let target = fixture.paths.data_dir.join("outside.db");
    write_mode(&target, b"outside", 0o600);
    symlink(&target, &fixture.paths.runtime_db).expect("db symlink");
    fixture.keys.clear_operations();
    let stopped = fixture.stopped();
    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("runtime symlink");
    assert_eq!(error.code(), "daemon.purge.filesystem_unsafe");
    assert!(fixture.keys.deletes().is_empty());
    assert!(fixture.plist.exists());
    assert!(fixture.old_directory.exists());
}

#[test]
fn offline_extra_child_in_any_version_rejects_before_first_deletion() {
    for (index, version_directory) in [OLD_VERSION, VERSION].into_iter().enumerate() {
        let fixture = Fixture::new(&format!("version-child-{index}"));
        fixture.prepare();
        let residual = fixture
            .paths
            .data_dir
            .join("bin")
            .join(version_directory)
            .join("offline-residual");
        write_mode(&residual, b"offline tamper", 0o600);
        fixture.keys.clear_operations();
        let disk_before = disk_snapshot(&fixture._root.0);
        let keys_before = fixture.keys.values_snapshot();

        let stopped = fixture.stopped();
        let error = run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .expect_err("unexpected version child must fail closed");

        assert_eq!(error.code(), "daemon.purge.install_layout_invalid");
        assert!(fixture.plist.exists(), "plist must not be detached");
        assert!(fixture.old_directory.exists(), "old version must remain");
        assert!(fixture.helper.exists(), "retained helper must remain");
        assert!(
            residual.exists(),
            "unrecognized child must not be rewritten"
        );
        assert!(fixture.keys.deletes().is_empty());
        drop(stopped);
        assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
        assert_eq!(fixture.keys.values_snapshot(), keys_before);
        assert_no_key_writes(&fixture.keys);
    }
}

#[test]
fn offline_extra_child_after_phase_commit_blocks_next_deletion_without_rewrite() {
    let fixture = Fixture::new("phase-child");
    fixture.prepare();
    let stopped = fixture.stopped();
    let error = run_purge_finalizer_with_observer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
        &CrashOnce::new(PurgeFinalizerEvent::BeforePhase(
            PurgeFinalizerPhase::InstallDetached,
        )),
    )
    .expect_err("stop after install phase commit");
    assert_eq!(error.code(), "daemon.purge.injected_crash");
    drop(stopped);

    let residual = fixture.helper.parent().unwrap().join("offline-residual");
    write_mode(&residual, b"offline tamper", 0o600);
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();
    let stopped = fixture.stopped();

    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("retained version tamper must block runtime deletion");

    assert_eq!(error.code(), "daemon.purge.install_layout_invalid");
    assert!(fixture.paths.runtime_db.exists());
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn restored_completed_prefix_is_rejected_before_next_phase_deletion() {
    for (index, phase) in [
        PurgeFinalizerPhase::InstallDetached,
        PurgeFinalizerPhase::RuntimeRemoved,
        PurgeFinalizerPhase::MachineSecretsRemoved,
        PurgeFinalizerPhase::StorageKekRemoved,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("prefix-{index}"));
        fixture.prepare();
        let stopped = fixture.stopped();
        let error = run_purge_finalizer_with_observer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
            &CrashOnce::new(PurgeFinalizerEvent::BeforePhase(phase)),
        )
        .expect_err("stop immediately after the previous phase commit");
        assert_eq!(error.code(), "daemon.purge.injected_crash");
        drop(stopped);

        match phase {
            PurgeFinalizerPhase::InstallDetached => {
                write_mode(&fixture.plist, b"offline restored plist", 0o600);
            }
            PurgeFinalizerPhase::RuntimeRemoved => {
                write_mode(
                    &fixture.paths.runtime_db,
                    b"offline restored runtime",
                    0o600,
                );
            }
            PurgeFinalizerPhase::CounterGuardsRemoved => unreachable!(),
            PurgeFinalizerPhase::MachineSecretsRemoved => {
                fixture
                    .keys
                    .insert(MACHINE_DATA_SIGN_ACCOUNT, b"offline restored machine key");
            }
            PurgeFinalizerPhase::StorageKekRemoved => {
                fixture
                    .keys
                    .insert(STORAGE_KEK_ACCOUNT, b"offline restored storage kek");
            }
            PurgeFinalizerPhase::Prepared => unreachable!(),
        }
        fixture.keys.clear_operations();
        let disk_before = disk_snapshot(&fixture._root.0);
        let keys_before = fixture.keys.values_snapshot();
        let stopped = fixture.stopped();

        run_purge_finalizer(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            &stopped,
            fixture.plan_id(),
        )
        .expect_err("restored completed prefix must fail closed");

        match phase {
            PurgeFinalizerPhase::InstallDetached => {
                assert!(fixture.paths.runtime_db.exists());
            }
            PurgeFinalizerPhase::RuntimeRemoved => {
                assert!(fixture.keys.contains(MACHINE_ROOT_SIGN_ACCOUNT));
            }
            PurgeFinalizerPhase::CounterGuardsRemoved => unreachable!(),
            PurgeFinalizerPhase::MachineSecretsRemoved => {
                assert!(fixture.keys.contains(STORAGE_KEK_ACCOUNT));
            }
            PurgeFinalizerPhase::StorageKekRemoved => {
                assert!(fixture.keys.contains(PURGE_FINALIZER_MARKER_ACCOUNT));
            }
            PurgeFinalizerPhase::Prepared => unreachable!(),
        }
        drop(stopped);
        assert_eq!(
            disk_snapshot(&fixture._root.0),
            disk_before,
            "phase={phase:?}"
        );
        assert_eq!(
            fixture.keys.values_snapshot(),
            keys_before,
            "phase={phase:?}"
        );
        assert_no_key_writes(&fixture.keys);
    }
}

#[test]
fn exact_frozen_prefix_replays_after_phase_marker_outlives_filesystem_deletion() {
    for (index, phase) in [
        PurgeFinalizerPhase::InstallDetached,
        PurgeFinalizerPhase::RuntimeRemoved,
        PurgeFinalizerPhase::MachineSecretsRemoved,
        PurgeFinalizerPhase::StorageKekRemoved,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("rollback-{index}"));
        fixture.prepare();
        let mut marker = load_marker(&fixture.keys)
            .expect("load frozen marker")
            .expect("marker exists");
        marker.phase = phase;
        store_marker_exact(&fixture.keys, &marker).expect("commit simulated advanced phase");
        let stopped = fixture.stopped();

        assert_eq!(
            run_purge_finalizer(
                &fixture.keys,
                &fixture.paths,
                &fixture.identity,
                &stopped,
                fixture.plan_id(),
            )
            .unwrap_or_else(|error| panic!("exact rollback replay {phase:?}: {error:?}")),
            PurgeFinalizerOutcome::Completed
        );

        assert!(!fixture.plist.exists());
        assert!(!fixture.old_directory.exists());
        assert!(!fixture.paths.runtime_db.exists());
        assert!(
            machine_accounts()
                .iter()
                .all(|account| !fixture.keys.contains(account))
        );
        assert!(!fixture.keys.contains(STORAGE_KEK_ACCOUNT));
        assert!(!fixture.keys.contains(PURGE_FINALIZER_MARKER_ACCOUNT));
    }
}

#[test]
fn offline_helper_replacement_rejects_before_first_deletion_without_rewrite() {
    let fixture = Fixture::new("helper-offline");
    fixture.prepare();
    fs::remove_file(&fixture.helper).expect("remove frozen helper");
    write_mode(&fixture.helper, b"offline replacement", 0o500);
    let replacement_identity = RunningFinalizerIdentity::injected_for_test(
        fixture.helper.clone(),
        VERSION.to_owned(),
        TEAM.to_owned(),
        ACCESS_GROUP.to_owned(),
    )
    .expect("replacement identity");
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();

    let stopped = fixture.stopped();
    let error = run_purge_finalizer(
        &fixture.keys,
        &fixture.paths,
        &replacement_identity,
        &stopped,
        fixture.plan_id(),
    )
    .expect_err("replacement helper must fail closed");

    assert_eq!(error.code(), "daemon.purge.helper_mismatch");
    drop(stopped);
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn resume_reserved_marker_is_absent_authorized_or_exact_replay() {
    let absent = Fixture::new("resume-absent");
    absent.keys.clear_operations();
    let disk_before = disk_snapshot(&absent._root.0);
    let keys_before = absent.keys.values_snapshot();
    assert_eq!(
        resume_reserved_purge_marker(
            &absent.keys,
            &absent.paths,
            &absent.identity,
            absent.authorization(),
        )
        .expect("absent marker is ordinary reset"),
        ResumeReservedPurgeMarkerOutcome::Absent
    );
    assert_eq!(disk_snapshot(&absent._root.0), disk_before);
    assert_eq!(absent.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&absent.keys);

    let fixture = Fixture::new("resume-auth");
    fixture.reserve();
    fixture.keys.clear_operations();
    assert_eq!(
        resume_reserved_purge_marker(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            fixture.authorization(),
        )
        .expect("reserved marker authorizes"),
        ResumeReservedPurgeMarkerOutcome::Authorized {
            phase: PurgeFinalizerPhase::Prepared,
        }
    );
    assert!(matches!(
        fixture.keys.operations().as_slice(),
        [.., KeyOperation::Store(account), KeyOperation::Load(readback)]
            if account == PURGE_FINALIZER_MARKER_ACCOUNT
                && readback == PURGE_FINALIZER_MARKER_ACCOUNT
    ));

    fixture.keys.clear_operations();
    let authorized_bytes = fixture.keys.values_snapshot();
    assert_eq!(
        resume_reserved_purge_marker(
            &fixture.keys,
            &fixture.paths,
            &fixture.identity,
            fixture.authorization(),
        )
        .expect("same authorization replays"),
        ResumeReservedPurgeMarkerOutcome::Replayed {
            phase: PurgeFinalizerPhase::Prepared,
        }
    );
    assert_eq!(fixture.keys.values_snapshot(), authorized_bytes);
    assert_no_key_writes(&fixture.keys);

    fixture.keys.clear_operations();
    let conflicting = AuthenticatedPurgeAuthorization {
        binding: PurgeAuthorizationBinding::Remote {
            database_id: fixture.database_id,
            relay_server_id: [0x12; 16],
            machine_route: [0x13; 16],
            root_key_id: [0x14; 16],
            root_fingerprint: [0x72; 32],
            trust_epoch: 7,
            reset_kind: 1,
            purge_proof_hash: [0x33; 32],
            cleanup_witness_hash: None,
        },
    };
    let error = resume_reserved_purge_marker(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        conflicting,
    )
    .expect_err("different authenticated state must conflict");
    assert_eq!(error.code(), "daemon.purge.marker_conflict");
    assert_eq!(fixture.keys.values_snapshot(), authorized_bytes);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn resume_reserved_marker_rejects_offline_layout_tamper_without_authorizing() {
    let fixture = Fixture::new("resume-tamper");
    fixture.reserve();
    write_mode(
        &fixture.old_directory.join("offline-residual"),
        b"tamper",
        0o600,
    );
    fixture.keys.clear_operations();
    let disk_before = disk_snapshot(&fixture._root.0);
    let keys_before = fixture.keys.values_snapshot();

    let error = resume_reserved_purge_marker(
        &fixture.keys,
        &fixture.paths,
        &fixture.identity,
        fixture.authorization(),
    )
    .expect_err("tampered frozen layout must reject authorization");

    assert_eq!(error.code(), "daemon.purge.install_layout_invalid");
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);
    assert_eq!(fixture.keys.values_snapshot(), keys_before);
    assert_no_key_writes(&fixture.keys);
}

#[test]
fn stopped_permit_never_creates_or_hardens_existing_only_substrate() {
    let fixture = Fixture::new("eo-lock");
    fs::remove_file(&fixture.paths.lock).expect("remove singleton lock");
    let disk_before = disk_snapshot(&fixture._root.0);
    PurgeStoppedPermit::acquire(&fixture.paths).expect_err("missing lock must reject");
    assert!(!fixture.paths.lock.exists(), "permit must not create lock");
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);

    let fixture = Fixture::new("eo-mode");
    set_mode(&fixture.paths.data_dir, 0o755);
    let disk_before = disk_snapshot(&fixture._root.0);
    PurgeStoppedPermit::acquire(&fixture.paths).expect_err("legacy mode must reject");
    assert_eq!(
        fs::symlink_metadata(&fixture.paths.data_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755,
        "permit must not fchmod the data directory"
    );
    assert_eq!(disk_snapshot(&fixture._root.0), disk_before);

    let root = TestRoot::new("eo-dir");
    let home = root.0.join("home");
    fs::create_dir(&home).expect("home");
    set_mode(&home, 0o700);
    let paths = DaemonPaths::stable(&home, Some(ACCESS_GROUP.to_owned())).expect("paths");
    let disk_before = disk_snapshot(&root.0);
    PurgeStoppedPermit::acquire(&paths).expect_err("missing data directory must reject");
    assert!(
        !paths.data_dir.exists(),
        "permit must not create data directory"
    );
    assert_eq!(disk_snapshot(&root.0), disk_before);
}

#[test]
fn socket_absent_does_not_bypass_busy_singleton_and_present_socket_blocks_permit() {
    let fixture = Fixture::new("singleton-busy");
    fixture.prepare();
    fixture.keys.clear_operations();
    let guard = SingletonGuard::acquire(&fixture.paths).expect("hold daemon singleton");
    let error = PurgeStoppedPermit::acquire(&fixture.paths).expect_err("lock busy");
    assert_eq!(error.code(), "daemon.singleton.already_running");
    assert!(fixture.keys.deletes().is_empty());
    drop(guard);

    write_mode(&fixture.paths.socket, b"occupied", 0o600);
    let error = PurgeStoppedPermit::acquire(&fixture.paths).expect_err("socket still present");
    assert_eq!(error.code(), "daemon.purge.daemon_still_running");
    assert!(fixture.keys.deletes().is_empty());
}
