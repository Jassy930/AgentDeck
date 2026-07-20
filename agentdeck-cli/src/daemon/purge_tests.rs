use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::{MachineRouteId, RelayServerId};
use agentdeck_protocol::runtime::{
    MachineRemoteFailureCode, MachineRemoteStatus, MachineRootFingerprint,
};

use super::*;
use crate::daemon::launchd::{LaunchAgentReadback, LaunchctlRunner, LifecycleError};

const VERSION: &str = "1.2.3";
const TEAM: &str = "TEAM123";
const ACCESS_GROUP: &str = "TEAM123.com.agentdeck.agentdeckd.stable";
const HELPER_BYTES: &[u8] = b"signed helper";

static NEXT_ROOT: AtomicUsize = AtomicUsize::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-cli-purge-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("root");
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
    paths: DaemonInstallPaths,
    helper: PathBuf,
    recovery_helper: PathBuf,
    runtime_db: PathBuf,
    artifact: InstalledArtifact,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = TestRoot::new(label);
        let home = root.0.join("home");
        fs::create_dir(&home).expect("home");
        set_mode(&home, 0o700);
        let paths = DaemonInstallPaths::injected_for_test(home).expect("paths");
        fs::create_dir_all(paths.data_root()).expect("data root");
        set_mode(paths.data_root(), 0o700);
        fs::create_dir(paths.bin_root()).expect("bin root");
        set_mode(paths.bin_root(), 0o700);
        let version = paths.version_directory(VERSION);
        fs::create_dir(&version).expect("version");
        set_mode(&version, 0o700);
        let helper = paths.version_daemon(VERSION);
        write_mode(&helper, HELPER_BYTES, 0o500);
        let recovery_helper = root.0.join("external-bundle-agentdeckd");
        write_mode(&recovery_helper, HELPER_BYTES, 0o500);
        symlink(VERSION, paths.current_link()).expect("current");
        fs::create_dir_all(paths.plist().parent().expect("plist parent")).expect("LaunchAgents");
        write_mode(paths.plist(), b"plist", 0o600);
        let runtime_db = paths.data_root().join("runtime.db");
        write_mode(&runtime_db, b"runtime", 0o600);
        let artifact = InstalledArtifact {
            path: helper.clone(),
            version: VERSION.to_owned(),
            protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
            sha256: sha256(HELPER_BYTES),
            team_identifier: TEAM.to_owned(),
            keychain_access_group: ACCESS_GROUP.to_owned(),
        };
        Self {
            _root: root,
            paths,
            helper,
            recovery_helper,
            runtime_db,
            artifact,
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("write");
    set_mode(path, mode);
}

#[derive(Clone)]
struct FakeLaunchctl {
    state: Arc<Mutex<LaunchState>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

struct LaunchState {
    loaded: bool,
    readback: LaunchAgentReadback,
    keep_loaded_after_bootout: bool,
}

impl FakeLaunchctl {
    fn new(paths: &DaemonInstallPaths, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(LaunchState {
                loaded: true,
                readback: LaunchAgentReadback {
                    pid: Some(42),
                    program: paths.current_daemon(),
                    plist: paths.plist().to_path_buf(),
                },
                keep_loaded_after_bootout: false,
            })),
            events,
        }
    }
}

impl LaunchctlRunner for FakeLaunchctl {
    fn readback(&self, _uid: u32) -> Result<Option<LaunchAgentReadback>, LifecycleError> {
        self.events.lock().unwrap().push("launchctl.readback");
        let state = self.state.lock().unwrap();
        Ok(state.loaded.then(|| state.readback.clone()))
    }

    fn bootstrap(&self, _uid: u32, _plist: &Path) -> Result<(), LifecycleError> {
        unreachable!()
    }

    fn kickstart(&self, _uid: u32) -> Result<(), LifecycleError> {
        unreachable!()
    }

    fn bootout(&self, _uid: u32) -> Result<(), LifecycleError> {
        self.events.lock().unwrap().push("launchctl.bootout");
        let mut state = self.state.lock().unwrap();
        if !state.keep_loaded_after_bootout {
            state.loaded = false;
        }
        Ok(())
    }
}

struct FakeArtifacts {
    artifact: InstalledArtifact,
    recovery_helper: PathBuf,
    calls: AtomicUsize,
    recovery_calls: AtomicUsize,
    fail_at: Option<usize>,
    changed_at: Option<usize>,
    recovery_changed_at: Option<usize>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl PurgeArtifactVerifier for FakeArtifacts {
    fn verify_existing(&self, path: &Path) -> Result<InstalledArtifact, PurgeCliError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.events.lock().unwrap().push("artifact.verify");
        if self.fail_at == Some(call) {
            return Err(PurgeCliError::Artifact(InstallError::SignatureRejected));
        }
        let mut artifact = self.artifact.clone();
        artifact.path = path.to_path_buf();
        if self.changed_at == Some(call) {
            artifact.sha256[0] ^= 1;
        }
        Ok(artifact)
    }

    fn verify_bundled_recovery_source(&self) -> Result<InstalledArtifact, PurgeCliError> {
        let call = self.recovery_calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.events.lock().unwrap().push("artifact.recovery.verify");
        let mut artifact = self.artifact.clone();
        artifact.path = self.recovery_helper.clone();
        if self.recovery_changed_at == Some(call) {
            artifact.sha256[0] ^= 1;
        }
        Ok(artifact)
    }
}

struct FakeRuntime {
    mismatch: bool,
    fail: bool,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl PurgeRuntimeClient for FakeRuntime {
    async fn trust_reset_for_uninstall(
        &self,
        plan: UninstallPurgePlanV1,
    ) -> Result<PurgeRuntimeReadback, PurgeCliError> {
        self.events.lock().unwrap().push("runtime.trust_reset");
        if self.fail {
            return Err(PurgeCliError::runtime(
                "daemon.purge.marker_reservation_failed",
            ));
        }
        Ok(PurgeRuntimeReadback {
            purge_ready: true,
            marker_prepared: !self.mismatch,
            marker_plan_id: *plan.plan_id(),
        })
    }
}

struct FakeSockets {
    absent: bool,
    unsafe_entry: bool,
    events: Arc<Mutex<Vec<&'static str>>>,
}

struct FakeProcesses {
    absent: bool,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl PurgeProcessProbe for FakeProcesses {
    fn is_absent(&self, _pid: u32) -> Result<bool, PurgeCliError> {
        self.events.lock().unwrap().push("pid.readback");
        Ok(self.absent)
    }
}

impl PurgeSocketProbe for FakeSockets {
    fn is_absent(&self, _path: &Path) -> Result<bool, PurgeCliError> {
        self.events.lock().unwrap().push("socket.readback");
        if self.unsafe_entry {
            return Err(PurgeCliError::SocketUnsafe);
        }
        Ok(self.absent)
    }
}

struct FakeHelper {
    paths: DaemonInstallPaths,
    runtime_db: PathBuf,
    recovery_helper: PathBuf,
    fail_after_marker: bool,
    terminal_proof_fails: bool,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl PurgeHelperRunner for FakeHelper {
    async fn run(
        &self,
        helper: &Path,
        plan: &UninstallPurgePlanV1,
    ) -> Result<PurgeHelperCompletion, PurgeCliError> {
        self.events.lock().unwrap().push("helper.run");
        assert!(helper.exists(), "exact helper remains during finalizer");
        assert_eq!(
            plan.helper_path(),
            self.paths.version_daemon(VERSION),
            "flat anchor execution must retain the original versioned plan identity"
        );
        let _ = fs::remove_file(self.paths.plist());
        let _ = fs::remove_file(self.paths.current_link());
        let _ = fs::remove_file(&self.runtime_db);
        if self.fail_after_marker {
            return Err(PurgeCliError::HelperFailed);
        }
        Ok(PurgeHelperCompletion::MarkerDeleted)
    }

    async fn prove_terminal(
        &self,
        helper: &Path,
    ) -> Result<PurgeTerminalProofCompletion, PurgeCliError> {
        self.events.lock().unwrap().push("helper.prove_terminal");
        assert_eq!(helper, self.recovery_helper);
        if self.terminal_proof_fails {
            return Err(PurgeCliError::HelperFailed);
        }
        Ok(PurgeTerminalProofCompletion::Proven)
    }
}

fn coordinator<'a>(
    fixture: &'a Fixture,
    launchctl: &'a FakeLaunchctl,
    artifacts: &'a FakeArtifacts,
    runtime: &'a FakeRuntime,
    sockets: &'a FakeSockets,
    processes: &'a FakeProcesses,
    helper: &'a FakeHelper,
) -> PurgeCoordinator<
    'a,
    FakeLaunchctl,
    FakeArtifacts,
    FakeRuntime,
    FakeSockets,
    FakeProcesses,
    FakeHelper,
> {
    PurgeCoordinator::new(
        &fixture.paths,
        launchctl,
        artifacts,
        runtime,
        sockets,
        processes,
        helper,
    )
}

type PurgeFakes = (
    Arc<Mutex<Vec<&'static str>>>,
    FakeLaunchctl,
    FakeArtifacts,
    FakeRuntime,
    FakeSockets,
    FakeProcesses,
    FakeHelper,
);

fn fakes(fixture: &Fixture) -> PurgeFakes {
    let events = Arc::new(Mutex::new(Vec::new()));
    (
        Arc::clone(&events),
        FakeLaunchctl::new(&fixture.paths, Arc::clone(&events)),
        FakeArtifacts {
            artifact: fixture.artifact.clone(),
            recovery_helper: fixture.recovery_helper.clone(),
            calls: AtomicUsize::new(0),
            recovery_calls: AtomicUsize::new(0),
            fail_at: None,
            changed_at: None,
            recovery_changed_at: None,
            events: Arc::clone(&events),
        },
        FakeRuntime {
            mismatch: false,
            fail: false,
            events: Arc::clone(&events),
        },
        FakeSockets {
            absent: true,
            unsafe_entry: false,
            events: Arc::clone(&events),
        },
        FakeProcesses {
            absent: true,
            events: Arc::clone(&events),
        },
        FakeHelper {
            paths: fixture.paths.clone(),
            runtime_db: fixture.runtime_db.clone(),
            recovery_helper: fixture.recovery_helper.clone(),
            fail_after_marker: false,
            terminal_proof_fails: false,
            events,
        },
    )
}

#[tokio::test]
async fn stopped_recovery_with_exact_current_skips_runtime_and_bootout() {
    let fixture = Fixture::new("stopped-current");
    let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;
    coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect("public stopped recovery");
    let events = events.lock().unwrap();
    assert!(!events.contains(&"runtime.trust_reset"));
    assert!(!events.contains(&"launchctl.bootout"));
    assert!(events.contains(&"helper.run"));
    assert!(!fixture.paths.bin_root().exists());
}

#[tokio::test]
async fn stopped_recovery_current_wrong_target_fails_before_helper() {
    let fixture = Fixture::new("stopped-wrong-current");
    fs::remove_file(fixture.paths.current_link()).unwrap();
    symlink("wrong-version", fixture.paths.current_link()).unwrap();
    let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;
    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("wrong current target");
    assert!(matches!(
        error,
        PurgeCliError::HelperUnsafe | PurgeCliError::Io(_)
    ));
    assert!(!events.lock().unwrap().contains(&"helper.run"));
    assert!(fixture.runtime_db.exists());
}

#[tokio::test]
async fn preexisting_anchor_conflicts_fail_before_runtime_or_helper() {
    for case in ["live-current-anchor", "stopped-current-anchor"] {
        let fixture = Fixture::new(case);
        write_mode(&fixture.paths.purge_retained_helper(), HELPER_BYTES, 0o500);
        let runtime_before = fs::read(&fixture.runtime_db).unwrap();
        let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
        if case == "stopped-current-anchor" {
            launchctl.state.lock().unwrap().loaded = false;
        }

        let error = coordinator(
            &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
        )
        .run()
        .await
        .expect_err("current plus flat anchor is ambiguous");

        assert_eq!(error.code(), "daemon.purge.stopped_recovery_unsafe");
        assert_eq!(artifacts.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&fixture.runtime_db).unwrap(), runtime_before);
        let events = events.lock().unwrap();
        assert!(!events.contains(&"runtime.trust_reset"));
        assert!(!events.contains(&"helper.run"));
    }
}

#[tokio::test]
async fn stopped_anchor_rejects_original_helper_or_unknown_bin_residue_before_helper() {
    for case in ["anchor-original-helper", "anchor-unknown-residue"] {
        let fixture = Fixture::new(case);
        fs::remove_file(fixture.paths.current_link()).unwrap();
        fs::remove_file(fixture.paths.plist()).unwrap();
        write_mode(&fixture.paths.purge_retained_helper(), HELPER_BYTES, 0o500);
        if case == "anchor-unknown-residue" {
            fs::remove_file(&fixture.helper).unwrap();
            fs::remove_dir(fixture.paths.version_directory(VERSION)).unwrap();
            write_mode(&fixture.paths.bin_root().join("unknown"), b"unknown", 0o600);
        }
        let runtime_before = fs::read(&fixture.runtime_db).unwrap();
        let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
        launchctl.state.lock().unwrap().loaded = false;

        let error = coordinator(
            &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
        )
        .run()
        .await
        .expect_err("anchor plus non-empty or unknown bin residue is ambiguous");

        assert_eq!(error.code(), "daemon.purge.stopped_recovery_unsafe");
        assert_eq!(artifacts.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(&fixture.runtime_db).unwrap(), runtime_before);
        let events = events.lock().unwrap();
        assert!(!events.contains(&"runtime.trust_reset"));
        assert!(!events.contains(&"helper.run"));
    }
}

#[tokio::test]
async fn stopped_recovery_without_current_requires_one_retained_helper_and_no_plist() {
    let fixture = Fixture::new("stopped-single-helper");
    fs::remove_file(fixture.paths.current_link()).unwrap();
    fs::remove_file(fixture.paths.plist()).unwrap();
    let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;
    coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect("single retained helper recovery");
    assert!(!events.lock().unwrap().contains(&"runtime.trust_reset"));

    let fixture = Fixture::new("stopped-multiple-helpers");
    fs::remove_file(fixture.paths.current_link()).unwrap();
    fs::remove_file(fixture.paths.plist()).unwrap();
    let extra = fixture.paths.version_directory("9.9.9");
    fs::create_dir(&extra).unwrap();
    set_mode(&extra, 0o700);
    write_mode(&extra.join("agentdeckd"), b"extra", 0o500);
    let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;
    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("ambiguous stopped recovery");
    assert_eq!(error.code(), "daemon.purge.stopped_recovery_unsafe");
    assert!(!events.lock().unwrap().contains(&"helper.run"));
}

#[test]
fn production_runtime_adapter_requires_purge_readback_absent_and_preserves_failure_code() {
    let fixture = Fixture::new("runtime-adapter");
    let plan = UninstallPurgePlanV1::new(
        fixture.helper.clone(),
        VERSION.to_owned(),
        ArtifactSha256::new(hex(&fixture.artifact.sha256)).unwrap(),
        TEAM.to_owned(),
        ACCESS_GROUP.to_owned(),
    )
    .unwrap();
    let purge_ready = MachineRemoteStatus::new(
        MachineRemoteLifecycle::PurgeReadbackAbsent,
        Some(RelayServerId::from_bytes([1; 16])),
        Some(MachineRouteId::from_bytes([2; 16])),
        Some(MachineRootFingerprint::from_bytes([3; 32])),
        Some(1),
        None,
    )
    .unwrap();
    let readback = decode_runtime_readback(
        &plan,
        ReplySequenceItem::Reply(Box::new(RuntimeReply::MachineRemoteStatus(purge_ready))),
    )
    .unwrap();
    assert!(readback.purge_ready);
    assert!(readback.marker_prepared);
    assert_eq!(readback.marker_plan_id, *plan.plan_id());

    let local_deleted = MachineRemoteStatus::new(
        MachineRemoteLifecycle::LocalDeleted,
        Some(RelayServerId::from_bytes([1; 16])),
        Some(MachineRouteId::from_bytes([2; 16])),
        Some(MachineRootFingerprint::from_bytes([3; 32])),
        Some(1),
        None,
    )
    .unwrap();
    let readback = decode_runtime_readback(
        &plan,
        ReplySequenceItem::Reply(Box::new(RuntimeReply::MachineRemoteStatus(local_deleted))),
    )
    .expect("successful uninstall request may return authenticated LocalDeleted late purge");
    assert!(readback.purge_ready);
    assert!(readback.marker_prepared);
    assert_eq!(readback.marker_plan_id, *plan.plan_id());

    let unenrolled = MachineRemoteStatus::new(
        MachineRemoteLifecycle::Unenrolled,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let readback = decode_runtime_readback(
        &plan,
        ReplySequenceItem::Reply(Box::new(RuntimeReply::MachineRemoteStatus(unenrolled))),
    )
    .expect("successful uninstall request may authorize an unenrolled local identity");
    assert!(readback.purge_ready);
    assert!(readback.marker_prepared);
    assert_eq!(readback.marker_plan_id, *plan.plan_id());

    let failure =
        MachineRemoteFailureCode::new("daemon.remote.trust_reset.admin_receipt_required").unwrap();
    let blocked = MachineRemoteStatus::new(
        MachineRemoteLifecycle::Blocked,
        None,
        None,
        None,
        None,
        Some(failure),
    )
    .unwrap();
    let error = decode_runtime_readback(
        &plan,
        ReplySequenceItem::Reply(Box::new(RuntimeReply::MachineRemoteStatus(blocked))),
    )
    .expect_err("blocked status must not authorize bootout");
    assert_eq!(
        error.code(),
        "daemon.remote.trust_reset.admin_receipt_required"
    );
}

#[tokio::test]
async fn two_phase_purge_orders_readbacks_helper_and_exact_cleanup() {
    let fixture = Fixture::new("happy");
    let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect("purge");
    assert!(!fixture.paths.bin_root().exists());
    assert!(!fixture.paths.plist().exists());
    assert!(!fixture.runtime_db.exists());
    assert_eq!(artifacts.calls.load(Ordering::SeqCst), 4);
    let events = events.lock().unwrap();
    let runtime_index = events
        .iter()
        .position(|event| *event == "runtime.trust_reset")
        .unwrap();
    let bootout_index = events
        .iter()
        .position(|event| *event == "launchctl.bootout")
        .unwrap();
    let helper_index = events
        .iter()
        .position(|event| *event == "helper.run")
        .unwrap();
    assert!(runtime_index < bootout_index && bootout_index < helper_index);
}

#[tokio::test]
async fn signature_pid_path_and_helper_symlink_fail_before_runtime_or_bootout() {
    for case in ["signature", "pid", "path", "symlink"] {
        let fixture = Fixture::new(case);
        let (events, launchctl, mut artifacts, runtime, sockets, processes, helper) =
            fakes(&fixture);
        match case {
            "signature" => artifacts.fail_at = Some(1),
            "pid" => launchctl.state.lock().unwrap().readback.pid = None,
            "path" => {
                launchctl.state.lock().unwrap().readback.program = PathBuf::from("/wrong/helper")
            }
            "symlink" => {
                fs::remove_file(&fixture.helper).unwrap();
                let target = fixture.paths.data_root().join("target-helper");
                write_mode(&target, HELPER_BYTES, 0o500);
                symlink(&target, &fixture.helper).unwrap();
            }
            _ => unreachable!(),
        }
        let error = coordinator(
            &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
        )
        .run()
        .await
        .expect_err("preflight rejection");
        assert!(!matches!(error, PurgeCliError::RuntimeReadbackMismatch));
        let events = events.lock().unwrap();
        assert!(!events.contains(&"runtime.trust_reset"));
        assert!(!events.contains(&"launchctl.bootout"));
        assert!(!events.contains(&"helper.run"));
        assert!(fixture.paths.plist().exists());
    }
}

#[tokio::test]
async fn runtime_marker_mismatch_blocks_bootout_and_helper() {
    let fixture = Fixture::new("runtime-mismatch");
    let (events, launchctl, artifacts, mut runtime, sockets, processes, helper) = fakes(&fixture);
    runtime.mismatch = true;
    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("marker mismatch");
    assert_eq!(error.code(), "daemon.purge.runtime_readback_mismatch");
    let events = events.lock().unwrap();
    assert!(!events.contains(&"launchctl.bootout"));
    assert!(!events.contains(&"helper.run"));
}

#[tokio::test]
async fn runtime_reservation_failure_performs_no_stop_or_helper_action() {
    let fixture = Fixture::new("reservation-failure");
    let (events, launchctl, artifacts, mut runtime, sockets, processes, helper) = fakes(&fixture);
    runtime.fail = true;
    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("reservation failure");
    assert_eq!(error.code(), "daemon.purge.marker_reservation_failed");
    let events = events.lock().unwrap();
    assert!(!events.contains(&"launchctl.bootout"));
    assert!(!events.contains(&"helper.run"));
    assert!(fixture.paths.plist().exists());
    assert!(fixture.paths.current_link().exists());
    assert!(fixture.runtime_db.exists());
}

#[tokio::test]
async fn crash_after_bootout_recovers_via_current_without_repeating_runtime() {
    let fixture = Fixture::new("bootout-recovery");
    let (events, launchctl, mut artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    artifacts.fail_at = Some(2);
    coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("crash boundary after bootout");
    assert!(!launchctl.state.lock().unwrap().loaded);
    assert!(fixture.paths.current_link().exists());

    coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect("stopped recovery through current");
    let events = events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == "runtime.trust_reset")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == "launchctl.bootout")
            .count(),
        1
    );
}

#[tokio::test]
async fn uds_or_attestation_change_after_bootout_blocks_helper_and_cleanup() {
    for case in ["uds", "attestation"] {
        let fixture = Fixture::new(case);
        let (events, launchctl, mut artifacts, runtime, mut sockets, processes, helper) =
            fakes(&fixture);
        if case == "uds" {
            sockets.unsafe_entry = true;
        } else {
            artifacts.changed_at = Some(2);
        }
        let _ = coordinator(
            &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
        )
        .run()
        .await
        .expect_err("post-bootout rejection");
        assert!(!events.lock().unwrap().contains(&"helper.run"));
        assert!(fixture.helper.exists());
        assert!(fixture.paths.bin_root().exists());
    }
}

#[tokio::test]
async fn launchd_absent_but_frozen_old_pid_alive_never_starts_helper() {
    let fixture = Fixture::new("old-pid-alive");
    let (events, launchctl, artifacts, runtime, sockets, mut processes, helper) = fakes(&fixture);
    processes.absent = false;
    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .with_stop_readback_attempts_for_test(1)
    .run()
    .await
    .expect_err("old PID still alive");
    assert_eq!(error.code(), "daemon.purge.daemon_still_running");
    let events = events.lock().unwrap();
    assert!(events.contains(&"pid.readback"));
    assert!(!events.contains(&"helper.run"));
    assert!(fixture.helper.exists());
}

#[tokio::test]
async fn marker_deleted_then_cli_crash_is_publicly_retryable_without_runtime() {
    let fixture = Fixture::new("cli-crash");
    let (events, launchctl, artifacts, runtime, sockets, processes, mut helper) = fakes(&fixture);
    helper.fail_after_marker = true;
    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("CLI observes uncertain exit after marker deletion");
    assert_eq!(error.code(), "daemon.purge.helper_failed");
    assert!(fixture.helper.exists());
    assert!(fixture.paths.bin_root().exists());
    helper.fail_after_marker = false;
    coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect("same public purge command resumes terminal proof");
    assert!(!fixture.paths.bin_root().exists());
    assert!(!fixture.paths.plist().exists());
    assert!(!fixture.paths.purge_retained_helper().exists());
    assert!(
        !fixture.runtime_db.exists(),
        "public retry never recreated Runtime data"
    );
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "runtime.trust_reset")
            .count(),
        1
    );
}

#[tokio::test]
async fn flat_anchor_crash_recovery_rebuilds_original_plan_and_cleans_anchor_last() {
    let fixture = Fixture::new("flat-anchor");
    fs::remove_file(fixture.paths.plist()).unwrap();
    fs::remove_file(fixture.paths.current_link()).unwrap();
    fs::remove_file(&fixture.runtime_db).unwrap();
    let original_identity = helper_identity(&fixture.helper).unwrap();
    let anchor = publish_purge_retained_helper(&fixture.paths, VERSION).unwrap();
    assert_eq!(helper_identity(&anchor).unwrap(), original_identity);
    let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;

    coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect("flat anchor resumes marker-absent terminal proof");

    let events = events.lock().unwrap();
    assert!(!events.contains(&"runtime.trust_reset"));
    assert!(events.contains(&"helper.run"));
    assert!(!fixture.paths.purge_retained_helper().exists());
    assert!(!fixture.paths.bin_root().exists());
}

#[tokio::test]
async fn absent_install_with_runtime_artifact_fails_closed_without_rewrite() {
    for suffix in ["", "-wal", "-shm"] {
        let fixture = Fixture::new(&format!("absent-install-runtime{suffix}"));
        fs::remove_file(fixture.paths.plist()).unwrap();
        fs::remove_file(fixture.paths.current_link()).unwrap();
        fs::remove_file(&fixture.helper).unwrap();
        fs::remove_dir(fixture.paths.version_directory(VERSION)).unwrap();
        fs::remove_dir(fixture.paths.bin_root()).unwrap();
        fs::remove_file(&fixture.runtime_db).unwrap();
        let artifact = PathBuf::from(format!("{}{}", fixture.runtime_db.display(), suffix));
        write_mode(&artifact, b"runtime-residue", 0o600);
        let before = fs::read(&artifact).unwrap();
        let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
        launchctl.state.lock().unwrap().loaded = false;

        let error = coordinator(
            &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
        )
        .run()
        .await
        .expect_err("visible Runtime residue cannot be reported as completed purge");

        assert_eq!(error.code(), "daemon.purge.stopped_recovery_unsafe");
        assert_eq!(fs::read(&artifact).unwrap(), before);
        assert_eq!(artifacts.calls.load(Ordering::SeqCst), 0);
        assert_eq!(artifacts.recovery_calls.load(Ordering::SeqCst), 0);
        let events = events.lock().unwrap();
        assert!(!events.contains(&"runtime.trust_reset"));
        assert!(!events.contains(&"helper.run"));
        assert!(!events.contains(&"helper.prove_terminal"));
    }
}

#[tokio::test]
async fn fully_absent_disk_requires_external_signed_helper_terminal_proof() {
    let fixture = Fixture::new("fully-absent");
    fs::remove_file(fixture.paths.plist()).unwrap();
    fs::remove_file(fixture.paths.current_link()).unwrap();
    fs::remove_file(&fixture.helper).unwrap();
    fs::remove_dir(fixture.paths.version_directory(VERSION)).unwrap();
    fs::remove_dir(fixture.paths.bin_root()).unwrap();
    fs::remove_file(&fixture.runtime_db).unwrap();
    let wal = fixture.paths.data_root().join("runtime.db-wal");
    let shm = fixture.paths.data_root().join("runtime.db-shm");
    assert!(!wal.exists() && !shm.exists());
    let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;
    let recovery_before = fs::read(&fixture.recovery_helper).unwrap();

    coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect("external signed helper proves Keychain terminal state");

    assert_eq!(artifacts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(artifacts.recovery_calls.load(Ordering::SeqCst), 2);
    assert_eq!(fs::read(&fixture.recovery_helper).unwrap(), recovery_before);
    let events = events.lock().unwrap();
    assert!(!events.contains(&"runtime.trust_reset"));
    assert!(!events.contains(&"helper.run"));
    assert!(events.contains(&"helper.prove_terminal"));
}

#[tokio::test]
async fn fully_absent_retry_requires_exact_data_root_durability_barrier() {
    let fixture = Fixture::new("fully-absent-data-root-sync");
    fs::remove_file(fixture.paths.plist()).unwrap();
    fs::remove_file(fixture.paths.current_link()).unwrap();
    fs::remove_file(&fixture.helper).unwrap();
    fs::remove_dir(fixture.paths.version_directory(VERSION)).unwrap();
    fs::remove_dir(fixture.paths.bin_root()).unwrap();
    fs::remove_file(&fixture.runtime_db).unwrap();
    set_mode(fixture.paths.data_root(), 0o755);
    let (events, launchctl, artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;

    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("terminal success requires an exact 0700 data-root fsync");

    assert_eq!(error.code(), "daemon.install.path_unsafe");
    assert_eq!(artifacts.recovery_calls.load(Ordering::SeqCst), 1);
    let events = events.lock().unwrap();
    assert!(events.contains(&"helper.prove_terminal"));
    assert!(!events.contains(&"runtime.trust_reset"));
}

#[tokio::test]
async fn fully_absent_disk_fails_closed_when_keychain_terminal_proof_fails() {
    let fixture = Fixture::new("fully-absent-proof-fails");
    fs::remove_file(fixture.paths.plist()).unwrap();
    fs::remove_file(fixture.paths.current_link()).unwrap();
    fs::remove_file(&fixture.helper).unwrap();
    fs::remove_dir(fixture.paths.version_directory(VERSION)).unwrap();
    fs::remove_dir(fixture.paths.bin_root()).unwrap();
    fs::remove_file(&fixture.runtime_db).unwrap();
    let recovery_before = fs::read(&fixture.recovery_helper).unwrap();
    let (events, launchctl, artifacts, runtime, sockets, processes, mut helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;
    helper.terminal_proof_fails = true;

    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("missing Keychain terminal proof must fail closed");

    assert_eq!(error.code(), "daemon.purge.helper_failed");
    assert_eq!(artifacts.recovery_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(&fixture.recovery_helper).unwrap(), recovery_before);
    let events = events.lock().unwrap();
    assert!(events.contains(&"helper.prove_terminal"));
    assert!(!events.contains(&"runtime.trust_reset"));
}

#[tokio::test]
async fn fully_absent_disk_rejects_recovery_helper_attestation_change_after_proof() {
    let fixture = Fixture::new("fully-absent-attestation-change");
    fs::remove_file(fixture.paths.plist()).unwrap();
    fs::remove_file(fixture.paths.current_link()).unwrap();
    fs::remove_file(&fixture.helper).unwrap();
    fs::remove_dir(fixture.paths.version_directory(VERSION)).unwrap();
    fs::remove_dir(fixture.paths.bin_root()).unwrap();
    fs::remove_file(&fixture.runtime_db).unwrap();
    let recovery_before = fs::read(&fixture.recovery_helper).unwrap();
    let (events, launchctl, mut artifacts, runtime, sockets, processes, helper) = fakes(&fixture);
    launchctl.state.lock().unwrap().loaded = false;
    artifacts.recovery_changed_at = Some(2);

    let error = coordinator(
        &fixture, &launchctl, &artifacts, &runtime, &sockets, &processes, &helper,
    )
    .run()
    .await
    .expect_err("recovery helper attestation change must fail closed");

    assert_eq!(error.code(), "daemon.purge.attestation_changed");
    assert_eq!(artifacts.recovery_calls.load(Ordering::SeqCst), 2);
    assert_eq!(fs::read(&fixture.recovery_helper).unwrap(), recovery_before);
    let events = events.lock().unwrap();
    assert!(events.contains(&"helper.prove_terminal"));
    assert!(!events.contains(&"runtime.trust_reset"));
}
