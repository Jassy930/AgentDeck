#![cfg(unix)]

#[path = "support/exec_gate_wire.rs"]
mod exec_gate_wire;
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead as _, BufReader};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use agentdeckd::runtime::process_identity::{
    ProcessGroupController, ProcessIdentity, ProcessObservation, ProcessSignal,
    SystemProcessGroupController,
};
use agentdeckd::runtime::recovery::{
    ConversationRecoveryState, RecoveryOptions, RuntimeRecoveryCoordinator,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, ExecutionFence, IdempotencyOwner,
    NewConversation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreHandle,
    StartCommand, StartOutcome,
};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use exec_gate_wire::{ChildFrame, GATE_PROTOCOL_VERSION, ParentFrame, read_frame, write_frame};
const CONTROL_FD: RawFd = 3;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const TEST_SAFE_HOME: &str = "/tmp/agentdeckd-exec-gate-safe-home";
const TEST_UNTRUSTED_PATH: &str = "/tmp/agentdeckd-untrusted-bin";
const MAX_EXEC_PATH_BYTES: usize = 16 * 1024;
const MAX_EXEC_SINGLE_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_EXEC_CONTROL_FRAME_BYTES: usize = 288 * 1024;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
    keys: MemoryKeyStore,
    _permit: store_admission::Permit,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let permit = store_admission::acquire();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-exec-gate-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create exec-gate test root");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure exec-gate test root");
        Self {
            path,
            keys: MemoryKeyStore::new(),
            _permit: permit,
        }
    }

    fn database(&self) -> PathBuf {
        self.path.join("runtime.db")
    }

    async fn store(&self) -> RuntimeStoreHandle {
        let storage_kek = load_or_create_storage_kek(&self.keys, &self.path.join("key-state.db"))
            .expect("load exec-gate StorageKEK");
        RuntimeStoreHandle::open(RuntimeStoreConfig::new(self.database()), storage_kek)
            .await
            .expect("open exec-gate store")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
struct GateSpec {
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
    program: PathBuf,
    arguments: Vec<Vec<u8>>,
    cwd: PathBuf,
}

impl GateSpec {
    fn prepare_frame(&self) -> ParentFrame {
        ParentFrame::Prepare {
            protocol_version: GATE_PROTOCOL_VERSION,
            command_id: self.command_id.to_canonical_string(),
            daemon_boot_id: self.daemon_boot_id.to_canonical_string(),
            execution_nonce: self.execution_nonce.clone(),
            program: self.program.as_os_str().as_bytes().to_vec(),
            arguments: self.arguments.clone(),
            cwd: self.cwd.as_os_str().as_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Debug)]
struct GateReady {
    process_group_id: i64,
    leader_pid: i64,
    leader_start_time: u64,
    execution_nonce: Vec<u8>,
    release_token: Vec<u8>,
    token_commitment: Vec<u8>,
}

struct CommittedRelease {
    frame: ParentFrame,
}

struct GateHarness {
    child: Child,
    control: Option<UnixStream>,
    spec: GateSpec,
    ready_process: Option<ProcessIdentity>,
}

impl GateHarness {
    fn spawn(spec: GateSpec) -> Self {
        Self::spawn_with_stdout(spec, Stdio::null())
    }

    fn spawn_with_piped_stdout(spec: GateSpec) -> Self {
        Self::spawn_with_stdout(spec, Stdio::piped())
    }

    fn spawn_with_stdout(spec: GateSpec, stdout: Stdio) -> Self {
        let (parent_control, child_control) = UnixStream::pair().expect("create private gate FD");
        parent_control
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("set gate read timeout");
        parent_control
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("set gate write timeout");
        let child_fd = child_control.as_raw_fd();
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentdeckd"));
        command
            .arg("--exec-gate")
            .env_clear()
            .env("HOME", TEST_SAFE_HOME)
            .env("PATH", TEST_UNTRUSTED_PATH)
            .env("AGENTDECK_EXEC_GATE_TEST_SECRET", "must-not-reach-vendor")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::null());
        // SAFETY: pre_exec 只调用 async-signal-safe dup2/fcntl/close，把 socketpair
        // child endpoint 安装到 gate 固定私有 FD；不会分配内存或触碰共享锁。
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(child_fd, CONTROL_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(CONTROL_FD, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if child_fd != CONTROL_FD {
                    libc::close(child_fd);
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn current-binary exec gate");
        drop(child_control);
        Self {
            child,
            control: Some(parent_control),
            spec,
            ready_process: None,
        }
    }

    fn ready(&mut self) -> GateReady {
        self.send(&self.spec.prepare_frame())
            .expect("send gate prepare frame");
        match self.recv().expect("receive exact GateReady") {
            ChildFrame::Ready {
                protocol_version,
                process_group_id,
                leader_pid,
                leader_start_time,
                execution_nonce,
                release_token,
                token_commitment,
            } => {
                assert_eq!(protocol_version, GATE_PROTOCOL_VERSION);
                assert_eq!(execution_nonce, self.spec.execution_nonce);
                assert_eq!(leader_pid, i64::from(self.child.id()));
                assert_eq!(process_group_id, leader_pid);
                assert!(leader_start_time > 0);
                assert!(release_token.len() >= 16);
                assert_eq!(token_commitment.len(), 32);
                self.ready_process = Some(
                    ProcessIdentity::new(process_group_id, leader_pid, leader_start_time)
                        .expect("gate returned a valid exact process identity"),
                );
                GateReady {
                    process_group_id,
                    leader_pid,
                    leader_start_time,
                    execution_nonce,
                    release_token,
                    token_commitment,
                }
            }
            other => panic!("expected GateReady, got {other:?}"),
        }
    }

    fn release(&mut self, release: &CommittedRelease) -> io::Result<()> {
        self.send(&release.frame)
    }

    fn recv(&mut self) -> io::Result<ChildFrame> {
        read_frame(self.control.as_mut().expect("gate control is open"))
    }

    fn send(&mut self, frame: &ParentFrame) -> io::Result<()> {
        write_frame(self.control.as_mut().expect("gate control is open"), frame)
    }

    fn close_control(&mut self) {
        if let Some(control) = self.control.take() {
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        self.child.wait().expect("wait for exec gate")
    }
}

impl Drop for GateHarness {
    fn drop(&mut self) {
        self.close_control();
        if self.child.try_wait().ok().flatten().is_none() {
            if let Some(process) = self.ready_process {
                // 威胁场景：失败测试若先 reap sentinel 再按缓存整数 PGID 清理，PID/PGID
                // 复用会误杀 unrelated group。只有 exact leader identity 仍匹配才授权组 KILL。
                let leader_pid =
                    i32::try_from(process.leader_pid()).expect("test-owned sentinel pid fits i32");
                // SAFETY: getpgid is read-only. `try_wait == None` above proves this exact Child
                // has not been reaped, so its PID cannot have been reused between the checks.
                if unsafe { libc::getpgid(leader_pid) } == leader_pid {
                    let process_group_id = i32::try_from(process.process_group_id())
                        .expect("test-owned process group id fits i32");
                    // SAFETY: the exact Child has not been reaped, so its PID cannot be reused;
                    // getpgid immediately above also proved that PID still leads this group.
                    unsafe {
                        libc::kill(-process_group_id, libc::SIGKILL);
                    }
                }
            }
            // Child ownership keeps this PID unreusable until wait; direct kill is therefore safe
            // even when a pre-ready gate never established a process group.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl GateReady {
    fn process_identity(&self) -> ProcessIdentity {
        ProcessIdentity::new(
            self.process_group_id,
            self.leader_pid,
            self.leader_start_time,
        )
        .expect("gate reported a valid process identity")
    }
}

struct StartedFixture {
    store: RuntimeStoreHandle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
}

impl StartedFixture {
    async fn new(root: &TestRoot, seed: u8) -> Self {
        let store = root.store().await;
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, seed);
        store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(1)),
                descriptor: runtime_descriptor::descriptor(b"exec gate fixture"),
            })
            .await
            .expect("create gate fixture conversation");
        let owner = IdempotencyOwner::Local {
            machine_trust_domain: [seed; 32],
            uid: 501,
            client_installation_id: [seed.wrapping_add(1); 16],
        };
        let command = match store
            .accept_command(AcceptCommand {
                conversation_id,
                owner,
                idempotency_key: format!("exec-gate-{seed}"),
                expected_configuration_revision: 0,
                payload: b"exec gate fixture prompt".to_vec(),
            })
            .await
            .expect("accept gate fixture command")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh gate fixture replayed"),
        };
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(2));
        let execution_nonce = format!("exec-gate-nonce-{seed}").into_bytes();
        assert!(matches!(
            store
                .mark_started_with_event(StartCommand {
                    conversation_id,
                    command_id: command.command_id,
                    daemon_boot_id,
                    execution_nonce: execution_nonce.clone(),
                })
                .await
                .expect("commit Started before gate spawn"),
            StartOutcome::Started { .. }
        ));
        Self {
            store,
            conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce,
        }
    }

    fn spec(&self, root: &TestRoot, arguments: Vec<Vec<u8>>) -> GateSpec {
        GateSpec {
            command_id: self.command_id,
            daemon_boot_id: self.daemon_boot_id,
            execution_nonce: self.execution_nonce.clone(),
            program: PathBuf::from("/bin/sh"),
            arguments,
            cwd: root.path.clone(),
        }
    }

    async fn authorize(&self, ready: &GateReady) -> CommittedRelease {
        let fence = self
            .store
            .persist_execution_fence(ExecutionFence {
                command_id: self.command_id,
                daemon_boot_id: self.daemon_boot_id,
                execution_nonce: self.execution_nonce.clone(),
                process_group_id: ready.process_group_id,
                leader_pid: ready.leader_pid,
                leader_start_time: ready.leader_start_time,
                payload: ready.token_commitment.clone(),
            })
            .await
            .expect("commit exact gate fence");
        let released = self
            .store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id: self.command_id,
                daemon_boot_id: self.daemon_boot_id,
                execution_nonce: self.execution_nonce.clone(),
            })
            .await
            .expect("commit exact release authorization");
        let release_authorized_at_ms = released
            .release_authorized_at_ms
            .expect("release authorization timestamp");
        assert_eq!(released.process_group_id, fence.process_group_id);
        CommittedRelease {
            frame: ParentFrame::Release {
                command_id: self.command_id.to_canonical_string(),
                daemon_boot_id: self.daemon_boot_id.to_canonical_string(),
                execution_nonce: ready.execution_nonce.clone(),
                process_group_id: ready.process_group_id,
                leader_pid: ready.leader_pid,
                leader_start_time: ready.leader_start_time,
                release_token: ready.release_token.clone(),
                token_commitment: ready.token_commitment.clone(),
                release_authorized_at_ms,
            },
        }
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
}

fn shell_arguments(script: &str, values: &[&Path]) -> Vec<Vec<u8>> {
    let mut arguments = vec![
        b"-c".to_vec(),
        script.as_bytes().to_vec(),
        b"gate-test".to_vec(),
    ];
    arguments.extend(
        values
            .iter()
            .map(|value| value.as_os_str().as_bytes().to_vec()),
    );
    arguments
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + IO_TIMEOUT;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_path_or_child_exit(gate: &mut GateHarness, path: &Path) {
    let deadline = Instant::now() + IO_TIMEOUT;
    while !path.exists() {
        if let Some(status) = gate.child.try_wait().expect("probe gate child status") {
            panic!(
                "gate/vendor exited before creating {}: {status}",
                path.display()
            );
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn assert_ready_matches_os(ready: &GateReady) {
    assert_eq!(
        SystemProcessGroupController
            .probe(ready.process_identity())
            .await
            .expect("probe gate process identity from OS"),
        ProcessObservation::ExactAlive,
        "GateReady did not match the independently observed OS identity"
    );
}

fn raw_release(spec: &GateSpec, ready: &GateReady) -> ParentFrame {
    ParentFrame::Release {
        command_id: spec.command_id.to_canonical_string(),
        daemon_boot_id: spec.daemon_boot_id.to_canonical_string(),
        execution_nonce: ready.execution_nonce.clone(),
        process_group_id: ready.process_group_id,
        leader_pid: ready.leader_pid,
        leader_start_time: ready.leader_start_time,
        release_token: ready.release_token.clone(),
        token_commitment: ready.token_commitment.clone(),
        release_authorized_at_ms: 1,
    }
}

#[derive(Clone, Copy, Debug)]
enum ReleaseMutation {
    CommandId,
    DaemonBootId,
    ExecutionNonce,
    ProcessGroupId,
    LeaderPid,
    LeaderStartTime,
    ReleaseToken,
    TokenCommitment,
    ReleaseTimestamp,
}

fn mutate_release(frame: &mut ParentFrame, mutation: ReleaseMutation) {
    let ParentFrame::Release {
        command_id,
        daemon_boot_id,
        execution_nonce,
        process_group_id,
        leader_pid,
        leader_start_time,
        release_token,
        token_commitment,
        release_authorized_at_ms,
    } = frame
    else {
        panic!("release mutation requires a Release frame");
    };
    match mutation {
        ReleaseMutation::CommandId => {
            *command_id = runtime_id(RuntimeIdKind::Command, 0xe1).to_canonical_string();
        }
        ReleaseMutation::DaemonBootId => {
            *daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0xe2).to_canonical_string();
        }
        ReleaseMutation::ExecutionNonce => execution_nonce[0] ^= 1,
        ReleaseMutation::ProcessGroupId => *process_group_id += 1,
        ReleaseMutation::LeaderPid => *leader_pid += 1,
        ReleaseMutation::LeaderStartTime => *leader_start_time += 1,
        ReleaseMutation::ReleaseToken => release_token[0] ^= 1,
        ReleaseMutation::TokenCommitment => token_commitment[0] ^= 1,
        ReleaseMutation::ReleaseTimestamp => *release_authorized_at_ms = 0,
    }
}

fn path_with_encoded_len(length: usize, fill: u8) -> PathBuf {
    assert!(length >= 1);
    let mut bytes = vec![fill; length];
    bytes[0] = b'/';
    PathBuf::from(OsString::from_vec(bytes))
}

fn assert_group_reaped(identity: &GateReady) {
    // SAFETY: negative exact gate PGID with signal 0 only probes existence and never sends a
    // signal. ESRCH proves no member of the reported group remains.
    let probe = unsafe { libc::kill(-i32::try_from(identity.process_group_id).unwrap(), 0) };
    assert_eq!(probe, -1, "reported process group still has live members");
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "process group probe failed for a reason other than complete exit"
    );
}

#[tokio::test]
async fn blocked_gate_never_execs_vendor_before_exact_committed_release_permit() {
    // 威胁场景：Started 已 COMMIT、但 Fence/release 尚未提交；若 gate 提前 exec，
    // daemon crash 会留下没有 durable 账本边界的 vendor 副作用。
    let root = TestRoot::new("blocked-until-release");
    let started = StartedFixture::new(&root, 0x21).await;
    let marker = root.path.join("vendor.marker");
    let args = shell_arguments(
        concat!(
            "if [ \"${AGENTDECK_EXEC_GATE_TEST_SECRET+x}\" = x ]; then exit 91; fi; ",
            "if [ \"$HOME\" != \"$1\" ]; then exit 92; fi; ",
            "case \":$PATH:\" in *\":$2:\"*) exit 93 ;; esac; ",
            "if [ -e /dev/fd/3 ]; then exit 94; fi; ",
            "printf released > \"$3\""
        ),
        &[
            Path::new(TEST_SAFE_HOME),
            Path::new(TEST_UNTRUSTED_PATH),
            &marker,
        ],
    );
    let mut gate = GateHarness::spawn(started.spec(&root, args));
    let ready = gate.ready();
    assert_ready_matches_os(&ready).await;
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !marker.exists(),
        "vendor crossed the durable release boundary"
    );

    let release = started.authorize(&ready).await;
    gate.release(&release)
        .expect("send exact committed release");
    wait_for_path_or_child_exit(&mut gate, &marker);
    assert_eq!(
        SystemProcessGroupController
            .probe(ready.process_identity())
            .await
            .expect("probe post-vendor sentinel"),
        ProcessObservation::ExactAlive,
        "gate sentinel exited with its short-lived vendor"
    );
    SystemProcessGroupController
        .signal(ready.process_identity(), ProcessSignal::Kill)
        .await
        .expect("kill exact sentinel after released vendor fixture");
    let status = gate.wait();
    assert!(
        status.code().is_none(),
        "sentinel did not receive group KILL"
    );
    assert_group_reaped(&ready);
    started
        .store
        .shutdown()
        .await
        .expect("shutdown gate fixture store");
}

#[tokio::test]
async fn raw_release_rejects_each_binding_field_independently() {
    // 威胁场景：攻击者或 wiring bug 只替换 release 的一个 binding 字段；若测试同时
    // 改动多个字段，单项校验被删除也可能继续绿灯。
    let root = TestRoot::new("release-binding");
    let started = StartedFixture::new(&root, 0x31).await;
    let marker = root.path.join("bound.marker");
    let spec = started.spec(&root, shell_arguments("printf bound > \"$1\"", &[&marker]));

    for mutation in [
        ReleaseMutation::CommandId,
        ReleaseMutation::DaemonBootId,
        ReleaseMutation::ExecutionNonce,
        ReleaseMutation::ProcessGroupId,
        ReleaseMutation::LeaderPid,
        ReleaseMutation::LeaderStartTime,
        ReleaseMutation::ReleaseToken,
        ReleaseMutation::TokenCommitment,
        ReleaseMutation::ReleaseTimestamp,
    ] {
        let mut gate = GateHarness::spawn(spec.clone());
        let ready = gate.ready();
        let mut frame = raw_release(&spec, &ready);
        mutate_release(&mut frame, mutation);
        gate.send(&frame).expect("send one-field-mutated release");
        let rejected = gate.recv().expect("read mutated release rejection");
        assert!(
            matches!(rejected, ChildFrame::Aborted { ref code } if !code.is_empty()),
            "mutation {mutation:?} was not rejected"
        );
        assert!(!marker.exists(), "mutation {mutation:?} executed vendor");
        assert!(!gate.wait().success());
        assert_group_reaped(&ready);
    }
    started
        .store
        .shutdown()
        .await
        .expect("shutdown release fixture store");
}

#[tokio::test]
async fn closing_control_fd_before_release_reaps_gate_without_vendor_exec() {
    // 威胁场景：daemon 在 gate ready 后、release 前崩溃；若私有 FD EOF 不让
    // blocked gate 自退，孤儿 gate 会长期占用 process group 并可能迟到 exec。
    let root = TestRoot::new("control-eof");
    let started = StartedFixture::new(&root, 0x41).await;
    let marker = root.path.join("must-not-exist.marker");
    let mut gate =
        GateHarness::spawn(started.spec(&root, shell_arguments("printf bad > \"$1\"", &[&marker])));
    let ready = gate.ready();
    gate.close_control();
    assert!(
        !gate.wait().success(),
        "pre-release EOF reported successful execution"
    );
    assert!(!marker.exists(), "vendor executed after control EOF");
    // SAFETY: signal 0 is a read-only existence probe for the exact child PID.
    let probe = unsafe { libc::kill(i32::try_from(ready.leader_pid).unwrap(), 0) };
    assert_eq!(probe, -1, "gate leader remained alive after control EOF");
    started
        .store
        .shutdown()
        .await
        .expect("shutdown EOF fixture store");
}

#[tokio::test]
async fn stable_gate_sentinel_survives_vendor_terminal_until_direct_group_kill() {
    // 威胁场景：vendor 直系进程输出 terminal 后退出，但忽略 TERM 且脱离 stdio 的
    // tool child 仍继续副作用。若 vendor 自身是 PGID leader，daemon 首次 cleanup 只会
    // 得到 Unknown；稳定 sentinel 必须继续占有 exact PID/start-time，允许 normal
    // completion 直接 KILL 整组且不依赖已 reap 整数 PGID。
    let root = TestRoot::new("stable-sentinel");
    let started = StartedFixture::new(&root, 0x51).await;
    let info = root.path.join("process-group.info");
    let script = concat!(
        "trap '' HUP TERM; ",
        "/bin/sh -c 'trap \"\" HUP TERM; exec </dev/null >/dev/null 2>/dev/null; ",
        "while :; do /bin/sleep 1; done' & child=$!; ",
        "vendor_pgid=$(/bin/ps -o pgid= -p $$); ",
        "child_pgid=$(/bin/ps -o pgid= -p $child); ",
        "printf '%s %s %s %s' $$ $vendor_pgid $child $child_pgid > \"$1\"; ",
        "printf 'terminal\\n'; ",
        "exit 0"
    );
    let mut gate = GateHarness::spawn_with_piped_stdout(
        started.spec(&root, shell_arguments(script, &[&info])),
    );
    let ready = gate.ready();
    assert_ready_matches_os(&ready).await;
    let release = started.authorize(&ready).await;
    gate.release(&release)
        .expect("release sentinel-owned vendor");
    gate.close_control();
    let mut terminal = String::new();
    BufReader::new(
        gate.child
            .stdout
            .take()
            .expect("sentinel harness owns vendor stdout"),
    )
    .read_line(&mut terminal)
    .expect("read vendor terminal output");
    assert_eq!(terminal, "terminal\n");
    wait_for_path(&info);
    let values = fs::read_to_string(&info)
        .expect("read stable sentinel fixture")
        .split_whitespace()
        .map(|value| value.parse::<i64>().expect("parse process identity"))
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 4);
    assert_ne!(
        values[0], ready.leader_pid,
        "vendor must be a sentinel child"
    );
    assert_eq!(values[1], ready.process_group_id);
    assert_eq!(values[3], ready.process_group_id);
    assert!(
        gate.child
            .try_wait()
            .expect("probe stable sentinel")
            .is_none(),
        "sentinel exited with the direct vendor"
    );
    assert_eq!(
        SystemProcessGroupController
            .probe(ready.process_identity())
            .await
            .expect("probe stable sentinel after vendor terminal"),
        ProcessObservation::ExactAlive
    );
    assert!(
        unsafe { libc::kill(-i32::try_from(ready.process_group_id).unwrap(), 0) } == 0,
        "detached tool child did not keep the reported process group alive"
    );
    SystemProcessGroupController
        .signal(ready.process_identity(), ProcessSignal::Kill)
        .await
        .expect("normal completion direct-kills exact sentinel group");
    let status = gate.wait();
    assert!(
        status.code().is_none(),
        "sentinel was not terminated by direct group KILL"
    );
    assert_eq!(
        SystemProcessGroupController
            .wait_for_exit(ready.process_identity(), Duration::from_secs(2))
            .await
            .expect("wait for direct-killed sentinel group"),
        ProcessObservation::Exited
    );
    assert_group_reaped(&ready);
    started
        .store
        .shutdown()
        .await
        .expect("shutdown group fixture store");
}

#[tokio::test]
async fn adgx_codec_accepts_exact_execspec_max_and_rejects_plus_one() {
    // 威胁场景：constructor 接受的最大合法 ExecSpec 若无法穿过私有 wire，会在真实
    // adapter 上线后形成只在大 argv 才触发的不可恢复启动失败。
    let root = TestRoot::new("codec-boundary");
    let started = StartedFixture::new(&root, 0x71).await;
    let arguments =
        std::iter::repeat_n(vec![b'a'; MAX_EXEC_SINGLE_ARGUMENT_BYTES], 16).collect::<Vec<_>>();
    let program = path_with_encoded_len(MAX_EXEC_PATH_BYTES, b'p');
    let exact_cwd_bytes = MAX_EXEC_CONTROL_FRAME_BYTES
        - arguments.iter().map(Vec::len).sum::<usize>()
        - program.as_os_str().as_bytes().len()
        - (3 + arguments.len()) * std::mem::size_of::<u64>();
    let exact = GateSpec {
        command_id: started.command_id,
        daemon_boot_id: started.daemon_boot_id,
        execution_nonce: started.execution_nonce.clone(),
        program: program.clone(),
        arguments: arguments.clone(),
        cwd: path_with_encoded_len(exact_cwd_bytes, b'c'),
    };
    assert_eq!(
        (3 + exact.arguments.len()) * std::mem::size_of::<u64>()
            + exact.program.as_os_str().as_bytes().len()
            + exact.cwd.as_os_str().as_bytes().len()
            + exact.arguments.iter().map(Vec::len).sum::<usize>(),
        MAX_EXEC_CONTROL_FRAME_BYTES
    );
    let mut exact_gate = GateHarness::spawn(exact.clone());
    let exact_ready = exact_gate.ready();
    assert_ready_matches_os(&exact_ready).await;
    exact_gate.close_control();
    assert!(!exact_gate.wait().success());
    assert_group_reaped(&exact_ready);

    let mut oversized = exact;
    oversized.cwd = path_with_encoded_len(exact_cwd_bytes + 1, b'c');
    let mut oversized_gate = GateHarness::spawn(oversized.clone());
    oversized_gate
        .send(&oversized.prepare_frame())
        .expect("send one-byte-oversized prepare frame");
    match oversized_gate.recv() {
        Err(_) | Ok(ChildFrame::Aborted { .. }) => {}
        Ok(ChildFrame::Ready { .. }) => {
            panic!("one-byte-oversized ExecSpec unexpectedly became ready")
        }
    }
    assert!(!oversized_gate.wait().success());
    started
        .store
        .shutdown()
        .await
        .expect("shutdown codec fixture store");
}

#[tokio::test]
async fn reopened_recovery_terminates_a_real_released_vendor_group() {
    // 威胁场景：daemon 在 durable release 后崩溃，忽略 TERM 的真实 vendor group
    // 继续运行；重启只有在 exact start-time 校验、TERM→KILL 并确认 PGID 消失后，
    // 才能把旧 turn 标 Interrupted 并恢复同 conversation。
    let root = TestRoot::new("system-recovery");
    let started = StartedFixture::new(&root, 0x61).await;
    let marker = root.path.join("released-vendor-running.marker");
    let script = "trap '' TERM; printf running > \"$1\"; while :; do /bin/sleep 1; done";
    let mut gate = GateHarness::spawn(started.spec(&root, shell_arguments(script, &[&marker])));
    let ready = gate.ready();
    let release = started.authorize(&ready).await;
    gate.release(&release)
        .expect("release long-running vendor group");
    wait_for_path(&marker);
    gate.close_control();
    started
        .store
        .shutdown()
        .await
        .expect("shutdown crashed daemon store");
    let gate_waiter = tokio::task::spawn_blocking(move || gate.wait());

    let reopened = root.store().await;
    let recovery = RuntimeRecoveryCoordinator::new(
        reopened.clone(),
        Arc::new(SystemProcessGroupController),
        RecoveryOptions {
            term_grace: Duration::from_millis(100),
            kill_grace: Duration::from_secs(2),
        },
    );
    let report = recovery
        .reconcile()
        .await
        .expect("reconcile real released process group");
    let outcome = report
        .conversation(started.conversation_id)
        .expect("real recovery conversation");
    assert_eq!(outcome.state(), ConversationRecoveryState::Ready);
    assert_eq!(outcome.interrupted_command_id(), Some(started.command_id));
    let status = gate_waiter.await.expect("join orphan gate waiter");
    assert!(
        status.code().is_none(),
        "orphan vendor was not signal-killed"
    );
    assert_group_reaped(&ready);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened recovery store");
}
