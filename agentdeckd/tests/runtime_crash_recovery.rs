#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentdeckd::runtime::model::{COMMAND_QUEUE_TTL_MS, RuntimeClock, RuntimeClockError};
use agentdeckd::runtime::process_identity::{
    ProcessControlError, ProcessGroupController, ProcessIdentity, ProcessObservation, ProcessSignal,
};
use agentdeckd::runtime::recovery::{
    ConversationRecoveryState, RecoveryOptions, RuntimeRecoveryCoordinator,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CommandReceiptSelector, CommandState,
    ExecutionFence, IdempotencyOwner, NewConversation, QueryCommandReceipt, RuntimeId,
    RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreHandle, StartCommand, StartOutcome,
};
use agentdeckd::runtime::{AgentRouter, RuntimeCore};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use async_trait::async_trait;

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
            "agentdeckd-runtime-crash-recovery-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create crash recovery test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure crash recovery test root");
        }
        Self {
            path,
            keys: MemoryKeyStore::new(),
            _permit: permit,
        }
    }

    async fn store(&self) -> RuntimeStoreHandle {
        let storage_kek = load_or_create_storage_kek(&self.keys, &self.path.join("key-state.db"))
            .expect("create recovery StorageKEK");
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(self.path.join("runtime.db")),
            storage_kek,
        )
        .await
        .expect("open recovery store")
    }

    async fn store_with_clock(&self, clock: ManualClock) -> RuntimeStoreHandle {
        let storage_kek = load_or_create_storage_kek(&self.keys, &self.path.join("key-state.db"))
            .expect("create clocked recovery StorageKEK");
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(self.path.join("runtime.db")).with_clock(clock),
            storage_kek,
        )
        .await
        .expect("open clocked recovery store")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Debug)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn new(now_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_ms)))
    }

    fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashBoundary {
    BeforeStartedCommit,
    AfterStartedCommitBeforeSpawn,
    GateReadyBeforeFenceCommit,
    FenceCommittedBeforeRelease,
    AfterRelease,
}

#[derive(Clone)]
struct StagedConversation {
    conversation_id: RuntimeId,
    old_command_id: RuntimeId,
    successor_command_id: Option<RuntimeId>,
    process: Option<ProcessIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProcessCall {
    Probe(ProcessIdentity),
    Signal(ProcessIdentity, ProcessSignal),
    Wait(ProcessIdentity, Duration),
}

#[derive(Clone)]
struct RecordingProcessManager {
    inner: Arc<RecordingProcessManagerInner>,
}

struct RecordingProcessManagerInner {
    observations: Mutex<VecDeque<Result<ProcessObservation, ProcessControlError>>>,
    calls: Mutex<Vec<ProcessCall>>,
}

impl RecordingProcessManager {
    fn scripted(
        observations: impl IntoIterator<Item = Result<ProcessObservation, ProcessControlError>>,
    ) -> Self {
        Self {
            inner: Arc::new(RecordingProcessManagerInner {
                observations: Mutex::new(observations.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }),
        }
    }

    fn calls(&self) -> Vec<ProcessCall> {
        self.inner.calls.lock().expect("process calls lock").clone()
    }

    fn next_observation(&self) -> Result<ProcessObservation, ProcessControlError> {
        self.inner
            .observations
            .lock()
            .expect("process observations lock")
            .pop_front()
            .expect("recovery made an unexpected process observation")
    }
}

#[async_trait]
impl ProcessGroupController for RecordingProcessManager {
    async fn probe(
        &self,
        identity: ProcessIdentity,
    ) -> Result<ProcessObservation, ProcessControlError> {
        self.inner
            .calls
            .lock()
            .expect("process calls lock")
            .push(ProcessCall::Probe(identity));
        self.next_observation()
    }

    async fn signal(
        &self,
        identity: ProcessIdentity,
        signal: ProcessSignal,
    ) -> Result<(), ProcessControlError> {
        self.inner
            .calls
            .lock()
            .expect("process calls lock")
            .push(ProcessCall::Signal(identity, signal));
        Ok(())
    }

    async fn wait_for_exit(
        &self,
        identity: ProcessIdentity,
        timeout: Duration,
    ) -> Result<ProcessObservation, ProcessControlError> {
        self.inner
            .calls
            .lock()
            .expect("process calls lock")
            .push(ProcessCall::Wait(identity, timeout));
        self.next_observation()
    }
}

#[derive(Clone)]
struct AdvanceClockOnProbe {
    clock: ManualClock,
    advance_to_ms: u64,
}

#[async_trait]
impl ProcessGroupController for AdvanceClockOnProbe {
    async fn probe(
        &self,
        _identity: ProcessIdentity,
    ) -> Result<ProcessObservation, ProcessControlError> {
        self.clock.set(self.advance_to_ms);
        Ok(ProcessObservation::Exited)
    }

    async fn signal(
        &self,
        _identity: ProcessIdentity,
        _signal: ProcessSignal,
    ) -> Result<(), ProcessControlError> {
        panic!("already-exited fixture must not signal")
    }

    async fn wait_for_exit(
        &self,
        _identity: ProcessIdentity,
        _timeout: Duration,
    ) -> Result<ProcessObservation, ProcessControlError> {
        panic!("already-exited fixture must not wait")
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [seed; 32],
        uid: 501,
        client_installation_id: [seed.wrapping_add(1); 16],
    }
}

fn remote_owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Remote {
        machine_trust_domain: [seed; 32],
        device_route: [seed.wrapping_add(1); 16],
        device_sign_fingerprint: [seed.wrapping_add(2); 32],
    }
}

async fn accept(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    seed: u8,
    suffix: &str,
) -> agentdeckd::runtime::store::CommandRecord {
    match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(seed),
            idempotency_key: format!("recovery-{seed}-{suffix}"),
            payload: format!("recovery prompt {suffix}").into_bytes(),
        })
        .await
        .expect("accept recovery command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh recovery command replayed"),
    }
}

async fn stage_boundary(
    store: &RuntimeStoreHandle,
    seed: u8,
    boundary: CrashBoundary,
) -> StagedConversation {
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, seed);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(1)),
            descriptor: runtime_descriptor::descriptor(b"crash recovery fixture"),
        })
        .await
        .expect("create recovery conversation");
    let old = accept(store, conversation_id, seed, "old").await;
    if boundary == CrashBoundary::BeforeStartedCommit {
        return StagedConversation {
            conversation_id,
            old_command_id: old.command_id,
            successor_command_id: None,
            process: None,
        };
    }

    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(2));
    let execution_nonce = format!("recovery-nonce-{seed}").into_bytes();
    assert!(matches!(
        store
            .mark_started_with_event(StartCommand {
                conversation_id,
                command_id: old.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
            })
            .await
            .expect("stage recovery Started"),
        StartOutcome::Started { .. }
    ));
    let successor = accept(store, conversation_id, seed, "successor").await;
    if matches!(
        boundary,
        CrashBoundary::AfterStartedCommitBeforeSpawn | CrashBoundary::GateReadyBeforeFenceCommit
    ) {
        return StagedConversation {
            conversation_id,
            old_command_id: old.command_id,
            successor_command_id: Some(successor.command_id),
            process: None,
        };
    }

    let process = ProcessIdentity::new(
        i64::from(seed) + 7_000,
        i64::from(seed) + 7_000,
        u64::from(seed) + 7_000,
    )
    .expect("valid process identity");
    store
        .persist_execution_fence(ExecutionFence {
            command_id: old.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: process.process_group_id(),
            leader_pid: process.leader_pid(),
            leader_start_time: process.leader_start_time(),
            payload: b"recovery gate token commitment".to_vec(),
        })
        .await
        .expect("stage recovery fence");
    if boundary == CrashBoundary::AfterRelease {
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id: old.command_id,
                daemon_boot_id,
                execution_nonce,
            })
            .await
            .expect("stage release authorization");
    }
    StagedConversation {
        conversation_id,
        old_command_id: old.command_id,
        successor_command_id: Some(successor.command_id),
        process: Some(process),
    }
}

fn options() -> RecoveryOptions {
    RecoveryOptions {
        term_grace: Duration::from_millis(10),
        kill_grace: Duration::from_millis(10),
    }
}

async fn command_state(
    store: &RuntimeStoreHandle,
    owner_seed: u8,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
) -> CommandState {
    store
        .query_command_receipt(QueryCommandReceipt {
            expected_owner: owner(owner_seed),
            selector: CommandReceiptSelector::Command {
                conversation_id,
                command_id,
            },
        })
        .await
        .expect("query recovered command")
        .state
}

#[tokio::test]
async fn five_crash_boundaries_never_replay_started_execution() {
    // 威胁场景：daemon 在 durable state 与 OS child 不一致的任一 cut 崩溃；
    // 重启若把 Started 当 Accepted 重放，会重复 vendor/tool 副作用。
    for (index, boundary) in [
        CrashBoundary::BeforeStartedCommit,
        CrashBoundary::AfterStartedCommitBeforeSpawn,
        CrashBoundary::GateReadyBeforeFenceCommit,
        CrashBoundary::FenceCommittedBeforeRelease,
        CrashBoundary::AfterRelease,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TestRoot::new(&format!("five-cuts-{index}"));
        let seed = 0x20 + index as u8 * 8;
        let staging_store = root.store().await;
        let staged = stage_boundary(&staging_store, seed, boundary).await;
        staging_store
            .shutdown()
            .await
            .expect("shutdown pre-crash store");
        let store = root.store().await;
        let observations = if staged.process.is_some() {
            vec![
                Ok(ProcessObservation::ExactAlive),
                Ok(ProcessObservation::Exited),
            ]
        } else {
            Vec::new()
        };
        let processes = RecordingProcessManager::scripted(observations);
        let recovery =
            RuntimeRecoveryCoordinator::new(store.clone(), Arc::new(processes.clone()), options());
        let report = recovery
            .reconcile()
            .await
            .expect("reconcile crash boundary");
        // Direct reconciliation deliberately exposes no startup permit; only RuntimeCore's
        // second-pass install path can mint that capability.
        let outcome = report
            .conversation(staged.conversation_id)
            .expect("recovery conversation outcome");
        assert_eq!(outcome.state(), ConversationRecoveryState::Ready);
        if boundary == CrashBoundary::BeforeStartedCommit {
            assert_eq!(outcome.accepted_command_ids(), &[staged.old_command_id]);
            assert_eq!(outcome.interrupted_command_id(), None);
        } else {
            assert_eq!(
                outcome.interrupted_command_id(),
                Some(staged.old_command_id),
                "Started execution must become Interrupted, never replayed"
            );
            assert_eq!(
                outcome.accepted_command_ids(),
                &[staged.successor_command_id.expect("successor")]
            );
        }
        assert_eq!(
            command_state(&store, seed, staged.conversation_id, staged.old_command_id,).await,
            if boundary == CrashBoundary::BeforeStartedCommit {
                CommandState::Accepted
            } else {
                CommandState::Interrupted
            }
        );
        if let Some(successor) = staged.successor_command_id {
            assert_eq!(
                command_state(&store, seed, staged.conversation_id, successor).await,
                CommandState::Accepted
            );
        }
        if let Some(identity) = staged.process {
            assert_eq!(
                processes.calls(),
                vec![
                    ProcessCall::Probe(identity),
                    ProcessCall::Signal(identity, ProcessSignal::Terminate),
                    ProcessCall::Wait(identity, options().term_grace),
                ]
            );
        } else {
            assert!(processes.calls().is_empty());
        }
        store
            .shutdown()
            .await
            .expect("shutdown crash boundary store");
    }
}

#[tokio::test]
async fn second_pass_verification_does_not_expire_the_first_pass_cut() {
    // 威胁场景：Accepted 在第一遍读出后、第二遍开始前恰好到期；若第二遍再次执行
    // expiry sweep，daemon 会因自己的时间推进改变 durable cut 并拒绝启动。
    let root = TestRoot::new("fixed-expiry-cut");
    let initial_now_ms = 1_000;
    let clock = ManualClock::new(initial_now_ms);
    let store = root.store_with_clock(clock.clone()).await;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0xB1);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0xB2),
            descriptor: runtime_descriptor::descriptor(b"fixed expiry recovery cut"),
        })
        .await
        .expect("create fixed-cut conversation");
    let started = accept(&store, conversation_id, 0xB3, "started").await;
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0xB4);
    let execution_nonce = b"fixed-cut-nonce".to_vec();
    assert!(matches!(
        store
            .mark_started_with_event(StartCommand {
                conversation_id,
                command_id: started.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
            })
            .await
            .expect("start fixed-cut command"),
        StartOutcome::Started { .. }
    ));
    let process = ProcessIdentity::new(4_141, 4_141, 42).expect("valid fixture identity");
    store
        .persist_execution_fence(ExecutionFence {
            command_id: started.command_id,
            daemon_boot_id,
            execution_nonce,
            process_group_id: process.process_group_id(),
            leader_pid: process.leader_pid(),
            leader_start_time: process.leader_start_time(),
            payload: vec![0xB5; 32],
        })
        .await
        .expect("persist fixed-cut fence");
    let successor = accept(&store, conversation_id, 0xB3, "successor").await;

    let recovery = RuntimeRecoveryCoordinator::new(
        store.clone(),
        Arc::new(AdvanceClockOnProbe {
            clock,
            advance_to_ms: initial_now_ms + COMMAND_QUEUE_TTL_MS,
        }),
        options(),
    );
    let report = recovery
        .reconcile()
        .await
        .expect("second pass keeps the first-pass expiry cut");
    let outcome = report
        .conversation(conversation_id)
        .expect("fixed-cut recovery outcome");
    assert_eq!(outcome.state(), ConversationRecoveryState::Ready);
    assert_eq!(outcome.accepted_command_ids(), &[successor.command_id]);
    assert_eq!(outcome.interrupted_command_id(), Some(started.command_id));
    store.shutdown().await.expect("shutdown fixed-cut store");
}

#[tokio::test]
async fn pid_start_time_mismatch_never_signals_reused_process() {
    // 威胁场景：PID/PGID 已复用；按 stale PID 发 TERM 会杀死无关进程。
    let root = TestRoot::new("pid-reuse");
    let staging_store = root.store().await;
    let staged = stage_boundary(&staging_store, 0x61, CrashBoundary::AfterRelease).await;
    staging_store
        .shutdown()
        .await
        .expect("shutdown PID reuse staging store");
    let store = root.store().await;
    let identity = staged.process.expect("persisted process identity");
    let processes = RecordingProcessManager::scripted([Ok(ProcessObservation::IdentityMismatch)]);
    let recovery =
        RuntimeRecoveryCoordinator::new(store.clone(), Arc::new(processes.clone()), options());
    let report = recovery.reconcile().await.expect("classify PID reuse");
    let outcome = report
        .conversation(staged.conversation_id)
        .expect("PID reuse outcome");
    assert_eq!(outcome.state(), ConversationRecoveryState::Blocked);
    assert!(outcome.accepted_command_ids().is_empty());
    assert_eq!(processes.calls(), vec![ProcessCall::Probe(identity)]);
    assert_eq!(
        command_state(&store, 0x61, staged.conversation_id, staged.old_command_id,).await,
        CommandState::Started
    );
    assert_eq!(
        command_state(
            &store,
            0x61,
            staged.conversation_id,
            staged.successor_command_id.expect("PID reuse successor"),
        )
        .await,
        CommandState::Accepted
    );
    store.shutdown().await.expect("shutdown PID reuse store");

    // 威胁场景：第一次 recovery 已因 PID reuse fail-closed，但 daemon 在本地用户
    // 诊断前再次重启；第二次启动不能因为 stale PGID 此刻恰好不存在就自动恢复 successor。
    let reopened = root.store().await;
    let second_processes = RecordingProcessManager::scripted([]);
    let second_recovery = RuntimeRecoveryCoordinator::new(
        reopened.clone(),
        Arc::new(second_processes.clone()),
        options(),
    );
    let second_report = second_recovery
        .reconcile()
        .await
        .expect("reconcile durable PID reuse block after reopen");
    let second_outcome = second_report
        .conversation(staged.conversation_id)
        .expect("reopened PID reuse outcome");
    assert_eq!(second_outcome.state(), ConversationRecoveryState::Blocked);
    assert!(second_outcome.accepted_command_ids().is_empty());
    assert!(
        second_processes.calls().is_empty(),
        "durable RecoveryBlocked must short-circuit stale process probing"
    );
    assert_eq!(
        command_state(
            &reopened,
            0x61,
            staged.conversation_id,
            staged.old_command_id,
        )
        .await,
        CommandState::Started
    );
    assert_eq!(
        command_state(
            &reopened,
            0x61,
            staged.conversation_id,
            staged.successor_command_id.expect("PID reuse successor"),
        )
        .await,
        CommandState::Accepted
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened PID reuse store");
}

#[tokio::test]
async fn term_then_kill_failure_keeps_same_conversation_queue_closed() {
    // 威胁场景：孤儿忽略 TERM，KILL 后仍无法证明全组退出；若恢复 successor，
    // 新旧 turn 会并发产生副作用。
    let root = TestRoot::new("unreaped-group");
    let staging_store = root.store().await;
    let staged = stage_boundary(&staging_store, 0x71, CrashBoundary::AfterRelease).await;
    staging_store
        .shutdown()
        .await
        .expect("shutdown unreaped-group staging store");
    let store = root.store().await;
    let identity = staged.process.expect("persisted process identity");
    let processes = RecordingProcessManager::scripted([
        Ok(ProcessObservation::ExactAlive),
        Ok(ProcessObservation::ExactAlive),
        Ok(ProcessObservation::ExactAlive),
    ]);
    let recovery =
        RuntimeRecoveryCoordinator::new(store.clone(), Arc::new(processes.clone()), options());
    let report = recovery.reconcile().await.expect("classify unreaped group");
    let outcome = report
        .conversation(staged.conversation_id)
        .expect("unreaped group outcome");
    assert_eq!(outcome.state(), ConversationRecoveryState::Blocked);
    assert!(outcome.accepted_command_ids().is_empty());
    assert_eq!(
        processes.calls(),
        vec![
            ProcessCall::Probe(identity),
            ProcessCall::Signal(identity, ProcessSignal::Terminate),
            ProcessCall::Wait(identity, options().term_grace),
            ProcessCall::Signal(identity, ProcessSignal::Kill),
            ProcessCall::Wait(identity, options().kill_grace),
        ]
    );
    assert_eq!(
        command_state(&store, 0x71, staged.conversation_id, staged.old_command_id,).await,
        CommandState::Started
    );
    assert_eq!(
        command_state(
            &store,
            0x71,
            staged.conversation_id,
            staged.successor_command_id.expect("unreaped successor"),
        )
        .await,
        CommandState::Accepted
    );
    store
        .shutdown()
        .await
        .expect("shutdown unreaped group store");
}

#[tokio::test]
async fn blocked_conversation_does_not_globally_block_healthy_queue() {
    // 威胁场景：一个不可 fencing 的 orphan 让整个 daemon 永久停摆；恢复必须
    // 阻断同 conversation，而不是无差别阻断已确认安全的队列。
    let root = TestRoot::new("conversation-isolation");
    let staging_store = root.store().await;
    let blocked = stage_boundary(&staging_store, 0x81, CrashBoundary::AfterRelease).await;
    let healthy = stage_boundary(&staging_store, 0x91, CrashBoundary::BeforeStartedCommit).await;
    staging_store
        .shutdown()
        .await
        .expect("shutdown mixed staging store");
    let store = root.store().await;
    let processes = RecordingProcessManager::scripted([
        Ok(ProcessObservation::ExactAlive),
        Ok(ProcessObservation::ExactAlive),
        Ok(ProcessObservation::ExactAlive),
    ]);
    let recovery = RuntimeRecoveryCoordinator::new(store.clone(), Arc::new(processes), options());
    let report = recovery
        .reconcile()
        .await
        .expect("reconcile mixed conversations");
    // Direct reconciliation deliberately exposes no startup permit.
    let blocked_outcome = report
        .conversation(blocked.conversation_id)
        .expect("blocked conversation outcome");
    assert_eq!(blocked_outcome.state(), ConversationRecoveryState::Blocked);
    assert!(blocked_outcome.accepted_command_ids().is_empty());
    let healthy_outcome = report
        .conversation(healthy.conversation_id)
        .expect("healthy conversation outcome");
    assert_eq!(healthy_outcome.state(), ConversationRecoveryState::Ready);
    assert_eq!(
        healthy_outcome.accepted_command_ids(),
        &[healthy.old_command_id]
    );
    store
        .shutdown()
        .await
        .expect("shutdown mixed recovery store");
}

#[tokio::test]
async fn runtime_core_rejects_remote_accepted_before_installing_any_actor() {
    // 威胁场景：P4 durable auth ledger 尚未接线，重启若仅凭 durable owner 近似
    // 恢复 remote Accepted，会绕过原 grant serial/revocation lease 继续执行。
    let root = TestRoot::new("remote-auth-ledger");
    let staging_store = root.store().await;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0xA1);
    staging_store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0xA2),
            descriptor: runtime_descriptor::descriptor(b"remote recovery fixture"),
        })
        .await
        .expect("create remote recovery conversation");
    let outcome = staging_store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: remote_owner(0xA3),
            idempotency_key: "remote-recovery".to_owned(),
            payload: b"remote recovery prompt".to_vec(),
        })
        .await
        .expect("accept remote recovery command");
    assert!(matches!(outcome, AcceptOutcome::Accepted { .. }));
    staging_store
        .shutdown()
        .await
        .expect("shutdown remote staging store");

    let store = root.store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = RuntimeCore::new(store, router, [0xA4; 32]).expect("construct recovery core");
    let failure = core
        .recover_for_startup()
        .await
        .expect_err("remote Accepted must block startup before P4 auth ledger");
    assert_eq!(
        failure.code,
        agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_RECOVERY_BLOCKED
    );
    core.shutdown()
        .await
        .expect("shutdown blocked recovery core");
}
