#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, CommandReceiptSelector, CommandState,
    CommandTerminal, CompleteCommand, CreateConversationOutcome, ExecutionFence, IdempotencyOwner,
    NewConversation, QueryCommandReceipt, RuntimeClock, RuntimeClockError, RuntimeCommitOperation,
    RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreHandle, RuntimeStoreOperation, StartCommand, StartOutcome,
    StartedBeforeReleaseTermination, TerminateAcceptedCommand, TerminateAcceptedOutcome,
    TerminateStartedBeforeRelease, TerminateStartedBeforeReleaseOutcome,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
    _permit: store_admission::Permit,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let permit = store_admission::acquire();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-p34-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create P3.4 store root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure P3.4 store root");
        }
        Self {
            path,
            _permit: permit,
        }
    }

    fn database(&self) -> PathBuf {
        self.path.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.path.join("key-state.db"))
            .expect("load P3.4 StorageKEK")
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

async fn create_and_accept(
    store: &RuntimeStoreHandle,
    conversation_seed: u8,
    owner: IdempotencyOwner,
    key: &str,
) -> (
    agentdeckd::runtime::store::ConversationRecord,
    agentdeckd::runtime::store::CommandRecord,
) {
    let conversation = store
        .create_conversation(conversation_input(conversation_seed))
        .await
        .expect("create conversation");
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner,
            idempotency_key: key.to_owned(),
            payload: format!("payload-{key}").into_bytes(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };
    (conversation, command)
}

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn conversation_input(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: runtime_descriptor::descriptor(format!("p34-{seed}").as_bytes()),
    }
}

fn remote_owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Remote {
        machine_trust_domain: [0xA1; 32],
        device_route: [seed; 16],
        device_sign_fingerprint: [0xB2; 32],
    }
}

fn local_owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0xA1; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

fn daemon_boot_id(seed: u8) -> RuntimeId {
    runtime_id(RuntimeIdKind::DaemonBoot, seed)
}

#[derive(Debug)]
struct FailTerminateReplyOnce(AtomicBool);

impl FailTerminateReplyOnce {
    fn new() -> Self {
        Self(AtomicBool::new(true))
    }
}

impl RuntimeStoreFaultInjector for FailTerminateReplyOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::TerminateAcceptedCommandAfterCommit
            && self.0.swap(false, Ordering::SeqCst)
        {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FailCreateReplyOnce(AtomicBool);

impl FailCreateReplyOnce {
    fn new() -> Self {
        Self(AtomicBool::new(true))
    }
}

impl RuntimeStoreFaultInjector for FailCreateReplyOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::CreateConversationAfterCommit
            && self.0.swap(false, Ordering::SeqCst)
        {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FailStartedTerminationReplyOnce(AtomicBool);

impl FailStartedTerminationReplyOnce {
    fn new() -> Self {
        Self(AtomicBool::new(true))
    }
}

impl RuntimeStoreFaultInjector for FailStartedTerminationReplyOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::TerminateStartedBeforeReleaseAfterCommit
            && self.0.swap(false, Ordering::SeqCst)
        {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ScriptedCapacityProbe {
    observations: Arc<Mutex<VecDeque<RuntimeCapacityObservation>>>,
    fallback: RuntimeCapacityObservation,
}

impl ScriptedCapacityProbe {
    fn new(
        observations: impl IntoIterator<Item = RuntimeCapacityObservation>,
        fallback: RuntimeCapacityObservation,
    ) -> Self {
        Self {
            observations: Arc::new(Mutex::new(observations.into_iter().collect())),
            fallback,
        }
    }
}

impl RuntimeCapacityProbe for ScriptedCapacityProbe {
    fn observe(
        &self,
        _database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        Ok(self
            .observations
            .lock()
            .expect("capacity observations lock")
            .pop_front()
            .unwrap_or(self.fallback))
    }
}

fn healthy_observation() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        main_bytes: 8 * 1024 * 1024,
        wal_bytes: 2 * 1024 * 1024,
        shm_bytes: 32 * 1024,
        filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
        filesystem_available_bytes: 4 * 1024 * 1024 * 1024,
    }
}

fn over_limit_observation() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        main_bytes: 2 * 1024 * 1024 * 1024 + 1,
        wal_bytes: 0,
        shm_bytes: 0,
        filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
        filesystem_available_bytes: 4 * 1024 * 1024 * 1024,
    }
}

#[tokio::test]
async fn idempotent_create_distinguishes_a_cross_restart_replay() {
    let root = TestRoot::new("create-replay-restart");
    let keys = MemoryKeyStore::new();
    let input = conversation_input(0x11);
    let config = RuntimeStoreConfig::new(root.database());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open first store");

    let created = match store
        .create_conversation_idempotent(input.clone())
        .await
        .expect("create conversation with outcome")
    {
        CreateConversationOutcome::Created { conversation } => conversation,
        CreateConversationOutcome::Replayed { .. } => panic!("first create cannot replay"),
    };
    store.shutdown().await.expect("shutdown first store");

    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen store");
    let replayed = match reopened
        .create_conversation_idempotent(input.clone())
        .await
        .expect("retry persisted conversation")
    {
        CreateConversationOutcome::Replayed { conversation } => conversation,
        CreateConversationOutcome::Created { .. } => panic!("persisted retry must replay"),
    };
    assert_eq!(replayed, created);
    assert_eq!(
        reopened
            .create_conversation(input)
            .await
            .expect("legacy create API remains compatible"),
        created
    );
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn idempotent_create_commit_unknown_retry_reports_replayed() {
    let root = TestRoot::new("create-unknown-replay");
    let keys = MemoryKeyStore::new();
    let input = conversation_input(0x12);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_fault_injector(Arc::new(FailCreateReplyOnce::new())),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    assert!(matches!(
        store
            .create_conversation_idempotent(input.clone())
            .await
            .expect_err("post-commit reply failure is unknown"),
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::CreateConversation
        }
    ));
    assert!(matches!(
        store
            .create_conversation_idempotent(input)
            .await
            .expect("exact retry resolves unknown outcome"),
        CreateConversationOutcome::Replayed { .. }
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn accepted_and_recovered_commands_return_the_redacted_owner() {
    let root = TestRoot::new("owner-recovery");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create conversation");
    let owner = remote_owner(0x33);
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: owner.clone(),
            idempotency_key: "owner-recovery".to_owned(),
            payload: b"owner recovery prompt".to_vec(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };
    assert_eq!(command.owner, owner);
    assert_eq!(
        format!("{:?}", command.owner),
        "IdempotencyOwner([REDACTED])"
    );
    let command_debug = format!("{command:?}");
    assert!(!command_debug.contains("machine_trust_domain"));
    assert!(!command_debug.contains("device_sign_fingerprint"));

    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load paged recovery");
    assert_eq!(recovery.accepted.len(), 1);
    assert_eq!(recovery.accepted[0].owner, owner);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn accepted_cancel_commits_event_and_replays_without_double_decrement() {
    let root = TestRoot::new("accepted-cancel");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let owner = remote_owner(0x44);
    let (conversation, command) = create_and_accept(&store, 2, owner.clone(), "cancel-once").await;
    clock.set(20);
    let input = || TerminateAcceptedCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        expected_owner: owner.clone(),
        reason: AcceptedTerminationReason::Canceled,
    };

    let (terminated, event) = match store
        .terminate_accepted_command(input())
        .await
        .expect("cancel accepted command")
    {
        TerminateAcceptedOutcome::Transitioned { command, event } => (command, event),
        other => panic!("first cancel must transition, got {other:?}"),
    };
    assert_eq!(terminated.state, CommandState::Canceled);
    assert_eq!(terminated.owner, owner);
    assert_eq!(terminated.started_at_ms, None);
    assert_eq!(terminated.turn_id, None);
    assert_eq!(terminated.terminal_event_id, Some(event.event_id));
    assert_eq!(event.event_seq, 0);
    assert_eq!(
        String::from_utf8(event.payload.clone()).expect("accepted terminal event utf8"),
        format!(
            "{{\"commandId\":\"{}\",\"kind\":\"commandCanceledBeforeStart\"}}",
            command.command_id.to_canonical_string()
        )
    );

    assert!(matches!(
        store
            .terminate_accepted_command(input())
            .await
            .expect("retry accepted cancel"),
        TerminateAcceptedOutcome::Replayed { command: replay, event: replay_event }
            if replay.command_id == command.command_id && replay_event.event_id == event.event_id
    ));
    let mut conflict = input();
    conflict.reason = AcceptedTerminationReason::RevokedBeforeStart;
    assert!(matches!(
        store
            .terminate_accepted_command(conflict)
            .await
            .expect_err("a different typed terminal reason cannot replay"),
        RuntimeStoreError::InvalidStateTransition
    ));

    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load recovery after cancel replay");
    assert!(recovery.accepted.is_empty());
    assert_eq!(recovery.conversations[0].accepted_command_count, 0);
    assert_eq!(recovery.conversations[0].event_high_water, Some(0));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn revoked_before_start_reopens_and_replays_with_its_own_terminal_domain() {
    let root = TestRoot::new("revoked-reopen");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open store");
    let owner = remote_owner(0x55);
    let (conversation, command) = create_and_accept(&store, 3, owner.clone(), "revoke-once").await;
    clock.set(20);
    let input = || TerminateAcceptedCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        expected_owner: owner.clone(),
        reason: AcceptedTerminationReason::RevokedBeforeStart,
    };
    let event_id = match store
        .terminate_accepted_command(input())
        .await
        .expect("revoke accepted command")
    {
        TerminateAcceptedOutcome::Transitioned { command, event } => {
            assert_eq!(command.state, CommandState::RevokedBeforeStart);
            assert_eq!(command.turn_id, None);
            event.event_id
        }
        other => panic!("first revoke must transition, got {other:?}"),
    };
    store.shutdown().await.expect("shutdown first store");

    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen validates revoked terminal integrity");
    assert!(matches!(
        reopened
            .terminate_accepted_command(input())
            .await
            .expect("replay revoked command after reopen"),
        TerminateAcceptedOutcome::Replayed { command: replay, event }
            if replay.state == CommandState::RevokedBeforeStart && event.event_id == event_id
    ));
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn accepted_termination_checks_owner_and_reports_a_started_race() {
    let root = TestRoot::new("owner-and-start-race");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let owner = local_owner(0x21);
    let (conversation, command) = create_and_accept(&store, 4, owner.clone(), "start-race").await;
    let terminate = |expected_owner| TerminateAcceptedCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        expected_owner,
        reason: AcceptedTerminationReason::Canceled,
    };
    assert!(matches!(
        store
            .terminate_accepted_command(terminate(local_owner(0x22)))
            .await
            .expect_err("another owner cannot terminate the command"),
        RuntimeStoreError::CommandOwnerMismatch
    ));

    clock.set(20);
    assert!(matches!(
        store
            .mark_started_with_event(StartCommand {
                conversation_id: conversation.conversation_id,
                command_id: command.command_id,
                daemon_boot_id: daemon_boot_id(0x61),
                execution_nonce: b"start-race-nonce".to_vec(),
            })
            .await
            .expect("start wins race"),
        StartOutcome::Started { .. }
    ));
    assert!(matches!(
        store
            .terminate_accepted_command(terminate(owner))
            .await
            .expect("terminate observes started winner"),
        TerminateAcceptedOutcome::AlreadyStarted { command: started }
            if started.state == CommandState::Started
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn accepted_termination_after_commit_unknown_converges_by_exact_retry() {
    let root = TestRoot::new("terminate-commit-unknown");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(Arc::new(FailTerminateReplyOnce::new())),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let owner = local_owner(0x31);
    let (conversation, command) =
        create_and_accept(&store, 5, owner.clone(), "unknown-termination").await;
    clock.set(20);
    let input = || TerminateAcceptedCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        expected_owner: owner.clone(),
        reason: AcceptedTerminationReason::RevokedBeforeStart,
    };
    assert!(matches!(
        store
            .terminate_accepted_command(input())
            .await
            .expect_err("reply loss after commit must be unknown"),
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::TerminateAcceptedCommand
        }
    ));
    assert!(matches!(
        store
            .terminate_accepted_command(input())
            .await
            .expect("identical retry resolves unknown outcome"),
        TerminateAcceptedOutcome::Replayed { command: replay, .. }
            if replay.command_id == command.command_id
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn accepted_termination_is_fenced_during_recovery() {
    let root = TestRoot::new("terminate-recovery-fence");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let owner = local_owner(0x41);
    let (conversation, command) =
        create_and_accept(&store, 6, owner.clone(), "recovery-fence").await;
    let input = TerminateAcceptedCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        expected_owner: owner,
        reason: AcceptedTerminationReason::Canceled,
    };
    let cursor = store.begin_recovery_scan().await.expect("begin recovery");
    assert!(matches!(
        store
            .terminate_accepted_command(input)
            .await
            .expect_err("recovery must fence safety mutation"),
        RuntimeStoreError::RecoveryInProgress
    ));
    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load only recovery page");
    store
        .finish_recovery_scan(page.completion.expect("terminal recovery page"))
        .await
        .expect("finish recovery");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn accepted_termination_consumes_reserved_capacity_while_safety_only() {
    let root = TestRoot::new("terminate-safety-only");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let probe = ScriptedCapacityProbe::new(
        [
            healthy_observation(),
            healthy_observation(),
            healthy_observation(),
            over_limit_observation(),
        ],
        healthy_observation(),
    );
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_capacity_probe(probe),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let owner = local_owner(0x51);
    let (conversation, command) = create_and_accept(&store, 7, owner.clone(), "safety-only").await;
    assert!(matches!(
        store
            .create_conversation(conversation_input(8))
            .await
            .expect_err("post-commit capacity violation latches ordinary writes"),
        RuntimeStoreError::SafetyOnly
    ));
    clock.set(20);
    assert!(matches!(
        store
            .terminate_accepted_command(TerminateAcceptedCommand {
                conversation_id: conversation.conversation_id,
                command_id: command.command_id,
                expected_owner: owner,
                reason: AcceptedTerminationReason::Canceled,
            })
            .await
            .expect("reserved safety tail permits accepted termination"),
        TerminateAcceptedOutcome::Transitioned { .. }
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn compact_receipt_query_supports_both_selectors_and_verifies_owner() {
    let root = TestRoot::new("compact-receipt-query");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let owner = remote_owner(0x71);
    let (conversation, command) =
        create_and_accept(&store, 9, owner.clone(), "receipt-lookup").await;
    let by_command = QueryCommandReceipt {
        expected_owner: owner.clone(),
        selector: CommandReceiptSelector::Command {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
        },
    };
    let by_idempotency = QueryCommandReceipt {
        expected_owner: owner.clone(),
        selector: CommandReceiptSelector::Idempotency {
            conversation_id: conversation.conversation_id,
            idempotency_key: "receipt-lookup".to_owned(),
        },
    };
    let accepted = store
        .query_command_receipt(by_command.clone())
        .await
        .expect("query accepted command by id");
    assert_eq!(accepted.command_id, command.command_id);
    assert_eq!(accepted.state, CommandState::Accepted);
    assert_eq!(accepted.turn_id, None);
    assert_eq!(
        store
            .query_command_receipt(by_idempotency.clone())
            .await
            .expect("query accepted command by idempotency"),
        accepted
    );
    let receipt_debug = format!("{accepted:?}");
    assert!(!receipt_debug.contains("payload-receipt-lookup"));

    assert!(matches!(
        store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: remote_owner(0x72),
                ..by_command.clone()
            })
            .await
            .expect_err("command selector checks expected owner"),
        RuntimeStoreError::CommandOwnerMismatch
    ));
    assert!(matches!(
        store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: owner.clone(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: runtime_id(RuntimeIdKind::Conversation, 0x7f),
                    command_id: command.command_id,
                },
            })
            .await
            .expect_err("command selector checks conversation binding"),
        RuntimeStoreError::CommandNotFound
    ));
    assert!(matches!(
        store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: owner.clone(),
                selector: CommandReceiptSelector::Idempotency {
                    conversation_id: conversation.conversation_id,
                    idempotency_key: "missing-key".to_owned(),
                },
            })
            .await
            .expect_err("unknown idempotency key is not found"),
        RuntimeStoreError::CommandNotFound
    ));

    clock.set(20);
    let turn_id = match store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(0x73),
            execution_nonce: b"receipt-query-nonce".to_vec(),
        })
        .await
        .expect("start queried command")
    {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("first start cannot replay"),
    };
    let started = store
        .query_command_receipt(by_idempotency.clone())
        .await
        .expect("query started command");
    assert_eq!(started.state, CommandState::Started);
    assert_eq!(started.turn_id, Some(turn_id));

    let cursor = store.begin_recovery_scan().await.expect("begin recovery");
    assert_eq!(
        store
            .query_command_receipt(by_idempotency)
            .await
            .expect("receipt query remains available during recovery"),
        started
    );
    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load recovery page");
    store
        .finish_recovery_scan(page.completion.expect("terminal recovery page"))
        .await
        .expect("finish recovery");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn fenced_started_command_can_terminate_before_release_and_exactly_replay() {
    let root = TestRoot::new("started-before-release");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open store");
    let owner = local_owner(0x81);
    let (conversation, command) =
        create_and_accept(&store, 0x21, owner.clone(), "pre-release-cancel").await;
    let boot_id = daemon_boot_id(0x82);
    let nonce = b"pre-release-cancel-nonce".to_vec();
    clock.set(20);
    let turn_id = match store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id: boot_id,
            execution_nonce: nonce.clone(),
        })
        .await
        .expect("start command")
    {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("first start cannot replay"),
    };
    clock.set(30);
    assert!(matches!(
        store
            .persist_execution_fence(ExecutionFence {
                command_id: command.command_id,
                daemon_boot_id: boot_id,
                execution_nonce: nonce.clone(),
                process_group_id: 7001,
                leader_pid: 7001,
                leader_start_time: 0,
                payload: b"invalid-pid-reuse-proof".to_vec(),
            })
            .await
            .expect_err("zero leader start time cannot support exact orphan fencing"),
        RuntimeStoreError::InvalidConfig(_)
    ));
    store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id: boot_id,
            execution_nonce: nonce.clone(),
            process_group_id: 7001,
            leader_pid: 7001,
            leader_start_time: 7001,
            payload: b"confirmed-dead-process-group".to_vec(),
        })
        .await
        .expect("persist unreleased fence");
    let input = || TerminateStartedBeforeRelease {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        turn_id,
        daemon_boot_id: boot_id,
        execution_nonce: nonce.clone(),
        reason: StartedBeforeReleaseTermination::Canceled,
    };

    let (terminal, event_id) = match store
        .terminate_started_before_release(input())
        .await
        .expect("terminate fenced started command")
    {
        TerminateStartedBeforeReleaseOutcome::Transitioned { command, event } => {
            (command, event.event_id)
        }
        other => panic!("first termination must transition, got {other:?}"),
    };
    assert_eq!(terminal.state, CommandState::Canceled);
    assert_eq!(terminal.turn_id, Some(turn_id));
    assert!(matches!(
        store
            .terminate_started_before_release(input())
            .await
            .expect("exact retry"),
        TerminateStartedBeforeReleaseOutcome::Replayed { command, event }
            if command.command_id == terminal.command_id && event.event_id == event_id
    ));
    assert!(matches!(
        store
            .complete_command_with_event(CompleteCommand {
                conversation_id: conversation.conversation_id,
                command_id: command.command_id,
                turn_id,
                terminal: CommandTerminal::canceled(),
            })
            .await
            .expect_err("released completion cannot alias a before-release terminal"),
        RuntimeStoreError::TerminalConflict
    ));

    let mut conflict = input();
    conflict.execution_nonce = b"different-nonce".to_vec();
    assert!(matches!(
        store
            .terminate_started_before_release(conflict)
            .await
            .expect_err("nonce mismatch cannot replay terminal"),
        RuntimeStoreError::StartConflict
    ));
    store.shutdown().await.expect("shutdown first store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen validates fenced pre-release terminal integrity");
    reopened.inspect().await.expect("full integrity inspection");
    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("recover after fenced pre-release terminal");
    assert!(recovery.accepted.is_empty());
    assert!(recovery.started.is_empty());
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn started_before_release_commit_unknown_converges_by_exact_retry() {
    let root = TestRoot::new("started-before-release-unknown");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let config = RuntimeStoreConfig::new(root.database())
        .with_clock(clock.clone())
        .with_fault_injector(Arc::new(FailStartedTerminationReplyOnce::new()));
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open store");
    let owner = local_owner(0x83);
    let (conversation, command) =
        create_and_accept(&store, 0x22, owner, "pre-release-unknown").await;
    let boot_id = daemon_boot_id(0x84);
    let nonce = b"pre-release-unknown-nonce".to_vec();
    clock.set(20);
    let turn_id = match store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id: boot_id,
            execution_nonce: nonce.clone(),
        })
        .await
        .expect("start command")
    {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("first start cannot replay"),
    };
    clock.set(30);
    let input = || TerminateStartedBeforeRelease {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        turn_id,
        daemon_boot_id: boot_id,
        execution_nonce: nonce.clone(),
        reason: StartedBeforeReleaseTermination::Interrupted,
    };

    assert!(matches!(
        store
            .terminate_started_before_release(input())
            .await
            .expect_err("reply loss after commit is unknown"),
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::TerminateStartedBeforeRelease
        }
    ));
    assert!(matches!(
        store
            .terminate_started_before_release(input())
            .await
            .expect("exact retry resolves unknown outcome"),
        TerminateStartedBeforeReleaseOutcome::Replayed { command, .. }
            if command.state == CommandState::Interrupted
    ));
    store.shutdown().await.expect("shutdown first store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen validates no-fence pre-release terminal integrity");
    reopened.inspect().await.expect("full integrity inspection");
    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("recover after no-fence pre-release terminal");
    assert!(recovery.accepted.is_empty());
    assert!(recovery.started.is_empty());
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn durable_conversation_catalog_saturates_and_stays_bounded_after_restart() {
    fn input(index: u64) -> NewConversation {
        let bytes = u128::from(index + 1).to_be_bytes();
        NewConversation {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, bytes)
                .expect("bounded conversation id"),
            adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, bytes)
                .expect("bounded adapter state key"),
            descriptor: runtime_descriptor::descriptor(b"bounded-catalog"),
        }
    }

    let root = TestRoot::new("conversation-cap");
    let keys = MemoryKeyStore::new();
    let test_capacity = 4_u64;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_command_capacity(1_024)
            .with_conversation_capacity(test_capacity),
        root.storage_kek(&keys),
    )
    .await
    .expect("open bounded catalog store");
    for index in 0..test_capacity {
        store
            .create_conversation(input(index))
            .await
            .expect("conversation below durable hard limit");
    }
    store
        .inspect()
        .await
        .expect("full-integrity inspect at catalog limit");
    assert!(matches!(
        store
            .create_conversation(input(test_capacity))
            .await
            .expect_err("catalog entry above hard limit must fail closed"),
        RuntimeStoreError::ConversationLimit
    ));
    assert!(matches!(
        store
            .create_conversation_idempotent(input(0))
            .await
            .expect("exact replay remains available at capacity"),
        CreateConversationOutcome::Replayed { .. }
    ));
    store.shutdown().await.expect("shutdown full catalog");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_conversation_capacity(test_capacity),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen full catalog");
    reopened
        .inspect()
        .await
        .expect("inspect reopened full catalog");
    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("paged recovery remains bounded by catalog limit");
    assert_eq!(
        u64::try_from(recovery.conversations.len()).expect("conversation count fits u64"),
        test_capacity
    );
    assert!(matches!(
        reopened
            .create_conversation(input(test_capacity))
            .await
            .expect_err("restart cannot reset durable catalog bound"),
        RuntimeStoreError::ConversationLimit
    ));
    reopened.shutdown().await.expect("shutdown reopened store");
}
