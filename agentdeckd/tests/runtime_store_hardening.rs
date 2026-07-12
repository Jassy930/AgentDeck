#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentdeckd::runtime::model::{
    AuthorizeExecutionRelease, COMMAND_QUEUE_TTL_MS, RuntimeClock, RuntimeClockError,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, CommandRecord, CommandState, CompleteCommand, CompleteOutcome,
    ExecutionFence, ExecutionIntentRecord, IdempotencyOwner, MachineEnrollmentReceiptRecord,
    NewConversation, RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
    StartCommand, StartOutcome, TerminalState,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, OpenFlags, params};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-hardening-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create hardening root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure hardening root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load hardening StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn conversation_input(seed: u8, descriptor: &[u8]) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: descriptor.to_vec(),
    }
}

fn local_owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x10; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

async fn create_conversation(
    store: &RuntimeStoreHandle,
    seed: u8,
    descriptor: &[u8],
) -> agentdeckd::runtime::store::ConversationRecord {
    store
        .create_conversation(conversation_input(seed, descriptor))
        .await
        .expect("create conversation")
}

async fn accept_new(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    owner: IdempotencyOwner,
    idempotency_key: &str,
    payload: &[u8],
) -> CommandRecord {
    match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner,
            idempotency_key: idempotency_key.to_owned(),
            payload: payload.to_vec(),
        })
        .await
        .expect("accept new command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh idempotency key cannot replay"),
    }
}

async fn start_new(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    nonce: &[u8],
    intent_payload: &[u8],
    event_payload: &[u8],
) -> ExecutionIntentRecord {
    match store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id,
            execution_nonce: nonce.to_vec(),
            intent_payload: intent_payload.to_vec(),
            event_payload: event_payload.to_vec(),
        })
        .await
        .expect("start command")
    {
        StartOutcome::Started { intent, .. } => intent,
        StartOutcome::Replayed { .. } => panic!("fresh start cannot replay"),
    }
}

fn fence_input(
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    nonce: &[u8],
    seed: i64,
    payload: &[u8],
) -> ExecutionFence {
    ExecutionFence {
        command_id,
        daemon_boot_id,
        execution_nonce: nonce.to_vec(),
        process_group_id: 4_000 + seed,
        leader_pid: 5_000 + seed,
        leader_start_time: 6_000 + u64::try_from(seed).expect("positive test seed"),
        payload: payload.to_vec(),
    }
}

fn release_input(
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    nonce: &[u8],
) -> AuthorizeExecutionRelease {
    AuthorizeExecutionRelease {
        command_id,
        daemon_boot_id,
        execution_nonce: nonce.to_vec(),
    }
}

fn complete_input(
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    terminal_payload: &[u8],
    event_payload: &[u8],
) -> CompleteCommand {
    CompleteCommand {
        conversation_id,
        command_id,
        turn_id,
        terminal_state: TerminalState::Completed,
        terminal_payload: terminal_payload.to_vec(),
        event_payload: event_payload.to_vec(),
    }
}

async fn create_completed_audit_fixture(root: &TestRoot, keys: &MemoryKeyStore, seed: u8) {
    let clock = ManualClock::new(1);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(keys),
    )
    .await
    .expect("open completed audit fixture");
    let conversation = create_conversation(&store, seed, b"terminal audit fixture").await;
    clock.set(10);
    let command = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(seed),
        "terminal-audit",
        b"prompt",
    )
    .await;
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(0x20));
    clock.set(20);
    let intent = start_new(
        &store,
        conversation.conversation_id,
        command.command_id,
        daemon_boot_id,
        b"audit-nonce",
        b"audit-intent",
        b"audit-start-event",
    )
    .await;
    store
        .persist_execution_fence(fence_input(
            command.command_id,
            daemon_boot_id,
            b"audit-nonce",
            i64::from(seed),
            b"audit-fence",
        ))
        .await
        .expect("persist audit fence");
    clock.set(30);
    store
        .authorize_execution_release(release_input(
            command.command_id,
            daemon_boot_id,
            b"audit-nonce",
        ))
        .await
        .expect("authorize audit release");
    clock.set(40);
    store
        .complete_command_with_event(complete_input(
            conversation.conversation_id,
            command.command_id,
            intent.turn_id,
            b"audit-result",
            b"audit-terminal-event",
        ))
        .await
        .expect("complete audit fixture");
    store
        .shutdown()
        .await
        .expect("shutdown completed audit fixture");
}

fn read_only_database(path: &Path) -> Connection {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open runtime database read-only")
}

fn event_count(path: &Path) -> u64 {
    read_only_database(path)
        .query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))
        .expect("count journal events")
}

fn assert_no_sentinels(database: &Path, sentinels: &[&[u8]]) {
    for path in [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ] {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        for sentinel in sentinels {
            assert!(!sentinel.is_empty(), "sentinel must be non-empty");
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|window| window == *sentinel),
                "plaintext sentinel leaked into {}: {}",
                path.display(),
                String::from_utf8_lossy(sentinel)
            );
        }
    }
}

#[derive(Debug)]
struct FailOperationsOnce {
    remaining: Mutex<Vec<RuntimeStoreOperation>>,
}

impl FailOperationsOnce {
    fn new(operations: Vec<RuntimeStoreOperation>) -> Self {
        Self {
            remaining: Mutex::new(operations),
        }
    }
}

impl RuntimeStoreFaultInjector for FailOperationsOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        let mut remaining = self.remaining.lock().expect("lock remaining faults");
        if let Some(position) = remaining
            .iter()
            .position(|candidate| *candidate == operation)
        {
            remaining.remove(position);
            Err(RuntimeStoreError::InvalidConfig(
                "injected hardening after-commit fault",
            ))
        } else {
            Ok(())
        }
    }
}

struct BlockingObservedFault {
    target: RuntimeStoreOperation,
    armed: AtomicBool,
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
    observed: Mutex<Vec<RuntimeStoreOperation>>,
}

impl BlockingObservedFault {
    fn new(target: RuntimeStoreOperation, entered: SyncSender<()>, release: Receiver<()>) -> Self {
        Self {
            target,
            armed: AtomicBool::new(false),
            entered,
            release: Mutex::new(release),
            observed: Mutex::new(Vec::new()),
        }
    }

    fn arm_and_clear(&self) {
        self.observed.lock().expect("clear observations").clear();
        self.armed.store(true, Ordering::SeqCst);
    }

    fn observed(&self) -> Vec<RuntimeStoreOperation> {
        self.observed.lock().expect("read observations").clone()
    }
}

impl std::fmt::Debug for BlockingObservedFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlockingObservedFault")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl RuntimeStoreFaultInjector for BlockingObservedFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        self.observed
            .lock()
            .expect("record operation")
            .push(operation);
        if operation == self.target && self.armed.swap(false, Ordering::SeqCst) {
            self.entered
                .send(())
                .map_err(|_| RuntimeStoreError::WorkerStopped)?;
            self.release
                .lock()
                .map_err(|_| RuntimeStoreError::WorkerStopped)?
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| RuntimeStoreError::WorkerStopped)?;
        }
        Ok(())
    }
}

fn assert_commit_unknown(error: RuntimeStoreError, expected: RuntimeCommitOperation) {
    assert!(
        matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown { operation } if operation == expected
        ),
        "expected CommitOutcomeUnknown({expected:?}), got {error:?}"
    );
}

#[tokio::test]
async fn caller_owned_conversation_ids_make_after_commit_retry_exact_and_conflicts_typed() {
    let root = TestRoot::new("conversation-commit-unknown");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let faults = Arc::new(FailOperationsOnce::new(vec![
        RuntimeStoreOperation::CreateConversationAfterCommit,
    ]));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock)
            .with_fault_injector(faults),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    let error = store
        .create_conversation(conversation_input(1, b"stable descriptor"))
        .await
        .expect_err("reply after committed create is unknown");
    assert_commit_unknown(error, RuntimeCommitOperation::CreateConversation);

    let replay = store
        .create_conversation(conversation_input(1, b"stable descriptor"))
        .await
        .expect("same stable create retries exactly");
    assert_eq!(
        replay.conversation_id,
        runtime_id(RuntimeIdKind::Conversation, 1)
    );
    assert_eq!(
        replay.adapter_state_key,
        runtime_id(RuntimeIdKind::AdapterState, 0x41)
    );
    assert_eq!(replay.catalog_revision, 0);

    let descriptor_conflict = store
        .create_conversation(conversation_input(1, b"different descriptor"))
        .await
        .expect_err("same stable ids with different descriptor conflict");
    assert!(matches!(
        descriptor_conflict,
        RuntimeStoreError::ConversationConflict
    ));

    let adapter_conflict = store
        .create_conversation(NewConversation {
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x42),
            ..conversation_input(1, b"stable descriptor")
        })
        .await
        .expect_err("same conversation id cannot change adapter state key");
    assert!(matches!(
        adapter_conflict,
        RuntimeStoreError::ConversationConflict
    ));

    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load recovery");
    assert_eq!(recovery.conversations.len(), 1);
    assert_eq!(recovery.conversations[0], replay);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn every_side_effect_after_commit_unknown_has_an_exact_retry() {
    let root = TestRoot::new("all-after-commit-retries");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let faults = Arc::new(FailOperationsOnce::new(vec![
        RuntimeStoreOperation::RecordEnrollmentReceiptAfterCommit,
        RuntimeStoreOperation::AcceptCommandAfterCommit,
        RuntimeStoreOperation::StartCommandAfterCommit,
        RuntimeStoreOperation::PersistFenceAfterCommit,
        RuntimeStoreOperation::AuthorizeExecutionReleaseAfterCommit,
        RuntimeStoreOperation::CompleteCommandAfterCommit,
    ]));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(faults),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let receipt = MachineEnrollmentReceiptRecord {
        relay_server_id: [0x11; 16],
        machine_route: [0x22; 16],
        root_fingerprint: [0x33; 32],
    };
    let error = store
        .record_machine_enrollment_receipt(receipt.clone())
        .await
        .expect_err("receipt commit reply is unknown");
    assert_commit_unknown(error, RuntimeCommitOperation::RecordEnrollmentReceipt);
    assert_eq!(
        store
            .record_machine_enrollment_receipt(receipt.clone())
            .await
            .expect("receipt exact retry"),
        receipt
    );
    let conversation = create_conversation(&store, 2, b"retry conversation").await;

    clock.set(10);
    let accept = || AcceptCommand {
        conversation_id: conversation.conversation_id,
        owner: local_owner(1),
        idempotency_key: "after-commit-accept".to_owned(),
        payload: b"accepted payload".to_vec(),
    };
    let error = store
        .accept_command(accept())
        .await
        .expect_err("accepted commit reply is unknown");
    assert_commit_unknown(error, RuntimeCommitOperation::AcceptCommand);
    let command = match store
        .accept_command(accept())
        .await
        .expect("accept exact retry")
    {
        AcceptOutcome::Replayed { command } => command,
        AcceptOutcome::Accepted { .. } => panic!("committed accept must replay"),
    };

    clock.set(20);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x70);
    let start = || StartCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        daemon_boot_id,
        execution_nonce: b"after-commit-nonce".to_vec(),
        intent_payload: b"after-commit-intent".to_vec(),
        event_payload: b"after-commit-start-event".to_vec(),
    };
    let error = store
        .mark_started_with_event(start())
        .await
        .expect_err("start commit reply is unknown");
    assert_commit_unknown(error, RuntimeCommitOperation::StartCommand);
    let intent = match store
        .mark_started_with_event(start())
        .await
        .expect("start exact retry")
    {
        StartOutcome::Replayed { intent, .. } => intent,
        StartOutcome::Started { .. } => panic!("committed start must replay"),
    };

    let fence = || {
        fence_input(
            command.command_id,
            daemon_boot_id,
            b"after-commit-nonce",
            1,
            b"after-commit-fence",
        )
    };
    let error = store
        .persist_execution_fence(fence())
        .await
        .expect_err("fence commit reply is unknown");
    assert_commit_unknown(error, RuntimeCommitOperation::PersistFence);
    let persisted_fence = store
        .persist_execution_fence(fence())
        .await
        .expect("fence exact retry");

    clock.set(30);
    let release = || release_input(command.command_id, daemon_boot_id, b"after-commit-nonce");
    let error = store
        .authorize_execution_release(release())
        .await
        .expect_err("release authorization commit reply is unknown");
    assert_commit_unknown(error, RuntimeCommitOperation::AuthorizeExecutionRelease);
    let released_fence = store
        .authorize_execution_release(release())
        .await
        .expect("release authorization exact retry");
    assert_eq!(released_fence.command_id, persisted_fence.command_id);
    assert_eq!(released_fence.release_authorized_at_ms, Some(30));

    clock.set(40);
    let complete = || {
        complete_input(
            conversation.conversation_id,
            command.command_id,
            intent.turn_id,
            b"after-commit-result",
            b"after-commit-terminal-event",
        )
    };
    let error = store
        .complete_command_with_event(complete())
        .await
        .expect_err("completion commit reply is unknown");
    assert_commit_unknown(error, RuntimeCommitOperation::CompleteCommand);
    assert!(matches!(
        store
            .complete_command_with_event(complete())
            .await
            .expect("completion exact retry"),
        CompleteOutcome::Replayed { command, .. }
            if command.command_id == persisted_fence.command_id
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn expiry_after_commit_unknown_converges_through_the_identical_outer_accept_retry() {
    let root = TestRoot::new("expiry-after-commit-retry");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let faults = Arc::new(FailOperationsOnce::new(vec![
        RuntimeStoreOperation::ExpireCommandsAfterCommit,
    ]));
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone())
            .with_clock(clock.clone())
            .with_fault_injector(faults),
        root.storage_kek(&keys),
    )
    .await
    .expect("open expiry retry store");
    let conversation = create_conversation(&store, 0x31, b"expiry retry").await;
    clock.set(10);
    let expired = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(1),
        "will-expire",
        b"old prompt",
    )
    .await;
    clock.set(10 + COMMAND_QUEUE_TTL_MS);
    let retry = || AcceptCommand {
        conversation_id: conversation.conversation_id,
        owner: local_owner(2),
        idempotency_key: "outer-exact-retry".to_owned(),
        payload: b"new prompt".to_vec(),
    };
    let error = store
        .accept_command(retry())
        .await
        .expect_err("expiry committed before its reply was lost");
    assert_commit_unknown(error, RuntimeCommitOperation::ExpireCommands);
    let accepted = match store
        .accept_command(retry())
        .await
        .expect("identical outer accept retry converges")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("outer accept was not committed yet"),
    };
    assert_ne!(accepted.command_id, expired.command_id);
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load canonical expiry result");
    assert_eq!(recovery.accepted.len(), 1);
    assert_eq!(recovery.accepted[0].command_id, accepted.command_id);
    assert_eq!(recovery.conversations[0].event_high_water, Some(0));
    assert_eq!(
        event_count(&database),
        1,
        "expiry event must be canonical once"
    );
    store.shutdown().await.expect("shutdown expiry retry store");
}

#[tokio::test]
async fn every_before_commit_fault_rolls_back_and_first_retry_commits_once() {
    let root = TestRoot::new("all-before-commit-rollbacks");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let faults = Arc::new(FailOperationsOnce::new(vec![
        RuntimeStoreOperation::RecordEnrollmentReceiptBeforeCommit,
        RuntimeStoreOperation::CreateConversationBeforeCommit,
        RuntimeStoreOperation::AcceptCommandBeforeCommit,
        RuntimeStoreOperation::StartCommandBeforeCommit,
        RuntimeStoreOperation::PersistFenceBeforeCommit,
        RuntimeStoreOperation::AuthorizeExecutionReleaseBeforeCommit,
        RuntimeStoreOperation::CompleteCommandBeforeCommit,
    ]));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(faults),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    let receipt = MachineEnrollmentReceiptRecord {
        relay_server_id: [0x44; 16],
        machine_route: [0x55; 16],
        root_fingerprint: [0x66; 32],
    };
    assert!(matches!(
        store
            .record_machine_enrollment_receipt(receipt.clone())
            .await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    assert_eq!(
        store
            .record_machine_enrollment_receipt(receipt.clone())
            .await
            .expect("receipt retry commits once"),
        receipt
    );

    let conversation = conversation_input(0x21, b"rollback conversation");
    assert!(matches!(
        store.create_conversation(conversation.clone()).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    let conversation = store
        .create_conversation(conversation)
        .await
        .expect("create retry commits once");
    assert_eq!(conversation.catalog_revision, 0);

    clock.set(10);
    let accept = || AcceptCommand {
        conversation_id: conversation.conversation_id,
        owner: local_owner(0x21),
        idempotency_key: "rollback-accept".to_owned(),
        payload: b"rollback prompt".to_vec(),
    };
    assert!(matches!(
        store.accept_command(accept()).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    let command = match store
        .accept_command(accept())
        .await
        .expect("accept retry commits once")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("rolled-back accept cannot replay"),
    };
    assert_eq!(command.command_seq, 0);

    clock.set(20);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x79);
    let start = || StartCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        daemon_boot_id,
        execution_nonce: b"rollback-nonce".to_vec(),
        intent_payload: b"rollback-intent".to_vec(),
        event_payload: b"rollback-start-event".to_vec(),
    };
    assert!(matches!(
        store.mark_started_with_event(start()).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("start rollback recovery");
    assert_eq!(recovery.accepted.len(), 1);
    assert!(recovery.started.is_empty());
    let intent = match store
        .mark_started_with_event(start())
        .await
        .expect("start retry commits once")
    {
        StartOutcome::Started { intent, event, .. } => {
            assert_eq!(event.event_seq, 0);
            intent
        }
        StartOutcome::Replayed { .. } => panic!("rolled-back start cannot replay"),
    };

    let fence = || {
        fence_input(
            command.command_id,
            daemon_boot_id,
            b"rollback-nonce",
            9,
            b"rollback-fence",
        )
    };
    assert!(matches!(
        store.persist_execution_fence(fence()).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    let persisted = store
        .persist_execution_fence(fence())
        .await
        .expect("fence retry commits once");
    assert_eq!(persisted.release_authorized_at_ms, None);

    clock.set(30);
    let release = || release_input(command.command_id, daemon_boot_id, b"rollback-nonce");
    assert!(matches!(
        store.authorize_execution_release(release()).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    let still_blocked = store
        .persist_execution_fence(fence())
        .await
        .expect("release rollback leaves the fence unreleased");
    assert_eq!(still_blocked.release_authorized_at_ms, None);
    store
        .authorize_execution_release(release())
        .await
        .expect("release retry commits once");

    clock.set(40);
    let complete = || {
        complete_input(
            conversation.conversation_id,
            command.command_id,
            intent.turn_id,
            b"rollback-result",
            b"rollback-terminal-event",
        )
    };
    assert!(matches!(
        store.complete_command_with_event(complete()).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("completion rollback recovery");
    assert_eq!(recovery.started.len(), 1);
    assert!(matches!(
        store
            .complete_command_with_event(complete())
            .await
            .expect("completion retry commits once"),
        CompleteOutcome::Completed { event, .. } if event.event_seq == 1
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn completion_requires_matching_fence_and_persisted_release_authorization() {
    let root = TestRoot::new("completion-release-gate");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, 3, b"release gate").await;
    clock.set(10);
    let command = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(1),
        "release-gate-command",
        b"prompt",
    )
    .await;
    clock.set(20);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x71);
    let intent = start_new(
        &store,
        conversation.conversation_id,
        command.command_id,
        daemon_boot_id,
        b"release-gate-nonce",
        b"intent",
        b"start event",
    )
    .await;

    clock.set(30);
    let completion = || {
        complete_input(
            conversation.conversation_id,
            command.command_id,
            intent.turn_id,
            b"result",
            b"terminal event",
        )
    };
    let without_fence = store
        .complete_command_with_event(completion())
        .await
        .expect_err("completion without execution fence must fail");
    assert!(matches!(
        without_fence,
        RuntimeStoreError::ExecutionFenceMissing
    ));

    store
        .persist_execution_fence(fence_input(
            command.command_id,
            daemon_boot_id,
            b"release-gate-nonce",
            2,
            b"fence",
        ))
        .await
        .expect("persist matching fence");
    let without_release = store
        .complete_command_with_event(completion())
        .await
        .expect_err("completion before durable release authorization must fail");
    assert!(matches!(
        without_release,
        RuntimeStoreError::ExecutionReleaseMissing
    ));

    let wrong_release = store
        .authorize_execution_release(release_input(
            command.command_id,
            daemon_boot_id,
            b"wrong-release-nonce",
        ))
        .await
        .expect_err("release must match persisted execution nonce");
    assert!(matches!(wrong_release, RuntimeStoreError::FenceConflict));

    let released = store
        .authorize_execution_release(release_input(
            command.command_id,
            daemon_boot_id,
            b"release-gate-nonce",
        ))
        .await
        .expect("persist release authorization");
    assert_eq!(released.release_authorized_at_ms, Some(30));
    assert!(matches!(
        store
            .complete_command_with_event(completion())
            .await
            .expect("released execution may complete"),
        CompleteOutcome::Completed { .. }
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn forged_release_time_and_shape_valid_token_fail_closed() {
    let root = TestRoot::new("forged-release-token");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, 0x31, b"forged release").await;
    clock.set(10);
    let command = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(0x31),
        "forged-release",
        b"prompt",
    )
    .await;
    clock.set(20);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x7a);
    start_new(
        &store,
        conversation.conversation_id,
        command.command_id,
        daemon_boot_id,
        b"forged-release-nonce",
        b"intent",
        b"started",
    )
    .await;
    store
        .persist_execution_fence(fence_input(
            command.command_id,
            daemon_boot_id,
            b"forged-release-nonce",
            11,
            b"fence",
        ))
        .await
        .expect("persist unreleased fence");
    store.shutdown().await.expect("shutdown store");

    let connection = Connection::open(&database).expect("open tamper fixture");
    connection
        .execute(
            "UPDATE execution_fences
             SET release_authorized_at_ms = 30, release_token = ?1
             WHERE command_id = ?2",
            params![vec![0xA5_u8; 32], &command.command_id.as_bytes()[..]],
        )
        .expect("forge shape-valid release metadata");
    drop(connection);

    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("forged release metadata must fail during open-time integrity validation");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
}

#[tokio::test]
async fn intent_and_fence_plain_metadata_tamper_fail_closed_against_sealed_fields() {
    {
        let root = TestRoot::new("intent-metadata-tamper");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(1);
        let database = root.database();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open intent tamper store");
        let conversation = create_conversation(&store, 0x41, b"intent metadata").await;
        clock.set(10);
        let command = accept_new(
            &store,
            conversation.conversation_id,
            local_owner(0x41),
            "intent-metadata",
            b"prompt",
        )
        .await;
        clock.set(20);
        start_new(
            &store,
            conversation.conversation_id,
            command.command_id,
            runtime_id(RuntimeIdKind::DaemonBoot, 0x71),
            b"intent-metadata-nonce",
            b"intent",
            b"started",
        )
        .await;
        store.shutdown().await.expect("shutdown intent store");

        let connection = Connection::open(&database).expect("open intent tamper fixture");
        connection
            .execute(
                "UPDATE execution_intents SET created_at_ms = created_at_ms + 1
                 WHERE command_id = ?1",
                [&command.command_id.as_bytes()[..]],
            )
            .expect("tamper authenticated intent timestamp");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database).with_clock(clock),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("intent metadata tamper must fail during open-time integrity validation");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }

    {
        let root = TestRoot::new("fence-metadata-tamper");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(1);
        let database = root.database();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open fence tamper store");
        let conversation = create_conversation(&store, 0x42, b"fence metadata").await;
        clock.set(10);
        let command = accept_new(
            &store,
            conversation.conversation_id,
            local_owner(0x42),
            "fence-metadata",
            b"prompt",
        )
        .await;
        clock.set(20);
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x72);
        start_new(
            &store,
            conversation.conversation_id,
            command.command_id,
            daemon_boot_id,
            b"fence-metadata-nonce",
            b"intent",
            b"started",
        )
        .await;
        store
            .persist_execution_fence(fence_input(
                command.command_id,
                daemon_boot_id,
                b"fence-metadata-nonce",
                12,
                b"fence",
            ))
            .await
            .expect("persist authenticated fence");
        store.shutdown().await.expect("shutdown fence store");

        let connection = Connection::open(&database).expect("open fence tamper fixture");
        connection
            .execute(
                "UPDATE execution_fences SET process_group_id = process_group_id + 1
                 WHERE command_id = ?1",
                [&command.command_id.as_bytes()[..]],
            )
            .expect("tamper authenticated fence process group");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database).with_clock(clock),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("fence metadata tamper must fail during open-time integrity validation");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }
}

#[tokio::test]
async fn authenticated_command_conversation_event_and_runtime_ledger_metadata_tamper_fail_closed() {
    // Command ordering metadata remains syntactically valid, but its old MAC must not authorize it.
    {
        let root = TestRoot::new("command-metadata-token-tamper");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open command metadata store");
        let conversation = create_conversation(&store, 0x41, b"command metadata").await;
        accept_new(
            &store,
            conversation.conversation_id,
            local_owner(1),
            "command-metadata",
            b"prompt",
        )
        .await;
        store
            .shutdown()
            .await
            .expect("shutdown before command tamper");
        let connection = Connection::open(root.database()).expect("open command tamper DB");
        connection
            .execute(
                "UPDATE commands SET command_seq = '00000000000000000001'",
                [],
            )
            .expect("tamper command sequence without its MAC");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint command tamper");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("command metadata tamper must fail at open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }

    // Catalog lifecycle is canonical ordering/state metadata, not an unauthenticated hint.
    {
        let root = TestRoot::new("conversation-metadata-token-tamper");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open conversation metadata store");
        create_conversation(&store, 0x42, b"conversation metadata").await;
        store
            .shutdown()
            .await
            .expect("shutdown before conversation tamper");
        let connection = Connection::open(root.database()).expect("open conversation tamper DB");
        connection
            .execute("UPDATE conversations SET lifecycle = 'archived'", [])
            .expect("tamper conversation lifecycle without its MAC");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint conversation tamper");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("conversation metadata tamper must fail at open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }

    // Event sequence is independently MAC-bound even when its SQL representation is shape-valid.
    {
        let root = TestRoot::new("event-metadata-token-tamper");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open event metadata store");
        let conversation = create_conversation(&store, 0x43, b"event metadata").await;
        let command = accept_new(
            &store,
            conversation.conversation_id,
            local_owner(1),
            "event-metadata",
            b"prompt",
        )
        .await;
        start_new(
            &store,
            conversation.conversation_id,
            command.command_id,
            runtime_id(RuntimeIdKind::DaemonBoot, 0x73),
            b"event-nonce",
            b"intent",
            b"event",
        )
        .await;
        store
            .shutdown()
            .await
            .expect("shutdown before event tamper");
        let connection = Connection::open(root.database()).expect("open event tamper DB");
        connection
            .execute(
                "UPDATE event_journal SET event_seq = '00000000000000000001'",
                [],
            )
            .expect("tamper event sequence without its MAC");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint event tamper");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("event metadata tamper must fail at open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }

    // Capacity reserve counters are authenticated facts; raw SQL cannot lower them.
    {
        let root = TestRoot::new("runtime-ledger-token-tamper");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open runtime ledger store");
        let conversation = create_conversation(&store, 0x44, b"runtime ledger").await;
        accept_new(
            &store,
            conversation.conversation_id,
            local_owner(1),
            "ledger-metadata",
            b"prompt",
        )
        .await;
        store
            .shutdown()
            .await
            .expect("shutdown before ledger tamper");
        let connection = Connection::open(root.database()).expect("open ledger tamper DB");
        connection
            .execute("UPDATE runtime_meta SET accepted_count = 0", [])
            .expect("tamper runtime ledger without its MAC");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint ledger tamper");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("runtime ledger tamper must fail at open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }
}

#[tokio::test]
async fn deleting_any_terminal_intent_fence_or_event_audit_row_fails_closed_at_open() {
    for (index, table) in ["execution_intents", "execution_fences", "event_journal"]
        .into_iter()
        .enumerate()
    {
        let root = TestRoot::new(table);
        let keys = MemoryKeyStore::new();
        create_completed_audit_fixture(
            &root,
            &keys,
            0x51_u8.wrapping_add(u8::try_from(index).expect("small audit index")),
        )
        .await;
        let connection = Connection::open(root.database()).expect("open audit tamper DB");
        connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .expect("disable fixture foreign keys");
        let deleted = connection
            .execute(&format!("DELETE FROM {table}"), [])
            .expect("delete terminal audit rows");
        assert!(deleted > 0, "fixture must contain {table} rows");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint audit deletion");
        drop(connection);

        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("missing terminal audit row must fail at open");
        assert!(
            matches!(error, RuntimeStoreError::UnknownOrCorruptSchema),
            "{table} deletion returned {error:?}"
        );
    }
}

#[tokio::test]
async fn authenticated_total_counts_detect_empty_catalog_and_whole_terminal_group_deletion() {
    {
        let root = TestRoot::new("empty-conversation-deletion");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open catalog deletion store");
        let deleted = create_conversation(&store, 0x61, b"delete this empty row").await;
        create_conversation(&store, 0x62, b"keep max catalog row").await;
        store.shutdown().await.expect("shutdown catalog fixture");
        let connection = Connection::open(root.database()).expect("open catalog tamper DB");
        connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .expect("disable fixture foreign keys");
        assert_eq!(
            connection
                .execute(
                    "DELETE FROM conversations WHERE conversation_id = ?1",
                    [&deleted.conversation_id.as_bytes()[..]],
                )
                .expect("delete non-max empty conversation"),
            1
        );
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint catalog deletion");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("authenticated conversation_count must detect deletion");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }

    {
        let root = TestRoot::new("whole-terminal-group-deletion");
        let keys = MemoryKeyStore::new();
        create_completed_audit_fixture(&root, &keys, 0x63).await;
        let connection = Connection::open(root.database()).expect("open terminal group tamper DB");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 DELETE FROM event_journal;
                 DELETE FROM execution_fences;
                 DELETE FROM execution_intents;
                 DELETE FROM commands;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .expect("delete internally self-consistent terminal group");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("authenticated table totals must detect terminal group deletion");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }
}

#[tokio::test]
async fn untouched_conversation_descriptor_ciphertext_is_authenticated_during_open_scan() {
    let root = TestRoot::new("descriptor-open-scan-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open descriptor tamper store");
    create_conversation(&store, 0x64, b"descriptor must authenticate at open").await;
    store.shutdown().await.expect("shutdown descriptor fixture");
    let connection = Connection::open(root.database()).expect("open descriptor tamper DB");
    connection
        .execute(
            "UPDATE conversations
             SET sealed_descriptor = zeroblob(length(sealed_descriptor))",
            [],
        )
        .expect("replace descriptor ciphertext with same-length invalid blob");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint descriptor tamper");
    drop(connection);
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("descriptor corruption must fail during open-time full scan");
    assert!(matches!(error, RuntimeStoreError::Cipher(_)));
}

#[tokio::test]
async fn an_older_valid_conversation_metadata_mac_cannot_roll_back_event_high_water() {
    let root = TestRoot::new("conversation-hwm-valid-mac-rollback");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open HWM rollback store");
    let conversation = create_conversation(&store, 0x65, b"HWM rollback").await;
    clock.set(10);
    let command = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(1),
        "hwm-rollback",
        b"prompt",
    )
    .await;
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x75);
    clock.set(20);
    let intent = start_new(
        &store,
        conversation.conversation_id,
        command.command_id,
        daemon_boot_id,
        b"hwm-nonce",
        b"intent",
        b"started",
    )
    .await;
    let old_metadata: (Option<String>, i64, Vec<u8>) = Connection::open(&database)
        .expect("open live HWM snapshot reader")
        .query_row(
            "SELECT event_high_water, updated_at_ms, metadata_token
             FROM conversations WHERE conversation_id = ?1",
            [&conversation.conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("capture older valid conversation metadata");
    assert_eq!(old_metadata.0.as_deref(), Some("00000000000000000000"));
    store
        .persist_execution_fence(fence_input(
            command.command_id,
            daemon_boot_id,
            b"hwm-nonce",
            7,
            b"fence",
        ))
        .await
        .expect("persist HWM fixture fence");
    clock.set(30);
    store
        .authorize_execution_release(release_input(
            command.command_id,
            daemon_boot_id,
            b"hwm-nonce",
        ))
        .await
        .expect("authorize HWM fixture release");
    clock.set(40);
    store
        .complete_command_with_event(complete_input(
            conversation.conversation_id,
            command.command_id,
            intent.turn_id,
            b"result",
            b"terminal",
        ))
        .await
        .expect("complete HWM fixture");
    store.shutdown().await.expect("shutdown HWM fixture");

    let connection = Connection::open(&database).expect("open HWM rollback DB");
    assert_eq!(
        connection
            .execute(
                "UPDATE conversations
                 SET event_high_water = ?1, updated_at_ms = ?2, metadata_token = ?3
                 WHERE conversation_id = ?4",
                params![
                    old_metadata.0,
                    old_metadata.1,
                    old_metadata.2,
                    &conversation.conversation_id.as_bytes()[..],
                ],
            )
            .expect("restore older valid conversation metadata row"),
        1
    );
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint valid-MAC HWM rollback");
    drop(connection);
    let error =
        RuntimeStoreHandle::open(RuntimeStoreConfig::new(database), root.storage_kek(&keys))
            .await
            .expect_err("actual event MAX must reject older valid HWM metadata");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
}

#[tokio::test]
async fn recovery_finish_revalidates_external_changes_before_reopening_mutations() {
    let root = TestRoot::new("recovery-finish-revalidation");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open recovery revalidation store");
    let conversation = create_conversation(&store, 0x66, b"finish revalidation").await;
    clock.set(10);
    let command = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(1),
        "finish-revalidation",
        b"prompt",
    )
    .await;
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x76);
    clock.set(20);
    let intent = start_new(
        &store,
        conversation.conversation_id,
        command.command_id,
        daemon_boot_id,
        b"finish-nonce",
        b"intent",
        b"started",
    )
    .await;
    store
        .persist_execution_fence(fence_input(
            command.command_id,
            daemon_boot_id,
            b"finish-nonce",
            8,
            b"fence",
        ))
        .await
        .expect("persist finish fixture fence");
    clock.set(30);
    store
        .authorize_execution_release(release_input(
            command.command_id,
            daemon_boot_id,
            b"finish-nonce",
        ))
        .await
        .expect("authorize finish fixture release");
    clock.set(40);
    store
        .complete_command_with_event(complete_input(
            conversation.conversation_id,
            command.command_id,
            intent.turn_id,
            b"result",
            b"terminal",
        ))
        .await
        .expect("complete finish fixture");

    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("freeze recovery scan");
    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load terminal recovery page");
    let completion = page
        .completion
        .expect("single conversation is terminal page");
    let connection = Connection::open(&database).expect("open concurrent tamper connection");
    connection
        .execute_batch("PRAGMA foreign_keys = OFF; DELETE FROM event_journal;")
        .expect("delete audit events after recovery page");
    drop(connection);

    let error = store
        .finish_recovery_scan(completion)
        .await
        .expect_err("finish must revalidate after the last page");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert!(matches!(
        store
            .create_conversation(conversation_input(0x67, b"must remain blocked"))
            .await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    store
        .inspect()
        .await
        .expect("inspect remains available while blocked");
    store
        .shutdown()
        .await
        .expect("shutdown blocked recovery store");
}

#[tokio::test]
async fn release_authorization_uses_safety_lane_when_normal_lane_is_full() {
    let root = TestRoot::new("release-safety-lane");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let injector = Arc::new(BlockingObservedFault::new(
        RuntimeStoreOperation::CreateConversationBeforeCommit,
        entered_tx,
        release_rx,
    ));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_command_capacity(1)
            .with_fault_injector(injector.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, 4, b"safety setup").await;
    clock.set(10);
    let command = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(1),
        "safety-command",
        b"prompt",
    )
    .await;
    clock.set(20);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x72);
    start_new(
        &store,
        conversation.conversation_id,
        command.command_id,
        daemon_boot_id,
        b"safety-nonce",
        b"intent",
        b"event",
    )
    .await;
    store
        .persist_execution_fence(fence_input(
            command.command_id,
            daemon_boot_id,
            b"safety-nonce",
            3,
            b"fence",
        ))
        .await
        .expect("persist fence");

    injector.arm_and_clear();
    let first_normal = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create_conversation(conversation_input(0x20, b"blocking normal"))
                .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .expect("join blocked-operation wait")
        .expect("normal operation reached worker");

    let queued_normal = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create_conversation(conversation_input(0x21, b"queued normal"))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !queued_normal.is_finished(),
        "normal lane must be saturated"
    );

    clock.set(30);
    let safety_release = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .authorize_execution_release(release_input(
                    command.command_id,
                    daemon_boot_id,
                    b"safety-nonce",
                ))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !safety_release.is_finished(),
        "safety release must be admitted instead of returning WorkerBusy"
    );

    release_tx
        .send(())
        .expect("release blocked normal operation");
    first_normal
        .await
        .expect("join first normal")
        .expect("first normal succeeds");
    let released = safety_release
        .await
        .expect("join safety release")
        .expect("safety release succeeds");
    assert_eq!(released.release_authorized_at_ms, Some(30));
    queued_normal
        .await
        .expect("join queued normal")
        .expect("queued normal succeeds");

    let observed = injector.observed();
    let creates = observed
        .iter()
        .enumerate()
        .filter_map(|(index, operation)| {
            (*operation == RuntimeStoreOperation::CreateConversationBeforeCommit).then_some(index)
        })
        .collect::<Vec<_>>();
    let release_index = observed
        .iter()
        .position(|operation| {
            *operation == RuntimeStoreOperation::AuthorizeExecutionReleaseBeforeCommit
        })
        .expect("observe release transaction");
    assert_eq!(creates.len(), 2);
    assert!(
        creates[0] < release_index && release_index < creates[1],
        "safety lane must run before queued normal work: {observed:?}"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn terminal_replay_and_token_bind_conversation_command_and_turn() {
    let root = TestRoot::new("terminal-binding");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let first_conversation = create_conversation(&store, 5, b"terminal one").await;
    let second_conversation = create_conversation(&store, 6, b"terminal two").await;
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x73);

    clock.set(10);
    let first_command = accept_new(
        &store,
        first_conversation.conversation_id,
        local_owner(1),
        "terminal-one",
        b"same prompt",
    )
    .await;
    let second_command = accept_new(
        &store,
        second_conversation.conversation_id,
        local_owner(1),
        "terminal-two",
        b"same prompt",
    )
    .await;

    clock.set(20);
    let first_intent = start_new(
        &store,
        first_conversation.conversation_id,
        first_command.command_id,
        daemon_boot_id,
        b"terminal-nonce-one",
        b"same intent",
        b"same start event",
    )
    .await;
    let second_intent = start_new(
        &store,
        second_conversation.conversation_id,
        second_command.command_id,
        daemon_boot_id,
        b"terminal-nonce-two",
        b"same intent",
        b"same start event",
    )
    .await;
    for (command, nonce, seed) in [
        (&first_command, b"terminal-nonce-one".as_slice(), 4),
        (&second_command, b"terminal-nonce-two".as_slice(), 5),
    ] {
        store
            .persist_execution_fence(fence_input(
                command.command_id,
                daemon_boot_id,
                nonce,
                seed,
                b"same fence payload",
            ))
            .await
            .expect("persist fence");
        store
            .authorize_execution_release(release_input(command.command_id, daemon_boot_id, nonce))
            .await
            .expect("authorize release");
    }

    clock.set(40);
    for (conversation_id, command_id, turn_id) in [
        (
            first_conversation.conversation_id,
            first_command.command_id,
            first_intent.turn_id,
        ),
        (
            second_conversation.conversation_id,
            second_command.command_id,
            second_intent.turn_id,
        ),
    ] {
        store
            .complete_command_with_event(complete_input(
                conversation_id,
                command_id,
                turn_id,
                b"identical terminal payload",
                b"identical terminal event",
            ))
            .await
            .expect("complete command");
    }

    let wrong_turn = store
        .complete_command_with_event(complete_input(
            first_conversation.conversation_id,
            first_command.command_id,
            second_intent.turn_id,
            b"identical terminal payload",
            b"identical terminal event",
        ))
        .await
        .expect_err("terminal replay with another turn must conflict");
    assert!(matches!(
        wrong_turn,
        RuntimeStoreError::InvalidStateTransition
    ));
    store.shutdown().await.expect("shutdown store");

    let connection = read_only_database(&database);
    let first_token: Vec<u8> = connection
        .query_row(
            "SELECT terminal_token FROM commands WHERE command_id = ?1",
            [&first_command.command_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("load first terminal token");
    let second_token: Vec<u8> = connection
        .query_row(
            "SELECT terminal_token FROM commands WHERE command_id = ?1",
            [&second_command.command_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("load second terminal token");
    assert_ne!(
        first_token, second_token,
        "terminal tokens must domain-bind conversation, command, and turn"
    );
}

#[tokio::test]
async fn accept_sweeps_expired_rows_before_quota_and_writes_canonical_events() {
    let root = TestRoot::new("accept-expiry-sweep");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, 7, b"expiry quota").await;
    for index in 0..32_u32 {
        let command = accept_new(
            &store,
            conversation.conversation_id,
            local_owner(1),
            &format!("expired-{index}"),
            format!("expired payload {index}").as_bytes(),
        )
        .await;
        assert_eq!(command.command_seq, u64::from(index));
    }

    let expiry_boundary = 1_000 + COMMAND_QUEUE_TTL_MS;
    clock.set(expiry_boundary);
    let accepted = store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: local_owner(1),
            idempotency_key: "after-expiry-sweep".to_owned(),
            payload: b"new prompt".to_vec(),
        })
        .await
        .expect("expired rows must be swept before quota");
    assert!(matches!(
        accepted,
        AcceptOutcome::Accepted {
            command,
            queue_position: 0,
        } if command.command_seq == 32
    ));

    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load recovery");
    assert_eq!(recovery.accepted.len(), 1);
    assert_eq!(recovery.conversations[0].event_high_water, Some(31));
    assert_eq!(event_count(&database), 32);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn recovery_sweeps_expiry_with_event_and_expired_completion_is_typed() {
    let root = TestRoot::new("recovery-expiry-sweep");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(2_000);
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, 8, b"recovery expiry").await;
    let command = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(1),
        "recovery-expired",
        b"expired prompt",
    )
    .await;

    let expiry_boundary = 2_000 + COMMAND_QUEUE_TTL_MS;
    clock.set(expiry_boundary);
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("recovery performs expiry sweep");
    assert!(recovery.accepted.is_empty());
    assert_eq!(recovery.conversations[0].event_high_water, Some(0));
    assert_eq!(event_count(&database), 1);

    let replay = store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: local_owner(1),
            idempotency_key: "recovery-expired".to_owned(),
            payload: b"expired prompt".to_vec(),
        })
        .await
        .expect("expired command remains in idempotency ledger");
    let expired = match replay {
        AcceptOutcome::Replayed { command } => command,
        AcceptOutcome::Accepted { .. } => panic!("expiry must not forget idempotency"),
    };
    assert_eq!(expired.command_id, command.command_id);
    assert_eq!(expired.state, CommandState::Expired);
    assert!(
        expired.terminal_event_id.is_some(),
        "expiry must own a canonical terminal event"
    );

    let completion_error = store
        .complete_command_with_event(complete_input(
            conversation.conversation_id,
            command.command_id,
            runtime_id(RuntimeIdKind::Turn, 0x55),
            b"impossible result",
            b"impossible event",
        ))
        .await
        .expect_err("expired completion is rejected without SQLite type leakage");
    assert!(matches!(
        completion_error,
        RuntimeStoreError::InvalidStateTransition
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn reverse_start_and_terminal_times_return_typed_errors_without_mutation() {
    let root = TestRoot::new("time-order");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(100);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, 9, b"time order").await;
    let command = accept_new(
        &store,
        conversation.conversation_id,
        local_owner(1),
        "time-order",
        b"prompt",
    )
    .await;
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x74);

    clock.set(99);
    let reverse_start = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: b"time-order-nonce".to_vec(),
            intent_payload: b"intent".to_vec(),
            event_payload: b"event".to_vec(),
        })
        .await
        .expect_err("clock before accepted state must be rejected before SQLite");
    assert!(matches!(
        reverse_start,
        RuntimeStoreError::ClockRegressed {
            persisted_ms: 100,
            observed_ms: 99,
        }
    ));

    clock.set(110);
    let intent = start_new(
        &store,
        conversation.conversation_id,
        command.command_id,
        daemon_boot_id,
        b"time-order-nonce",
        b"intent",
        b"event",
    )
    .await;
    store
        .persist_execution_fence(fence_input(
            command.command_id,
            daemon_boot_id,
            b"time-order-nonce",
            6,
            b"fence",
        ))
        .await
        .expect("persist fence");
    clock.set(120);
    store
        .authorize_execution_release(release_input(
            command.command_id,
            daemon_boot_id,
            b"time-order-nonce",
        ))
        .await
        .expect("authorize release");

    clock.set(105);
    let reverse_terminal = store
        .complete_command_with_event(complete_input(
            conversation.conversation_id,
            command.command_id,
            intent.turn_id,
            b"result",
            b"terminal event",
        ))
        .await
        .expect_err("terminal clock before release must be rejected before SQLite");
    assert!(matches!(
        reverse_terminal,
        RuntimeStoreError::ClockRegressed {
            persisted_ms: 120,
            observed_ms: 105,
        }
    ));
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load recovery");
    assert_eq!(recovery.started.len(), 1);
    assert_eq!(recovery.started[0].command.command_id, command.command_id);
    store.shutdown().await.expect("shutdown store");
}

async fn assert_blind_token_tamper_detected(label: &str, column: &str, replacement: u8) {
    let root = TestRoot::new(label);
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let database = root.database();
    let config = RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open store");
    let conversation = create_conversation(&store, replacement, b"token integrity").await;
    accept_new(
        &store,
        conversation.conversation_id,
        local_owner(replacement),
        "token-integrity-key",
        b"token integrity payload",
    )
    .await;
    store.shutdown().await.expect("shutdown before tamper");

    let connection = Connection::open(&database).expect("open database for offline tamper");
    let sql = match column {
        "owner_token" => "UPDATE commands SET owner_token = ?1",
        "idempotency_token" => "UPDATE commands SET idempotency_token = ?1",
        "payload_token" => "UPDATE commands SET payload_token = ?1",
        _ => panic!("unsupported token column"),
    };
    connection
        .execute(sql, params![vec![replacement; 32]])
        .expect("tamper blind token");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint tampered row");
    drop(connection);

    let error = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect_err("blind-token tamper must fail during open-time integrity validation");
    assert!(
        matches!(error, RuntimeStoreError::UnknownOrCorruptSchema),
        "{column} mismatch must fail closed, got {error:?}"
    );
}

#[tokio::test]
async fn recovery_recomputes_owner_idempotency_and_payload_blind_tokens() {
    assert_blind_token_tamper_detected("owner-token-tamper", "owner_token", 0xA1).await;
    assert_blind_token_tamper_detected("idempotency-token-tamper", "idempotency_token", 0xB2).await;
    assert_blind_token_tamper_detected("payload-token-tamper", "payload_token", 0xC3).await;
}

#[tokio::test]
async fn every_sensitive_journal_field_stays_out_of_db_wal_shm_and_debug() {
    const DESCRIPTOR: &[u8] = b"descriptor-plaintext-sentinel-8f91";
    const IDEMPOTENCY_KEY: &str = "idempotency-plaintext-sentinel-9a02";
    const PROMPT: &[u8] = b"prompt-plaintext-sentinel-ab13";
    const NONCE: &[u8] = b"nonce-plaintext-sentinel-bc24";
    const INTENT: &[u8] = b"intent-plaintext-sentinel-cd35";
    const START_EVENT: &[u8] = b"start-event-plaintext-sentinel-de46";
    const FENCE: &[u8] = b"fence-plaintext-sentinel-ef57";
    const RESULT: &[u8] = b"result-plaintext-sentinel-f068";
    const TERMINAL_EVENT: &[u8] = b"terminal-event-plaintext-sentinel-0179";
    const REMOTE_KEY: &str = "remote-idempotency-plaintext-128a";
    const REMOTE_PROMPT: &[u8] = b"remote-prompt-plaintext-sentinel-239b";
    const LOCAL_MACHINE_DOMAIN: [u8; 32] = [0xD3; 32];
    const LOCAL_INSTALLATION: [u8; 16] = [0xE4; 16];
    const REMOTE_ROUTE: [u8; 16] = [0xA5; 16];
    const REMOTE_FINGERPRINT: [u8; 32] = [0xB6; 32];

    let root = TestRoot::new("all-field-sentinels");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, 0x30, DESCRIPTOR).await;

    clock.set(10);
    let accepted = store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: LOCAL_MACHINE_DOMAIN,
                uid: 501,
                client_installation_id: LOCAL_INSTALLATION,
            },
            idempotency_key: IDEMPOTENCY_KEY.to_owned(),
            payload: PROMPT.to_vec(),
        })
        .await
        .expect("accept sentinel command");
    let command = match &accepted {
        AcceptOutcome::Accepted { command, .. } => command.clone(),
        AcceptOutcome::Replayed { .. } => panic!("sentinel command cannot replay"),
    };

    clock.set(20);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x75);
    let started = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: NONCE.to_vec(),
            intent_payload: INTENT.to_vec(),
            event_payload: START_EVENT.to_vec(),
        })
        .await
        .expect("start sentinel command");
    let turn_id = match &started {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("sentinel start cannot replay"),
    };
    let fence = store
        .persist_execution_fence(fence_input(
            command.command_id,
            daemon_boot_id,
            NONCE,
            7,
            FENCE,
        ))
        .await
        .expect("persist sentinel fence");
    clock.set(30);
    let released = store
        .authorize_execution_release(release_input(command.command_id, daemon_boot_id, NONCE))
        .await
        .expect("authorize sentinel release");
    clock.set(40);
    let completed = store
        .complete_command_with_event(complete_input(
            conversation.conversation_id,
            command.command_id,
            turn_id,
            RESULT,
            TERMINAL_EVENT,
        ))
        .await
        .expect("complete sentinel command");

    let remote = store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: IdempotencyOwner::Remote {
                machine_trust_domain: LOCAL_MACHINE_DOMAIN,
                device_route: REMOTE_ROUTE,
                device_sign_fingerprint: REMOTE_FINGERPRINT,
            },
            idempotency_key: REMOTE_KEY.to_owned(),
            payload: REMOTE_PROMPT.to_vec(),
        })
        .await
        .expect("accept remote-owner sentinel command");

    let sentinels: &[&[u8]] = &[
        DESCRIPTOR,
        IDEMPOTENCY_KEY.as_bytes(),
        PROMPT,
        NONCE,
        INTENT,
        START_EVENT,
        FENCE,
        RESULT,
        TERMINAL_EVENT,
        REMOTE_KEY.as_bytes(),
        REMOTE_PROMPT,
        &LOCAL_MACHINE_DOMAIN,
        &LOCAL_INSTALLATION,
        &REMOTE_ROUTE,
        &REMOTE_FINGERPRINT,
    ];
    assert_no_sentinels(&database, sentinels);

    let debug = format!("{accepted:?}{started:?}{fence:?}{released:?}{completed:?}{remote:?}");
    for sentinel in sentinels {
        assert!(
            !debug
                .as_bytes()
                .windows(sentinel.len())
                .any(|window| window == *sentinel),
            "plaintext sentinel leaked through Debug: {}",
            String::from_utf8_lossy(sentinel)
        );
    }

    store.shutdown().await.expect("shutdown store");
    assert_no_sentinels(&database, sentinels);
}
