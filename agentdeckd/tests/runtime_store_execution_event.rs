#[path = "support/runtime_configuration.rs"]
mod runtime_configuration;
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::identity::{EntityId, ItemId};
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody};
use agentdeck_protocol::{AgentItem, AgentItemMeta};
use agentdeckd::runtime::model::{
    MAX_RUNTIME_EVENT_BYTES, RuntimeCapacityObservation, RuntimeCapacityProbe,
    RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AppendExecutionEvent, AppendExecutionEventOutcome,
    AuthorizeExecutionRelease, CommandTerminal, CompleteCommand, CompleteOutcome, ExecutionFence,
    IdempotencyOwner, NewConversation, RuntimeClock, RuntimeClockError, RuntimeCommitOperation,
    RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreHandle, RuntimeStoreOperation, StartCommand, StartOutcome,
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
            "agentdeckd-runtime-execution-event-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create execution event test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure execution event test root");
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
            .expect("load execution event StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
}

fn owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x11; 32],
        uid: 501,
        client_installation_id: [0x22; 16],
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

#[derive(Clone, Debug)]
struct ArmableDiskLowProbe(Arc<AtomicBool>);

impl ArmableDiskLowProbe {
    fn healthy() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn arm(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl RuntimeCapacityProbe for ArmableDiskLowProbe {
    fn observe(
        &self,
        _database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        let low = self.0.load(Ordering::SeqCst);
        Ok(RuntimeCapacityObservation {
            main_bytes: 8 * 1024 * 1024,
            wal_bytes: 2 * 1024 * 1024,
            shm_bytes: 32 * 1024,
            filesystem_total_bytes: 4 * 1024 * 1024 * 1024,
            filesystem_available_bytes: if low {
                512 * 1024 * 1024 - 1
            } else {
                2 * 1024 * 1024 * 1024
            },
        })
    }
}

async fn started_turn_unreleased_with_event(
    store: &RuntimeStoreHandle,
    seed: u8,
) -> (RuntimeId, RuntimeId, RuntimeId, RuntimeId) {
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, seed);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(1)),
            descriptor: runtime_descriptor::descriptor(b"execution event real sample"),
        })
        .await
        .expect("create conversation");
    runtime_configuration::configure_codex_revision_one(store, conversation_id).await;
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(),
            idempotency_key: format!("execution-event-{seed}"),
            expected_configuration_revision: 1,
            payload: b"real prompt sample".to_vec(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh command cannot replay"),
    };
    let (turn_id, started_event_id) = match store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id: command.command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(2)),
            execution_nonce: format!("execution-event-nonce-{seed}").into_bytes(),
        })
        .await
        .expect("start command")
    {
        StartOutcome::Started { intent, event, .. } => (intent.turn_id, event.event_id),
        StartOutcome::Replayed { .. } => panic!("fresh start cannot replay"),
    };
    (
        conversation_id,
        command.command_id,
        turn_id,
        started_event_id,
    )
}

async fn started_turn_unreleased(
    store: &RuntimeStoreHandle,
    seed: u8,
) -> (RuntimeId, RuntimeId, RuntimeId) {
    let (conversation_id, command_id, turn_id, _) =
        started_turn_unreleased_with_event(store, seed).await;
    (conversation_id, command_id, turn_id)
}

async fn authorize_turn_release(store: &RuntimeStoreHandle, seed: u8, command_id: RuntimeId) {
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(2));
    let execution_nonce = format!("execution-event-nonce-{seed}").into_bytes();
    store
        .persist_execution_fence(ExecutionFence {
            command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: i64::from(seed) + 7_000,
            leader_pid: i64::from(seed) + 7_000,
            leader_start_time: u64::from(seed) + 7_000,
            payload: b"execution-event-released-fence".to_vec(),
        })
        .await
        .expect("persist execution fence");
    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id,
            daemon_boot_id,
            execution_nonce,
        })
        .await
        .expect("authorize execution release");
}

async fn started_turn(store: &RuntimeStoreHandle, seed: u8) -> (RuntimeId, RuntimeId, RuntimeId) {
    let started = started_turn_unreleased(store, seed).await;
    authorize_turn_release(store, seed, started.1).await;
    started
}

fn item_input(
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    event_id: RuntimeId,
    text: &str,
) -> AppendExecutionEvent {
    AppendExecutionEvent::item(
        conversation_id,
        command_id,
        turn_id,
        event_id,
        ItemId::new("real-item-id"),
        EntityId::new("real-entity-id"),
        AgentItem::AssistantMessage {
            text: text.to_owned(),
            meta: AgentItemMeta::default(),
        },
    )
}

#[tokio::test]
async fn execution_events_require_a_durable_release_boundary() {
    // 威胁场景：adapter 在 gate 未获 release 前伪造 Item；Store 必须保证零 durable output。
    let root = TestRoot::new("release-boundary");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open release-boundary store");
    let seed = 0x21;
    let (conversation_id, command_id, turn_id) = started_turn_unreleased(&store, seed).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x24);
    let input = item_input(
        conversation_id,
        command_id,
        turn_id,
        event_id,
        "must wait for release",
    );
    assert!(matches!(
        store.append_execution_event(input.clone()).await,
        Err(RuntimeStoreError::ExecutionFenceMissing)
    ));

    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(2));
    let execution_nonce = format!("execution-event-nonce-{seed}").into_bytes();
    store
        .persist_execution_fence(ExecutionFence {
            command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: 7_021,
            leader_pid: 7_021,
            leader_start_time: 7_021,
            payload: b"unreleased-fence".to_vec(),
        })
        .await
        .expect("persist unreleased fence");
    assert!(matches!(
        store.append_execution_event(input.clone()).await,
        Err(RuntimeStoreError::ExecutionReleaseMissing)
    ));

    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id,
            daemon_boot_id,
            execution_nonce,
        })
        .await
        .expect("authorize release");
    assert!(matches!(
        store
            .append_execution_event(input)
            .await
            .expect("released execution can append"),
        AppendExecutionEventOutcome::Appended { event }
            if event.event_id == event_id && event.event_seq == 2
    ));
    store
        .shutdown()
        .await
        .expect("shutdown release-boundary store");
}

#[tokio::test]
async fn dynamic_event_id_cannot_alias_started_or_terminal_pointers() {
    let root = TestRoot::new("fixed-pointer-collision");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open pointer-collision store");
    let seed = 0x29;
    let (conversation_id, command_id, turn_id, started_event_id) =
        started_turn_unreleased_with_event(&store, seed).await;
    authorize_turn_release(&store, seed, command_id).await;

    assert!(matches!(
        store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                started_event_id,
                "must not replace TurnStarted",
            ))
            .await,
        Err(RuntimeStoreError::ExecutionEventConflict)
    ));

    store
        .append_execution_event(item_input(
            conversation_id,
            command_id,
            turn_id,
            runtime_id(RuntimeIdKind::Event, 0x2D),
            "real dynamic item",
        ))
        .await
        .expect("append dynamic item before terminal");
    let terminal_event_id = match store
        .complete_command_with_event(CompleteCommand {
            conversation_id,
            command_id,
            turn_id,
            terminal: CommandTerminal::interrupted(),
        })
        .await
        .expect("persist terminal pointer")
    {
        CompleteOutcome::Completed { event, .. } => event.event_id,
        CompleteOutcome::Replayed { .. } => panic!("fresh terminal cannot replay"),
    };
    assert!(matches!(
        store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                terminal_event_id,
                "must not replace terminal",
            ))
            .await,
        Err(RuntimeStoreError::ExecutionEventConflict)
    ));
    store
        .shutdown()
        .await
        .expect("shutdown pointer-collision store");
}

#[tokio::test]
async fn append_and_terminal_race_serializes_without_post_terminal_event() {
    let root = TestRoot::new("append-terminal-race");
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(root.database());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open append-terminal race store");
    let (conversation_id, command_id, turn_id) = started_turn(&store, 0x2E).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x2F);

    let (append, terminal) = tokio::join!(
        store.append_execution_event(item_input(
            conversation_id,
            command_id,
            turn_id,
            event_id,
            "concurrent adapter output",
        )),
        store.complete_command_with_event(CompleteCommand {
            conversation_id,
            command_id,
            turn_id,
            terminal: CommandTerminal::interrupted(),
        }),
    );
    assert!(matches!(terminal, Ok(CompleteOutcome::Completed { .. })));
    assert!(matches!(
        append,
        Ok(AppendExecutionEventOutcome::Appended { .. })
            | Err(RuntimeStoreError::InvalidStateTransition)
    ));

    assert!(matches!(
        store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                runtime_id(RuntimeIdKind::Event, 0x30),
                "fresh output after the race terminal",
            ))
            .await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    store.shutdown().await.expect("shutdown race store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen race store");
    reopened
        .inspect()
        .await
        .expect("race leaves a valid dynamic ledger");
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened race store");
}

#[tokio::test]
async fn typed_item_append_exactly_replays_and_reopens() {
    let root = TestRoot::new("typed-replay");
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(root.database());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open store");
    let (conversation_id, command_id, turn_id) = started_turn(&store, 0x31).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x34);
    let input = item_input(
        conversation_id,
        command_id,
        turn_id,
        event_id,
        "real adapter item sample",
    );
    let appended = store
        .append_execution_event(input.clone())
        .await
        .expect("append typed item");
    let event = match appended {
        AppendExecutionEventOutcome::Appended { event } => event,
        AppendExecutionEventOutcome::Replayed { .. } => panic!("fresh append cannot replay"),
    };
    assert_eq!(event.event_seq, 2);
    let decoded: RuntimeEvent = serde_json::from_slice(&event.payload).expect("decode item event");
    assert!(matches!(
        decoded.body,
        RuntimeEventBody::Item {
            item: AgentItem::AssistantMessage { ref text, .. }
        } if text == "real adapter item sample"
    ));
    assert!(matches!(
        store
            .append_execution_event(input.clone())
            .await
            .expect("exact append replay"),
        AppendExecutionEventOutcome::Replayed { event: replay }
            if replay.event_id == event.event_id && replay.payload == event.payload
    ));

    let conflict = item_input(
        conversation_id,
        command_id,
        turn_id,
        event_id,
        "different adapter item",
    );
    assert!(matches!(
        store.append_execution_event(conflict).await,
        Err(RuntimeStoreError::ExecutionEventConflict)
    ));
    let identity_collision = item_input(
        runtime_id(RuntimeIdKind::Conversation, 0x7E),
        runtime_id(RuntimeIdKind::Command, 0x7D),
        runtime_id(RuntimeIdKind::Turn, 0x7C),
        event_id,
        "eventId collision across another execution",
    );
    assert!(matches!(
        store.append_execution_event(identity_collision).await,
        Err(RuntimeStoreError::ExecutionEventConflict)
    ));
    let wrong_turn = item_input(
        conversation_id,
        command_id,
        runtime_id(RuntimeIdKind::Turn, 0x7F),
        runtime_id(RuntimeIdKind::Event, 0x35),
        "wrong turn",
    );
    assert!(matches!(
        store.append_execution_event(wrong_turn).await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    let update_event_id = runtime_id(RuntimeIdKind::Event, 0x37);
    assert!(matches!(
        store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                update_event_id,
                "same item and entity receive a later update",
            ))
            .await
            .expect("append same item/entity update"),
        AppendExecutionEventOutcome::Appended { event }
            if event.event_id == update_event_id && event.event_seq == 3
    ));

    store
        .complete_command_with_event(CompleteCommand {
            conversation_id,
            command_id,
            turn_id,
            terminal: CommandTerminal::interrupted(),
        })
        .await
        .expect("complete execution after item");
    assert!(matches!(
        store
            .append_execution_event(input.clone())
            .await
            .expect("exact Item replay remains available after terminal"),
        AppendExecutionEventOutcome::Replayed { event: replay }
            if replay.event_id == event_id
    ));
    assert!(matches!(
        store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                runtime_id(RuntimeIdKind::Event, 0x36),
                "fresh item after terminal",
            ))
            .await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));

    store.shutdown().await.expect("shutdown before reopen");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen dynamically audited item ledger");
    reopened.inspect().await.expect("inspect reopened store");
    assert!(matches!(
        reopened
            .append_execution_event(input)
            .await
            .expect("replay after reopen"),
        AppendExecutionEventOutcome::Replayed { event: replay }
            if replay.event_id == event_id
    ));
    reopened.shutdown().await.expect("shutdown reopened store");
}

struct FailAppendReplyOnce {
    armed: AtomicBool,
}

struct FailAppendCommitOnce {
    armed: AtomicBool,
}

impl RuntimeStoreFaultInjector for FailAppendCommitOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::AppendExecutionEventBeforeCommit
            && self.armed.swap(false, Ordering::SeqCst)
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "rollback append before commit once",
            ));
        }
        Ok(())
    }
}

impl RuntimeStoreFaultInjector for FailAppendReplyOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::AppendExecutionEventAfterCommit
            && self.armed.swap(false, Ordering::SeqCst)
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "drop append after-commit reply once",
            ));
        }
        Ok(())
    }
}

#[tokio::test]
async fn append_after_commit_unknown_converges_with_the_same_event_id() {
    let root = TestRoot::new("commit-unknown");
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
        FailAppendReplyOnce {
            armed: AtomicBool::new(true),
        },
    ));
    let store = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("open fault-injected store");
    let (conversation_id, command_id, turn_id) = started_turn(&store, 0x41).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x44);
    let input = item_input(
        conversation_id,
        command_id,
        turn_id,
        event_id,
        "after-COMMIT replay item",
    );
    assert!(matches!(
        store.append_execution_event(input.clone()).await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AppendExecutionEvent
        })
    ));
    let replay = store
        .append_execution_event(input.clone())
        .await
        .expect("exact retry after unknown commit");
    let event = match replay {
        AppendExecutionEventOutcome::Replayed { event } => event,
        AppendExecutionEventOutcome::Appended { .. } => panic!("committed append must replay"),
    };
    assert_eq!(event.event_id, event_id);
    let decoded: RuntimeEvent = serde_json::from_slice(&event.payload).expect("decode Item event");
    let RuntimeEventBody::Item {
        item: AgentItem::AssistantMessage { text, .. },
    } = decoded.body
    else {
        panic!("expected canonical assistant Item");
    };
    assert_eq!(text, "after-COMMIT replay item");
    assert_eq!(event.event_seq, 2);
    let second_replay = match store
        .append_execution_event(input)
        .await
        .expect("repeat exact replay")
    {
        AppendExecutionEventOutcome::Replayed { event } => event,
        AppendExecutionEventOutcome::Appended { .. } => panic!("durable event must replay"),
    };
    assert_eq!(second_replay, event);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn exact_replay_bypasses_disk_admission_and_clock_regression() {
    let root = TestRoot::new("replay-bypasses-fresh-gates");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10_000);
    let probe = ArmableDiskLowProbe::healthy();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open replay gate store");
    let (conversation_id, command_id, turn_id) = started_turn(&store, 0x71).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x74);
    let input = item_input(
        conversation_id,
        command_id,
        turn_id,
        event_id,
        "byte-stable replay sample",
    );
    let appended = match store
        .append_execution_event(input.clone())
        .await
        .expect("append before gates fail")
    {
        AppendExecutionEventOutcome::Appended { event } => event,
        AppendExecutionEventOutcome::Replayed { .. } => panic!("fresh append cannot replay"),
    };

    clock.set(0);
    probe.arm();
    let replayed = match store
        .append_execution_event(input)
        .await
        .expect("exact replay is a readback, not a fresh side effect")
    {
        AppendExecutionEventOutcome::Replayed { event } => event,
        AppendExecutionEventOutcome::Appended { .. } => panic!("durable event must replay"),
    };
    assert_eq!(replayed, appended);

    assert!(matches!(
        store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                runtime_id(RuntimeIdKind::Event, 0x75),
                "fresh write remains gated",
            ))
            .await,
        Err(RuntimeStoreError::DiskLow { .. })
    ));
    store.shutdown().await.expect("shutdown replay gate store");
}

#[tokio::test]
async fn event_sequence_crosses_nine_to_ten_and_replays_byte_exact_after_reopen() {
    let root = TestRoot::new("sequence-nine-to-ten");
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(root.database());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open sequence-boundary store");
    let (conversation_id, command_id, turn_id) = started_turn(&store, 0x81).await;
    for offset in 0_u8..8 {
        let outcome = store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                runtime_id(RuntimeIdKind::Event, 0x90 + offset),
                &format!("sequence prefix {offset}"),
            ))
            .await
            .expect("append sequence prefix");
        assert!(matches!(
            outcome,
            AppendExecutionEventOutcome::Appended { event }
                if event.event_seq == u64::from(offset) + 2
        ));
    }

    let boundary_event_id = runtime_id(RuntimeIdKind::Event, 0xA0);
    let boundary_input = item_input(
        conversation_id,
        command_id,
        turn_id,
        boundary_event_id,
        "event sequence ten",
    );
    let appended = match store
        .append_execution_event(boundary_input.clone())
        .await
        .expect("append two-digit sequence")
    {
        AppendExecutionEventOutcome::Appended { event } => event,
        AppendExecutionEventOutcome::Replayed { .. } => panic!("fresh boundary cannot replay"),
    };
    assert_eq!(appended.event_seq, 10);
    let decoded: RuntimeEvent =
        serde_json::from_slice(&appended.payload).expect("decode sequence ten");
    assert_eq!(decoded.event_seq, 10);

    store
        .shutdown()
        .await
        .expect("shutdown sequence-boundary store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen sequence-boundary store");
    let replayed = match reopened
        .append_execution_event(boundary_input)
        .await
        .expect("replay sequence ten after reopen")
    {
        AppendExecutionEventOutcome::Replayed { event } => event,
        AppendExecutionEventOutcome::Appended { .. } => panic!("durable boundary must replay"),
    };
    assert_eq!(replayed, appended);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened sequence store");
}

#[tokio::test]
async fn append_before_commit_fault_rolls_back_and_first_retry_appends_once() {
    let root = TestRoot::new("before-commit");
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
        FailAppendCommitOnce {
            armed: AtomicBool::new(true),
        },
    ));
    let store = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("open before-commit fault store");
    let (conversation_id, command_id, turn_id) = started_turn(&store, 0x61).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x64);
    let input = item_input(
        conversation_id,
        command_id,
        turn_id,
        event_id,
        "before commit rollback sample",
    );
    assert!(matches!(
        store.append_execution_event(input.clone()).await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    assert!(matches!(
        store
            .append_execution_event(input.clone())
            .await
            .expect("first retry appends after rollback"),
        AppendExecutionEventOutcome::Appended { event }
            if event.event_id == event_id && event.event_seq == 2
    ));
    assert!(matches!(
        store
            .append_execution_event(input)
            .await
            .expect("second retry replays"),
        AppendExecutionEventOutcome::Replayed { event }
            if event.event_id == event_id && event.event_seq == 2
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn small_lane_accepts_small_item_and_rejects_only_the_actual_large_item() {
    let root = TestRoot::new("small-lane");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_lane_byte_capacity(32 * 1024),
        root.storage_kek(&keys),
    )
    .await
    .expect("open small-lane store");
    let (conversation_id, command_id, turn_id) = started_turn(&store, 0x51).await;
    assert!(matches!(
        store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                runtime_id(RuntimeIdKind::Event, 0x54),
                "small canonical Item",
            ))
            .await
            .expect("small Item must not require a 64 MiB lane"),
        AppendExecutionEventOutcome::Appended { .. }
    ));

    let mut tiny_text_with_large_caller_capacity = String::with_capacity(4 * 1024 * 1024);
    tiny_text_with_large_caller_capacity.push_str("tiny normalized item");
    assert!(matches!(
        store
            .append_execution_event(AppendExecutionEvent::item(
                conversation_id,
                command_id,
                turn_id,
                runtime_id(RuntimeIdKind::Event, 0x56),
                ItemId::new("normalized-item"),
                EntityId::new("normalized-entity"),
                AgentItem::AssistantMessage {
                    text: tiny_text_with_large_caller_capacity,
                    meta: AgentItemMeta::default(),
                },
            ))
            .await
            .expect("lane charge uses retained canonical bytes, not caller capacity"),
        AppendExecutionEventOutcome::Appended { .. }
    ));

    let reusable_event_id = runtime_id(RuntimeIdKind::Event, 0x55);
    let large = item_input(
        conversation_id,
        command_id,
        turn_id,
        reusable_event_id,
        &"x".repeat(64 * 1024),
    );
    assert!(matches!(
        store.append_execution_event(large).await,
        Err(RuntimeStoreError::WorkerBusy { .. })
    ));
    assert!(matches!(
        store
            .append_execution_event(item_input(
                conversation_id,
                command_id,
                turn_id,
                reusable_event_id,
                "small retry after lane rejection",
            ))
            .await
            .expect("lane rejection must leave eventId unused"),
        AppendExecutionEventOutcome::Appended { event }
            if event.event_id == reusable_event_id
    ));
    store.shutdown().await.expect("shutdown small-lane store");
}

#[tokio::test]
async fn public_append_distinguishes_exact_protocol_limit_from_one_byte_more() {
    let root = TestRoot::new("public-byte-boundary");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open public byte-boundary store");
    let (conversation_id, command_id, turn_id) = started_turn(&store, 0x76).await;
    let exact_event_id = runtime_id(RuntimeIdKind::Event, 0x79);
    let empty = RuntimeEvent::new(
        agentdeck_protocol::runtime::identity::ConversationId::new(
            conversation_id.to_canonical_string(),
        ),
        agentdeck_protocol::runtime::identity::EventId::new(exact_event_id.to_canonical_string()),
        2,
        Some(agentdeck_protocol::runtime::identity::CommandId::new(
            command_id.to_canonical_string(),
        )),
        Some(ItemId::new("limit-item")),
        Some(EntityId::new("limit-entity")),
        RuntimeEventBody::Item {
            item: AgentItem::AssistantMessage {
                text: String::new(),
                meta: AgentItemMeta::default(),
            },
        },
    )
    .expect("construct empty boundary event");
    let fixed_len = serde_json::to_vec(&empty)
        .expect("encode empty boundary event")
        .len();
    let text_bytes = MAX_RUNTIME_EVENT_BYTES
        .checked_sub(fixed_len)
        .expect("protocol limit exceeds fixed event overhead");

    let exact = store
        .append_execution_event(AppendExecutionEvent::item(
            conversation_id,
            command_id,
            turn_id,
            exact_event_id,
            ItemId::new("limit-item"),
            EntityId::new("limit-entity"),
            AgentItem::AssistantMessage {
                text: "x".repeat(text_bytes),
                meta: AgentItemMeta::default(),
            },
        ))
        .await;
    // The exact-limit payload passes the public canonical byte gate, then hits
    // the independent 64 MiB replay-retention rule because ConfigurationChanged
    // and TurnStarted already occupy the suffix and no replacement snapshot exists yet.
    assert!(matches!(
        exact,
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));

    assert!(matches!(
        store
            .append_execution_event(AppendExecutionEvent::item(
                conversation_id,
                command_id,
                turn_id,
                runtime_id(RuntimeIdKind::Event, 0x7A),
                ItemId::new("limit-item"),
                EntityId::new("limit-entity"),
                AgentItem::AssistantMessage {
                    text: "x".repeat(text_bytes + 1),
                    meta: AgentItemMeta::default(),
                },
            ))
            .await,
        Err(RuntimeStoreError::PayloadTooLarge)
    ));
    assert!(matches!(
        store
            .append_execution_event(AppendExecutionEvent::item(
                conversation_id,
                command_id,
                turn_id,
                exact_event_id,
                ItemId::new("limit-item"),
                EntityId::new("limit-entity"),
                AgentItem::AssistantMessage {
                    text: "small retry after independent retention rejection".to_owned(),
                    meta: AgentItemMeta::default(),
                },
            ))
            .await
            .expect("retention rejection leaves eventId unused"),
        AppendExecutionEventOutcome::Appended { event }
            if event.event_id == exact_event_id && event.event_seq == 2
    ));
    store
        .shutdown()
        .await
        .expect("shutdown public byte-boundary store");
}
