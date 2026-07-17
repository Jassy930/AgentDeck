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
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody, StreamCursor};
use agentdeck_protocol::{AgentItem, AgentItemMeta};
use agentdeckd::runtime::backfill::BarrierRequest;
use agentdeckd::runtime::events::{
    RegisterStreamBarrier, RuntimeStreamTarget, StreamBarrierRegistration, WatchGeneration,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AppendExecutionEvent, AppendExecutionEventOutcome,
    AuthorizeExecutionRelease, ExecutionFence, IdempotencyOwner, NewConversation,
    RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation, StartCommand,
    StartOutcome,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, OptionalExtension};

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
            "agentdeckd-execution-event-commit-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create execution event commit test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure execution event commit test root");
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
            .expect("load execution event commit StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct OneShotAppendFault {
    operation: RuntimeStoreOperation,
    armed: AtomicBool,
}

impl OneShotAppendFault {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            armed: AtomicBool::new(true),
        }
    }
}

impl RuntimeStoreFaultInjector for OneShotAppendFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RuntimeStoreError::InvalidConfig(
                "injected execution event COMMIT fault",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct DurableState {
    conversation_high_water: Option<String>,
    retention_indexed_through: Option<String>,
    journal_count: u64,
    journal_bytes: u64,
    stream_count: u64,
    stream_bytes: u64,
    ledger_event_count: u64,
    ledger_audit_bytes: u64,
    ledger_stream_count: u64,
    ledger_stream_bytes: u64,
    appended_row: Option<(String, Vec<u8>, u64)>,
    appended_index_row: Option<(String, u64)>,
}

fn nonnegative(value: i64) -> u64 {
    u64::try_from(value).expect("fixture SQLite counter is non-negative")
}

fn durable_state(database: &Path, conversation_id: RuntimeId, event_id: RuntimeId) -> DurableState {
    let connection = Connection::open(database).expect("open committed state readback");
    let conversation_high_water = connection
        .query_row(
            "SELECT event_high_water FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read conversation HWM");
    let retention_indexed_through = connection
        .query_row(
            "SELECT indexed_through_event_seq FROM event_retention WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read retention HWM");
    let (journal_count, journal_bytes): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
             FROM event_journal WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read audit totals");
    let (stream_count, stream_bytes): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
             FROM event_stream_index WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read stream index totals");
    let (ledger_event_count, ledger_audit_bytes, ledger_stream_count, ledger_stream_bytes): (
        i64,
        i64,
        i64,
        i64,
    ) = connection
        .query_row(
            "SELECT event_count, audit_event_logical_bytes,
                    event_stream_count, event_stream_bytes
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read Runtime ledger totals");
    let appended_row = connection
        .query_row(
            "SELECT event_seq, command_id, logical_event_bytes
             FROM event_journal WHERE event_id = ?1",
            [&event_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, nonnegative(row.get::<_, i64>(2)?))),
        )
        .optional()
        .expect("read appended audit row");
    let appended_index_row = connection
        .query_row(
            "SELECT event_seq, logical_event_bytes
             FROM event_stream_index WHERE event_id = ?1",
            [&event_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, nonnegative(row.get::<_, i64>(1)?))),
        )
        .optional()
        .expect("read appended stream row");
    DurableState {
        conversation_high_water,
        retention_indexed_through,
        journal_count: nonnegative(journal_count),
        journal_bytes: nonnegative(journal_bytes),
        stream_count: nonnegative(stream_count),
        stream_bytes: nonnegative(stream_bytes),
        ledger_event_count: nonnegative(ledger_event_count),
        ledger_audit_bytes: nonnegative(ledger_audit_bytes),
        ledger_stream_count: nonnegative(ledger_stream_count),
        ledger_stream_bytes: nonnegative(ledger_stream_bytes),
        appended_row,
        appended_index_row,
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid fixture RuntimeId")
}

fn owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x11; 32],
        uid: 501,
        client_installation_id: [0x22; 16],
    }
}

async fn released_started_turn(
    store: &RuntimeStoreHandle,
    seed: u8,
) -> (RuntimeId, RuntimeId, RuntimeId) {
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, seed);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(1)),
            descriptor: runtime_descriptor::descriptor(b"execution event commit sample"),
        })
        .await
        .expect("create execution event conversation");
    runtime_configuration::configure_codex_revision_one(store, conversation_id).await;
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(),
            idempotency_key: format!("execution-event-commit-{seed}"),
            expected_configuration_revision: 1,
            payload: b"real prompt sample".to_vec(),
        })
        .await
        .expect("accept execution event command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh command cannot replay"),
    };
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(2));
    let execution_nonce = format!("execution-event-commit-nonce-{seed}").into_bytes();
    let turn_id = match store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("start execution event command")
    {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("fresh start cannot replay"),
    };
    store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: i64::from(seed) + 9_000,
            leader_pid: i64::from(seed) + 9_000,
            leader_start_time: u64::from(seed) + 9_000,
            payload: b"released execution fence".to_vec(),
        })
        .await
        .expect("persist execution fence");
    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce,
        })
        .await
        .expect("authorize execution release");
    (conversation_id, command.command_id, turn_id)
}

fn item_input(
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    event_id: RuntimeId,
) -> AppendExecutionEvent {
    AppendExecutionEvent::item(
        conversation_id,
        command_id,
        turn_id,
        event_id,
        ItemId::new("commit-item-id"),
        EntityId::new("commit-entity-id"),
        AgentItem::AssistantMessage {
            text: "committed execution event".to_owned(),
            meta: AgentItemMeta::default(),
        },
    )
}

async fn register_watch(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    generation: u64,
) -> StreamBarrierRegistration {
    let registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(generation).expect("valid watch generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::At(1),
            },
        })
        .await
        .expect("register execution event watcher");
    assert_eq!(registration.high_water, StreamCursor::At(1));
    registration
}

fn assert_committed_state(
    state: &DurableState,
    command_id: RuntimeId,
    expected_event_bytes: usize,
) {
    let seq = "00000000000000000002".to_owned();
    assert_eq!(state.conversation_high_water.as_deref(), Some(seq.as_str()));
    assert_eq!(
        state.retention_indexed_through.as_deref(),
        Some(seq.as_str())
    );
    assert_eq!(state.journal_count, 3);
    assert_eq!(state.stream_count, 3);
    assert_eq!(state.ledger_event_count, state.journal_count);
    assert_eq!(state.ledger_audit_bytes, state.journal_bytes);
    assert_eq!(state.ledger_stream_count, state.stream_count);
    assert_eq!(state.ledger_stream_bytes, state.stream_bytes);
    assert_eq!(
        state.appended_row,
        Some((
            seq.clone(),
            command_id.as_bytes().to_vec(),
            u64::try_from(expected_event_bytes).unwrap(),
        ))
    );
    assert_eq!(
        state.appended_index_row,
        Some((seq, u64::try_from(expected_event_bytes).unwrap()))
    );
}

#[tokio::test]
async fn append_commit_advances_row_hwm_index_ledger_and_watcher_together() {
    let root = TestRoot::new("atomic");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open atomic append store");
    let (conversation_id, command_id, turn_id) = released_started_turn(&store, 0x21).await;
    let mut registration = register_watch(&store, conversation_id, 1).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x24);
    let event = match store
        .append_execution_event(item_input(conversation_id, command_id, turn_id, event_id))
        .await
        .expect("append execution event")
    {
        AppendExecutionEventOutcome::Appended { event } => event,
        AppendExecutionEventOutcome::Replayed { .. } => panic!("fresh append cannot replay"),
    };
    assert_eq!(
        registration.watch.take_coalesced(),
        Some(StreamCursor::At(2))
    );
    let decoded: RuntimeEvent = serde_json::from_slice(&event.payload).expect("decode typed event");
    assert!(matches!(decoded.body, RuntimeEventBody::Item { .. }));
    assert_committed_state(
        &durable_state(&root.database(), conversation_id, event_id),
        command_id,
        event.payload.len(),
    );
    store
        .shutdown()
        .await
        .expect("shutdown atomic append store");
}

#[tokio::test]
async fn append_before_commit_fault_rolls_back_all_projections_and_does_not_notify() {
    let root = TestRoot::new("before-commit");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
            OneShotAppendFault::new(RuntimeStoreOperation::AppendExecutionEventBeforeCommit),
        )),
        root.storage_kek(&keys),
    )
    .await
    .expect("open before-COMMIT append store");
    let (conversation_id, command_id, turn_id) = released_started_turn(&store, 0x31).await;
    let mut registration = register_watch(&store, conversation_id, 2).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x34);
    let before = durable_state(&root.database(), conversation_id, event_id);
    assert!(matches!(
        store
            .append_execution_event(item_input(conversation_id, command_id, turn_id, event_id,))
            .await,
        Err(RuntimeStoreError::InvalidConfig(_))
    ));
    assert_eq!(registration.watch.take_coalesced(), None);
    assert_eq!(
        durable_state(&root.database(), conversation_id, event_id),
        before
    );
    store
        .shutdown()
        .await
        .expect("shutdown before-COMMIT append store");
}

#[tokio::test]
async fn append_after_commit_unknown_notifies_and_same_event_id_replays_exactly() {
    let root = TestRoot::new("after-commit");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
            OneShotAppendFault::new(RuntimeStoreOperation::AppendExecutionEventAfterCommit),
        )),
        root.storage_kek(&keys),
    )
    .await
    .expect("open after-COMMIT append store");
    let (conversation_id, command_id, turn_id) = released_started_turn(&store, 0x41).await;
    let mut registration = register_watch(&store, conversation_id, 3).await;
    let event_id = runtime_id(RuntimeIdKind::Event, 0x44);
    let input = item_input(conversation_id, command_id, turn_id, event_id);
    assert!(matches!(
        store.append_execution_event(input.clone()).await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AppendExecutionEvent
        })
    ));
    assert_eq!(
        registration.watch.take_coalesced(),
        Some(StreamCursor::At(2))
    );
    let committed = durable_state(&root.database(), conversation_id, event_id);
    let replay = match store
        .append_execution_event(input)
        .await
        .expect("retry committed execution event")
    {
        AppendExecutionEventOutcome::Replayed { event } => event,
        AppendExecutionEventOutcome::Appended { .. } => panic!("unknown COMMIT must replay"),
    };
    assert_eq!(replay.event_id, event_id);
    assert_eq!(replay.event_seq, 2);
    assert_committed_state(&committed, command_id, replay.payload.len());
    assert_eq!(
        durable_state(&root.database(), conversation_id, event_id),
        committed,
        "exact replay must not advance any durable projection",
    );
    assert_eq!(registration.watch.take_coalesced(), None);
    store
        .shutdown()
        .await
        .expect("shutdown after-COMMIT append store");
}
