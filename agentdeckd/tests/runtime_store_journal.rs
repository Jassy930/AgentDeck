#[path = "support/runtime_configuration.rs"]
mod runtime_configuration;
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::TurnSummary;
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CommandState, CommandTerminal,
    CompleteCommand, CompleteOutcome, ExecutionFence, IdempotencyOwner, NewConversation,
    RuntimeClock, RuntimeClockError, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreHandle, StartCommand, StartOutcome,
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
            "agentdeckd-runtime-journal-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create journal root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure journal root");
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
            .expect("load journal StorageKEK")
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

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn conversation_input(seed: u8, descriptor: &[u8]) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: runtime_descriptor::descriptor(descriptor),
    }
}

fn local_owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x10; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

fn remote_owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Remote {
        machine_trust_domain: [0x10; 32],
        device_route: [seed; 16],
        device_sign_fingerprint: [seed.wrapping_add(1); 32],
    }
}

async fn create_conversation(
    store: &RuntimeStoreHandle,
    clock: &ManualClock,
    seed: u8,
    descriptor: &[u8],
    now_ms: u64,
) -> agentdeckd::runtime::store::ConversationRecord {
    clock.set(now_ms);
    store
        .create_conversation(conversation_input(seed, descriptor))
        .await
        .expect("create conversation")
}

async fn accept(
    store: &RuntimeStoreHandle,
    clock: &ManualClock,
    conversation_id: RuntimeId,
    owner: IdempotencyOwner,
    key: &str,
    payload: &[u8],
    now_ms: u64,
) -> AcceptOutcome {
    clock.set(now_ms);
    runtime_configuration::configure_codex_revision_one(store, conversation_id).await;
    store
        .accept_command(AcceptCommand {
            conversation_id,
            owner,
            idempotency_key: key.to_owned(),
            expected_configuration_revision: 1,
            payload: payload.to_vec(),
        })
        .await
        .expect("accept command")
}

fn assert_no_sentinel(database: &Path, sentinel: &[u8]) {
    for path in [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ] {
        let Ok(bytes) = fs::read(&path) else { continue };
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel),
            "plaintext sentinel leaked into {}",
            path.display()
        );
    }
}

#[tokio::test]
async fn catalog_command_sequences_and_idempotency_survive_restart() {
    let root = TestRoot::new("restart-idempotency");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let clock = ManualClock::new(1_000);
    let config = RuntimeStoreConfig::new(database.clone()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open store");
    let conversation =
        create_conversation(&store, &clock, 1, b"private-title-and-cwd", 1_000).await;
    assert_eq!(
        conversation.conversation_id.kind(),
        RuntimeIdKind::Conversation
    );
    assert_eq!(
        conversation.adapter_state_key.kind(),
        RuntimeIdKind::AdapterState
    );
    assert_eq!(conversation.catalog_revision, 0);

    let first = accept(
        &store,
        &clock,
        conversation.conversation_id,
        local_owner(1),
        "request-1",
        b"prompt-sentinel-alpha",
        1_001,
    )
    .await;
    let first_command = match first {
        AcceptOutcome::Accepted {
            command,
            queue_position,
        } => {
            assert_eq!(queue_position, 0);
            assert_eq!(command.command_seq, 0);
            assert_eq!(command.command_id.kind(), RuntimeIdKind::Command);
            command
        }
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };
    let replay = accept(
        &store,
        &clock,
        conversation.conversation_id,
        local_owner(1),
        "request-1",
        b"prompt-sentinel-alpha",
        1_002,
    )
    .await;
    assert!(matches!(
        replay,
        AcceptOutcome::Replayed { command } if command.command_id == first_command.command_id
    ));
    clock.set(1_003);
    let conflict = store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: local_owner(1),
            idempotency_key: "request-1".to_owned(),
            expected_configuration_revision: 1,
            payload: b"different prompt".to_vec(),
        })
        .await
        .expect_err("same owner/key with different payload conflicts");
    assert!(matches!(conflict, RuntimeStoreError::IdempotencyConflict));

    let second = accept(
        &store,
        &clock,
        conversation.conversation_id,
        local_owner(1),
        "request-2",
        b"prompt-sentinel-beta",
        1_004,
    )
    .await;
    assert!(matches!(
        second,
        AcceptOutcome::Accepted {
            command,
            queue_position: 1,
        } if command.command_seq == 1
    ));
    assert_no_sentinel(&database, b"prompt-sentinel-alpha");
    assert_no_sentinel(&database, b"private-title-and-cwd");
    store.shutdown().await.expect("shutdown store");

    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen store");
    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("load recovery");
    assert_eq!(recovery.conversations.len(), 1);
    assert_eq!(
        recovery.conversations[0].descriptor,
        runtime_descriptor::descriptor(b"private-title-and-cwd")
    );
    assert_eq!(recovery.accepted.len(), 2);
    assert_eq!(recovery.accepted[0].payload, b"prompt-sentinel-alpha");
    assert_eq!(recovery.accepted[1].payload, b"prompt-sentinel-beta");
    let next = create_conversation(&reopened, &clock, 2, b"second", 2_000).await;
    assert_eq!(next.catalog_revision, 1);
    reopened.shutdown().await.expect("shutdown reopened store");
    assert_no_sentinel(&database, b"prompt-sentinel-alpha");
}

#[tokio::test]
async fn idempotency_namespace_is_owner_and_conversation_scoped() {
    let root = TestRoot::new("owner-scope");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let first_conversation = create_conversation(&store, &clock, 1, b"one", 1).await;
    let second_conversation = create_conversation(&store, &clock, 2, b"two", 2).await;

    let local = accept(
        &store,
        &clock,
        first_conversation.conversation_id,
        local_owner(1),
        "same-key",
        b"same-payload",
        10,
    )
    .await;
    let remote = accept(
        &store,
        &clock,
        first_conversation.conversation_id,
        remote_owner(1),
        "same-key",
        b"same-payload",
        11,
    )
    .await;
    let other_conversation = accept(
        &store,
        &clock,
        second_conversation.conversation_id,
        local_owner(1),
        "same-key",
        b"same-payload",
        12,
    )
    .await;
    let command_ids = [local, remote, other_conversation].map(|outcome| match outcome {
        AcceptOutcome::Accepted { command, .. } => command.command_id,
        AcceptOutcome::Replayed { .. } => panic!("independent namespace cannot replay"),
    });
    assert_ne!(command_ids[0], command_ids[1]);
    assert_ne!(command_ids[0], command_ids[2]);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn per_conversation_queue_limit_is_exact_and_replay_precedes_admission() {
    let root = TestRoot::new("queue-limit");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, &clock, 1, b"queue", 1).await;
    let mut first_command_id = None;
    for index in 0..32_u32 {
        let outcome = accept(
            &store,
            &clock,
            conversation.conversation_id,
            local_owner(1),
            &format!("key-{index}"),
            format!("payload-{index}").as_bytes(),
            100 + u64::from(index),
        )
        .await;
        let AcceptOutcome::Accepted {
            command,
            queue_position,
        } = outcome
        else {
            panic!("unique command must be accepted")
        };
        assert_eq!(queue_position, index);
        if index == 0 {
            first_command_id = Some(command.command_id);
        }
    }
    clock.set(200);
    let error = store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: local_owner(1),
            idempotency_key: "overflow".to_owned(),
            expected_configuration_revision: 1,
            payload: b"overflow".to_vec(),
        })
        .await
        .expect_err("33rd queued command must fail");
    assert!(matches!(
        error,
        RuntimeStoreError::QueueFull {
            scope: agentdeckd::runtime::store::QueueScope::Conversation
        }
    ));
    let replay = accept(
        &store,
        &clock,
        conversation.conversation_id,
        local_owner(1),
        "key-0",
        b"payload-0",
        201,
    )
    .await;
    assert!(matches!(
        replay,
        AcceptOutcome::Replayed { command } if Some(command.command_id) == first_command_id
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn start_fence_and_complete_are_atomic_idempotent_transitions() {
    let root = TestRoot::new("execution-transitions");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, &clock, 1, b"execution", 1).await;
    let first = accept(
        &store,
        &clock,
        conversation.conversation_id,
        local_owner(1),
        "first",
        b"first prompt",
        10,
    )
    .await;
    let second = accept(
        &store,
        &clock,
        conversation.conversation_id,
        local_owner(1),
        "second",
        b"second prompt",
        11,
    )
    .await;
    let command = match first {
        AcceptOutcome::Accepted { command, .. } => command,
        _ => unreachable!(),
    };
    let second_command = match second {
        AcceptOutcome::Accepted { command, .. } => command,
        _ => unreachable!(),
    };
    let daemon_boot_id =
        agentdeckd::runtime::store::RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x55; 16])
            .expect("daemon boot id");

    clock.set(20);
    let out_of_order = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: second_command.command_id,
            daemon_boot_id,
            execution_nonce: b"nonce-second".to_vec(),
        })
        .await
        .expect_err("only queue head can start");
    assert!(matches!(out_of_order, RuntimeStoreError::NotQueueHead));

    let start_input = || StartCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        daemon_boot_id,
        execution_nonce: b"nonce-first".to_vec(),
    };
    let started = store
        .mark_started_with_event(start_input())
        .await
        .expect("start queue head");
    let (started_command, intent, started_event) = match started {
        StartOutcome::Started {
            command,
            intent,
            event,
        } => (command, intent, event),
        StartOutcome::Replayed { .. } => panic!("first start cannot replay"),
    };
    assert_eq!(started_command.state, CommandState::Started);
    assert_eq!(intent.turn_id.kind(), RuntimeIdKind::Turn);
    assert_eq!(started_event.event_seq, 1);
    let intent_json: serde_json::Value =
        serde_json::from_slice(&intent.payload).expect("decode Store-owned intent");
    assert_eq!(intent_json["kind"], "runtimeExecutionIntent");
    assert!(intent_json.get("prompt").is_none() && intent_json.get("vendor").is_none());
    let started_wire: RuntimeEvent =
        serde_json::from_slice(&started_event.payload).expect("decode Store-owned TurnStarted");
    assert_eq!(
        started_wire.command_id.as_ref().map(|id| id.as_str()),
        Some(command.command_id.to_canonical_string()).as_deref()
    );
    assert!(started_wire.item_id.is_none() && started_wire.entity_id.is_none());
    assert!(matches!(
        started_wire.body,
        RuntimeEventBody::TurnStarted { ref turn_id }
            if turn_id.as_str() == intent.turn_id.to_canonical_string()
    ));
    let replay = store
        .mark_started_with_event(start_input())
        .await
        .expect("exact start retry");
    assert!(matches!(
        replay,
        StartOutcome::Replayed { intent: replay, .. } if replay.turn_id == intent.turn_id
    ));
    clock.set(21);
    let concurrent_started = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: second_command.command_id,
            daemon_boot_id,
            execution_nonce: b"nonce-second-after-head".to_vec(),
        })
        .await
        .expect_err("one conversation cannot own two Started turns");
    assert!(matches!(
        concurrent_started,
        RuntimeStoreError::InvalidStateTransition
    ));
    let conflict = store
        .mark_started_with_event(StartCommand {
            execution_nonce: b"different nonce".to_vec(),
            ..start_input()
        })
        .await
        .expect_err("different start nonce conflicts");
    assert!(matches!(conflict, RuntimeStoreError::StartConflict));

    let fence_input = || ExecutionFence {
        command_id: command.command_id,
        daemon_boot_id,
        execution_nonce: b"nonce-first".to_vec(),
        process_group_id: 4242,
        leader_pid: 4243,
        leader_start_time: 99,
        payload: b"fence-private".to_vec(),
    };
    let fence = store
        .persist_execution_fence(fence_input())
        .await
        .expect("persist fence");
    assert_eq!(fence.process_group_id, 4242);
    assert_eq!(
        store
            .persist_execution_fence(fence_input())
            .await
            .expect("exact fence retry"),
        fence
    );
    let fence_conflict = store
        .persist_execution_fence(ExecutionFence {
            leader_pid: 9999,
            ..fence_input()
        })
        .await
        .expect_err("different fence conflicts");
    assert!(matches!(fence_conflict, RuntimeStoreError::FenceConflict));

    clock.set(25);
    let released_fence = store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: b"nonce-first".to_vec(),
        })
        .await
        .expect("authorize execution release");
    assert_eq!(released_fence.release_authorized_at_ms, Some(25));

    clock.set(30);
    let complete_input = || CompleteCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        turn_id: intent.turn_id,
        terminal: CommandTerminal::completed(TurnSummary {
            total_input_tokens: None,
            total_output_tokens: None,
            elapsed_ms: 7,
        }),
    };
    let completed = store
        .complete_command_with_event(complete_input())
        .await
        .expect("complete command");
    let (completed_event_id, completed_event_payload) = match completed {
        CompleteOutcome::Completed { command, event } => {
            assert_eq!(command.state, CommandState::Completed);
            assert_eq!(event.event_seq, 2);
            let wire: RuntimeEvent =
                serde_json::from_slice(&event.payload).expect("decode Store-owned TurnCompleted");
            assert!(matches!(
                wire.body,
                RuntimeEventBody::TurnCompleted { summary, .. }
                    if summary.elapsed_ms == 7
                        && summary.total_input_tokens.is_none()
                        && summary.total_output_tokens.is_none()
            ));
            (event.event_id, event.payload)
        }
        CompleteOutcome::Replayed { .. } => panic!("first complete cannot replay"),
    };
    let replayed = store
        .complete_command_with_event(complete_input())
        .await
        .expect("exact terminal retry");
    assert!(matches!(
        replayed,
        CompleteOutcome::Replayed { ref event, .. }
            if event.event_id == completed_event_id
                && event.payload == completed_event_payload
    ));
    let terminal_conflict = store
        .complete_command_with_event(CompleteCommand {
            terminal: CommandTerminal::completed(TurnSummary {
                total_input_tokens: Some(1),
                total_output_tokens: None,
                elapsed_ms: 7,
            }),
            ..complete_input()
        })
        .await
        .expect_err("different terminal payload conflicts");
    assert!(matches!(
        terminal_conflict,
        RuntimeStoreError::TerminalConflict
    ));

    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load post-completion recovery");
    assert!(recovery.started.is_empty());
    assert_eq!(recovery.accepted.len(), 1);
    assert_eq!(recovery.accepted[0].command_id, second_command.command_id);
    store.shutdown().await.expect("shutdown store");
    assert_no_sentinel(&root.database(), b"intent-private");
    assert_no_sentinel(&root.database(), b"result-private");
}

#[tokio::test]
async fn command_expires_exactly_at_the_24_hour_boundary() {
    let root = TestRoot::new("expiry");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = create_conversation(&store, &clock, 1, b"expiry", 1).await;
    let accepted = accept(
        &store,
        &clock,
        conversation.conversation_id,
        local_owner(1),
        "expires",
        b"payload",
        1_000,
    )
    .await;
    let command = match accepted {
        AcceptOutcome::Accepted { command, .. } => command,
        _ => unreachable!(),
    };
    let daemon_boot_id =
        agentdeckd::runtime::store::RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x77; 16])
            .expect("daemon boot id");
    clock.set(1_000 + 24 * 60 * 60 * 1_000);
    let error = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: b"nonce".to_vec(),
        })
        .await
        .expect_err("expiry boundary is exclusive");
    assert!(matches!(error, RuntimeStoreError::CommandExpired));
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load recovery");
    assert!(recovery.accepted.is_empty());
    assert!(recovery.started.is_empty());
    store.shutdown().await.expect("shutdown store");
}
