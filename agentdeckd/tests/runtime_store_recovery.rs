use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeckd::runtime::model::{COMMAND_QUEUE_TTL_MS, RuntimeClock, RuntimeClockError};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CommandTerminal, CompleteCommand,
    ConversationLifecycle, ExecutionFence, IdempotencyOwner, MarkConversationRecoveryBlocked,
    NewConversation, RecoverStartedCommand, RecoveryBlockedCommandBinding, RecoveryFenceBinding,
    RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreHandle,
    RuntimeStoreLane, StartCommand,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

#[path = "support/store_admission.rs"]
mod store_admission;

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
            "agentdeckd-runtime-recovery-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create recovery root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure recovery root");
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
            .expect("load recovery StorageKEK")
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
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid runtime id")
}

fn conversation_input(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: runtime_descriptor::descriptor(format!("recovery-{seed}").as_bytes()),
    }
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x11; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

const SMALL_SAFETY_LANE_BYTES: usize = 64 * 1024;
const OVERSIZED_FENCE_NONCE_CAPACITY: usize = 128 * 1024;

fn oversized_boxed_started_binding(
    command_id: RuntimeId,
    turn_id: RuntimeId,
    daemon_boot_id: RuntimeId,
) -> RecoveryBlockedCommandBinding {
    let execution_nonce = vec![0x51];
    assert_eq!(execution_nonce.capacity(), 1, "outer nonce sample capacity");
    let mut fence_nonce = Vec::with_capacity(OVERSIZED_FENCE_NONCE_CAPACITY);
    fence_nonce.push(0x52);
    RecoveryBlockedCommandBinding::Started {
        command_id,
        turn_id,
        daemon_boot_id,
        execution_nonce,
        fence: Some(Box::new(RecoveryFenceBinding {
            command_id,
            daemon_boot_id,
            execution_nonce: fence_nonce,
            process_group_id: 5_201,
            leader_pid: 5_201,
            leader_start_time: 91,
            release_authorized_at_ms: Some(92),
            payload_bytes: 32,
            payload_sha256: [0x53; 32],
        })),
    }
}

fn assert_safety_lane_busy(error: RuntimeStoreError) {
    assert!(matches!(
        error,
        RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Safety
        }
    ));
}

#[tokio::test]
async fn recover_started_charges_boxed_fence_nonce_before_safety_dispatch() {
    // 威胁场景：异常 recovery plan 把超大 allocation 藏进 boxed fence nonce；若漏计，
    // RecoverStartedCommand 会越过 64 KiB safety-lane cap 并进入 worker。
    let root = TestRoot::new("recover-started-box-charge");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_lane_byte_capacity(SMALL_SAFETY_LANE_BYTES),
        root.storage_kek(&keys),
    )
    .await
    .expect("open recover-started box charge store");
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x51);
    let command_id = runtime_id(RuntimeIdKind::Command, 0x52);
    let turn_id = runtime_id(RuntimeIdKind::Turn, 0x53);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x54);

    let error = store
        .recover_started_command_with_event(RecoverStartedCommand {
            completion: CompleteCommand {
                conversation_id,
                command_id,
                turn_id,
                terminal: CommandTerminal::interrupted(),
            },
            expected_started: oversized_boxed_started_binding(command_id, turn_id, daemon_boot_id),
        })
        .await
        .expect_err("boxed fence nonce must exceed the Safety lane budget");
    assert_safety_lane_busy(error);
    store.inspect().await.expect("read lane remains available");
    store
        .shutdown()
        .await
        .expect("shutdown recovery charge store");
}

#[tokio::test]
async fn mark_recovery_blocked_charges_boxed_fence_nonce_before_safety_dispatch() {
    // 威胁场景：异常 Started binding 用短 nonce 长度配超大 fence nonce capacity；若漏计，
    // RecoveryBlocked lifecycle CAS 可绕过 safety-lane byte cap。
    let root = TestRoot::new("mark-blocked-box-charge");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_lane_byte_capacity(SMALL_SAFETY_LANE_BYTES),
        root.storage_kek(&keys),
    )
    .await
    .expect("open mark-blocked box charge store");
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x61);
    let command_id = runtime_id(RuntimeIdKind::Command, 0x62);
    let turn_id = runtime_id(RuntimeIdKind::Turn, 0x63);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x64);

    let error = store
        .mark_conversation_recovery_blocked(MarkConversationRecoveryBlocked {
            conversation_id,
            expected_command: Some(oversized_boxed_started_binding(
                command_id,
                turn_id,
                daemon_boot_id,
            )),
        })
        .await
        .expect_err("boxed fence nonce must exceed the Safety lane budget");
    assert_safety_lane_busy(error);
    store.inspect().await.expect("read lane remains available");
    store
        .shutdown()
        .await
        .expect("shutdown blocked charge store");
}

async fn accept(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    seed: u8,
    payload: Vec<u8>,
) {
    assert!(matches!(
        store
            .accept_command(AcceptCommand {
                conversation_id,
                owner: owner(seed),
                idempotency_key: format!("request-{seed}"),
                payload,
            })
            .await
            .expect("accept recovery command"),
        AcceptOutcome::Accepted { .. }
    ));
}

#[tokio::test]
async fn recovery_pages_one_conversation_exactly_and_blocks_mutation_until_finish() {
    let root = TestRoot::new("paged");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open recovery store");
    let first = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create first conversation");
    let second = store
        .create_conversation(conversation_input(2))
        .await
        .expect("create second conversation");
    accept(&store, first.conversation_id, 1, b"first".to_vec()).await;
    accept(&store, second.conversation_id, 2, b"second".to_vec()).await;

    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin recovery scan");
    assert_eq!(
        store
            .begin_recovery_scan()
            .await
            .expect("lost begin reply retries exactly"),
        cursor
    );
    let first_page = store
        .load_recovery_page(cursor.clone())
        .await
        .expect("load first page");
    assert_eq!(
        store
            .load_recovery_page(cursor)
            .await
            .expect("lost page reply retries exactly"),
        first_page
    );
    let first_slice = first_page
        .conversation
        .as_ref()
        .expect("first page has one conversation");
    assert_eq!(
        first_slice.conversation.conversation_id,
        first.conversation_id
    );
    assert_eq!(first_slice.accepted.len(), 1);
    assert!(first_slice.started.is_none());
    assert!(first_page.completion.is_none());

    assert!(matches!(
        store.create_conversation(conversation_input(3)).await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));

    let second_cursor = first_page.next_cursor.expect("second page cursor");
    let second_page = store
        .load_recovery_page(second_cursor.clone())
        .await
        .expect("load second page");
    let second_slice = second_page
        .conversation
        .as_ref()
        .expect("second page has one conversation");
    assert_eq!(
        second_slice.conversation.conversation_id,
        second.conversation_id
    );
    assert!(second_page.next_cursor.is_none());
    let completion = second_page
        .completion
        .clone()
        .expect("terminal page has completion token");
    assert_eq!(
        store
            .load_recovery_page(second_cursor)
            .await
            .expect("terminal page retry is exact"),
        second_page
    );
    store
        .finish_recovery_scan(completion.clone())
        .await
        .expect("finish complete recovery scan");
    store
        .finish_recovery_scan(completion)
        .await
        .expect("lost finish reply retries exactly");
    store
        .create_conversation(conversation_input(3))
        .await
        .expect("writes resume only after explicit finish");
    store.shutdown().await.expect("shutdown recovery store");
}

#[tokio::test]
async fn recovery_sweeps_expired_commands_before_freezing_the_page_counts() {
    let root = TestRoot::new("expiry-first");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open expiry recovery store");
    let conversation = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create conversation");
    accept(
        &store,
        conversation.conversation_id,
        1,
        vec![0x44; 16 * 1024],
    )
    .await;
    clock.set(1_000 + COMMAND_QUEUE_TTL_MS);

    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("expiry sweep precedes frozen scan");
    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load post-expiry page");
    let slice = page.conversation.expect("conversation remains in catalog");
    assert!(slice.accepted.is_empty());
    assert!(slice.started.is_none());
    assert_eq!(slice.conversation.accepted_command_count, 0);
    assert_eq!(slice.conversation.event_high_water, Some(0));
    store
        .finish_recovery_scan(page.completion.expect("single page completes"))
        .await
        .expect("finish post-expiry scan");
    store
        .shutdown()
        .await
        .expect("shutdown expiry recovery store");
}

#[tokio::test]
async fn recovery_blocked_cas_rejects_every_stale_started_binding_field() {
    // 威胁场景：陈旧 recovery/actor 只命中 command+turn，却携带另一次 boot、nonce、
    // process identity 或 release record；宽松 CAS 会把错误 execution 永久标成已阻断。
    let root = TestRoot::new("exact-blocked-binding");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open exact blocked store");
    let conversation = store
        .create_conversation(conversation_input(0x31))
        .await
        .expect("create exact blocked conversation");
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: owner(0x32),
            idempotency_key: "exact-blocked".to_owned(),
            payload: b"exact blocked binding".to_vec(),
        })
        .await
        .expect("accept exact blocked command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh exact blocked command replayed"),
    };
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x33);
    let execution_nonce = b"exact-blocked-nonce".to_vec();
    let started = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("start exact blocked command");
    let turn_id = match started {
        agentdeckd::runtime::store::StartOutcome::Started { intent, .. } => intent.turn_id,
        agentdeckd::runtime::store::StartOutcome::Replayed { .. } => {
            panic!("fresh exact blocked start replayed")
        }
    };
    store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: 4_201,
            leader_pid: 4_201,
            leader_start_time: 77,
            payload: vec![0x34; 32],
        })
        .await
        .expect("persist exact blocked fence");
    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("authorize exact blocked release");

    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("scan exact blocked record");
    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load exact blocked record");
    let started = page
        .conversation
        .as_ref()
        .and_then(|recovery| recovery.started.as_ref())
        .expect("exact blocked Started readback")
        .clone();
    store
        .finish_recovery_scan(page.completion.expect("single exact blocked page"))
        .await
        .expect("finish exact blocked scan");
    let exact = RecoveryBlockedCommandBinding::Started {
        command_id: command.command_id,
        turn_id,
        daemon_boot_id,
        execution_nonce,
        fence: started
            .fence
            .as_ref()
            .map(RecoveryFenceBinding::from_record)
            .map(Box::new),
    };

    let mut stale = Vec::new();
    let mut wrong = exact.clone();
    let RecoveryBlockedCommandBinding::Started { command_id, .. } = &mut wrong else {
        unreachable!()
    };
    *command_id = runtime_id(RuntimeIdKind::Command, 0x41);
    stale.push(("command", wrong));
    let mut wrong = exact.clone();
    let RecoveryBlockedCommandBinding::Started {
        turn_id: wrong_turn_id,
        ..
    } = &mut wrong
    else {
        unreachable!()
    };
    *wrong_turn_id = runtime_id(RuntimeIdKind::Turn, 0x42);
    stale.push(("turn", wrong));
    let mut wrong = exact.clone();
    let RecoveryBlockedCommandBinding::Started {
        daemon_boot_id: wrong_boot_id,
        ..
    } = &mut wrong
    else {
        unreachable!()
    };
    *wrong_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x43);
    stale.push(("boot", wrong));
    let mut wrong = exact.clone();
    let RecoveryBlockedCommandBinding::Started {
        execution_nonce, ..
    } = &mut wrong
    else {
        unreachable!()
    };
    execution_nonce[0] ^= 1;
    stale.push(("nonce", wrong));
    for label in [
        "pgid",
        "pid",
        "start-time",
        "release-time",
        "payload-bytes",
        "payload-hash",
    ] {
        let mut wrong = exact.clone();
        let RecoveryBlockedCommandBinding::Started {
            fence: Some(fence), ..
        } = &mut wrong
        else {
            unreachable!()
        };
        match label {
            "pgid" => fence.process_group_id += 1,
            "pid" => fence.leader_pid += 1,
            "start-time" => fence.leader_start_time += 1,
            "release-time" => {
                fence.release_authorized_at_ms =
                    fence.release_authorized_at_ms.map(|value| value + 1)
            }
            "payload-bytes" => fence.payload_bytes += 1,
            "payload-hash" => fence.payload_sha256[0] ^= 1,
            _ => unreachable!(),
        }
        stale.push((label, wrong));
    }
    stale.push((
        "missing-fence",
        RecoveryBlockedCommandBinding::Started {
            command_id: command.command_id,
            turn_id,
            daemon_boot_id,
            execution_nonce: started.intent.execution_nonce.clone(),
            fence: None,
        },
    ));

    for (label, expected_command) in stale {
        assert!(
            store
                .mark_conversation_recovery_blocked(MarkConversationRecoveryBlocked {
                    conversation_id: conversation.conversation_id,
                    expected_command: Some(expected_command),
                })
                .await
                .is_err(),
            "stale {label} binding unexpectedly won the lifecycle CAS"
        );
    }
    for expected_command in [
        None,
        Some(RecoveryBlockedCommandBinding::Accepted {
            command_id: command.command_id,
        }),
    ] {
        assert!(
            store
                .mark_conversation_recovery_blocked(MarkConversationRecoveryBlocked {
                    conversation_id: conversation.conversation_id,
                    expected_command,
                })
                .await
                .is_err(),
            "non-Started binding unexpectedly blocked a Started command"
        );
    }
    let blocked = store
        .mark_conversation_recovery_blocked(MarkConversationRecoveryBlocked {
            conversation_id: conversation.conversation_id,
            expected_command: Some(exact),
        })
        .await
        .expect("exact Started binding wins lifecycle CAS");
    assert_eq!(blocked.lifecycle, ConversationLifecycle::RecoveryBlocked);
    store
        .shutdown()
        .await
        .expect("shutdown exact blocked store");
}

#[tokio::test]
async fn recovery_memory_is_bounded_per_conversation_not_by_the_total_queue_or_lane_budget() {
    let root = TestRoot::new("independent-budget");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_lane_byte_capacity(8 * 1024),
        root.storage_kek(&keys),
    )
    .await
    .expect("open small-lane recovery store");
    for seed in 1..=16_u8 {
        let conversation = store
            .create_conversation(conversation_input(seed))
            .await
            .expect("create paged conversation");
        accept(
            &store,
            conversation.conversation_id,
            seed,
            vec![seed; 4 * 1024],
        )
        .await;
    }

    let mut cursor = store
        .begin_recovery_scan()
        .await
        .expect("total recovery set may exceed lane budget");
    let mut recovered = 0_usize;
    let completion = loop {
        let page = store
            .load_recovery_page(cursor)
            .await
            .expect("load bounded recovery page");
        assert!(page.conversation.is_some());
        recovered += 1;
        match (page.next_cursor, page.completion) {
            (Some(next), None) => cursor = next,
            (None, Some(completion)) => break completion,
            _ => panic!("page cursor/completion shape must be canonical"),
        }
    };
    assert_eq!(recovered, 16);
    store
        .finish_recovery_scan(completion)
        .await
        .expect("finish bounded recovery scan");
    store.shutdown().await.expect("shutdown small-lane store");
}

#[tokio::test]
async fn a_cursor_from_another_scan_is_rejected_without_advancing_the_valid_scan() {
    let first_root = TestRoot::new("wrong-cursor-first");
    let second_root = TestRoot::new("wrong-cursor-second");
    let first_keys = MemoryKeyStore::new();
    let second_keys = MemoryKeyStore::new();
    let first = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(first_root.database()),
        first_root.storage_kek(&first_keys),
    )
    .await
    .expect("open first recovery store");
    let second = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(second_root.database()),
        second_root.storage_kek(&second_keys),
    )
    .await
    .expect("open second recovery store");
    first
        .create_conversation(conversation_input(1))
        .await
        .expect("create first recovery row");
    second
        .create_conversation(conversation_input(2))
        .await
        .expect("create second recovery row");

    let valid_cursor = first.begin_recovery_scan().await.expect("begin first scan");
    let foreign_cursor = second
        .begin_recovery_scan()
        .await
        .expect("begin second scan");
    assert!(matches!(
        first.load_recovery_page(foreign_cursor).await,
        Err(RuntimeStoreError::InvalidRecoveryCursor)
    ));
    let first_page = first
        .load_recovery_page(valid_cursor)
        .await
        .expect("valid cursor still starts at first page");
    assert_eq!(
        first_page
            .conversation
            .as_ref()
            .expect("first page record")
            .conversation
            .conversation_id,
        runtime_id(RuntimeIdKind::Conversation, 1)
    );
    first
        .finish_recovery_scan(first_page.completion.expect("first terminal page"))
        .await
        .expect("finish first scan");

    let second_page = second
        .load_recovery_page(
            second
                .begin_recovery_scan()
                .await
                .expect("unconsumed begin retry is exact"),
        )
        .await
        .expect("load second page");
    second
        .finish_recovery_scan(second_page.completion.expect("second terminal page"))
        .await
        .expect("finish second scan");
    first.shutdown().await.expect("shutdown first store");
    second.shutdown().await.expect("shutdown second store");
}
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
