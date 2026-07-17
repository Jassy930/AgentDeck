#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CommandTerminal, CompleteCommand,
    CompleteOutcome, ExecutionFence, IdempotencyOwner, MachineEnrollmentReceiptRecord,
    NewConversation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreHandle, StartCommand, StartOutcome,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, params};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const RUNTIME_DB_HARD_LIMIT_BYTES: u64 = 2 * GIB;

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
            "agentdeckd-runtime-capacity-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create capacity root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure capacity root");
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
            .expect("load capacity StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
struct MutableProbe {
    observations: Arc<Mutex<VecDeque<RuntimeCapacityObservation>>>,
    fallback: Arc<Mutex<RuntimeCapacityObservation>>,
}

impl MutableProbe {
    fn new(fallback: RuntimeCapacityObservation) -> Self {
        Self {
            observations: Arc::new(Mutex::new(VecDeque::new())),
            fallback: Arc::new(Mutex::new(fallback)),
        }
    }

    fn set(&self, observation: RuntimeCapacityObservation) {
        *self.fallback.lock().expect("capacity fallback lock") = observation;
    }

    fn script(&self, observations: impl IntoIterator<Item = RuntimeCapacityObservation>) {
        self.observations
            .lock()
            .expect("capacity script lock")
            .extend(observations);
    }
}

impl RuntimeCapacityProbe for MutableProbe {
    fn observe(
        &self,
        _database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        if let Some(observation) = self
            .observations
            .lock()
            .expect("capacity script lock")
            .pop_front()
        {
            return Ok(observation);
        }
        Ok(*self.fallback.lock().expect("capacity fallback lock"))
    }
}

fn healthy_observation() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        main_bytes: 8 * MIB,
        wal_bytes: 2 * MIB,
        shm_bytes: 32 * 1024,
        filesystem_total_bytes: 20 * GIB,
        filesystem_available_bytes: 4 * GIB,
    }
}

fn low_disk_observation() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        filesystem_total_bytes: 4 * GIB,
        filesystem_available_bytes: 512 * MIB - 1,
        ..healthy_observation()
    }
}

fn over_limit_observation() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        main_bytes: RUNTIME_DB_HARD_LIMIT_BYTES + 1,
        wal_bytes: 0,
        shm_bytes: 0,
        filesystem_available_bytes: 8 * GIB,
        ..healthy_observation()
    }
}

fn insufficient_terminal_tail_observation() -> RuntimeCapacityObservation {
    terminal_tail_observation(520 * MIB)
}

fn terminal_tail_observation(filesystem_available_bytes: u64) -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        filesystem_total_bytes: 4 * GIB,
        filesystem_available_bytes,
        ..healthy_observation()
    }
}

fn local_owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x10; 32],
        uid: 501,
        client_installation_id: [0x20; 16],
    }
}

fn daemon_boot_id() -> RuntimeId {
    RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x55; 16]).expect("daemon boot id")
}

fn conversation_input(seed: u8, descriptor: &[u8]) -> NewConversation {
    NewConversation {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
            .expect("conversation id"),
        adapter_state_key: RuntimeId::from_bytes(
            RuntimeIdKind::AdapterState,
            [seed.wrapping_add(0x40); 16],
        )
        .expect("adapter state key"),
        descriptor: runtime_descriptor::descriptor(descriptor),
    }
}

#[tokio::test]
async fn fresh_store_reads_back_the_exact_two_gib_max_page_count() {
    let root = TestRoot::new("max-page-count");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");

    let snapshot = store.inspect().await.expect("inspect runtime store");
    assert!(snapshot.page_size_bytes > 0);
    assert!(snapshot.page_count <= snapshot.max_page_count);
    assert_eq!(
        snapshot.max_page_count,
        RUNTIME_DB_HARD_LIMIT_BYTES / snapshot.page_size_bytes
    );

    store.shutdown().await.expect("shutdown runtime store");
}

#[tokio::test]
async fn disk_low_rejects_new_side_effects_with_a_typed_retryable_error() {
    let root = TestRoot::new("disk-low");
    let keys = MemoryKeyStore::new();
    let probe = MutableProbe::new(low_disk_observation());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");

    let error = store
        .create_conversation(conversation_input(1, b"blocked"))
        .await
        .expect_err("disk-low must reject an ordinary write");
    assert!(matches!(error, RuntimeStoreError::DiskLow { .. }));
    assert_eq!(error.code(), "daemon.runtime.disk_low");

    probe.set(healthy_observation());
    store
        .create_conversation(conversation_input(2, b"retry"))
        .await
        .expect("disk-low rejection must not permanently latch SafetyOnly");
    store.shutdown().await.expect("shutdown runtime store");
}

#[tokio::test]
async fn post_commit_disk_low_readback_does_not_permanently_latch_safety_only() {
    let root = TestRoot::new("post-commit-disk-low");
    let keys = MemoryKeyStore::new();
    let probe = MutableProbe::new(healthy_observation());
    probe.script([healthy_observation(), low_disk_observation()]);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open post-commit capacity store");

    store
        .create_conversation(conversation_input(1, b"committed-before-low-readback"))
        .await
        .expect("first write commits before post-commit DiskLow observation");
    probe.set(healthy_observation());
    store
        .create_conversation(conversation_input(2, b"healthy-retry"))
        .await
        .expect("DiskLow readback must not latch SafetyOnly");
    store.shutdown().await.expect("shutdown capacity store");
}

#[tokio::test]
async fn accepted_and_started_replays_bypass_disk_low_admission() {
    let root = TestRoot::new("replay-low-disk");
    let keys = MemoryKeyStore::new();
    let probe = MutableProbe::new(healthy_observation());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");
    let conversation = store
        .create_conversation(conversation_input(1, b"replay"))
        .await
        .expect("create conversation");
    let accept_input = || AcceptCommand {
        conversation_id: conversation.conversation_id,
        owner: local_owner(),
        idempotency_key: "same-request".to_owned(),
        expected_configuration_revision: 0,
        payload: b"same-prompt".to_vec(),
    };
    let command = match store
        .accept_command(accept_input())
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };

    probe.set(low_disk_observation());
    assert!(matches!(
        store
            .accept_command(accept_input())
            .await
            .expect("accept retry must replay"),
        AcceptOutcome::Replayed { command: replay } if replay.command_id == command.command_id
    ));

    probe.set(healthy_observation());
    let start_input = || StartCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        daemon_boot_id: daemon_boot_id(),
        execution_nonce: b"same-nonce".to_vec(),
    };
    let turn_id = match store
        .mark_started_with_event(start_input())
        .await
        .expect("start command")
    {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("first start cannot replay"),
    };

    probe.set(low_disk_observation());
    assert!(matches!(
        store
            .mark_started_with_event(start_input())
            .await
            .expect("start retry must replay"),
        StartOutcome::Replayed { intent, .. } if intent.turn_id == turn_id
    ));
    store.shutdown().await.expect("shutdown runtime store");
}

#[tokio::test]
async fn new_accept_and_start_are_rejected_before_their_first_durable_write() {
    let root = TestRoot::new("ordinary-write-gates");
    let keys = MemoryKeyStore::new();
    let probe = MutableProbe::new(healthy_observation());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");
    let conversation = store
        .create_conversation(conversation_input(1, b"ordinary-gates"))
        .await
        .expect("create conversation");
    let accept_input = || AcceptCommand {
        conversation_id: conversation.conversation_id,
        owner: local_owner(),
        idempotency_key: "gated-command".to_owned(),
        expected_configuration_revision: 0,
        payload: b"prompt".to_vec(),
    };

    probe.set(low_disk_observation());
    let accept_error = store
        .accept_command(accept_input())
        .await
        .expect_err("new accept must be gated before COMMIT");
    assert!(matches!(accept_error, RuntimeStoreError::DiskLow { .. }));

    probe.set(healthy_observation());
    let command = match store
        .accept_command(accept_input())
        .await
        .expect("retry accept after capacity recovery")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => {
            panic!("rejected accept must not leave an idempotency row")
        }
    };
    assert_eq!(command.command_seq, 0);
    let start_input = || StartCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        daemon_boot_id: daemon_boot_id(),
        execution_nonce: b"gated-nonce".to_vec(),
    };

    probe.set(low_disk_observation());
    let start_error = store
        .mark_started_with_event(start_input())
        .await
        .expect_err("new start must be gated before COMMIT");
    assert!(matches!(start_error, RuntimeStoreError::DiskLow { .. }));
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("read state after rejected start");
    assert_eq!(recovery.accepted.len(), 1);
    assert!(recovery.started.is_empty());

    probe.set(healthy_observation());
    assert!(matches!(
        store
            .mark_started_with_event(start_input())
            .await
            .expect("retry start after capacity recovery"),
        StartOutcome::Started { event, .. } if event.event_seq == 0
    ));
    store.shutdown().await.expect("shutdown runtime store");
}

#[tokio::test]
async fn start_reserves_the_complete_fence_release_and_max_terminal_tail() {
    let root = TestRoot::new("start-safety-reserve");
    let keys = MemoryKeyStore::new();
    let probe = MutableProbe::new(healthy_observation());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");
    let conversation = store
        .create_conversation(conversation_input(1, b"start-reserve"))
        .await
        .expect("create conversation");
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: local_owner(),
            idempotency_key: "reserve-command".to_owned(),
            expected_configuration_revision: 0,
            payload: b"prompt".to_vec(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };

    let start = StartCommand {
        conversation_id: conversation.conversation_id,
        command_id: command.command_id,
        daemon_boot_id: daemon_boot_id(),
        execution_nonce: vec![0xA5; 1024],
    };
    probe.set(insufficient_terminal_tail_observation());
    let error = store
        .mark_started_with_event(start.clone())
        .await
        .expect_err("start must reserve all remaining safety writes before COMMIT");
    let required_available_bytes = match error {
        RuntimeStoreError::DiskLow {
            available_bytes,
            required_available_bytes,
        } => {
            assert_eq!(available_bytes, 520 * MIB);
            assert!(required_available_bytes > available_bytes);
            required_available_bytes
        }
        other => panic!("expected DiskLow, got {other:?}"),
    };
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("reservation rejection leaves recovery readable");
    assert_eq!(recovery.accepted.len(), 1);
    assert!(recovery.started.is_empty());

    probe.set(terminal_tail_observation(required_available_bytes - 1));
    assert!(matches!(
        store
            .mark_started_with_event(start.clone())
            .await
            .expect_err("one byte below the exact reserve must still reject"),
        RuntimeStoreError::DiskLow {
            required_available_bytes: observed,
            ..
        } if observed == required_available_bytes
    ));

    probe.set(terminal_tail_observation(required_available_bytes));
    assert!(matches!(
        store
            .mark_started_with_event(start)
            .await
            .expect("the exact required capacity admits the same start"),
        StartOutcome::Started { .. }
    ));
    store.shutdown().await.expect("shutdown runtime store");
}

#[tokio::test]
async fn safety_only_revalidates_reserved_tail_before_fence_release_and_terminal_writes() {
    let root = TestRoot::new("safety-only");
    let keys = MemoryKeyStore::new();
    let probe = MutableProbe::new(healthy_observation());
    probe.script([
        healthy_observation(),
        healthy_observation(),
        healthy_observation(),
        healthy_observation(),
        healthy_observation(),
        over_limit_observation(),
    ]);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");
    let conversation = store
        .create_conversation(conversation_input(1, b"safety"))
        .await
        .expect("create conversation");
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: local_owner(),
            idempotency_key: "safety-command".to_owned(),
            expected_configuration_revision: 0,
            payload: b"prompt".to_vec(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };
    let started = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(),
            execution_nonce: b"safety-nonce".to_vec(),
        })
        .await
        .expect("start commits before the post-commit over-limit readback");
    let turn_id = match started {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("first start cannot replay"),
    };

    let ordinary_error = store
        .create_conversation(conversation_input(2, b"must-not-write"))
        .await
        .expect_err("post-commit overflow must latch SafetyOnly");
    assert!(matches!(ordinary_error, RuntimeStoreError::SafetyOnly));
    assert_eq!(ordinary_error.code(), "daemon.runtime.safety_only");

    probe.set(over_limit_observation());
    let rejected_fence = store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(),
            execution_nonce: b"safety-nonce".to_vec(),
            process_group_id: 4242,
            leader_pid: 4243,
            leader_start_time: 99,
            payload: b"fence".to_vec(),
        })
        .await
        .expect_err("safety write must fail closed when its reserved tail no longer fits");
    assert!(matches!(
        rejected_fence,
        RuntimeStoreError::StoreFull { .. }
    ));
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("rejected fence leaves recovery readable");
    assert_eq!(recovery.started.len(), 1);
    assert!(recovery.started[0].fence.is_none());

    probe.set(healthy_observation());
    store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(),
            execution_nonce: b"safety-nonce".to_vec(),
            process_group_id: 4242,
            leader_pid: 4243,
            leader_start_time: 99,
            payload: b"fence".to_vec(),
        })
        .await
        .expect("SafetyOnly permits fencing once the reserved tail validates again");
    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(),
            execution_nonce: b"safety-nonce".to_vec(),
        })
        .await
        .expect("SafetyOnly permits release once the reserved tail validates");
    let completed = store
        .complete_command_with_event(CompleteCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            turn_id,
            terminal: CommandTerminal::interrupted(),
        })
        .await
        .expect("SafetyOnly permits terminal completion while the reserved tail validates");
    assert!(matches!(completed, CompleteOutcome::Completed { .. }));
    store.shutdown().await.expect("shutdown runtime store");
}

#[tokio::test]
async fn rescue_receipt_replay_bypasses_capacity_but_a_new_receipt_revalidates_space() {
    let root = TestRoot::new("rescue-reserve");
    let keys = MemoryKeyStore::new();
    let probe = MutableProbe::new(healthy_observation());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");
    let receipt = MachineEnrollmentReceiptRecord {
        relay_server_id: [1; 16],
        machine_route: [2; 16],
        root_fingerprint: [3; 32],
    };
    store
        .record_machine_enrollment_receipt(receipt.clone())
        .await
        .expect("record rescue receipt");

    probe.set(over_limit_observation());
    assert_eq!(
        store
            .record_machine_enrollment_receipt(receipt.clone())
            .await
            .expect("exact receipt retry is read-only"),
        receipt
    );
    let error = store
        .record_machine_enrollment_receipt(MachineEnrollmentReceiptRecord {
            relay_server_id: [1; 16],
            machine_route: [4; 16],
            root_fingerprint: [5; 32],
        })
        .await
        .expect_err("new rescue receipt must revalidate its safety write budget");
    assert!(matches!(error, RuntimeStoreError::StoreFull { .. }));

    probe.set(healthy_observation());
    store.shutdown().await.expect("shutdown runtime store");
}

#[tokio::test]
async fn released_terminal_closes_on_fragmented_real_sqlite_with_a_pinned_wal_reader() {
    // 威胁场景：vendor 已越过 release gate 后，SQLite free-list 已碎片化且旧读事务
    // pin 住 WAL；若 safety reserve 低估 terminal transaction 的真实写入需求，daemon
    // 会无法持久化终态并留下仍可能产生副作用的 durable Started。
    //
    // 这是不注入 synthetic capacity probe 的真实 SQLite 基线。approval 注册能力是
    // daemon-private，integration test 无法伪造；因此本样本覆盖的 active approval 数为
    // 0，不冒充 `MAX_ACTIVE_APPROVALS_PER_TURN` 上限证据。完整 32 条上限仍须放在可调用
    // typed approval API 的 crate-private store test 中验证。
    let root = TestRoot::new("released-terminal-real-sqlite");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open real-capacity runtime store");

    let conversation = store
        .create_conversation(conversation_input(0x31, b"real sqlite terminal capacity"))
        .await
        .expect("create terminal capacity conversation");
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id: conversation.conversation_id,
            owner: local_owner(),
            idempotency_key: "released-terminal-real-sqlite".to_owned(),
            expected_configuration_revision: 0,
            payload: b"terminal capacity prompt".to_vec(),
        })
        .await
        .expect("accept terminal capacity command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh terminal capacity command cannot replay"),
    };
    let execution_nonce = b"released-terminal-real-sqlite-nonce".to_vec();
    let turn_id = match store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(),
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("start terminal capacity command")
    {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("fresh terminal capacity start cannot replay"),
    };
    store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(),
            execution_nonce: execution_nonce.clone(),
            process_group_id: 73_001,
            leader_pid: 73_001,
            leader_start_time: 73_001,
            payload: b"released terminal real sqlite fence".to_vec(),
        })
        .await
        .expect("persist terminal capacity fence");
    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(),
            execution_nonce,
        })
        .await
        .expect("authorize terminal capacity release");

    let pinned_reader = Connection::open(&database).expect("open pinned WAL reader");
    pinned_reader
        .execute_batch("BEGIN DEFERRED")
        .expect("begin pinned read transaction");
    let _: i64 = pinned_reader
        .query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))
        .expect("establish pinned WAL snapshot");

    let mut fragmenter = Connection::open(&database).expect("open fragmentation writer");
    fragmenter
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("set fragmentation busy timeout");
    fragmenter
        .execute_batch("PRAGMA wal_autocheckpoint = 0")
        .expect("disable fragmenter auto-checkpoint");
    {
        let transaction = fragmenter
            .transaction()
            .expect("begin real fragmentation transaction");
        transaction
            .execute_batch(
                "CREATE TABLE capacity_fragment_fixture (
                     fragment_id INTEGER PRIMARY KEY,
                     payload BLOB NOT NULL
                 )",
            )
            .expect("create fragmentation fixture table");
        for fragment_id in 0_i64..256 {
            transaction
                .execute(
                    "INSERT INTO capacity_fragment_fixture (fragment_id, payload)
                     VALUES (?1, zeroblob(?2))",
                    params![fragment_id, 16 * 1024_i64],
                )
                .expect("insert fragmentation fixture row");
        }
        transaction
            .commit()
            .expect("commit fragmentation fixture rows");
    }
    fragmenter
        .execute_batch("DROP TABLE capacity_fragment_fixture")
        .expect("drop fixture while retaining real free-list fragmentation");

    let page_count_before: u64 = fragmenter
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .expect("read fragmented page count");
    let freelist_before: u64 = fragmenter
        .query_row("PRAGMA freelist_count", [], |row| row.get(0))
        .expect("read fragmented free-list count");
    assert!(
        freelist_before > 0,
        "fixture must leave real SQLite free-list pages"
    );
    let (checkpoint_busy, wal_frames, checkpointed_frames): (i64, i64, i64) = fragmenter
        .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .expect("measure pinned WAL checkpoint");
    assert!(wal_frames > 0, "fixture must produce real WAL frames");
    assert!(
        checkpoint_busy != 0 || checkpointed_frames < wal_frames,
        "reader must prevent a complete WAL checkpoint: busy={checkpoint_busy}, \
         log={wal_frames}, checkpointed={checkpointed_frames}"
    );
    let wal_path = PathBuf::from(format!("{}-wal", database.display()));
    let wal_bytes_before = fs::metadata(&wal_path)
        .expect("fragmented WAL file exists")
        .len();

    let completed = store
        .complete_command_with_event(CompleteCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            turn_id,
            terminal: CommandTerminal::interrupted(),
        })
        .await
        .expect("released terminal must close on real fragmented SQLite");
    assert!(matches!(completed, CompleteOutcome::Completed { .. }));

    let wal_bytes_after = fs::metadata(&wal_path)
        .expect("terminal WAL file remains observable")
        .len();
    let durable = Connection::open(&database).expect("open terminal durable readback");
    let (state, terminal_event_present, active_approvals): (String, bool, i64) = durable
        .query_row(
            "SELECT c.state, c.terminal_event_id IS NOT NULL,
                    (SELECT active_approval_count FROM runtime_meta WHERE singleton = 1)
             FROM commands AS c WHERE c.command_id = ?1",
            [&command.command_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read back released terminal row");
    assert_eq!(state, "interrupted");
    assert!(terminal_event_present);
    assert_eq!(
        active_approvals, 0,
        "this honest baseline does not claim active-approval coverage"
    );
    drop(durable);

    pinned_reader
        .execute_batch("ROLLBACK")
        .expect("release pinned read transaction");
    drop(pinned_reader);
    drop(fragmenter);
    store.shutdown().await.expect("shutdown measured store");

    let reopened =
        RuntimeStoreHandle::open(RuntimeStoreConfig::new(database), root.storage_kek(&keys))
            .await
            .expect("reopen and authenticate measured terminal store");
    reopened
        .inspect()
        .await
        .expect("inspect measured terminal store");
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened measured store");

    eprintln!(
        "released terminal real SQLite evidence: page_count={page_count_before}, \
         freelist={freelist_before}, checkpoint=({checkpoint_busy},{wal_frames},\
         {checkpointed_frames}), wal_before={wal_bytes_before}, \
         wal_after={wal_bytes_after}, active_approvals=0"
    );
}
