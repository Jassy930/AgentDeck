#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CompleteCommand, CompleteOutcome,
    ExecutionFence, IdempotencyOwner, MachineEnrollmentReceiptRecord, NewConversation, RuntimeId,
    RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreHandle, StartCommand,
    StartOutcome, TerminalState,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const RUNTIME_DB_HARD_LIMIT_BYTES: u64 = 2 * GIB;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
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
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load capacity StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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
    RuntimeCapacityObservation {
        filesystem_total_bytes: 4 * GIB,
        filesystem_available_bytes: 600 * MIB,
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
        descriptor: descriptor.to_vec(),
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
        intent_payload: b"same-intent".to_vec(),
        event_payload: b"same-event".to_vec(),
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
        intent_payload: b"intent".to_vec(),
        event_payload: b"started".to_vec(),
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
            payload: b"prompt".to_vec(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };

    probe.set(insufficient_terminal_tail_observation());
    let error = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id: daemon_boot_id(),
            execution_nonce: b"reserve-nonce".to_vec(),
            intent_payload: b"intent".to_vec(),
            event_payload: b"started".to_vec(),
        })
        .await
        .expect_err("start must reserve all remaining safety writes before COMMIT");
    assert!(matches!(error, RuntimeStoreError::DiskLow { .. }));
    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("reservation rejection leaves recovery readable");
    assert_eq!(recovery.accepted.len(), 1);
    assert!(recovery.started.is_empty());
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
            intent_payload: b"intent".to_vec(),
            event_payload: b"started".to_vec(),
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
            terminal_state: TerminalState::Interrupted,
            terminal_payload: b"interrupted".to_vec(),
            event_payload: b"terminal".to_vec(),
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
