use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use agentdeck_protocol::runtime::identity::{ConversationId, EntityId, ItemId};
use agentdeck_protocol::runtime::{
    BackfillChunk, BackfillRange, ConversationSnapshot, RuntimeEvent, RuntimeEventBody,
    SnapshotItem, StreamCursor,
};
use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentKind, SessionCapabilities, VendorCapabilities,
};
use agentdeckd::runtime::backfill::{
    BarrierDecision, BarrierError, BarrierInput, BarrierRequest, plan_barrier,
};
use agentdeckd::runtime::events::{
    RegisterStreamBarrier, RelayCommittedCut, RuntimeStreamTarget, SnapshotBarrierSource,
    StoreCommitHub, WatchGeneration,
};
use agentdeckd::runtime::model::COMMAND_QUEUE_TTL_MS;
use agentdeckd::runtime::store::identity::RuntimeIdError;
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, AppendExecutionEvent,
    AppendExecutionEventOutcome, AuthorizeExecutionRelease, ConversationDescriptor, ExecutionFence,
    FreezePublicationRequest, IdempotencyOwner, NewConversation, PublicationPayloadKind,
    PublicationScope, RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeClock, RuntimeClockError,
    RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeIdSource, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreLane,
    RuntimeStoreOperation, StartCommand, TerminateAcceptedCommand, TerminateAcceptedOutcome,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

#[path = "support/store_admission.rs"]
mod store_admission;
mod support;
use support::runtime_configuration;
use support::snapshot::{prepare_canonical_snapshot_write_with_items, store_canonical_snapshot};

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
            "agentdeckd-runtime-stream-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure test root");
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
        load_or_create_storage_kek(keys, &self.path.join("key-state.db")).expect("StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct OneShotFault {
    operation: RuntimeStoreOperation,
    fired: AtomicBool,
}

impl OneShotFault {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            fired: AtomicBool::new(false),
        }
    }
}

impl RuntimeStoreFaultInjector for OneShotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && !self.fired.swap(true, Ordering::SeqCst) {
            Err(RuntimeStoreError::InvalidConfig(
                "injected stream barrier fault",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct NotificationReadbackCounter {
    reads: AtomicU64,
}

impl NotificationReadbackCounter {
    fn count(&self) -> u64 {
        self.reads.load(Ordering::SeqCst)
    }
}

impl RuntimeStoreFaultInjector for NotificationReadbackCounter {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::StreamNotificationReadback {
            self.reads.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

struct TamperRetentionAfterOperation {
    operation: RuntimeStoreOperation,
    database: PathBuf,
    conversation_id: RuntimeId,
    return_fault: bool,
    fired: AtomicBool,
}

impl TamperRetentionAfterOperation {
    fn new(
        operation: RuntimeStoreOperation,
        database: PathBuf,
        conversation_id: RuntimeId,
        return_fault: bool,
    ) -> Self {
        Self {
            operation,
            database,
            conversation_id,
            return_fault,
            fired: AtomicBool::new(false),
        }
    }
}

impl RuntimeStoreFaultInjector for TamperRetentionAfterOperation {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation != self.operation || self.fired.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let connection = rusqlite::Connection::open(&self.database)
            .map_err(|_| RuntimeStoreError::InvalidConfig("open readback tamper database"))?;
        connection
            .busy_timeout(Duration::from_secs(1))
            .map_err(|_| RuntimeStoreError::InvalidConfig("configure readback tamper database"))?;
        let changed = connection
            .execute(
                "UPDATE event_retention SET metadata_token = zeroblob(32)
                 WHERE conversation_id = ?1",
                [&self.conversation_id.as_bytes()[..]],
            )
            .map_err(|_| RuntimeStoreError::InvalidConfig("tamper readback target"))?;
        if changed != 1 || self.return_fault {
            return Err(RuntimeStoreError::InvalidConfig(
                "injected post-commit readback fault",
            ));
        }
        Ok(())
    }
}

fn tamper_retention_token(database: &Path, conversation_id: RuntimeId) {
    let connection = rusqlite::Connection::open(database).expect("open retention tamper database");
    connection
        .execute(
            "UPDATE event_retention SET metadata_token = zeroblob(32)
             WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
        )
        .expect("tamper exact retention target");
}

#[derive(Clone)]
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

struct SequenceIdSource(VecDeque<RuntimeId>);

impl SequenceIdSource {
    fn new(ids: impl IntoIterator<Item = RuntimeId>) -> Self {
        Self(ids.into_iter().collect())
    }
}

impl RuntimeIdSource for SequenceIdSource {
    fn next_id(&mut self, kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeIdError> {
        let id = self.0.pop_front().expect("deterministic id available");
        if id.kind() != kind {
            return Err(RuntimeIdError::SourceKindMismatch {
                kind,
                actual: id.kind(),
            });
        }
        Ok(id)
    }
}

fn conversation_id(seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16]).expect("conversation id")
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("runtime id")
}

async fn authorize_test_execution_release(
    store: &RuntimeStoreHandle,
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: &[u8],
    process_seed: i64,
) {
    store
        .persist_execution_fence(ExecutionFence {
            command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.to_vec(),
            process_group_id: process_seed,
            leader_pid: process_seed,
            leader_start_time: u64::try_from(process_seed).expect("positive process seed"),
            payload: b"runtime-stream-test-fence".to_vec(),
        })
        .await
        .expect("persist stream test execution fence");
    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.to_vec(),
        })
        .await
        .expect("authorize stream test execution release");
}

fn conversation(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: conversation_id(seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some(format!("stream-{seed}")),
            cwd: PathBuf::from("/tmp/runtime-stream"),
        },
    }
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [seed; 32],
        uid: 501,
        client_installation_id: [seed.wrapping_add(1); 16],
    }
}

async fn accept_one(store: &RuntimeStoreHandle, conversation_id: RuntimeId) -> RuntimeId {
    runtime_configuration::configure_codex_revision_one(store, conversation_id).await;
    match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(0x90),
            idempotency_key: "stream-command".to_owned(),
            expected_configuration_revision: 1,
            payload: b"stream prompt".to_vec(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command.command_id,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    }
}

fn input(
    target: RuntimeStreamTarget,
    request: BarrierRequest,
    high_water: StreamCursor,
    retained_floor: Option<u64>,
) -> BarrierInput {
    BarrierInput {
        target,
        request,
        high_water,
        retained_floor,
        snapshot_base: high_water,
        committed_outer: StreamCursor::BeforeFirst,
    }
}

#[path = "runtime_stream/barrier_integrity.rs"]
mod barrier_integrity;
#[path = "runtime_stream/contract.rs"]
mod contract;
#[path = "runtime_stream/store_commit_hub.rs"]
mod store_commit_hub;
