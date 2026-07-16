use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use agentdeck_protocol::runtime::configuration::MAX_CONFIGURATION_TEXT_BYTES;
use agentdeck_protocol::runtime::identity::{CommandId, ConversationId, EntityId, ItemId};
use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, CodexConversationConfiguration, ConversationConfiguration,
    ConversationSnapshot, SnapshotItem, StreamCursor, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, AgentItem, AgentItemMeta, AgentKind, ClaudeCodePermissionMode,
    CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode, ProtocolError,
    SessionCapabilities, SessionId, SessionStart, ThreadId, VendorCapabilities,
    VendorControlPayload,
};

use super::*;
use crate::agent::{Agent, AgentEventSender, AgentSessionHandle};
use crate::runtime::backfill::BarrierRequest;
use crate::runtime::events::{
    RegisterStreamBarrier, RuntimeStreamTarget, SnapshotBarrierSource, WatchGeneration,
};
use crate::runtime::store::{
    ConfigureConversation, ConfigureConversationOutcome, ConversationDescriptor, IdempotencyOwner,
    NewConversation, ReadySnapshotReference, RuntimeClock, RuntimeClockError, RuntimeId,
    RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreHandle, RuntimeStoreLane, RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_MALFORMED_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

struct SnapshotTestAgent;

#[async_trait::async_trait]
impl Agent for SnapshotTestAgent {
    fn kind(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn capabilities(&self) -> SessionCapabilities {
        capabilities(AgentKind::Codex)
    }

    async fn start_session(
        &self,
        _: SessionStart,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unreachable!("snapshot pin tests never start a vendor session")
    }

    async fn continue_thread(
        &self,
        _: ThreadId,
        _: PathBuf,
        _: String,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unreachable!("snapshot pin tests never continue a vendor session")
    }

    async fn submit_decision(&self, _: &SessionId, _: ActionDecision) -> Result<(), ProtocolError> {
        unreachable!("snapshot pin tests never submit approvals")
    }

    async fn submit_vendor_control(
        &self,
        _: &SessionId,
        _: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        unreachable!("snapshot pin tests never submit vendor control")
    }

    async fn cancel(&self, _: &SessionId) -> Result<(), ProtocolError> {
        unreachable!("snapshot pin tests never cancel a vendor session")
    }
}

#[derive(Default)]
struct BlockingSnapshotFault {
    state: Mutex<BlockingSnapshotFaultState>,
    changed: Condvar,
}

#[derive(Default)]
struct BlockingSnapshotFaultState {
    reached: bool,
    released: bool,
}

#[derive(Clone)]
struct BlockingAcquireClock {
    now_ms: u64,
    state: Arc<(Mutex<BlockingAcquireClockState>, Condvar)>,
}

#[derive(Default)]
struct BlockingAcquireClockState {
    armed: bool,
    reached: bool,
    released: bool,
}

impl BlockingAcquireClock {
    fn new(now_ms: u64) -> Self {
        Self {
            now_ms,
            state: Arc::new((
                Mutex::new(BlockingAcquireClockState::default()),
                Condvar::new(),
            )),
        }
    }

    fn arm(&self) {
        let (state, _) = &*self.state;
        let mut state = state.lock().expect("lock acquire clock arm");
        state.armed = true;
        state.reached = false;
        state.released = false;
    }

    fn wait_until_reached(&self) {
        let (state, changed) = &*self.state;
        let mut state = state.lock().expect("lock acquire clock wait");
        while !state.reached {
            state = changed.wait(state).expect("wait for acquire clock");
        }
    }

    fn release(&self) {
        let (state, changed) = &*self.state;
        let mut state = state.lock().expect("lock acquire clock release");
        state.released = true;
        changed.notify_all();
    }
}

impl RuntimeClock for BlockingAcquireClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        let (state, changed) = &*self.state;
        let mut state = state.lock().map_err(|_| RuntimeClockError::OutOfRange)?;
        if state.armed && !state.released {
            state.reached = true;
            changed.notify_all();
            while !state.released {
                state = changed
                    .wait(state)
                    .map_err(|_| RuntimeClockError::OutOfRange)?;
            }
        }
        Ok(self.now_ms)
    }
}

impl BlockingSnapshotFault {
    fn wait_until_reached(&self) {
        let mut state = self.state.lock().expect("lock blocking fault state");
        while !state.reached {
            state = self.changed.wait(state).expect("wait for snapshot fault");
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("lock blocking fault release");
        state.released = true;
        self.changed.notify_all();
    }
}

impl RuntimeStoreFaultInjector for BlockingSnapshotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation != RuntimeStoreOperation::StoreSnapshotBeforeCommit {
            return Ok(());
        }
        let mut state = self.state.lock().map_err(|_| {
            RuntimeStoreError::InvalidConfig("blocking snapshot fault state poisoned")
        })?;
        state.reached = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).map_err(|_| {
                RuntimeStoreError::InvalidConfig("blocking snapshot fault wait poisoned")
            })?;
        }
        Err(RuntimeStoreError::InvalidConfig(
            "injected snapshot pre-COMMIT fault",
        ))
    }
}

fn snapshot_test_router() -> Arc<AgentRouter> {
    let mut router = AgentRouter::new();
    router.register(Arc::new(SnapshotTestAgent));
    Arc::new(router)
}

fn snapshot_pin_test_root(label: &str) -> PathBuf {
    let sequence = NEXT_MALFORMED_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "agentdeck-snapshot-pin-{label}-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create snapshot pin test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure snapshot pin test root");
    }
    root
}

async fn open_snapshot_pin_test_store(
    root: &std::path::Path,
    config: RuntimeStoreConfig,
    seed: u8,
) -> (RuntimeStoreHandle, RuntimeId) {
    let keys = MemoryKeyStore::new();
    let storage_kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create snapshot pin test KEK");
    let store = RuntimeStoreHandle::open(config, storage_kek)
        .await
        .expect("open snapshot pin test store");
    let conversation_id = conversation_id(seed);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some(format!("snapshot-pin-{seed}")),
                cwd: PathBuf::from("/tmp/snapshot-pin-test"),
            },
        })
        .await
        .expect("create snapshot pin test conversation");
    (store, conversation_id)
}

async fn materialize_snapshot_build(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
) -> (
    SnapshotMaterializer,
    RuntimeSnapshotBuildPin,
    SnapshotBuildInput,
) {
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire managed snapshot test build source");
    let probe = match source.source() {
        SnapshotBarrierSource::Build(pin) => pin.clone(),
        SnapshotBarrierSource::Ready(_) => panic!("direct acquire must return build source"),
    };
    let materializer = SnapshotMaterializer::new(store.clone(), snapshot_test_router());
    let SnapshotMaterialization::Build(build) = materializer
        .materialize(source)
        .await
        .expect("materialize snapshot pin test build")
    else {
        panic!("fresh snapshot pin test source must build")
    };
    (materializer, probe, build)
}

#[tokio::test]
async fn dropping_snapshot_build_input_releases_exact_temp_pin() {
    let root = snapshot_pin_test_root("drop-build-input");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x71).await;
    let (_materializer, probe, build) = materialize_snapshot_build(&store, conversation_id).await;

    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active snapshot pin before BuildInput drop"),
        1
    );
    drop(build);
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active snapshot pin after BuildInput drop"),
        0
    );
    let error = store
        .prepare_authenticated_snapshot_build_context(probe)
        .await
        .expect_err("dropped BuildInput must invalidate its exact TEMP pin");
    assert!(matches!(error, RuntimeStoreError::InvalidStateTransition));

    store
        .shutdown()
        .await
        .expect("shutdown BuildInput drop test store");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn dropping_prequeue_snapshot_retry_error_releases_exact_temp_pin() {
    let root = snapshot_pin_test_root("drop-prequeue-retry");
    let config =
        RuntimeStoreConfig::new(root.join("runtime.db")).with_lane_byte_capacity(64 * 1024);
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x72).await;
    let (_materializer, probe, mut build) =
        materialize_snapshot_build(&store, conversation_id).await;
    let assembled = assemble_build_snapshot(
        &mut build,
        vec![SnapshotItem::Item {
            item_id: ItemId::new("prequeue-large-item"),
            entity_id: EntityId::new("prequeue-large-entity"),
            command_id: Some(CommandId::new("prequeue-large-command")),
            item: AgentItem::UserMessage {
                text: "x".repeat(128 * 1024),
                meta: AgentItemMeta::default(),
            },
        }],
    )
    .expect("assemble prequeue retry snapshot");
    let write = build
        .bind_assembled_snapshot(assembled)
        .expect("bind prequeue retry snapshot");

    let error = store
        .store_conversation_snapshot(write)
        .await
        .expect_err("oversized normal-lane charge must fail before queueing");
    assert!(matches!(
        error.error(),
        RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Normal
        }
    ));
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active snapshot pin while retry error is retained"),
        1
    );
    drop(error);
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active snapshot pin after retry error drop"),
        0
    );
    let error = store
        .prepare_authenticated_snapshot_build_context(probe)
        .await
        .expect_err("dropped retry error must invalidate its exact TEMP pin");
    assert!(matches!(error, RuntimeStoreError::InvalidStateTransition));

    store
        .shutdown()
        .await
        .expect("shutdown prequeue retry drop test store");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn aborting_queued_snapshot_store_releases_exact_temp_pin_after_worker_reply_drop() {
    let root = snapshot_pin_test_root("abort-queued-store");
    let fault = Arc::new(BlockingSnapshotFault::default());
    let config =
        RuntimeStoreConfig::new(root.join("runtime.db")).with_fault_injector(fault.clone());
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x73).await;
    let (_materializer, probe, mut build) =
        materialize_snapshot_build(&store, conversation_id).await;
    let assembled =
        assemble_build_snapshot(&mut build, vec![item(0)]).expect("assemble queued snapshot");
    let write = build
        .bind_assembled_snapshot(assembled)
        .expect("bind queued snapshot");
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active snapshot pin before queued store"),
        1
    );

    let store_for_write = store.clone();
    let task =
        tokio::spawn(async move { store_for_write.store_conversation_snapshot(write).await });
    let fault_waiter = fault.clone();
    tokio::task::spawn_blocking(move || fault_waiter.wait_until_reached())
        .await
        .expect("join snapshot fault waiter");
    task.abort();
    let join_error = task
        .await
        .expect_err("aborted snapshot store caller must not receive worker reply");
    assert!(join_error.is_cancelled());
    fault.release();

    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active snapshot pin after worker reply receiver drop"),
        0
    );
    let error = store
        .prepare_authenticated_snapshot_build_context(probe)
        .await
        .expect_err("aborted queued store must invalidate its exact TEMP pin");
    assert!(matches!(error, RuntimeStoreError::InvalidStateTransition));

    store
        .shutdown()
        .await
        .expect("shutdown aborted queued store test");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn dropping_taken_snapshot_source_releases_exact_temp_pin() {
    let root = snapshot_pin_test_root("drop-taken-source");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x74).await;
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(0x74).expect("non-zero snapshot generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture managed snapshot source");
    let source = registration
        .take_snapshot_source()
        .expect("fresh conversation requires a build source");
    let probe = match source.source() {
        SnapshotBarrierSource::Build(pin) => pin.clone(),
        SnapshotBarrierSource::Ready(_) => panic!("fresh conversation cannot be ready"),
    };
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active snapshot pin before source drop"),
        1
    );

    drop(source);
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active snapshot pin after source drop"),
        0
    );
    let error = store
        .prepare_authenticated_snapshot_build_context(probe)
        .await
        .expect_err("dropped source must invalidate its exact TEMP pin");
    assert!(matches!(error, RuntimeStoreError::InvalidStateTransition));

    store
        .shutdown()
        .await
        .expect("shutdown taken source drop test store");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn dropping_directly_acquired_snapshot_pin_releases_exact_temp_pin() {
    let root = snapshot_pin_test_root("drop-direct-acquire");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x76).await;
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("directly acquire managed snapshot build source");
    let probe = match source.source() {
        SnapshotBarrierSource::Build(pin) => pin.clone(),
        SnapshotBarrierSource::Ready(_) => panic!("direct acquire must return build source"),
    };
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count directly acquired snapshot pin"),
        1
    );

    drop(source);
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count directly acquired snapshot pin after drop"),
        0
    );
    let error = store
        .prepare_authenticated_snapshot_build_context(probe)
        .await
        .expect_err("dropped direct acquire must invalidate its exact TEMP pin");
    assert!(matches!(error, RuntimeStoreError::InvalidStateTransition));

    store
        .shutdown()
        .await
        .expect("shutdown direct acquire drop test store");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn canceling_snapshot_pin_acquire_after_insert_releases_exact_temp_pin() {
    let root = snapshot_pin_test_root("cancel-direct-acquire");
    let clock = BlockingAcquireClock::new(1_000);
    let config = RuntimeStoreConfig::new(root.join("runtime.db")).with_clock(clock.clone());
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x77).await;
    clock.arm();

    let store_for_acquire = store.clone();
    let acquire_task = tokio::spawn(async move {
        store_for_acquire
            .acquire_snapshot_build_source(conversation_id)
            .await
    });
    let clock_waiter = clock.clone();
    tokio::task::spawn_blocking(move || clock_waiter.wait_until_reached())
        .await
        .expect("join acquire clock waiter");
    acquire_task.abort();
    let join_error = acquire_task
        .await
        .expect_err("canceled acquire caller must not receive inserted pin");
    assert!(join_error.is_cancelled());
    clock.release();

    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count pins after canceled acquire reply"),
        0
    );
    store
        .shutdown()
        .await
        .expect("shutdown canceled acquire test store");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn release_build_input_worker_busy_keeps_cleanup_armed() {
    let root = snapshot_pin_test_root("release-worker-busy");
    let fault = Arc::new(BlockingSnapshotFault::default());
    let config = RuntimeStoreConfig::new(root.join("runtime.db"))
        .with_command_capacity(1)
        .with_fault_injector(fault.clone());
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x75).await;

    let (_first_materializer, _first_probe, mut first_build) =
        materialize_snapshot_build(&store, conversation_id).await;
    let first_assembled = assemble_build_snapshot(&mut first_build, vec![item(0)])
        .expect("assemble worker-blocking snapshot");
    let first_write = first_build
        .bind_assembled_snapshot(first_assembled)
        .expect("bind worker-blocking snapshot");
    let (second_materializer, second_probe, second_build) =
        materialize_snapshot_build(&store, conversation_id).await;
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count both active snapshot pins"),
        2
    );

    let store_for_write = store.clone();
    let write_task = tokio::spawn(async move {
        store_for_write
            .store_conversation_snapshot(first_write)
            .await
    });
    let fault_waiter = fault.clone();
    tokio::task::spawn_blocking(move || fault_waiter.wait_until_reached())
        .await
        .expect("join release test fault waiter");

    let store_for_inspect = store.clone();
    let (inspect_started_tx, inspect_started_rx) = tokio::sync::oneshot::channel();
    let inspect_task = tokio::spawn(async move {
        let _ = inspect_started_tx.send(());
        store_for_inspect.inspect().await
    });
    inspect_started_rx
        .await
        .expect("inspect task starts before release attempt");
    let release_error = second_materializer
        .release_build_input(second_build)
        .await
        .expect_err("full read queue must reject explicit build release");
    assert!(matches!(
        release_error,
        SnapshotMaterializationError::Store(RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Read
        })
    ));

    fault.release();
    let write_error = write_task
        .await
        .expect("join worker-blocking snapshot store")
        .expect_err("faulted snapshot store must preserve its retry write");
    drop(write_error);
    inspect_task
        .await
        .expect("join queued inspect")
        .expect("queued inspect completes after worker release");
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count active pins after failed explicit release cleanup"),
        0
    );
    let error = store
        .prepare_authenticated_snapshot_build_context(second_probe)
        .await
        .expect_err("failed explicit release must still invalidate its exact TEMP pin");
    assert!(matches!(error, RuntimeStoreError::InvalidStateTransition));

    store
        .shutdown()
        .await
        .expect("shutdown release worker-busy test store");
    let _ = fs::remove_dir_all(root);
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
}

fn conversation_id(seed: u8) -> RuntimeId {
    runtime_id(RuntimeIdKind::Conversation, seed)
}

fn capabilities(kind: AgentKind) -> SessionCapabilities {
    SessionCapabilities {
        agent_kind: kind,
        agent_version: "snapshot-test".to_owned(),
        features: BTreeSet::new(),
        vendor: match kind {
            AgentKind::Codex => VendorCapabilities::Codex(Default::default()),
            AgentKind::ClaudeCode => VendorCapabilities::ClaudeCode(Default::default()),
        },
    }
}

fn assembly_context(seed: u8, kind: AgentKind, base: StreamCursor) -> SnapshotAssemblyContext {
    let conversation_id = conversation_id(seed);
    SnapshotAssemblyContext {
        conversation_id,
        base_event_cursor: base,
        configuration_state: revision_zero_configuration_state(),
        capabilities: capabilities(kind),
        binding: SnapshotBuildBinding {
            pin_id: [seed.wrapping_add(0x20); 16],
            conversation_id,
            base_event_cursor: base,
        },
    }
}

fn revision_zero_configuration_state() -> ConversationConfigurationState {
    ConversationConfigurationState::new(0, None).expect("valid revision-zero configuration")
}

fn codex_configuration_state(
    revision: u64,
    reasoning_effort: CodexReasoningEffort,
) -> ConversationConfigurationState {
    ConversationConfigurationState::new(
        revision,
        Some(ConversationConfiguration::new(
            VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                CodexApprovalPolicy::OnRequest,
                CodexSandboxMode::WorkspaceWrite,
                reasoning_effort,
            )),
        )),
    )
    .expect("valid Codex configuration state")
}

fn maximum_claude_configuration_state() -> ConversationConfigurationState {
    let maximum = "x".repeat(MAX_CONFIGURATION_TEXT_BYTES);
    ConversationConfigurationState::new(
        1,
        Some(ConversationConfiguration::new(
            VendorConfigurationSnapshot::ClaudeCode(
                ClaudeCodeConversationConfiguration::new(
                    ClaudeCodePermissionMode::Default,
                    Some(maximum.clone()),
                    Some(maximum.clone()),
                    Some(maximum),
                )
                .expect("maximum Claude configuration"),
            ),
        )),
    )
    .expect("valid Claude configuration state")
}

async fn configure_snapshot_conversation(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    expected_revision: u64,
    reasoning_effort: CodexReasoningEffort,
) {
    let outcome = store
        .configure_conversation(ConfigureConversation {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0xA5; 32],
                uid: 501,
                client_installation_id: [0xA6; 16],
            },
            idempotency_key: format!("snapshot-unit-configuration-{expected_revision}"),
            expected_configuration_revision: expected_revision,
            configuration: codex_configuration_state(1, reasoning_effort)
                .configuration()
                .expect("configured state")
                .clone(),
        })
        .await
        .expect("configure snapshot unit conversation");
    assert!(matches!(
        outcome,
        ConfigureConversationOutcome::Applied { .. }
    ));
}

fn authenticated_context(seed: u8, kind: AgentKind) -> AuthenticatedConversationSnapshotContext {
    AuthenticatedConversationSnapshotContext {
        conversation_id: conversation_id(seed),
        agent_kind: kind,
        event_high_water: None,
    }
}

fn reference(seed: u8, base: StreamCursor, item_count: u64) -> ReadySnapshotReference {
    ReadySnapshotReference {
        snapshot_id: [seed.wrapping_add(1); 16],
        target: RuntimeStreamTarget::Conversation(conversation_id(seed)),
        base,
        item_count,
        logical_bytes: 1,
        content_sha256: [seed.wrapping_add(2); 32],
    }
}

fn item(seed: usize) -> SnapshotItem {
    SnapshotItem::Item {
        item_id: ItemId::new(format!("item-{seed}")),
        entity_id: EntityId::new(format!("entity-{seed}")),
        command_id: Some(CommandId::new(format!("command-{seed}"))),
        item: AgentItem::UserMessage {
            text: format!("message-{seed}"),
            meta: AgentItemMeta::default(),
        },
    }
}

fn ready_snapshot(
    seed: u8,
    kind: AgentKind,
    base: StreamCursor,
    items: Vec<SnapshotItem>,
) -> ConversationSnapshot {
    let mut all_items = vec![SnapshotItem::capabilities(capabilities(kind))];
    all_items.extend(items);
    ConversationSnapshot::new(
        ConversationId::new(conversation_id(seed).to_canonical_string()),
        base,
        revision_zero_configuration_state(),
        all_items,
    )
    .expect("valid test snapshot")
}

#[test]
fn canonical_legacy_v4_snapshot_dual_decodes_to_v2_wire() {
    // 威胁场景：已认证的 DB v4 ready row 仍是 Runtime v1 形状；升级后既不能
    // 把它误判为损坏，也不能把缺少 configurationState 的旧 JSON 原样发给 v2 client。
    let current = ready_snapshot(
        0x2b,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        vec![item(0)],
    );
    let legacy = LegacyConversationSnapshotV4 {
        conversation_id: current.conversation_id.clone(),
        base_event_cursor: current.base_event_cursor,
        items: current.items().to_vec(),
    };
    let legacy_payload = serde_json::to_vec(&legacy).expect("encode canonical v4 snapshot");
    assert!(
        !legacy_payload
            .windows(18)
            .any(|bytes| bytes == b"configurationState")
    );

    let decoded = decode_ready_snapshot_with_capacity(&legacy_payload, legacy_payload.capacity())
        .expect("dual decode canonical v4 snapshot");
    assert!(decoded.legacy_v4);
    assert_eq!(
        decoded
            .snapshot
            .configuration_state
            .configuration_revision(),
        0
    );
    assert!(
        decoded
            .snapshot
            .configuration_state
            .configuration()
            .is_none()
    );
    let selected_state = codex_configuration_state(1, CodexReasoningEffort::Medium);
    let selected = decode_ready_snapshot_with_configuration(
        &legacy_payload,
        legacy_payload.capacity(),
        &selected_state,
    )
    .expect("legacy snapshot injects cursor-selected configuration");
    assert!(selected.legacy_v4);
    assert_eq!(selected.snapshot.configuration_state, selected_state);
    let v2_payload =
        serialize_build_snapshot(&decoded.snapshot, None).expect("encode canonical v2 snapshot");
    assert!(
        std::str::from_utf8(&v2_payload)
            .expect("v2 snapshot UTF-8")
            .contains("configurationState")
    );

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(&legacy_payload);
    assert!(matches!(
        decode_ready_snapshot_with_capacity(&noncanonical, noncanonical.capacity()),
        Err(SnapshotMaterializationError::SchemaIncompatible)
    ));
}

#[tokio::test]
async fn legacy_ready_injects_cursor_configuration_without_rewriting_stored_payload() {
    // 威胁场景：升级后若 legacy Ready 用 current head 或在读路径改写 DB，旧 base
    // 会获得未来配置，且一次只读订阅会产生未授权持久化副作用。
    let root = snapshot_pin_test_root("legacy-cursor-configuration");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x2D).await;
    configure_snapshot_conversation(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire legacy configuration source");
    let legacy = LegacyConversationSnapshotV4 {
        conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
        base_event_cursor: StreamCursor::At(0),
        items: vec![SnapshotItem::capabilities(capabilities(AgentKind::Codex))],
    };
    let legacy_payload = serde_json::to_vec(&legacy).expect("encode production legacy payload");
    let stored = store
        .store_conversation_snapshot_fixture_for_test(source, 1, legacy_payload.clone())
        .await
        .expect("store authenticated legacy ready row");
    let stored_snapshot_id = stored.snapshot_id;
    let stored_hash = stored.content_sha256;
    configure_snapshot_conversation(&store, conversation_id, 1, CodexReasoningEffort::High).await;

    let ready_source = SnapshotMaterializationSource::new(
        SnapshotBarrierSource::Ready(ReadySnapshotReference {
            snapshot_id: stored_snapshot_id,
            target: RuntimeStreamTarget::Conversation(conversation_id),
            base: StreamCursor::At(0),
            item_count: 1,
            logical_bytes: u64::try_from(legacy_payload.len()).expect("legacy logical bytes"),
            content_sha256: stored_hash,
        }),
        None,
    );
    let materializer = SnapshotMaterializer::new(store.clone(), snapshot_test_router());
    let SnapshotMaterialization::Ready(ready) = materializer
        .materialize(ready_source)
        .await
        .expect("materialize legacy cursor configuration")
    else {
        panic!("authenticated legacy row must remain Ready")
    };
    let current: ConversationSnapshot =
        serde_json::from_slice(ready.canonical_payload()).expect("decode legacy v2 wire");
    assert_eq!(current.configuration_state.configuration_revision(), 1);
    assert_eq!(
        current.configuration_state,
        codex_configuration_state(1, CodexReasoningEffort::Low)
    );
    let (materialized_stored, wire_payload) = ready.into_parts();
    assert!(wire_payload.is_some());
    assert!(materialized_stored.payload.is_empty());
    assert_eq!(materialized_stored.content_sha256, stored_hash);
    drop(materialized_stored);
    let persisted = store
        .load_conversation_snapshot(conversation_id)
        .await
        .expect("reload legacy stored row")
        .expect("legacy stored row remains present");
    assert_eq!(persisted.payload, legacy_payload);
    assert_eq!(persisted.content_sha256, stored_hash);
    store.shutdown().await.expect("shutdown legacy store");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn current_ready_configuration_mismatch_fails_closed_in_materializer() {
    let root = snapshot_pin_test_root("current-configuration-mismatch");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let (store, conversation_id) = open_snapshot_pin_test_store(&root, config, 0x2F).await;
    configure_snapshot_conversation(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire current mismatch source");
    let wrong = ready_snapshot(0x2F, AgentKind::Codex, StreamCursor::At(0), Vec::new());
    let payload = serde_json::to_vec(&wrong).expect("encode current mismatch payload");
    let stored = store
        .store_conversation_snapshot_fixture_for_test(source, 1, payload)
        .await
        .expect("store authenticated current mismatch row");
    let ready_source = SnapshotMaterializationSource::new(
        SnapshotBarrierSource::Ready(ReadySnapshotReference {
            snapshot_id: stored.snapshot_id,
            target: RuntimeStreamTarget::Conversation(conversation_id),
            base: StreamCursor::At(0),
            item_count: stored.item_count,
            logical_bytes: u64::try_from(stored.payload.len()).expect("mismatch logical bytes"),
            content_sha256: stored.content_sha256,
        }),
        None,
    );
    let materializer = SnapshotMaterializer::new(store.clone(), snapshot_test_router());
    let error = materializer
        .materialize(ready_source)
        .await
        .expect_err("current ready configuration mismatch must fail closed");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    store.shutdown().await.expect("shutdown mismatch store");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn configuration_nested_allocations_are_charged_in_typed_build_and_legacy_paths() {
    // 威胁场景：Claude Code 三个短上限字段若未计入 Build/Ready/legacy 峰值，
    // 多个并发 snapshot 可越过共享 128 MiB 内存池。
    let configured = maximum_claude_configuration_state();
    let rev0 = revision_zero_configuration_state();
    let configured_snapshot = ConversationSnapshot::new(
        ConversationId::new(conversation_id(0x2d).to_canonical_string()),
        StreamCursor::At(0),
        configured.clone(),
        vec![SnapshotItem::capabilities(capabilities(
            AgentKind::ClaudeCode,
        ))],
    )
    .expect("configured typed snapshot");
    let rev0_snapshot = ConversationSnapshot::new(
        configured_snapshot.conversation_id.clone(),
        StreamCursor::BeforeFirst,
        rev0.clone(),
        configured_snapshot.items().to_vec(),
    )
    .expect("revision-zero typed snapshot");
    let configured_typed = estimate_typed_snapshot_retained_bytes(&configured_snapshot)
        .expect("estimate configured typed snapshot");
    let rev0_typed =
        estimate_typed_snapshot_retained_bytes(&rev0_snapshot).expect("estimate rev0 snapshot");
    assert!(configured_typed >= rev0_typed + 3 * MAX_CONFIGURATION_TEXT_BYTES);

    let configured_estimator =
        ConversationSnapshotBudgetEstimator::new(&capabilities(AgentKind::ClaudeCode), &configured)
            .expect("configured reducer estimator");
    let rev0_estimator =
        ConversationSnapshotBudgetEstimator::new(&capabilities(AgentKind::ClaudeCode), &rev0)
            .expect("rev0 reducer estimator");
    assert!(
        configured_estimator
            .current_bound()
            .expect("configured current bound")
            >= rev0_estimator.current_bound().expect("rev0 current bound")
                + 3 * MAX_CONFIGURATION_TEXT_BYTES
    );

    let legacy = LegacyConversationSnapshotV4 {
        conversation_id: configured_snapshot.conversation_id.clone(),
        base_event_cursor: StreamCursor::At(0),
        items: configured_snapshot.items().to_vec(),
    };
    let payload = serde_json::to_vec(&legacy).expect("encode memory legacy snapshot");
    let observation = observe_json_retained_budget(&payload).expect("scan memory legacy snapshot");
    let nested = configuration_state_nested_retained_bytes(&configured)
        .expect("estimate selected configuration");
    let nonraw_peak = observation
        .decoded_and_validation_bytes
        .checked_add(std::mem::size_of::<ConversationConfigurationState>())
        .and_then(|bytes| bytes.checked_add(2 * nested))
        .expect("legacy retained peak");
    let exact_raw = SNAPSHOT_BUILD_MEMORY_BYTES
        .checked_sub(nonraw_peak)
        .expect("legacy fixture fits exact memory pool");
    assert!(exact_raw >= payload.len());
    decode_ready_snapshot_with_configuration(&payload, exact_raw, &configured)
        .expect("exact legacy retained peak is legal");
    assert!(matches!(
        decode_ready_snapshot_with_configuration(&payload, exact_raw + 1, &configured),
        Err(SnapshotMaterializationError::PayloadTooLarge)
    ));
}

#[test]
fn legacy_v4_at_the_wire_limit_has_a_typed_migration_failure() {
    // 威胁场景：合法 v1 snapshot 已恰好占满 64 MiB 时，新增必填
    // configurationState 不可能在不丢业务内容的情况下仍落入同一 64 MiB 总上限。
    // 自动 rebuild 只会生成同一 canonical state；升级必须返回 typed payload-too-large，
    // 不能误报 schema corruption、截断内容或改写原 ciphertext。
    fn legacy_with_text(text: String) -> LegacyConversationSnapshotV4 {
        LegacyConversationSnapshotV4 {
            conversation_id: ConversationId::new(conversation_id(0x2c).to_canonical_string()),
            base_event_cursor: StreamCursor::At(0),
            items: vec![
                SnapshotItem::capabilities(capabilities(AgentKind::Codex)),
                SnapshotItem::Item {
                    item_id: ItemId::new("legacy-limit-item"),
                    entity_id: EntityId::new("legacy-limit-entity"),
                    command_id: None,
                    item: AgentItem::AssistantMessage {
                        text,
                        meta: AgentItemMeta::default(),
                    },
                },
            ],
        }
    }

    let fixed_bytes = serde_json::to_vec(&legacy_with_text(String::new()))
        .expect("encode empty legacy snapshot")
        .len();
    let text_bytes = MAX_CONVERSATION_SNAPSHOT_BYTES
        .checked_sub(fixed_bytes)
        .expect("legacy fixture overhead fits snapshot limit");
    let legacy = legacy_with_text("x".repeat(text_bytes));
    let legacy_payload = serde_json::to_vec(&legacy).expect("encode max-size legacy snapshot");
    assert_eq!(legacy_payload.len(), MAX_CONVERSATION_SNAPSHOT_BYTES);
    drop(legacy_payload);

    let current = legacy
        .into_current(revision_zero_configuration_state())
        .expect("legacy DTO itself remains valid");
    let error = serialize_build_snapshot(&current, None)
        .expect_err("v2 required field must cross the unchanged 64 MiB ceiling");
    assert!(matches!(
        error,
        SnapshotMaterializationError::PayloadTooLarge
    ));
}

#[tokio::test]
async fn authenticated_but_malformed_ready_fails_closed_without_build_fallback() {
    let sequence = NEXT_MALFORMED_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "agentdeck-snapshot-malformed-unit-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create malformed fixture root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure malformed fixture root");
    }
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let keys = MemoryKeyStore::new();
    let storage_kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create malformed fixture KEK");
    let store = RuntimeStoreHandle::open(config, storage_kek)
        .await
        .expect("open malformed fixture store");
    let conversation_id = conversation_id(0x2c);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x6c),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some("authenticated malformed snapshot".to_owned()),
                cwd: PathBuf::from("/tmp/authenticated-malformed-snapshot"),
            },
        })
        .await
        .expect("create malformed fixture conversation");
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire malformed fixture source");
    let stored = store
        .store_conversation_snapshot_fixture_for_test(source, 1, br#"{}"#.to_vec())
        .await
        .expect("persist authenticated malformed ready row");
    let source = SnapshotBarrierSource::Ready(ReadySnapshotReference {
        snapshot_id: stored.snapshot_id,
        target: RuntimeStreamTarget::Conversation(conversation_id),
        base: StreamCursor::from_high_water(stored.base_event_seq),
        item_count: stored.item_count,
        logical_bytes: u64::try_from(stored.payload.len()).expect("fixture length fits u64"),
        content_sha256: stored.content_sha256,
    });
    let materializer = SnapshotMaterializer::new(store.clone(), Arc::new(AgentRouter::new()));

    let error = materializer
        .materialize(SnapshotMaterializationSource::new(source, None))
        .await
        .expect_err("authenticated malformed ready must not fall back to build");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");

    store
        .shutdown()
        .await
        .expect("shutdown malformed fixture store");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn ready_and_build_handoffs_retain_only_raw_and_small_metadata() {
    let build = assemble_snapshot(
        assembly_context(0x2e, AgentKind::Codex, StreamCursor::BeforeFirst),
        vec![item(0)],
    )
    .expect("assemble build handoff");
    let build_retained = build.retained_memory_observation();
    assert_eq!(build_retained.decoded_dto_bytes(), 0);
    assert!(build_retained.raw_payload_bytes() >= build.canonical_payload().len());
    assert!(build_retained.small_metadata_bytes() < 4 * 1024);
    assert!(!build_retained.has_memory_lease());

    let sequence = NEXT_MALFORMED_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "agentdeck-snapshot-ready-retention-unit-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create ready retention root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure ready retention root");
    }
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let keys = MemoryKeyStore::new();
    let storage_kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create ready retention KEK");
    let store = RuntimeStoreHandle::open(config, storage_kek)
        .await
        .expect("open ready retention store");
    let conversation_id = conversation_id(0x2d);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x6d),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some("ready retention snapshot".to_owned()),
                cwd: PathBuf::from("/tmp/ready-retention-snapshot"),
            },
        })
        .await
        .expect("create ready retention conversation");
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire ready retention source");
    let payload = serde_json::to_vec(&ready_snapshot(
        0x2d,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        vec![item(0)],
    ))
    .expect("encode canonical ready retention fixture");
    let stored = store
        .store_conversation_snapshot_fixture_for_test(source, 2, payload)
        .await
        .expect("persist canonical ready retention fixture");
    let source = SnapshotBarrierSource::Ready(ReadySnapshotReference {
        snapshot_id: stored.snapshot_id,
        target: RuntimeStreamTarget::Conversation(conversation_id),
        base: StreamCursor::from_high_water(stored.base_event_seq),
        item_count: stored.item_count,
        logical_bytes: u64::try_from(stored.payload.len()).expect("fixture length fits u64"),
        content_sha256: stored.content_sha256,
    });
    let materializer = SnapshotMaterializer::new(store.clone(), Arc::new(AgentRouter::new()));
    let SnapshotMaterialization::Ready(ready) = materializer
        .materialize(SnapshotMaterializationSource::new(source, None))
        .await
        .expect("materialize canonical ready retention fixture")
    else {
        panic!("ready retention fixture cannot fall back to build")
    };
    let ready_retained = ready.retained_memory_observation();
    assert_eq!(ready_retained.decoded_dto_bytes(), 0);
    assert!(ready_retained.raw_payload_bytes() >= ready.canonical_payload().len());
    assert!(ready_retained.small_metadata_bytes() < 4 * 1024);
    assert!(ready_retained.has_memory_lease());

    drop(ready);
    store
        .shutdown()
        .await
        .expect("shutdown ready retention store");
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn build_handoff_clears_input_capabilities_before_raw_is_retained() {
    let sequence = NEXT_MALFORMED_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "agentdeck-snapshot-build-input-retention-unit-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create build input retention root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure build input retention root");
    }
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let keys = MemoryKeyStore::new();
    let storage_kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create build input retention KEK");
    let store = RuntimeStoreHandle::open(config, storage_kek)
        .await
        .expect("open build input retention store");
    let conversation_id = conversation_id(0x2f);
    let adapter_state_key = runtime_id(RuntimeIdKind::AdapterState, 0x6f);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key,
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some("build input retention snapshot".to_owned()),
                cwd: PathBuf::from("/tmp/build-input-retention-snapshot"),
            },
        })
        .await
        .expect("create build input retention conversation");
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire build input retention source");
    let materializer = SnapshotMaterializer::new(store.clone(), snapshot_test_router());
    let SnapshotMaterialization::Build(mut input) = materializer
        .materialize(source)
        .await
        .expect("materialize build input retention source")
    else {
        panic!("direct build source must materialize as BuildInput")
    };

    let assembled = assemble_build_snapshot(&mut input, vec![item(0)])
        .expect("assemble build input retention snapshot");
    assert!(input.capabilities().is_none());
    assert!(input.configuration_state().is_none());
    let write = input
        .bind_assembled_snapshot(assembled)
        .expect("bind build input retention snapshot");
    store
        .store_conversation_snapshot(write)
        .await
        .expect("store build input retention snapshot");

    store
        .shutdown()
        .await
        .expect("shutdown build input retention store");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn empty_build_uses_router_capabilities_and_before_first() {
    let context = assembly_context(0x11, AgentKind::Codex, StreamCursor::BeforeFirst);
    let assembled = assemble_snapshot(context, Vec::new()).expect("empty snapshot");
    let decoded: ConversationSnapshot = serde_json::from_slice(assembled.canonical_payload())
        .expect("decode build handoff for assertions");

    assert_eq!(assembled.item_count(), 1);
    assert_eq!(decoded.base_event_cursor, StreamCursor::BeforeFirst);
    let SnapshotItem::Capabilities { capabilities, .. } = &decoded.items()[0] else {
        panic!("capabilities must be first")
    };
    assert_eq!(capabilities.agent_kind, AgentKind::Codex);
}

#[test]
fn snapshot_budget_counts_capabilities_and_allows_only_9999_agent_items() {
    let context = assembly_context(0x12, AgentKind::Codex, StreamCursor::BeforeFirst);
    let allowed = (0..9_999).map(item).collect();
    let assembled =
        assemble_snapshot(context.clone(), allowed).expect("9,999 items plus capabilities");
    assert_eq!(assembled.item_count(), 10_000);

    let rejected = (0..10_000).map(item).collect();
    let error = assemble_snapshot(context, rejected).expect_err("10,000 agent items overflow");
    assert_eq!(error.code(), "daemon.payload.item_too_large");
}

#[test]
fn snapshot_budget_rejects_more_than_64mib() {
    let context = assembly_context(0x17, AgentKind::Codex, StreamCursor::BeforeFirst);
    let oversized = SnapshotItem::Item {
        item_id: ItemId::new("oversized-item"),
        entity_id: EntityId::new("oversized-entity"),
        command_id: None,
        item: AgentItem::AssistantMessage {
            text: "x".repeat(MAX_CONVERSATION_SNAPSHOT_BYTES),
            meta: AgentItemMeta::default(),
        },
    };

    let error = assemble_snapshot(context, vec![oversized])
        .expect_err("canonical payload above 64 MiB must fail before handoff");
    assert_eq!(error.code(), "daemon.payload.item_too_large");
}

#[test]
fn ready_decoder_rejects_noncanonical_json_after_successful_strict_decode() {
    let snapshot = ready_snapshot(
        0x13,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        Vec::new(),
    );
    let canonical = serde_json::to_vec(&snapshot).expect("encode canonical snapshot");
    let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
    noncanonical.push(b' ');
    noncanonical.extend_from_slice(&canonical);

    serde_json::from_slice::<ConversationSnapshot>(&noncanonical)
        .expect("strict DTO decode itself succeeds");
    let error = decode_ready_snapshot(&noncanonical)
        .expect_err("byte-noncanonical payload must fail closed");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
}

#[test]
fn structural_preflight_rejects_small_raw_large_dom_before_typed_decode() {
    const EMPTY_ARRAY_COUNT: usize = 2_100_000;
    let mut small_raw_large_dom = Vec::with_capacity(EMPTY_ARRAY_COUNT * 3 + 2);
    small_raw_large_dom.push(b'[');
    for index in 0..EMPTY_ARRAY_COUNT {
        if index != 0 {
            small_raw_large_dom.push(b',');
        }
        small_raw_large_dom.extend_from_slice(b"[]");
    }
    small_raw_large_dom.push(b']');
    assert!(small_raw_large_dom.len() < MAX_CONVERSATION_SNAPSHOT_BYTES);
    let observation = observe_json_retained_budget(&small_raw_large_dom)
        .expect("large-DOM fixture is structurally valid JSON");
    assert_eq!(observation.raw_bytes(), small_raw_large_dom.len());
    assert!(observation.total_retained_bytes() > SNAPSHOT_BUILD_MEMORY_BYTES);

    let error = decode_ready_snapshot(&small_raw_large_dom)
        .expect_err("DOM amplification must fail before typed snapshot decode");
    assert_eq!(error.code(), "daemon.payload.item_too_large");
}

#[test]
fn structural_preflight_accounts_for_dynamic_value_btree_nodes() {
    const SINGLETON_OBJECT_COUNT: usize = 220_000;
    let snapshot = ready_snapshot(
        0x19,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        vec![SnapshotItem::Item {
            item_id: ItemId::new("dynamic-map-item"),
            entity_id: EntityId::new("dynamic-map-entity"),
            command_id: None,
            item: AgentItem::ToolCall {
                name: "dynamic-map-tool".to_owned(),
                args: serde_json::Value::Array(Vec::new()),
                result: None,
                meta: AgentItemMeta::default(),
            },
        }],
    );
    let canonical = serde_json::to_vec(&snapshot).expect("encode dynamic map fixture");
    let marker = br#""args":[]"#;
    let marker_start = canonical
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("tool call fixture contains empty args array");
    let array_content_start = marker_start + marker.len() - 1;
    let mut small_raw_large_dom = Vec::with_capacity(canonical.len() + SINGLETON_OBJECT_COUNT * 11);
    small_raw_large_dom.extend_from_slice(&canonical[..array_content_start]);
    for index in 0..SINGLETON_OBJECT_COUNT {
        if index != 0 {
            small_raw_large_dom.push(b',');
        }
        small_raw_large_dom.extend_from_slice(br#"{"a":null}"#);
    }
    small_raw_large_dom.extend_from_slice(&canonical[array_content_start..]);
    assert!(small_raw_large_dom.len() < MAX_CONVERSATION_SNAPSHOT_BYTES);

    let observation = observe_json_retained_budget(&small_raw_large_dom)
        .expect("dynamic Value singleton-object fixture is structurally valid JSON");
    assert!(observation.total_retained_bytes() > SNAPSHOT_BUILD_MEMORY_BYTES);
    let error = decode_ready_snapshot(&small_raw_large_dom)
        .expect_err("dynamic Value BTreeMap amplification must fail before typed decode");
    assert_eq!(error.code(), "daemon.payload.item_too_large");
}

fn assert_escaped_dynamic_schema_key_fails_preflight(
    marker: &[u8],
    escaped_prefix: &[u8],
    escaped_suffix: &[u8],
) {
    const SINGLETON_OBJECT_COUNT: usize = 220_000;
    let snapshot = ready_snapshot(
        0x1d,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        vec![SnapshotItem::Item {
            item_id: ItemId::new("escaped-dynamic-item"),
            entity_id: EntityId::new("escaped-dynamic-entity"),
            command_id: None,
            item: AgentItem::ToolCall {
                name: "escaped-dynamic-tool".to_owned(),
                args: serde_json::Value::Array(Vec::new()),
                result: Some(serde_json::Value::Array(Vec::new())),
                meta: AgentItemMeta::default(),
            },
        }],
    );
    let canonical = serde_json::to_vec(&snapshot).expect("encode escaped-key fixture");
    let marker_start = canonical
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("canonical fixture contains target schema key");
    let mut escaped = Vec::with_capacity(
        canonical.len() + escaped_prefix.len() + escaped_suffix.len() + SINGLETON_OBJECT_COUNT * 11,
    );
    escaped.extend_from_slice(&canonical[..marker_start]);
    escaped.extend_from_slice(escaped_prefix);
    for index in 0..SINGLETON_OBJECT_COUNT {
        if index != 0 {
            escaped.push(b',');
        }
        escaped.extend_from_slice(br#"{"a":null}"#);
    }
    escaped.extend_from_slice(escaped_suffix);
    escaped.extend_from_slice(&canonical[marker_start + marker.len()..]);
    assert!(escaped.len() < MAX_CONVERSATION_SNAPSHOT_BYTES);

    let error = observe_json_retained_budget(&escaped)
        .expect_err("escaped fixed-schema key must fail in structural preflight");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
}

#[test]
fn escaped_args_schema_key_fails_before_typed_decode() {
    assert_escaped_dynamic_schema_key_fails_preflight(br#""args":[]"#, br#""a\u0072gs":["#, b"]");
}

#[test]
fn escaped_result_schema_key_fails_before_typed_decode() {
    assert_escaped_dynamic_schema_key_fails_preflight(
        br#""result":[]"#,
        br#""res\u0075lt":["#,
        b"]",
    );
}

#[test]
fn escaped_vendor_extensions_schema_key_fails_before_typed_decode() {
    assert_escaped_dynamic_schema_key_fails_preflight(
        br#""vendorExtensions":{}"#,
        br#""vendorExtensi\u006fns":{"values":["#,
        b"]}",
    );
}

#[test]
fn escaped_dynamic_map_key_remains_valid_and_counted() {
    let mut args = serde_json::Map::new();
    args.insert("escaped\nmap-key".to_owned(), serde_json::Value::Null);
    let snapshot = ready_snapshot(
        0x1e,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        vec![SnapshotItem::Item {
            item_id: ItemId::new("escaped-map-item"),
            entity_id: EntityId::new("escaped-map-entity"),
            command_id: None,
            item: AgentItem::ToolCall {
                name: "escaped-map-tool".to_owned(),
                args: serde_json::Value::Object(args),
                result: None,
                meta: AgentItemMeta::default(),
            },
        }],
    );
    let canonical = serde_json::to_vec(&snapshot).expect("encode escaped dynamic map key");
    assert!(
        canonical
            .windows(br#"escaped\nmap-key"#.len())
            .any(|window| { window == br#"escaped\nmap-key"# })
    );
    let observation = observe_json_retained_budget(&canonical)
        .expect("dynamic map key escapes remain structurally valid");
    assert!(observation.total_retained_bytes() > canonical.len());
    decode_ready_snapshot(&canonical).expect("canonical escaped dynamic key remains Ready-safe");
}

#[test]
fn canonical_compare_streams_without_second_payload_buffer() {
    let snapshot = ready_snapshot(
        0x1a,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        vec![item(0)],
    );
    let canonical = serde_json::to_vec(&snapshot).expect("encode canonical fixture");

    let observation = compare_canonical_snapshot(&canonical, &snapshot)
        .expect("streaming canonical comparison succeeds");
    assert_eq!(observation.bytes_compared(), canonical.len());
    assert_eq!(observation.peak_buffered_bytes(), 0);
}

#[test]
fn oversized_build_rejected_before_full_raw_allocation() {
    let context = assembly_context(0x1b, AgentKind::Codex, StreamCursor::BeforeFirst);
    let large_item = SnapshotItem::Item {
        item_id: ItemId::new("large-build-item"),
        entity_id: EntityId::new("large-build-entity"),
        command_id: None,
        item: AgentItem::AssistantMessage {
            text: "x".repeat(63 * 1024 * 1024 + 768 * 1024),
            meta: AgentItemMeta::default(),
        },
    };
    let snapshot = ConversationSnapshot::new(
        ConversationId::new(context.conversation_id.to_canonical_string()),
        context.base_event_cursor,
        agentdeck_protocol::runtime::ConversationConfigurationState::new(0, None).unwrap(),
        vec![
            SnapshotItem::capabilities(context.capabilities.clone()),
            large_item,
        ],
    )
    .expect("construct large build snapshot");
    let mut probe = BuildSerializationProbe::default();

    let error = serialize_build_snapshot(&snapshot, Some(&mut probe))
        .expect_err("typed+raw peak above 128 MiB must fail before raw allocation");
    assert_eq!(error.code(), "daemon.payload.item_too_large");
    assert!(probe.counted_canonical_bytes() <= MAX_CONVERSATION_SNAPSHOT_BYTES);
    assert!(probe.estimated_peak_bytes() > SNAPSHOT_BUILD_MEMORY_BYTES);
    assert_eq!(probe.full_payload_allocation_bytes(), 0);
}

#[test]
fn reducer_estimator_rejects_retained_bound_above_shared_pool_instead_of_clamping() {
    let estimator = ConversationSnapshotBudgetEstimator {
        nested: RetainedByteCounter::new(SNAPSHOT_BUILD_MEMORY_BYTES + 1),
        observed_item_events: 0,
    };

    let error = estimator
        .current_bound()
        .expect_err("an over-budget reducer must fail before moving the event page");
    assert_eq!(error.code(), "daemon.payload.item_too_large");
}

#[test]
fn ready_validator_rejects_conversation_base_count_and_agent_kind_mismatch() {
    let context = authenticated_context(0x14, AgentKind::Codex);

    let wrong_conversation = ready_snapshot(
        0x15,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        Vec::new(),
    );
    assert_eq!(
        validate_ready_snapshot(
            &context,
            &reference(0x14, StreamCursor::BeforeFirst, 1),
            &revision_zero_configuration_state(),
            &wrong_conversation,
        )
        .expect_err("conversation mismatch")
        .code(),
        "daemon.runtime.schema_incompatible"
    );

    let wrong_base = ready_snapshot(0x14, AgentKind::Codex, StreamCursor::At(0), Vec::new());
    assert_eq!(
        validate_ready_snapshot(
            &context,
            &reference(0x14, StreamCursor::BeforeFirst, 1),
            &revision_zero_configuration_state(),
            &wrong_base,
        )
        .expect_err("base mismatch")
        .code(),
        "daemon.runtime.schema_incompatible"
    );

    let valid = ready_snapshot(
        0x14,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        Vec::new(),
    );
    assert_eq!(
        validate_ready_snapshot(
            &context,
            &reference(0x14, StreamCursor::BeforeFirst, 2),
            &revision_zero_configuration_state(),
            &valid,
        )
        .expect_err("item count mismatch")
        .code(),
        "daemon.runtime.schema_incompatible"
    );

    let wrong_kind = ready_snapshot(
        0x14,
        AgentKind::ClaudeCode,
        StreamCursor::BeforeFirst,
        Vec::new(),
    );
    assert_eq!(
        validate_ready_snapshot(
            &context,
            &reference(0x14, StreamCursor::BeforeFirst, 1),
            &revision_zero_configuration_state(),
            &wrong_kind,
        )
        .expect_err("agent kind mismatch")
        .code(),
        "daemon.runtime.schema_incompatible"
    );
}

#[test]
fn ready_validator_rejects_configuration_state_mismatch() {
    let mut context = authenticated_context(0x15, AgentKind::Codex);
    context.event_high_water = Some(0);
    let snapshot = ready_snapshot(0x15, AgentKind::Codex, StreamCursor::At(0), Vec::new());
    let error = validate_ready_snapshot(
        &context,
        &reference(0x15, StreamCursor::At(0), 1),
        &codex_configuration_state(1, CodexReasoningEffort::High),
        &snapshot,
    )
    .expect_err("current ready DTO cannot disagree with cursor-selected configuration");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
}

#[test]
fn ready_validator_rejects_duplicate_final_item_id_without_repair() {
    let context = authenticated_context(0x16, AgentKind::Codex);
    let duplicate = SnapshotItem::Item {
        item_id: ItemId::new("item-0"),
        entity_id: EntityId::new("entity-distinct"),
        command_id: None,
        item: AgentItem::AssistantMessage {
            text: "duplicate identity".to_owned(),
            meta: AgentItemMeta::default(),
        },
    };
    let snapshot = ready_snapshot(
        0x16,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        vec![item(0), duplicate],
    );
    let error = validate_ready_snapshot(
        &context,
        &reference(0x16, StreamCursor::BeforeFirst, 3),
        &revision_zero_configuration_state(),
        &snapshot,
    )
    .expect_err("duplicate final item id must fail closed");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
}

#[test]
fn ready_validator_rejects_duplicate_final_entity_id_without_repair() {
    let context = authenticated_context(0x19, AgentKind::Codex);
    let first = SnapshotItem::Item {
        item_id: ItemId::new("ready-item-a"),
        entity_id: EntityId::new("shared-ready-entity"),
        command_id: None,
        item: AgentItem::AssistantMessage {
            text: "first".to_owned(),
            meta: AgentItemMeta::default(),
        },
    };
    let second = SnapshotItem::Item {
        item_id: ItemId::new("ready-item-b"),
        entity_id: EntityId::new("shared-ready-entity"),
        command_id: None,
        item: AgentItem::AssistantMessage {
            text: "second".to_owned(),
            meta: AgentItemMeta::default(),
        },
    };
    let snapshot = ready_snapshot(
        0x19,
        AgentKind::Codex,
        StreamCursor::BeforeFirst,
        vec![first, second],
    );

    let error = validate_ready_snapshot(
        &context,
        &reference(0x19, StreamCursor::BeforeFirst, 3),
        &revision_zero_configuration_state(),
        &snapshot,
    )
    .expect_err("duplicate final entity id must fail closed");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
}

#[test]
fn build_assembly_preserves_identity_and_rejects_duplicate_item_id() {
    let context = assembly_context(0x18, AgentKind::Codex, StreamCursor::BeforeFirst);
    let first = item(41);
    let assembled = assemble_snapshot(context.clone(), vec![first])
        .expect("identity-complete item assembles without repair");
    let decoded: ConversationSnapshot = serde_json::from_slice(assembled.canonical_payload())
        .expect("decode identity handoff for assertions");
    let SnapshotItem::Item {
        item_id,
        entity_id,
        command_id,
        ..
    } = &decoded.items()[1]
    else {
        panic!("second snapshot entry must remain an AgentItem")
    };
    assert_eq!(item_id.as_str(), "item-41");
    assert_eq!(entity_id.as_str(), "entity-41");
    assert_eq!(
        command_id.as_ref().map(|value| value.as_str()),
        Some("command-41")
    );

    let duplicate = SnapshotItem::Item {
        item_id: ItemId::new("item-41"),
        entity_id: EntityId::new("another-entity"),
        command_id: None,
        item: AgentItem::AssistantMessage {
            text: "same final item identity".to_owned(),
            meta: AgentItemMeta::default(),
        },
    };
    let error = assemble_snapshot(context, vec![item(41), duplicate])
        .expect_err("build assembly must not repair duplicate final item identity");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
}

#[test]
fn build_assembly_rejects_duplicate_entity_id_without_repair() {
    let context = assembly_context(0x1a, AgentKind::Codex, StreamCursor::BeforeFirst);
    let first = SnapshotItem::Item {
        item_id: ItemId::new("build-item-a"),
        entity_id: EntityId::new("shared-build-entity"),
        command_id: None,
        item: AgentItem::AssistantMessage {
            text: "first".to_owned(),
            meta: AgentItemMeta::default(),
        },
    };
    let second = SnapshotItem::Item {
        item_id: ItemId::new("build-item-b"),
        entity_id: EntityId::new("shared-build-entity"),
        command_id: None,
        item: AgentItem::AssistantMessage {
            text: "second".to_owned(),
            meta: AgentItemMeta::default(),
        },
    };

    let error = assemble_snapshot(context, vec![first, second])
        .expect_err("build assembly must not repair duplicate final entity identity");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
}

#[test]
fn ready_error_mapping_preserves_worker_busy_and_sql_engine_failures() {
    let busy = map_ready_store_error(RuntimeStoreError::WorkerBusy {
        lane: crate::runtime::model::RuntimeStoreLane::Read,
    });
    assert_eq!(busy.code(), "daemon.runtime.store_busy");

    let sqlite = map_ready_store_error(RuntimeStoreError::Sqlite(rusqlite::Error::InvalidQuery));
    assert_eq!(sqlite.code(), "daemon.runtime.store_unavailable");

    for lifecycle_error in [
        crate::runtime::store::cipher::CipherError::ReadCapabilityClosed,
        crate::runtime::store::cipher::CipherError::ReadCapabilityPoisoned,
    ] {
        let error = map_ready_store_error(RuntimeStoreError::Cipher(lifecycle_error));
        assert_eq!(error.code(), "daemon.runtime.store_unavailable");
    }

    for persisted_corruption in [
        CipherError::InvalidGeneration,
        CipherError::InvalidEncoding,
        CipherError::UnsupportedVersion { actual: 2 },
        CipherError::GenerationMismatch {
            expected: 1,
            actual: 2,
        },
        CipherError::InputTooLarge,
        CipherError::AuthenticationFailed,
    ] {
        let error = map_ready_store_error(RuntimeStoreError::Cipher(persisted_corruption));
        assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    }
}
