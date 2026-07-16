use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::identity::{CommandId, ConversationId, EntityId, ItemId};
use agentdeck_protocol::runtime::{ConversationSnapshot, SnapshotItem, StreamCursor};
use agentdeck_protocol::{
    ActionDecision, AgentItem, AgentItemMeta, AgentKind, ProtocolError, SessionCapabilities,
    SessionId, SessionStart, ThreadId, VendorCapabilities, VendorControlPayload,
};
use agentdeckd::agent::{Agent, AgentEventSender, AgentSessionHandle};
use agentdeckd::runtime::AgentRouter;
use agentdeckd::runtime::backfill::BarrierRequest;
use agentdeckd::runtime::events::{
    RegisterStreamBarrier, RuntimeStreamTarget, SnapshotBarrierSource,
    SnapshotMaterializationSource, WatchGeneration,
};
use agentdeckd::runtime::snapshot::assemble_build_snapshot;
use agentdeckd::runtime::snapshot::{SnapshotMaterialization, SnapshotMaterializer};
use agentdeckd::runtime::store::cipher::MAX_RUNTIME_ROW_PLAINTEXT_LEN;
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, ConversationDescriptor,
    IdempotencyOwner, NewConversation, RuntimeClock, RuntimeClockError, RuntimeId, RuntimeIdKind,
    RuntimeStoreConfig, RuntimeStoreHandle, TerminateAcceptedCommand,
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
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-snapshot-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
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

struct StubAgent {
    registered_kind: AgentKind,
    capability_kind: AgentKind,
}

#[async_trait::async_trait]
impl Agent for StubAgent {
    fn kind(&self) -> AgentKind {
        self.registered_kind
    }

    fn capabilities(&self) -> SessionCapabilities {
        capabilities(self.capability_kind)
    }

    async fn start_session(
        &self,
        _: SessionStart,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unreachable!("snapshot tests never start a vendor session")
    }

    async fn continue_thread(
        &self,
        _: ThreadId,
        _: PathBuf,
        _: String,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unreachable!("snapshot tests never continue a vendor session")
    }

    async fn submit_decision(&self, _: &SessionId, _: ActionDecision) -> Result<(), ProtocolError> {
        unreachable!("snapshot tests never submit an approval")
    }

    async fn submit_vendor_control(
        &self,
        _: &SessionId,
        _: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        unreachable!("snapshot tests never submit vendor control")
    }

    async fn cancel(&self, _: &SessionId) -> Result<(), ProtocolError> {
        unreachable!("snapshot tests never cancel a vendor session")
    }
}

fn capabilities(kind: AgentKind) -> SessionCapabilities {
    SessionCapabilities {
        agent_kind: kind,
        agent_version: "snapshot-stub".to_owned(),
        features: BTreeSet::new(),
        vendor: match kind {
            AgentKind::Codex => VendorCapabilities::Codex(Default::default()),
            AgentKind::ClaudeCode => VendorCapabilities::ClaudeCode(Default::default()),
        },
    }
}

fn router(registered_kind: AgentKind, capability_kind: AgentKind) -> Arc<AgentRouter> {
    let mut router = AgentRouter::new();
    router.register(Arc::new(StubAgent {
        registered_kind,
        capability_kind,
    }));
    Arc::new(router)
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
}

fn conversation(seed: u8, kind: AgentKind) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: ConversationDescriptor {
            agent_kind: kind,
            title: Some(format!("snapshot-{seed}")),
            cwd: PathBuf::from("/tmp/runtime-snapshot"),
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

async fn open_store(root: &TestRoot) -> RuntimeStoreHandle {
    let keys = MemoryKeyStore::new();
    RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store")
}

async fn open_store_with_clock(root: &TestRoot, clock: ManualClock) -> RuntimeStoreHandle {
    let keys = MemoryKeyStore::new();
    RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store with clock")
}

async fn capture_source(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    generation: u64,
) -> SnapshotMaterializationSource {
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(generation).expect("non-zero generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture snapshot barrier source");
    registration
        .take_snapshot_source()
        .expect("conversation snapshot source")
}

fn canonical_empty_payload(conversation_id: RuntimeId, kind: AgentKind) -> Vec<u8> {
    let snapshot = ConversationSnapshot::new(
        ConversationId::new(conversation_id.to_canonical_string()),
        StreamCursor::BeforeFirst,
        agentdeck_protocol::runtime::ConversationConfigurationState::new(0, None).unwrap(),
        vec![SnapshotItem::capabilities(capabilities(kind))],
    )
    .expect("valid empty conversation snapshot");
    serde_json::to_vec(&snapshot).expect("canonical snapshot payload")
}

async fn store_ready_empty(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    kind: AgentKind,
) {
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire ready snapshot source");
    let materializer = SnapshotMaterializer::new(store.clone(), router(kind, kind));
    let SnapshotMaterialization::Build(mut build) = materializer
        .materialize(source)
        .await
        .expect("prepare safe ready build")
    else {
        panic!("fresh exact pin must build")
    };
    let assembled =
        assemble_build_snapshot(&mut build, Vec::new()).expect("assemble canonical ready");
    let write = build
        .bind_assembled_snapshot(assembled)
        .expect("bind exact safe ready write");
    store
        .store_conversation_snapshot(write)
        .await
        .expect("store typed canonical ready payload");
}

fn flip_blob_column(database: &Path, table: &str, column: &str, conversation_id: RuntimeId) {
    let connection = rusqlite::Connection::open(database).expect("open ciphertext tamper database");
    let select = format!("SELECT {column} FROM {table} WHERE conversation_id = ?1");
    let mut bytes: Vec<u8> = connection
        .query_row(&select, [&conversation_id.as_bytes()[..]], |row| row.get(0))
        .expect("read exact ciphertext");
    let last = bytes.last_mut().expect("sealed row is non-empty");
    *last ^= 0x01;
    let update = format!("UPDATE {table} SET {column} = ?1 WHERE conversation_id = ?2");
    assert_eq!(
        connection
            .execute(
                &update,
                rusqlite::params![bytes, &conversation_id.as_bytes()[..]]
            )
            .expect("flip exact ciphertext byte"),
        1
    );
}

fn replace_snapshot_ciphertext_with_oversized_blob(database: &Path, conversation_id: RuntimeId) {
    let connection = rusqlite::Connection::open(database).expect("open oversized tamper database");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("enable explicit CHECK bypass for corruption fixture");
    let oversized = i64::try_from(MAX_RUNTIME_ROW_PLAINTEXT_LEN + 1024)
        .expect("oversized fixture length fits SQLite i64");
    assert_eq!(
        connection
            .execute(
                "UPDATE snapshots SET sealed_snapshot = zeroblob(?1)
                 WHERE target_scope = 'conversation' AND conversation_id = ?2",
                rusqlite::params![oversized, &conversation_id.as_bytes()[..]],
            )
            .expect("replace exact snapshot ciphertext with oversized zeroblob"),
        1
    );
}

async fn accept_one(store: &RuntimeStoreHandle, conversation_id: RuntimeId) -> RuntimeId {
    match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(0x90),
            idempotency_key: "snapshot-command".to_owned(),
            payload: b"snapshot prompt".to_vec(),
        })
        .await
        .expect("accept snapshot command")
    {
        AcceptOutcome::Accepted { command, .. } => command.command_id,
        AcceptOutcome::Replayed { .. } => panic!("first command cannot replay"),
    }
}

#[tokio::test]
async fn build_source_loads_authenticated_descriptor_and_router_capabilities() {
    let root = TestRoot::new("build-context");
    let store = open_store(&root).await;
    let input = conversation(0x21, AgentKind::ClaudeCode);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create build conversation");
    let source = capture_source(&store, conversation_id, 21).await;
    let materializer = SnapshotMaterializer::new(
        store.clone(),
        router(AgentKind::ClaudeCode, AgentKind::ClaudeCode),
    );

    let SnapshotMaterialization::Build(build) = materializer
        .materialize(source)
        .await
        .expect("prepare authenticated build")
    else {
        panic!("empty conversation must require a build")
    };
    assert_eq!(build.conversation_id(), conversation_id);
    assert_eq!(build.agent_kind(), AgentKind::ClaudeCode);
    assert_eq!(build.base_event_cursor(), StreamCursor::BeforeFirst);
    assert_eq!(
        build
            .capabilities()
            .expect("fresh build retains capabilities before assembly")
            .agent_kind,
        AgentKind::ClaudeCode
    );

    materializer
        .release_build_input(build)
        .await
        .expect("release successful build input pin");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn canonical_ready_source_materializes_successfully() {
    let root = TestRoot::new("canonical-ready");
    let store = open_store(&root).await;
    let input = conversation(0x22, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create ready conversation");
    let payload = canonical_empty_payload(conversation_id, AgentKind::Codex);
    store_ready_empty(&store, conversation_id, AgentKind::Codex).await;
    let source = capture_source(&store, conversation_id, 22).await;
    assert!(matches!(source.source(), SnapshotBarrierSource::Ready(_)));
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));

    let SnapshotMaterialization::Ready(ready) = materializer
        .materialize(source)
        .await
        .expect("materialize canonical ready row")
    else {
        panic!("ready source cannot fall back to build")
    };
    assert_eq!(ready.canonical_payload(), payload);
    assert_eq!(ready.item_count(), 1);
    let decoded: ConversationSnapshot = serde_json::from_slice(ready.canonical_payload())
        .expect("decode validated raw ready payload for assertions");
    assert_eq!(decoded.base_event_cursor, StreamCursor::BeforeFirst);
    drop(ready);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn descriptor_tamper_fails_before_snapshot_delivery() {
    let root = TestRoot::new("descriptor-tamper");
    let store = open_store(&root).await;
    let input = conversation(0x24, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create tamper conversation");
    store_ready_empty(&store, conversation_id, AgentKind::Codex).await;
    let source = capture_source(&store, conversation_id, 24).await;

    flip_blob_column(
        &root.database(),
        "conversations",
        "sealed_descriptor",
        conversation_id,
    );

    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let error = materializer
        .materialize(source)
        .await
        .expect_err("descriptor authentication must fail first");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_ciphertext_tamper_maps_to_schema_incompatible() {
    let root = TestRoot::new("snapshot-ciphertext-tamper");
    let store = open_store(&root).await;
    let input = conversation(0x2a, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create snapshot tamper conversation");
    store_ready_empty(&store, conversation_id, AgentKind::Codex).await;
    let source = capture_source(&store, conversation_id, 30).await;
    flip_blob_column(
        &root.database(),
        "snapshots",
        "sealed_snapshot",
        conversation_id,
    );

    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let error = materializer
        .materialize(source)
        .await
        .expect_err("snapshot ciphertext corruption is persisted schema corruption");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn oversized_persisted_snapshot_ciphertext_maps_to_schema_incompatible() {
    let root = TestRoot::new("snapshot-oversized-ciphertext-tamper");
    let store = open_store(&root).await;
    let input = conversation(0x2d, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create oversized snapshot tamper conversation");
    store_ready_empty(&store, conversation_id, AgentKind::Codex).await;
    let source = capture_source(&store, conversation_id, 32).await;
    replace_snapshot_ciphertext_with_oversized_blob(&root.database(), conversation_id);

    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let error = materializer
        .materialize(source)
        .await
        .expect_err("oversized persisted ciphertext is schema corruption");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn ready_worker_lifecycle_error_remains_store_unavailable() {
    let root = TestRoot::new("ready-worker-stopped");
    let store = open_store(&root).await;
    let input = conversation(0x2b, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create worker lifecycle conversation");
    store_ready_empty(&store, conversation_id, AgentKind::Codex).await;
    let source = capture_source(&store, conversation_id, 31).await;
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    store
        .shutdown()
        .await
        .expect("stop store before ready load");

    let error = materializer
        .materialize(source)
        .await
        .expect_err("stopped worker remains an engine/lifecycle failure");
    assert_eq!(error.code(), "daemon.runtime.store_unavailable");
}

#[tokio::test]
async fn router_capability_kind_mismatch_fails_build() {
    let root = TestRoot::new("router-mismatch");
    let store = open_store(&root).await;
    let input = conversation(0x25, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create router mismatch conversation");
    let source = capture_source(&store, conversation_id, 25).await;
    let materializer = SnapshotMaterializer::new(
        store.clone(),
        router(AgentKind::Codex, AgentKind::ClaudeCode),
    );

    let error = materializer
        .materialize(source)
        .await
        .expect_err("self-contradictory router capabilities must fail closed");
    assert_eq!(error.code(), "daemon.runtime.feature_unavailable");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn missing_router_capabilities_fail_build_and_release_pin() {
    let root = TestRoot::new("router-missing");
    let store = open_store(&root).await;
    let input = conversation(0x29, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create router missing conversation");
    let source = capture_source(&store, conversation_id, 29).await;
    let materializer = SnapshotMaterializer::new(store.clone(), Arc::new(AgentRouter::new()));

    let error = materializer
        .materialize(source)
        .await
        .expect_err("missing router capabilities must fail closed");
    assert_eq!(error.code(), "daemon.runtime.feature_unavailable");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn released_build_pin_fails_preparation_without_reacquiring() {
    let root = TestRoot::new("released-pin");
    let store = open_store(&root).await;
    let input = conversation(0x26, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create released-pin conversation");
    let source = capture_source(&store, conversation_id, 26).await;
    let probe = match source.source() {
        SnapshotBarrierSource::Build(pin) => pin.clone(),
        SnapshotBarrierSource::Ready(_) => panic!("fresh conversation must build"),
    };
    store
        .release_snapshot_build_pin(probe.clone())
        .await
        .expect("release exact captured pin");
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));

    let error = materializer
        .materialize(source)
        .await
        .expect_err("released pin cannot be replaced with a new pin");
    assert_eq!(error.code(), "daemon.runtime.invalid_state");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn expired_build_pin_fails_preparation_without_reacquiring() {
    let root = TestRoot::new("expired-pin");
    let clock = ManualClock::new(1_000);
    let store = open_store_with_clock(&root, clock.clone()).await;
    let input = conversation(0x27, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create expired-pin conversation");
    let source = capture_source(&store, conversation_id, 27).await;
    assert!(matches!(source.source(), SnapshotBarrierSource::Build(_)));
    clock.set(301_000);
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));

    let error = materializer
        .materialize(source)
        .await
        .expect_err("pin expires at the exact TTL boundary");
    assert_eq!(error.code(), "daemon.runtime.invalid_state");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn build_source_keeps_captured_base_when_current_high_water_advances() {
    let root = TestRoot::new("captured-base");
    let store = open_store(&root).await;
    let input = conversation(0x28, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create advancing conversation");
    let command_id = accept_one(&store, conversation_id).await;
    let source = capture_source(&store, conversation_id, 28).await;
    store
        .terminate_accepted_command(TerminateAcceptedCommand {
            conversation_id,
            command_id,
            expected_owner: owner(0x90),
            reason: AcceptedTerminationReason::Canceled,
        })
        .await
        .expect("advance authenticated event high-water");
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));

    let SnapshotMaterialization::Build(build) = materializer
        .materialize(source)
        .await
        .expect("captured base remains valid below current H")
    else {
        panic!("captured build source cannot be replaced")
    };
    assert_eq!(build.base_event_cursor(), StreamCursor::BeforeFirst);
    materializer
        .release_build_input(build)
        .await
        .expect("release advancing build pin");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn build_write_binding_rejects_cross_conversation_and_keeps_pin() {
    let root = TestRoot::new("cross-conversation-write-binding");
    let store = open_store(&root).await;
    let first = conversation(0x31, AgentKind::Codex);
    let first_id = first.conversation_id;
    let second = conversation(0x32, AgentKind::Codex);
    let second_id = second.conversation_id;
    store
        .create_conversation(first)
        .await
        .expect("create first binding conversation");
    store
        .create_conversation(second)
        .await
        .expect("create second binding conversation");
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let SnapshotMaterialization::Build(mut first_build) = materializer
        .materialize(capture_source(&store, first_id, 41).await)
        .await
        .expect("prepare first build")
    else {
        panic!("first source must build")
    };
    let SnapshotMaterialization::Build(mut second_build) = materializer
        .materialize(capture_source(&store, second_id, 42).await)
        .await
        .expect("prepare second build")
    else {
        panic!("second source must build")
    };
    let first_assembled =
        assemble_build_snapshot(&mut first_build, Vec::new()).expect("assemble first snapshot");

    let error = second_build
        .bind_assembled_snapshot(first_assembled)
        .expect_err("conversation A payload cannot bind to conversation B pin");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    materializer
        .release_build_input(first_build)
        .await
        .expect("release first exact pin");
    materializer
        .release_build_input(second_build)
        .await
        .expect("binding failure retains second exact pin");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn build_write_binding_rejects_distinct_pin_at_same_conversation_base() {
    let root = TestRoot::new("same-base-distinct-pin-binding");
    let store = open_store(&root).await;
    let input = conversation(0x33, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create same-base binding conversation");
    let first_source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire first exact source");
    let second_source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire second exact source");
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let SnapshotMaterialization::Build(mut first_build) = materializer
        .materialize(first_source)
        .await
        .expect("prepare first same-base build")
    else {
        panic!("first pin must build")
    };
    let SnapshotMaterialization::Build(mut second_build) = materializer
        .materialize(second_source)
        .await
        .expect("prepare second same-base build")
    else {
        panic!("second pin must build")
    };
    assert_eq!(
        first_build.conversation_id(),
        second_build.conversation_id()
    );
    assert_eq!(
        first_build.base_event_cursor(),
        second_build.base_event_cursor()
    );
    let first_assembled =
        assemble_build_snapshot(&mut first_build, Vec::new()).expect("assemble first exact pin");

    let error = second_build
        .bind_assembled_snapshot(first_assembled)
        .expect_err("same conversation/base still requires exact pin identity");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    materializer
        .release_build_input(first_build)
        .await
        .expect("release first same-base pin");
    materializer
        .release_build_input(second_build)
        .await
        .expect("binding failure retains second same-base pin");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn build_store_ready_near_limit_budget_is_symmetric() {
    const AGENT_ITEM_COUNT: usize = 9_999;
    const MESSAGE_BYTES: usize = 6_000;

    let root = TestRoot::new("build-ready-budget-symmetry");
    let store = open_store(&root).await;
    let input = conversation(0x34, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create near-limit budget conversation");
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let SnapshotMaterialization::Build(mut build) = materializer
        .materialize(capture_source(&store, conversation_id, 43).await)
        .await
        .expect("prepare near-limit build")
    else {
        panic!("fresh near-limit source must build")
    };
    let message = "x".repeat(MESSAGE_BYTES);
    let mut items = Vec::with_capacity(AGENT_ITEM_COUNT);
    for index in 0..AGENT_ITEM_COUNT {
        items.push(SnapshotItem::Item {
            item_id: ItemId::new(format!("near-limit-item-{index}")),
            entity_id: EntityId::new(format!("near-limit-entity-{index}")),
            command_id: Some(CommandId::new(format!("near-limit-command-{index}"))),
            item: AgentItem::UserMessage {
                text: message.clone(),
                meta: AgentItemMeta::default(),
            },
        });
    }
    let assembled =
        assemble_build_snapshot(&mut build, items).expect("Build accepts near-limit snapshot");
    assert!(
        assembled.canonical_payload().len() > 58 * 1024 * 1024,
        "near-limit fixture must exercise a large retained payload"
    );
    assert!(
        assembled.canonical_payload().len() < 64 * 1024 * 1024,
        "near-limit fixture must remain below the persisted snapshot cap"
    );
    let write = build
        .bind_assembled_snapshot(assembled)
        .expect("bind near-limit snapshot to exact build pin");
    drop(
        store
            .store_conversation_snapshot(write)
            .await
            .expect("persist near-limit Build output"),
    );
    let ready_source = capture_source(&store, conversation_id, 44).await;
    assert!(matches!(
        ready_source.source(),
        SnapshotBarrierSource::Ready(_)
    ));

    let SnapshotMaterialization::Ready(ready) = materializer
        .materialize(ready_source)
        .await
        .expect("Ready must accept the exact payload admitted by Build")
    else {
        panic!("persisted near-limit snapshot must stay on the Ready path")
    };
    assert_eq!(ready.item_count(), 10_000);
    store.shutdown().await.expect("shutdown store");
}

#[test]
fn store_public_snapshot_write_surface_is_opaque() {
    let stream_pipeline = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime/store/worker/stream_pipeline.rs"),
    )
    .expect("read store stream pipeline source");
    // 威胁场景：worker 机械拆分后，shape gate 若只扫描聚合文件，会把 opaque
    // production API 的原样迁移误报成能力消失，反而无法检查真实 owner surface。
    assert!(stream_pipeline.contains(
        "pub async fn store_conversation_snapshot(\n        &self,\n        write: PreparedConversationSnapshotWrite,"
    ));
    assert!(!stream_pipeline.contains("pub async fn store_conversation_snapshot_from_pin("));
}
