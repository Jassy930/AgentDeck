use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::identity::{CommandId, ConversationId, EntityId, ItemId};
use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, ConversationSnapshot, SnapshotItem,
    StreamCursor, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, AgentItem, AgentItemMeta, AgentKind, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode, ProtocolError, SessionCapabilities, SessionId, SessionStart, ThreadId,
    VendorCapabilities, VendorControlPayload,
};
use agentdeckd::agent::{Agent, AgentEventSender, AgentSessionHandle};
use agentdeckd::runtime::AgentRouter;
use agentdeckd::runtime::backfill::BarrierRequest;
use agentdeckd::runtime::events::{
    RegisterStreamBarrier, RuntimeStreamTarget, SnapshotBarrierSource,
    SnapshotMaterializationSource, WatchGeneration,
};
use agentdeckd::runtime::snapshot::assemble_build_snapshot;
use agentdeckd::runtime::snapshot::{
    SnapshotMaterialization, SnapshotMaterializationError, SnapshotMaterializer,
};
use agentdeckd::runtime::store::cipher::MAX_RUNTIME_ROW_PLAINTEXT_LEN;
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, ConfigurationRecord,
    ConfigureConversation, ConfigureConversationOutcome, ConversationDescriptor, IdempotencyOwner,
    NewConversation, RuntimeClock, RuntimeClockError, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreHandle, TerminateAcceptedCommand,
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

fn codex_configuration(reasoning: CodexReasoningEffort) -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            reasoning,
        ),
    ))
}

async fn configure_codex(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    expected_revision: u64,
    reasoning: CodexReasoningEffort,
) -> ConfigurationRecord {
    let outcome = store
        .configure_conversation(ConfigureConversation {
            conversation_id,
            owner: owner(0xA0),
            idempotency_key: format!("snapshot-configuration-{expected_revision}"),
            expected_configuration_revision: expected_revision,
            configuration: codex_configuration(reasoning),
        })
        .await
        .expect("configure snapshot conversation");
    match outcome {
        ConfigureConversationOutcome::Applied { configuration } => configuration,
        other => panic!("expected applied snapshot configuration, got {other:?}"),
    }
}

fn decode_assembled_snapshot(
    assembled: &agentdeckd::runtime::snapshot::AssembledConversationSnapshot,
) -> ConversationSnapshot {
    serde_json::from_slice(assembled.canonical_payload()).expect("decode assembled snapshot")
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

enum ConfigurationHeadTamper {
    SealedRequest,
    StateMetadata,
}

fn tamper_configuration_head(
    database: &Path,
    conversation_id: RuntimeId,
    revision: u64,
    tamper: ConfigurationHeadTamper,
) {
    let connection = rusqlite::Connection::open(database).expect("open configuration tamper DB");
    match tamper {
        ConfigurationHeadTamper::SealedRequest => {
            let encoded_revision = format!("{revision:020}");
            let mut sealed: Vec<u8> = connection
                .query_row(
                    "SELECT sealed_request FROM configuration_journal
                     WHERE conversation_id = ?1 AND configuration_revision = ?2",
                    rusqlite::params![&conversation_id.as_bytes()[..], encoded_revision],
                    |row| row.get(0),
                )
                .expect("read current configuration ciphertext");
            *sealed.last_mut().expect("configuration ciphertext tag") ^= 1;
            assert_eq!(
                connection
                    .execute(
                        "UPDATE configuration_journal SET sealed_request = ?1
                         WHERE conversation_id = ?2 AND configuration_revision = ?3",
                        rusqlite::params![
                            sealed,
                            &conversation_id.as_bytes()[..],
                            format!("{revision:020}")
                        ],
                    )
                    .expect("tamper current configuration ciphertext"),
                1
            );
        }
        ConfigurationHeadTamper::StateMetadata => {
            assert_eq!(
                connection
                    .execute(
                        "UPDATE conversation_state SET metadata_token = zeroblob(32)
                         WHERE conversation_id = ?1",
                        [&conversation_id.as_bytes()[..]],
                    )
                    .expect("tamper current configuration state metadata"),
                1
            );
        }
    }
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
async fn before_first_build_remains_revision_zero_after_configuration_advances() {
    // 威胁场景：BeforeFirst 与 event 0 若被混淆，后续 rev1 会被错误投影进一个
    // 明确冻结在首事件之前的 snapshot。
    let root = TestRoot::new("configuration-before-first");
    let store = open_store(&root).await;
    let input = conversation(0x29, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create BeforeFirst configuration conversation");
    let source = capture_source(&store, conversation_id, 29).await;
    configure_codex(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let SnapshotMaterialization::Build(mut build) = materializer
        .materialize(source)
        .await
        .expect("materialize frozen BeforeFirst build")
    else {
        panic!("frozen BeforeFirst source must remain Build")
    };
    let assembled =
        assemble_build_snapshot(&mut build, Vec::new()).expect("assemble BeforeFirst snapshot");
    let snapshot = decode_assembled_snapshot(&assembled);
    assert_eq!(snapshot.base_event_cursor, StreamCursor::BeforeFirst);
    assert_eq!(snapshot.configuration_state.configuration_revision(), 0);
    assert!(snapshot.configuration_state.configuration().is_none());
    materializer
        .release_build_input(build)
        .await
        .expect("release frozen BeforeFirst build");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn build_uses_configuration_selected_at_ordinary_event_not_current_head() {
    // 威胁场景：snapshot 若读取 current configuration head，排在 rev1 与 rev2
    // 之间的普通 event 会在重放时被错误解释为 rev2。
    let root = TestRoot::new("configuration-cursor-build");
    let store = open_store(&root).await;
    let input = conversation(0x2A, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create cursor configuration conversation");
    let first = configure_codex(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    assert_eq!(first.event_seq, 0);
    let command_id = accept_one(&store, conversation_id).await;
    store
        .terminate_accepted_command(TerminateAcceptedCommand {
            conversation_id,
            command_id,
            expected_owner: owner(0x90),
            reason: AcceptedTerminationReason::Canceled,
        })
        .await
        .expect("write ordinary event between configurations");
    let source = capture_source(&store, conversation_id, 30).await;
    let second = configure_codex(&store, conversation_id, 1, CodexReasoningEffort::High).await;
    assert_eq!(second.event_seq, 2);

    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let SnapshotMaterialization::Build(mut build) = materializer
        .materialize(source)
        .await
        .expect("materialize cursor-selected build")
    else {
        panic!("cursor-selected source must build")
    };
    assert_eq!(build.base_event_cursor(), StreamCursor::At(1));
    let assembled =
        assemble_build_snapshot(&mut build, Vec::new()).expect("assemble cursor snapshot");
    let snapshot = decode_assembled_snapshot(&assembled);
    assert_eq!(snapshot.configuration_state.configuration_revision(), 1);
    assert_eq!(
        snapshot.configuration_state.configuration(),
        Some(&codex_configuration(CodexReasoningEffort::Low))
    );
    materializer
        .release_build_input(build)
        .await
        .expect("release cursor-selected build");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn ready_snapshot_keeps_frozen_configuration_after_head_advances() {
    // 威胁场景：Ready payload 的 base 与 current head 分离后，若只校验
    // conversation/base/count，旧 snapshot 可携带错误配置并通过认证。
    let root = TestRoot::new("configuration-cursor-ready");
    let store = open_store(&root).await;
    let input = conversation(0x2B, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create ready configuration conversation");
    configure_codex(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    let command_id = accept_one(&store, conversation_id).await;
    store
        .terminate_accepted_command(TerminateAcceptedCommand {
            conversation_id,
            command_id,
            expected_owner: owner(0x90),
            reason: AcceptedTerminationReason::Canceled,
        })
        .await
        .expect("write ordinary event before ready snapshot base");
    let build_source = capture_source(&store, conversation_id, 31).await;
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let SnapshotMaterialization::Build(mut build) = materializer
        .materialize(build_source)
        .await
        .expect("prepare ready configuration build")
    else {
        panic!("first configuration source must build")
    };
    let assembled =
        assemble_build_snapshot(&mut build, Vec::new()).expect("assemble ready configuration");
    let write = build
        .bind_assembled_snapshot(assembled)
        .expect("bind ready configuration snapshot");
    store
        .store_conversation_snapshot(write)
        .await
        .expect("store ready configuration snapshot");
    configure_codex(&store, conversation_id, 1, CodexReasoningEffort::High).await;

    let ready_source = capture_source(&store, conversation_id, 32).await;
    assert!(matches!(
        ready_source.source(),
        SnapshotBarrierSource::Ready(_)
    ));
    let SnapshotMaterialization::Ready(ready) = materializer
        .materialize(ready_source)
        .await
        .expect("materialize frozen ready configuration")
    else {
        panic!("stored snapshot must materialize as Ready")
    };
    let snapshot: ConversationSnapshot =
        serde_json::from_slice(ready.canonical_payload()).expect("decode ready snapshot");
    assert_eq!(snapshot.base_event_cursor, StreamCursor::At(1));
    assert_eq!(snapshot.configuration_state.configuration_revision(), 1);
    assert_eq!(
        snapshot.configuration_state.configuration(),
        Some(&codex_configuration(CodexReasoningEffort::Low))
    );
    store.shutdown().await.expect("shutdown store");
}

async fn old_configuration_build_source(
    root: &TestRoot,
    seed: u8,
) -> (
    RuntimeStoreHandle,
    RuntimeId,
    SnapshotMaterializationSource,
    SnapshotMaterializer,
) {
    let store = open_store(root).await;
    let input = conversation(seed, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create selector tamper conversation");
    configure_codex(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    let source = capture_source(&store, conversation_id, u64::from(seed)).await;
    configure_codex(&store, conversation_id, 1, CodexReasoningEffort::High).await;
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    (store, conversation_id, source, materializer)
}

#[tokio::test]
async fn old_build_cursor_authenticates_current_configuration_cipher_and_state_head() {
    // 威胁场景：攻击者在旧 cursor 已冻结后篡改 current head；selector 若只认证
    // 被选中的旧 row，会让损坏的 append-only journal 继续产出看似合法 snapshot。
    for (label, tamper, expected_code) in [
        (
            "selector-current-cipher",
            ConfigurationHeadTamper::SealedRequest,
            "daemon.runtime.crypto_failed",
        ),
        (
            "selector-state-metadata",
            ConfigurationHeadTamper::StateMetadata,
            "daemon.runtime.schema_incompatible",
        ),
    ] {
        let root = TestRoot::new(label);
        let (store, conversation_id, source, materializer) = old_configuration_build_source(
            &root,
            if expected_code.ends_with("crypto_failed") {
                0x2C
            } else {
                0x2D
            },
        )
        .await;
        tamper_configuration_head(&root.database(), conversation_id, 2, tamper);
        let error = materializer
            .materialize(source)
            .await
            .expect_err("old Build cursor must authenticate current configuration head");
        assert_eq!(error.code(), expected_code);
        match expected_code {
            "daemon.runtime.crypto_failed" => assert!(matches!(
                error,
                SnapshotMaterializationError::Store(RuntimeStoreError::Cipher(_))
            )),
            _ => assert!(matches!(
                error,
                SnapshotMaterializationError::Store(RuntimeStoreError::UnknownOrCorruptSchema)
            )),
        }
        store
            .shutdown()
            .await
            .expect("shutdown tampered Build store");
    }
}

#[tokio::test]
async fn old_build_cursor_authenticates_intermediate_configuration_ciphertext() {
    // 威胁场景：攻击者只破坏 selected rev1 与 current rev3 之间的 rev2；若 selector
    // 只认证两端，损坏的 append-only journal 仍会为旧 cursor 产出合法外观的快照。
    let root = TestRoot::new("selector-intermediate-cipher");
    let store = open_store(&root).await;
    let input = conversation(0x36, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create intermediate tamper conversation");
    configure_codex(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    let source = capture_source(&store, conversation_id, 54).await;
    configure_codex(&store, conversation_id, 1, CodexReasoningEffort::Medium).await;
    configure_codex(&store, conversation_id, 2, CodexReasoningEffort::High).await;
    tamper_configuration_head(
        &root.database(),
        conversation_id,
        2,
        ConfigurationHeadTamper::SealedRequest,
    );

    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let error = materializer
        .materialize(source)
        .await
        .expect_err("old cursor must authenticate every intermediate configuration row");
    assert_eq!(error.code(), "daemon.runtime.crypto_failed");
    assert!(matches!(
        error,
        SnapshotMaterializationError::Store(RuntimeStoreError::Cipher(_))
    ));
    store
        .shutdown()
        .await
        .expect("shutdown intermediate tamper store");
}

#[tokio::test]
async fn old_build_cursor_rejects_configuration_gap_paired_with_valid_orphan() {
    // 威胁场景：攻击者回放已认证 rev3 state，删除 rev2 并保留合法 rev4 orphan，
    // 使物理 COUNT 仍等于 head=3；只比较 count/current/selected 会漏掉 gap 与 orphan。
    let root = TestRoot::new("selector-gap-valid-orphan");
    let store = open_store(&root).await;
    let input = conversation(0x37, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create gap/orphan tamper conversation");
    configure_codex(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    let source = capture_source(&store, conversation_id, 55).await;
    configure_codex(&store, conversation_id, 1, CodexReasoningEffort::Medium).await;
    configure_codex(&store, conversation_id, 2, CodexReasoningEffort::High).await;

    let replayed_rev3_state: (String, Vec<u8>) = {
        let connection =
            rusqlite::Connection::open(root.database()).expect("open rev3 state capture DB");
        connection
            .query_row(
                "SELECT current_configuration_revision, metadata_token
                 FROM conversation_state WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("capture authenticated rev3 state")
    };
    configure_codex(&store, conversation_id, 3, CodexReasoningEffort::Medium).await;
    {
        let connection =
            rusqlite::Connection::open(root.database()).expect("open gap/orphan tamper DB");
        assert_eq!(
            connection
                .execute(
                    "UPDATE conversation_state
                     SET current_configuration_revision = ?1, metadata_token = ?2
                     WHERE conversation_id = ?3",
                    rusqlite::params![
                        replayed_rev3_state.0,
                        replayed_rev3_state.1,
                        &conversation_id.as_bytes()[..]
                    ],
                )
                .expect("replay authenticated rev3 state"),
            1
        );
        assert_eq!(
            connection
                .execute(
                    "DELETE FROM configuration_journal
                     WHERE conversation_id = ?1 AND configuration_revision = ?2",
                    rusqlite::params![&conversation_id.as_bytes()[..], format!("{:020}", 2)],
                )
                .expect("delete intermediate rev2 while retaining rev4 orphan"),
            1
        );
    }

    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let error = materializer
        .materialize(source)
        .await
        .expect_err("old cursor must reject configuration gap paired with a valid orphan");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    assert!(matches!(
        error,
        SnapshotMaterializationError::Store(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    store
        .shutdown()
        .await
        .expect("shutdown gap/orphan tamper store");
}

#[tokio::test]
async fn old_build_cursor_rejects_configuration_chain_beyond_replayed_parent_high_water() {
    // 威胁场景：攻击者回放 rev1 时已认证的 parent H/token，同时保留合法 rev2/rev3
    // configuration 链；若不把链尾锚到 parent H，旧 base0 仍会产出合法外观快照。
    let root = TestRoot::new("selector-replayed-parent-high-water");
    let clock = ManualClock::new(1_000);
    let store = open_store_with_clock(&root, clock).await;
    let input = conversation(0x38, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create parent high-water replay conversation");
    configure_codex(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    let source = capture_source(&store, conversation_id, 56).await;
    let replayed_parent: (Option<String>, i64, Vec<u8>) = {
        let connection =
            rusqlite::Connection::open(root.database()).expect("open parent state capture DB");
        connection
            .query_row(
                "SELECT event_high_water, updated_at_ms, metadata_token
                 FROM conversations WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("capture authenticated rev1 parent row")
    };
    configure_codex(&store, conversation_id, 1, CodexReasoningEffort::Medium).await;
    configure_codex(&store, conversation_id, 2, CodexReasoningEffort::High).await;
    {
        let connection =
            rusqlite::Connection::open(root.database()).expect("open parent high-water replay DB");
        assert_eq!(
            connection
                .execute(
                    "UPDATE conversations
                     SET event_high_water = ?1, updated_at_ms = ?2, metadata_token = ?3
                     WHERE conversation_id = ?4",
                    rusqlite::params![
                        replayed_parent.0,
                        replayed_parent.1,
                        replayed_parent.2,
                        &conversation_id.as_bytes()[..]
                    ],
                )
                .expect("replay authenticated rev1 parent high-water"),
            1
        );
    }

    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let error = materializer
        .materialize(source)
        .await
        .expect_err("configuration chain cannot extend beyond authenticated parent high-water");
    assert_eq!(error.code(), "daemon.runtime.schema_incompatible");
    assert!(matches!(
        error,
        SnapshotMaterializationError::Store(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    store
        .shutdown()
        .await
        .expect("shutdown parent high-water replay store");
}

#[tokio::test]
#[ignore = "真实 production writer 写满 4,096 版后执行完整 cursor selector 的慢门禁"]
async fn production_max_configuration_chain_materializes_at_exact_limit() {
    // 威胁场景：合法会话达到配置硬上限时，全链认证若存在隐含较小上限或非有界
    // 保留，会在生产最大链上拒绝、漏验或耗尽内存。
    const CONFIGURATION_LIMIT: u64 = 4_096;
    let root = TestRoot::new("selector-production-max-chain");
    let store = open_store_with_clock(&root, ManualClock::new(2_000)).await;
    let input = conversation(0x39, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create production max-chain conversation");
    for revision in 0..CONFIGURATION_LIMIT {
        let reasoning = if revision % 2 == 0 {
            CodexReasoningEffort::Low
        } else {
            CodexReasoningEffort::High
        };
        configure_codex(&store, conversation_id, revision, reasoning).await;
    }

    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let SnapshotMaterialization::Build(build) = materializer
        .materialize(capture_source(&store, conversation_id, 57).await)
        .await
        .expect("materialize production max configuration chain")
    else {
        panic!("conversation without a stored snapshot must build")
    };
    assert_eq!(
        build
            .configuration_state()
            .expect("max-chain Build carries configuration state")
            .configuration_revision(),
        CONFIGURATION_LIMIT
    );
    materializer
        .release_build_input(build)
        .await
        .expect("release max-chain Build input");
    store.shutdown().await.expect("shutdown max-chain store");
}

#[tokio::test]
async fn old_ready_cursor_preserves_configuration_cipher_error_provenance() {
    // 威胁场景：同一 current configuration ciphertext 损坏若在 Ready 被重分类为
    // schema、在 Build 保留 crypto，会让诊断与恢复策略依 snapshot 命中状态漂移。
    let root = TestRoot::new("ready-selector-current-cipher");
    let store = open_store(&root).await;
    let input = conversation(0x2E, AgentKind::Codex);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create ready selector tamper conversation");
    configure_codex(&store, conversation_id, 0, CodexReasoningEffort::Low).await;
    store_ready_empty(&store, conversation_id, AgentKind::Codex).await;
    configure_codex(&store, conversation_id, 1, CodexReasoningEffort::High).await;
    let ready_source = capture_source(&store, conversation_id, 46).await;
    assert!(matches!(
        ready_source.source(),
        SnapshotBarrierSource::Ready(_)
    ));
    tamper_configuration_head(
        &root.database(),
        conversation_id,
        2,
        ConfigurationHeadTamper::SealedRequest,
    );
    let materializer =
        SnapshotMaterializer::new(store.clone(), router(AgentKind::Codex, AgentKind::Codex));
    let error = materializer
        .materialize(ready_source)
        .await
        .expect_err("Ready selector must preserve configuration crypto failure");
    assert_eq!(error.code(), "daemon.runtime.crypto_failed");
    assert!(matches!(
        error,
        SnapshotMaterializationError::Store(RuntimeStoreError::Cipher(_))
    ));
    store
        .shutdown()
        .await
        .expect("shutdown tampered Ready store");
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
