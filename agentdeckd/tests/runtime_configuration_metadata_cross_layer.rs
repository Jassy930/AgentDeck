//! B5 configuration + managed metadata 跨层收口。
//!
//! 本目标故意经过真实 UDS framing/peer verification/RuntimeCore/Store，而不是直接
//! 构造 `AuthenticatedPrincipal`。四条连接只使用两个 installation identity，从而在不放宽
//! production issuer 边界的前提下证明两个 authenticated principal 的并发语义。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agentdeck_protocol::runtime::command::{CatalogRequest, HelloParams};
use agentdeck_protocol::runtime::failure::DAEMON_COMMAND_IDEMPOTENCY_CONFLICT;
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    BackfillChunk, BackfillRequest, CatalogChange, CodexConversationConfiguration,
    ConfigurationReceipt, ConfigureConversationRequest, ConversationConfiguration, ConversationId,
    ConversationMetadataMutation, ConversationMetadataMutationRequest, ConversationMetadataReceipt,
    ConversationSnapshot, ConversationStart, ConversationStartReceipt, IdempotencyKey,
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeInnerCursor, RuntimeMessage, RuntimeReply,
    RuntimeRequest, StreamCursor, SubscriptionReceipt, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use agentdeckd::local::unix::serve_accepted_stream;
use agentdeckd::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
use agentdeckd::runtime::{AgentRouter, RuntimeCore};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::{UnixListener, UnixStream};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const INSTALLATION_A: &str = "123e4567-e89b-12d3-a456-42661417b501";
const INSTALLATION_B: &str = "123e4567-e89b-12d3-a456-42661417b502";

struct TestRoot {
    path: PathBuf,
    keys: MemoryKeyStore,
}

impl TestRoot {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-b5-cross-layer-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create B5 cross-layer root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure B5 cross-layer root");
        }
        Self {
            path,
            keys: MemoryKeyStore::new(),
        }
    }

    fn socket(&self) -> PathBuf {
        self.path.join("agentdeckd.sock")
    }

    async fn open_core(&self) -> (Arc<RuntimeCore>, u64) {
        let kek = load_or_create_storage_kek(&self.keys, &self.path.join("key-state.db"))
            .expect("load persistent B5 StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(self.path.join("runtime.db")).with_command_capacity(1_024),
            kek,
        )
        .await
        .expect("open B5 Runtime store");
        let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
        let core = Arc::new(
            RuntimeCore::new(store, router, [0xB5; 32]).expect("construct B5 RuntimeCore"),
        );
        let report = core.recover().await.expect("recover B5 RuntimeCore");
        (core, report.conversations)
    }

    fn bind(&self) -> UnixListener {
        let _ = fs::remove_file(self.socket());
        UnixListener::bind(self.socket()).expect("bind B5 test-owned UDS listener")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Client {
    reader: BufReader<ReadHalf<UnixStream>>,
    writer: WriteHalf<UnixStream>,
}

impl Client {
    async fn connect(path: &Path, installation_id: &str) -> Self {
        let stream = UnixStream::connect(path)
            .await
            .expect("connect B5 UDS client");
        let (reader, mut writer) = tokio::io::split(stream);
        let preface = serde_json::json!({
            "localProtocolVersion": 1,
            "clientInstallationId": installation_id,
        });
        write_line(
            &mut writer,
            &serde_json::to_vec(&preface).expect("encode B5 UDS preface"),
        )
        .await;
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    async fn hello(&mut self, message_id: &str) {
        let reply = self
            .request(
                message_id,
                RuntimeRequest::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                }),
            )
            .await;
        assert!(matches!(
            reply,
            RuntimeReply::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
            })
        ));
    }

    async fn request(&mut self, message_id: &str, request: RuntimeRequest) -> RuntimeReply {
        self.send(message_id, request).await;
        let envelope = self.read().await;
        assert_eq!(envelope.message_id.as_str(), message_id);
        match envelope.body {
            RuntimeMessage::Reply(reply) => reply,
            other => panic!("{message_id} expected directed reply, got {other:?}"),
        }
    }

    async fn send(&mut self, message_id: &str, request: RuntimeRequest) {
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new(message_id),
            body: RuntimeMessage::Request(request),
        };
        let bytes = envelope
            .to_json_bytes_checked()
            .expect("encode B5 Runtime envelope");
        write_line(&mut self.writer, &bytes).await;
    }

    async fn read(&mut self) -> RuntimeEnvelope {
        let mut line = Vec::new();
        let count = tokio::time::timeout(IO_TIMEOUT, self.reader.read_until(b'\n', &mut line))
            .await
            .expect("B5 Runtime reply timeout")
            .expect("read B5 Runtime reply");
        assert!(count > 0, "expected B5 Runtime reply before EOF");
        assert_eq!(line.pop(), Some(b'\n'));
        serde_json::from_slice(&line).expect("decode B5 Runtime reply")
    }

    async fn backfill(&mut self, message_id: &str, request: BackfillRequest) -> Vec<BackfillChunk> {
        self.send(message_id, RuntimeRequest::Backfill(request))
            .await;
        let mut chunks = Vec::new();
        loop {
            let envelope = self.read().await;
            assert_eq!(envelope.message_id.as_str(), message_id);
            match envelope.body {
                RuntimeMessage::Reply(RuntimeReply::Backfill(chunk)) => chunks.push(chunk),
                RuntimeMessage::Reply(RuntimeReply::SyncComplete(_)) => break,
                other => panic!("{message_id} expected backfill/sync, got {other:?}"),
            }
        }
        chunks
    }

    async fn conversation_snapshot(
        &mut self,
        message_id: &str,
        conversation_id: ConversationId,
    ) -> ConversationSnapshot {
        self.send(
            message_id,
            RuntimeRequest::Subscribe {
                inner_cursor: RuntimeInnerCursor::Conversation {
                    conversation_id,
                    cursor: StreamCursor::BeforeFirst,
                },
            },
        )
        .await;
        let mut snapshot = None;
        loop {
            let envelope = self.read().await;
            assert_eq!(envelope.message_id.as_str(), message_id);
            match envelope.body {
                RuntimeMessage::Reply(RuntimeReply::Subscription(
                    SubscriptionReceipt::Subscribed { .. },
                )) => {}
                RuntimeMessage::Reply(RuntimeReply::Snapshot(value)) => snapshot = Some(value),
                RuntimeMessage::Reply(RuntimeReply::Backfill(_)) => {}
                RuntimeMessage::Reply(RuntimeReply::SyncComplete(_)) => break,
                other => panic!("{message_id} expected snapshot sequence, got {other:?}"),
            }
        }
        snapshot.expect("conversation subscription must contain a snapshot")
    }
}

async fn write_line(writer: &mut WriteHalf<UnixStream>, bytes: &[u8]) {
    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_all(bytes).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    })
    .await
    .expect("B5 UDS write timeout")
    .expect("write B5 UDS frame");
}

fn serve_n(
    listener: UnixListener,
    core: Arc<RuntimeCore>,
    count: usize,
) -> tokio::task::JoinHandle<Vec<Result<(), String>>> {
    tokio::spawn(async move {
        let mut connections = Vec::with_capacity(count);
        for _ in 0..count {
            let (stream, _) = listener.accept().await.expect("accept B5 UDS client");
            let core = core.clone();
            connections.push(tokio::spawn(async move {
                serve_accepted_stream(stream, core)
                    .await
                    .map_err(|error| error.to_string())
            }));
        }
        let mut results = Vec::with_capacity(count);
        for connection in connections {
            results.push(
                connection
                    .await
                    .expect("B5 UDS connection task must not panic"),
            );
        }
        results
    })
}

async fn finish_phase(
    server: tokio::task::JoinHandle<Vec<Result<(), String>>>,
    core: &RuntimeCore,
) {
    let results = tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("B5 UDS server did not drain")
        .expect("B5 UDS accept task must not panic");
    assert!(
        results.iter().all(Result::is_ok),
        "B5 connection actor failures: {results:?}"
    );
    core.shutdown().await.expect("shutdown B5 RuntimeCore");
}

fn configuration(reasoning: CodexReasoningEffort) -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            reasoning,
        ),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Principal {
    A,
    B,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataEffect {
    Renamed,
    Archived,
}

fn configuration_winner(
    a: &RuntimeReply,
    b: &RuntimeReply,
    conversation_id: &ConversationId,
) -> Principal {
    match (a, b) {
        (
            RuntimeReply::Configuration(ConfigurationReceipt::Applied {
                conversation_id: applied,
                configuration_revision: 1,
            }),
            RuntimeReply::Configuration(ConfigurationReceipt::Conflict {
                conversation_id: conflict,
                current_configuration_revision: 1,
            }),
        ) if applied == conversation_id && conflict == conversation_id => Principal::A,
        (
            RuntimeReply::Configuration(ConfigurationReceipt::Conflict {
                conversation_id: conflict,
                current_configuration_revision: 1,
            }),
            RuntimeReply::Configuration(ConfigurationReceipt::Applied {
                conversation_id: applied,
                configuration_revision: 1,
            }),
        ) if applied == conversation_id && conflict == conversation_id => Principal::B,
        other => panic!("concurrent Configure must yield one Applied and one Conflict: {other:?}"),
    }
}

fn metadata_winner(
    a: &RuntimeReply,
    b: &RuntimeReply,
    conversation_id: &ConversationId,
) -> Principal {
    match (a, b) {
        (
            RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
                conversation_id: applied,
                entry_revision: 1,
            }),
            RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Conflict {
                conversation_id: conflict,
                current_entry_revision: 1,
            }),
        ) if applied == conversation_id && conflict == conversation_id => Principal::A,
        (
            RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Conflict {
                conversation_id: conflict,
                current_entry_revision: 1,
            }),
            RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
                conversation_id: applied,
                entry_revision: 1,
            }),
        ) if applied == conversation_id && conflict == conversation_id => Principal::B,
        other => panic!("concurrent metadata must yield one Applied and one Conflict: {other:?}"),
    }
}

fn assert_configuration_replayed(
    phase: &str,
    reply: &RuntimeReply,
    conversation_id: &ConversationId,
) {
    assert!(
        matches!(
            reply,
            RuntimeReply::Configuration(ConfigurationReceipt::Replayed {
                conversation_id: replayed,
                configuration_revision: 1,
            }) if replayed == conversation_id
        ),
        "{phase} configuration replay mismatch: expected conversation={conversation_id:?} revision=1, actual={reply:?}"
    );
}

fn assert_metadata_replayed(reply: &RuntimeReply, conversation_id: &ConversationId) {
    assert!(matches!(
        reply,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Replayed {
            conversation_id: replayed,
            entry_revision: 1,
        }) if replayed == conversation_id
    ));
}

#[derive(Debug, Eq, PartialEq)]
struct Observation {
    configuration_receipt: Vec<u8>,
    metadata_receipt: Vec<u8>,
    catalog: Vec<u8>,
    catalog_backfill: Vec<u8>,
    conversation_backfill: Vec<u8>,
    conversation_snapshot: Vec<u8>,
}

async fn observe(
    client: &mut Client,
    conversation_id: &ConversationId,
    configuration_receipt: &RuntimeReply,
    metadata_receipt: &RuntimeReply,
    expected_configuration: &ConversationConfiguration,
    metadata_effect: MetadataEffect,
    label: &str,
) -> Observation {
    let catalog = client
        .request(
            &format!("{label}-catalog"),
            RuntimeRequest::Catalog(CatalogRequest { page_cursor: None }),
        )
        .await;
    let RuntimeReply::Catalog(catalog) = catalog else {
        panic!("catalog observation must return a snapshot")
    };
    assert_eq!(catalog.base_catalog_cursor, StreamCursor::At(1));
    let [entry] = catalog.entries() else {
        panic!("B5 catalog must contain exactly one conversation")
    };
    assert_eq!(&entry.conversation_id, conversation_id);
    assert_eq!(entry.entry_revision, 1);
    match metadata_effect {
        MetadataEffect::Renamed => {
            assert_eq!(entry.title.as_deref(), Some("renamed by A"));
            assert!(!entry.archived);
        }
        MetadataEffect::Archived => {
            assert_eq!(entry.title.as_deref(), Some("B5 cross-layer"));
            assert!(entry.archived);
        }
    }

    let catalog_backfill = client
        .backfill(
            &format!("{label}-catalog-backfill"),
            BackfillRequest::Catalog {
                after: StreamCursor::BeforeFirst,
            },
        )
        .await;
    let mut catalog_deltas = Vec::new();
    for chunk in &catalog_backfill {
        let BackfillChunk::Catalog { deltas, .. } = chunk else {
            panic!("catalog backfill returned a conversation chunk")
        };
        catalog_deltas.extend(deltas);
    }
    assert_eq!(
        catalog_deltas
            .iter()
            .map(|delta| delta.catalog_revision)
            .collect::<Vec<_>>(),
        vec![0, 1],
        "start + one metadata Applied are the only catalog mutations"
    );
    let [CatalogChange::Upserted { entry: final_entry }] = catalog_deltas[1].changes.as_slice()
    else {
        panic!("metadata catalog delta must contain one upsert")
    };
    assert_eq!(final_entry.entry_revision, 1);

    let conversation_backfill = client
        .backfill(
            &format!("{label}-conversation-backfill"),
            BackfillRequest::Conversation {
                conversation_id: conversation_id.clone(),
                after: StreamCursor::BeforeFirst,
            },
        )
        .await;
    let mut events = Vec::new();
    for chunk in &conversation_backfill {
        let BackfillChunk::Conversation {
            conversation_id: observed,
            events: chunk_events,
            ..
        } = chunk
        else {
            panic!("conversation backfill returned a catalog chunk")
        };
        assert_eq!(observed, conversation_id);
        events.extend(chunk_events);
    }
    assert_eq!(
        events.len(),
        1,
        "metadata must not enter conversation events"
    );
    assert_eq!(events[0].event_seq, 0);
    let agentdeck_protocol::runtime::RuntimeEventBody::ConfigurationChanged { state } =
        &events[0].body
    else {
        panic!("the only conversation event must be ConfigurationChanged")
    };
    assert_eq!(state.configuration_revision(), 1);
    assert_eq!(state.configuration(), Some(expected_configuration));

    let snapshot = client
        .conversation_snapshot(
            &format!("{label}-conversation-snapshot"),
            conversation_id.clone(),
        )
        .await;
    assert_eq!(&snapshot.conversation_id, conversation_id);
    assert_eq!(snapshot.base_event_cursor, StreamCursor::At(0));
    assert_eq!(snapshot.configuration_state.configuration_revision(), 1);
    assert_eq!(
        snapshot.configuration_state.configuration(),
        Some(expected_configuration)
    );

    Observation {
        configuration_receipt: serde_json::to_vec(configuration_receipt)
            .expect("encode configuration replay receipt"),
        metadata_receipt: serde_json::to_vec(metadata_receipt)
            .expect("encode metadata replay receipt"),
        catalog: serde_json::to_vec(&catalog).expect("encode catalog observation"),
        catalog_backfill: serde_json::to_vec(&catalog_backfill)
            .expect("encode catalog backfill observation"),
        conversation_backfill: serde_json::to_vec(&conversation_backfill)
            .expect("encode conversation backfill observation"),
        conversation_snapshot: serde_json::to_vec(&snapshot)
            .expect("encode conversation snapshot observation"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_configuration_and_metadata_converge_across_restart() {
    // 威胁场景：configuration revision、entry/catalog revision 若在 Core/Store/恢复任一层
    // 共用了错误的 CAS 轴，并发写、断线重试或重启后会出现丢 event、重复
    // CatalogDelta，或把 metadata 伪装成 conversation event。
    let root = TestRoot::new();
    let (core, recovered) = root.open_core().await;
    assert_eq!(recovered, 0);
    let server = serve_n(root.bind(), core.clone(), 4);

    // A/B 各用两条连接，但 installation identity 相同；因此下面四个并发请求
    // 只属于两个 authenticated principals。
    let mut a_configuration = Client::connect(&root.socket(), INSTALLATION_A).await;
    let mut b_configuration = Client::connect(&root.socket(), INSTALLATION_B).await;
    let mut a_metadata = Client::connect(&root.socket(), INSTALLATION_A).await;
    let mut b_metadata = Client::connect(&root.socket(), INSTALLATION_B).await;
    tokio::join!(
        a_configuration.hello("hello-a-configuration"),
        b_configuration.hello("hello-b-configuration"),
        a_metadata.hello("hello-a-metadata"),
        b_metadata.hello("hello-b-metadata"),
    );

    let start = a_configuration
        .request(
            "start",
            RuntimeRequest::Start(ConversationStart {
                agent_kind: AgentKind::Codex,
                idempotency_key: IdempotencyKey::new("b5-start"),
                cwd: PathBuf::from("/tmp/agentdeck-b5-cross-layer"),
                title: Some("B5 cross-layer".to_owned()),
            }),
        )
        .await;
    let RuntimeReply::ConversationStart(ConversationStartReceipt {
        conversation_id,
        replayed: false,
    }) = start
    else {
        panic!("B5 start must create one conversation")
    };

    // A/B 故意复用相同 raw key：幂等 namespace 必须包含 authenticated owner，
    // 因而败者只能是 revision Conflict，不能被误判成跨 principal idempotency conflict。
    let configuration_a = ConfigureConversationRequest::new(
        conversation_id.clone(),
        IdempotencyKey::new("b5-configuration-shared"),
        0,
        configuration(CodexReasoningEffort::High),
    );
    let configuration_b = ConfigureConversationRequest::new(
        conversation_id.clone(),
        IdempotencyKey::new("b5-configuration-shared"),
        0,
        configuration(CodexReasoningEffort::Low),
    );
    let metadata_a = ConversationMetadataMutationRequest::new(
        conversation_id.clone(),
        IdempotencyKey::new("b5-metadata-shared"),
        0,
        ConversationMetadataMutation::rename(Some("renamed by A".to_owned()))
            .expect("valid B5 rename"),
    )
    .expect("valid B5 metadata A request");
    let metadata_b = ConversationMetadataMutationRequest::new(
        conversation_id.clone(),
        IdempotencyKey::new("b5-metadata-shared"),
        0,
        ConversationMetadataMutation::SetArchived { archived: true },
    )
    .expect("valid B5 metadata B request");

    let (configuration_a_reply, configuration_b_reply, metadata_a_reply, metadata_b_reply) = tokio::join!(
        a_configuration.request(
            "configuration-a",
            RuntimeRequest::ConfigureConversation(configuration_a.clone())
        ),
        b_configuration.request(
            "configuration-b",
            RuntimeRequest::ConfigureConversation(configuration_b.clone())
        ),
        a_metadata.request(
            "metadata-a",
            RuntimeRequest::UpdateConversationMetadata(metadata_a.clone())
        ),
        b_metadata.request(
            "metadata-b",
            RuntimeRequest::UpdateConversationMetadata(metadata_b.clone())
        ),
    );
    let configuration_principal = configuration_winner(
        &configuration_a_reply,
        &configuration_b_reply,
        &conversation_id,
    );
    let metadata_principal =
        metadata_winner(&metadata_a_reply, &metadata_b_reply, &conversation_id);
    let (winning_configuration_request, expected_configuration) = match configuration_principal {
        Principal::A => (
            configuration_a.clone(),
            configuration(CodexReasoningEffort::High),
        ),
        Principal::B => (
            configuration_b.clone(),
            configuration(CodexReasoningEffort::Low),
        ),
    };
    let (winning_metadata_request, metadata_effect) = match metadata_principal {
        Principal::A => (metadata_a.clone(), MetadataEffect::Renamed),
        Principal::B => (metadata_b.clone(), MetadataEffect::Archived),
    };

    let configuration_replay = match configuration_principal {
        Principal::A => {
            a_configuration
                .request(
                    "configuration-replay",
                    RuntimeRequest::ConfigureConversation(winning_configuration_request.clone()),
                )
                .await
        }
        Principal::B => {
            b_configuration
                .request(
                    "configuration-replay",
                    RuntimeRequest::ConfigureConversation(winning_configuration_request.clone()),
                )
                .await
        }
    };
    assert_configuration_replayed("before restart", &configuration_replay, &conversation_id);
    let metadata_replay = match metadata_principal {
        Principal::A => {
            a_metadata
                .request(
                    "metadata-replay",
                    RuntimeRequest::UpdateConversationMetadata(winning_metadata_request.clone()),
                )
                .await
        }
        Principal::B => {
            b_metadata
                .request(
                    "metadata-replay",
                    RuntimeRequest::UpdateConversationMetadata(winning_metadata_request.clone()),
                )
                .await
        }
    };
    assert_metadata_replayed(&metadata_replay, &conversation_id);

    let configuration_same_key = ConfigureConversationRequest::new(
        conversation_id.clone(),
        winning_configuration_request.idempotency_key.clone(),
        0,
        configuration(CodexReasoningEffort::Medium),
    );
    let configuration_same_key_reply = match configuration_principal {
        Principal::A => {
            a_configuration
                .request(
                    "configuration-same-key",
                    RuntimeRequest::ConfigureConversation(configuration_same_key),
                )
                .await
        }
        Principal::B => {
            b_configuration
                .request(
                    "configuration-same-key",
                    RuntimeRequest::ConfigureConversation(configuration_same_key),
                )
                .await
        }
    };
    assert!(matches!(
        configuration_same_key_reply,
        RuntimeReply::Configuration(ConfigurationReceipt::Failed { failure })
            if failure.code == DAEMON_COMMAND_IDEMPOTENCY_CONFLICT
    ));
    let metadata_same_key = ConversationMetadataMutationRequest::new(
        conversation_id.clone(),
        winning_metadata_request.idempotency_key.clone(),
        0,
        ConversationMetadataMutation::SetArchived { archived: false },
    )
    .expect("valid B5 same-key metadata conflict");
    let metadata_same_key_reply = match metadata_principal {
        Principal::A => {
            a_metadata
                .request(
                    "metadata-same-key",
                    RuntimeRequest::UpdateConversationMetadata(metadata_same_key),
                )
                .await
        }
        Principal::B => {
            b_metadata
                .request(
                    "metadata-same-key",
                    RuntimeRequest::UpdateConversationMetadata(metadata_same_key),
                )
                .await
        }
    };
    assert!(matches!(
        metadata_same_key_reply,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Failed { failure })
            if failure.code == DAEMON_COMMAND_IDEMPOTENCY_CONFLICT
    ));

    let stale_configuration = ConfigureConversationRequest::new(
        conversation_id.clone(),
        IdempotencyKey::new("b5-configuration-stale"),
        0,
        configuration(CodexReasoningEffort::Minimal),
    );
    let stale_configuration_reply = a_configuration
        .request(
            "configuration-stale",
            RuntimeRequest::ConfigureConversation(stale_configuration),
        )
        .await;
    assert!(matches!(
        stale_configuration_reply,
        RuntimeReply::Configuration(ConfigurationReceipt::Conflict {
            current_configuration_revision: 1,
            ..
        })
    ));
    let stale_metadata = ConversationMetadataMutationRequest::new(
        conversation_id.clone(),
        IdempotencyKey::new("b5-metadata-stale"),
        0,
        ConversationMetadataMutation::SetArchived { archived: false },
    )
    .expect("valid B5 stale metadata request");
    let stale_metadata_reply = a_metadata
        .request(
            "metadata-stale",
            RuntimeRequest::UpdateConversationMetadata(stale_metadata),
        )
        .await;
    assert!(matches!(
        stale_metadata_reply,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Conflict {
            current_entry_revision: 1,
            ..
        })
    ));

    let before_restart = observe(
        &mut a_configuration,
        &conversation_id,
        &configuration_replay,
        &metadata_replay,
        &expected_configuration,
        metadata_effect,
        "before-restart",
    )
    .await;

    drop(a_configuration);
    drop(b_configuration);
    drop(a_metadata);
    drop(b_metadata);
    finish_phase(server, &core).await;

    let (reopened, recovered) = root.open_core().await;
    assert_eq!(
        recovered, 1,
        "RuntimeCore recovery must reinstall the conversation"
    );
    let reopened_server = serve_n(root.bind(), reopened.clone(), 2);
    let mut reopened_a = Client::connect(&root.socket(), INSTALLATION_A).await;
    let mut reopened_b = Client::connect(&root.socket(), INSTALLATION_B).await;
    tokio::join!(
        reopened_a.hello("reopened-hello-a"),
        reopened_b.hello("reopened-hello-b"),
    );

    let reopened_configuration_replay = match configuration_principal {
        Principal::A => {
            reopened_a
                .request(
                    "reopened-configuration-replay",
                    RuntimeRequest::ConfigureConversation(winning_configuration_request),
                )
                .await
        }
        Principal::B => {
            reopened_b
                .request(
                    "reopened-configuration-replay",
                    RuntimeRequest::ConfigureConversation(winning_configuration_request),
                )
                .await
        }
    };
    assert_configuration_replayed(
        "after restart",
        &reopened_configuration_replay,
        &conversation_id,
    );
    let reopened_metadata_replay = match metadata_principal {
        Principal::A => {
            reopened_a
                .request(
                    "reopened-metadata-replay",
                    RuntimeRequest::UpdateConversationMetadata(winning_metadata_request),
                )
                .await
        }
        Principal::B => {
            reopened_b
                .request(
                    "reopened-metadata-replay",
                    RuntimeRequest::UpdateConversationMetadata(winning_metadata_request),
                )
                .await
        }
    };
    assert_metadata_replayed(&reopened_metadata_replay, &conversation_id);

    let after_restart = observe(
        &mut reopened_a,
        &conversation_id,
        &reopened_configuration_replay,
        &reopened_metadata_replay,
        &expected_configuration,
        metadata_effect,
        "after-restart",
    )
    .await;
    assert_eq!(
        after_restart, before_restart,
        "receipt/catalog/backfill/snapshot must be byte-stable across shutdown + recovery"
    );

    drop(reopened_a);
    drop(reopened_b);
    finish_phase(reopened_server, &reopened).await;
}
