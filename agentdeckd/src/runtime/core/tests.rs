use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::identity::{
    ApprovalId, ConversationId, EventId, IdempotencyKey, MessageId,
};
use agentdeck_protocol::runtime::{
    ArtifactSha256, CodexConversationConfiguration, ConfigurationReceipt,
    ConfigureConversationRequest, ConversationConfiguration, ConversationMetadataMutation,
    ConversationMetadataMutationRequest, ConversationMetadataReceipt, ConversationStart,
    LocalOnlyAdministration, MAX_RUNTIME_JSON_FRAME_BYTES, PromptPayload, QueryReceiptSelector,
    RuntimeEvent, RuntimeEventBody, RuntimeMessage, RuntimeStreamItem, SendPromptRequest,
    StageUpgradeReceipt, StageUpgradeRequest, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentKind, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode,
};
use tokio::sync::mpsc;

use super::*;
use crate::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct SequenceIdSource(VecDeque<RuntimeId>);

impl SequenceIdSource {
    fn new(ids: impl IntoIterator<Item = RuntimeId>) -> Self {
        Self(ids.into_iter().collect())
    }
}

impl crate::runtime::store::RuntimeIdSource for SequenceIdSource {
    fn next_id(
        &mut self,
        kind: RuntimeIdKind,
    ) -> Result<RuntimeId, crate::runtime::store::identity::RuntimeIdError> {
        let id = self.0.pop_front().expect("deterministic runtime id");
        if id.kind() != kind {
            return Err(
                crate::runtime::store::identity::RuntimeIdError::SourceKindMismatch {
                    kind,
                    actual: id.kind(),
                },
            );
        }
        Ok(id)
    }
}

struct BlockCreateConversationAfterCommit {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
    blocked: AtomicBool,
}

struct BlockConfigureConversationBeforeCommit {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
    blocked: AtomicBool,
}

impl super::super::store::RuntimeStoreFaultInjector for BlockConfigureConversationBeforeCommit {
    fn before_operation(
        &self,
        operation: super::super::store::RuntimeStoreOperation,
    ) -> Result<(), RuntimeStoreError> {
        if operation
            == super::super::store::RuntimeStoreOperation::ConfigureConversationBeforeCommit
            && !self.blocked.swap(true, Ordering::SeqCst)
        {
            self.entered.wait();
            self.release.wait();
        }
        Ok(())
    }
}

impl super::super::store::RuntimeStoreFaultInjector for BlockCreateConversationAfterCommit {
    fn before_operation(
        &self,
        operation: super::super::store::RuntimeStoreOperation,
    ) -> Result<(), RuntimeStoreError> {
        if operation == super::super::store::RuntimeStoreOperation::CreateConversationAfterCommit
            && !self.blocked.swap(true, Ordering::SeqCst)
        {
            self.entered.wait();
            self.release.wait();
        }
        Ok(())
    }
}

struct TestRoot {
    path: PathBuf,
    keys: MemoryKeyStore,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-runtime-core-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create core test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure core test root");
        }
        Self {
            path,
            keys: MemoryKeyStore::new(),
        }
    }

    fn kek(&self) -> StorageKek {
        load_or_create_storage_kek(&self.keys, &self.path.join("key-state.db"))
            .expect("core test StorageKEK")
    }

    async fn open_store(&self) -> RuntimeStoreHandle {
        RuntimeStoreHandle::open(
            super::super::store::RuntimeStoreConfig::new(self.path.join("runtime.db"))
                .with_command_capacity(1_024),
            self.kek(),
        )
        .await
        .expect("open core test store")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn core(root: &TestRoot) -> Arc<RuntimeCore> {
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    Arc::new(
        RuntimeCore::new_with_unconfigured_prompts_for_test(store, router, [0xA1; 32])
            .expect("construct RuntimeCore test fixture"),
    )
}

fn start_request(key: &str) -> RuntimeRequest {
    RuntimeRequest::Start(ConversationStart {
        agent_kind: AgentKind::Codex,
        idempotency_key: IdempotencyKey::new(key),
        cwd: PathBuf::from("/tmp/agentdeck-core-test"),
        title: Some("core test".to_owned()),
    })
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

fn start_receipt(reply: RuntimeReply) -> ConversationStartReceipt {
    match reply {
        RuntimeReply::ConversationStart(receipt) => receipt,
        other => panic!("expected conversation start receipt, got {other:?}"),
    }
}

async fn connect_local(core: &RuntimeCore, seed: u8) -> ConnectionId {
    let principal = core
        .issue_verified_local_principal(501, [seed; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    core.connect(principal, ConnectionSink::new(sink))
        .expect("connect local")
}

async fn saturate_paced_writer(
    core: &RuntimeCore,
    connection: ConnectionId,
    receiver: &mut mpsc::Receiver<crate::runtime::ConnectionWrite>,
    envelope: &RuntimeEnvelope,
) -> (crate::runtime::ConnectionWrite, Vec<FlushReceipt>) {
    let mut receipts = Vec::with_capacity(DEFAULT_CONNECTION_WRITER_FRAMES);
    receipts.push(
        core.enqueue_paced(connection, envelope)
            .await
            .expect("enqueue first paced frame"),
    );
    let held_write = receiver.recv().await.expect("first paced transport write");
    for _ in 1..DEFAULT_CONNECTION_WRITER_FRAMES {
        receipts.push(
            core.enqueue_paced(connection, envelope)
                .await
                .expect("fill paced frame budget"),
        );
    }
    (held_write, receipts)
}

async fn connect_local_with_approval_permissions(
    core: &RuntimeCore,
    seed: u8,
    permissions: crate::runtime::connection::ApprovalPermissionGrant,
) -> ConnectionId {
    let principal = core
        .principal_issuer
        .issue_verified_local_with_approval_permissions(501, [seed; 16], permissions)
        .expect("issue approval principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    core.connect(principal, ConnectionSink::new(sink))
        .expect("connect approval principal")
}

#[tokio::test]
async fn runtime_core_issues_explicit_local_control_without_upgrading_read_only_identity() {
    let root = TestRoot::new("local-control-principal");
    let core = core(&root).await;

    let control = core
        .issue_verified_local_control_principal(501, [0x21; 16])
        .expect("issue local-control principal");
    let approval = control
        .try_enter_approval()
        .expect("local-control approval capability");
    approval
        .require_resolve()
        .expect("local-control resolve permission");
    approval
        .require_retry()
        .expect("local-control retry permission");
    drop(approval);
    assert!(
        core.issue_verified_local_principal(501, [0x21; 16])
            .is_err(),
        "a local-control lease cannot be downgraded to read-only"
    );

    let read_only = core
        .issue_verified_local_principal(501, [0x22; 16])
        .expect("issue read-only local principal");
    assert!(matches!(
        read_only.try_enter_approval(),
        Err(crate::runtime::connection::PrincipalAccessError::PermissionDenied)
    ));
    assert!(
        core.issue_verified_local_control_principal(501, [0x22; 16])
            .is_err(),
        "a read-only lease cannot be upgraded to local-control"
    );
    core.shutdown().await.expect("shutdown cold core");
}

fn synthetic_wire_id(kind: RuntimeIdKind, seed: u8) -> String {
    RuntimeId::from_bytes(kind, [seed; 16])
        .expect("synthetic runtime id")
        .to_canonical_string()
}

#[tokio::test]
async fn direct_hello_remains_available_while_core_is_cold() {
    let root = TestRoot::new("cold-direct-hello");
    let core = core(&root).await;

    let reply = core
        .handle(
            ConnectionId::from_test_bytes([0x31; 16]),
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
    core.shutdown().await.expect("shutdown cold core");
}

#[tokio::test]
async fn runtime_v2_describe_and_configure_cut_over_without_enabling_later_families() {
    let root = TestRoot::new("v2-transitional");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core =
        Arc::new(RuntimeCore::new_production(store, router).expect("construct production v2 core"));
    core.recover().await.expect("recover v2 transitional core");
    let connection = connect_local(&core, 0x72).await;
    let conversation = start_receipt(
        core.handle(connection, start_request("v2-transitional-start"))
            .await,
    );
    let configuration = codex_configuration(CodexReasoningEffort::High);

    let describe = core
        .handle(connection, RuntimeRequest::DescribeAgents)
        .await;
    let RuntimeReply::Agents(descriptions) = describe else {
        panic!("DescribeAgents must return typed agent descriptions")
    };
    assert_eq!(descriptions.agents().len(), 2);
    assert_eq!(
        descriptions
            .agents()
            .iter()
            .map(|description| description.agent_kind())
            .collect::<Vec<_>>(),
        vec![AgentKind::Codex, AgentKind::ClaudeCode]
    );
    let configure = core
        .handle(
            connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                conversation.conversation_id.clone(),
                IdempotencyKey::new("v2-configure"),
                0,
                configuration,
            )),
        )
        .await;
    assert!(matches!(
        configure,
        RuntimeReply::Configuration(ConfigurationReceipt::Applied {
            ref conversation_id,
            configuration_revision: 1,
        }) if conversation_id == &conversation.conversation_id
    ));
    let metadata = core
        .handle(
            connection,
            RuntimeRequest::UpdateConversationMetadata(
                ConversationMetadataMutationRequest::new(
                    conversation.conversation_id.clone(),
                    IdempotencyKey::new("v2-metadata"),
                    0,
                    ConversationMetadataMutation::SetArchived { archived: true },
                )
                .unwrap(),
            ),
        )
        .await;
    assert!(matches!(
        metadata,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
    ));
    for expected_configuration_revision in [0, 1] {
        let prompt = core
            .handle(
                connection,
                RuntimeRequest::SendPrompt(SendPromptRequest {
                    conversation_id: conversation.conversation_id.clone(),
                    idempotency_key: IdempotencyKey::new(format!(
                        "v2-prompt-{expected_configuration_revision}"
                    )),
                    expected_configuration_revision,
                    prompt: PromptPayload::new("must not enter the legacy driver").unwrap(),
                }),
            )
            .await;
        assert!(matches!(
            prompt,
            RuntimeReply::Command(CommandReceipt::Failed {
                failure: RuntimeFailure { code, .. }
            }) if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
        ));
    }
    let stage = core
        .handle(
            connection,
            RuntimeRequest::StageUpgrade(
                StageUpgradeRequest::new(
                    "1.2.3".into(),
                    ArtifactSha256::new("ab".repeat(32)).unwrap(),
                    IdempotencyKey::new("v2-stage"),
                    LocalOnlyAdministration::LocalOnly,
                )
                .unwrap(),
            ),
        )
        .await;
    assert!(matches!(
        stage,
        RuntimeReply::StageUpgrade(StageUpgradeReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
    ));
    core.shutdown()
        .await
        .expect("shutdown v2 transitional core");
}

#[tokio::test]
async fn configure_conversation_returns_exact_replay_conflict_and_typed_failures() {
    // 威胁场景：若 Configure 的 parse/store 错误逃逸为 envelope failure，Companion
    // 会丢失 CAS/idempotency 语义，并可能把同一请求当成可无条件重试。
    let root = TestRoot::new("configure-receipts");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(RuntimeCore::new(store, router, [0xA3; 32]).expect("construct core"));
    core.recover()
        .await
        .expect("recover configure receipt core");
    let connection = connect_local(&core, 0x74).await;
    let conversation = start_receipt(
        core.handle(connection, start_request("configure-receipts-start"))
            .await,
    );

    let exact_request = ConfigureConversationRequest::new(
        conversation.conversation_id.clone(),
        IdempotencyKey::new("configure-exact"),
        0,
        codex_configuration(CodexReasoningEffort::High),
    );
    assert!(matches!(
        core.handle(
            connection,
            RuntimeRequest::ConfigureConversation(exact_request.clone())
        )
        .await,
        RuntimeReply::Configuration(ConfigurationReceipt::Applied {
            configuration_revision: 1,
            ..
        })
    ));
    assert!(matches!(
        core.handle(
            connection,
            RuntimeRequest::ConfigureConversation(exact_request)
        )
        .await,
        RuntimeReply::Configuration(ConfigurationReceipt::Replayed {
            configuration_revision: 1,
            ..
        })
    ));

    let same_key_different_request = core
        .handle(
            connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                conversation.conversation_id.clone(),
                IdempotencyKey::new("configure-exact"),
                0,
                codex_configuration(CodexReasoningEffort::Medium),
            )),
        )
        .await;
    assert!(matches!(
        same_key_different_request,
        RuntimeReply::Configuration(ConfigurationReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == "daemon.command.idempotency_conflict"
    ));

    let stale = core
        .handle(
            connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                conversation.conversation_id.clone(),
                IdempotencyKey::new("configure-stale"),
                0,
                codex_configuration(CodexReasoningEffort::Low),
            )),
        )
        .await;
    assert!(matches!(
        stale,
        RuntimeReply::Configuration(ConfigurationReceipt::Conflict {
            current_configuration_revision: 1,
            ..
        })
    ));

    let missing = core
        .handle(
            connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                ConversationId::new("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                IdempotencyKey::new("configure-missing"),
                0,
                codex_configuration(CodexReasoningEffort::Low),
            )),
        )
        .await;
    assert!(matches!(
        missing,
        RuntimeReply::Configuration(ConfigurationReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == agentdeck_protocol::runtime::failure::DAEMON_CONVERSATION_NOT_FOUND
    ));

    let malformed = core
        .handle(
            connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                ConversationId::new("not-a-canonical-runtime-id"),
                IdempotencyKey::new("configure-malformed"),
                0,
                codex_configuration(CodexReasoningEffort::Low),
            )),
        )
        .await;
    assert!(matches!(
        malformed,
        RuntimeReply::Configuration(ConfigurationReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_INVALID_REQUEST
    ));

    core.shutdown()
        .await
        .expect("shutdown configure receipt core");
}

#[tokio::test]
async fn describe_and_configure_authorization_failures_keep_their_reply_families() {
    let root = TestRoot::new("configure-revoked");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(RuntimeCore::new(store, router, [0xA4; 32]).expect("construct core"));
    core.recover()
        .await
        .expect("recover revoked configure core");
    let principal = core
        .issue_verified_local_principal(501, [0x75; 16])
        .expect("issue retained principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    let connection = core
        .connect(principal.clone(), ConnectionSink::new(sink))
        .expect("connect retained principal");
    principal.begin_revoke().await.expect("begin revoke");
    principal.finish_revoke();

    assert!(matches!(
        core.handle(connection, RuntimeRequest::DescribeAgents).await,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == DAEMON_AUTHORIZATION_REVOKED
    ));
    let configure = core
        .handle(
            connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                ConversationId::new("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                IdempotencyKey::new("configure-revoked"),
                0,
                codex_configuration(CodexReasoningEffort::Low),
            )),
        )
        .await;
    assert!(matches!(
        configure,
        RuntimeReply::Configuration(ConfigurationReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_AUTHORIZATION_REVOKED
    ));
    core.shutdown()
        .await
        .expect("shutdown revoked configure core");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configure_authorization_guard_covers_the_store_commit() {
    // 威胁场景：若 Core 只用 principal 取 owner 后就释放 guard，revoke 可在
    // Configure COMMIT 前完成，使已撤销身份仍写入 durable configuration。
    let root = TestRoot::new("configure-authorization-commit");
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let store = RuntimeStoreHandle::open(
        super::super::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_fault_injector(Arc::new(BlockConfigureConversationBeforeCommit {
                entered: entered.clone(),
                release: release.clone(),
                blocked: AtomicBool::new(false),
            })),
        root.kek(),
    )
    .await
    .expect("open configure authorization store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(RuntimeCore::new(store, router, [0xA5; 32]).expect("construct core"));
    core.recover()
        .await
        .expect("recover configure authorization core");
    let principal = core
        .issue_verified_local_principal(501, [0x76; 16])
        .expect("issue configure authorization principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    let connection = core
        .connect(principal.clone(), ConnectionSink::new(sink))
        .expect("connect configure authorization principal");
    let conversation = start_receipt(
        core.handle(connection, start_request("configure-authorization-start"))
            .await,
    );

    let handling = tokio::spawn({
        let core = core.clone();
        async move {
            core.handle(
                connection,
                RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                    conversation.conversation_id,
                    IdempotencyKey::new("configure-authorization"),
                    0,
                    codex_configuration(CodexReasoningEffort::High),
                )),
            )
            .await
        }
    });
    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .expect("observe Configure before COMMIT");
    let mut revoking = tokio::spawn({
        let principal = principal.clone();
        async move { principal.begin_revoke().await }
    });
    let revoked_before_release =
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut revoking).await;
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .expect("release Configure before COMMIT");
    let revoked_early = revoked_before_release.is_ok();
    let revoke_result = match revoked_before_release {
        Ok(result) => result,
        Err(_) => revoking.await,
    };
    assert!(matches!(
        handling.await.expect("join Configure request"),
        RuntimeReply::Configuration(ConfigurationReceipt::Applied {
            configuration_revision: 1,
            ..
        })
    ));
    assert!(
        !revoked_early,
        "revoke must wait for Configure authorization through COMMIT"
    );
    revoke_result
        .expect("join principal revoke")
        .expect("revoke after Configure COMMIT");
    principal.finish_revoke();
    core.shutdown()
        .await
        .expect("shutdown configure authorization core");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_configure_caller_keeps_authorization_until_store_completion() {
    // 威胁场景：连接断开会取消 Core caller future；若 authorization guard 仍由
    // caller 栈持有，revoke 可在已排队的 Store COMMIT 前完成。
    let root = TestRoot::new("configure-caller-canceled");
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let store = RuntimeStoreHandle::open(
        super::super::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_fault_injector(Arc::new(BlockConfigureConversationBeforeCommit {
                entered: entered.clone(),
                release: release.clone(),
                blocked: AtomicBool::new(false),
            })),
        root.kek(),
    )
    .await
    .expect("open canceled Configure store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(RuntimeCore::new(store, router, [0xA6; 32]).expect("construct core"));
    core.recover()
        .await
        .expect("recover canceled Configure core");
    let principal = core
        .issue_verified_local_principal(501, [0x77; 16])
        .expect("issue canceled Configure principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    let connection = core
        .connect(principal.clone(), ConnectionSink::new(sink))
        .expect("connect canceled Configure principal");
    let conversation = start_receipt(
        core.handle(connection, start_request("configure-canceled-start"))
            .await,
    );
    let internal_conversation =
        parse_conversation_id(&conversation.conversation_id).expect("parse started conversation");

    let handling = tokio::spawn({
        let core = core.clone();
        async move {
            core.handle(
                connection,
                RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                    conversation.conversation_id,
                    IdempotencyKey::new("configure-canceled"),
                    0,
                    codex_configuration(CodexReasoningEffort::High),
                )),
            )
            .await
        }
    });
    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .expect("observe canceled Configure before COMMIT");
    handling.abort();
    assert!(
        handling
            .await
            .expect_err("Configure caller must be canceled")
            .is_cancelled(),
        "aborted caller reports cancellation"
    );
    let mut revoking = tokio::spawn({
        let principal = principal.clone();
        async move { principal.begin_revoke().await }
    });
    let revoked_before_release =
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut revoking).await;
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .expect("release canceled Configure before COMMIT");
    let revoked_early = revoked_before_release.is_ok();
    let revoke_result = match revoked_before_release {
        Ok(result) => result,
        Err(_) => revoking.await,
    };
    assert!(
        !revoked_early,
        "detached durable Configure must retain authorization after caller cancellation"
    );
    revoke_result
        .expect("join canceled Configure revoke")
        .expect("revoke after detached Store completion");
    let state = core
        .store
        .load_configuration_state_at_event_cursor(internal_conversation, Some(0))
        .await
        .expect("read committed configuration after caller cancellation");
    assert_eq!(state.configuration_revision(), 1);
    principal.finish_revoke();
    core.shutdown()
        .await
        .expect("shutdown canceled Configure core");
}

#[tokio::test]
async fn side_effect_free_public_constructor_rejects_unconfigured_prompt() {
    let root = TestRoot::new("v2-public-constructor");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA2; 32])
            .expect("construct side-effect-free public core"),
    );
    core.recover().await.expect("recover public core");
    let connection = connect_local(&core, 0x73).await;
    let conversation = start_receipt(
        core.handle(connection, start_request("v2-public-constructor-start"))
            .await,
    );

    let reply = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: conversation.conversation_id,
                idempotency_key: IdempotencyKey::new("v2-public-constructor-prompt"),
                expected_configuration_revision: 0,
                prompt: PromptPayload::new("must stay fail-closed").unwrap(),
            }),
        )
        .await;
    assert!(matches!(
        reply,
        RuntimeReply::Command(CommandReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
    ));

    core.shutdown().await.expect("shutdown public core");
}

#[tokio::test]
async fn principal_without_approval_permission_cannot_claim() {
    let root = TestRoot::new("approval-permission-denied");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let connection = connect_local(&core, 41).await;

    let reply = core
        .handle(
            connection,
            RuntimeRequest::ResolveApproval {
                conversation_id: ConversationId::new(synthetic_wire_id(
                    RuntimeIdKind::Conversation,
                    0x41,
                )),
                turn_id: TurnId::new(synthetic_wire_id(RuntimeIdKind::Turn, 0x42)),
                approval_id: ApprovalId::new(synthetic_wire_id(RuntimeIdKind::Approval, 0x43)),
                decision: ActionDecision {
                    request_id: "request-permission-denied".to_owned(),
                    decision: ActionDecisionKind::Approve,
                    persist: false,
                },
            },
        )
        .await;

    assert!(matches!(
        reply,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
    ));
    let retry = core
        .handle(
            connection,
            RuntimeRequest::RetryApproval {
                conversation_id: ConversationId::new(synthetic_wire_id(
                    RuntimeIdKind::Conversation,
                    0x41,
                )),
                approval_id: ApprovalId::new(synthetic_wire_id(RuntimeIdKind::Approval, 0x43)),
            },
        )
        .await;
    assert!(matches!(
        retry,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
    ));
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn approval_requests_require_canonical_approval_ids() {
    let root = TestRoot::new("approval-id-validation");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let connection = connect_local_with_approval_permissions(
        &core,
        42,
        crate::runtime::connection::ApprovalPermissionGrant::ResolveOnly,
    )
    .await;

    let reply = core
        .handle(
            connection,
            RuntimeRequest::ResolveApproval {
                conversation_id: ConversationId::new(synthetic_wire_id(
                    RuntimeIdKind::Conversation,
                    0x51,
                )),
                turn_id: TurnId::new(synthetic_wire_id(RuntimeIdKind::Turn, 0x52)),
                approval_id: ApprovalId::new("not-a-canonical-approval-id"),
                decision: ActionDecision {
                    request_id: "request-invalid-id".to_owned(),
                    decision: ActionDecisionKind::Deny,
                    persist: false,
                },
            },
        )
        .await;

    assert!(matches!(
        reply,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == DAEMON_RUNTIME_INVALID_REQUEST
    ));
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn start_is_pure_durable_idempotent_then_prompt_and_query_are_separate() {
    let root = TestRoot::new("start-query");
    let core = core(&root).await;
    assert_eq!(
        core.recover().await.expect("recover"),
        RecoveryReport::default()
    );
    let connection = connect_local(&core, 1).await;

    let created = start_receipt(core.handle(connection, start_request("stable-start")).await);
    assert!(!created.replayed);
    let replayed = start_receipt(core.handle(connection, start_request("stable-start")).await);
    assert!(replayed.replayed);
    assert_eq!(created.conversation_id, replayed.conversation_id);
    assert_eq!(core.actor_count().await, 1);

    let invalid_prompt = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: created.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new(""),
                expected_configuration_revision: 0,
                prompt: PromptPayload::new("must be rejected before actor admission")
                    .expect("prompt"),
            }),
        )
        .await;
    assert!(matches!(
        invalid_prompt,
        RuntimeReply::Command(CommandReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_INVALID_REQUEST
    ));
    let missing_conversation = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: wire_conversation_id(
                    RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xEE; 16])
                        .expect("synthetic missing conversation"),
                ),
                idempotency_key: IdempotencyKey::new("missing-conversation"),
                expected_configuration_revision: 0,
                prompt: PromptPayload::new("must stay in command receipt family").expect("prompt"),
            }),
        )
        .await;
    assert!(matches!(
        missing_conversation,
        RuntimeReply::Command(CommandReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == agentdeck_protocol::runtime::failure::DAEMON_CONVERSATION_NOT_FOUND
    ));
    let invalid_query = core
        .handle(
            connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
                conversation_id: created.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new("x".repeat(1_025)),
            }),
        )
        .await;
    assert!(matches!(
        invalid_query,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == DAEMON_RUNTIME_INVALID_REQUEST
    ));
    let conflict = core
        .handle(
            connection,
            RuntimeRequest::Start(ConversationStart {
                agent_kind: AgentKind::ClaudeCode,
                idempotency_key: IdempotencyKey::new("stable-start"),
                cwd: PathBuf::from("/tmp/agentdeck-core-test"),
                title: Some("conflicting descriptor".to_owned()),
            }),
        )
        .await;
    assert!(matches!(
        conflict,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == agentdeck_protocol::runtime::failure::DAEMON_COMMAND_IDEMPOTENCY_CONFLICT
    ));

    let prompt_key = IdempotencyKey::new("prompt-1");
    let prompt = PromptPayload::new("hello durable queue").expect("prompt");
    let accepted = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: created.conversation_id.clone(),
                idempotency_key: prompt_key.clone(),
                expected_configuration_revision: 0,
                prompt,
            }),
        )
        .await;
    let command_id = match accepted {
        RuntimeReply::Command(CommandReceipt::Accepted { command_id, .. }) => command_id,
        other => panic!("expected accepted command, got {other:?}"),
    };
    let status = core
        .handle(
            connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
                conversation_id: created.conversation_id.clone(),
                idempotency_key: prompt_key,
            }),
        )
        .await;
    match status {
        RuntimeReply::CommandStatus(receipt) => {
            assert_eq!(receipt.conversation_id, created.conversation_id);
            assert_eq!(receipt.command_id, command_id);
            assert_eq!(receipt.status, CommandStatus::Accepted);
            assert_eq!(receipt.turn_id, None);
        }
        other => panic!("expected command status, got {other:?}"),
    }

    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn one_hundred_concurrent_start_retries_install_exactly_one_actor() {
    let root = TestRoot::new("start-race");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let connection = connect_local(&core, 2).await;
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let core = core.clone();
        tasks.push(tokio::spawn(async move {
            start_receipt(
                core.handle(connection, start_request("same-race-key"))
                    .await,
            )
        }));
    }
    let mut created = 0;
    let mut replayed = 0;
    let mut identity = None;
    for task in tasks {
        let receipt = task.await.expect("join start retry");
        if receipt.replayed {
            replayed += 1;
        } else {
            created += 1;
        }
        match &identity {
            Some(existing) => assert_eq!(existing, &receipt.conversation_id),
            None => identity = Some(receipt.conversation_id),
        }
    }
    assert_eq!(created, 1);
    assert_eq!(replayed, 99);
    assert_eq!(core.actor_count().await, 1);
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn accepted_queue_is_recovered_paged_and_remains_unstarted_without_real_gate() {
    let root = TestRoot::new("restart");
    let first_core = core(&root).await;
    first_core.recover().await.expect("first recover");
    let first_connection = connect_local(&first_core, 3).await;
    let conversation = start_receipt(
        first_core
            .handle(first_connection, start_request("restart-start"))
            .await,
    );
    let accepted = first_core
        .handle(
            first_connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: conversation.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new("restart-prompt"),
                expected_configuration_revision: 0,
                prompt: PromptPayload::new("survive restart").expect("prompt"),
            }),
        )
        .await;
    assert!(matches!(
        accepted,
        RuntimeReply::Command(CommandReceipt::Accepted { .. })
    ));
    first_core.shutdown().await.expect("first shutdown");
    drop(first_core);

    let second_core = core(&root).await;
    assert_eq!(
        second_core.recover().await.expect("second recover"),
        RecoveryReport {
            conversations: 1,
            accepted_commands: 1,
        }
    );
    let second_connection = connect_local(&second_core, 3).await;
    let replayed_start = start_receipt(
        second_core
            .handle(second_connection, start_request("restart-start"))
            .await,
    );
    assert!(replayed_start.replayed);
    assert_eq!(replayed_start.conversation_id, conversation.conversation_id);
    let status = second_core
        .handle(
            second_connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
                conversation_id: conversation.conversation_id,
                idempotency_key: IdempotencyKey::new("restart-prompt"),
            }),
        )
        .await;
    assert!(matches!(
        status,
        RuntimeReply::CommandStatus(CommandStatusReceipt {
            status: CommandStatus::Accepted,
            turn_id: None,
            ..
        })
    ));
    second_core.shutdown().await.expect("second shutdown");
}

#[tokio::test]
async fn shutdown_drains_admitted_operations_before_closing_subsystems() {
    let root = TestRoot::new("operation-drain");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let admitted = core
        .try_enter_operation()
        .expect("admit operation before draining");
    let shutting_core = core.clone();
    let shutdown = tokio::spawn(async move { shutting_core.shutdown().await });

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while core.lifecycle.load(Ordering::Acquire) != CORE_CLOSING {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown publishes internal closing fence");
    assert_ne!(
        core.lifecycle.load(Ordering::Acquire),
        CORE_DRAINING,
        "Draining is not published before admitted operations quiesce"
    );
    assert!(
        !shutdown.is_finished(),
        "shutdown must wait for the already admitted operation"
    );
    assert!(matches!(
        core.try_enter_operation(),
        Err(RuntimeCoreError::NotReady)
    ));

    drop(admitted);
    shutdown
        .await
        .expect("join shutdown")
        .expect("shutdown after quiescence");
    assert_eq!(core.lifecycle.load(Ordering::Acquire), CORE_STOPPED);
}

#[tokio::test]
async fn enqueue_writes_a_complete_runtime_envelope() {
    let root = TestRoot::new("complete-envelope");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [4; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");

    let outbound = agentdeck_protocol::runtime::RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: agentdeck_protocol::runtime::identity::MessageId::new(
            "message-core-envelope-test",
        ),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };
    core.enqueue(connection, &outbound).expect("enqueue reply");
    let write = receiver.recv().await.expect("transport write");
    let envelope: agentdeck_protocol::runtime::RuntimeEnvelope =
        serde_json::from_slice(write.bytes()).expect("complete RuntimeEnvelope");
    assert_eq!(envelope.version, RUNTIME_PROTOCOL_VERSION);
    assert_eq!(envelope.message_id.as_str(), "message-core-envelope-test");
    assert!(matches!(
        envelope.body,
        RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
    write.acknowledge().expect("ack transport write");
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn core_disconnect_cancels_only_the_slow_writer_and_rejects_ack_after_cancel() {
    // 威胁场景：一条 UDS socket write 永久阻塞时，Core fail-close 若不能被 transport
    // 观察，会让该连接继续持有 frame/byte budget；取消必须只命中该连接，不能伤及 sibling。
    let root = TestRoot::new("disconnect-cancels-slow-writer");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let (slow_tx, mut slow_rx) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let slow = core
        .connect(
            core.issue_verified_local_principal(501, [0x31; 16])
                .expect("issue slow principal"),
            ConnectionSink::new(slow_tx),
        )
        .expect("connect slow writer");
    let (sibling_tx, mut sibling_rx) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let sibling = core
        .connect(
            core.issue_verified_local_principal(501, [0x32; 16])
                .expect("issue sibling principal"),
            ConnectionSink::new(sibling_tx),
        )
        .expect("connect sibling writer");
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("message-core-writer-cancellation"),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };

    core.enqueue(slow, &envelope).expect("enqueue slow write");
    let mut slow_write = slow_rx.recv().await.expect("slow transport write");
    let disconnect = tokio::spawn({
        let core = core.clone();
        async move { core.disconnect(slow).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), slow_write.cancelled())
        .await
        .expect("Core disconnect must cancel the slow transport write");
    disconnect.await.expect("join slow disconnect");
    assert!(
        slow_write.acknowledge().is_err(),
        "ACK after cancel must fail"
    );

    core.enqueue(sibling, &envelope)
        .expect("sibling remains connected");
    sibling_rx
        .recv()
        .await
        .expect("sibling transport write")
        .acknowledge()
        .expect("ACK sibling write");
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn enqueue_rejects_oversized_reply_and_stream_before_connection_writer() {
    let root = TestRoot::new("oversized-egress-frame");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [5; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");

    let oversized_failure = || {
        RuntimeFailure::new(
            "daemon.test.oversized",
            "x".repeat(MAX_RUNTIME_JSON_FRAME_BYTES),
        )
    };
    let reply = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("message-core-oversized-reply"),
        body: RuntimeMessage::Reply(RuntimeReply::Failure(oversized_failure())),
    };
    let failure = core.enqueue(connection, &reply).unwrap_err();
    assert_eq!(
        failure.code,
        agentdeck_protocol::runtime::failure::DAEMON_PAYLOAD_ITEM_TOO_LARGE
    );

    let event = RuntimeEvent::new(
        ConversationId::new("conversation-core-oversized-stream"),
        EventId::new("event-core-oversized-stream"),
        0,
        None,
        None,
        None,
        RuntimeEventBody::Error {
            failure: oversized_failure(),
        },
    )
    .unwrap();
    let stream = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("message-core-oversized-stream"),
        body: RuntimeMessage::Stream(RuntimeStreamItem::Event(event)),
    };
    let failure = core.enqueue(connection, &stream).unwrap_err();
    assert_eq!(
        failure.code,
        agentdeck_protocol::runtime::failure::DAEMON_PAYLOAD_ITEM_TOO_LARGE
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn envelope_request_reply_reuses_the_exact_request_message_id() {
    let root = TestRoot::new("request-message-id");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [6; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");
    let request_id = MessageId::new("request-message-id-must-be-reused");

    core.handle_envelope(
        connection,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: request_id.clone(),
            body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            })),
        },
    )
    .await
    .expect("route request envelope");

    let write = receiver.recv().await.expect("directed reply write");
    let reply: RuntimeEnvelope =
        serde_json::from_slice(write.bytes()).expect("decode directed reply envelope");
    assert_eq!(reply.message_id.as_str(), request_id.as_str());
    assert!(matches!(
        reply.body,
        RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
    write.acknowledge().expect("ACK directed reply flush");
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn envelope_admission_survives_commit_to_reply_closing_fence() {
    let root = TestRoot::new("envelope-admission-commit-reply-fence");
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let store = RuntimeStoreHandle::open(
        super::super::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_fault_injector(Arc::new(BlockCreateConversationAfterCommit {
                entered: entered.clone(),
                release: release.clone(),
                blocked: AtomicBool::new(false),
            })),
        root.kek(),
    )
    .await
    .expect("open fenced core test store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32]).expect("construct fenced RuntimeCore"),
    );
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [10; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");
    let request_id = MessageId::new("admitted-start-reply-message-id");

    let handling = tokio::spawn({
        let core = core.clone();
        let request_id = request_id.clone();
        async move {
            core.handle_envelope(
                connection,
                RuntimeEnvelope {
                    version: RUNTIME_PROTOCOL_VERSION,
                    message_id: request_id,
                    body: RuntimeMessage::Request(start_request("admitted-start")),
                },
            )
            .await
        }
    });
    tokio::task::spawn_blocking(move || {
        entered.wait();
    })
    .await
    .expect("observe create conversation after COMMIT");
    core.lifecycle.store(CORE_CLOSING, Ordering::Release);
    tokio::task::spawn_blocking(move || {
        release.wait();
    })
    .await
    .expect("release create conversation after COMMIT");

    let route_result = handling.await.expect("join admitted envelope");
    let write = if route_result.is_ok() {
        Some(receiver.recv().await.expect("directed start reply write"))
    } else {
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        None
    };
    if let Some(write) = write.as_ref() {
        let reply: RuntimeEnvelope =
            serde_json::from_slice(write.bytes()).expect("decode directed start reply");
        assert_eq!(reply.message_id.as_str(), request_id.as_str());
        assert!(matches!(
            reply.body,
            RuntimeMessage::Reply(RuntimeReply::ConversationStart(_))
        ));
    }
    if let Some(write) = write {
        write.acknowledge().expect("ACK directed start reply");
    }
    core.shutdown().await.expect("shutdown fenced core");
    route_result.expect("already admitted envelope must cross the closing reply fence");
}

#[tokio::test]
async fn envelope_ingress_returns_typed_failures_for_wrong_version_and_non_request() {
    let root = TestRoot::new("invalid-envelope-kind");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [7; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");

    for (message_id, envelope, expected_code) in [
        (
            "wrong-version",
            RuntimeEnvelope {
                version: 1,
                message_id: MessageId::new("wrong-version"),
                body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                })),
            },
            DAEMON_RUNTIME_PROTOCOL_MISMATCH,
        ),
        (
            "non-request",
            RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id: MessageId::new("non-request"),
                body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                })),
            },
            DAEMON_RUNTIME_INVALID_REQUEST,
        ),
    ] {
        core.handle_envelope(connection, envelope)
            .await
            .expect("enqueue typed envelope failure");
        let write = receiver.recv().await.expect("typed failure write");
        let reply: RuntimeEnvelope =
            serde_json::from_slice(write.bytes()).expect("decode typed failure envelope");
        assert_eq!(reply.message_id.as_str(), message_id);
        assert!(matches!(
            reply.body,
            RuntimeMessage::Reply(RuntimeReply::Failure(RuntimeFailure { ref code, .. }))
                if code == expected_code
        ));
        write.acknowledge().expect("ACK typed failure flush");
    }
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn envelope_ingress_fails_typed_for_an_invalid_connection() {
    let root = TestRoot::new("invalid-envelope-connection");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [8; 16])
        .expect("issue local principal");
    let (sink, _receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");
    core.disconnect(connection).await;

    let failure = core
        .handle_envelope(
            connection,
            RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id: MessageId::new("disconnected-request"),
                body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                })),
            },
        )
        .await
        .expect_err("disconnected ingress must fail closed");
    assert_eq!(failure.code, DAEMON_RUNTIME_CONNECTION_UNAVAILABLE);
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn core_paced_egress_exposes_transport_flush_completion_without_socket_access() {
    let root = TestRoot::new("paced-egress-receipt");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [9; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");
    let outbound = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("paced-core-egress"),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };

    let receipt = core
        .enqueue_paced(connection, &outbound)
        .await
        .expect("pace through the connection-owned reply pump");
    let write = receiver.recv().await.expect("transport write");
    let completion = receipt.wait();
    tokio::pin!(completion);
    assert!(
        (tokio::select! {
            biased;
            result = &mut completion => Some(result),
            () = async {} => None,
        })
        .is_none()
    );
    write.acknowledge().expect("ACK transport flush");
    completion.await.expect("observe transport flush ACK");

    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn paced_enqueue_rejects_new_frame_after_closing() {
    let root = TestRoot::new("paced-closing-admission");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [11; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");
    let outbound = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("paced-closing-rejected"),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };

    core.lifecycle.store(CORE_CLOSING, Ordering::Release);
    let (failure, delivered) = match core.enqueue_paced(connection, &outbound).await {
        Err(failure) => (Some(failure), false),
        Ok(receipt) => {
            let write = receiver
                .recv()
                .await
                .expect("unexpected paced transport write");
            write
                .acknowledge()
                .expect("ACK unexpected paced transport write");
            receipt
                .wait()
                .await
                .expect("observe unexpected paced flush ACK");
            (None, true)
        }
    };
    let receiver_empty = matches!(
        receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );
    core.shutdown().await.expect("shutdown closing core");

    let failure = failure.expect("Closing must reject a new paced frame");
    assert_eq!(failure.code, DAEMON_RUNTIME_NOT_READY);
    assert!(!delivered, "Closing must not deliver a paced frame");
    assert!(receiver_empty, "rejected paced frame reached transport");
}

#[tokio::test]
async fn paced_closing_fast_rejects_before_waiting_for_writer_budget() {
    let root = TestRoot::new("paced-closing-fast-reject");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [12; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");
    let outbound = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("paced-closing-fast-reject"),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };
    let (held_write, receipts) =
        saturate_paced_writer(&core, connection, &mut receiver, &outbound).await;

    core.lifecycle.store(CORE_CLOSING, Ordering::Release);
    let mut closing_enqueue = Box::pin(core.enqueue_paced(connection, &outbound));
    let result = tokio::select! {
        biased;
        result = &mut closing_enqueue => Some(result),
        () = async {} => None,
    };
    drop(closing_enqueue);
    let receiver_empty = matches!(
        receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );
    drop(held_write);
    drop(receipts);
    core.shutdown().await.expect("shutdown closing core");

    let failure = result
        .expect("Closing paced admission was Pending on its first poll")
        .expect_err("Closing must reject a new paced frame");
    assert_eq!(failure.code, DAEMON_RUNTIME_NOT_READY);
    assert!(
        receiver_empty,
        "Closing delivered an additional paced frame"
    );
}

#[tokio::test]
async fn paced_reservation_wait_does_not_hold_core_shutdown_quiescence() {
    let root = TestRoot::new("paced-wait-shutdown-quiescence");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let principal = core
        .issue_verified_local_principal(501, [13; 16])
        .expect("issue local principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local");
    let saturated_outbound = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("paced-wait-shutdown-saturated"),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };
    let blocked_message_id = MessageId::new("paced-wait-shutdown-blocked");
    let blocked_outbound = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: blocked_message_id.clone(),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };
    let (held_write, receipts) =
        saturate_paced_writer(&core, connection, &mut receiver, &saturated_outbound).await;
    let mut blocked = Box::pin(core.enqueue_paced(connection, &blocked_outbound));
    assert!(
        (tokio::select! {
            biased;
            result = &mut blocked => Some(result),
            () = async {} => None,
        })
        .is_none(),
        "paced reservation unexpectedly bypassed the held writer budget"
    );
    let inflight_while_waiting = core.operation_inflight.load(Ordering::Acquire);

    let shutdown = tokio::spawn({
        let core = core.clone();
        async move { core.shutdown().await }
    });
    while core.lifecycle.load(Ordering::Acquire) == CORE_READY {
        tokio::task::yield_now().await;
    }
    let _ = held_write.acknowledge();
    let blocked_failure = blocked
        .await
        .expect_err("post-reserve Closing fence must reject the blocked frame");
    shutdown
        .await
        .expect("join core shutdown")
        .expect("shutdown core");
    drop(receipts);
    let mut blocked_delivered = false;
    while let Some(write) = receiver.recv().await {
        let envelope: RuntimeEnvelope =
            serde_json::from_slice(write.bytes()).expect("decode drained transport frame");
        if envelope.message_id.as_str() == blocked_message_id.as_str() {
            blocked_delivered = true;
        }
        drop(write);
    }

    assert_eq!(
        inflight_while_waiting, 0,
        "paced permit wait held RuntimeOperationGuard across await"
    );
    assert_eq!(blocked_failure.code, DAEMON_RUNTIME_NOT_READY);
    assert!(
        !blocked_delivered,
        "post-reserve rejected frame reached transport"
    );
}

#[path = "subscription_tests.rs"]
mod subscription_tests;
