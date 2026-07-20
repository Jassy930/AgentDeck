use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex as StdMutex};

use agentdeck_protocol::relay_v2::enrollment::EnrollmentBundleV2;
use agentdeck_protocol::runtime::command::{RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::failure::{
    DAEMON_COMMAND_HISTORY_ONLY, DAEMON_COMMAND_NOT_FOUND,
    DAEMON_CONVERSATION_CONFIGURATION_CONFLICT, DAEMON_CONVERSATION_CONFIGURATION_REQUIRED,
};
use agentdeck_protocol::runtime::identity::{
    ApprovalId, ConversationId, DeviceHandle, EventId, GrantSerial, IdempotencyKey, MessageId,
    PairingId,
};
use agentdeck_protocol::runtime::{
    ArtifactSha256, ClaudeCodeConversationConfiguration, CodexConversationConfiguration,
    ConfigurationReceipt, ConfigureConversationRequest, ConversationConfiguration,
    ConversationMetadataMutation, ConversationMetadataMutationRequest, ConversationMetadataReceipt,
    ConversationStart, LocalOnlyAdministration, MAX_RUNTIME_JSON_FRAME_BYTES, MachineEnrollRequest,
    PairInvite, PairingReceipt, PendingPairing, PromptPayload, QueryReceiptSelector,
    RevocationReceipt, RuntimeEvent, RuntimeEventBody, RuntimeMessage, RuntimeStreamItem,
    SendPromptRequest, StageUpgradeReceipt, StageUpgradeRequest, TrustResetRequest,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentKind, ClaudeCodePermissionMode, CodexApprovalPolicy,
    CodexReasoningEffort, CodexSandboxMode,
};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::*;
use crate::runtime::pairing_administration::{PairingAdministration, PairingAdministrationError};
use crate::runtime::remote_administration::{RemoteAdministration, RemoteAdministrationError};
use crate::runtime::revocation_administration::{
    RevocationAdministration, RevocationAdministrationError,
};
use crate::runtime::store::{ImportNativeProjection, ImportNativeProjectionOutcome};
use crate::security::{MemoryKeyStore, SecretBytes, StorageKek, load_or_create_storage_kek};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct CountingRemoteAdministration {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl RemoteAdministration for CountingRemoteAdministration {
    async fn enroll(
        &self,
        _request: MachineEnrollRequest,
    ) -> Result<agentdeck_protocol::runtime::MachineRemoteStatus, RemoteAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(unenrolled_remote_status())
    }

    async fn status(
        &self,
    ) -> Result<agentdeck_protocol::runtime::MachineRemoteStatus, RemoteAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(unenrolled_remote_status())
    }

    async fn trust_reset(
        &self,
        _request: TrustResetRequest,
    ) -> Result<agentdeck_protocol::runtime::MachineRemoteStatus, RemoteAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(unenrolled_remote_status())
    }
}

#[derive(Default)]
struct CountingPairingAdministration {
    calls: AtomicUsize,
    create_owner: StdMutex<Option<crate::runtime::store::IdempotencyOwner>>,
}

#[async_trait::async_trait]
impl PairingAdministration for CountingPairingAdministration {
    async fn create(
        &self,
        owner: crate::runtime::store::IdempotencyOwner,
        _request: agentdeck_protocol::runtime::CreatePairInviteRequest,
    ) -> Result<PairInvite, PairingAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.create_owner.lock().expect("lock pairing owner") = Some(owner);
        Err(PairingAdministrationError::new(
            "daemon.pairing.test_create",
        ))
    }

    async fn list(&self) -> Result<Vec<PendingPairing>, PairingAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(PairingAdministrationError::new("daemon.pairing.test_list"))
    }

    async fn confirm(
        &self,
        _pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(PairingAdministrationError::new(
            "daemon.pairing.test_confirm",
        ))
    }

    async fn cancel(
        &self,
        _pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(PairingAdministrationError::new(
            "daemon.pairing.test_cancel",
        ))
    }
}

struct CountingRevocationAdministration {
    calls: AtomicUsize,
    observed: StdMutex<Vec<(DeviceHandle, GrantSerial)>>,
    failure_code: Option<&'static str>,
}

impl CountingRevocationAdministration {
    fn succeeding() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            observed: StdMutex::new(Vec::new()),
            failure_code: None,
        }
    }

    fn failing(code: &'static str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            observed: StdMutex::new(Vec::new()),
            failure_code: Some(code),
        }
    }
}

#[async_trait::async_trait]
impl RevocationAdministration for CountingRevocationAdministration {
    async fn revoke_device(
        &self,
        device: DeviceHandle,
        grant_serial: GrantSerial,
    ) -> Result<RevocationReceipt, RevocationAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.observed
            .lock()
            .expect("lock observed revocation targets")
            .push((device, grant_serial));
        match self.failure_code {
            Some(code) => Err(RevocationAdministrationError::new(code)),
            None => Ok(RevocationReceipt::Committed { grant_serial }),
        }
    }
}

fn unenrolled_remote_status() -> agentdeck_protocol::runtime::MachineRemoteStatus {
    agentdeck_protocol::runtime::MachineRemoteStatus::new(
        agentdeck_protocol::runtime::MachineRemoteLifecycle::Unenrolled,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("valid unenrolled status")
}

async fn wait_until_principal_revoking(principal: &AuthenticatedPrincipal) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while principal.is_active() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("principal must enter Revoking before the test releases Store COMMIT");
}

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

struct BlockUpdateConversationMetadataBeforeCommit {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    blocked: AtomicBool,
}

struct BlockAcceptCommandBeforeCommit {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
    blocked: AtomicBool,
}

struct RecordingUpgradeService {
    prepares: AtomicUsize,
    arms: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::runtime::upgrade::UpgradeService for RecordingUpgradeService {
    async fn prepare(
        &self,
        request: StageUpgradeRequest,
    ) -> Result<crate::runtime::upgrade::PreparedUpgrade, RuntimeFailure> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        let target_version = request.target_version().to_owned();
        let arms = self.arms.clone();
        Ok(crate::runtime::upgrade::PreparedUpgrade::with_deferred(
            StageUpgradeReceipt::Staged { target_version },
            crate::runtime::upgrade::DeferredUpgrade::new(move || {
                arms.fetch_add(1, Ordering::SeqCst);
            }),
        ))
    }
}

impl super::super::store::RuntimeStoreFaultInjector for BlockAcceptCommandBeforeCommit {
    fn before_operation(
        &self,
        operation: super::super::store::RuntimeStoreOperation,
    ) -> Result<(), RuntimeStoreError> {
        if operation == super::super::store::RuntimeStoreOperation::AcceptCommandBeforeCommit
            && !self.blocked.swap(true, Ordering::SeqCst)
        {
            self.entered.wait();
            self.release.wait();
        }
        Ok(())
    }
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

impl super::super::store::RuntimeStoreFaultInjector
    for BlockUpdateConversationMetadataBeforeCommit
{
    fn before_operation(
        &self,
        operation: super::super::store::RuntimeStoreOperation,
    ) -> Result<(), RuntimeStoreError> {
        if operation
            == super::super::store::RuntimeStoreOperation::UpdateConversationMetadataBeforeCommit
            && !self.blocked.swap(true, Ordering::SeqCst)
        {
            self.entered.send(()).map_err(|_| {
                RuntimeStoreError::InvalidConfig("metadata test entry receiver dropped")
            })?;
            self.release
                .lock()
                .map_err(|_| RuntimeStoreError::InvalidConfig("metadata test release poisoned"))?
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| RuntimeStoreError::InvalidConfig("metadata test release timed out"))?;
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

    fn database(&self) -> PathBuf {
        self.path.join("runtime.db")
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

#[derive(Debug, Eq, PartialEq)]
struct PromptAdmissionEvidence {
    command_rows: i64,
    pin_rows: i64,
    event_rows: i64,
    command_high_water: Option<String>,
    conversation_accepted_count: i64,
    conversation_metadata_token: Vec<u8>,
    ledger_command_count: i64,
    ledger_pin_count: i64,
    ledger_event_count: i64,
    ledger_accepted_count: i64,
    ledger_accepted_payload_bytes: i64,
    ledger_metadata_token: Vec<u8>,
    artifacts: (Vec<u8>, Option<Vec<u8>>),
}

fn prompt_admission_evidence(
    database: &Path,
    conversation_id: RuntimeId,
) -> PromptAdmissionEvidence {
    let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only prompt admission evidence database");
    let target = &conversation_id.as_bytes()[..];
    let command_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM commands WHERE conversation_id = ?1",
            [target],
            |row| row.get(0),
        )
        .expect("count prompt admission commands");
    let pin_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM command_configuration_pins WHERE conversation_id = ?1",
            [target],
            |row| row.get(0),
        )
        .expect("count prompt admission configuration pins");
    let event_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM event_journal WHERE conversation_id = ?1",
            [target],
            |row| row.get(0),
        )
        .expect("count prompt admission events");
    let (command_high_water, conversation_accepted_count, conversation_metadata_token) = connection
        .query_row(
            "SELECT command_high_water, accepted_count, metadata_token
                 FROM conversations WHERE conversation_id = ?1",
            [target],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read prompt admission conversation evidence");
    let (
        ledger_command_count,
        ledger_pin_count,
        ledger_event_count,
        ledger_accepted_count,
        ledger_accepted_payload_bytes,
        ledger_metadata_token,
    ) = connection
        .query_row(
            "SELECT command_count, command_configuration_pin_count, event_count,
                    accepted_count, accepted_payload_bytes, metadata_token
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("read prompt admission ledger evidence");
    drop(connection);
    let main = fs::read(database).expect("read prompt admission main bytes");
    let wal_path = PathBuf::from(format!("{}-wal", database.display()));
    let wal = fs::read(wal_path).ok();
    PromptAdmissionEvidence {
        command_rows,
        pin_rows,
        event_rows,
        command_high_water,
        conversation_accepted_count,
        conversation_metadata_token,
        ledger_command_count,
        ledger_pin_count,
        ledger_event_count,
        ledger_accepted_count,
        ledger_accepted_payload_bytes,
        ledger_metadata_token,
        artifacts: (main, wal),
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
        RuntimeCore::new(store, router, [0xA1; 32]).expect("construct RuntimeCore test fixture"),
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

fn claude_code_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .expect("valid Claude Code native projection configuration"),
    ))
}

fn start_receipt(reply: RuntimeReply) -> ConversationStartReceipt {
    match reply {
        RuntimeReply::ConversationStart(receipt) => receipt,
        other => panic!("expected conversation start receipt, got {other:?}"),
    }
}

async fn configure_codex_revision_one(
    core: &RuntimeCore,
    connection: ConnectionId,
    conversation_id: ConversationId,
    key: &str,
) {
    let reply = core
        .handle(
            connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                conversation_id.clone(),
                IdempotencyKey::new(key),
                0,
                codex_configuration(CodexReasoningEffort::Medium),
            )),
        )
        .await;
    assert!(matches!(
        reply,
        RuntimeReply::Configuration(ConfigurationReceipt::Applied {
            conversation_id: configured,
            configuration_revision: 1,
        }) if configured == conversation_id
    ));
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

fn connect_local_control_with_sink(
    core: &RuntimeCore,
    seed: u8,
) -> (
    ConnectionId,
    mpsc::Receiver<crate::runtime::ConnectionWrite>,
) {
    let principal = core
        .issue_verified_local_control_principal(501, [seed; 16])
        .expect("issue local control principal");
    let (sink, receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect local control");
    (connection, receiver)
}

fn stage_upgrade_envelope(key: &str, message: &str) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message),
        body: RuntimeMessage::Request(RuntimeRequest::StageUpgrade(
            StageUpgradeRequest::new(
                "1.2.3".to_owned(),
                ArtifactSha256::new("ab".repeat(32)).expect("artifact hash"),
                IdempotencyKey::new(key),
                LocalOnlyAdministration::LocalOnly,
            )
            .expect("stage request"),
        )),
    }
}

fn artifact_hash(bytes: &[u8]) -> ArtifactSha256 {
    ArtifactSha256::new(
        <[u8; 32]>::from(Sha256::digest(bytes))
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .expect("canonical artifact hash")
}

fn versioned_upgrade_fixture(
    root: &TestRoot,
    version: &str,
    key: &str,
) -> (PathBuf, StageUpgradeRequest) {
    let bin_root = root.path.join("bin");
    let version_root = bin_root.join(version);
    fs::create_dir_all(&version_root).expect("create versioned upgrade fixture");
    fs::set_permissions(&bin_root, fs::Permissions::from_mode(0o700))
        .expect("secure upgrade bin root");
    fs::set_permissions(&version_root, fs::Permissions::from_mode(0o700))
        .expect("secure upgrade version root");
    let candidate = b"crash-recoverable daemon candidate";
    let daemon = version_root.join("agentdeckd");
    fs::write(&daemon, candidate).expect("write upgrade candidate");
    fs::set_permissions(&daemon, fs::Permissions::from_mode(0o500))
        .expect("secure upgrade candidate");
    let current = bin_root.join("current");
    if fs::symlink_metadata(&current).is_err() {
        symlink("old", current).expect("seed old current link");
    }
    let request = StageUpgradeRequest::new(
        version.to_owned(),
        artifact_hash(candidate),
        IdempotencyKey::new(key),
        LocalOnlyAdministration::LocalOnly,
    )
    .expect("valid crash recovery upgrade request");
    (bin_root, request)
}

async fn versioned_upgrade_core(
    root: &TestRoot,
    bin_root: &Path,
    trust_seed: u8,
) -> (Arc<RuntimeCore>, mpsc::UnboundedReceiver<()>) {
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let (exit, receiver) = mpsc::unbounded_channel();
    let core = Arc::new(
        RuntimeCore::new(store, router, [trust_seed; 32])
            .expect("construct crash recovery upgrade Core")
            .with_versioned_daemon_upgrade(bin_root.to_path_buf(), exit)
            .expect("install crash recovery upgrade service"),
    );
    core.recover()
        .await
        .expect("recover crash recovery upgrade Core");
    (core, receiver)
}

async fn begin_stage_upgrade(
    core: &Arc<RuntimeCore>,
    request: StageUpgradeRequest,
    principal_seed: u8,
    message_id: &str,
) -> (
    crate::runtime::ConnectionWrite,
    tokio::task::JoinHandle<Result<(), RuntimeFailure>>,
) {
    let (connection, mut writes) = connect_local_control_with_sink(core, principal_seed);
    let message_id = MessageId::new(message_id.to_owned());
    let handling = {
        let core = core.clone();
        tokio::spawn(async move {
            core.handle_envelope(
                connection,
                RuntimeEnvelope {
                    version: RUNTIME_PROTOCOL_VERSION,
                    message_id,
                    body: RuntimeMessage::Request(RuntimeRequest::StageUpgrade(request)),
                },
            )
            .await
        })
    };
    let write = tokio::time::timeout(std::time::Duration::from_secs(2), writes.recv())
        .await
        .expect("StageUpgrade reply deadline")
        .expect("StageUpgrade reply write");
    (write, handling)
}

async fn assert_upgrade_conflict(
    core: &Arc<RuntimeCore>,
    request: &StageUpgradeRequest,
    principal_seed: u8,
    message_id: &str,
) {
    let conflict = StageUpgradeRequest::new(
        "9.9.9-conflict".to_owned(),
        ArtifactSha256::new("cd".repeat(32)).expect("conflicting hash"),
        request.idempotency_key().clone(),
        LocalOnlyAdministration::LocalOnly,
    )
    .expect("valid conflicting upgrade request");
    let (write, handling) = begin_stage_upgrade(core, conflict, principal_seed, message_id).await;
    let reply: RuntimeEnvelope =
        serde_json::from_slice(write.bytes()).expect("decode conflict reply");
    assert!(matches!(
        reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Failed {
            failure: RuntimeFailure { ref code, .. },
        })) if code == "daemon.command.idempotency_conflict"
    ));
    write.acknowledge().expect("ACK conflict reply");
    handling
        .await
        .expect("join conflict handler")
        .expect("flush conflict reply");
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
    drop(
        control
            .try_enter_local_administration()
            .expect("local-control administration capability"),
    );
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
    assert!(matches!(
        read_only.try_enter_local_administration(),
        Err(crate::runtime::connection::PrincipalAccessError::PermissionDenied)
    ));
    assert!(
        core.issue_verified_local_control_principal(501, [0x22; 16])
            .is_err(),
        "a read-only lease cannot be upgraded to local-control"
    );
    core.shutdown().await.expect("shutdown cold core");
}

fn dormant_machine_administration_requests() -> Vec<RuntimeRequest> {
    let bundle: EnrollmentBundleV2 = serde_json::from_value(serde_json::json!({
        "version": 2,
        "publicWssUrl": "wss://relay.example.test/",
        "relayServerId": "IiIiIiIiIiIiIiIiIiIiIg==",
        "receiptVerifyKey": {
            "receiptFormatVersion": 1,
            "relayServerId": "IiIiIiIiIiIiIiIiIiIiIg==",
            "keyGeneration": 1,
            "keyId": "9uiDt7VE9fLhOJ4F1EvvLCH5R+HGrCJpMfGxejtfq3M=",
            "publicKey": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
        },
        "code": "REREREREREREREREREREREREREREREREREREREREREQ=",
        "spkiPins": ["-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"],
        "expiresAtMs": 1_700_000_000_000u64
    }))
    .expect("valid enrollment bundle");
    vec![
        RuntimeRequest::CreatePairInvite(
            agentdeck_protocol::runtime::command::CreatePairInviteRequest {
                display_name: "fixture machine".to_owned(),
                idempotency_key: IdempotencyKey::new("pair-invite-dormant-1"),
                scope: LocalOnlyAdministration::LocalOnly,
            },
        ),
        RuntimeRequest::ListPendingPairings {
            scope: LocalOnlyAdministration::LocalOnly,
        },
        RuntimeRequest::ConfirmPairing {
            pairing_id: agentdeck_protocol::runtime::identity::PairingId::new(
                "11111111-1111-1111-1111-111111111111",
            ),
            scope: LocalOnlyAdministration::LocalOnly,
        },
        RuntimeRequest::CancelPairing {
            pairing_id: agentdeck_protocol::runtime::identity::PairingId::new(
                "11111111-1111-1111-1111-111111111111",
            ),
            scope: LocalOnlyAdministration::LocalOnly,
        },
        RuntimeRequest::MachineEnroll(MachineEnrollRequest {
            bundle,
            scope: LocalOnlyAdministration::LocalOnly,
        }),
        RuntimeRequest::MachineRemoteStatus {
            scope: LocalOnlyAdministration::LocalOnly,
        },
        RuntimeRequest::TrustReset(
            TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                .expect("valid trust reset"),
        ),
        RuntimeRequest::Revoke(RevokeRequest {
            target: RevokeTarget::Device {
                device: DeviceHandle::new("device-1"),
                grant_serial: GrantSerial::new(7),
                scope: LocalOnlyAdministration::LocalOnly,
            },
        }),
    ]
}

#[tokio::test]
async fn dormant_machine_administration_requires_local_control_before_feature_gate() {
    let root = TestRoot::new("dormant-machine-admin-gate");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let remote_administration = Arc::new(CountingRemoteAdministration::default());
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32])
            .expect("construct RuntimeCore")
            .with_remote_administration(remote_administration.clone()),
    );
    core.recover().await.expect("recover");

    let read_only = connect_local(&core, 0x41).await;
    let (local_control, _control_writes) = connect_local_control_with_sink(&core, 0x42);
    let remote = core
        .principal_issuer
        .issue_test_remote([0x51; 16], [0x52; 16], 1, [0x53; 32])
        .expect("issue remote principal");
    let (remote_sink, _remote_writes) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    let remote = core
        .connect(remote, ConnectionSink::new(remote_sink))
        .expect("connect remote principal");

    for request in dormant_machine_administration_requests() {
        let is_remote_administration = matches!(
            &request,
            RuntimeRequest::MachineEnroll(_)
                | RuntimeRequest::MachineRemoteStatus { .. }
                | RuntimeRequest::TrustReset(_)
        );
        let is_pairing_administration = matches!(
            &request,
            RuntimeRequest::CreatePairInvite(_)
                | RuntimeRequest::ListPendingPairings { .. }
                | RuntimeRequest::ConfirmPairing { .. }
                | RuntimeRequest::CancelPairing { .. }
        );
        let is_revocation_administration = matches!(
            &request,
            RuntimeRequest::Revoke(RevokeRequest {
                target: RevokeTarget::Device { .. }
            })
        );
        for connection in [read_only, remote] {
            let calls = remote_administration.calls.load(Ordering::SeqCst);
            let reply = core.handle(connection, request.clone()).await;
            assert!(matches!(
                reply,
                RuntimeReply::Failure(RuntimeFailure { ref code, .. })
                    if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
            ));
            assert_eq!(
                remote_administration.calls.load(Ordering::SeqCst),
                calls,
                "permission rejection must happen before remote service"
            );
        }
        let reply = core.handle(local_control, request).await;
        if is_remote_administration {
            assert!(matches!(reply, RuntimeReply::MachineRemoteStatus(_)));
        } else if is_pairing_administration {
            assert!(matches!(
                reply,
                RuntimeReply::Failure(RuntimeFailure { ref code, .. })
                    if code == "daemon.pairing.administration.unavailable"
            ));
        } else if is_revocation_administration {
            assert!(matches!(
                reply,
                RuntimeReply::Failure(RuntimeFailure { ref code, .. })
                    if code == "daemon.revocation.administration.unavailable"
            ));
        } else {
            assert!(matches!(
                reply,
                RuntimeReply::Failure(RuntimeFailure { ref code, .. })
                    if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
            ));
        }
    }

    let self_revoke = RuntimeRequest::Revoke(RevokeRequest {
        target: RevokeTarget::SelfDevice,
    });
    for connection in [read_only, remote, local_control] {
        let reply = core.handle(connection, self_revoke.clone()).await;
        assert!(matches!(
            reply,
            RuntimeReply::Failure(RuntimeFailure { ref code, .. })
                if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
        ));
    }

    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn pairing_administration_is_local_control_only_and_binds_create_owner() {
    let root = TestRoot::new("pairing-admin-local-control");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let pairing = Arc::new(CountingPairingAdministration::default());
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA2; 32])
            .expect("construct RuntimeCore")
            .with_pairing_administration(pairing.clone()),
    );
    core.recover().await.expect("recover");

    let read_only = connect_local(&core, 0x61).await;
    let (local_control, _control_writes) = connect_local_control_with_sink(&core, 0x62);
    let remote = core
        .principal_issuer
        .issue_test_remote([0x63; 16], [0x64; 16], 1, [0x65; 32])
        .expect("issue remote principal");
    let (remote_sink, _remote_writes) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    let remote = core
        .connect(remote, ConnectionSink::new(remote_sink))
        .expect("connect remote principal");

    for request in dormant_machine_administration_requests()
        .into_iter()
        .filter(|request| {
            matches!(
                request,
                RuntimeRequest::CreatePairInvite(_)
                    | RuntimeRequest::ListPendingPairings { .. }
                    | RuntimeRequest::ConfirmPairing { .. }
                    | RuntimeRequest::CancelPairing { .. }
            )
        })
    {
        for connection in [read_only, remote] {
            let before = pairing.calls.load(Ordering::SeqCst);
            assert!(matches!(
                core.handle(connection, request.clone()).await,
                RuntimeReply::Failure(RuntimeFailure { ref code, .. })
                    if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
            ));
            assert_eq!(pairing.calls.load(Ordering::SeqCst), before);
        }
        let before = pairing.calls.load(Ordering::SeqCst);
        let reply = core.handle(local_control, request).await;
        assert!(matches!(reply, RuntimeReply::Failure(_)));
        assert_eq!(pairing.calls.load(Ordering::SeqCst), before + 1);
    }

    assert_eq!(
        pairing
            .create_owner
            .lock()
            .expect("lock pairing owner")
            .as_ref(),
        Some(&crate::runtime::store::IdempotencyOwner::Local {
            machine_trust_domain: [0xA2; 32],
            uid: 501,
            client_installation_id: [0x62; 16],
        })
    );
    let before = pairing.calls.load(Ordering::SeqCst);
    assert!(matches!(
        core.handle(
            local_control,
            RuntimeRequest::ConfirmPairing {
                pairing_id: PairingId::new("not-a-canonical-pairing-id"),
                scope: LocalOnlyAdministration::LocalOnly,
            },
        )
        .await,
        RuntimeReply::Failure(RuntimeFailure { ref code, .. })
            if code == DAEMON_RUNTIME_INVALID_REQUEST
    ));
    assert_eq!(pairing.calls.load(Ordering::SeqCst), before);
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn revocation_administration_is_local_control_only_and_receives_exact_target() {
    let root = TestRoot::new("revocation-admin-local-control");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let revocation = Arc::new(CountingRevocationAdministration::succeeding());
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xB1; 32])
            .expect("construct RuntimeCore")
            .with_revocation_administration(revocation.clone()),
    );
    core.recover().await.expect("recover");

    let read_only = connect_local(&core, 0x81).await;
    let (local_control, _control_writes) = connect_local_control_with_sink(&core, 0x82);
    let remote_principal = core
        .principal_issuer
        .issue_test_remote([0x83; 16], [0x84; 16], 9, [0x85; 32])
        .expect("issue remote principal");
    let (remote_sink, _remote_writes) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    let remote = core
        .connect(remote_principal, ConnectionSink::new(remote_sink))
        .expect("connect remote principal");
    let device = DeviceHandle::new("device-handle-exact-01");
    let grant_serial = GrantSerial::new(42);
    let request = RuntimeRequest::Revoke(RevokeRequest {
        target: RevokeTarget::Device {
            device: device.clone(),
            grant_serial,
            scope: LocalOnlyAdministration::LocalOnly,
        },
    });

    for connection in [read_only, remote] {
        assert!(matches!(
            core.handle(connection, request.clone()).await,
            RuntimeReply::Failure(RuntimeFailure { ref code, .. })
                if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
        ));
        assert_eq!(
            revocation.calls.load(Ordering::SeqCst),
            0,
            "authorization rejection must happen before revocation backend"
        );
    }
    assert!(matches!(
        core.handle(local_control, request).await,
        RuntimeReply::Revocation(RevocationReceipt::Committed {
            grant_serial: observed
        }) if observed == grant_serial
    ));
    assert_eq!(revocation.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        revocation
            .observed
            .lock()
            .expect("lock observed revocation targets")
            .as_slice(),
        &[(device, grant_serial)]
    );
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn revocation_backend_failure_maps_stable_bounded_code() {
    let root = TestRoot::new("revocation-admin-failure");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let revocation = Arc::new(CountingRevocationAdministration::failing(
        "daemon.revocation.test_backend",
    ));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xB2; 32])
            .expect("construct RuntimeCore")
            .with_revocation_administration(revocation.clone()),
    );
    core.recover().await.expect("recover");
    let (local_control, _control_writes) = connect_local_control_with_sink(&core, 0x86);
    let reply = core
        .handle(
            local_control,
            RuntimeRequest::Revoke(RevokeRequest {
                target: RevokeTarget::Device {
                    device: DeviceHandle::new("device-failure-01"),
                    grant_serial: GrantSerial::new(43),
                    scope: LocalOnlyAdministration::LocalOnly,
                },
            }),
        )
        .await;
    assert!(matches!(
        reply,
        RuntimeReply::Failure(RuntimeFailure { ref code, .. })
            if code == "daemon.revocation.test_backend"
    ));
    assert_eq!(revocation.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        RevocationAdministrationError::new("INVALID CODE").code(),
        "daemon.revocation.administration.unavailable"
    );
    assert_eq!(
        RevocationAdministrationError::new("x".repeat(129)).code(),
        "daemon.revocation.administration.unavailable"
    );
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn disabled_revocation_administration_fails_closed_for_local_control() {
    let root = TestRoot::new("revocation-admin-disabled");
    let core = core(&root).await;
    core.recover().await.expect("recover");
    let (local_control, _control_writes) = connect_local_control_with_sink(&core, 0x87);
    assert!(matches!(
        core.handle(
            local_control,
            RuntimeRequest::Revoke(RevokeRequest {
                target: RevokeTarget::Device {
                    device: DeviceHandle::new("device-disabled-01"),
                    grant_serial: GrantSerial::new(44),
                    scope: LocalOnlyAdministration::LocalOnly,
                },
            }),
        )
        .await,
        RuntimeReply::Failure(RuntimeFailure { ref code, .. })
            if code == "daemon.revocation.administration.unavailable"
    ));
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn revocation_self_device_remains_feature_unavailable_without_backend_call() {
    let root = TestRoot::new("revocation-self-device-gated");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let revocation = Arc::new(CountingRevocationAdministration::succeeding());
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xB3; 32])
            .expect("construct RuntimeCore")
            .with_revocation_administration(revocation.clone()),
    );
    core.recover().await.expect("recover");
    let read_only = connect_local(&core, 0x88).await;
    let (local_control, _control_writes) = connect_local_control_with_sink(&core, 0x89);
    let remote_principal = core
        .principal_issuer
        .issue_test_remote([0x8a; 16], [0x8b; 16], 10, [0x8c; 32])
        .expect("issue remote principal");
    let (remote_sink, _remote_writes) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    let remote = core
        .connect(remote_principal, ConnectionSink::new(remote_sink))
        .expect("connect remote principal");
    let request = RuntimeRequest::Revoke(RevokeRequest {
        target: RevokeTarget::SelfDevice,
    });

    for connection in [read_only, remote, local_control] {
        assert!(matches!(
            core.handle(connection, request.clone()).await,
            RuntimeReply::Failure(RuntimeFailure { ref code, .. })
                if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
        ));
    }
    assert_eq!(
        revocation.calls.load(Ordering::SeqCst),
        0,
        "SelfDevice must not enter the local revocation backend"
    );
    core.shutdown().await.expect("shutdown core");
}

#[test]
fn revocation_seam_has_no_pairing_access_or_relay_type_ingress() {
    let seam = include_str!("../revocation_administration.rs");
    let core = include_str!("../core.rs");
    for forbidden in ["PairingAccess", "relay_v2", "crate::remote"] {
        assert!(
            !seam.contains(forbidden),
            "revocation seam must not mention {forbidden}"
        );
    }
    assert!(
        !core.contains("PairingAccess"),
        "PairingAccess has no RuntimeCore/ConnectionId ingress and cannot call the backend"
    );
}

#[tokio::test]
async fn pairing_pending_sink_only_targets_current_local_control_connections() {
    let root = TestRoot::new("pairing-pending-local-control");
    let core = core(&root).await;
    core.recover().await.expect("recover");

    let read_only_principal = core
        .issue_verified_local_principal(501, [0x71; 16])
        .expect("issue read-only principal");
    let (read_only_sink, mut read_only_writes) =
        mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    core.connect(read_only_principal, ConnectionSink::new(read_only_sink))
        .expect("connect read-only principal");

    let (local_control, mut control_writes) = connect_local_control_with_sink(&core, 0x72);
    let remote_principal = core
        .principal_issuer
        .issue_test_remote([0x73; 16], [0x74; 16], 1, [0x75; 32])
        .expect("issue remote principal");
    let (remote_sink, mut remote_writes) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
    core.connect(remote_principal, ConnectionSink::new(remote_sink))
        .expect("connect remote principal");

    let pending = PendingPairing {
        pairing_id: PairingId::new("76767676-7676-7676-7676-767676767676"),
        request_hash: [0x77; 32],
        device_sign_fingerprint: [0x78; 32],
        requested_at_ms: 100,
        expires_at_ms: 200,
    };
    let sink = core.pairing_pending_sink();
    assert_eq!(sink.publish(pending.clone()).expect("publish pending"), 1);
    let write = tokio::time::timeout(std::time::Duration::from_secs(1), control_writes.recv())
        .await
        .expect("local control write deadline")
        .expect("local control stream write");
    let envelope: RuntimeEnvelope =
        serde_json::from_slice(write.bytes()).expect("decode pending envelope");
    assert!(matches!(
        envelope.body,
        RuntimeMessage::Stream(RuntimeStreamItem::PairingPending(value)) if value == pending
    ));
    write.acknowledge().expect("ack pending write");
    assert!(matches!(
        read_only_writes.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        remote_writes.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    core.disconnect(local_control).await;
    assert_eq!(sink.publish(pending).expect("publish without control"), 0);
    core.shutdown().await.expect("shutdown core");
}

fn synthetic_runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("synthetic runtime id")
}

fn synthetic_wire_id(kind: RuntimeIdKind, seed: u8) -> String {
    synthetic_runtime_id(kind, seed).to_canonical_string()
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
async fn runtime_v2_describe_configure_and_metadata_cut_over_without_enabling_upgrade() {
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
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
            ref conversation_id,
            entry_revision: 1,
        }) if conversation_id == &conversation.conversation_id
    ));
    let prompt = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: conversation.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new("v2-prompt-stale-configuration"),
                expected_configuration_revision: 0,
                prompt: PromptPayload::new("must reject before entering the real gate").unwrap(),
            }),
        )
        .await;
    assert!(
        matches!(
            &prompt,
            RuntimeReply::Command(CommandReceipt::Failed {
                failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_CONVERSATION_CONFIGURATION_CONFLICT
        ),
        "stale configured prompt must stay in CommandReceipt and map to configuration_conflict, got {prompt:?}"
    );
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
        }) if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
    ));
    let (control_connection, _control_writes) = connect_local_control_with_sink(&core, 0x73);
    let direct_control_stage = core
        .handle(
            control_connection,
            RuntimeRequest::StageUpgrade(
                StageUpgradeRequest::new(
                    "1.2.3".into(),
                    ArtifactSha256::new("ab".repeat(32)).unwrap(),
                    IdempotencyKey::new("v2-direct-control-stage"),
                    LocalOnlyAdministration::LocalOnly,
                )
                .unwrap(),
            ),
        )
        .await;
    assert!(matches!(
        direct_control_stage,
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
async fn metadata_update_returns_applied_replayed_conflict_and_typed_failures() {
    // 威胁场景：若 metadata mutation 脱离 ConversationMetadataReceipt family，
    // Companion 会丢失 CAS/idempotency 语义，并可能把业务拒绝误当成 envelope failure。
    let root = TestRoot::new("metadata-receipts");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(RuntimeCore::new(store, router, [0xA5; 32]).expect("construct core"));
    core.recover().await.expect("recover metadata receipt core");
    let connection = connect_local(&core, 0x76).await;
    let conversation = start_receipt(
        core.handle(connection, start_request("metadata-receipts-start"))
            .await,
    );

    let exact_request = ConversationMetadataMutationRequest::new(
        conversation.conversation_id.clone(),
        IdempotencyKey::new("metadata-exact"),
        0,
        ConversationMetadataMutation::rename(Some("metadata renamed".to_owned()))
            .expect("bounded metadata title"),
    )
    .expect("valid metadata request");
    assert!(matches!(
        core.handle(
            connection,
            RuntimeRequest::UpdateConversationMetadata(exact_request.clone())
        )
        .await,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
            ref conversation_id,
            entry_revision: 1,
        }) if conversation_id == &conversation.conversation_id
    ));
    assert!(matches!(
        core.handle(
            connection,
            RuntimeRequest::UpdateConversationMetadata(exact_request)
        )
        .await,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Replayed {
            ref conversation_id,
            entry_revision: 1,
        }) if conversation_id == &conversation.conversation_id
    ));

    let same_key_different_request = core
        .handle(
            connection,
            RuntimeRequest::UpdateConversationMetadata(
                ConversationMetadataMutationRequest::new(
                    conversation.conversation_id.clone(),
                    IdempotencyKey::new("metadata-exact"),
                    0,
                    ConversationMetadataMutation::SetArchived { archived: true },
                )
                .expect("valid different metadata request"),
            ),
        )
        .await;
    assert!(matches!(
        same_key_different_request,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == "daemon.command.idempotency_conflict"
    ));

    let stale = core
        .handle(
            connection,
            RuntimeRequest::UpdateConversationMetadata(
                ConversationMetadataMutationRequest::new(
                    conversation.conversation_id.clone(),
                    IdempotencyKey::new("metadata-stale"),
                    0,
                    ConversationMetadataMutation::SetArchived { archived: true },
                )
                .expect("valid stale metadata request"),
            ),
        )
        .await;
    assert!(matches!(
        stale,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Conflict {
            ref conversation_id,
            current_entry_revision: 1,
        }) if conversation_id == &conversation.conversation_id
    ));

    let missing_id = ConversationId::new("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    let missing = core
        .handle(
            connection,
            RuntimeRequest::UpdateConversationMetadata(
                ConversationMetadataMutationRequest::new(
                    missing_id,
                    IdempotencyKey::new("metadata-missing"),
                    0,
                    ConversationMetadataMutation::SetArchived { archived: true },
                )
                .expect("valid missing metadata request"),
            ),
        )
        .await;
    assert!(matches!(
        missing,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == agentdeck_protocol::runtime::failure::DAEMON_CONVERSATION_NOT_FOUND
    ));

    let malformed = core
        .handle(
            connection,
            RuntimeRequest::UpdateConversationMetadata(
                ConversationMetadataMutationRequest::new(
                    ConversationId::new("not-a-canonical-runtime-id"),
                    IdempotencyKey::new("metadata-malformed"),
                    0,
                    ConversationMetadataMutation::SetArchived { archived: true },
                )
                .expect("wire-valid malformed-id request"),
            ),
        )
        .await;
    assert!(matches!(
        malformed,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_INVALID_REQUEST
    ));

    core.shutdown()
        .await
        .expect("shutdown metadata receipt core");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_authorization_guard_covers_store_commit_and_reply() {
    // 威胁场景：若 metadata Update 在把请求交给 Store 后提前释放 guard，issuer
    // revoke 可在 COMMIT 前完成；已经通过授权线性化点的请求随后会错误地失去稳定结果。
    let root = TestRoot::new("metadata-authorization-commit");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let store = RuntimeStoreHandle::open(
        super::super::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_fault_injector(Arc::new(BlockUpdateConversationMetadataBeforeCommit {
                entered: entered_tx,
                release: std::sync::Mutex::new(release_rx),
                blocked: AtomicBool::new(false),
            })),
        root.kek(),
    )
    .await
    .expect("open metadata authorization store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core =
        Arc::new(RuntimeCore::new(store, router, [0xA8; 32]).expect("construct metadata core"));
    core.recover()
        .await
        .expect("recover metadata authorization core");
    let principal = core
        .issue_verified_local_principal(501, [0x79; 16])
        .expect("issue metadata authorization principal");
    let owner = principal.idempotency_owner();
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    let connection = core
        .connect(principal.clone(), ConnectionSink::new(sink))
        .expect("connect metadata authorization principal");
    let conversation = start_receipt(
        core.handle(connection, start_request("metadata-authorization-start"))
            .await,
    );
    let internal_conversation = parse_conversation_id(&conversation.conversation_id)
        .expect("parse metadata authorization conversation");
    let idempotency_key = "metadata-authorization";
    let mutation = ConversationMetadataMutation::SetArchived { archived: true };

    let handling = tokio::spawn({
        let core = core.clone();
        let conversation_id = conversation.conversation_id.clone();
        let mutation = mutation.clone();
        async move {
            core.handle(
                connection,
                RuntimeRequest::UpdateConversationMetadata(
                    ConversationMetadataMutationRequest::new(
                        conversation_id,
                        IdempotencyKey::new(idempotency_key),
                        0,
                        mutation,
                    )
                    .expect("valid authorized metadata request"),
                ),
            )
            .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(std::time::Duration::from_secs(5)))
        .await
        .expect("join metadata Update before-COMMIT observer")
        .expect("observe metadata Update before COMMIT");
    let revoking = tokio::spawn({
        let principal = principal.clone();
        async move { principal.begin_revoke().await }
    });
    wait_until_principal_revoking(&principal).await;
    assert!(
        !revoking.is_finished(),
        "revoke must remain blocked after entering Revoking and before Store COMMIT"
    );
    release_tx
        .send(())
        .expect("release metadata Update before COMMIT");
    let revoke_result = tokio::time::timeout(std::time::Duration::from_secs(5), revoking)
        .await
        .expect("metadata principal revoke must finish after Store COMMIT");
    assert!(matches!(
        handling.await.expect("join metadata Update request"),
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
            entry_revision: 1,
            ..
        })
    ));
    revoke_result
        .expect("join metadata principal revoke")
        .expect("revoke after metadata Store reply");
    let replay = core
        .store
        .update_managed_conversation_metadata(UpdateManagedConversationMetadata {
            conversation_id: internal_conversation,
            owner,
            idempotency_key: idempotency_key.to_owned(),
            expected_entry_revision: 0,
            mutation,
        })
        .await
        .expect("replay committed metadata outcome");
    assert!(matches!(
        replay,
        UpdateConversationMetadataOutcome::Replayed { mutation }
            if mutation.conversation_id == internal_conversation && mutation.entry_revision == 1
    ));
    principal.finish_revoke();
    core.shutdown()
        .await
        .expect("shutdown metadata authorization core");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_metadata_caller_keeps_authorization_until_store_completion() {
    // 威胁场景：caller future 被取消后，已入 Store 队列的 metadata Update 仍必须持有
    // guard；否则 revoke 会越过 durable outcome/notify/reply，留下无法稳定重放的半完成观察。
    let root = TestRoot::new("metadata-caller-canceled");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let store = RuntimeStoreHandle::open(
        super::super::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_fault_injector(Arc::new(BlockUpdateConversationMetadataBeforeCommit {
                entered: entered_tx,
                release: std::sync::Mutex::new(release_rx),
                blocked: AtomicBool::new(false),
            })),
        root.kek(),
    )
    .await
    .expect("open canceled metadata store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core =
        Arc::new(RuntimeCore::new(store, router, [0xA9; 32]).expect("construct metadata core"));
    core.recover()
        .await
        .expect("recover canceled metadata core");
    let principal = core
        .issue_verified_local_principal(501, [0x7A; 16])
        .expect("issue canceled metadata principal");
    let owner = principal.idempotency_owner();
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    let connection = core
        .connect(principal.clone(), ConnectionSink::new(sink))
        .expect("connect canceled metadata principal");
    let conversation = start_receipt(
        core.handle(connection, start_request("metadata-canceled-start"))
            .await,
    );
    let internal_conversation = parse_conversation_id(&conversation.conversation_id)
        .expect("parse canceled metadata conversation");
    let idempotency_key = "metadata-canceled";
    let mutation = ConversationMetadataMutation::rename(Some("committed after cancel".to_owned()))
        .expect("bounded canceled metadata title");

    let handling = tokio::spawn({
        let core = core.clone();
        let conversation_id = conversation.conversation_id.clone();
        let mutation = mutation.clone();
        async move {
            core.handle(
                connection,
                RuntimeRequest::UpdateConversationMetadata(
                    ConversationMetadataMutationRequest::new(
                        conversation_id,
                        IdempotencyKey::new(idempotency_key),
                        0,
                        mutation,
                    )
                    .expect("valid canceled metadata request"),
                ),
            )
            .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(std::time::Duration::from_secs(5)))
        .await
        .expect("join canceled metadata Update before-COMMIT observer")
        .expect("observe canceled metadata Update before COMMIT");
    handling.abort();
    assert!(
        handling
            .await
            .expect_err("metadata caller must be canceled")
            .is_cancelled(),
        "aborted metadata caller reports cancellation"
    );
    let revoking = tokio::spawn({
        let principal = principal.clone();
        async move { principal.begin_revoke().await }
    });
    wait_until_principal_revoking(&principal).await;
    assert!(
        !revoking.is_finished(),
        "revoke must remain blocked after caller cancellation and before Store COMMIT"
    );
    release_tx
        .send(())
        .expect("release canceled metadata Update before COMMIT");
    let revoke_result = tokio::time::timeout(std::time::Duration::from_secs(5), revoking)
        .await
        .expect("canceled metadata revoke must finish after Store COMMIT");
    revoke_result
        .expect("join canceled metadata revoke")
        .expect("revoke after detached metadata Store completion");
    let replay = core
        .store
        .update_managed_conversation_metadata(UpdateManagedConversationMetadata {
            conversation_id: internal_conversation,
            owner,
            idempotency_key: idempotency_key.to_owned(),
            expected_entry_revision: 0,
            mutation,
        })
        .await
        .expect("replay metadata committed after caller cancellation");
    assert!(matches!(
        replay,
        UpdateConversationMetadataOutcome::Replayed { mutation }
            if mutation.conversation_id == internal_conversation && mutation.entry_revision == 1
    ));
    principal.finish_revoke();
    core.shutdown()
        .await
        .expect("shutdown canceled metadata core");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_native_metadata_caller_keeps_actor_owned_operation_until_terminal_reply() {
    // 威胁场景：native mutation 已在 actor control lane 取得 durable-claim/release
    // 等价 barrier 后，transport task 被取消。若 coordinator future、authorization
    // 或 Core operation lease 仍归 caller 所有，revoke/shutdown 会越过尚未完成的
    // vendor/readback/Store terminal。这里用可控 operation 锁定 ownership，不 spawn vendor。
    let root = TestRoot::new("native-metadata-actor-owned-cancel");
    let store = root.open_store().await;
    let imported = store
        .claude_code_native_projection_store()
        .import(ImportNativeProjection {
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::ClaudeCode,
                title: Some("native actor-owned metadata".to_owned()),
                cwd: PathBuf::new(),
            },
            default_configuration: claude_code_configuration(),
            private_reference: SecretBytes::new(
                b"native-metadata-actor-owned-reference-v1".to_vec(),
            ),
            scan_generation: [0x7B; 16],
        })
        .await
        .expect("import actor-owned native metadata fixture");
    let conversation = match imported {
        ImportNativeProjectionOutcome::Imported { conversation, .. } => conversation,
        other => panic!("fresh native metadata fixture must import once, got {other:?}"),
    };
    let conversation_id = conversation.conversation_id;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xAA; 32])
            .expect("construct actor-owned native metadata core"),
    );
    core.recover()
        .await
        .expect("recover actor-owned native metadata core");
    assert!(
        core.conversations.contains(conversation_id).await,
        "recovery installs native projection actor"
    );
    let principal = core
        .issue_verified_local_principal(501, [0x7B; 16])
        .expect("issue native metadata principal");
    let authorization = principal
        .try_enter()
        .expect("enter native metadata authorization");
    let operation_guard = core
        .try_enter_operation()
        .expect("retain admitted native metadata operation");
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (terminal_tx, terminal_rx) = tokio::sync::oneshot::channel();
    let operation = async move {
        let _ = entered_tx.send(());
        let _ = release_rx.await;
        let _ = terminal_tx.send(());
        Ok(NativeMutationOutcome::Rejected(RuntimeFailure::new(
            "daemon.test.native_metadata_terminal",
            "test-only actor-owned terminal",
        )))
    };
    let caller = tokio::spawn({
        let conversations = core.conversations.clone();
        async move {
            conversations
                .update_native_metadata_operation_for_test(
                    conversation_id,
                    operation,
                    authorization,
                    operation_guard,
                )
                .await
        }
    });
    entered_rx
        .await
        .expect("actor reached native metadata claim/release barrier");
    caller.abort();
    assert!(
        caller
            .await
            .expect_err("transport caller must be canceled")
            .is_cancelled(),
        "caller cancellation occurs after actor owns the operation"
    );

    let revoking = tokio::spawn({
        let principal = principal.clone();
        async move { principal.begin_revoke().await }
    });
    wait_until_principal_revoking(&principal).await;
    assert!(
        !revoking.is_finished(),
        "actor-owned authorization blocks revoke after caller cancellation"
    );
    let shutdown = tokio::spawn({
        let core = core.clone();
        async move { core.shutdown().await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while core.lifecycle.load(Ordering::Acquire) != CORE_CLOSING {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown reaches operation-quiescence fence");
    assert!(
        !shutdown.is_finished(),
        "retained Core operation lease blocks shutdown before terminal reply"
    );

    release_tx
        .send(())
        .expect("release actor-owned native metadata barrier");
    terminal_rx
        .await
        .expect("actor-owned native metadata operation reaches terminal");
    revoking
        .await
        .expect("join native metadata revoke")
        .expect("revoke completes after terminal reply");
    principal.finish_revoke();
    shutdown
        .await
        .expect("join native metadata shutdown")
        .expect("shutdown waits for actor-owned terminal reply");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_closes_saturated_native_permit_waiter_before_operation_quiescence() {
    // 威胁场景：native metadata caller 已持有 Core operation/auth/会话 guard，
    // 但全局 adapter permit 被长 turn 占满。若 shutdown 先等 operation、后 close
    // semaphore，两者会永久互等。CLOSING 必须先拒绝这个尚未 claim 的 waiter；
    // 已经取得的 permit 本身仍保持有效，也不能被 shutdown 强制撤销。
    let root = TestRoot::new("native-metadata-saturated-shutdown");
    let store = root.open_store().await;
    let imported = store
        .claude_code_native_projection_store()
        .import(ImportNativeProjection {
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::ClaudeCode,
                title: Some("native saturated shutdown".to_owned()),
                cwd: PathBuf::new(),
            },
            default_configuration: claude_code_configuration(),
            private_reference: SecretBytes::new(
                b"native-metadata-saturated-shutdown-reference-v1".to_vec(),
            ),
            scan_generation: [0x7C; 16],
        })
        .await
        .expect("import saturated native metadata fixture");
    let conversation = match imported {
        ImportNativeProjectionOutcome::Imported { conversation, .. } => conversation,
        other => panic!("fresh saturated metadata fixture must import once, got {other:?}"),
    };
    let conversation_id = conversation.conversation_id;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::with_execution_coordinator(
            store,
            router,
            [0xAB; 32],
            Arc::new(DisabledExecutionCoordinator),
            1,
            false,
        )
        .expect("construct saturated native metadata core"),
    );
    core.recover()
        .await
        .expect("recover saturated native metadata core");
    let held_permit = core
        .conversations
        .acquire_native_adapter_permit()
        .await
        .expect("saturate the only adapter permit");
    let principal = core
        .issue_verified_local_principal(501, [0x7C; 16])
        .expect("issue saturated native metadata principal");
    let authorization = principal
        .try_enter()
        .expect("enter saturated native metadata authorization");
    let operation_guard = core
        .try_enter_operation()
        .expect("retain saturated native metadata operation");
    let operation_polls = Arc::new(AtomicUsize::new(0));
    let waiter = tokio::spawn({
        let conversations = core.conversations.clone();
        let operation_polls = operation_polls.clone();
        async move {
            conversations
                .update_native_metadata_operation_for_test(
                    conversation_id,
                    async move {
                        operation_polls.fetch_add(1, Ordering::AcqRel);
                        Ok(NativeMutationOutcome::Rejected(RuntimeFailure::new(
                            "daemon.test.unexpected_native_operation",
                            "saturated native operation must not be polled",
                        )))
                    },
                    authorization,
                    operation_guard,
                )
                .await
        }
    });

    // 反复探测同一 serialization guard，直到 waiter 已取得它并确实停在 permit。
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(10),
                core.conversations
                    .acquire_native_mutation_guard(conversation_id),
            )
            .await
            {
                Err(_) => break,
                Ok(Ok(guard)) => drop(guard),
                Ok(Err(error)) => panic!("probe native mutation guard failed: {error}"),
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("native metadata waiter must reach the saturated permit");
    assert!(!waiter.is_finished());
    assert_eq!(operation_polls.load(Ordering::Acquire), 0);

    let shutdown = tokio::spawn({
        let core = core.clone();
        async move { core.shutdown().await }
    });
    let waiter_error = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
        .await
        .expect("CLOSING must wake the native permit waiter")
        .expect("join saturated native permit waiter")
        .expect_err("closed admission must reject the unclaimed native operation");
    assert!(matches!(waiter_error, ConversationError::ActorUnavailable));
    tokio::time::timeout(std::time::Duration::from_secs(2), shutdown)
        .await
        .expect("shutdown must not wait for a closed permit waiter")
        .expect("join saturated native shutdown")
        .expect("shutdown saturated native metadata core");

    assert_eq!(
        operation_polls.load(Ordering::Acquire),
        0,
        "permit rejection must happen before claim/coordinator/vendor work"
    );
    assert_eq!(
        Connection::open(root.database())
            .expect("open saturated shutdown evidence")
            .query_row(
                "SELECT COUNT(*) FROM metadata_mutation_ledger WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| row.get::<_, i64>(0),
            )
            .expect("count saturated native metadata claims"),
        0,
        "unclaimed permit waiter must leave zero durable metadata rows"
    );
    drop(held_permit);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_send_prompt_caller_keeps_authorization_until_store_completion() {
    // 威胁场景：连接断开会取消 Core caller future；已经移交给 actor/Store 的
    // SendPrompt 必须继续持有 authorization guard，直到 Accept COMMIT 与队列注册完成。
    let root = TestRoot::new("send-prompt-caller-canceled");
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let blocker = Arc::new(BlockAcceptCommandBeforeCommit {
        entered: entered.clone(),
        release: release.clone(),
        blocked: AtomicBool::new(false),
    });
    let store = RuntimeStoreHandle::open(
        super::super::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_fault_injector(blocker.clone()),
        root.kek(),
    )
    .await
    .expect("open canceled SendPrompt store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(RuntimeCore::new(store, router, [0xA7; 32]).expect("construct core"));
    core.recover()
        .await
        .expect("recover canceled SendPrompt core");
    let principal = core
        .issue_verified_local_principal(501, [0x78; 16])
        .expect("issue canceled SendPrompt principal");
    let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
    tokio::spawn(async move {
        while let Some(write) = receiver.recv().await {
            let _ = write.acknowledge();
        }
    });
    let connection = core
        .connect(principal.clone(), ConnectionSink::new(sink))
        .expect("connect canceled SendPrompt principal");
    let conversation = start_receipt(
        core.handle(connection, start_request("send-prompt-canceled-start"))
            .await,
    );
    configure_codex_revision_one(
        &core,
        connection,
        conversation.conversation_id.clone(),
        "send-prompt-canceled-configuration",
    )
    .await;
    let internal_conversation =
        parse_conversation_id(&conversation.conversation_id).expect("parse started conversation");
    let idempotency_key = "send-prompt-canceled";

    let handling = tokio::spawn({
        let core = core.clone();
        let conversation_id = conversation.conversation_id;
        async move {
            core.handle(
                connection,
                RuntimeRequest::SendPrompt(SendPromptRequest {
                    conversation_id,
                    idempotency_key: IdempotencyKey::new(idempotency_key),
                    expected_configuration_revision: 1,
                    prompt: PromptPayload::new("commit after Core caller cancellation").unwrap(),
                }),
            )
            .await
        }
    });

    let reached_accept_barrier = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if blocker.blocked.load(Ordering::SeqCst) {
                break true;
            }
            if handling.is_finished() {
                break false;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("SendPrompt must either reach Accept before COMMIT or return a typed failure");
    if !reached_accept_barrier {
        let reply = handling.await.expect("join early SendPrompt reply");
        core.shutdown()
            .await
            .expect("shutdown early-return SendPrompt core");
        panic!("SendPrompt must reach Accept before COMMIT, got {reply:?}");
    }
    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .expect("observe canceled SendPrompt before COMMIT");

    handling.abort();
    let canceled_handling = handling.await;
    let mut revoking = tokio::spawn({
        let principal = principal.clone();
        async move { principal.begin_revoke().await }
    });
    let revoked_before_release =
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut revoking).await;

    // 从这里开始不做任何可能 panic 的断言，先无条件释放 Store worker。
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .expect("release canceled SendPrompt before COMMIT");
    let revoked_early = revoked_before_release.is_ok();
    let revoke_result = match revoked_before_release {
        Ok(result) => result,
        Err(_) => revoking.await,
    };
    let receipt = core
        .store
        .query_command_receipt(QueryCommandReceipt {
            expected_owner: principal.idempotency_owner(),
            selector: CommandReceiptSelector::Idempotency {
                conversation_id: internal_conversation,
                idempotency_key: idempotency_key.to_owned(),
            },
        })
        .await;
    principal.finish_revoke();
    core.shutdown()
        .await
        .expect("shutdown canceled SendPrompt core");

    assert!(
        canceled_handling
            .expect_err("SendPrompt caller must be canceled")
            .is_cancelled(),
        "aborted caller reports cancellation"
    );
    assert!(
        !revoked_early,
        "detached durable SendPrompt must retain authorization after caller cancellation"
    );
    revoke_result
        .expect("join canceled SendPrompt revoke")
        .expect("revoke after detached Store completion");
    let receipt = receipt.expect("read committed SendPrompt receipt after caller cancellation");
    assert_eq!(receipt.configuration_revision, 1);
    assert_eq!(receipt.state, CommandState::Accepted);
}

#[tokio::test]
async fn public_send_prompt_maps_configuration_preconditions_to_command_receipt_failures() {
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

    for expected_configuration_revision in [0, 1] {
        let reply = core
            .handle(
                connection,
                RuntimeRequest::SendPrompt(SendPromptRequest {
                    conversation_id: conversation.conversation_id.clone(),
                    idempotency_key: IdempotencyKey::new(format!(
                        "v2-unconfigured-prompt-{expected_configuration_revision}"
                    )),
                    expected_configuration_revision,
                    prompt: PromptPayload::new("configuration must be required").unwrap(),
                }),
            )
            .await;
        assert!(
            matches!(
                &reply,
                RuntimeReply::Command(CommandReceipt::Failed {
                    failure: RuntimeFailure { code, .. }
            }) if code == DAEMON_CONVERSATION_CONFIGURATION_REQUIRED
            ),
            "unconfigured prompt revision {expected_configuration_revision} must stay in CommandReceipt and map to configuration_required, got {reply:?}"
        );
    }

    configure_codex_revision_one(
        &core,
        connection,
        conversation.conversation_id.clone(),
        "v2-public-constructor-configuration",
    )
    .await;

    for expected_configuration_revision in [0, 2] {
        let reply = core
            .handle(
                connection,
                RuntimeRequest::SendPrompt(SendPromptRequest {
                    conversation_id: conversation.conversation_id.clone(),
                    idempotency_key: IdempotencyKey::new(format!(
                        "v2-conflicting-prompt-{expected_configuration_revision}"
                    )),
                    expected_configuration_revision,
                    prompt: PromptPayload::new("configuration revision must conflict").unwrap(),
                }),
            )
            .await;
        assert!(
            matches!(
                &reply,
                RuntimeReply::Command(CommandReceipt::Failed {
                    failure: RuntimeFailure { code, .. }
            }) if code == DAEMON_CONVERSATION_CONFIGURATION_CONFLICT
            ),
            "configured prompt revision {expected_configuration_revision} must stay in CommandReceipt and map to configuration_conflict, got {reply:?}"
        );
    }

    core.shutdown().await.expect("shutdown public core");
}

#[tokio::test]
async fn native_projected_send_prompt_is_feature_unavailable_without_side_effects_across_restart() {
    let root = TestRoot::new("native-send-prompt-admission");
    let store = root.open_store().await;
    let imported = store
        .claude_code_native_projection_store()
        .import(ImportNativeProjection {
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::ClaudeCode,
                title: Some("native history fixture".to_owned()),
                cwd: PathBuf::from("/tmp/agentdeck-native-send-prompt"),
            },
            default_configuration: claude_code_configuration(),
            private_reference: SecretBytes::new(
                b"native-send-prompt-private-reference-v1".to_vec(),
            ),
            scan_generation: [0x91; 16],
        })
        .await
        .expect("import native SendPrompt admission fixture");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("native SendPrompt admission fixture must import exactly once");
    };
    let native_wire_id = ConversationId::new(conversation.conversation_id.to_canonical_string());
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0x92; 32])
            .expect("construct native SendPrompt admission core"),
    );
    core.recover()
        .await
        .expect("recover native SendPrompt admission core");
    let connection = connect_local(&core, 0x92).await;
    let actor_baseline = core.actor_count().await;
    assert_eq!(
        actor_baseline, 1,
        "recovery must install the present native actor before testing Core admission"
    );
    let evidence_before = prompt_admission_evidence(&root.database(), conversation.conversation_id);

    let reply = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: native_wire_id.clone(),
                idempotency_key: IdempotencyKey::new("native-send-prompt-must-fail"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("native history cannot accept a durable prompt")
                    .expect("valid native rejection prompt"),
            }),
        )
        .await;
    assert!(matches!(
        reply,
        RuntimeReply::Command(CommandReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
    ));
    let exact_retry = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: native_wire_id.clone(),
                idempotency_key: IdempotencyKey::new("native-send-prompt-must-fail"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("native history cannot accept a durable prompt")
                    .expect("valid exact native rejection retry"),
            }),
        )
        .await;
    assert!(matches!(
        exact_retry,
        RuntimeReply::Command(CommandReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
    ));
    let receipt_lookup = core
        .handle(
            connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
                conversation_id: native_wire_id.clone(),
                idempotency_key: IdempotencyKey::new("native-send-prompt-must-fail"),
            }),
        )
        .await;
    assert!(matches!(
        receipt_lookup,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == DAEMON_COMMAND_NOT_FOUND
    ));
    assert_eq!(core.actor_count().await, actor_baseline);
    assert_eq!(
        prompt_admission_evidence(&root.database(), conversation.conversation_id),
        evidence_before,
        "Core rejection must not change command/pin/event/HWM/ledger/main+WAL"
    );
    core.shutdown()
        .await
        .expect("shutdown first native SendPrompt admission core");

    let reopened_store = root.open_store().await;
    let reopened_router = Arc::new(AgentRouter::with_runtime_store(reopened_store.clone()));
    let reopened_core = Arc::new(
        RuntimeCore::new(reopened_store, reopened_router, [0x93; 32])
            .expect("construct reopened native SendPrompt admission core"),
    );
    reopened_core
        .recover()
        .await
        .expect("recover reopened native SendPrompt admission core");
    let reopened_connection = connect_local(&reopened_core, 0x93).await;
    let reopened_actor_baseline = reopened_core.actor_count().await;
    assert_eq!(
        reopened_actor_baseline, 1,
        "restarted recovery must reinstall the present native actor"
    );
    let reopened_before = prompt_admission_evidence(&root.database(), conversation.conversation_id);
    let reopened_reply = reopened_core
        .handle(
            reopened_connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: native_wire_id,
                idempotency_key: IdempotencyKey::new("native-send-prompt-must-fail-after-restart"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("restart must preserve the native prompt gate")
                    .expect("valid reopened native rejection prompt"),
            }),
        )
        .await;
    assert!(matches!(
        reopened_reply,
        RuntimeReply::Command(CommandReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == DAEMON_RUNTIME_FEATURE_UNAVAILABLE
    ));
    assert_eq!(reopened_core.actor_count().await, reopened_actor_baseline);
    assert_eq!(
        prompt_admission_evidence(&root.database(), conversation.conversation_id),
        reopened_before,
        "restarted Core rejection must remain byte-exact and side-effect-free"
    );

    // 同一个 Core 上的 Managed conversation 仍应走原有 durable acceptance，证明
    // 门禁绑定 origin 而不是把整个 SendPrompt family 关闭。
    let managed = start_receipt(
        reopened_core
            .handle(
                reopened_connection,
                start_request("managed-send-prompt-control"),
            )
            .await,
    );
    configure_codex_revision_one(
        &reopened_core,
        reopened_connection,
        managed.conversation_id.clone(),
        "managed-send-prompt-control-configuration",
    )
    .await;
    let managed_reply = reopened_core
        .handle(
            reopened_connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: managed.conversation_id,
                idempotency_key: IdempotencyKey::new("managed-send-prompt-control-command"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("managed prompt remains admissible")
                    .expect("valid managed control prompt"),
            }),
        )
        .await;
    assert!(matches!(
        managed_reply,
        RuntimeReply::Command(CommandReceipt::Accepted { .. })
    ));
    reopened_core
        .shutdown()
        .await
        .expect("shutdown reopened native SendPrompt admission core");
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

    configure_codex_revision_one(
        &core,
        connection,
        created.conversation_id.clone(),
        "start-query-configuration",
    )
    .await;

    let prompt_key = IdempotencyKey::new("prompt-1");
    let prompt = PromptPayload::new("hello durable queue").expect("prompt");
    let accepted = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: created.conversation_id.clone(),
                idempotency_key: prompt_key.clone(),
                expected_configuration_revision: 1,
                prompt,
            }),
        )
        .await;
    let command_id = match accepted {
        RuntimeReply::Command(CommandReceipt::Accepted {
            command_id,
            configuration_revision: 1,
            ..
        }) => command_id,
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
            assert_eq!(receipt.configuration_revision, 1);
            assert_eq!(receipt.status, CommandStatus::Accepted);
            assert_eq!(receipt.turn_id, None);
        }
        other => panic!("expected command status, got {other:?}"),
    }

    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn query_receipt_reports_history_only_without_synthesizing_command_status() {
    let root = TestRoot::new("history-only-receipt");
    let core = core(&root).await;
    core.recover().await.expect("recover history-only core");
    let connection = connect_local(&core, 0x81).await;
    let conversation_id = synthetic_runtime_id(RuntimeIdKind::Conversation, 0x82);
    let command_id = synthetic_runtime_id(RuntimeIdKind::Command, 0x83);
    core.history_receipts
        .replace(conversation_id, [command_id])
        .expect("install verified history-only command set");

    let reply = core
        .handle(
            connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                conversation_id: wire_conversation_id(conversation_id),
                command_id: wire_command_id(command_id),
            }),
        )
        .await;

    match reply {
        RuntimeReply::Failure(RuntimeFailure { code, .. }) => {
            assert_eq!(code, DAEMON_COMMAND_HISTORY_ONLY);
        }
        RuntimeReply::CommandStatus(receipt) => {
            panic!("history-only identity must not synthesize CommandStatus: {receipt:?}");
        }
        other => panic!("expected history-only failure, got {other:?}"),
    }
    core.shutdown().await.expect("shutdown history-only core");
}

#[tokio::test]
async fn query_receipt_reports_not_found_for_unread_and_idempotency_selectors() {
    let root = TestRoot::new("history-receipt-not-found");
    let core = core(&root).await;
    core.recover().await.expect("recover receipt lookup core");
    let connection = connect_local(&core, 0x84).await;
    let conversation_id = synthetic_runtime_id(RuntimeIdKind::Conversation, 0x85);
    let indexed_command = synthetic_runtime_id(RuntimeIdKind::Command, 0x86);
    core.history_receipts
        .replace(conversation_id, [indexed_command])
        .expect("install one history-only command");

    let requests = [
        RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
            conversation_id: wire_conversation_id(conversation_id),
            command_id: wire_command_id(synthetic_runtime_id(RuntimeIdKind::Command, 0x87)),
        }),
        RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
            conversation_id: wire_conversation_id(synthetic_runtime_id(
                RuntimeIdKind::Conversation,
                0x88,
            )),
            command_id: wire_command_id(indexed_command),
        }),
        RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
            conversation_id: wire_conversation_id(conversation_id),
            idempotency_key: IdempotencyKey::new("history-registry-must-not-serve-idempotency"),
        }),
    ];
    for request in requests {
        let reply = core.handle(connection, request).await;
        assert!(
            matches!(
                &reply,
                RuntimeReply::Failure(RuntimeFailure { code, .. })
                    if code == DAEMON_COMMAND_NOT_FOUND
            ),
            "unread/random/idempotency lookup must stay not-found, got {reply:?}"
        );
    }

    core.shutdown().await.expect("shutdown receipt lookup core");
}

#[tokio::test]
async fn query_receipt_prefers_durable_command_over_history_only_registry() {
    let root = TestRoot::new("durable-receipt-precedence");
    let core = core(&root).await;
    core.recover().await.expect("recover durable receipt core");
    let connection = connect_local(&core, 0x89).await;
    let conversation = start_receipt(
        core.handle(
            connection,
            start_request("durable-receipt-precedence-start"),
        )
        .await,
    );
    configure_codex_revision_one(
        &core,
        connection,
        conversation.conversation_id.clone(),
        "durable-receipt-precedence-configure",
    )
    .await;
    let accepted = core
        .handle(
            connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: conversation.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new("durable-receipt-precedence-command"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("durable receipt wins").expect("prompt"),
            }),
        )
        .await;
    let command_id = match accepted {
        RuntimeReply::Command(CommandReceipt::Accepted { command_id, .. }) => command_id,
        other => panic!("expected accepted durable command, got {other:?}"),
    };
    let internal_conversation =
        parse_conversation_id(&conversation.conversation_id).expect("parse durable conversation");
    let internal_command = parse_command_id(&command_id).expect("parse durable command");
    core.history_receipts
        .replace(internal_conversation, [internal_command])
        .expect("also index durable command as history-only");

    let reply = core
        .handle(
            connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                conversation_id: conversation.conversation_id.clone(),
                command_id: command_id.clone(),
            }),
        )
        .await;
    assert!(
        matches!(
            &reply,
            RuntimeReply::CommandStatus(CommandStatusReceipt {
                conversation_id,
                command_id: returned_command,
                configuration_revision: 1,
                status: CommandStatus::Accepted,
                turn_id: None,
            }) if conversation_id == &conversation.conversation_id
                && returned_command == &command_id
        ),
        "durable receipt must win over volatile registry, got {reply:?}"
    );

    core.shutdown()
        .await
        .expect("shutdown durable receipt core");
}

#[tokio::test]
async fn query_receipt_never_falls_back_after_durable_owner_mismatch() {
    let root = TestRoot::new("receipt-owner-mismatch");
    let core = core(&root).await;
    core.recover().await.expect("recover owner mismatch core");
    let owner_connection = connect_local(&core, 0x8A).await;
    let other_connection = connect_local(&core, 0x8B).await;
    let conversation = start_receipt(
        core.handle(
            owner_connection,
            start_request("receipt-owner-mismatch-start"),
        )
        .await,
    );
    configure_codex_revision_one(
        &core,
        owner_connection,
        conversation.conversation_id.clone(),
        "receipt-owner-mismatch-configure",
    )
    .await;
    let command_id = match core
        .handle(
            owner_connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: conversation.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new("receipt-owner-mismatch-command"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("owner mismatch must not fall back").expect("prompt"),
            }),
        )
        .await
    {
        RuntimeReply::Command(CommandReceipt::Accepted { command_id, .. }) => command_id,
        other => panic!("expected accepted owner-scoped command, got {other:?}"),
    };
    core.history_receipts
        .replace(
            parse_conversation_id(&conversation.conversation_id)
                .expect("parse owner-scoped conversation"),
            [parse_command_id(&command_id).expect("parse owner-scoped command")],
        )
        .expect("index same command in volatile registry");

    let reply = core
        .handle(
            other_connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                conversation_id: conversation.conversation_id,
                command_id,
            }),
        )
        .await;
    assert!(
        matches!(
            &reply,
            RuntimeReply::Failure(RuntimeFailure { code, .. })
                if code == RuntimeStoreError::CommandOwnerMismatch.code()
        ),
        "owner mismatch must surface its durable failure without registry fallback, got {reply:?}"
    );

    core.shutdown().await.expect("shutdown owner mismatch core");
}

#[tokio::test]
async fn history_only_receipts_do_not_survive_runtime_core_restart() {
    let root = TestRoot::new("history-receipt-restart");
    let conversation_id = synthetic_runtime_id(RuntimeIdKind::Conversation, 0x8C);
    let command_id = synthetic_runtime_id(RuntimeIdKind::Command, 0x8D);

    let first_core = core(&root).await;
    first_core
        .recover()
        .await
        .expect("recover first history receipt core");
    let first_connection = connect_local(&first_core, 0x8E).await;
    first_core
        .history_receipts
        .replace(conversation_id, [command_id])
        .expect("install first-process receipt");
    assert!(matches!(
        first_core
            .handle(
                first_connection,
                RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                    conversation_id: wire_conversation_id(conversation_id),
                    command_id: wire_command_id(command_id),
                }),
            )
            .await,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == DAEMON_COMMAND_HISTORY_ONLY
    ));
    first_core.shutdown().await.expect("shutdown first core");
    drop(first_core);

    let second_core = core(&root).await;
    second_core
        .recover()
        .await
        .expect("recover replacement history receipt core");
    assert!(
        !second_core
            .history_receipts
            .contains(conversation_id, command_id)
            .expect("inspect fresh registry"),
        "a new RuntimeCore must start with an empty volatile registry"
    );
    let second_connection = connect_local(&second_core, 0x8E).await;
    let reply = second_core
        .handle(
            second_connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                conversation_id: wire_conversation_id(conversation_id),
                command_id: wire_command_id(command_id),
            }),
        )
        .await;
    assert!(
        matches!(
            &reply,
            RuntimeReply::Failure(RuntimeFailure { code, .. })
                if code == DAEMON_COMMAND_NOT_FOUND
        ),
        "restarted Core must not restore history-only receipts, got {reply:?}"
    );
    second_core.shutdown().await.expect("shutdown second core");
}

#[tokio::test]
async fn core_prompt_receipts_keep_original_pin_across_head_advance_and_lifecycle() {
    let root = TestRoot::new("prompt-pin-lifecycle");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let execution = super::super::conversation::tests::FakeCoordinator::held();
    let core = Arc::new(
        RuntimeCore::new_with_test_execution_coordinator(
            store,
            router,
            [0xA7; 32],
            Arc::new(execution.clone()),
        )
        .expect("construct pinned lifecycle core"),
    );
    core.recover().await.expect("recover pinned lifecycle core");
    let connection = connect_local(&core, 0x78).await;
    let conversation = start_receipt(
        core.handle(connection, start_request("prompt-pin-lifecycle-start"))
            .await,
    );
    configure_codex_revision_one(
        &core,
        connection,
        conversation.conversation_id.clone(),
        "prompt-pin-lifecycle-revision-one",
    )
    .await;

    let prompt_key = IdempotencyKey::new("prompt-pin-lifecycle-command");
    let prompt = PromptPayload::new("keep revision one through every status").expect("prompt");
    let prompt_request = || {
        RuntimeRequest::SendPrompt(SendPromptRequest {
            conversation_id: conversation.conversation_id.clone(),
            idempotency_key: prompt_key.clone(),
            expected_configuration_revision: 1,
            prompt: prompt.clone(),
        })
    };
    let command_id = match core.handle(connection, prompt_request()).await {
        RuntimeReply::Command(CommandReceipt::Accepted {
            command_id,
            configuration_revision: 1,
            ..
        }) => command_id,
        other => panic!("expected revision-one Accepted receipt, got {other:?}"),
    };
    execution.wait_for_starts(1).await;

    let query = || {
        RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
            conversation_id: conversation.conversation_id.clone(),
            command_id: command_id.clone(),
        })
    };
    let started = match core.handle(connection, query()).await {
        RuntimeReply::CommandStatus(receipt) => receipt,
        other => panic!("expected Started command status, got {other:?}"),
    };
    assert_eq!(started.configuration_revision, 1);
    assert_eq!(started.status, CommandStatus::Started);
    assert!(started.turn_id.is_some());

    let revision_two = core
        .handle(
            connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                conversation.conversation_id.clone(),
                IdempotencyKey::new("prompt-pin-lifecycle-revision-two"),
                1,
                codex_configuration(CodexReasoningEffort::High),
            )),
        )
        .await;
    assert!(matches!(
        revision_two,
        RuntimeReply::Configuration(ConfigurationReceipt::Applied {
            configuration_revision: 2,
            ..
        })
    ));

    assert!(matches!(
        core.handle(connection, prompt_request()).await,
        RuntimeReply::Command(CommandReceipt::Replayed {
            ref command_id,
            configuration_revision: 1,
        }) if command_id == &started.command_id
    ));
    let after_head_advance = match core.handle(connection, query()).await {
        RuntimeReply::CommandStatus(receipt) => receipt,
        other => panic!("expected post-configure command status, got {other:?}"),
    };
    assert_eq!(after_head_advance.configuration_revision, 1);
    assert_eq!(after_head_advance.status, CommandStatus::Started);
    assert_eq!(after_head_advance.turn_id, started.turn_id);

    execution.release(parse_command_id(&command_id).expect("parse pinned command id"));
    let terminal = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            match core.handle(connection, query()).await {
                RuntimeReply::CommandStatus(receipt)
                    if receipt.status == CommandStatus::Completed =>
                {
                    break receipt;
                }
                RuntimeReply::CommandStatus(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                other => panic!("expected terminal command status, got {other:?}"),
            }
        }
    })
    .await
    .expect("pinned command must reach terminal status");
    assert_eq!(terminal.configuration_revision, 1);
    assert_eq!(terminal.turn_id, started.turn_id);
    assert!(matches!(
        core.handle(connection, prompt_request()).await,
        RuntimeReply::Command(CommandReceipt::Replayed {
            command_id: replayed,
            configuration_revision: 1,
        }) if replayed == command_id
    ));

    core.shutdown()
        .await
        .expect("shutdown pinned lifecycle core");
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
    configure_codex_revision_one(
        &first_core,
        first_connection,
        conversation.conversation_id.clone(),
        "restart-configuration",
    )
    .await;
    let accepted = first_core
        .handle(
            first_connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: conversation.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new("restart-prompt"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("survive restart").expect("prompt"),
            }),
        )
        .await;
    assert!(matches!(
        accepted,
        RuntimeReply::Command(CommandReceipt::Accepted {
            configuration_revision: 1,
            ..
        })
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
            configuration_revision: 1,
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
async fn stage_upgrade_arms_only_after_exact_flush_ack_and_survives_later_disconnect() {
    let root = TestRoot::new("upgrade-flush-ack");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let arms = Arc::new(AtomicUsize::new(0));
    let service = Arc::new(RecordingUpgradeService {
        prepares: AtomicUsize::new(0),
        arms: arms.clone(),
    });
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32])
            .expect("construct upgrade Core")
            .with_test_upgrade_service(service.clone()),
    );
    core.recover().await.expect("recover upgrade Core");

    let read_only = core
        .issue_verified_local_principal(501, [0x80; 16])
        .expect("issue read-only local principal");
    let (read_only_sink, mut read_only_writes) =
        mpsc::channel::<crate::runtime::ConnectionWrite>(1);
    let read_only_connection = core
        .connect(read_only, ConnectionSink::new(read_only_sink))
        .expect("connect read-only principal");
    let denied = {
        let core = core.clone();
        tokio::spawn(async move {
            core.handle_envelope(
                read_only_connection,
                stage_upgrade_envelope("read-only-denied", "upgrade-read-only-denied"),
            )
            .await
        })
    };
    let denied_write = read_only_writes.recv().await.expect("denied reply write");
    let denied_reply: RuntimeEnvelope =
        serde_json::from_slice(denied_write.bytes()).expect("decode denied reply");
    assert!(matches!(
        denied_reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Failed {
            failure: RuntimeFailure { ref code, .. },
        })) if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
    ));
    denied_write
        .acknowledge()
        .expect("ACK authorization denial");
    denied
        .await
        .expect("denied handler task")
        .expect("denied handler result");
    assert_eq!(service.prepares.load(Ordering::SeqCst), 0);
    assert_eq!(arms.load(Ordering::SeqCst), 0);

    // Transport 丢弃未 ACK write：durable prepare 可以存在，但 action 必须保持未 arm。
    let (failed_connection, mut failed_writes) = connect_local_control_with_sink(&core, 0x81);
    let failed = {
        let core = core.clone();
        tokio::spawn(async move {
            core.handle_envelope(
                failed_connection,
                stage_upgrade_envelope("flush-failed", "upgrade-flush-failed"),
            )
            .await
        })
    };
    let failed_write = failed_writes.recv().await.expect("failed flush write");
    assert_eq!(arms.load(Ordering::SeqCst), 0);
    drop(failed_write);
    assert!(failed.await.expect("failed handler task").is_err());
    assert_eq!(arms.load(Ordering::SeqCst), 0);

    // Caller future 在 transport ACK 前取消，即使 writer 随后完成也没有 action owner。
    let (cancelled_connection, mut cancelled_writes) = connect_local_control_with_sink(&core, 0x82);
    let cancelled = {
        let core = core.clone();
        tokio::spawn(async move {
            core.handle_envelope(
                cancelled_connection,
                stage_upgrade_envelope("caller-cancelled", "upgrade-caller-cancelled"),
            )
            .await
        })
    };
    let cancelled_write = cancelled_writes.recv().await.expect("cancelled write");
    cancelled.abort();
    let _ = cancelled.await;
    let _ = cancelled_write.acknowledge();
    tokio::task::yield_now().await;
    assert_eq!(arms.load(Ordering::SeqCst), 0);

    // 完整 write/newline/flush 的 ConnectionWrite ACK 是唯一 arm 边界；ACK 后断开
    // 当前 connection 不得撤销已移交给 daemon 的 action。
    let (acked_connection, mut acked_writes) = connect_local_control_with_sink(&core, 0x83);
    let acked = {
        let core = core.clone();
        tokio::spawn(async move {
            core.handle_envelope(
                acked_connection,
                stage_upgrade_envelope("flush-acked", "upgrade-flush-acked"),
            )
            .await
        })
    };
    let acked_write = acked_writes.recv().await.expect("ACK write");
    let reply: RuntimeEnvelope =
        serde_json::from_slice(acked_write.bytes()).expect("decode StageUpgrade reply");
    assert!(matches!(
        reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Staged {
            ref target_version,
        })) if target_version == "1.2.3"
    ));
    assert_eq!(arms.load(Ordering::SeqCst), 0);
    acked_write
        .acknowledge()
        .expect("ACK exact transport flush");
    acked
        .await
        .expect("ACK handler task")
        .expect("ACK handler result");
    assert_eq!(arms.load(Ordering::SeqCst), 1);
    core.disconnect(acked_connection).await;
    assert_eq!(arms.load(Ordering::SeqCst), 1);
    assert_eq!(service.prepares.load(Ordering::SeqCst), 3);

    core.shutdown().await.expect("shutdown upgrade Core");
}

#[tokio::test]
async fn durable_stage_waits_for_active_turn_then_switches_current_and_requests_main_exit() {
    let root = TestRoot::new("upgrade-active-idle");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let execution = super::super::conversation::tests::FakeCoordinator::held();
    let bin_root = root.path.join("bin");
    let version_root = bin_root.join("2.3.4");
    fs::create_dir_all(&version_root).expect("version root");
    fs::set_permissions(&bin_root, fs::Permissions::from_mode(0o700)).expect("bin root mode");
    fs::set_permissions(&version_root, fs::Permissions::from_mode(0o700))
        .expect("version root mode");
    let candidate = b"versioned daemon candidate";
    let daemon = version_root.join("agentdeckd");
    fs::write(&daemon, candidate).expect("candidate daemon");
    fs::set_permissions(&daemon, fs::Permissions::from_mode(0o500)).expect("candidate mode");
    symlink("old", bin_root.join("current")).expect("old current");
    let (upgrade_exit, mut upgrade_exit_receiver) = mpsc::unbounded_channel();
    let core = Arc::new(
        RuntimeCore::new_with_test_execution_coordinator(
            store,
            router,
            [0xA8; 32],
            Arc::new(execution.clone()),
        )
        .expect("construct active upgrade Core")
        .with_versioned_daemon_upgrade(bin_root.clone(), upgrade_exit)
        .expect("install durable upgrade service"),
    );
    core.recover().await.expect("recover active upgrade Core");

    let user_connection = connect_local(&core, 0x84).await;
    let conversation = start_receipt(
        core.handle(user_connection, start_request("upgrade-active-start"))
            .await,
    );
    configure_codex_revision_one(
        &core,
        user_connection,
        conversation.conversation_id.clone(),
        "upgrade-active-configure",
    )
    .await;
    let command_id = match core
        .handle(
            user_connection,
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: conversation.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new("upgrade-active-prompt"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("hold one active turn").expect("prompt"),
            }),
        )
        .await
    {
        RuntimeReply::Command(CommandReceipt::Accepted { command_id, .. }) => command_id,
        other => panic!("expected Accepted command, got {other:?}"),
    };
    execution.wait_for_starts(1).await;
    assert_eq!(execution.active(), 1);

    let request = StageUpgradeRequest::new(
        "2.3.4".to_owned(),
        artifact_hash(candidate),
        IdempotencyKey::new("upgrade-active-admin"),
        LocalOnlyAdministration::LocalOnly,
    )
    .expect("upgrade request");
    let (admin_connection, mut admin_writes) = connect_local_control_with_sink(&core, 0x85);
    let handling = {
        let core = core.clone();
        let request = request.clone();
        tokio::spawn(async move {
            core.handle_envelope(
                admin_connection,
                RuntimeEnvelope {
                    version: RUNTIME_PROTOCOL_VERSION,
                    message_id: MessageId::new("upgrade-active-envelope"),
                    body: RuntimeMessage::Request(RuntimeRequest::StageUpgrade(request)),
                },
            )
            .await
        })
    };
    let write = admin_writes.recv().await.expect("AwaitingIdle write");
    let reply: RuntimeEnvelope =
        serde_json::from_slice(write.bytes()).expect("decode AwaitingIdle reply");
    assert!(matches!(
        reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(
            StageUpgradeReceipt::AwaitingIdle {
                ref target_version,
                active_turns: 1,
            }
        )) if target_version == "2.3.4"
    ));
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("current before ACK"),
        Path::new("old")
    );
    write.acknowledge().expect("ACK AwaitingIdle reply");
    handling
        .await
        .expect("upgrade handler task")
        .expect("upgrade handler result");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            upgrade_exit_receiver.recv()
        )
        .await
        .is_err(),
        "active turn must keep current and exit unchanged"
    );
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("current while active"),
        Path::new("old")
    );

    execution.release(parse_command_id(&command_id).expect("internal command id"));
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        upgrade_exit_receiver.recv(),
    )
    .await
    .expect("idle upgrade exit deadline")
    .expect("main-loop exit signal");
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("switched current"),
        Path::new("2.3.4")
    );
    let durable = core
        .store
        .query_admin_upgrade(request)
        .await
        .expect("query durable upgrade")
        .expect("durable upgrade row");
    assert_eq!(
        durable.status(),
        crate::runtime::store::AdminUpgradeStatus::Completed
    );

    core.shutdown().await.expect("shutdown active upgrade Core");
}

#[tokio::test]
async fn pending_upgrade_restart_requires_a_new_exact_flush_ack_before_switch() {
    let root = TestRoot::new("upgrade-pending-retry");
    let (bin_root, request) =
        versioned_upgrade_fixture(&root, "3.1.0", "upgrade-pending-retry-key");
    let (first, mut first_exit) = versioned_upgrade_core(&root, &bin_root, 0xB1).await;
    let (unacked, handling) =
        begin_stage_upgrade(&first, request.clone(), 0xB1, "upgrade-before-ack").await;
    let reply: RuntimeEnvelope =
        serde_json::from_slice(unacked.bytes()).expect("decode pre-ACK StageUpgrade reply");
    assert!(matches!(
        reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Staged {
            ref target_version,
        })) if target_version == "3.1.0"
    ));
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("current before first ACK"),
        Path::new("old")
    );
    drop(unacked);
    assert!(
        handling.await.expect("join pre-ACK handler").is_err(),
        "dropped transport ACK must cancel the deferred action"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), first_exit.recv())
            .await
            .is_err(),
        "pre-ACK failure must not request daemon exit"
    );
    let pending = first
        .store
        .query_admin_upgrade(request.clone())
        .await
        .expect("query pre-ACK durable row")
        .expect("pre-ACK durable row");
    assert_eq!(
        pending.status(),
        crate::runtime::store::AdminUpgradeStatus::Pending
    );
    first.shutdown().await.expect("shutdown pre-ACK Core");

    // ACK 前崩溃与 ACK 后、deferred task 真正开始前崩溃在 durable Store 中故意同态：
    // 两者都只保留 Pending。为避免无 ACK switch，restart 绝不自动 arm；调用方必须
    // 以 deterministic exact request 重试，并再次取得完整 flush ACK。
    let (restarted, mut restarted_exit) = versioned_upgrade_core(&root, &bin_root, 0xB2).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), restarted_exit.recv())
            .await
            .is_err(),
        "Pending restart must not auto-arm an indistinguishable request"
    );
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("current after Pending restart"),
        Path::new("old")
    );
    assert_upgrade_conflict(&restarted, &request, 0xB2, "upgrade-pending-conflict").await;

    let (retry, retry_handling) = begin_stage_upgrade(
        &restarted,
        request.clone(),
        0xB3,
        "upgrade-pending-exact-retry",
    )
    .await;
    let retry_reply: RuntimeEnvelope =
        serde_json::from_slice(retry.bytes()).expect("decode exact retry reply");
    assert!(matches!(
        retry_reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Replayed {
            ref target_version,
        })) if target_version == "3.1.0"
    ));
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("current before retry ACK"),
        Path::new("old")
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), restarted_exit.recv())
            .await
            .is_err(),
        "exact replay without ACK must still leave exit unchanged"
    );
    retry.acknowledge().expect("ACK exact retry");
    retry_handling
        .await
        .expect("join exact retry handler")
        .expect("flush exact retry");
    tokio::time::timeout(std::time::Duration::from_secs(3), restarted_exit.recv())
        .await
        .expect("retry-triggered upgrade exit deadline")
        .expect("retry-triggered upgrade exit");
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("current after retry ACK"),
        Path::new("3.1.0")
    );
    let completed = restarted
        .store
        .query_admin_upgrade(request)
        .await
        .expect("query completed retry")
        .expect("completed retry row");
    assert_eq!(
        completed.status(),
        crate::runtime::store::AdminUpgradeStatus::Completed
    );
    restarted
        .shutdown()
        .await
        .expect("shutdown exact-retry Core");
}

#[tokio::test]
async fn switched_pending_retry_finalizes_idempotently_and_completed_replay_is_inert() {
    let root = TestRoot::new("upgrade-switched-retry");
    let (bin_root, request) =
        versioned_upgrade_fixture(&root, "3.2.0", "upgrade-switched-retry-key");
    let store = root.open_store().await;
    store
        .accept_admin_upgrade(request.clone())
        .await
        .expect("persist pending upgrade before simulated crash");
    crate::runtime::upgrade::VersionedDaemonSwitcher::new(bin_root.clone())
        .expect("construct simulated crash switcher")
        .switch("3.2.0", request.candidate_sha256())
        .expect("switch current before simulated finalize crash");
    store
        .shutdown()
        .await
        .expect("close Store at post-switch/pre-finalize boundary");

    let (restarted, mut restarted_exit) = versioned_upgrade_core(&root, &bin_root, 0xB4).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), restarted_exit.recv())
            .await
            .is_err(),
        "post-switch Pending restart must still require exact replay"
    );
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("already-switched current"),
        Path::new("3.2.0")
    );
    assert_upgrade_conflict(&restarted, &request, 0xB4, "upgrade-switched-conflict").await;
    let (retry, retry_handling) = begin_stage_upgrade(
        &restarted,
        request.clone(),
        0xB5,
        "upgrade-switched-exact-retry",
    )
    .await;
    let retry_reply: RuntimeEnvelope =
        serde_json::from_slice(retry.bytes()).expect("decode switched exact retry");
    assert!(matches!(
        retry_reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Replayed {
            ref target_version,
        })) if target_version == "3.2.0"
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), restarted_exit.recv())
            .await
            .is_err(),
        "already-current retry must not exit before its new ACK"
    );
    retry.acknowledge().expect("ACK switched exact retry");
    retry_handling
        .await
        .expect("join switched retry handler")
        .expect("flush switched retry");
    tokio::time::timeout(std::time::Duration::from_secs(3), restarted_exit.recv())
        .await
        .expect("switched retry exit deadline")
        .expect("switched retry exit");
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("current after idempotent reswitch"),
        Path::new("3.2.0")
    );
    let completed = restarted
        .store
        .query_admin_upgrade(request.clone())
        .await
        .expect("query idempotently completed row")
        .expect("idempotently completed row");
    assert_eq!(
        completed.status(),
        crate::runtime::store::AdminUpgradeStatus::Completed
    );
    restarted
        .shutdown()
        .await
        .expect("shutdown post-switch retry Core");

    // Completed/current 已切但 main 尚未真正退出时崩溃：新进程从 current 启动后，
    // exact install replay 只读回 terminal Replayed，不重新 arm、switch 或发 exit。
    let (completed_core, mut completed_exit) = versioned_upgrade_core(&root, &bin_root, 0xB6).await;
    assert_upgrade_conflict(
        &completed_core,
        &request,
        0xB6,
        "upgrade-completed-conflict",
    )
    .await;
    let (replayed, replay_handling) = begin_stage_upgrade(
        &completed_core,
        request,
        0xB7,
        "upgrade-completed-exact-replay",
    )
    .await;
    let replay_reply: RuntimeEnvelope =
        serde_json::from_slice(replayed.bytes()).expect("decode Completed replay");
    assert!(matches!(
        replay_reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Replayed {
            ref target_version,
        })) if target_version == "3.2.0"
    ));
    replayed.acknowledge().expect("ACK Completed replay");
    replay_handling
        .await
        .expect("join Completed replay handler")
        .expect("flush Completed replay");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), completed_exit.recv())
            .await
            .is_err(),
        "Completed replay must not arm a second switch or exit"
    );
    assert_eq!(
        fs::read_link(bin_root.join("current")).expect("current after Completed replay"),
        Path::new("3.2.0")
    );
    completed_core
        .shutdown()
        .await
        .expect("shutdown Completed replay Core");
}

#[tokio::test]
async fn concurrent_acked_upgrades_switch_only_one_version_before_main_exit() {
    let root = TestRoot::new("upgrade-single-exit-winner");
    let (bin_root, first_request) =
        versioned_upgrade_fixture(&root, "4.0.0", "upgrade-first-winner-key");
    let (_, second_request) =
        versioned_upgrade_fixture(&root, "4.1.0", "upgrade-second-winner-key");
    let (core, mut exit) = versioned_upgrade_core(&root, &bin_root, 0xB8).await;

    let (first_write, first_handler) =
        begin_stage_upgrade(&core, first_request.clone(), 0xB8, "upgrade-first-winner").await;
    let (second_write, second_handler) =
        begin_stage_upgrade(&core, second_request.clone(), 0xB9, "upgrade-second-winner").await;
    first_write.acknowledge().expect("ACK first upgrade");
    second_write.acknowledge().expect("ACK second upgrade");
    first_handler
        .await
        .expect("join first upgrade handler")
        .expect("flush first upgrade");
    second_handler
        .await
        .expect("join second upgrade handler")
        .expect("flush second upgrade");

    tokio::time::timeout(std::time::Duration::from_secs(3), exit.recv())
        .await
        .expect("winning upgrade exit deadline")
        .expect("winning upgrade exit");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), exit.recv())
            .await
            .is_err(),
        "one process lifetime must publish exactly one upgrade exit"
    );
    let current = fs::read_link(bin_root.join("current")).expect("winning current link");
    assert!(matches!(current.to_str(), Some("4.0.0" | "4.1.0")));
    let first = core
        .store
        .query_admin_upgrade(first_request)
        .await
        .expect("query first concurrent upgrade")
        .expect("first concurrent upgrade row");
    let second = core
        .store
        .query_admin_upgrade(second_request)
        .await
        .expect("query second concurrent upgrade")
        .expect("second concurrent upgrade row");
    assert_eq!(
        usize::from(first.status() == crate::runtime::store::AdminUpgradeStatus::Completed)
            + usize::from(second.status() == crate::runtime::store::AdminUpgradeStatus::Completed),
        1,
        "exactly one ACKed upgrade may complete before main exit"
    );
    assert_eq!(
        usize::from(first.status() == crate::runtime::store::AdminUpgradeStatus::Pending)
            + usize::from(second.status() == crate::runtime::store::AdminUpgradeStatus::Pending),
        1,
        "the non-winning request must remain retryable Pending"
    );
    core.shutdown()
        .await
        .expect("shutdown concurrent upgrade Core");
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
    let inflight_while_waiting = core.operation_tracker.inflight.load(Ordering::Acquire);

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
