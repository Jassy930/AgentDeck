#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, CodexConversationConfiguration, ConversationConfiguration,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    AgentKind, ClaudeCodePermissionMode, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode,
};
use agentdeckd::runtime::store::{
    ConfigurationLimitScope, ConfigurationRecord, ConfigureConversation,
    ConfigureConversationOutcome, IdempotencyOwner, NewConversation, RuntimeClock,
    RuntimeClockError, RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, OpenFlags, params};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct OneShotFault {
    operation: RuntimeStoreOperation,
    armed: AtomicBool,
}

impl OneShotFault {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            armed: AtomicBool::new(true),
        }
    }
}

impl RuntimeStoreFaultInjector for OneShotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RuntimeStoreError::InvalidConfig(
                "injected configuration fault",
            ));
        }
        Ok(())
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-configuration-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create configuration test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure configuration test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load configuration test StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PublicMetadata {
    catalog_revision: String,
    updated_at_ms: i64,
    event_high_water: Option<String>,
    catalog_high_water: Option<String>,
    current_configuration_revision: Option<String>,
    entry_revision: String,
    catalog_rows: i64,
    event_rows: i64,
    configuration_rows: i64,
    event_stream_rows: i64,
    configuration_sealed_bytes: i64,
    ledger_event_rows: i64,
    ledger_audit_event_bytes: i64,
    ledger_event_stream_rows: i64,
    ledger_event_stream_bytes: i64,
    ledger_configuration_rows: i64,
    ledger_configuration_bytes: i64,
}

fn public_metadata(path: &Path, conversation_id: RuntimeId) -> PublicMetadata {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only metadata connection");
    let (catalog_revision, updated_at_ms, event_high_water) = connection
        .query_row(
            "SELECT catalog_revision, updated_at_ms, event_high_water
             FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read conversation metadata");
    let (
        catalog_high_water,
        ledger_event_rows,
        ledger_audit_event_bytes,
        ledger_event_stream_rows,
        ledger_event_stream_bytes,
        ledger_configuration_rows,
        ledger_configuration_bytes,
    ) = connection
        .query_row(
            "SELECT catalog_high_water, event_count, configuration_count,
                    configuration_sealed_bytes, audit_event_logical_bytes,
                    event_stream_count, event_stream_bytes
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            },
        )
        .expect("read runtime ledger high-waters");
    let (current_configuration_revision, entry_revision) = connection
        .query_row(
            "SELECT current_configuration_revision, entry_revision
             FROM conversation_state WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read public conversation state");
    let (
        catalog_rows,
        event_rows,
        configuration_rows,
        event_stream_rows,
        configuration_sealed_bytes,
    ) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM catalog_journal),
                 (SELECT COUNT(*) FROM event_journal),
                 (SELECT COUNT(*) FROM configuration_journal),
                 (SELECT COUNT(*) FROM event_stream_index),
                 (SELECT COALESCE(SUM(length(sealed_request)), 0)
                    FROM configuration_journal)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("read physical row counts");
    PublicMetadata {
        catalog_revision,
        updated_at_ms,
        event_high_water,
        catalog_high_water,
        current_configuration_revision,
        entry_revision,
        catalog_rows,
        event_rows,
        configuration_rows,
        event_stream_rows,
        configuration_sealed_bytes,
        ledger_event_rows,
        ledger_audit_event_bytes,
        ledger_event_stream_rows,
        ledger_event_stream_bytes,
        ledger_configuration_rows,
        ledger_configuration_bytes,
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn conversation(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: runtime_descriptor::descriptor(format!("configuration-{seed}").as_bytes()),
    }
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0xA1; 32],
        uid: 501,
        client_installation_id: [seed; 16],
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

fn claude_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .expect("valid Claude Code configuration"),
    ))
}

fn configure_request(
    conversation_id: RuntimeId,
    owner_seed: u8,
    key: &str,
    expected_revision: u64,
    configuration: ConversationConfiguration,
) -> ConfigureConversation {
    ConfigureConversation {
        conversation_id,
        owner: owner(owner_seed),
        idempotency_key: key.to_owned(),
        expected_configuration_revision: expected_revision,
        configuration,
    }
}

fn applied(outcome: ConfigureConversationOutcome) -> ConfigurationRecord {
    match outcome {
        ConfigureConversationOutcome::Applied { configuration } => configuration,
        other => panic!("expected applied configuration, got {other:?}"),
    }
}

fn replayed(outcome: ConfigureConversationOutcome) -> ConfigurationRecord {
    match outcome {
        ConfigureConversationOutcome::Replayed { configuration } => configuration,
        other => panic!("expected replayed configuration, got {other:?}"),
    }
}

fn conflict(outcome: ConfigureConversationOutcome) -> u64 {
    match outcome {
        ConfigureConversationOutcome::Conflict {
            current_configuration_revision,
        } => current_configuration_revision,
        other => panic!("expected configuration conflict, got {other:?}"),
    }
}

#[derive(Clone, Copy)]
enum ConfigurationTamper {
    ConfigurationMetadata,
    SealedRequest,
    StateHead,
    EventPayload,
    RuntimeLedger,
    DeleteConfiguration,
    DeleteEvent,
    SwapRequests,
}

impl ConfigurationTamper {
    const fn label(self) -> &'static str {
        match self {
            Self::ConfigurationMetadata => "configuration-metadata",
            Self::SealedRequest => "sealed-request",
            Self::StateHead => "state-head",
            Self::EventPayload => "event-payload",
            Self::RuntimeLedger => "runtime-ledger",
            Self::DeleteConfiguration => "delete-configuration",
            Self::DeleteEvent => "delete-event",
            Self::SwapRequests => "swap-requests",
        }
    }
}

async fn assert_configuration_tamper_rejected(tamper: ConfigurationTamper) {
    let root = TestRoot::new(tamper.label());
    let keys = MemoryKeyStore::new();
    let input = conversation(0x50);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open tamper store");
    store
        .create_conversation(input)
        .await
        .expect("create tamper conversation");
    for (revision, reasoning) in [CodexReasoningEffort::Low, CodexReasoningEffort::Low]
        .into_iter()
        .enumerate()
    {
        applied(
            store
                .configure_conversation(configure_request(
                    conversation_id,
                    0x51,
                    &format!("tamper-{revision}"),
                    revision as u64,
                    codex_configuration(reasoning),
                ))
                .await
                .expect("seed tamper configuration"),
        );
    }
    store.shutdown().await.expect("shutdown before tamper");

    let connection = Connection::open(root.database()).expect("open tamper database");
    connection
        .execute_batch("PRAGMA foreign_keys = OFF")
        .expect("disable tamper fixture foreign keys");
    match tamper {
        ConfigurationTamper::ConfigurationMetadata => {
            connection
                .execute(
                    "UPDATE configuration_journal SET metadata_token = zeroblob(32)
                     WHERE configuration_revision = '00000000000000000001'",
                    [],
                )
                .expect("tamper configuration metadata");
        }
        ConfigurationTamper::SealedRequest => {
            let (revision, mut sealed): (String, Vec<u8>) = connection
                .query_row(
                    "SELECT configuration_revision, sealed_request
                     FROM configuration_journal ORDER BY configuration_revision LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("read sealed request");
            *sealed.last_mut().expect("sealed request tag") ^= 1;
            connection
                .execute(
                    "UPDATE configuration_journal SET sealed_request = ?1
                     WHERE conversation_id = ?2 AND configuration_revision = ?3",
                    params![sealed, &conversation_id.as_bytes()[..], revision],
                )
                .expect("tamper sealed request");
        }
        ConfigurationTamper::StateHead => {
            connection
                .execute(
                    "UPDATE conversation_state
                     SET current_configuration_revision = '00000000000000000001'
                     WHERE conversation_id = ?1",
                    [&conversation_id.as_bytes()[..]],
                )
                .expect("tamper configuration head");
        }
        ConfigurationTamper::EventPayload => {
            let (event_id, mut sealed): (Vec<u8>, Vec<u8>) = connection
                .query_row(
                    "SELECT event_id, sealed_event FROM event_journal
                     ORDER BY event_seq LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("read sealed event");
            *sealed.last_mut().expect("sealed event tag") ^= 1;
            connection
                .execute(
                    "UPDATE event_journal SET sealed_event = ?1 WHERE event_id = ?2",
                    params![sealed, event_id],
                )
                .expect("tamper sealed event");
        }
        ConfigurationTamper::RuntimeLedger => {
            connection
                .execute(
                    "UPDATE runtime_meta SET configuration_count = 1 WHERE singleton = 1",
                    [],
                )
                .expect("tamper runtime configuration count");
        }
        ConfigurationTamper::DeleteConfiguration => {
            connection
                .execute(
                    "DELETE FROM configuration_journal
                     WHERE configuration_revision = '00000000000000000001'",
                    [],
                )
                .expect("delete non-head configuration");
        }
        ConfigurationTamper::DeleteEvent => {
            connection
                .execute(
                    "DELETE FROM event_journal WHERE event_seq = '00000000000000000000'",
                    [],
                )
                .expect("delete configuration event");
        }
        ConfigurationTamper::SwapRequests => {
            let rows = connection
                .prepare(
                    "SELECT configuration_revision, sealed_request
                     FROM configuration_journal ORDER BY configuration_revision",
                )
                .expect("prepare swapped requests")
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .expect("query swapped requests")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect swapped requests");
            assert_eq!(rows.len(), 2);
            connection
                .execute(
                    "UPDATE configuration_journal SET sealed_request = ?1
                     WHERE conversation_id = ?2 AND configuration_revision = ?3",
                    params![&rows[1].1, &conversation_id.as_bytes()[..], &rows[0].0],
                )
                .expect("swap first request");
            connection
                .execute(
                    "UPDATE configuration_journal SET sealed_request = ?1
                     WHERE conversation_id = ?2 AND configuration_revision = ?3",
                    params![&rows[0].1, &conversation_id.as_bytes()[..], &rows[1].0],
                )
                .expect("swap second request");
        }
    }
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint tamper");
    drop(connection);
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("configuration tamper must fail at reopen");
    let expected_error = match tamper {
        ConfigurationTamper::SealedRequest
        | ConfigurationTamper::EventPayload
        | ConfigurationTamper::SwapRequests => {
            matches!(error, RuntimeStoreError::Cipher(_))
        }
        ConfigurationTamper::ConfigurationMetadata
        | ConfigurationTamper::StateHead
        | ConfigurationTamper::RuntimeLedger
        | ConfigurationTamper::DeleteConfiguration
        | ConfigurationTamper::DeleteEvent => {
            matches!(error, RuntimeStoreError::UnknownOrCorruptSchema)
        }
    };
    assert!(expected_error, "{} returned {error:?}", tamper.label());
}

#[tokio::test]
async fn configuration_applies_reopens_and_replays_without_catalog_drift() {
    let root = TestRoot::new("apply-reopen-replay");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x21);
    let conversation_id = input.conversation_id;
    let configuration = codex_configuration(CodexReasoningEffort::Medium);
    let request = ConfigureConversation {
        conversation_id,
        owner: owner(0x31),
        idempotency_key: "configure-1".to_owned(),
        expected_configuration_revision: 0,
        configuration: configuration.clone(),
    };
    let clock = ManualClock(Arc::new(AtomicU64::new(1_000)));

    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open configuration store");
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let before = public_metadata(&root.database(), conversation_id);
    clock.0.store(10_000, Ordering::SeqCst);

    let record = applied(
        store
            .configure_conversation(request.clone())
            .await
            .expect("apply first configuration"),
    );
    assert_eq!(record.conversation_id, conversation_id);
    assert_eq!(record.configuration_revision, 1);
    assert_eq!(record.base_configuration_revision, 0);
    assert_eq!(record.event_seq, 0);
    assert_eq!(
        record.created_at_ms,
        u64::try_from(before.updated_at_ms).expect("non-negative conversation activity time")
    );
    assert_eq!(record.configuration, configuration);

    let after = public_metadata(&root.database(), conversation_id);
    assert_eq!(after.catalog_revision, before.catalog_revision);
    assert_eq!(after.updated_at_ms, before.updated_at_ms);
    assert_eq!(after.catalog_high_water, before.catalog_high_water);
    assert_eq!(after.catalog_rows, before.catalog_rows);
    assert_eq!(after.event_rows, before.event_rows + 1);
    assert_eq!(after.configuration_rows, before.configuration_rows + 1);
    store.shutdown().await.expect("shutdown configured store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen configured store");
    match reopened
        .configure_conversation(request)
        .await
        .expect("replay exact configuration")
    {
        ConfigureConversationOutcome::Replayed { configuration } => {
            assert_eq!(configuration, record);
        }
        other => panic!("expected replayed configuration, got {other:?}"),
    }
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn replay_precedes_revision_conflict_and_every_rejection_is_zero_write() {
    let root = TestRoot::new("replay-conflict-order");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x22);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open conflict store");
    store
        .create_conversation(input)
        .await
        .expect("create conflict conversation");

    let first_request = configure_request(
        conversation_id,
        0x32,
        "first",
        0,
        codex_configuration(CodexReasoningEffort::Low),
    );
    let first = applied(
        store
            .configure_conversation(first_request.clone())
            .await
            .expect("apply first revision"),
    );
    let after_first = public_metadata(&root.database(), conversation_id);

    for (key, expected) in [("stale", 0), ("future", 2)] {
        let outcome = store
            .configure_conversation(configure_request(
                conversation_id,
                0x33,
                key,
                expected,
                codex_configuration(CodexReasoningEffort::High),
            ))
            .await
            .expect("revision mismatch is a typed conflict");
        assert_eq!(conflict(outcome), 1);
        assert_eq!(
            public_metadata(&root.database(), conversation_id),
            after_first
        );
    }

    let error = store
        .configure_conversation(configure_request(
            conversation_id,
            0x32,
            "first",
            0,
            codex_configuration(CodexReasoningEffort::High),
        ))
        .await
        .expect_err("same key with a different request must conflict");
    assert!(matches!(error, RuntimeStoreError::IdempotencyConflict));
    assert_eq!(
        public_metadata(&root.database(), conversation_id),
        after_first
    );
    let error = store
        .configure_conversation(configure_request(
            conversation_id,
            0x32,
            "first",
            1,
            codex_configuration(CodexReasoningEffort::Low),
        ))
        .await
        .expect_err("same key with a different expected revision must conflict");
    assert!(matches!(error, RuntimeStoreError::IdempotencyConflict));
    assert_eq!(
        public_metadata(&root.database(), conversation_id),
        after_first
    );

    let second = applied(
        store
            .configure_conversation(configure_request(
                conversation_id,
                0x34,
                "first",
                1,
                codex_configuration(CodexReasoningEffort::High),
            ))
            .await
            .expect("apply second revision"),
    );
    assert_eq!(second.configuration_revision, 2);
    let after_second = public_metadata(&root.database(), conversation_id);
    assert_eq!(
        replayed(
            store
                .configure_conversation(first_request)
                .await
                .expect("old exact request replays after head advances")
        ),
        first
    );
    assert_eq!(
        public_metadata(&root.database(), conversation_id),
        after_second
    );
    store.shutdown().await.expect("shutdown conflict store");
}

#[tokio::test]
async fn concurrent_expected_zero_writers_produce_one_revision_without_a_gap() {
    let root = TestRoot::new("concurrent-cas");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x23);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open concurrent store");
    store
        .create_conversation(input)
        .await
        .expect("create concurrent conversation");
    let before = public_metadata(&root.database(), conversation_id);
    let (left, right) = tokio::join!(
        store.configure_conversation(configure_request(
            conversation_id,
            0x35,
            "left",
            0,
            codex_configuration(CodexReasoningEffort::Low),
        )),
        store.configure_conversation(configure_request(
            conversation_id,
            0x36,
            "right",
            0,
            codex_configuration(CodexReasoningEffort::High),
        )),
    );
    let mut applied_count = 0;
    let mut conflict_count = 0;
    for outcome in [left.expect("left writer"), right.expect("right writer")] {
        match outcome {
            ConfigureConversationOutcome::Applied { configuration } => {
                applied_count += 1;
                assert_eq!(configuration.configuration_revision, 1);
                assert_eq!(configuration.event_seq, 0);
            }
            ConfigureConversationOutcome::Conflict {
                current_configuration_revision,
            } => {
                conflict_count += 1;
                assert_eq!(current_configuration_revision, 1);
            }
            other => panic!("unexpected concurrent outcome {other:?}"),
        }
    }
    assert_eq!((applied_count, conflict_count), (1, 1));
    let after = public_metadata(&root.database(), conversation_id);
    assert_eq!(after.event_rows, before.event_rows + 1);
    assert_eq!(after.configuration_rows, before.configuration_rows + 1);
    assert_eq!(after.ledger_event_rows, before.ledger_event_rows + 1);
    assert_eq!(
        after.ledger_configuration_rows,
        before.ledger_configuration_rows + 1
    );
    store.shutdown().await.expect("shutdown concurrent store");
    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen gap-free concurrent store");
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn invalid_inputs_and_agent_mismatch_never_write_configuration_state() {
    let root = TestRoot::new("input-rejection");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x24);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open input rejection store");
    store
        .create_conversation(input)
        .await
        .expect("create input rejection conversation");
    let before = public_metadata(&root.database(), conversation_id);

    let wrong_kind = store
        .configure_conversation(configure_request(
            runtime_id(RuntimeIdKind::AdapterState, 0x70),
            0x37,
            "wrong-kind",
            0,
            codex_configuration(CodexReasoningEffort::Medium),
        ))
        .await
        .expect_err("cross-kind conversation id must fail");
    assert!(matches!(
        wrong_kind,
        RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Conversation,
            actual: RuntimeIdKind::AdapterState,
        }
    ));
    for key in [String::new(), "x".repeat(1_025)] {
        let error = store
            .configure_conversation(configure_request(
                conversation_id,
                0x38,
                &key,
                0,
                codex_configuration(CodexReasoningEffort::Medium),
            ))
            .await
            .expect_err("invalid idempotency key must fail");
        assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
    }
    let missing = store
        .configure_conversation(configure_request(
            runtime_id(RuntimeIdKind::Conversation, 0x71),
            0x39,
            "missing",
            0,
            codex_configuration(CodexReasoningEffort::Medium),
        ))
        .await
        .expect_err("missing conversation must fail");
    assert!(matches!(missing, RuntimeStoreError::ConversationNotFound));
    assert_eq!(claude_configuration().agent_kind(), AgentKind::ClaudeCode);
    let mismatch = store
        .configure_conversation(configure_request(
            conversation_id,
            0x3A,
            "agent-mismatch",
            0,
            claude_configuration(),
        ))
        .await
        .expect_err("configuration agent must match descriptor");
    assert!(matches!(
        mismatch,
        RuntimeStoreError::ConfigurationAgentMismatch
    ));
    assert_eq!(public_metadata(&root.database(), conversation_id), before);
    store.shutdown().await.expect("shutdown rejection store");
}

#[tokio::test]
async fn recovery_scan_fences_configuration_until_the_frozen_cut_finishes() {
    // 威胁场景：恢复扫描冻结一致性 cut 后若仍接受 Configure，event/configuration/ledger
    // 会跨越该 cut，导致恢复流程认证到混合时点。
    let root = TestRoot::new("recovery-fence");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x27);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open recovery fence store");
    store
        .create_conversation(input)
        .await
        .expect("create recovery fence conversation");
    let request = configure_request(
        conversation_id,
        0x3C,
        "recovery-fence",
        0,
        codex_configuration(CodexReasoningEffort::Medium),
    );
    let before = public_metadata(&root.database(), conversation_id);

    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin frozen recovery cut");
    assert!(matches!(
        store
            .configure_conversation(request.clone())
            .await
            .expect_err("Configure must be fenced during recovery"),
        RuntimeStoreError::RecoveryInProgress
    ));
    assert_eq!(public_metadata(&root.database(), conversation_id), before);

    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load only recovery page");
    store
        .finish_recovery_scan(page.completion.expect("terminal recovery page"))
        .await
        .expect("finish frozen recovery cut");
    let applied = applied(
        store
            .configure_conversation(request)
            .await
            .expect("Configure resumes after recovery finishes"),
    );
    assert_eq!(applied.configuration_revision, 1);
    store
        .shutdown()
        .await
        .expect("shutdown recovery fence store");
}

#[tokio::test]
#[ignore = "真实 production writer 写满单会话 4,096 版的慢门禁"]
async fn production_writer_rejects_one_past_configuration_quota_without_writing() {
    // 威胁场景：已认证客户端持续使用新 key 填满 append-only configuration journal；
    // one-past 若在写入 event/head/ledger 后才拒绝，会留下不可恢复的半提交状态。
    const EXACT_CONVERSATION_LIMIT: u64 = 4_096;

    let root = TestRoot::new("production-quota-boundary");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x28);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open production quota store");
    store
        .create_conversation(input)
        .await
        .expect("create production quota conversation");

    for expected_revision in 0..EXACT_CONVERSATION_LIMIT {
        let record = applied(
            store
                .configure_conversation(configure_request(
                    conversation_id,
                    0x3D,
                    &format!("quota-{expected_revision}"),
                    expected_revision,
                    codex_configuration(CodexReasoningEffort::Medium),
                ))
                .await
                .expect("every configuration through the exact limit is legal"),
        );
        assert_eq!(record.configuration_revision, expected_revision + 1);
    }

    let exact = public_metadata(&root.database(), conversation_id);
    assert_eq!(exact.configuration_rows, 4_096);
    assert_eq!(exact.ledger_configuration_rows, 4_096);
    let error = store
        .configure_conversation(configure_request(
            conversation_id,
            0x3D,
            "quota-one-past",
            EXACT_CONVERSATION_LIMIT,
            codex_configuration(CodexReasoningEffort::Medium),
        ))
        .await
        .expect_err("one-past configuration quota must reject before writing");
    assert!(matches!(
        error,
        RuntimeStoreError::ConfigurationLimit {
            scope: ConfigurationLimitScope::Conversation,
        }
    ));
    assert_eq!(public_metadata(&root.database(), conversation_id), exact);
    store.shutdown().await.expect("shutdown full quota store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen exact quota store");
    assert_eq!(public_metadata(&root.database(), conversation_id), exact);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened quota store");
}

#[tokio::test]
async fn before_and_after_commit_faults_converge_without_duplicate_charge() {
    for (label, operation) in [
        (
            "before-commit",
            RuntimeStoreOperation::ConfigureConversationBeforeCommit,
        ),
        (
            "after-commit",
            RuntimeStoreOperation::ConfigureConversationAfterCommit,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let input = conversation(if label == "before-commit" { 0x25 } else { 0x26 });
        let conversation_id = input.conversation_id;
        let request = configure_request(
            conversation_id,
            0x3B,
            label,
            0,
            codex_configuration(CodexReasoningEffort::Medium),
        );
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database())
                .with_fault_injector(Arc::new(OneShotFault::new(operation))),
            root.storage_kek(&keys),
        )
        .await
        .expect("open fault store");
        store
            .create_conversation(input)
            .await
            .expect("create fault conversation");
        let before = public_metadata(&root.database(), conversation_id);
        let error = store
            .configure_conversation(request.clone())
            .await
            .expect_err("injected configuration write must fail once");
        if operation == RuntimeStoreOperation::ConfigureConversationBeforeCommit {
            assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
            assert_eq!(public_metadata(&root.database(), conversation_id), before);
        } else {
            assert!(matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::ConfigureConversation,
                }
            ));
        }
        let record = if operation == RuntimeStoreOperation::ConfigureConversationBeforeCommit {
            applied(
                store
                    .configure_conversation(request.clone())
                    .await
                    .expect("retry rolled-back Configure"),
            )
        } else {
            replayed(
                store
                    .configure_conversation(request.clone())
                    .await
                    .expect("retry committed Configure"),
            )
        };
        assert_eq!(record.configuration_revision, 1);
        let committed = public_metadata(&root.database(), conversation_id);
        assert_eq!(committed.event_rows, before.event_rows + 1);
        assert_eq!(committed.configuration_rows, before.configuration_rows + 1);
        store.shutdown().await.expect("shutdown fault store");

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("reopen fault store");
        assert_eq!(
            replayed(
                reopened
                    .configure_conversation(request)
                    .await
                    .expect("reopen exact retry")
            ),
            record
        );
        assert_eq!(
            public_metadata(&root.database(), conversation_id),
            committed
        );
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened fault store");
    }
}

#[tokio::test]
async fn configuration_row_event_head_ledger_and_aad_tamper_fail_closed() {
    for tamper in [
        ConfigurationTamper::ConfigurationMetadata,
        ConfigurationTamper::SealedRequest,
        ConfigurationTamper::StateHead,
        ConfigurationTamper::EventPayload,
        ConfigurationTamper::RuntimeLedger,
        ConfigurationTamper::DeleteConfiguration,
        ConfigurationTamper::DeleteEvent,
        ConfigurationTamper::SwapRequests,
    ] {
        assert_configuration_tamper_rejected(tamper).await;
    }
}
