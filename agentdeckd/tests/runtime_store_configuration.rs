#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use agentdeckd::runtime::store::{
    ConfigurationRecord, ConfigureConversation, ConfigureConversationOutcome, IdempotencyOwner,
    NewConversation, RuntimeClock, RuntimeClockError, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreHandle,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, OpenFlags};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
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
    catalog_high_water: Option<String>,
    catalog_rows: i64,
    event_rows: i64,
    configuration_rows: i64,
}

fn public_metadata(path: &Path, conversation_id: RuntimeId) -> PublicMetadata {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only metadata connection");
    let (catalog_revision, updated_at_ms) = connection
        .query_row(
            "SELECT catalog_revision, updated_at_ms FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read conversation metadata");
    let catalog_high_water = connection
        .query_row(
            "SELECT catalog_high_water FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read catalog high-water");
    let (catalog_rows, event_rows, configuration_rows) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM catalog_journal),
                 (SELECT COUNT(*) FROM event_journal),
                 (SELECT COUNT(*) FROM configuration_journal)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read physical row counts");
    PublicMetadata {
        catalog_revision,
        updated_at_ms,
        catalog_high_water,
        catalog_rows,
        event_rows,
        configuration_rows,
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

fn applied(outcome: ConfigureConversationOutcome) -> ConfigurationRecord {
    match outcome {
        ConfigureConversationOutcome::Applied { configuration } => configuration,
        other => panic!("expected applied configuration, got {other:?}"),
    }
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
