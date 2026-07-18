use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::ConversationMetadataMutation;
use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    ConversationDescriptor, IdempotencyOwner, MAX_CONVERSATION_DESCRIPTOR_BYTES,
    MetadataMutationRecord, NewConversation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreHandle, UpdateConversationMetadataOutcome,
    UpdateManagedConversationMetadata,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, ToSql, Transaction};
use sha2::{Digest, Sha256};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const RUNTIME_DB_HARD_LIMIT_BYTES: u64 = 2 * GIB;
const MIN_FILESYSTEM_RESERVE_BYTES: u64 = 512 * MIB;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-metadata-capacity-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create metadata capacity test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure metadata capacity test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load metadata capacity StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct MutableCapacityProbe(Arc<Mutex<RuntimeCapacityObservation>>);

impl MutableCapacityProbe {
    fn new(observation: RuntimeCapacityObservation) -> Self {
        Self(Arc::new(Mutex::new(observation)))
    }

    fn set(&self, observation: RuntimeCapacityObservation) {
        *self.0.lock().expect("capacity probe lock") = observation;
    }
}

impl RuntimeCapacityProbe for MutableCapacityProbe {
    fn observe(
        &self,
        _storage_path: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        Ok(*self.0.lock().expect("capacity probe lock"))
    }
}

fn healthy_capacity() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        main_bytes: 8 * MIB,
        wal_bytes: 2 * MIB,
        shm_bytes: 32 * 1024,
        filesystem_total_bytes: 20 * GIB,
        filesystem_available_bytes: 4 * GIB,
    }
}

fn projection_probe_capacity() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        filesystem_total_bytes: 4 * GIB,
        filesystem_available_bytes: MIN_FILESYSTEM_RESERVE_BYTES,
        ..healthy_capacity()
    }
}

fn over_limit_capacity() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        main_bytes: RUNTIME_DB_HARD_LIMIT_BYTES + 1,
        wal_bytes: 0,
        shm_bytes: 0,
        filesystem_available_bytes: 8 * GIB,
        ..healthy_capacity()
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn near_limit_descriptor() -> (ConversationDescriptor, usize) {
    const HEADROOM: usize = 256;
    let target = MAX_CONVERSATION_DESCRIPTOR_BYTES - HEADROOM;
    let mut low = 1_usize;
    let mut high = MAX_CONVERSATION_DESCRIPTOR_BYTES;
    let mut best = None;
    while low <= high {
        let middle = low + (high - low) / 2;
        let descriptor = ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some("metadata-capacity".to_owned()),
            cwd: PathBuf::from(format!("/tmp/{}", "x".repeat(middle))),
        };
        let encoded_len = serde_json::to_vec(&descriptor)
            .expect("serialize candidate descriptor")
            .len();
        if encoded_len <= target {
            best = Some((descriptor, encoded_len));
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }
    let (descriptor, encoded_len) = best.expect("find a valid near-limit descriptor");
    assert!(encoded_len <= MAX_CONVERSATION_DESCRIPTOR_BYTES);
    assert!(
        encoded_len >= MAX_CONVERSATION_DESCRIPTOR_BYTES - 512,
        "descriptor must remain within 512 bytes of the 1 MiB bound, got {encoded_len}"
    );
    (descriptor, encoded_len)
}

fn conversation(seed: u8) -> (NewConversation, usize) {
    let (descriptor, encoded_len) = near_limit_descriptor();
    (
        NewConversation {
            conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
            descriptor,
        },
        encoded_len,
    )
}

fn owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0xA1; 32],
        uid: 501,
        client_installation_id: [0x31; 16],
    }
}

fn request(
    conversation_id: RuntimeId,
    key: &str,
    expected_entry_revision: u64,
    archived: bool,
) -> UpdateManagedConversationMetadata {
    UpdateManagedConversationMetadata {
        conversation_id,
        owner: owner(),
        idempotency_key: key.to_owned(),
        expected_entry_revision,
        mutation: ConversationMetadataMutation::SetArchived { archived },
    }
}

fn applied(outcome: UpdateConversationMetadataOutcome) -> MetadataMutationRecord {
    match outcome {
        UpdateConversationMetadataOutcome::Applied { mutation } => mutation,
        other => panic!("expected applied metadata mutation, got {other:?}"),
    }
}

fn replayed(outcome: UpdateConversationMetadataOutcome) -> MetadataMutationRecord {
    match outcome {
        UpdateConversationMetadataOutcome::Replayed { mutation } => mutation,
        other => panic!("expected replayed metadata mutation, got {other:?}"),
    }
}

fn disk_low_required(error: RuntimeStoreError) -> u64 {
    match error {
        RuntimeStoreError::DiskLow {
            available_bytes,
            required_available_bytes,
        } => {
            assert_eq!(available_bytes, MIN_FILESYSTEM_RESERVE_BYTES);
            required_available_bytes
        }
        other => panic!("expected DiskLow, got {other:?}"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TableDigest {
    rows: usize,
    sha256: [u8; 32],
}

fn update_cell_digest(hasher: &mut Sha256, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update([0]),
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        ValueRef::Real(value) => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => {
            hasher.update([3]);
            hasher.update(value.len().to_be_bytes());
            hasher.update(value);
        }
        ValueRef::Blob(value) => {
            hasher.update([4]);
            hasher.update(value.len().to_be_bytes());
            hasher.update(value);
        }
    }
}

fn table_digest(
    transaction: &Transaction<'_>,
    sql: &str,
    parameters: &[&dyn ToSql],
) -> TableDigest {
    let mut statement = transaction.prepare(sql).expect("prepare evidence digest");
    let column_count = statement.column_count();
    let mut hasher = Sha256::new();
    for column in statement.column_names() {
        hasher.update(column.len().to_be_bytes());
        hasher.update(column.as_bytes());
    }
    let mut query = statement.query(parameters).expect("query evidence digest");
    let mut rows = 0_usize;
    while let Some(row) = query.next().expect("iterate evidence digest") {
        hasher.update([0xFF]);
        for index in 0..column_count {
            update_cell_digest(
                &mut hasher,
                row.get_ref(index).expect("read evidence digest cell"),
            );
        }
        rows += 1;
    }
    TableDigest {
        rows,
        sha256: hasher.finalize().into(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MetadataEvidence {
    conversation_catalog_revision: String,
    event_high_water: Option<String>,
    lifecycle: String,
    entry_revision: String,
    catalog_high_water: Option<String>,
    metadata_count: i64,
    active_metadata_count: i64,
    metadata_charged_bytes: i64,
    catalog_delta_count: i64,
    catalog_delta_bytes: i64,
    event_count: i64,
    audit_event_bytes: i64,
    event_stream_count: i64,
    event_stream_bytes: i64,
    runtime_meta: TableDigest,
    conversation: TableDigest,
    conversation_state: TableDigest,
    catalog: TableDigest,
    event_journal: TableDigest,
    event_stream: TableDigest,
    metadata_ledger: TableDigest,
}

fn metadata_evidence(path: &Path, conversation_id: RuntimeId) -> MetadataEvidence {
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only metadata capacity evidence");
    let transaction = connection
        .transaction()
        .expect("begin consistent metadata capacity evidence transaction");
    let (
        conversation_catalog_revision,
        event_high_water,
        lifecycle,
        entry_revision,
        catalog_high_water,
        metadata_count,
        active_metadata_count,
        metadata_charged_bytes,
        catalog_delta_count,
        catalog_delta_bytes,
        event_count,
        audit_event_bytes,
        event_stream_count,
        event_stream_bytes,
    ) = transaction
        .query_row(
            "SELECT c.catalog_revision, c.event_high_water, c.lifecycle, s.entry_revision,
                    m.catalog_high_water, m.metadata_mutation_count,
                    m.active_metadata_mutation_count, m.metadata_mutation_charged_bytes,
                    m.catalog_delta_count, m.catalog_delta_bytes, m.event_count,
                    m.audit_event_logical_bytes, m.event_stream_count, m.event_stream_bytes
             FROM runtime_meta AS m
             JOIN conversations AS c ON c.conversation_id = ?1
             JOIN conversation_state AS s ON s.conversation_id = c.conversation_id
             WHERE m.singleton = 1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                ))
            },
        )
        .expect("read metadata capacity ledger evidence");
    let conversation_bytes: &[u8] = conversation_id.as_bytes();
    let target: [&dyn ToSql; 1] = [&conversation_bytes];
    let evidence = MetadataEvidence {
        conversation_catalog_revision,
        event_high_water,
        lifecycle,
        entry_revision,
        catalog_high_water,
        metadata_count,
        active_metadata_count,
        metadata_charged_bytes,
        catalog_delta_count,
        catalog_delta_bytes,
        event_count,
        audit_event_bytes,
        event_stream_count,
        event_stream_bytes,
        runtime_meta: table_digest(
            &transaction,
            "SELECT * FROM runtime_meta WHERE singleton = 1 ORDER BY singleton",
            &[],
        ),
        conversation: table_digest(
            &transaction,
            "SELECT * FROM conversations WHERE conversation_id = ?1 ORDER BY conversation_id",
            &target,
        ),
        conversation_state: table_digest(
            &transaction,
            "SELECT * FROM conversation_state WHERE conversation_id = ?1 ORDER BY conversation_id",
            &target,
        ),
        catalog: table_digest(
            &transaction,
            "SELECT * FROM catalog_journal WHERE conversation_id = ?1 ORDER BY catalog_revision",
            &target,
        ),
        event_journal: table_digest(
            &transaction,
            "SELECT * FROM event_journal WHERE conversation_id = ?1 ORDER BY event_seq",
            &target,
        ),
        event_stream: table_digest(
            &transaction,
            "SELECT * FROM event_stream_index WHERE conversation_id = ?1 ORDER BY event_seq",
            &target,
        ),
        metadata_ledger: table_digest(
            &transaction,
            "SELECT * FROM metadata_mutation_ledger
             WHERE conversation_id = ?1 ORDER BY created_at_ms, idempotency_token",
            &target,
        ),
    };
    transaction
        .commit()
        .expect("finish metadata capacity evidence transaction");
    evidence
}

fn assert_ledger_matches_physical(evidence: &MetadataEvidence) {
    assert_eq!(
        i64::try_from(evidence.catalog.rows).expect("catalog row count fits i64"),
        evidence.catalog_delta_count
    );
    assert_eq!(
        i64::try_from(evidence.metadata_ledger.rows).expect("metadata row count fits i64"),
        evidence.metadata_count
    );
    assert_eq!(
        i64::try_from(evidence.event_journal.rows).expect("event row count fits i64"),
        evidence.event_count
    );
    assert_eq!(
        i64::try_from(evidence.event_stream.rows).expect("event stream row count fits i64"),
        evidence.event_stream_count
    );
}

fn assert_one_applied_mutation(
    before: &MetadataEvidence,
    after: &MetadataEvidence,
    expected_revision: u64,
    expected_lifecycle: &str,
) {
    let revision = format!("{expected_revision:020}");
    assert_eq!(after.entry_revision, revision);
    assert_eq!(after.conversation_catalog_revision, revision);
    assert_eq!(after.catalog_high_water.as_deref(), Some(revision.as_str()));
    assert_eq!(after.lifecycle, expected_lifecycle);
    assert_eq!(after.metadata_count, before.metadata_count + 1);
    assert_eq!(after.metadata_ledger.rows, before.metadata_ledger.rows + 1);
    assert_eq!(after.active_metadata_count, 0);
    assert!(after.metadata_charged_bytes > before.metadata_charged_bytes);
    assert_eq!(after.catalog_delta_count, before.catalog_delta_count + 1);
    assert_eq!(after.catalog.rows, before.catalog.rows + 1);
    assert!(after.catalog_delta_bytes > before.catalog_delta_bytes);
    assert_eq!(after.event_high_water, before.event_high_water);
    assert_eq!(after.event_count, before.event_count);
    assert_eq!(after.audit_event_bytes, before.audit_event_bytes);
    assert_eq!(after.event_stream_count, before.event_stream_count);
    assert_eq!(after.event_stream_bytes, before.event_stream_bytes);
    assert_eq!(after.event_journal, before.event_journal);
    assert_eq!(after.event_stream, before.event_stream);
    assert_ledger_matches_physical(after);
}

#[tokio::test]
async fn disk_low_large_descriptor_projection_is_zero_write_and_same_handle_recovers() {
    let root = TestRoot::new("disk-low");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let (input, descriptor_bytes) = conversation(0x11);
    let conversation_id = input.conversation_id;
    let probe = MutableCapacityProbe::new(healthy_capacity());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open DiskLow metadata store");
    store
        .create_conversation(input)
        .await
        .expect("create near-limit descriptor conversation");
    let baseline = metadata_evidence(&database, conversation_id);
    assert_ledger_matches_physical(&baseline);

    probe.set(projection_probe_capacity());
    let stale = request(conversation_id, "project-old", 1, true);
    let stale_required = disk_low_required(
        store
            .update_managed_conversation_metadata(stale)
            .await
            .expect_err("stale request must still pass capacity admission before durable conflict"),
    );
    assert_eq!(metadata_evidence(&database, conversation_id), baseline);

    let archive = request(conversation_id, "project-new", 0, true);
    let valid_required = disk_low_required(
        store
            .update_managed_conversation_metadata(archive.clone())
            .await
            .expect_err("DiskLow must reject a fresh metadata mutation before COMMIT"),
    );
    assert_eq!(
        valid_required - stale_required,
        u64::try_from(2 * descriptor_bytes).expect("descriptor projection fits u64"),
        "fresh managed mutation must project one descriptor write plus one CatalogDelta copy"
    );
    assert_eq!(
        metadata_evidence(&database, conversation_id),
        baseline,
        "DiskLow must not drift conversation, catalog, event, or metadata ledger evidence"
    );

    probe.set(healthy_capacity());
    let archived = applied(
        store
            .update_managed_conversation_metadata(archive.clone())
            .await
            .expect("same handle must recover and apply after DiskLow clears"),
    );
    assert_eq!((archived.entry_revision, archived.catalog_revision), (1, 1));
    let applied_evidence = metadata_evidence(&database, conversation_id);
    assert_one_applied_mutation(&baseline, &applied_evidence, 1, "archived");

    probe.set(projection_probe_capacity());
    assert_eq!(
        replayed(
            store
                .update_managed_conversation_metadata(archive)
                .await
                .expect("exact replay must bypass DiskLow admission"),
        ),
        archived
    );
    assert_eq!(
        metadata_evidence(&database, conversation_id),
        applied_evidence,
        "DiskLow exact replay must remain read-only"
    );

    probe.set(healthy_capacity());
    store
        .shutdown()
        .await
        .expect("shutdown recovered DiskLow metadata store");
}

#[tokio::test]
async fn store_full_latches_new_metadata_until_reopen_but_exact_replay_stays_read_only() {
    let root = TestRoot::new("store-full");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let (input, descriptor_bytes) = conversation(0x21);
    assert!(descriptor_bytes >= MAX_CONVERSATION_DESCRIPTOR_BYTES - 512);
    let conversation_id = input.conversation_id;
    let probe = MutableCapacityProbe::new(healthy_capacity());
    let config = RuntimeStoreConfig::new(database.clone()).with_capacity_probe(probe.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open StoreFull metadata store");
    store
        .create_conversation(input)
        .await
        .expect("create StoreFull near-limit descriptor conversation");

    let seed_request = request(conversation_id, "replay-seed", 0, true);
    let seed = applied(
        store
            .update_managed_conversation_metadata(seed_request.clone())
            .await
            .expect("apply replay seed before StoreFull"),
    );
    let baseline = metadata_evidence(&database, conversation_id);
    assert_ledger_matches_physical(&baseline);
    let blocked_request = request(conversation_id, "blocked-new", 1, false);

    probe.set(over_limit_capacity());
    let error = store
        .update_managed_conversation_metadata(blocked_request.clone())
        .await
        .expect_err("StoreFull must reject and latch a fresh metadata mutation");
    assert!(matches!(error, RuntimeStoreError::StoreFull { .. }));
    assert_eq!(error.code(), "daemon.runtime.store_full");
    assert_eq!(
        metadata_evidence(&database, conversation_id),
        baseline,
        "StoreFull must not drift conversation, catalog, event, or metadata ledger evidence"
    );

    assert_eq!(
        replayed(
            store
                .update_managed_conversation_metadata(seed_request.clone())
                .await
                .expect("exact replay must bypass StoreFull and SafetyOnly"),
        ),
        seed
    );
    assert_eq!(metadata_evidence(&database, conversation_id), baseline);

    probe.set(healthy_capacity());
    let latched = store
        .update_managed_conversation_metadata(blocked_request.clone())
        .await
        .expect_err("healthy capacity must not clear same-handle SafetyOnly");
    assert!(matches!(latched, RuntimeStoreError::SafetyOnly));
    assert_eq!(latched.code(), "daemon.runtime.safety_only");
    assert_eq!(metadata_evidence(&database, conversation_id), baseline);

    store
        .shutdown()
        .await
        .expect("shutdown StoreFull-latched metadata store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen metadata store after capacity recovers");
    assert_eq!(
        replayed(
            reopened
                .update_managed_conversation_metadata(seed_request)
                .await
                .expect("seed exact replay must remain read-only after reopen"),
        ),
        seed
    );
    assert_eq!(metadata_evidence(&database, conversation_id), baseline);

    let unarchived = applied(
        reopened
            .update_managed_conversation_metadata(blocked_request)
            .await
            .expect("reopen must clear the handle-local SafetyOnly latch"),
    );
    assert_eq!(
        (unarchived.entry_revision, unarchived.catalog_revision),
        (2, 2)
    );
    let recovered = metadata_evidence(&database, conversation_id);
    assert_one_applied_mutation(&baseline, &recovered, 2, "active");

    reopened
        .shutdown()
        .await
        .expect("shutdown recovered StoreFull metadata store");
}
