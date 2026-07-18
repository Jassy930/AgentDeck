#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    CatalogChange, CatalogDelta, ConversationEntry, ConversationMetadataMutation,
};
use agentdeckd::runtime::store::{
    ConversationLifecycle, ConversationRecord, IdempotencyOwner, MarkConversationRecoveryBlocked,
    MetadataMutationRecord, NewConversation, RuntimeBackfillPlan, RuntimeBackfillTarget,
    RuntimeClock, RuntimeClockError, RuntimeCommitOperation, RuntimeId, RuntimeIdKind,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle,
    RuntimeStoreOperation, UpdateConversationMetadataOutcome, UpdateManagedConversationMetadata,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, OpenFlags};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

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
                "injected metadata mutation fault",
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
            "agentdeckd-runtime-metadata-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create metadata test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure metadata test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load metadata test StorageKEK")
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
    lifecycle: String,
    entry_revision: String,
    catalog_high_water: Option<String>,
    metadata_count: i64,
    active_metadata_count: i64,
    metadata_charged_bytes: i64,
    ledger_event_count: i64,
    catalog_rows: i64,
    event_rows: i64,
    metadata_rows: i64,
}

#[derive(Debug, Eq, PartialEq)]
struct ObservableMetadataState {
    public: PublicMetadata,
    conversation: ConversationRecord,
    catalog_payload: Vec<u8>,
}

fn public_metadata(path: &Path, conversation_id: RuntimeId) -> PublicMetadata {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only metadata observer");
    let (catalog_revision, updated_at_ms, event_high_water, lifecycle) = connection
        .query_row(
            "SELECT catalog_revision, updated_at_ms, event_high_water, lifecycle
             FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read conversation metadata");
    let entry_revision = connection
        .query_row(
            "SELECT entry_revision FROM conversation_state WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read entry revision");
    let (
        catalog_high_water,
        metadata_count,
        active_metadata_count,
        metadata_charged_bytes,
        ledger_event_count,
    ) = connection
        .query_row(
            "SELECT catalog_high_water, metadata_mutation_count,
                    active_metadata_mutation_count, metadata_mutation_charged_bytes,
                    event_count
             FROM runtime_meta WHERE singleton = 1",
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
        .expect("read metadata ledger totals");
    let (catalog_rows, event_rows, metadata_rows) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM catalog_journal),
                 (SELECT COUNT(*) FROM event_journal),
                 (SELECT COUNT(*) FROM metadata_mutation_ledger)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read physical metadata rows");
    PublicMetadata {
        catalog_revision,
        updated_at_ms,
        event_high_water,
        lifecycle,
        entry_revision,
        catalog_high_water,
        metadata_count,
        active_metadata_count,
        metadata_charged_bytes,
        ledger_event_count,
        catalog_rows,
        event_rows,
        metadata_rows,
    }
}

async fn catalog_deltas(store: &RuntimeStoreHandle) -> Vec<CatalogDelta> {
    let RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("freeze catalog readback")
    else {
        panic!("created conversation must have a retained catalog range");
    };
    let mut after = None;
    let mut deltas = Vec::new();
    loop {
        let page = store
            .load_catalog_backfill_page(pin.clone(), after)
            .await
            .expect("load catalog readback page");
        deltas.extend(page.deltas.iter().cloned());
        let next_after = page.next_after;
        let complete = page.complete;
        store
            .complete_backfill_page(page.completion().clone())
            .await
            .expect("complete catalog readback page");
        if complete {
            break;
        }
        after = Some(next_after);
    }
    deltas
}

async fn observable_metadata_state(
    store: &RuntimeStoreHandle,
    path: &Path,
    conversation_id: RuntimeId,
) -> ObservableMetadataState {
    let recovery = runtime_recovery::load_recovery_state(store)
        .await
        .expect("load authenticated metadata descriptor");
    let conversation = recovery
        .conversations
        .into_iter()
        .find(|conversation| conversation.conversation_id == conversation_id)
        .expect("metadata conversation must be recoverable");
    let catalog_payload = serde_json::to_vec(&catalog_deltas(store).await)
        .expect("serialize authenticated catalog payload");
    ObservableMetadataState {
        public: public_metadata(path, conversation_id),
        conversation,
        catalog_payload,
    }
}

fn catalog_upsert(deltas: &[CatalogDelta], revision: u64) -> &ConversationEntry {
    let delta = deltas
        .iter()
        .find(|delta| delta.catalog_revision == revision)
        .expect("catalog revision must be retained");
    match delta.changes.as_slice() {
        [CatalogChange::Upserted { entry }] => entry,
        changes => panic!("revision {revision} must contain one upsert, got {changes:?}"),
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn conversation(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: runtime_descriptor::descriptor(format!("metadata-{seed}").as_bytes()),
    }
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0xA1; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

fn request(
    conversation_id: RuntimeId,
    key: &str,
    expected_entry_revision: u64,
    mutation: ConversationMetadataMutation,
) -> UpdateManagedConversationMetadata {
    UpdateManagedConversationMetadata {
        conversation_id,
        owner: owner(0x31),
        idempotency_key: key.to_owned(),
        expected_entry_revision,
        mutation,
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

fn conflict(outcome: UpdateConversationMetadataOutcome) -> u64 {
    match outcome {
        UpdateConversationMetadataOutcome::Conflict {
            current_entry_revision,
        } => current_entry_revision,
        other => panic!("expected metadata revision conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn interleaved_metadata_mutations_share_catalog_revision_and_keep_entry_revisions_local() {
    let root = TestRoot::new("interleaved-revisions");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock(Arc::new(AtomicU64::new(100)));
    let first_input = conversation(0x11);
    let second_input = conversation(0x12);
    let first_id = first_input.conversation_id;
    let second_id = second_input.conversation_id;
    let first_cwd = first_input.descriptor.cwd.clone();
    let second_descriptor = second_input.descriptor.clone();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open interleaved metadata store");

    let first_created = store
        .create_conversation(first_input)
        .await
        .expect("create first managed conversation");
    clock.set(110);
    let second_created = store
        .create_conversation(second_input)
        .await
        .expect("create second managed conversation");
    assert_eq!(
        (
            first_created.catalog_revision,
            second_created.catalog_revision
        ),
        (0, 1)
    );

    clock.set(200);
    let first_mutation = applied(
        store
            .update_managed_conversation_metadata(request(
                first_id,
                "first-rename",
                0,
                ConversationMetadataMutation::rename(Some("first-renamed".to_owned()))
                    .expect("valid first rename"),
            ))
            .await
            .expect("rename first conversation"),
    );
    clock.set(300);
    let second_mutation = applied(
        store
            .update_managed_conversation_metadata(request(
                second_id,
                "second-archive",
                0,
                ConversationMetadataMutation::SetArchived { archived: true },
            ))
            .await
            .expect("archive second conversation"),
    );
    assert_eq!(
        (
            first_mutation.catalog_revision,
            second_mutation.catalog_revision
        ),
        (2, 3),
        "catalog revision is global across interleaved conversations"
    );
    assert_eq!(
        (
            first_mutation.entry_revision,
            second_mutation.entry_revision
        ),
        (1, 1),
        "entry revision is independent per conversation"
    );

    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("read back interleaved descriptors");
    let first = recovery
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == first_id)
        .expect("first conversation readback");
    assert_eq!(first.catalog_revision, 2);
    assert_eq!(first.lifecycle, ConversationLifecycle::Active);
    assert_eq!(first.descriptor.title.as_deref(), Some("first-renamed"));
    assert_eq!(first.descriptor.cwd, first_cwd);
    assert_eq!(first.updated_at_ms, first_created.updated_at_ms);
    let second = recovery
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == second_id)
        .expect("second conversation readback");
    assert_eq!(second.catalog_revision, 3);
    assert_eq!(second.lifecycle, ConversationLifecycle::Archived);
    assert_eq!(second.descriptor, second_descriptor);
    assert_eq!(second.updated_at_ms, second_created.updated_at_ms);

    let first_public = public_metadata(&root.database(), first_id);
    let second_public = public_metadata(&root.database(), second_id);
    assert_eq!(first_public.entry_revision, "00000000000000000001");
    assert_eq!(first_public.catalog_revision, "00000000000000000002");
    assert_eq!(first_public.lifecycle, "active");
    assert_eq!(second_public.entry_revision, "00000000000000000001");
    assert_eq!(second_public.catalog_revision, "00000000000000000003");
    assert_eq!(second_public.lifecycle, "archived");
    assert_eq!(
        first_public.catalog_high_water.as_deref(),
        Some("00000000000000000003")
    );
    assert_eq!(
        second_public.catalog_high_water,
        first_public.catalog_high_water
    );
    assert_eq!(first_public.metadata_count, 2);
    assert_eq!(second_public.metadata_count, 2);

    let deltas = catalog_deltas(&store).await;
    assert_eq!(
        deltas
            .iter()
            .map(|delta| delta.catalog_revision)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    let first_entry = catalog_upsert(&deltas, 2);
    assert_eq!(
        first_entry.conversation_id.as_str(),
        first_id.to_canonical_string()
    );
    assert_eq!(first_entry.title.as_deref(), Some("first-renamed"));
    assert_eq!(first_entry.cwd.as_ref(), Some(&first_cwd));
    assert_eq!(first_entry.last_active_ms, first_created.updated_at_ms);
    assert!(!first_entry.archived);
    assert_eq!(first_entry.entry_revision, 1);
    let second_entry = catalog_upsert(&deltas, 3);
    assert_eq!(
        second_entry.conversation_id.as_str(),
        second_id.to_canonical_string()
    );
    assert_eq!(second_entry.title, second_descriptor.title);
    assert_eq!(second_entry.cwd.as_ref(), Some(&second_descriptor.cwd));
    assert_eq!(second_entry.last_active_ms, second_created.updated_at_ms);
    assert!(second_entry.archived);
    assert_eq!(second_entry.entry_revision, 1);

    store
        .shutdown()
        .await
        .expect("shutdown interleaved metadata store");
}

#[tokio::test]
async fn stale_conflict_is_durable_and_exact_retry_keeps_original_current_revision() {
    let root = TestRoot::new("durable-conflict");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock(Arc::new(AtomicU64::new(100)));
    let input = conversation(0x31);
    let conversation_id = input.conversation_id;
    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open durable conflict store");
    store
        .create_conversation(input)
        .await
        .expect("create durable conflict conversation");

    clock.set(200);
    applied(
        store
            .update_managed_conversation_metadata(request(
                conversation_id,
                "advance-to-one",
                0,
                ConversationMetadataMutation::rename(Some("revision-one".to_owned()))
                    .expect("valid first rename"),
            ))
            .await
            .expect("advance entry revision to one"),
    );
    let before_conflict =
        observable_metadata_state(&store, &root.database(), conversation_id).await;
    let stale = request(
        conversation_id,
        "durable-stale",
        0,
        ConversationMetadataMutation::SetArchived { archived: true },
    );

    clock.set(210);
    assert_eq!(
        conflict(
            store
                .update_managed_conversation_metadata(stale.clone())
                .await
                .expect("first stale request returns conflict"),
        ),
        1
    );
    let after_conflict = observable_metadata_state(&store, &root.database(), conversation_id).await;
    assert_eq!(after_conflict.conversation, before_conflict.conversation);
    assert_eq!(
        after_conflict.catalog_payload,
        before_conflict.catalog_payload
    );
    assert_eq!(
        after_conflict.public.metadata_rows,
        before_conflict.public.metadata_rows + 1,
        "the first conflict must have one durable idempotency row"
    );
    assert_eq!(
        after_conflict.public.metadata_count,
        before_conflict.public.metadata_count + 1,
        "durable conflict must be authenticated by runtime ledger totals"
    );
    assert_eq!(after_conflict.public.active_metadata_count, 0);
    assert!(
        after_conflict.public.metadata_charged_bytes
            > before_conflict.public.metadata_charged_bytes
    );

    clock.set(300);
    let advanced = applied(
        store
            .update_managed_conversation_metadata(request(
                conversation_id,
                "advance-to-two",
                1,
                ConversationMetadataMutation::rename(Some("revision-two".to_owned()))
                    .expect("valid second rename"),
            ))
            .await
            .expect("advance head after durable conflict"),
    );
    assert_eq!(advanced.entry_revision, 2);

    clock.set(0);
    assert_eq!(
        conflict(
            store
                .update_managed_conversation_metadata(stale.clone())
                .await
                .expect("exact conflict retry replays before clock validation"),
        ),
        1,
        "exact retry must replay the originally observed revision after head advances"
    );
    assert!(matches!(
        store
            .update_managed_conversation_metadata(request(
                conversation_id,
                "durable-stale",
                0,
                ConversationMetadataMutation::rename(Some("different-request".to_owned()))
                    .expect("valid different request"),
            ))
            .await,
        Err(RuntimeStoreError::IdempotencyConflict)
    ));
    clock.set(310);
    let future = request(
        conversation_id,
        "durable-future",
        9,
        ConversationMetadataMutation::SetArchived { archived: true },
    );
    assert_eq!(
        conflict(
            store
                .update_managed_conversation_metadata(future.clone())
                .await
                .expect("future revision is durably conflicted"),
        ),
        2
    );
    let before_reopen = observable_metadata_state(&store, &root.database(), conversation_id).await;
    assert_eq!(
        before_reopen.public.metadata_rows,
        after_conflict.public.metadata_rows + 2,
        "the independent head advance and future conflict each add one row"
    );

    store
        .shutdown()
        .await
        .expect("shutdown durable conflict store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen durable conflict store");
    assert_eq!(
        observable_metadata_state(&reopened, &root.database(), conversation_id).await,
        before_reopen
    );
    assert_eq!(
        conflict(
            reopened
                .update_managed_conversation_metadata(stale)
                .await
                .expect("durable conflict replays after reopen"),
        ),
        1
    );
    assert_eq!(
        conflict(
            reopened
                .update_managed_conversation_metadata(future)
                .await
                .expect("future conflict replays after reopen"),
        ),
        2
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened durable conflict store");
}

#[tokio::test]
async fn recovery_blocked_allows_rename_but_unarchive_is_zero_write() {
    let root = TestRoot::new("recovery-blocked-metadata");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock(Arc::new(AtomicU64::new(100)));
    let input = conversation(0x39);
    let conversation_id = input.conversation_id;
    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open recovery-blocked metadata store");
    store
        .create_conversation(input)
        .await
        .expect("create recovery-blocked metadata conversation");
    clock.set(150);
    store
        .mark_conversation_recovery_blocked(MarkConversationRecoveryBlocked {
            conversation_id,
            expected_command: None,
        })
        .await
        .expect("mark metadata conversation recovery blocked");
    let blocked = observable_metadata_state(&store, &root.database(), conversation_id).await;

    clock.set(200);
    let renamed = applied(
        store
            .update_managed_conversation_metadata(request(
                conversation_id,
                "blocked-rename",
                0,
                ConversationMetadataMutation::rename(Some("blocked but renamed".to_owned()))
                    .expect("valid recovery-blocked rename"),
            ))
            .await
            .expect("rename must preserve RecoveryBlocked"),
    );
    assert_eq!(renamed.entry_revision, 1);
    let after_rename = observable_metadata_state(&store, &root.database(), conversation_id).await;
    assert_eq!(
        after_rename.conversation.lifecycle,
        ConversationLifecycle::RecoveryBlocked
    );
    assert_eq!(
        after_rename.conversation.descriptor.title.as_deref(),
        Some("blocked but renamed")
    );
    assert_eq!(
        after_rename.conversation.updated_at_ms, blocked.conversation.updated_at_ms,
        "metadata rename must not change last activity"
    );

    let before_unarchive =
        observable_metadata_state(&store, &root.database(), conversation_id).await;
    clock.set(250);
    assert!(matches!(
        store
            .update_managed_conversation_metadata(request(
                conversation_id,
                "blocked-unarchive",
                1,
                ConversationMetadataMutation::SetArchived { archived: false },
            ))
            .await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert_eq!(
        observable_metadata_state(&store, &root.database(), conversation_id).await,
        before_unarchive,
        "RecoveryBlocked unarchive rejection must be zero-write"
    );

    store
        .shutdown()
        .await
        .expect("shutdown recovery-blocked metadata store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen recovery-blocked metadata store");
    assert_eq!(
        observable_metadata_state(&reopened, &root.database(), conversation_id).await,
        before_unarchive
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened recovery-blocked metadata store");
}

#[tokio::test]
async fn managed_rename_archive_replay_and_reopen_keep_independent_revisions() {
    let root = TestRoot::new("managed-roundtrip");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock(Arc::new(AtomicU64::new(100)));
    let input = conversation(0x21);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open metadata store");
    store
        .create_conversation(input)
        .await
        .expect("create managed conversation");
    let baseline = public_metadata(&root.database(), conversation_id);

    clock.set(200);
    let rename = request(
        conversation_id,
        "rename-1",
        0,
        ConversationMetadataMutation::rename(Some("renamed".to_owned())).expect("valid rename"),
    );
    let first = applied(
        store
            .update_managed_conversation_metadata(rename.clone())
            .await
            .expect("apply rename"),
    );
    assert_eq!((first.entry_revision, first.catalog_revision), (1, 1));

    clock.set(0);
    assert_eq!(
        replayed(
            store
                .update_managed_conversation_metadata(rename.clone())
                .await
                .expect("exact replay bypasses regressed clock"),
        ),
        first
    );
    assert!(matches!(
        store
            .update_managed_conversation_metadata(request(
                conversation_id,
                "rename-1",
                0,
                ConversationMetadataMutation::rename(Some("different".to_owned()))
                    .expect("valid conflicting rename"),
            ))
            .await,
        Err(RuntimeStoreError::IdempotencyConflict)
    ));
    clock.set(250);
    assert_eq!(
        conflict(
            store
                .update_managed_conversation_metadata(request(
                    conversation_id,
                    "stale",
                    0,
                    ConversationMetadataMutation::SetArchived { archived: true },
                ))
                .await
                .expect("stale revision is a typed conflict"),
        ),
        1
    );

    clock.set(300);
    let archived = applied(
        store
            .update_managed_conversation_metadata(request(
                conversation_id,
                "archive",
                1,
                ConversationMetadataMutation::SetArchived { archived: true },
            ))
            .await
            .expect("archive managed conversation"),
    );
    assert_eq!((archived.entry_revision, archived.catalog_revision), (2, 2));
    clock.set(400);
    let unarchived = applied(
        store
            .update_managed_conversation_metadata(request(
                conversation_id,
                "unarchive",
                2,
                ConversationMetadataMutation::SetArchived { archived: false },
            ))
            .await
            .expect("unarchive managed conversation"),
    );
    assert_eq!(
        (unarchived.entry_revision, unarchived.catalog_revision),
        (3, 3)
    );

    let current = public_metadata(&root.database(), conversation_id);
    assert_eq!(current.updated_at_ms, baseline.updated_at_ms);
    assert_eq!(current.event_high_water, baseline.event_high_water);
    assert_eq!(current.event_rows, baseline.event_rows);
    assert_eq!(current.ledger_event_count, baseline.ledger_event_count);
    assert_eq!(current.entry_revision, "00000000000000000003");
    assert_eq!(current.catalog_revision, "00000000000000000003");
    assert_eq!(
        current.catalog_high_water,
        Some(current.catalog_revision.clone())
    );
    assert_eq!(current.lifecycle, "active");
    assert_eq!(current.metadata_count, 4);
    assert_eq!(current.active_metadata_count, 0);
    assert!(current.metadata_charged_bytes > 0);
    assert_eq!(current.metadata_rows, 4);
    assert_eq!(current.catalog_rows, baseline.catalog_rows + 3);

    store.shutdown().await.expect("shutdown metadata store");
    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen metadata store");
    assert_eq!(
        replayed(
            reopened
                .update_managed_conversation_metadata(request(
                    conversation_id,
                    "unarchive",
                    2,
                    ConversationMetadataMutation::SetArchived { archived: false },
                ))
                .await
                .expect("replay survives reopen"),
        ),
        unarchived
    );
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn metadata_mutation_before_and_after_commit_faults_converge_exactly() {
    for (label, operation, expected_commit_unknown) in [
        (
            "before",
            RuntimeStoreOperation::UpdateConversationMetadataBeforeCommit,
            false,
        ),
        (
            "after",
            RuntimeStoreOperation::UpdateConversationMetadataAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let input = conversation(if expected_commit_unknown { 0x42 } else { 0x41 });
        let conversation_id = input.conversation_id;
        let original_descriptor = input.descriptor.clone();
        let config = RuntimeStoreConfig::new(root.database())
            .with_fault_injector(Arc::new(OneShotFault::new(operation)));
        let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
            .await
            .expect("open faulted metadata store");
        store
            .create_conversation(input)
            .await
            .expect("create faulted conversation");
        let baseline = observable_metadata_state(&store, &root.database(), conversation_id).await;
        let mutation = request(
            conversation_id,
            "fault-key",
            0,
            ConversationMetadataMutation::SetArchived { archived: true },
        );
        let error = store
            .update_managed_conversation_metadata(mutation.clone())
            .await
            .expect_err("one-shot metadata fault must surface");
        let after_fault =
            observable_metadata_state(&store, &root.database(), conversation_id).await;
        let resolved = if expected_commit_unknown {
            assert!(matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::UpdateConversationMetadata
                }
            ));
            assert_ne!(
                after_fault, baseline,
                "after-COMMIT fault must expose the already committed mutation"
            );
            replayed(
                store
                    .update_managed_conversation_metadata(mutation.clone())
                    .await
                    .expect("after-commit retry replays"),
            )
        } else {
            assert_eq!(
                after_fault, baseline,
                "before-COMMIT failure must leave public metadata, descriptor, and catalog bytes unchanged"
            );
            applied(
                store
                    .update_managed_conversation_metadata(mutation.clone())
                    .await
                    .expect("before-commit retry applies"),
            )
        };
        assert_eq!(resolved.entry_revision, 1);
        assert_eq!(resolved.catalog_revision, 1);
        let settled = observable_metadata_state(&store, &root.database(), conversation_id).await;
        if expected_commit_unknown {
            assert_eq!(
                settled, after_fault,
                "after-COMMIT retry must be byte-equivalent to the state visible after the unknown outcome"
            );
        } else {
            assert_ne!(
                settled, baseline,
                "successful retry must commit one mutation"
            );
        }
        assert_eq!(settled.conversation.descriptor, original_descriptor);
        assert_eq!(
            settled.conversation.lifecycle,
            ConversationLifecycle::Archived
        );
        assert_eq!(settled.conversation.catalog_revision, 1);
        assert_eq!(settled.public.updated_at_ms, baseline.public.updated_at_ms);
        assert_eq!(
            settled.public.event_high_water,
            baseline.public.event_high_water
        );
        assert_eq!(settled.public.event_rows, baseline.public.event_rows);
        assert_eq!(
            settled.public.ledger_event_count,
            baseline.public.ledger_event_count
        );
        assert_eq!(settled.public.entry_revision, "00000000000000000001");
        assert_eq!(settled.public.catalog_revision, "00000000000000000001");
        assert_eq!(settled.public.lifecycle, "archived");
        assert_eq!(
            settled.public.metadata_rows,
            baseline.public.metadata_rows + 1
        );
        assert_eq!(
            settled.public.metadata_count,
            baseline.public.metadata_count + 1
        );
        assert_eq!(settled.public.active_metadata_count, 0);
        assert_eq!(
            settled.public.catalog_rows,
            baseline.public.catalog_rows + 1
        );
        let settled_deltas: Vec<CatalogDelta> = serde_json::from_slice(&settled.catalog_payload)
            .expect("decode settled catalog payload");
        let settled_entry = catalog_upsert(&settled_deltas, 1);
        assert_eq!(
            settled_entry.conversation_id.as_str(),
            conversation_id.to_canonical_string()
        );
        assert_eq!(settled_entry.title, original_descriptor.title);
        assert_eq!(settled_entry.cwd.as_ref(), Some(&original_descriptor.cwd));
        assert_eq!(
            settled_entry.last_active_ms,
            baseline.conversation.updated_at_ms
        );
        assert!(settled_entry.archived);
        assert_eq!(settled_entry.entry_revision, 1);

        store
            .shutdown()
            .await
            .expect("shutdown faulted metadata store");
        let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
            .await
            .expect("reopen faulted metadata store");
        assert_eq!(
            observable_metadata_state(&reopened, &root.database(), conversation_id).await,
            settled,
            "reopen must preserve the complete settled metadata observation"
        );
        assert_eq!(
            replayed(
                reopened
                    .update_managed_conversation_metadata(mutation)
                    .await
                    .expect("reopened retry replays exact mutation"),
            ),
            resolved
        );
        assert_eq!(
            observable_metadata_state(&reopened, &root.database(), conversation_id).await,
            settled,
            "replay after reopen must not change public metadata, descriptor, or catalog payload"
        );
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened faulted metadata store");
    }
}
