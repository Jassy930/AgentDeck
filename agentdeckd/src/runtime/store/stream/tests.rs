use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::event::RuntimeEventBody;
use agentdeck_protocol::runtime::identity::{ConversationId, EventId};
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeFailure};
use rusqlite::{Connection, TransactionBehavior, params};

use super::*;
use crate::runtime::events::{CommandStreamEffects, SnapshotBuildPinCleanup};
use crate::runtime::model::{
    AcceptCommand, AcceptOutcome, ConversationDescriptor, IdempotencyOwner,
    MAX_CONVERSATION_DESCRIPTOR_BYTES, MAX_RUNTIME_EVENT_BYTES, NewConversation,
    RuntimeStoreConfig, StartCommand, StartOutcome,
};
use crate::runtime::store::identity::{RuntimeIdError, RuntimeIdSource};
use crate::runtime::store::schema::{
    RUNTIME_DDL_V1, RUNTIME_MIGRATION_V2, RUNTIME_MIGRATION_V3, RUNTIME_MIGRATION_V4,
};
use crate::runtime::store::sequence::encode_sequence;
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_RETENTION_ROOT: AtomicU64 = AtomicU64::new(1);

struct RetentionIdSource(VecDeque<super::super::RuntimeId>);

impl RuntimeIdSource for RetentionIdSource {
    fn next_id(
        &mut self,
        kind: super::super::RuntimeIdKind,
    ) -> Result<super::super::RuntimeId, RuntimeIdError> {
        let id = self.0.pop_front().expect("retention id available");
        if id.kind() != kind {
            return Err(RuntimeIdError::SourceKindMismatch {
                kind,
                actual: id.kind(),
            });
        }
        Ok(id)
    }
}

fn fixture() -> (
    Connection,
    RuntimeKeyBundle,
    [u8; 16],
    super::super::RuntimeId,
) {
    let connection = Connection::open_in_memory().expect("open fixture");
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("enable FKs");
    connection.execute_batch(RUNTIME_DDL_V1).expect("v1 DDL");
    connection
        .execute_batch(RUNTIME_MIGRATION_V2)
        .expect("v2 DDL");
    connection
        .execute_batch(RUNTIME_MIGRATION_V3)
        .expect("v3 DDL");
    connection
        .execute_batch(RUNTIME_MIGRATION_V4)
        .expect("v4 DDL");
    initialize_ephemeral_state(&connection).expect("TEMP pins");
    let key_bundle = RuntimeKeyBundle::fresh(1).expect("row keys");
    let database_id = [0x91; 16];
    let conversation_id =
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Conversation, [0x11; 16])
            .expect("conversation id");
    let adapter_state_key =
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::AdapterState, [0x22; 16])
            .expect("adapter state key");
    let descriptor = ConversationDescriptor {
        agent_kind: AgentKind::Codex,
        title: Some("stream fixture".into()),
        cwd: PathBuf::from("/tmp/stream-fixture"),
    };
    let descriptor_bytes = super::super::journal::canonical_conversation_descriptor(&descriptor)
        .expect("canonical descriptor");
    let catalog_revision = encode_sequence(0);
    let metadata_token = super::super::journal::conversation_metadata_token_for_test(
        &key_bundle,
        conversation_id,
        adapter_state_key,
        0,
        None,
        None,
        0,
        crate::runtime::model::ConversationLifecycle::Active,
        1,
        1,
    )
    .expect("conversation metadata token");
    let sealed_descriptor = seal_v4_row(
        &key_bundle,
        database_id,
        b"conversations",
        conversation_id.as_bytes(),
        b"sealed_descriptor",
        &descriptor_bytes,
        MAX_CONVERSATION_DESCRIPTOR_BYTES,
    )
    .expect("sealed conversation descriptor");
    connection
        .execute(
            "INSERT INTO conversations (
                     conversation_id, adapter_state_key, catalog_revision,
                     command_high_water, event_high_water, lifecycle,
                     created_at_ms, updated_at_ms, accepted_count,
                     metadata_token, sealed_descriptor
                 ) VALUES (?1, ?2, ?3, NULL, NULL, 'active', 1, 1, 0, ?4, ?5)",
            params![
                &conversation_id.as_bytes()[..],
                &adapter_state_key.as_bytes()[..],
                &catalog_revision,
                &metadata_token[..],
                sealed_descriptor,
            ],
        )
        .expect("conversation row");
    super::super::journal::load_conversation(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
    )
    .expect("fixture conversation must satisfy the production authenticated decoder");
    {
        let transaction = connection
            .unchecked_transaction()
            .expect("retention transaction");
        insert_or_replace_retention(
            &transaction,
            &key_bundle,
            conversation_id.as_bytes(),
            None,
            None,
            0,
            0,
        )
        .expect("empty retention row");
        transaction.commit().expect("commit retention row");
    }
    (connection, key_bundle, database_id, conversation_id)
}

fn open_retention_state(
    label: &str,
) -> (
    PathBuf,
    RuntimeStoreConfig,
    super::super::sqlite::RuntimeSqlite,
) {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-retention-{label}-{}-{}",
        std::process::id(),
        NEXT_RETENTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create retention test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure retention test root");
    }
    let ids = [
        (super::super::RuntimeIdKind::Command, 0x80),
        (super::super::RuntimeIdKind::Turn, 0x81),
        (super::super::RuntimeIdKind::Event, 0x82),
        (super::super::RuntimeIdKind::Command, 0x83),
        (super::super::RuntimeIdKind::Turn, 0x84),
        (super::super::RuntimeIdKind::Event, 0x85),
    ]
    .into_iter()
    .map(|(kind, seed)| {
        super::super::RuntimeId::from_bytes(kind, [seed; 16]).expect("retention runtime id")
    })
    .collect();
    let config =
        RuntimeStoreConfig::new(root.join("runtime.db")).with_id_source(RetentionIdSource(ids));
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create retention test KEK");
    let state = super::super::sqlite::open(&config, kek).expect("open retention store");
    (root, config, state)
}

fn create_conversation_with_event(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    seed: u8,
    expected_event_seed: u8,
) -> super::super::RuntimeId {
    let conversation_id =
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Conversation, [seed; 16])
            .expect("conversation id");
    let input = NewConversation {
        conversation_id,
        adapter_state_key: super::super::RuntimeId::from_bytes(
            super::super::RuntimeIdKind::AdapterState,
            [seed.wrapping_add(0x40); 16],
        )
        .expect("adapter state key"),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some(format!("retention-{seed}")),
            cwd: PathBuf::from("/tmp/retention-production-gate"),
        },
    };
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("canonical descriptor");
    let mut effects = CommandStreamEffects::default();
    super::super::journal::create_conversation(state, config, input, descriptor, &mut effects)
        .expect("create retention conversation");
    let command_id = match super::super::journal::accept_command(
        state,
        config,
        AcceptCommand {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [seed; 32],
                uid: 501,
                client_installation_id: [seed.wrapping_add(1); 16],
            },
            idempotency_key: format!("retention-command-{seed}"),
            payload: b"retention prompt".to_vec(),
        },
        &mut effects,
    )
    .expect("accept retention command")
    {
        AcceptOutcome::Accepted { command, .. } => command.command_id,
        AcceptOutcome::Replayed { .. } => panic!("first retention command cannot replay"),
    };
    let expected_event_id = super::super::RuntimeId::from_bytes(
        super::super::RuntimeIdKind::Event,
        [expected_event_seed; 16],
    )
    .expect("expected event id");
    match super::super::journal::mark_started_with_event(
        state,
        config,
        StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: super::super::RuntimeId::from_bytes(
                super::super::RuntimeIdKind::DaemonBoot,
                [seed.wrapping_add(0x60); 16],
            )
            .expect("daemon boot id"),
            execution_nonce: vec![seed; 16],
        },
        super::super::command_event::StartEventSource::Canonical,
        &mut effects,
    )
    .expect("append retention event")
    {
        StartOutcome::Started { event, .. } => assert_eq!(event.event_id, expected_event_id),
        StartOutcome::Replayed { .. } => panic!("first retention start cannot replay"),
    }
    conversation_id
}

fn store_ready_snapshot(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    conversation_id: super::super::RuntimeId,
    seed: u8,
) {
    let now_ms = config.clock.now_ms().expect("snapshot test clock");
    let pin = acquire_snapshot_build_pin(state, conversation_id, now_ms)
        .expect("acquire production snapshot pin");
    assert_eq!(pin.base_event_seq(), Some(0));
    let (cleanup_tx, _cleanup_rx) = tokio::sync::mpsc::unbounded_channel();
    let cleanup = SnapshotBuildPinCleanup::new(pin.clone(), cleanup_tx);
    let mut payload = Vec::with_capacity(32 + super::super::cipher::ROW_BLOB_V1_OVERHEAD_LEN);
    payload.resize(32, seed);
    let write = super::super::PreparedConversationSnapshotWrite::new(pin, 1, payload, cleanup);
    super::super::snapshot::store_conversation_snapshot(state, config, write, now_ms)
        .expect("store authenticated ready snapshot");
}

fn freeze_exact_event_publication(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    conversation_id: super::super::RuntimeId,
    seed: u8,
) {
    let now_ms = config.clock.now_ms().expect("publication test clock");
    let stream_id = [seed; 16];
    let generation = [seed.wrapping_add(1); 16];
    super::super::publication::create_publication_stream(
        state,
        config,
        stream_id,
        super::super::publication::PublicationScope::Conversation(conversation_id),
        [seed.wrapping_add(2); 16],
        generation,
        now_ms,
    )
    .expect("create production publication stream");
    super::super::publication::freeze_publication(
        state,
        config,
        super::super::publication::FreezePublicationRequest {
            publication_id: [seed.wrapping_add(3); 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [seed.wrapping_add(4); 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: super::super::publication::PublicationPayloadKind::Event,
            blob: vec![seed; 48],
        },
        now_ms,
    )
    .expect("freeze exact authenticated event publication");
}

fn canonical_event(
    conversation_id: super::super::RuntimeId,
    event_id: super::super::RuntimeId,
    event_seq: u64,
) -> Vec<u8> {
    let event = RuntimeEvent::new(
        ConversationId::new(conversation_id.to_canonical_string()),
        EventId::new(event_id.to_canonical_string()),
        event_seq,
        None,
        None,
        None,
        RuntimeEventBody::Error {
            failure: RuntimeFailure::new("daemon.test", "fixture"),
        },
    )
    .expect("canonical event");
    serde_json::to_vec(&event).expect("encode canonical event")
}

fn legacy_event(
    conversation_id: super::super::RuntimeId,
    event_id: super::super::RuntimeId,
    event_seq: u64,
) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&canonical_event(conversation_id, event_id, event_seq))
            .expect("event value");
    let object = value.as_object_mut().expect("event object");
    object.remove("commandId");
    object.remove("itemId");
    object.remove("entityId");
    serde_json::to_vec(&value).expect("legacy bytes")
}

fn insert_audit_event(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: super::super::RuntimeId,
    event_seq: u64,
    payload: &[u8],
) -> super::super::RuntimeId {
    let mut id = [0x60; 16];
    id[15] = u8::try_from(event_seq + 1).expect("small event seq");
    let event_id = super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
        .expect("event id");
    let event_seq_encoded = encode_sequence(event_seq);
    let logical_bytes = u64::try_from(payload.len()).expect("payload length");
    let created_at_ms = 10 + event_seq;
    let sealed = seal_v4_row(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        payload,
        MAX_RUNTIME_EVENT_BYTES,
    )
    .expect("seal audit event");
    let command = optional_field(None);
    let token = metadata_mac(
        key_bundle,
        b"event.metadata.v1",
        &[
            conversation_id.as_bytes(),
            event_id.as_bytes(),
            event_seq_encoded.as_bytes(),
            &command,
            &logical_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
    )
    .expect("audit event token");
    connection
        .execute(
            "INSERT INTO event_journal (
                     conversation_id, event_seq, event_id, command_id,
                     logical_event_bytes, created_at_ms, metadata_token, sealed_event
                 ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7)",
            params![
                &conversation_id.as_bytes()[..],
                &event_seq_encoded,
                &event_id.as_bytes()[..],
                sqlite_u64(logical_bytes).expect("logical bytes"),
                sqlite_u64(created_at_ms).expect("created time"),
                &token[..],
                sealed,
            ],
        )
        .expect("audit event row");
    let adapter_state_key =
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::AdapterState, [0x22; 16])
            .expect("adapter state key");
    let conversation_token = super::super::journal::conversation_metadata_token_for_test(
        key_bundle,
        conversation_id,
        adapter_state_key,
        0,
        None,
        Some(event_seq),
        0,
        crate::runtime::model::ConversationLifecycle::Active,
        1,
        1,
    )
    .expect("conversation metadata token");
    connection
        .execute(
            "UPDATE conversations
                 SET event_high_water = ?1, metadata_token = ?2
                 WHERE conversation_id = ?3",
            params![
                &event_seq_encoded,
                &conversation_token[..],
                &conversation_id.as_bytes()[..],
            ],
        )
        .expect("advance audit HWM");
    event_id
}

fn sealed_audit_bytes(connection: &Connection) -> Vec<Vec<u8>> {
    connection
        .prepare("SELECT sealed_event FROM event_journal ORDER BY event_seq")
        .expect("prepare audit evidence")
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query audit evidence")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect audit evidence")
}

#[test]
fn migration_indexes_only_maximum_publishable_suffix_across_legacy_and_fixed_rows() {
    let (mut connection, key_bundle, database_id, conversation_id) = fixture();
    let id0 = {
        let mut id = [0x60; 16];
        id[15] = 1;
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
            .expect("legacy id shape")
    };
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        0,
        &legacy_event(conversation_id, id0, 0),
    );
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        1,
        b"opaque-fixed-event",
    );
    let id2 = super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, {
        let mut id = [0x60; 16];
        id[15] = 3;
        id
    })
    .expect("canonical id shape");
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        2,
        &canonical_event(conversation_id, id2, 2),
    );
    let before = sealed_audit_bytes(&connection);
    let current = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        conversation_count: 1,
        event_count: 3,
        ..RuntimeLedger::default()
    };
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("migration transaction");
    let migrated =
        migrate_v4_rows(&transaction, &key_bundle, database_id, &current).expect("migrate v4 rows");
    transaction.commit().expect("commit migration fixture");
    let indexed: Vec<String> = connection
        .prepare("SELECT event_seq FROM event_stream_index ORDER BY event_seq")
        .expect("prepare index")
        .query_map([], |row| row.get(0))
        .expect("query index")
        .collect::<Result<_, _>>()
        .expect("collect index");
    assert_eq!(indexed, [encode_sequence(2)]);
    assert_eq!(migrated.event_stream_count, 1);
    assert_eq!(sealed_audit_bytes(&connection), before);
}

#[test]
fn opaque_last_event_migrates_to_empty_suffix_without_rewriting_audit() {
    let (mut connection, key_bundle, database_id, conversation_id) = fixture();
    let id0 = {
        let mut id = [0x60; 16];
        id[15] = 1;
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
            .expect("event id")
    };
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        0,
        &canonical_event(conversation_id, id0, 0),
    );
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        1,
        b"opaque-last",
    );
    let before = sealed_audit_bytes(&connection);
    let current = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        conversation_count: 1,
        event_count: 2,
        ..RuntimeLedger::default()
    };
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("migration transaction");
    let migrated =
        migrate_v4_rows(&transaction, &key_bundle, database_id, &current).expect("migrate v4 rows");
    transaction.commit().expect("commit migration fixture");
    assert_eq!(migrated.event_stream_count, 0);
    assert_eq!(sealed_audit_bytes(&connection), before);
}

#[test]
fn canonical_event_after_opaque_break_starts_a_new_contiguous_suffix() {
    let (mut connection, key_bundle, database_id, conversation_id) = fixture();
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        0,
        b"opaque-zero",
    );
    let requested = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        conversation_count: 1,
        event_count: 1,
        ..RuntimeLedger::default()
    };
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("first writer transaction");
    let (first, _first_targets) = reconcile_event_stream(
        &transaction,
        &key_bundle,
        database_id,
        &RuntimeLedger::default(),
        &requested,
    )
    .expect("reconcile opaque row");
    transaction.commit().expect("commit opaque row");
    assert_eq!(first.event_stream_count, 0);

    let id1 = {
        let mut id = [0x60; 16];
        id[15] = 2;
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
            .expect("event id")
    };
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        1,
        &canonical_event(conversation_id, id1, 1),
    );
    let mut requested = first.clone();
    requested.event_count = 2;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("second writer transaction");
    let (second, _second_targets) =
        reconcile_event_stream(&transaction, &key_bundle, database_id, &first, &requested)
            .expect("reconcile canonical suffix");
    transaction.commit().expect("commit canonical suffix");
    assert_eq!(second.event_stream_count, 1);
    let only: String = connection
        .query_row("SELECT event_seq FROM event_stream_index", [], |row| {
            row.get(0)
        })
        .expect("new suffix row");
    assert_eq!(only, encode_sequence(1));

    let state = super::super::sqlite::RuntimeSqlite {
        connection,
        key_bundle: std::sync::Arc::new(key_bundle),
        storage_path: PathBuf::from("/tmp/stream-unit-fixture.db"),
        database_id,
        admission_state: super::super::admission::RuntimeAdmissionState::Normal,
        recovery_scan: None,
        last_finished_recovery: None,
    };
    assert!(matches!(
        acquire_backfill_pin(
            &state,
            RuntimeBackfillTarget::Conversation(conversation_id),
            None,
            100,
        ),
        Err(RuntimeStoreError::BackfillNeedSnapshot)
    ));
    let RuntimeBackfillPlan::Pinned(pin) = acquire_backfill_pin(
        &state,
        RuntimeBackfillTarget::Conversation(conversation_id),
        Some(0),
        100,
    )
    .expect("pin suffix after opaque boundary") else {
        panic!("event one is a non-empty retained suffix");
    };
    let page = load_event_backfill_page(&state, &pin, Some(0), 100)
        .expect("load retained canonical suffix");
    assert!(page.complete);
    assert_eq!(page.next_after, 1);
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].event_seq, 1);
    complete_backfill_page(&state, page.completion(), 100).expect("ACK retained event page");
}

#[test]
fn pinned_reader_and_rows_survive_rejected_writer_trim() {
    let (mut connection, key_bundle, database_id, conversation_id) = fixture();
    let mut ledger = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        conversation_count: 1,
        ..RuntimeLedger::default()
    };
    for seq in 0..2 {
        let event_id = {
            let mut id = [0x60; 16];
            id[15] = u8::try_from(seq + 1).expect("small seq");
            super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
                .expect("event id")
        };
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            seq,
            &canonical_event(conversation_id, event_id, seq),
        );
        let mut requested = ledger.clone();
        requested.event_count += 1;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("append transaction");
        let (next_ledger, _targets) =
            reconcile_event_stream(&transaction, &key_bundle, database_id, &ledger, &requested)
                .expect("reconcile canonical event");
        ledger = next_ledger;
        transaction.commit().expect("commit canonical event");
    }
    let pin_id = [0x77; 16];
    connection
        .execute(
            "INSERT INTO temp.active_stream_pins (
                     pin_id, scope, target_id, first_seq, through_seq,
                     next_after_seq, expires_at_ms, state
                 ) VALUES (?1, 'event', ?2, ?3, ?4, NULL, 999999, 'active')",
            params![
                &pin_id[..],
                &conversation_id.as_bytes()[..],
                encode_sequence(0),
                encode_sequence(1),
            ],
        )
        .expect("active reader pin");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("writer trim transaction");
    assert!(matches!(
        trim_unrecorded_conversation_window(
            &transaction,
            &key_bundle,
            conversation_id.as_bytes(),
            true,
            1,
            1,
            MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
        ),
        Err(RuntimeStoreError::WorkerBusy {
            lane: crate::runtime::model::RuntimeStoreLane::Normal,
        })
    ));
    drop(transaction);
    let state: String = connection
        .query_row(
            "SELECT state FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin_id[..]],
            |row| row.get(0),
        )
        .expect("active pin");
    assert_eq!(state, "active");
    let retained: Vec<String> = connection
        .prepare("SELECT event_seq FROM event_stream_index ORDER BY event_seq")
        .expect("prepare retained rows")
        .query_map([], |row| row.get(0))
        .expect("query retained rows")
        .collect::<Result<_, _>>()
        .expect("collect retained rows");
    assert_eq!(retained, [encode_sequence(0), encode_sequence(1)]);

    connection
        .execute(
            "DELETE FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin_id[..]],
        )
        .expect("release reader pin");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("uncovered writer trim transaction");
    assert!(matches!(
        trim_unrecorded_conversation_window(
            &transaction,
            &key_bundle,
            conversation_id.as_bytes(),
            true,
            1,
            1,
            MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
        ),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    drop(transaction);
    let retained_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM event_stream_index", [], |row| {
            row.get(0)
        })
        .expect("count retained rows after rejected trim");
    assert_eq!(retained_count, 2);
}

#[test]
fn journal_retention_uses_10000_events_or_64mib_and_512mib_global() {
    assert_eq!(MAX_EVENT_STREAM_EVENTS_PER_CONVERSATION, 10_000);
    assert_eq!(MAX_EVENT_STREAM_BYTES_PER_CONVERSATION, 64 * 1024 * 1024);
    assert_eq!(MAX_EVENT_STREAM_EVENTS_GLOBAL, 131_072);
    assert_eq!(MAX_EVENT_STREAM_BYTES_GLOBAL, 512 * 1024 * 1024);

    // 使用 production reconciliation 建立 authenticated logical suffix，再以
    // 缩放阈值调用同一个 production trim helper，分别证明 count 与 bytes 是 OR。
    let (mut connection, key_bundle, database_id, conversation_id) = fixture();
    let mut ledger = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        conversation_count: 1,
        ..RuntimeLedger::default()
    };
    for seq in 0..4 {
        let event_id = {
            let mut id = [0x60; 16];
            id[15] = u8::try_from(seq + 1).expect("small scaled sequence");
            super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
                .expect("scaled event id")
        };
        insert_audit_event(
            &connection,
            &key_bundle,
            database_id,
            conversation_id,
            seq,
            &canonical_event(conversation_id, event_id, seq),
        );
        let mut requested = ledger.clone();
        requested.event_count += 1;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("scaled append transaction");
        let (next, _targets) =
            reconcile_event_stream(&transaction, &key_bundle, database_id, &ledger, &requested)
                .expect("reconcile scaled canonical event");
        transaction.commit().expect("commit scaled event");
        ledger = next;
    }

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("scaled per-conversation count trim");
    trim_unrecorded_conversation_window(
        &transaction,
        &key_bundle,
        conversation_id.as_bytes(),
        false,
        0,
        3,
        u64::MAX,
    )
    .expect("count cap trims oldest suffix row");
    transaction.commit().expect("commit count trim");
    let after_count: Vec<String> = connection
        .prepare(
            "SELECT event_seq FROM event_stream_index
                 WHERE conversation_id = ?1 ORDER BY event_seq",
        )
        .expect("prepare count-trim readback")
        .query_map([&conversation_id.as_bytes()[..]], |row| row.get(0))
        .expect("query count-trim readback")
        .collect::<Result<_, _>>()
        .expect("collect count-trim readback");
    assert_eq!(
        after_count,
        [encode_sequence(1), encode_sequence(2), encode_sequence(3)]
    );

    let newest_bytes: i64 = connection
        .query_row(
            "SELECT logical_event_bytes FROM event_stream_index
                 WHERE conversation_id = ?1 AND event_seq = ?2",
            params![&conversation_id.as_bytes()[..], encode_sequence(3)],
            |row| row.get(0),
        )
        .expect("newest logical event bytes");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("scaled per-conversation byte trim");
    trim_unrecorded_conversation_window(
        &transaction,
        &key_bundle,
        conversation_id.as_bytes(),
        false,
        0,
        u64::MAX,
        u64::try_from(newest_bytes).expect("positive logical event bytes"),
    )
    .expect("byte cap independently trims oldest suffix rows");
    transaction.commit().expect("commit byte trim");
    let after_bytes: Vec<String> = connection
        .prepare(
            "SELECT event_seq FROM event_stream_index
                 WHERE conversation_id = ?1 ORDER BY event_seq",
        )
        .expect("prepare byte-trim readback")
        .query_map([&conversation_id.as_bytes()[..]], |row| row.get(0))
        .expect("query byte-trim readback")
        .collect::<Result<_, _>>()
        .expect("collect byte-trim readback");
    assert_eq!(after_bytes, [encode_sequence(3)]);

    // 全局 helper 查询整张 logical index；两个 production conversation 各有
    // 一条 authenticated row 时，缩放 global count=1 必须裁掉全局最老一条。
    let (root, config, mut state) = open_retention_state("scaled-global-cap");
    create_conversation_with_event(&mut state, &config, 0x21, 0x82);
    create_conversation_with_event(&mut state, &config, 0x22, 0x85);
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("scaled global trim transaction");
    trim_global_event_window_with_limits(
        &transaction,
        state.key_bundle.as_ref(),
        false,
        0,
        1,
        u64::MAX,
    )
    .expect("global count cap trims across conversations");
    transaction.commit().expect("commit global trim");
    let global_retained: i64 = state
        .connection
        .query_row("SELECT COUNT(*) FROM event_stream_index", [], |row| {
            row.get(0)
        })
        .expect("count globally retained rows");
    assert_eq!(global_retained, 1);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn ready_snapshot_authorizes_production_conversation_trim() {
    let (root, config, mut state) = open_retention_state("ready-snapshot-allows-trim");
    let conversation_id = create_conversation_with_event(&mut state, &config, 0x11, 0x82);
    store_ready_snapshot(&mut state, &config, conversation_id, 0x31);

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("ready snapshot trim transaction");
    trim_unrecorded_conversation_window(
        &transaction,
        state.key_bundle.as_ref(),
        conversation_id.as_bytes(),
        true,
        config.clock.now_ms().expect("ready snapshot trim clock"),
        0,
        MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
    )
    .expect("authenticated ready snapshot covers victim");
    transaction.commit().expect("commit snapshot-covered trim");
    let retained: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM event_stream_index WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("count snapshot-covered retention rows");
    assert_eq!(retained, 0);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn equal_length_snapshot_ciphertext_tamper_cannot_authorize_trim() {
    let (root, config, mut state) = open_retention_state("snapshot-ciphertext-tamper-trim");
    let conversation_id = create_conversation_with_event(&mut state, &config, 0x16, 0x82);
    store_ready_snapshot(&mut state, &config, conversation_id, 0x34);
    let mut sealed: Vec<u8> = state
        .connection
        .query_row(
            "SELECT sealed_snapshot FROM snapshots
                 WHERE target_scope = 'conversation' AND conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read snapshot ciphertext tamper fixture");
    *sealed
        .last_mut()
        .expect("sealed snapshot has an authentication tag") ^= 0x01;
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE snapshots SET sealed_snapshot = ?1
                     WHERE target_scope = 'conversation' AND conversation_id = ?2",
                params![sealed, &conversation_id.as_bytes()[..]],
            )
            .expect("install equal-length snapshot ciphertext tamper"),
        1
    );

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("tampered snapshot trim transaction");
    trim_unrecorded_conversation_window(
        &transaction,
        state.key_bundle.as_ref(),
        conversation_id.as_bytes(),
        true,
        config.clock.now_ms().expect("tamper trim clock"),
        0,
        MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
    )
    .expect_err("tampered snapshot cannot authorize replay membership deletion");
    drop(transaction);
    let retained: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM event_stream_index WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("count index rows after tampered snapshot rejection");
    assert_eq!(retained, 1);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn expired_snapshot_pin_is_purged_by_trim_and_cannot_revive() {
    let (root, config, mut state) = open_retention_state("expired-snapshot-pin-trim");
    let conversation_id = create_conversation_with_event(&mut state, &config, 0x17, 0x82);
    store_ready_snapshot(&mut state, &config, conversation_id, 0x35);
    let issued_at_ms = config.clock.now_ms().expect("expired pin issue clock");
    let pin = acquire_snapshot_build_pin(&state, conversation_id, issued_at_ms)
        .expect("acquire snapshot pin to expire");
    assert!(matches!(
        validate_snapshot_build_pin(&state.connection, &pin, pin.expires_at_ms),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    let expired_pin_count: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin.pin_id[..]],
            |row| row.get(0),
        )
        .expect("read back exact-expiry pin deletion");
    assert_eq!(expired_pin_count, 0);

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("expired pin trim transaction");
    let trim_now_ms = effective_trim_now_ms(issued_at_ms, Some(pin.expires_at_ms));
    assert_eq!(trim_now_ms, pin.expires_at_ms);
    trim_unrecorded_conversation_window(
        &transaction,
        state.key_bundle.as_ref(),
        conversation_id.as_bytes(),
        true,
        trim_now_ms,
        0,
        MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
    )
    .expect("pin at exact expiry no longer blocks ready-snapshot trim");
    transaction.commit().expect("commit expired-pin trim");

    let (pin_count, retained): (i64, i64) = state
        .connection
        .query_row(
            "SELECT
                     (SELECT COUNT(*) FROM temp.active_stream_pins WHERE pin_id = ?1),
                     (SELECT COUNT(*) FROM event_stream_index WHERE conversation_id = ?2)",
            params![&pin.pin_id[..], &conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read exact-expiry pin and replay membership");
    assert_eq!(pin_count, 0);
    assert_eq!(retained, 0);
    assert!(matches!(
        validate_snapshot_build_pin(&state.connection, &pin, issued_at_ms),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn exact_authenticated_outbox_does_not_authorize_production_conversation_trim() {
    let (root, config, mut state) = open_retention_state("exact-outbox-cannot-trim");
    let conversation_id = create_conversation_with_event(&mut state, &config, 0x12, 0x82);
    freeze_exact_event_publication(&mut state, &config, conversation_id, 0x51);

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("exact outbox trim transaction");
    let error = trim_unrecorded_conversation_window(
        &transaction,
        state.key_bundle.as_ref(),
        conversation_id.as_bytes(),
        true,
        config.clock.now_ms().expect("outbox-only trim clock"),
        0,
        MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
    )
    .expect_err("outbox is not a locally consumable replay replacement");
    assert!(matches!(error, RuntimeStoreError::PublicationNeedsSnapshot));
    drop(transaction);
    let retained: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM event_stream_index WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("count rows after outbox-only trim rejection");
    assert_eq!(retained, 1);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn active_snapshot_pin_blocks_both_replacements_and_rollback_preserves_state() {
    let (root, config, mut state) = open_retention_state("snapshot-pin-blocks-both");
    let conversation_id = create_conversation_with_event(&mut state, &config, 0x13, 0x82);
    store_ready_snapshot(&mut state, &config, conversation_id, 0x32);
    freeze_exact_event_publication(&mut state, &config, conversation_id, 0x61);
    let now_ms = config.clock.now_ms().expect("active pin test clock");
    let pin = acquire_snapshot_build_pin(&state, conversation_id, now_ms)
        .expect("acquire active snapshot pin over victim");
    assert_eq!(pin.base_event_seq(), Some(0));
    let pin_row: (String, Vec<u8>, Option<String>, String) = state
        .connection
        .query_row(
            "SELECT scope, target_id, through_seq, state
                 FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin.pin_id()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read active snapshot pin before trim");
    assert_eq!(pin_row.0, "snapshot");
    assert_eq!(pin_row.1.as_slice(), conversation_id.as_bytes());
    assert_eq!(pin_row.2, Some(encode_sequence(0)));
    assert_eq!(pin_row.3, "active");

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("pin-blocked trim transaction");
    let trim_error = trim_unrecorded_conversation_window(
        &transaction,
        state.key_bundle.as_ref(),
        conversation_id.as_bytes(),
        true,
        now_ms,
        0,
        MAX_EVENT_STREAM_BYTES_PER_CONVERSATION,
    )
    .expect_err("active snapshot pin must block both durable replacements");
    assert!(
        matches!(
            &trim_error,
            RuntimeStoreError::WorkerBusy {
                lane: crate::runtime::model::RuntimeStoreLane::Normal,
            }
        ),
        "unexpected retention error: {trim_error:?}"
    );
    drop(transaction);

    let (pin_state, retained): (String, i64) = state
        .connection
        .query_row(
            "SELECT
                     (SELECT state FROM temp.active_stream_pins WHERE pin_id = ?1),
                     (SELECT COUNT(*) FROM event_stream_index WHERE conversation_id = ?2)",
            params![&pin.pin_id()[..], &conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read pin and rows after rejected transaction");
    assert_eq!(pin_state, "active");
    assert_eq!(retained, 1);
    release_snapshot_build_pin(&state, &pin).expect("release retained snapshot pin");
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn global_trim_skips_blocked_oldest_and_trims_eligible_conversation() {
    let (root, config, mut state) = open_retention_state("global-skip-blocked-oldest");
    let blocked = create_conversation_with_event(&mut state, &config, 0x14, 0x82);
    let eligible = create_conversation_with_event(&mut state, &config, 0x15, 0x85);
    store_ready_snapshot(&mut state, &config, eligible, 0x33);
    let now_ms = config.clock.now_ms().expect("global trim test clock");
    let blocked_pin = acquire_snapshot_build_pin(&state, blocked, now_ms)
        .expect("pin globally oldest conversation");

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("bounded global trim transaction");
    trim_global_event_window_with_limits(
        &transaction,
        state.key_bundle.as_ref(),
        true,
        now_ms,
        1,
        MAX_EVENT_STREAM_BYTES_GLOBAL,
    )
    .expect("skip blocked oldest and trim eligible target");
    transaction.commit().expect("commit eligible global trim");

    let blocked_rows: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM event_stream_index WHERE conversation_id = ?1",
            [&blocked.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("count blocked rows");
    let eligible_rows: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM event_stream_index WHERE conversation_id = ?1",
            [&eligible.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("count eligible rows");
    assert_eq!(blocked_rows, 1);
    assert_eq!(eligible_rows, 0);
    release_snapshot_build_pin(&state, &blocked_pin).expect("release blocked pin");
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn event_stream_index_token_tamper_is_rejected_by_v4_integrity_scan() {
    let (mut connection, key_bundle, database_id, conversation_id) = fixture();
    let event_id = {
        let mut id = [0x60; 16];
        id[15] = 1;
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
            .expect("event id")
    };
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        0,
        &canonical_event(conversation_id, event_id, 0),
    );
    let current = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        conversation_count: 1,
        event_count: 1,
        ..RuntimeLedger::default()
    };
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("migration transaction");
    let migrated = migrate_v4_rows(&transaction, &key_bundle, database_id, &current)
        .expect("migrate event index");
    transaction.commit().expect("commit event index");
    connection
        .execute(
            "UPDATE event_stream_index SET metadata_token = zeroblob(32)",
            [],
        )
        .expect("tamper index token");
    assert!(matches!(
        validate_v4_integrity(&connection, &key_bundle, database_id, &migrated),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
}

#[test]
fn every_v4_ledger_count_bytes_and_floor_is_recomputed() {
    let (mut connection, key_bundle, database_id, conversation_id) = fixture();
    let event_id = {
        let mut id = [0x60; 16];
        id[15] = 1;
        super::super::RuntimeId::from_bytes(super::super::RuntimeIdKind::Event, id)
            .expect("event id")
    };
    insert_audit_event(
        &connection,
        &key_bundle,
        database_id,
        conversation_id,
        0,
        &canonical_event(conversation_id, event_id, 0),
    );
    let current = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        conversation_count: 1,
        event_count: 1,
        ..RuntimeLedger::default()
    };
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("migration transaction");
    let ledger = migrate_v4_rows(&transaction, &key_bundle, database_id, &current)
        .expect("migrate v4 ledger");
    transaction.commit().expect("commit v4 ledger");
    assert_eq!(
        ledger.catalog_retention_floor, None,
        "legacy catalog state is represented by the ready baseline snapshot, not a retained delta"
    );
    validate_v4_integrity(&connection, &key_bundle, database_id, &ledger)
        .expect("baseline ledger is coherent");

    let mut corruptions = Vec::new();
    let mut corrupted = ledger.clone();
    corrupted.audit_event_logical_bytes += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.event_stream_count += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.event_stream_bytes += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.catalog_delta_count += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.catalog_delta_bytes += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.catalog_retention_floor = Some(encode_sequence(0));
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.snapshot_count += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.snapshot_bytes += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.publication_stream_count += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.publication_outbox_count += 1;
    corruptions.push(corrupted);
    let mut corrupted = ledger.clone();
    corrupted.publication_outbox_bytes += 1;
    corruptions.push(corrupted);

    for corrupted in corruptions {
        assert!(matches!(
            validate_v4_integrity(&connection, &key_bundle, database_id, &corrupted),
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));
    }
}
