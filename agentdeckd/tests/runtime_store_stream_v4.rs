use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::AgentKind;
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, ConversationDescriptor, ExecutionFence, FreezePublicationRequest,
    IdempotencyOwner, NewConversation, PublicationPayloadKind, PublicationScope,
    RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeClock, RuntimeClockError,
    RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation, StartCommand,
    StartOutcome, StartedBeforeReleaseTermination, TerminateStartedBeforeRelease,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

#[path = "support/store_admission.rs"]
mod store_admission;
mod support;
use support::snapshot::{prepare_canonical_snapshot_write, store_canonical_snapshot};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
    _permit: store_admission::Permit,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let permit = store_admission::acquire();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-stream-v4-{label}-{}-{sequence}",
            std::process::id()
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
        load_or_create_storage_kek(keys, &self.path.join("key-state.db")).expect("load StorageKEK")
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

struct FailOnceAfterFreeze(AtomicBool);
struct FailOnceAfterDeliveryAck(AtomicBool);
struct FailOnceAfterSnapshot(AtomicBool);

impl RuntimeStoreFaultInjector for FailOnceAfterFreeze {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::FreezePublicationAfterCommit
            && !self.0.swap(true, Ordering::SeqCst)
        {
            Err(RuntimeStoreError::InvalidConfig(
                "injected post-freeze commit fault",
            ))
        } else {
            Ok(())
        }
    }
}

impl RuntimeStoreFaultInjector for FailOnceAfterDeliveryAck {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::AcknowledgePublicationAfterCommit
            && !self.0.swap(true, Ordering::SeqCst)
        {
            Err(RuntimeStoreError::InvalidConfig(
                "injected post-device-ack commit fault",
            ))
        } else {
            Ok(())
        }
    }
}

impl RuntimeStoreFaultInjector for FailOnceAfterSnapshot {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::StoreSnapshotAfterCommit
            && !self.0.swap(true, Ordering::SeqCst)
        {
            Err(RuntimeStoreError::InvalidConfig(
                "injected post-snapshot commit fault",
            ))
        } else {
            Ok(())
        }
    }
}

fn conversation(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
            .expect("conversation id"),
        adapter_state_key: RuntimeId::from_bytes(
            RuntimeIdKind::AdapterState,
            [seed.wrapping_add(0x40); 16],
        )
        .expect("adapter key"),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some(format!("stream-{seed}")),
            cwd: PathBuf::from("/tmp/runtime-stream-v4"),
        },
    }
}

#[tokio::test]
async fn catalog_pin_snapshot_and_publication_have_one_durable_cut() {
    let root = TestRoot::new("roundtrip");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x11);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");

    let RuntimeBackfillPlan::Pinned(catalog_pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("pin catalog revision zero")
    else {
        panic!("catalog revision zero must require a non-empty pinned page");
    };
    let catalog_page = store
        .load_catalog_backfill_page(catalog_pin, None)
        .await
        .expect("load catalog page");
    let catalog_completion = catalog_page.completion().clone();
    assert!(catalog_page.complete);
    assert_eq!(catalog_page.next_after, 0);
    assert_eq!(catalog_page.deltas[0].catalog_revision, 0);
    store
        .complete_backfill_page(catalog_completion)
        .await
        .expect("ACK catalog page completion");
    drop(catalog_page);

    let snapshot_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture empty conversation snapshot");
    let snapshot = store_canonical_snapshot(&store, snapshot_pin, "capabilities-only-snapshot")
        .await
        .expect("store empty-conversation snapshot");
    assert_eq!(
        store
            .load_conversation_snapshot(conversation_id)
            .await
            .expect("load snapshot")
            .expect("snapshot exists"),
        snapshot
    );

    let publication_stream_id = [0x51; 16];
    let generation = [0x52; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Conversation(conversation_id),
            [0x53; 16],
            generation,
        )
        .await
        .expect("create publication stream");
    let request = FreezePublicationRequest {
        publication_id: [0x54; 16],
        publication_stream_id,
        generation,
        counter_scope_token: [0x55; 32],
        sender_counter: 7,
        inner_after: None,
        inner_through: Some(0),
        payload_kind: PublicationPayloadKind::Event,
        blob: b"exact-fake-sealed-publication".to_vec(),
    };
    let frozen = store
        .freeze_publication(request.clone())
        .await
        .expect("freeze publication");
    assert_eq!(
        store
            .freeze_publication(request)
            .await
            .expect("exact freeze retry"),
        frozen
    );
    assert_eq!(
        store
            .load_pending_publications(publication_stream_id)
            .await
            .expect("pending publications"),
        std::slice::from_ref(&frozen)
    );
    let before_commit = store
        .load_publication_barrier(publication_stream_id)
        .await
        .expect("pre-commit barrier");
    assert_eq!(before_commit.committed_outer_cursor, None);
    assert_eq!(before_commit.committed_inner_cursor, None);

    store.shutdown().await.expect("shutdown before retry");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen store");
    assert_eq!(
        store
            .load_pending_publications(publication_stream_id)
            .await
            .expect("restart pending publication"),
        std::slice::from_ref(&frozen),
        "restart must replay byte-identical frozen blob"
    );
    let mut wrong_hash = frozen.blob_sha256;
    wrong_hash[0] ^= 1;
    assert!(matches!(
        store
            .acknowledge_publication_commit(
                publication_stream_id,
                generation,
                frozen.stream_seq,
                wrong_hash,
            )
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    let committed = store
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("commit exact publication");
    assert_eq!(committed.committed_outer_cursor, Some(0));
    assert_eq!(committed.committed_inner_cursor, Some(0));
    let raw = rusqlite::Connection::open(root.database()).expect("open committed outbox reader");
    let retained_after_commit: i64 = raw
        .query_row("SELECT COUNT(*) FROM publication_outbox", [], |row| {
            row.get(0)
        })
        .expect("count unacknowledged committed outbox");
    assert_eq!(
        retained_after_commit, 1,
        "Relay COMMIT cannot delete before device ACK"
    );
    drop(raw);
    assert_eq!(
        store
            .acknowledge_publication_commit(
                publication_stream_id,
                generation,
                frozen.stream_seq,
                frozen.blob_sha256,
            )
            .await
            .expect("exact commit retry"),
        committed
    );
    assert!(matches!(
        store
            .acknowledge_publication_delivery(
                publication_stream_id,
                generation,
                frozen.stream_seq,
                wrong_hash,
            )
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    let acknowledged = store
        .acknowledge_publication_delivery(
            publication_stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("exact device ACK");
    assert_eq!(acknowledged.acknowledged_outer_cursor, Some(0));
    assert_eq!(acknowledged.acknowledged_inner_cursor, Some(0));
    assert_eq!(
        store
            .acknowledge_publication_delivery(
                publication_stream_id,
                generation,
                frozen.stream_seq,
                frozen.blob_sha256,
            )
            .await
            .expect("exact device ACK retry"),
        acknowledged
    );
    let raw = rusqlite::Connection::open(root.database()).expect("open acknowledged outbox reader");
    let retained_after_ack: i64 = raw
        .query_row("SELECT COUNT(*) FROM publication_outbox", [], |row| {
            row.get(0)
        })
        .expect("count ACKed outbox");
    assert_eq!(retained_after_ack, 0);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn device_ack_after_commit_unknown_retries_without_deleting_twice() {
    let root = TestRoot::new("device-ack-unknown");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_fault_injector(Arc::new(FailOnceAfterDeliveryAck(AtomicBool::new(false)))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let stream_id = [0xC1; 16];
    let generation = [0xC2; 16];
    store
        .create_publication_stream(stream_id, PublicationScope::Catalog, [0xC3; 16], generation)
        .await
        .expect("create stream");
    let frozen = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0xC4; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0xC5; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"device-ack-unknown".to_vec(),
        })
        .await
        .expect("freeze publication");
    store
        .acknowledge_publication_commit(
            stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("Relay COMMIT");
    assert!(matches!(
        store
            .acknowledge_publication_delivery(
                stream_id,
                generation,
                frozen.stream_seq,
                frozen.blob_sha256,
            )
            .await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcknowledgePublication
        })
    ));
    let ack = store
        .acknowledge_publication_delivery(
            stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("exact ACK retry");
    assert_eq!(ack.acknowledged_outer_cursor, Some(0));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn acknowledged_publication_counter_cannot_be_reused_by_a_new_blob() {
    let root = TestRoot::new("counter-after-ack");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let stream_id = [0xD1; 16];
    let generation = [0xD2; 16];
    let counter_scope = [0xD3; 32];
    store
        .create_publication_stream(stream_id, PublicationScope::Catalog, [0xD4; 16], generation)
        .await
        .expect("create publication stream");
    let first_request = FreezePublicationRequest {
        publication_id: [0xD5; 16],
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: counter_scope,
        sender_counter: 41,
        inner_after: None,
        inner_through: None,
        payload_kind: PublicationPayloadKind::Control,
        blob: b"first-counter-use".to_vec(),
    };
    let frozen = store
        .freeze_publication(first_request.clone())
        .await
        .expect("freeze first counter use");
    assert_eq!(
        store
            .freeze_publication(first_request)
            .await
            .expect("exact publication retry precedes counter monotonicity gate"),
        frozen
    );
    store
        .acknowledge_publication_commit(
            stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("Relay COMMIT");
    store
        .acknowledge_publication_delivery(
            stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("device ACK deletes outbox row");

    assert!(matches!(
        store
            .freeze_publication(FreezePublicationRequest {
                publication_id: [0xD6; 16],
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter: 41,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"different-blob-must-not-reuse-counter".to_vec(),
            })
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert!(matches!(
        store
            .freeze_publication(FreezePublicationRequest {
                publication_id: [0xD7; 16],
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter: 40,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"lower-counter-must-also-fail".to_vec(),
            })
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    let advanced = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0xD8; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: counter_scope,
            sender_counter: 42,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"strictly-higher-counter-is-accepted".to_vec(),
        })
        .await
        .expect("strictly higher counter advances durable high-water");
    assert_eq!(advanced.sender_counter, 42);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_counter_high_water_survives_daemon_reopen_after_ack() {
    let root = TestRoot::new("counter-reopen-after-ack");
    let keys = MemoryKeyStore::new();
    let stream_id = [0xE1; 16];
    let generation = [0xE2; 16];
    let counter_scope = [0xE3; 32];
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_publication_stream(stream_id, PublicationScope::Catalog, [0xE4; 16], generation)
        .await
        .expect("create publication stream");
    let acknowledged_request = FreezePublicationRequest {
        publication_id: [0xE5; 16],
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: counter_scope,
        sender_counter: 9,
        inner_after: None,
        inner_through: None,
        payload_kind: PublicationPayloadKind::Control,
        blob: b"persist-counter-high-water".to_vec(),
    };
    let frozen = store
        .freeze_publication(acknowledged_request.clone())
        .await
        .expect("freeze publication");
    store
        .acknowledge_publication_commit(
            stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("Relay COMMIT");
    store
        .acknowledge_publication_delivery(
            stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("device ACK");
    store.shutdown().await.expect("shutdown before reopen");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen store");
    assert!(matches!(
        reopened
            .freeze_publication(acknowledged_request.clone())
            .await,
        Err(RuntimeStoreError::PublicationAlreadyAcknowledged)
    ));
    let mut conflicting_reuse = acknowledged_request;
    conflicting_reuse.blob = b"same-id-different-request".to_vec();
    assert!(matches!(
        reopened.freeze_publication(conflicting_reuse).await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert!(matches!(
        reopened
            .freeze_publication(FreezePublicationRequest {
                publication_id: [0xE6; 16],
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter: 9,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"reopen-counter-reuse".to_vec(),
            })
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn counter_scope_cannot_be_rebound_to_another_stream_or_generation() {
    let root = TestRoot::new("counter-cross-stream");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let first = conversation(0xD7);
    let second = conversation(0xD8);
    let first_conversation = first.conversation_id;
    let second_conversation = second.conversation_id;
    store
        .create_conversation(first)
        .await
        .expect("create first conversation");
    store
        .create_conversation(second)
        .await
        .expect("create second conversation");
    let first_stream = [0xF1; 16];
    let second_stream = [0xF2; 16];
    let first_generation = [0xF3; 16];
    let second_generation = [0xF4; 16];
    let counter_scope = [0xF5; 32];
    store
        .create_publication_stream(
            first_stream,
            PublicationScope::Conversation(first_conversation),
            [0xF6; 16],
            first_generation,
        )
        .await
        .expect("create first stream");
    store
        .create_publication_stream(
            second_stream,
            PublicationScope::Conversation(second_conversation),
            [0xF7; 16],
            second_generation,
        )
        .await
        .expect("create second stream");
    store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0xF8; 16],
            publication_stream_id: first_stream,
            generation: first_generation,
            counter_scope_token: counter_scope,
            sender_counter: 100,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"bind-counter-scope".to_vec(),
        })
        .await
        .expect("bind scope to first stream");
    assert!(matches!(
        store
            .freeze_publication(FreezePublicationRequest {
                publication_id: [0xF9; 16],
                publication_stream_id: second_stream,
                generation: second_generation,
                counter_scope_token: counter_scope,
                sender_counter: 101,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"cross-stream-scope-reuse".to_vec(),
            })
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn persisted_counter_scope_and_high_water_are_authenticated_on_reopen() {
    for (label, tamper_sql) in [
        (
            "counter-scope-auth",
            "UPDATE publication_streams SET counter_scope_token = zeroblob(32)",
        ),
        (
            "counter-high-water-auth",
            "UPDATE publication_streams
             SET sender_counter_high_water = '00000000000000000042'",
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open counter authentication fixture");
        let stream_id = [0xB1; 16];
        let generation = [0xB2; 16];
        store
            .create_publication_stream(stream_id, PublicationScope::Catalog, [0xB3; 16], generation)
            .await
            .expect("create counter authentication stream");
        store
            .freeze_publication(FreezePublicationRequest {
                publication_id: [0xB4; 16],
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: [0xB5; 32],
                sender_counter: 41,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"authenticated-counter-state".to_vec(),
            })
            .await
            .expect("freeze authenticated counter state");
        store.shutdown().await.expect("shutdown before tamper");

        let connection = rusqlite::Connection::open(root.database()).expect("open raw DB");
        connection
            .execute(tamper_sql, [])
            .expect("tamper persisted counter state");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("counter state tamper must fail closed");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }
}

#[tokio::test]
async fn first_control_publication_commits_outer_cut_while_inner_stays_before_first() {
    let root = TestRoot::new("first-control-cut");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let publication_stream_id = [0x61; 16];
    let generation = [0x62; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0x63; 16],
            generation,
        )
        .await
        .expect("create empty catalog publication stream");
    let frozen = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0x64; 16],
            publication_stream_id,
            generation,
            counter_scope_token: [0x65; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"first-key-control-frame".to_vec(),
        })
        .await
        .expect("freeze first control frame");

    let cut = store
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("commit first control frame");
    assert_eq!(cut.committed_outer_cursor, Some(0));
    assert_eq!(cut.committed_inner_cursor, None);
    store.shutdown().await.expect("shutdown store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen committed BeforeFirst cut");
    assert_eq!(
        reopened
            .load_publication_barrier(publication_stream_id)
            .await
            .expect("load committed control cut"),
        cut
    );
    let first_delta = reopened
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0x66; 16],
            publication_stream_id,
            generation,
            counter_scope_token: [0x65; 32],
            sender_counter: 2,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"first-catalog-delta".to_vec(),
        })
        .await
        .expect("freeze first inner row after control-only cut");
    let first_data_cut = reopened
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            first_delta.stream_seq,
            first_delta.blob_sha256,
        )
        .await
        .expect("commit first inner row after control-only cut");
    assert_eq!(first_data_cut.committed_outer_cursor, Some(1));
    assert_eq!(first_data_cut.committed_inner_cursor, Some(0));
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn catalog_pin_rejects_cursor_mismatch_and_expires_at_exact_ttl() {
    let root = TestRoot::new("pin-ttl");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(conversation(0x21))
        .await
        .expect("create conversation");
    let RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("pin catalog")
    else {
        panic!("catalog has revision zero");
    };
    assert!(matches!(
        store.load_catalog_backfill_page(pin.clone(), Some(0)).await,
        Err(RuntimeStoreError::InvalidBackfillPin)
    ));
    clock.set(pin.expires_at_ms);
    assert!(matches!(
        store.load_catalog_backfill_page(pin, None).await,
        Err(RuntimeStoreError::InvalidBackfillPin)
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn catalog_backfill_pin_rejects_clock_rollback_before_its_issue_time() {
    let root = TestRoot::new("catalog-pin-clock-rollback");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(conversation(0x22))
        .await
        .expect("create catalog revision zero");
    let RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("pin catalog")
    else {
        panic!("catalog has revision zero");
    };

    clock.set(999);
    assert!(matches!(
        store.load_catalog_backfill_page(pin.clone(), None).await,
        Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: 1_000,
            observed_ms: 999,
        })
    ));

    clock.set(1_000);
    let page = store
        .load_catalog_backfill_page(pin, None)
        .await
        .expect("clock rollback does not consume the pin");
    let completion = page.completion().clone();
    assert!(page.complete);
    store
        .complete_backfill_page(completion)
        .await
        .expect("ACK catalog page after clock recovery");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_build_pin_rejects_clock_rollback_before_its_issue_time() {
    let root = TestRoot::new("snapshot-pin-clock-rollback");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(2_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x23);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture snapshot pin");

    clock.set(1_999);
    let error = store_canonical_snapshot(&store, pin, "clock-safe-snapshot")
        .await
        .expect_err("clock regression rejects safe snapshot preparation");
    assert_eq!(error.code(), "daemon.runtime.invalid_state");

    clock.set(2_000);
    let replacement_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire fresh pin after failed preparation cleanup");
    store_canonical_snapshot(&store, replacement_pin, "clock-safe-snapshot")
        .await
        .expect("fresh exact pin succeeds after clock recovers");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_hash_or_metadata_tamper_fails_closed_on_reopen() {
    let root = TestRoot::new("snapshot-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x31);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let snapshot_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture snapshot tamper fixture");
    store_canonical_snapshot(&store, snapshot_pin, "snapshot")
        .await
        .expect("store snapshot");
    store.shutdown().await.expect("shutdown before tamper");

    let connection = rusqlite::Connection::open(root.database()).expect("open raw DB");
    connection
        .execute("UPDATE snapshots SET content_sha256 = zeroblob(32)", [])
        .expect("tamper snapshot hash");
    drop(connection);
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("tampered snapshot must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
}

#[tokio::test]
async fn publication_rejects_inner_gaps_and_outbox_token_tamper_fails_closed() {
    let root = TestRoot::new("publication-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x41);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let stream_id = [0x61; 16];
    let generation = [0x62; 16];
    store
        .create_publication_stream(
            stream_id,
            PublicationScope::Conversation(conversation_id),
            [0x63; 16],
            generation,
        )
        .await
        .expect("create stream");
    let request = |publication_id, inner_after, inner_through| FreezePublicationRequest {
        publication_id,
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: [0x68; 32],
        sender_counter: u64::from(publication_id[0]),
        inner_after,
        inner_through,
        payload_kind: PublicationPayloadKind::Event,
        blob: vec![publication_id[0]; 32],
    };
    assert!(matches!(
        store
            .freeze_publication(request([0x64; 16], Some(0), Some(1)))
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    store
        .freeze_publication(request([0x65; 16], None, Some(0)))
        .await
        .expect("freeze first contiguous range");
    assert!(matches!(
        store
            .freeze_publication(request([0x66; 16], Some(2), Some(3)))
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    store
        .freeze_publication(request([0x67; 16], Some(0), Some(1)))
        .await
        .expect("freeze next contiguous range");
    store.shutdown().await.expect("shutdown before tamper");

    let connection = rusqlite::Connection::open(root.database()).expect("open raw DB");
    connection
        .execute(
            "UPDATE publication_outbox SET metadata_token = zeroblob(32)
             WHERE publication_id = ?1",
            [&[0x65_u8; 16][..]],
        )
        .expect("tamper outbox token");
    drop(connection);
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("tampered outbox must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
}

#[tokio::test]
async fn catalog_delta_token_tamper_fails_closed_on_reopen() {
    let root = TestRoot::new("catalog-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(conversation(0x51))
        .await
        .expect("create catalog delta");
    store.shutdown().await.expect("shutdown before tamper");
    let connection = rusqlite::Connection::open(root.database()).expect("open raw DB");
    connection
        .execute(
            "UPDATE catalog_journal SET metadata_token = zeroblob(32)",
            [],
        )
        .expect("tamper catalog token");
    drop(connection);
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("tampered catalog delta must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
}

#[tokio::test]
async fn publication_after_commit_unknown_retries_the_exact_frozen_row() {
    let root = TestRoot::new("publication-commit-unknown");
    let keys = MemoryKeyStore::new();
    let fault = Arc::new(FailOnceAfterFreeze(AtomicBool::new(false)));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(fault),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x61);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let stream_id = [0x71; 16];
    let generation = [0x72; 16];
    store
        .create_publication_stream(
            stream_id,
            PublicationScope::Conversation(conversation_id),
            [0x73; 16],
            generation,
        )
        .await
        .expect("create publication stream");
    let request = FreezePublicationRequest {
        publication_id: [0x74; 16],
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: [0x75; 32],
        sender_counter: 1,
        inner_after: None,
        inner_through: Some(0),
        payload_kind: PublicationPayloadKind::Event,
        blob: b"freeze-once".to_vec(),
    };
    assert!(matches!(
        store.freeze_publication(request.clone()).await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::FreezePublication
        })
    ));
    let replayed = store
        .freeze_publication(request)
        .await
        .expect("retry exact frozen row");
    assert_eq!(replayed.stream_seq, 0);
    assert_eq!(replayed.blob, b"freeze-once");
    assert_eq!(
        store
            .load_pending_publications(stream_id)
            .await
            .expect("single pending row"),
        [replayed]
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_build_pin_allows_frozen_base_while_writer_advances_high_water() {
    let root = TestRoot::new("snapshot-frozen-base");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x71);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    clock.set(1_100);
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0xA1; 32],
                uid: 501,
                client_installation_id: [0xA2; 16],
            },
            idempotency_key: "snapshot-build".to_owned(),
            expected_configuration_revision: 0,
            payload: b"snapshot command".to_vec(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };
    let daemon_boot_id =
        RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x73; 16]).expect("daemon boot id");
    let execution_nonce = b"snapshot-build-nonce".to_vec();
    clock.set(1_200);
    let intent = match store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("start command")
    {
        StartOutcome::Started { intent, .. } => intent,
        StartOutcome::Replayed { .. } => panic!("first start cannot replay"),
    };
    clock.set(1_300);
    store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: 4_001,
            leader_pid: 4_001,
            leader_start_time: 4_001,
            payload: b"snapshot build fence".to_vec(),
        })
        .await
        .expect("persist unreleased fence");
    let pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("freeze snapshot base at event zero");
    let sibling_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("second opaque capability at same base");
    assert_eq!(
        pin.build_pin()
            .expect("direct acquire returns build source")
            .base_event_seq(),
        Some(0)
    );

    clock.set(1_400);
    store
        .terminate_started_before_release(TerminateStartedBeforeRelease {
            conversation_id,
            command_id: command.command_id,
            turn_id: intent.turn_id,
            daemon_boot_id,
            execution_nonce,
            reason: StartedBeforeReleaseTermination::Canceled,
        })
        .await
        .expect("advance event high-water to one while snapshot builds");

    clock.set(1_500);
    let stored = store_canonical_snapshot(&store, pin, "snapshot frozen at event zero")
        .await
        .expect("commit pinned stale-base snapshot");
    assert_eq!(stored.base_event_seq, Some(0));
    drop(sibling_pin);
    assert_eq!(
        store
            .load_conversation_snapshot(conversation_id)
            .await
            .expect("load frozen snapshot")
            .expect("snapshot exists"),
        stored
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn exact_snapshot_replay_consumes_each_new_valid_build_pin() {
    let root = TestRoot::new("snapshot-exact-consumes-new-pin");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0xDA);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let source_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire source snapshot pin");
    let stored = store_canonical_snapshot(&store, source_pin, "exact-snapshot")
        .await
        .expect("store source snapshot");

    let replay_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire a distinct pin for exact replay");
    let replayed = store_canonical_snapshot(&store, replay_pin, "exact-snapshot")
        .await
        .expect("exact replay consumes the new pin");
    assert_eq!(replayed, stored);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn exact_snapshot_replay_rejects_released_and_expired_build_pins() {
    let root = TestRoot::new("snapshot-exact-invalid-pins");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0xDB);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let source_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire source snapshot pin");
    store_canonical_snapshot(&store, source_pin, "stable-snapshot")
        .await
        .expect("store source snapshot");

    let released = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire pin to release");
    store
        .release_snapshot_build_pin(
            released
                .build_pin()
                .expect("direct acquire returns build source")
                .clone(),
        )
        .await
        .expect("release pin before replay");
    let error = store_canonical_snapshot(&store, released, "stable-snapshot")
        .await
        .expect_err("released pin cannot replay safe snapshot");
    assert_eq!(error.code(), "daemon.runtime.invalid_state");

    let expired = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire pin to expire");
    clock.set(301_000);
    let error = store_canonical_snapshot(&store, expired, "stable-snapshot")
        .await
        .expect_err("expired pin cannot replay safe snapshot");
    assert_eq!(error.code(), "daemon.runtime.invalid_state");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_commit_unknown_replays_only_the_persisted_source_pin() {
    let root = TestRoot::new("snapshot-commit-unknown-source-pin");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_fault_injector(Arc::new(FailOnceAfterSnapshot(AtomicBool::new(false)))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0xDC);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let source_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire source snapshot pin");
    let write = prepare_canonical_snapshot_write(&store, source_pin, "commit-unknown-snapshot")
        .await
        .expect("prepare exact opaque snapshot write");
    let failure = store
        .store_conversation_snapshot(write)
        .await
        .expect_err("post-COMMIT fault returns the same opaque write");
    assert!(matches!(
        failure.error(),
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::StoreSnapshot
        }
    ));
    let write = failure
        .into_retry_write()
        .expect("COMMIT-unknown retains exact opaque write for replay");
    let replayed = store
        .store_conversation_snapshot(write)
        .await
        .expect("same persisted source pin replays COMMIT-unknown outcome");
    assert!(
        replayed
            .payload
            .windows("commit-unknown-snapshot".len())
            .any(|window| { window == b"commit-unknown-snapshot" })
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn exact_snapshot_candidate_corruption_returns_no_consumed_retry_write() {
    let root = TestRoot::new("snapshot-exact-corrupt-no-retry");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0xDE);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire source snapshot pin");
    store_canonical_snapshot(&store, source, "exact-corrupt-candidate")
        .await
        .expect("store source snapshot");
    let replay_source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire replay snapshot pin");
    let write = prepare_canonical_snapshot_write(&store, replay_source, "exact-corrupt-candidate")
        .await
        .expect("prepare exact replay write");

    let connection = rusqlite::Connection::open(root.database()).expect("open corruption handle");
    let mut sealed: Vec<u8> = connection
        .query_row(
            "SELECT sealed_snapshot FROM snapshots
             WHERE target_scope = 'conversation' AND conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read exact candidate ciphertext");
    let last = sealed
        .last_mut()
        .expect("sealed snapshot always contains an authentication tag");
    *last ^= 0x01;
    assert_eq!(
        connection
            .execute(
                "UPDATE snapshots SET sealed_snapshot = ?1
                 WHERE target_scope = 'conversation' AND conversation_id = ?2",
                rusqlite::params![sealed, &conversation_id.as_bytes()[..]],
            )
            .expect("tamper exact candidate ciphertext"),
        1
    );
    drop(connection);

    let failure = store
        .store_conversation_snapshot(write)
        .await
        .expect_err("corrupt exact candidate must fail closed");
    assert_eq!(failure.code(), "daemon.runtime.crypto_failed");
    assert!(
        failure.into_retry_write().is_none(),
        "incoming payload was consumed before old ciphertext authentication failed"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_source_build_pin_is_authenticated_on_reopen() {
    let root = TestRoot::new("snapshot-source-pin-auth");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0xDD);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let source_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire source snapshot pin");
    store_canonical_snapshot(&store, source_pin, "source-pin-auth")
        .await
        .expect("store snapshot");
    store.shutdown().await.expect("shutdown before tamper");

    let connection = rusqlite::Connection::open(root.database()).expect("open raw DB");
    connection
        .execute(
            "UPDATE snapshots SET source_build_pin_id = zeroblob(16)
             WHERE target_scope = 'conversation'",
            [],
        )
        .expect("tamper source build pin");
    drop(connection);
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("tampered source build pin must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
}

#[tokio::test]
async fn retention_stream_and_v4_ledger_tamper_each_fail_closed_on_reopen() {
    async fn assert_rejected(label: &str, sql: &str, create_stream: bool) {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open tamper fixture");
        let input = conversation(label.as_bytes()[0]);
        let conversation_id = input.conversation_id;
        store
            .create_conversation(input)
            .await
            .expect("create tamper conversation");
        if create_stream {
            store
                .create_publication_stream(
                    [0xD1; 16],
                    PublicationScope::Conversation(conversation_id),
                    [0xD2; 16],
                    [0xD3; 16],
                )
                .await
                .expect("create tamper publication stream");
        }
        store.shutdown().await.expect("shutdown before tamper");
        let connection = rusqlite::Connection::open(root.database()).expect("open raw DB");
        if matches!(label, "retention-orphan" | "stream-index-orphan") {
            connection
                .pragma_update(None, "foreign_keys", false)
                .expect("disable FK to simulate offline bypass");
        }
        connection.execute(sql, []).expect("apply bounded tamper");
        drop(connection);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect_err("authenticated v4 tamper must fail closed");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    }

    assert_rejected(
        "retention-token",
        "UPDATE event_retention SET metadata_token = zeroblob(32)",
        false,
    )
    .await;
    assert_rejected(
        "retention-range-digest",
        "UPDATE event_retention SET range_digest = zeroblob(32)",
        false,
    )
    .await;
    assert_rejected(
        "retention-orphan",
        "INSERT INTO event_retention (
             conversation_id, oldest_retained_event_seq, indexed_through_event_seq,
             retained_event_count, retained_logical_bytes, range_digest, metadata_token
         )
         SELECT X'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE', oldest_retained_event_seq,
                indexed_through_event_seq, retained_event_count, retained_logical_bytes,
                range_digest, metadata_token
         FROM event_retention LIMIT 1",
        false,
    )
    .await;
    assert_rejected(
        "stream-index-orphan",
        "INSERT INTO event_stream_index (
             conversation_id, event_seq, event_id, logical_event_bytes,
             created_at_ms, metadata_token
         ) VALUES (
             X'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE', '00000000000000000000',
             X'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD', 1, 0, zeroblob(32)
         )",
        false,
    )
    .await;
    assert_rejected(
        "stream-token",
        "UPDATE publication_streams SET metadata_token = zeroblob(32)",
        true,
    )
    .await;
    assert_rejected(
        "ledger-count",
        "UPDATE runtime_meta SET catalog_delta_count = 0 WHERE singleton = 1",
        false,
    )
    .await;
}

#[tokio::test]
async fn before_first_snapshot_capability_survives_event_zero_writer_progress() {
    let root = TestRoot::new("snapshot-before-first");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(2_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x79);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create empty conversation");
    let before_first = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture BeforeFirst snapshot capability");
    assert_eq!(
        before_first
            .build_pin()
            .expect("direct acquire returns build source")
            .base_event_seq(),
        None
    );
    clock.set(2_100);
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0xB1; 32],
                uid: 501,
                client_installation_id: [0xB2; 16],
            },
            idempotency_key: "before-first".to_owned(),
            expected_configuration_revision: 0,
            payload: b"advance to event zero".to_vec(),
        })
        .await
        .expect("accept command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first accept cannot replay"),
    };
    clock.set(2_200);
    store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id: command.command_id,
            daemon_boot_id: RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0xB3; 16])
                .expect("daemon boot id"),
            execution_nonce: b"before-first-nonce".to_vec(),
        })
        .await
        .expect("advance event H to zero");
    clock.set(2_300);
    let snapshot = store_canonical_snapshot(&store, before_first, "capabilities-only-before-first")
        .await
        .expect("commit captured BeforeFirst snapshot after H advanced");
    assert_eq!(snapshot.base_event_seq, None);
    store.shutdown().await.expect("shutdown store");
}
