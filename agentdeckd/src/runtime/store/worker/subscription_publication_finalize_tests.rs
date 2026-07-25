use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::e2ee::{AuthorizationCapabilityV1, AuthorizationPermissionV1};
use agentdeck_protocol::runtime::StreamCursor;

use crate::runtime::backfill::BarrierRequest;
use crate::runtime::events::{
    RegisterStreamBarrier, RuntimeStreamTarget, StreamBarrierRegistration, WatchGeneration,
};
use crate::runtime::model::{
    ConversationDescriptor, NewConversation, RuntimeClock, RuntimeClockError,
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreOperation,
};
use crate::runtime::store::{
    FreezePublicationRequest, PublicationPayloadKind, PublicationScope, PublicationStreamRecord,
    RuntimeId, RuntimeIdKind, RuntimeStoreHandle,
    active_authorization_store_with_permissions_for_test,
    production_aligned_active_authorization_store_for_test,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::super::publication::FinalizeSubscriptionPublicationRequest;

const REOPEN_NOW_MS: u64 = 1_800_000_100_000;

#[derive(Clone, Debug)]
struct FixedClock(u64);

impl RuntimeClock for FixedClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0)
    }
}

#[derive(Debug)]
struct OneShotFinalizeFault {
    operation: RuntimeStoreOperation,
    armed: AtomicBool,
}

impl OneShotFinalizeFault {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            armed: AtomicBool::new(true),
        }
    }
}

impl RuntimeStoreFaultInjector for OneShotFinalizeFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

fn secure_tempdir() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("create subscription publication test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure subscription publication test root");
    }
    root
}

fn database(root: &Path) -> PathBuf {
    root.join("runtime.db")
}

fn key_state(root: &Path) -> PathBuf {
    root.join("key-state.db")
}

fn reopen_config(root: &Path) -> RuntimeStoreConfig {
    RuntimeStoreConfig::new(database(root))
        .with_clock(FixedClock(REOPEN_NOW_MS))
        .with_capacity_probe(super::super::pairing_tests::GenerousCapacity)
}

async fn open_relay_authority(root: &Path, keys: &MemoryKeyStore) -> RuntimeStoreHandle {
    production_aligned_active_authorization_store_for_test(
        &database(root),
        load_or_create_storage_kek(keys, &key_state(root))
            .expect("load subscription publication StorageKEK"),
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await
}

async fn ensure_pristine_catalog(store: &RuntimeStoreHandle) -> PublicationStreamRecord {
    let stream = store
        .ensure_subscription_publication_stream(PublicationScope::Catalog)
        .await
        .expect("ensure pristine Catalog publication stream");
    assert_pristine(&stream);
    stream
}

async fn reopen_store(
    root: &Path,
    keys: &MemoryKeyStore,
    fault: Option<RuntimeStoreOperation>,
) -> RuntimeStoreHandle {
    let mut config = reopen_config(root);
    if let Some(operation) = fault {
        config = config.with_fault_injector(Arc::new(OneShotFinalizeFault::new(operation)));
    }
    RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(keys, &key_state(root))
            .expect("reload subscription publication StorageKEK"),
    )
    .await
    .expect("reopen subscription publication Store")
}

fn catalog_barrier(generation: u64, after: StreamCursor) -> RegisterStreamBarrier {
    RegisterStreamBarrier {
        target: RuntimeStreamTarget::Catalog,
        generation: WatchGeneration::new(generation).expect("valid Catalog watch generation"),
        request: BarrierRequest::Backfill { after },
    }
}

fn finalize_request(
    registration: &StreamBarrierRegistration,
) -> FinalizeSubscriptionPublicationRequest {
    FinalizeSubscriptionPublicationRequest {
        target: registration.target,
        captured_high_water: registration.high_water,
        durable_snapshot_base: None,
        captured: registration.relay_committed.clone(),
        watch_token: registration.watch.token(),
    }
}

async fn finalize_error(
    store: &RuntimeStoreHandle,
    request: FinalizeSubscriptionPublicationRequest,
) -> RuntimeStoreError {
    match store.finalize_subscription_publication(request).await {
        Ok(_) => panic!("subscription publication finalize unexpectedly succeeded"),
        Err(error) => error,
    }
}

async fn release_registration(store: &RuntimeStoreHandle, registration: StreamBarrierRegistration) {
    assert!(
        store
            .release_stream_watch(registration.watch.token())
            .await
            .expect("release subscription publication watch")
    );
    drop(registration);
}

fn assert_pristine(stream: &PublicationStreamRecord) {
    assert!(stream.counter_scope_token.is_none());
    assert!(stream.sender_counter_high_water.is_none());
    assert!(stream.reserved_high_water.is_none());
    assert!(stream.committed_high_water.is_none());
    assert!(stream.committed_inner_cursor.is_none());
    assert!(stream.last_committed_blob_hash.is_none());
    assert!(stream.acknowledged_high_water.is_none());
    assert!(stream.acknowledged_inner_cursor.is_none());
    assert!(stream.last_acknowledged_blob_hash.is_none());
    assert!(stream.last_acknowledged_publication_id.is_none());
    assert!(stream.last_acknowledged_request_digest.is_none());
    assert!(stream.last_rotation_request_digest.is_none());
    assert_eq!(stream.rotation_serial, 0);
}

fn assert_baseline_closed(stream: &PublicationStreamRecord) {
    assert_eq!(stream.committed_inner_cursor, None);
    assert_eq!(stream.acknowledged_inner_cursor, None);
    assert!(stream.last_rotation_request_digest.is_some());
    assert_eq!(stream.rotation_serial, 1);
}

async fn freeze_control(
    store: &RuntimeStoreHandle,
    stream: &PublicationStreamRecord,
    seed: u8,
) -> super::super::publication::FrozenPublication {
    store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [seed; 16],
            publication_stream_id: stream.publication_stream_id,
            generation: stream.generation,
            counter_scope_token: [seed.wrapping_add(1); 32],
            sender_counter: 0,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: vec![seed; 32],
        })
        .await
        .expect("freeze Catalog control publication")
}

async fn assert_finalize_cut(
    store: &RuntimeStoreHandle,
    registration: &StreamBarrierRegistration,
    expected_outer: StreamCursor,
) {
    let outcome = store
        .finalize_subscription_publication(finalize_request(registration))
        .await
        .expect("read back finalized subscription publication");
    let (cut, overlap) = outcome.into_attached(&registration.watch);
    assert_eq!(cut.outer, expected_outer);
    assert_eq!(cut.inner, StreamCursor::BeforeFirst);
    let binding = cut
        .stream_binding
        .as_ref()
        .expect("remote subscription retains StreamBinding permit");
    assert_eq!(binding.outer(), expected_outer);
    assert_eq!(binding.inner(), StreamCursor::BeforeFirst);
    assert!(overlap.is_none(), "empty Catalog has no overlap to pin");
}

#[tokio::test]
async fn finalize_before_commit_rolls_back_without_write_and_exact_retry_closes_baseline() {
    let root = secure_tempdir();
    let keys = MemoryKeyStore::new();
    let initial = open_relay_authority(root.path(), &keys).await;
    let pristine = ensure_pristine_catalog(&initial).await;
    initial
        .shutdown()
        .await
        .expect("shutdown pristine BeforeCommit fixture");

    let store = reopen_store(
        root.path(),
        &keys,
        Some(RuntimeStoreOperation::FinalizeSubscriptionPublicationBeforeCommit),
    )
    .await;
    let registration = store
        .register_stream_barrier(catalog_barrier(1, StreamCursor::BeforeFirst))
        .await
        .expect("register BeforeCommit Catalog barrier");
    assert_eq!(registration.high_water, StreamCursor::BeforeFirst);
    let request = finalize_request(&registration);

    let error = finalize_error(&store, request.clone()).await;
    assert!(matches!(error, RuntimeStoreError::WorkerStopped));
    assert_eq!(
        store
            .load_publication_stream_record(pristine.publication_stream_id)
            .await
            .expect("read stream after BeforeCommit rollback"),
        pristine,
        "BeforeCommit failure must leave the authenticated row byte-semantically unchanged"
    );

    let outcome = store
        .finalize_subscription_publication(request)
        .await
        .expect("exact BeforeCommit retry succeeds");
    let (cut, overlap) = outcome.into_attached(&registration.watch);
    assert_eq!(cut.outer, StreamCursor::BeforeFirst);
    assert_eq!(cut.inner, StreamCursor::BeforeFirst);
    assert!(cut.stream_binding.is_some());
    assert!(overlap.is_none());
    let closed = store
        .load_publication_stream_record(pristine.publication_stream_id)
        .await
        .expect("read stream after exact BeforeCommit retry");
    assert_baseline_closed(&closed);

    release_registration(&store, registration).await;
    store
        .shutdown()
        .await
        .expect("shutdown BeforeCommit finalize fixture");
}

#[tokio::test]
async fn finalize_after_commit_is_outcome_unknown_then_replays_read_only_across_restart() {
    let root = secure_tempdir();
    let keys = MemoryKeyStore::new();
    let initial = open_relay_authority(root.path(), &keys).await;
    let pristine = ensure_pristine_catalog(&initial).await;
    initial
        .shutdown()
        .await
        .expect("shutdown pristine AfterCommit fixture");

    let store = reopen_store(
        root.path(),
        &keys,
        Some(RuntimeStoreOperation::FinalizeSubscriptionPublicationAfterCommit),
    )
    .await;
    let registration = store
        .register_stream_barrier(catalog_barrier(1, StreamCursor::BeforeFirst))
        .await
        .expect("register AfterCommit Catalog barrier");
    let request = finalize_request(&registration);

    let error = finalize_error(&store, request.clone()).await;
    assert!(matches!(
        error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::FinalizeSubscriptionPublication
        }
    ));
    let committed = store
        .load_publication_stream_record(pristine.publication_stream_id)
        .await
        .expect("read committed baseline after lost reply");
    assert_baseline_closed(&committed);

    let retry = store
        .finalize_subscription_publication(request)
        .await
        .expect("same-worker exact retry reads committed baseline");
    let (cut, overlap) = retry.into_attached(&registration.watch);
    assert_eq!(cut.outer, StreamCursor::BeforeFirst);
    assert_eq!(cut.inner, StreamCursor::BeforeFirst);
    assert!(cut.stream_binding.is_some());
    assert!(overlap.is_none());
    assert_eq!(
        store
            .load_publication_stream_record(pristine.publication_stream_id)
            .await
            .expect("read stream after same-worker exact retry"),
        committed,
        "non-pristine exact retry must not rewrite timestamp, digest, or lineage"
    );
    release_registration(&store, registration).await;
    store
        .shutdown()
        .await
        .expect("shutdown AfterCommit faulted Store");

    let reopened = reopen_store(root.path(), &keys, None).await;
    let registration = reopened
        .register_stream_barrier(catalog_barrier(1, StreamCursor::BeforeFirst))
        .await
        .expect("register restart readback barrier");
    assert_finalize_cut(&reopened, &registration, StreamCursor::BeforeFirst).await;
    assert_eq!(
        reopened
            .load_publication_stream_record(pristine.publication_stream_id)
            .await
            .expect("read stream after restart retry"),
        committed,
        "restart retry must remain a pure authenticated readback"
    );
    release_registration(&reopened, registration).await;
    reopened
        .shutdown()
        .await
        .expect("shutdown restarted AfterCommit Store");
}

async fn baseline_first_sequence(seed: u8) {
    let root = secure_tempdir();
    let keys = MemoryKeyStore::new();
    let store = open_relay_authority(root.path(), &keys).await;
    let stream = ensure_pristine_catalog(&store).await;
    let registration = store
        .register_stream_barrier(catalog_barrier(1, StreamCursor::BeforeFirst))
        .await
        .expect("register baseline-first Catalog barrier");

    assert_finalize_cut(&store, &registration, StreamCursor::BeforeFirst).await;
    let winner = store
        .load_publication_stream_record(stream.publication_stream_id)
        .await
        .expect("read baseline-first winner");
    assert_baseline_closed(&winner);

    let frozen = freeze_control(&store, &stream, seed).await;
    assert_finalize_cut(&store, &registration, StreamCursor::BeforeFirst).await;
    let after_freeze = store
        .load_publication_stream_record(stream.publication_stream_id)
        .await
        .expect("read baseline-first row after freeze");
    assert_eq!(after_freeze.rotation_serial, winner.rotation_serial);
    assert_eq!(
        after_freeze.last_rotation_request_digest,
        winner.last_rotation_request_digest
    );

    store
        .acknowledge_publication_commit(
            stream.publication_stream_id,
            stream.generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("commit baseline-first control publication");
    assert_finalize_cut(&store, &registration, StreamCursor::At(0)).await;
    store
        .acknowledge_publication_delivery(
            stream.publication_stream_id,
            stream.generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("ack baseline-first control publication");
    assert_finalize_cut(&store, &registration, StreamCursor::At(0)).await;

    release_registration(&store, registration).await;
    store
        .shutdown()
        .await
        .expect("shutdown baseline-first sequence");
}

async fn outer_first_sequence(seed: u8) {
    let root = secure_tempdir();
    let keys = MemoryKeyStore::new();
    let store = open_relay_authority(root.path(), &keys).await;
    let stream = ensure_pristine_catalog(&store).await;
    let registration = store
        .register_stream_barrier(catalog_barrier(1, StreamCursor::BeforeFirst))
        .await
        .expect("register outer-first Catalog barrier");

    let frozen = freeze_control(&store, &stream, seed).await;
    let frozen_winner = store
        .load_publication_stream_record(stream.publication_stream_id)
        .await
        .expect("read outer-first frozen winner");
    assert_eq!(frozen_winner.rotation_serial, 0);
    assert!(frozen_winner.last_rotation_request_digest.is_none());
    assert_finalize_cut(&store, &registration, StreamCursor::BeforeFirst).await;
    assert_eq!(
        store
            .load_publication_stream_record(stream.publication_stream_id)
            .await
            .expect("read outer-first row after delayed finalize"),
        frozen_winner,
        "outer-first delayed finalize must not seize the closed baseline opportunity"
    );

    store
        .acknowledge_publication_commit(
            stream.publication_stream_id,
            stream.generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("commit outer-first control publication");
    assert_finalize_cut(&store, &registration, StreamCursor::At(0)).await;
    store
        .acknowledge_publication_delivery(
            stream.publication_stream_id,
            stream.generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("ack outer-first control publication");
    assert_finalize_cut(&store, &registration, StreamCursor::At(0)).await;

    release_registration(&store, registration).await;
    store
        .shutdown()
        .await
        .expect("shutdown outer-first sequence");
}

#[tokio::test]
async fn delayed_finalize_is_first_wins_in_both_orders_and_reads_fresh_outer_cut() {
    baseline_first_sequence(0x71).await;
    outer_first_sequence(0x81).await;
}

async fn open_relay_authority_with_catalog_head(
    root: &Path,
    keys: &MemoryKeyStore,
) -> RuntimeStoreHandle {
    let store = active_authorization_store_with_permissions_for_test(
        &database(root),
        load_or_create_storage_kek(keys, &key_state(root)).expect("create retained-gap StorageKEK"),
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await;
    store
        .ensure_remote_catalog_publication_after_transition()
        .await
        .expect("ensure retained-gap production Catalog carrier");
    store
        .create_conversation(NewConversation {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x91; 16])
                .expect("retained-gap conversation id"),
            adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x92; 16])
                .expect("retained-gap adapter state id"),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some("subscription publication retained gap".to_owned()),
                cwd: PathBuf::from("/tmp/agentdeck-subscription-publication-retained-gap"),
            },
        })
        .await
        .expect("create retained-gap Catalog revision zero");
    super::super::pairing_grant_tests::complete_active_zero_cut_transition(&store).await;
    store
}

fn trim_catalog_through_head(root: &Path, keys: &MemoryKeyStore, head: StreamCursor) {
    let config = reopen_config(root);
    let mut state = super::super::sqlite::open(
        &config,
        load_or_create_storage_kek(keys, &key_state(root))
            .expect("reload retained-gap StorageKEK for trim"),
    )
    .expect("open retained-gap SQLite state");
    super::super::snapshot::refresh_catalog_snapshot(&mut state, &config, None, head)
        .expect("persist ready Catalog snapshot before retention trim");

    let previous = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        state.key_bundle.as_ref(),
        state.database_id,
    )
    .expect("load retained-gap ledger before trim");
    let key_bundle = Arc::clone(&state.key_bundle);
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .expect("begin retained-gap Catalog trim");
    let mut floor = previous.catalog_retention_floor.clone();
    super::super::catalog::trim_catalog_window_with_limits(
        &transaction,
        key_bundle.as_ref(),
        database_id,
        &mut floor,
        REOPEN_NOW_MS,
        0,
        super::super::catalog::MAX_CATALOG_DELTA_BYTES,
    )
    .expect("trim Catalog through the captured head");
    let (count, bytes): (i64, i64) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(logical_delta_bytes), 0) FROM catalog_journal",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("measure retained-gap Catalog window");
    let mut next = previous.clone();
    next.catalog_delta_count = u64::try_from(count).expect("Catalog retained count");
    next.catalog_delta_bytes = u64::try_from(bytes).expect("Catalog retained bytes");
    next.catalog_retention_floor = floor;
    let _pending_targets = super::super::sqlite::update_runtime_ledger(
        &transaction,
        key_bundle.as_ref(),
        database_id,
        &previous,
        &next,
    )
    .expect("authenticate retained-gap Catalog ledger");
    transaction
        .commit()
        .expect("commit retained-gap Catalog trim");
}

#[tokio::test]
async fn retained_gap_fails_typed_before_stream_binding_after_non_pristine_readback() {
    let root = secure_tempdir();
    let keys = MemoryKeyStore::new();
    let store = open_relay_authority_with_catalog_head(root.path(), &keys).await;
    let stream = store
        .ensure_subscription_publication_stream(PublicationScope::Catalog)
        .await
        .expect("load retained-gap Catalog carrier");
    assert!(stream.counter_scope_token.is_some());
    assert!(stream.sender_counter_high_water.is_some());
    assert_eq!(stream.reserved_high_water, Some(0));
    assert_eq!(stream.committed_high_water, Some(0));
    assert_eq!(stream.acknowledged_high_water, Some(0));
    assert_eq!(stream.committed_inner_cursor, None);
    assert_eq!(stream.acknowledged_inner_cursor, None);
    assert_eq!(
        stream.last_committed_blob_hash,
        stream.last_acknowledged_blob_hash
    );
    assert!(stream.last_acknowledged_publication_id.is_some());
    assert!(stream.last_acknowledged_request_digest.is_some());
    assert_eq!(stream.rotation_serial, 0);
    assert!(stream.last_rotation_request_digest.is_none());
    let registration = store
        .register_stream_barrier(catalog_barrier(1, StreamCursor::At(0)))
        .await
        .expect("capture exact retained-gap Catalog head");
    assert_eq!(registration.high_water, StreamCursor::At(0));
    let outcome = store
        .finalize_subscription_publication(finalize_request(&registration))
        .await
        .expect("close baseline while Catalog revision zero remains retained");
    let (cut, overlap) = outcome.into_attached(&registration.watch);
    assert_eq!(cut.inner, StreamCursor::BeforeFirst);
    let mut overlap = overlap.expect("BeforeFirst to revision zero requires an exact overlap pin");
    let pin_id = overlap.pin().pin_id;
    store
        .release_backfill_pin(pin_id)
        .await
        .expect("release retained-gap setup overlap pin");
    overlap.disarm_after_release();
    drop(overlap);
    let baseline = store
        .load_publication_stream_record(stream.publication_stream_id)
        .await
        .expect("read retained-gap baseline winner");
    assert_eq!(
        baseline, stream,
        "non-pristine DirectoryAdvance readback must not rewrite the publication row"
    );
    release_registration(&store, registration).await;
    store
        .shutdown()
        .await
        .expect("shutdown retained-gap Store before trim");

    trim_catalog_through_head(root.path(), &keys, StreamCursor::At(0));

    let reopened = reopen_store(root.path(), &keys, None).await;
    let registration = reopened
        .register_stream_barrier(catalog_barrier(1, StreamCursor::At(0)))
        .await
        .expect("register SyncComplete barrier at trimmed Catalog head");
    assert_eq!(registration.high_water, StreamCursor::At(0));
    let error = finalize_error(&reopened, finalize_request(&registration)).await;
    assert!(matches!(error, RuntimeStoreError::PublicationNeedsSnapshot));
    assert_eq!(
        reopened
            .load_publication_stream_record(stream.publication_stream_id)
            .await
            .expect("read baseline after retained-gap rejection"),
        baseline,
        "failed overlap pin must not rewrite the already-finalized publication row"
    );

    release_registration(&reopened, registration).await;
    reopened
        .shutdown()
        .await
        .expect("shutdown retained-gap reopened Store");
}
