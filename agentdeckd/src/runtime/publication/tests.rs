use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_protocol::AgentKind;

use super::*;
use crate::runtime::store::{
    ConversationDescriptor, FreezePublicationRequest, NewConversation, PublicationPayloadKind,
    PublicationScope, RuntimeClock, RuntimeClockError, RuntimeId, RuntimeIdKind,
    RuntimeStoreConfig, RuntimeStoreFaultInjector, RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-publication-dispatch-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create publication test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure publication test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn new(now_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_ms)))
    }
}

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct OneShotFault {
    operation: RuntimeStoreOperation,
    fired: AtomicBool,
}

impl OneShotFault {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            fired: AtomicBool::new(false),
        }
    }
}

impl RuntimeStoreFaultInjector for OneShotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && !self.fired.swap(true, Ordering::SeqCst) {
            Err(RuntimeStoreError::InvalidConfig(
                "injected publication dispatcher fault",
            ))
        } else {
            Ok(())
        }
    }
}

struct OneShotSafetyBusy(AtomicBool);

impl RuntimeStoreFaultInjector for OneShotSafetyBusy {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::CommitPublicationBeforeCommit
            && !self.0.swap(true, Ordering::SeqCst)
        {
            Err(RuntimeStoreError::WorkerBusy {
                lane: RuntimeStoreLane::Safety,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
enum TransportPlan {
    ExactCommit,
    WrongReceipt,
    OutcomeUnknown,
    Offline,
    Panic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SentPublication {
    key: PublicationDispatchKey,
    blob: Vec<u8>,
}

struct ScriptedTransport {
    plans: Mutex<VecDeque<TransportPlan>>,
    sent: Mutex<Vec<SentPublication>>,
    active: Mutex<HashMap<[u8; 16], usize>>,
    max_per_stream: Mutex<HashMap<[u8; 16], usize>>,
    active_global: AtomicUsize,
    max_global: AtomicUsize,
}

impl ScriptedTransport {
    fn new(plans: impl IntoIterator<Item = TransportPlan>) -> Self {
        Self {
            plans: Mutex::new(plans.into_iter().collect()),
            sent: Mutex::new(Vec::new()),
            active: Mutex::new(HashMap::new()),
            max_per_stream: Mutex::new(HashMap::new()),
            active_global: AtomicUsize::new(0),
            max_global: AtomicUsize::new(0),
        }
    }

    fn sent(&self) -> Vec<SentPublication> {
        self.sent.lock().expect("sent lock").clone()
    }

    fn max_per_stream(&self) -> usize {
        self.max_per_stream
            .lock()
            .expect("max stream lock")
            .values()
            .copied()
            .max()
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl PublicationTransport for ScriptedTransport {
    async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
        let key = PublicationDispatchKey::from(&publication);
        self.sent.lock().expect("sent lock").push(SentPublication {
            key,
            blob: publication.blob.clone(),
        });
        {
            let mut active = self.active.lock().expect("active stream lock");
            let count = active.entry(key.publication_stream_id).or_default();
            *count += 1;
            let mut maximum = self.max_per_stream.lock().expect("max stream lock");
            maximum
                .entry(key.publication_stream_id)
                .and_modify(|current| *current = (*current).max(*count))
                .or_insert(*count);
        }
        let global = self.active_global.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_global.fetch_max(global, Ordering::SeqCst);
        tokio::task::yield_now().await;
        self.active_global.fetch_sub(1, Ordering::SeqCst);
        *self
            .active
            .lock()
            .expect("active stream lock")
            .get_mut(&key.publication_stream_id)
            .expect("active stream entry") -= 1;

        match self
            .plans
            .lock()
            .expect("transport plan lock")
            .pop_front()
            .unwrap_or(TransportPlan::ExactCommit)
        {
            TransportPlan::ExactCommit => {
                PublicationTransportOutcome::Committed(PublicationCommitReceipt { key })
            }
            TransportPlan::WrongReceipt => {
                let mut wrong = key;
                wrong.stream_seq = wrong.stream_seq.saturating_add(1);
                PublicationTransportOutcome::Committed(PublicationCommitReceipt { key: wrong })
            }
            TransportPlan::OutcomeUnknown => PublicationTransportOutcome::OutcomeUnknown,
            TransportPlan::Offline => PublicationTransportOutcome::Offline,
            TransportPlan::Panic => panic!("injected publication transport panic"),
        }
    }
}

async fn open_store(
    label: &str,
    fault: Option<Arc<dyn RuntimeStoreFaultInjector>>,
) -> (TestRoot, RuntimeStoreHandle) {
    let root = TestRoot::new(label);
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
        .expect("create publication test KEK");
    let mut config = RuntimeStoreConfig::new(root.database()).with_clock(ManualClock::new(1_000));
    if let Some(fault) = fault {
        config = config.with_fault_injector(fault);
    }
    let store = RuntimeStoreHandle::open(config, kek)
        .await
        .expect("open publication store");
    (root, store)
}

fn id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("runtime id")
}

async fn create_conversation(store: &RuntimeStoreHandle, seed: u8) -> RuntimeId {
    let conversation_id = id(RuntimeIdKind::Conversation, seed);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some(format!("publication-{seed}")),
                cwd: PathBuf::from("/tmp/publication-dispatch"),
            },
        })
        .await
        .expect("create publication conversation");
    conversation_id
}

async fn create_stream(
    store: &RuntimeStoreHandle,
    seed: u8,
    scope: PublicationScope,
) -> ([u8; 16], [u8; 16]) {
    let stream_id = [seed; 16];
    let generation = [seed.wrapping_add(1); 16];
    store
        .create_publication_stream(stream_id, scope, [seed.wrapping_add(2); 16], generation)
        .await
        .expect("create publication stream");
    (stream_id, generation)
}

fn publication_id(seed: u8, sequence: u64) -> [u8; 16] {
    let mut value = [seed; 16];
    value[8..].copy_from_slice(&sequence.to_be_bytes());
    value
}

#[allow(
    clippy::too_many_arguments,
    reason = "publication fixture keeps every frozen identity/range field explicit at call sites"
)]
async fn freeze(
    store: &RuntimeStoreHandle,
    stream_id: [u8; 16],
    generation: [u8; 16],
    seed: u8,
    sequence: u64,
    after: Option<u64>,
    through: u64,
    payload_kind: PublicationPayloadKind,
    blob: Vec<u8>,
) -> FrozenPublication {
    store
        .freeze_publication(FreezePublicationRequest {
            publication_id: publication_id(seed, sequence + 1),
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [seed.wrapping_add(3); 32],
            sender_counter: sequence + 1,
            inner_after: after,
            inner_through: Some(through),
            payload_kind,
            blob,
        })
        .await
        .expect("freeze publication")
}

#[tokio::test]
async fn publication_freezes_generation_seq_counter_blob_and_inner_range_atomically() {
    let (_root, store) = open_store("atomic-freeze", None).await;
    let (stream_id, generation) = create_stream(&store, 0x11, PublicationScope::Catalog).await;
    let transport = Arc::new(ScriptedTransport::new([TransportPlan::ExactCommit]));
    let mut dispatcher = PublicationDispatcher::open(store.clone(), transport)
        .await
        .unwrap();
    let blob = b"exact frozen publication".to_vec();
    let frozen = freeze(
        &store,
        stream_id,
        generation,
        0x11,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        blob.clone(),
    )
    .await;
    assert_eq!(frozen.generation, generation);
    assert_eq!(frozen.stream_seq, 0);
    assert_eq!(frozen.sender_counter, 1);
    assert_eq!((frozen.inner_after, frozen.inner_through), (None, Some(0)));
    assert_eq!(frozen.blob, blob);
    assert_eq!(
        store.load_pending_publication_streams().await.unwrap(),
        [stream_id]
    );
    dispatcher.notify_frozen_stream(stream_id);
    assert_eq!(dispatcher.drive_round().await.unwrap().committed, 1);
    drop(dispatcher);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn read_pool_busy_defers_without_terminalizing_and_retries_on_next_drive() {
    let (_root, store) = open_store("read-pool-busy-deferred", None).await;
    let conversation_id = create_conversation(&store, 0xc1).await;
    let snapshot_source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture snapshot source for retained read lease");
    store
        .store_conversation_snapshot_fixture_for_test(
            snapshot_source,
            1,
            b"authenticated snapshot read lease fixture".to_vec(),
        )
        .await
        .expect("store retained read lease fixture");

    let (stream_id, generation) = create_stream(&store, 0xd1, PublicationScope::Catalog).await;
    let exact_blob = b"publication deferred only while read pool is busy".to_vec();
    freeze(
        &store,
        stream_id,
        generation,
        0xd1,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        exact_blob.clone(),
    )
    .await;
    let transport = Arc::new(ScriptedTransport::new([TransportPlan::ExactCommit]));
    let mut dispatcher = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .expect("discover pending publication before exhausting read pool");

    // load_conversation_snapshot 的返回值真实持有整池 128 MiB retained lease。
    let held_snapshot = store
        .load_conversation_snapshot(conversation_id)
        .await
        .expect("load snapshot and hold full read pool")
        .expect("stored snapshot fixture");
    let deferred = dispatcher
        .drive_round()
        .await
        .expect("transient ReadPool busy must not terminalize the stream");
    assert_eq!((deferred.loaded, deferred.committed), (0, 0));
    assert_eq!(
        dispatcher.state(stream_id),
        Some(DispatcherStreamState::Ready)
    );
    assert!(transport.sent().is_empty());

    drop(held_snapshot);
    let resumed = dispatcher
        .drive_round()
        .await
        .expect("next owner drive retries after read lease release");
    assert_eq!((resumed.loaded, resumed.committed), (1, 1));
    let sent = transport.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].blob, exact_blob);
    assert!(
        store
            .load_pending_publication_streams()
            .await
            .expect("read committed pending directory")
            .is_empty()
    );

    drop(dispatcher);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_after_commit_unknown_replays_byte_identical_blob() {
    let fault = Arc::new(OneShotFault::new(
        RuntimeStoreOperation::CommitPublicationAfterCommit,
    ));
    let (_root, store) = open_store("commit-unknown", Some(fault)).await;
    let (stream_id, generation) = create_stream(&store, 0x21, PublicationScope::Catalog).await;
    freeze(
        &store,
        stream_id,
        generation,
        0x21,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        b"commit outcome exact bytes".to_vec(),
    )
    .await;
    let transport = Arc::new(ScriptedTransport::new([TransportPlan::ExactCommit]));
    let mut dispatcher = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .unwrap();
    let first = dispatcher.drive_round().await.unwrap();
    assert_eq!((first.committed, first.commit_pending), (0, 1));
    let second = dispatcher.drive_round().await.unwrap();
    assert_eq!(second.committed, 1);
    assert_eq!(transport.sent().len(), 1, "store retry must not republish");
    drop(dispatcher);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn safety_lane_busy_retries_exact_commit_without_republishing() {
    let fault = Arc::new(OneShotSafetyBusy(AtomicBool::new(false)));
    let (_root, store) = open_store("safety-busy-commit-retry", Some(fault)).await;
    let (stream_id, generation) = create_stream(&store, 0x29, PublicationScope::Catalog).await;
    freeze(
        &store,
        stream_id,
        generation,
        0x29,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        b"safety lane busy exact commit".to_vec(),
    )
    .await;
    let transport = Arc::new(ScriptedTransport::new([TransportPlan::ExactCommit]));
    let mut dispatcher = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .expect("discover pending publication");

    let first = dispatcher
        .drive_round()
        .await
        .expect("transient safety busy remains commit-pending");
    assert_eq!((first.committed, first.commit_pending), (0, 1));
    assert_eq!(transport.sent().len(), 1);

    let second = dispatcher
        .drive_round()
        .await
        .expect("next owner drive retries the exact local commit");
    assert_eq!(second.committed, 1);
    assert_eq!(
        transport.sent().len(),
        1,
        "local safety-lane retry must not call transport.publish again"
    );

    drop(dispatcher);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_ack_requires_exact_generation_seq_and_blob_hash() {
    let (_root, store) = open_store("exact-receipt", None).await;
    let (stream_id, generation) = create_stream(&store, 0x31, PublicationScope::Catalog).await;
    freeze(
        &store,
        stream_id,
        generation,
        0x31,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        b"receipt-bound bytes".to_vec(),
    )
    .await;
    let transport = Arc::new(ScriptedTransport::new([TransportPlan::WrongReceipt]));
    let mut dispatcher = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .unwrap();
    assert!(matches!(
        dispatcher.drive_round().await,
        Err(PublicationDispatchError::ReceiptMismatch)
    ));
    assert!(matches!(
        dispatcher.state(stream_id),
        Some(DispatcherStreamState::TerminalError)
    ));
    freeze(
        &store,
        stream_id,
        generation,
        0x31,
        1,
        Some(0),
        1,
        PublicationPayloadKind::Catalog,
        b"later frozen bytes".to_vec(),
    )
    .await;
    dispatcher.notify_frozen_stream(stream_id);
    assert_eq!(dispatcher.discover_pending().await.unwrap(), 0);
    let after_notify = dispatcher.drive_round().await.unwrap();
    assert_eq!((after_notify.loaded, after_notify.committed), (0, 0));
    assert_eq!(transport.sent().len(), 1, "terminal error must fail closed");
    assert_eq!(
        store.load_pending_publication_streams().await.unwrap(),
        [stream_id]
    );
    drop(dispatcher);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_child_panic_terminalizes_its_stream() {
    let (_root, store) = open_store("child-panic", None).await;
    let (stream_id, generation) = create_stream(&store, 0x39, PublicationScope::Catalog).await;
    freeze(
        &store,
        stream_id,
        generation,
        0x39,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        b"panic-bound bytes".to_vec(),
    )
    .await;
    let transport = Arc::new(ScriptedTransport::new([TransportPlan::Panic]));
    let mut dispatcher = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .unwrap();
    assert!(matches!(
        dispatcher.drive_round().await,
        Err(PublicationDispatchError::ChildTaskFailed)
    ));
    assert!(matches!(
        dispatcher.state(stream_id),
        Some(DispatcherStreamState::TerminalError)
    ));
    let second = dispatcher.drive_round().await.unwrap();
    assert_eq!((second.loaded, second.committed), (0, 0));
    assert_eq!(transport.sent().len(), 1);
    assert_eq!(
        store.load_pending_publication_streams().await.unwrap(),
        [stream_id]
    );
    drop(dispatcher);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_restart_retries_frozen_rows_without_resealing() {
    let (_root, store) = open_store("restart-retry", None).await;
    let (stream_id, generation) = create_stream(&store, 0x41, PublicationScope::Catalog).await;
    freeze(
        &store,
        stream_id,
        generation,
        0x41,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        b"byte-identical restart row".to_vec(),
    )
    .await;
    let transport = Arc::new(ScriptedTransport::new([
        TransportPlan::OutcomeUnknown,
        TransportPlan::ExactCommit,
    ]));
    let mut first = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .unwrap();
    assert_eq!(first.drive_round().await.unwrap().outcome_unknown, 1);
    drop(first);
    let mut restarted = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .unwrap();
    assert_eq!(restarted.drive_round().await.unwrap().committed, 1);
    let sent = transport.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1]);
    drop(restarted);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_dispatch_is_fair_with_one_inflight_per_stream() {
    let (_root, store) = open_store("fair-dispatch", None).await;
    let mut stream_ids = Vec::new();
    for seed in [0x51, 0x61, 0x71] {
        let conversation = create_conversation(&store, seed).await;
        let (stream_id, generation) =
            create_stream(&store, seed, PublicationScope::Conversation(conversation)).await;
        freeze(
            &store,
            stream_id,
            generation,
            seed,
            0,
            None,
            0,
            PublicationPayloadKind::Event,
            vec![seed; 32],
        )
        .await;
        stream_ids.push(stream_id);
    }
    let transport = Arc::new(ScriptedTransport::new([]));
    let mut dispatcher = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .unwrap();
    assert_eq!(dispatcher.drive_round().await.unwrap().committed, 2);
    let first_round = transport.sent();
    assert_eq!(first_round.len(), 2);
    assert_eq!(dispatcher.drive_round().await.unwrap().committed, 1);
    let sent = transport.sent();
    assert!(
        sent.iter()
            .any(|row| row.key.publication_stream_id == stream_ids[2])
    );
    assert_eq!(transport.max_per_stream(), 1);
    assert!(transport.max_global.load(Ordering::SeqCst) <= 2);
    assert_eq!(MAX_PUBLICATION_MEMORY_BYTES, 16 * 1024 * 1024);
    drop(dispatcher);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_outbox_caps_never_drop_unacked_rows() {
    let (root, store) = open_store("outbox-cap", None).await;
    let (stream_id, generation) = create_stream(&store, 0x81, PublicationScope::Catalog).await;
    let blob = vec![0x5a; 4 * 1024 * 1024];
    for sequence in 0..16 {
        freeze(
            &store,
            stream_id,
            generation,
            0x81,
            sequence,
            sequence.checked_sub(1),
            sequence,
            PublicationPayloadKind::Catalog,
            blob.clone(),
        )
        .await;
    }
    let rejected = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: publication_id(0x81, 17),
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x84; 32],
            sender_counter: 17,
            inner_after: Some(15),
            inner_through: Some(16),
            payload_kind: PublicationPayloadKind::Catalog,
            blob,
        })
        .await
        .expect_err("65 MiB outbox must require snapshot");
    assert!(matches!(
        rejected,
        RuntimeStoreError::PublicationNeedsSnapshot
    ));
    let connection = rusqlite::Connection::open(root.database()).expect("open cap readback");
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM publication_outbox WHERE publication_stream_id = ?1",
            [&stream_id[..]],
            |row| row.get(0),
        )
        .expect("count retained outbox rows");
    assert_eq!(rows, 16);
    drop(connection);
    assert_eq!(
        store.load_pending_publication_streams().await.unwrap(),
        [stream_id]
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_inner_ranges_have_no_gap_or_overlap() {
    let (_root, store) = open_store("inner-ranges", None).await;
    let (stream_id, generation) = create_stream(&store, 0x91, PublicationScope::Catalog).await;
    freeze(
        &store,
        stream_id,
        generation,
        0x91,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        b"range zero".to_vec(),
    )
    .await;
    for (publication, after, through) in [(2, Some(1), 2), (3, None, 1)] {
        let error = store
            .freeze_publication(FreezePublicationRequest {
                publication_id: publication_id(0x91, publication),
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: [0x94; 32],
                sender_counter: publication,
                inner_after: after,
                inner_through: Some(through),
                payload_kind: PublicationPayloadKind::Catalog,
                blob: b"invalid range".to_vec(),
            })
            .await
            .expect_err("gap/overlap must fail closed");
        assert!(matches!(error, RuntimeStoreError::PublicationMismatch));
    }
    freeze(
        &store,
        stream_id,
        generation,
        0x91,
        1,
        Some(0),
        1,
        PublicationPayloadKind::Catalog,
        b"exact next range".to_vec(),
    )
    .await;
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn authenticated_pending_stream_enumeration_rejects_directory_tamper() {
    let (root, store) = open_store("directory-tamper", None).await;
    let (stream_id, generation) = create_stream(&store, 0xa1, PublicationScope::Catalog).await;
    freeze(
        &store,
        stream_id,
        generation,
        0xa1,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        b"directory authenticated".to_vec(),
    )
    .await;
    rusqlite::Connection::open(root.database())
        .expect("open tamper connection")
        .execute(
            "UPDATE publication_streams SET metadata_token = zeroblob(32)
             WHERE publication_stream_id = ?1",
            [&stream_id[..]],
        )
        .expect("tamper stream metadata token");
    assert!(matches!(
        store.load_pending_publication_streams().await,
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn offline_waits_for_explicit_reconnect_without_hot_loop() {
    let (_root, store) = open_store("offline-wake", None).await;
    let (stream_id, generation) = create_stream(&store, 0xb1, PublicationScope::Catalog).await;
    freeze(
        &store,
        stream_id,
        generation,
        0xb1,
        0,
        None,
        0,
        PublicationPayloadKind::Catalog,
        b"offline exact row".to_vec(),
    )
    .await;
    let transport = Arc::new(ScriptedTransport::new([
        TransportPlan::Offline,
        TransportPlan::ExactCommit,
    ]));
    let mut dispatcher = PublicationDispatcher::open(store.clone(), transport.clone())
        .await
        .unwrap();
    assert!(dispatcher.drive_round().await.unwrap().offline);
    assert!(dispatcher.drive_round().await.unwrap().offline);
    assert_eq!(transport.sent().len(), 1);
    dispatcher.notify_reconnected();
    assert_eq!(dispatcher.drive_round().await.unwrap().committed, 1);
    assert_eq!(transport.sent().len(), 2);
    drop(dispatcher);
    store.shutdown().await.expect("shutdown store");
}
