use super::*;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Instant;

use crate::runtime::store::{RuntimeId, RuntimeIdKind};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::super::cipher::{CipherError, RowAad};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentdeckd-runtime-shutdown-unit-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create isolated runtime store root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure runtime store root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, store: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(store, &self.0.join("key-state.db"))
            .expect("create or reload test StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct BlockingAfterCommit {
    blocked: AtomicBool,
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
}

impl crate::runtime::model::RuntimeStoreFaultInjector for BlockingAfterCommit {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::CreateConversationAfterCommit
            && !self.blocked.swap(true, Ordering::SeqCst)
        {
            self.entered
                .send(())
                .map_err(|_| RuntimeStoreError::WorkerStopped)?;
            self.release
                .lock()
                .map_err(|_| RuntimeStoreError::WorkerStopped)?
                .recv()
                .map_err(|_| RuntimeStoreError::WorkerStopped)?;
        }
        Ok(())
    }
}

fn conversation_input() -> NewConversation {
    NewConversation {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x41; 16])
            .expect("conversation id"),
        adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x42; 16])
            .expect("adapter state key"),
        descriptor: crate::runtime::model::ConversationDescriptor {
            agent_kind: agentdeck_protocol::AgentKind::Codex,
            title: Some("shutdown-timeout".to_owned()),
            cwd: PathBuf::from("/tmp/agentdeck-runtime-test"),
        },
    }
}

#[tokio::test]
async fn shutdown_deadline_only_reports_that_quiescence_was_not_observed() {
    let (_reply, result) = oneshot::channel();

    let error = await_shutdown_quiescence(result, Duration::from_millis(1))
        .await
        .expect_err("held reply must cross the observation deadline");

    assert!(matches!(error, RuntimeStoreError::ShutdownTimedOut));
}

#[test]
fn store_watch_incarnation_entropy_failure_is_typed_before_worker_ready() {
    let (cleanup_tx, _cleanup_rx) = mpsc::unbounded_channel();
    let error = match store_commit_hub_from_entropy(cleanup_tx, |_| Err(())) {
        Ok(_) => panic!("entropy failure must reject worker initialization"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RuntimeStoreError::WatchIncarnationEntropyUnavailable
    ));
    assert_eq!(error.code(), "daemon.runtime.store_unavailable");
}

#[tokio::test]
async fn shutdown_closes_live_store_watch_before_waiting_for_blocked_read_pool() {
    let root = TestRoot::new();
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");
    let registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: crate::runtime::events::WatchGeneration::new(1).expect("watch generation"),
            request: crate::runtime::backfill::BarrierRequest::Subscribe {
                cursor: agentdeck_protocol::runtime::StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register live store watch");
    let mut watch = registration.watch;
    let (read_entered_tx, read_entered_rx) = oneshot::channel();
    let (read_release_tx, read_release_rx) = oneshot::channel();
    let blocked_read = tokio::spawn({
        let read_pool = store.read_pool.clone();
        async move {
            read_pool
                .run(async move {
                    let _ = read_entered_tx.send(());
                    let _ = read_release_rx.await;
                })
                .await
        }
    });
    read_entered_rx.await.expect("read pool operation entered");

    let read_pool = store.read_pool.clone();
    let shutdown = tokio::spawn(async move { store.shutdown().await });
    loop {
        match read_pool.run(async {}).await {
            Err(ReadPoolError::Closed) => break,
            Ok(()) | Err(ReadPoolError::Busy) => tokio::task::yield_now().await,
            Err(error) => panic!("unexpected read pool probe failure: {error}"),
        }
    }
    let watch_closed_before_read_quiescence = tokio::select! {
        biased;
        result = watch.next_committed() => result.is_err(),
        _ = tokio::task::yield_now() => false,
    };

    read_release_tx.send(()).expect("release blocked read");
    blocked_read
        .await
        .expect("join blocked read")
        .expect("blocked read completes");
    shutdown
        .await
        .expect("join store shutdown")
        .expect("store shutdown completes");
    assert!(
        watch_closed_before_read_quiescence,
        "StoreCommitHub must drop and close external watches before read_pool close_and_wait"
    );
}

#[tokio::test]
async fn shutdown_timeout_cannot_cancel_read_crypto_finalization() {
    let root = TestRoot::new();
    let keys = MemoryKeyStore::new();
    let (worker_entered_tx, worker_entered_rx) = sync_channel(1);
    let (worker_release_tx, worker_release_rx) = sync_channel(1);
    let mut store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
            BlockingAfterCommit {
                blocked: AtomicBool::new(false),
                entered: worker_entered_tx,
                release: Mutex::new(worker_release_rx),
            },
        )),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");
    store.shutdown_timeout = Duration::from_millis(10);
    let surviving = store.clone();
    let in_flight = tokio::spawn({
        let store = store.clone();
        async move { store.create_conversation(conversation_input()).await }
    });
    tokio::task::spawn_blocking(move || {
        worker_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker blocks after commit");
    })
    .await
    .expect("join worker entered observer");
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let blocked_read = tokio::spawn({
        let read_pool = store.read_pool.clone();
        async move {
            read_pool
                .run(async move {
                    let _ = entered_tx.send(());
                    let _ = release_rx.await;
                })
                .await
        }
    });
    entered_rx.await.expect("read becomes active");

    assert!(
        surviving
            .read_crypto
            .verify_blind_index(b"shutdown-finalizer", b"before", &[0; 32])
            .is_ok(),
        "surviving handle starts with a live read capability"
    );
    let error = store
        .shutdown()
        .await
        .expect_err("active read must cross the short observation deadline");
    assert!(matches!(error, RuntimeStoreError::ShutdownTimedOut));

    let reopen_error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("blocked worker must retain its path lease");
    assert!(matches!(reopen_error, RuntimeStoreError::StoreAlreadyOpen));

    release_tx.send(()).expect("release active read");
    blocked_read
        .await
        .expect("join active read")
        .expect("active read completes during shutdown");
    assert!(
        surviving
            .read_crypto
            .verify_blind_index(b"shutdown-finalizer", b"between", &[0; 32])
            .is_ok(),
        "worker still using its row keys prevents early read-key zeroization"
    );

    worker_release_tx.send(()).expect("release blocked worker");
    in_flight
        .await
        .expect("join in-flight operation")
        .expect("operation committed before shutdown won arbitration");

    let deadline = Instant::now() + Duration::from_secs(2);
    while surviving
        .read_crypto
        .verify_blind_index(b"shutdown-finalizer", b"after", &[0; 32])
        .is_ok()
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let aad = RowAad {
        schema_family: b"agentdeck.runtime",
        schema_version: 1,
        database_id: &[0x11; 16],
        table: b"fixture",
        primary_key: b"row",
        column: b"payload",
    };
    assert!(matches!(
        surviving.read_crypto.open_bounded(&aad, &[], 64),
        Err(CipherError::ReadCapabilityClosed)
    ));
    assert!(matches!(
        surviving
            .read_crypto
            .verify_blind_index(b"shutdown-finalizer", b"after", &[0; 32]),
        Err(CipherError::ReadCapabilityClosed)
    ));

    drop(surviving);
    // 威胁场景：高并发测试调度会放大 read crypto close 与 dedicated worker
    // thread 最终 drop path lease 之间的合法短窗口；只要 lease 最终释放就满足
    // shutdown contract，不能把一次立即 reopen 的调度竞态误报为资源泄漏。
    let reopen_deadline = Instant::now() + Duration::from_secs(2);
    let reopened = loop {
        match RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        {
            Ok(store) => break store,
            Err(RuntimeStoreError::StoreAlreadyOpen) if Instant::now() < reopen_deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("worker must eventually release path lease: {error}"),
        }
    };
    reopened
        .shutdown()
        .await
        .expect("shutdown explicitly reopened worker");
}

#[test]
fn shutdown_finalization_survives_caller_runtime_drop() {
    let root = TestRoot::new();
    let keys = MemoryKeyStore::new();
    let (worker_entered_tx, worker_entered_rx) = sync_channel(1);
    let (worker_release_tx, worker_release_rx) = sync_channel(1);
    let caller_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("caller runtime");
    let surviving = caller_runtime.block_on(async {
        let mut store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                BlockingAfterCommit {
                    blocked: AtomicBool::new(false),
                    entered: worker_entered_tx,
                    release: Mutex::new(worker_release_rx),
                },
            )),
            root.storage_kek(&keys),
        )
        .await
        .expect("open runtime store");
        store.shutdown_timeout = Duration::from_millis(10);
        let surviving = store.clone();
        let in_flight = tokio::spawn({
            let store = store.clone();
            async move { store.create_conversation(conversation_input()).await }
        });
        tokio::task::spawn_blocking(move || {
            worker_entered_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("worker blocks after commit");
        })
        .await
        .expect("join worker entered observer");
        let error = store
            .shutdown()
            .await
            .expect_err("blocked worker crosses the observation deadline");
        assert!(matches!(error, RuntimeStoreError::ShutdownTimedOut));
        drop(in_flight);
        surviving
    });

    // Tokio runtime shutdown aborts ordinary spawned async tasks. Store finalization must
    // therefore be owned by the dedicated store worker, not this caller runtime.
    drop(caller_runtime);
    worker_release_tx.send(()).expect("release blocked worker");
    let deadline = Instant::now() + Duration::from_secs(2);
    while surviving
        .read_crypto
        .verify_blind_index(b"runtime-drop-finalizer", b"after", &[0; 32])
        .is_ok()
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        surviving
            .read_crypto
            .verify_blind_index(b"runtime-drop-finalizer", b"after", &[0; 32]),
        Err(CipherError::ReadCapabilityClosed)
    ));

    drop(surviving);
    let verification_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("verification runtime");
    let reopen_deadline = Instant::now() + Duration::from_secs(2);
    let reopened = loop {
        match verification_runtime.block_on(RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )) {
            Ok(store) => break store,
            Err(RuntimeStoreError::StoreAlreadyOpen) if Instant::now() < reopen_deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("worker must eventually release path lease: {error}"),
        }
    };
    verification_runtime
        .block_on(reopened.shutdown())
        .expect("shutdown reopened worker");
}

#[tokio::test]
async fn timeout_and_handle_drop_keep_the_path_lease_until_the_worker_exits() {
    let root = TestRoot::new();
    let keys = MemoryKeyStore::new();
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let mut store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
            BlockingAfterCommit {
                blocked: AtomicBool::new(false),
                entered: entered_tx,
                release: Mutex::new(release_rx),
            },
        )),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");
    store.shutdown_timeout = Duration::from_millis(10);
    let stale = store.clone();
    let in_flight = tokio::spawn({
        let store = store.clone();
        async move { store.create_conversation(conversation_input()).await }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(2)))
        .await
        .expect("join entered wait")
        .expect("operation blocks after commit");

    let error = store
        .shutdown()
        .await
        .expect_err("blocked worker must cross the short observation deadline");
    assert!(matches!(error, RuntimeStoreError::ShutdownTimedOut));
    assert!(matches!(
        stale.clone().shutdown().await,
        Err(RuntimeStoreError::ShutdownInProgress)
    ));

    drop(stale);
    let reopen_error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("timeout and handle drop must not release the live worker lease");
    assert!(matches!(reopen_error, RuntimeStoreError::StoreAlreadyOpen));

    release_tx.send(()).expect("release blocked worker");
    in_flight
        .await
        .expect("join in-flight operation")
        .expect("operation committed before shutdown won arbitration");

    let deadline = Instant::now() + Duration::from_secs(2);
    let reopened = loop {
        match RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        {
            Ok(reopened) => break reopened,
            Err(RuntimeStoreError::StoreAlreadyOpen) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("worker did not release resources after exit: {error}"),
        }
    };
    reopened
        .shutdown()
        .await
        .expect("shutdown the single explicitly reopened worker");
}
