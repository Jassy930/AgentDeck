use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentdeckd::runtime::store::{
    NewConversation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-shutdown-{}-{sequence}",
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

impl RuntimeStoreFaultInjector for BlockingAfterCommit {
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
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x51; 16])
            .expect("conversation id"),
        adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x52; 16])
            .expect("adapter state key"),
        descriptor: runtime_descriptor::descriptor(b"shutdown-cancellation"),
    }
}

#[tokio::test]
async fn dropped_shutdown_waiter_keeps_singleton_until_the_worker_really_exits() {
    let root = TestRoot::new();
    let keys = MemoryKeyStore::new();
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let store = RuntimeStoreHandle::open(
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
    let stale = store.clone();
    let in_flight = tokio::spawn({
        let store = store.clone();
        async move { store.create_conversation(conversation_input()).await }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(2)))
        .await
        .expect("join entered wait")
        .expect("operation blocks after commit");

    let mut shutdown = Box::pin(store.shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
            .await
            .is_err(),
        "shutdown is waiting for worker quiescence"
    );
    drop(shutdown);
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
    .expect_err("dropping all handles must not release the live worker lease");
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
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
