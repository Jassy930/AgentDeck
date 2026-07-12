#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeckd::runtime::store::{
    NewConversation, RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-commit-outcome-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create commit-outcome root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure commit-outcome root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load commit-outcome StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct FailCreateReplyOnce(AtomicBool);

impl FailCreateReplyOnce {
    fn new() -> Self {
        Self(AtomicBool::new(true))
    }
}

impl RuntimeStoreFaultInjector for FailCreateReplyOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::CreateConversationAfterCommit
            && self.0.swap(false, Ordering::SeqCst)
        {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

#[tokio::test]
async fn unknown_commit_reply_is_recovered_by_an_identical_retry() {
    let root = TestRoot::new();
    let keys = MemoryKeyStore::new();
    let input = NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, 1),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 2),
        descriptor: runtime_descriptor::descriptor(b"stable conversation descriptor"),
    };
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_fault_injector(Arc::new(FailCreateReplyOnce::new())),
        root.storage_kek(&keys),
    )
    .await
    .expect("open runtime store");

    let error = store
        .create_conversation(input.clone())
        .await
        .expect_err("committed write whose reply failed must be unknown");
    assert!(matches!(
        error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::CreateConversation
        }
    ));

    let replay = store
        .create_conversation(input.clone())
        .await
        .expect("identical retry resolves the unknown outcome");
    assert_eq!(replay.conversation_id, input.conversation_id);
    assert_eq!(replay.adapter_state_key, input.adapter_state_key);
    assert_eq!(replay.descriptor, input.descriptor);

    let recovery = runtime_recovery::load_recovery_state(&store)
        .await
        .expect("load recovery state");
    assert_eq!(recovery.conversations, vec![replay]);
    store.shutdown().await.expect("shutdown runtime store");
}
