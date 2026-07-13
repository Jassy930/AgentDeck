use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::AgentKind;
use agentdeckd::runtime::store::{
    ConversationDescriptor, NewConversation, RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeId,
    RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreHandle,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-read-pool-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create read-pool root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure read-pool root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db")).expect("load StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn conversation(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
            .expect("conversation id"),
        adapter_state_key: RuntimeId::from_bytes(
            RuntimeIdKind::AdapterState,
            [seed.wrapping_add(0x80); 16],
        )
        .expect("adapter state key"),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some(format!("read-pool-{seed}")),
            cwd: PathBuf::from("/tmp/runtime-read-pool"),
        },
    }
}

#[tokio::test]
async fn frozen_catalog_pages_use_64_row_short_reads_and_never_block_writer() {
    let root = TestRoot::new();
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store and eight-connection read pool");
    for seed in 1_u8..=65 {
        store
            .create_conversation(conversation(seed))
            .await
            .expect("append catalog delta");
    }
    let RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("freeze catalog revision 64")
    else {
        panic!("non-empty catalog requires a pin");
    };
    assert_eq!(pin.through, 64);
    let first = store
        .load_catalog_backfill_page(pin.clone(), None)
        .await
        .expect("read first pool page");
    assert_eq!(first.deltas.len(), 64);
    assert_eq!(first.next_after, 63);
    assert!(!first.complete);

    // `first` 故意继续持有 page memory lease，模拟慢 reply consumer。writer 不等
    // 这个 lease，也不持有跨网络 read transaction。
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        store.create_conversation(conversation(70)),
    )
    .await
    .expect("slow page consumer must not block writer")
    .expect("writer commits new catalog delta");

    let second = store
        .load_catalog_backfill_page(pin, Some(first.next_after))
        .await
        .expect("read final frozen page");
    assert_eq!(second.deltas.len(), 1);
    assert_eq!(second.deltas[0].catalog_revision, 64);
    assert_eq!(second.next_after, 64);
    assert!(second.complete);
    // revision 65 was committed after the frozen cut and cannot leak into either page.
    assert!(
        first
            .deltas
            .iter()
            .chain(second.deltas.iter())
            .all(|delta| delta.catalog_revision <= 64)
    );
    drop(first);
    drop(second);
    store
        .shutdown()
        .await
        .expect("shutdown store and read pool");
}

#[test]
fn store_handle_keeps_only_a_closeable_read_crypto_capability() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let worker = fs::read_to_string(root.join("src/runtime/store/worker.rs"))
        .expect("read runtime store worker source");
    let cipher = fs::read_to_string(root.join("src/runtime/store/cipher.rs"))
        .expect("read runtime store cipher source");
    assert!(worker.contains("read_crypto: RuntimeReadCryptoCapability"));
    assert!(!worker.contains("read_key_bundle: Arc<super::cipher::RuntimeKeyBundle>"));
    assert!(cipher.contains("pub(crate) struct RuntimeReadCryptoCapability"));
    assert!(cipher.contains("pub(crate) fn close(&self)"));
    assert!(cipher.contains("read crypto capability is closed"));
}
