use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeckd::runtime::model::{COMMAND_QUEUE_TTL_MS, RuntimeClock, RuntimeClockError};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, IdempotencyOwner, NewConversation, RuntimeId, RuntimeIdKind,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreHandle,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

#[path = "support/store_admission.rs"]
mod store_admission;

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
            "agentdeckd-runtime-recovery-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create recovery root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure recovery root");
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
        load_or_create_storage_kek(keys, &self.path.join("key-state.db"))
            .expect("load recovery StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Debug)]
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

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid runtime id")
}

fn conversation_input(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: runtime_descriptor::descriptor(format!("recovery-{seed}").as_bytes()),
    }
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x11; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

async fn accept(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    seed: u8,
    payload: Vec<u8>,
) {
    assert!(matches!(
        store
            .accept_command(AcceptCommand {
                conversation_id,
                owner: owner(seed),
                idempotency_key: format!("request-{seed}"),
                payload,
            })
            .await
            .expect("accept recovery command"),
        AcceptOutcome::Accepted { .. }
    ));
}

#[tokio::test]
async fn recovery_pages_one_conversation_exactly_and_blocks_mutation_until_finish() {
    let root = TestRoot::new("paged");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open recovery store");
    let first = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create first conversation");
    let second = store
        .create_conversation(conversation_input(2))
        .await
        .expect("create second conversation");
    accept(&store, first.conversation_id, 1, b"first".to_vec()).await;
    accept(&store, second.conversation_id, 2, b"second".to_vec()).await;

    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin recovery scan");
    assert_eq!(
        store
            .begin_recovery_scan()
            .await
            .expect("lost begin reply retries exactly"),
        cursor
    );
    let first_page = store
        .load_recovery_page(cursor.clone())
        .await
        .expect("load first page");
    assert_eq!(
        store
            .load_recovery_page(cursor)
            .await
            .expect("lost page reply retries exactly"),
        first_page
    );
    let first_slice = first_page
        .conversation
        .as_ref()
        .expect("first page has one conversation");
    assert_eq!(
        first_slice.conversation.conversation_id,
        first.conversation_id
    );
    assert_eq!(first_slice.accepted.len(), 1);
    assert!(first_slice.started.is_none());
    assert!(first_page.completion.is_none());

    assert!(matches!(
        store.create_conversation(conversation_input(3)).await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));

    let second_cursor = first_page.next_cursor.expect("second page cursor");
    let second_page = store
        .load_recovery_page(second_cursor.clone())
        .await
        .expect("load second page");
    let second_slice = second_page
        .conversation
        .as_ref()
        .expect("second page has one conversation");
    assert_eq!(
        second_slice.conversation.conversation_id,
        second.conversation_id
    );
    assert!(second_page.next_cursor.is_none());
    let completion = second_page
        .completion
        .clone()
        .expect("terminal page has completion token");
    assert_eq!(
        store
            .load_recovery_page(second_cursor)
            .await
            .expect("terminal page retry is exact"),
        second_page
    );
    store
        .finish_recovery_scan(completion.clone())
        .await
        .expect("finish complete recovery scan");
    store
        .finish_recovery_scan(completion)
        .await
        .expect("lost finish reply retries exactly");
    store
        .create_conversation(conversation_input(3))
        .await
        .expect("writes resume only after explicit finish");
    store.shutdown().await.expect("shutdown recovery store");
}

#[tokio::test]
async fn recovery_sweeps_expired_commands_before_freezing_the_page_counts() {
    let root = TestRoot::new("expiry-first");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open expiry recovery store");
    let conversation = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create conversation");
    accept(
        &store,
        conversation.conversation_id,
        1,
        vec![0x44; 16 * 1024],
    )
    .await;
    clock.set(1_000 + COMMAND_QUEUE_TTL_MS);

    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("expiry sweep precedes frozen scan");
    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load post-expiry page");
    let slice = page.conversation.expect("conversation remains in catalog");
    assert!(slice.accepted.is_empty());
    assert!(slice.started.is_none());
    assert_eq!(slice.conversation.accepted_command_count, 0);
    assert_eq!(slice.conversation.event_high_water, Some(0));
    store
        .finish_recovery_scan(page.completion.expect("single page completes"))
        .await
        .expect("finish post-expiry scan");
    store
        .shutdown()
        .await
        .expect("shutdown expiry recovery store");
}

#[tokio::test]
async fn recovery_memory_is_bounded_per_conversation_not_by_the_total_queue_or_lane_budget() {
    let root = TestRoot::new("independent-budget");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_lane_byte_capacity(8 * 1024),
        root.storage_kek(&keys),
    )
    .await
    .expect("open small-lane recovery store");
    for seed in 1..=16_u8 {
        let conversation = store
            .create_conversation(conversation_input(seed))
            .await
            .expect("create paged conversation");
        accept(
            &store,
            conversation.conversation_id,
            seed,
            vec![seed; 4 * 1024],
        )
        .await;
    }

    let mut cursor = store
        .begin_recovery_scan()
        .await
        .expect("total recovery set may exceed lane budget");
    let mut recovered = 0_usize;
    let completion = loop {
        let page = store
            .load_recovery_page(cursor)
            .await
            .expect("load bounded recovery page");
        assert!(page.conversation.is_some());
        recovered += 1;
        match (page.next_cursor, page.completion) {
            (Some(next), None) => cursor = next,
            (None, Some(completion)) => break completion,
            _ => panic!("page cursor/completion shape must be canonical"),
        }
    };
    assert_eq!(recovered, 16);
    store
        .finish_recovery_scan(completion)
        .await
        .expect("finish bounded recovery scan");
    store.shutdown().await.expect("shutdown small-lane store");
}

#[tokio::test]
async fn a_cursor_from_another_scan_is_rejected_without_advancing_the_valid_scan() {
    let first_root = TestRoot::new("wrong-cursor-first");
    let second_root = TestRoot::new("wrong-cursor-second");
    let first_keys = MemoryKeyStore::new();
    let second_keys = MemoryKeyStore::new();
    let first = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(first_root.database()),
        first_root.storage_kek(&first_keys),
    )
    .await
    .expect("open first recovery store");
    let second = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(second_root.database()),
        second_root.storage_kek(&second_keys),
    )
    .await
    .expect("open second recovery store");
    first
        .create_conversation(conversation_input(1))
        .await
        .expect("create first recovery row");
    second
        .create_conversation(conversation_input(2))
        .await
        .expect("create second recovery row");

    let valid_cursor = first.begin_recovery_scan().await.expect("begin first scan");
    let foreign_cursor = second
        .begin_recovery_scan()
        .await
        .expect("begin second scan");
    assert!(matches!(
        first.load_recovery_page(foreign_cursor).await,
        Err(RuntimeStoreError::InvalidRecoveryCursor)
    ));
    let first_page = first
        .load_recovery_page(valid_cursor)
        .await
        .expect("valid cursor still starts at first page");
    assert_eq!(
        first_page
            .conversation
            .as_ref()
            .expect("first page record")
            .conversation
            .conversation_id,
        runtime_id(RuntimeIdKind::Conversation, 1)
    );
    first
        .finish_recovery_scan(first_page.completion.expect("first terminal page"))
        .await
        .expect("finish first scan");

    let second_page = second
        .load_recovery_page(
            second
                .begin_recovery_scan()
                .await
                .expect("unconsumed begin retry is exact"),
        )
        .await
        .expect("load second page");
    second
        .finish_recovery_scan(second_page.completion.expect("second terminal page"))
        .await
        .expect("finish second scan");
    first.shutdown().await.expect("shutdown first store");
    second.shutdown().await.expect("shutdown second store");
}
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
