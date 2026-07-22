use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, StreamRouteId, TrustEpoch,
};
use agentdeckd::remote::replay::{
    RemoteReplayConfig, RemoteReplayGuard, ReplayDecision, ReplayKeyScope, ReplayObservation,
    ReplayReadiness, ReplaySignatureStatus,
};
use agentdeckd::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

#[path = "support/store_admission.rs"]
mod store_admission;

const CURRENT_REVISION: u64 = 7;
const RETIRED_REPLAY_RETENTION_MS: u64 = 25 * 60 * 60 * 1_000;

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
            "agentdeckd-remote-replay-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create remote replay test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure remote replay test root");
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
            .expect("load remote replay StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn open_store(root: &TestRoot, keys: &MemoryKeyStore) -> RuntimeStoreHandle {
    RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(keys),
    )
    .await
    .expect("open Runtime store for remote replay")
}

fn machine(seed: u8) -> MachineRouteId {
    MachineRouteId::from_bytes([seed; 16])
}

fn device(seed: u8) -> DeviceRouteId {
    DeviceRouteId::from_bytes([seed; 16])
}

fn stream(seed: u8) -> StreamRouteId {
    StreamRouteId::from_bytes([seed; 16])
}

fn command_scope(seed: u8) -> ReplayKeyScope {
    ReplayKeyScope::device_command(
        machine(seed),
        TrustEpoch::new(1),
        device(seed.wrapping_add(1)),
        GrantSerial::new(1),
        1,
    )
    .expect("valid DeviceCommandTx replay scope")
}

fn observation(
    scope: ReplayKeyScope,
    revision: u64,
    counter: u64,
    hash_seed: u8,
) -> ReplayObservation {
    ReplayObservation {
        scope,
        key_directory_revision: KeyDirectoryRevision::new(revision),
        sender_counter: counter,
        ciphertext_sha256: [hash_seed; 32],
        signature: ReplaySignatureStatus::Verified,
        readiness: ReplayReadiness::Ready,
    }
}

async fn admit(
    guard: &RemoteReplayGuard,
    observation: ReplayObservation,
) -> Result<ReplayDecision, agentdeckd::remote::replay::ReplayError> {
    guard
        .admit(KeyDirectoryRevision::new(CURRENT_REVISION), observation)
        .await
}

#[tokio::test]
async fn counter_scope_covers_machine_trust_device_grant_stream_purpose_and_epoch() {
    let root = TestRoot::new("complete-counter-scope");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default());

    let machine_a = machine(0x11);
    let machine_b = machine(0x12);
    let device_a = device(0x21);
    let device_b = device(0x22);
    let stream_a = stream(0x31);
    let stream_b = stream(0x32);
    let trust_1 = TrustEpoch::new(1);
    let trust_2 = TrustEpoch::new(2);
    let grant_1 = GrantSerial::new(1);
    let grant_2 = GrantSerial::new(2);

    let scopes = [
        ReplayKeyScope::device_command(machine_a, trust_1, device_a, grant_1, 7).unwrap(),
        ReplayKeyScope::device_command(machine_b, trust_1, device_a, grant_1, 7).unwrap(),
        ReplayKeyScope::device_command(machine_a, trust_2, device_a, grant_1, 7).unwrap(),
        ReplayKeyScope::device_command(machine_a, trust_1, device_b, grant_1, 7).unwrap(),
        ReplayKeyScope::device_command(machine_a, trust_1, device_a, grant_2, 7).unwrap(),
        ReplayKeyScope::device_reply(machine_a, trust_1, device_a, grant_1, 7).unwrap(),
        ReplayKeyScope::device_command(machine_a, trust_1, device_a, grant_1, 8).unwrap(),
        ReplayKeyScope::conversation(machine_a, trust_1, stream_a, 7).unwrap(),
        ReplayKeyScope::conversation(machine_a, trust_1, stream_b, 7).unwrap(),
        ReplayKeyScope::catalog(machine_a, trust_1, 7).unwrap(),
    ];

    for scope in &scopes {
        assert_eq!(
            admit(
                &guard,
                observation(scope.clone(), CURRENT_REVISION, 9, 0x41)
            )
            .await
            .expect("each complete key scope owns an independent counter window"),
            ReplayDecision::Fresh
        );
    }

    assert_eq!(
        admit(
            &guard,
            observation(scopes[0].clone(), CURRENT_REVISION, 9, 0x41),
        )
        .await
        .expect("same complete scope and tuple is a duplicate"),
        ReplayDecision::ExactDuplicate
    );

    drop(guard);
    store.shutdown().await.expect("shutdown Runtime store");
}

#[tokio::test]
async fn replay_window_accepts_out_of_order_and_marks_only_below_floor_stale() {
    let root = TestRoot::new("window");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default());
    let scope = command_scope(0x41);

    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 10, 0x10),
        )
        .await
        .unwrap(),
        ReplayDecision::Fresh
    );
    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 4_105, 0x11),
        )
        .await
        .unwrap(),
        ReplayDecision::Fresh
    );
    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 2_000, 0x12),
        )
        .await
        .expect("unseen counter inside the 4,096-entry window is valid out-of-order delivery"),
        ReplayDecision::Fresh
    );
    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 10, 0x10),
        )
        .await
        .expect("the inclusive floor is still retained"),
        ReplayDecision::ExactDuplicate
    );

    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 4_106, 0x13),
        )
        .await
        .unwrap(),
        ReplayDecision::Fresh
    );
    let stale = admit(&guard, observation(scope, CURRENT_REVISION, 10, 0xff))
        .await
        .expect("below-floor tuple is stale without historical hash comparison");
    assert_eq!(stale, ReplayDecision::Stale);
    assert!(!stale.should_dispatch_to_runtime_core());

    drop(guard);
    store.shutdown().await.expect("shutdown Runtime store");
}

#[tokio::test]
async fn exact_duplicate_reenters_runtime_idempotency_but_nonce_reuse_isolated() {
    let root = TestRoot::new("duplicate-vs-reuse");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default());
    let scope = command_scope(0x51);

    let fresh = admit(
        &guard,
        observation(scope.clone(), CURRENT_REVISION, 42, 0x21),
    )
    .await
    .unwrap();
    assert_eq!(fresh, ReplayDecision::Fresh);
    assert!(fresh.should_dispatch_to_runtime_core());

    // replay state 可能已 COMMIT，而 daemon 在 RuntimeCore admission 前崩溃。完全相同的
    // tuple 必须再次进入 Core，由 durable idempotency ledger 重放原 receipt，不能在 link 丢弃。
    let duplicate = admit(
        &guard,
        observation(scope.clone(), CURRENT_REVISION, 42, 0x21),
    )
    .await
    .unwrap();
    assert_eq!(duplicate, ReplayDecision::ExactDuplicate);
    assert!(duplicate.should_dispatch_to_runtime_core());

    let reuse = admit(
        &guard,
        observation(scope.clone(), CURRENT_REVISION, 42, 0x22),
    )
    .await
    .expect_err("same counter with a different ciphertext hash is nonce reuse");
    assert_eq!(reuse.code(), "daemon.remote.replay.nonce_reuse");
    assert!(reuse.requires_connection_isolation());

    let same_epoch = admit(
        &guard,
        observation(scope.clone(), CURRENT_REVISION, 43, 0x23),
    )
    .await
    .expect_err("nonce reuse durably retires the compromised sender epoch");
    assert_eq!(same_epoch.code(), "daemon.remote.replay.retired_key");
    assert!(same_epoch.requires_connection_isolation());

    drop(guard);
    store.shutdown().await.expect("shutdown Runtime store");

    let reopened = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(reopened.clone(), RemoteReplayConfig::default());
    let after_retention_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock follows Unix epoch")
            .as_millis(),
    )
    .expect("current wall clock fits u64")
    .saturating_add(RETIRED_REPLAY_RETENTION_MS);
    assert_eq!(
        guard
            .gc_retired(after_retention_ms)
            .await
            .expect("compromised sender epoch GC remains well formed"),
        0,
        "ordinary retention GC must not erase nonce-reuse quarantine while the sender epoch can still be presented"
    );
    assert!(
        guard.contains_scope(&scope).await.unwrap(),
        "nonce-reuse quarantine remains durable after the ordinary retention deadline"
    );
    let after_restart = admit(&guard, observation(scope, CURRENT_REVISION, 44, 0x24))
        .await
        .expect_err("compromised sender epoch stays retired across daemon restart");
    assert_eq!(after_restart.code(), "daemon.remote.replay.retired_key");
    drop(guard);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened compromised replay store");
}

#[tokio::test]
async fn sender_counter_zero_is_a_durable_first_tuple_not_an_absence_sentinel() {
    let root = TestRoot::new("counter-zero");
    let keys = MemoryKeyStore::new();
    let scope = command_scope(0x55);
    let store = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default());

    let first = admit(
        &guard,
        observation(scope.clone(), CURRENT_REVISION, 0, 0x25),
    )
    .await
    .expect("SenderCounter(0) is the first valid nonce tuple");
    assert_eq!(first, ReplayDecision::Fresh);
    assert!(first.should_dispatch_to_runtime_core());

    let duplicate = admit(
        &guard,
        observation(scope.clone(), CURRENT_REVISION, 0, 0x25),
    )
    .await
    .expect("counter zero exact tuple is replayable");
    assert_eq!(duplicate, ReplayDecision::ExactDuplicate);
    assert!(duplicate.should_dispatch_to_runtime_core());

    drop(guard);
    store
        .shutdown()
        .await
        .expect("shutdown counter-zero Runtime store");

    let reopened = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(reopened.clone(), RemoteReplayConfig::default());
    assert_eq!(
        admit(&guard, observation(scope, CURRENT_REVISION, 0, 0x25))
            .await
            .expect("counter zero survives authenticated state decode"),
        ReplayDecision::ExactDuplicate
    );

    drop(guard);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened counter-zero Runtime store");
}

#[tokio::test]
async fn replay_commit_survives_restart_and_exact_retry_remains_dispatchable() {
    let root = TestRoot::new("restart-before-core");
    let keys = MemoryKeyStore::new();
    let scope = command_scope(0x59);
    let store = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default());
    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 73, 0x29),
        )
        .await
        .expect("durably commit replay tuple before simulated Core crash"),
        ReplayDecision::Fresh
    );
    drop(guard);
    store
        .shutdown()
        .await
        .expect("shutdown after replay COMMIT");

    let reopened = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(reopened.clone(), RemoteReplayConfig::default());
    let retry = admit(&guard, observation(scope, CURRENT_REVISION, 73, 0x29))
        .await
        .expect("restart reads exact durable replay tuple");
    assert_eq!(retry, ReplayDecision::ExactDuplicate);
    assert!(
        retry.should_dispatch_to_runtime_core(),
        "exact retry must reach the durable Runtime idempotency ledger"
    );

    drop(guard);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened Runtime store");
}

#[tokio::test]
async fn revision_signature_and_barrier_readiness_gate_before_replay_commit() {
    let root = TestRoot::new("revision-readiness");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default());

    let lower_scope = command_scope(0x61);
    let rollback = admit(
        &guard,
        observation(lower_scope.clone(), CURRENT_REVISION - 1, 1, 0x31),
    )
    .await
    .expect_err("lower key-directory revision is rollback");
    assert_eq!(rollback.code(), "daemon.remote.replay.revision_rollback");
    assert!(rollback.requires_connection_isolation());
    assert!(!guard.contains_scope(&lower_scope).await.unwrap());

    let higher_scope = command_scope(0x62);
    let mut unverified_higher = observation(higher_scope.clone(), CURRENT_REVISION + 1, 2, 0x32);
    unverified_higher.signature = ReplaySignatureStatus::Unverified;
    let unverified = admit(&guard, unverified_higher)
        .await
        .expect_err("unverified higher revision must not request KeySync");
    assert_eq!(
        unverified.code(),
        "daemon.remote.replay.signature_unverified"
    );
    assert!(unverified.requires_connection_isolation());
    assert!(!guard.contains_scope(&higher_scope).await.unwrap());

    let key_sync = admit(
        &guard,
        observation(higher_scope.clone(), CURRENT_REVISION + 1, 2, 0x32),
    )
    .await
    .expect("only a verified higher revision requests bounded KeySync");
    assert_eq!(
        key_sync,
        ReplayDecision::KeySyncRequired {
            local_revision: KeyDirectoryRevision::new(CURRENT_REVISION),
            observed_revision: KeyDirectoryRevision::new(CURRENT_REVISION + 1),
        }
    );
    assert!(!key_sync.should_dispatch_to_runtime_core());
    assert!(
        guard.contains_scope(&higher_scope).await.unwrap(),
        "verified higher-revision probes still consume the command-key replay tuple"
    );
    assert_eq!(
        admit(
            &guard,
            observation(higher_scope.clone(), CURRENT_REVISION + 1, 2, 0x32),
        )
        .await
        .expect("exact higher-revision retry remains an idempotent KeySync trigger"),
        ReplayDecision::KeySyncRequired {
            local_revision: KeyDirectoryRevision::new(CURRENT_REVISION),
            observed_revision: KeyDirectoryRevision::new(CURRENT_REVISION + 1),
        }
    );
    let higher_nonce_reuse = admit(
        &guard,
        observation(higher_scope, CURRENT_REVISION + 1, 2, 0x35),
    )
    .await
    .expect_err("higher-revision probe cannot reuse a command nonce with different ciphertext");
    assert_eq!(
        higher_nonce_reuse.code(),
        "daemon.remote.replay.nonce_reuse"
    );
    assert!(higher_nonce_reuse.requires_connection_isolation());

    let barrier_scope = command_scope(0x63);
    let mut barrier_pending = observation(barrier_scope.clone(), CURRENT_REVISION, 3, 0x33);
    barrier_pending.readiness = ReplayReadiness::WaitingForBarrier;
    let waiting = admit(&guard, barrier_pending).await.unwrap();
    assert_eq!(waiting, ReplayDecision::WaitingForBarrier);
    assert!(!waiting.should_dispatch_to_runtime_core());
    assert!(!guard.contains_scope(&barrier_scope).await.unwrap());
    assert_eq!(
        admit(
            &guard,
            observation(barrier_scope, CURRENT_REVISION, 3, 0x33),
        )
        .await
        .expect("barrier wait must not consume the tuple"),
        ReplayDecision::Fresh
    );

    let key_scope = command_scope(0x64);
    let mut key_pending = observation(key_scope.clone(), CURRENT_REVISION, 4, 0x34);
    key_pending.readiness = ReplayReadiness::WaitingForKey;
    let waiting = admit(&guard, key_pending).await.unwrap();
    assert_eq!(waiting, ReplayDecision::WaitingForKey);
    assert!(!waiting.should_dispatch_to_runtime_core());
    assert!(!guard.contains_scope(&key_scope).await.unwrap());
    assert_eq!(
        admit(&guard, observation(key_scope, CURRENT_REVISION, 4, 0x34),)
            .await
            .expect("key wait must not consume the tuple"),
        ReplayDecision::Fresh
    );

    drop(guard);
    store.shutdown().await.expect("shutdown Runtime store");
}

#[tokio::test]
async fn replay_window_and_exact_hashes_survive_runtime_store_restart() {
    let root = TestRoot::new("restart");
    let keys = MemoryKeyStore::new();
    let scope = command_scope(0x71);

    let store = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default());
    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 5_000, 0x41),
        )
        .await
        .unwrap(),
        ReplayDecision::Fresh
    );
    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 1_000, 0x42),
        )
        .await
        .unwrap(),
        ReplayDecision::Fresh
    );
    drop(guard);
    store
        .shutdown()
        .await
        .expect("shutdown before replay restart");

    let reopened = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(reopened.clone(), RemoteReplayConfig::default());
    for (counter, hash_seed) in [(5_000, 0x41), (1_000, 0x42)] {
        let duplicate = admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, counter, hash_seed),
        )
        .await
        .expect("persisted tuple must remain an exact duplicate after restart");
        assert_eq!(duplicate, ReplayDecision::ExactDuplicate);
        assert!(duplicate.should_dispatch_to_runtime_core());
    }
    assert_eq!(
        admit(&guard, observation(scope, CURRENT_REVISION, 904, 0xff),)
            .await
            .expect("persisted floor rejects stale replay after restart"),
        ReplayDecision::Stale
    );

    drop(guard);
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened Runtime store");
}

#[tokio::test]
async fn retired_replay_state_keeps_24h_plus_1h_and_gc_respects_pins() {
    let root = TestRoot::new("retired-gc");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let guard = RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default());
    let scope = command_scope(0x81);
    let retired_at_ms = 1_000_000;
    let pin_id = [0x82; 16];

    assert_eq!(
        admit(
            &guard,
            observation(scope.clone(), CURRENT_REVISION, 9, 0x51),
        )
        .await
        .unwrap(),
        ReplayDecision::Fresh
    );
    guard
        .retire_scope(scope.clone(), retired_at_ms)
        .await
        .expect("retire replay scope");
    guard
        .pin_retired_scope(scope.clone(), pin_id)
        .await
        .expect("pin replay state needed by retained Relay data");

    assert_eq!(
        guard
            .gc_retired(retired_at_ms + RETIRED_REPLAY_RETENTION_MS - 1)
            .await
            .unwrap(),
        0
    );
    assert!(guard.contains_scope(&scope).await.unwrap());

    assert_eq!(
        guard
            .gc_retired(retired_at_ms + RETIRED_REPLAY_RETENTION_MS)
            .await
            .expect("pin blocks GC at the 25-hour cutoff"),
        0
    );
    assert!(guard.contains_scope(&scope).await.unwrap());

    guard
        .release_retired_pin(scope.clone(), pin_id)
        .await
        .expect("release replay retention pin");
    assert_eq!(
        guard
            .gc_retired(retired_at_ms + RETIRED_REPLAY_RETENTION_MS)
            .await
            .expect("unpinned retired state is collected at cutoff"),
        1
    );
    assert!(!guard.contains_scope(&scope).await.unwrap());

    drop(guard);
    store.shutdown().await.expect("shutdown Runtime store");
}

#[tokio::test]
async fn replay_capacity_fails_closed_without_evicting_an_existing_guard() {
    let root = TestRoot::new("capacity");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let config = RemoteReplayConfig::default().with_scope_capacity(1);
    let guard = RemoteReplayGuard::new(store.clone(), config);
    let first = command_scope(0x91);
    let second = command_scope(0x92);

    assert_eq!(
        admit(
            &guard,
            observation(first.clone(), CURRENT_REVISION, 1, 0x61),
        )
        .await
        .unwrap(),
        ReplayDecision::Fresh
    );
    let capacity = admit(
        &guard,
        observation(second.clone(), CURRENT_REVISION, 1, 0x62),
    )
    .await
    .expect_err("capacity exhaustion must stop admission");
    assert_eq!(capacity.code(), "daemon.remote.replay.capacity");
    assert!(!capacity.requires_connection_isolation());
    assert!(guard.contains_scope(&first).await.unwrap());
    assert!(!guard.contains_scope(&second).await.unwrap());

    let first_again = admit(&guard, observation(first, CURRENT_REVISION, 1, 0x61))
        .await
        .expect("capacity failure must not evict the existing replay guard");
    assert_eq!(first_again, ReplayDecision::ExactDuplicate);
    assert!(first_again.should_dispatch_to_runtime_core());

    drop(guard);
    store.shutdown().await.expect("shutdown Runtime store");
}
