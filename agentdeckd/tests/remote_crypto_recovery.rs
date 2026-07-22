use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, MachineRouteId, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeckd::remote::counter::{
    CounterDbState, CounterGuardBackend, CounterGuardState, CounterRecovery, CounterScope,
    reconcile_counter_recovery,
};
use agentdeckd::remote::identity::KeyStoreCounterGuardBackend;
use agentdeckd::remote::publisher::{
    PublicationSealAxes, SignedPublicationCoordinator, SignedPublicationRequest,
};
use agentdeckd::runtime::store::{
    PublicationPayloadKind, PublicationScope, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
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
            "agentdeckd-remote-signed-freeze-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create signed-freeze root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure signed-freeze root");
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
            .expect("load signed-freeze StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct FailOnceAt {
    operation: RuntimeStoreOperation,
    calls: AtomicUsize,
}

impl FailOnceAt {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            calls: AtomicUsize::new(0),
        }
    }
}

impl RuntimeStoreFaultInjector for FailOnceAt {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(RuntimeStoreError::InvalidConfig(
                "injected signed-publication freeze crash cut",
            ))
        } else {
            Ok(())
        }
    }
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

fn generation(seed: u8) -> StreamGenerationId {
    StreamGenerationId::from_bytes([seed; 16])
}

fn publication_scope(
    trust_domain: [u8; 32],
    purpose: KeyPurpose,
    epoch: u64,
    publication_stream_id: [u8; 16],
) -> CounterScope {
    CounterScope::publication(
        trust_domain,
        KeyId { purpose, epoch },
        publication_stream_id,
    )
    .expect("valid publication counter scope")
}

#[test]
fn counter_scope_separates_distinct_key_and_sender_ownership_domains() {
    let trust_a = [0x11; 32];
    let trust_b = [0x12; 32];
    let stream_a = [0x21; 16];
    let stream_b = [0x22; 16];

    let scopes = [
        publication_scope(trust_a, KeyPurpose::ConversationDek, 7, stream_a),
        publication_scope(trust_b, KeyPurpose::ConversationDek, 7, stream_a),
        publication_scope(trust_a, KeyPurpose::ConversationDek, 7, stream_b),
        publication_scope(trust_a, KeyPurpose::Catalog, 7, stream_a),
        publication_scope(trust_a, KeyPurpose::ConversationDek, 8, stream_a),
        CounterScope::directed_reply(
            trust_a,
            KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: 7,
            },
            device(0x41),
            GrantSerial::new(3),
        )
        .expect("valid directed-reply counter scope"),
    ];

    for (index, scope) in scopes.iter().enumerate() {
        assert_ne!(scope.token(), [0; 32]);
        assert!(
            scopes[..index]
                .iter()
                .all(|previous| previous.token() != scope.token()),
            "不同 key 或 sender ownership 输入必须派生不同的 CounterGuard account token"
        );
    }
}

#[test]
fn publication_scope_survives_route_and_generation_rollover_without_counter_restart() {
    let trust_domain = [0x4a; 32];
    let publication_stream_id = [0x4b; 16];
    let key_id = KeyId {
        purpose: KeyPurpose::ConversationDek,
        epoch: 7,
    };
    let previous_route = stream(0x4c);
    let next_route = stream(0x4d);
    let previous_generation = generation(0x4e);
    let next_generation = generation(0x4f);
    assert_ne!(previous_route, next_route);
    assert_ne!(previous_generation, next_generation);

    let before = CounterScope::publication(trust_domain, key_id, publication_stream_id)
        .expect("stable publication scope before Relay rollover");
    let after = CounterScope::publication(trust_domain, key_id, publication_stream_id)
        .expect("same daemon-local publication scope after Relay rollover");
    assert_eq!(before.token(), after.token());

    let stable = CounterGuardState::stable(before.token(), 1_024, [0x50; 32]).unwrap();
    let database = CounterDbState::unchanged(after.token(), 1_024, [0x50; 32]).unwrap();
    assert_eq!(
        reconcile_counter_recovery(&stable, &database).unwrap(),
        CounterRecovery::ReserveNextBlock { after: 1_024 },
        "generation rollover must continue after the durable high-water, never restart at zero"
    );

    for isolated in [
        CounterScope::publication([0x51; 32], key_id, publication_stream_id).unwrap(),
        CounterScope::publication(
            trust_domain,
            KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: 8,
            },
            publication_stream_id,
        )
        .unwrap(),
        CounterScope::publication(
            trust_domain,
            KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 7,
            },
            publication_stream_id,
        )
        .unwrap(),
        CounterScope::publication(trust_domain, key_id, [0x52; 16]).unwrap(),
    ] {
        assert_ne!(before.token(), isolated.token());
    }
}

#[test]
fn pending_guard_distinguishes_crash_gap_frozen_retry_and_backup_rollback() {
    let scope = publication_scope([0x51; 32], KeyPurpose::Catalog, 4, [0x52; 16]);
    let previous_anchor = [0x54; 32];
    let frozen_anchor = [0x55; 32];
    let publication_id = [0x56; 16];
    let reservation_id = [0x57; 16];
    let pending = CounterGuardState::pending(
        scope.token(),
        1_024,
        2_048,
        reservation_id,
        publication_id,
        previous_anchor,
    )
    .unwrap();

    assert_eq!(
        reconcile_counter_recovery(
            &pending,
            &CounterDbState::unchanged(scope.token(), 1_024, previous_anchor).unwrap(),
        )
        .unwrap(),
        CounterRecovery::GuardAheadGap {
            abandoned_through: 2_048,
        }
    );

    assert_eq!(
        reconcile_counter_recovery(
            &pending,
            &CounterDbState::frozen(
                scope.token(),
                2_048,
                reservation_id,
                publication_id,
                frozen_anchor,
            )
            .unwrap(),
        )
        .unwrap(),
        CounterRecovery::RetryFrozen {
            publication_id,
            exact_db_anchor: frozen_anchor,
        }
    );

    let stable = CounterGuardState::stable(scope.token(), 2_048, frozen_anchor).unwrap();
    assert_eq!(
        reconcile_counter_recovery(
            &stable,
            &CounterDbState::unchanged(scope.token(), 1_024, previous_anchor).unwrap(),
        )
        .unwrap(),
        CounterRecovery::RetireKey
    );
}

#[test]
fn counter_exhaustion_requires_epoch_retirement_without_wrap() {
    let scope = publication_scope([0x91; 32], KeyPurpose::Catalog, u64::MAX, [0x92; 16]);
    let guard = CounterGuardState::stable(scope.token(), u64::MAX - 511, [0x94; 32]).unwrap();
    let db = CounterDbState::unchanged(scope.token(), u64::MAX - 511, [0x94; 32]).unwrap();
    assert_eq!(
        reconcile_counter_recovery(&guard, &db).unwrap(),
        CounterRecovery::RetireKey
    );
}

#[test]
fn trust_epoch_is_part_of_directed_counter_scope() {
    let trust_domain = [0xa1; 32];
    let first = CounterScope::directed_reply_for_trust_epoch(
        trust_domain,
        machine(0xa2),
        TrustEpoch::new(1),
        device(0xa3),
        GrantSerial::new(4),
        7,
    )
    .unwrap();
    let second = CounterScope::directed_reply_for_trust_epoch(
        trust_domain,
        machine(0xa2),
        TrustEpoch::new(2),
        device(0xa3),
        GrantSerial::new(4),
        7,
    )
    .unwrap();
    assert_ne!(first.token(), second.token());
}

fn signed_request(
    publication_id: [u8; 16],
    publication_stream_id: [u8; 16],
    stream_generation: StreamGenerationId,
    counter_scope: CounterScope,
) -> SignedPublicationRequest {
    SignedPublicationRequest {
        publication_id,
        publication_stream_id,
        machine_route: machine(0xb1),
        generation: stream_generation,
        key_directory_revision: 7,
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 3,
        },
        counter_scope,
        inner_after: None,
        inner_through: None,
        payload_kind: PublicationPayloadKind::Control,
        sealer_retained_bytes: 0,
    }
}

async fn open_signed_store(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    fault: Option<Arc<dyn RuntimeStoreFaultInjector>>,
) -> RuntimeStoreHandle {
    let mut config = RuntimeStoreConfig::new(root.database());
    if let Some(fault) = fault {
        config = config.with_fault_injector(fault);
    }
    RuntimeStoreHandle::open(config, root.storage_kek(keys))
        .await
        .expect("open signed-publication Store")
}

async fn create_catalog_publication_stream(
    store: &RuntimeStoreHandle,
    publication_stream_id: [u8; 16],
    route: StreamRouteId,
    generation: StreamGenerationId,
) {
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            *route.as_bytes(),
            *generation.as_bytes(),
        )
        .await
        .expect("create signed-publication stream");
}

#[tokio::test]
async fn transaction_bound_sealer_observes_store_assigned_axes_once_and_exact_retry_skips_sealer() {
    let root = TestRoot::new("assigned-axes");
    let keys = MemoryKeyStore::new();
    let store = open_signed_store(&root, &keys, None).await;
    let publication_stream_id = [0xb2; 16];
    let route = stream(0xb3);
    let stream_generation = generation(0xb4);
    create_catalog_publication_stream(&store, publication_stream_id, route, stream_generation)
        .await;
    let scope = publication_scope([0xb5; 32], KeyPurpose::Catalog, 3, publication_stream_id);
    let request = signed_request([0xb6; 16], publication_stream_id, stream_generation, scope);
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let coordinator = SignedPublicationCoordinator::new(&store, &backend);
    let seal_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let first = coordinator
        .freeze_signed(request, {
            let seal_calls = seal_calls.clone();
            let observed = observed.clone();
            move |axes: PublicationSealAxes| {
                seal_calls.fetch_add(1, Ordering::SeqCst);
                observed
                    .lock()
                    .expect("record assigned axes")
                    .push((axes.stream_seq(), axes.sender_counter()));
                let mut exact = b"signed-from-assigned-axes".to_vec();
                exact.extend_from_slice(&axes.stream_seq().to_be_bytes());
                exact.extend_from_slice(&axes.sender_counter().to_be_bytes());
                Ok(exact)
            }
        })
        .await
        .expect("transaction-bound signed freeze");
    assert_eq!(seal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        observed.lock().expect("read assigned axes").as_slice(),
        &[(first.stream_seq, first.sender_counter)]
    );
    assert!(first.blob.ends_with(&first.sender_counter.to_be_bytes()));

    let repeated = coordinator
        .freeze_signed(
            request,
            |_axes: PublicationSealAxes| -> Result<Vec<u8>, _> {
                panic!("exact frozen retry must not invoke a second sealer")
            },
        )
        .await
        .expect("exact signed freeze retry");
    assert_eq!(repeated, first);
    assert_eq!(seal_calls.load(Ordering::SeqCst), 1);

    let persisted_guard = backend
        .load_guard(&scope)
        .expect("load finalized CounterGuard")
        .expect("CounterGuard exists");
    assert_eq!(
        persisted_guard.phase(),
        agentdeckd::remote::counter::CounterGuardPhase::Stable
    );
    assert_eq!(
        persisted_guard.database_anchor(),
        first
            .counter_db_anchor
            .expect("signed freeze has an authenticated counter anchor")
    );
    store
        .shutdown()
        .await
        .expect("shutdown assigned-axes Store");
}

#[tokio::test]
async fn coordinator_continues_the_generation_independent_guard_high_water() {
    let root = TestRoot::new("generation-independent-counter");
    let keys = MemoryKeyStore::new();
    let store = open_signed_store(&root, &keys, None).await;
    let publication_stream_id = [0xb7; 16];
    let route = stream(0xb8);
    let stream_generation = generation(0xb9);
    create_catalog_publication_stream(&store, publication_stream_id, route, stream_generation)
        .await;
    let key_id = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: 3,
    };
    let scope = CounterScope::publication([0xba; 32], key_id, publication_stream_id)
        .expect("stable daemon-local publication scope");
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let coordinator = SignedPublicationCoordinator::new(&store, &backend);

    let first = coordinator
        .freeze_signed(
            signed_request([0xbb; 16], publication_stream_id, stream_generation, scope),
            |axes| Ok(axes.sender_counter().to_be_bytes().to_vec()),
        )
        .await
        .expect("freeze first counter block");
    let next = coordinator
        .freeze_signed(
            signed_request([0xbc; 16], publication_stream_id, stream_generation, scope),
            |axes| Ok(axes.sender_counter().to_be_bytes().to_vec()),
        )
        .await
        .expect("reuse durable guard and database high-water");

    assert_eq!(first.sender_counter, 0);
    assert_eq!(
        next.sender_counter,
        first.sender_counter + agentdeckd::remote::counter::COUNTER_BLOCK_SIZE,
        "the next publication must consume the next reserved block, not restart from zero"
    );
    let guard = backend
        .load_guard(&scope)
        .expect("load generation-independent guard")
        .expect("stable guard exists");
    assert_eq!(
        guard.reserved_through(),
        2 * agentdeckd::remote::counter::COUNTER_BLOCK_SIZE
    );

    store
        .shutdown()
        .await
        .expect("shutdown generation-independent counter Store");
}

#[tokio::test]
async fn exact_retry_finds_publication_beyond_the_first_pending_page_without_resealing() {
    let root = TestRoot::new("exact-lookup-after-page");
    let keys = MemoryKeyStore::new();
    let store = open_signed_store(&root, &keys, None).await;
    let publication_stream_id = [0xba; 16];
    let route = stream(0xbb);
    let stream_generation = generation(0xbc);
    create_catalog_publication_stream(&store, publication_stream_id, route, stream_generation)
        .await;
    let scope = publication_scope([0xbd; 32], KeyPurpose::Catalog, 3, publication_stream_id);
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let coordinator = SignedPublicationCoordinator::new(&store, &backend);
    let mut last_request = None;
    let mut last_frozen = None;
    for ordinal in 1_u8..=65 {
        let request = signed_request(
            [ordinal; 16],
            publication_stream_id,
            stream_generation,
            scope,
        );
        let frozen = coordinator
            .freeze_signed(request, move |axes| {
                let mut blob = vec![ordinal; 32];
                blob.extend_from_slice(&axes.sender_counter().to_be_bytes());
                Ok(blob)
            })
            .await
            .expect("freeze pending publication");
        last_request = Some(request);
        last_frozen = Some(frozen);
    }
    assert_eq!(
        store
            .load_pending_publications(publication_stream_id)
            .await
            .expect("load deliberately truncated pending page")
            .len(),
        64,
        "fixture must place the exact retry target after the first pending page"
    );

    let repeated = coordinator
        .freeze_signed(
            last_request.expect("last signed request"),
            |_axes: PublicationSealAxes| -> Result<Vec<u8>, _> {
                panic!("authenticated publication-id lookup must skip resealing")
            },
        )
        .await
        .expect("exact retry after the first pending page");
    assert_eq!(repeated, last_frozen.expect("last frozen publication"));
    store.shutdown().await.expect("shutdown exact-lookup Store");
}

#[tokio::test]
async fn post_commit_unknown_reopens_exact_blob_and_finalizes_pending_guard_without_resealing() {
    let root = TestRoot::new("post-commit");
    let keys = MemoryKeyStore::new();
    let fault = Arc::new(FailOnceAt::new(
        RuntimeStoreOperation::FreezePublicationAfterCommit,
    ));
    let store = open_signed_store(&root, &keys, Some(fault)).await;
    let publication_stream_id = [0xc1; 16];
    let route = stream(0xc2);
    let stream_generation = generation(0xc3);
    create_catalog_publication_stream(&store, publication_stream_id, route, stream_generation)
        .await;
    let scope = publication_scope([0xc4; 32], KeyPurpose::Catalog, 3, publication_stream_id);
    let request = signed_request([0xc5; 16], publication_stream_id, stream_generation, scope);
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let coordinator = SignedPublicationCoordinator::new(&store, &backend);
    let exact = b"post-commit-exact-signed-blob".to_vec();
    let error = coordinator
        .freeze_signed(request, {
            let exact = exact.clone();
            move |_axes| Ok(exact)
        })
        .await
        .expect_err("after-COMMIT result is intentionally unknown");
    assert_eq!(error.code(), "daemon.remote.publisher.store_unavailable");
    assert_eq!(
        backend
            .load_guard(&scope)
            .expect("load pending guard")
            .expect("pending guard exists")
            .phase(),
        agentdeckd::remote::counter::CounterGuardPhase::Pending
    );
    store
        .shutdown()
        .await
        .expect("shutdown unknown-outcome Store");

    let reopened = open_signed_store(&root, &keys, None).await;
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let coordinator = SignedPublicationCoordinator::new(&reopened, &backend);
    let recovered = coordinator
        .freeze_signed(
            request,
            |_axes: PublicationSealAxes| -> Result<Vec<u8>, _> {
                panic!("durably frozen retry must not reseal")
            },
        )
        .await
        .expect("recover exact committed freeze");
    assert_eq!(recovered.blob, exact);
    let stable = backend
        .load_guard(&scope)
        .expect("load recovered guard")
        .expect("recovered guard exists");
    assert_eq!(
        stable.phase(),
        agentdeckd::remote::counter::CounterGuardPhase::Stable
    );
    assert_eq!(
        stable.database_anchor(),
        recovered
            .counter_db_anchor
            .expect("recovered signed freeze has an authenticated counter anchor")
    );
    reopened.shutdown().await.expect("shutdown recovered Store");
}

#[tokio::test]
async fn offline_counter_row_tamper_is_rejected_during_open_without_rewriting_database() {
    let root = TestRoot::new("counter-row-tamper");
    let keys = MemoryKeyStore::new();
    let store = open_signed_store(&root, &keys, None).await;
    let publication_stream_id = [0xca; 16];
    let route = stream(0xcb);
    let stream_generation = generation(0xcc);
    create_catalog_publication_stream(&store, publication_stream_id, route, stream_generation)
        .await;
    let scope = publication_scope([0xcd; 32], KeyPurpose::Catalog, 3, publication_stream_id);
    let request = signed_request([0xce; 16], publication_stream_id, stream_generation, scope);
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    SignedPublicationCoordinator::new(&store, &backend)
        .freeze_signed(request, |_axes| Ok(b"counter-audit-tamper-target".to_vec()))
        .await
        .expect("freeze authenticated counter row");
    store
        .shutdown()
        .await
        .expect("shutdown before offline tamper");

    let connection =
        rusqlite::Connection::open(root.database()).expect("open DB for offline tamper");
    let mut sealed: Vec<u8> = connection
        .query_row(
            "SELECT sealed_state FROM remote_counter_states",
            [],
            |row| row.get(0),
        )
        .expect("read sealed counter row");
    let last = sealed.last_mut().expect("sealed counter row is nonempty");
    *last ^= 0x01;
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_counter_states SET sealed_state = ?1",
                [&sealed],
            )
            .expect("tamper sealed counter row"),
        1
    );
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint offline tamper");
    drop(connection);
    let before = fs::read(root.database()).expect("read tampered DB bytes");

    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect_err("counter row tamper must fail during full open audit");
    assert!(matches!(
        error.code(),
        "daemon.runtime.schema_incompatible" | "daemon.runtime.crypto_failed"
    ));
    assert_eq!(
        fs::read(root.database()).expect("read DB after rejected open"),
        before,
        "offline tamper rejection must not rewrite the main database"
    );
}

#[tokio::test]
async fn database_backup_rollback_behind_stable_guard_retires_key_before_resealing() {
    let root = TestRoot::new("counter-backup-rollback");
    let keys = MemoryKeyStore::new();
    let publication_stream_id = [0xda; 16];
    let route = stream(0xdb);
    let stream_generation = generation(0xdc);
    let store = open_signed_store(&root, &keys, None).await;
    create_catalog_publication_stream(&store, publication_stream_id, route, stream_generation)
        .await;
    store.shutdown().await.expect("shutdown rollback baseline");
    let backup = root.path.join("runtime-before-counter.db");
    fs::copy(root.database(), &backup).expect("snapshot pre-counter database");

    let scope = publication_scope([0xdd; 32], KeyPurpose::Catalog, 3, publication_stream_id);
    let request = signed_request([0xde; 16], publication_stream_id, stream_generation, scope);
    let store = open_signed_store(&root, &keys, None).await;
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    SignedPublicationCoordinator::new(&store, &backend)
        .freeze_signed(request, |_axes| {
            Ok(b"must-not-survive-backup-rollback".to_vec())
        })
        .await
        .expect("advance DB and stable CounterGuard");
    store.shutdown().await.expect("shutdown advanced database");

    fs::copy(&backup, root.database()).expect("restore internally consistent older database");
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{}", root.database().display(), suffix));
    }
    let reopened = open_signed_store(&root, &keys, None).await;
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let startup_error = SignedPublicationCoordinator::new(&reopened, &backend)
        .audit_sender_scope(
            scope,
            KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 3,
            },
        )
        .await
        .expect_err("startup audit must retire a stable guard ahead of restored DB");
    assert_eq!(startup_error.code(), "daemon.remote.publisher.retire_key");
    let manifest: (Vec<u8>, String) = rusqlite::Connection::open(root.database())
        .expect("open rollback manifest readback")
        .query_row(
            "SELECT scope_token, phase FROM remote_counter_guard_manifest",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("rollback audit reconstructs authenticated guard inventory");
    assert_eq!(
        manifest,
        (scope.token().to_vec(), "materialized".to_owned())
    );
    let seal_calls = Arc::new(AtomicUsize::new(0));
    let error = SignedPublicationCoordinator::new(&reopened, &backend)
        .freeze_signed(request, {
            let seal_calls = seal_calls.clone();
            move |_axes| {
                seal_calls.fetch_add(1, Ordering::SeqCst);
                Ok(b"forbidden-reseal-after-rollback".to_vec())
            }
        })
        .await
        .expect_err("stable guard ahead of restored DB must retire the key");
    assert_eq!(error.code(), "daemon.remote.publisher.retire_key");
    assert_eq!(seal_calls.load(Ordering::SeqCst), 0);
    reopened.shutdown().await.expect("shutdown rollback Store");

    let connection = rusqlite::Connection::open(root.database())
        .expect("open rollback Store for durable retirement readback");
    let (lifecycle, purpose, key_epoch, reserved_end): (String, String, String, String) =
        connection
            .query_row(
                "SELECT lifecycle, purpose, key_epoch, reserved_end
             FROM remote_counter_states WHERE scope_token = ?1",
                [&scope.token()[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("RetireKey must commit an authenticated durable counter tombstone");
    assert_eq!(lifecycle, "retired");
    assert_eq!(purpose, "catalog");
    assert_eq!(key_epoch, "00000000000000000003");
    assert_eq!(reserved_end, "00000000000000001024");
    drop(connection);

    let retired = open_signed_store(&root, &keys, None).await;
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let retry_seal_calls = Arc::new(AtomicUsize::new(0));
    let error = SignedPublicationCoordinator::new(&retired, &backend)
        .freeze_signed(request, {
            let retry_seal_calls = retry_seal_calls.clone();
            move |_axes| {
                retry_seal_calls.fetch_add(1, Ordering::SeqCst);
                Ok(b"forbidden-reseal-after-durable-retirement".to_vec())
            }
        })
        .await
        .expect_err("durably retired scope must remain blocked after restart");
    assert_eq!(error.code(), "daemon.remote.publisher.retire_key");
    assert_eq!(retry_seal_calls.load(Ordering::SeqCst), 0);
    retired
        .shutdown()
        .await
        .expect("shutdown durably retired Store");
}

#[tokio::test]
async fn pre_commit_crash_abandons_reserved_block_before_same_publication_is_resealed() {
    let root = TestRoot::new("pre-commit");
    let keys = MemoryKeyStore::new();
    let fault = Arc::new(FailOnceAt::new(
        RuntimeStoreOperation::FreezePublicationBeforeCommit,
    ));
    let store = open_signed_store(&root, &keys, Some(fault)).await;
    let publication_stream_id = [0xd1; 16];
    let route = stream(0xd2);
    let stream_generation = generation(0xd3);
    create_catalog_publication_stream(&store, publication_stream_id, route, stream_generation)
        .await;
    let scope = publication_scope([0xd4; 32], KeyPurpose::Catalog, 3, publication_stream_id);
    let request = signed_request([0xd5; 16], publication_stream_id, stream_generation, scope);
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let coordinator = SignedPublicationCoordinator::new(&store, &backend);
    let first_counter = Arc::new(AtomicU64::new(u64::MAX));
    coordinator
        .freeze_signed(request, {
            let first_counter = first_counter.clone();
            move |axes| {
                first_counter.store(axes.sender_counter(), Ordering::SeqCst);
                Ok(b"rolled-back-seal".to_vec())
            }
        })
        .await
        .expect_err("before-COMMIT fault must roll back Store rows");
    store.shutdown().await.expect("shutdown rolled-back Store");

    let reopened = open_signed_store(&root, &keys, None).await;
    let backend = KeyStoreCounterGuardBackend::new(&keys);
    let coordinator = SignedPublicationCoordinator::new(&reopened, &backend);
    let recovered = coordinator
        .freeze_signed(request, |axes| {
            let mut exact = b"resealed-after-gap".to_vec();
            exact.extend_from_slice(&axes.sender_counter().to_be_bytes());
            Ok(exact)
        })
        .await
        .expect("skip abandoned block and reseal");
    assert!(
        recovered.sender_counter
            >= first_counter
                .load(Ordering::SeqCst)
                .checked_add(agentdeckd::remote::counter::COUNTER_BLOCK_SIZE)
                .expect("first block has a successor"),
        "崩溃前已经 Pending 的整块必须全部跳过"
    );
    assert_ne!(recovered.blob, b"rolled-back-seal");
    reopened
        .shutdown()
        .await
        .expect("shutdown gap-recovery Store");
}
