//! P4.5 CounterGuard scope manifest 的 authenticated Store focused tests。

use rusqlite::Connection;

use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::cipher::{KeyWrapAad, RuntimeKeyBundle};
use super::pairing_tests::{GenerousCapacity, TestRoot, artifact_bytes};
use super::remote_counter_guard_manifest::{MAX_REMOTE_COUNTER_GUARD_SCOPES, metadata_token};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sqlite::{load_runtime_ledger, update_runtime_ledger};

async fn open_store(root: &TestRoot, keys: &MemoryKeyStore) -> RuntimeStoreHandle {
    RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(GenerousCapacity),
        load_or_create_storage_kek(keys, &root.database()).expect("load manifest test StorageKEK"),
    )
    .await
    .expect("open manifest test Store")
}

fn fill_manifest_to_capacity(root: &TestRoot, keys: &MemoryKeyStore) {
    let storage_kek = load_or_create_storage_kek(keys, &root.database())
        .expect("reload capacity fixture StorageKEK");
    let mut connection = Connection::open(root.database()).expect("open capacity fixture writer");
    let (database_id, generation, wrapped): (Vec<u8>, i64, Vec<u8>) = connection
        .query_row(
            "SELECT database_id, key_generation, wrapped_key_bundle
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read capacity fixture key metadata");
    let database_id: [u8; 16] = database_id.try_into().expect("database id shape");
    let key_bundle = RuntimeKeyBundle::unwrap(
        &storage_kek,
        &KeyWrapAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
        },
        &wrapped,
    )
    .expect("unwrap capacity fixture row keys");
    assert_eq!(i64::from(key_bundle.generation()), generation);

    let transaction = connection.transaction().expect("begin capacity fixture");
    let ledger = load_runtime_ledger(&transaction, &key_bundle, database_id)
        .expect("authenticate capacity fixture ledger");
    assert_eq!(ledger.remote_counter_guard_manifest_count, 0);
    for index in 1..=MAX_REMOTE_COUNTER_GUARD_SCOPES {
        let mut scope_token = [0_u8; 32];
        scope_token[24..].copy_from_slice(&index.to_be_bytes());
        let token = metadata_token(&key_bundle, database_id, scope_token, false)
            .expect("authenticate capacity fixture row");
        transaction
            .execute(
                "INSERT INTO remote_counter_guard_manifest
                     (scope_token, database_id, phase, metadata_token)
                 VALUES (?1, ?2, 'reserved', ?3)",
                rusqlite::params![&scope_token[..], &database_id[..], &token[..]],
            )
            .expect("insert capacity fixture row");
    }
    let mut next = ledger.clone();
    next.remote_counter_guard_manifest_count = MAX_REMOTE_COUNTER_GUARD_SCOPES;
    let _ = update_runtime_ledger(&transaction, &key_bundle, database_id, &ledger, &next)
        .expect("publish capacity fixture ledger");
    transaction.commit().expect("commit capacity fixture");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint capacity fixture");
}

#[tokio::test]
async fn reserved_to_materialized_is_canonical_and_survives_restart() {
    let root = TestRoot::new("counter-guard-manifest-restart");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;

    store
        .register_remote_counter_guard_scope([0x42; 32])
        .await
        .expect("register later scope");
    store
        .register_remote_counter_guard_scope([0x21; 32])
        .await
        .expect("register earlier scope");
    assert_eq!(
        store
            .load_remote_counter_guard_manifest()
            .await
            .expect("load authenticated manifest"),
        vec![[0x21; 32], [0x42; 32]]
    );
    assert_eq!(
        store
            .load_remote_counter_guard_cleanup_manifest()
            .await
            .expect("load reserved cleanup phases"),
        vec![([0x21; 32], false), ([0x42; 32], false)]
    );
    store
        .mark_remote_counter_guard_scope_materialized([0x42; 32])
        .await
        .expect("mark later scope materialized");
    assert_eq!(
        store
            .load_remote_counter_guard_cleanup_manifest()
            .await
            .expect("load mixed cleanup phases"),
        vec![([0x21; 32], false), ([0x42; 32], true)]
    );
    store.shutdown().await.expect("shutdown manifest Store");

    let connection = Connection::open(root.database()).expect("open manifest count reader");
    assert_eq!(
        connection
            .query_row(
                "SELECT remote_counter_guard_manifest_count FROM runtime_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("read manifest ledger count"),
        2
    );
    drop(connection);

    let reopened = open_store(&root, &keys).await;
    assert_eq!(
        reopened
            .load_remote_counter_guard_manifest()
            .await
            .expect("load manifest after restart"),
        vec![[0x21; 32], [0x42; 32]]
    );
    assert_eq!(
        reopened
            .load_remote_counter_guard_cleanup_manifest()
            .await
            .expect("load cleanup phases after restart"),
        vec![([0x21; 32], false), ([0x42; 32], true)]
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened manifest Store");
}

#[tokio::test]
async fn offline_phase_tamper_fails_full_open_without_rewriting_artifacts() {
    let root = TestRoot::new("counter-guard-manifest-phase-tamper");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    store
        .register_remote_counter_guard_scope([0x54; 32])
        .await
        .expect("register phase tamper fixture scope");
    store
        .shutdown()
        .await
        .expect("shutdown phase tamper fixture");

    let connection = Connection::open(root.database()).expect("open offline phase tamper writer");
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_counter_guard_manifest SET phase = 'materialized'",
                [],
            )
            .expect("tamper manifest phase without its MAC"),
        1
    );
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint offline phase tamper");
    drop(connection);

    let before = artifact_bytes(&root.database());
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(GenerousCapacity),
        load_or_create_storage_kek(&keys, &root.database())
            .expect("reload phase-tampered manifest StorageKEK"),
    )
    .await
    .expect_err("phase-tampered manifest must fail full open");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), before);
}

#[tokio::test]
async fn offline_manifest_tamper_fails_full_open_without_rewriting_artifacts() {
    let root = TestRoot::new("counter-guard-manifest-tamper");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    store
        .register_remote_counter_guard_scope([0x53; 32])
        .await
        .expect("register tamper fixture scope");
    store.shutdown().await.expect("shutdown tamper fixture");

    let connection = Connection::open(root.database()).expect("open offline tamper writer");
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_counter_guard_manifest SET metadata_token = zeroblob(32)",
                [],
            )
            .expect("tamper manifest metadata token"),
        1
    );
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint offline manifest tamper");
    drop(connection);

    let before = artifact_bytes(&root.database());
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(GenerousCapacity),
        load_or_create_storage_kek(&keys, &root.database())
            .expect("reload tampered manifest StorageKEK"),
    )
    .await
    .expect_err("tampered manifest must fail full open");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), before);
}

#[tokio::test]
async fn exact_duplicate_registration_is_zero_write() {
    let root = TestRoot::new("counter-guard-manifest-idempotent");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let scope_token = [0x64; 32];
    store
        .register_remote_counter_guard_scope(scope_token)
        .await
        .expect("register idempotent fixture scope");
    assert_eq!(
        store
            .load_remote_counter_guard_manifest()
            .await
            .expect("warm manifest read path"),
        vec![scope_token]
    );
    let before = artifact_bytes(&root.database());
    store
        .register_remote_counter_guard_scope(scope_token)
        .await
        .expect("repeat exact manifest registration");
    assert_eq!(artifact_bytes(&root.database()), before);
    assert_eq!(
        store
            .load_remote_counter_guard_manifest()
            .await
            .expect("reload idempotent manifest"),
        vec![scope_token]
    );
    store
        .shutdown()
        .await
        .expect("shutdown idempotent manifest Store");
}

#[tokio::test]
async fn materialized_mark_and_registration_are_idempotent_zero_writes() {
    let root = TestRoot::new("counter-guard-manifest-materialized-idempotent");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let scope_token = [0x65; 32];
    store
        .register_remote_counter_guard_scope(scope_token)
        .await
        .expect("register materialized idempotence fixture");
    store
        .mark_remote_counter_guard_scope_materialized(scope_token)
        .await
        .expect("materialize fixture scope");
    assert_eq!(
        store
            .load_remote_counter_guard_cleanup_manifest()
            .await
            .expect("warm materialized cleanup read path"),
        vec![(scope_token, true)]
    );

    let before = artifact_bytes(&root.database());
    store
        .mark_remote_counter_guard_scope_materialized(scope_token)
        .await
        .expect("repeat exact materialized mark");
    store
        .register_remote_counter_guard_scope(scope_token)
        .await
        .expect("repeat registration must not demote materialized scope");
    assert_eq!(artifact_bytes(&root.database()), before);
    assert_eq!(
        store
            .load_remote_counter_guard_cleanup_manifest()
            .await
            .expect("materialized scope remains monotonic"),
        vec![(scope_token, true)]
    );
    store
        .shutdown()
        .await
        .expect("shutdown materialized idempotence Store");
}

#[tokio::test]
async fn manifest_cap_rejects_the_4097th_scope_without_writing() {
    let root = TestRoot::new("counter-guard-manifest-capacity");
    let keys = MemoryKeyStore::new();
    open_store(&root, &keys)
        .await
        .shutdown()
        .await
        .expect("create empty capacity fixture");
    fill_manifest_to_capacity(&root, &keys);

    let store = open_store(&root, &keys).await;
    assert_eq!(
        store
            .load_remote_counter_guard_manifest()
            .await
            .expect("load full manifest")
            .len(),
        usize::try_from(MAX_REMOTE_COUNTER_GUARD_SCOPES).expect("manifest cap fits usize")
    );
    let before = artifact_bytes(&root.database());
    let error = store
        .register_remote_counter_guard_scope([0xff; 32])
        .await
        .expect_err("4097th scope must be rejected");
    assert!(matches!(
        error,
        RuntimeStoreError::StoreFull {
            projected_footprint_bytes: 4_097,
            hard_limit_bytes: 4_096,
        }
    ));
    assert_eq!(artifact_bytes(&root.database()), before);
    store
        .shutdown()
        .await
        .expect("shutdown full manifest Store");
}
