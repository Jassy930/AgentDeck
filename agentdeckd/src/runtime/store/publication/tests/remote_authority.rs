use agentdeck_protocol::e2ee::{AuthorizationCapabilityV1, AuthorizationPermissionV1};
use agentdeck_protocol::runtime::StreamCursor;
use rusqlite::{Transaction, TransactionBehavior};

use crate::runtime::backfill::BarrierRequest;
use crate::runtime::events::{RegisterStreamBarrier, RuntimeStreamTarget, WatchGeneration};
use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};
use crate::runtime::store::{
    RuntimeStoreHandle, production_aligned_active_authorization_store_for_test,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::super::{
    FreezePublicationRequest, PublicationPayloadKind, PublicationScope, PublicationStreamRecord,
    PublicationStreamState, authenticate_subscription_publication_stream, freeze_publication,
    load_stream, update_stream,
};

fn catalog_barrier(generation: u64) -> RegisterStreamBarrier {
    RegisterStreamBarrier {
        target: RuntimeStreamTarget::Catalog,
        generation: WatchGeneration::new(generation).expect("valid catalog watch generation"),
        request: BarrierRequest::Backfill {
            after: StreamCursor::BeforeFirst,
        },
    }
}

fn authenticate_catalog(
    state: &crate::runtime::store::sqlite::RuntimeSqlite,
) -> Result<Option<PublicationStreamRecord>, RuntimeStoreError> {
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Deferred)?;
    let ledger = crate::runtime::store::sqlite::load_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
    )?;
    authenticate_subscription_publication_stream(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        PublicationScope::Catalog,
    )
}

fn assert_pristine_catalog_authentication(
    state: &crate::runtime::store::sqlite::RuntimeSqlite,
    expected: &PublicationStreamRecord,
) {
    let authenticated = authenticate_catalog(state)
        .expect("pristine remote authority authenticates")
        .expect("active remote authority requires the catalog publication");
    assert_eq!(&authenticated, expected);
}

#[tokio::test]
async fn subscription_publication_remote_authority_tri_state_and_corruption_fail_close() {
    // 单一 production pairing fixture 依次锁定 remote-required 的 missing、Active、
    // NeedsSnapshot、Retired-only 四态；状态变更间均重开真实 Store worker，避免用
    // 测试专用 ledger bypass 冒充 barrier capture。
    let root = tempfile::tempdir().expect("create remote-authority publication root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure remote-authority publication root");
    }
    let database = root.path().join("runtime.db");
    let key_state = root.path().join("key-state.db");
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(database.clone())
        .with_capacity_probe(crate::runtime::store::pairing_tests::GenerousCapacity);
    let store = production_aligned_active_authorization_store_for_test(
        &database,
        load_or_create_storage_kek(&keys, &key_state).expect("create remote-authority StorageKEK"),
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await;

    let missing = match store.register_stream_barrier(catalog_barrier(1)).await {
        Err(error) => error,
        Ok(_) => panic!("active remote authority without a catalog publication must fail closed"),
    };
    assert!(matches!(missing, RuntimeStoreError::PublicationMismatch));

    let stream = store
        .ensure_subscription_publication_stream(PublicationScope::Catalog)
        .await
        .expect("create production catalog publication");
    let active = store
        .register_stream_barrier(catalog_barrier(2))
        .await
        .expect("active remote authority captures an active catalog publication");
    assert_eq!(
        active.relay_committed.publication_stream_id,
        Some(stream.publication_stream_id)
    );
    assert_eq!(active.relay_committed.generation, Some(stream.generation));
    let binding = active
        .relay_committed
        .stream_binding
        .as_ref()
        .expect("remote-required active publication returns a binding permit");
    assert_eq!(binding.generation(), stream.generation);
    assert!(
        store
            .release_stream_watch(active.watch.token())
            .await
            .expect("release active catalog watch")
    );
    drop(active);
    store
        .shutdown()
        .await
        .expect("shutdown active fixture Store");

    let mut state = crate::runtime::store::sqlite::open(
        &config,
        load_or_create_storage_kek(&keys, &key_state).expect("reload remote-authority StorageKEK"),
    )
    .expect("reopen pristine remote-authority state");
    assert_pristine_catalog_authentication(&state, &stream);

    // authenticate_subscription_publication_stream 必须认证完整 authorization、global
    // key directory 与 Runtime ledger；任一轴损坏都不能降级为 local-only None。
    let authorization_token: Vec<u8> = state
        .connection
        .query_row(
            "SELECT metadata_token FROM remote_authorization_ledger
             WHERE lifecycle = 'active'",
            [],
            |row| row.get(0),
        )
        .expect("read active authorization token");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE remote_authorization_ledger
                 SET metadata_token = zeroblob(32) WHERE lifecycle = 'active'",
                [],
            )
            .expect("tamper active authorization token"),
        1
    );
    authenticate_catalog(&state)
        .expect_err("authorization corruption cannot downgrade remote authority");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE remote_authorization_ledger
                 SET metadata_token = ?1 WHERE lifecycle = 'active'",
                [&authorization_token],
            )
            .expect("restore active authorization token"),
        1
    );
    assert_pristine_catalog_authentication(&state, &stream);

    let key_directory_token: Vec<u8> = state
        .connection
        .query_row(
            "SELECT metadata_token FROM remote_key_directory WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read global key directory token");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE remote_key_directory SET metadata_token = zeroblob(32)
                 WHERE singleton = 1",
                [],
            )
            .expect("tamper global key directory token"),
        1
    );
    authenticate_catalog(&state)
        .expect_err("global key corruption cannot produce a binding permit");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE remote_key_directory SET metadata_token = ?1 WHERE singleton = 1",
                [&key_directory_token],
            )
            .expect("restore global key directory token"),
        1
    );
    assert_pristine_catalog_authentication(&state, &stream);

    let active_count: i64 = state
        .connection
        .query_row(
            "SELECT remote_authorization_active_count FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read authenticated active authorization count");
    assert_eq!(active_count, 1);
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE runtime_meta SET remote_authorization_active_count = 0
                 WHERE singleton = 1",
                [],
            )
            .expect("tamper Runtime ledger active count"),
        1
    );
    authenticate_catalog(&state)
        .expect_err("Runtime ledger corruption cannot downgrade remote authority");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE runtime_meta SET remote_authorization_active_count = ?1
                 WHERE singleton = 1",
                [active_count],
            )
            .expect("restore Runtime ledger active count"),
        1
    );
    assert_pristine_catalog_authentication(&state, &stream);

    // sender-counter 的 production terminal boundary 会把 current stream durable 地推进
    // 到 NeedsSnapshot；barrier 必须在返回任何 binding 前给出 typed failure。
    freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0xa1; 16],
            publication_stream_id: stream.publication_stream_id,
            generation: stream.generation,
            counter_scope_token: [0xa2; 32],
            sender_counter: u64::MAX,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: vec![0xa3],
        },
        stream.updated_at_ms.saturating_add(1),
    )
    .expect("freeze terminal sender counter through production publication path");
    let needs_snapshot = load_stream(
        &state.connection,
        &state.key_bundle,
        stream.publication_stream_id,
    )
    .expect("load durable NeedsSnapshot publication");
    assert_eq!(needs_snapshot.state, PublicationStreamState::NeedsSnapshot);
    drop(state);

    let needs_snapshot_store = RuntimeStoreHandle::open(
        config.clone(),
        load_or_create_storage_kek(&keys, &key_state).expect("reload NeedsSnapshot StorageKEK"),
    )
    .await
    .expect("reopen NeedsSnapshot Store");
    let error = match needs_snapshot_store
        .register_stream_barrier(catalog_barrier(3))
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("NeedsSnapshot must fail before returning a binding"),
    };
    assert!(matches!(error, RuntimeStoreError::PublicationNeedsSnapshot));
    needs_snapshot_store
        .shutdown()
        .await
        .expect("shutdown NeedsSnapshot Store");

    let mut state = crate::runtime::store::sqlite::open(
        &config,
        load_or_create_storage_kek(&keys, &key_state).expect("reload retired-only StorageKEK"),
    )
    .expect("reopen state for authenticated retired-only lineage");
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("begin retired-only publication transaction");
    let mut retired = load_stream(
        &transaction,
        &state.key_bundle,
        stream.publication_stream_id,
    )
    .expect("load NeedsSnapshot row before retiring it");
    retired.state = PublicationStreamState::Retired;
    retired.updated_at_ms = retired.updated_at_ms.saturating_add(1);
    update_stream(&transaction, &state.key_bundle, &retired)
        .expect("persist authenticated Retired publication row");
    transaction
        .commit()
        .expect("commit authenticated Retired publication row");
    drop(state);

    let retired_store = RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&keys, &key_state)
            .expect("reload final retired-only StorageKEK"),
    )
    .await
    .expect("reopen retired-only Store");
    let error = match retired_store
        .register_stream_barrier(catalog_barrier(4))
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("active remote authority cannot bind retired-only lineage"),
    };
    assert!(matches!(error, RuntimeStoreError::PublicationMismatch));
    retired_store
        .shutdown()
        .await
        .expect("shutdown retired-only Store");
}
