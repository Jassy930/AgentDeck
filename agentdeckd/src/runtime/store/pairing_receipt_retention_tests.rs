//! P4.3 pairing receipt 30 天 retention purge focused tests。

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::relay_v2::PairRouteId;
use agentdeck_protocol::relay_v2::frame::{
    OpaqueRouteFrame, PairRouteCloseOutcome, PairRouteClosed, RelayFrameBody,
};
use rusqlite::Connection;

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::pairing_receipt_retention::{MAX_PAIRING_RECEIPT_PURGE_BATCH, next_ledger_for_test};
use super::pairing_terminal::{PairingTerminalAction, RECEIPT_RETENTION_MS};
use super::pairing_tests::{
    GenerousCapacity, NOW_MS, OneShotFault, TestClock, TestRoot, artifact_bytes, make_active,
    prepare_unused_pairing,
};
use super::sqlite::RuntimeLedger;

fn config(root: &TestRoot, clock: Arc<AtomicU64>) -> RuntimeStoreConfig {
    RuntimeStoreConfig::new(root.database())
        .with_clock(TestClock(clock))
        .with_capacity_probe(GenerousCapacity)
}

async fn open_store(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    clock: Arc<AtomicU64>,
) -> RuntimeStoreHandle {
    RuntimeStoreHandle::open(
        config(root, clock),
        load_or_create_storage_kek(keys, &root.database()).expect("load test StorageKEK"),
    )
    .await
    .expect("open receipt retention store")
}

fn closed_terminal(pair_route: PairRouteId) -> Vec<u8> {
    agentdeck_protocol::relay_v2::encode(&OpaqueRouteFrame {
        version: agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route,
            outcome: PairRouteCloseOutcome::Closed,
        }),
    })
}

async fn terminal_receipt(
    store: &RuntimeStoreHandle,
    binding: &crate::runtime::model::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    seed: u8,
    close: bool,
) -> (super::RuntimeId, PairRouteId) {
    let pair_route = PairRouteId::from_bytes([seed; 16]);
    let (pairing_id, _) = prepare_unused_pairing(
        store,
        binding,
        data_cert,
        pair_route,
        seed.wrapping_add(1),
        seed.wrapping_add(2),
        &format!("retention-{seed}"),
    )
    .await;
    store
        .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
        .await
        .expect("terminalize retention fixture");
    if close {
        store
            .acknowledge_pair_route_close(pairing_id, closed_terminal(pair_route))
            .await
            .expect("close retention fixture");
    }
    (pairing_id, pair_route)
}

fn receipt_ledger(database: &Path) -> (u64, u64, u64, u64) {
    let connection = Connection::open(database).expect("open receipt ledger database");
    let physical = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(receipt_bytes), 0) FROM remote_pairing_receipts",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        )
        .expect("read physical receipt totals");
    let ledger = connection
        .query_row(
            "SELECT remote_pairing_receipt_count, remote_pairing_receipt_bytes
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        )
        .expect("read authenticated ledger projection");
    (physical.0, physical.1, ledger.0, ledger.1)
}

#[tokio::test]
async fn strict_cutoff_keeps_live_recovery_and_purges_only_closed_tombstones() {
    let root = TestRoot::new("receipt-retention-cutoff");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&store).await;
    let _closed = terminal_receipt(&store, &binding, &data_cert, 0x71, true).await;
    let (live_pairing, live_route) =
        terminal_receipt(&store, &binding, &data_cert, 0x72, false).await;
    assert_eq!(receipt_ledger(&root.database()).0, 2);

    clock.store(NOW_MS + RECEIPT_RETENTION_MS, Ordering::SeqCst);
    assert!(
        store
            .plan_expired_pairing_receipt_purge()
            .await
            .expect("plan at exact retention cutoff")
            .is_none()
    );
    assert_eq!(receipt_ledger(&root.database()).0, 2);

    clock.store(NOW_MS + RECEIPT_RETENTION_MS + 1, Ordering::SeqCst);
    let first_plan = store
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan first eligible closed tombstone")
        .expect("one closed tombstone is eligible");
    let first = store
        .apply_pairing_receipt_purge(first_plan)
        .await
        .expect("purge first eligible closed tombstone");
    assert_eq!(first.purged_count(), 1);
    assert!(first.purged_bytes() > 0);
    assert!(!first.has_more());
    assert_eq!(receipt_ledger(&root.database()).0, 1);
    assert!(
        store
            .load_pairing_invite(live_pairing)
            .await
            .expect("load live terminal pairing")
            .is_some()
    );

    store
        .acknowledge_pair_route_close(live_pairing, closed_terminal(live_route))
        .await
        .expect("finish protected Close recovery");
    let second_plan = store
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan newly safe tombstone")
        .expect("closed terminal receipt becomes eligible");
    let second = store
        .apply_pairing_receipt_purge(second_plan.clone())
        .await
        .expect("purge newly safe tombstone");
    assert_eq!(second.purged_count(), 1);
    assert_eq!(receipt_ledger(&root.database()), (0, 0, 0, 0));
    let retry = store
        .apply_pairing_receipt_purge(second_plan)
        .await
        .expect("exact maintenance retry");
    assert_eq!(retry.purged_count(), 0);
    assert_eq!(retry.purged_bytes(), 0);
    assert!(!retry.has_more());
    assert!(retry.replayed());
    store.shutdown().await.expect("shutdown cutoff store");
}

#[tokio::test]
async fn purge_batch_has_a_fixed_upper_bound_and_reports_remaining_work() {
    let root = TestRoot::new("receipt-retention-batch");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&store).await;
    for index in 0..=MAX_PAIRING_RECEIPT_PURGE_BATCH {
        let seed = u8::try_from(index + 1).expect("test batch fits u8");
        terminal_receipt(&store, &binding, &data_cert, seed, true).await;
    }
    let total = MAX_PAIRING_RECEIPT_PURGE_BATCH + 1;
    assert_eq!(receipt_ledger(&root.database()).0, total);
    clock.store(NOW_MS + RECEIPT_RETENTION_MS + 1, Ordering::SeqCst);

    let first_plan = store
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan bounded first page")
        .expect("first page exists");
    assert_eq!(
        first_plan.candidate_count(),
        MAX_PAIRING_RECEIPT_PURGE_BATCH
    );
    let first = store
        .apply_pairing_receipt_purge(first_plan)
        .await
        .expect("purge bounded first page");
    assert_eq!(first.purged_count(), MAX_PAIRING_RECEIPT_PURGE_BATCH);
    assert!(first.has_more());
    assert_eq!(receipt_ledger(&root.database()).0, 1);
    let second_plan = store
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan final page")
        .expect("one receipt remains");
    let second = store
        .apply_pairing_receipt_purge(second_plan)
        .await
        .expect("purge final page");
    assert_eq!(second.purged_count(), 1);
    assert!(!second.has_more());
    assert_eq!(receipt_ledger(&root.database()), (0, 0, 0, 0));
    store.shutdown().await.expect("shutdown batch store");
}

#[tokio::test]
async fn stale_mixed_page_cas_rejects_without_deleting_a_new_candidate() {
    let root = TestRoot::new("receipt-retention-mixed-cas");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&store).await;
    terminal_receipt(&store, &binding, &data_cert, 0x75, true).await;
    terminal_receipt(&store, &binding, &data_cert, 0x76, true).await;
    clock.store(NOW_MS + RECEIPT_RETENTION_MS + 1, Ordering::SeqCst);

    let stale_page = store
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan two-receipt page")
        .expect("two receipts are eligible");
    assert_eq!(stale_page.candidate_count(), 2);
    let mut first_only = stale_page.clone();
    first_only.truncate_for_test(1);
    assert_eq!(
        store
            .apply_pairing_receipt_purge(first_only)
            .await
            .expect("purge first frozen candidate")
            .purged_count(),
        1
    );
    let before_conflict = receipt_ledger(&root.database());
    assert_eq!(before_conflict.0, 1);
    assert!(matches!(
        store.apply_pairing_receipt_purge(stale_page).await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(receipt_ledger(&root.database()), before_conflict);

    let final_page = store
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan surviving candidate")
        .expect("one candidate survives mixed CAS");
    assert_eq!(
        store
            .apply_pairing_receipt_purge(final_page)
            .await
            .expect("purge surviving candidate")
            .purged_count(),
        1
    );
    assert_eq!(receipt_ledger(&root.database()), (0, 0, 0, 0));
    store.shutdown().await.expect("shutdown mixed CAS store");
}

#[tokio::test]
async fn purge_fault_boundaries_converge_by_exact_retry_and_restart() {
    for (label, operation, committed) in [
        (
            "receipt-purge-before",
            RuntimeStoreOperation::PurgePairingReceiptsBeforeCommit,
            false,
        ),
        (
            "receipt-purge-after",
            RuntimeStoreOperation::PurgePairingReceiptsAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let setup = open_store(&root, &keys, clock.clone()).await;
        let (binding, data_cert) = make_active(&setup).await;
        terminal_receipt(
            &setup,
            &binding,
            &data_cert,
            if committed { 0x81 } else { 0x82 },
            true,
        )
        .await;
        setup.shutdown().await.expect("shutdown purge fault setup");
        clock.store(NOW_MS + RECEIPT_RETENTION_MS + 1, Ordering::SeqCst);

        let faulted = RuntimeStoreHandle::open(
            config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database())
                .expect("reload fault test StorageKEK"),
        )
        .await
        .expect("open faulted purge store");
        let plan = faulted
            .plan_expired_pairing_receipt_purge()
            .await
            .expect("plan faulted purge")
            .expect("fault fixture is eligible");
        let error = faulted
            .apply_pairing_receipt_purge(plan.clone())
            .await
            .expect_err("purge fault must surface");
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::PurgePairingReceipts
                }
            ),
            committed
        );
        assert_eq!(receipt_ledger(&root.database()).0, u64::from(!committed));
        let retry = faulted
            .apply_pairing_receipt_purge(plan.clone())
            .await
            .expect("retry purge after injected fault");
        assert_eq!(retry.purged_count(), u64::from(!committed));
        assert_eq!(receipt_ledger(&root.database()), (0, 0, 0, 0));
        faulted
            .shutdown()
            .await
            .expect("shutdown faulted purge store");

        let reopened = open_store(&root, &keys, clock.clone()).await;
        let restart = reopened
            .apply_pairing_receipt_purge(plan)
            .await
            .expect("restart exact frozen-page retry");
        assert_eq!(restart.purged_count(), 0);
        assert!(restart.replayed());
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened purge store");
    }
}

#[tokio::test]
async fn after_commit_unknown_replays_frozen_page_without_consuming_the_next_page() {
    let root = TestRoot::new("receipt-purge-multipage-unknown");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let setup = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&setup).await;
    for index in 0..=MAX_PAIRING_RECEIPT_PURGE_BATCH {
        let seed = u8::try_from(index + 0x31).expect("multipage seed fits u8");
        terminal_receipt(&setup, &binding, &data_cert, seed, true).await;
    }
    setup
        .shutdown()
        .await
        .expect("shutdown multipage fault setup");
    clock.store(NOW_MS + RECEIPT_RETENTION_MS + 1, Ordering::SeqCst);

    let faulted = RuntimeStoreHandle::open(
        config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
            operation: RuntimeStoreOperation::PurgePairingReceiptsAfterCommit,
            fired: AtomicBool::new(false),
        })),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload multipage StorageKEK"),
    )
    .await
    .expect("open multipage fault store");
    let frozen = faulted
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan multipage purge")
        .expect("multipage purge has work");
    assert_eq!(frozen.candidate_count(), MAX_PAIRING_RECEIPT_PURGE_BATCH);
    assert!(matches!(
        faulted.apply_pairing_receipt_purge(frozen.clone()).await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PurgePairingReceipts
        })
    ));
    assert_eq!(receipt_ledger(&root.database()).0, 1);
    let retry = faulted
        .apply_pairing_receipt_purge(frozen.clone())
        .await
        .expect("exact retry frozen first page");
    assert!(retry.replayed());
    assert_eq!(retry.purged_count(), 0);
    assert!(retry.has_more());
    assert_eq!(receipt_ledger(&root.database()).0, 1);
    faulted
        .shutdown()
        .await
        .expect("shutdown multipage fault store");

    let reopened = open_store(&root, &keys, clock.clone()).await;
    let restart_retry = reopened
        .apply_pairing_receipt_purge(frozen)
        .await
        .expect("restart exact retry frozen first page");
    assert!(restart_retry.replayed());
    assert_eq!(receipt_ledger(&root.database()).0, 1);
    let final_plan = reopened
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan independent final page")
        .expect("final page remains after exact replay");
    assert_eq!(final_plan.candidate_count(), 1);
    let final_outcome = reopened
        .apply_pairing_receipt_purge(final_plan)
        .await
        .expect("purge independent final page");
    assert_eq!(final_outcome.purged_count(), 1);
    assert!(!final_outcome.replayed());
    assert_eq!(receipt_ledger(&root.database()), (0, 0, 0, 0));
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened multipage store");
}

#[tokio::test]
async fn offline_retention_tamper_fails_open_without_rewriting_artifacts() {
    let root = TestRoot::new("receipt-retention-tamper");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&store).await;
    terminal_receipt(&store, &binding, &data_cert, 0x91, true).await;
    store.shutdown().await.expect("shutdown tamper setup");

    let connection = Connection::open(root.database()).expect("open offline tamper database");
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_pairing_receipts
                 SET retain_until_ms = retain_until_ms + 1",
                [],
            )
            .expect("tamper retain cutoff"),
        1
    );
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint retention tamper");
    drop(connection);
    let before = artifact_bytes(&root.database());
    let error = RuntimeStoreHandle::open(
        config(&root, clock),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload tamper StorageKEK"),
    )
    .await
    .expect_err("tampered retention metadata must fail full open");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), before);
}

#[test]
fn purge_ledger_decrement_releases_count_and_byte_capacity() {
    let ledger = RuntimeLedger {
        remote_pairing_receipt_count: 65_536,
        remote_pairing_receipt_bytes: 64 * 1024 * 1024,
        ..RuntimeLedger::default()
    };
    let next = next_ledger_for_test(&ledger, 1, 65_536).expect("release receipt capacity");
    assert_eq!(next.remote_pairing_receipt_count, 65_535);
    assert_eq!(next.remote_pairing_receipt_bytes, 64 * 1024 * 1024 - 65_536);
}
