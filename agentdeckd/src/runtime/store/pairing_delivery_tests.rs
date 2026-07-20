//! P4.3 G3 PairResponseReceived Store 子片 focused tests。

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_crypto::{SigningKey, sign_pair_response_received, sign_tbs};
use agentdeck_protocol::e2ee::PairResponseReceivedV1;
use agentdeck_protocol::relay_v2::frame::{
    GrantCommitted, OpaqueRouteFrame, PairRouteCloseOutcome, PairRouteClosed, RelayFrameBody,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, Ed25519Signature, RELAY_PROTOCOL_VERSION, encode,
};
use agentdeck_protocol::runtime::{PairingReceipt, PairingState};

use crate::remote::access::{PairResponseAccessBinding, VerifiedPairResponseReceipt};
use crate::runtime::model::{
    MachineEnrollmentState, RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::pairing::PairingInviteLifecycle;
use super::pairing_delivery::{
    AcknowledgePairResponseReceived, AcknowledgePairResponseReceivedOutcome,
};
use super::pairing_grant::PairingGrantPreparation;
use super::pairing_grant_commit::{AcknowledgeGrantCommitted, GrantCommittedRecovery};
use super::pairing_grant_tests::{awaiting_pairing, grant_input};
use super::pairing_grant_tx::ConfirmPairingGrantOutcome;
use super::pairing_revocation::{BeginDeviceRevocation, BeginDeviceRevocationOutcome};
use super::pairing_terminal::RECEIPT_RETENTION_MS;
use super::pairing_tests::{
    GenerousCapacity, NOW_MS, OneShotFault, TestClock, TestRoot, artifact_bytes, make_active,
};

const DEVICE_SIGN_SEED: [u8; 32] = [0xa4; 32];
const ROOT_SIGN_SEED: [u8; 32] = [0x41; 32];

fn grant_committed_frame(recovery: &super::pairing_grant_tx::GrantPreparingRecovery) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: recovery.device_route(),
            grant_serial: recovery.grant_serial(),
            grant_hash: recovery.grant_hash(),
        }),
    })
}

fn close_terminal(
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
    outcome: PairRouteCloseOutcome,
) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route,
            outcome,
        }),
    })
}

async fn prepare_committed(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
) -> (PairingGrantPreparation, GrantCommittedRecovery) {
    let (binding, data_cert) = make_active(store).await;
    let preparation = awaiting_pairing(store, &binding, &data_cert).await;
    let confirmed = store
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect("confirm grant before delivery");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("fresh confirm must freeze grant: {other:?}"),
    };
    clock.store(NOW_MS + 1, Ordering::SeqCst);
    let committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&installing),
        ))
        .await
        .expect("commit grant before delivery");
    let recovery = match committed {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("fresh GrantCommitted ACK must transition: {other:?}"),
    };
    (preparation, recovery)
}

fn verified_receipt(recovery: &GrantCommittedRecovery) -> VerifiedPairResponseReceipt {
    let binding = PairResponseAccessBinding::from_frozen(
        recovery.invite(),
        recovery.request_hash(),
        recovery.relay_grant(),
        recovery.pair_response(),
    )
    .expect("rebuild authenticated response binding");
    let receipt = sign_pair_response_received(
        &SigningKey::from_seed(&DEVICE_SIGN_SEED),
        binding.info(),
        binding.receipt_context(),
        PairResponseReceivedV1 {
            request_hash: recovery.request_hash(),
            grant_hash: recovery.grant_hash(),
            response_hash: recovery.response_hash(),
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign endpoint receipt");
    binding
        .verify_signed_receipt(
            &receipt
                .canonical_bytes()
                .expect("canonical endpoint receipt"),
        )
        .expect("verify endpoint receipt")
}

fn delivery_counts(database: &std::path::Path) -> (u64, u64, u64, u64) {
    rusqlite::Connection::open(database)
        .expect("open delivery evidence DB")
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM remote_pairings WHERE lifecycle = 'delivered'),
                 (SELECT COUNT(*) FROM remote_pairing_receipts WHERE action = 'confirmed'),
                 (SELECT COUNT(*) FROM remote_control_outbox
                    WHERE operation_kind = 'closePairRoute'),
                 remote_control_outbox_count
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read delivery evidence")
}

async fn authorization_only_store_for_test(database: &Path, revoking: bool) -> RuntimeStoreHandle {
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.to_path_buf()).with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, database).expect("create authorization test StorageKEK"),
    )
    .await
    .expect("open authorization-only test Store");
    let (preparation, committed) = prepare_committed(&store, &clock).await;
    let proof = verified_receipt(&committed);
    clock.store(NOW_MS + 2, Ordering::SeqCst);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver authorization-only test grant")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh test grant must deliver: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("scrub authorization-only pairing row");
    assert!(
        store
            .list_pairing_recovery()
            .await
            .expect("read scrubbed pairing recovery")
            .is_empty()
    );

    if revoking {
        let Some(MachineEnrollmentState::Active(active)) = store
            .load_machine_enrollment_state()
            .await
            .expect("load authorization-only active enrollment")
        else {
            panic!("authorization-only test Store must remain Active")
        };
        let grant = committed.relay_grant();
        let mut revocation = DeviceRevocation {
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        revocation.signature = sign_tbs(
            &SigningKey::from_seed(&ROOT_SIGN_SEED),
            &revocation.to_be_signed_v1(
                committed.invite().relay_server_id,
                active.binding.root_fingerprint,
            ),
        )
        .into();
        clock.store(NOW_MS + 3, Ordering::SeqCst);
        assert!(matches!(
            store
                .begin_device_revocation(BeginDeviceRevocation::local(revocation))
                .await
                .expect("begin authorization-only test revocation"),
            BeginDeviceRevocationOutcome::Prepared { .. }
        ));
    }
    store
}

pub(crate) async fn active_authorization_store_for_test(database: &Path) -> RuntimeStoreHandle {
    authorization_only_store_for_test(database, false).await
}

pub(crate) async fn revoking_authorization_store_for_test(database: &Path) -> RuntimeStoreHandle {
    authorization_only_store_for_test(database, true).await
}

#[tokio::test]
async fn valid_receipt_atomically_delivers_replays_and_scrubs_only_after_close_ack() {
    let root = TestRoot::new("pairing-delivery-happy");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open delivery store");
    let (preparation, committed) = prepare_committed(&store, &clock).await;
    let proof = verified_receipt(&committed);
    let before_committed_projection = artifact_bytes(&root.database());
    let committed_winner = store
        .load_pairing_winner(preparation.pairing_id())
        .await
        .expect("load authenticated GrantCommitted winner")
        .expect("confirmed receipt must exist");
    assert!(matches!(
        committed_winner.receipt(),
        PairingReceipt::Confirmed { .. }
    ));
    assert_eq!(committed_winner.state(), PairingState::GrantCommitted);
    assert_eq!(
        artifact_bytes(&root.database()),
        before_committed_projection
    );

    clock.store(NOW_MS + 2, Ordering::SeqCst);
    let delivered = store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("commit endpoint delivery");
    let close = match delivered {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("first valid receipt must deliver: {other:?}"),
    };
    assert_eq!(close.pairing_id(), preparation.pairing_id());
    assert_eq!(close.pair_route(), committed.invite().pair_route);
    assert_eq!(delivery_counts(&root.database()), (1, 1, 1, 1));
    let before_delivered_projection = artifact_bytes(&root.database());
    let delivered_winner = store
        .load_pairing_winner(preparation.pairing_id())
        .await
        .expect("load authenticated Delivered winner")
        .expect("delivered confirmed receipt must exist");
    assert!(matches!(
        delivered_winner.receipt(),
        PairingReceipt::Confirmed { .. }
    ));
    assert_eq!(delivered_winner.state(), PairingState::Delivered);
    assert_eq!(
        artifact_bytes(&root.database()),
        before_delivered_projection
    );
    assert_eq!(
        store
            .load_pairing_invite(preparation.pairing_id())
            .await
            .expect("load delivered pairing")
            .expect("secret row retained before Close ACK")
            .lifecycle(),
        PairingInviteLifecycle::Delivered
    );
    assert!(
        store
            .list_grant_committed_recovery()
            .await
            .expect("committed recovery after delivery")
            .is_empty()
    );

    let before_replay = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("exact delivery replay"),
        AcknowledgePairResponseReceivedOutcome::Replayed { close: _ }
    ));
    assert_eq!(artifact_bytes(&root.database()), before_replay);

    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("acknowledge ClosePairRoute");
    assert_eq!(delivery_counts(&root.database()), (0, 1, 0, 0));
    assert!(
        store
            .load_pairing_invite(preparation.pairing_id())
            .await
            .expect("load scrubbed pairing")
            .is_none()
    );
    store.shutdown().await.expect("shutdown delivery store");

    clock.store(NOW_MS + RECEIPT_RETENTION_MS, Ordering::SeqCst);
    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen scrubbed delivery store");
    let before_tombstone_projection = artifact_bytes(&root.database());
    let tombstone_winner = reopened
        .load_pairing_winner(preparation.pairing_id())
        .await
        .expect("load authenticated retained tombstone winner")
        .expect("30-day confirmed tombstone must remain readable");
    assert!(matches!(
        tombstone_winner.receipt(),
        PairingReceipt::Confirmed { .. }
    ));
    assert_eq!(tombstone_winner.state(), PairingState::ClosedTombstone);
    assert_eq!(
        artifact_bytes(&root.database()),
        before_tombstone_projection
    );
    assert!(matches!(
        reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn receipt_for_unknown_pairing_and_expired_receipt_are_zero_write_conflicts() {
    let root = TestRoot::new("pairing-delivery-conflicts");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock.clone()));
    let store = RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open conflict store");
    let (preparation, committed) = prepare_committed(&store, &clock).await;
    let proof = verified_receipt(&committed);

    let before_unknown = artifact_bytes(&root.database());
    let unknown =
        super::identity::RuntimeId::from_bytes(super::identity::RuntimeIdKind::Pairing, [0xee; 16])
            .expect("nonzero pairing id");
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                unknown, &proof,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_unknown);

    clock.store(committed.invite().expires_at_ms, Ordering::SeqCst);
    let before_expired = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await,
        Err(RuntimeStoreError::PairingExpired)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_expired);
    store.shutdown().await.expect("shutdown conflict store");
}

#[tokio::test]
async fn delivery_commit_fault_boundaries_converge_by_restart_and_exact_retry() {
    for (label, operation, committed) in [
        (
            "pairing-delivery-before-commit",
            RuntimeStoreOperation::AcknowledgePairResponseReceivedBeforeCommit,
            false,
        ),
        (
            "pairing-delivery-after-commit",
            RuntimeStoreOperation::AcknowledgePairResponseReceivedAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let config = || {
            RuntimeStoreConfig::new(root.database())
                .with_capacity_probe(GenerousCapacity)
                .with_clock(TestClock(clock.clone()))
        };
        let setup = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open delivery fault setup");
        let (preparation, recovery) = prepare_committed(&setup, &clock).await;
        let proof = verified_receipt(&recovery);
        clock.store(NOW_MS + 2, Ordering::SeqCst);
        setup.shutdown().await.expect("shutdown delivery setup");

        let faulted = RuntimeStoreHandle::open(
            config().with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted delivery store");
        let error = faulted
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect_err("delivery fault must surface");
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::AcknowledgePairResponseReceived,
                }
            ),
            committed
        );
        assert_eq!(
            faulted
                .list_pairing_terminal_recovery()
                .await
                .expect("read close recovery after delivery fault")
                .len(),
            usize::from(committed)
        );
        assert_eq!(
            faulted
                .list_grant_committed_recovery()
                .await
                .expect("read response recovery after delivery fault")
                .len(),
            usize::from(!committed)
        );
        faulted.shutdown().await.expect("shutdown faulted store");

        let reopened = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("reopen delivery fault store");
        let retry = reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("exact delivery retry after restart");
        assert!(matches!(
            (committed, retry),
            (
                true,
                AcknowledgePairResponseReceivedOutcome::Replayed { .. }
            ) | (
                false,
                AcknowledgePairResponseReceivedOutcome::Delivered { .. }
            )
        ));
        assert_eq!(delivery_counts(&root.database()), (1, 1, 1, 1));
        reopened.shutdown().await.expect("shutdown recovered store");
    }
}

#[tokio::test]
async fn offline_delivered_lifecycle_tamper_fails_full_open_without_rewriting_artifacts() {
    let root = TestRoot::new("pairing-delivery-offline-tamper");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open tamper setup");
    let (preparation, recovery) = prepare_committed(&store, &clock).await;
    let proof = verified_receipt(&recovery);
    clock.store(NOW_MS + 2, Ordering::SeqCst);
    store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver before offline tamper");
    store.shutdown().await.expect("shutdown tamper setup");

    let connection = rusqlite::Connection::open(root.database()).expect("open offline writer");
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_pairings SET lifecycle = 'grantCommitted'
                 WHERE pairing_id = ?1 AND lifecycle = 'delivered'",
                [&preparation.pairing_id().as_bytes()[..]],
            )
            .expect("tamper delivered lifecycle without KEK"),
        1
    );
    drop(connection);
    let tampered = artifact_bytes(&root.database());

    let error = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect_err("offline lifecycle tamper must fail full open");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), tampered);
}
