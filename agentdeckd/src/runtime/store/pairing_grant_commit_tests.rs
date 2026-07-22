//! Focused tests for the P4.3 G2 GrantCommitted Store slice.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, GrantCommitted, OpaqueRouteFrame, RelayFrameBody, RouteAccepted,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, PairRouteId, RELAY_PROTOCOL_VERSION, encode,
};

use crate::runtime::model::{
    MachineIdentityBinding, RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::pairing::PairingInviteLifecycle;
use super::pairing_grant::PairingGrantPreparation;
use super::pairing_grant_commit::{AcknowledgeGrantCommitted, AcknowledgeGrantCommittedOutcome};
use super::pairing_grant_tests::{
    awaiting_pairing, awaiting_pairing_with, complete_active_zero_cut_transition, grant_input,
    grant_input_with, secret,
};
use super::pairing_grant_tx::ConfirmPairingGrantOutcome;
use super::pairing_tests::{
    GenerousCapacity, NOW_MS, OneShotFault, TestClock, TestRoot, artifact_bytes, make_active,
};

#[derive(Clone, Copy)]
struct AckAxes {
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    grant_hash: [u8; 32],
}

fn grant_committed_frame(axes: AckAxes) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: axes.device_route,
            grant_serial: axes.grant_serial,
            grant_hash: axes.grant_hash,
        }),
    })
}

async fn prepare_grant(
    store: &RuntimeStoreHandle,
) -> (
    MachineIdentityBinding,
    agentdeck_protocol::relay_v2::SignedCertificate,
    PairingGrantPreparation,
    AckAxes,
    Vec<u8>,
) {
    let (binding, data_cert) = make_active(store).await;
    let preparation = awaiting_pairing(store, &binding, &data_cert).await;
    let confirmed = store
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect("confirm grant before GrantCommitted ACK");
    let recovery = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("fresh grant must confirm: {other:?}"),
    };
    let axes = AckAxes {
        device_route: recovery.device_route(),
        grant_serial: recovery.grant_serial(),
        grant_hash: recovery.grant_hash(),
    };
    let response = recovery.canonical_response().to_vec();
    (binding, data_cert, preparation, axes, response)
}

fn grant_ledger(database: &std::path::Path) -> (u64, u64, u64, u64, u64, u64) {
    let connection = rusqlite::Connection::open(database).expect("open ledger evidence DB");
    connection
        .query_row(
            "SELECT remote_authorization_count,
                    remote_authorization_preparing_count,
                    remote_authorization_active_count,
                    remote_control_outbox_count,
                    remote_control_outbox_pending_count,
                    remote_control_outbox_sealed_bytes
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("read grant ledger")
}

#[tokio::test]
async fn grant_committed_ack_is_atomic_replay_safe_and_recovers_exact_response() {
    let root = TestRoot::new("grant-committed-happy");
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
    .expect("open GrantCommitted store");
    let (_, _, preparation, axes, expected_response) = prepare_grant(&store).await;
    let preparing_ledger = grant_ledger(&root.database());
    assert_eq!(preparing_ledger.0, 1);
    assert_eq!(preparing_ledger.1, 1);
    assert_eq!(preparing_ledger.2, 0);
    assert_eq!(preparing_ledger.3, 1);
    assert_eq!(preparing_ledger.4, 1);
    assert!(preparing_ledger.5 > 0);

    clock.store(NOW_MS + 1, Ordering::SeqCst);
    let committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(axes),
        ))
        .await
        .expect("acknowledge GrantCommitted");
    let recovery = match committed {
        AcknowledgeGrantCommittedOutcome::Committed { recovery } => recovery,
        other => panic!("fresh ACK must commit: {other:?}"),
    };
    assert_eq!(recovery.pairing_id(), preparation.pairing_id());
    assert_eq!(recovery.request_hash(), preparation.request_hash());
    assert_eq!(recovery.device_route(), axes.device_route);
    assert_eq!(recovery.grant_serial(), axes.grant_serial);
    assert_eq!(recovery.grant_hash(), axes.grant_hash);
    assert_eq!(recovery.canonical_pair_response(), expected_response);
    assert_eq!(
        recovery.pair_response().canonical_sha256().ok(),
        Some(recovery.response_hash())
    );
    assert_eq!(recovery.relay_grant().canonical_sha256(), axes.grant_hash);
    assert_eq!(
        recovery.invite_hpke_private_key().public_key().to_bytes(),
        recovery.invite().invite_hpke_pubkey.0
    );
    assert_eq!(grant_ledger(&root.database()), (1, 0, 1, 0, 0, 0));
    assert_eq!(
        store
            .load_pairing_invite(preparation.pairing_id())
            .await
            .expect("load committed pairing")
            .expect("pairing remains")
            .lifecycle(),
        PairingInviteLifecycle::GrantCommitted
    );
    assert!(
        store
            .list_grant_preparing_recovery()
            .await
            .expect("preparing recovery after ACK")
            .is_empty()
    );

    let before_replay = artifact_bytes(&root.database());
    let replayed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(axes),
        ))
        .await
        .expect("replay exact GrantCommitted");
    let replayed = match replayed {
        AcknowledgeGrantCommittedOutcome::Replayed { recovery } => recovery,
        other => panic!("exact duplicate must replay: {other:?}"),
    };
    assert_eq!(replayed.canonical_pair_response(), expected_response);
    assert_eq!(artifact_bytes(&root.database()), before_replay);
    let mut wrong_committed_hash = axes.grant_hash;
    wrong_committed_hash[31] ^= 0x01;
    let before_conflict = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                preparation.pairing_id(),
                grant_committed_frame(AckAxes {
                    grant_hash: wrong_committed_hash,
                    ..axes
                }),
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_conflict);
    assert_eq!(
        store
            .list_grant_committed_recovery()
            .await
            .expect("list committed recovery")
            .len(),
        1
    );
    store.shutdown().await.expect("shutdown committed store");

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen committed store");
    let recovered = reopened
        .list_grant_committed_recovery()
        .await
        .expect("recover committed response after restart");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].canonical_pair_response(), expected_response);
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn grant_committed_rejects_wrong_axes_route_accepted_and_wrong_state_without_writing() {
    let root = TestRoot::new("grant-committed-wrong-axes");
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
    .expect("open wrong-axis store");
    let (_, _, preparation, axes, _) = prepare_grant(&store).await;

    let mut wrong_hash = axes.grant_hash;
    wrong_hash[0] ^= 0xff;
    let invalid = [
        grant_committed_frame(AckAxes {
            device_route: DeviceRouteId::from_bytes([0xee; 16]),
            ..axes
        }),
        grant_committed_frame(AckAxes {
            grant_serial: GrantSerial::new(axes.grant_serial.value() + 1),
            ..axes
        }),
        grant_committed_frame(AckAxes {
            grant_hash: wrong_hash,
            ..axes
        }),
        encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::PairFrame {
                    pair_route: preparation.invite().pair_route,
                },
            }),
        }),
    ];
    for canonical in invalid {
        let before = artifact_bytes(&root.database());
        assert!(matches!(
            store
                .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                    preparation.pairing_id(),
                    canonical,
                ))
                .await,
            Err(RuntimeStoreError::PairingConflict)
        ));
        assert_eq!(artifact_bytes(&root.database()), before);
    }
    let preparing_ledger = grant_ledger(&root.database());
    assert_eq!(preparing_ledger.0, 1);
    assert_eq!(preparing_ledger.1, 1);
    assert_eq!(preparing_ledger.2, 0);
    assert_eq!(preparing_ledger.3, 1);
    assert_eq!(preparing_ledger.4, 1);
    assert!(preparing_ledger.5 > 0);
    store.shutdown().await.expect("shutdown wrong-axis store");

    let wrong_state_root = TestRoot::new("grant-committed-wrong-state");
    let wrong_state_keys = MemoryKeyStore::new();
    let wrong_state_clock = Arc::new(AtomicU64::new(NOW_MS));
    let wrong_state_config = || {
        RuntimeStoreConfig::new(wrong_state_root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(wrong_state_clock.clone()))
    };
    let wrong_state_store = RuntimeStoreHandle::open(
        wrong_state_config(),
        load_or_create_storage_kek(&wrong_state_keys, &wrong_state_root.database())
            .expect("load wrong-state StorageKEK"),
    )
    .await
    .expect("open wrong-state store");
    let (binding, cert) = make_active(&wrong_state_store).await;
    let awaiting = awaiting_pairing(&wrong_state_store, &binding, &cert).await;
    let before = artifact_bytes(&wrong_state_root.database());
    assert!(matches!(
        wrong_state_store
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                awaiting.pairing_id(),
                grant_committed_frame(AckAxes {
                    device_route: DeviceRouteId::from_bytes([0xd1; 16]),
                    grant_serial: GrantSerial::new(1),
                    grant_hash: [0xaa; 32],
                }),
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&wrong_state_root.database()), before);
    wrong_state_store
        .shutdown()
        .await
        .expect("shutdown wrong-state store");
}

#[tokio::test]
async fn grant_committed_fault_boundaries_converge_by_restart_and_exact_retry() {
    for (label, operation, committed) in [
        (
            "grant-committed-before",
            RuntimeStoreOperation::AcknowledgeGrantCommittedBeforeCommit,
            false,
        ),
        (
            "grant-committed-after",
            RuntimeStoreOperation::AcknowledgeGrantCommittedAfterCommit,
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
        .expect("open fault setup");
        let (_, _, preparation, axes, expected_response) = prepare_grant(&setup).await;
        setup.shutdown().await.expect("shutdown fault setup");

        let faulted = RuntimeStoreHandle::open(
            config().with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted ACK store");
        let error = faulted
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                preparation.pairing_id(),
                grant_committed_frame(axes),
            ))
            .await
            .expect_err("ACK fault must surface");
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::AcknowledgeGrantCommitted,
                }
            ),
            committed
        );
        assert_eq!(
            faulted
                .list_grant_committed_recovery()
                .await
                .expect("read committed recovery after fault")
                .len(),
            usize::from(committed)
        );
        assert_eq!(
            faulted
                .list_grant_preparing_recovery()
                .await
                .expect("read preparing recovery after fault")
                .len(),
            usize::from(!committed)
        );
        faulted.shutdown().await.expect("shutdown faulted store");

        let reopened = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("reopen after ACK fault");
        let retry = reopened
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                preparation.pairing_id(),
                grant_committed_frame(axes),
            ))
            .await
            .expect("exact ACK retry after restart");
        let recovery = match (committed, retry) {
            (true, AcknowledgeGrantCommittedOutcome::Replayed { recovery })
            | (false, AcknowledgeGrantCommittedOutcome::Committed { recovery }) => recovery,
            (_, other) => panic!("unexpected retry outcome: {other:?}"),
        };
        assert_eq!(recovery.canonical_pair_response(), expected_response);
        assert_eq!(grant_ledger(&root.database()), (1, 0, 1, 0, 0, 0));
        reopened.shutdown().await.expect("shutdown recovered store");
    }
}

#[tokio::test]
async fn full_open_audit_accepts_mixed_committed_and_preparing_grants() {
    let root = TestRoot::new("grant-committed-mixed-audit");
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
    .expect("open mixed-audit store");
    let (binding, data_cert, first_preparation, first_axes, _) = prepare_grant(&store).await;
    store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            first_preparation.pairing_id(),
            grant_committed_frame(first_axes),
        ))
        .await
        .expect("commit first grant");
    complete_active_zero_cut_transition(&store).await;

    let second_preparation = awaiting_pairing_with(
        &store,
        &binding,
        &data_cert,
        PairRouteId::from_bytes([0xb1; 16]),
        0xb2,
        0xb3,
        0xb4,
        0xb5,
        0xb6,
        0xb7,
        "grant-committed-mixed-second",
    )
    .await;
    let second_route = DeviceRouteId::from_bytes([0xd2; 16]);
    let next_global = store
        .load_global_key_state()
        .await
        .expect("load committed singleton")
        .expect("singleton exists")
        .next_for_device(second_route, secret(0xe1), secret(0xe2), secret(0xe3))
        .expect("append second device");
    assert!(matches!(
        store
            .confirm_pairing_grant(grant_input_with(
                &second_preparation,
                &binding,
                &data_cert,
                second_route,
                GrantSerial::new(1),
                next_global,
                None,
                0xe4,
            ))
            .await
            .expect("confirm second grant"),
        ConfirmPairingGrantOutcome::Confirmed { .. }
    ));
    let mixed_ledger = grant_ledger(&root.database());
    assert_eq!(mixed_ledger.0, 2);
    assert_eq!(mixed_ledger.1, 1);
    assert_eq!(mixed_ledger.2, 1);
    assert_eq!(mixed_ledger.3, 1);
    assert_eq!(mixed_ledger.4, 1);
    assert!(mixed_ledger.5 > 0);
    store.shutdown().await.expect("shutdown mixed-audit store");

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("full-open audit mixed grant states");
    assert_eq!(
        reopened
            .list_grant_committed_recovery()
            .await
            .expect("list committed side")
            .len(),
        1
    );
    assert_eq!(
        reopened
            .list_grant_preparing_recovery()
            .await
            .expect("list preparing side")
            .len(),
        1
    );
    reopened.shutdown().await.expect("shutdown mixed reopen");
}

#[tokio::test]
async fn offline_grant_committed_tamper_fails_full_open_without_rewriting_artifacts() {
    for (label, sql) in [
        (
            "grant-committed-pairing-token",
            "UPDATE remote_pairings SET metadata_token = zeroblob(length(metadata_token)) \
             WHERE lifecycle = 'grantCommitted'",
        ),
        (
            "grant-committed-auth-token",
            "UPDATE remote_authorization_ledger \
             SET metadata_token = zeroblob(length(metadata_token)) WHERE lifecycle = 'active'",
        ),
        (
            "grant-committed-auth-lifecycle",
            "UPDATE remote_authorization_ledger SET lifecycle = 'grantPreparing' \
             WHERE lifecycle = 'active'",
        ),
        (
            "grant-committed-sealed-state",
            "UPDATE remote_pairings SET sealed_state = zeroblob(length(sealed_state)) \
             WHERE lifecycle = 'grantCommitted'",
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
        let store = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open tamper setup");
        let (_, _, preparation, axes, _) = prepare_grant(&store).await;
        store
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                preparation.pairing_id(),
                grant_committed_frame(axes),
            ))
            .await
            .expect("commit before offline tamper");
        store.shutdown().await.expect("shutdown before tamper");

        let connection = rusqlite::Connection::open(root.database()).expect("open offline DB");
        assert_eq!(
            connection.execute(sql, []).expect("tamper committed row"),
            1
        );
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint committed tamper");
        drop(connection);
        let before = artifact_bytes(&root.database());
        let error = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect_err("committed tamper must fail full open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(artifact_bytes(&root.database()), before);
    }
}
