//! P4.3 G4 durable revocation Store focused tests。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_crypto::{SigningKey, sign_tbs};
use agentdeck_protocol::relay_v2::frame::{OpaqueRouteFrame, RelayFrameBody, RevocationCommitted};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, MachineRouteId,
    RELAY_PROTOCOL_VERSION, RelayGrant, RootKeyId, TrustEpoch, decode, encode,
};
use agentdeck_protocol::runtime::PairingReceipt;
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial as RuntimeGrantSerial};

use crate::runtime::model::{
    MachineIdentityBinding, RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing::PairingInviteLifecycle;
use super::pairing_grant_commit::AcknowledgeGrantCommitted;
use super::pairing_grant_tests::{awaiting_pairing, grant_input};
use super::pairing_grant_tx::{ConfirmPairingGrantOutcome, GrantPreparingRecovery};
use super::pairing_revocation::{
    BeginDeviceRevocation, BeginDeviceRevocationOutcome, RevocationRecoveryPhase,
    RevocationTargetStatus, prepare_begin_for_dispatch,
};
use super::pairing_revocation_ack::{
    AcknowledgeOrphanGrantCommittedOutcome, AcknowledgeRevocationCommitted,
    AcknowledgeRevocationCommittedOutcome, prepare_revocation_committed,
};
use super::pairing_tests::{
    GenerousCapacity, NOW_MS, OneShotFault, RELAY, TestClock, TestRoot, artifact_bytes, make_active,
};

const ROOT_SEED: [u8; 32] = [0x41; 32];
const PAIRING_EXPIRY_MS: u64 = NOW_MS + 300_000;

fn revocation() -> DeviceRevocation {
    DeviceRevocation {
        machine_route: MachineRouteId::from_bytes([0x31; 16]),
        device_route: DeviceRouteId::from_bytes([0x41; 16]),
        grant_serial: GrantSerial::new(1),
        root_key_id: RootKeyId::from_bytes([0x51; 16]),
        trust_epoch: TrustEpoch::new(1),
        signature: Ed25519Signature([0x61; 64]),
    }
}

fn config(root: &TestRoot, clock: Arc<AtomicU64>) -> RuntimeStoreConfig {
    RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock))
}

fn grant_from_install(recovery: &GrantPreparingRecovery) -> RelayGrant {
    let frame: OpaqueRouteFrame =
        decode(recovery.canonical_install_frame()).expect("decode frozen InstallGrant");
    match frame.body {
        RelayFrameBody::InstallGrant(install) => install.grant,
        other => panic!("expected InstallGrant, got {other:?}"),
    }
}

fn grant_committed_frame(grant: &RelayGrant) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(agentdeck_protocol::relay_v2::frame::GrantCommitted {
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
        }),
    })
}

fn signed_revocation(grant: &RelayGrant, binding: &MachineIdentityBinding) -> DeviceRevocation {
    let mut revocation = DeviceRevocation {
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: grant.grant_serial,
        root_key_id: grant.root_key_id,
        trust_epoch: grant.trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SEED),
        &revocation.to_be_signed_v1(RELAY, binding.root_fingerprint),
    )
    .into();
    revocation
}

fn revocation_committed_frame(revocation: &DeviceRevocation) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: revocation.device_route,
            grant_serial: revocation.grant_serial,
            signed_revocation: revocation.clone(),
        }),
    })
}

fn device_handle(device_route: DeviceRouteId) -> DeviceHandle {
    let mut value = String::from("device-");
    for byte in device_route.as_bytes() {
        value.push_str(&format!("{byte:02x}"));
    }
    DeviceHandle::new(value)
}

async fn prepare_installing_grant(
    store: &RuntimeStoreHandle,
) -> (
    MachineIdentityBinding,
    RuntimeId,
    GrantPreparingRecovery,
    RelayGrant,
) {
    let (binding, data_cert) = make_active(store).await;
    let preparation = awaiting_pairing(store, &binding, &data_cert).await;
    let pairing_id = preparation.pairing_id();
    let outcome = store
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect("freeze grant before revocation");
    let recovery = match outcome {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("fresh grant must confirm: {other:?}"),
    };
    let grant = grant_from_install(&recovery);
    (binding, pairing_id, recovery, grant)
}

async fn begin_expired_orphan(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
) -> (RuntimeId, RelayGrant, DeviceRevocation) {
    let (binding, pairing_id, _, grant) = prepare_installing_grant(store).await;
    let revocation = signed_revocation(&grant, &binding);
    clock.store(PAIRING_EXPIRY_MS, Ordering::SeqCst);
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::orphan(
                pairing_id,
                revocation.clone(),
            ))
            .await
            .expect("begin expired orphan"),
        BeginDeviceRevocationOutcome::Prepared { recovery }
            if recovery.phase() == RevocationRecoveryPhase::AwaitingGrantCommit
    ));
    (pairing_id, grant, revocation)
}

#[test]
fn prepare_local_revocation_freezes_bounded_canonical_frame() {
    let prepared = prepare_begin_for_dispatch(BeginDeviceRevocation::local(revocation()))
        .expect("freeze shaped local revocation");
    assert!(prepared.retained_bytes() > 0);
}

#[test]
fn prepare_orphan_revocation_rejects_non_pairing_id() {
    let wrong = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x71; 16])
        .expect("non-pairing runtime id");
    assert!(matches!(
        prepare_begin_for_dispatch(BeginDeviceRevocation::orphan(wrong, revocation())),
        Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: RuntimeIdKind::Conversation,
        })
    ));
}

#[test]
fn prepare_revocation_ack_accepts_only_exact_terminal_shape() {
    let signed_revocation = revocation();
    let canonical = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: signed_revocation.device_route,
            grant_serial: signed_revocation.grant_serial,
            signed_revocation,
        }),
    });
    prepare_revocation_committed(AcknowledgeRevocationCommitted::new(canonical))
        .expect("accept canonical RevocationCommitted");
    assert!(matches!(
        prepare_revocation_committed(AcknowledgeRevocationCommitted::new(Vec::new())),
        Err(RuntimeStoreError::PayloadTooLarge)
    ));
}

#[tokio::test]
async fn expired_preparing_grant_revokes_in_strict_order_and_recovers_after_restart() {
    let root = TestRoot::new("revocation-orphan-happy");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open revocation store");
    let (binding, pairing_id, installing, grant) = prepare_installing_grant(&store).await;
    let revocation = signed_revocation(&grant, &binding);
    let install_frame = installing.canonical_install_frame().to_vec();
    let revoke_frame = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevokeDevice(agentdeck_protocol::relay_v2::frame::RevokeDevice {
            revocation: revocation.clone(),
        }),
    });

    clock.store(PAIRING_EXPIRY_MS, Ordering::SeqCst);
    let due = store
        .list_due_orphan_revocation_targets()
        .await
        .expect("load expired orphan targets");
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].pairing_id(), Some(pairing_id));
    assert_eq!(due[0].grant(), &grant);

    let begun = store
        .begin_device_revocation(BeginDeviceRevocation::orphan(
            pairing_id,
            revocation.clone(),
        ))
        .await
        .expect("begin expired orphan revocation");
    let recovery = match begun {
        BeginDeviceRevocationOutcome::Prepared { recovery } => recovery,
        other => panic!("fresh orphan revoke must prepare: {other:?}"),
    };
    assert_eq!(recovery.pairing_id(), Some(pairing_id));
    assert_eq!(
        recovery.phase(),
        RevocationRecoveryPhase::AwaitingGrantCommit
    );
    assert_eq!(recovery.canonical_next_frame(), install_frame);
    assert_eq!(recovery.revocation(), &revocation);

    let replayed = store
        .begin_device_revocation(BeginDeviceRevocation::orphan(
            pairing_id,
            revocation.clone(),
        ))
        .await
        .expect("replay exact orphan begin");
    assert!(matches!(
        replayed,
        BeginDeviceRevocationOutcome::Replayed { recovery }
            if recovery.phase() == RevocationRecoveryPhase::AwaitingGrantCommit
                && recovery.canonical_next_frame() == install_frame
    ));

    let before_early_ack = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                revocation_committed_frame(&revocation),
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_early_ack);

    let advanced = store
        .acknowledge_orphan_grant_committed(pairing_id, grant_committed_frame(&grant))
        .await
        .expect("acknowledge orphan InstallGrant commit");
    let recovery = match advanced {
        AcknowledgeOrphanGrantCommittedOutcome::Advanced { recovery } => recovery,
        other => panic!("first orphan grant ACK must advance: {other:?}"),
    };
    assert_eq!(recovery.phase(), RevocationRecoveryPhase::ReadyToRevoke);
    assert_eq!(recovery.canonical_next_frame(), revoke_frame);

    let before_grant_replay = artifact_bytes(&root.database());
    let replayed = store
        .acknowledge_orphan_grant_committed(pairing_id, grant_committed_frame(&grant))
        .await
        .expect("replay orphan GrantCommitted");
    assert!(matches!(
        replayed,
        AcknowledgeOrphanGrantCommittedOutcome::Replayed { recovery }
            if recovery.phase() == RevocationRecoveryPhase::ReadyToRevoke
                && recovery.canonical_next_frame() == revoke_frame
    ));
    assert_eq!(artifact_bytes(&root.database()), before_grant_replay);

    let committed = store
        .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
            revocation_committed_frame(&revocation),
        ))
        .await
        .expect("acknowledge revocation commit");
    assert!(matches!(
        committed,
        AcknowledgeRevocationCommittedOutcome::Committed {
            revocation: observed
        } if observed == revocation
    ));
    assert!(
        store
            .list_revocation_recovery()
            .await
            .expect("list completed revocations")
            .is_empty()
    );
    assert_eq!(
        store
            .load_pairing_invite(pairing_id)
            .await
            .expect("load expired pairing")
            .expect("expired pairing remains until close ACK")
            .lifecycle(),
        PairingInviteLifecycle::Expired
    );
    let terminals = store
        .list_pairing_terminal_recovery()
        .await
        .expect("recover close after revocation");
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0].close().pairing_id(), pairing_id);
    assert!(matches!(
        terminals[0].receipt(),
        PairingReceipt::Confirmed { .. }
    ));

    let before_revocation_replay = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                revocation_committed_frame(&revocation),
            ))
            .await
            .expect("replay exact revocation ACK"),
        AcknowledgeRevocationCommittedOutcome::Replayed {
            revocation: observed
        } if observed == revocation
    ));
    assert_eq!(artifact_bytes(&root.database()), before_revocation_replay);
    store.shutdown().await.expect("shutdown revocation store");

    let reopened = RuntimeStoreHandle::open(
        config(&root, clock),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen completed revocation store");
    let status = reopened
        .load_revocation_target(
            &device_handle(grant.device_route),
            RuntimeGrantSerial::new(grant.grant_serial.value()),
        )
        .await
        .expect("load revoked target after restart")
        .expect("revoked target remains auditable");
    assert!(matches!(
        status,
        RevocationTargetStatus::Revoked {
            revocation: observed
        } if observed == revocation
    ));
    assert_eq!(
        reopened
            .list_pairing_terminal_recovery()
            .await
            .expect("recover close after restart")
            .len(),
        1
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened revocation store");
}

#[tokio::test]
async fn local_pre_expiry_revocation_cancels_undelivered_pairing_and_cannot_replay_as_orphan() {
    let root = TestRoot::new("revocation-local-cancel");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open local revocation store");
    let (binding, pairing_id, installing, grant) = prepare_installing_grant(&store).await;
    clock.store(NOW_MS + 1, Ordering::SeqCst);
    store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            pairing_id,
            grant_committed_frame(&grant),
        ))
        .await
        .expect("activate grant before local revoke");

    let handle = device_handle(grant.device_route);
    let runtime_serial = RuntimeGrantSerial::new(grant.grant_serial.value());
    let target = store
        .load_revocation_target(&handle, runtime_serial)
        .await
        .expect("load local revocation target")
        .expect("active grant is a known target");
    assert!(matches!(
        target,
        RevocationTargetStatus::Ready { target }
            if target.pairing_id().is_none()
                && target.device() == &handle
                && target.grant() == &grant
    ));

    let revocation = signed_revocation(&grant, &binding);
    clock.store(NOW_MS + 2, Ordering::SeqCst);
    let begun = store
        .begin_device_revocation(BeginDeviceRevocation::local(revocation.clone()))
        .await
        .expect("begin local revocation before pairing expiry");
    let recovery = match begun {
        BeginDeviceRevocationOutcome::Prepared { recovery } => recovery,
        other => panic!("fresh local revoke must prepare: {other:?}"),
    };
    assert_eq!(recovery.pairing_id(), Some(pairing_id));
    assert_eq!(recovery.phase(), RevocationRecoveryPhase::ReadyToRevoke);
    assert_ne!(
        recovery.canonical_next_frame(),
        installing.canonical_install_frame()
    );

    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::local(revocation.clone()))
            .await
            .expect("replay exact local begin"),
        BeginDeviceRevocationOutcome::Replayed { recovery }
            if recovery.pairing_id() == Some(pairing_id)
                && recovery.phase() == RevocationRecoveryPhase::ReadyToRevoke
    ));
    let before_wrong_cause = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::orphan(
                pairing_id,
                revocation.clone(),
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_wrong_cause);

    store
        .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
            revocation_committed_frame(&revocation),
        ))
        .await
        .expect("commit local revocation");
    assert_eq!(
        store
            .load_pairing_invite(pairing_id)
            .await
            .expect("load canceled pairing")
            .expect("pairing remains until close ACK")
            .lifecycle(),
        PairingInviteLifecycle::Canceled
    );
    let terminals = store
        .list_pairing_terminal_recovery()
        .await
        .expect("recover local cancellation close");
    assert_eq!(terminals.len(), 1);
    assert!(matches!(
        terminals[0].receipt(),
        PairingReceipt::Confirmed { .. }
    ));
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::local(revocation.clone()))
            .await
            .expect("replay completed local revoke"),
        BeginDeviceRevocationOutcome::AlreadyRevoked {
            revocation: observed
        } if observed == revocation
    ));
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::orphan(pairing_id, revocation))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    store
        .shutdown()
        .await
        .expect("shutdown local revocation store");
}

#[tokio::test]
async fn revocation_begin_fault_boundaries_converge_by_restart_and_exact_retry() {
    for (label, operation, committed) in [
        (
            "revocation-begin-before",
            RuntimeStoreOperation::BeginDeviceRevocationBeforeCommit,
            false,
        ),
        (
            "revocation-begin-after",
            RuntimeStoreOperation::BeginDeviceRevocationAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let setup = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open begin-fault setup");
        let (binding, pairing_id, _, grant) = prepare_installing_grant(&setup).await;
        let revocation = signed_revocation(&grant, &binding);
        clock.store(PAIRING_EXPIRY_MS, Ordering::SeqCst);
        setup.shutdown().await.expect("shutdown begin-fault setup");

        let faulted = RuntimeStoreHandle::open(
            config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted begin store");
        let error = faulted
            .begin_device_revocation(BeginDeviceRevocation::orphan(
                pairing_id,
                revocation.clone(),
            ))
            .await
            .expect_err("begin fault must surface");
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::BeginDeviceRevocation,
                }
            ),
            committed
        );
        assert_eq!(
            faulted
                .list_revocation_recovery()
                .await
                .expect("read recovery after begin fault")
                .len(),
            usize::from(committed)
        );
        faulted
            .shutdown()
            .await
            .expect("shutdown faulted begin store");

        let reopened = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("reopen after begin fault");
        let retry = reopened
            .begin_device_revocation(BeginDeviceRevocation::orphan(pairing_id, revocation))
            .await
            .expect("retry exact begin after restart");
        assert!(matches!(
            (committed, retry),
            (true, BeginDeviceRevocationOutcome::Replayed { recovery })
                | (false, BeginDeviceRevocationOutcome::Prepared { recovery })
                if recovery.phase() == RevocationRecoveryPhase::AwaitingGrantCommit
        ));
        reopened
            .shutdown()
            .await
            .expect("shutdown recovered begin store");
    }
}

#[tokio::test]
async fn orphan_grant_ack_fault_boundaries_never_expose_revoke_early() {
    for (label, operation, committed) in [
        (
            "revocation-orphan-ack-before",
            RuntimeStoreOperation::AcknowledgeOrphanGrantCommittedBeforeCommit,
            false,
        ),
        (
            "revocation-orphan-ack-after",
            RuntimeStoreOperation::AcknowledgeOrphanGrantCommittedAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let setup = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open orphan-ack setup");
        let (pairing_id, grant, _) = begin_expired_orphan(&setup, &clock).await;
        setup.shutdown().await.expect("shutdown orphan-ack setup");

        let faulted = RuntimeStoreHandle::open(
            config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted orphan ACK store");
        let error = faulted
            .acknowledge_orphan_grant_committed(pairing_id, grant_committed_frame(&grant))
            .await
            .expect_err("orphan grant ACK fault must surface");
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::AcknowledgeOrphanGrantCommitted,
                }
            ),
            committed
        );
        let recoveries = faulted
            .list_revocation_recovery()
            .await
            .expect("recover phase after orphan ACK fault");
        assert_eq!(recoveries.len(), 1);
        assert_eq!(
            recoveries[0].phase(),
            if committed {
                RevocationRecoveryPhase::ReadyToRevoke
            } else {
                RevocationRecoveryPhase::AwaitingGrantCommit
            }
        );
        faulted
            .shutdown()
            .await
            .expect("shutdown faulted orphan ACK store");

        let reopened = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("reopen after orphan ACK fault");
        let retry = reopened
            .acknowledge_orphan_grant_committed(pairing_id, grant_committed_frame(&grant))
            .await
            .expect("retry exact orphan ACK");
        assert!(matches!(
            (committed, retry),
            (true, AcknowledgeOrphanGrantCommittedOutcome::Replayed { recovery })
                | (false, AcknowledgeOrphanGrantCommittedOutcome::Advanced { recovery })
                if recovery.phase() == RevocationRecoveryPhase::ReadyToRevoke
        ));
        reopened
            .shutdown()
            .await
            .expect("shutdown recovered orphan ACK store");
    }
}

#[tokio::test]
async fn revocation_ack_fault_boundaries_converge_to_one_terminal_close() {
    for (label, operation, committed) in [
        (
            "revocation-ack-before",
            RuntimeStoreOperation::AcknowledgeRevocationCommittedBeforeCommit,
            false,
        ),
        (
            "revocation-ack-after",
            RuntimeStoreOperation::AcknowledgeRevocationCommittedAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let setup = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open revocation-ack setup");
        let (pairing_id, grant, revocation) = begin_expired_orphan(&setup, &clock).await;
        setup
            .acknowledge_orphan_grant_committed(pairing_id, grant_committed_frame(&grant))
            .await
            .expect("advance orphan before revocation ACK fault");
        clock.store(PAIRING_EXPIRY_MS + 1, Ordering::SeqCst);
        setup
            .shutdown()
            .await
            .expect("shutdown revocation-ack setup");

        let faulted = RuntimeStoreHandle::open(
            config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted revocation ACK store");
        let error = faulted
            .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                revocation_committed_frame(&revocation),
            ))
            .await
            .expect_err("revocation ACK fault must surface");
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::AcknowledgeRevocationCommitted,
                }
            ),
            committed
        );
        assert_eq!(
            faulted
                .list_revocation_recovery()
                .await
                .expect("read revocation recovery after ACK fault")
                .len(),
            usize::from(!committed)
        );
        assert_eq!(
            faulted
                .list_pairing_terminal_recovery()
                .await
                .expect("read close recovery after ACK fault")
                .len(),
            usize::from(committed)
        );
        faulted
            .shutdown()
            .await
            .expect("shutdown faulted revocation ACK store");

        let reopened = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("reopen after revocation ACK fault");
        let retry = reopened
            .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                revocation_committed_frame(&revocation),
            ))
            .await
            .expect("retry exact revocation ACK");
        assert!(matches!(
            (committed, retry),
            (true, AcknowledgeRevocationCommittedOutcome::Replayed { revocation: observed })
                | (false, AcknowledgeRevocationCommittedOutcome::Committed { revocation: observed })
                if observed == revocation
        ));
        let terminals = reopened
            .list_pairing_terminal_recovery()
            .await
            .expect("recover exactly one close");
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].close().pairing_id(), pairing_id);
        reopened
            .shutdown()
            .await
            .expect("shutdown recovered revocation ACK store");
    }
}

#[tokio::test]
async fn offline_revocation_tamper_fails_full_open_without_rewriting_artifacts() {
    for (label, sql) in [
        (
            "revocation-sealed-payload-tamper",
            "UPDATE remote_authorization_ledger \
             SET sealed_revocation = zeroblob(length(sealed_revocation)) \
             WHERE lifecycle = 'revoking'",
        ),
        (
            "revocation-hash-tamper",
            "UPDATE remote_authorization_ledger \
             SET revocation_hash = X'01010101010101010101010101010101\
                                      01010101010101010101010101010101' \
             WHERE lifecycle = 'revoking'",
        ),
        (
            "revocation-outbox-tamper",
            "UPDATE remote_control_outbox \
             SET metadata_token = zeroblob(length(metadata_token)) \
             WHERE operation_kind = 'revokeDevice'",
        ),
        (
            "revocation-pairing-token-tamper",
            "UPDATE remote_pairings SET metadata_token = zeroblob(length(metadata_token)) \
             WHERE lifecycle = 'orphanRevoking'",
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let store = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open revocation tamper setup");
        begin_expired_orphan(&store, &clock).await;
        store
            .shutdown()
            .await
            .expect("shutdown before revocation tamper");

        let connection = rusqlite::Connection::open(root.database()).expect("open offline DB");
        assert_eq!(
            connection.execute(sql, []).expect("tamper revocation row"),
            1
        );
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint offline revocation tamper");
        drop(connection);
        let before = artifact_bytes(&root.database());
        let error = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect_err("offline revocation tamper must fail full open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(artifact_bytes(&root.database()), before);
    }
}
