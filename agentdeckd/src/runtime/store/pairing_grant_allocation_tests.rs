//! P4.3 grant serial renewal 的 Store authority focused tests。
//!
//! 覆盖 authenticated allocation、同 fingerprint 单调续期、stale allocation CAS、
//! 撤销终态拒绝，以及 Superseded 历史的离线篡改 fail-close/零改写。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_crypto::{SigningKey, sha256, sign_pair_response_received, sign_tbs};
use agentdeck_protocol::e2ee::PairResponseReceivedV1;
use agentdeck_protocol::relay_v2::frame::{
    GrantCommitted, OpaqueRouteFrame, PairRouteCloseOutcome, PairRouteClosed, RelayFrameBody,
    RetireMachine, RevocationCommitted,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, RELAY_PROTOCOL_VERSION,
    RelayGrant, RootKeyId, TrustEpoch, decode, encode,
};

use crate::remote::access::{PairResponseAccessBinding, VerifiedPairResponseReceipt};
use crate::runtime::model::{MachineIdentityBinding, RuntimeStoreConfig, RuntimeStoreError};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::pairing_authorization::AuthorizationLifecycle;
use super::pairing_delivery::{
    AcknowledgePairResponseReceived, AcknowledgePairResponseReceivedOutcome,
};
use super::pairing_grant::{ConfirmPairingGrant, PairingGrantPreparation};
use super::pairing_grant_allocation::GrantAllocationProjection;
use super::pairing_grant_commit::{
    AcknowledgeGrantCommitted, AcknowledgeGrantCommittedOutcome, GrantCommittedRecovery,
};
use super::pairing_grant_tests::{
    awaiting_pairing, awaiting_pairing_with, grant_input, grant_input_with, secret,
};
use super::pairing_grant_tx::{ConfirmPairingGrantOutcome, GrantPreparingRecovery};
use super::pairing_revocation::{BeginDeviceRevocation, BeginDeviceRevocationOutcome};
use super::pairing_revocation_ack::{
    AcknowledgeRevocationCommitted, AcknowledgeRevocationCommittedOutcome,
};
use super::pairing_terminal::{PairingTerminalAction, PairingTerminalizeOutcome};
use super::pairing_tests::{
    GenerousCapacity, MACHINE_ROUTE, NOW_MS, RELAY, TestClock, TestRoot, artifact_bytes,
    make_active,
};

const ROOT_SEED: [u8; 32] = [0x41; 32];
const DEVICE_SIGN_SEED: [u8; 32] = [0xa4; 32];

#[test]
fn max_serial_requires_trust_reset_without_wrapping() {
    assert!(matches!(
        super::pairing_grant_allocation::checked_next_serial(GrantSerial::new(u64::MAX)),
        Err(RuntimeStoreError::GrantSerialTrustResetRequired)
    ));
}

fn config(root: &TestRoot, clock: Arc<AtomicU64>) -> RuntimeStoreConfig {
    RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock))
}

fn next_time(clock: &AtomicU64) {
    let _ = clock.fetch_add(1, Ordering::SeqCst);
}

fn grant_from_install(recovery: &GrantPreparingRecovery) -> RelayGrant {
    let frame: OpaqueRouteFrame =
        decode(recovery.canonical_install_frame()).expect("decode InstallGrant");
    match frame.body {
        RelayFrameBody::InstallGrant(install) => install.grant,
        other => panic!("expected InstallGrant, got {other:?}"),
    }
}

fn grant_committed_frame(grant: &RelayGrant) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
        }),
    })
}

fn pair_route_closed_frame(pair_route: agentdeck_protocol::relay_v2::PairRouteId) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route,
            outcome: PairRouteCloseOutcome::Closed,
        }),
    })
}

fn verified_receipt(recovery: &GrantCommittedRecovery) -> VerifiedPairResponseReceipt {
    let binding = PairResponseAccessBinding::from_frozen(
        recovery.invite(),
        recovery.request_hash(),
        recovery.relay_grant(),
        recovery.pair_response(),
    )
    .expect("rebuild response binding");
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
    .expect("sign PairResponseReceived");
    binding
        .verify_signed_receipt(
            &receipt
                .canonical_bytes()
                .expect("canonical PairResponseReceived"),
        )
        .expect("verify PairResponseReceived")
}

async fn confirm_and_commit(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    preparation: &PairingGrantPreparation,
    input: ConfirmPairingGrant,
) -> (RelayGrant, GrantCommittedRecovery) {
    let confirmed = store
        .confirm_pairing_grant(input)
        .await
        .expect("confirm grant");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("fresh grant must confirm: {other:?}"),
    };
    let grant = grant_from_install(&installing);
    next_time(clock);
    let committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&grant),
        ))
        .await
        .expect("acknowledge GrantCommitted");
    let recovery = match committed {
        AcknowledgeGrantCommittedOutcome::Committed { recovery } => recovery,
        other => panic!("fresh GrantCommitted must transition: {other:?}"),
    };
    (grant, recovery)
}

async fn confirm_commit_and_deliver(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    preparation: &PairingGrantPreparation,
    input: ConfirmPairingGrant,
) -> RelayGrant {
    let (grant, committed) = confirm_and_commit(store, clock, preparation, input).await;
    let proof = verified_receipt(&committed);
    next_time(clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("acknowledge PairResponseReceived")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh PairResponseReceived must deliver: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            pair_route_closed_frame(close.pair_route()),
        )
        .await
        .expect("acknowledge PairRouteClosed");
    grant
}

async fn cancel_and_close(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    pairing_id: super::RuntimeId,
) {
    next_time(clock);
    let close = match store
        .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
        .await
        .expect("cancel pairing")
    {
        PairingTerminalizeOutcome::Transitioned { close, .. } => close,
        other => panic!("fresh cancel must transition: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(pairing_id, pair_route_closed_frame(close.pair_route()))
        .await
        .expect("acknowledge canceled PairRouteClosed");
}

fn renewal_projection(
    projection: GrantAllocationProjection,
) -> (
    [u8; 32],
    DeviceRouteId,
    GrantSerial,
    GrantSerial,
    super::pairing_grant::GlobalKeyStateV1,
) {
    match projection {
        GrantAllocationProjection::Renew {
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        } => (
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        ),
        GrantAllocationProjection::New { .. } => panic!("expected renewal allocation"),
    }
}

async fn first_delivered(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    binding: &MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
) -> RelayGrant {
    let preparation = awaiting_pairing(store, binding, data_cert).await;
    confirm_commit_and_deliver(
        store,
        clock,
        &preparation,
        grant_input(&preparation, binding, data_cert),
    )
    .await
}

async fn renewal_preparation(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    seed: u8,
    key: &str,
) -> PairingGrantPreparation {
    awaiting_pairing_with(
        store,
        binding,
        data_cert,
        agentdeck_protocol::relay_v2::PairRouteId::from_bytes([seed; 16]),
        seed.wrapping_add(1),
        seed.wrapping_add(2),
        0xa4,
        seed.wrapping_add(3),
        seed.wrapping_add(4),
        seed.wrapping_add(5),
        key,
    )
    .await
}

fn renewal_input(
    preparation: &PairingGrantPreparation,
    binding: &MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    projection: GrantAllocationProjection,
    entropy_seed: u8,
) -> (DeviceRouteId, GrantSerial, ConfirmPairingGrant) {
    let (_, route, _, next_serial, current_global) = renewal_projection(projection);
    let next_global = current_global
        .renew_for_device(
            route,
            secret(entropy_seed),
            secret(entropy_seed.wrapping_add(1)),
            secret(entropy_seed.wrapping_add(2)),
        )
        .expect("renew global keys");
    let input = grant_input_with(
        preparation,
        binding,
        data_cert,
        route,
        next_serial,
        next_global,
        None,
        entropy_seed.wrapping_add(3),
    );
    (route, next_serial, input)
}

#[tokio::test]
async fn new_allocation_authenticates_fingerprint_and_wrong_fingerprint_is_zero_write() {
    let root = TestRoot::new("grant-allocation-new");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open allocation store");
    let (binding, data_cert) = make_active(&store).await;
    let preparation = awaiting_pairing(&store, &binding, &data_cert).await;
    let fingerprint = sha256(&preparation.request().device_sign_pubkey.0);

    match store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("load new allocation")
    {
        GrantAllocationProjection::New {
            device_sign_fingerprint,
            current_global_keys,
        } => {
            assert_eq!(device_sign_fingerprint, fingerprint);
            assert!(current_global_keys.is_none());
        }
        GrantAllocationProjection::Renew { .. } => panic!("new fingerprint must not renew"),
    }

    let mut wrong = fingerprint;
    wrong[31] ^= 1;
    let before = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .load_grant_allocation(preparation.pairing_id(), wrong)
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before);
    store.shutdown().await.expect("shutdown allocation store");
}

#[tokio::test]
async fn renewal_reuses_route_increments_serial_and_atomically_supersedes_previous() {
    let root = TestRoot::new("grant-allocation-renew");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open renewal store");
    let (binding, data_cert) = make_active(&store).await;
    let first = first_delivered(&store, &clock, &binding, &data_cert).await;
    let preparation =
        renewal_preparation(&store, &binding, &data_cert, 0xb1, "grant-renew-second").await;
    let fingerprint = sha256(&preparation.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("load renewal allocation");
    let (_, route, current_serial, next_serial, _) = renewal_projection(match projection {
        GrantAllocationProjection::Renew {
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        } => GrantAllocationProjection::Renew {
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        },
        GrantAllocationProjection::New { .. } => panic!("expected renewal allocation"),
    });
    assert_eq!(route, first.device_route);
    assert_eq!(current_serial, GrantSerial::new(1));
    assert_eq!(next_serial, GrantSerial::new(2));

    let projection = store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("reload renewal allocation for consumption");
    let (route, serial, input) =
        renewal_input(&preparation, &binding, &data_cert, projection, 0x11);
    let outcome = store
        .confirm_pairing_grant(input)
        .await
        .expect("confirm renewal");
    assert!(matches!(
        outcome,
        ConfirmPairingGrantOutcome::Confirmed { .. }
    ));
    assert_eq!(route, first.device_route);
    assert_eq!(serial, GrantSerial::new(2));

    let rows = rusqlite::Connection::open(root.database())
        .expect("open renewal evidence DB")
        .prepare(
            "SELECT grant_serial, lifecycle FROM remote_authorization_ledger \
             ORDER BY device_route, grant_serial",
        )
        .expect("prepare renewal evidence")
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("query renewal evidence")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect renewal evidence");
    assert_eq!(
        rows,
        [
            ("00000000000000000001".to_owned(), "superseded".to_owned()),
            (
                "00000000000000000002".to_owned(),
                "grantPreparing".to_owned()
            ),
        ]
    );
    let global = store
        .load_global_key_state()
        .await
        .expect("load renewed global keys")
        .expect("global keys exist");
    assert_eq!(global.device_count(), 1);
    assert_eq!(global.revision().value(), 2);
    store.shutdown().await.expect("shutdown renewal store");
}

#[tokio::test]
async fn two_stale_allocations_allow_only_first_confirm_to_commit() {
    let root = TestRoot::new("grant-allocation-stale");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open stale allocation store");
    let (binding, data_cert) = make_active(&store).await;
    let first = first_delivered(&store, &clock, &binding, &data_cert).await;
    let left = renewal_preparation(&store, &binding, &data_cert, 0xb1, "stale-left").await;
    let right = renewal_preparation(&store, &binding, &data_cert, 0xc1, "stale-right").await;
    let fingerprint = sha256(&left.request().device_sign_pubkey.0);
    assert_eq!(fingerprint, sha256(&right.request().device_sign_pubkey.0));
    let left_projection = store
        .load_grant_allocation(left.pairing_id(), fingerprint)
        .await
        .expect("load left allocation");
    let right_projection = store
        .load_grant_allocation(right.pairing_id(), fingerprint)
        .await
        .expect("load right stale allocation");
    let (left_route, left_serial, left_input) =
        renewal_input(&left, &binding, &data_cert, left_projection, 0xd1);
    let (right_route, right_serial, right_input) =
        renewal_input(&right, &binding, &data_cert, right_projection, 0xe1);
    assert_eq!(left_route, first.device_route);
    assert_eq!(right_route, first.device_route);
    assert_eq!(left_serial, GrantSerial::new(2));
    assert_eq!(right_serial, GrantSerial::new(2));
    assert!(matches!(
        store
            .confirm_pairing_grant(left_input)
            .await
            .expect("first stale allocation wins"),
        ConfirmPairingGrantOutcome::Confirmed { .. }
    ));

    let before_loser = artifact_bytes(&root.database());
    assert!(matches!(
        store.confirm_pairing_grant(right_input).await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_loser);
    store
        .shutdown()
        .await
        .expect("shutdown stale allocation store");
}

#[tokio::test]
async fn restart_allocates_from_highest_serial_without_adding_a_device() {
    let root = TestRoot::new("grant-allocation-restart");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let make_config = || config(&root, clock.clone());
    let store = RuntimeStoreHandle::open(
        make_config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open restart allocation store");
    let (binding, data_cert) = make_active(&store).await;
    let first = first_delivered(&store, &clock, &binding, &data_cert).await;
    let second = renewal_preparation(&store, &binding, &data_cert, 0xb1, "restart-second").await;
    let fingerprint = sha256(&second.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(second.pairing_id(), fingerprint)
        .await
        .expect("load second allocation");
    let (_, _, second_input) = renewal_input(&second, &binding, &data_cert, projection, 0x11);
    let second_grant = confirm_commit_and_deliver(&store, &clock, &second, second_input).await;
    assert_eq!(second_grant.device_route, first.device_route);
    assert_eq!(second_grant.grant_serial, GrantSerial::new(2));
    assert_eq!(
        store
            .load_global_key_state()
            .await
            .expect("load global state")
            .expect("global state exists")
            .device_count(),
        1
    );
    store.shutdown().await.expect("shutdown before restart");

    let reopened = RuntimeStoreHandle::open(
        make_config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen renewal store");
    let third = renewal_preparation(&reopened, &binding, &data_cert, 0xd1, "restart-third").await;
    let (_, route, current, next, global) = renewal_projection(
        reopened
            .load_grant_allocation(third.pairing_id(), fingerprint)
            .await
            .expect("load third allocation after restart"),
    );
    assert_eq!(route, first.device_route);
    assert_eq!(current, GrantSerial::new(2));
    assert_eq!(next, GrantSerial::new(3));
    assert_eq!(global.device_count(), 1);
    reopened.shutdown().await.expect("shutdown reopened store");
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

fn retirement(binding: &MachineIdentityBinding) -> RetireMachine {
    let mut retirement = RetireMachine {
        machine_route: MACHINE_ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        signature: Ed25519Signature([0; 64]),
    };
    retirement.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SEED),
        &retirement.to_be_signed_v1(RELAY, binding.root_fingerprint),
    )
    .into();
    retirement
}

#[tokio::test]
async fn revoking_and_revoked_history_refuse_renewal_and_revoked_route_reuse() {
    let root = TestRoot::new("grant-allocation-revoked");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open revoked allocation store");
    let (binding, data_cert) = make_active(&store).await;
    let first = first_delivered(&store, &clock, &binding, &data_cert).await;
    let second = renewal_preparation(&store, &binding, &data_cert, 0xb1, "revoked-second").await;
    let fingerprint = sha256(&second.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(second.pairing_id(), fingerprint)
        .await
        .expect("load second serial before revoke");
    let (_, _, second_input) = renewal_input(&second, &binding, &data_cert, projection, 0x11);
    let grant = confirm_commit_and_deliver(&store, &clock, &second, second_input).await;
    assert_eq!(grant.device_route, first.device_route);
    assert_eq!(grant.grant_serial, GrantSerial::new(2));
    let renewal = renewal_preparation(&store, &binding, &data_cert, 0xd1, "revoked-renewal").await;
    let fingerprint = sha256(&renewal.request().device_sign_pubkey.0);
    let drain = store
        .list_revocation_drain_targets()
        .await
        .expect("load pre-revoke drain target");
    assert_eq!(
        drain.len(),
        1,
        "Superseded history must not become a target"
    );
    assert_eq!(drain[0].grant().grant_serial, GrantSerial::new(2));
    let revocation = signed_revocation(&grant, &binding);
    next_time(&clock);
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::local(revocation.clone()))
            .await
            .expect("begin revocation"),
        BeginDeviceRevocationOutcome::Prepared { .. }
    ));
    assert!(
        store
            .list_revocation_drain_targets()
            .await
            .expect("load revoking drain targets")
            .is_empty(),
        "Superseded and Revoking rows are not new drain work"
    );
    assert!(matches!(
        store
            .load_grant_allocation(renewal.pairing_id(), fingerprint)
            .await,
        Err(RuntimeStoreError::GrantRouteRevoked)
    ));

    next_time(&clock);
    assert!(matches!(
        store
            .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                revocation_committed_frame(&revocation),
            ))
            .await
            .expect("acknowledge revocation"),
        AcknowledgeRevocationCommittedOutcome::Committed { .. }
    ));
    assert!(
        store
            .list_revocation_drain_targets()
            .await
            .expect("load revoked drain targets")
            .is_empty(),
        "Superseded and Revoked rows are terminal for drain"
    );
    assert!(matches!(
        store
            .load_grant_allocation(renewal.pairing_id(), fingerprint)
            .await,
        Err(RuntimeStoreError::GrantRouteRevoked)
    ));

    let other = awaiting_pairing_with(
        &store,
        &binding,
        &data_cert,
        agentdeck_protocol::relay_v2::PairRouteId::from_bytes([0xc1; 16]),
        0xc2,
        0xc3,
        0xc4,
        0xc5,
        0xc6,
        0xc7,
        "revoked-route-reuse",
    )
    .await;
    let other_fingerprint = sha256(&other.request().device_sign_pubkey.0);
    let current_global = match store
        .load_grant_allocation(other.pairing_id(), other_fingerprint)
        .await
        .expect("new fingerprint allocation")
    {
        GrantAllocationProjection::New {
            device_sign_fingerprint,
            current_global_keys,
        } => {
            assert_eq!(device_sign_fingerprint, other_fingerprint);
            current_global_keys.expect("revoked device keeps global history")
        }
        GrantAllocationProjection::Renew { .. } => panic!("different fingerprint must be new"),
    };
    let before_reuse = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .confirm_pairing_grant(grant_input_with(
                &other,
                &binding,
                &data_cert,
                grant.device_route,
                GrantSerial::new(1),
                current_global,
                None,
                0xd1,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_reuse);

    cancel_and_close(&store, &clock, renewal.pairing_id()).await;
    cancel_and_close(&store, &clock, other.pairing_id()).await;

    let cleanup_precondition = rusqlite::Connection::open(root.database())
        .expect("open cleanup precondition DB")
        .query_row(
            "SELECT (SELECT COUNT(*) FROM remote_pairings),
                    (SELECT COUNT(*) FROM remote_control_outbox),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'superseded'),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'revoked')",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .expect("read cleanup precondition");
    assert_eq!(cleanup_precondition, (0, 0, 1, 1));
    store
        .prepare_machine_retirement(retirement(&binding))
        .await
        .expect("Superseded plus Revoked history permits root-present cleanup");
    let remaining = rusqlite::Connection::open(root.database())
        .expect("open post-cleanup evidence DB")
        .query_row(
            "SELECT (SELECT COUNT(*) FROM remote_pairings),
                    (SELECT COUNT(*) FROM remote_control_outbox),
                    (SELECT COUNT(*) FROM remote_authorization_ledger),
                    (SELECT COUNT(*) FROM remote_key_directory)",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .expect("read post-cleanup evidence");
    assert_eq!(remaining, (0, 0, 0, 0));
    store
        .shutdown()
        .await
        .expect("shutdown revoked allocation store");
}

async fn prepare_two_serial_history(root: &TestRoot, keys: &MemoryKeyStore, clock: Arc<AtomicU64>) {
    let store = RuntimeStoreHandle::open(
        config(root, clock.clone()),
        load_or_create_storage_kek(keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open tamper setup");
    let (binding, data_cert) = make_active(&store).await;
    let _ = first_delivered(&store, &clock, &binding, &data_cert).await;
    let second = renewal_preparation(&store, &binding, &data_cert, 0xb1, "tamper-second").await;
    let fingerprint = sha256(&second.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(second.pairing_id(), fingerprint)
        .await
        .expect("load tamper renewal allocation");
    let (_, _, input) = renewal_input(&second, &binding, &data_cert, projection, 0x11);
    let _ = confirm_commit_and_deliver(&store, &clock, &second, input).await;
    store.shutdown().await.expect("shutdown tamper setup");
}

#[tokio::test]
async fn authenticated_history_audit_rejects_route_fingerprint_serial_and_lifecycle_drift() {
    let root = TestRoot::new("grant-history-invariants");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    prepare_two_serial_history(&root, &keys, clock.clone()).await;
    let state = super::sqlite::open(
        &config(&root, clock),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .expect("open authenticated history state");
    let mut directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)
            .expect("load authenticated history");
    let history = &mut directory.grants.authorizations;
    assert_eq!(history.len(), 2);
    super::pairing_grant::validate_authorization_histories(history)
        .expect("baseline history is valid");

    let first_fingerprint = history[0].device_sign_fingerprint;
    history[0].device_sign_fingerprint[0] ^= 1;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[0].device_sign_fingerprint = first_fingerprint;

    let second_route = history[1].device_route;
    history[1].device_route = DeviceRouteId::from_bytes([0x01; 16]);
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[1].device_route = second_route;

    let first_serial = history[0].grant_serial;
    history[0].grant_serial = history[1].grant_serial;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[0].grant_serial = first_serial;

    history[0].lifecycle = AuthorizationLifecycle::Active;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[0].lifecycle = AuthorizationLifecycle::Superseded;

    history[1].lifecycle = AuthorizationLifecycle::Superseded;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[1].lifecycle = AuthorizationLifecycle::Active;

    history[0].lifecycle = AuthorizationLifecycle::Revoked;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
}

#[tokio::test]
async fn offline_superseded_serial_and_fingerprint_tamper_fail_close_without_rewrite() {
    for (label, sql) in [
        (
            "grant-superseded-metadata-tamper",
            "UPDATE remote_authorization_ledger \
             SET state_changed_at_ms = state_changed_at_ms + 1 \
             WHERE lifecycle = 'superseded'",
        ),
        (
            "grant-superseded-serial-tamper",
            "UPDATE remote_authorization_ledger \
             SET grant_serial = '00000000000000000009' \
             WHERE lifecycle = 'superseded'",
        ),
        (
            "grant-superseded-fingerprint-tamper",
            concat!(
                "UPDATE remote_authorization_ledger SET device_sign_fingerprint = ",
                "X'0101010101010101010101010101010101010101010101010101010101010101'",
                " WHERE lifecycle = 'superseded'"
            ),
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        prepare_two_serial_history(&root, &keys, clock.clone()).await;
        let connection = rusqlite::Connection::open(root.database()).expect("open offline DB");
        assert_eq!(connection.execute(sql, []).expect("tamper history row"), 1);
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint offline tamper");
        drop(connection);
        let before = artifact_bytes(&root.database());
        let error = RuntimeStoreHandle::open(
            config(&root, clock),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect_err("offline history tamper must fail full open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(artifact_bytes(&root.database()), before);
    }
}
