//! Focused tests for the P4.3 G1 confirm/grant Store slice.
//!
//! Matrix: confirm first-valid/replay/AlreadyHandled, before+after COMMIT unknown,
//! wrong request/grant axes/hash/serial, confirm-vs-cancel first winner, auth/key/outbox
//! quota arithmetic, offline tamper zero-write, and restart recovery exact bytes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_crypto::{
    HpkePublicKey, PairResponseSealAuthority, SigningKey, seal_key_directory_entry,
    seal_pair_response, sha256, sign_device_authorization, sign_key_directory, sign_tbs,
};
use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, E2EE_FORMAT_VERSION, KeyDirectorySignatureContextV1, KeyDirectoryV1,
    KeyUpdateInfoV1, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
    PairResponseInfoV1, PairResponsePlaintextV1,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, Ed25519Signature, GrantSerial, RELAY_PROTOCOL_VERSION, RelayGrant, RootKeyId,
    TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation};
use crate::security::{MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::pairing::{AcceptPairRequest, CommitPairPending, PairingInviteLifecycle};
use super::pairing_grant::{ConfirmPairingGrant, GlobalKeyStateV1, PairingGrantPreparation};
use super::pairing_grant_tx::ConfirmPairingGrantOutcome;
use super::pairing_terminal::{PairingTerminalAction, PairingTerminalizeOutcome};
use super::pairing_tests::{
    DeterministicRng, GenerousCapacity, NOW_MS, OneShotFault, TestClock, TestRoot, artifact_bytes,
    make_active, pending_envelope, prepare_unused_pairing, verified_request,
};
use super::sqlite::RuntimeLedger;

const ROOT_SEED: [u8; 32] = [0x41; 32];
const DATA_SEED: [u8; 32] = [0x43; 32];

pub(super) fn secret(seed: u8) -> SecretBytes {
    SecretBytes::new(vec![seed; 32])
}

fn pair_context(pair_route: agentdeck_protocol::relay_v2::PairRouteId) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponse,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn key_context(info: &KeyUpdateInfoV1) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(info.machine_route),
        device_route: Some(info.device_route),
        stream_route: None,
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: info.key_epoch,
    }
}

pub(super) fn grant_input(
    preparation: &PairingGrantPreparation,
    binding: &crate::runtime::store::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
) -> ConfirmPairingGrant {
    let device_route = DeviceRouteId::from_bytes([0xd1; 16]);
    let global = GlobalKeyStateV1::bootstrap(
        1,
        1,
        secret(0xc1),
        device_route,
        1,
        secret(0xc2),
        1,
        secret(0xc3),
    )
    .expect("bootstrap global state");
    grant_input_with(
        preparation,
        binding,
        data_cert,
        device_route,
        GrantSerial::new(1),
        global,
        None,
        0xd2,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn grant_input_with(
    preparation: &PairingGrantPreparation,
    binding: &crate::runtime::store::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    global: GlobalKeyStateV1,
    confirm_request_hash: Option<[u8; 32]>,
    entropy_seed: u8,
) -> ConfirmPairingGrant {
    let root = SigningKey::from_seed(&ROOT_SEED);
    let data = SigningKey::from_seed(&DATA_SEED);
    let request = preparation.request();
    let invite = preparation.invite();
    let mut grant = RelayGrant {
        machine_route: agentdeck_protocol::relay_v2::MachineRouteId::from_bytes([0x32; 16]),
        device_route,
        device_sign_pubkey: request.device_sign_pubkey,
        grant_serial,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        signature: Ed25519Signature([0; 64]),
    };
    grant.signature = sign_tbs(
        &root,
        &grant.to_be_signed_v1(invite.relay_server_id, binding.root_fingerprint),
    )
    .into();
    let authorization = sign_device_authorization(
        &root,
        invite.relay_server_id,
        &grant,
        DeviceAuthorizationV1 {
            format_version: E2EE_FORMAT_VERSION,
            grant_hash: grant.canonical_sha256(),
            machine_route: grant.machine_route,
            device_route,
            device_sign_fingerprint: sha256(&request.device_sign_pubkey.0),
            grant_serial: grant.grant_serial,
            device_hpke_pubkey: request.device_hpke_pubkey,
            capabilities: request.authorization_request.capabilities.clone(),
            permissions: request.authorization_request.permissions.clone(),
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign authorization");
    let recipient =
        HpkePublicKey::from_bytes(&request.device_hpke_pubkey.0).expect("device HPKE public key");
    let mut entries = Vec::new();
    for (index, view) in global
        .bootstrap_view(device_route)
        .expect("bootstrap key view")
        .into_iter()
        .enumerate()
    {
        let info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: invite.relay_server_id,
            machine_route: grant.machine_route,
            device_route,
            stream_route: None,
            grant_serial: grant.grant_serial,
            root_trust_epoch: grant.trust_epoch,
            key_directory_revision: global.revision(),
            key_purpose: view.purpose,
            key_epoch: view.epoch,
        };
        entries.push(
            seal_key_directory_entry(
                &recipient,
                &info,
                &key_context(&info),
                &view.key,
                &mut DeterministicRng::new(
                    [entropy_seed.wrapping_add(u8::try_from(index).expect("three key entries"));
                        32],
                ),
            )
            .expect("seal directory entry"),
        );
    }
    let signer =
        MachineDataSignerBindingV1::from_certificate(data_cert).expect("data signer binding");
    let directory_context = KeyDirectorySignatureContextV1 {
        relay_server_id: invite.relay_server_id,
        machine_route: grant.machine_route,
        device_route,
        grant_serial: grant.grant_serial,
        root_trust_epoch: grant.trust_epoch,
    };
    let directory = sign_key_directory(
        &data,
        &signer,
        &directory_context,
        KeyDirectoryV1 {
            revision: global.revision(),
            entries,
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign directory");
    let response_info = PairResponseInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: invite.pair_route,
        invite_hash: invite.canonical_sha256().expect("invite hash"),
        expiry_ms: invite.expires_at_ms,
        request_hash: preparation.request_hash(),
        machine_route: grant.machine_route,
        device_route,
        grant_serial: grant.grant_serial,
        root_trust_epoch: grant.trust_epoch,
    };
    let response = seal_pair_response(
        &recipient,
        &response_info,
        &pair_context(invite.pair_route),
        &PairResponsePlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            request_hash: preparation.request_hash(),
            relay_grant: grant.clone(),
            device_authorization: authorization.clone(),
            key_directory: directory.clone(),
        },
        PairResponseSealAuthority {
            machine_data_signing_key: &data,
            signer: &signer,
            machine_root_verifying_key: &root.verifying_key(),
        },
        &mut DeterministicRng::new([entropy_seed.wrapping_add(6); 32]),
    )
    .expect("seal response");
    ConfirmPairingGrant::new(
        preparation.pairing_id(),
        confirm_request_hash.unwrap_or_else(|| preparation.request_hash()),
        grant,
        authorization,
        directory,
        response,
        global,
    )
}

pub(super) async fn awaiting_pairing(
    store: &RuntimeStoreHandle,
    binding: &crate::runtime::store::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
) -> PairingGrantPreparation {
    awaiting_pairing_with(
        store,
        binding,
        data_cert,
        agentdeck_protocol::relay_v2::PairRouteId::from_bytes([0xa1; 16]),
        0xa2,
        0xa3,
        0xa4,
        0xa5,
        0xa6,
        0xa7,
        "grant-confirm",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn awaiting_pairing_with(
    store: &RuntimeStoreHandle,
    binding: &crate::runtime::store::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
    invite_seed: u8,
    private_seed: u8,
    device_sign_seed: u8,
    device_hpke_seed: u8,
    request_rng_seed: u8,
    pending_seed: u8,
    key: &str,
) -> PairingGrantPreparation {
    let (pairing_id, invite) = prepare_unused_pairing(
        store,
        binding,
        data_cert,
        pair_route,
        invite_seed,
        private_seed,
        key,
    )
    .await;
    let verified = verified_request(
        &invite,
        private_seed,
        device_sign_seed,
        device_hpke_seed,
        request_rng_seed,
    );
    let request_hash = verified.request_hash();
    store
        .accept_pair_request(AcceptPairRequest::new(pairing_id, verified))
        .await
        .expect("accept request");
    store
        .commit_pair_pending(CommitPairPending::new(
            pairing_id,
            request_hash,
            pending_envelope(pending_seed),
        ))
        .await
        .expect("commit pending");
    store
        .load_pairing_invite(pairing_id)
        .await
        .expect("load awaiting pairing")
        .expect("pairing exists")
        .into_grant_preparation()
        .expect("authenticated awaiting preparation")
}

#[test]
fn global_key_state_bootstrap_rejects_any_secret_reuse() {
    let route = DeviceRouteId::from_bytes([1; 16]);
    assert!(
        GlobalKeyStateV1::bootstrap(1, 1, secret(1), route, 1, secret(1), 1, secret(3),).is_err()
    );
}

#[test]
fn global_key_state_merge_preserves_devices_and_catalog_history_exactly() {
    let first = DeviceRouteId::from_bytes([1; 16]);
    let second = DeviceRouteId::from_bytes([2; 16]);
    let state = GlobalKeyStateV1::bootstrap(1, 1, secret(1), first, 1, secret(2), 1, secret(3))
        .expect("bootstrap global key state");
    let state = state
        .next_for_device(second, secret(4), secret(5), secret(6))
        .expect("merge second device");
    assert_eq!(state.revision().value(), 2);
    assert_eq!(state.device_count(), 2);
    assert_eq!(state.bootstrap_view(first).expect("first view").len(), 3);
    assert_eq!(state.bootstrap_view(second).expect("second view").len(), 3);
}

#[test]
fn confirm_ledger_rejects_quota_and_arithmetic_overflow_before_any_sql() {
    let overflow = RuntimeLedger {
        remote_pairing_receipt_count: u64::MAX,
        ..RuntimeLedger::default()
    };
    assert!(matches!(
        super::pairing_grant_tx::next_ledger_for_test(&overflow, 0, 1, 1, 1, None, 1, 1),
        Err(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_receipt_count",
        })
    ));

    let authorization_full = RuntimeLedger {
        remote_authorization_count: 256,
        ..RuntimeLedger::default()
    };
    assert!(matches!(
        super::pairing_grant_tx::next_ledger_for_test(&authorization_full, 0, 1, 1, 1, None, 1, 1,),
        Err(RuntimeStoreError::PairingLimit)
    ));

    let outbox_full = RuntimeLedger {
        remote_control_outbox_count: 1_024,
        ..RuntimeLedger::default()
    };
    assert!(matches!(
        super::pairing_grant_tx::next_ledger_for_test(&outbox_full, 0, 1, 1, 1, None, 1, 1),
        Err(RuntimeStoreError::PairingLimit)
    ));
}

#[tokio::test]
async fn confirm_freezes_all_rows_replays_exact_and_blocks_terminal_reversal() {
    let root = TestRoot::new("grant-confirm-replay");
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
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    let preparation = awaiting_pairing(&store, &binding, &data_cert).await;
    let first = store
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect("confirm grant");
    let (install, response) = match first {
        ConfirmPairingGrantOutcome::Confirmed { receipt, recovery } => {
            assert!(matches!(
                receipt,
                agentdeck_protocol::runtime::PairingReceipt::Confirmed { .. }
            ));
            assert_eq!(recovery.receipt(), &receipt);
            (
                recovery.canonical_install_frame().to_vec(),
                recovery.canonical_response().to_vec(),
            )
        }
        other => panic!("fresh confirm must transition: {other:?}"),
    };
    let retry = store
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect("retry exact confirm");
    match retry {
        ConfirmPairingGrantOutcome::Replayed { recovery, .. } => {
            assert_eq!(recovery.canonical_install_frame(), install);
            assert_eq!(recovery.canonical_response(), response);
        }
        other => panic!("exact retry must replay: {other:?}"),
    }
    let cancel = store
        .terminalize_pairing(preparation.pairing_id(), PairingTerminalAction::Cancel)
        .await
        .expect("cancel after confirm returns first winner");
    assert!(matches!(
        cancel,
        PairingTerminalizeOutcome::AlreadyHandled {
            state: agentdeck_protocol::runtime::PairingState::GrantPreparing,
            ..
        }
    ));
    let recovered = store
        .list_grant_preparing_recovery()
        .await
        .expect("list grant recovery");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].canonical_install_frame(), install);
    assert_eq!(recovered[0].canonical_response(), response);
    assert_eq!(
        store
            .load_pairing_invite(preparation.pairing_id())
            .await
            .expect("load confirmed pairing")
            .expect("pairing remains")
            .lifecycle(),
        PairingInviteLifecycle::GrantPreparing
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn terminal_first_winner_blocks_confirm_and_exact_retries_do_not_write() {
    let cancel_root = TestRoot::new("cancel-before-grant-confirm");
    let cancel_keys = MemoryKeyStore::new();
    let cancel_clock = Arc::new(AtomicU64::new(NOW_MS));
    let cancel_config = || {
        RuntimeStoreConfig::new(cancel_root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(cancel_clock.clone()))
    };
    let cancel_store = RuntimeStoreHandle::open(
        cancel_config(),
        load_or_create_storage_kek(&cancel_keys, &cancel_root.database())
            .expect("load cancel StorageKEK"),
    )
    .await
    .expect("open cancel-first store");
    let (cancel_binding, cancel_cert) = make_active(&cancel_store).await;
    let cancel_preparation = awaiting_pairing(&cancel_store, &cancel_binding, &cancel_cert).await;
    cancel_store
        .terminalize_pairing(
            cancel_preparation.pairing_id(),
            PairingTerminalAction::Cancel,
        )
        .await
        .expect("cancel wins before confirm");
    let before_cancel_retry = artifact_bytes(&cancel_root.database());
    let canceled = cancel_store
        .confirm_pairing_grant(grant_input(
            &cancel_preparation,
            &cancel_binding,
            &cancel_cert,
        ))
        .await
        .expect("confirm observes cancel winner");
    assert!(matches!(
        canceled,
        ConfirmPairingGrantOutcome::AlreadyHandled {
            receipt: agentdeck_protocol::runtime::PairingReceipt::Canceled { .. },
            state: agentdeck_protocol::runtime::PairingState::Canceled,
        }
    ));
    assert_eq!(artifact_bytes(&cancel_root.database()), before_cancel_retry);
    cancel_store
        .shutdown()
        .await
        .expect("shutdown cancel-first store");

    let expiry_root = TestRoot::new("expiry-before-grant-confirm");
    let expiry_keys = MemoryKeyStore::new();
    let expiry_clock = Arc::new(AtomicU64::new(NOW_MS));
    let expiry_config = || {
        RuntimeStoreConfig::new(expiry_root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(expiry_clock.clone()))
    };
    let expiry_store = RuntimeStoreHandle::open(
        expiry_config(),
        load_or_create_storage_kek(&expiry_keys, &expiry_root.database())
            .expect("load expiry StorageKEK"),
    )
    .await
    .expect("open expiry-first store");
    let (expiry_binding, expiry_cert) = make_active(&expiry_store).await;
    let expiry_preparation = awaiting_pairing(&expiry_store, &expiry_binding, &expiry_cert).await;
    expiry_clock.store(NOW_MS + 300_000, Ordering::SeqCst);
    let expired = expiry_store
        .confirm_pairing_grant(grant_input(
            &expiry_preparation,
            &expiry_binding,
            &expiry_cert,
        ))
        .await
        .expect("expiry wins confirm at deadline");
    assert!(matches!(
        expired,
        ConfirmPairingGrantOutcome::AlreadyHandled {
            receipt: agentdeck_protocol::runtime::PairingReceipt::Expired { .. },
            state: agentdeck_protocol::runtime::PairingState::Expired,
        }
    ));
    let before_expiry_retry = artifact_bytes(&expiry_root.database());
    assert!(matches!(
        expiry_store
            .confirm_pairing_grant(grant_input(
                &expiry_preparation,
                &expiry_binding,
                &expiry_cert,
            ))
            .await
            .expect("exact confirm retry observes expiry winner"),
        ConfirmPairingGrantOutcome::AlreadyHandled {
            receipt: agentdeck_protocol::runtime::PairingReceipt::Expired { .. },
            state: agentdeck_protocol::runtime::PairingState::Expired,
        }
    ));
    assert_eq!(artifact_bytes(&expiry_root.database()), before_expiry_retry);
    expiry_store
        .shutdown()
        .await
        .expect("shutdown expiry-first store");
}

#[tokio::test]
async fn confirmed_pairing_rejects_wrong_request_route_and_serial_without_writing() {
    let root = TestRoot::new("grant-confirm-conflict-axes");
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
    .expect("open conflict-axis store");
    let (binding, data_cert) = make_active(&store).await;
    let preparation = awaiting_pairing(&store, &binding, &data_cert).await;
    store
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect("confirm baseline grant");

    let before_wrong_hash = artifact_bytes(&root.database());
    let route = DeviceRouteId::from_bytes([0xd1; 16]);
    let wrong_hash_global =
        GlobalKeyStateV1::bootstrap(1, 1, secret(0xc1), route, 1, secret(0xc2), 1, secret(0xc3))
            .expect("bootstrap wrong-hash state");
    assert!(matches!(
        store
            .confirm_pairing_grant(grant_input_with(
                &preparation,
                &binding,
                &data_cert,
                route,
                GrantSerial::new(1),
                wrong_hash_global,
                Some([0xee; 32]),
                0xd2,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_wrong_hash);

    let before_wrong_route = artifact_bytes(&root.database());
    let wrong_route = DeviceRouteId::from_bytes([0xd2; 16]);
    let wrong_route_global = GlobalKeyStateV1::bootstrap(
        1,
        1,
        secret(0xe1),
        wrong_route,
        1,
        secret(0xe2),
        1,
        secret(0xe3),
    )
    .expect("bootstrap wrong-route state");
    assert!(matches!(
        store
            .confirm_pairing_grant(grant_input_with(
                &preparation,
                &binding,
                &data_cert,
                wrong_route,
                GrantSerial::new(1),
                wrong_route_global,
                None,
                0xe4,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_wrong_route);

    let before_wrong_serial = artifact_bytes(&root.database());
    let wrong_serial_global =
        GlobalKeyStateV1::bootstrap(1, 1, secret(0xc1), route, 1, secret(0xc2), 1, secret(0xc3))
            .expect("bootstrap wrong-serial state");
    assert!(matches!(
        store
            .confirm_pairing_grant(grant_input_with(
                &preparation,
                &binding,
                &data_cert,
                route,
                GrantSerial::new(2),
                wrong_serial_global,
                None,
                0xe5,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_wrong_serial);
    store
        .shutdown()
        .await
        .expect("shutdown conflict-axis store");
}

#[tokio::test]
async fn second_device_confirm_preserves_first_device_in_singleton_across_restart() {
    let root = TestRoot::new("grant-second-device");
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
    .expect("open multi-device store");
    let (binding, data_cert) = make_active(&store).await;
    let first_preparation = awaiting_pairing(&store, &binding, &data_cert).await;
    let first = store
        .confirm_pairing_grant(grant_input(&first_preparation, &binding, &data_cert))
        .await
        .expect("confirm first device");
    let (first_install, first_response) = match first {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => (
            recovery.canonical_install_frame().to_vec(),
            recovery.canonical_response().to_vec(),
        ),
        other => panic!("first device must confirm: {other:?}"),
    };

    let second_preparation = awaiting_pairing_with(
        &store,
        &binding,
        &data_cert,
        agentdeck_protocol::relay_v2::PairRouteId::from_bytes([0xb1; 16]),
        0xb2,
        0xb3,
        0xb4,
        0xb5,
        0xb6,
        0xb7,
        "grant-confirm-second",
    )
    .await;
    let second_route = DeviceRouteId::from_bytes([0xd2; 16]);
    let next_global = store
        .load_global_key_state()
        .await
        .expect("load first global state")
        .expect("first global state exists")
        .next_for_device(second_route, secret(0xe1), secret(0xe2), secret(0xe3))
        .expect("append second device to singleton");
    let second = store
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
        .expect("confirm second device");
    assert!(matches!(
        second,
        ConfirmPairingGrantOutcome::Confirmed { .. }
    ));
    let merged = store
        .load_global_key_state()
        .await
        .expect("load merged global state")
        .expect("merged global state exists");
    assert_eq!(merged.revision().value(), 2);
    assert_eq!(merged.device_count(), 2);
    assert_eq!(
        merged
            .bootstrap_view(DeviceRouteId::from_bytes([0xd1; 16]))
            .expect("first device remains addressable")
            .len(),
        3
    );
    assert_eq!(
        merged
            .bootstrap_view(second_route)
            .expect("second device is addressable")
            .len(),
        3
    );
    let recovery = store
        .list_grant_preparing_recovery()
        .await
        .expect("list both grant recoveries");
    assert_eq!(recovery.len(), 2);
    let recovered_first = recovery
        .iter()
        .find(|item| item.pairing_id() == first_preparation.pairing_id())
        .expect("first device recovery survives second confirm");
    assert_eq!(recovered_first.canonical_install_frame(), first_install);
    assert_eq!(recovered_first.canonical_response(), first_response);
    store.shutdown().await.expect("shutdown multi-device store");

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen multi-device store");
    let reopened_global = reopened
        .load_global_key_state()
        .await
        .expect("load global state after restart")
        .expect("global state survives restart");
    assert_eq!(reopened_global.revision().value(), 2);
    assert_eq!(reopened_global.device_count(), 2);
    assert_eq!(
        reopened
            .list_grant_preparing_recovery()
            .await
            .expect("recover both grants after restart")
            .len(),
        2
    );
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn confirm_fault_boundaries_and_restart_recovery_converge_to_exact_bytes() {
    for (label, operation, committed) in [
        (
            "grant-before-commit",
            RuntimeStoreOperation::ConfirmPairingGrantBeforeCommit,
            false,
        ),
        (
            "grant-after-commit",
            RuntimeStoreOperation::ConfirmPairingGrantAfterCommit,
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
        .expect("open grant fault setup");
        let (binding, data_cert) = make_active(&setup).await;
        let preparation = awaiting_pairing(&setup, &binding, &data_cert).await;
        let expected =
            super::pairing_grant_tx::prepare(grant_input(&preparation, &binding, &data_cert))
                .expect("prepare expected canonical grant artifacts");
        let expected_install = expected.canonical_install_frame.clone();
        let expected_response = expected.canonical_response.expose_secret().to_vec();
        setup.shutdown().await.expect("shutdown grant fault setup");

        let faulted = RuntimeStoreHandle::open(
            config().with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted grant store");
        let error = faulted
            .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
            .await
            .expect_err("grant fault must surface");
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: crate::runtime::model::RuntimeCommitOperation::ConfirmPairingGrant,
                }
            ),
            committed
        );
        let immediate = faulted
            .list_grant_preparing_recovery()
            .await
            .expect("read grant recovery after fault");
        assert_eq!(immediate.len(), usize::from(committed));
        if let Some(recovery) = immediate.first() {
            assert_eq!(recovery.pairing_id(), preparation.pairing_id());
            assert_eq!(recovery.request_hash(), preparation.request_hash());
            assert_eq!(recovery.canonical_install_frame(), expected_install);
            assert_eq!(recovery.canonical_response(), expected_response);
        }
        faulted
            .shutdown()
            .await
            .expect("shutdown faulted grant store");

        let reopened = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("reopen grant store after fault");
        let recovered_before_retry = reopened
            .list_grant_preparing_recovery()
            .await
            .expect("recover grant state after restart");
        assert_eq!(recovered_before_retry.len(), usize::from(committed));
        let retry = reopened
            .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
            .await
            .expect("exact grant retry after restart");
        let recovery = match (committed, retry) {
            (true, ConfirmPairingGrantOutcome::Replayed { recovery, .. })
            | (false, ConfirmPairingGrantOutcome::Confirmed { recovery, .. }) => recovery,
            (_, other) => panic!("unexpected grant retry outcome: {other:?}"),
        };
        assert_eq!(recovery.pairing_id(), preparation.pairing_id());
        assert_eq!(recovery.request_hash(), preparation.request_hash());
        assert_eq!(recovery.canonical_install_frame(), expected_install);
        assert_eq!(recovery.canonical_response(), expected_response);
        reopened
            .shutdown()
            .await
            .expect("shutdown recovered grant store");
    }
}

#[tokio::test]
async fn confirm_respects_retained_memory_budget_without_writing() {
    let root = TestRoot::new("grant-retained-memory-budget");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let base_config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let setup = RuntimeStoreHandle::open(
        base_config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open retained-memory setup");
    let (binding, data_cert) = make_active(&setup).await;
    let preparation = awaiting_pairing(&setup, &binding, &data_cert).await;
    setup
        .shutdown()
        .await
        .expect("shutdown retained-memory setup");

    let constrained = RuntimeStoreHandle::open(
        base_config().with_lane_byte_capacity(1),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("open constrained store");
    let before = artifact_bytes(&root.database());
    let error = constrained
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect_err("oversized retained grant must not enter safety lane");
    assert!(matches!(
        error,
        RuntimeStoreError::WorkerBusy {
            lane: crate::runtime::model::RuntimeStoreLane::Safety,
        }
    ));
    assert_eq!(artifact_bytes(&root.database()), before);
    constrained
        .shutdown()
        .await
        .expect("shutdown constrained store");
}

#[tokio::test]
async fn offline_grant_row_tamper_fails_full_open_without_rewriting_artifacts() {
    for (label, sql) in [
        (
            "grant-pairing-token-tamper",
            "UPDATE remote_pairings SET metadata_token = zeroblob(length(metadata_token))\
             WHERE lifecycle = 'grantPreparing'",
        ),
        (
            "grant-authorization-token-tamper",
            "UPDATE remote_authorization_ledger \
             SET metadata_token = zeroblob(length(metadata_token))",
        ),
        (
            "grant-global-key-token-tamper",
            "UPDATE remote_key_directory SET metadata_token = zeroblob(length(metadata_token))",
        ),
        (
            "grant-outbox-token-tamper",
            "UPDATE remote_control_outbox SET metadata_token = zeroblob(length(metadata_token)) \
             WHERE operation_kind = 'installGrant'",
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
        .expect("open grant tamper setup");
        let (binding, data_cert) = make_active(&store).await;
        let preparation = awaiting_pairing(&store, &binding, &data_cert).await;
        store
            .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
            .await
            .expect("confirm grant before offline tamper");
        store
            .shutdown()
            .await
            .expect("shutdown before offline tamper");

        let connection = rusqlite::Connection::open(root.database()).expect("open offline DB");
        assert_eq!(connection.execute(sql, []).expect("tamper grant row"), 1);
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint offline grant tamper");
        drop(connection);
        let before = artifact_bytes(&root.database());
        let error = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect_err("offline grant tamper must fail full open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(artifact_bytes(&root.database()), before);
    }
}
