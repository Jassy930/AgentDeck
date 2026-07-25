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
    AuthorizationCapabilityV1, AuthorizationPermissionV1, DeviceAuthorizationV1,
    E2EE_FORMAT_VERSION, KeyDirectorySignatureContextV1, KeyDirectoryV1, KeyId, KeyPurpose,
    KeyUpdateInfoV1, KeyUpdateSetV1, KeyUpdateV1, MachineDataSignerBindingV1, OuterContextV1,
    OuterFrameKind, PairResponseInfoV1, PairResponsePlaintextV1,
};
use agentdeck_protocol::relay_v2::frame::{
    GrantCommitted, InstallGrant, OpaqueRouteFrame, RelayFrameBody,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, Ed25519Signature, GrantSerial, KeyDirectoryRevision, RELAY_PROTOCOL_VERSION,
    RelayGrant, RootKeyId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::{RUNTIME_PROTOCOL_VERSION, StreamCursor};
use tokio::sync::Semaphore;

use crate::runtime::backfill::BarrierRequest;
use crate::runtime::catalog_snapshot::CatalogSnapshotProvider;
use crate::runtime::connection::PrincipalIssuer;
use crate::runtime::events::{RegisterStreamBarrier, RuntimeStreamTarget, WatchGeneration};
use crate::runtime::model::{
    ConversationDescriptor, NewConversation, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreOperation,
};
use crate::runtime::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES;
use crate::security::{MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::pairing::{AcceptPairRequest, CommitPairPending, PairingInviteLifecycle};
use super::pairing_grant::{
    ConfirmPairingGrant, ConversationKeyRotation, GlobalKeyStateV1, MAX_DEVICES,
    MAX_RETENTION_OWNERS_PER_KEY, PairingGrantPreparation, RETIRED_KEY_RETENTION_MS,
    RetiredKeyOwnerKind, RetiredSharedKeyOwner,
};
use super::pairing_grant_allocation_tests::complete_active_membership_transition;
use super::pairing_grant_commit::AcknowledgeGrantCommitted;
use super::pairing_grant_tx::ConfirmPairingGrantOutcome;
use super::pairing_terminal::{PairingTerminalAction, PairingTerminalizeOutcome};
use super::pairing_tests::{
    DeterministicRng, GenerousCapacity, NOW_MS, OneShotFault, TestClock, TestRoot, artifact_bytes,
    make_active, pending_envelope, prepare_unused_pairing, verified_request,
    verified_request_with_authorization,
};
use super::publication::PublicationScope;
use super::sqlite::RuntimeLedger;

const ROOT_SEED: [u8; 32] = [0x41; 32];
const DATA_SEED: [u8; 32] = [0x43; 32];

struct ArmableConfirmFault {
    armed: AtomicBool,
}

impl crate::runtime::model::RuntimeStoreFaultInjector for ArmableConfirmFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::ConfirmPairingGrantBeforeCommit
            && self.armed.swap(false, Ordering::SeqCst)
        {
            Err(RuntimeStoreError::InvalidConfig(
                "injected ADGK2 add-member fault",
            ))
        } else {
            Ok(())
        }
    }
}

pub(super) fn secret(seed: u8) -> SecretBytes {
    SecretBytes::new(vec![seed; 32])
}

fn lifetime_secret(domain: u8, index: usize) -> SecretBytes {
    let index = u16::try_from(index).expect("lifetime fixture index fits u16");
    let mut bytes = vec![domain; 32];
    bytes[1..3].copy_from_slice(&index.to_be_bytes());
    SecretBytes::new(bytes)
}

fn lifetime_device_route(index: usize) -> DeviceRouteId {
    let index = u16::try_from(index).expect("lifetime fixture route fits u16");
    let mut route = [0_u8; 16];
    route[0] = 0xd0;
    route[14..].copy_from_slice(&index.to_be_bytes());
    DeviceRouteId::from_bytes(route)
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
        stream_route: info.stream_route,
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
        .install_directory_view(device_route)
        .expect("install key view")
        .into_iter()
        .enumerate()
    {
        let info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: invite.relay_server_id,
            machine_route: grant.machine_route,
            device_route,
            stream_route: view.stream_route,
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

pub(super) async fn awaiting_pairing_with_authorization(
    store: &RuntimeStoreHandle,
    binding: &crate::runtime::store::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    capabilities: Vec<AuthorizationCapabilityV1>,
    permissions: Vec<AuthorizationPermissionV1>,
) -> PairingGrantPreparation {
    let (pairing_id, invite) = prepare_unused_pairing(
        store,
        binding,
        data_cert,
        agentdeck_protocol::relay_v2::PairRouteId::from_bytes([0xa1; 16]),
        0xa2,
        0xa3,
        "grant-confirm-authorized",
    )
    .await;
    let verified = verified_request_with_authorization(
        &invite,
        0xa3,
        0xa4,
        0xa5,
        0xa6,
        capabilities,
        permissions,
    );
    let request_hash = verified.request_hash();
    store
        .accept_pair_request(AcceptPairRequest::new(pairing_id, verified))
        .await
        .expect("accept authorized request");
    store
        .commit_pair_pending(CommitPairPending::new(
            pairing_id,
            request_hash,
            pending_envelope(0xa7),
        ))
        .await
        .expect("commit authorized pending");
    store
        .load_pairing_invite(pairing_id)
        .await
        .expect("load authorized awaiting pairing")
        .expect("authorized pairing exists")
        .into_grant_preparation()
        .expect("authenticated authorized preparation")
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

fn legacy_adgk1_fixture() -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ADGK1");
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x11; 32]);
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&[0x21; 16]);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x22; 32]);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x23; 32]);
    encoded
}

fn legacy_adgk1_history_fixture() -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ADGK1");
    encoded.extend_from_slice(&2_u64.to_be_bytes());
    encoded.extend_from_slice(&2_u16.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x11; 32]);
    encoded.extend_from_slice(&2_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x12; 32]);
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.extend_from_slice(&[0x21; 16]);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x22; 32]);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&[0x23; 32]);
    encoded
}

fn state_with_two_conversations() -> GlobalKeyStateV1 {
    GlobalKeyStateV1::bootstrap(
        1,
        1,
        secret(0x11),
        DeviceRouteId::from_bytes([0x21; 16]),
        1,
        secret(0x22),
        1,
        secret(0x23),
    )
    .expect("bootstrap ADGK2 state")
    .activate_conversation(StreamRouteId::from_bytes([0x31; 16]), secret(0x32))
    .expect("activate first conversation")
    .activate_conversation(StreamRouteId::from_bytes([0x41; 16]), secret(0x42))
    .expect("activate second conversation")
}

fn state_with_retired_shared_keys() -> GlobalKeyStateV1 {
    let first_stream = StreamRouteId::from_bytes([0x31; 16]);
    let second_stream = StreamRouteId::from_bytes([0x41; 16]);
    state_with_two_conversations()
        .plan_add_device(
            DeviceRouteId::from_bytes([0x51; 16]),
            secret(0x52),
            secret(0x53),
            secret(0x54),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0x55)),
                ConversationKeyRotation::new(second_stream, secret(0x56)),
            ],
            10_000,
        )
        .expect("rotate shared keys")
        .into_state()
}

fn retention_owner(
    kind: RetiredKeyOwnerKind,
    owner_id: [u8; 16],
    purpose: KeyPurpose,
    stream_route: Option<StreamRouteId>,
    epoch: u64,
) -> RetiredSharedKeyOwner {
    RetiredSharedKeyOwner::new(kind, owner_id, purpose, stream_route, epoch)
        .expect("valid retired-key owner")
}

fn bootstrap_lineage_fixture_with(
    first_stream: StreamRouteId,
    first_current_key: SecretBytes,
) -> GlobalKeyStateV1 {
    let revoked_route = DeviceRouteId::from_bytes([0x21; 16]);
    let active_route = DeviceRouteId::from_bytes([0x51; 16]);
    let second_stream = StreamRouteId::from_bytes([0x41; 16]);
    GlobalKeyStateV1::bootstrap(
        1,
        1,
        secret(0x11),
        revoked_route,
        1,
        secret(0x22),
        1,
        secret(0x23),
    )
    .expect("bootstrap stable-lineage fixture")
    .activate_conversation(first_stream, secret(0x32))
    .expect("activate first stable-lineage conversation")
    .activate_conversation(second_stream, secret(0x42))
    .expect("activate second stable-lineage conversation")
    .plan_add_device(
        active_route,
        secret(0x52),
        secret(0x53),
        secret(0x54),
        vec![
            ConversationKeyRotation::new(first_stream, secret(0x55)),
            ConversationKeyRotation::new(second_stream, secret(0x56)),
        ],
        10_000,
    )
    .expect("add active stable-lineage device")
    .into_state()
    .plan_revoke_device(
        revoked_route,
        secret(0x61),
        vec![
            ConversationKeyRotation::new(first_stream, first_current_key),
            ConversationKeyRotation::new(second_stream, secret(0x63)),
        ],
        20_000,
    )
    .expect("revoke old stable-lineage device")
    .into_state()
}

fn bootstrap_lineage_fixture() -> GlobalKeyStateV1 {
    bootstrap_lineage_fixture_with(StreamRouteId::from_bytes([0x31; 16]), secret(0x62))
}

fn bootstrap_lineage_hash(state: &GlobalKeyStateV1) -> [u8; 32] {
    state.validate().expect("stable-lineage fixture validates");
    state
        .pairing_bootstrap_lineage_hash()
        .expect("hash validated stable-lineage fixture")
}

fn bootstrap_lineage_hash_hex(state: &GlobalKeyStateV1) -> String {
    bootstrap_lineage_hash(state)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn with_current_conversation_epoch(
    state: &GlobalKeyStateV1,
    current_key: u8,
    expected_epoch: u64,
    replacement_epoch: u64,
) -> GlobalKeyStateV1 {
    let mut canonical = state
        .canonical_bytes_for_test()
        .expect("encode conversation-epoch lineage fixture");
    let key_pattern = [current_key; 32];
    let key_offsets = canonical
        .windows(key_pattern.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == key_pattern).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(
        key_offsets.len(),
        1,
        "current conversation key fixture must occur exactly once"
    );
    let epoch_offset = key_offsets[0]
        .checked_sub(18)
        .expect("ADGK2 owner-free InternalKey prefix exists");
    assert_eq!(
        &canonical[epoch_offset..epoch_offset + 8],
        expected_epoch.to_be_bytes().as_slice(),
        "located current conversation key must carry the expected epoch"
    );
    assert_eq!(
        &canonical[epoch_offset + 8..epoch_offset + 18],
        &[0; 10],
        "current conversation key must be unretired and owner-free"
    );
    canonical[epoch_offset..epoch_offset + 8].copy_from_slice(&replacement_epoch.to_be_bytes());
    GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
        .expect("conversation-epoch mutation remains a valid canonical state")
}

fn assert_bootstrap_lineage_changed(
    axis: &str,
    baseline_hash: [u8; 32],
    candidate: &GlobalKeyStateV1,
) {
    assert_ne!(
        bootstrap_lineage_hash(candidate),
        baseline_hash,
        "changing {axis} must change the stable bootstrap lineage digest"
    );
}

#[test]
fn bootstrap_lineage_digest_has_fixed_sha256_kat() {
    assert_eq!(
        bootstrap_lineage_hash_hex(&bootstrap_lineage_fixture()),
        "2df91367dc4be4c1404451128961e4f6f99b610402cb1aa3a90818bbb560262e"
    );
}

#[test]
fn bootstrap_lineage_binds_every_current_key_axis() {
    let baseline_hash = bootstrap_lineage_hash(&bootstrap_lineage_fixture());

    let mut revision = bootstrap_lineage_fixture();
    revision.revision = 6;
    assert_bootstrap_lineage_changed("revision", baseline_hash, &revision);

    let mut catalog_epoch = bootstrap_lineage_fixture();
    catalog_epoch
        .catalogs
        .last_mut()
        .expect("current catalog exists")
        .epoch = 4;
    assert_bootstrap_lineage_changed("catalog epoch", baseline_hash, &catalog_epoch);

    let mut catalog_key = bootstrap_lineage_fixture();
    catalog_key
        .catalogs
        .last_mut()
        .expect("current catalog exists")
        .key = secret(0x71);
    assert_bootstrap_lineage_changed("catalog key", baseline_hash, &catalog_key);

    let mut device_route = bootstrap_lineage_fixture();
    device_route
        .devices
        .iter_mut()
        .find(|device| device.is_active())
        .expect("active device exists")
        .device_route = DeviceRouteId::from_bytes([0x52; 16]);
    assert_bootstrap_lineage_changed("active device route", baseline_hash, &device_route);

    let mut command_epoch = bootstrap_lineage_fixture();
    command_epoch
        .devices
        .iter_mut()
        .find(|device| device.is_active())
        .expect("active device exists")
        .command
        .epoch = 2;
    assert_bootstrap_lineage_changed("command epoch", baseline_hash, &command_epoch);

    let mut command_key = bootstrap_lineage_fixture();
    command_key
        .devices
        .iter_mut()
        .find(|device| device.is_active())
        .expect("active device exists")
        .command
        .key = Some(secret(0x72));
    assert_bootstrap_lineage_changed("command key", baseline_hash, &command_key);

    let mut reply_epoch = bootstrap_lineage_fixture();
    reply_epoch
        .devices
        .iter_mut()
        .find(|device| device.is_active())
        .expect("active device exists")
        .reply
        .epoch = 2;
    assert_bootstrap_lineage_changed("reply epoch", baseline_hash, &reply_epoch);

    let mut reply_key = bootstrap_lineage_fixture();
    reply_key
        .devices
        .iter_mut()
        .find(|device| device.is_active())
        .expect("active device exists")
        .reply
        .key = Some(secret(0x73));
    assert_bootstrap_lineage_changed("reply key", baseline_hash, &reply_key);

    let conversation_route =
        bootstrap_lineage_fixture_with(StreamRouteId::from_bytes([0x33; 16]), secret(0x62));
    assert_bootstrap_lineage_changed("conversation route", baseline_hash, &conversation_route);

    let conversation_epoch =
        with_current_conversation_epoch(&bootstrap_lineage_fixture(), 0x62, 3, 4);
    assert_bootstrap_lineage_changed("conversation epoch", baseline_hash, &conversation_epoch);

    let conversation_key =
        bootstrap_lineage_fixture_with(StreamRouteId::from_bytes([0x31; 16]), secret(0x64));
    assert_bootstrap_lineage_changed("conversation key", baseline_hash, &conversation_key);
}

#[test]
fn bootstrap_lineage_ignores_retention_owner_while_present_and_after_release() {
    let owner = retention_owner(
        RetiredKeyOwnerKind::Publication,
        [0x8f; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let baseline = bootstrap_lineage_fixture();
    let baseline_hash = bootstrap_lineage_hash(&baseline);
    let owned = baseline
        .acquire_retired_shared_key_owner(owner)
        .expect("acquire owner on an existing retired catalog key");
    assert!(
        owned.has_retention_owner_for_test(owner),
        "owner must actually exist before the exclusion assertion"
    );
    assert_eq!(bootstrap_lineage_hash(&owned), baseline_hash);

    let released = owned
        .release_retired_shared_key_owner(owner)
        .expect("release existing retired catalog owner");
    assert!(
        !released.has_retention_owner_for_test(owner),
        "released owner must actually be absent"
    );
    assert_eq!(bootstrap_lineage_hash(&released), baseline_hash);
}

#[test]
fn bootstrap_lineage_ignores_retired_shared_key_gc_and_tombstones() {
    let baseline = bootstrap_lineage_fixture();
    let baseline_hash = bootstrap_lineage_hash(&baseline);
    assert_eq!(baseline.retired_key_count_for_test(), 6);

    let tombstoned = baseline
        .prune_expired_retired_keys(10_000 + RETIRED_KEY_RETENTION_MS)
        .expect("collect the first retired shared-key generation");
    assert_eq!(
        tombstoned.retired_key_count_for_test(),
        3,
        "first-generation retired shared secrets must actually be collected"
    );
    let tombstone_probe = retention_owner(
        RetiredKeyOwnerKind::Replay,
        [0x90; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let tombstoned = tombstoned
        .release_retired_shared_key_owner(tombstone_probe)
        .expect("exact release retry proves the collected target tombstone exists");
    assert_eq!(
        bootstrap_lineage_hash(&tombstoned),
        baseline_hash,
        "retired shared-key GC and its tombstone must not fork current lineage"
    );
}

#[test]
fn bootstrap_lineage_ignores_revoked_device_directed_secret_scrub() {
    let first_stream = StreamRouteId::from_bytes([0x31; 16]);
    let second_stream = StreamRouteId::from_bytes([0x41; 16]);
    let mut retained = bootstrap_lineage_fixture()
        .prune_expired_retired_keys(10_000 + RETIRED_KEY_RETENTION_MS)
        .expect("collect the first retired shared-key generation");
    for owner in [
        retention_owner(
            RetiredKeyOwnerKind::Snapshot,
            [0xa1; 16],
            KeyPurpose::Catalog,
            None,
            2,
        ),
        retention_owner(
            RetiredKeyOwnerKind::Snapshot,
            [0xa2; 16],
            KeyPurpose::ConversationDek,
            Some(first_stream),
            2,
        ),
        retention_owner(
            RetiredKeyOwnerKind::Snapshot,
            [0xa3; 16],
            KeyPurpose::ConversationDek,
            Some(second_stream),
            2,
        ),
    ] {
        retained = retained
            .acquire_retired_shared_key_owner(owner)
            .expect("pin second-generation retired shared key during directed-secret scrub");
    }
    assert_eq!(retained.retired_key_count_for_test(), 3);
    assert_eq!(
        retained
            .retained_retired_secret_count()
            .expect("count retained shared and directed secrets before scrub"),
        5
    );
    let baseline_hash = bootstrap_lineage_hash(&retained);

    let scrubbed = retained
        .prune_expired_retired_keys(20_000 + RETIRED_KEY_RETENTION_MS)
        .expect("scrub revoked-device directed secrets while owners pin shared history");
    assert_eq!(
        scrubbed.retired_key_count_for_test(),
        3,
        "pinned shared history must remain present to isolate directed-secret scrub"
    );
    assert_eq!(
        scrubbed
            .retained_retired_secret_count()
            .expect("count retained secrets after revoked-device scrub"),
        3,
        "only the revoked device command/reply secrets must be removed"
    );
    assert_eq!(
        bootstrap_lineage_hash(&scrubbed),
        baseline_hash,
        "revoked-device directed-secret scrub must not fork active lineage"
    );
}

#[test]
fn adgk1_is_read_compatibly_but_every_new_encoding_is_strict_adgk2() {
    let legacy = legacy_adgk1_fixture();
    let upgraded = GlobalKeyStateV1::from_canonical_bytes_for_test(&legacy)
        .expect("ADGK1 fixture remains readable");
    let canonical = upgraded
        .canonical_bytes_for_test()
        .expect("upgraded state has canonical ADGK2 bytes");
    assert_eq!(&canonical[..5], b"ADGK2");
    assert_ne!(canonical, legacy);
    assert_eq!(upgraded.revision().value(), 1);
    assert_eq!(upgraded.device_count(), 1);

    let decoded = GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
        .expect("canonical ADGK2 roundtrip");
    assert_eq!(
        decoded.canonical_bytes_for_test().expect("ADGK2 re-encode"),
        canonical
    );

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&trailing).is_err());

    let mut retired_current = canonical.clone();
    retired_current[30] = 1;
    assert!(
        GlobalKeyStateV1::from_canonical_bytes_for_test(&retired_current).is_err(),
        "current key cannot carry retired-at metadata"
    );
    let mut owned_current = canonical;
    let mut owner = Vec::with_capacity(42);
    owner.push(0); // Publication
    owner.extend_from_slice(&[0x71; 16]);
    owner.push(0); // Catalog
    owner.extend_from_slice(&[0; 16]);
    owner.extend_from_slice(&1_u64.to_be_bytes());
    owned_current[31..33].copy_from_slice(&1_u16.to_be_bytes());
    owned_current.splice(33..33, owner);
    let owned_current_decoded = GlobalKeyStateV1::from_canonical_bytes_for_test(&owned_current)
        .expect("current shared key may pre-bind a canonical retention owner");
    assert_eq!(
        owned_current_decoded
            .canonical_bytes_for_test()
            .expect("pre-bound current owner re-encodes canonically"),
        owned_current,
        "rotation must be able to move the exact current key plus owner into retired history"
    );
}

#[test]
fn member_add_rotates_all_shared_epochs_and_never_bootstraps_old_keys() {
    let first = DeviceRouteId::from_bytes([0x21; 16]);
    let second = DeviceRouteId::from_bytes([0x51; 16]);
    let first_stream = StreamRouteId::from_bytes([0x31; 16]);
    let second_stream = StreamRouteId::from_bytes([0x41; 16]);
    let retired_at_ms = 10_000;
    let plan = state_with_two_conversations()
        .plan_add_device(
            second,
            secret(0x52),
            secret(0x53),
            secret(0x54),
            vec![
                ConversationKeyRotation::new(second_stream, secret(0x56)),
                ConversationKeyRotation::new(first_stream, secret(0x55)),
            ],
            retired_at_ms,
        )
        .expect("atomically plan member add");

    assert_eq!(plan.revision().value(), 4);
    assert_eq!(
        plan.transitions()
            .iter()
            .map(|transition| (
                transition.purpose,
                transition.stream_route,
                transition.old_epoch,
                transition.new_epoch,
                transition.retired_at_ms,
            ))
            .collect::<Vec<_>>(),
        vec![
            (KeyPurpose::Catalog, None, 1, 2, retired_at_ms),
            (
                KeyPurpose::ConversationDek,
                Some(first_stream),
                1,
                2,
                retired_at_ms,
            ),
            (
                KeyPurpose::ConversationDek,
                Some(second_stream),
                1,
                2,
                retired_at_ms,
            ),
        ]
    );
    let bootstrap = plan
        .new_device_bootstrap()
        .expect("bootstrap view")
        .expect("add has a new device");
    assert_eq!(
        bootstrap
            .each_ref()
            .map(|entry| (entry.purpose, entry.epoch)),
        [
            (KeyPurpose::Catalog, 2),
            (KeyPurpose::DeviceCommandTx, 1),
            (KeyPurpose::DeviceReplyTx, 1),
        ]
    );
    assert!(
        bootstrap
            .iter()
            .all(|entry| entry.purpose != KeyPurpose::ConversationDek)
    );

    for route in [first, second] {
        let updates = plan
            .shared_updates_for_device(route)
            .expect("remaining/new device receives only current shared epochs");
        assert_eq!(updates.len(), 3);
        assert_eq!(
            updates
                .iter()
                .map(|entry| (entry.purpose, entry.stream_route, entry.epoch))
                .collect::<Vec<_>>(),
            vec![
                (KeyPurpose::Catalog, None, 2),
                (KeyPurpose::ConversationDek, Some(first_stream), 2),
                (KeyPurpose::ConversationDek, Some(second_stream), 2),
            ]
        );
    }
    assert_eq!(plan.retired_key_count_for_test(), 3);
    assert_eq!(plan.retired_at_values_for_test(), vec![retired_at_ms; 3]);

    let state = plan.into_state();
    let canonical = state
        .canonical_bytes_for_test()
        .expect("rotation plan encodes canonically");
    assert_eq!(&canonical[..5], b"ADGK2");
    assert_eq!(
        GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
            .expect("rotation plan survives audit decode")
            .canonical_bytes_for_test()
            .expect("rotation plan canonical re-encode"),
        canonical
    );
}

#[test]
fn member_rotation_requires_exact_conversation_set_and_revoke_blocks_old_member() {
    let first = DeviceRouteId::from_bytes([0x21; 16]);
    let second = DeviceRouteId::from_bytes([0x51; 16]);
    let first_stream = StreamRouteId::from_bytes([0x31; 16]);
    let second_stream = StreamRouteId::from_bytes([0x41; 16]);

    assert!(
        state_with_two_conversations()
            .plan_add_device(
                second,
                secret(0x52),
                secret(0x53),
                secret(0x54),
                vec![ConversationKeyRotation::new(first_stream, secret(0x55),)],
                10_000,
            )
            .is_err(),
        "缺任一 active conversation rotation 必须整笔拒绝"
    );

    let added = state_with_two_conversations()
        .plan_add_device(
            second,
            secret(0x52),
            secret(0x53),
            secret(0x54),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0x55)),
                ConversationKeyRotation::new(second_stream, secret(0x56)),
            ],
            10_000,
        )
        .expect("add second member")
        .into_state();
    let revoked = added
        .plan_revoke_device(
            first,
            secret(0x61),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0x62)),
                ConversationKeyRotation::new(second_stream, secret(0x63)),
            ],
            20_000,
        )
        .expect("atomically plan revoke");
    assert!(revoked.shared_updates_for_device(first).is_err());
    assert_eq!(
        revoked
            .shared_updates_for_device(second)
            .expect("remaining member gets current keys")
            .iter()
            .map(|entry| entry.epoch)
            .collect::<Vec<_>>(),
        vec![3, 3, 3]
    );
    assert_eq!(revoked.device_revoked_at_for_test(first), Some(20_000));
    let revoked = revoked.into_state();
    assert!(
        revoked
            .device_transport_key(first, KeyPurpose::DeviceReplyTx)
            .is_err(),
        "revoked device must not obtain a directed reply key"
    );
    assert_eq!(
        revoked
            .device_transport_key(second, KeyPurpose::DeviceCommandTx)
            .expect("remaining device command key")
            .epoch,
        1
    );
    assert_eq!(
        revoked
            .device_transport_key(second, KeyPurpose::DeviceReplyTx)
            .expect("remaining device reply key")
            .epoch,
        1
    );
}

#[test]
fn revoked_device_keys_are_removed_after_retention_but_route_tombstone_survives() {
    let revoked_route = DeviceRouteId::from_bytes([0x21; 16]);
    let remaining_route = DeviceRouteId::from_bytes([0x51; 16]);
    let first_stream = StreamRouteId::from_bytes([0x31; 16]);
    let second_stream = StreamRouteId::from_bytes([0x41; 16]);
    let retired_at_ms = 20_000;
    let state = state_with_two_conversations()
        .plan_add_device(
            remaining_route,
            secret(0x52),
            secret(0x53),
            secret(0x54),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0x55)),
                ConversationKeyRotation::new(second_stream, secret(0x56)),
            ],
            10_000,
        )
        .expect("add remaining device")
        .into_state()
        .plan_revoke_device(
            revoked_route,
            secret(0x61),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0x62)),
                ConversationKeyRotation::new(second_stream, secret(0x63)),
            ],
            retired_at_ms,
        )
        .expect("revoke first device")
        .into_state();
    let before = state
        .canonical_bytes_for_test()
        .expect("encode retained revoked-device keys");
    assert!(before.windows(32).any(|window| window == [0x22; 32]));
    assert!(before.windows(32).any(|window| window == [0x23; 32]));
    assert_eq!(
        state
            .retained_retired_secret_count()
            .expect("count shared and directed retired secrets"),
        8,
        "six retired shared keys plus the revoked device's two directed keys are retained"
    );

    let retained = state
        .prune_expired_retired_keys(retired_at_ms + RETIRED_KEY_RETENTION_MS - 1)
        .expect("retain revoked-device keys for the full retention window");
    let retained_canonical = retained
        .canonical_bytes_for_test()
        .expect("encode pre-deadline revoked-device keys");
    assert!(
        retained_canonical
            .windows(32)
            .any(|window| window == [0x22; 32])
            && retained_canonical
                .windows(32)
                .any(|window| window == [0x23; 32])
    );

    let collected = retained
        .prune_expired_retired_keys(retired_at_ms + RETIRED_KEY_RETENTION_MS)
        .expect("collect expired revoked-device keys");
    let canonical = collected
        .canonical_bytes_for_test()
        .expect("encode revoked-device route tombstone");
    assert!(
        !canonical.windows(32).any(|window| window == [0x22; 32])
            && !canonical.windows(32).any(|window| window == [0x23; 32]),
        "expired DeviceCommandTx/DeviceReplyTx raw keys must not remain in ADGK2"
    );
    assert!(collected.contains_device_route(revoked_route));
    assert_eq!(
        collected.device_revoked_at_for_test(revoked_route),
        Some(retired_at_ms)
    );
    assert!(
        collected
            .device_transport_key(revoked_route, KeyPurpose::DeviceCommandTx)
            .is_err(),
        "route tombstone must never recover a removed transport secret"
    );
    assert!(
        collected
            .device_transport_key(remaining_route, KeyPurpose::DeviceReplyTx)
            .is_ok(),
        "active device transport key must remain available"
    );
    assert_eq!(
        collected
            .retained_retired_secret_count()
            .expect("count collected retired secrets"),
        0
    );
    assert_eq!(
        GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
            .expect("reopen route tombstone")
            .canonical_bytes_for_test()
            .expect("re-encode route tombstone"),
        canonical
    );
}

#[test]
fn collected_device_secrets_do_not_release_the_256_route_tombstone_limit() {
    let mut state = GlobalKeyStateV1::bootstrap(
        1,
        1,
        lifetime_secret(0x11, 0),
        lifetime_device_route(0),
        1,
        lifetime_secret(0x21, 0),
        1,
        lifetime_secret(0x31, 0),
    )
    .expect("bootstrap lifetime tombstone fixture");
    let mut now_ms = 10_000_u64;

    for index in 0..(MAX_DEVICES - 1) {
        state = state
            .plan_revoke_device(
                lifetime_device_route(index),
                lifetime_secret(0x41, index),
                Vec::new(),
                now_ms,
            )
            .expect("revoke current lifetime route")
            .into_state();
        now_ms = now_ms
            .checked_add(RETIRED_KEY_RETENTION_MS + 1)
            .expect("fixture clock remains bounded");
        state = state
            .prune_expired_retired_keys(now_ms)
            .expect("collect expired directed secrets")
            .plan_add_device(
                lifetime_device_route(index + 1),
                lifetime_secret(0x51, index),
                lifetime_secret(0x61, index + 1),
                lifetime_secret(0x71, index + 1),
                Vec::new(),
                now_ms,
            )
            .expect("append next lifetime route")
            .into_state();
        now_ms = now_ms
            .checked_add(1)
            .expect("fixture clock remains bounded");
    }

    assert_eq!(state.device_count(), MAX_DEVICES);
    assert!(state.contains_device_route(lifetime_device_route(0)));
    let canonical = state
        .canonical_bytes_for_test()
        .expect("encode capped lifetime tombstones");
    assert!(matches!(
        GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
            .expect("reopen capped state for limit check")
            .plan_add_device(
                lifetime_device_route(MAX_DEVICES),
                lifetime_secret(0x81, MAX_DEVICES),
                lifetime_secret(0x82, MAX_DEVICES),
                lifetime_secret(0x83, MAX_DEVICES),
                Vec::new(),
                now_ms,
            ),
        Err(RuntimeStoreError::PairingLimit)
    ));
    assert!(matches!(
        GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
            .expect("reopen capped state for route-reuse check")
            .plan_add_device(
                lifetime_device_route(0),
                lifetime_secret(0x84, 0),
                lifetime_secret(0x85, 0),
                lifetime_secret(0x86, 0),
                Vec::new(),
                now_ms,
            ),
        Err(RuntimeStoreError::PairingConflict)
    ));

    let reopened = GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
        .expect("reopen capped lifetime tombstones");
    assert_eq!(reopened.device_count(), MAX_DEVICES);
    assert!(reopened.contains_device_route(lifetime_device_route(0)));
    assert_eq!(
        reopened
            .canonical_bytes_for_test()
            .expect("re-encode capped lifetime tombstones"),
        canonical
    );
}

#[test]
fn retired_keys_are_kept_for_full_relay_retention_plus_one_hour() {
    let first_stream = StreamRouteId::from_bytes([0x31; 16]);
    let second_stream = StreamRouteId::from_bytes([0x41; 16]);
    let retired_at_ms = 10_000;
    let state = state_with_two_conversations()
        .plan_add_device(
            DeviceRouteId::from_bytes([0x51; 16]),
            secret(0x52),
            secret(0x53),
            secret(0x54),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0x55)),
                ConversationKeyRotation::new(second_stream, secret(0x56)),
            ],
            retired_at_ms,
        )
        .expect("rotate shared keys")
        .into_state();
    let retention = retention_owner(
        RetiredKeyOwnerKind::Snapshot,
        [0x71; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let owned = state
        .acquire_retired_shared_key_owner(retention)
        .expect("acquire retired catalog owner");
    let before_deadline = owned
        .prune_expired_retired_keys(retired_at_ms + RETIRED_KEY_RETENTION_MS - 1)
        .expect("pre-deadline prune is valid");
    assert_eq!(before_deadline.retired_key_count_for_test(), 3);
    let at_deadline = before_deadline
        .prune_expired_retired_keys(retired_at_ms + RETIRED_KEY_RETENTION_MS)
        .expect("deadline prune is valid");
    assert_eq!(at_deadline.retired_key_count_for_test(), 1);
    let retired = at_deadline
        .retired_shared_keys()
        .expect("retired key readback");
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].purpose, KeyPurpose::Catalog);
    assert_eq!(retired[0].stream_route, None);
    assert_eq!(retired[0].epoch, 1);
    assert_eq!(retired[0].retired_at_ms, retired_at_ms);
    assert_eq!(retired[0].retention_owners, vec![retention]);
    let at_deadline = at_deadline
        .release_retired_shared_key_owner(retention)
        .expect("release retired catalog owner")
        .prune_expired_retired_keys(retired_at_ms + RETIRED_KEY_RETENTION_MS)
        .expect("released key becomes collectable");
    assert_eq!(at_deadline.retired_key_count_for_test(), 0);
    assert_eq!(
        at_deadline
            .shared_key_epochs_for_test()
            .into_iter()
            .map(|(_, epoch)| epoch)
            .collect::<Vec<_>>(),
        vec![2, 2, 2]
    );

    let legacy = GlobalKeyStateV1::from_canonical_bytes_for_test(&legacy_adgk1_history_fixture())
        .expect("legacy state");
    let legacy = legacy
        .prune_expired_retired_keys(u64::MAX)
        .expect("legacy unknown retirement remains auditable");
    assert_eq!(legacy.device_count(), 1);
    assert_eq!(legacy.retired_key_count_for_test(), 1);
}

#[test]
fn retired_key_owner_identity_is_idempotent_recoverable_and_release_safe() {
    let retired_at_ms = 10_000;
    let deadline = retired_at_ms + RETIRED_KEY_RETENTION_MS;
    let publication = retention_owner(
        RetiredKeyOwnerKind::Publication,
        [0x91; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let replay = retention_owner(
        RetiredKeyOwnerKind::Replay,
        [0x81; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let wrong_owner = retention_owner(
        RetiredKeyOwnerKind::Replay,
        [0x82; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );

    let acquired = state_with_retired_shared_keys()
        .acquire_retired_shared_key_owner(publication)
        .expect("acquire publication owner");
    let once = acquired
        .canonical_bytes_for_test()
        .expect("encode one owner");
    let acquired = acquired
        .acquire_retired_shared_key_owner(publication)
        .expect("duplicate acquire is idempotent");
    assert_eq!(
        acquired
            .canonical_bytes_for_test()
            .expect("re-encode duplicate acquire"),
        once
    );
    let acquired = acquired
        .acquire_retired_shared_key_owner(replay)
        .expect("acquire replay owner");
    let before_wrong_release = acquired
        .canonical_bytes_for_test()
        .expect("encode both owners");
    let acquired = acquired
        .release_retired_shared_key_owner(wrong_owner)
        .expect("wrong owner release is a no-op");
    assert_eq!(
        acquired
            .canonical_bytes_for_test()
            .expect("wrong release remains byte-stable"),
        before_wrong_release
    );

    let canonical = acquired
        .canonical_bytes_for_test()
        .expect("freeze recoverable owners");
    let reopened = GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
        .expect("reopen owner-bound ADGK2 state");
    let catalog = reopened
        .retired_shared_keys()
        .expect("read retired owner set")
        .into_iter()
        .find(|key| key.purpose == KeyPurpose::Catalog && key.epoch == 1)
        .expect("retired catalog key");
    assert_eq!(catalog.retention_owners, vec![publication, replay]);

    let retained = reopened
        .prune_expired_retired_keys(deadline)
        .expect("owned catalog remains at retention deadline");
    assert_eq!(retained.retired_key_count_for_test(), 1);
    let retained = retained
        .release_retired_shared_key_owner(publication)
        .expect("release publication owner");
    let once_released = retained
        .canonical_bytes_for_test()
        .expect("encode first release");
    let retained = retained
        .release_retired_shared_key_owner(publication)
        .expect("exact release retry is idempotent");
    assert_eq!(
        retained
            .canonical_bytes_for_test()
            .expect("release retry is byte-stable"),
        once_released
    );
    assert_eq!(
        retained
            .retired_shared_keys()
            .expect("read remaining replay owner")[0]
            .retention_owners,
        vec![replay]
    );
    let collected = retained
        .release_retired_shared_key_owner(replay)
        .expect("release last owner")
        .prune_expired_retired_keys(deadline)
        .expect("owner-free retired key becomes collectable");
    assert_eq!(collected.retired_key_count_for_test(), 0);
}

#[test]
fn current_shared_key_owner_survives_rotation_and_blocks_retired_gc() {
    let first_stream = StreamRouteId::from_bytes([0x31; 16]);
    let second_stream = StreamRouteId::from_bytes([0x41; 16]);
    let retired_at_ms = 10_000;
    let publication = retention_owner(
        RetiredKeyOwnerKind::Publication,
        [0x98; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let rotated = state_with_two_conversations()
        .acquire_retired_shared_key_owner(publication)
        .expect("pre-bind owner while publication key is current")
        .plan_add_device(
            DeviceRouteId::from_bytes([0x58; 16]),
            secret(0x59),
            secret(0x5a),
            secret(0x5b),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0x5c)),
                ConversationKeyRotation::new(second_stream, secret(0x5d)),
            ],
            retired_at_ms,
        )
        .expect("rotate owner-bound current key")
        .into_state();
    let retired = rotated
        .retired_shared_keys()
        .expect("read owner after rotation");
    let catalog = retired
        .iter()
        .find(|key| key.purpose == KeyPurpose::Catalog && key.epoch == 1)
        .expect("old catalog key is retired");
    assert_eq!(catalog.retention_owners, vec![publication]);

    let deadline = retired_at_ms + RETIRED_KEY_RETENTION_MS;
    let retained = rotated
        .prune_expired_retired_keys(deadline)
        .expect("owner blocks retired-key deadline GC");
    assert_eq!(retained.retired_key_count_for_test(), 1);
    let collected = retained
        .release_retired_shared_key_owner(publication)
        .expect("release publication owner")
        .prune_expired_retired_keys(deadline)
        .expect("released current-origin owner permits GC");
    assert_eq!(collected.retired_key_count_for_test(), 0);
}

#[test]
fn released_owner_retry_survives_gc_and_reopen_without_accepting_forged_target() {
    let retired_at_ms = 10_000;
    let deadline = retired_at_ms + RETIRED_KEY_RETENTION_MS;
    let released = retention_owner(
        RetiredKeyOwnerKind::Publication,
        [0xa1; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let collected = state_with_retired_shared_keys()
        .acquire_retired_shared_key_owner(released)
        .expect("acquire durable owner")
        .release_retired_shared_key_owner(released)
        .expect("release durable owner")
        .prune_expired_retired_keys(deadline)
        .expect("collect owner-free retired key");
    let canonical = collected
        .canonical_bytes_for_test()
        .expect("freeze collected state");
    let reopened = GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
        .expect("reopen collected state");

    let retried = reopened
        .release_retired_shared_key_owner(released)
        .expect("exact release retry remains idempotent after GC and reopen");
    assert_eq!(
        retried
            .canonical_bytes_for_test()
            .expect("exact release retry remains byte-stable"),
        canonical
    );

    let forged_epoch = retention_owner(
        RetiredKeyOwnerKind::Publication,
        [0xa2; 16],
        KeyPurpose::Catalog,
        None,
        99,
    );
    assert!(
        GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
            .expect("reopen state for forged epoch check")
            .release_retired_shared_key_owner(forged_epoch)
            .is_err(),
        "从未存在的 epoch 不能被 missing-target 幂等语义吞掉"
    );
    let forged_route = retention_owner(
        RetiredKeyOwnerKind::Replay,
        [0xa3; 16],
        KeyPurpose::ConversationDek,
        Some(StreamRouteId::from_bytes([0xfe; 16])),
        1,
    );
    assert!(
        GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
            .expect("reopen state for forged route check")
            .release_retired_shared_key_owner(forged_route)
            .is_err(),
        "从未存在的 stream route 不能被 missing-target 幂等语义吞掉"
    );
}

#[test]
fn retired_target_tombstones_are_canonical_and_reject_duplicates_or_forged_targets() {
    const TOMBSTONE_BYTES: usize = 25;
    let canonical = state_with_retired_shared_keys()
        .prune_expired_retired_keys(10_000 + RETIRED_KEY_RETENTION_MS)
        .expect("collect three owner-free retired keys")
        .canonical_bytes_for_test()
        .expect("encode target tombstones");
    let tombstone_count_offset = canonical.len() - 4 - 3 * TOMBSTONE_BYTES;
    let first_tombstone_offset = tombstone_count_offset + 4;
    assert_eq!(
        &canonical[tombstone_count_offset..first_tombstone_offset],
        &3_u32.to_be_bytes()
    );
    assert_eq!(
        GlobalKeyStateV1::from_canonical_bytes_for_test(&canonical)
            .expect("decode canonical tombstones")
            .canonical_bytes_for_test()
            .expect("re-encode canonical tombstones"),
        canonical
    );

    let mut duplicate = canonical.clone();
    let first =
        duplicate[first_tombstone_offset..first_tombstone_offset + TOMBSTONE_BYTES].to_vec();
    duplicate.splice(
        first_tombstone_offset + TOMBSTONE_BYTES..first_tombstone_offset + TOMBSTONE_BYTES,
        first,
    );
    duplicate[tombstone_count_offset..first_tombstone_offset].copy_from_slice(&4_u32.to_be_bytes());
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&duplicate).is_err());

    let mut noncanonical_order = canonical.clone();
    let first = noncanonical_order
        [first_tombstone_offset..first_tombstone_offset + TOMBSTONE_BYTES]
        .to_vec();
    let second = noncanonical_order
        [first_tombstone_offset + TOMBSTONE_BYTES..first_tombstone_offset + 2 * TOMBSTONE_BYTES]
        .to_vec();
    noncanonical_order[first_tombstone_offset..first_tombstone_offset + TOMBSTONE_BYTES]
        .copy_from_slice(&second);
    noncanonical_order
        [first_tombstone_offset + TOMBSTONE_BYTES..first_tombstone_offset + 2 * TOMBSTONE_BYTES]
        .copy_from_slice(&first);
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&noncanonical_order).is_err());

    let mut forged_kind = canonical.clone();
    forged_kind[first_tombstone_offset] = 1; // ConversationDEK with a zero route.
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&forged_kind).is_err());

    let mut forged_current_epoch = canonical;
    forged_current_epoch[first_tombstone_offset + 17..first_tombstone_offset + 25]
        .copy_from_slice(&2_u64.to_be_bytes());
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&forged_current_epoch).is_err());
}

#[test]
fn retired_key_owner_encoding_is_canonical_and_rejects_malformed_sets() {
    const OWNER_COUNT_OFFSET: usize = 5 + 8 + 2 + 8 + 8;
    const FIRST_OWNER_OFFSET: usize = OWNER_COUNT_OFFSET + 2;
    const OWNER_BYTES: usize = 42;
    let publication = retention_owner(
        RetiredKeyOwnerKind::Publication,
        [0x91; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let replay = retention_owner(
        RetiredKeyOwnerKind::Replay,
        [0x81; 16],
        KeyPurpose::Catalog,
        None,
        1,
    );
    let reverse_order = state_with_retired_shared_keys()
        .acquire_retired_shared_key_owner(replay)
        .expect("acquire replay first")
        .acquire_retired_shared_key_owner(publication)
        .expect("acquire publication second")
        .canonical_bytes_for_test()
        .expect("encode reverse acquire order");
    let canonical_order = state_with_retired_shared_keys()
        .acquire_retired_shared_key_owner(publication)
        .expect("acquire publication first")
        .acquire_retired_shared_key_owner(replay)
        .expect("acquire replay second")
        .canonical_bytes_for_test()
        .expect("encode canonical acquire order");
    assert_eq!(reverse_order, canonical_order);
    assert_eq!(
        &canonical_order[OWNER_COUNT_OFFSET..FIRST_OWNER_OFFSET],
        &2_u16.to_be_bytes()
    );

    let mut duplicate = canonical_order.clone();
    let first_owner = duplicate[FIRST_OWNER_OFFSET..FIRST_OWNER_OFFSET + OWNER_BYTES].to_vec();
    duplicate.splice(
        FIRST_OWNER_OFFSET + 2 * OWNER_BYTES..FIRST_OWNER_OFFSET + 2 * OWNER_BYTES,
        first_owner,
    );
    duplicate[OWNER_COUNT_OFFSET..FIRST_OWNER_OFFSET].copy_from_slice(&3_u16.to_be_bytes());
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&duplicate).is_err());

    let mut zero_id = canonical_order.clone();
    zero_id[FIRST_OWNER_OFFSET + 1..FIRST_OWNER_OFFSET + 17].fill(0);
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&zero_id).is_err());

    let mut invalid_kind = canonical_order.clone();
    invalid_kind[FIRST_OWNER_OFFSET] = 0xff;
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&invalid_kind).is_err());

    let mut wrong_target = canonical_order.clone();
    wrong_target[FIRST_OWNER_OFFSET + 17] = 1; // ConversationDEK
    wrong_target[FIRST_OWNER_OFFSET + 18..FIRST_OWNER_OFFSET + 34].fill(0x31);
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&wrong_target).is_err());

    let mut wrong_epoch = canonical_order.clone();
    wrong_epoch[FIRST_OWNER_OFFSET + 34..FIRST_OWNER_OFFSET + 42]
        .copy_from_slice(&2_u64.to_be_bytes());
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&wrong_epoch).is_err());

    let mut noncanonical_order = canonical_order;
    let first = noncanonical_order[FIRST_OWNER_OFFSET..FIRST_OWNER_OFFSET + OWNER_BYTES].to_vec();
    let second = noncanonical_order
        [FIRST_OWNER_OFFSET + OWNER_BYTES..FIRST_OWNER_OFFSET + 2 * OWNER_BYTES]
        .to_vec();
    noncanonical_order[FIRST_OWNER_OFFSET..FIRST_OWNER_OFFSET + OWNER_BYTES]
        .copy_from_slice(&second);
    noncanonical_order[FIRST_OWNER_OFFSET + OWNER_BYTES..FIRST_OWNER_OFFSET + 2 * OWNER_BYTES]
        .copy_from_slice(&first);
    assert!(GlobalKeyStateV1::from_canonical_bytes_for_test(&noncanonical_order).is_err());
}

#[test]
fn retired_key_owner_binding_and_capacity_fail_closed() {
    let stream = StreamRouteId::from_bytes([0x31; 16]);
    assert!(
        RetiredSharedKeyOwner::new(
            RetiredKeyOwnerKind::Publication,
            [0; 16],
            KeyPurpose::Catalog,
            None,
            1,
        )
        .is_err()
    );
    assert!(
        RetiredSharedKeyOwner::new(
            RetiredKeyOwnerKind::Publication,
            [1; 16],
            KeyPurpose::Catalog,
            Some(stream),
            1,
        )
        .is_err()
    );
    assert!(
        RetiredSharedKeyOwner::new(
            RetiredKeyOwnerKind::Replay,
            [2; 16],
            KeyPurpose::ConversationDek,
            None,
            1,
        )
        .is_err()
    );
    assert!(
        RetiredSharedKeyOwner::new(
            RetiredKeyOwnerKind::Replay,
            [3; 16],
            KeyPurpose::ConversationDek,
            Some(StreamRouteId::from_bytes([0; 16])),
            1,
        )
        .is_err()
    );
    assert!(
        RetiredSharedKeyOwner::new(
            RetiredKeyOwnerKind::Snapshot,
            [4; 16],
            KeyPurpose::DeviceReplyTx,
            None,
            1,
        )
        .is_err()
    );
    assert!(
        RetiredSharedKeyOwner::new(
            RetiredKeyOwnerKind::Snapshot,
            [5; 16],
            KeyPurpose::Catalog,
            None,
            0,
        )
        .is_err()
    );

    let mut state = state_with_retired_shared_keys();
    for value in 1..=MAX_RETENTION_OWNERS_PER_KEY {
        state = state
            .acquire_retired_shared_key_owner(retention_owner(
                RetiredKeyOwnerKind::Publication,
                u128::try_from(value).expect("owner index").to_be_bytes(),
                KeyPurpose::Catalog,
                None,
                1,
            ))
            .expect("fill exact owner capacity");
    }
    state = state
        .acquire_retired_shared_key_owner(retention_owner(
            RetiredKeyOwnerKind::Publication,
            1_u128.to_be_bytes(),
            KeyPurpose::Catalog,
            None,
            1,
        ))
        .expect("duplicate acquire remains legal at capacity");
    assert_eq!(
        state
            .retired_shared_keys()
            .expect("read full owner set")
            .into_iter()
            .find(|key| key.purpose == KeyPurpose::Catalog && key.epoch == 1)
            .expect("retired catalog")
            .retention_owners
            .len(),
        MAX_RETENTION_OWNERS_PER_KEY
    );
    assert!(matches!(
        state.acquire_retired_shared_key_owner(retention_owner(
            RetiredKeyOwnerKind::Publication,
            u128::try_from(MAX_RETENTION_OWNERS_PER_KEY + 1)
                .expect("overflow owner index")
                .to_be_bytes(),
            KeyPurpose::Catalog,
            None,
            1,
        )),
        Err(RuntimeStoreError::PairingLimit)
    ));
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
    let (first_install, first_response, first_recovery) = match first {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => (
            recovery.canonical_install_frame().to_vec(),
            recovery.canonical_response().to_vec(),
            recovery,
        ),
        other => panic!("first device must confirm: {other:?}"),
    };
    store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            first_recovery.pairing_id(),
            grant_committed_frame(&first_recovery),
        ))
        .await
        .expect("activate first authorization");
    complete_active_zero_cut_transition(&store).await;

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
        .plan_add_device(
            second_route,
            secret(0xe1),
            secret(0xe2),
            secret(0xe3),
            Vec::new(),
            NOW_MS,
        )
        .expect("atomically append second device to singleton")
        .into_state();
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
    let preparing = store
        .list_grant_preparing_recovery()
        .await
        .expect("list second grantPreparing recovery");
    assert_eq!(preparing.len(), 1);
    assert_eq!(preparing[0].pairing_id(), second_preparation.pairing_id());
    let committed = store
        .list_grant_committed_recovery()
        .await
        .expect("list first grantCommitted recovery");
    assert_eq!(committed.len(), 1);
    let recovered_first = committed
        .iter()
        .find(|item| item.pairing_id() == first_preparation.pairing_id())
        .expect("first device recovery survives second confirm");
    assert_eq!(
        agentdeck_protocol::relay_v2::encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::InstallGrant(InstallGrant {
                grant: recovered_first.relay_grant().clone(),
            }),
        }),
        first_install
    );
    assert_eq!(recovered_first.canonical_pair_response(), first_response);
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
            .expect("recover second grantPreparing after restart")
            .len(),
        1
    );
    assert_eq!(
        reopened
            .list_grant_committed_recovery()
            .await
            .expect("recover first grantCommitted after restart")
            .len(),
        1
    );
    reopened.shutdown().await.expect("shutdown reopened store");
}

async fn create_active_conversation_stream(
    store: &RuntimeStoreHandle,
    seed: u8,
) -> super::RuntimeId {
    let conversation_id =
        super::RuntimeId::from_bytes(super::RuntimeIdKind::Conversation, [seed; 16])
            .expect("conversation id");
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: super::RuntimeId::from_bytes(
                super::RuntimeIdKind::AdapterState,
                [seed.wrapping_add(1); 16],
            )
            .expect("adapter state key"),
            descriptor: ConversationDescriptor {
                agent_kind: agentdeck_protocol::AgentKind::Codex,
                title: Some(format!("ADGK2 conversation {seed}")),
                cwd: std::path::PathBuf::from(format!("/tmp/adgk2-{seed}")),
            },
        })
        .await
        .expect("create active conversation");
    conversation_id
}

fn grant_committed_frame(recovery: &super::pairing_grant_tx::GrantPreparingRecovery) -> Vec<u8> {
    agentdeck_protocol::relay_v2::encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: recovery.device_route(),
            grant_serial: recovery.grant_serial(),
            grant_hash: recovery.grant_hash(),
        }),
    })
}

pub(crate) async fn complete_active_zero_cut_transition(store: &RuntimeStoreHandle) {
    let recovery = store
        .load_active_key_transition()
        .await
        .expect("load active zero-cut transition")
        .expect("zero-cut transition exists");
    assert_eq!(recovery.transition.recipients.len(), 1);
    assert!(recovery.transition.cuts.is_empty());
    let operation_id = recovery.transition.operation_id;
    let recipient = recovery.transition.recipients[0];
    let key_revision = recovery.transition.to_revision;
    let device_route = DeviceRouteId::from_bytes(recipient.device_route);
    let global = store
        .load_global_key_state()
        .await
        .expect("load zero-cut global key state")
        .expect("zero-cut global key state exists");
    let updates = global
        .install_directory_view(device_route)
        .expect("render zero-cut exact key slots")
        .into_iter()
        .map(|view| KeyUpdateV1 {
            key_directory_revision: KeyDirectoryRevision::new(key_revision),
            key_id: KeyId {
                purpose: view.purpose,
                epoch: view.epoch,
            },
            device_route,
            stream_route: view.stream_route,
            enc: vec![0xa5; 32],
            wrapped_key: vec![0x5a; 48],
            signature: Ed25519Signature([0x7f; 64]),
        })
        .collect();
    let canonical_update_set = KeyUpdateSetV1 {
        key_directory_revision: KeyDirectoryRevision::new(key_revision),
        device_route,
        updates,
    }
    .canonical_bytes()
    .expect("encode canonical zero-cut key update fixture");
    store
        .mark_key_transition_rotated(operation_id)
        .await
        .expect("mark zero-cut transition rotated");
    store
        .freeze_key_updates(
            operation_id,
            vec![super::key_transition::FrozenKeyUpdate {
                recipient,
                key_revision,
                canonical_update_set: canonical_update_set.clone(),
            }],
        )
        .await
        .expect("freeze zero-cut transition update");
    store
        .freeze_key_barriers(operation_id, Vec::new())
        .await
        .expect("freeze empty old-audience barrier set");
    store
        .mark_key_barriers_committed(operation_id)
        .await
        .expect("commit empty old-audience barrier set");
    let persisted = store
        .load_active_key_transition()
        .await
        .expect("load zero-cut update before ACK")
        .expect("zero-cut transition remains active")
        .updates
        .into_iter()
        .find(|update| update.recipient == recipient)
        .expect("zero-cut target update exists");
    if persisted.lifecycle == super::key_transition::KeyUpdateLifecycle::Frozen {
        store
            .acknowledge_key_update(super::key_transition::AcknowledgeKeyUpdate {
                operation_id,
                recipient,
                key_revision,
                update_hash: super::key_transition::canonical_update_hash(&canonical_update_set)
                    .expect("hash test key update"),
                canonical_ack: b"test-key-update-ack".to_vec(),
                acknowledged_at_ms: 0,
            })
            .await
            .expect("ack zero-cut key update");
    } else {
        assert_eq!(
            persisted.lifecycle,
            super::key_transition::KeyUpdateLifecycle::Acked,
            "PairResponseReceived 可预先 Ack first-device bootstrap target"
        );
    }
    store
        .complete_key_transition(operation_id)
        .await
        .expect("complete zero-cut transition");
}

#[tokio::test]
async fn paired_conversation_create_atomically_stages_dek_and_activation_transition() {
    let root = TestRoot::new("grant-conversation-activation");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let fault = Arc::new(OneShotFault {
        operation: RuntimeStoreOperation::CreateConversationBeforeCommit,
        fired: AtomicBool::new(false),
    });
    let config = RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock))
        .with_fault_injector(fault);
    let store = RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open conversation activation store");
    let (binding, data_cert) = make_active(&store).await;
    let preparation = awaiting_pairing(&store, &binding, &data_cert).await;
    let confirmed = store
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect("confirm baseline paired device");
    let recovery = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("baseline device must confirm: {other:?}"),
    };
    store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            recovery.pairing_id(),
            grant_committed_frame(&recovery),
        ))
        .await
        .expect("activate baseline authorization");
    complete_active_zero_cut_transition(&store).await;

    let conversation_id =
        super::RuntimeId::from_bytes(super::RuntimeIdKind::Conversation, [0x51; 16])
            .expect("conversation id");
    let input = NewConversation {
        conversation_id,
        adapter_state_key: super::RuntimeId::from_bytes(
            super::RuntimeIdKind::AdapterState,
            [0x52; 16],
        )
        .expect("adapter state key"),
        descriptor: ConversationDescriptor {
            agent_kind: agentdeck_protocol::AgentKind::Codex,
            title: Some("ADGK2 activated conversation".to_owned()),
            cwd: std::path::PathBuf::from("/tmp/adgk2-activation"),
        },
    };
    let before_fault = artifact_bytes(&root.database());
    assert!(matches!(
        store.create_conversation(input.clone()).await,
        Err(RuntimeStoreError::WorkerStopped)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_fault);
    assert_eq!(
        store
            .load_global_key_state()
            .await
            .expect("load unchanged global state")
            .expect("paired global key state exists")
            .revision()
            .value(),
        1
    );
    assert!(
        store
            .load_active_key_transition()
            .await
            .expect("load rolled-back activation transition")
            .is_none()
    );
    store
        .create_conversation(input)
        .await
        .expect("retry atomic conversation activation");
    let global = store
        .load_global_key_state()
        .await
        .expect("load conversation global key state")
        .expect("paired global key state exists");
    assert_eq!(global.revision().value(), 2);
    let routes = global.active_conversation_routes();
    assert_eq!(routes.len(), 1);

    let transition = store
        .load_active_key_transition()
        .await
        .expect("load conversation activation transition")
        .expect("conversation activation transition exists");
    assert_eq!(
        transition.transition.operation,
        super::key_transition::KeyTransitionOperation::ActivateConversation
    );
    assert_eq!(transition.transition.from_revision, 1);
    assert_eq!(transition.transition.to_revision, 2);
    assert_eq!(transition.transition.recipients.len(), 1);
    assert_eq!(
        transition.transition.target,
        super::key_transition::KeyTransitionTarget::Conversation {
            conversation_id: *conversation_id.as_bytes(),
            stream_route: *routes[0].as_bytes(),
        }
    );

    let read = rusqlite::Connection::open(root.database())
        .expect("open publication mapping evidence database");
    let persisted_route: Vec<u8> = read
        .query_row(
            "SELECT stream_route FROM publication_streams\n             WHERE scope = 'conversation' AND conversation_id = ?1",
            [conversation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("read durable conversation publication mapping");
    assert_eq!(persisted_route, routes[0].as_bytes());
    drop(read);

    store.shutdown().await.expect("shutdown activation store");
}

#[tokio::test]
async fn add_member_rotates_two_production_conversations_and_aligns_active_authorizations() {
    let root = TestRoot::new("grant-add-member-adgk2");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let fault = Arc::new(ArmableConfirmFault {
        armed: AtomicBool::new(false),
    });
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
            .with_fault_injector(fault.clone())
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open ADGK2 add-member store");
    store
        .create_publication_stream(
            [0x21; 16],
            PublicationScope::Catalog,
            [0x22; 16],
            [0x23; 16],
        )
        .await
        .expect("create production catalog publication stream");
    let _first_conversation = create_active_conversation_stream(&store, 0x31).await;
    let _second_conversation = create_active_conversation_stream(&store, 0x41).await;
    let principal = PrincipalIssuer::local_only(
        store
            .machine_trust_domain()
            .expect("load catalog snapshot trust domain"),
    )
    .issue_verified_local(501, [0x24; 16])
    .expect("issue catalog snapshot principal");
    let catalog_provider = CatalogSnapshotProvider::with_clock(
        store.clone(),
        Arc::new(TestClock(clock.clone())),
        Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES)),
    )
    .expect("create production catalog snapshot provider");
    let mut catalog_registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(1).expect("catalog snapshot generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture exact catalog snapshot barrier");
    let catalog_page = catalog_provider
        .first_page(&mut catalog_registration, &principal)
        .await
        .expect("materialize production catalog snapshot");
    drop(catalog_page);
    drop(catalog_registration);
    drop(catalog_provider);
    let (binding, data_cert) = make_active(&store).await;

    let first_preparation = awaiting_pairing(&store, &binding, &data_cert).await;
    let first_fingerprint = sha256(&first_preparation.request().device_sign_pubkey.0);
    let active_conversation_routes = match store
        .load_grant_allocation(first_preparation.pairing_id(), first_fingerprint)
        .await
        .expect("load authenticated deferred conversation routes")
    {
        super::pairing_grant_allocation::GrantAllocationProjection::New {
            current_global_keys: None,
            active_conversation_routes,
            ..
        } => active_conversation_routes,
        _ => panic!("first grant must use a fresh allocation"),
    };
    assert_eq!(active_conversation_routes.len(), 2);
    let first_stream = active_conversation_routes[0];
    let second_stream = active_conversation_routes[1];
    let first_route = DeviceRouteId::from_bytes([0xd1; 16]);
    let first_global = GlobalKeyStateV1::bootstrap_with_conversations(
        1,
        1,
        secret(0xc1),
        first_route,
        1,
        secret(0xc2),
        1,
        secret(0xc3),
        vec![
            ConversationKeyRotation::new(first_stream, secret(0xc4)),
            ConversationKeyRotation::new(second_stream, secret(0xc5)),
        ],
    )
    .expect("bootstrap first global state with deferred conversation keys");
    let first = store
        .confirm_pairing_grant(grant_input_with(
            &first_preparation,
            &binding,
            &data_cert,
            first_route,
            GrantSerial::new(1),
            first_global,
            None,
            0xd2,
        ))
        .await
        .expect("confirm first device with production conversation keys");
    let first_recovery = match first {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("first device must confirm: {other:?}"),
    };
    store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            first_recovery.pairing_id(),
            grant_committed_frame(&first_recovery),
        ))
        .await
        .expect("activate first authorization");
    complete_active_membership_transition(&store, &clock).await;

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
        "grant-add-member-adgk2-second",
    )
    .await;
    let second_route = DeviceRouteId::from_bytes([0xd2; 16]);
    let next_global = store
        .load_global_key_state()
        .await
        .expect("load first global state")
        .expect("first global state exists")
        .plan_add_device(
            second_route,
            secret(0xe1),
            secret(0xe2),
            secret(0xe3),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0xe4)),
                ConversationKeyRotation::new(second_stream, secret(0xe5)),
            ],
            NOW_MS,
        )
        .expect("plan add over all active streams")
        .into_state();
    let before_fault = artifact_bytes(&root.database());
    fault.armed.store(true, Ordering::SeqCst);
    let error = store
        .confirm_pairing_grant(grant_input_with(
            &second_preparation,
            &binding,
            &data_cert,
            second_route,
            GrantSerial::new(1),
            next_global,
            None,
            0xe6,
        ))
        .await
        .expect_err("injected add-member transaction must roll back");
    assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
    assert_eq!(artifact_bytes(&root.database()), before_fault);

    let retry_global = store
        .load_global_key_state()
        .await
        .expect("load unchanged global state after rollback")
        .expect("first global state remains")
        .plan_add_device(
            second_route,
            secret(0xe1),
            secret(0xe2),
            secret(0xe3),
            vec![
                ConversationKeyRotation::new(first_stream, secret(0xe4)),
                ConversationKeyRotation::new(second_stream, secret(0xe5)),
            ],
            NOW_MS,
        )
        .expect("rebuild exact add plan after rollback")
        .into_state();
    store
        .confirm_pairing_grant(grant_input_with(
            &second_preparation,
            &binding,
            &data_cert,
            second_route,
            GrantSerial::new(1),
            retry_global,
            None,
            0xe6,
        ))
        .await
        .expect("retry second device with atomic shared-key rotation");

    let global = store
        .load_global_key_state()
        .await
        .expect("load rotated global state")
        .expect("rotated global state exists");
    assert_eq!(global.revision().value(), 2);
    assert_eq!(
        global
            .shared_key_epochs_for_test()
            .into_iter()
            .map(|(_, epoch)| epoch)
            .collect::<Vec<_>>(),
        vec![2, 2, 2]
    );
    let second_bootstrap = global
        .bootstrap_view(second_route)
        .expect("new device bootstrap");
    assert_eq!(
        second_bootstrap[0].epoch, 2,
        "new device only sees new catalog epoch"
    );
    store.shutdown().await.expect("shutdown ADGK2 store");

    let connection = rusqlite::Connection::open(root.database()).expect("open authorization DB");
    let revisions = connection
        .prepare(
            "SELECT lifecycle, key_directory_revision FROM remote_authorization_ledger
             ORDER BY device_route, grant_serial",
        )
        .expect("prepare revision evidence")
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("query revision evidence")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect revision evidence");
    assert_eq!(
        revisions,
        vec![
            ("active".to_owned(), "00000000000000000002".to_owned()),
            (
                "grantPreparing".to_owned(),
                "00000000000000000002".to_owned()
            ),
        ]
    );
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
