#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_cli::remote::key_sync::{
    DurableKeySyncStateV1, FrozenKeySyncSendV1, KeySyncUpdateSetHandoff,
    SignedHigherRevisionObservationV1,
};
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage, PairedPromotionCoordinator,
};
use agentdeck_crypto::{
    HpkeEnvelopeV1, HpkePrivateKey, HpkePublicKey, hpke_seal_base, sign_key_update,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, KeyUpdateInfoV1, KeyUpdateSetV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, SignedSealedBlobV1,
    StreamBindingV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::{SealedBlob, Send};
use agentdeck_protocol::relay_v2::{
    Ed25519Signature, GrantSerial, KeyDirectoryRevision, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RequestRouteId, StreamGenerationId, StreamRouteId, TrustEpoch, encode,
};
use agentdeck_protocol::runtime::{
    ConversationId, RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, StreamCursor,
};

use remote_pairing::{
    CATALOG_EPOCH, CONVERSATION_EPOCH, DEVICE_COMMAND_EPOCH, DEVICE_COMMAND_KEY,
    DEVICE_REPLY_EPOCH, DEVICE_REPLY_KEY, DeterministicRng, INSTALLATION_ID,
    KEY_DIRECTORY_REVISION, NOW_MS, PairingFixture, PanicRng,
};

const STARTED_AT_MS: u64 = 1_000_000;
const CATALOG_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const CONVERSATION_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x82; 16]);
const CONVERSATION_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x92; 16]);
const OTHER_CONVERSATION_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x83; 16]);

struct NoopMutationObserver;

impl PairedMutationObserver for NoopMutationObserver {
    fn after_stage(&self, _stage: PairedMutationStage) {}
}

struct PanicOnceAtStage {
    stage: PairedMutationStage,
    fired: AtomicBool,
}

impl PairedMutationObserver for PanicOnceAtStage {
    fn after_stage(&self, stage: PairedMutationStage) {
        if stage == self.stage && !self.fired.swap(true, Ordering::SeqCst) {
            panic!("injected combined install crash at {stage:?}");
        }
    }
}

fn file_tree_bytes(root: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut snapshot = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return snapshot;
    };
    for entry in entries {
        let path = entry.expect("read combined install tree").path();
        if path.is_dir() {
            snapshot.extend(file_tree_bytes(&path));
        } else if path.is_file() {
            snapshot.push((
                path.clone(),
                fs::read(path).expect("snapshot durable combined bytes"),
            ));
        }
    }
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    snapshot
}

#[derive(Debug, Eq, PartialEq)]
struct DurableSnapshot {
    sealed_state_files: Vec<(std::path::PathBuf, Vec<u8>)>,
    paired_keychain_accounts: Vec<(PairedRemoteKeyPurpose, Option<Vec<u8>>)>,
}

fn paired_keychain_accounts(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
) -> Vec<(PairedRemoteKeyPurpose, Option<Vec<u8>>)> {
    let identity = fixture.identity();
    [
        PairedRemoteKeyPurpose::DeviceSignPrivateKey,
        PairedRemoteKeyPurpose::DeviceHpkePrivateKey,
        PairedRemoteKeyPurpose::DeviceGrant,
        PairedRemoteKeyPurpose::DeviceStorageKek,
        PairedRemoteKeyPurpose::CounterGuard,
        PairedRemoteKeyPurpose::CommitMarker,
    ]
    .into_iter()
    .map(|purpose| {
        let account = RemoteKeyAccount::paired(
            INSTALLATION_ID,
            identity.machine_root_fingerprint(),
            identity.machine_route(),
            purpose,
        );
        let value = store
            .load(&account)
            .expect("snapshot paired Keychain account")
            .map(|secret| secret.expose_secret().to_vec());
        (purpose, value)
    })
    .collect()
}

fn durable_snapshot(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
    state_root: &Path,
) -> DurableSnapshot {
    DurableSnapshot {
        sealed_state_files: file_tree_bytes(state_root),
        paired_keychain_accounts: paired_keychain_accounts(fixture, store),
    }
}

fn assert_rejection_preserves_durable_state(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
    state_root: &Path,
    case: &str,
    reject: impl FnOnce() -> bool,
) {
    let before = durable_snapshot(fixture, store, state_root);
    assert!(
        before
            .paired_keychain_accounts
            .iter()
            .all(|(_, value)| value.is_some()),
        "{case} baseline must contain all six paired Keychain accounts"
    );
    assert!(reject(), "{case} must be rejected");
    let after = durable_snapshot(fixture, store, state_root);
    assert_eq!(
        after.sealed_state_files, before.sealed_state_files,
        "{case} must not rewrite any sealed-state artifact"
    );
    assert_eq!(
        after.paired_keychain_accounts, before.paired_keychain_accounts,
        "{case} must not rewrite any paired Keychain account"
    );
}

fn promote_with_device_hpke(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
    state_root: &Path,
    seed: u8,
) -> HpkePublicKey {
    use agentdeck_cli::remote::pending::PendingPairingCoordinator;

    let pending = PendingPairingCoordinator::new(store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([seed; 32]);
    let prepared = pending
        .prepare(
            fixture.invite(),
            fixture.authorization(),
            NOW_MS,
            &mut request_rng,
        )
        .expect("prepare PairRequest");
    let recipient = HpkePublicKey::from_bytes(&prepared.device_hpke_public_key())
        .expect("generated DeviceHPKE public key");
    let response = fixture.response_for(&prepared, [seed.wrapping_add(1); 32]);
    drop(prepared);
    let verified = pending
        .verify_response(
            fixture.invite(),
            fixture.authorization(),
            NOW_MS + 1,
            &response,
        )
        .expect("verify PairResponse");
    let mut promotion_rng = DeterministicRng::new([seed.wrapping_add(2); 32]);
    PairedPromotionCoordinator::new(store, INSTALLATION_ID, state_root)
        .promote(verified, &mut promotion_rng)
        .expect("promote paired fixture");
    recipient
}

fn binding(
    fixture: &PairingFixture,
    purpose: KeyPurpose,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
) -> StreamBindingV1 {
    let (key_epoch, inner_cursor) = match purpose {
        KeyPurpose::Catalog => (
            CATALOG_EPOCH,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(3),
            },
        ),
        KeyPurpose::ConversationDek => (
            CONVERSATION_EPOCH,
            RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new("018f0f9d-6f0a-7ad0-8000-000000000082"),
                cursor: StreamCursor::At(11),
            },
        ),
        KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => unreachable!(),
    };
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        stream_route,
        stream_generation,
        stream_cursor: StreamCursor::At(5),
        inner_cursor,
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose,
            epoch: key_epoch,
        },
    }
}

fn initial_key_sync(fixture: &PairingFixture) -> DurableKeySyncStateV1 {
    let observation = SignedHigherRevisionObservationV1::new(
        fixture.machine_route(),
        fixture.device_route(),
        GrantSerial::new(7),
        TrustEpoch::new(2),
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION + 1),
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH + 1,
        },
        None,
        CATALOG_ROUTE,
        CATALOG_GENERATION,
        17,
        23,
        [0x44; 32],
        [0x55; 32],
    )
    .expect("valid higher-revision observation");
    let request = observation.request_for_attempt(1).expect("first request");
    let blob: SignedSealedBlobV1 = UnsignedSealedBlobV1::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: DEVICE_COMMAND_EPOCH,
        },
        DEVICE_COMMAND_EPOCH,
        request.requested_key_directory_revision.value(),
        [0x71; 12],
        vec![0x71; 16],
    )
    .attach_signature(Ed25519Signature([0x71; 64]));
    let request_route = RequestRouteId::from_bytes([0x71; 16]);
    let frame = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(Send {
            device_route: request.device_route,
            request_route,
            sealed_blob: SealedBlob(blob.to_wire_bytes()),
        }),
    };
    DurableKeySyncStateV1::start(
        observation,
        STARTED_AT_MS,
        FrozenKeySyncSendV1::new(request, encode(&frame)).expect("freeze KeySync send"),
    )
    .expect("start KeySync")
}

fn key_update_context(info: &KeyUpdateInfoV1) -> OuterContextV1 {
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

#[allow(clippy::too_many_arguments)]
fn signed_update(
    fixture: &PairingFixture,
    recipient: &HpkePublicKey,
    purpose: KeyPurpose,
    stream_route: Option<StreamRouteId>,
    epoch: u64,
    key: [u8; 32],
    seed: u8,
) -> KeyUpdateV1 {
    let revision = KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION + 1);
    let info = KeyUpdateInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: fixture.invite().relay_server_id,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        stream_route,
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        key_directory_revision: revision,
        key_purpose: purpose,
        key_epoch: epoch,
    };
    let context = key_update_context(&info);
    let mut rng = DeterministicRng::new([seed; 32]);
    let HpkeEnvelopeV1 { enc, ciphertext } = hpke_seal_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &key,
        &mut rng,
    )
    .expect("seal KeyUpdate");
    let unsigned = KeyUpdateV1 {
        key_directory_revision: revision,
        key_id: KeyId { purpose, epoch },
        device_route: fixture.device_route(),
        stream_route,
        enc,
        wrapped_key: ciphertext,
        signature: Ed25519Signature([0; 64]),
    };
    let signer = MachineDataSignerBindingV1::from_certificate(&fixture.invite().data_sign_cert)
        .expect("valid MachineData signer binding");
    sign_key_update(
        &PairingFixture::machine_data_signing_key(),
        &signer,
        &info,
        &context,
        unsigned,
    )
    .expect("sign KeyUpdate")
}

fn mixed_update_set(fixture: &PairingFixture, recipient: &HpkePublicKey) -> KeyUpdateSetV1 {
    let set = KeyUpdateSetV1 {
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION + 1),
        device_route: fixture.device_route(),
        updates: vec![
            signed_update(
                fixture,
                recipient,
                KeyPurpose::Catalog,
                None,
                CATALOG_EPOCH + 1,
                [0x81; 32],
                0x41,
            ),
            signed_update(
                fixture,
                recipient,
                KeyPurpose::ConversationDek,
                Some(CONVERSATION_ROUTE),
                CONVERSATION_EPOCH,
                [0x74; 32],
                0x42,
            ),
            signed_update(
                fixture,
                recipient,
                KeyPurpose::DeviceCommandTx,
                None,
                DEVICE_COMMAND_EPOCH,
                DEVICE_COMMAND_KEY,
                0x43,
            ),
            signed_update(
                fixture,
                recipient,
                KeyPurpose::DeviceReplyTx,
                None,
                DEVICE_REPLY_EPOCH,
                DEVICE_REPLY_KEY,
                0x44,
            ),
        ],
    };
    set.validate().expect("valid mixed UpdateSet");
    set
}

fn handoff(state: &DurableKeySyncStateV1, set: KeyUpdateSetV1) -> KeySyncUpdateSetHandoff {
    let request_route = state
        .active_send()
        .expect("active KeySync send")
        .request_route();
    state
        .clone()
        .into_update_set_handoff(STARTED_AT_MS + 1_000, request_route, set)
        .expect("authenticated UpdateSet handoff")
}

fn install_v4_baseline(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
    state_root: &Path,
    seed: u8,
    install_conversation: bool,
) -> (HpkePublicKey, DurableKeySyncStateV1) {
    let recipient = promote_with_device_hpke(fixture, store, state_root, seed);
    let paired = PairedMachineStore::new_with_mutation_observer(
        store,
        INSTALLATION_ID,
        state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open V1 baseline");
    let mut bindings = vec![binding(
        fixture,
        KeyPurpose::Catalog,
        CATALOG_ROUTE,
        CATALOG_GENERATION,
    )];
    if install_conversation {
        bindings.push(binding(
            fixture,
            KeyPurpose::ConversationDek,
            CONVERSATION_ROUTE,
            CONVERSATION_GENERATION,
        ));
    }
    for (index, binding) in bindings.into_iter().enumerate() {
        let mut rng = DeterministicRng::new([seed.wrapping_add(3 + index as u8); 32]);
        opened
            .install_stream_binding_for_automatic_harness(binding, &mut rng)
            .expect("install stream binding");
    }
    let key_sync = initial_key_sync(fixture);
    let mut rng = DeterministicRng::new([seed.wrapping_add(5); 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(None, Some(&key_sync), &mut rng)
        .expect("install active ADKS");
    (recipient, key_sync)
}

fn assert_prepare_case_rejected(
    case: &str,
    seed: u8,
    build_set: impl FnOnce(&PairingFixture, &HpkePublicKey) -> KeyUpdateSetV1,
) {
    let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_ROUTE);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("rejected combined install root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical rejected combined install root")
        .join(format!("paired-state-{seed:02x}"));
    let (recipient, key_sync) = install_v4_baseline(&fixture, &store, &state_root, seed, true);
    let set = build_set(&fixture, &recipient);
    set.validate()
        .expect("rejection fixture must be a wire-canonical UpdateSet");
    let handoff = handoff(&key_sync, set);

    assert_rejection_preserves_durable_state(&fixture, &store, &state_root, case, || {
        let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        let opened = paired
            .open_exact(fixture.identity())
            .expect("open rejected combined install baseline");
        opened
            .prepare_key_update_install(handoff, STARTED_AT_MS + 2_000)
            .is_err()
    });
}

#[test]
fn v4_to_v5_combined_install_is_atomic_and_committed_retry_mints_exact_ack() {
    let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_ROUTE);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("combined install root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical combined install root")
        .join("paired-state");
    let (recipient, key_sync) = install_v4_baseline(&fixture, &store, &state_root, 0x31, true);
    let set = mixed_update_set(&fixture, &recipient);
    let handoff = handoff(&key_sync, set.clone());

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open combined install baseline");
    let before_bindings = opened.durable_stream_bindings().expect("baseline bindings");
    let prepared = opened
        .prepare_key_update_install(handoff.clone(), STARTED_AT_MS + 2_000)
        .expect("prepare combined candidate");
    let mut rng = DeterministicRng::new([0x51; 32]);
    let committed = opened
        .commit_key_update_install(prepared, &mut rng)
        .expect("commit combined candidate");
    assert!(!committed.already_committed());
    assert_eq!(
        committed.ack().key_directory_revision.value(),
        KEY_DIRECTORY_REVISION + 1
    );
    assert_eq!(
        committed.ack().update_set_sha256,
        set.canonical_sha256().expect("UpdateSet hash")
    );
    assert_eq!(committed.ack_basis().attempt(), 1);
    assert_eq!(
        committed.ack_basis().source_request_route(),
        handoff.request_route()
    );

    let generation = opened
        .durable_key_generation_state()
        .expect("read ADKG")
        .expect("V5 ADKG");
    assert_eq!(
        generation.effective_directory_revision().value(),
        KEY_DIRECTORY_REVISION + 1
    );
    assert!(
        generation
            .find_slot(KeyPurpose::Catalog, None)
            .expect("catalog slot")
            .staged()
            .is_some(),
        "catalog rotation must remain staged until EpochBarrier"
    );
    assert!(
        generation
            .find_slot(KeyPurpose::ConversationDek, Some(CONVERSATION_ROUTE))
            .expect("conversation slot")
            .staged()
            .is_none(),
        "same-epoch conversation rewrap replaces current"
    );
    let after_bindings = opened
        .durable_stream_bindings()
        .expect("installed bindings");
    assert_eq!(after_bindings.len(), before_bindings.len());
    let before_catalog = before_bindings
        .iter()
        .find(|binding| binding.binding().key_id.purpose == KeyPurpose::Catalog)
        .expect("baseline catalog binding");
    let after_catalog = after_bindings
        .iter()
        .find(|binding| binding.binding().key_id.purpose == KeyPurpose::Catalog)
        .expect("installed catalog binding");
    assert_eq!(
        after_catalog, before_catalog,
        "rotation binding must remain exact"
    );
    let before_conversation = before_bindings
        .iter()
        .find(|binding| binding.binding().key_id.purpose == KeyPurpose::ConversationDek)
        .expect("baseline conversation binding");
    let after_conversation = after_bindings
        .iter()
        .find(|binding| binding.binding().key_id.purpose == KeyPurpose::ConversationDek)
        .expect("installed conversation binding");
    assert_eq!(
        after_conversation.binding().key_directory_revision.value(),
        KEY_DIRECTORY_REVISION + 1
    );
    assert_eq!(
        after_conversation.outer_applied(),
        before_conversation.outer_applied()
    );
    assert_eq!(
        after_conversation.outer_acked(),
        before_conversation.outer_acked()
    );
    assert_eq!(
        after_conversation.inner_observed(),
        before_conversation.inner_observed()
    );
    assert_eq!(
        after_conversation.inner_applied(),
        before_conversation.inner_applied()
    );

    let prepared_retry = opened
        .prepare_key_update_install(handoff, u64::MAX)
        .expect("deadline-independent committed retry");
    let committed_retry = opened
        .commit_key_update_install(prepared_retry, &mut PanicRng)
        .expect("committed retry consumes no entropy");
    assert!(committed_retry.already_committed());
    assert_eq!(committed_retry.ack(), committed.ack());
}

#[test]
fn combined_install_rejects_wrong_roster_without_any_durable_write() {
    assert_prepare_case_rejected("wrong roster", 0x81, |fixture, recipient| {
        let mut set = mixed_update_set(fixture, recipient);
        set.updates[1] = signed_update(
            fixture,
            recipient,
            KeyPurpose::ConversationDek,
            Some(OTHER_CONVERSATION_ROUTE),
            1,
            [0x84; 32],
            0x91,
        );
        set
    });
}

#[test]
fn combined_install_rejects_bad_machine_data_signature_without_any_durable_write() {
    assert_prepare_case_rejected(
        "bad MachineDataSign signature",
        0x82,
        |fixture, recipient| {
            let mut set = mixed_update_set(fixture, recipient);
            set.updates[0].signature.0[0] ^= 0x80;
            set
        },
    );
}

#[test]
fn combined_install_rejects_wrong_hpke_recipient_without_any_durable_write() {
    assert_prepare_case_rejected("wrong HPKE recipient", 0x83, |fixture, recipient| {
        let mut set = mixed_update_set(fixture, recipient);
        let (_wrong_private, wrong_recipient) = HpkePrivateKey::derive_keypair(&[0xa5; 32]);
        set.updates[0] = signed_update(
            fixture,
            &wrong_recipient,
            KeyPurpose::Catalog,
            None,
            CATALOG_EPOCH + 1,
            [0x81; 32],
            0x92,
        );
        set
    });
}

#[test]
fn combined_install_rejects_same_epoch_replacement_with_different_raw_key_without_writes() {
    assert_prepare_case_rejected(
        "same-epoch replacement with a different raw key",
        0x84,
        |fixture, recipient| {
            let mut set = mixed_update_set(fixture, recipient);
            set.updates[1] = signed_update(
                fixture,
                recipient,
                KeyPurpose::ConversationDek,
                Some(CONVERSATION_ROUTE),
                CONVERSATION_EPOCH,
                [0x99; 32],
                0x93,
            );
            set
        },
    );
}

#[test]
fn combined_install_rejects_rotation_that_reuses_old_raw_key_without_any_durable_write() {
    assert_prepare_case_rejected(
        "epoch+1 rotation reusing the old raw key",
        0x85,
        |fixture, recipient| {
            let mut set = mixed_update_set(fixture, recipient);
            set.updates[0] = signed_update(
                fixture,
                recipient,
                KeyPurpose::Catalog,
                None,
                CATALOG_EPOCH + 1,
                [0x71; 32],
                0x94,
            );
            set
        },
    );
}

#[test]
fn combined_install_rejects_observation_epoch_mismatch_without_any_durable_write() {
    assert_prepare_case_rejected(
        "observation key epoch mismatching the UpdateSet replacement",
        0x86,
        |fixture, recipient| {
            let mut set = mixed_update_set(fixture, recipient);
            set.updates[0] = signed_update(
                fixture,
                recipient,
                KeyPurpose::Catalog,
                None,
                CATALOG_EPOCH,
                [0x71; 32],
                0x95,
            );
            set
        },
    );
}

#[test]
fn key_sync_rejects_revision_mismatch_without_any_durable_write() {
    let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_ROUTE);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("revision mismatch root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical revision mismatch root")
        .join("paired-state");
    let (recipient, key_sync) = install_v4_baseline(&fixture, &store, &state_root, 0x87, true);
    let mut set = mixed_update_set(&fixture, &recipient);
    let wrong_revision = KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION + 2);
    set.key_directory_revision = wrong_revision;
    for update in &mut set.updates {
        update.key_directory_revision = wrong_revision;
    }
    set.validate()
        .expect("revision mismatch fixture remains wire-canonical");
    let request_route = key_sync
        .active_send()
        .expect("active KeySync send")
        .request_route();

    assert_rejection_preserves_durable_state(
        &fixture,
        &store,
        &state_root,
        "requested revision mismatch",
        || {
            key_sync
                .into_update_set_handoff(STARTED_AT_MS + 1_000, request_route, set)
                .is_err()
        },
    );
}

#[test]
fn combined_install_accepts_exactly_one_new_epoch_one_conversation_without_binding_invention() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("single conversation add root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical single conversation add root")
        .join("paired-state");
    let (recipient, key_sync) = install_v4_baseline(&fixture, &store, &state_root, 0x88, false);
    let mut set = mixed_update_set(&fixture, &recipient);
    set.updates[1] = signed_update(
        &fixture,
        &recipient,
        KeyPurpose::ConversationDek,
        Some(CONVERSATION_ROUTE),
        1,
        [0x84; 32],
        0x96,
    );
    set.validate()
        .expect("single epoch-1 conversation addition is wire-canonical");
    let handoff = handoff(&key_sync, set);

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open single conversation add baseline");
    assert!(
        opened
            .durable_stream_bindings()
            .expect("baseline bindings")
            .iter()
            .all(|binding| binding.binding().key_id.purpose != KeyPurpose::ConversationDek),
        "the baseline must not already contain a conversation binding"
    );
    let prepared = opened
        .prepare_key_update_install(handoff, STARTED_AT_MS + 2_000)
        .expect("prepare one conversation addition");
    let mut rng = DeterministicRng::new([0xa6; 32]);
    let committed = opened
        .commit_key_update_install(prepared, &mut rng)
        .expect("commit one conversation addition");
    assert!(!committed.already_committed());

    let generation = opened
        .durable_key_generation_state()
        .expect("read ADKG after conversation addition")
        .expect("V5 ADKG after conversation addition");
    let conversation = generation
        .find_slot(KeyPurpose::ConversationDek, Some(CONVERSATION_ROUTE))
        .expect("new conversation slot");
    assert_eq!(conversation.current().key_id().epoch, 1);
    assert!(conversation.staged().is_none());
    assert!(conversation.retired().is_empty());
    assert!(
        opened
            .durable_stream_bindings()
            .expect("bindings after conversation addition")
            .iter()
            .all(|binding| binding.binding().key_id.purpose != KeyPurpose::ConversationDek),
        "UpdateSet inventory must not invent a stream binding before publication"
    );
}

#[test]
fn every_combined_state_transaction_crash_cut_recovers_only_complete_old_or_new_tuple() {
    for (index, stage) in [
        PairedMutationStage::StateStageDurable,
        PairedMutationStage::StateGuardPendingDurable,
        PairedMutationStage::StateActiveDurable,
        PairedMutationStage::StateGuardStableDurable,
        PairedMutationStage::StateStageCleared,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_ROUTE);
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("combined crash root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical combined crash root")
            .join(format!("paired-state-{index}"));
        let seed = 0x61 + u8::try_from(index).expect("bounded crash index") * 5;
        let (recipient, key_sync) = install_v4_baseline(&fixture, &store, &state_root, seed, true);
        let set = mixed_update_set(&fixture, &recipient);
        let handoff = handoff(&key_sync, set.clone());

        let observer = Arc::new(PanicOnceAtStage {
            stage,
            fired: AtomicBool::new(false),
        });
        let crashing = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            observer.clone(),
        );
        let mut opened = crashing
            .open_exact(fixture.identity())
            .expect("open combined crash candidate");
        let prepared = opened
            .prepare_key_update_install(handoff, STARTED_AT_MS + 2_000)
            .expect("prepare combined crash candidate");
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let mut rng = DeterministicRng::new([seed.wrapping_add(4); 32]);
            opened
                .commit_key_update_install(prepared, &mut rng)
                .expect("observer must terminate combined install");
        }));
        assert!(crashed.is_err(), "{stage:?} must inject process death");
        assert!(observer.fired.load(Ordering::SeqCst), "{stage:?}");
        drop(opened);

        let reader = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        let before_list = file_tree_bytes(&state_root);
        assert_eq!(
            reader
                .list()
                .expect("list audits active and prepared combined tuple")
                .len(),
            1,
            "{stage:?}"
        );
        assert_eq!(
            file_tree_bytes(&state_root),
            before_list,
            "list must not recover or rewrite at {stage:?}"
        );

        let reopened = reader
            .open_exact(fixture.identity())
            .expect("recover combined install crash cut");
        let recovered_sync = reopened
            .durable_key_sync_state()
            .expect("read recovered ADKS")
            .expect("active ADKS remains present");
        let recovered_generation = reopened
            .durable_key_generation_state()
            .expect("read recovered ADKG");
        let bindings = reopened
            .durable_stream_bindings()
            .expect("read recovered bindings");
        let catalog_revision = bindings
            .iter()
            .find(|binding| binding.binding().key_id.purpose == KeyPurpose::Catalog)
            .expect("catalog binding")
            .binding()
            .key_directory_revision
            .value();
        let conversation_revision = bindings
            .iter()
            .find(|binding| binding.binding().key_id.purpose == KeyPurpose::ConversationDek)
            .expect("conversation binding")
            .binding()
            .key_directory_revision
            .value();

        if stage == PairedMutationStage::StateStageDurable {
            assert!(
                recovered_sync.latest_completed_ack_basis().is_none(),
                "{stage:?}"
            );
            assert!(recovered_generation.is_none(), "{stage:?}");
            assert_eq!(catalog_revision, KEY_DIRECTORY_REVISION, "{stage:?}");
            assert_eq!(conversation_revision, KEY_DIRECTORY_REVISION, "{stage:?}");
        } else {
            let basis = recovered_sync
                .latest_completed_ack_basis()
                .expect("new tuple has ACK basis");
            assert_eq!(
                basis.update_set_sha256(),
                set.canonical_sha256().unwrap(),
                "{stage:?}"
            );
            let generation = recovered_generation.expect("new tuple has ADKG");
            assert_eq!(
                generation.effective_directory_revision().value(),
                KEY_DIRECTORY_REVISION + 1,
                "{stage:?}"
            );
            assert_eq!(catalog_revision, KEY_DIRECTORY_REVISION, "{stage:?}");
            assert_eq!(
                conversation_revision,
                KEY_DIRECTORY_REVISION + 1,
                "{stage:?}"
            );
        }
    }
}
