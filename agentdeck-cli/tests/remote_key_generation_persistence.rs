#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentdeck_cli::remote::crypto_state::{
    CryptoStateIdentity, DeviceStorageKek, FileCryptoStateStore,
};
use agentdeck_cli::remote::key_generation::{
    DurableKeyGenerationStateV1, DurableKeyGenerationV1, DurableKeySlotV1, KeySlotIdentityV1,
};
use agentdeck_cli::remote::key_sync::{
    DurableKeySyncStateV1, FrozenKeySyncSendV1, SignedHigherRevisionObservationV1,
};
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage, PairedPromotionCoordinator,
};
use agentdeck_cli::remote::pending::PendingPairingCoordinator;
use agentdeck_crypto::{
    HpkeEnvelopeV1, HpkePrivateKey, HpkePublicKey, hpke_seal_base, sign_key_update,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, KeyUpdateInfoV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, StreamBindingV1,
    UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::{SealedBlob, Send};
use agentdeck_protocol::relay_v2::{
    Ed25519Signature, GrantSerial, KeyDirectoryRevision, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RequestRouteId, StreamGenerationId, StreamRouteId, TrustEpoch, encode,
};
use agentdeck_protocol::runtime::{RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, StreamCursor};

use remote_pairing::{
    CATALOG_EPOCH, DEVICE_COMMAND_EPOCH, DEVICE_COMMAND_KEY, DEVICE_REPLY_EPOCH, DEVICE_REPLY_KEY,
    DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION, NOW_MS, PairingFixture, PanicRng,
};

const ADPS_HEADER_LEN: usize = 12;
const CATALOG_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);

struct NoopMutationObserver;

impl PairedMutationObserver for NoopMutationObserver {
    fn after_stage(&self, _stage: PairedMutationStage) {}
}

#[derive(Clone, Copy)]
enum InventoryFault {
    None,
    DirectedRaw,
    BadBootstrap,
    BadSignature,
    WrongHpke,
}

fn file_tree_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut snapshot = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return snapshot;
    };
    for entry in entries {
        let path = entry.expect("read key-generation fixture tree").path();
        if path.is_dir() {
            snapshot.extend(file_tree_bytes(&path));
        } else if path.is_file() {
            snapshot.push((
                path.clone(),
                fs::read(path).expect("snapshot durable bytes"),
            ));
        }
    }
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    snapshot
}

fn paired_key_bytes(
    store: &dyn RemoteKeyStore,
    fixture: &PairingFixture,
) -> Vec<(PairedRemoteKeyPurpose, Vec<u8>)> {
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
            fixture.identity().machine_root_fingerprint(),
            fixture.machine_route(),
            purpose,
        );
        let bytes = store
            .load(&account)
            .expect("snapshot paired key")
            .expect("paired key exists")
            .expose_secret()
            .to_vec();
        (purpose, bytes)
    })
    .collect()
}

fn paired_state_plaintext(
    store: &dyn RemoteKeyStore,
    fixture: &PairingFixture,
    state_root: &Path,
) -> Vec<u8> {
    let account = RemoteKeyAccount::paired(
        INSTALLATION_ID,
        fixture.identity().machine_root_fingerprint(),
        fixture.machine_route(),
        PairedRemoteKeyPurpose::DeviceStorageKek,
    );
    let record = store
        .load(&account)
        .expect("load StorageKEK")
        .expect("StorageKEK exists");
    let kek = record.expose_secret()[40..72]
        .try_into()
        .expect("paired StorageKEK bytes");
    FileCryptoStateStore::new_in(
        state_root,
        CryptoStateIdentity::new(
            INSTALLATION_ID,
            fixture.identity().machine_root_fingerprint(),
            fixture.machine_route(),
        ),
        DeviceStorageKek::new(kek),
    )
    .expect("open state inspector")
    .load()
    .expect("load paired state")
    .expect("paired state exists")
    .expose_secret()
    .to_vec()
}

fn promote_with_device_hpke(
    fixture: &PairingFixture,
    store: &dyn RemoteKeyStore,
    state_root: &Path,
    seed: u8,
) -> HpkePublicKey {
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

fn catalog_binding(fixture: &PairingFixture) -> StreamBindingV1 {
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        stream_route: CATALOG_ROUTE,
        stream_generation: CATALOG_GENERATION,
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
    }
}

fn key_sync_state(fixture: &PairingFixture) -> DurableKeySyncStateV1 {
    let observation = SignedHigherRevisionObservationV1::new(
        fixture.machine_route(),
        fixture.device_route(),
        GrantSerial::new(7),
        TrustEpoch::new(2),
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION + 3),
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
    let blob = UnsignedSealedBlobV1::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: 4,
        },
        4,
        request.requested_key_directory_revision.value(),
        [0x71; 12],
        vec![0x71; 16],
    )
    .attach_signature(Ed25519Signature([0x71; 64]));
    let frame = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(Send {
            device_route: request.device_route,
            request_route: RequestRouteId::from_bytes([0x71; 16]),
            sealed_blob: SealedBlob(blob.to_wire_bytes()),
        }),
    };
    let frozen = FrozenKeySyncSendV1::new(request, encode(&frame)).expect("freeze KeySync Send");
    DurableKeySyncStateV1::start(observation, 1_000_000, frozen)
        .expect("start durable KeySync state")
}

fn prepare_v6_with_empty_adks(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
    state_root: &Path,
    seed: u8,
) -> HpkePublicKey {
    let recipient = promote_with_device_hpke(fixture, store, state_root, seed);
    let paired = PairedMachineStore::new_with_mutation_observer(
        store,
        INSTALLATION_ID,
        state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open paired state");
    let mut binding_rng = DeterministicRng::new([seed.wrapping_add(3); 32]);
    opened
        .install_stream_binding_for_automatic_harness(catalog_binding(fixture), &mut binding_rng)
        .expect("install the first typed stream binding");
    let key_sync = key_sync_state(fixture);
    let mut install_rng = DeterministicRng::new([seed.wrapping_add(4); 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(
            None,
            Some(&key_sync),
            &mut install_rng,
        )
        .expect("install ADKS in current V6");
    let mut clear_rng = DeterministicRng::new([seed.wrapping_add(5); 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(
            Some(&key_sync),
            None,
            &mut clear_rng,
        )
        .expect("leave current V6 with empty ADKS");
    drop(opened);
    assert_eq!(
        u16::from_be_bytes(
            paired_state_plaintext(store, fixture, state_root)[4..6]
                .try_into()
                .unwrap()
        ),
        6
    );
    recipient
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
    epoch: u64,
    revision: u64,
    key: [u8; 32],
    seed: u8,
) -> KeyUpdateV1 {
    let info = KeyUpdateInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: fixture.invite().relay_server_id,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        stream_route: None,
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        key_directory_revision: KeyDirectoryRevision::new(revision),
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
        key_directory_revision: KeyDirectoryRevision::new(revision),
        key_id: KeyId { purpose, epoch },
        device_route: fixture.device_route(),
        stream_route: None,
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

fn generation_state(
    fixture: &PairingFixture,
    recipient: &HpkePublicKey,
    fault: InventoryFault,
) -> DurableKeyGenerationStateV1 {
    let catalog_epoch = if matches!(fault, InventoryFault::BadBootstrap) {
        CATALOG_EPOCH + 10
    } else {
        CATALOG_EPOCH
    };
    let wrong_recipient = HpkePrivateKey::derive_keypair(&[0xa7; 32]).1;
    let catalog_recipient = if matches!(fault, InventoryFault::WrongHpke) {
        &wrong_recipient
    } else {
        recipient
    };
    let mut catalog_update = signed_update(
        fixture,
        catalog_recipient,
        KeyPurpose::Catalog,
        catalog_epoch + 1,
        KEY_DIRECTORY_REVISION + 1,
        [0x81; 32],
        0x41,
    );
    if matches!(fault, InventoryFault::BadSignature) {
        catalog_update.signature.0[0] ^= 1;
    }
    let catalog_identity = KeySlotIdentityV1::new(KeyPurpose::Catalog, None).unwrap();
    let catalog = DurableKeySlotV1::new(
        catalog_identity,
        DurableKeyGenerationV1::from_bootstrap_entry(
            KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
            KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: catalog_epoch,
            },
            None,
            fixture.device_route(),
        )
        .unwrap(),
        Some(DurableKeyGenerationV1::from_update(catalog_update).unwrap()),
        Vec::new(),
    )
    .unwrap();
    let command_key = if matches!(fault, InventoryFault::DirectedRaw) {
        [0x99; 32]
    } else {
        DEVICE_COMMAND_KEY
    };
    let directed = |purpose, epoch, key, seed| {
        DurableKeySlotV1::new(
            KeySlotIdentityV1::new(purpose, None).unwrap(),
            DurableKeyGenerationV1::from_update(signed_update(
                fixture,
                recipient,
                purpose,
                epoch,
                KEY_DIRECTORY_REVISION + 1,
                key,
                seed,
            ))
            .unwrap(),
            None,
            Vec::new(),
        )
        .unwrap()
    };
    DurableKeyGenerationStateV1::new(
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION + 1),
        vec![
            catalog,
            directed(
                KeyPurpose::DeviceCommandTx,
                DEVICE_COMMAND_EPOCH,
                command_key,
                0x42,
            ),
            directed(
                KeyPurpose::DeviceReplyTx,
                DEVICE_REPLY_EPOCH,
                DEVICE_REPLY_KEY,
                0x43,
            ),
        ],
    )
    .unwrap()
}

fn counter_guard_revision(store: &dyn RemoteKeyStore, fixture: &PairingFixture) -> u64 {
    let account = RemoteKeyAccount::paired(
        INSTALLATION_ID,
        fixture.identity().machine_root_fingerprint(),
        fixture.machine_route(),
        PairedRemoteKeyPurpose::CounterGuard,
    );
    let bytes = store
        .load(&account)
        .expect("load CounterGuard")
        .expect("CounterGuard exists");
    let bytes = bytes.expose_secret();
    let offset = match u16::from_be_bytes(bytes[4..6].try_into().unwrap()) {
        1 => 8,
        2 => 40,
        version => panic!("unexpected CounterGuard version {version}"),
    };
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn v6_empty_adks_generation_only_commit_reopens_v6_with_split_revisions() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("key-generation migration root");
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let recipient = prepare_v6_with_empty_adks(&fixture, &store, &state_root, 0x31);
    let legacy = paired_state_plaintext(&store, &fixture, &state_root);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let replacement = generation_state(&fixture, &recipient, InventoryFault::None);
    let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut production_opened = production
        .open_exact(fixture.identity())
        .expect("open production");
    let production_files = file_tree_bytes(&state_root);
    let production_keys = paired_key_bytes(&store, &fixture);
    assert!(
        production_opened
            .commit_key_generation_state_transition_for_automatic_harness(
                None,
                &replacement,
                &mut PanicRng,
            )
            .is_err()
    );
    assert_eq!(file_tree_bytes(&state_root), production_files);
    assert_eq!(paired_key_bytes(&store, &fixture), production_keys);
    drop(production_opened);

    let mut opened = paired.open_exact(fixture.identity()).expect("open V6");
    let wrong_directed = generation_state(&fixture, &recipient, InventoryFault::DirectedRaw);
    let files_before_reject = file_tree_bytes(&state_root);
    let keys_before_reject = paired_key_bytes(&store, &fixture);
    assert!(
        opened
            .commit_key_generation_state_transition_for_automatic_harness(
                None,
                &wrong_directed,
                &mut PanicRng,
            )
            .is_err(),
        "normal UpdateSet must reject a directed raw-key rotation before entropy"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before_reject);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before_reject);

    let mut rng = DeterministicRng::new([0x51; 32]);
    assert_eq!(
        opened
            .commit_key_generation_state_transition_for_automatic_harness(
                None,
                &replacement,
                &mut rng,
            )
            .expect("commit first V6 inventory"),
        replacement
    );
    let retry_files = file_tree_bytes(&state_root);
    let retry_keys = paired_key_bytes(&store, &fixture);
    assert_eq!(
        opened
            .commit_key_generation_state_transition_for_automatic_harness(
                None,
                &replacement,
                &mut PanicRng,
            )
            .expect("exact retry ignores stale expected without entropy"),
        replacement
    );
    assert_eq!(file_tree_bytes(&state_root), retry_files);
    assert_eq!(paired_key_bytes(&store, &fixture), retry_keys);
    drop(opened);

    let upgraded = paired_state_plaintext(&store, &fixture, &state_root);
    assert_eq!(u16::from_be_bytes(upgraded[4..6].try_into().unwrap()), 6);
    let legacy_key_generation_offset = legacy
        .len()
        .checked_sub(6)
        .expect("V6 has key-generation length and transfer count suffix");
    assert_eq!(
        &upgraded[ADPS_HEADER_LEN..legacy_key_generation_offset],
        &legacy[ADPS_HEADER_LEN..legacy_key_generation_offset]
    );
    let canonical = replacement.canonical_bytes().unwrap();
    assert_eq!(
        u32::from_be_bytes(
            upgraded[legacy_key_generation_offset..legacy_key_generation_offset + 4]
                .try_into()
                .unwrap()
        ) as usize,
        canonical.len()
    );
    let canonical_start = legacy_key_generation_offset + 4;
    let canonical_end = canonical_start + canonical.len();
    assert_eq!(&upgraded[canonical_start..canonical_end], canonical);
    assert_eq!(
        &upgraded[canonical_end..],
        &[0, 0],
        "V6 transfer collection remains empty"
    );

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
        .open_exact(fixture.identity())
        .expect("reopen V6");
    let files_before_transfer_read = file_tree_bytes(&state_root);
    let keys_before_transfer_read = paired_key_bytes(&store, &fixture);
    assert!(
        reopened
            .durable_transfer_state()
            .expect("V6 keeps an empty transfer collection")
            .canonical_record_bytes()
            .unwrap()
            .is_empty()
    );
    assert_eq!(file_tree_bytes(&state_root), files_before_transfer_read);
    assert_eq!(
        paired_key_bytes(&store, &fixture),
        keys_before_transfer_read,
        "V6 transfer readback must not rewrite"
    );
    assert_eq!(
        reopened.directory_revision().value(),
        KEY_DIRECTORY_REVISION + 1
    );
    let durable = reopened
        .durable_key_generation_state()
        .unwrap()
        .expect("V5 inventory");
    assert_eq!(
        durable.bootstrap_directory_revision().value(),
        KEY_DIRECTORY_REVISION
    );
    assert_eq!(
        durable.effective_directory_revision().value(),
        KEY_DIRECTORY_REVISION + 1
    );
    let catalog = durable.find_slot(KeyPurpose::Catalog, None).unwrap();
    assert_eq!(
        catalog.current().key_directory_revision().value(),
        KEY_DIRECTORY_REVISION
    );
    assert_eq!(
        catalog.staged().unwrap().key_directory_revision().value(),
        KEY_DIRECTORY_REVISION + 1
    );
    for purpose in [KeyPurpose::DeviceCommandTx, KeyPurpose::DeviceReplyTx] {
        assert_eq!(
            durable
                .directed_current(purpose)
                .unwrap()
                .key_directory_revision()
                .value(),
            KEY_DIRECTORY_REVISION + 1
        );
    }
    assert_eq!(
        reopened.durable_stream_bindings().unwrap()[0]
            .binding()
            .key_directory_revision
            .value(),
        KEY_DIRECTORY_REVISION
    );
    assert_eq!(
        counter_guard_revision(&store, &fixture),
        KEY_DIRECTORY_REVISION
    );
}

#[test]
fn tampered_v6_key_generation_carriers_fail_close_without_audit_writes() {
    for (index, fault) in [
        InventoryFault::BadBootstrap,
        InventoryFault::BadSignature,
        InventoryFault::WrongHpke,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("invalid V5 root");
        let state_root = fs::canonicalize(temp.path())
            .unwrap()
            .join(format!("paired-state-{index}"));
        let recipient = prepare_v6_with_empty_adks(
            &fixture,
            &store,
            &state_root,
            0x71 + u8::try_from(index).unwrap() * 7,
        );
        let raw = generation_state(&fixture, &recipient, fault)
            .canonical_bytes()
            .unwrap();
        let automatic = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            Arc::new(NoopMutationObserver),
        );
        let mut opened = automatic
            .open_exact(fixture.identity())
            .expect("open injector");
        let mut rng = DeterministicRng::new([0x91 + index as u8; 32]);
        opened
            .replace_unchecked_key_generation_state_for_automatic_harness(raw, &mut rng)
            .expect("persist unchecked V6 key-generation field");
        drop(opened);

        let files_before = file_tree_bytes(&state_root);
        let keys_before = paired_key_bytes(&store, &fixture);
        let reader = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        assert!(
            reader.list().is_err(),
            "invalid case {index} must fail list audit"
        );
        assert!(
            reader.open_exact(fixture.identity()).is_err(),
            "invalid case {index} must fail exact-open audit"
        );
        assert_eq!(file_tree_bytes(&state_root), files_before);
        assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    }
}
