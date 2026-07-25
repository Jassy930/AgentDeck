#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_cli::remote::crypto_state::{
    CryptoStateIdentity, DeviceStorageKek, FileCryptoStateStore,
};
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    AutomaticRuntimeProjection, AutomaticRuntimeStateProbe, PairedMachineStore,
    PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::stream_state::{DurableStreamBindingV1, RemoteStreamStateError};
use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose, StreamBindingV1};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION,
    StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::{
    ConversationId, RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, StreamCursor,
};

use remote_pairing::{
    CATALOG_EPOCH, CONVERSATION_EPOCH, DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION,
    PairingFixture, PanicRng,
};

const CATALOG_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CONVERSATION_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x82; 16]);
const CATALOG_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const CONVERSATION_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x92; 16]);
const LEGACY_MUTABLE_STATE_VERSION: u16 = 2;
const TRANSFER_RUNTIME_STATE_VERSION: u16 = 6;
const DURABLE_STREAM_STATE_HEADER_BYTES: usize = 12;
const EMERGENCY_REPLAY_DEBT_HASH_DOMAIN: &[u8] = b"AgentDeck/DurableStreamEmergencyReplayDebtV2\0";

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
            panic!("injected stream-state crash at {stage:?}");
        }
    }
}

fn files_with_suffix(root: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut matches = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return matches;
    };
    for entry in entries {
        let path = entry.expect("read stream-state fixture entry").path();
        if path.is_dir() {
            matches.extend(files_with_suffix(&path, suffix));
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(suffix))
        {
            matches.push(path);
        }
    }
    matches
}

fn file_tree_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut snapshot = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return snapshot;
    };
    for entry in entries {
        let path = entry.expect("read stream-state fixture tree").path();
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
    let kek_account = RemoteKeyAccount::paired(
        INSTALLATION_ID,
        fixture.identity().machine_root_fingerprint(),
        fixture.machine_route(),
        PairedRemoteKeyPurpose::DeviceStorageKek,
    );
    let kek_record = store.load(&kek_account).unwrap().unwrap();
    let kek: [u8; 32] = kek_record.expose_secret()[40..72].try_into().unwrap();
    let inspector = FileCryptoStateStore::new_in(
        state_root,
        CryptoStateIdentity::new(
            INSTALLATION_ID,
            fixture.identity().machine_root_fingerprint(),
            fixture.machine_route(),
        ),
        DeviceStorageKek::new(kek),
    )
    .unwrap();
    inspector.load().unwrap().unwrap().expose_secret().to_vec()
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

fn conversation_binding(fixture: &PairingFixture) -> StreamBindingV1 {
    conversation_binding_for(
        fixture,
        CONVERSATION_ROUTE,
        CONVERSATION_GENERATION,
        "018f0f9d-6f0a-7ad0-8000-000000000082",
    )
}

fn conversation_binding_for(
    fixture: &PairingFixture,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    conversation_id: &str,
) -> StreamBindingV1 {
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
        stream_cursor: StreamCursor::At(4),
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(conversation_id),
            cursor: StreamCursor::At(11),
        },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: CONVERSATION_EPOCH,
        },
    }
}

fn indexed_conversation_binding(fixture: &PairingFixture, index: u64) -> StreamBindingV1 {
    let mut route = [0x82; 16];
    route[8..].copy_from_slice(&index.to_be_bytes());
    let mut generation = [0x92; 16];
    generation[8..].copy_from_slice(&index.to_be_bytes());
    conversation_binding_for(
        fixture,
        StreamRouteId::from_bytes(route),
        StreamGenerationId::from_bytes(generation),
        &format!("018f0f9d-6f0a-7ad0-8000-{index:012x}"),
    )
}

fn catalog_v6_replay_offsets(canonical: &[u8]) -> (usize, usize) {
    assert_eq!(u16::from_be_bytes([canonical[4], canonical[5]]), 6);
    let binding_len = u32::from_be_bytes(canonical[12..16].try_into().unwrap()) as usize;
    let count_offset = DURABLE_STREAM_STATE_HEADER_BYTES + 4 + binding_len + 2 * 9 + 2 * 10 + 1;
    assert_eq!(&canonical[count_offset..count_offset + 4], &[0; 4]);
    (count_offset, count_offset + 4)
}

fn rewrite_stream_state_body_len(canonical: &mut [u8]) {
    let body_len = u32::try_from(canonical.len() - DURABLE_STREAM_STATE_HEADER_BYTES).unwrap();
    canonical[8..12].copy_from_slice(&body_len.to_be_bytes());
}

fn valid_emergency_debt_canonical(
    initial: &DurableStreamBindingV1,
    binding: &StreamBindingV1,
) -> (Vec<u8>, usize, usize) {
    let mut canonical = initial.canonical_bytes().unwrap();
    let (count_offset, entries_offset) = catalog_v6_replay_offsets(&canonical);
    let mut replay = Vec::with_capacity(129);
    replay.push(0); // Catalog key purpose
    replay.extend_from_slice(&binding.key_id.epoch.to_be_bytes());
    replay.extend_from_slice(&binding.key_directory_revision.value().to_be_bytes());
    replay.extend_from_slice(binding.stream_route.as_bytes());
    replay.extend_from_slice(binding.stream_generation.as_bytes());
    replay.extend_from_slice(&0_u64.to_be_bytes());
    replay.extend_from_slice(&17_u64.to_be_bytes());
    replay.extend_from_slice(&[0x61; 32]);
    replay.extend_from_slice(&[0x62; 32]);
    assert_eq!(replay.len(), 129);

    canonical[count_offset..count_offset + 4].copy_from_slice(&1_u32.to_be_bytes());
    canonical.splice(entries_offset..entries_offset, replay.iter().copied());
    assert_eq!(
        canonical.last(),
        Some(&0),
        "initial V6 debt tag must be absent"
    );
    *canonical.last_mut().unwrap() = 1;
    let mut debt_input = EMERGENCY_REPLAY_DEBT_HASH_DOMAIN.to_vec();
    debt_input.extend_from_slice(&replay);
    canonical.extend_from_slice(&sha256(&debt_input));
    rewrite_stream_state_body_len(&mut canonical);
    (canonical, entries_offset, replay.len())
}

fn assert_initial_state(state: &DurableStreamBindingV1, binding: &StreamBindingV1) {
    assert_eq!(state.binding(), binding);
    assert_eq!(state.outer_applied(), binding.stream_cursor);
    assert_eq!(state.outer_acked(), StreamCursor::BeforeFirst);
    assert_eq!(state.inner_applied(), &binding.inner_cursor);
    assert_eq!(state.replay_tuple(), None);
    let canonical = state
        .canonical_bytes()
        .expect("canonical durable stream state");
    assert_eq!(
        DurableStreamBindingV1::from_canonical_bytes(&canonical)
            .expect("strict durable stream state readback"),
        *state
    );
}

fn assert_empty_target_rejects_semantic_mismatch(
    fixture: &PairingFixture,
    binding: StreamBindingV1,
    seed: u8,
    label: &str,
) {
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("independent mismatch root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical mismatch root")
        .join("paired-state");
    fixture.promote(&store, &state_root, seed);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    assert!(
        opened.durable_stream_bindings().unwrap().is_empty(),
        "{label} fixture must start with an empty target collection"
    );
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, fixture);

    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .install_stream_binding_for_automatic_harness(binding, &mut panic_rng)
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict",
        "{label} must reach semantic audit before target lookup"
    );
    assert!(opened.durable_stream_bindings().unwrap().is_empty());
    assert_eq!(file_tree_bytes(&state_root), files_before, "{label}");
    assert_eq!(paired_key_bytes(&store, fixture), keys_before, "{label}");
}

#[test]
fn catalog_stream_binding_is_atomic_idempotent_and_restart_durable() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("stream state root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical stream state root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x61);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open paired machine");
    assert!(opened.durable_stream_bindings().unwrap().is_empty());

    let binding = catalog_binding(&fixture);
    let mut rng = DeterministicRng::new([0x62; 32]);
    let installed = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut rng)
        .expect("install catalog stream binding");
    assert_initial_state(&installed, &binding);

    let mut panic_rng = PanicRng;
    let retried = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut panic_rng)
        .expect("exact retry must not mutate or consume entropy");
    assert_eq!(retried, installed);
    drop(opened);

    let restarted = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    assert_eq!(
        restarted
            .list()
            .expect("full V3 list audit after restart")
            .len(),
        1
    );
    let mut reopened = restarted
        .open_exact(fixture.identity())
        .expect("reopen paired machine");
    let reopened_bindings = reopened.durable_stream_bindings().unwrap();
    assert_eq!(
        reopened_bindings.as_slice(),
        std::slice::from_ref(&installed)
    );

    let mut drifted = binding;
    drifted.stream_generation = StreamGenerationId::from_bytes([0x93; 16]);
    let mut drift_rng = PanicRng;
    assert_eq!(
        reopened
            .install_stream_binding_for_automatic_harness(drifted, &mut drift_rng)
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(reopened.durable_stream_bindings().unwrap(), [installed]);
}

#[test]
fn v6_emergency_debt_decoder_rejects_tampered_duplicate_and_missing_replay_tuple() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("debt decoder root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical debt decoder root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x63);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let binding = catalog_binding(&fixture);
    let mut rng = DeterministicRng::new([0x64; 32]);
    let initial = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut rng)
        .unwrap();
    let (canonical, entries_offset, replay_len) =
        valid_emergency_debt_canonical(&initial, &binding);
    assert_eq!(
        DurableStreamBindingV1::from_canonical_bytes(&canonical)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        canonical
    );

    let mut tampered = canonical.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        DurableStreamBindingV1::from_canonical_bytes(&tampered).unwrap_err(),
        RemoteStreamStateError::InvalidCanonical
    );

    let mut tampered_signed_frame = canonical.clone();
    tampered_signed_frame[entries_offset + replay_len - 1] ^= 1;
    assert_eq!(
        DurableStreamBindingV1::from_canonical_bytes(&tampered_signed_frame).unwrap_err(),
        RemoteStreamStateError::InvalidCanonical,
        "V6 emergency debt must bind the complete replay tuple including signed-frame identity",
    );

    let count_offset = entries_offset - 4;
    let mut missing = canonical.clone();
    missing[count_offset..entries_offset].copy_from_slice(&0_u32.to_be_bytes());
    missing.drain(entries_offset..entries_offset + replay_len);
    rewrite_stream_state_body_len(&mut missing);
    assert_eq!(
        DurableStreamBindingV1::from_canonical_bytes(&missing).unwrap_err(),
        RemoteStreamStateError::InvalidCanonical
    );

    let mut duplicate = canonical.clone();
    duplicate[count_offset..entries_offset].copy_from_slice(&2_u32.to_be_bytes());
    let replay = duplicate[entries_offset..entries_offset + replay_len].to_vec();
    duplicate.splice(
        entries_offset + replay_len..entries_offset + replay_len,
        replay,
    );
    rewrite_stream_state_body_len(&mut duplicate);
    assert_eq!(
        DurableStreamBindingV1::from_canonical_bytes(&duplicate).unwrap_err(),
        RemoteStreamStateError::InvalidCanonical
    );
}

#[test]
fn stream_binding_collection_accepts_4096_and_rejects_4097() {
    const MAX_BINDINGS: usize = 4_096;

    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("stream collection boundary root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical stream collection boundary root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x65);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let bindings = (0..MAX_BINDINGS)
        .map(|index| indexed_conversation_binding(&fixture, index as u64))
        .collect::<Vec<_>>();
    let mut rng = DeterministicRng::new([0x66; 32]);
    opened
        .replace_unchecked_stream_bindings_for_automatic_harness(bindings, &mut rng)
        .expect("the complete 4096-entry stream collection must be accepted");
    assert_eq!(
        opened.durable_stream_bindings().unwrap().len(),
        MAX_BINDINGS
    );

    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    let overflow = (0..=MAX_BINDINGS)
        .map(|index| indexed_conversation_binding(&fixture, index as u64))
        .collect::<Vec<_>>();
    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .replace_unchecked_stream_bindings_for_automatic_harness(overflow, &mut panic_rng)
            .unwrap_err()
            .code(),
        "remote.pairing.paired_invalid"
    );
    assert_eq!(
        opened.durable_stream_bindings().unwrap().len(),
        MAX_BINDINGS
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
}

#[test]
fn catalog_and_conversation_bindings_coexist_without_cross_target_replacement() {
    let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_ROUTE);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("stream state root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical stream state root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x71);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open paired machine");

    let catalog = catalog_binding(&fixture);
    let conversation = conversation_binding(&fixture);
    let mut first_rng = DeterministicRng::new([0x72; 32]);
    let catalog_state = opened
        .install_stream_binding_for_automatic_harness(catalog.clone(), &mut first_rng)
        .expect("install catalog binding");
    let mut second_rng = DeterministicRng::new([0x73; 32]);
    let conversation_state = opened
        .install_stream_binding_for_automatic_harness(conversation.clone(), &mut second_rng)
        .expect("install conversation binding");
    assert_initial_state(&catalog_state, &catalog);
    assert_initial_state(&conversation_state, &conversation);
    assert_eq!(
        opened.durable_stream_bindings().unwrap(),
        [catalog_state.clone(), conversation_state.clone()]
    );

    let mut wrong_key = conversation;
    wrong_key.key_id.epoch += 1;
    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .install_stream_binding_for_automatic_harness(wrong_key, &mut panic_rng)
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(
        opened.durable_stream_bindings().unwrap(),
        [catalog_state, conversation_state]
    );
}

#[test]
fn install_rejects_authority_revision_epoch_capability_permission_and_key_slot_mismatch() {
    let fixture = PairingFixture::new();
    let mut wrong_machine = catalog_binding(&fixture);
    wrong_machine.machine_route = MachineRouteId::from_bytes([0xa1; 16]);
    assert_empty_target_rejects_semantic_mismatch(
        &fixture,
        wrong_machine,
        0x81,
        "machine authority",
    );

    let fixture = PairingFixture::new();
    let mut wrong_device = catalog_binding(&fixture);
    wrong_device.device_route = DeviceRouteId::from_bytes([0xa2; 16]);
    assert_empty_target_rejects_semantic_mismatch(&fixture, wrong_device, 0x82, "device authority");

    let fixture = PairingFixture::new();
    let mut wrong_grant = catalog_binding(&fixture);
    wrong_grant.grant_serial = GrantSerial::new(8);
    assert_empty_target_rejects_semantic_mismatch(&fixture, wrong_grant, 0x83, "grant authority");

    let fixture = PairingFixture::new();
    let mut wrong_trust = catalog_binding(&fixture);
    wrong_trust.root_trust_epoch = TrustEpoch::new(3);
    assert_empty_target_rejects_semantic_mismatch(
        &fixture,
        wrong_trust,
        0x84,
        "trust epoch authority",
    );

    let fixture = PairingFixture::new();
    let mut wrong_revision = catalog_binding(&fixture);
    wrong_revision.key_directory_revision = KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION + 1);
    assert_empty_target_rejects_semantic_mismatch(
        &fixture,
        wrong_revision,
        0x85,
        "directory revision",
    );

    let fixture = PairingFixture::new();
    let mut wrong_epoch = catalog_binding(&fixture);
    wrong_epoch.key_id.epoch += 1;
    assert_empty_target_rejects_semantic_mismatch(&fixture, wrong_epoch, 0x86, "key epoch");

    // Canonical authorization forbids permission-without-capability, so capability removal must
    // remove its CatalogRead permission as one valid authorization pair. Permission-only drift is
    // independently reachable and covered by the next fixture.
    let fixture = PairingFixture::new().without_catalog_authorization();
    assert_empty_target_rejects_semantic_mismatch(
        &fixture,
        catalog_binding(&fixture),
        0x87,
        "authorization capability+permission pair",
    );

    let fixture = PairingFixture::new().without_catalog_read_permission();
    assert_empty_target_rejects_semantic_mismatch(
        &fixture,
        catalog_binding(&fixture),
        0x88,
        "authorization permission",
    );

    let fixture = PairingFixture::new();
    assert_empty_target_rejects_semantic_mismatch(
        &fixture,
        conversation_binding(&fixture),
        0x89,
        "missing conversation key slot",
    );
}

#[test]
fn canonical_semantic_invalid_v3_active_and_prepared_fail_close_without_writes() {
    for (index, prepared_only) in [false, true].into_iter().enumerate() {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("semantic-invalid V3 root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical semantic-invalid root")
            .join(format!("paired-state-{index}"));
        fixture.promote(&store, &state_root, 0x91 + index as u8);

        let panic_observer = Arc::new(PanicOnceAtStage {
            stage: PairedMutationStage::StateStageDurable,
            fired: AtomicBool::new(false),
        });
        let observer: Arc<dyn PairedMutationObserver> = if prepared_only {
            panic_observer.clone()
        } else {
            Arc::new(NoopMutationObserver)
        };
        let automatic = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            observer,
        );
        let mut opened = automatic.open_exact(fixture.identity()).unwrap();
        let mut wrong_epoch = catalog_binding(&fixture);
        wrong_epoch.key_id.epoch += 1;
        let canonical = wrong_epoch.canonical_bytes().unwrap();
        assert_eq!(
            StreamBindingV1::from_canonical_bytes(&canonical).unwrap(),
            wrong_epoch
        );

        if prepared_only {
            let crashed = catch_unwind(AssertUnwindSafe(|| {
                let mut rng = DeterministicRng::new([0xa1 + index as u8; 32]);
                opened
                    .replace_unchecked_stream_bindings_for_automatic_harness(
                        vec![wrong_epoch.clone()],
                        &mut rng,
                    )
                    .expect("observer must stop after the canonical prepared stage");
            }));
            assert!(crashed.is_err());
            assert!(panic_observer.fired.load(Ordering::SeqCst));
        } else {
            let mut rng = DeterministicRng::new([0xa1 + index as u8; 32]);
            opened
                .replace_unchecked_stream_bindings_for_automatic_harness(
                    vec![wrong_epoch],
                    &mut rng,
                )
                .expect("automatic harness installs semantic-invalid active V3");
        }
        drop(opened);
        assert_eq!(
            files_with_suffix(&state_root, ".crypto-state-stage.v1").len(),
            usize::from(prepared_only)
        );

        let files_before = file_tree_bytes(&state_root);
        let keys_before = paired_key_bytes(&store, &fixture);
        let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        assert_eq!(
            production.list().unwrap_err().code(),
            "remote.pairing.paired_conflict",
            "{} semantic mismatch must fail list audit",
            if prepared_only { "prepared" } else { "active" }
        );
        assert_eq!(file_tree_bytes(&state_root), files_before);
        assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
        assert_eq!(
            production
                .open_exact(fixture.identity())
                .unwrap_err()
                .code(),
            "remote.pairing.paired_conflict",
            "{} semantic mismatch must fail exact-open audit",
            if prepared_only { "prepared" } else { "active" }
        );
        assert_eq!(file_tree_bytes(&state_root), files_before);
        assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    }
}

#[test]
fn automatic_stream_fault_injection_helpers_reject_production_handles_before_writes() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("production authority root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical production authority root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0xb1);
    let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = production.open_exact(fixture.identity()).unwrap();
    let canonical = catalog_binding(&fixture);
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);

    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .replace_automatic_runtime_state_probe(
                AutomaticRuntimeStateProbe::new(0xb2),
                &mut panic_rng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_invalid"
    );
    assert_eq!(
        opened
            .replace_unchecked_stream_bindings_for_automatic_harness(
                vec![canonical],
                &mut panic_rng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_invalid"
    );
    assert_eq!(
        opened
            .replace_automatic_legacy_v2_runtime_state_probe(
                AutomaticRuntimeStateProbe::new(0xb2),
                &mut panic_rng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_invalid"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
}

#[test]
fn install_rejects_one_relay_route_aliasing_multiple_targets() {
    let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_ROUTE);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("stream state root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical stream state root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x91);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();

    let first = conversation_binding_for(
        &fixture,
        CONVERSATION_ROUTE,
        CONVERSATION_GENERATION,
        "018f0f9d-6f0a-7ad0-8000-0000000000a1",
    );
    let mut first_rng = DeterministicRng::new([0x92; 32]);
    let installed = opened
        .install_stream_binding_for_automatic_harness(first, &mut first_rng)
        .unwrap();
    let alias = conversation_binding_for(
        &fixture,
        CONVERSATION_ROUTE,
        StreamGenerationId::from_bytes([0x94; 16]),
        "018f0f9d-6f0a-7ad0-8000-0000000000b2",
    );
    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .install_stream_binding_for_automatic_harness(alias, &mut panic_rng)
            .unwrap_err()
            .code(),
        "remote.pairing.paired_invalid"
    );
    assert_eq!(opened.durable_stream_bindings().unwrap(), [installed]);
}

#[test]
fn exact_retry_recovers_post_active_crash_without_rng_or_sealed_state_rewrite() {
    for (index, stage) in [
        PairedMutationStage::StateActiveDurable,
        PairedMutationStage::StateGuardStableDurable,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("stream crash root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical stream crash root")
            .join(format!("paired-state-{index}"));
        fixture.promote(&store, &state_root, 0xa1 + index as u8);
        let observer = Arc::new(PanicOnceAtStage {
            stage,
            fired: AtomicBool::new(false),
        });
        let paired = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            observer.clone(),
        );
        let mut opened = paired.open_exact(fixture.identity()).unwrap();
        let binding = catalog_binding(&fixture);
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let mut rng = DeterministicRng::new([0xb1 + index as u8; 32]);
            opened
                .install_stream_binding_for_automatic_harness(binding.clone(), &mut rng)
                .expect("observer must terminate the mutation");
        }));
        assert!(crashed.is_err(), "{stage:?} must inject one crash");
        assert!(observer.fired.load(Ordering::SeqCst));

        let state_files = files_with_suffix(&state_root, ".crypto-state.v1");
        assert_eq!(state_files.len(), 1);
        let sealed_before_retry = fs::read(&state_files[0]).unwrap();
        assert_eq!(
            files_with_suffix(&state_root, ".crypto-state-stage.v1").len(),
            1,
            "both post-active cuts retain the authenticated stage before recovery"
        );

        let mut panic_rng = PanicRng;
        let recovered = opened
            .install_stream_binding_for_automatic_harness(binding.clone(), &mut panic_rng)
            .expect("exact retry must finish guard/stage recovery without entropy");
        assert_initial_state(&recovered, &binding);
        assert_eq!(fs::read(&state_files[0]).unwrap(), sealed_before_retry);
        assert!(
            files_with_suffix(&state_root, ".crypto-state-stage.v1").is_empty(),
            "exact retry must clear the authenticated prepared stage"
        );
        drop(opened);

        let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        assert_eq!(restarted.list().unwrap().len(), 1);
        assert_eq!(
            restarted
                .open_exact(fixture.identity())
                .unwrap()
                .durable_stream_bindings()
                .unwrap(),
            [recovered]
        );
    }
}

#[test]
fn v3_bindings_survive_every_counter_reservation_crash_cut_without_hwm_reuse() {
    for (index, stage) in [
        PairedMutationStage::GuardPendingDurable,
        PairedMutationStage::StateDurable,
        PairedMutationStage::GuardStableDurable,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("V3 counter crash root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical V3 counter crash root")
            .join(format!("paired-state-{index}"));
        fixture.promote(&store, &state_root, 0xc1 + index as u8);
        let observer = Arc::new(PanicOnceAtStage {
            stage,
            fired: AtomicBool::new(false),
        });
        let paired = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            observer.clone(),
        );
        let mut opened = paired.open_exact(fixture.identity()).unwrap();
        let binding = catalog_binding(&fixture);
        let mut install_rng = DeterministicRng::new([0xd1 + index as u8; 32]);
        let installed = opened
            .install_stream_binding_for_automatic_harness(binding, &mut install_rng)
            .unwrap();

        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let mut counter_rng = DeterministicRng::new([0xe1 + index as u8; 32]);
            opened
                .reserve_command_counter_block(&mut counter_rng)
                .expect("observer must terminate the counter transaction");
        }));
        assert!(crashed.is_err(), "{stage:?} must inject one crash");
        assert!(observer.fired.load(Ordering::SeqCst));
        drop(opened);

        let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        assert_eq!(restarted.list().unwrap().len(), 1);
        let mut recovered = restarted.open_exact(fixture.identity()).unwrap();
        let recovered_bindings = recovered.durable_stream_bindings().unwrap();
        assert_eq!(
            recovered_bindings.as_slice(),
            std::slice::from_ref(&installed)
        );
        let mut next_rng = DeterministicRng::new([0xf1 + index as u8; 32]);
        let next = recovered
            .reserve_command_counter_block(&mut next_rng)
            .expect("recovered allocator must skip the crashed reservation");
        assert_eq!((next.start(), next.end_exclusive()), (1_024, 2_048));
        assert_eq!(recovered.durable_stream_bindings().unwrap(), [installed]);
    }
}

#[test]
fn empty_stream_legacy_v2_upgrades_to_v6_without_losing_counter_receipt_or_replay() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("legacy V2 upgrade root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical legacy V2 upgrade root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x31);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let mut first_counter_rng = DeterministicRng::new([0x32; 32]);
    let first = opened
        .reserve_command_counter_block(&mut first_counter_rng)
        .unwrap();
    assert_eq!((first.start(), first.end_exclusive()), (0, 1_024));

    let legacy_probe = AutomaticRuntimeStateProbe::new(0x33);
    let mut legacy_rng = DeterministicRng::new([0x34; 32]);
    assert_eq!(
        opened
            .replace_automatic_legacy_v2_runtime_state_probe(legacy_probe, &mut legacy_rng)
            .unwrap(),
        legacy_probe
    );
    assert_eq!(
        opened.automatic_legacy_runtime_fields_probe().unwrap(),
        Some(legacy_probe)
    );
    assert!(opened.durable_stream_bindings().unwrap().is_empty());
    drop(opened);

    let legacy_plaintext = paired_state_plaintext(&store, &fixture, &state_root);
    assert_eq!(
        u16::from_be_bytes(legacy_plaintext[4..6].try_into().unwrap()),
        LEGACY_MUTABLE_STATE_VERSION
    );

    let restarted = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut reopened = restarted.open_exact(fixture.identity()).unwrap();
    assert_eq!(
        reopened.automatic_legacy_runtime_fields_probe().unwrap(),
        Some(legacy_probe)
    );
    assert!(reopened.durable_stream_bindings().unwrap().is_empty());

    let binding = catalog_binding(&fixture);
    let mut install_rng = DeterministicRng::new([0x35; 32]);
    let installed = reopened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut install_rng)
        .unwrap();
    assert_initial_state(&installed, &binding);
    assert_eq!(
        reopened.automatic_legacy_runtime_fields_probe().unwrap(),
        Some(legacy_probe),
        "legacy receipt/replay bytes must survive the V6 stream install"
    );
    assert_eq!(reopened.durable_stream_bindings().unwrap(), [installed]);

    let mut next_counter_rng = DeterministicRng::new([0x36; 32]);
    let next = reopened
        .reserve_command_counter_block(&mut next_counter_rng)
        .unwrap();
    assert_eq!(
        (next.start(), next.end_exclusive()),
        (1_024, 2_048),
        "V6 upgrade must preserve the legacy counter reservation"
    );
    drop(reopened);

    let typed_plaintext = paired_state_plaintext(&store, &fixture, &state_root);
    assert_eq!(
        u16::from_be_bytes(typed_plaintext[4..6].try_into().unwrap()),
        TRANSFER_RUNTIME_STATE_VERSION
    );
}

#[test]
fn automatic_probe_uses_exchange_and_replay_only_and_survives_restart() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("automatic probe root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical automatic probe root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x41);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let probe = AutomaticRuntimeStateProbe::new(0x42);
    let expected_projection = AutomaticRuntimeProjection::new(Some(probe), Some(probe), Vec::new());
    let mut state_rng = DeterministicRng::new([0x43; 32]);
    assert_eq!(
        opened
            .replace_automatic_runtime_state_probe(probe, &mut state_rng)
            .unwrap(),
        probe
    );
    assert_eq!(opened.automatic_runtime_state_probe().unwrap(), Some(probe));
    assert_eq!(
        opened
            .automatic_runtime_projection_for_automatic_harness()
            .unwrap(),
        expected_projection
    );
    assert!(opened.durable_stream_bindings().unwrap().is_empty());
    let transfer = opened.durable_transfer_state().unwrap();
    assert_eq!(transfer.active_count(), 0);
    assert_eq!(transfer.completed_count(), 0);
    assert_eq!(transfer.marker_count(), 0);

    let files_after = file_tree_bytes(&state_root);
    let keys_after = paired_key_bytes(&store, &fixture);
    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .replace_automatic_runtime_state_probe(probe, &mut panic_rng)
            .unwrap(),
        probe
    );
    assert_eq!(file_tree_bytes(&state_root), files_after);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_after);
    drop(opened);

    let restarted = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    assert_eq!(restarted.list().unwrap().len(), 1);
    let mut reopened = restarted.open_exact(fixture.identity()).unwrap();
    assert_eq!(
        reopened.automatic_runtime_state_probe().unwrap(),
        Some(probe)
    );
    assert_eq!(
        reopened
            .automatic_runtime_projection_for_automatic_harness()
            .unwrap(),
        expected_projection
    );
    assert!(reopened.durable_stream_bindings().unwrap().is_empty());
    let transfer = reopened.durable_transfer_state().unwrap();
    assert_eq!(transfer.active_count(), 0);
    assert_eq!(transfer.completed_count(), 0);
    assert_eq!(transfer.marker_count(), 0);
    let mut counter_rng = DeterministicRng::new([0x44; 32]);
    let first = reopened
        .reserve_command_counter_block(&mut counter_rng)
        .unwrap();
    assert_eq!((first.start(), first.end_exclusive()), (0, 1_024));
    assert_eq!(
        reopened.automatic_runtime_state_probe().unwrap(),
        Some(probe)
    );
    assert_eq!(
        reopened
            .automatic_runtime_projection_for_automatic_harness()
            .unwrap(),
        expected_projection
    );
    assert!(reopened.durable_stream_bindings().unwrap().is_empty());
    let transfer = reopened.durable_transfer_state().unwrap();
    assert_eq!(transfer.active_count(), 0);
    assert_eq!(transfer.completed_count(), 0);
    assert_eq!(transfer.marker_count(), 0);
}
