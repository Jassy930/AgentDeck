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
use agentdeck_cli::remote::key_sync::{
    DurableKeySyncStateV1, FrozenKeySyncSendV1, KEY_SYNC_WINDOW_MS,
    SignedHigherRevisionObservationV1,
};
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    AutomaticRuntimeStateProbe, PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, KeySyncRequestV1, SignedSealedBlobV1, StreamBindingV1,
    UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::{SealedBlob, Send};
use agentdeck_protocol::relay_v2::{
    Ed25519Signature, GrantSerial, KeyDirectoryRevision, MachineRouteId, OpaqueRouteFrame,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId, StreamGenerationId, StreamRouteId,
    TrustEpoch, encode,
};
use agentdeck_protocol::runtime::{
    ConversationId, RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, StreamCursor,
};

use remote_pairing::{
    CATALOG_EPOCH, CONVERSATION_EPOCH, DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION,
    PairingFixture, PanicRng,
};

const STARTED_AT_MS: u64 = 1_000_000;
const ADPS_KEY_SYNC_VERSION: u16 = 4;
const ADPS_TRANSFER_VERSION: u16 = 6;
const ADPS_HEADER_LEN: usize = 12;
const ADKS_MAX_CANONICAL_BYTES: usize = 256 * 1024;
const CATALOG_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const CONVERSATION_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x82; 16]);
const CONVERSATION_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x92; 16]);

#[derive(Clone, Copy, Debug)]
enum BaselineVersion {
    V1,
    V2,
    V6Stream,
}

impl BaselineVersion {
    const fn wire_version(self) -> u16 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V6Stream => ADPS_TRANSFER_VERSION,
        }
    }
}

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
            panic!("injected KeySync persistence crash at {stage:?}");
        }
    }
}

fn file_tree_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut snapshot = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return snapshot;
    };
    for entry in entries {
        let path = entry.expect("read KeySync persistence fixture tree").path();
        if path.is_dir() {
            snapshot.extend(file_tree_bytes(&path));
        } else if path.is_file() {
            snapshot.push((
                path.clone(),
                fs::read(path).expect("snapshot durable fixture bytes"),
            ));
        }
    }
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    snapshot
}

fn files_with_suffix(root: &Path, suffix: &str) -> Vec<PathBuf> {
    file_tree_bytes(root)
        .into_iter()
        .map(|(path, _)| path)
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(suffix))
        })
        .collect()
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
    let kek_record = store
        .load(&kek_account)
        .expect("load StorageKEK record")
        .expect("StorageKEK record exists");
    let kek: [u8; 32] = kek_record.expose_secret()[40..72]
        .try_into()
        .expect("paired StorageKEK bytes");
    let inspector = FileCryptoStateStore::new_in(
        state_root,
        CryptoStateIdentity::new(
            INSTALLATION_ID,
            fixture.identity().machine_root_fingerprint(),
            fixture.machine_route(),
        ),
        DeviceStorageKek::new(kek),
    )
    .expect("open paired state inspector");
    inspector
        .load()
        .expect("load paired state")
        .expect("paired state exists")
        .expose_secret()
        .to_vec()
}

fn state_wire_version(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(
        bytes[4..6]
            .try_into()
            .expect("ADPS state has a version field"),
    )
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
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        stream_route: CONVERSATION_ROUTE,
        stream_generation: CONVERSATION_GENERATION,
        stream_cursor: StreamCursor::At(4),
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("018f0f9d-6f0a-7ad0-8000-000000000082"),
            cursor: StreamCursor::At(11),
        },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: CONVERSATION_EPOCH,
        },
    }
}

fn key_sync_observation(fixture: &PairingFixture) -> SignedHigherRevisionObservationV1 {
    key_sync_observation_for_axes(
        fixture,
        fixture.machine_route(),
        CATALOG_ROUTE,
        CATALOG_GENERATION,
    )
}

fn key_sync_observation_for_machine(
    fixture: &PairingFixture,
    machine_route: MachineRouteId,
) -> SignedHigherRevisionObservationV1 {
    key_sync_observation_for_axes(fixture, machine_route, CATALOG_ROUTE, CATALOG_GENERATION)
}

fn key_sync_observation_for_axes(
    fixture: &PairingFixture,
    machine_route: MachineRouteId,
    publication_stream_route: StreamRouteId,
    publication_stream_generation: StreamGenerationId,
) -> SignedHigherRevisionObservationV1 {
    SignedHigherRevisionObservationV1::new(
        machine_route,
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
        publication_stream_route,
        publication_stream_generation,
        17,
        23,
        [0x44; 32],
        [0x55; 32],
    )
    .expect("valid signed higher-revision observation")
}

fn signed_command_blob(request_revision: KeyDirectoryRevision, seed: u8) -> SignedSealedBlobV1 {
    UnsignedSealedBlobV1::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: 4,
        },
        4,
        request_revision.value(),
        [seed; 12],
        vec![seed; 16],
    )
    .attach_signature(Ed25519Signature([seed; 64]))
}

fn frozen_request(request: KeySyncRequestV1, route_seed: u8) -> FrozenKeySyncSendV1 {
    let frame = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(Send {
            device_route: request.device_route,
            request_route: RequestRouteId::from_bytes([route_seed; 16]),
            sealed_blob: SealedBlob(
                signed_command_blob(request.requested_key_directory_revision, route_seed)
                    .to_wire_bytes(),
            ),
        }),
    };
    FrozenKeySyncSendV1::new(request, encode(&frame)).expect("freeze exact KeySync Send")
}

fn key_sync_state(fixture: &PairingFixture) -> DurableKeySyncStateV1 {
    key_sync_state_from_observation(key_sync_observation(fixture))
}

fn key_sync_state_from_observation(
    observation: SignedHigherRevisionObservationV1,
) -> DurableKeySyncStateV1 {
    let request = observation
        .request_for_attempt(1)
        .expect("first bounded KeySync request");
    DurableKeySyncStateV1::start(observation, STARTED_AT_MS, frozen_request(request, 0x71))
        .expect("start durable KeySync fixture")
}

fn advanced_key_sync_state(
    initial: &DurableKeySyncStateV1,
    observed_offset_ms: u64,
) -> DurableKeySyncStateV1 {
    let mut replacement = initial.clone();
    let observation = replacement.observation().clone();
    replacement
        .observe_again(&observation, STARTED_AT_MS + observed_offset_ms)
        .expect("advance durable KeySync watermark");
    replacement
}

fn assert_same_budget_and_send(actual: &DurableKeySyncStateV1, expected: &DurableKeySyncStateV1) {
    assert_eq!(actual.started_at_ms(), expected.started_at_ms());
    assert_eq!(actual.deadline_at_ms(), expected.deadline_at_ms());
    assert_eq!(actual.attempt_count(), expected.attempt_count());
    assert_eq!(
        actual
            .active_send()
            .expect("fixture remains active")
            .exact_send_bytes(),
        expected
            .active_send()
            .expect("fixture remains active")
            .exact_send_bytes()
    );
    assert_eq!(
        actual
            .active_send()
            .expect("fixture remains active")
            .exact_send_sha256(),
        expected
            .active_send()
            .expect("fixture remains active")
            .exact_send_sha256()
    );
}

fn prepare_baseline(
    version: BaselineVersion,
    store: &MemoryRemoteKeyStore,
    fixture: &PairingFixture,
    state_root: &Path,
    seed: u8,
) {
    fixture.promote(store, state_root, seed);
    let paired = PairedMachineStore::new_with_mutation_observer(
        store,
        INSTALLATION_ID,
        state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open baseline paired machine");
    match version {
        BaselineVersion::V1 => {}
        BaselineVersion::V2 => {
            let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);
            opened
                .replace_automatic_legacy_v2_runtime_state_probe(
                    AutomaticRuntimeStateProbe::new(seed.wrapping_add(2)),
                    &mut rng,
                )
                .expect("prepare legacy V2 baseline");
        }
        BaselineVersion::V6Stream => {
            let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);
            opened
                .install_stream_binding_for_automatic_harness(catalog_binding(fixture), &mut rng)
                .expect("prepare current V6 stream baseline");
        }
    }
    drop(opened);
    assert_eq!(
        state_wire_version(&paired_state_plaintext(store, fixture, state_root)),
        version.wire_version()
    );
}

fn assert_v4_appends_exact_key_sync_field(
    legacy: &[u8],
    upgraded: &[u8],
    state: &DurableKeySyncStateV1,
) {
    let canonical = state.canonical_bytes().expect("canonical KeySync state");
    assert_eq!(state_wire_version(upgraded), ADPS_KEY_SYNC_VERSION);
    assert_eq!(
        &upgraded[ADPS_HEADER_LEN..legacy.len()],
        &legacy[ADPS_HEADER_LEN..],
        "ADPS V4 must preserve the complete V2/V3 body prefix byte-for-byte"
    );
    let suffix = &upgraded[legacy.len()..];
    assert_eq!(suffix.len(), 4 + canonical.len());
    assert_eq!(
        u32::from_be_bytes(suffix[..4].try_into().expect("KeySync field length")) as usize,
        canonical.len()
    );
    assert_eq!(&suffix[4..], canonical);
}

fn assert_v6_replaces_exact_key_sync_field(
    baseline: &[u8],
    upgraded: &[u8],
    state: &DurableKeySyncStateV1,
) {
    let canonical = state.canonical_bytes().expect("canonical KeySync state");
    assert_eq!(state_wire_version(baseline), ADPS_TRANSFER_VERSION);
    assert_eq!(state_wire_version(upgraded), ADPS_TRANSFER_VERSION);
    let key_sync_offset = baseline
        .len()
        .checked_sub(10)
        .expect("V6 has KeySync, key-generation and transfer suffixes");
    assert_eq!(
        &baseline[key_sync_offset..],
        &[0; 10],
        "baseline V6 has empty KeySync/key-generation/transfer collections"
    );
    assert_eq!(
        &upgraded[ADPS_HEADER_LEN..key_sync_offset],
        &baseline[ADPS_HEADER_LEN..key_sync_offset],
        "V6 KeySync mutation preserves every preceding field byte-exact"
    );
    assert_eq!(
        u32::from_be_bytes(
            upgraded[key_sync_offset..key_sync_offset + 4]
                .try_into()
                .expect("V6 KeySync field length")
        ) as usize,
        canonical.len()
    );
    let canonical_start = key_sync_offset + 4;
    let canonical_end = canonical_start + canonical.len();
    assert_eq!(&upgraded[canonical_start..canonical_end], canonical);
    assert_eq!(
        &upgraded[canonical_end..],
        &[0; 6],
        "key-generation and transfer collections remain empty"
    );
}

fn assert_v6_has_exact_key_sync_field(encoded: &[u8], state: &DurableKeySyncStateV1) {
    let canonical = state.canonical_bytes().expect("canonical KeySync state");
    assert_eq!(state_wire_version(encoded), ADPS_TRANSFER_VERSION);
    let length_offset = encoded
        .len()
        .checked_sub(canonical.len() + 10)
        .expect("V6 contains KeySync plus empty key-generation/transfer suffixes");
    assert_eq!(
        u32::from_be_bytes(
            encoded[length_offset..length_offset + 4]
                .try_into()
                .expect("V6 KeySync field length")
        ) as usize,
        canonical.len()
    );
    let canonical_start = length_offset + 4;
    let canonical_end = canonical_start + canonical.len();
    assert_eq!(&encoded[canonical_start..canonical_end], canonical);
    assert_eq!(&encoded[canonical_end..], &[0; 6]);
}

fn assert_v1_bootstrap_is_wrapped_exactly_in_v4(
    legacy: &[u8],
    upgraded: &[u8],
    state: &DurableKeySyncStateV1,
) {
    let canonical = state.canonical_bytes().expect("canonical KeySync state");
    assert_eq!(state_wire_version(upgraded), ADPS_KEY_SYNC_VERSION);
    let body = &upgraded[ADPS_HEADER_LEN..];
    assert_eq!(&body[..32], sha256(legacy));
    assert!(body[32..64].iter().any(|byte| *byte != 0));
    let bootstrap_len =
        u32::from_be_bytes(body[64..68].try_into().expect("V4 bootstrap field length")) as usize;
    assert_eq!(bootstrap_len, legacy.len());
    assert_eq!(&body[68..68 + bootstrap_len], legacy);

    let mut cursor = 68 + bootstrap_len;
    assert_eq!(&body[cursor..cursor + 4], &[0; 4], "empty receipt");
    cursor += 4;
    assert_eq!(&body[cursor..cursor + 36], &[0; 36], "no reservation");
    cursor += 36;
    assert_eq!(&body[cursor..cursor + 2], &[0; 2], "empty replay set");
    cursor += 2;
    assert_eq!(&body[cursor..cursor + 2], &[0; 2], "empty stream set");
    cursor += 2;
    assert_eq!(
        u32::from_be_bytes(
            body[cursor..cursor + 4]
                .try_into()
                .expect("KeySync field length")
        ) as usize,
        canonical.len()
    );
    cursor += 4;
    assert_eq!(&body[cursor..], canonical);
}

#[test]
fn v1_v2_and_current_v6_read_empty_then_first_key_sync_write_is_exact() {
    for (index, version) in [
        BaselineVersion::V1,
        BaselineVersion::V2,
        BaselineVersion::V6Stream,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("KeySync migration root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical KeySync migration root")
            .join(format!("paired-state-{index}"));
        let seed = 0x31 + u8::try_from(index).expect("bounded fixture index") * 4;
        prepare_baseline(version, &store, &fixture, &state_root, seed);
        let legacy = paired_state_plaintext(&store, &fixture, &state_root);

        let paired = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            Arc::new(NoopMutationObserver),
        );
        let mut opened = paired
            .open_exact(fixture.identity())
            .expect("open legacy paired state");
        let files_before_transfer_read = file_tree_bytes(&state_root);
        let keys_before_transfer_read = paired_key_bytes(&store, &fixture);
        assert!(
            opened
                .durable_transfer_state()
                .expect("baseline states map to an empty transfer collection")
                .canonical_record_bytes()
                .unwrap()
                .is_empty()
        );
        assert_eq!(file_tree_bytes(&state_root), files_before_transfer_read);
        assert_eq!(
            paired_key_bytes(&store, &fixture),
            keys_before_transfer_read,
            "legacy transfer readback must not migrate or rewrite"
        );
        assert_eq!(
            opened
                .durable_key_sync_state()
                .expect("read legacy KeySync projection"),
            None
        );
        let state = key_sync_state(&fixture);
        let mut rng = DeterministicRng::new([seed.wrapping_add(3); 32]);
        assert_eq!(
            opened
                .commit_key_sync_state_transition_for_automatic_harness(
                    None,
                    Some(&state),
                    &mut rng,
                )
                .expect("commit first KeySync state"),
            Some(state.clone())
        );
        drop(opened);

        let upgraded = paired_state_plaintext(&store, &fixture, &state_root);
        match version {
            BaselineVersion::V1 => {
                assert_v1_bootstrap_is_wrapped_exactly_in_v4(&legacy, &upgraded, &state)
            }
            BaselineVersion::V2 => {
                assert_v4_appends_exact_key_sync_field(&legacy, &upgraded, &state)
            }
            BaselineVersion::V6Stream => {
                assert_v6_replaces_exact_key_sync_field(&legacy, &upgraded, &state)
            }
        }
        let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        let reopened = restarted
            .open_exact(fixture.identity())
            .expect("reopen migrated/current ADPS state");
        let files_before_v4_transfer_read = file_tree_bytes(&state_root);
        let keys_before_v4_transfer_read = paired_key_bytes(&store, &fixture);
        assert!(
            reopened
                .durable_transfer_state()
                .expect("post-KeySync state has an empty transfer collection")
                .canonical_record_bytes()
                .unwrap()
                .is_empty()
        );
        assert_eq!(file_tree_bytes(&state_root), files_before_v4_transfer_read);
        assert_eq!(
            paired_key_bytes(&store, &fixture),
            keys_before_v4_transfer_read,
            "transfer readback must not migrate or rewrite"
        );
        assert_eq!(
            reopened
                .durable_key_sync_state()
                .expect("read restarted KeySync projection"),
            Some(state)
        );
    }
}

#[test]
fn canonical_restart_stale_expected_cas_and_exact_idempotency_are_bounded() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("KeySync CAS root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical KeySync CAS root")
        .join("paired-state");
    prepare_baseline(BaselineVersion::V1, &store, &fixture, &state_root, 0x51);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open CAS fixture");
    let initial = key_sync_state(&fixture);
    let initial_canonical = initial.canonical_bytes().expect("initial canonical state");
    let mut first_rng = DeterministicRng::new([0x52; 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(
            None,
            Some(&initial),
            &mut first_rng,
        )
        .expect("commit initial KeySync state");

    let files_before_retry = file_tree_bytes(&state_root);
    let keys_before_retry = paired_key_bytes(&store, &fixture);
    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .commit_key_sync_state_transition_for_automatic_harness(
                None,
                Some(&initial),
                &mut panic_rng,
            )
            .expect("same replacement is idempotent despite stale expected"),
        Some(initial.clone())
    );
    assert_eq!(file_tree_bytes(&state_root), files_before_retry);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before_retry);

    let current = advanced_key_sync_state(&initial, 1_000);
    let mut advance_rng = DeterministicRng::new([0x53; 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(
            Some(&initial),
            Some(&current),
            &mut advance_rng,
        )
        .expect("advance durable KeySync watermark");
    let stale_replacement = advanced_key_sync_state(&initial, 2_000);
    let files_before_stale = file_tree_bytes(&state_root);
    let keys_before_stale = paired_key_bytes(&store, &fixture);
    let mut stale_rng = PanicRng;
    assert_eq!(
        opened
            .commit_key_sync_state_transition_for_automatic_harness(
                Some(&initial),
                Some(&stale_replacement),
                &mut stale_rng,
            )
            .expect_err("stale expected state must fail CAS")
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before_stale);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before_stale);
    drop(opened);

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let reopened = restarted
        .open_exact(fixture.identity())
        .expect("reopen CAS fixture");
    let restarted_state = reopened
        .durable_key_sync_state()
        .expect("read restarted KeySync state")
        .expect("KeySync state remains present");
    assert_eq!(restarted_state, current);
    assert_ne!(
        restarted_state.canonical_bytes().unwrap(),
        initial_canonical
    );
    assert_same_budget_and_send(&restarted_state, &initial);
    assert_eq!(
        restarted_state.deadline_at_ms(),
        STARTED_AT_MS + KEY_SYNC_WINDOW_MS
    );
}

#[test]
fn unchecked_adks_is_automatic_only_and_open_audit_rejects_every_invalid_shape_without_writes() {
    let fixture = PairingFixture::new();
    let valid_state = key_sync_state(&fixture);
    let valid = valid_state.canonical_bytes().expect("valid ADKS fixture");

    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("production unchecked rejection root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical production rejection root")
        .join("paired-state");
    prepare_baseline(BaselineVersion::V1, &store, &fixture, &state_root, 0x61);
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut production_opened = production
        .open_exact(fixture.identity())
        .expect("open production handle");
    let mut panic_rng = PanicRng;
    assert_eq!(
        production_opened
            .commit_key_sync_state_transition_for_automatic_harness(
                None,
                Some(&valid_state),
                &mut panic_rng,
            )
            .expect_err("production handle must reject automatic KeySync commit")
            .code(),
        "remote.pairing.paired_invalid"
    );
    let mut panic_rng = PanicRng;
    assert_eq!(
        production_opened
            .replace_unchecked_key_sync_state_for_automatic_harness(
                Some(valid.clone()),
                &mut panic_rng,
            )
            .expect_err("production handle must reject unchecked injection")
            .code(),
        "remote.pairing.paired_invalid"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    drop(production_opened);

    let mut trailing = valid.clone();
    trailing.push(0x99);
    let mut oversize = valid;
    oversize.resize(ADKS_MAX_CANONICAL_BYTES + 1, 0xa5);
    for (index, (label, raw)) in [
        ("malformed", b"not-a-canonical-adks".to_vec()),
        ("trailing", trailing),
        ("oversize", oversize),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("invalid ADKS root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical invalid ADKS root")
            .join(format!("paired-state-{index}"));
        prepare_baseline(
            BaselineVersion::V6Stream,
            &store,
            &fixture,
            &state_root,
            0x71 + u8::try_from(index).expect("bounded invalid index") * 4,
        );
        let automatic = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            Arc::new(NoopMutationObserver),
        );
        let mut opened = automatic
            .open_exact(fixture.identity())
            .expect("open automatic invalid-state injector");
        let mut rng = DeterministicRng::new([0x81 + index as u8; 32]);
        opened
            .replace_unchecked_key_sync_state_for_automatic_harness(Some(raw), &mut rng)
            .expect("inject unchecked ADKS through a complete durable transaction");
        drop(opened);

        let files_before_audit = file_tree_bytes(&state_root);
        let keys_before_audit = paired_key_bytes(&store, &fixture);
        let reader = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        assert_eq!(
            reader.list().expect_err("invalid ADKS list audit").code(),
            "remote.pairing.paired_invalid",
            "{label}"
        );
        assert_eq!(
            reader
                .open_exact(fixture.identity())
                .expect_err("invalid ADKS exact-open audit")
                .code(),
            "remote.pairing.paired_invalid",
            "{label}"
        );
        assert_eq!(file_tree_bytes(&state_root), files_before_audit, "{label}");
        assert_eq!(
            paired_key_bytes(&store, &fixture),
            keys_before_audit,
            "{label}"
        );
    }
}

#[test]
fn contextual_invalid_adks_fails_candidate_active_and_prepared_audit_without_writes() {
    for context_case in 0_usize..2 {
        for (stage_index, crash_stage) in [None, Some(PairedMutationStage::StateStageDurable)]
            .into_iter()
            .enumerate()
        {
            let index = context_case * 2 + stage_index;
            let fixture = PairingFixture::new();
            let store = MemoryRemoteKeyStore::new();
            let temp = tempfile::tempdir().expect("context-invalid ADKS root");
            let state_root = fs::canonicalize(temp.path())
                .expect("canonical context-invalid ADKS root")
                .join(format!("paired-state-{index}"));
            prepare_baseline(
                BaselineVersion::V6Stream,
                &store,
                &fixture,
                &state_root,
                0xd1 + u8::try_from(index).expect("bounded context index") * 4,
            );
            let invalid_observation = if context_case == 0 {
                key_sync_observation_for_machine(&fixture, MachineRouteId::from_bytes([0xe1; 16]))
            } else {
                key_sync_observation_for_axes(
                    &fixture,
                    fixture.machine_route(),
                    StreamRouteId::from_bytes([0xe2; 16]),
                    StreamGenerationId::from_bytes([0xe3; 16]),
                )
            };
            let invalid = key_sync_state_from_observation(invalid_observation);
            let invalid_bytes = invalid
                .canonical_bytes()
                .expect("canonical context-invalid ADKS");
            let observer: Arc<dyn PairedMutationObserver> = match crash_stage {
                Some(stage) => Arc::new(PanicOnceAtStage {
                    stage,
                    fired: AtomicBool::new(false),
                }),
                None => Arc::new(NoopMutationObserver),
            };
            let automatic = PairedMachineStore::new_with_mutation_observer(
                &store,
                INSTALLATION_ID,
                &state_root,
                observer,
            );
            let mut opened = automatic
                .open_exact(fixture.identity())
                .expect("open context-invalid ADKS injector");

            let files_before_candidate = file_tree_bytes(&state_root);
            let keys_before_candidate = paired_key_bytes(&store, &fixture);
            let mut panic_rng = PanicRng;
            assert_eq!(
                opened
                    .commit_key_sync_state_transition_for_automatic_harness(
                        None,
                        Some(&invalid),
                        &mut panic_rng,
                    )
                    .expect_err("context-invalid candidate must fail before entropy")
                    .code(),
                "remote.pairing.paired_conflict"
            );
            assert_eq!(file_tree_bytes(&state_root), files_before_candidate);
            assert_eq!(paired_key_bytes(&store, &fixture), keys_before_candidate);

            if crash_stage.is_some() {
                let crashed = catch_unwind(AssertUnwindSafe(|| {
                    let mut rng = DeterministicRng::new([0xf1 + index as u8; 32]);
                    opened
                        .replace_unchecked_key_sync_state_for_automatic_harness(
                            Some(invalid_bytes.clone()),
                            &mut rng,
                        )
                        .expect("observer must terminate context-invalid stage");
                }));
                assert!(crashed.is_err(), "prepared context-invalid seam must crash");
            } else {
                let mut rng = DeterministicRng::new([0xf1 + index as u8; 32]);
                opened
                    .replace_unchecked_key_sync_state_for_automatic_harness(
                        Some(invalid_bytes),
                        &mut rng,
                    )
                    .expect("inject canonical context-invalid active ADKS");
            }
            drop(opened);

            let files_before_audit = file_tree_bytes(&state_root);
            let keys_before_audit = paired_key_bytes(&store, &fixture);
            let reader = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
            assert_eq!(
                reader
                    .list()
                    .expect_err("context-invalid list audit")
                    .code(),
                "remote.pairing.paired_conflict"
            );
            assert_eq!(
                reader
                    .open_exact(fixture.identity())
                    .expect_err("context-invalid exact-open audit")
                    .code(),
                "remote.pairing.paired_conflict"
            );
            assert_eq!(file_tree_bytes(&state_root), files_before_audit);
            assert_eq!(paired_key_bytes(&store, &fixture), keys_before_audit);
        }
    }
}

#[test]
fn every_state_transaction_crash_cut_recovers_without_resetting_key_sync_budget_or_send() {
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
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("KeySync crash root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical KeySync crash root")
            .join(format!("paired-state-{index}"));
        prepare_baseline(
            BaselineVersion::V1,
            &store,
            &fixture,
            &state_root,
            0x91 + u8::try_from(index).expect("bounded crash index") * 4,
        );
        let initial = key_sync_state(&fixture);
        let replacement = advanced_key_sync_state(&initial, 5_000);
        let bootstrap = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            Arc::new(NoopMutationObserver),
        );
        let mut opened = bootstrap
            .open_exact(fixture.identity())
            .expect("open KeySync crash bootstrap");
        let mut bootstrap_rng = DeterministicRng::new([0xa1 + index as u8; 32]);
        opened
            .commit_key_sync_state_transition_for_automatic_harness(
                None,
                Some(&initial),
                &mut bootstrap_rng,
            )
            .expect("commit pre-crash KeySync state");
        drop(opened);

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
            .expect("open KeySync crash candidate");
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let mut rng = DeterministicRng::new([0xb1 + index as u8; 32]);
            opened
                .commit_key_sync_state_transition_for_automatic_harness(
                    Some(&initial),
                    Some(&replacement),
                    &mut rng,
                )
                .expect("observer must terminate KeySync state transition");
        }));
        assert!(crashed.is_err(), "{stage:?} must inject one crash");
        assert!(observer.fired.load(Ordering::SeqCst));
        drop(opened);

        let reader = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        let files_before_list = file_tree_bytes(&state_root);
        assert_eq!(
            reader
                .list()
                .expect("list validates active and prepared KeySync states")
                .len(),
            1,
            "{stage:?}"
        );
        assert_eq!(
            file_tree_bytes(&state_root),
            files_before_list,
            "list must remain read-only at {stage:?}"
        );
        let reopened = reader
            .open_exact(fixture.identity())
            .expect("reopen and recover KeySync state transaction");
        let recovered = reopened
            .durable_key_sync_state()
            .expect("read recovered KeySync state")
            .expect("pre-crash KeySync state remains present");
        let expected = if stage == PairedMutationStage::StateStageDurable {
            &initial
        } else {
            &replacement
        };
        assert_eq!(&recovered, expected, "{stage:?}");
        assert_same_budget_and_send(&recovered, &initial);
        assert_eq!(recovered.started_at_ms(), STARTED_AT_MS, "{stage:?}");
        assert_eq!(
            recovered.deadline_at_ms(),
            STARTED_AT_MS + KEY_SYNC_WINDOW_MS,
            "{stage:?}"
        );
        assert!(
            files_with_suffix(&state_root, ".crypto-state-stage.v1").is_empty(),
            "{stage:?} recovery must clear the prepared sidecar"
        );
    }
}

#[test]
fn counter_and_stream_mutations_preserve_exact_adks_and_v6_wire_version() {
    let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_ROUTE);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("KeySync mutation preservation root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical KeySync mutation preservation root")
        .join("paired-state");
    prepare_baseline(
        BaselineVersion::V6Stream,
        &store,
        &fixture,
        &state_root,
        0xc1,
    );
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open KeySync mutation preservation fixture");
    let state = key_sync_state(&fixture);
    let mut install_rng = DeterministicRng::new([0xc2; 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(
            None,
            Some(&state),
            &mut install_rng,
        )
        .expect("install KeySync state before adjacent mutations");
    assert_v6_has_exact_key_sync_field(
        &paired_state_plaintext(&store, &fixture, &state_root),
        &state,
    );

    let mut counter_rng = DeterministicRng::new([0xc3; 32]);
    opened
        .reserve_command_counter_block(&mut counter_rng)
        .expect("reserve counter block while preserving ADKS");
    assert_eq!(
        opened.durable_key_sync_state().unwrap(),
        Some(state.clone())
    );
    assert_v6_has_exact_key_sync_field(
        &paired_state_plaintext(&store, &fixture, &state_root),
        &state,
    );

    let mut stream_rng = DeterministicRng::new([0xc4; 32]);
    opened
        .install_stream_binding_for_automatic_harness(
            conversation_binding(&fixture),
            &mut stream_rng,
        )
        .expect("install adjacent conversation binding while preserving ADKS");
    assert_eq!(opened.durable_stream_bindings().unwrap().len(), 2);
    assert_eq!(
        opened.durable_key_sync_state().unwrap(),
        Some(state.clone())
    );
    assert_v6_has_exact_key_sync_field(
        &paired_state_plaintext(&store, &fixture, &state_root),
        &state,
    );
    drop(opened);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
        .open_exact(fixture.identity())
        .expect("reopen V6 after counter and stream mutations");
    assert_eq!(reopened.durable_stream_bindings().unwrap().len(), 2);
    assert_eq!(reopened.durable_key_sync_state().unwrap(), Some(state));
}

#[test]
fn clearing_key_sync_state_is_durable_and_exact_clear_retry_is_idempotent() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("KeySync clear root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical KeySync clear root")
        .join("paired-state");
    prepare_baseline(
        BaselineVersion::V6Stream,
        &store,
        &fixture,
        &state_root,
        0xc1,
    );
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open KeySync clear fixture");
    let state = key_sync_state(&fixture);
    let mut install_rng = DeterministicRng::new([0xc2; 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(
            None,
            Some(&state),
            &mut install_rng,
        )
        .expect("install KeySync state before clear");
    let mut clear_rng = DeterministicRng::new([0xc3; 32]);
    assert_eq!(
        opened
            .commit_key_sync_state_transition_for_automatic_harness(
                Some(&state),
                None,
                &mut clear_rng,
            )
            .expect("clear KeySync state"),
        None
    );
    assert_eq!(
        opened
            .durable_key_sync_state()
            .expect("read cleared KeySync state"),
        None
    );

    let files_before_retry = file_tree_bytes(&state_root);
    let keys_before_retry = paired_key_bytes(&store, &fixture);
    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .commit_key_sync_state_transition_for_automatic_harness(
                Some(&state),
                None,
                &mut panic_rng,
            )
            .expect("exact clear retry is idempotent"),
        None
    );
    assert_eq!(file_tree_bytes(&state_root), files_before_retry);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before_retry);
    drop(opened);

    let plaintext = paired_state_plaintext(&store, &fixture, &state_root);
    assert_eq!(state_wire_version(&plaintext), ADPS_TRANSFER_VERSION);
    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert_eq!(
        restarted
            .open_exact(fixture.identity())
            .expect("reopen cleared KeySync state")
            .durable_key_sync_state()
            .expect("read cleared KeySync state after restart"),
        None
    );
}
