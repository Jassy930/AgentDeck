#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    AutomaticRuntimeProjection, AutomaticRuntimeStateProbe, PairedMachineStore,
    PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::transfer_state::{
    DurableLiveTransferStateV1, DurableTransferBootstrapError, DurableTransferOutcomeV1,
    MAX_DURABLE_TRANSFER_RECORD_BYTES, MAX_DURABLE_TRANSFER_RECORDS,
};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose, StreamBindingV1};
use agentdeck_protocol::relay_v2::{
    GrantSerial, KeyDirectoryRevision, RELAY_PROTOCOL_VERSION, StreamGenerationId, StreamRouteId,
    TrustEpoch,
};
use agentdeck_protocol::runtime::{
    DurableStreamTransferIdentity, MAX_PART_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor,
    RuntimeTransferCarrierV1, RuntimeTransferChannel, StreamCursor, TransferEnvelope,
};

use remote_pairing::{
    CATALOG_EPOCH, DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION, PairingFixture,
    PanicRng,
};

const CATALOG_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const START_MS: u64 = 10_000;

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
            panic!("injected paired transfer crash at {stage:?}");
        }
    }
}

fn file_tree_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut snapshot = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return snapshot;
    };
    for entry in entries {
        let path = entry.expect("read paired transfer fixture entry").path();
        if path.is_dir() {
            snapshot.extend(file_tree_bytes(&path));
        } else if path.is_file() {
            snapshot.push((
                path.clone(),
                fs::read(path).expect("snapshot paired transfer durable bytes"),
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
            .expect("snapshot paired transfer key")
            .expect("paired transfer key exists")
            .expose_secret()
            .to_vec();
        (purpose, bytes)
    })
    .collect()
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

fn first_catalog_part() -> RuntimeTransferCarrierV1 {
    let payload = vec![0x5a; MAX_PART_BYTES + 1];
    let identity = DurableStreamTransferIdentity::for_catalog(1, 2, &payload)
        .expect("bounded catalog transfer identity");
    RuntimeTransferCarrierV1::new(
        identity.message_id(),
        RuntimeTransferChannel::Stream,
        TransferEnvelope::new(
            identity.transfer_id(),
            0,
            identity.part_count(),
            identity.total_sha256(),
            identity.total_bytes(),
            payload[..MAX_PART_BYTES].to_vec(),
        )
        .expect("bounded first transfer part"),
    )
}

#[test]
fn paired_state_persists_transfer_records_with_the_exact_stream_binding_cas() {
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("paired transfer tempdir");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical paired transfer root")
        .join("paired-state");
    let fixture = PairingFixture::new();
    fixture.promote(&store, &state_root, 0x41);

    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open paired machine");
    let empty = opened
        .durable_transfer_state()
        .expect("legacy paired state maps to an empty transfer collection");
    assert_eq!(empty, DurableLiveTransferStateV1::empty());

    let binding = catalog_binding(&fixture);
    let durable = opened
        .install_stream_binding_for_automatic_harness(
            binding.clone(),
            &mut DeterministicRng::new([0x42; 32]),
        )
        .expect("install catalog binding");
    let transition = empty
        .clone()
        .accept_part(&binding, first_catalog_part(), START_MS)
        .expect("buffer first transfer part");
    assert!(matches!(
        transition.outcome(),
        DurableTransferOutcomeV1::Buffered {
            received_parts: 1,
            part_count: 2
        }
    ));

    let (_, committed) = opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &durable,
            &durable,
            &empty,
            transition.state(),
            &mut DeterministicRng::new([0x43; 32]),
        )
        .expect("commit binding and transfer records in one paired-state CAS");
    assert_eq!(
        committed.canonical_record_bytes().unwrap(),
        transition.record_bytes()
    );
    drop(opened);

    let reopened = paired
        .open_exact(fixture.identity())
        .expect("restart-open paired machine");
    assert_eq!(
        reopened.durable_stream_bindings().unwrap(),
        [durable],
        "restart readback must recover the exact binding and transfer-record axes"
    );
    assert_eq!(
        reopened
            .durable_transfer_state()
            .expect("strict transfer readback")
            .canonical_record_bytes()
            .unwrap(),
        transition.record_bytes()
    );
}

#[test]
fn stale_combined_cas_rejects_before_entropy_or_any_durable_write() {
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("stale paired transfer tempdir");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical stale paired transfer root")
        .join("paired-state");
    let fixture = PairingFixture::new();
    fixture.promote(&store, &state_root, 0x51);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let binding = catalog_binding(&fixture);
    let durable = opened
        .install_stream_binding_for_automatic_harness(
            binding.clone(),
            &mut DeterministicRng::new([0x52; 32]),
        )
        .unwrap();
    let empty = DurableLiveTransferStateV1::empty();
    let buffered = empty
        .clone()
        .accept_part(&binding, first_catalog_part(), START_MS)
        .unwrap();
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &durable,
            &durable,
            &empty,
            buffered.state(),
            &mut DeterministicRng::new([0x53; 32]),
        )
        .unwrap();

    let aborted = buffered
        .state()
        .clone()
        .abort_exact_binding(
            &binding,
            None,
            DurableTransferBootstrapError::InvalidIdentity,
            START_MS + 1,
        )
        .unwrap();
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .commit_stream_transfer_transition_for_automatic_harness(
                &durable,
                &durable,
                &empty,
                aborted.state(),
                &mut panic_rng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    assert_eq!(
        opened
            .durable_transfer_state()
            .unwrap()
            .canonical_record_bytes()
            .unwrap(),
        buffered.record_bytes()
    );

    let mut replacement_binding = binding.clone();
    replacement_binding.stream_generation = StreamGenerationId::from_bytes([0xa1; 16]);
    let replacement_durable = opened
        .commit_subscription_bootstrap_for_automatic_harness(
            replacement_binding,
            binding.inner_cursor.clone(),
            &mut DeterministicRng::new([0x54; 32]),
        )
        .unwrap();
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    assert_eq!(
        opened
            .commit_stream_transfer_transition_for_automatic_harness(
                &durable,
                &durable,
                &DurableLiveTransferStateV1::empty(),
                &DurableLiveTransferStateV1::empty(),
                &mut PanicRng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    assert_eq!(
        opened.durable_stream_bindings().unwrap(),
        [replacement_durable]
    );
    assert_eq!(
        opened.durable_transfer_state().unwrap(),
        DurableLiveTransferStateV1::empty()
    );
}

#[test]
fn combined_cas_recovers_both_axes_after_post_active_crash_cuts() {
    for (index, stage) in [
        PairedMutationStage::StateActiveDurable,
        PairedMutationStage::StateGuardStableDurable,
    ]
    .into_iter()
    .enumerate()
    {
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("crash paired transfer tempdir");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical crash paired transfer root")
            .join(format!("paired-state-{index}"));
        let fixture = PairingFixture::new();
        fixture.promote(&store, &state_root, 0x58 + index as u8);
        let baseline = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            Arc::new(NoopMutationObserver),
        );
        let mut baseline_opened = baseline.open_exact(fixture.identity()).unwrap();
        let binding = catalog_binding(&fixture);
        let durable = baseline_opened
            .install_stream_binding_for_automatic_harness(
                binding.clone(),
                &mut DeterministicRng::new([0x5a + index as u8; 32]),
            )
            .unwrap();
        drop(baseline_opened);

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
        let mut opened = crashing.open_exact(fixture.identity()).unwrap();
        let empty = DurableLiveTransferStateV1::empty();
        let transition = empty
            .clone()
            .accept_part(&binding, first_catalog_part(), START_MS)
            .unwrap();
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            opened
                .commit_stream_transfer_transition_for_automatic_harness(
                    &durable,
                    &durable,
                    &empty,
                    transition.state(),
                    &mut DeterministicRng::new([0x5c + index as u8; 32]),
                )
                .expect("observer must terminate the combined CAS");
        }));
        assert!(crashed.is_err(), "{stage:?} must inject one crash");
        assert!(observer.fired.load(Ordering::SeqCst));

        let (recovered_binding, recovered_transfer) = opened
            .commit_stream_transfer_transition_for_automatic_harness(
                &durable,
                &durable,
                &empty,
                transition.state(),
                &mut PanicRng,
            )
            .expect("exact retry must recover the already committed combined CAS");
        assert_eq!(recovered_binding, durable);
        assert_eq!(
            recovered_transfer.canonical_record_bytes().unwrap(),
            transition.record_bytes()
        );
        drop(opened);

        let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
            .open_exact(fixture.identity())
            .expect("cold-open recovered combined CAS");
        assert_eq!(reopened.durable_stream_bindings().unwrap(), [durable]);
        assert_eq!(
            reopened
                .durable_transfer_state()
                .unwrap()
                .canonical_record_bytes()
                .unwrap(),
            transition.record_bytes()
        );
    }
}

#[test]
fn stale_runtime_projection_cas_cannot_revert_fresh_binding_or_transfer_cut() {
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("stale runtime projection tempdir");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical stale runtime projection root")
        .join("paired-state");
    let fixture = PairingFixture::new();
    fixture.promote(&store, &state_root, 0x5d);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();

    let old_binding = catalog_binding(&fixture);
    let old_durable = opened
        .install_stream_binding_for_automatic_harness(
            old_binding.clone(),
            &mut DeterministicRng::new([0x5e; 32]),
        )
        .unwrap();
    let old_transfer = DurableLiveTransferStateV1::empty()
        .accept_part(&old_binding, first_catalog_part(), START_MS)
        .unwrap();
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &old_durable,
            &old_durable,
            &DurableLiveTransferStateV1::empty(),
            old_transfer.state(),
            &mut DeterministicRng::new([0x5f; 32]),
        )
        .unwrap();

    let empty_projection = AutomaticRuntimeProjection::new(None, None, vec![old_durable.clone()]);
    let stale_expected = AutomaticRuntimeProjection::new(
        Some(AutomaticRuntimeStateProbe::new(0x60)),
        Some(AutomaticRuntimeStateProbe::new(0x61)),
        vec![old_durable.clone()],
    );
    opened
        .replace_runtime_projection_preserving_transfer_records_for_automatic_harness(
            &empty_projection,
            &stale_expected,
            &mut DeterministicRng::new([0x60; 32]),
        )
        .expect("install the caller's original three-axis projection");
    assert_eq!(
        opened
            .durable_transfer_state()
            .unwrap()
            .canonical_record_bytes()
            .unwrap(),
        old_transfer.record_bytes(),
        "directed projection mutation must preserve the old transfer cut"
    );

    let mut new_binding = old_binding.clone();
    new_binding.stream_generation = StreamGenerationId::from_bytes([0x96; 16]);
    new_binding.stream_cursor = StreamCursor::At(0);
    new_binding.inner_cursor = RuntimeInnerCursor::Catalog {
        cursor: StreamCursor::At(0),
    };
    let new_inner = new_binding.inner_cursor.clone();
    let new_durable = opened
        .commit_subscription_bootstrap_for_automatic_harness(
            new_binding.clone(),
            new_inner.clone(),
            &mut DeterministicRng::new([0x62; 32]),
        )
        .expect("install a newer binding and reducer cut");
    assert_eq!(new_durable.binding(), &new_binding);
    assert_eq!(new_durable.outer_applied(), StreamCursor::At(0));
    assert_eq!(new_durable.inner_observed(), &new_inner);
    assert_eq!(new_durable.inner_applied(), &new_inner);

    let fresh_transfer = DurableLiveTransferStateV1::empty()
        .accept_part(&new_binding, first_catalog_part(), START_MS + 1)
        .unwrap();
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &new_durable,
            &new_durable,
            &DurableLiveTransferStateV1::empty(),
            fresh_transfer.state(),
            &mut DeterministicRng::new([0x63; 32]),
        )
        .expect("commit the fresh transfer cut on the new binding");

    let pre_fresh_projection = AutomaticRuntimeProjection::new(
        None,
        Some(AutomaticRuntimeStateProbe::new(0x61)),
        vec![new_durable.clone()],
    );
    let exchange_advanced_projection = AutomaticRuntimeProjection::new(
        Some(AutomaticRuntimeStateProbe::new(0x64)),
        Some(AutomaticRuntimeStateProbe::new(0x61)),
        vec![new_durable.clone()],
    );
    let fresh_projection = AutomaticRuntimeProjection::new(
        Some(AutomaticRuntimeStateProbe::new(0x64)),
        Some(AutomaticRuntimeStateProbe::new(0x65)),
        vec![new_durable.clone()],
    );
    opened
        .replace_runtime_projection_preserving_transfer_records_for_automatic_harness(
            &pre_fresh_projection,
            &exchange_advanced_projection,
            &mut DeterministicRng::new([0x64; 32]),
        )
        .expect("advance only the fresh exchange axis");
    opened
        .replace_runtime_projection_preserving_transfer_records_for_automatic_harness(
            &pre_fresh_projection,
            &fresh_projection,
            &mut DeterministicRng::new([0x65; 32]),
        )
        .expect("mixed expected/replacement axes must finish the replay advance");

    let stale_replacement = AutomaticRuntimeProjection::new(
        Some(AutomaticRuntimeStateProbe::new(0x66)),
        Some(AutomaticRuntimeStateProbe::new(0x67)),
        vec![old_durable],
    );
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    assert_eq!(
        opened
            .replace_runtime_projection_preserving_transfer_records_for_automatic_harness(
                &stale_expected,
                &stale_replacement,
                &mut PanicRng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    assert_eq!(
        opened
            .automatic_runtime_projection_for_automatic_harness()
            .unwrap(),
        fresh_projection,
        "stale expected must not roll back fresh exchange/replay/binding axes"
    );
    assert_eq!(opened.durable_stream_bindings().unwrap(), [new_durable]);
    assert_eq!(
        opened
            .durable_transfer_state()
            .unwrap()
            .canonical_record_bytes()
            .unwrap(),
        fresh_transfer.record_bytes(),
        "stale expected must not roll back the fresh transfer cut"
    );

    let exact_retry = opened
        .replace_runtime_projection_preserving_transfer_records_for_automatic_harness(
            &stale_expected,
            &fresh_projection,
            &mut PanicRng,
        )
        .expect("all-replacement exact retry must need no entropy or write");
    assert_eq!(exact_retry, fresh_projection);
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);

    drop(opened);
    let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut production_opened = production
        .open_exact(fixture.identity())
        .expect("production handle can audit the canonical binding and transfer state");
    assert_eq!(
        production_opened
            .replace_runtime_projection_preserving_transfer_records_for_automatic_harness(
                &fresh_projection,
                &fresh_projection,
                &mut PanicRng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_invalid",
        "production handles must reject the automatic CAS driver before entropy or writes"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
}

#[test]
fn subscription_replacement_purges_active_completed_and_bootstrap_records() {
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("replacement paired transfer tempdir");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical replacement paired transfer root")
        .join("paired-state");
    let fixture = PairingFixture::new();
    fixture.promote(&store, &state_root, 0x61);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let first = catalog_binding(&fixture);
    let first_durable = opened
        .install_stream_binding_for_automatic_harness(
            first.clone(),
            &mut DeterministicRng::new([0x62; 32]),
        )
        .unwrap();
    let empty = DurableLiveTransferStateV1::empty();
    let active = empty
        .clone()
        .accept_part(&first, first_catalog_part(), START_MS)
        .unwrap();
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &first_durable,
            &first_durable,
            &empty,
            active.state(),
            &mut DeterministicRng::new([0x63; 32]),
        )
        .unwrap();

    let mut second = first.clone();
    second.stream_generation = StreamGenerationId::from_bytes([0x92; 16]);
    let second_durable = opened
        .commit_subscription_bootstrap_for_automatic_harness(
            second.clone(),
            second.inner_cursor.clone(),
            &mut DeterministicRng::new([0x64; 32]),
        )
        .expect("replacement must purge the old active transfer");
    assert_eq!(
        opened.durable_transfer_state().unwrap(),
        DurableLiveTransferStateV1::empty()
    );

    let payload = vec![0x6a; 1_024];
    let identity = DurableStreamTransferIdentity::for_catalog(1, 1, &payload).unwrap();
    let complete = DurableLiveTransferStateV1::empty()
        .accept_part(
            &second,
            RuntimeTransferCarrierV1::new(
                identity.message_id(),
                RuntimeTransferChannel::Stream,
                TransferEnvelope::new(
                    identity.transfer_id(),
                    0,
                    1,
                    identity.total_sha256(),
                    identity.total_bytes(),
                    payload,
                )
                .unwrap(),
            ),
            START_MS + 2,
        )
        .unwrap();
    assert!(matches!(
        complete.outcome(),
        DurableTransferOutcomeV1::Complete { .. }
    ));
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &second_durable,
            &second_durable,
            &DurableLiveTransferStateV1::empty(),
            complete.state(),
            &mut DeterministicRng::new([0x65; 32]),
        )
        .unwrap();

    let mut third = second.clone();
    third.stream_generation = StreamGenerationId::from_bytes([0x93; 16]);
    let third_durable = opened
        .commit_subscription_bootstrap_for_automatic_harness(
            third.clone(),
            third.inner_cursor.clone(),
            &mut DeterministicRng::new([0x66; 32]),
        )
        .expect("replacement must purge the old completed tombstone");
    assert_eq!(
        opened.durable_transfer_state().unwrap(),
        DurableLiveTransferStateV1::empty()
    );

    let marker = DurableLiveTransferStateV1::empty()
        .abort_exact_binding(
            &third,
            None,
            DurableTransferBootstrapError::InvalidIdentity,
            START_MS + 3,
        )
        .unwrap();
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &third_durable,
            &third_durable,
            &DurableLiveTransferStateV1::empty(),
            marker.state(),
            &mut DeterministicRng::new([0x67; 32]),
        )
        .unwrap();
    opened
        .commit_subscription_bootstrap_for_automatic_harness(
            third.clone(),
            third.inner_cursor.clone(),
            &mut DeterministicRng::new([0x68; 32]),
        )
        .expect("same-binding bootstrap must purge the old bootstrap marker");
    assert_eq!(
        opened.durable_transfer_state().unwrap(),
        DurableLiveTransferStateV1::empty()
    );
    drop(opened);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
        .open_exact(fixture.identity())
        .expect("replacement cleanup must survive restart");
    assert_eq!(
        reopened.durable_transfer_state().unwrap(),
        DurableLiveTransferStateV1::empty()
    );
}

#[test]
fn malformed_and_noncanonical_transfer_records_fail_cold_open_without_rewrite() {
    for (index, label) in ["malformed", "trailing", "foreign-binding"]
        .into_iter()
        .enumerate()
    {
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("invalid paired transfer tempdir");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical invalid paired transfer root")
            .join(format!("paired-state-{index}"));
        let fixture = PairingFixture::new();
        fixture.promote(&store, &state_root, 0x71 + index as u8);
        let paired = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            Arc::new(NoopMutationObserver),
        );
        let mut opened = paired.open_exact(fixture.identity()).unwrap();
        let binding = catalog_binding(&fixture);
        opened
            .install_stream_binding_for_automatic_harness(
                binding.clone(),
                &mut DeterministicRng::new([0x73 + index as u8; 32]),
            )
            .unwrap();
        let mut record_binding = binding.clone();
        if index == 2 {
            record_binding.stream_generation = StreamGenerationId::from_bytes([0xa2; 16]);
        }
        let transition = DurableLiveTransferStateV1::empty()
            .accept_part(&record_binding, first_catalog_part(), START_MS)
            .unwrap();
        let records = if index == 0 {
            vec![b"not-a-canonical-adtf-record".to_vec()]
        } else if index == 1 {
            let mut raw = transition.record_bytes()[0].clone();
            raw.push(0);
            vec![raw]
        } else {
            transition.record_bytes().to_vec()
        };
        opened
            .replace_unchecked_transfer_records_for_automatic_harness(
                records,
                &mut DeterministicRng::new([0x75 + index as u8; 32]),
            )
            .expect("automatic harness persists unchecked V6 transfer records");
        let same_handle_files = file_tree_bytes(&state_root);
        let same_handle_keys = paired_key_bytes(&store, &fixture);
        assert_eq!(
            opened
                .replace_unchecked_transfer_records_for_automatic_harness(
                    Vec::new(),
                    &mut PanicRng,
                )
                .expect_err("same automatic handle must re-decode malformed V6 on refresh")
                .code(),
            "remote.pairing.paired_invalid",
            "{label}"
        );
        assert_eq!(file_tree_bytes(&state_root), same_handle_files, "{label}");
        assert_eq!(
            paired_key_bytes(&store, &fixture),
            same_handle_keys,
            "{label}"
        );
        drop(opened);

        let files_before = file_tree_bytes(&state_root);
        let keys_before = paired_key_bytes(&store, &fixture);
        let reader = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        assert_eq!(
            reader
                .list()
                .expect_err("invalid transfer list audit")
                .code(),
            "remote.pairing.paired_invalid",
            "{label}"
        );
        assert_eq!(
            reader
                .open_exact(fixture.identity())
                .expect_err("invalid transfer exact-open audit")
                .code(),
            "remote.pairing.paired_invalid",
            "{label}"
        );
        assert_eq!(file_tree_bytes(&state_root), files_before, "{label}");
        assert_eq!(paired_key_bytes(&store, &fixture), keys_before, "{label}");
    }
}

#[test]
fn unchecked_transfer_injection_is_automatic_only_and_keeps_structural_bounds() {
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("unchecked paired transfer tempdir");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical unchecked paired transfer root")
        .join("paired-state");
    let fixture = PairingFixture::new();
    fixture.promote(&store, &state_root, 0x81);

    let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut production_opened = production.open_exact(fixture.identity()).unwrap();
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    assert_eq!(
        production_opened
            .replace_unchecked_transfer_records_for_automatic_harness(
                vec![b"malformed".to_vec()],
                &mut PanicRng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_invalid"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    drop(production_opened);

    let automatic = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = automatic.open_exact(fixture.identity()).unwrap();
    for (label, records) in [
        (
            "record-count",
            vec![vec![1]; MAX_DURABLE_TRANSFER_RECORDS + 1],
        ),
        (
            "record-bytes",
            vec![vec![0x5a; MAX_DURABLE_TRANSFER_RECORD_BYTES + 1]],
        ),
    ] {
        let files_before = file_tree_bytes(&state_root);
        let keys_before = paired_key_bytes(&store, &fixture);
        assert_eq!(
            opened
                .replace_unchecked_transfer_records_for_automatic_harness(records, &mut PanicRng,)
                .unwrap_err()
                .code(),
            "remote.pairing.paired_invalid",
            "{label}"
        );
        assert_eq!(file_tree_bytes(&state_root), files_before, "{label}");
        assert_eq!(paired_key_bytes(&store, &fixture), keys_before, "{label}");
    }
}
