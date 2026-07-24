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
    CryptoStateIdentity, DeviceStorageKek, FileCryptoStateStore, MAX_CRYPTO_STATE_PLAINTEXT_LEN,
};
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::stream_state::DurableStreamBindingV1;
use agentdeck_cli::remote::transfer_state::{
    DurableLiveTransferStateV1, DurableTransferBootstrapError, DurableTransferOutcomeV1,
    DurableTransferStateError,
};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose, StreamBindingV1};
use agentdeck_protocol::relay_v2::{
    GrantSerial, KeyDirectoryRevision, RELAY_PROTOCOL_VERSION, StreamGenerationId, StreamRouteId,
    TrustEpoch,
};
use agentdeck_protocol::runtime::identity::{ConversationId, EventId};
use agentdeck_protocol::runtime::{
    DurableStreamTransferIdentity, DurableStreamTransferSource, MAX_PART_BYTES,
    RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, RuntimeTransferCarrierV1, RuntimeTransferChannel,
    StreamCursor, TransferEnvelope,
};

use remote_pairing::{
    CATALOG_EPOCH, CONVERSATION_EPOCH, DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION,
    PairingFixture, PanicRng,
};

const START_MS: u64 = 10_000;
const CATALOG_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const CONVERSATION_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x82; 16]);
const CONVERSATION_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x92; 16]);
const STREAM_STATE_VERSION: u16 = 3;
const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;

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
            panic!("injected transfer-state crash at {stage:?}");
        }
    }
}

#[derive(Clone, Copy)]
struct ReplayFixture {
    stream_seq: u64,
    sender_counter: u64,
    ciphertext_sha256: [u8; 32],
}

fn files_with_suffix(root: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut matches = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return matches;
    };
    for entry in entries {
        let path = entry.expect("read transfer-state fixture entry").path();
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
        let path = entry.expect("read transfer-state fixture tree").path();
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

fn catalog_binding(
    fixture: &PairingFixture,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    inner_cursor: StreamCursor,
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
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: inner_cursor,
        },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
    }
}

fn conversation_binding(fixture: &PairingFixture, conversation_id: &str) -> StreamBindingV1 {
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
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(conversation_id),
            cursor: StreamCursor::At(12),
        },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: CONVERSATION_EPOCH,
        },
    }
}

fn put_cursor(output: &mut Vec<u8>, cursor: StreamCursor) {
    match cursor {
        StreamCursor::BeforeFirst => {
            output.push(0);
            output.extend_from_slice(&0_u64.to_be_bytes());
        }
        StreamCursor::At(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn put_inner_cursor(output: &mut Vec<u8>, cursor: &RuntimeInnerCursor) {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor } => {
            output.push(0);
            put_cursor(output, *cursor);
        }
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } => {
            output.push(1);
            let identity = conversation_id.as_str().as_bytes();
            output.extend_from_slice(&(identity.len() as u32).to_be_bytes());
            output.extend_from_slice(identity);
            put_cursor(output, *cursor);
        }
    }
}

fn durable_binding_state(
    binding: &StreamBindingV1,
    outer_applied: StreamCursor,
    inner_observed: RuntimeInnerCursor,
    inner_applied: RuntimeInnerCursor,
    replay: &[ReplayFixture],
) -> DurableStreamBindingV1 {
    durable_binding_state_with_ledgers(
        binding,
        outer_applied,
        inner_observed,
        inner_applied,
        (binding.stream_route, binding.stream_generation),
        replay,
        &[],
    )
}

fn durable_binding_state_with_ledgers(
    binding: &StreamBindingV1,
    outer_applied: StreamCursor,
    inner_observed: RuntimeInnerCursor,
    inner_applied: RuntimeInnerCursor,
    replay_subscription: (StreamRouteId, StreamGenerationId),
    replay: &[ReplayFixture],
    retired: &[(StreamRouteId, StreamGenerationId)],
) -> DurableStreamBindingV1 {
    let canonical_binding = binding.canonical_bytes().expect("canonical stream binding");
    let mut body = Vec::new();
    body.extend_from_slice(&(canonical_binding.len() as u32).to_be_bytes());
    body.extend_from_slice(&canonical_binding);
    put_cursor(&mut body, outer_applied);
    put_cursor(&mut body, StreamCursor::BeforeFirst);
    put_inner_cursor(&mut body, &inner_observed);
    put_inner_cursor(&mut body, &inner_applied);
    body.push(0);
    body.extend_from_slice(&(replay.len() as u32).to_be_bytes());
    for entry in replay {
        body.extend_from_slice(replay_subscription.0.as_bytes());
        body.extend_from_slice(replay_subscription.1.as_bytes());
        body.extend_from_slice(&entry.stream_seq.to_be_bytes());
        body.extend_from_slice(&entry.sender_counter.to_be_bytes());
        body.extend_from_slice(&entry.ciphertext_sha256);
    }
    body.extend_from_slice(&(retired.len() as u32).to_be_bytes());
    for (stream_route, stream_generation) in retired {
        body.extend_from_slice(stream_route.as_bytes());
        body.extend_from_slice(stream_generation.as_bytes());
    }

    let mut canonical = Vec::with_capacity(12 + body.len());
    canonical.extend_from_slice(b"ADSB");
    canonical.extend_from_slice(&STREAM_STATE_VERSION.to_be_bytes());
    canonical.extend_from_slice(&[0, 0]);
    canonical.extend_from_slice(&(body.len() as u32).to_be_bytes());
    canonical.extend_from_slice(&body);
    DurableStreamBindingV1::from_canonical_bytes(&canonical)
        .expect("strict advanced stream binding fixture")
}

fn carrier(
    identity: DurableStreamTransferIdentity,
    part_index: u32,
    part: Vec<u8>,
) -> RuntimeTransferCarrierV1 {
    RuntimeTransferCarrierV1::new(
        identity.message_id(),
        RuntimeTransferChannel::Stream,
        TransferEnvelope::new(
            identity.transfer_id(),
            part_index,
            identity.part_count(),
            identity.total_sha256(),
            identity.total_bytes(),
            part,
        )
        .expect("bounded transfer fixture"),
    )
}

fn split_catalog(
    first_revision: u64,
    through_revision: u64,
) -> (Vec<u8>, RuntimeTransferCarrierV1, RuntimeTransferCarrierV1) {
    let payload = vec![0x5a; MAX_PART_BYTES + 1];
    let identity =
        DurableStreamTransferIdentity::for_catalog(first_revision, through_revision, &payload)
            .expect("bounded multi-revision catalog identity");
    let first = carrier(identity, 0, payload[..MAX_PART_BYTES].to_vec());
    let final_part = carrier(identity, 1, payload[MAX_PART_BYTES..].to_vec());
    (payload, first, final_part)
}

fn assert_persisted_pair(
    opened: &agentdeck_cli::remote::paired_machine::OpenedPairedMachine<'_>,
    expected_binding: &DurableStreamBindingV1,
    expected_transfer: &DurableLiveTransferStateV1,
) {
    assert_eq!(
        opened.durable_stream_bindings().unwrap(),
        std::slice::from_ref(expected_binding)
    );
    assert_eq!(opened.durable_transfer_state().unwrap(), *expected_transfer);
}

#[test]
fn legacy_empty_middle_part_and_catalog_completion_share_one_paired_cas() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("transfer persistence root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical transfer persistence root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x21);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    assert_eq!(
        opened.durable_transfer_state().unwrap(),
        DurableLiveTransferStateV1::empty(),
        "legacy paired state must decode as an empty transfer collection"
    );

    let binding = catalog_binding(
        &fixture,
        CATALOG_ROUTE,
        CATALOG_GENERATION,
        StreamCursor::At(6),
    );
    let mut install_rng = DeterministicRng::new([0x22; 32]);
    let installed = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut install_rng)
        .unwrap();
    let (payload, first, final_part) = split_catalog(7, 9);
    let empty = DurableLiveTransferStateV1::empty();
    let middle_transition = empty
        .clone()
        .accept_part(&binding, first, START_MS)
        .expect("buffer authenticated first part");
    assert_eq!(middle_transition.record_bytes().len(), 2);
    let middle = middle_transition.into_state();
    let middle_admitted = durable_binding_state(
        &binding,
        StreamCursor::BeforeFirst,
        binding.inner_cursor.clone(),
        binding.inner_cursor.clone(),
        &[ReplayFixture {
            stream_seq: 0,
            sender_counter: 41,
            ciphertext_sha256: [0x31; 32],
        }],
    );
    let mut admission_rng = DeterministicRng::new([0x23; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &installed,
            &middle_admitted,
            &empty,
            &empty,
            &mut admission_rng,
        )
        .expect("replay admission must be durable before TransferPart open/apply");
    let middle_binding = durable_binding_state(
        &binding,
        StreamCursor::At(0),
        binding.inner_cursor.clone(),
        binding.inner_cursor.clone(),
        &[ReplayFixture {
            stream_seq: 0,
            sender_counter: 41,
            ciphertext_sha256: [0x31; 32],
        }],
    );
    let mut middle_rng = DeterministicRng::new([0x24; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &middle_admitted,
            &middle_binding,
            &empty,
            &middle,
            &mut middle_rng,
        )
        .expect("admitted replay must stay fixed while outer and active records commit");
    assert_eq!(middle_binding.outer_applied(), StreamCursor::At(0));
    assert_eq!(middle_binding.inner_applied(), &binding.inner_cursor);
    assert_persisted_pair(&opened, &middle_binding, &middle);
    drop(opened);

    let restarted = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    assert_eq!(restarted.list().unwrap().len(), 1);
    let mut reopened = restarted.open_exact(fixture.identity()).unwrap();
    assert_persisted_pair(&reopened, &middle_binding, &middle);

    let complete = middle
        .clone()
        .accept_part(&binding, final_part, START_MS + 1)
        .expect("complete authenticated catalog range");
    match complete.outcome() {
        DurableTransferOutcomeV1::Complete {
            payload: assembled,
            source:
                DurableStreamTransferSource::Catalog {
                    first_revision,
                    through_revision,
                },
        } => {
            assert_eq!(assembled, &payload);
            assert_eq!((*first_revision, *through_revision), (7, 9));
        }
        other => panic!("expected completed catalog transfer, got {other:?}"),
    }
    let completed = complete.into_state();
    let completed_admitted = durable_binding_state(
        &binding,
        StreamCursor::At(0),
        binding.inner_cursor.clone(),
        binding.inner_cursor.clone(),
        &[
            ReplayFixture {
                stream_seq: 0,
                sender_counter: 41,
                ciphertext_sha256: [0x31; 32],
            },
            ReplayFixture {
                stream_seq: 1,
                sender_counter: 42,
                ciphertext_sha256: [0x32; 32],
            },
        ],
    );
    let mut final_admission_rng = DeterministicRng::new([0x25; 32]);
    reopened
        .commit_stream_transfer_transition_for_automatic_harness(
            &middle_binding,
            &completed_admitted,
            &middle,
            &middle,
            &mut final_admission_rng,
        )
        .expect("final-part replay tuple must be durable before open/apply");

    let completed_binding = durable_binding_state(
        &binding,
        StreamCursor::At(1),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(9),
        },
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(9),
        },
        &[
            ReplayFixture {
                stream_seq: 0,
                sender_counter: 41,
                ciphertext_sha256: [0x31; 32],
            },
            ReplayFixture {
                stream_seq: 1,
                sender_counter: 42,
                ciphertext_sha256: [0x32; 32],
            },
        ],
    );
    let mut complete_rng = DeterministicRng::new([0x26; 32]);
    reopened
        .commit_stream_transfer_transition_for_automatic_harness(
            &completed_admitted,
            &completed_binding,
            &middle,
            &completed,
            &mut complete_rng,
        )
        .expect("outer+inner and completed tombstone must commit together");
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    let mut panic_rng = PanicRng;
    let replayed = reopened
        .commit_stream_transfer_transition_for_automatic_harness(
            &completed_admitted,
            &completed_binding,
            &middle,
            &completed,
            &mut panic_rng,
        )
        .expect("exact combined-CAS retry must not consume entropy or rewrite state");
    assert_eq!(replayed, (completed_binding.clone(), completed.clone()));
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    assert_eq!(completed.active_count(), 0);
    assert_eq!(completed.completed_count(), 1);
    assert_persisted_pair(&reopened, &completed_binding, &completed);
}

#[test]
fn event_completion_commits_exact_conversation_target_and_event_sequence() {
    let conversation = "11111111-1111-4111-8111-000000000051";
    let event = "11111111-1111-4111-8111-000000000052";
    let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_ROUTE);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("event transfer root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical event transfer root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x31);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let binding = conversation_binding(&fixture, conversation);
    let mut install_rng = DeterministicRng::new([0x32; 32]);
    let installed = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut install_rng)
        .unwrap();
    let payload = b"canonical-event".to_vec();
    let identity = DurableStreamTransferIdentity::for_event(
        &ConversationId::new(conversation),
        &EventId::new(event),
        13,
        &payload,
    )
    .unwrap();
    let empty = DurableLiveTransferStateV1::empty();
    let transition = empty
        .clone()
        .accept_part(&binding, carrier(identity, 0, payload.clone()), START_MS)
        .unwrap();
    match transition.outcome() {
        DurableTransferOutcomeV1::Complete {
            payload: assembled,
            source:
                DurableStreamTransferSource::Event {
                    conversation_id,
                    event_id,
                    event_seq,
                },
        } => {
            assert_eq!(assembled, &payload);
            assert_eq!(conversation_id.to_string(), conversation);
            assert_eq!(event_id.to_string(), event);
            assert_eq!(*event_seq, 13);
        }
        other => panic!("expected completed Event transfer, got {other:?}"),
    }
    let completed = transition.into_state();
    let completed_admitted = durable_binding_state(
        &binding,
        StreamCursor::BeforeFirst,
        binding.inner_cursor.clone(),
        binding.inner_cursor.clone(),
        &[ReplayFixture {
            stream_seq: 0,
            sender_counter: 51,
            ciphertext_sha256: [0x41; 32],
        }],
    );
    let mut admission_rng = DeterministicRng::new([0x33; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &installed,
            &completed_admitted,
            &empty,
            &empty,
            &mut admission_rng,
        )
        .expect("Event replay tuple must be durable before open/apply");
    let completed_binding = durable_binding_state(
        &binding,
        StreamCursor::At(0),
        RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(conversation),
            cursor: StreamCursor::At(13),
        },
        RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(conversation),
            cursor: StreamCursor::At(13),
        },
        &[ReplayFixture {
            stream_seq: 0,
            sender_counter: 51,
            ciphertext_sha256: [0x41; 32],
        }],
    );
    let mut rng = DeterministicRng::new([0x34; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &completed_admitted,
            &completed_binding,
            &empty,
            &completed,
            &mut rng,
        )
        .expect("Event outer+inner+tombstone must commit together");
    assert_persisted_pair(&opened, &completed_binding, &completed);
}

#[test]
fn stale_cas_and_offline_record_tamper_fail_closed_without_rewrites() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("stale transfer root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical stale transfer root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x41);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let binding = catalog_binding(
        &fixture,
        CATALOG_ROUTE,
        CATALOG_GENERATION,
        StreamCursor::At(16),
    );
    let mut install_rng = DeterministicRng::new([0x42; 32]);
    let installed = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut install_rng)
        .unwrap();
    let (_payload, first, final_part) = split_catalog(17, 18);
    let empty = DurableLiveTransferStateV1::empty();
    let middle = empty
        .clone()
        .accept_part(&binding, first, START_MS)
        .unwrap()
        .into_state();
    let middle_admitted = durable_binding_state(
        &binding,
        StreamCursor::BeforeFirst,
        binding.inner_cursor.clone(),
        binding.inner_cursor.clone(),
        &[ReplayFixture {
            stream_seq: 0,
            sender_counter: 61,
            ciphertext_sha256: [0x51; 32],
        }],
    );
    let mut admission_rng = DeterministicRng::new([0x43; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &installed,
            &middle_admitted,
            &empty,
            &empty,
            &mut admission_rng,
        )
        .unwrap();
    let middle_binding = durable_binding_state(
        &binding,
        StreamCursor::At(0),
        binding.inner_cursor.clone(),
        binding.inner_cursor.clone(),
        &[ReplayFixture {
            stream_seq: 0,
            sender_counter: 61,
            ciphertext_sha256: [0x51; 32],
        }],
    );
    let mut middle_rng = DeterministicRng::new([0x44; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &middle_admitted,
            &middle_binding,
            &empty,
            &middle,
            &mut middle_rng,
        )
        .unwrap();
    let completed = middle
        .clone()
        .accept_part(&binding, final_part, START_MS + 1)
        .unwrap()
        .into_state();
    let completed_admitted = durable_binding_state(
        &binding,
        StreamCursor::At(0),
        binding.inner_cursor.clone(),
        binding.inner_cursor.clone(),
        &[
            ReplayFixture {
                stream_seq: 0,
                sender_counter: 61,
                ciphertext_sha256: [0x51; 32],
            },
            ReplayFixture {
                stream_seq: 1,
                sender_counter: 62,
                ciphertext_sha256: [0x52; 32],
            },
        ],
    );
    let completed_binding = durable_binding_state(
        &binding,
        StreamCursor::At(1),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(18),
        },
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(18),
        },
        &[
            ReplayFixture {
                stream_seq: 0,
                sender_counter: 61,
                ciphertext_sha256: [0x51; 32],
            },
            ReplayFixture {
                stream_seq: 1,
                sender_counter: 62,
                ciphertext_sha256: [0x52; 32],
            },
        ],
    );
    let mut final_admission_rng = DeterministicRng::new([0x45; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &middle_binding,
            &completed_admitted,
            &middle,
            &middle,
            &mut final_admission_rng,
        )
        .unwrap();
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    let mut panic_rng = PanicRng;
    let replayed = opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &middle_binding,
            &completed_admitted,
            &middle,
            &middle,
            &mut panic_rng,
        )
        .expect("exact replay-admission retry must not consume entropy or rewrite state");
    assert_eq!(replayed, (completed_admitted.clone(), middle.clone()));
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    assert_eq!(
        opened
            .commit_stream_transfer_transition_for_automatic_harness(
                &middle_binding,
                &completed_binding,
                &middle,
                &completed,
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
            .commit_stream_transfer_transition_for_automatic_harness(
                &completed_admitted,
                &completed_binding,
                &empty,
                &completed,
                &mut panic_rng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);

    let mut malformed = middle.canonical_record_bytes().unwrap();
    malformed[0].push(0);
    assert_eq!(
        DurableLiveTransferStateV1::from_record_bytes(&malformed).unwrap_err(),
        DurableTransferStateError::InvalidRecord
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    drop(opened);

    let state_files = files_with_suffix(&state_root, ".crypto-state.v1");
    assert_eq!(state_files.len(), 1);
    let mut tampered = fs::read(&state_files[0]).unwrap();
    *tampered.last_mut().expect("sealed state has an AEAD tag") ^= 1;
    fs::write(&state_files[0], &tampered).unwrap();
    let tampered_tree = file_tree_bytes(&state_root);
    let tampered_keys = paired_key_bytes(&store, &fixture);
    let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert_eq!(
        production.list().unwrap_err().code(),
        "remote.crypto_state.authentication_failed"
    );
    assert_eq!(file_tree_bytes(&state_root), tampered_tree);
    assert_eq!(paired_key_bytes(&store, &fixture), tampered_keys);
    assert_eq!(
        production
            .open_exact(fixture.identity())
            .unwrap_err()
            .code(),
        "remote.crypto_state.authentication_failed"
    );
    assert_eq!(file_tree_bytes(&state_root), tampered_tree);
    assert_eq!(paired_key_bytes(&store, &fixture), tampered_keys);
}

#[test]
fn every_paired_state_crash_cut_recovers_the_binding_and_transfer_pair() {
    for (index, stage) in [
        PairedMutationStage::StateStageDurable,
        PairedMutationStage::StateGuardPendingDurable,
        PairedMutationStage::StateActiveDurable,
        PairedMutationStage::StateGuardStableDurable,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("transfer crash root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical transfer crash root")
            .join(format!("paired-state-{index}"));
        fixture.promote(&store, &state_root, 0x51 + index as u8);
        let automatic = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            Arc::new(NoopMutationObserver),
        );
        let mut opened = automatic.open_exact(fixture.identity()).unwrap();
        let binding = catalog_binding(
            &fixture,
            CATALOG_ROUTE,
            CATALOG_GENERATION,
            StreamCursor::At(26),
        );
        let mut install_rng = DeterministicRng::new([0x61 + index as u8; 32]);
        let installed = opened
            .install_stream_binding_for_automatic_harness(binding.clone(), &mut install_rng)
            .unwrap();
        drop(opened);

        let empty = DurableLiveTransferStateV1::empty();
        let (_payload, first, _) = split_catalog(27, 28);
        let middle = empty
            .clone()
            .accept_part(&binding, first, START_MS)
            .unwrap()
            .into_state();
        let middle_admitted = durable_binding_state(
            &binding,
            StreamCursor::BeforeFirst,
            binding.inner_cursor.clone(),
            binding.inner_cursor.clone(),
            &[ReplayFixture {
                stream_seq: 0,
                sender_counter: 71,
                ciphertext_sha256: [0x61; 32],
            }],
        );
        let mut admission_opened = automatic.open_exact(fixture.identity()).unwrap();
        let mut admission_rng = DeterministicRng::new([0x69 + index as u8; 32]);
        admission_opened
            .commit_stream_transfer_transition_for_automatic_harness(
                &installed,
                &middle_admitted,
                &empty,
                &empty,
                &mut admission_rng,
            )
            .unwrap();
        drop(admission_opened);
        let middle_binding = durable_binding_state(
            &binding,
            StreamCursor::At(0),
            binding.inner_cursor.clone(),
            binding.inner_cursor.clone(),
            &[ReplayFixture {
                stream_seq: 0,
                sender_counter: 71,
                ciphertext_sha256: [0x61; 32],
            }],
        );
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
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let mut rng = DeterministicRng::new([0x71 + index as u8; 32]);
            opened
                .commit_stream_transfer_transition_for_automatic_harness(
                    &middle_admitted,
                    &middle_binding,
                    &empty,
                    &middle,
                    &mut rng,
                )
                .expect("observer must terminate the paired transaction");
        }));
        assert!(crashed.is_err(), "{stage:?} must inject one crash");
        assert!(observer.fired.load(Ordering::SeqCst));
        drop(opened);

        let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        assert_eq!(restarted.list().unwrap().len(), 1, "{stage:?}");
        let reopened = restarted.open_exact(fixture.identity()).unwrap();
        if stage == PairedMutationStage::StateStageDurable {
            assert_persisted_pair(&reopened, &middle_admitted, &empty);
        } else {
            assert_persisted_pair(&reopened, &middle_binding, &middle);
        }
        assert!(
            files_with_suffix(&state_root, ".crypto-state-stage.v1").is_empty(),
            "{stage:?} recovery must clear the prepared sidecar"
        );
    }
}

#[test]
fn binding_replacement_cleans_old_exact_active_or_marker_but_same_binding_reopen_preserves_it() {
    for marker in [false, true] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("binding replacement root");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonical binding replacement root")
            .join(if marker {
                "paired-state-marker"
            } else {
                "paired-state-active"
            });
        fixture.promote(&store, &state_root, 0x81 + u8::from(marker));
        let paired = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            Arc::new(NoopMutationObserver),
        );
        let mut opened = paired.open_exact(fixture.identity()).unwrap();
        let binding = catalog_binding(
            &fixture,
            CATALOG_ROUTE,
            CATALOG_GENERATION,
            StreamCursor::At(36),
        );
        let mut install_rng = DeterministicRng::new([0x82 + u8::from(marker); 32]);
        let installed = opened
            .install_stream_binding_for_automatic_harness(binding.clone(), &mut install_rng)
            .unwrap();
        let empty = DurableLiveTransferStateV1::empty();
        let current = if marker {
            empty
                .clone()
                .abort_exact_binding(
                    &binding,
                    None,
                    DurableTransferBootstrapError::PayloadRejected,
                    START_MS,
                )
                .unwrap()
                .into_state()
        } else {
            let (_payload, first, _) = split_catalog(37, 38);
            empty
                .clone()
                .accept_part(&binding, first, START_MS)
                .unwrap()
                .into_state()
        };
        let (expected_binding, current_binding) = if marker {
            (installed.clone(), installed.clone())
        } else {
            let admitted = durable_binding_state(
                &binding,
                StreamCursor::BeforeFirst,
                binding.inner_cursor.clone(),
                binding.inner_cursor.clone(),
                &[ReplayFixture {
                    stream_seq: 0,
                    sender_counter: 81,
                    ciphertext_sha256: [0x71; 32],
                }],
            );
            let mut admission_rng = DeterministicRng::new([0x83; 32]);
            opened
                .commit_stream_transfer_transition_for_automatic_harness(
                    &installed,
                    &admitted,
                    &empty,
                    &empty,
                    &mut admission_rng,
                )
                .unwrap();
            let applied = durable_binding_state(
                &binding,
                StreamCursor::At(0),
                binding.inner_cursor.clone(),
                binding.inner_cursor.clone(),
                &[ReplayFixture {
                    stream_seq: 0,
                    sender_counter: 81,
                    ciphertext_sha256: [0x71; 32],
                }],
            );
            (admitted, applied)
        };
        let mut persist_rng = DeterministicRng::new([0x84 + u8::from(marker); 32]);
        opened
            .commit_stream_transfer_transition_for_automatic_harness(
                &expected_binding,
                &current_binding,
                &empty,
                &current,
                &mut persist_rng,
            )
            .unwrap();
        drop(opened);

        let mut reopened = paired.open_exact(fixture.identity()).unwrap();
        assert_persisted_pair(&reopened, &current_binding, &current);
        assert_eq!(current.active_count(), usize::from(!marker));
        assert_eq!(current.marker_count(), usize::from(marker));

        let replacement_wire = catalog_binding(
            &fixture,
            StreamRouteId::from_bytes([0x83; 16]),
            StreamGenerationId::from_bytes([0x93; 16]),
            StreamCursor::At(36),
        );
        let preserved_replay = [ReplayFixture {
            stream_seq: 0,
            sender_counter: 81,
            ciphertext_sha256: [0x71; 32],
        }];
        let replacement = durable_binding_state_with_ledgers(
            &replacement_wire,
            StreamCursor::BeforeFirst,
            replacement_wire.inner_cursor.clone(),
            replacement_wire.inner_cursor.clone(),
            (CATALOG_ROUTE, CATALOG_GENERATION),
            if marker { &[] } else { &preserved_replay },
            &[(CATALOG_ROUTE, CATALOG_GENERATION)],
        );
        let cleaned = current.clone().purge_exact_binding(&binding).unwrap();
        assert_eq!(cleaned.active_count(), 0);
        assert_eq!(cleaned.marker_count(), 0);
        let mut replace_rng = DeterministicRng::new([0x86 + u8::from(marker); 32]);
        let committed = reopened
            .commit_subscription_bootstrap_for_automatic_harness(
                replacement_wire,
                replacement.inner_applied().clone(),
                &mut replace_rng,
            )
            .expect("subscription replacement and exact transfer purge must be one CAS");
        assert_eq!(committed, replacement);
        assert_persisted_pair(&reopened, &replacement, &cleaned);
    }
}

fn push_incomplete_part(
    state: DurableLiveTransferStateV1,
    binding: &StreamBindingV1,
    identity: DurableStreamTransferIdentity,
    part_index: u32,
    part_len: usize,
    now_ms: u64,
) -> DurableLiveTransferStateV1 {
    let transition = state
        .accept_part(
            binding,
            carrier(identity, part_index, vec![part_index as u8; part_len]),
            now_ms,
        )
        .expect("bounded incomplete part");
    assert!(matches!(
        transition.outcome(),
        DurableTransferOutcomeV1::Buffered { .. }
    ));
    transition.into_state()
}

#[test]
fn full_paired_plaintext_capacity_is_typed_and_allows_a_durable_bootstrap_marker() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("transfer cap root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical transfer cap root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x91);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired.open_exact(fixture.identity()).unwrap();
    let binding = catalog_binding(
        &fixture,
        CATALOG_ROUTE,
        CATALOG_GENERATION,
        StreamCursor::BeforeFirst,
    );
    let mut install_rng = DeterministicRng::new([0x92; 32]);
    let installed = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut install_rng)
        .unwrap();
    let empty = DurableLiveTransferStateV1::empty();
    let mut near_limit = empty.clone();
    let mut now_ms = START_MS;
    for (revision, digest) in [(101, [0xa1; 32]), (102, [0xa2; 32])] {
        let identity = DurableStreamTransferIdentity::from_catalog_metadata(
            revision,
            revision,
            MAX_TRANSFER_BYTES,
            digest,
        )
        .unwrap();
        for part_index in 0..18 {
            near_limit = push_incomplete_part(
                near_limit,
                &binding,
                identity,
                part_index,
                MAX_PART_BYTES,
                now_ms,
            );
            now_ms += 1;
        }
    }
    let tail_identity = DurableStreamTransferIdentity::from_catalog_metadata(
        103,
        103,
        MAX_TRANSFER_BYTES,
        [0xa3; 32],
    )
    .unwrap();
    near_limit = push_incomplete_part(near_limit, &binding, tail_identity, 0, 1024 * 1024, now_ms);
    assert_eq!(near_limit.buffered_bytes(), 127 * 1024 * 1024);

    let mut near_rng = DeterministicRng::new([0x93; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &installed,
            &installed,
            &empty,
            &near_limit,
            &mut near_rng,
        )
        .expect("127 MiB records plus paired envelope must remain representable");
    let plaintext = paired_state_plaintext(&store, &fixture, &state_root);
    assert!(plaintext.len() <= MAX_CRYPTO_STATE_PLAINTEXT_LEN);
    assert!(
        plaintext.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN - 2 * 1024 * 1024,
        "accepted candidate must exercise the full-state boundary"
    );

    let over_limit = push_incomplete_part(
        near_limit.clone(),
        &binding,
        tail_identity,
        1,
        1024 * 1024,
        now_ms + 1,
    );
    assert_eq!(
        over_limit.buffered_bytes(),
        MAX_CRYPTO_STATE_PLAINTEXT_LEN as u64
    );
    let files_before = file_tree_bytes(&state_root);
    let keys_before = paired_key_bytes(&store, &fixture);
    let mut panic_rng = PanicRng;
    assert_eq!(
        opened
            .commit_stream_transfer_transition_for_automatic_harness(
                &installed,
                &installed,
                &near_limit,
                &over_limit,
                &mut panic_rng,
            )
            .unwrap_err()
            .code(),
        "remote.pairing.paired_capacity"
    );
    assert_eq!(file_tree_bytes(&state_root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    assert_eq!(opened.durable_transfer_state().unwrap(), near_limit);

    let transfer_id = tail_identity.transfer_id();
    let marker = near_limit
        .clone()
        .abort_exact_binding(
            &binding,
            Some(&transfer_id),
            DurableTransferBootstrapError::ReassemblyFull,
            now_ms + 1,
        )
        .expect("capacity fallback must build one canonical bootstrap marker")
        .into_state();
    assert_eq!(marker.active_count(), 0);
    assert_eq!(marker.marker_count(), 1);
    assert_eq!(marker.buffered_bytes(), 0);
    let mut marker_rng = DeterministicRng::new([0x94; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &installed,
            &installed,
            &near_limit,
            &marker,
            &mut marker_rng,
        )
        .expect("the compact reassembly-full marker must fit after exact binding purge");
    assert_eq!(opened.durable_transfer_state().unwrap(), marker);
}
