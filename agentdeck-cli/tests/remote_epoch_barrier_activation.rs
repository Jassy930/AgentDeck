#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::collections::VecDeque;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
use agentdeck_cli::remote::pending::PendingPairingCoordinator;
use agentdeck_cli::remote::runtime::{
    ExactRelayFrame, ReceivedRuntimeFrame, RemoteRuntime, RemoteRuntimeError,
    RemoteRuntimeTransport, RemoteRuntimeTransportError, RemoteStreamFrameOutcome,
    RemoteSubscriptionBootstrapItem, RemoteSubscriptionReducer,
};
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, HpkeEnvelopeV1, HpkePublicKey, SecretAeadKey, SenderCounter,
    VerifyingKey, hpke_seal_base, open_sealed_payload, seal_symmetric, sha256, sign_key_update,
    sign_sealed, verify_sealed,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, EpochBarrierV1, KeyControlRequestV1, KeyControlV1, KeyId, KeyPurpose,
    KeyUpdateInfoV1, KeyUpdateSetV1, KeyUpdateV1, MachineDataSignerBindingV1, OuterContextV1,
    OuterFrameKind, SignedSealedBlobV1, StreamAppliedAckV1, StreamBindingV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, Publish, RouteAccepted, SealedBlob, Send};
use agentdeck_protocol::relay_v2::{
    Ed25519Signature, GrantSerial, KeyDirectoryRevision, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RequestRouteId, StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};
use agentdeck_protocol::runtime::{
    RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, RuntimeStreamItem, StreamCursor,
};
use async_trait::async_trait;

use remote_pairing::{
    CATALOG_EPOCH, DEVICE_COMMAND_EPOCH, DEVICE_COMMAND_KEY, DEVICE_REPLY_EPOCH, DEVICE_REPLY_KEY,
    DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION, NOW_MS, PairingFixture,
};

const STARTED_AT_MS: u64 = 1_000_000;
const CATALOG_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const OUTER_HIGH_WATER: u64 = 5;
const INNER_HIGH_WATER: u64 = 3;
const UPDATE_REVISION: u64 = KEY_DIRECTORY_REVISION + 1;
const NEW_CATALOG_KEY: [u8; 32] = [0x81; 32];
const BARRIER_COUNTER: u64 = 23;

struct NoopMutationObserver;

impl PairedMutationObserver for NoopMutationObserver {
    fn after_stage(&self, _stage: PairedMutationStage) {}
}

struct PanicOnNthStage {
    stage: PairedMutationStage,
    occurrence: usize,
    seen: AtomicUsize,
}

impl PairedMutationObserver for PanicOnNthStage {
    fn after_stage(&self, stage: PairedMutationStage) {
        if stage == self.stage && self.seen.fetch_add(1, Ordering::SeqCst) + 1 == self.occurrence {
            panic!("injected EpochBarrier crash at {stage:?}");
        }
    }
}

#[derive(Clone)]
struct CatalogReducer {
    cursor: RuntimeInnerCursor,
}

impl CatalogReducer {
    fn at_barrier_cut() -> Self {
        Self {
            cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(INNER_HIGH_WATER),
            },
        }
    }
}

impl RemoteSubscriptionReducer for CatalogReducer {
    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, _item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        panic!("EpochBarrier must not enter the bootstrap reducer")
    }

    fn apply_live(&mut self, _item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        panic!("EpochBarrier must not enter the business stream reducer")
    }
}

struct BarrierTransport {
    inbound: VecDeque<ReceivedRuntimeFrame>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    queue_stream_applied_ack_route_accepted: bool,
    fail_first_stream_applied_ack_send: bool,
}

impl BarrierTransport {
    fn new(frame: OpaqueRouteFrame) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::from([received_exact(frame)]),
                sent: Arc::clone(&sent),
                queue_stream_applied_ack_route_accepted: false,
                fail_first_stream_applied_ack_send: false,
            },
            sent,
        )
    }

    fn empty() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::new(),
                sent: Arc::clone(&sent),
                queue_stream_applied_ack_route_accepted: false,
                fail_first_stream_applied_ack_send: false,
            },
            sent,
        )
    }

    fn with_stream_applied_ack_route_accepted(mut self) -> Self {
        self.queue_stream_applied_ack_route_accepted = true;
        self
    }

    fn with_first_stream_applied_ack_send_failure(mut self) -> Self {
        self.fail_first_stream_applied_ack_send = true;
        self
    }
}

#[async_trait]
impl RemoteRuntimeTransport for BarrierTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        let bytes = frame.into_bytes();
        self.sent
            .lock()
            .expect("barrier outbound recorder")
            .push(bytes.clone());
        let decoded = decode(&bytes).expect("decode recorded EpochBarrier outbound");
        if self.fail_first_stream_applied_ack_send
            && matches!(&decoded.body, RelayFrameBody::Send(_))
        {
            self.fail_first_stream_applied_ack_send = false;
            return Err(RemoteRuntimeTransportError::Failed(
                "injected StreamAppliedAck send failure".into(),
            ));
        }
        if self.queue_stream_applied_ack_route_accepted
            && let RelayFrameBody::Send(send) = decoded.body
        {
            self.inbound.push_back(received_exact(OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::RouteAccepted(RouteAccepted {
                    accepted: AcceptedRef::Request {
                        request_route: send.request_route,
                    },
                }),
            }));
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        Ok(self.inbound.pop_front())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct DurableSnapshot {
    sealed_state_files: Vec<(PathBuf, Vec<u8>)>,
    paired_keychain_accounts: Vec<(PairedRemoteKeyPurpose, Option<Vec<u8>>)>,
}

struct StagedBarrierFixture {
    pairing: PairingFixture,
    store: MemoryRemoteKeyStore,
    state_root: PathBuf,
    device_sign: VerifyingKey,
    frame: OpaqueRouteFrame,
}

fn state_root(temp: &tempfile::TempDir, case: &str) -> PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical epoch-barrier tempdir")
        .join(case)
}

fn received_exact(frame: OpaqueRouteFrame) -> ReceivedRuntimeFrame {
    let canonical = encode(&frame);
    ReceivedRuntimeFrame::from_untrusted_parts(frame, canonical)
}

fn file_tree_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut snapshot = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return snapshot;
    };
    for entry in entries {
        let path = entry.expect("read epoch-barrier state entry").path();
        if path.is_dir() {
            snapshot.extend(file_tree_bytes(&path));
        } else if path.is_file() {
            snapshot.push((
                path.clone(),
                fs::read(path).expect("snapshot epoch-barrier durable bytes"),
            ));
        }
    }
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    snapshot
}

fn paired_keychain_accounts(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
) -> Vec<(PairedRemoteKeyPurpose, Option<Vec<u8>>)> {
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
        let value = store
            .load(&account)
            .expect("snapshot paired Keychain account")
            .map(|secret| secret.expose_secret().to_vec());
        (purpose, value)
    })
    .collect()
}

fn durable_snapshot(fixture: &StagedBarrierFixture) -> DurableSnapshot {
    DurableSnapshot {
        sealed_state_files: file_tree_bytes(&fixture.state_root),
        paired_keychain_accounts: paired_keychain_accounts(&fixture.pairing, &fixture.store),
    }
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
        stream_cursor: StreamCursor::At(OUTER_HIGH_WATER),
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
    }
}

fn promote_and_install_binding(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
    root: &Path,
    seed: u8,
) -> (HpkePublicKey, VerifyingKey) {
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
    let device_sign = VerifyingKey::from_bytes(&prepared.device_sign_public_key())
        .expect("generated DeviceSign public key");
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
    PairedPromotionCoordinator::new(store, INSTALLATION_ID, root)
        .promote(verified, &mut promotion_rng)
        .expect("promote paired fixture");

    let paired = PairedMachineStore::new_with_mutation_observer(
        store,
        INSTALLATION_ID,
        root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open epoch-barrier fixture");
    let mut binding_rng = DeterministicRng::new([seed.wrapping_add(3); 32]);
    opened
        .install_stream_binding_for_automatic_harness(catalog_binding(fixture), &mut binding_rng)
        .expect("install authenticated catalog binding");
    (recipient, device_sign)
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

fn signed_update(
    fixture: &PairingFixture,
    recipient: &HpkePublicKey,
    purpose: KeyPurpose,
    epoch: u64,
    key: [u8; 32],
    seed: u8,
) -> KeyUpdateV1 {
    let revision = KeyDirectoryRevision::new(UPDATE_REVISION);
    let info = KeyUpdateInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: fixture.invite().relay_server_id,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        stream_route: None,
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
    let signer = MachineDataSignerBindingV1::from_certificate(&fixture.invite().data_sign_cert)
        .expect("valid MachineData signer binding");
    sign_key_update(
        &PairingFixture::machine_data_signing_key(),
        &signer,
        &info,
        &context,
        KeyUpdateV1 {
            key_directory_revision: revision,
            key_id: KeyId { purpose, epoch },
            device_route: fixture.device_route(),
            stream_route: None,
            enc,
            wrapped_key: ciphertext,
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign KeyUpdate")
}

fn update_set(fixture: &PairingFixture, recipient: &HpkePublicKey) -> KeyUpdateSetV1 {
    let set = KeyUpdateSetV1 {
        key_directory_revision: KeyDirectoryRevision::new(UPDATE_REVISION),
        device_route: fixture.device_route(),
        updates: vec![
            signed_update(
                fixture,
                recipient,
                KeyPurpose::Catalog,
                CATALOG_EPOCH + 1,
                NEW_CATALOG_KEY,
                0x41,
            ),
            signed_update(
                fixture,
                recipient,
                KeyPurpose::DeviceCommandTx,
                DEVICE_COMMAND_EPOCH,
                DEVICE_COMMAND_KEY,
                0x42,
            ),
            signed_update(
                fixture,
                recipient,
                KeyPurpose::DeviceReplyTx,
                DEVICE_REPLY_EPOCH,
                DEVICE_REPLY_KEY,
                0x43,
            ),
        ],
    };
    set.validate().expect("valid exact-next UpdateSet");
    set
}

fn epoch_barrier(stream_cursor: StreamCursor, inner_cursor: RuntimeInnerCursor) -> EpochBarrierV1 {
    EpochBarrierV1 {
        stream_generation: CATALOG_GENERATION,
        stream_cursor,
        inner_cursor,
        old_epoch: CATALOG_EPOCH,
        new_epoch: CATALOG_EPOCH + 1,
        key_directory_revision: KeyDirectoryRevision::new(UPDATE_REVISION),
    }
}

fn barrier_frame(barrier: &EpochBarrierV1) -> OpaqueRouteFrame {
    let stream_seq = barrier
        .stream_cursor
        .checked_next()
        .expect("barrier old cut has exact next");
    let context = OuterContextV1 {
        frame_kind: OuterFrameKind::CatalogPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(remote_pairing::MACHINE_ROUTE),
        device_route: None,
        stream_route: Some(CATALOG_ROUTE),
        request_route: None,
        pair_route: None,
        stream_generation: Some(CATALOG_GENERATION),
        stream_cursor: None,
        stream_seq: Some(stream_seq),
        message_key_epoch: barrier.new_epoch,
    };
    let control = KeyControlV1::epoch_barrier(CATALOG_ROUTE, barrier.clone());
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: barrier.new_epoch,
        },
        barrier.new_epoch,
        barrier.key_directory_revision.value(),
        SecretAeadKey::from_bytes(NEW_CATALOG_KEY),
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        control.sealed_payload_kind(),
        &control.canonical_bytes().expect("canonical EpochBarrier"),
        SenderCounter(BARRIER_COUNTER),
    )
    .expect("seal daemon-shape EpochBarrier");
    let signed = sign_sealed(
        unsigned,
        &PairingFixture::machine_data_signing_key(),
        &context,
    );
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Publish(Publish {
            stream_route: CATALOG_ROUTE,
            generation: CATALOG_GENERATION,
            stream_seq,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn observation_for_barrier(
    fixture: &PairingFixture,
    frame: &OpaqueRouteFrame,
) -> SignedHigherRevisionObservationV1 {
    let RelayFrameBody::Publish(publish) = &frame.body else {
        panic!("barrier carrier is Publish")
    };
    let signed = SignedSealedBlobV1::from_wire_bytes(&publish.sealed_blob.0)
        .expect("canonical signed EpochBarrier");
    SignedHigherRevisionObservationV1::new(
        fixture.machine_route(),
        fixture.device_route(),
        GrantSerial::new(7),
        TrustEpoch::new(2),
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        KeyDirectoryRevision::new(UPDATE_REVISION),
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH + 1,
        },
        None,
        CATALOG_ROUTE,
        CATALOG_GENERATION,
        publish.stream_seq,
        BARRIER_COUNTER,
        sha256(&encode(frame)),
        sha256(&signed.inner.ciphertext),
    )
    .expect("valid exact EpochBarrier observation")
}

fn initial_key_sync(fixture: &PairingFixture, frame: &OpaqueRouteFrame) -> DurableKeySyncStateV1 {
    let observation = observation_for_barrier(fixture, frame);
    let request = observation
        .request_for_attempt(1)
        .expect("first KeySync request");
    let request_route = RequestRouteId::from_bytes([0x71; 16]);
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
    let frozen = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(Send {
            device_route: fixture.device_route(),
            request_route,
            sealed_blob: SealedBlob(blob.to_wire_bytes()),
        }),
    };
    DurableKeySyncStateV1::start(
        observation,
        STARTED_AT_MS,
        FrozenKeySyncSendV1::new(request, encode(&frozen)).expect("freeze KeySync request"),
    )
    .expect("start barrier-backed KeySync")
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

fn staged_fixture(
    temp: &tempfile::TempDir,
    case: &str,
    barrier: EpochBarrierV1,
) -> StagedBarrierFixture {
    let pairing = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let state_root = state_root(temp, case);
    let frame = barrier_frame(&barrier);
    let (recipient, device_sign) = promote_and_install_binding(&pairing, &store, &state_root, 0x31);
    let key_sync = initial_key_sync(&pairing, &frame);

    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = paired
        .open_exact(pairing.identity())
        .expect("open staged EpochBarrier fixture");
    let mut key_sync_rng = DeterministicRng::new([0x35; 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(
            None,
            Some(&key_sync),
            &mut key_sync_rng,
        )
        .expect("install active ADKS");
    let prepared = opened
        .prepare_key_update_install(
            handoff(&key_sync, update_set(&pairing, &recipient)),
            STARTED_AT_MS + 2_000,
        )
        .expect("prepare staged rotation");
    let mut install_rng = DeterministicRng::new([0x36; 32]);
    opened
        .commit_key_update_install(prepared, &mut install_rng)
        .expect("commit staged rotation");
    drop(opened);

    StagedBarrierFixture {
        pairing,
        store,
        state_root,
        device_sign,
        frame,
    }
}

fn open_outbound_control(bytes: &[u8], device_sign: &VerifyingKey) -> Option<KeyControlRequestV1> {
    let frame = decode(bytes).expect("decode canonical outbound frame");
    let RelayFrameBody::Send(send) = frame.body else {
        return None;
    };
    let signed = SignedSealedBlobV1::from_wire_bytes(&send.sealed_blob.0)
        .expect("outbound command carries canonical signed blob");
    let context = OuterContextV1::uplink_send(
        remote_pairing::MACHINE_ROUTE,
        remote_pairing::DEVICE_ROUTE,
        send.request_route,
        DEVICE_COMMAND_EPOCH,
    );
    let verified = verify_sealed(signed, device_sign, &context)
        .expect("outbound command has DeviceSign/AAD proof");
    let receiving = AeadReceivingKey::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: DEVICE_COMMAND_EPOCH,
        },
        DEVICE_COMMAND_EPOCH,
        SecretAeadKey::from_bytes(DEVICE_COMMAND_KEY),
    );
    let opened = open_sealed_payload(&receiving, &context, verified)
        .expect("open outbound key-control command");
    Some(
        KeyControlRequestV1::from_canonical_bytes(&opened.payload)
            .expect("canonical outbound key-control request"),
    )
}

fn sent_stream_applied_ack(
    sent: &[Vec<u8>],
    device_sign: &VerifyingKey,
) -> Option<StreamAppliedAckV1> {
    sent.iter().find_map(|bytes| {
        let control = open_outbound_control(bytes, device_sign)?;
        match control {
            KeyControlRequestV1::StreamAppliedAck { ack } => Some(ack),
            KeyControlRequestV1::KeySync { .. } | KeyControlRequestV1::KeyUpdateAck { .. } => None,
        }
    })
}

#[tokio::test]
async fn epoch_barrier_exact_next_activates_staged_key_and_emits_exact_stream_applied_ack() {
    let temp = tempfile::tempdir().expect("exact EpochBarrier root");
    let barrier = epoch_barrier(
        StreamCursor::At(OUTER_HIGH_WATER),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
    );
    let fixture = staged_fixture(&temp, "exact", barrier.clone());

    let before = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("open staged precondition");
    let before_generation = before
        .durable_key_generation_state()
        .expect("read staged generation")
        .expect("V5 generation exists");
    let before_slot = before_generation
        .find_slot(KeyPurpose::Catalog, None)
        .expect("catalog slot");
    assert_eq!(before_slot.current().key_id().epoch, CATALOG_EPOCH);
    assert_eq!(
        before_slot
            .staged()
            .expect("rotation remains staged")
            .key_id()
            .epoch,
        CATALOG_EPOCH + 1
    );
    drop(before);

    let (transport, sent) = BarrierTransport::new(fixture.frame.clone());
    let opened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("open exact EpochBarrier runtime");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CatalogReducer::at_barrier_cut();
    let outcome = runtime.receive_stream_frame(&mut reducer).await;
    drop(runtime);

    let reopened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("reopen activated EpochBarrier state");
    let generation = reopened
        .durable_key_generation_state()
        .expect("read activated generation")
        .expect("V5 generation remains present");
    let slot = generation
        .find_slot(KeyPurpose::Catalog, None)
        .expect("activated catalog slot");
    let binding = reopened
        .durable_stream_bindings()
        .expect("read activated binding")
        .into_iter()
        .find(|candidate| candidate.binding().stream_route == CATALOG_ROUTE)
        .expect("catalog binding remains installed");
    let sent = sent.lock().expect("read barrier sends").clone();
    let applied_ack = sent_stream_applied_ack(&sent, &fixture.device_sign);

    let activated = slot.current().key_id().epoch == CATALOG_EPOCH + 1
        && slot.staged().is_none()
        && slot
            .retired()
            .last()
            .is_some_and(|retired| retired.key_id().epoch == CATALOG_EPOCH)
        && binding.binding().key_id.epoch == CATALOG_EPOCH + 1
        && binding.binding().key_directory_revision.value() == UPDATE_REVISION
        && binding.outer_applied() == StreamCursor::At(OUTER_HIGH_WATER + 1)
        && binding.inner_observed() == &barrier.inner_cursor
        && binding.inner_applied() == &barrier.inner_cursor;
    let ack_exact = applied_ack
        .as_ref()
        .is_some_and(|ack| ack.validate_for_barrier(CATALOG_ROUTE, &barrier).is_ok());
    let send_order_exact = sent.len() == 2
        && matches!(
            decode(&sent[0]).expect("decode StreamAppliedAck").body,
            RelayFrameBody::Send(_)
        )
        && matches!(
            decode(&sent[1]).expect("decode Relay Ack").body,
            RelayFrameBody::Ack(_)
        );

    assert!(
        activated && ack_exact && send_order_exact,
        "exact EpochBarrier must atomically activate staged key/binding/replay and send StreamAppliedAck before Relay Ack; outcome={outcome:?}, activated={activated}, ack_exact={ack_exact}, send_order_exact={send_order_exact}, sends={}",
        sent.len()
    );
}

#[tokio::test]
async fn committed_epoch_barrier_duplicate_reopens_without_retiring_or_reducing_twice() {
    let temp = tempfile::tempdir().expect("duplicate EpochBarrier root");
    let barrier = epoch_barrier(
        StreamCursor::At(OUTER_HIGH_WATER),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
    );
    let fixture = staged_fixture(&temp, "duplicate", barrier.clone());

    let (first_transport, _) = BarrierTransport::new(fixture.frame.clone());
    let opened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("open first barrier runtime");
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_reducer = CatalogReducer::at_barrier_cut();
    assert!(matches!(
        first_runtime.receive_stream_frame(&mut first_reducer).await,
        Ok(RemoteStreamFrameOutcome::EpochBarrierApplied {
            already_applied: false,
            ..
        })
    ));
    drop(first_runtime);

    let (duplicate_transport, duplicate_sent) = BarrierTransport::new(fixture.frame.clone());
    let reopened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("reopen committed barrier runtime");
    let mut duplicate_runtime = RemoteRuntime::new(reopened, duplicate_transport);
    let mut duplicate_reducer = CatalogReducer::at_barrier_cut();
    let duplicate = duplicate_runtime
        .receive_stream_frame(&mut duplicate_reducer)
        .await;
    drop(duplicate_runtime);

    let reopened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("audit duplicate barrier result");
    let generation = reopened
        .durable_key_generation_state()
        .expect("read duplicate generation")
        .expect("V5 generation exists");
    let slot = generation
        .find_slot(KeyPurpose::Catalog, None)
        .expect("catalog slot exists");
    let sent = duplicate_sent.lock().expect("read duplicate sends").clone();
    assert!(
        matches!(
            duplicate,
            Ok(RemoteStreamFrameOutcome::EpochBarrierApplied {
                already_applied: true,
                ..
            })
        ) && slot.retired().len() == 1
            && sent_stream_applied_ack(&sent, &fixture.device_sign)
                .is_some_and(|ack| ack.validate_for_barrier(CATALOG_ROUTE, &barrier).is_ok()),
        "committed duplicate must only resend exact receipts; outcome={duplicate:?}, retired={}, sends={}",
        slot.retired().len(),
        sent.len()
    );
}

#[tokio::test]
async fn route_accepted_keeps_receipt_durable_and_cold_recovery_reseals_it() {
    let temp = tempfile::tempdir().expect("receipt recovery root");
    let barrier = epoch_barrier(
        StreamCursor::At(OUTER_HIGH_WATER),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
    );
    let fixture = staged_fixture(&temp, "receipt-recovery", barrier.clone());
    let (transport, _) = BarrierTransport::new(fixture.frame.clone());
    let transport = transport.with_stream_applied_ack_route_accepted();
    let opened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("open receipt activation runtime");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CatalogReducer::at_barrier_cut();
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::EpochBarrierApplied { .. })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::StreamAppliedAckRouteAccepted {
            stream_route,
            applied_stream_seq,
        }) if stream_route == CATALOG_ROUTE && applied_stream_seq == OUTER_HIGH_WATER + 1
    ));
    drop(runtime);

    let (recovery_transport, recovery_sent) = BarrierTransport::empty();
    let recovery_transport = recovery_transport.with_stream_applied_ack_route_accepted();
    let reopened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("reopen durable receipt runtime");
    let mut recovery = RemoteRuntime::new(reopened, recovery_transport);
    recovery
        .recover_durable_epoch_barrier_acks()
        .await
        .expect("first cold receipt recovery");
    recovery
        .recover_durable_epoch_barrier_acks()
        .await
        .expect("RouteAccepted does not clear durable receipt basis");
    drop(recovery);

    let sent = recovery_sent.lock().expect("read recovery sends").clone();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|bytes| {
        open_outbound_control(bytes, &fixture.device_sign).is_some_and(|control| {
            matches!(
                control,
                KeyControlRequestV1::StreamAppliedAck { ack }
                    if ack.validate_for_barrier(CATALOG_ROUTE, &barrier).is_ok()
            )
        })
    }));
}

#[tokio::test]
async fn stream_applied_ack_send_failure_stops_relay_ack_and_cold_recovery_retries() {
    let temp = tempfile::tempdir().expect("receipt send failure root");
    let barrier = epoch_barrier(
        StreamCursor::At(OUTER_HIGH_WATER),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
    );
    let fixture = staged_fixture(&temp, "receipt-send-failure", barrier.clone());
    let (transport, failed_sent) = BarrierTransport::new(fixture.frame.clone());
    let transport = transport.with_first_stream_applied_ack_send_failure();
    let opened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("open send-failure activation runtime");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CatalogReducer::at_barrier_cut();
    let result = runtime.receive_stream_frame(&mut reducer).await;
    drop(runtime);

    let failed_sent = failed_sent
        .lock()
        .expect("read failed activation sends")
        .clone();
    assert!(matches!(result, Err(RemoteRuntimeError::Transport(_))));
    assert_eq!(failed_sent.len(), 1);
    assert!(matches!(
        decode(&failed_sent[0])
            .expect("decode failed StreamAppliedAck attempt")
            .body,
        RelayFrameBody::Send(_)
    ));

    let (recovery_transport, recovery_sent) = BarrierTransport::empty();
    let recovery_transport = recovery_transport.with_stream_applied_ack_route_accepted();
    let reopened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("reopen committed activation after ACK send failure");
    let mut recovery = RemoteRuntime::new(reopened, recovery_transport);
    recovery
        .recover_durable_epoch_barrier_acks()
        .await
        .expect("cold recovery retries durable StreamAppliedAck");
    drop(recovery);
    let recovery_sent = recovery_sent
        .lock()
        .expect("read recovered ACK send")
        .clone();
    assert_eq!(recovery_sent.len(), 1);
    assert!(
        sent_stream_applied_ack(&recovery_sent, &fixture.device_sign)
            .is_some_and(|ack| ack.validate_for_barrier(CATALOG_ROUTE, &barrier).is_ok())
    );
}

#[test]
fn epoch_barrier_admission_and_activation_cas_crashes_recover_by_exact_retry() {
    for occurrence in [1, 2] {
        let temp = tempfile::tempdir().expect("EpochBarrier crash root");
        let barrier = epoch_barrier(
            StreamCursor::At(OUTER_HIGH_WATER),
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(INNER_HIGH_WATER),
            },
        );
        let fixture = staged_fixture(&temp, &format!("crash-{occurrence}"), barrier);
        let observer = Arc::new(PanicOnNthStage {
            stage: PairedMutationStage::StateActiveDurable,
            occurrence,
            seen: AtomicUsize::new(0),
        });
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let opened = PairedMachineStore::new_with_mutation_observer(
                &fixture.store,
                INSTALLATION_ID,
                &fixture.state_root,
                observer.clone(),
            )
            .open_exact(fixture.pairing.identity())
            .expect("open crash-injected barrier runtime");
            let (transport, _) = BarrierTransport::new(fixture.frame.clone());
            let mut runtime = RemoteRuntime::new(opened, transport);
            let mut reducer = CatalogReducer::at_barrier_cut();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build crash runtime")
                .block_on(runtime.receive_stream_frame(&mut reducer))
                .expect("mutation observer must interrupt the transaction");
        }));
        assert!(crashed.is_err());
        assert!(observer.seen.load(Ordering::SeqCst) >= occurrence);

        let reopened =
            PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
                .open_exact(fixture.pairing.identity())
                .expect("cold open recovers pending state transaction");
        let (retry_transport, retry_sent) = BarrierTransport::new(fixture.frame.clone());
        let mut retry = RemoteRuntime::new(reopened, retry_transport);
        let mut reducer = CatalogReducer::at_barrier_cut();
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build retry runtime")
            .block_on(retry.receive_stream_frame(&mut reducer));
        drop(retry);
        let sent = retry_sent.lock().expect("read crash retry sends").clone();
        assert!(
            matches!(
                result,
                Ok(RemoteStreamFrameOutcome::EpochBarrierApplied { .. })
            ) && sent_stream_applied_ack(&sent, &fixture.device_sign).is_some(),
            "crash occurrence {occurrence} must recover through exact retry; result={result:?}, sends={}",
            sent.len()
        );
    }
}

#[tokio::test]
async fn staged_barrier_same_counter_different_ciphertext_quarantines_without_activation() {
    let temp = tempfile::tempdir().expect("nonce-reuse barrier root");
    let wrong = epoch_barrier(
        StreamCursor::At(OUTER_HIGH_WATER),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER + 1),
        },
    );
    let exact = epoch_barrier(
        StreamCursor::At(OUTER_HIGH_WATER),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
    );
    let fixture = staged_fixture(&temp, "nonce-reuse", wrong);

    let (first_transport, _) = BarrierTransport::new(fixture.frame.clone());
    let opened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("open first nonce tuple");
    let mut first = RemoteRuntime::new(opened, first_transport);
    let mut reducer = CatalogReducer::at_barrier_cut();
    assert!(first.receive_stream_frame(&mut reducer).await.is_err());
    drop(first);

    let (conflict_transport, conflict_sent) = BarrierTransport::new(barrier_frame(&exact));
    let reopened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("reopen pending nonce tuple");
    let mut conflict = RemoteRuntime::new(reopened, conflict_transport);
    let mut reducer = CatalogReducer::at_barrier_cut();
    let result = conflict.receive_stream_frame(&mut reducer).await;
    drop(conflict);

    let reopened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
        .open_exact(fixture.pairing.identity())
        .expect("quarantined pending tuple remains auditable");
    let generation = reopened
        .durable_key_generation_state()
        .expect("read quarantined generation")
        .expect("V5 generation exists");
    let slot = generation
        .find_slot(KeyPurpose::Catalog, None)
        .expect("catalog slot exists");
    assert!(matches!(result, Err(RemoteRuntimeError::NonceReuse)));
    assert_eq!(slot.current().key_id().epoch, CATALOG_EPOCH);
    assert!(slot.staged().is_some());
    assert!(
        sent_stream_applied_ack(
            &conflict_sent.lock().expect("read conflict sends"),
            &fixture.device_sign,
        )
        .is_none()
    );
}

#[tokio::test]
async fn epoch_barrier_rejects_cut_and_inner_cursor_drift_fail_closed() {
    for (case, barrier) in [
        (
            "wrong-outer-cut",
            epoch_barrier(
                StreamCursor::At(OUTER_HIGH_WATER - 1),
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(INNER_HIGH_WATER),
                },
            ),
        ),
        (
            "wrong-inner-cut",
            epoch_barrier(
                StreamCursor::At(OUTER_HIGH_WATER),
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(INNER_HIGH_WATER + 1),
                },
            ),
        ),
    ] {
        let temp = tempfile::tempdir().expect("drift EpochBarrier root");
        let fixture = staged_fixture(&temp, case, barrier);
        let before = durable_snapshot(&fixture);
        assert!(
            before
                .paired_keychain_accounts
                .iter()
                .all(|(_, value)| value.is_some()),
            "{case} baseline has all six paired Keychain accounts"
        );

        let (transport, sent) = BarrierTransport::new(fixture.frame.clone());
        let opened = PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
            .open_exact(fixture.pairing.identity())
            .expect("open drift EpochBarrier runtime");
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut reducer = CatalogReducer::at_barrier_cut();
        let result = runtime.receive_stream_frame(&mut reducer).await;
        drop(runtime);

        let after = durable_snapshot(&fixture);
        let sent = sent.lock().expect("read drift sends").clone();
        let emitted_applied_ack = sent_stream_applied_ack(&sent, &fixture.device_sign).is_some();
        assert!(
            result.is_err() && !emitted_applied_ack,
            "{case} must fail-close without StreamAppliedAck; result={result:?}, emitted_applied_ack={emitted_applied_ack}, sends={}",
            sent.len()
        );

        if case == "wrong-outer-cut" {
            assert_eq!(
                before, after,
                "wrong outer cut is rejected before staged replay admission"
            );
            continue;
        }

        assert_ne!(
            before, after,
            "wrong inner cut is authenticated only after durable staged replay admission"
        );
        for ((before_purpose, before_value), (after_purpose, after_value)) in before
            .paired_keychain_accounts
            .iter()
            .zip(&after.paired_keychain_accounts)
        {
            assert_eq!(before_purpose, after_purpose);
            if *before_purpose != PairedRemoteKeyPurpose::CounterGuard {
                assert_eq!(
                    before_value, after_value,
                    "wrong inner cut may only advance the state CAS CounterGuard fence"
                );
            }
        }

        let reopened =
            PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
                .open_exact(fixture.pairing.identity())
                .expect("pending staged replay remains a valid fail-closed durable state");
        let generation = reopened
            .durable_key_generation_state()
            .expect("read non-activated generation")
            .expect("V5 generation remains installed");
        let slot = generation
            .find_slot(KeyPurpose::Catalog, None)
            .expect("catalog slot remains installed");
        let binding = reopened
            .durable_stream_bindings()
            .expect("read non-activated binding")
            .into_iter()
            .find(|candidate| candidate.binding().stream_route == CATALOG_ROUTE)
            .expect("catalog binding remains installed");
        assert_eq!(slot.current().key_id().epoch, CATALOG_EPOCH);
        assert_eq!(
            slot.staged()
                .expect("rotation remains staged")
                .key_id()
                .epoch,
            CATALOG_EPOCH + 1
        );
        assert_eq!(binding.binding().key_id.epoch, CATALOG_EPOCH);
        assert_eq!(
            binding.binding().key_directory_revision.value(),
            KEY_DIRECTORY_REVISION
        );
        assert_eq!(binding.outer_applied(), StreamCursor::At(OUTER_HIGH_WATER));
        drop(reopened);

        let retry_before = durable_snapshot(&fixture);
        let (retry_transport, retry_sent) = BarrierTransport::new(fixture.frame.clone());
        let reopened =
            PairedMachineStore::new(&fixture.store, INSTALLATION_ID, &fixture.state_root)
                .open_exact(fixture.pairing.identity())
                .expect("reopen pending staged replay for exact retry");
        let mut retry_runtime = RemoteRuntime::new(reopened, retry_transport);
        let mut retry_reducer = CatalogReducer::at_barrier_cut();
        let retry_result = retry_runtime.receive_stream_frame(&mut retry_reducer).await;
        drop(retry_runtime);
        let retry_after = durable_snapshot(&fixture);
        let retry_sent = retry_sent.lock().expect("read retry sends").clone();
        assert!(
            retry_result.is_err()
                && retry_before == retry_after
                && sent_stream_applied_ack(&retry_sent, &fixture.device_sign).is_none(),
            "exact invalid retry must reuse the durable pending admission without another mutation or ACK; result={retry_result:?}, state_equal={}, sends={}",
            retry_before == retry_after,
            retry_sent.len()
        );
    }
}
