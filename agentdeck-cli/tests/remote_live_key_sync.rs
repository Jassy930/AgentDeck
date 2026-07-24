#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::runtime::{
    ExactRelayFrame, ReceivedRuntimeFrame, RemoteRuntime, RemoteRuntimeError,
    RemoteRuntimeTransport, RemoteRuntimeTransportError, RemoteStreamFrameOutcome,
    RemoteSubscriptionBootstrapItem, RemoteSubscriptionReducer,
};
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, VerifyingKey,
    open_sealed_payload, seal_symmetric, sign_sealed, verify_sealed,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyControlRequestV1, KeyId, KeyPurpose, OuterContextV1, OuterFrameKind,
    SealedPayloadKind, SignedSealedBlobV1, StreamBindingV1,
};
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, Publish, RouteAccepted, SealedBlob};
use agentdeck_protocol::relay_v2::{
    GrantSerial, KeyDirectoryRevision, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody,
    StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    CatalogDelta, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeInnerCursor, RuntimeMessage,
    RuntimeStreamItem, StreamCursor,
};
use async_trait::async_trait;

use remote_pairing::{
    CATALOG_EPOCH, DEVICE_COMMAND_EPOCH, DEVICE_COMMAND_KEY, DeterministicRng, INSTALLATION_ID,
    KEY_DIRECTORY_REVISION, PairingFixture,
};

const CATALOG_STREAM_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_STREAM_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const OUTER_HIGH_WATER: u64 = 23;
const INNER_HIGH_WATER: u64 = 17;

#[derive(Clone, Copy)]
enum PublishShape {
    HigherDirectory,
    ForgedHigherDirectory,
    WrongAadHigherDirectory,
    WrongOuterRouteHigherDirectory,
    WrongOuterGenerationHigherDirectory,
    SameDirectoryHigherEpoch,
}

#[derive(Default)]
struct RecordingObserver {
    stages: Mutex<Vec<PairedMutationStage>>,
}

impl RecordingObserver {
    fn clear(&self) {
        self.stages.lock().expect("mutation stages").clear();
    }

    fn snapshot(&self) -> Vec<PairedMutationStage> {
        self.stages.lock().expect("mutation stages").clone()
    }
}

impl PairedMutationObserver for RecordingObserver {
    fn after_stage(&self, stage: PairedMutationStage) {
        self.stages.lock().expect("mutation stages").push(stage);
    }
}

struct KeySyncTransport {
    inbound: VecDeque<ReceivedRuntimeFrame>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    observer: Arc<RecordingObserver>,
    fail_next_send: bool,
    queue_route_accepted: bool,
}

impl KeySyncTransport {
    fn new(
        publish: OpaqueRouteFrame,
        observer: Arc<RecordingObserver>,
        fail_next_send: bool,
        queue_route_accepted: bool,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::from([received_exact(publish)]),
                sent: Arc::clone(&sent),
                observer,
                fail_next_send,
                queue_route_accepted,
            },
            sent,
        )
    }
}

#[async_trait]
impl RemoteRuntimeTransport for KeySyncTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        let bytes = frame.into_bytes();
        let decoded = decode(&bytes).expect("runtime only sends canonical Relay frames");
        let RelayFrameBody::Send(send) = decoded.body else {
            panic!("KeySync ingress must not ACK or emit another Relay control");
        };
        assert_eq!(
            self.observer.snapshot().last(),
            Some(&PairedMutationStage::StateStageCleared),
            "ADKS durable CAS must finish before transport.send"
        );
        self.sent.lock().expect("sent KeySync recorder").push(bytes);
        if self.fail_next_send {
            self.fail_next_send = false;
            return Err(RemoteRuntimeTransportError::Failed(
                "injected first KeySync send failure".to_owned(),
            ));
        }
        if self.queue_route_accepted {
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

#[derive(Clone)]
struct RejectingReducer {
    cursor: RuntimeInnerCursor,
}

impl RemoteSubscriptionReducer for RejectingReducer {
    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, _item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        panic!("KeySync must not enter the bootstrap reducer")
    }

    fn apply_live(&mut self, _item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        panic!("KeySync must not enter the live reducer")
    }
}

fn state_root(temp: &tempfile::TempDir) -> PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical KeySync tempdir")
        .join("paired-state")
}

fn file_tree_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut snapshot = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return snapshot;
    };
    for entry in entries {
        let path = entry.expect("read KeySync tree entry").path();
        if path.is_dir() {
            snapshot.extend(file_tree_bytes(&path));
        } else if path.is_file() {
            snapshot.push((
                path.clone(),
                fs::read(path).expect("snapshot KeySync durable bytes"),
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
            .expect("load paired key snapshot")
            .expect("paired key exists")
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
        stream_route: CATALOG_STREAM_ROUTE,
        stream_generation: CATALOG_STREAM_GENERATION,
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

fn publish_frame(shape: PublishShape) -> OpaqueRouteFrame {
    publish_frame_with_counter(shape, 705)
}

fn publish_frame_with_counter(shape: PublishShape, sender_counter: u64) -> OpaqueRouteFrame {
    let stream_seq = OUTER_HIGH_WATER + 1;
    let key_epoch = if matches!(shape, PublishShape::SameDirectoryHigherEpoch) {
        CATALOG_EPOCH + 1
    } else {
        CATALOG_EPOCH
    };
    let directory_revision = if matches!(shape, PublishShape::SameDirectoryHigherEpoch) {
        KEY_DIRECTORY_REVISION
    } else {
        KEY_DIRECTORY_REVISION + 1
    };
    let expected_context = OuterContextV1 {
        frame_kind: OuterFrameKind::CatalogPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(remote_pairing::MACHINE_ROUTE),
        device_route: None,
        stream_route: Some(CATALOG_STREAM_ROUTE),
        request_route: None,
        pair_route: None,
        stream_generation: Some(CATALOG_STREAM_GENERATION),
        stream_cursor: None,
        stream_seq: Some(stream_seq),
        message_key_epoch: key_epoch,
    };
    let seal_context = if matches!(shape, PublishShape::WrongAadHigherDirectory) {
        OuterContextV1 {
            stream_route: Some(StreamRouteId::from_bytes([0xfe; 16])),
            ..expected_context.clone()
        }
    } else {
        expected_context.clone()
    };
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("live-key-sync-higher-directory"),
        body: RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(CatalogDelta {
            catalog_revision: INNER_HIGH_WATER + 1,
            changes: Vec::new(),
        })),
    };
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: key_epoch,
        },
        key_epoch,
        directory_revision,
        SecretAeadKey::from_bytes([0x71; 32]),
    );
    let unsigned = seal_symmetric(
        &key,
        &seal_context,
        SealedPayloadKind::CatalogDelta,
        &envelope
            .to_json_bytes_checked()
            .expect("canonical live KeySync trigger"),
        SenderCounter(sender_counter),
    )
    .expect("seal signed higher-directory publication");
    let signer = if matches!(shape, PublishShape::ForgedHigherDirectory) {
        SigningKey::from_seed(&[0xfa; 32])
    } else {
        PairingFixture::machine_data_signing_key()
    };
    let signed = sign_sealed(unsigned, &signer, &seal_context);
    let outer_stream_route = if matches!(shape, PublishShape::WrongOuterRouteHigherDirectory) {
        StreamRouteId::from_bytes([0xfd; 16])
    } else {
        CATALOG_STREAM_ROUTE
    };
    let outer_generation = if matches!(shape, PublishShape::WrongOuterGenerationHigherDirectory) {
        StreamGenerationId::from_bytes([0xfc; 16])
    } else {
        CATALOG_STREAM_GENERATION
    };
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Publish(Publish {
            stream_route: outer_stream_route,
            generation: outer_generation,
            stream_seq,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn received_exact(frame: OpaqueRouteFrame) -> ReceivedRuntimeFrame {
    let canonical = encode(&frame);
    ReceivedRuntimeFrame::from_untrusted_parts(frame, canonical)
}

fn install_binding(
    store: &MemoryRemoteKeyStore,
    root: &Path,
    fixture: &PairingFixture,
    observer: Arc<RecordingObserver>,
    seed: u8,
) -> VerifyingKey {
    let device_sign = fixture.promote(store, root, seed);
    let paired = PairedMachineStore::new_with_mutation_observer(
        store,
        INSTALLATION_ID,
        root,
        observer.clone(),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open paired KeySync fixture");
    let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);
    opened
        .install_stream_binding_for_automatic_harness(catalog_binding(fixture), &mut rng)
        .expect("install authenticated catalog binding");
    drop(opened);
    observer.clear();
    device_sign
}

fn assert_key_sync_send(bytes: &[u8], device_sign: &VerifyingKey) {
    let frame = decode(bytes).expect("decode exact KeySync Send");
    let RelayFrameBody::Send(send) = frame.body else {
        panic!("KeySync exact bytes must carry Relay Send");
    };
    let signed = SignedSealedBlobV1::from_wire_bytes(&send.sealed_blob.0)
        .expect("KeySync Send carries canonical signed blob");
    assert_eq!(signed.inner.key_id.purpose, KeyPurpose::DeviceCommandTx);
    assert_eq!(signed.inner.key_epoch, DEVICE_COMMAND_EPOCH);
    assert_eq!(
        signed.inner.key_directory_revision,
        KEY_DIRECTORY_REVISION + 1,
        "typed KeySync helper alone may declare the exact-next revision"
    );
    let context = OuterContextV1::uplink_send(
        remote_pairing::MACHINE_ROUTE,
        remote_pairing::DEVICE_ROUTE,
        send.request_route,
        DEVICE_COMMAND_EPOCH,
    );
    let verified = verify_sealed(signed, device_sign, &context)
        .expect("KeySync Send has the real DeviceSign/AAD proof");
    let receiving_key = AeadReceivingKey::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: DEVICE_COMMAND_EPOCH,
        },
        DEVICE_COMMAND_EPOCH,
        SecretAeadKey::from_bytes(DEVICE_COMMAND_KEY),
    );
    let opened = open_sealed_payload(&receiving_key, &context, verified)
        .expect("open current DeviceCommandTx KeySync probe");
    assert_eq!(opened.payload_kind, SealedPayloadKind::KeyUpdate);
    let control = KeyControlRequestV1::from_canonical_bytes(&opened.payload)
        .expect("decode canonical KeySync control request");
    let KeyControlRequestV1::KeySync { request } = control else {
        panic!("live higher-directory trigger may only emit KeySync");
    };
    assert_eq!(
        request.known_key_directory_revision.value(),
        KEY_DIRECTORY_REVISION
    );
    assert_eq!(
        request.requested_key_directory_revision.value(),
        KEY_DIRECTORY_REVISION + 1
    );
    assert_eq!(request.attempt, 1);
}

#[tokio::test]
async fn signed_higher_directory_is_durable_before_send_and_restart_reuses_exact_probe() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("live KeySync state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let device_sign = install_binding(&store, &root, &fixture, observer.clone(), 0xb1);
    let higher = publish_frame(PublishShape::HigherDirectory);

    let opened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("open before first higher-directory frame");
    let (transport, first_sent) =
        KeySyncTransport::new(higher.clone(), observer.clone(), true, false);
    let mut runtime = RemoteRuntime::new(opened, transport);
    let initial_cursor = RuntimeInnerCursor::Catalog {
        cursor: StreamCursor::At(INNER_HIGH_WATER),
    };
    let mut reducer = RejectingReducer {
        cursor: initial_cursor.clone(),
    };
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("injected transport failure must remain observable");
    assert_eq!(error.code(), "remote.runtime.transport_failed");
    assert_eq!(reducer.inner_cursor(), &initial_cursor);
    drop(runtime);

    let first_bytes = first_sent
        .lock()
        .expect("first KeySync Send")
        .first()
        .expect("first KeySync Send exists")
        .clone();
    assert_key_sync_send(&first_bytes, &device_sign);
    let reopened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("restart must audit persisted ADKS");
    let persisted = reopened
        .durable_key_sync_state()
        .expect("read durable KeySync")
        .expect("failed send retains ADKS");
    assert_eq!(persisted.attempt_count(), 1);
    let started_at_ms = persisted.started_at_ms();
    let deadline_at_ms = persisted.deadline_at_ms();
    let last_observed_before_retry = persisted.last_observed_at_ms();
    assert_eq!(
        persisted
            .active_send()
            .expect("active KeySync probe")
            .exact_send_bytes(),
        first_bytes
    );
    observer.clear();
    tokio::time::sleep(Duration::from_millis(2)).await;

    let (transport, retry_sent) = KeySyncTransport::new(higher, observer.clone(), false, true);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert_eq!(
        retry_sent.lock().expect("retry KeySync Send").as_slice(),
        std::slice::from_ref(&first_bytes),
        "restart must resend the exact requestRoute/counter/ciphertext/proof"
    );
    assert_eq!(
        observer.snapshot(),
        vec![
            PairedMutationStage::StateStageDurable,
            PairedMutationStage::StateGuardPendingDurable,
            PairedMutationStage::StateActiveDurable,
            PairedMutationStage::StateGuardStableDurable,
            PairedMutationStage::StateStageCleared,
        ],
        "same signed trigger must durably CAS the ADKS clock watermark without a new counter reservation"
    );
    assert_eq!(reducer.inner_cursor(), &initial_cursor);
    let durable_after_retry = file_tree_bytes(&root);
    let keys_after_retry = paired_key_bytes(&store, &fixture);
    observer.clear();

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncRouteAccepted { attempt: 1 })
    ));
    assert!(observer.snapshot().is_empty());
    assert_eq!(file_tree_bytes(&root), durable_after_retry);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_after_retry);
    assert_eq!(reducer.inner_cursor(), &initial_cursor);
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("route acceptance must not clear ADKS");
    let persisted = reopened
        .durable_key_sync_state()
        .expect("read ADKS after RouteAccepted")
        .expect("RouteAccepted is not KeySync success");
    assert_eq!(persisted.attempt_count(), 1);
    assert_eq!(persisted.started_at_ms(), started_at_ms);
    assert_eq!(persisted.deadline_at_ms(), deadline_at_ms);
    assert!(persisted.last_observed_at_ms() > last_observed_before_retry);
    assert_eq!(
        persisted
            .active_send()
            .expect("RouteAccepted retains the active probe")
            .exact_send_bytes(),
        first_bytes
    );
    let binding = reopened
        .durable_stream_bindings()
        .expect("read unchanged stream binding")
        .pop()
        .expect("catalog binding remains installed");
    assert_eq!(binding.outer_applied(), StreamCursor::At(OUTER_HIGH_WATER));
    assert_eq!(binding.outer_acked(), StreamCursor::BeforeFirst);
    assert_eq!(binding.replay_tuple(), None);
}

#[tokio::test]
async fn different_signed_higher_frame_conflicts_without_overwriting_active_adks() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("conflicting live KeySync root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    install_binding(&store, &root, &fixture, observer.clone(), 0xb8);

    let opened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("open before active KeySync");
    let (transport, _) = KeySyncTransport::new(
        publish_frame_with_counter(PublishShape::HigherDirectory, 705),
        observer.clone(),
        true,
        false,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = RejectingReducer {
        cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
    };
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Err(RemoteRuntimeError::Transport(_))
    ));
    drop(runtime);
    let durable_before = file_tree_bytes(&root);
    let keys_before = paired_key_bytes(&store, &fixture);
    observer.clear();

    let reopened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("reopen active KeySync");
    let (transport, sent) = KeySyncTransport::new(
        publish_frame_with_counter(PublishShape::HigherDirectory, 706),
        observer.clone(),
        false,
        false,
    );
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("different authenticated observation must conflict");
    assert_eq!(error.code(), "remote.runtime.state_invalid");
    assert!(sent.lock().expect("conflict Send recorder").is_empty());
    assert!(observer.snapshot().is_empty());
    drop(runtime);
    assert_eq!(file_tree_bytes(&root), durable_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
}

#[tokio::test]
async fn untrusted_or_same_directory_epoch_drift_never_starts_key_sync() {
    for (seed, shape, expected_code) in [
        (
            0xc1,
            PublishShape::ForgedHigherDirectory,
            "remote.crypto.bad_sender_signature",
        ),
        (
            0xc2,
            PublishShape::WrongAadHigherDirectory,
            "remote.crypto.bad_sender_signature",
        ),
        (
            0xc3,
            PublishShape::SameDirectoryHigherEpoch,
            "remote.crypto.key_epoch_missing",
        ),
        (
            0xc4,
            PublishShape::WrongOuterRouteHigherDirectory,
            "remote.runtime.reply_invalid",
        ),
        (
            0xc5,
            PublishShape::WrongOuterGenerationHigherDirectory,
            "remote.runtime.reply_invalid",
        ),
    ] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("rejected live KeySync root");
        let root = state_root(&temp);
        let observer = Arc::new(RecordingObserver::default());
        install_binding(&store, &root, &fixture, observer.clone(), seed);
        let durable_before = file_tree_bytes(&root);
        let keys_before = paired_key_bytes(&store, &fixture);
        let opened = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &root,
            observer.clone(),
        )
        .open_exact(fixture.identity())
        .expect("open rejected KeySync fixture");
        let (transport, sent) =
            KeySyncTransport::new(publish_frame(shape), observer.clone(), false, false);
        let mut runtime = RemoteRuntime::new(opened, transport);
        let initial_cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        };
        let mut reducer = RejectingReducer {
            cursor: initial_cursor.clone(),
        };

        let error = runtime
            .receive_stream_frame(&mut reducer)
            .await
            .expect_err("untrusted/same-directory drift must stay fatal");
        assert_eq!(error.code(), expected_code);
        assert!(sent.lock().expect("rejected Send recorder").is_empty());
        assert!(observer.snapshot().is_empty());
        assert_eq!(reducer.inner_cursor(), &initial_cursor);
        drop(runtime);
        assert_eq!(file_tree_bytes(&root), durable_before);
        assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
        let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("reopen rejected KeySync fixture");
        assert!(
            reopened
                .durable_key_sync_state()
                .expect("read absent ADKS")
                .is_none()
        );
    }
}
