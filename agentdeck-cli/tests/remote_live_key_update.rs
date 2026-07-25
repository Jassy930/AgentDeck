#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agentdeck_cli::remote::key_sync::{
    DurableKeySyncStateV1, FrozenKeySyncSendV1, KeySyncCoordinationStatus,
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
    ExactRelayFrame, MAX_REMOTE_SUBSCRIPTION_REDUCER_RETAINED_BYTES, ReceivedRuntimeFrame,
    RemoteRuntime, RemoteRuntimeError, RemoteRuntimeTransport, RemoteRuntimeTransportError,
    RemoteStreamFrameOutcome, RemoteSubscriptionBootstrapItem, RemoteSubscriptionReducer,
};
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, HpkeEnvelopeV1, HpkePublicKey, SecretAeadKey, SenderCounter,
    VerifyingKey, hpke_seal_base, open_sealed_payload,
    rand_core::{TryCryptoRng, TryRng},
    seal_symmetric, sha256, sign_key_update, sign_sealed, verify_sealed,
};
use agentdeck_protocol::e2ee::{
    DirectoryCurrentV1, DirectoryRevisionAdvanceV1, E2EE_FORMAT_VERSION, KeyControlRequestV1,
    KeyControlV1, KeyId, KeyPurpose, KeyUpdateAckV1, KeyUpdateInfoV1, KeyUpdateSetV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, SealedPayloadKind,
    SignedSealedBlobV1, StreamBindingV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Publish, Reply, RouteAccepted, SealedBlob, Send as RelaySend,
};
use agentdeck_protocol::relay_v2::{
    Ed25519Signature, GrantSerial, KeyDirectoryRevision, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RequestRouteId, StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};
use agentdeck_protocol::runtime::identity::{CommandId, MessageId};
use agentdeck_protocol::runtime::{
    CatalogDelta, CommandReceipt, ConversationId, IdempotencyKey, PromptPayload,
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeInnerCursor, RuntimeMessage, RuntimeReply,
    RuntimeRequest, RuntimeStreamItem, SendPromptRequest, StreamCursor,
};
use async_trait::async_trait;

use remote_pairing::{
    CATALOG_EPOCH, DEVICE_COMMAND_EPOCH, DEVICE_COMMAND_KEY, DEVICE_REPLY_EPOCH, DEVICE_REPLY_KEY,
    DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION, NOW_MS, PairingFixture, PanicRng,
};

const CATALOG_STREAM_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_STREAM_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const OUTER_HIGH_WATER: u64 = 23;
const INNER_HIGH_WATER: u64 = 17;
const UPDATE_REVISION: u64 = KEY_DIRECTORY_REVISION + 1;
const SECOND_UPDATE_REVISION: u64 = UPDATE_REVISION + 1;

struct FixedRouteRng {
    bytes: VecDeque<u8>,
}

impl FixedRouteRng {
    fn new(request_route: RequestRouteId) -> Self {
        Self {
            bytes: request_route.as_bytes().iter().copied().collect(),
        }
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.bytes.pop_front().unwrap_or(0xa5);
        }
    }
}

impl TryRng for FixedRouteRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(output);
        Ok(())
    }
}

impl TryCryptoRng for FixedRouteRng {}

#[derive(Default)]
struct RecordingObserver {
    stages: Mutex<Vec<PairedMutationStage>>,
    crash_after_state_stage_cleared: Mutex<bool>,
}

impl RecordingObserver {
    fn clear(&self) {
        self.stages.lock().expect("mutation stages").clear();
    }

    fn snapshot(&self) -> Vec<PairedMutationStage> {
        self.stages.lock().expect("mutation stages").clone()
    }

    fn arm_crash_after_state_stage_cleared(&self) {
        let mut armed = self
            .crash_after_state_stage_cleared
            .lock()
            .expect("mutation crash arm");
        assert!(!*armed, "mutation crash observer is already armed");
        *armed = true;
    }
}

impl PairedMutationObserver for RecordingObserver {
    fn after_stage(&self, stage: PairedMutationStage) {
        self.stages.lock().expect("mutation stages").push(stage);
        let should_crash = stage == PairedMutationStage::StateStageCleared && {
            let mut armed = self
                .crash_after_state_stage_cleared
                .lock()
                .expect("mutation crash arm");
            std::mem::take(&mut *armed)
        };
        if should_crash {
            panic!("automatic crash after durable paired-state CAS cleanup");
        }
    }
}

#[derive(Clone)]
struct RejectingReducer {
    cursor: RuntimeInnerCursor,
}

impl RemoteSubscriptionReducer for RejectingReducer {
    const MAX_RETAINED_BYTES: usize = 64 * 1024;

    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, _item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        panic!("key-control Reply must not enter the bootstrap reducer")
    }

    fn apply_live(&mut self, _item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        panic!("key-control Reply must not enter the live reducer")
    }
}

#[derive(Clone)]
struct LiveCatalogReducer {
    cursor: RuntimeInnerCursor,
    applied: usize,
    reject_live: bool,
}

impl LiveCatalogReducer {
    fn at(inner_high_water: u64) -> Self {
        Self {
            cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(inner_high_water),
            },
            applied: 0,
            reject_live: false,
        }
    }

    fn rejecting(inner_high_water: u64) -> Self {
        Self {
            reject_live: true,
            ..Self::at(inner_high_water)
        }
    }
}

impl RemoteSubscriptionReducer for LiveCatalogReducer {
    const MAX_RETAINED_BYTES: usize = 64 * 1024;

    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, _item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        Err(RemoteRuntimeError::InvalidReply(
            "live replay fixture does not accept bootstrap items",
        ))
    }

    fn apply_live(&mut self, item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        if self.reject_live {
            return Err(RemoteRuntimeError::InvalidReply(
                "injected live reducer rejection",
            ));
        }
        let RuntimeStreamItem::CatalogDelta(delta) = item else {
            return Err(RemoteRuntimeError::InvalidReply(
                "live replay fixture expected a CatalogDelta",
            ));
        };
        let RuntimeInnerCursor::Catalog { cursor } = &self.cursor else {
            return Err(RemoteRuntimeError::InvalidReply(
                "live replay fixture cursor target drifted",
            ));
        };
        if cursor.checked_next().ok() != Some(delta.catalog_revision) {
            return Err(RemoteRuntimeError::InvalidReply(
                "live replay fixture received a non-contiguous CatalogDelta",
            ));
        }
        self.cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(delta.catalog_revision),
        };
        self.applied += 1;
        Ok(())
    }
}

#[derive(Clone)]
struct OverCapacityReducer {
    cursor: RuntimeInnerCursor,
}

impl RemoteSubscriptionReducer for OverCapacityReducer {
    const MAX_RETAINED_BYTES: usize = MAX_REMOTE_SUBSCRIPTION_REDUCER_RETAINED_BYTES + 1;

    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, _item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        panic!("over-capacity reducer must be rejected before bootstrap apply")
    }

    fn apply_live(&mut self, _item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        panic!("over-capacity reducer must be rejected before live apply")
    }
}

struct PanicTransport;

#[async_trait]
impl RemoteRuntimeTransport for PanicTransport {
    async fn send(&mut self, _frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        panic!("over-capacity reducer must be rejected before transport send")
    }

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        panic!("over-capacity reducer must be rejected before transport recv")
    }
}

struct StreamReplayTransport {
    inbound: VecDeque<ReceivedRuntimeFrame>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    fail_first_ack: bool,
}

impl StreamReplayTransport {
    fn new(
        frames: Vec<OpaqueRouteFrame>,
        fail_first_ack: bool,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: frames.into_iter().map(received_exact).collect(),
                sent: Arc::clone(&sent),
                fail_first_ack,
            },
            sent,
        )
    }
}

#[async_trait]
impl RemoteRuntimeTransport for StreamReplayTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        let bytes = frame.into_bytes();
        let decoded = decode(&bytes).expect("runtime only sends canonical Relay frames");
        if !matches!(decoded.body, RelayFrameBody::Ack(_)) {
            panic!("live replay fixture may only emit a stream ACK")
        }
        self.sent.lock().expect("stream ACK recorder").push(bytes);
        if self.fail_first_ack {
            self.fail_first_ack = false;
            return Err(RemoteRuntimeTransportError::Failed(
                "injected predecessor ACK send failure".into(),
            ));
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        Ok(self.inbound.pop_front())
    }
}

struct DirectedReplayTransport {
    inbound: VecDeque<ReceivedRuntimeFrame>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    reply_revision: Option<u64>,
    reply_counter: u64,
    device_sign: VerifyingKey,
}

impl DirectedReplayTransport {
    fn new(
        reply_revision: Option<u64>,
        reply_counter: u64,
        device_sign: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::new(),
                sent: Arc::clone(&sent),
                reply_revision,
                reply_counter,
                device_sign,
            },
            sent,
        )
    }
}

#[async_trait]
impl RemoteRuntimeTransport for DirectedReplayTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        let bytes = frame.into_bytes();
        let decoded = decode(&bytes).expect("runtime only sends canonical Relay frames");
        let RelayFrameBody::Send(send) = decoded.body else {
            panic!("directed replay fixture may only emit Relay Send")
        };
        let (message_id, request) =
            open_runtime_request(&send.sealed_blob.0, send.request_route, &self.device_sign);
        assert_eq!(
            serde_json::to_value(request).expect("serialize actual predecessor request"),
            serde_json::to_value(RuntimeRequest::SendPrompt(prompt_request()))
                .expect("serialize expected predecessor request")
        );
        self.sent
            .lock()
            .expect("directed replay recorder")
            .push(bytes);
        if let Some(revision) = self.reply_revision.take() {
            self.inbound.push_back(received_exact(command_reply(
                send.request_route,
                message_id,
                revision,
                self.reply_counter,
            )));
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        Ok(self.inbound.pop_front())
    }
}

struct KeyUpdateTransport {
    inbound: VecDeque<ReceivedRuntimeFrame>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    key_sync_replies: VecDeque<ScriptedKeySyncReply>,
    wrong_reply_route: bool,
    queue_key_sync_route_accepted: bool,
    queue_ack_route_accepted: bool,
    fail_after_recording_ack: bool,
    fail_after_recording_stream_ack: bool,
    key_sync_send_count: usize,
    fail_on_key_sync_send: Option<usize>,
    extra_key_sync_route_accepted_on_send: Option<usize>,
    publish_after_ack: Option<OpaqueRouteFrame>,
    device_sign: VerifyingKey,
}

enum ScriptedKeySyncReply {
    UpdateSet {
        update_set: KeyUpdateSetV1,
        header_revision: u64,
    },
    DirectoryCurrent {
        status: DirectoryCurrentV1,
        header_revision: u64,
    },
}

impl KeyUpdateTransport {
    fn for_update(
        update_set: KeyUpdateSetV1,
        wrong_reply_route: bool,
        device_sign: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::from([received_exact(higher_publish())]),
                sent: Arc::clone(&sent),
                key_sync_replies: VecDeque::from([ScriptedKeySyncReply::UpdateSet {
                    update_set,
                    header_revision: UPDATE_REVISION,
                }]),
                wrong_reply_route,
                queue_key_sync_route_accepted: false,
                queue_ack_route_accepted: true,
                fail_after_recording_ack: false,
                fail_after_recording_stream_ack: false,
                key_sync_send_count: 0,
                fail_on_key_sync_send: None,
                extra_key_sync_route_accepted_on_send: None,
                publish_after_ack: None,
                device_sign,
            },
            sent,
        )
    }

    fn for_ack_resume(device_sign: VerifyingKey) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::new(),
                sent: Arc::clone(&sent),
                key_sync_replies: VecDeque::new(),
                wrong_reply_route: false,
                queue_key_sync_route_accepted: false,
                queue_ack_route_accepted: true,
                fail_after_recording_ack: false,
                fail_after_recording_stream_ack: false,
                key_sync_send_count: 0,
                fail_on_key_sync_send: None,
                extra_key_sync_route_accepted_on_send: None,
                publish_after_ack: None,
                device_sign,
            },
            sent,
        )
    }

    fn for_directory_current(
        status: DirectoryCurrentV1,
        device_sign: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::from([received_exact(higher_publish())]),
                sent: Arc::clone(&sent),
                key_sync_replies: VecDeque::from([ScriptedKeySyncReply::DirectoryCurrent {
                    status,
                    header_revision: KEY_DIRECTORY_REVISION,
                }]),
                wrong_reply_route: false,
                queue_key_sync_route_accepted: false,
                queue_ack_route_accepted: false,
                fail_after_recording_ack: false,
                fail_after_recording_stream_ack: false,
                key_sync_send_count: 0,
                fail_on_key_sync_send: None,
                extra_key_sync_route_accepted_on_send: None,
                publish_after_ack: None,
                device_sign,
            },
            sent,
        )
    }

    fn with_reply_header_revision(mut self, revision: u64) -> Self {
        let first = self
            .key_sync_replies
            .front_mut()
            .expect("scripted reply exists");
        match first {
            ScriptedKeySyncReply::UpdateSet {
                header_revision, ..
            }
            | ScriptedKeySyncReply::DirectoryCurrent {
                header_revision, ..
            } => *header_revision = revision,
        }
        self
    }

    fn with_publish_after_ack(mut self, publish: OpaqueRouteFrame) -> Self {
        self.publish_after_ack = Some(publish);
        self
    }

    fn with_key_sync_route_accepted_after_reply(mut self) -> Self {
        self.queue_key_sync_route_accepted = true;
        self
    }

    fn with_key_sync_send_failure(mut self, send_number: usize) -> Self {
        assert!(send_number > 0);
        self.fail_on_key_sync_send = Some(send_number);
        self
    }

    fn with_stream_ack_failure(mut self) -> Self {
        self.fail_after_recording_stream_ack = true;
        self
    }

    fn with_extra_key_sync_route_accepted_on_send(mut self, send_number: usize) -> Self {
        assert!(send_number > 0);
        self.extra_key_sync_route_accepted_on_send = Some(send_number);
        self
    }

    fn for_script(
        initial_publish: OpaqueRouteFrame,
        key_sync_replies: VecDeque<ScriptedKeySyncReply>,
        queue_ack_route_accepted: bool,
        fail_after_recording_ack: bool,
        device_sign: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::from([received_exact(initial_publish)]),
                sent: Arc::clone(&sent),
                key_sync_replies,
                wrong_reply_route: false,
                queue_key_sync_route_accepted: false,
                queue_ack_route_accepted,
                fail_after_recording_ack,
                fail_after_recording_stream_ack: false,
                key_sync_send_count: 0,
                fail_on_key_sync_send: None,
                extra_key_sync_route_accepted_on_send: None,
                publish_after_ack: None,
                device_sign,
            },
            sent,
        )
    }

    fn for_recovery(
        key_sync_replies: VecDeque<ScriptedKeySyncReply>,
        device_sign: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: VecDeque::new(),
                sent: Arc::clone(&sent),
                key_sync_replies,
                wrong_reply_route: false,
                queue_key_sync_route_accepted: true,
                queue_ack_route_accepted: true,
                fail_after_recording_ack: false,
                fail_after_recording_stream_ack: false,
                key_sync_send_count: 0,
                fail_on_key_sync_send: None,
                extra_key_sync_route_accepted_on_send: None,
                publish_after_ack: None,
                device_sign,
            },
            sent,
        )
    }
}

#[async_trait]
impl RemoteRuntimeTransport for KeyUpdateTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        let bytes = frame.into_bytes();
        let decoded = decode(&bytes).expect("runtime only sends canonical Relay frames");
        let send = match decoded.body {
            RelayFrameBody::Ack(_) => {
                self.sent.lock().expect("sent recorder").push(bytes);
                if self.fail_after_recording_stream_ack {
                    self.fail_after_recording_stream_ack = false;
                    return Err(RemoteRuntimeTransportError::Failed(
                        "injected post-record stream ACK transport failure".into(),
                    ));
                }
                return Ok(());
            }
            RelayFrameBody::Send(send) => send,
            _ => panic!("key update flow may only emit opaque Relay Send or stream ACK"),
        };
        let control =
            open_command_control(&send.sealed_blob.0, send.request_route, &self.device_sign);
        self.sent.lock().expect("sent recorder").push(bytes);
        match control {
            KeyControlRequestV1::KeySync { .. } => {
                self.key_sync_send_count += 1;
                if self.fail_on_key_sync_send == Some(self.key_sync_send_count) {
                    self.fail_on_key_sync_send = None;
                    return Err(RemoteRuntimeTransportError::Failed(
                        "injected frozen KeySync probe send failure".into(),
                    ));
                }
                let request_route = if self.wrong_reply_route {
                    RequestRouteId::from_bytes([0xee; 16])
                } else {
                    send.request_route
                };
                if let Some(reply) = self.key_sync_replies.pop_front() {
                    let reply = match reply {
                        ScriptedKeySyncReply::UpdateSet {
                            update_set,
                            header_revision,
                        } => update_reply(request_route, update_set, header_revision),
                        ScriptedKeySyncReply::DirectoryCurrent {
                            status,
                            header_revision,
                        } => directory_current_reply(request_route, status, header_revision),
                    };
                    self.inbound.push_back(received_exact(reply));
                }
                if self.queue_key_sync_route_accepted {
                    self.inbound.push_back(received_exact(OpaqueRouteFrame {
                        version: RELAY_PROTOCOL_VERSION,
                        body: RelayFrameBody::RouteAccepted(RouteAccepted {
                            accepted: AcceptedRef::Request {
                                request_route: send.request_route,
                            },
                        }),
                    }));
                }
                if self.extra_key_sync_route_accepted_on_send == Some(self.key_sync_send_count) {
                    self.extra_key_sync_route_accepted_on_send = None;
                    self.inbound.push_back(received_exact(OpaqueRouteFrame {
                        version: RELAY_PROTOCOL_VERSION,
                        body: RelayFrameBody::RouteAccepted(RouteAccepted {
                            accepted: AcceptedRef::Request {
                                request_route: send.request_route,
                            },
                        }),
                    }));
                }
            }
            KeyControlRequestV1::KeyUpdateAck { .. } => {
                if self.fail_after_recording_ack {
                    self.fail_after_recording_ack = false;
                    return Err(RemoteRuntimeTransportError::Failed(
                        "injected post-record ACK transport failure".into(),
                    ));
                }
                if self.queue_ack_route_accepted {
                    self.inbound.push_back(received_exact(OpaqueRouteFrame {
                        version: RELAY_PROTOCOL_VERSION,
                        body: RelayFrameBody::RouteAccepted(RouteAccepted {
                            accepted: AcceptedRef::Request {
                                request_route: send.request_route,
                            },
                        }),
                    }));
                }
                if let Some(publish) = self.publish_after_ack.take() {
                    self.inbound.push_back(received_exact(publish));
                }
            }
            KeyControlRequestV1::StreamAppliedAck { .. } => {
                panic!("V5-B must not emit a V5-C StreamAppliedAck")
            }
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        Ok(self.inbound.pop_front())
    }
}

fn state_root(temp: &tempfile::TempDir) -> PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical key-update tempdir")
        .join("paired-state")
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
        let path = entry.expect("read key-update tree entry").path();
        if path.is_dir() {
            snapshot.extend(file_tree_bytes(&path));
        } else if path.is_file() {
            snapshot.push((
                path.clone(),
                fs::read(path).expect("snapshot key-update durable bytes"),
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

fn promote_and_install_binding(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
    root: &Path,
    observer: Arc<RecordingObserver>,
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
        observer.clone(),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open paired key-update fixture");
    let mut binding_rng = DeterministicRng::new([seed.wrapping_add(3); 32]);
    opened
        .install_stream_binding_for_automatic_harness(catalog_binding(fixture), &mut binding_rng)
        .expect("install authenticated catalog binding");
    drop(opened);
    observer.clear();
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
    revision: u64,
    purpose: KeyPurpose,
    epoch: u64,
    key: [u8; 32],
    seed: u8,
) -> KeyUpdateV1 {
    let revision = KeyDirectoryRevision::new(revision);
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
    update_set_at_revision(
        fixture,
        recipient,
        UPDATE_REVISION,
        CATALOG_EPOCH + 1,
        [0x82; 32],
        0x41,
    )
}

fn update_set_at_revision(
    fixture: &PairingFixture,
    recipient: &HpkePublicKey,
    revision: u64,
    catalog_epoch: u64,
    catalog_key: [u8; 32],
    seed: u8,
) -> KeyUpdateSetV1 {
    let set = KeyUpdateSetV1 {
        key_directory_revision: KeyDirectoryRevision::new(revision),
        device_route: fixture.device_route(),
        updates: vec![
            signed_update(
                fixture,
                recipient,
                revision,
                KeyPurpose::Catalog,
                catalog_epoch,
                catalog_key,
                seed,
            ),
            signed_update(
                fixture,
                recipient,
                revision,
                KeyPurpose::DeviceCommandTx,
                DEVICE_COMMAND_EPOCH,
                DEVICE_COMMAND_KEY,
                seed.wrapping_add(1),
            ),
            signed_update(
                fixture,
                recipient,
                revision,
                KeyPurpose::DeviceReplyTx,
                DEVICE_REPLY_EPOCH,
                DEVICE_REPLY_KEY,
                seed.wrapping_add(2),
            ),
        ],
    };
    set.validate().expect("canonical exact-next UpdateSet");
    set
}

fn higher_publish() -> OpaqueRouteFrame {
    higher_publish_at(UPDATE_REVISION, CATALOG_EPOCH + 1, [0x82; 32])
}

fn directory_advance_publish() -> OpaqueRouteFrame {
    directory_advance_publish_at(
        KEY_DIRECTORY_REVISION,
        KEY_DIRECTORY_REVISION,
        UPDATE_REVISION,
        CATALOG_STREAM_ROUTE,
        CATALOG_STREAM_GENERATION,
        OUTER_HIGH_WATER + 1,
        705,
    )
}

#[allow(clippy::too_many_arguments)]
fn directory_advance_publish_at(
    header_revision: u64,
    from_revision: u64,
    to_revision: u64,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    stream_seq: u64,
    sender_counter: u64,
) -> OpaqueRouteFrame {
    let context = OuterContextV1 {
        frame_kind: OuterFrameKind::CatalogPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(remote_pairing::MACHINE_ROUTE),
        device_route: None,
        stream_route: Some(stream_route),
        request_route: None,
        pair_route: None,
        stream_generation: Some(stream_generation),
        stream_cursor: None,
        stream_seq: Some(stream_seq),
        message_key_epoch: CATALOG_EPOCH,
    };
    let advance = DirectoryRevisionAdvanceV1 {
        from_key_directory_revision: KeyDirectoryRevision::new(from_revision),
        to_key_directory_revision: KeyDirectoryRevision::new(to_revision),
    };
    advance
        .validate()
        .expect("canonical directory revision advance");
    let control = KeyControlV1::directory_revision_advance(advance);
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
        CATALOG_EPOCH,
        header_revision,
        SecretAeadKey::from_bytes([0x71; 32]),
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        control.sealed_payload_kind(),
        &control
            .canonical_bytes()
            .expect("canonical DirectoryRevisionAdvance control"),
        SenderCounter(sender_counter),
    )
    .expect("seal DirectoryRevisionAdvance publication");
    let signed = sign_sealed(
        unsigned,
        &PairingFixture::machine_data_signing_key(),
        &context,
    );
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Publish(Publish {
            stream_route,
            generation: stream_generation,
            stream_seq,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn higher_publish_at(
    observed_revision: u64,
    observed_epoch: u64,
    observed_key: [u8; 32],
) -> OpaqueRouteFrame {
    catalog_publish_at(
        observed_revision,
        observed_epoch,
        observed_key,
        OUTER_HIGH_WATER + 1,
        INNER_HIGH_WATER + 1,
        705,
    )
}

fn catalog_publish_at(
    observed_revision: u64,
    observed_epoch: u64,
    observed_key: [u8; 32],
    stream_seq: u64,
    inner_revision: u64,
    sender_counter: u64,
) -> OpaqueRouteFrame {
    let context = OuterContextV1 {
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
        message_key_epoch: observed_epoch,
    };
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("live-key-update-trigger"),
        body: RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(CatalogDelta {
            catalog_revision: inner_revision,
            changes: Vec::new(),
        })),
    };
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: observed_epoch,
        },
        observed_epoch,
        observed_revision,
        SecretAeadKey::from_bytes(observed_key),
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        SealedPayloadKind::CatalogDelta,
        &envelope
            .to_json_bytes_checked()
            .expect("canonical higher-revision publication"),
        SenderCounter(sender_counter),
    )
    .expect("seal higher-revision publication");
    let signed = sign_sealed(
        unsigned,
        &PairingFixture::machine_data_signing_key(),
        &context,
    );
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Publish(Publish {
            stream_route: CATALOG_STREAM_ROUTE,
            generation: CATALOG_STREAM_GENERATION,
            stream_seq,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn update_reply(
    request_route: RequestRouteId,
    update_set: KeyUpdateSetV1,
    header_revision: u64,
) -> OpaqueRouteFrame {
    let context = OuterContextV1::directed_reply(
        remote_pairing::MACHINE_ROUTE,
        remote_pairing::DEVICE_ROUTE,
        request_route,
        DEVICE_REPLY_EPOCH,
    );
    let control = KeyControlV1::update_set(update_set);
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: DEVICE_REPLY_EPOCH,
        },
        DEVICE_REPLY_EPOCH,
        header_revision,
        SecretAeadKey::from_bytes(DEVICE_REPLY_KEY),
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        control.sealed_payload_kind(),
        &control
            .canonical_bytes()
            .expect("canonical UpdateSet control"),
        SenderCounter(
            900_u64
                .checked_add(header_revision)
                .expect("test reply counter remains bounded"),
        ),
    )
    .expect("seal exact-next UpdateSet Reply");
    let signed = sign_sealed(
        unsigned,
        &PairingFixture::machine_data_signing_key(),
        &context,
    );
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Reply(Reply {
            device_route: remote_pairing::DEVICE_ROUTE,
            request_route,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn directory_current(fixture: &PairingFixture) -> DirectoryCurrentV1 {
    DirectoryCurrentV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        current_key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        requested_key_directory_revision: KeyDirectoryRevision::new(UPDATE_REVISION),
    }
}

fn directory_current_reply(
    request_route: RequestRouteId,
    status: DirectoryCurrentV1,
    header_revision: u64,
) -> OpaqueRouteFrame {
    let context = OuterContextV1::directed_reply(
        remote_pairing::MACHINE_ROUTE,
        remote_pairing::DEVICE_ROUTE,
        request_route,
        DEVICE_REPLY_EPOCH,
    );
    let control = KeyControlV1::directory_current(status);
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: DEVICE_REPLY_EPOCH,
        },
        DEVICE_REPLY_EPOCH,
        header_revision,
        SecretAeadKey::from_bytes(DEVICE_REPLY_KEY),
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        control.sealed_payload_kind(),
        &control
            .canonical_bytes()
            .expect("canonical DirectoryCurrent control"),
        SenderCounter(900),
    )
    .expect("seal current-revision DirectoryCurrent Reply");
    let signed = sign_sealed(
        unsigned,
        &PairingFixture::machine_data_signing_key(),
        &context,
    );
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Reply(Reply {
            device_route: remote_pairing::DEVICE_ROUTE,
            request_route,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn open_command_control(
    sealed_blob: &[u8],
    request_route: RequestRouteId,
    device_sign: &VerifyingKey,
) -> KeyControlRequestV1 {
    let signed = SignedSealedBlobV1::from_wire_bytes(sealed_blob)
        .expect("outbound command carries canonical signed blob");
    assert_eq!(signed.inner.key_id.purpose, KeyPurpose::DeviceCommandTx);
    assert_eq!(signed.inner.key_epoch, DEVICE_COMMAND_EPOCH);
    let context = OuterContextV1::uplink_send(
        remote_pairing::MACHINE_ROUTE,
        remote_pairing::DEVICE_ROUTE,
        request_route,
        DEVICE_COMMAND_EPOCH,
    );
    let verified = verify_sealed(signed, device_sign, &context)
        .expect("outbound command has the real DeviceSign/AAD proof");
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
    assert_eq!(opened.payload_kind, SealedPayloadKind::KeyUpdate);
    KeyControlRequestV1::from_canonical_bytes(&opened.payload)
        .expect("canonical outbound key-control request")
}

fn prompt_request() -> SendPromptRequest {
    SendPromptRequest {
        conversation_id: ConversationId::new("conversation-predecessor-reply"),
        idempotency_key: IdempotencyKey::new("prompt-predecessor-reply"),
        expected_configuration_revision: 9,
        prompt: PromptPayload::new("验证 rewrap 后的旧 revision 回执")
            .expect("bounded predecessor prompt"),
    }
}

fn open_runtime_request(
    sealed_blob: &[u8],
    request_route: RequestRouteId,
    device_sign: &VerifyingKey,
) -> (MessageId, RuntimeRequest) {
    let signed = SignedSealedBlobV1::from_wire_bytes(sealed_blob)
        .expect("outbound request carries canonical signed blob");
    assert_eq!(signed.inner.key_id.purpose, KeyPurpose::DeviceCommandTx);
    let context = OuterContextV1::uplink_send(
        remote_pairing::MACHINE_ROUTE,
        remote_pairing::DEVICE_ROUTE,
        request_route,
        DEVICE_COMMAND_EPOCH,
    );
    let verified =
        verify_sealed(signed, device_sign, &context).expect("outbound request DeviceSign proof");
    let receiving = AeadReceivingKey::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: DEVICE_COMMAND_EPOCH,
        },
        DEVICE_COMMAND_EPOCH,
        SecretAeadKey::from_bytes(DEVICE_COMMAND_KEY),
    );
    let opened =
        open_sealed_payload(&receiving, &context, verified).expect("open outbound Runtime request");
    assert_eq!(opened.payload_kind, SealedPayloadKind::CommandRequest);
    let envelope = RuntimeEnvelope::from_json_bytes_checked(&opened.payload)
        .expect("canonical outbound Runtime request envelope");
    let RuntimeMessage::Request(request) = envelope.body else {
        panic!("outbound Runtime envelope is a request")
    };
    (envelope.message_id, request)
}

fn command_reply(
    request_route: RequestRouteId,
    message_id: MessageId,
    directory_revision: u64,
    sender_counter: u64,
) -> OpaqueRouteFrame {
    let context = OuterContextV1::directed_reply(
        remote_pairing::MACHINE_ROUTE,
        remote_pairing::DEVICE_ROUTE,
        request_route,
        DEVICE_REPLY_EPOCH,
    );
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id,
        body: RuntimeMessage::Reply(RuntimeReply::Command(CommandReceipt::Accepted {
            command_id: CommandId::new("command-predecessor-reply"),
            queue_position: 1,
            configuration_revision: 9,
        })),
    };
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: DEVICE_REPLY_EPOCH,
        },
        DEVICE_REPLY_EPOCH,
        directory_revision,
        SecretAeadKey::from_bytes(DEVICE_REPLY_KEY),
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        SealedPayloadKind::CommandReceipt,
        &envelope
            .to_json_bytes_checked()
            .expect("canonical predecessor Runtime reply"),
        SenderCounter(sender_counter),
    )
    .expect("seal predecessor Runtime reply");
    let signed = sign_sealed(
        unsigned,
        &PairingFixture::machine_data_signing_key(),
        &context,
    );
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Reply(Reply {
            device_route: remote_pairing::DEVICE_ROUTE,
            request_route,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn sent_ack(
    sent: &[Vec<u8>],
    device_sign: &VerifyingKey,
) -> (RequestRouteId, KeyUpdateAckV1, Vec<u8>) {
    sent.iter()
        .find_map(|bytes| {
            let frame = decode(bytes).expect("decode outbound key-control frame");
            let RelayFrameBody::Send(send) = frame.body else {
                return None;
            };
            match open_command_control(&send.sealed_blob.0, send.request_route, device_sign) {
                KeyControlRequestV1::KeyUpdateAck { ack } => {
                    Some((send.request_route, ack, bytes.clone()))
                }
                KeyControlRequestV1::KeySync { .. }
                | KeyControlRequestV1::StreamAppliedAck { .. } => None,
            }
        })
        .expect("one authenticated KeyUpdateAck Send")
}

fn sent_command(
    bytes: &[u8],
    device_sign: &VerifyingKey,
) -> (RequestRouteId, u64, KeyControlRequestV1) {
    let frame = decode(bytes).expect("decode outbound key-control frame");
    let RelayFrameBody::Send(send) = frame.body else {
        panic!("outbound key-control carrier is Relay Send")
    };
    let signed = SignedSealedBlobV1::from_wire_bytes(&send.sealed_blob.0)
        .expect("outbound key-control signed blob");
    let revision = signed.inner.key_directory_revision;
    let control = open_command_control(&send.sealed_blob.0, send.request_route, device_sign);
    (send.request_route, revision, control)
}

fn sent_stream_ack_cuts(sent: &[Vec<u8>]) -> Vec<(StreamRouteId, StreamGenerationId, u64)> {
    sent.iter()
        .filter_map(|bytes| {
            let frame = decode(bytes).expect("decode outbound Relay frame");
            let RelayFrameBody::Ack(ack) = frame.body else {
                return None;
            };
            Some((ack.stream_route, ack.generation, ack.up_to_seq))
        })
        .collect()
}

fn reducer() -> RejectingReducer {
    RejectingReducer {
        cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
    }
}

async fn install_revision_only_rewrap(
    fixture: &PairingFixture,
    store: &MemoryRemoteKeyStore,
    root: &Path,
    recipient: &HpkePublicKey,
    device_sign: &VerifyingKey,
    revision: u64,
    durable_inner_high_water: u64,
) {
    let update_set = update_set_at_revision(
        fixture,
        recipient,
        revision,
        CATALOG_EPOCH,
        [0x71; 32],
        u8::try_from(revision).unwrap_or(0x61),
    );
    let trigger = catalog_publish_at(
        revision,
        CATALOG_EPOCH,
        [0x71; 32],
        OUTER_HIGH_WATER + 2,
        durable_inner_high_water + 1,
        706_u64
            .checked_add(revision)
            .expect("bounded trigger counter"),
    );
    let (transport, _) = KeyUpdateTransport::for_script(
        trigger,
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set,
            header_revision: revision,
        }]),
        false,
        false,
        *device_sign,
    );
    let opened = PairedMachineStore::new(store, INSTALLATION_ID, root)
        .open_exact(fixture.identity())
        .expect("open revision-only rewrap fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = RejectingReducer {
        cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(durable_inner_high_water),
        },
    };

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision,
            ..
        }) if key_directory_revision == revision
    ));
}

#[tokio::test]
async fn reducer_capacity_rejects_subscribe_and_receive_before_io_or_durable_mutation() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("reducer capacity state root");
    let root = state_root(&temp);
    fixture.promote(&store, &root, 0x34);

    let observer = Arc::new(RecordingObserver::default());
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    );
    let opened = paired
        .open_exact(fixture.identity())
        .expect("open reducer capacity fixture");
    observer.clear();
    let before = file_tree_bytes(&root);
    let cursor = RuntimeInnerCursor::Catalog {
        cursor: StreamCursor::At(INNER_HIGH_WATER),
    };
    let mut reducer = OverCapacityReducer {
        cursor: cursor.clone(),
    };
    let mut runtime = RemoteRuntime::new(opened, PanicTransport);
    let mut rng = PanicRng;

    let subscribe_error = match runtime.subscribe(cursor, &mut reducer, &mut rng).await {
        Err(error) => error,
        Ok(_) => panic!("over-capacity subscribe unexpectedly succeeded"),
    };
    assert!(matches!(
        subscribe_error,
        RemoteRuntimeError::ReducerCapacity
    ));
    assert_eq!(subscribe_error.code(), "remote.runtime.reducer_capacity");
    assert_eq!(file_tree_bytes(&root), before);
    assert!(observer.snapshot().is_empty());

    let receive_error = match runtime.receive_stream_frame(&mut reducer).await {
        Err(error) => error,
        Ok(_) => panic!("over-capacity receive unexpectedly succeeded"),
    };
    assert!(matches!(receive_error, RemoteRuntimeError::ReducerCapacity));
    assert_eq!(receive_error.code(), "remote.runtime.reducer_capacity");
    assert_eq!(file_tree_bytes(&root), before);
    assert!(observer.snapshot().is_empty());
}

#[tokio::test]
async fn revision_only_rewrap_recovers_exact_predecessor_pending_stream_frame() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("pending predecessor stream state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x35);
    let predecessor = catalog_publish_at(
        KEY_DIRECTORY_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        OUTER_HIGH_WATER + 1,
        INNER_HIGH_WATER + 1,
        704,
    );
    let (transport, sent) = StreamReplayTransport::new(vec![predecessor.clone()], false);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open predecessor pending fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LiveCatalogReducer::rejecting(INNER_HIGH_WATER);

    let rejected = runtime.receive_stream_frame(&mut reducer).await;
    assert!(matches!(
        rejected,
        Err(RemoteRuntimeError::InvalidReply(
            "injected live reducer rejection"
        ))
    ));
    assert!(sent.lock().expect("predecessor pending sends").is_empty());
    drop(runtime);

    install_revision_only_rewrap(
        &fixture,
        &store,
        &root,
        &recipient,
        &device_sign,
        UPDATE_REVISION,
        INNER_HIGH_WATER,
    )
    .await;
    install_revision_only_rewrap(
        &fixture,
        &store,
        &root,
        &recipient,
        &device_sign,
        SECOND_UPDATE_REVISION,
        INNER_HIGH_WATER,
    )
    .await;

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen rewrapped predecessor pending fixture");
    let before = reopened
        .durable_stream_bindings()
        .expect("read predecessor pending binding");
    assert_eq!(before.len(), 1);
    assert_eq!(
        before[0].binding().key_directory_revision.value(),
        SECOND_UPDATE_REVISION
    );
    assert_eq!(
        before[0].outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER)
    );
    assert_eq!(
        before[0]
            .replay_tuple()
            .expect("pending predecessor tuple survives rewrap")
            .stream_seq(),
        OUTER_HIGH_WATER + 1
    );

    let (transport, sent) = StreamReplayTransport::new(vec![predecessor], false);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::Applied(item))
            if matches!(item.as_ref(), RuntimeStreamItem::CatalogDelta(delta)
                if delta.catalog_revision == INNER_HIGH_WATER + 1)
    ));
    assert_eq!(reducer.applied, 1);
    assert_eq!(sent.lock().expect("pending predecessor ACKs").len(), 1);
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen applied predecessor pending fixture");
    let after = reopened
        .durable_stream_bindings()
        .expect("read applied predecessor pending binding");
    assert_eq!(after.len(), 1);
    assert_eq!(
        after[0].outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER + 1)
    );
    assert_eq!(
        after[0].outer_acked(),
        StreamCursor::At(OUTER_HIGH_WATER + 1)
    );
}

#[tokio::test]
async fn revision_only_rewrap_reacks_exact_predecessor_applied_duplicate() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("applied predecessor stream state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x45);
    let predecessor = catalog_publish_at(
        KEY_DIRECTORY_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        OUTER_HIGH_WATER + 1,
        INNER_HIGH_WATER + 1,
        708,
    );
    let (transport, sent) = StreamReplayTransport::new(vec![predecessor.clone()], true);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open predecessor ACK-loss fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);

    let ack_failure = runtime.receive_stream_frame(&mut reducer).await;
    assert!(matches!(
        ack_failure,
        Err(RemoteRuntimeError::Transport(
            RemoteRuntimeTransportError::Failed(message)
        )) if message == "injected predecessor ACK send failure"
    ));
    assert_eq!(reducer.applied, 1);
    assert_eq!(sent.lock().expect("failed predecessor ACK").len(), 1);
    drop(runtime);

    install_revision_only_rewrap(
        &fixture,
        &store,
        &root,
        &recipient,
        &device_sign,
        UPDATE_REVISION,
        INNER_HIGH_WATER + 1,
    )
    .await;

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen rewrapped predecessor ACK-loss fixture");
    let before = reopened
        .durable_stream_bindings()
        .expect("read predecessor ACK-loss binding");
    assert_eq!(before.len(), 1);
    assert_eq!(
        before[0].binding().key_directory_revision.value(),
        UPDATE_REVISION
    );
    assert_eq!(
        before[0].outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER + 1)
    );
    assert_ne!(before[0].outer_acked(), before[0].outer_applied());

    let (transport, sent) = StreamReplayTransport::new(vec![predecessor], false);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER + 1);
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::AppliedDuplicate)
    ));
    assert_eq!(
        reducer.applied, 0,
        "applied duplicate must not re-enter reducer"
    );
    assert_eq!(sent.lock().expect("replayed predecessor ACK").len(), 1);
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen re-ACKed predecessor fixture");
    let after = reopened
        .durable_stream_bindings()
        .expect("read re-ACKed predecessor binding");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].outer_acked(), after[0].outer_applied());
}

#[tokio::test]
async fn revision_only_rewrap_rejects_unseen_predecessor_without_stream_mutation() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("unseen predecessor stream state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x55);
    install_revision_only_rewrap(
        &fixture,
        &store,
        &root,
        &recipient,
        &device_sign,
        UPDATE_REVISION,
        INNER_HIGH_WATER,
    )
    .await;
    install_revision_only_rewrap(
        &fixture,
        &store,
        &root,
        &recipient,
        &device_sign,
        SECOND_UPDATE_REVISION,
        INNER_HIGH_WATER,
    )
    .await;

    let unseen = catalog_publish_at(
        KEY_DIRECTORY_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        OUTER_HIGH_WATER + 1,
        INNER_HIGH_WATER + 1,
        799,
    );
    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen unseen predecessor fixture");
    let (transport, sent) = StreamReplayTransport::new(vec![unseen], false);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);
    let rejected = runtime.receive_stream_frame(&mut reducer).await;
    assert_eq!(
        rejected.expect_err("unseen predecessor is rejected").code(),
        "remote.crypto.key_revision_rollback"
    );
    assert_eq!(reducer.applied, 0);
    assert!(sent.lock().expect("unseen predecessor sends").is_empty());
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen rejected unseen predecessor fixture");
    let bindings = reopened
        .durable_stream_bindings()
        .expect("read rejected unseen predecessor binding");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].replay_entry_count(), 0);
    assert_eq!(
        bindings[0].outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER)
    );
}

#[tokio::test]
async fn revision_only_rewrap_quarantines_predecessor_nonce_reuse() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("predecessor nonce-reuse state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x65);
    let sender_counter = 804;
    let predecessor = catalog_publish_at(
        KEY_DIRECTORY_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        OUTER_HIGH_WATER + 1,
        INNER_HIGH_WATER + 1,
        sender_counter,
    );
    let (transport, _) = StreamReplayTransport::new(vec![predecessor], false);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open predecessor nonce-reuse fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LiveCatalogReducer::rejecting(INNER_HIGH_WATER);
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Err(RemoteRuntimeError::InvalidReply(
            "injected live reducer rejection"
        ))
    ));
    drop(runtime);

    install_revision_only_rewrap(
        &fixture,
        &store,
        &root,
        &recipient,
        &device_sign,
        UPDATE_REVISION,
        INNER_HIGH_WATER,
    )
    .await;
    let conflicting = catalog_publish_at(
        KEY_DIRECTORY_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        OUTER_HIGH_WATER + 1,
        INNER_HIGH_WATER + 2,
        sender_counter,
    );
    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen predecessor nonce-reuse fixture");
    let (transport, sent) = StreamReplayTransport::new(vec![conflicting], false);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);
    let rejected = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("same predecessor nonce with different ciphertext is quarantined");
    assert_eq!(rejected.code(), "remote.crypto.nonce_reuse");
    assert_eq!(reducer.applied, 0);
    assert!(
        sent.lock()
            .expect("nonce-reuse predecessor sends")
            .is_empty()
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen quarantined predecessor fixture");
    let bindings = reopened
        .durable_stream_bindings()
        .expect("read quarantined predecessor binding");
    assert_eq!(bindings.len(), 1);
    assert!(bindings[0].replay_quarantined());
    assert_eq!(
        bindings[0].outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER)
    );
}

#[tokio::test]
async fn pending_send_accepts_intermediate_reply_after_multiple_rewraps_and_reopens() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("predecessor directed reply state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x75);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open predecessor directed pending fixture");
    let (transport, first_sent) = DirectedReplayTransport::new(None, 850, device_sign);
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0x76; 32]);
    assert!(matches!(
        runtime.prompt(prompt_request(), &mut rng).await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    let frozen_send = first_sent
        .lock()
        .expect("first predecessor directed send")
        .first()
        .expect("one frozen predecessor directed send")
        .clone();
    drop(runtime);

    install_revision_only_rewrap(
        &fixture,
        &store,
        &root,
        &recipient,
        &device_sign,
        UPDATE_REVISION,
        INNER_HIGH_WATER,
    )
    .await;
    install_revision_only_rewrap(
        &fixture,
        &store,
        &root,
        &recipient,
        &device_sign,
        SECOND_UPDATE_REVISION,
        INNER_HIGH_WATER,
    )
    .await;

    let durable_before_invalid = file_tree_bytes(&root);

    // frozen request 签入 R，因此 R-1 是 rollback；即使 raw key/epoch/prefix 相同，也必须
    // 在 replay mutation 前拒绝，并保留原 durable pending intent。
    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen predecessor directed rollback fixture");
    let (transport, rollback_sent) =
        DirectedReplayTransport::new(Some(KEY_DIRECTORY_REVISION - 1), 851, device_sign);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut panic_rng = PanicRng;
    assert!(
        runtime
            .prompt(prompt_request(), &mut panic_rng)
            .await
            .is_err()
    );
    assert_eq!(
        rollback_sent
            .lock()
            .expect("rollback predecessor send")
            .as_slice(),
        [frozen_send.clone()].as_slice()
    );
    drop(runtime);
    assert_eq!(file_tree_bytes(&root), durable_before_invalid);

    // current 是 R+2，R+3 是 future；同样必须零 mutation 拒绝。
    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen predecessor directed future fixture");
    let (transport, future_sent) =
        DirectedReplayTransport::new(Some(SECOND_UPDATE_REVISION + 1), 852, device_sign);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut panic_rng = PanicRng;
    assert!(
        runtime
            .prompt(prompt_request(), &mut panic_rng)
            .await
            .is_err()
    );
    assert_eq!(
        future_sent
            .lock()
            .expect("future predecessor send")
            .as_slice(),
        [frozen_send.clone()].as_slice()
    );
    drop(runtime);
    assert_eq!(file_tree_bytes(&root), durable_before_invalid);

    // daemon 合法地可在 R+1 完成，而 device 已推进到 R+2。完整验签的中间 revision
    // 应完成同一 frozen intent；ReplayWindow 仍持久化 current R+2 作为 high-water。
    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen predecessor directed intermediate fixture");
    let (transport, intermediate_sent) =
        DirectedReplayTransport::new(Some(UPDATE_REVISION), 853, device_sign);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut panic_rng = PanicRng;
    let outcome = runtime
        .prompt(prompt_request(), &mut panic_rng)
        .await
        .expect("frozen request accepts a same-lineage intermediate reply");
    assert!(matches!(
        outcome.receipt(),
        CommandReceipt::Accepted {
            command_id,
            configuration_revision: 9,
            ..
        } if command_id.as_str() == "command-predecessor-reply"
    ));
    assert_eq!(
        intermediate_sent
            .lock()
            .expect("intermediate predecessor retry send")
            .as_slice(),
        [frozen_send.clone()].as_slice()
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("intermediate reply replay window and terminal reopen");
    let (transport, terminal_sent) = DirectedReplayTransport::new(None, 854, device_sign);
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut panic_rng = PanicRng;
    let reopened_outcome = runtime
        .prompt(prompt_request(), &mut panic_rng)
        .await
        .expect("durable terminal survives replay-window audit");
    assert_eq!(reopened_outcome.receipt(), outcome.receipt());
    assert!(
        terminal_sent
            .lock()
            .expect("terminal reopen sends")
            .is_empty()
    );
}

#[tokio::test]
async fn directory_advance_crash_after_replay_commit_recovers_exact_signed_frame() {
    let fixture = PairingFixture::new();
    let store = Arc::new(MemoryRemoteKeyStore::new());
    let temp = tempfile::tempdir().expect("directory advance replay-to-ADKS crash state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (_recipient, device_sign) =
        promote_and_install_binding(&fixture, store.as_ref(), &root, observer.clone(), 0x8f);
    let advance = directory_advance_publish();
    let signed_frame_sha256 = sha256(&encode(&advance));
    let ciphertext_sha256 = match &advance.body {
        RelayFrameBody::Publish(publish) => {
            let signed = SignedSealedBlobV1::from_wire_bytes(&publish.sealed_blob.0)
                .expect("directory advance carries canonical signed payload");
            sha256(&signed.inner.ciphertext)
        }
        _ => panic!("directory advance fixture must be a Publish"),
    };
    let (transport, sent_before_crash) =
        KeyUpdateTransport::for_script(advance.clone(), VecDeque::new(), false, false, device_sign);

    observer.arm_crash_after_state_stage_cleared();
    let task_store = Arc::clone(&store);
    let task_root = root.clone();
    let task_observer = Arc::clone(&observer);
    let task_identity = fixture.identity();
    let crashed = tokio::spawn(async move {
        let opened = PairedMachineStore::new_with_mutation_observer(
            task_store.as_ref(),
            INSTALLATION_ID,
            &task_root,
            task_observer,
        )
        .open_exact(task_identity)
        .expect("open replay-to-ADKS crash fixture");
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);
        runtime.receive_stream_frame(&mut reducer).await
    })
    .await;
    assert!(crashed.is_err(), "observer must terminate the receive task");
    assert!(crashed.unwrap_err().is_panic());
    assert!(
        sent_before_crash
            .lock()
            .expect("pre-crash sent frames")
            .is_empty(),
        "the replay-tuple CAS cut occurs before any KeySync probe",
    );
    assert_eq!(
        observer
            .snapshot()
            .iter()
            .filter(|stage| **stage == PairedMutationStage::StateStageCleared)
            .count(),
        1,
        "the injected crash must cut immediately after the first paired-state CAS",
    );

    let reopened = PairedMachineStore::new(store.as_ref(), INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("cold-open replay tuple committed before ADKS");
    let binding = reopened
        .durable_stream_bindings()
        .expect("read crash-cut stream binding")
        .pop()
        .expect("one Catalog binding");
    let replay = binding
        .replay_tuple()
        .expect("directory advance replay tuple survived the crash");
    assert_eq!(replay.stream_seq(), OUTER_HIGH_WATER + 1);
    assert_eq!(replay.sender_counter(), 705);
    assert_eq!(replay.signed_frame_sha256(), signed_frame_sha256);
    assert_eq!(replay.ciphertext_sha256(), ciphertext_sha256);
    assert_eq!(binding.outer_applied(), StreamCursor::At(OUTER_HIGH_WATER));
    assert_eq!(
        binding.inner_observed(),
        &RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        },
    );
    assert_eq!(binding.inner_applied(), binding.inner_observed());
    assert!(
        reopened
            .durable_key_sync_state()
            .expect("read crash-cut ADKS")
            .is_none(),
        "the first CAS must not imply that the independent ADKS CAS committed",
    );
    drop(reopened);

    observer.clear();
    let (retry_transport, retry_sent) =
        KeyUpdateTransport::for_script(advance, VecDeque::new(), false, false, device_sign);
    let reopened = PairedMachineStore::new_with_mutation_observer(
        store.as_ref(),
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("reopen exact directory advance retry");
    let mut runtime = RemoteRuntime::new(reopened, retry_transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert_eq!(reducer.applied, 0);
    assert_eq!(
        observer
            .snapshot()
            .iter()
            .filter(|stage| **stage == PairedMutationStage::StateStageCleared)
            .count(),
        1,
        "exact replay skips a second tuple CAS and commits only the new ADKS",
    );
    assert_eq!(
        retry_sent.lock().expect("retry sent frames").len(),
        1,
        "exact replay starts one bounded KeySync probe",
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(store.as_ref(), INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen ADKS created by exact frame retry");
    let retried_binding = reopened
        .durable_stream_bindings()
        .expect("read retried stream binding")
        .pop()
        .expect("one Catalog binding");
    assert_eq!(retried_binding.replay_tuple(), Some(replay));
    let active = reopened
        .durable_key_sync_state()
        .expect("read retry ADKS")
        .expect("exact retry creates ADKS");
    assert_eq!(active.status(), KeySyncCoordinationStatus::Active);
    assert_eq!(
        active.observation().signed_frame_sha256(),
        replay.signed_frame_sha256(),
    );
    assert_eq!(
        active.observation().ciphertext_sha256(),
        replay.ciphertext_sha256(),
    );
    assert_eq!(
        retried_binding.outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER),
        "ADKS coordination still cannot advance the business outer cut",
    );
}

#[tokio::test]
async fn directory_advance_replay_is_durable_before_cold_recovery_commits_outer_only() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("directory advance cold-recovery state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x91);
    let update = update_set_at_revision(
        &fixture,
        &recipient,
        UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x92,
    );
    let (transport, _) = KeyUpdateTransport::for_script(
        directory_advance_publish(),
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: update.clone(),
            header_revision: UPDATE_REVISION,
        }]),
        true,
        false,
        device_sign,
    );
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open directory advance fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert_eq!(reducer.applied, 0);
    assert_eq!(
        reducer.inner_cursor(),
        &RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(INNER_HIGH_WATER),
        }
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after durable directory advance admission");
    let before = reopened
        .durable_stream_bindings()
        .expect("read admitted Catalog binding")
        .pop()
        .expect("one Catalog binding");
    assert_eq!(before.outer_applied(), StreamCursor::At(OUTER_HIGH_WATER));
    assert_eq!(before.inner_observed(), reducer.inner_cursor());
    assert_eq!(before.inner_applied(), reducer.inner_cursor());
    let replay = before
        .replay_tuple()
        .expect("old revision replay is durable");
    assert_eq!(
        replay.key_directory_revision(),
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION)
    );
    assert_eq!(replay.stream_seq(), OUTER_HIGH_WATER + 1);
    assert_eq!(replay.sender_counter(), 705);
    let active = reopened
        .durable_key_sync_state()
        .expect("read active directory advance ADKS")
        .expect("directory advance starts durable KeySync");
    assert_eq!(active.status(), KeySyncCoordinationStatus::Active);

    let (recovery_transport, recovery_sent) = KeyUpdateTransport::for_recovery(
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: update,
            header_revision: UPDATE_REVISION,
        }]),
        device_sign,
    );
    let mut recovered = RemoteRuntime::new(reopened, recovery_transport);
    recovered
        .recover_durable_key_sync()
        .await
        .expect("cold recovery installs keys, ACKs update, then commits directory advance");
    let recovery_sent = recovery_sent
        .lock()
        .expect("directory advance recovery sent frames")
        .clone();
    assert_eq!(
        sent_stream_ack_cuts(&recovery_sent),
        vec![(
            CATALOG_STREAM_ROUTE,
            CATALOG_STREAM_GENERATION,
            OUTER_HIGH_WATER + 1,
        )]
    );

    drop(recovered);
    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen committed directory advance");
    let committed = reopened
        .durable_stream_bindings()
        .expect("read committed Catalog binding")
        .pop()
        .expect("one Catalog binding");
    assert_eq!(
        committed.binding().key_directory_revision,
        KeyDirectoryRevision::new(UPDATE_REVISION)
    );
    assert_eq!(
        committed.outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER + 1)
    );
    assert_eq!(
        committed.outer_acked(),
        StreamCursor::At(OUTER_HIGH_WATER + 1)
    );
    assert_eq!(committed.inner_observed(), reducer.inner_cursor());
    assert_eq!(committed.inner_applied(), reducer.inner_cursor());
    assert_eq!(reducer.applied, 0, "control never enters the reducer");
}

#[tokio::test]
async fn directory_advance_stream_ack_failure_recovers_committed_outer_without_inner_reapply() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("directory advance ACK crash state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x93);
    let update = update_set_at_revision(
        &fixture,
        &recipient,
        UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x94,
    );
    let (transport, first_sent) = KeyUpdateTransport::for_script(
        directory_advance_publish(),
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: update,
            header_revision: UPDATE_REVISION,
        }]),
        true,
        false,
        device_sign,
    );
    let transport = transport.with_stream_ack_failure();
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open directory advance ACK crash fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("stream ACK failure occurs after durable outer commit");
    assert_eq!(error.code(), "remote.runtime.transport_failed");
    assert_eq!(
        sent_stream_ack_cuts(&first_sent.lock().expect("failed stream ACK frames").clone()),
        vec![(
            CATALOG_STREAM_ROUTE,
            CATALOG_STREAM_GENERATION,
            OUTER_HIGH_WATER + 1,
        )]
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after committed outer / failed ACK");
    let pending_ack = reopened
        .durable_stream_bindings()
        .expect("read pending stream ACK binding")
        .pop()
        .expect("one Catalog binding");
    assert_eq!(
        pending_ack.outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER + 1)
    );
    assert_ne!(pending_ack.outer_acked(), pending_ack.outer_applied());
    assert_eq!(pending_ack.inner_observed(), reducer.inner_cursor());
    assert_eq!(pending_ack.inner_applied(), reducer.inner_cursor());

    let (recovery_transport, recovery_sent) =
        KeyUpdateTransport::for_recovery(VecDeque::new(), device_sign);
    let mut recovered = RemoteRuntime::new(reopened, recovery_transport);
    recovered
        .recover_durable_key_sync()
        .await
        .expect("resolved cold recovery re-ACKs update then retries cumulative stream ACK");
    assert_eq!(
        sent_stream_ack_cuts(
            &recovery_sent
                .lock()
                .expect("retried stream ACK frames")
                .clone()
        ),
        vec![(
            CATALOG_STREAM_ROUTE,
            CATALOG_STREAM_GENERATION,
            OUTER_HIGH_WATER + 1,
        )]
    );
    drop(recovered);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after stream ACK retry");
    let recovered = reopened
        .durable_stream_bindings()
        .expect("read ACKed binding")
        .pop()
        .expect("one Catalog binding");
    assert_eq!(recovered.outer_acked(), recovered.outer_applied());
    assert_eq!(recovered.inner_observed(), reducer.inner_cursor());
    assert_eq!(recovered.inner_applied(), reducer.inner_cursor());
    assert_eq!(reducer.applied, 0);
}

#[tokio::test]
async fn consecutive_directory_advances_do_not_reack_the_predecessor_revision() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("consecutive directory-advance state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x95);
    let first = update_set_at_revision(
        &fixture,
        &recipient,
        UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x96,
    );
    let second = update_set_at_revision(
        &fixture,
        &recipient,
        SECOND_UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x97,
    );
    let second_advance = directory_advance_publish_at(
        UPDATE_REVISION,
        UPDATE_REVISION,
        SECOND_UPDATE_REVISION,
        CATALOG_STREAM_ROUTE,
        CATALOG_STREAM_GENERATION,
        OUTER_HIGH_WATER + 2,
        706,
    );
    let (transport, sent) = KeyUpdateTransport::for_script(
        directory_advance_publish(),
        VecDeque::from([
            ScriptedKeySyncReply::UpdateSet {
                update_set: first,
                header_revision: UPDATE_REVISION,
            },
            ScriptedKeySyncReply::UpdateSet {
                update_set: second,
                header_revision: SECOND_UPDATE_REVISION,
            },
        ]),
        false,
        false,
        device_sign,
    );
    let transport = transport.with_publish_after_ack(second_advance);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open consecutive directory-advance fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: UPDATE_REVISION,
            next_attempt: None,
        })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: SECOND_UPDATE_REVISION,
            next_attempt: None,
        })
    ));

    let sent = sent
        .lock()
        .expect("consecutive directory-advance sent frames")
        .clone();
    assert_eq!(sent.len(), 6);
    let (_, first_probe_revision, first_probe) = sent_command(&sent[0], &device_sign);
    let (_, first_ack_revision, first_ack) = sent_command(&sent[1], &device_sign);
    let (_, second_probe_revision, second_probe) = sent_command(&sent[3], &device_sign);
    let (_, second_ack_revision, second_ack) = sent_command(&sent[4], &device_sign);
    assert!(matches!(first_probe, KeyControlRequestV1::KeySync { .. }));
    assert!(matches!(
        first_ack,
        KeyControlRequestV1::KeyUpdateAck { .. }
    ));
    assert!(matches!(second_probe, KeyControlRequestV1::KeySync { .. }));
    assert!(matches!(
        second_ack,
        KeyControlRequestV1::KeyUpdateAck { .. }
    ));
    assert_eq!(first_probe_revision, UPDATE_REVISION);
    assert_eq!(first_ack_revision, UPDATE_REVISION);
    assert_eq!(second_probe_revision, SECOND_UPDATE_REVISION);
    assert_eq!(second_ack_revision, SECOND_UPDATE_REVISION);
    assert_eq!(
        sent_stream_ack_cuts(&sent),
        vec![
            (
                CATALOG_STREAM_ROUTE,
                CATALOG_STREAM_GENERATION,
                OUTER_HIGH_WATER + 1,
            ),
            (
                CATALOG_STREAM_ROUTE,
                CATALOG_STREAM_GENERATION,
                OUTER_HIGH_WATER + 2,
            ),
        ]
    );
    assert_eq!(reducer.applied, 0, "control never enters the reducer");
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after consecutive directory advances");
    let state = reopened
        .durable_key_sync_state()
        .expect("read second resolved ADKS")
        .expect("second directory advance remains durable");
    assert_eq!(state.status(), KeySyncCoordinationStatus::Resolved);
    assert_eq!(state.attempt(), 1);
    assert_eq!(
        state
            .latest_completed_ack_basis()
            .expect("second completion basis")
            .key_directory_revision()
            .value(),
        SECOND_UPDATE_REVISION
    );
    let binding = reopened
        .durable_stream_bindings()
        .expect("read twice-advanced Catalog binding")
        .pop()
        .expect("one Catalog binding");
    assert_eq!(
        binding.binding().key_directory_revision.value(),
        SECOND_UPDATE_REVISION
    );
    assert_eq!(
        binding.outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER + 2)
    );
    assert_eq!(binding.outer_acked(), binding.outer_applied());
}

#[tokio::test]
async fn directory_advance_supersession_probe_failure_cold_retries_only_the_new_probe() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("directory-advance supersession recovery state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0x98);
    let first = update_set_at_revision(
        &fixture,
        &recipient,
        UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x99,
    );
    let second = update_set_at_revision(
        &fixture,
        &recipient,
        SECOND_UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x9a,
    );
    let second_advance = directory_advance_publish_at(
        UPDATE_REVISION,
        UPDATE_REVISION,
        SECOND_UPDATE_REVISION,
        CATALOG_STREAM_ROUTE,
        CATALOG_STREAM_GENERATION,
        OUTER_HIGH_WATER + 2,
        706,
    );
    let (transport, first_sent) = KeyUpdateTransport::for_script(
        directory_advance_publish(),
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: first,
            header_revision: UPDATE_REVISION,
        }]),
        false,
        false,
        device_sign,
    );
    let transport = transport
        .with_publish_after_ack(second_advance)
        .with_key_sync_send_failure(2);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open directory-advance supersession fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LiveCatalogReducer::at(INNER_HIGH_WATER);

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: UPDATE_REVISION,
            next_attempt: None,
        })
    ));
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("new-cycle probe fails after typed-notice ADKS CAS");
    assert_eq!(error.code(), "remote.runtime.transport_failed");
    let first_sent = first_sent
        .lock()
        .expect("directory-advance pre-crash sent frames")
        .clone();
    assert_eq!(first_sent.len(), 4);
    let frozen_probe = first_sent[3].clone();
    let (_, frozen_revision, frozen_control) = sent_command(&frozen_probe, &device_sign);
    assert_eq!(frozen_revision, SECOND_UPDATE_REVISION);
    assert!(matches!(
        frozen_control,
        KeyControlRequestV1::KeySync { .. }
    ));
    assert_eq!(
        sent_stream_ack_cuts(&first_sent),
        vec![(
            CATALOG_STREAM_ROUTE,
            CATALOG_STREAM_GENERATION,
            OUTER_HIGH_WATER + 1,
        )]
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen typed-notice ADKS after probe send failure");
    let active = reopened
        .durable_key_sync_state()
        .expect("read superseding ADKS")
        .expect("superseding ADKS remains durable");
    assert_eq!(active.status(), KeySyncCoordinationStatus::Active);
    assert_eq!(
        active.latest_completed_ack_basis(),
        None,
        "typed notice proves predecessor completion; old ACK must not survive the CAS"
    );
    assert_eq!(
        active
            .active_send()
            .expect("new probe remains frozen")
            .exact_send_bytes(),
        frozen_probe.as_slice()
    );

    let (recovery_transport, recovery_sent) = KeyUpdateTransport::for_recovery(
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: second,
            header_revision: SECOND_UPDATE_REVISION,
        }]),
        device_sign,
    );
    let mut recovered = RemoteRuntime::new(reopened, recovery_transport);
    recovered
        .recover_durable_key_sync()
        .await
        .expect("cold recovery exact-retries only the new probe and finishes the notice");
    let recovery_sent = recovery_sent
        .lock()
        .expect("directory-advance recovery sent frames")
        .clone();
    assert_eq!(recovery_sent.len(), 3);
    assert_eq!(recovery_sent[0], frozen_probe);
    let (_, new_ack_revision, new_ack) = sent_command(&recovery_sent[1], &device_sign);
    assert_eq!(new_ack_revision, SECOND_UPDATE_REVISION);
    assert!(matches!(new_ack, KeyControlRequestV1::KeyUpdateAck { .. }));
    assert_eq!(
        sent_stream_ack_cuts(&recovery_sent),
        vec![(
            CATALOG_STREAM_ROUTE,
            CATALOG_STREAM_GENERATION,
            OUTER_HIGH_WATER + 2,
        )]
    );
    drop(recovered);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after typed-notice cold recovery");
    let binding = reopened
        .durable_stream_bindings()
        .expect("read recovered Catalog binding")
        .pop()
        .expect("one Catalog binding");
    assert_eq!(
        binding.outer_applied(),
        StreamCursor::At(OUTER_HIGH_WATER + 2)
    );
    assert_eq!(binding.outer_acked(), binding.outer_applied());
    assert_eq!(reducer.applied, 0);
}

#[tokio::test]
async fn update_reply_combines_install_before_ack_and_restart_reseals_same_basis() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("live key-update state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer.clone(), 0xa1);
    let update_set = update_set(&fixture, &recipient);
    let expected_hash = update_set
        .canonical_sha256()
        .expect("canonical UpdateSet hash");
    let (transport, sent) = KeyUpdateTransport::for_update(update_set.clone(), false, device_sign);
    let opened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("open before live key update");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("higher revision starts KeySync");
    observer.clear();
    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("authenticated UpdateSet installs and emits ACK");
    let reply_stages = observer.snapshot();
    assert_eq!(
        reply_stages
            .iter()
            .filter(|stage| **stage == PairedMutationStage::StateStageDurable)
            .count(),
        2,
        "one CAS admits reply replay; exactly one further CAS must combine ADKG+ADKS+binding install"
    );
    assert_eq!(
        reply_stages.last(),
        Some(&PairedMutationStage::GuardStableDurable),
        "ACK transport send may run only after its CounterGuard reservation is durable"
    );
    let first_sent = sent.lock().expect("first key-update sent frames").clone();
    let (first_ack_route, first_ack, first_ack_bytes) = sent_ack(&first_sent, &device_sign);
    first_ack
        .validate_for_update_set(&update_set)
        .expect("ACK binds the exact installed UpdateSet");
    assert_eq!(first_ack.update_set_sha256, expected_hash);

    observer.clear();
    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("ACK RouteAccepted is transport-only, not install success");
    assert!(observer.snapshot().is_empty());
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("RouteAccepted must leave a reopenable committed install");
    let basis = reopened
        .durable_key_sync_state()
        .expect("read completed ADKS")
        .expect("completed ADKS remains durable")
        .latest_completed_ack_basis()
        .expect("RouteAccepted must not clear the committed ACK basis");
    assert_eq!(basis.key_directory_revision().value(), UPDATE_REVISION);
    assert_eq!(basis.update_set_sha256(), expected_hash);

    let (resume_transport, resume_sent) = KeyUpdateTransport::for_ack_resume(device_sign);
    let mut resumed = RemoteRuntime::new(reopened, resume_transport);
    resumed
        .resume_pending_key_update_ack()
        .await
        .expect("restart reseals the committed ACK basis");
    let resumed_sent = resume_sent.lock().expect("resumed ACK frames").clone();
    let (second_ack_route, second_ack, second_ack_bytes) = sent_ack(&resumed_sent, &device_sign);
    assert_eq!(
        second_ack, first_ack,
        "restart must preserve canonical ACK body"
    );
    assert_ne!(
        second_ack_route, first_ack_route,
        "restart uses a fresh route"
    );
    assert_ne!(
        second_ack_bytes, first_ack_bytes,
        "restart uses a fresh CounterGuard reservation and sealed carrier"
    );
    resumed
        .receive_stream_frame(&mut reducer)
        .await
        .expect("resumed ACK RouteAccepted remains transport-only");
    drop(resumed);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after resumed ACK RouteAccepted");
    let persisted_basis = reopened
        .durable_key_sync_state()
        .expect("read ADKS after resumed ACK")
        .expect("ADKS persists after resumed ACK")
        .latest_completed_ack_basis()
        .expect("resumed RouteAccepted still cannot clear ACK basis");
    assert_eq!(persisted_basis, basis);
}

#[tokio::test]
async fn live_update_reply_before_probe_route_accepted_drains_both_control_routes() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("delayed live RouteAccepted state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0xa2);
    let (transport, _sent) =
        KeyUpdateTransport::for_update(update_set(&fixture, &recipient), false, device_sign);
    let transport = transport.with_key_sync_route_accepted_after_reply();
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open delayed live RouteAccepted fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: UPDATE_REVISION,
            next_attempt: None,
        })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncRouteAccepted { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateAckRouteAccepted {
            key_directory_revision: UPDATE_REVISION,
        })
    ));
}

#[tokio::test]
async fn duplicate_exact_probe_requires_one_route_accepted_per_send() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("duplicate probe RouteAccepted state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0xa3);
    let (mut transport, sent) =
        KeyUpdateTransport::for_update(update_set(&fixture, &recipient), false, device_sign);
    transport = transport
        .with_key_sync_route_accepted_after_reply()
        .with_extra_key_sync_route_accepted_on_send(2);
    transport
        .inbound
        .push_back(received_exact(higher_publish()));
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open duplicate probe RouteAccepted fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    for _ in 0..2 {
        assert!(matches!(
            runtime.receive_stream_frame(&mut reducer).await,
            Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
        ));
    }
    let sent_before_reply = sent.lock().expect("duplicate probe sent frames").clone();
    assert_eq!(sent_before_reply.len(), 2);
    assert_eq!(
        sent_before_reply[0], sent_before_reply[1],
        "same active durable probe must be retried byte-for-byte"
    );

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: UPDATE_REVISION,
            next_attempt: None,
        })
    ));
    for _ in 0..2 {
        assert!(matches!(
            runtime.receive_stream_frame(&mut reducer).await,
            Ok(RemoteStreamFrameOutcome::KeySyncRouteAccepted { attempt: 1 })
        ));
    }
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("a third acceptance has no successful probe send to correlate");
    assert_eq!(error.code(), "remote.runtime.reply_invalid");
}

#[tokio::test]
async fn business_request_route_collision_with_pending_key_sync_rejects_before_mutation() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("request-route owner collision state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer.clone(), 0xa4);
    let (transport, sent) =
        KeyUpdateTransport::for_update(update_set(&fixture, &recipient), false, device_sign);
    let opened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("open request-route owner collision fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    let sent_before = sent
        .lock()
        .expect("request-route collision sent frames")
        .clone();
    let (probe_route, _, probe) = sent_command(&sent_before[0], &device_sign);
    assert!(matches!(probe, KeyControlRequestV1::KeySync { .. }));
    let files_before = file_tree_bytes(&root);
    let keys_before = paired_key_bytes(&store, &fixture);
    observer.clear();

    let mut rng = FixedRouteRng::new(probe_route);
    let error = runtime
        .prompt(prompt_request(), &mut rng)
        .await
        .expect_err("a business request must not reuse a pending KeySync route");
    assert!(matches!(error, RemoteRuntimeError::EntropyUnavailable));
    assert!(observer.snapshot().is_empty());
    assert_eq!(file_tree_bytes(&root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
    assert_eq!(
        sent.lock()
            .expect("request-route collision sent frames after rejection")
            .as_slice(),
        sent_before.as_slice()
    );
}

#[tokio::test]
async fn directory_current_validates_then_freezes_attempt_two_before_send() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("DirectoryCurrent state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (_recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer.clone(), 0xc1);
    let (transport, sent) =
        KeyUpdateTransport::for_directory_current(directory_current(&fixture), device_sign);
    let transport = transport.with_key_sync_route_accepted_after_reply();
    let opened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("open DirectoryCurrent fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    observer.clear();
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 2 })
    ));
    let stages = observer.snapshot();
    assert_eq!(
        stages
            .iter()
            .filter(|stage| **stage == PairedMutationStage::StateStageDurable)
            .count(),
        2,
        "reply replay and ADKS attempt-two freeze are separate durable CAS operations"
    );
    assert_eq!(
        stages
            .iter()
            .filter(|stage| **stage == PairedMutationStage::GuardPendingDurable)
            .count(),
        1,
        "valid DirectoryCurrent reserves exactly one command counter block"
    );
    let sent = sent.lock().expect("DirectoryCurrent sent frames").clone();
    assert_eq!(sent.len(), 2);
    let mut request_routes = Vec::new();
    for (index, expected_attempt) in [1_u8, 2].into_iter().enumerate() {
        let frame = decode(&sent[index]).expect("decode KeySync attempt");
        let RelayFrameBody::Send(send) = frame.body else {
            panic!("DirectoryCurrent flow emits Relay Send")
        };
        request_routes.push(send.request_route);
        let KeyControlRequestV1::KeySync { request } =
            open_command_control(&send.sealed_blob.0, send.request_route, &device_sign)
        else {
            panic!("DirectoryCurrent flow may only retry KeySync")
        };
        assert_eq!(request.attempt, expected_attempt);
    }
    assert_ne!(request_routes[0], request_routes[1]);
    for expected_attempt in [1_u8, 2] {
        assert!(matches!(
            runtime.receive_stream_frame(&mut reducer).await,
            Ok(RemoteStreamFrameOutcome::KeySyncRouteAccepted { attempt })
                if attempt == expected_attempt
        ));
    }
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen DirectoryCurrent attempt two");
    let state = reopened
        .durable_key_sync_state()
        .expect("read DirectoryCurrent ADKS")
        .expect("attempt two remains durable");
    assert_eq!(state.attempt(), 2);
    assert!(state.active_send().is_some());
    assert!(state.latest_completed_ack_basis().is_none());
}

#[tokio::test]
async fn invalid_directory_current_does_not_reserve_counter_or_advance_adks() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("invalid DirectoryCurrent state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (_recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer.clone(), 0xd1);
    let mut invalid = directory_current(&fixture);
    invalid.grant_serial = GrantSerial::new(8);
    let (transport, sent) = KeyUpdateTransport::for_directory_current(invalid, device_sign);
    let opened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("open invalid DirectoryCurrent fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("higher revision starts KeySync");
    observer.clear();
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("mismatched DirectoryCurrent authority must fail before retry mutation");
    assert_eq!(error.code(), "remote.runtime.reply_invalid");
    assert_eq!(
        observer
            .snapshot()
            .iter()
            .filter(|stage| **stage == PairedMutationStage::StateStageDurable)
            .count(),
        1,
        "only authenticated reply replay admission may persist before plaintext reconciliation"
    );
    assert!(
        !observer
            .snapshot()
            .contains(&PairedMutationStage::GuardPendingDurable),
        "invalid status must not reserve a command counter block"
    );
    assert_eq!(
        sent.lock()
            .expect("invalid DirectoryCurrent sent frames")
            .len(),
        1,
        "invalid status must not send attempt two"
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after invalid DirectoryCurrent");
    let state = reopened
        .durable_key_sync_state()
        .expect("read ADKS after invalid DirectoryCurrent")
        .expect("attempt one remains active");
    assert_eq!(state.attempt(), 1);
    assert!(state.active_send().is_some());
    assert!(state.latest_completed_ack_basis().is_none());
}

async fn assert_key_sync_header_control_mismatch_is_rejected(
    directory_current_under_requested_revision: bool,
    seed: u8,
) {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("header/control mismatch state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer.clone(), seed);
    let (transport, sent) = if directory_current_under_requested_revision {
        let (transport, sent) =
            KeyUpdateTransport::for_directory_current(directory_current(&fixture), device_sign);
        (transport.with_reply_header_revision(UPDATE_REVISION), sent)
    } else {
        let (transport, sent) =
            KeyUpdateTransport::for_update(update_set(&fixture, &recipient), false, device_sign);
        (
            transport.with_reply_header_revision(KEY_DIRECTORY_REVISION),
            sent,
        )
    };
    let opened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("open header/control mismatch fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();
    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("higher revision starts KeySync");
    observer.clear();

    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("header revision and decrypted control variant must be paired");
    assert_eq!(error.code(), "remote.runtime.reply_invalid");
    let stages = observer.snapshot();
    assert_eq!(
        stages
            .iter()
            .filter(|stage| **stage == PairedMutationStage::StateStageDurable)
            .count(),
        1,
        "authenticated reply replay is consumed before decrypted variant reconciliation"
    );
    assert!(!stages.contains(&PairedMutationStage::GuardPendingDurable));
    assert_eq!(
        sent.lock().expect("mismatched control sent frames").len(),
        1
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen header/control mismatch fixture");
    assert_eq!(
        reopened.directory_revision().value(),
        KEY_DIRECTORY_REVISION
    );
    let state = reopened
        .durable_key_sync_state()
        .expect("read mismatch ADKS")
        .expect("attempt one remains active");
    assert_eq!(state.attempt(), 1);
    assert!(state.latest_completed_ack_basis().is_none());
}

#[tokio::test]
async fn key_sync_reply_header_revision_must_match_decrypted_control_variant() {
    assert_key_sync_header_control_mismatch_is_rejected(false, 0xe1).await;
    assert_key_sync_header_control_mismatch_is_rejected(true, 0xe2).await;
}

#[tokio::test]
async fn intermediate_update_sends_ack_before_freezing_and_sending_next_probe() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("intermediate key-update state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer.clone(), 0xf1);
    let first_update = update_set(&fixture, &recipient);
    let (transport, sent) = KeyUpdateTransport::for_script(
        higher_publish_at(SECOND_UPDATE_REVISION, CATALOG_EPOCH + 1, [0x82; 32]),
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: first_update,
            header_revision: UPDATE_REVISION,
        }]),
        false,
        false,
        device_sign,
    );
    let transport = transport.with_key_sync_route_accepted_after_reply();
    let opened =
        PairedMachineStore::new_with_mutation_observer(&store, INSTALLATION_ID, &root, observer)
            .open_exact(fixture.identity())
            .expect("open intermediate key-update fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: UPDATE_REVISION,
            next_attempt: Some(2),
        })
    ));
    let sent = sent.lock().expect("intermediate sent frames").clone();
    assert_eq!(sent.len(), 3);
    let (first_route, first_header, first) = sent_command(&sent[0], &device_sign);
    let (_, ack_header, ack) = sent_command(&sent[1], &device_sign);
    let (next_route, next_header, next) = sent_command(&sent[2], &device_sign);
    let KeyControlRequestV1::KeySync { request: first } = first else {
        panic!("first carrier is KeySync")
    };
    let KeyControlRequestV1::KeyUpdateAck { ack } = ack else {
        panic!("intermediate install must ACK before continuing")
    };
    let KeyControlRequestV1::KeySync { request: next } = next else {
        panic!("third carrier is the next KeySync probe")
    };
    assert_eq!(first_header, UPDATE_REVISION);
    assert_eq!(first.attempt, 1);
    assert_eq!(ack_header, UPDATE_REVISION);
    assert_eq!(ack.key_directory_revision.value(), UPDATE_REVISION);
    assert_eq!(next_header, SECOND_UPDATE_REVISION);
    assert_eq!(next.attempt, 2);
    assert_eq!(next.known_key_directory_revision.value(), UPDATE_REVISION);
    assert_eq!(
        next.requested_key_directory_revision.value(),
        SECOND_UPDATE_REVISION
    );
    assert_ne!(first_route, next_route);
    for expected_attempt in [1_u8, 2] {
        assert!(matches!(
            runtime.receive_stream_frame(&mut reducer).await,
            Ok(RemoteStreamFrameOutcome::KeySyncRouteAccepted { attempt })
                if attempt == expected_attempt
        ));
    }
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen intermediate continuation");
    assert_eq!(reopened.directory_revision().value(), UPDATE_REVISION);
    let state = reopened
        .durable_key_sync_state()
        .expect("read intermediate ADKS")
        .expect("continuation remains durable");
    assert_eq!(state.attempt(), 2);
    assert!(state.active_send().is_some());
    assert_eq!(
        state
            .latest_completed_ack_basis()
            .expect("intermediate completion retains ACK basis")
            .key_directory_revision()
            .value(),
        UPDATE_REVISION
    );
}

#[tokio::test]
async fn restart_after_intermediate_install_reacks_before_resuming_next_probe() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("intermediate restart state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer.clone(), 0xf2);
    let (transport, first_sent) = KeyUpdateTransport::for_script(
        higher_publish_at(SECOND_UPDATE_REVISION, CATALOG_EPOCH + 1, [0x82; 32]),
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: update_set(&fixture, &recipient),
            header_revision: UPDATE_REVISION,
        }]),
        false,
        true,
        device_sign,
    );
    let opened =
        PairedMachineStore::new_with_mutation_observer(&store, INSTALLATION_ID, &root, observer)
            .open_exact(fixture.identity())
            .expect("open intermediate restart fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();
    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("higher revision starts KeySync");
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("injected ACK send ambiguity stops before next probe freeze");
    assert_eq!(error.code(), "remote.runtime.transport_failed");
    let first_sent = first_sent
        .lock()
        .expect("first intermediate sent frames")
        .clone();
    assert_eq!(first_sent.len(), 2);
    let (first_ack_route, first_ack_header, first_ack) = sent_command(&first_sent[1], &device_sign);
    let KeyControlRequestV1::KeyUpdateAck { ack: first_ack } = first_ack else {
        panic!("failed transport still recorded the intermediate ACK carrier")
    };
    assert_eq!(first_ack_header, UPDATE_REVISION);
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen AwaitingProbe intermediate state");
    let awaiting = reopened
        .durable_key_sync_state()
        .expect("read AwaitingProbe ADKS")
        .expect("intermediate completion is durable");
    assert!(awaiting.active_send().is_none());
    assert_eq!(awaiting.attempt(), 1);
    assert!(awaiting.latest_completed_ack_basis().is_some());

    let (resume_transport, resumed_sent) = KeyUpdateTransport::for_ack_resume(device_sign);
    let mut resumed = RemoteRuntime::new(reopened, resume_transport);
    resumed
        .resume_pending_key_update_ack()
        .await
        .expect("restart ACKs before freezing and sending attempt two");
    let resumed_sent = resumed_sent
        .lock()
        .expect("resumed intermediate sent frames")
        .clone();
    assert_eq!(resumed_sent.len(), 2);
    let (resumed_ack_route, resumed_ack_header, resumed_ack) =
        sent_command(&resumed_sent[0], &device_sign);
    let (_, resumed_probe_header, resumed_probe) = sent_command(&resumed_sent[1], &device_sign);
    let KeyControlRequestV1::KeyUpdateAck { ack: resumed_ack } = resumed_ack else {
        panic!("restart must emit ACK first")
    };
    let KeyControlRequestV1::KeySync {
        request: resumed_probe,
    } = resumed_probe
    else {
        panic!("restart emits next KeySync only after ACK")
    };
    assert_ne!(resumed_ack_route, first_ack_route);
    assert_eq!(resumed_ack, first_ack);
    assert_eq!(resumed_ack_header, UPDATE_REVISION);
    assert_eq!(resumed_probe_header, SECOND_UPDATE_REVISION);
    assert_eq!(resumed_probe.attempt, 2);
    assert_eq!(
        resumed_probe.known_key_directory_revision.value(),
        UPDATE_REVISION
    );
    assert_eq!(
        resumed_probe.requested_key_directory_revision.value(),
        SECOND_UPDATE_REVISION
    );
    drop(resumed);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen resumed attempt two");
    let state = reopened
        .durable_key_sync_state()
        .expect("read resumed ADKS")
        .expect("attempt two is durable before send");
    assert_eq!(state.attempt(), 2);
    assert!(state.active_send().is_some());
}

#[tokio::test]
async fn resolved_revision_only_update_reacks_before_starting_a_new_bounded_cycle() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("resolved supersession state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0xf3);
    let first = update_set_at_revision(
        &fixture,
        &recipient,
        UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x71,
    );
    let second = update_set_at_revision(
        &fixture,
        &recipient,
        SECOND_UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x81,
    );
    let (transport, sent) = KeyUpdateTransport::for_script(
        higher_publish_at(UPDATE_REVISION, CATALOG_EPOCH, [0x71; 32]),
        VecDeque::from([
            ScriptedKeySyncReply::UpdateSet {
                update_set: first,
                header_revision: UPDATE_REVISION,
            },
            ScriptedKeySyncReply::UpdateSet {
                update_set: second,
                header_revision: SECOND_UPDATE_REVISION,
            },
        ]),
        false,
        false,
        device_sign,
    );
    let transport = transport.with_publish_after_ack(higher_publish_at(
        SECOND_UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
    ));
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open resolved supersession fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: UPDATE_REVISION,
            next_attempt: None,
        })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    let second_install = runtime.receive_stream_frame(&mut reducer).await;
    assert!(
        matches!(
            second_install,
            Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
                key_directory_revision: SECOND_UPDATE_REVISION,
                next_attempt: None,
            })
        ),
        "unexpected second install outcome: {second_install:?}"
    );

    let sent = sent
        .lock()
        .expect("resolved supersession sent frames")
        .clone();
    assert_eq!(sent.len(), 5);
    let (_, first_probe_revision, first_probe) = sent_command(&sent[0], &device_sign);
    let (_, first_ack_revision, first_ack) = sent_command(&sent[1], &device_sign);
    let (_, resumed_ack_revision, resumed_ack) = sent_command(&sent[2], &device_sign);
    let (_, second_probe_revision, second_probe) = sent_command(&sent[3], &device_sign);
    let (_, second_ack_revision, second_ack) = sent_command(&sent[4], &device_sign);
    let KeyControlRequestV1::KeySync {
        request: first_probe,
    } = first_probe
    else {
        panic!("first cycle starts with KeySync")
    };
    let KeyControlRequestV1::KeyUpdateAck { ack: first_ack } = first_ack else {
        panic!("first cycle installs before ACK")
    };
    let KeyControlRequestV1::KeyUpdateAck { ack: resumed_ack } = resumed_ack else {
        panic!("new signed observation must re-ACK the resolved cycle first")
    };
    let KeyControlRequestV1::KeySync {
        request: second_probe,
    } = second_probe
    else {
        panic!("new cycle starts only after old ACK retry")
    };
    let KeyControlRequestV1::KeyUpdateAck { ack: second_ack } = second_ack else {
        panic!("second cycle installs before ACK")
    };
    assert_eq!(first_probe_revision, UPDATE_REVISION);
    assert_eq!(first_probe.attempt, 1);
    assert_eq!(first_ack_revision, UPDATE_REVISION);
    assert_eq!(resumed_ack_revision, UPDATE_REVISION);
    assert_eq!(resumed_ack, first_ack);
    assert_eq!(second_probe_revision, SECOND_UPDATE_REVISION);
    assert_eq!(
        second_probe.attempt, 1,
        "new observation gets a fresh bounded budget"
    );
    assert_eq!(
        second_probe.known_key_directory_revision.value(),
        UPDATE_REVISION
    );
    assert_eq!(second_ack_revision, SECOND_UPDATE_REVISION);
    assert_eq!(
        second_ack.key_directory_revision.value(),
        SECOND_UPDATE_REVISION
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after two independent revision-only cycles");
    assert_eq!(
        reopened.directory_revision().value(),
        SECOND_UPDATE_REVISION
    );
    let state = reopened
        .durable_key_sync_state()
        .expect("read second resolved ADKS")
        .expect("second cycle remains durable");
    assert_eq!(state.status(), KeySyncCoordinationStatus::Resolved);
    assert_eq!(state.attempt(), 1);
    assert_eq!(
        state
            .latest_completed_ack_basis()
            .expect("second cycle ACK basis")
            .key_directory_revision()
            .value(),
        SECOND_UPDATE_REVISION
    );
}

#[tokio::test]
async fn superseded_cycle_probe_send_failure_cold_recovers_ack_then_exact_probe() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("superseded cold-recovery state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0xf4);
    let first = update_set_at_revision(
        &fixture,
        &recipient,
        UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x71,
    );
    let second = update_set_at_revision(
        &fixture,
        &recipient,
        SECOND_UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x81,
    );
    let (transport, first_sent) = KeyUpdateTransport::for_script(
        higher_publish_at(UPDATE_REVISION, CATALOG_EPOCH, [0x71; 32]),
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: first,
            header_revision: UPDATE_REVISION,
        }]),
        false,
        false,
        device_sign,
    );
    let transport = transport
        .with_publish_after_ack(higher_publish_at(
            SECOND_UPDATE_REVISION,
            CATALOG_EPOCH,
            [0x71; 32],
        ))
        .with_key_sync_send_failure(2);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open superseded cold-recovery fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt: 1 })
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: UPDATE_REVISION,
            next_attempt: None,
        })
    ));
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("new-cycle ADKS CAS survives an injected probe send failure");
    assert_eq!(error.code(), "remote.runtime.transport_failed");
    let first_sent = first_sent
        .lock()
        .expect("superseded pre-crash sent frames")
        .clone();
    assert_eq!(first_sent.len(), 4);
    let (_, _, first_ack) = sent_command(&first_sent[1], &device_sign);
    let KeyControlRequestV1::KeyUpdateAck { ack: first_ack } = first_ack else {
        panic!("first cycle must install before its ACK")
    };
    let (_, _, retried_ack) = sent_command(&first_sent[2], &device_sign);
    let KeyControlRequestV1::KeyUpdateAck { ack: retried_ack } = retried_ack else {
        panic!("superseding observation must re-ACK the old completion")
    };
    assert_eq!(retried_ack, first_ack);
    let frozen_probe = first_sent[3].clone();
    let (_, frozen_probe_revision, frozen_probe_control) =
        sent_command(&frozen_probe, &device_sign);
    let KeyControlRequestV1::KeySync {
        request: frozen_probe_request,
    } = frozen_probe_control
    else {
        panic!("fourth send is the frozen next-cycle probe")
    };
    assert_eq!(frozen_probe_revision, SECOND_UPDATE_REVISION);
    assert_eq!(frozen_probe_request.attempt, 1);
    assert_eq!(
        frozen_probe_request.known_key_directory_revision.value(),
        UPDATE_REVISION
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after new-cycle CAS and probe send failure");
    let active = reopened
        .durable_key_sync_state()
        .expect("read superseded active ADKS")
        .expect("superseded active ADKS remains durable");
    assert_eq!(active.status(), KeySyncCoordinationStatus::Active);
    assert_eq!(
        active
            .latest_completed_ack_basis()
            .expect("old completion basis remains retained")
            .key_directory_revision()
            .value(),
        UPDATE_REVISION
    );
    assert_eq!(
        active
            .active_send()
            .expect("new-cycle probe remains frozen")
            .exact_send_bytes(),
        frozen_probe.as_slice()
    );

    let (recovery_transport, recovery_sent) = KeyUpdateTransport::for_recovery(
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: second,
            header_revision: SECOND_UPDATE_REVISION,
        }]),
        device_sign,
    );
    let mut recovered = RemoteRuntime::new(reopened, recovery_transport);
    recovered
        .recover_durable_key_sync()
        .await
        .expect("cold recovery ACKs old completion then exact-retries frozen probe");
    let recovery_sent = recovery_sent
        .lock()
        .expect("superseded recovery sent frames")
        .clone();
    assert_eq!(recovery_sent.len(), 3);
    let (_, old_ack_revision, old_ack) = sent_command(&recovery_sent[0], &device_sign);
    let KeyControlRequestV1::KeyUpdateAck { ack: old_ack } = old_ack else {
        panic!("cold recovery must re-ACK before probing")
    };
    assert_eq!(old_ack_revision, UPDATE_REVISION);
    assert_eq!(old_ack, first_ack);
    assert_eq!(recovery_sent[1], frozen_probe);
    let (_, new_ack_revision, new_ack) = sent_command(&recovery_sent[2], &device_sign);
    let KeyControlRequestV1::KeyUpdateAck { ack: new_ack } = new_ack else {
        panic!("recovered second install must emit its ACK")
    };
    assert_eq!(new_ack_revision, SECOND_UPDATE_REVISION);
    assert_eq!(
        new_ack.key_directory_revision.value(),
        SECOND_UPDATE_REVISION
    );

    assert!(matches!(
        recovered.receive_stream_frame(&mut reducer).await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    drop(recovered);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after superseded cold recovery");
    let resolved = reopened
        .durable_key_sync_state()
        .expect("read recovered ADKS")
        .expect("recovered ADKS remains durable");
    assert_eq!(resolved.status(), KeySyncCoordinationStatus::Resolved);
    assert_eq!(
        resolved
            .latest_completed_ack_basis()
            .expect("new completion basis")
            .key_directory_revision()
            .value(),
        SECOND_UPDATE_REVISION
    );
}

#[tokio::test]
async fn cold_recovery_never_resends_an_active_probe_after_absolute_deadline() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("expired cold-recovery state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (_recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0xf5);
    let observation = SignedHigherRevisionObservationV1::new(
        fixture.machine_route(),
        fixture.device_route(),
        GrantSerial::new(7),
        TrustEpoch::new(2),
        KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        KeyDirectoryRevision::new(UPDATE_REVISION),
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
        None,
        CATALOG_STREAM_ROUTE,
        CATALOG_STREAM_GENERATION,
        OUTER_HIGH_WATER + 1,
        901,
        [0x91; 32],
        [0x92; 32],
    )
    .expect("valid expired KeySync observation");
    let request = observation
        .request_for_attempt(1)
        .expect("expired fixture request");
    let request_route = RequestRouteId::from_bytes([0x93; 16]);
    let signed_command = UnsignedSealedBlobV1::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: DEVICE_COMMAND_EPOCH,
        },
        DEVICE_COMMAND_EPOCH,
        UPDATE_REVISION,
        [0x94; 12],
        vec![0x95; 16],
    )
    .attach_signature(Ed25519Signature([0x96; 64]));
    let frozen = FrozenKeySyncSendV1::new(
        request,
        encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Send(RelaySend {
                device_route: fixture.device_route(),
                request_route,
                sealed_blob: SealedBlob(signed_command.to_wire_bytes()),
            }),
        }),
    )
    .expect("freeze expired KeySync Send");
    let expired = DurableKeySyncStateV1::start(observation, 1, frozen)
        .expect("construct expired active ADKS");
    assert!(expired.deadline_at_ms() < NOW_MS);

    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        Arc::new(RecordingObserver::default()),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open expired KeySync fixture");
    let mut rng = DeterministicRng::new([0x95; 32]);
    opened
        .commit_key_sync_state_transition_for_automatic_harness(None, Some(&expired), &mut rng)
        .expect("persist expired active ADKS");
    let files_before = file_tree_bytes(&root);
    let keys_before = paired_key_bytes(&store, &fixture);
    let (transport, sent) = KeyUpdateTransport::for_ack_resume(device_sign);
    let mut runtime = RemoteRuntime::new(opened, transport);
    let error = runtime
        .recover_durable_key_sync()
        .await
        .expect_err("expired active probe must never be resent");
    assert_eq!(error.code(), "remote.crypto.key_epoch_missing");
    assert!(sent.lock().expect("expired recovery sends").is_empty());
    drop(runtime);
    assert_eq!(file_tree_bytes(&root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
}

#[tokio::test]
async fn retained_ack_hash_mismatch_fails_open_audit_without_rewrite() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("retained ACK audit state root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer, 0xf6);
    let first = update_set_at_revision(
        &fixture,
        &recipient,
        UPDATE_REVISION,
        CATALOG_EPOCH,
        [0x71; 32],
        0x71,
    );
    let (transport, _) = KeyUpdateTransport::for_script(
        higher_publish_at(UPDATE_REVISION, CATALOG_EPOCH, [0x71; 32]),
        VecDeque::from([ScriptedKeySyncReply::UpdateSet {
            update_set: first,
            header_revision: UPDATE_REVISION,
        }]),
        false,
        false,
        device_sign,
    );
    let transport = transport
        .with_publish_after_ack(higher_publish_at(
            SECOND_UPDATE_REVISION,
            CATALOG_EPOCH,
            [0x71; 32],
        ))
        .with_key_sync_send_failure(2);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open retained ACK audit fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();
    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("start first audit cycle");
    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("resolve first audit cycle");
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Err(RemoteRuntimeError::Transport(_))
    ));
    drop(runtime);

    let automatic = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        Arc::new(RecordingObserver::default()),
    );
    let mut opened = automatic
        .open_exact(fixture.identity())
        .expect("open canonical retained ACK state before tamper");
    let state = opened
        .durable_key_sync_state()
        .expect("read retained ACK state")
        .expect("retained ACK state exists");
    assert_eq!(state.status(), KeySyncCoordinationStatus::Active);
    let original_basis = state
        .latest_completed_ack_basis()
        .expect("retained ACK basis exists");
    let mut tampered = state.canonical_bytes().expect("canonical retained ADKS");
    let extension_offset = tampered
        .windows(4)
        .position(|window| window == b"AKA1")
        .expect("retained ACK extension magic");
    let retained_hash_offset = extension_offset + 4 + 1 + 16 + 8;
    tampered[retained_hash_offset] ^= 0x01;
    let tampered_state = DurableKeySyncStateV1::from_canonical_bytes(&tampered)
        .expect("tampered hash remains structurally canonical");
    assert_ne!(
        tampered_state
            .latest_completed_ack_basis()
            .expect("tampered retained basis")
            .update_set_sha256(),
        original_basis.update_set_sha256()
    );
    let mut rng = DeterministicRng::new([0xf7; 32]);
    opened
        .replace_unchecked_key_sync_state_for_automatic_harness(Some(tampered), &mut rng)
        .expect("inject authenticated-at-rest retained hash drift");
    drop(opened);

    let files_before = file_tree_bytes(&root);
    let keys_before = paired_key_bytes(&store, &fixture);
    let error = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect_err("retained hash drift must fail the full open audit");
    assert_eq!(error.code(), "remote.pairing.paired_conflict");
    assert_eq!(file_tree_bytes(&root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);
}

#[tokio::test]
async fn wrong_update_reply_route_rejects_before_replay_install_or_ack_mutation() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("wrong-route key-update root");
    let root = state_root(&temp);
    let observer = Arc::new(RecordingObserver::default());
    let (recipient, device_sign) =
        promote_and_install_binding(&fixture, &store, &root, observer.clone(), 0xb1);
    let update_set = update_set(&fixture, &recipient);
    let (transport, sent) = KeyUpdateTransport::for_update(update_set, true, device_sign);
    let opened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("open wrong-route fixture");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = reducer();

    runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect("higher revision starts KeySync");
    let files_before = file_tree_bytes(&root);
    let keys_before = paired_key_bytes(&store, &fixture);
    observer.clear();
    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("wrong requestRoute UpdateSet must fail before install");
    assert_eq!(error.code(), "remote.runtime.reply_invalid");
    assert!(observer.snapshot().is_empty());
    let sent = sent.lock().expect("wrong-route sent frames").clone();
    assert_eq!(sent.len(), 1, "wrong route must not emit KeyUpdateAck");
    assert!(matches!(
        open_command_control(
            match &decode(&sent[0]).expect("decode KeySync").body {
                RelayFrameBody::Send(send) => &send.sealed_blob.0,
                _ => unreachable!("first send is KeySync"),
            },
            match decode(&sent[0]).expect("decode KeySync route").body {
                RelayFrameBody::Send(send) => send.request_route,
                _ => unreachable!("first send is KeySync"),
            },
            &device_sign,
        ),
        KeyControlRequestV1::KeySync { .. }
    ));
    drop(runtime);
    assert_eq!(file_tree_bytes(&root), files_before);
    assert_eq!(paired_key_bytes(&store, &fixture), keys_before);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("wrong-route rejection leaves current state reopenable");
    let key_sync = reopened
        .durable_key_sync_state()
        .expect("read active ADKS")
        .expect("wrong route retains active KeySync attempt");
    assert!(key_sync.active_send().is_some());
    assert!(key_sync.latest_completed_ack_basis().is_none());
    assert_eq!(
        reopened.directory_revision().value(),
        KEY_DIRECTORY_REVISION
    );
}
