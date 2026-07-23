#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::runtime::{
    ExactRelayFrame, ReceivedRuntimeFrame, RemoteCatalogPageOutcome, RemotePromptOutcome,
    RemoteRuntime, RemoteRuntimeError, RemoteRuntimeTransport, RemoteRuntimeTransportError,
    RemoteStreamFrameOutcome, RemoteSubscriptionBootstrapItem, RemoteSubscriptionReducer,
};
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, VerifyingKey,
    counter::COUNTER_BLOCK_SIZE, open_sealed_payload, seal_symmetric, sha256, sign_sealed,
    sign_tbs, verify_sealed,
};
use agentdeck_protocol::capabilities::{SessionCapabilities, VendorCapabilities};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyControlV1, KeyId, KeyPurpose, OuterContextV1, OuterFrameKind,
    SealedPayloadKind, SignedSealedBlobV1, StreamBindingV1,
};
use agentdeck_protocol::relay_v2::auth::{DeviceRevocation, Ed25519Signature};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Ack, Publish, Reply, RevocationCommitted, RouteAccepted, SealedBlob, Send,
    Subscribe,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial as RelayGrantSerial, KeyDirectoryRevision, OpaqueRouteFrame,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId, StreamGenerationId, StreamRouteId,
    TrustEpoch, decode, encode,
};
use agentdeck_protocol::runtime::command::{CatalogRequest, RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CatalogPageCursor, CommandId, GrantSerial as RuntimeGrantSerial, MessageId,
    StreamGeneration, TransferId, TurnId,
};
use agentdeck_protocol::runtime::{
    ApprovalReceipt, BackfillChunk, BackfillRange, CatalogDelta, CatalogSnapshot, CommandReceipt,
    ConversationConfigurationState, ConversationEntry, ConversationId, ConversationSnapshot,
    IdempotencyKey, MAX_RUNTIME_JSON_FRAME_BYTES, PromptPayload, RUNTIME_PROTOCOL_VERSION,
    RevocationReceipt, RuntimeEnvelope, RuntimeFailure, RuntimeInnerCursor, RuntimeMessage,
    RuntimeReply, RuntimeRequest, RuntimeStreamItem, RuntimeSyncComplete, RuntimeTransferCarrierV1,
    RuntimeTransferChannel, SendPromptRequest, SnapshotItem, StreamCursor, SubscriptionReceipt,
    TransferEnvelope,
};
use agentdeck_protocol::vendor::codex::CodexCapabilities;
use agentdeck_protocol::{ActionDecision, ActionDecisionKind, AgentKind};
use async_trait::async_trait;

use remote_pairing::{
    CATALOG_EPOCH, CONVERSATION_EPOCH, DEVICE_COMMAND_EPOCH, DEVICE_COMMAND_KEY,
    DEVICE_REPLY_EPOCH, DEVICE_REPLY_KEY, DEVICE_ROUTE, DeterministicRng, INSTALLATION_ID,
    KEY_DIRECTORY_REVISION, MACHINE_ROUTE, PairingFixture, PanicRng, RELAY_SERVER, ROOT_KEY_ID,
};

const REPLY_COUNTER: u64 = 41;
const WRONG_REQUEST_ROUTE: RequestRouteId = RequestRouteId::from_bytes([0xa5; 16]);
const CATALOG_STREAM_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CONVERSATION_STREAM_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x82; 16]);
const CATALOG_RELAY_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const CONVERSATION_RELAY_GENERATION: StreamGenerationId =
    StreamGenerationId::from_bytes([0x92; 16]);
const CATALOG_OUTER_HIGH_WATER: u64 = 23;
const CATALOG_INNER_HIGH_WATER: u64 = 17;
const CONVERSATION_OUTER_HIGH_WATER: u64 = 29;
const CONVERSATION_INNER_HIGH_WATER: u64 = 11;
const SUBSCRIPTION_CONVERSATION_ID: &str = "018f0f9d-6f0a-7ad0-8000-000000000082";

struct PanicOnNthStateActive {
    target: usize,
    calls: AtomicUsize,
}

struct AssertShutdownBeforeCleanup {
    shutdown_observed: Arc<AtomicBool>,
    cleanup_stages: AtomicUsize,
}

impl AssertShutdownBeforeCleanup {
    fn new(shutdown_observed: Arc<AtomicBool>) -> Self {
        Self {
            shutdown_observed,
            cleanup_stages: AtomicUsize::new(0),
        }
    }
}

impl PairedMutationObserver for AssertShutdownBeforeCleanup {
    fn after_stage(&self, stage: PairedMutationStage) {
        if matches!(
            stage,
            PairedMutationStage::CleanupJournalDurable
                | PairedMutationStage::CleanupStateDeleted
                | PairedMutationStage::CleanupCounterGuardDeleted
                | PairedMutationStage::CleanupGrantDeleted
                | PairedMutationStage::CleanupDeviceHpkeDeleted
                | PairedMutationStage::CleanupDeviceSignDeleted
                | PairedMutationStage::CleanupStorageKekDeleted
                | PairedMutationStage::CleanupJournalDeleted
        ) {
            assert!(
                self.shutdown_observed.load(Ordering::SeqCst),
                "revocation cleanup must not start before transport shutdown completes"
            );
            self.cleanup_stages.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl PanicOnNthStateActive {
    fn new(target: usize) -> Self {
        Self {
            target,
            calls: AtomicUsize::new(0),
        }
    }
}

impl PairedMutationObserver for PanicOnNthStateActive {
    fn after_stage(&self, stage: PairedMutationStage) {
        if stage == PairedMutationStage::StateActiveDurable
            && self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.target
        {
            panic!("injected process death after durable runtime state");
        }
    }
}

#[derive(Clone, Copy)]
enum TransportScript {
    ReplyOnly,
    ReplyOnlyWithShape(ReplyShape),
    ReplyThenRouteAccepted,
    RouteAcceptedThenReply,
    RouteAcceptedOnly,
    EofAfterSend,
    WrongRequestRouteOnly,
    RevocationTerminalOnly(RevocationTerminalShape),
    Subscription(SubscriptionScript),
}

#[derive(Clone, Copy)]
enum SubscriptionScript {
    CatalogAt,
    CatalogFailure,
    CatalogCompact,
    CatalogCompactBackfill,
    CatalogSnapshotThenBackfill,
    CatalogCompactSnapshotThenBackfill,
    CatalogDuplicateOpenPage,
    CatalogMissingFirstPage,
    CatalogCompactMissingMiddlePage,
    CatalogCompactWrongMessage,
    CatalogCompactWrongChannel,
    CatalogCompactCrossTarget,
    CatalogPartialTransferThenSync,
    CatalogPartialTransferThenPending,
    CatalogUnfinishedPageThenSync,
    CatalogSyncAheadOfBinding,
    CatalogSmallSyncAhead,
    ConversationIndependentGeneration,
    ConversationCompact,
    CatalogBeforeFirst,
    CatalogBeforeFirstNoSnapshot,
    CatalogMissingBinding,
    CatalogCrossTargetBinding,
    CatalogWrongBindingRevision,
    CatalogBindingBeforeSync,
}

#[derive(Clone, Copy)]
enum RevocationTerminalShape {
    Exact,
    ForgedSignature,
    WrongDeviceRoute,
    WrongGrantSerial,
    NonExactBytes,
}

struct FakeTransport {
    script: TransportScript,
    expected_request: RuntimeRequest,
    reply: RuntimeReply,
    reply_sequence: Option<Vec<RuntimeReply>>,
    expected_command_counter: u64,
    reply_counter: u64,
    device_sign_verifying_key: VerifyingKey,
    inbound: VecDeque<ReceivedRuntimeFrame>,
    post_script_inbound: VecDeque<ReceivedRuntimeFrame>,
    sent_codec_frames: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown_observed: Option<Arc<AtomicBool>>,
    panic_on_first_subscription_control: bool,
    fail_on_subscription_ack: bool,
}

impl FakeTransport {
    fn new(
        script: TransportScript,
        expected_request: SendPromptRequest,
        receipt: CommandReceipt,
        device_sign_verifying_key: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        Self::new_with_reply_counter(
            script,
            expected_request,
            receipt,
            device_sign_verifying_key,
            REPLY_COUNTER,
        )
    }

    fn new_with_reply_counter(
        script: TransportScript,
        expected_request: SendPromptRequest,
        receipt: CommandReceipt,
        device_sign_verifying_key: VerifyingKey,
        reply_counter: u64,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        Self::new_runtime_with_reply_counter(
            script,
            RuntimeRequest::SendPrompt(expected_request),
            RuntimeReply::Command(receipt),
            device_sign_verifying_key,
            reply_counter,
        )
    }

    fn new_runtime(
        script: TransportScript,
        expected_request: RuntimeRequest,
        reply: RuntimeReply,
        device_sign_verifying_key: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        Self::new_runtime_with_reply_counter(
            script,
            expected_request,
            reply,
            device_sign_verifying_key,
            REPLY_COUNTER,
        )
    }

    fn new_runtime_with_reply_counter(
        script: TransportScript,
        expected_request: RuntimeRequest,
        reply: RuntimeReply,
        device_sign_verifying_key: VerifyingKey,
        reply_counter: u64,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        Self::new_runtime_with_counters(
            script,
            expected_request,
            reply,
            device_sign_verifying_key,
            0,
            reply_counter,
        )
    }

    fn new_runtime_with_counters(
        script: TransportScript,
        expected_request: RuntimeRequest,
        reply: RuntimeReply,
        device_sign_verifying_key: VerifyingKey,
        expected_command_counter: u64,
        reply_counter: u64,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent_codec_frames = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                script,
                expected_request,
                reply,
                reply_sequence: None,
                expected_command_counter,
                reply_counter,
                device_sign_verifying_key,
                inbound: VecDeque::new(),
                post_script_inbound: VecDeque::new(),
                sent_codec_frames: Arc::clone(&sent_codec_frames),
                shutdown_observed: None,
                panic_on_first_subscription_control: false,
                fail_on_subscription_ack: false,
            },
            sent_codec_frames,
        )
    }

    fn new_runtime_sequence(
        expected_request: RuntimeRequest,
        replies: Vec<RuntimeReply>,
        device_sign_verifying_key: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let fallback = replies
            .first()
            .cloned()
            .expect("reply sequence must not be empty");
        let (mut transport, sent) = Self::new_runtime(
            TransportScript::ReplyOnly,
            expected_request,
            fallback,
            device_sign_verifying_key,
        );
        transport.reply_sequence = Some(replies);
        (transport, sent)
    }

    fn new_subscription(
        script: SubscriptionScript,
        inner_cursor: RuntimeInnerCursor,
        device_sign_verifying_key: VerifyingKey,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        Self::new_runtime(
            TransportScript::Subscription(script),
            RuntimeRequest::Subscribe { inner_cursor },
            RuntimeReply::Subscription(catalog_subscription_receipt()),
            device_sign_verifying_key,
        )
    }

    fn new_subscription_with_counters(
        script: SubscriptionScript,
        inner_cursor: RuntimeInnerCursor,
        device_sign_verifying_key: VerifyingKey,
        expected_command_counter: u64,
        reply_counter: u64,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        Self::new_runtime_with_counters(
            TransportScript::Subscription(script),
            RuntimeRequest::Subscribe { inner_cursor },
            RuntimeReply::Subscription(catalog_subscription_receipt()),
            device_sign_verifying_key,
            expected_command_counter,
            reply_counter,
        )
    }

    fn with_shutdown_observer(mut self, shutdown_observed: Arc<AtomicBool>) -> Self {
        self.shutdown_observed = Some(shutdown_observed);
        self
    }

    fn with_panic_on_first_subscription_control(mut self) -> Self {
        self.panic_on_first_subscription_control = true;
        self
    }

    fn with_fail_on_subscription_ack(mut self) -> Self {
        self.fail_on_subscription_ack = true;
        self
    }

    fn with_post_script_inbound(mut self, frames: Vec<OpaqueRouteFrame>) -> Self {
        self.post_script_inbound = frames.into_iter().map(received_exact).collect();
        self
    }

    fn inspect_real_send(&self, frame: &OpaqueRouteFrame) -> (RequestRouteId, MessageId) {
        assert_eq!(frame.version, RELAY_PROTOCOL_VERSION);
        let RelayFrameBody::Send(Send {
            device_route,
            request_route,
            sealed_blob,
        }) = &frame.body
        else {
            panic!("remote prompt transport may only emit Relay Send frames");
        };
        assert_eq!(*device_route, DEVICE_ROUTE);

        let signed = SignedSealedBlobV1::from_wire_bytes(&sealed_blob.0)
            .expect("Send must carry canonical SignedSealedBlobV1 bytes");
        assert_eq!(
            signed.inner.key_id,
            KeyId {
                purpose: KeyPurpose::DeviceCommandTx,
                epoch: DEVICE_COMMAND_EPOCH,
            }
        );
        assert_eq!(signed.inner.key_epoch, DEVICE_COMMAND_EPOCH);
        assert_eq!(signed.inner.key_directory_revision, KEY_DIRECTORY_REVISION);
        assert_eq!(
            u64::from_be_bytes(signed.inner.nonce[4..].try_into().expect("counter nonce")),
            self.expected_command_counter,
            "the request must consume the expected durable command block"
        );

        let context = OuterContextV1::uplink_send(
            MACHINE_ROUTE,
            DEVICE_ROUTE,
            *request_route,
            DEVICE_COMMAND_EPOCH,
        );
        let verified = verify_sealed(signed, &self.device_sign_verifying_key, &context)
            .expect("fake daemon must verify the real DeviceSign signature and exact uplink AAD");
        let receiving_key = AeadReceivingKey::new(
            KeyId {
                purpose: KeyPurpose::DeviceCommandTx,
                epoch: DEVICE_COMMAND_EPOCH,
            },
            DEVICE_COMMAND_EPOCH,
            SecretAeadKey::from_bytes(DEVICE_COMMAND_KEY),
        );
        let opened = open_sealed_payload(&receiving_key, &context, verified)
            .expect("fake daemon must open the real DeviceCommandTx AEAD payload");
        assert_eq!(opened.payload_kind, SealedPayloadKind::CommandRequest);
        let envelope = RuntimeEnvelope::from_json_bytes_checked(&opened.payload)
            .expect("decrypted bytes must be a checked Runtime request envelope");
        assert_eq!(envelope.version, RUNTIME_PROTOCOL_VERSION);
        let RuntimeMessage::Request(actual) = envelope.body else {
            panic!("remote runtime may only emit RuntimeRequest payloads");
        };
        assert_eq!(
            serde_json::to_value(actual).expect("serialize actual RuntimeRequest"),
            serde_json::to_value(&self.expected_request)
                .expect("serialize expected RuntimeRequest"),
            "remote runtime must seal the exact expected request variant and fields"
        );
        (*request_route, envelope.message_id)
    }

    fn queue_scripted_inbound(&mut self, request_route: RequestRouteId, message_id: MessageId) {
        if let Some(replies) = &self.reply_sequence {
            for (offset, reply) in replies.iter().enumerate() {
                self.inbound.push_back(received_exact(reply_frame(
                    request_route,
                    message_id.clone(),
                    reply.clone(),
                    ReplyShape::Valid,
                    self.reply_counter + offset as u64,
                )));
            }
            self.inbound.append(&mut self.post_script_inbound);
            return;
        }
        let accepted = route_accepted(request_route);
        match self.script {
            TransportScript::ReplyOnly => self.inbound.push_back(received_exact(reply_frame(
                request_route,
                message_id,
                self.reply.clone(),
                ReplyShape::Valid,
                self.reply_counter,
            ))),
            TransportScript::ReplyOnlyWithShape(shape) => {
                self.inbound.push_back(received_exact(reply_frame(
                    request_route,
                    message_id,
                    self.reply.clone(),
                    shape,
                    self.reply_counter,
                )));
            }
            TransportScript::ReplyThenRouteAccepted => {
                self.inbound.push_back(received_exact(reply_frame(
                    request_route,
                    message_id,
                    self.reply.clone(),
                    ReplyShape::Valid,
                    self.reply_counter,
                )));
                self.inbound.push_back(received_exact(accepted));
            }
            TransportScript::RouteAcceptedThenReply => {
                self.inbound.push_back(received_exact(accepted));
                self.inbound.push_back(received_exact(reply_frame(
                    request_route,
                    message_id,
                    self.reply.clone(),
                    ReplyShape::Valid,
                    self.reply_counter,
                )));
            }
            TransportScript::RouteAcceptedOnly => {
                self.inbound.push_back(received_exact(accepted));
            }
            TransportScript::EofAfterSend => {}
            TransportScript::WrongRequestRouteOnly => {
                self.inbound.push_back(received_exact(reply_frame(
                    WRONG_REQUEST_ROUTE,
                    message_id,
                    self.reply.clone(),
                    ReplyShape::Valid,
                    self.reply_counter,
                )));
            }
            TransportScript::RevocationTerminalOnly(shape) => {
                self.inbound.push_back(revocation_terminal(shape));
            }
            TransportScript::Subscription(script) => {
                self.inbound.extend(
                    subscription_inbound_frames(
                        script,
                        request_route,
                        message_id,
                        self.reply_counter,
                    )
                    .into_iter()
                    .map(received_exact),
                );
            }
        }
        self.inbound.append(&mut self.post_script_inbound);
    }
}

#[async_trait]
impl RemoteRuntimeTransport for FakeTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        let exact_bytes = frame.into_bytes();
        let decoded = decode(&exact_bytes).expect("runtime must hand transport canonical bytes");
        self.sent_codec_frames
            .lock()
            .expect("sent-frame recorder")
            .push(exact_bytes);
        match &decoded.body {
            RelayFrameBody::Send(_) => {
                let (request_route, message_id) = self.inspect_real_send(&decoded);
                self.queue_scripted_inbound(request_route, message_id);
            }
            RelayFrameBody::Subscribe(_) | RelayFrameBody::Ack(_)
                if matches!(self.script, TransportScript::Subscription(_)) =>
            {
                if self.panic_on_first_subscription_control {
                    self.panic_on_first_subscription_control = false;
                    panic!("injected process death after durable binding install");
                }
                if matches!(decoded.body, RelayFrameBody::Ack(_)) && self.fail_on_subscription_ack {
                    self.fail_on_subscription_ack = false;
                    return Err(RemoteRuntimeTransportError::Failed(
                        "injected subscription ACK send failure".to_owned(),
                    ));
                }
            }
            body => panic!("remote runtime emitted an unexpected Relay frame: {body:?}"),
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        if let Some(frame) = self.inbound.pop_front() {
            return Ok(Some(frame));
        }
        if matches!(
            self.script,
            TransportScript::Subscription(SubscriptionScript::CatalogPartialTransferThenPending)
        ) {
            return std::future::pending::<
                Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError>,
            >()
            .await;
        }
        Ok(None)
    }

    async fn shutdown(&mut self) {
        if let Some(shutdown_observed) = &self.shutdown_observed {
            shutdown_observed.store(true, Ordering::SeqCst);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ReplyShape {
    Valid,
    ForgedMachineDataSignature,
    AuthenticatedBadCiphertext,
    WrongMessageId,
    WrongTransferChannel,
    WrongPayloadKind,
    WrongKeyPurpose,
    WrongKeyEpoch,
    WrongDirectoryRevision,
    WrongNoncePrefix,
    WrongAad,
    NonCanonicalJson,
}

#[derive(Clone, Copy, Debug)]
enum StreamPublishShape {
    Valid,
    ForgedSignature,
    WrongAad,
    NonCanonicalJson,
    AuthenticatedBadCiphertext,
    LowerDirectoryRevision,
    HigherDirectoryRevision,
    LowerKeyEpoch,
    HigherKeyEpoch,
    WrongKeyPurpose,
    WrongNoncePrefix,
    MalformedSealedBlob,
}

fn reply_frame(
    request_route: RequestRouteId,
    message_id: MessageId,
    reply: RuntimeReply,
    shape: ReplyShape,
    counter: u64,
) -> OpaqueRouteFrame {
    let expected_context = OuterContextV1::directed_reply(
        MACHINE_ROUTE,
        DEVICE_ROUTE,
        request_route,
        DEVICE_REPLY_EPOCH,
    );
    let reply_message_id = if matches!(shape, ReplyShape::WrongMessageId) {
        MessageId::new("wrong-message-id")
    } else {
        message_id
    };
    let (payload_kind, mut plaintext) = match reply {
        RuntimeReply::TransferPart(transfer) => (
            SealedPayloadKind::TransferPart,
            RuntimeTransferCarrierV1::new(
                reply_message_id,
                if matches!(shape, ReplyShape::WrongTransferChannel) {
                    RuntimeTransferChannel::Stream
                } else {
                    RuntimeTransferChannel::Reply
                },
                transfer,
            )
            .encode()
            .expect("fixture compact transfer carrier"),
        ),
        reply => {
            let payload_kind = match reply {
                RuntimeReply::Catalog(_) => SealedPayloadKind::CatalogSnapshot,
                RuntimeReply::Snapshot(_) => SealedPayloadKind::ConversationSnapshot,
                RuntimeReply::Backfill(_) => SealedPayloadKind::BackfillChunk,
                _ => SealedPayloadKind::CommandReceipt,
            };
            let envelope = RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id: reply_message_id,
                body: RuntimeMessage::Reply(reply),
            };
            (
                payload_kind,
                envelope
                    .to_json_bytes_checked()
                    .expect("fixture Runtime reply envelope"),
            )
        }
    };
    if matches!(shape, ReplyShape::NonCanonicalJson)
        && payload_kind != SealedPayloadKind::TransferPart
    {
        plaintext.insert(1, b' ');
    }
    let key_purpose = if matches!(shape, ReplyShape::WrongKeyPurpose) {
        KeyPurpose::DeviceCommandTx
    } else {
        KeyPurpose::DeviceReplyTx
    };
    let key_epoch = if matches!(shape, ReplyShape::WrongKeyEpoch) {
        DEVICE_REPLY_EPOCH + 1
    } else {
        DEVICE_REPLY_EPOCH
    };
    let directory_revision = if matches!(shape, ReplyShape::WrongDirectoryRevision) {
        KEY_DIRECTORY_REVISION + 1
    } else {
        KEY_DIRECTORY_REVISION
    };
    let sending_key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: key_purpose,
            epoch: key_epoch,
        },
        key_epoch,
        directory_revision,
        SecretAeadKey::from_bytes(DEVICE_REPLY_KEY),
    );
    let seal_context = if matches!(shape, ReplyShape::WrongAad) {
        OuterContextV1::directed_reply(
            MACHINE_ROUTE,
            DEVICE_ROUTE,
            WRONG_REQUEST_ROUTE,
            DEVICE_REPLY_EPOCH,
        )
    } else {
        expected_context.clone()
    };
    let mut unsigned = seal_symmetric(
        &sending_key,
        &seal_context,
        if matches!(shape, ReplyShape::WrongPayloadKind) {
            SealedPayloadKind::CommandRequest
        } else {
            payload_kind
        },
        &plaintext,
        SenderCounter(counter),
    )
    .expect("seal fixture DeviceReplyTx payload");
    if matches!(shape, ReplyShape::AuthenticatedBadCiphertext) {
        unsigned.ciphertext[0] ^= 1;
    }
    if matches!(shape, ReplyShape::WrongNoncePrefix) {
        unsigned.nonce[0] ^= 1;
    }
    let signing_key = match shape {
        ReplyShape::ForgedMachineDataSignature => SigningKey::from_seed(&[0x99; 32]),
        ReplyShape::Valid
        | ReplyShape::AuthenticatedBadCiphertext
        | ReplyShape::WrongMessageId
        | ReplyShape::WrongTransferChannel
        | ReplyShape::WrongPayloadKind
        | ReplyShape::WrongKeyPurpose
        | ReplyShape::WrongKeyEpoch
        | ReplyShape::WrongDirectoryRevision
        | ReplyShape::WrongNoncePrefix
        | ReplyShape::WrongAad
        | ReplyShape::NonCanonicalJson => PairingFixture::machine_data_signing_key(),
    };
    let signed = sign_sealed(unsigned, &signing_key, &expected_context);
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Reply(Reply {
            device_route: DEVICE_ROUTE,
            request_route,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn key_control_stream_binding_reply_frame(
    request_route: RequestRouteId,
    binding: StreamBindingV1,
    counter: u64,
) -> OpaqueRouteFrame {
    let context = OuterContextV1::directed_reply(
        MACHINE_ROUTE,
        DEVICE_ROUTE,
        request_route,
        DEVICE_REPLY_EPOCH,
    );
    let control = KeyControlV1::stream_binding(binding);
    let plaintext = control
        .canonical_bytes()
        .expect("fixture canonical StreamBinding KeyControl");
    let sending_key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: DEVICE_REPLY_EPOCH,
        },
        DEVICE_REPLY_EPOCH,
        KEY_DIRECTORY_REVISION,
        SecretAeadKey::from_bytes(DEVICE_REPLY_KEY),
    );
    let unsigned = seal_symmetric(
        &sending_key,
        &context,
        control.sealed_payload_kind(),
        &plaintext,
        SenderCounter(counter),
    )
    .expect("seal canonical DeviceReplyTx StreamBinding");
    let signed = sign_sealed(
        unsigned,
        &PairingFixture::machine_data_signing_key(),
        &context,
    );
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Reply(Reply {
            device_route: DEVICE_ROUTE,
            request_route,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn catalog_publish_frame(
    stream_seq: u64,
    catalog_revision: u64,
    sender_counter: u64,
    shape: StreamPublishShape,
) -> OpaqueRouteFrame {
    let item = RuntimeStreamItem::CatalogDelta(CatalogDelta {
        catalog_revision,
        changes: Vec::new(),
    });
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(format!("catalog-live-{stream_seq}")),
        body: RuntimeMessage::Stream(item),
    };
    let mut plaintext = envelope
        .to_json_bytes_checked()
        .expect("canonical live Catalog envelope");
    if matches!(shape, StreamPublishShape::NonCanonicalJson) {
        plaintext.insert(1, b' ');
    }
    let key_purpose = if matches!(shape, StreamPublishShape::WrongKeyPurpose) {
        KeyPurpose::ConversationDek
    } else {
        KeyPurpose::Catalog
    };
    let key_epoch = match shape {
        StreamPublishShape::LowerKeyEpoch => CATALOG_EPOCH - 1,
        StreamPublishShape::HigherKeyEpoch => CATALOG_EPOCH + 1,
        _ => CATALOG_EPOCH,
    };
    let directory_revision = match shape {
        StreamPublishShape::LowerDirectoryRevision => KEY_DIRECTORY_REVISION - 1,
        StreamPublishShape::HigherDirectoryRevision => KEY_DIRECTORY_REVISION + 1,
        _ => KEY_DIRECTORY_REVISION,
    };
    let expected_context = OuterContextV1 {
        frame_kind: OuterFrameKind::CatalogPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(MACHINE_ROUTE),
        device_route: None,
        stream_route: Some(CATALOG_STREAM_ROUTE),
        request_route: None,
        pair_route: None,
        stream_generation: Some(CATALOG_RELAY_GENERATION),
        stream_cursor: None,
        stream_seq: Some(stream_seq),
        message_key_epoch: key_epoch,
    };
    let seal_context = if matches!(shape, StreamPublishShape::WrongAad) {
        OuterContextV1 {
            stream_route: Some(StreamRouteId::from_bytes([0xfe; 16])),
            ..expected_context.clone()
        }
    } else {
        expected_context.clone()
    };
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: key_purpose,
            epoch: key_epoch,
        },
        key_epoch,
        directory_revision,
        SecretAeadKey::from_bytes([0x71; 32]),
    );
    let mut unsigned = seal_symmetric(
        &key,
        &seal_context,
        SealedPayloadKind::CatalogDelta,
        &plaintext,
        SenderCounter(sender_counter),
    )
    .expect("seal live Catalog publication");
    if matches!(shape, StreamPublishShape::AuthenticatedBadCiphertext) {
        unsigned.ciphertext[0] ^= 1;
    }
    if matches!(shape, StreamPublishShape::WrongNoncePrefix) {
        unsigned.nonce[0] ^= 1;
    }
    let signer = if matches!(shape, StreamPublishShape::ForgedSignature) {
        SigningKey::from_seed(&[0xfa; 32])
    } else {
        PairingFixture::machine_data_signing_key()
    };
    let signed = sign_sealed(unsigned, &signer, &seal_context);
    let mut sealed_blob = signed.to_wire_bytes();
    if matches!(shape, StreamPublishShape::MalformedSealedBlob) {
        sealed_blob.pop();
    }
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Publish(Publish {
            stream_route: CATALOG_STREAM_ROUTE,
            generation: CATALOG_RELAY_GENERATION,
            stream_seq,
            sealed_blob: SealedBlob(sealed_blob),
        }),
    }
}

fn catalog_requested_cursor() -> RuntimeInnerCursor {
    RuntimeInnerCursor::Catalog {
        cursor: StreamCursor::BeforeFirst,
    }
}

fn catalog_backfill_requested_cursor() -> RuntimeInnerCursor {
    RuntimeInnerCursor::Catalog {
        cursor: StreamCursor::At(0),
    }
}

fn conversation_requested_cursor() -> RuntimeInnerCursor {
    RuntimeInnerCursor::Conversation {
        conversation_id: ConversationId::new(SUBSCRIPTION_CONVERSATION_ID),
        cursor: StreamCursor::BeforeFirst,
    }
}

#[derive(Clone)]
struct CapturingSubscriptionReducer {
    cursor: RuntimeInnerCursor,
    applied: Vec<RemoteSubscriptionBootstrapItem>,
    live_applied: Vec<RuntimeStreamItem>,
    reject_apply: bool,
    stall_cursor: bool,
}

impl CapturingSubscriptionReducer {
    fn new(cursor: RuntimeInnerCursor) -> Self {
        Self {
            cursor,
            applied: Vec::new(),
            live_applied: Vec::new(),
            reject_apply: false,
            stall_cursor: false,
        }
    }

    fn rejecting(cursor: RuntimeInnerCursor) -> Self {
        Self {
            reject_apply: true,
            ..Self::new(cursor)
        }
    }

    fn stalling(cursor: RuntimeInnerCursor) -> Self {
        Self {
            stall_cursor: true,
            ..Self::new(cursor)
        }
    }

    fn applied(&self) -> &[RemoteSubscriptionBootstrapItem] {
        &self.applied
    }

    fn live_applied(&self) -> &[RuntimeStreamItem] {
        &self.live_applied
    }
}

impl RemoteSubscriptionReducer for CapturingSubscriptionReducer {
    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        if self.reject_apply {
            return Err(RemoteRuntimeError::InvalidReply(
                "test reducer injected an apply rejection",
            ));
        }
        let next = match (item, &self.cursor) {
            (
                RemoteSubscriptionBootstrapItem::CatalogSnapshot(snapshot),
                RuntimeInnerCursor::Catalog { .. },
            ) => RuntimeInnerCursor::Catalog {
                cursor: snapshot.base_catalog_cursor,
            },
            (
                RemoteSubscriptionBootstrapItem::ConversationSnapshot(snapshot),
                RuntimeInnerCursor::Conversation {
                    conversation_id, ..
                },
            ) if &snapshot.conversation_id == conversation_id => RuntimeInnerCursor::Conversation {
                conversation_id: conversation_id.clone(),
                cursor: snapshot.base_event_cursor,
            },
            (
                RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Catalog { range, .. }),
                RuntimeInnerCursor::Catalog { cursor },
            ) if range.after() == *cursor => RuntimeInnerCursor::Catalog {
                cursor: range.through(),
            },
            (
                RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Conversation {
                    conversation_id,
                    range,
                    ..
                }),
                RuntimeInnerCursor::Conversation {
                    conversation_id: expected,
                    cursor,
                },
            ) if conversation_id == expected && range.after() == *cursor => {
                RuntimeInnerCursor::Conversation {
                    conversation_id: expected.clone(),
                    cursor: range.through(),
                }
            }
            _ => {
                return Err(RemoteRuntimeError::InvalidReply(
                    "test reducer rejected a cross-target or discontinuous bootstrap item",
                ));
            }
        };
        if !self.stall_cursor {
            self.cursor = next;
        }
        self.applied.push(item.clone());
        Ok(())
    }

    fn apply_live(&mut self, item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        if self.reject_apply {
            return Err(RemoteRuntimeError::InvalidReply(
                "test reducer injected a live apply rejection",
            ));
        }
        let next = match (item, &self.cursor) {
            (RuntimeStreamItem::CatalogDelta(delta), RuntimeInnerCursor::Catalog { cursor })
                if cursor.checked_next().ok() == Some(delta.catalog_revision) =>
            {
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(delta.catalog_revision),
                }
            }
            (
                RuntimeStreamItem::Event(event),
                RuntimeInnerCursor::Conversation {
                    conversation_id,
                    cursor,
                },
            ) if &event.conversation_id == conversation_id
                && cursor.checked_next().ok() == Some(event.event_seq) =>
            {
                RuntimeInnerCursor::Conversation {
                    conversation_id: conversation_id.clone(),
                    cursor: StreamCursor::At(event.event_seq),
                }
            }
            _ => {
                return Err(RemoteRuntimeError::InvalidReply(
                    "test reducer rejected a cross-target or discontinuous live item",
                ));
            }
        };
        if !self.stall_cursor {
            self.cursor = next;
        }
        self.live_applied.push(item.clone());
        Ok(())
    }
}

fn catalog_runtime_generation() -> StreamGeneration {
    StreamGeneration::new("018f0f9d-6f0a-7ad0-8000-000000000091")
}

fn conversation_runtime_generation() -> StreamGeneration {
    // 该 Runtime generation 故意不等于 Relay binding 的 [0x92; 16] generation。
    StreamGeneration::new("018f0f9d-6f0a-7ad0-8000-000000000093")
}

fn catalog_subscription_receipt() -> SubscriptionReceipt {
    SubscriptionReceipt::Subscribed {
        stream_generation: catalog_runtime_generation(),
    }
}

fn conversation_subscription_receipt() -> SubscriptionReceipt {
    SubscriptionReceipt::Subscribed {
        stream_generation: conversation_runtime_generation(),
    }
}

fn catalog_sync_complete(outer: StreamCursor, inner: StreamCursor) -> RuntimeSyncComplete {
    RuntimeSyncComplete {
        stream_generation: catalog_runtime_generation(),
        stream_cursor: outer,
        inner_cursor: RuntimeInnerCursor::Catalog { cursor: inner },
        key_directory_revision: KEY_DIRECTORY_REVISION,
    }
}

fn conversation_sync_complete() -> RuntimeSyncComplete {
    RuntimeSyncComplete {
        stream_generation: conversation_runtime_generation(),
        stream_cursor: StreamCursor::At(CONVERSATION_OUTER_HIGH_WATER),
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(SUBSCRIPTION_CONVERSATION_ID),
            cursor: StreamCursor::At(CONVERSATION_INNER_HIGH_WATER),
        },
        key_directory_revision: KEY_DIRECTORY_REVISION,
    }
}

fn catalog_stream_binding(outer: StreamCursor, inner: StreamCursor) -> StreamBindingV1 {
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE_ROUTE,
        device_route: DEVICE_ROUTE,
        grant_serial: RelayGrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        stream_route: CATALOG_STREAM_ROUTE,
        stream_generation: CATALOG_RELAY_GENERATION,
        stream_cursor: outer,
        inner_cursor: RuntimeInnerCursor::Catalog { cursor: inner },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
    }
}

fn conversation_stream_binding(outer: StreamCursor, inner: StreamCursor) -> StreamBindingV1 {
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE_ROUTE,
        device_route: DEVICE_ROUTE,
        grant_serial: RelayGrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        stream_route: CONVERSATION_STREAM_ROUTE,
        stream_generation: CONVERSATION_RELAY_GENERATION,
        stream_cursor: outer,
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(SUBSCRIPTION_CONVERSATION_ID),
            cursor: inner,
        },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: CONVERSATION_EPOCH,
        },
    }
}

fn subscription_catalog_snapshot(cursor: StreamCursor) -> CatalogSnapshot {
    if cursor == StreamCursor::At(CATALOG_INNER_HIGH_WATER) {
        let fixture = catalog_snapshot();
        CatalogSnapshot::new(cursor, fixture.entries().to_vec(), None, None)
            .expect("bounded final subscription catalog snapshot page")
    } else {
        CatalogSnapshot::new(cursor, Vec::new(), None, None)
            .expect("bounded empty subscription catalog snapshot")
    }
}

fn subscription_catalog_page(current: Option<&str>, next: Option<&str>) -> CatalogSnapshot {
    CatalogSnapshot::new(
        StreamCursor::At(CATALOG_INNER_HIGH_WATER),
        Vec::new(),
        current.map(CatalogPageCursor::new),
        next.map(CatalogPageCursor::new),
    )
    .expect("bounded chained subscription Catalog page")
}

fn subscription_catalog_backfill() -> BackfillChunk {
    BackfillChunk::catalog(
        BackfillRange::new(StreamCursor::At(0), StreamCursor::At(1))
            .expect("one-entry catalog backfill range"),
        vec![CatalogDelta {
            catalog_revision: 1,
            changes: Vec::new(),
        }],
    )
    .expect("one-entry catalog backfill")
}

fn subscription_conversation_snapshot() -> ConversationSnapshot {
    let capabilities = SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "remote-subscription-fixture".to_owned(),
        features: BTreeSet::new(),
        vendor: VendorCapabilities::Codex(CodexCapabilities::default()),
    };
    ConversationSnapshot::new(
        ConversationId::new(SUBSCRIPTION_CONVERSATION_ID),
        StreamCursor::At(CONVERSATION_INNER_HIGH_WATER),
        ConversationConfigurationState::new(0, None)
            .expect("empty configuration state is canonical"),
        vec![SnapshotItem::capabilities(capabilities)],
    )
    .expect("capabilities-first conversation snapshot")
}

fn subscription_inbound_frames(
    script: SubscriptionScript,
    request_route: RequestRouteId,
    message_id: MessageId,
    reply_counter: u64,
) -> Vec<OpaqueRouteFrame> {
    let counter_delta = reply_counter
        .checked_sub(REPLY_COUNTER)
        .expect("subscription reply counter base cannot move backwards");
    let adjusted_counter = |counter: u64| {
        counter
            .checked_add(counter_delta)
            .expect("subscription fixture reply counter overflow")
    };
    let runtime_reply = |reply, counter| {
        reply_frame(
            request_route,
            message_id.clone(),
            reply,
            ReplyShape::Valid,
            adjusted_counter(counter),
        )
    };
    let runtime_reply_shape = |reply, shape, counter| {
        reply_frame(
            request_route,
            message_id.clone(),
            reply,
            shape,
            adjusted_counter(counter),
        )
    };
    let stream_binding_reply = |binding, counter| {
        key_control_stream_binding_reply_frame(request_route, binding, adjusted_counter(counter))
    };
    let accepted = route_accepted(request_route);
    match script {
        SubscriptionScript::CatalogAt => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(inner)),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 3),
            ]
        }
        SubscriptionScript::CatalogFailure => vec![
            accepted,
            runtime_reply(
                RuntimeReply::Failure(RuntimeFailure::new(
                    "daemon.subscription.fixture_unavailable",
                    "fixture transiently rejects the subscription",
                )),
                REPLY_COUNTER,
            ),
        ],
        SubscriptionScript::CatalogCompact
        | SubscriptionScript::CatalogCompactWrongMessage
        | SubscriptionScript::CatalogCompactWrongChannel => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            let mut parts = catalog_transfer_replies(&subscription_catalog_snapshot(inner));
            let first = parts.remove(0);
            let second = parts.remove(0);
            let first_shape = match script {
                SubscriptionScript::CatalogCompactWrongMessage => ReplyShape::WrongMessageId,
                SubscriptionScript::CatalogCompactWrongChannel => ReplyShape::WrongTransferChannel,
                _ => ReplyShape::Valid,
            };
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply_shape(first, first_shape, REPLY_COUNTER + 1),
                runtime_reply(second, REPLY_COUNTER + 2),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 3,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 4),
            ]
        }
        SubscriptionScript::CatalogCompactBackfill => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let sync_inner = StreamCursor::At(1);
            let payload = serde_json::to_vec(&subscription_catalog_backfill())
                .expect("canonical Catalog backfill transfer payload");
            let mut parts = transfer_replies(payload, "catalog-backfill-subscription-transfer");
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 1),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 2),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, sync_inner)),
                    REPLY_COUNTER + 3,
                ),
                stream_binding_reply(
                    catalog_stream_binding(outer, StreamCursor::At(0)),
                    REPLY_COUNTER + 4,
                ),
            ]
        }
        SubscriptionScript::CatalogSnapshotThenBackfill => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let snapshot_inner = StreamCursor::At(0);
            let sync_inner = StreamCursor::At(1);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(snapshot_inner)),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::Backfill(subscription_catalog_backfill()),
                    REPLY_COUNTER + 2,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, sync_inner)),
                    REPLY_COUNTER + 3,
                ),
                stream_binding_reply(
                    catalog_stream_binding(outer, snapshot_inner),
                    REPLY_COUNTER + 4,
                ),
            ]
        }
        SubscriptionScript::CatalogCompactSnapshotThenBackfill => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let snapshot_inner = StreamCursor::At(0);
            let sync_inner = StreamCursor::At(1);
            let mut parts =
                catalog_transfer_replies(&subscription_catalog_snapshot(snapshot_inner));
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 1),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 2),
                runtime_reply(
                    RuntimeReply::Backfill(subscription_catalog_backfill()),
                    REPLY_COUNTER + 3,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, sync_inner)),
                    REPLY_COUNTER + 4,
                ),
                stream_binding_reply(
                    catalog_stream_binding(outer, snapshot_inner),
                    REPLY_COUNTER + 5,
                ),
            ]
        }
        SubscriptionScript::CatalogDuplicateOpenPage => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            let repeated = runtime_reply(
                RuntimeReply::Catalog(subscription_catalog_page(None, Some("subscription-page-2"))),
                REPLY_COUNTER + 1,
            );
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                repeated.clone(),
                repeated,
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_page(
                        Some("subscription-page-2"),
                        None,
                    )),
                    REPLY_COUNTER + 2,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 3,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 4),
            ]
        }
        SubscriptionScript::CatalogMissingFirstPage => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_page(
                        Some("subscription-page-2"),
                        None,
                    )),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 3),
            ]
        }
        SubscriptionScript::CatalogCompactMissingMiddlePage => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            let payload = serde_json::to_vec(&subscription_catalog_page(
                Some("subscription-page-3"),
                None,
            ))
            .expect("canonical final Catalog page with a missing predecessor");
            let mut parts = transfer_replies(payload, "missing-middle-catalog-page");
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_page(
                        None,
                        Some("subscription-page-2"),
                    )),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 2),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 3),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 4,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 5),
            ]
        }
        SubscriptionScript::CatalogCompactCrossTarget => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            let payload = serde_json::to_vec(&subscription_conversation_snapshot())
                .expect("canonical cross-target conversation snapshot");
            let mut parts = transfer_replies(payload, "cross-target-subscription-transfer");
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 1),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 2),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 3,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 4),
            ]
        }
        SubscriptionScript::CatalogPartialTransferThenSync => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            let first = catalog_transfer_replies(&subscription_catalog_snapshot(inner)).remove(0);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(first, REPLY_COUNTER + 1),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 3),
            ]
        }
        SubscriptionScript::CatalogPartialTransferThenPending => {
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            let first = catalog_transfer_replies(&subscription_catalog_snapshot(inner)).remove(0);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(first, REPLY_COUNTER + 1),
            ]
        }
        SubscriptionScript::CatalogUnfinishedPageThenSync => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(RuntimeReply::Catalog(catalog_snapshot()), REPLY_COUNTER + 1),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 3),
            ]
        }
        SubscriptionScript::CatalogSyncAheadOfBinding => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let sync_inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(sync_inner)),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, sync_inner)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(
                    catalog_stream_binding(outer, StreamCursor::BeforeFirst),
                    REPLY_COUNTER + 3,
                ),
            ]
        }
        SubscriptionScript::CatalogSmallSyncAhead => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let sync_inner = StreamCursor::At(2);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(sync_inner)),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, sync_inner)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(
                    catalog_stream_binding(outer, StreamCursor::BeforeFirst),
                    REPLY_COUNTER + 3,
                ),
            ]
        }
        SubscriptionScript::ConversationIndependentGeneration => vec![
            accepted,
            runtime_reply(
                RuntimeReply::Subscription(conversation_subscription_receipt()),
                REPLY_COUNTER,
            ),
            runtime_reply(
                RuntimeReply::Snapshot(subscription_conversation_snapshot()),
                REPLY_COUNTER + 1,
            ),
            runtime_reply(
                RuntimeReply::SyncComplete(conversation_sync_complete()),
                REPLY_COUNTER + 2,
            ),
            stream_binding_reply(
                conversation_stream_binding(
                    StreamCursor::At(CONVERSATION_OUTER_HIGH_WATER),
                    StreamCursor::At(CONVERSATION_INNER_HIGH_WATER),
                ),
                REPLY_COUNTER + 3,
            ),
        ],
        SubscriptionScript::ConversationCompact => {
            let payload = serde_json::to_vec(&subscription_conversation_snapshot())
                .expect("canonical Conversation snapshot transfer payload");
            let mut parts = transfer_replies(payload, "conversation-subscription-transfer");
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(conversation_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 1),
                runtime_reply(parts.remove(0), REPLY_COUNTER + 2),
                runtime_reply(
                    RuntimeReply::SyncComplete(conversation_sync_complete()),
                    REPLY_COUNTER + 3,
                ),
                stream_binding_reply(
                    conversation_stream_binding(
                        StreamCursor::At(CONVERSATION_OUTER_HIGH_WATER),
                        StreamCursor::At(CONVERSATION_INNER_HIGH_WATER),
                    ),
                    REPLY_COUNTER + 4,
                ),
            ]
        }
        SubscriptionScript::CatalogBeforeFirst => {
            let cursor = StreamCursor::BeforeFirst;
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(cursor)),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(cursor, cursor)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(catalog_stream_binding(cursor, cursor), REPLY_COUNTER + 3),
            ]
        }
        SubscriptionScript::CatalogBeforeFirstNoSnapshot => {
            let cursor = StreamCursor::BeforeFirst;
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(cursor, cursor)),
                    REPLY_COUNTER + 1,
                ),
                stream_binding_reply(catalog_stream_binding(cursor, cursor), REPLY_COUNTER + 2),
            ]
        }
        SubscriptionScript::CatalogMissingBinding => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(inner)),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 2,
                ),
            ]
        }
        SubscriptionScript::CatalogCrossTargetBinding => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(inner)),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(
                    conversation_stream_binding(
                        outer,
                        StreamCursor::At(CONVERSATION_INNER_HIGH_WATER),
                    ),
                    REPLY_COUNTER + 3,
                ),
            ]
        }
        SubscriptionScript::CatalogWrongBindingRevision => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            let mut binding = catalog_stream_binding(outer, inner);
            binding.key_directory_revision = KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION + 1);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(inner)),
                    REPLY_COUNTER + 1,
                ),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 2,
                ),
                stream_binding_reply(binding, REPLY_COUNTER + 3),
            ]
        }
        SubscriptionScript::CatalogBindingBeforeSync => {
            let outer = StreamCursor::At(CATALOG_OUTER_HIGH_WATER);
            let inner = StreamCursor::At(CATALOG_INNER_HIGH_WATER);
            vec![
                accepted,
                runtime_reply(
                    RuntimeReply::Subscription(catalog_subscription_receipt()),
                    REPLY_COUNTER,
                ),
                runtime_reply(
                    RuntimeReply::Catalog(subscription_catalog_snapshot(inner)),
                    REPLY_COUNTER + 1,
                ),
                stream_binding_reply(catalog_stream_binding(outer, inner), REPLY_COUNTER + 2),
                runtime_reply(
                    RuntimeReply::SyncComplete(catalog_sync_complete(outer, inner)),
                    REPLY_COUNTER + 3,
                ),
            ]
        }
    }
}

fn route_accepted(request_route: RequestRouteId) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::Request { request_route },
        }),
    }
}

fn received_exact(frame: OpaqueRouteFrame) -> ReceivedRuntimeFrame {
    let canonical_bytes = encode(&frame);
    ReceivedRuntimeFrame::from_untrusted_parts(frame, canonical_bytes)
}

fn revocation_terminal(shape: RevocationTerminalShape) -> ReceivedRuntimeFrame {
    let device_route = if matches!(shape, RevocationTerminalShape::WrongDeviceRoute) {
        DeviceRouteId::from_bytes([0xb1; 16])
    } else {
        DEVICE_ROUTE
    };
    let grant_serial = if matches!(shape, RevocationTerminalShape::WrongGrantSerial) {
        RelayGrantSerial::new(8)
    } else {
        RelayGrantSerial::new(7)
    };
    let mut revocation = DeviceRevocation {
        machine_route: MACHINE_ROUTE,
        device_route,
        grant_serial,
        root_key_id: ROOT_KEY_ID,
        trust_epoch: agentdeck_protocol::relay_v2::TrustEpoch::new(2),
        signature: Ed25519Signature([0; 64]),
    };
    let signing_key = if matches!(shape, RevocationTerminalShape::ForgedSignature) {
        SigningKey::from_seed(&[0xb2; 32])
    } else {
        PairingFixture::root_signing_key()
    };
    let root_fingerprint = sha256(
        &PairingFixture::root_signing_key()
            .verifying_key()
            .to_bytes(),
    );
    revocation.signature = sign_tbs(
        &signing_key,
        &revocation.to_be_signed_v1(RELAY_SERVER, root_fingerprint),
    )
    .into();
    let frame = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route,
            grant_serial,
            signed_revocation: revocation,
        }),
    };
    let mut canonical_bytes = encode(&frame);
    if matches!(shape, RevocationTerminalShape::NonExactBytes) {
        canonical_bytes.push(0);
    }
    ReceivedRuntimeFrame::from_untrusted_parts(frame, canonical_bytes)
}

fn revoke_self_request() -> RuntimeRequest {
    RuntimeRequest::Revoke(RevokeRequest {
        target: RevokeTarget::SelfDevice,
    })
}

fn committed_revocation_receipt() -> RuntimeReply {
    RuntimeReply::Revocation(RevocationReceipt::Committed {
        grant_serial: RuntimeGrantSerial::new(7),
    })
}

fn prompt_request() -> SendPromptRequest {
    SendPromptRequest {
        conversation_id: ConversationId::new("conversation-remote-runtime"),
        idempotency_key: IdempotencyKey::new("prompt-intent-stable-1"),
        expected_configuration_revision: 9,
        prompt: PromptPayload::new("请从真实 daemon receipt 返回结果").expect("bounded prompt"),
    }
}

fn accepted_receipt() -> CommandReceipt {
    accepted_receipt_at_revision(9)
}

fn accepted_receipt_at_revision(configuration_revision: u64) -> CommandReceipt {
    CommandReceipt::Accepted {
        command_id: CommandId::new("command-remote-runtime-1"),
        queue_position: 3,
        configuration_revision,
    }
}

fn failed_receipt() -> CommandReceipt {
    CommandReceipt::Failed {
        failure: RuntimeFailure::new(
            "daemon.command.queue_full",
            "fixture queue is intentionally full",
        ),
    }
}

fn approval_conversation_id() -> ConversationId {
    ConversationId::new("conversation-remote-approval")
}

fn approval_turn_id() -> TurnId {
    TurnId::new("turn-remote-approval")
}

fn approval_id() -> ApprovalId {
    ApprovalId::new("approval-remote-runtime-1")
}

fn approval_decision() -> ActionDecision {
    ActionDecision {
        request_id: "action-request-remote-runtime-1".to_owned(),
        decision: ActionDecisionKind::Approve,
        persist: false,
    }
}

fn resolve_approval_request() -> RuntimeRequest {
    RuntimeRequest::ResolveApproval {
        conversation_id: approval_conversation_id(),
        turn_id: approval_turn_id(),
        approval_id: approval_id(),
        decision: approval_decision(),
    }
}

fn retry_approval_request() -> RuntimeRequest {
    RuntimeRequest::RetryApproval {
        conversation_id: approval_conversation_id(),
        approval_id: approval_id(),
    }
}

fn applied_approval_receipt() -> ApprovalReceipt {
    ApprovalReceipt::Applied {
        approval_id: approval_id(),
    }
}

fn delivery_failed_approval_receipt() -> ApprovalReceipt {
    ApprovalReceipt::DeliveryFailed {
        approval_id: approval_id(),
    }
}

fn catalog_page_cursor() -> CatalogPageCursor {
    CatalogPageCursor::new("catalog-page-cursor-1")
}

fn catalog_request(page_cursor: Option<CatalogPageCursor>) -> RuntimeRequest {
    RuntimeRequest::Catalog(CatalogRequest { page_cursor })
}

fn catalog_snapshot_with_current(
    current_page_cursor: Option<CatalogPageCursor>,
) -> CatalogSnapshot {
    CatalogSnapshot::new(
        StreamCursor::At(17),
        vec![ConversationEntry {
            conversation_id: ConversationId::new("conversation-catalog-1"),
            agent_kind: AgentKind::Codex,
            title: Some("Catalog fixture".to_owned()),
            cwd: Some(PathBuf::from("/tmp/catalog-fixture")),
            last_active_ms: 42,
            archived: false,
            entry_revision: 5,
        }],
        current_page_cursor,
        Some(CatalogPageCursor::new("catalog-page-cursor-2")),
    )
    .expect("bounded catalog fixture")
}

fn catalog_snapshot() -> CatalogSnapshot {
    catalog_snapshot_with_current(None)
}

fn newer_catalog_snapshot() -> CatalogSnapshot {
    CatalogSnapshot::new(
        StreamCursor::At(18),
        vec![ConversationEntry {
            conversation_id: ConversationId::new("conversation-catalog-2"),
            agent_kind: AgentKind::ClaudeCode,
            title: Some("Newer catalog fixture".to_owned()),
            cwd: Some(PathBuf::from("/tmp/newer-catalog-fixture")),
            last_active_ms: 84,
            archived: false,
            entry_revision: 6,
        }],
        None,
        None,
    )
    .expect("bounded newer catalog fixture")
}

fn catalog_transfer_replies(snapshot: &CatalogSnapshot) -> Vec<RuntimeReply> {
    let payload = serde_json::to_vec(snapshot).expect("encode CatalogSnapshot transfer payload");
    transfer_replies(payload, "catalog-transfer-1")
}

fn transfer_replies(payload: Vec<u8>, transfer_id: &str) -> Vec<RuntimeReply> {
    let midpoint = payload.len() / 2;
    let total_sha256 = sha256(&payload);
    let total_bytes = payload.len() as u64;
    let transfer_id = TransferId::new(transfer_id);
    [payload[..midpoint].to_vec(), payload[midpoint..].to_vec()]
        .into_iter()
        .enumerate()
        .map(|(index, part)| {
            RuntimeReply::TransferPart(
                TransferEnvelope::new(
                    transfer_id.clone(),
                    index as u32,
                    2,
                    total_sha256,
                    total_bytes,
                    part,
                )
                .expect("valid compact Catalog transfer part"),
            )
        })
        .collect()
}

fn assert_catalog_outcome(
    outcome: &RemoteCatalogPageOutcome,
    route_accepted: bool,
    expected: &CatalogSnapshot,
) {
    assert_eq!(outcome.route_accepted(), route_accepted);
    assert_eq!(outcome.snapshot(), expected);
}

fn state_root(temp: &tempfile::TempDir) -> PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical tempdir")
        .join("paired-state")
}

fn assert_file_tree_omits(root: &std::path::Path, sentinel: &[u8]) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).expect("read paired state directory") {
                pending.push(entry.expect("read paired state entry").path());
            }
            continue;
        }
        let bytes = fs::read(&path).expect("read paired state artifact");
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|candidate| candidate == sentinel),
            "bootstrap plaintext sentinel leaked into {}",
            path.display()
        );
    }
}

fn paired_account(fixture: &PairingFixture, purpose: PairedRemoteKeyPurpose) -> RemoteKeyAccount {
    let identity = fixture.identity();
    RemoteKeyAccount::paired(
        INSTALLATION_ID,
        identity.machine_root_fingerprint(),
        identity.machine_route(),
        purpose,
    )
}

type PairedMaterialSnapshot = Vec<(PairedRemoteKeyPurpose, Option<Vec<u8>>)>;
type CryptoStateSnapshot = Vec<(String, Vec<u8>)>;
type MachineArtifactSnapshot = (PairedMaterialSnapshot, CryptoStateSnapshot);

fn paired_materials(
    store: &dyn RemoteKeyStore,
    fixture: &PairingFixture,
) -> PairedMaterialSnapshot {
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
        let value = store
            .load(&paired_account(fixture, purpose))
            .expect("read paired material")
            .map(|secret| secret.expose_secret().to_vec());
        (purpose, value)
    })
    .collect()
}

fn crypto_state_files(root: &std::path::Path) -> CryptoStateSnapshot {
    fn visit(root: &std::path::Path, entries: &mut Vec<(String, Vec<u8>)>) {
        if !root.exists() {
            return;
        }
        for entry in
            fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
        {
            let path = entry.expect("read state entry").path();
            let metadata = fs::symlink_metadata(&path).expect("state entry metadata");
            if metadata.is_dir() {
                visit(&path, entries);
            } else if metadata.is_file()
                && path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.ends_with(".crypto-state.v1") || name.ends_with(".crypto-state-stage.v1")
                })
            {
                entries.push((
                    path.to_string_lossy().into_owned(),
                    fs::read(&path).expect("read crypto-state artifact"),
                ));
            }
        }
    }

    let mut entries = Vec::new();
    visit(root, &mut entries);
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    entries
}

fn machine_artifacts(
    store: &dyn RemoteKeyStore,
    state_root: &std::path::Path,
    fixture: &PairingFixture,
) -> MachineArtifactSnapshot {
    (
        paired_materials(store, fixture),
        crypto_state_files(state_root),
    )
}

fn assert_machine_active(
    store: &dyn RemoteKeyStore,
    state_root: &std::path::Path,
    fixture: &PairingFixture,
) {
    let paired = PairedMachineStore::new(store, INSTALLATION_ID, state_root);
    assert_eq!(paired.list().expect("list paired machine").len(), 1);
    drop(
        paired
            .open_exact(fixture.identity())
            .expect("paired machine remains openable"),
    );
}

fn assert_cleanup_complete(
    store: &dyn RemoteKeyStore,
    state_root: &std::path::Path,
    fixture: &PairingFixture,
) {
    assert!(
        paired_materials(store, fixture)
            .into_iter()
            .all(|(_, value)| value.is_none()),
        "signed terminal cleanup must remove every paired Keychain item"
    );
    assert!(
        crypto_state_files(state_root).is_empty(),
        "signed terminal cleanup must remove active state and prepared sidecar"
    );
    assert!(
        PairedMachineStore::new(store, INSTALLATION_ID, state_root)
            .list()
            .expect("list after cleanup")
            .is_empty()
    );
}

fn assert_accepted_outcome(outcome: &RemotePromptOutcome, route_accepted: bool) {
    assert_eq!(outcome.route_accepted(), route_accepted);
    assert!(matches!(
        outcome.receipt(),
        CommandReceipt::Accepted {
            command_id,
            queue_position: 3,
            configuration_revision: 9,
        } if command_id == &CommandId::new("command-remote-runtime-1")
    ));
}

fn assert_not_terminal(result: Result<RemotePromptOutcome, RemoteRuntimeError>) {
    assert!(
        result.is_err(),
        "transport state or unauthenticated/uncorrelated reply must not become command success"
    );
}

fn one_sent_codec_frame(recorder: &Arc<Mutex<Vec<Vec<u8>>>>) -> Vec<u8> {
    let frames = recorder.lock().expect("sent-frame recorder");
    assert_eq!(frames.len(), 1, "one prompt attempt emits one frozen Send");
    frames[0].clone()
}

#[tokio::test]
async fn revoke_self_route_accepted_then_eof_is_outcome_unknown_without_cleanup() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xb0);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (transport, sent) = FakeTransport::new_runtime(
        TransportScript::RouteAcceptedOnly,
        revoke_self_request(),
        committed_revocation_receipt(),
        device_sign,
    );
    let shutdown_observed = Arc::new(AtomicBool::new(false));
    let transport = transport.with_shutdown_observer(Arc::clone(&shutdown_observed));
    let mut rng = DeterministicRng::new([0xb1; 32]);

    assert!(matches!(
        RemoteRuntime::new(opened, transport)
            .revoke_self(&mut rng)
            .await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    assert!(
        shutdown_observed.load(Ordering::SeqCst),
        "outcome-unknown self-revoke must still await transport shutdown"
    );
    let _ = one_sent_codec_frame(&sent);
    assert_machine_active(&store, &root, &fixture);
}

#[tokio::test]
async fn authenticated_revocation_committed_receipt_then_eof_still_does_not_cleanup() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xb2);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (transport, _sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        revoke_self_request(),
        committed_revocation_receipt(),
        device_sign,
    );
    let mut rng = DeterministicRng::new([0xb3; 32]);

    assert!(matches!(
        RemoteRuntime::new(opened, transport)
            .revoke_self(&mut rng)
            .await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    assert_machine_active(&store, &root, &fixture);
}

#[tokio::test]
async fn rejected_revocation_terminals_do_not_mutate_the_pending_machine() {
    for (index, shape) in [
        RevocationTerminalShape::ForgedSignature,
        RevocationTerminalShape::WrongDeviceRoute,
        RevocationTerminalShape::WrongGrantSerial,
        RevocationTerminalShape::NonExactBytes,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, 0xb4 + index as u8);

        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open promoted machine");
        let (first_transport, first_sent) = FakeTransport::new_runtime(
            TransportScript::EofAfterSend,
            revoke_self_request(),
            committed_revocation_receipt(),
            device_sign,
        );
        let mut first_rng = DeterministicRng::new([0xc0 + index as u8; 32]);
        assert!(matches!(
            RemoteRuntime::new(opened, first_transport)
                .revoke_self(&mut first_rng)
                .await,
            Err(RemoteRuntimeError::OutcomeUnknown)
        ));
        let frozen = one_sent_codec_frame(&first_sent);

        let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("reopen pending self-revoke");
        let before = machine_artifacts(&store, &root, &fixture);
        let (bad_transport, bad_sent) = FakeTransport::new_runtime(
            TransportScript::RevocationTerminalOnly(shape),
            revoke_self_request(),
            committed_revocation_receipt(),
            device_sign,
        );
        let mut panic_rng = PanicRng;
        assert!(
            RemoteRuntime::new(reopened, bad_transport)
                .revoke_self(&mut panic_rng)
                .await
                .is_err(),
            "forged, wrong-bound, or non-exact terminal must be rejected"
        );
        assert_eq!(
            one_sent_codec_frame(&bad_sent),
            frozen,
            "terminal rejection retry must reuse the frozen Send"
        );
        assert_eq!(
            machine_artifacts(&store, &root, &fixture),
            before,
            "terminal rejection must not perform any further persistent mutation"
        );
        assert_machine_active(&store, &root, &fixture);
    }
}

#[tokio::test]
async fn outcome_unknown_restart_reuses_exact_send_and_only_exact_terminal_cleans_up() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xb8);

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (first_transport, first_sent) = FakeTransport::new_runtime(
        TransportScript::EofAfterSend,
        revoke_self_request(),
        committed_revocation_receipt(),
        device_sign,
    );
    let mut first_rng = DeterministicRng::new([0xc8; 32]);
    assert!(matches!(
        RemoteRuntime::new(opened, first_transport)
            .revoke_self(&mut first_rng)
            .await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    let frozen = one_sent_codec_frame(&first_sent);

    let shutdown_observed = Arc::new(AtomicBool::new(false));
    let cleanup_observer = Arc::new(AssertShutdownBeforeCleanup::new(Arc::clone(
        &shutdown_observed,
    )));
    let reopened = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &root,
        cleanup_observer.clone(),
    )
    .open_exact(fixture.identity())
    .expect("reopen pending self-revoke");
    let (terminal_transport, retry_sent) = FakeTransport::new_runtime(
        TransportScript::RevocationTerminalOnly(RevocationTerminalShape::Exact),
        revoke_self_request(),
        committed_revocation_receipt(),
        device_sign,
    );
    let terminal_transport =
        terminal_transport.with_shutdown_observer(Arc::clone(&shutdown_observed));
    let mut panic_rng = PanicRng;
    RemoteRuntime::new(reopened, terminal_transport)
        .revoke_self(&mut panic_rng)
        .await
        .expect("exact root-signed terminal commits cleanup");

    assert_eq!(
        one_sent_codec_frame(&retry_sent),
        frozen,
        "outcome-unknown restart must reuse exact requestRoute/counter/ciphertext/proof bytes"
    );
    assert!(shutdown_observed.load(Ordering::SeqCst));
    assert!(
        cleanup_observer.cleanup_stages.load(Ordering::SeqCst) > 0,
        "successful self-revoke must execute observed cleanup stages"
    );
    assert_cleanup_complete(&store, &root, &fixture);
}

#[tokio::test]
async fn revoke_self_failure_replies_are_durable_terminals_without_cleanup() {
    for (index, reply) in [
        RuntimeReply::Failure(RuntimeFailure::new(
            "daemon.revocation.rejected",
            "fixture rejects self revocation",
        )),
        RuntimeReply::Revocation(RevocationReceipt::Failed {
            failure: RuntimeFailure::new(
                "daemon.revocation.store_failed",
                "fixture revocation transaction failed",
            ),
        }),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, 0xba + index as u8);
        let expected_failure = match &reply {
            RuntimeReply::Failure(failure)
            | RuntimeReply::Revocation(RevocationReceipt::Failed { failure }) => failure.clone(),
            _ => unreachable!("failure fixture"),
        };

        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open promoted machine");
        let (transport, _sent) = FakeTransport::new_runtime(
            TransportScript::ReplyOnly,
            revoke_self_request(),
            reply,
            device_sign,
        );
        let mut rng = DeterministicRng::new([0xca + index as u8; 32]);
        assert!(matches!(
            RemoteRuntime::new(opened, transport)
                .revoke_self(&mut rng)
                .await,
            Err(RemoteRuntimeError::DaemonFailure(observed))
                if observed.code == expected_failure.code
                    && observed.message == expected_failure.message
        ));
        assert_machine_active(&store, &root, &fixture);

        let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("reopen durable failed self-revoke");
        let (unused_transport, replay_sent) = FakeTransport::new_runtime(
            TransportScript::EofAfterSend,
            revoke_self_request(),
            committed_revocation_receipt(),
            device_sign,
        );
        let mut panic_rng = PanicRng;
        assert!(matches!(
            RemoteRuntime::new(reopened, unused_transport)
                .revoke_self(&mut panic_rng)
                .await,
            Err(RemoteRuntimeError::DaemonFailure(observed))
                if observed.code == expected_failure.code
                    && observed.message == expected_failure.message
        ));
        assert!(
            replay_sent.lock().expect("sent-frame recorder").is_empty(),
            "durable self-revoke failure must replay locally without transport or entropy"
        );
        assert_machine_active(&store, &root, &fixture);
    }
}

#[tokio::test]
async fn resolve_approval_only_matching_authenticated_approval_receipt_is_terminal() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x90);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let expected_receipt = applied_approval_receipt();
    let (transport, sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        resolve_approval_request(),
        RuntimeReply::Approval(expected_receipt.clone()),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xa0; 32]);

    let outcome = runtime
        .resolve_approval(
            approval_conversation_id(),
            approval_turn_id(),
            approval_id(),
            approval_decision(),
            &mut rng,
        )
        .await
        .expect("matching authenticated ApprovalReceipt is terminal");

    assert!(!outcome.route_accepted());
    assert_eq!(outcome.receipt(), &expected_receipt);
    let _ = one_sent_codec_frame(&sent);
}

#[tokio::test]
async fn resolve_approval_route_accepted_followed_by_eof_is_not_success() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x91);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (transport, _sent) = FakeTransport::new_runtime(
        TransportScript::RouteAcceptedOnly,
        resolve_approval_request(),
        RuntimeReply::Approval(applied_approval_receipt()),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xa1; 32]);

    assert!(matches!(
        runtime
            .resolve_approval(
                approval_conversation_id(),
                approval_turn_id(),
                approval_id(),
                approval_decision(),
                &mut rng,
            )
            .await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
}

#[tokio::test]
async fn resolve_approval_restarts_with_the_exact_frozen_relay_frame() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x92);

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (first_transport, first_sent) = FakeTransport::new_runtime(
        TransportScript::EofAfterSend,
        resolve_approval_request(),
        RuntimeReply::Approval(applied_approval_receipt()),
        device_sign,
    );
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_rng = DeterministicRng::new([0xa2; 32]);
    assert!(matches!(
        first_runtime
            .resolve_approval(
                approval_conversation_id(),
                approval_turn_id(),
                approval_id(),
                approval_decision(),
                &mut first_rng,
            )
            .await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    let first_codec_frame = one_sent_codec_frame(&first_sent);
    drop(first_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen pending approval after unknown outcome");
    let expected_receipt = applied_approval_receipt();
    let (retry_transport, retry_sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        resolve_approval_request(),
        RuntimeReply::Approval(expected_receipt.clone()),
        device_sign,
    );
    let mut retry_runtime = RemoteRuntime::new(reopened, retry_transport);
    let mut retry_rng = PanicRng;
    let outcome = retry_runtime
        .resolve_approval(
            approval_conversation_id(),
            approval_turn_id(),
            approval_id(),
            approval_decision(),
            &mut retry_rng,
        )
        .await
        .expect("exact approval retry may finish from an authenticated receipt");

    assert_eq!(outcome.receipt(), &expected_receipt);
    assert_eq!(
        one_sent_codec_frame(&retry_sent),
        first_codec_frame,
        "restart must reuse the exact approval Relay frame, including requestRoute/counter/ciphertext/proof"
    );
}

#[tokio::test]
async fn retry_approval_after_terminal_resolve_starts_a_distinct_authenticated_exchange() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x93);
    let expected_receipt = applied_approval_receipt();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (resolve_transport, resolve_sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        resolve_approval_request(),
        RuntimeReply::Approval(expected_receipt.clone()),
        device_sign,
    );
    let mut resolve_runtime = RemoteRuntime::new(opened, resolve_transport);
    let mut resolve_rng = DeterministicRng::new([0xa3; 32]);
    resolve_runtime
        .resolve_approval(
            approval_conversation_id(),
            approval_turn_id(),
            approval_id(),
            approval_decision(),
            &mut resolve_rng,
        )
        .await
        .expect("resolve approval terminal");
    let resolve_frame = one_sent_codec_frame(&resolve_sent);
    drop(resolve_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after terminal resolve");
    let (retry_transport, retry_sent) = FakeTransport::new_runtime_with_counters(
        TransportScript::ReplyOnly,
        retry_approval_request(),
        RuntimeReply::Approval(expected_receipt.clone()),
        device_sign,
        1_024,
        REPLY_COUNTER + 1,
    );
    let mut retry_runtime = RemoteRuntime::new(reopened, retry_transport);
    let mut retry_rng = DeterministicRng::new([0xa4; 32]);
    let retry_outcome = retry_runtime
        .retry_approval(approval_conversation_id(), approval_id(), &mut retry_rng)
        .await
        .expect("RetryApproval is a distinct authenticated request intent");
    let retry_frame = one_sent_codec_frame(&retry_sent);

    assert_eq!(retry_outcome.receipt(), &expected_receipt);
    assert_ne!(
        retry_frame, resolve_frame,
        "RetryApproval must not replay a terminal ResolveApproval exchange for the same approval"
    );
}

#[tokio::test]
async fn retry_approval_terminal_starts_a_new_attempt_while_pending_restart_is_exact() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x9a);

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let first_receipt = delivery_failed_approval_receipt();
    let (first_transport, first_sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        retry_approval_request(),
        RuntimeReply::Approval(first_receipt.clone()),
        device_sign,
    );
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_rng = DeterministicRng::new([0xaa; 32]);
    let first = first_runtime
        .retry_approval(approval_conversation_id(), approval_id(), &mut first_rng)
        .await
        .expect("first retry attempt reaches authenticated terminal");
    assert_eq!(first.receipt(), &first_receipt);
    let first_frame = one_sent_codec_frame(&first_sent);
    drop(first_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen first retry terminal");
    let (second_transport, second_sent) = FakeTransport::new_runtime_with_counters(
        TransportScript::EofAfterSend,
        retry_approval_request(),
        RuntimeReply::Approval(applied_approval_receipt()),
        device_sign,
        1_024,
        REPLY_COUNTER + 1,
    );
    let mut second_runtime = RemoteRuntime::new(reopened, second_transport);
    let mut second_rng = DeterministicRng::new([0xab; 32]);
    assert!(matches!(
        second_runtime
            .retry_approval(approval_conversation_id(), approval_id(), &mut second_rng,)
            .await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    let second_frame = one_sent_codec_frame(&second_sent);
    assert_ne!(
        second_frame, first_frame,
        "a user retry after terminal must start a new durable business attempt"
    );
    drop(second_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen outcome-unknown second retry attempt");
    let expected_receipt = applied_approval_receipt();
    let (resume_transport, resume_sent) = FakeTransport::new_runtime_with_counters(
        TransportScript::ReplyOnly,
        retry_approval_request(),
        RuntimeReply::Approval(expected_receipt.clone()),
        device_sign,
        1_024,
        REPLY_COUNTER + 1,
    );
    let mut resumed = RemoteRuntime::new(reopened, resume_transport);
    let mut panic_rng = PanicRng;
    let outcome = resumed
        .retry_approval(approval_conversation_id(), approval_id(), &mut panic_rng)
        .await
        .expect("pending retry attempt resumes from the exact frozen frame");
    assert_eq!(outcome.receipt(), &expected_receipt);
    assert_eq!(
        one_sent_codec_frame(&resume_sent),
        second_frame,
        "crash restart within one retry attempt must not reseal or consume caller entropy"
    );
}

#[tokio::test]
async fn retry_approval_rejects_authenticated_claimed_without_making_it_terminal() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x9b);

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (claimed_transport, _sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        retry_approval_request(),
        RuntimeReply::Approval(ApprovalReceipt::Claimed {
            approval_id: approval_id(),
        }),
        device_sign,
    );
    let mut claimed_runtime = RemoteRuntime::new(opened, claimed_transport);
    let mut first_rng = DeterministicRng::new([0xac; 32]);
    assert!(matches!(
        claimed_runtime
            .retry_approval(approval_conversation_id(), approval_id(), &mut first_rng,)
            .await,
        Err(RemoteRuntimeError::InvalidReply(_))
    ));
    drop(claimed_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen pending retry after impossible Claimed receipt");
    let expected_receipt = applied_approval_receipt();
    let (valid_transport, _sent) = FakeTransport::new_runtime_with_reply_counter(
        TransportScript::ReplyOnly,
        retry_approval_request(),
        RuntimeReply::Approval(expected_receipt.clone()),
        device_sign,
        REPLY_COUNTER + 1,
    );
    let mut valid_runtime = RemoteRuntime::new(reopened, valid_transport);
    let mut panic_rng = PanicRng;
    let outcome = valid_runtime
        .retry_approval(approval_conversation_id(), approval_id(), &mut panic_rng)
        .await
        .expect("later valid RetryApproval receipt completes the original pending attempt");
    assert_eq!(outcome.receipt(), &expected_receipt);
}

#[tokio::test]
async fn resolve_approval_wrong_reply_kind_message_id_or_approval_id_is_not_terminal() {
    for (index, script, wrong_reply) in [
        (
            0_u8,
            TransportScript::ReplyOnly,
            RuntimeReply::Command(accepted_receipt()),
        ),
        (
            1,
            TransportScript::ReplyOnlyWithShape(ReplyShape::WrongMessageId),
            RuntimeReply::Approval(applied_approval_receipt()),
        ),
        (
            2,
            TransportScript::ReplyOnly,
            RuntimeReply::Approval(ApprovalReceipt::Applied {
                approval_id: ApprovalId::new("approval-wrong-runtime-2"),
            }),
        ),
    ] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, 0x94 + index);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open promoted machine");
        let (bad_transport, _sent) = FakeTransport::new_runtime_with_reply_counter(
            script,
            resolve_approval_request(),
            wrong_reply,
            device_sign,
            REPLY_COUNTER,
        );
        let mut bad_runtime = RemoteRuntime::new(opened, bad_transport);
        let mut first_rng = DeterministicRng::new([0xa5 + index; 32]);

        assert!(
            bad_runtime
                .resolve_approval(
                    approval_conversation_id(),
                    approval_turn_id(),
                    approval_id(),
                    approval_decision(),
                    &mut first_rng,
                )
                .await
                .is_err(),
            "wrong authenticated approval reply axis {index} must not become terminal"
        );
        drop(bad_runtime);

        let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("reopen non-terminal approval exchange");
        let expected_receipt = applied_approval_receipt();
        let (valid_transport, _sent) = FakeTransport::new_runtime_with_reply_counter(
            TransportScript::ReplyOnly,
            resolve_approval_request(),
            RuntimeReply::Approval(expected_receipt.clone()),
            device_sign,
            REPLY_COUNTER + 1,
        );
        let mut valid_runtime = RemoteRuntime::new(reopened, valid_transport);
        let mut retry_rng = PanicRng;
        let outcome = valid_runtime
            .resolve_approval(
                approval_conversation_id(),
                approval_turn_id(),
                approval_id(),
                approval_decision(),
                &mut retry_rng,
            )
            .await
            .expect("later correctly correlated ApprovalReceipt remains terminal");
        assert_eq!(outcome.receipt(), &expected_receipt);
    }
}

#[tokio::test]
async fn prompt_uses_real_send_and_accepts_authenticated_reply_without_route_accepted() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x41);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let request = prompt_request();
    let (transport, sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0x51; 32]);

    let outcome = runtime
        .prompt(request, &mut rng)
        .await
        .expect("authenticated daemon receipt is terminal");

    assert_accepted_outcome(&outcome, false);
    let _ = one_sent_codec_frame(&sent);
}

#[tokio::test]
async fn reply_before_route_accepted_is_terminal_but_does_not_claim_transport_acceptance() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x42);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let request = prompt_request();
    let (transport, _sent) = FakeTransport::new(
        TransportScript::ReplyThenRouteAccepted,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0x52; 32]);

    let outcome = runtime
        .prompt(request, &mut rng)
        .await
        .expect("Reply may race ahead of RouteAccepted");

    assert_accepted_outcome(&outcome, false);
}

#[tokio::test]
async fn route_accepted_followed_by_eof_never_becomes_command_success() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x43);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let request = prompt_request();
    let (transport, _sent) = FakeTransport::new(
        TransportScript::RouteAcceptedOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0x53; 32]);

    assert_not_terminal(runtime.prompt(request, &mut rng).await);
}

#[tokio::test]
async fn route_accepted_is_only_reported_after_a_later_authenticated_daemon_receipt() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x48);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let request = prompt_request();
    let (transport, _sent) = FakeTransport::new(
        TransportScript::RouteAcceptedThenReply,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0x58; 32]);

    let outcome = runtime
        .prompt(request, &mut rng)
        .await
        .expect("RouteAccepted is nonterminal and a later daemon receipt completes the prompt");

    assert_accepted_outcome(&outcome, true);
}

#[tokio::test]
async fn authenticated_receipt_with_wrong_configuration_revision_never_becomes_terminal() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x48);
    let request = prompt_request();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (wrong_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt_at_revision(10),
        device_sign,
    );
    let mut wrong_runtime = RemoteRuntime::new(opened, wrong_transport);
    let mut first_rng = DeterministicRng::new([0x58; 32]);
    assert_not_terminal(wrong_runtime.prompt(request.clone(), &mut first_rng).await);
    drop(wrong_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen non-terminal prompt after wrong receipt revision");
    let (retry_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt_at_revision(10),
        device_sign,
    );
    let mut retry_runtime = RemoteRuntime::new(reopened, retry_transport);
    let mut retry_rng = PanicRng;
    assert_not_terminal(retry_runtime.prompt(request, &mut retry_rng).await);
}

#[tokio::test]
async fn unknown_send_outcome_reopens_and_resends_the_exact_codec_frame_for_the_same_intent() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x44);
    let request = prompt_request();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (first_transport, first_sent) = FakeTransport::new(
        TransportScript::EofAfterSend,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_rng = DeterministicRng::new([0x54; 32]);
    assert_not_terminal(first_runtime.prompt(request.clone(), &mut first_rng).await);
    let first_codec_frame = one_sent_codec_frame(&first_sent);
    drop(first_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen pending prompt after outcome-unknown");
    let (retry_transport, retry_sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut retry_runtime = RemoteRuntime::new(reopened, retry_transport);
    let mut retry_rng = PanicRng;
    let outcome = retry_runtime
        .prompt(request, &mut retry_rng)
        .await
        .expect("exact retry may finish from authenticated receipt");

    assert_accepted_outcome(&outcome, false);
    assert_eq!(
        one_sent_codec_frame(&retry_sent),
        first_codec_frame,
        "restart must reuse the exact Relay codec frame, including requestRoute/counter/ciphertext/proof"
    );
}

#[tokio::test]
async fn terminal_same_intent_returns_locally_without_transport_or_caller_rng() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x59);
    let request = prompt_request();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (first_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_rng = DeterministicRng::new([0x69; 32]);
    let first = first_runtime
        .prompt(request.clone(), &mut first_rng)
        .await
        .expect("first authenticated terminal");
    assert_accepted_outcome(&first, false);
    drop(first_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen terminal prompt");
    let (unused_transport, sent) = FakeTransport::new(
        TransportScript::EofAfterSend,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut replay = RemoteRuntime::new(reopened, unused_transport);
    let mut panic_rng = PanicRng;
    let local = replay
        .prompt(request, &mut panic_rng)
        .await
        .expect("terminal replay is a local read");

    assert_accepted_outcome(&local, false);
    assert!(sent.lock().expect("sent-frame recorder").is_empty());
}

#[tokio::test]
async fn pending_different_intent_is_typed_conflict_without_transport_or_caller_rng() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x5a);
    let request = prompt_request();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (first_transport, _sent) = FakeTransport::new(
        TransportScript::EofAfterSend,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_rng = DeterministicRng::new([0x6a; 32]);
    assert!(matches!(
        first_runtime.prompt(request, &mut first_rng).await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    drop(first_runtime);

    let mut conflicting = prompt_request();
    conflicting.idempotency_key = IdempotencyKey::new("prompt-intent-conflict-2");
    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen pending prompt");
    let (unused_transport, sent) = FakeTransport::new(
        TransportScript::EofAfterSend,
        conflicting.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(reopened, unused_transport);
    let mut panic_rng = PanicRng;
    assert!(matches!(
        runtime.prompt(conflicting, &mut panic_rng).await,
        Err(RemoteRuntimeError::PendingIntentConflict)
    ));
    assert!(sent.lock().expect("sent-frame recorder").is_empty());
}

#[tokio::test]
async fn failed_daemon_receipt_is_durable_terminal_and_replays_locally() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x5b);
    let request = prompt_request();
    let failure = failed_receipt();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (first_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        failure.clone(),
        device_sign,
    );
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_rng = DeterministicRng::new([0x6b; 32]);
    let first = first_runtime
        .prompt(request.clone(), &mut first_rng)
        .await
        .expect("authenticated failure is a terminal daemon receipt");
    assert_eq!(first.receipt(), &failure);
    drop(first_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen failed terminal");
    let (unused_transport, sent) = FakeTransport::new(
        TransportScript::EofAfterSend,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut replay = RemoteRuntime::new(reopened, unused_transport);
    let mut panic_rng = PanicRng;
    let local = replay
        .prompt(request, &mut panic_rng)
        .await
        .expect("failed terminal is read locally after restart");
    assert_eq!(local.receipt(), &failure);
    assert!(sent.lock().expect("sent-frame recorder").is_empty());
}

#[tokio::test]
async fn authenticated_runtime_failure_is_typed_durable_and_does_not_block_a_new_intent() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x5c);
    let request = prompt_request();
    let failure = RuntimeFailure::new(
        "daemon.remote.fixture_rejected",
        "fixture rejects the authenticated request",
    );

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (first_transport, _sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        RuntimeRequest::SendPrompt(request.clone()),
        RuntimeReply::Failure(failure.clone()),
        device_sign,
    );
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_rng = DeterministicRng::new([0x6c; 32]);
    assert!(matches!(
        first_runtime.prompt(request.clone(), &mut first_rng).await,
        Err(RemoteRuntimeError::DaemonFailure(observed))
            if observed.code == failure.code && observed.message == failure.message
    ));
    drop(first_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen authenticated daemon failure terminal");
    let (unused_transport, replay_sent) = FakeTransport::new_runtime(
        TransportScript::EofAfterSend,
        RuntimeRequest::SendPrompt(request.clone()),
        RuntimeReply::Command(accepted_receipt()),
        device_sign,
    );
    let mut replay_runtime = RemoteRuntime::new(reopened, unused_transport);
    let mut panic_rng = PanicRng;
    assert!(matches!(
        replay_runtime.prompt(request.clone(), &mut panic_rng).await,
        Err(RemoteRuntimeError::DaemonFailure(observed))
            if observed.code == failure.code && observed.message == failure.message
    ));
    assert!(
        replay_sent.lock().expect("sent-frame recorder").is_empty(),
        "same failed intent must replay locally without transport or caller entropy"
    );
    drop(replay_runtime);

    let mut different = request;
    different.idempotency_key = IdempotencyKey::new("prompt-after-daemon-failure");
    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen before different prompt intent");
    let (different_transport, different_sent) = FakeTransport::new_runtime_with_counters(
        TransportScript::ReplyOnly,
        RuntimeRequest::SendPrompt(different.clone()),
        RuntimeReply::Command(accepted_receipt()),
        device_sign,
        1_024,
        REPLY_COUNTER + 1,
    );
    let mut different_runtime = RemoteRuntime::new(reopened, different_transport);
    let mut different_rng = DeterministicRng::new([0x6d; 32]);
    let outcome = different_runtime
        .prompt(different, &mut different_rng)
        .await
        .expect("a different intent can replace the failed terminal");
    assert_accepted_outcome(&outcome, false);
    let _ = one_sent_codec_frame(&different_sent);
}

#[tokio::test]
async fn forged_machine_data_signature_is_not_terminal_and_does_not_poison_reply_replay() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x45);
    let request = prompt_request();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (forged_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnlyWithShape(ReplyShape::ForgedMachineDataSignature),
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut forged_runtime = RemoteRuntime::new(opened, forged_transport);
    let mut first_rng = DeterministicRng::new([0x55; 32]);
    assert_not_terminal(forged_runtime.prompt(request.clone(), &mut first_rng).await);
    drop(forged_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after forged reply");
    let (valid_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut valid_runtime = RemoteRuntime::new(reopened, valid_transport);
    let mut retry_rng = PanicRng;
    let outcome = valid_runtime
        .prompt(request, &mut retry_rng)
        .await
        .expect("forged signature must not consume the authenticated replay tuple");
    assert_accepted_outcome(&outcome, false);
}

#[tokio::test]
async fn every_reply_header_aad_payload_and_message_axis_fails_closed() {
    for (index, shape) in [
        ReplyShape::WrongMessageId,
        ReplyShape::WrongPayloadKind,
        ReplyShape::WrongKeyPurpose,
        ReplyShape::WrongKeyEpoch,
        ReplyShape::WrongDirectoryRevision,
        ReplyShape::WrongNoncePrefix,
        ReplyShape::WrongAad,
        ReplyShape::NonCanonicalJson,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, 0x70 + index as u8);
        let request = prompt_request();
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open promoted machine");
        let (transport, _sent) = FakeTransport::new(
            TransportScript::ReplyOnlyWithShape(shape),
            request.clone(),
            accepted_receipt(),
            device_sign,
        );
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut rng = DeterministicRng::new([0x80 + index as u8; 32]);

        assert!(
            runtime.prompt(request, &mut rng).await.is_err(),
            "invalid reply shape {shape:?} must not become terminal"
        );
    }
}

#[tokio::test]
async fn wrong_request_route_is_not_terminal_and_does_not_consume_the_correlated_reply() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x46);
    let request = prompt_request();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (wrong_route_transport, _sent) = FakeTransport::new(
        TransportScript::WrongRequestRouteOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut wrong_route_runtime = RemoteRuntime::new(opened, wrong_route_transport);
    let mut first_rng = DeterministicRng::new([0x56; 32]);
    assert_not_terminal(
        wrong_route_runtime
            .prompt(request.clone(), &mut first_rng)
            .await,
    );
    drop(wrong_route_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after uncorrelated reply");
    let (valid_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut valid_runtime = RemoteRuntime::new(reopened, valid_transport);
    let mut retry_rng = PanicRng;
    let outcome = valid_runtime
        .prompt(request, &mut retry_rng)
        .await
        .expect("wrong route must not consume the correct reply tuple");
    assert_accepted_outcome(&outcome, false);
}

#[tokio::test]
async fn same_reply_counter_with_different_signed_ciphertext_stays_non_terminal_after_restart() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0x47);
    let request = prompt_request();

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (bad_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnlyWithShape(ReplyShape::AuthenticatedBadCiphertext),
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut bad_runtime = RemoteRuntime::new(opened, bad_transport);
    let mut first_rng = DeterministicRng::new([0x57; 32]);
    assert_not_terminal(bad_runtime.prompt(request.clone(), &mut first_rng).await);
    drop(bad_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after authenticated bad ciphertext");
    let (different_ciphertext_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut retry_runtime = RemoteRuntime::new(reopened, different_ciphertext_transport);
    let mut retry_rng = PanicRng;

    assert_not_terminal(retry_runtime.prompt(request, &mut retry_rng).await);
    drop(retry_runtime);

    let quarantined = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen durable nonce-reuse quarantine");
    let (higher_counter_transport, sent) = FakeTransport::new_with_reply_counter(
        TransportScript::ReplyOnly,
        prompt_request(),
        accepted_receipt(),
        device_sign,
        REPLY_COUNTER + 1,
    );
    let mut quarantined_runtime = RemoteRuntime::new(quarantined, higher_counter_transport);
    let mut quarantined_rng = PanicRng;
    assert!(matches!(
        quarantined_runtime
            .prompt(prompt_request(), &mut quarantined_rng)
            .await,
        Err(RemoteRuntimeError::ReplayRejected)
    ));
    assert!(
        sent.lock().expect("sent-frame recorder").is_empty(),
        "durably quarantined reply scope must isolate before another command send"
    );
}

#[test]
fn crash_after_replay_admission_before_aead_open_recovers_exact_reply() {
    let fixture = PairingFixture::new();
    let store = Arc::new(MemoryRemoteKeyStore::new());
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(store.as_ref(), &root, 0x5c);
    let request = prompt_request();

    let crashed_store = Arc::clone(&store);
    let crashed_root = root.clone();
    let crashed_request = request.clone();
    let crashed = std::thread::spawn(move || {
        let observer = Arc::new(PanicOnNthStateActive::new(2));
        let opened = PairedMachineStore::new_with_mutation_observer(
            crashed_store.as_ref(),
            INSTALLATION_ID,
            &crashed_root,
            observer,
        )
        .open_exact(PairingFixture::new().identity())
        .expect("open promoted machine with crash observer");
        let (transport, _sent) = FakeTransport::new(
            TransportScript::ReplyOnly,
            crashed_request.clone(),
            accepted_receipt(),
            device_sign,
        );
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut rng = DeterministicRng::new([0x6c; 32]);
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("single-thread test Runtime");
        let _ = executor.block_on(runtime.prompt(crashed_request, &mut rng));
    })
    .join();
    assert!(crashed.is_err(), "observer must simulate process death");

    let reopened = PairedMachineStore::new(store.as_ref(), INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("recover replay-admitted runtime state");
    let (retry_transport, _sent) = FakeTransport::new(
        TransportScript::ReplyOnly,
        request.clone(),
        accepted_receipt(),
        device_sign,
    );
    let mut retry_runtime = RemoteRuntime::new(reopened, retry_transport);
    let mut panic_rng = PanicRng;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("single-thread retry Runtime");
    let outcome = executor
        .block_on(retry_runtime.prompt(request, &mut panic_rng))
        .expect("exact authenticated reply completes after replay-state recovery");
    assert_accepted_outcome(&outcome, false);
}

#[tokio::test]
async fn catalog_page_seals_exact_cursor_request_and_only_reports_authenticated_snapshot() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xc0);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let page_cursor = catalog_page_cursor();
    let snapshot = catalog_snapshot_with_current(Some(page_cursor.clone()));
    let (transport, sent) = FakeTransport::new_runtime(
        TransportScript::RouteAcceptedThenReply,
        catalog_request(Some(page_cursor.clone())),
        RuntimeReply::Catalog(snapshot.clone()),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xc1; 32]);

    let outcome = runtime
        .catalog_page(Some(page_cursor), &mut rng)
        .await
        .expect("authenticated CatalogSnapshot is terminal");

    assert_catalog_outcome(&outcome, true, &snapshot);
    let _ = one_sent_codec_frame(&sent);
}

#[tokio::test]
async fn catalog_rejects_a_page_that_does_not_echo_the_requested_cursor_direct_or_compact() {
    for (seed, compact) in [(0xb0, false), (0xb2, true)] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("mismatched Catalog cursor state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open mismatched Catalog cursor machine");
        let requested = catalog_page_cursor();
        let mismatched = catalog_snapshot_with_current(None);
        let (transport, sent) = if compact {
            FakeTransport::new_runtime_sequence(
                catalog_request(Some(requested.clone())),
                catalog_transfer_replies(&mismatched),
                device_sign,
            )
        } else {
            FakeTransport::new_runtime(
                TransportScript::ReplyOnly,
                catalog_request(Some(requested.clone())),
                RuntimeReply::Catalog(mismatched),
                device_sign,
            )
        };
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);

        assert!(matches!(
            runtime.catalog_page(Some(requested), &mut rng).await,
            Err(RemoteRuntimeError::InvalidReply(_))
        ));
        let _ = one_sent_codec_frame(&sent);
    }
}

#[tokio::test]
async fn catalog_route_accepted_only_restarts_with_the_exact_frozen_send() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xc2);
    let page_cursor = catalog_page_cursor();
    let snapshot = catalog_snapshot_with_current(Some(page_cursor.clone()));

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (first_transport, first_sent) = FakeTransport::new_runtime(
        TransportScript::RouteAcceptedOnly,
        catalog_request(Some(page_cursor.clone())),
        RuntimeReply::Catalog(snapshot.clone()),
        device_sign,
    );
    let mut first_runtime = RemoteRuntime::new(opened, first_transport);
    let mut first_rng = DeterministicRng::new([0xc3; 32]);
    assert!(matches!(
        first_runtime
            .catalog_page(Some(page_cursor.clone()), &mut first_rng)
            .await,
        Err(RemoteRuntimeError::OutcomeUnknown)
    ));
    let first_frame = one_sent_codec_frame(&first_sent);
    drop(first_runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen pending catalog request");
    let (retry_transport, retry_sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        catalog_request(Some(page_cursor.clone())),
        RuntimeReply::Catalog(snapshot.clone()),
        device_sign,
    );
    let mut retry_runtime = RemoteRuntime::new(reopened, retry_transport);
    let mut retry_rng = PanicRng;
    let outcome = retry_runtime
        .catalog_page(Some(page_cursor), &mut retry_rng)
        .await
        .expect("exact catalog retry may finish from authenticated snapshot");

    assert_catalog_outcome(&outcome, false, &snapshot);
    assert_eq!(one_sent_codec_frame(&retry_sent), first_frame);
}

#[tokio::test]
async fn catalog_authenticated_daemon_failure_is_never_snapshot_success() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xc4);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let failure = RuntimeFailure::new(
        "daemon.catalog.fixture_rejected",
        "fixture rejects the catalog request",
    );
    let (transport, _sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnly,
        catalog_request(None),
        RuntimeReply::Failure(failure.clone()),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xc5; 32]);

    assert!(matches!(
        runtime.catalog_page(None, &mut rng).await,
        Err(RemoteRuntimeError::DaemonFailure(observed))
            if observed.code == failure.code && observed.message == failure.message
    ));
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after consumed catalog failure");
    let snapshot = catalog_snapshot();
    let (retry_transport, retry_sent) = FakeTransport::new_runtime_with_counters(
        TransportScript::ReplyOnly,
        catalog_request(None),
        RuntimeReply::Catalog(snapshot.clone()),
        device_sign,
        COUNTER_BLOCK_SIZE,
        REPLY_COUNTER + 1,
    );
    let mut retry = RemoteRuntime::new(reopened, retry_transport);
    let mut retry_rng = DeterministicRng::new([0xd5; 32]);
    let outcome = retry
        .catalog_page(None, &mut retry_rng)
        .await
        .expect("a transient authenticated failure cannot pin future catalog reads");
    assert_catalog_outcome(&outcome, false, &snapshot);
    let _ = one_sent_codec_frame(&retry_sent);
}

#[test]
fn catalog_terminal_replays_after_crash_once_then_the_next_read_is_fresh() {
    let fixture = PairingFixture::new();
    let store = Arc::new(MemoryRemoteKeyStore::new());
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(store.as_ref(), &root, 0xc6);
    let snapshot = catalog_snapshot();

    let crashed_store = Arc::clone(&store);
    let crashed_root = root.clone();
    let crashed_snapshot = snapshot.clone();
    let crashed = std::thread::spawn(move || {
        let observer = Arc::new(PanicOnNthStateActive::new(3));
        let opened = PairedMachineStore::new_with_mutation_observer(
            crashed_store.as_ref(),
            INSTALLATION_ID,
            &crashed_root,
            observer,
        )
        .open_exact(PairingFixture::new().identity())
        .expect("open promoted machine with terminal crash observer");
        let (transport, _sent) = FakeTransport::new_runtime(
            TransportScript::ReplyOnly,
            catalog_request(None),
            RuntimeReply::Catalog(crashed_snapshot),
            device_sign,
        );
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut rng = DeterministicRng::new([0xc7; 32]);
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("single-thread test Runtime");
        let _ = executor.block_on(runtime.catalog_page(None, &mut rng));
    })
    .join();
    assert!(
        crashed.is_err(),
        "observer must stop after durable terminal and before consumption"
    );

    let reopened = PairedMachineStore::new(store.as_ref(), INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen crash-durable catalog terminal");
    let (unused_transport, sent) = FakeTransport::new_runtime(
        TransportScript::EofAfterSend,
        catalog_request(None),
        RuntimeReply::Catalog(catalog_snapshot()),
        device_sign,
    );
    let mut replay = RemoteRuntime::new(reopened, unused_transport);
    let mut panic_rng = PanicRng;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("single-thread replay Runtime");
    let local = executor
        .block_on(replay.catalog_page(None, &mut panic_rng))
        .expect("durable catalog terminal is a local read");

    assert_catalog_outcome(&local, false, &snapshot);
    assert!(sent.lock().expect("sent-frame recorder").is_empty());
    drop(replay);

    let reopened = PairedMachineStore::new(store.as_ref(), INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after catalog terminal consumption");
    let newer = newer_catalog_snapshot();
    let (fresh_transport, fresh_sent) = FakeTransport::new_runtime_with_counters(
        TransportScript::ReplyOnly,
        catalog_request(None),
        RuntimeReply::Catalog(newer.clone()),
        device_sign,
        COUNTER_BLOCK_SIZE,
        REPLY_COUNTER + 1,
    );
    let mut fresh = RemoteRuntime::new(reopened, fresh_transport);
    let mut fresh_rng = DeterministicRng::new([0xd7; 32]);
    let fresh_outcome = executor
        .block_on(fresh.catalog_page(None, &mut fresh_rng))
        .expect("the next invocation must query a fresh catalog page");
    assert_catalog_outcome(&fresh_outcome, false, &newer);
    let _ = one_sent_codec_frame(&fresh_sent);
}

#[tokio::test]
async fn catalog_requires_catalog_snapshot_payload_kind() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xc8);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let (transport, _sent) = FakeTransport::new_runtime(
        TransportScript::ReplyOnlyWithShape(ReplyShape::WrongPayloadKind),
        catalog_request(None),
        RuntimeReply::Catalog(catalog_snapshot()),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xc9; 32]);

    assert!(matches!(
        runtime.catalog_page(None, &mut rng).await,
        Err(RemoteRuntimeError::InvalidReply(_))
    ));
}

#[tokio::test]
async fn catalog_compact_transfer_reassembles_before_persisting_the_terminal_snapshot() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xca);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted machine");
    let expected = catalog_snapshot();
    let (transport, _sent) = FakeTransport::new_runtime_sequence(
        catalog_request(None),
        catalog_transfer_replies(&expected),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xcb; 32]);

    let outcome = runtime
        .catalog_page(None, &mut rng)
        .await
        .expect("two authenticated ADRT1 parts must produce one Catalog terminal");
    assert_catalog_outcome(&outcome, false, &expected);
}

#[tokio::test]
async fn large_compact_catalog_returns_without_leaving_an_undecodable_durable_terminal() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("large compact Catalog state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xb4);
    let mut entry = catalog_snapshot().entries()[0].clone();
    entry.title = Some("x".repeat(MAX_RUNTIME_JSON_FRAME_BYTES + 16 * 1024));
    let expected = CatalogSnapshot::new(StreamCursor::At(17), vec![entry], None, None)
        .expect("valid Catalog page larger than the durable terminal bound");
    assert!(serde_json::to_vec(&expected).unwrap().len() > MAX_RUNTIME_JSON_FRAME_BYTES);

    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open large compact Catalog machine");
    let (transport, _sent) = FakeTransport::new_runtime_sequence(
        catalog_request(None),
        catalog_transfer_replies(&expected),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xb5; 32]);
    let outcome = runtime.catalog_page(None, &mut rng).await.expect(
        "large read-only Catalog page clears exact pending instead of persisting plaintext",
    );
    assert_catalog_outcome(&outcome, false, &expected);
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("large Catalog completion leaves a decodable paired state");
    let fresh_snapshot = newer_catalog_snapshot();
    let (fresh_transport, fresh_sent) = FakeTransport::new_runtime_with_counters(
        TransportScript::ReplyOnly,
        catalog_request(None),
        RuntimeReply::Catalog(fresh_snapshot.clone()),
        device_sign,
        COUNTER_BLOCK_SIZE,
        REPLY_COUNTER + 2,
    );
    let mut fresh = RemoteRuntime::new(reopened, fresh_transport);
    let mut fresh_rng = DeterministicRng::new([0xb6; 32]);
    let fresh_outcome = fresh
        .catalog_page(None, &mut fresh_rng)
        .await
        .expect("the next Catalog call creates a fresh request");
    assert_catalog_outcome(&fresh_outcome, false, &fresh_snapshot);
    let _ = one_sent_codec_frame(&fresh_sent);
}

#[tokio::test]
async fn catalog_compact_transfer_rejects_noncanonical_snapshot_json() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("noncanonical compact Catalog state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xb7);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open noncanonical compact Catalog machine");
    let mut payload = serde_json::to_vec(&catalog_snapshot()).expect("canonical Catalog payload");
    payload.insert(1, b' ');
    let (transport, _sent) = FakeTransport::new_runtime_sequence(
        catalog_request(None),
        transfer_replies(payload, "noncanonical-catalog-transfer"),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xb8; 32]);

    assert!(matches!(
        runtime.catalog_page(None, &mut rng).await,
        Err(RemoteRuntimeError::InvalidReply(_))
    ));
}

#[tokio::test]
async fn catalog_compact_transfer_rejects_wrong_message_or_stream_channel() {
    for (seed, shape) in [
        (0xcc, ReplyShape::WrongMessageId),
        (0xcd, ReplyShape::WrongTransferChannel),
    ] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open promoted machine");
        let mut replies = catalog_transfer_replies(&catalog_snapshot());
        let first = replies.remove(0);
        let (transport, _sent) = FakeTransport::new_runtime(
            TransportScript::ReplyOnlyWithShape(shape),
            catalog_request(None),
            first,
            device_sign,
        );
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut rng = DeterministicRng::new([seed; 32]);

        assert!(matches!(
            runtime.catalog_page(None, &mut rng).await,
            Err(RemoteRuntimeError::InvalidReply(_))
        ));
    }
}

fn decoded_outbound_frames(recorder: &Arc<Mutex<Vec<Vec<u8>>>>) -> Vec<OpaqueRouteFrame> {
    recorder
        .lock()
        .expect("sent-frame recorder")
        .iter()
        .map(|bytes| decode(bytes).expect("recorded outbound frame is canonical"))
        .collect()
}

fn assert_binding_controls(
    recorder: &Arc<Mutex<Vec<Vec<u8>>>>,
    expected_binding: &StreamBindingV1,
    request_send_prefix: bool,
    expected_ack: Option<u64>,
) {
    let frames = decoded_outbound_frames(recorder);
    let control_offset = usize::from(request_send_prefix);
    if request_send_prefix {
        assert!(
            matches!(frames[0].body, RelayFrameBody::Send(_)),
            "bootstrap must begin with exactly one directed Runtime Send"
        );
    }
    let expected_len = control_offset + 1 + usize::from(expected_ack.is_some());
    assert_eq!(
        frames.len(),
        expected_len,
        "only binding-derived Subscribe and optional Ack may follow the Runtime Send"
    );
    assert!(matches!(
        &frames[control_offset].body,
        RelayFrameBody::Subscribe(Subscribe {
            stream_route,
            generation,
            cursor,
        }) if *stream_route == expected_binding.stream_route
            && *generation == expected_binding.stream_generation
            && *cursor == expected_binding.stream_cursor
    ));
    match expected_ack {
        Some(up_to_seq) => assert!(matches!(
            &frames[control_offset + 1].body,
            RelayFrameBody::Ack(Ack {
                stream_route,
                generation,
                up_to_seq: actual,
            }) if *stream_route == expected_binding.stream_route
                && *generation == expected_binding.stream_generation
                && *actual == up_to_seq
        )),
        None => assert!(
            frames
                .iter()
                .all(|frame| !matches!(frame.body, RelayFrameBody::Ack(_))),
            "BeforeFirst has no committed outer sequence to acknowledge"
        ),
    }
}

fn assert_only_runtime_subscribe_send(recorder: &Arc<Mutex<Vec<Vec<u8>>>>) {
    let frames = decoded_outbound_frames(recorder);
    assert_eq!(
        frames.len(),
        1,
        "rejected bootstrap must emit zero Relay subscription controls"
    );
    assert!(matches!(frames[0].body, RelayFrameBody::Send(_)));
}

fn assert_durable_stream_binding(
    store: &dyn RemoteKeyStore,
    root: &std::path::Path,
    fixture: &PairingFixture,
    expected: &StreamBindingV1,
) {
    let opened = PairedMachineStore::new(store, INSTALLATION_ID, root)
        .open_exact(fixture.identity())
        .expect("reopen paired machine after subscription bootstrap");
    let bindings = opened
        .durable_stream_bindings()
        .expect("read durable stream bindings");
    assert_eq!(bindings.len(), 1);
    let installed = &bindings[0];
    assert_eq!(installed.binding(), expected);
    assert_eq!(installed.outer_applied(), expected.stream_cursor);
    assert_eq!(installed.outer_acked(), expected.stream_cursor);
    assert_eq!(installed.inner_observed(), &expected.inner_cursor);
    assert_eq!(installed.inner_applied(), &expected.inner_cursor);
    assert_eq!(installed.replay_tuple(), None);
}

fn assert_durable_stream_binding_unacked(
    store: &dyn RemoteKeyStore,
    root: &std::path::Path,
    fixture: &PairingFixture,
    expected: &StreamBindingV1,
) {
    let opened = PairedMachineStore::new(store, INSTALLATION_ID, root)
        .open_exact(fixture.identity())
        .expect("reopen paired machine after pre-ACK crash");
    let bindings = opened
        .durable_stream_bindings()
        .expect("read durable stream bindings");
    assert_eq!(bindings.len(), 1);
    let installed = &bindings[0];
    assert_eq!(installed.binding(), expected);
    assert_eq!(installed.outer_applied(), expected.stream_cursor);
    assert_eq!(installed.outer_acked(), StreamCursor::BeforeFirst);
    assert_eq!(installed.inner_observed(), &expected.inner_cursor);
    assert_eq!(installed.inner_applied(), &expected.inner_cursor);
    assert_eq!(installed.replay_tuple(), None);
}

#[allow(clippy::too_many_arguments)]
fn assert_durable_stream_progress(
    store: &dyn RemoteKeyStore,
    root: &std::path::Path,
    fixture: &PairingFixture,
    expected_binding: &StreamBindingV1,
    outer_applied: StreamCursor,
    outer_acked: StreamCursor,
    inner_observed: RuntimeInnerCursor,
    inner_applied: RuntimeInnerCursor,
    replay: Option<(u64, u64)>,
) {
    let opened = PairedMachineStore::new(store, INSTALLATION_ID, root)
        .open_exact(fixture.identity())
        .expect("reopen paired machine after live stream progress");
    let bindings = opened
        .durable_stream_bindings()
        .expect("read live durable stream bindings");
    assert_eq!(bindings.len(), 1);
    let state = &bindings[0];
    assert_eq!(state.binding(), expected_binding);
    assert_eq!(state.outer_applied(), outer_applied);
    assert_eq!(state.outer_acked(), outer_acked);
    assert_eq!(state.inner_observed(), &inner_observed);
    assert_eq!(state.inner_applied(), &inner_applied);
    assert_eq!(
        state
            .replay_tuple()
            .map(|tuple| (tuple.stream_seq(), tuple.sender_counter())),
        replay,
    );
}

fn assert_durable_catalog_live_failure_state(
    store: &dyn RemoteKeyStore,
    root: &std::path::Path,
    fixture: &PairingFixture,
    expected_binding: &StreamBindingV1,
    replay: Option<(u64, u64)>,
    replay_entry_count: usize,
    replay_quarantined: bool,
) {
    assert_durable_stream_progress(
        store,
        root,
        fixture,
        expected_binding,
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER),
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(CATALOG_INNER_HIGH_WATER),
        },
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(CATALOG_INNER_HIGH_WATER),
        },
        replay,
    );
    let opened = PairedMachineStore::new(store, INSTALLATION_ID, root)
        .open_exact(fixture.identity())
        .expect("reopen paired machine to inspect live replay metadata");
    let bindings = opened
        .durable_stream_bindings()
        .expect("read live replay metadata");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].replay_entry_count(), replay_entry_count);
    assert_eq!(bindings[0].replay_quarantined(), replay_quarantined);
}

fn assert_no_durable_stream_binding(
    store: &dyn RemoteKeyStore,
    root: &std::path::Path,
    fixture: &PairingFixture,
) {
    let opened = PairedMachineStore::new(store, INSTALLATION_ID, root)
        .open_exact(fixture.identity())
        .expect("reopen rejected subscription machine");
    assert!(
        opened
            .durable_stream_bindings()
            .expect("read durable stream bindings")
            .is_empty(),
        "rejected bootstrap must not reach the StreamBinding installer"
    );
}

#[tokio::test]
async fn subscription_daemon_failure_is_consumed_before_same_cursor_retry() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("subscription failure state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xce);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open subscription failure machine");
    let (transport, first_sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogFailure,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xcf; 32]);

    assert!(matches!(
        runtime
            .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
            .await,
        Err(RemoteRuntimeError::DaemonFailure(failure))
            if failure.code == "daemon.subscription.fixture_unavailable"
    ));
    assert_only_runtime_subscribe_send(&first_sent);
    assert!(reducer.applied().is_empty());
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen after consumed subscription failure");
    let (transport, retry_sent) = FakeTransport::new_subscription_with_counters(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
        COUNTER_BLOCK_SIZE,
        REPLY_COUNTER + 1,
    );
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xd0; 32]);
    let outcome = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("a transient daemon failure cannot pin the same subscription cursor");

    assert!(outcome.route_accepted());
    assert_eq!(reducer.applied().len(), 1);
    assert_binding_controls(
        &retry_sent,
        outcome.binding(),
        true,
        Some(CATALOG_OUTER_HIGH_WATER),
    );
}

#[test]
fn cold_restart_after_binding_commit_refetches_snapshot_before_resuming_controls() {
    let fixture = PairingFixture::new();
    let store = Arc::new(MemoryRemoteKeyStore::new());
    let temp = tempfile::tempdir().expect("subscription state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(store.as_ref(), &root, 0xe0);
    let expected_binding = catalog_stream_binding(
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER),
        StreamCursor::At(CATALOG_INNER_HIGH_WATER),
    );

    let crashed_store = Arc::clone(&store);
    let crashed_root = root.clone();
    let crashed = std::thread::spawn(move || {
        let opened =
            PairedMachineStore::new(crashed_store.as_ref(), INSTALLATION_ID, &crashed_root)
                .open_exact(PairingFixture::new().identity())
                .expect("open promoted machine before injected crash");
        let (transport, _sent) = FakeTransport::new_subscription(
            SubscriptionScript::CatalogAt,
            catalog_requested_cursor(),
            device_sign,
        );
        let mut runtime =
            RemoteRuntime::new(opened, transport.with_panic_on_first_subscription_control());
        let mut rng = DeterministicRng::new([0xe1; 32]);
        let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("subscription crash Runtime");
        let _ = executor.block_on(runtime.subscribe(
            catalog_requested_cursor(),
            &mut reducer,
            &mut rng,
        ));
    })
    .join();
    assert!(
        crashed.is_err(),
        "fixture must stop at the first binding-derived Relay control"
    );
    assert_durable_stream_binding_unacked(store.as_ref(), &root, &fixture, &expected_binding);

    let reopened = PairedMachineStore::new(store.as_ref(), INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("restart after durable binding install");
    let (transport, sent) = FakeTransport::new_subscription_with_counters(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
        COUNTER_BLOCK_SIZE,
        REPLY_COUNTER + COUNTER_BLOCK_SIZE,
    );
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut rng = DeterministicRng::new([0xe2; 32]);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("subscription recovery Runtime");
    let outcome = executor
        .block_on(runtime.subscribe(catalog_requested_cursor(), &mut reducer, &mut rng))
        .expect("cold restart refetches the non-persisted reducer snapshot");

    assert!(
        outcome.route_accepted(),
        "cold recovery must report only the fresh request acceptance"
    );
    assert_eq!(reducer.applied().len(), 1);
    assert!(matches!(
        &reducer.applied()[0],
        RemoteSubscriptionBootstrapItem::CatalogSnapshot(_)
    ));
    assert_eq!(outcome.subscription(), &catalog_subscription_receipt());
    assert_eq!(
        outcome.sync_complete(),
        &catalog_sync_complete(
            StreamCursor::At(CATALOG_OUTER_HIGH_WATER),
            StreamCursor::At(CATALOG_INNER_HIGH_WATER),
        )
    );
    assert_eq!(outcome.binding(), &expected_binding);
    assert_binding_controls(
        &sent,
        &expected_binding,
        true,
        Some(CATALOG_OUTER_HIGH_WATER),
    );
}

#[tokio::test]
async fn subscription_ack_send_failure_keeps_durable_cursor_unacked() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("subscription ACK failure state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xe3);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open subscription ACK failure machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport.with_fail_on_subscription_ack());
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xe4; 32]);
    let expected_binding = catalog_stream_binding(
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER),
        StreamCursor::At(CATALOG_INNER_HIGH_WATER),
    );

    assert!(matches!(
        runtime
            .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
            .await,
        Err(RemoteRuntimeError::Transport(RemoteRuntimeTransportError::Failed(message)))
            if message == "injected subscription ACK send failure"
    ));
    assert_binding_controls(
        &sent,
        &expected_binding,
        true,
        Some(CATALOG_OUTER_HIGH_WATER),
    );
    drop(runtime);
    assert_durable_stream_binding_unacked(&store, &root, &fixture, &expected_binding);
}

#[tokio::test]
async fn live_catalog_publish_is_verified_reduced_durable_and_exact_duplicate_safe() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("live Catalog state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xe5);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open live Catalog machine");
    let publish = catalog_publish_frame(
        CATALOG_OUTER_HIGH_WATER + 1,
        CATALOG_INNER_HIGH_WATER + 1,
        500,
        StreamPublishShape::Valid,
    );
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
    );
    let transport = transport.with_post_script_inbound(vec![publish.clone(), publish]);
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xe6; 32]);
    let bootstrap = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("bootstrap before live Catalog");
    let binding = bootstrap.binding().clone();

    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::Applied(item))
            if matches!(item.as_ref(), RuntimeStreamItem::CatalogDelta(delta)
                if delta.catalog_revision == CATALOG_INNER_HIGH_WATER + 1)
    ));
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::AppliedDuplicate)
    ));
    assert_eq!(reducer.live_applied().len(), 1);
    assert_eq!(
        reducer.inner_cursor(),
        &RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(CATALOG_INNER_HIGH_WATER + 1),
        }
    );
    let frames = decoded_outbound_frames(&sent);
    assert_eq!(frames.len(), 5, "duplicate must re-ACK without reapplying");
    for frame in &frames[3..] {
        assert!(matches!(
            frame.body,
            RelayFrameBody::Ack(Ack {
                up_to_seq,
                ..
            }) if up_to_seq == CATALOG_OUTER_HIGH_WATER + 1
        ));
    }
    drop(runtime);
    assert_durable_stream_progress(
        &store,
        &root,
        &fixture,
        &binding,
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER + 1),
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER + 1),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(CATALOG_INNER_HIGH_WATER + 1),
        },
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(CATALOG_INNER_HIGH_WATER + 1),
        },
        Some((CATALOG_OUTER_HIGH_WATER + 1, 500)),
    );
}

#[tokio::test]
async fn snapshot_ahead_live_overlap_advances_observed_before_applying_the_next_item() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("live overlap state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xe7);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open live overlap machine");
    let publications = (0_u64..=3)
        .map(|inner| {
            catalog_publish_frame(
                CATALOG_OUTER_HIGH_WATER + 1 + inner,
                inner,
                600 + inner,
                StreamPublishShape::Valid,
            )
        })
        .collect();
    let (transport, _sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogSmallSyncAhead,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport.with_post_script_inbound(publications));
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xe8; 32]);
    let bootstrap = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("small snapshot-ahead bootstrap");
    let binding = bootstrap.binding().clone();

    for _ in 0..3 {
        assert!(matches!(
            runtime.receive_stream_frame(&mut reducer).await,
            Ok(RemoteStreamFrameOutcome::AuthenticatedOverlap)
        ));
        assert!(reducer.live_applied().is_empty());
        assert_eq!(
            reducer.inner_cursor(),
            &RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(2),
            }
        );
    }
    assert!(matches!(
        runtime.receive_stream_frame(&mut reducer).await,
        Ok(RemoteStreamFrameOutcome::Applied(item))
            if matches!(item.as_ref(), RuntimeStreamItem::CatalogDelta(delta)
                if delta.catalog_revision == 3)
    ));
    assert_eq!(reducer.live_applied().len(), 1);
    drop(runtime);
    assert_durable_stream_progress(
        &store,
        &root,
        &fixture,
        &binding,
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER + 4),
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER + 4),
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(3),
        },
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(3),
        },
        Some((CATALOG_OUTER_HIGH_WATER + 4, 603)),
    );
}

#[tokio::test]
async fn forged_signature_or_wrong_aad_is_rejected_before_replay_hwm_reducer_or_ack() {
    for (seed, shape) in [
        (0xe9, StreamPublishShape::ForgedSignature),
        (0xea, StreamPublishShape::WrongAad),
    ] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("untrusted live state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open machine before untrusted live frame");
        let untrusted = catalog_publish_frame(
            CATALOG_OUTER_HIGH_WATER + 1,
            CATALOG_INNER_HIGH_WATER + 1,
            700,
            shape,
        );
        let (transport, sent) = FakeTransport::new_subscription(
            SubscriptionScript::CatalogAt,
            catalog_requested_cursor(),
            device_sign,
        );
        let mut runtime =
            RemoteRuntime::new(opened, transport.with_post_script_inbound(vec![untrusted]));
        let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
        let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);
        let bootstrap = runtime
            .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
            .await
            .expect("bootstrap before untrusted live frame");
        let binding = bootstrap.binding().clone();
        let controls_before = decoded_outbound_frames(&sent).len();

        let error = runtime
            .receive_stream_frame(&mut reducer)
            .await
            .expect_err("signature or signed AAD mismatch must fail closed");
        assert_eq!(error.code(), "remote.crypto.bad_sender_signature");
        assert!(reducer.live_applied().is_empty());
        assert_eq!(decoded_outbound_frames(&sent).len(), controls_before);
        drop(runtime);
        assert_durable_catalog_live_failure_state(
            &store, &root, &fixture, &binding, None, 0, false,
        );
    }
}

#[tokio::test]
async fn signed_stream_key_drift_and_malformed_headers_have_stable_crypto_codes() {
    for (seed, shape, expected_code) in [
        (
            0x91,
            StreamPublishShape::LowerDirectoryRevision,
            "remote.crypto.key_revision_rollback",
        ),
        (
            0x92,
            StreamPublishShape::LowerKeyEpoch,
            "remote.crypto.key_revision_rollback",
        ),
        (
            0x93,
            StreamPublishShape::HigherDirectoryRevision,
            "remote.crypto.key_epoch_missing",
        ),
        (
            0x94,
            StreamPublishShape::HigherKeyEpoch,
            "remote.crypto.key_epoch_missing",
        ),
        (
            0x95,
            StreamPublishShape::WrongKeyPurpose,
            "remote.crypto.bad_ciphertext",
        ),
        (
            0x96,
            StreamPublishShape::WrongNoncePrefix,
            "remote.crypto.bad_ciphertext",
        ),
        (
            0x97,
            StreamPublishShape::MalformedSealedBlob,
            "remote.crypto.bad_ciphertext",
        ),
    ] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("classified live crypto failure state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open machine before classified live crypto failure");
        let publish = catalog_publish_frame(
            CATALOG_OUTER_HIGH_WATER + 1,
            CATALOG_INNER_HIGH_WATER + 1,
            705,
            shape,
        );
        let (transport, sent) = FakeTransport::new_subscription(
            SubscriptionScript::CatalogAt,
            catalog_requested_cursor(),
            device_sign,
        );
        let mut runtime =
            RemoteRuntime::new(opened, transport.with_post_script_inbound(vec![publish]));
        let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
        let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);
        let bootstrap = runtime
            .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
            .await
            .expect("bootstrap before classified live crypto failure");
        let binding = bootstrap.binding().clone();
        let controls_before = decoded_outbound_frames(&sent).len();

        let error = runtime
            .receive_stream_frame(&mut reducer)
            .await
            .expect_err("classified live crypto failure must fail closed");
        assert_eq!(error.code(), expected_code, "unexpected code for {shape:?}");
        assert!(reducer.live_applied().is_empty());
        assert_eq!(decoded_outbound_frames(&sent).len(), controls_before);
        drop(runtime);
        assert_durable_catalog_live_failure_state(
            &store, &root, &fixture, &binding, None, 0, false,
        );
    }
}

#[tokio::test]
async fn authenticated_bad_ciphertext_is_replay_durable_but_never_advances_business_cut_or_ack() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("bad live ciphertext state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xeb);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open machine before bad live ciphertext");
    let stream_seq = CATALOG_OUTER_HIGH_WATER + 1;
    let sender_counter = 701;
    let bad_ciphertext = catalog_publish_frame(
        stream_seq,
        CATALOG_INNER_HIGH_WATER + 1,
        sender_counter,
        StreamPublishShape::AuthenticatedBadCiphertext,
    );
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
    );
    let transport =
        transport.with_post_script_inbound(vec![bad_ciphertext.clone(), bad_ciphertext]);
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xec; 32]);
    let bootstrap = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("bootstrap before bad live ciphertext");
    let binding = bootstrap.binding().clone();
    let controls_before = decoded_outbound_frames(&sent).len();

    for _ in 0..2 {
        let error = runtime
            .receive_stream_frame(&mut reducer)
            .await
            .expect_err("authenticated bad ciphertext must fail AEAD on exact retry");
        assert_eq!(error.code(), "remote.crypto.bad_ciphertext");
        assert!(reducer.live_applied().is_empty());
        assert_eq!(decoded_outbound_frames(&sent).len(), controls_before);
    }
    drop(runtime);
    assert_durable_catalog_live_failure_state(
        &store,
        &root,
        &fixture,
        &binding,
        Some((stream_seq, sender_counter)),
        1,
        false,
    );
}

#[tokio::test]
async fn authenticated_noncanonical_runtime_json_is_replay_durable_without_business_progress() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("noncanonical live JSON state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xed);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open machine before noncanonical live JSON");
    let stream_seq = CATALOG_OUTER_HIGH_WATER + 1;
    let sender_counter = 702;
    let noncanonical = catalog_publish_frame(
        stream_seq,
        CATALOG_INNER_HIGH_WATER + 1,
        sender_counter,
        StreamPublishShape::NonCanonicalJson,
    );
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(
        opened,
        transport.with_post_script_inbound(vec![noncanonical]),
    );
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xee; 32]);
    let bootstrap = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("bootstrap before noncanonical live JSON");
    let binding = bootstrap.binding().clone();
    let controls_before = decoded_outbound_frames(&sent).len();

    let error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("authenticated noncanonical Runtime JSON must fail closed");
    assert_eq!(error.code(), "remote.runtime.reply_invalid");
    assert!(reducer.live_applied().is_empty());
    assert_eq!(decoded_outbound_frames(&sent).len(), controls_before);
    drop(runtime);
    assert_durable_catalog_live_failure_state(
        &store,
        &root,
        &fixture,
        &binding,
        Some((stream_seq, sender_counter)),
        1,
        false,
    );
}

#[tokio::test]
async fn live_reducer_rejection_or_cursor_stall_never_commits_outer_inner_or_ack() {
    for (seed, reject_apply) in [(0xef, true), (0xf0, false)] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("failed live reducer state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open machine before failed live reducer");
        let stream_seq = CATALOG_OUTER_HIGH_WATER + 1;
        let sender_counter = 703;
        let publish = catalog_publish_frame(
            stream_seq,
            CATALOG_INNER_HIGH_WATER + 1,
            sender_counter,
            StreamPublishShape::Valid,
        );
        let (transport, sent) = FakeTransport::new_subscription(
            SubscriptionScript::CatalogAt,
            catalog_requested_cursor(),
            device_sign,
        );
        let mut runtime =
            RemoteRuntime::new(opened, transport.with_post_script_inbound(vec![publish]));
        let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
        let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);
        let bootstrap = runtime
            .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
            .await
            .expect("bootstrap before failed live reducer");
        let binding = bootstrap.binding().clone();
        if reject_apply {
            reducer.reject_apply = true;
        } else {
            reducer.stall_cursor = true;
        }
        let controls_before = decoded_outbound_frames(&sent).len();

        let error = runtime
            .receive_stream_frame(&mut reducer)
            .await
            .expect_err("reducer rejection or cursor stall must abort the live commit");
        assert_eq!(error.code(), "remote.runtime.reply_invalid");
        assert!(reducer.live_applied().is_empty());
        assert_eq!(
            reducer.inner_cursor(),
            &RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(CATALOG_INNER_HIGH_WATER),
            }
        );
        assert_eq!(decoded_outbound_frames(&sent).len(), controls_before);
        drop(runtime);
        assert_durable_catalog_live_failure_state(
            &store,
            &root,
            &fixture,
            &binding,
            Some((stream_seq, sender_counter)),
            1,
            false,
        );
    }
}

#[tokio::test]
async fn same_counter_with_different_live_ciphertext_durably_quarantines_the_stream() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("live nonce reuse state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xf1);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open machine before live nonce reuse");
    let stream_seq = CATALOG_OUTER_HIGH_WATER + 1;
    let sender_counter = 704;
    let first = catalog_publish_frame(
        stream_seq,
        CATALOG_INNER_HIGH_WATER + 1,
        sender_counter,
        StreamPublishShape::NonCanonicalJson,
    );
    let conflicting = catalog_publish_frame(
        stream_seq,
        CATALOG_INNER_HIGH_WATER + 1,
        sender_counter,
        StreamPublishShape::Valid,
    );
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(
        opened,
        transport.with_post_script_inbound(vec![first, conflicting]),
    );
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xf2; 32]);
    let bootstrap = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("bootstrap before live nonce reuse");
    let binding = bootstrap.binding().clone();
    let controls_before = decoded_outbound_frames(&sent).len();

    let first_error = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("first authenticated noncanonical payload must not apply");
    assert_eq!(first_error.code(), "remote.runtime.reply_invalid");
    let nonce_reuse = runtime
        .receive_stream_frame(&mut reducer)
        .await
        .expect_err("same counter with different ciphertext must quarantine");
    assert_eq!(nonce_reuse.code(), "remote.crypto.nonce_reuse");
    assert!(reducer.live_applied().is_empty());
    assert_eq!(decoded_outbound_frames(&sent).len(), controls_before);
    drop(runtime);
    assert_durable_catalog_live_failure_state(
        &store,
        &root,
        &fixture,
        &binding,
        Some((stream_seq, sender_counter)),
        1,
        true,
    );
}

#[tokio::test]
async fn subscription_compact_catalog_snapshot_is_applied_before_hwm_and_controls() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("compact subscription state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xd0);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open compact subscription machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogCompact,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xd1; 32]);
    let outcome = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("compact transfer reaches the staged reducer");
    let expected_binding = catalog_stream_binding(
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER),
        StreamCursor::At(CATALOG_INNER_HIGH_WATER),
    );

    assert_eq!(reducer.applied().len(), 1);
    let RemoteSubscriptionBootstrapItem::CatalogSnapshot(snapshot) = &reducer.applied()[0] else {
        panic!("compact Catalog transfer must reduce to one CatalogSnapshot")
    };
    assert_eq!(
        snapshot,
        &subscription_catalog_snapshot(StreamCursor::At(CATALOG_INNER_HIGH_WATER))
    );
    assert_eq!(outcome.binding(), &expected_binding);
    assert_binding_controls(
        &sent,
        &expected_binding,
        true,
        Some(CATALOG_OUTER_HIGH_WATER),
    );
    drop(runtime);
    assert_durable_stream_binding(&store, &root, &fixture, &expected_binding);
    assert_file_tree_omits(&root, b"Catalog fixture");
}

#[tokio::test]
async fn compact_backfill_and_conversation_snapshot_reach_their_exact_reducers() {
    {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("compact backfill state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, 0xc0);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open compact backfill machine");
        let (transport, sent) = FakeTransport::new_subscription(
            SubscriptionScript::CatalogCompactBackfill,
            catalog_backfill_requested_cursor(),
            device_sign,
        );
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut reducer = CapturingSubscriptionReducer::new(catalog_backfill_requested_cursor());
        let mut rng = DeterministicRng::new([0xc1; 32]);
        let outcome = runtime
            .subscribe(catalog_backfill_requested_cursor(), &mut reducer, &mut rng)
            .await
            .expect("compact Catalog backfill reaches reducer");
        assert_eq!(reducer.applied().len(), 1);
        assert!(matches!(
            &reducer.applied()[0],
            RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Catalog { .. })
        ));
        assert_eq!(
            reducer.inner_cursor(),
            &RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(1),
            }
        );
        assert_binding_controls(
            &sent,
            outcome.binding(),
            true,
            Some(CATALOG_OUTER_HIGH_WATER),
        );
        drop(runtime);
        let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("reopen compact backfill binding");
        let bindings = reopened
            .durable_stream_bindings()
            .expect("read compact backfill HWM");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].inner_applied(), reducer.inner_cursor());
    }

    {
        let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_STREAM_ROUTE);
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("compact conversation state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, 0xc2);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open compact conversation machine");
        let (transport, sent) = FakeTransport::new_subscription(
            SubscriptionScript::ConversationCompact,
            conversation_requested_cursor(),
            device_sign,
        );
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut reducer = CapturingSubscriptionReducer::new(conversation_requested_cursor());
        let mut rng = DeterministicRng::new([0xc3; 32]);
        let outcome = runtime
            .subscribe(conversation_requested_cursor(), &mut reducer, &mut rng)
            .await
            .expect("compact Conversation snapshot reaches reducer");
        assert_eq!(reducer.applied().len(), 1);
        assert!(matches!(
            &reducer.applied()[0],
            RemoteSubscriptionBootstrapItem::ConversationSnapshot(_)
        ));
        assert_binding_controls(
            &sent,
            outcome.binding(),
            true,
            Some(CONVERSATION_OUTER_HIGH_WATER),
        );
        drop(runtime);
        assert_durable_stream_binding(&store, &root, &fixture, outcome.binding());
    }
}

#[tokio::test]
async fn exact_duplicate_bootstrap_page_is_applied_only_once() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("duplicate bootstrap state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xc8);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open duplicate bootstrap machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogDuplicateOpenPage,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xc9; 32]);
    let outcome = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("an exact transport duplicate is idempotent within one bootstrap");

    assert_eq!(
        reducer.applied().len(),
        2,
        "the repeated non-final Catalog page must reach the reducer exactly once"
    );
    assert_binding_controls(
        &sent,
        outcome.binding(),
        true,
        Some(CATALOG_OUTER_HIGH_WATER),
    );
}

#[tokio::test]
async fn missing_catalog_subscription_page_fails_closed_direct_or_compact() {
    for (seed, script) in [
        (0xcc, SubscriptionScript::CatalogMissingFirstPage),
        (0xcd, SubscriptionScript::CatalogCompactMissingMiddlePage),
    ] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("missing Catalog page state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open missing Catalog page machine");
        let (transport, sent) =
            FakeTransport::new_subscription(script, catalog_requested_cursor(), device_sign);
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
        let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);

        assert!(
            runtime
                .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
                .await
                .is_err(),
            "a signed final page cannot hide an omitted predecessor"
        );
        assert!(reducer.applied().is_empty());
        assert_only_runtime_subscribe_send(&sent);
        drop(runtime);
        assert_no_durable_stream_binding(&store, &root, &fixture);
    }
}

#[tokio::test(start_paused = true)]
async fn partial_subscription_transfer_expires_without_waiting_for_another_frame() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("expired bootstrap transfer state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xca);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open expired bootstrap transfer machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogPartialTransferThenPending,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xcb; 32]);

    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(agentdeck_protocol::runtime::TRANSFER_TTL_MS + 1_000),
        runtime.subscribe(catalog_requested_cursor(), &mut reducer, &mut rng),
    )
    .await
    .expect("the Runtime must own an earlier transfer deadline");
    assert!(matches!(
        outcome,
        Err(RemoteRuntimeError::Transfer(
            agentdeck_protocol::runtime::TransferError::Expired
        ))
    ));
    assert!(reducer.applied().is_empty());
    assert_only_runtime_subscribe_send(&sent);
    drop(runtime);
    assert_no_durable_stream_binding(&store, &root, &fixture);
}

#[tokio::test]
async fn snapshot_and_backfill_modes_cannot_be_mixed_direct_or_compact() {
    for (seed, script) in [
        (0xc4, SubscriptionScript::CatalogSnapshotThenBackfill),
        (0xc6, SubscriptionScript::CatalogCompactSnapshotThenBackfill),
    ] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("mixed subscription mode state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open mixed subscription mode machine");
        let (transport, sent) =
            FakeTransport::new_subscription(script, catalog_requested_cursor(), device_sign);
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
        let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);

        assert!(
            runtime
                .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
                .await
                .is_err(),
            "one bootstrap must choose exactly one of snapshot or backfill"
        );
        assert!(reducer.applied().is_empty());
        assert_eq!(reducer.inner_cursor(), &catalog_requested_cursor());
        assert_only_runtime_subscribe_send(&sent);
        drop(runtime);
        assert_no_durable_stream_binding(&store, &root, &fixture);
    }
}

#[tokio::test]
async fn invalid_or_incomplete_subscription_transfer_never_swaps_reducer_or_hwm() {
    for (seed, script) in [
        (0xd2, SubscriptionScript::CatalogCompactWrongMessage),
        (0xd4, SubscriptionScript::CatalogCompactWrongChannel),
        (0xd6, SubscriptionScript::CatalogCompactCrossTarget),
        (0xd8, SubscriptionScript::CatalogPartialTransferThenSync),
        (0xda, SubscriptionScript::CatalogUnfinishedPageThenSync),
        (0xdb, SubscriptionScript::CatalogBeforeFirstNoSnapshot),
    ] {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("rejected transfer state root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open rejected transfer machine");
        let (transport, sent) =
            FakeTransport::new_subscription(script, catalog_requested_cursor(), device_sign);
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
        let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);

        assert!(
            runtime
                .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
                .await
                .is_err(),
            "invalid compact metadata, target, completion, or pagination must fail-close"
        );
        assert!(
            reducer.applied().is_empty(),
            "a failed staged reducer must not replace the caller's canonical state"
        );
        assert_eq!(reducer.inner_cursor(), &catalog_requested_cursor());
        assert_only_runtime_subscribe_send(&sent);
        drop(runtime);
        assert_no_durable_stream_binding(&store, &root, &fixture);
    }
}

#[tokio::test]
async fn reducer_rejection_keeps_exact_pending_and_retry_uses_no_new_entropy() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("reducer rejection state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xdc);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open reducer rejection machine");
    let (transport, first_sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CapturingSubscriptionReducer::rejecting(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xdd; 32]);
    assert!(
        runtime
            .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
            .await
            .is_err()
    );
    assert!(reducer.applied().is_empty());
    assert_only_runtime_subscribe_send(&first_sent);
    drop(runtime);
    assert_no_durable_stream_binding(&store, &root, &fixture);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen exact pending after reducer rejection");
    let (transport, retry_sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(reopened, transport);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let mut panic_rng = PanicRng;
    let outcome = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut panic_rng)
        .await
        .expect("exact pending retry succeeds without caller entropy");
    assert!(outcome.route_accepted());
    assert_eq!(reducer.applied().len(), 1);
    assert_binding_controls(
        &retry_sent,
        outcome.binding(),
        true,
        Some(CATALOG_OUTER_HIGH_WATER),
    );
}

#[tokio::test]
async fn reducer_cursor_mismatch_never_commits_binding_or_controls() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("stalled reducer state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xde);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open stalled reducer machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogAt,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = CapturingSubscriptionReducer::stalling(catalog_requested_cursor());
    let mut rng = DeterministicRng::new([0xdf; 32]);
    assert!(
        runtime
            .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
            .await
            .is_err()
    );
    assert!(reducer.applied().is_empty());
    assert_only_runtime_subscribe_send(&sent);
    drop(runtime);
    assert_no_durable_stream_binding(&store, &root, &fixture);
}

#[tokio::test]
async fn sync_inner_ahead_of_publication_cut_is_persisted_as_the_applied_inner_cursor() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("subscription state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xef);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted catalog machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogSyncAheadOfBinding,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xf0; 32]);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let outcome = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("SyncComplete may advance beyond the Relay publication cut");
    let expected_binding = catalog_stream_binding(
        StreamCursor::At(CATALOG_OUTER_HIGH_WATER),
        StreamCursor::BeforeFirst,
    );
    assert_eq!(reducer.applied().len(), 1);
    assert_eq!(
        reducer.inner_cursor(),
        &RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(CATALOG_INNER_HIGH_WATER),
        }
    );
    assert_eq!(outcome.binding(), &expected_binding);
    assert_binding_controls(
        &sent,
        &expected_binding,
        true,
        Some(CATALOG_OUTER_HIGH_WATER),
    );
    drop(runtime);

    let reopened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("reopen advanced subscription cut");
    let bindings = reopened
        .durable_stream_bindings()
        .expect("read advanced durable binding");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].binding(), &expected_binding);
    assert_eq!(
        bindings[0].inner_applied(),
        &RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(CATALOG_INNER_HIGH_WATER),
        }
    );
}

#[tokio::test]
async fn conversation_subscription_keeps_runtime_and_relay_generations_independent() {
    let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_STREAM_ROUTE);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("subscription state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xe2);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted conversation machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::ConversationIndependentGeneration,
        conversation_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xe3; 32]);
    let mut reducer = CapturingSubscriptionReducer::new(conversation_requested_cursor());
    let outcome = runtime
        .subscribe(conversation_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("independent Runtime and Relay generations are valid");
    let expected_binding = conversation_stream_binding(
        StreamCursor::At(CONVERSATION_OUTER_HIGH_WATER),
        StreamCursor::At(CONVERSATION_INNER_HIGH_WATER),
    );

    assert!(outcome.route_accepted());
    assert_eq!(outcome.subscription(), &conversation_subscription_receipt());
    assert_eq!(outcome.sync_complete(), &conversation_sync_complete());
    assert_eq!(outcome.binding(), &expected_binding);
    assert_eq!(reducer.applied().len(), 1);
    assert!(matches!(
        &reducer.applied()[0],
        RemoteSubscriptionBootstrapItem::ConversationSnapshot(_)
    ));
    assert_binding_controls(
        &sent,
        &expected_binding,
        true,
        Some(CONVERSATION_OUTER_HIGH_WATER),
    );
    drop(runtime);
    assert_durable_stream_binding(&store, &root, &fixture, &expected_binding);
}

#[tokio::test]
async fn before_first_binding_subscribes_without_emitting_an_ack() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("subscription state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xe4);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted catalog machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogBeforeFirst,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xe5; 32]);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());
    let outcome = runtime
        .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
        .await
        .expect("BeforeFirst binding completes without a fabricated Ack");
    let expected_binding =
        catalog_stream_binding(StreamCursor::BeforeFirst, StreamCursor::BeforeFirst);

    assert_eq!(outcome.binding(), &expected_binding);
    assert_binding_controls(&sent, &expected_binding, true, None);
    drop(runtime);
    assert_durable_stream_binding(&store, &root, &fixture, &expected_binding);
}

#[tokio::test]
async fn route_accepted_and_sync_complete_without_stream_binding_are_not_terminal() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("subscription state root");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xe6);
    let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
        .open_exact(fixture.identity())
        .expect("open promoted catalog machine");
    let (transport, sent) = FakeTransport::new_subscription(
        SubscriptionScript::CatalogMissingBinding,
        catalog_requested_cursor(),
        device_sign,
    );
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut rng = DeterministicRng::new([0xe7; 32]);
    let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());

    assert!(
        runtime
            .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
            .await
            .is_err(),
        "RouteAccepted plus SyncComplete must not complete without StreamBinding"
    );
    assert!(reducer.applied().is_empty());
    assert_only_runtime_subscribe_send(&sent);
    drop(runtime);
    assert_no_durable_stream_binding(&store, &root, &fixture);
}

#[tokio::test]
async fn invalid_stream_binding_target_revision_or_order_rejects_before_install_and_controls() {
    for (seed, script) in [
        (0xe8, SubscriptionScript::CatalogCrossTargetBinding),
        (0xea, SubscriptionScript::CatalogWrongBindingRevision),
        (0xec, SubscriptionScript::CatalogBindingBeforeSync),
    ] {
        let fixture = PairingFixture::new().with_conversation_stream(CONVERSATION_STREAM_ROUTE);
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("independent subscription rejection root");
        let root = state_root(&temp);
        let device_sign = fixture.promote(&store, &root, seed);
        let opened = PairedMachineStore::new(&store, INSTALLATION_ID, &root)
            .open_exact(fixture.identity())
            .expect("open promoted catalog machine");
        let (transport, sent) =
            FakeTransport::new_subscription(script, catalog_requested_cursor(), device_sign);
        let mut runtime = RemoteRuntime::new(opened, transport);
        let mut rng = DeterministicRng::new([seed.wrapping_add(1); 32]);
        let mut reducer = CapturingSubscriptionReducer::new(catalog_requested_cursor());

        assert!(
            runtime
                .subscribe(catalog_requested_cursor(), &mut reducer, &mut rng)
                .await
                .is_err(),
            "invalid binding must not become a subscription terminal"
        );
        assert!(reducer.applied().is_empty());
        assert_only_runtime_subscribe_send(&sent);
        drop(runtime);
        assert_no_durable_stream_binding(&store, &root, &fixture);
    }
}
