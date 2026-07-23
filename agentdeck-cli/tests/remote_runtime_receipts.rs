#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::collections::VecDeque;
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
};
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, VerifyingKey,
    counter::COUNTER_BLOCK_SIZE, open_sealed_payload, seal_symmetric, sha256, sign_sealed,
    sign_tbs, verify_sealed,
};
use agentdeck_protocol::e2ee::{
    KeyId, KeyPurpose, OuterContextV1, SealedPayloadKind, SignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::auth::{DeviceRevocation, Ed25519Signature};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Reply, RevocationCommitted, RouteAccepted, SealedBlob, Send,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial as RelayGrantSerial, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RequestRouteId, decode, encode,
};
use agentdeck_protocol::runtime::command::{CatalogRequest, RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CatalogPageCursor, CommandId, GrantSerial as RuntimeGrantSerial, MessageId,
    TransferId, TurnId,
};
use agentdeck_protocol::runtime::{
    ApprovalReceipt, CatalogSnapshot, CommandReceipt, ConversationEntry, ConversationId,
    IdempotencyKey, PromptPayload, RUNTIME_PROTOCOL_VERSION, RevocationReceipt, RuntimeEnvelope,
    RuntimeFailure, RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeTransferCarrierV1,
    RuntimeTransferChannel, SendPromptRequest, StreamCursor, TransferEnvelope,
};
use agentdeck_protocol::{ActionDecision, ActionDecisionKind, AgentKind};
use async_trait::async_trait;

use remote_pairing::{
    DEVICE_COMMAND_EPOCH, DEVICE_COMMAND_KEY, DEVICE_REPLY_EPOCH, DEVICE_REPLY_KEY, DEVICE_ROUTE,
    DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION, MACHINE_ROUTE, PairingFixture,
    PanicRng, RELAY_SERVER, ROOT_KEY_ID,
};

const REPLY_COUNTER: u64 = 41;
const WRONG_REQUEST_ROUTE: RequestRouteId = RequestRouteId::from_bytes([0xa5; 16]);

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
    sent_codec_frames: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown_observed: Option<Arc<AtomicBool>>,
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
                sent_codec_frames: Arc::clone(&sent_codec_frames),
                shutdown_observed: None,
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

    fn with_shutdown_observer(mut self, shutdown_observed: Arc<AtomicBool>) -> Self {
        self.shutdown_observed = Some(shutdown_observed);
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
        }
    }
}

#[async_trait]
impl RemoteRuntimeTransport for FakeTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        let exact_bytes = frame.into_bytes();
        let decoded = decode(&exact_bytes).expect("runtime must hand transport canonical bytes");
        let (request_route, message_id) = self.inspect_real_send(&decoded);
        self.sent_codec_frames
            .lock()
            .expect("sent-frame recorder")
            .push(exact_bytes);
        self.queue_scripted_inbound(request_route, message_id);
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        Ok(self.inbound.pop_front())
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
    let (payload_kind, plaintext) = match reply {
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
            let payload_kind = if matches!(reply, RuntimeReply::Catalog(_)) {
                SealedPayloadKind::CatalogSnapshot
            } else {
                SealedPayloadKind::CommandReceipt
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
        | ReplyShape::WrongAad => PairingFixture::machine_data_signing_key(),
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

fn catalog_snapshot() -> CatalogSnapshot {
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
        Some(CatalogPageCursor::new("catalog-page-cursor-2")),
    )
    .expect("bounded catalog fixture")
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
    )
    .expect("bounded newer catalog fixture")
}

fn catalog_transfer_replies(snapshot: &CatalogSnapshot) -> Vec<RuntimeReply> {
    let payload = serde_json::to_vec(snapshot).expect("encode CatalogSnapshot transfer payload");
    let midpoint = payload.len() / 2;
    let total_sha256 = sha256(&payload);
    let total_bytes = payload.len() as u64;
    let transfer_id = TransferId::new("catalog-transfer-1");
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
    let snapshot = catalog_snapshot();
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
async fn catalog_route_accepted_only_restarts_with_the_exact_frozen_send() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let root = state_root(&temp);
    let device_sign = fixture.promote(&store, &root, 0xc2);
    let snapshot = catalog_snapshot();
    let page_cursor = catalog_page_cursor();

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
