#![cfg(unix)]

#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_cli::remote::keychain::MemoryRemoteKeyStore;
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::runtime::{
    ExactRelayFrame, RemotePromptOutcome, RemoteRuntime, RemoteRuntimeError,
    RemoteRuntimeTransport, RemoteRuntimeTransportError,
};
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, VerifyingKey,
    open_sealed_payload, seal_symmetric, sign_sealed, verify_sealed,
};
use agentdeck_protocol::e2ee::{
    KeyId, KeyPurpose, OuterContextV1, SealedPayloadKind, SignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, Reply, RouteAccepted, SealedBlob, Send};
use agentdeck_protocol::relay_v2::{
    OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId, decode,
};
use agentdeck_protocol::runtime::identity::{CommandId, MessageId};
use agentdeck_protocol::runtime::{
    CommandReceipt, ConversationId, IdempotencyKey, PromptPayload, RUNTIME_PROTOCOL_VERSION,
    RuntimeEnvelope, RuntimeFailure, RuntimeMessage, RuntimeReply, RuntimeRequest,
    SendPromptRequest,
};
use async_trait::async_trait;

use remote_pairing::{
    DEVICE_COMMAND_EPOCH, DEVICE_COMMAND_KEY, DEVICE_REPLY_EPOCH, DEVICE_REPLY_KEY, DEVICE_ROUTE,
    DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION, MACHINE_ROUTE, PairingFixture,
    PanicRng,
};

const REPLY_COUNTER: u64 = 41;
const WRONG_REQUEST_ROUTE: RequestRouteId = RequestRouteId::from_bytes([0xa5; 16]);

struct PanicOnNthStateActive {
    target: usize,
    calls: AtomicUsize,
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
}

struct FakeTransport {
    script: TransportScript,
    expected_request: SendPromptRequest,
    receipt: CommandReceipt,
    reply_counter: u64,
    device_sign_verifying_key: VerifyingKey,
    inbound: VecDeque<OpaqueRouteFrame>,
    sent_codec_frames: Arc<Mutex<Vec<Vec<u8>>>>,
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
        let sent_codec_frames = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                script,
                expected_request,
                receipt,
                reply_counter,
                device_sign_verifying_key,
                inbound: VecDeque::new(),
                sent_codec_frames: Arc::clone(&sent_codec_frames),
            },
            sent_codec_frames,
        )
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
            0,
            "the first durable command block starts at counter zero"
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
        let RuntimeMessage::Request(RuntimeRequest::SendPrompt(actual)) = envelope.body else {
            panic!("remote prompt may only emit RuntimeRequest::SendPrompt");
        };
        assert_eq!(actual, self.expected_request);
        (*request_route, envelope.message_id)
    }

    fn queue_scripted_inbound(&mut self, request_route: RequestRouteId, message_id: MessageId) {
        let accepted = route_accepted(request_route);
        match self.script {
            TransportScript::ReplyOnly => self.inbound.push_back(reply_frame(
                request_route,
                message_id,
                self.receipt.clone(),
                ReplyShape::Valid,
                self.reply_counter,
            )),
            TransportScript::ReplyOnlyWithShape(shape) => {
                self.inbound.push_back(reply_frame(
                    request_route,
                    message_id,
                    self.receipt.clone(),
                    shape,
                    self.reply_counter,
                ));
            }
            TransportScript::ReplyThenRouteAccepted => {
                self.inbound.push_back(reply_frame(
                    request_route,
                    message_id,
                    self.receipt.clone(),
                    ReplyShape::Valid,
                    self.reply_counter,
                ));
                self.inbound.push_back(accepted);
            }
            TransportScript::RouteAcceptedThenReply => {
                self.inbound.push_back(accepted);
                self.inbound.push_back(reply_frame(
                    request_route,
                    message_id,
                    self.receipt.clone(),
                    ReplyShape::Valid,
                    self.reply_counter,
                ));
            }
            TransportScript::RouteAcceptedOnly => self.inbound.push_back(accepted),
            TransportScript::EofAfterSend => {}
            TransportScript::WrongRequestRouteOnly => self.inbound.push_back(reply_frame(
                WRONG_REQUEST_ROUTE,
                message_id,
                self.receipt.clone(),
                ReplyShape::Valid,
                self.reply_counter,
            )),
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

    async fn recv(&mut self) -> Result<Option<OpaqueRouteFrame>, RemoteRuntimeTransportError> {
        Ok(self.inbound.pop_front())
    }
}

#[derive(Clone, Copy, Debug)]
enum ReplyShape {
    Valid,
    ForgedMachineDataSignature,
    AuthenticatedBadCiphertext,
    WrongMessageId,
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
    receipt: CommandReceipt,
    shape: ReplyShape,
    counter: u64,
) -> OpaqueRouteFrame {
    let expected_context = OuterContextV1::directed_reply(
        MACHINE_ROUTE,
        DEVICE_ROUTE,
        request_route,
        DEVICE_REPLY_EPOCH,
    );
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: if matches!(shape, ReplyShape::WrongMessageId) {
            MessageId::new("wrong-message-id")
        } else {
            message_id
        },
        body: RuntimeMessage::Reply(RuntimeReply::Command(receipt)),
    };
    let plaintext = envelope
        .to_json_bytes_checked()
        .expect("fixture Runtime reply envelope");
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
            SealedPayloadKind::CommandReceipt
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

fn state_root(temp: &tempfile::TempDir) -> PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical tempdir")
        .join("paired-state")
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
