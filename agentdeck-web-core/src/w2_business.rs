//! W2b 浏览器 paired principal 与最小业务闭环状态机。
//!
//! 本模块只消费 W2a 已验证的 PairResponse capability。TypeScript 仍只能取得连接 URL、
//! opaque Relay frame 与脱敏 view state；Runtime/E2EE wire、密钥、counter 和业务明文解析
//! 全部留在 Rust/WASM。

use std::collections::{HashMap, HashSet};

use agentdeck_crypto::rand_core::TryRng as _;
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, HpkePrivateKey, SenderCounter, SigningKey,
    VerifiedPairResponseV1, VerifyingKey, derive_nonce_prefix, open_key_directory_entry,
    open_sealed_payload, seal_symmetric, sign_authentication_transcript, sign_sealed,
    verify_sealed,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, E2EE_FORMAT_VERSION, EpochBarrierV1,
    KeyControlRequestV1, KeyControlV1, KeyPurpose, KeyUpdateInfoV1, OuterContextV1, OuterFrameKind,
    SealedPayloadKind, SignedSealedBlobV1, StreamAppliedAckV1, StreamBindingV1,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, RelayGrant,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Ack, AuthProof, Authenticate, Challenge, Hello, Pong, Publish, ReplayComplete,
    SealedBlob, Send, Subscribe,
};
use agentdeck_protocol::relay_v2::{
    KeyDirectoryRevision, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId,
    StreamCursor, StreamGenerationId, StreamRouteId, decode, encode,
};
use agentdeck_protocol::runtime::command::PromptPayload;
use agentdeck_protocol::runtime::identity::{ApprovalId, MessageId, TurnId};
use agentdeck_protocol::runtime::{
    ApprovalDeliveryState, ApprovalReceipt, CatalogSnapshot, CommandReceipt, ConversationId,
    ConversationSnapshot, IdempotencyKey, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeEvent,
    RuntimeEventBody, RuntimeInnerCursor, RuntimeMessage, RuntimeReply, RuntimeRequest,
    RuntimeStreamItem, RuntimeSyncComplete, SendPromptRequest, SubscriptionReceipt,
};
use agentdeck_protocol::trunk::{ActionDecision, ActionDecisionKind, AgentItem};
use serde::{Deserialize, Serialize};

use crate::DeterministicRng;
use crate::w2::W2PairingError;

const EXPECTED_ASSISTANT_TEXT: &str = "synthetic Codex response";
const EXPECTED_APPROVAL_SUMMARY: &str = "synthetic codex approval";
const W2B_PROMPT_TEXT: &str = "web-w2b-prompt-7fb7f299";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W2BusinessEvidence {
    pub principal_authenticated: bool,
    pub catalog_route_accepted: bool,
    pub catalog_entry_count: usize,
    pub conversation_title: Option<String>,
    pub catalog_subscription_active: bool,
    pub business_fence_count: u64,
    pub conversation_route_accepted: bool,
    pub conversation_open: bool,
    pub relay_subscription_active: bool,
    pub prompt_route_accepted: bool,
    pub prompt_accepted: bool,
    pub assistant_observed: bool,
    pub approval_pending: bool,
    pub approval_summary_matched: bool,
    pub approval_route_accepted: bool,
    pub approval_receipt_applied: bool,
    pub approval_event_applied: bool,
    pub command_completed: bool,
    pub outer_ack_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrincipalPhase {
    Initial,
    HelloSent,
    AuthenticateSent,
    Active,
    Failed,
}

struct StreamKey {
    stream_route: Option<StreamRouteId>,
    key: AeadReceivingKey,
    nonce_prefix: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubscriptionTarget {
    Catalog,
    Conversation,
}

struct SubscriptionTracker {
    target: SubscriptionTarget,
    subscription_generation: Option<agentdeck_protocol::runtime::identity::StreamGeneration>,
    snapshot_cursor: Option<StreamCursor>,
    configuration_revision: Option<u64>,
    sync_complete: Option<RuntimeSyncComplete>,
    binding: Option<StreamBindingV1>,
}

enum PendingKind {
    Subscribe(Box<SubscriptionTracker>),
    Prompt {
        terminal: bool,
    },
    Approval {
        terminal: bool,
        receipt_applied: bool,
    },
}

struct PendingRequest {
    request_route: RequestRouteId,
    message_id: MessageId,
    route_accepted: bool,
    kind: PendingKind,
}

struct ApprovalContext {
    turn_id: TurnId,
    approval_id: ApprovalId,
    request_id: String,
}

struct PendingControlAck {
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
    up_to_seq: u64,
    inner_cursor: RuntimeInnerCursor,
}

pub(crate) struct W2BusinessCore {
    connect_url: String,
    phase: PrincipalPhase,
    device_signing_key: SigningKey,
    _device_hpke_private_key: HpkePrivateKey,
    _verified_response: VerifiedPairResponseV1,
    machine_data_verifying_key: VerifyingKey,
    grant: RelayGrant,
    authorization: agentdeck_protocol::e2ee::DeviceAuthorizationV1,
    command_key: AeadSendingKey,
    reply_key: AeadReceivingKey,
    reply_nonce_prefix: [u8; 4],
    stream_keys: Vec<StreamKey>,
    directory_revision: u64,
    command_counter: u64,
    request_sequence: u64,
    reply_counters: HashSet<u64>,
    stream_counters: HashSet<(StreamRouteId, u64)>,
    pending_control_acks: HashMap<RequestRouteId, PendingControlAck>,
    pending_replay_completes: HashSet<(StreamRouteId, StreamGenerationId, u64)>,
    fenced_request_routes: HashSet<RequestRouteId>,
    rng: DeterministicRng,
    pending: Option<PendingRequest>,
    conversation_id: Option<ConversationId>,
    configuration_revision: Option<u64>,
    catalog_binding: Option<StreamBindingV1>,
    conversation_binding: Option<StreamBindingV1>,
    prompt_command_id: Option<agentdeck_protocol::runtime::identity::CommandId>,
    prompt_turn_id: Option<TurnId>,
    approval: Option<ApprovalContext>,
    evidence: W2BusinessEvidence,
}

impl std::fmt::Debug for W2BusinessCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("W2BusinessCore")
            .field("phase", &self.phase)
            .field("crypto", &"<redacted>")
            .finish()
    }
}

impl W2BusinessCore {
    pub(crate) fn new(
        wss_url: &str,
        device_signing_key: SigningKey,
        device_hpke_private_key: HpkePrivateKey,
        verified_response: VerifiedPairResponseV1,
        rng: DeterministicRng,
    ) -> Result<Self, W2PairingError> {
        let device_hpke_pubkey: [u8; 32] = device_hpke_private_key
            .public_key()
            .to_bytes()
            .try_into()
            .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
        if verified_response.relay_grant().device_sign_pubkey.0
            != device_signing_key.verifying_key().to_bytes()
            || verified_response
                .device_authorization()
                .device_hpke_pubkey
                .0
                != device_hpke_pubkey
        {
            return Err(W2PairingError::BusinessCryptoFailed);
        }
        let grant = verified_response.relay_grant().clone();
        let authorization = verified_response.device_authorization().clone();
        let info = verified_response.info().clone();
        let machine_data_verifying_key =
            VerifyingKey::from_bytes(&verified_response.data_sign_certificate().subject_pubkey.0)
                .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
        let directory_revision = verified_response.key_directory().revision.value();
        let mut command_key = None;
        let mut reply_key = None;
        let mut stream_keys = Vec::new();
        let mut slots = HashSet::new();
        for entry in &verified_response.key_directory().entries {
            if !slots.insert((entry.key_id.purpose, entry.stream_route)) {
                return Err(W2PairingError::BusinessCryptoFailed);
            }
            let entry_info = KeyUpdateInfoV1 {
                e2ee_format_version: E2EE_FORMAT_VERSION,
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                relay_server_id: info.relay_server_id,
                machine_route: info.machine_route,
                device_route: info.device_route,
                stream_route: entry.stream_route,
                grant_serial: info.grant_serial,
                root_trust_epoch: info.root_trust_epoch,
                key_directory_revision: verified_response.key_directory().revision,
                key_purpose: entry.key_id.purpose,
                key_epoch: entry.key_id.epoch,
            };
            let key = open_key_directory_entry(
                &device_hpke_private_key,
                &entry_info,
                &key_update_context(&entry_info),
                entry,
            )
            .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
            match entry.key_id.purpose {
                KeyPurpose::DeviceCommandTx if entry.stream_route.is_none() => {
                    if command_key.is_some() {
                        return Err(W2PairingError::BusinessCryptoFailed);
                    }
                    command_key = Some(AeadSendingKey::with_derived_nonce_prefix(
                        entry.key_id,
                        entry.key_id.epoch,
                        directory_revision,
                        key,
                    ));
                }
                KeyPurpose::DeviceReplyTx if entry.stream_route.is_none() => {
                    if reply_key.is_some() {
                        return Err(W2PairingError::BusinessCryptoFailed);
                    }
                    let nonce_prefix = derive_nonce_prefix(&key);
                    reply_key = Some((
                        AeadReceivingKey::new(entry.key_id, entry.key_id.epoch, key),
                        nonce_prefix,
                    ));
                }
                KeyPurpose::Catalog | KeyPurpose::ConversationDek => {
                    let nonce_prefix = derive_nonce_prefix(&key);
                    stream_keys.push(StreamKey {
                        stream_route: entry.stream_route,
                        key: AeadReceivingKey::new(entry.key_id, entry.key_id.epoch, key),
                        nonce_prefix,
                    });
                }
                KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
                    return Err(W2PairingError::BusinessCryptoFailed);
                }
            }
        }
        let command_key = command_key.ok_or(W2PairingError::BusinessCryptoFailed)?;
        let (reply_key, reply_nonce_prefix) =
            reply_key.ok_or(W2PairingError::BusinessCryptoFailed)?;
        let connect_url = format!("{wss_url}v2/connect");
        Ok(Self {
            connect_url,
            phase: PrincipalPhase::Initial,
            device_signing_key,
            _device_hpke_private_key: device_hpke_private_key,
            _verified_response: verified_response,
            machine_data_verifying_key,
            grant,
            authorization,
            command_key,
            reply_key,
            reply_nonce_prefix,
            stream_keys,
            directory_revision,
            command_counter: 0,
            request_sequence: 0,
            reply_counters: HashSet::new(),
            stream_counters: HashSet::new(),
            pending_control_acks: HashMap::new(),
            pending_replay_completes: HashSet::new(),
            fenced_request_routes: HashSet::new(),
            rng,
            pending: None,
            conversation_id: None,
            configuration_revision: None,
            catalog_binding: None,
            conversation_binding: None,
            prompt_command_id: None,
            prompt_turn_id: None,
            approval: None,
            evidence: W2BusinessEvidence::default(),
        })
    }

    pub(crate) fn connect_url(&self) -> Result<&str, W2PairingError> {
        if self.phase != PrincipalPhase::Initial {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        Ok(&self.connect_url)
    }

    pub(crate) fn start_hello(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if self.phase != PrincipalPhase::Initial {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        self.phase = PrincipalPhase::HelloSent;
        Ok(frame(RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        })))
    }

    pub(crate) fn accept_challenge(&mut self, bytes: &[u8]) -> Result<Vec<u8>, W2PairingError> {
        if self.phase != PrincipalPhase::HelloSent {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let decoded = decode(bytes).map_err(|_| self.fail(W2PairingError::BusinessFrameInvalid))?;
        let RelayFrameBody::Challenge(Challenge {
            relay_server_id,
            connection_instance,
            challenge_nonce,
        }) = decoded.body
        else {
            return Err(self.fail(W2PairingError::BusinessHandshakeRejected));
        };
        if relay_server_id != self._verified_response.info().relay_server_id {
            return Err(self.fail(W2PairingError::BusinessHandshakeRejected));
        }
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::Device,
            challenge_nonce,
            connection_instance,
            relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.grant.machine_route,
            device_route: Some(self.grant.device_route),
            serial_or_generation: self.grant.grant_serial.value(),
            credential_sha256: self.grant.canonical_sha256(),
        };
        let signature =
            sign_authentication_transcript(&self.device_signing_key, &transcript).into();
        self.phase = PrincipalPhase::AuthenticateSent;
        Ok(frame(RelayFrameBody::Authenticate(Authenticate {
            proof: AuthProof::Device {
                relay_grant: self.grant.clone(),
            },
            signature,
        })))
    }

    pub(crate) fn accept_authenticated(&mut self, bytes: &[u8]) -> Result<(), W2PairingError> {
        if self.phase != PrincipalPhase::AuthenticateSent {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let decoded = decode(bytes).map_err(|_| self.fail(W2PairingError::BusinessFrameInvalid))?;
        match decoded.body {
            RelayFrameBody::Authenticated(authenticated)
                if authenticated.heartbeat_interval_secs > 0 =>
            {
                self.phase = PrincipalPhase::Active;
                self.evidence.principal_authenticated = true;
                Ok(())
            }
            _ => Err(self.fail(W2PairingError::BusinessHandshakeRejected)),
        }
    }

    pub(crate) fn start_catalog(&mut self) -> Result<Vec<u8>, W2PairingError> {
        let requested = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        };
        self.start_request(
            RuntimeRequest::Subscribe {
                inner_cursor: requested,
            },
            AuthorizationCapabilityV1::Catalog,
            AuthorizationPermissionV1::CatalogRead,
            PendingKind::Subscribe(Box::new(SubscriptionTracker {
                target: SubscriptionTarget::Catalog,
                subscription_generation: None,
                snapshot_cursor: None,
                configuration_revision: None,
                sync_complete: None,
                binding: None,
            })),
        )
    }

    pub(crate) fn start_conversation(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if !self.evidence.catalog_subscription_active {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let conversation_id = self
            .conversation_id
            .clone()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let requested = RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor: StreamCursor::BeforeFirst,
        };
        self.start_request(
            RuntimeRequest::Subscribe {
                inner_cursor: requested.clone(),
            },
            AuthorizationCapabilityV1::Conversation,
            AuthorizationPermissionV1::ConversationRead,
            PendingKind::Subscribe(Box::new(SubscriptionTracker {
                target: SubscriptionTarget::Conversation,
                subscription_generation: None,
                snapshot_cursor: None,
                configuration_revision: None,
                sync_complete: None,
                binding: None,
            })),
        )
    }

    pub(crate) fn start_prompt(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if !self.evidence.conversation_open || self.evidence.prompt_accepted {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let conversation_id = self
            .conversation_id
            .clone()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let configuration_revision = self
            .configuration_revision
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let idempotency_key = IdempotencyKey::new(format!(
            "w2b-prompt-{}",
            self.request_sequence
                .checked_add(1)
                .ok_or(W2PairingError::BusinessCounterExhausted)?
        ));
        let prompt = PromptPayload::new(W2B_PROMPT_TEXT)
            .map_err(|_| W2PairingError::BusinessFrameInvalid)?;
        self.start_request(
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id,
                idempotency_key,
                expected_configuration_revision: configuration_revision,
                prompt,
            }),
            AuthorizationCapabilityV1::Prompt,
            AuthorizationPermissionV1::PromptSend,
            PendingKind::Prompt { terminal: false },
        )
    }

    pub(crate) fn start_approval(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if !self.evidence.approval_pending || self.evidence.approval_receipt_applied {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let conversation_id = self
            .conversation_id
            .clone()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let approval = self
            .approval
            .as_ref()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let (request, permission) = if self.evidence.approval_route_accepted {
            if !self.evidence.approval_event_applied {
                return Err(W2PairingError::BusinessStateInvalid);
            }
            (
                RuntimeRequest::RetryApproval {
                    conversation_id,
                    approval_id: approval.approval_id.clone(),
                },
                AuthorizationPermissionV1::ApprovalRetry,
            )
        } else {
            (
                RuntimeRequest::ResolveApproval {
                    conversation_id,
                    turn_id: approval.turn_id.clone(),
                    approval_id: approval.approval_id.clone(),
                    decision: ActionDecision {
                        request_id: approval.request_id.clone(),
                        decision: ActionDecisionKind::Approve,
                        persist: false,
                    },
                },
                AuthorizationPermissionV1::ApprovalResolve,
            )
        };
        self.start_request(
            request,
            AuthorizationCapabilityV1::Approval,
            permission,
            PendingKind::Approval {
                terminal: false,
                receipt_applied: false,
            },
        )
    }

    pub(crate) fn accept_frame(&mut self, bytes: &[u8]) -> Result<Vec<u8>, W2PairingError> {
        if self.phase != PrincipalPhase::Active {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let decoded = decode(bytes).map_err(|_| self.fail(W2PairingError::BusinessFrameInvalid))?;
        match decoded.body {
            RelayFrameBody::Ping(ping) => {
                Ok(frame(RelayFrameBody::Pong(Pong { nonce: ping.nonce })))
            }
            RelayFrameBody::RouteAccepted(accepted) => {
                let AcceptedRef::Request { request_route } = accepted.accepted else {
                    return Err(self.fail(W2PairingError::BusinessFrameInvalid));
                };
                if let Some(control) = self.pending_control_acks.remove(&request_route) {
                    self.commit_control_ack(&control)?;
                    return Ok(frame(RelayFrameBody::Ack(Ack {
                        stream_route: control.stream_route,
                        generation: control.generation,
                        up_to_seq: control.up_to_seq,
                    })));
                }
                if self.fenced_request_routes.remove(&request_route) {
                    return Ok(Vec::new());
                }
                let pending = self
                    .pending
                    .as_mut()
                    .ok_or(W2PairingError::BusinessStateInvalid)?;
                if pending.request_route != request_route || pending.route_accepted {
                    return Err(self.fail(W2PairingError::BusinessFrameInvalid));
                }
                pending.route_accepted = true;
                self.finish_pending_if_ready();
                Ok(Vec::new())
            }
            RelayFrameBody::Reply(reply) => self.accept_reply(reply),
            RelayFrameBody::Publish(publish) => self
                .accept_publish(publish)
                .map_err(|error| self.fail(error)),
            RelayFrameBody::ReplayComplete(replay) => self.accept_replay_complete(replay),
            RelayFrameBody::Error(_) => Err(self.fail(W2PairingError::BusinessRelayRejected)),
            RelayFrameBody::ServerRestarting(_) => {
                Err(self.fail(W2PairingError::BusinessOutcomeUnknown))
            }
            _ => Err(self.fail(W2PairingError::BusinessFrameInvalid)),
        }
    }

    pub(crate) fn evidence(&self) -> W2BusinessEvidence {
        self.evidence.clone()
    }

    fn start_request(
        &mut self,
        request: RuntimeRequest,
        capability: AuthorizationCapabilityV1,
        permission: AuthorizationPermissionV1,
        kind: PendingKind,
    ) -> Result<Vec<u8>, W2PairingError> {
        if self.phase != PrincipalPhase::Active || self.pending.is_some() {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        if !self.authorization.capabilities.contains(&capability)
            || !self.authorization.permissions.contains(&permission)
        {
            return Err(self.fail(W2PairingError::BusinessAuthorizationDenied));
        }
        let request_route = self.random_request_route()?;
        let sequence = self
            .request_sequence
            .checked_add(1)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        let message_id = MessageId::new(format!("web-w2b-{sequence}"));
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: message_id.clone(),
            body: RuntimeMessage::Request(request),
        };
        let plaintext = envelope
            .to_json_bytes_checked()
            .map_err(|_| W2PairingError::BusinessFrameInvalid)?;
        let next_counter = self
            .command_counter
            .checked_add(1)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        let context = OuterContextV1::uplink_send(
            self.grant.machine_route,
            self.grant.device_route,
            request_route,
            self.command_key.epoch,
        );
        let unsigned = seal_symmetric(
            &self.command_key,
            &context,
            SealedPayloadKind::CommandRequest,
            &plaintext,
            SenderCounter(self.command_counter),
        )
        .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
        let sealed = sign_sealed(unsigned, &self.device_signing_key, &context).to_wire_bytes();
        self.command_counter = next_counter;
        self.request_sequence = sequence;
        self.pending = Some(PendingRequest {
            request_route,
            message_id,
            route_accepted: false,
            kind,
        });
        Ok(frame(RelayFrameBody::Send(Send {
            device_route: self.grant.device_route,
            request_route,
            sealed_blob: SealedBlob(sealed),
        })))
    }

    fn accept_reply(
        &mut self,
        reply: agentdeck_protocol::relay_v2::frame::Reply,
    ) -> Result<Vec<u8>, W2PairingError> {
        let (request_route, expected_message_id) = self
            .pending
            .as_ref()
            .map(|pending| (pending.request_route, pending.message_id.clone()))
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        if reply.device_route != self.grant.device_route || reply.request_route != request_route {
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        let opened = self.open_directed_reply(request_route, &reply.sealed_blob.0)?;
        if opened.payload_kind == SealedPayloadKind::KeyUpdate {
            let control = KeyControlV1::from_canonical_bytes(&opened.payload)
                .map_err(|_| self.fail(W2PairingError::BusinessFrameInvalid))?;
            let KeyControlV1::StreamBinding { binding, .. } = control else {
                return Err(self.fail(W2PairingError::BusinessFrameInvalid));
            };
            self.accept_stream_binding(binding)
        } else {
            let envelope: RuntimeEnvelope = serde_json::from_slice(&opened.payload)
                .map_err(|_| self.fail(W2PairingError::BusinessFrameInvalid))?;
            if envelope.message_id != expected_message_id
                || envelope
                    .to_json_bytes_checked()
                    .map_err(|_| self.fail(W2PairingError::BusinessFrameInvalid))?
                    != opened.payload
            {
                return Err(self.fail(W2PairingError::BusinessFrameInvalid));
            }
            let RuntimeMessage::Reply(runtime_reply) = envelope.body else {
                return Err(self.fail(W2PairingError::BusinessFrameInvalid));
            };
            if let RuntimeReply::Failure(failure) = &runtime_reply
                && failure.code == "daemon.remote.transition.business_fenced"
            {
                self.accept_business_fence(request_route)?;
                return Ok(Vec::new());
            }
            self.accept_runtime_reply(opened.payload_kind, runtime_reply)?;
            self.finish_pending_if_ready();
            Ok(Vec::new())
        }
    }

    fn open_directed_reply(
        &mut self,
        request_route: RequestRouteId,
        sealed_blob: &[u8],
    ) -> Result<agentdeck_protocol::e2ee::SealedPayloadV1, W2PairingError> {
        let signed = SignedSealedBlobV1::from_wire_bytes(sealed_blob)
            .map_err(|_| self.fail(W2PairingError::BusinessCryptoFailed))?;
        let header = &signed.inner;
        if header.key_id != self.reply_key.key_id
            || header.key_epoch != self.reply_key.epoch
            || header.key_directory_revision != self.directory_revision
            || header.nonce[..4] != self.reply_nonce_prefix
        {
            return Err(self.fail(W2PairingError::BusinessCryptoFailed));
        }
        let counter = u64::from_be_bytes(
            header.nonce[4..]
                .try_into()
                .map_err(|_| self.fail(W2PairingError::BusinessCryptoFailed))?,
        );
        if !self.reply_counters.insert(counter) {
            return Err(self.fail(W2PairingError::BusinessCryptoFailed));
        }
        let context = OuterContextV1::directed_reply(
            self.grant.machine_route,
            self.grant.device_route,
            request_route,
            self.reply_key.epoch,
        );
        let verified = verify_sealed(signed, &self.machine_data_verifying_key, &context)
            .map_err(|_| self.fail(W2PairingError::BusinessCryptoFailed))?;
        open_sealed_payload(&self.reply_key, &context, verified)
            .map_err(|_| self.fail(W2PairingError::BusinessCryptoFailed))
    }

    fn accept_business_fence(
        &mut self,
        request_route: RequestRouteId,
    ) -> Result<(), W2PairingError> {
        let pending = self
            .pending
            .take()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        if pending.request_route != request_route {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        if !pending.route_accepted {
            self.fenced_request_routes.insert(request_route);
        }
        self.evidence.business_fence_count = self
            .evidence
            .business_fence_count
            .checked_add(1)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        Ok(())
    }

    fn accept_runtime_reply(
        &mut self,
        payload_kind: SealedPayloadKind,
        reply: RuntimeReply,
    ) -> Result<(), W2PairingError> {
        let mut pending = self
            .pending
            .take()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let result = match (&mut pending.kind, payload_kind, reply) {
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::CommandReceipt,
                RuntimeReply::Subscription(SubscriptionReceipt::Subscribed { stream_generation }),
            ) if tracker.subscription_generation.is_none() => {
                tracker.subscription_generation = Some(stream_generation);
                Ok(())
            }
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::CatalogSnapshot,
                RuntimeReply::Catalog(snapshot),
            ) if tracker.target == SubscriptionTarget::Catalog
                && tracker.subscription_generation.is_some()
                && tracker.snapshot_cursor.is_none() =>
            {
                self.accept_catalog_snapshot(tracker, snapshot)
            }
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::ConversationSnapshot,
                RuntimeReply::Snapshot(snapshot),
            ) if tracker.target == SubscriptionTarget::Conversation
                && tracker.subscription_generation.is_some()
                && tracker.snapshot_cursor.is_none() =>
            {
                self.accept_conversation_snapshot(tracker, snapshot)
            }
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::CommandReceipt,
                RuntimeReply::SyncComplete(sync),
            ) if tracker.subscription_generation.is_some()
                && tracker.snapshot_cursor.is_some()
                && tracker.sync_complete.is_none() =>
            {
                let generation = tracker
                    .subscription_generation
                    .as_ref()
                    .ok_or(W2PairingError::BusinessFrameInvalid)?;
                let snapshot_cursor = tracker
                    .snapshot_cursor
                    .ok_or(W2PairingError::BusinessFrameInvalid)?;
                let expected_inner = match tracker.target {
                    SubscriptionTarget::Catalog => RuntimeInnerCursor::Catalog {
                        cursor: snapshot_cursor,
                    },
                    SubscriptionTarget::Conversation => RuntimeInnerCursor::Conversation {
                        conversation_id: self
                            .conversation_id
                            .clone()
                            .ok_or(W2PairingError::BusinessStateInvalid)?,
                        cursor: snapshot_cursor,
                    },
                };
                if sync.stream_generation != *generation
                    || sync.inner_cursor != expected_inner
                    || sync.key_directory_revision != self.directory_revision
                {
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                tracker.sync_complete = Some(sync);
                Ok(())
            }
            (
                PendingKind::Prompt { terminal },
                SealedPayloadKind::CommandReceipt,
                RuntimeReply::Command(CommandReceipt::Accepted {
                    command_id,
                    configuration_revision,
                    ..
                }),
            ) if !*terminal && Some(configuration_revision) == self.configuration_revision => {
                self.prompt_command_id = Some(command_id);
                *terminal = true;
                Ok(())
            }
            (
                PendingKind::Approval {
                    terminal,
                    receipt_applied,
                },
                SealedPayloadKind::CommandReceipt,
                RuntimeReply::Approval(receipt),
            ) if !*terminal => {
                let approval = self
                    .approval
                    .as_ref()
                    .ok_or(W2PairingError::BusinessStateInvalid)?;
                let claimed = matches!(
                    receipt,
                    ApprovalReceipt::Claimed { ref approval_id }
                        if approval_id == &approval.approval_id
                );
                let applied = matches!(
                    receipt,
                    ApprovalReceipt::Applied { ref approval_id }
                        if approval_id == &approval.approval_id
                ) || matches!(
                    receipt,
                    ApprovalReceipt::AlreadyHandled {
                        ref approval_id,
                        decision: ActionDecisionKind::Approve,
                        state: ApprovalDeliveryState::Applied,
                    } if approval_id == &approval.approval_id
                );
                if !claimed && !applied {
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                *terminal = true;
                *receipt_applied = applied;
                Ok(())
            }
            _ => Err(W2PairingError::BusinessFrameInvalid),
        };
        self.pending = Some(pending);
        result
    }

    fn accept_catalog_snapshot(
        &mut self,
        tracker: &mut SubscriptionTracker,
        snapshot: CatalogSnapshot,
    ) -> Result<(), W2PairingError> {
        if snapshot.current_page_cursor().is_some()
            || snapshot.next_page_cursor().is_some()
            || snapshot.entries().len() != 1
        {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let entry = &snapshot.entries()[0];
        if entry.archived {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        self.conversation_id = Some(entry.conversation_id.clone());
        self.evidence.catalog_entry_count = 1;
        self.evidence.conversation_title = entry.title.clone();
        tracker.snapshot_cursor = Some(snapshot.base_catalog_cursor);
        Ok(())
    }

    fn accept_conversation_snapshot(
        &mut self,
        tracker: &mut SubscriptionTracker,
        snapshot: ConversationSnapshot,
    ) -> Result<(), W2PairingError> {
        if snapshot.conversation_id
            != self
                .conversation_id
                .clone()
                .ok_or(W2PairingError::BusinessStateInvalid)?
        {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let revision = snapshot.configuration_state.configuration_revision();
        if revision == 0 {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        tracker.snapshot_cursor = Some(snapshot.base_event_cursor);
        tracker.configuration_revision = Some(revision);
        Ok(())
    }

    fn accept_stream_binding(
        &mut self,
        binding: StreamBindingV1,
    ) -> Result<Vec<u8>, W2PairingError> {
        let mut pending = self
            .pending
            .take()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let PendingKind::Subscribe(tracker) = &mut pending.kind else {
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        };
        let sync = tracker
            .sync_complete
            .as_ref()
            .ok_or(W2PairingError::BusinessFrameInvalid)?;
        if tracker.binding.is_some()
            || binding.machine_route != self.grant.machine_route
            || binding.device_route != self.grant.device_route
            || binding.grant_serial != self.grant.grant_serial
            || binding.root_trust_epoch != self.grant.trust_epoch
            || binding.key_directory_revision.value() != self.directory_revision
            || binding.stream_cursor != sync.stream_cursor
            || binding.inner_cursor != sync.inner_cursor
            || binding.key_id.purpose
                != match tracker.target {
                    SubscriptionTarget::Catalog => KeyPurpose::Catalog,
                    SubscriptionTarget::Conversation => KeyPurpose::ConversationDek,
                }
        {
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        let matching_keys = self
            .stream_keys
            .iter()
            .filter(|key| stream_key_matches(key, &binding))
            .count();
        if matching_keys != 1 {
            return Err(self.fail(W2PairingError::BusinessCryptoFailed));
        }
        tracker.binding = Some(binding.clone());
        match tracker.target {
            SubscriptionTarget::Catalog => self.catalog_binding = Some(binding.clone()),
            SubscriptionTarget::Conversation => {
                self.configuration_revision = tracker.configuration_revision;
                self.conversation_binding = Some(binding.clone());
            }
        }
        self.pending = Some(pending);
        self.finish_pending_if_ready();
        Ok(frame(RelayFrameBody::Subscribe(Subscribe {
            stream_route: binding.stream_route,
            generation: binding.stream_generation,
            cursor: binding.stream_cursor,
        })))
    }

    fn accept_publish(&mut self, publish: Publish) -> Result<Vec<u8>, W2PairingError> {
        let binding = self
            .binding_for_stream(publish.stream_route, publish.generation)
            .cloned()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        if publish.stream_route != binding.stream_route
            || publish.generation != binding.stream_generation
            || binding.stream_cursor.checked_next().ok() != Some(publish.stream_seq)
        {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let stream_key = self
            .stream_keys
            .iter()
            .find(|key| stream_key_matches(key, &binding))
            .ok_or(W2PairingError::BusinessCryptoFailed)?;
        let signed = SignedSealedBlobV1::from_wire_bytes(&publish.sealed_blob.0)
            .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
        let header = &signed.inner;
        if header.key_id != stream_key.key.key_id
            || header.key_epoch != stream_key.key.epoch
            || header.key_directory_revision != self.directory_revision
            || header.nonce[..4] != stream_key.nonce_prefix
        {
            return Err(W2PairingError::BusinessCryptoFailed);
        }
        let counter = u64::from_be_bytes(
            header.nonce[4..]
                .try_into()
                .map_err(|_| W2PairingError::BusinessCryptoFailed)?,
        );
        if !self.stream_counters.insert((publish.stream_route, counter)) {
            return Err(W2PairingError::BusinessCryptoFailed);
        }
        let context = OuterContextV1 {
            frame_kind: match binding.key_id.purpose {
                KeyPurpose::Catalog => OuterFrameKind::CatalogPublish,
                KeyPurpose::ConversationDek => OuterFrameKind::ConversationPublish,
                KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
            },
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: Some(self.grant.machine_route),
            device_route: None,
            stream_route: Some(publish.stream_route),
            request_route: None,
            pair_route: None,
            stream_generation: Some(publish.generation),
            stream_cursor: None,
            stream_seq: Some(publish.stream_seq),
            message_key_epoch: stream_key.key.epoch,
        };
        let verified = verify_sealed(signed, &self.machine_data_verifying_key, &context)
            .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
        let opened = open_sealed_payload(&stream_key.key, &context, verified)
            .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
        if opened.payload_kind == SealedPayloadKind::KeyUpdate {
            let control = KeyControlV1::from_canonical_bytes(&opened.payload)
                .map_err(|_| W2PairingError::BusinessFrameInvalid)?;
            let KeyControlV1::EpochBarrier {
                stream_route,
                barrier,
                ..
            } = control
            else {
                return Err(W2PairingError::BusinessFrameInvalid);
            };
            if stream_route != publish.stream_route {
                return Err(W2PairingError::BusinessFrameInvalid);
            }
            return self.start_stream_applied_ack(&binding, &publish, barrier);
        }
        if opened.payload_kind != SealedPayloadKind::ConversationEvent {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let envelope: RuntimeEnvelope = serde_json::from_slice(&opened.payload)
            .map_err(|_| W2PairingError::BusinessFrameInvalid)?;
        if envelope
            .to_json_bytes_checked()
            .map_err(|_| W2PairingError::BusinessFrameInvalid)?
            != opened.payload
        {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let RuntimeMessage::Stream(RuntimeStreamItem::Event(event)) = envelope.body else {
            return Err(W2PairingError::BusinessFrameInvalid);
        };
        let event_seq = self.accept_event(event)?;
        let binding = self
            .conversation_binding
            .as_mut()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        binding.stream_cursor = StreamCursor::At(publish.stream_seq);
        binding.inner_cursor = RuntimeInnerCursor::Conversation {
            conversation_id: self
                .conversation_id
                .clone()
                .ok_or(W2PairingError::BusinessStateInvalid)?,
            cursor: StreamCursor::At(event_seq),
        };
        self.evidence.outer_ack_count = self
            .evidence
            .outer_ack_count
            .checked_add(1)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        Ok(frame(RelayFrameBody::Ack(Ack {
            stream_route: publish.stream_route,
            generation: publish.generation,
            up_to_seq: publish.stream_seq,
        })))
    }

    fn accept_event(&mut self, event: RuntimeEvent) -> Result<u64, W2PairingError> {
        let conversation_id = self
            .conversation_id
            .as_ref()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let binding = self
            .conversation_binding
            .as_ref()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let RuntimeInnerCursor::Conversation { cursor, .. } = &binding.inner_cursor else {
            return Err(W2PairingError::BusinessFrameInvalid);
        };
        if &event.conversation_id != conversation_id
            || cursor.checked_next().ok() != Some(event.event_seq)
        {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let command_matches = self
            .prompt_command_id
            .as_ref()
            .is_some_and(|command_id| event.command_id.as_ref() == Some(command_id));
        let event_seq = event.event_seq;
        match event.body {
            RuntimeEventBody::TurnStarted { turn_id } if command_matches => {
                self.prompt_turn_id = Some(turn_id);
            }
            RuntimeEventBody::Item {
                item: AgentItem::AssistantMessage { text, .. },
            } if command_matches && text == EXPECTED_ASSISTANT_TEXT => {
                self.evidence.assistant_observed = true;
            }
            RuntimeEventBody::ActionRequest {
                turn_id,
                approval_id,
                request,
            } if command_matches
                && self.prompt_turn_id.as_ref() == Some(&turn_id)
                && request.summary == EXPECTED_APPROVAL_SUMMARY =>
            {
                self.approval = Some(ApprovalContext {
                    turn_id,
                    approval_id,
                    request_id: request.request_id,
                });
                self.evidence.approval_pending = true;
                self.evidence.approval_summary_matched = true;
            }
            RuntimeEventBody::ApprovalResolved {
                turn_id,
                approval_id,
                decision: Some(ActionDecisionKind::Approve),
                state: ApprovalDeliveryState::Applied,
            } if command_matches
                && self.approval.as_ref().is_some_and(|approval| {
                    approval.turn_id == turn_id && approval.approval_id == approval_id
                }) =>
            {
                self.evidence.approval_event_applied = true;
            }
            RuntimeEventBody::TurnCompleted { turn_id, .. }
                if command_matches && self.prompt_turn_id.as_ref() == Some(&turn_id) =>
            {
                self.evidence.command_completed = true;
            }
            RuntimeEventBody::Capabilities { .. }
            | RuntimeEventBody::ConfigurationChanged { .. }
            | RuntimeEventBody::VendorPanelEvent { .. }
            | RuntimeEventBody::Item { .. }
            | RuntimeEventBody::TurnStarted { .. }
            | RuntimeEventBody::ActionRequest { .. }
            | RuntimeEventBody::ApprovalResolved { .. } => {}
            RuntimeEventBody::TurnCompleted { .. }
            | RuntimeEventBody::TurnInterrupted { .. }
            | RuntimeEventBody::Error { .. } => {
                return Err(W2PairingError::BusinessFrameInvalid);
            }
        }
        Ok(event_seq)
    }

    fn start_stream_applied_ack(
        &mut self,
        binding: &StreamBindingV1,
        publish: &Publish,
        barrier: EpochBarrierV1,
    ) -> Result<Vec<u8>, W2PairingError> {
        if barrier.old_epoch != 0
            || barrier.new_epoch != binding.key_id.epoch
            || barrier.stream_generation != binding.stream_generation
            || barrier.stream_cursor != binding.stream_cursor
            || barrier.inner_cursor != binding.inner_cursor
            || barrier.key_directory_revision.value() != self.directory_revision
            || barrier.stream_cursor.checked_next().ok() != Some(publish.stream_seq)
        {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let request_route = self.random_request_route()?;
        if self.pending_control_acks.contains_key(&request_route) {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let next_counter = self
            .command_counter
            .checked_add(1)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        let ack = StreamAppliedAckV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.grant.machine_route,
            device_route: self.grant.device_route,
            grant_serial: self.grant.grant_serial,
            root_trust_epoch: self.grant.trust_epoch,
            stream_route: publish.stream_route,
            stream_generation: publish.generation,
            applied_stream_seq: publish.stream_seq,
            inner_cursor: barrier.inner_cursor.clone(),
            key_directory_revision: KeyDirectoryRevision::new(self.directory_revision),
            key_epoch: barrier.new_epoch,
            epoch_barrier_sha256: barrier
                .canonical_sha256()
                .map_err(|_| W2PairingError::BusinessFrameInvalid)?,
        };
        ack.validate()
            .map_err(|_| W2PairingError::BusinessFrameInvalid)?;
        let control = KeyControlRequestV1::stream_applied_ack(ack);
        let plaintext = control
            .canonical_bytes()
            .map_err(|_| W2PairingError::BusinessFrameInvalid)?;
        let context = OuterContextV1::uplink_send(
            self.grant.machine_route,
            self.grant.device_route,
            request_route,
            self.command_key.epoch,
        );
        let unsigned = seal_symmetric(
            &self.command_key,
            &context,
            control.sealed_payload_kind(),
            &plaintext,
            SenderCounter(self.command_counter),
        )
        .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
        let sealed = sign_sealed(unsigned, &self.device_signing_key, &context).to_wire_bytes();
        self.command_counter = next_counter;
        self.pending_control_acks.insert(
            request_route,
            PendingControlAck {
                stream_route: publish.stream_route,
                generation: publish.generation,
                up_to_seq: publish.stream_seq,
                inner_cursor: barrier.inner_cursor,
            },
        );
        Ok(frame(RelayFrameBody::Send(Send {
            device_route: self.grant.device_route,
            request_route,
            sealed_blob: SealedBlob(sealed),
        })))
    }

    fn commit_control_ack(&mut self, control: &PendingControlAck) -> Result<(), W2PairingError> {
        let binding = self
            .binding_for_stream_mut(control.stream_route, control.generation)
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        if binding.stream_cursor.checked_next().ok() != Some(control.up_to_seq)
            || binding.inner_cursor != control.inner_cursor
        {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let purpose = binding.key_id.purpose;
        binding.stream_cursor = StreamCursor::At(control.up_to_seq);
        self.evidence.outer_ack_count = self
            .evidence
            .outer_ack_count
            .checked_add(1)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        if self.pending_replay_completes.remove(&(
            control.stream_route,
            control.generation,
            control.up_to_seq,
        )) {
            self.mark_subscription_active(purpose)?;
        }
        Ok(())
    }

    fn binding_for_stream(
        &self,
        stream_route: StreamRouteId,
        generation: StreamGenerationId,
    ) -> Option<&StreamBindingV1> {
        [&self.catalog_binding, &self.conversation_binding]
            .into_iter()
            .flatten()
            .find(|binding| {
                binding.stream_route == stream_route && binding.stream_generation == generation
            })
    }

    fn binding_for_stream_mut(
        &mut self,
        stream_route: StreamRouteId,
        generation: StreamGenerationId,
    ) -> Option<&mut StreamBindingV1> {
        [&mut self.catalog_binding, &mut self.conversation_binding]
            .into_iter()
            .find_map(|candidate| {
                candidate.as_mut().filter(|binding| {
                    binding.stream_route == stream_route && binding.stream_generation == generation
                })
            })
    }

    fn accept_replay_complete(
        &mut self,
        replay: ReplayComplete,
    ) -> Result<Vec<u8>, W2PairingError> {
        let binding = self
            .binding_for_stream(replay.stream_route, replay.generation)
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        if replay.current_cursor != binding.stream_cursor {
            let pending = self.pending_control_acks.values().find(|control| {
                control.stream_route == replay.stream_route
                    && control.generation == replay.generation
                    && replay.current_cursor == StreamCursor::At(control.up_to_seq)
            });
            let Some(pending) = pending else {
                return Err(self.fail(W2PairingError::BusinessFrameInvalid));
            };
            self.pending_replay_completes.insert((
                pending.stream_route,
                pending.generation,
                pending.up_to_seq,
            ));
            return Ok(Vec::new());
        }
        let purpose = binding.key_id.purpose;
        self.mark_subscription_active(purpose)?;
        Ok(Vec::new())
    }

    fn mark_subscription_active(&mut self, purpose: KeyPurpose) -> Result<(), W2PairingError> {
        match purpose {
            KeyPurpose::Catalog => self.evidence.catalog_subscription_active = true,
            KeyPurpose::ConversationDek => self.evidence.relay_subscription_active = true,
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
                return Err(self.fail(W2PairingError::BusinessFrameInvalid));
            }
        }
        Ok(())
    }

    fn finish_pending_if_ready(&mut self) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let terminal = match &pending.kind {
            PendingKind::Prompt { terminal }
            | PendingKind::Approval {
                terminal,
                receipt_applied: _,
            } => *terminal,
            PendingKind::Subscribe(tracker) => tracker.binding.is_some(),
        };
        if !pending.route_accepted || !terminal {
            return;
        }
        match &pending.kind {
            PendingKind::Subscribe(tracker) => match tracker.target {
                SubscriptionTarget::Catalog => self.evidence.catalog_route_accepted = true,
                SubscriptionTarget::Conversation => {
                    self.evidence.conversation_route_accepted = true;
                    self.evidence.conversation_open = true;
                }
            },
            PendingKind::Prompt { .. } => {
                self.evidence.prompt_route_accepted = true;
                self.evidence.prompt_accepted = true;
            }
            PendingKind::Approval {
                receipt_applied, ..
            } => {
                self.evidence.approval_route_accepted = true;
                self.evidence.approval_receipt_applied |= *receipt_applied;
            }
        }
        self.pending = None;
    }

    fn random_request_route(&mut self) -> Result<RequestRouteId, W2PairingError> {
        for _ in 0..4 {
            let mut bytes = [0_u8; 16];
            self.rng
                .try_fill_bytes(&mut bytes)
                .map_err(|_| W2PairingError::EntropyUnavailable)?;
            if bytes != [0; 16] {
                return Ok(RequestRouteId::from_bytes(bytes));
            }
        }
        Err(W2PairingError::EntropyUnavailable)
    }

    fn fail(&mut self, error: W2PairingError) -> W2PairingError {
        self.phase = PrincipalPhase::Failed;
        error
    }
}

fn stream_key_matches(key: &StreamKey, binding: &StreamBindingV1) -> bool {
    key.key.key_id == binding.key_id
        && key.key.epoch == binding.key_id.epoch
        && match binding.key_id.purpose {
            KeyPurpose::Catalog => key.stream_route.is_none(),
            KeyPurpose::ConversationDek => key.stream_route == Some(binding.stream_route),
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => false,
        }
}

fn frame(body: RelayFrameBody) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    })
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
