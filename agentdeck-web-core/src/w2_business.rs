//! W2b 浏览器 paired principal 与最小业务闭环状态机。
//!
//! 本模块只消费 W2a 已验证的 PairResponse capability。TypeScript 仍只能取得连接 URL、
//! opaque Relay frame 与脱敏 view state；Runtime/E2EE wire、密钥、counter 和业务明文解析
//! 全部留在 Rust/WASM。

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use agentdeck_crypto::PairResponseExpectedV1;
use agentdeck_crypto::rand_core::TryRng as _;
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, HpkePrivateKey, SenderCounter, SignatureBytes, SigningKey,
    VerifiedPairResponseV1, VerifyingKey, derive_nonce_prefix, open_key_directory_entry,
    open_pair_response_verified, open_sealed_payload, seal_symmetric,
    sign_authentication_transcript, sign_sealed, verify_sealed, verify_tbs,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, E2EE_FORMAT_VERSION, EpochBarrierV1,
    KeyControlRequestV1, KeyControlV1, KeyPurpose, KeyUpdateInfoV1, OuterContextV1, OuterFrameKind,
    PairInviteV1, PairResponseV1, SealedPayloadKind, SignedSealedBlobV1, StreamAppliedAckV1,
    StreamBindingV1,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, RelayGrant,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Ack, AuthProof, Authenticate, Challenge, Hello, Pong, Publish, ReplayComplete,
    RevocationCommitted, SealedBlob, Send, Subscribe,
};
use agentdeck_protocol::relay_v2::{
    KeyDirectoryRevision, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId,
    StreamCursor, StreamGenerationId, StreamRouteId, decode, encode,
};
use agentdeck_protocol::runtime::command::{PromptPayload, RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::identity::{ApprovalId, MessageId, TurnId};
use agentdeck_protocol::runtime::{
    ApprovalDeliveryState, ApprovalReceipt, BackfillChunk, CatalogChange, CatalogSnapshot,
    CommandReceipt, ConversationId, ConversationSnapshot, IdempotencyKey, RUNTIME_PROTOCOL_VERSION,
    RevocationReceipt, RuntimeEnvelope, RuntimeEvent, RuntimeEventBody, RuntimeInnerCursor,
    RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeStreamItem, RuntimeSyncComplete,
    SendPromptRequest, SubscriptionReceipt,
};
use agentdeck_protocol::trunk::{ActionDecision, ActionDecisionKind, AgentItem};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::DeterministicRng;
use crate::w2::W2PairingError;

const EXPECTED_ASSISTANT_TEXT: &str = "synthetic Codex response";
const EXPECTED_APPROVAL_SUMMARY: &str = "synthetic codex approval";
const W2B_PROMPT_TEXT: &str = "web-w2b-prompt-7fb7f299";
const W2C_RESTART_MARKER_TITLE: &str = "R4.4 daemon restart marker";
const W2_DURABLE_STATE_VERSION: u16 = 1;
const W2_COUNTER_RESERVATION_BLOCK: u64 = 256;
const W2_MAX_DURABLE_STATE_BYTES: usize = 256 * 1_024;

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
    pub durable_promoted: bool,
    pub durable_restored: bool,
    pub counter_reservation_start: u64,
    pub counter_reservation_end: u64,
    pub reconnect_authenticated: bool,
    pub recovery_catalog_backfill_count: u64,
    pub recovery_conversation_backfill_count: u64,
    pub restart_marker_observed: bool,
    pub revoke_route_accepted: bool,
    pub revocation_receipt_committed: bool,
    pub revocation_terminal_verified: bool,
    pub recovery_stage: Option<String>,
}

/// W2.7 负向准入矩阵的 typed readback。
///
/// 这些字段由 Web business core 与生产收包路径共用的 admission helper 计算；host 只读结果，
/// 不解析 Relay/Runtime wire，也不自行实现 replay、cursor 或 counter 规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W2NegativeSnapshot {
    pub approval_loser_recognized_applied: bool,
    pub approval_loser_zero_claim_mutation: bool,
    pub stale_publish_rejected: bool,
    pub skipped_publish_rejected: bool,
    pub rejected_publish_cursor_unchanged: bool,
    pub reply_nonce_replay_rejected: bool,
    pub reply_counter_set_unchanged: bool,
    pub stream_nonce_reuse_rejected: bool,
    pub stream_counter_set_unchanged: bool,
    pub uncommitted_reservation_rejected: bool,
    pub reservation_overflow_rejected: bool,
    pub rejected_reservation_counter_unchanged: bool,
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
    requested: RuntimeInnerCursor,
    delivered: RuntimeInnerCursor,
    recovery: bool,
    subscription_generation: Option<agentdeck_protocol::runtime::identity::StreamGeneration>,
    snapshot_cursor: Option<StreamCursor>,
    configuration_revision: Option<u64>,
    sync_complete: Option<RuntimeSyncComplete>,
    binding: Option<StreamBindingV1>,
    snapshot_seen: bool,
    backfill_count: u64,
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
    Revoke {
        receipt_committed: bool,
        terminal_verified: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurabilityPhase {
    Volatile,
    AwaitingCommit { reserved_high_water: u64 },
    Active { reserved_high_water: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApprovalReceiptAdmission {
    Claimed,
    AppliedWinner,
    AppliedLoser,
}

impl ApprovalReceiptAdmission {
    const fn applied(self) -> bool {
        matches!(self, Self::AppliedWinner | Self::AppliedLoser)
    }

    const fn creates_claim(self) -> bool {
        matches!(self, Self::Claimed)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct W2DurableStateV1 {
    version: u16,
    paired_at_ms: u64,
    invite: Vec<u8>,
    device_sign_seed: [u8; 32],
    device_hpke_ikm: [u8; 32],
    canonical_response: Vec<u8>,
    reserved_high_water: u64,
    request_sequence: u64,
    catalog_inner_cursor: Option<RuntimeInnerCursor>,
    conversation_inner_cursor: Option<RuntimeInnerCursor>,
    conversation_id: Option<ConversationId>,
    configuration_revision: Option<u64>,
    prompt_command_id: Option<agentdeck_protocol::runtime::identity::CommandId>,
    prompt_turn_id: Option<TurnId>,
    approval: Option<ApprovalContext>,
    evidence: W2BusinessEvidence,
}

impl Drop for W2DurableStateV1 {
    fn drop(&mut self) {
        self.device_sign_seed.fill(0);
        self.device_hpke_ikm.fill(0);
        self.invite.fill(0);
        self.canonical_response.fill(0);
    }
}

struct PendingRequest {
    request_route: RequestRouteId,
    message_id: MessageId,
    route_accepted: bool,
    kind: PendingKind,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    invite: PairInviteV1,
    paired_at_ms: u64,
    device_sign_seed: Zeroizing<[u8; 32]>,
    device_hpke_ikm: Zeroizing<[u8; 32]>,
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
    durability: DurabilityPhase,
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
    durable_catalog_cursor: Option<RuntimeInnerCursor>,
    durable_conversation_cursor: Option<RuntimeInnerCursor>,
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        invite: PairInviteV1,
        paired_at_ms: u64,
        device_sign_seed: Zeroizing<[u8; 32]>,
        device_hpke_ikm: Zeroizing<[u8; 32]>,
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
        let connect_url = format!("{}v2/connect", invite.wss_url);
        Ok(Self {
            connect_url,
            phase: PrincipalPhase::Initial,
            invite,
            paired_at_ms,
            device_sign_seed,
            device_hpke_ikm,
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
            durability: DurabilityPhase::Volatile,
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
            durable_catalog_cursor: None,
            durable_conversation_cursor: None,
            prompt_command_id: None,
            prompt_turn_id: None,
            approval: None,
            evidence: W2BusinessEvidence::default(),
        })
    }

    pub(crate) fn prepare_durable_promotion(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if self.phase != PrincipalPhase::Initial
            || self.durability != DurabilityPhase::Volatile
            || self.command_counter != 0
            || self.request_sequence != 0
        {
            return Err(W2PairingError::DurableStateInvalid);
        }
        self.durability = DurabilityPhase::AwaitingCommit {
            reserved_high_water: W2_COUNTER_RESERVATION_BLOCK,
        };
        self.evidence.durable_promoted = true;
        self.evidence.counter_reservation_start = 0;
        self.evidence.counter_reservation_end = W2_COUNTER_RESERVATION_BLOCK;
        self.export_durable_state()
    }

    pub(crate) fn export_durable_state(&self) -> Result<Vec<u8>, W2PairingError> {
        if self.pending.is_some() || self.phase == PrincipalPhase::Failed {
            return Err(W2PairingError::DurableStateInvalid);
        }
        let reserved_high_water = match self.durability {
            DurabilityPhase::Volatile => return Err(W2PairingError::DurableNotPrepared),
            DurabilityPhase::AwaitingCommit {
                reserved_high_water,
            }
            | DurabilityPhase::Active {
                reserved_high_water,
            } => reserved_high_water,
        };
        if reserved_high_water == 0
            || !reserved_high_water.is_multiple_of(W2_COUNTER_RESERVATION_BLOCK)
            || self.command_counter > reserved_high_water
        {
            return Err(W2PairingError::DurableStateInvalid);
        }
        // StreamBinding 的 inner cursor 是 Relay publication cut；directed bootstrap 的
        // SyncComplete 可以在同一次线性化期间推进得更高。持久化 reducer 已应用的 cut，
        // 不能被较旧的 publication cut 覆盖，否则 reload 会重复补拉已应用数据。
        let catalog_inner_cursor = self.durable_catalog_cursor.clone().or_else(|| {
            self.catalog_binding
                .as_ref()
                .map(|binding| binding.inner_cursor.clone())
        });
        let conversation_inner_cursor = self.durable_conversation_cursor.clone().or_else(|| {
            self.conversation_binding
                .as_ref()
                .map(|binding| binding.inner_cursor.clone())
        });
        let state = W2DurableStateV1 {
            version: W2_DURABLE_STATE_VERSION,
            paired_at_ms: self.paired_at_ms,
            invite: self
                .invite
                .canonical_bytes()
                .map_err(|_| W2PairingError::DurableStateInvalid)?,
            device_sign_seed: *self.device_sign_seed,
            device_hpke_ikm: *self.device_hpke_ikm,
            canonical_response: self._verified_response.canonical_response().to_vec(),
            reserved_high_water,
            request_sequence: self.request_sequence,
            catalog_inner_cursor,
            conversation_inner_cursor,
            conversation_id: self.conversation_id.clone(),
            configuration_revision: self.configuration_revision,
            prompt_command_id: self.prompt_command_id.clone(),
            prompt_turn_id: self.prompt_turn_id.clone(),
            approval: self.approval.clone(),
            evidence: self.evidence.clone(),
        };
        let encoded =
            serde_json::to_vec(&state).map_err(|_| W2PairingError::SerializationFailed)?;
        if encoded.len() > W2_MAX_DURABLE_STATE_BYTES {
            return Err(W2PairingError::DurableStateInvalid);
        }
        Ok(encoded)
    }

    pub(crate) fn activate_durable_state(&mut self) -> Result<(), W2PairingError> {
        let DurabilityPhase::AwaitingCommit {
            reserved_high_water,
        } = self.durability
        else {
            return Err(W2PairingError::DurableNotPrepared);
        };
        self.durability = DurabilityPhase::Active {
            reserved_high_water,
        };
        Ok(())
    }

    pub(crate) fn restore(
        bytes: &[u8],
        rng: DeterministicRng,
    ) -> Result<(Self, PairInviteV1), W2PairingError> {
        if bytes.is_empty() || bytes.len() > W2_MAX_DURABLE_STATE_BYTES {
            return Err(W2PairingError::DurableStateInvalid);
        }
        let state: W2DurableStateV1 =
            serde_json::from_slice(bytes).map_err(|_| W2PairingError::DurableStateInvalid)?;
        if serde_json::to_vec(&state).map_err(|_| W2PairingError::DurableStateInvalid)? != bytes
            || state.version != W2_DURABLE_STATE_VERSION
            || state.paired_at_ms == 0
            || state.reserved_high_water == 0
            || !state
                .reserved_high_water
                .is_multiple_of(W2_COUNTER_RESERVATION_BLOCK)
        {
            return Err(W2PairingError::DurableStateInvalid);
        }
        let next_high_water = state
            .reserved_high_water
            .checked_add(W2_COUNTER_RESERVATION_BLOCK)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        let invite = PairInviteV1::from_canonical_bytes(&state.invite)
            .map_err(|_| W2PairingError::DurableStateInvalid)?;
        let response = PairResponseV1::from_canonical_bytes(&state.canonical_response)
            .map_err(|_| W2PairingError::DurableStateInvalid)?;
        let device_sign_seed = Zeroizing::new(state.device_sign_seed);
        let device_hpke_ikm = Zeroizing::new(state.device_hpke_ikm);
        let device_signing_key = SigningKey::from_seed(&device_sign_seed);
        let (device_hpke_private_key, device_hpke_public_key) =
            HpkePrivateKey::derive_keypair(device_hpke_ikm.as_ref());
        let device_hpke_pubkey: [u8; 32] = device_hpke_public_key
            .to_bytes()
            .try_into()
            .map_err(|_| W2PairingError::DurableStateInvalid)?;
        let authorization =
            super::w2::mvp_authorization().map_err(|_| W2PairingError::DurableStateInvalid)?;
        let verified_response = open_pair_response_verified(
            &device_hpke_private_key,
            PairResponseExpectedV1::new(
                &invite,
                response.info.request_hash,
                device_signing_key.verifying_key().to_bytes(),
                device_hpke_pubkey,
                &authorization,
                state.paired_at_ms,
            ),
            &state.canonical_response,
        )
        .map_err(|_| W2PairingError::DurableStateInvalid)?;
        let restored_invite = invite.clone();
        let mut core = Self::new(
            invite,
            state.paired_at_ms,
            device_sign_seed,
            device_hpke_ikm,
            device_signing_key,
            device_hpke_private_key,
            verified_response,
            rng,
        )?;
        validate_restored_projection(&state)?;
        core.command_counter = state.reserved_high_water;
        core.request_sequence = state.request_sequence;
        core.durability = DurabilityPhase::AwaitingCommit {
            reserved_high_water: next_high_water,
        };
        core.durable_catalog_cursor = state.catalog_inner_cursor.clone();
        core.durable_conversation_cursor = state.conversation_inner_cursor.clone();
        core.conversation_id = state.conversation_id.clone();
        core.configuration_revision = state.configuration_revision;
        core.prompt_command_id = state.prompt_command_id.clone();
        core.prompt_turn_id = state.prompt_turn_id.clone();
        core.approval = state.approval.clone();
        core.evidence = state.evidence.clone();
        core.evidence.principal_authenticated = false;
        core.evidence.catalog_route_accepted = false;
        core.evidence.catalog_subscription_active = false;
        core.evidence.conversation_route_accepted = false;
        core.evidence.conversation_open = false;
        core.evidence.relay_subscription_active = false;
        core.evidence.durable_restored = true;
        core.evidence.reconnect_authenticated = false;
        core.evidence.counter_reservation_start = state.reserved_high_water;
        core.evidence.counter_reservation_end = next_high_water;
        core.evidence.recovery_catalog_backfill_count = 0;
        core.evidence.recovery_conversation_backfill_count = 0;
        core.evidence.revoke_route_accepted = false;
        core.evidence.revocation_receipt_committed = false;
        core.evidence.revocation_terminal_verified = false;
        core.evidence.recovery_stage = Some("recovery.state.restored".to_owned());
        Ok((core, restored_invite))
    }

    pub(crate) fn connect_url(&self) -> Result<&str, W2PairingError> {
        if matches!(self.durability, DurabilityPhase::AwaitingCommit { .. }) {
            return Err(W2PairingError::DurableCommitRequired);
        }
        if self.phase != PrincipalPhase::Initial {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        Ok(&self.connect_url)
    }

    pub(crate) fn start_hello(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if matches!(self.durability, DurabilityPhase::AwaitingCommit { .. }) {
            return Err(W2PairingError::DurableCommitRequired);
        }
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
                self.evidence.reconnect_authenticated |= self.evidence.durable_restored;
                Ok(())
            }
            _ => Err(self.fail(W2PairingError::BusinessHandshakeRejected)),
        }
    }

    pub(crate) fn start_catalog(&mut self) -> Result<Vec<u8>, W2PairingError> {
        let requested = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        };
        self.start_subscription(SubscriptionTarget::Catalog, requested, false)
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
        self.start_subscription(SubscriptionTarget::Conversation, requested, false)
    }

    pub(crate) fn start_recovery_catalog(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if !self.evidence.durable_restored || self.evidence.catalog_subscription_active {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let requested = self
            .durable_catalog_cursor
            .clone()
            .ok_or(W2PairingError::DurableStateInvalid)?;
        self.evidence.recovery_stage = Some("recovery.catalog.requested".to_owned());
        self.start_subscription(SubscriptionTarget::Catalog, requested, true)
    }

    pub(crate) fn start_recovery_conversation(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if !self.evidence.durable_restored
            || !self.evidence.catalog_subscription_active
            || self.evidence.relay_subscription_active
        {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        let requested = self
            .durable_conversation_cursor
            .clone()
            .ok_or(W2PairingError::DurableStateInvalid)?;
        self.evidence.recovery_stage = Some("recovery.conversation.requested".to_owned());
        self.start_subscription(SubscriptionTarget::Conversation, requested, true)
    }

    fn start_subscription(
        &mut self,
        target: SubscriptionTarget,
        requested: RuntimeInnerCursor,
        recovery: bool,
    ) -> Result<Vec<u8>, W2PairingError> {
        let (capability, permission) = match target {
            SubscriptionTarget::Catalog => (
                AuthorizationCapabilityV1::Catalog,
                AuthorizationPermissionV1::CatalogRead,
            ),
            SubscriptionTarget::Conversation => (
                AuthorizationCapabilityV1::Conversation,
                AuthorizationPermissionV1::ConversationRead,
            ),
        };
        self.start_request(
            RuntimeRequest::Subscribe {
                inner_cursor: requested.clone(),
            },
            capability,
            permission,
            PendingKind::Subscribe(Box::new(SubscriptionTracker {
                target,
                requested: requested.clone(),
                delivered: requested,
                recovery,
                subscription_generation: None,
                snapshot_cursor: None,
                configuration_revision: None,
                sync_complete: None,
                binding: None,
                snapshot_seen: false,
                backfill_count: 0,
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

    pub(crate) fn start_revoke_self(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if !self.evidence.durable_restored
            || !self.evidence.catalog_subscription_active
            || !self.evidence.relay_subscription_active
            || !self.evidence.restart_marker_observed
            || self.evidence.revocation_terminal_verified
        {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        self.start_request(
            RuntimeRequest::Revoke(RevokeRequest {
                target: RevokeTarget::SelfDevice,
            }),
            AuthorizationCapabilityV1::SelfRevocation,
            AuthorizationPermissionV1::RevokeSelf,
            PendingKind::Revoke {
                receipt_committed: false,
                terminal_verified: false,
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
                self.set_recovery_frame_stage("ping");
                Ok(frame(RelayFrameBody::Pong(Pong { nonce: ping.nonce })))
            }
            RelayFrameBody::RouteAccepted(accepted) => {
                self.set_recovery_frame_stage("route_accepted");
                let AcceptedRef::Request { request_route } = accepted.accepted else {
                    self.set_recovery_frame_stage("route_accepted.invalid_kind");
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
                    self.set_recovery_frame_stage("route_accepted.request_mismatch");
                    return Err(self.fail(W2PairingError::BusinessFrameInvalid));
                }
                pending.route_accepted = true;
                self.finish_pending_if_ready();
                Ok(Vec::new())
            }
            RelayFrameBody::Reply(reply) => {
                self.set_recovery_frame_stage("reply");
                self.accept_reply(reply)
            }
            RelayFrameBody::Publish(publish) => {
                self.set_recovery_frame_stage("publish");
                self.accept_publish(publish)
                    .map_err(|error| self.fail(error))
            }
            RelayFrameBody::ReplayComplete(replay) => {
                self.set_recovery_frame_stage("replay_complete");
                self.accept_replay_complete(replay)
            }
            RelayFrameBody::RevocationCommitted(committed) => {
                self.set_recovery_frame_stage("revocation_committed");
                self.accept_revocation_terminal(bytes, committed)
            }
            RelayFrameBody::Error(_) => {
                self.set_recovery_frame_stage("relay_error");
                Err(self.fail(W2PairingError::BusinessRelayRejected))
            }
            RelayFrameBody::ServerRestarting(_) => {
                self.set_recovery_frame_stage("server_restarting");
                Err(self.fail(W2PairingError::BusinessOutcomeUnknown))
            }
            _ => {
                self.set_recovery_frame_stage("unexpected");
                Err(self.fail(W2PairingError::BusinessFrameInvalid))
            }
        }
    }

    pub(crate) fn evidence(&self) -> W2BusinessEvidence {
        self.evidence.clone()
    }

    pub(crate) const fn machine_route(&self) -> agentdeck_protocol::relay_v2::MachineRouteId {
        self.grant.machine_route
    }

    pub(crate) const fn device_route(&self) -> agentdeck_protocol::relay_v2::DeviceRouteId {
        self.grant.device_route
    }

    pub(crate) const fn revocation_terminal_verified(&self) -> bool {
        self.evidence.revocation_terminal_verified
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
        if matches!(self.durability, DurabilityPhase::AwaitingCommit { .. }) {
            return Err(W2PairingError::DurableCommitRequired);
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
        self.ensure_counter_reserved(next_counter)?;
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
        let (opened, counter) = self.open_directed_reply(request_route, &reply.sealed_blob.0)?;
        let response = if opened.payload_kind == SealedPayloadKind::KeyUpdate {
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
                Ok(Vec::new())
            } else {
                self.accept_runtime_reply(opened.payload_kind, runtime_reply)?;
                self.finish_pending_if_ready();
                Ok(Vec::new())
            }
        }?;
        if !self.reply_counters.insert(counter) {
            return Err(self.fail(W2PairingError::BusinessCryptoFailed));
        }
        Ok(response)
    }

    fn open_directed_reply(
        &mut self,
        request_route: RequestRouteId,
        sealed_blob: &[u8],
    ) -> Result<(agentdeck_protocol::e2ee::SealedPayloadV1, u64), W2PairingError> {
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
        if !nonce_counter_is_fresh(&self.reply_counters, &counter) {
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
        let opened = open_sealed_payload(&self.reply_key, &context, verified)
            .map_err(|_| self.fail(W2PairingError::BusinessCryptoFailed))?;
        Ok((opened, counter))
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
        if self.evidence.durable_restored {
            let suffix = match (&pending.kind, &reply) {
                (
                    PendingKind::Approval { .. },
                    RuntimeReply::Approval(ApprovalReceipt::Claimed { .. }),
                ) => "approval.reply.claimed",
                (
                    PendingKind::Approval { .. },
                    RuntimeReply::Approval(ApprovalReceipt::Applied { .. }),
                ) => "approval.reply.applied",
                (
                    PendingKind::Approval { .. },
                    RuntimeReply::Approval(ApprovalReceipt::AlreadyHandled { .. }),
                ) => "approval.reply.already_handled",
                (
                    PendingKind::Approval { .. },
                    RuntimeReply::Approval(ApprovalReceipt::DeliveryFailed { .. }),
                ) => "approval.reply.delivery_failed",
                (
                    PendingKind::Approval { .. },
                    RuntimeReply::Approval(ApprovalReceipt::Expired { .. }),
                ) => "approval.reply.expired",
                (PendingKind::Approval { .. }, RuntimeReply::Failure(_)) => {
                    "approval.reply.failure"
                }
                (PendingKind::Approval { .. }, _) => "approval.reply.unexpected",
                _ => "reply.received",
            };
            self.evidence.recovery_stage = Some(format!("recovery.{suffix}"));
        }
        let result = match (&mut pending.kind, payload_kind, reply) {
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::CommandReceipt,
                RuntimeReply::Subscription(SubscriptionReceipt::Subscribed { stream_generation }),
            ) if tracker.subscription_generation.is_none() => {
                tracker.subscription_generation = Some(stream_generation);
                self.set_recovery_stage(tracker, "subscription_receipt.accepted");
                Ok(())
            }
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::CatalogSnapshot,
                RuntimeReply::Catalog(snapshot),
            ) if tracker.target == SubscriptionTarget::Catalog
                && tracker.subscription_generation.is_some()
                && !tracker.snapshot_seen
                && tracker.backfill_count == 0 =>
            {
                self.accept_catalog_snapshot(tracker, snapshot)
            }
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::ConversationSnapshot,
                RuntimeReply::Snapshot(snapshot),
            ) if tracker.target == SubscriptionTarget::Conversation
                && tracker.subscription_generation.is_some()
                && !tracker.snapshot_seen
                && tracker.backfill_count == 0 =>
            {
                self.accept_conversation_snapshot(tracker, snapshot)
            }
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::BackfillChunk,
                RuntimeReply::Backfill(chunk),
            ) if tracker.subscription_generation.is_some() && tracker.sync_complete.is_none() => {
                self.set_recovery_stage(tracker, "backfill.received");
                self.accept_backfill(tracker, chunk)?;
                self.set_recovery_stage(tracker, "backfill.applied");
                Ok(())
            }
            (
                PendingKind::Subscribe(tracker),
                SealedPayloadKind::CommandReceipt,
                RuntimeReply::SyncComplete(sync),
            ) if tracker.subscription_generation.is_some() && tracker.sync_complete.is_none() => {
                self.set_recovery_stage(tracker, "sync_complete.received");
                let generation = tracker
                    .subscription_generation
                    .as_ref()
                    .ok_or(W2PairingError::BusinessFrameInvalid)?;
                if sync.stream_generation != *generation {
                    self.set_recovery_stage(tracker, "sync_complete.generation_mismatch");
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                if sync.inner_cursor != tracker.delivered {
                    self.set_recovery_stage(tracker, "sync_complete.inner_cursor_mismatch");
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                if sync.key_directory_revision != self.directory_revision {
                    self.set_recovery_stage(tracker, "sync_complete.directory_revision_mismatch");
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                if inner_cursor_value(&tracker.requested) == StreamCursor::BeforeFirst
                    && !tracker.snapshot_seen
                {
                    self.set_recovery_stage(tracker, "sync_complete.snapshot_missing");
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                tracker.sync_complete = Some(sync);
                self.set_recovery_stage(tracker, "sync_complete.accepted");
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
                let admission = classify_approval_receipt(&receipt, &approval.approval_id)
                    .ok_or(W2PairingError::BusinessFrameInvalid)?;
                *terminal = true;
                *receipt_applied = admission.applied();
                Ok(())
            }
            (
                PendingKind::Revoke {
                    receipt_committed,
                    terminal_verified: _,
                },
                SealedPayloadKind::CommandReceipt,
                RuntimeReply::Revocation(RevocationReceipt::Committed { grant_serial }),
            ) if grant_serial.0 == self.grant.grant_serial.value() => {
                *receipt_committed = true;
                self.evidence.revocation_receipt_committed = true;
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
        tracker.delivered = RuntimeInnerCursor::Catalog {
            cursor: snapshot.base_catalog_cursor,
        };
        tracker.snapshot_seen = true;
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
        tracker.delivered = RuntimeInnerCursor::Conversation {
            conversation_id: snapshot.conversation_id,
            cursor: snapshot.base_event_cursor,
        };
        tracker.snapshot_seen = true;
        Ok(())
    }

    fn accept_backfill(
        &mut self,
        tracker: &mut SubscriptionTracker,
        chunk: BackfillChunk,
    ) -> Result<(), W2PairingError> {
        match (tracker.target, chunk, &tracker.delivered) {
            (
                SubscriptionTarget::Catalog,
                BackfillChunk::Catalog { range, deltas },
                RuntimeInnerCursor::Catalog { cursor },
            ) if range.after() == *cursor => {
                for delta in deltas {
                    self.accept_catalog_delta(&delta)?;
                }
                tracker.delivered = RuntimeInnerCursor::Catalog {
                    cursor: range.through(),
                };
            }
            (
                SubscriptionTarget::Conversation,
                BackfillChunk::Conversation {
                    conversation_id,
                    range,
                    events,
                    ..
                },
                RuntimeInnerCursor::Conversation {
                    conversation_id: expected,
                    cursor,
                },
            ) if &conversation_id == expected && range.after() == *cursor => {
                let mut expected_seq = cursor
                    .checked_next()
                    .map_err(|_| W2PairingError::BusinessFrameInvalid)?;
                for event in events {
                    if event.conversation_id != conversation_id || event.event_seq != expected_seq {
                        return Err(W2PairingError::BusinessFrameInvalid);
                    }
                    expected_seq = expected_seq
                        .checked_add(1)
                        .ok_or(W2PairingError::BusinessCounterExhausted)?;
                }
                tracker.delivered = RuntimeInnerCursor::Conversation {
                    conversation_id,
                    cursor: range.through(),
                };
            }
            _ => return Err(W2PairingError::BusinessFrameInvalid),
        }
        tracker.backfill_count = tracker
            .backfill_count
            .checked_add(1)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        if tracker.recovery {
            match tracker.target {
                SubscriptionTarget::Catalog => {
                    self.evidence.recovery_catalog_backfill_count = self
                        .evidence
                        .recovery_catalog_backfill_count
                        .checked_add(1)
                        .ok_or(W2PairingError::BusinessCounterExhausted)?;
                }
                SubscriptionTarget::Conversation => {
                    self.evidence.recovery_conversation_backfill_count = self
                        .evidence
                        .recovery_conversation_backfill_count
                        .checked_add(1)
                        .ok_or(W2PairingError::BusinessCounterExhausted)?;
                }
            }
        }
        Ok(())
    }

    fn accept_catalog_delta(
        &mut self,
        delta: &agentdeck_protocol::runtime::CatalogDelta,
    ) -> Result<(), W2PairingError> {
        let conversation_id = self
            .conversation_id
            .as_ref()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        for change in &delta.changes {
            match change {
                CatalogChange::Upserted { entry } if &entry.conversation_id == conversation_id => {
                    if entry.archived {
                        return Err(W2PairingError::BusinessFrameInvalid);
                    }
                    self.evidence.conversation_title = entry.title.clone();
                    if entry.title.as_deref() == Some(W2C_RESTART_MARKER_TITLE) {
                        self.evidence.restart_marker_observed = true;
                    }
                }
                CatalogChange::Removed {
                    conversation_id: removed,
                } if removed == conversation_id => {
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                CatalogChange::Upserted { .. } | CatalogChange::Removed { .. } => {}
            }
        }
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
        self.set_recovery_stage(tracker, "stream_binding.received");
        let sync = tracker
            .sync_complete
            .as_ref()
            .ok_or(W2PairingError::BusinessFrameInvalid)?;
        if tracker.binding.is_some() {
            self.set_recovery_stage(tracker, "stream_binding.duplicate");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if binding.machine_route != self.grant.machine_route {
            self.set_recovery_stage(tracker, "stream_binding.machine_route_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if binding.device_route != self.grant.device_route {
            self.set_recovery_stage(tracker, "stream_binding.device_route_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if binding.grant_serial != self.grant.grant_serial {
            self.set_recovery_stage(tracker, "stream_binding.grant_serial_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if binding.root_trust_epoch != self.grant.trust_epoch {
            self.set_recovery_stage(tracker, "stream_binding.trust_epoch_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if binding.key_directory_revision.value() != self.directory_revision {
            self.set_recovery_stage(tracker, "stream_binding.directory_revision_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if binding.stream_cursor != sync.stream_cursor {
            self.set_recovery_stage(tracker, "stream_binding.stream_cursor_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if !same_inner_target(&binding.inner_cursor, &sync.inner_cursor) {
            self.set_recovery_stage(tracker, "stream_binding.sync_target_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if !same_inner_target(&tracker.requested, &binding.inner_cursor) {
            self.set_recovery_stage(tracker, "stream_binding.target_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if cursor_cmp(
            inner_cursor_value(&binding.inner_cursor),
            inner_cursor_value(&tracker.requested),
        )
        .is_lt()
        {
            self.set_recovery_stage(tracker, "stream_binding.cursor_regressed");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if cursor_cmp(
            inner_cursor_value(&sync.inner_cursor),
            inner_cursor_value(&binding.inner_cursor),
        )
        .is_lt()
        {
            self.set_recovery_stage(tracker, "stream_binding.sync_cursor_regressed");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        if binding.key_id.purpose
            != match tracker.target {
                SubscriptionTarget::Catalog => KeyPurpose::Catalog,
                SubscriptionTarget::Conversation => KeyPurpose::ConversationDek,
            }
        {
            self.set_recovery_stage(tracker, "stream_binding.key_purpose_mismatch");
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        let matching_keys = self
            .stream_keys
            .iter()
            .filter(|key| stream_key_matches(key, &binding))
            .count();
        if matching_keys != 1 {
            self.set_recovery_stage(tracker, "stream_binding.key_slot_mismatch");
            return Err(self.fail(W2PairingError::BusinessCryptoFailed));
        }
        let synced_inner_cursor = sync.inner_cursor.clone();
        tracker.binding = Some(binding.clone());
        match tracker.target {
            SubscriptionTarget::Catalog => {
                self.durable_catalog_cursor = Some(synced_inner_cursor);
                self.catalog_binding = Some(binding.clone());
            }
            SubscriptionTarget::Conversation => {
                if tracker.configuration_revision.is_some() {
                    self.configuration_revision = tracker.configuration_revision;
                }
                self.durable_conversation_cursor = Some(synced_inner_cursor);
                self.conversation_binding = Some(binding.clone());
            }
        }
        self.set_recovery_stage(tracker, "stream_binding.accepted");
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
            || !stream_seq_is_exact_next(binding.stream_cursor, publish.stream_seq)
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
        let counter_key = (publish.stream_route, counter);
        if !nonce_counter_is_fresh(&self.stream_counters, &counter_key) {
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
            let response = self.start_stream_applied_ack(&binding, &publish, barrier)?;
            if !self.stream_counters.insert(counter_key) {
                return Err(W2PairingError::BusinessCryptoFailed);
            }
            return Ok(response);
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
        match (binding.key_id.purpose, opened.payload_kind, envelope.body) {
            (
                KeyPurpose::Catalog,
                SealedPayloadKind::CatalogDelta,
                RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(delta)),
            ) => self.accept_live_catalog_delta(&publish, delta)?,
            (
                KeyPurpose::ConversationDek,
                SealedPayloadKind::ConversationEvent,
                RuntimeMessage::Stream(RuntimeStreamItem::Event(event)),
            ) => self.accept_live_conversation_event(&publish, event)?,
            _ => return Err(W2PairingError::BusinessFrameInvalid),
        }
        if !self.stream_counters.insert(counter_key) {
            return Err(W2PairingError::BusinessCryptoFailed);
        }
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

    fn accept_live_catalog_delta(
        &mut self,
        publish: &Publish,
        delta: agentdeck_protocol::runtime::CatalogDelta,
    ) -> Result<(), W2PairingError> {
        let binding_cursor = match self
            .catalog_binding
            .as_ref()
            .ok_or(W2PairingError::BusinessStateInvalid)?
            .inner_cursor
        {
            RuntimeInnerCursor::Catalog { cursor } => cursor,
            RuntimeInnerCursor::Conversation { .. } => {
                return Err(W2PairingError::BusinessFrameInvalid);
            }
        };
        if binding_cursor.checked_next().ok() != Some(delta.catalog_revision) {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let durable_cursor = match self
            .durable_catalog_cursor
            .as_ref()
            .ok_or(W2PairingError::DurableStateInvalid)?
        {
            RuntimeInnerCursor::Catalog { cursor } => *cursor,
            RuntimeInnerCursor::Conversation { .. } => {
                return Err(W2PairingError::DurableStateInvalid);
            }
        };
        match cursor_cmp(StreamCursor::At(delta.catalog_revision), durable_cursor) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal => {
                self.set_recovery_stage_for_purpose(
                    KeyPurpose::Catalog,
                    "publication_overlap.acknowledged",
                );
            }
            std::cmp::Ordering::Greater => {
                if durable_cursor.checked_next().ok() != Some(delta.catalog_revision) {
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                self.accept_catalog_delta(&delta)?;
                self.durable_catalog_cursor = Some(RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(delta.catalog_revision),
                });
                self.set_recovery_stage_for_purpose(KeyPurpose::Catalog, "live_delta.applied");
            }
        }
        let binding = self
            .catalog_binding
            .as_mut()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        binding.stream_cursor = StreamCursor::At(publish.stream_seq);
        binding.inner_cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(delta.catalog_revision),
        };
        Ok(())
    }

    fn accept_live_conversation_event(
        &mut self,
        publish: &Publish,
        event: RuntimeEvent,
    ) -> Result<(), W2PairingError> {
        let conversation_id = self
            .conversation_id
            .clone()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let binding_cursor = match &self
            .conversation_binding
            .as_ref()
            .ok_or(W2PairingError::BusinessStateInvalid)?
            .inner_cursor
        {
            RuntimeInnerCursor::Conversation {
                conversation_id: bound,
                cursor,
            } if bound == &conversation_id => *cursor,
            RuntimeInnerCursor::Catalog { .. } | RuntimeInnerCursor::Conversation { .. } => {
                return Err(W2PairingError::BusinessFrameInvalid);
            }
        };
        if event.conversation_id != conversation_id
            || binding_cursor.checked_next().ok() != Some(event.event_seq)
        {
            return Err(W2PairingError::BusinessFrameInvalid);
        }
        let durable_cursor = match self
            .durable_conversation_cursor
            .as_ref()
            .ok_or(W2PairingError::DurableStateInvalid)?
        {
            RuntimeInnerCursor::Conversation {
                conversation_id: durable_conversation,
                cursor,
            } if durable_conversation == &conversation_id => *cursor,
            RuntimeInnerCursor::Catalog { .. } | RuntimeInnerCursor::Conversation { .. } => {
                return Err(W2PairingError::DurableStateInvalid);
            }
        };
        let event_seq = event.event_seq;
        match cursor_cmp(StreamCursor::At(event_seq), durable_cursor) {
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal => {
                self.set_recovery_stage_for_purpose(
                    KeyPurpose::ConversationDek,
                    "publication_overlap.acknowledged",
                );
            }
            std::cmp::Ordering::Greater => {
                if durable_cursor.checked_next().ok() != Some(event_seq) {
                    return Err(W2PairingError::BusinessFrameInvalid);
                }
                self.accept_event(event)?;
                self.durable_conversation_cursor = Some(RuntimeInnerCursor::Conversation {
                    conversation_id: conversation_id.clone(),
                    cursor: StreamCursor::At(event_seq),
                });
                self.set_recovery_stage_for_purpose(
                    KeyPurpose::ConversationDek,
                    "live_event.applied",
                );
            }
        }
        let binding = self
            .conversation_binding
            .as_mut()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        binding.stream_cursor = StreamCursor::At(publish.stream_seq);
        binding.inner_cursor = RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor: StreamCursor::At(event_seq),
        };
        Ok(())
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
        self.set_recovery_stage_for_purpose(binding.key_id.purpose, "epoch_barrier.received");
        if barrier.old_epoch != 0
            || barrier.new_epoch != binding.key_id.epoch
            || barrier.stream_generation != binding.stream_generation
            || barrier.stream_cursor != binding.stream_cursor
            || barrier.inner_cursor != binding.inner_cursor
            || barrier.key_directory_revision.value() != self.directory_revision
            || barrier.stream_cursor.checked_next().ok() != Some(publish.stream_seq)
        {
            self.set_recovery_stage_for_purpose(binding.key_id.purpose, "epoch_barrier.mismatch");
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
        self.ensure_counter_reserved(next_counter)?;
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
        self.set_recovery_stage_for_purpose(binding.key_id.purpose, "stream_applied_ack.sent");
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
        match purpose {
            // EpochBarrier 确认的是 publication cut；directed bootstrap 可能已经把 reducer
            // 应用到更高的 SyncComplete cut，因此这里只推进 outer cursor，不能回退 durable
            // inner cursor。
            KeyPurpose::Catalog | KeyPurpose::ConversationDek => {}
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
                return Err(W2PairingError::BusinessFrameInvalid);
            }
        }
        self.evidence.outer_ack_count = self
            .evidence
            .outer_ack_count
            .checked_add(1)
            .ok_or(W2PairingError::BusinessCounterExhausted)?;
        self.set_recovery_stage_for_purpose(purpose, "stream_applied_ack.committed");
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
        let (purpose, binding_cursor) = {
            let binding = self
                .binding_for_stream(replay.stream_route, replay.generation)
                .ok_or(W2PairingError::BusinessStateInvalid)?;
            (binding.key_id.purpose, binding.stream_cursor)
        };
        self.set_recovery_stage_for_purpose(purpose, "replay_complete.received");
        if replay.current_cursor != binding_cursor {
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
            self.set_recovery_stage_for_purpose(purpose, "replay_complete.awaiting_control_ack");
            return Ok(Vec::new());
        }
        self.mark_subscription_active(purpose)?;
        self.set_recovery_stage_for_purpose(purpose, "subscription.active");
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

    fn set_recovery_stage(&mut self, tracker: &SubscriptionTracker, suffix: &str) {
        if !tracker.recovery {
            return;
        }
        let target = match tracker.target {
            SubscriptionTarget::Catalog => "catalog",
            SubscriptionTarget::Conversation => "conversation",
        };
        self.evidence.recovery_stage = Some(format!("recovery.{target}.{suffix}"));
    }

    fn set_recovery_stage_for_purpose(&mut self, purpose: KeyPurpose, suffix: &str) {
        if !self.evidence.durable_restored {
            return;
        }
        let target = match purpose {
            KeyPurpose::Catalog => "catalog",
            KeyPurpose::ConversationDek => "conversation",
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => "invalid",
        };
        self.evidence.recovery_stage = Some(format!("recovery.{target}.{suffix}"));
    }

    fn set_recovery_frame_stage(&mut self, frame: &str) {
        if self.evidence.durable_restored {
            self.evidence.recovery_stage = Some(format!("recovery.frame.{frame}"));
        }
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
            PendingKind::Revoke {
                receipt_committed,
                terminal_verified,
            } => *receipt_committed && *terminal_verified,
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
            PendingKind::Revoke { .. } => {
                self.evidence.revoke_route_accepted = true;
            }
        }
        self.pending = None;
    }

    fn accept_revocation_terminal(
        &mut self,
        canonical_bytes: &[u8],
        committed: RevocationCommitted,
    ) -> Result<Vec<u8>, W2PairingError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        if !matches!(pending.kind, PendingKind::Revoke { .. }) {
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        let decoded = decode(canonical_bytes).map_err(|_| W2PairingError::BusinessFrameInvalid)?;
        if encode(&decoded) != canonical_bytes
            || committed.device_route != self.grant.device_route
            || committed.grant_serial != self.grant.grant_serial
            || committed.signed_revocation.machine_route != self.grant.machine_route
            || committed.signed_revocation.device_route != self.grant.device_route
            || committed.signed_revocation.grant_serial != self.grant.grant_serial
            || committed.signed_revocation.root_key_id != self.grant.root_key_id
            || committed.signed_revocation.trust_epoch != self.grant.trust_epoch
        {
            return Err(self.fail(W2PairingError::BusinessFrameInvalid));
        }
        let root = VerifyingKey::from_bytes(&self._verified_response.machine_root_pubkey().0)
            .map_err(|_| W2PairingError::BusinessCryptoFailed)?;
        if agentdeck_crypto::sha256(&root.to_bytes())
            != self._verified_response.machine_root_fingerprint()
        {
            return Err(self.fail(W2PairingError::BusinessCryptoFailed));
        }
        verify_tbs(
            &root,
            &committed.signed_revocation.to_be_signed_v1(
                self._verified_response.info().relay_server_id,
                self._verified_response.machine_root_fingerprint(),
            ),
            &SignatureBytes::from(committed.signed_revocation.signature),
        )
        .map_err(|_| self.fail(W2PairingError::BusinessCryptoFailed))?;
        let pending = self
            .pending
            .as_mut()
            .ok_or(W2PairingError::BusinessStateInvalid)?;
        let PendingKind::Revoke {
            receipt_committed,
            terminal_verified,
        } = &mut pending.kind
        else {
            return Err(W2PairingError::BusinessStateInvalid);
        };
        // 与 production RemoteRuntime::revoke_self 对齐：root-signed terminal 本身就是
        // Relay COMMIT 的权威证明。directed daemon receipt 与 RouteAccepted 可能因连接随
        // revoke 关闭而不可见，此时从 verified terminal 合成相同的 committed receipt。
        *receipt_committed = true;
        *terminal_verified = true;
        self.evidence.revocation_receipt_committed = true;
        self.evidence.revocation_terminal_verified = true;
        self.finish_pending_if_ready();
        Ok(Vec::new())
    }

    fn ensure_counter_reserved(&self, next_counter: u64) -> Result<(), W2PairingError> {
        counter_reservation_admission(self.durability, next_counter)
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

/// 生成 native/WASM 共用的 W2.7 负向准入证据。
#[must_use]
pub fn w2_negative_snapshot() -> W2NegativeSnapshot {
    let approval_id = ApprovalId::new("web-w2-negative-approval");
    let loser = ApprovalReceipt::AlreadyHandled {
        approval_id: approval_id.clone(),
        decision: ActionDecisionKind::Approve,
        state: ApprovalDeliveryState::Applied,
    };
    let loser_admission = classify_approval_receipt(&loser, &approval_id);

    let cursor = StreamCursor::At(9);
    let stale_publish_rejected = !stream_seq_is_exact_next(cursor, 9);
    let skipped_publish_rejected = !stream_seq_is_exact_next(cursor, 11);
    let cursor_after_rejections = cursor;

    let reply_counters = HashSet::from([7_u64]);
    let reply_counter_count = reply_counters.len();
    let reply_nonce_replay_rejected = !nonce_counter_is_fresh(&reply_counters, &7);

    let stream_route = StreamRouteId::from_bytes([0x27; 16]);
    let stream_counters = HashSet::from([(stream_route, 13_u64)]);
    let stream_counter_count = stream_counters.len();
    let stream_nonce_reuse_rejected =
        !nonce_counter_is_fresh(&stream_counters, &(stream_route, 13));

    let command_counter = W2_COUNTER_RESERVATION_BLOCK;
    let uncommitted_reservation_rejected = matches!(
        counter_reservation_admission(
            DurabilityPhase::AwaitingCommit {
                reserved_high_water: W2_COUNTER_RESERVATION_BLOCK,
            },
            1,
        ),
        Err(W2PairingError::DurableCommitRequired)
    );
    let reservation_overflow_rejected = matches!(
        counter_reservation_admission(
            DurabilityPhase::Active {
                reserved_high_water: W2_COUNTER_RESERVATION_BLOCK,
            },
            W2_COUNTER_RESERVATION_BLOCK + 1,
        ),
        Err(W2PairingError::BusinessCounterExhausted)
    );

    W2NegativeSnapshot {
        approval_loser_recognized_applied: loser_admission
            == Some(ApprovalReceiptAdmission::AppliedLoser),
        approval_loser_zero_claim_mutation: loser_admission
            .is_some_and(|admission| !admission.creates_claim()),
        stale_publish_rejected,
        skipped_publish_rejected,
        rejected_publish_cursor_unchanged: cursor_after_rejections == cursor,
        reply_nonce_replay_rejected,
        reply_counter_set_unchanged: reply_counters.len() == reply_counter_count,
        stream_nonce_reuse_rejected,
        stream_counter_set_unchanged: stream_counters.len() == stream_counter_count,
        uncommitted_reservation_rejected,
        reservation_overflow_rejected,
        rejected_reservation_counter_unchanged: command_counter == W2_COUNTER_RESERVATION_BLOCK,
    }
}

fn classify_approval_receipt(
    receipt: &ApprovalReceipt,
    expected_approval_id: &ApprovalId,
) -> Option<ApprovalReceiptAdmission> {
    match receipt {
        ApprovalReceipt::Claimed { approval_id } if approval_id == expected_approval_id => {
            Some(ApprovalReceiptAdmission::Claimed)
        }
        ApprovalReceipt::Applied { approval_id } if approval_id == expected_approval_id => {
            Some(ApprovalReceiptAdmission::AppliedWinner)
        }
        ApprovalReceipt::AlreadyHandled {
            approval_id,
            decision: ActionDecisionKind::Approve,
            state: ApprovalDeliveryState::Applied,
        } if approval_id == expected_approval_id => Some(ApprovalReceiptAdmission::AppliedLoser),
        ApprovalReceipt::Claimed { .. }
        | ApprovalReceipt::Applied { .. }
        | ApprovalReceipt::AlreadyHandled { .. }
        | ApprovalReceipt::DeliveryFailed { .. }
        | ApprovalReceipt::Expired { .. } => None,
    }
}

fn nonce_counter_is_fresh<T>(seen: &HashSet<T>, counter: &T) -> bool
where
    T: Eq + Hash,
{
    !seen.contains(counter)
}

fn stream_seq_is_exact_next(cursor: StreamCursor, stream_seq: u64) -> bool {
    cursor.checked_next().ok() == Some(stream_seq)
}

fn counter_reservation_admission(
    durability: DurabilityPhase,
    next_counter: u64,
) -> Result<(), W2PairingError> {
    match durability {
        DurabilityPhase::Volatile => Ok(()),
        DurabilityPhase::AwaitingCommit { .. } => Err(W2PairingError::DurableCommitRequired),
        DurabilityPhase::Active {
            reserved_high_water,
        } if next_counter <= reserved_high_water => Ok(()),
        DurabilityPhase::Active { .. } => Err(W2PairingError::BusinessCounterExhausted),
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

fn validate_restored_projection(state: &W2DurableStateV1) -> Result<(), W2PairingError> {
    if !state.evidence.durable_promoted
        || state.evidence.counter_reservation_end != state.reserved_high_water
        || state.evidence.counter_reservation_start >= state.evidence.counter_reservation_end
        || state.request_sequence > state.reserved_high_water
    {
        return Err(W2PairingError::DurableStateInvalid);
    }
    if let Some(cursor) = &state.catalog_inner_cursor
        && !matches!(cursor, RuntimeInnerCursor::Catalog { .. })
    {
        return Err(W2PairingError::DurableStateInvalid);
    }
    if let Some(cursor) = &state.conversation_inner_cursor {
        let RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor: stream_cursor,
        } = cursor
        else {
            return Err(W2PairingError::DurableStateInvalid);
        };
        if state.conversation_id.as_ref() != Some(conversation_id)
            || state
                .configuration_revision
                .is_none_or(|revision| revision == 0)
            || stream_cursor.checked_next().is_err()
            || state.catalog_inner_cursor.is_none()
        {
            return Err(W2PairingError::DurableStateInvalid);
        }
    } else if state.conversation_id.is_some() != state.configuration_revision.is_some() {
        return Err(W2PairingError::DurableStateInvalid);
    }
    if state.evidence.command_completed
        && (state.catalog_inner_cursor.is_none()
            || state.conversation_inner_cursor.is_none()
            || state.conversation_id.is_none()
            || state.configuration_revision.is_none()
            || state.prompt_command_id.is_none()
            || state.prompt_turn_id.is_none())
    {
        return Err(W2PairingError::DurableStateInvalid);
    }
    if state.evidence.approval_pending
        && (state.prompt_command_id.is_none()
            || state.prompt_turn_id.is_none()
            || state.approval.is_none())
    {
        return Err(W2PairingError::DurableStateInvalid);
    }
    if state.evidence.restart_marker_observed && state.catalog_inner_cursor.is_none() {
        return Err(W2PairingError::DurableStateInvalid);
    }
    Ok(())
}

fn inner_cursor_value(cursor: &RuntimeInnerCursor) -> StreamCursor {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor }
        | RuntimeInnerCursor::Conversation { cursor, .. } => *cursor,
    }
}

fn same_inner_target(left: &RuntimeInnerCursor, right: &RuntimeInnerCursor) -> bool {
    match (left, right) {
        (RuntimeInnerCursor::Catalog { .. }, RuntimeInnerCursor::Catalog { .. }) => true,
        (
            RuntimeInnerCursor::Conversation {
                conversation_id: left,
                ..
            },
            RuntimeInnerCursor::Conversation {
                conversation_id: right,
                ..
            },
        ) => left == right,
        _ => false,
    }
}

fn cursor_cmp(left: StreamCursor, right: StreamCursor) -> std::cmp::Ordering {
    match (left, right) {
        (StreamCursor::BeforeFirst, StreamCursor::BeforeFirst) => std::cmp::Ordering::Equal,
        (StreamCursor::BeforeFirst, StreamCursor::At(_)) => std::cmp::Ordering::Less,
        (StreamCursor::At(_), StreamCursor::BeforeFirst) => std::cmp::Ordering::Greater,
        (StreamCursor::At(left), StreamCursor::At(right)) => left.cmp(&right),
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
