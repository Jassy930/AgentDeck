//! PairResponse 验证后的 two-phase paired machine promotion。
//!
//! `PairedCommitMarkerV1` 是唯一可见性边界。随机 StorageKEK 必须先以 provisional
//! Keychain item 持久化，随后才能一次性提交 sealed CryptoState；其余 final items 完成
//! exact readback 后才最后写 marker。marker 前的 partial state 永远不代表 paired。

#![cfg(unix)]

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentdeck_crypto::counter::COUNTER_BLOCK_SIZE;
use agentdeck_crypto::rand_core::CryptoRng;
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, CryptoError, HpkePrivateKey, HpkePublicKey, SenderCounter,
    SignatureBytes, SigningKey, VerifyingKey, open_key_directory_entry, open_pair_response,
    open_sealed_payload, seal_key_sync_probe, seal_pair_response_received, seal_symmetric, sha256,
    sign_authentication_transcript, sign_revocation_cleanup_journal_digest, sign_sealed,
    verify_revocation_cleanup_journal_digest, verify_sealed, verify_tbs,
};
use agentdeck_protocol::ActionDecision;
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, DeviceAuthorizationV1,
    E2EE_FORMAT_VERSION, KeyDirectoryV1, KeyId, KeyPurpose, KeySyncRequestV1, KeyUpdateInfoV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairResponseReceivedV1,
    PairResponseV1, PairingControlEnvelopeV1, PairingError, SealedPayloadKind, SealedPayloadV1,
    SignedSealedBlobV1, StreamBindingV1, VerifiedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthCanonicalError, AuthenticationRole, AuthenticationTranscriptV1, CertRole, Ed25519Signature,
    RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::frame::{
    AuthProof, Authenticate, Challenge, Publish, RevocationCommitted,
};
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RelayServerId,
    RequestRouteId, RootKeyId, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::relay_v2::{
    OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, decode, encode,
};
use agentdeck_protocol::runtime::command::{CatalogRequest, RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::identity::{ApprovalId, MessageId, TurnId};
use agentdeck_protocol::runtime::{
    ConversationId, MachineRootFingerprint, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope,
    RuntimeInnerCursor, RuntimeMessage, RuntimeRequest, SendPromptRequest,
};
use agentdeck_relay_client::{
    LinkAuthenticator, RelayClientConfig, RelayClientError, RelayTlsPolicy,
};
use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::crypto_state::{
    CryptoStateError, CryptoStateIdentity, CryptoStateSnapshot, DeviceStorageKek,
    FileCryptoStateStore, MAX_CRYPTO_STATE_PLAINTEXT_LEN, PreparedCryptoStateStage,
    revocation_cleanup_entries_absent_in,
};
use super::device_lock::{RemoteDeviceLease, RemoteDeviceLockError, RemoteDeviceLockKey};
use super::key_sync::{DurableKeySyncStateV1, SignedHigherRevisionObservationV1};
use super::keychain::{
    PairedRemoteKeyPurpose, ParsedPairedRemoteKeyAccount, PendingRemoteKeyPurpose,
    RemoteKeyAccount, RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use super::pending::{PendingInvitePublicProjection, VerifiedPendingPairResponse};
use super::stream_state::{DurableStreamBindingV1, decode_stream_bindings, encode_stream_bindings};

const STATE_MAGIC: &[u8; 4] = b"ADPS";
const STATE_VERSION: u16 = 1;
const MUTABLE_STATE_VERSION: u16 = 2;
const TYPED_RUNTIME_STATE_VERSION: u16 = 3;
const KEY_SYNC_STATE_VERSION: u16 = 4;
const STATE_HEADER_LEN: usize = 12;
const MAX_STATE_FIELD_LEN: usize = 8 * 1024 * 1024;
const MAX_STATE_STRING_LEN: usize = 8 * 1024;
const MAX_STATE_COLLECTION_ITEMS: usize = 4_096;
const MUTABLE_STATE_FIXED_ENCODED_LEN: usize = STATE_HEADER_LEN + 64 + 4 + 4 + 36 + 2 + 2;
const AUTOMATIC_RUNTIME_STATE_PROBE_DOMAIN: &[u8] = b"AgentDeck/AutomaticRuntimeStateProbeV1\0";
const MAX_MUTABLE_AUDIT_ATTEMPTS: usize = 3;

const MARKER_MAGIC: &[u8; 4] = b"ADPM";
const MARKER_VERSION: u16 = 1;
const PAIRED_COMMIT_MARKER_BYTES: usize = 480;
const CLEANUP_JOURNAL_MAGIC: &[u8; 4] = b"ADPC";
const CLEANUP_JOURNAL_VERSION: u16 = 1;
const MAX_CLEANUP_TERMINAL_BYTES: usize = 64 * 1024;
const MAX_CLEANUP_GRANT_BYTES: usize = 4 * 1024;
const KEK_MAGIC: &[u8; 4] = b"ADKK";
const KEK_VERSION: u16 = 1;
const COUNTER_GUARD_MAGIC: &[u8; 4] = b"ADCG";
const COUNTER_GUARD_VERSION: u16 = 1;
const MUTABLE_COUNTER_GUARD_VERSION: u16 = 2;
const PROMOTION_ID_DOMAIN: &[u8] = b"AgentDeck/PairedPromotionIdV1\0";

/// 仅供 automatic library harness 在 reservation/recovery 的 durable 边界注入进程终止。
/// production CLI 不构造该 observer，也不存在环境变量或配置入口。
#[doc(hidden)]
pub trait PairedMutationObserver: Send + Sync {
    fn after_stage(&self, stage: PairedMutationStage);
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairedMutationStage {
    GuardPendingDurable,
    StateDurable,
    RecoveryStateDurable,
    GuardStableDurable,
    StateStageDurable,
    StateGuardPendingDurable,
    StateActiveDurable,
    StateRecoveryActiveDurable,
    StateGuardStableDurable,
    StateStageCleared,
    CleanupJournalDurable,
    CleanupStateDeleted,
    CleanupCounterGuardDeleted,
    CleanupGrantDeleted,
    CleanupDeviceHpkeDeleted,
    CleanupDeviceSignDeleted,
    CleanupStorageKekDeleted,
    CleanupJournalDeleted,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RuntimeStateMutationAuthority {
    Production,
    AutomaticHarness,
}

/// runtime transport 可读写的 bounded opaque state 投影；不包含 KEK、traffic key 或 raw
/// paired state。`exchange` 对应单一 terminal exchange blob，另外两项保持 canonical 顺序。
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct OpaqueRuntimeState {
    exchange: Option<Vec<u8>>,
    replay_windows: Vec<Vec<u8>>,
    stream_cursors: Vec<Vec<u8>>,
}

impl fmt::Debug for OpaqueRuntimeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueRuntimeState([REDACTED])")
    }
}

impl OpaqueRuntimeState {
    #[must_use]
    pub(crate) fn new(
        exchange: Option<Vec<u8>>,
        replay_windows: Vec<Vec<u8>>,
        stream_cursors: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            exchange,
            replay_windows,
            stream_cursors,
        }
    }

    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self {
            exchange: None,
            replay_windows: Vec::new(),
            stream_cursors: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn exchange(&self) -> Option<&[u8]> {
        self.exchange.as_deref()
    }

    #[must_use]
    pub(crate) fn replay_windows(&self) -> &[Vec<u8>] {
        &self.replay_windows
    }

    #[must_use]
    pub(crate) fn stream_cursors(&self) -> &[Vec<u8>] {
        &self.stream_cursors
    }

    fn validate(&self) -> Result<(), PairedPromotionError> {
        if self.exchange.as_ref().is_some_and(Vec::is_empty)
            || self
                .exchange
                .as_ref()
                .is_some_and(|value| value.len() > MAX_STATE_FIELD_LEN)
            || self.replay_windows.len() > MAX_STATE_COLLECTION_ITEMS
            || self.stream_cursors.len() > MAX_STATE_COLLECTION_ITEMS
            || self
                .replay_windows
                .iter()
                .chain(&self.stream_cursors)
                .any(|entry| entry.is_empty() || entry.len() > MAX_STATE_FIELD_LEN)
        {
            return Err(PairedPromotionError::InvalidState);
        }
        checked_mutable_state_encoded_len(
            0,
            self.exchange.as_ref().map_or(0, Vec::len),
            self.replay_windows.iter().map(Vec::len),
            self.stream_cursors.iter().map(Vec::len),
        )?;
        Ok(())
    }

    fn from_automatic_probe(probe: AutomaticRuntimeStateProbe) -> Self {
        let encoded = probe.encoded();
        Self {
            exchange: Some(encoded.clone()),
            replay_windows: vec![encoded.clone()],
            stream_cursors: vec![encoded],
        }
    }

    fn from_automatic_legacy_v2_probe(probe: AutomaticRuntimeStateProbe) -> Self {
        let encoded = probe.encoded();
        Self {
            exchange: Some(encoded.clone()),
            replay_windows: vec![encoded],
            stream_cursors: Vec::new(),
        }
    }

    fn automatic_probe(&self) -> Result<Option<AutomaticRuntimeStateProbe>, PairedPromotionError> {
        if self == &Self::empty() {
            return Ok(None);
        }
        let exchange = self
            .exchange
            .as_deref()
            .ok_or(PairedPromotionError::InvalidState)?;
        let probe = AutomaticRuntimeStateProbe::decode(exchange)?;
        let expected = Self::from_automatic_probe(probe);
        if self != &expected {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(Some(probe))
    }

    fn automatic_legacy_v2_probe(
        &self,
    ) -> Result<Option<AutomaticRuntimeStateProbe>, PairedPromotionError> {
        let Some(exchange) = self.exchange.as_deref() else {
            return Ok(None);
        };
        let probe = AutomaticRuntimeStateProbe::decode(exchange)?;
        let encoded = probe.encoded();
        if self.replay_windows.as_slice() != [encoded] {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(Some(probe))
    }
}

/// 仅供 automatic crash harness 驱动通用 state-mutation 边界的非生产探针。
///
/// 探针使用与 runtime exchange/replay/cursor codec 不相交的 domain，不能伪造 daemon receipt、
/// replay admission 或 cursor。production CLI 不构造该类型，也不存在参数、环境变量或配置入口。
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomaticRuntimeStateProbe(u8);

impl AutomaticRuntimeStateProbe {
    #[must_use]
    pub const fn new(seed: u8) -> Self {
        Self(seed)
    }

    fn encoded(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(AUTOMATIC_RUNTIME_STATE_PROBE_DOMAIN.len() + 1);
        encoded.extend_from_slice(AUTOMATIC_RUNTIME_STATE_PROBE_DOMAIN);
        encoded.push(self.0);
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, PairedPromotionError> {
        let seed = encoded
            .strip_prefix(AUTOMATIC_RUNTIME_STATE_PROBE_DOMAIN)
            .and_then(|suffix| <[u8; 1]>::try_from(suffix).ok())
            .map(|suffix| suffix[0])
            .ok_or(PairedPromotionError::InvalidState)?;
        Ok(Self(seed))
    }
}

/// 已在 CounterGuard 中 durable 预留的 DeviceCommandTx counter 整块。
///
/// reservation 不实现 `Clone`/`Copy`，且 seal API 按值消费：
/// ```compile_fail
/// use agentdeck_cli::remote::paired_machine::CommandCounterReservation;
/// fn consume(value: CommandCounterReservation) { drop(value); }
/// fn cannot_reuse(value: CommandCounterReservation) {
///     consume(value);
///     consume(value);
/// }
/// ```
#[derive(Eq, PartialEq)]
pub struct CommandCounterReservation {
    reservation_id: [u8; 16],
    start: u64,
    end_exclusive: u64,
}

fn validate_current_command_reservation(
    current: Option<&CommandCounterReservation>,
    candidate: &CommandCounterReservation,
) -> Result<(), PairedPromotionError> {
    candidate.validate()?;
    if current != Some(candidate) {
        return Err(PairedPromotionError::Conflict);
    }
    Ok(())
}

/// 远端 paired-machine sealing 层允许进入 authenticated command 通道的闭合集合。
///
/// 每个 variant 都在本模块内固定映射到唯一 capability/permission 与 wire
/// `RuntimeRequest`。调用方不能传入裸 `RuntimeRequest`，因此新增远程命令必须显式扩展本
/// allowlist 及其授权映射。
pub(crate) enum AuthorizedRuntimeRequest {
    Catalog(CatalogRequest),
    Subscribe(RuntimeInnerCursor),
    SendPrompt(SendPromptRequest),
    ResolveApproval {
        conversation_id: ConversationId,
        turn_id: TurnId,
        approval_id: ApprovalId,
        decision: ActionDecision,
    },
    RetryApproval {
        conversation_id: ConversationId,
        approval_id: ApprovalId,
    },
    RevokeSelf,
}

impl AuthorizedRuntimeRequest {
    const fn required_authorization(
        &self,
    ) -> (AuthorizationCapabilityV1, AuthorizationPermissionV1) {
        match self {
            Self::Catalog(_) => (
                AuthorizationCapabilityV1::Catalog,
                AuthorizationPermissionV1::CatalogRead,
            ),
            Self::Subscribe(RuntimeInnerCursor::Catalog { .. }) => (
                AuthorizationCapabilityV1::Catalog,
                AuthorizationPermissionV1::CatalogRead,
            ),
            Self::Subscribe(RuntimeInnerCursor::Conversation { .. }) => (
                AuthorizationCapabilityV1::Conversation,
                AuthorizationPermissionV1::ConversationRead,
            ),
            Self::SendPrompt(_) => (
                AuthorizationCapabilityV1::Prompt,
                AuthorizationPermissionV1::PromptSend,
            ),
            Self::ResolveApproval { .. } => (
                AuthorizationCapabilityV1::Approval,
                AuthorizationPermissionV1::ApprovalResolve,
            ),
            Self::RetryApproval { .. } => (
                AuthorizationCapabilityV1::Approval,
                AuthorizationPermissionV1::ApprovalRetry,
            ),
            Self::RevokeSelf => (
                AuthorizationCapabilityV1::SelfRevocation,
                AuthorizationPermissionV1::RevokeSelf,
            ),
        }
    }

    fn into_runtime_request(self) -> RuntimeRequest {
        match self {
            Self::Catalog(request) => RuntimeRequest::Catalog(request),
            Self::Subscribe(inner_cursor) => RuntimeRequest::Subscribe { inner_cursor },
            Self::SendPrompt(request) => RuntimeRequest::SendPrompt(request),
            Self::ResolveApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision,
            } => RuntimeRequest::ResolveApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision,
            },
            Self::RetryApproval {
                conversation_id,
                approval_id,
            } => RuntimeRequest::RetryApproval {
                conversation_id,
                approval_id,
            },
            Self::RevokeSelf => RuntimeRequest::Revoke(RevokeRequest {
                target: RevokeTarget::SelfDevice,
            }),
        }
    }
}

impl fmt::Debug for CommandCounterReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandCounterReservation")
            .field("reservation_id", &"[REDACTED]")
            .field("start", &self.start)
            .field("end_exclusive", &self.end_exclusive)
            .finish()
    }
}

impl CommandCounterReservation {
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 16] {
        self.reservation_id
    }

    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end_exclusive(&self) -> u64 {
        self.end_exclusive
    }

    fn validate(&self) -> Result<(), PairedPromotionError> {
        if all_zero(&self.reservation_id)
            || self
                .start
                .checked_add(COUNTER_BLOCK_SIZE)
                .is_none_or(|end| end != self.end_exclusive)
        {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(())
    }
}

/// 纯内存地准备下一整块；overflow 必须早于 entropy、state 构造与任一 durable mutation。
fn prepare_command_counter_reservation<R: CryptoRng>(
    previous_high_water: u64,
    rng: &mut R,
) -> Result<CommandCounterReservation, PairedPromotionError> {
    let end_exclusive = previous_high_water
        .checked_add(COUNTER_BLOCK_SIZE)
        .ok_or(PairedPromotionError::CounterEpochExhausted)?;
    let mut reservation_id = [0_u8; 16];
    rng.try_fill_bytes(&mut reservation_id)
        .map_err(|_| PairedPromotionError::EntropyUnavailable)?;
    if all_zero(&reservation_id) {
        return Err(PairedPromotionError::EntropyUnavailable);
    }
    let reservation = CommandCounterReservation {
        reservation_id,
        start: previous_high_water,
        end_exclusive,
    };
    reservation.validate()?;
    Ok(reservation)
}

#[derive(Debug, Error)]
pub enum PairedPromotionError {
    #[error("paired promotion could not acquire the remote device lease")]
    DeviceLock(#[source] RemoteDeviceLockError),
    #[error("paired promotion persistence failed")]
    Persistence(#[source] RemoteKeyStoreError),
    #[error("paired promotion sealed state failed")]
    CryptoState(#[source] CryptoStateError),
    #[error("paired promotion cryptographic validation failed")]
    Crypto(#[source] CryptoError),
    #[error("paired promotion canonical state is invalid")]
    Protocol(#[source] PairingError),
    #[error("paired promotion auth credential is invalid")]
    AuthCanonical(#[source] AuthCanonicalError),
    #[error("paired promotion entropy source is unavailable")]
    EntropyUnavailable,
    #[error("paired command counter reached the current key epoch limit")]
    CounterEpochExhausted,
    #[error("paired promotion is incomplete or corrupt")]
    Incomplete,
    #[error("paired promotion conflicts with durable state")]
    Conflict,
    #[error("paired machine is revoked and cleanup is pending")]
    RevokedCleanupPending,
    #[error("paired promotion state has an invalid canonical encoding")]
    InvalidState,
}

impl PairedPromotionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DeviceLock(error) => error.code(),
            Self::Persistence(_) => "remote.pairing.paired_persistence_failed",
            Self::CryptoState(error) => error.code(),
            Self::Crypto(_) | Self::Protocol(_) | Self::AuthCanonical(_) | Self::InvalidState => {
                "remote.pairing.paired_invalid"
            }
            Self::EntropyUnavailable => "remote.pairing.entropy_unavailable",
            Self::CounterEpochExhausted => "remote.counter.epoch_retirement_required",
            Self::Incomplete => "remote.pairing.paired_incomplete",
            Self::Conflict => "remote.pairing.paired_conflict",
            Self::RevokedCleanupPending => "remote.pairing.revoked_cleanup_pending",
        }
    }
}

/// marker exact readback 后才可返回给 transport 的 frozen receipt outbox。
pub struct PromotedPairedMachine {
    state_path: PathBuf,
    canonical_receipt_carrier: Vec<u8>,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    already_committed: bool,
}

impl fmt::Debug for PromotedPairedMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromotedPairedMachine([REDACTED])")
    }
}

impl PromotedPairedMachine {
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    #[must_use]
    pub fn canonical_receipt_carrier(&self) -> &[u8] {
        &self.canonical_receipt_carrier
    }

    #[must_use]
    pub const fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    #[must_use]
    pub const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }

    #[must_use]
    pub const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    #[must_use]
    pub const fn grant_hash(&self) -> [u8; 32] {
        self.grant_hash
    }

    #[must_use]
    pub const fn response_hash(&self) -> [u8; 32] {
        self.response_hash
    }

    #[must_use]
    pub const fn was_already_committed(&self) -> bool {
        self.already_committed
    }
}

/// marker account、sealed state 与所有 final Keychain item 共用的 machine identity。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PairedMachineIdentity {
    machine_root_fingerprint: MachineRootFingerprint,
    machine_route: MachineRouteId,
}

impl fmt::Debug for PairedMachineIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedMachineIdentity([REDACTED])")
    }
}

impl PairedMachineIdentity {
    #[must_use]
    pub const fn new(
        machine_root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
    ) -> Self {
        Self {
            machine_root_fingerprint,
            machine_route,
        }
    }

    #[must_use]
    pub const fn machine_root_fingerprint(self) -> MachineRootFingerprint {
        self.machine_root_fingerprint
    }

    #[must_use]
    pub const fn machine_route(self) -> MachineRouteId {
        self.machine_route
    }
}

/// 完整审计后可用于选择 machine 的无 secret 投影。
#[derive(Clone, Eq, PartialEq)]
pub struct PairedMachineSummary {
    identity: PairedMachineIdentity,
    machine_display_name: String,
    device_route: DeviceRouteId,
}

impl fmt::Debug for PairedMachineSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedMachineSummary([REDACTED])")
    }
}

impl PairedMachineSummary {
    #[must_use]
    pub const fn identity(&self) -> PairedMachineIdentity {
        self.identity
    }

    #[must_use]
    pub fn machine_display_name(&self) -> &str {
        &self.machine_display_name
    }

    #[must_use]
    pub const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }
}

enum OpenedPairedKeyMaterial {
    CommandTx(AeadSendingKey),
    ReplyTx {
        key: AeadReceivingKey,
        nonce_prefix: [u8; 4],
    },
    StreamRx {
        key: AeadReceivingKey,
        nonce_prefix: [u8; 4],
    },
}

struct OpenedPairedDirectoryKey {
    key_id: KeyId,
    stream_route: Option<StreamRouteId>,
    material: OpenedPairedKeyMaterial,
}

#[derive(Clone, Copy)]
struct StreamBindingAuditContext {
    identity: PairedMachineIdentity,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    trust_epoch: TrustEpoch,
    directory_revision: KeyDirectoryRevision,
}

fn validate_stream_binding_against_audit(
    binding: &StreamBindingV1,
    context: StreamBindingAuditContext,
    authorization: &DeviceAuthorizationV1,
    opened_keys: &[OpenedPairedDirectoryKey],
) -> Result<(), PairedPromotionError> {
    if binding.machine_route != context.identity.machine_route
        || binding.device_route != context.device_route
        || binding.grant_serial != context.grant_serial
        || binding.root_trust_epoch != context.trust_epoch
        || binding.key_directory_revision != context.directory_revision
        || authorization.machine_route != context.identity.machine_route
        || authorization.device_route != context.device_route
        || authorization.grant_serial != context.grant_serial
        || authorization.trust_epoch != context.trust_epoch
    {
        return Err(PairedPromotionError::Conflict);
    }
    let (required_capability, required_permission, expected_route) = match binding.key_id.purpose {
        KeyPurpose::Catalog => (
            AuthorizationCapabilityV1::Catalog,
            AuthorizationPermissionV1::CatalogRead,
            None,
        ),
        KeyPurpose::ConversationDek => (
            AuthorizationCapabilityV1::Conversation,
            AuthorizationPermissionV1::ConversationRead,
            Some(binding.stream_route),
        ),
        KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
            return Err(PairedPromotionError::Conflict);
        }
    };
    if !authorization.capabilities.contains(&required_capability)
        || !authorization.permissions.contains(&required_permission)
    {
        return Err(PairedPromotionError::Conflict);
    }
    let matching = opened_keys
        .iter()
        .filter(|entry| {
            entry.key_id == binding.key_id
                && entry.stream_route == expected_route
                && matches!(&entry.material, OpenedPairedKeyMaterial::StreamRx { .. })
        })
        .count();
    if matching == 1 {
        Ok(())
    } else {
        Err(PairedPromotionError::Conflict)
    }
}

fn validate_typed_stream_state_and_stage(
    state: &PairedCryptoState,
    prepared_stage: Option<&PreparedCryptoStateStage>,
    context: StreamBindingAuditContext,
    authorization: &DeviceAuthorizationV1,
    opened_keys: &[OpenedPairedDirectoryKey],
) -> Result<(), PairedPromotionError> {
    validate_typed_stream_state(state, context, authorization, opened_keys)?;
    validate_key_sync_state_against_audit(state, context)?;
    if let Some(prepared) = prepared_stage {
        let next = PairedCryptoState::decode(prepared.snapshot().expose_secret())?;
        validate_typed_stream_state(&next, context, authorization, opened_keys)?;
        validate_key_sync_state_against_audit(&next, context)?;
    }
    Ok(())
}

fn validate_typed_stream_state(
    state: &PairedCryptoState,
    context: StreamBindingAuditContext,
    authorization: &DeviceAuthorizationV1,
    opened_keys: &[OpenedPairedDirectoryKey],
) -> Result<(), PairedPromotionError> {
    let Some(bindings) = state.typed_durable_stream_bindings()? else {
        return Ok(());
    };
    for binding in bindings {
        validate_stream_binding_against_audit(
            binding.binding(),
            context,
            authorization,
            opened_keys,
        )?;
    }
    Ok(())
}

/// ADKS canonical bytes 只证明编码有效；durable acceptance 还必须绑定当前 paired
/// authority、已安装 directory revision，以及产生 higher-revision observation 的 exact
/// live publication slot。active、prepared 与 commit candidate 共用这一条审计路径。
fn validate_key_sync_state_against_audit(
    state: &PairedCryptoState,
    context: StreamBindingAuditContext,
) -> Result<(), PairedPromotionError> {
    let Some(key_sync) = state.durable_key_sync_state()? else {
        return Ok(());
    };
    let observation = key_sync.observation();
    if observation.machine_route() != context.identity.machine_route
        || observation.device_route() != context.device_route
        || observation.grant_serial() != context.grant_serial
        || observation.root_trust_epoch() != context.trust_epoch
        || key_sync.current_known_key_directory_revision() != context.directory_revision
    {
        return Err(PairedPromotionError::Conflict);
    }

    let bindings = state.durable_stream_bindings()?;
    // V1/V2 legacy state 没有 typed publication inventory；首次 V4 migration 仍可由
    // marker/directory 的硬 authority 轴授权。只要 inventory 已存在，就必须 exact 命中，
    // 不允许用另一路 route/generation 或 purpose/slot 注入 canonical ADKS。
    if bindings.is_empty() {
        return Ok(());
    }
    let matching_publications = bindings
        .into_iter()
        .filter(|durable| {
            let binding = durable.binding();
            binding.stream_route == observation.publication_stream_route()
                && binding.stream_generation == observation.publication_stream_generation()
                && binding.key_directory_revision == key_sync.current_known_key_directory_revision()
                && binding.key_id.purpose == observation.observed_key_id().purpose
                && stream_key_slot_route(binding.key_id, binding.stream_route).ok()
                    == Some(observation.key_slot_stream_route())
        })
        .count();
    if matching_publications == 1 {
        Ok(())
    } else {
        Err(PairedPromotionError::Conflict)
    }
}

struct AuditedPairedMachine {
    identity: PairedMachineIdentity,
    machine_display_name: String,
    wss_url: String,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    trust_epoch: TrustEpoch,
    directory_revision: KeyDirectoryRevision,
    relay_server_id: RelayServerId,
    current_spki_pin: [u8; 32],
    next_spki_pin: [u8; 32],
    state_store: FileCryptoStateStore,
    state_snapshot: CryptoStateSnapshot,
    state: PairedCryptoState,
    prepared_stage: Option<PreparedCryptoStateStage>,
    counter_account: RemoteKeyAccount,
    counter_guard_bytes: RemoteSecret,
    counter_guard: CounterGuardState,
    device_command_binding: CounterBindingV1,
    marker: PairedCommitMarkerV1,
    _canonical_receipt_carrier: Vec<u8>,
    grant: RelayGrant,
    authorization: DeviceAuthorizationV1,
    device_signing_key: Arc<SigningKey>,
    machine_data_verifying_key: VerifyingKey,
    _device_hpke_private_key: HpkePrivateKey,
    opened_directory_keys: Vec<OpenedPairedDirectoryKey>,
}

/// `OpenedPairedMachine` 审计后 mint 的受控 Relay 连接材料。
///
/// 该投影只允许消费为 immutable client config 与 typed authenticator；不暴露
/// DeviceSign、grant 或 TLS pin 的 raw getter。
pub(super) struct PairedRelayConnectionMaterial {
    config: RelayClientConfig,
    authenticator: Arc<dyn LinkAuthenticator>,
}

impl fmt::Debug for PairedRelayConnectionMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedRelayConnectionMaterial([REDACTED])")
    }
}

impl PairedRelayConnectionMaterial {
    pub(super) fn into_parts(self) -> (RelayClientConfig, Arc<dyn LinkAuthenticator>) {
        (self.config, self.authenticator)
    }
}

struct PairedDeviceAuthenticator {
    signing_key: Arc<SigningKey>,
    grant: RelayGrant,
}

#[async_trait]
impl LinkAuthenticator for PairedDeviceAuthenticator {
    fn proof(&self) -> AuthProof {
        AuthProof::Device {
            relay_grant: self.grant.clone(),
        }
    }

    async fn authenticate(&self, challenge: &Challenge) -> Result<Authenticate, RelayClientError> {
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::Device,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.grant.machine_route,
            device_route: Some(self.grant.device_route),
            serial_or_generation: self.grant.grant_serial.value(),
            credential_sha256: self.grant.canonical_sha256(),
        };
        Ok(Authenticate {
            proof: self.proof(),
            signature: sign_authentication_transcript(self.signing_key.as_ref(), &transcript)
                .into(),
        })
    }
}

pub(super) fn paired_spki_pins(current: [u8; 32], next: [u8; 32]) -> Vec<[u8; 32]> {
    if current == next {
        vec![current]
    } else {
        vec![current, next]
    }
}

#[cfg(test)]
pub(super) fn device_authenticator_for_test(
    signing_key: SigningKey,
    grant: RelayGrant,
) -> Arc<dyn LinkAuthenticator> {
    Arc::new(PairedDeviceAuthenticator {
        signing_key: Arc::new(signing_key),
        grant,
    })
}

/// 已完成 canonical decode、header/AAD 绑定与 MachineDataSign 验证的 directed reply。
/// 字段保持私有，只有 replay durable admission 后才能交回 paired machine 做 AEAD open。
pub(crate) struct VerifiedDirectedReply {
    verified: VerifiedSealedBlobV1,
    context: OuterContextV1,
    brand: DirectedReplyBrand,
    counter: u64,
    signed_blob_hash: [u8; 32],
}

/// 已完成 canonical Relay outer、durable route/generation 与 MachineDataSign/AAD 验证的
/// stream proof。当前 revision 才携带可进入 replay/AEAD 的 branded token；未知更高
/// directory revision 只携带 bounded KeySync observation，绝不伪装成可解密 publication。
pub(crate) enum VerifiedStreamPublish {
    Current(VerifiedCurrentStreamPublish),
    Higher(VerifiedHigherStreamPublish),
}

pub(crate) struct VerifiedCurrentStreamPublish {
    verified: VerifiedSealedBlobV1,
    context: OuterContextV1,
    brand: StreamPublishBrand,
    stream_seq: u64,
    counter: u64,
    ciphertext_sha256: [u8; 32],
}

pub(crate) struct VerifiedHigherStreamPublish {
    observation: SignedHigherRevisionObservationV1,
}

/// 当前 paired capability 对 root-signed Relay terminal 完整验签后铸造的撤销证明。
///
/// 字段私有且类型不可由调用方构造；后续 cleanup 协调器只能消费本 token，不能接受裸
/// `RevocationCommitted`、socket close 或普通 daemon receipt 作为删除授权。
pub struct VerifiedRevocationTerminal {
    canonical_bytes: Vec<u8>,
    identity: PairedMachineIdentity,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
}

impl fmt::Debug for VerifiedRevocationTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedRevocationTerminal([REDACTED])")
    }
}

impl VerifiedRevocationTerminal {
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn identity(&self) -> PairedMachineIdentity {
        self.identity
    }

    #[must_use]
    pub const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }

    #[must_use]
    pub const fn grant_serial(&self) -> GrantSerial {
        self.grant_serial
    }
}

#[derive(Clone, Copy)]
struct RevocationTerminalBinding {
    root_fingerprint: [u8; 32],
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    machine_root_pubkey: [u8; 32],
}

fn validate_exact_revocation_terminal(
    frame: &OpaqueRouteFrame,
    canonical_bytes: &[u8],
    expected: RevocationTerminalBinding,
) -> Result<(), PairedPromotionError> {
    if frame.version != RELAY_PROTOCOL_VERSION || encode(frame).as_slice() != canonical_bytes {
        return Err(PairedPromotionError::InvalidState);
    }
    let RelayFrameBody::RevocationCommitted(RevocationCommitted {
        device_route,
        grant_serial,
        signed_revocation,
    }) = &frame.body
    else {
        return Err(PairedPromotionError::InvalidState);
    };
    if *device_route != signed_revocation.device_route
        || *grant_serial != signed_revocation.grant_serial
        || signed_revocation.machine_route != expected.machine_route
        || signed_revocation.device_route != expected.device_route
        || signed_revocation.grant_serial != expected.grant_serial
        || signed_revocation.root_key_id != expected.root_key_id
        || signed_revocation.trust_epoch != expected.trust_epoch
    {
        return Err(PairedPromotionError::Conflict);
    }
    let root = VerifyingKey::from_bytes(&expected.machine_root_pubkey)
        .map_err(PairedPromotionError::Crypto)?;
    if sha256(&root.to_bytes()) != expected.root_fingerprint {
        return Err(PairedPromotionError::Conflict);
    }
    verify_tbs(
        &root,
        &signed_revocation.to_be_signed_v1(expected.relay_server_id, expected.root_fingerprint),
        &SignatureBytes::from(signed_revocation.signature),
    )
    .map_err(PairedPromotionError::Crypto)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectedReplyBrand {
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    key_id: KeyId,
    key_epoch: u64,
    directory_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StreamPublishBrand {
    machine_route: MachineRouteId,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    key_id: KeyId,
    directory_revision: u64,
    frame_kind: OuterFrameKind,
}

fn validate_directed_reply_brand(
    actual: DirectedReplyBrand,
    expected: DirectedReplyBrand,
) -> Result<(), PairedPromotionError> {
    if actual != expected {
        return Err(PairedPromotionError::Conflict);
    }
    Ok(())
}

fn stream_publish_frame_kind(key_id: KeyId) -> Result<OuterFrameKind, PairedPromotionError> {
    match key_id.purpose {
        KeyPurpose::Catalog => Ok(OuterFrameKind::CatalogPublish),
        KeyPurpose::ConversationDek => Ok(OuterFrameKind::ConversationPublish),
        KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
            Err(PairedPromotionError::Conflict)
        }
    }
}

fn stream_key_slot_route(
    key_id: KeyId,
    publication_route: StreamRouteId,
) -> Result<Option<StreamRouteId>, PairedPromotionError> {
    match key_id.purpose {
        KeyPurpose::Catalog => Ok(None),
        KeyPurpose::ConversationDek => Ok(Some(publication_route)),
        KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
            Err(PairedPromotionError::Conflict)
        }
    }
}

fn stream_publish_brand(
    machine_route: MachineRouteId,
    binding: &StreamBindingV1,
) -> Result<StreamPublishBrand, PairedPromotionError> {
    Ok(StreamPublishBrand {
        machine_route,
        stream_route: binding.stream_route,
        stream_generation: binding.stream_generation,
        key_id: binding.key_id,
        directory_revision: binding.key_directory_revision.value(),
        frame_kind: stream_publish_frame_kind(binding.key_id)?,
    })
}

impl VerifiedDirectedReply {
    #[must_use]
    pub(crate) const fn key_epoch(&self) -> u64 {
        self.brand.key_epoch
    }

    #[must_use]
    pub(crate) const fn directory_revision(&self) -> u64 {
        self.brand.directory_revision
    }

    #[must_use]
    pub(crate) const fn counter(&self) -> u64 {
        self.counter
    }

    #[must_use]
    pub(crate) const fn signed_blob_hash(&self) -> [u8; 32] {
        self.signed_blob_hash
    }
}

impl VerifiedCurrentStreamPublish {
    #[must_use]
    pub(crate) const fn stream_seq(&self) -> u64 {
        self.stream_seq
    }

    #[must_use]
    pub(crate) const fn counter(&self) -> u64 {
        self.counter
    }

    #[must_use]
    pub(crate) const fn ciphertext_sha256(&self) -> [u8; 32] {
        self.ciphertext_sha256
    }
}

impl VerifiedHigherStreamPublish {
    #[must_use]
    pub(crate) fn into_observation(self) -> SignedHigherRevisionObservationV1 {
        self.observation
    }
}

impl AuditedPairedMachine {
    fn summary(&self) -> PairedMachineSummary {
        PairedMachineSummary {
            identity: self.identity,
            machine_display_name: self.machine_display_name.clone(),
            device_route: self.device_route,
        }
    }

    fn into_opened<'a>(
        self,
        store: &'a dyn RemoteKeyStore,
        mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
        runtime_state_mutation_authority: RuntimeStateMutationAuthority,
        lease: RemoteDeviceLease,
    ) -> OpenedPairedMachine<'a> {
        OpenedPairedMachine {
            audited: self,
            store,
            mutation_observer,
            runtime_state_mutation_authority,
            _lease: lease,
        }
    }
}

/// marker-first 只读审计成功后持有 device lease 与 typed crypto capabilities 的 machine。
///
/// 本类型不实现 `Clone` / serde，`Debug` 永远 redacted，且没有 raw secret getter。
pub struct OpenedPairedMachine<'a> {
    audited: AuditedPairedMachine,
    store: &'a dyn RemoteKeyStore,
    mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    // 必须最后销毁，确保 crypto/counter capabilities 不会晚于跨进程独占 lease。
    _lease: RemoteDeviceLease,
}

impl fmt::Debug for OpenedPairedMachine<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedPairedMachine([REDACTED])")
    }
}

impl OpenedPairedMachine<'_> {
    #[must_use]
    pub const fn identity(&self) -> PairedMachineIdentity {
        self.audited.identity
    }

    #[must_use]
    pub fn machine_display_name(&self) -> &str {
        &self.audited.machine_display_name
    }

    #[must_use]
    pub fn wss_url(&self) -> &str {
        &self.audited.wss_url
    }

    /// 从完整审计后的 paired capability mint 唯一 production Relay profile。
    ///
    /// TLS 永远是 state-bound pinned-SPKI；current/next 仅做保序 exact 去重，不存在
    /// public-CA fallback、CLI override 或 raw DeviceSign/grant getter。
    pub(super) fn mint_relay_connection_material(
        &self,
    ) -> Result<PairedRelayConnectionMaterial, RelayClientError> {
        let tls = RelayTlsPolicy::pinned_spki(paired_spki_pins(
            self.audited.current_spki_pin,
            self.audited.next_spki_pin,
        ))?;
        let config =
            RelayClientConfig::new(&self.audited.wss_url, self.audited.relay_server_id, tls)?;
        let authenticator: Arc<dyn LinkAuthenticator> = Arc::new(PairedDeviceAuthenticator {
            signing_key: Arc::clone(&self.audited.device_signing_key),
            grant: self.audited.grant.clone(),
        });
        Ok(PairedRelayConnectionMaterial {
            config,
            authenticator,
        })
    }

    #[must_use]
    pub const fn device_route(&self) -> DeviceRouteId {
        self.audited.device_route
    }

    #[must_use]
    pub const fn grant_serial(&self) -> GrantSerial {
        self.audited.grant_serial
    }

    #[must_use]
    pub const fn trust_epoch(&self) -> TrustEpoch {
        self.audited.trust_epoch
    }

    #[must_use]
    pub const fn directory_revision(&self) -> KeyDirectoryRevision {
        self.audited.directory_revision
    }

    /// 验证 active connection 或 reconnect authentication 返回的 exact root-signed
    /// `RevocationCommitted`。本函数纯验证、零持久化 mutation；成功只铸造后续 cleanup
    /// 可以消费的 type-state。
    pub fn verify_revocation_terminal(
        &self,
        frame: &OpaqueRouteFrame,
        canonical_bytes: &[u8],
    ) -> Result<VerifiedRevocationTerminal, PairedPromotionError> {
        let bootstrap = self.audited.state.bootstrap();
        validate_exact_revocation_terminal(
            frame,
            canonical_bytes,
            RevocationTerminalBinding {
                root_fingerprint: bootstrap.machine_root_fingerprint,
                relay_server_id: self.audited.relay_server_id,
                machine_route: self.audited.identity.machine_route,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                root_key_id: self.audited.grant.root_key_id,
                trust_epoch: self.audited.trust_epoch,
                machine_root_pubkey: bootstrap.machine_root_pubkey,
            },
        )?;

        Ok(VerifiedRevocationTerminal {
            canonical_bytes: canonical_bytes.to_vec(),
            identity: self.audited.identity,
            device_route: self.audited.device_route,
            grant_serial: self.audited.grant_serial,
        })
    }

    /// 把已验证的 root-signed terminal 原子提升为唯一 cleanup journal，再按固定顺序
    /// 删除本 machine 的 sealed state 与 Keychain material。journal 是唯一可见性边界，
    /// 一旦 durable，machine 永远不能再作为 active pairing 打开。
    pub fn commit_revocation_cleanup(
        mut self,
        terminal: VerifiedRevocationTerminal,
    ) -> Result<(), PairedPromotionError> {
        if terminal.identity != self.audited.identity
            || terminal.device_route != self.audited.device_route
            || terminal.grant_serial != self.audited.grant_serial
        {
            return Err(PairedPromotionError::Conflict);
        }

        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.refresh_mutable_state()?;
        if self.audited.prepared_stage.is_some() {
            return Err(PairedPromotionError::Conflict);
        }

        let accounts = PairedAccounts::new(
            self.audited.marker.installation_id,
            self.audited.identity.machine_root_fingerprint,
            self.audited.identity.machine_route,
        );
        let device_sign = self.load_cleanup_source(&accounts.device_sign)?;
        let device_hpke = self.load_cleanup_source(&accounts.device_hpke)?;
        let grant = self.load_cleanup_source(&accounts.grant)?;
        let storage_kek = self.load_cleanup_source(&accounts.kek)?;
        let kek_record = StorageKekRecordV1::decode(storage_kek.expose_secret())?;
        if kek_record.promotion_id != self.audited.marker.promotion_id
            || kek_record.commitment() != self.audited.marker.kek_record_hash
        {
            return Err(PairedPromotionError::Conflict);
        }
        let durable = audit_durable_state(
            self.audited.state.bootstrap(),
            grant.expose_secret(),
            &device_sign,
            &device_hpke,
        )?;
        if durable.device_signing_key.verifying_key().to_bytes()
            != self.audited.marker.device_sign_pubkey
            || hpke_public_bytes(&durable.device_hpke_private_key)?
                != self.audited.marker.device_hpke_pubkey
        {
            return Err(PairedPromotionError::Conflict);
        }

        let terminal_frame =
            decode(&terminal.canonical_bytes).map_err(|_| PairedPromotionError::InvalidState)?;
        let bootstrap = self.audited.state.bootstrap();
        validate_exact_revocation_terminal(
            &terminal_frame,
            &terminal.canonical_bytes,
            RevocationTerminalBinding {
                root_fingerprint: bootstrap.machine_root_fingerprint,
                relay_server_id: bootstrap.relay_server_id,
                machine_route: bootstrap.machine_route,
                device_route: bootstrap.device_route,
                grant_serial: bootstrap.grant_serial,
                root_key_id: durable.grant.root_key_id,
                trust_epoch: bootstrap.trust_epoch,
                machine_root_pubkey: bootstrap.machine_root_pubkey,
            },
        )?;

        let mut journal = PairedCleanupJournalV1 {
            installation_id: self.audited.marker.installation_id,
            root_fingerprint: self.audited.marker.root_fingerprint,
            relay_server_id: self.audited.marker.relay_server_id,
            machine_route: self.audited.marker.machine_route,
            device_route: self.audited.marker.device_route,
            grant_serial: self.audited.marker.grant_serial,
            root_key_id: durable.grant.root_key_id,
            trust_epoch: self.audited.marker.trust_epoch,
            machine_root_pubkey: bootstrap.machine_root_pubkey,
            active_marker: self.audited.marker,
            terminal_bytes: terminal.canonical_bytes,
            grant_bytes: grant.expose_secret().to_vec(),
            state_plaintext_hash: sha256(self.audited.state_snapshot.expose_secret()),
            counter_guard_hash: sha256(self.audited.counter_guard_bytes.expose_secret()),
            grant_hash: sha256(grant.expose_secret()),
            device_hpke_hash: sha256(device_hpke.expose_secret()),
            device_sign_hash: sha256(device_sign.expose_secret()),
            storage_kek_hash: sha256(storage_kek.expose_secret()),
            journal_signature: SignatureBytes([0; 64]),
        };
        journal.journal_signature = sign_revocation_cleanup_journal_digest(
            &durable.device_signing_key,
            sha256(&journal.encode_unsigned()?),
        );
        journal.validate(self.audited.identity)?;
        let active_marker = RemoteSecret::new(self.audited.marker.encode());
        let journal_bytes = journal.encode()?;
        self.store
            .compare_and_replace_exact(
                &accounts.marker,
                &active_marker,
                &RemoteSecret::new(journal_bytes.clone()),
            )
            .map_err(PairedPromotionError::Persistence)?;
        self.observe_mutation(PairedMutationStage::CleanupJournalDurable);

        execute_revocation_cleanup(
            self.store,
            self.audited.state_store.root(),
            self.audited.identity,
            &accounts,
            &journal,
            &journal_bytes,
            self.mutation_observer.as_deref(),
        )
    }

    fn load_cleanup_source(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<RemoteSecret, PairedPromotionError> {
        self.store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)
    }

    /// 只暴露已逐项 DeviceHPKE 解封成功的 key 数量，不返回 raw key。
    #[must_use]
    pub fn opened_key_count(&self) -> usize {
        self.audited.opened_directory_keys.len()
    }

    /// 查询完整审计后是否存在指定 purpose；不暴露 epoch、route 或 raw key。
    #[must_use]
    pub fn has_opened_key_purpose(&self, purpose: KeyPurpose) -> bool {
        self.audited
            .opened_directory_keys
            .iter()
            .any(|key| key.key_id.purpose == purpose)
    }

    /// 返回 runtime opaque fields 的 owned projection；不包含 KEK、traffic key 或 signing key。
    #[must_use]
    pub(crate) fn opaque_runtime_state(&self) -> OpaqueRuntimeState {
        self.audited.state.opaque_runtime_state()
    }

    /// 返回 open-time 已完成 canonical 审计的 stream binding owned projection。
    /// V1/V2 legacy state 只接受空集合；typed binding 一律写入 V3。
    pub fn durable_stream_bindings(
        &self,
    ) -> Result<Vec<DurableStreamBindingV1>, PairedPromotionError> {
        self.audited.state.durable_stream_bindings()
    }

    /// 返回 open-time 已完成 canonical 审计的 KeySync coordination owned projection。
    /// V1/V2/V3 与 V4 的 empty optional field 都映射为 `None`。
    pub fn durable_key_sync_state(
        &self,
    ) -> Result<Option<DurableKeySyncStateV1>, PairedPromotionError> {
        self.audited.state.durable_key_sync_state()
    }

    /// 以完整 canonical ADKS bytes 做 CAS，并复用 paired state 的 prepared/guard 前滚事务。
    /// exact replacement 优先于 expected 比较，因此 committed retry 即使携带 stale expected
    /// 也不会取 entropy 或产生 durable write。
    pub(crate) fn commit_key_sync_state_transition<R: CryptoRng>(
        &mut self,
        expected: Option<&DurableKeySyncStateV1>,
        replacement: Option<&DurableKeySyncStateV1>,
        rng: &mut R,
    ) -> Result<Option<DurableKeySyncStateV1>, PairedPromotionError> {
        let canonical_bytes = |state: Option<&DurableKeySyncStateV1>| {
            state
                .map(|value| {
                    value
                        .canonical_bytes()
                        .map_err(|_| PairedPromotionError::InvalidState)
                })
                .transpose()
        };
        let expected_bytes = canonical_bytes(expected)?;
        let replacement_bytes = canonical_bytes(replacement)?;

        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        let current_bytes = self
            .audited
            .state
            .key_sync_state_bytes()
            .map(ToOwned::to_owned);
        if current_bytes == replacement_bytes {
            return self.audited.state.durable_key_sync_state();
        }
        if current_bytes != expected_bytes {
            return Err(PairedPromotionError::Conflict);
        }

        let next_state = self.audited.state.with_key_sync_state_bytes(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            replacement_bytes.clone(),
            true,
        )?;
        validate_key_sync_state_against_audit(
            &next_state,
            StreamBindingAuditContext {
                identity: self.audited.identity,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                trust_epoch: self.audited.trust_epoch,
                directory_revision: self.audited.directory_revision,
            },
        )?;
        let next_state_bytes = next_state.encode()?;
        match self.commit_prepared_state_transition(next_state, next_state_bytes, rng) {
            Ok(()) => self.audited.state.durable_key_sync_state(),
            Err(write_error) => {
                // guard finalize 或 sidecar cleanup 失败时，先前 active CAS 可能已经提交。
                // 只在完整 durable readback 等于 candidate 时把结果升级为成功。
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                let _recovery = self.recover_pending_guard();
                let recovered_bytes = self
                    .audited
                    .state
                    .key_sync_state_bytes()
                    .map(ToOwned::to_owned);
                if recovered_bytes == replacement_bytes {
                    self.audited.state.durable_key_sync_state()
                } else if recovered_bytes == expected_bytes {
                    Err(write_error)
                } else {
                    Err(PairedPromotionError::Conflict)
                }
            }
        }
    }

    /// 仅供 automatic integration harness 驱动 crate-private authenticated KeySync commit。
    /// production handle 在读取 state、canonical candidate、entropy 与任一 durable mutation
    /// 之前拒绝，不能把公开可构造的 observation 当作 ingress proof type。
    #[doc(hidden)]
    pub fn commit_key_sync_state_transition_for_automatic_harness<R: CryptoRng>(
        &mut self,
        expected: Option<&DurableKeySyncStateV1>,
        replacement: Option<&DurableKeySyncStateV1>,
        rng: &mut R,
    ) -> Result<Option<DurableKeySyncStateV1>, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.commit_key_sync_state_transition(expected, replacement, rng)
    }

    /// 仅供 automatic fault harness 写入非 canonical ADKS，证明后续 `list`/`open`
    /// 全库审计 fail-close 且零改写。production handle 在读取 state、取 entropy 与任一
    /// durable mutation 之前拒绝。
    #[doc(hidden)]
    pub fn replace_unchecked_key_sync_state_for_automatic_harness<R: CryptoRng>(
        &mut self,
        replacement: Option<Vec<u8>>,
        rng: &mut R,
    ) -> Result<(), PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }

        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        if self.audited.state.key_sync_state_bytes() == replacement.as_deref() {
            return Ok(());
        }
        let next_state = self.audited.state.with_key_sync_state_bytes(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            replacement,
            false,
        )?;
        let next_state_bytes = match &next_state {
            PairedCryptoState::V4(value) => {
                value.encode_version_inner(KEY_SYNC_STATE_VERSION, false)?
            }
            PairedCryptoState::V1(_) | PairedCryptoState::V2(_) | PairedCryptoState::V3(_) => {
                return Err(PairedPromotionError::InvalidState);
            }
        };
        self.commit_prepared_state_transition(next_state, next_state_bytes, rng)
    }

    /// 安装 directed `StreamBindingV1` 的初始 durable cut。相同 target 只允许 exact
    /// idempotent retry；generation、route、key 或 cursor 漂移必须由后续显式 replacement
    /// 状态机处理，不能在这个初始入口静默覆盖。
    pub(crate) fn install_stream_binding<R: CryptoRng>(
        &mut self,
        binding: StreamBindingV1,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        let candidate = DurableStreamBindingV1::from_stream_binding(binding)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.validate_stream_binding_capability(candidate.binding())?;
        let mut states = self.audited.state.durable_stream_bindings()?;
        let target = candidate.target_key();
        if let Some(existing) = states.iter().find(|state| state.target_key() == target) {
            return if existing.binding() == candidate.binding() {
                Ok(existing.clone())
            } else {
                Err(PairedPromotionError::Conflict)
            };
        }
        states.push(candidate.clone());
        let stream_bindings =
            encode_stream_bindings(states).map_err(|_| PairedPromotionError::InvalidState)?;
        let current = self.audited.state.opaque_runtime_state();
        let replacement = OpaqueRuntimeState::new(
            current.exchange().map(ToOwned::to_owned),
            current.replay_windows().to_vec(),
            stream_bindings,
        );
        self.replace_opaque_runtime_state(&replacement, rng)?;
        Ok(candidate)
    }

    /// 在 authenticated subscription bootstrap 已完整归约后，原子安装或替换该 target
    /// 的 directed `StreamBindingV1`、推进已应用 inner cut，并清除 exact request pending。
    ///
    /// bootstrap 明文不写入 durable state；因此不能持久化一个缺少 reducer 内容、却能在
    /// 冷启动时冒充完整结果的 terminal。若进程在后续 Relay control send 前退出，下一次
    /// cold subscribe 会建立新的 snapshot request，并由本入口替换旧 target binding。
    /// 其他 target 与 receive replay windows 始终原样保留；新 route 与其他 target 冲突时
    /// canonical collection encoder 会在任何写入前 fail-close。
    pub(crate) fn commit_subscription_bootstrap<R: CryptoRng>(
        &mut self,
        binding: StreamBindingV1,
        inner_applied: RuntimeInnerCursor,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        let mut states = self.audited.state.durable_stream_bindings()?;
        let fresh = DurableStreamBindingV1::from_subscription_bootstrap(
            binding.clone(),
            inner_applied.clone(),
        )
        .map_err(|_| PairedPromotionError::InvalidState)?;
        let target = fresh.target_key();
        let candidate =
            if let Some(existing) = states.iter().find(|state| state.target_key() == target) {
                existing
                    .replace_subscription_bootstrap(binding, inner_applied)
                    .map_err(|_| PairedPromotionError::Conflict)?
            } else {
                fresh
            };
        self.validate_stream_binding_capability(candidate.binding())?;
        states.retain(|state| state.target_key() != target);
        states.push(candidate.clone());
        let stream_bindings =
            encode_stream_bindings(states).map_err(|_| PairedPromotionError::InvalidState)?;
        let current = self.audited.state.opaque_runtime_state();
        let replacement =
            OpaqueRuntimeState::new(None, current.replay_windows().to_vec(), stream_bindings);
        self.replace_opaque_runtime_state(&replacement, rng)?;
        Ok(candidate)
    }

    /// 以完整 durable state 做 CAS，提交一条 live stream 的 replay admission 或 outer/inner
    /// apply transition。replacement 不能改写 binding/target；其他 stream、directed exchange
    /// 与 reply replay windows 在同一 sealed-state transaction 中逐字保留。
    pub(crate) fn commit_stream_state_transition<R: CryptoRng>(
        &mut self,
        expected: &DurableStreamBindingV1,
        replacement: &DurableStreamBindingV1,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        if expected.binding() != replacement.binding()
            || expected.target_key() != replacement.target_key()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let _ = replacement
            .canonical_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.validate_stream_binding_capability(expected.binding())?;
        self.validate_stream_binding_capability(replacement.binding())?;
        let mut states = self.audited.state.durable_stream_bindings()?;
        let target = expected.target_key();
        let current = states
            .iter_mut()
            .find(|state| state.target_key() == target)
            .ok_or(PairedPromotionError::Conflict)?;
        if current == replacement {
            return Ok(current.clone());
        }
        if current != expected {
            return Err(PairedPromotionError::Conflict);
        }
        *current = replacement.clone();
        let stream_bindings =
            encode_stream_bindings(states).map_err(|_| PairedPromotionError::InvalidState)?;
        let current_runtime = self.audited.state.opaque_runtime_state();
        let next_runtime = OpaqueRuntimeState::new(
            current_runtime.exchange().map(ToOwned::to_owned),
            current_runtime.replay_windows().to_vec(),
            stream_bindings,
        );
        match self.replace_opaque_runtime_state(&next_runtime, rng) {
            Ok(_) => Ok(replacement.clone()),
            Err(write_error) => {
                // active state CAS 之后的 guard-finalize/sidecar cleanup 仍可能报错。此时先
                // refresh + forward-recover，再以完整 candidate readback 决定是否已 COMMIT；
                // 不能把“已落盘但返回 Err”交给 runtime，导致 reducer 永久不 swap。
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                let _recovery = self.recover_pending_guard();
                let recovered = self.audited.state.durable_stream_bindings()?;
                let current = recovered
                    .iter()
                    .find(|state| state.target_key() == target)
                    .ok_or(PairedPromotionError::Conflict)?;
                if current == replacement {
                    Ok(replacement.clone())
                } else if current == expected {
                    Err(write_error)
                } else {
                    Err(PairedPromotionError::Conflict)
                }
            }
        }
    }

    /// 在对应 Relay ACK 的 transport write 成功后，精确推进同一 durable stream cut。
    /// 只有调用方刚读取的完整 state 仍与磁盘一致时才允许写入，避免把旧 ACK 套到已替换
    /// binding、reducer 或 replay state 上。重复提交同一 exact cut 保持幂等。
    pub(crate) fn commit_stream_ack<R: CryptoRng>(
        &mut self,
        expected: &DurableStreamBindingV1,
        up_to_seq: u64,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.validate_stream_binding_capability(expected.binding())?;
        let mut states = self.audited.state.durable_stream_bindings()?;
        let target = expected.target_key();
        let current = states
            .iter_mut()
            .find(|state| state.target_key() == target)
            .ok_or(PairedPromotionError::Conflict)?;
        let expected_acked = expected
            .with_committed_outer_ack(up_to_seq)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        if current != expected && current != &expected_acked {
            return Err(PairedPromotionError::Conflict);
        }
        let committed = current
            .with_committed_outer_ack(up_to_seq)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        *current = committed.clone();
        let stream_bindings =
            encode_stream_bindings(states).map_err(|_| PairedPromotionError::InvalidState)?;
        let current = self.audited.state.opaque_runtime_state();
        let replacement = OpaqueRuntimeState::new(
            current.exchange().map(ToOwned::to_owned),
            current.replay_windows().to_vec(),
            stream_bindings,
        );
        self.replace_opaque_runtime_state(&replacement, rng)?;
        Ok(committed)
    }

    /// 仅供 automatic library harness 覆盖 stream-state 持久化与 crash recovery。
    /// production handle 不能调用；真实链路必须由后续 authenticated KeyControl ingress
    /// 在 crate 内消费 verified `StreamBindingV1` 后进入私有安装入口。
    #[doc(hidden)]
    pub fn install_stream_binding_for_automatic_harness<R: CryptoRng>(
        &mut self,
        binding: StreamBindingV1,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.install_stream_binding(binding, rng)
    }

    /// 仅供 automatic fault harness 把 canonical、但与当前 paired authority/key slot
    /// 不一致的 V3 stream collection 注入完整 durable transaction。此入口故意跳过
    /// semantic audit，用来证明后续 `list`/`open` 的全库审计 fail-close；production handle
    /// 永远在编码、entropy 与持久化之前拒绝。
    #[doc(hidden)]
    pub fn replace_unchecked_stream_bindings_for_automatic_harness<R: CryptoRng>(
        &mut self,
        bindings: Vec<StreamBindingV1>,
        rng: &mut R,
    ) -> Result<(), PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let bindings = bindings
            .into_iter()
            .map(DurableStreamBindingV1::from_stream_binding)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let stream_bindings =
            encode_stream_bindings(bindings).map_err(|_| PairedPromotionError::InvalidState)?;
        let current = self.audited.state.opaque_runtime_state();
        let replacement = OpaqueRuntimeState::new(
            current.exchange().map(ToOwned::to_owned),
            current.replay_windows().to_vec(),
            stream_bindings,
        );
        self.replace_opaque_runtime_state(&replacement, rng)?;
        Ok(())
    }

    fn validate_stream_binding_capability(
        &self,
        binding: &StreamBindingV1,
    ) -> Result<(), PairedPromotionError> {
        validate_stream_binding_against_audit(
            binding,
            StreamBindingAuditContext {
                identity: self.audited.identity,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                trust_epoch: self.audited.trust_epoch,
                directory_revision: self.audited.directory_revision,
            },
            &self.audited.authorization,
            &self.audited.opened_directory_keys,
        )
    }

    /// 当前 authenticated DeviceReplyTx replay scope；只暴露非秘密 epoch/revision。
    pub(crate) fn directed_reply_scope(&self) -> Result<(u64, u64), PairedPromotionError> {
        let reply_epoch = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::ReplyTx { key, .. } => Some(key.epoch),
                OpenedPairedKeyMaterial::CommandTx(_)
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        Ok((reply_epoch, self.audited.directory_revision.value()))
    }

    /// 使用审计后的 DeviceCommandTx + DeviceSign capability 封装闭合 allowlist 中的请求。
    /// reservation 按值消费并与当前 authenticated state exact 对照，调用方不能传裸 counter
    /// 或任意 `RuntimeRequest`。
    pub(crate) fn seal_runtime_request(
        &self,
        request_route: RequestRouteId,
        message_id: MessageId,
        request: AuthorizedRuntimeRequest,
        reservation: CommandCounterReservation,
    ) -> Result<Vec<u8>, PairedPromotionError> {
        let (required_capability, required_permission) = request.required_authorization();
        if self.audited.grant.machine_route != self.audited.identity.machine_route
            || self.audited.grant.device_route != self.audited.device_route
            || self.audited.grant.grant_serial != self.audited.grant_serial
            || self.audited.authorization.machine_route != self.audited.identity.machine_route
            || self.audited.authorization.device_route != self.audited.device_route
            || self.audited.authorization.grant_serial != self.audited.grant_serial
            || !self
                .audited
                .authorization
                .capabilities
                .contains(&required_capability)
            || !self
                .audited
                .authorization
                .permissions
                .contains(&required_permission)
        {
            return Err(PairedPromotionError::Conflict);
        }
        validate_current_command_reservation(
            self.audited.state.counter_reservation(),
            &reservation,
        )?;
        let command_key = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::CommandTx(key) => Some(key),
                OpenedPairedKeyMaterial::ReplyTx { .. }
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id,
            body: RuntimeMessage::Request(request.into_runtime_request()),
        };
        let plaintext = envelope
            .to_json_bytes_checked()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let context = OuterContextV1::uplink_send(
            self.audited.identity.machine_route,
            self.audited.device_route,
            request_route,
            command_key.epoch,
        );
        let unsigned = seal_symmetric(
            command_key,
            &context,
            SealedPayloadKind::CommandRequest,
            &plaintext,
            SenderCounter(reservation.start()),
        )
        .map_err(PairedPromotionError::Crypto)?;
        Ok(
            sign_sealed(unsigned, self.audited.device_signing_key.as_ref(), &context)
                .to_wire_bytes(),
        )
    }

    /// 使用当前审计后的 DeviceCommandTx + DeviceSign capability 封装 typed KeySync probe。
    /// reservation 按值消费；sealed header revision 只能由 request 的 exact-next revision
    /// 产生，不能由 runtime 传入裸 override。
    pub(crate) fn seal_key_sync_request(
        &self,
        request_route: RequestRouteId,
        request: &KeySyncRequestV1,
        reservation: CommandCounterReservation,
    ) -> Result<Vec<u8>, PairedPromotionError> {
        if request.machine_route != self.audited.identity.machine_route
            || request.device_route != self.audited.device_route
            || request.grant_serial != self.audited.grant_serial
            || request.root_trust_epoch != self.audited.trust_epoch
            || request.known_key_directory_revision != self.audited.directory_revision
        {
            return Err(PairedPromotionError::Conflict);
        }
        validate_current_command_reservation(
            self.audited.state.counter_reservation(),
            &reservation,
        )?;
        let command_key = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::CommandTx(key) => Some(key),
                OpenedPairedKeyMaterial::ReplyTx { .. }
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        let (unsigned, context) = seal_key_sync_probe(
            command_key,
            request_route,
            request,
            SenderCounter(reservation.start()),
        )
        .map_err(PairedPromotionError::Crypto)?;
        Ok(
            sign_sealed(unsigned, self.audited.device_signing_key.as_ref(), &context)
                .to_wire_bytes(),
        )
    }

    /// 在任何 stream replay/outer/inner durable mutation 前完成 Publish 的完整公开边界
    /// 验证。`binding` 必须来自本 machine 已审计的 durable collection；Publish route、
    /// generation、key header、nonce prefix、AAD 与 MachineDataSign 任一漂移都 fail-close。
    pub(crate) fn verify_stream_publish(
        &self,
        durable: &DurableStreamBindingV1,
        publish: &Publish,
    ) -> Result<VerifiedStreamPublish, PairedPromotionError> {
        let binding = durable.binding();
        let installed = self
            .audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .filter(|state| state == durable)
            .count();
        if installed != 1 {
            return Err(PairedPromotionError::Conflict);
        }
        self.validate_stream_binding_capability(binding)?;
        if publish.stream_route != binding.stream_route
            || publish.generation != binding.stream_generation
        {
            return Err(PairedPromotionError::Conflict);
        }
        let expected_slot = stream_key_slot_route(binding.key_id, binding.stream_route)?;
        let mut matching =
            self.audited
                .opened_directory_keys
                .iter()
                .filter_map(|entry| match &entry.material {
                    OpenedPairedKeyMaterial::StreamRx { key, nonce_prefix }
                        if entry.key_id == binding.key_id
                            && entry.stream_route == expected_slot =>
                    {
                        Some((key, *nonce_prefix))
                    }
                    OpenedPairedKeyMaterial::CommandTx(_)
                    | OpenedPairedKeyMaterial::ReplyTx { .. }
                    | OpenedPairedKeyMaterial::StreamRx { .. } => None,
                });
        let (stream_key, nonce_prefix) =
            matching.next().ok_or(PairedPromotionError::InvalidState)?;
        if matching.next().is_some() {
            return Err(PairedPromotionError::InvalidState);
        }
        let signed = SignedSealedBlobV1::from_wire_bytes(&publish.sealed_blob.0)
            .map_err(|error| PairedPromotionError::Crypto(error.into()))?;
        let expected_revision = self.audited.directory_revision.value();
        if binding.key_directory_revision.value() != expected_revision
            || binding.key_id != stream_key.key_id
            || binding.key_id.epoch != stream_key.epoch
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let frame_kind = stream_publish_frame_kind(binding.key_id)?;
        let context = OuterContextV1 {
            frame_kind,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: Some(self.audited.identity.machine_route),
            device_route: None,
            stream_route: Some(publish.stream_route),
            request_route: None,
            pair_route: None,
            stream_generation: Some(publish.generation),
            stream_cursor: None,
            stream_seq: Some(publish.stream_seq),
            // 先以 sender 签入 header 的 epoch 重建 TBS。只有 MachineDataSign 通过后，
            // 才能把 revision/epoch 漂移分类为 rollback 或 bounded KeySync 所需的
            // missing epoch；未认证 header 不能驱动安全状态机。
            message_key_epoch: signed.inner.key_epoch,
        };
        context
            .validate()
            .map_err(|_| PairedPromotionError::Crypto(CryptoError::BadCiphertext))?;
        let verified = verify_sealed(signed, &self.audited.machine_data_verifying_key, &context)
            .map_err(PairedPromotionError::Crypto)?;
        let header = &verified.sealed().inner;
        if header.key_id.epoch != header.key_epoch || header.key_epoch == 0 {
            return Err(PairedPromotionError::Crypto(CryptoError::BadCiphertext));
        }
        if header.key_directory_revision < expected_revision
            || (header.key_directory_revision == expected_revision
                && header.key_id.purpose == binding.key_id.purpose
                && header.key_epoch < stream_key.epoch)
        {
            return Err(PairedPromotionError::Crypto(CryptoError::E2ee(
                agentdeck_protocol::e2ee::E2eeError::KeyRevisionRollback,
            )));
        }
        if header.key_directory_revision > expected_revision {
            if header.key_id.purpose != binding.key_id.purpose {
                return Err(PairedPromotionError::Crypto(CryptoError::BadCiphertext));
            }
            let key_slot_stream_route = stream_key_slot_route(header.key_id, publish.stream_route)?;
            let signed_frame_sha256 = sha256(&encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Publish(publish.clone()),
            }));
            let observation = SignedHigherRevisionObservationV1::new(
                self.audited.identity.machine_route,
                self.audited.device_route,
                self.audited.grant_serial,
                self.audited.trust_epoch,
                self.audited.directory_revision,
                KeyDirectoryRevision::new(header.key_directory_revision),
                header.key_id,
                key_slot_stream_route,
                publish.stream_route,
                publish.generation,
                publish.stream_seq,
                u64::from_be_bytes(
                    header.nonce[4..]
                        .try_into()
                        .map_err(|_| PairedPromotionError::InvalidState)?,
                ),
                signed_frame_sha256,
                sha256(&header.ciphertext),
            )
            .map_err(|_| PairedPromotionError::InvalidState)?;
            return Ok(VerifiedStreamPublish::Higher(VerifiedHigherStreamPublish {
                observation,
            }));
        }
        if header.key_directory_revision == expected_revision
            && header.key_id.purpose == binding.key_id.purpose
            && header.key_epoch > stream_key.epoch
        {
            return Err(PairedPromotionError::Crypto(CryptoError::E2ee(
                agentdeck_protocol::e2ee::E2eeError::KeyEpochMissing,
            )));
        }
        if header.key_id != binding.key_id
            || header.key_id != stream_key.key_id
            || header.key_epoch != stream_key.epoch
            || header.key_directory_revision != expected_revision
            || header.nonce[..4] != nonce_prefix
        {
            return Err(PairedPromotionError::Crypto(CryptoError::BadCiphertext));
        }
        let counter = u64::from_be_bytes(
            header.nonce[4..]
                .try_into()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        );
        let ciphertext_sha256 = sha256(&header.ciphertext);
        Ok(VerifiedStreamPublish::Current(
            VerifiedCurrentStreamPublish {
                verified,
                context,
                brand: stream_publish_brand(self.audited.identity.machine_route, binding)?,
                stream_seq: publish.stream_seq,
                counter,
                ciphertext_sha256,
            },
        ))
    }

    /// 只消费本 capability 铸造的 verified stream token；调用方必须先把其 replay tuple
    /// durable admission。再次对照当前 key slot 与完整 brand，避免验证和 open 之间发生
    /// binding/key replacement 后继续使用旧 capability。
    pub(crate) fn open_verified_stream_publish(
        &self,
        candidate: VerifiedCurrentStreamPublish,
    ) -> Result<SealedPayloadV1, PairedPromotionError> {
        let expected_slot =
            stream_key_slot_route(candidate.brand.key_id, candidate.brand.stream_route)?;
        let mut matching =
            self.audited
                .opened_directory_keys
                .iter()
                .filter_map(|entry| match &entry.material {
                    OpenedPairedKeyMaterial::StreamRx { key, .. }
                        if entry.key_id == candidate.brand.key_id
                            && entry.stream_route == expected_slot =>
                    {
                        Some(key)
                    }
                    OpenedPairedKeyMaterial::CommandTx(_)
                    | OpenedPairedKeyMaterial::ReplyTx { .. }
                    | OpenedPairedKeyMaterial::StreamRx { .. } => None,
                });
        let stream_key = matching.next().ok_or(PairedPromotionError::InvalidState)?;
        if matching.next().is_some() {
            return Err(PairedPromotionError::InvalidState);
        }
        let expected_brand = StreamPublishBrand {
            machine_route: self.audited.identity.machine_route,
            stream_route: candidate.brand.stream_route,
            stream_generation: candidate.brand.stream_generation,
            key_id: stream_key.key_id,
            directory_revision: self.audited.directory_revision.value(),
            frame_kind: stream_publish_frame_kind(stream_key.key_id)?,
        };
        if candidate.brand != expected_brand
            || candidate.context.machine_route != Some(expected_brand.machine_route)
            || candidate.context.stream_route != Some(expected_brand.stream_route)
            || candidate.context.stream_generation != Some(expected_brand.stream_generation)
            || candidate.context.stream_seq != Some(candidate.stream_seq)
            || candidate.context.message_key_epoch != stream_key.epoch
        {
            return Err(PairedPromotionError::Conflict);
        }
        let installed = self
            .audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .filter(|state| {
                stream_publish_brand(self.audited.identity.machine_route, state.binding())
                    .is_ok_and(|brand| brand == candidate.brand)
            })
            .count();
        if installed != 1 {
            return Err(PairedPromotionError::Conflict);
        }
        open_sealed_payload(stream_key, &candidate.context, candidate.verified)
            .map_err(PairedPromotionError::Crypto)
    }

    /// 在 replay state 之前完成 outer-correlated reply 的 canonical/header/AAD/signature 验证。
    pub(crate) fn verify_directed_reply(
        &self,
        request_route: RequestRouteId,
        sealed_blob: &[u8],
    ) -> Result<VerifiedDirectedReply, PairedPromotionError> {
        let reply = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::ReplyTx { key, nonce_prefix } => {
                    Some((key, *nonce_prefix))
                }
                OpenedPairedKeyMaterial::CommandTx(_)
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        let signed = SignedSealedBlobV1::from_wire_bytes(sealed_blob)
            .map_err(|error| PairedPromotionError::Crypto(error.into()))?;
        let expected_revision = self.audited.directory_revision.value();
        if signed.inner.key_id != reply.0.key_id
            || signed.inner.key_epoch != reply.0.epoch
            || signed.inner.key_directory_revision != expected_revision
            || signed.inner.nonce[..4] != reply.1
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let context = OuterContextV1::directed_reply(
            self.audited.identity.machine_route,
            self.audited.device_route,
            request_route,
            reply.0.epoch,
        );
        let counter = u64::from_be_bytes(
            signed.inner.nonce[4..]
                .try_into()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        );
        let signed_blob_hash = sha256(sealed_blob);
        let verified = verify_sealed(signed, &self.audited.machine_data_verifying_key, &context)
            .map_err(PairedPromotionError::Crypto)?;
        Ok(VerifiedDirectedReply {
            verified,
            context,
            brand: DirectedReplyBrand {
                machine_route: self.audited.identity.machine_route,
                device_route: self.audited.device_route,
                key_id: reply.0.key_id,
                key_epoch: reply.0.epoch,
                directory_revision: expected_revision,
            },
            counter,
            signed_blob_hash,
        })
    }

    /// 只接受上一步产生的 verified candidate；runtime 必须先 durable admit replay tuple。
    pub(crate) fn open_verified_directed_reply(
        &self,
        candidate: VerifiedDirectedReply,
    ) -> Result<SealedPayloadV1, PairedPromotionError> {
        let reply_key = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::ReplyTx { key, .. } => Some(key),
                OpenedPairedKeyMaterial::CommandTx(_)
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        let expected_context = OuterContextV1::directed_reply(
            self.audited.identity.machine_route,
            self.audited.device_route,
            candidate
                .context
                .request_route
                .ok_or(PairedPromotionError::InvalidState)?,
            reply_key.epoch,
        );
        let expected_brand = DirectedReplyBrand {
            machine_route: self.audited.identity.machine_route,
            device_route: self.audited.device_route,
            key_id: reply_key.key_id,
            key_epoch: reply_key.epoch,
            directory_revision: self.audited.directory_revision.value(),
        };
        validate_directed_reply_brand(candidate.brand, expected_brand)?;
        if candidate.context != expected_context {
            return Err(PairedPromotionError::Conflict);
        }
        open_sealed_payload(reply_key, &candidate.context, candidate.verified)
            .map_err(PairedPromotionError::Crypto)
    }

    /// 仅供 automatic crash harness 读回非生产 state-mutation 探针。
    #[doc(hidden)]
    pub fn automatic_runtime_state_probe(
        &self,
    ) -> Result<Option<AutomaticRuntimeStateProbe>, PairedPromotionError> {
        self.audited.state.opaque_runtime_state().automatic_probe()
    }

    /// 仅供 automatic migration harness 对账 legacy V2 的 receipt/replay 字段；stream
    /// collection 不参与 probe，因此同一 probe 可在 V3 upgrade 后继续逐字验证。
    #[doc(hidden)]
    pub fn automatic_legacy_runtime_fields_probe(
        &self,
    ) -> Result<Option<AutomaticRuntimeStateProbe>, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.audited
            .state
            .opaque_runtime_state()
            .automatic_legacy_v2_probe()
    }

    /// 仅供 automatic crash harness 写入与 production runtime codec 不相交的探针。
    #[doc(hidden)]
    pub fn replace_automatic_runtime_state_probe<R: CryptoRng>(
        &mut self,
        probe: AutomaticRuntimeStateProbe,
        rng: &mut R,
    ) -> Result<AutomaticRuntimeStateProbe, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let replacement = OpaqueRuntimeState::from_automatic_probe(probe);
        self.replace_opaque_runtime_state(&replacement, rng)?
            .automatic_probe()?
            .ok_or(PairedPromotionError::InvalidState)
    }

    /// 仅供 automatic migration harness 构造“非空 receipt/replay + 空 stream collection”
    /// 的 legacy V2。production handle 在 entropy 与任一 durable mutation 之前拒绝；V3
    /// state 也禁止经此入口降级。
    #[doc(hidden)]
    pub fn replace_automatic_legacy_v2_runtime_state_probe<R: CryptoRng>(
        &mut self,
        probe: AutomaticRuntimeStateProbe,
        rng: &mut R,
    ) -> Result<AutomaticRuntimeStateProbe, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
            || matches!(
                self.audited.state,
                PairedCryptoState::V3(_) | PairedCryptoState::V4(_)
            )
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let replacement = OpaqueRuntimeState::from_automatic_legacy_v2_probe(probe);
        self.replace_opaque_runtime_state_as_legacy_v2(&replacement, rng)?
            .automatic_legacy_v2_probe()?
            .ok_or(PairedPromotionError::InvalidState)
    }

    /// 用 prepared sidecar → StatePending → active state → Stable 的固定前滚事务替换 runtime
    /// opaque fields。HWM 与 counter reservation 始终保持不变。
    pub(crate) fn replace_opaque_runtime_state<R: CryptoRng>(
        &mut self,
        replacement: &OpaqueRuntimeState,
        rng: &mut R,
    ) -> Result<OpaqueRuntimeState, PairedPromotionError> {
        self.replace_opaque_runtime_state_inner(replacement, false, rng)
    }

    fn replace_opaque_runtime_state_as_legacy_v2<R: CryptoRng>(
        &mut self,
        replacement: &OpaqueRuntimeState,
        rng: &mut R,
    ) -> Result<OpaqueRuntimeState, PairedPromotionError> {
        self.replace_opaque_runtime_state_inner(replacement, true, rng)
    }

    fn replace_opaque_runtime_state_inner<R: CryptoRng>(
        &mut self,
        replacement: &OpaqueRuntimeState,
        force_legacy_v2: bool,
        rng: &mut R,
    ) -> Result<OpaqueRuntimeState, PairedPromotionError> {
        replacement.validate()?;
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        let current_runtime = self.audited.state.opaque_runtime_state();
        if &current_runtime == replacement {
            return Ok(current_runtime);
        }
        let next_state = if force_legacy_v2 {
            self.audited.state.with_legacy_v2_opaque_runtime_state(
                self.audited.marker.state_plaintext_hash,
                self.audited.marker.counter_guard_hash,
                replacement,
            )?
        } else {
            self.audited.state.with_opaque_runtime_state(
                self.audited.marker.state_plaintext_hash,
                self.audited.marker.counter_guard_hash,
                replacement,
            )?
        };
        let next_state_bytes = next_state.encode()?;
        self.commit_prepared_state_transition(next_state, next_state_bytes, rng)?;
        Ok(self.audited.state.opaque_runtime_state())
    }

    /// 以 prepared sidecar 认证 exact next，再依次提交 StatePending、active、StateStable
    /// 并清理 sidecar。调用方必须先 refresh + recover，并在本函数前完成 CAS/幂等判断。
    fn commit_prepared_state_transition<R: CryptoRng>(
        &mut self,
        next_state: PairedCryptoState,
        next_state_bytes: Vec<u8>,
        rng: &mut R,
    ) -> Result<(), PairedPromotionError> {
        let (reserved_high_water, current_state_hash, binding, initial_guard_commitment) =
            match self.audited.counter_guard {
                CounterGuardState::V1(guard) => (
                    guard.reserved_high_water,
                    sha256(self.audited.state_snapshot.expose_secret()),
                    guard.binding,
                    self.audited.marker.counter_guard_hash,
                ),
                CounterGuardState::V2(CounterGuardV2 {
                    initial_guard_commitment,
                    directory_revision: _,
                    binding,
                    phase:
                        CounterGuardPhaseV2::Stable {
                            reserved_high_water,
                            current_state_hash,
                        },
                }) => (
                    reserved_high_water,
                    current_state_hash,
                    binding,
                    initial_guard_commitment,
                ),
                CounterGuardState::V2(CounterGuardV2 {
                    initial_guard_commitment,
                    directory_revision: _,
                    binding,
                    phase:
                        CounterGuardPhaseV2::StateStable {
                            reserved_high_water,
                            current_state_hash,
                            ..
                        },
                }) => (
                    reserved_high_water,
                    current_state_hash,
                    binding,
                    initial_guard_commitment,
                ),
                CounterGuardState::V2(CounterGuardV2 {
                    phase:
                        CounterGuardPhaseV2::Pending { .. } | CounterGuardPhaseV2::StatePending { .. },
                    ..
                }) => return Err(PairedPromotionError::InvalidState),
            };
        if current_state_hash != sha256(self.audited.state_snapshot.expose_secret()) {
            return Err(PairedPromotionError::Conflict);
        }

        let next_state_hash = sha256(&next_state_bytes);
        let next_snapshot = CryptoStateSnapshot::new(next_state_bytes);
        let mut mutation_id = [0_u8; 16];
        rng.try_fill_bytes(&mut mutation_id)
            .map_err(|_| PairedPromotionError::EntropyUnavailable)?;
        if all_zero(&mutation_id) {
            return Err(PairedPromotionError::EntropyUnavailable);
        }
        let previous_guard_hash = sha256(self.audited.counter_guard_bytes.expose_secret());

        let prepared = self
            .audited
            .state_store
            .prepare_stage(
                &self.audited.state_snapshot,
                previous_guard_hash,
                mutation_id,
                &next_snapshot,
            )
            .map_err(PairedPromotionError::CryptoState)?;
        self.observe_mutation(PairedMutationStage::StateStageDurable);
        let pending = CounterGuardV2::state_pending(
            initial_guard_commitment,
            self.audited.directory_revision,
            binding,
            reserved_high_water,
            prepared.mutation_id(),
            prepared.previous_guard_hash(),
            prepared.previous_state_hash(),
            prepared.next_state_hash(),
            prepared.sealed_commitment(),
        )?;
        self.audited.prepared_stage = Some(prepared);
        self.replace_counter_guard(CounterGuardState::V2(pending))?;
        self.observe_mutation(PairedMutationStage::StateGuardPendingDurable);

        self.audited
            .state_store
            .compare_and_replace(&self.audited.state_snapshot, &next_snapshot)
            .map_err(PairedPromotionError::CryptoState)?;
        self.observe_mutation(PairedMutationStage::StateActiveDurable);
        self.audited.state_snapshot = next_snapshot;
        self.audited.state = next_state;

        let stable = CounterGuardV2::state_stable(
            initial_guard_commitment,
            self.audited.directory_revision,
            binding,
            reserved_high_water,
            next_state_hash,
            mutation_id,
            previous_guard_hash,
            self.audited
                .prepared_stage
                .as_ref()
                .ok_or(PairedPromotionError::Conflict)?
                .sealed_commitment(),
        )?;
        self.replace_counter_guard(CounterGuardState::V2(stable))?;
        self.observe_mutation(PairedMutationStage::StateGuardStableDurable);
        self.clear_authenticated_prepared_stage()
    }

    /// 先提升 Keychain guard，再替换 sealed state，最后 finalize guard。
    /// 重启永不复用先前进程可能消费过的 reservation remainder。
    pub fn reserve_command_counter_block<R: CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<CommandCounterReservation, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;

        let (previous_high_water, current_state_hash, binding, initial_guard_commitment) =
            match self.audited.counter_guard {
                CounterGuardState::V1(guard) => (
                    guard.reserved_high_water,
                    sha256(self.audited.state_snapshot.expose_secret()),
                    guard.binding,
                    self.audited.marker.counter_guard_hash,
                ),
                CounterGuardState::V2(CounterGuardV2 {
                    initial_guard_commitment,
                    directory_revision: _,
                    binding,
                    phase:
                        CounterGuardPhaseV2::Stable {
                            reserved_high_water,
                            current_state_hash,
                        },
                }) => (
                    reserved_high_water,
                    current_state_hash,
                    binding,
                    initial_guard_commitment,
                ),
                CounterGuardState::V2(CounterGuardV2 {
                    initial_guard_commitment,
                    directory_revision: _,
                    binding,
                    phase:
                        CounterGuardPhaseV2::StateStable {
                            reserved_high_water,
                            current_state_hash,
                            ..
                        },
                }) => (
                    reserved_high_water,
                    current_state_hash,
                    binding,
                    initial_guard_commitment,
                ),
                CounterGuardState::V2(CounterGuardV2 {
                    phase:
                        CounterGuardPhaseV2::Pending { .. } | CounterGuardPhaseV2::StatePending { .. },
                    ..
                }) => return Err(PairedPromotionError::InvalidState),
            };
        if current_state_hash != sha256(self.audited.state_snapshot.expose_secret()) {
            return Err(PairedPromotionError::Conflict);
        }
        let reservation = prepare_command_counter_reservation(previous_high_water, rng)?;
        let end_exclusive = reservation.end_exclusive;
        let reservation_id = reservation.reservation_id;

        let next_state = self.audited.state.with_counter_reservation(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            &reservation,
        )?;
        let next_state_bytes = next_state.encode()?;
        let next_state_hash = sha256(&next_state_bytes);
        let pending = CounterGuardV2::pending(
            initial_guard_commitment,
            self.audited.directory_revision,
            binding,
            previous_high_water,
            end_exclusive,
            reservation_id,
            current_state_hash,
            next_state_hash,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(pending))?;
        self.observe_mutation(PairedMutationStage::GuardPendingDurable);

        let next_snapshot = CryptoStateSnapshot::new(next_state_bytes);
        self.audited
            .state_store
            .compare_and_replace(&self.audited.state_snapshot, &next_snapshot)
            .map_err(PairedPromotionError::CryptoState)?;
        // observer 位于 durable store 返回与内存 cache 更新之间，覆盖 committed-but-stale handle。
        self.observe_mutation(PairedMutationStage::StateDurable);
        self.audited.state_snapshot = next_snapshot;
        self.audited.state = next_state;

        let stable = CounterGuardV2::stable(
            initial_guard_commitment,
            self.audited.directory_revision,
            binding,
            end_exclusive,
            next_state_hash,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(stable))?;
        self.observe_mutation(PairedMutationStage::GuardStableDurable);
        Ok(reservation)
    }

    fn recover_pending_guard(&mut self) -> Result<(), PairedPromotionError> {
        match self.audited.counter_guard {
            CounterGuardState::V1(_) => self.clear_authenticated_prepared_stage(),
            CounterGuardState::V2(guard) => match guard.phase {
                CounterGuardPhaseV2::Stable { .. } | CounterGuardPhaseV2::StateStable { .. } => {
                    self.clear_authenticated_prepared_stage()
                }
                CounterGuardPhaseV2::Pending { .. } => self.recover_counter_pending(guard),
                CounterGuardPhaseV2::StatePending { .. } => self.recover_state_pending(guard),
            },
        }
    }

    fn recover_counter_pending(
        &mut self,
        guard: CounterGuardV2,
    ) -> Result<(), PairedPromotionError> {
        let CounterGuardPhaseV2::Pending {
            previous_high_water,
            next_high_water,
            reservation_id,
            previous_state_hash,
            next_state_hash,
        } = guard.phase
        else {
            return Err(PairedPromotionError::InvalidState);
        };
        let mut current_hash = sha256(self.audited.state_snapshot.expose_secret());
        let expected = CommandCounterReservation {
            reservation_id,
            start: previous_high_water,
            end_exclusive: next_high_water,
        };
        expected.validate()?;
        if current_hash == next_state_hash {
            if self.audited.state.counter_reservation() != Some(&expected) {
                return Err(PairedPromotionError::Conflict);
            }
        } else if current_hash == previous_state_hash {
            // guard-first 已经让整块不可复用。用 pending 中冻结的同一 reservation 重建
            // canonical next state，写成 sealed counter fence，但绝不把该块返回给调用方。
            let (skipped_state, skipped_snapshot) = rebuild_frozen_counter_state(
                &self.audited.marker,
                &self.audited.state,
                expected,
                next_state_hash,
            )?;
            self.audited
                .state_store
                .compare_and_replace(&self.audited.state_snapshot, &skipped_snapshot)
                .map_err(PairedPromotionError::CryptoState)?;
            // recovery 自己也是 state CAS → guard finalize 的事务；在 cache 更新前保留
            // 独立 crash seam，证明 committed-but-stale reopen 只走 pending+next。
            self.observe_mutation(PairedMutationStage::RecoveryStateDurable);
            self.audited.state_snapshot = skipped_snapshot;
            self.audited.state = skipped_state;
            current_hash = next_state_hash;
        } else {
            return Err(PairedPromotionError::Conflict);
        }

        // 无论 recovery 从 previous 还是 next 进入，重启都不暴露该 reservation；它只作为
        // exact sealed fence 与 Stable HWM 绑定，下一次调用从下一整块继续。
        let stable = CounterGuardV2::stable(
            guard.initial_guard_commitment,
            guard.directory_revision,
            guard.binding,
            next_high_water,
            current_hash,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(stable))?;
        Ok(())
    }

    fn recover_state_pending(&mut self, guard: CounterGuardV2) -> Result<(), PairedPromotionError> {
        let CounterGuardPhaseV2::StatePending {
            reserved_high_water,
            mutation_id,
            previous_guard_hash,
            previous_state_hash,
            next_state_hash,
            stage_commitment,
        } = guard.phase
        else {
            return Err(PairedPromotionError::InvalidState);
        };
        let prepared = self
            .audited
            .prepared_stage
            .take()
            .ok_or(PairedPromotionError::Conflict)?;
        if prepared.mutation_id() != mutation_id
            || prepared.previous_guard_hash() != previous_guard_hash
            || prepared.previous_state_hash() != previous_state_hash
            || prepared.next_state_hash() != next_state_hash
            || prepared.sealed_commitment() != stage_commitment
        {
            return Err(PairedPromotionError::Conflict);
        }
        let current_hash = sha256(self.audited.state_snapshot.expose_secret());
        if current_hash == previous_state_hash {
            let next_snapshot =
                CryptoStateSnapshot::new(prepared.snapshot().expose_secret().to_vec());
            let next_state = PairedCryptoState::decode(next_snapshot.expose_secret())?;
            self.audited
                .state_store
                .compare_and_replace(&self.audited.state_snapshot, &next_snapshot)
                .map_err(PairedPromotionError::CryptoState)?;
            self.observe_mutation(PairedMutationStage::StateRecoveryActiveDurable);
            self.audited.state_snapshot = next_snapshot;
            self.audited.state = next_state;
        } else if current_hash != next_state_hash
            || self.audited.state_snapshot.expose_secret() != prepared.snapshot().expose_secret()
        {
            return Err(PairedPromotionError::Conflict);
        }

        let stable = CounterGuardV2::state_stable(
            guard.initial_guard_commitment,
            guard.directory_revision,
            guard.binding,
            reserved_high_water,
            next_state_hash,
            mutation_id,
            previous_guard_hash,
            stage_commitment,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(stable))?;
        self.observe_mutation(PairedMutationStage::StateGuardStableDurable);
        self.audited.prepared_stage = Some(prepared);
        self.clear_authenticated_prepared_stage()
    }

    fn clear_authenticated_prepared_stage(&mut self) -> Result<(), PairedPromotionError> {
        let Some(prepared) = self.audited.prepared_stage.take() else {
            return Ok(());
        };
        self.audited
            .state_store
            .clear_prepared_stage_exact(&prepared)
            .map_err(PairedPromotionError::CryptoState)?;
        self.observe_mutation(PairedMutationStage::StateStageCleared);
        Ok(())
    }

    /// mutation error 之后不得信任内存 expected；每次 reserve 都从两个 durable backend
    /// 重新读回，并只接受 marker initial commitments 下的 coherent previous/next/stable。
    fn refresh_mutable_state(&mut self) -> Result<(), PairedPromotionError> {
        let counter_guard_bytes = self
            .store
            .load(&self.audited.counter_account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let counter_guard = CounterGuardState::decode(counter_guard_bytes.expose_secret())?;
        let state_snapshot = self
            .audited
            .state_store
            .load()
            .map_err(PairedPromotionError::CryptoState)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let state = PairedCryptoState::decode(state_snapshot.expose_secret())?;
        let prepared_stage = self
            .audited
            .state_store
            .load_prepared_stage()
            .map_err(PairedPromotionError::CryptoState)?;
        self.audited.marker.validate_state(
            self.audited.identity,
            &state,
            state_snapshot.expose_secret(),
        )?;
        validate_typed_stream_state_and_stage(
            &state,
            prepared_stage.as_ref(),
            StreamBindingAuditContext {
                identity: self.audited.identity,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                trust_epoch: self.audited.trust_epoch,
                directory_revision: self.audited.directory_revision,
            },
            &self.audited.authorization,
            &self.audited.opened_directory_keys,
        )?;
        validate_counter_guard_state(
            &self.audited.marker,
            self.audited.identity,
            &counter_guard,
            counter_guard_bytes.expose_secret(),
            &state,
            state_snapshot.expose_secret(),
            prepared_stage.as_ref(),
            self.audited.device_command_binding,
        )?;
        self.audited.counter_guard_bytes = counter_guard_bytes;
        self.audited.counter_guard = counter_guard;
        self.audited.state_snapshot = state_snapshot;
        self.audited.state = state;
        self.audited.prepared_stage = prepared_stage;
        Ok(())
    }

    fn replace_counter_guard(
        &mut self,
        replacement: CounterGuardState,
    ) -> Result<(), PairedPromotionError> {
        let replacement_bytes = replacement.encode();
        self.store
            .compare_and_replace_exact(
                &self.audited.counter_account,
                &self.audited.counter_guard_bytes,
                &RemoteSecret::new(replacement_bytes.clone()),
            )
            .map_err(PairedPromotionError::Persistence)?;
        self.audited.counter_guard_bytes = RemoteSecret::new(replacement_bytes);
        self.audited.counter_guard = replacement;
        Ok(())
    }

    fn observe_mutation(&self, stage: PairedMutationStage) {
        if let Some(observer) = &self.mutation_observer {
            observer.after_stage(stage);
        }
    }
}

/// 当前 installation 的 marker-backed paired machine 只读恢复入口。
pub struct PairedMachineStore<'a> {
    store: &'a dyn RemoteKeyStore,
    installation_id: Uuid,
    state_root: PathBuf,
    mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
}

impl fmt::Debug for PairedMachineStore<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedMachineStore")
            .field("identity", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a> PairedMachineStore<'a> {
    #[must_use]
    pub fn new(store: &'a dyn RemoteKeyStore, installation_id: Uuid, state_root: &Path) -> Self {
        Self::new_inner(
            store,
            installation_id,
            state_root,
            None,
            RuntimeStateMutationAuthority::Production,
        )
    }

    /// Automatic harness constructor。仅此注入入口 mint runtime-state probe write capability；
    /// production `new` 构造的 opened handle 永远拒绝该探针，且 CLI/env/config 不可达。
    #[doc(hidden)]
    #[must_use]
    pub fn new_with_mutation_observer(
        store: &'a dyn RemoteKeyStore,
        installation_id: Uuid,
        state_root: &Path,
        observer: Arc<dyn PairedMutationObserver>,
    ) -> Self {
        Self::new_inner(
            store,
            installation_id,
            state_root,
            Some(observer),
            RuntimeStateMutationAuthority::AutomaticHarness,
        )
    }

    fn new_inner(
        store: &'a dyn RemoteKeyStore,
        installation_id: Uuid,
        state_root: &Path,
        mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
        runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    ) -> Self {
        Self {
            store,
            installation_id,
            state_root: state_root.to_path_buf(),
            mutation_observer,
            runtime_state_mutation_authority,
        }
    }

    /// 只枚举当前 installation 的 commit marker，并逐项完成与 `open_exact` 相同的全审计。
    /// 任一 marker 损坏都会让整个 list fail-close，不会静默省略。
    pub fn list(&self) -> Result<Vec<PairedMachineSummary>, PairedPromotionError> {
        let markers = self
            .store
            .list_paired_commit_markers(self.installation_id)
            .map_err(PairedPromotionError::Persistence)?;
        let mut machines = Vec::with_capacity(markers.len());
        for parsed in markers {
            let identity = self.validate_marker_account(&parsed)?;
            let marker_secret = self.load_required(parsed.account())?;
            match PairedMarkerValue::decode(marker_secret.expose_secret())? {
                PairedMarkerValue::Active(marker) => {
                    let audited = self.audit_active_marker(&parsed, *marker)?;
                    machines.push(audited.summary());
                }
                PairedMarkerValue::Cleanup(journal) => {
                    // 合法 ADPC 已经永久关闭可见性；list 只验证 journal 自身并隐藏，
                    // 不恢复、不删除，也不把剩余 credential 暴露成 active machine。
                    journal.validate(identity)?;
                    let accounts = PairedAccounts::new(
                        self.installation_id,
                        identity.machine_root_fingerprint,
                        identity.machine_route,
                    );
                    audit_revocation_cleanup(
                        self.store,
                        &self.state_root,
                        identity,
                        &accounts,
                        &journal,
                    )?;
                }
            }
        }
        Ok(machines)
    }

    /// 在取得 exact machine lease 后，从 marker 开始只读恢复；缺失 marker 不可见且不可修复。
    pub fn open_exact(
        &self,
        identity: PairedMachineIdentity,
    ) -> Result<OpenedPairedMachine<'a>, PairedPromotionError> {
        let account = RemoteKeyAccount::paired(
            self.installation_id,
            identity.machine_root_fingerprint,
            identity.machine_route,
            PairedRemoteKeyPurpose::CommitMarker,
        );
        let parsed = RemoteKeyAccount::parse_paired(account.as_str())
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let lease = RemoteDeviceLease::acquire_in(
            &self.state_root,
            RemoteDeviceLockKey::new(
                self.installation_id,
                identity.machine_root_fingerprint,
                identity.machine_route,
            ),
        )
        .map_err(PairedPromotionError::DeviceLock)?;
        let marker_secret = self.load_required(parsed.account())?;
        let marker = match PairedMarkerValue::decode(marker_secret.expose_secret())? {
            PairedMarkerValue::Active(marker) => *marker,
            PairedMarkerValue::Cleanup(journal) => {
                // cleanup pending 时只读取并验证唯一 marker，绝不再读取残留 credential。
                journal.validate(identity)?;
                return Err(PairedPromotionError::RevokedCleanupPending);
            }
        };
        let audited = self.audit_active_marker(&parsed, marker)?;
        let mut opened = audited.into_opened(
            self.store,
            self.mutation_observer.clone(),
            self.runtime_state_mutation_authority,
            lease,
        );
        opened.recover_pending_guard()?;
        Ok(opened)
    }

    /// 恢复当前 installation 中所有 durable ADPC cleanup journal。
    ///
    /// 第一遍先对全部 ADPM/ADPC 做零写全审计；任一 active machine 或 cleanup prefix
    /// 损坏都会阻止所有删除。只有全局审计通过后，才逐 machine 取得 lease、逐字重读
    /// journal，并在每个删除边界前重新执行完整 preflight。
    pub fn recover_revocation_cleanups(&self) -> Result<(), PairedPromotionError> {
        let markers = self
            .store
            .list_paired_commit_markers(self.installation_id)
            .map_err(PairedPromotionError::Persistence)?;
        let mut cleanups = Vec::new();

        for parsed in markers {
            let identity = self.validate_marker_account(&parsed)?;
            let marker_secret = self.load_required(parsed.account())?;
            match PairedMarkerValue::decode(marker_secret.expose_secret())? {
                PairedMarkerValue::Active(marker) => {
                    // recovery 是 installation-wide fail-close：不能先清掉 A，再忽略损坏的 B。
                    drop(self.audit_active_marker(&parsed, *marker)?);
                }
                PairedMarkerValue::Cleanup(journal) => {
                    journal.validate(identity)?;
                    let accounts = PairedAccounts::new(
                        self.installation_id,
                        identity.machine_root_fingerprint,
                        identity.machine_route,
                    );
                    audit_revocation_cleanup(
                        self.store,
                        &self.state_root,
                        identity,
                        &accounts,
                        &journal,
                    )?;
                    cleanups.push((identity, marker_secret.expose_secret().to_vec()));
                }
            }
        }

        for (identity, expected_journal_bytes) in cleanups {
            let _lease = RemoteDeviceLease::acquire_in(
                &self.state_root,
                RemoteDeviceLockKey::new(
                    self.installation_id,
                    identity.machine_root_fingerprint,
                    identity.machine_route,
                ),
            )
            .map_err(PairedPromotionError::DeviceLock)?;
            let accounts = PairedAccounts::new(
                self.installation_id,
                identity.machine_root_fingerprint,
                identity.machine_route,
            );
            let durable = self.load_required(&accounts.marker)?;
            if durable.expose_secret() != expected_journal_bytes {
                return Err(PairedPromotionError::Conflict);
            }
            let PairedMarkerValue::Cleanup(current) =
                PairedMarkerValue::decode(durable.expose_secret())?
            else {
                return Err(PairedPromotionError::Conflict);
            };
            current.validate(identity)?;
            execute_revocation_cleanup(
                self.store,
                &self.state_root,
                identity,
                &accounts,
                &current,
                durable.expose_secret(),
                self.mutation_observer.as_deref(),
            )?;
        }
        Ok(())
    }

    fn validate_marker_account(
        &self,
        parsed: &ParsedPairedRemoteKeyAccount,
    ) -> Result<PairedMachineIdentity, PairedPromotionError> {
        if parsed.installation_id() != self.installation_id
            || parsed.purpose() != PairedRemoteKeyPurpose::CommitMarker
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(PairedMachineIdentity::new(
            parsed.machine_root_fingerprint(),
            parsed.machine_route(),
        ))
    }

    fn audit_active_marker(
        &self,
        parsed: &ParsedPairedRemoteKeyAccount,
        marker: PairedCommitMarkerV1,
    ) -> Result<AuditedPairedMachine, PairedPromotionError> {
        let identity = self.validate_marker_account(parsed)?;
        marker.validate_account(self.installation_id, identity)?;
        let accounts = PairedAccounts::new(
            self.installation_id,
            identity.machine_root_fingerprint,
            identity.machine_route,
        );
        if &accounts.marker != parsed.account() {
            return Err(PairedPromotionError::Conflict);
        }

        // 固定只读顺序：marker → KEK → DeviceSign/HPKE → grant → guard → sealed state。
        let kek_secret = self.load_required(&accounts.kek)?;
        let kek_record = StorageKekRecordV1::decode(kek_secret.expose_secret())?;
        if kek_record.promotion_id != marker.promotion_id
            || marker.kek_record_hash != kek_record.commitment()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let device_sign_secret = self.load_required(&accounts.device_sign)?;
        let device_hpke_secret = self.load_required(&accounts.device_hpke)?;
        let grant_secret = self.load_required(&accounts.grant)?;

        let state_store = FileCryptoStateStore::new_in(
            &self.state_root,
            CryptoStateIdentity::new(
                self.installation_id,
                identity.machine_root_fingerprint,
                identity.machine_route,
            ),
            kek_record.device_storage_kek(),
        )
        .map_err(PairedPromotionError::CryptoState)?;
        let (counter_secret, state_snapshot, prepared_stage) =
            self.load_coherent_mutable_pair(&accounts.counter_guard, &state_store)?;
        let counter_guard = CounterGuardState::decode(counter_secret.expose_secret())?;
        let state = PairedCryptoState::decode(state_snapshot.expose_secret())?;
        marker.validate_state(identity, &state, state_snapshot.expose_secret())?;
        let bootstrap = state.bootstrap();

        let audit = audit_durable_state(
            bootstrap,
            grant_secret.expose_secret(),
            &device_sign_secret,
            &device_hpke_secret,
        )?;
        validate_typed_stream_state_and_stage(
            &state,
            prepared_stage.as_ref(),
            StreamBindingAuditContext {
                identity,
                device_route: bootstrap.device_route,
                grant_serial: bootstrap.grant_serial,
                trust_epoch: bootstrap.trust_epoch,
                directory_revision: bootstrap.directory_revision,
            },
            &audit.authorization,
            &audit.opened_keys,
        )?;
        if marker.device_sign_pubkey != audit.device_signing_key.verifying_key().to_bytes()
            || marker.device_hpke_pubkey != hpke_public_bytes(&audit.device_hpke_private_key)?
        {
            return Err(PairedPromotionError::Conflict);
        }
        validate_counter_guard_state(
            &marker,
            identity,
            &counter_guard,
            counter_secret.expose_secret(),
            &state,
            state_snapshot.expose_secret(),
            prepared_stage.as_ref(),
            audit.device_command_binding,
        )?;

        Ok(AuditedPairedMachine {
            identity,
            machine_display_name: bootstrap.machine_display_name.clone(),
            wss_url: bootstrap.wss_url.clone(),
            device_route: bootstrap.device_route,
            grant_serial: bootstrap.grant_serial,
            trust_epoch: bootstrap.trust_epoch,
            directory_revision: bootstrap.directory_revision,
            relay_server_id: bootstrap.relay_server_id,
            current_spki_pin: bootstrap.current_spki_pin,
            next_spki_pin: bootstrap.next_spki_pin,
            _canonical_receipt_carrier: bootstrap.receipt_carrier.clone(),
            state_store,
            state_snapshot,
            state,
            prepared_stage,
            counter_account: accounts.counter_guard,
            counter_guard_bytes: counter_secret,
            counter_guard,
            device_command_binding: audit.device_command_binding,
            marker,
            grant: audit.grant,
            authorization: audit.authorization,
            device_signing_key: Arc::new(audit.device_signing_key),
            machine_data_verifying_key: audit.machine_data_verifying_key,
            _device_hpke_private_key: audit.device_hpke_private_key,
            opened_directory_keys: audit.opened_keys,
        })
    }

    fn load_required(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<RemoteSecret, PairedPromotionError> {
        self.store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)
    }

    /// `list()` 不取 device lease；用 bounded guard1→state→guard2 避免把合法 writer
    /// 的三阶段切换误判为 durable divergence。读取始终只读，耗尽重试后 fail-close。
    fn load_coherent_mutable_pair(
        &self,
        counter_account: &RemoteKeyAccount,
        state_store: &FileCryptoStateStore,
    ) -> Result<
        (
            RemoteSecret,
            CryptoStateSnapshot,
            Option<PreparedCryptoStateStage>,
        ),
        PairedPromotionError,
    > {
        let mut last_stage_error = None;
        for _ in 0..MAX_MUTABLE_AUDIT_ATTEMPTS {
            let before = self.load_required(counter_account)?;
            let state = state_store
                .load()
                .map_err(PairedPromotionError::CryptoState)?
                .ok_or(PairedPromotionError::Incomplete)?;
            let prepared_stage = state_store.load_prepared_stage();
            let after = self.load_required(counter_account)?;
            if before.expose_secret() == after.expose_secret() {
                match prepared_stage {
                    Ok(stage) => return Ok((after, state, stage)),
                    Err(error) => last_stage_error = Some(error),
                }
            }
        }
        last_stage_error.map_or_else(
            || Err(PairedPromotionError::Conflict),
            |error| Err(PairedPromotionError::CryptoState(error)),
        )
    }
}

pub struct PairedPromotionCoordinator<'a> {
    store: &'a dyn RemoteKeyStore,
    installation_id: Uuid,
    state_root: PathBuf,
}

impl fmt::Debug for PairedPromotionCoordinator<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedPromotionCoordinator")
            .field("identity", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a> PairedPromotionCoordinator<'a> {
    #[must_use]
    pub fn new(store: &'a dyn RemoteKeyStore, installation_id: Uuid, state_root: &Path) -> Self {
        Self {
            store,
            installation_id,
            state_root: state_root.to_path_buf(),
        }
    }

    /// 只接受 durable pending transaction 产出的不可伪造 verified capability。
    pub fn promote<R: CryptoRng>(
        &self,
        response: VerifiedPendingPairResponse,
        rng: &mut R,
    ) -> Result<PromotedPairedMachine, PairedPromotionError> {
        let material = response.into_promotion_material();
        let verified = material.verified;
        let info = verified.info();
        let root_fingerprint =
            MachineRootFingerprint::from_bytes(verified.machine_root_fingerprint());
        let accounts =
            PairedAccounts::new(self.installation_id, root_fingerprint, info.machine_route);
        let _lease = RemoteDeviceLease::acquire_in(
            &self.state_root,
            RemoteDeviceLockKey::new(self.installation_id, root_fingerprint, info.machine_route),
        )
        .map_err(PairedPromotionError::DeviceLock)?;

        let promotion_id = promotion_id(self.installation_id, &verified);
        if let Some(marker) = self
            .store
            .load(&accounts.marker)
            .map_err(PairedPromotionError::Persistence)?
        {
            return self.audit_committed(
                &accounts,
                &verified,
                &material.invite_public,
                promotion_id,
                marker.expose_secret(),
                true,
            );
        }

        let pending = self.load_pending_secrets(verified.info().invite_hash)?;
        let signing_key = signing_key(&pending.device_sign)?;
        let hpke_private = hpke_private_key(&pending.device_hpke)?;
        validate_pending_keys(&verified, &signing_key, &hpke_private)?;

        // StorageKEK 是 sealed file 的 prerequisite；marker 前只属于 provisional state。
        if self
            .store
            .load(&accounts.kek)
            .map_err(PairedPromotionError::Persistence)?
            .is_none()
        {
            self.reject_state_without_kek(root_fingerprint, info.machine_route)?;
        }
        let kek_record = self.load_or_create_kek(&accounts.kek, promotion_id, rng)?;
        let state_store = self.open_state_store(
            root_fingerprint,
            info.machine_route,
            kek_record.device_storage_kek(),
        )?;
        let state = match state_store
            .load()
            .map_err(PairedPromotionError::CryptoState)?
        {
            Some(snapshot) => PairedCryptoStateV1::decode(snapshot.expose_secret())?,
            None => {
                let state = build_initial_state(
                    self.installation_id,
                    &verified,
                    &material.invite_public,
                    promotion_id,
                    &signing_key,
                    rng,
                )?;
                let encoded = state.encode()?;
                state_store
                    .commit_initial(&CryptoStateSnapshot::new(encoded))
                    .map_err(PairedPromotionError::CryptoState)?;
                let durable = state_store
                    .load()
                    .map_err(PairedPromotionError::CryptoState)?
                    .ok_or(PairedPromotionError::Incomplete)?;
                PairedCryptoStateV1::decode(durable.expose_secret())?
            }
        };

        let grant_bytes = verified.relay_grant().canonical_bytes();
        let audit = audit_state(
            self.installation_id,
            &state,
            &verified,
            &material.invite_public,
            &grant_bytes,
            &pending.device_sign,
            &pending.device_hpke,
        )?;
        let counter_guard =
            CounterGuardV1::from_binding(state.directory_revision, audit.device_command_binding);
        let counter_bytes = counter_guard.encode();

        self.persist_exact(&accounts.device_sign, &pending.device_sign)?;
        self.persist_exact(&accounts.device_hpke, &pending.device_hpke)?;
        self.persist_exact(&accounts.grant, &RemoteSecret::new(grant_bytes.clone()))?;
        self.persist_exact(
            &accounts.counter_guard,
            &RemoteSecret::new(counter_bytes.clone()),
        )?;

        let state_bytes = state.encode()?;
        let marker = PairedCommitMarkerV1::new(
            self.installation_id,
            &state,
            promotion_id,
            sha256(&state_bytes),
            kek_record.commitment(),
            sha256(&counter_bytes),
            signing_key.verifying_key().to_bytes(),
            hpke_public_bytes(&hpke_private)?,
        );
        let marker_bytes = marker.encode();
        self.persist_exact(&accounts.marker, &RemoteSecret::new(marker_bytes.clone()))?;

        self.audit_committed(
            &accounts,
            &verified,
            &material.invite_public,
            promotion_id,
            &marker_bytes,
            false,
        )
    }

    fn load_pending_secrets(
        &self,
        invite_hash: [u8; 32],
    ) -> Result<PendingSecrets, PairedPromotionError> {
        let device_sign = self
            .store
            .load(&RemoteKeyAccount::pending(
                self.installation_id,
                invite_hash,
                PendingRemoteKeyPurpose::DeviceSignPrivateKey,
            ))
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let device_hpke = self
            .store
            .load(&RemoteKeyAccount::pending(
                self.installation_id,
                invite_hash,
                PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
            ))
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        Ok(PendingSecrets {
            device_sign,
            device_hpke,
        })
    }

    fn load_or_create_kek<R: CryptoRng>(
        &self,
        account: &RemoteKeyAccount,
        promotion_id: [u8; 32],
        rng: &mut R,
    ) -> Result<StorageKekRecordV1, PairedPromotionError> {
        if let Some(existing) = self
            .store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
        {
            let record = StorageKekRecordV1::decode(existing.expose_secret())?;
            return if record.promotion_id == promotion_id {
                Ok(record)
            } else {
                Err(PairedPromotionError::Conflict)
            };
        }

        let mut key = [0_u8; 32];
        rng.try_fill_bytes(&mut key)
            .map_err(|_| PairedPromotionError::EntropyUnavailable)?;
        if key.iter().all(|byte| *byte == 0) {
            key.zeroize();
            return Err(PairedPromotionError::EntropyUnavailable);
        }
        let candidate = StorageKekRecordV1 { promotion_id, key };
        let encoded = candidate.encode();
        match self
            .store
            .persist_immutable(account, &RemoteSecret::new(encoded))
        {
            Ok(_) => {}
            Err(RemoteKeyStoreError::ImmutableConflict { .. }) => {
                return Err(PairedPromotionError::Conflict);
            }
            Err(error) => return Err(PairedPromotionError::Persistence(error)),
        }
        let durable = self
            .store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let durable = StorageKekRecordV1::decode(durable.expose_secret())?;
        if durable.promotion_id != promotion_id {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(durable)
    }

    fn open_state_store(
        &self,
        root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
        kek: DeviceStorageKek,
    ) -> Result<FileCryptoStateStore, PairedPromotionError> {
        FileCryptoStateStore::new_in(
            &self.state_root,
            CryptoStateIdentity::new(self.installation_id, root_fingerprint, machine_route),
            kek,
        )
        .map_err(PairedPromotionError::CryptoState)
    }

    /// immutable state 已存在但 KEK 缺失时不可生成替代 KEK；否则会把离线损坏扩大成
    /// 一个看似可恢复、实际永远无法解密的 provisional account。
    fn reject_state_without_kek(
        &self,
        root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
    ) -> Result<(), PairedPromotionError> {
        let probe = self.open_state_store(
            root_fingerprint,
            machine_route,
            DeviceStorageKek::new([0; 32]),
        )?;
        match probe.load() {
            Ok(None) => Ok(()),
            Ok(Some(_)) | Err(CryptoStateError::AuthenticationFailed) => {
                Err(PairedPromotionError::Incomplete)
            }
            Err(error) => Err(PairedPromotionError::CryptoState(error)),
        }
    }

    fn persist_exact(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<(), PairedPromotionError> {
        match self.store.persist_immutable(account, value) {
            Ok(_) => {}
            Err(RemoteKeyStoreError::ImmutableConflict { .. }) => {
                return Err(PairedPromotionError::Conflict);
            }
            Err(error) => return Err(PairedPromotionError::Persistence(error)),
        }
        let durable = self
            .store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        if durable.expose_secret() != value.expose_secret() {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_committed(
        &self,
        accounts: &PairedAccounts,
        verified: &agentdeck_crypto::VerifiedPairResponseV1,
        invite: &PendingInvitePublicProjection,
        promotion_id: [u8; 32],
        marker_bytes: &[u8],
        already_committed: bool,
    ) -> Result<PromotedPairedMachine, PairedPromotionError> {
        let marker = PairedCommitMarkerV1::decode(marker_bytes)?;
        marker.validate_expected(self.installation_id, verified, promotion_id)?;

        let kek_secret = self.load_required(&accounts.kek)?;
        let kek_record = StorageKekRecordV1::decode(kek_secret.expose_secret())?;
        if kek_record.promotion_id != promotion_id
            || marker.kek_record_hash != kek_record.commitment()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let state_store = self.open_state_store(
            MachineRootFingerprint::from_bytes(verified.machine_root_fingerprint()),
            verified.info().machine_route,
            kek_record.device_storage_kek(),
        )?;
        let state_snapshot = state_store
            .load()
            .map_err(PairedPromotionError::CryptoState)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let state = PairedCryptoState::decode(state_snapshot.expose_secret())?;
        let identity = PairedMachineIdentity::new(
            MachineRootFingerprint::from_bytes(verified.machine_root_fingerprint()),
            verified.info().machine_route,
        );
        marker.validate_state(identity, &state, state_snapshot.expose_secret())?;
        let bootstrap = state.bootstrap();

        let device_sign = self.load_required(&accounts.device_sign)?;
        let device_hpke = self.load_required(&accounts.device_hpke)?;
        let grant = self.load_required(&accounts.grant)?;
        let counter = self.load_required(&accounts.counter_guard)?;
        let signing_key = signing_key(&device_sign)?;
        let hpke_private = hpke_private_key(&device_hpke)?;
        let audit = audit_state(
            self.installation_id,
            bootstrap,
            verified,
            invite,
            grant.expose_secret(),
            &device_sign,
            &device_hpke,
        )?;
        let counter_guard = CounterGuardState::decode(counter.expose_secret())?;
        let prepared_stage = state_store
            .load_prepared_stage()
            .map_err(PairedPromotionError::CryptoState)?;
        validate_typed_stream_state_and_stage(
            &state,
            prepared_stage.as_ref(),
            StreamBindingAuditContext {
                identity,
                device_route: bootstrap.device_route,
                grant_serial: bootstrap.grant_serial,
                trust_epoch: bootstrap.trust_epoch,
                directory_revision: bootstrap.directory_revision,
            },
            verified.device_authorization(),
            &audit.opened_keys,
        )?;
        validate_counter_guard_state(
            &marker,
            identity,
            &counter_guard,
            counter.expose_secret(),
            &state,
            state_snapshot.expose_secret(),
            prepared_stage.as_ref(),
            audit.device_command_binding,
        )?;
        if marker.device_sign_pubkey != signing_key.verifying_key().to_bytes()
            || marker.device_hpke_pubkey != hpke_public_bytes(&hpke_private)?
            || marker.receipt_carrier_hash != sha256(&bootstrap.receipt_carrier)
        {
            return Err(PairedPromotionError::Conflict);
        }

        Ok(PromotedPairedMachine {
            state_path: state_store.state_path().to_path_buf(),
            canonical_receipt_carrier: bootstrap.receipt_carrier.clone(),
            machine_route: bootstrap.machine_route,
            device_route: bootstrap.device_route,
            request_hash: bootstrap.request_hash,
            grant_hash: bootstrap.grant_hash,
            response_hash: bootstrap.response_hash,
            already_committed,
        })
    }

    fn load_required(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<RemoteSecret, PairedPromotionError> {
        self.store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)
    }
}

struct PendingSecrets {
    device_sign: RemoteSecret,
    device_hpke: RemoteSecret,
}

struct PairedAccounts {
    device_sign: RemoteKeyAccount,
    device_hpke: RemoteKeyAccount,
    grant: RemoteKeyAccount,
    kek: RemoteKeyAccount,
    counter_guard: RemoteKeyAccount,
    marker: RemoteKeyAccount,
}

impl PairedAccounts {
    fn new(
        installation_id: Uuid,
        root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
    ) -> Self {
        let account = |purpose| {
            RemoteKeyAccount::paired(installation_id, root_fingerprint, machine_route, purpose)
        };
        Self {
            device_sign: account(PairedRemoteKeyPurpose::DeviceSignPrivateKey),
            device_hpke: account(PairedRemoteKeyPurpose::DeviceHpkePrivateKey),
            grant: account(PairedRemoteKeyPurpose::DeviceGrant),
            kek: account(PairedRemoteKeyPurpose::DeviceStorageKek),
            counter_guard: account(PairedRemoteKeyPurpose::CounterGuard),
            marker: account(PairedRemoteKeyPurpose::CommitMarker),
        }
    }
}

struct RevocationCleanupPreflight {
    state_store: Option<FileCryptoStateStore>,
    state_present: bool,
    counter_guard_present: bool,
    grant_present: bool,
    device_hpke_present: bool,
    device_sign_present: bool,
    storage_kek_present: bool,
}

fn audit_revocation_cleanup(
    store: &dyn RemoteKeyStore,
    state_root: &Path,
    identity: PairedMachineIdentity,
    accounts: &PairedAccounts,
    journal: &PairedCleanupJournalV1,
) -> Result<RevocationCleanupPreflight, PairedPromotionError> {
    journal.validate(identity)?;
    let expected_journal = journal.encode()?;
    let durable_journal = store
        .load(&accounts.marker)
        .map_err(PairedPromotionError::Persistence)?
        .ok_or(PairedPromotionError::Incomplete)?;
    if durable_journal.expose_secret() != expected_journal {
        return Err(PairedPromotionError::Conflict);
    }

    let counter_guard =
        load_cleanup_item(store, &accounts.counter_guard, journal.counter_guard_hash)?;
    let grant = load_cleanup_item(store, &accounts.grant, journal.grant_hash)?;
    if grant
        .as_ref()
        .is_some_and(|value| value.expose_secret() != journal.grant_bytes)
    {
        return Err(PairedPromotionError::Conflict);
    }
    let device_hpke = load_cleanup_item(store, &accounts.device_hpke, journal.device_hpke_hash)?;
    let device_sign = load_cleanup_item(store, &accounts.device_sign, journal.device_sign_hash)?;
    let storage_kek = load_cleanup_item(store, &accounts.kek, journal.storage_kek_hash)?;

    let state_identity = CryptoStateIdentity::new(
        journal.installation_id,
        identity.machine_root_fingerprint,
        identity.machine_route,
    );
    let (state_store, state_present) = if let Some(secret) = storage_kek.as_ref() {
        let record = StorageKekRecordV1::decode(secret.expose_secret())?;
        if record.promotion_id != journal.active_marker.promotion_id
            || record.commitment() != journal.storage_kek_hash
        {
            return Err(PairedPromotionError::Conflict);
        }
        let state_store =
            FileCryptoStateStore::new_in(state_root, state_identity, record.device_storage_kek())
                .map_err(PairedPromotionError::CryptoState)?;
        let present = state_store
            .audit_revocation_cleanup_state(journal.state_plaintext_hash)
            .map_err(PairedPromotionError::CryptoState)?;
        (Some(state_store), present)
    } else {
        if !revocation_cleanup_entries_absent_in(state_root, state_identity)
            .map_err(PairedPromotionError::CryptoState)?
        {
            return Err(PairedPromotionError::Conflict);
        }
        (None, false)
    };

    let presence = [
        state_present,
        counter_guard.is_some(),
        grant.is_some(),
        device_hpke.is_some(),
        device_sign.is_some(),
        storage_kek.is_some(),
    ];
    let mut reached_remaining_suffix = false;
    for present in presence {
        if present {
            reached_remaining_suffix = true;
        } else if reached_remaining_suffix {
            // 只接受删除顺序形成的 absence prefix：false* true*。
            return Err(PairedPromotionError::Conflict);
        }
    }

    if state_present {
        let state_store_ref = state_store.as_ref().ok_or(PairedPromotionError::Conflict)?;
        let snapshot = state_store_ref
            .load()
            .map_err(PairedPromotionError::CryptoState)?
            .ok_or(PairedPromotionError::Incomplete)?;
        if sha256(snapshot.expose_secret()) != journal.state_plaintext_hash {
            return Err(PairedPromotionError::Conflict);
        }
        let state = PairedCryptoState::decode(snapshot.expose_secret())?;
        journal
            .active_marker
            .validate_state(identity, &state, snapshot.expose_secret())?;
        let device_sign = device_sign
            .as_ref()
            .ok_or(PairedPromotionError::Incomplete)?;
        let device_hpke = device_hpke
            .as_ref()
            .ok_or(PairedPromotionError::Incomplete)?;
        let grant = grant.as_ref().ok_or(PairedPromotionError::Incomplete)?;
        let durable = audit_durable_state(
            state.bootstrap(),
            grant.expose_secret(),
            device_sign,
            device_hpke,
        )?;
        let bootstrap = state.bootstrap();
        validate_typed_stream_state_and_stage(
            &state,
            None,
            StreamBindingAuditContext {
                identity,
                device_route: bootstrap.device_route,
                grant_serial: bootstrap.grant_serial,
                trust_epoch: bootstrap.trust_epoch,
                directory_revision: bootstrap.directory_revision,
            },
            &durable.authorization,
            &durable.opened_keys,
        )?;
        if durable.device_signing_key.verifying_key().to_bytes()
            != journal.active_marker.device_sign_pubkey
            || hpke_public_bytes(&durable.device_hpke_private_key)?
                != journal.active_marker.device_hpke_pubkey
            || durable.grant.root_key_id != journal.root_key_id
        {
            return Err(PairedPromotionError::Conflict);
        }
        let counter = counter_guard
            .as_ref()
            .ok_or(PairedPromotionError::Incomplete)?;
        let counter_state = CounterGuardState::decode(counter.expose_secret())?;
        validate_counter_guard_state(
            &journal.active_marker,
            identity,
            &counter_state,
            counter.expose_secret(),
            &state,
            snapshot.expose_secret(),
            None,
            durable.device_command_binding,
        )?;
    }

    Ok(RevocationCleanupPreflight {
        state_store,
        state_present,
        counter_guard_present: counter_guard.is_some(),
        grant_present: grant.is_some(),
        device_hpke_present: device_hpke.is_some(),
        device_sign_present: device_sign.is_some(),
        storage_kek_present: storage_kek.is_some(),
    })
}

fn load_cleanup_item(
    store: &dyn RemoteKeyStore,
    account: &RemoteKeyAccount,
    expected_hash: [u8; 32],
) -> Result<Option<RemoteSecret>, PairedPromotionError> {
    let value = store
        .load(account)
        .map_err(PairedPromotionError::Persistence)?;
    if value
        .as_ref()
        .is_some_and(|secret| sha256(secret.expose_secret()) != expected_hash)
    {
        return Err(PairedPromotionError::Conflict);
    }
    Ok(value)
}

fn delete_cleanup_item(
    store: &dyn RemoteKeyStore,
    account: &RemoteKeyAccount,
    expected_hash: [u8; 32],
) -> Result<(), PairedPromotionError> {
    let current = store
        .load(account)
        .map_err(PairedPromotionError::Persistence)?
        .ok_or(PairedPromotionError::Incomplete)?;
    if sha256(current.expose_secret()) != expected_hash {
        return Err(PairedPromotionError::Conflict);
    }
    store
        .delete_exact(account)
        .map_err(PairedPromotionError::Persistence)
}

fn observe_cleanup(observer: Option<&dyn PairedMutationObserver>, stage: PairedMutationStage) {
    if let Some(observer) = observer {
        observer.after_stage(stage);
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_revocation_cleanup(
    store: &dyn RemoteKeyStore,
    state_root: &Path,
    identity: PairedMachineIdentity,
    accounts: &PairedAccounts,
    journal: &PairedCleanupJournalV1,
    journal_bytes: &[u8],
    observer: Option<&dyn PairedMutationObserver>,
) -> Result<(), PairedPromotionError> {
    let mut preflight = audit_revocation_cleanup(store, state_root, identity, accounts, journal)?;
    if preflight.state_present {
        preflight
            .state_store
            .take()
            .ok_or(PairedPromotionError::Conflict)?
            .delete_revocation_cleanup_state(journal.state_plaintext_hash)
            .map_err(PairedPromotionError::CryptoState)?;
        observe_cleanup(observer, PairedMutationStage::CleanupStateDeleted);
    }

    preflight = audit_revocation_cleanup(store, state_root, identity, accounts, journal)?;
    if preflight.counter_guard_present {
        delete_cleanup_item(store, &accounts.counter_guard, journal.counter_guard_hash)?;
        observe_cleanup(observer, PairedMutationStage::CleanupCounterGuardDeleted);
    }

    preflight = audit_revocation_cleanup(store, state_root, identity, accounts, journal)?;
    if preflight.grant_present {
        delete_cleanup_item(store, &accounts.grant, journal.grant_hash)?;
        observe_cleanup(observer, PairedMutationStage::CleanupGrantDeleted);
    }

    preflight = audit_revocation_cleanup(store, state_root, identity, accounts, journal)?;
    if preflight.device_hpke_present {
        delete_cleanup_item(store, &accounts.device_hpke, journal.device_hpke_hash)?;
        observe_cleanup(observer, PairedMutationStage::CleanupDeviceHpkeDeleted);
    }

    preflight = audit_revocation_cleanup(store, state_root, identity, accounts, journal)?;
    if preflight.device_sign_present {
        delete_cleanup_item(store, &accounts.device_sign, journal.device_sign_hash)?;
        observe_cleanup(observer, PairedMutationStage::CleanupDeviceSignDeleted);
    }

    preflight = audit_revocation_cleanup(store, state_root, identity, accounts, journal)?;
    if preflight.storage_kek_present {
        delete_cleanup_item(store, &accounts.kek, journal.storage_kek_hash)?;
        observe_cleanup(observer, PairedMutationStage::CleanupStorageKekDeleted);
    }

    preflight = audit_revocation_cleanup(store, state_root, identity, accounts, journal)?;
    if preflight.state_present
        || preflight.counter_guard_present
        || preflight.grant_present
        || preflight.device_hpke_present
        || preflight.device_sign_present
        || preflight.storage_kek_present
    {
        return Err(PairedPromotionError::Conflict);
    }
    let current = store
        .load(&accounts.marker)
        .map_err(PairedPromotionError::Persistence)?
        .ok_or(PairedPromotionError::Incomplete)?;
    if current.expose_secret() != journal_bytes {
        return Err(PairedPromotionError::Conflict);
    }
    store
        .delete_exact(&accounts.marker)
        .map_err(PairedPromotionError::Persistence)?;
    observe_cleanup(observer, PairedMutationStage::CleanupJournalDeleted);
    Ok(())
}

fn signing_key(secret: &RemoteSecret) -> Result<SigningKey, PairedPromotionError> {
    let mut seed: [u8; 32] = secret
        .expose_secret()
        .try_into()
        .map_err(|_| PairedPromotionError::InvalidState)?;
    let key = SigningKey::from_seed(&seed);
    seed.zeroize();
    Ok(key)
}

fn hpke_private_key(secret: &RemoteSecret) -> Result<HpkePrivateKey, PairedPromotionError> {
    HpkePrivateKey::from_bytes(secret.expose_secret()).map_err(PairedPromotionError::Crypto)
}

fn hpke_public_bytes(private: &HpkePrivateKey) -> Result<[u8; 32], PairedPromotionError> {
    private
        .public_key()
        .to_bytes()
        .try_into()
        .map_err(|_| PairedPromotionError::InvalidState)
}

fn validate_pending_keys(
    verified: &agentdeck_crypto::VerifiedPairResponseV1,
    signing_key: &SigningKey,
    hpke_private: &HpkePrivateKey,
) -> Result<(), PairedPromotionError> {
    if verified.relay_grant().device_sign_pubkey.0 != signing_key.verifying_key().to_bytes()
        || verified.device_authorization().device_hpke_pubkey.0 != hpke_public_bytes(hpke_private)?
    {
        return Err(PairedPromotionError::Conflict);
    }
    Ok(())
}

fn promotion_id(
    installation_id: Uuid,
    verified: &agentdeck_crypto::VerifiedPairResponseV1,
) -> [u8; 32] {
    let info = verified.info();
    promotion_id_from_parts(
        installation_id,
        info.invite_hash,
        info.request_hash,
        verified.response_hash(),
        verified.machine_root_fingerprint(),
        info.machine_route,
    )
}

fn promotion_id_from_parts(
    installation_id: Uuid,
    invite_hash: [u8; 32],
    request_hash: [u8; 32],
    response_hash: [u8; 32],
    machine_root_fingerprint: [u8; 32],
    machine_route: MachineRouteId,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(PROMOTION_ID_DOMAIN.len() + 176);
    input.extend_from_slice(PROMOTION_ID_DOMAIN);
    input.extend_from_slice(installation_id.as_bytes());
    input.extend_from_slice(&invite_hash);
    input.extend_from_slice(&request_hash);
    input.extend_from_slice(&response_hash);
    input.extend_from_slice(&machine_root_fingerprint);
    input.extend_from_slice(machine_route.as_bytes());
    sha256(&input)
}

fn response_received_context(
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponseReceived,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn pair_response_context(pair_route: agentdeck_protocol::relay_v2::PairRouteId) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponse,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
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

fn build_initial_state<R: CryptoRng>(
    installation_id: Uuid,
    verified: &agentdeck_crypto::VerifiedPairResponseV1,
    invite: &PendingInvitePublicProjection,
    promotion_id: [u8; 32],
    device_signing_key: &SigningKey,
    rng: &mut R,
) -> Result<PairedCryptoStateV1, PairedPromotionError> {
    let info = verified.info();
    let grant_hash = verified.relay_grant().canonical_sha256();
    let invite_recipient = HpkePublicKey::from_bytes(&invite.invite_hpke_pubkey)
        .map_err(PairedPromotionError::Crypto)?;
    let receipt = seal_pair_response_received(
        &invite_recipient,
        info,
        &response_received_context(info.pair_route),
        PairResponseReceivedV1 {
            request_hash: info.request_hash,
            grant_hash,
            response_hash: verified.response_hash(),
            signature: Ed25519Signature([0; 64]),
        },
        device_signing_key,
        rng,
    )
    .map_err(PairedPromotionError::Crypto)?
    .canonical_bytes()
    .map_err(PairedPromotionError::Protocol)?;

    Ok(PairedCryptoStateV1 {
        installation_id,
        invite_hpke_pubkey: invite.invite_hpke_pubkey,
        wss_url: invite.wss_url.clone(),
        current_spki_pin: invite.current_spki_pin,
        next_spki_pin: invite.next_spki_pin,
        machine_display_name: invite.machine_display_name.clone(),
        relay_server_id: info.relay_server_id,
        machine_root_pubkey: verified.machine_root_pubkey().0,
        machine_root_fingerprint: verified.machine_root_fingerprint(),
        machine_route: info.machine_route,
        device_route: info.device_route,
        grant_serial: info.grant_serial,
        trust_epoch: info.root_trust_epoch,
        invite_hash: info.invite_hash,
        request_hash: info.request_hash,
        grant_hash,
        response_hash: verified.response_hash(),
        promotion_id,
        directory_revision: verified.key_directory().revision,
        canonical_response: verified.canonical_response().to_vec(),
        data_sign_certificate: verified.data_sign_certificate().canonical_bytes(),
        device_authorization: verified
            .device_authorization()
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?,
        key_directory: verified
            .key_directory()
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?,
        receipt_carrier: receipt,
    })
}

struct StateAudit {
    device_command_binding: CounterBindingV1,
    opened_keys: Vec<OpenedPairedDirectoryKey>,
}

struct DurableStateAudit {
    device_signing_key: SigningKey,
    machine_data_verifying_key: VerifyingKey,
    device_hpke_private_key: HpkePrivateKey,
    grant: RelayGrant,
    authorization: DeviceAuthorizationV1,
    opened_keys: Vec<OpenedPairedDirectoryKey>,
    device_command_binding: CounterBindingV1,
}

#[allow(clippy::too_many_arguments)]
fn audit_state(
    installation_id: Uuid,
    state: &PairedCryptoStateV1,
    verified: &agentdeck_crypto::VerifiedPairResponseV1,
    invite: &PendingInvitePublicProjection,
    grant_bytes: &[u8],
    device_sign_secret: &RemoteSecret,
    device_hpke_secret: &RemoteSecret,
) -> Result<StateAudit, PairedPromotionError> {
    let expected_info = verified.info();
    if state.installation_id != installation_id
        || state.invite_hpke_pubkey != invite.invite_hpke_pubkey
        || state.wss_url != invite.wss_url
        || state.current_spki_pin != invite.current_spki_pin
        || state.next_spki_pin != invite.next_spki_pin
        || state.machine_display_name != invite.machine_display_name
        || state.relay_server_id != expected_info.relay_server_id
        || state.machine_root_pubkey != verified.machine_root_pubkey().0
        || state.machine_root_fingerprint != verified.machine_root_fingerprint()
        || state.machine_route != expected_info.machine_route
        || state.device_route != expected_info.device_route
        || state.grant_serial != expected_info.grant_serial
        || state.trust_epoch != expected_info.root_trust_epoch
        || state.invite_hash != expected_info.invite_hash
        || state.request_hash != expected_info.request_hash
        || state.grant_hash != verified.relay_grant().canonical_sha256()
        || state.response_hash != verified.response_hash()
        || state.promotion_id != promotion_id(installation_id, verified)
        || state.directory_revision != verified.key_directory().revision
        || state.canonical_response != verified.canonical_response()
        || state.data_sign_certificate != verified.data_sign_certificate().canonical_bytes()
        || state.device_authorization
            != verified
                .device_authorization()
                .canonical_bytes()
                .map_err(PairedPromotionError::Protocol)?
        || state.key_directory
            != verified
                .key_directory()
                .canonical_bytes()
                .map_err(PairedPromotionError::Protocol)?
        || grant_bytes != verified.relay_grant().canonical_bytes()
    {
        return Err(PairedPromotionError::Conflict);
    }

    let durable = audit_durable_state(state, grant_bytes, device_sign_secret, device_hpke_secret)?;
    Ok(StateAudit {
        device_command_binding: durable.device_command_binding,
        opened_keys: durable.opened_keys,
    })
}

/// 不依赖 pending transaction 的 durable paired state 全审计。
///
/// canonical PairResponse 会再次以 paired DeviceHPKE 解密，随后 exact 比对并复核
/// Root→Data cert、grant/authorization、directory 签名，再逐项重新解封 wrapped keys。
fn audit_durable_state(
    state: &PairedCryptoStateV1,
    grant_bytes: &[u8],
    device_sign_secret: &RemoteSecret,
    device_hpke_secret: &RemoteSecret,
) -> Result<DurableStateAudit, PairedPromotionError> {
    let response = PairResponseV1::from_canonical_bytes(&state.canonical_response)
        .map_err(PairedPromotionError::Protocol)?;
    let info = &response.info;
    if state.relay_server_id != info.relay_server_id
        || state.machine_route != info.machine_route
        || state.device_route != info.device_route
        || state.grant_serial != info.grant_serial
        || state.trust_epoch != info.root_trust_epoch
        || state.invite_hash != info.invite_hash
        || state.request_hash != info.request_hash
        || state.response_hash != sha256(&state.canonical_response)
        || state.promotion_id
            != promotion_id_from_parts(
                state.installation_id,
                state.invite_hash,
                state.request_hash,
                state.response_hash,
                state.machine_root_fingerprint,
                state.machine_route,
            )
    {
        return Err(PairedPromotionError::Conflict);
    }
    let certificate = SignedCertificate::from_canonical_bytes(&state.data_sign_certificate)
        .map_err(PairedPromotionError::AuthCanonical)?;
    let grant = RelayGrant::from_canonical_bytes(grant_bytes)
        .map_err(PairedPromotionError::AuthCanonical)?;
    let authorization = DeviceAuthorizationV1::from_canonical_bytes(&state.device_authorization)
        .map_err(PairedPromotionError::Protocol)?;
    let directory = KeyDirectoryV1::from_canonical_bytes(&state.key_directory)
        .map_err(PairedPromotionError::Protocol)?;
    PairingControlEnvelopeV1::from_canonical_bytes(&state.receipt_carrier)
        .map_err(PairedPromotionError::Protocol)?;

    if state.grant_hash != grant.canonical_sha256()
        || state.directory_revision != directory.revision
        || grant.machine_route != state.machine_route
        || grant.device_route != state.device_route
        || grant.grant_serial != state.grant_serial
        || grant.trust_epoch != state.trust_epoch
    {
        return Err(PairedPromotionError::Conflict);
    }

    let root = VerifyingKey::from_bytes(&state.machine_root_pubkey)
        .map_err(PairedPromotionError::Crypto)?;
    if sha256(&root.to_bytes()) != state.machine_root_fingerprint
        || certificate.cert_role != CertRole::Data
        || certificate.root_key_id != grant.root_key_id
        || certificate.trust_epoch != state.trust_epoch
    {
        return Err(PairedPromotionError::Conflict);
    }
    verify_tbs(
        &root,
        &certificate.to_be_signed_v1(
            state.relay_server_id,
            state.machine_route,
            state.machine_root_fingerprint,
        ),
        &SignatureBytes::from(certificate.signature),
    )
    .map_err(PairedPromotionError::Crypto)?;
    verify_tbs(
        &root,
        &grant.to_be_signed_v1(state.relay_server_id, state.machine_root_fingerprint),
        &SignatureBytes::from(grant.signature),
    )
    .map_err(PairedPromotionError::Crypto)?;

    let data_verifier = VerifyingKey::from_bytes(&certificate.subject_pubkey.0)
        .map_err(PairedPromotionError::Crypto)?;
    let signer = MachineDataSignerBindingV1::from_certificate(&certificate)
        .map_err(PairedPromotionError::Protocol)?;
    let signing_key = signing_key(device_sign_secret)?;
    let hpke_private = hpke_private_key(device_hpke_secret)?;
    let plaintext = open_pair_response(
        &hpke_private,
        info,
        &pair_response_context(info.pair_route),
        &response,
        &data_verifier,
        &signer,
        &root,
    )
    .map_err(PairedPromotionError::Crypto)?;
    if plaintext.request_hash != state.request_hash
        || plaintext.relay_grant.canonical_bytes() != grant_bytes
        || plaintext
            .device_authorization
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?
            != state.device_authorization
        || plaintext
            .key_directory
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?
            != state.key_directory
        || authorization
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?
            != state.device_authorization
        || directory
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?
            != state.key_directory
        || grant.device_sign_pubkey.0 != signing_key.verifying_key().to_bytes()
        || authorization.device_hpke_pubkey.0 != hpke_public_bytes(&hpke_private)?
    {
        return Err(PairedPromotionError::Conflict);
    }

    let mut slots = HashSet::with_capacity(directory.entries.len());
    let mut command_binding = None;
    let mut reply_key_seen = false;
    let mut opened_keys = Vec::with_capacity(directory.entries.len());
    for entry in &directory.entries {
        if !slots.insert((entry.key_id.purpose, entry.stream_route)) {
            return Err(PairedPromotionError::InvalidState);
        }
        let entry_info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: state.relay_server_id,
            machine_route: state.machine_route,
            device_route: state.device_route,
            stream_route: entry.stream_route,
            grant_serial: state.grant_serial,
            root_trust_epoch: state.trust_epoch,
            key_directory_revision: directory.revision,
            key_purpose: entry.key_id.purpose,
            key_epoch: entry.key_id.epoch,
        };
        let key = open_key_directory_entry(
            &hpke_private,
            &entry_info,
            &key_update_context(&entry_info),
            entry,
        )
        .map_err(PairedPromotionError::Crypto)?;
        if entry.key_id.purpose == KeyPurpose::DeviceCommandTx {
            if entry.stream_route.is_some() || command_binding.is_some() {
                return Err(PairedPromotionError::InvalidState);
            }
            command_binding = Some(CounterBindingV1 {
                key_epoch: entry.key_id.epoch,
                nonce_prefix: agentdeck_crypto::derive_nonce_prefix(&key),
            });
        } else if entry.key_id.purpose == KeyPurpose::DeviceReplyTx {
            if entry.stream_route.is_some() || reply_key_seen {
                return Err(PairedPromotionError::InvalidState);
            }
            reply_key_seen = true;
        }
        let material = match entry.key_id.purpose {
            KeyPurpose::DeviceCommandTx => {
                OpenedPairedKeyMaterial::CommandTx(AeadSendingKey::with_derived_nonce_prefix(
                    entry.key_id,
                    entry.key_id.epoch,
                    directory.revision.value(),
                    key,
                ))
            }
            KeyPurpose::DeviceReplyTx => {
                let nonce_prefix = agentdeck_crypto::derive_nonce_prefix(&key);
                OpenedPairedKeyMaterial::ReplyTx {
                    key: AeadReceivingKey::new(entry.key_id, entry.key_id.epoch, key),
                    nonce_prefix,
                }
            }
            KeyPurpose::Catalog | KeyPurpose::ConversationDek => {
                let nonce_prefix = agentdeck_crypto::derive_nonce_prefix(&key);
                OpenedPairedKeyMaterial::StreamRx {
                    key: AeadReceivingKey::new(entry.key_id, entry.key_id.epoch, key),
                    nonce_prefix,
                }
            }
        };
        opened_keys.push(OpenedPairedDirectoryKey {
            key_id: entry.key_id,
            stream_route: entry.stream_route,
            material,
        });
    }
    if !reply_key_seen {
        return Err(PairedPromotionError::InvalidState);
    }

    Ok(DurableStateAudit {
        device_signing_key: signing_key,
        machine_data_verifying_key: data_verifier,
        device_hpke_private_key: hpke_private,
        grant,
        authorization,
        opened_keys,
        device_command_binding: command_binding.ok_or(PairedPromotionError::InvalidState)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_counter_guard_state(
    marker: &PairedCommitMarkerV1,
    identity: PairedMachineIdentity,
    guard: &CounterGuardState,
    guard_bytes: &[u8],
    state: &PairedCryptoState,
    state_bytes: &[u8],
    prepared_stage: Option<&PreparedCryptoStateStage>,
    expected_binding: CounterBindingV1,
) -> Result<(), PairedPromotionError> {
    let state_hash = sha256(state_bytes);
    match (*guard, state) {
        (CounterGuardState::V1(value), PairedCryptoState::V1(_))
            if value
                == CounterGuardV1::from_binding(marker.directory_revision, expected_binding)
                && sha256(guard_bytes) == marker.counter_guard_hash =>
        {
            validate_uncommitted_orphan_stage(
                marker,
                identity,
                guard_bytes,
                state,
                state_bytes,
                0,
                prepared_stage,
            )
        }
        (CounterGuardState::V1(_), PairedCryptoState::V1(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V2(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V3(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V4(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V2(value), _) => {
            if value.initial_guard_commitment != marker.counter_guard_hash
                || value.directory_revision != marker.directory_revision
                || value.binding != expected_binding
            {
                return Err(PairedPromotionError::Conflict);
            }
            match value.phase {
                CounterGuardPhaseV2::Stable {
                    reserved_high_water,
                    current_state_hash,
                } if current_state_hash == state_hash
                    && state_matches_stable_high_water(state, reserved_high_water) =>
                {
                    validate_uncommitted_orphan_stage(
                        marker,
                        identity,
                        guard_bytes,
                        state,
                        state_bytes,
                        reserved_high_water,
                        prepared_stage,
                    )
                }
                CounterGuardPhaseV2::StateStable {
                    reserved_high_water,
                    current_state_hash,
                    mutation_id,
                    previous_guard_hash,
                    stage_commitment,
                } if current_state_hash == state_hash
                    && state_matches_stable_high_water(state, reserved_high_water) =>
                {
                    validate_state_stable_stage(
                        marker,
                        identity,
                        guard_bytes,
                        state,
                        state_bytes,
                        reserved_high_water,
                        mutation_id,
                        previous_guard_hash,
                        stage_commitment,
                        prepared_stage,
                    )
                }
                CounterGuardPhaseV2::Pending {
                    previous_high_water,
                    next_high_water,
                    reservation_id,
                    previous_state_hash,
                    next_state_hash,
                } if state_hash == previous_state_hash
                    && state_matches_previous_high_water(state, previous_high_water) =>
                {
                    if prepared_stage.is_some() {
                        return Err(PairedPromotionError::Conflict);
                    }
                    let expected = CommandCounterReservation {
                        reservation_id,
                        start: previous_high_water,
                        end_exclusive: next_high_water,
                    };
                    expected.validate()?;
                    rebuild_frozen_counter_state(marker, state, expected, next_state_hash)?;
                    Ok(())
                }
                CounterGuardPhaseV2::Pending {
                    previous_high_water,
                    next_high_water,
                    reservation_id,
                    previous_state_hash: _,
                    next_state_hash,
                } if state_hash == next_state_hash => {
                    if prepared_stage.is_some() {
                        return Err(PairedPromotionError::Conflict);
                    }
                    let expected = CommandCounterReservation {
                        reservation_id,
                        start: previous_high_water,
                        end_exclusive: next_high_water,
                    };
                    expected.validate()?;
                    if state.counter_reservation() == Some(&expected) {
                        Ok(())
                    } else {
                        Err(PairedPromotionError::Conflict)
                    }
                }
                CounterGuardPhaseV2::StatePending {
                    reserved_high_water,
                    mutation_id,
                    previous_guard_hash,
                    previous_state_hash,
                    next_state_hash,
                    stage_commitment,
                } => validate_state_pending_stage(
                    marker,
                    identity,
                    state,
                    state_bytes,
                    reserved_high_water,
                    mutation_id,
                    previous_guard_hash,
                    previous_state_hash,
                    next_state_hash,
                    stage_commitment,
                    prepared_stage,
                ),
                _ => Err(PairedPromotionError::Conflict),
            }
        }
    }
}

fn validate_uncommitted_orphan_stage(
    marker: &PairedCommitMarkerV1,
    identity: PairedMachineIdentity,
    guard_bytes: &[u8],
    active: &PairedCryptoState,
    active_bytes: &[u8],
    reserved_high_water: u64,
    prepared_stage: Option<&PreparedCryptoStateStage>,
) -> Result<(), PairedPromotionError> {
    let Some(stage) = prepared_stage else {
        return Ok(());
    };
    let active_hash = sha256(active_bytes);
    if stage.previous_guard_hash() != sha256(guard_bytes)
        || active_hash != stage.previous_state_hash()
    {
        return Err(PairedPromotionError::Conflict);
    }
    let next = PairedCryptoState::decode(stage.snapshot().expose_secret())?;
    marker.validate_state(identity, &next, stage.snapshot().expose_secret())?;
    if !state_matches_stable_high_water(&next, reserved_high_water) {
        return Err(PairedPromotionError::Conflict);
    }
    validate_runtime_only_transition(marker, active, &next, stage.snapshot().expose_secret())
}

#[allow(clippy::too_many_arguments)]
fn validate_state_stable_stage(
    marker: &PairedCommitMarkerV1,
    identity: PairedMachineIdentity,
    guard_bytes: &[u8],
    active: &PairedCryptoState,
    active_bytes: &[u8],
    reserved_high_water: u64,
    mutation_id: [u8; 16],
    previous_guard_hash: [u8; 32],
    stage_commitment: [u8; 32],
    prepared_stage: Option<&PreparedCryptoStateStage>,
) -> Result<(), PairedPromotionError> {
    let Some(stage) = prepared_stage else {
        return Ok(());
    };
    let active_hash = sha256(active_bytes);
    let next = PairedCryptoState::decode(stage.snapshot().expose_secret())?;
    marker.validate_state(identity, &next, stage.snapshot().expose_secret())?;
    if !state_matches_stable_high_water(&next, reserved_high_water) {
        return Err(PairedPromotionError::Conflict);
    }
    if stage.mutation_id() == mutation_id
        && stage.previous_guard_hash() == previous_guard_hash
        && stage.sealed_commitment() == stage_commitment
        && active_hash == stage.next_state_hash()
        && active_bytes == stage.snapshot().expose_secret()
    {
        // Stable 已经提交本轮 exact next；sidecar 只待安全清理，不能再次执行 transition。
        Ok(())
    } else if stage.previous_guard_hash() == sha256(guard_bytes)
        && active_hash == stage.previous_state_hash()
    {
        // 下一轮只完成了 stage-first；这是未提交 intent，只允许清理，绝不能前滚 active/HWM。
        validate_runtime_only_transition(marker, active, &next, stage.snapshot().expose_secret())
    } else {
        Err(PairedPromotionError::Conflict)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_state_pending_stage(
    marker: &PairedCommitMarkerV1,
    identity: PairedMachineIdentity,
    active: &PairedCryptoState,
    active_bytes: &[u8],
    reserved_high_water: u64,
    mutation_id: [u8; 16],
    previous_guard_hash: [u8; 32],
    previous_state_hash: [u8; 32],
    next_state_hash: [u8; 32],
    stage_commitment: [u8; 32],
    prepared_stage: Option<&PreparedCryptoStateStage>,
) -> Result<(), PairedPromotionError> {
    let stage = prepared_stage.ok_or(PairedPromotionError::Conflict)?;
    if stage.mutation_id() != mutation_id
        || stage.previous_guard_hash() != previous_guard_hash
        || stage.previous_state_hash() != previous_state_hash
        || stage.next_state_hash() != next_state_hash
        || stage.sealed_commitment() != stage_commitment
    {
        return Err(PairedPromotionError::Conflict);
    }
    let next = PairedCryptoState::decode(stage.snapshot().expose_secret())?;
    marker.validate_state(identity, &next, stage.snapshot().expose_secret())?;
    if !state_matches_stable_high_water(&next, reserved_high_water) {
        return Err(PairedPromotionError::Conflict);
    }
    let active_hash = sha256(active_bytes);
    if active_hash == previous_state_hash
        && state_matches_previous_high_water(active, reserved_high_water)
    {
        validate_runtime_only_transition(marker, active, &next, stage.snapshot().expose_secret())
    } else if active_hash == next_state_hash
        && active_bytes == stage.snapshot().expose_secret()
        && state_matches_stable_high_water(active, reserved_high_water)
    {
        Ok(())
    } else {
        Err(PairedPromotionError::Conflict)
    }
}

fn validate_runtime_only_transition(
    marker: &PairedCommitMarkerV1,
    previous: &PairedCryptoState,
    next: &PairedCryptoState,
    next_bytes: &[u8],
) -> Result<(), PairedPromotionError> {
    let rebuilt = previous.rebuild_mutable_projection_from(
        marker.state_plaintext_hash,
        marker.counter_guard_hash,
        next,
    )?;
    let rebuilt_bytes = Zeroizing::new(rebuilt.encode()?);
    if rebuilt_bytes.as_slice() == next_bytes {
        Ok(())
    } else {
        Err(PairedPromotionError::Conflict)
    }
}

/// 纯只读地重建 Pending 冻结的 canonical next state；inventory audit 与 recovery
/// 共用这一条路径，避免 `list()` 接受一个直到 `open()` 才发现不可恢复的 transition。
fn rebuild_frozen_counter_state(
    marker: &PairedCommitMarkerV1,
    previous: &PairedCryptoState,
    reservation: CommandCounterReservation,
    expected_state_hash: [u8; 32],
) -> Result<(PairedCryptoState, CryptoStateSnapshot), PairedPromotionError> {
    let next = previous.with_counter_reservation(
        marker.state_plaintext_hash,
        marker.counter_guard_hash,
        &reservation,
    )?;
    let encoded = next.encode()?;
    if sha256(&encoded) != expected_state_hash {
        return Err(PairedPromotionError::Conflict);
    }
    Ok((next, CryptoStateSnapshot::new(encoded)))
}

fn state_matches_previous_high_water(state: &PairedCryptoState, high_water: u64) -> bool {
    match state {
        // V1 guard 本身只编码初始 HWM=0；任何非零值都必须已有 V2 sealed fence。
        PairedCryptoState::V1(_) => high_water == 0,
        PairedCryptoState::V2(_) | PairedCryptoState::V3(_) | PairedCryptoState::V4(_) => {
            match state.counter_reservation() {
                Some(reservation) => reservation.end_exclusive == high_water,
                None => high_water == 0,
            }
        }
    }
}

fn state_matches_stable_high_water(state: &PairedCryptoState, high_water: u64) -> bool {
    match state {
        // stable V2 总在 sealed-state CAS 之后；V1 state 是不可能的 durable 顺序。
        PairedCryptoState::V1(_) => false,
        PairedCryptoState::V2(_) | PairedCryptoState::V3(_) | PairedCryptoState::V4(_) => {
            match state.counter_reservation() {
                Some(reservation) => reservation.end_exclusive == high_water,
                None => high_water == 0,
            }
        }
    }
}

struct StorageKekRecordV1 {
    promotion_id: [u8; 32],
    key: [u8; 32],
}

impl fmt::Debug for StorageKekRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StorageKekRecordV1([REDACTED])")
    }
}

impl Drop for StorageKekRecordV1 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl StorageKekRecordV1 {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(72);
        encoded.extend_from_slice(KEK_MAGIC);
        encoded.extend_from_slice(&KEK_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&self.promotion_id);
        encoded.extend_from_slice(&self.key);
        encoded
    }

    fn commitment(&self) -> [u8; 32] {
        sha256(&Zeroizing::new(self.encode()))
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() != 72
            || &bytes[..4] != KEK_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != KEK_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let promotion_id: [u8; 32] = bytes[8..40]
            .try_into()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let key: [u8; 32] = bytes[40..72]
            .try_into()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        if all_zero(&promotion_id) || all_zero(&key) {
            return Err(PairedPromotionError::InvalidState);
        }
        let value = Self { promotion_id, key };
        if value.encode() != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn device_storage_kek(&self) -> DeviceStorageKek {
        DeviceStorageKek::new(self.key)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterBindingV1 {
    key_epoch: u64,
    nonce_prefix: [u8; 4],
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CounterGuardState {
    V1(CounterGuardV1),
    V2(CounterGuardV2),
}

impl fmt::Debug for CounterGuardState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CounterGuardState([REDACTED])")
    }
}

impl CounterGuardState {
    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() < 8 || &bytes[..4] != COUNTER_GUARD_MAGIC {
            return Err(PairedPromotionError::InvalidState);
        }
        match u16::from_be_bytes([bytes[4], bytes[5]]) {
            COUNTER_GUARD_VERSION => CounterGuardV1::decode(bytes).map(Self::V1),
            MUTABLE_COUNTER_GUARD_VERSION => CounterGuardV2::decode(bytes).map(Self::V2),
            _ => Err(PairedPromotionError::InvalidState),
        }
    }

    fn encode(self) -> Vec<u8> {
        match self {
            Self::V1(value) => value.encode(),
            Self::V2(value) => value.encode(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterGuardV1 {
    directory_revision: KeyDirectoryRevision,
    binding: CounterBindingV1,
    reserved_high_water: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CounterGuardPhaseV2 {
    Stable {
        reserved_high_water: u64,
        current_state_hash: [u8; 32],
    },
    Pending {
        previous_high_water: u64,
        next_high_water: u64,
        reservation_id: [u8; 16],
        previous_state_hash: [u8; 32],
        next_state_hash: [u8; 32],
    },
    StatePending {
        reserved_high_water: u64,
        mutation_id: [u8; 16],
        previous_guard_hash: [u8; 32],
        previous_state_hash: [u8; 32],
        next_state_hash: [u8; 32],
        stage_commitment: [u8; 32],
    },
    StateStable {
        reserved_high_water: u64,
        current_state_hash: [u8; 32],
        mutation_id: [u8; 16],
        previous_guard_hash: [u8; 32],
        stage_commitment: [u8; 32],
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CounterGuardV2 {
    initial_guard_commitment: [u8; 32],
    directory_revision: KeyDirectoryRevision,
    binding: CounterBindingV1,
    phase: CounterGuardPhaseV2,
}

impl fmt::Debug for CounterGuardV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CounterGuardV2([REDACTED])")
    }
}

impl CounterGuardV2 {
    fn stable(
        initial_guard_commitment: [u8; 32],
        directory_revision: KeyDirectoryRevision,
        binding: CounterBindingV1,
        reserved_high_water: u64,
        current_state_hash: [u8; 32],
    ) -> Result<Self, PairedPromotionError> {
        let value = Self {
            initial_guard_commitment,
            directory_revision,
            binding,
            phase: CounterGuardPhaseV2::Stable {
                reserved_high_water,
                current_state_hash,
            },
        };
        value.validate()?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    fn pending(
        initial_guard_commitment: [u8; 32],
        directory_revision: KeyDirectoryRevision,
        binding: CounterBindingV1,
        previous_high_water: u64,
        next_high_water: u64,
        reservation_id: [u8; 16],
        previous_state_hash: [u8; 32],
        next_state_hash: [u8; 32],
    ) -> Result<Self, PairedPromotionError> {
        let value = Self {
            initial_guard_commitment,
            directory_revision,
            binding,
            phase: CounterGuardPhaseV2::Pending {
                previous_high_water,
                next_high_water,
                reservation_id,
                previous_state_hash,
                next_state_hash,
            },
        };
        value.validate()?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    fn state_pending(
        initial_guard_commitment: [u8; 32],
        directory_revision: KeyDirectoryRevision,
        binding: CounterBindingV1,
        reserved_high_water: u64,
        mutation_id: [u8; 16],
        previous_guard_hash: [u8; 32],
        previous_state_hash: [u8; 32],
        next_state_hash: [u8; 32],
        stage_commitment: [u8; 32],
    ) -> Result<Self, PairedPromotionError> {
        let value = Self {
            initial_guard_commitment,
            directory_revision,
            binding,
            phase: CounterGuardPhaseV2::StatePending {
                reserved_high_water,
                mutation_id,
                previous_guard_hash,
                previous_state_hash,
                next_state_hash,
                stage_commitment,
            },
        };
        value.validate()?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    fn state_stable(
        initial_guard_commitment: [u8; 32],
        directory_revision: KeyDirectoryRevision,
        binding: CounterBindingV1,
        reserved_high_water: u64,
        current_state_hash: [u8; 32],
        mutation_id: [u8; 16],
        previous_guard_hash: [u8; 32],
        stage_commitment: [u8; 32],
    ) -> Result<Self, PairedPromotionError> {
        let value = Self {
            initial_guard_commitment,
            directory_revision,
            binding,
            phase: CounterGuardPhaseV2::StateStable {
                reserved_high_water,
                current_state_hash,
                mutation_id,
                previous_guard_hash,
                stage_commitment,
            },
        };
        value.validate()?;
        Ok(value)
    }

    fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(match self.phase {
            CounterGuardPhaseV2::Stable { .. } => 100,
            CounterGuardPhaseV2::Pending { .. } => 156,
            CounterGuardPhaseV2::StatePending { .. } => 212,
            CounterGuardPhaseV2::StateStable { .. } => 180,
        });
        encoded.extend_from_slice(COUNTER_GUARD_MAGIC);
        encoded.extend_from_slice(&MUTABLE_COUNTER_GUARD_VERSION.to_be_bytes());
        encoded.push(match self.phase {
            CounterGuardPhaseV2::Stable { .. } => 0,
            CounterGuardPhaseV2::Pending { .. } => 1,
            CounterGuardPhaseV2::StatePending { .. } => 2,
            CounterGuardPhaseV2::StateStable { .. } => 3,
        });
        encoded.push(0);
        encoded.extend_from_slice(&self.initial_guard_commitment);
        encoded.extend_from_slice(&self.directory_revision.value().to_be_bytes());
        encoded.extend_from_slice(&self.binding.key_epoch.to_be_bytes());
        encoded.extend_from_slice(&self.binding.nonce_prefix);
        match self.phase {
            CounterGuardPhaseV2::Stable {
                reserved_high_water,
                current_state_hash,
            } => {
                encoded.extend_from_slice(&reserved_high_water.to_be_bytes());
                encoded.extend_from_slice(&current_state_hash);
            }
            CounterGuardPhaseV2::Pending {
                previous_high_water,
                next_high_water,
                reservation_id,
                previous_state_hash,
                next_state_hash,
            } => {
                encoded.extend_from_slice(&previous_high_water.to_be_bytes());
                encoded.extend_from_slice(&next_high_water.to_be_bytes());
                encoded.extend_from_slice(&reservation_id);
                encoded.extend_from_slice(&previous_state_hash);
                encoded.extend_from_slice(&next_state_hash);
            }
            CounterGuardPhaseV2::StatePending {
                reserved_high_water,
                mutation_id,
                previous_guard_hash,
                previous_state_hash,
                next_state_hash,
                stage_commitment,
            } => {
                encoded.extend_from_slice(&reserved_high_water.to_be_bytes());
                encoded.extend_from_slice(&mutation_id);
                encoded.extend_from_slice(&previous_guard_hash);
                encoded.extend_from_slice(&previous_state_hash);
                encoded.extend_from_slice(&next_state_hash);
                encoded.extend_from_slice(&stage_commitment);
            }
            CounterGuardPhaseV2::StateStable {
                reserved_high_water,
                current_state_hash,
                mutation_id,
                previous_guard_hash,
                stage_commitment,
            } => {
                encoded.extend_from_slice(&reserved_high_water.to_be_bytes());
                encoded.extend_from_slice(&current_state_hash);
                encoded.extend_from_slice(&mutation_id);
                encoded.extend_from_slice(&previous_guard_hash);
                encoded.extend_from_slice(&stage_commitment);
            }
        }
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if !matches!(bytes.len(), 100 | 156 | 180 | 212)
            || &bytes[..4] != COUNTER_GUARD_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != MUTABLE_COUNTER_GUARD_VERSION
            || bytes[7] != 0
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[8..]);
        let initial_guard_commitment = decoder.fixed()?;
        let directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
        let binding = CounterBindingV1 {
            key_epoch: decoder.u64()?,
            nonce_prefix: decoder.fixed()?,
        };
        let value = match bytes[6] {
            0 if bytes.len() == 100 => Self::stable(
                initial_guard_commitment,
                directory_revision,
                binding,
                decoder.u64()?,
                decoder.fixed()?,
            )?,
            1 if bytes.len() == 156 => Self::pending(
                initial_guard_commitment,
                directory_revision,
                binding,
                decoder.u64()?,
                decoder.u64()?,
                decoder.fixed()?,
                decoder.fixed()?,
                decoder.fixed()?,
            )?,
            2 if bytes.len() == 212 => Self::state_pending(
                initial_guard_commitment,
                directory_revision,
                binding,
                decoder.u64()?,
                decoder.fixed()?,
                decoder.fixed()?,
                decoder.fixed()?,
                decoder.fixed()?,
                decoder.fixed()?,
            )?,
            3 if bytes.len() == 180 => Self::state_stable(
                initial_guard_commitment,
                directory_revision,
                binding,
                decoder.u64()?,
                decoder.fixed()?,
                decoder.fixed()?,
                decoder.fixed()?,
                decoder.fixed()?,
            )?,
            _ => return Err(PairedPromotionError::InvalidState),
        };
        decoder.finish()?;
        if value.encode() != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn validate(self) -> Result<(), PairedPromotionError> {
        if all_zero(&self.initial_guard_commitment)
            || self.directory_revision.value() == 0
            || self.binding.key_epoch == 0
        {
            return Err(PairedPromotionError::InvalidState);
        }
        match self.phase {
            CounterGuardPhaseV2::Stable {
                reserved_high_water,
                current_state_hash,
            } if reserved_high_water == 0
                || !reserved_high_water.is_multiple_of(COUNTER_BLOCK_SIZE)
                || all_zero(&current_state_hash) =>
            {
                Err(PairedPromotionError::InvalidState)
            }
            CounterGuardPhaseV2::Pending {
                previous_high_water,
                next_high_water,
                reservation_id,
                previous_state_hash,
                next_state_hash,
            } if !previous_high_water.is_multiple_of(COUNTER_BLOCK_SIZE)
                || previous_high_water
                    .checked_add(COUNTER_BLOCK_SIZE)
                    .is_none_or(|end| end != next_high_water)
                || all_zero(&reservation_id)
                || all_zero(&previous_state_hash)
                || all_zero(&next_state_hash)
                || previous_state_hash == next_state_hash =>
            {
                Err(PairedPromotionError::InvalidState)
            }
            CounterGuardPhaseV2::StatePending {
                reserved_high_water,
                mutation_id,
                previous_guard_hash,
                previous_state_hash,
                next_state_hash,
                stage_commitment,
            } if !reserved_high_water.is_multiple_of(COUNTER_BLOCK_SIZE)
                || all_zero(&mutation_id)
                || all_zero(&previous_guard_hash)
                || all_zero(&previous_state_hash)
                || all_zero(&next_state_hash)
                || all_zero(&stage_commitment)
                || previous_state_hash == next_state_hash =>
            {
                Err(PairedPromotionError::InvalidState)
            }
            CounterGuardPhaseV2::StateStable {
                reserved_high_water,
                current_state_hash,
                mutation_id,
                previous_guard_hash,
                stage_commitment,
            } if !reserved_high_water.is_multiple_of(COUNTER_BLOCK_SIZE)
                || all_zero(&current_state_hash)
                || all_zero(&mutation_id)
                || all_zero(&previous_guard_hash)
                || all_zero(&stage_commitment) =>
            {
                Err(PairedPromotionError::InvalidState)
            }
            _ => Ok(()),
        }
    }
}

impl CounterGuardV1 {
    fn from_binding(directory_revision: KeyDirectoryRevision, binding: CounterBindingV1) -> Self {
        Self {
            directory_revision,
            binding,
            reserved_high_water: 0,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(36);
        encoded.extend_from_slice(COUNTER_GUARD_MAGIC);
        encoded.extend_from_slice(&COUNTER_GUARD_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&self.directory_revision.value().to_be_bytes());
        encoded.extend_from_slice(&self.binding.key_epoch.to_be_bytes());
        encoded.extend_from_slice(&self.binding.nonce_prefix);
        encoded.extend_from_slice(&self.reserved_high_water.to_be_bytes());
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() != 36
            || &bytes[..4] != COUNTER_GUARD_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != COUNTER_GUARD_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let value = Self {
            directory_revision: KeyDirectoryRevision::new(read_u64(&bytes[8..16])?),
            binding: CounterBindingV1 {
                key_epoch: read_u64(&bytes[16..24])?,
                nonce_prefix: bytes[24..28]
                    .try_into()
                    .map_err(|_| PairedPromotionError::InvalidState)?,
            },
            reserved_high_water: read_u64(&bytes[28..36])?,
        };
        if value.directory_revision.value() == 0
            || value.binding.key_epoch == 0
            || value.reserved_high_water != 0
            || value.encode() != bytes
        {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }
}

#[derive(Clone)]
struct PairedCryptoStateV1 {
    installation_id: Uuid,
    invite_hpke_pubkey: [u8; 32],
    wss_url: String,
    current_spki_pin: [u8; 32],
    next_spki_pin: [u8; 32],
    machine_display_name: String,
    relay_server_id: RelayServerId,
    machine_root_pubkey: [u8; 32],
    machine_root_fingerprint: [u8; 32],
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    trust_epoch: TrustEpoch,
    invite_hash: [u8; 32],
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    promotion_id: [u8; 32],
    directory_revision: KeyDirectoryRevision,
    canonical_response: Vec<u8>,
    data_sign_certificate: Vec<u8>,
    device_authorization: Vec<u8>,
    key_directory: Vec<u8>,
    receipt_carrier: Vec<u8>,
}

impl fmt::Debug for PairedCryptoStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCryptoStateV1([REDACTED])")
    }
}

impl PairedCryptoStateV1 {
    fn encode(&self) -> Result<Vec<u8>, PairedPromotionError> {
        self.validate_shape()?;
        let mut body = Vec::new();
        body.extend_from_slice(self.installation_id.as_bytes());
        body.extend_from_slice(&self.invite_hpke_pubkey);
        body.extend_from_slice(self.relay_server_id.as_bytes());
        body.extend_from_slice(&self.machine_root_pubkey);
        body.extend_from_slice(&self.machine_root_fingerprint);
        body.extend_from_slice(&self.current_spki_pin);
        body.extend_from_slice(&self.next_spki_pin);
        body.extend_from_slice(self.machine_route.as_bytes());
        body.extend_from_slice(self.device_route.as_bytes());
        body.extend_from_slice(&self.grant_serial.value().to_be_bytes());
        body.extend_from_slice(&self.trust_epoch.value().to_be_bytes());
        body.extend_from_slice(&self.invite_hash);
        body.extend_from_slice(&self.request_hash);
        body.extend_from_slice(&self.grant_hash);
        body.extend_from_slice(&self.response_hash);
        body.extend_from_slice(&self.promotion_id);
        body.extend_from_slice(&self.directory_revision.value().to_be_bytes());
        // receipt outbox=pending、counter reservation=None、空 replay/cursor collections。
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        put_state_field(&mut body, self.wss_url.as_bytes(), MAX_STATE_STRING_LEN)?;
        put_state_field(
            &mut body,
            self.machine_display_name.as_bytes(),
            MAX_STATE_STRING_LEN,
        )?;
        put_state_field(&mut body, &self.canonical_response, MAX_STATE_FIELD_LEN)?;
        put_state_field(&mut body, &self.data_sign_certificate, MAX_STATE_FIELD_LEN)?;
        put_state_field(&mut body, &self.device_authorization, MAX_STATE_FIELD_LEN)?;
        put_state_field(&mut body, &self.key_directory, MAX_STATE_FIELD_LEN)?;
        put_state_field(&mut body, &self.receipt_carrier, MAX_STATE_FIELD_LEN)?;
        if body.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN - STATE_HEADER_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        let body_len = u32::try_from(body.len()).map_err(|_| PairedPromotionError::InvalidState)?;
        let mut encoded = Vec::with_capacity(STATE_HEADER_LEN + body.len());
        encoded.extend_from_slice(STATE_MAGIC);
        encoded.extend_from_slice(&STATE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&body_len.to_be_bytes());
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() < STATE_HEADER_LEN
            || bytes.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN
            || &bytes[..4] != STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != STATE_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        ) as usize;
        if declared != bytes.len() - STATE_HEADER_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[STATE_HEADER_LEN..]);
        let installation_id = Uuid::from_bytes(decoder.fixed()?);
        let invite_hpke_pubkey = decoder.fixed()?;
        let relay_server_id = RelayServerId::from_bytes(decoder.fixed()?);
        let machine_root_pubkey = decoder.fixed()?;
        let machine_root_fingerprint = decoder.fixed()?;
        let current_spki_pin = decoder.fixed()?;
        let next_spki_pin = decoder.fixed()?;
        let machine_route = MachineRouteId::from_bytes(decoder.fixed()?);
        let device_route = DeviceRouteId::from_bytes(decoder.fixed()?);
        let grant_serial = GrantSerial::new(decoder.u64()?);
        let trust_epoch = TrustEpoch::new(decoder.u64()?);
        let invite_hash = decoder.fixed()?;
        let request_hash = decoder.fixed()?;
        let grant_hash = decoder.fixed()?;
        let response_hash = decoder.fixed()?;
        let promotion_id = decoder.fixed()?;
        let directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
        if decoder.u8()? != 0 || decoder.u8()? != 0 || decoder.u16()? != 0 || decoder.u16()? != 0 {
            return Err(PairedPromotionError::InvalidState);
        }
        let wss_url = decoder.string(MAX_STATE_STRING_LEN)?;
        let machine_display_name = decoder.string(MAX_STATE_STRING_LEN)?;
        let canonical_response = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let data_sign_certificate = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let device_authorization = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let key_directory = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let receipt_carrier = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        decoder.finish()?;
        let value = Self {
            installation_id,
            invite_hpke_pubkey,
            wss_url,
            current_spki_pin,
            next_spki_pin,
            machine_display_name,
            relay_server_id,
            machine_root_pubkey,
            machine_root_fingerprint,
            machine_route,
            device_route,
            grant_serial,
            trust_epoch,
            invite_hash,
            request_hash,
            grant_hash,
            response_hash,
            promotion_id,
            directory_revision,
            canonical_response,
            data_sign_certificate,
            device_authorization,
            key_directory,
            receipt_carrier,
        };
        value.validate_shape()?;
        if value.encode()? != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), PairedPromotionError> {
        if self.installation_id.is_nil()
            || all_zero(&self.invite_hpke_pubkey)
            || self.wss_url.is_empty()
            || self.wss_url.len() > MAX_STATE_STRING_LEN
            || all_zero(&self.current_spki_pin)
            || all_zero(&self.next_spki_pin)
            || self.machine_display_name.is_empty()
            || self.machine_display_name.len() > MAX_STATE_STRING_LEN
            || all_zero(self.relay_server_id.as_bytes())
            || all_zero(&self.machine_root_pubkey)
            || all_zero(&self.machine_root_fingerprint)
            || all_zero(self.machine_route.as_bytes())
            || all_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.trust_epoch.value() == 0
            || all_zero(&self.invite_hash)
            || all_zero(&self.request_hash)
            || all_zero(&self.grant_hash)
            || all_zero(&self.response_hash)
            || all_zero(&self.promotion_id)
            || self.directory_revision.value() == 0
            || self.canonical_response.is_empty()
            || self.data_sign_certificate.is_empty()
            || self.device_authorization.is_empty()
            || self.key_directory.is_empty()
            || self.receipt_carrier.is_empty()
        {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(())
    }
}

enum PairedCryptoState {
    V1(PairedCryptoStateV1),
    V2(PairedCryptoStateV2),
    V3(PairedCryptoStateV2),
    V4(PairedCryptoStateV2),
}

impl fmt::Debug for PairedCryptoState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCryptoState([REDACTED])")
    }
}

impl PairedCryptoState {
    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() < STATE_HEADER_LEN || &bytes[..4] != STATE_MAGIC {
            return Err(PairedPromotionError::InvalidState);
        }
        match u16::from_be_bytes([bytes[4], bytes[5]]) {
            STATE_VERSION => PairedCryptoStateV1::decode(bytes).map(Self::V1),
            MUTABLE_STATE_VERSION => {
                PairedCryptoStateV2::decode_version(bytes, MUTABLE_STATE_VERSION).map(Self::V2)
            }
            TYPED_RUNTIME_STATE_VERSION => {
                PairedCryptoStateV2::decode_version(bytes, TYPED_RUNTIME_STATE_VERSION)
                    .map(Self::V3)
            }
            KEY_SYNC_STATE_VERSION => {
                PairedCryptoStateV2::decode_version(bytes, KEY_SYNC_STATE_VERSION).map(Self::V4)
            }
            _ => Err(PairedPromotionError::InvalidState),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, PairedPromotionError> {
        match self {
            Self::V1(value) => value.encode(),
            Self::V2(value) => value.encode_version(MUTABLE_STATE_VERSION),
            Self::V3(value) => value.encode_version(TYPED_RUNTIME_STATE_VERSION),
            Self::V4(value) => value.encode_version(KEY_SYNC_STATE_VERSION),
        }
    }

    const fn bootstrap(&self) -> &PairedCryptoStateV1 {
        match self {
            Self::V1(value) => value,
            Self::V2(value) | Self::V3(value) | Self::V4(value) => &value.bootstrap,
        }
    }

    const fn counter_reservation(&self) -> Option<&CommandCounterReservation> {
        match self {
            Self::V1(_) => None,
            Self::V2(value) | Self::V3(value) | Self::V4(value) => {
                value.counter_reservation.as_ref()
            }
        }
    }

    fn with_counter_reservation(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        reservation: &CommandCounterReservation,
    ) -> Result<Self, PairedPromotionError> {
        reservation.validate()?;
        let version = match self {
            Self::V1(_) | Self::V2(_) => MUTABLE_STATE_VERSION,
            Self::V3(_) => TYPED_RUNTIME_STATE_VERSION,
            Self::V4(_) => KEY_SYNC_STATE_VERSION,
        };
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            &self.opaque_runtime_state(),
            Some(reservation),
            self.key_sync_state_bytes().map(ToOwned::to_owned),
            version,
            true,
        )
    }

    fn opaque_runtime_state(&self) -> OpaqueRuntimeState {
        match self {
            Self::V1(_) => OpaqueRuntimeState::empty(),
            Self::V2(value) | Self::V3(value) | Self::V4(value) => OpaqueRuntimeState {
                exchange: value.receipt_terminal.clone(),
                replay_windows: value.replay_windows.clone(),
                stream_cursors: value.stream_cursors.clone(),
            },
        }
    }

    fn durable_stream_bindings(&self) -> Result<Vec<DurableStreamBindingV1>, PairedPromotionError> {
        match self {
            Self::V1(_) => Ok(Vec::new()),
            Self::V2(value) if value.stream_cursors.is_empty() => Ok(Vec::new()),
            Self::V2(_) => Err(PairedPromotionError::InvalidState),
            Self::V3(value) | Self::V4(value) => decode_stream_bindings(&value.stream_cursors)
                .map_err(|_| PairedPromotionError::InvalidState),
        }
    }

    fn typed_durable_stream_bindings(
        &self,
    ) -> Result<Option<Vec<DurableStreamBindingV1>>, PairedPromotionError> {
        match self {
            Self::V1(_) | Self::V2(_) => Ok(None),
            Self::V3(value) | Self::V4(value) => decode_stream_bindings(&value.stream_cursors)
                .map(Some)
                .map_err(|_| PairedPromotionError::InvalidState),
        }
    }

    fn key_sync_state_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::V1(_) | Self::V2(_) | Self::V3(_) => None,
            Self::V4(value) => value.durable_key_sync_state.as_deref(),
        }
    }

    fn durable_key_sync_state(
        &self,
    ) -> Result<Option<DurableKeySyncStateV1>, PairedPromotionError> {
        self.key_sync_state_bytes()
            .map(DurableKeySyncStateV1::from_canonical_bytes)
            .transpose()
            .map_err(|_| PairedPromotionError::InvalidState)
    }

    fn with_opaque_runtime_state(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        runtime: &OpaqueRuntimeState,
    ) -> Result<Self, PairedPromotionError> {
        runtime.validate()?;
        let automatic_probe = runtime.automatic_probe().ok().flatten().is_some();
        let version = if matches!(self, Self::V4(_)) {
            KEY_SYNC_STATE_VERSION
        } else if automatic_probe {
            MUTABLE_STATE_VERSION
        } else {
            TYPED_RUNTIME_STATE_VERSION
        };
        self.with_opaque_runtime_state_version(
            initial_state_commitment,
            initial_guard_commitment,
            runtime,
            self.key_sync_state_bytes().map(ToOwned::to_owned),
            version,
            true,
        )
    }

    fn with_legacy_v2_opaque_runtime_state(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        runtime: &OpaqueRuntimeState,
    ) -> Result<Self, PairedPromotionError> {
        runtime.validate()?;
        if !runtime.stream_cursors.is_empty()
            || runtime.automatic_legacy_v2_probe()?.is_none()
            || matches!(self, Self::V3(_) | Self::V4(_))
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.with_opaque_runtime_state_version(
            initial_state_commitment,
            initial_guard_commitment,
            runtime,
            None,
            MUTABLE_STATE_VERSION,
            true,
        )
    }

    fn with_opaque_runtime_state_version(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        runtime: &OpaqueRuntimeState,
        durable_key_sync_state: Option<Vec<u8>>,
        version: u16,
        validate_key_sync: bool,
    ) -> Result<Self, PairedPromotionError> {
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            runtime,
            self.counter_reservation(),
            durable_key_sync_state,
            version,
            validate_key_sync,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_mutable_projection(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        runtime: &OpaqueRuntimeState,
        counter_reservation: Option<&CommandCounterReservation>,
        durable_key_sync_state: Option<Vec<u8>>,
        version: u16,
        validate_key_sync: bool,
    ) -> Result<Self, PairedPromotionError> {
        if !matches!(
            version,
            MUTABLE_STATE_VERSION | TYPED_RUNTIME_STATE_VERSION | KEY_SYNC_STATE_VERSION
        ) || matches!(self, Self::V4(_)) && version != KEY_SYNC_STATE_VERSION
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let copy_reservation =
            |reservation: &CommandCounterReservation| CommandCounterReservation {
                reservation_id: reservation.reservation_id,
                start: reservation.start,
                end_exclusive: reservation.end_exclusive,
            };
        let value = match self {
            Self::V1(bootstrap) => PairedCryptoStateV2 {
                initial_state_commitment,
                initial_guard_commitment,
                bootstrap: bootstrap.clone(),
                receipt_terminal: runtime.exchange.clone(),
                counter_reservation: counter_reservation.map(copy_reservation),
                replay_windows: runtime.replay_windows.clone(),
                stream_cursors: runtime.stream_cursors.clone(),
                durable_key_sync_state,
            },
            Self::V2(current) | Self::V3(current) | Self::V4(current) => PairedCryptoStateV2 {
                initial_state_commitment: current.initial_state_commitment,
                initial_guard_commitment: current.initial_guard_commitment,
                bootstrap: current.bootstrap.clone(),
                receipt_terminal: runtime.exchange.clone(),
                counter_reservation: counter_reservation.map(copy_reservation),
                replay_windows: runtime.replay_windows.clone(),
                stream_cursors: runtime.stream_cursors.clone(),
                durable_key_sync_state,
            },
        };
        value.validate_for_version_inner(version, validate_key_sync)?;
        match version {
            MUTABLE_STATE_VERSION => Ok(Self::V2(value)),
            TYPED_RUNTIME_STATE_VERSION => Ok(Self::V3(value)),
            KEY_SYNC_STATE_VERSION => Ok(Self::V4(value)),
            _ => Err(PairedPromotionError::InvalidState),
        }
    }

    fn with_key_sync_state_bytes(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        durable_key_sync_state: Option<Vec<u8>>,
        validate_key_sync: bool,
    ) -> Result<Self, PairedPromotionError> {
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            &self.opaque_runtime_state(),
            self.counter_reservation(),
            durable_key_sync_state,
            KEY_SYNC_STATE_VERSION,
            validate_key_sync,
        )
    }

    fn rebuild_mutable_projection_from(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        next: &Self,
    ) -> Result<Self, PairedPromotionError> {
        let version = match next {
            Self::V1(_) => return Err(PairedPromotionError::Conflict),
            Self::V2(_) => MUTABLE_STATE_VERSION,
            Self::V3(_) => TYPED_RUNTIME_STATE_VERSION,
            Self::V4(_) => KEY_SYNC_STATE_VERSION,
        };
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            &next.opaque_runtime_state(),
            self.counter_reservation(),
            next.key_sync_state_bytes().map(ToOwned::to_owned),
            version,
            true,
        )
    }
}

/// V2/V3/V4 共用 payload：marker 的两个旧 hash 固化为 initial commitments，当前 state hash
/// 只由 guard 绑定。V2 保留 legacy bounded opaque fields；V3 additionally 要求 stream collection
/// 逐项通过 typed canonical decode；V4 末尾再追加 optional canonical ADKS KeySync state。
struct PairedCryptoStateV2 {
    initial_state_commitment: [u8; 32],
    initial_guard_commitment: [u8; 32],
    bootstrap: PairedCryptoStateV1,
    receipt_terminal: Option<Vec<u8>>,
    counter_reservation: Option<CommandCounterReservation>,
    replay_windows: Vec<Vec<u8>>,
    stream_cursors: Vec<Vec<u8>>,
    durable_key_sync_state: Option<Vec<u8>>,
}

impl fmt::Debug for PairedCryptoStateV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCryptoStateV2([REDACTED])")
    }
}

impl PairedCryptoStateV2 {
    fn encode_version(&self, version: u16) -> Result<Vec<u8>, PairedPromotionError> {
        self.encode_version_inner(version, true)
    }

    fn encode_version_inner(
        &self,
        version: u16,
        validate_key_sync: bool,
    ) -> Result<Vec<u8>, PairedPromotionError> {
        self.validate_for_version_inner(version, validate_key_sync)?;
        let mut body = Vec::new();
        body.extend_from_slice(&self.initial_state_commitment);
        body.extend_from_slice(&self.initial_guard_commitment);
        let bootstrap = Zeroizing::new(self.bootstrap.encode()?);
        put_state_field(
            &mut body,
            bootstrap.as_slice(),
            MAX_CRYPTO_STATE_PLAINTEXT_LEN,
        )?;
        put_state_field(
            &mut body,
            self.receipt_terminal.as_deref().unwrap_or_default(),
            MAX_STATE_FIELD_LEN,
        )?;
        match &self.counter_reservation {
            Some(reservation) => {
                body.push(1);
                body.extend_from_slice(&[0, 0, 0]);
                body.extend_from_slice(&reservation.reservation_id);
                body.extend_from_slice(&reservation.start.to_be_bytes());
                body.extend_from_slice(&reservation.end_exclusive.to_be_bytes());
            }
            None => body.extend_from_slice(&[0; 36]),
        }
        put_state_collection(&mut body, &self.replay_windows)?;
        put_state_collection(&mut body, &self.stream_cursors)?;
        if version == KEY_SYNC_STATE_VERSION {
            put_state_field(
                &mut body,
                self.durable_key_sync_state.as_deref().unwrap_or_default(),
                MAX_STATE_FIELD_LEN,
            )?;
        }
        if body.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN - STATE_HEADER_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        let body_len = u32::try_from(body.len()).map_err(|_| PairedPromotionError::InvalidState)?;
        let mut encoded = Vec::with_capacity(STATE_HEADER_LEN + body.len());
        encoded.extend_from_slice(STATE_MAGIC);
        encoded.extend_from_slice(&version.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&body_len.to_be_bytes());
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    fn decode_version(bytes: &[u8], version: u16) -> Result<Self, PairedPromotionError> {
        if bytes.len() < STATE_HEADER_LEN
            || bytes.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN
            || &bytes[..4] != STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != version
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        ) as usize;
        if declared != bytes.len() - STATE_HEADER_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[STATE_HEADER_LEN..]);
        let initial_state_commitment = decoder.fixed()?;
        let initial_guard_commitment = decoder.fixed()?;
        let bootstrap =
            PairedCryptoStateV1::decode(decoder.field(MAX_CRYPTO_STATE_PLAINTEXT_LEN)?)?;
        let receipt = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let receipt_terminal = (!receipt.is_empty()).then_some(receipt);
        let reservation_tag = decoder.u8()?;
        if decoder.take(3)? != [0, 0, 0] {
            return Err(PairedPromotionError::InvalidState);
        }
        let reservation_id = decoder.fixed()?;
        let reservation_start = decoder.u64()?;
        let reservation_end = decoder.u64()?;
        let counter_reservation = match reservation_tag {
            0 if all_zero(&reservation_id) && reservation_start == 0 && reservation_end == 0 => {
                None
            }
            1 => Some(CommandCounterReservation {
                reservation_id,
                start: reservation_start,
                end_exclusive: reservation_end,
            }),
            _ => return Err(PairedPromotionError::InvalidState),
        };
        let replay_windows = decode_state_collection(&mut decoder)?;
        let stream_cursors = decode_state_collection(&mut decoder)?;
        let durable_key_sync_state = if version == KEY_SYNC_STATE_VERSION {
            let bytes = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
            (!bytes.is_empty()).then_some(bytes)
        } else {
            None
        };
        decoder.finish()?;
        let value = Self {
            initial_state_commitment,
            initial_guard_commitment,
            bootstrap,
            receipt_terminal,
            counter_reservation,
            replay_windows,
            stream_cursors,
            durable_key_sync_state,
        };
        value.validate_for_version(version)?;
        let canonical = Zeroizing::new(value.encode_version(version)?);
        if canonical.as_slice() != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn validate_for_version(&self, version: u16) -> Result<(), PairedPromotionError> {
        self.validate_for_version_inner(version, true)
    }

    fn validate_for_version_inner(
        &self,
        version: u16,
        validate_key_sync: bool,
    ) -> Result<(), PairedPromotionError> {
        if !matches!(
            version,
            MUTABLE_STATE_VERSION | TYPED_RUNTIME_STATE_VERSION | KEY_SYNC_STATE_VERSION
        ) {
            return Err(PairedPromotionError::InvalidState);
        }
        let bootstrap = Zeroizing::new(self.bootstrap.encode()?);
        if all_zero(&self.initial_state_commitment)
            || all_zero(&self.initial_guard_commitment)
            || sha256(bootstrap.as_slice()) != self.initial_state_commitment
            || self.receipt_terminal.as_ref().is_some_and(Vec::is_empty)
            || self.replay_windows.len() > MAX_STATE_COLLECTION_ITEMS
            || self.stream_cursors.len() > MAX_STATE_COLLECTION_ITEMS
            || self
                .replay_windows
                .iter()
                .chain(&self.stream_cursors)
                .any(|entry| entry.is_empty() || entry.len() > MAX_STATE_FIELD_LEN)
        {
            return Err(PairedPromotionError::InvalidState);
        }
        if version != KEY_SYNC_STATE_VERSION && self.durable_key_sync_state.is_some() {
            return Err(PairedPromotionError::InvalidState);
        }
        if validate_key_sync && let Some(bytes) = &self.durable_key_sync_state {
            let state = DurableKeySyncStateV1::from_canonical_bytes(bytes)
                .map_err(|_| PairedPromotionError::InvalidState)?;
            if state
                .canonical_bytes()
                .map_err(|_| PairedPromotionError::InvalidState)?
                != *bytes
            {
                return Err(PairedPromotionError::InvalidState);
            }
        }
        if let Some(reservation) = &self.counter_reservation {
            reservation.validate()?;
        }
        let encoded_len = checked_mutable_state_encoded_len(
            bootstrap.len(),
            self.receipt_terminal.as_ref().map_or(0, Vec::len),
            self.replay_windows.iter().map(Vec::len),
            self.stream_cursors.iter().map(Vec::len),
        )?;
        if version == KEY_SYNC_STATE_VERSION {
            let key_sync_len = self.durable_key_sync_state.as_ref().map_or(0, Vec::len);
            if key_sync_len > MAX_STATE_FIELD_LEN
                || encoded_len
                    .checked_add(4)
                    .and_then(|length| length.checked_add(key_sync_len))
                    .is_none_or(|length| length > MAX_CRYPTO_STATE_PLAINTEXT_LEN)
            {
                return Err(PairedPromotionError::InvalidState);
            }
        }
        if version == TYPED_RUNTIME_STATE_VERSION || version == KEY_SYNC_STATE_VERSION {
            decode_stream_bindings(&self.stream_cursors)
                .map_err(|_| PairedPromotionError::InvalidState)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct PairedCommitMarkerV1 {
    installation_id: Uuid,
    root_fingerprint: [u8; 32],
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    trust_epoch: TrustEpoch,
    directory_revision: KeyDirectoryRevision,
    device_sign_pubkey: [u8; 32],
    device_hpke_pubkey: [u8; 32],
    invite_hash: [u8; 32],
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    promotion_id: [u8; 32],
    state_plaintext_hash: [u8; 32],
    kek_record_hash: [u8; 32],
    counter_guard_hash: [u8; 32],
    receipt_carrier_hash: [u8; 32],
}

impl fmt::Debug for PairedCommitMarkerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCommitMarkerV1([REDACTED])")
    }
}

impl PairedCommitMarkerV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        installation_id: Uuid,
        state: &PairedCryptoStateV1,
        promotion_id: [u8; 32],
        state_plaintext_hash: [u8; 32],
        kek_record_hash: [u8; 32],
        counter_guard_hash: [u8; 32],
        device_sign_pubkey: [u8; 32],
        device_hpke_pubkey: [u8; 32],
    ) -> Self {
        Self {
            installation_id,
            root_fingerprint: state.machine_root_fingerprint,
            relay_server_id: state.relay_server_id,
            machine_route: state.machine_route,
            device_route: state.device_route,
            grant_serial: state.grant_serial,
            trust_epoch: state.trust_epoch,
            directory_revision: state.directory_revision,
            device_sign_pubkey,
            device_hpke_pubkey,
            invite_hash: state.invite_hash,
            request_hash: state.request_hash,
            grant_hash: state.grant_hash,
            response_hash: state.response_hash,
            promotion_id,
            state_plaintext_hash,
            kek_record_hash,
            counter_guard_hash,
            receipt_carrier_hash: sha256(&state.receipt_carrier),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(PAIRED_COMMIT_MARKER_BYTES);
        encoded.extend_from_slice(MARKER_MAGIC);
        encoded.extend_from_slice(&MARKER_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(self.installation_id.as_bytes());
        encoded.extend_from_slice(&self.root_fingerprint);
        encoded.extend_from_slice(self.relay_server_id.as_bytes());
        encoded.extend_from_slice(self.machine_route.as_bytes());
        encoded.extend_from_slice(self.device_route.as_bytes());
        encoded.extend_from_slice(&self.grant_serial.value().to_be_bytes());
        encoded.extend_from_slice(&self.trust_epoch.value().to_be_bytes());
        encoded.extend_from_slice(&self.directory_revision.value().to_be_bytes());
        encoded.extend_from_slice(&self.device_sign_pubkey);
        encoded.extend_from_slice(&self.device_hpke_pubkey);
        for hash in [
            self.invite_hash,
            self.request_hash,
            self.grant_hash,
            self.response_hash,
            self.promotion_id,
            self.state_plaintext_hash,
            self.kek_record_hash,
            self.counter_guard_hash,
            self.receipt_carrier_hash,
        ] {
            encoded.extend_from_slice(&hash);
        }
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() != PAIRED_COMMIT_MARKER_BYTES
            || &bytes[..4] != MARKER_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != MARKER_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[8..]);
        let value = Self {
            installation_id: Uuid::from_bytes(decoder.fixed()?),
            root_fingerprint: decoder.fixed()?,
            relay_server_id: RelayServerId::from_bytes(decoder.fixed()?),
            machine_route: MachineRouteId::from_bytes(decoder.fixed()?),
            device_route: DeviceRouteId::from_bytes(decoder.fixed()?),
            grant_serial: GrantSerial::new(decoder.u64()?),
            trust_epoch: TrustEpoch::new(decoder.u64()?),
            directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            device_sign_pubkey: decoder.fixed()?,
            device_hpke_pubkey: decoder.fixed()?,
            invite_hash: decoder.fixed()?,
            request_hash: decoder.fixed()?,
            grant_hash: decoder.fixed()?,
            response_hash: decoder.fixed()?,
            promotion_id: decoder.fixed()?,
            state_plaintext_hash: decoder.fixed()?,
            kek_record_hash: decoder.fixed()?,
            counter_guard_hash: decoder.fixed()?,
            receipt_carrier_hash: decoder.fixed()?,
        };
        decoder.finish()?;
        if value.encode() != bytes || value.any_required_zero() {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn any_required_zero(&self) -> bool {
        self.installation_id.is_nil()
            || all_zero(&self.root_fingerprint)
            || all_zero(self.relay_server_id.as_bytes())
            || all_zero(self.machine_route.as_bytes())
            || all_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.trust_epoch.value() == 0
            || self.directory_revision.value() == 0
            || [
                self.device_sign_pubkey,
                self.device_hpke_pubkey,
                self.invite_hash,
                self.request_hash,
                self.grant_hash,
                self.response_hash,
                self.promotion_id,
                self.state_plaintext_hash,
                self.kek_record_hash,
                self.counter_guard_hash,
                self.receipt_carrier_hash,
            ]
            .iter()
            .any(|value| all_zero(value))
    }

    fn validate_account(
        &self,
        installation_id: Uuid,
        identity: PairedMachineIdentity,
    ) -> Result<(), PairedPromotionError> {
        if self.installation_id != installation_id
            || self.root_fingerprint != *identity.machine_root_fingerprint.as_bytes()
            || self.machine_route != identity.machine_route
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(())
    }

    fn validate_state(
        &self,
        identity: PairedMachineIdentity,
        state: &PairedCryptoState,
        state_bytes: &[u8],
    ) -> Result<(), PairedPromotionError> {
        let bootstrap = state.bootstrap();
        if bootstrap.installation_id != self.installation_id
            || bootstrap.machine_root_fingerprint != self.root_fingerprint
            || bootstrap.machine_root_fingerprint != *identity.machine_root_fingerprint.as_bytes()
            || bootstrap.relay_server_id != self.relay_server_id
            || bootstrap.machine_route != self.machine_route
            || bootstrap.machine_route != identity.machine_route
            || bootstrap.device_route != self.device_route
            || bootstrap.grant_serial != self.grant_serial
            || bootstrap.trust_epoch != self.trust_epoch
            || bootstrap.directory_revision != self.directory_revision
            || bootstrap.invite_hash != self.invite_hash
            || bootstrap.request_hash != self.request_hash
            || bootstrap.grant_hash != self.grant_hash
            || bootstrap.response_hash != self.response_hash
            || bootstrap.promotion_id != self.promotion_id
            || sha256(&bootstrap.receipt_carrier) != self.receipt_carrier_hash
        {
            return Err(PairedPromotionError::Conflict);
        }
        match state {
            PairedCryptoState::V1(_) if sha256(state_bytes) == self.state_plaintext_hash => {}
            PairedCryptoState::V2(value)
            | PairedCryptoState::V3(value)
            | PairedCryptoState::V4(value)
                if value.initial_state_commitment == self.state_plaintext_hash
                    && value.initial_guard_commitment == self.counter_guard_hash => {}
            _ => return Err(PairedPromotionError::Conflict),
        }
        Ok(())
    }

    fn validate_expected(
        &self,
        installation_id: Uuid,
        verified: &agentdeck_crypto::VerifiedPairResponseV1,
        promotion_id: [u8; 32],
    ) -> Result<(), PairedPromotionError> {
        let info = verified.info();
        if self.installation_id != installation_id
            || self.root_fingerprint != verified.machine_root_fingerprint()
            || self.relay_server_id != info.relay_server_id
            || self.machine_route != info.machine_route
            || self.device_route != info.device_route
            || self.grant_serial != info.grant_serial
            || self.trust_epoch != info.root_trust_epoch
            || self.directory_revision != verified.key_directory().revision
            || self.device_sign_pubkey != verified.relay_grant().device_sign_pubkey.0
            || self.device_hpke_pubkey != verified.device_authorization().device_hpke_pubkey.0
            || self.invite_hash != info.invite_hash
            || self.request_hash != info.request_hash
            || self.grant_hash != verified.relay_grant().canonical_sha256()
            || self.response_hash != verified.response_hash()
            || self.promotion_id != promotion_id
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(())
    }
}

enum PairedMarkerValue {
    Active(Box<PairedCommitMarkerV1>),
    Cleanup(Box<PairedCleanupJournalV1>),
}

impl PairedMarkerValue {
    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        match bytes.get(..4) {
            Some(magic) if magic == MARKER_MAGIC => {
                PairedCommitMarkerV1::decode(bytes).map(|marker| Self::Active(Box::new(marker)))
            }
            Some(magic) if magic == CLEANUP_JOURNAL_MAGIC => PairedCleanupJournalV1::decode(bytes)
                .map(|journal| Self::Cleanup(Box::new(journal))),
            _ => Err(PairedPromotionError::InvalidState),
        }
    }
}

struct PairedCleanupJournalV1 {
    installation_id: Uuid,
    root_fingerprint: [u8; 32],
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    machine_root_pubkey: [u8; 32],
    active_marker: PairedCommitMarkerV1,
    terminal_bytes: Vec<u8>,
    grant_bytes: Vec<u8>,
    state_plaintext_hash: [u8; 32],
    counter_guard_hash: [u8; 32],
    grant_hash: [u8; 32],
    device_hpke_hash: [u8; 32],
    device_sign_hash: [u8; 32],
    storage_kek_hash: [u8; 32],
    journal_signature: SignatureBytes,
}

impl fmt::Debug for PairedCleanupJournalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCleanupJournalV1([REDACTED])")
    }
}

impl PairedCleanupJournalV1 {
    fn encode_unsigned(&self) -> Result<Vec<u8>, PairedPromotionError> {
        let mut encoded = Vec::with_capacity(
            8 + 16
                + 32
                + 16
                + 16
                + 16
                + 8
                + 16
                + 8
                + 32
                + PAIRED_COMMIT_MARKER_BYTES
                + 4
                + self.terminal_bytes.len()
                + 4
                + self.grant_bytes.len()
                + 6 * 32,
        );
        encoded.extend_from_slice(CLEANUP_JOURNAL_MAGIC);
        encoded.extend_from_slice(&CLEANUP_JOURNAL_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(self.installation_id.as_bytes());
        encoded.extend_from_slice(&self.root_fingerprint);
        encoded.extend_from_slice(self.relay_server_id.as_bytes());
        encoded.extend_from_slice(self.machine_route.as_bytes());
        encoded.extend_from_slice(self.device_route.as_bytes());
        encoded.extend_from_slice(&self.grant_serial.value().to_be_bytes());
        encoded.extend_from_slice(self.root_key_id.as_bytes());
        encoded.extend_from_slice(&self.trust_epoch.value().to_be_bytes());
        encoded.extend_from_slice(&self.machine_root_pubkey);
        encoded.extend_from_slice(&self.active_marker.encode());
        put_state_field(
            &mut encoded,
            &self.terminal_bytes,
            MAX_CLEANUP_TERMINAL_BYTES,
        )?;
        put_state_field(&mut encoded, &self.grant_bytes, MAX_CLEANUP_GRANT_BYTES)?;
        for hash in [
            self.state_plaintext_hash,
            self.counter_guard_hash,
            self.grant_hash,
            self.device_hpke_hash,
            self.device_sign_hash,
            self.storage_kek_hash,
        ] {
            encoded.extend_from_slice(&hash);
        }
        Ok(encoded)
    }

    fn encode(&self) -> Result<Vec<u8>, PairedPromotionError> {
        let mut encoded = self.encode_unsigned()?;
        encoded.extend_from_slice(&self.journal_signature.0);
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        const FIXED_AFTER_HEADER: usize = 16
            + 32
            + 16
            + 16
            + 16
            + 8
            + 16
            + 8
            + 32
            + PAIRED_COMMIT_MARKER_BYTES
            + 4
            + 4
            + 6 * 32
            + 64;
        if bytes.len() < 8 + FIXED_AFTER_HEADER
            || &bytes[..4] != CLEANUP_JOURNAL_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != CLEANUP_JOURNAL_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[8..]);
        let installation_id = Uuid::from_bytes(decoder.fixed()?);
        let root_fingerprint = decoder.fixed()?;
        let relay_server_id = RelayServerId::from_bytes(decoder.fixed()?);
        let machine_route = MachineRouteId::from_bytes(decoder.fixed()?);
        let device_route = DeviceRouteId::from_bytes(decoder.fixed()?);
        let grant_serial = GrantSerial::new(decoder.u64()?);
        let root_key_id = RootKeyId::from_bytes(decoder.fixed()?);
        let trust_epoch = TrustEpoch::new(decoder.u64()?);
        let machine_root_pubkey = decoder.fixed()?;
        let active_marker_bytes: [u8; PAIRED_COMMIT_MARKER_BYTES] = decoder.fixed()?;
        let active_marker = PairedCommitMarkerV1::decode(&active_marker_bytes)?;
        let terminal_bytes = decoder.field(MAX_CLEANUP_TERMINAL_BYTES)?.to_vec();
        let grant_bytes = decoder.field(MAX_CLEANUP_GRANT_BYTES)?.to_vec();
        let value = Self {
            installation_id,
            root_fingerprint,
            relay_server_id,
            machine_route,
            device_route,
            grant_serial,
            root_key_id,
            trust_epoch,
            machine_root_pubkey,
            active_marker,
            terminal_bytes,
            grant_bytes,
            state_plaintext_hash: decoder.fixed()?,
            counter_guard_hash: decoder.fixed()?,
            grant_hash: decoder.fixed()?,
            device_hpke_hash: decoder.fixed()?,
            device_sign_hash: decoder.fixed()?,
            storage_kek_hash: decoder.fixed()?,
            journal_signature: SignatureBytes(decoder.fixed()?),
        };
        decoder.finish()?;
        if value.encode()?.as_slice() != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn validate(&self, identity: PairedMachineIdentity) -> Result<(), PairedPromotionError> {
        self.active_marker
            .validate_account(self.installation_id, identity)?;
        if self.installation_id.is_nil()
            || self.root_fingerprint != *identity.machine_root_fingerprint.as_bytes()
            || self.root_fingerprint != self.active_marker.root_fingerprint
            || self.relay_server_id != self.active_marker.relay_server_id
            || self.machine_route != identity.machine_route
            || self.machine_route != self.active_marker.machine_route
            || self.device_route != self.active_marker.device_route
            || self.grant_serial != self.active_marker.grant_serial
            || self.trust_epoch != self.active_marker.trust_epoch
            || all_zero(self.root_key_id.as_bytes())
            || sha256(&self.machine_root_pubkey) != self.root_fingerprint
            || self.terminal_bytes.is_empty()
            || self.terminal_bytes.len() > MAX_CLEANUP_TERMINAL_BYTES
            || self.grant_bytes.is_empty()
            || self.grant_bytes.len() > MAX_CLEANUP_GRANT_BYTES
            || [
                self.state_plaintext_hash,
                self.counter_guard_hash,
                self.grant_hash,
                self.device_hpke_hash,
                self.device_sign_hash,
                self.storage_kek_hash,
            ]
            .iter()
            .any(|hash| all_zero(hash))
        {
            return Err(PairedPromotionError::Conflict);
        }

        let root = VerifyingKey::from_bytes(&self.machine_root_pubkey)
            .map_err(PairedPromotionError::Crypto)?;
        let grant = RelayGrant::from_canonical_bytes(&self.grant_bytes)
            .map_err(PairedPromotionError::AuthCanonical)?;
        if grant.machine_route != self.machine_route
            || grant.device_route != self.device_route
            || grant.grant_serial != self.grant_serial
            || grant.root_key_id != self.root_key_id
            || grant.trust_epoch != self.trust_epoch
            || grant.device_sign_pubkey.0 != self.active_marker.device_sign_pubkey
            || grant.canonical_sha256() != self.grant_hash
            || self.grant_hash != self.active_marker.grant_hash
            || self.storage_kek_hash != self.active_marker.kek_record_hash
        {
            return Err(PairedPromotionError::Conflict);
        }
        verify_tbs(
            &root,
            &grant.to_be_signed_v1(self.relay_server_id, self.root_fingerprint),
            &SignatureBytes::from(grant.signature),
        )
        .map_err(PairedPromotionError::Crypto)?;
        let device_sign = VerifyingKey::from_bytes(&grant.device_sign_pubkey.0)
            .map_err(PairedPromotionError::Crypto)?;
        verify_revocation_cleanup_journal_digest(
            &device_sign,
            sha256(&self.encode_unsigned()?),
            &self.journal_signature,
        )
        .map_err(PairedPromotionError::Crypto)?;

        let terminal =
            decode(&self.terminal_bytes).map_err(|_| PairedPromotionError::InvalidState)?;
        validate_exact_revocation_terminal(
            &terminal,
            &self.terminal_bytes,
            RevocationTerminalBinding {
                root_fingerprint: self.root_fingerprint,
                relay_server_id: self.relay_server_id,
                machine_route: self.machine_route,
                device_route: self.device_route,
                grant_serial: self.grant_serial,
                root_key_id: self.root_key_id,
                trust_epoch: self.trust_epoch,
                machine_root_pubkey: self.machine_root_pubkey,
            },
        )
    }
}

struct StateDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> StateDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PairedPromotionError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(PairedPromotionError::InvalidState)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(PairedPromotionError::InvalidState)?;
        self.cursor = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], PairedPromotionError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PairedPromotionError::InvalidState)
    }

    fn u8(&mut self) -> Result<u8, PairedPromotionError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PairedPromotionError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, PairedPromotionError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, PairedPromotionError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn field(&mut self, max: usize) -> Result<&'a [u8], PairedPromotionError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| PairedPromotionError::InvalidState)?;
        if length > max {
            return Err(PairedPromotionError::InvalidState);
        }
        self.take(length)
    }

    fn string(&mut self, max: usize) -> Result<String, PairedPromotionError> {
        String::from_utf8(self.field(max)?.to_vec()).map_err(|_| PairedPromotionError::InvalidState)
    }

    fn finish(self) -> Result<(), PairedPromotionError> {
        if self.cursor != self.bytes.len() {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(())
    }
}

fn put_state_field(
    encoded: &mut Vec<u8>,
    value: &[u8],
    max: usize,
) -> Result<(), PairedPromotionError> {
    if value.len() > max {
        return Err(PairedPromotionError::InvalidState);
    }
    let length = u32::try_from(value.len()).map_err(|_| PairedPromotionError::InvalidState)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value);
    Ok(())
}

fn put_state_collection(
    encoded: &mut Vec<u8>,
    values: &[Vec<u8>],
) -> Result<(), PairedPromotionError> {
    if values.len() > MAX_STATE_COLLECTION_ITEMS {
        return Err(PairedPromotionError::InvalidState);
    }
    let count = u16::try_from(values.len()).map_err(|_| PairedPromotionError::InvalidState)?;
    encoded.extend_from_slice(&count.to_be_bytes());
    for value in values {
        if value.is_empty() {
            return Err(PairedPromotionError::InvalidState);
        }
        put_state_field(encoded, value, MAX_STATE_FIELD_LEN)?;
    }
    Ok(())
}

fn checked_mutable_state_encoded_len<I, J>(
    bootstrap_len: usize,
    receipt_len: usize,
    replay_lengths: I,
    cursor_lengths: J,
) -> Result<usize, PairedPromotionError>
where
    I: IntoIterator<Item = usize>,
    J: IntoIterator<Item = usize>,
{
    if bootstrap_len > MAX_CRYPTO_STATE_PLAINTEXT_LEN || receipt_len > MAX_STATE_FIELD_LEN {
        return Err(PairedPromotionError::InvalidState);
    }
    let mut encoded_len = MUTABLE_STATE_FIXED_ENCODED_LEN
        .checked_add(bootstrap_len)
        .and_then(|length| length.checked_add(receipt_len))
        .ok_or(PairedPromotionError::InvalidState)?;
    for value_len in replay_lengths.into_iter().chain(cursor_lengths) {
        if value_len == 0 || value_len > MAX_STATE_FIELD_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        encoded_len = encoded_len
            .checked_add(4)
            .and_then(|length| length.checked_add(value_len))
            .ok_or(PairedPromotionError::InvalidState)?;
        if encoded_len > MAX_CRYPTO_STATE_PLAINTEXT_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
    }
    if encoded_len > MAX_CRYPTO_STATE_PLAINTEXT_LEN {
        return Err(PairedPromotionError::InvalidState);
    }
    Ok(encoded_len)
}

fn decode_state_collection(
    decoder: &mut StateDecoder<'_>,
) -> Result<Vec<Vec<u8>>, PairedPromotionError> {
    let count = usize::from(decoder.u16()?);
    if count > MAX_STATE_COLLECTION_ITEMS {
        return Err(PairedPromotionError::InvalidState);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        if value.is_empty() {
            return Err(PairedPromotionError::InvalidState);
        }
        values.push(value);
    }
    Ok(values)
}

fn read_u64(bytes: &[u8]) -> Result<u64, PairedPromotionError> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| PairedPromotionError::InvalidState)?,
    ))
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod counter_reservation_tests {
    use std::convert::Infallible;

    use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};

    use super::*;

    fn reservation(id: u8, start: u64) -> CommandCounterReservation {
        CommandCounterReservation {
            reservation_id: [id; 16],
            start,
            end_exclusive: start + COUNTER_BLOCK_SIZE,
        }
    }

    #[test]
    fn old_prompt_reservation_cannot_seal_after_current_state_advances() {
        let old = reservation(0x11, 0);
        let current = reservation(0x22, COUNTER_BLOCK_SIZE);

        assert!(matches!(
            validate_current_command_reservation(Some(&current), &old),
            Err(PairedPromotionError::Conflict)
        ));
        validate_current_command_reservation(Some(&current), &current)
            .expect("exact authenticated current reservation remains usable once");
    }

    #[test]
    fn closed_runtime_requests_map_to_one_exact_authorization_each() {
        let catalog = AuthorizedRuntimeRequest::Catalog(CatalogRequest { page_cursor: None });
        let prompt = AuthorizedRuntimeRequest::SendPrompt(SendPromptRequest {
            conversation_id: ConversationId::new("conversation-authorization-map"),
            idempotency_key: agentdeck_protocol::runtime::IdempotencyKey::new(
                "prompt-authorization-map",
            ),
            expected_configuration_revision: 3,
            prompt: agentdeck_protocol::runtime::PromptPayload::new("fixture")
                .expect("bounded prompt"),
        });
        let resolve = AuthorizedRuntimeRequest::ResolveApproval {
            conversation_id: ConversationId::new("conversation-authorization-map"),
            turn_id: TurnId::new("turn-authorization-map"),
            approval_id: ApprovalId::new("approval-authorization-map"),
            decision: ActionDecision {
                request_id: "request-authorization-map".to_owned(),
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                persist: false,
            },
        };
        let retry = AuthorizedRuntimeRequest::RetryApproval {
            conversation_id: ConversationId::new("conversation-authorization-map"),
            approval_id: ApprovalId::new("approval-authorization-map"),
        };
        let revoke_self = AuthorizedRuntimeRequest::RevokeSelf;

        assert_eq!(
            catalog.required_authorization(),
            (
                AuthorizationCapabilityV1::Catalog,
                AuthorizationPermissionV1::CatalogRead,
            )
        );
        assert!(matches!(
            catalog.into_runtime_request(),
            RuntimeRequest::Catalog(CatalogRequest { page_cursor: None })
        ));
        assert_eq!(
            prompt.required_authorization(),
            (
                AuthorizationCapabilityV1::Prompt,
                AuthorizationPermissionV1::PromptSend,
            )
        );
        assert_eq!(
            resolve.required_authorization(),
            (
                AuthorizationCapabilityV1::Approval,
                AuthorizationPermissionV1::ApprovalResolve,
            )
        );
        assert_eq!(
            retry.required_authorization(),
            (
                AuthorizationCapabilityV1::Approval,
                AuthorizationPermissionV1::ApprovalRetry,
            )
        );
        assert_eq!(
            revoke_self.required_authorization(),
            (
                AuthorizationCapabilityV1::SelfRevocation,
                AuthorizationPermissionV1::RevokeSelf,
            )
        );
        assert!(matches!(
            revoke_self.into_runtime_request(),
            RuntimeRequest::Revoke(RevokeRequest {
                target: RevokeTarget::SelfDevice
            })
        ));
    }

    #[test]
    fn directed_reply_brand_rejects_cross_machine_candidate() {
        let expected = DirectedReplyBrand {
            machine_route: MachineRouteId::from_bytes([0x11; 16]),
            device_route: DeviceRouteId::from_bytes([0x22; 16]),
            key_id: KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: 7,
            },
            key_epoch: 7,
            directory_revision: 4,
        };
        let other_machine = DirectedReplyBrand {
            machine_route: MachineRouteId::from_bytes([0x33; 16]),
            ..expected
        };

        assert!(matches!(
            validate_directed_reply_brand(other_machine, expected),
            Err(PairedPromotionError::Conflict)
        ));
    }

    struct CountingRng {
        fill_calls: usize,
    }

    impl TryRng for CountingRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unreachable!("counter reservation only requests exact bytes")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unreachable!("counter reservation only requests exact bytes")
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            self.fill_calls += 1;
            output.fill(0x5a);
            Ok(())
        }
    }

    impl TryCryptoRng for CountingRng {}

    #[test]
    fn last_counter_block_succeeds_then_epoch_exhaustion_precedes_entropy() {
        let maximum_aligned_high_water = u64::MAX - (u64::MAX % COUNTER_BLOCK_SIZE);
        let last_start = maximum_aligned_high_water - COUNTER_BLOCK_SIZE;
        let mut rng = CountingRng { fill_calls: 0 };

        let last = prepare_command_counter_reservation(last_start, &mut rng).unwrap();
        assert_eq!(last.start(), last_start);
        assert_eq!(last.end_exclusive(), maximum_aligned_high_water);
        assert_eq!(rng.fill_calls, 1);

        let error = prepare_command_counter_reservation(maximum_aligned_high_water, &mut rng)
            .expect_err("the next block cannot be represented in the current key epoch");
        assert_eq!(error.code(), "remote.counter.epoch_retirement_required");
        assert_eq!(
            rng.fill_calls, 1,
            "overflow must fail before RNG and therefore before every durable mutation"
        );
    }

    #[test]
    fn mutable_state_size_gate_accepts_exact_cap_and_rejects_one_more_without_allocating_payloads()
    {
        let bootstrap_len = 1_024;
        let mut replay_lengths = vec![MAX_STATE_FIELD_LEN; 14];
        let used = MUTABLE_STATE_FIXED_ENCODED_LEN
            + bootstrap_len
            + MAX_STATE_FIELD_LEN
            + replay_lengths.len() * (4 + MAX_STATE_FIELD_LEN);
        let exact_tail = MAX_CRYPTO_STATE_PLAINTEXT_LEN - used - 4;
        assert!(exact_tail <= MAX_STATE_FIELD_LEN);
        replay_lengths.push(exact_tail);

        assert_eq!(
            checked_mutable_state_encoded_len(
                bootstrap_len,
                MAX_STATE_FIELD_LEN,
                replay_lengths.iter().copied(),
                [],
            )
            .unwrap(),
            MAX_CRYPTO_STATE_PLAINTEXT_LEN
        );
        *replay_lengths.last_mut().unwrap() += 1;
        assert_eq!(
            checked_mutable_state_encoded_len(
                bootstrap_len,
                MAX_STATE_FIELD_LEN,
                replay_lengths.iter().copied(),
                [],
            )
            .unwrap_err()
            .code(),
            "remote.pairing.paired_invalid"
        );
    }

    #[test]
    fn legacy_stable_and_pending_tags_keep_exact_bytes_while_zero_hwm_stays_invalid() {
        let mut stable = Vec::new();
        stable.extend_from_slice(COUNTER_GUARD_MAGIC);
        stable.extend_from_slice(&MUTABLE_COUNTER_GUARD_VERSION.to_be_bytes());
        stable.extend_from_slice(&[0, 0]);
        stable.extend_from_slice(&[0x11; 32]);
        stable.extend_from_slice(&4_u64.to_be_bytes());
        stable.extend_from_slice(&5_u64.to_be_bytes());
        stable.extend_from_slice(&[0x22; 4]);
        stable.extend_from_slice(&COUNTER_BLOCK_SIZE.to_be_bytes());
        stable.extend_from_slice(&[0x33; 32]);
        assert_eq!(stable.len(), 100);
        assert_eq!(CounterGuardV2::decode(&stable).unwrap().encode(), stable);

        let mut zero_hwm = stable.clone();
        zero_hwm[60..68].fill(0);
        assert_eq!(
            CounterGuardV2::decode(&zero_hwm).unwrap_err().code(),
            "remote.pairing.paired_invalid"
        );

        let mut pending = Vec::new();
        pending.extend_from_slice(COUNTER_GUARD_MAGIC);
        pending.extend_from_slice(&MUTABLE_COUNTER_GUARD_VERSION.to_be_bytes());
        pending.extend_from_slice(&[1, 0]);
        pending.extend_from_slice(&[0x11; 32]);
        pending.extend_from_slice(&4_u64.to_be_bytes());
        pending.extend_from_slice(&5_u64.to_be_bytes());
        pending.extend_from_slice(&[0x22; 4]);
        pending.extend_from_slice(&COUNTER_BLOCK_SIZE.to_be_bytes());
        pending.extend_from_slice(&(COUNTER_BLOCK_SIZE * 2).to_be_bytes());
        pending.extend_from_slice(&[0x44; 16]);
        pending.extend_from_slice(&[0x55; 32]);
        pending.extend_from_slice(&[0x66; 32]);
        assert_eq!(pending.len(), 156);
        assert_eq!(CounterGuardV2::decode(&pending).unwrap().encode(), pending);
    }
}
