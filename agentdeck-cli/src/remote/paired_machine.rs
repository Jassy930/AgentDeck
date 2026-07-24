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
    AeadReceivingKey, AeadSendingKey, CryptoError, HpkePrivateKey, HpkePublicKey, SecretAeadKey,
    SenderCounter, SignatureBytes, SigningKey, VerifyingKey, open_key_directory_entry,
    open_key_update, open_pair_response, open_sealed_payload, seal_key_sync_probe,
    seal_pair_response_received, seal_symmetric, sha256, sign_authentication_transcript,
    sign_revocation_cleanup_journal_digest, sign_sealed, verify_revocation_cleanup_journal_digest,
    verify_sealed, verify_tbs,
};
use agentdeck_protocol::ActionDecision;
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, DeviceAuthorizationV1,
    E2EE_FORMAT_VERSION, E2eeError, EpochBarrierV1, KeyControlRequestV1, KeyControlV1,
    KeyDirectoryV1, KeyId, KeyPurpose, KeySyncRequestV1, KeyUpdateAckV1, KeyUpdateInfoV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairResponseReceivedV1,
    PairResponseV1, PairingControlEnvelopeV1, PairingError, SealedPayloadKind, SealedPayloadV1,
    SignedSealedBlobV1, StreamAppliedAckV1, StreamBindingV1, VerifiedSealedBlobV1,
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
use agentdeck_protocol::runtime::identity::{ApprovalId, MessageId, TransferId, TurnId};
use agentdeck_protocol::runtime::{
    ConversationId, MachineRootFingerprint, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope,
    RuntimeInnerCursor, RuntimeMessage, RuntimeRequest, RuntimeTransferCarrierV1,
    SendPromptRequest,
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
    FileCryptoStateStore, MAX_CRYPTO_STATE_PLAINTEXT_LEN, PreparedCryptoStateCapacityMode,
    PreparedCryptoStateStage, revocation_cleanup_entries_absent_in,
};
use super::device_lock::{RemoteDeviceLease, RemoteDeviceLockError, RemoteDeviceLockKey};
use super::key_generation::{
    DurableKeyCarrierV1, DurableKeyGenerationStateV1, DurableKeyGenerationV1,
    SharedUpdateMetadataKindV1, stage_normal_update_set, validate_directed_rewrap_metadata,
    validate_normal_update_transition,
};
use super::key_sync::{
    DurableKeySyncStateV1, KeySyncUpdateSetHandoff, KeyUpdateAckBasisV1,
    SignedHigherRevisionObservationV1,
};
use super::keychain::{
    PairedRemoteKeyPurpose, ParsedPairedRemoteKeyAccount, PendingRemoteKeyPurpose,
    RemoteKeyAccount, RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use super::pending::{PendingInvitePublicProjection, VerifiedPendingPairResponse};
use super::stream_state::{
    DURABLE_STREAM_REPLAY_TUPLE_V4_BYTES, DurableStreamBindingV1,
    EMERGENCY_REPLAY_DEBT_METADATA_BYTES, MAX_DURABLE_STREAM_BINDINGS, StreamPublishDisposition,
    decode_stream_bindings, encode_stream_bindings,
};
use super::transfer_state::{
    DurableLiveTransferStateV1, DurableTransferBindingIdentityV1, DurableTransferBootstrapError,
    DurableTransferOutcomeV1, DurableTransferTransitionV1, MAX_DURABLE_TRANSFER_RECORDS,
    MAX_NEEDS_BOOTSTRAP_MARKER_RECORD_BYTES, bootstrap_error_for_exact_binding_records,
    bootstrap_marker_credit_bytes_records, has_emergency_marker_cardinality_reserve,
};

const STATE_MAGIC: &[u8; 4] = b"ADPS";
const STATE_VERSION: u16 = 1;
const MUTABLE_STATE_VERSION: u16 = 2;
const TYPED_RUNTIME_STATE_VERSION: u16 = 3;
const KEY_SYNC_STATE_VERSION: u16 = 4;
const KEY_GENERATION_STATE_VERSION: u16 = 5;
const TRANSFER_STATE_VERSION: u16 = 6;
const STATE_HEADER_LEN: usize = 12;
const MAX_STATE_FIELD_LEN: usize = 8 * 1024 * 1024;
const MAX_STATE_STRING_LEN: usize = 8 * 1024;
const MAX_STATE_COLLECTION_ITEMS: usize = 4_096;
const MUTABLE_STATE_FIXED_ENCODED_LEN: usize = STATE_HEADER_LEN + 64 + 4 + 4 + 36 + 2 + 2;
const AUTOMATIC_RUNTIME_STATE_PROBE_DOMAIN: &[u8] = b"AgentDeck/AutomaticRuntimeStateProbeV1\0";
const MAX_MUTABLE_AUDIT_ATTEMPTS: usize = 3;

const fn checked_capacity_add(left: usize, right: usize) -> usize {
    match left.checked_add(right) {
        Some(value) => value,
        None => panic!("paired-state capacity arithmetic overflow"),
    }
}

const fn checked_capacity_sub(left: usize, right: usize) -> usize {
    match left.checked_sub(right) {
        Some(value) => value,
        None => panic!("paired-state emergency headroom exceeds hard capacity"),
    }
}

const fn checked_capacity_mul(left: usize, right: usize) -> usize {
    match left.checked_mul(right) {
        Some(value) => value,
        None => panic!("paired-state capacity multiplication overflow"),
    }
}

/// 每个 installed binding 最多消费一次 authenticated replay admission 与一个 terminal
/// marker。两个 4-byte 项分别保守覆盖变长 stream field 与新增 transfer record 的
/// collection framing；实际 replay tuple 为 fixed width。
const V6_EMERGENCY_BINDING_HEADROOM: usize = checked_capacity_add(
    checked_capacity_add(
        checked_capacity_add(4, DURABLE_STREAM_REPLAY_TUPLE_V4_BYTES),
        EMERGENCY_REPLAY_DEBT_METADATA_BYTES,
    ),
    checked_capacity_add(4, MAX_NEEDS_BOOTSTRAP_MARKER_RECORD_BYTES),
);
/// 普通 V6 mutation 为完整 durable binding collection 聚合预留 emergency 空间。一个
/// binding 落 marker 后会被 ingress fence，不能再次消费；因此 4096 倍是闭合上界。
const V6_EMERGENCY_HEADROOM: usize =
    checked_capacity_mul(V6_EMERGENCY_BINDING_HEADROOM, MAX_DURABLE_STREAM_BINDINGS);
const V6_NORMAL_STATE_PLAINTEXT_LIMIT: usize =
    checked_capacity_sub(MAX_CRYPTO_STATE_PLAINTEXT_LEN, V6_EMERGENCY_HEADROOM);

fn v6_exact_emergency_credit_bytes(
    stream_cursors: &[Vec<u8>],
    transfer_records: &[Vec<u8>],
) -> Result<usize, PairedPromotionError> {
    let stream_credit = decode_stream_bindings(stream_cursors)
        .map_err(|_| PairedPromotionError::InvalidState)?
        .into_iter()
        .try_fold(0_usize, |credit, binding| {
            credit
                .checked_add(binding.emergency_replay_debt_credit_bytes())
                .ok_or(PairedPromotionError::InvalidState)
        })?;
    let marker_credit = bootstrap_marker_credit_bytes_records(transfer_records)
        .map_err(|_| PairedPromotionError::InvalidState)?;
    stream_credit
        .checked_add(marker_credit)
        .filter(|credit| *credit <= V6_EMERGENCY_HEADROOM)
        .ok_or(PairedPromotionError::InvalidState)
}

fn v6_base_plaintext_usage(
    encoded_len: usize,
    emergency_credit: usize,
) -> Result<usize, PairedPromotionError> {
    encoded_len
        .checked_sub(emergency_credit)
        .ok_or(PairedPromotionError::InvalidState)
}

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

/// Production 普通 V6 mutation 的 plaintext budget。真实 128 MiB hard cap 顶部固定保留
/// [`V6_EMERGENCY_HEADROOM`]；lowered value 只供一个默认 integration test 在小内存规模
/// 驱动同一 Production authority 路径，不持久化、不进入 CLI/env/config。Emergency marker
/// 不使用该可降低预算，只能通过 private typed fallback 使用真实 hard cap。
#[derive(Clone, Copy, Eq, PartialEq)]
struct LiveTransferCandidateCapacity {
    plaintext_limit: usize,
}

impl LiveTransferCandidateCapacity {
    const PRODUCTION: Self = Self {
        plaintext_limit: V6_NORMAL_STATE_PLAINTEXT_LIMIT,
    };

    #[cfg(debug_assertions)]
    fn lowered_for_automatic_harness(plaintext_limit: usize) -> Result<Self, PairedPromotionError> {
        if plaintext_limit == 0 || plaintext_limit >= V6_NORMAL_STATE_PLAINTEXT_LIMIT {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(Self { plaintext_limit })
    }

    fn validate_normal(self, encoded_len: usize) -> Result<(), PairedPromotionError> {
        if encoded_len > self.plaintext_limit {
            return Err(PairedPromotionError::StateCapacity);
        }
        Ok(())
    }
}

type V6StateCapacityMode = PreparedCryptoStateCapacityMode;

fn validate_v6_encoded_capacity_with_context(
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
    encoded_len: usize,
    stream_cursors: &[Vec<u8>],
    transfer_records: &[Vec<u8>],
) -> Result<(), PairedPromotionError> {
    if encoded_len > MAX_CRYPTO_STATE_PLAINTEXT_LEN {
        return Err(PairedPromotionError::StateCapacity);
    }
    if runtime_state_mutation_authority == RuntimeStateMutationAuthority::Production {
        let emergency_credit = v6_exact_emergency_credit_bytes(stream_cursors, transfer_records)?;
        let base_usage = v6_base_plaintext_usage(encoded_len, emergency_credit)?;
        live_transfer_candidate_capacity.validate_normal(base_usage)?;
    }
    Ok(())
}

fn validate_v6_transfer_cardinality_reserve_with_context(
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    records: &[Vec<u8>],
    mode: V6StateCapacityMode,
) -> Result<(), PairedPromotionError> {
    if mode == V6StateCapacityMode::Normal
        && runtime_state_mutation_authority == RuntimeStateMutationAuthority::Production
        && !has_emergency_marker_cardinality_reserve(records)
            .map_err(|_| PairedPromotionError::InvalidState)?
    {
        return Err(PairedPromotionError::StateCapacity);
    }
    Ok(())
}

fn validate_equivalent_v6_normal_capacity_with_context(
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
    state: &PairedCryptoState,
) -> Result<(), PairedPromotionError> {
    let transfer_records = state.shared_durable_transfer_records();
    let stream_cursors = state.durable_stream_binding_bytes();
    let encoded_len = state.validate_current_v6_stream_transfer_capacity(
        stream_cursors,
        transfer_records.as_slice(),
    )?;
    validate_v6_encoded_capacity_with_context(
        runtime_state_mutation_authority,
        live_transfer_candidate_capacity,
        encoded_len,
        stream_cursors,
        transfer_records.as_slice(),
    )?;
    validate_v6_transfer_cardinality_reserve_with_context(
        runtime_state_mutation_authority,
        transfer_records.as_slice(),
        V6StateCapacityMode::Normal,
    )
}

fn validate_state_candidate_capacity_with_context(
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
    state: &PairedCryptoState,
    encoded_len: usize,
    mode: V6StateCapacityMode,
) -> Result<(), PairedPromotionError> {
    if mode == V6StateCapacityMode::Normal {
        return validate_equivalent_v6_normal_capacity_with_context(
            runtime_state_mutation_authority,
            live_transfer_candidate_capacity,
            state,
        );
    }
    let PairedCryptoState::V6(value) = state else {
        return Err(PairedPromotionError::InvalidState);
    };
    validate_v6_encoded_capacity_with_context(
        runtime_state_mutation_authority,
        live_transfer_candidate_capacity,
        encoded_len,
        &value.stream_cursors,
        value.durable_transfer_records.as_slice(),
    )?;
    validate_v6_transfer_cardinality_reserve_with_context(
        runtime_state_mutation_authority,
        value.durable_transfer_records.as_slice(),
        mode,
    )
}

/// V6 durable transfer records 的 immutable shared owner。公开读取只返回 immutable
/// slice；所有真实 replacement 都必须通过 `from_owned` 建立新 allocation，禁止
/// `Arc::make_mut`、mutable slice 或其他 copy-on-write 入口。最后一个 owner 释放时逐 record
/// 清零明文字节。
#[derive(Clone)]
struct SharedTransferRecords(Arc<TransferRecordOwner>);

struct TransferRecordOwner(Vec<Vec<u8>>);

impl Drop for TransferRecordOwner {
    fn drop(&mut self) {
        for record in &mut self.0 {
            record.zeroize();
        }
    }
}

impl SharedTransferRecords {
    fn from_owned(records: Vec<Vec<u8>>) -> Self {
        Self(Arc::new(TransferRecordOwner(records)))
    }

    fn empty() -> Self {
        Self::from_owned(Vec::new())
    }

    fn as_slice(&self) -> &[Vec<u8>] {
        &self.0.0
    }

    fn iter(&self) -> std::slice::Iter<'_, Vec<u8>> {
        self.as_slice().iter()
    }

    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    #[cfg(test)]
    fn shares_allocation_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl PartialEq for SharedTransferRecords {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for SharedTransferRecords {}

/// runtime transport 可读写的 bounded opaque state 投影；不包含 KEK、traffic key 或 raw
/// paired state。`exchange` 对应单一 terminal exchange blob，另外两项保持 canonical 顺序。
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct OpaqueRuntimeState {
    exchange: Option<Vec<u8>>,
    replay_windows: Vec<Vec<u8>>,
    stream_cursors: Vec<Vec<u8>>,
    transfer_records: SharedTransferRecords,
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
        transfer_records: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            exchange,
            replay_windows,
            stream_cursors,
            transfer_records: SharedTransferRecords::from_owned(transfer_records),
        }
    }

    fn new_preserving_transfer_records(
        exchange: Option<Vec<u8>>,
        replay_windows: Vec<Vec<u8>>,
        stream_cursors: Vec<Vec<u8>>,
        transfer_records: SharedTransferRecords,
    ) -> Self {
        Self {
            exchange,
            replay_windows,
            stream_cursors,
            transfer_records,
        }
    }

    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            exchange: None,
            replay_windows: Vec::new(),
            stream_cursors: Vec::new(),
            transfer_records: SharedTransferRecords::empty(),
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
            || self.transfer_records.len() > MAX_DURABLE_TRANSFER_RECORDS
            || self
                .replay_windows
                .iter()
                .chain(&self.stream_cursors)
                .chain(self.transfer_records.iter())
                .any(|entry| entry.is_empty() || entry.len() > MAX_STATE_FIELD_LEN)
        {
            return Err(PairedPromotionError::InvalidState);
        }
        checked_mutable_state_encoded_len(
            0,
            self.exchange.as_ref().map_or(0, Vec::len),
            self.replay_windows.iter().map(Vec::len),
            self.stream_cursors.iter().map(Vec::len),
            self.transfer_records.iter().map(Vec::len),
        )?;
        Ok(())
    }

    fn from_automatic_probe(probe: AutomaticRuntimeStateProbe) -> Self {
        let encoded = probe.encoded();
        Self {
            exchange: Some(encoded.clone()),
            replay_windows: vec![encoded],
            stream_cursors: Vec::new(),
            transfer_records: SharedTransferRecords::empty(),
        }
    }

    fn from_automatic_legacy_v2_probe(probe: AutomaticRuntimeStateProbe) -> Self {
        let encoded = probe.encoded();
        Self {
            exchange: Some(encoded.clone()),
            replay_windows: vec![encoded],
            stream_cursors: Vec::new(),
            transfer_records: SharedTransferRecords::empty(),
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
/// 探针只占用 exchange 与单条 replay window，使用与 production codec 不相交的 domain，
/// 不能伪造 daemon receipt、replay admission、stream cursor 或 transfer record。production
/// CLI 不构造该类型，也不存在参数、环境变量或配置入口。
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

/// 仅供 automatic integration harness 表达 directed runtime 的三轴 CAS 投影。
///
/// exchange/replay 使用与 production codec 不相交的 probe domain；stream binding 则继续
/// 使用 production canonical encoder。该类型不含 transfer records，避免测试入口本身
/// 获得覆盖 durable transfer collection 的能力。
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomaticRuntimeProjection {
    exchange: Option<AutomaticRuntimeStateProbe>,
    replay_window: Option<AutomaticRuntimeStateProbe>,
    stream_bindings: Vec<DurableStreamBindingV1>,
}

impl AutomaticRuntimeProjection {
    #[must_use]
    pub fn new(
        exchange: Option<AutomaticRuntimeStateProbe>,
        replay_window: Option<AutomaticRuntimeStateProbe>,
        stream_bindings: Vec<DurableStreamBindingV1>,
    ) -> Self {
        Self {
            exchange,
            replay_window,
            stream_bindings,
        }
    }

    fn to_opaque_runtime_state(&self) -> Result<OpaqueRuntimeState, PairedPromotionError> {
        Ok(OpaqueRuntimeState::new(
            self.exchange.map(AutomaticRuntimeStateProbe::encoded),
            self.replay_window
                .map(AutomaticRuntimeStateProbe::encoded)
                .into_iter()
                .collect(),
            encode_stream_bindings(self.stream_bindings.clone())
                .map_err(|_| PairedPromotionError::InvalidState)?,
            Vec::new(),
        ))
    }

    fn from_opaque_runtime_state(
        runtime: &OpaqueRuntimeState,
    ) -> Result<Self, PairedPromotionError> {
        let exchange = runtime
            .exchange()
            .map(AutomaticRuntimeStateProbe::decode)
            .transpose()?;
        let replay_window = match runtime.replay_windows() {
            [] => None,
            [encoded] => Some(AutomaticRuntimeStateProbe::decode(encoded)?),
            _ => return Err(PairedPromotionError::InvalidState),
        };
        let stream_bindings = decode_stream_bindings(runtime.stream_cursors())
            .map_err(|_| PairedPromotionError::InvalidState)?;
        Ok(Self {
            exchange,
            replay_window,
            stream_bindings,
        })
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
    #[error("paired promotion candidate exceeds the sealed state capacity")]
    StateCapacity,
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
            Self::StateCapacity => "remote.pairing.paired_capacity",
            Self::RevokedCleanupPending => "remote.pairing.revoked_cleanup_pending",
        }
    }
}

/// 已完成全部 signature/HPKE/raw relation/roster/binding 校验、等待单次 ADPS CAS 的
/// normal UpdateSet candidate。字段保持私有，调用方不能拼出 generation-only 或 ADKS-only
/// 半安装状态；`Debug` 永远不输出 paired-state plaintext。
pub struct PreparedKeyUpdateInstall {
    expected_state_bytes: Vec<u8>,
    candidate_state_bytes: Vec<u8>,
    candidate_generation_bytes: Vec<u8>,
    candidate_key_sync_bytes: Vec<u8>,
    candidate_stream_binding_bytes: Vec<Vec<u8>>,
    expected_ack_basis: KeyUpdateAckBasisV1,
}

impl fmt::Debug for PreparedKeyUpdateInstall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedKeyUpdateInstall([REDACTED])")
    }
}

/// combined CAS 完整 durable readback 后铸造的 ACK capability。它证明 ADKG、ADKS 与
/// installed binding collection 来自同一 paired-state snapshot；Relay RouteAccepted 不会
/// 产生该值。
pub struct CommittedKeyUpdateInstall {
    key_sync_state: DurableKeySyncStateV1,
    ack_basis: KeyUpdateAckBasisV1,
    ack: KeyUpdateAckV1,
    already_committed: bool,
}

impl fmt::Debug for CommittedKeyUpdateInstall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedKeyUpdateInstall([REDACTED])")
    }
}

impl CommittedKeyUpdateInstall {
    #[must_use]
    pub const fn key_sync_state(&self) -> &DurableKeySyncStateV1 {
        &self.key_sync_state
    }

    #[must_use]
    pub const fn ack_basis(&self) -> KeyUpdateAckBasisV1 {
        self.ack_basis
    }

    #[must_use]
    pub const fn ack(&self) -> &KeyUpdateAckV1 {
        &self.ack
    }

    #[must_use]
    pub const fn already_committed(&self) -> bool {
        self.already_committed
    }
}

/// 已完成 staged-key signature/AAD、durable replay admission、AEAD 与 canonical
/// EpochBarrier 逐轴校验，等待单次 ADPS CAS 的私有 activation capability。
///
/// expected/candidate 都是完整 paired-state plaintext；调用方不能拆开提交 ADKG、
/// stream binding 或 receipt basis。`Debug` 永不输出密钥、barrier 或 state bytes。
pub(crate) struct PreparedEpochBarrierActivation {
    expected_state_bytes: Vec<u8>,
    candidate_state_bytes: Vec<u8>,
    candidate_generation_bytes: Vec<u8>,
    candidate_stream_binding_bytes: Vec<Vec<u8>>,
    expected_stream_route: StreamRouteId,
    expected_stream_generation: StreamGenerationId,
    expected_ack: StreamAppliedAckV1,
}

impl fmt::Debug for PreparedEpochBarrierActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedEpochBarrierActivation([REDACTED])")
    }
}

/// combined activation 完整 durable readback 后铸造的 receipt capability。该值只证明
/// 本地 staged→current、stream cut/replay 与 ACK basis 已一起 COMMIT；Relay 的
/// RouteAccepted 仍只是 transport state。
pub(crate) struct CommittedEpochBarrierActivation {
    stream_binding: DurableStreamBindingV1,
    ack: StreamAppliedAckV1,
    already_committed: bool,
}

impl fmt::Debug for CommittedEpochBarrierActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedEpochBarrierActivation([REDACTED])")
    }
}

impl CommittedEpochBarrierActivation {
    #[must_use]
    pub(crate) const fn stream_binding(&self) -> &DurableStreamBindingV1 {
        &self.stream_binding
    }

    #[must_use]
    pub(crate) const fn ack(&self) -> &StreamAppliedAckV1 {
        &self.ack
    }

    #[must_use]
    pub(crate) const fn already_committed(&self) -> bool {
        self.already_committed
    }
}

/// 从当前 audited paired snapshot 加载并消费 owned semantic transfer state 后铸造的
/// production-only capability。完整 expected snapshot 由 `Arc` 零复制持有；runtime 只能
/// 查看逻辑 outcome，不能替换 expected snapshot、candidate records 或 CAS target。
pub(crate) struct PendingStreamTransferTransition {
    expected_state_snapshot: Arc<CryptoStateSnapshot>,
    expected_binding: DurableStreamBindingV1,
    transition: DurableTransferTransitionV1,
}

impl fmt::Debug for PendingStreamTransferTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingStreamTransferTransition([REDACTED])")
    }
}

impl PendingStreamTransferTransition {
    pub(crate) fn take_outcome(&mut self) -> DurableTransferOutcomeV1 {
        self.transition.take_outcome()
    }

    #[must_use]
    pub(crate) const fn bootstrap_error(&self) -> Option<DurableTransferBootstrapError> {
        match self.transition.outcome() {
            DurableTransferOutcomeV1::NeedsBootstrap { error } => Some(*error),
            DurableTransferOutcomeV1::Buffered { .. }
            | DurableTransferOutcomeV1::AlreadyComplete
            | DurableTransferOutcomeV1::Complete { .. } => None,
        }
    }
}

/// 已把 canonical transfer records 按值移入完整 V6 candidate 的私有 prepared token。
/// expected/candidate 都持有 exact paired plaintext snapshot；commit/recovery 只做逐字节
/// expected-or-candidate 判定，不以 transfer semantic hash 代替 full-state CAS。
struct PreparedStreamTransferTransition {
    expected_state_snapshot: Arc<CryptoStateSnapshot>,
    candidate_state_snapshot: Arc<CryptoStateSnapshot>,
    candidate_state: Option<PairedCryptoState>,
    expected_binding: DurableStreamBindingV1,
    replacement_binding: DurableStreamBindingV1,
}

impl fmt::Debug for PreparedStreamTransferTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedStreamTransferTransition([REDACTED])")
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
    key_directory_revision: KeyDirectoryRevision,
    material: OpenedPairedKeyMaterial,
}

#[derive(Clone, Copy)]
struct StreamBindingAuditContext {
    identity: PairedMachineIdentity,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    trust_epoch: TrustEpoch,
    bootstrap_directory_revision: KeyDirectoryRevision,
    effective_directory_revision: KeyDirectoryRevision,
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
                && entry.key_directory_revision == binding.key_directory_revision
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
    prepared_opened_keys: Option<&[OpenedPairedDirectoryKey]>,
) -> Result<(), PairedPromotionError> {
    let mut active_context = context;
    active_context.effective_directory_revision = state.effective_directory_revision()?;
    validate_typed_stream_state(state, active_context, authorization, opened_keys)?;
    validate_key_sync_state_against_audit(state, active_context)?;
    if let Some(prepared) = prepared_stage {
        let next = PairedCryptoState::decode(prepared.snapshot().expose_secret())?;
        let mut next_context = context;
        next_context.effective_directory_revision = next.effective_directory_revision()?;
        validate_typed_stream_state(
            &next,
            next_context,
            authorization,
            prepared_opened_keys.unwrap_or(opened_keys),
        )?;
        validate_key_sync_state_against_audit(&next, next_context)?;
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
    let generation = state.durable_key_generation_state()?;
    for binding in bindings {
        validate_stream_binding_against_audit(
            binding.binding(),
            context,
            authorization,
            opened_keys,
        )?;
        if binding.pending_epoch_barrier().is_some() {
            validate_pending_epoch_barrier_against_generation(
                &binding,
                generation.as_ref().ok_or(PairedPromotionError::Conflict)?,
            )?;
        }
    }
    Ok(())
}

/// Cold open 必须把已经 durable admission 的 future-key replay tuple 与 ADKG 的唯一
/// shared staged slot 逐轴交叉认证。该约束只从 pending 指向 staged；正常 UpdateSet 在
/// barrier 到达前允许 staged slot 尚无 pending carrier。
fn validate_pending_epoch_barrier_against_generation(
    binding: &DurableStreamBindingV1,
    generation: &DurableKeyGenerationStateV1,
) -> Result<(), PairedPromotionError> {
    let pending = binding
        .pending_epoch_barrier()
        .ok_or(PairedPromotionError::Conflict)?;
    let tuple = pending.replay_tuple();
    let current = binding.binding();
    let slot_route = stream_key_slot_route(current.key_id, current.stream_route)?;
    let slot = generation
        .find_slot(current.key_id.purpose, slot_route)
        .ok_or(PairedPromotionError::Conflict)?;
    let staged = slot.staged().ok_or(PairedPromotionError::Conflict)?;
    if generation.effective_directory_revision() != tuple.key_directory_revision()
        || slot.current().key_id() != current.key_id
        || slot.current().key_directory_revision() != current.key_directory_revision
        || slot.current().stream_route() != slot_route
        || tuple.key_id().purpose != current.key_id.purpose
        || tuple.stream_route() != current.stream_route
        || tuple.stream_generation() != current.stream_generation
        || staged.key_id() != tuple.key_id()
        || staged.key_directory_revision() != tuple.key_directory_revision()
        || staged.stream_route() != slot_route
    {
        return Err(PairedPromotionError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod pending_epoch_barrier_audit_tests {
    use super::*;
    use crate::remote::key_generation::{DurableKeySlotV1, KeySlotIdentityV1};
    use agentdeck_protocol::e2ee::KeyUpdateV1;
    use agentdeck_protocol::runtime::StreamCursor;

    const ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x41; 16]);
    const GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x42; 16]);
    const DEVICE: DeviceRouteId = DeviceRouteId::from_bytes([0x43; 16]);

    fn pending_catalog() -> DurableStreamBindingV1 {
        let binding = StreamBindingV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: MachineRouteId::from_bytes([0x44; 16]),
            device_route: DEVICE,
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
            stream_route: ROUTE,
            stream_generation: GENERATION,
            stream_cursor: StreamCursor::BeforeFirst,
            inner_cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
            key_directory_revision: KeyDirectoryRevision::new(4),
            key_id: KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 3,
            },
        };
        DurableStreamBindingV1::from_stream_binding(binding)
            .expect("valid catalog binding")
            .admit_pending_epoch_barrier(
                KeyId {
                    purpose: KeyPurpose::Catalog,
                    epoch: 4,
                },
                KeyDirectoryRevision::new(5),
                0,
                9,
                [0x45; 32],
            )
            .expect("valid pending barrier")
            .0
    }

    fn update_generation(
        purpose: KeyPurpose,
        revision: u64,
        epoch: u64,
        seed: u8,
    ) -> DurableKeyGenerationV1 {
        DurableKeyGenerationV1::from_update(KeyUpdateV1 {
            key_directory_revision: KeyDirectoryRevision::new(revision),
            key_id: KeyId { purpose, epoch },
            device_route: DEVICE,
            stream_route: None,
            enc: vec![seed; 32],
            wrapped_key: vec![seed.wrapping_add(1); 48],
            signature: Ed25519Signature([seed.wrapping_add(2); 64]),
        })
        .expect("valid staged generation")
    }

    fn generation(
        staged: Option<DurableKeyGenerationV1>,
        effective: u64,
    ) -> DurableKeyGenerationStateV1 {
        let current = DurableKeyGenerationV1::from_bootstrap_entry(
            KeyDirectoryRevision::new(4),
            KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 3,
            },
            None,
            DEVICE,
        )
        .expect("valid current generation");
        DurableKeyGenerationStateV1::new(
            KeyDirectoryRevision::new(4),
            KeyDirectoryRevision::new(effective),
            vec![
                DurableKeySlotV1::new(
                    KeySlotIdentityV1::new(KeyPurpose::Catalog, None).expect("catalog slot"),
                    current,
                    staged,
                    Vec::new(),
                )
                .expect("valid key slot"),
                DurableKeySlotV1::new(
                    KeySlotIdentityV1::new(KeyPurpose::DeviceCommandTx, None)
                        .expect("command slot"),
                    update_generation(KeyPurpose::DeviceCommandTx, effective, 5, 0x51),
                    None,
                    Vec::new(),
                )
                .expect("valid command slot"),
                DurableKeySlotV1::new(
                    KeySlotIdentityV1::new(KeyPurpose::DeviceReplyTx, None).expect("reply slot"),
                    update_generation(KeyPurpose::DeviceReplyTx, effective, 7, 0x61),
                    None,
                    Vec::new(),
                )
                .expect("valid reply slot"),
            ],
        )
        .expect("valid generation state")
    }

    #[test]
    fn pending_epoch_barrier_requires_the_exact_staged_generation_axes() {
        let binding = pending_catalog();
        let exact = generation(Some(update_generation(KeyPurpose::Catalog, 5, 4, 0x41)), 5);
        validate_pending_epoch_barrier_against_generation(&binding, &exact)
            .expect("exact staged generation matches pending tuple");

        for drifted in [
            generation(None, 5),
            generation(Some(update_generation(KeyPurpose::Catalog, 5, 5, 0x42)), 5),
            generation(Some(update_generation(KeyPurpose::Catalog, 6, 4, 0x43)), 6),
        ] {
            assert!(matches!(
                validate_pending_epoch_barrier_against_generation(&binding, &drifted),
                Err(PairedPromotionError::Conflict)
            ));
        }
    }
}

/// ADKS 必须绑定当前 paired authority、已安装 revision 与 exact live publication slot。
/// V5-A equality audit 只接受 steady state；install intermediate 必须由 V5-B combined CAS
/// 扩展，禁止在 generation-only seam 放宽。
fn validate_key_sync_state_against_audit(
    state: &PairedCryptoState,
    context: StreamBindingAuditContext,
) -> Result<(), PairedPromotionError> {
    let Some(key_sync) = state.durable_key_sync_state()? else {
        return Ok(());
    };
    let observation = key_sync.observation();
    if context.effective_directory_revision < context.bootstrap_directory_revision
        || observation.machine_route() != context.identity.machine_route
        || observation.device_route() != context.device_route
        || observation.grant_serial() != context.grant_serial
        || observation.root_trust_epoch() != context.trust_epoch
        || key_sync.current_known_key_directory_revision() != context.effective_directory_revision
    {
        return Err(PairedPromotionError::Conflict);
    }

    let current_known = key_sync.current_known_key_directory_revision();
    let binding_revision = if current_known == observation.known_key_directory_revision() {
        // 新 cycle Active 状态没有本轮 completion；其 latest basis 来自上一轮 Resolved
        // 状态的 retained ACK。即使 observation/current 已相等，也必须把 retained
        // revision/hash 与当前 ADKG staged set 交叉认证，不能等到实际重封 ACK 才发现漂移。
        if let Some(retained) = key_sync.latest_completed_ack_basis() {
            let generation = state
                .durable_key_generation_state()?
                .ok_or(PairedPromotionError::Conflict)?;
            let installed_set = generation
                .staged_normal_update_set()
                .map_err(|_| PairedPromotionError::Conflict)?;
            if retained.key_directory_revision() != current_known
                || retained.key_directory_revision() != generation.effective_directory_revision()
                || installed_set
                    .canonical_sha256()
                    .map_err(PairedPromotionError::Protocol)?
                    != retained.update_set_sha256()
            {
                return Err(PairedPromotionError::Conflict);
            }
        }
        current_known
    } else {
        let completed = key_sync
            .latest_completed_ack_basis()
            .ok_or(PairedPromotionError::Conflict)?;
        let generation = state
            .durable_key_generation_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        let installed_set = generation
            .staged_normal_update_set()
            .map_err(|_| PairedPromotionError::Conflict)?;
        if completed.key_directory_revision() != current_known
            || completed.key_directory_revision() != generation.effective_directory_revision()
            || installed_set
                .canonical_sha256()
                .map_err(PairedPromotionError::Protocol)?
                != completed.update_set_sha256()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let slot_route = observation.key_slot_stream_route();
        let observed_update = installed_set
            .updates
            .iter()
            .find(|update| {
                update.key_id.purpose == observation.observed_key_id().purpose
                    && update.stream_route == slot_route
            })
            .ok_or(PairedPromotionError::Conflict)?;
        if observed_update.key_id != observation.observed_key_id() {
            return Err(PairedPromotionError::Conflict);
        }
        let current = generation
            .find_slot(observation.observed_key_id().purpose, slot_route)
            .ok_or(PairedPromotionError::Conflict)?
            .current();
        current.key_directory_revision()
    };

    let bindings = state.durable_stream_bindings()?;
    // V1/V2 legacy state 没有 typed publication inventory；首次 V4 migration 仍可由
    // marker/directory 的硬 authority 轴授权。只要 inventory 已存在，就必须 exact 命中，
    // 不允许用另一路 route/generation 或 purpose/slot 注入 canonical ADKS。
    if bindings.is_empty() {
        return if current_known == observation.known_key_directory_revision() {
            Ok(())
        } else {
            Err(PairedPromotionError::Conflict)
        };
    }
    let matching_publications = bindings
        .into_iter()
        .filter(|durable| {
            let binding = durable.binding();
            binding.stream_route == observation.publication_stream_route()
                && binding.stream_generation == observation.publication_stream_generation()
                && binding.key_directory_revision == binding_revision
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
    bootstrap_directory_revision: KeyDirectoryRevision,
    effective_directory_revision: KeyDirectoryRevision,
    relay_server_id: RelayServerId,
    current_spki_pin: [u8; 32],
    next_spki_pin: [u8; 32],
    state_store: FileCryptoStateStore,
    state_snapshot: Arc<CryptoStateSnapshot>,
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
    machine_data_signer_binding: MachineDataSignerBindingV1,
    device_hpke_private_key: HpkePrivateKey,
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
    replay_revision_ceiling: u64,
    counter: u64,
    signed_blob_hash: [u8; 32],
}

/// 已完成 canonical Relay outer、durable route/generation 与 MachineDataSign/AAD 验证的
/// stream proof。当前 revision 携带普通 live token；与 ADKG 唯一 staged shared slot
/// 精确匹配的 next revision/new epoch 只携带 EpochBarrier admission token；其余未知更高
/// revision 只能触发 bounded KeySync，绝不伪装成可解密 publication。
pub(crate) enum VerifiedStreamPublish {
    Current(Box<VerifiedCurrentStreamPublish>),
    StagedEpochBarrier(Box<VerifiedStagedEpochBarrierPublish>),
    CommittedEpochBarrierDuplicate(Box<VerifiedCurrentStreamPublish>),
    Higher(Box<VerifiedHigherStreamPublish>),
}

pub(crate) struct VerifiedCurrentStreamPublish {
    verified: VerifiedSealedBlobV1,
    context: OuterContextV1,
    brand: StreamPublishBrand,
    header_directory_revision: u64,
    stream_seq: u64,
    counter: u64,
    ciphertext_sha256: [u8; 32],
}

pub(crate) struct VerifiedHigherStreamPublish {
    observation: SignedHigherRevisionObservationV1,
}

/// 仅证明 outer/signature/AAD/header 已绑定唯一 staged shared generation；AEAD 必须等
/// staged replay tuple durable admission 后才能消费。字段私有，不能由 runtime 拼造。
pub(crate) struct VerifiedStagedEpochBarrierPublish {
    verified: VerifiedSealedBlobV1,
    context: OuterContextV1,
    brand: StreamPublishBrand,
    stream_seq: u64,
    counter: u64,
    ciphertext_sha256: [u8; 32],
}

/// staged replay 已 durable、AEAD/canonical control 与本地 C/H/epoch/revision 全部精确
/// 对账后的 activation proof。它仍不代表 paired-state activation 已提交。
pub(crate) struct VerifiedEpochBarrierActivation {
    durable: DurableStreamBindingV1,
    stream_route: StreamRouteId,
    barrier: EpochBarrierV1,
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
    pub(crate) const fn replay_revision_ceiling(&self) -> u64 {
        self.replay_revision_ceiling
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

    #[must_use]
    pub(crate) const fn header_directory_revision(&self) -> KeyDirectoryRevision {
        KeyDirectoryRevision::new(self.header_directory_revision)
    }
}

impl VerifiedHigherStreamPublish {
    #[must_use]
    pub(crate) fn into_observation(self) -> SignedHigherRevisionObservationV1 {
        self.observation
    }
}

impl VerifiedStagedEpochBarrierPublish {
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

    #[must_use]
    pub(crate) const fn key_id(&self) -> KeyId {
        self.brand.key_id
    }

    #[must_use]
    pub(crate) const fn key_directory_revision(&self) -> KeyDirectoryRevision {
        KeyDirectoryRevision::new(self.brand.directory_revision)
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
        live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
        lease: RemoteDeviceLease,
    ) -> OpenedPairedMachine<'a> {
        OpenedPairedMachine {
            audited: self,
            store,
            mutation_observer,
            runtime_state_mutation_authority,
            live_transfer_candidate_capacity,
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
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
    // 必须最后销毁，确保 crypto/counter capabilities 不会晚于跨进程独占 lease。
    _lease: RemoteDeviceLease,
}

impl fmt::Debug for OpenedPairedMachine<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedPairedMachine([REDACTED])")
    }
}

impl OpenedPairedMachine<'_> {
    fn validate_v6_encoded_capacity(
        &self,
        encoded_len: usize,
        stream_cursors: &[Vec<u8>],
        transfer_records: &[Vec<u8>],
    ) -> Result<(), PairedPromotionError> {
        validate_v6_encoded_capacity_with_context(
            self.runtime_state_mutation_authority,
            self.live_transfer_candidate_capacity,
            encoded_len,
            stream_cursors,
            transfer_records,
        )
    }

    fn validate_v6_transfer_cardinality_reserve(
        &self,
        records: &[Vec<u8>],
        mode: V6StateCapacityMode,
    ) -> Result<(), PairedPromotionError> {
        validate_v6_transfer_cardinality_reserve_with_context(
            self.runtime_state_mutation_authority,
            records,
            mode,
        )
    }

    /// Emergency mode 只能消费由当前 normal V6 投影预留的 headroom。冷读 legacy V1–V5
    /// 不触发迁移；但只要 current state 的等价 V6 投影已越过 normal byte/cardinality
    /// 边界，任何 emergency mutation 都必须在 entropy 与写盘前 fail-close。
    fn validate_v6_emergency_base_capacity(&self) -> Result<(), PairedPromotionError> {
        self.validate_equivalent_v6_normal_capacity(&self.audited.state)
    }

    /// Counter reservation 与 crash recovery 可能从 V2–V5 直接生成 next state。即使
    /// candidate 为兼容旧 Pending hash 保留了原 enum version，也必须按其等价 V6 投影执行
    /// 与普通 transfer mutation 相同的 exact byte/cardinality gate。
    fn validate_equivalent_v6_normal_capacity(
        &self,
        state: &PairedCryptoState,
    ) -> Result<(), PairedPromotionError> {
        validate_equivalent_v6_normal_capacity_with_context(
            self.runtime_state_mutation_authority,
            self.live_transfer_candidate_capacity,
            state,
        )
    }

    fn validate_state_candidate_capacity(
        &self,
        state: &PairedCryptoState,
        encoded_len: usize,
        mode: V6StateCapacityMode,
    ) -> Result<(), PairedPromotionError> {
        validate_state_candidate_capacity_with_context(
            self.runtime_state_mutation_authority,
            self.live_transfer_candidate_capacity,
            state,
            encoded_len,
            mode,
        )
    }

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
        self.audited.effective_directory_revision
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

    /// 返回 cold-open 已完成 canonical record 与 installed binding 交叉审计的 live transfer
    /// state。V1–V5 legacy paired state 精确映射为空集合，不执行迁移写入。
    pub fn durable_transfer_state(
        &self,
    ) -> Result<DurableLiveTransferStateV1, PairedPromotionError> {
        self.audited.state.durable_transfer_state()
    }

    /// exact binding 上的 terminal bootstrap marker 是 ingress fence。只扫描并解码 compact
    /// marker records，不复制同 collection 中的大 part bytes。
    pub(crate) fn transfer_bootstrap_error_for_binding(
        &self,
        expected_binding: &DurableStreamBindingV1,
    ) -> Result<Option<DurableTransferBootstrapError>, PairedPromotionError> {
        self.validate_stream_binding_capability(expected_binding.binding())?;
        let matching = self
            .audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .filter(|binding| binding == expected_binding)
            .count();
        if matching != 1 {
            return Err(PairedPromotionError::Conflict);
        }
        self.audited
            .state
            .durable_transfer_bootstrap_error(expected_binding.binding())
    }

    /// 返回 open-time 已完成 canonical 审计的 KeySync coordination owned projection。
    /// V1/V2/V3 与 V4 的 empty optional field 都映射为 `None`。
    pub fn durable_key_sync_state(
        &self,
    ) -> Result<Option<DurableKeySyncStateV1>, PairedPromotionError> {
        self.audited.state.durable_key_sync_state()
    }

    /// 返回 open-time 已完成 canonical、MachineDataSign 与 DeviceHPKE 全审计的 generation
    /// inventory。V1–V4 映射为 `None`；V5 field required 且不能清空退化。
    pub fn durable_key_generation_state(
        &self,
    ) -> Result<Option<DurableKeyGenerationStateV1>, PairedPromotionError> {
        self.audited.state.durable_key_generation_state()
    }

    /// 纯内存构造 normal UpdateSet 的唯一 combined candidate。该步骤不取 entropy、不写
    /// Keychain/磁盘；ADKG、ADKS 与 same-epoch shared binding replacement 会先组成一个
    /// 完整 V5 plaintext，之后只能交给 [`Self::commit_key_update_install`]。
    pub fn prepare_key_update_install(
        &self,
        handoff: KeySyncUpdateSetHandoff,
        installed_at_ms: u64,
    ) -> Result<PreparedKeyUpdateInstall, PairedPromotionError> {
        let update_set_sha256 = handoff.update_set_sha256();
        let update_set_canonical = handoff.update_set_canonical_bytes().to_vec();
        let current_key_sync = self
            .audited
            .state
            .durable_key_sync_state()?
            .ok_or(PairedPromotionError::Conflict)?;

        // Committed retry 必须先于 clock/deadline 与 candidate reconstruction。只认 durable
        // attempt/source route/revision/hash 四元组和 exact ADKG projection；同一 Reply 在
        // deadline 后重放仍零 entropy、零写并可重建 ACK。
        if let Some(expected_ack_basis) = current_key_sync.latest_completed_ack_basis()
            && expected_ack_basis.attempt() == handoff.request().attempt
            && expected_ack_basis.source_request_route() == handoff.request_route()
            && expected_ack_basis.key_directory_revision()
                == handoff.requested_key_directory_revision()
            && expected_ack_basis.update_set_sha256() == update_set_sha256
        {
            let generation = self
                .audited
                .state
                .durable_key_generation_state()?
                .ok_or(PairedPromotionError::Conflict)?;
            let installed_set = generation
                .staged_normal_update_set()
                .map_err(|_| PairedPromotionError::Conflict)?;
            if installed_set
                .canonical_bytes()
                .map_err(PairedPromotionError::Protocol)?
                != update_set_canonical
            {
                return Err(PairedPromotionError::Conflict);
            }
            let candidate_generation_bytes = generation
                .canonical_bytes()
                .map_err(|_| PairedPromotionError::InvalidState)?;
            let candidate_key_sync_bytes = current_key_sync
                .canonical_bytes()
                .map_err(|_| PairedPromotionError::InvalidState)?;
            let candidate_stream_binding_bytes =
                encode_stream_bindings(self.audited.state.durable_stream_bindings()?)
                    .map_err(|_| PairedPromotionError::InvalidState)?;
            let candidate_state_bytes = self.audited.state_snapshot.expose_secret().to_vec();
            return Ok(PreparedKeyUpdateInstall {
                expected_state_bytes: candidate_state_bytes.clone(),
                candidate_state_bytes,
                candidate_generation_bytes,
                candidate_key_sync_bytes,
                candidate_stream_binding_bytes,
                expected_ack_basis,
            });
        }
        if &current_key_sync != handoff.retained_state() {
            return Err(PairedPromotionError::Conflict);
        }
        let outcome = handoff
            .clone()
            .after_durable_install(installed_at_ms, update_set_sha256)
            .map_err(|_| PairedPromotionError::Conflict)?;
        let candidate_key_sync = outcome.state().clone();
        let expected_ack_basis = candidate_key_sync
            .latest_completed_ack_basis()
            .ok_or(PairedPromotionError::Conflict)?;
        if expected_ack_basis.attempt() != handoff.request().attempt
            || expected_ack_basis.source_request_route() != handoff.request_route()
            || expected_ack_basis.key_directory_revision()
                != handoff.requested_key_directory_revision()
            || expected_ack_basis.update_set_sha256() != update_set_sha256
        {
            return Err(PairedPromotionError::Conflict);
        }
        let candidate_key_sync_bytes = candidate_key_sync
            .canonical_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?;

        let previous_generation = match self.audited.state.durable_key_generation_state()? {
            Some(state) => state,
            None => {
                let directory = KeyDirectoryV1::from_canonical_bytes(
                    &self.audited.state.bootstrap().key_directory,
                )
                .map_err(PairedPromotionError::Protocol)?;
                DurableKeyGenerationStateV1::from_bootstrap_directory(&directory)
                    .map_err(|_| PairedPromotionError::Conflict)?
            }
        };
        let candidate_generation =
            stage_normal_update_set(&previous_generation, handoff.update_set())
                .map_err(|_| PairedPromotionError::Conflict)?;
        validate_normal_update_raw_relations(
            &previous_generation,
            &candidate_generation,
            handoff.update_set(),
            self.audited.state.bootstrap(),
            &self.audited.device_hpke_private_key,
            &self.audited.machine_data_verifying_key,
            &self.audited.machine_data_signer_binding,
        )?;

        let previous_bindings = self.audited.state.durable_stream_bindings()?;
        let candidate_bindings = rewrap_stream_bindings_for_normal_update(
            &previous_generation,
            &candidate_generation,
            handoff.update_set(),
            previous_bindings.clone(),
        )?;
        let candidate_stream_binding_bytes = encode_stream_bindings(candidate_bindings.clone())
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let candidate_generation_bytes = candidate_generation
            .canonical_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let mut runtime = self.audited.state.opaque_runtime_state();
        runtime.stream_cursors = candidate_stream_binding_bytes.clone();
        let mut transfer = self.audited.state.durable_transfer_state()?;
        for previous in &previous_bindings {
            if candidate_bindings
                .iter()
                .find(|candidate| candidate.target_key() == previous.target_key())
                .is_none_or(|candidate| candidate.binding() != previous.binding())
            {
                transfer = transfer
                    .purge_exact_binding(previous.binding())
                    .map_err(|_| PairedPromotionError::InvalidState)?;
            }
        }
        runtime.transfer_records = SharedTransferRecords::from_owned(
            transfer
                .canonical_record_bytes()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        );
        let candidate_state = self.audited.state.with_mutable_projection(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            &runtime,
            self.audited.state.counter_reservation(),
            Some(candidate_key_sync_bytes.clone()),
            Some(candidate_generation_bytes.clone()),
            if matches!(&self.audited.state, PairedCryptoState::V6(_))
                || !runtime.stream_cursors.is_empty()
                || !runtime.transfer_records.is_empty()
            {
                TRANSFER_STATE_VERSION
            } else {
                KEY_GENERATION_STATE_VERSION
            },
            true,
            true,
            true,
        )?;

        // 用 candidate current inventory（不是 active/旧 inventory）审计 candidate binding。
        let inventories = audit_key_generation_state_and_stage(
            &candidate_state,
            None,
            candidate_state.bootstrap(),
            &self.audited.device_hpke_private_key,
            &self.audited.machine_data_verifying_key,
            &self.audited.machine_data_signer_binding,
            &self.audited.opened_directory_keys,
        )?;
        let candidate_opened = inventories
            .active
            .as_deref()
            .ok_or(PairedPromotionError::InvalidState)?;
        validate_typed_stream_state_and_stage(
            &candidate_state,
            None,
            StreamBindingAuditContext {
                identity: self.audited.identity,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                trust_epoch: self.audited.trust_epoch,
                bootstrap_directory_revision: self.audited.bootstrap_directory_revision,
                effective_directory_revision: candidate_generation.effective_directory_revision(),
            },
            &self.audited.authorization,
            candidate_opened,
            None,
        )?;
        let candidate_state_bytes = candidate_state.encode()?;
        Ok(PreparedKeyUpdateInstall {
            expected_state_bytes: self.audited.state_snapshot.expose_secret().to_vec(),
            candidate_state_bytes,
            candidate_generation_bytes,
            candidate_key_sync_bytes,
            candidate_stream_binding_bytes,
            expected_ack_basis,
        })
    }

    /// 单次提交完整 V5 candidate。exact committed retry 优先于 expected 比较，因此 stale
    /// prepared + `PanicRng` 仍零 entropy/零写；任何 crash cut 恢复后只接受完整旧或新
    /// snapshot。ACK 只在 ADKG/ADKS/binding collection 全部逐字读回后返回。
    pub fn commit_key_update_install<R: CryptoRng>(
        &mut self,
        prepared: PreparedKeyUpdateInstall,
        rng: &mut R,
    ) -> Result<CommittedKeyUpdateInstall, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.refresh_mutable_state()?;

        let current = self.audited.state_snapshot.expose_secret();
        if current == prepared.candidate_state_bytes {
            return self.read_back_committed_key_update_install(&prepared, true);
        }
        if current != prepared.expected_state_bytes {
            return Err(PairedPromotionError::Conflict);
        }

        let candidate_state = PairedCryptoState::decode(&prepared.candidate_state_bytes)?;
        let write_result = self.commit_prepared_state_transition(
            candidate_state,
            prepared.candidate_state_bytes.clone(),
            rng,
        );
        match write_result {
            Ok(()) => self.read_back_committed_key_update_install(&prepared, false),
            Err(write_error) => {
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                let _recovery = self.recover_pending_guard();
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                if self.audited.state_snapshot.expose_secret() == prepared.candidate_state_bytes {
                    self.read_back_committed_key_update_install(&prepared, false)
                } else if self.audited.state_snapshot.expose_secret()
                    == prepared.expected_state_bytes
                {
                    Err(write_error)
                } else {
                    Err(PairedPromotionError::Conflict)
                }
            }
        }
    }

    fn read_back_committed_key_update_install(
        &mut self,
        prepared: &PreparedKeyUpdateInstall,
        already_committed: bool,
    ) -> Result<CommittedKeyUpdateInstall, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.refresh_mutable_state()?;
        if self.audited.state_snapshot.expose_secret() != prepared.candidate_state_bytes {
            return Err(PairedPromotionError::Conflict);
        }
        let generation = self
            .audited
            .state
            .durable_key_generation_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        let key_sync_state = self
            .audited
            .state
            .durable_key_sync_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        let generation_bytes = generation
            .canonical_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let key_sync_bytes = key_sync_state
            .canonical_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let binding_bytes = encode_stream_bindings(self.audited.state.durable_stream_bindings()?)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let ack_basis = key_sync_state
            .latest_completed_ack_basis()
            .ok_or(PairedPromotionError::Conflict)?;
        if generation_bytes != prepared.candidate_generation_bytes
            || key_sync_bytes != prepared.candidate_key_sync_bytes
            || binding_bytes != prepared.candidate_stream_binding_bytes
            || ack_basis != prepared.expected_ack_basis
        {
            return Err(PairedPromotionError::Conflict);
        }
        let ack = KeyUpdateAckV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.audited.identity.machine_route,
            device_route: self.audited.device_route,
            grant_serial: self.audited.grant_serial,
            root_trust_epoch: self.audited.trust_epoch,
            key_directory_revision: ack_basis.key_directory_revision(),
            update_set_sha256: ack_basis.update_set_sha256(),
        };
        ack.validate().map_err(PairedPromotionError::Protocol)?;
        Ok(CommittedKeyUpdateInstall {
            key_sync_state,
            ack_basis,
            ack,
            already_committed,
        })
    }

    /// 仅供 automatic wrapper 的 generation-only CAS；production UpdateSet 必须走 V5-B 的
    /// ADKG+ADKS/roster/activation transaction，不能复用本 seam。
    fn commit_key_generation_state_transition<R: CryptoRng>(
        &mut self,
        expected: Option<&DurableKeyGenerationStateV1>,
        replacement: &DurableKeyGenerationStateV1,
        rng: &mut R,
    ) -> Result<DurableKeyGenerationStateV1, PairedPromotionError> {
        let canonical = |state: &DurableKeyGenerationStateV1| {
            state
                .canonical_bytes()
                .map_err(|_| PairedPromotionError::InvalidState)
        };
        let expected_bytes = expected.map(canonical).transpose()?;
        let replacement_bytes = canonical(replacement)?;

        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        let current_bytes = self
            .audited
            .state
            .key_generation_state_bytes()
            .map(ToOwned::to_owned);
        if current_bytes.as_deref() == Some(replacement_bytes.as_slice()) {
            return self
                .audited
                .state
                .durable_key_generation_state()?
                .ok_or(PairedPromotionError::InvalidState);
        }
        if current_bytes != expected_bytes {
            return Err(PairedPromotionError::Conflict);
        }
        if let Some(previous) = self.audited.state.durable_key_generation_state()? {
            validate_directed_rewrap_metadata(&previous, replacement)
                .map_err(|_| PairedPromotionError::Conflict)?;
        }

        let next_state = self.audited.state.with_key_generation_state_bytes(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            Some(replacement_bytes.clone()),
            true,
        )?;
        let active_keys = audit_key_generation_state_and_stage(
            &next_state,
            None,
            next_state.bootstrap(),
            &self.audited.device_hpke_private_key,
            &self.audited.machine_data_verifying_key,
            &self.audited.machine_data_signer_binding,
            &self.audited.opened_directory_keys,
        )?
        .active
        .ok_or(PairedPromotionError::InvalidState)?;
        validate_typed_stream_state_and_stage(
            &next_state,
            None,
            StreamBindingAuditContext {
                identity: self.audited.identity,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                trust_epoch: self.audited.trust_epoch,
                bootstrap_directory_revision: self.audited.bootstrap_directory_revision,
                effective_directory_revision: replacement.effective_directory_revision(),
            },
            &self.audited.authorization,
            &active_keys,
            None,
        )?;
        let next_state_bytes = next_state.encode()?;
        match self.commit_prepared_state_transition(next_state, next_state_bytes, rng) {
            Ok(()) => {
                self.refresh_mutable_state()?;
                self.audited
                    .state
                    .durable_key_generation_state()?
                    .ok_or(PairedPromotionError::InvalidState)
            }
            Err(write_error) => {
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                let _recovery = self.recover_pending_guard();
                let recovered = self
                    .audited
                    .state
                    .key_generation_state_bytes()
                    .map(ToOwned::to_owned);
                if recovered.as_deref() == Some(replacement_bytes.as_slice()) {
                    self.audited
                        .state
                        .durable_key_generation_state()?
                        .ok_or(PairedPromotionError::InvalidState)
                } else if recovered == expected_bytes {
                    Err(write_error)
                } else {
                    Err(PairedPromotionError::Conflict)
                }
            }
        }
    }

    /// 仅 automatic harness 可达；production handle 在读取 candidate/entropy 前拒绝。
    #[doc(hidden)]
    pub fn commit_key_generation_state_transition_for_automatic_harness<R: CryptoRng>(
        &mut self,
        expected: Option<&DurableKeyGenerationStateV1>,
        replacement: &DurableKeyGenerationStateV1,
        rng: &mut R,
    ) -> Result<DurableKeyGenerationStateV1, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.commit_key_generation_state_transition(expected, replacement, rng)
    }

    /// 注入非 canonical ADKG，证明 list/open 全库审计 fail-close 且零改写。
    #[doc(hidden)]
    pub fn replace_unchecked_key_generation_state_for_automatic_harness<R: CryptoRng>(
        &mut self,
        replacement: Vec<u8>,
        rng: &mut R,
    ) -> Result<(), PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        if self.audited.state.key_generation_state_bytes() == Some(replacement.as_slice()) {
            return Ok(());
        }
        let next_state = self.audited.state.with_key_generation_state_bytes(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            Some(replacement),
            false,
        )?;
        let next_state_bytes = match &next_state {
            PairedCryptoState::V5(value) => {
                value.encode_version_inner(KEY_GENERATION_STATE_VERSION, true, false, true)?
            }
            PairedCryptoState::V6(value) => {
                value.encode_version_inner(TRANSFER_STATE_VERSION, true, false, true)?
            }
            PairedCryptoState::V1(_)
            | PairedCryptoState::V2(_)
            | PairedCryptoState::V3(_)
            | PairedCryptoState::V4(_) => return Err(PairedPromotionError::InvalidState),
        };
        self.commit_prepared_state_transition(next_state, next_state_bytes, rng)
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
                bootstrap_directory_revision: self.audited.bootstrap_directory_revision,
                effective_directory_revision: self.audited.effective_directory_revision,
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
                value.encode_version_inner(KEY_SYNC_STATE_VERSION, false, true, true)?
            }
            PairedCryptoState::V5(value) => {
                value.encode_version_inner(KEY_GENERATION_STATE_VERSION, false, true, true)?
            }
            PairedCryptoState::V6(value) => {
                value.encode_version_inner(TRANSFER_STATE_VERSION, false, true, true)?
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
        let replacement = OpaqueRuntimeState::new_preserving_transfer_records(
            current.exchange,
            current.replay_windows,
            stream_bindings,
            current.transfer_records,
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
        let existing = states
            .iter()
            .find(|state| state.target_key() == target)
            .cloned();
        let candidate = if let Some(existing) = existing.as_ref() {
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
        let mut transfer = self.audited.state.durable_transfer_state()?;
        if let Some(existing) = existing {
            // 成功 bootstrap 代表 reducer 已用完整 snapshot 建立新 cut；即使 raw binding
            // 未变化，也不能把旧 partial/NeedsBootstrap/completed 记录带过这个边界。
            transfer = transfer
                .purge_exact_binding(existing.binding())
                .map_err(|_| PairedPromotionError::InvalidState)?;
        }
        let transfer_records = transfer
            .canonical_record_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let current = self.audited.state.opaque_runtime_state();
        let replacement = OpaqueRuntimeState::new(
            None,
            current.replay_windows().to_vec(),
            stream_bindings,
            transfer_records,
        );
        self.replace_opaque_runtime_state(&replacement, rng)?;
        Ok(candidate)
    }

    /// 仅供 automatic library harness 驱动 production subscription replacement，并验证
    /// 旧 binding 的 active/completed/NeedsBootstrap transfer records 与新 binding 在同一
    /// paired-state transaction 中完成 cleanup/install。
    #[doc(hidden)]
    pub fn commit_subscription_bootstrap_for_automatic_harness<R: CryptoRng>(
        &mut self,
        binding: StreamBindingV1,
        inner_applied: RuntimeInnerCursor,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.commit_subscription_bootstrap(binding, inner_applied, rng)
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
        match self.commit_stream_bindings_preserving_transfer_from_current(stream_bindings, rng) {
            Ok(()) => Ok(replacement.clone()),
            Err(write_error) => {
                // active state CAS 之后的 guard-finalize/sidecar cleanup 仍可能报错。此时先
                // refresh + forward-recover，再以完整 candidate readback 决定是否已 COMMIT；
                // 不能把“已落盘但返回 Err”交给 runtime，导致 reducer 永久不 swap。
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                self.recover_pending_guard()?;
                self.refresh_mutable_state()?;
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

    /// caller 已完成 refresh/recovery 与 raw-binding equality check；这里只替换 encoded
    /// stream collection。V6/非空 transfer collection 从 audited state 只 clone immutable
    /// Arc owner 进入 candidate；encoder 只读同一 records allocation，不建立第二份最多
    /// 128 MiB 的 collection。
    fn commit_stream_bindings_preserving_transfer_from_current<R: CryptoRng>(
        &mut self,
        stream_bindings: Vec<Vec<u8>>,
        rng: &mut R,
    ) -> Result<(), PairedPromotionError> {
        if self.audited.state.durable_stream_binding_bytes() == stream_bindings {
            return Ok(());
        }
        let transfer_records = self.audited.state.shared_durable_transfer_records();
        let candidate_encoded_len = self
            .audited
            .state
            .validate_current_v6_stream_transfer_capacity(
                &stream_bindings,
                transfer_records.as_slice(),
            )?;
        self.validate_v6_encoded_capacity(
            candidate_encoded_len,
            &stream_bindings,
            transfer_records.as_slice(),
        )?;
        self.validate_v6_transfer_cardinality_reserve(
            transfer_records.as_slice(),
            V6StateCapacityMode::Normal,
        )?;
        let next_state = self
            .audited
            .state
            .with_shared_stream_transfer_projection(stream_bindings, transfer_records)?;
        let next_state_bytes = next_state.encode_transfer_prevalidated()?;
        self.commit_prepared_state_transition(next_state, next_state_bytes, rng)
    }

    /// 从当前 exact paired snapshot 加载并按值消费 live transfer semantic state。返回值
    /// 同时持有该 snapshot 的零复制 capability，后续 combined CAS 不需要重编码 expected
    /// records，也不能把另一个 paired snapshot 的 transition 拼接进来。
    pub(crate) fn prepare_live_transfer_part(
        &self,
        expected_binding: &DurableStreamBindingV1,
        carrier: RuntimeTransferCarrierV1,
        now_ms: u64,
    ) -> Result<PendingStreamTransferTransition, PairedPromotionError> {
        let transition = self
            .audited
            .state
            .durable_transfer_state()?
            .accept_part(expected_binding.binding(), carrier, now_ms)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        self.bind_pending_stream_transfer_transition(expected_binding, transition)
    }

    /// 从 current exact state 生成 compact NeedsBootstrap marker。用于 malformed payload、
    /// reducer rejection，以及大 candidate 命中 paired V6 capacity 后的 fail-closed fallback；
    /// 不复用已消费或可能超限的 replacement records。
    pub(crate) fn prepare_live_transfer_bootstrap_marker(
        &self,
        expected_binding: &DurableStreamBindingV1,
        transfer_id: Option<&TransferId>,
        error: DurableTransferBootstrapError,
        now_ms: u64,
    ) -> Result<PendingStreamTransferTransition, PairedPromotionError> {
        let transition = self
            .audited
            .state
            .durable_transfer_state()?
            .abort_exact_binding(expected_binding.binding(), transfer_id, error, now_ms)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        self.bind_pending_stream_transfer_transition(expected_binding, transition)
    }

    /// Idle TTL 唤醒的 owned transition。无 due active 时 semantic state 直接释放，不生成
    /// candidate records；有 due binding 时由当前 installed collection 反查唯一 exact binding。
    pub(crate) fn prepare_due_live_transfer_expiry(
        &self,
        now_ms: u64,
    ) -> Result<Option<PendingStreamTransferTransition>, PairedPromotionError> {
        let Some((identity, transition)) = self
            .audited
            .state
            .durable_transfer_state()?
            .expire_due_active_transition(now_ms)
            .map_err(|_| PairedPromotionError::InvalidState)?
        else {
            return Ok(None);
        };
        let expected_binding = self.stream_binding_for_transfer_identity(identity)?;
        self.bind_pending_stream_transfer_transition(&expected_binding, transition)
            .map(Some)
    }

    fn stream_binding_for_transfer_identity(
        &self,
        identity: DurableTransferBindingIdentityV1,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        let mut matching = self
            .audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .filter(|binding| {
                DurableTransferBindingIdentityV1::from_stream_binding(binding.binding())
                    == Ok(identity)
            });
        let binding = matching.next().ok_or(PairedPromotionError::Conflict)?;
        if matching.next().is_some() {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(binding)
    }

    fn bind_pending_stream_transfer_transition(
        &self,
        expected_binding: &DurableStreamBindingV1,
        transition: DurableTransferTransitionV1,
    ) -> Result<PendingStreamTransferTransition, PairedPromotionError> {
        self.validate_stream_binding_capability(expected_binding.binding())?;
        let bindings = self.audited.state.durable_stream_bindings()?;
        let current = bindings
            .iter()
            .find(|state| state.target_key() == expected_binding.target_key())
            .ok_or(PairedPromotionError::Conflict)?;
        if current != expected_binding {
            return Err(PairedPromotionError::Conflict);
        }
        transition
            .state()
            .validate_against_bindings(&bindings)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        Ok(PendingStreamTransferTransition {
            expected_state_snapshot: Arc::clone(&self.audited.state_snapshot),
            expected_binding: expected_binding.clone(),
            transition,
        })
    }

    /// 把 pending semantic transition 与 outer/inner candidate 收口为完整 V6 prepared
    /// snapshot。canonical record bytes 直接按值移入 candidate；semantic state 完成 binding
    /// 交叉验证后立即释放，不会经 `OpaqueRuntimeState` / `with_mutable_projection` 再 clone。
    fn prepare_stream_transfer_transition(
        &self,
        pending: PendingStreamTransferTransition,
        replacement_binding: DurableStreamBindingV1,
        capacity_mode: V6StateCapacityMode,
    ) -> Result<PreparedStreamTransferTransition, PairedPromotionError> {
        if capacity_mode == V6StateCapacityMode::EmergencyBootstrapMarker {
            self.validate_v6_emergency_base_capacity()?;
        }
        let PendingStreamTransferTransition {
            expected_state_snapshot,
            expected_binding,
            transition,
        } = pending;
        if !Arc::ptr_eq(&expected_state_snapshot, &self.audited.state_snapshot)
            || expected_binding.binding() != replacement_binding.binding()
            || expected_binding.target_key() != replacement_binding.target_key()
        {
            return Err(PairedPromotionError::Conflict);
        }
        self.validate_stream_binding_capability(expected_binding.binding())?;
        self.validate_stream_binding_capability(replacement_binding.binding())?;
        let _ = replacement_binding
            .canonical_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?;

        let mut bindings = self.audited.state.durable_stream_bindings()?;
        let current_index = bindings
            .iter()
            .position(|state| state.target_key() == expected_binding.target_key())
            .ok_or(PairedPromotionError::Conflict)?;
        if bindings[current_index] != expected_binding {
            return Err(PairedPromotionError::Conflict);
        }
        bindings[current_index] = replacement_binding.clone();

        let (replacement_transfer, replacement_records, outcome) = transition.into_prepared_parts();
        let replacement_records = SharedTransferRecords::from_owned(replacement_records);
        replacement_transfer
            .validate_against_bindings(&bindings)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        drop(replacement_transfer);
        drop(outcome);

        let stream_bindings =
            encode_stream_bindings(bindings).map_err(|_| PairedPromotionError::InvalidState)?;
        let candidate_encoded_len = self
            .audited
            .state
            .validate_current_v6_stream_transfer_capacity(
                &stream_bindings,
                replacement_records.as_slice(),
            )?;
        self.validate_v6_encoded_capacity(
            candidate_encoded_len,
            &stream_bindings,
            replacement_records.as_slice(),
        )?;
        self.validate_v6_transfer_cardinality_reserve(
            replacement_records.as_slice(),
            capacity_mode,
        )?;
        let candidate_state = self
            .audited
            .state
            .with_shared_stream_transfer_projection(stream_bindings, replacement_records)?;
        let candidate_state_snapshot = Arc::new(CryptoStateSnapshot::new(
            candidate_state.encode_transfer_prevalidated()?,
        ));
        Ok(PreparedStreamTransferTransition {
            expected_state_snapshot,
            candidate_state_snapshot,
            candidate_state: Some(candidate_state),
            expected_binding,
            replacement_binding,
        })
    }

    /// Production combined CAS 只返回 committed binding。transfer state 已由 private
    /// prepared token 与 exact candidate snapshot 认证，正常路径不做完整 collection readback
    /// 或 clone；automatic harness 如需语义断言可在提交后另行 cold readback。
    pub(crate) fn commit_stream_transfer_transition<R: CryptoRng>(
        &mut self,
        pending: PendingStreamTransferTransition,
        replacement_binding: DurableStreamBindingV1,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        let prepared = self.prepare_stream_transfer_transition(
            pending,
            replacement_binding,
            V6StateCapacityMode::Normal,
        )?;
        self.commit_prepared_stream_transfer_transition(prepared, V6StateCapacityMode::Normal, rng)
    }

    /// Terminal NeedsBootstrap mutation 是唯一可使用真实 128 MiB hard cap 的 mutation。
    /// 普通路径已为该 compact marker 预留 byte/cardinality headroom；这里仍验证 pending
    /// 确实来自 transfer 状态机的 terminal outcome，禁止把 emergency mode 变成通用旁路。
    pub(crate) fn commit_stream_bootstrap_transition<R: CryptoRng>(
        &mut self,
        pending: PendingStreamTransferTransition,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        if !matches!(
            pending.transition.outcome(),
            DurableTransferOutcomeV1::NeedsBootstrap { .. }
        ) {
            return Err(PairedPromotionError::InvalidState);
        }
        let replacement_binding = pending.expected_binding.clone();
        let prepared = self.prepare_stream_transfer_transition(
            pending,
            replacement_binding,
            V6StateCapacityMode::EmergencyBootstrapMarker,
        )?;
        self.commit_prepared_stream_transfer_transition(
            prepared,
            V6StateCapacityMode::EmergencyBootstrapMarker,
            rng,
        )
    }

    /// Normal budget 已满时从 current exact snapshot 构造 ReassemblyFull terminal marker。
    /// `expected_binding` 必须来自 current exact snapshot；`replay_admitted_binding` 只能增加
    /// 已认证 replay tuple，不能推进 outer/inner/ACK。marker 与 replay replacement 在同一
    /// prepared-state CAS 中提交，payload kind 仍加密时传入 `transfer_id=None`。
    pub(crate) fn commit_stream_reassembly_full_fallback<R: CryptoRng>(
        &mut self,
        expected_binding: &DurableStreamBindingV1,
        replay_admitted_binding: DurableStreamBindingV1,
        transfer_id: Option<&TransferId>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        replay_admitted_binding
            .validate_identical_or_fresh_replay_admission_from(expected_binding)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let replay_admitted_binding = replay_admitted_binding
            .with_emergency_replay_debt_from(expected_binding)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let pending = self.prepare_live_transfer_bootstrap_marker(
            expected_binding,
            transfer_id,
            DurableTransferBootstrapError::ReassemblyFull,
            now_ms,
        )?;
        if !matches!(
            pending.transition.outcome(),
            DurableTransferOutcomeV1::NeedsBootstrap {
                error: DurableTransferBootstrapError::ReassemblyFull,
            }
        ) {
            return Err(PairedPromotionError::InvalidState);
        }
        let prepared = self.prepare_stream_transfer_transition(
            pending,
            replay_admitted_binding,
            V6StateCapacityMode::EmergencyBootstrapMarker,
        )?;
        self.commit_prepared_stream_transfer_transition(
            prepared,
            V6StateCapacityMode::EmergencyBootstrapMarker,
            rng,
        )
    }

    fn commit_prepared_stream_transfer_transition<R: CryptoRng>(
        &mut self,
        mut prepared: PreparedStreamTransferTransition,
        capacity_mode: V6StateCapacityMode,
        rng: &mut R,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.refresh_mutable_state()?;

        let current = self.audited.state_snapshot.expose_secret();
        if current == prepared.candidate_state_snapshot.expose_secret() {
            return self.read_back_committed_stream_transfer_binding(&prepared);
        }
        if current != prepared.expected_state_snapshot.expose_secret() {
            return Err(PairedPromotionError::Conflict);
        }

        let candidate_state = prepared
            .candidate_state
            .take()
            .ok_or(PairedPromotionError::Conflict)?;
        let write_result = self.commit_prepared_state_transition_snapshot_with_capacity(
            candidate_state,
            Arc::clone(&prepared.candidate_state_snapshot),
            capacity_mode,
            rng,
        );
        match write_result {
            Ok(()) => self.read_back_committed_stream_transfer_binding(&prepared),
            Err(write_error) => {
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                if self.recover_pending_guard().is_err() || self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                let recovered = self.audited.state_snapshot.expose_secret();
                if recovered == prepared.candidate_state_snapshot.expose_secret() {
                    self.read_back_committed_stream_transfer_binding(&prepared)
                } else if recovered == prepared.expected_state_snapshot.expose_secret() {
                    Err(write_error)
                } else {
                    Err(PairedPromotionError::Conflict)
                }
            }
        }
    }

    fn read_back_committed_stream_transfer_binding(
        &self,
        prepared: &PreparedStreamTransferTransition,
    ) -> Result<DurableStreamBindingV1, PairedPromotionError> {
        if self.audited.state_snapshot.expose_secret()
            != prepared.candidate_state_snapshot.expose_secret()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let binding = self
            .audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .find(|state| state.target_key() == prepared.expected_binding.target_key())
            .ok_or(PairedPromotionError::Conflict)?;
        if binding != prepared.replacement_binding {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(binding)
    }

    /// Automatic library harness 对 production combined CAS 的唯一公开驱动入口。harness
    /// 允许从显式 replacement state 构造 transition，提交后再单独读取 semantic state；
    /// production runtime 没有这个重编码/clone seam。
    #[doc(hidden)]
    pub fn commit_stream_transfer_transition_for_automatic_harness<R: CryptoRng>(
        &mut self,
        expected_binding: &DurableStreamBindingV1,
        replacement_binding: &DurableStreamBindingV1,
        expected_transfer: &DurableLiveTransferStateV1,
        replacement_transfer: &DurableLiveTransferStateV1,
        rng: &mut R,
    ) -> Result<(DurableStreamBindingV1, DurableLiveTransferStateV1), PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let current_binding = self
            .audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .find(|state| state.target_key() == expected_binding.target_key())
            .ok_or(PairedPromotionError::Conflict)?;
        let current_transfer = self.audited.state.durable_transfer_state()?;
        if current_binding == *replacement_binding && current_transfer == *replacement_transfer {
            return Ok((current_binding, current_transfer));
        }
        if current_binding != *expected_binding || current_transfer != *expected_transfer {
            return Err(PairedPromotionError::Conflict);
        }
        let transition =
            DurableTransferTransitionV1::from_automatic_harness_state(replacement_transfer.clone())
                .map_err(|_| PairedPromotionError::InvalidState)?;
        let pending = self.bind_pending_stream_transfer_transition(expected_binding, transition)?;
        let committed =
            self.commit_stream_transfer_transition(pending, replacement_binding.clone(), rng)?;
        let transfer = self.durable_transfer_state()?;
        Ok((committed, transfer))
    }

    /// 仅供 automatic fault harness 通过完整 paired transaction 写入结构有界、但语义上
    /// malformed/non-canonical 的 V6 transfer collection。production handle 在读取 bytes、
    /// entropy 与任一 durable mutation 前拒绝；正常 mutation 永远使用 strict canonical state。
    #[doc(hidden)]
    pub fn replace_unchecked_transfer_records_for_automatic_harness<R: CryptoRng>(
        &mut self,
        replacement: Vec<Vec<u8>>,
        rng: &mut R,
    ) -> Result<(), PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        let mut runtime = self.audited.state.opaque_runtime_state();
        if runtime.transfer_records.as_slice() == replacement.as_slice() {
            return Ok(());
        }
        runtime.transfer_records = SharedTransferRecords::from_owned(replacement);
        runtime.validate()?;
        let next_state = self.audited.state.with_mutable_projection(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            &runtime,
            self.audited.state.counter_reservation(),
            self.audited
                .state
                .key_sync_state_bytes()
                .map(ToOwned::to_owned),
            self.audited
                .state
                .key_generation_state_bytes()
                .map(ToOwned::to_owned),
            TRANSFER_STATE_VERSION,
            true,
            true,
            false,
        )?;
        let next_state_bytes = match &next_state {
            PairedCryptoState::V6(value) => {
                value.encode_version_inner(TRANSFER_STATE_VERSION, true, true, false)?
            }
            PairedCryptoState::V1(_)
            | PairedCryptoState::V2(_)
            | PairedCryptoState::V3(_)
            | PairedCryptoState::V4(_)
            | PairedCryptoState::V5(_) => return Err(PairedPromotionError::InvalidState),
        };
        self.commit_prepared_state_transition(next_state, next_state_bytes, rng)
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
        self.commit_stream_bindings_preserving_transfer_from_current(stream_bindings, rng)?;
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
        let replacement = OpaqueRuntimeState::new_preserving_transfer_records(
            current.exchange,
            current.replay_windows,
            stream_bindings,
            current.transfer_records,
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
                bootstrap_directory_revision: self.audited.bootstrap_directory_revision,
                effective_directory_revision: self.audited.effective_directory_revision,
            },
            &self.audited.authorization,
            &self.audited.opened_directory_keys,
        )
    }

    /// 当前 authenticated DeviceReplyTx replay scope；只暴露非秘密 epoch/revision。
    pub(crate) fn directed_reply_scope(&self) -> Result<(u64, u64), PairedPromotionError> {
        let (reply_epoch, reply_revision) = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::ReplyTx { key, .. } => {
                    Some((key.epoch, entry.key_directory_revision.value()))
                }
                OpenedPairedKeyMaterial::CommandTx(_)
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        Ok((reply_epoch, reply_revision))
    }

    /// 把 KeySync Reply 的公开 request projection 重新绑定到当前 durable active ADKS 与
    /// 当前 DeviceReplyTx revision。调用方持有旧 clone 或错误 route 时在验签/解密前拒绝。
    fn validate_active_key_sync_request(
        &self,
        request: &KeySyncRequestV1,
        request_route: RequestRouteId,
    ) -> Result<KeyDirectoryRevision, PairedPromotionError> {
        request.validate().map_err(PairedPromotionError::Protocol)?;
        let key_sync = self
            .audited
            .state
            .durable_key_sync_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        let active = key_sync
            .active_send()
            .ok_or(PairedPromotionError::Conflict)?;
        let (_, reply_revision) = self.directed_reply_scope()?;
        let reply_revision = KeyDirectoryRevision::new(reply_revision);
        if active.request() != request
            || active.request_route() != request_route
            || request.machine_route != self.audited.identity.machine_route
            || request.device_route != self.audited.device_route
            || request.grant_serial != self.audited.grant_serial
            || request.root_trust_epoch != self.audited.trust_epoch
            || request.known_key_directory_revision != reply_revision
            || request.known_key_directory_revision != self.audited.effective_directory_revision
            || key_sync.current_known_key_directory_revision() != reply_revision
            || request.requested_key_directory_revision
                != reply_revision
                    .next()
                    .map_err(|_| PairedPromotionError::Conflict)?
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(reply_revision)
    }

    /// 从已完成 open-time ADKG+ADKS+binding audit 的 latest completion basis 铸造 ACK。
    /// basis 只是索引；revision/hash/authority 必须再次从当前 durable state 精确反查。
    pub(crate) fn key_update_ack_from_basis(
        &self,
        basis: KeyUpdateAckBasisV1,
    ) -> Result<KeyUpdateAckV1, PairedPromotionError> {
        validate_key_sync_state_against_audit(
            &self.audited.state,
            StreamBindingAuditContext {
                identity: self.audited.identity,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                trust_epoch: self.audited.trust_epoch,
                bootstrap_directory_revision: self.audited.bootstrap_directory_revision,
                effective_directory_revision: self.audited.effective_directory_revision,
            },
        )?;
        let key_sync = self
            .audited
            .state
            .durable_key_sync_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        let durable_basis = key_sync
            .latest_completed_ack_basis()
            .ok_or(PairedPromotionError::Conflict)?;
        let generation = self
            .audited
            .state
            .durable_key_generation_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        let installed_set = generation
            .staged_normal_update_set()
            .map_err(|_| PairedPromotionError::Conflict)?;
        if durable_basis != basis
            || key_sync.current_known_key_directory_revision() != basis.key_directory_revision()
            || generation.effective_directory_revision() != basis.key_directory_revision()
            || self.audited.effective_directory_revision != basis.key_directory_revision()
            || installed_set
                .canonical_sha256()
                .map_err(PairedPromotionError::Protocol)?
                != basis.update_set_sha256()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let ack = KeyUpdateAckV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.audited.identity.machine_route,
            device_route: self.audited.device_route,
            grant_serial: self.audited.grant_serial,
            root_trust_epoch: self.audited.trust_epoch,
            key_directory_revision: basis.key_directory_revision(),
            update_set_sha256: basis.update_set_sha256(),
        };
        ack.validate().map_err(PairedPromotionError::Protocol)?;
        Ok(ack)
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
            || request.known_key_directory_revision != self.audited.effective_directory_revision
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

    /// 只用当前 durable completion basis 与当前 DeviceCommandTx capability 封装 ACK。
    /// runtime 传入的公开 ACK 必须逐字段等于内部重新铸造值，不能借此发送任意 key-control。
    pub(crate) fn seal_key_update_ack(
        &self,
        request_route: RequestRouteId,
        ack: &KeyUpdateAckV1,
        reservation: CommandCounterReservation,
    ) -> Result<Vec<u8>, PairedPromotionError> {
        if request_route.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(PairedPromotionError::Conflict);
        }
        let key_sync = self
            .audited
            .state
            .durable_key_sync_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        let basis = key_sync
            .latest_completed_ack_basis()
            .ok_or(PairedPromotionError::Conflict)?;
        let expected = self.key_update_ack_from_basis(basis)?;
        if ack != &expected {
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
                OpenedPairedKeyMaterial::CommandTx(key) => {
                    Some((key, entry.key_directory_revision))
                }
                OpenedPairedKeyMaterial::ReplyTx { .. }
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        if command_key.1 != ack.key_directory_revision
            || command_key.0.key_directory_revision != ack.key_directory_revision.value()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let control = KeyControlRequestV1::key_update_ack(ack.clone());
        let plaintext = control
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?;
        let context = OuterContextV1::uplink_send(
            self.audited.identity.machine_route,
            self.audited.device_route,
            request_route,
            command_key.0.epoch,
        );
        let unsigned = seal_symmetric(
            command_key.0,
            &context,
            control.sealed_payload_kind(),
            &plaintext,
            SenderCounter(reservation.start()),
        )
        .map_err(PairedPromotionError::Crypto)?;
        Ok(
            sign_sealed(unsigned, self.audited.device_signing_key.as_ref(), &context)
                .to_wire_bytes(),
        )
    }

    /// 用当前 durable barrier receipt basis 与 DeviceCommandTx capability 重封
    /// StreamAppliedAck。basis 会保留到后续 directory transition 显式替换，Relay 的
    /// RouteAccepted 不会清除它。
    pub(crate) fn seal_stream_applied_ack(
        &self,
        request_route: RequestRouteId,
        ack: &StreamAppliedAckV1,
        reservation: CommandCounterReservation,
    ) -> Result<Vec<u8>, PairedPromotionError> {
        if request_route.as_bytes().iter().all(|byte| *byte == 0)
            || !self
                .pending_stream_applied_acks()?
                .iter()
                .any(|basis| basis == ack)
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
                OpenedPairedKeyMaterial::CommandTx(key) => {
                    Some((key, entry.key_directory_revision))
                }
                OpenedPairedKeyMaterial::ReplyTx { .. }
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        if command_key.1 != ack.key_directory_revision
            || command_key.0.key_directory_revision != ack.key_directory_revision.value()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let control = KeyControlRequestV1::stream_applied_ack(ack.clone());
        let plaintext = control
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?;
        let context = OuterContextV1::uplink_send(
            self.audited.identity.machine_route,
            self.audited.device_route,
            request_route,
            command_key.0.epoch,
        );
        let unsigned = seal_symmetric(
            command_key.0,
            &context,
            control.sealed_payload_kind(),
            &plaintext,
            SenderCounter(reservation.start()),
        )
        .map_err(PairedPromotionError::Crypto)?;
        Ok(
            sign_sealed(unsigned, self.audited.device_signing_key.as_ref(), &context)
                .to_wire_bytes(),
        )
    }

    fn staged_stream_receiving_key(
        &self,
        binding: &StreamBindingV1,
        key_id: KeyId,
        key_directory_revision: KeyDirectoryRevision,
    ) -> Result<(AeadReceivingKey, [u8; 4]), PairedPromotionError> {
        if key_id.purpose != binding.key_id.purpose
            || binding.key_id.epoch.checked_add(1) != Some(key_id.epoch)
        {
            return Err(PairedPromotionError::Conflict);
        }
        let generation = self
            .audited
            .state
            .durable_key_generation_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        if generation.effective_directory_revision() != key_directory_revision {
            return Err(PairedPromotionError::Conflict);
        }
        let slot_route = stream_key_slot_route(key_id, binding.stream_route)?;
        let staged = generation
            .find_slot(key_id.purpose, slot_route)
            .and_then(|slot| slot.staged())
            .ok_or(PairedPromotionError::Conflict)?;
        if staged.key_id() != key_id
            || staged.key_directory_revision() != key_directory_revision
            || staged.stream_route() != slot_route
        {
            return Err(PairedPromotionError::Conflict);
        }
        let secret = open_durable_generation(
            self.audited.state.bootstrap(),
            &self.audited.device_hpke_private_key,
            &self.audited.machine_data_verifying_key,
            &self.audited.machine_data_signer_binding,
            staged,
        )?;
        let nonce_prefix = agentdeck_crypto::derive_nonce_prefix(&secret);
        Ok((
            AeadReceivingKey::new(key_id, key_id.epoch, secret),
            nonce_prefix,
        ))
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
                        Some((key, *nonce_prefix, entry.key_directory_revision))
                    }
                    OpenedPairedKeyMaterial::CommandTx(_)
                    | OpenedPairedKeyMaterial::ReplyTx { .. }
                    | OpenedPairedKeyMaterial::StreamRx { .. } => None,
                });
        let (stream_key, nonce_prefix, stream_revision) =
            matching.next().ok_or(PairedPromotionError::InvalidState)?;
        if matching.next().is_some() {
            return Err(PairedPromotionError::InvalidState);
        }
        let signed = SignedSealedBlobV1::from_wire_bytes(&publish.sealed_blob.0)
            .map_err(|error| PairedPromotionError::Crypto(error.into()))?;
        let expected_revision = stream_revision.value();
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
        let counter = u64::from_be_bytes(
            header.nonce[4..]
                .try_into()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        );
        let ciphertext_sha256 = sha256(&header.ciphertext);
        // 连续 same-epoch rewrap 保留同一 raw key/nonce domain 与 durable replay window。
        // 任一旧 revision 只在该 tuple 已被当前 binding 精确记录时可继续进入 runtime
        // 分类；fresh predecessor 仍是 rollback。NonceReuse 也必须进入 durable quarantine
        // 分支，不能被这里提前折叠成无状态错误。
        let retained_predecessor = header.key_directory_revision < expected_revision
            && header.key_id == binding.key_id
            && header.key_id == stream_key.key_id
            && header.key_epoch == stream_key.epoch
            && header.nonce[..4] == nonce_prefix
            && durable
                .admit_publish_at_authenticated_revision(
                    KeyDirectoryRevision::new(header.key_directory_revision),
                    publish.stream_seq,
                    counter,
                    ciphertext_sha256,
                )
                .is_ok_and(|(_, disposition)| {
                    matches!(
                        disposition,
                        StreamPublishDisposition::PendingDuplicate
                            | StreamPublishDisposition::AppliedDuplicate
                            | StreamPublishDisposition::NonceReuseQuarantined
                    )
                });
        if (header.key_directory_revision < expected_revision && !retained_predecessor)
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
            let header_revision = KeyDirectoryRevision::new(header.key_directory_revision);
            if header_revision == self.audited.effective_directory_revision
                && binding.key_id.epoch.checked_add(1) == Some(header.key_epoch)
            {
                // Staged key 只允许验证 exact-next outer frame；encrypted C/H/variant 在
                // durable staged replay admission 后再由专用 open capability 校验。
                if durable.outer_applied().checked_next().ok() != Some(publish.stream_seq) {
                    return Err(PairedPromotionError::Conflict);
                }
                let (_staged_key, staged_nonce_prefix) =
                    self.staged_stream_receiving_key(binding, header.key_id, header_revision)?;
                if header.nonce[..4] != staged_nonce_prefix {
                    return Err(PairedPromotionError::Crypto(CryptoError::BadCiphertext));
                }
                let staged_key_id = header.key_id;
                let staged_directory_revision = header.key_directory_revision;
                let staged_brand = StreamPublishBrand {
                    machine_route: self.audited.identity.machine_route,
                    stream_route: binding.stream_route,
                    stream_generation: binding.stream_generation,
                    key_id: staged_key_id,
                    directory_revision: staged_directory_revision,
                    frame_kind,
                };
                return Ok(VerifiedStreamPublish::StagedEpochBarrier(Box::new(
                    VerifiedStagedEpochBarrierPublish {
                        verified,
                        context,
                        brand: staged_brand,
                        stream_seq: publish.stream_seq,
                        counter,
                        ciphertext_sha256,
                    },
                )));
            }
            if header_revision <= self.audited.effective_directory_revision {
                // 已知 revision 却没有唯一 staged capability 不是 KeySync trigger。
                return Err(PairedPromotionError::Conflict);
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
                self.audited.effective_directory_revision,
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
            return Ok(VerifiedStreamPublish::Higher(Box::new(
                VerifiedHigherStreamPublish { observation },
            )));
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
            || (header.key_directory_revision != expected_revision && !retained_predecessor)
            || header.nonce[..4] != nonce_prefix
        {
            return Err(PairedPromotionError::Crypto(CryptoError::BadCiphertext));
        }
        let header_directory_revision = header.key_directory_revision;
        let current = VerifiedCurrentStreamPublish {
            verified,
            context,
            brand: stream_publish_brand(self.audited.identity.machine_route, binding)?,
            header_directory_revision,
            stream_seq: publish.stream_seq,
            counter,
            ciphertext_sha256,
        };
        let committed_barrier_duplicate = durable
            .latest_stream_applied_ack_basis()
            .is_some_and(|ack| ack.applied_stream_seq == publish.stream_seq)
            && durable
                .admit_publish_at_authenticated_revision(
                    KeyDirectoryRevision::new(header_directory_revision),
                    publish.stream_seq,
                    counter,
                    ciphertext_sha256,
                )
                .is_ok_and(|(_, disposition)| {
                    disposition == StreamPublishDisposition::AppliedDuplicate
                });
        if committed_barrier_duplicate {
            Ok(VerifiedStreamPublish::CommittedEpochBarrierDuplicate(
                Box::new(current),
            ))
        } else {
            Ok(VerifiedStreamPublish::Current(Box::new(current)))
        }
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
                    OpenedPairedKeyMaterial::StreamRx { key, nonce_prefix }
                        if entry.key_id == candidate.brand.key_id
                            && entry.stream_route == expected_slot =>
                    {
                        Some((key, *nonce_prefix, entry.key_directory_revision))
                    }
                    OpenedPairedKeyMaterial::CommandTx(_)
                    | OpenedPairedKeyMaterial::ReplyTx { .. }
                    | OpenedPairedKeyMaterial::StreamRx { .. } => None,
                });
        let (stream_key, nonce_prefix, stream_revision) =
            matching.next().ok_or(PairedPromotionError::InvalidState)?;
        if matching.next().is_some() {
            return Err(PairedPromotionError::InvalidState);
        }
        let expected_brand = StreamPublishBrand {
            machine_route: self.audited.identity.machine_route,
            stream_route: candidate.brand.stream_route,
            stream_generation: candidate.brand.stream_generation,
            key_id: stream_key.key_id,
            directory_revision: stream_revision.value(),
            frame_kind: stream_publish_frame_kind(stream_key.key_id)?,
        };
        let header = &candidate.verified.sealed().inner;
        let revision_allowed =
            candidate.header_directory_revision <= expected_brand.directory_revision;
        if candidate.brand != expected_brand
            || header.key_id != stream_key.key_id
            || header.key_epoch != stream_key.epoch
            || header.key_directory_revision != candidate.header_directory_revision
            || header.nonce[..4] != nonce_prefix
            || !revision_allowed
            || candidate.context.machine_route != Some(expected_brand.machine_route)
            || candidate.context.stream_route != Some(expected_brand.stream_route)
            || candidate.context.stream_generation != Some(expected_brand.stream_generation)
            || candidate.context.stream_seq != Some(candidate.stream_seq)
            || candidate.context.message_key_epoch != stream_key.epoch
        {
            return Err(PairedPromotionError::Conflict);
        }
        let mut installed = self
            .audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .filter(|state| {
                stream_publish_brand(self.audited.identity.machine_route, state.binding())
                    .is_ok_and(|brand| brand == candidate.brand)
            });
        let installed_state = installed.next().ok_or(PairedPromotionError::Conflict)?;
        if installed.next().is_some() {
            return Err(PairedPromotionError::Conflict);
        }
        if candidate.header_directory_revision != expected_brand.directory_revision {
            let (_, disposition) = installed_state
                .admit_publish_at_authenticated_revision(
                    KeyDirectoryRevision::new(candidate.header_directory_revision),
                    candidate.stream_seq,
                    candidate.counter,
                    candidate.ciphertext_sha256,
                )
                .map_err(|_| PairedPromotionError::Conflict)?;
            if disposition != StreamPublishDisposition::PendingDuplicate {
                return Err(PairedPromotionError::Conflict);
            }
        }
        open_sealed_payload(stream_key, &candidate.context, candidate.verified)
            .map_err(PairedPromotionError::Crypto)
    }

    /// 把 staged-key Publish 的 replay tuple 先单独 durable admission。ADKG/current binding
    /// 此时保持旧 cut；AEAD 与 canonical barrier 只能消费本次 exact readback 后的 token。
    pub(crate) fn admit_staged_epoch_barrier<R: CryptoRng>(
        &mut self,
        durable: &DurableStreamBindingV1,
        candidate: &VerifiedStagedEpochBarrierPublish,
        rng: &mut R,
    ) -> Result<(DurableStreamBindingV1, StreamPublishDisposition), PairedPromotionError> {
        let binding = durable.binding();
        let expected_brand = StreamPublishBrand {
            machine_route: self.audited.identity.machine_route,
            stream_route: binding.stream_route,
            stream_generation: binding.stream_generation,
            key_id: candidate.key_id(),
            directory_revision: candidate.key_directory_revision().value(),
            frame_kind: stream_publish_frame_kind(binding.key_id)?,
        };
        if candidate.brand != expected_brand
            || candidate.context.machine_route != Some(expected_brand.machine_route)
            || candidate.context.stream_route != Some(expected_brand.stream_route)
            || candidate.context.stream_generation != Some(expected_brand.stream_generation)
            || candidate.context.stream_seq != Some(candidate.stream_seq)
            || candidate.context.message_key_epoch != expected_brand.key_id.epoch
        {
            return Err(PairedPromotionError::Conflict);
        }
        let header = &candidate.verified.sealed().inner;
        let (_key, nonce_prefix) = self.staged_stream_receiving_key(
            binding,
            candidate.key_id(),
            candidate.key_directory_revision(),
        )?;
        if header.key_id != candidate.key_id()
            || header.key_epoch != candidate.key_id().epoch
            || header.key_directory_revision != candidate.key_directory_revision().value()
            || header.nonce[..4] != nonce_prefix
        {
            return Err(PairedPromotionError::Conflict);
        }
        let (admitted, disposition) = durable
            .admit_pending_epoch_barrier(
                candidate.key_id(),
                candidate.key_directory_revision(),
                candidate.stream_seq(),
                candidate.counter(),
                candidate.ciphertext_sha256(),
            )
            .map_err(|_| PairedPromotionError::Conflict)?;
        if admitted == *durable {
            return Ok((admitted, disposition));
        }
        let committed = self.commit_stream_state_transition(durable, &admitted, rng)?;
        if committed != admitted {
            return Err(PairedPromotionError::Conflict);
        }
        Ok((committed, disposition))
    }

    /// 只在 staged replay admission 已 durable readback 后解密；成功 token 固定绑定当前
    /// admitted state 的 C/H 与唯一 staged generation，不能跨 stream 或跨 CAS 复用。
    pub(crate) fn open_verified_staged_epoch_barrier(
        &self,
        durable: DurableStreamBindingV1,
        candidate: VerifiedStagedEpochBarrierPublish,
    ) -> Result<VerifiedEpochBarrierActivation, PairedPromotionError> {
        let installed = self
            .audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .filter(|state| state == &durable)
            .count();
        let pending = durable
            .pending_epoch_barrier()
            .ok_or(PairedPromotionError::Conflict)?;
        let tuple = pending.replay_tuple();
        if installed != 1
            || pending.replay_quarantined()
            || tuple.key_id() != candidate.key_id()
            || tuple.key_directory_revision() != candidate.key_directory_revision()
            || tuple.stream_seq() != candidate.stream_seq()
            || tuple.sender_counter() != candidate.counter()
            || tuple.ciphertext_sha256() != candidate.ciphertext_sha256()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let binding = durable.binding();
        let (stream_key, nonce_prefix) = self.staged_stream_receiving_key(
            binding,
            candidate.key_id(),
            candidate.key_directory_revision(),
        )?;
        let header = &candidate.verified.sealed().inner;
        if header.key_id != candidate.key_id()
            || header.key_epoch != candidate.key_id().epoch
            || header.key_directory_revision != candidate.key_directory_revision().value()
            || header.nonce[..4] != nonce_prefix
        {
            return Err(PairedPromotionError::Conflict);
        }
        let candidate_stream_seq = candidate.stream_seq();
        let candidate_key_id = candidate.key_id();
        let candidate_key_directory_revision = candidate.key_directory_revision();
        let opened = open_sealed_payload(&stream_key, &candidate.context, candidate.verified)
            .map_err(PairedPromotionError::Crypto)?;
        if opened.payload_kind != SealedPayloadKind::KeyUpdate {
            return Err(PairedPromotionError::Conflict);
        }
        let control = KeyControlV1::from_canonical_bytes(&opened.payload)
            .map_err(PairedPromotionError::Protocol)?;
        let KeyControlV1::EpochBarrier {
            stream_route,
            barrier,
            ..
        } = control
        else {
            return Err(PairedPromotionError::Conflict);
        };
        barrier.validate().map_err(PairedPromotionError::Protocol)?;
        let expected_stream_seq = barrier
            .stream_cursor
            .checked_next()
            .map_err(|_| PairedPromotionError::Conflict)?;
        if stream_route != binding.stream_route
            || barrier.stream_generation != binding.stream_generation
            || barrier.stream_cursor != durable.outer_applied()
            || barrier.inner_cursor != *durable.inner_observed()
            || barrier.inner_cursor != *durable.inner_applied()
            || expected_stream_seq != candidate_stream_seq
            || barrier.old_epoch != binding.key_id.epoch
            || barrier.new_epoch != candidate_key_id.epoch
            || barrier.key_directory_revision != candidate_key_directory_revision
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(VerifiedEpochBarrierActivation {
            durable,
            stream_route,
            barrier,
        })
    }

    /// 纯内存构造 activation 的完整 paired-state candidate。ADKS bytes 保持逐字不变；
    /// ADKG、target binding/replay 与 StreamAppliedAck basis 只能一起进入下一次 CAS。
    pub(crate) fn prepare_epoch_barrier_activation(
        &self,
        verified: VerifiedEpochBarrierActivation,
    ) -> Result<PreparedEpochBarrierActivation, PairedPromotionError> {
        let current_generation = self
            .audited
            .state
            .durable_key_generation_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        let slot_route = stream_key_slot_route(
            KeyId {
                purpose: verified.durable.binding().key_id.purpose,
                epoch: verified.barrier.new_epoch,
            },
            verified.stream_route,
        )?;
        let candidate_generation = current_generation
            .activate_shared_key_slot(
                verified.durable.binding().key_id.purpose,
                slot_route,
                verified.barrier.key_directory_revision,
                verified.barrier.old_epoch,
                verified.barrier.new_epoch,
            )
            .map_err(|_| PairedPromotionError::Conflict)?;
        let candidate_binding = verified
            .durable
            .activate_epoch_barrier(verified.stream_route, &verified.barrier)
            .map_err(|_| PairedPromotionError::Conflict)?;
        let expected_ack = candidate_binding
            .latest_stream_applied_ack_basis()
            .cloned()
            .ok_or(PairedPromotionError::Conflict)?;
        expected_ack
            .validate_for_barrier(verified.stream_route, &verified.barrier)
            .map_err(PairedPromotionError::Protocol)?;

        let mut bindings = self.audited.state.durable_stream_bindings()?;
        let target = verified.durable.target_key();
        let current = bindings
            .iter_mut()
            .find(|state| state.target_key() == target)
            .ok_or(PairedPromotionError::Conflict)?;
        if current != &verified.durable {
            return Err(PairedPromotionError::Conflict);
        }
        *current = candidate_binding;
        let candidate_stream_binding_bytes =
            encode_stream_bindings(bindings).map_err(|_| PairedPromotionError::InvalidState)?;
        let candidate_generation_bytes = candidate_generation
            .canonical_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let candidate_key_sync_bytes = self
            .audited
            .state
            .key_sync_state_bytes()
            .map(ToOwned::to_owned);
        let mut runtime = self.audited.state.opaque_runtime_state();
        runtime.stream_cursors = candidate_stream_binding_bytes.clone();
        runtime.transfer_records = SharedTransferRecords::from_owned(
            self.audited
                .state
                .durable_transfer_state()?
                .purge_exact_binding(verified.durable.binding())
                .map_err(|_| PairedPromotionError::InvalidState)?
                .canonical_record_bytes()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        );
        let candidate_state = self.audited.state.with_mutable_projection(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            &runtime,
            self.audited.state.counter_reservation(),
            candidate_key_sync_bytes,
            Some(candidate_generation_bytes.clone()),
            TRANSFER_STATE_VERSION,
            true,
            true,
            true,
        )?;

        let inventories = audit_key_generation_state_and_stage(
            &candidate_state,
            None,
            candidate_state.bootstrap(),
            &self.audited.device_hpke_private_key,
            &self.audited.machine_data_verifying_key,
            &self.audited.machine_data_signer_binding,
            &self.audited.opened_directory_keys,
        )?;
        let candidate_opened = inventories
            .active
            .as_deref()
            .ok_or(PairedPromotionError::InvalidState)?;
        validate_typed_stream_state_and_stage(
            &candidate_state,
            None,
            StreamBindingAuditContext {
                identity: self.audited.identity,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                trust_epoch: self.audited.trust_epoch,
                bootstrap_directory_revision: self.audited.bootstrap_directory_revision,
                effective_directory_revision: candidate_generation.effective_directory_revision(),
            },
            &self.audited.authorization,
            candidate_opened,
            None,
        )?;
        let candidate_state_bytes = candidate_state.encode()?;
        Ok(PreparedEpochBarrierActivation {
            expected_state_bytes: self.audited.state_snapshot.expose_secret().to_vec(),
            candidate_state_bytes,
            candidate_generation_bytes,
            candidate_stream_binding_bytes,
            expected_stream_route: verified.stream_route,
            expected_stream_generation: verified.barrier.stream_generation,
            expected_ack,
        })
    }

    pub(crate) fn commit_epoch_barrier_activation<R: CryptoRng>(
        &mut self,
        prepared: PreparedEpochBarrierActivation,
        rng: &mut R,
    ) -> Result<CommittedEpochBarrierActivation, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.refresh_mutable_state()?;
        let current = self.audited.state_snapshot.expose_secret();
        if current == prepared.candidate_state_bytes {
            return self.read_back_committed_epoch_barrier_activation(&prepared, true);
        }
        if current != prepared.expected_state_bytes {
            return Err(PairedPromotionError::Conflict);
        }
        let candidate_state = PairedCryptoState::decode(&prepared.candidate_state_bytes)?;
        let write_result = self.commit_prepared_state_transition(
            candidate_state,
            prepared.candidate_state_bytes.clone(),
            rng,
        );
        match write_result {
            Ok(()) => self.read_back_committed_epoch_barrier_activation(&prepared, false),
            Err(write_error) => {
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                let _recovery = self.recover_pending_guard();
                if self.refresh_mutable_state().is_err() {
                    return Err(write_error);
                }
                if self.audited.state_snapshot.expose_secret() == prepared.candidate_state_bytes {
                    self.read_back_committed_epoch_barrier_activation(&prepared, false)
                } else if self.audited.state_snapshot.expose_secret()
                    == prepared.expected_state_bytes
                {
                    Err(write_error)
                } else {
                    Err(PairedPromotionError::Conflict)
                }
            }
        }
    }

    fn read_back_committed_epoch_barrier_activation(
        &mut self,
        prepared: &PreparedEpochBarrierActivation,
        already_committed: bool,
    ) -> Result<CommittedEpochBarrierActivation, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.refresh_mutable_state()?;
        if self.audited.state_snapshot.expose_secret() != prepared.candidate_state_bytes {
            return Err(PairedPromotionError::Conflict);
        }
        let generation = self
            .audited
            .state
            .durable_key_generation_state()?
            .ok_or(PairedPromotionError::Conflict)?;
        if generation
            .canonical_bytes()
            .map_err(|_| PairedPromotionError::InvalidState)?
            != prepared.candidate_generation_bytes
        {
            return Err(PairedPromotionError::Conflict);
        }
        let bindings = self.audited.state.durable_stream_bindings()?;
        if encode_stream_bindings(bindings.clone())
            .map_err(|_| PairedPromotionError::InvalidState)?
            != prepared.candidate_stream_binding_bytes
        {
            return Err(PairedPromotionError::Conflict);
        }
        let mut matching = bindings.into_iter().filter(|state| {
            state.binding().stream_route == prepared.expected_stream_route
                && state.binding().stream_generation == prepared.expected_stream_generation
                && state.latest_stream_applied_ack_basis() == Some(&prepared.expected_ack)
        });
        let stream_binding = matching.next().ok_or(PairedPromotionError::Conflict)?;
        if matching.next().is_some() {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(CommittedEpochBarrierActivation {
            stream_binding,
            ack: prepared.expected_ack.clone(),
            already_committed,
        })
    }

    /// 已提交 barrier 的 current-key exact duplicate。必须重新 AEAD/canonical decode 并
    /// 与 durable receipt basis 对账，之后只重发 receipt/Relay ACK，不二次 retirement。
    pub(crate) fn open_committed_epoch_barrier_duplicate(
        &self,
        durable: DurableStreamBindingV1,
        candidate: VerifiedCurrentStreamPublish,
    ) -> Result<CommittedEpochBarrierActivation, PairedPromotionError> {
        let opened = self.open_verified_stream_publish(candidate)?;
        if opened.payload_kind != SealedPayloadKind::KeyUpdate {
            return Err(PairedPromotionError::Conflict);
        }
        let control = KeyControlV1::from_canonical_bytes(&opened.payload)
            .map_err(PairedPromotionError::Protocol)?;
        let KeyControlV1::EpochBarrier {
            stream_route,
            barrier,
            ..
        } = control
        else {
            return Err(PairedPromotionError::Conflict);
        };
        let ack = durable
            .latest_stream_applied_ack_basis()
            .cloned()
            .ok_or(PairedPromotionError::Conflict)?;
        ack.validate_for_barrier(stream_route, &barrier)
            .map_err(PairedPromotionError::Protocol)?;
        let idempotent = durable
            .activate_epoch_barrier(stream_route, &barrier)
            .map_err(|_| PairedPromotionError::Conflict)?;
        if durable.binding().stream_route != stream_route
            || durable.binding().stream_generation != barrier.stream_generation
            || durable.binding().key_directory_revision != barrier.key_directory_revision
            || durable.binding().key_id.epoch != barrier.new_epoch
            || idempotent != durable
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(CommittedEpochBarrierActivation {
            stream_binding: durable,
            ack,
            already_committed: true,
        })
    }

    /// 返回所有已通过 open-time 全库审计、仍需在连接恢复时幂等重发的 barrier receipt。
    pub(crate) fn pending_stream_applied_acks(
        &self,
    ) -> Result<Vec<StreamAppliedAckV1>, PairedPromotionError> {
        self.audited
            .state
            .durable_stream_bindings()?
            .into_iter()
            .filter_map(|binding| binding.latest_stream_applied_ack_basis().cloned())
            .map(|ack| {
                ack.validate().map_err(PairedPromotionError::Protocol)?;
                if ack.machine_route != self.audited.identity.machine_route
                    || ack.device_route != self.audited.device_route
                    || ack.grant_serial != self.audited.grant_serial
                    || ack.root_trust_epoch != self.audited.trust_epoch
                    || ack.key_directory_revision != self.audited.effective_directory_revision
                {
                    return Err(PairedPromotionError::Conflict);
                }
                Ok(ack)
            })
            .collect()
    }

    /// KeySync 专用 Reply verifier。当前 DeviceReplyTx raw key 在 same-epoch rewrap 中保持
    /// 不变，但 signed header 只允许 active request 的 known R 或 requested R+1；普通
    /// directed reply verifier 仍严格限制在当前 R，不能借此 seam 全局放宽。
    pub(crate) fn verify_key_sync_reply(
        &self,
        request: &KeySyncRequestV1,
        request_route: RequestRouteId,
        sealed_blob: &[u8],
    ) -> Result<VerifiedDirectedReply, PairedPromotionError> {
        let current_revision = self.validate_active_key_sync_request(request, request_route)?;
        let reply = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::ReplyTx { key, nonce_prefix } => {
                    Some((key, *nonce_prefix, entry.key_directory_revision))
                }
                OpenedPairedKeyMaterial::CommandTx(_)
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        if reply.2 != current_revision {
            return Err(PairedPromotionError::InvalidState);
        }
        let signed = SignedSealedBlobV1::from_wire_bytes(sealed_blob)
            .map_err(|error| PairedPromotionError::Crypto(error.into()))?;
        if signed.inner.key_id != reply.0.key_id
            || signed.inner.key_epoch != reply.0.epoch
            || signed.inner.nonce[..4] != reply.1
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let header_revision = signed.inner.key_directory_revision;
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
        if header_revision < current_revision.value() {
            return Err(PairedPromotionError::Crypto(CryptoError::E2ee(
                E2eeError::KeyRevisionRollback,
            )));
        }
        if header_revision != current_revision.value()
            && header_revision != request.requested_key_directory_revision.value()
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(VerifiedDirectedReply {
            verified,
            context,
            brand: DirectedReplyBrand {
                machine_route: self.audited.identity.machine_route,
                device_route: self.audited.device_route,
                key_id: reply.0.key_id,
                key_epoch: reply.0.epoch,
                directory_revision: header_revision,
            },
            replay_revision_ceiling: request.requested_key_directory_revision.value(),
            counter,
            signed_blob_hash,
        })
    }

    /// 只消费 KeySync verifier 产生的 candidate；AEAD open 前再次对照 durable active ADKS、
    /// exact request route 与 R/R+1 header，避免 verification 与 replay admission 之间漂移。
    pub(crate) fn open_verified_key_sync_reply(
        &self,
        request: &KeySyncRequestV1,
        candidate: VerifiedDirectedReply,
    ) -> Result<SealedPayloadV1, PairedPromotionError> {
        let request_route = candidate
            .context
            .request_route
            .ok_or(PairedPromotionError::InvalidState)?;
        let current_revision = self.validate_active_key_sync_request(request, request_route)?;
        let reply = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::ReplyTx { key, .. } => {
                    Some((key, entry.key_directory_revision))
                }
                OpenedPairedKeyMaterial::CommandTx(_)
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        let expected_context = OuterContextV1::directed_reply(
            self.audited.identity.machine_route,
            self.audited.device_route,
            request_route,
            reply.0.epoch,
        );
        let revision_allowed = candidate.brand.directory_revision == current_revision.value()
            || candidate.brand.directory_revision
                == request.requested_key_directory_revision.value();
        if reply.1 != current_revision
            || candidate.brand.machine_route != self.audited.identity.machine_route
            || candidate.brand.device_route != self.audited.device_route
            || candidate.brand.key_id != reply.0.key_id
            || candidate.brand.key_epoch != reply.0.epoch
            || !revision_allowed
            || candidate.context != expected_context
        {
            return Err(PairedPromotionError::Conflict);
        }
        open_sealed_payload(reply.0, &candidate.context, candidate.verified)
            .map_err(PairedPromotionError::Crypto)
    }

    /// 认证 durable pending Send 并返回其原始 directory revision。连续 same-epoch rewrap
    /// 只能保留同一 command key id/epoch/nonce domain；rotation 后的旧 pending 不得借此
    /// seam 使用新 key scope。签名复核也避免仅凭可解析 header 放宽 reply revision。
    fn verify_pending_directed_request_revision(
        &self,
        request_route: RequestRouteId,
        sealed_blob: &[u8],
    ) -> Result<u64, PairedPromotionError> {
        let mut matching =
            self.audited
                .opened_directory_keys
                .iter()
                .filter_map(|entry| match &entry.material {
                    OpenedPairedKeyMaterial::CommandTx(key) => Some(key),
                    OpenedPairedKeyMaterial::ReplyTx { .. }
                    | OpenedPairedKeyMaterial::StreamRx { .. } => None,
                });
        let command = matching.next().ok_or(PairedPromotionError::InvalidState)?;
        if matching.next().is_some() {
            return Err(PairedPromotionError::InvalidState);
        }
        let signed = SignedSealedBlobV1::from_wire_bytes(sealed_blob)
            .map_err(|error| PairedPromotionError::Crypto(error.into()))?;
        let request_revision = signed.inner.key_directory_revision;
        if signed.inner.key_id != command.key_id
            || signed.inner.key_epoch != command.epoch
            || request_revision == 0
            || request_revision > command.key_directory_revision
            || signed.inner.nonce[..4] != command.nonce_prefix
        {
            return Err(PairedPromotionError::Conflict);
        }
        let context = OuterContextV1::uplink_send(
            self.audited.identity.machine_route,
            self.audited.device_route,
            request_route,
            command.epoch,
        );
        let device_verifier = self.audited.device_signing_key.verifying_key();
        verify_sealed(signed, &device_verifier, &context).map_err(PairedPromotionError::Crypto)?;
        Ok(request_revision)
    }

    /// 在 replay state 之前完成 outer-correlated reply 的 canonical/header/AAD/signature 验证。
    /// daemon 可在 request revision 之后、device current revision 之前的任一 same-lineage
    /// revision 完成 reply；更旧 rollback 与 future revision 都在 replay mutation 前拒绝。
    pub(crate) fn verify_directed_reply(
        &self,
        request_route: RequestRouteId,
        request_sealed_blob: &[u8],
        reply_sealed_blob: &[u8],
    ) -> Result<VerifiedDirectedReply, PairedPromotionError> {
        let request_revision =
            self.verify_pending_directed_request_revision(request_route, request_sealed_blob)?;
        let reply = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::ReplyTx { key, nonce_prefix } => {
                    Some((key, *nonce_prefix, entry.key_directory_revision))
                }
                OpenedPairedKeyMaterial::CommandTx(_)
                | OpenedPairedKeyMaterial::StreamRx { .. } => None,
            })
            .ok_or(PairedPromotionError::InvalidState)?;
        let signed = SignedSealedBlobV1::from_wire_bytes(reply_sealed_blob)
            .map_err(|error| PairedPromotionError::Crypto(error.into()))?;
        let expected_revision = reply.2.value();
        let header_revision = signed.inner.key_directory_revision;
        if signed.inner.key_id != reply.0.key_id
            || signed.inner.key_epoch != reply.0.epoch
            || header_revision < request_revision
            || header_revision > expected_revision
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
        let signed_blob_hash = sha256(reply_sealed_blob);
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
                directory_revision: header_revision,
            },
            replay_revision_ceiling: expected_revision,
            counter,
            signed_blob_hash,
        })
    }

    /// 只接受上一步产生的 verified candidate；runtime 必须先 durable admit replay tuple。
    pub(crate) fn open_verified_directed_reply(
        &self,
        request_sealed_blob: &[u8],
        candidate: VerifiedDirectedReply,
    ) -> Result<SealedPayloadV1, PairedPromotionError> {
        let reply_key = self
            .audited
            .opened_directory_keys
            .iter()
            .find_map(|entry| match &entry.material {
                OpenedPairedKeyMaterial::ReplyTx { key, nonce_prefix } => {
                    Some((key, *nonce_prefix, entry.key_directory_revision))
                }
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
            reply_key.0.epoch,
        );
        let request_revision = self.verify_pending_directed_request_revision(
            expected_context
                .request_route
                .ok_or(PairedPromotionError::InvalidState)?,
            request_sealed_blob,
        )?;
        let expected_brand = DirectedReplyBrand {
            machine_route: self.audited.identity.machine_route,
            device_route: self.audited.device_route,
            key_id: reply_key.0.key_id,
            key_epoch: reply_key.0.epoch,
            directory_revision: candidate.brand.directory_revision,
        };
        validate_directed_reply_brand(candidate.brand, expected_brand)?;
        let header = &candidate.verified.sealed().inner;
        let current_revision = reply_key.2.value();
        if (candidate.brand.directory_revision < request_revision
            || candidate.brand.directory_revision > current_revision)
            || header.key_id != reply_key.0.key_id
            || header.key_epoch != reply_key.0.epoch
            || header.key_directory_revision != candidate.brand.directory_revision
            || header.nonce[..4] != reply_key.1
            || candidate.context != expected_context
        {
            return Err(PairedPromotionError::Conflict);
        }
        open_sealed_payload(reply_key.0, &candidate.context, candidate.verified)
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

    /// 仅供 automatic CAS harness 读回 exchange/replay/stream 三轴投影。production handle
    /// 在读取 opaque bytes 前拒绝；transfer records 故意不属于该投影，须走独立 typed API。
    #[doc(hidden)]
    pub fn automatic_runtime_projection_for_automatic_harness(
        &self,
    ) -> Result<AutomaticRuntimeProjection, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        AutomaticRuntimeProjection::from_opaque_runtime_state(
            &self.audited.state.opaque_runtime_state(),
        )
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
                PairedCryptoState::V3(_)
                    | PairedCryptoState::V4(_)
                    | PairedCryptoState::V5(_)
                    | PairedCryptoState::V6(_)
            )
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let replacement = OpaqueRuntimeState::from_automatic_legacy_v2_probe(probe);
        self.replace_opaque_runtime_state_as_legacy_v2(&replacement, rng)?
            .automatic_legacy_v2_probe()?
            .ok_or(PairedPromotionError::InvalidState)
    }

    /// Integration-only legacy migration fixture：把 current canonical V6 在 transfer
    /// collection 为空时逐字段重编码为 V5。只允许 AutomaticHarness authority；production
    /// open 永远没有此降级入口，且 cold read 本身仍保持零写。
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn rewrite_current_state_as_legacy_v5_for_automatic_harness<R: CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(), PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.refresh_mutable_state()?;
        let PairedCryptoState::V6(current) = &self.audited.state else {
            return Err(PairedPromotionError::InvalidState);
        };
        if !current.durable_transfer_records.is_empty() {
            return Err(PairedPromotionError::InvalidState);
        }
        let legacy_value = PairedCryptoStateV2 {
            initial_state_commitment: current.initial_state_commitment,
            initial_guard_commitment: current.initial_guard_commitment,
            bootstrap: current.bootstrap.clone(),
            receipt_terminal: current.receipt_terminal.clone(),
            counter_reservation: current.counter_reservation.as_ref().map(|reservation| {
                CommandCounterReservation {
                    reservation_id: reservation.reservation_id,
                    start: reservation.start,
                    end_exclusive: reservation.end_exclusive,
                }
            }),
            replay_windows: current.replay_windows.clone(),
            stream_cursors: current.stream_cursors.clone(),
            durable_key_sync_state: current.durable_key_sync_state.clone(),
            durable_key_generation_state: current.durable_key_generation_state.clone(),
            durable_transfer_records: SharedTransferRecords::empty(),
        };
        legacy_value.validate_for_version_inner(KEY_GENERATION_STATE_VERSION, true, true, true)?;
        let legacy = PairedCryptoState::V5(legacy_value);
        let PairedCryptoState::V5(value) = &legacy else {
            unreachable!("legacy fixture was just constructed as V5")
        };
        let bytes = value.encode_version_inner(KEY_GENERATION_STATE_VERSION, true, true, true)?;
        self.commit_prepared_state_transition(legacy, bytes, rng)
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

    /// Directed exchange/replay/cursor mutation 不拥有 durable transfer collection。调用方
    /// 必须提供刚才读取的三轴 expected projection；refresh/recovery 后，每一轴只接受
    /// expected 或 replacement，其他 fresh value 一律在 entropy 与 durable write 前冲突。
    /// 全部三轴已是 replacement 时是 exact retry；否则把仍处于 expected 的轴一并推进。
    /// transfer records 始终从同一份 fresh current snapshot 复制，caller 的 stale cache
    /// 无法回退已经提交的 binding/outer/inner/replay/transfer cut。
    pub(crate) fn replace_runtime_projection_preserving_transfer_records<R: CryptoRng>(
        &mut self,
        expected: &OpaqueRuntimeState,
        exchange: Option<Vec<u8>>,
        replay_windows: Vec<Vec<u8>>,
        stream_cursors: Vec<Vec<u8>>,
        rng: &mut R,
    ) -> Result<OpaqueRuntimeState, PairedPromotionError> {
        let expected_projection = OpaqueRuntimeState::new(
            expected.exchange.clone(),
            expected.replay_windows.clone(),
            expected.stream_cursors.clone(),
            Vec::new(),
        );
        expected_projection.validate()?;
        let replacement_projection =
            OpaqueRuntimeState::new(exchange, replay_windows, stream_cursors, Vec::new());
        replacement_projection.validate()?;
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;
        self.refresh_mutable_state()?;
        let current = self.audited.state.opaque_runtime_state();
        let exchange_matches = current.exchange == expected_projection.exchange
            || current.exchange == replacement_projection.exchange;
        let replay_matches = current.replay_windows == expected_projection.replay_windows
            || current.replay_windows == replacement_projection.replay_windows;
        let cursor_matches = current.stream_cursors == expected_projection.stream_cursors
            || current.stream_cursors == replacement_projection.stream_cursors;
        if !exchange_matches || !replay_matches || !cursor_matches {
            return Err(PairedPromotionError::Conflict);
        }
        if current.exchange == replacement_projection.exchange
            && current.replay_windows == replacement_projection.replay_windows
            && current.stream_cursors == replacement_projection.stream_cursors
        {
            return Ok(current);
        }
        let replacement = OpaqueRuntimeState::new_preserving_transfer_records(
            replacement_projection.exchange,
            replacement_projection.replay_windows,
            replacement_projection.stream_cursors,
            current.transfer_records,
        );
        self.replace_opaque_runtime_state_from_current(&replacement, false, rng)
    }

    /// Automatic integration harness 对 production 三轴 CAS 的唯一公开驱动入口。
    /// authority check 在 probe encoding、state read、entropy 与 durable mutation 之前完成。
    #[doc(hidden)]
    pub fn replace_runtime_projection_preserving_transfer_records_for_automatic_harness<
        R: CryptoRng,
    >(
        &mut self,
        expected: &AutomaticRuntimeProjection,
        replacement: &AutomaticRuntimeProjection,
        rng: &mut R,
    ) -> Result<AutomaticRuntimeProjection, PairedPromotionError> {
        if self.runtime_state_mutation_authority != RuntimeStateMutationAuthority::AutomaticHarness
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let expected = expected.to_opaque_runtime_state()?;
        let replacement = replacement.to_opaque_runtime_state()?;
        let committed = self.replace_runtime_projection_preserving_transfer_records(
            &expected,
            replacement.exchange,
            replacement.replay_windows,
            replacement.stream_cursors,
            rng,
        )?;
        AutomaticRuntimeProjection::from_opaque_runtime_state(&committed)
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
        self.replace_opaque_runtime_state_from_current(replacement, force_legacy_v2, rng)
    }

    /// 在 caller 已完成 refresh/recovery 与完整 CAS 判断后，基于同一份 audited snapshot
    /// 准备 mutation。这里不得再次 refresh，否则会在 CAS check 与 candidate build 之间
    /// 引入 stale overwrite 窗口；最终 state-store compare-and-replace 仍负责跨 handle 竞争。
    fn replace_opaque_runtime_state_from_current<R: CryptoRng>(
        &mut self,
        replacement: &OpaqueRuntimeState,
        force_legacy_v2: bool,
        rng: &mut R,
    ) -> Result<OpaqueRuntimeState, PairedPromotionError> {
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
        self.commit_prepared_state_transition_snapshot_with_capacity(
            next_state,
            Arc::new(CryptoStateSnapshot::new(next_state_bytes)),
            V6StateCapacityMode::Normal,
            rng,
        )
    }

    /// 与 [`Self::commit_prepared_state_transition`] 相同，但允许 private prepared token
    /// 共享同一份 exact candidate plaintext，用于 COMMIT-unknown 的逐字节 recovery 判定，
    /// 避免为了 readback 再复制一份接近 128 MiB 的 snapshot。
    fn commit_prepared_state_transition_snapshot_with_capacity<R: CryptoRng>(
        &mut self,
        next_state: PairedCryptoState,
        next_snapshot: Arc<CryptoStateSnapshot>,
        capacity_mode: V6StateCapacityMode,
        rng: &mut R,
    ) -> Result<(), PairedPromotionError> {
        if capacity_mode == V6StateCapacityMode::EmergencyBootstrapMarker {
            self.validate_v6_emergency_base_capacity()?;
        }
        self.validate_state_candidate_capacity(
            &next_state,
            next_snapshot.expose_secret().len(),
            capacity_mode,
        )?;
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

        let next_state_hash = sha256(next_snapshot.expose_secret());
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
                self.audited.state_snapshot.as_ref(),
                previous_guard_hash,
                mutation_id,
                capacity_mode,
                next_snapshot.as_ref(),
            )
            .map_err(PairedPromotionError::CryptoState)?;
        self.observe_mutation(PairedMutationStage::StateStageDurable);
        let pending = CounterGuardV2::state_pending(
            initial_guard_commitment,
            self.audited.bootstrap_directory_revision,
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
            .compare_and_replace(self.audited.state_snapshot.as_ref(), next_snapshot.as_ref())
            .map_err(PairedPromotionError::CryptoState)?;
        self.observe_mutation(PairedMutationStage::StateActiveDurable);
        self.audited.state_snapshot = next_snapshot;
        self.audited.state = next_state;

        let stable = CounterGuardV2::state_stable(
            initial_guard_commitment,
            self.audited.bootstrap_directory_revision,
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
        let preflight_end = previous_high_water
            .checked_add(COUNTER_BLOCK_SIZE)
            .ok_or(PairedPromotionError::CounterEpochExhausted)?;
        let preflight_reservation = CommandCounterReservation {
            reservation_id: [0xa5; 16],
            start: previous_high_water,
            end_exclusive: preflight_end,
        };
        let preflight_state = self.audited.state.with_counter_reservation(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            &preflight_reservation,
        )?;
        self.validate_equivalent_v6_normal_capacity(&preflight_state)?;

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
            self.audited.bootstrap_directory_revision,
            binding,
            previous_high_water,
            end_exclusive,
            reservation_id,
            current_state_hash,
            next_state_hash,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(pending))?;
        self.observe_mutation(PairedMutationStage::GuardPendingDurable);

        let next_snapshot = Arc::new(CryptoStateSnapshot::new(next_state_bytes));
        self.audited
            .state_store
            .compare_and_replace(self.audited.state_snapshot.as_ref(), next_snapshot.as_ref())
            .map_err(PairedPromotionError::CryptoState)?;
        // observer 位于 durable store 返回与内存 cache 更新之间，覆盖 committed-but-stale handle。
        self.observe_mutation(PairedMutationStage::StateDurable);
        self.audited.state_snapshot = next_snapshot;
        self.audited.state = next_state;

        let stable = CounterGuardV2::stable(
            initial_guard_commitment,
            self.audited.bootstrap_directory_revision,
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
        self.pending_recovery_context()
            .recover_counter_pending(guard)
    }

    fn recover_state_pending(&mut self, guard: CounterGuardV2) -> Result<(), PairedPromotionError> {
        self.pending_recovery_context().recover_state_pending(guard)
    }

    fn pending_recovery_context(&mut self) -> MutablePendingRecovery<'_> {
        let mutation_observer = self.mutation_observer.as_ref();
        let runtime_state_mutation_authority = self.runtime_state_mutation_authority;
        let live_transfer_candidate_capacity = self.live_transfer_candidate_capacity;
        let key_store = self.store;
        let audited = &mut self.audited;
        MutablePendingRecovery {
            state_store: &audited.state_store,
            key_store,
            counter_account: &audited.counter_account,
            counter_guard_bytes: &mut audited.counter_guard_bytes,
            counter_guard: &mut audited.counter_guard,
            state_snapshot: &mut audited.state_snapshot,
            state: &mut audited.state,
            prepared_stage: &mut audited.prepared_stage,
            marker: &audited.marker,
            mutation_observer,
            runtime_state_mutation_authority,
            live_transfer_candidate_capacity,
        }
    }

    fn clear_authenticated_prepared_stage(&mut self) -> Result<(), PairedPromotionError> {
        let Some(prepared) = self.audited.prepared_stage.as_ref() else {
            return Ok(());
        };
        self.audited
            .state_store
            .clear_prepared_stage_exact(prepared)
            .map_err(PairedPromotionError::CryptoState)?;
        self.audited.prepared_stage = None;
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
        let loaded_state_snapshot = self
            .audited
            .state_store
            .load()
            .map_err(PairedPromotionError::CryptoState)?
            .ok_or(PairedPromotionError::Incomplete)?;
        // Production Runtime hot paths refresh before every CAS。exact-equal load 已完成
        // file/AEAD 验证，不能在旧 128 MiB snapshot + decoded records 仍存活时再无条件
        // decode 一份；相同 plaintext 立即释放 fresh load，复用已审计 state/records。
        // AutomaticHarness 能故意写入 validate_transfer=false 的 malformed cache，因此禁用
        // 快路，保持下一次同 handle refresh 也必须 canonical decode 后 fail-close。
        let refreshed_state =
            if self.runtime_state_mutation_authority == RuntimeStateMutationAuthority::Production {
                decode_changed_state_snapshot(
                    self.audited.state_snapshot.as_ref(),
                    loaded_state_snapshot,
                )?
            } else {
                let state = PairedCryptoState::decode(loaded_state_snapshot.expose_secret())?;
                Some((state, loaded_state_snapshot))
            };
        let prepared_stage = self
            .audited
            .state_store
            .load_prepared_stage()
            .map_err(PairedPromotionError::CryptoState)?;
        let (state, state_snapshot) = match &refreshed_state {
            Some((state, snapshot)) => (state, snapshot),
            None => (&self.audited.state, self.audited.state_snapshot.as_ref()),
        };
        self.audited.marker.validate_state(
            self.audited.identity,
            state,
            state_snapshot.expose_secret(),
        )?;
        let inventories = audit_key_generation_state_and_stage(
            state,
            prepared_stage.as_ref(),
            state.bootstrap(),
            &self.audited.device_hpke_private_key,
            &self.audited.machine_data_verifying_key,
            &self.audited.machine_data_signer_binding,
            &self.audited.opened_directory_keys,
        )?;
        let effective_directory_revision = state.effective_directory_revision()?;
        let opened_keys = inventories
            .active
            .as_deref()
            .unwrap_or(&self.audited.opened_directory_keys);
        validate_typed_stream_state_and_stage(
            state,
            prepared_stage.as_ref(),
            StreamBindingAuditContext {
                identity: self.audited.identity,
                device_route: self.audited.device_route,
                grant_serial: self.audited.grant_serial,
                trust_epoch: self.audited.trust_epoch,
                bootstrap_directory_revision: self.audited.bootstrap_directory_revision,
                effective_directory_revision: self.audited.effective_directory_revision,
            },
            &self.audited.authorization,
            opened_keys,
            inventories.prepared.as_deref(),
        )?;
        validate_counter_guard_state(
            &self.audited.marker,
            self.audited.identity,
            &counter_guard,
            counter_guard_bytes.expose_secret(),
            state,
            state_snapshot.expose_secret(),
            prepared_stage.as_ref(),
            self.audited.device_command_binding,
            self.runtime_state_mutation_authority,
            self.live_transfer_candidate_capacity,
        )?;
        self.audited.counter_guard_bytes = counter_guard_bytes;
        self.audited.counter_guard = counter_guard;
        if let Some((state, state_snapshot)) = refreshed_state {
            self.audited.state_snapshot = Arc::new(state_snapshot);
            self.audited.state = state;
        }
        self.audited.prepared_stage = prepared_stage;
        self.audited.effective_directory_revision = effective_directory_revision;
        if let Some(active_keys) = inventories.active {
            self.audited.opened_directory_keys = active_keys;
        }
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

/// Pending recovery 的最小 durable tuple。production `OpenedPairedMachine` 与 unit
/// crash harness 共用同一实现，避免 validator-only 测试与真实 guard/state CAS 漂移。
struct MutablePendingRecovery<'a> {
    state_store: &'a FileCryptoStateStore,
    key_store: &'a dyn RemoteKeyStore,
    counter_account: &'a RemoteKeyAccount,
    counter_guard_bytes: &'a mut RemoteSecret,
    counter_guard: &'a mut CounterGuardState,
    state_snapshot: &'a mut Arc<CryptoStateSnapshot>,
    state: &'a mut PairedCryptoState,
    prepared_stage: &'a mut Option<PreparedCryptoStateStage>,
    marker: &'a PairedCommitMarkerV1,
    mutation_observer: Option<&'a Arc<dyn PairedMutationObserver>>,
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
}

impl MutablePendingRecovery<'_> {
    fn validate_equivalent_v6_normal_capacity(
        &self,
        state: &PairedCryptoState,
    ) -> Result<(), PairedPromotionError> {
        validate_equivalent_v6_normal_capacity_with_context(
            self.runtime_state_mutation_authority,
            self.live_transfer_candidate_capacity,
            state,
        )
    }

    fn validate_state_candidate_capacity(
        &self,
        state: &PairedCryptoState,
        encoded_len: usize,
        mode: V6StateCapacityMode,
    ) -> Result<(), PairedPromotionError> {
        validate_state_candidate_capacity_with_context(
            self.runtime_state_mutation_authority,
            self.live_transfer_candidate_capacity,
            state,
            encoded_len,
            mode,
        )
    }

    fn observe_mutation(&self, stage: PairedMutationStage) {
        if let Some(observer) = self.mutation_observer {
            observer.after_stage(stage);
        }
    }

    fn replace_counter_guard(
        &mut self,
        replacement: CounterGuardState,
    ) -> Result<(), PairedPromotionError> {
        let replacement_bytes = replacement.encode();
        self.key_store
            .compare_and_replace_exact(
                self.counter_account,
                self.counter_guard_bytes,
                &RemoteSecret::new(replacement_bytes.clone()),
            )
            .map_err(PairedPromotionError::Persistence)?;
        *self.counter_guard_bytes = RemoteSecret::new(replacement_bytes);
        *self.counter_guard = replacement;
        Ok(())
    }

    fn clear_authenticated_prepared_stage(&mut self) -> Result<(), PairedPromotionError> {
        let Some(prepared) = self.prepared_stage.as_ref() else {
            return Ok(());
        };
        self.state_store
            .clear_prepared_stage_exact(prepared)
            .map_err(PairedPromotionError::CryptoState)?;
        *self.prepared_stage = None;
        self.observe_mutation(PairedMutationStage::StateStageCleared);
        Ok(())
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
        let mut current_hash = sha256(self.state_snapshot.expose_secret());
        let expected = CommandCounterReservation {
            reservation_id,
            start: previous_high_water,
            end_exclusive: next_high_water,
        };
        expected.validate()?;
        if current_hash == next_state_hash {
            if self.state.counter_reservation() != Some(&expected) {
                return Err(PairedPromotionError::Conflict);
            }
            self.validate_equivalent_v6_normal_capacity(self.state)?;
        } else if current_hash == previous_state_hash {
            // guard-first 已经让整块不可复用。用 pending 中冻结的同一 reservation 重建
            // canonical next state，写成 sealed counter fence，但绝不把该块返回给调用方。
            let (skipped_state, skipped_snapshot) =
                rebuild_frozen_counter_state(self.marker, self.state, expected, next_state_hash)?;
            self.validate_equivalent_v6_normal_capacity(&skipped_state)?;
            self.state_store
                .compare_and_replace(self.state_snapshot.as_ref(), &skipped_snapshot)
                .map_err(PairedPromotionError::CryptoState)?;
            self.observe_mutation(PairedMutationStage::RecoveryStateDurable);
            *self.state_snapshot = Arc::new(skipped_snapshot);
            *self.state = skipped_state;
            current_hash = next_state_hash;
        } else {
            return Err(PairedPromotionError::Conflict);
        }

        let stable = CounterGuardV2::stable(
            guard.initial_guard_commitment,
            guard.directory_revision,
            guard.binding,
            next_high_water,
            current_hash,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(stable))
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
        {
            let prepared = self
                .prepared_stage
                .as_ref()
                .ok_or(PairedPromotionError::Conflict)?;
            if prepared.mutation_id() != mutation_id
                || prepared.previous_guard_hash() != previous_guard_hash
                || prepared.previous_state_hash() != previous_state_hash
                || prepared.next_state_hash() != next_state_hash
                || prepared.sealed_commitment() != stage_commitment
            {
                return Err(PairedPromotionError::Conflict);
            }
        }
        let current_hash = sha256(self.state_snapshot.expose_secret());
        if current_hash == previous_state_hash {
            let prepared = self
                .prepared_stage
                .as_ref()
                .ok_or(PairedPromotionError::Conflict)?;
            let capacity_mode = prepared.capacity_mode();
            let next_snapshot = prepared.shared_snapshot();
            let next_state = PairedCryptoState::decode(next_snapshot.expose_secret())?;
            if capacity_mode == V6StateCapacityMode::EmergencyBootstrapMarker {
                self.validate_equivalent_v6_normal_capacity(self.state)?;
            }
            self.validate_state_candidate_capacity(
                &next_state,
                next_snapshot.expose_secret().len(),
                capacity_mode,
            )?;
            self.state_store
                .compare_and_replace(self.state_snapshot.as_ref(), next_snapshot.as_ref())
                .map_err(PairedPromotionError::CryptoState)?;
            self.observe_mutation(PairedMutationStage::StateRecoveryActiveDurable);
            *self.state_snapshot = next_snapshot;
            *self.state = next_state;
        } else {
            let prepared = self
                .prepared_stage
                .as_ref()
                .ok_or(PairedPromotionError::Conflict)?;
            if current_hash != next_state_hash
                || self.state_snapshot.expose_secret() != prepared.snapshot().expose_secret()
            {
                return Err(PairedPromotionError::Conflict);
            }
            self.validate_state_candidate_capacity(
                self.state,
                self.state_snapshot.expose_secret().len(),
                prepared.capacity_mode(),
            )?;
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
        self.clear_authenticated_prepared_stage()
    }
}

fn decode_changed_state_snapshot(
    current: &CryptoStateSnapshot,
    loaded: CryptoStateSnapshot,
) -> Result<Option<(PairedCryptoState, CryptoStateSnapshot)>, PairedPromotionError> {
    if loaded.expose_secret() == current.expose_secret() {
        return Ok(None);
    }
    let state = PairedCryptoState::decode(loaded.expose_secret())?;
    Ok(Some((state, loaded)))
}

/// 当前 installation 的 marker-backed paired machine 只读恢复入口。
pub struct PairedMachineStore<'a> {
    store: &'a dyn RemoteKeyStore,
    installation_id: Uuid,
    state_root: PathBuf,
    mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
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
            LiveTransferCandidateCapacity::PRODUCTION,
        )
    }

    /// 默认 integration gate 专用的 lowered-cap Production constructor。它只缩小 live
    /// transfer replacement candidate 的 plaintext budget；replay/ACK preserving preflight
    /// 仍使用完整 128 MiB hard cap。该值不持久化，production CLI/env/config 不可达。
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn new_with_production_transfer_candidate_limit_for_automatic_harness(
        store: &'a dyn RemoteKeyStore,
        installation_id: Uuid,
        state_root: &Path,
        plaintext_limit: usize,
    ) -> Result<Self, PairedPromotionError> {
        let capacity =
            LiveTransferCandidateCapacity::lowered_for_automatic_harness(plaintext_limit)?;
        Ok(Self::new_inner(
            store,
            installation_id,
            state_root,
            None,
            RuntimeStateMutationAuthority::Production,
            capacity,
        ))
    }

    /// 与 lowered-cap Production constructor 相同，但附带一次性 mutation observer，供
    /// integration gate 固定 emergency CAS 的 crash/COMMIT-unknown cut。observer 不改变
    /// Production authority，也不开放 runtime-state probe write capability。
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn new_with_production_transfer_candidate_limit_and_mutation_observer_for_automatic_harness(
        store: &'a dyn RemoteKeyStore,
        installation_id: Uuid,
        state_root: &Path,
        plaintext_limit: usize,
        observer: Arc<dyn PairedMutationObserver>,
    ) -> Result<Self, PairedPromotionError> {
        let capacity =
            LiveTransferCandidateCapacity::lowered_for_automatic_harness(plaintext_limit)?;
        Ok(Self::new_inner(
            store,
            installation_id,
            state_root,
            Some(observer),
            RuntimeStateMutationAuthority::Production,
            capacity,
        ))
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
            LiveTransferCandidateCapacity::PRODUCTION,
        )
    }

    fn new_inner(
        store: &'a dyn RemoteKeyStore,
        installation_id: Uuid,
        state_root: &Path,
        mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
        runtime_state_mutation_authority: RuntimeStateMutationAuthority,
        live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
    ) -> Self {
        Self {
            store,
            installation_id,
            state_root: state_root.to_path_buf(),
            mutation_observer,
            runtime_state_mutation_authority,
            live_transfer_candidate_capacity,
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
            self.live_transfer_candidate_capacity,
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

        let mut audit = audit_durable_state(
            bootstrap,
            grant_secret.expose_secret(),
            &device_sign_secret,
            &device_hpke_secret,
        )?;
        let inventories = audit_key_generation_state_and_stage(
            &state,
            prepared_stage.as_ref(),
            bootstrap,
            &audit.device_hpke_private_key,
            &audit.machine_data_verifying_key,
            &audit.machine_data_signer_binding,
            &audit.opened_keys,
        )?;
        if let Some(active_keys) = inventories.active {
            audit.opened_keys = active_keys;
        }
        validate_typed_stream_state_and_stage(
            &state,
            prepared_stage.as_ref(),
            StreamBindingAuditContext {
                identity,
                device_route: bootstrap.device_route,
                grant_serial: bootstrap.grant_serial,
                trust_epoch: bootstrap.trust_epoch,
                bootstrap_directory_revision: bootstrap.directory_revision,
                effective_directory_revision: state.effective_directory_revision()?,
            },
            &audit.authorization,
            &audit.opened_keys,
            inventories.prepared.as_deref(),
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
            self.runtime_state_mutation_authority,
            self.live_transfer_candidate_capacity,
        )?;
        let effective_directory_revision = state.effective_directory_revision()?;

        Ok(AuditedPairedMachine {
            identity,
            machine_display_name: bootstrap.machine_display_name.clone(),
            wss_url: bootstrap.wss_url.clone(),
            device_route: bootstrap.device_route,
            grant_serial: bootstrap.grant_serial,
            trust_epoch: bootstrap.trust_epoch,
            bootstrap_directory_revision: bootstrap.directory_revision,
            effective_directory_revision,
            relay_server_id: bootstrap.relay_server_id,
            current_spki_pin: bootstrap.current_spki_pin,
            next_spki_pin: bootstrap.next_spki_pin,
            _canonical_receipt_carrier: bootstrap.receipt_carrier.clone(),
            state_store,
            state_snapshot: Arc::new(state_snapshot),
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
            machine_data_signer_binding: audit.machine_data_signer_binding,
            device_hpke_private_key: audit.device_hpke_private_key,
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
        let mut audit = audit_state(
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
        let inventories = audit_key_generation_state_and_stage(
            &state,
            prepared_stage.as_ref(),
            bootstrap,
            &audit.device_hpke_private_key,
            &audit.machine_data_verifying_key,
            &audit.machine_data_signer_binding,
            &audit.opened_keys,
        )?;
        if let Some(active_keys) = inventories.active {
            audit.opened_keys = active_keys;
        }
        validate_typed_stream_state_and_stage(
            &state,
            prepared_stage.as_ref(),
            StreamBindingAuditContext {
                identity,
                device_route: bootstrap.device_route,
                grant_serial: bootstrap.grant_serial,
                trust_epoch: bootstrap.trust_epoch,
                bootstrap_directory_revision: bootstrap.directory_revision,
                effective_directory_revision: state.effective_directory_revision()?,
            },
            verified.device_authorization(),
            &audit.opened_keys,
            inventories.prepared.as_deref(),
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
            RuntimeStateMutationAuthority::Production,
            LiveTransferCandidateCapacity::PRODUCTION,
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
        let mut durable = audit_durable_state(
            state.bootstrap(),
            grant.expose_secret(),
            device_sign,
            device_hpke,
        )?;
        let bootstrap = state.bootstrap();
        let inventories = audit_key_generation_state_and_stage(
            &state,
            None,
            bootstrap,
            &durable.device_hpke_private_key,
            &durable.machine_data_verifying_key,
            &durable.machine_data_signer_binding,
            &durable.opened_keys,
        )?;
        if let Some(active_keys) = inventories.active {
            durable.opened_keys = active_keys;
        }
        validate_typed_stream_state_and_stage(
            &state,
            None,
            StreamBindingAuditContext {
                identity,
                device_route: bootstrap.device_route,
                grant_serial: bootstrap.grant_serial,
                trust_epoch: bootstrap.trust_epoch,
                bootstrap_directory_revision: bootstrap.directory_revision,
                effective_directory_revision: state.effective_directory_revision()?,
            },
            &durable.authorization,
            &durable.opened_keys,
            inventories.prepared.as_deref(),
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
            RuntimeStateMutationAuthority::Production,
            LiveTransferCandidateCapacity::PRODUCTION,
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

struct DurableStateAudit {
    device_signing_key: SigningKey,
    machine_data_verifying_key: VerifyingKey,
    machine_data_signer_binding: MachineDataSignerBindingV1,
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
) -> Result<DurableStateAudit, PairedPromotionError> {
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

    audit_durable_state(state, grant_bytes, device_sign_secret, device_hpke_secret)
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
            key_directory_revision: directory.revision,
            material,
        });
    }
    if !reply_key_seen {
        return Err(PairedPromotionError::InvalidState);
    }

    Ok(DurableStateAudit {
        device_signing_key: signing_key,
        machine_data_verifying_key: data_verifier,
        machine_data_signer_binding: signer,
        device_hpke_private_key: hpke_private,
        grant,
        authorization,
        opened_keys,
        device_command_binding: command_binding.ok_or(PairedPromotionError::InvalidState)?,
    })
}

fn open_durable_generation(
    bootstrap: &PairedCryptoStateV1,
    device_hpke_private_key: &HpkePrivateKey,
    machine_data_verifying_key: &VerifyingKey,
    machine_data_signer_binding: &MachineDataSignerBindingV1,
    generation: &DurableKeyGenerationV1,
) -> Result<SecretAeadKey, PairedPromotionError> {
    if generation.device_route() != bootstrap.device_route {
        return Err(PairedPromotionError::Conflict);
    }
    let info = KeyUpdateInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: bootstrap.relay_server_id,
        machine_route: bootstrap.machine_route,
        device_route: bootstrap.device_route,
        stream_route: generation.stream_route(),
        grant_serial: bootstrap.grant_serial,
        root_trust_epoch: bootstrap.trust_epoch,
        key_directory_revision: generation.key_directory_revision(),
        key_purpose: generation.key_id().purpose,
        key_epoch: generation.key_id().epoch,
    };
    match generation.carrier() {
        DurableKeyCarrierV1::BootstrapEntry => {
            if generation.key_directory_revision() != bootstrap.directory_revision {
                return Err(PairedPromotionError::Conflict);
            }
            let directory = KeyDirectoryV1::from_canonical_bytes(&bootstrap.key_directory)
                .map_err(PairedPromotionError::Protocol)?;
            let mut matching = directory.entries.iter().filter(|entry| {
                entry.device_route == generation.device_route()
                    && entry.key_id == generation.key_id()
                    && entry.stream_route == generation.stream_route()
            });
            let entry = matching.next().ok_or(PairedPromotionError::Conflict)?;
            if matching.next().is_some() {
                return Err(PairedPromotionError::Conflict);
            }
            open_key_directory_entry(
                device_hpke_private_key,
                &info,
                &key_update_context(&info),
                entry,
            )
            .map_err(PairedPromotionError::Crypto)
        }
        DurableKeyCarrierV1::Update(update) => open_key_update(
            device_hpke_private_key,
            machine_data_verifying_key,
            machine_data_signer_binding,
            &info,
            &key_update_context(&info),
            update,
        )
        .map(|opened| opened.into_key())
        .map_err(PairedPromotionError::Crypto),
    }
}

fn directed_generation_matches_active(
    active: &[OpenedPairedDirectoryKey],
    generation: &DurableKeyGenerationV1,
    candidate: &SecretAeadKey,
) -> Result<(), PairedPromotionError> {
    let mut matches = active.iter().filter(|entry| {
        entry.key_id.purpose == generation.key_id().purpose && entry.stream_route.is_none()
    });
    let existing = matches.next().ok_or(PairedPromotionError::Conflict)?;
    if matches.next().is_some() || existing.key_id.epoch != generation.key_id().epoch {
        return Err(PairedPromotionError::Conflict);
    }
    let same = match &existing.material {
        OpenedPairedKeyMaterial::CommandTx(key)
            if generation.key_id().purpose == KeyPurpose::DeviceCommandTx =>
        {
            key.matches_secret(candidate)
        }
        OpenedPairedKeyMaterial::ReplyTx { key, .. }
            if generation.key_id().purpose == KeyPurpose::DeviceReplyTx =>
        {
            key.matches_secret(candidate)
        }
        OpenedPairedKeyMaterial::CommandTx(_)
        | OpenedPairedKeyMaterial::ReplyTx { .. }
        | OpenedPairedKeyMaterial::StreamRx { .. } => false,
    };
    if same {
        Ok(())
    } else {
        Err(PairedPromotionError::Conflict)
    }
}

/// 消费 exact transition validator 的 typed token，并在 durable mutation 前完成所有
/// DeviceHPKE raw-key relation。normal UpdateSet 的每个 replacement 必须彼此唯一；只有
/// shared same-epoch rewrap 与 directed rewrap 可以和同一旧 slot 的 current key 相同。
fn validate_normal_update_raw_relations(
    previous: &DurableKeyGenerationStateV1,
    candidate: &DurableKeyGenerationStateV1,
    update_set: &agentdeck_protocol::e2ee::KeyUpdateSetV1,
    bootstrap: &PairedCryptoStateV1,
    device_hpke_private_key: &HpkePrivateKey,
    machine_data_verifying_key: &VerifyingKey,
    machine_data_signer_binding: &MachineDataSignerBindingV1,
) -> Result<(), PairedPromotionError> {
    let metadata = validate_normal_update_transition(previous, candidate, update_set)
        .map_err(|_| PairedPromotionError::Conflict)?;

    struct ComparableKey {
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
        current: bool,
        key: AeadReceivingKey,
    }

    let mut previous_keys = Vec::with_capacity(previous.slots().len());
    for slot in previous.slots() {
        for generation in slot.retired() {
            let key = open_durable_generation(
                bootstrap,
                device_hpke_private_key,
                machine_data_verifying_key,
                machine_data_signer_binding,
                generation,
            )?;
            previous_keys.push(ComparableKey {
                purpose: generation.key_id().purpose,
                stream_route: generation.stream_route(),
                current: false,
                key: AeadReceivingKey::new(generation.key_id(), generation.key_id().epoch, key),
            });
        }
        let generation = slot.current();
        let key = open_durable_generation(
            bootstrap,
            device_hpke_private_key,
            machine_data_verifying_key,
            machine_data_signer_binding,
            generation,
        )?;
        previous_keys.push(ComparableKey {
            purpose: generation.key_id().purpose,
            stream_route: generation.stream_route(),
            current: true,
            key: AeadReceivingKey::new(generation.key_id(), generation.key_id().epoch, key),
        });
    }

    let mut replacement_keys: Vec<ComparableKey> = Vec::with_capacity(update_set.updates.len());
    for update in &update_set.updates {
        let replacement = DurableKeyGenerationV1::from_update(update.clone())
            .map_err(|_| PairedPromotionError::Conflict)?;
        let purpose = replacement.key_id().purpose;
        let stream_route = replacement.stream_route();
        let allow_same_slot = match purpose {
            KeyPurpose::Catalog | KeyPurpose::ConversationDek => {
                let shared = metadata
                    .shared()
                    .iter()
                    .find(|entry| {
                        entry.identity().purpose() == purpose
                            && entry.identity().stream_route() == stream_route
                    })
                    .ok_or(PairedPromotionError::Conflict)?;
                if shared.replacement() != &replacement {
                    return Err(PairedPromotionError::Conflict);
                }
                match shared.kind() {
                    SharedUpdateMetadataKindV1::RewrapSameEpoch => {
                        shared.previous_current().is_some()
                    }
                    SharedUpdateMetadataKindV1::RotateNextEpoch
                    | SharedUpdateMetadataKindV1::AddConversation => false,
                }
            }
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
                let directed = metadata
                    .directed()
                    .iter()
                    .find(|(_, after)| after.key_id().purpose == purpose)
                    .ok_or(PairedPromotionError::Conflict)?;
                if directed.1 != &replacement {
                    return Err(PairedPromotionError::Conflict);
                }
                true
            }
        };
        let opened = open_durable_generation(
            bootstrap,
            device_hpke_private_key,
            machine_data_verifying_key,
            machine_data_signer_binding,
            &replacement,
        )?;

        let mut matching_previous = previous_keys
            .iter()
            .filter(|entry| entry.key.matches_secret(&opened));
        let first_match = matching_previous.next();
        let duplicate_previous = matching_previous.next().is_some();
        if duplicate_previous
            || first_match.is_some() != allow_same_slot
            || allow_same_slot
                && first_match.is_none_or(|entry| {
                    !entry.current || entry.purpose != purpose || entry.stream_route != stream_route
                })
            || replacement_keys
                .iter()
                .any(|entry| entry.key.matches_secret(&opened))
        {
            return Err(PairedPromotionError::Conflict);
        }
        replacement_keys.push(ComparableKey {
            purpose,
            stream_route,
            current: true,
            key: AeadReceivingKey::new(replacement.key_id(), replacement.key_id().epoch, opened),
        });
    }
    Ok(())
}

fn rewrap_stream_bindings_for_normal_update(
    previous: &DurableKeyGenerationStateV1,
    candidate: &DurableKeyGenerationStateV1,
    update_set: &agentdeck_protocol::e2ee::KeyUpdateSetV1,
    bindings: Vec<DurableStreamBindingV1>,
) -> Result<Vec<DurableStreamBindingV1>, PairedPromotionError> {
    let metadata = validate_normal_update_transition(previous, candidate, update_set)
        .map_err(|_| PairedPromotionError::Conflict)?;
    bindings
        .into_iter()
        .map(|binding| {
            let current = binding.binding();
            let slot_route = stream_key_slot_route(current.key_id, current.stream_route)?;
            let update = metadata
                .shared()
                .iter()
                .find(|entry| {
                    entry.identity().purpose() == current.key_id.purpose
                        && entry.identity().stream_route() == slot_route
                })
                .ok_or(PairedPromotionError::Conflict)?;
            let previous_current = update
                .previous_current()
                .ok_or(PairedPromotionError::Conflict)?;
            if current.key_id != previous_current.key_id()
                || current.key_directory_revision != previous_current.key_directory_revision()
            {
                return Err(PairedPromotionError::Conflict);
            }
            match update.kind() {
                SharedUpdateMetadataKindV1::RewrapSameEpoch => binding
                    .with_rewrapped_key_revision(update_set.key_directory_revision)
                    .map_err(|_| PairedPromotionError::Conflict),
                SharedUpdateMetadataKindV1::RotateNextEpoch => binding
                    .with_superseded_stream_applied_ack()
                    .map_err(|_| PairedPromotionError::Conflict),
                SharedUpdateMetadataKindV1::AddConversation => Err(PairedPromotionError::Conflict),
            }
        })
        .collect()
}

/// 对 ADKG 中所有 current/staged/retired carrier 做完整 MachineDataSign + DeviceHPKE
/// 审计；只把 current generation 铸造成 active crypto capability。V5-A 对 directed staged
/// recovery shape 保持 fail-close；V5-B 激活前仍须同 epoch、同 raw key。
fn audit_key_generation_state(
    state: &DurableKeyGenerationStateV1,
    bootstrap: &PairedCryptoStateV1,
    device_hpke_private_key: &HpkePrivateKey,
    machine_data_verifying_key: &VerifyingKey,
    machine_data_signer_binding: &MachineDataSignerBindingV1,
    active: &[OpenedPairedDirectoryKey],
) -> Result<Vec<OpenedPairedDirectoryKey>, PairedPromotionError> {
    if state.bootstrap_directory_revision() != bootstrap.directory_revision
        || state.effective_directory_revision() <= bootstrap.directory_revision
        || state.device_route() != bootstrap.device_route
    {
        return Err(PairedPromotionError::Conflict);
    }
    let mut opened = Vec::with_capacity(state.slots().len());
    for slot in state.slots() {
        let purpose = slot.identity().purpose();
        for retained in slot.retired() {
            drop(open_durable_generation(
                bootstrap,
                device_hpke_private_key,
                machine_data_verifying_key,
                machine_data_signer_binding,
                retained,
            )?);
        }
        if let Some(staged) = slot.staged() {
            drop(open_durable_generation(
                bootstrap,
                device_hpke_private_key,
                machine_data_verifying_key,
                machine_data_signer_binding,
                staged,
            )?);
        }

        let current = slot.current();
        let key = open_durable_generation(
            bootstrap,
            device_hpke_private_key,
            machine_data_verifying_key,
            machine_data_signer_binding,
            current,
        )?;
        if matches!(
            purpose,
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx
        ) {
            if current.key_directory_revision() != state.effective_directory_revision() {
                return Err(PairedPromotionError::Conflict);
            }
            directed_generation_matches_active(active, current, &key)?;
        }
        let nonce_prefix = agentdeck_crypto::derive_nonce_prefix(&key);
        let material = match purpose {
            KeyPurpose::DeviceCommandTx => {
                OpenedPairedKeyMaterial::CommandTx(AeadSendingKey::with_derived_nonce_prefix(
                    current.key_id(),
                    current.key_id().epoch,
                    current.key_directory_revision().value(),
                    key,
                ))
            }
            KeyPurpose::DeviceReplyTx => OpenedPairedKeyMaterial::ReplyTx {
                key: AeadReceivingKey::new(current.key_id(), current.key_id().epoch, key),
                nonce_prefix,
            },
            KeyPurpose::Catalog | KeyPurpose::ConversationDek => {
                OpenedPairedKeyMaterial::StreamRx {
                    key: AeadReceivingKey::new(current.key_id(), current.key_id().epoch, key),
                    nonce_prefix,
                }
            }
        };
        opened.push(OpenedPairedDirectoryKey {
            key_id: current.key_id(),
            stream_route: current.stream_route(),
            key_directory_revision: current.key_directory_revision(),
            material,
        });
    }
    Ok(opened)
}

struct AuditedKeyGenerationInventories {
    active: Option<Vec<OpenedPairedDirectoryKey>>,
    prepared: Option<Vec<OpenedPairedDirectoryKey>>,
}

fn audit_key_generation_state_and_stage(
    state: &PairedCryptoState,
    prepared_stage: Option<&PreparedCryptoStateStage>,
    bootstrap: &PairedCryptoStateV1,
    device_hpke_private_key: &HpkePrivateKey,
    machine_data_verifying_key: &VerifyingKey,
    machine_data_signer_binding: &MachineDataSignerBindingV1,
    bootstrap_active: &[OpenedPairedDirectoryKey],
) -> Result<AuditedKeyGenerationInventories, PairedPromotionError> {
    let active_generation = state.durable_key_generation_state()?;
    let active_keys = active_generation
        .as_ref()
        .map(|generation| {
            audit_key_generation_state(
                generation,
                bootstrap,
                device_hpke_private_key,
                machine_data_verifying_key,
                machine_data_signer_binding,
                bootstrap_active,
            )
        })
        .transpose()?;
    let mut prepared_keys = None;
    if let Some(prepared) = prepared_stage {
        let next = PairedCryptoState::decode(prepared.snapshot().expose_secret())?;
        let next_generation = next.durable_key_generation_state()?;
        let active_key_sync = state.durable_key_sync_state()?;
        let next_key_sync = next.durable_key_sync_state()?;
        let key_sync_advanced = match (&active_key_sync, &next_key_sync) {
            (Some(previous), Some(candidate)) => {
                candidate.current_known_key_directory_revision()
                    > previous.current_known_key_directory_revision()
            }
            (None, Some(candidate)) => {
                candidate.current_known_key_directory_revision() > bootstrap.directory_revision
            }
            (Some(_), None) => return Err(PairedPromotionError::Conflict),
            (None, None) => false,
        };
        match (&active_generation, &next_generation) {
            (Some(previous), Some(candidate)) => {
                if previous != candidate {
                    if key_sync_advanced {
                        let update_set = candidate
                            .staged_normal_update_set()
                            .map_err(|_| PairedPromotionError::Conflict)?;
                        validate_normal_update_raw_relations(
                            previous,
                            candidate,
                            &update_set,
                            bootstrap,
                            device_hpke_private_key,
                            machine_data_verifying_key,
                            machine_data_signer_binding,
                        )?;
                    } else {
                        validate_directed_rewrap_metadata(previous, candidate)
                            .map_err(|_| PairedPromotionError::Conflict)?;
                    }
                }
            }
            (None, Some(candidate)) => {
                if key_sync_advanced {
                    let directory = KeyDirectoryV1::from_canonical_bytes(&bootstrap.key_directory)
                        .map_err(PairedPromotionError::Protocol)?;
                    let previous =
                        DurableKeyGenerationStateV1::from_bootstrap_directory(&directory)
                            .map_err(|_| PairedPromotionError::Conflict)?;
                    let update_set = candidate
                        .staged_normal_update_set()
                        .map_err(|_| PairedPromotionError::Conflict)?;
                    validate_normal_update_raw_relations(
                        &previous,
                        candidate,
                        &update_set,
                        bootstrap,
                        device_hpke_private_key,
                        machine_data_verifying_key,
                        machine_data_signer_binding,
                    )?;
                }
            }
            (Some(_), None) => return Err(PairedPromotionError::Conflict),
            (None, None) => {
                return Ok(AuditedKeyGenerationInventories {
                    active: active_keys,
                    prepared: None,
                });
            }
        }
        if let Some(candidate) = next_generation.as_ref() {
            let current = active_keys.as_deref().unwrap_or(bootstrap_active);
            prepared_keys = Some(audit_key_generation_state(
                candidate,
                bootstrap,
                device_hpke_private_key,
                machine_data_verifying_key,
                machine_data_signer_binding,
                current,
            )?);
        }
    }
    Ok(AuditedKeyGenerationInventories {
        active: active_keys,
        prepared: prepared_keys,
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
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
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
                runtime_state_mutation_authority,
                live_transfer_candidate_capacity,
            )
        }
        (CounterGuardState::V1(_), PairedCryptoState::V1(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V2(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V3(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V4(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V5(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V6(_)) => Err(PairedPromotionError::Conflict),
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
                        runtime_state_mutation_authority,
                        live_transfer_candidate_capacity,
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
                        runtime_state_mutation_authority,
                        live_transfer_candidate_capacity,
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
                    let (candidate, _) =
                        rebuild_frozen_counter_state(marker, state, expected, next_state_hash)?;
                    validate_equivalent_v6_normal_capacity_with_context(
                        runtime_state_mutation_authority,
                        live_transfer_candidate_capacity,
                        &candidate,
                    )?;
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
                        validate_equivalent_v6_normal_capacity_with_context(
                            runtime_state_mutation_authority,
                            live_transfer_candidate_capacity,
                            state,
                        )
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
                    runtime_state_mutation_authority,
                    live_transfer_candidate_capacity,
                ),
                _ => Err(PairedPromotionError::Conflict),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_uncommitted_orphan_stage(
    marker: &PairedCommitMarkerV1,
    identity: PairedMachineIdentity,
    guard_bytes: &[u8],
    active: &PairedCryptoState,
    active_bytes: &[u8],
    reserved_high_water: u64,
    prepared_stage: Option<&PreparedCryptoStateStage>,
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
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
    if stage.capacity_mode() == V6StateCapacityMode::EmergencyBootstrapMarker {
        validate_equivalent_v6_normal_capacity_with_context(
            runtime_state_mutation_authority,
            live_transfer_candidate_capacity,
            active,
        )?;
    }
    validate_state_candidate_capacity_with_context(
        runtime_state_mutation_authority,
        live_transfer_candidate_capacity,
        &next,
        stage.snapshot().expose_secret().len(),
        stage.capacity_mode(),
    )?;
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
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
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
    validate_state_candidate_capacity_with_context(
        runtime_state_mutation_authority,
        live_transfer_candidate_capacity,
        &next,
        stage.snapshot().expose_secret().len(),
        stage.capacity_mode(),
    )?;
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
        if stage.capacity_mode() == V6StateCapacityMode::EmergencyBootstrapMarker {
            validate_equivalent_v6_normal_capacity_with_context(
                runtime_state_mutation_authority,
                live_transfer_candidate_capacity,
                active,
            )?;
        }
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
    runtime_state_mutation_authority: RuntimeStateMutationAuthority,
    live_transfer_candidate_capacity: LiveTransferCandidateCapacity,
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
    validate_state_candidate_capacity_with_context(
        runtime_state_mutation_authority,
        live_transfer_candidate_capacity,
        &next,
        stage.snapshot().expose_secret().len(),
        stage.capacity_mode(),
    )?;
    let active_hash = sha256(active_bytes);
    if active_hash == previous_state_hash
        && state_matches_previous_high_water(active, reserved_high_water)
    {
        if stage.capacity_mode() == V6StateCapacityMode::EmergencyBootstrapMarker {
            validate_equivalent_v6_normal_capacity_with_context(
                runtime_state_mutation_authority,
                live_transfer_candidate_capacity,
                active,
            )?;
        }
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
    let upgraded = previous.with_counter_reservation(
        marker.state_plaintext_hash,
        marker.counter_guard_hash,
        &reservation,
    )?;
    let upgraded_encoded = upgraded.encode()?;
    if sha256(&upgraded_encoded) == expected_state_hash {
        return Ok((upgraded, CryptoStateSnapshot::new(upgraded_encoded)));
    }

    let legacy = previous.with_counter_reservation_preserving_version(
        marker.state_plaintext_hash,
        marker.counter_guard_hash,
        &reservation,
    )?;
    let legacy_encoded = legacy.encode()?;
    if sha256(&legacy_encoded) == expected_state_hash {
        Ok((legacy, CryptoStateSnapshot::new(legacy_encoded)))
    } else {
        Err(PairedPromotionError::Conflict)
    }
}

fn state_matches_previous_high_water(state: &PairedCryptoState, high_water: u64) -> bool {
    match state {
        // V1 guard 本身只编码初始 HWM=0；任何非零值都必须已有 V2 sealed fence。
        PairedCryptoState::V1(_) => high_water == 0,
        PairedCryptoState::V2(_)
        | PairedCryptoState::V3(_)
        | PairedCryptoState::V4(_)
        | PairedCryptoState::V5(_)
        | PairedCryptoState::V6(_) => match state.counter_reservation() {
            Some(reservation) => reservation.end_exclusive == high_water,
            None => high_water == 0,
        },
    }
}

fn state_matches_stable_high_water(state: &PairedCryptoState, high_water: u64) -> bool {
    match state {
        // stable V2 总在 sealed-state CAS 之后；V1 state 是不可能的 durable 顺序。
        PairedCryptoState::V1(_) => false,
        PairedCryptoState::V2(_)
        | PairedCryptoState::V3(_)
        | PairedCryptoState::V4(_)
        | PairedCryptoState::V5(_)
        | PairedCryptoState::V6(_) => match state.counter_reservation() {
            Some(reservation) => reservation.end_exclusive == high_water,
            None => high_water == 0,
        },
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
    V5(PairedCryptoStateV2),
    V6(PairedCryptoStateV2),
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
            KEY_GENERATION_STATE_VERSION => {
                PairedCryptoStateV2::decode_version(bytes, KEY_GENERATION_STATE_VERSION)
                    .map(Self::V5)
            }
            TRANSFER_STATE_VERSION => {
                PairedCryptoStateV2::decode_version(bytes, TRANSFER_STATE_VERSION).map(Self::V6)
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
            Self::V5(value) => value.encode_version(KEY_GENERATION_STATE_VERSION),
            Self::V6(value) => value.encode_version(TRANSFER_STATE_VERSION),
        }
    }

    const fn bootstrap(&self) -> &PairedCryptoStateV1 {
        match self {
            Self::V1(value) => value,
            Self::V2(value)
            | Self::V3(value)
            | Self::V4(value)
            | Self::V5(value)
            | Self::V6(value) => &value.bootstrap,
        }
    }

    const fn counter_reservation(&self) -> Option<&CommandCounterReservation> {
        match self {
            Self::V1(_) => None,
            Self::V2(value)
            | Self::V3(value)
            | Self::V4(value)
            | Self::V5(value)
            | Self::V6(value) => value.counter_reservation.as_ref(),
        }
    }

    fn with_counter_reservation(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        reservation: &CommandCounterReservation,
    ) -> Result<Self, PairedPromotionError> {
        reservation.validate()?;
        let runtime = self.opaque_runtime_state();
        let version = if matches!(self, Self::V6(_))
            || !runtime.stream_cursors.is_empty()
            || !runtime.transfer_records.is_empty()
        {
            TRANSFER_STATE_VERSION
        } else {
            match self {
                Self::V1(_) | Self::V2(_) => MUTABLE_STATE_VERSION,
                Self::V3(_) => TYPED_RUNTIME_STATE_VERSION,
                Self::V4(_) => KEY_SYNC_STATE_VERSION,
                Self::V5(_) => KEY_GENERATION_STATE_VERSION,
                Self::V6(_) => TRANSFER_STATE_VERSION,
            }
        };
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            &runtime,
            Some(reservation),
            self.key_sync_state_bytes().map(ToOwned::to_owned),
            self.key_generation_state_bytes().map(ToOwned::to_owned),
            version,
            true,
            true,
            true,
        )
    }

    /// 只用于识别旧二进制已经冻结进 CounterGuard Pending hash 的 canonical candidate。
    /// 新 mutation 永远走 [`Self::with_counter_reservation`] 的 stream/transfer→V6 规则。
    fn with_counter_reservation_preserving_version(
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
            Self::V5(_) => KEY_GENERATION_STATE_VERSION,
            Self::V6(_) => TRANSFER_STATE_VERSION,
        };
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            &self.opaque_runtime_state(),
            Some(reservation),
            self.key_sync_state_bytes().map(ToOwned::to_owned),
            self.key_generation_state_bytes().map(ToOwned::to_owned),
            version,
            true,
            true,
            true,
        )
    }

    fn opaque_runtime_state(&self) -> OpaqueRuntimeState {
        match self {
            Self::V1(_) => OpaqueRuntimeState::empty(),
            Self::V2(value)
            | Self::V3(value)
            | Self::V4(value)
            | Self::V5(value)
            | Self::V6(value) => OpaqueRuntimeState {
                exchange: value.receipt_terminal.clone(),
                replay_windows: value.replay_windows.clone(),
                stream_cursors: value.stream_cursors.clone(),
                transfer_records: value.durable_transfer_records.clone(),
            },
        }
    }

    fn durable_stream_bindings(&self) -> Result<Vec<DurableStreamBindingV1>, PairedPromotionError> {
        match self {
            Self::V1(_) => Ok(Vec::new()),
            Self::V2(value) if value.stream_cursors.is_empty() => Ok(Vec::new()),
            Self::V2(_) => Err(PairedPromotionError::InvalidState),
            Self::V3(value) | Self::V4(value) | Self::V5(value) | Self::V6(value) => {
                decode_stream_bindings(&value.stream_cursors)
                    .map_err(|_| PairedPromotionError::InvalidState)
            }
        }
    }

    fn typed_durable_stream_bindings(
        &self,
    ) -> Result<Option<Vec<DurableStreamBindingV1>>, PairedPromotionError> {
        match self {
            Self::V1(_) | Self::V2(_) => Ok(None),
            Self::V3(value) | Self::V4(value) | Self::V5(value) | Self::V6(value) => {
                decode_stream_bindings(&value.stream_cursors)
                    .map(Some)
                    .map_err(|_| PairedPromotionError::InvalidState)
            }
        }
    }

    fn durable_transfer_state(&self) -> Result<DurableLiveTransferStateV1, PairedPromotionError> {
        let records = match self {
            Self::V1(_) => &[][..],
            Self::V2(value)
            | Self::V3(value)
            | Self::V4(value)
            | Self::V5(value)
            | Self::V6(value) => value.durable_transfer_records.as_slice(),
        };
        let transfer = DurableLiveTransferStateV1::from_record_bytes(records)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        transfer
            .validate_against_bindings(&self.durable_stream_bindings()?)
            .map_err(|_| PairedPromotionError::InvalidState)?;
        Ok(transfer)
    }

    fn durable_transfer_bootstrap_error(
        &self,
        binding: &StreamBindingV1,
    ) -> Result<Option<DurableTransferBootstrapError>, PairedPromotionError> {
        let records = match self {
            Self::V1(_) => &[][..],
            Self::V2(value)
            | Self::V3(value)
            | Self::V4(value)
            | Self::V5(value)
            | Self::V6(value) => value.durable_transfer_records.as_slice(),
        };
        bootstrap_error_for_exact_binding_records(records, binding)
            .map_err(|_| PairedPromotionError::InvalidState)
    }

    fn shared_durable_transfer_records(&self) -> SharedTransferRecords {
        match self {
            Self::V1(_) => SharedTransferRecords::empty(),
            Self::V2(value)
            | Self::V3(value)
            | Self::V4(value)
            | Self::V5(value)
            | Self::V6(value) => value.durable_transfer_records.clone(),
        }
    }

    fn durable_stream_binding_bytes(&self) -> &[Vec<u8>] {
        match self {
            Self::V1(_) => &[],
            Self::V2(value)
            | Self::V3(value)
            | Self::V4(value)
            | Self::V5(value)
            | Self::V6(value) => &value.stream_cursors,
        }
    }

    fn key_sync_state_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::V1(_) | Self::V2(_) | Self::V3(_) => None,
            Self::V4(value) | Self::V5(value) | Self::V6(value) => {
                value.durable_key_sync_state.as_deref()
            }
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

    fn key_generation_state_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::V1(_) | Self::V2(_) | Self::V3(_) | Self::V4(_) => None,
            Self::V5(value) | Self::V6(value) => value.durable_key_generation_state.as_deref(),
        }
    }

    fn durable_key_generation_state(
        &self,
    ) -> Result<Option<DurableKeyGenerationStateV1>, PairedPromotionError> {
        self.key_generation_state_bytes()
            .map(DurableKeyGenerationStateV1::from_canonical_bytes)
            .transpose()
            .map_err(|_| PairedPromotionError::InvalidState)
    }

    fn effective_directory_revision(&self) -> Result<KeyDirectoryRevision, PairedPromotionError> {
        Ok(self
            .durable_key_generation_state()?
            .map_or(self.bootstrap().directory_revision, |state| {
                state.effective_directory_revision()
            }))
    }

    /// 对 production V6 candidate 做精确 plaintext 长度预检。字段形状仍由后续 canonical
    /// validation 负责；这里只把“各字段合法但总编码超过 128 MiB”从 generic invalid 中
    /// 分离出来，使 live transfer 能在读取 entropy 或写盘前转成 compact durable marker。
    fn validate_v6_stream_transfer_capacity<I>(
        &self,
        stream_cursors: &[Vec<u8>],
        transfer_records: &[Vec<u8>],
        receipt_len: usize,
        replay_lengths: I,
    ) -> Result<usize, PairedPromotionError>
    where
        I: IntoIterator<Item = usize>,
    {
        let bootstrap = Zeroizing::new(self.bootstrap().encode()?);
        checked_v6_runtime_projection_encoded_len(
            bootstrap.len(),
            receipt_len,
            replay_lengths,
            stream_cursors.iter().map(Vec::len),
            self.key_sync_state_bytes().map_or(0, <[u8]>::len),
            self.key_generation_state_bytes().map_or(0, <[u8]>::len),
            transfer_records.iter().map(Vec::len),
            transfer_records.len(),
        )
    }

    fn validate_current_v6_stream_transfer_capacity(
        &self,
        stream_cursors: &[Vec<u8>],
        transfer_records: &[Vec<u8>],
    ) -> Result<usize, PairedPromotionError> {
        match self {
            Self::V1(_) => Err(PairedPromotionError::InvalidState),
            Self::V2(current)
            | Self::V3(current)
            | Self::V4(current)
            | Self::V5(current)
            | Self::V6(current) => self.validate_v6_stream_transfer_capacity(
                stream_cursors,
                transfer_records,
                current.receipt_terminal.as_ref().map_or(0, Vec::len),
                current.replay_windows.iter().map(Vec::len),
            ),
        }
    }

    fn with_shared_stream_transfer_projection(
        &self,
        stream_cursors: Vec<Vec<u8>>,
        transfer_records: SharedTransferRecords,
    ) -> Result<Self, PairedPromotionError> {
        let copy_reservation =
            |reservation: &CommandCounterReservation| CommandCounterReservation {
                reservation_id: reservation.reservation_id,
                start: reservation.start,
                end_exclusive: reservation.end_exclusive,
            };
        let value = match self {
            Self::V1(_) => return Err(PairedPromotionError::InvalidState),
            Self::V2(current)
            | Self::V3(current)
            | Self::V4(current)
            | Self::V5(current)
            | Self::V6(current) => PairedCryptoStateV2 {
                initial_state_commitment: current.initial_state_commitment,
                initial_guard_commitment: current.initial_guard_commitment,
                bootstrap: current.bootstrap.clone(),
                receipt_terminal: current.receipt_terminal.clone(),
                counter_reservation: current.counter_reservation.as_ref().map(copy_reservation),
                replay_windows: current.replay_windows.clone(),
                stream_cursors,
                durable_key_sync_state: current.durable_key_sync_state.clone(),
                durable_key_generation_state: current.durable_key_generation_state.clone(),
                durable_transfer_records: transfer_records,
            },
        };
        value.validate_for_version_inner(TRANSFER_STATE_VERSION, true, true, false)?;
        Ok(Self::V6(value))
    }

    fn encode_transfer_prevalidated(&self) -> Result<Vec<u8>, PairedPromotionError> {
        match self {
            Self::V6(value) => {
                value.encode_version_inner(TRANSFER_STATE_VERSION, true, true, false)
            }
            Self::V1(_) | Self::V2(_) | Self::V3(_) | Self::V4(_) | Self::V5(_) => {
                Err(PairedPromotionError::InvalidState)
            }
        }
    }

    fn with_opaque_runtime_state(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        runtime: &OpaqueRuntimeState,
    ) -> Result<Self, PairedPromotionError> {
        runtime.validate()?;
        let automatic_probe = runtime.automatic_probe().ok().flatten().is_some();
        let version = if matches!(self, Self::V6(_))
            || !runtime.stream_cursors.is_empty()
            || !runtime.transfer_records.is_empty()
        {
            TRANSFER_STATE_VERSION
        } else if matches!(self, Self::V5(_)) {
            KEY_GENERATION_STATE_VERSION
        } else if matches!(self, Self::V4(_)) {
            KEY_SYNC_STATE_VERSION
        } else if automatic_probe {
            MUTABLE_STATE_VERSION
        } else {
            TYPED_RUNTIME_STATE_VERSION
        };
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            runtime,
            self.counter_reservation(),
            self.key_sync_state_bytes().map(ToOwned::to_owned),
            self.key_generation_state_bytes().map(ToOwned::to_owned),
            version,
            true,
            true,
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
            || !runtime.transfer_records.is_empty()
            || matches!(self, Self::V3(_) | Self::V4(_) | Self::V5(_) | Self::V6(_))
        {
            return Err(PairedPromotionError::InvalidState);
        }
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            runtime,
            self.counter_reservation(),
            None,
            None,
            MUTABLE_STATE_VERSION,
            true,
            true,
            true,
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
        durable_key_generation_state: Option<Vec<u8>>,
        version: u16,
        validate_key_sync: bool,
        validate_key_generation: bool,
        validate_transfer: bool,
    ) -> Result<Self, PairedPromotionError> {
        if !matches!(
            version,
            MUTABLE_STATE_VERSION
                | TYPED_RUNTIME_STATE_VERSION
                | KEY_SYNC_STATE_VERSION
                | KEY_GENERATION_STATE_VERSION
                | TRANSFER_STATE_VERSION
        ) || matches!(self, Self::V4(_)) && version < KEY_SYNC_STATE_VERSION
            || matches!(self, Self::V5(_))
                && !matches!(
                    version,
                    KEY_GENERATION_STATE_VERSION | TRANSFER_STATE_VERSION
                )
            || matches!(self, Self::V6(_)) && version != TRANSFER_STATE_VERSION
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
                durable_key_generation_state,
                durable_transfer_records: runtime.transfer_records.clone(),
            },
            Self::V2(current)
            | Self::V3(current)
            | Self::V4(current)
            | Self::V5(current)
            | Self::V6(current) => PairedCryptoStateV2 {
                initial_state_commitment: current.initial_state_commitment,
                initial_guard_commitment: current.initial_guard_commitment,
                bootstrap: current.bootstrap.clone(),
                receipt_terminal: runtime.exchange.clone(),
                counter_reservation: counter_reservation.map(copy_reservation),
                replay_windows: runtime.replay_windows.clone(),
                stream_cursors: runtime.stream_cursors.clone(),
                durable_key_sync_state,
                durable_key_generation_state,
                durable_transfer_records: runtime.transfer_records.clone(),
            },
        };
        value.validate_for_version_inner(
            version,
            validate_key_sync,
            validate_key_generation,
            validate_transfer,
        )?;
        match version {
            MUTABLE_STATE_VERSION => Ok(Self::V2(value)),
            TYPED_RUNTIME_STATE_VERSION => Ok(Self::V3(value)),
            KEY_SYNC_STATE_VERSION => Ok(Self::V4(value)),
            KEY_GENERATION_STATE_VERSION => Ok(Self::V5(value)),
            TRANSFER_STATE_VERSION => Ok(Self::V6(value)),
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
        let runtime = self.opaque_runtime_state();
        let version = if matches!(self, Self::V6(_)) || !runtime.stream_cursors.is_empty() {
            TRANSFER_STATE_VERSION
        } else if matches!(self, Self::V5(_)) {
            KEY_GENERATION_STATE_VERSION
        } else {
            KEY_SYNC_STATE_VERSION
        };
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            &runtime,
            self.counter_reservation(),
            durable_key_sync_state,
            self.key_generation_state_bytes().map(ToOwned::to_owned),
            version,
            validate_key_sync,
            true,
            true,
        )
    }

    fn with_key_generation_state_bytes(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        durable_key_generation_state: Option<Vec<u8>>,
        validate_key_generation: bool,
    ) -> Result<Self, PairedPromotionError> {
        let runtime = self.opaque_runtime_state();
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            &runtime,
            self.counter_reservation(),
            self.key_sync_state_bytes().map(ToOwned::to_owned),
            durable_key_generation_state,
            if matches!(self, Self::V6(_)) || !runtime.stream_cursors.is_empty() {
                TRANSFER_STATE_VERSION
            } else {
                KEY_GENERATION_STATE_VERSION
            },
            true,
            validate_key_generation,
            true,
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
            Self::V5(_) => KEY_GENERATION_STATE_VERSION,
            Self::V6(_) => TRANSFER_STATE_VERSION,
        };
        self.with_mutable_projection(
            initial_state_commitment,
            initial_guard_commitment,
            &next.opaque_runtime_state(),
            self.counter_reservation(),
            next.key_sync_state_bytes().map(ToOwned::to_owned),
            next.key_generation_state_bytes().map(ToOwned::to_owned),
            version,
            true,
            true,
            true,
        )
    }
}

/// V2–V6 共用 payload：marker 的两个旧 hash 固化为 initial commitments，当前 state hash
/// 只由 guard 绑定。V2 保留 legacy bounded opaque fields；V3 additionally 要求 stream collection
/// 逐项通过 typed canonical decode；V4 追加 optional canonical ADKS，V5 再追加 canonical
/// key-generation state；V6 追加独立 durable transfer record collection，旧 body prefix 始终
/// 逐字保留。
struct PairedCryptoStateV2 {
    initial_state_commitment: [u8; 32],
    initial_guard_commitment: [u8; 32],
    bootstrap: PairedCryptoStateV1,
    receipt_terminal: Option<Vec<u8>>,
    counter_reservation: Option<CommandCounterReservation>,
    replay_windows: Vec<Vec<u8>>,
    stream_cursors: Vec<Vec<u8>>,
    durable_key_sync_state: Option<Vec<u8>>,
    durable_key_generation_state: Option<Vec<u8>>,
    durable_transfer_records: SharedTransferRecords,
}

impl fmt::Debug for PairedCryptoStateV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCryptoStateV2([REDACTED])")
    }
}

impl PairedCryptoStateV2 {
    fn encode_version(&self, version: u16) -> Result<Vec<u8>, PairedPromotionError> {
        self.encode_version_inner(version, true, true, true)
    }

    fn encode_version_inner(
        &self,
        version: u16,
        validate_key_sync: bool,
        validate_key_generation: bool,
        validate_transfer: bool,
    ) -> Result<Vec<u8>, PairedPromotionError> {
        self.validate_for_version_inner(
            version,
            validate_key_sync,
            validate_key_generation,
            validate_transfer,
        )?;
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
        if matches!(
            version,
            KEY_SYNC_STATE_VERSION | KEY_GENERATION_STATE_VERSION | TRANSFER_STATE_VERSION
        ) {
            put_state_field(
                &mut body,
                self.durable_key_sync_state.as_deref().unwrap_or_default(),
                MAX_STATE_FIELD_LEN,
            )?;
        }
        if matches!(
            version,
            KEY_GENERATION_STATE_VERSION | TRANSFER_STATE_VERSION
        ) {
            put_state_field(
                &mut body,
                self.durable_key_generation_state
                    .as_deref()
                    .unwrap_or_default(),
                MAX_STATE_FIELD_LEN,
            )?;
        }
        if version == TRANSFER_STATE_VERSION {
            put_state_collection_with_limit(
                &mut body,
                self.durable_transfer_records.as_slice(),
                MAX_DURABLE_TRANSFER_RECORDS,
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
        let durable_key_sync_state = if matches!(
            version,
            KEY_SYNC_STATE_VERSION | KEY_GENERATION_STATE_VERSION | TRANSFER_STATE_VERSION
        ) {
            let bytes = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
            (!bytes.is_empty()).then_some(bytes)
        } else {
            None
        };
        let durable_key_generation_state = if matches!(
            version,
            KEY_GENERATION_STATE_VERSION | TRANSFER_STATE_VERSION
        ) {
            let bytes = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
            (!bytes.is_empty()).then_some(bytes)
        } else {
            None
        };
        let durable_transfer_records = if version == TRANSFER_STATE_VERSION {
            decode_shared_transfer_records(&mut decoder)?
        } else {
            SharedTransferRecords::empty()
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
            durable_key_generation_state,
            durable_transfer_records,
        };
        value.validate_for_version(version)?;
        let canonical = Zeroizing::new(value.encode_version(version)?);
        if canonical.as_slice() != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn validate_for_version(&self, version: u16) -> Result<(), PairedPromotionError> {
        self.validate_for_version_inner(version, true, true, true)
    }

    fn validate_for_version_inner(
        &self,
        version: u16,
        validate_key_sync: bool,
        validate_key_generation: bool,
        validate_transfer: bool,
    ) -> Result<(), PairedPromotionError> {
        if !matches!(
            version,
            MUTABLE_STATE_VERSION
                | TYPED_RUNTIME_STATE_VERSION
                | KEY_SYNC_STATE_VERSION
                | KEY_GENERATION_STATE_VERSION
                | TRANSFER_STATE_VERSION
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
        if version < KEY_SYNC_STATE_VERSION && self.durable_key_sync_state.is_some() {
            return Err(PairedPromotionError::InvalidState);
        }
        if version < KEY_GENERATION_STATE_VERSION && self.durable_key_generation_state.is_some() {
            return Err(PairedPromotionError::InvalidState);
        }
        if version == KEY_GENERATION_STATE_VERSION && self.durable_key_generation_state.is_none() {
            return Err(PairedPromotionError::InvalidState);
        }
        if version < TRANSFER_STATE_VERSION && !self.durable_transfer_records.is_empty() {
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
        if validate_key_generation && let Some(bytes) = &self.durable_key_generation_state {
            let state = DurableKeyGenerationStateV1::from_canonical_bytes(bytes)
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
            self.durable_transfer_records.iter().map(Vec::len),
        )?;
        let mut encoded_len = encoded_len;
        if matches!(
            version,
            KEY_SYNC_STATE_VERSION | KEY_GENERATION_STATE_VERSION
        ) {
            let key_sync_len = self.durable_key_sync_state.as_ref().map_or(0, Vec::len);
            if key_sync_len > MAX_STATE_FIELD_LEN
                || encoded_len
                    .checked_add(4)
                    .and_then(|length| length.checked_add(key_sync_len))
                    .is_none_or(|length| length > MAX_CRYPTO_STATE_PLAINTEXT_LEN)
            {
                return Err(PairedPromotionError::InvalidState);
            }
            encoded_len = encoded_len + 4 + key_sync_len;
        }
        if version == KEY_GENERATION_STATE_VERSION {
            let key_generation_len = self
                .durable_key_generation_state
                .as_ref()
                .map_or(0, Vec::len);
            if key_generation_len > MAX_STATE_FIELD_LEN
                || encoded_len
                    .checked_add(4)
                    .and_then(|length| length.checked_add(key_generation_len))
                    .is_none_or(|length| length > MAX_CRYPTO_STATE_PLAINTEXT_LEN)
            {
                return Err(PairedPromotionError::InvalidState);
            }
            encoded_len = encoded_len + 4 + key_generation_len;
        }
        if version == TRANSFER_STATE_VERSION {
            checked_v6_suffix_encoded_len(
                encoded_len,
                self.durable_key_sync_state.as_ref().map_or(0, Vec::len),
                self.durable_key_generation_state
                    .as_ref()
                    .map_or(0, Vec::len),
                self.durable_transfer_records.len(),
            )?;
        }
        if matches!(
            version,
            TYPED_RUNTIME_STATE_VERSION
                | KEY_SYNC_STATE_VERSION
                | KEY_GENERATION_STATE_VERSION
                | TRANSFER_STATE_VERSION
        ) {
            let bindings = decode_stream_bindings(&self.stream_cursors)
                .map_err(|_| PairedPromotionError::InvalidState)?;
            if validate_transfer && version == TRANSFER_STATE_VERSION {
                DurableLiveTransferStateV1::from_record_bytes(
                    self.durable_transfer_records.as_slice(),
                )
                .and_then(|transfer| transfer.validate_against_bindings(&bindings))
                .map_err(|_| PairedPromotionError::InvalidState)?;
            }
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
            | PairedCryptoState::V5(value)
            | PairedCryptoState::V6(value)
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
    put_state_collection_with_limit(encoded, values, MAX_STATE_COLLECTION_ITEMS)
}

fn put_state_collection_with_limit(
    encoded: &mut Vec<u8>,
    values: &[Vec<u8>],
    maximum_items: usize,
) -> Result<(), PairedPromotionError> {
    if values.len() > maximum_items || maximum_items > usize::from(u16::MAX) {
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

fn checked_mutable_state_encoded_len<I, J, K>(
    bootstrap_len: usize,
    receipt_len: usize,
    replay_lengths: I,
    cursor_lengths: J,
    transfer_lengths: K,
) -> Result<usize, PairedPromotionError>
where
    I: IntoIterator<Item = usize>,
    J: IntoIterator<Item = usize>,
    K: IntoIterator<Item = usize>,
{
    if bootstrap_len > MAX_CRYPTO_STATE_PLAINTEXT_LEN || receipt_len > MAX_STATE_FIELD_LEN {
        return Err(PairedPromotionError::InvalidState);
    }
    let mut encoded_len = MUTABLE_STATE_FIXED_ENCODED_LEN
        .checked_add(bootstrap_len)
        .and_then(|length| length.checked_add(receipt_len))
        .ok_or(PairedPromotionError::InvalidState)?;
    for value_len in replay_lengths
        .into_iter()
        .chain(cursor_lengths)
        .chain(transfer_lengths)
    {
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

fn checked_v6_suffix_encoded_len(
    encoded_len: usize,
    key_sync_len: usize,
    key_generation_len: usize,
    transfer_record_count: usize,
) -> Result<usize, PairedPromotionError> {
    if key_sync_len > MAX_STATE_FIELD_LEN
        || key_generation_len > MAX_STATE_FIELD_LEN
        || transfer_record_count > MAX_DURABLE_TRANSFER_RECORDS
    {
        return Err(PairedPromotionError::InvalidState);
    }
    encoded_len
        .checked_add(4)
        .and_then(|length| length.checked_add(key_sync_len))
        .and_then(|length| length.checked_add(4))
        .and_then(|length| length.checked_add(key_generation_len))
        .and_then(|length| length.checked_add(2))
        .filter(|length| *length <= MAX_CRYPTO_STATE_PLAINTEXT_LEN)
        .ok_or(PairedPromotionError::InvalidState)
}

#[allow(clippy::too_many_arguments)]
fn checked_v6_runtime_projection_encoded_len<I, J, K>(
    bootstrap_len: usize,
    receipt_len: usize,
    replay_lengths: I,
    cursor_lengths: J,
    key_sync_len: usize,
    key_generation_len: usize,
    transfer_lengths: K,
    transfer_record_count: usize,
) -> Result<usize, PairedPromotionError>
where
    I: IntoIterator<Item = usize>,
    J: IntoIterator<Item = usize>,
    K: IntoIterator<Item = usize>,
{
    if bootstrap_len > MAX_CRYPTO_STATE_PLAINTEXT_LEN
        || receipt_len > MAX_STATE_FIELD_LEN
        || key_sync_len > MAX_STATE_FIELD_LEN
        || key_generation_len > MAX_STATE_FIELD_LEN
        || transfer_record_count > MAX_DURABLE_TRANSFER_RECORDS
    {
        return Err(PairedPromotionError::InvalidState);
    }
    let mut encoded_len = MUTABLE_STATE_FIXED_ENCODED_LEN
        .checked_add(bootstrap_len)
        .and_then(|length| length.checked_add(receipt_len))
        .ok_or(PairedPromotionError::StateCapacity)?;
    for value_len in replay_lengths
        .into_iter()
        .chain(cursor_lengths)
        .chain(transfer_lengths)
    {
        if value_len == 0 || value_len > MAX_STATE_FIELD_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        encoded_len = encoded_len
            .checked_add(4)
            .and_then(|length| length.checked_add(value_len))
            .ok_or(PairedPromotionError::StateCapacity)?;
    }
    encoded_len = encoded_len
        .checked_add(4)
        .and_then(|length| length.checked_add(key_sync_len))
        .and_then(|length| length.checked_add(4))
        .and_then(|length| length.checked_add(key_generation_len))
        .and_then(|length| length.checked_add(2))
        .ok_or(PairedPromotionError::StateCapacity)?;
    if encoded_len > MAX_CRYPTO_STATE_PLAINTEXT_LEN {
        return Err(PairedPromotionError::StateCapacity);
    }
    Ok(encoded_len)
}

fn decode_state_collection(
    decoder: &mut StateDecoder<'_>,
) -> Result<Vec<Vec<u8>>, PairedPromotionError> {
    decode_state_collection_with_limit(decoder, MAX_STATE_COLLECTION_ITEMS)
}

fn decode_state_collection_with_limit(
    decoder: &mut StateDecoder<'_>,
    maximum_items: usize,
) -> Result<Vec<Vec<u8>>, PairedPromotionError> {
    let count = usize::from(decoder.u16()?);
    if count > maximum_items {
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

fn decode_shared_transfer_records(
    decoder: &mut StateDecoder<'_>,
) -> Result<SharedTransferRecords, PairedPromotionError> {
    let count = usize::from(decoder.u16()?);
    if count > MAX_DURABLE_TRANSFER_RECORDS {
        return Err(PairedPromotionError::InvalidState);
    }
    // 解码尚未成功时先由 zeroizing guard 持有部分 records；只有完整 collection 成功后
    // 才按值移交给 immutable shared owner，避免 malformed V6 让已复制明文走普通 drop。
    let mut values = Zeroizing::new(Vec::with_capacity(count));
    for _ in 0..count {
        let value = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        if value.is_empty() {
            return Err(PairedPromotionError::InvalidState);
        }
        values.push(value);
    }
    Ok(SharedTransferRecords::from_owned(std::mem::take(
        &mut *values,
    )))
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
    use std::fs;
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};

    use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
    use agentdeck_protocol::runtime::StreamCursor;

    use crate::remote::key_generation::{
        DurableKeyGenerationV1, DurableKeySlotV1, KeySlotIdentityV1,
    };
    use crate::remote::keychain::MemoryRemoteKeyStore;

    use crate::remote::crypto_state::PreparedStageCleanupObserver;

    use super::*;

    #[allow(dead_code)]
    mod real_pairing_fixture {
        use crate as agentdeck_cli;

        include!("../../tests/support/remote_pairing.rs");
    }

    #[test]
    fn v6_emergency_headroom_covers_every_durable_binding_exactly() {
        let per_binding = checked_capacity_add(
            checked_capacity_add(
                checked_capacity_add(4, DURABLE_STREAM_REPLAY_TUPLE_V4_BYTES),
                EMERGENCY_REPLAY_DEBT_METADATA_BYTES,
            ),
            checked_capacity_add(4, MAX_NEEDS_BOOTSTRAP_MARKER_RECORD_BYTES),
        );
        assert_eq!(V6_EMERGENCY_BINDING_HEADROOM, per_binding);
        assert_eq!(
            V6_EMERGENCY_HEADROOM,
            per_binding
                .checked_mul(MAX_DURABLE_STREAM_BINDINGS)
                .expect("bounded aggregate emergency reserve"),
        );
        assert_eq!(
            V6_NORMAL_STATE_PLAINTEXT_LIMIT
                .checked_add(V6_EMERGENCY_HEADROOM)
                .expect("normal plus emergency capacity"),
            MAX_CRYPTO_STATE_PLAINTEXT_LEN,
        );
        let exact_max_credit = DURABLE_STREAM_REPLAY_TUPLE_V4_BYTES
            + EMERGENCY_REPLAY_DEBT_METADATA_BYTES
            + 4
            + MAX_NEEDS_BOOTSTRAP_MARKER_RECORD_BYTES;
        assert_eq!(
            V6_EMERGENCY_BINDING_HEADROOM - exact_max_credit,
            4,
            "唯一额外保守量是已有 stream collection field 的 4-byte framing",
        );
    }

    #[test]
    fn exact_credit_never_lends_unused_marker_headroom_to_normal_base() {
        let normal_limit = 1_000;
        let actual_short_marker_credit = 80;
        let base_usage = v6_base_plaintext_usage(
            normal_limit + actual_short_marker_credit + 1,
            actual_short_marker_credit,
        )
        .unwrap();
        assert!(matches!(
            LiveTransferCandidateCapacity {
                plaintext_limit: normal_limit,
            }
            .validate_normal(base_usage),
            Err(PairedPromotionError::StateCapacity)
        ));

        let debt_credit =
            DURABLE_STREAM_REPLAY_TUPLE_V4_BYTES + EMERGENCY_REPLAY_DEBT_METADATA_BYTES;
        let with_marker = v6_base_plaintext_usage(
            normal_limit + debt_credit + actual_short_marker_credit,
            debt_credit + actual_short_marker_credit,
        )
        .unwrap();
        let after_marker_cleanup =
            v6_base_plaintext_usage(normal_limit + debt_credit, debt_credit).unwrap();
        assert_eq!(with_marker, normal_limit);
        assert_eq!(after_marker_cleanup, normal_limit);
        LiveTransferCandidateCapacity {
            plaintext_limit: normal_limit,
        }
        .validate_normal(after_marker_cleanup)
        .expect("marker cleanup 后保留的 replay debt 仍以 exact credit 合法持久化");
    }

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

    fn v6_state_with_transfer_records(records: Vec<Vec<u8>>) -> PairedCryptoState {
        let bootstrap = PairedCryptoStateV1 {
            installation_id: Uuid::from_bytes([0x01; 16]),
            invite_hpke_pubkey: [0x02; 32],
            wss_url: "wss://relay.example.test".to_owned(),
            current_spki_pin: [0x03; 32],
            next_spki_pin: [0x04; 32],
            machine_display_name: "transfer-sharing-fixture".to_owned(),
            relay_server_id: RelayServerId::from_bytes([0x05; 16]),
            machine_root_pubkey: [0x06; 32],
            machine_root_fingerprint: [0x07; 32],
            machine_route: MachineRouteId::from_bytes([0x08; 16]),
            device_route: DeviceRouteId::from_bytes([0x09; 16]),
            grant_serial: GrantSerial::new(1),
            trust_epoch: TrustEpoch::new(1),
            invite_hash: [0x0a; 32],
            request_hash: [0x0b; 32],
            grant_hash: [0x0c; 32],
            response_hash: [0x0d; 32],
            promotion_id: [0x0e; 32],
            directory_revision: KeyDirectoryRevision::new(1),
            canonical_response: vec![0x0f],
            data_sign_certificate: vec![0x10],
            device_authorization: vec![0x11],
            key_directory: vec![0x12],
            receipt_carrier: vec![0x13],
        };
        let initial_state_commitment = sha256(&bootstrap.encode().unwrap());
        PairedCryptoState::V6(PairedCryptoStateV2 {
            initial_state_commitment,
            initial_guard_commitment: [0x14; 32],
            bootstrap,
            receipt_terminal: None,
            counter_reservation: None,
            replay_windows: Vec::new(),
            stream_cursors: Vec::new(),
            durable_key_sync_state: None,
            durable_key_generation_state: None,
            durable_transfer_records: SharedTransferRecords::from_owned(records),
        })
    }

    fn marker_identity_for_state(
        state: &PairedCryptoState,
    ) -> (PairedCommitMarkerV1, PairedMachineIdentity) {
        let bootstrap = state.bootstrap();
        let (initial_state_commitment, initial_guard_commitment) = match state {
            PairedCryptoState::V2(value)
            | PairedCryptoState::V3(value)
            | PairedCryptoState::V4(value)
            | PairedCryptoState::V5(value)
            | PairedCryptoState::V6(value) => (
                value.initial_state_commitment,
                value.initial_guard_commitment,
            ),
            PairedCryptoState::V1(_) => panic!("mutable-state fixture required"),
        };
        (
            PairedCommitMarkerV1::new(
                bootstrap.installation_id,
                bootstrap,
                bootstrap.promotion_id,
                initial_state_commitment,
                [0x91; 32],
                initial_guard_commitment,
                [0x92; 32],
                [0x93; 32],
            ),
            PairedMachineIdentity {
                machine_root_fingerprint: MachineRootFingerprint::from_bytes(
                    bootstrap.machine_root_fingerprint,
                ),
                machine_route: bootstrap.machine_route,
            },
        )
    }

    fn indexed_transfer_stream_binding(index: u64) -> StreamBindingV1 {
        let mut route = [0x61; 16];
        route[8..].copy_from_slice(&index.to_be_bytes());
        let mut generation = [0x62; 16];
        generation[8..].copy_from_slice(&index.to_be_bytes());
        StreamBindingV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: MachineRouteId::from_bytes([0x08; 16]),
            device_route: DeviceRouteId::from_bytes([0x09; 16]),
            grant_serial: GrantSerial::new(1),
            root_trust_epoch: TrustEpoch::new(1),
            stream_route: StreamRouteId::from_bytes(route),
            stream_generation: StreamGenerationId::from_bytes(generation),
            stream_cursor: StreamCursor::BeforeFirst,
            inner_cursor: RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new(format!(
                    "11111111-1111-4111-8111-{index:012x}"
                )),
                cursor: StreamCursor::BeforeFirst,
            },
            key_directory_revision: KeyDirectoryRevision::new(1),
            key_id: KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: 1,
            },
        }
    }

    fn indexed_bootstrap_marker_record(index: u64) -> Vec<u8> {
        let binding = indexed_transfer_stream_binding(index);
        DurableLiveTransferStateV1::empty()
            .abort_exact_binding(
                &binding,
                None,
                DurableTransferBootstrapError::PayloadRejected,
                index + 1,
            )
            .expect("construct canonical indexed bootstrap marker")
            .record_bytes()[0]
            .clone()
    }

    fn recovery_state_store(
        temp: &tempfile::TempDir,
        state: &PairedCryptoState,
    ) -> FileCryptoStateStore {
        let bootstrap = state.bootstrap();
        FileCryptoStateStore::new_in(
            &fs::canonicalize(temp.path())
                .expect("canonicalize recovery tempdir")
                .join("remote-state"),
            CryptoStateIdentity::new(
                bootstrap.installation_id,
                MachineRootFingerprint::from_bytes(bootstrap.machine_root_fingerprint),
                bootstrap.machine_route,
            ),
            DeviceStorageKek::new([0xa1; 32]),
        )
        .expect("construct recovery CryptoState store")
    }

    fn recovery_counter_account(state: &PairedCryptoState) -> RemoteKeyAccount {
        let bootstrap = state.bootstrap();
        RemoteKeyAccount::paired(
            bootstrap.installation_id,
            MachineRootFingerprint::from_bytes(bootstrap.machine_root_fingerprint),
            bootstrap.machine_route,
            PairedRemoteKeyPurpose::CounterGuard,
        )
    }

    struct FailOnceAfterPreparedUnlink {
        fired: AtomicBool,
    }

    impl PreparedStageCleanupObserver for FailOnceAfterPreparedUnlink {
        fn after_unlink_before_parent_sync(&self) -> Result<(), CryptoStateError> {
            if !self.fired.swap(true, Ordering::SeqCst) {
                return Err(CryptoStateError::Io {
                    operation: "injected prepared cleanup parent sync",
                    source: io::Error::other("injected parent fsync failure"),
                });
            }
            Ok(())
        }
    }

    #[test]
    fn prepared_cleanup_failure_retains_token_for_same_handle_retry() {
        let state = v6_state_with_transfer_records(Vec::new());
        let state_bytes = state.encode().expect("encode cleanup retry state");
        let temp = tempfile::tempdir().expect("prepared cleanup retry tempdir");
        let state_store = recovery_state_store(&temp, &state);
        let initial_snapshot = CryptoStateSnapshot::new(state_bytes);
        state_store
            .commit_initial(&initial_snapshot)
            .expect("commit cleanup retry state");
        let next_snapshot = CryptoStateSnapshot::new(b"prepared cleanup retry next".to_vec());
        let prepared = state_store
            .prepare_stage(
                &initial_snapshot,
                [0xb1; 32],
                [0xb2; 16],
                V6StateCapacityMode::Normal,
                &next_snapshot,
            )
            .expect("commit cleanup retry stage");

        let stage_path = state_store.prepared_stage_path().to_path_buf();
        let injected_missing_path = stage_path.with_extension("injected-missing");
        fs::rename(&stage_path, &injected_missing_path)
            .expect("inject prepared cleanup readback failure");

        let (marker, _) = marker_identity_for_state(&state);
        let binding = CounterBindingV1 {
            key_epoch: 1,
            nonce_prefix: [0xb3; 4],
        };
        let mut counter_guard = CounterGuardState::V1(CounterGuardV1::from_binding(
            marker.directory_revision,
            binding,
        ));
        let mut counter_guard_bytes = RemoteSecret::new(counter_guard.encode());
        let mut state_snapshot = Arc::new(initial_snapshot);
        let mut state = state;
        let mut prepared_stage = Some(prepared);
        let key_store = MemoryRemoteKeyStore::new();
        let counter_account = recovery_counter_account(&state);
        let mut recovery = MutablePendingRecovery {
            state_store: &state_store,
            key_store: &key_store,
            counter_account: &counter_account,
            counter_guard_bytes: &mut counter_guard_bytes,
            counter_guard: &mut counter_guard,
            state_snapshot: &mut state_snapshot,
            state: &mut state,
            prepared_stage: &mut prepared_stage,
            marker: &marker,
            mutation_observer: None,
            runtime_state_mutation_authority: RuntimeStateMutationAuthority::Production,
            live_transfer_candidate_capacity: LiveTransferCandidateCapacity::PRODUCTION,
        };

        let error = recovery
            .clear_authenticated_prepared_stage()
            .expect_err("missing exact stage must fail cleanup");
        assert!(matches!(
            error,
            PairedPromotionError::CryptoState(CryptoStateError::Missing)
        ));
        assert!(
            recovery.prepared_stage.is_some(),
            "failed cleanup must retain the authenticated expected token"
        );

        fs::rename(&injected_missing_path, &stage_path)
            .expect("restore exact prepared stage for same-handle retry");
        recovery
            .clear_authenticated_prepared_stage()
            .expect("same handle retries exact prepared cleanup");
        assert!(recovery.prepared_stage.is_none());
        assert!(!stage_path.exists());
    }

    #[test]
    fn prepared_cleanup_retries_parent_sync_after_owned_unlink_without_accepting_plain_missing() {
        let state = v6_state_with_transfer_records(Vec::new());
        let state_bytes = state.encode().expect("encode post-unlink cleanup state");
        let temp = tempfile::tempdir().expect("post-unlink cleanup tempdir");
        let state_store = recovery_state_store(&temp, &state)
            .with_prepared_cleanup_observer_for_test(Arc::new(FailOnceAfterPreparedUnlink {
                fired: AtomicBool::new(false),
            }));
        let initial_snapshot = CryptoStateSnapshot::new(state_bytes.clone());
        state_store
            .commit_initial(&initial_snapshot)
            .expect("commit post-unlink cleanup state");
        let next_snapshot = CryptoStateSnapshot::new(b"post-unlink cleanup next".to_vec());
        let prepared = state_store
            .prepare_stage(
                &initial_snapshot,
                [0xc1; 32],
                [0xc2; 16],
                V6StateCapacityMode::Normal,
                &next_snapshot,
            )
            .expect("commit post-unlink prepared stage");
        let stage_path = state_store.prepared_stage_path().to_path_buf();

        let (marker, _) = marker_identity_for_state(&state);
        let binding = CounterBindingV1 {
            key_epoch: 1,
            nonce_prefix: [0xc3; 4],
        };
        let mut counter_guard = CounterGuardState::V1(CounterGuardV1::from_binding(
            marker.directory_revision,
            binding,
        ));
        let mut counter_guard_bytes = RemoteSecret::new(counter_guard.encode());
        let mut state_snapshot = Arc::new(initial_snapshot);
        let mut state = state;
        let mut prepared_stage = Some(prepared);
        let key_store = MemoryRemoteKeyStore::new();
        let counter_account = recovery_counter_account(&state);
        let mut recovery = MutablePendingRecovery {
            state_store: &state_store,
            key_store: &key_store,
            counter_account: &counter_account,
            counter_guard_bytes: &mut counter_guard_bytes,
            counter_guard: &mut counter_guard,
            state_snapshot: &mut state_snapshot,
            state: &mut state,
            prepared_stage: &mut prepared_stage,
            marker: &marker,
            mutation_observer: None,
            runtime_state_mutation_authority: RuntimeStateMutationAuthority::Production,
            live_transfer_candidate_capacity: LiveTransferCandidateCapacity::PRODUCTION,
        };

        let first = recovery
            .clear_authenticated_prepared_stage()
            .expect_err("first cleanup must fail after owned unlink");
        assert!(matches!(
            first,
            PairedPromotionError::CryptoState(CryptoStateError::Io { .. })
        ));
        assert!(!stage_path.exists(), "fault cut must be after unlink");
        assert!(
            recovery.prepared_stage.is_some(),
            "authenticated token must survive"
        );

        recovery
            .clear_authenticated_prepared_stage()
            .expect("same handle must re-fsync authenticated absence");
        assert!(recovery.prepared_stage.is_none());

        let plain_missing = PreparedCryptoStateStage::authenticated_for_test(
            [0xd1; 16],
            [0xd2; 32],
            V6StateCapacityMode::Normal,
            &state_bytes,
            b"unowned missing stage".to_vec(),
            [0xd3; 32],
        );
        assert!(matches!(
            state_store.clear_prepared_stage_exact(&plain_missing),
            Err(CryptoStateError::Missing)
        ));
    }

    fn paired_keychain_commitments(
        store: &MemoryRemoteKeyStore,
        accounts: &PairedAccounts,
    ) -> Vec<[u8; 32]> {
        [
            &accounts.device_sign,
            &accounts.device_hpke,
            &accounts.grant,
            &accounts.kek,
            &accounts.counter_guard,
            &accounts.marker,
        ]
        .into_iter()
        .map(|account| {
            let value = store
                .load(account)
                .expect("load paired Keychain fixture")
                .expect("paired Keychain fixture exists");
            sha256(value.expose_secret())
        })
        .collect()
    }

    #[test]
    fn resealed_prepared_stage_conflicts_in_list_and_open_without_writes() {
        use real_pairing_fixture::{INSTALLATION_ID, PairingFixture};

        // 该 unit fixture 必须直接构造 production-authority store，才能验证 public
        // list/open audit；用显式 test-only 别名避免 production capability sentinel 把
        // `#[cfg(test)]` 内部调用误判成 recovery gateway bypass。
        type TestOnlyRawStore<'a> = PairedMachineStore<'a>;

        let temp = tempfile::tempdir().expect("resealed stage tempdir");
        let state_root = fs::canonicalize(temp.path())
            .expect("canonicalize resealed stage tempdir")
            .join("remote-state");
        let key_store = MemoryRemoteKeyStore::new();
        let fixture = PairingFixture::new();
        fixture.promote(&key_store, &state_root, 0x41);
        let identity = fixture.identity();

        let paired = TestOnlyRawStore::new(&key_store, INSTALLATION_ID, &state_root);
        let mut opened = paired
            .open_exact(identity)
            .expect("open real promoted machine");
        let replacement =
            OpaqueRuntimeState::from_automatic_probe(AutomaticRuntimeStateProbe::new(0x42));
        let next_state = opened
            .audited
            .state
            .with_opaque_runtime_state(
                opened.audited.marker.state_plaintext_hash,
                opened.audited.marker.counter_guard_hash,
                &replacement,
            )
            .expect("construct valid runtime-only next state");
        let next_snapshot = CryptoStateSnapshot::new(
            next_state
                .encode()
                .expect("encode valid runtime-only next state"),
        );
        let (reserved_high_water, binding, initial_guard_commitment) =
            match opened.audited.counter_guard {
                CounterGuardState::V1(guard) => (
                    guard.reserved_high_water,
                    guard.binding,
                    opened.audited.marker.counter_guard_hash,
                ),
                CounterGuardState::V2(_) => panic!("fresh promotion must start with V1 guard"),
            };
        let mutation_id = [0x43; 16];
        let previous_guard_hash = sha256(opened.audited.counter_guard_bytes.expose_secret());
        let prepared = opened
            .audited
            .state_store
            .prepare_stage(
                opened.audited.state_snapshot.as_ref(),
                previous_guard_hash,
                mutation_id,
                V6StateCapacityMode::Normal,
                &next_snapshot,
            )
            .expect("persist authentic prepared stage");
        let original_stage_commitment = prepared.sealed_commitment();
        let pending = CounterGuardV2::state_pending(
            initial_guard_commitment,
            opened.audited.bootstrap_directory_revision,
            binding,
            reserved_high_water,
            prepared.mutation_id(),
            prepared.previous_guard_hash(),
            prepared.previous_state_hash(),
            prepared.next_state_hash(),
            original_stage_commitment,
        )
        .expect("construct authentic StatePending guard");
        opened.audited.prepared_stage = Some(prepared);
        opened
            .replace_counter_guard(CounterGuardState::V2(pending))
            .expect("persist authentic StatePending guard");

        let state_path = opened.audited.state_store.state_path().to_path_buf();
        let stage_path = opened
            .audited
            .state_store
            .prepared_stage_path()
            .to_path_buf();
        let original_sealed = fs::read(&stage_path).expect("read original sealed stage");
        assert_eq!(sha256(&original_sealed), original_stage_commitment);
        let resealed = opened
            .audited
            .state_store
            .reseal_prepared_stage_for_test(
                opened
                    .audited
                    .prepared_stage
                    .as_ref()
                    .expect("retain authentic stage token"),
            )
            .expect("reseal identical authenticated prepared plaintext");
        assert_ne!(
            resealed, original_sealed,
            "fresh nonce must change sealed bytes"
        );
        assert_ne!(
            sha256(&resealed),
            original_stage_commitment,
            "guard commitment must remain bound to the original sealed bytes",
        );
        fs::write(&stage_path, &resealed).expect("replace sidecar with valid reseal");

        let loaded_reseal = opened
            .audited
            .state_store
            .load_prepared_stage()
            .expect("authenticate resealed sidecar")
            .expect("resealed sidecar exists");
        let expected_stage = opened
            .audited
            .prepared_stage
            .as_ref()
            .expect("retain original authenticated stage token");
        assert_eq!(loaded_reseal.mutation_id(), expected_stage.mutation_id());
        assert_eq!(
            loaded_reseal.previous_guard_hash(),
            expected_stage.previous_guard_hash(),
        );
        assert_eq!(
            loaded_reseal.previous_state_hash(),
            expected_stage.previous_state_hash(),
        );
        assert_eq!(
            loaded_reseal.next_state_hash(),
            expected_stage.next_state_hash()
        );
        assert_eq!(
            loaded_reseal.capacity_mode(),
            expected_stage.capacity_mode()
        );
        assert_eq!(
            loaded_reseal.snapshot().expose_secret(),
            expected_stage.snapshot().expose_secret(),
        );
        assert_eq!(loaded_reseal.sealed_commitment(), sha256(&resealed));
        assert_ne!(loaded_reseal.sealed_commitment(), original_stage_commitment,);
        drop(loaded_reseal);

        let accounts = PairedAccounts::new(
            INSTALLATION_ID,
            identity.machine_root_fingerprint,
            identity.machine_route,
        );
        let keychain_before = paired_keychain_commitments(&key_store, &accounts);
        let active_before = fs::read(&state_path).expect("read active state before audit");
        let sidecar_before = fs::read(&stage_path).expect("read resealed sidecar before audit");
        assert_eq!(sidecar_before, resealed);
        drop(opened);
        drop(paired);

        let reader = TestOnlyRawStore::new(&key_store, INSTALLATION_ID, &state_root);
        assert!(matches!(reader.list(), Err(PairedPromotionError::Conflict)));
        assert!(matches!(
            reader.open_exact(identity),
            Err(PairedPromotionError::Conflict)
        ));

        assert_eq!(
            paired_keychain_commitments(&key_store, &accounts),
            keychain_before,
            "read-only public audits must not rewrite any paired Keychain record",
        );
        assert_eq!(
            fs::read(&state_path).expect("read active state after rejected audits"),
            active_before,
        );
        assert_eq!(
            fs::read(&stage_path).expect("read sidecar after rejected audits"),
            sidecar_before,
        );
    }

    fn assert_emergency_state_pending_recovery_cut(
        previous: &PairedCryptoState,
        previous_bytes: &[u8],
        next_bytes: &[u8],
        active_next: bool,
    ) {
        let temp = tempfile::tempdir().expect("state-pending recovery tempdir");
        let state_store = recovery_state_store(&temp, previous);
        let previous_snapshot = CryptoStateSnapshot::new(previous_bytes.to_vec());
        let next_snapshot = CryptoStateSnapshot::new(next_bytes.to_vec());
        state_store
            .commit_initial(&previous_snapshot)
            .expect("commit previous recovery state");
        let mutation_id = [0x81; 16];
        let previous_guard_hash = [0x82; 32];
        let prepared = state_store
            .prepare_stage(
                &previous_snapshot,
                previous_guard_hash,
                mutation_id,
                V6StateCapacityMode::EmergencyBootstrapMarker,
                &next_snapshot,
            )
            .expect("commit emergency prepared sidecar");
        let binding = CounterBindingV1 {
            key_epoch: 1,
            nonce_prefix: [0x84; 4],
        };
        let (marker, _) = marker_identity_for_state(previous);
        let pending = CounterGuardV2::state_pending(
            marker.counter_guard_hash,
            marker.directory_revision,
            binding,
            0,
            prepared.mutation_id(),
            prepared.previous_guard_hash(),
            prepared.previous_state_hash(),
            prepared.next_state_hash(),
            prepared.sealed_commitment(),
        )
        .expect("construct StatePending guard");
        drop(prepared);
        if active_next {
            state_store
                .compare_and_replace(&previous_snapshot, &next_snapshot)
                .expect("commit active-next crash cut");
        }
        drop(previous_snapshot);
        drop(next_snapshot);

        let key_store = MemoryRemoteKeyStore::new();
        let counter_account = recovery_counter_account(previous);
        let pending_bytes = pending.encode();
        key_store
            .persist_immutable(&counter_account, &RemoteSecret::new(pending_bytes.clone()))
            .expect("commit StatePending guard");
        let state_file_before =
            fs::read(state_store.state_path()).expect("read pre-recovery state");

        // Cold-open the complete mutable tuple, then drive the exact production recovery engine.
        let loaded_snapshot = state_store
            .load()
            .expect("load active crash-cut state")
            .expect("active crash-cut state exists");
        let loaded_state = PairedCryptoState::decode(loaded_snapshot.expose_secret())
            .expect("decode active crash-cut state");
        let loaded_stage = state_store
            .load_prepared_stage()
            .expect("load prepared crash-cut sidecar");
        let mut state_snapshot = Arc::new(loaded_snapshot);
        let mut state = loaded_state;
        let mut prepared_stage = loaded_stage;
        let mut counter_guard_bytes = key_store
            .load(&counter_account)
            .expect("load pending guard")
            .expect("pending guard exists");
        let mut counter_guard = CounterGuardState::decode(counter_guard_bytes.expose_secret())
            .expect("decode pending guard");
        MutablePendingRecovery {
            state_store: &state_store,
            key_store: &key_store,
            counter_account: &counter_account,
            counter_guard_bytes: &mut counter_guard_bytes,
            counter_guard: &mut counter_guard,
            state_snapshot: &mut state_snapshot,
            state: &mut state,
            prepared_stage: &mut prepared_stage,
            marker: &marker,
            mutation_observer: None,
            runtime_state_mutation_authority: RuntimeStateMutationAuthority::Production,
            live_transfer_candidate_capacity: LiveTransferCandidateCapacity::PRODUCTION,
        }
        .recover_state_pending(pending)
        .expect("recover authenticated emergency StatePending");

        assert_eq!(state_snapshot.expose_secret(), next_bytes);
        assert_eq!(state.encode().unwrap(), next_bytes);
        assert!(prepared_stage.is_none());
        assert!(
            state_store
                .load_prepared_stage()
                .expect("read back cleared prepared sidecar")
                .is_none()
        );
        assert_eq!(
            state_store
                .load()
                .expect("load recovered state")
                .expect("recovered state exists")
                .expose_secret(),
            next_bytes,
        );
        assert!(matches!(
            counter_guard,
            CounterGuardState::V2(CounterGuardV2 {
                phase: CounterGuardPhaseV2::StateStable { .. },
                ..
            })
        ));
        assert_eq!(
            key_store
                .load(&counter_account)
                .expect("read back stable guard")
                .expect("stable guard exists")
                .expose_secret(),
            counter_guard_bytes.expose_secret(),
        );
        let state_file_after = fs::read(state_store.state_path()).expect("read recovered state");
        assert_eq!(
            state_file_after == state_file_before,
            active_next,
            "active-first recovery must not rewrite state; guard-first recovery must CAS next",
        );
    }

    fn canonical_catalog_stream_binding() -> Vec<u8> {
        DurableStreamBindingV1::from_stream_binding(StreamBindingV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: MachineRouteId::from_bytes([0x41; 16]),
            device_route: DeviceRouteId::from_bytes([0x42; 16]),
            grant_serial: GrantSerial::new(1),
            root_trust_epoch: TrustEpoch::new(1),
            stream_route: StreamRouteId::from_bytes([0x43; 16]),
            stream_generation: StreamGenerationId::from_bytes([0x44; 16]),
            stream_cursor: StreamCursor::BeforeFirst,
            inner_cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
            key_directory_revision: KeyDirectoryRevision::new(1),
            key_id: KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 1,
            },
        })
        .unwrap()
        .canonical_bytes()
        .unwrap()
    }

    fn canonical_bootstrap_key_generation_state() -> Vec<u8> {
        let revision = KeyDirectoryRevision::new(1);
        let device_route = DeviceRouteId::from_bytes([0x45; 16]);
        let slots = [
            KeyPurpose::Catalog,
            KeyPurpose::DeviceCommandTx,
            KeyPurpose::DeviceReplyTx,
        ]
        .into_iter()
        .map(|purpose| {
            let identity = KeySlotIdentityV1::new(purpose, None).unwrap();
            let generation = DurableKeyGenerationV1::from_bootstrap_entry(
                revision,
                KeyId { purpose, epoch: 1 },
                None,
                device_route,
            )
            .unwrap();
            DurableKeySlotV1::new(identity, generation, None, Vec::new()).unwrap()
        })
        .collect();
        DurableKeyGenerationStateV1::new(revision, revision, slots)
            .unwrap()
            .canonical_bytes()
            .unwrap()
    }

    fn legacy_stream_state(version: u16) -> PairedCryptoState {
        let PairedCryptoState::V6(mut value) = v6_state_with_transfer_records(Vec::new()) else {
            unreachable!()
        };
        value.stream_cursors = vec![canonical_catalog_stream_binding()];
        match version {
            TYPED_RUNTIME_STATE_VERSION => PairedCryptoState::V3(value),
            KEY_SYNC_STATE_VERSION => PairedCryptoState::V4(value),
            KEY_GENERATION_STATE_VERSION => {
                value.durable_key_generation_state =
                    Some(canonical_bootstrap_key_generation_state());
                PairedCryptoState::V5(value)
            }
            _ => panic!("unsupported legacy test version"),
        }
    }

    #[test]
    fn automatic_probe_uses_only_exchange_and_one_replay_slot() {
        let probe = AutomaticRuntimeStateProbe::new(0x51);
        let opaque = OpaqueRuntimeState::from_automatic_probe(probe);
        opaque.validate().unwrap();
        assert_eq!(opaque.exchange(), Some(probe.encoded().as_slice()));
        assert_eq!(opaque.replay_windows(), &[probe.encoded()]);
        assert!(opaque.stream_cursors().is_empty());
        assert!(opaque.transfer_records.is_empty());
        assert_eq!(opaque.automatic_probe().unwrap(), Some(probe));
    }

    #[test]
    fn counter_reservation_upgrades_every_legacy_stream_state_to_v6() {
        for version in [
            TYPED_RUNTIME_STATE_VERSION,
            KEY_SYNC_STATE_VERSION,
            KEY_GENERATION_STATE_VERSION,
        ] {
            let legacy = legacy_stream_state(version);
            let value = match &legacy {
                PairedCryptoState::V3(value)
                | PairedCryptoState::V4(value)
                | PairedCryptoState::V5(value) => value,
                _ => unreachable!(),
            };
            let initial_state_commitment = value.initial_state_commitment;
            let initial_guard_commitment = value.initial_guard_commitment;
            let reservation = reservation(0x52, 0);

            let upgraded = legacy
                .with_counter_reservation(
                    initial_state_commitment,
                    initial_guard_commitment,
                    &reservation,
                )
                .unwrap();
            assert!(matches!(upgraded, PairedCryptoState::V6(_)));
            let upgraded_bytes = upgraded.encode().unwrap();
            assert_eq!(
                u16::from_be_bytes([upgraded_bytes[4], upgraded_bytes[5]]),
                TRANSFER_STATE_VERSION,
            );
            assert!(matches!(
                PairedCryptoState::decode(&upgraded_bytes).unwrap(),
                PairedCryptoState::V6(_)
            ));

            let legacy_frozen = legacy
                .with_counter_reservation_preserving_version(
                    initial_state_commitment,
                    initial_guard_commitment,
                    &reservation,
                )
                .unwrap();
            assert_eq!(
                u16::from_be_bytes([
                    legacy_frozen.encode().unwrap()[4],
                    legacy_frozen.encode().unwrap()[5],
                ]),
                version,
            );
        }
    }

    #[test]
    fn legacy_counter_preflight_rejects_equivalent_v6_over_cap_before_entropy_or_mutation() {
        for version in [
            TYPED_RUNTIME_STATE_VERSION,
            KEY_SYNC_STATE_VERSION,
            KEY_GENERATION_STATE_VERSION,
        ] {
            let legacy = legacy_stream_state(version);
            let state_before = legacy.encode().unwrap();
            let guard_before = [0x71; 64];
            let value = match &legacy {
                PairedCryptoState::V3(value)
                | PairedCryptoState::V4(value)
                | PairedCryptoState::V5(value) => value,
                _ => unreachable!(),
            };
            let placeholder = reservation(0x72, 0);
            let candidate = legacy
                .with_counter_reservation(
                    value.initial_state_commitment,
                    value.initial_guard_commitment,
                    &placeholder,
                )
                .unwrap();
            let records = candidate.shared_durable_transfer_records();
            let streams = candidate.durable_stream_binding_bytes();
            let encoded_len = candidate
                .validate_current_v6_stream_transfer_capacity(streams, records.as_slice())
                .unwrap();
            let emergency_credit =
                v6_exact_emergency_credit_bytes(streams, records.as_slice()).unwrap();
            let base_usage = v6_base_plaintext_usage(encoded_len, emergency_credit).unwrap();
            let lowered = LiveTransferCandidateCapacity {
                plaintext_limit: base_usage - 1,
            };
            let rng = CountingRng { fill_calls: 0 };

            assert!(matches!(
                lowered.validate_normal(base_usage),
                Err(PairedPromotionError::StateCapacity)
            ));
            assert_eq!(rng.fill_calls, 0, "capacity rejection must precede entropy");
            assert_eq!(legacy.encode().unwrap(), state_before);
            assert_eq!(guard_before, [0x71; 64]);
        }
    }

    #[test]
    fn counter_pending_active_next_over_normal_recovery_is_zero_write() {
        let previous = legacy_stream_state(TYPED_RUNTIME_STATE_VERSION);
        let value = match &previous {
            PairedCryptoState::V3(value) => value,
            _ => unreachable!(),
        };
        let reservation = reservation(0x73, 0);
        let next = previous
            .with_counter_reservation_preserving_version(
                value.initial_state_commitment,
                value.initial_guard_commitment,
                &reservation,
            )
            .expect("build frozen legacy active-next candidate");
        let next_bytes = next.encode().expect("encode frozen legacy candidate");
        let records = next.shared_durable_transfer_records();
        let streams = next.durable_stream_binding_bytes();
        let encoded_len = next
            .validate_current_v6_stream_transfer_capacity(streams, records.as_slice())
            .expect("measure equivalent V6 candidate");
        let emergency_credit =
            v6_exact_emergency_credit_bytes(streams, records.as_slice()).unwrap();
        let base_usage = v6_base_plaintext_usage(encoded_len, emergency_credit).unwrap();
        let lowered = LiveTransferCandidateCapacity {
            plaintext_limit: base_usage - 1,
        };
        let (marker, identity) = marker_identity_for_state(&next);
        let binding = CounterBindingV1 {
            key_epoch: 1,
            nonce_prefix: [0x74; 4],
        };
        let guard = CounterGuardV2::pending(
            marker.counter_guard_hash,
            marker.directory_revision,
            binding,
            0,
            COUNTER_BLOCK_SIZE,
            reservation.reservation_id,
            sha256(&previous.encode().unwrap()),
            sha256(&next_bytes),
        )
        .expect("build active-next pending guard");
        let guard_bytes = guard.encode();

        assert!(matches!(
            validate_counter_guard_state(
                &marker,
                identity,
                &CounterGuardState::V2(guard),
                &guard_bytes,
                &next,
                &next_bytes,
                None,
                binding,
                RuntimeStateMutationAuthority::Production,
                lowered,
            ),
            Err(PairedPromotionError::StateCapacity)
        ));

        let temp = tempfile::tempdir().expect("counter active-next recovery tempdir");
        let state_store = recovery_state_store(&temp, &next);
        state_store
            .commit_initial(&CryptoStateSnapshot::new(next_bytes.clone()))
            .expect("commit legacy active-next state");
        let key_store = MemoryRemoteKeyStore::new();
        let counter_account = recovery_counter_account(&next);
        key_store
            .persist_immutable(&counter_account, &RemoteSecret::new(guard_bytes.clone()))
            .expect("commit CounterPending guard");
        let state_file_before =
            fs::read(state_store.state_path()).expect("read active-next state before recovery");
        let guard_before = key_store
            .load(&counter_account)
            .expect("load CounterPending guard before recovery")
            .expect("CounterPending guard exists");

        let loaded_snapshot = state_store
            .load()
            .expect("cold-load legacy active-next state")
            .expect("legacy active-next state exists");
        let loaded_state = PairedCryptoState::decode(loaded_snapshot.expose_secret())
            .expect("decode legacy active-next state");
        let mut state_snapshot = Arc::new(loaded_snapshot);
        let mut state = loaded_state;
        let mut prepared_stage = state_store
            .load_prepared_stage()
            .expect("audit absent counter prepared stage");
        let mut counter_guard_bytes = key_store
            .load(&counter_account)
            .expect("cold-load CounterPending guard")
            .expect("CounterPending guard exists");
        let mut counter_guard = CounterGuardState::decode(counter_guard_bytes.expose_secret())
            .expect("decode CounterPending guard");
        let error = MutablePendingRecovery {
            state_store: &state_store,
            key_store: &key_store,
            counter_account: &counter_account,
            counter_guard_bytes: &mut counter_guard_bytes,
            counter_guard: &mut counter_guard,
            state_snapshot: &mut state_snapshot,
            state: &mut state,
            prepared_stage: &mut prepared_stage,
            marker: &marker,
            mutation_observer: None,
            runtime_state_mutation_authority: RuntimeStateMutationAuthority::Production,
            live_transfer_candidate_capacity: lowered,
        }
        .recover_counter_pending(guard)
        .expect_err("over-normal active-next must not finalize Stable");

        assert!(matches!(error, PairedPromotionError::StateCapacity));
        assert_eq!(state_snapshot.expose_secret(), next_bytes);
        assert_eq!(state.encode().unwrap(), next_bytes);
        assert!(prepared_stage.is_none());
        assert!(matches!(
            counter_guard,
            CounterGuardState::V2(CounterGuardV2 {
                phase: CounterGuardPhaseV2::Pending { .. },
                ..
            })
        ));
        assert_eq!(
            fs::read(state_store.state_path()).expect("read state after rejected recovery"),
            state_file_before,
        );
        assert_eq!(
            key_store
                .load(&counter_account)
                .expect("read guard after rejected recovery")
                .expect("pending guard remains")
                .expose_secret(),
            guard_before.expose_secret(),
        );
    }

    #[test]
    fn state_pending_emergency_mode_recovers_4095_to_4096_marker_at_both_crash_cuts() {
        let records = (0..MAX_DURABLE_STREAM_BINDINGS as u64)
            .map(indexed_bootstrap_marker_record)
            .collect::<Vec<_>>();
        let stream_cursors = encode_stream_bindings(
            (0..MAX_DURABLE_STREAM_BINDINGS as u64)
                .map(indexed_transfer_stream_binding)
                .map(DurableStreamBindingV1::from_stream_binding)
                .collect::<Result<Vec<_>, _>>()
                .expect("construct 4096 durable stream bindings"),
        )
        .expect("encode 4096 durable stream bindings");
        let mut previous =
            v6_state_with_transfer_records(records[..MAX_DURABLE_STREAM_BINDINGS - 1].to_vec());
        let mut next = v6_state_with_transfer_records(records);
        let PairedCryptoState::V6(previous_value) = &mut previous else {
            unreachable!()
        };
        previous_value.stream_cursors = stream_cursors.clone();
        let PairedCryptoState::V6(next_value) = &mut next else {
            unreachable!()
        };
        next_value.stream_cursors = stream_cursors;
        let previous_bytes = previous
            .encode()
            .expect("encode 4095-marker previous state");
        let next_bytes = next.encode().expect("encode 4096-marker emergency state");
        assert_emergency_state_pending_recovery_cut(&previous, &previous_bytes, &next_bytes, false);
        assert_emergency_state_pending_recovery_cut(&previous, &previous_bytes, &next_bytes, true);

        let (marker, identity) = marker_identity_for_state(&previous);
        let mutation_id = [0x81; 16];
        let previous_guard_hash = [0x82; 32];
        let stage_commitment = [0x83; 32];
        let forged_normal_stage = PreparedCryptoStateStage::authenticated_for_test(
            mutation_id,
            previous_guard_hash,
            V6StateCapacityMode::Normal,
            &previous_bytes,
            next_bytes.clone(),
            stage_commitment,
        );
        assert!(matches!(
            validate_state_pending_stage(
                &marker,
                identity,
                &previous,
                &previous_bytes,
                0,
                mutation_id,
                previous_guard_hash,
                sha256(&previous_bytes),
                sha256(&next_bytes),
                stage_commitment,
                Some(&forged_normal_stage),
                RuntimeStateMutationAuthority::Production,
                LiveTransferCandidateCapacity::PRODUCTION,
            ),
            Err(PairedPromotionError::StateCapacity)
        ));
    }

    fn v6_shared_transfer_records(state: &PairedCryptoState) -> &SharedTransferRecords {
        let PairedCryptoState::V6(value) = state else {
            panic!("test fixture must remain V6")
        };
        &value.durable_transfer_records
    }

    #[test]
    fn v6_transfer_records_share_only_on_preserving_paths_and_keep_exact_bytes() {
        let owned_records = vec![vec![0x21, 0x22], vec![0x31, 0x32, 0x33]];
        let state = v6_state_with_transfer_records(owned_records.clone());
        let opaque = state.opaque_runtime_state();
        assert!(
            v6_shared_transfer_records(&state).shares_allocation_with(&opaque.transfer_records),
            "state→opaque preserving projection must clone only the Arc"
        );

        let PairedCryptoState::V6(current) = &state else {
            unreachable!()
        };
        let preserved = state
            .with_mutable_projection(
                current.initial_state_commitment,
                current.initial_guard_commitment,
                &opaque,
                None,
                None,
                None,
                TRANSFER_STATE_VERSION,
                true,
                true,
                false,
            )
            .unwrap();
        assert!(
            v6_shared_transfer_records(&state)
                .shares_allocation_with(v6_shared_transfer_records(&preserved)),
            "preserving mutation must retain the exact shared allocation"
        );
        let shared_projection = state
            .with_shared_stream_transfer_projection(
                Vec::new(),
                v6_shared_transfer_records(&state).clone(),
            )
            .unwrap();
        assert!(
            v6_shared_transfer_records(&state)
                .shares_allocation_with(v6_shared_transfer_records(&shared_projection)),
            "binding/ACK preserving projection must retain the exact shared allocation"
        );

        let replacement = state
            .with_shared_stream_transfer_projection(
                Vec::new(),
                SharedTransferRecords::from_owned(owned_records.clone()),
            )
            .unwrap();
        assert!(
            !v6_shared_transfer_records(&state)
                .shares_allocation_with(v6_shared_transfer_records(&replacement)),
            "owned replacement must establish a distinct immutable allocation"
        );
        assert!(
            v6_shared_transfer_records(&state) == v6_shared_transfer_records(&replacement),
            "business equality remains exact record bytes, not Arc identity"
        );

        let original_bytes = state.encode_transfer_prevalidated().unwrap();
        assert_eq!(
            preserved.encode_transfer_prevalidated().unwrap(),
            original_bytes,
            "Arc-preserving projection must not alter canonical V6 bytes"
        );
        assert_eq!(
            replacement.encode_transfer_prevalidated().unwrap(),
            original_bytes,
            "equal owned replacement records must retain canonical V6 bytes"
        );
        let mut exact_transfer_suffix = Vec::new();
        exact_transfer_suffix.extend_from_slice(&2_u16.to_be_bytes());
        exact_transfer_suffix.extend_from_slice(&2_u32.to_be_bytes());
        exact_transfer_suffix.extend_from_slice(&[0x21, 0x22]);
        exact_transfer_suffix.extend_from_slice(&3_u32.to_be_bytes());
        exact_transfer_suffix.extend_from_slice(&[0x31, 0x32, 0x33]);
        assert!(original_bytes.ends_with(&exact_transfer_suffix));
    }

    #[test]
    fn canonical_v6_decode_uses_a_fresh_owner_without_changing_full_state_bytes() {
        let state = v6_state_with_transfer_records(Vec::new());
        let canonical = state.encode_transfer_prevalidated().unwrap();
        let current_snapshot = CryptoStateSnapshot::new(canonical.clone());
        assert!(
            decode_changed_state_snapshot(
                &current_snapshot,
                CryptoStateSnapshot::new(canonical.clone()),
            )
            .unwrap()
            .is_none(),
            "exact-equal refresh must reuse the audited state and shared record owner"
        );
        let decoded = PairedCryptoState::decode(&canonical).unwrap();

        assert!(
            !v6_shared_transfer_records(&state)
                .shares_allocation_with(v6_shared_transfer_records(&decoded)),
            "decode must establish a fresh owned transfer collection"
        );
        assert_eq!(decoded.encode().unwrap(), canonical);
    }

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
                [],
            )
            .unwrap_err()
            .code(),
            "remote.pairing.paired_invalid"
        );
    }

    #[test]
    fn v6_transfer_lengths_share_the_full_128_mib_state_cap_without_allocating_payloads() {
        let bootstrap_len = 1_024;
        let suffix_len = 4 + 4 + 2; // empty ADKS + empty ADKG + transfer count
        let mut transfer_lengths = vec![MAX_STATE_FIELD_LEN; 15];
        let used = MUTABLE_STATE_FIXED_ENCODED_LEN
            + bootstrap_len
            + transfer_lengths.len() * (4 + MAX_STATE_FIELD_LEN)
            + suffix_len;
        let exact_tail = MAX_CRYPTO_STATE_PLAINTEXT_LEN - used - 4;
        assert!(exact_tail <= MAX_STATE_FIELD_LEN);
        transfer_lengths.push(exact_tail);

        let base = checked_mutable_state_encoded_len(
            bootstrap_len,
            0,
            [],
            [],
            transfer_lengths.iter().copied(),
        )
        .unwrap();
        assert_eq!(
            checked_v6_suffix_encoded_len(base, 0, 0, transfer_lengths.len()).unwrap(),
            MAX_CRYPTO_STATE_PLAINTEXT_LEN
        );

        *transfer_lengths.last_mut().unwrap() += 1;
        let one_over_base = checked_mutable_state_encoded_len(
            bootstrap_len,
            0,
            [],
            [],
            transfer_lengths.iter().copied(),
        )
        .unwrap();
        assert_eq!(
            checked_v6_suffix_encoded_len(one_over_base, 0, 0, transfer_lengths.len())
                .unwrap_err()
                .code(),
            "remote.pairing.paired_invalid"
        );
        assert!(checked_v6_suffix_encoded_len(0, 0, 0, MAX_DURABLE_TRANSFER_RECORDS).is_ok());
        assert_eq!(
            checked_v6_suffix_encoded_len(0, 0, 0, MAX_DURABLE_TRANSFER_RECORDS + 1)
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
