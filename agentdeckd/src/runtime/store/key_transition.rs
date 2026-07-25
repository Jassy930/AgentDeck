//! P4.5 durable key-transition Store substrate。
//!
//! 本模块只持有 authenticated transition、per-recipient exact update/ACK tombstone 与
//! pre-barrier business fence；不生成 key material、不签名、不发送 Relay frame。

#![allow(
    dead_code,
    reason = "P4.5 publisher/RemoteLink wiring consumes this Store substrate in the next slice"
)]

use agentdeck_protocol::e2ee::{KeyDirectoryV1, KeyId, KeyPurpose, KeyUpdateSetV1};
use rusqlite::{Connection, Transaction, TransactionBehavior};

use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};

use super::cipher::{ROW_BLOB_V1_OVERHEAD_LEN, RuntimeKeyBundle};
use super::schema::{
    RUNTIME_KEY_UPDATE_MAX_CANONICAL_BYTES, RUNTIME_KEY_UPDATE_MAX_PLAINTEXT_BYTES,
    RUNTIME_KEY_UPDATE_MAX_SEALED_STATE_BYTES,
};
use super::sqlite::{RuntimeLedger, RuntimeSqlite, SafetyReserveProjection};

mod codec;
mod completion;
mod directory_advance;
mod epoch_barrier;
mod integrity;
mod lifecycle;
mod snapshot_permit;
mod storage;

use codec::*;
use completion::has_all_stream_applied_acks;
pub(crate) use completion::{
    cancel_key_transition, complete_key_transition, try_complete_key_transition,
};
pub(crate) use directory_advance::authorize_directory_advance_identity;
pub(crate) use epoch_barrier::authorize_epoch_barrier_identity;
pub(crate) use integrity::validate_v12_integrity;
use integrity::{verify_exact_committed_cuts, verify_transition_publication_commit};
pub(crate) use lifecycle::{
    apply_counter_retirement_after_guard_readback, apply_pending_replay_retirement,
    begin_key_transition, canonical_update_hash, ensure_key_transition_slot_available,
    finalize_key_directory_rotation, gc_expired_key_transitions,
    load_pending_counter_retirement_plan, stage_key_transition_in_transaction,
    stage_key_transition_with_global_lineage_in_transaction,
};
#[cfg(test)]
pub(crate) use lifecycle::{
    begin_key_transition_with_global_lineage_for_test,
    collect_completed_key_transition_for_legacy_test, mark_rotated_preparing_updates,
};
pub(crate) use snapshot_permit::{
    TransitionSnapshotFlush, TransitionSnapshotFlushRecord, TransitionSnapshotPermit,
    TransitionSnapshotRequest, mark_transition_snapshot_flushed,
    resolve_transition_snapshot_permit,
};
#[cfg(test)]
pub(crate) use snapshot_permit::{
    TransitionSnapshotQuery, resolve_transition_snapshot_permit_for_test,
};
pub(super) use snapshot_permit::{
    TransitionStreamBindingCut, TransitionStreamBindingProvenance,
    validate_transition_snapshot_permit_axes_in_transaction,
    validate_transition_snapshot_permit_in_transaction,
    validate_transition_stream_binding_provenance_in_transaction,
};
use storage::*;

pub(super) const MAX_KEY_TRANSITIONS: u64 = 4_096;
pub(super) const MAX_KEY_TRANSITION_SEALED_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_KEY_UPDATE_ROWS: u64 = 65_536;
pub(super) const MAX_KEY_UPDATE_SEALED_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_KEY_TRANSITION_RECIPIENTS: usize = 256;
pub(crate) const MAX_KEY_TRANSITION_CONVERSATIONS: usize = 1_024;
pub(crate) const MAX_CANONICAL_KEY_UPDATE_BYTES: usize = RUNTIME_KEY_UPDATE_MAX_CANONICAL_BYTES;
pub(crate) const MAX_CANONICAL_KEY_ACK_BYTES: usize = 64 * 1024;
pub(crate) const KEY_TRANSITION_TOMBSTONE_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub(crate) const COUNTER_RETIREMENT_RETENTION_MS: u64 =
    super::remote_replay::REMOTE_REPLAY_RETENTION_MS;
pub(crate) const DEFAULT_KEY_TRANSITION_GC_MAX_ROWS: u64 = 512;
pub(crate) const DEFAULT_KEY_TRANSITION_GC_MAX_SEALED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TRANSITION_PLAINTEXT_BYTES: usize = 512 * 1024;
const MAX_UPDATE_PLAINTEXT_BYTES: usize = RUNTIME_KEY_UPDATE_MAX_PLAINTEXT_BYTES;
const _: () = assert!(
    MAX_UPDATE_PLAINTEXT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN
        == RUNTIME_KEY_UPDATE_MAX_SEALED_STATE_BYTES
);
const TRANSITION_TABLE: &[u8] = b"remote_key_transitions";
const UPDATE_TABLE: &[u8] = b"remote_key_update_outbox";
const SEALED_COLUMN: &[u8] = b"sealed_state";
const TRANSITION_METADATA_DOMAIN: &[u8] = b"runtime.remote.key-transition.metadata.v1";
const UPDATE_METADATA_DOMAIN: &[u8] = b"runtime.remote.key-update.metadata.v1";
const TRANSITION_MAGIC: &[u8; 4] = b"ADKT";
const UPDATE_MAGIC: &[u8; 4] = b"ADKU";
const LEGACY_TRANSITION_CODEC_VERSION: u8 = 1;
const PREVIOUS_TRANSITION_CODEC_VERSION: u8 = 2;
const TRANSITION_CODEC_VERSION: u8 = 3;
const LEGACY_UPDATE_CODEC_VERSION: u8 = 1;
const UPDATE_CODEC_VERSION: u8 = 2;
const MAX_TERMINAL_BASE_MS: u64 = i64::MAX as u64 - KEY_TRANSITION_TOMBSTONE_RETENTION_MS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyTransitionOperation {
    Add,
    Renew,
    Revoke,
    ActivateConversation,
    CounterRecovery,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct KeyTransitionRecipient {
    pub device_route: [u8; 16],
    pub grant_serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyTransitionTarget {
    Device(KeyTransitionRecipient),
    Conversation {
        conversation_id: [u8; 16],
        stream_route: [u8; 16],
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum KeyTransitionStreamScope {
    Catalog,
    Conversation([u8; 16]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyTransitionStreamCut {
    pub scope: KeyTransitionStreamScope,
    pub publication_stream_id: [u8; 16],
    pub stream_route: [u8; 16],
    pub generation: [u8; 16],
    pub relay_committed_outer: Option<u64>,
    pub relay_committed_inner: Option<u64>,
    pub barrier_sequence: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub epoch_barrier_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyTransitionPhase {
    DrainingOld,
    RotatedPreparingUpdates,
    UpdatesFrozen,
    BarriersFrozen,
    BarriersCommitted,
    Complete,
}

impl KeyTransitionPhase {
    const fn rank(self) -> u8 {
        match self {
            Self::DrainingOld => 0,
            Self::RotatedPreparingUpdates => 1,
            Self::UpdatesFrozen => 2,
            Self::BarriersFrozen => 3,
            Self::BarriersCommitted => 4,
            Self::Complete => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyTransitionTerminal {
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyUpdateLifecycle {
    Frozen,
    Acked,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BeginKeyTransition {
    pub operation_id: [u8; 16],
    pub operation: KeyTransitionOperation,
    pub target: KeyTransitionTarget,
    pub from_revision: u64,
    pub to_revision: u64,
    pub recipients: Vec<KeyTransitionRecipient>,
    /// Membership transaction 从 authenticated old enrollment/global-key state 冻结的
    /// 旧 `DeviceCommandTx` replay scope。非 renew/revoke transition 始终为 `None`。
    pub replay_retirement: Option<ReplayRetirement>,
    pub created_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplayRetirementLifecycle {
    Pending,
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CounterRetirementLifecycle {
    Pending,
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplayRetirement {
    pub scope: [u8; super::remote_replay::REMOTE_REPLAY_SCOPE_BYTES],
    /// 与 replay scope 中 old DeviceCommandTx epoch 来自同一 authenticated
    /// old-device global state；后续 guard-first counter GC 用它派生旧 reply scope。
    pub old_reply_key_epoch: u64,
    pub lifecycle: ReplayRetirementLifecycle,
}

impl ReplayRetirement {
    pub(crate) fn pending_device_command(
        scope: [u8; super::remote_replay::REMOTE_REPLAY_SCOPE_BYTES],
        old_reply_key_epoch: u64,
    ) -> Result<Self, RuntimeStoreError> {
        super::remote_replay::validate_device_command_scope(&scope)?;
        if old_reply_key_epoch == 0 {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        Ok(Self {
            scope,
            old_reply_key_epoch,
            lifecycle: ReplayRetirementLifecycle::Pending,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FrozenKeyUpdate {
    pub recipient: KeyTransitionRecipient,
    pub key_revision: u64,
    pub canonical_update_set: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcknowledgeKeyUpdate {
    pub operation_id: [u8; 16],
    pub recipient: KeyTransitionRecipient,
    pub key_revision: u64,
    pub update_hash: [u8; 32],
    pub canonical_ack: Vec<u8>,
    pub acknowledged_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcknowledgeStreamApplied {
    pub operation_id: [u8; 16],
    pub recipient: KeyTransitionRecipient,
    pub key_revision: u64,
    pub scope: KeyTransitionStreamScope,
    pub stream_route: [u8; 16],
    pub stream_generation: [u8; 16],
    pub applied_stream_seq: u64,
    pub inner_cursor: Option<u64>,
    pub key_epoch: u64,
    pub epoch_barrier_sha256: [u8; 32],
    /// Store-current authorization lineage；只用于与 durable snapshot flush marker
    /// 做 exact 比对，不接受 wire 自报值。
    pub authorization_hash: [u8; 32],
    pub canonical_ack: Vec<u8>,
    pub acknowledged_at_ms: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct StreamAppliedAckRecord {
    pub scope: KeyTransitionStreamScope,
    pub stream_route: [u8; 16],
    pub stream_generation: [u8; 16],
    pub applied_stream_seq: u64,
    pub inner_cursor: Option<u64>,
    pub key_revision: u64,
    pub key_epoch: u64,
    pub epoch_barrier_sha256: [u8; 32],
    pub canonical_ack: Vec<u8>,
    pub acknowledged_at_ms: u64,
}

/// Pairing confirm 与 Add/Renew transition 同事务冻结的 global-key lineage。
///
/// `global_key_state_hash` 是 confirm 时完整 ADGK canonical state 的不可变锚；
/// `stable_key_lineage_hash` 只覆盖同 revision 内不可变的 active roster、epoch
/// 和 key material。后者故意排除 retention owner、tombstone 与 revoked-secret
/// GC 状态，避免把合法的 storage-lifecycle mutation 误判为 key fork。
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct KeyTransitionGlobalLineage {
    pub global_key_state_hash: [u8; 32],
    pub stable_key_lineage_hash: Option<[u8; 32]>,
}

impl std::fmt::Debug for KeyTransitionGlobalLineage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyTransitionGlobalLineage([REDACTED])")
    }
}

/// 经过 DeviceSign 验证的 `PairResponseReceived` 与一次 Add/Renew transition
/// 之间的完整 durable 绑定。它只证明目标设备已经安装 PairResponse 内的目标
/// KeyDirectory；不能替代其他 recipient 的普通 `KeyUpdateAckV1`。
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PairingBootstrapInstallBinding {
    pub pairing_id: [u8; 16],
    pub relay_server_id: [u8; 16],
    pub pair_route: [u8; 16],
    pub machine_route: [u8; 16],
    pub device_route: [u8; 16],
    pub grant_serial: u64,
    pub root_trust_epoch: u64,
    pub key_revision: u64,
    pub expiry_ms: u64,
    pub invite_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub grant_hash: [u8; 32],
    pub response_hash: [u8; 32],
    pub receipt_hash: [u8; 32],
    pub device_sign_fingerprint: [u8; 32],
    pub info_sha256: [u8; 32],
    pub aad_sha256: [u8; 32],
    pub tbs_sha256: [u8; 32],
    pub key_directory_hash: [u8; 32],
    pub global_key_state_hash: [u8; 32],
    pub key_slot_digest: [u8; 32],
    pub canonical_receipt: Vec<u8>,
    pub received_at_ms: u64,
}

impl std::fmt::Debug for PairingBootstrapInstallBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PairingBootstrapInstallBinding([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PairingBootstrapInstallProof {
    pub operation_id: [u8; 16],
    pub binding: PairingBootstrapInstallBinding,
}

impl std::fmt::Debug for PairingBootstrapInstallProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PairingBootstrapInstallProof([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PairingBootstrapProofReconcileMode {
    FreshDelivery,
    LegacyReplayBackfill,
}

pub(crate) enum PairingBootstrapInstallProofRead {
    Verified(Box<PairingBootstrapInstallProof>),
    LegacyTransitionCollected,
}

fn key_purpose_tag(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 0,
        KeyPurpose::ConversationDek => 1,
        KeyPurpose::DeviceCommandTx => 2,
        KeyPurpose::DeviceReplyTx => 3,
    }
}

// PairResponse 与后续 KeyUpdateSet 会分别执行随机 HPKE 封装；即使明文 key
// material 相同，`enc`/`wrapped_key` 也不会逐字节相等。这里因此只绑定由
// authenticated GlobalKeyState 派生、且在 confirm_pairing_grant 时已经与
// PairResponse 交叉校验过的稳定 slot 轴，不能把随机密文误当成材料等价证明。
fn append_key_slot(
    encoded: &mut Vec<u8>,
    purpose: KeyPurpose,
    epoch: u64,
    stream_route: Option<[u8; 16]>,
) {
    encoded.push(key_purpose_tag(purpose));
    encoded.extend_from_slice(&epoch.to_be_bytes());
    match stream_route {
        None => encoded.push(0),
        Some(route) => {
            encoded.push(1);
            encoded.extend_from_slice(&route);
        }
    }
}

pub(crate) fn key_directory_slot_digest(
    directory: &KeyDirectoryV1,
) -> Result<[u8; 32], RuntimeStoreError> {
    directory
        .validate()
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    let device_route = directory
        .entries
        .first()
        .ok_or(RuntimeStoreError::PublicationMismatch)?
        .device_route;
    let mut encoded = Vec::with_capacity(directory.entries.len() * 128 + 64);
    encoded.extend_from_slice(b"AgentDeck/PairingBootstrapKeySlotsV1\0");
    encoded.extend_from_slice(&directory.revision.value().to_be_bytes());
    encoded.extend_from_slice(device_route.as_bytes());
    encoded.extend_from_slice(
        &u16::try_from(directory.entries.len())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    for entry in &directory.entries {
        append_key_slot(
            &mut encoded,
            entry.key_id.purpose,
            entry.key_id.epoch,
            entry.stream_route.map(|route| *route.as_bytes()),
        );
    }
    let digest = agentdeck_crypto::sha256(&encoded);
    validate_nonzero(digest)?;
    Ok(digest)
}

fn key_update_set_slot_digest(set: &KeyUpdateSetV1) -> Result<[u8; 32], RuntimeStoreError> {
    set.validate()
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    let mut encoded = Vec::with_capacity(set.updates.len() * 128 + 64);
    encoded.extend_from_slice(b"AgentDeck/PairingBootstrapKeySlotsV1\0");
    encoded.extend_from_slice(&set.key_directory_revision.value().to_be_bytes());
    encoded.extend_from_slice(set.device_route.as_bytes());
    encoded.extend_from_slice(
        &u16::try_from(set.updates.len())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    for update in &set.updates {
        append_key_slot(
            &mut encoded,
            update.key_id.purpose,
            update.key_id.epoch,
            update.stream_route.map(|route| *route.as_bytes()),
        );
    }
    let digest = agentdeck_crypto::sha256(&encoded);
    validate_nonzero(digest)?;
    Ok(digest)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteTransitionIngressClass {
    /// 只证明 transition 已把所有 EpochBarrier durable 提交，足以启动
    /// RemoteLink 的 KeySync/ACK 控制面；不代表普通业务已经可放行。
    ControlPlaneReady,
    Business,
    KeySync,
    KeyUpdateAck,
    StreamAppliedAck,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyTransitionRecord {
    pub operation_id: [u8; 16],
    pub operation: KeyTransitionOperation,
    pub target: KeyTransitionTarget,
    pub from_revision: u64,
    pub to_revision: u64,
    pub phase: KeyTransitionPhase,
    pub terminal: Option<KeyTransitionTerminal>,
    pub recipients: Vec<KeyTransitionRecipient>,
    pub global_lineage: Option<KeyTransitionGlobalLineage>,
    pub bootstrap_install_proof: Option<PairingBootstrapInstallProof>,
    pub replay_retirement: Option<ReplayRetirement>,
    /// transition 派生的 shared/reply/recovery counter scope 必须 guard-first
    /// 收口后才可 GC 该 tombstone。
    pub counter_retirement: CounterRetirementLifecycle,
    pub cuts: Vec<KeyTransitionStreamCut>,
    pub update_count: u64,
    pub created_at_ms: u64,
    pub state_changed_at_ms: u64,
    pub terminal_at_ms: Option<u64>,
    pub retain_until_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyUpdateRecord {
    pub operation_id: [u8; 16],
    pub recipient: KeyTransitionRecipient,
    pub key_revision: u64,
    pub lifecycle: KeyUpdateLifecycle,
    pub canonical_update_set: Vec<u8>,
    pub canonical_ack: Option<Vec<u8>>,
    pub snapshot_flushes: Vec<TransitionSnapshotFlushRecord>,
    pub stream_applied_acks: Vec<StreamAppliedAckRecord>,
    pub created_at_ms: u64,
    pub state_changed_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeySyncRead {
    pub recipient: KeyTransitionRecipient,
    pub known_revision: u64,
    pub requested_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyUpdateAckResolve {
    pub recipient: KeyTransitionRecipient,
    pub key_revision: u64,
    pub update_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyUpdateAckBinding {
    pub operation_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamAppliedAckResolve {
    pub recipient: KeyTransitionRecipient,
    pub key_revision: u64,
    pub scope: KeyTransitionStreamScope,
    pub stream_route: [u8; 16],
    pub stream_generation: [u8; 16],
    pub applied_stream_seq: u64,
    pub inner_cursor: Option<u64>,
    pub key_epoch: u64,
    pub epoch_barrier_sha256: [u8; 32],
    pub authorization_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamAppliedAckBinding {
    pub operation_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyTransitionRecovery {
    pub transition: KeyTransitionRecord,
    pub updates: Vec<KeyUpdateRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KeyTransitionCompletion {
    Pending,
    Completed(Box<KeyTransitionRecord>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyTransitionGcLimits {
    pub max_rows: u64,
    pub max_sealed_bytes: u64,
}

impl Default for KeyTransitionGcLimits {
    fn default() -> Self {
        Self {
            max_rows: DEFAULT_KEY_TRANSITION_GC_MAX_ROWS,
            max_sealed_bytes: DEFAULT_KEY_TRANSITION_GC_MAX_SEALED_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct KeyTransitionGcOutcome {
    pub transitions_deleted: u64,
    pub updates_deleted: u64,
    pub transition_sealed_bytes_deleted: u64,
    pub update_sealed_bytes_deleted: u64,
    /// CounterRecovery 只能在对应 CounterGuard-first counter GC 完成后删除。
    pub counter_recovery_blocked: u64,
    /// Pending replay retirement 必须先原子收口，不允许 GC 丢失冻结 scope。
    pub replay_retirement_blocked: u64,
    pub counter_retirement_blocked: u64,
    /// Delivered pairing 或其 Close outbox 尚在时，ADKT proof 仍是延迟 Close
    /// scrub 的唯一 durable 安装证明，不能先行 GC。
    pub bootstrap_pairing_blocked: u64,
    pub limit_reached: bool,
}

/// manager/maintenance 可执行的只读 exact plan。scope token 已按字节序排序去重；
/// caller 必须逐项 existing-only 删除 Keychain guard 并读回 absent，之后才能把同一
/// plan 交给 `apply_counter_retirement_after_guard_readback`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CounterRetirementPlan {
    pub operation_id: [u8; 16],
    pub scope_tokens: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CounterRetirementApplyOutcome {
    Applied {
        operation_id: [u8; 16],
        counter_rows_deleted: u64,
        manifest_rows_deleted: u64,
    },
    AlreadyCollected {
        operation_id: [u8; 16],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReplayRetirementApplyOutcome {
    NoPending,
    Applied {
        transition: Box<KeyTransitionRecord>,
        replay_scope_observed: bool,
    },
}

struct AuthenticatedTransition {
    record: KeyTransitionRecord,
    codec_version: u8,
    sealed_bytes: u64,
    metadata_token: [u8; 32],
}

struct AuthenticatedUpdate {
    record: KeyUpdateRecord,
    codec_version: u8,
    sealed_bytes: u64,
    metadata_token: [u8; 32],
}

struct RawTransition {
    operation_id: Vec<u8>,
    database_id: Vec<u8>,
    operation_kind: String,
    target_device_route: Option<Vec<u8>>,
    target_grant_serial: Option<String>,
    target_conversation_id: Option<Vec<u8>>,
    target_stream_route: Option<Vec<u8>>,
    from_revision: String,
    to_revision: String,
    phase: String,
    terminal_kind: Option<String>,
    recipient_count: i64,
    stream_count: i64,
    update_count: i64,
    created_at_ms: i64,
    state_changed_at_ms: i64,
    terminal_at_ms: Option<i64>,
    retain_until_ms: Option<i64>,
    sealed_state: Vec<u8>,
    sealed_state_bytes: i64,
    metadata_token: Vec<u8>,
}

struct RawUpdate {
    operation_id: Vec<u8>,
    device_route: Vec<u8>,
    grant_serial: String,
    database_id: Vec<u8>,
    key_revision: String,
    lifecycle: String,
    update_hash: Vec<u8>,
    canonical_update_bytes: i64,
    ack_hash: Option<Vec<u8>>,
    applied_ack_count: i64,
    applied_ack_set_hash: Option<Vec<u8>>,
    created_at_ms: i64,
    state_changed_at_ms: i64,
    sealed_state: Vec<u8>,
    sealed_state_bytes: i64,
    metadata_token: Vec<u8>,
}

fn bootstrap_target(binding: &PairingBootstrapInstallBinding) -> KeyTransitionRecipient {
    KeyTransitionRecipient {
        device_route: binding.device_route,
        grant_serial: binding.grant_serial,
    }
}

fn ensure_bootstrap_update_matches(
    binding: &PairingBootstrapInstallBinding,
    update: &KeyUpdateRecord,
) -> Result<(), RuntimeStoreError> {
    if update.recipient != bootstrap_target(binding) || update.key_revision != binding.key_revision
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let set = KeyUpdateSetV1::from_canonical_bytes(&update.canonical_update_set)
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    if set.device_route.as_bytes() != &binding.device_route
        || set.key_directory_revision.value() != binding.key_revision
        || key_update_set_slot_digest(&set)? != binding.key_slot_digest
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn ensure_bootstrap_global_lineage_matches(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    transition: &KeyTransitionRecord,
    binding: &PairingBootstrapInstallBinding,
) -> Result<(), RuntimeStoreError> {
    let lineage = transition
        .global_lineage
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if lineage.global_key_state_hash != binding.global_key_state_hash {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let global = super::pairing_grant::load_global_key_state(connection, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if transition.phase == KeyTransitionPhase::Complete && global.revision > binding.key_revision {
        return Ok(());
    }
    if global.revision != binding.key_revision {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let expected = lineage
        .stable_key_lineage_hash
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if global.state.pairing_bootstrap_lineage_hash()? != expected {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn derive_legacy_bootstrap_global_lineage(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    binding: &PairingBootstrapInstallBinding,
) -> Result<KeyTransitionGlobalLineage, RuntimeStoreError> {
    let global = super::pairing_grant::load_global_key_state(connection, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    // 旧 ADKT v1/v2 没有独立 stable lineage 锚。只有当前 authenticated state
    // 仍停在 binding revision，且完整 confirm-time hash 逐字节一致时，才能
    // 从当前状态建立可持久化的 stable commitment。revision 已前进时没有历史
    // material commitment 可供重建，必须 fail-closed，禁止写入 stable=None。
    if global.revision != binding.key_revision
        || global.directory_hash != binding.global_key_state_hash
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(KeyTransitionGlobalLineage {
        global_key_state_hash: binding.global_key_state_hash,
        stable_key_lineage_hash: Some(global.state.pairing_bootstrap_lineage_hash()?),
    })
}

fn exact_bootstrap_proof(
    transition: &KeyTransitionRecord,
    binding: PairingBootstrapInstallBinding,
) -> Result<PairingBootstrapInstallProof, RuntimeStoreError> {
    let target = bootstrap_target(&binding);
    if !matches!(
        (transition.operation, transition.target),
        (
            KeyTransitionOperation::Add | KeyTransitionOperation::Renew,
            KeyTransitionTarget::Device(observed),
        ) if observed == target
    ) || transition.to_revision != binding.key_revision
        || !transition.recipients.contains(&target)
        || transition.terminal == Some(KeyTransitionTerminal::Cancelled)
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let proof = PairingBootstrapInstallProof {
        operation_id: transition.operation_id,
        binding,
    };
    let mut candidate = transition.clone();
    candidate.bootstrap_install_proof = Some(proof.clone());
    validate_transition_record(&candidate)?;
    Ok(proof)
}

#[cfg(test)]
pub(super) fn exact_bootstrap_proof_for_test(
    transition: &KeyTransitionRecord,
    binding: PairingBootstrapInstallBinding,
) -> Result<PairingBootstrapInstallProof, RuntimeStoreError> {
    exact_bootstrap_proof(transition, binding)
}

pub(crate) fn reconcile_pairing_bootstrap_install_proof_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &mut super::sqlite::RuntimeLedger,
    binding: PairingBootstrapInstallBinding,
    mode: PairingBootstrapProofReconcileMode,
) -> Result<PairingBootstrapInstallProof, RuntimeStoreError> {
    let recipient = bootstrap_target(&binding);
    let authenticated = load_pairing_bootstrap_transition(
        transaction,
        key_bundle,
        database_id,
        recipient,
        binding.key_revision,
    )?
    .ok_or(RuntimeStoreError::PublicationMismatch)?;
    let mut candidate = authenticated.record.clone();
    if candidate.global_lineage.is_none() {
        if !matches!(
            authenticated.codec_version,
            LEGACY_TRANSITION_CODEC_VERSION | PREVIOUS_TRANSITION_CODEC_VERSION
        ) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        candidate.global_lineage = Some(derive_legacy_bootstrap_global_lineage(
            transaction,
            key_bundle,
            database_id,
            &binding,
        )?);
    }
    let proof = exact_bootstrap_proof(&candidate, binding)?;
    ensure_bootstrap_global_lineage_matches(
        transaction,
        key_bundle,
        database_id,
        &candidate,
        &proof.binding,
    )?;
    if let Some(existing) = authenticated.record.bootstrap_install_proof.as_ref()
        && existing != &proof
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }

    let update = if authenticated.record.phase.rank() >= KeyTransitionPhase::UpdatesFrozen.rank() {
        Some(
            load_update(
                transaction,
                key_bundle,
                database_id,
                authenticated.record.operation_id,
                recipient,
            )?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        )
    } else {
        None
    };
    if let Some(update) = update.as_ref() {
        match update.record.lifecycle {
            KeyUpdateLifecycle::Frozen => {
                ensure_bootstrap_update_matches(&proof.binding, &update.record)?;
                if mode == PairingBootstrapProofReconcileMode::FreshDelivery {
                    require_monotonic_time(
                        update.record.state_changed_at_ms,
                        proof.binding.received_at_ms,
                    )?;
                }
                let mut changed = update.record.clone();
                changed.lifecycle = KeyUpdateLifecycle::Acked;
                changed.canonical_ack = Some(proof.binding.canonical_receipt.clone());
                changed.state_changed_at_ms = update
                    .record
                    .state_changed_at_ms
                    .max(proof.binding.received_at_ms);
                replace_update(
                    transaction,
                    key_bundle,
                    database_id,
                    update,
                    &changed,
                    ledger,
                )?;
            }
            KeyUpdateLifecycle::Acked => {
                // 目标可能已经用正常 KeyUpdateAck 先行 Acked；保留其真实 ACK，
                // 但无论 ACK provenance 为何都必须核对同一 slot lineage。
                ensure_bootstrap_update_matches(&proof.binding, &update.record)?;
                if mode == PairingBootstrapProofReconcileMode::FreshDelivery {
                    require_monotonic_time(
                        update.record.state_changed_at_ms,
                        proof.binding.received_at_ms,
                    )?;
                }
            }
            KeyUpdateLifecycle::Cancelled => {
                return Err(RuntimeStoreError::InvalidStateTransition);
            }
        }
    }

    if authenticated.record.bootstrap_install_proof.is_none()
        || authenticated.record.global_lineage != candidate.global_lineage
    {
        candidate.bootstrap_install_proof = Some(proof.clone());
        replace_transition(
            transaction,
            key_bundle,
            database_id,
            &authenticated,
            &candidate,
            ledger,
        )?;
    }
    Ok(proof)
}

pub(crate) fn load_pairing_bootstrap_install_proof(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    recipient: KeyTransitionRecipient,
    key_revision: u64,
) -> Result<PairingBootstrapInstallProofRead, RuntimeStoreError> {
    let ledger = super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    validate_v12_integrity(connection, key_bundle, database_id, &ledger)?;
    let Some(transition) = load_pairing_bootstrap_transition(
        connection,
        key_bundle,
        database_id,
        recipient,
        key_revision,
    )?
    else {
        if pairing_bootstrap_update_exists(connection, recipient, key_revision)? {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        return Ok(PairingBootstrapInstallProofRead::LegacyTransitionCollected);
    };
    let proof = transition
        .record
        .bootstrap_install_proof
        .clone()
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if proof.operation_id != transition.record.operation_id
        || proof.binding.device_route != recipient.device_route
        || proof.binding.grant_serial != recipient.grant_serial
        || proof.binding.key_revision != key_revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    ensure_bootstrap_global_lineage_matches(
        connection,
        key_bundle,
        database_id,
        &transition.record,
        &proof.binding,
    )?;
    if transition.record.phase.rank() >= KeyTransitionPhase::UpdatesFrozen.rank() {
        let update = load_update(
            connection,
            key_bundle,
            database_id,
            transition.record.operation_id,
            recipient,
        )?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if update.record.lifecycle != KeyUpdateLifecycle::Acked {
            return Err(RuntimeStoreError::InvalidStateTransition);
        }
        ensure_bootstrap_update_matches(&proof.binding, &update.record)?;
    }
    Ok(PairingBootstrapInstallProofRead::Verified(Box::new(proof)))
}

pub(crate) fn freeze_key_updates(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    updates: Vec<FrozenKeyUpdate>,
    frozen_at_ms: u64,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    let projected = updates.iter().try_fold(
        128 * 1024_u64 + MAX_CANONICAL_KEY_ACK_BYTES as u64,
        |total, update| {
            total
                .checked_add(
                    u64::try_from(update.canonical_update_set.len())
                        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                )
                .and_then(|value| value.checked_add(ROW_BLOB_V1_OVERHEAD_LEN as u64 + 512))
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "key update freeze projection",
                })
        },
    )?;
    admit_transition_write(state, config, projected)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated = load_transition(&transaction, &key_bundle, database_id, operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    validate_update_set(&authenticated.record, &updates)?;
    if authenticated.record.phase != KeyTransitionPhase::Complete
        && let Some(proof) = authenticated.record.bootstrap_install_proof.as_ref()
    {
        ensure_bootstrap_global_lineage_matches(
            &transaction,
            &key_bundle,
            database_id,
            &authenticated.record,
            &proof.binding,
        )?;
    }
    if authenticated.record.phase.rank() >= KeyTransitionPhase::UpdatesFrozen.rank() {
        if authenticated.record.terminal == Some(KeyTransitionTerminal::Cancelled)
            || !updates_match(
                &transaction,
                &key_bundle,
                database_id,
                &authenticated.record,
                &updates,
                frozen_at_ms,
            )?
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        transaction.rollback()?;
        return Ok(authenticated.record);
    }
    if authenticated.record.phase != KeyTransitionPhase::RotatedPreparingUpdates {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let mut next = ledger.clone();
    for update in &updates {
        let bootstrap_ack = authenticated
            .record
            .bootstrap_install_proof
            .as_ref()
            .filter(|proof| update.recipient == bootstrap_target(&proof.binding));
        if let Some(proof) = bootstrap_ack {
            if proof.binding.received_at_ms > frozen_at_ms {
                return Err(RuntimeStoreError::ClockRegressed {
                    persisted_ms: proof.binding.received_at_ms,
                    observed_ms: frozen_at_ms,
                });
            }
            let candidate = KeyUpdateRecord {
                operation_id,
                recipient: update.recipient,
                key_revision: update.key_revision,
                lifecycle: KeyUpdateLifecycle::Frozen,
                canonical_update_set: update.canonical_update_set.clone(),
                canonical_ack: None,
                snapshot_flushes: Vec::new(),
                stream_applied_acks: Vec::new(),
                created_at_ms: frozen_at_ms,
                state_changed_at_ms: frozen_at_ms,
            };
            ensure_bootstrap_update_matches(&proof.binding, &candidate)?;
        }
        let record = KeyUpdateRecord {
            operation_id,
            recipient: update.recipient,
            key_revision: update.key_revision,
            lifecycle: if bootstrap_ack.is_some() {
                KeyUpdateLifecycle::Acked
            } else {
                KeyUpdateLifecycle::Frozen
            },
            canonical_update_set: update.canonical_update_set.clone(),
            canonical_ack: bootstrap_ack.map(|proof| proof.binding.canonical_receipt.clone()),
            snapshot_flushes: Vec::new(),
            stream_applied_acks: Vec::new(),
            created_at_ms: frozen_at_ms,
            state_changed_at_ms: frozen_at_ms,
        };
        insert_update(&transaction, &key_bundle, database_id, &record, &mut next)?;
    }
    let mut changed = authenticated.record.clone();
    require_monotonic_time(changed.state_changed_at_ms, frozen_at_ms)?;
    changed.phase = KeyTransitionPhase::UpdatesFrozen;
    changed.update_count = updates.len() as u64;
    changed.state_changed_at_ms = frozen_at_ms;
    replace_transition(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated,
        &changed,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(changed)
}

#[cfg(test)]
pub(crate) fn replace_transition_and_update_for_capacity_test(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    transition: KeyTransitionRecord,
    update: KeyUpdateRecord,
) -> Result<(), RuntimeStoreError> {
    let projected = u64::try_from(encode_transition(&transition)?.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
        .checked_add(
            u64::try_from(encode_update(&update)?.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        )
        .and_then(|value| value.checked_add(256 * 1024))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "key-update capacity test projection",
        })?;
    admit_transition_write(state, config, projected)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated_transition = load_transition(
        &transaction,
        &key_bundle,
        database_id,
        transition.operation_id,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let authenticated_update = load_update(
        &transaction,
        &key_bundle,
        database_id,
        update.operation_id,
        update.recipient,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let mut next = ledger.clone();
    replace_transition(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated_transition,
        &transition,
        &mut next,
    )?;
    replace_update(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated_update,
        &update,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(())
}

#[cfg(test)]
pub(crate) fn replace_update_for_legacy_transition_test(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    update: KeyUpdateRecord,
) -> Result<(), RuntimeStoreError> {
    let projected = u64::try_from(encode_update(&update)?.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
        .checked_add(128 * 1024)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "legacy key-update test projection",
        })?;
    admit_transition_write(state, config, projected)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated_update = load_update(
        &transaction,
        &key_bundle,
        database_id,
        update.operation_id,
        update.recipient,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let mut next = ledger.clone();
    replace_update(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated_update,
        &update,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum LegacyTransitionCodecForTest {
    V1,
    V2,
}

#[cfg(test)]
pub(crate) fn reseal_transition_with_legacy_codec_for_test(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    codec: LegacyTransitionCodecForTest,
) -> Result<(), RuntimeStoreError> {
    admit_transition_write(state, config, 256 * 1024)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated = load_transition(&transaction, &key_bundle, database_id, operation_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let version = match codec {
        LegacyTransitionCodecForTest::V1 => LEGACY_TRANSITION_CODEC_VERSION,
        LegacyTransitionCodecForTest::V2 => PREVIOUS_TRANSITION_CODEC_VERSION,
    };
    let mut legacy_record = authenticated.record.clone();
    legacy_record.global_lineage = None;
    legacy_record.bootstrap_install_proof = None;
    let (sealed, metadata_token) =
        seal_transition_row_legacy_for_test(&key_bundle, database_id, &legacy_record, version)?;
    let sealed_bytes =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    if transaction.execute(
        "UPDATE remote_key_transitions
         SET sealed_state = ?1, sealed_state_bytes = ?2, metadata_token = ?3
         WHERE operation_id = ?4 AND metadata_token = ?5",
        rusqlite::params![
            &sealed,
            i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &metadata_token[..],
            &operation_id[..],
            &authenticated.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    let mut next = ledger.clone();
    next.remote_key_transition_sealed_bytes = next
        .remote_key_transition_sealed_bytes
        .checked_sub(authenticated.sealed_bytes)
        .and_then(|value| value.checked_add(sealed_bytes))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(())
}

#[cfg(test)]
pub(crate) fn transition_codec_version_for_test(
    state: &RuntimeSqlite,
    operation_id: [u8; 16],
) -> Result<u8, RuntimeStoreError> {
    let sealed = state.connection.query_row(
        "SELECT sealed_state FROM remote_key_transitions WHERE operation_id = ?1",
        [&operation_id[..]],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let plaintext = open_transition(&state.key_bundle, state.database_id, operation_id, &sealed)?;
    plaintext
        .expose_secret()
        .get(4)
        .copied()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(crate) fn freeze_key_barriers(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    cuts: Vec<KeyTransitionStreamCut>,
    frozen_at_ms: u64,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    admit_transition_write(state, config, 256 * 1024)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated = load_transition(&transaction, &key_bundle, database_id, operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    validate_transition_stream_cuts(&authenticated.record, &cuts)?;
    if authenticated.record.phase.rank() >= KeyTransitionPhase::BarriersFrozen.rank() {
        if authenticated.record.cuts != cuts
            || authenticated.record.terminal == Some(KeyTransitionTerminal::Cancelled)
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        transaction.rollback()?;
        return Ok(authenticated.record);
    }
    if authenticated.record.phase != KeyTransitionPhase::UpdatesFrozen {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    verify_exact_committed_cuts(&transaction, &key_bundle, &authenticated.record, &cuts)?;
    for cut in cuts
        .iter()
        .filter(|cut| cut.scope == KeyTransitionStreamScope::Catalog)
    {
        let _ = super::snapshot::preflight_transition_catalog_cut_in(
            &transaction,
            &key_bundle,
            database_id,
            agentdeck_protocol::runtime::sync::StreamCursor::from_high_water(
                cut.relay_committed_inner,
            ),
        )?;
    }
    handoff_epoch_barrier_counter_scopes(
        &transaction,
        &key_bundle,
        database_id,
        &cuts,
        frozen_at_ms,
    )?;
    let mut changed = authenticated.record.clone();
    require_monotonic_time(changed.state_changed_at_ms, frozen_at_ms)?;
    changed.phase = KeyTransitionPhase::BarriersFrozen;
    changed.cuts = cuts;
    changed.state_changed_at_ms = frozen_at_ms;
    let mut next = ledger.clone();
    replace_transition(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated,
        &changed,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(changed)
}

/// 旧 key 的全部 publication 已 COMMIT + local ACK 后，在冻结 exact barrier cuts 的
/// 同一事务内解绑旧 sender scope。随后 EpochBarrier 的 transaction-bound freeze 才能
/// 用新 key/scope 绑定同一 stream；crash/reopen 看到的只能是“旧 scope + UpdatesFrozen”
/// 或“unbound scope + BarriersFrozen”，不会出现半笔 scope overwrite。
fn handoff_epoch_barrier_counter_scopes(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    cuts: &[KeyTransitionStreamCut],
    frozen_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    for cut in cuts {
        let mut stream =
            super::publication::load_stream(transaction, key_bundle, cut.publication_stream_id)?;
        let pending: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM publication_outbox WHERE publication_stream_id = ?1",
            [&cut.publication_stream_id[..]],
            |row| row.get(0),
        )?;
        if pending != 0
            || stream.state != super::publication::PublicationStreamState::Active
            || stream.stream_route != cut.stream_route
            || stream.generation != cut.generation
            || stream.reserved_high_water != cut.relay_committed_outer
            || stream.committed_high_water != cut.relay_committed_outer
            || stream.acknowledged_high_water != cut.relay_committed_outer
            || stream.committed_inner_cursor != cut.relay_committed_inner
            || stream.acknowledged_inner_cursor != cut.relay_committed_inner
            || stream.last_committed_blob_hash != stream.last_acknowledged_blob_hash
            || now_ms_before(frozen_at_ms, stream.updated_at_ms)
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        match cut.old_epoch {
            0 => {
                if stream.counter_scope_token.is_some()
                    || stream.sender_counter_high_water.is_some()
                {
                    return Err(RuntimeStoreError::PublicationMismatch);
                }
            }
            old_epoch => {
                match (stream.counter_scope_token, stream.sender_counter_high_water) {
                    // 该 generation 从未 seal 过 shared frame 时没有可交接的
                    // CounterGuard/DB sender lineage。old epoch 仍是 barrier 的
                    // 语义轴，但不能要求一个从未创建的 counter scope。
                    (None, None) => {}
                    (Some(scope_token), Some(_)) => {
                        super::remote_counter::require_existing_scope_key_identity(
                            transaction,
                            key_bundle,
                            database_id,
                            scope_token,
                            KeyId {
                                purpose: match cut.scope {
                                    KeyTransitionStreamScope::Catalog => KeyPurpose::Catalog,
                                    KeyTransitionStreamScope::Conversation(_) => {
                                        KeyPurpose::ConversationDek
                                    }
                                },
                                epoch: old_epoch,
                            },
                        )?;
                        stream.counter_scope_token = None;
                        stream.sender_counter_high_water = None;
                        stream.updated_at_ms = frozen_at_ms;
                        super::publication::update_stream(transaction, key_bundle, &stream)?;
                    }
                    _ => return Err(RuntimeStoreError::PublicationMismatch),
                }
            }
        }
    }
    Ok(())
}

const fn now_ms_before(now_ms: u64, persisted_ms: u64) -> bool {
    now_ms < persisted_ms
}

pub(crate) fn mark_key_barriers_committed(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    committed_at_ms: u64,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    admit_transition_write(state, config, 128 * 1024)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated = load_transition(&transaction, &key_bundle, database_id, operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if matches!(
        authenticated.record.phase,
        KeyTransitionPhase::BarriersFrozen | KeyTransitionPhase::BarriersCommitted
    ) {
        super::transition_material::validate_transition_authorizations_in_transaction(
            &transaction,
            &key_bundle,
            database_id,
            &authenticated.record,
        )?;
    }
    let (record, committed) = mark_authenticated_key_barriers_committed(
        transaction,
        &key_bundle,
        database_id,
        ledger,
        authenticated,
        committed_at_ms,
    )?;
    if committed {
        super::sqlite::latch_post_commit_capacity(state, config);
    }
    Ok(record)
}

/// 早期 key-transition 单元测试只构造 ADKT/publication substrate，不构造 P4.3
/// MachineRoot/enrollment/authorization ledger。它们继续通过本 test-only seam 隔离测试
/// phase/ACK/GC 语义；production 入口和 authorization focused matrix 始终走上方完整 gate。
#[cfg(test)]
pub(super) fn mark_key_barriers_committed_without_authorization_revalidation_for_test(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    committed_at_ms: u64,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    admit_transition_write(state, config, 128 * 1024)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated = load_transition(&transaction, &key_bundle, database_id, operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    let (record, committed) = mark_authenticated_key_barriers_committed(
        transaction,
        &key_bundle,
        database_id,
        ledger,
        authenticated,
        committed_at_ms,
    )?;
    if committed {
        super::sqlite::latch_post_commit_capacity(state, config);
    }
    Ok(record)
}

fn mark_authenticated_key_barriers_committed(
    transaction: Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: RuntimeLedger,
    authenticated: AuthenticatedTransition,
    committed_at_ms: u64,
) -> Result<(KeyTransitionRecord, bool), RuntimeStoreError> {
    if authenticated.record.phase == KeyTransitionPhase::BarriersCommitted {
        transaction.rollback()?;
        return Ok((authenticated.record, false));
    }
    if authenticated.record.phase != KeyTransitionPhase::BarriersFrozen {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    verify_transition_publication_commit(
        &transaction,
        key_bundle,
        database_id,
        &authenticated.record,
    )?;
    let mut changed = authenticated.record.clone();
    require_monotonic_time(changed.state_changed_at_ms, committed_at_ms)?;
    changed.phase = KeyTransitionPhase::BarriersCommitted;
    changed.state_changed_at_ms = committed_at_ms;
    let mut next = ledger.clone();
    replace_transition(
        &transaction,
        key_bundle,
        database_id,
        &authenticated,
        &changed,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    Ok((changed, true))
}

pub(crate) fn acknowledge_key_update(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: AcknowledgeKeyUpdate,
) -> Result<KeyUpdateRecord, RuntimeStoreError> {
    validate_ack(&input)?;
    admit_transition_write(
        state,
        config,
        u64::try_from(input.canonical_ack.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            + 128 * 1024,
    )?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let transition = load_transition(&transaction, &key_bundle, database_id, input.operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if transition.record.phase.rank() < KeyTransitionPhase::UpdatesFrozen.rank()
        || transition.record.terminal == Some(KeyTransitionTerminal::Cancelled)
        || transition.record.to_revision != input.key_revision
        || !transition.record.recipients.contains(&input.recipient)
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let authenticated = load_update(
        &transaction,
        &key_bundle,
        database_id,
        input.operation_id,
        input.recipient,
    )?
    .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if authenticated.record.key_revision != input.key_revision
        || canonical_update_hash(&authenticated.record.canonical_update_set)? != input.update_hash
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let bootstrap_ack_upgrade =
        transition
            .record
            .bootstrap_install_proof
            .as_ref()
            .filter(|proof| {
                input.recipient == bootstrap_target(&proof.binding)
                    && input.key_revision == proof.binding.key_revision
                    && authenticated.record.canonical_ack.as_deref()
                        == Some(proof.binding.canonical_receipt.as_slice())
            });
    if authenticated.record.lifecycle == KeyUpdateLifecycle::Acked {
        if authenticated.record.canonical_ack.as_deref() == Some(input.canonical_ack.as_slice()) {
            transaction.rollback()?;
            return Ok(authenticated.record);
        }
        let Some(proof) = bootstrap_ack_upgrade else {
            return Err(RuntimeStoreError::PublicationMismatch);
        };
        // PairResponse receipt 与已经在途的正常 KeyUpdateAck 可以交叉到达。
        // receipt 先赢时，仅允许 exact target 把 placeholder ACK 单调升级成
        // 经过 DeviceSign 验证的真实 ACK；proof 本身继续独立保留。
        ensure_bootstrap_update_matches(&proof.binding, &authenticated.record)?;
    }
    if authenticated.record.lifecycle != KeyUpdateLifecycle::Frozen
        && bootstrap_ack_upgrade.is_none()
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let is_bootstrap_ack_upgrade = authenticated.record.lifecycle == KeyUpdateLifecycle::Acked;
    require_monotonic_time(
        authenticated.record.state_changed_at_ms,
        input.acknowledged_at_ms,
    )?;
    let mut changed = authenticated.record.clone();
    changed.lifecycle = KeyUpdateLifecycle::Acked;
    changed.canonical_ack = Some(input.canonical_ack);
    if !is_bootstrap_ack_upgrade {
        changed.state_changed_at_ms = input.acknowledged_at_ms;
    }
    let mut next = ledger.clone();
    replace_update(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated,
        &changed,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(changed)
}

pub(crate) fn acknowledge_stream_applied(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: AcknowledgeStreamApplied,
) -> Result<KeyUpdateRecord, RuntimeStoreError> {
    validate_stream_applied_ack(&input)?;
    admit_transition_write(
        state,
        config,
        u64::try_from(input.canonical_ack.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            + 128 * 1024,
    )?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let transition = load_transition(&transaction, &key_bundle, database_id, input.operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if !matches!(
        (transition.record.phase, transition.record.terminal),
        (KeyTransitionPhase::BarriersCommitted, None)
            | (
                KeyTransitionPhase::Complete,
                Some(KeyTransitionTerminal::Completed)
            )
    ) || transition.record.to_revision != input.key_revision
        || !transition.record.recipients.contains(&input.recipient)
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let cut = transition
        .record
        .cuts
        .iter()
        .find(|cut| {
            cut.scope == input.scope
                && cut.stream_route == input.stream_route
                && cut.generation == input.stream_generation
        })
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if cut.barrier_sequence != input.applied_stream_seq
        || cut.relay_committed_inner != input.inner_cursor
        || cut.new_epoch != input.key_epoch
        || cut.epoch_barrier_sha256 != input.epoch_barrier_sha256
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let authenticated = load_update(
        &transaction,
        &key_bundle,
        database_id,
        input.operation_id,
        input.recipient,
    )?
    .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if authenticated.record.lifecycle != KeyUpdateLifecycle::Acked
        || authenticated.record.key_revision != input.key_revision
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if snapshot_permit::snapshot_delivery_required(&transition.record, input.recipient)
        && !snapshot_permit::has_exact_snapshot_flush(
            &transition.record,
            &authenticated.record,
            cut,
            input.authorization_hash,
        )
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let applied = StreamAppliedAckRecord {
        scope: input.scope,
        stream_route: input.stream_route,
        stream_generation: input.stream_generation,
        applied_stream_seq: input.applied_stream_seq,
        inner_cursor: input.inner_cursor,
        key_revision: input.key_revision,
        key_epoch: input.key_epoch,
        epoch_barrier_sha256: input.epoch_barrier_sha256,
        canonical_ack: input.canonical_ack,
        acknowledged_at_ms: input.acknowledged_at_ms,
    };
    let identity = applied_ack_identity(&applied);
    if let Some(existing) = authenticated
        .record
        .stream_applied_acks
        .iter()
        .find(|record| applied_ack_identity(record) == identity)
    {
        if same_applied_ack(existing, &applied) {
            transaction.rollback()?;
            return Ok(authenticated.record);
        }
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    require_monotonic_time(
        authenticated.record.state_changed_at_ms,
        input.acknowledged_at_ms,
    )?;
    let mut changed = authenticated.record.clone();
    changed.stream_applied_acks.push(applied);
    changed
        .stream_applied_acks
        .sort_by_key(applied_ack_identity);
    changed.state_changed_at_ms = input.acknowledged_at_ms;
    let mut next = ledger.clone();
    replace_update(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated,
        &changed,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(changed)
}

pub(crate) fn ensure_remote_ingress_allowed(
    state: &RuntimeSqlite,
    class: RemoteTransitionIngressClass,
) -> Result<(), RuntimeStoreError> {
    match class {
        RemoteTransitionIngressClass::KeySync
        | RemoteTransitionIngressClass::KeyUpdateAck
        | RemoteTransitionIngressClass::StreamAppliedAck => Ok(()),
        RemoteTransitionIngressClass::ControlPlaneReady => {
            ensure_no_pre_barrier_business(&state.connection, &state.key_bundle, state.database_id)
        }
        RemoteTransitionIngressClass::Business => ensure_no_active_transition_for_business(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        ),
    }
}

pub(crate) fn ensure_no_pre_barrier_business(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    match load_active_transition(connection, key_bundle, database_id)? {
        None => Ok(()),
        Some(active) if active.record.phase == KeyTransitionPhase::BarriersCommitted => Ok(()),
        Some(_) => Err(RuntimeStoreError::InvalidStateTransition),
    }
}

/// 普通 business ingress/shared publication 的最终 ACK fence。
///
/// `BarriersCommitted` 只允许 RemoteLink 控制面启动以接收 KeyUpdateAck 与
/// StreamAppliedAck；所有 required ACK 令 `try_complete_key_transition` 释放 active
/// slot 前，任何普通业务、Catalog/Event/Transfer freeze 或 conversation activation
/// 都必须继续 fail-close。
pub(crate) fn ensure_no_active_transition_for_business(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    match load_active_transition(connection, key_bundle, database_id)? {
        None => Ok(()),
        Some(_) => Err(RuntimeStoreError::InvalidStateTransition),
    }
}

/// 允许长生命周期业务 reply 把 frozen revision 单调刷新到当前 revision 前，认证
/// 每一条连续 transition edge 都真实到达 BusinessReady。仅检查“当前没有 active
/// transition”不足以区分已完成与已取消的历史 edge。
pub(super) fn ensure_business_revision_refresh_ready(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    frozen_revision: u64,
    current_revision: u64,
) -> Result<(), RuntimeStoreError> {
    if current_revision < frozen_revision
        || current_revision.saturating_sub(frozen_revision) > MAX_KEY_TRANSITIONS
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    ensure_no_active_transition_for_business(connection, key_bundle, database_id)?;
    if current_revision == frozen_revision {
        return Ok(());
    }

    for from_revision in frozen_revision..current_revision {
        let to_revision = from_revision
            .checked_add(1)
            .ok_or(RuntimeStoreError::PairingConflict)?;
        let mut statement = connection.prepare(
            "SELECT operation_id FROM remote_key_transitions
             WHERE from_revision = ?1 AND to_revision = ?2
             ORDER BY operation_id LIMIT 2",
        )?;
        let operation_ids = statement
            .query_map(
                rusqlite::params![
                    super::sequence::encode_sequence(from_revision),
                    super::sequence::encode_sequence(to_revision),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if operation_ids.len() != 1 {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let operation_id: [u8; 16] = operation_ids[0]
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let transition = load_transition(connection, key_bundle, database_id, operation_id)?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if transition.record.from_revision != from_revision
            || transition.record.to_revision != to_revision
            || !matches!(
                (transition.record.phase, transition.record.terminal),
                (KeyTransitionPhase::BarriersCommitted, None)
                    | (
                        KeyTransitionPhase::Complete,
                        Some(KeyTransitionTerminal::Completed)
                    )
            )
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
    }
    Ok(())
}

pub(crate) fn load_active_key_transition(
    state: &RuntimeSqlite,
) -> Result<Option<KeyTransitionRecovery>, RuntimeStoreError> {
    let Some(transition) =
        load_active_transition(&state.connection, &state.key_bundle, state.database_id)?
    else {
        return Ok(None);
    };
    let updates = load_updates_for_operation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        transition.record.operation_id,
    )?
    .into_iter()
    .map(|update| update.record)
    .collect();
    Ok(Some(KeyTransitionRecovery {
        transition: transition.record,
        updates,
    }))
}

#[cfg(test)]
pub(crate) fn load_key_transition_for_capacity_test(
    state: &RuntimeSqlite,
    operation_id: [u8; 16],
) -> Result<KeyTransitionRecovery, RuntimeStoreError> {
    let transition = load_transition(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        operation_id,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let updates = load_updates_for_operation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        operation_id,
    )?
    .into_iter()
    .map(|update| update.record)
    .collect();
    Ok(KeyTransitionRecovery {
        transition: transition.record,
        updates,
    })
}

/// Catalog retention 的持久 fence。active transition row 本身已由 metadata token +
/// sealed payload 全量认证；只要 frozen Catalog H 尚未完成/取消，所需 0..H delta
/// 就不能被 durable D 授权裁掉，否则 crash/reopen 后 transition 只能失败。
pub(super) fn active_catalog_cut_covers_revision(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    revision: u64,
) -> Result<bool, RuntimeStoreError> {
    let Some(transition) = load_active_transition(connection, key_bundle, database_id)? else {
        return Ok(false);
    };
    Ok(transition.record.cuts.iter().any(|cut| {
        cut.scope == KeyTransitionStreamScope::Catalog
            && cut
                .relay_committed_inner
                .is_some_and(|frozen| revision <= frozen)
    }))
}

/// Counter rollback tombstone 的 cross-row full-audit binding。
/// RecoveryStaged 必须仍指向同一 active `CounterRecovery` transition；不能接受把两份
/// 各自 MAC 有效但来自不同备份时点的 row 拼接成可继续发送的状态。
pub(super) fn validate_counter_recovery_transition_binding(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    operation_id: [u8; 16],
    from_revision: u64,
    to_revision: u64,
) -> Result<(), RuntimeStoreError> {
    let transition = load_transition(connection, key_bundle, database_id, operation_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if transition.record.operation != KeyTransitionOperation::CounterRecovery
        || transition.record.from_revision != from_revision
        || transition.record.to_revision != to_revision
        || transition.record.phase == KeyTransitionPhase::Complete
        || transition.record.terminal.is_some()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(crate) fn load_key_update_for_sync(
    state: &RuntimeSqlite,
    query: KeySyncRead,
) -> Result<FrozenKeyUpdate, RuntimeStoreError> {
    validate_nonzero(query.recipient.device_route)?;
    if query.recipient.grant_serial == 0 || query.requested_revision <= query.known_revision {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let transition =
        load_active_transition(&state.connection, &state.key_bundle, state.database_id)?
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if transition.record.phase.rank() < KeyTransitionPhase::UpdatesFrozen.rank()
        || transition.record.from_revision != query.known_revision
        || transition.record.to_revision != query.requested_revision
        || !transition.record.recipients.contains(&query.recipient)
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let update = load_update(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        transition.record.operation_id,
        query.recipient,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if update.record.key_revision != query.requested_revision {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(FrozenKeyUpdate {
        recipient: update.record.recipient,
        key_revision: update.record.key_revision,
        canonical_update_set: update.record.canonical_update_set,
    })
}

pub(crate) fn resolve_key_update_ack(
    state: &RuntimeSqlite,
    query: KeyUpdateAckResolve,
) -> Result<KeyUpdateAckBinding, RuntimeStoreError> {
    validate_nonzero(query.recipient.device_route)?;
    validate_nonzero(query.update_hash)?;
    if query.recipient.grant_serial == 0 || query.key_revision == 0 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let operation_ids =
        load_ack_candidate_operation_ids(&state.connection, query.recipient, query.key_revision)?;
    let mut binding = None;
    for operation_id in operation_ids {
        let transition = load_transition(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            operation_id,
        )?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let update = load_update(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            operation_id,
            query.recipient,
        )?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if transition.record.terminal == Some(KeyTransitionTerminal::Cancelled) {
            if update.record.lifecycle != KeyUpdateLifecycle::Cancelled {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            continue;
        }
        if transition.record.phase.rank() < KeyTransitionPhase::UpdatesFrozen.rank()
            || transition.record.to_revision != query.key_revision
            || !transition.record.recipients.contains(&query.recipient)
            || update.record.key_revision != query.key_revision
            || !matches!(
                update.record.lifecycle,
                KeyUpdateLifecycle::Frozen | KeyUpdateLifecycle::Acked
            )
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if canonical_update_hash(&update.record.canonical_update_set)? != query.update_hash {
            continue;
        }
        if binding.replace(operation_id).is_some() {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    }
    binding
        .map(|operation_id| KeyUpdateAckBinding { operation_id })
        .ok_or(RuntimeStoreError::PublicationMismatch)
}

pub(crate) fn resolve_stream_applied_ack(
    state: &RuntimeSqlite,
    query: StreamAppliedAckResolve,
) -> Result<StreamAppliedAckBinding, RuntimeStoreError> {
    validate_nonzero(query.recipient.device_route)?;
    validate_nonzero(query.stream_route)?;
    validate_nonzero(query.stream_generation)?;
    validate_nonzero(query.epoch_barrier_sha256)?;
    validate_nonzero(query.authorization_hash)?;
    if matches!(query.scope, KeyTransitionStreamScope::Conversation(id) if id == [0; 16])
        || query.recipient.grant_serial == 0
        || query.key_revision == 0
        || query.key_epoch == 0
        || query.applied_stream_seq == u64::MAX
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let operation_ids =
        load_ack_candidate_operation_ids(&state.connection, query.recipient, query.key_revision)?;
    let mut binding = None;
    for operation_id in operation_ids {
        let transition = load_transition(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            operation_id,
        )?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let update = load_update(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            operation_id,
            query.recipient,
        )?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if transition.record.terminal == Some(KeyTransitionTerminal::Cancelled) {
            if update.record.lifecycle != KeyUpdateLifecycle::Cancelled {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            continue;
        }
        if transition.record.to_revision != query.key_revision
            || !transition.record.recipients.contains(&query.recipient)
            || update.record.key_revision != query.key_revision
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if update.record.lifecycle != KeyUpdateLifecycle::Acked
            || !matches!(
                (transition.record.phase, transition.record.terminal),
                (KeyTransitionPhase::BarriersCommitted, None)
                    | (
                        KeyTransitionPhase::Complete,
                        Some(KeyTransitionTerminal::Completed)
                    )
            )
        {
            continue;
        }
        let mut matching_cuts = transition.record.cuts.iter().filter(|cut| {
            cut.scope == query.scope
                && cut.stream_route == query.stream_route
                && cut.generation == query.stream_generation
                && cut.barrier_sequence == query.applied_stream_seq
                && cut.relay_committed_inner == query.inner_cursor
                && cut.new_epoch == query.key_epoch
                && cut.epoch_barrier_sha256 == query.epoch_barrier_sha256
        });
        let Some(cut) = matching_cuts.next() else {
            continue;
        };
        if matching_cuts.next().is_some()
            || snapshot_permit::snapshot_delivery_required(&transition.record, query.recipient)
                && !snapshot_permit::has_exact_snapshot_flush(
                    &transition.record,
                    &update.record,
                    cut,
                    query.authorization_hash,
                )
            || binding.replace(operation_id).is_some()
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    }
    binding
        .map(|operation_id| StreamAppliedAckBinding { operation_id })
        .ok_or(RuntimeStoreError::PublicationMismatch)
}

pub(crate) fn validate_stream_cuts(
    operation: KeyTransitionOperation,
    cuts: &[KeyTransitionStreamCut],
) -> Result<(), RuntimeStoreError> {
    if operation == KeyTransitionOperation::ActivateConversation {
        return if cuts.is_empty() {
            Ok(())
        } else {
            Err(RuntimeStoreError::PublicationMismatch)
        };
    }
    if operation == KeyTransitionOperation::CounterRecovery && cuts.is_empty() {
        return Ok(());
    }
    if cuts.is_empty()
        || cuts.len() > MAX_KEY_TRANSITION_CONVERSATIONS + 1
        || matches!(
            operation,
            KeyTransitionOperation::Renew | KeyTransitionOperation::CounterRecovery
        ) && cuts.len() != 1
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let mut catalog_count = 0_usize;
    let mut previous: Option<(KeyTransitionStreamScope, [u8; 16])> = None;
    for cut in cuts {
        if cut.publication_stream_id == [0; 16]
            || cut.stream_route == [0; 16]
            || cut.generation == [0; 16]
            || matches!(cut.scope, KeyTransitionStreamScope::Conversation(id) if id == [0; 16])
            || cut.epoch_barrier_sha256 == [0; 32]
            || (cut.old_epoch == 0 && operation != KeyTransitionOperation::Add)
            || cut.new_epoch
                != cut
                    .old_epoch
                    .checked_add(1)
                    .ok_or(RuntimeStoreError::PublicationCounterExhausted)?
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        // Relay committed outer 与 tagged Runtime inner 是独立 cursor。这里仅验证
        // transition 结构；`freeze_key_barriers` 随后的 exact Store projection 会把
        // 两轴逐一绑定到 authenticated publication stream，并在 Store projection
        // 入口单独约束 `(BeforeFirst, At(H))` 必须是 rotation baseline。
        let expected_barrier = match cut.relay_committed_outer {
            None => 0,
            Some(value) => value
                .checked_add(1)
                .ok_or(RuntimeStoreError::PublicationCounterExhausted)?,
        };
        if cut.barrier_sequence != expected_barrier {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        if cut.barrier_sequence == u64::MAX {
            return Err(RuntimeStoreError::PublicationCounterExhausted);
        }
        if cut.scope == KeyTransitionStreamScope::Catalog {
            catalog_count += 1;
        }
        let identity = (cut.scope, cut.publication_stream_id);
        if previous.is_some_and(|value| value >= identity) {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        previous = Some(identity);
    }
    if operation == KeyTransitionOperation::CounterRecovery {
        if catalog_count > 1 {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    } else if catalog_count != 1 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn zero_cut_transition_allowed(record: &KeyTransitionRecord) -> bool {
    match record.operation {
        KeyTransitionOperation::Add => matches!(
            record.target,
            KeyTransitionTarget::Device(target)
                if record.recipients.as_slice() == [target]
        ),
        KeyTransitionOperation::Renew => false,
        KeyTransitionOperation::Revoke => record.recipients.is_empty(),
        KeyTransitionOperation::ActivateConversation => true,
        KeyTransitionOperation::CounterRecovery => {
            matches!(record.target, KeyTransitionTarget::Device(_))
        }
    }
}

pub(super) fn validate_transition_stream_cuts(
    record: &KeyTransitionRecord,
    cuts: &[KeyTransitionStreamCut],
) -> Result<(), RuntimeStoreError> {
    if cuts.is_empty() {
        return if zero_cut_transition_allowed(record) {
            Ok(())
        } else {
            Err(RuntimeStoreError::PublicationMismatch)
        };
    }
    let has_genesis_sentinel = cuts.iter().any(|cut| cut.old_epoch == 0);
    if has_genesis_sentinel
        && (!matches!(
            (record.operation, record.target),
            (KeyTransitionOperation::Add, KeyTransitionTarget::Device(target))
                if record.recipients.as_slice() == [target]
        ) || cuts
            .iter()
            .any(|cut| cut.old_epoch != 0 || cut.new_epoch != 1))
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    validate_stream_cuts(record.operation, cuts)
}

fn validate_begin(input: &BeginKeyTransition) -> Result<(), RuntimeStoreError> {
    validate_nonzero(input.operation_id)?;
    if input.to_revision
        != input
            .from_revision
            .checked_add(1)
            .ok_or(RuntimeStoreError::PublicationCounterExhausted)?
        || input.to_revision == 0
        || input.created_at_ms > MAX_TERMINAL_BASE_MS
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    validate_recipients(&input.recipients)?;
    validate_replay_retirement(input.operation, input.target, input.replay_retirement)?;
    match (input.operation, input.target) {
        (KeyTransitionOperation::Add, KeyTransitionTarget::Device(target))
        | (KeyTransitionOperation::Renew, KeyTransitionTarget::Device(target))
            if input.recipients.contains(&target) =>
        {
            Ok(())
        }
        (KeyTransitionOperation::Revoke, KeyTransitionTarget::Device(target))
            if !input.recipients.contains(&target) =>
        {
            Ok(())
        }
        (
            KeyTransitionOperation::ActivateConversation,
            KeyTransitionTarget::Conversation {
                conversation_id,
                stream_route,
            },
        ) if conversation_id != [0; 16] && stream_route != [0; 16] => Ok(()),
        (KeyTransitionOperation::CounterRecovery, KeyTransitionTarget::Device(target))
            if input.recipients.contains(&target) =>
        {
            Ok(())
        }
        (
            KeyTransitionOperation::CounterRecovery,
            KeyTransitionTarget::Conversation {
                conversation_id,
                stream_route,
            },
        ) if conversation_id != [0; 16] && stream_route != [0; 16] => Ok(()),
        _ => Err(RuntimeStoreError::PublicationMismatch),
    }
}

fn validate_replay_retirement(
    operation: KeyTransitionOperation,
    target: KeyTransitionTarget,
    retirement: Option<ReplayRetirement>,
) -> Result<(), RuntimeStoreError> {
    let Some(retirement) = retirement else {
        return Ok(());
    };
    if retirement.lifecycle != ReplayRetirementLifecycle::Pending {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let KeyTransitionTarget::Device(target) = target else {
        return Err(RuntimeStoreError::PublicationMismatch);
    };
    let (device_route, old_grant_serial) =
        super::remote_replay::device_command_scope_subject(&retirement.scope)?;
    if device_route != target.device_route
        || match operation {
            KeyTransitionOperation::Renew => old_grant_serial == target.grant_serial,
            KeyTransitionOperation::Revoke => old_grant_serial != target.grant_serial,
            KeyTransitionOperation::Add
            | KeyTransitionOperation::ActivateConversation
            | KeyTransitionOperation::CounterRecovery => true,
        }
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn validate_recipients(recipients: &[KeyTransitionRecipient]) -> Result<(), RuntimeStoreError> {
    if recipients.len() > MAX_KEY_TRANSITION_RECIPIENTS {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let mut previous = None;
    for recipient in recipients {
        if recipient.device_route == [0; 16]
            || recipient.grant_serial == 0
            || previous.is_some_and(|value| value >= *recipient)
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        previous = Some(*recipient);
    }
    Ok(())
}

fn validate_update_set(
    transition: &KeyTransitionRecord,
    updates: &[FrozenKeyUpdate],
) -> Result<(), RuntimeStoreError> {
    if updates.len() != transition.recipients.len() {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    for (recipient, update) in transition.recipients.iter().zip(updates) {
        if update.recipient != *recipient
            || update.key_revision != transition.to_revision
            || canonical_update_hash(&update.canonical_update_set)? == [0; 32]
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    }
    Ok(())
}

fn validate_ack(input: &AcknowledgeKeyUpdate) -> Result<(), RuntimeStoreError> {
    validate_nonzero(input.operation_id)?;
    validate_nonzero(input.recipient.device_route)?;
    validate_nonzero(input.update_hash)?;
    if input.recipient.grant_serial == 0
        || input.key_revision == 0
        || input.canonical_ack.is_empty()
        || input.canonical_ack.len() > MAX_CANONICAL_KEY_ACK_BYTES
        || input.acknowledged_at_ms > MAX_TERMINAL_BASE_MS
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn validate_stream_applied_ack(input: &AcknowledgeStreamApplied) -> Result<(), RuntimeStoreError> {
    validate_nonzero(input.operation_id)?;
    validate_nonzero(input.recipient.device_route)?;
    validate_nonzero(input.stream_route)?;
    validate_nonzero(input.stream_generation)?;
    validate_nonzero(input.epoch_barrier_sha256)?;
    validate_nonzero(input.authorization_hash)?;
    if matches!(input.scope, KeyTransitionStreamScope::Conversation(id) if id == [0; 16]) {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if input.recipient.grant_serial == 0
        || input.key_revision == 0
        || input.key_epoch == 0
        || input.applied_stream_seq == u64::MAX
        || input.canonical_ack.is_empty()
        || input.canonical_ack.len() > MAX_CANONICAL_KEY_ACK_BYTES
        || input.acknowledged_at_ms > MAX_TERMINAL_BASE_MS
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn applied_ack_identity(
    record: &StreamAppliedAckRecord,
) -> (KeyTransitionStreamScope, [u8; 16], [u8; 16], u64) {
    (
        record.scope,
        record.stream_route,
        record.stream_generation,
        record.applied_stream_seq,
    )
}

fn snapshot_flush_identity(
    record: &TransitionSnapshotFlushRecord,
) -> (KeyTransitionStreamScope, [u8; 16], [u8; 16]) {
    (record.scope, record.stream_route, record.generation)
}

fn same_applied_ack(left: &StreamAppliedAckRecord, right: &StreamAppliedAckRecord) -> bool {
    applied_ack_identity(left) == applied_ack_identity(right)
        && left.inner_cursor == right.inner_cursor
        && left.key_revision == right.key_revision
        && left.key_epoch == right.key_epoch
        && left.epoch_barrier_sha256 == right.epoch_barrier_sha256
        && left.canonical_ack == right.canonical_ack
}

fn validate_nonzero<const N: usize>(bytes: [u8; N]) -> Result<(), RuntimeStoreError> {
    if bytes == [0; N] {
        Err(RuntimeStoreError::PublicationMismatch)
    } else {
        Ok(())
    }
}

fn require_monotonic_time(previous: u64, observed: u64) -> Result<(), RuntimeStoreError> {
    if observed > MAX_TERMINAL_BASE_MS {
        return Err(RuntimeStoreError::TimeOutOfRange);
    }
    if observed < previous {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: previous,
            observed_ms: observed,
        });
    }
    Ok(())
}

fn same_begin(existing: &KeyTransitionRecord, requested: &KeyTransitionRecord) -> bool {
    existing.operation_id == requested.operation_id
        && existing.operation == requested.operation
        && existing.target == requested.target
        && existing.from_revision == requested.from_revision
        && existing.to_revision == requested.to_revision
        && existing.recipients == requested.recipients
        && existing.replay_retirement == requested.replay_retirement
        && existing.created_at_ms == requested.created_at_ms
}

fn encoded_transition_len(record: &KeyTransitionRecord) -> Result<u64, RuntimeStoreError> {
    u64::try_from(encode_transition(record)?.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN as u64 + 4 * 1024)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "key transition write projection",
        })
}

fn admit_transition_write(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    projected_write_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::Current,
    )
}

fn advance_exact_phase(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    expected: KeyTransitionPhase,
    next_phase: KeyTransitionPhase,
    changed_at_ms: u64,
) -> Result<KeyTransitionRecord, RuntimeStoreError> {
    validate_nonzero(operation_id)?;
    admit_transition_write(state, config, 128 * 1024)?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let authenticated = load_transition(&transaction, &key_bundle, database_id, operation_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if authenticated.record.phase == next_phase {
        if authenticated.record.state_changed_at_ms == changed_at_ms {
            transaction.rollback()?;
            return Ok(authenticated.record);
        }
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if authenticated.record.phase != expected
        || authenticated.record.terminal.is_some()
        || next_phase.rank() != expected.rank() + 1
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    require_monotonic_time(authenticated.record.state_changed_at_ms, changed_at_ms)?;
    let mut changed = authenticated.record.clone();
    changed.phase = next_phase;
    changed.state_changed_at_ms = changed_at_ms;
    let mut next = ledger.clone();
    replace_transition(
        &transaction,
        &key_bundle,
        database_id,
        &authenticated,
        &changed,
        &mut next,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(changed)
}
