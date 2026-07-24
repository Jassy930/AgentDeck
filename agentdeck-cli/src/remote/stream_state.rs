//! Persistent remote live-stream 的严格本地状态编码。
//!
//! `StreamBindingV1` 原始 canonical bytes 始终保留；Relay outer applied/ACK、Runtime
//! inner observed/applied、receive replay window 与 retired subscription cleanup outbox 是
//! 彼此独立的轴，不能互相推导。

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use agentdeck_protocol::e2ee::{
    EpochBarrierV1, KeyId, KeyPurpose, STREAM_BINDING_MAX_CANONICAL_BYTES, StreamAppliedAckV1,
    StreamBindingV1,
};
use agentdeck_protocol::relay_v2::{KeyDirectoryRevision, StreamGenerationId, StreamRouteId};
use agentdeck_protocol::runtime::{ConversationId, RuntimeInnerCursor, StreamCursor};
use thiserror::Error;

const STREAM_STATE_MAGIC: &[u8; 4] = b"ADSB";
const LEGACY_STREAM_STATE_VERSION: u16 = 1;
const PREVIOUS_STREAM_STATE_VERSION: u16 = 2;
const RETIRED_STREAM_STATE_VERSION: u16 = 3;
const STREAM_STATE_VERSION: u16 = 4;
const STREAM_STATE_HEADER_LEN: usize = 12;
const MAX_CONVERSATION_ID_BYTES: usize = 1_024;
const MAX_LEGACY_DURABLE_STREAM_STATE_BYTES: usize = 16 * 1_024;
const MAX_DURABLE_STREAM_STATE_BYTES: usize = 512 * 1_024;
const MAX_STREAM_REPLAY_ENTRIES: usize = 4_096;
const MAX_STREAM_REPLAY_DISTANCE: u64 = 4_095;
// 单 connection 的 live subscription quota 同为 64；handoff cleanup 不允许越过该硬界。
const MAX_RETIRED_SUBSCRIPTIONS: usize = 64;
pub(crate) const MAX_DURABLE_STREAM_BINDINGS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableStreamReplayTupleV1 {
    key_id: KeyId,
    key_directory_revision: KeyDirectoryRevision,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    stream_seq: u64,
    sender_counter: u64,
    ciphertext_sha256: [u8; 32],
}

impl DurableStreamReplayTupleV1 {
    #[must_use]
    pub const fn key_id(self) -> KeyId {
        self.key_id
    }

    #[must_use]
    pub const fn key_directory_revision(self) -> KeyDirectoryRevision {
        self.key_directory_revision
    }

    #[must_use]
    pub const fn stream_seq(self) -> u64 {
        self.stream_seq
    }

    #[must_use]
    pub const fn stream_route(self) -> StreamRouteId {
        self.stream_route
    }

    #[must_use]
    pub const fn stream_generation(self) -> StreamGenerationId {
        self.stream_generation
    }

    #[must_use]
    pub const fn sender_counter(self) -> u64 {
        self.sender_counter
    }

    #[must_use]
    pub const fn ciphertext_sha256(self) -> [u8; 32] {
        self.ciphertext_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PendingEpochBarrierV1 {
    replay_tuple: DurableStreamReplayTupleV1,
    replay_quarantined: bool,
}

impl PendingEpochBarrierV1 {
    #[must_use]
    pub const fn replay_tuple(&self) -> DurableStreamReplayTupleV1 {
        self.replay_tuple
    }

    #[must_use]
    pub const fn replay_quarantined(&self) -> bool {
        self.replay_quarantined
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableRetiredSubscriptionV1 {
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
}

impl DurableRetiredSubscriptionV1 {
    #[must_use]
    pub const fn stream_route(self) -> StreamRouteId {
        self.stream_route
    }

    #[must_use]
    pub const fn stream_generation(self) -> StreamGenerationId {
        self.stream_generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableStreamBindingV1 {
    binding: StreamBindingV1,
    outer_applied: StreamCursor,
    outer_acked: StreamCursor,
    inner_observed: RuntimeInnerCursor,
    inner_applied: RuntimeInnerCursor,
    replay_quarantined: bool,
    replay_entries: Vec<DurableStreamReplayTupleV1>,
    retired_subscriptions: Vec<DurableRetiredSubscriptionV1>,
    pending_epoch_barrier: Option<PendingEpochBarrierV1>,
    latest_stream_applied_ack_basis: Option<StreamAppliedAckV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamPublishDisposition {
    Fresh,
    PendingDuplicate,
    AppliedDuplicate,
    NonceReuseQuarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamDirectApplyMode {
    Overlap,
    Apply,
}

impl DurableStreamBindingV1 {
    pub(crate) fn from_stream_binding(
        binding: StreamBindingV1,
    ) -> Result<Self, RemoteStreamStateError> {
        let value = Self {
            outer_applied: binding.stream_cursor,
            outer_acked: StreamCursor::BeforeFirst,
            inner_observed: binding.inner_cursor.clone(),
            inner_applied: binding.inner_cursor.clone(),
            binding,
            replay_quarantined: false,
            replay_entries: Vec::new(),
            retired_subscriptions: Vec::new(),
            pending_epoch_barrier: None,
            latest_stream_applied_ack_basis: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// 从完整 subscription bootstrap 建立初始 durable reducer cut。Relay binding 的
    /// inner cursor 是 publication cut；directed snapshot/backfill 的 SyncComplete 可以
    /// 在线性化期间推进到同 target 的更高 inner cursor。
    pub(crate) fn from_subscription_bootstrap(
        binding: StreamBindingV1,
        inner_applied: RuntimeInnerCursor,
    ) -> Result<Self, RemoteStreamStateError> {
        let value = Self {
            outer_applied: binding.stream_cursor,
            outer_acked: StreamCursor::BeforeFirst,
            inner_observed: binding.inner_cursor.clone(),
            binding,
            inner_applied,
            replay_quarantined: false,
            replay_entries: Vec::new(),
            retired_subscriptions: Vec::new(),
            pending_epoch_barrier: None,
            latest_stream_applied_ack_basis: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// 冷 subscription 为同一 target 安装新的 snapshot cut。相同 key epoch 下 replay
    /// window 属于 key-directory slot，不能因重连或 Relay generation 轮换被清空。Catalog
    /// slot 不绑定 publication route；Conversation slot 由 directory stream route 区分。
    pub(crate) fn replace_subscription_bootstrap(
        &self,
        binding: StreamBindingV1,
        inner_applied: RuntimeInnerCursor,
    ) -> Result<Self, RemoteStreamStateError> {
        self.validate()?;
        if self.pending_epoch_barrier.is_some() {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let candidate = Self::from_subscription_bootstrap(binding, inner_applied)?;
        if self.target_key() != candidate.target_key() {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        if cursor_cmp(
            inner_cursor_value(&candidate.binding.inner_cursor),
            inner_cursor_value(&self.inner_observed),
        ) == Ordering::Less
            || cursor_cmp(
                inner_cursor_value(&candidate.inner_applied),
                inner_cursor_value(&self.inner_applied),
            ) == Ordering::Less
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let active_changed = self.binding.stream_route != candidate.binding.stream_route
            || self.binding.stream_generation != candidate.binding.stream_generation;
        let candidate_pair = subscription_pair(
            candidate.binding.stream_route,
            candidate.binding.stream_generation,
        );
        let mut retired_subscriptions = self.retired_subscriptions.clone();
        if active_changed {
            if retired_subscriptions
                .binary_search_by(|retired| retired_pair(retired).cmp(&candidate_pair))
                .is_ok()
            {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
            if retired_subscriptions.len() == MAX_RETIRED_SUBSCRIPTIONS {
                return Err(RemoteStreamStateError::TooLarge);
            }
            let retired = DurableRetiredSubscriptionV1 {
                stream_route: self.binding.stream_route,
                stream_generation: self.binding.stream_generation,
            };
            let position = match retired_subscriptions
                .binary_search_by(|existing| retired_pair(existing).cmp(&retired_pair(&retired)))
            {
                Ok(_) => return Err(RemoteStreamStateError::InvalidCanonical),
                Err(position) => position,
            };
            retired_subscriptions.insert(position, retired);
        }
        let candidate = Self {
            retired_subscriptions,
            ..candidate
        };
        if !same_replay_scope(&self.binding, &candidate.binding) {
            candidate.validate()?;
            return Ok(candidate);
        }
        if self.replay_quarantined
            || (self.binding.stream_route == candidate.binding.stream_route
                && self.binding.stream_generation == candidate.binding.stream_generation
                && cursor_cmp(self.outer_applied, candidate.outer_applied) == Ordering::Greater)
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let preserved = Self {
            replay_entries: self.replay_entries.clone(),
            ..candidate
        };
        preserved.validate()?;
        Ok(preserved)
    }

    #[must_use]
    pub const fn binding(&self) -> &StreamBindingV1 {
        &self.binding
    }

    /// 同一 shared-key epoch 的 directory carrier rewrap 只推进 exact-next revision。
    /// 所有 subscription、cursor、Relay ACK、replay/quarantine 与 cleanup outbox 状态原样
    /// 保留；旧 revision 的 barrier ACK basis 不能用新 command key 重封，因此会被清除。
    /// shared-key rotation 必须走独立的 epoch barrier/新 binding 安装路径。
    pub(crate) fn with_rewrapped_key_revision(
        &self,
        next_revision: KeyDirectoryRevision,
    ) -> Result<Self, RemoteStreamStateError> {
        self.validate()?;
        if !matches!(
            self.binding.key_id.purpose,
            KeyPurpose::Catalog | KeyPurpose::ConversationDek
        ) {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let expected = self
            .binding
            .key_directory_revision
            .next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if next_revision != expected {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        if self.pending_epoch_barrier.is_some() {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }

        let mut rewrapped = self.clone();
        rewrapped.binding.key_directory_revision = next_revision;
        rewrapped.latest_stream_applied_ack_basis = None;
        rewrapped.validate()?;
        Ok(rewrapped)
    }

    /// 任一后续 directory transition 都会使旧 revision 的 StreamAppliedAck basis 失去
    /// command-key sealing authority。rotation 的 stream binding 仍停在旧 epoch/revision
    /// 等待下一条 barrier，因此只显式 supersede receipt，其他 durable 轴逐字保留。
    pub(crate) fn with_superseded_stream_applied_ack(
        &self,
    ) -> Result<Self, RemoteStreamStateError> {
        self.validate()?;
        let mut superseded = self.clone();
        superseded.latest_stream_applied_ack_basis = None;
        superseded.validate()?;
        Ok(superseded)
    }

    #[must_use]
    pub const fn outer_applied(&self) -> StreamCursor {
        self.outer_applied
    }

    #[must_use]
    pub const fn outer_acked(&self) -> StreamCursor {
        self.outer_acked
    }

    #[must_use]
    pub const fn inner_observed(&self) -> &RuntimeInnerCursor {
        &self.inner_observed
    }

    #[must_use]
    pub const fn inner_applied(&self) -> &RuntimeInnerCursor {
        &self.inner_applied
    }

    #[must_use]
    pub fn replay_tuple(&self) -> Option<DurableStreamReplayTupleV1> {
        self.replay_entries
            .iter()
            .filter(|entry| {
                entry.stream_route == self.binding.stream_route
                    && entry.stream_generation == self.binding.stream_generation
            })
            .max_by_key(|entry| entry.stream_seq)
            .copied()
    }

    #[must_use]
    pub const fn replay_entry_count(&self) -> usize {
        self.replay_entries.len()
    }

    #[must_use]
    pub const fn replay_quarantined(&self) -> bool {
        self.replay_quarantined
    }

    #[must_use]
    pub(crate) const fn pending_epoch_barrier(&self) -> Option<&PendingEpochBarrierV1> {
        self.pending_epoch_barrier.as_ref()
    }

    #[must_use]
    pub(crate) const fn latest_stream_applied_ack_basis(&self) -> Option<&StreamAppliedAckV1> {
        self.latest_stream_applied_ack_basis.as_ref()
    }

    #[must_use]
    pub(crate) fn retired_subscriptions(&self) -> &[DurableRetiredSubscriptionV1] {
        &self.retired_subscriptions
    }

    /// 新 active subscription 的 exact ReplayComplete barrier 已确认后，才允许清空旧
    /// `(streamRoute, generation)` cleanup outbox。错误 route/generation/cut 一律不改状态。
    pub(crate) fn clear_retired_subscriptions_after_replay_barrier(
        &self,
        stream_route: StreamRouteId,
        stream_generation: StreamGenerationId,
        current_cursor: StreamCursor,
    ) -> Result<Self, RemoteStreamStateError> {
        if stream_route != self.binding.stream_route
            || stream_generation != self.binding.stream_generation
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        self.validate_replay_complete(current_cursor)?;
        let mut cleared = self.clone();
        cleared.retired_subscriptions.clear();
        cleared.validate()?;
        Ok(cleared)
    }

    /// 只把已经完整应用的 exact outer cut 标记为已发送 ACK。ACK 不允许跳过当前
    /// `outer_applied`、回退或预先承诺尚未应用的 Relay sequence。
    pub(crate) fn with_committed_outer_ack(
        &self,
        up_to_seq: u64,
    ) -> Result<Self, RemoteStreamStateError> {
        let acked = StreamCursor::At(up_to_seq);
        if self.replay_quarantined
            || self.outer_applied != acked
            || cursor_cmp(self.outer_acked, acked) == Ordering::Greater
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let mut value = self.clone();
        value.outer_acked = acked;
        value.validate()?;
        Ok(value)
    }

    /// 在 AEAD open 之前 durable admit 一条已完成 canonical outer/header/AAD/signature
    /// 验证的 Publish。新 tuple 必须是 exact-next outer sequence；sender counter 可在
    /// 4096 数值窗口内乱序到达，但 floor 以下的 unseen counter 会被拒绝。相同 tuple 只
    /// 区分 pending/applied 幂等重放，同 counter 不同 ciphertext 会持久化 quarantine。
    #[cfg(test)]
    pub(crate) fn admit_publish(
        &self,
        stream_seq: u64,
        sender_counter: u64,
        ciphertext_sha256: [u8; 32],
    ) -> Result<(Self, StreamPublishDisposition), RemoteStreamStateError> {
        self.admit_publish_at_authenticated_revision(
            self.binding.key_directory_revision,
            stream_seq,
            sender_counter,
            ciphertext_sha256,
        )
    }

    /// 显式带入已完成 signature/AAD 验证的 header revision。它只允许旧 revision 的 exact
    /// durable duplicate；旧 revision 的 fresh tuple 一律作为 rollback 拒绝，避免
    /// same-epoch rewrap 后把网络输入误标成当前 revision。
    pub(crate) fn admit_publish_at_authenticated_revision(
        &self,
        authenticated_revision: KeyDirectoryRevision,
        stream_seq: u64,
        sender_counter: u64,
        ciphertext_sha256: [u8; 32],
    ) -> Result<(Self, StreamPublishDisposition), RemoteStreamStateError> {
        self.validate()?;
        if authenticated_revision.value() == 0
            || authenticated_revision.value() > self.binding.key_directory_revision.value()
            || ciphertext_sha256 == [0; 32]
            || StreamCursor::At(stream_seq).checked_next().is_err()
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        if self.pending_epoch_barrier.is_some() {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        if self.replay_quarantined {
            return Ok((
                self.clone(),
                StreamPublishDisposition::NonceReuseQuarantined,
            ));
        }
        if let Some(replay) = self.replay_entries.iter().find(|entry| {
            same_nonce_scope(entry.key_id, self.binding.key_id)
                && entry.sender_counter == sender_counter
        }) {
            if replay.key_directory_revision != authenticated_revision
                || replay.stream_route != self.binding.stream_route
                || replay.stream_generation != self.binding.stream_generation
                || replay.stream_seq != stream_seq
                || replay.ciphertext_sha256 != ciphertext_sha256
            {
                let mut quarantined = self.clone();
                quarantined.replay_quarantined = true;
                quarantined.validate()?;
                return Ok((quarantined, StreamPublishDisposition::NonceReuseQuarantined));
            }
            let disposition = if cursor_cmp(StreamCursor::At(stream_seq), self.outer_applied)
                != Ordering::Greater
            {
                StreamPublishDisposition::AppliedDuplicate
            } else if self.outer_applied.checked_next().ok() == Some(stream_seq) {
                StreamPublishDisposition::PendingDuplicate
            } else {
                return Err(RemoteStreamStateError::InvalidCanonical);
            };
            return Ok((self.clone(), disposition));
        }
        if self.replay_entries.iter().any(|entry| {
            entry.stream_route == self.binding.stream_route
                && entry.stream_generation == self.binding.stream_generation
                && entry.stream_seq == stream_seq
        }) {
            let mut quarantined = self.clone();
            quarantined.replay_quarantined = true;
            quarantined.validate()?;
            return Ok((quarantined, StreamPublishDisposition::NonceReuseQuarantined));
        }
        let replay_floor = replay_scope_high_water(&self.replay_entries, self.binding.key_id)
            .map_or(0, |high_water| {
                high_water.saturating_sub(MAX_STREAM_REPLAY_DISTANCE)
            });
        if authenticated_revision != self.binding.key_directory_revision
            || self.outer_applied.checked_next().ok() != Some(stream_seq)
            || (!self.replay_entries.is_empty() && sender_counter < replay_floor)
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let mut pending = self.clone();
        let replay = DurableStreamReplayTupleV1 {
            key_id: self.binding.key_id,
            key_directory_revision: authenticated_revision,
            stream_route: self.binding.stream_route,
            stream_generation: self.binding.stream_generation,
            stream_seq,
            sender_counter,
            ciphertext_sha256,
        };
        let insertion = match pending
            .replay_entries
            .binary_search_by(|entry| replay_cmp(entry, &replay))
        {
            Ok(_) => return Err(RemoteStreamStateError::InvalidCanonical),
            Err(insertion) => insertion,
        };
        pending.replay_entries.insert(insertion, replay);
        let replay_high_water =
            replay_scope_high_water(&pending.replay_entries, self.binding.key_id)
                .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        let replay_floor = replay_high_water.saturating_sub(MAX_STREAM_REPLAY_DISTANCE);
        pending.replay_entries.retain(|entry| {
            !same_nonce_scope(entry.key_id, self.binding.key_id)
                || entry.sender_counter >= replay_floor
        });
        if pending.replay_entries.len() > MAX_STREAM_REPLAY_ENTRIES {
            return Err(RemoteStreamStateError::TooLarge);
        }
        pending.validate()?;
        Ok((pending, StreamPublishDisposition::Fresh))
    }

    /// 在 AEAD open 前只接纳当前 shared-key scope 的 exact-next epoch/revision barrier
    /// carrier。future scope 不从网络输入推导，只允许由当前 durable binding 唯一计算出的
    /// `(same purpose, epoch+1, revision+1)`；pending tuple 在 activation 前独立持久化。
    pub(crate) fn admit_pending_epoch_barrier(
        &self,
        key_id: KeyId,
        key_directory_revision: KeyDirectoryRevision,
        stream_seq: u64,
        sender_counter: u64,
        ciphertext_sha256: [u8; 32],
    ) -> Result<(Self, StreamPublishDisposition), RemoteStreamStateError> {
        self.validate()?;
        let expected_epoch = self
            .binding
            .key_id
            .epoch
            .checked_add(1)
            .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        let expected_revision = self
            .binding
            .key_directory_revision
            .next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        let expected_stream_seq = self
            .outer_applied
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if self.replay_quarantined
            || self.inner_observed != self.inner_applied
            || ciphertext_sha256 == [0; 32]
            || key_id.purpose != self.binding.key_id.purpose
            || key_id.epoch != expected_epoch
            || key_directory_revision != expected_revision
            || stream_seq != expected_stream_seq
            || StreamCursor::At(stream_seq).checked_next().is_err()
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }

        let replay_tuple = DurableStreamReplayTupleV1 {
            key_id,
            key_directory_revision,
            stream_route: self.binding.stream_route,
            stream_generation: self.binding.stream_generation,
            stream_seq,
            sender_counter,
            ciphertext_sha256,
        };
        if let Some(existing) = self.pending_epoch_barrier {
            if existing.replay_quarantined {
                return Ok((
                    self.clone(),
                    StreamPublishDisposition::NonceReuseQuarantined,
                ));
            }
            let existing_tuple = existing.replay_tuple;
            if existing_tuple.key_id != key_id
                || existing_tuple.key_directory_revision != key_directory_revision
                || existing_tuple.stream_route != replay_tuple.stream_route
                || existing_tuple.stream_generation != replay_tuple.stream_generation
                || existing_tuple.stream_seq != stream_seq
            {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
            if existing_tuple.sender_counter == sender_counter
                && existing_tuple.ciphertext_sha256 == ciphertext_sha256
            {
                return Ok((self.clone(), StreamPublishDisposition::PendingDuplicate));
            }
            let mut quarantined = self.clone();
            quarantined
                .pending_epoch_barrier
                .as_mut()
                .ok_or(RemoteStreamStateError::InvalidCanonical)?
                .replay_quarantined = true;
            quarantined.validate()?;
            return Ok((quarantined, StreamPublishDisposition::NonceReuseQuarantined));
        }

        if self.replay_entries.len() == MAX_STREAM_REPLAY_ENTRIES {
            return Err(RemoteStreamStateError::TooLarge);
        }
        if self.replay_entries.iter().any(|entry| {
            entry.stream_route == replay_tuple.stream_route
                && entry.stream_generation == replay_tuple.stream_generation
                && entry.stream_seq == replay_tuple.stream_seq
        }) || self.replay_entries.iter().any(|entry| {
            same_nonce_scope(entry.key_id, replay_tuple.key_id)
                && entry.sender_counter == replay_tuple.sender_counter
        }) {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }

        let mut pending = self.clone();
        pending.pending_epoch_barrier = Some(PendingEpochBarrierV1 {
            replay_tuple,
            replay_quarantined: false,
        });
        pending.validate()?;
        Ok((pending, StreamPublishDisposition::Fresh))
    }

    /// 只在 pending carrier 已完成新 key AEAD open，且 payload 是精确 epoch barrier 时原子
    /// 激活。`D=next(C)` 被记为 outer applied，inner cut 保持 H 不前进，并持久化后续由
    /// DeviceCommandTx 认证发送的 exact `StreamAppliedAckV1` basis。
    pub(crate) fn activate_epoch_barrier(
        &self,
        stream_route: StreamRouteId,
        barrier: &EpochBarrierV1,
    ) -> Result<Self, RemoteStreamStateError> {
        self.validate()?;
        barrier
            .validate()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if self.pending_epoch_barrier.is_none() {
            if self.is_exact_committed_epoch_barrier(stream_route, barrier)? {
                return Ok(self.clone());
            }
            return Err(RemoteStreamStateError::InvalidCanonical);
        }

        let pending = self
            .pending_epoch_barrier
            .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        let replay = pending.replay_tuple;
        let next_epoch = self
            .binding
            .key_id
            .epoch
            .checked_add(1)
            .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        let next_revision = self
            .binding
            .key_directory_revision
            .next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        let next_stream_seq = self
            .outer_applied
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if self.replay_quarantined
            || pending.replay_quarantined
            || stream_route != self.binding.stream_route
            || barrier.stream_generation != self.binding.stream_generation
            || barrier.stream_cursor != self.outer_applied
            || barrier.inner_cursor != self.inner_observed
            || barrier.inner_cursor != self.inner_applied
            || barrier.old_epoch != self.binding.key_id.epoch
            || barrier.new_epoch != next_epoch
            || barrier.key_directory_revision != next_revision
            || (self.outer_acked != StreamCursor::BeforeFirst
                && self.outer_acked != barrier.stream_cursor)
            || replay.key_id
                != (KeyId {
                    purpose: self.binding.key_id.purpose,
                    epoch: barrier.new_epoch,
                })
            || replay.key_directory_revision != barrier.key_directory_revision
            || replay.stream_route != stream_route
            || replay.stream_generation != barrier.stream_generation
            || replay.stream_seq != next_stream_seq
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }

        let mut binding = self.binding.clone();
        binding.stream_cursor = barrier.stream_cursor;
        binding.inner_cursor = barrier.inner_cursor.clone();
        binding.key_id = replay.key_id;
        binding.key_directory_revision = replay.key_directory_revision;

        let ack = StreamAppliedAckV1 {
            format_version: binding.format_version,
            runtime_protocol_version: binding.runtime_protocol_version,
            relay_protocol_version: binding.relay_protocol_version,
            machine_route: binding.machine_route,
            device_route: binding.device_route,
            grant_serial: binding.grant_serial,
            root_trust_epoch: binding.root_trust_epoch,
            stream_route,
            stream_generation: barrier.stream_generation,
            applied_stream_seq: next_stream_seq,
            inner_cursor: barrier.inner_cursor.clone(),
            key_directory_revision: barrier.key_directory_revision,
            key_epoch: barrier.new_epoch,
            epoch_barrier_sha256: barrier
                .canonical_sha256()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?,
        };
        ack.validate_for_barrier(stream_route, barrier)
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;

        let mut activated = self.clone();
        activated.binding = binding;
        activated.outer_applied = StreamCursor::At(next_stream_seq);
        let insertion = match activated
            .replay_entries
            .binary_search_by(|entry| replay_cmp(entry, &replay))
        {
            Ok(_) => return Err(RemoteStreamStateError::InvalidCanonical),
            Err(position) => position,
        };
        activated.replay_entries.insert(insertion, replay);
        activated.pending_epoch_barrier = None;
        activated.latest_stream_applied_ack_basis = Some(ack);
        activated.validate()?;
        Ok(activated)
    }

    fn is_exact_committed_epoch_barrier(
        &self,
        stream_route: StreamRouteId,
        barrier: &EpochBarrierV1,
    ) -> Result<bool, RemoteStreamStateError> {
        let next_stream_seq = barrier
            .stream_cursor
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        let Some(ack) = self.latest_stream_applied_ack_basis.as_ref() else {
            return Ok(false);
        };
        if stream_route != self.binding.stream_route
            || barrier.stream_generation != self.binding.stream_generation
            || barrier.stream_cursor != self.binding.stream_cursor
            || barrier.inner_cursor != self.binding.inner_cursor
            || barrier.new_epoch != self.binding.key_id.epoch
            || barrier.key_directory_revision != self.binding.key_directory_revision
            || cursor_cmp(StreamCursor::At(next_stream_seq), self.outer_applied)
                == Ordering::Greater
            || cursor_cmp(
                inner_cursor_value(&barrier.inner_cursor),
                inner_cursor_value(&self.inner_observed),
            ) == Ordering::Greater
            || cursor_cmp(
                inner_cursor_value(&barrier.inner_cursor),
                inner_cursor_value(&self.inner_applied),
            ) == Ordering::Greater
        {
            return Ok(false);
        }
        ack.validate_for_barrier(stream_route, barrier)
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        Ok(true)
    }

    /// 判断 exact-next authenticated inner item 是 bootstrap snapshot 已覆盖的 overlap，
    /// 还是需要真正送入 reducer 的新 item。任何 target 漂移、跳号或 observed 超前都拒绝。
    pub(crate) fn direct_apply_mode(
        &self,
        observed_after: &RuntimeInnerCursor,
    ) -> Result<StreamDirectApplyMode, RemoteStreamStateError> {
        self.validate()?;
        if self.replay_quarantined
            || !same_target(&self.inner_observed, observed_after)
            || inner_cursor_value(&self.inner_observed).checked_next().ok()
                != inner_cursor_value(observed_after).high_water()
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        match cursor_cmp(
            inner_cursor_value(&self.inner_observed),
            inner_cursor_value(&self.inner_applied),
        ) {
            Ordering::Less
                if cursor_cmp(
                    inner_cursor_value(observed_after),
                    inner_cursor_value(&self.inner_applied),
                ) != Ordering::Greater =>
            {
                Ok(StreamDirectApplyMode::Overlap)
            }
            Ordering::Equal => Ok(StreamDirectApplyMode::Apply),
            Ordering::Less | Ordering::Greater => Err(RemoteStreamStateError::InvalidCanonical),
        }
    }

    /// AEAD、canonical Runtime item 与 clone reducer 全部验证后，原子推进 exact outer 与
    /// observed inner；只有非 overlap item 同时推进 applied inner。
    pub(crate) fn commit_direct_publish(
        &self,
        stream_seq: u64,
        observed_after: RuntimeInnerCursor,
    ) -> Result<(Self, StreamDirectApplyMode), RemoteStreamStateError> {
        if self.replay_quarantined {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let replay = self
            .replay_entries
            .iter()
            .find(|entry| {
                entry.stream_route == self.binding.stream_route
                    && entry.stream_generation == self.binding.stream_generation
                    && entry.stream_seq == stream_seq
            })
            .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        if replay.stream_seq != stream_seq
            || self.outer_applied.checked_next().ok() != Some(stream_seq)
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let mode = self.direct_apply_mode(&observed_after)?;
        let mut committed = self.clone();
        committed.outer_applied = StreamCursor::At(stream_seq);
        committed.inner_observed = observed_after.clone();
        if mode == StreamDirectApplyMode::Apply {
            committed.inner_applied = observed_after;
        }
        committed.validate()?;
        Ok((committed, mode))
    }

    pub(crate) fn validate_gap(
        &self,
        need_stream_seq: u64,
        oldest_stream_seq: u64,
    ) -> Result<(), RemoteStreamStateError> {
        self.validate()?;
        if !self.replay_quarantined
            && self.outer_applied.checked_next().ok() == Some(need_stream_seq)
            && oldest_stream_seq > need_stream_seq
        {
            Ok(())
        } else {
            Err(RemoteStreamStateError::InvalidCanonical)
        }
    }

    pub(crate) fn validate_replay_complete(
        &self,
        current_cursor: StreamCursor,
    ) -> Result<(), RemoteStreamStateError> {
        self.validate()?;
        if !self.replay_quarantined && current_cursor == self.outer_applied {
            Ok(())
        } else {
            Err(RemoteStreamStateError::InvalidCanonical)
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RemoteStreamStateError> {
        self.validate()?;
        let binding = self
            .binding
            .canonical_bytes()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        let mut body = Vec::with_capacity(binding.len() + 256);
        put_bytes(&mut body, &binding)?;
        put_cursor(&mut body, self.outer_applied);
        put_cursor(&mut body, self.outer_acked);
        put_inner_cursor(&mut body, &self.inner_observed)?;
        put_inner_cursor(&mut body, &self.inner_applied)?;
        body.push(u8::from(self.replay_quarantined));
        put_replay_count(&mut body, self.replay_entries.len())?;
        for replay in &self.replay_entries {
            put_replay_tuple_v4(&mut body, replay);
        }
        put_retired_subscriptions(&mut body, &self.retired_subscriptions)?;
        match self.pending_epoch_barrier {
            None => body.push(0),
            Some(pending) => {
                body.push(1);
                put_replay_tuple_v4(&mut body, &pending.replay_tuple);
                body.push(u8::from(pending.replay_quarantined));
            }
        }
        match &self.latest_stream_applied_ack_basis {
            None => body.push(0),
            Some(ack) => {
                body.push(1);
                let ack = ack
                    .canonical_bytes()
                    .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
                put_bytes(&mut body, &ack)?;
            }
        }
        if body.len() > MAX_DURABLE_STREAM_STATE_BYTES - STREAM_STATE_HEADER_LEN {
            return Err(RemoteStreamStateError::TooLarge);
        }
        encode_stream_state_body(STREAM_STATE_VERSION, body)
    }

    fn legacy_v2_canonical_bytes(&self) -> Result<Vec<u8>, RemoteStreamStateError> {
        if !self.retired_subscriptions.is_empty() {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        self.legacy_v2_or_v3_canonical_bytes(PREVIOUS_STREAM_STATE_VERSION)
    }

    fn legacy_v3_canonical_bytes(&self) -> Result<Vec<u8>, RemoteStreamStateError> {
        self.legacy_v2_or_v3_canonical_bytes(RETIRED_STREAM_STATE_VERSION)
    }

    fn legacy_v2_or_v3_canonical_bytes(
        &self,
        version: u16,
    ) -> Result<Vec<u8>, RemoteStreamStateError> {
        self.validate()?;
        if !matches!(
            version,
            PREVIOUS_STREAM_STATE_VERSION | RETIRED_STREAM_STATE_VERSION
        ) || self.pending_epoch_barrier.is_some()
            || self.latest_stream_applied_ack_basis.is_some()
            || self.replay_entries.iter().any(|replay| {
                replay.key_id != self.binding.key_id
                    || replay.key_directory_revision != self.binding.key_directory_revision
            })
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let binding = self
            .binding
            .canonical_bytes()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        let mut body = Vec::with_capacity(binding.len() + 128);
        put_bytes(&mut body, &binding)?;
        put_cursor(&mut body, self.outer_applied);
        put_cursor(&mut body, self.outer_acked);
        put_inner_cursor(&mut body, &self.inner_observed)?;
        put_inner_cursor(&mut body, &self.inner_applied)?;
        body.push(u8::from(self.replay_quarantined));
        put_replay_count(&mut body, self.replay_entries.len())?;
        for replay in &self.replay_entries {
            put_replay_tuple_legacy(&mut body, replay);
        }
        if version == RETIRED_STREAM_STATE_VERSION {
            put_retired_subscriptions(&mut body, &self.retired_subscriptions)?;
        }
        if body.len() > MAX_DURABLE_STREAM_STATE_BYTES - STREAM_STATE_HEADER_LEN {
            return Err(RemoteStreamStateError::TooLarge);
        }
        encode_stream_state_body(version, body)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RemoteStreamStateError> {
        if bytes.len() < STREAM_STATE_HEADER_LEN
            || bytes.len() > MAX_DURABLE_STREAM_STATE_BYTES
            || &bytes[..4] != STREAM_STATE_MAGIC
            || bytes[6..8] != [0, 0]
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if !matches!(
            version,
            LEGACY_STREAM_STATE_VERSION
                | PREVIOUS_STREAM_STATE_VERSION
                | RETIRED_STREAM_STATE_VERSION
                | STREAM_STATE_VERSION
        ) || (version == LEGACY_STREAM_STATE_VERSION
            && bytes.len() > MAX_LEGACY_DURABLE_STREAM_STATE_BYTES)
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?,
        ) as usize;
        if declared != bytes.len() - STREAM_STATE_HEADER_LEN {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let mut decoder = Decoder::new(&bytes[STREAM_STATE_HEADER_LEN..]);
        let binding_bytes = decoder.bytes(STREAM_BINDING_MAX_CANONICAL_BYTES)?;
        let binding = StreamBindingV1::from_canonical_bytes(binding_bytes)
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if binding
            .canonical_bytes()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?
            != binding_bytes
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let outer_applied = decoder.cursor()?;
        let outer_acked = decoder.cursor()?;
        let (
            inner_observed,
            inner_applied,
            replay_quarantined,
            replay_entries,
            retired_subscriptions,
            pending_epoch_barrier,
            latest_stream_applied_ack_basis,
        ) = match version {
            LEGACY_STREAM_STATE_VERSION => {
                let inner_applied = decoder.inner_cursor()?;
                let legacy_replay_present = match decoder.u8()? {
                    0 => false,
                    1 => {
                        let _stream_seq = decoder.u64()?;
                        let _sender_counter = decoder.u64()?;
                        let _signed_blob_sha256: [u8; 32] = decoder.fixed()?;
                        true
                    }
                    _ => return Err(RemoteStreamStateError::InvalidCanonical),
                };
                if outer_applied != binding.stream_cursor || legacy_replay_present {
                    return Err(RemoteStreamStateError::InvalidCanonical);
                }
                (
                    binding.inner_cursor.clone(),
                    inner_applied,
                    false,
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                )
            }
            PREVIOUS_STREAM_STATE_VERSION | RETIRED_STREAM_STATE_VERSION | STREAM_STATE_VERSION => {
                let inner_observed = decoder.inner_cursor()?;
                let inner_applied = decoder.inner_cursor()?;
                let replay_quarantined = match decoder.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(RemoteStreamStateError::InvalidCanonical),
                };
                let replay_count = usize::try_from(decoder.u32()?)
                    .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
                if replay_count > MAX_STREAM_REPLAY_ENTRIES {
                    return Err(RemoteStreamStateError::InvalidCanonical);
                }
                let mut replay_entries = Vec::with_capacity(replay_count);
                for _ in 0..replay_count {
                    replay_entries.push(if version == STREAM_STATE_VERSION {
                        decode_replay_tuple_v4(&mut decoder)?
                    } else {
                        DurableStreamReplayTupleV1 {
                            key_id: binding.key_id,
                            key_directory_revision: binding.key_directory_revision,
                            stream_route: StreamRouteId::from_bytes(decoder.fixed()?),
                            stream_generation: StreamGenerationId::from_bytes(decoder.fixed()?),
                            stream_seq: decoder.u64()?,
                            sender_counter: decoder.u64()?,
                            ciphertext_sha256: decoder.fixed()?,
                        }
                    });
                }
                let retired_subscriptions =
                    if matches!(version, RETIRED_STREAM_STATE_VERSION | STREAM_STATE_VERSION) {
                        decode_retired_subscriptions(&mut decoder)?
                    } else {
                        Vec::new()
                    };
                let (pending_epoch_barrier, latest_stream_applied_ack_basis) =
                    if version == STREAM_STATE_VERSION {
                        let pending = match decoder.u8()? {
                            0 => None,
                            1 => Some(PendingEpochBarrierV1 {
                                replay_tuple: decode_replay_tuple_v4(&mut decoder)?,
                                replay_quarantined: decode_bool(&mut decoder)?,
                            }),
                            _ => return Err(RemoteStreamStateError::InvalidCanonical),
                        };
                        let ack = match decoder.u8()? {
                            0 => None,
                            1 => Some(
                                StreamAppliedAckV1::from_canonical_bytes(
                                    decoder.bytes(STREAM_BINDING_MAX_CANONICAL_BYTES)?,
                                )
                                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?,
                            ),
                            _ => return Err(RemoteStreamStateError::InvalidCanonical),
                        };
                        (pending, ack)
                    } else {
                        (None, None)
                    };
                (
                    inner_observed,
                    inner_applied,
                    replay_quarantined,
                    replay_entries,
                    retired_subscriptions,
                    pending_epoch_barrier,
                    latest_stream_applied_ack_basis,
                )
            }
            _ => return Err(RemoteStreamStateError::InvalidCanonical),
        };
        decoder.finish()?;
        let value = Self {
            binding,
            outer_applied,
            outer_acked,
            inner_observed,
            inner_applied,
            replay_quarantined,
            replay_entries,
            retired_subscriptions,
            pending_epoch_barrier,
            latest_stream_applied_ack_basis,
        };
        value.validate()?;
        let exact = match version {
            LEGACY_STREAM_STATE_VERSION => value.legacy_v1_canonical_bytes()?,
            PREVIOUS_STREAM_STATE_VERSION => value.legacy_v2_canonical_bytes()?,
            RETIRED_STREAM_STATE_VERSION => value.legacy_v3_canonical_bytes()?,
            STREAM_STATE_VERSION => value.canonical_bytes()?,
            _ => return Err(RemoteStreamStateError::InvalidCanonical),
        };
        if exact != bytes {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        Ok(value)
    }

    fn legacy_v1_canonical_bytes(&self) -> Result<Vec<u8>, RemoteStreamStateError> {
        self.validate()?;
        if self.outer_applied != self.binding.stream_cursor
            || self.inner_observed != self.binding.inner_cursor
            || self.replay_quarantined
            || !self.replay_entries.is_empty()
            || !self.retired_subscriptions.is_empty()
            || self.pending_epoch_barrier.is_some()
            || self.latest_stream_applied_ack_basis.is_some()
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let binding = self
            .binding
            .canonical_bytes()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        let mut body = Vec::with_capacity(binding.len() + 96);
        put_bytes(&mut body, &binding)?;
        put_cursor(&mut body, self.outer_applied);
        put_cursor(&mut body, self.outer_acked);
        put_inner_cursor(&mut body, &self.inner_applied)?;
        body.push(0);
        if body.len() > MAX_LEGACY_DURABLE_STREAM_STATE_BYTES - STREAM_STATE_HEADER_LEN {
            return Err(RemoteStreamStateError::TooLarge);
        }
        encode_stream_state_body(LEGACY_STREAM_STATE_VERSION, body)
    }

    fn validate(&self) -> Result<(), RemoteStreamStateError> {
        self.binding
            .validate()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        self.outer_applied
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        self.outer_acked
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        inner_cursor_value(&self.inner_applied)
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        inner_cursor_value(&self.inner_observed)
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if !same_target(&self.binding.inner_cursor, &self.inner_observed)
            || !same_target(&self.inner_observed, &self.inner_applied)
            || cursor_cmp(self.binding.stream_cursor, self.outer_applied) == Ordering::Greater
            || (self.outer_acked != StreamCursor::BeforeFirst
                && cursor_cmp(self.binding.stream_cursor, self.outer_acked) == Ordering::Greater)
            || cursor_cmp(self.outer_acked, self.outer_applied) == Ordering::Greater
            || cursor_cmp(
                inner_cursor_value(&self.binding.inner_cursor),
                inner_cursor_value(&self.inner_observed),
            ) == Ordering::Greater
            || cursor_cmp(
                inner_cursor_value(&self.inner_observed),
                inner_cursor_value(&self.inner_applied),
            ) == Ordering::Greater
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        if self
            .replay_entries
            .len()
            .checked_add(usize::from(self.pending_epoch_barrier.is_some()))
            .is_none_or(|count| count > MAX_STREAM_REPLAY_ENTRIES)
            || (self.replay_quarantined && self.replay_entries.is_empty())
            || (self.replay_quarantined && self.pending_epoch_barrier.is_some())
            || self.retired_subscriptions.len() > MAX_RETIRED_SUBSCRIPTIONS
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let active_pair =
            subscription_pair(self.binding.stream_route, self.binding.stream_generation);
        let mut previous_retired = None;
        for retired in &self.retired_subscriptions {
            let pair = retired_pair(retired);
            if pair == active_pair || previous_retired.is_some_and(|previous| previous >= pair) {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
            previous_retired = Some(pair);
        }
        let mut replay_high_waters = HashMap::new();
        for replay in &self.replay_entries {
            replay_high_waters
                .entry(replay.key_id)
                .and_modify(|high_water: &mut u64| {
                    *high_water = (*high_water).max(replay.sender_counter);
                })
                .or_insert(replay.sender_counter);
        }
        let mut previous = None;
        let mut stream_sequences = HashSet::with_capacity(self.replay_entries.len());
        let pending_seq = self.outer_applied.checked_next().ok();
        for replay in &self.replay_entries {
            let replay_cursor = StreamCursor::At(replay.stream_seq);
            let replay_floor = replay_high_waters
                .get(&replay.key_id)
                .ok_or(RemoteStreamStateError::InvalidCanonical)?
                .saturating_sub(MAX_STREAM_REPLAY_DISTANCE);
            if replay.key_id.purpose != self.binding.key_id.purpose
                || replay.key_id.epoch == 0
                || replay.key_id.epoch > self.binding.key_id.epoch
                || replay.key_directory_revision.value() == 0
                || replay.key_directory_revision.value()
                    > self.binding.key_directory_revision.value()
                || is_zero_16(replay.stream_route.as_bytes())
                || is_zero_16(replay.stream_generation.as_bytes())
                || replay.ciphertext_sha256 == [0; 32]
                || replay.sender_counter < replay_floor
                || replay_cursor.checked_next().is_err()
                || (replay.stream_route == self.binding.stream_route
                    && replay.stream_generation == self.binding.stream_generation
                    && cursor_cmp(replay_cursor, self.outer_applied) == Ordering::Greater
                    && (pending_seq != Some(replay.stream_seq)
                        || replay.key_id != self.binding.key_id))
                || !stream_sequences.insert((
                    *replay.stream_route.as_bytes(),
                    *replay.stream_generation.as_bytes(),
                    replay.stream_seq,
                ))
                || previous.is_some_and(|previous: &DurableStreamReplayTupleV1| {
                    replay_cmp(previous, replay) != Ordering::Less
                })
            {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
            previous = Some(replay);
        }

        if let Some(pending) = self.pending_epoch_barrier {
            let replay = pending.replay_tuple;
            let expected_epoch = self
                .binding
                .key_id
                .epoch
                .checked_add(1)
                .ok_or(RemoteStreamStateError::InvalidCanonical)?;
            let expected_revision = self
                .binding
                .key_directory_revision
                .next()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
            let expected_stream_seq = self
                .outer_applied
                .checked_next()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
            if replay.key_id.purpose != self.binding.key_id.purpose
                || replay.key_id.epoch != expected_epoch
                || replay.key_directory_revision != expected_revision
                || replay.stream_route != self.binding.stream_route
                || replay.stream_generation != self.binding.stream_generation
                || replay.stream_seq != expected_stream_seq
                || replay.ciphertext_sha256 == [0; 32]
                || StreamCursor::At(replay.stream_seq).checked_next().is_err()
                || self.replay_entries.iter().any(|committed| {
                    committed.stream_route == replay.stream_route
                        && committed.stream_generation == replay.stream_generation
                        && committed.stream_seq == replay.stream_seq
                })
                || self.replay_entries.iter().any(|committed| {
                    same_nonce_scope(committed.key_id, replay.key_id)
                        && committed.sender_counter == replay.sender_counter
                })
            {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
        }

        if let Some(ack) = &self.latest_stream_applied_ack_basis {
            ack.validate()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
            let barrier = EpochBarrierV1 {
                stream_generation: self.binding.stream_generation,
                stream_cursor: self.binding.stream_cursor,
                inner_cursor: self.binding.inner_cursor.clone(),
                old_epoch: self
                    .binding
                    .key_id
                    .epoch
                    .checked_sub(1)
                    .ok_or(RemoteStreamStateError::InvalidCanonical)?,
                new_epoch: self.binding.key_id.epoch,
                key_directory_revision: self.binding.key_directory_revision,
            };
            ack.validate_for_barrier(self.binding.stream_route, &barrier)
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
            let expected_stream_seq = self
                .binding
                .stream_cursor
                .checked_next()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
            if ack.format_version != self.binding.format_version
                || ack.runtime_protocol_version != self.binding.runtime_protocol_version
                || ack.relay_protocol_version != self.binding.relay_protocol_version
                || ack.machine_route != self.binding.machine_route
                || ack.device_route != self.binding.device_route
                || ack.grant_serial != self.binding.grant_serial
                || ack.root_trust_epoch != self.binding.root_trust_epoch
                || ack.stream_route != self.binding.stream_route
                || ack.stream_generation != self.binding.stream_generation
                || ack.applied_stream_seq != expected_stream_seq
                || ack.inner_cursor != self.binding.inner_cursor
                || ack.key_directory_revision != self.binding.key_directory_revision
                || ack.key_epoch != self.binding.key_id.epoch
                || cursor_cmp(StreamCursor::At(ack.applied_stream_seq), self.outer_applied)
                    == Ordering::Greater
            {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
        }
        Ok(())
    }

    pub(crate) fn target_key(&self) -> DurableStreamTargetKey {
        target_key(&self.binding.inner_cursor)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DurableStreamTargetKey {
    Catalog,
    Conversation(String),
}

pub(crate) fn decode_stream_bindings(
    entries: &[Vec<u8>],
) -> Result<Vec<DurableStreamBindingV1>, RemoteStreamStateError> {
    if entries.len() > MAX_DURABLE_STREAM_BINDINGS {
        return Err(RemoteStreamStateError::TooLarge);
    }
    let mut states = Vec::with_capacity(entries.len());
    let mut previous = None;
    let mut routes = HashSet::with_capacity(entries.len());
    let mut subscription_pairs = HashSet::with_capacity(entries.len());
    for entry in entries {
        let state = DurableStreamBindingV1::from_canonical_bytes(entry)?;
        let key = state.target_key();
        if previous.as_ref().is_some_and(|previous| previous >= &key)
            || !routes.insert(*state.binding.stream_route.as_bytes())
            || !insert_subscription_pairs(&mut subscription_pairs, &state)
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        previous = Some(key);
        states.push(state);
    }
    Ok(states)
}

pub(crate) fn encode_stream_bindings(
    mut states: Vec<DurableStreamBindingV1>,
) -> Result<Vec<Vec<u8>>, RemoteStreamStateError> {
    if states.len() > MAX_DURABLE_STREAM_BINDINGS {
        return Err(RemoteStreamStateError::TooLarge);
    }
    states.sort_by_key(DurableStreamBindingV1::target_key);
    let mut encoded = Vec::with_capacity(states.len());
    let mut previous = None;
    let mut routes = HashSet::with_capacity(states.len());
    let mut subscription_pairs = HashSet::with_capacity(states.len());
    for state in states {
        let key = state.target_key();
        if previous.as_ref().is_some_and(|previous| previous >= &key)
            || !routes.insert(*state.binding.stream_route.as_bytes())
            || !insert_subscription_pairs(&mut subscription_pairs, &state)
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        previous = Some(key);
        encoded.push(state.canonical_bytes()?);
    }
    Ok(encoded)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RemoteStreamStateError {
    #[error("durable stream state has an invalid canonical encoding")]
    InvalidCanonical,
    #[error("durable stream state exceeds its hard bound")]
    TooLarge,
}

impl RemoteStreamStateError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidCanonical => "remote.stream_state.invalid",
            Self::TooLarge => "remote.stream_state.too_large",
        }
    }
}

fn target_key(cursor: &RuntimeInnerCursor) -> DurableStreamTargetKey {
    match cursor {
        RuntimeInnerCursor::Catalog { .. } => DurableStreamTargetKey::Catalog,
        RuntimeInnerCursor::Conversation {
            conversation_id, ..
        } => DurableStreamTargetKey::Conversation(conversation_id.as_str().to_owned()),
    }
}

fn same_target(left: &RuntimeInnerCursor, right: &RuntimeInnerCursor) -> bool {
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

fn same_replay_scope(left: &StreamBindingV1, right: &StreamBindingV1) -> bool {
    if left.key_id != right.key_id {
        return false;
    }
    match left.key_id.purpose {
        KeyPurpose::Catalog => true,
        KeyPurpose::ConversationDek => left.stream_route == right.stream_route,
        KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => false,
    }
}

fn same_nonce_scope(left: KeyId, right: KeyId) -> bool {
    left == right
}

fn key_purpose_tag(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 0,
        KeyPurpose::ConversationDek => 1,
        KeyPurpose::DeviceCommandTx => 2,
        KeyPurpose::DeviceReplyTx => 3,
    }
}

fn decode_key_purpose(tag: u8) -> Result<KeyPurpose, RemoteStreamStateError> {
    match tag {
        0 => Ok(KeyPurpose::Catalog),
        1 => Ok(KeyPurpose::ConversationDek),
        2 => Ok(KeyPurpose::DeviceCommandTx),
        3 => Ok(KeyPurpose::DeviceReplyTx),
        _ => Err(RemoteStreamStateError::InvalidCanonical),
    }
}

fn replay_cmp(left: &DurableStreamReplayTupleV1, right: &DurableStreamReplayTupleV1) -> Ordering {
    (
        key_purpose_tag(left.key_id.purpose),
        left.key_id.epoch,
        left.sender_counter,
    )
        .cmp(&(
            key_purpose_tag(right.key_id.purpose),
            right.key_id.epoch,
            right.sender_counter,
        ))
}

fn replay_scope_high_water(
    replay_entries: &[DurableStreamReplayTupleV1],
    key_id: KeyId,
) -> Option<u64> {
    replay_entries
        .iter()
        .filter(|entry| same_nonce_scope(entry.key_id, key_id))
        .map(|entry| entry.sender_counter)
        .max()
}

fn put_replay_count(output: &mut Vec<u8>, count: usize) -> Result<(), RemoteStreamStateError> {
    output.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| RemoteStreamStateError::TooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

fn put_replay_tuple_legacy(output: &mut Vec<u8>, replay: &DurableStreamReplayTupleV1) {
    output.extend_from_slice(replay.stream_route.as_bytes());
    output.extend_from_slice(replay.stream_generation.as_bytes());
    output.extend_from_slice(&replay.stream_seq.to_be_bytes());
    output.extend_from_slice(&replay.sender_counter.to_be_bytes());
    output.extend_from_slice(&replay.ciphertext_sha256);
}

fn put_replay_tuple_v4(output: &mut Vec<u8>, replay: &DurableStreamReplayTupleV1) {
    output.push(key_purpose_tag(replay.key_id.purpose));
    output.extend_from_slice(&replay.key_id.epoch.to_be_bytes());
    output.extend_from_slice(&replay.key_directory_revision.value().to_be_bytes());
    put_replay_tuple_legacy(output, replay);
}

fn decode_replay_tuple_v4(
    decoder: &mut Decoder<'_>,
) -> Result<DurableStreamReplayTupleV1, RemoteStreamStateError> {
    Ok(DurableStreamReplayTupleV1 {
        key_id: KeyId {
            purpose: decode_key_purpose(decoder.u8()?)?,
            epoch: decoder.u64()?,
        },
        key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
        stream_route: StreamRouteId::from_bytes(decoder.fixed()?),
        stream_generation: StreamGenerationId::from_bytes(decoder.fixed()?),
        stream_seq: decoder.u64()?,
        sender_counter: decoder.u64()?,
        ciphertext_sha256: decoder.fixed()?,
    })
}

fn put_retired_subscriptions(
    output: &mut Vec<u8>,
    retired_subscriptions: &[DurableRetiredSubscriptionV1],
) -> Result<(), RemoteStreamStateError> {
    output.extend_from_slice(
        &u32::try_from(retired_subscriptions.len())
            .map_err(|_| RemoteStreamStateError::TooLarge)?
            .to_be_bytes(),
    );
    for retired in retired_subscriptions {
        output.extend_from_slice(retired.stream_route.as_bytes());
        output.extend_from_slice(retired.stream_generation.as_bytes());
    }
    Ok(())
}

fn decode_retired_subscriptions(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<DurableRetiredSubscriptionV1>, RemoteStreamStateError> {
    let retired_count =
        usize::try_from(decoder.u32()?).map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
    if retired_count > MAX_RETIRED_SUBSCRIPTIONS {
        return Err(RemoteStreamStateError::InvalidCanonical);
    }
    let mut retired = Vec::with_capacity(retired_count);
    for _ in 0..retired_count {
        retired.push(DurableRetiredSubscriptionV1 {
            stream_route: StreamRouteId::from_bytes(decoder.fixed()?),
            stream_generation: StreamGenerationId::from_bytes(decoder.fixed()?),
        });
    }
    Ok(retired)
}

fn decode_bool(decoder: &mut Decoder<'_>) -> Result<bool, RemoteStreamStateError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RemoteStreamStateError::InvalidCanonical),
    }
}

fn is_zero_16(value: &[u8; 16]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn subscription_pair(
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
) -> ([u8; 16], [u8; 16]) {
    (*stream_route.as_bytes(), *stream_generation.as_bytes())
}

fn retired_pair(retired: &DurableRetiredSubscriptionV1) -> ([u8; 16], [u8; 16]) {
    subscription_pair(retired.stream_route, retired.stream_generation)
}

fn insert_subscription_pairs(
    pairs: &mut HashSet<([u8; 16], [u8; 16])>,
    state: &DurableStreamBindingV1,
) -> bool {
    if !pairs.insert(subscription_pair(
        state.binding.stream_route,
        state.binding.stream_generation,
    )) {
        return false;
    }
    state
        .retired_subscriptions
        .iter()
        .all(|retired| pairs.insert(retired_pair(retired)))
}

fn inner_cursor_value(cursor: &RuntimeInnerCursor) -> StreamCursor {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor }
        | RuntimeInnerCursor::Conversation { cursor, .. } => *cursor,
    }
}

fn cursor_cmp(left: StreamCursor, right: StreamCursor) -> Ordering {
    match (left, right) {
        (StreamCursor::BeforeFirst, StreamCursor::BeforeFirst) => Ordering::Equal,
        (StreamCursor::BeforeFirst, StreamCursor::At(_)) => Ordering::Less,
        (StreamCursor::At(_), StreamCursor::BeforeFirst) => Ordering::Greater,
        (StreamCursor::At(left), StreamCursor::At(right)) => left.cmp(&right),
    }
}

fn encode_stream_state_body(
    version: u16,
    body: Vec<u8>,
) -> Result<Vec<u8>, RemoteStreamStateError> {
    let body_len = u32::try_from(body.len()).map_err(|_| RemoteStreamStateError::TooLarge)?;
    let mut encoded = Vec::with_capacity(STREAM_STATE_HEADER_LEN + body.len());
    encoded.extend_from_slice(STREAM_STATE_MAGIC);
    encoded.extend_from_slice(&version.to_be_bytes());
    encoded.extend_from_slice(&[0, 0]);
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RemoteStreamStateError> {
    let length = u32::try_from(bytes.len()).map_err(|_| RemoteStreamStateError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_cursor(output: &mut Vec<u8>, cursor: StreamCursor) {
    match cursor {
        StreamCursor::BeforeFirst => {
            output.push(0);
            output.extend_from_slice(&0_u64.to_be_bytes());
        }
        StreamCursor::At(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn put_inner_cursor(
    output: &mut Vec<u8>,
    cursor: &RuntimeInnerCursor,
) -> Result<(), RemoteStreamStateError> {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor } => {
            output.push(0);
            put_cursor(output, *cursor);
        }
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } => {
            output.push(1);
            let identity = conversation_id.as_str().as_bytes();
            if identity.is_empty() || identity.len() > MAX_CONVERSATION_ID_BYTES {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
            put_bytes(output, identity)?;
            put_cursor(output, *cursor);
        }
    }
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RemoteStreamStateError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RemoteStreamStateError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(RemoteStreamStateError::InvalidCanonical)
    }

    fn u32(&mut self) -> Result<u32, RemoteStreamStateError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, RemoteStreamStateError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?,
        ))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RemoteStreamStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], RemoteStreamStateError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if length == 0 || length > maximum {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        self.take(length)
    }

    fn cursor(&mut self) -> Result<StreamCursor, RemoteStreamStateError> {
        let tag = self.u8()?;
        let value = self.u64()?;
        match (tag, value) {
            (0, 0) => Ok(StreamCursor::BeforeFirst),
            (1, value) => Ok(StreamCursor::At(value)),
            _ => Err(RemoteStreamStateError::InvalidCanonical),
        }
    }

    fn inner_cursor(&mut self) -> Result<RuntimeInnerCursor, RemoteStreamStateError> {
        match self.u8()? {
            0 => Ok(RuntimeInnerCursor::Catalog {
                cursor: self.cursor()?,
            }),
            1 => {
                let bytes = self.bytes(MAX_CONVERSATION_ID_BYTES)?;
                let identity = std::str::from_utf8(bytes)
                    .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
                Ok(RuntimeInnerCursor::Conversation {
                    conversation_id: ConversationId::new(identity),
                    cursor: self.cursor()?,
                })
            }
            _ => Err(RemoteStreamStateError::InvalidCanonical),
        }
    }

    fn finish(self) -> Result<(), RemoteStreamStateError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(RemoteStreamStateError::InvalidCanonical)
        }
    }
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, EpochBarrierV1, KeyId, KeyPurpose};
    use agentdeck_protocol::relay_v2::{
        DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION,
        StreamGenerationId, StreamRouteId, TrustEpoch,
    };
    use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

    use super::*;

    fn binding(
        route: StreamRouteId,
        generation: u8,
        target: RuntimeInnerCursor,
    ) -> StreamBindingV1 {
        let purpose = match &target {
            RuntimeInnerCursor::Catalog { .. } => KeyPurpose::Catalog,
            RuntimeInnerCursor::Conversation { .. } => KeyPurpose::ConversationDek,
        };
        StreamBindingV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: MachineRouteId::from_bytes([0x11; 16]),
            device_route: DeviceRouteId::from_bytes([0x12; 16]),
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
            stream_route: route,
            stream_generation: StreamGenerationId::from_bytes([generation; 16]),
            stream_cursor: StreamCursor::BeforeFirst,
            inner_cursor: target,
            key_directory_revision: KeyDirectoryRevision::new(4),
            key_id: KeyId { purpose, epoch: 3 },
        }
    }

    fn catalog(route: u8) -> DurableStreamBindingV1 {
        DurableStreamBindingV1::from_stream_binding(binding(
            StreamRouteId::from_bytes([route; 16]),
            route.wrapping_add(0x10),
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        ))
        .unwrap()
    }

    fn conversation(route: u8, id: &str) -> DurableStreamBindingV1 {
        DurableStreamBindingV1::from_stream_binding(binding(
            StreamRouteId::from_bytes([route; 16]),
            route.wrapping_add(0x20),
            RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new(id),
                cursor: StreamCursor::BeforeFirst,
            },
        ))
        .unwrap()
    }

    fn replay_entry_offsets(canonical: &[u8]) -> (usize, usize) {
        assert!(matches!(
            u16::from_be_bytes([canonical[4], canonical[5]]),
            PREVIOUS_STREAM_STATE_VERSION
        ));
        let mut decoder = Decoder::new(&canonical[STREAM_STATE_HEADER_LEN..]);
        decoder.bytes(STREAM_BINDING_MAX_CANONICAL_BYTES).unwrap();
        decoder.cursor().unwrap();
        decoder.cursor().unwrap();
        decoder.inner_cursor().unwrap();
        decoder.inner_cursor().unwrap();
        decoder.u8().unwrap();
        let count_offset = STREAM_STATE_HEADER_LEN + decoder.cursor;
        decoder.u32().unwrap();
        let entries_offset = STREAM_STATE_HEADER_LEN + decoder.cursor;
        (count_offset, entries_offset)
    }

    fn retired_subscription_offsets(canonical: &[u8]) -> (usize, usize) {
        assert_eq!(
            u16::from_be_bytes([canonical[4], canonical[5]]),
            RETIRED_STREAM_STATE_VERSION
        );
        let mut decoder = Decoder::new(&canonical[STREAM_STATE_HEADER_LEN..]);
        decoder.bytes(STREAM_BINDING_MAX_CANONICAL_BYTES).unwrap();
        decoder.cursor().unwrap();
        decoder.cursor().unwrap();
        decoder.inner_cursor().unwrap();
        decoder.inner_cursor().unwrap();
        decoder.u8().unwrap();
        let replay_count = decoder.u32().unwrap();
        for _ in 0..replay_count {
            decoder.take(80).unwrap();
        }
        let count_offset = STREAM_STATE_HEADER_LEN + decoder.cursor;
        decoder.u32().unwrap();
        let entries_offset = STREAM_STATE_HEADER_LEN + decoder.cursor;
        (count_offset, entries_offset)
    }

    fn state_with_two_replay_entries() -> DurableStreamBindingV1 {
        let initial = catalog(0x62);
        let (first_pending, disposition) = initial.admit_publish(0, 10, [0x71; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let (first_applied, mode) = first_pending
            .commit_direct_publish(
                0,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(0),
                },
            )
            .unwrap();
        assert_eq!(mode, StreamDirectApplyMode::Apply);
        let (second_pending, disposition) = first_applied.admit_publish(1, 20, [0x72; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        second_pending
    }

    fn applied_catalog_cut(route: u8) -> DurableStreamBindingV1 {
        let initial = catalog(route);
        let (pending, disposition) = initial.admit_publish(0, 10, [0x91; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let (applied, mode) = pending
            .commit_direct_publish(
                0,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(0),
                },
            )
            .unwrap();
        assert_eq!(mode, StreamDirectApplyMode::Apply);
        applied.with_committed_outer_ack(0).unwrap()
    }

    fn next_epoch_barrier(state: &DurableStreamBindingV1) -> EpochBarrierV1 {
        EpochBarrierV1 {
            stream_generation: state.binding.stream_generation,
            stream_cursor: state.outer_applied,
            inner_cursor: state.inner_applied.clone(),
            old_epoch: state.binding.key_id.epoch,
            new_epoch: state.binding.key_id.epoch + 1,
            key_directory_revision: state.binding.key_directory_revision.next().unwrap(),
        }
    }

    #[test]
    fn staged_epoch_barrier_admission_is_scoped_bounded_and_quarantines_nonce_conflict() {
        let state = applied_catalog_cut(0x63);
        let barrier = next_epoch_barrier(&state);
        let new_key_id = KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: barrier.new_epoch,
        };
        let (pending, disposition) = state
            .admit_pending_epoch_barrier(
                new_key_id,
                barrier.key_directory_revision,
                1,
                10,
                [0x92; 32],
            )
            .unwrap();
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let staged = pending.pending_epoch_barrier().expect("pending barrier");
        assert_eq!(staged.replay_tuple().key_id(), new_key_id);
        assert_eq!(
            staged.replay_tuple().key_directory_revision(),
            barrier.key_directory_revision
        );
        assert_eq!(staged.replay_tuple().sender_counter(), 10);
        assert!(!staged.replay_quarantined());
        let pending_canonical = pending.canonical_bytes().unwrap();
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&pending_canonical).unwrap(),
            pending,
        );
        assert!(
            pending
                .replace_subscription_bootstrap(
                    pending.binding.clone(),
                    pending.inner_applied.clone(),
                )
                .is_err(),
            "subscription replacement must not erase a durable staged barrier",
        );

        let (exact, disposition) = pending
            .admit_pending_epoch_barrier(
                new_key_id,
                barrier.key_directory_revision,
                1,
                10,
                [0x92; 32],
            )
            .unwrap();
        assert_eq!(disposition, StreamPublishDisposition::PendingDuplicate);
        assert_eq!(exact, pending);

        let (outer_identity_quarantined, disposition) = pending
            .admit_pending_epoch_barrier(
                new_key_id,
                barrier.key_directory_revision,
                1,
                11,
                [0x94; 32],
            )
            .unwrap();
        assert_eq!(disposition, StreamPublishDisposition::NonceReuseQuarantined,);
        assert!(
            outer_identity_quarantined
                .pending_epoch_barrier()
                .expect("outer identity quarantine")
                .replay_quarantined(),
        );

        let (quarantined, disposition) = pending
            .admit_pending_epoch_barrier(
                new_key_id,
                barrier.key_directory_revision,
                1,
                10,
                [0x93; 32],
            )
            .unwrap();
        assert_eq!(disposition, StreamPublishDisposition::NonceReuseQuarantined);
        assert!(
            quarantined
                .pending_epoch_barrier()
                .expect("quarantined pending barrier")
                .replay_quarantined()
        );
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&quarantined.canonical_bytes().unwrap(),)
                .unwrap(),
            quarantined,
        );
        assert!(
            quarantined
                .activate_epoch_barrier(state.binding.stream_route, &barrier)
                .is_err()
        );

        for (key_id, revision) in [
            (
                KeyId {
                    purpose: KeyPurpose::ConversationDek,
                    epoch: barrier.new_epoch,
                },
                barrier.key_directory_revision,
            ),
            (state.binding.key_id, barrier.key_directory_revision),
            (new_key_id, state.binding.key_directory_revision),
            (
                KeyId {
                    purpose: KeyPurpose::Catalog,
                    epoch: barrier.new_epoch + 1,
                },
                barrier.key_directory_revision,
            ),
        ] {
            assert!(
                state
                    .admit_pending_epoch_barrier(key_id, revision, 1, 10, [0x94; 32])
                    .is_err(),
                "arbitrary future key scope must be rejected",
            );
        }
    }

    #[test]
    fn epoch_barrier_activation_binds_exact_cut_and_committed_retry_is_idempotent() {
        let state = applied_catalog_cut(0x64);
        let barrier = next_epoch_barrier(&state);
        let new_key_id = KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: barrier.new_epoch,
        };
        let (pending, _) = state
            .admit_pending_epoch_barrier(
                new_key_id,
                barrier.key_directory_revision,
                1,
                10,
                [0xa1; 32],
            )
            .unwrap();
        let activated = pending
            .activate_epoch_barrier(state.binding.stream_route, &barrier)
            .expect("activate exact barrier");

        assert_eq!(activated.binding.key_id, new_key_id);
        assert_eq!(
            activated.binding.key_directory_revision,
            barrier.key_directory_revision
        );
        assert_eq!(activated.binding.stream_cursor, barrier.stream_cursor);
        assert_eq!(activated.binding.inner_cursor, barrier.inner_cursor);
        assert_eq!(activated.outer_applied(), StreamCursor::At(1));
        assert_eq!(activated.outer_acked(), StreamCursor::At(0));
        assert_eq!(activated.inner_observed(), &barrier.inner_cursor);
        assert_eq!(activated.inner_applied(), &barrier.inner_cursor);
        assert_eq!(activated.replay_entry_count(), 2);
        assert!(activated.pending_epoch_barrier().is_none());
        let ack = activated
            .latest_stream_applied_ack_basis()
            .expect("durable StreamAppliedAck basis");
        ack.validate_for_barrier(state.binding.stream_route, &barrier)
            .expect("ACK basis binds exact barrier");

        assert_eq!(
            activated
                .activate_epoch_barrier(state.binding.stream_route, &barrier)
                .expect("committed activation retry"),
            activated
        );
        let (next_pending, disposition) = activated
            .admit_publish(2, 20, [0xa2; 32])
            .expect("admit post-barrier publish");
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let (progressed, mode) = next_pending
            .commit_direct_publish(
                2,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(1),
                },
            )
            .expect("apply post-barrier publish");
        assert_eq!(mode, StreamDirectApplyMode::Apply);
        assert_eq!(
            progressed
                .activate_epoch_barrier(state.binding.stream_route, &barrier)
                .expect("committed retry remains idempotent after later progress"),
            progressed,
        );
        let canonical = activated.canonical_bytes().unwrap();
        assert_eq!(
            u16::from_be_bytes([canonical[4], canonical[5]]),
            STREAM_STATE_VERSION
        );
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&canonical).unwrap(),
            activated
        );
        let mut forged_ack = activated.clone();
        forged_ack
            .latest_stream_applied_ack_basis
            .as_mut()
            .expect("ACK basis")
            .epoch_barrier_sha256[0] ^= 1;
        assert_eq!(
            forged_ack.canonical_bytes().unwrap_err(),
            RemoteStreamStateError::InvalidCanonical,
            "open-time validation must reconstruct and authenticate the exact barrier hash",
        );
        let rewrapped = activated
            .with_rewrapped_key_revision(
                barrier
                    .key_directory_revision
                    .next()
                    .expect("next revision"),
            )
            .expect("same-epoch rewrap after activation");
        assert!(
            rewrapped.latest_stream_applied_ack_basis().is_none(),
            "a new revision must not re-seal the previous revision's barrier ACK basis",
        );
        assert_eq!(
            rewrapped.replay_entries, activated.replay_entries,
            "rewrap preserves the scoped replay audit trail without relabeling revisions",
        );
        let mut expected_superseded = activated.clone();
        expected_superseded.latest_stream_applied_ack_basis = None;
        assert_eq!(
            activated
                .with_superseded_stream_applied_ack()
                .expect("next rotation supersedes the old receipt basis"),
            expected_superseded,
            "rotation receipt supersession changes no stream/replay/cursor axis",
        );
    }

    #[test]
    fn epoch_barrier_receipt_basis_survives_carrier_replay_window_pruning() {
        let state = catalog(0x65);
        let barrier = next_epoch_barrier(&state);
        let new_key_id = KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: barrier.new_epoch,
        };
        let (pending, disposition) = state
            .admit_pending_epoch_barrier(
                new_key_id,
                barrier.key_directory_revision,
                0,
                0,
                [0xa5; 32],
            )
            .expect("admit first-frame epoch barrier");
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let mut near_window_edge = pending
            .activate_epoch_barrier(state.binding.stream_route, &barrier)
            .expect("activate first-frame epoch barrier");

        // 直接构造已经通过前 4,095 个 current-epoch frame 的 canonical cut，避免这个
        // focused regression 用 O(n²) admission 循环拖慢整个 lib gate。最后一条仍走真实
        // admission/commit，精确覆盖 carrier 被 floor 淘汰的边界。
        near_window_edge.replay_entries.extend(
            (1..u64::try_from(MAX_STREAM_REPLAY_ENTRIES).unwrap()).map(|counter| {
                DurableStreamReplayTupleV1 {
                    key_id: new_key_id,
                    key_directory_revision: barrier.key_directory_revision,
                    stream_route: state.binding.stream_route,
                    stream_generation: state.binding.stream_generation,
                    stream_seq: counter,
                    sender_counter: counter,
                    ciphertext_sha256: [u8::try_from(counter % 251 + 1).unwrap(); 32],
                }
            }),
        );
        near_window_edge.outer_applied = StreamCursor::At(4_095);
        near_window_edge.inner_observed = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(4_094),
        };
        near_window_edge.inner_applied = near_window_edge.inner_observed.clone();
        near_window_edge
            .validate()
            .expect("canonical state immediately before carrier pruning");

        let (admitted, disposition) = near_window_edge
            .admit_publish(4_096, 4_096, [0xf6; 32])
            .expect("admit the frame that prunes the barrier carrier");
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let (progressed, mode) = admitted
            .commit_direct_publish(
                4_096,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(4_095),
                },
            )
            .expect("commit after barrier carrier pruning");
        assert_eq!(mode, StreamDirectApplyMode::Apply);

        assert_eq!(progressed.replay_entry_count(), MAX_STREAM_REPLAY_ENTRIES);
        assert!(
            progressed
                .replay_entries
                .iter()
                .all(|entry| entry.stream_seq != 0 || entry.key_id != new_key_id),
            "the old barrier carrier may age out of the bounded replay window",
        );
        assert!(progressed.latest_stream_applied_ack_basis().is_some());
        assert_eq!(
            progressed
                .activate_epoch_barrier(state.binding.stream_route, &barrier)
                .expect("durable receipt basis remains independently idempotent"),
            progressed,
        );
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(
                &progressed
                    .canonical_bytes()
                    .expect("encode progressed state")
            )
            .expect("decode progressed state"),
            progressed,
        );
    }

    #[test]
    fn epoch_barrier_rejects_axis_drift_and_lagging_old_ack_without_mutation() {
        let overlap_bootstrap = DurableStreamBindingV1::from_subscription_bootstrap(
            binding(
                StreamRouteId::from_bytes([0x66; 16]),
                0x76,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::BeforeFirst,
                },
            ),
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(0),
            },
        )
        .unwrap();
        assert!(
            overlap_bootstrap
                .admit_pending_epoch_barrier(
                    KeyId {
                        purpose: KeyPurpose::Catalog,
                        epoch: 4,
                    },
                    KeyDirectoryRevision::new(5),
                    0,
                    9,
                    [0xb0; 32],
                )
                .is_err(),
            "a barrier cannot occupy D while bootstrap overlap still needs current-key frames",
        );

        let state = applied_catalog_cut(0x65);
        let barrier = next_epoch_barrier(&state);
        let new_key_id = KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: barrier.new_epoch,
        };
        let (pending, _) = state
            .admit_pending_epoch_barrier(
                new_key_id,
                barrier.key_directory_revision,
                1,
                11,
                [0xb1; 32],
            )
            .unwrap();

        let mut drifted = Vec::new();
        let mut wrong_generation = barrier.clone();
        wrong_generation.stream_generation = StreamGenerationId::from_bytes([0xee; 16]);
        drifted.push(wrong_generation);
        let mut wrong_outer = barrier.clone();
        wrong_outer.stream_cursor = StreamCursor::BeforeFirst;
        drifted.push(wrong_outer);
        let mut wrong_inner = barrier.clone();
        wrong_inner.inner_cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        };
        drifted.push(wrong_inner);
        let mut wrong_old = barrier.clone();
        wrong_old.old_epoch -= 1;
        drifted.push(wrong_old);
        let mut wrong_new = barrier.clone();
        wrong_new.new_epoch += 1;
        drifted.push(wrong_new);
        let mut wrong_revision = barrier.clone();
        wrong_revision.key_directory_revision = KeyDirectoryRevision::new(7);
        drifted.push(wrong_revision);
        for candidate in drifted {
            assert!(
                pending
                    .activate_epoch_barrier(state.binding.stream_route, &candidate)
                    .is_err()
            );
        }
        assert!(
            pending
                .activate_epoch_barrier(StreamRouteId::from_bytes([0xef; 16]), &barrier)
                .is_err()
        );

        let lagging = DurableStreamBindingV1 {
            outer_applied: StreamCursor::At(2),
            outer_acked: StreamCursor::At(1),
            inner_observed: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(2),
            },
            inner_applied: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(2),
            },
            replay_entries: vec![
                DurableStreamReplayTupleV1 {
                    key_id: state.binding.key_id,
                    key_directory_revision: state.binding.key_directory_revision,
                    stream_route: state.binding.stream_route,
                    stream_generation: state.binding.stream_generation,
                    stream_seq: 0,
                    sender_counter: 10,
                    ciphertext_sha256: [0xc1; 32],
                },
                DurableStreamReplayTupleV1 {
                    key_id: state.binding.key_id,
                    key_directory_revision: state.binding.key_directory_revision,
                    stream_route: state.binding.stream_route,
                    stream_generation: state.binding.stream_generation,
                    stream_seq: 1,
                    sender_counter: 11,
                    ciphertext_sha256: [0xc2; 32],
                },
                DurableStreamReplayTupleV1 {
                    key_id: state.binding.key_id,
                    key_directory_revision: state.binding.key_directory_revision,
                    stream_route: state.binding.stream_route,
                    stream_generation: state.binding.stream_generation,
                    stream_seq: 2,
                    sender_counter: 12,
                    ciphertext_sha256: [0xc3; 32],
                },
            ],
            ..state
        };
        lagging
            .validate()
            .expect("lagging ACK is valid before barrier");
        let lagging_barrier = next_epoch_barrier(&lagging);
        let (lagging_pending, _) = lagging
            .admit_pending_epoch_barrier(
                KeyId {
                    purpose: KeyPurpose::Catalog,
                    epoch: lagging_barrier.new_epoch,
                },
                lagging_barrier.key_directory_revision,
                3,
                13,
                [0xc4; 32],
            )
            .unwrap();
        assert!(
            lagging_pending
                .activate_epoch_barrier(lagging.binding.stream_route, &lagging_barrier)
                .is_err(),
            "old outer ACK must be BeforeFirst or exact C",
        );
    }

    #[test]
    fn shared_key_revision_rewrap_changes_only_the_exact_next_revision() {
        let initial = catalog(0x2a);
        let mut replacement = initial.binding.clone();
        replacement.stream_route = StreamRouteId::from_bytes([0x2b; 16]);
        replacement.stream_generation = StreamGenerationId::from_bytes([0x3b; 16]);
        let rolled = initial
            .replace_subscription_bootstrap(
                replacement,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::BeforeFirst,
                },
            )
            .expect("install replacement subscription");
        let (pending, disposition) = rolled.admit_publish(0, 10, [0x71; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let (applied, mode) = pending
            .commit_direct_publish(
                0,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(0),
                },
            )
            .unwrap();
        assert_eq!(mode, StreamDirectApplyMode::Apply);
        let acked = applied.with_committed_outer_ack(0).unwrap();
        let (next_pending, disposition) = acked.admit_publish(1, 20, [0x72; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let (quarantined, disposition) = next_pending.admit_publish(1, 20, [0x73; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::NonceReuseQuarantined);

        let rewrapped_acked = acked
            .with_rewrapped_key_revision(KeyDirectoryRevision::new(5))
            .unwrap();
        assert_eq!(
            rewrapped_acked
                .admit_publish_at_authenticated_revision(
                    KeyDirectoryRevision::new(4),
                    0,
                    10,
                    [0x71; 32],
                )
                .unwrap()
                .1,
            StreamPublishDisposition::AppliedDuplicate,
            "an authenticated predecessor revision may only replay its exact durable tuple",
        );
        assert!(
            rewrapped_acked
                .admit_publish_at_authenticated_revision(
                    KeyDirectoryRevision::new(4),
                    1,
                    30,
                    [0x75; 32],
                )
                .is_err(),
            "a predecessor revision cannot create a fresh tuple after rewrap",
        );
        let (rewrap_quarantined, disposition) =
            rewrapped_acked.admit_publish(1, 10, [0x74; 32]).unwrap();
        assert_eq!(
            disposition,
            StreamPublishDisposition::NonceReuseQuarantined,
            "same-epoch rewrap must share the previous revision's nonce scope",
        );
        assert!(rewrap_quarantined.replay_quarantined());

        let mut expected_catalog = quarantined.clone();
        expected_catalog.binding.key_directory_revision = KeyDirectoryRevision::new(5);
        assert_eq!(
            quarantined
                .with_rewrapped_key_revision(KeyDirectoryRevision::new(5))
                .unwrap(),
            expected_catalog,
            "rewrap must preserve route/generation, cursors, ACK, replay, quarantine and retired subscriptions",
        );

        let conversation = conversation(0x2c, "rewrap-conversation");
        let mut expected_conversation = conversation.clone();
        expected_conversation.binding.key_directory_revision = KeyDirectoryRevision::new(5);
        assert_eq!(
            conversation
                .with_rewrapped_key_revision(KeyDirectoryRevision::new(5))
                .unwrap(),
            expected_conversation,
            "ConversationDEK uses the same exact metadata-only transition",
        );
    }

    #[test]
    fn shared_key_revision_rewrap_rejects_non_next_and_non_shared_revisions() {
        let state = catalog(0x2d);
        for revision in [0, 3, 4, 6] {
            assert_eq!(
                state
                    .with_rewrapped_key_revision(KeyDirectoryRevision::new(revision))
                    .unwrap_err(),
                RemoteStreamStateError::InvalidCanonical,
                "revision {revision} must not be accepted from current revision 4",
            );
        }

        let mut exhausted = state.clone();
        exhausted.binding.key_directory_revision = KeyDirectoryRevision::new(u64::MAX);
        assert_eq!(
            exhausted
                .with_rewrapped_key_revision(KeyDirectoryRevision::new(u64::MAX))
                .unwrap_err(),
            RemoteStreamStateError::InvalidCanonical,
            "revision exhaustion must fail closed instead of wrapping",
        );

        for purpose in [KeyPurpose::DeviceCommandTx, KeyPurpose::DeviceReplyTx] {
            let mut directed = state.clone();
            directed.binding.key_id.purpose = purpose;
            assert_eq!(
                directed
                    .with_rewrapped_key_revision(KeyDirectoryRevision::new(5))
                    .unwrap_err(),
                RemoteStreamStateError::InvalidCanonical,
                "directed key carriers never own StreamBinding state",
            );
        }
    }

    #[test]
    fn subscription_bootstrap_keeps_a_sync_inner_cut_ahead_of_the_publication_binding() {
        let mut binding = binding(
            StreamRouteId::from_bytes([0x30; 16]),
            0x40,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        );
        binding.stream_cursor = StreamCursor::At(7);
        let state = DurableStreamBindingV1::from_subscription_bootstrap(
            binding,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(9),
            },
        )
        .expect("directed SyncComplete may be ahead of the Relay publication cut");
        assert_eq!(
            state.inner_applied(),
            &RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(9),
            }
        );
        assert_eq!(
            state.inner_observed(),
            &RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
            "directed bootstrap may advance the reducer without inventing observed publications",
        );
        assert_eq!(
            state.outer_acked(),
            StreamCursor::BeforeFirst,
            "durable bootstrap must not claim an ACK before the Relay control is sent",
        );
        let canonical = state
            .canonical_bytes()
            .expect("encode advanced bootstrap cut");
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&canonical)
                .expect("decode advanced bootstrap cut"),
            state
        );
    }

    #[test]
    fn replay_admission_is_independent_from_outer_apply_and_ack() {
        let initial = catalog(0x31);
        let pending = DurableStreamBindingV1 {
            replay_entries: vec![DurableStreamReplayTupleV1 {
                key_id: initial.binding.key_id,
                key_directory_revision: initial.binding.key_directory_revision,
                stream_route: initial.binding.stream_route,
                stream_generation: initial.binding.stream_generation,
                stream_seq: 0,
                sender_counter: 0,
                ciphertext_sha256: [0x41; 32],
            }],
            ..initial.clone()
        };
        let canonical = pending.canonical_bytes().expect("durable pre-apply replay");
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&canonical).unwrap(),
            pending
        );

        let applied = DurableStreamBindingV1 {
            outer_applied: StreamCursor::At(0),
            ..pending.clone()
        };
        applied
            .canonical_bytes()
            .expect("same replay tuple remains valid after apply");

        let skipped = DurableStreamBindingV1 {
            replay_entries: vec![DurableStreamReplayTupleV1 {
                key_id: initial.binding.key_id,
                key_directory_revision: initial.binding.key_directory_revision,
                stream_route: initial.binding.stream_route,
                stream_generation: initial.binding.stream_generation,
                stream_seq: 1,
                sender_counter: 0,
                ciphertext_sha256: [0x42; 32],
            }],
            ..initial
        };
        assert_eq!(
            skipped.canonical_bytes().unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
    }

    #[test]
    fn outer_ack_can_only_commit_the_exact_applied_cut() {
        let mut binding = binding(
            StreamRouteId::from_bytes([0x32; 16]),
            0x42,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(5),
            },
        );
        binding.stream_cursor = StreamCursor::At(7);
        let pending = DurableStreamBindingV1::from_stream_binding(binding).unwrap();

        assert_eq!(pending.outer_acked(), StreamCursor::BeforeFirst);
        assert!(pending.with_committed_outer_ack(6).is_err());
        assert!(pending.with_committed_outer_ack(8).is_err());
        let acked = pending.with_committed_outer_ack(7).unwrap();
        assert_eq!(acked.outer_acked(), StreamCursor::At(7));
        assert_eq!(acked.with_committed_outer_ack(7).unwrap(), acked);

        let replay = DurableStreamReplayTupleV1 {
            key_id: acked.binding.key_id,
            key_directory_revision: acked.binding.key_directory_revision,
            stream_route: acked.binding.stream_route,
            stream_generation: acked.binding.stream_generation,
            stream_seq: 9,
            sender_counter: 3,
            ciphertext_sha256: [0x43; 32],
        };
        let lagging_ack = DurableStreamBindingV1 {
            outer_applied: StreamCursor::At(9),
            replay_entries: vec![replay],
            ..acked.clone()
        };
        lagging_ack
            .canonical_bytes()
            .expect("an ACK may lag the applied cut after the binding cursor");
        let impossible_pre_binding_ack = DurableStreamBindingV1 {
            outer_acked: StreamCursor::At(3),
            ..lagging_ack
        };
        assert_eq!(
            impossible_pre_binding_ack.canonical_bytes().unwrap_err(),
            RemoteStreamStateError::InvalidCanonical,
        );
    }

    #[test]
    fn direct_publish_kernel_tracks_authenticated_overlap_before_new_reducer_items() {
        let mut binding = binding(
            StreamRouteId::from_bytes([0x33; 16]),
            0x43,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(5),
            },
        );
        binding.stream_cursor = StreamCursor::At(7);
        let mut state = DurableStreamBindingV1::from_subscription_bootstrap(
            binding,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(8),
            },
        )
        .unwrap();

        for (stream_seq, inner, expected_mode) in [
            (8, 6, StreamDirectApplyMode::Overlap),
            (9, 7, StreamDirectApplyMode::Overlap),
            (10, 8, StreamDirectApplyMode::Overlap),
            (11, 9, StreamDirectApplyMode::Apply),
        ] {
            let hash = [u8::try_from(stream_seq).unwrap(); 32];
            let (pending, disposition) = state
                .admit_publish(stream_seq, stream_seq + 100, hash)
                .unwrap();
            assert_eq!(disposition, StreamPublishDisposition::Fresh);
            let (same_pending, disposition) = pending
                .admit_publish(stream_seq, stream_seq + 100, hash)
                .unwrap();
            assert_eq!(disposition, StreamPublishDisposition::PendingDuplicate);
            assert_eq!(same_pending, pending);
            let (quarantined, disposition) = pending
                .admit_publish(stream_seq, stream_seq + 100, [0xee; 32])
                .unwrap();
            assert_eq!(disposition, StreamPublishDisposition::NonceReuseQuarantined);
            assert!(quarantined.replay_quarantined());
            assert_eq!(
                quarantined.replay_entry_count(),
                pending.replay_entry_count()
            );
            assert_eq!(
                quarantined
                    .admit_publish(stream_seq + 1, stream_seq + 101, [0xdd; 32])
                    .unwrap()
                    .1,
                StreamPublishDisposition::NonceReuseQuarantined,
                "a durable nonce conflict must leave the binding fail-closed",
            );

            let observed_after = RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(inner),
            };
            assert_eq!(
                pending.direct_apply_mode(&observed_after).unwrap(),
                expected_mode,
            );
            let (committed, actual_mode) = pending
                .commit_direct_publish(stream_seq, observed_after)
                .unwrap();
            assert_eq!(actual_mode, expected_mode);
            assert_eq!(committed.outer_applied(), StreamCursor::At(stream_seq));
            assert_eq!(
                committed.inner_observed(),
                &RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(inner),
                }
            );
            state = committed;
        }

        assert_eq!(
            state.inner_applied(),
            &RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(9),
            }
        );
        let (same, disposition) = state.admit_publish(11, 111, [11; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::AppliedDuplicate);
        assert_eq!(same, state);
        assert_eq!(
            state.admit_publish(10, 110, [10; 32]).unwrap().1,
            StreamPublishDisposition::AppliedDuplicate,
        );
        assert!(state.admit_publish(13, 113, [13; 32]).is_err());
        assert_eq!(
            state.admit_publish(12, 105, [12; 32]).unwrap().1,
            StreamPublishDisposition::Fresh,
            "an unseen counter inside the 4096 numerical window may arrive out of order",
        );
        let (quarantined, disposition) = state.admit_publish(12, 111, [12; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::NonceReuseQuarantined);
        assert!(quarantined.replay_quarantined());
        assert!(
            state
                .direct_apply_mode(&RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(11),
                })
                .is_err()
        );
    }

    #[test]
    fn gap_and_replay_complete_validate_exact_durable_outer_cut_without_mutation() {
        let mut binding = binding(
            StreamRouteId::from_bytes([0x34; 16]),
            0x44,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(2),
            },
        );
        binding.stream_cursor = StreamCursor::At(4);
        let state = DurableStreamBindingV1::from_stream_binding(binding).unwrap();

        state.validate_replay_complete(StreamCursor::At(4)).unwrap();
        assert!(state.validate_replay_complete(StreamCursor::At(5)).is_err());
        state.validate_gap(5, 6).unwrap();
        assert!(state.validate_gap(4, 6).is_err());
        assert!(state.validate_gap(5, 5).is_err());
    }

    #[test]
    fn legacy_v1_bootstrap_state_decodes_and_the_next_write_upgrades_to_v4() {
        let mut binding = binding(
            StreamRouteId::from_bytes([0x35; 16]),
            0x45,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(3),
            },
        );
        binding.stream_cursor = StreamCursor::At(5);
        let state = DurableStreamBindingV1::from_subscription_bootstrap(
            binding.clone(),
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(7),
            },
        )
        .unwrap()
        .with_committed_outer_ack(5)
        .unwrap();
        let legacy = state.legacy_v1_canonical_bytes().unwrap();
        assert_eq!(
            u16::from_be_bytes([legacy[4], legacy[5]]),
            LEGACY_STREAM_STATE_VERSION
        );

        let migrated = DurableStreamBindingV1::from_canonical_bytes(&legacy).unwrap();
        assert_eq!(migrated.binding(), &binding);
        assert_eq!(migrated.inner_observed(), &binding.inner_cursor);
        assert_eq!(
            migrated.inner_applied(),
            &RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(7),
            }
        );
        assert_eq!(migrated.outer_acked(), StreamCursor::At(5));
        let upgraded = migrated.canonical_bytes().unwrap();
        assert_eq!(
            u16::from_be_bytes([upgraded[4], upgraded[5]]),
            STREAM_STATE_VERSION
        );
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&upgraded).unwrap(),
            migrated
        );
    }

    #[test]
    fn legacy_v1_decoder_rejects_advanced_outer_and_a_present_replay_tuple() {
        let mut binding = binding(
            StreamRouteId::from_bytes([0x65; 16]),
            0x75,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(3),
            },
        );
        binding.stream_cursor = StreamCursor::At(5);
        let state = DurableStreamBindingV1::from_subscription_bootstrap(
            binding,
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(7),
            },
        )
        .unwrap();
        let legacy = state.legacy_v1_canonical_bytes().unwrap();

        let mut advanced_outer = legacy.clone();
        let binding_len = u32::from_be_bytes(advanced_outer[12..16].try_into().unwrap()) as usize;
        let outer_tag_offset = 16 + binding_len;
        assert_eq!(advanced_outer[outer_tag_offset], 1);
        advanced_outer[outer_tag_offset + 1..outer_tag_offset + 9]
            .copy_from_slice(&6_u64.to_be_bytes());
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&advanced_outer).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical,
            "v1 migration must not synthesize a missing receive replay window after outer progress",
        );

        let mut replay_present = legacy;
        assert_eq!(replay_present.last(), Some(&0));
        *replay_present.last_mut().unwrap() = 1;
        replay_present.extend_from_slice(&8_u64.to_be_bytes());
        replay_present.extend_from_slice(&9_u64.to_be_bytes());
        replay_present.extend_from_slice(&[0x81; 32]);
        let body_len = u32::try_from(replay_present.len() - STREAM_STATE_HEADER_LEN).unwrap();
        replay_present[8..12].copy_from_slice(&body_len.to_be_bytes());
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&replay_present).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical,
            "the legacy signed-blob tuple cannot be reinterpreted as a v2 ciphertext replay entry",
        );
    }

    #[test]
    fn v2_decoder_rejects_noncanonical_replay_windows() {
        const REPLAY_ENTRY_LEN: usize = 80;
        const STREAM_SEQ_OFFSET: usize = 32;
        const SENDER_COUNTER_OFFSET: usize = 40;
        const CIPHERTEXT_HASH_OFFSET: usize = 48;

        let canonical = state_with_two_replay_entries()
            .legacy_v2_canonical_bytes()
            .unwrap();
        let (count_offset, entries_offset) = replay_entry_offsets(&canonical);
        assert_eq!(
            u32::from_be_bytes(
                canonical[count_offset..count_offset + 4]
                    .try_into()
                    .unwrap()
            ),
            2
        );
        assert_eq!(canonical.len() - entries_offset, 2 * REPLAY_ENTRY_LEN);

        let mut duplicate_counter = canonical.clone();
        duplicate_counter[entries_offset + REPLAY_ENTRY_LEN + SENDER_COUNTER_OFFSET
            ..entries_offset + REPLAY_ENTRY_LEN + SENDER_COUNTER_OFFSET + 8]
            .copy_from_slice(&10_u64.to_be_bytes());

        let mut unsorted_counter = canonical.clone();
        unsorted_counter
            [entries_offset + SENDER_COUNTER_OFFSET..entries_offset + SENDER_COUNTER_OFFSET + 8]
            .copy_from_slice(&21_u64.to_be_bytes());

        let mut duplicate_outer_identity = canonical.clone();
        duplicate_outer_identity[entries_offset + REPLAY_ENTRY_LEN + STREAM_SEQ_OFFSET
            ..entries_offset + REPLAY_ENTRY_LEN + STREAM_SEQ_OFFSET + 8]
            .copy_from_slice(&0_u64.to_be_bytes());

        let mut zero_hash = canonical;
        zero_hash
            [entries_offset + CIPHERTEXT_HASH_OFFSET..entries_offset + CIPHERTEXT_HASH_OFFSET + 32]
            .fill(0);

        for (label, mutated) in [
            ("duplicate sender counter", duplicate_counter),
            ("unsorted sender counter", unsorted_counter),
            ("duplicate outer identity", duplicate_outer_identity),
            ("zero ciphertext hash", zero_hash),
        ] {
            assert_eq!(
                DurableStreamBindingV1::from_canonical_bytes(&mutated).unwrap_err(),
                RemoteStreamStateError::InvalidCanonical,
                "{label}",
            );
        }
    }

    #[test]
    fn v2_decoder_rejects_a_replay_count_above_the_hard_cap_before_allocation() {
        let mut canonical = catalog(0x63).legacy_v2_canonical_bytes().unwrap();
        let (count_offset, entries_offset) = replay_entry_offsets(&canonical);
        assert_eq!(entries_offset, canonical.len());
        canonical[count_offset..count_offset + 4].copy_from_slice(
            &u32::try_from(MAX_STREAM_REPLAY_ENTRIES + 1)
                .unwrap()
                .to_be_bytes(),
        );

        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&canonical).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical,
        );
    }

    #[test]
    fn nonce_reuse_quarantine_roundtrips_and_remains_fail_closed() {
        let pending = state_with_two_replay_entries();
        let (quarantined, disposition) = pending.admit_publish(1, 20, [0x73; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::NonceReuseQuarantined);
        assert!(quarantined.replay_quarantined());

        let canonical = quarantined.canonical_bytes().unwrap();
        let reopened = DurableStreamBindingV1::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(reopened, quarantined);
        assert_eq!(
            reopened.admit_publish(2, 21, [0x74; 32]).unwrap().1,
            StreamPublishDisposition::NonceReuseQuarantined,
        );
        assert!(reopened.with_committed_outer_ack(0).is_err());
        assert!(
            reopened
                .commit_direct_publish(
                    1,
                    RuntimeInnerCursor::Catalog {
                        cursor: StreamCursor::At(1),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn mutating_one_stream_binding_preserves_other_targets_replay_windows() {
        let catalog_pending = state_with_two_replay_entries();
        let conversation = conversation(0x64, "conversation-isolated");
        let (conversation_pending, disposition) =
            conversation.admit_publish(0, 30, [0x75; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        let other_before = conversation_pending.canonical_bytes().unwrap();

        let mut collection = decode_stream_bindings(
            &encode_stream_bindings(vec![conversation_pending.clone(), catalog_pending.clone()])
                .unwrap(),
        )
        .unwrap();
        let catalog = collection
            .iter_mut()
            .find(|state| state.target_key() == DurableStreamTargetKey::Catalog)
            .unwrap();
        let (replacement, disposition) = catalog.admit_publish(1, 20, [0x76; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::NonceReuseQuarantined);
        *catalog = replacement;

        let reopened =
            decode_stream_bindings(&encode_stream_bindings(collection).unwrap()).unwrap();
        let other_after = reopened
            .iter()
            .find(|state| {
                state.target_key()
                    == DurableStreamTargetKey::Conversation("conversation-isolated".to_owned())
            })
            .unwrap();
        assert_eq!(other_after, &conversation_pending);
        assert_eq!(other_after.canonical_bytes().unwrap(), other_before);
        assert_eq!(other_after.replay_entry_count(), 1);
        assert!(!other_after.replay_quarantined());
    }

    #[test]
    fn replay_window_uses_a_4096_counter_floor_and_rejects_unseen_stale_values() {
        let mut state = catalog(0x36);
        state.outer_applied = StreamCursor::At(5_000);
        state.inner_observed = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(5_000),
        };
        state.inner_applied = state.inner_observed.clone();
        let stream_route = state.binding.stream_route;
        let stream_generation = state.binding.stream_generation;
        state.replay_entries = (905_u64..=5_000)
            .map(|value| DurableStreamReplayTupleV1 {
                key_id: state.binding.key_id,
                key_directory_revision: state.binding.key_directory_revision,
                stream_route,
                stream_generation,
                stream_seq: value,
                sender_counter: value,
                ciphertext_sha256: [u8::try_from(value % 251 + 1).unwrap(); 32],
            })
            .collect();
        state.validate().expect("exact 4096-entry receive window");

        assert_eq!(
            state
                .admit_publish(1_000, 1_000, [u8::try_from(1_000 % 251 + 1).unwrap(); 32])
                .unwrap()
                .1,
            StreamPublishDisposition::AppliedDuplicate,
        );
        assert!(state.admit_publish(5_001, 904, [0xa1; 32]).is_err());
        let (pending, disposition) = state.admit_publish(5_001, 5_001, [0xa2; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::Fresh);
        assert_eq!(pending.replay_entry_count(), MAX_STREAM_REPLAY_ENTRIES);
        assert_eq!(
            pending.replay_entries.first().unwrap().sender_counter(),
            906
        );
        let (quarantined, disposition) = pending.admit_publish(5_001, 905, [0xa3; 32]).unwrap();
        assert_eq!(disposition, StreamPublishDisposition::NonceReuseQuarantined);
        assert!(quarantined.replay_quarantined());
        assert!(quarantined.with_committed_outer_ack(5_000).is_err());
        assert!(
            quarantined
                .commit_direct_publish(
                    5_001,
                    RuntimeInnerCursor::Catalog {
                        cursor: StreamCursor::At(5_001),
                    },
                )
                .is_err()
        );
        let canonical = quarantined.canonical_bytes().unwrap();
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&canonical).unwrap(),
            quarantined,
        );
        assert!(state.admit_publish(u64::MAX, 5_001, [0xa4; 32]).is_err());
    }

    #[test]
    fn catalog_generation_handoff_preserves_key_scope_without_aliasing_outer_sequence_zero() {
        let initial = catalog(0x37);
        let (pending, _) = initial.admit_publish(0, 10, [0xb1; 32]).unwrap();
        let (applied, _) = pending
            .commit_direct_publish(
                0,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(0),
                },
            )
            .unwrap();
        let mut next_binding = applied.binding.clone();
        next_binding.stream_route = StreamRouteId::from_bytes([0x38; 16]);
        next_binding.stream_generation = StreamGenerationId::from_bytes([0x48; 16]);
        next_binding.stream_cursor = StreamCursor::BeforeFirst;
        next_binding.inner_cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(0),
        };
        let rolled = applied
            .replace_subscription_bootstrap(
                next_binding,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(0),
                },
            )
            .expect("Catalog route/generation handoff preserves the same key window");
        assert_eq!(rolled.replay_entry_count(), 1);
        assert_eq!(
            rolled.admit_publish(0, 11, [0xb2; 32]).unwrap().1,
            StreamPublishDisposition::Fresh,
            "new generation seq=0 is a distinct authenticated outer identity",
        );
        let (quarantined, disposition) = rolled.admit_publish(0, 10, [0xb1; 32]).unwrap();
        assert_eq!(
            disposition,
            StreamPublishDisposition::NonceReuseQuarantined,
            "the same key/counter/ciphertext cannot be rebound to a different outer context",
        );
        assert!(quarantined.replay_quarantined());

        let mut rollback = rolled.binding.clone();
        rollback.inner_cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        };
        assert!(
            rolled
                .replace_subscription_bootstrap(
                    rollback,
                    RuntimeInnerCursor::Catalog {
                        cursor: StreamCursor::BeforeFirst,
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn v2_state_migrates_with_an_empty_cleanup_outbox_and_the_next_write_upgrades() {
        let state = state_with_two_replay_entries();
        let v2 = state.legacy_v2_canonical_bytes().unwrap();
        assert_eq!(u16::from_be_bytes([v2[4], v2[5]]), 2);

        let migrated = DurableStreamBindingV1::from_canonical_bytes(&v2).unwrap();
        assert_eq!(migrated, state);
        assert!(migrated.retired_subscriptions().is_empty());
        let upgraded = migrated.canonical_bytes().unwrap();
        assert_eq!(
            u16::from_be_bytes([upgraded[4], upgraded[5]]),
            STREAM_STATE_VERSION
        );
        assert_ne!(upgraded, v2);
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&upgraded).unwrap(),
            migrated
        );
    }

    #[test]
    fn route_generation_handoff_durably_queues_cleanup_and_exact_retry_is_idempotent() {
        let initial = state_with_two_replay_entries();
        let retired = DurableRetiredSubscriptionV1 {
            stream_route: initial.binding.stream_route,
            stream_generation: initial.binding.stream_generation,
        };
        let mut next_binding = initial.binding.clone();
        next_binding.stream_route = StreamRouteId::from_bytes([0x82; 16]);
        next_binding.stream_generation = StreamGenerationId::from_bytes([0x83; 16]);
        next_binding.stream_cursor = StreamCursor::BeforeFirst;
        next_binding.inner_cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(0),
        };
        let rolled = initial
            .replace_subscription_bootstrap(
                next_binding,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(0),
                },
            )
            .unwrap();

        assert_eq!(rolled.replay_entry_count(), initial.replay_entry_count());
        assert_eq!(rolled.retired_subscriptions(), &[retired]);
        let exact_retry = rolled
            .replace_subscription_bootstrap(rolled.binding.clone(), rolled.inner_applied.clone())
            .unwrap();
        assert_eq!(exact_retry, rolled);
        let reopened =
            DurableStreamBindingV1::from_canonical_bytes(&rolled.canonical_bytes().unwrap())
                .unwrap();
        assert_eq!(reopened, rolled);
    }

    #[test]
    fn cleanup_outbox_clear_requires_the_exact_active_replay_barrier_and_is_idempotent() {
        let initial = catalog(0x84);
        let mut next_binding = initial.binding.clone();
        next_binding.stream_route = StreamRouteId::from_bytes([0x85; 16]);
        next_binding.stream_generation = StreamGenerationId::from_bytes([0x86; 16]);
        let rolled = initial
            .replace_subscription_bootstrap(
                next_binding,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::BeforeFirst,
                },
            )
            .unwrap();
        assert_eq!(rolled.retired_subscriptions().len(), 1);

        assert!(
            rolled
                .clear_retired_subscriptions_after_replay_barrier(
                    StreamRouteId::from_bytes([0x87; 16]),
                    rolled.binding.stream_generation,
                    StreamCursor::BeforeFirst,
                )
                .is_err()
        );
        assert!(
            rolled
                .clear_retired_subscriptions_after_replay_barrier(
                    rolled.binding.stream_route,
                    StreamGenerationId::from_bytes([0x88; 16]),
                    StreamCursor::BeforeFirst,
                )
                .is_err()
        );
        assert!(
            rolled
                .clear_retired_subscriptions_after_replay_barrier(
                    rolled.binding.stream_route,
                    rolled.binding.stream_generation,
                    StreamCursor::At(0),
                )
                .is_err()
        );

        let cleared = rolled
            .clear_retired_subscriptions_after_replay_barrier(
                rolled.binding.stream_route,
                rolled.binding.stream_generation,
                StreamCursor::BeforeFirst,
            )
            .unwrap();
        assert!(cleared.retired_subscriptions().is_empty());
        assert_eq!(
            cleared
                .clear_retired_subscriptions_after_replay_barrier(
                    cleared.binding.stream_route,
                    cleared.binding.stream_generation,
                    StreamCursor::BeforeFirst,
                )
                .unwrap(),
            cleared
        );
    }

    #[test]
    fn cleanup_outbox_is_bounded_and_rejects_reusing_a_retired_pair() {
        let mut state = catalog(0x89);
        for index in 0..MAX_RETIRED_SUBSCRIPTIONS {
            let mut next_binding = state.binding.clone();
            let value = u8::try_from(index + 1).unwrap();
            next_binding.stream_route = StreamRouteId::from_bytes([value; 16]);
            next_binding.stream_generation =
                StreamGenerationId::from_bytes([value.wrapping_add(0x40); 16]);
            state = state
                .replace_subscription_bootstrap(
                    next_binding,
                    RuntimeInnerCursor::Catalog {
                        cursor: StreamCursor::BeforeFirst,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            state.retired_subscriptions().len(),
            MAX_RETIRED_SUBSCRIPTIONS
        );

        let mut overflow = state.binding.clone();
        overflow.stream_route = StreamRouteId::from_bytes([0xf0; 16]);
        overflow.stream_generation = StreamGenerationId::from_bytes([0xf1; 16]);
        assert_eq!(
            state
                .replace_subscription_bootstrap(
                    overflow,
                    RuntimeInnerCursor::Catalog {
                        cursor: StreamCursor::BeforeFirst,
                    },
                )
                .unwrap_err(),
            RemoteStreamStateError::TooLarge
        );

        let retired = state.retired_subscriptions()[0];
        let mut reused = state.binding.clone();
        reused.stream_route = retired.stream_route();
        reused.stream_generation = retired.stream_generation();
        assert_eq!(
            state
                .replace_subscription_bootstrap(
                    reused,
                    RuntimeInnerCursor::Catalog {
                        cursor: StreamCursor::BeforeFirst,
                    },
                )
                .unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
    }

    #[test]
    fn v3_decoder_rejects_duplicate_unsorted_overflow_and_active_cleanup_aliases() {
        const RETIRED_ENTRY_LEN: usize = 32;

        let mut state = catalog(0x8a);
        for (route, generation) in [(0x8b, 0x9b), (0x8c, 0x9c)] {
            let mut next_binding = state.binding.clone();
            next_binding.stream_route = StreamRouteId::from_bytes([route; 16]);
            next_binding.stream_generation = StreamGenerationId::from_bytes([generation; 16]);
            state = state
                .replace_subscription_bootstrap(
                    next_binding,
                    RuntimeInnerCursor::Catalog {
                        cursor: StreamCursor::BeforeFirst,
                    },
                )
                .unwrap();
        }
        let canonical = state.legacy_v3_canonical_bytes().unwrap();
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&canonical).unwrap(),
            state,
            "v3 retired-subscription state migrates without inventing pending/ACK state",
        );
        let (count_offset, entries_offset) = retired_subscription_offsets(&canonical);
        assert_eq!(
            u32::from_be_bytes(
                canonical[count_offset..count_offset + 4]
                    .try_into()
                    .unwrap()
            ),
            2
        );
        assert_eq!(canonical.len() - entries_offset, 2 * RETIRED_ENTRY_LEN);

        let mut duplicate = canonical.clone();
        duplicate.copy_within(
            entries_offset..entries_offset + RETIRED_ENTRY_LEN,
            entries_offset + RETIRED_ENTRY_LEN,
        );
        let mut unsorted = canonical.clone();
        let (left, right) = unsorted[entries_offset..].split_at_mut(RETIRED_ENTRY_LEN);
        left.swap_with_slice(&mut right[..RETIRED_ENTRY_LEN]);
        let mut active_alias = canonical;
        active_alias[entries_offset..entries_offset + 16]
            .copy_from_slice(state.binding.stream_route.as_bytes());
        active_alias[entries_offset + 16..entries_offset + RETIRED_ENTRY_LEN]
            .copy_from_slice(state.binding.stream_generation.as_bytes());

        for (label, mutated) in [
            ("duplicate", duplicate),
            ("unsorted", unsorted),
            ("active alias", active_alias),
        ] {
            assert_eq!(
                DurableStreamBindingV1::from_canonical_bytes(&mutated).unwrap_err(),
                RemoteStreamStateError::InvalidCanonical,
                "{label}",
            );
        }

        let empty = catalog(0x8d).legacy_v3_canonical_bytes().unwrap();
        let (count_offset, entries_offset) = retired_subscription_offsets(&empty);
        assert_eq!(entries_offset, empty.len());
        let mut overflow = empty;
        overflow[count_offset..count_offset + 4].copy_from_slice(
            &u32::try_from(MAX_RETIRED_SUBSCRIPTIONS + 1)
                .unwrap()
                .to_be_bytes(),
        );
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&overflow).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
    }

    #[test]
    fn collection_rejects_active_retired_and_retired_retired_pair_aliases() {
        let initial = catalog(0x8e);
        let retired_pair = (
            initial.binding.stream_route,
            initial.binding.stream_generation,
        );
        let mut next_binding = initial.binding.clone();
        next_binding.stream_route = StreamRouteId::from_bytes([0x8f; 16]);
        next_binding.stream_generation = StreamGenerationId::from_bytes([0x9f; 16]);
        let catalog_rolled = initial
            .replace_subscription_bootstrap(
                next_binding,
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::BeforeFirst,
                },
            )
            .unwrap();
        let conversation_active = DurableStreamBindingV1::from_stream_binding(binding(
            retired_pair.0,
            *retired_pair.1.as_bytes().first().unwrap(),
            RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new("active-retired-alias"),
                cursor: StreamCursor::BeforeFirst,
            },
        ))
        .unwrap();
        assert_eq!(
            conversation_active.binding.stream_generation,
            retired_pair.1
        );
        assert_eq!(
            encode_stream_bindings(vec![catalog_rolled.clone(), conversation_active]).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );

        let conversation_initial = DurableStreamBindingV1::from_stream_binding(binding(
            retired_pair.0,
            *retired_pair.1.as_bytes().first().unwrap(),
            RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new("retired-retired-alias"),
                cursor: StreamCursor::BeforeFirst,
            },
        ))
        .unwrap();
        let mut conversation_next = conversation_initial.binding.clone();
        conversation_next.stream_route = StreamRouteId::from_bytes([0x90; 16]);
        conversation_next.stream_generation = StreamGenerationId::from_bytes([0xa0; 16]);
        let conversation_rolled = conversation_initial
            .replace_subscription_bootstrap(
                conversation_next,
                RuntimeInnerCursor::Conversation {
                    conversation_id: ConversationId::new("retired-retired-alias"),
                    cursor: StreamCursor::BeforeFirst,
                },
            )
            .unwrap();
        assert_eq!(
            encode_stream_bindings(vec![catalog_rolled, conversation_rolled]).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
    }

    #[test]
    fn collection_rejects_duplicate_targets_routes_and_noncanonical_order() {
        let catalog_state = catalog(0x51);
        let first = conversation(0x52, "conversation-a");
        let second = conversation(0x53, "conversation-b");
        let canonical =
            encode_stream_bindings(vec![second.clone(), catalog_state.clone(), first.clone()])
                .expect("encoder sorts unique targets");
        decode_stream_bindings(&canonical).expect("canonical sorted collection");

        assert_eq!(
            encode_stream_bindings(vec![first.clone(), conversation(0x54, "conversation-a")])
                .unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
        assert_eq!(
            encode_stream_bindings(vec![first.clone(), conversation(0x52, "conversation-b")])
                .unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
        assert_eq!(
            encode_stream_bindings(vec![catalog(0x52), first]).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );

        let mut reversed = canonical;
        reversed.swap(0, 1);
        assert_eq!(
            decode_stream_bindings(&reversed).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
    }

    #[test]
    fn canonical_decoder_rejects_reserved_trailing_and_noncanonical_cursor_bytes() {
        let canonical = catalog(0x61).canonical_bytes().unwrap();
        for mutated in [
            {
                let mut value = canonical.clone();
                value[6] = 1;
                value
            },
            {
                let mut value = canonical.clone();
                value.push(0);
                let body_len = u32::from_be_bytes(value[8..12].try_into().unwrap()) + 1;
                value[8..12].copy_from_slice(&body_len.to_be_bytes());
                value
            },
            {
                let mut value = canonical.clone();
                let binding_len = u32::from_be_bytes(value[12..16].try_into().unwrap()) as usize;
                let outer_cursor_value = 16 + binding_len + 1;
                value[outer_cursor_value + 7] = 1;
                value
            },
        ] {
            assert_eq!(
                DurableStreamBindingV1::from_canonical_bytes(&mutated).unwrap_err(),
                RemoteStreamStateError::InvalidCanonical
            );
        }
    }
}
