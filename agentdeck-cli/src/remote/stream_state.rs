//! Persistent remote live-stream 的严格本地状态编码。
//!
//! `StreamBindingV1` 原始 canonical bytes 始终保留；Relay outer applied/ACK、Runtime
//! inner observed/applied、receive replay window 与 retired subscription cleanup outbox 是
//! 彼此独立的轴，不能互相推导。

use std::cmp::Ordering;
use std::collections::HashSet;

use agentdeck_protocol::e2ee::{KeyPurpose, STREAM_BINDING_MAX_CANONICAL_BYTES, StreamBindingV1};
use agentdeck_protocol::relay_v2::{StreamGenerationId, StreamRouteId};
use agentdeck_protocol::runtime::{ConversationId, RuntimeInnerCursor, StreamCursor};
use thiserror::Error;

const STREAM_STATE_MAGIC: &[u8; 4] = b"ADSB";
const LEGACY_STREAM_STATE_VERSION: u16 = 1;
const PREVIOUS_STREAM_STATE_VERSION: u16 = 2;
const STREAM_STATE_VERSION: u16 = 3;
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
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    stream_seq: u64,
    sender_counter: u64,
    ciphertext_sha256: [u8; 32],
}

impl DurableStreamReplayTupleV1 {
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
    pub(crate) fn admit_publish(
        &self,
        stream_seq: u64,
        sender_counter: u64,
        ciphertext_sha256: [u8; 32],
    ) -> Result<(Self, StreamPublishDisposition), RemoteStreamStateError> {
        self.validate()?;
        if ciphertext_sha256 == [0; 32] || StreamCursor::At(stream_seq).checked_next().is_err() {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        if self.replay_quarantined {
            return Ok((
                self.clone(),
                StreamPublishDisposition::NonceReuseQuarantined,
            ));
        }
        if let Some(replay) = self
            .replay_entries
            .iter()
            .find(|entry| entry.sender_counter == sender_counter)
        {
            if replay.stream_route != self.binding.stream_route
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
        let replay_floor = self.replay_entries.last().map_or(0, |entry| {
            entry
                .sender_counter
                .saturating_sub(MAX_STREAM_REPLAY_DISTANCE)
        });
        if self.outer_applied.checked_next().ok() != Some(stream_seq)
            || (!self.replay_entries.is_empty() && sender_counter < replay_floor)
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let mut pending = self.clone();
        let insertion = match pending
            .replay_entries
            .binary_search_by_key(&sender_counter, |entry| entry.sender_counter)
        {
            Ok(_) => return Err(RemoteStreamStateError::InvalidCanonical),
            Err(insertion) => insertion,
        };
        pending.replay_entries.insert(
            insertion,
            DurableStreamReplayTupleV1 {
                stream_route: self.binding.stream_route,
                stream_generation: self.binding.stream_generation,
                stream_seq,
                sender_counter,
                ciphertext_sha256,
            },
        );
        let replay_high_water = pending
            .replay_entries
            .last()
            .ok_or(RemoteStreamStateError::InvalidCanonical)?
            .sender_counter;
        let replay_floor = replay_high_water.saturating_sub(MAX_STREAM_REPLAY_DISTANCE);
        pending
            .replay_entries
            .retain(|entry| entry.sender_counter >= replay_floor);
        pending.validate()?;
        Ok((pending, StreamPublishDisposition::Fresh))
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
        self.v2_or_v3_canonical_bytes(STREAM_STATE_VERSION)
    }

    fn legacy_v2_canonical_bytes(&self) -> Result<Vec<u8>, RemoteStreamStateError> {
        if !self.retired_subscriptions.is_empty() {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        self.v2_or_v3_canonical_bytes(PREVIOUS_STREAM_STATE_VERSION)
    }

    fn v2_or_v3_canonical_bytes(&self, version: u16) -> Result<Vec<u8>, RemoteStreamStateError> {
        self.validate()?;
        if !matches!(
            version,
            PREVIOUS_STREAM_STATE_VERSION | STREAM_STATE_VERSION
        ) {
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
        let replay_count = u32::try_from(self.replay_entries.len())
            .map_err(|_| RemoteStreamStateError::TooLarge)?;
        body.extend_from_slice(&replay_count.to_be_bytes());
        for replay in &self.replay_entries {
            body.extend_from_slice(replay.stream_route.as_bytes());
            body.extend_from_slice(replay.stream_generation.as_bytes());
            body.extend_from_slice(&replay.stream_seq.to_be_bytes());
            body.extend_from_slice(&replay.sender_counter.to_be_bytes());
            body.extend_from_slice(&replay.ciphertext_sha256);
        }
        if version == STREAM_STATE_VERSION {
            let retired_count = u32::try_from(self.retired_subscriptions.len())
                .map_err(|_| RemoteStreamStateError::TooLarge)?;
            body.extend_from_slice(&retired_count.to_be_bytes());
            for retired in &self.retired_subscriptions {
                body.extend_from_slice(retired.stream_route.as_bytes());
                body.extend_from_slice(retired.stream_generation.as_bytes());
            }
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
            LEGACY_STREAM_STATE_VERSION | PREVIOUS_STREAM_STATE_VERSION | STREAM_STATE_VERSION
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
                )
            }
            PREVIOUS_STREAM_STATE_VERSION | STREAM_STATE_VERSION => {
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
                    replay_entries.push(DurableStreamReplayTupleV1 {
                        stream_route: StreamRouteId::from_bytes(decoder.fixed()?),
                        stream_generation: StreamGenerationId::from_bytes(decoder.fixed()?),
                        stream_seq: decoder.u64()?,
                        sender_counter: decoder.u64()?,
                        ciphertext_sha256: decoder.fixed()?,
                    });
                }
                let retired_subscriptions = if version == STREAM_STATE_VERSION {
                    let retired_count = usize::try_from(decoder.u32()?)
                        .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
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
                    retired
                } else {
                    Vec::new()
                };
                (
                    inner_observed,
                    inner_applied,
                    replay_quarantined,
                    replay_entries,
                    retired_subscriptions,
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
        };
        value.validate()?;
        let exact = match version {
            LEGACY_STREAM_STATE_VERSION => value.legacy_v1_canonical_bytes()?,
            PREVIOUS_STREAM_STATE_VERSION => value.legacy_v2_canonical_bytes()?,
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
        if self.replay_entries.len() > MAX_STREAM_REPLAY_ENTRIES
            || (self.replay_quarantined && self.replay_entries.is_empty())
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
        let Some(last) = self.replay_entries.last() else {
            return Ok(());
        };
        let replay_floor = last
            .sender_counter
            .saturating_sub(MAX_STREAM_REPLAY_DISTANCE);
        let mut previous = None;
        let mut stream_sequences = HashSet::with_capacity(self.replay_entries.len());
        let pending_seq = self.outer_applied.checked_next().ok();
        for replay in &self.replay_entries {
            let replay_cursor = StreamCursor::At(replay.stream_seq);
            if replay.ciphertext_sha256 == [0; 32]
                || replay.sender_counter < replay_floor
                || replay_cursor.checked_next().is_err()
                || (replay.stream_route == self.binding.stream_route
                    && replay.stream_generation == self.binding.stream_generation
                    && cursor_cmp(replay_cursor, self.outer_applied) == Ordering::Greater
                    && pending_seq != Some(replay.stream_seq))
                || !stream_sequences.insert((
                    *replay.stream_route.as_bytes(),
                    *replay.stream_generation.as_bytes(),
                    replay.stream_seq,
                ))
                || previous.is_some_and(|previous: &DurableStreamReplayTupleV1| {
                    previous.sender_counter >= replay.sender_counter
                })
            {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
            previous = Some(replay);
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
    use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose};
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
            PREVIOUS_STREAM_STATE_VERSION | STREAM_STATE_VERSION
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
            STREAM_STATE_VERSION
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
    fn legacy_v1_bootstrap_state_decodes_and_the_next_write_upgrades_to_v3() {
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
        let canonical = state.canonical_bytes().unwrap();
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

        let empty = catalog(0x8d).canonical_bytes().unwrap();
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
