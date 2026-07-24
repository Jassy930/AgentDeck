//! Persistent remote KeySync 的有界、可持久化协调状态。
//!
//! 本模块不验签、不解密、不访问 Keychain，也不发送网络帧。调用方只能在完整
//! MachineDataSign/AAD 验证后构造 [`SignedHigherRevisionObservationV1`]，并把由对应
//! [`KeySyncRequestV1`] 产生的 exact Relay `Send` 交给这里冻结。状态机负责持久化
//! observation identity、30 秒绝对窗口、最多三次 probe、逐次 exact send 与 terminal
//! `UpdateSet` handoff；transport retry 永远复用当前冻结字节。

use std::collections::HashSet;
use std::fmt;

use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::{
    DirectoryCurrentV1, E2EE_FORMAT_VERSION, KeyId, KeyPurpose, KeySyncRequestV1, KeyUpdateSetV1,
    REMOTE_CRYPTO_KEY_EPOCH_MISSING, SignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RequestRouteId, StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};
use agentdeck_protocol::runtime::{RUNTIME_PROTOCOL_VERSION, StreamCursor};
use thiserror::Error;

const KEY_SYNC_STATE_MAGIC: &[u8; 4] = b"ADKS";
const KEY_SYNC_STATE_VERSION: u16 = 1;
const KEY_SYNC_STATE_HEADER_LEN: usize = 12;
const RETAINED_ACK_EXTENSION_MAGIC: &[u8; 4] = b"AKA1";
const MAX_KEY_SYNC_REQUEST_BYTES: usize = 8 * 1024;
const MAX_DURABLE_KEY_SYNC_STATE_BYTES: usize = 256 * 1024;

/// 单个 signed KeySync `Send` 的 endpoint 上界。KeySync request 是 small-control carrier；
/// 64 KiB 已远高于当前 canonical request，同时避免三次 durable retry 占满 128 MiB
/// CryptoState 总预算。
pub const KEY_SYNC_MAX_SEND_BYTES: usize = 64 * 1024;
pub const KEY_SYNC_MAX_ATTEMPTS: u8 = 3;
pub const KEY_SYNC_WINDOW_MS: u64 = 30_000;

/// 只有上层完成 signed header、outer AAD 与 MachineDataSign 验证后才能提供的观察摘要。
/// 两个 hash 都进入 durable identity：同一密文的 exact signed frame retry 才是同一观察；
/// 任一 hash 或 authority/key 轴变化都与当前协调冲突。
#[derive(Clone, Eq, PartialEq)]
pub struct SignedHigherRevisionObservationV1 {
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_trust_epoch: TrustEpoch,
    known_key_directory_revision: KeyDirectoryRevision,
    observed_key_directory_revision: KeyDirectoryRevision,
    observed_key_id: KeyId,
    key_slot_stream_route: Option<StreamRouteId>,
    publication_stream_route: StreamRouteId,
    publication_stream_generation: StreamGenerationId,
    publication_stream_seq: u64,
    sender_counter: u64,
    signed_frame_sha256: [u8; 32],
    ciphertext_sha256: [u8; 32],
}

impl fmt::Debug for SignedHigherRevisionObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedHigherRevisionObservationV1([REDACTED])")
    }
}

impl SignedHigherRevisionObservationV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        grant_serial: GrantSerial,
        root_trust_epoch: TrustEpoch,
        known_key_directory_revision: KeyDirectoryRevision,
        observed_key_directory_revision: KeyDirectoryRevision,
        observed_key_id: KeyId,
        key_slot_stream_route: Option<StreamRouteId>,
        publication_stream_route: StreamRouteId,
        publication_stream_generation: StreamGenerationId,
        publication_stream_seq: u64,
        sender_counter: u64,
        signed_frame_sha256: [u8; 32],
        ciphertext_sha256: [u8; 32],
    ) -> Result<Self, KeySyncError> {
        let value = Self {
            machine_route,
            device_route,
            grant_serial,
            root_trust_epoch,
            known_key_directory_revision,
            observed_key_directory_revision,
            observed_key_id,
            key_slot_stream_route,
            publication_stream_route,
            publication_stream_generation,
            publication_stream_seq,
            sender_counter,
            signed_frame_sha256,
            ciphertext_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), KeySyncError> {
        let stream_shape_valid = match self.observed_key_id.purpose {
            KeyPurpose::Catalog => self.key_slot_stream_route.is_none(),
            KeyPurpose::ConversationDek => {
                self.key_slot_stream_route == Some(self.publication_stream_route)
                    && !is_zero(self.publication_stream_route.as_bytes())
            }
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => false,
        };
        if is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.root_trust_epoch.value() == 0
            || self.known_key_directory_revision.value() == 0
            || self.observed_key_directory_revision.value()
                <= self.known_key_directory_revision.value()
            || self.observed_key_id.epoch == 0
            || !stream_shape_valid
            || is_zero(self.publication_stream_route.as_bytes())
            || is_zero(self.publication_stream_generation.as_bytes())
            || StreamCursor::At(self.publication_stream_seq)
                .checked_next()
                .is_err()
            || is_zero(&self.signed_frame_sha256)
            || is_zero(&self.ciphertext_sha256)
        {
            return Err(KeySyncError::InvalidCanonical);
        }
        self.known_key_directory_revision
            .next()
            .map_err(|_| KeySyncError::InvalidCanonical)?;
        Ok(())
    }

    pub fn request_for_attempt(&self, attempt: u8) -> Result<KeySyncRequestV1, KeySyncError> {
        self.validate()?;
        build_request(self, self.known_key_directory_revision, attempt)
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
    pub const fn grant_serial(&self) -> GrantSerial {
        self.grant_serial
    }

    #[must_use]
    pub const fn root_trust_epoch(&self) -> TrustEpoch {
        self.root_trust_epoch
    }

    #[must_use]
    pub const fn known_key_directory_revision(&self) -> KeyDirectoryRevision {
        self.known_key_directory_revision
    }

    #[must_use]
    pub const fn observed_key_directory_revision(&self) -> KeyDirectoryRevision {
        self.observed_key_directory_revision
    }

    #[must_use]
    pub fn requested_key_directory_revision(&self) -> KeyDirectoryRevision {
        self.known_key_directory_revision
            .next()
            .expect("validated KeySync observation has an exact next revision")
    }

    #[must_use]
    pub const fn observed_key_id(&self) -> KeyId {
        self.observed_key_id
    }

    #[must_use]
    pub const fn key_slot_stream_route(&self) -> Option<StreamRouteId> {
        self.key_slot_stream_route
    }

    #[must_use]
    pub const fn publication_stream_route(&self) -> StreamRouteId {
        self.publication_stream_route
    }

    #[must_use]
    pub const fn publication_stream_generation(&self) -> StreamGenerationId {
        self.publication_stream_generation
    }

    #[must_use]
    pub const fn publication_stream_seq(&self) -> u64 {
        self.publication_stream_seq
    }

    #[must_use]
    pub const fn sender_counter(&self) -> u64 {
        self.sender_counter
    }

    #[must_use]
    pub const fn signed_frame_sha256(&self) -> [u8; 32] {
        self.signed_frame_sha256
    }

    #[must_use]
    pub const fn ciphertext_sha256(&self) -> [u8; 32] {
        self.ciphertext_sha256
    }
}

fn build_request(
    observation: &SignedHigherRevisionObservationV1,
    known_key_directory_revision: KeyDirectoryRevision,
    attempt: u8,
) -> Result<KeySyncRequestV1, KeySyncError> {
    if attempt == 0 {
        return Err(KeySyncError::InvalidCanonical);
    }
    if attempt > KEY_SYNC_MAX_ATTEMPTS {
        return Err(KeySyncError::Exhausted);
    }
    if known_key_directory_revision.value() < observation.known_key_directory_revision.value()
        || known_key_directory_revision.value()
            >= observation.observed_key_directory_revision.value()
    {
        return Err(KeySyncError::InvalidCanonical);
    }
    let requested_key_directory_revision = known_key_directory_revision
        .next()
        .map_err(|_| KeySyncError::InvalidCanonical)?;
    let request = KeySyncRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: observation.machine_route,
        device_route: observation.device_route,
        grant_serial: observation.grant_serial,
        root_trust_epoch: observation.root_trust_epoch,
        known_key_directory_revision,
        requested_key_directory_revision,
        key_id: observation.observed_key_id,
        stream_route: observation.key_slot_stream_route,
        attempt,
    };
    request
        .validate()
        .map_err(|_| KeySyncError::InvalidCanonical)?;
    Ok(request)
}

/// 一次 KeySync attempt 已冻结的 request 与 Relay `Send`。构造器只验证 canonical
/// outer/signed sealed-blob shape；密文是否确实承载给定 request 仍由拥有 DeviceCommandTx
/// capability 的上层 sealing path 保证。
#[derive(Clone, Eq, PartialEq)]
pub struct FrozenKeySyncSendV1 {
    request: KeySyncRequestV1,
    request_route: RequestRouteId,
    request_sha256: [u8; 32],
    exact_send: Vec<u8>,
    exact_send_sha256: [u8; 32],
}

impl fmt::Debug for FrozenKeySyncSendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenKeySyncSendV1([REDACTED])")
    }
}

impl FrozenKeySyncSendV1 {
    pub fn new(request: KeySyncRequestV1, exact_send: Vec<u8>) -> Result<Self, KeySyncError> {
        request
            .validate()
            .map_err(|_| KeySyncError::InvalidCanonical)?;
        if exact_send.len() > KEY_SYNC_MAX_SEND_BYTES {
            return Err(KeySyncError::TooLarge);
        }
        if exact_send.is_empty() {
            return Err(KeySyncError::InvalidCanonical);
        }
        let decoded = decode(&exact_send).map_err(|_| KeySyncError::InvalidCanonical)?;
        if encode(&decoded) != exact_send {
            return Err(KeySyncError::InvalidCanonical);
        }
        let RelayFrameBody::Send(send) = &decoded.body else {
            return Err(KeySyncError::InvalidCanonical);
        };
        if send.device_route != request.device_route
            || is_zero(send.request_route.as_bytes())
            || send.sealed_blob.0.is_empty()
        {
            return Err(KeySyncError::InvalidCanonical);
        }
        let signed = SignedSealedBlobV1::from_wire_bytes(&send.sealed_blob.0)
            .map_err(|_| KeySyncError::InvalidCanonical)?;
        if signed.inner.key_id.purpose != KeyPurpose::DeviceCommandTx
            || signed.inner.key_directory_revision
                != request.requested_key_directory_revision.value()
        {
            return Err(KeySyncError::InvalidCanonical);
        }
        let request_bytes = request
            .canonical_bytes()
            .map_err(|_| KeySyncError::InvalidCanonical)?;
        if request_bytes.len() > MAX_KEY_SYNC_REQUEST_BYTES {
            return Err(KeySyncError::TooLarge);
        }
        Ok(Self {
            request,
            request_route: send.request_route,
            request_sha256: sha256(&request_bytes),
            exact_send_sha256: sha256(&exact_send),
            exact_send,
        })
    }

    fn validate(&self) -> Result<(), KeySyncError> {
        let rebuilt = Self::new(self.request.clone(), self.exact_send.clone())?;
        if rebuilt != *self {
            return Err(KeySyncError::InvalidCanonical);
        }
        Ok(())
    }

    #[must_use]
    pub const fn request(&self) -> &KeySyncRequestV1 {
        &self.request
    }

    #[must_use]
    pub const fn request_route(&self) -> RequestRouteId {
        self.request_route
    }

    #[must_use]
    pub const fn request_sha256(&self) -> [u8; 32] {
        self.request_sha256
    }

    #[must_use]
    pub fn exact_send_bytes(&self) -> &[u8] {
        &self.exact_send
    }

    #[must_use]
    pub const fn exact_send_sha256(&self) -> [u8; 32] {
        self.exact_send_sha256
    }
}

#[derive(Clone, Eq, PartialEq)]
struct KeySyncAttemptRecord {
    started_at_ms: u64,
    frozen: FrozenKeySyncSendV1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CompletedKeySyncUpdate {
    attempt: u8,
    installed_at_ms: u64,
    key_directory_revision: KeyDirectoryRevision,
    update_set_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeySyncCoordinationStatus {
    Active,
    AwaitingProbe,
    Resolved,
    Exhausted,
}

/// 可以直接纳入已加密 CryptoState snapshot 的 canonical durable 状态。
#[derive(Clone, Eq, PartialEq)]
pub struct DurableKeySyncStateV1 {
    observation: SignedHigherRevisionObservationV1,
    started_at_ms: u64,
    deadline_at_ms: u64,
    last_observed_at_ms: u64,
    current_known_key_directory_revision: KeyDirectoryRevision,
    attempts: Vec<KeySyncAttemptRecord>,
    completed_updates: Vec<CompletedKeySyncUpdate>,
    retained_ack_basis: Option<KeyUpdateAckBasisV1>,
}

impl fmt::Debug for DurableKeySyncStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableKeySyncStateV1([REDACTED])")
    }
}

impl DurableKeySyncStateV1 {
    pub fn start(
        observation: SignedHigherRevisionObservationV1,
        started_at_ms: u64,
        first: FrozenKeySyncSendV1,
    ) -> Result<Self, KeySyncError> {
        observation.validate()?;
        let deadline_at_ms = started_at_ms
            .checked_add(KEY_SYNC_WINDOW_MS)
            .ok_or(KeySyncError::InvalidCanonical)?;
        if first.request != observation.request_for_attempt(1)? {
            return Err(KeySyncError::InvalidCanonical);
        }
        let current_known_key_directory_revision = observation.known_key_directory_revision;
        let value = Self {
            observation,
            started_at_ms,
            deadline_at_ms,
            last_observed_at_ms: started_at_ms,
            current_known_key_directory_revision,
            attempts: vec![KeySyncAttemptRecord {
                started_at_ms,
                frozen: first,
            }],
            completed_updates: Vec::new(),
            retained_ack_basis: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// 同一 signed observation 只返回当前 attempt 的 exact bytes，不消费新 attempt。
    /// `last_observed_at_ms` 必须与 exact retry 一起持久化，作为 restart 后的回退检测水位。
    pub fn observe_again(
        &mut self,
        observation: &SignedHigherRevisionObservationV1,
        now_ms: u64,
    ) -> Result<&FrozenKeySyncSendV1, KeySyncError> {
        observation.validate()?;
        if observation != &self.observation {
            return Err(KeySyncError::ObservationConflict);
        }
        self.check_time(now_ms)?;
        if self.status() != KeySyncCoordinationStatus::Active {
            return Err(KeySyncError::ResponseConflict);
        }
        self.last_observed_at_ms = now_ms;
        self.active_send().ok_or(KeySyncError::InvalidCanonical)
    }

    /// 在预留 counter、seal 与持久化之前只读验证 authenticated `DirectoryCurrent`，
    /// 并返回下一次应当承载的 canonical request。这样无效 route/status、deadline 或
    /// attempt budget 不会消耗不可回退的 durable counter。
    pub fn next_retry_request_after_directory_current(
        &self,
        now_ms: u64,
        reply_request_route: RequestRouteId,
        status: &DirectoryCurrentV1,
    ) -> Result<KeySyncRequestV1, KeySyncError> {
        self.validate()?;
        self.check_time(now_ms)?;
        if self.attempts.len() >= usize::from(KEY_SYNC_MAX_ATTEMPTS) {
            return Err(KeySyncError::Exhausted);
        }
        if self.status() != KeySyncCoordinationStatus::Active {
            return Err(KeySyncError::ResponseConflict);
        }
        let active = self.active_send().ok_or(KeySyncError::InvalidCanonical)?;
        if reply_request_route != active.request_route
            || status.validate().is_err()
            || status.machine_route != self.observation.machine_route
            || status.device_route != self.observation.device_route
            || status.grant_serial != self.observation.grant_serial
            || status.root_trust_epoch != self.observation.root_trust_epoch
            || status.current_key_directory_revision != active.request.known_key_directory_revision
            || status.requested_key_directory_revision
                != active.request.requested_key_directory_revision
        {
            return Err(KeySyncError::ResponseConflict);
        }
        let next_attempt =
            u8::try_from(self.attempts.len() + 1).map_err(|_| KeySyncError::Exhausted)?;
        build_request(
            &self.observation,
            self.current_known_key_directory_revision,
            next_attempt,
        )
    }

    /// authenticated `DirectoryCurrent` 不是 ACK；只在它精确关联当前 request 时消费一次
    /// attempt，并冻结调用方已按 `attempt+1` 生成的新 `Send`。
    pub fn retry_after_directory_current(
        &mut self,
        now_ms: u64,
        reply_request_route: RequestRouteId,
        status: &DirectoryCurrentV1,
        next: FrozenKeySyncSendV1,
    ) -> Result<&FrozenKeySyncSendV1, KeySyncError> {
        let expected =
            self.next_retry_request_after_directory_current(now_ms, reply_request_route, status)?;
        if next.request != expected
            || self
                .attempts
                .iter()
                .any(|attempt| attempt.frozen.request_route == next.request_route)
        {
            return Err(KeySyncError::ResponseConflict);
        }
        next.validate()?;
        self.attempts.push(KeySyncAttemptRecord {
            started_at_ms: now_ms,
            frozen: next,
        });
        self.last_observed_at_ms = now_ms;
        self.validate()?;
        self.active_send().ok_or(KeySyncError::InvalidCanonical)
    }

    /// 为下一轮已签名 higher-revision observation 做纯只读验证，并返回新的 attempt-1
    /// request。旧协调必须已经 Resolved；新 observation 必须从刚安装的 revision 继续，
    /// authority 不得漂移。旧 30 秒窗口不会延长，而是从 `started_at_ms` 开始一轮全新的
    /// bounded budget；跨轮 persistent clock watermark 仍禁止回退。
    ///
    /// 调用方必须先重发旧 durable ACK，再预留 counter/seal，并通过
    /// [`Self::start_next_cycle`] 与旧 Resolved ADKS 做单次 CAS。Relay `RouteAccepted` 本身
    /// 绝不能调用这个 supersession seam。
    pub fn next_cycle_request(
        &self,
        observation: &SignedHigherRevisionObservationV1,
        started_at_ms: u64,
    ) -> Result<KeySyncRequestV1, KeySyncError> {
        self.validate()?;
        observation.validate()?;
        if self.status() != KeySyncCoordinationStatus::Resolved {
            return Err(KeySyncError::ResponseConflict);
        }
        if started_at_ms < self.last_observed_at_ms {
            return Err(KeySyncError::ClockRollback);
        }
        if observation.machine_route != self.observation.machine_route
            || observation.device_route != self.observation.device_route
            || observation.grant_serial != self.observation.grant_serial
            || observation.root_trust_epoch != self.observation.root_trust_epoch
            || observation.known_key_directory_revision != self.current_known_key_directory_revision
        {
            return Err(KeySyncError::ObservationConflict);
        }
        observation.request_for_attempt(1)
    }

    /// 构造下一轮 coordination state；重复执行上述只读验证，并拒绝复用上一轮的
    /// requestRoute。返回值仍需由 paired-state CAS 原子替换旧 Resolved ADKS。
    pub fn start_next_cycle(
        &self,
        observation: SignedHigherRevisionObservationV1,
        started_at_ms: u64,
        first: FrozenKeySyncSendV1,
    ) -> Result<Self, KeySyncError> {
        let expected = self.next_cycle_request(&observation, started_at_ms)?;
        if first.request != expected
            || self
                .attempts
                .iter()
                .any(|attempt| attempt.frozen.request_route == first.request_route)
        {
            return Err(KeySyncError::ResponseConflict);
        }
        first.validate()?;
        let retained_ack_basis = self
            .latest_completed_ack_basis()
            .ok_or(KeySyncError::InvalidCanonical)?;
        let mut next = Self::start(observation, started_at_ms, first)?;
        next.retained_ack_basis = Some(retained_ack_basis);
        next.validate()?;
        Ok(next)
    }

    /// 已 durable 安装上一轮 UpdateSet 后，按同一 observation、绝对 deadline 与总 attempt
    /// budget 生成下一条 exact-next request。返回 request 不改变状态；冻结 Send 才消费 attempt。
    pub fn next_request(&self) -> Result<KeySyncRequestV1, KeySyncError> {
        self.validate()?;
        match self.status() {
            KeySyncCoordinationStatus::AwaitingProbe => {}
            KeySyncCoordinationStatus::Exhausted => return Err(KeySyncError::Exhausted),
            KeySyncCoordinationStatus::Active | KeySyncCoordinationStatus::Resolved => {
                return Err(KeySyncError::ResponseConflict);
            }
        }
        let attempt = u8::try_from(self.attempts.len() + 1).map_err(|_| KeySyncError::Exhausted)?;
        build_request(
            &self.observation,
            self.current_known_key_directory_revision,
            attempt,
        )
    }

    /// AwaitingProbe 冷恢复的只读 preflight；deadline/clock 失败必须发生在新的
    /// CounterGuard reservation、seal 与 paired-state CAS 之前。
    pub(crate) fn next_request_at(&self, now_ms: u64) -> Result<KeySyncRequestV1, KeySyncError> {
        self.validate()?;
        self.check_time(now_ms)?;
        self.next_request()
    }

    /// 在安装事务已把 continuation state 持久化后，用新 active DeviceCommandTx capability
    /// 冻结下一次 Send；started/deadline、observation 与历史 attempt 均保持不变。
    pub fn freeze_next_probe(
        &mut self,
        now_ms: u64,
        next: FrozenKeySyncSendV1,
    ) -> Result<&FrozenKeySyncSendV1, KeySyncError> {
        self.validate()?;
        self.check_time(now_ms)?;
        let expected = self.next_request()?;
        if next.request != expected
            || self
                .attempts
                .iter()
                .any(|attempt| attempt.frozen.request_route == next.request_route)
        {
            return Err(KeySyncError::ResponseConflict);
        }
        next.validate()?;
        self.attempts.push(KeySyncAttemptRecord {
            started_at_ms: now_ms,
            frozen: next,
        });
        self.last_observed_at_ms = now_ms;
        self.validate()?;
        self.active_send().ok_or(KeySyncError::InvalidCanonical)
    }

    /// consumed state 只产生一个 terminal handoff；上层必须继续完成 update signature/HPKE
    /// 安装与 durable commit。本方法不把 Relay `RouteAccepted` 当作 terminal。
    pub fn into_update_set_handoff(
        self,
        now_ms: u64,
        reply_request_route: RequestRouteId,
        update_set: KeyUpdateSetV1,
    ) -> Result<KeySyncUpdateSetHandoff, KeySyncError> {
        self.validate()?;
        self.check_time(now_ms)?;
        if self.status() != KeySyncCoordinationStatus::Active {
            return Err(KeySyncError::ResponseConflict);
        }
        let active = self.active_send().ok_or(KeySyncError::InvalidCanonical)?;
        if reply_request_route != active.request_route
            || update_set.validate().is_err()
            || update_set.device_route != self.observation.device_route
            || update_set.key_directory_revision != active.request.requested_key_directory_revision
        {
            return Err(KeySyncError::ResponseConflict);
        }
        let update_set_canonical = update_set
            .canonical_bytes()
            .map_err(|_| KeySyncError::ResponseConflict)?;
        let update_set_sha256 = sha256(&update_set_canonical);
        let terminal = self
            .attempts
            .last()
            .ok_or(KeySyncError::InvalidCanonical)?
            .frozen
            .clone();
        Ok(KeySyncUpdateSetHandoff {
            completed_at_ms: now_ms,
            requested_key_directory_revision: terminal.request.requested_key_directory_revision,
            state: self,
            terminal,
            update_set,
            update_set_canonical,
            update_set_sha256,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KeySyncError> {
        self.validate()?;
        let mut body = Vec::with_capacity(512 + self.attempts.len() * 1024);
        encode_observation(&mut body, &self.observation);
        body.extend_from_slice(&self.started_at_ms.to_be_bytes());
        body.extend_from_slice(&self.deadline_at_ms.to_be_bytes());
        body.extend_from_slice(&self.last_observed_at_ms.to_be_bytes());
        body.extend_from_slice(
            &self
                .current_known_key_directory_revision
                .value()
                .to_be_bytes(),
        );
        body.push(u8::try_from(self.attempts.len()).map_err(|_| KeySyncError::InvalidCanonical)?);
        body.push(
            u8::try_from(self.completed_updates.len())
                .map_err(|_| KeySyncError::InvalidCanonical)?,
        );
        for completed in &self.completed_updates {
            body.push(completed.attempt);
            body.extend_from_slice(&completed.installed_at_ms.to_be_bytes());
            body.extend_from_slice(&completed.key_directory_revision.value().to_be_bytes());
            body.extend_from_slice(&completed.update_set_sha256);
        }
        for attempt in &self.attempts {
            body.extend_from_slice(&attempt.started_at_ms.to_be_bytes());
            let request = attempt
                .frozen
                .request
                .canonical_bytes()
                .map_err(|_| KeySyncError::InvalidCanonical)?;
            put_bytes(&mut body, &request)?;
            body.extend_from_slice(&attempt.frozen.request_sha256);
            put_bytes(&mut body, &attempt.frozen.exact_send)?;
            body.extend_from_slice(&attempt.frozen.exact_send_sha256);
        }
        if let Some(retained) = self.retained_ack_basis {
            body.extend_from_slice(RETAINED_ACK_EXTENSION_MAGIC);
            body.push(retained.attempt);
            body.extend_from_slice(retained.source_request_route.as_bytes());
            body.extend_from_slice(&retained.key_directory_revision.value().to_be_bytes());
            body.extend_from_slice(&retained.update_set_sha256);
        }
        if body.len() > MAX_DURABLE_KEY_SYNC_STATE_BYTES - KEY_SYNC_STATE_HEADER_LEN {
            return Err(KeySyncError::TooLarge);
        }
        let body_len = u32::try_from(body.len()).map_err(|_| KeySyncError::TooLarge)?;
        let mut encoded = Vec::with_capacity(KEY_SYNC_STATE_HEADER_LEN + body.len());
        encoded.extend_from_slice(KEY_SYNC_STATE_MAGIC);
        encoded.extend_from_slice(&KEY_SYNC_STATE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&body_len.to_be_bytes());
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, KeySyncError> {
        if bytes.len() > MAX_DURABLE_KEY_SYNC_STATE_BYTES {
            return Err(KeySyncError::TooLarge);
        }
        if bytes.len() < KEY_SYNC_STATE_HEADER_LEN
            || &bytes[..4] != KEY_SYNC_STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != KEY_SYNC_STATE_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(KeySyncError::InvalidCanonical);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| KeySyncError::InvalidCanonical)?,
        ) as usize;
        if declared != bytes.len() - KEY_SYNC_STATE_HEADER_LEN {
            return Err(KeySyncError::InvalidCanonical);
        }
        let mut decoder = Decoder::new(&bytes[KEY_SYNC_STATE_HEADER_LEN..]);
        let observation = decode_observation(&mut decoder)?;
        let started_at_ms = decoder.u64()?;
        let deadline_at_ms = decoder.u64()?;
        let last_observed_at_ms = decoder.u64()?;
        let current_known_key_directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
        let attempt_count = usize::from(decoder.u8()?);
        if attempt_count == 0 || attempt_count > usize::from(KEY_SYNC_MAX_ATTEMPTS) {
            return Err(KeySyncError::InvalidCanonical);
        }
        let completed_count = usize::from(decoder.u8()?);
        if completed_count > attempt_count {
            return Err(KeySyncError::InvalidCanonical);
        }
        let mut completed_updates = Vec::with_capacity(completed_count);
        for _ in 0..completed_count {
            completed_updates.push(CompletedKeySyncUpdate {
                attempt: decoder.u8()?,
                installed_at_ms: decoder.u64()?,
                key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
                update_set_sha256: decoder.fixed()?,
            });
        }
        let mut attempts = Vec::with_capacity(attempt_count);
        for _ in 0..attempt_count {
            let attempt_started_at_ms = decoder.u64()?;
            let request_bytes = decoder.bytes(MAX_KEY_SYNC_REQUEST_BYTES)?;
            let request_sha256 = decoder.fixed()?;
            let request = KeySyncRequestV1::from_canonical_bytes(request_bytes)
                .map_err(|_| KeySyncError::InvalidCanonical)?;
            if request
                .canonical_bytes()
                .map_err(|_| KeySyncError::InvalidCanonical)?
                != request_bytes
                || sha256(request_bytes) != request_sha256
            {
                return Err(KeySyncError::InvalidCanonical);
            }
            let exact_send = decoder.bytes(KEY_SYNC_MAX_SEND_BYTES)?.to_vec();
            let exact_send_sha256: [u8; 32] = decoder.fixed()?;
            let frozen = FrozenKeySyncSendV1::new(request, exact_send)?;
            if frozen.request_sha256 != request_sha256
                || frozen.exact_send_sha256 != exact_send_sha256
            {
                return Err(KeySyncError::InvalidCanonical);
            }
            attempts.push(KeySyncAttemptRecord {
                started_at_ms: attempt_started_at_ms,
                frozen,
            });
        }
        let retained_ack_basis = if decoder.remaining() == 0 {
            None
        } else {
            if decoder.fixed::<4>()? != *RETAINED_ACK_EXTENSION_MAGIC {
                return Err(KeySyncError::InvalidCanonical);
            }
            Some(KeyUpdateAckBasisV1 {
                attempt: decoder.u8()?,
                source_request_route: RequestRouteId::from_bytes(decoder.fixed()?),
                key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
                update_set_sha256: decoder.fixed()?,
            })
        };
        decoder.finish()?;
        let value = Self {
            observation,
            started_at_ms,
            deadline_at_ms,
            last_observed_at_ms,
            current_known_key_directory_revision,
            attempts,
            completed_updates,
            retained_ack_basis,
        };
        value.validate()?;
        if value.canonical_bytes()? != bytes {
            return Err(KeySyncError::InvalidCanonical);
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), KeySyncError> {
        self.observation.validate()?;
        if self.deadline_at_ms
            != self
                .started_at_ms
                .checked_add(KEY_SYNC_WINDOW_MS)
                .ok_or(KeySyncError::InvalidCanonical)?
            || self.last_observed_at_ms < self.started_at_ms
            || self.last_observed_at_ms >= self.deadline_at_ms
            || self.attempts.is_empty()
            || self.attempts.len() > usize::from(KEY_SYNC_MAX_ATTEMPTS)
            || self.completed_updates.len() > self.attempts.len()
            || self.current_known_key_directory_revision.value()
                < self.observation.known_key_directory_revision.value()
            || self.current_known_key_directory_revision.value()
                > self.observation.observed_key_directory_revision.value()
        {
            return Err(KeySyncError::InvalidCanonical);
        }
        if let Some(retained) = self.retained_ack_basis
            && (!self.completed_updates.is_empty()
                || self.status() != KeySyncCoordinationStatus::Active
                || retained.attempt == 0
                || retained.attempt > KEY_SYNC_MAX_ATTEMPTS
                || is_zero(retained.source_request_route.as_bytes())
                || retained.key_directory_revision != self.observation.known_key_directory_revision
                || retained.key_directory_revision != self.current_known_key_directory_revision
                || is_zero(&retained.update_set_sha256))
        {
            return Err(KeySyncError::InvalidCanonical);
        }

        let mut previous_completed_attempt = 0_u8;
        for completed in &self.completed_updates {
            if completed.attempt == 0
                || usize::from(completed.attempt) > self.attempts.len()
                || completed.attempt <= previous_completed_attempt
                || is_zero(&completed.update_set_sha256)
            {
                return Err(KeySyncError::InvalidCanonical);
            }
            previous_completed_attempt = completed.attempt;
        }

        let mut known_revision = self.observation.known_key_directory_revision;
        let mut completed_index = 0_usize;
        let mut last_event_at_ms = self.started_at_ms;
        let mut routes = HashSet::with_capacity(self.attempts.len() + 1);
        if let Some(retained) = self.retained_ack_basis {
            routes.insert(*retained.source_request_route.as_bytes());
        }
        for (index, attempt) in self.attempts.iter().enumerate() {
            let attempt_number =
                u8::try_from(index + 1).map_err(|_| KeySyncError::InvalidCanonical)?;
            if attempt.started_at_ms < self.started_at_ms
                || attempt.started_at_ms >= self.deadline_at_ms
                || attempt.started_at_ms > self.last_observed_at_ms
                || attempt.started_at_ms < last_event_at_ms
                || attempt.frozen.request
                    != build_request(&self.observation, known_revision, attempt_number)?
                || !routes.insert(*attempt.frozen.request_route.as_bytes())
            {
                return Err(KeySyncError::InvalidCanonical);
            }
            attempt.frozen.validate()?;
            last_event_at_ms = attempt.started_at_ms;

            let Some(completed) = self.completed_updates.get(completed_index) else {
                continue;
            };
            if completed.attempt < attempt_number {
                return Err(KeySyncError::InvalidCanonical);
            }
            if completed.attempt == attempt_number {
                if completed.installed_at_ms < last_event_at_ms
                    || completed.installed_at_ms >= self.deadline_at_ms
                    || completed.installed_at_ms > self.last_observed_at_ms
                    || completed.key_directory_revision
                        != attempt.frozen.request.requested_key_directory_revision
                {
                    return Err(KeySyncError::InvalidCanonical);
                }
                known_revision = completed.key_directory_revision;
                last_event_at_ms = completed.installed_at_ms;
                completed_index += 1;
            }
        }
        if self
            .attempts
            .first()
            .is_none_or(|attempt| attempt.started_at_ms != self.started_at_ms)
            || completed_index != self.completed_updates.len()
            || known_revision != self.current_known_key_directory_revision
        {
            return Err(KeySyncError::InvalidCanonical);
        }
        Ok(())
    }

    fn check_time(&self, now_ms: u64) -> Result<(), KeySyncError> {
        if now_ms < self.last_observed_at_ms {
            return Err(KeySyncError::ClockRollback);
        }
        if now_ms >= self.deadline_at_ms {
            return Err(KeySyncError::Exhausted);
        }
        Ok(())
    }

    #[must_use]
    pub const fn observation(&self) -> &SignedHigherRevisionObservationV1 {
        &self.observation
    }

    #[must_use]
    pub const fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    #[must_use]
    pub const fn deadline_at_ms(&self) -> u64 {
        self.deadline_at_ms
    }

    #[must_use]
    pub const fn last_observed_at_ms(&self) -> u64 {
        self.last_observed_at_ms
    }

    #[must_use]
    pub const fn current_known_key_directory_revision(&self) -> KeyDirectoryRevision {
        self.current_known_key_directory_revision
    }

    #[must_use]
    pub fn status(&self) -> KeySyncCoordinationStatus {
        let last_attempt = u8::try_from(self.attempts.len()).unwrap_or(u8::MAX);
        let last_completed = self
            .completed_updates
            .last()
            .is_some_and(|completed| completed.attempt == last_attempt);
        if !last_completed {
            KeySyncCoordinationStatus::Active
        } else if self.current_known_key_directory_revision
            == self.observation.observed_key_directory_revision
        {
            KeySyncCoordinationStatus::Resolved
        } else if self.attempts.len() >= usize::from(KEY_SYNC_MAX_ATTEMPTS) {
            KeySyncCoordinationStatus::Exhausted
        } else {
            KeySyncCoordinationStatus::AwaitingProbe
        }
    }

    #[must_use]
    pub fn attempt(&self) -> u8 {
        self.attempts
            .last()
            .expect("validated KeySync state always has an attempt")
            .frozen
            .request
            .attempt
    }

    #[must_use]
    pub fn attempt_count(&self) -> usize {
        self.attempts.len()
    }

    /// 最近一次 durable install 的不可伪造 ACK basis。`attempt` 必须反查同一 ADKS
    /// history 中冻结的 source requestRoute；revision/hash 单独不足以证明 ACK 属于哪次
    /// authenticated KeySync Reply。
    #[must_use]
    pub fn latest_completed_ack_basis(&self) -> Option<KeyUpdateAckBasisV1> {
        let Some(completed) = self.completed_updates.last() else {
            return self.retained_ack_basis;
        };
        let attempt_index = usize::from(completed.attempt).checked_sub(1)?;
        let attempt = self.attempts.get(attempt_index)?;
        Some(KeyUpdateAckBasisV1 {
            attempt: completed.attempt,
            source_request_route: attempt.frozen.request_route,
            key_directory_revision: completed.key_directory_revision,
            update_set_sha256: completed.update_set_sha256,
        })
    }

    #[must_use]
    pub fn active_send(&self) -> Option<&FrozenKeySyncSendV1> {
        (self.status() == KeySyncCoordinationStatus::Active).then(|| {
            &self
                .attempts
                .last()
                .expect("active KeySync state always has an attempt")
                .frozen
        })
    }

    /// 冷启动或 transport ambiguity 后只读取得仍在 30 秒预算内的 frozen active Send。
    /// 不更新 `last_observed_at_ms`、不重置 deadline，也不生成新的 route/counter。
    pub(crate) fn active_retry_at(
        &self,
        now_ms: u64,
    ) -> Result<&FrozenKeySyncSendV1, KeySyncError> {
        self.validate()?;
        self.check_time(now_ms)?;
        self.active_send().ok_or(KeySyncError::InvalidCanonical)
    }
}

/// UpdateSet 验证/安装层的 terminal 输入；保留触发它的 exact request route、request hash、
/// frozen Send hash 与完整 canonical update set，不能用 transport acceptance 替代。
#[derive(Clone, Eq, PartialEq)]
pub struct KeySyncUpdateSetHandoff {
    completed_at_ms: u64,
    requested_key_directory_revision: KeyDirectoryRevision,
    state: DurableKeySyncStateV1,
    terminal: FrozenKeySyncSendV1,
    update_set: KeyUpdateSetV1,
    update_set_canonical: Vec<u8>,
    update_set_sha256: [u8; 32],
}

impl fmt::Debug for KeySyncUpdateSetHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeySyncUpdateSetHandoff([REDACTED])")
    }
}

impl KeySyncUpdateSetHandoff {
    /// 返回产生 handoff 的完整 authenticated coordination state；combined installer
    /// 必须把它与当前 durable ADKS exact 对照，不能只相信公开 revision/hash。
    #[must_use]
    pub(crate) const fn retained_state(&self) -> &DurableKeySyncStateV1 {
        &self.state
    }

    #[must_use]
    pub const fn completed_at_ms(&self) -> u64 {
        self.completed_at_ms
    }

    #[must_use]
    pub const fn retained_observation(&self) -> &SignedHigherRevisionObservationV1 {
        &self.state.observation
    }

    #[must_use]
    pub const fn started_at_ms(&self) -> u64 {
        self.state.started_at_ms
    }

    #[must_use]
    pub const fn deadline_at_ms(&self) -> u64 {
        self.state.deadline_at_ms
    }

    #[must_use]
    pub fn attempt_count(&self) -> usize {
        self.state.attempts.len()
    }

    #[must_use]
    pub const fn request_route(&self) -> RequestRouteId {
        self.terminal.request_route
    }

    #[must_use]
    pub const fn requested_key_directory_revision(&self) -> KeyDirectoryRevision {
        self.requested_key_directory_revision
    }

    #[must_use]
    pub const fn request_sha256(&self) -> [u8; 32] {
        self.terminal.request_sha256
    }

    #[must_use]
    pub const fn request(&self) -> &KeySyncRequestV1 {
        &self.terminal.request
    }

    #[must_use]
    pub fn exact_send_bytes(&self) -> &[u8] {
        &self.terminal.exact_send
    }

    #[must_use]
    pub const fn exact_send_sha256(&self) -> [u8; 32] {
        self.terminal.exact_send_sha256
    }

    #[must_use]
    pub const fn update_set(&self) -> &KeyUpdateSetV1 {
        &self.update_set
    }

    #[must_use]
    pub fn update_set_canonical_bytes(&self) -> &[u8] {
        &self.update_set_canonical
    }

    #[must_use]
    pub const fn update_set_sha256(&self) -> [u8; 32] {
        self.update_set_sha256
    }

    /// 仅在上层已把 handoff 的 exact UpdateSet durable 安装并读回同一 hash 后调用。
    /// 返回的 continuation/resolution 继承原 observation、started/deadline 与全部 attempt
    /// 历史；安装中间 revision 绝不重新 `start()` 或重置预算。
    pub fn after_durable_install(
        mut self,
        installed_at_ms: u64,
        installed_update_set_sha256: [u8; 32],
    ) -> Result<KeySyncInstallOutcome, KeySyncError> {
        self.state.validate()?;
        self.state.check_time(installed_at_ms)?;
        if installed_at_ms < self.completed_at_ms
            || installed_update_set_sha256 != self.update_set_sha256
            || self.state.status() != KeySyncCoordinationStatus::Active
            || self.state.active_send() != Some(&self.terminal)
        {
            return Err(KeySyncError::ResponseConflict);
        }
        self.state.completed_updates.push(CompletedKeySyncUpdate {
            attempt: self.terminal.request.attempt,
            installed_at_ms,
            key_directory_revision: self.requested_key_directory_revision,
            update_set_sha256: self.update_set_sha256,
        });
        // authenticated exact-next UpdateSet 证明 daemon 已处理携带 known revision 的
        // 新 KeySync request；此时旧 cycle ACK basis 才可由本次新 completion 取代。
        self.state.retained_ack_basis = None;
        self.state.current_known_key_directory_revision = self.requested_key_directory_revision;
        self.state.last_observed_at_ms = installed_at_ms;
        self.state.validate()?;
        Ok(match self.state.status() {
            KeySyncCoordinationStatus::AwaitingProbe => KeySyncInstallOutcome::Continue(self.state),
            KeySyncCoordinationStatus::Resolved => KeySyncInstallOutcome::Resolved(self.state),
            KeySyncCoordinationStatus::Exhausted => KeySyncInstallOutcome::Exhausted(self.state),
            KeySyncCoordinationStatus::Active => {
                return Err(KeySyncError::InvalidCanonical);
            }
        })
    }
}

/// 已由 ADKS completion record 与其 exact frozen attempt 共同证明的 KeyUpdateAck basis。
/// 该值不含 secret，也不冻结新的 outbound Send；重启可使用新的 requestRoute/counter 重新
/// seal 同一个 canonical ACK，但不能改变 source attempt/revision/UpdateSet hash。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KeyUpdateAckBasisV1 {
    attempt: u8,
    source_request_route: RequestRouteId,
    key_directory_revision: KeyDirectoryRevision,
    update_set_sha256: [u8; 32],
}

impl fmt::Debug for KeyUpdateAckBasisV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyUpdateAckBasisV1([REDACTED])")
    }
}

impl KeyUpdateAckBasisV1 {
    #[must_use]
    pub const fn attempt(self) -> u8 {
        self.attempt
    }

    #[must_use]
    pub const fn source_request_route(self) -> RequestRouteId {
        self.source_request_route
    }

    #[must_use]
    pub const fn key_directory_revision(self) -> KeyDirectoryRevision {
        self.key_directory_revision
    }

    #[must_use]
    pub const fn update_set_sha256(self) -> [u8; 32] {
        self.update_set_sha256
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum KeySyncInstallOutcome {
    Continue(DurableKeySyncStateV1),
    Resolved(DurableKeySyncStateV1),
    Exhausted(DurableKeySyncStateV1),
}

impl fmt::Debug for KeySyncInstallOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Continue(_) => "KeySyncInstallOutcome::Continue([REDACTED])",
            Self::Resolved(_) => "KeySyncInstallOutcome::Resolved([REDACTED])",
            Self::Exhausted(_) => "KeySyncInstallOutcome::Exhausted([REDACTED])",
        })
    }
}

impl KeySyncInstallOutcome {
    #[must_use]
    pub const fn state(&self) -> &DurableKeySyncStateV1 {
        match self {
            Self::Continue(state) | Self::Resolved(state) | Self::Exhausted(state) => state,
        }
    }

    #[must_use]
    pub fn into_state(self) -> DurableKeySyncStateV1 {
        match self {
            Self::Continue(state) | Self::Resolved(state) | Self::Exhausted(state) => state,
        }
    }

    #[must_use]
    pub const fn public_code(&self) -> Option<&'static str> {
        match self {
            Self::Exhausted(_) => Some(REMOTE_CRYPTO_KEY_EPOCH_MISSING),
            Self::Continue(_) | Self::Resolved(_) => None,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum KeySyncError {
    #[error("durable KeySync state has an invalid canonical encoding")]
    InvalidCanonical,
    #[error("durable KeySync state exceeds its hard bound")]
    TooLarge,
    #[error("a different signed higher-revision observation is already active")]
    ObservationConflict,
    #[error("authenticated KeySync response does not match the active request")]
    ResponseConflict,
    #[error("persisted KeySync clock watermark moved backwards")]
    ClockRollback,
    #[error("bounded KeySync attempt or time budget is exhausted")]
    Exhausted,
}

impl KeySyncError {
    /// 只有预算耗尽进入既有公开 failure code；其余错误只在本地 typed coordinator
    /// 内部处理，不扩展 remote wire diagnostic family。
    #[must_use]
    pub const fn public_code(&self) -> Option<&'static str> {
        match self {
            Self::Exhausted => Some(REMOTE_CRYPTO_KEY_EPOCH_MISSING),
            Self::InvalidCanonical
            | Self::TooLarge
            | Self::ObservationConflict
            | Self::ResponseConflict
            | Self::ClockRollback => None,
        }
    }
}

fn encode_observation(output: &mut Vec<u8>, value: &SignedHigherRevisionObservationV1) {
    output.extend_from_slice(value.machine_route.as_bytes());
    output.extend_from_slice(value.device_route.as_bytes());
    output.extend_from_slice(&value.grant_serial.value().to_be_bytes());
    output.extend_from_slice(&value.root_trust_epoch.value().to_be_bytes());
    output.extend_from_slice(&value.known_key_directory_revision.value().to_be_bytes());
    output.extend_from_slice(&value.observed_key_directory_revision.value().to_be_bytes());
    output.push(key_purpose_tag(value.observed_key_id.purpose));
    output.extend_from_slice(&value.observed_key_id.epoch.to_be_bytes());
    match value.key_slot_stream_route {
        None => output.push(0),
        Some(route) => {
            output.push(1);
            output.extend_from_slice(route.as_bytes());
        }
    }
    output.extend_from_slice(value.publication_stream_route.as_bytes());
    output.extend_from_slice(value.publication_stream_generation.as_bytes());
    output.extend_from_slice(&value.publication_stream_seq.to_be_bytes());
    output.extend_from_slice(&value.sender_counter.to_be_bytes());
    output.extend_from_slice(&value.signed_frame_sha256);
    output.extend_from_slice(&value.ciphertext_sha256);
}

fn decode_observation(
    decoder: &mut Decoder<'_>,
) -> Result<SignedHigherRevisionObservationV1, KeySyncError> {
    let machine_route = MachineRouteId::from_bytes(decoder.fixed()?);
    let device_route = DeviceRouteId::from_bytes(decoder.fixed()?);
    let grant_serial = GrantSerial::new(decoder.u64()?);
    let root_trust_epoch = TrustEpoch::new(decoder.u64()?);
    let known_key_directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
    let observed_key_directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
    let observed_key_id = KeyId {
        purpose: decode_key_purpose(decoder.u8()?)?,
        epoch: decoder.u64()?,
    };
    let key_slot_stream_route = match decoder.u8()? {
        0 => None,
        1 => Some(StreamRouteId::from_bytes(decoder.fixed()?)),
        _ => return Err(KeySyncError::InvalidCanonical),
    };
    let publication_stream_route = StreamRouteId::from_bytes(decoder.fixed()?);
    let publication_stream_generation = StreamGenerationId::from_bytes(decoder.fixed()?);
    let publication_stream_seq = decoder.u64()?;
    let sender_counter = decoder.u64()?;
    SignedHigherRevisionObservationV1::new(
        machine_route,
        device_route,
        grant_serial,
        root_trust_epoch,
        known_key_directory_revision,
        observed_key_directory_revision,
        observed_key_id,
        key_slot_stream_route,
        publication_stream_route,
        publication_stream_generation,
        publication_stream_seq,
        sender_counter,
        decoder.fixed()?,
        decoder.fixed()?,
    )
}

fn key_purpose_tag(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 0,
        KeyPurpose::ConversationDek => 1,
        KeyPurpose::DeviceCommandTx => 2,
        KeyPurpose::DeviceReplyTx => 3,
    }
}

fn decode_key_purpose(tag: u8) -> Result<KeyPurpose, KeySyncError> {
    match tag {
        0 => Ok(KeyPurpose::Catalog),
        1 => Ok(KeyPurpose::ConversationDek),
        2 => Ok(KeyPurpose::DeviceCommandTx),
        3 => Ok(KeyPurpose::DeviceReplyTx),
        _ => Err(KeySyncError::InvalidCanonical),
    }
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), KeySyncError> {
    let length = u32::try_from(bytes.len()).map_err(|_| KeySyncError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], KeySyncError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(KeySyncError::InvalidCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(KeySyncError::InvalidCanonical)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, KeySyncError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(KeySyncError::InvalidCanonical)
    }

    fn u32(&mut self) -> Result<u32, KeySyncError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| KeySyncError::InvalidCanonical)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, KeySyncError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| KeySyncError::InvalidCanonical)?,
        ))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], KeySyncError> {
        self.take(N)?
            .try_into()
            .map_err(|_| KeySyncError::InvalidCanonical)
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], KeySyncError> {
        let length = usize::try_from(self.u32()?).map_err(|_| KeySyncError::InvalidCanonical)?;
        if length == 0 || length > maximum {
            return Err(KeySyncError::InvalidCanonical);
        }
        self.take(length)
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    fn finish(self) -> Result<(), KeySyncError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(KeySyncError::InvalidCanonical)
        }
    }
}
