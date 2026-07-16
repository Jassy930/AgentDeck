//! Runtime transfer 的有界重组与原子 reducer 提交。
//! 威胁场景：故障或恶意端用冲突 part、过期 generation 或伪造 range 耗尽内存并推进未完整 payload。

use std::collections::BTreeMap;

use agentdeck_protocol::SessionCapabilities;
use agentdeck_protocol::runtime::identity::{ConversationId, StreamGeneration, TransferId};
use agentdeck_protocol::runtime::{
    BackfillChunk, BackfillRange, MAX_ACTIVE_TRANSFERS, MAX_COMPLETED_TRANSFER_TOMBSTONES,
    MAX_JSON_PART_BYTES, MAX_JSON_TRANSFER_PARTS, MAX_PART_BYTES, MAX_REASSEMBLY_BYTES,
    MAX_TRANSFER_BYTES, MAX_TRANSFER_PARTS, RuntimeTransferChannel, StreamCursor, TRANSFER_TTL_MS,
    TransferEnvelope, TransferError,
};
use sha2::{Digest, Sha256};

pub const MAX_GLOBAL_REASSEMBLY_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_GLOBAL_COMPLETED_TOMBSTONES: usize = 8_192;

/// 同一 transfer 的 wire carrier profile。JSON/UDS 受 base64 + JSONL frame
/// 上限约束；RemoteCompact 对应 ADRT1 compact-binary carrier。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferCarrierProfile {
    JsonUds,
    RemoteCompact,
}

impl TransferCarrierProfile {
    pub const fn max_part_bytes(self) -> usize {
        match self {
            Self::JsonUds => MAX_JSON_PART_BYTES,
            Self::RemoteCompact => MAX_PART_BYTES,
        }
    }

    pub const fn max_part_count(self) -> u32 {
        match self {
            Self::JsonUds => MAX_JSON_TRANSFER_PARTS,
            Self::RemoteCompact => MAX_TRANSFER_PARTS,
        }
    }

    fn validate_envelope(self, envelope: &TransferEnvelope) -> Result<(), TransferError> {
        match self {
            Self::JsonUds => envelope.validate_json_part(),
            Self::RemoteCompact => envelope.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TransferConnectionId(u64);

impl TransferConnectionId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TransferTarget {
    Catalog,
    Conversation(ConversationId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferBinding {
    Catalog {
        carrier_profile: TransferCarrierProfile,
        channel: RuntimeTransferChannel,
        stream_generation: StreamGeneration,
        range: BackfillRange,
    },
    Conversation {
        carrier_profile: TransferCarrierProfile,
        channel: RuntimeTransferChannel,
        target: ConversationId,
        stream_generation: StreamGeneration,
        range: BackfillRange,
        capabilities_sha256: [u8; 32],
    },
}

impl TransferBinding {
    fn target(&self) -> TransferTarget {
        match self {
            Self::Catalog { .. } => TransferTarget::Catalog,
            Self::Conversation { target, .. } => TransferTarget::Conversation(target.clone()),
        }
    }

    fn carrier_profile(&self) -> TransferCarrierProfile {
        match self {
            Self::Catalog {
                carrier_profile, ..
            }
            | Self::Conversation {
                carrier_profile, ..
            } => *carrier_profile,
        }
    }

    fn stream_generation(&self) -> &StreamGeneration {
        match self {
            Self::Catalog {
                stream_generation, ..
            }
            | Self::Conversation {
                stream_generation, ..
            } => stream_generation,
        }
    }

    fn range(&self) -> BackfillRange {
        match self {
            Self::Catalog { range, .. } | Self::Conversation { range, .. } => *range,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferLimits {
    pub max_active_transfers_per_connection: usize,
    pub max_reassembly_bytes_per_connection: u64,
    pub max_reassembly_bytes_global: u64,
    pub max_completed_tombstones_per_connection: usize,
    pub max_completed_tombstones_global: usize,
    pub ttl_ms: u64,
}

impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            max_active_transfers_per_connection: MAX_ACTIVE_TRANSFERS,
            max_reassembly_bytes_per_connection: MAX_REASSEMBLY_BYTES,
            max_reassembly_bytes_global: MAX_GLOBAL_REASSEMBLY_BYTES,
            max_completed_tombstones_per_connection: MAX_COMPLETED_TRANSFER_TOMBSTONES,
            max_completed_tombstones_global: MAX_GLOBAL_COMPLETED_TOMBSTONES,
            ttl_ms: TRANSFER_TTL_MS,
        }
    }
}

impl TransferLimits {
    fn validate(self) -> Result<Self, TransferStateError> {
        if self.max_active_transfers_per_connection == 0
            || self.max_active_transfers_per_connection > MAX_ACTIVE_TRANSFERS
            || self.max_reassembly_bytes_per_connection == 0
            || self.max_reassembly_bytes_per_connection > MAX_REASSEMBLY_BYTES
            || self.max_reassembly_bytes_global == 0
            || self.max_reassembly_bytes_global > MAX_GLOBAL_REASSEMBLY_BYTES
            || self.max_reassembly_bytes_per_connection > self.max_reassembly_bytes_global
            || self.max_completed_tombstones_per_connection == 0
            || self.max_completed_tombstones_per_connection > MAX_COMPLETED_TRANSFER_TOMBSTONES
            || self.max_completed_tombstones_global == 0
            || self.max_completed_tombstones_global > MAX_GLOBAL_COMPLETED_TOMBSTONES
            || self.max_completed_tombstones_per_connection > self.max_completed_tombstones_global
            || self.ttl_ms == 0
            || self.ttl_ms > TRANSFER_TTL_MS
        {
            return Err(TransferStateError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferCommit {
    InProgress {
        received_parts: u32,
        part_count: u32,
    },
    Applied {
        through: StreamCursor,
    },
    AlreadyApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferMetrics {
    pub active_transfers: usize,
    pub reassembly_bytes: u64,
    pub completed_tombstones: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransferReducerError {
    #[error("validated transfer reducer rejected the payload")]
    Rejected,
}

pub trait TransferReducer: Clone {
    fn cursor(&self, target: &TransferTarget) -> StreamCursor;
    fn apply(&mut self, payload: &BackfillChunk) -> Result<(), TransferReducerError>;
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransferStateError {
    #[error(transparent)]
    Transfer(#[from] TransferError),
    #[error("transfer connection is not registered")]
    UnknownConnection,
    #[error("transfer connection is already registered")]
    DuplicateConnection,
    #[error("transfer uses a stale subscription generation")]
    StaleGeneration,
    #[error("transfer payload is not a strict validated Runtime BackfillChunk DTO")]
    StrictDtoDecode,
    #[error("runtime transfer DTO encoding failed")]
    DtoEncode,
    #[error("transfer target, range, or capabilities binding mismatches the payload")]
    BindingMismatch,
    #[error("transfer range does not continue or finish at the reducer cursor")]
    RangeMismatch,
    #[error("validated reducer rejected the payload")]
    ReducerRejected,
    #[error("transfer clock regressed from {previous_ms} ms to {observed_ms} ms")]
    ClockRegressed { previous_ms: u64, observed_ms: u64 },
    #[error("transfer absolute expiry is outside the representable clock range")]
    TimeOutOfRange,
    #[error("transfer accounting invariant failed")]
    AccountingOverflow,
    #[error("transfer limits are invalid")]
    InvalidLimits,
}

impl From<TransferReducerError> for TransferStateError {
    fn from(_: TransferReducerError) -> Self {
        Self::ReducerRejected
    }
}

struct PartialTransfer {
    binding: TransferBinding,
    part_count: u32,
    total_bytes: u64,
    total_sha256: [u8; 32],
    expires_at_ms: u64,
    parts: BTreeMap<u32, Vec<u8>>,
    buffered_bytes: u64,
}

impl PartialTransfer {
    fn metadata_matches(&self, binding: &TransferBinding, envelope: &TransferEnvelope) -> bool {
        &self.binding == binding
            && self.part_count == envelope.part_count
            && self.total_bytes == envelope.total_bytes
            && self.total_sha256 == envelope.total_sha256
    }
}

struct CompletedTransfer {
    binding: TransferBinding,
    part_count: u32,
    total_bytes: u64,
    total_sha256: [u8; 32],
    expires_at_ms: u64,
}

impl CompletedTransfer {
    fn metadata_matches(&self, binding: &TransferBinding, envelope: &TransferEnvelope) -> bool {
        &self.binding == binding
            && self.part_count == envelope.part_count
            && self.total_bytes == envelope.total_bytes
            && self.total_sha256 == envelope.total_sha256
    }
}

struct ConnectionTransferState<R> {
    reducer: R,
    generations: BTreeMap<TransferTarget, StreamGeneration>,
    active: BTreeMap<TransferId, PartialTransfer>,
    completed: BTreeMap<TransferId, CompletedTransfer>,
    reassembly_bytes: u64,
}

impl<R> ConnectionTransferState<R> {
    fn new(reducer: R) -> Self {
        Self {
            reducer,
            generations: BTreeMap::new(),
            active: BTreeMap::new(),
            completed: BTreeMap::new(),
            reassembly_bytes: 0,
        }
    }
}

pub struct TransferStateMachine<R> {
    limits: TransferLimits,
    connections: BTreeMap<TransferConnectionId, ConnectionTransferState<R>>,
    active_transfers: usize,
    reassembly_bytes: u64,
    completed_tombstones: usize,
    last_now_ms: Option<u64>,
}

impl<R: TransferReducer> Default for TransferStateMachine<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: TransferReducer> TransferStateMachine<R> {
    pub fn new() -> Self {
        Self {
            limits: TransferLimits::default(),
            connections: BTreeMap::new(),
            active_transfers: 0,
            reassembly_bytes: 0,
            completed_tombstones: 0,
            last_now_ms: None,
        }
    }

    pub fn with_limits(limits: TransferLimits) -> Result<Self, TransferStateError> {
        Ok(Self {
            limits: limits.validate()?,
            connections: BTreeMap::new(),
            active_transfers: 0,
            reassembly_bytes: 0,
            completed_tombstones: 0,
            last_now_ms: None,
        })
    }

    pub fn connect(
        &mut self,
        connection_id: TransferConnectionId,
        reducer: R,
    ) -> Result<(), TransferStateError> {
        if self.connections.contains_key(&connection_id) {
            return Err(TransferStateError::DuplicateConnection);
        }
        self.connections
            .insert(connection_id, ConnectionTransferState::new(reducer));
        Ok(())
    }

    pub fn reducer(&self, connection_id: TransferConnectionId) -> Option<&R> {
        self.connections
            .get(&connection_id)
            .map(|connection| &connection.reducer)
    }

    pub fn metrics(&self) -> TransferMetrics {
        TransferMetrics {
            active_transfers: self.active_transfers,
            reassembly_bytes: self.reassembly_bytes,
            completed_tombstones: self.completed_tombstones,
        }
    }

    /// 无新 part 时也在 absolute TTL 边界释放 partial 与 tombstone。
    pub fn expire(&mut self, now_ms: u64) -> Result<(), TransferStateError> {
        self.observe_now(now_ms)?;
        self.purge_expired(now_ms)
    }

    pub fn set_generation(
        &mut self,
        connection_id: TransferConnectionId,
        target: TransferTarget,
        stream_generation: StreamGeneration,
    ) -> Result<(), TransferStateError> {
        let stale = {
            let connection = self
                .connections
                .get_mut(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?;
            connection
                .generations
                .insert(target.clone(), stream_generation.clone());
            connection
                .active
                .iter()
                .filter(|(_, transfer)| {
                    transfer.binding.target() == target
                        && transfer.binding.stream_generation() != &stream_generation
                })
                .map(|(transfer_id, _)| transfer_id.clone())
                .collect::<Vec<_>>()
        };
        for transfer_id in stale {
            self.abort_transfer(connection_id, &transfer_id)?;
        }
        Ok(())
    }

    pub fn disconnect(
        &mut self,
        connection_id: TransferConnectionId,
    ) -> Result<(), TransferStateError> {
        let Some(connection) = self.connections.remove(&connection_id) else {
            return Ok(());
        };
        self.reassembly_bytes = self
            .reassembly_bytes
            .checked_sub(connection.reassembly_bytes)
            .ok_or(TransferStateError::AccountingOverflow)?;
        self.active_transfers = self
            .active_transfers
            .checked_sub(connection.active.len())
            .ok_or(TransferStateError::AccountingOverflow)?;
        self.completed_tombstones = self
            .completed_tombstones
            .checked_sub(connection.completed.len())
            .ok_or(TransferStateError::AccountingOverflow)?;
        Ok(())
    }

    pub fn accept(
        &mut self,
        connection_id: TransferConnectionId,
        binding: TransferBinding,
        envelope: TransferEnvelope,
        now_ms: u64,
    ) -> Result<TransferCommit, TransferStateError> {
        if !self.connections.contains_key(&connection_id) {
            return Err(TransferStateError::UnknownConnection);
        }
        self.observe_now(now_ms)?;
        let transfer_id = envelope.transfer_id.clone();
        self.require_current_generation(connection_id, &binding)?;
        let carrier_profile = binding.carrier_profile();
        let wire_validation = carrier_profile.validate_envelope(&envelope).and_then(|()| {
            validate_declared_transfer(
                carrier_profile,
                envelope.part_count,
                envelope.total_bytes,
                envelope.part.len() as u64,
            )
        });
        if let Err(error) = wire_validation {
            self.abort_transfer(connection_id, &transfer_id)?;
            return Err(error.into());
        }

        if self.targeted_transfer_expired(connection_id, &envelope.transfer_id, now_ms)? {
            self.abort_transfer(connection_id, &envelope.transfer_id)?;
            return Err(TransferError::Expired.into());
        }
        self.purge_expired(now_ms)?;

        if let Some(completed) = self
            .connections
            .get(&connection_id)
            .ok_or(TransferStateError::UnknownConnection)?
            .completed
            .get(&envelope.transfer_id)
        {
            return if completed.metadata_matches(&binding, &envelope) {
                Ok(TransferCommit::AlreadyApplied)
            } else {
                Err(TransferError::HashMismatch.into())
            };
        }

        if let Some(existing) = self
            .connections
            .get(&connection_id)
            .ok_or(TransferStateError::UnknownConnection)?
            .active
            .get(&envelope.transfer_id)
        {
            if !existing.metadata_matches(&binding, &envelope) {
                self.abort_transfer(connection_id, &envelope.transfer_id)?;
                return Err(TransferError::HashMismatch.into());
            }
            if let Some(previous) = existing.parts.get(&envelope.part_index) {
                if previous == &envelope.part {
                    return Ok(TransferCommit::InProgress {
                        received_parts: existing.parts.len() as u32,
                        part_count: existing.part_count,
                    });
                }
                self.abort_transfer(connection_id, &envelope.transfer_id)?;
                return Err(TransferError::HashMismatch.into());
            }
        }

        let is_new = !self
            .connections
            .get(&connection_id)
            .ok_or(TransferStateError::UnknownConnection)?
            .active
            .contains_key(&envelope.transfer_id);
        let new_expires_at_ms = if is_new {
            Some(checked_deadline(now_ms, self.limits.ttl_ms)?)
        } else {
            None
        };
        if is_new
            && self
                .connections
                .get(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?
                .active
                .len()
                >= self.limits.max_active_transfers_per_connection
        {
            return Err(TransferError::ReassemblyFull.into());
        }

        let incoming_bytes = envelope.part.len() as u64;
        let connection_projected = checked_reassembly_projection(
            self.connections
                .get(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?
                .reassembly_bytes,
            incoming_bytes,
            self.limits.max_reassembly_bytes_per_connection,
        );
        let connection_projected = match connection_projected {
            Ok(projected) => projected,
            Err(error) => {
                self.abort_transfer(connection_id, &transfer_id)?;
                return Err(error.into());
            }
        };
        let global_projected = checked_reassembly_projection(
            self.reassembly_bytes,
            incoming_bytes,
            self.limits.max_reassembly_bytes_global,
        );
        let global_projected = match global_projected {
            Ok(projected) => projected,
            Err(error) => {
                self.abort_transfer(connection_id, &transfer_id)?;
                return Err(error.into());
            }
        };

        let part_index = envelope.part_index;
        let part_count = envelope.part_count;
        let total_bytes = envelope.total_bytes;
        let total_sha256 = envelope.total_sha256;
        {
            let connection = self
                .connections
                .get_mut(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?;
            if let Some(expires_at_ms) = new_expires_at_ms {
                let replaced = connection.active.insert(
                    transfer_id.clone(),
                    PartialTransfer {
                        binding,
                        part_count,
                        total_bytes,
                        total_sha256,
                        expires_at_ms,
                        parts: BTreeMap::new(),
                        buffered_bytes: 0,
                    },
                );
                debug_assert!(replaced.is_none());
            }
            let transfer = connection
                .active
                .get_mut(&transfer_id)
                .ok_or(TransferStateError::AccountingOverflow)?;
            transfer.parts.insert(part_index, envelope.part);
            transfer.buffered_bytes = transfer
                .buffered_bytes
                .checked_add(incoming_bytes)
                .ok_or(TransferStateError::AccountingOverflow)?;
            connection.reassembly_bytes = connection_projected;
        }
        self.reassembly_bytes = global_projected;
        if is_new {
            self.active_transfers = self
                .active_transfers
                .checked_add(1)
                .ok_or(TransferStateError::AccountingOverflow)?;
        }

        let (received_parts, buffered_bytes, frozen_binding) = {
            let transfer = self
                .connections
                .get(&connection_id)
                .and_then(|connection| connection.active.get(&transfer_id))
                .ok_or(TransferStateError::AccountingOverflow)?;
            (
                transfer.parts.len() as u32,
                transfer.buffered_bytes,
                transfer.binding.clone(),
            )
        };
        if received_parts != part_count {
            return Ok(TransferCommit::InProgress {
                received_parts,
                part_count,
            });
        }
        if buffered_bytes != total_bytes {
            self.abort_transfer(connection_id, &transfer_id)?;
            return Err(TransferError::HashMismatch.into());
        }

        let completed_expires_at_ms = match checked_deadline(now_ms, self.limits.ttl_ms) {
            Ok(expires_at_ms) => expires_at_ms,
            Err(error) => {
                self.abort_transfer(connection_id, &transfer_id)?;
                return Err(error);
            }
        };

        let assembly_admission = checked_reassembly_projection(
            self.connections
                .get(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?
                .reassembly_bytes,
            total_bytes,
            self.limits.max_reassembly_bytes_per_connection,
        )
        .and_then(|_| {
            checked_reassembly_projection(
                self.reassembly_bytes,
                total_bytes,
                self.limits.max_reassembly_bytes_global,
            )
        });
        if let Err(error) = assembly_admission {
            self.abort_transfer(connection_id, &transfer_id)?;
            return Err(error.into());
        }
        let assembly_capacity = match usize::try_from(total_bytes) {
            Ok(capacity) => capacity,
            Err(_) => {
                self.abort_transfer(connection_id, &transfer_id)?;
                return Err(TransferError::TooLarge.into());
            }
        };
        let mut assembled = Vec::new();
        if assembled.try_reserve_exact(assembly_capacity).is_err() {
            self.abort_transfer(connection_id, &transfer_id)?;
            return Err(TransferError::ReassemblyFull.into());
        }
        {
            let transfer = self
                .connections
                .get(&connection_id)
                .and_then(|connection| connection.active.get(&transfer_id))
                .ok_or(TransferStateError::AccountingOverflow)?;
            for part in transfer.parts.values() {
                assembled.extend_from_slice(part);
            }
        }
        self.abort_transfer(connection_id, &transfer_id)?;
        if assembled.len() as u64 != total_bytes
            || <[u8; 32]>::from(Sha256::digest(&assembled)) != total_sha256
        {
            return Err(TransferError::HashMismatch.into());
        }

        // 这里只证明 wire/profile representability 与 reassembly 算法契约：
        // totalSha256 绑定原 bytes，BackfillChunk decoder 校验语义而不要求 Swift/Rust
        // JSON 键序相同。production retained reducer budget 必须由 P4.4 Rust owner / P5.3
        // Swift assembler 接入，并在各自接入测试中证明；本期无 production owner，不能
        // 把本状态机测试冒充该内存闭环。
        let payload: BackfillChunk =
            serde_json::from_slice(&assembled).map_err(|_| TransferStateError::StrictDtoDecode)?;
        validate_payload_binding(&frozen_binding, &payload)?;
        self.require_current_generation(connection_id, &frozen_binding)?;

        let target = frozen_binding.target();
        let range = frozen_binding.range();
        {
            let connection = self
                .connections
                .get(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?;
            if connection.completed.len() >= self.limits.max_completed_tombstones_per_connection
                || self.completed_tombstones >= self.limits.max_completed_tombstones_global
            {
                return Err(TransferError::ReassemblyFull.into());
            }
        }

        let candidate = {
            let connection = self
                .connections
                .get(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?;
            if connection.reducer.cursor(&target) != range.after() {
                return Err(TransferStateError::RangeMismatch);
            }
            let mut candidate = connection.reducer.clone();
            candidate.apply(&payload)?;
            if candidate.cursor(&target) != range.through() {
                return Err(TransferStateError::RangeMismatch);
            }
            candidate
        };

        let next_tombstone_count = self
            .completed_tombstones
            .checked_add(1)
            .ok_or(TransferStateError::AccountingOverflow)?;
        let connection = self
            .connections
            .get_mut(&connection_id)
            .ok_or(TransferStateError::UnknownConnection)?;
        match connection.completed.entry(transfer_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(CompletedTransfer {
                    binding: frozen_binding,
                    part_count,
                    total_bytes,
                    total_sha256,
                    expires_at_ms: completed_expires_at_ms,
                });
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(TransferStateError::AccountingOverflow);
            }
        }
        connection.reducer = candidate;
        self.completed_tombstones = next_tombstone_count;
        Ok(TransferCommit::Applied {
            through: range.through(),
        })
    }

    fn require_current_generation(
        &self,
        connection_id: TransferConnectionId,
        binding: &TransferBinding,
    ) -> Result<(), TransferStateError> {
        let connection = self
            .connections
            .get(&connection_id)
            .ok_or(TransferStateError::UnknownConnection)?;
        match connection.generations.get(&binding.target()) {
            Some(current) if current == binding.stream_generation() => Ok(()),
            _ => Err(TransferStateError::StaleGeneration),
        }
    }

    fn targeted_transfer_expired(
        &self,
        connection_id: TransferConnectionId,
        transfer_id: &TransferId,
        now_ms: u64,
    ) -> Result<bool, TransferStateError> {
        let connection = self
            .connections
            .get(&connection_id)
            .ok_or(TransferStateError::UnknownConnection)?;
        Ok(connection
            .active
            .get(transfer_id)
            .is_some_and(|transfer| now_ms >= transfer.expires_at_ms))
    }

    fn observe_now(&mut self, now_ms: u64) -> Result<(), TransferStateError> {
        if let Some(previous_ms) = self.last_now_ms
            && now_ms < previous_ms
        {
            return Err(TransferStateError::ClockRegressed {
                previous_ms,
                observed_ms: now_ms,
            });
        }
        self.last_now_ms = Some(now_ms);
        Ok(())
    }

    fn purge_expired(&mut self, now_ms: u64) -> Result<(), TransferStateError> {
        let connection_ids = self.connections.keys().copied().collect::<Vec<_>>();
        for connection_id in connection_ids {
            let expired_active = self
                .connections
                .get(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?
                .active
                .iter()
                .filter(|(_, transfer)| now_ms >= transfer.expires_at_ms)
                .map(|(transfer_id, _)| transfer_id.clone())
                .collect::<Vec<_>>();
            for transfer_id in expired_active {
                self.abort_transfer(connection_id, &transfer_id)?;
            }

            let expired_completed = self
                .connections
                .get(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?
                .completed
                .iter()
                .filter(|(_, transfer)| now_ms >= transfer.expires_at_ms)
                .map(|(transfer_id, _)| transfer_id.clone())
                .collect::<Vec<_>>();
            for transfer_id in expired_completed {
                let removed = self
                    .connections
                    .get_mut(&connection_id)
                    .ok_or(TransferStateError::UnknownConnection)?
                    .completed
                    .remove(&transfer_id)
                    .is_some();
                if removed {
                    self.completed_tombstones = self
                        .completed_tombstones
                        .checked_sub(1)
                        .ok_or(TransferStateError::AccountingOverflow)?;
                }
            }
        }
        Ok(())
    }

    fn abort_transfer(
        &mut self,
        connection_id: TransferConnectionId,
        transfer_id: &TransferId,
    ) -> Result<(), TransferStateError> {
        let removed = self
            .connections
            .get_mut(&connection_id)
            .ok_or(TransferStateError::UnknownConnection)?
            .active
            .remove(transfer_id);
        if let Some(transfer) = removed {
            let connection = self
                .connections
                .get_mut(&connection_id)
                .ok_or(TransferStateError::UnknownConnection)?;
            connection.reassembly_bytes = connection
                .reassembly_bytes
                .checked_sub(transfer.buffered_bytes)
                .ok_or(TransferStateError::AccountingOverflow)?;
            self.reassembly_bytes = self
                .reassembly_bytes
                .checked_sub(transfer.buffered_bytes)
                .ok_or(TransferStateError::AccountingOverflow)?;
            self.active_transfers = self
                .active_transfers
                .checked_sub(1)
                .ok_or(TransferStateError::AccountingOverflow)?;
        }
        Ok(())
    }
}

pub fn validate_declared_transfer(
    carrier_profile: TransferCarrierProfile,
    part_count: u32,
    total_bytes: u64,
    part_bytes: u64,
) -> Result<(), TransferError> {
    let representable = u64::from(part_count)
        .checked_mul(carrier_profile.max_part_bytes() as u64)
        .ok_or(TransferError::TooLarge)?;
    if part_count == 0
        || part_count > carrier_profile.max_part_count()
        || total_bytes > MAX_TRANSFER_BYTES
        || total_bytes > representable
        || part_bytes > carrier_profile.max_part_bytes() as u64
        || part_bytes > total_bytes
    {
        return Err(TransferError::TooLarge);
    }
    Ok(())
}

pub fn checked_reassembly_projection(
    current: u64,
    incoming: u64,
    limit: u64,
) -> Result<u64, TransferError> {
    let projected = current
        .checked_add(incoming)
        .ok_or(TransferError::ReassemblyFull)?;
    if projected > limit {
        return Err(TransferError::ReassemblyFull);
    }
    Ok(projected)
}

fn checked_deadline(now_ms: u64, ttl_ms: u64) -> Result<u64, TransferStateError> {
    now_ms
        .checked_add(ttl_ms)
        .ok_or(TransferStateError::TimeOutOfRange)
}

pub fn capabilities_digest(
    capabilities: &SessionCapabilities,
) -> Result<[u8; 32], TransferStateError> {
    let encoded = serde_json::to_vec(capabilities).map_err(|_| TransferStateError::DtoEncode)?;
    Ok(Sha256::digest(encoded).into())
}

fn validate_payload_binding(
    binding: &TransferBinding,
    payload: &BackfillChunk,
) -> Result<(), TransferStateError> {
    match (binding, payload) {
        (
            TransferBinding::Catalog { range, .. },
            BackfillChunk::Catalog {
                range: payload_range,
                ..
            },
        ) if range == payload_range => Ok(()),
        (
            TransferBinding::Conversation {
                target,
                range,
                capabilities_sha256,
                ..
            },
            BackfillChunk::Conversation {
                conversation_id,
                capabilities_preamble,
                range: payload_range,
                ..
            },
        ) if target == conversation_id
            && range == payload_range
            && capabilities_digest(capabilities_preamble)? == *capabilities_sha256 =>
        {
            Ok(())
        }
        _ => Err(TransferStateError::BindingMismatch),
    }
}
