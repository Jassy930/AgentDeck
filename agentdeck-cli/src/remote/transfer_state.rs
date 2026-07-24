//! Remote live `TransferPart` 的纯 durable record codec 与状态机。
//!
//! 本模块不做 IO，也不假定 candidate records 已经持久化。调用方必须把返回的完整
//! record 集合与对应 `DurableStreamBindingV1` 在同一个 CAS 中提交，成功后才可消费
//! `Complete` payload。每个 active transfer 使用一条 header 和逐 part 独立 records；
//! active 数量、part 数量与 buffered bytes 始终从 records/parts 重算。

use std::collections::BTreeMap;

use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::StreamBindingV1;
use agentdeck_protocol::relay_v2::{StreamGenerationId, StreamRouteId};
use agentdeck_protocol::runtime::identity::{MAX_TRANSFER_ID_BYTES, MessageId, TransferId};
use agentdeck_protocol::runtime::{
    DurableStreamObjectId, DurableStreamTransferIdentity, DurableStreamTransferSource,
    MAX_ACTIVE_TRANSFERS, MAX_COMPLETED_TRANSFER_TOMBSTONES, MAX_PART_BYTES, MAX_REASSEMBLY_BYTES,
    MAX_TRANSFER_PARTS, RuntimeInnerCursor, RuntimeTransferCarrierV1, RuntimeTransferChannel,
    TRANSFER_TTL_MS,
};
use thiserror::Error;

use super::stream_state::{DurableStreamBindingV1, MAX_DURABLE_STREAM_BINDINGS};

const RECORD_MAGIC: &[u8; 4] = b"ADTF";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_BYTES: usize = 8;
/// 单条 durable record 与其中任一 length-delimited field 的硬上限。
pub const MAX_DURABLE_TRANSFER_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_ID_BYTES: usize = 1_024;
const MAX_TRANSFER_BINDING_RECORD_BYTES: usize = 1 + 16 + 32 + 16 + 16;
/// Emergency capacity reservation 使用的最坏 `NeedsBootstrap` record 大小：conversation
/// binding、存在且达到 wire 上限的 transfer id、failure tag 与两个 durable clock 字段。
/// 外层 V6 collection 的 4-byte field length 由 paired-state owner 另行计入。
pub(crate) const MAX_NEEDS_BOOTSTRAP_MARKER_RECORD_BYTES: usize = RECORD_HEADER_BYTES
    + MAX_TRANSFER_BINDING_RECORD_BYTES
    + 1
    + 4
    + MAX_TRANSFER_ID_BYTES
    + 1
    + 8
    + 8;
// Marker 是 installed exact binding 的 terminal fence，而不是 active-transfer 槽。上限必须
// 覆盖完整 durable binding collection；否则 64 个已失败 binding 会让第 65 个 binding 在
// byte headroom 仍充足时无法持久化 emergency marker。
const MAX_MARKERS: usize = MAX_DURABLE_STREAM_BINDINGS;
pub const MAX_DURABLE_TRANSFER_RECORDS: usize = MAX_ACTIVE_TRANSFERS
    * (MAX_TRANSFER_PARTS as usize + 1)
    + MAX_COMPLETED_TRANSFER_TOMBSTONES
    + MAX_MARKERS;

/// StreamBinding 的业务 target；随机 route/generation 与完整 canonical hash 另行绑定。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DurableTransferTargetV1 {
    Catalog,
    Conversation {
        conversation_id: DurableStreamObjectId,
    },
}

/// 一个 exact StreamBinding 的 durable identity。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DurableTransferBindingIdentityV1 {
    target: DurableTransferTargetV1,
    binding_sha256: [u8; 32],
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
}

impl DurableTransferBindingIdentityV1 {
    pub fn from_stream_binding(
        binding: &StreamBindingV1,
    ) -> Result<Self, DurableTransferStateError> {
        let binding_sha256 = binding
            .canonical_sha256()
            .map_err(|_| DurableTransferStateError::InvalidBinding)?;
        let target = match &binding.inner_cursor {
            RuntimeInnerCursor::Catalog { .. } => DurableTransferTargetV1::Catalog,
            RuntimeInnerCursor::Conversation {
                conversation_id, ..
            } => DurableTransferTargetV1::Conversation {
                conversation_id: DurableStreamObjectId::parse_canonical(conversation_id.as_str())
                    .map_err(|_| DurableTransferStateError::InvalidBinding)?,
            },
        };
        Ok(Self {
            target,
            binding_sha256,
            stream_route: binding.stream_route,
            stream_generation: binding.stream_generation,
        })
    }

    #[must_use]
    pub const fn target(self) -> DurableTransferTargetV1 {
        self.target
    }

    #[must_use]
    pub const fn binding_sha256(self) -> [u8; 32] {
        self.binding_sha256
    }

    #[must_use]
    pub const fn stream_route(self) -> StreamRouteId {
        self.stream_route
    }

    #[must_use]
    pub const fn stream_generation(self) -> StreamGenerationId {
        self.stream_generation
    }

    fn sort_key(self) -> BindingSortKey {
        let mut bytes = [0_u8; 81];
        match self.target {
            DurableTransferTargetV1::Catalog => bytes[0] = 0,
            DurableTransferTargetV1::Conversation { conversation_id } => {
                bytes[0] = 1;
                bytes[1..17].copy_from_slice(&conversation_id.as_bytes());
            }
        }
        bytes[17..49].copy_from_slice(&self.binding_sha256);
        bytes[49..65].copy_from_slice(self.stream_route.as_bytes());
        bytes[65..81].copy_from_slice(self.stream_generation.as_bytes());
        BindingSortKey(bytes)
    }

    fn target_key(self) -> [u8; 17] {
        let mut key = [0_u8; 17];
        match self.target {
            DurableTransferTargetV1::Catalog => key[0] = 0,
            DurableTransferTargetV1::Conversation { conversation_id } => {
                key[0] = 1;
                key[1..].copy_from_slice(&conversation_id.as_bytes());
            }
        }
        key
    }
}

/// 需要废弃当前 exact binding 并重新 bootstrap 的稳定原因。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DurableTransferBootstrapError {
    #[error("durable transfer identity is invalid")]
    InvalidIdentity,
    #[error("durable transfer carrier metadata does not match")]
    MetadataMismatch,
    #[error("durable transfer source does not match the binding target")]
    TargetMismatch,
    #[error("durable transfer belongs to a stale binding")]
    StaleBinding,
    #[error("duplicate transfer part conflicts with durable bytes")]
    ConflictingDuplicate,
    #[error("durable transfer reached its absolute TTL")]
    Expired,
    #[error("active transfer limit reached")]
    ActiveLimit,
    #[error("reassembly memory budget reached")]
    ReassemblyFull,
    #[error("assembled transfer length does not match authenticated metadata")]
    LengthMismatch,
    #[error("assembled transfer hash does not match authenticated metadata")]
    HashMismatch,
    #[error("authenticated payload was rejected by the caller")]
    PayloadRejected,
}

impl DurableTransferBootstrapError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "remote.transfer.identity_invalid",
            Self::MetadataMismatch => "remote.transfer.metadata_mismatch",
            Self::TargetMismatch => "remote.transfer.target_mismatch",
            Self::StaleBinding => "remote.transfer.stale_binding",
            Self::ConflictingDuplicate => "remote.transfer.duplicate_conflict",
            Self::Expired => "remote.transfer.expired",
            Self::ActiveLimit => "remote.transfer.active_limit",
            Self::ReassemblyFull => "remote.transfer.reassembly_full",
            Self::LengthMismatch => "remote.transfer.length_mismatch",
            Self::HashMismatch => "remote.transfer.hash_mismatch",
            Self::PayloadRejected => "remote.transfer.payload_rejected",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::InvalidIdentity => 1,
            Self::MetadataMismatch => 2,
            Self::TargetMismatch => 3,
            Self::StaleBinding => 4,
            Self::ConflictingDuplicate => 5,
            Self::Expired => 6,
            Self::ActiveLimit => 7,
            Self::ReassemblyFull => 8,
            Self::LengthMismatch => 9,
            Self::HashMismatch => 10,
            Self::PayloadRejected => 11,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, DurableTransferStateError> {
        match tag {
            1 => Ok(Self::InvalidIdentity),
            2 => Ok(Self::MetadataMismatch),
            3 => Ok(Self::TargetMismatch),
            4 => Ok(Self::StaleBinding),
            5 => Ok(Self::ConflictingDuplicate),
            6 => Ok(Self::Expired),
            7 => Ok(Self::ActiveLimit),
            8 => Ok(Self::ReassemblyFull),
            9 => Ok(Self::LengthMismatch),
            10 => Ok(Self::HashMismatch),
            11 => Ok(Self::PayloadRejected),
            _ => Err(DurableTransferStateError::InvalidRecord),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableTransferOutcomeV1 {
    Buffered {
        received_parts: u32,
        part_count: u32,
    },
    Complete {
        payload: Vec<u8>,
        source: DurableStreamTransferSource,
    },
    AlreadyComplete,
    NeedsBootstrap {
        error: DurableTransferBootstrapError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DurableTransferStateError {
    #[error("durable transfer record is invalid or non-canonical")]
    InvalidRecord,
    #[error("stream binding is invalid")]
    InvalidBinding,
    #[error("durable transfer state exceeds its hard limit")]
    TooLarge,
    #[error("durable transfer clock moved backwards")]
    ClockRollback,
    #[error("durable transfer arithmetic overflow")]
    ArithmeticOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveHeader {
    binding: DurableTransferBindingIdentityV1,
    identity: DurableStreamTransferIdentity,
    message_id: MessageId,
    channel: RuntimeTransferChannel,
    started_at_ms: u64,
    expires_at_ms: u64,
    clock_watermark_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveTransfer {
    header: ActiveHeader,
    parts: BTreeMap<u32, Vec<u8>>,
}

impl ActiveTransfer {
    fn buffered_bytes(&self) -> Result<u64, DurableTransferStateError> {
        self.parts.values().try_fold(0_u64, |total, part| {
            total
                .checked_add(
                    u64::try_from(part.len()).map_err(|_| DurableTransferStateError::TooLarge)?,
                )
                .ok_or(DurableTransferStateError::ArithmeticOverflow)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletedTransfer {
    binding: DurableTransferBindingIdentityV1,
    identity: DurableStreamTransferIdentity,
    message_id: MessageId,
    channel: RuntimeTransferChannel,
    completed_at_ms: u64,
    expires_at_ms: u64,
    clock_watermark_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NeedsBootstrapMarker {
    binding: DurableTransferBindingIdentityV1,
    transfer_id: Option<TransferId>,
    error: DurableTransferBootstrapError,
    marked_at_ms: u64,
    clock_watermark_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartRecord {
    binding: DurableTransferBindingIdentityV1,
    transfer_id: TransferId,
    part_index: u32,
    part: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecordKind {
    ActiveHeader(ActiveHeader),
    Part(PartRecord),
    Completed(CompletedTransfer),
    NeedsBootstrap(NeedsBootstrapMarker),
}

/// 可独立写入一个 field 的 strict canonical record。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableTransferRecordV1 {
    kind: RecordKind,
}

impl DurableTransferRecordV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DurableTransferStateError> {
        validate_record_kind(&self.kind)?;
        let mut encoder = RecordEncoder::new(record_tag(&self.kind));
        match &self.kind {
            RecordKind::ActiveHeader(header) => {
                encode_binding(&mut encoder, header.binding)?;
                encoder.field(header.identity.transfer_id().as_str().as_bytes())?;
                encoder.field(header.message_id.as_str().as_bytes())?;
                encoder.u8(channel_tag(header.channel));
                encoder.u64(header.started_at_ms);
                encoder.u64(header.expires_at_ms);
                encoder.u64(header.clock_watermark_ms);
            }
            RecordKind::Part(part) => {
                encode_binding(&mut encoder, part.binding)?;
                encoder.field(part.transfer_id.as_str().as_bytes())?;
                encoder.u32(part.part_index);
                encoder.field(&part.part)?;
            }
            RecordKind::Completed(completed) => {
                encode_binding(&mut encoder, completed.binding)?;
                encoder.field(completed.identity.transfer_id().as_str().as_bytes())?;
                encoder.field(completed.message_id.as_str().as_bytes())?;
                encoder.u8(channel_tag(completed.channel));
                encoder.u64(completed.completed_at_ms);
                encoder.u64(completed.expires_at_ms);
                encoder.u64(completed.clock_watermark_ms);
            }
            RecordKind::NeedsBootstrap(marker) => {
                encode_binding(&mut encoder, marker.binding)?;
                match &marker.transfer_id {
                    None => encoder.u8(0),
                    Some(transfer_id) => {
                        encoder.u8(1);
                        encoder.field(transfer_id.as_str().as_bytes())?;
                    }
                }
                encoder.u8(marker.error.tag());
                encoder.u64(marker.marked_at_ms);
                encoder.u64(marker.clock_watermark_ms);
            }
        }
        encoder.finish()
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DurableTransferStateError> {
        let mut decoder = RecordDecoder::new(bytes)?;
        let kind = match decoder.kind {
            1 => {
                let binding = decode_binding(&mut decoder)?;
                let identity = decode_identity(decoder.string(MAX_ID_BYTES)?)?;
                let message_id = decode_message_id(decoder.string(MAX_ID_BYTES)?)?;
                let channel = decode_channel(decoder.u8()?)?;
                RecordKind::ActiveHeader(ActiveHeader {
                    binding,
                    identity,
                    message_id,
                    channel,
                    started_at_ms: decoder.u64()?,
                    expires_at_ms: decoder.u64()?,
                    clock_watermark_ms: decoder.u64()?,
                })
            }
            2 => RecordKind::Part(PartRecord {
                binding: decode_binding(&mut decoder)?,
                transfer_id: decode_transfer_id(decoder.string(MAX_ID_BYTES)?)?,
                part_index: decoder.u32()?,
                part: decoder.field(MAX_PART_BYTES)?.to_vec(),
            }),
            3 => {
                let binding = decode_binding(&mut decoder)?;
                let identity = decode_identity(decoder.string(MAX_ID_BYTES)?)?;
                let message_id = decode_message_id(decoder.string(MAX_ID_BYTES)?)?;
                let channel = decode_channel(decoder.u8()?)?;
                RecordKind::Completed(CompletedTransfer {
                    binding,
                    identity,
                    message_id,
                    channel,
                    completed_at_ms: decoder.u64()?,
                    expires_at_ms: decoder.u64()?,
                    clock_watermark_ms: decoder.u64()?,
                })
            }
            4 => {
                let binding = decode_binding(&mut decoder)?;
                let transfer_id = match decoder.u8()? {
                    0 => None,
                    1 => Some(decode_transfer_id(decoder.string(MAX_ID_BYTES)?)?),
                    _ => return Err(DurableTransferStateError::InvalidRecord),
                };
                RecordKind::NeedsBootstrap(NeedsBootstrapMarker {
                    binding,
                    transfer_id,
                    error: DurableTransferBootstrapError::from_tag(decoder.u8()?)?,
                    marked_at_ms: decoder.u64()?,
                    clock_watermark_ms: decoder.u64()?,
                })
            }
            _ => return Err(DurableTransferStateError::InvalidRecord),
        };
        decoder.finish()?;
        let record = Self { kind };
        validate_record_kind(&record.kind)?;
        if record.canonical_bytes()? != bytes {
            return Err(DurableTransferStateError::InvalidRecord);
        }
        Ok(record)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct BindingSortKey([u8; 81]);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct TransferKey {
    binding: BindingSortKey,
    transfer_id: String,
}

impl TransferKey {
    fn new(binding: DurableTransferBindingIdentityV1, transfer_id: &TransferId) -> Self {
        Self {
            binding: binding.sort_key(),
            transfer_id: transfer_id.as_str().to_owned(),
        }
    }
}

/// 从逐条 records 恢复的纯状态；没有任何构造器执行持久写入。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableLiveTransferStateV1 {
    active: BTreeMap<TransferKey, ActiveTransfer>,
    completed: BTreeMap<TransferKey, CompletedTransfer>,
    markers: BTreeMap<BindingSortKey, NeedsBootstrapMarker>,
    buffered_bytes: u64,
    max_buffered_bytes: u64,
}

impl DurableLiveTransferStateV1 {
    #[must_use]
    pub fn empty() -> Self {
        Self::empty_with_buffer_budget(MAX_REASSEMBLY_BYTES)
            .expect("protocol reassembly limit is a valid durable budget")
    }

    /// 可选择更低但绝不能更高的预算，便于资源受限客户端与 scaled verification。
    pub fn empty_with_buffer_budget(
        max_buffered_bytes: u64,
    ) -> Result<Self, DurableTransferStateError> {
        validate_buffer_budget(max_buffered_bytes)?;
        Ok(Self {
            active: BTreeMap::new(),
            completed: BTreeMap::new(),
            markers: BTreeMap::new(),
            buffered_bytes: 0,
            max_buffered_bytes,
        })
    }

    pub fn from_record_bytes(records: &[Vec<u8>]) -> Result<Self, DurableTransferStateError> {
        Self::from_record_bytes_with_buffer_budget(records, MAX_REASSEMBLY_BYTES)
    }

    pub fn from_record_bytes_with_buffer_budget(
        records: &[Vec<u8>],
        max_buffered_bytes: u64,
    ) -> Result<Self, DurableTransferStateError> {
        validate_buffer_budget(max_buffered_bytes)?;
        if records.len() > MAX_DURABLE_TRANSFER_RECORDS {
            return Err(DurableTransferStateError::TooLarge);
        }
        let mut state = Self {
            active: BTreeMap::new(),
            completed: BTreeMap::new(),
            markers: BTreeMap::new(),
            buffered_bytes: 0,
            max_buffered_bytes,
        };
        let mut parts = Vec::new();
        for bytes in records {
            let record = DurableTransferRecordV1::from_canonical_bytes(bytes)?;
            match record.kind {
                RecordKind::ActiveHeader(header) => {
                    let key = TransferKey::new(header.binding, &header.identity.transfer_id());
                    if state
                        .active
                        .insert(
                            key,
                            ActiveTransfer {
                                header,
                                parts: BTreeMap::new(),
                            },
                        )
                        .is_some()
                    {
                        return Err(DurableTransferStateError::InvalidRecord);
                    }
                }
                RecordKind::Part(part) => parts.push(part),
                RecordKind::Completed(completed) => {
                    let key =
                        TransferKey::new(completed.binding, &completed.identity.transfer_id());
                    if state.completed.insert(key, completed).is_some() {
                        return Err(DurableTransferStateError::InvalidRecord);
                    }
                }
                RecordKind::NeedsBootstrap(marker) => {
                    if state
                        .markers
                        .insert(marker.binding.sort_key(), marker)
                        .is_some()
                    {
                        return Err(DurableTransferStateError::InvalidRecord);
                    }
                }
            }
        }
        for part in parts {
            let key = TransferKey::new(part.binding, &part.transfer_id);
            let active = state
                .active
                .get_mut(&key)
                .ok_or(DurableTransferStateError::InvalidRecord)?;
            if active.parts.insert(part.part_index, part.part).is_some() {
                return Err(DurableTransferStateError::InvalidRecord);
            }
        }
        state.recompute_and_validate()?;
        if state.canonical_record_bytes()?.as_slice() != records {
            return Err(DurableTransferStateError::InvalidRecord);
        }
        Ok(state)
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    #[must_use]
    pub fn marker_count(&self) -> usize {
        self.markers.len()
    }

    #[must_use]
    pub const fn buffered_bytes(&self) -> u64 {
        self.buffered_bytes
    }

    /// 返回最早到期的 active transfer 所属 exact binding 与绝对到期时间。
    ///
    /// 该查询不推进 durable clock，也不修改任何 record。相同到期时间按 canonical
    /// transfer key 排序，供 runtime 在没有新入站 part 时确定性地安排 TTL 唤醒。
    #[must_use]
    pub fn earliest_active_expiry(&self) -> Option<(DurableTransferBindingIdentityV1, u64)> {
        self.active
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                left.header
                    .expires_at_ms
                    .cmp(&right.header.expires_at_ms)
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(_, active)| (active.header.binding, active.header.expires_at_ms))
    }

    /// Runtime scheduler 建立 monotonic timeout 前的只读绝对时钟门禁。wall clock 若低于
    /// sealed state 的 durable watermark，必须立即 fail-close，不能用放大的 remaining
    /// 静默延长 active transfer 的 absolute TTL。
    pub(crate) fn earliest_active_expiry_at(
        &self,
        now_ms: u64,
    ) -> Result<Option<(DurableTransferBindingIdentityV1, u64)>, DurableTransferStateError> {
        self.validate_clock(now_ms)?;
        Ok(self.earliest_active_expiry())
    }

    /// 在 `now_ms` 已到达最早 active transfer 的绝对 TTL 时，确定性地废弃其 exact
    /// binding；尚未到期则原样返回。一次只处理一个 binding，runtime 可循环调用直至
    /// 返回 `None`，再把最终候选状态纳入 paired-state CAS。
    pub fn expire_due_active(
        mut self,
        now_ms: u64,
    ) -> Result<(Self, Option<DurableTransferBindingIdentityV1>), DurableTransferStateError> {
        self.validate_clock(now_ms)?;
        let expired = self.expire_next_due_active_internal(now_ms)?;
        Ok((self, expired))
    }

    /// Production runtime 的 owned expiry 路径。只有确有 active binding 到期时才生成
    /// canonical candidate records；调用方可把 transition 直接移交 paired-state prepare，
    /// 不必再次遍历或复制可能接近 128 MiB 的 transfer collection。
    pub(crate) fn expire_due_active_transition(
        mut self,
        now_ms: u64,
    ) -> Result<
        Option<(
            DurableTransferBindingIdentityV1,
            DurableTransferTransitionV1,
        )>,
        DurableTransferStateError,
    > {
        self.validate_clock(now_ms)?;
        let Some(expired) = self.expire_next_due_active_internal(now_ms)? else {
            return Ok(None);
        };
        let transition = DurableTransferTransitionV1::new(
            self,
            DurableTransferOutcomeV1::NeedsBootstrap {
                error: DurableTransferBootstrapError::Expired,
            },
        )?;
        Ok(Some((expired, transition)))
    }

    fn expire_next_due_active_internal(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<DurableTransferBindingIdentityV1>, DurableTransferStateError> {
        let earliest = self
            .active
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                left.header
                    .expires_at_ms
                    .cmp(&right.header.expires_at_ms)
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(_, active)| {
                (
                    active.header.binding,
                    active.header.identity.transfer_id(),
                    active.header.expires_at_ms,
                )
            });
        let Some((binding, transfer_id, expires_at_ms)) = earliest else {
            return Ok(None);
        };
        if now_ms < expires_at_ms {
            return Ok(None);
        }
        self.abort_binding_internal(
            binding,
            Some(transfer_id),
            DurableTransferBootstrapError::Expired,
            now_ms,
        )?;
        Ok(Some(binding))
    }

    pub fn canonical_record_bytes(&self) -> Result<Vec<Vec<u8>>, DurableTransferStateError> {
        self.validate_in_memory()?;
        self.records()
            .into_iter()
            .map(|record| record.canonical_bytes())
            .collect()
    }

    /// Cold-open 时把所有仍可继续接收的 active/NeedsBootstrap record 精确绑定到当前
    /// installed stream collection。Completed tombstone 只用于 exact duplicate 去重，可在
    /// binding replacement 后短期保留；受控 replacement 会通过
    /// [`Self::purge_exact_binding`] 一并回收。
    pub fn validate_against_bindings(
        &self,
        bindings: &[DurableStreamBindingV1],
    ) -> Result<(), DurableTransferStateError> {
        self.validate_in_memory()?;
        let mut installed = BTreeMap::new();
        for binding in bindings {
            let identity =
                DurableTransferBindingIdentityV1::from_stream_binding(binding.binding())?;
            if installed.insert(identity.sort_key(), identity).is_some() {
                return Err(DurableTransferStateError::InvalidBinding);
            }
        }
        if self
            .active
            .values()
            .map(|active| active.header.binding.sort_key())
            .chain(
                self.markers
                    .values()
                    .map(|marker| marker.binding.sort_key()),
            )
            .any(|binding| !installed.contains_key(&binding))
        {
            return Err(DurableTransferStateError::InvalidBinding);
        }
        Ok(())
    }

    pub fn accept_part(
        mut self,
        binding: &StreamBindingV1,
        carrier: RuntimeTransferCarrierV1,
        now_ms: u64,
    ) -> Result<DurableTransferTransitionV1, DurableTransferStateError> {
        self.validate_clock(now_ms)?;
        self.purge_expired_completed(now_ms);
        while self.expire_next_due_active_internal(now_ms)?.is_some() {}
        let requested_binding = DurableTransferBindingIdentityV1::from_stream_binding(binding)?;
        let requested_key = requested_binding.sort_key();
        if let Some(marker) = self.markers.get_mut(&requested_key) {
            marker.clock_watermark_ms = now_ms;
            let error = marker.error;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap { error },
            );
        }

        let identity =
            match DurableStreamTransferIdentity::parse_transfer_id(&carrier.transfer.transfer_id) {
                Ok(identity) => identity,
                Err(_) => {
                    self.abort_binding_internal(
                        requested_binding,
                        None,
                        DurableTransferBootstrapError::InvalidIdentity,
                        now_ms,
                    )?;
                    return DurableTransferTransitionV1::new(
                        self,
                        DurableTransferOutcomeV1::NeedsBootstrap {
                            error: DurableTransferBootstrapError::InvalidIdentity,
                        },
                    );
                }
            };
        if identity.validate_carrier(&carrier).is_err() {
            self.abort_binding_internal(
                requested_binding,
                Some(identity.transfer_id()),
                DurableTransferBootstrapError::MetadataMismatch,
                now_ms,
            )?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::MetadataMismatch,
                },
            );
        }
        if !binding_matches_source(requested_binding, identity.source()) {
            self.abort_binding_internal(
                requested_binding,
                Some(identity.transfer_id()),
                DurableTransferBootstrapError::TargetMismatch,
                now_ms,
            )?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::TargetMismatch,
                },
            );
        }

        let stale_bindings = self.stale_bindings_for_target(requested_binding);
        if !stale_bindings.is_empty() {
            for stale in stale_bindings {
                self.abort_binding_internal(
                    stale,
                    Some(identity.transfer_id()),
                    DurableTransferBootstrapError::StaleBinding,
                    now_ms,
                )?;
            }
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::StaleBinding,
                },
            );
        }

        let transfer_id = identity.transfer_id();
        let key = TransferKey::new(requested_binding, &transfer_id);
        if let Some(completed) = self.completed.get_mut(&key) {
            completed.clock_watermark_ms = now_ms;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::AlreadyComplete,
            );
        }

        let part_index = carrier.transfer.part_index;
        let part = carrier.transfer.part;
        if let Some(mut active) = self.active.remove(&key) {
            self.recompute_buffered()?;
            if now_ms >= active.header.expires_at_ms {
                self.abort_binding_internal(
                    requested_binding,
                    Some(transfer_id),
                    DurableTransferBootstrapError::Expired,
                    now_ms,
                )?;
                return DurableTransferTransitionV1::new(
                    self,
                    DurableTransferOutcomeV1::NeedsBootstrap {
                        error: DurableTransferBootstrapError::Expired,
                    },
                );
            }
            if let Some(existing) = active.parts.get(&part_index) {
                if existing != &part {
                    self.abort_binding_internal(
                        requested_binding,
                        Some(transfer_id),
                        DurableTransferBootstrapError::ConflictingDuplicate,
                        now_ms,
                    )?;
                    return DurableTransferTransitionV1::new(
                        self,
                        DurableTransferOutcomeV1::NeedsBootstrap {
                            error: DurableTransferBootstrapError::ConflictingDuplicate,
                        },
                    );
                }
                active.header.clock_watermark_ms = now_ms;
                let received_parts = u32::try_from(active.parts.len())
                    .map_err(|_| DurableTransferStateError::TooLarge)?;
                let part_count = identity.part_count();
                self.active.insert(key, active);
                self.recompute_buffered()?;
                return DurableTransferTransitionV1::new(
                    self,
                    DurableTransferOutcomeV1::Buffered {
                        received_parts,
                        part_count,
                    },
                );
            }
            active.parts.insert(part_index, part);
            active.header.clock_watermark_ms = now_ms;
            return self.finish_active(key, active, identity, now_ms);
        }

        if self.active.len() >= MAX_ACTIVE_TRANSFERS {
            self.abort_binding_internal(
                requested_binding,
                Some(transfer_id),
                DurableTransferBootstrapError::ActiveLimit,
                now_ms,
            )?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::ActiveLimit,
                },
            );
        }
        let expires_at_ms = now_ms
            .checked_add(TRANSFER_TTL_MS)
            .ok_or(DurableTransferStateError::ArithmeticOverflow)?;
        let mut parts = BTreeMap::new();
        parts.insert(part_index, part);
        let active = ActiveTransfer {
            header: ActiveHeader {
                binding: requested_binding,
                identity,
                message_id: identity.message_id(),
                channel: RuntimeTransferChannel::Stream,
                started_at_ms: now_ms,
                expires_at_ms,
                clock_watermark_ms: now_ms,
            },
            parts,
        };
        self.finish_active(key, active, identity, now_ms)
    }

    pub fn abort_exact_binding(
        mut self,
        binding: &StreamBindingV1,
        transfer_id: Option<&TransferId>,
        error: DurableTransferBootstrapError,
        now_ms: u64,
    ) -> Result<DurableTransferTransitionV1, DurableTransferStateError> {
        self.validate_clock(now_ms)?;
        let binding = DurableTransferBindingIdentityV1::from_stream_binding(binding)?;
        let transfer_id = match transfer_id {
            None => None,
            Some(transfer_id) => {
                let identity = DurableStreamTransferIdentity::parse_transfer_id(transfer_id)
                    .map_err(|_| DurableTransferStateError::InvalidRecord)?;
                if !binding_matches_source(binding, identity.source()) {
                    return Err(DurableTransferStateError::InvalidRecord);
                }
                Some(identity.transfer_id())
            }
        };
        self.abort_binding_internal(binding, transfer_id, error, now_ms)?;
        DurableTransferTransitionV1::new(self, DurableTransferOutcomeV1::NeedsBootstrap { error })
    }

    /// Binding replacement/teardown 的显式 exact cleanup；Completed tombstone 继续保留。
    pub fn cleanup_exact_binding(
        mut self,
        binding: &StreamBindingV1,
        now_ms: u64,
    ) -> Result<Self, DurableTransferStateError> {
        self.validate_clock(now_ms)?;
        self.purge_expired_completed(now_ms);
        let binding = DurableTransferBindingIdentityV1::from_stream_binding(binding)?;
        let key = binding.sort_key();
        self.active
            .retain(|transfer_key, _| transfer_key.binding != key);
        self.markers.remove(&key);
        for completed in self.completed.values_mut() {
            if completed.binding == binding {
                completed.clock_watermark_ms = now_ms;
            }
        }
        self.recompute_and_validate()?;
        Ok(self)
    }

    /// Binding replacement 的完整 cleanup：active、NeedsBootstrap 与 completed tombstone
    /// 必须在安装新 binding 的同一 paired-state CAS 中一起删除，旧 binding 的任何 record
    /// 都不能成为新 generation 的恢复依据。
    pub fn purge_exact_binding(
        mut self,
        binding: &StreamBindingV1,
    ) -> Result<Self, DurableTransferStateError> {
        let binding = DurableTransferBindingIdentityV1::from_stream_binding(binding)?;
        let key = binding.sort_key();
        self.active
            .retain(|transfer_key, _| transfer_key.binding != key);
        self.completed
            .retain(|transfer_key, _| transfer_key.binding != key);
        self.markers.remove(&key);
        self.recompute_and_validate()?;
        Ok(self)
    }

    fn finish_active(
        mut self,
        key: TransferKey,
        active: ActiveTransfer,
        identity: DurableStreamTransferIdentity,
        now_ms: u64,
    ) -> Result<DurableTransferTransitionV1, DurableTransferStateError> {
        let active_bytes = active.buffered_bytes()?;
        let new_buffered = self
            .buffered_bytes
            .checked_add(active_bytes)
            .ok_or(DurableTransferStateError::ArithmeticOverflow)?;
        if new_buffered > self.max_buffered_bytes {
            self.abort_binding_internal(
                active.header.binding,
                Some(identity.transfer_id()),
                DurableTransferBootstrapError::ReassemblyFull,
                now_ms,
            )?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::ReassemblyFull,
                },
            );
        }
        let received_parts =
            u32::try_from(active.parts.len()).map_err(|_| DurableTransferStateError::TooLarge)?;
        let part_count = identity.part_count();
        if received_parts < part_count {
            self.active.insert(key, active);
            self.recompute_buffered()?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::Buffered {
                    received_parts,
                    part_count,
                },
            );
        }
        if received_parts != part_count {
            self.abort_binding_internal(
                active.header.binding,
                Some(identity.transfer_id()),
                DurableTransferBootstrapError::LengthMismatch,
                now_ms,
            )?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::LengthMismatch,
                },
            );
        }
        let peak = new_buffered
            .checked_add(identity.total_bytes())
            .ok_or(DurableTransferStateError::ArithmeticOverflow)?;
        if peak > self.max_buffered_bytes {
            self.abort_binding_internal(
                active.header.binding,
                Some(identity.transfer_id()),
                DurableTransferBootstrapError::ReassemblyFull,
                now_ms,
            )?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::ReassemblyFull,
                },
            );
        }
        let capacity = usize::try_from(identity.total_bytes())
            .map_err(|_| DurableTransferStateError::TooLarge)?;
        let mut payload = Vec::with_capacity(capacity);
        for part_index in 0..part_count {
            let part = active
                .parts
                .get(&part_index)
                .ok_or(DurableTransferStateError::InvalidRecord)?;
            payload.extend_from_slice(part);
            if payload.len() > capacity {
                break;
            }
        }
        if payload.len() != capacity {
            self.abort_binding_internal(
                active.header.binding,
                Some(identity.transfer_id()),
                DurableTransferBootstrapError::LengthMismatch,
                now_ms,
            )?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::LengthMismatch,
                },
            );
        }
        if sha256(&payload) != identity.total_sha256() {
            self.abort_binding_internal(
                active.header.binding,
                Some(identity.transfer_id()),
                DurableTransferBootstrapError::HashMismatch,
                now_ms,
            )?;
            return DurableTransferTransitionV1::new(
                self,
                DurableTransferOutcomeV1::NeedsBootstrap {
                    error: DurableTransferBootstrapError::HashMismatch,
                },
            );
        }
        self.remember_completed(
            key,
            CompletedTransfer {
                binding: active.header.binding,
                identity,
                message_id: active.header.message_id,
                channel: active.header.channel,
                completed_at_ms: now_ms,
                expires_at_ms: now_ms
                    .checked_add(TRANSFER_TTL_MS)
                    .ok_or(DurableTransferStateError::ArithmeticOverflow)?,
                clock_watermark_ms: now_ms,
            },
        );
        self.recompute_buffered()?;
        DurableTransferTransitionV1::new(
            self,
            DurableTransferOutcomeV1::Complete {
                payload,
                source: identity.source(),
            },
        )
    }

    fn remember_completed(&mut self, key: TransferKey, completed: CompletedTransfer) {
        if self.completed.len() == MAX_COMPLETED_TRANSFER_TOMBSTONES {
            let oldest = self
                .completed
                .iter()
                .min_by(|left, right| {
                    left.1
                        .completed_at_ms
                        .cmp(&right.1.completed_at_ms)
                        .then_with(|| left.0.cmp(right.0))
                })
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.completed.remove(&oldest);
            }
        }
        self.completed.insert(key, completed);
    }

    fn purge_expired_completed(&mut self, now_ms: u64) {
        self.completed
            .retain(|_, completed| now_ms < completed.expires_at_ms);
    }

    fn stale_bindings_for_target(
        &self,
        requested: DurableTransferBindingIdentityV1,
    ) -> Vec<DurableTransferBindingIdentityV1> {
        let target = requested.target_key();
        let mut stale = BTreeMap::<BindingSortKey, DurableTransferBindingIdentityV1>::new();
        for active in self.active.values() {
            let binding = active.header.binding;
            if binding != requested && binding.target_key() == target {
                stale.insert(binding.sort_key(), binding);
            }
        }
        for marker in self.markers.values() {
            let binding = marker.binding;
            if binding != requested && binding.target_key() == target {
                stale.insert(binding.sort_key(), binding);
            }
        }
        stale.into_values().collect()
    }

    fn abort_binding_internal(
        &mut self,
        binding: DurableTransferBindingIdentityV1,
        transfer_id: Option<TransferId>,
        error: DurableTransferBootstrapError,
        now_ms: u64,
    ) -> Result<(), DurableTransferStateError> {
        let binding_key = binding.sort_key();
        self.active.retain(|key, _| key.binding != binding_key);
        if !self.markers.contains_key(&binding_key) && self.markers.len() >= MAX_MARKERS {
            return Err(DurableTransferStateError::TooLarge);
        }
        self.markers.insert(
            binding_key,
            NeedsBootstrapMarker {
                binding,
                transfer_id,
                error,
                marked_at_ms: now_ms,
                clock_watermark_ms: now_ms,
            },
        );
        self.recompute_buffered()?;
        Ok(())
    }

    fn records(&self) -> Vec<DurableTransferRecordV1> {
        let mut records = Vec::new();
        for active in self.active.values() {
            records.push(DurableTransferRecordV1 {
                kind: RecordKind::ActiveHeader(active.header.clone()),
            });
            let transfer_id = active.header.identity.transfer_id();
            for (part_index, part) in &active.parts {
                records.push(DurableTransferRecordV1 {
                    kind: RecordKind::Part(PartRecord {
                        binding: active.header.binding,
                        transfer_id: transfer_id.clone(),
                        part_index: *part_index,
                        part: part.clone(),
                    }),
                });
            }
        }
        records.extend(
            self.completed
                .values()
                .cloned()
                .map(|completed| DurableTransferRecordV1 {
                    kind: RecordKind::Completed(completed),
                }),
        );
        records.extend(
            self.markers
                .values()
                .cloned()
                .map(|marker| DurableTransferRecordV1 {
                    kind: RecordKind::NeedsBootstrap(marker),
                }),
        );
        records
    }

    fn validate_clock(&self, now_ms: u64) -> Result<(), DurableTransferStateError> {
        if now_ms < self.clock_watermark_ms() {
            Err(DurableTransferStateError::ClockRollback)
        } else {
            Ok(())
        }
    }

    fn clock_watermark_ms(&self) -> u64 {
        self.active
            .values()
            .map(|active| active.header.clock_watermark_ms)
            .chain(
                self.completed
                    .values()
                    .map(|completed| completed.clock_watermark_ms),
            )
            .chain(
                self.markers
                    .values()
                    .map(|marker| marker.clock_watermark_ms),
            )
            .max()
            .unwrap_or(0)
    }

    fn recompute_buffered(&mut self) -> Result<(), DurableTransferStateError> {
        self.buffered_bytes = self.active.values().try_fold(0_u64, |total, active| {
            total
                .checked_add(active.buffered_bytes()?)
                .ok_or(DurableTransferStateError::ArithmeticOverflow)
        })?;
        if self.buffered_bytes > self.max_buffered_bytes {
            return Err(DurableTransferStateError::TooLarge);
        }
        Ok(())
    }

    fn recompute_and_validate(&mut self) -> Result<(), DurableTransferStateError> {
        self.recompute_buffered()?;
        self.validate_in_memory()
    }

    fn validate_in_memory(&self) -> Result<(), DurableTransferStateError> {
        validate_buffer_budget(self.max_buffered_bytes)?;
        if self.active.len() > MAX_ACTIVE_TRANSFERS
            || self.completed.len() > MAX_COMPLETED_TRANSFER_TOMBSTONES
            || self.markers.len() > MAX_MARKERS
        {
            return Err(DurableTransferStateError::TooLarge);
        }
        let mut recomputed = 0_u64;
        for (key, active) in &self.active {
            validate_active(active)?;
            if *key
                != TransferKey::new(active.header.binding, &active.header.identity.transfer_id())
                || self.completed.contains_key(key)
                || self.markers.contains_key(&active.header.binding.sort_key())
            {
                return Err(DurableTransferStateError::InvalidRecord);
            }
            recomputed = recomputed
                .checked_add(active.buffered_bytes()?)
                .ok_or(DurableTransferStateError::ArithmeticOverflow)?;
        }
        for (key, completed) in &self.completed {
            validate_completed(completed)?;
            if *key != TransferKey::new(completed.binding, &completed.identity.transfer_id()) {
                return Err(DurableTransferStateError::InvalidRecord);
            }
        }
        for (key, marker) in &self.markers {
            validate_marker(marker)?;
            if *key != marker.binding.sort_key() {
                return Err(DurableTransferStateError::InvalidRecord);
            }
        }
        if recomputed != self.buffered_bytes || recomputed > self.max_buffered_bytes {
            return Err(DurableTransferStateError::InvalidRecord);
        }
        Ok(())
    }
}

/// 已完成完整 V6 state audit 后的 marker-only 快查。非 marker record 不解码 part bytes，
/// 避免 exact-binding ingress fence 为一次只读判断复制接近 128 MiB 的 durable collection。
/// 任一 marker 仍走完整 canonical decoder；重复 exact marker fail-close。
pub(crate) fn bootstrap_error_for_exact_binding_records(
    records: &[Vec<u8>],
    binding: &StreamBindingV1,
) -> Result<Option<DurableTransferBootstrapError>, DurableTransferStateError> {
    let requested = DurableTransferBindingIdentityV1::from_stream_binding(binding)?;
    let requested_key = requested.sort_key();
    let mut found = None;
    for bytes in records {
        if audited_record_kind_tag(bytes)? != 4 {
            continue;
        }
        let record = DurableTransferRecordV1::from_canonical_bytes(bytes)?;
        let RecordKind::NeedsBootstrap(marker) = record.kind else {
            return Err(DurableTransferStateError::InvalidRecord);
        };
        if marker.binding.sort_key() == requested_key && found.replace(marker.error).is_some() {
            return Err(DurableTransferStateError::InvalidRecord);
        }
    }
    Ok(found)
}

/// 普通 production V6 candidate 必须同时为一个 transfer record 与一个 marker 留槽。
/// 使用 checked cardinality，而不是假定 byte headroom 能覆盖 collection/count hard cap。
pub(crate) fn has_emergency_marker_cardinality_reserve(
    records: &[Vec<u8>],
) -> Result<bool, DurableTransferStateError> {
    let marker_count = bootstrap_marker_count_records(records)?;
    let record_with_reserve = records
        .len()
        .checked_add(1)
        .is_some_and(|count| count <= MAX_DURABLE_TRANSFER_RECORDS);
    let marker_with_reserve = marker_count
        .checked_add(1)
        .is_some_and(|count| count <= MAX_MARKERS);
    Ok(record_with_reserve && marker_with_reserve)
}

pub(crate) fn bootstrap_marker_count_records(
    records: &[Vec<u8>],
) -> Result<usize, DurableTransferStateError> {
    let mut marker_count = 0_usize;
    for bytes in records {
        if audited_record_kind_tag(bytes)? == 4 {
            marker_count = marker_count
                .checked_add(1)
                .ok_or(DurableTransferStateError::ArithmeticOverflow)?;
        }
    }
    Ok(marker_count)
}

/// 返回 paired-state 可从 emergency reserve 精确抵扣的 marker bytes。只有完整通过
/// canonical decoder 的 `NeedsBootstrap` record 才获得 credit；外层 V6 collection 的
/// 4-byte field framing 与 record 实际长度一并 checked-sum，短 marker 不获得最坏长度额度。
pub(crate) fn bootstrap_marker_credit_bytes_records(
    records: &[Vec<u8>],
) -> Result<usize, DurableTransferStateError> {
    let mut credit = 0_usize;
    for bytes in records {
        if audited_record_kind_tag(bytes)? != 4 {
            continue;
        }
        let record = DurableTransferRecordV1::from_canonical_bytes(bytes)?;
        if !matches!(record.kind, RecordKind::NeedsBootstrap(_)) {
            return Err(DurableTransferStateError::InvalidRecord);
        }
        credit = credit
            .checked_add(4)
            .and_then(|value| value.checked_add(bytes.len()))
            .ok_or(DurableTransferStateError::ArithmeticOverflow)?;
    }
    Ok(credit)
}

fn audited_record_kind_tag(bytes: &[u8]) -> Result<u8, DurableTransferStateError> {
    let kind = RecordDecoder::new(bytes)?.kind;
    if !(1..=4).contains(&kind) {
        return Err(DurableTransferStateError::InvalidRecord);
    }
    Ok(kind)
}

impl Default for DurableLiveTransferStateV1 {
    fn default() -> Self {
        Self::empty()
    }
}

/// 尚未持久化的完整 candidate record 集合与对应逻辑结果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableTransferTransitionV1 {
    state: DurableLiveTransferStateV1,
    record_bytes: Vec<Vec<u8>>,
    outcome: DurableTransferOutcomeV1,
}

impl DurableTransferTransitionV1 {
    fn new(
        state: DurableLiveTransferStateV1,
        outcome: DurableTransferOutcomeV1,
    ) -> Result<Self, DurableTransferStateError> {
        let record_bytes = state.canonical_record_bytes()?;
        Ok(Self {
            state,
            record_bytes,
            outcome,
        })
    }

    /// 仅供 paired-machine automatic harness 把已构造的 replacement state 送入同一条
    /// production owned prepare/commit 路径；production runtime 只能使用状态机 mutation
    /// 返回的 transition。
    pub(crate) fn from_automatic_harness_state(
        state: DurableLiveTransferStateV1,
    ) -> Result<Self, DurableTransferStateError> {
        Self::new(state, DurableTransferOutcomeV1::AlreadyComplete)
    }

    #[must_use]
    pub const fn state(&self) -> &DurableLiveTransferStateV1 {
        &self.state
    }

    #[must_use]
    pub fn record_bytes(&self) -> &[Vec<u8>] {
        &self.record_bytes
    }

    #[must_use]
    pub const fn outcome(&self) -> &DurableTransferOutcomeV1 {
        &self.outcome
    }

    pub(crate) fn take_outcome(&mut self) -> DurableTransferOutcomeV1 {
        std::mem::replace(&mut self.outcome, DurableTransferOutcomeV1::AlreadyComplete)
    }

    #[must_use]
    pub fn into_state(self) -> DurableLiveTransferStateV1 {
        self.state
    }

    #[must_use]
    pub(crate) fn into_prepared_parts(
        self,
    ) -> (
        DurableLiveTransferStateV1,
        Vec<Vec<u8>>,
        DurableTransferOutcomeV1,
    ) {
        (self.state, self.record_bytes, self.outcome)
    }
}

fn validate_buffer_budget(max_buffered_bytes: u64) -> Result<(), DurableTransferStateError> {
    if max_buffered_bytes == 0 || max_buffered_bytes > MAX_REASSEMBLY_BYTES {
        Err(DurableTransferStateError::TooLarge)
    } else {
        Ok(())
    }
}

fn validate_active(active: &ActiveTransfer) -> Result<(), DurableTransferStateError> {
    validate_header(&active.header)?;
    let part_count = active.header.identity.part_count();
    if active.parts.is_empty() || active.parts.len() >= part_count as usize {
        return Err(DurableTransferStateError::InvalidRecord);
    }
    let mut total = 0_u64;
    for (part_index, part) in &active.parts {
        if *part_index >= part_count || part.len() > MAX_PART_BYTES {
            return Err(DurableTransferStateError::InvalidRecord);
        }
        total = total
            .checked_add(
                u64::try_from(part.len()).map_err(|_| DurableTransferStateError::TooLarge)?,
            )
            .ok_or(DurableTransferStateError::ArithmeticOverflow)?;
    }
    if total > active.header.identity.total_bytes() {
        return Err(DurableTransferStateError::InvalidRecord);
    }
    Ok(())
}

fn validate_header(header: &ActiveHeader) -> Result<(), DurableTransferStateError> {
    if header.message_id != header.identity.message_id()
        || header.channel != RuntimeTransferChannel::Stream
        || !binding_matches_source(header.binding, header.identity.source())
        || header.expires_at_ms
            != header
                .started_at_ms
                .checked_add(TRANSFER_TTL_MS)
                .ok_or(DurableTransferStateError::ArithmeticOverflow)?
        || header.clock_watermark_ms < header.started_at_ms
        || header.clock_watermark_ms >= header.expires_at_ms
    {
        return Err(DurableTransferStateError::InvalidRecord);
    }
    Ok(())
}

fn validate_completed(completed: &CompletedTransfer) -> Result<(), DurableTransferStateError> {
    if completed.message_id != completed.identity.message_id()
        || completed.channel != RuntimeTransferChannel::Stream
        || !binding_matches_source(completed.binding, completed.identity.source())
        || completed.expires_at_ms
            != completed
                .completed_at_ms
                .checked_add(TRANSFER_TTL_MS)
                .ok_or(DurableTransferStateError::ArithmeticOverflow)?
        || completed.clock_watermark_ms < completed.completed_at_ms
        || completed.clock_watermark_ms >= completed.expires_at_ms
    {
        return Err(DurableTransferStateError::InvalidRecord);
    }
    Ok(())
}

fn validate_marker(marker: &NeedsBootstrapMarker) -> Result<(), DurableTransferStateError> {
    if marker.clock_watermark_ms < marker.marked_at_ms {
        return Err(DurableTransferStateError::InvalidRecord);
    }
    if let Some(transfer_id) = &marker.transfer_id {
        DurableStreamTransferIdentity::parse_transfer_id(transfer_id)
            .map_err(|_| DurableTransferStateError::InvalidRecord)?;
    }
    Ok(())
}

fn validate_record_kind(kind: &RecordKind) -> Result<(), DurableTransferStateError> {
    match kind {
        RecordKind::ActiveHeader(header) => validate_header(header),
        RecordKind::Part(part) => {
            let identity = DurableStreamTransferIdentity::parse_transfer_id(&part.transfer_id)
                .map_err(|_| DurableTransferStateError::InvalidRecord)?;
            if !part.transfer_id.is_valid_wire_value()
                || part.part.len() > MAX_PART_BYTES
                || part.part_index >= identity.part_count()
                || !binding_matches_source(part.binding, identity.source())
            {
                return Err(DurableTransferStateError::InvalidRecord);
            }
            Ok(())
        }
        RecordKind::Completed(completed) => validate_completed(completed),
        RecordKind::NeedsBootstrap(marker) => validate_marker(marker),
    }
}

fn binding_matches_source(
    binding: DurableTransferBindingIdentityV1,
    source: DurableStreamTransferSource,
) -> bool {
    matches!(
        (binding.target, source),
        (
            DurableTransferTargetV1::Catalog,
            DurableStreamTransferSource::Catalog { .. }
        )
    ) || matches!(
        (binding.target, source),
        (
            DurableTransferTargetV1::Conversation { conversation_id: expected },
            DurableStreamTransferSource::Event { conversation_id, .. }
        ) if expected == conversation_id
    )
}

fn record_tag(kind: &RecordKind) -> u8 {
    match kind {
        RecordKind::ActiveHeader(_) => 1,
        RecordKind::Part(_) => 2,
        RecordKind::Completed(_) => 3,
        RecordKind::NeedsBootstrap(_) => 4,
    }
}

fn channel_tag(channel: RuntimeTransferChannel) -> u8 {
    match channel {
        RuntimeTransferChannel::Reply => 0,
        RuntimeTransferChannel::Stream => 1,
    }
}

fn decode_channel(tag: u8) -> Result<RuntimeTransferChannel, DurableTransferStateError> {
    match tag {
        1 => Ok(RuntimeTransferChannel::Stream),
        _ => Err(DurableTransferStateError::InvalidRecord),
    }
}

fn decode_identity(
    value: &str,
) -> Result<DurableStreamTransferIdentity, DurableTransferStateError> {
    DurableStreamTransferIdentity::parse_transfer_id(&TransferId::new(value))
        .map_err(|_| DurableTransferStateError::InvalidRecord)
}

fn decode_transfer_id(value: &str) -> Result<TransferId, DurableTransferStateError> {
    let transfer_id = TransferId::new(value);
    DurableStreamTransferIdentity::parse_transfer_id(&transfer_id)
        .map_err(|_| DurableTransferStateError::InvalidRecord)?;
    Ok(transfer_id)
}

fn decode_message_id(value: &str) -> Result<MessageId, DurableTransferStateError> {
    let message_id = MessageId::new(value);
    if !message_id.is_valid_wire_value() {
        return Err(DurableTransferStateError::InvalidRecord);
    }
    Ok(message_id)
}

fn encode_binding(
    encoder: &mut RecordEncoder,
    binding: DurableTransferBindingIdentityV1,
) -> Result<(), DurableTransferStateError> {
    match binding.target {
        DurableTransferTargetV1::Catalog => encoder.u8(0),
        DurableTransferTargetV1::Conversation { conversation_id } => {
            encoder.u8(1);
            encoder.fixed(&conversation_id.as_bytes());
        }
    }
    encoder.fixed(&binding.binding_sha256);
    encoder.fixed(binding.stream_route.as_bytes());
    encoder.fixed(binding.stream_generation.as_bytes());
    Ok(())
}

fn decode_binding(
    decoder: &mut RecordDecoder<'_>,
) -> Result<DurableTransferBindingIdentityV1, DurableTransferStateError> {
    let target = match decoder.u8()? {
        0 => DurableTransferTargetV1::Catalog,
        1 => DurableTransferTargetV1::Conversation {
            conversation_id: DurableStreamObjectId::from_bytes(decoder.fixed()?)
                .map_err(|_| DurableTransferStateError::InvalidRecord)?,
        },
        _ => return Err(DurableTransferStateError::InvalidRecord),
    };
    let binding_sha256 = decoder.fixed()?;
    let stream_route = StreamRouteId::from_bytes(decoder.fixed()?);
    let stream_generation = StreamGenerationId::from_bytes(decoder.fixed()?);
    if stream_route.as_bytes() == &[0; 16] || stream_generation.as_bytes() == &[0; 16] {
        return Err(DurableTransferStateError::InvalidRecord);
    }
    Ok(DurableTransferBindingIdentityV1 {
        target,
        binding_sha256,
        stream_route,
        stream_generation,
    })
}

struct RecordEncoder {
    bytes: Vec<u8>,
}

impl RecordEncoder {
    fn new(kind: u8) -> Self {
        let mut bytes = Vec::with_capacity(RECORD_HEADER_BYTES);
        bytes.extend_from_slice(RECORD_MAGIC);
        bytes.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        bytes.push(kind);
        bytes.push(0);
        Self { bytes }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn field(&mut self, value: &[u8]) -> Result<(), DurableTransferStateError> {
        if value.len() > MAX_DURABLE_TRANSFER_RECORD_BYTES {
            return Err(DurableTransferStateError::TooLarge);
        }
        let length = u32::try_from(value.len()).map_err(|_| DurableTransferStateError::TooLarge)?;
        self.u32(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, DurableTransferStateError> {
        if self.bytes.len() > MAX_DURABLE_TRANSFER_RECORD_BYTES {
            return Err(DurableTransferStateError::TooLarge);
        }
        Ok(self.bytes)
    }
}

struct RecordDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    kind: u8,
}

impl<'a> RecordDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, DurableTransferStateError> {
        if bytes.len() < RECORD_HEADER_BYTES || bytes.len() > MAX_DURABLE_TRANSFER_RECORD_BYTES {
            return Err(DurableTransferStateError::TooLarge);
        }
        if &bytes[..4] != RECORD_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != RECORD_VERSION
            || bytes[7] != 0
        {
            return Err(DurableTransferStateError::InvalidRecord);
        }
        Ok(Self {
            bytes,
            offset: RECORD_HEADER_BYTES,
            kind: bytes[6],
        })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DurableTransferStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DurableTransferStateError::ArithmeticOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DurableTransferStateError::InvalidRecord)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, DurableTransferStateError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DurableTransferStateError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DurableTransferStateError::InvalidRecord)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, DurableTransferStateError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DurableTransferStateError::InvalidRecord)?,
        ))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DurableTransferStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DurableTransferStateError::InvalidRecord)
    }

    fn field(&mut self, maximum: usize) -> Result<&'a [u8], DurableTransferStateError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| DurableTransferStateError::TooLarge)?;
        if length > maximum || length > MAX_DURABLE_TRANSFER_RECORD_BYTES {
            return Err(DurableTransferStateError::TooLarge);
        }
        self.take(length)
    }

    fn string(&mut self, maximum: usize) -> Result<&'a str, DurableTransferStateError> {
        std::str::from_utf8(self.field(maximum)?)
            .map_err(|_| DurableTransferStateError::InvalidRecord)
    }

    fn finish(self) -> Result<(), DurableTransferStateError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DurableTransferStateError::InvalidRecord)
        }
    }
}

const _: () = assert!(MAX_PART_BYTES < MAX_DURABLE_TRANSFER_RECORD_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_credit_uses_exact_canonical_record_length_and_rejects_trailing_bytes() {
        let marker = DurableTransferRecordV1 {
            kind: RecordKind::NeedsBootstrap(NeedsBootstrapMarker {
                binding: DurableTransferBindingIdentityV1 {
                    target: DurableTransferTargetV1::Catalog,
                    binding_sha256: [0x31; 32],
                    stream_route: StreamRouteId::from_bytes([0x32; 16]),
                    stream_generation: StreamGenerationId::from_bytes([0x33; 16]),
                },
                transfer_id: None,
                error: DurableTransferBootstrapError::ReassemblyFull,
                marked_at_ms: 40,
                clock_watermark_ms: 40,
            }),
        }
        .canonical_bytes()
        .unwrap();
        assert!(marker.len() < MAX_NEEDS_BOOTSTRAP_MARKER_RECORD_BYTES);
        assert_eq!(
            bootstrap_marker_credit_bytes_records(std::slice::from_ref(&marker)).unwrap(),
            4 + marker.len(),
        );

        let mut noncanonical = marker;
        noncanonical.push(0);
        assert!(matches!(
            bootstrap_marker_credit_bytes_records(&[noncanonical]),
            Err(DurableTransferStateError::InvalidRecord)
        ));
    }
}
