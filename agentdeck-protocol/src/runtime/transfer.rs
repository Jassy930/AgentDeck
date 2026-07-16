//! Runtime v2 使用的 `RuntimeTransferCarrierV1` 有界分片与重组（design §9.5）。
//!
//! `TransferEnvelope { transferId, partIndex, partCount, totalSha256, totalBytes, part }`
//! 用于 snapshot / history page / 长 tool output 等超过 Relay 单 frame 4 MiB 的 payload。
//!
//! 上界（具名常量 + 构造校验）：
//! - remote compact 每个加密前 part ≤ 3.5 MiB、≤ 64 parts；JSON/UDS 每个
//!   raw part ≤ 700 KiB、≤ 94 parts；两者的单 transfer 总量都 ≤ 64 MiB、TTL 5 分钟。
//! - partCount/totalBytes/totalSha256 在首 part 后不可变。
//! - 每 connection 同时重组内存 ≤ 128 MiB。
//! - 超限、重复 index 不同内容、hash 不符、超时 → typed error（不 panic）。
//!
//! `TransferReassembler` 是纯状态机：无 IO，时间由调用方注入（`now_ms`）。

use crate::runtime::RUNTIME_PROTOCOL_VERSION;
use crate::runtime::identity::{
    MAX_MESSAGE_ID_BYTES, MAX_TRANSFER_ID_BYTES, MessageId, TransferId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// 每个加密前 part 的最大字节数（3.5 MiB）。3.5 MiB + AEAD/outer overhead 仍落在
/// Relay 4 MiB 单 frame 硬上限内。
pub const MAX_PART_BYTES: usize = 3_670_016; // 3.5 * 1024 * 1024
/// JSON/UDS base64 carrier 的 raw part 上限（700 KiB）。它与 remote compact-binary
/// 3.5 MiB 上限分离，确保最长合法 identity/metadata 下完整 JSONL frame 仍严格小于 1 MiB。
pub const MAX_JSON_PART_BYTES: usize = 700 * 1024;
/// remote compact 单 transfer 最大 part 数。
pub const MAX_TRANSFER_PARTS: u32 = 64;
/// 单 transfer 最大总字节数（64 MiB）。
pub const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
/// JSON/UDS 表达完整 64 MiB transfer 所需的最大 part 数：
/// `ceil(64 MiB / 700 KiB) = 94`。remote compact 仍使用 64。
pub const MAX_JSON_TRANSFER_PARTS: u32 = 94;
/// 每 connection 同时重组内存上限（128 MiB）。
pub const MAX_REASSEMBLY_BYTES: u64 = 128 * 1024 * 1024;
/// transfer TTL（5 分钟，毫秒）。
pub const TRANSFER_TTL_MS: u64 = 5 * 60 * 1000;
/// 每 connection 同时 active transfer 数上限。
pub const MAX_ACTIVE_TRANSFERS: usize = 64;
/// 完成去重 tombstone 上限。
pub const MAX_COMPLETED_TRANSFER_TOMBSTONES: usize = 256;
/// Relay frame 硬上限。
pub const MAX_TRANSFER_CARRIER_BYTES: usize = 4 * 1024 * 1024;
const TRANSFER_CARRIER_MAGIC: &[u8; 5] = b"ADRT1";

/// 分片重组 typed error（映射到 `remote.transfer.*` failure codes）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    /// part/total/parts 超限，或 part_index 越界。
    #[error("transfer exceeds size bounds")]
    TooLarge,
    /// 重复 index 内容不同、首 part 后 metadata 改变、或重组后总 hash 不符。
    #[error("transfer integrity mismatch")]
    HashMismatch,
    /// transfer 超过 TTL 未完成。
    #[error("transfer expired")]
    Expired,
    /// 每 connection 重组内存超过 128 MiB 上限。
    #[error("connection reassembly buffer full")]
    ReassemblyFull,
}

/// Transfer 必须绑定最初出现的 carrier channel，防止 reply/stream 串流。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeTransferChannel {
    Reply,
    Stream,
}

impl TransferError {
    /// 稳定 failure code（design §14）。
    pub fn code(&self) -> &'static str {
        match self {
            TransferError::TooLarge => crate::runtime::failure::REMOTE_TRANSFER_TOO_LARGE,
            TransferError::HashMismatch => crate::runtime::failure::REMOTE_TRANSFER_HASH_MISMATCH,
            TransferError::Expired => crate::runtime::failure::REMOTE_TRANSFER_EXPIRED,
            TransferError::ReassemblyFull => {
                crate::runtime::failure::REMOTE_TRANSFER_REASSEMBLY_FULL
            }
        }
    }
}

/// 一个分片。`part` 与 `total_sha256` 走 base64 字符串 wire（降低体积，schema 为 String）。
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferEnvelope {
    pub transfer_id: TransferId,
    pub part_index: u32,
    pub part_count: u32,
    #[serde(with = "b64_hash")]
    #[schemars(with = "String")]
    pub total_sha256: [u8; 32],
    pub total_bytes: u64,
    #[serde(with = "b64_bytes")]
    #[schemars(with = "String")]
    pub part: Vec<u8>,
}

impl TransferEnvelope {
    /// 构造并按 remote compact 上限校验一个分片；任何越界都返回 typed error。
    pub fn new(
        transfer_id: TransferId,
        part_index: u32,
        part_count: u32,
        total_sha256: [u8; 32],
        total_bytes: u64,
        part: Vec<u8>,
    ) -> Result<Self, TransferError> {
        let env = TransferEnvelope {
            transfer_id,
            part_index,
            part_count,
            total_sha256,
            total_bytes,
            part,
        };
        env.validate()?;
        Ok(env)
    }

    /// 构造并按 JSON/UDS 上限校验一个分片。独立的 94-part ceiling 只补足
    /// 700 KiB raw part 对完整 64 MiB transfer 的可表示性，不扩大总字节上限。
    pub fn new_json(
        transfer_id: TransferId,
        part_index: u32,
        part_count: u32,
        total_sha256: [u8; 32],
        total_bytes: u64,
        part: Vec<u8>,
    ) -> Result<Self, TransferError> {
        let env = TransferEnvelope {
            transfer_id,
            part_index,
            part_count,
            total_sha256,
            total_bytes,
            part,
        };
        env.validate_json_part()?;
        Ok(env)
    }

    /// 校验构造不变量（part≤3.5MiB、parts∈[1,64]、total≤64MiB、index<count）。
    pub fn validate(&self) -> Result<(), TransferError> {
        self.validate_with_bounds(MAX_PART_BYTES, MAX_TRANSFER_PARTS)
    }

    fn validate_with_bounds(
        &self,
        maximum_part_bytes: usize,
        maximum_part_count: u32,
    ) -> Result<(), TransferError> {
        let maximum_representable = u64::from(self.part_count)
            .checked_mul(maximum_part_bytes as u64)
            .ok_or(TransferError::TooLarge)?;
        if !self.transfer_id.is_valid_wire_value()
            || self.part_count == 0
            || self.part_count > maximum_part_count
            || self.part_index >= self.part_count
            || self.part.len() > maximum_part_bytes
            || self.total_bytes > MAX_TRANSFER_BYTES
            || self.total_bytes > maximum_representable
            || self.part.len() as u64 > self.total_bytes
        {
            return Err(TransferError::TooLarge);
        }
        Ok(())
    }

    /// JSON/UDS 额外上限；remote compact-binary carrier 不调用本校验。
    pub fn validate_json_part(&self) -> Result<(), TransferError> {
        self.validate_with_bounds(MAX_JSON_PART_BYTES, MAX_JSON_TRANSFER_PARTS)
    }
}

impl Serialize for TransferEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate_json_part()
            .map_err(serde::ser::Error::custom)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire<'a> {
            transfer_id: &'a TransferId,
            part_index: u32,
            part_count: u32,
            #[serde(with = "b64_hash")]
            total_sha256: &'a [u8; 32],
            total_bytes: u64,
            #[serde(with = "b64_bytes")]
            part: &'a [u8],
        }
        Wire {
            transfer_id: &self.transfer_id,
            part_index: self.part_index,
            part_count: self.part_count,
            total_sha256: &self.total_sha256,
            total_bytes: self.total_bytes,
            part: &self.part,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TransferEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            transfer_id: TransferId,
            part_index: u32,
            part_count: u32,
            #[serde(with = "b64_hash")]
            total_sha256: [u8; 32],
            total_bytes: u64,
            #[serde(with = "b64_bytes")]
            part: Vec<u8>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            transfer_id: wire.transfer_id,
            part_index: wire.part_index,
            part_count: wire.part_count,
            total_sha256: wire.total_sha256,
            total_bytes: wire.total_bytes,
            part: wire.part,
        };
        value
            .validate_json_part()
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// 重组进度。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferProgress {
    InProgress {
        received_parts: u32,
        part_count: u32,
    },
    Complete(Vec<u8>),
    /// 同 transfer/channel/metadata 已完整应用过；不得再次产生 Complete。
    AlreadyComplete,
}

struct PartialTransfer {
    channel: RuntimeTransferChannel,
    part_count: u32,
    total_bytes: u64,
    total_sha256: [u8; 32],
    started_at_ms: u64,
    parts: BTreeMap<u32, Vec<u8>>,
    buffered_bytes: u64,
}

struct CompletedTransfer {
    channel: RuntimeTransferChannel,
    part_count: u32,
    total_bytes: u64,
    total_sha256: [u8; 32],
    completed_at_ms: u64,
}

/// 每 connection 的分片重组器（纯状态机，无 IO，时间由调用方注入）。
pub struct TransferReassembler {
    max_reassembly_bytes: u64,
    ttl_ms: u64,
    active: BTreeMap<TransferId, PartialTransfer>,
    completed: BTreeMap<TransferId, CompletedTransfer>,
    buffered_bytes: u64,
}

impl Default for TransferReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferReassembler {
    /// 使用 design 默认上限（128 MiB / 5 分钟）。
    pub fn new() -> Self {
        Self::with_limits(MAX_REASSEMBLY_BYTES, TRANSFER_TTL_MS)
    }

    /// 使用自定义上限（测试注入用）。
    pub fn with_limits(max_reassembly_bytes: u64, ttl_ms: u64) -> Self {
        Self {
            max_reassembly_bytes,
            ttl_ms,
            active: BTreeMap::new(),
            completed: BTreeMap::new(),
            buffered_bytes: 0,
        }
    }

    /// 当前重组内存占用（跨全部 active transfer）。
    pub fn buffered_bytes(&self) -> u64 {
        self.buffered_bytes
    }

    /// 按 remote compact 的 64-part profile 消费一个分片。
    pub fn accept(
        &mut self,
        channel: RuntimeTransferChannel,
        env: TransferEnvelope,
        now_ms: u64,
    ) -> Result<TransferProgress, TransferError> {
        env.validate()?;
        self.accept_validated(channel, env, now_ms)
    }

    /// 按 JSON/UDS 的 94-part profile 消费一个分片。
    pub fn accept_json(
        &mut self,
        channel: RuntimeTransferChannel,
        env: TransferEnvelope,
        now_ms: u64,
    ) -> Result<TransferProgress, TransferError> {
        env.validate_json_part()?;
        self.accept_validated(channel, env, now_ms)
    }

    fn accept_validated(
        &mut self,
        channel: RuntimeTransferChannel,
        env: TransferEnvelope,
        now_ms: u64,
    ) -> Result<TransferProgress, TransferError> {
        // 已存在的 transfer：先判 TTL（超时 → typed Expired），再判 metadata 一致性。
        // 注意必须在 housekeeping purge 之前判定，否则超时分片会被误当作新 transfer 首片。
        if let Some(existing) = self.active.get(&env.transfer_id) {
            if now_ms.saturating_sub(existing.started_at_ms) >= self.ttl_ms {
                self.drop_transfer(&env.transfer_id);
                return Err(TransferError::Expired);
            }
            if existing.channel != channel
                || existing.part_count != env.part_count
                || existing.total_bytes != env.total_bytes
                || existing.total_sha256 != env.total_sha256
            {
                self.drop_transfer(&env.transfer_id);
                return Err(TransferError::HashMismatch);
            }
            if let Some(prev) = existing.parts.get(&env.part_index) {
                // 重复 index：内容相同 → 幂等；内容不同 → 冲突。
                if prev == &env.part {
                    let received = existing.parts.len() as u32;
                    return Ok(TransferProgress::InProgress {
                        received_parts: received,
                        part_count: existing.part_count,
                    });
                }
                self.drop_transfer(&env.transfer_id);
                return Err(TransferError::HashMismatch);
            }
        }

        // housekeeping：淘汰其它已超时 transfer，释放重组内存后再判 cap。
        self.purge_expired(now_ms);

        if let Some(done) = self.completed.get(&env.transfer_id) {
            if done.channel != channel
                || done.part_count != env.part_count
                || done.total_bytes != env.total_bytes
                || done.total_sha256 != env.total_sha256
            {
                return Err(TransferError::HashMismatch);
            }
            return Ok(TransferProgress::AlreadyComplete);
        }

        if !self.active.contains_key(&env.transfer_id) && self.active.len() >= MAX_ACTIVE_TRANSFERS
        {
            return Err(TransferError::ReassemblyFull);
        }

        // 重组内存上界（跨全部 active transfer）。
        let incoming = env.part.len() as u64;
        let projected = self
            .buffered_bytes
            .checked_add(incoming)
            .ok_or(TransferError::ReassemblyFull)?;
        if projected > self.max_reassembly_bytes {
            return Err(TransferError::ReassemblyFull);
        }

        let entry = self
            .active
            .entry(env.transfer_id.clone())
            .or_insert_with(|| PartialTransfer {
                channel,
                part_count: env.part_count,
                total_bytes: env.total_bytes,
                total_sha256: env.total_sha256,
                started_at_ms: now_ms,
                parts: BTreeMap::new(),
                buffered_bytes: 0,
            });
        entry.parts.insert(env.part_index, env.part.clone());
        entry.buffered_bytes = entry
            .buffered_bytes
            .checked_add(incoming)
            .ok_or(TransferError::ReassemblyFull)?;
        self.buffered_bytes = projected;

        if entry.parts.len() as u32 != entry.part_count {
            return Ok(TransferProgress::InProgress {
                received_parts: entry.parts.len() as u32,
                part_count: entry.part_count,
            });
        }

        // 全部 part 到齐时先比较已计入 connection budget 的实际 bytes；声明长度不匹配必须
        // 在按 totalBytes 预分配之前 fail-close，否则小 parts 可诱导额外 64 MiB 瞬时分配。
        if entry.buffered_bytes != entry.total_bytes {
            self.drop_transfer(&env.transfer_id);
            return Err(TransferError::HashMismatch);
        }

        // assembly 与已缓存 parts 在复制期间同时存活，因此还要为完整 totalBytes 单独预留
        // connection budget。预留失败必须先 abort/release active transfer，再返回 typed full。
        let assembly_bytes = entry.total_bytes;
        let assembly_projected = match self.buffered_bytes.checked_add(assembly_bytes) {
            Some(projected) if projected <= self.max_reassembly_bytes => projected,
            _ => {
                self.drop_transfer(&env.transfer_id);
                return Err(TransferError::ReassemblyFull);
            }
        };
        self.buffered_bytes = assembly_projected;

        // 长度与 assembly reservation 都已证明后，才重组并校验总 hash。
        let mut assembled = Vec::with_capacity(assembly_bytes as usize);
        for (_idx, bytes) in entry.parts.iter() {
            assembled.extend_from_slice(bytes);
        }
        let expected = entry.total_sha256;
        self.drop_transfer(&env.transfer_id);
        self.buffered_bytes = self.buffered_bytes.saturating_sub(assembly_bytes);
        let actual: [u8; 32] = Sha256::digest(&assembled).into();
        if actual != expected {
            return Err(TransferError::HashMismatch);
        }
        self.remember_completed(
            env.transfer_id,
            CompletedTransfer {
                channel,
                part_count: env.part_count,
                total_bytes: env.total_bytes,
                total_sha256: env.total_sha256,
                completed_at_ms: now_ms,
            },
        );
        Ok(TransferProgress::Complete(assembled))
    }

    fn purge_expired(&mut self, now_ms: u64) {
        let expired: Vec<TransferId> = self
            .active
            .iter()
            .filter(|(_, t)| now_ms.saturating_sub(t.started_at_ms) >= self.ttl_ms)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.drop_transfer(&id);
        }
        self.completed
            .retain(|_, transfer| now_ms.saturating_sub(transfer.completed_at_ms) < self.ttl_ms);
    }

    fn drop_transfer(&mut self, id: &TransferId) {
        if let Some(t) = self.active.remove(id) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(t.buffered_bytes);
        }
    }

    fn remember_completed(&mut self, id: TransferId, completed: CompletedTransfer) {
        if self.completed.len() >= MAX_COMPLETED_TRANSFER_TOMBSTONES
            && let Some(oldest) = self
                .completed
                .iter()
                .min_by_key(|(_, value)| value.completed_at_ms)
                .map(|(id, _)| id.clone())
        {
            self.completed.remove(&oldest);
        }
        self.completed.insert(id, completed);
    }
}

/// 远程 transfer part 的 compact binary carrier。JSON `TransferEnvelope` 只作为模型/本地
/// fixture；生产 Relay 使用本 carrier，raw part 不做 base64 膨胀。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTransferCarrierV1 {
    pub runtime_version: u16,
    pub message_id: MessageId,
    pub channel: RuntimeTransferChannel,
    pub transfer: TransferEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeTransferCarrierError {
    #[error("invalid compact transfer carrier")]
    Invalid,
    #[error("unsupported runtime version")]
    Version,
    #[error("compact transfer carrier exceeds Relay frame limit")]
    TooLarge,
    #[error(transparent)]
    Transfer(#[from] TransferError),
}

impl RuntimeTransferCarrierV1 {
    pub fn new(
        message_id: MessageId,
        channel: RuntimeTransferChannel,
        transfer: TransferEnvelope,
    ) -> Self {
        Self {
            runtime_version: RUNTIME_PROTOCOL_VERSION,
            message_id,
            channel,
            transfer,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, RuntimeTransferCarrierError> {
        if self.runtime_version != RUNTIME_PROTOCOL_VERSION {
            return Err(RuntimeTransferCarrierError::Version);
        }
        self.transfer.validate()?;
        if !self.message_id.is_valid_wire_value() {
            return Err(RuntimeTransferCarrierError::Invalid);
        }
        let message = self.message_id.as_str().as_bytes();
        let transfer_id = self.transfer.transfer_id.as_str().as_bytes();
        let message_len =
            u16::try_from(message.len()).map_err(|_| RuntimeTransferCarrierError::Invalid)?;
        let transfer_len =
            u16::try_from(transfer_id.len()).map_err(|_| RuntimeTransferCarrierError::Invalid)?;
        let part_len = u32::try_from(self.transfer.part.len())
            .map_err(|_| RuntimeTransferCarrierError::TooLarge)?;
        if message.is_empty()
            || transfer_id.is_empty()
            || message.len() > MAX_MESSAGE_ID_BYTES
            || transfer_id.len() > MAX_TRANSFER_ID_BYTES
        {
            return Err(RuntimeTransferCarrierError::Invalid);
        }
        let mut out = Vec::with_capacity(self.transfer.part.len() + 96);
        out.extend_from_slice(TRANSFER_CARRIER_MAGIC);
        out.extend_from_slice(&self.runtime_version.to_be_bytes());
        out.push(match self.channel {
            RuntimeTransferChannel::Reply => 0,
            RuntimeTransferChannel::Stream => 1,
        });
        out.extend_from_slice(&message_len.to_be_bytes());
        out.extend_from_slice(message);
        out.extend_from_slice(&transfer_len.to_be_bytes());
        out.extend_from_slice(transfer_id);
        out.extend_from_slice(&self.transfer.part_index.to_be_bytes());
        out.extend_from_slice(&self.transfer.part_count.to_be_bytes());
        out.extend_from_slice(&self.transfer.total_sha256);
        out.extend_from_slice(&self.transfer.total_bytes.to_be_bytes());
        out.extend_from_slice(&part_len.to_be_bytes());
        out.extend_from_slice(&self.transfer.part);
        if out.len() >= MAX_TRANSFER_CARRIER_BYTES {
            return Err(RuntimeTransferCarrierError::TooLarge);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RuntimeTransferCarrierError> {
        if bytes.len() >= MAX_TRANSFER_CARRIER_BYTES {
            return Err(RuntimeTransferCarrierError::TooLarge);
        }
        let mut reader = CarrierReader::new(bytes);
        if reader.take(TRANSFER_CARRIER_MAGIC.len())? != TRANSFER_CARRIER_MAGIC {
            return Err(RuntimeTransferCarrierError::Invalid);
        }
        let runtime_version = reader.u16()?;
        if runtime_version != RUNTIME_PROTOCOL_VERSION {
            return Err(RuntimeTransferCarrierError::Version);
        }
        let channel = match reader.u8()? {
            0 => RuntimeTransferChannel::Reply,
            1 => RuntimeTransferChannel::Stream,
            _ => return Err(RuntimeTransferCarrierError::Invalid),
        };
        let message_id = reader.utf8_u16()?;
        let transfer_id = reader.utf8_u16()?;
        if message_id.is_empty()
            || transfer_id.is_empty()
            || message_id.len() > MAX_MESSAGE_ID_BYTES
            || transfer_id.len() > MAX_TRANSFER_ID_BYTES
        {
            return Err(RuntimeTransferCarrierError::Invalid);
        }
        let part_index = reader.u32()?;
        let part_count = reader.u32()?;
        let total_sha256: [u8; 32] = reader
            .take(32)?
            .try_into()
            .map_err(|_| RuntimeTransferCarrierError::Invalid)?;
        let total_bytes = reader.u64()?;
        let part_len =
            usize::try_from(reader.u32()?).map_err(|_| RuntimeTransferCarrierError::Invalid)?;
        let part = reader.take(part_len)?.to_vec();
        if !reader.is_empty() {
            return Err(RuntimeTransferCarrierError::Invalid);
        }
        let transfer = TransferEnvelope::new(
            TransferId::new(transfer_id),
            part_index,
            part_count,
            total_sha256,
            total_bytes,
            part,
        )?;
        Ok(Self {
            runtime_version,
            message_id: MessageId::new(message_id),
            channel,
            transfer,
        })
    }
}

struct CarrierReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CarrierReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RuntimeTransferCarrierError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RuntimeTransferCarrierError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RuntimeTransferCarrierError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RuntimeTransferCarrierError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RuntimeTransferCarrierError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| RuntimeTransferCarrierError::Invalid)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, RuntimeTransferCarrierError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| RuntimeTransferCarrierError::Invalid)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, RuntimeTransferCarrierError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| RuntimeTransferCarrierError::Invalid)?,
        ))
    }

    fn utf8_u16(&mut self) -> Result<String, RuntimeTransferCarrierError> {
        let len = usize::from(self.u16()?);
        let value = std::str::from_utf8(self.take(len)?)
            .map_err(|_| RuntimeTransferCarrierError::Invalid)?;
        Ok(value.to_owned())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// 32-byte hash 的 base64 wire 编解码。
mod b64_hash {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let raw = STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("totalSha256 must decode to exactly 32 bytes"))
    }
}

/// 可变长 bytes 的 base64 wire 编解码。
mod b64_bytes {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
