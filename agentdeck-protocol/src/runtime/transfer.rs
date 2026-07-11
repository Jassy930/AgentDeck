//! Runtime v1 有界分片与重组（design §9.5）。
//!
//! `TransferEnvelope { transferId, partIndex, partCount, totalSha256, totalBytes, part }`
//! 用于 snapshot / history page / 长 tool output 等超过 Relay 单 frame 4 MiB 的 payload。
//!
//! 上界（具名常量 + 构造校验）：
//! - 每个加密前 part ≤ 3.5 MiB；单 transfer ≤ 64 parts / 64 MiB；TTL 5 分钟。
//! - partCount/totalBytes/totalSha256 在首 part 后不可变。
//! - 每 connection 同时重组内存 ≤ 128 MiB。
//! - 超限、重复 index 不同内容、hash 不符、超时 → typed error（不 panic）。
//!
//! `TransferReassembler` 是纯状态机：无 IO，时间由调用方注入（`now_ms`）。

use crate::runtime::identity::TransferId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// 每个加密前 part 的最大字节数（3.5 MiB）。3.5 MiB + AEAD/outer overhead 仍落在
/// Relay 4 MiB 单 frame 硬上限内。
pub const MAX_PART_BYTES: usize = 3_670_016; // 3.5 * 1024 * 1024
/// 单 transfer 最大 part 数。
pub const MAX_TRANSFER_PARTS: u32 = 64;
/// 单 transfer 最大总字节数（64 MiB）。
pub const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
/// 每 connection 同时重组内存上限（128 MiB）。
pub const MAX_REASSEMBLY_BYTES: u64 = 128 * 1024 * 1024;
/// transfer TTL（5 分钟，毫秒）。
pub const TRANSFER_TTL_MS: u64 = 5 * 60 * 1000;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// 构造并校验一个分片；任何越界都返回 typed error（不 panic）。
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

    /// 校验构造不变量（part≤3.5MiB、parts∈[1,64]、total≤64MiB、index<count）。
    pub fn validate(&self) -> Result<(), TransferError> {
        if self.part_count == 0
            || self.part_count > MAX_TRANSFER_PARTS
            || self.part_index >= self.part_count
            || self.part.len() > MAX_PART_BYTES
            || self.total_bytes > MAX_TRANSFER_BYTES
        {
            return Err(TransferError::TooLarge);
        }
        Ok(())
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
}

struct PartialTransfer {
    part_count: u32,
    total_bytes: u64,
    total_sha256: [u8; 32],
    started_at_ms: u64,
    parts: BTreeMap<u32, Vec<u8>>,
    buffered_bytes: u64,
}

/// 每 connection 的分片重组器（纯状态机，无 IO，时间由调用方注入）。
pub struct TransferReassembler {
    max_reassembly_bytes: u64,
    ttl_ms: u64,
    active: BTreeMap<TransferId, PartialTransfer>,
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
            buffered_bytes: 0,
        }
    }

    /// 当前重组内存占用（跨全部 active transfer）。
    pub fn buffered_bytes(&self) -> u64 {
        self.buffered_bytes
    }

    /// 消费一个分片。返回 `InProgress` 或重组完成的 `Complete(bytes)`。
    pub fn accept(
        &mut self,
        env: TransferEnvelope,
        now_ms: u64,
    ) -> Result<TransferProgress, TransferError> {
        env.validate()?;

        // 已存在的 transfer：先判 TTL（超时 → typed Expired），再判 metadata 一致性。
        // 注意必须在 housekeeping purge 之前判定，否则超时分片会被误当作新 transfer 首片。
        if let Some(existing) = self.active.get(&env.transfer_id) {
            if now_ms.saturating_sub(existing.started_at_ms) > self.ttl_ms {
                self.drop_transfer(&env.transfer_id);
                return Err(TransferError::Expired);
            }
            if existing.part_count != env.part_count
                || existing.total_bytes != env.total_bytes
                || existing.total_sha256 != env.total_sha256
            {
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
                return Err(TransferError::HashMismatch);
            }
        }

        // housekeeping：淘汰其它已超时 transfer，释放重组内存后再判 cap。
        self.purge_expired(now_ms);

        // 重组内存上界（跨全部 active transfer）。
        let incoming = env.part.len() as u64;
        if self.buffered_bytes + incoming > self.max_reassembly_bytes {
            return Err(TransferError::ReassemblyFull);
        }

        let entry = self
            .active
            .entry(env.transfer_id.clone())
            .or_insert_with(|| PartialTransfer {
                part_count: env.part_count,
                total_bytes: env.total_bytes,
                total_sha256: env.total_sha256,
                started_at_ms: now_ms,
                parts: BTreeMap::new(),
                buffered_bytes: 0,
            });
        entry.parts.insert(env.part_index, env.part.clone());
        entry.buffered_bytes += incoming;
        self.buffered_bytes += incoming;

        if entry.parts.len() as u32 != entry.part_count {
            return Ok(TransferProgress::InProgress {
                received_parts: entry.parts.len() as u32,
                part_count: entry.part_count,
            });
        }

        // 全部 part 到齐：重组并校验总 hash。
        let mut assembled = Vec::with_capacity(entry.total_bytes as usize);
        for (_idx, bytes) in entry.parts.iter() {
            assembled.extend_from_slice(bytes);
        }
        let expected = entry.total_sha256;
        let assembled_len_ok = assembled.len() as u64 == entry.total_bytes;
        self.drop_transfer(&env.transfer_id);

        if !assembled_len_ok {
            return Err(TransferError::HashMismatch);
        }
        let actual: [u8; 32] = Sha256::digest(&assembled).into();
        if actual != expected {
            return Err(TransferError::HashMismatch);
        }
        Ok(TransferProgress::Complete(assembled))
    }

    fn purge_expired(&mut self, now_ms: u64) {
        let expired: Vec<TransferId> = self
            .active
            .iter()
            .filter(|(_, t)| now_ms.saturating_sub(t.started_at_ms) > self.ttl_ms)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.drop_transfer(&id);
        }
    }

    fn drop_transfer(&mut self, id: &TransferId) {
        if let Some(t) = self.active.remove(id) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(t.buffered_bytes);
        }
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
