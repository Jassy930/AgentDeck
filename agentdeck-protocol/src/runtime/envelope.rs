//! Runtime v1 顶层 envelope（design §8.2）。
//!
//! `RuntimeEnvelope` 是 UDS 与解密后远程链路的共同业务 wire。它把三类业务消息
//! （请求/回复/流）统一封装；限制值（如单个 `RuntimeRequest` ≤ 1 MiB）在契约层
//! 以具名常量 + 构造校验承载。

use crate::runtime::catalog::{CatalogDelta, CatalogSnapshot};
use crate::runtime::command::{HelloParams, RuntimeRequest};
use crate::runtime::event::RuntimeEvent;
use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{MessageId, PairingId};
use crate::runtime::receipt::{ApprovalReceipt, CommandReceipt, RevocationReceipt};
use crate::runtime::sync::{BackfillChunk, ConversationSnapshot, RuntimeSyncComplete};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 解密后单个 `RuntimeRequest` 的最大字节数（design §8.8：1 MiB）。
pub const MAX_RUNTIME_REQUEST_BYTES: usize = 1024 * 1024;

/// 请求大小校验失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeSizeError {
    #[error("runtime request exceeds {MAX_RUNTIME_REQUEST_BYTES} bytes (1 MiB)")]
    TooLarge,
    #[error("failed to encode runtime envelope: {0}")]
    Encode(String),
}

/// 校验一个已编码 `RuntimeRequest` 的字节数不超过 1 MiB（不 panic）。
pub fn ensure_request_within_limit(encoded_len: usize) -> Result<(), RuntimeSizeError> {
    if encoded_len > MAX_RUNTIME_REQUEST_BYTES {
        return Err(RuntimeSizeError::TooLarge);
    }
    Ok(())
}

/// Runtime v1 顶层封装。
///
/// 未派生 `PartialEq`：`RuntimeMessage` 传递内嵌未派生 `PartialEq` 的中立 trunk 类型；
/// 本 task 不改动 trunk，契约测试以 wire round-trip 覆盖。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEnvelope {
    pub version: u16,
    pub message_id: MessageId,
    pub body: RuntimeMessage,
}

impl RuntimeEnvelope {
    /// 序列化并校验大小；返回编码字节数或 typed error（design §8.8：超限拒绝，不 panic）。
    pub fn check_encoded_size(&self) -> Result<usize, RuntimeSizeError> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| RuntimeSizeError::Encode(e.to_string()))?;
        ensure_request_within_limit(bytes.len())?;
        Ok(bytes.len())
    }
}

/// 三类业务消息（design core interface）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "message",
    content = "payload",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeMessage {
    Request(RuntimeRequest),
    Reply(RuntimeReply),
    Stream(RuntimeStreamItem),
}

/// daemon → client 回复（关联到某请求）。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reply", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeReply {
    /// 版本/能力握手回执。
    Hello(HelloParams),
    /// sendPrompt/start 等有副作用命令回执。
    Command(CommandReceipt),
    /// resolveApproval/retryApproval 回执。
    Approval(ApprovalReceipt),
    /// revoke 回执。
    Revocation(RevocationReceipt),
    /// catalog snapshot（分页，每页 ≤ 500 rows）。
    Catalog(CatalogSnapshot),
    /// conversation snapshot（capabilities 先行）。
    Snapshot(ConversationSnapshot),
    /// backfill 批次。
    Backfill(BackfillChunk),
    /// 首次订阅/backfill 完成 barrier。
    SyncComplete(RuntimeSyncComplete),
    /// createPairInvite 回执 —— local-only administration。
    PairInvite(PairInvite),
    /// listPendingPairings 回执 —— local-only administration。
    PendingPairings { pairings: Vec<PendingPairing> },
    /// 类型化业务失败。
    Failure(RuntimeFailure),
}

/// daemon → client 订阅推送项。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "stream", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeStreamItem {
    /// 一条 canonical 事件。
    Event(RuntimeEvent),
    /// catalog 增量。
    CatalogDelta(CatalogDelta),
    /// 订阅 barrier 完成。
    SyncComplete(RuntimeSyncComplete),
}

/// createPairInvite 回执中的邀请引用（不含 P1.1 不涉及的 crypto secret/relay 材料）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairInvite {
    pub pairing_id: PairingId,
    pub display_name: String,
    pub expires_at_ms: u64,
}

/// 一个待本地确认的 pending pairing（local-only administration 列表项）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingPairing {
    pub pairing_id: PairingId,
    /// 设备指纹；本地 UI 显示供用户确认（design §6.3）。
    pub device_fingerprint: String,
    pub requested_at_ms: u64,
}
