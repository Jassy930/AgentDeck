//! Runtime v2 顶层 envelope（design §8.2）。
//!
//! `RuntimeEnvelope` 是 UDS 与解密后远程链路的共同业务 wire。它把三类业务消息
//! （请求/回复/流）统一封装；限制值（如单个 `RuntimeRequest` ≤ 1 MiB）在契约层
//! 以具名常量 + 构造校验承载。

use crate::runtime::catalog::{CatalogDelta, CatalogSnapshot};
use crate::runtime::command::{HelloParams, RuntimeRequest};
use crate::runtime::configuration::{AgentDescriptions, ConfigurationReceipt};
use crate::runtime::event::RuntimeEvent;
use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{MessageId, PairingId};
use crate::runtime::metadata::ConversationMetadataReceipt;
use crate::runtime::receipt::{
    ApprovalReceipt, CancellationReceipt, CommandReceipt, CommandStatusReceipt,
    ConversationStartReceipt, RevocationReceipt,
};
use crate::runtime::sync::{
    BackfillChunk, ConversationSnapshot, RuntimeSyncComplete, SubscriptionReceipt,
};
use crate::runtime::transfer::TransferEnvelope;
use crate::runtime::upgrade::StageUpgradeReceipt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 解密后单个 `RuntimeRequest` 的最大字节数（design §8.8：1 MiB）。
pub const MAX_RUNTIME_REQUEST_BYTES: usize = 1024 * 1024;
/// Runtime JSONL/UDS 完整 frame hard cap。remote compact-binary 使用独立 4 MiB carrier 上限。
pub const MAX_RUNTIME_JSON_FRAME_BYTES: usize = 1024 * 1024;

/// 请求大小校验失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeSizeError {
    #[error("runtime request exceeds {MAX_RUNTIME_REQUEST_BYTES} bytes (1 MiB)")]
    TooLarge,
    #[error("runtime JSON/UDS frame exceeds {MAX_RUNTIME_JSON_FRAME_BYTES} bytes (1 MiB)")]
    FrameTooLarge,
    #[error("failed to encode runtime envelope: {0}")]
    Encode(String),
}

/// 校验一个已编码 `RuntimeRequest` 的字节数不超过 1 MiB（不 panic）。
pub fn ensure_request_within_limit(encoded_len: usize) -> Result<(), RuntimeSizeError> {
    if encoded_len >= MAX_RUNTIME_REQUEST_BYTES {
        return Err(RuntimeSizeError::TooLarge);
    }
    Ok(())
}

/// Runtime v2 顶层封装。
///
/// 未派生 `PartialEq`：`RuntimeMessage` 传递内嵌未派生 `PartialEq` 的中立 trunk 类型；
/// 本 task 不改动 trunk，契约测试以 wire round-trip 覆盖。
#[derive(Debug, Clone, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEnvelope {
    pub version: u16,
    pub message_id: MessageId,
    pub body: RuntimeMessage,
}

impl RuntimeEnvelope {
    fn validate_version(&self) -> Result<(), &'static str> {
        if self.version == crate::runtime::RUNTIME_PROTOCOL_VERSION {
            Ok(())
        } else {
            Err("unsupported Runtime protocol version")
        }
    }

    /// 序列化并校验大小；返回编码字节数或 typed error（design §8.8：超限拒绝，不 panic）。
    pub fn check_encoded_size(&self) -> Result<usize, RuntimeSizeError> {
        Ok(self.to_json_bytes_checked()?.len())
    }

    /// Runtime JSON/UDS 唯一受检编码入口；daemon writer 必须消费这里返回的 exact bytes，
    /// 不能先绕过 hard cap 自行 `serde_json::to_vec`。
    pub fn to_json_bytes_checked(&self) -> Result<Vec<u8>, RuntimeSizeError> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| RuntimeSizeError::Encode(e.to_string()))?;
        if matches!(&self.body, RuntimeMessage::Request(_)) {
            ensure_request_within_limit(bytes.len())?;
        }
        if bytes.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
            return Err(RuntimeSizeError::FrameTooLarge);
        }
        Ok(bytes)
    }
}

impl Serialize for RuntimeEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate_version().map_err(serde::ser::Error::custom)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire<'a> {
            version: u16,
            message_id: &'a MessageId,
            body: &'a RuntimeMessage,
        }
        Wire {
            version: self.version,
            message_id: &self.message_id,
            body: &self.body,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RuntimeEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            version: u16,
            message_id: MessageId,
            body: RuntimeMessage,
        }
        let wire = Wire::deserialize(deserializer)?;
        let envelope = Self {
            version: wire.version,
            message_id: wire.message_id,
            body: wire.body,
        };
        envelope
            .validate_version()
            .map_err(serde::de::Error::custom)?;
        Ok(envelope)
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
    /// agent discovery 与默认 configuration。
    Agents(AgentDescriptions),
    /// ConfigureConversation CAS 回执。
    Configuration(ConfigurationReceipt),
    /// UpdateConversationMetadata CAS 回执。
    ConversationMetadata(ConversationMetadataReceipt),
    /// StageUpgrade 本机管理回执。
    StageUpgrade(StageUpgradeReceipt),
    /// sendPrompt 有副作用命令回执。
    Command(CommandReceipt),
    /// queryReceipt 返回 command journal 的精确持久化状态。
    CommandStatus(CommandStatusReceipt),
    /// 纯幂等 conversation 创建回执。
    ConversationStart(ConversationStartReceipt),
    /// queued/active cancel 精确回执。
    Cancellation(CancellationReceipt),
    /// resolveApproval/retryApproval 回执。
    Approval(ApprovalReceipt),
    /// revoke 回执。
    Revocation(RevocationReceipt),
    /// Subscribe/Unsubscribe typed 回执。
    Subscription(SubscriptionReceipt),
    /// catalog snapshot（分页，每页 ≤ 500 rows）。
    Catalog(CatalogSnapshot),
    /// conversation snapshot（capabilities 先行）。
    Snapshot(ConversationSnapshot),
    /// backfill 批次。
    Backfill(BackfillChunk),
    /// 首次订阅/backfill 完成 barrier。
    SyncComplete(RuntimeSyncComplete),
    /// 大 reply 的 compact-binary 分片模型；远程链路不使用 JSON base64 载荷。
    TransferPart(TransferEnvelope),
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
    /// 大 live item 的 compact-binary 分片模型。
    TransferPart(TransferEnvelope),
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
