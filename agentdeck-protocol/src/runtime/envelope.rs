//! Runtime v4 顶层 envelope（design §8.2）。
//!
//! `RuntimeEnvelope` 是 UDS 与解密后远程链路的共同业务 wire。它把三类业务消息
//! （请求/回复/流）统一封装；限制值（如单个 `RuntimeRequest` ≤ 1 MiB）在契约层
//! 以具名常量 + 构造校验承载。

use crate::e2ee::PairInviteV1;
use crate::relay_v2::id::{MachineRouteId, RelayServerId};
use crate::runtime::catalog::{CatalogDelta, CatalogSnapshot};
use crate::runtime::command::{HelloParams, RuntimeRequest};
use crate::runtime::configuration::{AgentDescriptions, ConfigurationReceipt};
use crate::runtime::event::RuntimeEvent;
use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{MessageId, PairingId};
use crate::runtime::metadata::ConversationMetadataReceipt;
use crate::runtime::receipt::{
    ApprovalReceipt, CancellationReceipt, CommandReceipt, CommandStatusReceipt,
    ConversationStartReceipt, PairingReceipt, RevocationReceipt,
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

/// RemoteLink 解密后的 Runtime ingress 错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeDecodeError {
    #[error("runtime JSON frame exceeds {MAX_RUNTIME_JSON_FRAME_BYTES} bytes (1 MiB)")]
    FrameTooLarge,
    #[error("failed to decode runtime envelope: {0}")]
    Decode(String),
    #[error("remote runtime ingress accepts Request envelopes only")]
    NotRequest,
}

/// 校验一个已编码 `RuntimeRequest` 的字节数不超过 1 MiB（不 panic）。
pub fn ensure_request_within_limit(encoded_len: usize) -> Result<(), RuntimeSizeError> {
    if encoded_len >= MAX_RUNTIME_REQUEST_BYTES {
        return Err(RuntimeSizeError::TooLarge);
    }
    Ok(())
}

/// Runtime v4 顶层封装。
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

    /// 解密后的 remote Runtime ingress 唯一受检入口。
    ///
    /// raw frame 必须严格小于 1 MiB；随后复用 `RuntimeEnvelope` 的 deny-unknown、
    /// duplicate-field 与 current-version 反序列化约束，并只允许 client→daemon Request。
    pub fn from_json_bytes_checked(bytes: &[u8]) -> Result<Self, RuntimeDecodeError> {
        if bytes.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
            return Err(RuntimeDecodeError::FrameTooLarge);
        }
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|error| RuntimeDecodeError::Decode(error.to_string()))?;
        if !matches!(&envelope.body, RuntimeMessage::Request(_)) {
            return Err(RuntimeDecodeError::NotRequest);
        }
        Ok(envelope)
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
    /// confirmPairing/cancelPairing 的 canonical durable 回执。
    Pairing(PairingReceipt),
    /// machine enrollment / status / trust-reset 的最小生命周期读回。
    MachineRemoteStatus(MachineRemoteStatus),
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
    /// 只允许 daemon 向 local-control UDS connection 投递的待确认配对事件。
    PairingPending(PendingPairing),
}

/// createPairInvite 回执。完整 bearer invite 只经 same-UID UDS 返回，并继续由
/// `PairInviteV1` 的 redacted Debug/strict wire 约束保护。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairInvite {
    pub pairing_id: PairingId,
    pub invite: Box<PairInviteV1>,
}

/// 一个待本地确认的 pending pairing（local-only administration 列表项）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingPairing {
    pub pairing_id: PairingId,
    /// 已冻结 PairRequest 的 SHA-256；绑定 pending/confirm/replay。
    #[serde(with = "crate::relay_v2::id::b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    /// DeviceSign 公钥 fingerprint；本地 UI 显示供用户确认（design §6.3）。
    #[serde(with = "crate::relay_v2::id::b64_32")]
    #[schemars(with = "String")]
    pub device_sign_fingerprint: [u8; 32],
    pub requested_at_ms: u64,
    pub expires_at_ms: u64,
}

/// machine remote 生命周期；不携带任何 enrollment secret、证书或 purge proof。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MachineRemoteLifecycle {
    Unenrolled,
    EnrollmentPrepared,
    EnrollmentResponseValidated,
    Active,
    RetirePending,
    RelayCommitted,
    PurgeReadbackAbsent,
    LocalDeleted,
    Blocked,
}

/// MachineRoot 公钥 fingerprint 的固定 32-byte、标准 base64 wire。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct MachineRootFingerprint(
    #[serde(with = "crate::relay_v2::id::b64_32")]
    #[schemars(with = "String")]
    [u8; 32],
);

impl MachineRootFingerprint {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for MachineRootFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MachineRootFingerprint(<redacted>)")
    }
}

/// 可公开读回的稳定 failure code；禁止自由文本、空值与无界字符串。
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct MachineRemoteFailureCode(
    #[schemars(length(min = 1, max = 128), regex(pattern = "^[a-z0-9._-]+$"))] String,
);

impl MachineRemoteFailureCode {
    pub fn new(value: impl Into<String>) -> Result<Self, MachineRemoteStatusError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
        {
            return Err(MachineRemoteStatusError::InvalidFailureCode);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MachineRemoteFailureCode {
    type Error = MachineRemoteStatusError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MachineRemoteFailureCode> for String {
    fn from(value: MachineRemoteFailureCode) -> Self {
        value.0
    }
}

impl std::fmt::Debug for MachineRemoteFailureCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MachineRemoteFailureCode(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MachineRemoteStatusError {
    #[error("machine remote failure code is not a bounded stable code")]
    InvalidFailureCode,
    #[error("machine remote status binding axes are incomplete for lifecycle")]
    IncompleteBinding,
    #[error("machine remote status carries binding axes forbidden for lifecycle")]
    UnexpectedBinding,
    #[error("machine remote status required binding is all-zero: {0}")]
    ZeroBinding(&'static str),
    #[error("machine remote status failure code does not match lifecycle")]
    FailureCodeLifecycleMismatch,
}

/// 本机管理员可见的最小 machine remote 状态。
///
/// 可选字段只用于定位当前 trust domain；禁止扩展 enrollment code、origin、SPKI pin、
/// cert、retirement/purge proof 或自由文本 message/detail。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRemoteStatus {
    pub lifecycle: MachineRemoteLifecycle,
    pub relay_server_id: Option<RelayServerId>,
    pub machine_route: Option<MachineRouteId>,
    pub root_fingerprint: Option<MachineRootFingerprint>,
    pub trust_epoch: Option<u64>,
    pub failure_code: Option<MachineRemoteFailureCode>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MachineRemoteStatusWire {
    lifecycle: MachineRemoteLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay_server_id: Option<RelayServerId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    machine_route: Option<MachineRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_fingerprint: Option<MachineRootFingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trust_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure_code: Option<MachineRemoteFailureCode>,
}

impl MachineRemoteStatus {
    pub fn new(
        lifecycle: MachineRemoteLifecycle,
        relay_server_id: Option<RelayServerId>,
        machine_route: Option<MachineRouteId>,
        root_fingerprint: Option<MachineRootFingerprint>,
        trust_epoch: Option<u64>,
        failure_code: Option<MachineRemoteFailureCode>,
    ) -> Result<Self, MachineRemoteStatusError> {
        let status = Self {
            lifecycle,
            relay_server_id,
            machine_route,
            root_fingerprint,
            trust_epoch,
            failure_code,
        };
        status.validate()?;
        Ok(status)
    }

    pub fn validate(&self) -> Result<(), MachineRemoteStatusError> {
        let present = [
            self.relay_server_id.is_some(),
            self.machine_route.is_some(),
            self.root_fingerprint.is_some(),
            self.trust_epoch.is_some(),
        ];
        let has_none = present.iter().all(|value| !value);
        let has_complete = present.iter().all(|value| *value);

        match self.lifecycle {
            MachineRemoteLifecycle::Unenrolled => {
                if !has_none {
                    return Err(MachineRemoteStatusError::UnexpectedBinding);
                }
                if self.failure_code.is_some() {
                    return Err(MachineRemoteStatusError::FailureCodeLifecycleMismatch);
                }
            }
            MachineRemoteLifecycle::Blocked => {
                if !has_none && !has_complete {
                    return Err(MachineRemoteStatusError::IncompleteBinding);
                }
                if self.failure_code.is_none() {
                    return Err(MachineRemoteStatusError::FailureCodeLifecycleMismatch);
                }
            }
            _ => {
                if !has_complete {
                    return Err(MachineRemoteStatusError::IncompleteBinding);
                }
                if self.failure_code.is_some() {
                    return Err(MachineRemoteStatusError::FailureCodeLifecycleMismatch);
                }
            }
        }

        if has_complete {
            if self.relay_server_id.as_ref().unwrap().as_bytes() == &[0; 16] {
                return Err(MachineRemoteStatusError::ZeroBinding("relayServerId"));
            }
            if self.machine_route.as_ref().unwrap().as_bytes() == &[0; 16] {
                return Err(MachineRemoteStatusError::ZeroBinding("machineRoute"));
            }
            if self.root_fingerprint.as_ref().unwrap().as_bytes() == &[0; 32] {
                return Err(MachineRemoteStatusError::ZeroBinding("rootFingerprint"));
            }
            if self.trust_epoch == Some(0) {
                return Err(MachineRemoteStatusError::ZeroBinding("trustEpoch"));
            }
        }
        Ok(())
    }
}

impl From<&MachineRemoteStatus> for MachineRemoteStatusWire {
    fn from(value: &MachineRemoteStatus) -> Self {
        Self {
            lifecycle: value.lifecycle,
            relay_server_id: value.relay_server_id,
            machine_route: value.machine_route,
            root_fingerprint: value.root_fingerprint,
            trust_epoch: value.trust_epoch,
            failure_code: value.failure_code.clone(),
        }
    }
}

impl Serialize for MachineRemoteStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        MachineRemoteStatusWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MachineRemoteStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MachineRemoteStatusWire::deserialize(deserializer)?;
        Self::new(
            wire.lifecycle,
            wire.relay_server_id,
            wire.machine_route,
            wire.root_fingerprint,
            wire.trust_epoch,
            wire.failure_code,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for MachineRemoteStatus {
    fn schema_name() -> String {
        "MachineRemoteStatus".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        MachineRemoteStatusWire::json_schema(generator)
    }
}
