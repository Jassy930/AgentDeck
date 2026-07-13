//! Runtime v1 device/local → daemon 请求（design §8 / §13.2）。
//!
//! `RuntimeRequest` 是解密后设备/本地统一规范化的业务请求（RC-2 传输平权）。
//! pending pairing 的 list/confirm/cancel 以及 create/trust-reset/device-revoke 是
//! **local-only administration**：daemon 只允许 same-UID UDS `LocalPrincipal` 调用，
//! 任何 `RemotePrincipal`、PairingAccess 或 Relay 管理员都无权调用（design §6.2/§6.3/§6.5）。
//! 本 task 只定义契约与标注，不实现执行语义。

use crate::runtime::identity::{
    ApprovalId, CatalogPageCursor, CommandId, ConversationId, DeviceHandle, GrantSerial,
    IdempotencyKey, PairingId, TurnId,
};
use crate::runtime::sync::{BackfillRequest, RuntimeInnerCursor, RuntimeSubscriptionTarget};
use crate::trunk::{ActionDecision, AgentKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// prompt 明文 UTF-8 最大字节数（design §8.8：256 KiB）。
pub const MAX_PROMPT_BYTES: usize = 256 * 1024;

/// prompt 校验失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PromptError {
    #[error("prompt exceeds {MAX_PROMPT_BYTES} bytes (256 KiB)")]
    TooLarge,
}

/// 已校验的 prompt 明文（≤ 256 KiB UTF-8）。构造与 wire 反序列化都强制上限。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct PromptPayload(String);

impl PromptPayload {
    pub fn new(text: impl Into<String>) -> Result<Self, PromptError> {
        let text = text.into();
        if text.len() > MAX_PROMPT_BYTES {
            return Err(PromptError::TooLarge);
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl TryFrom<String> for PromptPayload {
    type Error = PromptError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        PromptPayload::new(value)
    }
}

impl From<PromptPayload> for String {
    fn from(value: PromptPayload) -> Self {
        value.0
    }
}

/// local-only administration 信任边界标记。
///
/// 携带此标记的请求是 **local-only administration**：daemon 必须拒绝任何不是来自
/// same-UID UDS `LocalPrincipal` 的调用。它显式记录在类型、文档与 schema 中，
/// 让客户端与审阅者都能确认该请求永不允许远端或 Relay 管理员发起。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum LocalOnlyAdministration {
    LocalOnly,
}

/// `Hello` 握手参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HelloParams {
    pub runtime_protocol_version: u16,
}

/// catalog 请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogRequest {
    #[serde(deserialize_with = "deserialize_required_optional_page_cursor")]
    #[schemars(with = "crate::runtime::schema::RequiredNullable<CatalogPageCursor>")]
    pub page_cursor: Option<CatalogPageCursor>,
}

/// 新建 conversation（daemon 在 adapter 启动前生成 conversationId）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationStart {
    pub agent_kind: AgentKind,
    pub idempotency_key: IdempotencyKey,
    pub cwd: PathBuf,
    #[serde(default)]
    pub title: Option<String>,
}

/// 发送 prompt。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendPromptRequest {
    pub conversation_id: ConversationId,
    pub idempotency_key: IdempotencyKey,
    pub prompt: PromptPayload,
}

/// 按 command 或 conversation-scoped idempotency key 精确查询原始回执。
///
/// internally-tagged 形态排除“全空、两种 selector 同时出现、字段互相矛盾”的
/// 歧义；两种 selector 都必须绑定 conversation。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "selector", rename_all = "camelCase", deny_unknown_fields)]
pub enum QueryReceiptSelector {
    Command {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "commandId")]
        command_id: CommandId,
    },
    Idempotency {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "idempotencyKey")]
        idempotency_key: IdempotencyKey,
    },
}

/// 创建 PairInvite —— local-only administration（design §6.2）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreatePairInviteRequest {
    /// 仅供人识别的机器显示名；存在于带外邀请中，不进入 Relay 明文。
    pub display_name: String,
    /// 邀请 TTL（秒）；design 固定 5 分钟单次。
    #[serde(default = "default_pair_ttl_secs")]
    pub ttl_secs: u32,
    /// local-only administration 标记。
    pub scope: LocalOnlyAdministration,
}

fn default_pair_ttl_secs() -> u32 {
    300
}

/// 撤销请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeRequest {
    pub target: RevokeTarget,
}

/// 撤销目标：设备只能 revoke self；撤销其他设备是 local-only administration。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum RevokeTarget {
    /// 撤销自身（iOS 只允许这一种）。
    SelfDevice,
    /// 撤销指定设备 —— local-only administration。
    Device {
        device: DeviceHandle,
        grant_serial: GrantSerial,
        scope: LocalOnlyAdministration,
    },
}

/// device/local → daemon 请求集合（design §13.2 命令面 + §6 pairing/revoke 管理面）。
///
/// 未派生 `PartialEq`：`ResolveApproval` 内嵌未派生 `PartialEq` 的中立 `ActionDecision`；
/// 本 task 不改动 trunk，契约测试以 wire round-trip 覆盖。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "request", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeRequest {
    /// 版本/能力握手。
    Hello(HelloParams),
    /// 请求 catalog snapshot / 订阅。
    Catalog(CatalogRequest),
    /// 订阅某 conversation 的事件流，从 cursor 之后开始。
    Subscribe {
        #[serde(rename = "innerCursor")]
        inner_cursor: RuntimeInnerCursor,
    },
    /// 释放 catalog/conversation watcher；对相同 target 幂等。
    Unsubscribe { target: RuntimeSubscriptionTarget },
    /// Relay gap 后按 inner HWM 请求定向 backfill/snapshot。
    Backfill(BackfillRequest),
    /// 新建 conversation。
    Start(ConversationStart),
    /// 发送 prompt（有副作用；receipt Accepted/Replayed/Failed）。
    SendPrompt(SendPromptRequest),
    /// 提交 approval 决定（first-wins）。
    ResolveApproval {
        conversation_id: ConversationId,
        turn_id: TurnId,
        approval_id: ApprovalId,
        decision: ActionDecision,
    },
    /// 对已 claim 的同一决定重启投递（不提交新决定）。
    RetryApproval {
        conversation_id: ConversationId,
        approval_id: ApprovalId,
    },
    /// 精确取消尚未 Started 的 queued command。
    CancelQueued {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "commandId")]
        command_id: CommandId,
    },
    /// 明确请求取消当前 active turn；缺失/stale turnId 必须 fail-close。
    CancelActive {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "turnId")]
        turn_id: TurnId,
    },
    /// 查询原始回执（断线重取；不依赖 Relay 请求来源缓存）。
    QueryReceipt(QueryReceiptSelector),
    /// 创建 PairInvite —— local-only administration。
    CreatePairInvite(CreatePairInviteRequest),
    /// 列出待本地确认的 pending pairing —— local-only administration。
    ///
    /// daemon 只允许 same-UID UDS `LocalPrincipal` 调用；远端/Relay 管理员无权调用。
    ListPendingPairings { scope: LocalOnlyAdministration },
    /// 确认一个 pending pairing —— local-only administration。
    ///
    /// daemon 只允许 same-UID UDS `LocalPrincipal` 调用；远端/Relay 管理员无权调用。
    ConfirmPairing {
        pairing_id: PairingId,
        scope: LocalOnlyAdministration,
    },
    /// 取消一个 pending pairing —— local-only administration。
    ///
    /// daemon 只允许 same-UID UDS `LocalPrincipal` 调用；远端/Relay 管理员无权调用。
    CancelPairing {
        pairing_id: PairingId,
        scope: LocalOnlyAdministration,
    },
    /// 撤销设备（self 或指定设备）。
    Revoke(RevokeRequest),
    /// machine trust reset —— local-only administration。
    TrustReset { scope: LocalOnlyAdministration },
}

fn deserialize_required_optional_page_cursor<'de, D>(
    deserializer: D,
) -> Result<Option<CatalogPageCursor>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<CatalogPageCursor>::deserialize(deserializer)
}
