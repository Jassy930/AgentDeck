//! Runtime v2 命令回执（design §8.5 / §8.6 / §13.2）。
//!
//! 业务成功只来自 daemon（RC-5）：Relay 的 `RouteAccepted` 永远不是 command success。
//! - `sendPrompt → CommandReceipt::Accepted/Replayed/Failed`。
//! - `resolveApproval → ApprovalReceipt::Claimed/Applied/AlreadyHandled(state)/DeliveryFailed/Expired`。

use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{ApprovalId, CommandId, ConversationId, GrantSerial, TurnId};
use crate::trunk::ActionDecisionKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 有副作用命令回执（design §8.6 idempotency：Accepted/Replayed；§14 Failed）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum CommandReceipt {
    /// 首次接受：已在 command journal 事务提交后返回，含队列位置。
    Accepted {
        #[serde(rename = "commandId")]
        #[schemars(rename = "commandId")]
        command_id: CommandId,
        #[serde(rename = "queuePosition")]
        #[schemars(rename = "queuePosition")]
        queue_position: u32,
        #[serde(rename = "configurationRevision")]
        #[schemars(rename = "configurationRevision")]
        configuration_revision: u64,
    },
    /// 同 idempotency key + 同 payload：重放原结果，不再次调用 adapter。
    Replayed {
        #[serde(rename = "commandId")]
        #[schemars(rename = "commandId")]
        command_id: CommandId,
        #[serde(rename = "configurationRevision")]
        #[schemars(rename = "configurationRevision")]
        configuration_revision: u64,
    },
    /// 类型化业务失败（含 `daemon.command.idempotency_conflict` 等）。
    Failed { failure: RuntimeFailure },
}

/// command journal 的中立精确状态。
///
/// `QueryReceipt` 必须返回持久化状态，不能把查询结果压缩成
/// `CommandReceipt::Replayed`，否则断线客户端无法区分排队、执行中与各终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CommandStatus {
    Accepted,
    Started,
    Completed,
    Failed,
    Interrupted,
    Expired,
    Canceled,
    RevokedBeforeStart,
}

/// `QueryReceipt` 返回的精确 command journal 记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandStatusReceipt {
    pub conversation_id: ConversationId,
    pub command_id: CommandId,
    pub configuration_revision: u64,
    pub status: CommandStatus,
    /// `Accepted` 等尚未分配 turn 的状态为 `null`。
    pub turn_id: Option<TurnId>,
}

/// 幂等创建 conversation 的精确回执。
///
/// Start 只创建 catalog，不携带 prompt；daemon 只返回公共稳定 `conversationId`。
/// daemon-private adapter handle 不得进入 wire。相同 owner/conversation-scope key
/// 重试时 `replayed=true`，客户端随后使用独立 key 配置并发送 `SendPrompt`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationStartReceipt {
    pub conversation_id: ConversationId,
    pub replayed: bool,
}

/// queued 与 active cancel 的精确成功回执。
///
/// `QueuedCanceled` 已把 Accepted command 终止；`ActiveCancelRequested` 只表示
/// 对精确 turn 的取消请求已被 daemon 接受，不能冒充 turn 已经终止。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum CancellationReceipt {
    QueuedCanceled {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "commandId")]
        command_id: CommandId,
    },
    ActiveCancelRequested {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "turnId")]
        turn_id: TurnId,
    },
}

/// approval delivery 状态机的精确状态（design §8.5）。
///
/// `Pending → Claimed → Applying → Applied | DeliveryFailed ↗ Applying | Expired`。
/// `DeliveryFailed` 是保留赢家决定的可重试状态，不是最终 Applied。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ApprovalDeliveryState {
    Claimed,
    Applying,
    Applied,
    DeliveryFailed,
    Expired,
}

/// approval 命令回执（design §13.2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum ApprovalReceipt {
    /// 本决定赢得 compare-and-swap。
    Claimed { approval_id: ApprovalId },
    /// 决定已成功投递到 adapter。
    Applied { approval_id: ApprovalId },
    /// 后到决定：返回不可变赢家决定与当前精确 delivery state。
    AlreadyHandled {
        approval_id: ApprovalId,
        decision: ActionDecisionKind,
        state: ApprovalDeliveryState,
    },
    /// 赢家决定投递失败但保留，可 `RetryApproval` 重试同一决定。
    DeliveryFailed { approval_id: ApprovalId },
    /// deadline/turn 结束仍未投递成功。
    Expired { approval_id: ApprovalId },
}

/// 撤销回执（design §13.2：revokeSelf → RevocationReceipt）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum RevocationReceipt {
    /// 撤销事务已提交（含被撤销 grant serial）。
    Committed { grant_serial: GrantSerial },
    /// 撤销失败。
    Failed { failure: RuntimeFailure },
}
