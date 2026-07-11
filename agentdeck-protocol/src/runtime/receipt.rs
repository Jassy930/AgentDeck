//! Runtime v1 命令回执（design §8.5 / §8.6 / §13.2）。
//!
//! 业务成功只来自 daemon（RC-5）：Relay 的 `RouteAccepted` 永远不是 command success。
//! - `sendPrompt → CommandReceipt::Accepted/Replayed/Failed`。
//! - `resolveApproval → ApprovalReceipt::Claimed/Applied/AlreadyHandled(state)/DeliveryFailed/Expired`。

use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{ApprovalId, CommandId, GrantSerial};
use crate::trunk::ActionDecisionKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 有副作用命令回执（design §8.6 idempotency：Accepted/Replayed；§14 Failed）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum CommandReceipt {
    /// 首次接受：已在 command journal 事务提交后返回，含队列位置。
    Accepted {
        command_id: CommandId,
        queue_position: u32,
    },
    /// 同 idempotency key + 同 payload：重放原结果，不再次调用 adapter。
    Replayed { command_id: CommandId },
    /// 类型化业务失败（含 `daemon.command.idempotency_conflict` 等）。
    Failed { failure: RuntimeFailure },
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
