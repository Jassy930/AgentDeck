//! Runtime v1 canonical 事件流（design §8.1 / §9）。
//!
//! `RuntimeEvent` 是 daemon canonical event stream 的中立业务 wire。稳定聚合靠
//! `item_id`/`entity_id`，去重靠 `event_id`，排序靠 conversation-单调 `event_seq`。

use crate::capabilities::SessionCapabilities;
use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{
    ApprovalId, CommandId, ConversationId, EntityId, EventId, ItemId, TurnId,
};
use crate::runtime::receipt::ApprovalDeliveryState;
use crate::trunk::{ActionDecisionKind, ActionRequest, AgentItem, TurnSummary};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 一条 canonical 事件（design core interface）。
///
/// 未派生 `PartialEq`：`RuntimeEventBody` 内嵌未派生 `PartialEq` 的中立 trunk 类型；
/// 本 task 不改动 trunk，契约测试以 wire round-trip 覆盖。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvent {
    pub conversation_id: ConversationId,
    pub event_id: EventId,
    pub event_seq: u64,
    #[serde(default)]
    pub item_id: Option<ItemId>,
    #[serde(default)]
    pub entity_id: Option<EntityId>,
    pub body: RuntimeEventBody,
}

/// 事件体。全部中立：不承载 vendor thread/turn 身份，只用中立稳定 ID。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeEventBody {
    /// 会话能力先行（RC-16：snapshot/live 都必须先于 AgentItem 交付）。
    Capabilities { capabilities: SessionCapabilities },
    /// 一条 agent item 的新增/更新（聚合 ID 在外层 `item_id`/`entity_id`）。
    Item { item: AgentItem },
    /// 一个 turn 开始，绑定触发它的 command。
    TurnStarted {
        turn_id: TurnId,
        command_id: CommandId,
    },
    /// 需要审批的动作请求。
    ActionRequest {
        turn_id: TurnId,
        approval_id: ApprovalId,
        request: ActionRequest,
    },
    /// 审批 first-wins 结果广播（含精确 delivery state）。
    ApprovalResolved {
        turn_id: TurnId,
        approval_id: ApprovalId,
        /// `Pending -> Expired` 尚无 first-wins winner，因此必须为 `null`；
        /// Claimed 之后的所有状态都携带不可变赢家决定。
        #[serde(deserialize_with = "deserialize_required_optional_decision")]
        #[schemars(required)]
        decision: Option<ActionDecisionKind>,
        state: ApprovalDeliveryState,
    },
    /// turn 正常完成。
    TurnCompleted {
        turn_id: TurnId,
        summary: TurnSummary,
    },
    /// turn 中断（crash/cancel/中断，unknown outcome）。
    TurnInterrupted { turn_id: TurnId },
    /// 业务失败事件。
    Error { failure: RuntimeFailure },
}

fn deserialize_required_optional_decision<'de, D>(
    deserializer: D,
) -> Result<Option<ActionDecisionKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<ActionDecisionKind>::deserialize(deserializer)
}
