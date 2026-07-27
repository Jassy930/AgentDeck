//! Runtime v2 canonical 事件流与稳定聚合身份。

use crate::capabilities::SessionCapabilities;
use crate::runtime::configuration::ConversationConfigurationState;
use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{
    ApprovalId, CommandId, ConversationId, EntityId, EventId, ItemId, TurnId,
};
use crate::runtime::receipt::ApprovalDeliveryState;
use crate::trunk::{ActionDecisionKind, ActionRequest, AgentItem, TurnSummary, VendorPanelPayload};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeEventError {
    #[error("runtime event identity fields do not match its body")]
    InvalidIdentity,
}

/// 一条 canonical event。三个 nullable identity key 在 wire 上必须显式存在。
#[derive(Debug, Clone, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvent {
    pub conversation_id: ConversationId,
    pub event_id: EventId,
    pub event_seq: u64,
    #[schemars(with = "crate::runtime::schema::RequiredNullable<CommandId>")]
    pub command_id: Option<CommandId>,
    #[schemars(with = "crate::runtime::schema::RequiredNullable<ItemId>")]
    pub item_id: Option<ItemId>,
    #[schemars(with = "crate::runtime::schema::RequiredNullable<EntityId>")]
    pub entity_id: Option<EntityId>,
    pub body: RuntimeEventBody,
}

impl RuntimeEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conversation_id: ConversationId,
        event_id: EventId,
        event_seq: u64,
        command_id: Option<CommandId>,
        item_id: Option<ItemId>,
        entity_id: Option<EntityId>,
        body: RuntimeEventBody,
    ) -> Result<Self, RuntimeEventError> {
        let event = Self {
            conversation_id,
            event_id,
            event_seq,
            command_id,
            item_id,
            entity_id,
            body,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), RuntimeEventError> {
        let item_identity = self.item_id.is_some() && self.entity_id.is_some();
        let no_item_identity = self.item_id.is_none() && self.entity_id.is_none();
        let valid = match &self.body {
            RuntimeEventBody::Capabilities { .. }
            | RuntimeEventBody::ConfigurationChanged { .. }
            | RuntimeEventBody::VendorPanelEvent { .. } => {
                no_item_identity && self.command_id.is_none()
            }
            RuntimeEventBody::Item { item } => {
                item_identity
                    && (!matches!(item, AgentItem::UserMessage { .. }) || self.command_id.is_some())
            }
            RuntimeEventBody::TurnStarted { .. }
            | RuntimeEventBody::ActionRequest { .. }
            | RuntimeEventBody::ApprovalResolved { .. }
            | RuntimeEventBody::TurnCompleted { .. }
            | RuntimeEventBody::TurnInterrupted { .. } => {
                no_item_identity && self.command_id.is_some()
            }
            RuntimeEventBody::Error { failure } => {
                no_item_identity
                    && (self.command_id.is_none()
                        || (failure.code
                            == crate::runtime::failure::DAEMON_RUNTIME_EXECUTION_FAILED
                            && failure.message == "agent execution failed"
                            && failure.diagnostic_ref.is_none()))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(RuntimeEventError::InvalidIdentity)
        }
    }
}

impl Serialize for RuntimeEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire<'a> {
            conversation_id: &'a ConversationId,
            event_id: &'a EventId,
            event_seq: u64,
            command_id: &'a Option<CommandId>,
            item_id: &'a Option<ItemId>,
            entity_id: &'a Option<EntityId>,
            body: &'a RuntimeEventBody,
        }
        Wire {
            conversation_id: &self.conversation_id,
            event_id: &self.event_id,
            event_seq: self.event_seq,
            command_id: &self.command_id,
            item_id: &self.item_id,
            entity_id: &self.entity_id,
            body: &self.body,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RuntimeEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            conversation_id: ConversationId,
            event_id: EventId,
            event_seq: u64,
            #[serde(deserialize_with = "deserialize_required_optional_command_id")]
            command_id: Option<CommandId>,
            #[serde(deserialize_with = "deserialize_required_optional_item_id")]
            item_id: Option<ItemId>,
            #[serde(deserialize_with = "deserialize_required_optional_entity_id")]
            entity_id: Option<EntityId>,
            body: RuntimeEventBody,
        }
        let wire = Wire::deserialize(deserializer)?;
        RuntimeEvent::new(
            wire.conversation_id,
            wire.event_id,
            wire.event_seq,
            wire.command_id,
            wire.item_id,
            wire.entity_id,
            wire.body,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// 事件体。command/item/entity identity 只在 RuntimeEvent 外层出现一次。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeEventBody {
    Capabilities {
        capabilities: SessionCapabilities,
    },
    ConfigurationChanged {
        state: ConversationConfigurationState,
    },
    VendorPanelEvent {
        #[serde(rename = "vendorPanel")]
        vendor_panel: VendorPanelPayload,
    },
    Item {
        item: AgentItem,
    },
    TurnStarted {
        turn_id: TurnId,
    },
    ActionRequest {
        turn_id: TurnId,
        approval_id: ApprovalId,
        request: ActionRequest,
    },
    ApprovalResolved {
        turn_id: TurnId,
        approval_id: ApprovalId,
        #[serde(deserialize_with = "deserialize_required_optional_decision")]
        #[schemars(with = "crate::runtime::schema::RequiredNullable<ActionDecisionKind>")]
        decision: Option<ActionDecisionKind>,
        state: ApprovalDeliveryState,
    },
    TurnCompleted {
        turn_id: TurnId,
        summary: TurnSummary,
    },
    TurnInterrupted {
        turn_id: TurnId,
    },
    Error {
        failure: RuntimeFailure,
    },
}

fn deserialize_required_optional_decision<'de, D>(
    deserializer: D,
) -> Result<Option<ActionDecisionKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<ActionDecisionKind>::deserialize(deserializer)
}

fn deserialize_required_optional_command_id<'de, D>(
    deserializer: D,
) -> Result<Option<CommandId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<CommandId>::deserialize(deserializer)
}

fn deserialize_required_optional_item_id<'de, D>(
    deserializer: D,
) -> Result<Option<ItemId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<ItemId>::deserialize(deserializer)
}

fn deserialize_required_optional_entity_id<'de, D>(
    deserializer: D,
) -> Result<Option<EntityId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<EntityId>::deserialize(deserializer)
}
