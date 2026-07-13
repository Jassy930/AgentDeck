//! 既有 `event_journal` payload 到当前 RuntimeEvent 的只读兼容桥。
//!
//! migration/open 不改写旧 ciphertext；本模块只在已认证 `EventRecord` 身份约束下
//! 解码 current wire 或可无损归一化的 legacy full RuntimeEvent。fixed/internal audit
//! payload 明确保持 NonCanonical，由 replay 层形成 snapshot boundary。

use agentdeck_protocol::runtime::identity::{
    ApprovalId, CommandId, ConversationId, EntityId, EventId, ItemId, TurnId,
};
use agentdeck_protocol::runtime::{
    ApprovalDeliveryState, RuntimeEvent, RuntimeEventBody, RuntimeFailure,
};
use agentdeck_protocol::{
    ActionDecisionKind, ActionRequest, AgentItem, SessionCapabilities, TurnSummary,
};
use serde::{Deserialize, Serialize};

use crate::runtime::model::{EventRecord, RuntimeStoreError};

#[derive(Debug)]
pub(super) enum PersistedRuntimeEvent {
    Canonical(Box<RuntimeEvent>),
    NonCanonical,
}

pub(super) fn decode_persisted_runtime_event(
    event: &EventRecord,
) -> Result<PersistedRuntimeEvent, RuntimeStoreError> {
    if let Ok(decoded) = serde_json::from_slice::<RuntimeEvent>(&event.payload) {
        validate_authenticated_identity(&decoded, event)?;
        let canonical =
            serde_json::to_vec(&decoded).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if canonical != event.payload {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        return Ok(PersistedRuntimeEvent::Canonical(Box::new(decoded)));
    }

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&event.payload) else {
        return Ok(PersistedRuntimeEvent::NonCanonical);
    };
    let Some(object) = value.as_object() else {
        return Ok(PersistedRuntimeEvent::NonCanonical);
    };
    if !["conversationId", "eventId", "eventSeq", "body"]
        .iter()
        .all(|field| object.contains_key(*field))
    {
        return Ok(PersistedRuntimeEvent::NonCanonical);
    }

    let legacy: LegacyRuntimeEvent = serde_json::from_slice(&event.payload)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_legacy =
        serde_json::to_vec(&legacy).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if canonical_legacy != event.payload {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let decoded = legacy.into_current(event.command_id)?;
    validate_authenticated_identity(&decoded, event)?;
    Ok(PersistedRuntimeEvent::Canonical(Box::new(decoded)))
}

/// P3.5 及更早版本真正写入过的完整 RuntimeEvent shape。这里必须保持
/// `deny_unknown_fields`，不能用 Value 删除未知字段后把任意 JSON 升级为 canonical。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyRuntimeEvent {
    conversation_id: ConversationId,
    event_id: EventId,
    event_seq: u64,
    #[serde(default)]
    item_id: Option<ItemId>,
    #[serde(default)]
    entity_id: Option<EntityId>,
    body: LegacyRuntimeEventBody,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum LegacyRuntimeEventBody {
    Capabilities {
        capabilities: SessionCapabilities,
    },
    Item {
        item: AgentItem,
    },
    TurnStarted {
        turn_id: TurnId,
        command_id: CommandId,
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

impl LegacyRuntimeEvent {
    fn into_current(
        self,
        authenticated_command_id: Option<super::RuntimeId>,
    ) -> Result<RuntimeEvent, RuntimeStoreError> {
        let command_id =
            authenticated_command_id.map(|id| CommandId::new(id.to_canonical_string()));
        let body = match self.body {
            LegacyRuntimeEventBody::Capabilities { capabilities } => {
                RuntimeEventBody::Capabilities { capabilities }
            }
            LegacyRuntimeEventBody::Item { item } => RuntimeEventBody::Item { item },
            LegacyRuntimeEventBody::TurnStarted {
                turn_id,
                command_id: legacy_command_id,
            } => {
                if command_id.as_ref() != Some(&legacy_command_id) {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                RuntimeEventBody::TurnStarted { turn_id }
            }
            LegacyRuntimeEventBody::ActionRequest {
                turn_id,
                approval_id,
                request,
            } => RuntimeEventBody::ActionRequest {
                turn_id,
                approval_id,
                request,
            },
            LegacyRuntimeEventBody::ApprovalResolved {
                turn_id,
                approval_id,
                decision,
                state,
            } => RuntimeEventBody::ApprovalResolved {
                turn_id,
                approval_id,
                decision,
                state,
            },
            LegacyRuntimeEventBody::TurnCompleted { turn_id, summary } => {
                RuntimeEventBody::TurnCompleted { turn_id, summary }
            }
            LegacyRuntimeEventBody::TurnInterrupted { turn_id } => {
                RuntimeEventBody::TurnInterrupted { turn_id }
            }
            LegacyRuntimeEventBody::Error { failure } => RuntimeEventBody::Error { failure },
        };
        RuntimeEvent::new(
            self.conversation_id,
            self.event_id,
            self.event_seq,
            command_id,
            self.item_id,
            self.entity_id,
            body,
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }
}

fn deserialize_required_optional_decision<'de, D>(
    deserializer: D,
) -> Result<Option<ActionDecisionKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<ActionDecisionKind>::deserialize(deserializer)
}

fn validate_authenticated_identity(
    decoded: &RuntimeEvent,
    event: &EventRecord,
) -> Result<(), RuntimeStoreError> {
    let command_matches = match (&decoded.command_id, event.command_id) {
        (None, None) => true,
        (Some(decoded), Some(stored)) => decoded.as_str() == stored.to_canonical_string(),
        _ => false,
    };
    if decoded.conversation_id.as_str() != event.conversation_id.to_canonical_string()
        || decoded.event_id.as_str() != event.event_id.to_canonical_string()
        || decoded.event_seq != event.event_seq
        || !command_matches
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::runtime::event::RuntimeEventBody;
    use agentdeck_protocol::runtime::identity::{
        ApprovalId, CommandId, ConversationId, EventId, TurnId,
    };
    use agentdeck_protocol::{
        ActionKind, ActionRequest, ActionRequestVendor, CodexApprovalPolicy, CodexSandboxMode,
    };

    use super::*;
    use crate::runtime::store::{RuntimeId, RuntimeIdKind};

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
    }

    fn record() -> EventRecord {
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, 1);
        let event_id = runtime_id(RuntimeIdKind::Event, 2);
        let command_id = runtime_id(RuntimeIdKind::Command, 3);
        let turn_id = runtime_id(RuntimeIdKind::Turn, 4);
        let approval_id = runtime_id(RuntimeIdKind::Approval, 5);
        let event = RuntimeEvent::new(
            ConversationId::new(conversation_id.to_canonical_string()),
            EventId::new(event_id.to_canonical_string()),
            7,
            Some(CommandId::new(command_id.to_canonical_string())),
            None,
            None,
            RuntimeEventBody::ActionRequest {
                turn_id: TurnId::new(turn_id.to_canonical_string()),
                approval_id: ApprovalId::new(approval_id.to_canonical_string()),
                request: ActionRequest {
                    request_id: "legacy-approval-request".to_owned(),
                    kind: ActionKind::ExecuteCommand,
                    summary: "legacy persisted approval".to_owned(),
                    vendor: ActionRequestVendor::Codex {
                        approval_policy_at_decision: CodexApprovalPolicy::OnRequest,
                        sandbox_at_decision: CodexSandboxMode::WorkspaceWrite,
                        can_persist: true,
                    },
                },
            },
        )
        .expect("valid current event");
        EventRecord {
            conversation_id,
            event_id,
            event_seq: 7,
            command_id: Some(command_id),
            created_at_ms: 11,
            payload: serde_json::to_vec(&event).expect("encode current event"),
        }
    }

    fn legacy_record(body: LegacyRuntimeEventBody) -> EventRecord {
        let mut event = record();
        let legacy = LegacyRuntimeEvent {
            conversation_id: ConversationId::new(event.conversation_id.to_canonical_string()),
            event_id: EventId::new(event.event_id.to_canonical_string()),
            event_seq: event.event_seq,
            item_id: None,
            entity_id: None,
            body,
        };
        event.payload = serde_json::to_vec(&legacy).expect("canonical legacy event");
        event
    }

    fn legacy_action_request() -> LegacyRuntimeEventBody {
        LegacyRuntimeEventBody::ActionRequest {
            turn_id: TurnId::new(runtime_id(RuntimeIdKind::Turn, 4).to_canonical_string()),
            approval_id: ApprovalId::new(
                runtime_id(RuntimeIdKind::Approval, 5).to_canonical_string(),
            ),
            request: ActionRequest {
                request_id: "legacy-approval-request".to_owned(),
                kind: ActionKind::ExecuteCommand,
                summary: "legacy persisted approval".to_owned(),
                vendor: ActionRequestVendor::Codex {
                    approval_policy_at_decision: CodexApprovalPolicy::OnRequest,
                    sandbox_at_decision: CodexSandboxMode::WorkspaceWrite,
                    can_persist: true,
                },
            },
        }
    }

    #[test]
    fn strict_current_event_decodes_with_authenticated_identity() {
        let event = record();
        let decoded = decode_persisted_runtime_event(&event).expect("decode current event");
        assert!(matches!(decoded, PersistedRuntimeEvent::Canonical(_)));
    }

    #[test]
    fn legacy_full_event_injects_authenticated_outer_command_without_rewriting_ciphertext() {
        let event = legacy_record(legacy_action_request());
        let persisted_legacy = event.payload.clone();

        let decoded = decode_persisted_runtime_event(&event).expect("decode legacy event");
        let PersistedRuntimeEvent::Canonical(decoded) = decoded else {
            panic!("legacy full RuntimeEvent must stay publishable");
        };
        assert_eq!(
            decoded.command_id.as_ref().map(|id| id.as_str()),
            event
                .command_id
                .map(|id| id.to_canonical_string())
                .as_deref()
        );
        assert_eq!(
            event.payload, persisted_legacy,
            "compatibility bridge is read-only"
        );
    }

    #[test]
    fn legacy_turn_started_command_matches_authenticated_journal_command() {
        let event = legacy_record(LegacyRuntimeEventBody::TurnStarted {
            turn_id: TurnId::new(runtime_id(RuntimeIdKind::Turn, 4).to_canonical_string()),
            command_id: CommandId::new(event_command_id().to_canonical_string()),
        });
        let decoded = decode_persisted_runtime_event(&event).expect("matching legacy command");
        let PersistedRuntimeEvent::Canonical(decoded) = decoded else {
            panic!("matching legacy TurnStarted must remain publishable");
        };
        assert!(matches!(decoded.body, RuntimeEventBody::TurnStarted { .. }));
    }

    #[test]
    fn legacy_body_command_must_match_authenticated_journal_command() {
        let event = legacy_record(LegacyRuntimeEventBody::TurnStarted {
            turn_id: TurnId::new(runtime_id(RuntimeIdKind::Turn, 4).to_canonical_string()),
            command_id: CommandId::new(
                runtime_id(RuntimeIdKind::Command, 99).to_canonical_string(),
            ),
        });
        assert!(decode_persisted_runtime_event(&event).is_err());
    }

    #[test]
    fn legacy_non_turn_body_cannot_smuggle_a_command_field() {
        let mut event = legacy_record(legacy_action_request());
        let mut value: serde_json::Value =
            serde_json::from_slice(&event.payload).expect("legacy event JSON");
        let object = value.as_object_mut().expect("event object");
        object
            .get_mut("body")
            .and_then(serde_json::Value::as_object_mut)
            .expect("event body")
            .insert(
                "command_id".to_owned(),
                serde_json::Value::String(event_command_id().to_canonical_string()),
            );
        event.payload = serde_json::to_vec(&value).expect("legacy event JSON");
        assert!(decode_persisted_runtime_event(&event).is_err());
    }

    fn event_command_id() -> RuntimeId {
        runtime_id(RuntimeIdKind::Command, 3)
    }

    #[test]
    fn opaque_fixed_event_is_explicitly_noncanonical() {
        let mut event = record();
        event.payload = br#"{"kind":"fixed_event","payload":"audit-only"}"#.to_vec();
        assert!(matches!(
            decode_persisted_runtime_event(&event).expect("classify fixed event"),
            PersistedRuntimeEvent::NonCanonical
        ));
    }
}
