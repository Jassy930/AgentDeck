use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentItemState, AgentKind, ServerEvent, SessionCapabilities,
    SessionId, ShellStatus, ThreadId, TurnId,
};
use std::collections::BTreeSet;

fn ek(agent_kind: AgentKind) -> ServerEvent {
    ServerEvent::AgentItem {
        session_id: SessionId("s1".into()),
        thread_id: ThreadId("t1".into()),
        agent_kind,
        turn_id: TurnId("turn-1".into()),
        item_id: "item-1".into(),
        state: AgentItemState::Completed,
        item: AgentItem::AssistantMessage {
            text: "hi".into(),
            meta: AgentItemMeta::default(),
        },
    }
}

#[test]
fn agent_item_carries_agent_kind() {
    let event = ek(AgentKind::Codex);
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains(r#""agentKind":"codex""#));
}

#[test]
fn capabilities_event_round_trip() {
    let caps = SessionCapabilities {
        agent_kind: AgentKind::ClaudeCode,
        agent_version: "cc 1.0".into(),
        features: BTreeSet::new(),
        vendor: agentdeck_protocol::VendorCapabilities::ClaudeCode(Default::default()),
    };
    let event = ServerEvent::SessionCapabilities {
        session_id: SessionId("s1".into()),
        agent_kind: AgentKind::ClaudeCode,
        capabilities: caps,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ServerEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, ServerEvent::SessionCapabilities { .. }));
}

#[test]
fn agent_item_shell_fields_camel_case() {
    let event = ServerEvent::AgentItem {
        session_id: SessionId("s1".into()),
        thread_id: ThreadId("t1".into()),
        agent_kind: AgentKind::ClaudeCode,
        turn_id: TurnId("turn-1".into()),
        item_id: "item-1".into(),
        state: AgentItemState::Completed,
        item: AgentItem::Shell {
            command: "ls".into(),
            status: ShellStatus::Completed,
            exit_code: Some(0),
            duration_ms: Some(10),
            meta: AgentItemMeta::default(),
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(
        json.contains(r#""exitCode":0"#),
        "exitCode missing in: {json}"
    );
    assert!(
        json.contains(r#""durationMs":10"#),
        "durationMs missing in: {json}"
    );
}

#[test]
fn streaming_identity_is_required_and_round_trips() {
    let mut value = serde_json::to_value(ek(AgentKind::Codex)).unwrap();
    value["state"] = serde_json::json!("streaming");
    let event: ServerEvent = serde_json::from_value(value.clone()).unwrap();
    assert!(
        matches!(event, ServerEvent::AgentItem { turn_id, item_id, state: AgentItemState::Streaming, .. } if turn_id.0 == "turn-1" && item_id == "item-1")
    );
    for field in ["turnId", "itemId", "state"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<ServerEvent>(missing).is_err(),
            "{field} must be required"
        );
    }
}
