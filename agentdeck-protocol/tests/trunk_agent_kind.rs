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
        item_id: "message-1".into(),
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
        item_id: "shell-1".into(),
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
