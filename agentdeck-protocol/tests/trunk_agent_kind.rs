use agentdeck_protocol::{ServerEvent, AgentKind, SessionId, ThreadId, AgentItem, AgentItemMeta, SessionCapabilities};
use std::collections::BTreeSet;

fn ek(agent_kind: AgentKind) -> ServerEvent {
    ServerEvent::AgentItem {
        session_id: SessionId("s1".into()),
        thread_id: ThreadId("t1".into()),
        agent_kind,
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
        capabilities: caps,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ServerEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, ServerEvent::SessionCapabilities { .. }));
}
