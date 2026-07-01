//! Regression tests for Claude Code system events that carry useful
//! diagnostics but are not hook events.

use agentdeck_protocol::{
    AgentKind, ClaudeCodePermissionMode, ClaudeCodeVendorPanelEvent, ServerEvent, SessionId,
    VendorPanelPayload,
};
use agentdeckd::claude_code::translate::ClaudeCodeTranslator;

#[test]
fn api_retry_system_event_is_visible_to_clients() {
    let mut t = ClaudeCodeTranslator::new(
        SessionId("agentdeck-session".into()),
        ClaudeCodePermissionMode::BypassPermissions,
    );
    let out = t.translate_line(
        r#"{"type":"system","subtype":"api_retry","attempt":3,"error":{"type":"server_error","message":"Overloaded"},"session_id":"cc-session"}"#,
    );

    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::VendorPanelEvent {
            agent_kind,
            payload,
            ..
        } => {
            assert_eq!(*agent_kind, AgentKind::ClaudeCode);
            match payload {
                VendorPanelPayload::ClaudeCode(ClaudeCodeVendorPanelEvent::SystemStatus {
                    subtype,
                    message,
                    attempt,
                    ..
                }) => {
                    assert_eq!(subtype, "api_retry");
                    assert_eq!(*attempt, Some(3));
                    assert!(message.as_deref().unwrap_or("").contains("Overloaded"));
                }
                other => panic!("expected system status payload, got {other:?}"),
            }
        }
        other => panic!("expected VendorPanelEvent, got {other:?}"),
    }
}
