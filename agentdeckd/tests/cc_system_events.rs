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
        r#"{"type":"system","subtype":"api_retry","attempt":3,"max_retries":10,"retry_delay_ms":2218.38,"error_status":503,"error":"server_error","session_id":"cc-session"}"#,
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
                    error,
                    error_status,
                    max_retries,
                    message,
                    attempt,
                    retry_delay_ms,
                    ..
                }) => {
                    assert_eq!(subtype, "api_retry");
                    assert_eq!(*attempt, Some(3));
                    assert_eq!(error.as_deref(), Some("server_error"));
                    assert_eq!(*error_status, Some(503));
                    assert_eq!(*max_retries, Some(10));
                    let retry_delay = retry_delay_ms.expect("retry_delay_ms");
                    assert!((retry_delay - 2218.38).abs() < 0.001);
                    assert_eq!(message.as_deref(), Some("server_error"));
                }
                other => panic!("expected system status payload, got {other:?}"),
            }
        }
        other => panic!("expected VendorPanelEvent, got {other:?}"),
    }
}
