use agentdeck_protocol::AgentKind;

#[test]
fn serializes_to_snake_case() {
    assert_eq!(
        serde_json::to_string(&AgentKind::Codex).unwrap(),
        r#""codex""#
    );
    assert_eq!(
        serde_json::to_string(&AgentKind::ClaudeCode).unwrap(),
        r#""claude_code""#
    );
}

#[test]
fn deserializes_from_snake_case() {
    let codex: AgentKind = serde_json::from_str(r#""codex""#).unwrap();
    let cc: AgentKind = serde_json::from_str(r#""claude_code""#).unwrap();
    assert!(matches!(codex, AgentKind::Codex));
    assert!(matches!(cc, AgentKind::ClaudeCode));
}

#[test]
fn rejects_unknown_kind() {
    let result: Result<AgentKind, _> = serde_json::from_str(r#""gemini""#);
    assert!(result.is_err());
}

#[test]
fn schema_generates() {
    let _: schemars::schema::RootSchema = schemars::schema_for!(AgentKind);
}
