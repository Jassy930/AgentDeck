use agentdeck_protocol::{
    AgentKind, CapabilityId, SessionCapabilities, VendorCapabilities,
    CodexCapabilities, CodexSandboxMode, CodexReasoningEffort,
    ClaudeCodeCapabilities, ClaudeCodePermissionMode,
};
use std::collections::BTreeSet;

#[test]
fn codex_capabilities_round_trip() {
    let caps = SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "codex 0.x.y".to_string(),
        features: BTreeSet::from([
            CapabilityId::StreamingMessages,
            CapabilityId::CodexSandboxMode,
            CapabilityId::Approval,
        ]),
        vendor: VendorCapabilities::Codex(CodexCapabilities {
            sandbox_modes: vec![
                CodexSandboxMode::ReadOnly,
                CodexSandboxMode::WorkspaceWrite,
            ],
            persistence_supported: true,
            reasoning_effort_levels: vec![
                CodexReasoningEffort::Low,
                CodexReasoningEffort::Medium,
            ],
        }),
    };
    let json = serde_json::to_string(&caps).unwrap();
    let back: SessionCapabilities = serde_json::from_str(&json).unwrap();
    assert_eq!(back.agent_kind, AgentKind::Codex);
    assert!(back.features.contains(&CapabilityId::CodexSandboxMode));
}

#[test]
fn claude_code_capabilities_round_trip() {
    let caps = SessionCapabilities {
        agent_kind: AgentKind::ClaudeCode,
        agent_version: "claude-code 1.x.y".to_string(),
        features: BTreeSet::from([
            CapabilityId::StreamingMessages,
            CapabilityId::ClaudeCodePermissionMode,
            CapabilityId::ClaudeCodePlanMode,
            CapabilityId::Worktree,
        ]),
        vendor: VendorCapabilities::ClaudeCode(ClaudeCodeCapabilities {
            permission_modes: vec![
                ClaudeCodePermissionMode::Default,
                ClaudeCodePermissionMode::Plan,
                ClaudeCodePermissionMode::AcceptEdits,
            ],
            output_styles: vec!["default".into(), "explanatory".into()],
            hooks_supported: vec!["PreToolUse".into(), "PostToolUse".into()],
            cli_version: "1.0.0".into(),
        }),
    };
    let json = serde_json::to_string(&caps).unwrap();
    let _: SessionCapabilities = serde_json::from_str(&json).unwrap();
}

#[test]
fn features_set_serializes_deterministically() {
    // BTreeSet serializes in sort order → consistent across runs
    let caps = SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "x".into(),
        features: BTreeSet::from([
            CapabilityId::Shell,
            CapabilityId::Approval,
            CapabilityId::Mcp,
        ]),
        vendor: VendorCapabilities::Codex(CodexCapabilities::default()),
    };
    let json = serde_json::to_string(&caps).unwrap();
    let first = json.clone();
    let second = serde_json::to_string(&caps).unwrap();
    assert_eq!(first, second);
}
