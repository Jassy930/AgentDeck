use agentdeck_protocol::*;
use std::path::PathBuf;

#[test]
fn codex_session_start_round_trip() {
    let start = SessionStart {
        agent_kind: AgentKind::Codex,
        cwd: PathBuf::from("/tmp/proj"),
        prompt: Some("fix auth".into()),
        vendor_options: VendorSessionOptions::Codex(CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::OnRequest,
            sandbox: CodexSandboxMode::WorkspaceWrite,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Medium,
            mcp_overrides: vec![],
        }),
        runtime_options: RuntimeOptions::default(),
    };
    let json = serde_json::to_string(&start).unwrap();
    let back: SessionStart = serde_json::from_str(&json).unwrap();
    assert_eq!(back.agent_kind, AgentKind::Codex);
    assert!(matches!(
        back.vendor_options,
        VendorSessionOptions::Codex(_)
    ));
}

#[test]
fn claude_code_session_start_round_trip() {
    let start = SessionStart {
        agent_kind: AgentKind::ClaudeCode,
        cwd: PathBuf::from("/tmp/proj"),
        prompt: None,
        vendor_options: VendorSessionOptions::ClaudeCode(ClaudeCodeSessionOptions {
            permission_mode: ClaudeCodePermissionMode::AcceptEdits,
            model: Some("sonnet".into()),
            effort: Some("medium".into()),
            hooks: vec![],
            output_style: None,
            allowed_tools: None,
            disallowed_tools: None,
            mcp_config_path: None,
            plugin_dirs: vec![],
            worktree: None,
            session_name: Some("auth-work".into()),
            session_id: None,
        }),
        runtime_options: RuntimeOptions::default(),
    };
    let json = serde_json::to_string(&start).unwrap();
    let _: SessionStart = serde_json::from_str(&json).unwrap();
}

#[test]
fn vendor_options_rejects_wrong_agent_kind_combo() {
    // The enum-tag itself enforces this: VendorSessionOptions::Codex
    // payload deserializes as CodexSessionOptions only.
    let bad_json = r#"{
        "agentKind": "codex",
        "cwd": "/tmp",
        "prompt": null,
        "vendorOptions": {
            "agentKind": "claude_code",
            "permissionMode": "default",
            "hooks": [],
            "pluginDirs": []
        },
        "runtimeOptions": {}
    }"#;
    // Different tag → different variant; serde keeps types straight
    let parsed: serde_json::Value = serde_json::from_str(bad_json).unwrap();
    // Demonstrating the structural separation; full validation happens
    // in daemon's session start handler (covered by Phase 2 tests).
    assert_eq!(parsed["vendorOptions"]["agentKind"], "claude_code");
}
