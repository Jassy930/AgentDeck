use agentdeck_protocol::*;
use std::path::PathBuf;

#[test]
fn codex_session_start_round_trip() {
    let start = SessionStart {
        session_id: SessionId("session-codex".into()),
        agent_kind: AgentKind::Codex,
        cwd: PathBuf::from("/tmp/proj"),
        resume_thread_id: None,
        initial_turn: Some(InitialTurn {
            turn_id: TurnId("turn-1".into()),
            prompt: "fix auth".into(),
        }),
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
    assert_eq!(back.session_id.0, "session-codex");
    assert_eq!(back.agent_kind, AgentKind::Codex);
    assert_eq!(back.initial_turn.unwrap().turn_id.0, "turn-1");
    assert!(matches!(
        back.vendor_options,
        VendorSessionOptions::Codex(_)
    ));
}

#[test]
fn claude_code_session_start_round_trip() {
    let start = SessionStart {
        session_id: SessionId("session-cc".into()),
        agent_kind: AgentKind::ClaudeCode,
        cwd: PathBuf::from("/tmp/proj"),
        resume_thread_id: Some(ThreadId("thread-cc".into())),
        initial_turn: None,
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
    let back: SessionStart = serde_json::from_str(&json).unwrap();
    assert_eq!(back.resume_thread_id.unwrap().0, "thread-cc");
}

#[test]
fn vendor_options_tag_deserializes_independently_from_outer_agent_kind() {
    let bad_json = r#"{
        "sessionId": "session-bad",
        "agentKind": "codex",
        "cwd": "/tmp",
        "resumeThreadId": null,
        "initialTurn": null,
        "vendorOptions": {
            "agentKind": "claude_code",
            "permissionMode": "default",
            "hooks": [],
            "pluginDirs": []
        },
        "runtimeOptions": {}
    }"#;
    let parsed: SessionStart = serde_json::from_str(bad_json).unwrap();
    assert_eq!(parsed.agent_kind, AgentKind::Codex);
    assert!(matches!(
        parsed.vendor_options,
        VendorSessionOptions::ClaudeCode(_)
    ));
    // Serde proves the wire shape only. The shared daemon router rejects this
    // semantic mismatch before dispatching to either vendor adapter.
}
