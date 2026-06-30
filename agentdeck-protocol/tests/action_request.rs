use agentdeck_protocol::*;

#[test]
fn codex_action_request_carries_sandbox_at_decision() {
    let req = ActionRequest {
        request_id: "r1".into(),
        kind: ActionKind::ExecuteCommand,
        summary: "rm -rf node_modules".into(),
        vendor: ActionRequestVendor::Codex {
            approval_policy_at_decision: CodexApprovalPolicy::OnRequest,
            sandbox_at_decision: CodexSandboxMode::WorkspaceWrite,
            can_persist: true,
        },
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains(r#""canPersist":true"#));
    assert!(json.contains(r#""sandboxAtDecision":"workspace-write""#));
    let back: ActionRequest = serde_json::from_str(&json).unwrap();
    assert!(matches!(back.kind, ActionKind::ExecuteCommand));
}

#[test]
fn cc_action_request_carries_permission_mode() {
    let req = ActionRequest {
        request_id: "r2".into(),
        kind: ActionKind::EditFiles,
        summary: "edit auth.py".into(),
        vendor: ActionRequestVendor::ClaudeCode {
            permission_mode_at_decision: ClaudeCodePermissionMode::AcceptEdits,
            tool_name: "Edit".into(),
        },
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains(r#""toolName":"Edit""#));
    let _: ActionRequest = serde_json::from_str(&json).unwrap();
}

#[test]
fn vendor_control_payloads_typed() {
    let codex_ctrl = VendorControlPayload::Codex(
        CodexVendorControl::UpdateSandbox(CodexSandboxMode::ReadOnly),
    );
    let cc_ctrl = VendorControlPayload::ClaudeCode(
        ClaudeCodeVendorControl::UpdatePermissionMode(ClaudeCodePermissionMode::Plan),
    );
    let _ = serde_json::to_string(&codex_ctrl).unwrap();
    let _ = serde_json::to_string(&cc_ctrl).unwrap();
}

#[test]
fn codex_vendor_control_round_trips_all_variants() {
    let cases = vec![
        CodexVendorControl::UpdateSandbox(CodexSandboxMode::ReadOnly),
        CodexVendorControl::UpdateApprovalPolicy(CodexApprovalPolicy::Never),
        CodexVendorControl::UpdateReasoningEffort(CodexReasoningEffort::High),
    ];
    for c in cases {
        let json = serde_json::to_string(&c).unwrap();
        let back: CodexVendorControl = serde_json::from_str(&json).unwrap_or_else(
            |e| panic!("round-trip failed for {:?}: {} (json was {})", c, e, json)
        );
        let back_json = serde_json::to_string(&back).unwrap();
        assert_eq!(json, back_json, "re-serialize differs");
    }
}

#[test]
fn cc_vendor_control_round_trips_all_variants() {
    let cases = vec![
        ClaudeCodeVendorControl::UpdatePermissionMode(ClaudeCodePermissionMode::Plan),
        ClaudeCodeVendorControl::UpdateOutputStyle { name: Some("concise".into()) },
        ClaudeCodeVendorControl::AddHook(ClaudeCodeHookConfig {
            matcher: "PreToolUse".into(),
            command: "echo".into(),
            timeout_ms: None,
        }),
        ClaudeCodeVendorControl::RemoveHook { matcher: "PreToolUse".into() },
    ];
    for c in cases {
        let json = serde_json::to_string(&c).unwrap();
        let _back: ClaudeCodeVendorControl = serde_json::from_str(&json).unwrap_or_else(
            |e| panic!("round-trip failed for {:?}: {} (json was {})", c, e, json)
        );
    }
}
