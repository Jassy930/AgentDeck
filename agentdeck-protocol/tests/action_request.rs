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
