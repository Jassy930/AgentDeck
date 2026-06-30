//! Shape / contract tests for `ClaudeCodeAdapter`.
//!
//! Symmetric to `tests/codex_adapter_shape.rs` (N5). Validates the v2
//! `Agent` trait wiring without spawning a real `claude` child for the
//! offline cases, then opt-in spawns a real `claude` (skipped when not
//! on PATH) to verify the N7 invariant end-to-end.

use agentdeckd::agent::Agent;
use agentdeckd::claude_code::ClaudeCodeAdapter;
use agentdeck_protocol::*;

fn cc_opts() -> ClaudeCodeSessionOptions {
    ClaudeCodeSessionOptions {
        permission_mode: ClaudeCodePermissionMode::BypassPermissions,
        model: Some("haiku".into()),
        effort: Some("low".into()),
        hooks: vec![],
        output_style: None,
        allowed_tools: None,
        disallowed_tools: None,
        mcp_config_path: None,
        plugin_dirs: vec![],
        worktree: None,
        session_name: None,
        session_id: None,
    }
}

#[test]
fn cc_adapter_impls_agent_trait() {
    let a = ClaudeCodeAdapter::new_for_test();
    let _: &dyn Agent = &a;
    assert_eq!(a.kind(), AgentKind::ClaudeCode);
}

#[test]
fn placeholder_capabilities_advertise_cc_agent_kind() {
    // Task 4A returns a placeholder; real probe is Task 4B. We only
    // check the shape here so the daemon can satisfy N7.
    let a = ClaudeCodeAdapter::new_for_test();
    let caps = a.capabilities();
    assert_eq!(caps.agent_kind, AgentKind::ClaudeCode);
    assert!(!caps.agent_version.is_empty());
    // Vendor block is the CC variant.
    assert!(matches!(caps.vendor, VendorCapabilities::ClaudeCode(_)));
    // No Codex features leaked.
    assert!(!caps.features.contains(&CapabilityId::CodexSandboxMode));
}

#[tokio::test]
async fn start_session_rejects_wrong_vendor_options() {
    let a = ClaudeCodeAdapter::new_for_test();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let start = SessionStart {
        agent_kind: AgentKind::ClaudeCode,
        cwd: std::env::current_dir().unwrap(),
        prompt: None,
        vendor_options: VendorSessionOptions::Codex(CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::Never,
            sandbox: CodexSandboxMode::ReadOnly,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Minimal,
            mcp_overrides: vec![],
        }),
        runtime_options: Default::default(),
    };
    let result = a.start_session(start, tx).await;
    match result {
        Err(e) => assert_eq!(e.code, "wrong-vendor"),
        Ok(_) => panic!("expected wrong-vendor error"),
    }
}

#[tokio::test]
async fn submit_vendor_control_rejects_codex_payload() {
    let a = ClaudeCodeAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let result = a
        .submit_vendor_control(
            &sid,
            VendorControlPayload::Codex(CodexVendorControl::UpdateSandbox(
                CodexSandboxMode::ReadOnly,
            )),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "wrong-vendor");
}

#[tokio::test]
async fn submit_vendor_control_cc_returns_pending_task_4b() {
    let a = ClaudeCodeAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let result = a
        .submit_vendor_control(
            &sid,
            VendorControlPayload::ClaudeCode(ClaudeCodeVendorControl::UpdatePermissionMode(
                ClaudeCodePermissionMode::Default,
            )),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().code,
        "cc-vendor-control-pending-task-4b"
    );
}

#[tokio::test]
async fn submit_decision_returns_pending_task_4b() {
    let a = ClaudeCodeAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let decision = ActionDecision {
        request_id: "fake".into(),
        decision: ActionDecisionKind::Approve,
        persist: false,
    };
    let result = a.submit_decision(&sid, decision).await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().code,
        "cc-submit-decision-pending-task-4b"
    );
}

#[tokio::test]
async fn cancel_on_unknown_session_is_idempotent_ok() {
    let a = ClaudeCodeAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let result = a.cancel(&sid).await;
    assert!(result.is_ok());
}

/// Opt-in smoke that spawns a real `claude`. Skips cleanly when the
/// binary is missing (CI runners without CC installed). When present,
/// asserts the N7 invariant: SessionStarted + SessionCapabilities
/// are the first two events on the wire, before any AgentItem.
#[tokio::test]
async fn real_claude_emits_started_then_capabilities() {
    // Use `which` to skip cleanly on CI / contributor machines that
    // don't have `claude` installed. The events we assert on
    // (SessionStarted + SessionCapabilities) are emitted synchronously
    // BEFORE spawn, so this test passes in milliseconds even when a
    // real claude child is spawned — it does not depend on the model
    // actually producing output.
    if which::which("claude").is_err() {
        println!(
            "SKIP real_claude_emits_started_then_capabilities: `claude` not in PATH (PATH={:?})",
            std::env::var("PATH")
        );
        return;
    }
    let a = ClaudeCodeAdapter::new_for_test();
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let start = SessionStart {
        agent_kind: AgentKind::ClaudeCode,
        cwd: std::env::current_dir().unwrap(),
        prompt: Some("just say hi in 3 words and stop".into()),
        vendor_options: VendorSessionOptions::ClaudeCode(cc_opts()),
        runtime_options: Default::default(),
    };
    let handle = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        a.start_session(start, tx),
    )
    .await
    .expect("start_session timed out")
    .expect("start_session failed");

    let e1 = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("first event timeout")
        .expect("channel closed");
    assert!(
        matches!(e1, ServerEvent::SessionStarted { agent_kind: AgentKind::ClaudeCode, .. }),
        "first event should be SessionStarted, got {e1:?}"
    );

    let e2 = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("second event timeout")
        .expect("channel closed");
    assert!(
        matches!(e2, ServerEvent::SessionCapabilities { agent_kind: AgentKind::ClaudeCode, .. }),
        "second event should be SessionCapabilities, got {e2:?}"
    );

    // Cleanup — kill the claude child + abort pump.
    a.cancel(&handle.session_id).await.expect("cancel ok");
    // Drop the receiver so any in-flight events don't block the test.
    drop(rx);
}

/// Slower end-to-end smoke that waits for the translator to emit at
/// least one AssistantMessage or TurnComplete event from a real claude
/// child — proves the stream-json mapping holds against the live CLI
/// shape. Skipped when `claude` is not on PATH.
#[tokio::test]
async fn real_claude_streams_at_least_one_assistant_or_turn_complete() {
    if which::which("claude").is_err() {
        println!("SKIP real_claude_streams_*: `claude` not in PATH");
        return;
    }
    let a = ClaudeCodeAdapter::new_for_test();
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let start = SessionStart {
        agent_kind: AgentKind::ClaudeCode,
        cwd: std::env::current_dir().unwrap(),
        prompt: Some("reply with the single word: pong".into()),
        vendor_options: VendorSessionOptions::ClaudeCode(cc_opts()),
        runtime_options: Default::default(),
    };
    let handle = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        a.start_session(start, tx),
    )
    .await
    .expect("start_session timed out")
    .expect("start_session failed");

    let mut saw_assistant_or_complete = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(maybe_ev) = tokio::time::timeout(remaining, rx.recv()).await else {
            break;
        };
        let Some(ev) = maybe_ev else { break };
        match ev {
            ServerEvent::AgentItem {
                item: AgentItem::AssistantMessage { .. },
                ..
            }
            | ServerEvent::TurnComplete { .. } => {
                saw_assistant_or_complete = true;
                break;
            }
            _ => {}
        }
    }

    a.cancel(&handle.session_id).await.expect("cancel ok");
    drop(rx);

    assert!(
        saw_assistant_or_complete,
        "did not receive AssistantMessage or TurnComplete from real claude — translator wire mapping likely wrong"
    );
}
