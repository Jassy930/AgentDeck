//! Shape / contract tests for `ClaudeCodeAdapter`.
//!
//! Parallel to `tests/codex_adapter_shape.rs` (N5). Validates the v4
//! `Agent` trait wiring without spawning a real `claude` child for the
//! offline cases, then opt-in spawns a real `claude` only when
//! `AGENTDECK_E2E=1` and the binary is on PATH.

use agentdeck_protocol::*;
use agentdeckd::agent::Agent;
use agentdeckd::claude_code::ClaudeCodeAdapter;
use agentdeckd::claude_code::auth::{AuthState, probe_auth_status};
use agentdeckd::claude_code::history;

mod support;

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
fn capabilities_advertise_cc_agent_kind_and_only_verified_features() {
    // Task 4B: capabilities() returns the real builder result.
    let a = ClaudeCodeAdapter::new_for_test();
    let caps = a.capabilities();
    assert_eq!(caps.agent_kind, AgentKind::ClaudeCode);
    assert!(!caps.agent_version.is_empty());
    // Vendor block is the CC variant.
    assert!(matches!(caps.vendor, VendorCapabilities::ClaudeCode(_)));
    // CC-only features are present.
    assert!(
        caps.features
            .contains(&CapabilityId::ClaudeCodePermissionMode)
    );
    assert!(caps.features.contains(&CapabilityId::ClaudeCodeHooks));
    // CC still drops partial message and reasoning deltas, so it must not
    // advertise either streaming capability.
    assert!(!caps.features.contains(&CapabilityId::StreamingMessages));
    assert!(!caps.features.contains(&CapabilityId::StreamingReasoning));
    assert!(!caps.features.contains(&CapabilityId::Approval));
    assert!(caps.features.contains(&CapabilityId::Worktree));
    // No Codex-only features leaked.
    assert!(!caps.features.contains(&CapabilityId::CodexSandboxMode));
}

#[tokio::test]
async fn start_session_rejects_wrong_vendor_options() {
    let a = ClaudeCodeAdapter::new_for_test();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let start = SessionStart {
        session_id: SessionId("cc-wrong-vendor".into()),
        agent_kind: AgentKind::ClaudeCode,
        cwd: std::env::current_dir().unwrap(),
        resume_thread_id: None,
        initial_turn: None,
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
async fn submit_vendor_control_permission_mode_requires_new_turn() {
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
        "cc-vendor-control-requires-new-turn",
        "Permission mode change should return structured 'requires new turn' error \
         (CC has no in-place mutation API)"
    );
}

#[tokio::test]
async fn submit_vendor_control_output_style_not_supported() {
    let a = ClaudeCodeAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let result = a
        .submit_vendor_control(
            &sid,
            VendorControlPayload::ClaudeCode(ClaudeCodeVendorControl::UpdateOutputStyle {
                name: Some("explanatory".into()),
            }),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "cc-vendor-control-not-supported");
}

#[tokio::test]
async fn submit_decision_on_unknown_session_returns_session_not_found() {
    // Without an active CC session in the adapter's map, submit_decision
    // surfaces a structured `session-not-found` error rather than
    // silently dropping or hanging.
    let a = ClaudeCodeAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let decision = ActionDecision {
        request_id: "fake".into(),
        decision: ActionDecisionKind::Approve,
        persist: false,
    };
    let result = a.submit_decision(&sid, decision).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "session-not-found");
}

#[tokio::test]
async fn cancel_on_unknown_session_is_idempotent_ok() {
    let a = ClaudeCodeAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let result = a.cancel(&sid).await;
    assert!(result.is_ok());
}

/// Opt-in smoke that spawns a real `claude`. Requires `AGENTDECK_E2E=1`
/// and skips cleanly when the binary is missing. When present,
/// asserts the N7 invariant: SessionStarted + SessionCapabilities
/// are the first two events on the wire, before any AgentItem.
#[tokio::test]
async fn real_claude_emits_started_then_capabilities() {
    if !support::real_vendor_enabled() {
        println!("SKIP real_claude_emits_started_then_capabilities: AGENTDECK_E2E != 1");
        return;
    }
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
        session_id: SessionId("cc-real-start".into()),
        agent_kind: AgentKind::ClaudeCode,
        cwd: std::env::current_dir().unwrap(),
        resume_thread_id: None,
        initial_turn: Some(InitialTurn {
            turn_id: TurnId("cc-real-turn".into()),
            prompt: "just say hi in 3 words and stop".into(),
        }),
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
        matches!(
            e1,
            ServerEvent::SessionStarted {
                agent_kind: AgentKind::ClaudeCode,
                ..
            }
        ),
        "first event should be SessionStarted, got {e1:?}"
    );

    let e2 = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("second event timeout")
        .expect("channel closed");
    assert!(
        matches!(
            e2,
            ServerEvent::SessionCapabilities {
                agent_kind: AgentKind::ClaudeCode,
                ..
            }
        ),
        "second event should be SessionCapabilities, got {e2:?}"
    );

    // Cleanup — kill the claude child + abort pump.
    a.cancel(&handle.session_id).await.expect("cancel ok");
    // Drop the receiver so any in-flight events don't block the test.
    drop(rx);
}

/// Opt-in real-claude smoke for the auth probe. Requires
/// `AGENTDECK_E2E=1` and skips when claude is missing. Always succeeds — both authenticated and not-logged-in
/// developers can run the suite.
#[test]
fn real_claude_auth_status_probe_returns_known_state() {
    if !support::real_vendor_enabled() {
        println!("SKIP real_claude_auth_status_probe: AGENTDECK_E2E != 1");
        return;
    }
    if which::which("claude").is_err() {
        println!("SKIP real_claude_auth_status_probe: `claude` not in PATH");
        return;
    }
    let state = probe_auth_status();
    assert!(
        matches!(
            state,
            AuthState::LoggedInSubscription
                | AuthState::LoggedInConsoleApiKey
                | AuthState::NotAuthenticated
                | AuthState::Unknown
        ),
        "auth state {state:?} unexpected"
    );
    eprintln!("real_claude_auth_status_probe: state={state:?}");
}

/// Opt-in real-claude smoke for `list_history` (jsonl enumeration), gated by
/// `AGENTDECK_E2E=1`.
/// Either succeeds with N items, or returns an empty list — both are
/// acceptable. Should never panic / hang.
#[tokio::test]
async fn real_claude_list_history_returns_or_empty() {
    if !support::real_vendor_enabled() {
        println!("SKIP real_claude_list_history: AGENTDECK_E2E != 1");
        return;
    }
    if which::which("claude").is_err() {
        println!("SKIP real_claude_list_history: `claude` not in PATH");
        return;
    }
    let items = history::list_history(None, None)
        .await
        .expect("list_history should not error on a working CC install");
    eprintln!("real_claude_list_history: {} sessions found", items.len());
    // Every returned item must be CC-kinded.
    for it in &items {
        assert_eq!(it.agent_kind, AgentKind::ClaudeCode);
        assert!(!it.thread_id.0.is_empty());
    }
}

/// Slower end-to-end smoke that waits for the translator to emit at
/// least one AssistantMessage or TurnComplete event from a real claude
/// child — proves the stream-json mapping holds against the live CLI
/// shape. Requires `AGENTDECK_E2E=1` and `claude` on PATH.
#[tokio::test]
async fn real_claude_streams_at_least_one_assistant_or_turn_complete() {
    if !support::real_vendor_enabled() {
        println!("SKIP real_claude_streams_*: AGENTDECK_E2E != 1");
        return;
    }
    if which::which("claude").is_err() {
        println!("SKIP real_claude_streams_*: `claude` not in PATH");
        return;
    }
    let a = ClaudeCodeAdapter::new_for_test();
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let start = SessionStart {
        session_id: SessionId("cc-real-stream".into()),
        agent_kind: AgentKind::ClaudeCode,
        cwd: std::env::current_dir().unwrap(),
        resume_thread_id: None,
        initial_turn: Some(InitialTurn {
            turn_id: TurnId("cc-real-stream-turn".into()),
            prompt: "reply with the single word: pong".into(),
        }),
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
