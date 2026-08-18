//! Shape / contract tests for `CodexAdapter`.
//!
//! These verify the v3 `Agent` trait wiring without spawning a real
//! `codex app-server` (the optional real-codex test below requires both
//! `AGENTDECK_E2E=1` and a binary on PATH). The goal is a fast unit-style
//! safety net for Task 3B's adapter that:
//!
//!   1. Confirms the adapter is `dyn Agent`-compatible (Send + Sync +
//!      'static + the right method set).
//!   2. Confirms its pre-M0 capability claim stays empty until the
//!      corresponding lifecycle/streaming gates are accepted.
//!   3. Confirms it rejects wrong-vendor `VendorSessionOptions` /
//!      `VendorControlPayload` with structured errors (N4 / N5 guard).
//!   4. Confirms live commands reject an unknown session id while legacy
//!      whole-session cancel stays idempotent for an already-closed session.
//!   5. (gated) Confirms a real `codex app-server` start_session
//!      emits SessionStarted then SessionCapabilities as its first
//!      two events (N7).

use agentdeck_protocol::*;
use agentdeckd::agent::Agent;
use agentdeckd::codex::adapter::CodexAdapter;

mod support;

#[test]
fn codex_adapter_impls_agent_trait() {
    let a = CodexAdapter::new_for_test();
    let _: &dyn Agent = &a;
    assert_eq!(a.kind(), AgentKind::Codex);
}

#[test]
fn capabilities_do_not_claim_unaccepted_features() {
    let a = CodexAdapter::new_for_test();
    let caps = a.capabilities();
    assert_eq!(caps.agent_kind, AgentKind::Codex);
    assert!(caps.features.is_empty());
}

#[tokio::test]
async fn start_session_rejects_wrong_vendor_options() {
    let a = CodexAdapter::new_for_test();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let start = SessionStart {
        session_id: SessionId("wrong-vendor-session".into()),
        agent_kind: AgentKind::Codex,
        cwd: std::env::current_dir().unwrap(),
        resume_thread_id: None,
        initial_turn: None,
        vendor_options: VendorSessionOptions::ClaudeCode(ClaudeCodeSessionOptions {
            permission_mode: ClaudeCodePermissionMode::Default,
            model: None,
            effort: None,
            hooks: vec![],
            output_style: None,
            allowed_tools: None,
            disallowed_tools: None,
            mcp_config_path: None,
            plugin_dirs: vec![],
            worktree: None,
            session_name: None,
            session_id: None,
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
async fn submit_vendor_control_rejects_claude_code_payload() {
    let a = CodexAdapter::new_for_test();
    let sid = SessionId("doesnt-matter".into());
    let result = a
        .submit_vendor_control(
            &sid,
            VendorControlPayload::ClaudeCode(ClaudeCodeVendorControl::UpdatePermissionMode(
                ClaudeCodePermissionMode::Default,
            )),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "wrong-vendor");
}

#[tokio::test]
async fn submit_vendor_control_codex_returns_requires_new_turn() {
    // Codex thread/start options are immutable per thread; the adapter
    // surfaces this as a structured error rather than silently dropping
    // the update.
    let a = CodexAdapter::new_for_test();
    let sid = SessionId("doesnt-matter".into());
    let result = a
        .submit_vendor_control(
            &sid,
            VendorControlPayload::Codex(CodexVendorControl::UpdateSandbox(
                CodexSandboxMode::ReadOnly,
            )),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().code,
        "codex-vendor-control-requires-new-turn"
    );
}

#[tokio::test]
async fn submit_decision_on_unknown_session_returns_session_not_found() {
    let a = CodexAdapter::new_for_test();
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
    // Hub may call cancel on a session that already disconnected; that
    // must NOT error — matches the v1 contract.
    let a = CodexAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let result = a.cancel(&sid).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn live_turn_commands_require_the_exact_active_session_id() {
    let a = CodexAdapter::new_for_test();
    let sid = SessionId("phantom".into());
    let error = a
        .start_turn(&sid, TurnId("turn-1".into()), "hello".into())
        .await
        .unwrap_err();
    assert_eq!(error.code, "session-not-found");
}

/// Optional smoke test that requires `AGENTDECK_E2E=1` and a real `codex`
/// binary in PATH. We use `which::which` to skip cleanly when codex is absent (CI
/// machines, contributor laptops without codex login). When present,
/// the test asserts the N7 invariant: SessionStarted + SessionCapabilities
/// are the first two events on the wire, before any AgentItem.
#[tokio::test]
async fn real_codex_emits_started_then_capabilities() {
    if !support::real_vendor_enabled() {
        eprintln!("SKIP real_codex_emits_started_then_capabilities: AGENTDECK_E2E != 1");
        return;
    }
    if which::which("codex").is_err() {
        eprintln!("SKIP real_codex_emits_started_then_capabilities: codex binary not in PATH");
        return;
    }
    let a = CodexAdapter::new_for_test();
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let start = SessionStart {
        session_id: SessionId("real-codex-shape-session".into()),
        agent_kind: AgentKind::Codex,
        cwd: std::env::current_dir().unwrap(),
        resume_thread_id: None,
        initial_turn: None,
        vendor_options: VendorSessionOptions::Codex(CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::Never,
            sandbox: CodexSandboxMode::ReadOnly,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Medium,
            mcp_overrides: vec![],
        }),
        runtime_options: Default::default(),
    };
    let mut handle = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        a.start_session(start, tx),
    )
    .await
    .expect("start_session timed out")
    .expect("start_session failed");
    let e1 = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .expect("recv timeout")
        .expect("channel closed");
    assert!(matches!(
        e1,
        ServerEvent::SessionStarted {
            agent_kind: AgentKind::Codex,
            ..
        }
    ));
    let e2 = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .expect("recv timeout")
        .expect("channel closed");
    assert!(matches!(
        e2,
        ServerEvent::SessionCapabilities {
            agent_kind: AgentKind::Codex,
            ..
        }
    ));
    // Clean up through the M0 close mailbox, then require owner-confirmed
    // process cleanup rather than treating command acceptance as terminal.
    a.close_session(&handle.session_id).await.expect("close ok");
    let exit = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        handle.exit.take().expect("Codex owner exit receiver"),
    )
    .await
    .expect("owner cleanup timed out")
    .expect("owner dropped cleanup signal");
    assert_eq!(exit.outcome, SessionOutcome::Closed);
}
