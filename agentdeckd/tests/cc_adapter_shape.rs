//! Shape / contract tests for `ClaudeCodeAdapter`.
//!
//! Symmetric to `tests/codex_adapter_shape.rs` (N5). Validates the v2
//! `Agent` trait wiring without spawning a real `claude` child for the
//! offline cases, then opt-in spawns a real `claude` (skipped when not
//! on PATH) to verify the N7 invariant end-to-end.

use agentdeck_protocol::*;
use agentdeckd::agent::{Agent, CanonicalAgentEvent};
use agentdeckd::claude_code::ClaudeCodeAdapter;
use agentdeckd::claude_code::auth::{AuthState, probe_auth_status};
use agentdeckd::claude_code::history;
use agentdeckd::runtime::AgentRouter;
use agentdeckd::runtime::store::{
    ConversationDescriptor, NewConversation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreHandle,
};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};

fn random_runtime_id(kind: RuntimeIdKind) -> RuntimeId {
    loop {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).expect("read OS entropy");
        if let Ok(id) = RuntimeId::from_bytes(kind, bytes) {
            return id;
        }
    }
}

struct CanonicalTestRoot(std::path::PathBuf);

impl CanonicalTestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "agentdeckd-cc-canonical-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&path).expect("create canonical CC test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("secure canonical CC test root");
        }
        Self(path)
    }
}

impl Drop for CanonicalTestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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

fn live_e2e_enabled() -> bool {
    std::env::var("AGENTDECK_E2E").as_deref() == Ok("1")
}

#[test]
fn cc_adapter_impls_agent_trait() {
    let a = ClaudeCodeAdapter::new_for_test();
    let _: &dyn Agent = &a;
    assert_eq!(a.kind(), AgentKind::ClaudeCode);
}

#[test]
fn capabilities_advertise_cc_agent_kind_and_full_feature_set() {
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
    // Shared features symmetric with Codex (N5).
    assert!(caps.features.contains(&CapabilityId::StreamingMessages));
    assert!(caps.features.contains(&CapabilityId::Worktree));
    // No Codex-only features leaked.
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

/// Opt-in smoke that spawns a real `claude`. Skips cleanly when the
/// binary is missing (CI runners without CC installed). When present,
/// asserts the N7 invariant: SessionStarted + SessionCapabilities
/// are the first two events on the wire, before any AgentItem.
#[tokio::test]
async fn real_claude_emits_started_then_capabilities() {
    if !live_e2e_enabled() {
        println!("SKIP real_claude_emits_started_then_capabilities: set AGENTDECK_E2E=1");
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

/// Opt-in real-claude smoke for the auth probe. Skipped when claude
/// is missing. Always succeeds — both authenticated and not-logged-in
/// developers can run the suite.
#[test]
fn real_claude_auth_status_probe_returns_known_state() {
    if !live_e2e_enabled() {
        println!("SKIP real_claude_auth_status_probe: set AGENTDECK_E2E=1");
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

/// Opt-in real-claude smoke for `list_history` (jsonl enumeration).
/// Either succeeds with N items, or returns an empty list — both are
/// acceptable. Should never panic / hang.
#[tokio::test]
async fn real_claude_list_history_returns_or_empty() {
    if !live_e2e_enabled() {
        println!("SKIP real_claude_list_history: set AGENTDECK_E2E=1");
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
/// shape. Skipped when `claude` is not on PATH.
#[tokio::test]
async fn real_claude_streams_at_least_one_assistant_or_turn_complete() {
    if !live_e2e_enabled() {
        println!("SKIP real_claude_streams_*: set AGENTDECK_E2E=1");
        return;
    }
    if which::which("claude").is_err() {
        println!("SKIP real_claude_streams_*: `claude` not in PATH");
        return;
    }
    let root = CanonicalTestRoot::new();
    let database = root.0.join("runtime.db");
    let key_store = MemoryKeyStore::new();
    let storage_kek =
        load_or_create_storage_kek(&key_store, &database).expect("create canonical test KEK");
    let store = RuntimeStoreHandle::open(RuntimeStoreConfig::new(database), storage_kek)
        .await
        .expect("open canonical CC store");
    let adapter_state_key = random_runtime_id(RuntimeIdKind::AdapterState);
    let cwd = std::env::current_dir().unwrap();
    store
        .create_conversation(NewConversation {
            conversation_id: random_runtime_id(RuntimeIdKind::Conversation),
            adapter_state_key,
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::ClaudeCode,
                title: Some("canonical CC smoke".into()),
                cwd: cwd.clone(),
            },
        })
        .await
        .expect("create canonical CC conversation");
    let router = AgentRouter::with_runtime_store(store.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let start = SessionStart {
        agent_kind: AgentKind::ClaudeCode,
        cwd,
        prompt: Some("reply with the single word: pong".into()),
        vendor_options: VendorSessionOptions::ClaudeCode(cc_opts()),
        runtime_options: Default::default(),
    };
    let handle = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        router.start_adapter_state(adapter_state_key, start, tx),
    )
    .await
    .expect("canonical start timed out")
    .expect("canonical start failed");
    assert_eq!(handle.adapter_state_key, adapter_state_key);

    let mut saw_assistant_or_complete = false;
    let mut saw_capabilities = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(maybe_ev) = tokio::time::timeout(remaining, rx.recv()).await else {
            break;
        };
        let Some(ev) = maybe_ev else { break };
        match ev {
            CanonicalAgentEvent::Capabilities(_) => saw_capabilities = true,
            CanonicalAgentEvent::Item(AgentItem::AssistantMessage { .. })
            | CanonicalAgentEvent::TurnComplete(_) => {
                assert!(
                    saw_capabilities,
                    "canonical Runtime must receive capabilities before items"
                );
                saw_assistant_or_complete = true;
                break;
            }
            _ => {}
        }
    }

    router.cancel(&handle.session_id).await.expect("cancel ok");
    drop(rx);
    store.shutdown().await.expect("shutdown canonical CC store");

    assert!(
        saw_assistant_or_complete,
        "did not receive AssistantMessage or TurnComplete from real claude — translator wire mapping likely wrong"
    );
}
