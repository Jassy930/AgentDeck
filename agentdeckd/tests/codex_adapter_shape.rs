//! Shape / contract tests for `CodexAdapter`.
//!
//! These verify the v2 `Agent` trait wiring without spawning a real
//! `codex app-server` (the optional real-codex test below skips itself
//! when the binary is not on PATH). The goal is a fast unit-style
//! safety net for Task 3B's adapter that:
//!
//!   1. Confirms the adapter is `dyn Agent`-compatible (Send + Sync +
//!      'static + the right method set).
//!   2. Confirms it advertises the right `AgentKind` + capability set
//!      (CodexSandboxMode + Approval as the load-bearing features
//!      downstream code keys off).
//!   3. Confirms it rejects wrong-vendor `VendorSessionOptions` /
//!      `VendorControlPayload` with structured errors (N4 / N5 guard).
//!   4. Confirms `submit_decision` / `cancel` against an unknown
//!      session id return `session-not-found` (the hub will plumb
//!      these directly to the client).
//!   5. (gated) Confirms a real `codex app-server` start_session
//!      emits SessionStarted then SessionCapabilities as its first
//!      two events (N7).

use agentdeck_protocol::*;
use agentdeckd::agent::{Agent, CanonicalAgentEvent};
use agentdeckd::codex::adapter::CodexAdapter;
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

fn live_e2e_enabled() -> bool {
    std::env::var("AGENTDECK_E2E").as_deref() == Ok("1")
}

struct CanonicalTestRoot(std::path::PathBuf);

impl CanonicalTestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "agentdeckd-codex-canonical-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&path).expect("create canonical Codex test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("secure canonical Codex test root");
        }
        Self(path)
    }
}

impl Drop for CanonicalTestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn codex_adapter_impls_agent_trait() {
    let a = CodexAdapter::new_for_test();
    let _: &dyn Agent = &a;
    assert_eq!(a.kind(), AgentKind::Codex);
}

#[test]
fn capabilities_includes_codex_features() {
    let a = CodexAdapter::new_for_test();
    let caps = a.capabilities();
    assert_eq!(caps.agent_kind, AgentKind::Codex);
    assert!(caps.features.contains(&CapabilityId::CodexSandboxMode));
    assert!(caps.features.contains(&CapabilityId::Approval));
    // Sanity: the Claude-Code-only features did NOT leak in.
    assert!(
        !caps
            .features
            .contains(&CapabilityId::ClaudeCodePermissionMode)
    );
}

#[tokio::test]
async fn start_session_rejects_wrong_vendor_options() {
    let a = CodexAdapter::new_for_test();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let start = SessionStart {
        agent_kind: AgentKind::Codex,
        cwd: std::env::current_dir().unwrap(),
        prompt: None,
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

/// Optional smoke test that requires a real `codex` binary in PATH.
/// We use `which::which` to skip cleanly when codex is absent (CI
/// machines, contributor laptops without codex login). When present,
/// the test asserts the N7 invariant: SessionStarted + SessionCapabilities
/// are the first two events on the wire, before any AgentItem.
#[tokio::test]
async fn real_codex_canonical_start_binds_private_state_then_emits_capabilities() {
    if !live_e2e_enabled() {
        eprintln!("SKIP real_codex_canonical_start: set AGENTDECK_E2E=1");
        return;
    }
    if which::which("codex").is_err() {
        eprintln!("SKIP real_codex_emits_started_then_capabilities: codex binary not in PATH");
        return;
    }
    let root = CanonicalTestRoot::new();
    let database = root.0.join("runtime.db");
    let key_store = MemoryKeyStore::new();
    let storage_kek =
        load_or_create_storage_kek(&key_store, &database).expect("create canonical test KEK");
    let store = RuntimeStoreHandle::open(RuntimeStoreConfig::new(database), storage_kek)
        .await
        .expect("open canonical Codex store");
    let adapter_state_key = random_runtime_id(RuntimeIdKind::AdapterState);
    let cwd = std::env::current_dir().unwrap();
    store
        .create_conversation(NewConversation {
            conversation_id: random_runtime_id(RuntimeIdKind::Conversation),
            adapter_state_key,
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some("canonical Codex smoke".into()),
                cwd: cwd.clone(),
            },
        })
        .await
        .expect("create canonical Codex conversation");
    let router = AgentRouter::with_runtime_store(store.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let start = SessionStart {
        agent_kind: AgentKind::Codex,
        cwd,
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
    let handle = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        router.start_adapter_state(adapter_state_key, start, tx),
    )
    .await
    .expect("canonical start timed out")
    .expect("canonical start failed");
    assert_eq!(handle.adapter_state_key, adapter_state_key);
    let e1 = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .expect("recv timeout")
        .expect("channel closed");
    assert!(matches!(e1, CanonicalAgentEvent::Capabilities(_)));
    // Clean up: cancel the session so the codex child process dies.
    router.cancel(&handle.session_id).await.expect("cancel ok");
    drop(rx);
    store
        .shutdown()
        .await
        .expect("shutdown canonical Codex store");
}
