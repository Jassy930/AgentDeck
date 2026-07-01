//! Integration smoke: AgentRouter holding BOTH CodexAdapter and
//! ClaudeCodeAdapter simultaneously, exercising the cross-agent
//! `handle_history` merge path added in Task 4C.
//!
//! Phase 4 Task 4C — Phase 4 finalization. Closeout assertion that
//! the daemon binary's `main.rs` wiring (register both adapters into
//! one router) behaves correctly: kinds enumerate, list-merge runs,
//! Codex's stub returns empty + CC's real history merges in
//! gracefully.

use agentdeck_protocol::*;
use agentdeckd::agent::DynAgent;
use agentdeckd::claude_code::ClaudeCodeAdapter;
use agentdeckd::codex::CodexAdapter;
use agentdeckd::runtime::router::AgentRouter;
use std::sync::Arc;

fn router_with_both() -> AgentRouter {
    let mut r = AgentRouter::new();
    r.register(Arc::new(CodexAdapter::new()) as DynAgent);
    r.register(Arc::new(ClaudeCodeAdapter::new()) as DynAgent);
    r
}

#[test]
fn router_lists_both_codex_and_cc() {
    let r = router_with_both();
    let mut kinds = r.list_agents();
    kinds.sort_by_key(|k| match k {
        AgentKind::Codex => 0,
        AgentKind::ClaudeCode => 1,
    });
    assert_eq!(kinds.len(), 2);
    assert!(kinds.contains(&AgentKind::Codex));
    assert!(kinds.contains(&AgentKind::ClaudeCode));
}

#[test]
fn router_capabilities_distinct_per_kind() {
    let r = router_with_both();
    let codex = r.capabilities(AgentKind::Codex).expect("codex caps");
    let cc = r.capabilities(AgentKind::ClaudeCode).expect("cc caps");
    assert_eq!(codex.agent_kind, AgentKind::Codex);
    assert_eq!(cc.agent_kind, AgentKind::ClaudeCode);
    assert!(matches!(codex.vendor, VendorCapabilities::Codex(_)));
    assert!(matches!(cc.vendor, VendorCapabilities::ClaudeCode(_)));
}

/// Cross-agent list — request has `agent_kind = None`. The router
/// fans out to every registered adapter. Codex's v0.2 stub returns
/// an empty Vec; CC's real implementation enumerates jsonl files.
/// The merged result is always Ok(HistoryResponse::List(_)), even if
/// both adapters contribute zero items (no CC binary / no jsonl).
#[tokio::test]
async fn router_cross_agent_history_list_merges_without_error() {
    let r = router_with_both();
    let req = HistoryRequest::List {
        agent_kind: None,
        cwd_filter: None,
        limit: None,
    };
    let result = r.handle_history(req).await.expect("merge must not error");
    let items = match result {
        HistoryResponse::List(v) => v,
        other => panic!("expected List variant, got {other:?}"),
    };
    // Every item must be CC-kinded (codex returns empty) — proves the
    // router routed by kind and labeled correctly. If CC isn't on the
    // PATH the list may be empty; that's still acceptable.
    for item in &items {
        assert_eq!(
            item.agent_kind,
            AgentKind::ClaudeCode,
            "non-CC item in cross-agent list (codex stub should produce none)"
        );
    }
    eprintln!(
        "router_cross_agent_history_list_merges_without_error: \
         total merged items = {}",
        items.len()
    );
}

/// Codex-specific List goes to the codex stub — empty Vec, never an
/// error. (Important: the router must not 500 just because codex's
/// list is a no-op stub.)
#[tokio::test]
async fn router_codex_list_returns_empty_stub() {
    let r = router_with_both();
    let req = HistoryRequest::List {
        agent_kind: Some(AgentKind::Codex),
        cwd_filter: None,
        limit: None,
    };
    let result = r
        .handle_history(req)
        .await
        .expect("codex stub must not error");
    match result {
        HistoryResponse::List(v) => assert!(
            v.is_empty(),
            "Codex v0.2 stub returns empty Vec; got {} items",
            v.len()
        ),
        other => panic!("expected List variant, got {other:?}"),
    }
}

/// Codex-specific Read goes to the codex stub which returns a
/// structured `codex-history-read-not-implemented` error. This is the
/// trait-method-exists, impl-deferred posture documented in spec § 5
/// (v0.2 CC MUST; Codex MAY).
#[tokio::test]
async fn router_codex_read_surfaces_not_implemented_error() {
    let r = router_with_both();
    let req = HistoryRequest::Read {
        thread_id: ThreadId("nonexistent".into()),
        agent_kind: AgentKind::Codex,
    };
    let err = r.handle_history(req).await.expect_err("codex stub errors");
    assert_eq!(err.code, "codex-history-read-not-implemented");
}

/// CC-specific Unarchive is a NO-OP per the Task 4C design (CC's
/// `claude rm` is soft; `--resume` always finds it back). Must return
/// `Ack`, never an error.
#[tokio::test]
async fn router_cc_unarchive_is_noop_ack() {
    let r = router_with_both();
    let req = HistoryRequest::Unarchive {
        thread_id: ThreadId("anything".into()),
        agent_kind: AgentKind::ClaudeCode,
    };
    let result = r.handle_history(req).await.expect("cc unarchive must Ack");
    assert!(matches!(result, HistoryResponse::Ack));
}

/// Requesting an unregistered agent kind through the router yields a
/// structured `agent-not-registered` error.
#[tokio::test]
async fn router_unregistered_kind_returns_structured_error() {
    let r = AgentRouter::new(); // empty
    let req = HistoryRequest::List {
        agent_kind: Some(AgentKind::Codex),
        cwd_filter: None,
        limit: None,
    };
    let err = r
        .handle_history(req)
        .await
        .expect_err("empty router errors");
    assert_eq!(err.code, "agent-not-registered");
}
