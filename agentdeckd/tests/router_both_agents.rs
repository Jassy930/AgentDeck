//! Integration smoke: AgentRouter holding BOTH CodexAdapter and
//! ClaudeCodeAdapter simultaneously, exercising the cross-agent
//! `handle_history` merge path added in Task 4C.
//!
//! The daemon binary registers both adapters into one router. Pure shape
//! tests always run; operations that inspect real local histories are gated
//! behind `AGENTDECK_E2E=1`.

use agentdeck_protocol::*;
use agentdeckd::agent::{Agent, AgentEventSender, AgentSessionHandle, DynAgent};
use agentdeckd::claude_code::ClaudeCodeAdapter;
use agentdeckd::codex::CodexAdapter;
use agentdeckd::runtime::router::AgentRouter;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;

mod support;

fn router_with_both() -> AgentRouter {
    let mut r = AgentRouter::new();
    r.register(Arc::new(CodexAdapter::new_for_test()) as DynAgent);
    r.register(Arc::new(ClaudeCodeAdapter::new_for_test()) as DynAgent);
    r
}

struct DelayedHistoryAgent {
    kind: AgentKind,
    gate: Arc<Barrier>,
    delay: Duration,
}

#[async_trait::async_trait]
impl Agent for DelayedHistoryAgent {
    fn kind(&self) -> AgentKind {
        self.kind
    }

    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            agent_kind: self.kind,
            agent_version: "delayed-history-stub".into(),
            features: Default::default(),
            vendor: match self.kind {
                AgentKind::Codex => VendorCapabilities::Codex(Default::default()),
                AgentKind::ClaudeCode => VendorCapabilities::ClaudeCode(Default::default()),
            },
        }
    }

    async fn start_session(
        &self,
        _: SessionStart,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unimplemented!("history-only test stub")
    }

    async fn continue_thread(
        &self,
        _: ThreadId,
        _: std::path::PathBuf,
        _: String,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unimplemented!("history-only test stub")
    }

    async fn submit_decision(&self, _: &SessionId, _: ActionDecision) -> Result<(), ProtocolError> {
        Ok(())
    }

    async fn submit_vendor_control(
        &self,
        _: &SessionId,
        _: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        Ok(())
    }

    async fn cancel(&self, _: &SessionId) -> Result<(), ProtocolError> {
        Ok(())
    }

    async fn handle_history(&self, _: HistoryRequest) -> Result<HistoryResponse, ProtocolError> {
        self.gate.wait().await;
        tokio::time::sleep(self.delay).await;
        Ok(HistoryResponse::List(Vec::new()))
    }
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

#[tokio::test]
async fn router_queries_both_history_sources_concurrently() {
    let gate = Arc::new(Barrier::new(2));
    let delay = Duration::from_millis(100);
    let mut router = AgentRouter::new();
    for kind in [AgentKind::Codex, AgentKind::ClaudeCode] {
        router.register(Arc::new(DelayedHistoryAgent {
            kind,
            gate: Arc::clone(&gate),
            delay,
        }));
    }

    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_millis(300),
        router.handle_history(HistoryRequest::List {
            request_id: Some("parallel-history-1".into()),
            agent_kind: None,
            cwd_filter: None,
            limit: None,
        }),
    )
    .await
    .expect("both sources must reach the barrier concurrently")
    .expect("both delayed history sources must succeed");
    let elapsed = started.elapsed();

    assert!(matches!(response, HistoryResponse::List(items) if items.is_empty()));
    assert!(
        elapsed < Duration::from_millis(250),
        "two 100ms sources should complete concurrently, elapsed={elapsed:?}"
    );
}

/// Cross-agent list — request has `agent_kind = None`, so both real local
/// history sources are queried and merged newest-first.
#[tokio::test]
async fn router_cross_agent_history_list_merges_without_error() {
    if !support::real_vendor_enabled() {
        eprintln!("SKIP router_cross_agent_history_list_merges_without_error: AGENTDECK_E2E != 1");
        return;
    }
    let r = router_with_both();
    let req = HistoryRequest::List {
        request_id: None,
        agent_kind: None,
        cwd_filter: None,
        limit: None,
    };
    let result = r.handle_history(req).await.expect("merge must not error");
    let items = match result {
        HistoryResponse::List(v) => v,
        other => panic!("expected List variant, got {other:?}"),
    };
    for item in &items {
        assert!(matches!(
            item.agent_kind,
            AgentKind::Codex | AgentKind::ClaudeCode
        ));
    }
    eprintln!(
        "router_cross_agent_history_list_merges_without_error: \
         total merged items = {}",
        items.len()
    );
}

/// Codex-specific List routes real app-server results and stamps every item
/// with the neutral Codex agent kind.
#[tokio::test]
async fn router_codex_list_returns_real_history_or_empty() {
    if !support::real_vendor_enabled() {
        eprintln!("SKIP router_codex_list_returns_real_history_or_empty: AGENTDECK_E2E != 1");
        return;
    }
    let r = router_with_both();
    let req = HistoryRequest::List {
        request_id: None,
        agent_kind: Some(AgentKind::Codex),
        cwd_filter: None,
        limit: Some(3),
    };
    let result = r
        .handle_history(req)
        .await
        .expect("real Codex list must not error");
    match result {
        HistoryResponse::List(items) => {
            assert!(items.len() <= 3);
            assert!(items.iter().all(|item| item.agent_kind == AgentKind::Codex));
        }
        other => panic!("expected List variant, got {other:?}"),
    }
}

/// Codex-specific Read routes through app-server and returns the same thread
/// id when at least one persisted local history exists.
#[tokio::test]
async fn router_codex_read_returns_real_history_when_available() {
    if !support::real_vendor_enabled() {
        eprintln!("SKIP router_codex_read_returns_real_history_when_available: AGENTDECK_E2E != 1");
        return;
    }
    let r = router_with_both();
    let listed = r
        .handle_history(HistoryRequest::List {
            request_id: None,
            agent_kind: Some(AgentKind::Codex),
            cwd_filter: None,
            limit: Some(1),
        })
        .await
        .expect("real Codex list must succeed");
    let HistoryResponse::List(items) = listed else {
        panic!("expected list response");
    };
    let Some(first) = items.first() else {
        eprintln!("SKIP router_codex_read_returns_real_history_when_available: no history");
        return;
    };
    let expected = first.thread_id.clone();
    let read = r
        .handle_history(HistoryRequest::Read {
            request_id: None,
            thread_id: expected.clone(),
            agent_kind: AgentKind::Codex,
        })
        .await
        .expect("real Codex read must succeed");
    let HistoryResponse::Read(detail) = read else {
        panic!("expected read response");
    };
    assert_eq!(detail.thread_id, expected);
    assert_eq!(detail.agent_kind, AgentKind::Codex);
}

/// CC-specific Unarchive is a NO-OP per the Task 4C design (CC's
/// `claude rm` is soft; `--resume` always finds it back). Must return
/// `Ack`, never an error.
#[tokio::test]
async fn router_cc_unarchive_is_noop_ack() {
    let r = router_with_both();
    let req = HistoryRequest::Unarchive {
        request_id: None,
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
        request_id: None,
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
