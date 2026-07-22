use agentdeck_protocol::*;
use agentdeckd::agent::{Agent, AgentEventSender, AgentSessionHandle};
use agentdeckd::runtime::router::AgentRouter;
use std::sync::Arc;

struct StubAgent {
    kind: AgentKind,
    history: StubHistory,
}

enum StubHistory {
    List(Vec<HistoryListItem>),
    Error(&'static str),
}

impl StubAgent {
    fn without_history(kind: AgentKind) -> Self {
        Self {
            kind,
            history: StubHistory::Error("history-not-supported"),
        }
    }

    fn with_history(kind: AgentKind, history: StubHistory) -> Self {
        Self { kind, history }
    }
}

#[async_trait::async_trait]
impl Agent for StubAgent {
    fn kind(&self) -> AgentKind {
        self.kind
    }
    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            agent_kind: self.kind,
            agent_version: "stub".into(),
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
        unimplemented!()
    }
    async fn continue_thread(
        &self,
        _: ThreadId,
        _: std::path::PathBuf,
        _: String,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unimplemented!()
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
        match &self.history {
            StubHistory::List(items) => Ok(HistoryResponse::List(items.clone())),
            StubHistory::Error(code) => Err(ProtocolError {
                code: (*code).into(),
                message: format!("{} history failed", self.kind.as_str()),
                diagnostic_ref: None,
            }),
        }
    }
}

#[test]
fn router_lists_registered_agents() {
    let mut r = AgentRouter::new();
    r.register(Arc::new(StubAgent::without_history(AgentKind::Codex)));
    r.register(Arc::new(StubAgent::without_history(AgentKind::ClaudeCode)));
    let mut listed = r.list_agents();
    listed.sort_by_key(|k| k.as_str());
    assert_eq!(listed.len(), 2);
}

#[test]
fn router_returns_capabilities_for_known_kind() {
    let mut r = AgentRouter::new();
    r.register(Arc::new(StubAgent::without_history(AgentKind::Codex)));
    let caps = r.capabilities(AgentKind::Codex).expect("codex registered");
    assert_eq!(caps.agent_kind, AgentKind::Codex);
}

#[test]
fn router_rejects_unregistered_kind() {
    let r = AgentRouter::new();
    assert!(r.capabilities(AgentKind::Codex).is_none());
}

fn cross_agent_list_request() -> HistoryRequest {
    HistoryRequest::List {
        request_id: None,
        agent_kind: None,
        cwd_filter: None,
        limit: None,
    }
}

#[tokio::test]
async fn cross_agent_history_rejects_router_without_sources() {
    let error = AgentRouter::new()
        .handle_history(cross_agent_list_request())
        .await
        .expect_err("empty router must not masquerade as empty history");

    assert_eq!(error.code, "history-no-sources");
    assert_eq!(error.message, "no history sources are registered");
}

#[tokio::test]
async fn cross_agent_history_aggregates_all_failures_in_stable_agent_order() {
    let mut router = AgentRouter::new();
    // Register in reverse order; AgentRouter's BTreeMap must still produce
    // the same aggregate error on every run.
    router.register(Arc::new(StubAgent::with_history(
        AgentKind::ClaudeCode,
        StubHistory::Error("cc-history-down"),
    )));
    router.register(Arc::new(StubAgent::with_history(
        AgentKind::Codex,
        StubHistory::Error("codex-history-down"),
    )));

    let error = router
        .handle_history(cross_agent_list_request())
        .await
        .expect_err("all failed sources must produce one aggregate error");

    assert_eq!(error.code, "history-all-sources-failed");
    assert_eq!(
        error.message,
        "all registered history sources failed (codex=codex-history-down, \
         claude_code=cc-history-down)"
    );
}

#[tokio::test]
async fn cross_agent_history_keeps_best_effort_result_when_one_source_succeeds() {
    let mut router = AgentRouter::new();
    router.register(Arc::new(StubAgent::with_history(
        AgentKind::Codex,
        StubHistory::Error("codex-history-down"),
    )));
    router.register(Arc::new(StubAgent::with_history(
        AgentKind::ClaudeCode,
        StubHistory::List(vec![HistoryListItem {
            thread_id: ThreadId("cc-thread".into()),
            agent_kind: AgentKind::ClaudeCode,
            title: Some("working source".into()),
            cwd: "/tmp/cc".into(),
            last_active_ms: 42,
            archived: false,
        }]),
    )));

    let response = router
        .handle_history(cross_agent_list_request())
        .await
        .expect("one successful source must keep the merged list usable");
    let HistoryResponse::List(items) = response else {
        panic!("expected list response");
    };

    assert_eq!(items.len(), 1);
    assert_eq!(items[0].thread_id, ThreadId("cc-thread".into()));
    assert_eq!(items[0].agent_kind, AgentKind::ClaudeCode);
}
