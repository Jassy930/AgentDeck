use agentdeck_protocol::*;
use agentdeckd::agent::{Agent, AgentEventSender, AgentSessionHandle};
use agentdeckd::runtime::router::AgentRouter;
use agentdeckd::runtime::store::{RuntimeId, RuntimeIdKind};
use std::sync::Arc;

struct StubAgent {
    kind: AgentKind,
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
}

#[test]
fn router_lists_registered_agents() {
    let mut r = AgentRouter::new();
    r.register(Arc::new(StubAgent {
        kind: AgentKind::Codex,
    }));
    r.register(Arc::new(StubAgent {
        kind: AgentKind::ClaudeCode,
    }));
    let mut listed = r.list_agents();
    listed.sort_by_key(|k| k.as_str());
    assert_eq!(listed.len(), 2);
}

#[test]
fn router_returns_capabilities_for_known_kind() {
    let mut r = AgentRouter::new();
    r.register(Arc::new(StubAgent {
        kind: AgentKind::Codex,
    }));
    let caps = r.capabilities(AgentKind::Codex).expect("codex registered");
    assert_eq!(caps.agent_kind, AgentKind::Codex);
}

#[test]
fn router_rejects_unregistered_kind() {
    let r = AgentRouter::new();
    assert!(r.capabilities(AgentKind::Codex).is_none());
}

#[tokio::test]
async fn release_unknown_session_is_idempotent_and_does_not_create_ownership() {
    let router = AgentRouter::new();
    let session_id = SessionId("missing-session".to_owned());
    assert!(!router.release_session(&session_id).await);
    assert_eq!(router.active_session_count().await, 0);
}

#[tokio::test]
async fn canonical_continue_routes_only_the_neutral_adapter_state_key() {
    let mut router = AgentRouter::new();
    router.register(Arc::new(StubAgent {
        kind: AgentKind::Codex,
    }));
    let (events, _receiver) = tokio::sync::mpsc::channel(1);
    let key = RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x91; 16])
        .expect("neutral adapter state key");

    let result = router
        .continue_adapter_state(
            key,
            AgentKind::Codex,
            "/tmp".into(),
            "continue".to_owned(),
            events,
        )
        .await;
    let error = match result {
        Ok(_) => panic!("stub has no private repository"),
        Err(error) => error,
    };
    assert_eq!(error.code, "adapter-state-not-configured");
}
