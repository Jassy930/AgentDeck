//! Compile-time guard for the Agent trait shape. If a future PR weakens
//! Send+Sync+'static or removes a required method, this file fails to
//! compile, breaking the build.

use agentdeck_protocol::*;
use agentdeckd::agent::{Agent, AgentEventSender, AgentSessionHandle, PreparedAgentTurn};

#[allow(dead_code)]
fn assert_send_sync_static<T: Agent>() {
    fn require<T: Send + Sync + 'static>() {}
    require::<T>();
}

#[allow(dead_code)]
fn capability_signature_present(a: &dyn Agent) -> SessionCapabilities {
    a.capabilities()
}

#[allow(dead_code)]
fn assert_prepared_turn_is_send_static<T: PreparedAgentTurn>() {
    fn require<T: Send + 'static>() {}
    require::<T>();
}

/// An adapter that opts into the default `handle_history` impl must
/// surface the `history-not-supported` error code — proves Task 4C's
/// default behavior is wired correctly.
struct DefaultHistoryStub;

#[async_trait::async_trait]
impl Agent for DefaultHistoryStub {
    fn kind(&self) -> AgentKind {
        AgentKind::Codex
    }
    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            agent_kind: AgentKind::Codex,
            agent_version: "stub".into(),
            features: Default::default(),
            vendor: VendorCapabilities::Codex(Default::default()),
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

#[tokio::test]
async fn default_handle_history_returns_history_not_supported() {
    let a = DefaultHistoryStub;
    let req = HistoryRequest::List {
        agent_kind: Some(AgentKind::Codex),
        cwd_filter: None,
        limit: None,
    };
    let err = a.handle_history(req).await.unwrap_err();
    assert_eq!(err.code, "history-not-supported");
}
