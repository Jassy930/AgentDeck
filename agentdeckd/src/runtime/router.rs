//! Routes incoming session requests to the appropriate adapter by
//! AgentKind, and holds per-session locks (K2: same sessionId cannot
//! run concurrent turns; agentKind is immutable per session).

use crate::agent::{AgentEventSender, AgentSessionHandle, DynAgent};
use agentdeck_protocol::{
    ActionDecision, AgentKind, ProtocolError, SessionCapabilities, SessionId,
    SessionStart, ThreadId, VendorControlPayload,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Routes by AgentKind; holds per-session ownership to enforce K2.
pub struct AgentRouter {
    agents: BTreeMap<AgentKind, DynAgent>,
    sessions: Arc<Mutex<HashMap<SessionId, AgentKind>>>,
}

impl AgentRouter {
    pub fn new() -> Self {
        Self {
            agents: BTreeMap::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register(&mut self, agent: DynAgent) {
        let kind = agent.kind();
        self.agents.insert(kind, agent);
    }

    pub fn list_agents(&self) -> Vec<AgentKind> {
        self.agents.keys().copied().collect()
    }

    pub fn capabilities(&self, kind: AgentKind) -> Option<SessionCapabilities> {
        self.agents.get(&kind).map(|a| a.capabilities())
    }

    pub async fn start_session(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        let agent = self.agents.get(&start.agent_kind).ok_or_else(|| ProtocolError {
            code: "agent-not-registered".into(),
            message: format!("no adapter registered for agentKind={:?}", start.agent_kind),
            diagnostic_ref: None,
        })?;
        let handle = agent.start_session(start, events).await?;
        self.sessions.lock().await.insert(handle.session_id.clone(), handle.agent_kind);
        Ok(handle)
    }

    pub async fn continue_thread(
        &self,
        thread_id: ThreadId,
        agent_kind: AgentKind,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        let agent = self.agents.get(&agent_kind).ok_or_else(|| ProtocolError {
            code: "agent-not-registered".into(),
            message: format!("no adapter registered for agentKind={:?}", agent_kind),
            diagnostic_ref: None,
        })?;
        let handle = agent.continue_thread(thread_id, prompt, events).await?;
        self.sessions.lock().await.insert(handle.session_id.clone(), handle.agent_kind);
        Ok(handle)
    }

    pub async fn submit_decision(
        &self,
        session_id: &SessionId,
        decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents.get(&kind).unwrap().submit_decision(session_id, decision).await
    }

    pub async fn submit_vendor_control(
        &self,
        session_id: &SessionId,
        payload: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents.get(&kind).unwrap().submit_vendor_control(session_id, payload).await
    }

    pub async fn cancel(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents.get(&kind).unwrap().cancel(session_id).await?;
        self.sessions.lock().await.remove(session_id);
        Ok(())
    }

    async fn lookup_session(&self, sid: &SessionId) -> Result<AgentKind, ProtocolError> {
        self.sessions.lock().await.get(sid).copied().ok_or_else(|| ProtocolError {
            code: "session-not-found".into(),
            message: format!("session {:?} unknown to router", sid),
            diagnostic_ref: None,
        })
    }
}

impl Default for AgentRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AgentRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRouter")
            .field("agent_kinds", &self.agents.keys().collect::<Vec<_>>())
            .finish()
    }
}
