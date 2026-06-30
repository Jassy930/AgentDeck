//! Routes incoming session requests to the appropriate adapter by
//! AgentKind, and holds per-session locks (K2: same sessionId cannot
//! run concurrent turns; agentKind is immutable per session).

use crate::agent::{AgentEventSender, AgentSessionHandle, DynAgent};
use agentdeck_protocol::{
    ActionDecision, AgentKind, HistoryRequest, HistoryResponse, ProtocolError,
    SessionCapabilities, SessionId, SessionStart, ThreadId, VendorControlPayload,
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

    /// Route a `HistoryRequest` to the matching adapter. For `List` with
    /// `agent_kind = None` we fan out to every registered adapter and
    /// merge the resulting `HistoryListItem`s (newest first by
    /// `last_active_ms`). A single adapter's failure during cross-agent
    /// list does NOT block the others — surfacing partial results is
    /// preferable to surfacing zero. Read / Archive / Unarchive / Rename
    /// always carry an explicit `agent_kind` and route to one adapter.
    ///
    /// Added by Task 4C — Phase 4 finalization.
    pub async fn handle_history(
        &self,
        request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        let agent_kind = match &request {
            HistoryRequest::List { agent_kind: Some(k), .. } => *k,
            HistoryRequest::List { agent_kind: None, .. } => {
                return self.handle_history_cross_agent(request).await;
            }
            HistoryRequest::Read { agent_kind, .. }
            | HistoryRequest::Archive { agent_kind, .. }
            | HistoryRequest::Unarchive { agent_kind, .. }
            | HistoryRequest::Rename { agent_kind, .. } => *agent_kind,
        };
        let agent = self.agents.get(&agent_kind).ok_or_else(|| ProtocolError {
            code: "agent-not-registered".into(),
            message: format!("no adapter registered for agentKind={:?}", agent_kind),
            diagnostic_ref: None,
        })?;
        agent.handle_history(request).await
    }

    /// Fan-out helper for cross-agent `List`. Queries every registered
    /// adapter with the agent-specific `List` (cwd_filter preserved),
    /// merges items, and sorts newest-first. Per-adapter errors and
    /// wrong-variant responses are silently dropped — the caller gets
    /// whatever items the working adapters produced.
    async fn handle_history_cross_agent(
        &self,
        request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        let cwd_filter = match &request {
            HistoryRequest::List { cwd_filter, .. } => cwd_filter.clone(),
            _ => unreachable!("handle_history_cross_agent only called for List"),
        };
        let mut all = Vec::new();
        for (kind, agent) in self.agents.iter() {
            let req = HistoryRequest::List {
                agent_kind: Some(*kind),
                cwd_filter: cwd_filter.clone(),
            };
            match agent.handle_history(req).await {
                Ok(HistoryResponse::List(items)) => all.extend(items),
                Ok(_) => {} // wrong variant from adapter; ignore
                Err(_) => {} // one adapter's failure doesn't block the others
            }
        }
        all.sort_by_key(|item| std::cmp::Reverse(item.last_active_ms));
        Ok(HistoryResponse::List(all))
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
