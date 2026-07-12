//! Routes incoming session requests to the appropriate adapter by
//! AgentKind, and holds per-session locks (K2: same sessionId cannot
//! run concurrent turns; agentKind is immutable per session).

use crate::agent::{
    AgentEventSender, AgentSessionHandle, CanonicalAgentEventSender, CanonicalAgentSessionHandle,
    CanonicalHistoryRead, DynAgent,
};
use agentdeck_protocol::{
    ActionDecision, AgentKind, HistoryRequest, HistoryResponse, ProtocolError, SessionCapabilities,
    SessionId, SessionStart, ThreadId, VendorControlPayload, effective_history_list_limit,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::runtime::store::RuntimeId;
use crate::runtime::store::RuntimeStoreHandle;
use crate::{claude_code::ClaudeCodeAdapter, codex::CodexAdapter};

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

    /// 构造 canonical Runtime router，并在 `runtime` 边界内把 singleton store
    /// 分裂为两个不可伪造、固定 namespace 的 vault。具体 adapter 只收到自身
    /// capability，不能从 `RuntimeStoreHandle` 获取另一私有映射域。
    #[must_use]
    pub fn with_runtime_store(store: RuntimeStoreHandle) -> Self {
        let mut router = Self::new();
        router.register(Arc::new(CodexAdapter::with_state_vault(
            store.codex_adapter_state_vault(),
        )));
        router.register(Arc::new(ClaudeCodeAdapter::with_state_vault(
            store.claude_code_adapter_state_vault(),
        )));
        router
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

    /// 旧 IPC v2/stdin compatibility：不持久化 neutral adapterStateKey。
    pub async fn start_session_stdio_compat(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        let agent = self
            .agents
            .get(&start.agent_kind)
            .ok_or_else(|| ProtocolError {
                code: "agent-not-registered".into(),
                message: format!("no adapter registered for agentKind={:?}", start.agent_kind),
                diagnostic_ref: None,
            })?;
        let handle = agent.start_session(start, events).await?;
        self.sessions
            .lock()
            .await
            .insert(handle.session_id.clone(), handle.agent_kind);
        Ok(handle)
    }

    /// Canonical Runtime entry: the caller owns the stable neutral
    /// adapterStateKey. The adapter persists its vendor resume reference only in
    /// its typed private namespace before returning success.
    pub async fn start_adapter_state(
        &self,
        adapter_state_key: RuntimeId,
        start: SessionStart,
        events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        let agent = self
            .agents
            .get(&start.agent_kind)
            .ok_or_else(|| ProtocolError {
                code: "agent-not-registered".into(),
                message: format!("no adapter registered for agentKind={:?}", start.agent_kind),
                diagnostic_ref: None,
            })?;
        let handle = agent
            .start_adapter_state(adapter_state_key, start, events)
            .await?;
        self.sessions
            .lock()
            .await
            .insert(handle.session_id.clone(), handle.agent_kind);
        Ok(handle)
    }

    /// 旧 IPC v2/stdin compatibility：raw vendor ThreadId 只允许由
    /// RuntimeHub 的 legacy command surface 调用，RuntimeCore 禁止使用。
    pub async fn continue_thread_stdio_compat(
        &self,
        thread_id: ThreadId,
        agent_kind: AgentKind,
        cwd: std::path::PathBuf,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        let agent = self.agents.get(&agent_kind).ok_or_else(|| ProtocolError {
            code: "agent-not-registered".into(),
            message: format!("no adapter registered for agentKind={:?}", agent_kind),
            diagnostic_ref: None,
        })?;
        let handle = agent
            .continue_thread(thread_id, cwd, prompt, events)
            .await?;
        self.sessions
            .lock()
            .await
            .insert(handle.session_id.clone(), handle.agent_kind);
        Ok(handle)
    }

    /// Canonical Runtime entry: raw vendor ThreadId never crosses this boundary.
    pub async fn continue_adapter_state(
        &self,
        adapter_state_key: RuntimeId,
        agent_kind: AgentKind,
        cwd: std::path::PathBuf,
        prompt: String,
        events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        let agent = self.agents.get(&agent_kind).ok_or_else(|| ProtocolError {
            code: "agent-not-registered".into(),
            message: format!("no adapter registered for agentKind={agent_kind:?}"),
            diagnostic_ref: None,
        })?;
        let handle = agent
            .continue_adapter_state(adapter_state_key, cwd, prompt, events)
            .await?;
        self.sessions
            .lock()
            .await
            .insert(handle.session_id.clone(), handle.agent_kind);
        Ok(handle)
    }

    /// Canonical Runtime history read；raw vendor ThreadId 在具体 adapter 私域
    /// resolve，router 只接收 neutral adapterStateKey 与中立 turns。
    pub async fn read_adapter_history(
        &self,
        adapter_state_key: RuntimeId,
        agent_kind: AgentKind,
    ) -> Result<CanonicalHistoryRead, ProtocolError> {
        let agent = self.agents.get(&agent_kind).ok_or_else(|| ProtocolError {
            code: "agent-not-registered".into(),
            message: format!("no adapter registered for agentKind={agent_kind:?}"),
            diagnostic_ref: None,
        })?;
        agent.read_adapter_history(adapter_state_key).await
    }

    pub async fn submit_decision(
        &self,
        session_id: &SessionId,
        decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents
            .get(&kind)
            .unwrap()
            .submit_decision(session_id, decision)
            .await
    }

    pub async fn submit_vendor_control(
        &self,
        session_id: &SessionId,
        payload: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents
            .get(&kind)
            .unwrap()
            .submit_vendor_control(session_id, payload)
            .await
    }

    pub async fn cancel(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents.get(&kind).unwrap().cancel(session_id).await?;
        self.sessions.lock().await.remove(session_id);
        Ok(())
    }

    /// Canonical execution 正常终止后的显式 ownership release。P3.7 coordinator
    /// 在 terminal journal COMMIT 后调用；与 `cancel` 不同，这里不再次向 adapter
    /// 发送副作用，只释放 router 的 transient session ownership。
    pub async fn release_session(&self, session_id: &SessionId) -> bool {
        self.sessions.lock().await.remove(session_id).is_some()
    }

    /// 诊断/泄漏门禁使用的当前 transient session 数。
    pub async fn active_session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// 旧 IPC v2/stdin compatibility：route a raw `HistoryRequest` to the
    /// matching adapter. RuntimeCore canonical history must use adapterStateKey
    /// and the adapter-private managed-history helpers. For `List` with
    /// `agent_kind = None` we fan out to every registered adapter and
    /// merge the resulting `HistoryListItem`s (newest first by
    /// `last_active_ms`). A single adapter's failure during cross-agent
    /// list does NOT block the others — surfacing partial results is
    /// preferable to surfacing zero. Read / Archive / Unarchive / Rename
    /// always carry an explicit `agent_kind` and route to one adapter.
    ///
    /// Added by Task 4C — Phase 4 finalization.
    pub async fn handle_history_stdio_compat(
        &self,
        request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        let agent_kind = match &request {
            HistoryRequest::List {
                agent_kind: Some(k),
                ..
            } => *k,
            HistoryRequest::List {
                agent_kind: None, ..
            } => {
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
        let (cwd_filter, limit) = match &request {
            HistoryRequest::List {
                cwd_filter, limit, ..
            } => (cwd_filter.clone(), *limit),
            _ => unreachable!("handle_history_cross_agent only called for List"),
        };
        let mut all = Vec::new();
        for (kind, agent) in self.agents.iter() {
            let req = HistoryRequest::List {
                agent_kind: Some(*kind),
                cwd_filter: cwd_filter.clone(),
                limit,
            };
            match agent.handle_history(req).await {
                Ok(HistoryResponse::List(items)) => all.extend(items),
                Ok(_) => {}  // wrong variant from adapter; ignore
                Err(_) => {} // one adapter's failure doesn't block the others
            }
        }
        all.sort_by_key(|item| std::cmp::Reverse(item.last_active_ms));
        all.truncate(effective_history_list_limit(limit));
        Ok(HistoryResponse::List(all))
    }

    async fn lookup_session(&self, sid: &SessionId) -> Result<AgentKind, ProtocolError> {
        self.sessions
            .lock()
            .await
            .get(sid)
            .copied()
            .ok_or_else(|| ProtocolError {
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
