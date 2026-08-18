//! Routes incoming session requests to the appropriate adapter by
//! AgentKind, and holds per-session locks (K2: same sessionId cannot
//! run concurrent turns; agentKind is immutable per session).

use crate::agent::{AgentEventSender, AgentSessionHandle, DynAgent};
use agentdeck_protocol::{
    ActionDecision, AgentKind, HistoryRequest, HistoryResponse, ProtocolError, SessionCapabilities,
    SessionId, SessionStart, ThreadId, TurnId, VendorControlPayload, effective_history_list_limit,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

/// Leave two seconds below the hub's 32-second request deadline so a hung
/// source cannot discard items already returned by another source.
const HISTORY_SOURCE_TIMEOUT: Duration = Duration::from_secs(30);

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
        validate_session_start(&start)?;
        let session_id = start.session_id.clone();
        let agent_kind = start.agent_kind;
        let agent = self.agents.get(&agent_kind).ok_or_else(|| ProtocolError {
            code: "agent-not-registered".into(),
            message: format!("no adapter registered for agentKind={agent_kind:?}"),
            diagnostic_ref: None,
        })?;

        // Register the client-owned ID before vendor I/O so TurnCancel and
        // SessionClose can route while the adapter is still initializing.
        {
            let mut sessions = self.sessions.lock().await;
            if sessions.contains_key(&session_id) {
                return Err(ProtocolError {
                    code: "session-already-exists".into(),
                    message: format!("session {:?} is already registered", session_id),
                    diagnostic_ref: None,
                });
            }
            sessions.insert(session_id.clone(), agent_kind);
        }

        match agent.start_session(start, events).await {
            Ok(handle) => Ok(handle),
            Err(error) => {
                self.unregister_session(&session_id).await;
                Err(error)
            }
        }
    }

    pub async fn start_turn(
        &self,
        session_id: &SessionId,
        turn_id: TurnId,
        prompt: String,
    ) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents
            .get(&kind)
            .expect("registered session must retain its adapter")
            .start_turn(session_id, turn_id, prompt)
            .await
    }

    pub async fn cancel_turn(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
    ) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents
            .get(&kind)
            .expect("registered session must retain its adapter")
            .cancel_turn(session_id, turn_id)
            .await
    }

    pub async fn close_session(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        let kind = self.lookup_session(session_id).await?;
        self.agents
            .get(&kind)
            .expect("registered session must retain its adapter")
            .close_session(session_id)
            .await
    }

    /// Remove a terminal session from the routing table. RuntimeHub calls
    /// this only after the owner reports that process cleanup and `wait`
    /// completed, immediately before publishing `SessionClosed`.
    pub async fn unregister_session(&self, session_id: &SessionId) {
        self.sessions.lock().await.remove(session_id);
    }

    /// Notify the owning adapter while RuntimeHub holds its session-admission
    /// gate. The Hub enqueues the old terminal before releasing that gate, so
    /// replacement starts cannot race the adapter-local slot transition.
    pub async fn session_retired(
        &self,
        agent_kind: AgentKind,
        session_id: &SessionId,
        cleanup_confirmed: bool,
    ) {
        if let Some(agent) = self.agents.get(&agent_kind) {
            agent.session_retired(session_id, cleanup_confirmed).await;
        }
    }

    pub async fn continue_thread(
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
        self.unregister_session(session_id).await;
        Ok(())
    }

    /// Route a `HistoryRequest` to the matching adapter. For `List` with
    /// `agent_kind = None` we fan out to every registered adapter and
    /// merge the resulting `HistoryListItem`s (newest first by
    /// `last_active_ms`). A single adapter's failure during cross-agent
    /// list does NOT block the others — surfacing partial results is
    /// preferable to surfacing zero. An empty router and an all-sources
    /// failure are reported explicitly instead of masquerading as an empty
    /// history. Read / Archive / Unarchive / Rename always carry an explicit
    /// `agent_kind` and route to one adapter.
    ///
    /// Added by Task 4C — Phase 4 finalization.
    pub async fn handle_history(
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
    /// wrong-variant responses are recorded as failed sources. If at least
    /// one source succeeds, the caller gets its best-effort result; if every
    /// source fails, the caller gets one deterministic aggregate error.
    async fn handle_history_cross_agent(
        &self,
        request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        self.handle_history_cross_agent_with_timeout(request, HISTORY_SOURCE_TIMEOUT)
            .await
    }

    async fn handle_history_cross_agent_with_timeout(
        &self,
        request: HistoryRequest,
        source_timeout: Duration,
    ) -> Result<HistoryResponse, ProtocolError> {
        let (cwd_filter, limit) = match &request {
            HistoryRequest::List {
                cwd_filter, limit, ..
            } => (cwd_filter.clone(), *limit),
            _ => unreachable!("handle_history_cross_agent only called for List"),
        };

        if self.agents.is_empty() {
            return Err(ProtocolError {
                code: "history-no-sources".into(),
                message: "no history sources are registered".into(),
                diagnostic_ref: None,
            });
        }

        let mut pending = JoinSet::new();
        for (kind, agent) in &self.agents {
            let kind = *kind;
            let agent = Arc::clone(agent);
            let source_deadline = tokio::time::Instant::now() + source_timeout;
            let req = HistoryRequest::List {
                request_id: None,
                agent_kind: Some(kind),
                cwd_filter: cwd_filter.clone(),
                limit,
            };
            pending.spawn(async move {
                let result =
                    match tokio::time::timeout_at(source_deadline, agent.handle_history(req)).await
                    {
                        Ok(result) => result,
                        Err(_) => Err(ProtocolError {
                            code: "history-source-timeout".into(),
                            message: format!(
                                "history source {} exceeded the {source_timeout:?} router deadline",
                                kind.as_str()
                            ),
                            diagnostic_ref: None,
                        }),
                    };
                (kind, result)
            });
        }

        let mut all = Vec::new();
        let mut successful_sources = Vec::new();
        let mut failed_sources = Vec::new();
        let mut task_failures = Vec::new();
        while let Some(joined) = pending.join_next().await {
            let (kind, result) = match joined {
                Ok(result) => result,
                Err(error) => {
                    task_failures.push(format!("adapter task failed: {error}"));
                    continue;
                }
            };
            match result {
                Ok(HistoryResponse::List(items)) => {
                    successful_sources.push(kind);
                    all.extend(items);
                }
                Ok(response) => {
                    let response_kind = match response {
                        HistoryResponse::Read(_) => "read",
                        HistoryResponse::Ack => "ack",
                        HistoryResponse::List(_) => unreachable!("List handled above"),
                    };
                    failed_sources.push((
                        kind,
                        ProtocolError {
                            code: "history-source-invalid-response".into(),
                            message: format!(
                                "history source {} returned {response_kind} for a list request",
                                kind.as_str()
                            ),
                            diagnostic_ref: None,
                        },
                    ));
                }
                Err(error) => failed_sources.push((kind, error)),
            }
        }

        if successful_sources.is_empty() {
            failed_sources.sort_by_key(|(kind, _)| *kind);
            let failures = failed_sources
                .iter()
                .map(|(kind, error)| format!("{}={}", kind.as_str(), error.code))
                .chain(task_failures)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ProtocolError {
                code: "history-all-sources-failed".into(),
                message: format!("all registered history sources failed ({failures})"),
                diagnostic_ref: None,
            });
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

fn validate_session_start(start: &SessionStart) -> Result<(), ProtocolError> {
    if start.session_id.0.trim().is_empty() {
        return Err(ProtocolError {
            code: "invalid-session".into(),
            message: "sessionId must be non-empty".into(),
            diagnostic_ref: None,
        });
    }
    if start
        .resume_thread_id
        .as_ref()
        .is_some_and(|thread_id| thread_id.0.trim().is_empty())
    {
        return Err(ProtocolError {
            code: "invalid-thread".into(),
            message: "resumeThreadId must be non-empty when provided".into(),
            diagnostic_ref: None,
        });
    }
    if let Some(initial_turn) = &start.initial_turn
        && (initial_turn.turn_id.0.trim().is_empty() || initial_turn.prompt.trim().is_empty())
    {
        return Err(ProtocolError {
            code: "invalid-turn".into(),
            message: "initialTurn.turnId and prompt must be non-empty".into(),
            diagnostic_ref: None,
        });
    }
    let vendor_matches = matches!(
        (start.agent_kind, &start.vendor_options),
        (
            AgentKind::Codex,
            agentdeck_protocol::VendorSessionOptions::Codex(_)
        ) | (
            AgentKind::ClaudeCode,
            agentdeck_protocol::VendorSessionOptions::ClaudeCode(_)
        )
    );
    if !vendor_matches {
        return Err(ProtocolError {
            code: "wrong-vendor".into(),
            message: "agentKind must match vendorOptions.agentKind".into(),
            diagnostic_ref: None,
        });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Agent, AgentEventSender, AgentSessionHandle};
    use agentdeck_protocol::{
        ClaudeCodePermissionMode, ClaudeCodeSessionOptions, CodexApprovalPolicy,
        CodexReasoningEffort, CodexSandboxMode, CodexSessionOptions, HistoryListItem, InitialTurn,
        RuntimeOptions, VendorCapabilities, VendorSessionOptions,
    };

    enum HistoryBehavior {
        Immediate(Vec<HistoryListItem>),
        Pending,
    }

    struct HistoryOnlyAgent {
        kind: AgentKind,
        behavior: HistoryBehavior,
    }

    #[async_trait::async_trait]
    impl Agent for HistoryOnlyAgent {
        fn kind(&self) -> AgentKind {
            self.kind
        }

        fn capabilities(&self) -> SessionCapabilities {
            SessionCapabilities {
                agent_kind: self.kind,
                agent_version: "history-timeout-stub".into(),
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

        async fn submit_decision(
            &self,
            _: &SessionId,
            _: ActionDecision,
        ) -> Result<(), ProtocolError> {
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

        async fn handle_history(
            &self,
            _: HistoryRequest,
        ) -> Result<HistoryResponse, ProtocolError> {
            match &self.behavior {
                HistoryBehavior::Immediate(items) => Ok(HistoryResponse::List(items.clone())),
                HistoryBehavior::Pending => std::future::pending().await,
            }
        }
    }

    fn history_item(kind: AgentKind, thread_id: &str) -> HistoryListItem {
        HistoryListItem {
            thread_id: ThreadId(thread_id.into()),
            agent_kind: kind,
            title: Some("available source".into()),
            cwd: "/tmp/history-timeout-test".into(),
            last_active_ms: 42,
            archived: false,
        }
    }

    fn cross_agent_request() -> HistoryRequest {
        HistoryRequest::List {
            request_id: None,
            agent_kind: None,
            cwd_filter: None,
            limit: None,
        }
    }

    #[tokio::test]
    async fn cross_agent_history_keeps_success_when_other_source_times_out() {
        let mut router = AgentRouter::new();
        router.register(Arc::new(HistoryOnlyAgent {
            kind: AgentKind::Codex,
            behavior: HistoryBehavior::Immediate(vec![history_item(
                AgentKind::Codex,
                "ready-thread",
            )]),
        }));
        router.register(Arc::new(HistoryOnlyAgent {
            kind: AgentKind::ClaudeCode,
            behavior: HistoryBehavior::Pending,
        }));

        let response = tokio::time::timeout(
            Duration::from_millis(250),
            router.handle_history_cross_agent_with_timeout(
                cross_agent_request(),
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("router must not wait for the hub deadline")
        .expect("one successful source must preserve its result");

        let HistoryResponse::List(items) = response else {
            panic!("expected list response");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].thread_id, ThreadId("ready-thread".into()));
    }

    #[tokio::test]
    async fn cross_agent_history_aggregates_all_source_timeouts() {
        let mut router = AgentRouter::new();
        for kind in [AgentKind::ClaudeCode, AgentKind::Codex] {
            router.register(Arc::new(HistoryOnlyAgent {
                kind,
                behavior: HistoryBehavior::Pending,
            }));
        }

        let error = tokio::time::timeout(
            Duration::from_millis(250),
            router.handle_history_cross_agent_with_timeout(
                cross_agent_request(),
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("router must bound every pending source")
        .expect_err("all timed-out sources must produce one aggregate error");

        assert_eq!(error.code, "history-all-sources-failed");
        assert_eq!(
            error.message,
            "all registered history sources failed (codex=history-source-timeout, \
             claude_code=history-source-timeout)"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    enum LifecycleCall {
        Start(SessionId),
        TurnStart(SessionId, TurnId, String),
        TurnCancel(SessionId, TurnId),
        SessionClose(SessionId),
    }

    struct LifecycleAgent {
        calls: Arc<std::sync::Mutex<Vec<LifecycleCall>>>,
        fail_start: bool,
    }

    #[async_trait::async_trait]
    impl Agent for LifecycleAgent {
        fn kind(&self) -> AgentKind {
            AgentKind::Codex
        }

        fn capabilities(&self) -> SessionCapabilities {
            SessionCapabilities {
                agent_kind: AgentKind::Codex,
                agent_version: "lifecycle-router-stub".into(),
                features: Default::default(),
                vendor: VendorCapabilities::Codex(Default::default()),
            }
        }

        async fn start_session(
            &self,
            start: SessionStart,
            _: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            self.calls
                .lock()
                .unwrap()
                .push(LifecycleCall::Start(start.session_id.clone()));
            if self.fail_start {
                return Err(ProtocolError {
                    code: "stub-start-failed".into(),
                    message: "stub start failed".into(),
                    diagnostic_ref: None,
                });
            }

            let pump = tokio::spawn(std::future::pending::<()>());
            let abort_handle = pump.abort_handle();
            pump.abort();
            Ok(AgentSessionHandle {
                session_id: start.session_id,
                thread_id: Some(ThreadId("router-thread".into())),
                agent_kind: AgentKind::Codex,
                abort_handle,
                exit: None,
            })
        }

        async fn continue_thread(
            &self,
            _: ThreadId,
            _: std::path::PathBuf,
            _: String,
            _: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            unimplemented!("legacy continue is outside lifecycle router tests")
        }

        async fn start_turn(
            &self,
            session_id: &SessionId,
            turn_id: TurnId,
            prompt: String,
        ) -> Result<(), ProtocolError> {
            self.calls.lock().unwrap().push(LifecycleCall::TurnStart(
                session_id.clone(),
                turn_id,
                prompt,
            ));
            Ok(())
        }

        async fn cancel_turn(
            &self,
            session_id: &SessionId,
            turn_id: &TurnId,
        ) -> Result<(), ProtocolError> {
            self.calls.lock().unwrap().push(LifecycleCall::TurnCancel(
                session_id.clone(),
                turn_id.clone(),
            ));
            Ok(())
        }

        async fn close_session(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
            self.calls
                .lock()
                .unwrap()
                .push(LifecycleCall::SessionClose(session_id.clone()));
            Ok(())
        }

        async fn submit_decision(
            &self,
            _: &SessionId,
            _: ActionDecision,
        ) -> Result<(), ProtocolError> {
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

    fn lifecycle_start(session_id: &str) -> SessionStart {
        SessionStart {
            session_id: SessionId(session_id.into()),
            agent_kind: AgentKind::Codex,
            cwd: "/tmp".into(),
            resume_thread_id: None,
            initial_turn: None,
            vendor_options: VendorSessionOptions::Codex(CodexSessionOptions {
                approval_policy: CodexApprovalPolicy::Never,
                sandbox: CodexSandboxMode::ReadOnly,
                persist_approval: false,
                reasoning_effort: CodexReasoningEffort::Medium,
                mcp_overrides: vec![],
            }),
            runtime_options: RuntimeOptions::default(),
        }
    }

    #[tokio::test]
    async fn lifecycle_commands_route_by_client_session_id() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = AgentRouter::new();
        router.register(Arc::new(LifecycleAgent {
            calls: Arc::clone(&calls),
            fail_start: false,
        }));
        let (events, _events_rx) = tokio::sync::mpsc::channel(8);
        let session_id = SessionId("client-session".into());
        let turn_id = TurnId("client-turn".into());

        router
            .start_session(lifecycle_start(&session_id.0), events)
            .await
            .expect("stub session starts");
        router
            .start_turn(&session_id, turn_id.clone(), "hello".into())
            .await
            .expect("turn routes");
        router
            .cancel_turn(&session_id, &turn_id)
            .await
            .expect("cancel routes");
        router
            .close_session(&session_id)
            .await
            .expect("close routes");

        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                LifecycleCall::Start(session_id.clone()),
                LifecycleCall::TurnStart(session_id.clone(), turn_id.clone(), "hello".into()),
                LifecycleCall::TurnCancel(session_id.clone(), turn_id),
                LifecycleCall::SessionClose(session_id),
            ]
        );
    }

    #[tokio::test]
    async fn duplicate_session_id_is_rejected_before_second_adapter_start() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = AgentRouter::new();
        router.register(Arc::new(LifecycleAgent {
            calls: Arc::clone(&calls),
            fail_start: false,
        }));
        let (events, _events_rx) = tokio::sync::mpsc::channel(8);

        router
            .start_session(lifecycle_start("duplicate"), events.clone())
            .await
            .expect("first start succeeds");
        let error = match router
            .start_session(lifecycle_start("duplicate"), events)
            .await
        {
            Ok(_) => panic!("duplicate client session id must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code, "session-already-exists");
        assert_eq!(
            *calls.lock().unwrap(),
            vec![LifecycleCall::Start(SessionId("duplicate".into()))]
        );
    }

    #[tokio::test]
    async fn rejects_invalid_caller_owned_start_fields_before_adapter_start() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = AgentRouter::new();
        router.register(Arc::new(LifecycleAgent {
            calls: Arc::clone(&calls),
            fail_start: false,
        }));
        let (events, _events_rx) = tokio::sync::mpsc::channel(8);

        let mut cases = Vec::new();

        let mut empty_session = lifecycle_start(" ");
        empty_session.initial_turn = Some(InitialTurn {
            turn_id: TurnId("turn-1".into()),
            prompt: "hello".into(),
        });
        cases.push((empty_session, "invalid-session"));

        let mut empty_thread = lifecycle_start("session-thread");
        empty_thread.resume_thread_id = Some(ThreadId(" ".into()));
        cases.push((empty_thread, "invalid-thread"));

        let mut empty_turn_id = lifecycle_start("session-turn-id");
        empty_turn_id.initial_turn = Some(InitialTurn {
            turn_id: TurnId(" ".into()),
            prompt: "hello".into(),
        });
        cases.push((empty_turn_id, "invalid-turn"));

        let mut empty_prompt = lifecycle_start("session-prompt");
        empty_prompt.initial_turn = Some(InitialTurn {
            turn_id: TurnId("turn-1".into()),
            prompt: " ".into(),
        });
        cases.push((empty_prompt, "invalid-turn"));

        let mut wrong_vendor = lifecycle_start("session-vendor");
        wrong_vendor.vendor_options = VendorSessionOptions::ClaudeCode(ClaudeCodeSessionOptions {
            permission_mode: ClaudeCodePermissionMode::BypassPermissions,
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
        });
        cases.push((wrong_vendor, "wrong-vendor"));

        for (start, expected_code) in cases {
            let error = match router.start_session(start, events.clone()).await {
                Err(error) => error,
                Ok(_) => panic!("invalid start must be rejected by the shared router"),
            };
            assert_eq!(error.code, expected_code);
        }
        assert!(
            calls.lock().unwrap().is_empty(),
            "invalid starts must not reach vendor adapters"
        );
    }

    #[tokio::test]
    async fn failed_start_removes_pre_registered_client_session_id() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = AgentRouter::new();
        router.register(Arc::new(LifecycleAgent {
            calls,
            fail_start: true,
        }));
        let (events, _events_rx) = tokio::sync::mpsc::channel(8);
        let session_id = SessionId("failed-start".into());

        let error = match router
            .start_session(lifecycle_start(&session_id.0), events)
            .await
        {
            Ok(_) => panic!("stub start must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code, "stub-start-failed");

        let route_error = router
            .start_turn(&session_id, TurnId("late-turn".into()), "nope".into())
            .await
            .expect_err("failed start must not leave a routable session");
        assert_eq!(route_error.code, "session-not-found");
    }
}
