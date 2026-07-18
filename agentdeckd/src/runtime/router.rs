//! Routes requests to the appropriate adapter by `AgentKind`.
//!
//! The `SessionId` ownership map exists only for the legacy IPC v2/stdin
//! compatibility surface. Canonical P3.7 typed turn preparation selects an
//! adapter without creating or consulting compatibility session ownership.

use crate::agent::{
    AdapterStateHandle, AgentEventSender, AgentSessionHandle, AgentTurnRequest,
    CanonicalAgentEventSender, CanonicalAgentSessionHandle, CanonicalHistoryRead,
    CanonicalNativeHistoryRead, DynAgent, DynNativeHistoryReader, NativeHistoryReadError,
    PreparedAgentTurnHandle, prepare_turn as prepare_agent_turn,
};
use agentdeck_protocol::runtime::{AgentDescription, AgentDescriptions, ConfigurationError};
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

/// Routes by `AgentKind`; legacy compatibility calls additionally retain
/// transient `SessionId` ownership for their existing control surface.
pub struct AgentRouter {
    agents: BTreeMap<AgentKind, DynAgent>,
    native_history_readers: BTreeMap<AgentKind, DynNativeHistoryReader>,
    sessions: Arc<Mutex<HashMap<SessionId, AgentKind>>>,
}

impl AgentRouter {
    pub fn new() -> Self {
        Self {
            agents: BTreeMap::new(),
            native_history_readers: BTreeMap::new(),
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
        let claude_code = Arc::new(ClaudeCodeAdapter::with_state_vault(
            store.claude_code_adapter_state_vault(),
        ));
        router.register(claude_code.clone());
        router.register_native_history_reader(AgentKind::ClaudeCode, claude_code);
        router
    }

    pub fn register(&mut self, agent: DynAgent) {
        let kind = agent.kind();
        self.agents.insert(kind, agent);
    }

    pub(crate) fn register_native_history_reader(
        &mut self,
        agent_kind: AgentKind,
        reader: DynNativeHistoryReader,
    ) {
        self.native_history_readers.insert(agent_kind, reader);
    }

    pub fn list_agents(&self) -> Vec<AgentKind> {
        self.agents.keys().copied().collect()
    }

    pub fn capabilities(&self, kind: AgentKind) -> Option<SessionCapabilities> {
        self.agents.get(&kind).map(|a| a.capabilities())
    }

    /// 为 Runtime `DescribeAgents` 构造稳定排序的完整描述。
    ///
    /// `agents` 使用 `BTreeMap<AgentKind, _>`，因此输出顺序不依赖注册顺序。
    /// 任一 adapter 返回错误、capabilities/default kind 不匹配或 vendor block
    /// 不匹配时，整批构造直接失败；禁止 panic 或静默过滤畸形 adapter。
    pub fn agent_descriptions(&self) -> Result<AgentDescriptions, ConfigurationError> {
        let descriptions = self
            .agents
            .iter()
            .map(|(agent_kind, agent)| {
                AgentDescription::new(
                    *agent_kind,
                    agent.capabilities(),
                    agent.default_configuration()?,
                )
            })
            .collect::<Result<Vec<_>, ConfigurationError>>()?;
        AgentDescriptions::new(descriptions)
    }

    /// Canonical production cold-prepare route. This method only selects the typed
    /// adapter and delegates to the daemon-owned binding helper; it deliberately
    /// does not create compatibility `SessionId` ownership or expose approval /
    /// cancellation lookup by execution identity.
    pub(crate) async fn prepare_turn(
        &self,
        agent_kind: AgentKind,
        request: AgentTurnRequest,
        state: AdapterStateHandle,
    ) -> Result<PreparedAgentTurnHandle, ProtocolError> {
        let agent = self.agents.get(&agent_kind).ok_or_else(|| ProtocolError {
            code: "agent-not-registered".into(),
            message: format!("no adapter registered for agentKind={agent_kind:?}"),
            diagnostic_ref: None,
        })?;
        prepare_agent_turn(agent.as_ref(), request, state).await
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

    /// 旧 adapter-state compatibility/testing entry：调用方持有 stable neutral
    /// adapterStateKey，但返回值仍建立 transient `SessionId` ownership。P3.7
    /// canonical execution 必须改走 typed `prepare_turn`，不得依赖此映射。
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

    /// 旧 adapter-state compatibility/testing entry：raw vendor ThreadId 不跨越
    /// 此边界，但返回值仍建立 transient `SessionId` ownership。P3.7 canonical
    /// execution 必须改走 typed `prepare_turn`。
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

    /// Key-bearing native history typed route。Router 只携带 neutral
    /// adapterStateKey；private reference 的解析、no-follow 重验与 stable key
    /// 提取全部留在具体 adapter 私域。当前 Codex/未注册扩展稳定 unavailable。
    pub(crate) async fn read_native_history(
        &self,
        adapter_state_key: RuntimeId,
        agent_kind: AgentKind,
    ) -> Result<CanonicalNativeHistoryRead, NativeHistoryReadError> {
        if !self.agents.contains_key(&agent_kind) {
            return Err(NativeHistoryReadError::Unavailable);
        }
        let reader = self
            .native_history_readers
            .get(&agent_kind)
            .ok_or(NativeHistoryReadError::Unavailable)?;
        let read = reader.read_native_history(adapter_state_key).await?;
        if read.agent_kind() != agent_kind {
            return Err(NativeHistoryReadError::InvalidSource);
        }
        Ok(read)
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

    /// 旧 compatibility session 正常终止后的显式 ownership release。typed P3.7
    /// execution 不登记 `SessionId`，因此不得调用本入口。与 compatibility
    /// `cancel` 不同，这里不再次向 adapter 发送副作用。
    pub async fn release_session(&self, session_id: &SessionId) -> bool {
        self.sessions.lock().await.remove(session_id).is_some()
    }

    /// 诊断/泄漏门禁使用的当前 compatibility transient session 数。
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

#[cfg(test)]
mod typed_prepare_tests {
    use super::*;
    use crate::agent::{
        AdapterStateHandle, Agent, AgentTurnRequest, ExecSpec, ExecutionId, PreparedAgentTurn,
    };
    use agentdeck_protocol::runtime::{
        ClaudeCodeConversationConfiguration, CodexConversationConfiguration,
        ConversationConfiguration, PromptPayload, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{
        ClaudeCodePermissionMode, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
    };
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StubPreparedTurn {
        spec: ExecSpec,
    }

    impl PreparedAgentTurn for StubPreparedTurn {
        fn exec_spec(&self) -> &ExecSpec {
            &self.spec
        }
    }

    struct PrepareProbeAgent {
        kind: AgentKind,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Agent for PrepareProbeAgent {
        fn kind(&self) -> AgentKind {
            self.kind
        }

        fn capabilities(&self) -> SessionCapabilities {
            unreachable!("typed prepare route does not probe capabilities")
        }

        fn default_configuration(&self) -> Result<ConversationConfiguration, ConfigurationError> {
            match self.kind {
                AgentKind::Codex => Ok(ConversationConfiguration::new(
                    VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                        CodexApprovalPolicy::OnRequest,
                        CodexSandboxMode::WorkspaceWrite,
                        CodexReasoningEffort::Medium,
                    )),
                )),
                AgentKind::ClaudeCode => ClaudeCodeConversationConfiguration::new(
                    ClaudeCodePermissionMode::Default,
                    None,
                    None,
                    None,
                )
                .map(VendorConfigurationSnapshot::ClaudeCode)
                .map(ConversationConfiguration::new),
            }
        }

        async fn prepare_adapter_turn(
            &self,
            _capability: &mut crate::agent::PrepareAdapterTurnCapability,
            request: AgentTurnRequest,
            state: AdapterStateHandle,
        ) -> Result<Box<dyn PreparedAgentTurn>, ProtocolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(StubPreparedTurn {
                spec: ExecSpec::new(
                    &request,
                    state,
                    "/usr/bin/true",
                    Vec::<OsString>::new(),
                    "/tmp",
                )
                .expect("valid probe exec spec"),
            }))
        }

        async fn start_session(
            &self,
            _start: SessionStart,
            _events: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            unreachable!("typed prepare route does not start compatibility sessions")
        }

        async fn continue_thread(
            &self,
            _thread_id: ThreadId,
            _cwd: PathBuf,
            _prompt: String,
            _events: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            unreachable!("typed prepare route does not continue compatibility sessions")
        }

        async fn submit_decision(
            &self,
            _session_id: &SessionId,
            _decision: ActionDecision,
        ) -> Result<(), ProtocolError> {
            unreachable!("typed prepare route does not resolve compatibility approvals")
        }

        async fn submit_vendor_control(
            &self,
            _session_id: &SessionId,
            _payload: VendorControlPayload,
        ) -> Result<(), ProtocolError> {
            unreachable!("typed prepare route does not submit compatibility controls")
        }

        async fn cancel(&self, _session_id: &SessionId) -> Result<(), ProtocolError> {
            unreachable!("typed prepare route does not cancel compatibility sessions")
        }
    }

    fn runtime_id(kind: crate::runtime::store::RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
    }

    fn configuration(agent_kind: AgentKind) -> ConversationConfiguration {
        match agent_kind {
            AgentKind::Codex => ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                CodexConversationConfiguration::new(
                    CodexApprovalPolicy::OnRequest,
                    CodexSandboxMode::WorkspaceWrite,
                    CodexReasoningEffort::Medium,
                ),
            )),
            AgentKind::ClaudeCode => {
                ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
                    ClaudeCodeConversationConfiguration::new(
                        ClaudeCodePermissionMode::Default,
                        None,
                        None,
                        None,
                    )
                    .expect("bounded Claude Code configuration"),
                ))
            }
        }
    }

    fn request(seed: u8, agent_kind: AgentKind) -> AgentTurnRequest {
        let execution_id = ExecutionId::from_command_id(runtime_id(
            crate::runtime::store::RuntimeIdKind::Command,
            seed,
        ))
        .expect("command execution id");
        AgentTurnRequest::new(
            execution_id,
            std::env::current_dir().expect("current directory"),
            PromptPayload::new("typed router probe").expect("bounded prompt"),
            3,
            configuration(agent_kind),
        )
        .expect("absolute request cwd")
    }

    fn adapter_state(seed: u8) -> AdapterStateHandle {
        AdapterStateHandle::new(runtime_id(
            crate::runtime::store::RuntimeIdKind::AdapterState,
            seed,
        ))
        .expect("adapter state handle")
    }

    #[tokio::test]
    async fn routes_typed_prepare_only_to_the_selected_adapter_without_session_ownership() {
        let codex_calls = Arc::new(AtomicUsize::new(0));
        let claude_calls = Arc::new(AtomicUsize::new(0));
        let mut router = AgentRouter::new();
        router.register(Arc::new(PrepareProbeAgent {
            kind: AgentKind::Codex,
            calls: Arc::clone(&codex_calls),
        }));
        router.register(Arc::new(PrepareProbeAgent {
            kind: AgentKind::ClaudeCode,
            calls: Arc::clone(&claude_calls),
        }));

        let prepared: PreparedAgentTurnHandle = router
            .prepare_turn(
                AgentKind::ClaudeCode,
                request(0x41, AgentKind::ClaudeCode),
                adapter_state(0x42),
            )
            .await
            .expect("selected adapter prepares the turn");

        assert_eq!(codex_calls.load(Ordering::SeqCst), 0);
        assert_eq!(claude_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            prepared
                .exec_spec()
                .expect("validated prepared spec")
                .program(),
            Path::new("/usr/bin/true")
        );
        assert_eq!(router.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn rejects_configuration_agent_mismatch_before_adapter_hook() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = AgentRouter::new();
        router.register(Arc::new(PrepareProbeAgent {
            kind: AgentKind::Codex,
            calls: Arc::clone(&calls),
        }));

        let error = router
            .prepare_turn(
                AgentKind::Codex,
                request(0x51, AgentKind::ClaudeCode),
                adapter_state(0x52),
            )
            .await
            .expect_err("configuration agent mismatch must fail before adapter prepare");

        assert_eq!(error.code, "adapter-configuration-agent-mismatch");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(router.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn codex_and_default_adapter_report_native_history_unavailable() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = AgentRouter::new();
        router.register(Arc::new(PrepareProbeAgent {
            kind: AgentKind::Codex,
            calls: Arc::clone(&calls),
        }));

        let error = router
            .read_native_history(
                runtime_id(crate::runtime::store::RuntimeIdKind::AdapterState, 0x61),
                AgentKind::Codex,
            )
            .await
            .expect_err("Codex has no native history projection backend");

        assert_eq!(error, NativeHistoryReadError::Unavailable);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
