//! Agent trait — the contract every adapter (CodexAdapter, ClaudeCodeAdapter,
//! future community adapters) must implement.
//!
//! N3 守护：Adapter 实现彼此不可见。共享逻辑只能下沉到此 trait 的 default
//! 方法，或 daemon 层。

use agentdeck_protocol::{
    ActionDecision, ActionRequest, AgentItem, AgentKind, HistoryRequest, HistoryResponse,
    HistoryTurn, ProtocolError, ServerEvent, SessionCapabilities, SessionId, SessionStart,
    ThreadId, TurnSummary, VendorControlPayload, VendorPanelPayload,
};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::runtime::store::RuntimeId;

pub type AgentEventSender = mpsc::Sender<ServerEvent>;

/// Canonical Runtime 从 adapter 接收的中立事件。旧 `ServerEvent` 强制携带
/// `ThreadId`，因此只能留在 stdio compatibility 路径；本类型在结构上没有 vendor
/// resume identity，也不允许透传未经建模的 raw vendor frame。
#[derive(Debug, Clone)]
pub enum CanonicalAgentEvent {
    Capabilities(SessionCapabilities),
    Item(AgentItem),
    ActionRequest(ActionRequest),
    TurnComplete(TurnSummary),
    Error(ProtocolError),
    VendorControl(VendorControlPayload),
    VendorPanelEvent(VendorPanelPayload),
}

pub type CanonicalAgentEventSender = mpsc::Sender<CanonicalAgentEvent>;

/// Canonical Runtime handle。只回传 daemon-owned transient session 与 neutral
/// `adapterStateKey`；vendor resume reference 永远留在 adapter 私域。
pub struct CanonicalAgentSessionHandle {
    pub session_id: SessionId,
    pub adapter_state_key: RuntimeId,
    pub agent_kind: AgentKind,
    pub abort_handle: tokio::task::AbortHandle,
}

/// Canonical history readback；不包含 stdio `HistoryReadResponse.thread_id`。
#[derive(Debug, Clone)]
pub struct CanonicalHistoryRead {
    pub agent_kind: AgentKind,
    pub turns: Vec<HistoryTurn>,
}

/// Handle returned when a session is started. The hub uses it to send
/// follow-up prompts / decisions / cancels to the same session.
pub struct AgentSessionHandle {
    pub session_id: SessionId,
    /// 仅供旧 IPC v2/stdin compatibility 回写；RuntimeCore 不得用它做主键或
    /// continue lookup。canonical 路径只携带 neutral adapterStateKey。
    pub thread_id: Option<ThreadId>,
    pub agent_kind: AgentKind,
    /// Used by RuntimeHub to drop the session and release the per-session lock.
    pub abort_handle: tokio::task::AbortHandle,
}

#[async_trait::async_trait]
pub trait Agent: Send + Sync + 'static {
    /// Static agent kind. Must match the discriminant used in protocol
    /// AgentKind for routing.
    fn kind(&self) -> AgentKind;

    /// Probe and return current capabilities. Called by daemon BEFORE
    /// emitting SessionCapabilities event. Implementation may invoke
    /// vendor CLI (e.g. `claude --version`, `claude auth status`) to
    /// determine accurate values; must complete within ~2s or return
    /// minimal capabilities + log a diagnostic.
    fn capabilities(&self) -> SessionCapabilities;

    /// Start a new session and stream events to the given sender. The
    /// adapter must:
    ///   1. Send SessionStarted FIRST.
    ///   2. Send SessionCapabilities BEFORE any AgentItem (N7).
    ///   3. Emit AgentItem / ActionRequest / VendorPanelEvent / TurnComplete
    ///      / Error as appropriate.
    async fn start_session(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError>;

    /// Canonical Runtime 路径：由 daemon 先生成并持久化 neutral
    /// `adapterStateKey`，adapter 再把 vendor resume reference 写入自己的私有
    /// namespace。默认拒绝，只有注入 typed repository 的 adapter 才能启用。
    async fn start_adapter_state(
        &self,
        _adapter_state_key: RuntimeId,
        _start: SessionStart,
        _events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        Err(ProtocolError {
            code: "adapter-state-not-configured".into(),
            message: "adapter private state repository is not configured".into(),
            diagnostic_ref: None,
        })
    }

    /// Continue an existing thread with a new prompt. `cwd` MUST be the
    /// working directory associated with the thread — vendors like
    /// Claude Code look up resume files under
    /// `~/.claude/projects/<encoded_cwd>/<id>.jsonl`, and tool_use runs
    /// in this directory. The hub passes the cwd from the original
    /// `SessionStart` (the Swift UI / CLI carries it forward).
    /// 旧 IPC v2/stdin compatibility 入口；raw ThreadId 不得进入 RuntimeCore。
    async fn continue_thread(
        &self,
        thread_id: ThreadId,
        cwd: std::path::PathBuf,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError>;

    /// Canonical Runtime 路径：只按 neutral adapterStateKey 继续，vendor ref
    /// 的解密与解释必须完全留在具体 adapter 模块。
    async fn continue_adapter_state(
        &self,
        _adapter_state_key: RuntimeId,
        _cwd: std::path::PathBuf,
        _prompt: String,
        _events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        Err(ProtocolError {
            code: "adapter-state-not-configured".into(),
            message: "adapter private state repository is not configured".into(),
            diagnostic_ref: None,
        })
    }

    /// Canonical history lookup：common 只给 neutral adapterStateKey；adapter
    /// 在私域解析 native ref，返回不含 ThreadId 的中立 turns。
    async fn read_adapter_history(
        &self,
        _adapter_state_key: RuntimeId,
    ) -> Result<CanonicalHistoryRead, ProtocolError> {
        Err(ProtocolError {
            code: "adapter-state-not-configured".into(),
            message: "adapter private history repository is not configured".into(),
            diagnostic_ref: None,
        })
    }

    /// Submit a user decision on a pending ActionRequest.
    async fn submit_decision(
        &self,
        session_id: &SessionId,
        decision: ActionDecision,
    ) -> Result<(), ProtocolError>;

    /// Submit a vendor-specific control update mid-session.
    async fn submit_vendor_control(
        &self,
        session_id: &SessionId,
        payload: VendorControlPayload,
    ) -> Result<(), ProtocolError>;

    /// Cancel a running session.
    async fn cancel(&self, session_id: &SessionId) -> Result<(), ProtocolError>;

    /// Serve a compatibility `HistoryRequest` (List / Read / Archive / Unarchive /
    /// Rename) for this adapter's own threads. The default returns a
    /// structured "not-supported" error so older / partial adapters
    /// don't break compilation when this trait grows. CC and Codex
    /// override this; the router merges cross-agent `List` results
    /// across all registered adapters (see `AgentRouter::handle_history`). Raw
    /// ThreadId stays on this stdio compatibility surface; P3 RuntimeCore imports
    /// native history through adapter-private reconciliation instead.
    ///
    /// Added by Task 4C — Phase 4 finalization.
    async fn handle_history(
        &self,
        _request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        Err(ProtocolError {
            code: "history-not-supported".into(),
            message: format!("agent {:?} does not implement history", self.kind()),
            diagnostic_ref: None,
        })
    }
}

/// Newtype wrapper to allow `dyn Agent` in maps.
pub type DynAgent = Arc<dyn Agent>;
