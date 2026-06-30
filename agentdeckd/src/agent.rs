//! Agent trait — the contract every adapter (CodexAdapter, ClaudeCodeAdapter,
//! future community adapters) must implement.
//!
//! N3 守护：Adapter 实现彼此不可见。共享逻辑只能下沉到此 trait 的 default
//! 方法，或 daemon 层。

use agentdeck_protocol::{
    ActionDecision, AgentKind, HistoryRequest, HistoryResponse, ProtocolError, ServerEvent,
    SessionCapabilities, SessionId, SessionStart, ThreadId, VendorControlPayload,
};
use std::sync::Arc;
use tokio::sync::mpsc;

pub type AgentEventSender = mpsc::Sender<ServerEvent>;

/// Handle returned when a session is started. The hub uses it to send
/// follow-up prompts / decisions / cancels to the same session.
pub struct AgentSessionHandle {
    pub session_id: SessionId,
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

    /// Continue an existing thread with a new prompt.
    async fn continue_thread(
        &self,
        thread_id: ThreadId,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError>;

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

    /// Serve a `HistoryRequest` (List / Read / Archive / Unarchive /
    /// Rename) for this adapter's own threads. The default returns a
    /// structured "not-supported" error so older / partial adapters
    /// don't break compilation when this trait grows. CC and Codex
    /// override this; the router merges cross-agent `List` results
    /// across all registered adapters (see `AgentRouter::handle_history`).
    ///
    /// Added by Task 4C — Phase 4 finalization.
    async fn handle_history(
        &self,
        _request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        Err(ProtocolError {
            code: "history-not-supported".into(),
            message: format!(
                "agent {:?} does not implement history",
                self.kind()
            ),
            diagnostic_ref: None,
        })
    }
}

/// Newtype wrapper to allow `dyn Agent` in maps.
pub type DynAgent = Arc<dyn Agent>;
