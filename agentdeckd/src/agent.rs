//! Agent trait — the contract every adapter (CodexAdapter, ClaudeCodeAdapter,
//! future community adapters) must implement.
//!
//! N3 守护：Adapter 实现彼此不可见。共享逻辑只能下沉到此 trait 的 default
//! 方法，或 daemon 层。

use agentdeck_protocol::{
    ActionDecision, AgentKind, HistoryRequest, HistoryResponse, ProtocolError, ServerEvent,
    SessionCapabilities, SessionId, SessionOutcome, SessionStart, ThreadId, TurnId,
    VendorControlPayload,
};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

pub type AgentEventSender = mpsc::Sender<ServerEvent>;

/// Terminal state reported by a session owner after it has stopped its
/// pumps and reaped the owned vendor process. The owner must not emit
/// `SessionClosed` itself: RuntimeHub first removes the session from both
/// routing tables, then publishes the terminal event.
pub struct AgentSessionExit {
    pub thread_id: Option<ThreadId>,
    pub outcome: SessionOutcome,
    pub error: Option<ProtocolError>,
    /// True only when no child was spawned or every owned process and pump
    /// was confirmed stopped. False poisons the daemon: another session must
    /// not be accepted after cleanup could not be proven.
    pub cleanup_confirmed: bool,
}

/// Handle returned when a session is started. The hub uses it to send
/// follow-up prompts / decisions / cancels to the same session.
pub struct AgentSessionHandle {
    pub session_id: SessionId,
    pub thread_id: Option<ThreadId>,
    pub agent_kind: AgentKind,
    /// Legacy pump abort handle kept for adapters that have not moved to a
    /// session owner yet. RuntimeHub does not use it to implement turn cancel
    /// or session close.
    pub abort_handle: tokio::task::AbortHandle,
    /// Session-owner completion signal. `Some` means the owner guarantees it
    /// sends exactly once, only after process cleanup and `wait` have finished.
    /// `None` keeps non-M0 adapters source-compatible during migration.
    pub exit: Option<oneshot::Receiver<AgentSessionExit>>,
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

    /// Continue an existing thread with a new prompt. `cwd` MUST be the
    /// working directory associated with the thread — vendors like
    /// Claude Code look up resume files under
    /// `~/.claude/projects/<encoded_cwd>/<id>.jsonl`, and tool_use runs
    /// in this directory. The hub passes the cwd from the original
    /// `SessionStart` (the Swift UI / CLI carries it forward).
    async fn continue_thread(
        &self,
        thread_id: ThreadId,
        cwd: std::path::PathBuf,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError>;

    /// Start another turn in an already-open live session. Session-scoped
    /// adapters override this; legacy one-shot adapters get a structured
    /// failure rather than silently starting a second process.
    async fn start_turn(
        &self,
        _session_id: &SessionId,
        _turn_id: TurnId,
        _prompt: String,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError {
            code: "turn-start-not-supported".into(),
            message: format!("agent {:?} does not implement live turn start", self.kind()),
            diagnostic_ref: None,
        })
    }

    /// Cancel only the matching in-flight turn while keeping the session
    /// alive. Implementations must not translate this into session teardown.
    async fn cancel_turn(
        &self,
        _session_id: &SessionId,
        _turn_id: &TurnId,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError {
            code: "turn-cancel-not-supported".into(),
            message: format!(
                "agent {:?} does not implement live turn cancel",
                self.kind()
            ),
            diagnostic_ref: None,
        })
    }

    /// Ask the session owner to stop and reap its vendor process. An M0 owner
    /// reports completion through `AgentSessionHandle::exit`; it must not emit
    /// `SessionClosed` directly.
    async fn close_session(&self, _session_id: &SessionId) -> Result<(), ProtocolError> {
        Err(ProtocolError {
            code: "session-close-not-supported".into(),
            message: format!(
                "agent {:?} does not implement live session close",
                self.kind()
            ),
            diagnostic_ref: None,
        })
    }

    /// Release adapter-local ownership inside RuntimeHub's session-admission
    /// critical section immediately before the unique `SessionClosed` is
    /// enqueued. A replacement start shares that gate, so it cannot enter
    /// before the old terminal. Cleanup failures pass `false` so an adapter
    /// can retain a poisoned slot until the daemon exits.
    async fn session_retired(&self, _session_id: &SessionId, _cleanup_confirmed: bool) {}

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
            message: format!("agent {:?} does not implement history", self.kind()),
            diagnostic_ref: None,
        })
    }
}

/// Newtype wrapper to allow `dyn Agent` in maps.
pub type DynAgent = Arc<dyn Agent>;
