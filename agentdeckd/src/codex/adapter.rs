//! Codex adapter for the session-scoped M0 lifecycle.
//!
//! The adapter owns only one control mailbox. The [`CodexSessionOwner`]
//! exclusively owns the app-server child, stdio, RPC correlation and turn
//! state until cleanup has completed.

use crate::agent::{Agent, AgentEventSender, AgentSessionExit, AgentSessionHandle};
use crate::codex::capabilities::{build_codex_capabilities, supported_codex_version};
use crate::codex::session::{
    AppServerFactory, CodexSessionOwner, ProcessAppServerFactory, SessionCommand,
};
use agentdeck_protocol::{
    ActionDecision, AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
    CodexSessionOptions, HistoryRequest, HistoryResponse, ProtocolError, SessionCapabilities,
    SessionId, SessionStart, ThreadId, TurnId, VendorControlPayload, VendorSessionOptions,
};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, oneshot};

const SESSION_COMMAND_CAPACITY: usize = 8;

#[derive(Clone)]
struct SessionControl {
    session_id: SessionId,
    commands: mpsc::Sender<SessionCommand>,
}

async fn publish_owner_exit(exit_tx: oneshot::Sender<AgentSessionExit>, exit: AgentSessionExit) {
    // RuntimeHub owns the externally observable retirement order. The owner
    // leaves this slot occupied; the Hub later holds its admission gate while
    // it releases the slot and enqueues SessionClosed. Cleanup failures
    // intentionally never release the slot.
    let _ = exit_tx.send(exit);
}

/// Codex M0 supports one live session per daemon instance.
pub struct CodexAdapter {
    factory: Arc<dyn AppServerFactory>,
    session: Arc<Mutex<Option<SessionControl>>>,
}

impl CodexAdapter {
    pub fn new() -> Self {
        Self::with_factory(Arc::new(ProcessAppServerFactory::production()))
    }

    /// Deterministic constructor for shape tests. Capability inspection uses
    /// the pinned protocol version and never executes the user's Codex binary.
    /// A gated test may still explicitly call `start_session` to exercise the
    /// production factory.
    pub fn new_for_test() -> Self {
        Self::new()
    }

    fn with_factory(factory: Arc<dyn AppServerFactory>) -> Self {
        Self {
            factory,
            session: Arc::new(Mutex::new(None)),
        }
    }

    fn capabilities_for_v3(&self) -> SessionCapabilities {
        build_codex_capabilities(supported_codex_version().to_string())
    }

    fn validate_start(start: &SessionStart) -> Result<(), ProtocolError> {
        if start.agent_kind != AgentKind::Codex {
            return Err(error(
                "wrong-vendor",
                "CodexAdapter received a non-Codex agentKind",
            ));
        }
        if start.session_id.0.trim().is_empty() {
            return Err(error("invalid-session", "sessionId must be non-empty"));
        }
        validate_cwd(&start.cwd)?;
        if start
            .resume_thread_id
            .as_ref()
            .is_some_and(|thread_id| thread_id.0.trim().is_empty())
        {
            return Err(error(
                "invalid-thread",
                "resumeThreadId must be non-empty when provided",
            ));
        }
        if let Some(initial_turn) = &start.initial_turn {
            if initial_turn.turn_id.0.trim().is_empty() || initial_turn.prompt.trim().is_empty() {
                return Err(error(
                    "invalid-turn",
                    "initialTurn.turnId and prompt must be non-empty",
                ));
            }
        }

        let options = match &start.vendor_options {
            VendorSessionOptions::Codex(options) => options,
            VendorSessionOptions::ClaudeCode(_) => {
                return Err(error(
                    "wrong-vendor",
                    "CodexAdapter received non-Codex vendor options",
                ));
            }
        };
        validate_m0_options(options)
    }

    async fn command_sender(
        &self,
        session_id: &SessionId,
    ) -> Result<mpsc::Sender<SessionCommand>, ProtocolError> {
        let session = self.session.lock().await;
        match session.as_ref() {
            Some(control) if &control.session_id == session_id => Ok(control.commands.clone()),
            _ => Err(session_not_found(session_id)),
        }
    }

    async fn dispatch_command<F>(
        &self,
        session_id: &SessionId,
        build: F,
    ) -> Result<(), ProtocolError>
    where
        F: FnOnce(oneshot::Sender<Result<(), ProtocolError>>) -> SessionCommand,
    {
        let commands = self.command_sender(session_id).await?;
        dispatch_to_owner(commands, session_id, build).await
    }
}

#[async_trait::async_trait]
impl Agent for CodexAdapter {
    fn kind(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn capabilities(&self) -> SessionCapabilities {
        self.capabilities_for_v3()
    }

    async fn start_session(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        Self::validate_start(&start)?;

        let session_id = start.session_id.clone();
        let resume_thread_id = start.resume_thread_id.clone();
        let (commands, command_rx) = mpsc::channel(SESSION_COMMAND_CAPACITY);
        let (exit_tx, exit_rx) = oneshot::channel();

        // Hold the slot lock until the task has been spawned and its control
        // mailbox installed. If the owner fails immediately, its cleanup task
        // waits for this lock and cannot clear a slot that has not been set yet.
        let mut active = self.session.lock().await;
        if let Some(existing) = active.as_ref() {
            return Err(error(
                "session-busy",
                format!(
                    "Codex session {} is still active; close it before starting another",
                    existing.session_id.0
                ),
            ));
        }

        let owner = CodexSessionOwner::new(start, events, command_rx, Arc::clone(&self.factory));
        let owner_task = tokio::spawn(async move {
            let exit = owner.run().await;
            publish_owner_exit(exit_tx, exit).await;
        });
        let abort_handle = owner_task.abort_handle();
        *active = Some(SessionControl {
            session_id: session_id.clone(),
            commands,
        });
        drop(active);

        Ok(AgentSessionHandle {
            session_id,
            // A new thread id is known only after the asynchronous handshake.
            // A resume request may safely expose its caller-provided id here;
            // the owner still verifies the vendor response before readiness.
            thread_id: resume_thread_id,
            agent_kind: AgentKind::Codex,
            abort_handle,
            exit: Some(exit_rx),
        })
    }

    async fn continue_thread(
        &self,
        _thread_id: ThreadId,
        _cwd: std::path::PathBuf,
        _prompt: String,
        _events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        Err(error(
            "codex-continue-requires-session-start",
            "Codex resume requires SessionStart with caller-owned sessionId and resumeThreadId",
        ))
    }

    async fn start_turn(
        &self,
        session_id: &SessionId,
        turn_id: TurnId,
        prompt: String,
    ) -> Result<(), ProtocolError> {
        self.dispatch_command(session_id, |reply| SessionCommand::StartTurn {
            turn_id,
            prompt,
            reply,
        })
        .await
    }

    async fn cancel_turn(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
    ) -> Result<(), ProtocolError> {
        self.dispatch_command(session_id, |reply| SessionCommand::CancelTurn {
            turn_id: turn_id.clone(),
            reply,
        })
        .await
    }

    async fn close_session(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        self.dispatch_command(session_id, |reply| SessionCommand::Close { reply })
            .await
    }

    async fn session_retired(&self, session_id: &SessionId, cleanup_confirmed: bool) {
        if !cleanup_confirmed {
            return;
        }
        let mut active = self.session.lock().await;
        if active
            .as_ref()
            .is_some_and(|control| &control.session_id == session_id)
        {
            *active = None;
        }
    }

    async fn submit_decision(
        &self,
        session_id: &SessionId,
        _decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        let _ = self.command_sender(session_id).await?;
        Err(error(
            "action-decision-not-supported",
            "Codex M0 uses approvalPolicy=never and does not accept action decisions",
        ))
    }

    async fn submit_vendor_control(
        &self,
        _session_id: &SessionId,
        payload: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        match payload {
            VendorControlPayload::Codex(_) => Err(error(
                "codex-vendor-control-requires-new-turn",
                "Codex M0 options are fixed for the whole session; start a new session to change them",
            )),
            VendorControlPayload::ClaudeCode(_) => Err(error(
                "wrong-vendor",
                "CodexAdapter received non-Codex vendor control",
            )),
        }
    }

    /// Route neutral history requests through Codex's official app-server
    /// history APIs. These short-lived processes are independent of the one
    /// M0 live-session slot.
    async fn handle_history(
        &self,
        request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        use crate::codex::history;
        match request {
            HistoryRequest::List {
                cwd_filter, limit, ..
            } => {
                let items = history::list_history(cwd_filter.as_deref(), limit).await?;
                Ok(HistoryResponse::List(items))
            }
            HistoryRequest::Read { thread_id, .. } => {
                let response = history::read_history(&thread_id).await?;
                Ok(HistoryResponse::Read(response))
            }
            HistoryRequest::Archive { thread_id, .. } => {
                history::archive(&thread_id).await?;
                Ok(HistoryResponse::Ack)
            }
            HistoryRequest::Unarchive { thread_id, .. } => {
                history::unarchive(&thread_id).await?;
                Ok(HistoryResponse::Ack)
            }
            HistoryRequest::Rename {
                thread_id, title, ..
            } => {
                history::rename(&thread_id, &title).await?;
                Ok(HistoryResponse::Ack)
            }
        }
    }

    /// Legacy session cancellation now means an orderly session close. An
    /// already-gone session remains an idempotent success for old callers.
    async fn cancel(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        let commands = {
            let session = self.session.lock().await;
            match session.as_ref() {
                Some(control) if &control.session_id == session_id => {
                    Some(control.commands.clone())
                }
                _ => None,
            }
        };
        let Some(commands) = commands else {
            return Ok(());
        };
        dispatch_to_owner(commands, session_id, |reply| SessionCommand::Close {
            reply,
        })
        .await
    }
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_cwd(cwd: &Path) -> Result<(), ProtocolError> {
    if !cwd.is_absolute() || !cwd.is_dir() {
        return Err(error(
            "invalid-cwd",
            "cwd must be an absolute path to an existing directory",
        ));
    }
    Ok(())
}

fn validate_m0_options(options: &CodexSessionOptions) -> Result<(), ProtocolError> {
    let supported = options.approval_policy == CodexApprovalPolicy::Never
        && options.sandbox == CodexSandboxMode::ReadOnly
        && options.reasoning_effort == CodexReasoningEffort::Medium
        && !options.persist_approval
        && options.mcp_overrides.is_empty();
    if !supported {
        return Err(error(
            "unsupported-session-options",
            "Codex M0 requires approvalPolicy=never, sandbox=read-only, reasoningEffort=medium, persistApproval=false and no MCP overrides",
        ));
    }
    Ok(())
}

async fn dispatch_to_owner<F>(
    commands: mpsc::Sender<SessionCommand>,
    session_id: &SessionId,
    build: F,
) -> Result<(), ProtocolError>
where
    F: FnOnce(oneshot::Sender<Result<(), ProtocolError>>) -> SessionCommand,
{
    let (reply_tx, reply_rx) = oneshot::channel();
    commands
        .send(build(reply_tx))
        .await
        .map_err(|_| session_not_found(session_id))?;
    reply_rx.await.map_err(|_| session_not_found(session_id))?
}

fn session_not_found(session_id: &SessionId) -> ProtocolError {
    error(
        "session-not-found",
        format!("Codex session {} is not active", session_id.0),
    )
}

fn error(code: &str, message: impl Into<String>) -> ProtocolError {
    ProtocolError {
        code: code.into(),
        message: message.into(),
        diagnostic_ref: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex::session::OpenedAppServer;
    use agentdeck_protocol::{InitialTurn, RuntimeOptions, SessionOutcome};
    use async_trait::async_trait;
    use std::future::pending;
    use std::path::PathBuf;

    struct PendingFactory;

    #[async_trait]
    impl AppServerFactory for PendingFactory {
        async fn open(&self, _cwd: &Path) -> Result<OpenedAppServer, ProtocolError> {
            pending().await
        }
    }

    struct FailingFactory;

    #[async_trait]
    impl AppServerFactory for FailingFactory {
        async fn open(&self, _cwd: &Path) -> Result<OpenedAppServer, ProtocolError> {
            Err(error("fake-open-failed", "deterministic factory failure"))
        }
    }

    fn valid_start(session_id: &str) -> SessionStart {
        SessionStart {
            session_id: SessionId(session_id.into()),
            agent_kind: AgentKind::Codex,
            cwd: std::env::current_dir().unwrap(),
            resume_thread_id: None,
            initial_turn: Some(InitialTurn {
                turn_id: TurnId("turn-1".into()),
                prompt: "hello".into(),
            }),
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
    async fn retains_exact_client_session_id_and_rejects_a_second_session() {
        let adapter = CodexAdapter::with_factory(Arc::new(PendingFactory));
        let (events, _events_rx) = mpsc::channel(8);
        let first = adapter
            .start_session(valid_start("client-session-1"), events.clone())
            .await
            .unwrap();
        assert_eq!(first.session_id, SessionId("client-session-1".into()));
        assert!(first.exit.is_some());

        let error = match adapter
            .start_session(valid_start("client-session-2"), events)
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("a second Codex session must be rejected"),
        };
        assert_eq!(error.code, "session-busy");

        // The pending factory deliberately keeps the owner alive so the
        // second-start assertion is deterministic. No child was spawned.
        first.abort_handle.abort();
    }

    #[tokio::test]
    async fn owner_exit_keeps_slot_until_hub_publishes_retirement() {
        let adapter = CodexAdapter::with_factory(Arc::new(FailingFactory));
        let (events, _events_rx) = mpsc::channel(8);

        for session_id in ["failed-session-1", "failed-session-2"] {
            let mut handle = adapter
                .start_session(valid_start(session_id), events.clone())
                .await
                .unwrap();
            let exit = handle.exit.take().unwrap().await.unwrap();
            assert_eq!(exit.outcome, SessionOutcome::Failed);
            assert_eq!(exit.error.as_ref().unwrap().code, "fake-open-failed");
            assert!(
                adapter.session.lock().await.is_some(),
                "owner exit must not release capacity before SessionClosed"
            );
            adapter
                .session_retired(&SessionId(session_id.into()), exit.cleanup_confirmed)
                .await;
            assert!(adapter.session.lock().await.is_none());
        }
    }

    #[tokio::test]
    async fn owner_exit_signal_does_not_mutate_adapter_capacity() {
        let (exit_tx, mut exit_rx) = oneshot::channel();
        publish_owner_exit(
            exit_tx,
            AgentSessionExit {
                thread_id: Some(ThreadId("cleanup-thread".into())),
                outcome: SessionOutcome::Closed,
                error: None,
                cleanup_confirmed: true,
            },
        )
        .await;
        let exit = exit_rx
            .try_recv()
            .expect("owner exit reaches the Hub immediately");
        assert!(exit.cleanup_confirmed);
    }

    #[tokio::test]
    async fn unconfirmed_cleanup_keeps_the_single_session_slot_owned() {
        let session_id = SessionId("cleanup-unconfirmed".into());
        let (commands, _command_rx) = mpsc::channel(1);
        let active = Arc::new(Mutex::new(Some(SessionControl {
            session_id: session_id.clone(),
            commands,
        })));
        let (exit_tx, exit_rx) = oneshot::channel();

        publish_owner_exit(
            exit_tx,
            AgentSessionExit {
                thread_id: Some(ThreadId("cleanup-thread".into())),
                outcome: SessionOutcome::Failed,
                error: Some(error(
                    "codex-cleanup-failed",
                    "deterministic cleanup failure",
                )),
                cleanup_confirmed: false,
            },
        )
        .await;

        let exit = exit_rx.await.expect("owner exit reaches the Hub");
        assert!(!exit.cleanup_confirmed);
        assert_eq!(
            active.lock().await.as_ref().map(|slot| &slot.session_id),
            Some(&session_id)
        );

        let adapter = CodexAdapter {
            factory: Arc::new(FailingFactory),
            session: active,
        };
        adapter.session_retired(&session_id, false).await;
        let (events, _events_rx) = mpsc::channel(1);
        let error = match adapter
            .start_session(valid_start("replacement-session"), events)
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("poisoned adapter must not admit a replacement session"),
        };
        assert_eq!(error.code, "session-busy");
    }

    #[test]
    fn validates_the_exact_m0_options() {
        let mut start = valid_start("session-1");
        assert!(CodexAdapter::validate_start(&start).is_ok());

        let VendorSessionOptions::Codex(options) = &mut start.vendor_options else {
            unreachable!();
        };
        options.reasoning_effort = CodexReasoningEffort::Low;
        let error = CodexAdapter::validate_start(&start).unwrap_err();
        assert_eq!(error.code, "unsupported-session-options");
    }

    #[test]
    fn validates_ids_and_cwd_before_opening_the_factory() {
        let mut start = valid_start(" ");
        assert_eq!(
            CodexAdapter::validate_start(&start).unwrap_err().code,
            "invalid-session"
        );

        start = valid_start("session-1");
        start.cwd = PathBuf::from("relative/path");
        assert_eq!(
            CodexAdapter::validate_start(&start).unwrap_err().code,
            "invalid-cwd"
        );
    }
}
