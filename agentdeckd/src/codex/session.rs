//! Session-scoped Codex app-server owner.
//!
//! Exactly one task owns one live app-server connection.  All requests,
//! responses, notifications, turn commands and cleanup decisions are
//! serialized here so a turn terminal can never race another stdout reader
//! or a process kill performed by a different task.

use crate::agent::{AgentEventSender, AgentSessionExit};
use crate::codex::app_server::{
    CodexBinary, StderrTail, drain_child_stderr, join_stderr_drain, process_group_exists,
    signal_process_group, spawn_child_with_binary,
};
use crate::codex::capabilities::build_codex_capabilities;
use crate::codex::translate::CodexTranslator;
use agentdeck_protocol::{
    AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode, InitialTurn,
    ProtocolError, ServerEvent, SessionId, SessionOutcome, SessionStart, ThreadId, TurnId,
    TurnNextState, TurnOutcome, TurnSummary,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const INTERRUPT_TERMINAL_TIMEOUT: Duration = Duration::from_secs(10);
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const KILL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_GROUP_POLL_INTERVAL: Duration = Duration::from_millis(10);

type BoxReader = Pin<Box<dyn AsyncRead + Send>>;
type BoxWriter = Pin<Box<dyn AsyncWrite + Send>>;

pub(crate) type CommandReply = oneshot::Sender<Result<(), ProtocolError>>;

#[derive(Debug)]
pub(crate) enum SessionCommand {
    StartTurn {
        turn_id: TurnId,
        prompt: String,
        reply: CommandReply,
    },
    CancelTurn {
        turn_id: TurnId,
        reply: CommandReply,
    },
    Close {
        reply: CommandReply,
    },
}

#[async_trait]
pub(crate) trait AppServerProcess: Send {
    fn pid(&self) -> Option<u32>;
    async fn shutdown(&mut self) -> Result<(), ProtocolError>;
}

pub(crate) struct OpenedAppServer {
    version: String,
    stdin: Option<BoxWriter>,
    stdout: BufReader<BoxReader>,
    process: Box<dyn AppServerProcess>,
    stderr_tail: Option<StderrTail>,
    stderr_drain: Option<JoinHandle<Result<(), ProtocolError>>>,
}

impl OpenedAppServer {
    #[cfg(test)]
    fn for_test(
        version: impl Into<String>,
        stdin: impl AsyncWrite + Send + 'static,
        stdout: impl AsyncRead + Send + 'static,
        process: impl AppServerProcess + 'static,
    ) -> Self {
        Self {
            version: version.into(),
            stdin: Some(Box::pin(stdin)),
            stdout: BufReader::new(Box::pin(stdout)),
            process: Box::new(process),
            stderr_tail: None,
            stderr_drain: None,
        }
    }

    async fn shutdown(&mut self) -> Result<(), ProtocolError> {
        // Closing stdin is the normal app-server shutdown signal.  The direct
        // child is only group-killed if it does not leave within the grace
        // period; either way `shutdown` waits for the direct child.
        self.stdin.take();
        let process_result = self.process.shutdown().await;
        let stderr_result = join_stderr_drain(&mut self.stderr_drain, process_result.is_ok()).await;
        process_result.and(stderr_result)
    }
}

#[async_trait]
pub(crate) trait AppServerFactory: Send + Sync {
    async fn open(&self, cwd: &Path) -> Result<OpenedAppServer, ProtocolError>;
}

#[derive(Clone, Default)]
pub(crate) struct ProcessAppServerFactory;

impl ProcessAppServerFactory {
    pub(crate) fn production() -> Self {
        Self
    }
}

#[async_trait]
impl AppServerFactory for ProcessAppServerFactory {
    async fn open(&self, cwd: &Path) -> Result<OpenedAppServer, ProtocolError> {
        let binary = CodexBinary::resolve()?;
        let mut child = spawn_child_with_binary(cwd, &binary)?;
        let stdin = child.stdin.take().ok_or_else(|| ProtocolError {
            code: "codex-spawn-failed".into(),
            message: "codex child missing stdin pipe".into(),
            diagnostic_ref: None,
        })?;
        let stdout = child.stdout.take().ok_or_else(|| ProtocolError {
            code: "codex-spawn-failed".into(),
            message: "codex child missing stdout pipe".into(),
            diagnostic_ref: None,
        })?;
        let (stderr_tail, stderr_drain) = drain_child_stderr(&mut child)?;
        Ok(OpenedAppServer {
            version: binary.version().to_string(),
            stdin: Some(Box::pin(stdin)),
            stdout: BufReader::new(Box::pin(stdout)),
            process: Box::new(OwnedChild::new(child)),
            stderr_tail: Some(stderr_tail),
            stderr_drain: Some(stderr_drain),
        })
    }
}

struct OwnedChild {
    child: Option<Child>,
    process_group_id: Option<u32>,
    signal_group: Arc<dyn Fn(u32) -> std::io::Result<()> + Send + Sync>,
    group_exists: Arc<dyn Fn(u32) -> std::io::Result<bool> + Send + Sync>,
    group_exit_timeout: Duration,
}

impl OwnedChild {
    fn new(child: Child) -> Self {
        let process_group_id = child.id();
        Self {
            child: Some(child),
            process_group_id,
            signal_group: Arc::new(signal_process_group),
            group_exists: Arc::new(process_group_exists),
            group_exit_timeout: KILL_SHUTDOWN_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_group_ops(
        child: Child,
        signal_group: Arc<dyn Fn(u32) -> std::io::Result<()> + Send + Sync>,
        group_exists: Arc<dyn Fn(u32) -> std::io::Result<bool> + Send + Sync>,
        group_exit_timeout: Duration,
    ) -> Self {
        let process_group_id = child.id();
        Self {
            child: Some(child),
            process_group_id,
            signal_group,
            group_exists,
            group_exit_timeout,
        }
    }

    fn terminate_process_group(&self) -> Result<Option<u32>, ProtocolError> {
        #[cfg(unix)]
        {
            let process_group_id = self.process_group_id.ok_or_else(|| ProtocolError {
                code: "codex-cleanup-failed".into(),
                message: "Codex app-server process group id was not captured".into(),
                diagnostic_ref: None,
            })?;
            (self.signal_group)(process_group_id).map_err(|error| ProtocolError {
                code: "codex-cleanup-failed".into(),
                message: format!("failed to terminate Codex app-server process group: {error}"),
                diagnostic_ref: None,
            })?;
            Ok(Some(process_group_id))
        }
        #[cfg(not(unix))]
        {
            Ok(None)
        }
    }

    async fn confirm_process_group_exit(
        &self,
        process_group_id: Option<u32>,
    ) -> Result<(), ProtocolError> {
        #[cfg(unix)]
        if let Some(process_group_id) = process_group_id {
            let wait_for_exit = async {
                loop {
                    match (self.group_exists)(process_group_id) {
                        Ok(false) => return Ok(()),
                        Ok(true) => tokio::time::sleep(PROCESS_GROUP_POLL_INTERVAL).await,
                        Err(error) => {
                            return Err(ProtocolError {
                                code: "codex-cleanup-failed".into(),
                                message: format!(
                                    "failed to confirm Codex app-server process group exit: {error}"
                                ),
                                diagnostic_ref: None,
                            });
                        }
                    }
                }
            };
            return tokio::time::timeout(self.group_exit_timeout, wait_for_exit)
                .await
                .map_err(|_| ProtocolError {
                    code: "codex-cleanup-failed".into(),
                    message: "timed out waiting for Codex app-server process group to exit".into(),
                    diagnostic_ref: None,
                })?;
        }
        let _ = process_group_id;
        Ok(())
    }

    async fn cleanup_process_group(&self) -> Result<(), ProtocolError> {
        let process_group_id = self.terminate_process_group()?;
        self.confirm_process_group_exit(process_group_id).await
    }
}

#[async_trait]
impl AppServerProcess for OwnedChild {
    fn pid(&self) -> Option<u32> {
        self.process_group_id
    }

    async fn shutdown(&mut self) -> Result<(), ProtocolError> {
        let Some(mut child) = self.child.take() else {
            return self.cleanup_process_group().await;
        };
        match child.try_wait() {
            Ok(Some(_)) => return self.cleanup_process_group().await,
            Ok(None) => {}
            Err(error) => {
                let group_result = self.cleanup_process_group().await;
                return group_result.and(Err(cleanup_error(error)));
            }
        }
        match tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, child.wait()).await {
            Ok(Ok(_)) => return self.cleanup_process_group().await,
            Ok(Err(error)) => {
                let group_result = self.cleanup_process_group().await;
                return group_result.and(Err(cleanup_error(error)));
            }
            Err(_) => {}
        }
        let group_signal_result = self.terminate_process_group();
        let direct_kill_error = child.start_kill().err().map(cleanup_error);
        let wait_result = match tokio::time::timeout(KILL_SHUTDOWN_TIMEOUT, child.wait()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(cleanup_error(error)),
            Err(_) => Err(ProtocolError {
                code: "codex-cleanup-failed".into(),
                message: "timed out waiting for Codex app-server to exit after termination".into(),
                diagnostic_ref: None,
            }),
        };
        let group_result = match group_signal_result {
            Ok(process_group_id) => self.confirm_process_group_exit(process_group_id).await,
            Err(error) => Err(error),
        };
        group_result?;
        match wait_result {
            Ok(()) => Ok(()),
            Err(error) => Err(direct_kill_error.unwrap_or(error)),
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.terminate_process_group();
        }
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
    }
}

fn cleanup_error(error: std::io::Error) -> ProtocolError {
    ProtocolError {
        code: "codex-cleanup-failed".into(),
        message: format!("failed to wait for Codex app-server: {error}"),
        diagnostic_ref: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerState {
    Initializing,
    Ready,
    StartingTurn,
    Running,
    Interrupting,
    Stopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Initialize,
    ThreadStart,
    ThreadResume,
    TurnStart,
    TurnInterrupt,
}

impl PendingKind {
    fn method(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::ThreadStart => "thread/start",
            Self::ThreadResume => "thread/resume",
            Self::TurnStart => "turn/start",
            Self::TurnInterrupt => "turn/interrupt",
        }
    }
}

#[derive(Debug)]
struct PendingRpc {
    id: u64,
    kind: PendingKind,
    deadline: tokio::time::Instant,
}

#[derive(Debug)]
struct TurnContext {
    client_id: TurnId,
    vendor_id: Option<String>,
    started_at: Instant,
    cancel_requested: bool,
    close_requested: bool,
    interrupt_sent: bool,
    failure_override: Option<ProtocolError>,
    pending_terminal: Option<VendorTerminal>,
}

#[derive(Debug)]
struct VendorTerminal {
    vendor_id: String,
    status: String,
    duration_ms: Option<u64>,
}

#[derive(Debug)]
struct LogicalExit {
    outcome: SessionOutcome,
    error: Option<ProtocolError>,
}

pub(crate) struct CodexSessionOwner {
    start: SessionStart,
    events: AgentEventSender,
    commands: mpsc::Receiver<SessionCommand>,
    factory: Arc<dyn AppServerFactory>,
    interrupt_terminal_timeout: Duration,
}

impl CodexSessionOwner {
    pub(crate) fn new(
        start: SessionStart,
        events: AgentEventSender,
        commands: mpsc::Receiver<SessionCommand>,
        factory: Arc<dyn AppServerFactory>,
    ) -> Self {
        Self {
            start,
            events,
            commands,
            factory,
            interrupt_terminal_timeout: INTERRUPT_TERMINAL_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_interrupt_terminal_timeout(mut self, timeout: Duration) -> Self {
        self.interrupt_terminal_timeout = timeout;
        self
    }

    pub(crate) async fn run(mut self) -> AgentSessionExit {
        let session_id = self.start.session_id.clone();

        // Keep control responsive while a test or future production factory
        // performs asynchronous pre-spawn work. A queued close wins before the
        // open future is polled, so it cannot create a child only to tear it
        // down again.
        let open_cwd = self.start.cwd.clone();
        let open = self.factory.open(&open_cwd);
        tokio::pin!(open);
        let opened = loop {
            tokio::select! {
                biased;
                command = self.commands.recv() => {
                    match command {
                        Some(SessionCommand::Close { reply }) => {
                            let _ = reply.send(Ok(()));
                            return AgentSessionExit {
                                thread_id: self.start.resume_thread_id.clone(),
                                outcome: SessionOutcome::Closed,
                                error: None,
                                cleanup_confirmed: true,
                            };
                        }
                        Some(other) => reject_preinitialization_command(other),
                        None => {
                            return AgentSessionExit {
                                thread_id: self.start.resume_thread_id.clone(),
                                outcome: SessionOutcome::Closed,
                                error: None,
                                cleanup_confirmed: true,
                            };
                        }
                    }
                }
                result = &mut open => break result,
            }
        };

        let mut connection = match opened {
            Ok(connection) => connection,
            Err(error) => {
                return AgentSessionExit {
                    thread_id: self.start.resume_thread_id.clone(),
                    outcome: SessionOutcome::Failed,
                    error: Some(with_diagnostic_ref(error, &session_id)),
                    cleanup_confirmed: true,
                };
            }
        };
        let _process_id = connection.process.pid();

        let mut running = RunningOwner::new(
            self.start,
            self.events,
            self.commands,
            connection.version.clone(),
            self.interrupt_terminal_timeout,
        );
        let logical_exit = running.run(&mut connection).await;
        let thread_id = running.thread_id.clone();
        let cleanup_result = running.shutdown_connection(&mut connection).await;

        match cleanup_result {
            Ok(()) => AgentSessionExit {
                thread_id,
                outcome: logical_exit.outcome,
                error: logical_exit.error,
                cleanup_confirmed: true,
            },
            Err(error) => AgentSessionExit {
                thread_id,
                outcome: SessionOutcome::Failed,
                error: Some(with_diagnostic_ref(error, &session_id)),
                cleanup_confirmed: false,
            },
        }
    }
}

fn reject_preinitialization_command(command: SessionCommand) {
    let (reply, error) = match command {
        SessionCommand::StartTurn { reply, .. } => (
            reply,
            ProtocolError {
                code: "session-not-ready".into(),
                message: "session is still initializing".into(),
                diagnostic_ref: None,
            },
        ),
        SessionCommand::CancelTurn { reply, .. } => (
            reply,
            ProtocolError {
                code: "turn-not-active".into(),
                message: "session has no active turn".into(),
                diagnostic_ref: None,
            },
        ),
        SessionCommand::Close { .. } => unreachable!(),
    };
    let _ = reply.send(Err(error));
}

fn reject_stopping_command(command: SessionCommand) {
    match command {
        SessionCommand::StartTurn { reply, .. } => {
            let _ = reply.send(Err(ProtocolError {
                code: "session-not-ready".into(),
                message: "session is stopping".into(),
                diagnostic_ref: None,
            }));
        }
        SessionCommand::CancelTurn { reply, .. } => {
            let _ = reply.send(Err(ProtocolError {
                code: "turn-not-active".into(),
                message: "session is stopping and has no active turn".into(),
                diagnostic_ref: None,
            }));
        }
        SessionCommand::Close { reply } => {
            let _ = reply.send(Ok(()));
        }
    }
}

struct RunningOwner {
    session_id: SessionId,
    cwd: PathBuf,
    resume_thread_id: Option<ThreadId>,
    initial_turn: Option<InitialTurn>,
    events: AgentEventSender,
    commands: mpsc::Receiver<SessionCommand>,
    version: String,
    state: OwnerState,
    thread_id: Option<ThreadId>,
    translator: Option<CodexTranslator>,
    next_rpc_id: u64,
    pending: Option<PendingRpc>,
    turn: Option<TurnContext>,
    used_turn_ids: HashSet<TurnId>,
    interrupt_terminal_timeout: Duration,
    close_deadline: Option<tokio::time::Instant>,
    interrupt_terminal_deadline: Option<tokio::time::Instant>,
}

impl RunningOwner {
    fn new(
        start: SessionStart,
        events: AgentEventSender,
        commands: mpsc::Receiver<SessionCommand>,
        version: String,
        interrupt_terminal_timeout: Duration,
    ) -> Self {
        Self {
            session_id: start.session_id,
            cwd: start.cwd,
            resume_thread_id: start.resume_thread_id,
            initial_turn: start.initial_turn,
            events,
            commands,
            version,
            state: OwnerState::Initializing,
            thread_id: None,
            translator: None,
            next_rpc_id: 1,
            pending: None,
            turn: None,
            used_turn_ids: HashSet::new(),
            interrupt_terminal_timeout,
            close_deadline: None,
            interrupt_terminal_deadline: None,
        }
    }

    async fn run(&mut self, connection: &mut OpenedAppServer) -> LogicalExit {
        if let Err(error) = self
            .send_request(
                connection,
                PendingKind::Initialize,
                json!({
                    "clientInfo": {
                        "name": "agentdeck",
                        "version": env!("CARGO_PKG_VERSION"),
                    }
                }),
            )
            .await
        {
            return self.fatal(error).await;
        }

        loop {
            let input = if let Some((deadline, timeout)) = self.next_timeout() {
                tokio::select! {
                    command = self.commands.recv() => OwnerInput::Command(command),
                    line = read_line(&mut connection.stdout) => OwnerInput::Line(line),
                    _ = tokio::time::sleep_until(deadline) => OwnerInput::Timeout(timeout),
                }
            } else {
                tokio::select! {
                    command = self.commands.recv() => OwnerInput::Command(command),
                    line = read_line(&mut connection.stdout) => OwnerInput::Line(line),
                }
            };

            let exit = match input {
                OwnerInput::Command(Some(command)) => {
                    self.handle_command(connection, command).await
                }
                OwnerInput::Command(None) => Some(LogicalExit {
                    outcome: SessionOutcome::Closed,
                    error: None,
                }),
                OwnerInput::Line(Ok(Some(frame))) => self.handle_frame(connection, frame).await,
                OwnerInput::Line(Ok(None)) => Some(
                    self.fatal(self.error("codex-disconnected", "Codex app-server closed stdout"))
                        .await,
                ),
                OwnerInput::Line(Err(error)) => Some(self.fatal(error).await),
                OwnerInput::Timeout(OwnerTimeout::Rpc(kind)) => Some(
                    self.fatal(self.error(
                        "codex-rpc-timeout",
                        format!("timed out waiting for {} response", kind.method()),
                    ))
                    .await,
                ),
                OwnerInput::Timeout(OwnerTimeout::Close) => Some(
                    self.fatal(self.error(
                        "codex-close-timeout",
                        "timed out waiting for the active turn to stop during SessionClose",
                    ))
                    .await,
                ),
                OwnerInput::Timeout(OwnerTimeout::InterruptTerminal) => Some(
                    self.fatal(self.error(
                        "codex-interrupt-timeout",
                        "timed out waiting for turn/completed after turn/interrupt succeeded",
                    ))
                    .await,
                ),
            };
            if let Some(exit) = exit {
                self.state = OwnerState::Stopping;
                return exit;
            }
        }
    }

    async fn shutdown_connection(
        &mut self,
        connection: &mut OpenedAppServer,
    ) -> Result<(), ProtocolError> {
        self.state = OwnerState::Stopping;
        let shutdown = connection.shutdown();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = &mut shutdown => {
                    self.commands.close();
                    while let Ok(command) = self.commands.try_recv() {
                        reject_stopping_command(command);
                    }
                    return result;
                }
                command = self.commands.recv() => {
                    match command {
                        Some(command) => reject_stopping_command(command),
                        None => return shutdown.await,
                    }
                }
            }
        }
    }

    async fn handle_command(
        &mut self,
        connection: &mut OpenedAppServer,
        command: SessionCommand,
    ) -> Option<LogicalExit> {
        match command {
            SessionCommand::StartTurn {
                turn_id,
                prompt,
                reply,
            } => {
                let result = self.accept_turn(connection, turn_id, prompt).await;
                match result {
                    Ok(()) => {
                        let _ = reply.send(Ok(()));
                        None
                    }
                    Err(error) if is_command_rejection(&error) => {
                        let _ = reply.send(Err(error));
                        None
                    }
                    Err(error) => {
                        let _ = reply.send(Ok(()));
                        Some(self.fatal(error).await)
                    }
                }
            }
            SessionCommand::CancelTurn { turn_id, reply } => {
                let result = self.cancel_turn(connection, &turn_id).await;
                match result {
                    Ok(()) => {
                        let _ = reply.send(Ok(()));
                        None
                    }
                    Err(error) if is_command_rejection(&error) => {
                        let _ = reply.send(Err(error));
                        None
                    }
                    Err(error) => {
                        let _ = reply.send(Ok(()));
                        Some(self.fatal(error).await)
                    }
                }
            }
            SessionCommand::Close { reply } => {
                let _ = reply.send(Ok(()));
                if let Some(turn) = &mut self.turn {
                    turn.close_requested = true;
                    if self.close_deadline.is_none() {
                        self.close_deadline =
                            Some(tokio::time::Instant::now() + self.interrupt_terminal_timeout);
                    }
                    match self.ensure_interrupt(connection).await {
                        Ok(()) => None,
                        Err(error) => Some(self.fatal(error).await),
                    }
                } else {
                    Some(LogicalExit {
                        outcome: SessionOutcome::Closed,
                        error: None,
                    })
                }
            }
        }
    }

    async fn handle_frame(
        &mut self,
        connection: &mut OpenedAppServer,
        frame: Value,
    ) -> Option<LogicalExit> {
        let method = frame.get("method").and_then(Value::as_str);
        let has_id = frame.get("id").is_some();

        if has_id && method.is_none() {
            return self.handle_response(connection, frame).await;
        }
        if has_id && method.is_some() {
            return self.handle_server_request(connection, frame).await;
        }
        let Some(method) = method else {
            return Some(
                self.fatal(self.error(
                    "codex-protocol-error",
                    "Codex emitted an unclassifiable frame",
                ))
                .await,
            );
        };
        if frame.get("error").is_some_and(|error| !error.is_null()) {
            return Some(
                self.fatal(self.error(
                    "codex-protocol-error",
                    "Codex emitted an error notification",
                ))
                .await,
            );
        }
        match method {
            "turn/completed" => self.handle_turn_completed(connection, &frame).await,
            "turn/started" => self.handle_turn_started(&frame).await,
            // The authoritative session lifecycle is emitted only after the
            // correlated thread response.  A notification must not create a
            // second/phantom SessionStarted.
            "thread/started" => None,
            _ => {
                if let Some(translator) = &mut self.translator {
                    for output in translator.translate_value_with_routes(&frame) {
                        match output.event {
                            ServerEvent::SessionStarted { .. }
                            | ServerEvent::TurnComplete { .. }
                            | ServerEvent::Error { .. } => {}
                            event => {
                                let _ = self.events.send(event).await;
                            }
                        }
                    }
                }
                None
            }
        }
    }

    fn next_timeout(&self) -> Option<(tokio::time::Instant, OwnerTimeout)> {
        let rpc = self
            .pending
            .as_ref()
            .map(|pending| (pending.deadline, OwnerTimeout::Rpc(pending.kind)));
        let close = self
            .close_deadline
            .map(|deadline| (deadline, OwnerTimeout::Close));
        let interrupt_terminal = self
            .interrupt_terminal_deadline
            .map(|deadline| (deadline, OwnerTimeout::InterruptTerminal));
        [rpc, close, interrupt_terminal]
            .into_iter()
            .flatten()
            .min_by_key(|(deadline, _)| *deadline)
    }

    async fn handle_response(
        &mut self,
        connection: &mut OpenedAppServer,
        frame: Value,
    ) -> Option<LogicalExit> {
        let Some(id) = frame.get("id").and_then(Value::as_u64) else {
            return Some(
                self.fatal(self.error(
                    "codex-unmatched-response",
                    "Codex response used an unexpected id type",
                ))
                .await,
            );
        };
        let Some(pending) = self.pending.take() else {
            return Some(
                self.fatal(self.error(
                    "codex-unmatched-response",
                    "Codex emitted a response with no pending request",
                ))
                .await,
            );
        };
        if pending.id != id {
            return Some(
                self.fatal(self.error(
                    "codex-unmatched-response",
                    "Codex response id did not match the pending request",
                ))
                .await,
            );
        }

        if frame.get("error").is_some_and(|value| !value.is_null()) {
            // A turn may reach its authoritative terminal while the correlated
            // interrupt response is still in flight. If that response then
            // reports that the interrupt lost the race, the completed turn is
            // still authoritative and must win over the request error. This
            // keeps both cancel and running-close races single-terminal and
            // preserves the state selected by `finish_vendor_turn`.
            if pending.kind == PendingKind::TurnInterrupt
                && let Some(terminal) = self
                    .turn
                    .as_mut()
                    .and_then(|turn| turn.pending_terminal.take())
            {
                return self.finish_vendor_turn(terminal).await;
            }
            let error = self.error(
                "codex-protocol-error",
                format!("Codex rejected {}", pending.kind.method()),
            );
            return match pending.kind {
                PendingKind::TurnStart => {
                    let closing = self.turn.as_ref().is_some_and(|turn| turn.close_requested);
                    let error = self
                        .turn
                        .as_ref()
                        .and_then(|turn| turn.failure_override.clone())
                        .unwrap_or(error);
                    self.finish_turn(
                        TurnOutcome::Failed,
                        if closing {
                            TurnNextState::Closing
                        } else {
                            TurnNextState::Ready
                        },
                        None,
                        Some(error),
                    )
                    .await;
                    closing.then_some(LogicalExit {
                        outcome: SessionOutcome::Closed,
                        error: None,
                    })
                }
                _ => Some(self.fatal(error).await),
            };
        }
        let result = frame.get("result").cloned().unwrap_or(Value::Null);

        match pending.kind {
            PendingKind::Initialize => {
                if let Err(error) = self
                    .write(connection, &json!({ "method": "initialized" }))
                    .await
                {
                    return Some(self.fatal(error).await);
                }
                let (kind, params) = if let Some(thread_id) = &self.resume_thread_id {
                    (
                        PendingKind::ThreadResume,
                        json!({
                            "threadId": thread_id.0,
                            "cwd": self.cwd.display().to_string(),
                            "sandbox": "read-only",
                            "approvalPolicy": "never",
                        }),
                    )
                } else {
                    (
                        PendingKind::ThreadStart,
                        json!({
                            "cwd": self.cwd.display().to_string(),
                            "sandbox": "read-only",
                            "approvalPolicy": "never",
                        }),
                    )
                };
                if let Err(error) = self.send_request(connection, kind, params).await {
                    return Some(self.fatal(error).await);
                }
            }
            PendingKind::ThreadStart | PendingKind::ThreadResume => {
                let Some(id) = result
                    .get("thread")
                    .and_then(|thread| thread.get("id"))
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                else {
                    return Some(
                        self.fatal(
                            self.error("codex-protocol-error", "thread response omitted thread.id"),
                        )
                        .await,
                    );
                };
                if pending.kind == PendingKind::ThreadResume
                    && self.resume_thread_id.as_ref().map(|id| id.0.as_str()) != Some(id)
                {
                    return Some(
                        self.fatal(self.error(
                            "codex-protocol-error",
                            "thread/resume returned a different thread id",
                        ))
                        .await,
                    );
                }
                let thread_id = ThreadId(id.to_string());
                self.thread_id = Some(thread_id.clone());
                self.translator = Some(CodexTranslator::with_policy(
                    self.session_id.clone(),
                    Some(thread_id.clone()),
                    CodexApprovalPolicy::Never,
                    CodexSandboxMode::ReadOnly,
                    false,
                ));
                let _ = self
                    .events
                    .send(ServerEvent::SessionStarted {
                        session_id: self.session_id.clone(),
                        thread_id: Some(thread_id),
                        agent_kind: AgentKind::Codex,
                    })
                    .await;
                let _ = self
                    .events
                    .send(ServerEvent::SessionCapabilities {
                        session_id: self.session_id.clone(),
                        agent_kind: AgentKind::Codex,
                        capabilities: build_codex_capabilities(self.version.clone()),
                    })
                    .await;
                self.state = OwnerState::Ready;
                if let Some(initial_turn) = self.initial_turn.take() {
                    if let Err(error) = self
                        .accept_turn(connection, initial_turn.turn_id, initial_turn.prompt)
                        .await
                    {
                        return Some(self.fatal(error).await);
                    }
                }
            }
            PendingKind::TurnStart => {
                let Some(vendor_turn_id) = result
                    .get("turn")
                    .and_then(|turn| turn.get("id"))
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                else {
                    return Some(
                        self.fatal(self.error(
                            "codex-protocol-error",
                            "turn/start response omitted turn.id",
                        ))
                        .await,
                    );
                };
                let Some(turn) = &mut self.turn else {
                    return Some(
                        self.fatal(self.error(
                            "codex-protocol-error",
                            "turn/start response arrived without an active turn",
                        ))
                        .await,
                    );
                };
                if let Some(existing) = &turn.vendor_id {
                    if existing != vendor_turn_id {
                        return Some(
                            self.fatal(self.error(
                                "codex-protocol-error",
                                "turn/start response changed the vendor turn id",
                            ))
                            .await,
                        );
                    }
                }
                turn.vendor_id = Some(vendor_turn_id.to_string());
                self.state = OwnerState::Running;
                if turn.cancel_requested || turn.close_requested || turn.failure_override.is_some()
                {
                    if let Err(error) = self.ensure_interrupt(connection).await {
                        return Some(self.fatal(error).await);
                    }
                }
            }
            PendingKind::TurnInterrupt => {
                self.state = OwnerState::Interrupting;
                if let Some(terminal) = self
                    .turn
                    .as_mut()
                    .and_then(|turn| turn.pending_terminal.take())
                {
                    return self.finish_vendor_turn(terminal).await;
                }
                self.interrupt_terminal_deadline =
                    Some(tokio::time::Instant::now() + self.interrupt_terminal_timeout);
            }
        }
        None
    }

    async fn handle_server_request(
        &mut self,
        connection: &mut OpenedAppServer,
        frame: Value,
    ) -> Option<LogicalExit> {
        let Some(id) = frame.get("id").cloned() else {
            unreachable!();
        };
        let method = frame
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if let Err(error) = self
            .write(
                connection,
                &json!({
                    "id": id,
                    "error": { "code": -32601, "message": "not supported" },
                }),
            )
            .await
        {
            return Some(self.fatal(error).await);
        }
        let error = self.error(
            "codex-unsupported-server-request",
            format!("unsupported Codex server request: {method}"),
        );
        let Some(turn) = &mut self.turn else {
            return Some(self.fatal(error).await);
        };
        turn.failure_override = Some(error);
        match self.ensure_interrupt(connection).await {
            Ok(()) => None,
            Err(error) => Some(self.fatal(error).await),
        }
    }

    async fn handle_turn_started(&mut self, frame: &Value) -> Option<LogicalExit> {
        let vendor_id = frame
            .get("params")
            .and_then(|params| params.get("turn"))
            .and_then(|turn| turn.get("id"))
            .and_then(Value::as_str);
        if let (Some(vendor_id), Some(turn)) = (vendor_id, &mut self.turn) {
            if let Some(existing) = &turn.vendor_id {
                if existing != vendor_id {
                    return Some(
                        self.fatal(self.error(
                            "codex-protocol-error",
                            "turn/started used a different turn id",
                        ))
                        .await,
                    );
                }
            } else {
                turn.vendor_id = Some(vendor_id.to_string());
            }
        }
        None
    }

    async fn handle_turn_completed(
        &mut self,
        _connection: &mut OpenedAppServer,
        frame: &Value,
    ) -> Option<LogicalExit> {
        if matches!(
            self.pending.as_ref().map(|pending| pending.kind),
            Some(PendingKind::TurnStart)
        ) {
            return Some(
                self.fatal(self.error(
                    "codex-protocol-error",
                    "turn completed before turn/start response",
                ))
                .await,
            );
        }
        let Some(turn) = frame.get("params").and_then(|params| params.get("turn")) else {
            return Some(
                self.fatal(
                    self.error("codex-protocol-error", "turn/completed omitted params.turn"),
                )
                .await,
            );
        };
        let Some(vendor_id) = turn
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            return Some(
                self.fatal(self.error("codex-protocol-error", "turn/completed omitted turn.id"))
                    .await,
            );
        };
        let Some(status) = turn.get("status").and_then(Value::as_str) else {
            return Some(
                self.fatal(
                    self.error("codex-protocol-error", "turn/completed omitted turn.status"),
                )
                .await,
            );
        };
        let duration_ms = turn
            .get("durationMs")
            .and_then(Value::as_i64)
            .and_then(|value| u64::try_from(value).ok());
        let terminal = VendorTerminal {
            vendor_id: vendor_id.to_string(),
            status: status.to_string(),
            duration_ms,
        };
        if matches!(
            self.pending.as_ref().map(|pending| pending.kind),
            Some(PendingKind::TurnInterrupt)
        ) {
            if let Some(active) = &mut self.turn {
                active.pending_terminal = Some(terminal);
                return None;
            }
        }
        self.finish_vendor_turn(terminal).await
    }

    async fn accept_turn(
        &mut self,
        connection: &mut OpenedAppServer,
        turn_id: TurnId,
        prompt: String,
    ) -> Result<(), ProtocolError> {
        if self.turn.is_some() {
            return Err(ProtocolError {
                code: "turn-already-running".into(),
                message: "the session already has an in-flight turn".into(),
                diagnostic_ref: None,
            });
        }
        if self.state != OwnerState::Ready {
            return Err(ProtocolError {
                code: "session-not-ready".into(),
                message: "the session is not ready for a new turn".into(),
                diagnostic_ref: None,
            });
        }
        if turn_id.0.trim().is_empty() || prompt.trim().is_empty() {
            return Err(ProtocolError {
                code: "invalid-turn".into(),
                message: "turnId and prompt must be non-empty".into(),
                diagnostic_ref: None,
            });
        }
        if !self.used_turn_ids.insert(turn_id.clone()) {
            return Err(ProtocolError {
                code: "turn-id-already-used".into(),
                message: "turnId was already used in this session".into(),
                diagnostic_ref: None,
            });
        }
        let thread_id = self.thread_id.clone().ok_or_else(|| {
            self.error("session-not-ready", "the session has no established thread")
        })?;
        self.turn = Some(TurnContext {
            client_id: turn_id.clone(),
            vendor_id: None,
            started_at: Instant::now(),
            cancel_requested: false,
            close_requested: false,
            interrupt_sent: false,
            failure_override: None,
            pending_terminal: None,
        });
        self.state = OwnerState::StartingTurn;
        let _ = self
            .events
            .send(ServerEvent::TurnStarted {
                session_id: self.session_id.clone(),
                thread_id: thread_id.clone(),
                agent_kind: AgentKind::Codex,
                turn_id,
            })
            .await;
        self.send_request(
            connection,
            PendingKind::TurnStart,
            json!({
                "threadId": thread_id.0,
                "input": [{ "type": "text", "text": prompt }],
                "effort": reasoning_effort_str(CodexReasoningEffort::Medium),
            }),
        )
        .await
    }

    async fn cancel_turn(
        &mut self,
        connection: &mut OpenedAppServer,
        turn_id: &TurnId,
    ) -> Result<(), ProtocolError> {
        let Some(turn) = &mut self.turn else {
            return Err(ProtocolError {
                code: "turn-not-active".into(),
                message: "the session has no active turn".into(),
                diagnostic_ref: None,
            });
        };
        if &turn.client_id != turn_id {
            return Err(ProtocolError {
                code: "turn-not-active".into(),
                message: "turnId does not match the active turn".into(),
                diagnostic_ref: None,
            });
        }
        if turn.cancel_requested {
            return Ok(());
        }
        turn.cancel_requested = true;
        self.ensure_interrupt(connection).await
    }

    async fn ensure_interrupt(
        &mut self,
        connection: &mut OpenedAppServer,
    ) -> Result<(), ProtocolError> {
        let Some(turn) = &self.turn else {
            return Ok(());
        };
        if turn.interrupt_sent {
            return Ok(());
        }
        // Codex may publish turn/started before replying to turn/start. Keep
        // the interrupt intent on the turn, but do not overlap JSON-RPC
        // requests; handle_response retries this after the correlated start
        // response clears `pending`.
        if self.pending.is_some() {
            return Ok(());
        }
        // The official interrupt requires the vendor turn id.  A cancel that
        // arrives while turn/start is still pending is remembered and sent as
        // soon as the correlated response supplies that id.
        let Some(vendor_turn_id) = turn.vendor_id.clone() else {
            return Ok(());
        };
        let thread_id = self.thread_id.clone().ok_or_else(|| {
            self.error("session-not-ready", "cannot interrupt without a thread id")
        })?;
        self.turn
            .as_mut()
            .expect("active turn checked above")
            .interrupt_sent = true;
        self.state = OwnerState::Interrupting;
        self.send_request(
            connection,
            PendingKind::TurnInterrupt,
            json!({ "threadId": thread_id.0, "turnId": vendor_turn_id }),
        )
        .await
    }

    async fn finish_vendor_turn(&mut self, terminal: VendorTerminal) -> Option<LogicalExit> {
        let Some(turn) = &self.turn else {
            return Some(
                self.fatal(self.error(
                    "codex-protocol-error",
                    "turn terminal arrived without an active turn",
                ))
                .await,
            );
        };
        if let Some(expected) = &turn.vendor_id {
            if expected != &terminal.vendor_id {
                return Some(
                    self.fatal(self.error(
                        "codex-protocol-error",
                        "turn terminal used a different turn id",
                    ))
                    .await,
                );
            }
        }

        if terminal.status == "inProgress" {
            return Some(
                self.fatal(self.error(
                    "codex-terminal-status-invalid",
                    "turn/completed carried inProgress status",
                ))
                .await,
            );
        }

        let closing = turn.close_requested;
        let elapsed_ms = terminal.duration_ms.unwrap_or_else(|| {
            u64::try_from(turn.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
        });
        let (outcome, error) = if let Some(error) = turn.failure_override.clone() {
            (TurnOutcome::Failed, Some(error))
        } else if closing || turn.cancel_requested {
            (TurnOutcome::Canceled, None)
        } else {
            match terminal.status.as_str() {
                "completed" => (TurnOutcome::Succeeded, None),
                "interrupted" => (TurnOutcome::Canceled, None),
                "failed" => (
                    TurnOutcome::Failed,
                    Some(self.error("codex-turn-failed", "Codex reported a failed turn")),
                ),
                _ => {
                    return Some(
                        self.fatal(self.error(
                            "codex-terminal-status-invalid",
                            "unknown Codex terminal status",
                        ))
                        .await,
                    );
                }
            }
        };
        let next_state = if closing {
            TurnNextState::Closing
        } else {
            TurnNextState::Ready
        };
        self.finish_turn(
            outcome,
            next_state,
            Some(TurnSummary {
                total_input_tokens: None,
                total_output_tokens: None,
                elapsed_ms,
            }),
            error,
        )
        .await;

        if closing {
            Some(LogicalExit {
                outcome: SessionOutcome::Closed,
                error: None,
            })
        } else {
            None
        }
    }

    async fn finish_turn(
        &mut self,
        outcome: TurnOutcome,
        next_state: TurnNextState,
        summary: Option<TurnSummary>,
        error: Option<ProtocolError>,
    ) {
        let Some(turn) = self.turn.take() else {
            return;
        };
        self.pending = None;
        self.close_deadline = None;
        self.interrupt_terminal_deadline = None;
        self.state = if next_state == TurnNextState::Ready {
            OwnerState::Ready
        } else {
            OwnerState::Stopping
        };
        if let Some(translator) = &mut self.translator {
            // Keep the same translator/session identity; Issue #4 adds an
            // explicit per-turn buffer reset while implementing streaming.
            let _ = translator.thread_id();
        }
        let Some(thread_id) = self.thread_id.clone() else {
            return;
        };
        let _ = self
            .events
            .send(ServerEvent::TurnFinished {
                session_id: self.session_id.clone(),
                thread_id,
                agent_kind: AgentKind::Codex,
                turn_id: turn.client_id,
                outcome,
                next_state,
                summary,
                error,
            })
            .await;
    }

    async fn fatal(&mut self, error: ProtocolError) -> LogicalExit {
        let error = with_diagnostic_ref(error, &self.session_id);
        if self.turn.is_some() {
            self.finish_turn(
                TurnOutcome::Failed,
                TurnNextState::Closing,
                None,
                Some(error.clone()),
            )
            .await;
        }
        LogicalExit {
            outcome: SessionOutcome::Failed,
            error: Some(error),
        }
    }

    async fn send_request(
        &mut self,
        connection: &mut OpenedAppServer,
        kind: PendingKind,
        params: Value,
    ) -> Result<(), ProtocolError> {
        if self.pending.is_some() {
            return Err(self.error(
                "codex-protocol-error",
                "attempted to overlap app-server requests",
            ));
        }
        let id = self.next_rpc_id;
        self.next_rpc_id = self
            .next_rpc_id
            .checked_add(1)
            .ok_or_else(|| self.error("codex-rpc-id-exhausted", "Codex request id exhausted"))?;
        self.write(
            connection,
            &json!({ "id": id, "method": kind.method(), "params": params }),
        )
        .await?;
        self.pending = Some(PendingRpc {
            id,
            kind,
            deadline: tokio::time::Instant::now() + RPC_TIMEOUT,
        });
        Ok(())
    }

    async fn write(
        &self,
        connection: &mut OpenedAppServer,
        frame: &Value,
    ) -> Result<(), ProtocolError> {
        let stderr_tail = connection.stderr_tail.clone();
        let stdin = connection.stdin.as_mut().ok_or_else(|| {
            self.error("codex-stdin-write-failed", "Codex stdin is already closed")
        })?;
        let mut line = serde_json::to_vec(frame).map_err(|error| {
            self.error(
                "codex-encode-failed",
                format!("failed to encode Codex request: {error}"),
            )
        })?;
        line.push(b'\n');
        stdin.write_all(&line).await.map_err(|error| {
            enrich_with_stderr_tail(
                stderr_tail.as_ref(),
                self.error(
                    "codex-stdin-write-failed",
                    format!("failed to write Codex request: {error}"),
                ),
            )
        })?;
        stdin.flush().await.map_err(|error| {
            enrich_with_stderr_tail(
                stderr_tail.as_ref(),
                self.error(
                    "codex-stdin-write-failed",
                    format!("failed to flush Codex request: {error}"),
                ),
            )
        })
    }

    fn error(&self, code: &str, message: impl Into<String>) -> ProtocolError {
        ProtocolError {
            code: code.into(),
            message: message.into(),
            diagnostic_ref: Some(self.session_id.0.clone()),
        }
    }
}

fn enrich_with_stderr_tail(
    stderr_tail: Option<&StderrTail>,
    error: ProtocolError,
) -> ProtocolError {
    stderr_tail.map_or(error.clone(), |tail| tail.enrich_error(error))
}

fn is_command_rejection(error: &ProtocolError) -> bool {
    matches!(
        error.code.as_str(),
        "turn-already-running"
            | "turn-id-already-used"
            | "session-not-ready"
            | "turn-not-active"
            | "invalid-turn"
    )
}

fn with_diagnostic_ref(mut error: ProtocolError, session_id: &SessionId) -> ProtocolError {
    if error.diagnostic_ref.is_none() {
        error.diagnostic_ref = Some(session_id.0.clone());
    }
    error
}

fn reasoning_effort_str(effort: CodexReasoningEffort) -> &'static str {
    match effort {
        CodexReasoningEffort::Minimal => "minimal",
        CodexReasoningEffort::Low => "low",
        CodexReasoningEffort::Medium => "medium",
        CodexReasoningEffort::High => "high",
    }
}

enum OwnerInput {
    Command(Option<SessionCommand>),
    Line(Result<Option<Value>, ProtocolError>),
    Timeout(OwnerTimeout),
}

#[derive(Clone, Copy)]
enum OwnerTimeout {
    Rpc(PendingKind),
    Close,
    InterruptTerminal,
}

async fn read_line(reader: &mut BufReader<BoxReader>) -> Result<Option<Value>, ProtocolError> {
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .await
        .map_err(|error| ProtocolError {
            code: "codex-stdout-read-failed".into(),
            message: format!("failed to read Codex stdout: {error}"),
            diagnostic_ref: None,
        })?;
    if bytes == 0 {
        return Ok(None);
    }
    serde_json::from_str(line.trim())
        .map(Some)
        .map_err(|error| ProtocolError {
            code: "codex-malformed-json".into(),
            // Never copy the raw vendor line into IPC.
            message: format!("Codex emitted malformed JSON: {error}"),
            diagnostic_ref: None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::{CodexSessionOptions, RuntimeOptions, VendorSessionOptions};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, DuplexStream, duplex};

    #[derive(Clone)]
    struct TestProcess {
        cleaned: Arc<AtomicBool>,
        cleanup_error: Option<ProtocolError>,
    }

    #[async_trait]
    impl AppServerProcess for TestProcess {
        fn pid(&self) -> Option<u32> {
            Some(4242)
        }

        async fn shutdown(&mut self) -> Result<(), ProtocolError> {
            self.cleaned.store(true, Ordering::SeqCst);
            self.cleanup_error.clone().map_or(Ok(()), Err)
        }
    }

    struct BlockingCleanupProcess {
        entered: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
    }

    #[async_trait]
    impl AppServerProcess for BlockingCleanupProcess {
        fn pid(&self) -> Option<u32> {
            Some(4243)
        }

        async fn shutdown(&mut self) -> Result<(), ProtocolError> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            if let Some(release) = self.release.take() {
                let _ = release.await;
            }
            Ok(())
        }
    }

    struct TestFactory {
        connection: StdMutex<Option<OpenedAppServer>>,
        opens: AtomicUsize,
    }

    impl TestFactory {
        fn new(connection: OpenedAppServer) -> Self {
            Self {
                connection: StdMutex::new(Some(connection)),
                opens: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl AppServerFactory for TestFactory {
        async fn open(&self, _cwd: &Path) -> Result<OpenedAppServer, ProtocolError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.connection
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| ProtocolError {
                    code: "test-spawned-twice".into(),
                    message: "test factory was opened more than once".into(),
                    diagnostic_ref: None,
                })
        }
    }

    struct PendingOpenFactory;

    #[async_trait]
    impl AppServerFactory for PendingOpenFactory {
        async fn open(&self, _cwd: &Path) -> Result<OpenedAppServer, ProtocolError> {
            std::future::pending().await
        }
    }

    fn start(initial_turn: Option<InitialTurn>) -> SessionStart {
        SessionStart {
            session_id: SessionId("session-1".into()),
            agent_kind: AgentKind::Codex,
            cwd: PathBuf::from("/tmp"),
            resume_thread_id: None,
            initial_turn,
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

    async fn read_json(reader: &mut BufReader<DuplexStream>) -> Value {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(line.trim()).unwrap()
    }

    async fn write_json(stream: &mut DuplexStream, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).await.unwrap();
        stream.flush().await.unwrap();
    }

    fn test_connection(
        cleanup_error: Option<ProtocolError>,
    ) -> (
        OpenedAppServer,
        BufReader<DuplexStream>,
        DuplexStream,
        Arc<AtomicBool>,
    ) {
        let (owner_stdin, server_input) = duplex(8192);
        let (server_output, owner_stdout) = duplex(8192);
        let cleaned = Arc::new(AtomicBool::new(false));
        let connection = OpenedAppServer::for_test(
            "codex-cli 0.145.0",
            owner_stdin,
            owner_stdout,
            TestProcess {
                cleaned: Arc::clone(&cleaned),
                cleanup_error,
            },
        );
        (
            connection,
            BufReader::new(server_input),
            server_output,
            cleaned,
        )
    }

    async fn accept_new_thread_handshake(
        server_input: &mut BufReader<DuplexStream>,
        server_output: &mut DuplexStream,
    ) {
        let initialize = read_json(server_input).await;
        assert_eq!(initialize["id"], 1);
        assert_eq!(initialize["method"], "initialize");
        write_json(server_output, json!({"id": 1, "result": {}})).await;
        assert_eq!(
            read_json(server_input).await,
            json!({"method": "initialized"})
        );
        let thread_start = read_json(server_input).await;
        assert_eq!(thread_start["id"], 2);
        assert_eq!(thread_start["method"], "thread/start");
        assert_eq!(thread_start["params"]["sandbox"], "read-only");
        assert_eq!(thread_start["params"]["approvalPolicy"], "never");
        write_json(
            server_output,
            json!({"id": 2, "result": {"thread": {"id": "thread-1"}}}),
        )
        .await;
    }

    async fn next_event(events: &mut mpsc::Receiver<ServerEvent>) -> ServerEvent {
        tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("timed out waiting for owner event")
            .expect("owner event channel closed")
    }

    async fn command_reply(reply: oneshot::Receiver<Result<(), ProtocolError>>) {
        tokio::time::timeout(Duration::from_secs(2), reply)
            .await
            .expect("timed out waiting for owner command reply")
            .expect("owner command reply channel dropped")
            .expect("owner rejected command");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reaped_direct_child_still_cleans_the_saved_process_group() {
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let expected_process_group = child.id().unwrap();
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let recorded_calls = Arc::clone(&calls);
        let signal_group = Arc::new(move |process_group_id| {
            recorded_calls.lock().unwrap().push(process_group_id);
            Ok(())
        });
        let mut owned = OwnedChild::with_group_ops(
            child,
            signal_group,
            Arc::new(|_| Ok(false)),
            Duration::from_millis(50),
        );
        owned.child.as_mut().unwrap().wait().await.unwrap();

        owned.shutdown().await.unwrap();

        assert_eq!(*calls.lock().unwrap(), vec![expected_process_group]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_group_signal_failure_prevents_cleanup_confirmation() {
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let signal_group = Arc::new(|_process_group_id| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "synthetic group signal failure",
            ))
        });
        let mut owned = OwnedChild::with_group_ops(
            child,
            signal_group,
            Arc::new(|_| Ok(false)),
            Duration::from_millis(50),
        );
        owned.child.as_mut().unwrap().wait().await.unwrap();

        let error = owned.shutdown().await.unwrap_err();

        assert_eq!(error.code, "codex-cleanup-failed");
        assert!(error.message.contains("process group"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_group_cleanup_waits_for_confirmed_disappearance() {
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let probes = Arc::new(AtomicUsize::new(0));
        let recorded_probes = Arc::clone(&probes);
        let group_exists = Arc::new(move |_process_group_id| {
            Ok(recorded_probes.fetch_add(1, Ordering::SeqCst) == 0)
        });
        let mut owned = OwnedChild::with_group_ops(
            child,
            Arc::new(|_| Ok(())),
            group_exists,
            Duration::from_millis(100),
        );
        owned.child.as_mut().unwrap().wait().await.unwrap();

        owned.shutdown().await.unwrap();

        assert_eq!(probes.load(Ordering::SeqCst), 2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_group_disappearance_timeout_prevents_cleanup_confirmation() {
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let mut owned = OwnedChild::with_group_ops(
            child,
            Arc::new(|_| Ok(())),
            Arc::new(|_| Ok(true)),
            Duration::from_millis(25),
        );
        owned.child.as_mut().unwrap().wait().await.unwrap();

        let error = owned.shutdown().await.unwrap_err();

        assert_eq!(error.code, "codex-cleanup-failed");
        assert!(error.message.contains("process group to exit"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_group_probe_failure_prevents_cleanup_confirmation() {
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let mut owned = OwnedChild::with_group_ops(
            child,
            Arc::new(|_| Ok(())),
            Arc::new(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "synthetic group probe failure",
                ))
            }),
            Duration::from_millis(50),
        );
        owned.child.as_mut().unwrap().wait().await.unwrap();

        let error = owned.shutdown().await.unwrap_err();

        assert_eq!(error.code, "codex-cleanup-failed");
        assert!(error.message.contains("confirm"));
    }

    #[tokio::test]
    async fn owner_reuses_one_connection_for_two_turns_then_waits_on_close() {
        let (owner_stdin, server_input) = duplex(8192);
        let mut server_input = BufReader::new(server_input);
        let (mut server_output, owner_stdout) = duplex(8192);
        let cleaned = Arc::new(AtomicBool::new(false));
        let connection = OpenedAppServer::for_test(
            "codex-cli 0.145.0",
            owner_stdin,
            owner_stdout,
            TestProcess {
                cleaned: Arc::clone(&cleaned),
                cleanup_error: None,
            },
        );
        assert_eq!(connection.process.pid(), Some(4242));
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(32);
        let (commands_tx, commands_rx) = mpsc::channel(8);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-1".into()),
                prompt: "first".into(),
            })),
            events_tx,
            commands_rx,
            factory.clone(),
        );

        let server = tokio::spawn(async move {
            let initialize = read_json(&mut server_input).await;
            assert_eq!(initialize["method"], "initialize");
            write_json(&mut server_output, json!({"id": 1, "result": {}})).await;
            assert_eq!(
                read_json(&mut server_input).await,
                json!({"method":"initialized"})
            );
            let thread_start = read_json(&mut server_input).await;
            assert_eq!(thread_start["method"], "thread/start");
            write_json(
                &mut server_output,
                json!({"id": 2, "result": {"thread": {"id": "thread-1"}}}),
            )
            .await;

            for (rpc_id, vendor_turn, expected_prompt) in [
                (3, "vendor-turn-1", "first"),
                (4, "vendor-turn-2", "second"),
            ] {
                let turn_start = read_json(&mut server_input).await;
                assert_eq!(turn_start["method"], "turn/start");
                assert_eq!(turn_start["params"]["input"][0]["text"], expected_prompt);
                write_json(
                    &mut server_output,
                    json!({"id": rpc_id, "result": {"turn": {"id": vendor_turn}}}),
                )
                .await;
                write_json(
                    &mut server_output,
                    json!({
                        "method": "turn/completed",
                        "params": {"turn": {"id": vendor_turn, "status": "completed", "items": []}}
                    }),
                )
                .await;
            }
            // Closing the connection drops the owner-side writer before the
            // process wait is acknowledged.
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });

        let run = tokio::spawn(owner.run());

        assert!(matches!(
            events_rx.recv().await,
            Some(ServerEvent::SessionStarted { .. })
        ));
        assert!(matches!(
            events_rx.recv().await,
            Some(ServerEvent::SessionCapabilities { .. })
        ));
        assert!(
            matches!(events_rx.recv().await, Some(ServerEvent::TurnStarted { turn_id, .. }) if turn_id == TurnId("turn-1".into()))
        );
        assert!(
            matches!(events_rx.recv().await, Some(ServerEvent::TurnFinished { turn_id, outcome: TurnOutcome::Succeeded, next_state: TurnNextState::Ready, .. }) if turn_id == TurnId("turn-1".into()))
        );

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::StartTurn {
                turn_id: TurnId("turn-1".into()),
                prompt: "duplicate".into(),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let error = reply_rx.await.unwrap().unwrap_err();
        assert_eq!(error.code, "turn-id-already-used");

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::StartTurn {
                turn_id: TurnId("turn-2".into()),
                prompt: "second".into(),
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap().unwrap();
        assert!(
            matches!(events_rx.recv().await, Some(ServerEvent::TurnStarted { turn_id, .. }) if turn_id == TurnId("turn-2".into()))
        );
        assert!(
            matches!(events_rx.recv().await, Some(ServerEvent::TurnFinished { turn_id, outcome: TurnOutcome::Succeeded, next_state: TurnNextState::Ready, .. }) if turn_id == TurnId("turn-2".into()))
        );

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap().unwrap();
        let exit = run.await.unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        server.await.unwrap();
        assert!(cleaned.load(Ordering::SeqCst));
        assert_eq!(factory.opens.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn owner_rejects_turn_while_factory_is_initializing_and_close_skips_spawn() {
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(
            start(None),
            events_tx,
            commands_rx,
            Arc::new(PendingOpenFactory),
        );
        let run = tokio::spawn(owner.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::StartTurn {
                turn_id: TurnId("turn-during-init".into()),
                prompt: "must not start".into(),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), reply_rx)
            .await
            .expect("initializing command reply timed out")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, "session-not-ready");

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        let exit = run.await.unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        assert!(exit.cleanup_confirmed);
        assert!(events_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn owner_rejects_new_turn_promptly_while_process_cleanup_is_pending() {
        let (owner_stdin, server_input) = duplex(8192);
        let mut server_input = BufReader::new(server_input);
        let (mut server_output, owner_stdout) = duplex(8192);
        let (cleanup_entered_tx, cleanup_entered_rx) = oneshot::channel();
        let (cleanup_release_tx, cleanup_release_rx) = oneshot::channel();
        let connection = OpenedAppServer::for_test(
            "codex-cli 0.145.0",
            owner_stdin,
            owner_stdout,
            BlockingCleanupProcess {
                entered: Some(cleanup_entered_tx),
                release: Some(cleanup_release_rx),
            },
        );
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(start(None), events_tx, commands_rx, factory);

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        cleanup_entered_rx
            .await
            .expect("owner never entered process cleanup");

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::StartTurn {
                turn_id: TurnId("turn-during-stop".into()),
                prompt: "must not wait for cleanup".into(),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), reply_rx)
            .await
            .expect("stopping command reply timed out")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, "session-not-ready");

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::CancelTurn {
                turn_id: TurnId("turn-during-stop".into()),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), reply_rx)
            .await
            .expect("stopping cancel reply timed out")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, "turn-not-active");

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;

        cleanup_release_tx.send(()).unwrap();
        let exit = run.await.unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        assert!(exit.cleanup_confirmed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn owner_exit_waits_for_stderr_pump_join() {
        let (mut connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let pump_stopped = Arc::new(AtomicBool::new(false));
        let pump_cleaned = Arc::clone(&cleaned);
        let pump_stopped_task = Arc::clone(&pump_stopped);
        connection.stderr_drain = Some(tokio::spawn(async move {
            while !pump_cleaned.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            pump_stopped_task.store(true, Ordering::SeqCst);
            Ok(())
        }));
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (commands_tx, commands_rx) = mpsc::channel(2);
        let owner = CodexSessionOwner::new(start(None), events_tx, commands_rx, factory);

        let server = tokio::spawn(async move {
            assert_eq!(read_json(&mut server_input).await["method"], "initialize");
            write_json(&mut server_output, json!({"id": 1, "result": {}})).await;
            assert_eq!(
                read_json(&mut server_input).await,
                json!({"method": "initialized"})
            );
            assert_eq!(read_json(&mut server_input).await["method"], "thread/start");
            write_json(
                &mut server_output,
                json!({"id": 2, "result": {"thread": {"id": "thread-1"}}}),
            )
            .await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap().unwrap();

        let exit = run.await.unwrap();
        assert!(exit.cleanup_confirmed);
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(
            pump_stopped.load(Ordering::SeqCst),
            "owner exit must not become observable before stderr pump join"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancel_interrupts_only_the_turn_then_reuses_the_session() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(32);
        let (commands_tx, commands_rx) = mpsc::channel(8);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-cancel".into()),
                prompt: "cancel me".into(),
            })),
            events_tx,
            commands_rx,
            factory.clone(),
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;

            let first_start = read_json(&mut server_input).await;
            assert_eq!(first_start["id"], 3);
            assert_eq!(first_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-cancel"}}}),
            )
            .await;

            let interrupt = read_json(&mut server_input).await;
            assert_eq!(interrupt["id"], 4);
            assert_eq!(interrupt["method"], "turn/interrupt");
            assert_eq!(interrupt["params"]["turnId"], "vendor-cancel");
            write_json(&mut server_output, json!({"id": 4, "result": {}})).await;
            write_json(
                &mut server_output,
                json!({
                    "method": "turn/completed",
                    "params": {"turn": {"id": "vendor-cancel", "status": "interrupted"}}
                }),
            )
            .await;

            let second_start = read_json(&mut server_input).await;
            assert_eq!(second_start["id"], 5);
            assert_eq!(second_start["method"], "turn/start");
            assert_eq!(second_start["params"]["threadId"], "thread-1");
            write_json(
                &mut server_output,
                json!({"id": 5, "result": {"turn": {"id": "vendor-after-cancel"}}}),
            )
            .await;
            write_json(
                &mut server_output,
                json!({
                    "method": "turn/completed",
                    "params": {"turn": {"id": "vendor-after-cancel", "status": "completed"}}
                }),
            )
            .await;

            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { turn_id, .. }
                if turn_id == TurnId("turn-cancel".into())
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::CancelTurn {
                turn_id: TurnId("turn-cancel".into()),
                reply: reply_tx,
            })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnFinished {
                turn_id,
                outcome: TurnOutcome::Canceled,
                next_state: TurnNextState::Ready,
                ..
            } if turn_id == TurnId("turn-cancel".into())
        ));
        assert!(!cleaned.load(Ordering::SeqCst));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::StartTurn {
                turn_id: TurnId("turn-after-cancel".into()),
                prompt: "second".into(),
                reply: reply_tx,
            })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { turn_id, .. }
                if turn_id == TurnId("turn-after-cancel".into())
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnFinished {
                turn_id,
                outcome: TurnOutcome::Succeeded,
                next_state: TurnNextState::Ready,
                ..
            } if turn_id == TurnId("turn-after-cancel".into())
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("owner close timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
        assert!(cleaned.load(Ordering::SeqCst));
        assert_eq!(factory.opens.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancel_uses_terminal_that_precedes_a_rejected_interrupt_response() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(32);
        let (commands_tx, commands_rx) = mpsc::channel(8);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-cancel-race".into()),
                prompt: "cancel me".into(),
            })),
            events_tx,
            commands_rx,
            factory.clone(),
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let first_start = read_json(&mut server_input).await;
            assert_eq!(first_start["id"], 3);
            assert_eq!(first_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-cancel-race"}}}),
            )
            .await;

            let interrupt = read_json(&mut server_input).await;
            assert_eq!(interrupt["id"], 4);
            assert_eq!(interrupt["method"], "turn/interrupt");
            write_json(
                &mut server_output,
                json!({
                    "method": "turn/completed",
                    "params": {
                        "turn": {"id": "vendor-cancel-race", "status": "interrupted"}
                    }
                }),
            )
            .await;
            write_json(
                &mut server_output,
                json!({
                    "id": 4,
                    "error": {"code": -32000, "message": "turn already terminal"}
                }),
            )
            .await;

            let second_start = read_json(&mut server_input).await;
            assert_eq!(second_start["id"], 5);
            assert_eq!(second_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 5, "result": {"turn": {"id": "vendor-after-race"}}}),
            )
            .await;
            write_json(
                &mut server_output,
                json!({
                    "method": "turn/completed",
                    "params": {"turn": {"id": "vendor-after-race", "status": "completed"}}
                }),
            )
            .await;

            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { turn_id, .. }
                if turn_id == TurnId("turn-cancel-race".into())
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::CancelTurn {
                turn_id: TurnId("turn-cancel-race".into()),
                reply: reply_tx,
            })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnFinished {
                turn_id,
                outcome: TurnOutcome::Canceled,
                next_state: TurnNextState::Ready,
                ..
            } if turn_id == TurnId("turn-cancel-race".into())
        ));
        assert!(
            events_rx.try_recv().is_err(),
            "cancel race emitted a duplicate terminal"
        );
        assert!(!cleaned.load(Ordering::SeqCst));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::StartTurn {
                turn_id: TurnId("turn-after-race".into()),
                prompt: "second".into(),
                reply: reply_tx,
            })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { turn_id, .. }
                if turn_id == TurnId("turn-after-race".into())
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnFinished {
                turn_id,
                outcome: TurnOutcome::Succeeded,
                next_state: TurnNextState::Ready,
                ..
            } if turn_id == TurnId("turn-after-race".into())
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("owner close timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        assert!(exit.cleanup_confirmed);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
        assert!(cleaned.load(Ordering::SeqCst));
        assert_eq!(factory.opens.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn close_during_running_emits_turn_terminal_before_owner_exit() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-close".into()),
                prompt: "close me".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-close"}}}),
            )
            .await;
            let interrupt = read_json(&mut server_input).await;
            assert_eq!(interrupt["method"], "turn/interrupt");
            write_json(&mut server_output, json!({"id": 4, "result": {}})).await;
            write_json(
                &mut server_output,
                json!({
                    "method": "turn/completed",
                    "params": {"turn": {"id": "vendor-close", "status": "interrupted"}}
                }),
            )
            .await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { .. }
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Canceled,
                next_state: TurnNextState::Closing,
                ..
            }
        ));

        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("owner close timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(events_rx.try_recv().is_err());
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn close_uses_terminal_that_precedes_a_rejected_interrupt_response() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-close-race".into()),
                prompt: "close me".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["id"], 3);
            assert_eq!(turn_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-close-race"}}}),
            )
            .await;

            let interrupt = read_json(&mut server_input).await;
            assert_eq!(interrupt["id"], 4);
            assert_eq!(interrupt["method"], "turn/interrupt");
            write_json(
                &mut server_output,
                json!({
                    "method": "turn/completed",
                    "params": {
                        "turn": {"id": "vendor-close-race", "status": "interrupted"}
                    }
                }),
            )
            .await;
            write_json(
                &mut server_output,
                json!({
                    "id": 4,
                    "error": {"code": -32000, "message": "turn already terminal"}
                }),
            )
            .await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { turn_id, .. }
                if turn_id == TurnId("turn-close-race".into())
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnFinished {
                turn_id,
                outcome: TurnOutcome::Canceled,
                next_state: TurnNextState::Closing,
                ..
            } if turn_id == TurnId("turn-close-race".into())
        ));

        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("owner close timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        assert!(exit.cleanup_confirmed);
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(
            events_rx.try_recv().is_err(),
            "close race emitted a duplicate terminal"
        );
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn close_times_out_after_interrupt_ack_without_vendor_terminal() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-close-timeout".into()),
                prompt: "close me".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        )
        .with_interrupt_terminal_timeout(Duration::from_millis(25));

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-close-timeout"}}}),
            )
            .await;
            let interrupt = read_json(&mut server_input).await;
            assert_eq!(interrupt["method"], "turn/interrupt");
            assert_eq!(interrupt["params"]["turnId"], "vendor-close-timeout");
            write_json(&mut server_output, json!({"id": 4, "result": {}})).await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { .. }
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        match next_event(&mut events_rx).await {
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Failed,
                next_state: TurnNextState::Closing,
                error: Some(error),
                ..
            } => assert_eq!(error.code, "codex-close-timeout"),
            other => panic!("expected close-timeout terminal, got {other:?}"),
        }

        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("close timeout did not force owner exit")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Failed);
        assert_eq!(
            exit.error.as_ref().map(|error| error.code.as_str()),
            Some("codex-close-timeout")
        );
        assert!(exit.cleanup_confirmed);
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(events_rx.try_recv().is_err());
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn cancel_times_out_after_interrupt_ack_without_vendor_terminal() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-cancel-timeout".into()),
                prompt: "cancel me".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        )
        .with_interrupt_terminal_timeout(Duration::from_millis(25));

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-cancel-timeout"}}}),
            )
            .await;
            let interrupt = read_json(&mut server_input).await;
            assert_eq!(interrupt["method"], "turn/interrupt");
            assert_eq!(interrupt["params"]["turnId"], "vendor-cancel-timeout");
            write_json(&mut server_output, json!({"id": 4, "result": {}})).await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { .. }
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::CancelTurn {
                turn_id: TurnId("turn-cancel-timeout".into()),
                reply: reply_tx,
            })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        match next_event(&mut events_rx).await {
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Failed,
                next_state: TurnNextState::Closing,
                error: Some(error),
                ..
            } => assert_eq!(error.code, "codex-interrupt-timeout"),
            other => panic!("expected interrupt-timeout terminal, got {other:?}"),
        }

        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("interrupt timeout did not force owner exit")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Failed);
        assert_eq!(
            exit.error.as_ref().map(|error| error.code.as_str()),
            Some("codex-interrupt-timeout")
        );
        assert!(exit.cleanup_confirmed);
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(events_rx.try_recv().is_err());
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn second_start_turn_is_rejected_without_queueing_or_overwriting_active_turn() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-active".into()),
                prompt: "first".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["method"], "turn/start");
            assert_eq!(turn_start["params"]["input"][0]["text"], "first");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-active"}}}),
            )
            .await;

            // The rejected second start must not reach the wire. The next
            // request is close interrupting the original vendor turn.
            let interrupt = read_json(&mut server_input).await;
            assert_eq!(interrupt["method"], "turn/interrupt");
            assert_eq!(interrupt["params"]["turnId"], "vendor-active");
            write_json(&mut server_output, json!({"id": 4, "result": {}})).await;
            write_json(
                &mut server_output,
                json!({
                    "method": "turn/completed",
                    "params": {"turn": {"id": "vendor-active", "status": "interrupted"}}
                }),
            )
            .await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { turn_id, .. }
                if turn_id == TurnId("turn-active".into())
        ));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::StartTurn {
                turn_id: TurnId("turn-rejected".into()),
                prompt: "second".into(),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), reply_rx)
            .await
            .expect("second start was not rejected immediately")
            .expect("owner dropped second start reply")
            .unwrap_err();
        assert_eq!(error.code, "turn-already-running");
        assert!(events_rx.try_recv().is_err());

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnFinished {
                turn_id,
                outcome: TurnOutcome::Canceled,
                next_state: TurnNextState::Closing,
                ..
            } if turn_id == TurnId("turn-active".into())
        ));

        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("owner close timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        assert!(cleaned.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn cancel_waits_for_turn_start_response_before_sending_interrupt() {
        let (mut connection, _server_input, _server_output, _cleaned) = test_connection(None);
        let (events_tx, _events_rx) = mpsc::channel(4);
        let (_commands_tx, commands_rx) = mpsc::channel(4);
        let mut owner = RunningOwner::new(
            start(None),
            events_tx,
            commands_rx,
            connection.version.clone(),
            INTERRUPT_TERMINAL_TIMEOUT,
        );
        owner.state = OwnerState::StartingTurn;
        owner.thread_id = Some(ThreadId("thread-1".into()));
        owner.pending = Some(PendingRpc {
            id: 3,
            kind: PendingKind::TurnStart,
            deadline: tokio::time::Instant::now() + Duration::from_secs(1),
        });
        owner.turn = Some(TurnContext {
            client_id: TurnId("turn-race".into()),
            vendor_id: None,
            started_at: Instant::now(),
            cancel_requested: false,
            close_requested: false,
            interrupt_sent: false,
            failure_override: None,
            pending_terminal: None,
        });

        assert!(
            owner
                .handle_turn_started(&json!({
                    "method": "turn/started",
                    "params": {"turn": {"id": "vendor-race"}}
                }))
                .await
                .is_none()
        );
        owner
            .cancel_turn(&mut connection, &TurnId("turn-race".into()))
            .await
            .unwrap();

        let turn = owner.turn.as_ref().unwrap();
        assert!(turn.cancel_requested);
        assert!(!turn.interrupt_sent);
        assert!(matches!(
            owner.pending.as_ref().map(|pending| pending.kind),
            Some(PendingKind::TurnStart)
        ));
    }

    #[tokio::test]
    async fn malformed_json_fails_the_turn_and_session_then_waits_cleanup() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (_commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-malformed".into()),
                prompt: "hello".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-malformed"}}}),
            )
            .await;
            server_output.write_all(b"{ malformed\n").await.unwrap();
            server_output.flush().await.unwrap();
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { .. }
        ));
        match next_event(&mut events_rx).await {
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Failed,
                next_state: TurnNextState::Closing,
                error: Some(error),
                ..
            } => {
                assert_eq!(error.code, "codex-malformed-json");
                assert_eq!(error.diagnostic_ref.as_deref(), Some("session-1"));
            }
            other => panic!("expected fatal turn terminal, got {other:?}"),
        }
        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("owner failure timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Failed);
        assert_eq!(
            exit.error.as_ref().map(|error| error.code.as_str()),
            Some("codex-malformed-json")
        );
        assert!(cleaned.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn unmatched_response_is_a_fatal_correlated_failure() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (_commands_tx, commands_rx) = mpsc::channel(4);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-unmatched".into()),
                prompt: "hello".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-unmatched"}}}),
            )
            .await;
            write_json(&mut server_output, json!({"id": 99, "result": {}})).await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { .. }
        ));
        match next_event(&mut events_rx).await {
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Failed,
                next_state: TurnNextState::Closing,
                error: Some(error),
                ..
            } => assert_eq!(error.code, "codex-unmatched-response"),
            other => panic!("expected unmatched-response terminal, got {other:?}"),
        }
        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("owner failure timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Failed);
        assert!(cleaned.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn handshake_failure_has_no_phantom_session_started_and_is_reaped() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let (_commands_tx, commands_rx) = mpsc::channel(2);
        let owner = CodexSessionOwner::new(start(None), events_tx, commands_rx, factory);

        let server = tokio::spawn(async move {
            let initialize = read_json(&mut server_input).await;
            assert_eq!(initialize["method"], "initialize");
            write_json(
                &mut server_output,
                json!({"id": 1, "error": {"code": -32000, "message": "no"}}),
            )
            .await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });

        let exit = tokio::time::timeout(Duration::from_secs(2), owner.run())
            .await
            .expect("handshake failure timed out");
        assert_eq!(exit.outcome, SessionOutcome::Failed);
        assert_eq!(
            exit.error.as_ref().map(|error| error.code.as_str()),
            Some("codex-protocol-error")
        );
        assert_eq!(
            exit.error
                .as_ref()
                .and_then(|error| error.diagnostic_ref.as_deref()),
            Some("session-1")
        );
        assert!(events_rx.recv().await.is_none());
        assert!(cleaned.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn cleanup_failure_overrides_normal_close_with_failed_exit() {
        let cleanup_error = ProtocolError {
            code: "codex-cleanup-failed".into(),
            message: "fake wait failure".into(),
            diagnostic_ref: None,
        };
        let (connection, mut server_input, mut server_output, cleaned) =
            test_connection(Some(cleanup_error));
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (commands_tx, commands_rx) = mpsc::channel(2);
        let owner = CodexSessionOwner::new(start(None), events_tx, commands_rx, factory);
        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("cleanup failure timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Failed);
        let error = exit.error.expect("cleanup error");
        assert_eq!(error.code, "codex-cleanup-failed");
        assert_eq!(error.diagnostic_ref.as_deref(), Some("session-1"));
        assert!(cleaned.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn resume_handshake_verifies_thread_before_session_started() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (commands_tx, commands_rx) = mpsc::channel(2);
        let mut resume = start(None);
        resume.resume_thread_id = Some(ThreadId("thread-resume".into()));
        let owner = CodexSessionOwner::new(resume, events_tx, commands_rx, factory);

        let server = tokio::spawn(async move {
            let initialize = read_json(&mut server_input).await;
            assert_eq!(initialize["method"], "initialize");
            write_json(&mut server_output, json!({"id": 1, "result": {}})).await;
            assert_eq!(
                read_json(&mut server_input).await,
                json!({"method": "initialized"})
            );
            let thread_resume = read_json(&mut server_input).await;
            assert_eq!(thread_resume["id"], 2);
            assert_eq!(thread_resume["method"], "thread/resume");
            assert_eq!(thread_resume["params"]["threadId"], "thread-resume");
            assert_eq!(thread_resume["params"]["cwd"], "/tmp");
            assert_eq!(thread_resume["params"]["sandbox"], "read-only");
            assert_eq!(thread_resume["params"]["approvalPolicy"], "never");
            write_json(
                &mut server_output,
                json!({"id": 2, "result": {"thread": {"id": "thread-resume"}}}),
            )
            .await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted {
                thread_id: Some(thread_id),
                ..
            } if thread_id == ThreadId("thread-resume".into())
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("resume close timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        assert_eq!(exit.thread_id, Some(ThreadId("thread-resume".into())));
        assert!(cleaned.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn eof_during_turn_fails_once_and_closes_the_session() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (_commands_tx, commands_rx) = mpsc::channel(2);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-eof".into()),
                prompt: "hello".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-eof"}}}),
            )
            .await;
            drop(server_output);
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { .. }
        ));
        match next_event(&mut events_rx).await {
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Failed,
                next_state: TurnNextState::Closing,
                error: Some(error),
                ..
            } => assert_eq!(error.code, "codex-disconnected"),
            other => panic!("expected EOF terminal, got {other:?}"),
        }
        assert!(events_rx.try_recv().is_err());
        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("EOF cleanup timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Failed);
        assert!(cleaned.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn unsupported_server_request_is_rejected_and_fails_only_the_turn() {
        let (connection, mut server_input, mut server_output, cleaned) = test_connection(None);
        let factory = Arc::new(TestFactory::new(connection));
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (commands_tx, commands_rx) = mpsc::channel(2);
        let owner = CodexSessionOwner::new(
            start(Some(InitialTurn {
                turn_id: TurnId("turn-request".into()),
                prompt: "hello".into(),
            })),
            events_tx,
            commands_rx,
            factory,
        );

        let server = tokio::spawn(async move {
            accept_new_thread_handshake(&mut server_input, &mut server_output).await;
            let turn_start = read_json(&mut server_input).await;
            assert_eq!(turn_start["method"], "turn/start");
            write_json(
                &mut server_output,
                json!({"id": 3, "result": {"turn": {"id": "vendor-request"}}}),
            )
            .await;
            write_json(
                &mut server_output,
                json!({
                    "id": "approval-1",
                    "method": "item/commandExecution/requestApproval",
                    "params": {}
                }),
            )
            .await;

            let rejection = read_json(&mut server_input).await;
            assert_eq!(rejection["id"], "approval-1");
            assert_eq!(rejection["error"]["code"], -32601);
            let interrupt = read_json(&mut server_input).await;
            assert_eq!(interrupt["id"], 4);
            assert_eq!(interrupt["method"], "turn/interrupt");
            write_json(&mut server_output, json!({"id": 4, "result": {}})).await;
            write_json(
                &mut server_output,
                json!({
                    "method": "turn/completed",
                    "params": {"turn": {"id": "vendor-request", "status": "interrupted"}}
                }),
            )
            .await;
            let mut rest = Vec::new();
            server_input.read_to_end(&mut rest).await.unwrap();
        });
        let run = tokio::spawn(owner.run());

        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::SessionCapabilities { .. }
        ));
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnStarted { .. }
        ));
        match next_event(&mut events_rx).await {
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Failed,
                next_state: TurnNextState::Ready,
                error: Some(error),
                ..
            } => assert_eq!(error.code, "codex-unsupported-server-request"),
            other => panic!("expected unsupported-request terminal, got {other:?}"),
        }
        assert!(!cleaned.load(Ordering::SeqCst));

        let (reply_tx, reply_rx) = oneshot::channel();
        commands_tx
            .send(SessionCommand::Close { reply: reply_tx })
            .await
            .unwrap();
        command_reply(reply_rx).await;
        let exit = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("close after rejected request timed out")
            .unwrap();
        assert_eq!(exit.outcome, SessionOutcome::Closed);
        assert!(cleaned.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("fake server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn terminal_status_mapping_distinguishes_recoverable_failure_and_fatal_in_progress() {
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let (_commands_tx, commands_rx) = mpsc::channel(2);
        let mut failed_owner = RunningOwner::new(
            start(None),
            events_tx,
            commands_rx,
            "codex-cli 0.145.0".into(),
            INTERRUPT_TERMINAL_TIMEOUT,
        );
        failed_owner.state = OwnerState::Running;
        failed_owner.thread_id = Some(ThreadId("thread-1".into()));
        failed_owner.turn = Some(TurnContext {
            client_id: TurnId("turn-failed".into()),
            vendor_id: Some("vendor-failed".into()),
            started_at: Instant::now(),
            cancel_requested: false,
            close_requested: false,
            interrupt_sent: false,
            failure_override: None,
            pending_terminal: None,
        });
        assert!(
            failed_owner
                .finish_vendor_turn(VendorTerminal {
                    vendor_id: "vendor-failed".into(),
                    status: "failed".into(),
                    duration_ms: Some(1),
                })
                .await
                .is_none()
        );
        assert_eq!(failed_owner.state, OwnerState::Ready);
        assert!(matches!(
            next_event(&mut events_rx).await,
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Failed,
                next_state: TurnNextState::Ready,
                ..
            }
        ));

        let (events_tx, mut events_rx) = mpsc::channel(4);
        let (_commands_tx, commands_rx) = mpsc::channel(2);
        let mut invalid_owner = RunningOwner::new(
            start(None),
            events_tx,
            commands_rx,
            "codex-cli 0.145.0".into(),
            INTERRUPT_TERMINAL_TIMEOUT,
        );
        invalid_owner.state = OwnerState::Running;
        invalid_owner.thread_id = Some(ThreadId("thread-1".into()));
        invalid_owner.turn = Some(TurnContext {
            client_id: TurnId("turn-invalid".into()),
            vendor_id: Some("vendor-invalid".into()),
            started_at: Instant::now(),
            cancel_requested: false,
            close_requested: false,
            interrupt_sent: false,
            failure_override: None,
            pending_terminal: None,
        });
        let exit = invalid_owner
            .finish_vendor_turn(VendorTerminal {
                vendor_id: "vendor-invalid".into(),
                status: "inProgress".into(),
                duration_ms: None,
            })
            .await
            .expect("inProgress terminal must be fatal");
        assert_eq!(exit.outcome, SessionOutcome::Failed);
        assert_eq!(invalid_owner.state, OwnerState::Stopping);
        match next_event(&mut events_rx).await {
            ServerEvent::TurnFinished {
                outcome: TurnOutcome::Failed,
                next_state: TurnNextState::Closing,
                error: Some(error),
                ..
            } => assert_eq!(error.code, "codex-terminal-status-invalid"),
            other => panic!("expected invalid-status terminal, got {other:?}"),
        }
    }
}
