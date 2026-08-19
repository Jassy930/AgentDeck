//! RuntimeHub — owns the `AgentRouter`, the stdin reader, the stdout
//! writer, and the per-session events mpsc. Translates wire JSONL
//! ⇄ `ClientCommand` / `ServerEvent`.
//!
//! Wire protocol: newline-delimited JSON in both directions.
//!
//!   stdin  : one `ClientCommand` per line (deny_unknown_fields).
//!   stdout : one `ServerEvent` per line ‑ except for the four
//!            admin commands (Ping / Selfcheck / ProtocolSchema /
//!            ProtocolVersion) which write a vendor-neutral JSON
//!            reply directly. This is a deliberate side-channel
//!            (see "Admin replies" below) chosen to avoid protocol
//!            churn during Phase 3.
//!
//! Admin replies (request → response, NOT streaming events):
//! `ServerEvent` has no `Reply { ... }` variant; the four admin
//! commands above need a one-shot reply rather than a stream of
//! events. We side-channel them through a second mpsc carrying raw
//! JSON lines; the single writer task drains BOTH channels and
//! serializes writes onto stdout. Concretely the reader handles
//! these inline and pushes a JSON string ‑ event-side mpsc is
//! untouched, so streaming events for concurrent sessions are not
//! starved. This keeps the writer single-owner (no shared
//! Mutex<Stdout>) and means Phase 4 / Phase 5 can add a real
//! `ServerEvent::Reply` later without breaking on-wire behavior.

use crate::agent::{AgentEventSender, AgentSessionHandle};
use crate::runtime::router::AgentRouter;
#[cfg(test)]
use agentdeck_protocol::HistoryRequest;
use agentdeck_protocol::{
    ClientCommand, HistoryResponse, PROTOCOL_VERSION, ProtocolError, ServerEvent, SessionId,
};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Notify, mpsc, watch};

/// Channel depth for the unified ServerEvent stream coming out of all
/// sessions. 256 is generous: the writer drains it as fast as stdout
/// will accept (line per `recv`).
const EVENTS_CHANNEL_CAPACITY: usize = 256;

/// Channel depth for admin (request/response) replies — Ping, Selfcheck,
/// ProtocolSchema, ProtocolVersion. These are bursty but rare; 32 is
/// enough headroom for a flood of selfchecks during boot.
const ADMIN_REPLY_CAPACITY: usize = 32;

/// Lifecycle commands use one ordered worker. The stdin loop only enqueues
/// them, so admin commands remain responsive while start/control calls await
/// adapter work, but session commands can never overtake each other.
type LifecycleSender = mpsc::UnboundedSender<ClientCommand>;

/// Bound the complete merged-history operation below the Swift client's
/// 35-second transport timeout. Dropping the router future also guarantees
/// the daemon cannot emit a late terminal reply after this deadline.
const HISTORY_REQUEST_TIMEOUT: Duration = Duration::from_secs(32);

async fn handle_history_with_timeout<F>(
    request: F,
    timeout: Duration,
) -> Result<HistoryResponse, ProtocolError>
where
    F: Future<Output = Result<HistoryResponse, ProtocolError>>,
{
    tokio::time::timeout(timeout, request)
        .await
        .map_err(|_| ProtocolError {
            code: "history-request-timeout".into(),
            message: format!("history request exceeded the {timeout:?} daemon deadline"),
            diagnostic_ref: None,
        })?
}

fn history_admin_reply(
    request_id: Option<String>,
    result: Result<HistoryResponse, ProtocolError>,
) -> String {
    let mut reply = serde_json::json!({ "reply": "history" });
    if let Some(request_id) = request_id {
        reply["requestId"] = serde_json::Value::String(request_id);
    }
    match result {
        Ok(response) => reply["response"] = serde_json::json!(response),
        Err(error) => reply["error"] = serde_json::json!(error),
    }
    reply.to_string()
}

/// Coordinator for the daemon's stdin/stdout main loop.
///
/// Owns an `Arc<AgentRouter>` (shared with every spawned session pump)
/// plus an in-process map of `session_id → AgentSessionHandle`. The
/// handle map keeps session owner handles alive until their terminal
/// cleanup signal is supervised.
pub struct RuntimeHub {
    pub router: Arc<AgentRouter>,
    /// Holds every started session's `AgentSessionHandle`. Session close is
    /// always requested through the adapter; RuntimeHub never aborts the
    /// handle as a substitute for owner cleanup.
    sessions: Arc<Mutex<HashMap<SessionId, AgentSessionHandle>>>,
}

impl RuntimeHub {
    pub fn new(router: Arc<AgentRouter>) -> Self {
        Self {
            router,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Run the daemon main loop until stdin closes or an unrecoverable
    /// write error occurs on stdout.
    ///
    /// Two concurrent tasks coordinate via mpsc:
    ///   - **Writer task**: drains `events_rx` (per-session events)
    ///     and `admin_rx` (admin command replies) and serializes
    ///     every line to stdout. Single owner of `stdout`, so no
    ///     lock is needed.
    ///   - **Reader loop (this future)**: reads stdin line by line,
    ///     parses `ClientCommand`, dispatches via `self.router`.
    pub async fn run<R, W>(self, stdin: R, stdout: W) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (events_tx, events_rx) = mpsc::channel::<ServerEvent>(EVENTS_CHANNEL_CAPACITY);
        let (admin_tx, admin_rx) = mpsc::channel::<String>(ADMIN_REPLY_CAPACITY);
        let (lifecycle_tx, lifecycle_rx) = mpsc::unbounded_channel::<ClientCommand>();
        let (poison_tx, mut poison_rx) = watch::channel(false);
        let sessions_changed = Arc::new(Notify::new());
        let retiring_sessions = Arc::new(Mutex::new(HashSet::new()));
        let session_admission = Arc::new(Mutex::new(()));

        let mut writer_handle =
            tokio::spawn(writer_task(stdout, events_rx, admin_rx, poison_tx.clone()));
        let lifecycle_handle = tokio::spawn(lifecycle_worker(
            Arc::clone(&self.router),
            Arc::clone(&self.sessions),
            lifecycle_rx,
            events_tx.clone(),
            poison_tx.clone(),
            poison_rx.clone(),
            Arc::clone(&sessions_changed),
            Arc::clone(&retiring_sessions),
            Arc::clone(&session_admission),
        ));

        let mut reader = BufReader::new(stdin).lines();
        let mut poisoned = false;
        let mut writer_result = None;
        loop {
            let next = tokio::select! {
                biased;
                result = &mut writer_handle => {
                    writer_result = Some(writer_join_result(result));
                    // Stop the ordered worker after its current operation. A
                    // closed command sender alone would drain queued starts
                    // even though their events can no longer be delivered.
                    let _ = poison_tx.send(true);
                    break;
                }
                changed = poison_rx.changed() => {
                    if changed.is_ok() && *poison_rx.borrow() {
                        poisoned = true;
                        break;
                    }
                    continue;
                }
                next = reader.next_line() => next,
            };
            match next {
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    // K1 (C6 fix): never await long-running session commands
                    // inline — that blocks the stdin loop so subsequent
                    // Ping / lifecycle controls queue behind a vendor handshake.
                    // Long-running commands (SessionStart, TurnStart,
                    // TurnCancel, SessionClose,
                    // History) are tokio::spawn'd; cheap admin commands
                    // (Ping, Selfcheck, AgentList, AgentCapabilities,
                    // ProtocolVersion, ProtocolSchema, ActionDecision,
                    // VendorControl) stay inline since
                    // they complete near-instantly.
                    self.handle_line(
                        line,
                        &events_tx,
                        &admin_tx,
                        &lifecycle_tx,
                        &retiring_sessions,
                    )
                    .await;
                }
                Ok(None) => break, // EOF
                Err(e) => {
                    // stdin closed unexpectedly; treat as graceful EOF.
                    eprintln!("[agentdeckd] stdin read error: {e}");
                    break;
                }
            }
        }

        // Closing the ordered queue first lets the worker drain every command
        // already read from stdin, then close/reap all retained sessions. If a
        // cleanup failure poisoned the daemon, the worker drops queued work
        // and only performs shutdown.
        drop(lifecycle_tx);
        let _ = lifecycle_handle.await;

        // Drop both root senders so the writer task drains all terminal events
        // from supervisors before it exits.
        drop(events_tx);
        drop(admin_tx);
        let writer_result = match writer_result {
            Some(result) => result,
            None => writer_join_result(writer_handle.await),
        };
        if let Err(error) = writer_result {
            return Err(error);
        }
        if poisoned || *poison_rx.borrow() {
            Err(io::Error::other(
                "session cleanup could not be confirmed; daemon retired",
            ))
        } else {
            Ok(())
        }
    }

    async fn handle_line(
        &self,
        line: String,
        events_tx: &AgentEventSender,
        admin_tx: &mpsc::Sender<String>,
        lifecycle_tx: &LifecycleSender,
        retiring_sessions: &Mutex<HashSet<SessionId>>,
    ) {
        let cmd: ClientCommand = match serde_json::from_str(&line) {
            Ok(c) => c,
            Err(e) => {
                let err = ServerEvent::Error {
                    session_id: None,
                    error: ProtocolError {
                        code: "parse-error".into(),
                        message: format!("invalid ClientCommand: {e}"),
                        diagnostic_ref: None,
                    },
                };
                let _ = events_tx.send(err).await;
                return;
            }
        };
        self.dispatch(cmd, events_tx, admin_tx, lifecycle_tx, retiring_sessions)
            .await;
    }

    async fn dispatch(
        &self,
        cmd: ClientCommand,
        events_tx: &AgentEventSender,
        admin_tx: &mpsc::Sender<String>,
        lifecycle_tx: &LifecycleSender,
        retiring_sessions: &Mutex<HashSet<SessionId>>,
    ) {
        match cmd {
            // ── Cheap / admin commands: handle inline ──────────────────
            ClientCommand::Ping => {
                let reply = serde_json::json!({ "reply": "ping", "ok": true });
                let _ = admin_tx.send(reply.to_string()).await;
            }
            ClientCommand::Selfcheck => {
                // v2 selfcheck reports daemon liveness + registered adapters.
                // The CLI / Swift can call this without spawning a real turn.
                let agents: Vec<String> = self
                    .router
                    .list_agents()
                    .iter()
                    .map(|k| k.as_str().to_string())
                    .collect();
                let reply = serde_json::json!({
                    "reply": "selfcheck",
                    "ok": true,
                    "protocolVersion": PROTOCOL_VERSION,
                    "agents": agents,
                });
                let _ = admin_tx.send(reply.to_string()).await;
            }
            ClientCommand::ProtocolSchema => {
                let reply = serde_json::json!({
                    "reply": "protocolSchema",
                    "schema": agentdeck_protocol::protocol_schema(),
                });
                let _ = admin_tx.send(reply.to_string()).await;
            }
            ClientCommand::ProtocolVersion => {
                let reply = serde_json::json!({
                    "reply": "protocolVersion",
                    "protocolVersion": PROTOCOL_VERSION,
                });
                let _ = admin_tx.send(reply.to_string()).await;
            }
            ClientCommand::ActionDecision {
                session_id,
                decision,
            } => {
                if is_session_retiring(retiring_sessions, &session_id).await {
                    return;
                }
                if let Err(error) = self.router.submit_decision(&session_id, decision).await {
                    send_lifecycle_error(events_tx, retiring_sessions, session_id, error).await;
                }
            }
            ClientCommand::VendorControl {
                session_id,
                payload,
            } => {
                if is_session_retiring(retiring_sessions, &session_id).await {
                    return;
                }
                if let Err(error) = self
                    .router
                    .submit_vendor_control(&session_id, payload)
                    .await
                {
                    send_lifecycle_error(events_tx, retiring_sessions, session_id, error).await;
                }
            }
            ClientCommand::AgentList => {
                let kinds: Vec<String> = self
                    .router
                    .list_agents()
                    .iter()
                    .map(|k| k.as_str().to_string())
                    .collect();
                let reply = serde_json::json!({
                    "reply": "agentList",
                    "agents": kinds,
                });
                let _ = admin_tx.send(reply.to_string()).await;
            }
            ClientCommand::AgentCapabilities { agent_kind } => {
                match self.router.capabilities(agent_kind) {
                    Some(caps) => {
                        let reply = serde_json::json!({
                            "reply": "agentCapabilities",
                            "agentKind": agent_kind.as_str(),
                            "capabilities": caps,
                        });
                        let _ = admin_tx.send(reply.to_string()).await;
                    }
                    None => {
                        let err = ServerEvent::Error {
                            session_id: None,
                            error: ProtocolError {
                                code: "agent-not-registered".into(),
                                message: format!(
                                    "no adapter registered for agentKind={:?}",
                                    agent_kind
                                ),
                                diagnostic_ref: None,
                            },
                        };
                        let _ = events_tx.send(err).await;
                    }
                }
            }
            // Lifecycle commands are enqueued in wire order and awaited by one
            // worker. This keeps Ping/admin responsive without allowing
            // start→close or turnStart→cancel to overtake each other.
            ClientCommand::SessionStart(start) => {
                let _ = lifecycle_tx.send(ClientCommand::SessionStart(start));
            }
            ClientCommand::TurnStart {
                session_id,
                turn_id,
                prompt,
            } => {
                let _ = lifecycle_tx.send(ClientCommand::TurnStart {
                    session_id,
                    turn_id,
                    prompt,
                });
            }
            ClientCommand::TurnCancel {
                session_id,
                turn_id,
            } => {
                let _ = lifecycle_tx.send(ClientCommand::TurnCancel {
                    session_id,
                    turn_id,
                });
            }
            ClientCommand::SessionClose { session_id } => {
                let _ = lifecycle_tx.send(ClientCommand::SessionClose { session_id });
            }
            ClientCommand::History(req) => {
                // Task 4C — Phase 4 finalization: route through the
                // router's `handle_history`, which routes by agent kind
                // (or fans out for cross-agent List). The response is
                // a typed `HistoryResponse` envelope; we side-channel
                // the JSON onto the admin reply stream (same posture
                // as Ping / Selfcheck — request/response, not streaming
                // events) so it doesn't try to fit through the
                // `ServerEvent` shape.
                //
                // Success and error use one request-correlated admin reply.
                // Do not also emit an uncorrelated `ServerEvent::Error`: a
                // concurrent history waiter could mistake that side-channel
                // event for its own terminal failure.
                //
                // K1 (C6 fix): spawn — Read/List can fan out across
                // adapters and touch disk; don't block stdin.
                let request_id = req.request_id().map(str::to_owned);
                let router = Arc::clone(&self.router);
                let admin_tx = admin_tx.clone();
                tokio::spawn(async move {
                    let result = handle_history_with_timeout(
                        router.handle_history(req),
                        HISTORY_REQUEST_TIMEOUT,
                    )
                    .await;
                    let _ = admin_tx.send(history_admin_reply(request_id, result)).await;
                });
            }
        }
    }
}

fn writer_join_result(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Result<()> {
    match result {
        Ok(result) => result,
        Err(error) => Err(io::Error::other(format!(
            "stdout writer task failed: {error}"
        ))),
    }
}

/// Execute session lifecycle commands in the exact order they were read from
/// stdin. Admin/history work remains outside this worker so a slow adapter
/// operation cannot block Ping or other request/reply commands.
async fn lifecycle_worker(
    router: Arc<AgentRouter>,
    sessions: Arc<Mutex<HashMap<SessionId, AgentSessionHandle>>>,
    mut commands: mpsc::UnboundedReceiver<ClientCommand>,
    events_tx: AgentEventSender,
    poison_tx: watch::Sender<bool>,
    mut poison_rx: watch::Receiver<bool>,
    sessions_changed: Arc<Notify>,
    retiring_sessions: Arc<Mutex<HashSet<SessionId>>>,
    session_admission: Arc<Mutex<()>>,
) {
    let mut closing = HashSet::new();

    loop {
        let command = tokio::select! {
            biased;
            changed = poison_rx.changed() => {
                if changed.is_ok() && *poison_rx.borrow() {
                    break;
                }
                continue;
            }
            command = commands.recv() => command,
        };
        let Some(command) = command else {
            break;
        };

        match command {
            ClientCommand::SessionStart(start) => {
                let _admission = session_admission.lock().await;
                let session_id = start.session_id.clone();
                if closing.contains(&session_id)
                    || is_session_retiring(&retiring_sessions, &session_id).await
                {
                    continue;
                }
                match router.start_session(start, events_tx.clone()).await {
                    Ok(handle) => {
                        supervise_session(
                            Arc::clone(&router),
                            Arc::clone(&sessions),
                            session_id,
                            handle,
                            events_tx.clone(),
                            poison_tx.clone(),
                            Arc::clone(&sessions_changed),
                            Arc::clone(&retiring_sessions),
                            Arc::clone(&session_admission),
                        )
                        .await;
                    }
                    Err(error) => {
                        send_lifecycle_error(&events_tx, &retiring_sessions, session_id, error)
                            .await;
                    }
                }
            }
            ClientCommand::TurnStart {
                session_id,
                turn_id,
                prompt,
            } => {
                if closing.contains(&session_id)
                    || is_session_retiring(&retiring_sessions, &session_id).await
                {
                    continue;
                }
                if let Err(error) = router.start_turn(&session_id, turn_id, prompt).await {
                    send_lifecycle_error(&events_tx, &retiring_sessions, session_id, error).await;
                }
            }
            ClientCommand::TurnCancel {
                session_id,
                turn_id,
            } => {
                if closing.contains(&session_id)
                    || is_session_retiring(&retiring_sessions, &session_id).await
                {
                    continue;
                }
                if let Err(error) = router.cancel_turn(&session_id, &turn_id).await {
                    send_lifecycle_error(&events_tx, &retiring_sessions, session_id, error).await;
                }
            }
            ClientCommand::SessionClose { session_id } => {
                if is_session_retiring(&retiring_sessions, &session_id).await
                    || !closing.insert(session_id.clone())
                {
                    continue;
                }
                match router.close_session(&session_id).await {
                    Ok(()) => {
                        wait_for_session_removal(&sessions, &session_id, &sessions_changed).await;
                    }
                    Err(error) => {
                        closing.remove(&session_id);
                        send_lifecycle_error(&events_tx, &retiring_sessions, session_id, error)
                            .await;
                    }
                }
            }
            _ => unreachable!("only lifecycle commands enter the ordered worker"),
        }
    }

    shutdown_retained_sessions(
        &router,
        &sessions,
        &events_tx,
        &poison_tx,
        &sessions_changed,
        &retiring_sessions,
    )
    .await;
}

async fn is_session_retiring(
    retiring_sessions: &Mutex<HashSet<SessionId>>,
    session_id: &SessionId,
) -> bool {
    retiring_sessions.lock().await.contains(session_id)
}

async fn send_lifecycle_error(
    events_tx: &AgentEventSender,
    retiring_sessions: &Mutex<HashSet<SessionId>>,
    session_id: SessionId,
    error: ProtocolError,
) {
    // Serialize error publication against the supervisor's terminal marker.
    // An error that wins this lock is enqueued before SessionClosed; once the
    // marker is present, no later event for that session may be published.
    let retiring = retiring_sessions.lock().await;
    if retiring.contains(&session_id) {
        return;
    }
    let _ = events_tx
        .send(ServerEvent::Error {
            session_id: Some(session_id),
            error,
        })
        .await;
}

async fn wait_for_session_removal(
    sessions: &Arc<Mutex<HashMap<SessionId, AgentSessionHandle>>>,
    session_id: &SessionId,
    sessions_changed: &Arc<Notify>,
) {
    loop {
        let changed = sessions_changed.notified();
        if !sessions.lock().await.contains_key(session_id) {
            break;
        }
        changed.await;
    }
}

/// EOF is an orderly close request for every retained session. Session-owner
/// adapters remove themselves only after child wait and pump join. Legacy
/// adapters have no owner exit signal, so they fall back to their existing
/// cancel path and are removed locally.
async fn shutdown_retained_sessions(
    router: &Arc<AgentRouter>,
    sessions: &Arc<Mutex<HashMap<SessionId, AgentSessionHandle>>>,
    events_tx: &AgentEventSender,
    poison_tx: &watch::Sender<bool>,
    sessions_changed: &Arc<Notify>,
    retiring_sessions: &Mutex<HashSet<SessionId>>,
) {
    let session_ids = sessions.lock().await.keys().cloned().collect::<Vec<_>>();
    for session_id in session_ids {
        if is_session_retiring(retiring_sessions, &session_id).await {
            continue;
        }
        match router.close_session(&session_id).await {
            Ok(()) => {}
            Err(error) if error.code == "session-close-not-supported" => {
                if let Err(error) = router.cancel(&session_id).await {
                    send_lifecycle_error(events_tx, retiring_sessions, session_id.clone(), error)
                        .await;
                    let _ = poison_tx.send(true);
                }
                sessions.lock().await.remove(&session_id);
                sessions_changed.notify_waiters();
            }
            Err(error) => {
                send_lifecycle_error(events_tx, retiring_sessions, session_id, error).await;
            }
        }
    }

    loop {
        let changed = sessions_changed.notified();
        if sessions.lock().await.is_empty() {
            break;
        }
        changed.await;
    }
}

/// Retain a newly-started session and, for session-owner adapters, supervise
/// its terminal cleanup. The owner reports only after stopping pumps and
/// reaping its child. We then clear both routing tables before making the
/// unique `SessionClosed` event observable to clients.
async fn supervise_session(
    router: Arc<AgentRouter>,
    sessions: Arc<Mutex<HashMap<SessionId, AgentSessionHandle>>>,
    session_id: SessionId,
    mut handle: AgentSessionHandle,
    events_tx: AgentEventSender,
    poison_tx: watch::Sender<bool>,
    sessions_changed: Arc<Notify>,
    retiring_sessions: Arc<Mutex<HashSet<SessionId>>>,
    session_admission: Arc<Mutex<()>>,
) {
    let agent_kind = handle.agent_kind;
    let fallback_thread_id = handle.thread_id.clone();
    let exit = handle.exit.take();
    sessions.lock().await.insert(session_id.clone(), handle);

    let Some(exit) = exit else {
        return;
    };

    tokio::spawn(async move {
        match exit.await {
            Ok(exit) => {
                let admission = session_admission.lock().await;
                let cleanup_confirmed = exit.cleanup_confirmed;
                retiring_sessions.lock().await.insert(session_id.clone());
                if !cleanup_confirmed {
                    // Stop both the stdin loop and lifecycle intake before a
                    // failed terminal can become visible. Otherwise a client
                    // could enqueue a replacement session after observing the
                    // terminal but before the daemon learns it is poisoned.
                    let _ = poison_tx.send(true);
                }
                router.unregister_session(&session_id).await;
                sessions.lock().await.remove(&session_id);
                router
                    .session_retired(agent_kind, &session_id, cleanup_confirmed)
                    .await;
                let _ = events_tx
                    .send(ServerEvent::SessionClosed {
                        session_id: session_id.clone(),
                        thread_id: exit.thread_id,
                        agent_kind,
                        outcome: exit.outcome,
                        error: exit.error,
                    })
                    .await;
                drop(admission);
                sessions_changed.notify_waiters();
            }
            Err(_) => {
                let admission = session_admission.lock().await;
                // A dropped sender does not prove that the vendor process was
                // reaped. Poison intake first, retire both routes, then publish
                // the one failed session terminal with a usable diagnostic ref.
                let error = ProtocolError {
                    code: "session-exit-signal-dropped".into(),
                    message: "session owner exited without confirming cleanup".into(),
                    diagnostic_ref: Some(session_id.0.clone()),
                };
                retiring_sessions.lock().await.insert(session_id.clone());
                let _ = poison_tx.send(true);
                router.unregister_session(&session_id).await;
                sessions.lock().await.remove(&session_id);
                router.session_retired(agent_kind, &session_id, false).await;
                let _ = events_tx
                    .send(ServerEvent::SessionClosed {
                        session_id: session_id.clone(),
                        thread_id: fallback_thread_id,
                        agent_kind,
                        outcome: agentdeck_protocol::SessionOutcome::Failed,
                        error: Some(error),
                    })
                    .await;
                drop(admission);
                sessions_changed.notify_waiters();
            }
        }
    });
}

/// Single-owner stdout writer. Drains the per-session events stream and
/// the admin reply stream into a single newline-delimited byte stream.
async fn writer_task<W>(
    mut stdout: W,
    mut events_rx: mpsc::Receiver<ServerEvent>,
    mut admin_rx: mpsc::Receiver<String>,
    stop_tx: watch::Sender<bool>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let result = async {
        loop {
            tokio::select! {
                biased; // prefer admin (request/response) replies for snappier
                        // selfchecks under load; events are still drained next.
                maybe_admin = admin_rx.recv() => {
                    match maybe_admin {
                        Some(line) => {
                            write_line(&mut stdout, line.as_bytes()).await?;
                        }
                        None => {
                            // admin channel closed; keep draining events
                            // until that side also closes.
                            while let Some(event) = events_rx.recv().await {
                                let line = match serde_json::to_string(&event) {
                                    Ok(s) => s,
                                    Err(_) => continue,
                                };
                                write_line(&mut stdout, line.as_bytes()).await?;
                            }
                            break;
                        }
                    }
                }
                maybe_event = events_rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            let line = match serde_json::to_string(&event) {
                                Ok(s) => s,
                                Err(_) => continue,
                            };
                            write_line(&mut stdout, line.as_bytes()).await?;
                        }
                        None => {
                            // events channel closed; keep draining admin
                            // until that side also closes.
                            while let Some(line) = admin_rx.recv().await {
                                write_line(&mut stdout, line.as_bytes()).await?;
                            }
                            break;
                        }
                    }
                }
            }
        }
        stdout.flush().await
    }
    .await;
    if result.is_err() {
        // Signal before dropping the receivers so an in-flight lifecycle
        // operation cannot resume and drain queued starts first.
        let _ = stop_tx.send(true);
    }
    result
}

async fn write_line<W: AsyncWrite + Unpin>(stdout: &mut W, body: &[u8]) -> io::Result<()> {
    stdout.write_all(body).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Agent, AgentEventSender, AgentSessionExit, AgentSessionHandle, DynAgent};
    use agentdeck_protocol::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::duplex;
    use tokio::sync::oneshot;

    struct EofLifecycleStub {
        exit_sender: std::sync::Mutex<Option<oneshot::Sender<AgentSessionExit>>>,
        start_calls: AtomicUsize,
        close_calls: AtomicUsize,
        cleanup_confirmed: bool,
        wait_for_event_receiver_close: bool,
    }

    struct FailingWriter;

    struct SpontaneousFailureStub {
        active_session: std::sync::Mutex<Option<SessionId>>,
        accepted_starts: AtomicUsize,
        retirement_entered: mpsc::UnboundedSender<SessionId>,
        retirement_release: Arc<tokio::sync::Semaphore>,
    }

    impl tokio::io::AsyncWrite for FailingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deterministic stdout failure",
            )))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[async_trait::async_trait]
    impl Agent for SpontaneousFailureStub {
        fn kind(&self) -> AgentKind {
            AgentKind::Codex
        }

        fn capabilities(&self) -> SessionCapabilities {
            SessionCapabilities {
                agent_kind: AgentKind::Codex,
                agent_version: "spontaneous-failure-stub".into(),
                features: Default::default(),
                vendor: VendorCapabilities::Codex(Default::default()),
            }
        }

        async fn start_session(
            &self,
            start: SessionStart,
            _: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            {
                let mut active = self.active_session.lock().unwrap();
                if let Some(active) = active.as_ref() {
                    return Err(ProtocolError {
                        code: "session-busy".into(),
                        message: format!("session {} is still active", active.0),
                        diagnostic_ref: None,
                    });
                }
                *active = Some(start.session_id.clone());
            }
            self.accepted_starts.fetch_add(1, Ordering::SeqCst);

            let (exit_sender, exit) = oneshot::channel();
            assert!(
                exit_sender
                    .send(AgentSessionExit {
                        thread_id: None,
                        outcome: SessionOutcome::Failed,
                        error: Some(ProtocolError {
                            code: "factory-open-failed".into(),
                            message: "deterministic spontaneous factory failure".into(),
                            diagnostic_ref: Some(start.session_id.0.clone()),
                        }),
                        cleanup_confirmed: true,
                    })
                    .is_ok(),
                "Hub owns the spontaneous exit receiver"
            );
            let pump = tokio::spawn(std::future::pending::<()>());
            let abort_handle = pump.abort_handle();
            pump.abort();
            Ok(AgentSessionHandle {
                session_id: start.session_id,
                thread_id: None,
                agent_kind: AgentKind::Codex,
                abort_handle,
                exit: Some(exit),
            })
        }

        async fn continue_thread(
            &self,
            _: ThreadId,
            _: std::path::PathBuf,
            _: String,
            _: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            unimplemented!("legacy continue is outside this test")
        }

        async fn session_retired(&self, session_id: &SessionId, cleanup_confirmed: bool) {
            self.retirement_entered.send(session_id.clone()).unwrap();
            self.retirement_release
                .acquire()
                .await
                .expect("test retirement semaphore remains open")
                .forget();
            if cleanup_confirmed {
                let mut active = self.active_session.lock().unwrap();
                if active.as_ref() == Some(session_id) {
                    *active = None;
                }
            }
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

    #[async_trait::async_trait]
    impl Agent for EofLifecycleStub {
        fn kind(&self) -> AgentKind {
            AgentKind::Codex
        }

        fn capabilities(&self) -> SessionCapabilities {
            SessionCapabilities {
                agent_kind: AgentKind::Codex,
                agent_version: "eof-lifecycle-stub".into(),
                features: Default::default(),
                vendor: VendorCapabilities::Codex(Default::default()),
            }
        }

        async fn start_session(
            &self,
            start: SessionStart,
            events: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            self.start_calls.fetch_add(1, Ordering::SeqCst);
            let thread_id = ThreadId("eof-thread".into());
            events
                .send(ServerEvent::SessionStarted {
                    session_id: start.session_id.clone(),
                    thread_id: Some(thread_id.clone()),
                    agent_kind: AgentKind::Codex,
                })
                .await
                .unwrap();
            if self.wait_for_event_receiver_close {
                events.closed().await;
            }
            let pump = tokio::spawn(std::future::pending::<()>());
            let abort_handle = pump.abort_handle();
            pump.abort();
            let (exit_sender, exit) = oneshot::channel();
            *self.exit_sender.lock().unwrap() = Some(exit_sender);
            Ok(AgentSessionHandle {
                session_id: start.session_id,
                thread_id: Some(thread_id),
                agent_kind: AgentKind::Codex,
                abort_handle,
                exit: Some(exit),
            })
        }

        async fn continue_thread(
            &self,
            _: ThreadId,
            _: std::path::PathBuf,
            _: String,
            _: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            unimplemented!("legacy continue is outside this test")
        }

        async fn close_session(&self, _: &SessionId) -> Result<(), ProtocolError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            let error = (!self.cleanup_confirmed).then(|| ProtocolError {
                code: "codex-cleanup-failed".into(),
                message: "deterministic cleanup failure".into(),
                diagnostic_ref: Some("eof-session".into()),
            });
            let _ = self
                .exit_sender
                .lock()
                .unwrap()
                .take()
                .expect("started session owns an exit sender")
                .send(AgentSessionExit {
                    thread_id: Some(ThreadId("eof-thread".into())),
                    outcome: if self.cleanup_confirmed {
                        SessionOutcome::Closed
                    } else {
                        SessionOutcome::Failed
                    },
                    error,
                    cleanup_confirmed: self.cleanup_confirmed,
                });
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

    fn eof_session_start(session_id: &str) -> ClientCommand {
        ClientCommand::SessionStart(SessionStart {
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
            runtime_options: Default::default(),
        })
    }

    async fn write_command(writer: &mut tokio::io::DuplexStream, command: &ClientCommand) {
        writer
            .write_all(serde_json::to_string(command).unwrap().as_bytes())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
    }

    async fn read_server_event<R>(reader: &mut BufReader<R>) -> ServerEvent
    where
        R: AsyncRead + Unpin,
    {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(1), reader.read_line(&mut line))
            .await
            .expect("daemon must emit a terminal line")
            .unwrap();
        assert_ne!(read, 0, "daemon output closed before the expected event");
        serde_json::from_str(line.trim()).expect("daemon event JSON")
    }

    /// Sanity: parse errors come back as ServerEvent::Error not a panic
    /// or a silent drop.
    #[tokio::test]
    async fn malformed_stdin_line_yields_error_event() {
        let router = Arc::new(AgentRouter::new());
        let hub = RuntimeHub::new(router);

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        client_to_daemon
            .write_all(b"{ this is not json }\n")
            .await
            .unwrap();
        client_to_daemon.shutdown().await.unwrap();

        let mut buf = Vec::new();
        let read_fut = async {
            use tokio::io::AsyncReadExt;
            client_from_daemon.read_to_end(&mut buf).await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(2), read_fut)
            .await
            .expect("daemon should respond and exit");
        hub_task.await.unwrap().unwrap();

        let response = String::from_utf8_lossy(&buf);
        let first_line = response.lines().next().expect("at least one reply line");
        let event: ServerEvent = serde_json::from_str(first_line).expect("ServerEvent JSON");
        match event {
            ServerEvent::Error { error, .. } => {
                assert_eq!(error.code, "parse-error");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Ping is side-channeled as a `{reply: "ping"}` line.
    #[tokio::test]
    async fn ping_returns_reply_line() {
        let router = Arc::new(AgentRouter::new());
        let hub = RuntimeHub::new(router);

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        let line = serde_json::to_string(&ClientCommand::Ping).unwrap();
        client_to_daemon.write_all(line.as_bytes()).await.unwrap();
        client_to_daemon.write_all(b"\n").await.unwrap();
        client_to_daemon.shutdown().await.unwrap();

        let mut buf = Vec::new();
        let read_fut = async {
            use tokio::io::AsyncReadExt;
            client_from_daemon.read_to_end(&mut buf).await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(2), read_fut)
            .await
            .expect("daemon should respond and exit");
        hub_task.await.unwrap().unwrap();

        let response = String::from_utf8_lossy(&buf);
        let first_line = response.lines().next().expect("at least one reply line");
        let parsed: serde_json::Value = serde_json::from_str(first_line).expect("reply JSON");
        assert_eq!(parsed["reply"], "ping");
        assert_eq!(parsed["ok"], true);
    }

    #[tokio::test]
    async fn stdin_eof_drains_queued_start_then_closes_and_waits_for_terminal() {
        let stub = Arc::new(EofLifecycleStub {
            exit_sender: std::sync::Mutex::new(None),
            start_calls: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            cleanup_confirmed: true,
            wait_for_event_receiver_close: false,
        });
        let mut router = AgentRouter::new();
        let agent: DynAgent = stub.clone();
        router.register(agent);
        let hub = RuntimeHub::new(Arc::new(router));

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);
        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        // EOF arrives without waiting for SessionStarted. The ordered worker
        // must still drain this already-read start, retain the owner, request
        // close, and wait for its cleanup terminal.
        write_command(&mut client_to_daemon, &eof_session_start("eof-session")).await;
        client_to_daemon.shutdown().await.unwrap();

        let mut output = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_to_end(&mut client_from_daemon, &mut output),
        )
        .await
        .expect("EOF shutdown must finish")
        .unwrap();
        hub_task.await.unwrap().unwrap();

        let events = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<ServerEvent>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            events.first(),
            Some(ServerEvent::SessionStarted { .. })
        ));
        assert!(matches!(
            events.last(),
            Some(ServerEvent::SessionClosed {
                outcome: SessionOutcome::Closed,
                ..
            })
        ));
        assert_eq!(stub.close_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stdout_write_failure_stops_intake_and_reaps_retained_session() {
        let stub = Arc::new(EofLifecycleStub {
            exit_sender: std::sync::Mutex::new(None),
            start_calls: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            cleanup_confirmed: true,
            wait_for_event_receiver_close: true,
        });
        let mut router = AgentRouter::new();
        let agent: DynAgent = stub.clone();
        router.register(agent);
        let hub = RuntimeHub::new(Arc::new(router));
        let retained_sessions = Arc::clone(&hub.sessions);

        // Keep the client end open: only the deterministic stdout failure may
        // stop intake and initiate the ordinary close/reap path.
        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let queued_input = format!(
            "{}\n{}\n",
            serde_json::to_string(&eof_session_start("writer-failure-session")).unwrap(),
            serde_json::to_string(&eof_session_start("must-not-start-after-writer-failure"))
                .unwrap(),
        );
        client_to_daemon
            .write_all(queued_input.as_bytes())
            .await
            .unwrap();
        let hub_task = tokio::spawn(hub.run(daemon_stdin, FailingWriter));

        let error = tokio::time::timeout(Duration::from_secs(2), hub_task)
            .await
            .expect("stdout failure must stop intake without waiting for stdin EOF")
            .unwrap()
            .expect_err("stdout failure must be returned by RuntimeHub::run");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("deterministic stdout failure"));
        assert_eq!(
            stub.start_calls.load(Ordering::SeqCst),
            1,
            "writer failure must discard queued lifecycle starts"
        );
        assert_eq!(stub.close_calls.load(Ordering::SeqCst), 1);
        assert!(
            retained_sessions.lock().await.is_empty(),
            "run must not return while a failed-writer session remains retained"
        );
    }

    #[tokio::test]
    async fn spontaneous_failure_serializes_replacement_after_session_terminal() {
        let (retirement_entered_tx, mut retirement_entered_rx) = mpsc::unbounded_channel();
        let retirement_release = Arc::new(tokio::sync::Semaphore::new(0));
        let stub = Arc::new(SpontaneousFailureStub {
            active_session: std::sync::Mutex::new(None),
            accepted_starts: AtomicUsize::new(0),
            retirement_entered: retirement_entered_tx,
            retirement_release: Arc::clone(&retirement_release),
        });
        let mut router = AgentRouter::new();
        let agent: DynAgent = stub.clone();
        router.register(agent);
        let hub = RuntimeHub::new(Arc::new(router));

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, client_from_daemon) = duplex(4096);
        let mut client_from_daemon = BufReader::new(client_from_daemon);
        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        let first_id = SessionId("factory-failure-first".into());
        write_command(&mut client_to_daemon, &eof_session_start(&first_id.0)).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), retirement_entered_rx.recv())
                .await
                .expect("first owner must reach Hub retirement"),
            Some(first_id.clone())
        );

        // Queue a different ID while retirement still owns admission. It must
        // neither enter the adapter nor make an event observable before the
        // old slot is retired and its terminal is enqueued.
        let replacement_id = SessionId("factory-failure-replacement".into());
        write_command(&mut client_to_daemon, &eof_session_start(&replacement_id.0)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), retirement_entered_rx.recv())
                .await
                .is_err(),
            "replacement must wait behind the old session terminal"
        );
        assert_eq!(stub.accepted_starts.load(Ordering::SeqCst), 1);
        let mut premature = String::new();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                client_from_daemon.read_line(&mut premature),
            )
            .await
            .is_err(),
            "SessionClosed must not be visible before adapter retirement completes"
        );

        retirement_release.add_permits(1);
        assert!(matches!(
            read_server_event(&mut client_from_daemon).await,
            ServerEvent::SessionClosed {
                session_id,
                outcome: SessionOutcome::Failed,
                error: Some(ProtocolError { code, .. }),
                ..
            } if session_id == first_id && code == "factory-open-failed"
        ));

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), retirement_entered_rx.recv())
                .await
                .expect("replacement starts only after the old terminal is enqueued"),
            Some(replacement_id.clone())
        );
        assert_eq!(stub.accepted_starts.load(Ordering::SeqCst), 2);
        retirement_release.add_permits(1);
        assert!(matches!(
            read_server_event(&mut client_from_daemon).await,
            ServerEvent::SessionClosed {
                session_id,
                outcome: SessionOutcome::Failed,
                error: Some(ProtocolError { code, .. }),
                ..
            } if session_id == replacement_id && code == "factory-open-failed"
        ));

        client_to_daemon.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), hub_task)
            .await
            .expect("Hub exits after both spontaneous failures retire")
            .unwrap()
            .unwrap();
        assert!(stub.active_session.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn cleanup_failure_emits_failed_terminal_then_retires_daemon() {
        let stub = Arc::new(EofLifecycleStub {
            exit_sender: std::sync::Mutex::new(None),
            start_calls: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            cleanup_confirmed: false,
            wait_for_event_receiver_close: false,
        });
        let mut router = AgentRouter::new();
        let agent: DynAgent = stub.clone();
        router.register(agent);
        let hub = RuntimeHub::new(Arc::new(router));

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);
        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        write_command(&mut client_to_daemon, &eof_session_start("eof-session")).await;
        write_command(
            &mut client_to_daemon,
            &ClientCommand::SessionClose {
                session_id: SessionId("eof-session".into()),
            },
        )
        .await;
        write_command(
            &mut client_to_daemon,
            &eof_session_start("must-not-start-after-poison"),
        )
        .await;

        let mut output = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_to_end(&mut client_from_daemon, &mut output),
        )
        .await
        .expect("poisoned daemon must stop intake and exit")
        .unwrap();
        let error = hub_task
            .await
            .unwrap()
            .expect_err("unconfirmed cleanup must retire the daemon");
        assert!(error.to_string().contains("daemon retired"));

        let events = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<ServerEvent>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            events.last(),
            Some(ServerEvent::SessionClosed {
                outcome: SessionOutcome::Failed,
                error: Some(ProtocolError { code, .. }),
                ..
            }) if code == "codex-cleanup-failed"
        ));
        assert!(events.iter().all(|event| !matches!(
            event,
            ServerEvent::SessionStarted { session_id, .. }
                if session_id.0 == "must-not-start-after-poison"
        )));
        assert_eq!(stub.close_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn spontaneous_owner_terminal_tombstones_the_session_id() {
        let stub = Arc::new(EofLifecycleStub {
            exit_sender: std::sync::Mutex::new(None),
            start_calls: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            cleanup_confirmed: true,
            wait_for_event_receiver_close: false,
        });
        let mut router = AgentRouter::new();
        let agent: DynAgent = stub.clone();
        router.register(agent);
        let hub = RuntimeHub::new(Arc::new(router));

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, client_from_daemon) = duplex(4096);
        let mut client_from_daemon = BufReader::new(client_from_daemon);
        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));
        let session_id = SessionId("spontaneous-terminal".into());

        write_command(&mut client_to_daemon, &eof_session_start(&session_id.0)).await;
        assert!(matches!(
            read_server_event(&mut client_from_daemon).await,
            ServerEvent::SessionStarted { .. }
        ));

        assert!(
            stub.exit_sender
                .lock()
                .unwrap()
                .take()
                .expect("started session owns an exit sender")
                .send(AgentSessionExit {
                    thread_id: Some(ThreadId("eof-thread".into())),
                    outcome: SessionOutcome::Failed,
                    error: Some(ProtocolError {
                        code: "codex-protocol-error".into(),
                        message: "deterministic spontaneous terminal".into(),
                        diagnostic_ref: Some(session_id.0.clone()),
                    }),
                    cleanup_confirmed: true,
                })
                .is_ok(),
            "supervisor retains the exit receiver"
        );

        assert!(matches!(
            read_server_event(&mut client_from_daemon).await,
            ServerEvent::SessionClosed {
                session_id: terminal_session_id,
                outcome: SessionOutcome::Failed,
                ..
            } if terminal_session_id == session_id
        ));

        write_command(
            &mut client_to_daemon,
            &ClientCommand::TurnStart {
                session_id: session_id.clone(),
                turn_id: TurnId("after-terminal".into()),
                prompt: "must be ignored".into(),
            },
        )
        .await;
        write_command(&mut client_to_daemon, &eof_session_start(&session_id.0)).await;
        write_command(
            &mut client_to_daemon,
            &ClientCommand::ActionDecision {
                session_id: session_id.clone(),
                decision: ActionDecision {
                    request_id: "after-terminal-action".into(),
                    decision: ActionDecisionKind::Approve,
                    persist: false,
                },
            },
        )
        .await;
        write_command(
            &mut client_to_daemon,
            &ClientCommand::VendorControl {
                session_id: session_id.clone(),
                payload: VendorControlPayload::Codex(CodexVendorControl::UpdateSandbox(
                    CodexSandboxMode::ReadOnly,
                )),
            },
        )
        .await;

        let mut late = String::new();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                client_from_daemon.read_line(&mut late),
            )
            .await
            .is_err(),
            "terminal session commands must not emit events or reuse the session id"
        );
        assert_eq!(stub.close_calls.load(Ordering::SeqCst), 0);

        client_to_daemon.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), hub_task)
            .await
            .expect("hub exits after terminal tombstone test")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn spontaneous_cleanup_failure_terminal_is_the_last_event() {
        let stub = Arc::new(EofLifecycleStub {
            exit_sender: std::sync::Mutex::new(None),
            start_calls: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            cleanup_confirmed: false,
            wait_for_event_receiver_close: false,
        });
        let mut router = AgentRouter::new();
        let agent: DynAgent = stub.clone();
        router.register(agent);
        let hub = RuntimeHub::new(Arc::new(router));

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, client_from_daemon) = duplex(4096);
        let mut client_from_daemon = BufReader::new(client_from_daemon);
        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));
        let session_id = SessionId("spontaneous-cleanup-failure".into());

        write_command(&mut client_to_daemon, &eof_session_start(&session_id.0)).await;
        assert!(matches!(
            read_server_event(&mut client_from_daemon).await,
            ServerEvent::SessionStarted { .. }
        ));
        assert!(
            stub.exit_sender
                .lock()
                .unwrap()
                .take()
                .expect("started session owns an exit sender")
                .send(AgentSessionExit {
                    thread_id: Some(ThreadId("eof-thread".into())),
                    outcome: SessionOutcome::Failed,
                    error: Some(ProtocolError {
                        code: "codex-cleanup-failed".into(),
                        message: "deterministic spontaneous cleanup failure".into(),
                        diagnostic_ref: Some(session_id.0.clone()),
                    }),
                    cleanup_confirmed: false,
                })
                .is_ok(),
            "supervisor retains the exit receiver"
        );

        let mut output = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_to_end(&mut client_from_daemon, &mut output),
        )
        .await
        .expect("poisoned daemon must publish its terminal and exit")
        .unwrap();
        let error = hub_task
            .await
            .unwrap()
            .expect_err("unconfirmed cleanup must retire the daemon");
        assert!(error.to_string().contains("daemon retired"));

        let events = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<ServerEvent>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            events.last(),
            Some(ServerEvent::SessionClosed {
                session_id: terminal_session_id,
                outcome: SessionOutcome::Failed,
                error: Some(ProtocolError { code, .. }),
                ..
            }) if terminal_session_id == &session_id && code == "codex-cleanup-failed"
        ));
        assert_eq!(stub.close_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cleanup_failure_poison_is_visible_before_session_terminal() {
        let router = Arc::new(AgentRouter::new());
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let session_id = SessionId("cleanup-failed-session".into());
        let thread_id = ThreadId("cleanup-failed-thread".into());
        let (exit_sender, exit) = oneshot::channel();
        let pump = tokio::spawn(std::future::pending::<()>());
        let abort_handle = pump.abort_handle();
        pump.abort();
        let handle = AgentSessionHandle {
            session_id: session_id.clone(),
            thread_id: Some(thread_id.clone()),
            agent_kind: AgentKind::Codex,
            abort_handle,
            exit: Some(exit),
        };
        let (events_tx, mut events_rx) = mpsc::channel(2);
        let (poison_tx, poison_rx) = watch::channel(false);
        let sessions_changed = Arc::new(Notify::new());

        supervise_session(
            router,
            Arc::clone(&sessions),
            session_id.clone(),
            handle,
            events_tx,
            poison_tx,
            sessions_changed,
            Arc::new(Mutex::new(HashSet::new())),
            Arc::new(Mutex::new(())),
        )
        .await;
        assert!(
            exit_sender
                .send(AgentSessionExit {
                    thread_id: Some(thread_id),
                    outcome: SessionOutcome::Failed,
                    error: Some(ProtocolError {
                        code: "codex-cleanup-failed".into(),
                        message: "deterministic cleanup failure".into(),
                        diagnostic_ref: Some(session_id.0.clone()),
                    }),
                    cleanup_confirmed: false,
                })
                .is_ok(),
            "supervisor must still own the exit receiver"
        );

        let terminal = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("cleanup failure must publish a terminal")
            .expect("event channel remains open");
        assert!(
            *poison_rx.borrow(),
            "daemon poison must happen-before SessionClosed visibility"
        );
        assert!(!sessions.lock().await.contains_key(&session_id));
        assert!(matches!(
            terminal,
            ServerEvent::SessionClosed {
                outcome: SessionOutcome::Failed,
                error: Some(ProtocolError { code, .. }),
                ..
            } if code == "codex-cleanup-failed"
        ));
    }

    #[tokio::test]
    async fn dropped_owner_exit_sender_emits_one_failed_session_terminal() {
        let router = Arc::new(AgentRouter::new());
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let session_id = SessionId("dropped-exit-session".into());
        let thread_id = ThreadId("dropped-exit-thread".into());
        let (exit_sender, exit) = oneshot::channel();
        let pump = tokio::spawn(std::future::pending::<()>());
        let abort_handle = pump.abort_handle();
        pump.abort();
        let handle = AgentSessionHandle {
            session_id: session_id.clone(),
            thread_id: Some(thread_id.clone()),
            agent_kind: AgentKind::Codex,
            abort_handle,
            exit: Some(exit),
        };
        let (events_tx, mut events_rx) = mpsc::channel(2);
        let (poison_tx, poison_rx) = watch::channel(false);
        let sessions_changed = Arc::new(Notify::new());

        supervise_session(
            router,
            Arc::clone(&sessions),
            session_id.clone(),
            handle,
            events_tx,
            poison_tx,
            sessions_changed,
            Arc::new(Mutex::new(HashSet::new())),
            Arc::new(Mutex::new(())),
        )
        .await;
        drop(exit_sender);

        let terminal = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("dropped exit sender must publish a terminal")
            .expect("event channel remains open");
        assert!(
            *poison_rx.borrow(),
            "daemon poison must happen-before SessionClosed visibility"
        );
        assert!(!sessions.lock().await.contains_key(&session_id));
        assert!(matches!(
            terminal,
            ServerEvent::SessionClosed {
                session_id: terminal_session_id,
                thread_id: Some(terminal_thread_id),
                outcome: SessionOutcome::Failed,
                error: Some(ProtocolError {
                    code,
                    diagnostic_ref: Some(diagnostic_ref),
                    ..
                }),
                ..
            } if terminal_session_id == session_id
                && terminal_thread_id == thread_id
                && code == "session-exit-signal-dropped"
                && diagnostic_ref == session_id.0
        ));
        assert!(
            matches!(
                events_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "dropped exit sender must not emit a second error terminal"
        );
    }

    #[test]
    fn history_success_admin_reply_echoes_request_id() {
        let line = history_admin_reply(
            Some("history-success-1".into()),
            Ok(HistoryResponse::List(Vec::new())),
        );
        let reply: serde_json::Value = serde_json::from_str(&line).expect("history reply JSON");

        assert_eq!(reply["reply"], "history");
        assert_eq!(reply["requestId"], "history-success-1");
        assert_eq!(reply["response"]["kind"], "list");
        assert!(reply.get("error").is_none());
    }

    #[tokio::test]
    async fn history_timeout_helper_bounds_pending_future() {
        let pending = std::future::pending::<Result<HistoryResponse, ProtocolError>>();
        let error = handle_history_with_timeout(pending, Duration::from_millis(5))
            .await
            .expect_err("pending history future must time out");

        assert_eq!(error.code, "history-request-timeout");
        assert!(error.message.contains("5ms"));
    }

    /// An empty router is a configuration failure, not an empty history.
    /// The error must use the History admin envelope so request/response
    /// clients always receive a terminal reply for their refresh.
    #[tokio::test]
    async fn history_list_on_bare_router_returns_admin_error_reply() {
        let router = Arc::new(AgentRouter::new());
        let hub = RuntimeHub::new(router);

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        let cmd = ClientCommand::History(HistoryRequest::List {
            request_id: Some("history-list-1".into()),
            agent_kind: None,
            cwd_filter: None,
            limit: None,
        });
        let line = serde_json::to_string(&cmd).unwrap();
        client_to_daemon.write_all(line.as_bytes()).await.unwrap();
        client_to_daemon.write_all(b"\n").await.unwrap();
        client_to_daemon.shutdown().await.unwrap();

        let mut buf = Vec::new();
        let read_fut = async {
            use tokio::io::AsyncReadExt;
            client_from_daemon.read_to_end(&mut buf).await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(2), read_fut)
            .await
            .expect("daemon should respond and exit");
        hub_task.await.unwrap().unwrap();

        let lines = String::from_utf8_lossy(&buf)
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("output JSON"))
            .collect::<Vec<_>>();
        let reply = lines
            .iter()
            .find(|line| line["reply"] == "history")
            .expect("history admin reply");
        assert_eq!(reply["requestId"], "history-list-1");
        assert_eq!(reply["error"]["code"], "history-no-sources");
        assert!(reply.get("response").is_none());
        assert!(lines.iter().all(|line| line.get("type").is_none()));
    }

    /// Read against an unregistered agent kind returns exactly one correlated
    /// History admin error reply, without an uncorrelated Error event.
    #[tokio::test]
    async fn history_read_for_unregistered_kind_returns_only_correlated_reply() {
        let router = Arc::new(AgentRouter::new());
        let hub = RuntimeHub::new(router);

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        let cmd = ClientCommand::History(HistoryRequest::Read {
            request_id: Some("history-read-1".into()),
            thread_id: ThreadId("nope".into()),
            agent_kind: AgentKind::Codex,
        });
        let line = serde_json::to_string(&cmd).unwrap();
        client_to_daemon.write_all(line.as_bytes()).await.unwrap();
        client_to_daemon.write_all(b"\n").await.unwrap();
        client_to_daemon.shutdown().await.unwrap();

        let mut buf = Vec::new();
        let read_fut = async {
            use tokio::io::AsyncReadExt;
            client_from_daemon.read_to_end(&mut buf).await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(2), read_fut)
            .await
            .expect("daemon should respond and exit");
        hub_task.await.unwrap().unwrap();

        let lines = String::from_utf8_lossy(&buf)
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("output JSON"))
            .collect::<Vec<_>>();
        let reply = lines
            .iter()
            .find(|line| line["reply"] == "history")
            .expect("history admin reply");
        assert_eq!(reply["requestId"], "history-read-1");
        assert_eq!(reply["error"]["code"], "agent-not-registered");
        assert!(lines.iter().all(|line| line.get("type").is_none()));
    }

    /// K1 regression (C6 fix): a slow SessionStart must NOT block
    /// subsequent admin commands. We register a stub agent whose
    /// `start_session` sleeps for 500 ms, send SessionStart then Ping
    /// back-to-back, and assert the Ping reply lands on stdout long
    /// before the slow start completes. Before C6 this would block.
    #[tokio::test]
    async fn ping_during_slow_session_start_is_not_blocked() {
        use crate::agent::{Agent, AgentEventSender, AgentSessionHandle, DynAgent};
        use agentdeck_protocol::{
            ActionDecision, AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
            CodexSessionOptions, ProtocolError, SessionCapabilities, SessionStart, ThreadId,
            VendorControlPayload, VendorSessionOptions,
        };
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Instant;

        struct SlowStub {
            started: Arc<AtomicBool>,
        }
        #[async_trait::async_trait]
        impl Agent for SlowStub {
            fn kind(&self) -> AgentKind {
                AgentKind::Codex
            }
            fn capabilities(&self) -> SessionCapabilities {
                use agentdeck_protocol::{CodexCapabilities, VendorCapabilities};
                SessionCapabilities {
                    agent_kind: AgentKind::Codex,
                    agent_version: "stub".into(),
                    features: Default::default(),
                    vendor: VendorCapabilities::Codex(CodexCapabilities {
                        persistence_supported: false,
                        sandbox_modes: vec![],
                        reasoning_effort_levels: vec![],
                    }),
                }
            }
            async fn start_session(
                &self,
                _: SessionStart,
                _: AgentEventSender,
            ) -> Result<AgentSessionHandle, ProtocolError> {
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.started.store(true, Ordering::SeqCst);
                Err(ProtocolError {
                    code: "stub".into(),
                    message: "slow stub completed".into(),
                    diagnostic_ref: None,
                })
            }
            async fn continue_thread(
                &self,
                _: ThreadId,
                _: std::path::PathBuf,
                _: String,
                _: AgentEventSender,
            ) -> Result<AgentSessionHandle, ProtocolError> {
                unimplemented!()
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

        let started = Arc::new(AtomicBool::new(false));
        let stub: DynAgent = Arc::new(SlowStub {
            started: Arc::clone(&started),
        });
        let mut router = AgentRouter::new();
        router.register(stub);
        let hub = RuntimeHub::new(Arc::new(router));

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        // 1) Submit SessionStart — will take 500ms inside the stub.
        let start = ClientCommand::SessionStart(SessionStart {
            session_id: SessionId("slow-start-session".into()),
            agent_kind: AgentKind::Codex,
            cwd: std::path::PathBuf::from("/tmp"),
            resume_thread_id: None,
            initial_turn: None,
            vendor_options: VendorSessionOptions::Codex(CodexSessionOptions {
                approval_policy: CodexApprovalPolicy::OnRequest,
                sandbox: CodexSandboxMode::WorkspaceWrite,
                persist_approval: false,
                reasoning_effort: CodexReasoningEffort::Medium,
                mcp_overrides: vec![],
            }),
            runtime_options: Default::default(),
        });
        let line = serde_json::to_string(&start).unwrap();
        client_to_daemon.write_all(line.as_bytes()).await.unwrap();
        client_to_daemon.write_all(b"\n").await.unwrap();

        // 2) Immediately follow with a Ping — must be answered before
        //    the 500ms slow start finishes (K1).
        let ping = serde_json::to_string(&ClientCommand::Ping).unwrap();
        client_to_daemon.write_all(ping.as_bytes()).await.unwrap();
        client_to_daemon.write_all(b"\n").await.unwrap();

        // 3) Read the first line off stdout: should be the ping reply
        //    within ~50ms, while the slow start is still pending.
        use tokio::io::AsyncReadExt;
        let t0 = Instant::now();
        let mut byte = [0u8; 1];
        let mut line_buf = Vec::new();
        loop {
            let n = tokio::time::timeout(
                Duration::from_millis(250),
                client_from_daemon.read(&mut byte),
            )
            .await
            .expect("ping reply should arrive well before slow start completes")
            .unwrap();
            if n == 0 {
                break;
            }
            if byte[0] == b'\n' {
                break;
            }
            line_buf.push(byte[0]);
        }
        let elapsed = t0.elapsed();
        let parsed: serde_json::Value = serde_json::from_slice(&line_buf).expect("ping reply JSON");
        assert_eq!(parsed["reply"], "ping");
        assert!(
            elapsed < Duration::from_millis(400),
            "ping reply took {elapsed:?}; stdin appears blocked by slow SessionStart"
        );
        assert!(
            !started.load(Ordering::SeqCst),
            "slow SessionStart must still be in flight when Ping returned"
        );

        // Cleanup: shut the daemon down cleanly so the test exits.
        client_to_daemon.shutdown().await.unwrap();
        // Best-effort wait for hub to exit; the slow stub finishes its
        // sleep then emits an Error event, which the writer drains.
        let _ = tokio::time::timeout(Duration::from_secs(2), hub_task).await;
    }

    /// TurnStart, TurnCancel, and SessionClose are owner control calls and can
    /// wait on vendor I/O. Each must be dispatched off the stdin loop so Ping
    /// remains responsive while the control call is still pending.
    #[tokio::test]
    async fn ping_is_not_blocked_by_slow_lifecycle_controls() {
        use crate::agent::{
            Agent, AgentEventSender, AgentSessionExit, AgentSessionHandle, DynAgent,
        };
        use agentdeck_protocol::{
            ActionDecision, AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
            CodexSessionOptions, ProtocolError, SessionCapabilities, SessionOutcome, SessionStart,
            ThreadId, TurnId, VendorCapabilities, VendorControlPayload, VendorSessionOptions,
        };
        use tokio::sync::{Semaphore, mpsc as tokio_mpsc, oneshot};

        struct SlowLifecycleStub {
            entered: tokio_mpsc::UnboundedSender<&'static str>,
            release: Arc<Semaphore>,
            exit_sender: std::sync::Mutex<Option<oneshot::Sender<AgentSessionExit>>>,
        }

        impl SlowLifecycleStub {
            async fn block(&self, operation: &'static str) {
                self.entered.send(operation).unwrap();
                self.release
                    .acquire()
                    .await
                    .expect("test semaphore remains open")
                    .forget();
            }
        }

        #[async_trait::async_trait]
        impl Agent for SlowLifecycleStub {
            fn kind(&self) -> AgentKind {
                AgentKind::Codex
            }

            fn capabilities(&self) -> SessionCapabilities {
                SessionCapabilities {
                    agent_kind: AgentKind::Codex,
                    agent_version: "slow-lifecycle-stub".into(),
                    features: Default::default(),
                    vendor: VendorCapabilities::Codex(Default::default()),
                }
            }

            async fn start_session(
                &self,
                start: SessionStart,
                events: AgentEventSender,
            ) -> Result<AgentSessionHandle, ProtocolError> {
                let thread_id = ThreadId("slow-lifecycle-thread".into());
                events
                    .send(ServerEvent::SessionStarted {
                        session_id: start.session_id.clone(),
                        thread_id: Some(thread_id.clone()),
                        agent_kind: AgentKind::Codex,
                    })
                    .await
                    .unwrap();

                let pump = tokio::spawn(std::future::pending::<()>());
                let abort_handle = pump.abort_handle();
                pump.abort();
                let (exit_sender, exit) = oneshot::channel();
                *self.exit_sender.lock().unwrap() = Some(exit_sender);
                Ok(AgentSessionHandle {
                    session_id: start.session_id,
                    thread_id: Some(thread_id),
                    agent_kind: AgentKind::Codex,
                    abort_handle,
                    exit: Some(exit),
                })
            }

            async fn continue_thread(
                &self,
                _: ThreadId,
                _: std::path::PathBuf,
                _: String,
                _: AgentEventSender,
            ) -> Result<AgentSessionHandle, ProtocolError> {
                unimplemented!("legacy continue is outside this test")
            }

            async fn start_turn(
                &self,
                _: &SessionId,
                _: TurnId,
                _: String,
            ) -> Result<(), ProtocolError> {
                self.block("turnStart").await;
                Ok(())
            }

            async fn cancel_turn(&self, _: &SessionId, _: &TurnId) -> Result<(), ProtocolError> {
                self.block("turnCancel").await;
                Ok(())
            }

            async fn close_session(&self, _: &SessionId) -> Result<(), ProtocolError> {
                self.block("sessionClose").await;
                let exit_sender = self
                    .exit_sender
                    .lock()
                    .unwrap()
                    .take()
                    .expect("started session owns an exit sender");
                let _ = exit_sender.send(AgentSessionExit {
                    thread_id: Some(ThreadId("slow-lifecycle-thread".into())),
                    outcome: SessionOutcome::Closed,
                    error: None,
                    cleanup_confirmed: true,
                });
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

        async fn send_command(writer: &mut tokio::io::DuplexStream, command: &ClientCommand) {
            let line = serde_json::to_string(command).unwrap();
            writer.write_all(line.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
        }

        async fn read_line(reader: &mut tokio::io::DuplexStream) -> serde_json::Value {
            use tokio::io::AsyncReadExt;
            let mut byte = [0_u8; 1];
            let mut line = Vec::new();
            loop {
                let n = tokio::time::timeout(Duration::from_secs(1), reader.read(&mut byte))
                    .await
                    .expect("stdin loop must remain responsive")
                    .unwrap();
                assert_ne!(n, 0, "daemon output closed before a complete line");
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            serde_json::from_slice(&line).expect("daemon output JSON")
        }

        let (entered_tx, mut entered_rx) = tokio_mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let stub: DynAgent = Arc::new(SlowLifecycleStub {
            entered: entered_tx,
            release: Arc::clone(&release),
            exit_sender: std::sync::Mutex::new(None),
        });
        let mut router = AgentRouter::new();
        router.register(stub);
        let hub = RuntimeHub::new(Arc::new(router));
        let retained_sessions = Arc::clone(&hub.sessions);

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);
        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        let session_id = SessionId("slow-lifecycle-session".into());
        send_command(
            &mut client_to_daemon,
            &ClientCommand::SessionStart(SessionStart {
                session_id: session_id.clone(),
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
                runtime_options: Default::default(),
            }),
        )
        .await;

        let controls = [
            (
                "turnStart",
                ClientCommand::TurnStart {
                    session_id: session_id.clone(),
                    turn_id: TurnId("slow-turn".into()),
                    prompt: "hello".into(),
                },
            ),
            (
                "turnCancel",
                ClientCommand::TurnCancel {
                    session_id: session_id.clone(),
                    turn_id: TurnId("slow-turn".into()),
                },
            ),
            (
                "sessionClose",
                ClientCommand::SessionClose {
                    session_id: session_id.clone(),
                },
            ),
        ];

        // Enqueue all controls back-to-back. The adapter must observe the
        // exact JSONL order even though each call remains pending.
        for (_, command) in &controls {
            send_command(&mut client_to_daemon, &command).await;
        }

        let started = read_line(&mut client_from_daemon).await;
        assert_eq!(started["type"], "sessionStarted");

        for (expected_operation, _) in &controls {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), entered_rx.recv())
                    .await
                    .expect("control call must reach the adapter"),
                Some(*expected_operation)
            );

            send_command(&mut client_to_daemon, &ClientCommand::Ping).await;
            let ping = read_line(&mut client_from_daemon).await;
            assert_eq!(ping["reply"], "ping");
            assert_eq!(ping["ok"], true);
            // Lifecycle calls are serialized in wire order. Release this one
            // before enqueueing the next while keeping Ping independently
            // responsive through the reader/admin path.
            release.add_permits(1);
        }

        let closed = read_line(&mut client_from_daemon).await;
        assert_eq!(closed["type"], "sessionClosed");
        assert_eq!(closed["sessionId"], session_id.0.as_str());
        assert!(
            !retained_sessions.lock().await.contains_key(&session_id),
            "SessionClosed must only be published after the Hub handle is removed"
        );

        send_command(
            &mut client_to_daemon,
            &ClientCommand::TurnStart {
                session_id: session_id.clone(),
                turn_id: TurnId("after-close".into()),
                prompt: "must fail".into(),
            },
        )
        .await;
        use tokio::io::AsyncReadExt;
        let mut late = [0_u8; 1];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                client_from_daemon.read(&mut late),
            )
            .await
            .is_err(),
            "no session event may be emitted after SessionClosed"
        );

        client_to_daemon.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), hub_task)
            .await
            .expect("hub exits after pending controls finish")
            .unwrap()
            .unwrap();
    }

    /// Selfcheck reports protocolVersion + registered agent kinds.
    #[tokio::test]
    async fn selfcheck_returns_protocol_and_agents() {
        let router = Arc::new(AgentRouter::new());
        let hub = RuntimeHub::new(router);

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        let line = serde_json::to_string(&ClientCommand::Selfcheck).unwrap();
        client_to_daemon.write_all(line.as_bytes()).await.unwrap();
        client_to_daemon.write_all(b"\n").await.unwrap();
        client_to_daemon.shutdown().await.unwrap();

        let mut buf = Vec::new();
        let read_fut = async {
            use tokio::io::AsyncReadExt;
            client_from_daemon.read_to_end(&mut buf).await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(2), read_fut)
            .await
            .expect("daemon should respond and exit");
        hub_task.await.unwrap().unwrap();

        let response = String::from_utf8_lossy(&buf);
        let first_line = response.lines().next().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(first_line).unwrap();
        assert_eq!(parsed["reply"], "selfcheck");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["protocolVersion"], PROTOCOL_VERSION);
        assert!(parsed["agents"].is_array());
    }
}
