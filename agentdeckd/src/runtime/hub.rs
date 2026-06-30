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
use agentdeck_protocol::{
    ClientCommand, ProtocolError, ServerEvent, SessionId, PROTOCOL_VERSION,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Mutex};

/// Channel depth for the unified ServerEvent stream coming out of all
/// sessions. 256 is generous: the writer drains it as fast as stdout
/// will accept (line per `recv`).
const EVENTS_CHANNEL_CAPACITY: usize = 256;

/// Channel depth for admin (request/response) replies — Ping, Selfcheck,
/// ProtocolSchema, ProtocolVersion. These are bursty but rare; 32 is
/// enough headroom for a flood of selfchecks during boot.
const ADMIN_REPLY_CAPACITY: usize = 32;

/// Coordinator for the daemon's stdin/stdout main loop.
///
/// Owns an `Arc<AgentRouter>` (shared with every spawned session pump)
/// plus an in-process map of `session_id → AgentSessionHandle`. The
/// handle map keeps abort handles alive so `SessionCancel` can drop
/// them via the router and `Drop for Hub` reaps everything cleanly.
pub struct RuntimeHub {
    pub router: Arc<AgentRouter>,
    /// Holds every started session's `AgentSessionHandle`. We keep them
    /// alive so the abort_handle inside them stays valid; on
    /// `SessionCancel`, the router walks its own session map and we
    /// drop ours afterward. This is independent of the router's K2
    /// per-session lock (the router's map is keyed by `SessionId` →
    /// `AgentKind` and is purely for routing).
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

        let writer_handle = tokio::spawn(writer_task(stdout, events_rx, admin_rx));

        let mut reader = BufReader::new(stdin).lines();
        loop {
            match reader.next_line().await {
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    // K1 (C6 fix): never await long-running session commands
                    // inline — that blocks the stdin loop so subsequent
                    // Ping / SessionCancel queue behind a vendor handshake.
                    // Long-running commands (SessionStart, SessionContinue,
                    // History) are tokio::spawn'd; cheap admin commands
                    // (Ping, Selfcheck, AgentList, AgentCapabilities,
                    // ProtocolVersion, ProtocolSchema, SessionCancel,
                    // ActionDecision, VendorControl) stay inline since
                    // they complete near-instantly.
                    self.handle_line(line, &events_tx, &admin_tx).await;
                }
                Ok(None) => break, // EOF
                Err(e) => {
                    // stdin closed unexpectedly; treat as graceful EOF.
                    eprintln!("[agentdeckd] stdin read error: {e}");
                    break;
                }
            }
        }

        // Drop both senders so the writer task drains and exits.
        drop(events_tx);
        drop(admin_tx);
        let _ = writer_handle.await;
        Ok(())
    }

    async fn handle_line(
        &self,
        line: String,
        events_tx: &AgentEventSender,
        admin_tx: &mpsc::Sender<String>,
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
        self.dispatch(cmd, events_tx, admin_tx).await;
    }

    async fn dispatch(
        &self,
        cmd: ClientCommand,
        events_tx: &AgentEventSender,
        admin_tx: &mpsc::Sender<String>,
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
            ClientCommand::SessionCancel { session_id } => {
                if let Err(error) = self.router.cancel(&session_id).await {
                    let _ = events_tx
                        .send(ServerEvent::Error {
                            session_id: Some(session_id.clone()),
                            error,
                        })
                        .await;
                }
                // Drop our handle reference regardless — cancel is
                // idempotent at the router level.
                self.sessions.lock().await.remove(&session_id);
            }
            ClientCommand::ActionDecision { session_id, decision } => {
                if let Err(error) =
                    self.router.submit_decision(&session_id, decision).await
                {
                    let _ = events_tx
                        .send(ServerEvent::Error {
                            session_id: Some(session_id),
                            error,
                        })
                        .await;
                }
            }
            ClientCommand::VendorControl { session_id, payload } => {
                if let Err(error) = self
                    .router
                    .submit_vendor_control(&session_id, payload)
                    .await
                {
                    let _ = events_tx
                        .send(ServerEvent::Error {
                            session_id: Some(session_id),
                            error,
                        })
                        .await;
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
            // ── K1 (C6 fix): spawn long-running commands so the stdin
            // loop stays responsive. Each spawned task gets its own
            // Arc<AgentRouter> + Arc<Mutex<sessions>> clone and its own
            // mpsc::Sender clones — all are cheap. Output ordering on
            // the wire is preserved because the writer task is the
            // single owner of stdout and drains events_rx / admin_rx
            // serially.
            ClientCommand::SessionStart(start) => {
                let router = Arc::clone(&self.router);
                let sessions = Arc::clone(&self.sessions);
                let events_tx = events_tx.clone();
                tokio::spawn(async move {
                    match router.start_session(start, events_tx.clone()).await {
                        Ok(handle) => {
                            sessions
                                .lock()
                                .await
                                .insert(handle.session_id.clone(), handle);
                        }
                        Err(error) => {
                            let _ = events_tx
                                .send(ServerEvent::Error {
                                    session_id: None,
                                    error,
                                })
                                .await;
                        }
                    }
                });
            }
            ClientCommand::SessionContinue {
                thread_id,
                agent_kind,
                cwd,
                prompt,
            } => {
                let router = Arc::clone(&self.router);
                let sessions = Arc::clone(&self.sessions);
                let events_tx = events_tx.clone();
                tokio::spawn(async move {
                    match router
                        .continue_thread(thread_id, agent_kind, cwd, prompt, events_tx.clone())
                        .await
                    {
                        Ok(handle) => {
                            sessions
                                .lock()
                                .await
                                .insert(handle.session_id.clone(), handle);
                        }
                        Err(error) => {
                            let _ = events_tx
                                .send(ServerEvent::Error {
                                    session_id: None,
                                    error,
                                })
                                .await;
                        }
                    }
                });
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
                // Errors still flow through events_tx as
                // `ServerEvent::Error` (consistent with every other
                // failure path in this dispatch).
                //
                // K1 (C6 fix): spawn — Read/List can fan out across
                // adapters and touch disk; don't block stdin.
                let router = Arc::clone(&self.router);
                let events_tx = events_tx.clone();
                let admin_tx = admin_tx.clone();
                tokio::spawn(async move {
                    match router.handle_history(req).await {
                        Ok(response) => {
                            let line = serde_json::json!({
                                "reply": "history",
                                "response": response,
                            })
                            .to_string();
                            let _ = admin_tx.send(line).await;
                        }
                        Err(error) => {
                            let _ = events_tx
                                .send(ServerEvent::Error {
                                    session_id: None,
                                    error,
                                })
                                .await;
                        }
                    }
                });
            }
        }
    }
}

/// Single-owner stdout writer. Drains the per-session events stream and
/// the admin reply stream into a single newline-delimited byte stream.
async fn writer_task<W>(
    mut stdout: W,
    mut events_rx: mpsc::Receiver<ServerEvent>,
    mut admin_rx: mpsc::Receiver<String>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    loop {
        tokio::select! {
            biased; // prefer admin (request/response) replies for snappier
                    // selfchecks under load; events are still drained next.
            maybe_admin = admin_rx.recv() => {
                match maybe_admin {
                    Some(line) => {
                        if !write_line(&mut stdout, line.as_bytes()).await { break; }
                    }
                    None => {
                        // admin channel closed; keep draining events
                        // until that side also closes.
                        while let Some(event) = events_rx.recv().await {
                            let line = match serde_json::to_string(&event) {
                                Ok(s) => s,
                                Err(_) => continue,
                            };
                            if !write_line(&mut stdout, line.as_bytes()).await { break; }
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
                        if !write_line(&mut stdout, line.as_bytes()).await { break; }
                    }
                    None => {
                        // events channel closed; keep draining admin
                        // until that side also closes.
                        while let Some(line) = admin_rx.recv().await {
                            if !write_line(&mut stdout, line.as_bytes()).await { break; }
                        }
                        break;
                    }
                }
            }
        }
    }
    // Best-effort flush before returning.
    let _ = stdout.flush().await;
}

async fn write_line<W: AsyncWrite + Unpin>(stdout: &mut W, body: &[u8]) -> bool {
    if stdout.write_all(body).await.is_err() {
        return false;
    }
    if stdout.write_all(b"\n").await.is_err() {
        return false;
    }
    if stdout.flush().await.is_err() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::*;
    use std::time::Duration;
    use tokio::io::{duplex, AsyncWriteExt as _};

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
        let parsed: serde_json::Value =
            serde_json::from_str(first_line).expect("reply JSON");
        assert_eq!(parsed["reply"], "ping");
        assert_eq!(parsed["ok"], true);
    }

    /// Task 4C — Phase 4 finalization: History command now flows
    /// end-to-end through the router. With an empty router the
    /// cross-agent List collapses to `{"reply":"history","response":
    /// {"kind":"list","value":[]}}` on the admin reply side-channel.
    /// Asserts the wire shape so Phase 5 / 6 clients can rely on it.
    #[tokio::test]
    async fn history_list_returns_admin_reply_with_empty_list_on_bare_router() {
        let router = Arc::new(AgentRouter::new());
        let hub = RuntimeHub::new(router);

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        let cmd = ClientCommand::History(HistoryRequest::List {
            agent_kind: None,
            cwd_filter: None,
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

        let response = String::from_utf8_lossy(&buf);
        let first_line = response.lines().next().expect("at least one reply line");
        let parsed: serde_json::Value =
            serde_json::from_str(first_line).expect("history reply JSON");
        assert_eq!(parsed["reply"], "history");
        assert_eq!(parsed["response"]["kind"], "list");
        assert!(parsed["response"]["value"].is_array());
        assert_eq!(parsed["response"]["value"].as_array().unwrap().len(), 0);
    }

    /// Read against an unregistered agent kind surfaces an Error
    /// event (not a hung-forever admin reply). Confirms the failure
    /// path still flows through the normal events stream.
    #[tokio::test]
    async fn history_read_for_unregistered_kind_yields_error_event() {
        let router = Arc::new(AgentRouter::new());
        let hub = RuntimeHub::new(router);

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        let cmd = ClientCommand::History(HistoryRequest::Read {
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

        let response = String::from_utf8_lossy(&buf);
        let first_line = response.lines().next().expect("at least one reply line");
        let event: ServerEvent = serde_json::from_str(first_line).expect("ServerEvent");
        match event {
            ServerEvent::Error { error, .. } => {
                assert_eq!(error.code, "agent-not-registered");
            }
            other => panic!("expected Error, got {other:?}"),
        }
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
            ActionDecision, AgentKind, CodexApprovalPolicy, CodexReasoningEffort,
            CodexSandboxMode, CodexSessionOptions, ProtocolError, SessionCapabilities,
            SessionStart, ThreadId, VendorControlPayload, VendorSessionOptions,
        };
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Instant;

        struct SlowStub {
            started: Arc<AtomicBool>,
        }
        #[async_trait::async_trait]
        impl Agent for SlowStub {
            fn kind(&self) -> AgentKind { AgentKind::Codex }
            fn capabilities(&self) -> SessionCapabilities {
                use agentdeck_protocol::{
                    CodexCapabilities, VendorCapabilities,
                };
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
            ) -> Result<(), ProtocolError> { Ok(()) }
            async fn submit_vendor_control(
                &self,
                _: &SessionId,
                _: VendorControlPayload,
            ) -> Result<(), ProtocolError> { Ok(()) }
            async fn cancel(&self, _: &SessionId) -> Result<(), ProtocolError> { Ok(()) }
        }

        let started = Arc::new(AtomicBool::new(false));
        let stub: DynAgent = Arc::new(SlowStub { started: Arc::clone(&started) });
        let mut router = AgentRouter::new();
        router.register(stub);
        let hub = RuntimeHub::new(Arc::new(router));

        let (mut client_to_daemon, daemon_stdin) = duplex(4096);
        let (daemon_stdout, mut client_from_daemon) = duplex(4096);

        let hub_task = tokio::spawn(hub.run(daemon_stdin, daemon_stdout));

        // 1) Submit SessionStart — will take 500ms inside the stub.
        let start = ClientCommand::SessionStart(SessionStart {
            agent_kind: AgentKind::Codex,
            cwd: std::path::PathBuf::from("/tmp"),
            prompt: Some("hi".into()),
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
            if n == 0 { break; }
            if byte[0] == b'\n' { break; }
            line_buf.push(byte[0]);
        }
        let elapsed = t0.elapsed();
        let parsed: serde_json::Value =
            serde_json::from_slice(&line_buf).expect("ping reply JSON");
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
