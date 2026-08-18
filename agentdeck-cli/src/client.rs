//! v3 client API — sends `ClientCommand` JSONL, reads `ServerEvent` JSONL
//! and admin reply side-channel.
//!
//! ## Admin reply parsing
//!
//! The daemon writes two kinds of lines to stdout (via a single writer task):
//!
//!   1. `ServerEvent` lines — always have a `"type"` JSON key
//!      (e.g. `{"type":"sessionStarted", ...}`)
//!
//!   2. Admin reply lines — always have a `"reply"` JSON key
//!      (e.g. `{"reply":"ping","ok":true}`)
//!
//! The two shapes are disjoint: no valid `ServerEvent` has `"reply"` and
//! no admin reply has `"type"`. Therefore the CLI can parse any stdout line
//! by peeking at which key is present, with zero ambiguity.
//!
//! Admin replies for `History` commands wrap the typed `HistoryResponse`
//! envelope under `"response"` within `{"reply":"history","response":{...}}`.
//! A failed request uses the same terminal reply with a typed `"error"`
//! field, which is surfaced immediately with its daemon error code.

use crate::output::CliError;
use crate::transport::{AsyncProcessTransport, ProcessTransport, SyncTransport, split_async};
use agentdeck_protocol::{
    ActionDecision, AgentKind, ClientCommand, HistoryRequest, HistoryResponse, InitialTurn,
    ProtocolError, ServerEvent, SessionCapabilities, SessionId, SessionStart, ThreadId, TurnId,
    VendorControlPayload, VendorSessionOptions,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

// ── Envelope discriminant ─────────────────────────────────────────────────────

/// What kind of line did the daemon write?
enum DaemonLine {
    Event(ServerEvent),
    AdminReply(serde_json::Value),
    /// Unparseable — skip silently.
    Unknown,
}

enum SessionStreamAction {
    Forward(ServerEvent),
    RequestClose(SessionId),
    Finish(ServerEvent),
    Ignore,
}

#[derive(Default)]
struct SessionStreamState {
    closing_session: Option<SessionId>,
    pending_turn_terminal: Option<ServerEvent>,
    client_close_sent: bool,
}

impl SessionStreamState {
    fn accept(&mut self, event: ServerEvent) -> SessionStreamAction {
        if let Some(expected_session) = &self.closing_session {
            return match &event {
                ServerEvent::SessionClosed {
                    session_id,
                    outcome,
                    ..
                } if session_id == expected_session => {
                    let terminal = if matches!(outcome, agentdeck_protocol::SessionOutcome::Failed)
                    {
                        event
                    } else {
                        self.pending_turn_terminal.take().unwrap_or(event)
                    };
                    SessionStreamAction::Finish(terminal)
                }
                ServerEvent::Error {
                    session_id: Some(session_id),
                    ..
                } if session_id == expected_session && self.client_close_sent => {
                    SessionStreamAction::Finish(event)
                }
                _ => SessionStreamAction::Ignore,
            };
        }

        match &event {
            ServerEvent::TurnFinished {
                session_id,
                next_state,
                ..
            } => {
                let session_id = session_id.clone();
                let should_request_close =
                    matches!(next_state, agentdeck_protocol::TurnNextState::Ready);
                self.pending_turn_terminal = Some(event);
                self.closing_session = Some(session_id.clone());
                if should_request_close {
                    self.client_close_sent = true;
                    SessionStreamAction::RequestClose(session_id)
                } else {
                    // Fatal/running-close paths have already committed the
                    // owner to cleanup. Wait for its authoritative terminal;
                    // a duplicate SessionClose can race with route removal.
                    SessionStreamAction::Ignore
                }
            }
            ServerEvent::TurnComplete { .. }
            | ServerEvent::SessionClosed { .. }
            | ServerEvent::Error { .. } => SessionStreamAction::Finish(event),
            _ => SessionStreamAction::Forward(event),
        }
    }
}

fn parse_daemon_line(raw: &str) -> DaemonLine {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw) else {
        return DaemonLine::Unknown;
    };
    if val.get("type").is_some() {
        // Try ServerEvent
        if let Ok(ev) = serde_json::from_value::<ServerEvent>(val) {
            return DaemonLine::Event(ev);
        }
        return DaemonLine::Unknown;
    }
    if val.get("reply").is_some() {
        return DaemonLine::AdminReply(val);
    }
    DaemonLine::Unknown
}

// ── Sync round-trip helper (admin commands only) ──────────────────────────────

/// Send a `ClientCommand` and wait for the admin reply JSON whose `"reply"`
/// field matches `expected_reply`. Skips `ServerEvent` lines encountered
/// while waiting (they belong to concurrent sessions).
fn admin_round_trip<T: SyncTransport>(
    transport: &mut T,
    cmd: &ClientCommand,
    expected_reply: &str,
) -> Result<serde_json::Value, CliError> {
    admin_round_trip_matching(transport, cmd, expected_reply, None)
}

fn admin_round_trip_matching<T: SyncTransport>(
    transport: &mut T,
    cmd: &ClientCommand,
    expected_reply: &str,
    expected_request_id: Option<&str>,
) -> Result<serde_json::Value, CliError> {
    let line = serde_json::to_string(cmd)?;
    transport.send_line(&line)?;
    loop {
        let raw = transport.recv_line()?;
        let Some(raw) = raw else {
            return Err(CliError::NoResponse);
        };
        match parse_daemon_line(&raw) {
            DaemonLine::AdminReply(v) => {
                let got = v.get("reply").and_then(|r| r.as_str()).unwrap_or("");
                let request_matches = expected_request_id.is_none_or(|expected| {
                    v.get("requestId").and_then(|id| id.as_str()) == Some(expected)
                });
                if got == expected_reply && request_matches {
                    if let Some(error_value) = v.get("error").filter(|value| !value.is_null()) {
                        let error = serde_json::from_value::<ProtocolError>(error_value.clone())
                            .map_err(|source| CliError::Protocol {
                                code: None,
                                message: format!(
                                    "invalid error field in {expected_reply} reply: {source}"
                                ),
                            })?;
                        return Err(CliError::Protocol {
                            code: Some(error.code),
                            message: error.message,
                        });
                    }
                    return Ok(v);
                }
                // Different admin reply: might be from a concurrent command;
                // keep reading.
            }
            DaemonLine::Event(ServerEvent::Error { error, .. }) => {
                // C5 fix: thread the daemon's structured `error.code`
                // (e.g. `agent-not-registered`) through to the CLI
                // envelope instead of collapsing it to "protocol".
                return Err(CliError::Protocol {
                    code: Some(error.code),
                    message: error.message,
                });
            }
            DaemonLine::Event(_) => continue,
            DaemonLine::Unknown => continue,
        }
    }
}

// ── Sync Client (admin commands: ping/selfcheck/agent-list/capabilities/history) ──

pub struct Client {
    transport: ProcessTransport,
    next_history_request_id: u64,
}

impl Client {
    /// Spawn the daemon and return a ready client.
    pub fn connect(profile: &str, data_dir: Option<&str>) -> Result<Self, CliError> {
        let transport = ProcessTransport::spawn(profile, data_dir)
            .map_err(|e| CliError::Transport(e.to_string()))?;
        Ok(Self {
            transport,
            next_history_request_id: 1,
        })
    }

    pub fn ping(&mut self) -> Result<(), CliError> {
        let v = admin_round_trip(&mut self.transport, &ClientCommand::Ping, "ping")?;
        if v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) {
            Ok(())
        } else {
            Err(CliError::Protocol {
                code: None,
                message: "ping returned ok=false".into(),
            })
        }
    }

    pub fn selfcheck(&mut self) -> Result<serde_json::Value, CliError> {
        let v = admin_round_trip(&mut self.transport, &ClientCommand::Selfcheck, "selfcheck")?;
        if v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) {
            Ok(v)
        } else {
            Err(CliError::Session {
                code: None,
                message: "selfcheck returned ok=false".into(),
            })
        }
    }

    pub fn protocol_schema(&mut self) -> Result<serde_json::Value, CliError> {
        let v = admin_round_trip(
            &mut self.transport,
            &ClientCommand::ProtocolSchema,
            "protocolSchema",
        )?;
        v.get("schema").cloned().ok_or_else(|| CliError::Protocol {
            code: None,
            message: "missing schema field".into(),
        })
    }

    pub fn protocol_version(&mut self) -> Result<u32, CliError> {
        let v = admin_round_trip(
            &mut self.transport,
            &ClientCommand::ProtocolVersion,
            "protocolVersion",
        )?;
        v.get("protocolVersion")
            .and_then(|x| x.as_u64())
            .map(|n| n as u32)
            .ok_or_else(|| CliError::Protocol {
                code: None,
                message: "missing protocolVersion field".into(),
            })
    }

    pub fn agent_list(&mut self) -> Result<Vec<String>, CliError> {
        let v = admin_round_trip(&mut self.transport, &ClientCommand::AgentList, "agentList")?;
        let arr = v
            .get("agents")
            .and_then(|a| a.as_array())
            .ok_or_else(|| CliError::Protocol {
                code: None,
                message: "missing agents array".into(),
            })?;
        Ok(arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect())
    }

    pub fn agent_capabilities(&mut self, kind: AgentKind) -> Result<SessionCapabilities, CliError> {
        let v = admin_round_trip(
            &mut self.transport,
            &ClientCommand::AgentCapabilities { agent_kind: kind },
            "agentCapabilities",
        )?;
        let caps_val = v
            .get("capabilities")
            .cloned()
            .ok_or_else(|| CliError::Protocol {
                code: None,
                message: "missing capabilities field".into(),
            })?;
        serde_json::from_value::<SessionCapabilities>(caps_val).map_err(CliError::Json)
    }

    pub fn history(&mut self, req: HistoryRequest) -> Result<HistoryResponse, CliError> {
        let request_id = format!(
            "cli-history-{}-{}",
            std::process::id(),
            self.next_history_request_id
        );
        self.next_history_request_id =
            self.next_history_request_id
                .checked_add(1)
                .ok_or_else(|| CliError::Protocol {
                    code: None,
                    message: "history request id exhausted".into(),
                })?;
        let command = ClientCommand::History(req.with_request_id(request_id.clone()));
        let v =
            admin_round_trip_matching(&mut self.transport, &command, "history", Some(&request_id))?;
        let resp_val = v
            .get("response")
            .cloned()
            .ok_or_else(|| CliError::Protocol {
                code: None,
                message: "missing response field in history reply".into(),
            })?;
        serde_json::from_value::<HistoryResponse>(resp_val).map_err(CliError::Json)
    }
}

// ── Async streaming session (session run / continue) ──────────────────────────

/// Run a streaming session (start or continue) via an async daemon transport.
/// Sends the given `SessionStart` command, then
/// reads `ServerEvent` lines from stdout and forwards them to the returned
/// mpsc receiver until a turn/session terminal or `Error` is received.
///
/// Admin reply lines encountered on the shared stdout are skipped (they
/// belong to a different logical channel).
pub async fn stream_session(
    cmd: ClientCommand,
    profile: &str,
    data_dir: Option<&str>,
) -> Result<mpsc::Receiver<ServerEvent>, CliError> {
    let requested_session_id = match &cmd {
        ClientCommand::SessionStart(start) => Some(start.session_id.clone()),
        _ => None,
    };
    let mut transport = AsyncProcessTransport::spawn(profile, data_dir)
        .await
        .map_err(|e| CliError::Transport(e.to_string()))?;

    let line = serde_json::to_string(&cmd)?;
    transport
        .send_line(&line)
        .await
        .map_err(|e| CliError::Transport(e.to_string()))?;

    // Split into writer (keeps child alive) + line receiver channel.
    let (mut writer, mut line_rx) = split_async(transport);

    let (tx, rx) = mpsc::channel::<ServerEvent>(64);

    tokio::spawn(async move {
        // Keep writer (and child process) alive for the duration of streaming.
        // On every terminal path, graceful shutdown closes stdin so the Hub
        // can request SessionClose and wait for owner cleanup before daemon
        // exit; the transport's Drop kill is only a cancellation fallback.
        let mut state = SessionStreamState::default();
        let mut terminal = None;
        loop {
            let Some(raw) = line_rx.recv().await else {
                break;
            };
            match parse_daemon_line(&raw) {
                DaemonLine::Event(ev) => match state.accept(ev) {
                    SessionStreamAction::Forward(ev) => {
                        if tx.send(ev).await.is_err() {
                            break;
                        }
                    }
                    SessionStreamAction::RequestClose(session_id) => {
                        let close = ClientCommand::SessionClose {
                            session_id: session_id.clone(),
                        };
                        let line = serde_json::to_string(&close)
                            .expect("SessionClose serialization is infallible");
                        if let Err(error) = writer.send_line(&line).await {
                            terminal = Some(ServerEvent::Error {
                                session_id: Some(session_id),
                                error: ProtocolError {
                                    code: "daemon-session-close-write-failed".into(),
                                    message: format!("write SessionClose to agentdeckd: {error}"),
                                    diagnostic_ref: None,
                                },
                            });
                            break;
                        }
                    }
                    SessionStreamAction::Finish(ev) => {
                        terminal = Some(ev);
                        break;
                    }
                    SessionStreamAction::Ignore => {}
                },
                DaemonLine::AdminReply(_) => continue,
                DaemonLine::Unknown => continue,
            }
        }
        // Stop the stdout pump before waiting so it cannot block on a full
        // channel after this task has stopped consuming lines.
        drop(line_rx);
        if let Err(error) = writer.shutdown().await
            && terminal.as_ref().is_none_or(terminal_reports_success)
        {
            terminal = Some(ServerEvent::Error {
                session_id: requested_session_id,
                error: ProtocolError {
                    code: "daemon-shutdown-failed".into(),
                    message: error.to_string(),
                    diagnostic_ref: None,
                },
            });
        }
        // Deliver the terminal only after daemon stdin is closed and the child
        // has been reaped. This prevents the CLI runtime from exiting while its
        // cleanup task is still in flight.
        if let Some(terminal) = terminal {
            let _ = tx.send(terminal).await;
        }
    });

    Ok(rx)
}

fn terminal_reports_success(event: &ServerEvent) -> bool {
    matches!(
        event,
        ServerEvent::TurnFinished {
            outcome: agentdeck_protocol::TurnOutcome::Succeeded,
            ..
        } | ServerEvent::TurnComplete { .. }
            | ServerEvent::SessionClosed {
                outcome: agentdeck_protocol::SessionOutcome::Closed,
                ..
            }
    )
}

// ── Convenience constructors for session commands ─────────────────────────────

pub fn session_start_cmd(
    agent_kind: AgentKind,
    cwd: std::path::PathBuf,
    prompt: String,
    vendor_options: VendorSessionOptions,
) -> ClientCommand {
    session_start_or_resume_cmd(agent_kind, cwd, prompt, vendor_options, None)
}

pub fn session_continue_cmd(
    thread_id: String,
    agent_kind: AgentKind,
    cwd: std::path::PathBuf,
    prompt: String,
    vendor_options: VendorSessionOptions,
) -> ClientCommand {
    session_start_or_resume_cmd(
        agent_kind,
        cwd,
        prompt,
        vendor_options,
        Some(ThreadId(thread_id)),
    )
}

#[allow(dead_code)]
pub fn turn_start_cmd(session_id: String, turn_id: String, prompt: String) -> ClientCommand {
    ClientCommand::TurnStart {
        session_id: SessionId(session_id),
        turn_id: TurnId(turn_id),
        prompt,
    }
}

#[allow(dead_code)]
pub fn turn_cancel_cmd(session_id: String, turn_id: String) -> ClientCommand {
    ClientCommand::TurnCancel {
        session_id: SessionId(session_id),
        turn_id: TurnId(turn_id),
    }
}

#[allow(dead_code)]
pub fn session_close_cmd(session_id: String) -> ClientCommand {
    ClientCommand::SessionClose {
        session_id: SessionId(session_id),
    }
}

fn session_start_or_resume_cmd(
    agent_kind: AgentKind,
    cwd: std::path::PathBuf,
    prompt: String,
    vendor_options: VendorSessionOptions,
    resume_thread_id: Option<ThreadId>,
) -> ClientCommand {
    ClientCommand::SessionStart(SessionStart {
        session_id: SessionId(next_cli_id("session")),
        agent_kind,
        cwd,
        resume_thread_id,
        initial_turn: Some(InitialTurn {
            turn_id: TurnId(next_cli_id("turn")),
            prompt,
        }),
        vendor_options,
        runtime_options: Default::default(),
    })
}

fn next_cli_id(kind: &str) -> String {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("cli-{kind}-{}-{timestamp}-{sequence}", std::process::id())
}

#[allow(dead_code)]
pub fn action_decision_cmd(session_id: String, decision: ActionDecision) -> ClientCommand {
    ClientCommand::ActionDecision {
        session_id: SessionId(session_id),
        decision,
    }
}

#[allow(dead_code)]
pub fn vendor_control_cmd(session_id: String, payload: VendorControlPayload) -> ClientCommand {
    ClientCommand::VendorControl {
        session_id: SessionId(session_id),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FakeTransport;

    fn turn_finished() -> ServerEvent {
        ServerEvent::TurnFinished {
            session_id: SessionId("session-1".into()),
            thread_id: ThreadId("thread-1".into()),
            agent_kind: AgentKind::Codex,
            turn_id: TurnId("turn-1".into()),
            outcome: agentdeck_protocol::TurnOutcome::Succeeded,
            next_state: agentdeck_protocol::TurnNextState::Ready,
            summary: None,
            error: None,
        }
    }

    fn ping_reply() -> String {
        r#"{"reply":"ping","ok":true}"#.to_string()
    }

    fn selfcheck_reply() -> String {
        r#"{"reply":"selfcheck","ok":true,"protocolVersion":3,"agents":["codex","claude_code"]}"#
            .to_string()
    }

    fn error_event(msg: &str) -> String {
        serde_json::json!({
            "type": "error",
            "error": { "code": "test", "message": msg, "diagnosticRef": null }
        })
        .to_string()
    }

    #[test]
    fn parse_daemon_line_discriminates_event_vs_admin() {
        // ServerEvent has "type"
        let ev_line = r#"{"type":"error","error":{"code":"x","message":"y","diagnosticRef":null}}"#;
        assert!(matches!(parse_daemon_line(ev_line), DaemonLine::Event(_)));

        // Admin reply has "reply"
        let admin_line = r#"{"reply":"ping","ok":true}"#;
        assert!(matches!(
            parse_daemon_line(admin_line),
            DaemonLine::AdminReply(_)
        ));

        // Unknown
        let unknown = r#"{"foo":"bar"}"#;
        assert!(matches!(parse_daemon_line(unknown), DaemonLine::Unknown));
    }

    #[test]
    fn typed_turn_terminal_is_held_until_clean_matching_session_close() {
        let mut state = SessionStreamState::default();
        assert!(matches!(
            state.accept(turn_finished()),
            SessionStreamAction::RequestClose(SessionId(ref id)) if id == "session-1"
        ));
        assert!(matches!(
            state.accept(ServerEvent::SessionClosed {
                session_id: SessionId("other-session".into()),
                thread_id: None,
                agent_kind: AgentKind::Codex,
                outcome: agentdeck_protocol::SessionOutcome::Closed,
                error: None,
            }),
            SessionStreamAction::Ignore
        ));
        let action = state.accept(ServerEvent::SessionClosed {
            session_id: SessionId("session-1".into()),
            thread_id: Some(ThreadId("thread-1".into())),
            agent_kind: AgentKind::Codex,
            outcome: agentdeck_protocol::SessionOutcome::Closed,
            error: None,
        });
        assert!(matches!(
            action,
            SessionStreamAction::Finish(ServerEvent::TurnFinished { .. })
        ));
    }

    #[test]
    fn failed_session_close_replaces_pending_success_terminal() {
        let mut state = SessionStreamState::default();
        assert!(matches!(
            state.accept(turn_finished()),
            SessionStreamAction::RequestClose(_)
        ));
        let action = state.accept(ServerEvent::SessionClosed {
            session_id: SessionId("session-1".into()),
            thread_id: Some(ThreadId("thread-1".into())),
            agent_kind: AgentKind::Codex,
            outcome: agentdeck_protocol::SessionOutcome::Failed,
            error: Some(ProtocolError {
                code: "codex-cleanup-failed".into(),
                message: "cleanup failed".into(),
                diagnostic_ref: None,
            }),
        });
        assert!(matches!(
            action,
            SessionStreamAction::Finish(ServerEvent::SessionClosed {
                outcome: agentdeck_protocol::SessionOutcome::Failed,
                ..
            })
        ));
    }

    #[test]
    fn closing_turn_waits_for_authoritative_session_terminal_without_duplicate_close() {
        let mut state = SessionStreamState::default();
        let closing_turn = ServerEvent::TurnFinished {
            session_id: SessionId("session-1".into()),
            thread_id: ThreadId("thread-1".into()),
            agent_kind: AgentKind::Codex,
            turn_id: TurnId("turn-1".into()),
            outcome: agentdeck_protocol::TurnOutcome::Failed,
            next_state: agentdeck_protocol::TurnNextState::Closing,
            summary: None,
            error: Some(ProtocolError {
                code: "codex-protocol-error".into(),
                message: "fatal turn failure".into(),
                diagnostic_ref: None,
            }),
        };
        assert!(matches!(
            state.accept(closing_turn),
            SessionStreamAction::Ignore
        ));
        assert!(matches!(
            state.accept(ServerEvent::Error {
                session_id: Some(SessionId("session-1".into())),
                error: ProtocolError {
                    code: "session-not-found".into(),
                    message: "route already retired".into(),
                    diagnostic_ref: None,
                },
            }),
            SessionStreamAction::Ignore
        ));
        let action = state.accept(ServerEvent::SessionClosed {
            session_id: SessionId("session-1".into()),
            thread_id: Some(ThreadId("thread-1".into())),
            agent_kind: AgentKind::Codex,
            outcome: agentdeck_protocol::SessionOutcome::Failed,
            error: Some(ProtocolError {
                code: "codex-protocol-error".into(),
                message: "fatal session failure".into(),
                diagnostic_ref: None,
            }),
        });
        assert!(matches!(
            action,
            SessionStreamAction::Finish(ServerEvent::SessionClosed {
                outcome: agentdeck_protocol::SessionOutcome::Failed,
                ..
            })
        ));
    }

    #[test]
    fn admin_round_trip_fake_skips_event_lines_and_matches_reply() {
        // Use a non-error ServerEvent (agentItem etc.) — those should be
        // skipped while waiting for the matching admin reply.
        // We can't construct a full AgentItem without all fields, so we
        // use a stray admin reply with a different key first.
        let different_reply = r#"{"reply":"protocolVersion","protocolVersion":3}"#.to_string();
        let mut fake = FakeTransport::new(vec![
            // stray admin reply with different key — skip and keep looking
            different_reply,
            ping_reply(),
        ]);
        let v = admin_round_trip(&mut fake, &ClientCommand::Ping, "ping").unwrap();
        assert_eq!(v["reply"], "ping");
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn admin_round_trip_fake_returns_no_response_on_eof() {
        let mut fake = FakeTransport::new(vec![]);
        let err = admin_round_trip(&mut fake, &ClientCommand::Ping, "ping").unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn admin_round_trip_fake_propagates_error_event() {
        let mut fake = FakeTransport::new(vec![error_event("daemon failed")]);
        let err = admin_round_trip(&mut fake, &ClientCommand::Ping, "ping").unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.message().contains("daemon failed"));
    }

    #[test]
    fn selfcheck_ok_true_returns_value() {
        let mut fake = FakeTransport::new(vec![selfcheck_reply()]);
        let v = admin_round_trip(&mut fake, &ClientCommand::Selfcheck, "selfcheck").unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["protocolVersion"], 3);
    }

    #[test]
    fn agent_list_parses_from_admin_reply() {
        let raw = r#"{"reply":"agentList","agents":["codex","claude_code"]}"#;
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let arr = v["agents"].as_array().unwrap();
        let kinds: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
        assert!(kinds.contains(&"codex"));
        assert!(kinds.contains(&"claude_code"));
    }

    #[test]
    fn history_parses_empty_list_response() {
        let raw = r#"{"reply":"history","response":{"kind":"list","value":[]}}"#;
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let resp: HistoryResponse = serde_json::from_value(v["response"].clone()).unwrap();
        assert!(matches!(resp, HistoryResponse::List(ref items) if items.is_empty()));
    }

    #[test]
    fn admin_round_trip_propagates_history_admin_error_without_waiting() {
        let error_reply = serde_json::json!({
            "reply": "history",
            "requestId": "history-request-42",
            "error": {
                "code": "history-all-sources-failed",
                "message": "all registered history sources failed",
                "diagnosticRef": null,
            }
        })
        .to_string();
        let success_reply = r#"{"reply":"history","requestId":"history-request-42","response":{"kind":"list","value":[]}}"#.to_string();
        let mut fake = FakeTransport::new(vec![error_reply, success_reply.clone()]);

        let err = admin_round_trip_matching(
            &mut fake,
            &ClientCommand::History(HistoryRequest::List {
                request_id: Some("history-request-42".into()),
                agent_kind: None,
                cwd_filter: None,
                limit: None,
            }),
            "history",
            Some("history-request-42"),
        )
        .unwrap_err();

        match err {
            CliError::Protocol { code, message } => {
                assert_eq!(code.as_deref(), Some("history-all-sources-failed"));
                assert_eq!(message, "all registered history sources failed");
            }
            other => panic!("expected CliError::Protocol, got {other:?}"),
        }
        assert_eq!(
            fake.recv_line().unwrap().as_deref(),
            Some(success_reply.as_str()),
            "the matching error reply must terminate the round trip immediately"
        );
    }

    #[test]
    fn correlated_history_round_trip_skips_stale_reply_with_same_discriminator() {
        let stale =
            r#"{"reply":"history","requestId":"old","response":{"kind":"list","value":[]}}"#
                .to_string();
        let current =
            r#"{"reply":"history","requestId":"current","response":{"kind":"list","value":[]}}"#
                .to_string();
        let mut fake = FakeTransport::new(vec![stale, current]);
        let command = ClientCommand::History(HistoryRequest::List {
            request_id: Some("current".into()),
            agent_kind: None,
            cwd_filter: None,
            limit: None,
        });

        let reply = admin_round_trip_matching(&mut fake, &command, "history", Some("current"))
            .expect("current history reply");

        assert_eq!(reply["requestId"], "current");
    }

    #[test]
    fn session_continue_cmd_builds_correct_variant() {
        let options =
            VendorSessionOptions::ClaudeCode(agentdeck_protocol::ClaudeCodeSessionOptions {
                permission_mode: agentdeck_protocol::ClaudeCodePermissionMode::Default,
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
        let cmd = session_continue_cmd(
            "tid-1".into(),
            AgentKind::ClaudeCode,
            std::path::PathBuf::from("/tmp/work"),
            "continue this".into(),
            options,
        );
        let ClientCommand::SessionStart(start) = cmd else {
            panic!("continue must use SessionStart with resumeThreadId");
        };
        assert_eq!(start.agent_kind, AgentKind::ClaudeCode);
        assert_eq!(start.cwd, std::path::PathBuf::from("/tmp/work"));
        assert_eq!(start.resume_thread_id, Some(ThreadId("tid-1".into())));
        assert_eq!(
            start.initial_turn.as_ref().map(|turn| turn.prompt.as_str()),
            Some("continue this")
        );
        assert!(!start.session_id.0.is_empty());
        assert!(
            start
                .initial_turn
                .as_ref()
                .is_some_and(|turn| !turn.turn_id.0.is_empty())
        );
    }

    /// C5 fix: when the daemon emits a `ServerEvent::Error` with a
    /// structured `error.code` (e.g. `cc-not-installed`), the CLI
    /// surfaces that code in the envelope instead of the literal
    /// `"protocol"` discriminator.
    #[test]
    fn admin_round_trip_propagates_daemon_error_code() {
        let raw = serde_json::json!({
            "type": "error",
            "error": {
                "code": "cc-not-installed",
                "message": "no claude binary",
                "diagnosticRef": null,
            }
        })
        .to_string();
        let mut fake = FakeTransport::new(vec![raw]);
        let err = admin_round_trip(&mut fake, &ClientCommand::Ping, "ping").unwrap_err();
        match err {
            CliError::Protocol { code, message } => {
                assert_eq!(code.as_deref(), Some("cc-not-installed"));
                assert_eq!(message, "no claude binary");
            }
            other => panic!("expected CliError::Protocol, got {other:?}"),
        }
    }
}
