//! v2 client API — sends `ClientCommand` JSONL, reads `ServerEvent` JSONL
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

use crate::output::CliError;
use crate::transport::{AsyncProcessTransport, ProcessTransport, SyncTransport, split_async};
use agentdeck_protocol::{
    ActionDecision, AgentKind, ClientCommand, HistoryRequest, HistoryResponse, ServerEvent,
    SessionCapabilities, SessionId, SessionStart, ThreadId, VendorControlPayload,
};
use tokio::sync::mpsc;

// ── Envelope discriminant ─────────────────────────────────────────────────────

/// What kind of line did the daemon write?
enum DaemonLine {
    Event(ServerEvent),
    AdminReply(serde_json::Value),
    /// Unparseable — skip silently.
    Unknown,
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
fn admin_round_trip(
    transport: &mut ProcessTransport,
    cmd: &ClientCommand,
    expected_reply: &str,
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
                if got == expected_reply {
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
}

impl Client {
    /// Spawn the daemon and return a ready client.
    pub fn connect(profile: &str, data_dir: Option<&str>) -> Result<Self, CliError> {
        let transport = ProcessTransport::spawn(profile, data_dir)
            .map_err(|e| CliError::Transport(e.to_string()))?;
        Ok(Self { transport })
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
        let v = admin_round_trip(&mut self.transport, &ClientCommand::History(req), "history")?;
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
/// Sends the given `cmd` (must be `SessionStart` or `SessionContinue`), then
/// reads `ServerEvent` lines from stdout and forwards them to the returned
/// mpsc receiver until `TurnComplete` or `Error` is received.
///
/// Admin reply lines encountered on the shared stdout are skipped (they
/// belong to a different logical channel).
pub async fn stream_session(
    cmd: ClientCommand,
    profile: &str,
    data_dir: Option<&str>,
) -> Result<mpsc::Receiver<ServerEvent>, CliError> {
    let mut transport = AsyncProcessTransport::spawn(profile, data_dir)
        .await
        .map_err(|e| CliError::Transport(e.to_string()))?;

    let line = serde_json::to_string(&cmd)?;
    transport
        .send_line(&line)
        .await
        .map_err(|e| CliError::Transport(e.to_string()))?;

    // Split into writer (keeps child alive) + line receiver channel.
    let (writer, mut line_rx) = split_async(transport);

    let (tx, rx) = mpsc::channel::<ServerEvent>(64);

    tokio::spawn(async move {
        // Keep writer (and child process) alive for the duration of streaming.
        let _writer = writer;
        loop {
            let Some(raw) = line_rx.recv().await else {
                break;
            };
            match parse_daemon_line(&raw) {
                DaemonLine::Event(ev) => {
                    let is_terminal = matches!(&ev, ServerEvent::TurnComplete { .. })
                        || matches!(&ev, ServerEvent::Error { .. });
                    let _ = tx.send(ev).await;
                    if is_terminal {
                        break;
                    }
                }
                DaemonLine::AdminReply(_) => continue,
                DaemonLine::Unknown => continue,
            }
        }
    });

    Ok(rx)
}

// ── Convenience constructors for session commands ─────────────────────────────

pub fn session_start_cmd(start: SessionStart) -> ClientCommand {
    ClientCommand::SessionStart(start)
}

pub fn session_continue_cmd(
    thread_id: String,
    agent_kind: AgentKind,
    cwd: std::path::PathBuf,
    prompt: String,
) -> ClientCommand {
    ClientCommand::SessionContinue {
        thread_id: ThreadId(thread_id),
        agent_kind,
        cwd,
        prompt,
    }
}

#[allow(dead_code)]
pub fn session_cancel_cmd(session_id: String) -> ClientCommand {
    ClientCommand::SessionCancel {
        session_id: SessionId(session_id),
    }
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

    fn ping_reply() -> String {
        r#"{"reply":"ping","ok":true}"#.to_string()
    }

    fn selfcheck_reply() -> String {
        r#"{"reply":"selfcheck","ok":true,"protocolVersion":2,"agents":["codex","claude_code"]}"#
            .to_string()
    }

    fn error_event(msg: &str) -> String {
        serde_json::json!({
            "type": "error",
            "error": { "code": "test", "message": msg, "diagnosticRef": null }
        })
        .to_string()
    }

    fn admin_round_trip_fake(
        fake: &mut FakeTransport,
        cmd: &ClientCommand,
        expected: &str,
    ) -> Result<serde_json::Value, CliError> {
        let line = serde_json::to_string(cmd).unwrap();
        fake.send_line(&line).unwrap();
        loop {
            let raw = fake.recv_line().unwrap();
            let Some(raw) = raw else {
                return Err(CliError::NoResponse);
            };
            match parse_daemon_line(&raw) {
                DaemonLine::AdminReply(v) => {
                    let got = v.get("reply").and_then(|r| r.as_str()).unwrap_or("");
                    if got == expected {
                        return Ok(v);
                    }
                }
                DaemonLine::Event(ServerEvent::Error { error, .. }) => {
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
    fn admin_round_trip_fake_skips_event_lines_and_matches_reply() {
        // Use a non-error ServerEvent (agentItem etc.) — those should be
        // skipped while waiting for the matching admin reply.
        // We can't construct a full AgentItem without all fields, so we
        // use a stray admin reply with a different key first.
        let different_reply = r#"{"reply":"protocolVersion","protocolVersion":2}"#.to_string();
        let mut fake = FakeTransport::new(vec![
            // stray admin reply with different key — skip and keep looking
            different_reply,
            ping_reply(),
        ]);
        let v = admin_round_trip_fake(&mut fake, &ClientCommand::Ping, "ping").unwrap();
        assert_eq!(v["reply"], "ping");
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn admin_round_trip_fake_returns_no_response_on_eof() {
        let mut fake = FakeTransport::new(vec![]);
        let err = admin_round_trip_fake(&mut fake, &ClientCommand::Ping, "ping").unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn admin_round_trip_fake_propagates_error_event() {
        let mut fake = FakeTransport::new(vec![error_event("daemon failed")]);
        let err = admin_round_trip_fake(&mut fake, &ClientCommand::Ping, "ping").unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.message().contains("daemon failed"));
    }

    #[test]
    fn selfcheck_ok_true_returns_value() {
        let mut fake = FakeTransport::new(vec![selfcheck_reply()]);
        let v = admin_round_trip_fake(&mut fake, &ClientCommand::Selfcheck, "selfcheck").unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["protocolVersion"], 2);
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
    fn session_continue_cmd_builds_correct_variant() {
        let cmd = session_continue_cmd(
            "tid-1".into(),
            AgentKind::ClaudeCode,
            std::path::PathBuf::from("/tmp/work"),
            "continue this".into(),
        );
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("sessionContinue"));
        assert!(json.contains("claude_code"));
        // C3 fix: cwd is now part of the on-wire SessionContinue payload
        // so adapter `continue_thread` no longer falls back to
        // `std::env::current_dir()` (which broke CC `--resume` and
        // tool_use cwd).
        assert!(json.contains("/tmp/work"));
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
        let err = admin_round_trip_fake(&mut fake, &ClientCommand::Ping, "ping").unwrap_err();
        match err {
            CliError::Protocol { code, message } => {
                assert_eq!(code.as_deref(), Some("cc-not-installed"));
                assert_eq!(message, "no claude binary");
            }
            other => panic!("expected CliError::Protocol, got {other:?}"),
        }
    }
}
