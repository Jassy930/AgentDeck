//! agentdeckd — AgentDeck daemon.
//!
//! Architecture (Eng D2): the IPC protocol IS the agent-neutral boundary.
//! `ipc` defines neutral types with zero vendor vocabulary. `codex` is the
//! ONLY module that knows Codex exists — it spawns the Codex app-server
//! child, owns it (Eng A1 second layer), and translates Codex items into
//! neutral `AgentItem`s. The Swift app speaks only `ipc`; a future Claude
//! Code / SSH adapter is another sibling of `codex` and changes nothing on
//! the Swift side.
//!
//!   Swift app ──JSONL──▶ agentdeckd ─┬─ ipc   (neutral wire)
//!             ◀─JSONL───             └─ codex ──▶ codex app-server child
//!                                                ◀── JSON-RPC (newline)
//!
//! Step 2 scope: a `startSession` request drives CodexAdapter
//! initialize → thread/start → turn/start and streams neutral AgentItems
//! back over IPC, plus neutral sessionState transitions (Eng D9). Step 1's
//! ping/pong/shutdown round trip is retained.

mod codex;
mod diag;
mod ipc;
mod record;

use std::io::{BufRead, ErrorKind, Write};
use std::sync::mpsc::{self, Receiver, Sender};

use ipc::{IpcMessage, SessionState};

#[derive(Debug, Default, PartialEq, Eq)]
struct HistoryListParams {
    cwd: Option<String>,
    search_term: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
struct StartTurnParams {
    thread_id: String,
    prompt: String,
}

#[derive(Debug, Clone)]
struct HubSession {
    session_id: String,
    thread_id: Option<String>,
}

fn write_msg(stdout: &mut impl Write, msg: &IpcMessage) -> std::io::Result<()> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    stdout.write_all(s.as_bytes())?;
    stdout.flush()
}

fn write_outbound_messages(
    mut stdout: impl Write,
    out_rx: Receiver<IpcMessage>,
) -> std::io::Result<()> {
    for msg in out_rx {
        if let Err(e) = write_msg(&mut stdout, &msg) {
            diag::log("writer_failed", &e.to_string());
            return Err(e);
        }
    }
    Ok(())
}

fn send_msg(out_tx: &Sender<IpcMessage>, msg: IpcMessage) -> std::io::Result<()> {
    out_tx
        .send(msg)
        .map_err(|_| std::io::Error::new(ErrorKind::BrokenPipe, "stdout writer channel closed"))
}

fn start_turn_ack(msg: &IpcMessage) -> Result<IpcMessage, String> {
    let session_id = msg
        .session_id
        .clone()
        .ok_or_else(|| "startTurn requires sessionId".to_string())?;
    let hub_session = HubSession {
        session_id,
        thread_id: msg.thread_id.clone(),
    };
    Ok(IpcMessage {
        kind: "turnAccepted".into(),
        id: msg.id,
        session_id: Some(hub_session.session_id),
        thread_id: hub_session.thread_id,
        payload: None,
    })
}

fn history_list_params(payload: Option<&serde_json::Value>) -> HistoryListParams {
    let Some(payload) = payload else {
        return HistoryListParams::default();
    };
    HistoryListParams {
        cwd: payload
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        search_term: payload
            .get("searchTerm")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        cursor: payload
            .get("cursor")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        limit: payload
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok()),
    }
}

fn history_read_thread_id(payload: Option<&serde_json::Value>) -> Option<String> {
    payload?
        .get("threadId")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn start_turn_params(payload: Option<&serde_json::Value>) -> Option<StartTurnParams> {
    let payload = payload?;
    let thread_id = payload.get("threadId")?.as_str()?.to_string();
    let prompt = payload.get("prompt")?.as_str()?.to_string();
    if thread_id.is_empty() || prompt.is_empty() {
        return None;
    }
    Some(StartTurnParams { thread_id, prompt })
}

fn run_history_list(
    out_tx: &Sender<IpcMessage>,
    id: Option<u64>,
    params: HistoryListParams,
) -> std::io::Result<()> {
    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => {
            diag::log("history_list_spawn_failed", &e.to_string());
            return send_msg(out_tx, IpcMessage::error(id, &e.to_string()));
        }
    };
    if let Err(e) = adapter.initialize() {
        diag::log("history_list_handshake_failed", &e.to_string());
        return send_msg(out_tx, IpcMessage::error(id, &e.to_string()));
    }
    match adapter.thread_list(
        params.cwd.as_deref(),
        params.search_term.as_deref(),
        params.cursor.as_deref(),
        params.limit,
    ) {
        Ok(list) => send_msg(
            out_tx,
            IpcMessage {
                kind: "historyThreads".into(),
                id,
                session_id: None,
                thread_id: None,
                payload: Some(serde_json::to_value(list).expect("history list serializes")),
            },
        ),
        Err(e) => {
            diag::log("history_list_failed", &e.to_string());
            send_msg(out_tx, IpcMessage::error(id, &e.to_string()))
        }
    }
}

fn run_history_read(
    out_tx: &Sender<IpcMessage>,
    id: Option<u64>,
    thread_id: &str,
) -> std::io::Result<()> {
    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => {
            diag::log("history_read_spawn_failed", &e.to_string());
            return send_msg(out_tx, IpcMessage::error(id, &e.to_string()));
        }
    };
    if let Err(e) = adapter.initialize() {
        diag::log("history_read_handshake_failed", &e.to_string());
        return send_msg(out_tx, IpcMessage::error(id, &e.to_string()));
    }
    match adapter.thread_read(thread_id) {
        Ok(detail) => send_msg(
            out_tx,
            IpcMessage {
                kind: "historyThread".into(),
                id,
                session_id: None,
                thread_id: None,
                payload: Some(serde_json::to_value(detail).expect("history detail serializes")),
            },
        ),
        Err(e) => {
            diag::log("history_read_failed", &e.to_string());
            send_msg(out_tx, IpcMessage::error(id, &e.to_string()))
        }
    }
}

fn run_thread_management(
    out_tx: &Sender<IpcMessage>,
    id: Option<u64>,
    action: &str,
    thread_id: &str,
    name: Option<&str>,
) -> std::io::Result<()> {
    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => return send_msg(out_tx, IpcMessage::error(id, &e.to_string())),
    };
    if let Err(e) = adapter.initialize() {
        return send_msg(out_tx, IpcMessage::error(id, &e.to_string()));
    }
    let result = match action {
        "archive" => adapter.thread_archive(thread_id),
        "unarchive" => adapter.thread_unarchive(thread_id),
        "rename" => adapter.thread_set_name(thread_id, name.unwrap_or("")),
        _ => Err(codex::CodexError::Protocol(
            "unknown thread management action".into(),
        )),
    };
    match result {
        Ok(()) => send_msg(
            out_tx,
            IpcMessage {
                kind: "historyThreadUpdated".into(),
                id,
                session_id: None,
                thread_id: None,
                payload: Some(serde_json::json!({ "threadId": thread_id })),
            },
        ),
        Err(e) => send_msg(out_tx, IpcMessage::error(id, &e.to_string())),
    }
}

/// Handle a `startSession` request: drive a full Codex turn, streaming
/// neutral AgentItems and sessionState transitions over IPC.
///
/// Eng D9: the daemon is the sole state source. Every transition is emitted
/// so the Swift app mirrors, never guesses. Eng premise 9: failures surface
/// as a visible error + Failed state, never a silent hang.
/// Append a line to the run record. Eng E2: a write failure does NOT block
/// the session, but IS surfaced as a visible IPC warning — never silent.
fn record_or_warn(out_tx: &Sender<IpcMessage>, run_id: &str, line: &str) -> std::io::Result<()> {
    if let Err(reason) = record::try_append(run_id, line) {
        diag::log("record_failed", &reason);
        send_msg(
            out_tx,
            IpcMessage {
                kind: "warning".into(),
                id: None,
                session_id: None,
                thread_id: None,
                payload: Some(serde_json::json!({
                    "message": format!("本次未留痕: {reason}")
                })),
            },
        )?;
    }
    Ok(())
}

fn run_session(
    out_tx: &Sender<IpcMessage>,
    id: Option<u64>,
    cwd: &str,
    prompt: &str,
) -> std::io::Result<()> {
    // run_id: AgentDeck-generated (premise 5), not user input, so it is a
    // safe filename component (no path traversal).
    let run_id = format!(
        "run-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    diag::log("session_start", &format!("run={run_id} cwd={cwd}"));
    send_msg(out_tx, IpcMessage::session_state(SessionState::Starting))?;
    record_or_warn(
        out_tx,
        &run_id,
        &format!(
            r#"{{"event":"start","prompt":{}}}"#,
            serde_json::to_string(prompt).unwrap_or_else(|_| "\"\"".into())
        ),
    )?;

    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => {
            diag::log("spawn_failed", &e.to_string());
            send_msg(out_tx, IpcMessage::error(id, &e.to_string()))?;
            return send_msg(out_tx, IpcMessage::session_state(SessionState::Failed));
        }
    };

    if let Err(e) = adapter.initialize() {
        diag::log("handshake_failed", &e.to_string());
        send_msg(out_tx, IpcMessage::error(id, &e.to_string()))?;
        return send_msg(out_tx, IpcMessage::session_state(SessionState::Failed));
    }

    let thread_id = match adapter.thread_start(cwd) {
        Ok(t) => t,
        Err(e) => {
            diag::log("thread_start_failed", &e.to_string());
            send_msg(out_tx, IpcMessage::error(id, &e.to_string()))?;
            return send_msg(out_tx, IpcMessage::session_state(SessionState::Failed));
        }
    };

    send_msg(out_tx, IpcMessage::session_state(SessionState::Running))?;

    // TRUE streaming (the Beat 1 soul — "the native streaming session IS
    // the wow"). EVERY delta is written to IPC the moment it is translated,
    // inside the turn_start callback. NO daemon-side coalescing: merging all
    // deltas into one (the old A2 behavior) destroyed the stream — the whole
    // reply appeared in one jarring burst (the bad feel the user reported).
    //
    // Backpressure is now the SwiftUI render layer's job: SessionModel
    // buffers agentItem deltas and flushes them at frame-ish cadence. The
    // daemon's job is to forward faithfully, not to buffer. (Design doc A2 is
    // downgraded accordingly: daemon-side merge → render-layer throttling.)
    //
    // The callback can't use `?`, so it stashes the first write error into
    // `write_err`; surfaced after the turn. `stdout`/`write_err` are
    // independent of `adapter`, so the closure does not conflict with
    // `turn_start`'s `&mut self`.
    let mut write_err: Option<std::io::Error> = None;
    {
        let run_id = &run_id;
        let out_tx = out_tx.clone();
        let turn = adapter.turn_start(&thread_id, prompt, |item| {
            if write_err.is_some() {
                return;
            }
            if let Err(e) = send_msg(&out_tx, IpcMessage::agent_item(&item)) {
                write_err = Some(e);
                return;
            }
            // Record each neutral item as it streams (redaction inside).
            if let Ok(j) = serde_json::to_string(&item)
                && let Err(reason) = record::try_append(run_id, &j)
            {
                diag::log("record_failed", &reason);
                // Best-effort: a record failure must not abort the
                // stream; the visible warning is emitted post-turn.
            }
        });
        if let Some(e) = write_err {
            return Err(e);
        }
        // Re-bind `turn` result for the match below.
        match turn {
            Ok(()) => {}
            Err(e) => {
                diag::log("turn_failed", &format!("run={run_id} {e}"));
                record_or_warn(
                    &out_tx,
                    run_id,
                    &format!(
                        r#"{{"event":"failed","error":{}}}"#,
                        serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"\"".into())
                    ),
                )?;
                send_msg(&out_tx, IpcMessage::error(id, &e.to_string()))?;
                return send_msg(&out_tx, IpcMessage::session_state(SessionState::Failed));
            }
        }
    }

    // Turn succeeded (failure already returned inside the streaming block).
    diag::log("session_complete", &format!("run={run_id}"));
    record_or_warn(out_tx, &run_id, r#"{"event":"complete"}"#)?;
    send_msg(out_tx, IpcMessage::session_state(SessionState::Ready))?;
    send_msg(
        out_tx,
        IpcMessage {
            kind: "turnComplete".into(),
            id,
            session_id: None,
            thread_id: None,
            payload: None,
        },
    )
}

fn run_turn_on_existing_thread(
    out_tx: &Sender<IpcMessage>,
    id: Option<u64>,
    thread_id: &str,
    prompt: &str,
) -> std::io::Result<()> {
    let run_id = format!(
        "run-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    diag::log(
        "history_turn_start",
        &format!("run={run_id} thread={thread_id}"),
    );
    send_msg(out_tx, IpcMessage::session_state(SessionState::Starting))?;
    record_or_warn(
        out_tx,
        &run_id,
        &format!(
            r#"{{"event":"resume","threadId":{},"prompt":{}}}"#,
            serde_json::to_string(thread_id).unwrap_or_else(|_| "\"\"".into()),
            serde_json::to_string(prompt).unwrap_or_else(|_| "\"\"".into())
        ),
    )?;

    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => {
            diag::log("history_turn_spawn_failed", &e.to_string());
            send_msg(out_tx, IpcMessage::error(id, &e.to_string()))?;
            return send_msg(out_tx, IpcMessage::session_state(SessionState::Failed));
        }
    };
    if let Err(e) = adapter.initialize() {
        diag::log("history_turn_handshake_failed", &e.to_string());
        send_msg(out_tx, IpcMessage::error(id, &e.to_string()))?;
        return send_msg(out_tx, IpcMessage::session_state(SessionState::Failed));
    }
    if let Err(e) = adapter.thread_resume(thread_id) {
        diag::log("history_turn_resume_failed", &e.to_string());
        send_msg(out_tx, IpcMessage::error(id, &e.to_string()))?;
        return send_msg(out_tx, IpcMessage::session_state(SessionState::Failed));
    }

    send_msg(out_tx, IpcMessage::session_state(SessionState::Running))?;
    let mut write_err: Option<std::io::Error> = None;
    {
        let run_id = &run_id;
        let out_tx = out_tx.clone();
        let turn = adapter.turn_start(thread_id, prompt, |item| {
            if write_err.is_some() {
                return;
            }
            if let Err(e) = send_msg(&out_tx, IpcMessage::agent_item(&item)) {
                write_err = Some(e);
                return;
            }
            if let Ok(j) = serde_json::to_string(&item)
                && let Err(reason) = record::try_append(run_id, &j)
            {
                diag::log("record_failed", &reason);
            }
        });
        if let Some(e) = write_err {
            return Err(e);
        }
        match turn {
            Ok(()) => {}
            Err(e) => {
                diag::log("history_turn_failed", &format!("run={run_id} {e}"));
                record_or_warn(
                    &out_tx,
                    run_id,
                    &format!(
                        r#"{{"event":"failed","error":{}}}"#,
                        serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"\"".into())
                    ),
                )?;
                send_msg(&out_tx, IpcMessage::error(id, &e.to_string()))?;
                return send_msg(&out_tx, IpcMessage::session_state(SessionState::Failed));
            }
        }
    }

    diag::log(
        "history_turn_complete",
        &format!("run={run_id} thread={thread_id}"),
    );
    record_or_warn(out_tx, &run_id, r#"{"event":"complete"}"#)?;
    send_msg(out_tx, IpcMessage::session_state(SessionState::Ready))?;
    send_msg(
        out_tx,
        IpcMessage {
            kind: "turnComplete".into(),
            id,
            session_id: None,
            thread_id: None,
            payload: None,
        },
    )
}

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let (out_tx, out_rx) = mpsc::channel::<IpcMessage>();
    let writer = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        write_outbound_messages(stdout, out_rx)
    });

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let msg: IpcMessage = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                // Fail loud, not silent (Eng premise 9).
                send_msg(
                    &out_tx,
                    IpcMessage::error(None, &format!("malformed JSONL: {e}")),
                )?;
                continue;
            }
        };

        match msg.kind.as_str() {
            "ping" => send_msg(&out_tx, IpcMessage::pong(msg.id))?,
            "shutdown" => {
                send_msg(&out_tx, IpcMessage::pong(msg.id))?;
                break;
            }
            "history/listThreads" => {
                let params = history_list_params(msg.payload.as_ref());
                run_history_list(&out_tx, msg.id, params)?;
            }
            "history/readThread" => {
                if let Some(thread_id) = history_read_thread_id(msg.payload.as_ref()) {
                    run_history_read(&out_tx, msg.id, &thread_id)?;
                } else {
                    send_msg(
                        &out_tx,
                        IpcMessage::error(msg.id, "history/readThread requires threadId"),
                    )?;
                }
            }
            "history/archiveThread" | "history/unarchiveThread" | "history/renameThread" => {
                let thread_id = msg
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("threadId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let name = msg
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str());
                if thread_id.is_empty() || (msg.kind == "history/renameThread" && name.is_none()) {
                    send_msg(
                        &out_tx,
                        IpcMessage::error(msg.id, "thread management requires threadId"),
                    )?;
                } else {
                    let action = match msg.kind.as_str() {
                        "history/archiveThread" => "archive",
                        "history/unarchiveThread" => "unarchive",
                        _ => "rename",
                    };
                    run_thread_management(&out_tx, msg.id, action, thread_id, name)?;
                }
            }
            "startSession" => {
                let cwd = msg
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("cwd"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let prompt = msg
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("prompt"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if cwd.is_empty() || prompt.is_empty() {
                    send_msg(
                        &out_tx,
                        IpcMessage::error(msg.id, "startSession requires cwd and prompt"),
                    )?;
                } else {
                    run_session(&out_tx, msg.id, cwd, prompt)?;
                }
            }
            "startTurn" => {
                if let Some(params) = start_turn_params(msg.payload.as_ref()) {
                    if msg.session_id.is_some() {
                        match start_turn_ack(&msg) {
                            Ok(ack) => send_msg(&out_tx, ack)?,
                            Err(e) => {
                                send_msg(&out_tx, IpcMessage::error(msg.id, &e))?;
                                continue;
                            }
                        }
                    }
                    run_turn_on_existing_thread(
                        &out_tx,
                        msg.id,
                        &params.thread_id,
                        &params.prompt,
                    )?;
                } else {
                    send_msg(
                        &out_tx,
                        IpcMessage::error(msg.id, "startTurn requires threadId and prompt"),
                    )?;
                }
            }
            other => send_msg(
                &out_tx,
                IpcMessage::error(msg.id, &format!("unknown kind: {other}")),
            )?,
        }
    }

    drop(out_tx);
    match writer.join() {
        Ok(result) => result?,
        Err(_) => {
            return Err(std::io::Error::other("stdout writer thread panicked"));
        }
    }
    Ok(())
}

// main.rs is the thin dispatch shell. Real coverage lives where the logic
// lives: the neutral-protocol guard + per-kind tests in ipc.rs, and the
// Codex→neutral translation regression net in codex.rs. Dispatch behavior
// (ping/pong/shutdown + startSession arg validation) is covered end-to-end
// by the integration check below and in CI — no placeholder unit test here.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn history_list_params_reads_optional_filters() {
        let p = json!({"cwd": "/tmp/project", "searchTerm": "fix", "cursor": "c2", "limit": 20});
        let params = history_list_params(Some(&p));
        assert_eq!(params.cwd.as_deref(), Some("/tmp/project"));
        assert_eq!(params.search_term.as_deref(), Some("fix"));
        assert_eq!(params.cursor.as_deref(), Some("c2"));
        assert_eq!(params.limit, Some(20));
    }

    #[test]
    fn history_read_thread_id_reads_required_id() {
        let p = json!({"threadId": "thread_1"});
        assert_eq!(
            history_read_thread_id(Some(&p)),
            Some("thread_1".to_string())
        );
    }

    #[test]
    fn start_turn_params_reads_thread_and_prompt() {
        let p = json!({"threadId": "thread_1", "prompt": "continue"});
        let params = start_turn_params(Some(&p)).unwrap();
        assert_eq!(params.thread_id, "thread_1");
        assert_eq!(params.prompt, "continue");
    }

    #[test]
    fn start_turn_request_builds_session_started_ack() {
        let msg = IpcMessage {
            kind: "startTurn".into(),
            id: Some(42),
            session_id: Some("session_1".into()),
            thread_id: Some("top_level_thread".into()),
            payload: Some(serde_json::json!({
                "threadId": "payload_thread",
                "prompt": "continue"
            })),
        };

        let ack = start_turn_ack(&msg).unwrap();

        assert_eq!(ack.kind, "turnAccepted");
        assert_eq!(ack.id, Some(42));
        assert_eq!(ack.session_id.as_deref(), Some("session_1"));
        assert_eq!(ack.thread_id.as_deref(), Some("top_level_thread"));
    }

    #[test]
    fn writer_returns_write_errors() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(ErrorKind::BrokenPipe, "closed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (out_tx, out_rx) = mpsc::channel::<IpcMessage>();
        out_tx.send(IpcMessage::pong(Some(1))).unwrap();
        drop(out_tx);

        let err = write_outbound_messages(FailingWriter, out_rx).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    }
}
