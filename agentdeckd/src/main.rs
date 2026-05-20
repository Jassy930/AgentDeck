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

const WRITER_STOP_KIND: &str = "__agentdeckd/writerStop";

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

#[derive(Debug)]
enum HubAction {
    Reply(IpcMessage),
    History(HistoryAction),
    SpawnTurn {
        id: Option<u64>,
        session_id: String,
        thread_id: Option<String>,
        cwd: Option<String>,
        prompt: String,
    },
    Shutdown,
}

#[derive(Debug)]
enum HistoryAction {
    ListThreads {
        id: Option<u64>,
        params: HistoryListParams,
    },
    ReadThread {
        id: Option<u64>,
        thread_id: String,
    },
    ArchiveThread {
        id: Option<u64>,
        thread_id: String,
    },
    UnarchiveThread {
        id: Option<u64>,
        thread_id: String,
    },
    RenameThread {
        id: Option<u64>,
        thread_id: String,
        name: String,
    },
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
        if msg.kind == WRITER_STOP_KIND {
            break;
        }
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

fn writer_stop_msg() -> IpcMessage {
    IpcMessage {
        kind: WRITER_STOP_KIND.into(),
        id: None,
        session_id: None,
        thread_id: None,
        payload: None,
    }
}

fn turn_accepted(id: Option<u64>, session_id: &str, thread_id: Option<&str>) -> IpcMessage {
    IpcMessage {
        kind: "turnAccepted".into(),
        id,
        session_id: Some(session_id.to_string()),
        thread_id: thread_id.map(str::to_string),
        payload: None,
    }
}

fn request_session_id(msg: &IpcMessage, fallback: String) -> String {
    msg.session_id
        .clone()
        .or_else(|| {
            msg.payload
                .as_ref()
                .and_then(|p| p.get("sessionId"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or(fallback)
}

fn classify_request(msg: &IpcMessage) -> Result<HubAction, String> {
    match msg.kind.as_str() {
        "ping" => Ok(HubAction::Reply(IpcMessage::pong(msg.id))),
        "shutdown" => Ok(HubAction::Shutdown),
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
                return Err("startSession requires cwd and prompt".into());
            }
            let fallback_session_id = msg
                .id
                .map(|id| format!("session_{id}"))
                .unwrap_or_else(|| "session".into());
            Ok(HubAction::SpawnTurn {
                id: msg.id,
                session_id: request_session_id(msg, fallback_session_id),
                thread_id: None,
                cwd: Some(cwd.to_string()),
                prompt: prompt.to_string(),
            })
        }
        "startTurn" => {
            let params = start_turn_params(msg.payload.as_ref())
                .ok_or_else(|| "startTurn requires threadId and prompt".to_string())?;
            let fallback_session_id = format!("session_{}", params.thread_id);
            Ok(HubAction::SpawnTurn {
                id: msg.id,
                session_id: request_session_id(msg, fallback_session_id),
                thread_id: Some(params.thread_id),
                cwd: None,
                prompt: params.prompt,
            })
        }
        "history/listThreads" => Ok(HubAction::History(HistoryAction::ListThreads {
            id: msg.id,
            params: history_list_params(msg.payload.as_ref()),
        })),
        "history/readThread" => match history_read_thread_id(msg.payload.as_ref()) {
            Some(thread_id) => Ok(HubAction::History(HistoryAction::ReadThread {
                id: msg.id,
                thread_id,
            })),
            None => Ok(HubAction::Reply(IpcMessage::error(
                msg.id,
                "history/readThread requires threadId",
            ))),
        },
        "history/archiveThread" => match history_management_thread_id(msg.payload.as_ref()) {
            Some(thread_id) => Ok(HubAction::History(HistoryAction::ArchiveThread {
                id: msg.id,
                thread_id,
            })),
            None => Ok(HubAction::Reply(IpcMessage::error(
                msg.id,
                "thread management requires threadId",
            ))),
        },
        "history/unarchiveThread" => match history_management_thread_id(msg.payload.as_ref()) {
            Some(thread_id) => Ok(HubAction::History(HistoryAction::UnarchiveThread {
                id: msg.id,
                thread_id,
            })),
            None => Ok(HubAction::Reply(IpcMessage::error(
                msg.id,
                "thread management requires threadId",
            ))),
        },
        "history/renameThread" => match history_rename_params(msg.payload.as_ref()) {
            Some((thread_id, name)) => Ok(HubAction::History(HistoryAction::RenameThread {
                id: msg.id,
                thread_id,
                name,
            })),
            None => Ok(HubAction::Reply(IpcMessage::error(
                msg.id,
                "thread management requires threadId",
            ))),
        },
        other => Ok(HubAction::Reply(IpcMessage::error(
            msg.id,
            &format!("unknown kind: {other}"),
        ))),
    }
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
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn history_management_thread_id(payload: Option<&serde_json::Value>) -> Option<String> {
    history_read_thread_id(payload)
}

fn history_rename_params(payload: Option<&serde_json::Value>) -> Option<(String, String)> {
    let payload = payload?;
    let thread_id = payload
        .get("threadId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?
        .to_string();
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?
        .to_string();
    Some((thread_id, name))
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

fn run_history_worker(out_tx: Sender<IpcMessage>, action: HistoryAction) -> std::io::Result<()> {
    match action {
        HistoryAction::ListThreads { id, params } => run_history_list(&out_tx, id, params),
        HistoryAction::ReadThread { id, thread_id } => run_history_read(&out_tx, id, &thread_id),
        HistoryAction::ArchiveThread { id, thread_id } => {
            run_thread_management(&out_tx, id, "archive", &thread_id, None)
        }
        HistoryAction::UnarchiveThread { id, thread_id } => {
            run_thread_management(&out_tx, id, "unarchive", &thread_id, None)
        }
        HistoryAction::RenameThread {
            id,
            thread_id,
            name,
        } => run_thread_management(&out_tx, id, "rename", &thread_id, Some(&name)),
    }
}

fn emit_session_event(
    tx: &Sender<IpcMessage>,
    session_id: &str,
    thread_id: Option<&str>,
    event: IpcMessage,
) -> std::io::Result<()> {
    send_msg(tx, IpcMessage::session_event(session_id, thread_id, event))
}

/// Handle a `startSession` request: drive a full Codex turn, streaming
/// neutral AgentItems and sessionState transitions over IPC.
///
/// Eng D9: the daemon is the sole state source. Every transition is emitted
/// so the Swift app mirrors, never guesses. Eng premise 9: failures surface
/// as a visible error + Failed state, never a silent hang.
/// Append a line to the run record. Eng E2: a write failure does NOT block
/// the session, but IS surfaced as a visible IPC warning — never silent.
fn record_or_warn(
    out_tx: &Sender<IpcMessage>,
    session_id: &str,
    thread_id: Option<&str>,
    run_id: &str,
    line: &str,
) -> std::io::Result<()> {
    if let Err(reason) = record::try_append(run_id, line) {
        diag::log("record_failed", &reason);
        emit_session_event(
            out_tx,
            session_id,
            thread_id,
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
    session_id: &str,
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
    emit_session_event(
        out_tx,
        session_id,
        None,
        IpcMessage::session_state(SessionState::Starting),
    )?;
    record_or_warn(
        out_tx,
        session_id,
        None,
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
            emit_session_event(
                out_tx,
                session_id,
                None,
                IpcMessage::error(id, &e.to_string()),
            )?;
            return emit_session_event(
                out_tx,
                session_id,
                None,
                IpcMessage::session_state(SessionState::Failed),
            );
        }
    };

    if let Err(e) = adapter.initialize() {
        diag::log("handshake_failed", &e.to_string());
        emit_session_event(
            out_tx,
            session_id,
            None,
            IpcMessage::error(id, &e.to_string()),
        )?;
        return emit_session_event(
            out_tx,
            session_id,
            None,
            IpcMessage::session_state(SessionState::Failed),
        );
    }

    let thread_id = match adapter.thread_start(cwd) {
        Ok(t) => t,
        Err(e) => {
            diag::log("thread_start_failed", &e.to_string());
            emit_session_event(
                out_tx,
                session_id,
                None,
                IpcMessage::error(id, &e.to_string()),
            )?;
            return emit_session_event(
                out_tx,
                session_id,
                None,
                IpcMessage::session_state(SessionState::Failed),
            );
        }
    };

    emit_session_event(
        out_tx,
        session_id,
        Some(&thread_id),
        IpcMessage::session_state(SessionState::Running),
    )?;

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
        let event_thread_id = thread_id.clone();
        let turn = adapter.turn_start(&thread_id, prompt, |item| {
            if write_err.is_some() {
                return;
            }
            if let Err(e) = emit_session_event(
                &out_tx,
                session_id,
                Some(&event_thread_id),
                IpcMessage::agent_item(&item),
            ) {
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
                    session_id,
                    Some(&thread_id),
                    run_id,
                    &format!(
                        r#"{{"event":"failed","error":{}}}"#,
                        serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"\"".into())
                    ),
                )?;
                emit_session_event(
                    &out_tx,
                    session_id,
                    Some(&thread_id),
                    IpcMessage::error(id, &e.to_string()),
                )?;
                return emit_session_event(
                    &out_tx,
                    session_id,
                    Some(&thread_id),
                    IpcMessage::session_state(SessionState::Failed),
                );
            }
        }
    }

    // Turn succeeded (failure already returned inside the streaming block).
    diag::log("session_complete", &format!("run={run_id}"));
    record_or_warn(
        out_tx,
        session_id,
        Some(&thread_id),
        &run_id,
        r#"{"event":"complete"}"#,
    )?;
    emit_session_event(
        out_tx,
        session_id,
        Some(&thread_id),
        IpcMessage::session_state(SessionState::Ready),
    )?;
    emit_session_event(
        out_tx,
        session_id,
        Some(&thread_id),
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
    session_id: &str,
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
    emit_session_event(
        out_tx,
        session_id,
        Some(thread_id),
        IpcMessage::session_state(SessionState::Starting),
    )?;
    record_or_warn(
        out_tx,
        session_id,
        Some(thread_id),
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
            emit_session_event(
                out_tx,
                session_id,
                Some(thread_id),
                IpcMessage::error(id, &e.to_string()),
            )?;
            return emit_session_event(
                out_tx,
                session_id,
                Some(thread_id),
                IpcMessage::session_state(SessionState::Failed),
            );
        }
    };
    if let Err(e) = adapter.initialize() {
        diag::log("history_turn_handshake_failed", &e.to_string());
        emit_session_event(
            out_tx,
            session_id,
            Some(thread_id),
            IpcMessage::error(id, &e.to_string()),
        )?;
        return emit_session_event(
            out_tx,
            session_id,
            Some(thread_id),
            IpcMessage::session_state(SessionState::Failed),
        );
    }
    if let Err(e) = adapter.thread_resume(thread_id) {
        diag::log("history_turn_resume_failed", &e.to_string());
        emit_session_event(
            out_tx,
            session_id,
            Some(thread_id),
            IpcMessage::error(id, &e.to_string()),
        )?;
        return emit_session_event(
            out_tx,
            session_id,
            Some(thread_id),
            IpcMessage::session_state(SessionState::Failed),
        );
    }

    emit_session_event(
        out_tx,
        session_id,
        Some(thread_id),
        IpcMessage::session_state(SessionState::Running),
    )?;
    let mut write_err: Option<std::io::Error> = None;
    {
        let run_id = &run_id;
        let out_tx = out_tx.clone();
        let turn = adapter.turn_start(thread_id, prompt, |item| {
            if write_err.is_some() {
                return;
            }
            if let Err(e) = emit_session_event(
                &out_tx,
                session_id,
                Some(thread_id),
                IpcMessage::agent_item(&item),
            ) {
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
                    session_id,
                    Some(thread_id),
                    run_id,
                    &format!(
                        r#"{{"event":"failed","error":{}}}"#,
                        serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"\"".into())
                    ),
                )?;
                emit_session_event(
                    &out_tx,
                    session_id,
                    Some(thread_id),
                    IpcMessage::error(id, &e.to_string()),
                )?;
                return emit_session_event(
                    &out_tx,
                    session_id,
                    Some(thread_id),
                    IpcMessage::session_state(SessionState::Failed),
                );
            }
        }
    }

    diag::log(
        "history_turn_complete",
        &format!("run={run_id} thread={thread_id}"),
    );
    record_or_warn(
        out_tx,
        session_id,
        Some(thread_id),
        &run_id,
        r#"{"event":"complete"}"#,
    )?;
    emit_session_event(
        out_tx,
        session_id,
        Some(thread_id),
        IpcMessage::session_state(SessionState::Ready),
    )?;
    emit_session_event(
        out_tx,
        session_id,
        Some(thread_id),
        IpcMessage {
            kind: "turnComplete".into(),
            id,
            session_id: None,
            thread_id: None,
            payload: None,
        },
    )
}

fn run_turn_worker(
    out_tx: Sender<IpcMessage>,
    id: Option<u64>,
    session_id: &str,
    thread_id: Option<&str>,
    cwd: Option<&str>,
    prompt: &str,
) -> std::io::Result<()> {
    if let Some(thread_id) = thread_id {
        return run_turn_on_existing_thread(&out_tx, id, session_id, thread_id, prompt);
    }
    if let Some(cwd) = cwd {
        return run_session(&out_tx, id, session_id, cwd, prompt);
    }
    Err(std::io::Error::new(
        ErrorKind::InvalidInput,
        "turn worker requires either threadId or cwd",
    ))
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

        match classify_request(&msg) {
            Ok(HubAction::Reply(reply)) => send_msg(&out_tx, reply)?,
            Ok(HubAction::Shutdown) => {
                send_msg(&out_tx, IpcMessage::pong(msg.id))?;
                send_msg(&out_tx, writer_stop_msg())?;
                break;
            }
            Ok(HubAction::History(action)) => {
                let worker_tx = out_tx.clone();
                std::thread::spawn(move || {
                    if let Err(err) = run_history_worker(worker_tx.clone(), action) {
                        let _ = worker_tx.send(IpcMessage::error(None, &err.to_string()));
                    }
                });
            }
            Ok(HubAction::SpawnTurn {
                id,
                session_id,
                thread_id,
                cwd,
                prompt,
            }) => {
                let ack = turn_accepted(id, &session_id, thread_id.as_deref());
                let _ = out_tx.send(ack);

                let worker_tx = out_tx.clone();
                std::thread::spawn(move || {
                    if let Err(err) = run_turn_worker(
                        worker_tx.clone(),
                        id,
                        &session_id,
                        thread_id.as_deref(),
                        cwd.as_deref(),
                        &prompt,
                    ) {
                        let _ = worker_tx.send(IpcMessage::session_event(
                            &session_id,
                            thread_id.as_deref(),
                            IpcMessage::error(None, &err.to_string()),
                        ));
                    }
                });
            }
            Err(e) => send_msg(&out_tx, IpcMessage::error(msg.id, &e))?,
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
    fn dispatch_start_turn_returns_ack_without_running_turn_inline() {
        let msg = IpcMessage {
            kind: "startTurn".into(),
            id: Some(7),
            session_id: Some("session_7".into()),
            thread_id: Some("thread_7".into()),
            payload: Some(serde_json::json!({
                "threadId": "thread_7",
                "prompt": "hello"
            })),
        };

        let action = classify_request(&msg).unwrap();

        assert!(matches!(action, HubAction::SpawnTurn { .. }));
    }

    #[test]
    fn dispatch_history_read_thread_returns_foreground_history_action() {
        let msg = IpcMessage {
            kind: "history/readThread".into(),
            id: Some(8),
            session_id: None,
            thread_id: None,
            payload: Some(serde_json::json!({
                "threadId": "thread_8"
            })),
        };

        let action = classify_request(&msg).unwrap();

        assert!(matches!(
            action,
            HubAction::History(HistoryAction::ReadThread {
                id: Some(8),
                ref thread_id,
            }) if thread_id == "thread_8"
        ));
    }

    #[test]
    fn dispatch_history_read_after_start_turn_does_not_wait_for_turn_completion() {
        let turn_msg = IpcMessage {
            kind: "startTurn".into(),
            id: Some(7),
            session_id: Some("session_7".into()),
            thread_id: Some("thread_7".into()),
            payload: Some(serde_json::json!({
                "threadId": "thread_7",
                "prompt": "hello"
            })),
        };
        let history_msg = IpcMessage {
            kind: "history/readThread".into(),
            id: Some(8),
            session_id: None,
            thread_id: None,
            payload: Some(serde_json::json!({
                "threadId": "thread_8"
            })),
        };

        let turn_action = classify_request(&turn_msg).unwrap();
        let history_action = classify_request(&history_msg).unwrap();

        assert!(matches!(turn_action, HubAction::SpawnTurn { .. }));
        assert!(matches!(
            history_action,
            HubAction::History(HistoryAction::ReadThread {
                id: Some(8),
                ref thread_id,
            }) if thread_id == "thread_8"
        ));
    }

    #[test]
    fn dispatch_history_read_thread_invalid_payload_returns_error_action() {
        let msg = IpcMessage {
            kind: "history/readThread".into(),
            id: Some(9),
            session_id: None,
            thread_id: None,
            payload: Some(serde_json::json!({})),
        };

        let action = classify_request(&msg).unwrap();

        assert!(matches!(
            action,
            HubAction::Reply(IpcMessage {
                kind,
                id: Some(9),
                ..
            }) if kind == "error"
        ));
    }

    #[test]
    fn turn_accepted_builds_session_started_ack() {
        let ack = turn_accepted(Some(42), "session_1", Some("top_level_thread"));

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
