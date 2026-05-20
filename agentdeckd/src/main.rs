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
use std::time::{SystemTime, UNIX_EPOCH};

use diag::DiagnosticEvent;
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

#[derive(Debug, PartialEq, Eq)]
struct DiagnosticsReportParams {
    run_id: Option<String>,
    limit: usize,
    since_seconds: Option<u64>,
}

#[derive(Debug)]
enum HubAction {
    Reply(IpcMessage),
    History(HistoryAction),
    LoggingSelfcheck {
        id: Option<u64>,
    },
    DiagnosticsReport {
        id: Option<u64>,
        payload: Option<serde_json::Value>,
    },
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
        "selfcheck/logging" => Ok(HubAction::LoggingSelfcheck { id: msg.id }),
        "diagnostics/report" => Ok(HubAction::DiagnosticsReport {
            id: msg.id,
            payload: msg.payload.clone(),
        }),
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

fn diagnostics_report_params(payload: Option<&serde_json::Value>) -> DiagnosticsReportParams {
    let limit = payload
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_u64())
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(50)
        .clamp(1, 500);
    let since_seconds = payload
        .and_then(|p| p.get("sinceSeconds"))
        .and_then(|v| v.as_u64());
    let run_id = payload
        .and_then(|p| p.get("runId"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    DiagnosticsReportParams {
        run_id,
        limit,
        since_seconds,
    }
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

#[cfg(test)]
fn record_or_warn_with_writer(
    stdout: &mut impl Write,
    run_id: &str,
    line: &str,
    append: impl Fn(&str, &str) -> Result<(), String>,
) -> std::io::Result<()> {
    if let Err(reason) = append(run_id, line) {
        diag::log("record_failed", &reason);
        write_msg(
            stdout,
            &IpcMessage {
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

#[cfg(test)]
fn record_item_or_warn(
    stdout: &mut impl Write,
    run_id: &str,
    line: &str,
    warning_emitted: &mut bool,
    append: impl Fn(&str, &str) -> Result<(), String>,
) -> std::io::Result<()> {
    if let Err(reason) = append(run_id, line) {
        diag::log("record_failed", &reason);
        if !*warning_emitted {
            *warning_emitted = true;
            write_msg(
                stdout,
                &IpcMessage {
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
    }
    Ok(())
}

struct RecordWarningContext<'a> {
    out_tx: &'a Sender<IpcMessage>,
    session_id: &'a str,
    run_id: &'a str,
    thread_id: Option<&'a str>,
    request_id: Option<u64>,
}

fn record_item_or_warn_with_context(
    context: RecordWarningContext<'_>,
    event_seq: &mut u64,
    line: &str,
    warning_emitted: &mut bool,
) -> std::io::Result<()> {
    if let Err(reason) = record::try_append(context.run_id, line) {
        *event_seq += 1;
        let mut event = DiagnosticEvent::new("record_failed")
            .level("warning")
            .code("record_write_failed")
            .run_id(context.run_id)
            .request_id_opt(context.request_id)
            .event_seq(*event_seq)
            .message("run record write failed")
            .detail(&reason);
        if let Some(thread_id) = context.thread_id {
            event = event.thread_id(thread_id);
        }
        diag::log_event(event);
        if !*warning_emitted {
            *warning_emitted = true;
            emit_session_event(
                context.out_tx,
                context.session_id,
                context.thread_id,
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
    }
    Ok(())
}

fn new_run_id() -> String {
    static RUN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = RUN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("run-{}-{nanos}-{seq}", std::process::id())
}

enum TurnStart<'a> {
    NewSession { cwd: &'a str },
    ResumedThread { thread_id: &'a str },
}

struct TurnRunContext<'a> {
    id: Option<u64>,
    session_id: &'a str,
    prompt: &'a str,
    start: TurnStart<'a>,
}

impl<'a> TurnRunContext<'a> {
    fn initial_thread_id(&self) -> Option<&'a str> {
        match self.start {
            TurnStart::NewSession { .. } => None,
            TurnStart::ResumedThread { thread_id } => Some(thread_id),
        }
    }

    fn start_log_name(&self) -> &'static str {
        match self.start {
            TurnStart::NewSession { .. } => "session_start",
            TurnStart::ResumedThread { .. } => "history_turn_start",
        }
    }

    fn start_message(&self) -> &'static str {
        match self.start {
            TurnStart::NewSession { .. } => "session started",
            TurnStart::ResumedThread { .. } => "history turn started",
        }
    }

    fn start_detail(&self) -> Option<String> {
        match self.start {
            TurnStart::NewSession { cwd } => Some(format!("cwd={cwd}")),
            TurnStart::ResumedThread { .. } => None,
        }
    }

    fn start_record_line(&self) -> String {
        match self.start {
            TurnStart::NewSession { .. } => serde_json::json!({
                "event": "start",
                "prompt": self.prompt,
            })
            .to_string(),
            TurnStart::ResumedThread { thread_id } => serde_json::json!({
                "event": "resume",
                "threadId": thread_id,
                "prompt": self.prompt,
            })
            .to_string(),
        }
    }

    fn turn_failed_log_name(&self) -> &'static str {
        match self.start {
            TurnStart::NewSession { .. } => "turn_failed",
            TurnStart::ResumedThread { .. } => "history_turn_failed",
        }
    }

    fn turn_failed_message(&self) -> &'static str {
        match self.start {
            TurnStart::NewSession { .. } => "turn failed",
            TurnStart::ResumedThread { .. } => "history turn failed",
        }
    }

    fn turn_complete_log_name(&self) -> &'static str {
        match self.start {
            TurnStart::NewSession { .. } => "session_complete",
            TurnStart::ResumedThread { .. } => "history_turn_complete",
        }
    }

    fn turn_complete_message(&self) -> &'static str {
        match self.start {
            TurnStart::NewSession { .. } => "session complete",
            TurnStart::ResumedThread { .. } => "history turn complete",
        }
    }
}

fn begin_turn_run(
    out_tx: &Sender<IpcMessage>,
    context: &TurnRunContext<'_>,
    run_id: &str,
    event_seq: u64,
) -> std::io::Result<()> {
    let mut event = DiagnosticEvent::new(context.start_log_name())
        .level("info")
        .code(context.start_log_name())
        .run_id(run_id)
        .request_id_opt(context.id)
        .event_seq(event_seq)
        .message(context.start_message());
    if let Some(thread_id) = context.initial_thread_id() {
        event = event.thread_id(thread_id);
    }
    if let Some(detail) = context.start_detail() {
        event = event.detail(detail);
    }
    diag::log_event(event);

    emit_session_event(
        out_tx,
        context.session_id,
        context.initial_thread_id(),
        IpcMessage::session_state(SessionState::Starting),
    )?;
    record_or_warn(
        out_tx,
        context.session_id,
        context.initial_thread_id(),
        run_id,
        &context.start_record_line(),
    )
}

fn run_codex_turn(
    out_tx: &Sender<IpcMessage>,
    adapter: &mut codex::CodexAdapter,
    context: &TurnRunContext<'_>,
    run_id: &str,
    thread_id: &str,
    event_seq: &mut u64,
) -> std::io::Result<()> {
    emit_session_event(
        out_tx,
        context.session_id,
        Some(thread_id),
        IpcMessage::session_state(SessionState::Running),
    )?;

    let mut write_err: Option<std::io::Error> = None;
    let mut record_warning_emitted = false;
    {
        let out_tx = out_tx.clone();
        let event_thread_id = thread_id.to_string();
        let turn = adapter.turn_start(thread_id, context.prompt, |item| {
            if write_err.is_some() {
                return;
            }
            if let Err(e) = emit_session_event(
                &out_tx,
                context.session_id,
                Some(&event_thread_id),
                IpcMessage::agent_item(&item),
            ) {
                write_err = Some(e);
                return;
            }
            if let Ok(j) = serde_json::to_string(&item)
                && let Err(e) = record_item_or_warn_with_context(
                    RecordWarningContext {
                        out_tx: &out_tx,
                        session_id: context.session_id,
                        run_id,
                        thread_id: Some(&event_thread_id),
                        request_id: context.id,
                    },
                    event_seq,
                    &j,
                    &mut record_warning_emitted,
                )
            {
                write_err = Some(e);
            }
        });
        if let Some(e) = write_err {
            return Err(e);
        }
        if let Err(e) = turn {
            *event_seq += 1;
            diag::log_event(
                DiagnosticEvent::new(context.turn_failed_log_name())
                    .level("error")
                    .code("turn_failed")
                    .run_id(run_id)
                    .thread_id(thread_id)
                    .request_id_opt(context.id)
                    .event_seq(*event_seq)
                    .message(context.turn_failed_message())
                    .detail(e.to_string()),
            );
            record_or_warn(
                &out_tx,
                context.session_id,
                Some(thread_id),
                run_id,
                &serde_json::json!({
                    "event": "failed",
                    "error": e.to_string(),
                })
                .to_string(),
            )?;
            emit_session_event(
                &out_tx,
                context.session_id,
                Some(thread_id),
                IpcMessage::error(context.id, &e.to_string()),
            )?;
            return emit_session_event(
                &out_tx,
                context.session_id,
                Some(thread_id),
                IpcMessage::session_state(SessionState::Failed),
            );
        }
    }

    *event_seq += 1;
    diag::log_event(
        DiagnosticEvent::new(context.turn_complete_log_name())
            .level("info")
            .code(context.turn_complete_log_name())
            .run_id(run_id)
            .thread_id(thread_id)
            .request_id_opt(context.id)
            .event_seq(*event_seq)
            .message(context.turn_complete_message()),
    );
    record_or_warn(
        out_tx,
        context.session_id,
        Some(thread_id),
        run_id,
        r#"{"event":"complete"}"#,
    )?;
    emit_session_event(
        out_tx,
        context.session_id,
        Some(thread_id),
        IpcMessage::session_state(SessionState::Ready),
    )?;
    emit_session_event(
        out_tx,
        context.session_id,
        Some(thread_id),
        IpcMessage {
            kind: "turnComplete".into(),
            id: context.id,
            session_id: None,
            thread_id: None,
            payload: None,
        },
    )
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
    let context = TurnRunContext {
        id,
        session_id,
        prompt,
        start: TurnStart::NewSession { cwd },
    };
    let run_id = new_run_id();
    let mut event_seq = 1;
    begin_turn_run(out_tx, &context, &run_id, event_seq)?;

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

    run_codex_turn(
        out_tx,
        &mut adapter,
        &context,
        &run_id,
        &thread_id,
        &mut event_seq,
    )
}

fn run_turn_on_existing_thread(
    out_tx: &Sender<IpcMessage>,
    id: Option<u64>,
    session_id: &str,
    thread_id: &str,
    prompt: &str,
) -> std::io::Result<()> {
    let context = TurnRunContext {
        id,
        session_id,
        prompt,
        start: TurnStart::ResumedThread { thread_id },
    };
    let run_id = new_run_id();
    let mut event_seq = 1;
    begin_turn_run(out_tx, &context, &run_id, event_seq)?;

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

    run_codex_turn(
        out_tx,
        &mut adapter,
        &context,
        &run_id,
        thread_id,
        &mut event_seq,
    )
}

fn selfcheck_failure(
    code: &str,
    message: impl Into<String>,
    path_hint: impl Into<String>,
    suggested_next_check: impl Into<String>,
) -> serde_json::Value {
    serde_json::json!({
        "code": code,
        "message": message.into(),
        "pathHint": path_hint.into(),
        "suggestedNextCheck": suggested_next_check.into(),
    })
}

fn run_logging_selfcheck(out_tx: &Sender<IpcMessage>, id: Option<u64>) -> std::io::Result<()> {
    let probe_id = format!("probe-{}", new_run_id());
    let run_id = format!("selfcheck-{}", new_run_id());
    let secret_key = "sk-agentdeck-selfcheck";
    let secret_bearer = "Bearer agentdeck-selfcheck-token";

    diag::log_event(
        DiagnosticEvent::new("selfcheck_logging")
            .level("info")
            .code("selfcheck_logging")
            .run_id(&run_id)
            .event_seq(1)
            .message(format!("logging selfcheck {probe_id}"))
            .detail(format!("{probe_id} {secret_key} {secret_bearer}")),
    );

    let record_line = serde_json::json!({
        "event": "selfcheck",
        "probeId": probe_id,
        "token": secret_key,
        "authorization": secret_bearer,
    })
    .to_string();
    let record_write = record::try_append(&run_id, &record_line);

    let record_path = record::record_dir().map(|mut p| {
        p.push(format!("{run_id}.jsonl"));
        p
    });
    let diagnostic_path = diag::diagnostic_log_path();
    let record_path_hint = record_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "record path unavailable".into());
    let diagnostic_path_hint = diagnostic_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "diagnostic path unavailable".into());

    let record_content = record_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let diagnostic_content = diagnostic_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();

    let record_ok = record_write.is_ok() && record_content.contains(&probe_id);
    let diagnostic_ok = diagnostic_content.contains(&probe_id);
    let redaction_ok = !record_content.contains(secret_key)
        && !record_content.contains("agentdeck-selfcheck-token")
        && !diagnostic_content.contains(secret_key)
        && !diagnostic_content.contains("agentdeck-selfcheck-token");

    let mut failures = Vec::new();
    if let Err(reason) = record_write {
        failures.push(selfcheck_failure(
            "record_write_failed",
            reason,
            &record_path_hint,
            "检查 AGENTDECK_DATA_DIR 或用户 Application Support 目录权限",
        ));
    } else if !record_ok {
        failures.push(selfcheck_failure(
            "record_probe_missing",
            "run record probe was not readable after write",
            &record_path_hint,
            "检查 runs 目录是否可读且 runId 文件是否存在",
        ));
    }
    if !diagnostic_ok {
        failures.push(selfcheck_failure(
            "diagnostic_probe_missing",
            "diagnostic probe was not readable after write",
            &diagnostic_path_hint,
            "检查 diagnostic.log 是否可写可读",
        ));
    }
    if !redaction_ok {
        failures.push(selfcheck_failure(
            "redaction_failed",
            "selfcheck secret appeared in persisted logs",
            format!("{record_path_hint}; {diagnostic_path_hint}"),
            "停止分享日志并修复 record::redact",
        ));
    }

    send_msg(
        out_tx,
        IpcMessage {
            kind: "loggingSelfcheck".into(),
            id,
            session_id: None,
            thread_id: None,
            payload: Some(serde_json::json!({
                "recordOk": record_ok,
                "diagnosticOk": diagnostic_ok,
                "redactionOk": redaction_ok,
                "probeId": probe_id,
                "runId": run_id,
                "recordPathHint": record_path_hint,
                "diagnosticPathHint": diagnostic_path_hint,
                "failures": failures,
            })),
        },
    )
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn system_time_epoch_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_diagnostic_ts(ts: &serde_json::Value) -> Option<u64> {
    ts.as_str()
        .and_then(|s| s.strip_prefix("t="))
        .and_then(|s| s.parse::<u64>().ok())
}

fn suggested_next_check_for_failure(code: &str) -> &'static str {
    match code {
        "record_write_failed" | "record_probe_missing" => {
            "检查 runs 目录权限，必要时用 AGENTDECK_DATA_DIR 指向临时目录后重跑 --selfcheck"
        }
        "diagnostic_write_failed" | "diagnostic_probe_missing" | "diagnostic_parse_failed" => {
            "检查 diagnostic.log 是否可写可读，并确认每行都是 JSON"
        }
        "redaction_failed" => "停止分享日志，修复 record::redact 后重跑 --selfcheck",
        "turn_failed" => "按 runId 同时查看 diagnostic.log 与 runs/<runId>.jsonl 中的上下文",
        "daemon_spawn_failed" | "app_server_handshake_failed" => {
            "确认 agent 子进程可启动，并查看 diagnostic.log 中同一 requestId 的失败详情"
        }
        "adapter_unhandled_method" => {
            "保留 raw record，并按 method 扩展 adapter 映射或降级展示策略"
        }
        "ipc_malformed_jsonl" => "检查调用方写入 daemon stdin 的 JSONL 是否一行一个完整 JSON",
        _ => "按 runId、threadId、requestId 和 eventSeq 关联 diagnostic.log 与 runs/*.jsonl",
    }
}

fn diagnostics_failure_from_event(
    event: &serde_json::Value,
    path_hint: &str,
) -> Option<serde_json::Value> {
    let code = event.get("code").and_then(|v| v.as_str())?;
    let level = event
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("warning");
    let is_failure = matches!(level, "warning" | "error")
        || code.ends_with("_failed")
        || matches!(
            code,
            "record_probe_missing"
                | "diagnostic_probe_missing"
                | "redaction_failed"
                | "adapter_unhandled_method"
                | "ipc_malformed_jsonl"
        );
    if !is_failure {
        return None;
    }

    Some(serde_json::json!({
        "code": code,
        "severity": level,
        "message": event.get("message").and_then(|v| v.as_str()).unwrap_or(code),
        "pathHint": path_hint,
        "runId": event.get("runId").cloned().unwrap_or(serde_json::Value::Null),
        "threadId": event.get("threadId").cloned().unwrap_or(serde_json::Value::Null),
        "requestId": event.get("requestId").cloned().unwrap_or(serde_json::Value::Null),
        "eventSeq": event.get("eventSeq").cloned().unwrap_or(serde_json::Value::Null),
        "suggestedNextCheck": suggested_next_check_for_failure(code),
    }))
}

fn latest_run_records(params: &DiagnosticsReportParams) -> Vec<serde_json::Value> {
    let Some(dir) = record::record_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let cutoff = params
        .since_seconds
        .map(|seconds| now_epoch_secs().saturating_sub(seconds));

    let mut records = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let Some(run_id) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if let Some(filter) = params.run_id.as_deref()
            && run_id != filter
        {
            continue;
        }
        let metadata = entry.metadata().ok();
        let updated_at = metadata
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(system_time_epoch_secs)
            .unwrap_or(0);
        if let Some(cutoff) = cutoff
            && updated_at > 0
            && updated_at < cutoff
        {
            continue;
        }
        let line_count = std::fs::read_to_string(&path)
            .map(|content| content.lines().count())
            .unwrap_or(0);
        records.push((
            updated_at,
            serde_json::json!({
                "runId": run_id,
                "path": path.display().to_string(),
                "updatedAt": updated_at,
                "lineCount": line_count,
            }),
        ));
    }
    records.sort_by_key(|record| std::cmp::Reverse(record.0));
    records
        .into_iter()
        .take(params.limit)
        .map(|(_, value)| value)
        .collect()
}

fn diagnostic_failures(params: &DiagnosticsReportParams) -> Vec<serde_json::Value> {
    let Some(path) = diag::diagnostic_log_path() else {
        return Vec::new();
    };
    let path_hint = path.display().to_string();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let cutoff = params
        .since_seconds
        .map(|seconds| now_epoch_secs().saturating_sub(seconds));

    let mut failures = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            failures.push(serde_json::json!({
                "code": "diagnostic_parse_failed",
                "severity": "warning",
                "message": format!("diagnostic log line {} is not valid JSON", idx + 1),
                "pathHint": path_hint,
                "runId": serde_json::Value::Null,
                "threadId": serde_json::Value::Null,
                "requestId": serde_json::Value::Null,
                "eventSeq": serde_json::Value::Null,
                "suggestedNextCheck": suggested_next_check_for_failure("diagnostic_parse_failed"),
            }));
            continue;
        };
        if let Some(cutoff) = cutoff
            && let Some(ts) = parse_diagnostic_ts(&event["ts"])
            && ts < cutoff
        {
            continue;
        }
        if let Some(filter) = params.run_id.as_deref()
            && event.get("runId").and_then(|v| v.as_str()) != Some(filter)
        {
            continue;
        }
        if let Some(failure) = diagnostics_failure_from_event(&event, &path_hint) {
            failures.push(failure);
        }
    }
    failures.reverse();
    failures.truncate(params.limit);
    failures
}

fn run_diagnostics_report(
    out_tx: &Sender<IpcMessage>,
    id: Option<u64>,
    payload: Option<&serde_json::Value>,
) -> std::io::Result<()> {
    let params = diagnostics_report_params(payload);
    let data_dir = record::app_data_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "data dir unavailable".into());
    let runs_dir = record::record_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "runs dir unavailable".into());
    let diagnostic_log = diag::diagnostic_log_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "diagnostic log unavailable".into());

    send_msg(
        out_tx,
        IpcMessage {
            kind: "diagnosticsReport".into(),
            id,
            session_id: None,
            thread_id: None,
            payload: Some(serde_json::json!({
                "schemaVersion": 1,
                "dataDir": data_dir,
                "runsDir": runs_dir,
                "diagnosticLog": diagnostic_log,
                "latestRuns": latest_run_records(&params),
                "failures": diagnostic_failures(&params),
                "nextChecks": [
                    "运行 swift run AgentDeck -- --selfcheck",
                    "运行 swift run AgentDeck -- --diagnostics-report --json",
                    "按 runId 同时过滤 diagnostic.log 与 runs/*.jsonl"
                ],
            })),
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
            Ok(HubAction::LoggingSelfcheck { id }) => {
                run_logging_selfcheck(&out_tx, id)?;
            }
            Ok(HubAction::DiagnosticsReport { id, payload }) => {
                run_diagnostics_report(&out_tx, id, payload.as_ref())?;
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
    fn streaming_record_failure_emits_warning() {
        let mut out = Vec::new();
        let append = |_run_id: &str, _line: &str| Err("HOME not set".to_string());
        record_or_warn_with_writer(&mut out, "run-test", r#"{"event":"probe"}"#, append).unwrap();

        let wire = String::from_utf8(out).unwrap();
        assert!(wire.contains(r#""kind":"warning""#));
        assert!(wire.contains("本次未留痕"));
    }

    #[test]
    fn record_failure_warning_is_emitted_once_per_turn() {
        let mut out = Vec::new();
        let mut emitted = false;
        let append = |_run_id: &str, _line: &str| Err("permission denied".to_string());

        record_item_or_warn(&mut out, "run-test", "{}", &mut emitted, append).unwrap();
        record_item_or_warn(&mut out, "run-test", "{}", &mut emitted, append).unwrap();

        let wire = String::from_utf8(out).unwrap();
        assert_eq!(wire.matches(r#""kind":"warning""#).count(), 1);
    }

    #[test]
    fn new_run_id_is_unique_for_rapid_calls() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(ids.insert(new_run_id()));
        }
    }

    #[test]
    fn turn_runner_context_builds_start_records_for_new_and_resumed_turns() {
        let new_turn = TurnRunContext {
            id: Some(1),
            session_id: "session_new",
            prompt: "hello",
            start: TurnStart::NewSession { cwd: "/tmp/project" },
        };
        let resumed_turn = TurnRunContext {
            id: Some(2),
            session_id: "session_existing",
            prompt: "continue",
            start: TurnStart::ResumedThread {
                thread_id: "thread_1",
            },
        };

        assert_eq!(new_turn.initial_thread_id(), None);
        assert_eq!(new_turn.start_log_name(), "session_start");
        assert!(new_turn.start_record_line().contains(r#""event":"start""#));
        assert!(new_turn.start_record_line().contains(r#""prompt":"hello""#));

        assert_eq!(resumed_turn.initial_thread_id(), Some("thread_1"));
        assert_eq!(resumed_turn.start_log_name(), "history_turn_start");
        assert!(resumed_turn
            .start_record_line()
            .contains(r#""event":"resume""#));
        assert!(resumed_turn
            .start_record_line()
            .contains(r#""threadId":"thread_1""#));
        assert!(resumed_turn
            .start_record_line()
            .contains(r#""prompt":"continue""#));
    }

    #[test]
    fn diagnostics_failure_from_event_uses_stable_code() {
        let event = json!({
            "level": "warning",
            "code": "record_write_failed",
            "message": "run record write failed",
            "runId": "run_1",
            "threadId": "thread_1",
            "eventSeq": 12
        });

        let failure = diagnostics_failure_from_event(&event, "/tmp/run_1.jsonl").unwrap();

        assert_eq!(failure["code"], "record_write_failed");
        assert_eq!(failure["severity"], "warning");
        assert_eq!(failure["runId"], "run_1");
        assert_eq!(failure["threadId"], "thread_1");
        assert_eq!(failure["eventSeq"], 12);
        assert_eq!(failure["pathHint"], "/tmp/run_1.jsonl");
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
