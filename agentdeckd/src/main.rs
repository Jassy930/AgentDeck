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

use std::io::{BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use diag::DiagnosticEvent;
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

#[derive(Debug, PartialEq, Eq)]
struct DiagnosticsReportParams {
    run_id: Option<String>,
    limit: usize,
    since_seconds: Option<u64>,
}

fn write_msg(stdout: &mut impl Write, msg: &IpcMessage) -> std::io::Result<()> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    stdout.write_all(s.as_bytes())?;
    stdout.flush()
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
    stdout: &mut impl Write,
    id: Option<u64>,
    params: HistoryListParams,
) -> std::io::Result<()> {
    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => {
            diag::log("history_list_spawn_failed", &e.to_string());
            return write_msg(stdout, &IpcMessage::error(id, &e.to_string()));
        }
    };
    if let Err(e) = adapter.initialize() {
        diag::log("history_list_handshake_failed", &e.to_string());
        return write_msg(stdout, &IpcMessage::error(id, &e.to_string()));
    }
    match adapter.thread_list(
        params.cwd.as_deref(),
        params.search_term.as_deref(),
        params.cursor.as_deref(),
        params.limit,
    ) {
        Ok(list) => write_msg(
            stdout,
            &IpcMessage {
                kind: "historyThreads".into(),
                id,
                payload: Some(serde_json::to_value(list).expect("history list serializes")),
            },
        ),
        Err(e) => {
            diag::log("history_list_failed", &e.to_string());
            write_msg(stdout, &IpcMessage::error(id, &e.to_string()))
        }
    }
}

fn run_history_read(
    stdout: &mut impl Write,
    id: Option<u64>,
    thread_id: &str,
) -> std::io::Result<()> {
    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => {
            diag::log("history_read_spawn_failed", &e.to_string());
            return write_msg(stdout, &IpcMessage::error(id, &e.to_string()));
        }
    };
    if let Err(e) = adapter.initialize() {
        diag::log("history_read_handshake_failed", &e.to_string());
        return write_msg(stdout, &IpcMessage::error(id, &e.to_string()));
    }
    match adapter.thread_read(thread_id) {
        Ok(detail) => write_msg(
            stdout,
            &IpcMessage {
                kind: "historyThread".into(),
                id,
                payload: Some(serde_json::to_value(detail).expect("history detail serializes")),
            },
        ),
        Err(e) => {
            diag::log("history_read_failed", &e.to_string());
            write_msg(stdout, &IpcMessage::error(id, &e.to_string()))
        }
    }
}

fn run_thread_management(
    stdout: &mut impl Write,
    id: Option<u64>,
    action: &str,
    thread_id: &str,
    name: Option<&str>,
) -> std::io::Result<()> {
    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => return write_msg(stdout, &IpcMessage::error(id, &e.to_string())),
    };
    if let Err(e) = adapter.initialize() {
        return write_msg(stdout, &IpcMessage::error(id, &e.to_string()));
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
        Ok(()) => write_msg(
            stdout,
            &IpcMessage {
                kind: "historyThreadUpdated".into(),
                id,
                payload: Some(serde_json::json!({ "threadId": thread_id })),
            },
        ),
        Err(e) => write_msg(stdout, &IpcMessage::error(id, &e.to_string())),
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
fn record_or_warn(stdout: &mut impl Write, run_id: &str, line: &str) -> std::io::Result<()> {
    record_or_warn_with_writer(stdout, run_id, line, record::try_append)
}

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
                    payload: Some(serde_json::json!({
                        "message": format!("本次未留痕: {reason}")
                    })),
                },
            )?;
        }
    }
    Ok(())
}

fn record_item_or_warn_with_context(
    stdout: &mut impl Write,
    run_id: &str,
    thread_id: Option<&str>,
    request_id: Option<u64>,
    event_seq: &mut u64,
    line: &str,
    warning_emitted: &mut bool,
) -> std::io::Result<()> {
    if let Err(reason) = record::try_append(run_id, line) {
        *event_seq += 1;
        let mut event = DiagnosticEvent::new("record_failed")
            .level("warning")
            .code("record_write_failed")
            .run_id(run_id)
            .request_id_opt(request_id)
            .event_seq(*event_seq)
            .message("run record write failed")
            .detail(&reason);
        if let Some(thread_id) = thread_id {
            event = event.thread_id(thread_id);
        }
        diag::log_event(event);
        if !*warning_emitted {
            *warning_emitted = true;
            write_msg(
                stdout,
                &IpcMessage {
                    kind: "warning".into(),
                    id: None,
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

fn run_session(
    stdout: &mut impl Write,
    id: Option<u64>,
    cwd: &str,
    prompt: &str,
) -> std::io::Result<()> {
    // run_id: AgentDeck-generated (premise 5), not user input, so it is a
    // safe filename component (no path traversal).
    let run_id = new_run_id();
    let mut event_seq = 1;
    diag::log_event(
        DiagnosticEvent::new("session_start")
            .level("info")
            .code("session_start")
            .run_id(&run_id)
            .request_id_opt(id)
            .event_seq(event_seq)
            .message("session started")
            .detail(format!("cwd={cwd}")),
    );
    write_msg(stdout, &IpcMessage::session_state(SessionState::Starting))?;
    record_or_warn(
        stdout,
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
            write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
            return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
        }
    };

    if let Err(e) = adapter.initialize() {
        diag::log("handshake_failed", &e.to_string());
        write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
        return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
    }

    let thread_id = match adapter.thread_start(cwd) {
        Ok(t) => t,
        Err(e) => {
            diag::log("thread_start_failed", &e.to_string());
            write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
            return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
        }
    };

    write_msg(stdout, &IpcMessage::session_state(SessionState::Running))?;

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
    let mut record_warning_emitted = false;
    {
        let stdout = &mut *stdout;
        let run_id = &run_id;
        let thread_id_str = thread_id.as_str();
        let turn = adapter.turn_start(thread_id_str, prompt, |item| {
            if write_err.is_some() {
                return;
            }
            if let Err(e) = write_msg(stdout, &IpcMessage::agent_item(&item)) {
                write_err = Some(e);
                return;
            }
            // Record each neutral item as it streams (redaction inside).
            if let Ok(j) = serde_json::to_string(&item)
                && let Err(e) = record_item_or_warn_with_context(
                    stdout,
                    run_id,
                    Some(thread_id_str),
                    id,
                    &mut event_seq,
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
        // Re-bind `turn` result for the match below.
        match turn {
            Ok(()) => {}
            Err(e) => {
                event_seq += 1;
                diag::log_event(
                    DiagnosticEvent::new("turn_failed")
                        .level("error")
                        .code("turn_failed")
                        .run_id(run_id)
                        .thread_id(thread_id_str)
                        .request_id_opt(id)
                        .event_seq(event_seq)
                        .message("turn failed")
                        .detail(e.to_string()),
                );
                record_or_warn(
                    stdout,
                    run_id,
                    &format!(
                        r#"{{"event":"failed","error":{}}}"#,
                        serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"\"".into())
                    ),
                )?;
                write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
                return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
            }
        }
    }

    // Turn succeeded (failure already returned inside the streaming block).
    event_seq += 1;
    diag::log_event(
        DiagnosticEvent::new("session_complete")
            .level("info")
            .code("session_complete")
            .run_id(&run_id)
            .thread_id(&thread_id)
            .request_id_opt(id)
            .event_seq(event_seq)
            .message("session complete"),
    );
    record_or_warn(stdout, &run_id, r#"{"event":"complete"}"#)?;
    write_msg(stdout, &IpcMessage::session_state(SessionState::Ready))?;
    write_msg(
        stdout,
        &IpcMessage {
            kind: "turnComplete".into(),
            id,
            payload: None,
        },
    )
}

fn run_turn_on_existing_thread(
    stdout: &mut impl Write,
    id: Option<u64>,
    thread_id: &str,
    prompt: &str,
) -> std::io::Result<()> {
    let run_id = new_run_id();
    let mut event_seq = 1;
    diag::log_event(
        DiagnosticEvent::new("history_turn_start")
            .level("info")
            .code("history_turn_start")
            .run_id(&run_id)
            .thread_id(thread_id)
            .request_id_opt(id)
            .event_seq(event_seq)
            .message("history turn started"),
    );
    write_msg(stdout, &IpcMessage::session_state(SessionState::Starting))?;
    record_or_warn(
        stdout,
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
            write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
            return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
        }
    };
    if let Err(e) = adapter.initialize() {
        diag::log("history_turn_handshake_failed", &e.to_string());
        write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
        return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
    }
    if let Err(e) = adapter.thread_resume(thread_id) {
        diag::log("history_turn_resume_failed", &e.to_string());
        write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
        return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
    }

    write_msg(stdout, &IpcMessage::session_state(SessionState::Running))?;
    let mut write_err: Option<std::io::Error> = None;
    let mut record_warning_emitted = false;
    {
        let stdout = &mut *stdout;
        let run_id = &run_id;
        let turn = adapter.turn_start(thread_id, prompt, |item| {
            if write_err.is_some() {
                return;
            }
            if let Err(e) = write_msg(stdout, &IpcMessage::agent_item(&item)) {
                write_err = Some(e);
                return;
            }
            if let Ok(j) = serde_json::to_string(&item)
                && let Err(e) = record_item_or_warn_with_context(
                    stdout,
                    run_id,
                    Some(thread_id),
                    id,
                    &mut event_seq,
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
        match turn {
            Ok(()) => {}
            Err(e) => {
                event_seq += 1;
                diag::log_event(
                    DiagnosticEvent::new("history_turn_failed")
                        .level("error")
                        .code("turn_failed")
                        .run_id(run_id)
                        .thread_id(thread_id)
                        .request_id_opt(id)
                        .event_seq(event_seq)
                        .message("history turn failed")
                        .detail(e.to_string()),
                );
                record_or_warn(
                    stdout,
                    run_id,
                    &format!(
                        r#"{{"event":"failed","error":{}}}"#,
                        serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"\"".into())
                    ),
                )?;
                write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
                return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
            }
        }
    }

    event_seq += 1;
    diag::log_event(
        DiagnosticEvent::new("history_turn_complete")
            .level("info")
            .code("history_turn_complete")
            .run_id(&run_id)
            .thread_id(thread_id)
            .request_id_opt(id)
            .event_seq(event_seq)
            .message("history turn complete"),
    );
    record_or_warn(stdout, &run_id, r#"{"event":"complete"}"#)?;
    write_msg(stdout, &IpcMessage::session_state(SessionState::Ready))?;
    write_msg(
        stdout,
        &IpcMessage {
            kind: "turnComplete".into(),
            id,
            payload: None,
        },
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

fn run_logging_selfcheck(stdout: &mut impl Write, id: Option<u64>) -> std::io::Result<()> {
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

    write_msg(
        stdout,
        &IpcMessage {
            kind: "loggingSelfcheck".into(),
            id,
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
    records.sort_by(|a, b| b.0.cmp(&a.0));
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
    stdout: &mut impl Write,
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

    write_msg(
        stdout,
        &IpcMessage {
            kind: "diagnosticsReport".into(),
            id,
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

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let msg: IpcMessage = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                // Fail loud, not silent (Eng premise 9).
                write_msg(
                    &mut stdout,
                    &IpcMessage::error(None, &format!("malformed JSONL: {e}")),
                )?;
                continue;
            }
        };

        match msg.kind.as_str() {
            "ping" => write_msg(&mut stdout, &IpcMessage::pong(msg.id))?,
            "shutdown" => {
                write_msg(&mut stdout, &IpcMessage::pong(msg.id))?;
                break;
            }
            "selfcheck/logging" => {
                run_logging_selfcheck(&mut stdout, msg.id)?;
            }
            "diagnostics/report" => {
                run_diagnostics_report(&mut stdout, msg.id, msg.payload.as_ref())?;
            }
            "history/listThreads" => {
                let params = history_list_params(msg.payload.as_ref());
                run_history_list(&mut stdout, msg.id, params)?;
            }
            "history/readThread" => {
                if let Some(thread_id) = history_read_thread_id(msg.payload.as_ref()) {
                    run_history_read(&mut stdout, msg.id, &thread_id)?;
                } else {
                    write_msg(
                        &mut stdout,
                        &IpcMessage::error(msg.id, "history/readThread requires threadId"),
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
                    write_msg(
                        &mut stdout,
                        &IpcMessage::error(msg.id, "thread management requires threadId"),
                    )?;
                } else {
                    let action = match msg.kind.as_str() {
                        "history/archiveThread" => "archive",
                        "history/unarchiveThread" => "unarchive",
                        _ => "rename",
                    };
                    run_thread_management(&mut stdout, msg.id, action, thread_id, name)?;
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
                    write_msg(
                        &mut stdout,
                        &IpcMessage::error(msg.id, "startSession requires cwd and prompt"),
                    )?;
                } else {
                    run_session(&mut stdout, msg.id, cwd, prompt)?;
                }
            }
            "startTurn" => {
                if let Some(params) = start_turn_params(msg.payload.as_ref()) {
                    run_turn_on_existing_thread(
                        &mut stdout,
                        msg.id,
                        &params.thread_id,
                        &params.prompt,
                    )?;
                } else {
                    write_msg(
                        &mut stdout,
                        &IpcMessage::error(msg.id, "startTurn requires threadId and prompt"),
                    )?;
                }
            }
            other => write_msg(
                &mut stdout,
                &IpcMessage::error(msg.id, &format!("unknown kind: {other}")),
            )?,
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
}
