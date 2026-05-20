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

use ipc::{IpcMessage, SessionState};

fn write_msg(stdout: &mut impl Write, msg: &IpcMessage) -> std::io::Result<()> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    stdout.write_all(s.as_bytes())?;
    stdout.flush()
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
    if let Err(reason) = record::try_append(run_id, line) {
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

fn run_session(
    stdout: &mut impl Write,
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
    {
        let stdout = &mut *stdout;
        let run_id = &run_id;
        let turn = adapter.turn_start(&thread_id, prompt, |item| {
            if write_err.is_some() {
                return;
            }
            if let Err(e) = write_msg(stdout, &IpcMessage::agent_item(&item)) {
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
    diag::log("session_complete", &format!("run={run_id}"));
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
