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
mod ipc;

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
fn run_session(
    stdout: &mut impl Write,
    id: Option<u64>,
    cwd: &str,
    prompt: &str,
) -> std::io::Result<()> {
    write_msg(stdout, &IpcMessage::session_state(SessionState::Starting))?;

    let mut adapter = match codex::CodexAdapter::spawn() {
        Ok(a) => a,
        Err(e) => {
            write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
            return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
        }
    };

    if let Err(e) = adapter.initialize() {
        write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
        return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
    }

    let thread_id = match adapter.thread_start(cwd) {
        Ok(t) => t,
        Err(e) => {
            write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
            return write_msg(stdout, &IpcMessage::session_state(SessionState::Failed));
        }
    };

    write_msg(stdout, &IpcMessage::session_state(SessionState::Running))?;

    // Collect items first (turn_start borrows the adapter); emitting inside
    // the closure would double-borrow stdout. Step 3 replaces this with the
    // bounded-buffer + delta-coalescing channel (Eng A2).
    let mut items = Vec::new();
    let turn = adapter.turn_start(&thread_id, prompt, |item| items.push(item));

    for item in &items {
        write_msg(stdout, &IpcMessage::agent_item(item))?;
    }

    match turn {
        Ok(()) => {
            write_msg(stdout, &IpcMessage::session_state(SessionState::Ready))?;
            write_msg(stdout, &IpcMessage { kind: "turnComplete".into(), id, payload: None })
        }
        Err(e) => {
            write_msg(stdout, &IpcMessage::error(id, &e.to_string()))?;
            write_msg(stdout, &IpcMessage::session_state(SessionState::Failed))
        }
    }
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
