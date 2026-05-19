//! agentdeckd — AgentDeck daemon.
//!
//! Step 1 scope: the minimal IPC loop. The Swift app spawns this binary as a
//! child process and speaks newline-delimited JSON (JSONL) over stdio. This
//! is the SAME framing the Codex app-server uses on its wire (verified in the
//! Step 0 protocol spike — single `\n` terminator, no Content-Length, see
//! protocol/SPIKE_FINDINGS.md), so the daemon can later bridge both stdio
//! streams with one framing strategy.
//!
//! The IPC protocol is the agent-neutral boundary (Eng D2). Every message on
//! this wire is a neutral `IpcMessage` — there is intentionally NO Codex
//! vocabulary here. A future CodexAdapter (and later Claude Code / SSH
//! adapters) translates vendor-specific events into these neutral messages
//! INSIDE the daemon; the Swift app never learns which agent is behind it.
//!
//!   Swift app  ──JSONL──▶  agentdeckd  ──(later)──▶  codex app-server child
//!              ◀─JSONL───              ◀─JSON-RPC──
//!
//! Step 1 only implements the Swift↔daemon half: a `ping` → `pong` round trip
//! plus a `shutdown` request, proving the framing, the neutral envelope, and
//! the process-lifecycle contract (the Swift app kills this child on exit;
//! Step 3+ adds the daemon→app-server process-group ownership from Eng A1).

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

/// A message on the agent-neutral IPC wire.
///
/// `kind` is the discriminator. v0.1 Step 1 kinds: `ping`, `pong`,
/// `shutdown`, `error`. Later steps add neutral `AgentItem` kinds
/// (reasoning / shell / fileEdit — Eng D4 per-kind structured schema) and
/// neutral `AgentActionRequest` / `AgentDecision` (Eng D8). No `codex*` kind
/// ever appears here — that is the verifiable form of Eng premise D2.
#[derive(Debug, Serialize, Deserialize)]
struct IpcMessage {
    /// Discriminator. Must never contain vendor names.
    kind: String,
    /// Correlates a response to its request. Echoed back unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    /// Kind-specific payload. Shape depends on `kind` (Eng D4).
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
}

impl IpcMessage {
    fn pong(id: Option<u64>) -> Self {
        Self { kind: "pong".to_string(), id, payload: None }
    }

    fn error(id: Option<u64>, message: &str) -> Self {
        Self {
            kind: "error".to_string(),
            id,
            payload: Some(serde_json::json!({ "message": message })),
        }
    }
}

/// Outcome of handling one inbound line.
enum Step {
    /// Write this reply, then keep reading.
    Reply(IpcMessage),
    /// Write this reply (if any), then exit cleanly.
    Shutdown(Option<IpcMessage>),
    /// Malformed input. Reply with an error, keep reading (fail loud, not
    /// silent — Eng premise 9 / front-of-mind reverse-of-silent philosophy).
    Malformed(IpcMessage),
}

/// Pure message handler. Kept side-effect-free so Step 1 can unit-test the
/// neutral protocol without spawning a process or touching stdio.
fn handle_line(line: &str) -> Step {
    let msg: IpcMessage = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(e) => {
            return Step::Malformed(IpcMessage::error(
                None,
                &format!("malformed JSONL: {e}"),
            ));
        }
    };

    match msg.kind.as_str() {
        "ping" => Step::Reply(IpcMessage::pong(msg.id)),
        "shutdown" => Step::Shutdown(Some(IpcMessage::pong(msg.id))),
        other => Step::Reply(IpcMessage::error(
            msg.id,
            &format!("unknown kind: {other}"),
        )),
    }
}

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // D7-confirmed framing: read line-by-line. One JSON value per line,
    // terminated by `\n`. No Content-Length header parsing needed.
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let (reply, should_exit) = match handle_line(&line) {
            Step::Reply(m) => (Some(m), false),
            Step::Malformed(m) => (Some(m), false),
            Step::Shutdown(m) => (m, true),
        };

        if let Some(m) = reply {
            let mut s = serde_json::to_string(&m)?;
            s.push('\n');
            stdout.write_all(s.as_bytes())?;
            stdout.flush()?;
        }

        if should_exit {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_yields_pong_with_same_id() {
        match handle_line(r#"{"kind":"ping","id":7}"#) {
            Step::Reply(m) => {
                assert_eq!(m.kind, "pong");
                assert_eq!(m.id, Some(7));
            }
            _ => panic!("expected Reply(pong)"),
        }
    }

    #[test]
    fn shutdown_exits_with_pong() {
        match handle_line(r#"{"kind":"shutdown","id":1}"#) {
            Step::Shutdown(Some(m)) => {
                assert_eq!(m.kind, "pong");
                assert_eq!(m.id, Some(1));
            }
            _ => panic!("expected Shutdown(pong)"),
        }
    }

    #[test]
    fn malformed_json_fails_loud_not_silent() {
        match handle_line("not json at all") {
            Step::Malformed(m) => {
                assert_eq!(m.kind, "error");
                let msg = m.payload.unwrap()["message"].as_str().unwrap().to_string();
                assert!(msg.contains("malformed JSONL"));
            }
            _ => panic!("expected Malformed(error) — must not silently drop"),
        }
    }

    #[test]
    fn unknown_kind_is_visible_error_not_silent_drop() {
        match handle_line(r#"{"kind":"frobnicate","id":3}"#) {
            Step::Reply(m) => {
                assert_eq!(m.kind, "error");
                assert_eq!(m.id, Some(3));
            }
            _ => panic!("expected Reply(error) for unknown kind"),
        }
    }

    /// The IPC wire must never carry vendor vocabulary (Eng D2). This is a
    /// guard test: if someone later adds a `codex`-named kind to the neutral
    /// protocol, this fails. The neutral boundary is a verifiable fact, not
    /// a convention.
    #[test]
    fn neutral_protocol_has_no_vendor_vocabulary() {
        let pong = serde_json::to_string(&IpcMessage::pong(Some(1))).unwrap();
        let err = serde_json::to_string(&IpcMessage::error(Some(1), "x")).unwrap();
        for wire in [&pong, &err] {
            let lower = wire.to_lowercase();
            assert!(!lower.contains("codex"), "vendor name leaked onto neutral IPC wire: {wire}");
            assert!(!lower.contains("openai"), "vendor name leaked onto neutral IPC wire: {wire}");
        }
    }
}
