//! CodexAdapter — the ONLY place in AgentDeck that knows Codex exists.
//!
//! Eng D2: this module is the vendor-specific side of the neutral boundary.
//! It speaks the Codex app-server JSON-RPC protocol (verified in Step 0:
//! newline-delimited JSON, `jsonrpc` field omitted on the wire — see
//! protocol/SPIKE_FINDINGS.md) and translates Codex `ThreadItem`s into the
//! neutral `ipc::AgentItem`. Everything Codex-shaped is contained here; the
//! `ipc` module and the Swift app never reference Codex.
//!
//! Process ownership (Eng A1, second layer): the daemon spawns
//! `codex app-server` as a child in its own process group. When the daemon
//! exits, the app-server child is killed too — no orphan (the first layer,
//! Swift killing the daemon, is in DaemonClient.swift).
//!
//! Auth (Eng S1): we DO NOT touch / store / forward any token. The Codex CLI
//! uses the auth the user already established via `codex login`; spawning the
//! app-server inherits it. AgentDeck never sees a credential.
//!
//! Step 2 scope: initialize → thread/start → turn/start → translate the first
//! reasoning (`agentMessage`) item to a neutral AgentItem. Shell / file-edit
//! / approval / backpressure-coalescing land in Step 3+.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

use crate::ipc::{AgentItem, AgentItemKind, Lifecycle};

#[derive(Debug)]
pub enum CodexError {
    NotFound,
    SpawnFailed(String),
    Handshake(String),
    Protocol(String),
    Disconnected,
}

impl std::fmt::Display for CodexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodexError::NotFound => write!(f, "codex binary not found on PATH or common locations"),
            CodexError::SpawnFailed(m) => write!(f, "failed to spawn codex app-server: {m}"),
            CodexError::Handshake(m) => write!(f, "codex initialize handshake failed: {m}"),
            CodexError::Protocol(m) => write!(f, "codex protocol error: {m}"),
            CodexError::Disconnected => write!(f, "codex app-server disconnected (EOF)"),
        }
    }
}

/// Locate the `codex` binary. GUI-launched macOS apps have a different PATH
/// than the terminal (Codex C-path), so probe common install locations in
/// addition to PATH.
fn locate_codex() -> Option<String> {
    if let Ok(out) = Command::new("/usr/bin/which").arg("codex").output() {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                return Some(p);
            }
        }
    }
    for cand in [
        "/opt/homebrew/bin/codex",
        "/usr/local/bin/codex",
        "/usr/bin/codex",
    ] {
        if std::path::Path::new(cand).exists() {
            return Some(cand.to_string());
        }
    }
    None
}

pub struct CodexAdapter {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl CodexAdapter {
    /// Spawn `codex app-server` as an owned child. A1 second layer: the child
    /// is in the daemon's process group; killed on daemon exit (Drop impl).
    pub fn spawn() -> Result<Self, CodexError> {
        let codex = locate_codex().ok_or(CodexError::NotFound)?;
        let mut child = Command::new(codex)
            .arg("app-server")
            // stdio:// is the default transport (verified Step 0).
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            // A1 second layer + Codex #11: put the child in its OWN process
            // group. The `codex` CLI re-execs / forks the real app-server
            // (and MCP servers, sandbox helpers) as children; killing only
            // the CLI pid leaves orphans (observed in the Step 2 e2e test).
            // A fresh process group lets us signal the WHOLE tree on drop.
            .process_group(0)
            .spawn()
            .map_err(|e| CodexError::SpawnFailed(e.to_string()))?;

        let stdin = child.stdin.take().ok_or_else(|| {
            CodexError::SpawnFailed("no stdin pipe".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            CodexError::SpawnFailed("no stdout pipe".into())
        })?;

        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
            next_id: 1,
        })
    }

    fn send_request(&mut self, method: &str, params: Value) -> Result<u64, CodexError> {
        let id = self.next_id;
        self.next_id += 1;
        // Step 0 finding: jsonrpc field omitted on the wire; newline-framed.
        let req = json!({ "id": id, "method": method, "params": params });
        let mut line = serde_json::to_string(&req)
            .map_err(|e| CodexError::Protocol(e.to_string()))?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .map_err(|e| CodexError::Protocol(e.to_string()))?;
        self.stdin
            .flush()
            .map_err(|e| CodexError::Protocol(e.to_string()))?;
        Ok(id)
    }

    /// Read one newline-delimited JSON message (D7-confirmed framing).
    fn read_message(&mut self) -> Result<Value, CodexError> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| CodexError::Protocol(e.to_string()))?;
        if n == 0 {
            return Err(CodexError::Disconnected);
        }
        serde_json::from_str(line.trim())
            .map_err(|e| CodexError::Protocol(format!("malformed: {e}: {}", line.trim())))
    }

    /// Read messages until the response with `id` arrives, returning its
    /// `result`. Notifications seen along the way are passed to `on_notify`.
    fn await_response(
        &mut self,
        id: u64,
        mut on_notify: impl FnMut(&str, &Value),
    ) -> Result<Value, CodexError> {
        loop {
            let msg = self.read_message()?;
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = msg.get("error") {
                    return Err(CodexError::Protocol(err.to_string()));
                }
                return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
            }
            if let Some(method) = msg.get("method").and_then(Value::as_str) {
                let params = msg.get("params").cloned().unwrap_or(Value::Null);
                on_notify(method, &params);
            }
        }
    }

    /// initialize handshake (Eng S1: no token handling — inherits codex login).
    pub fn initialize(&mut self) -> Result<(), CodexError> {
        let id = self.send_request(
            "initialize",
            json!({ "clientInfo": { "name": "agentdeck", "version": "0.1.0" } }),
        )?;
        self.await_response(id, |_, _| {})
            .map_err(|e| CodexError::Handshake(e.to_string()))?;
        Ok(())
    }

    /// thread/start. `cwd` is the project directory (Eng D3: Swift validates
    /// existence/readability first; the daemon passes it as the authoritative
    /// final gate before app-server).
    ///
    /// Wire shape verified Step 2 (NOT assumed): the thread id is at
    /// `result.thread.id`, not `result.threadId`. The end-to-end test caught
    /// the wrong-path assumption — exactly why D7/C-protocol mandates real
    /// verification over assumption.
    pub fn thread_start(&mut self, cwd: &str) -> Result<String, CodexError> {
        let id = self.send_request("thread/start", json!({ "cwd": cwd }))?;
        let result = self.await_response(id, |_, _| {})?;
        result
            .get("thread")
            .and_then(|t| t.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| CodexError::Protocol("thread/start: no thread.id in result".into()))
    }

    /// turn/start with a text prompt. Emits neutral AgentItems via `emit` as
    /// item notifications arrive. Step 2 returns once turn/completed is seen.
    pub fn turn_start(
        &mut self,
        thread_id: &str,
        prompt: &str,
        mut emit: impl FnMut(AgentItem),
    ) -> Result<(), CodexError> {
        let id = self.send_request(
            "turn/start",
            json!({
                "threadId": thread_id,
                "input": [ { "type": "text", "text": prompt } ],
            }),
        )?;

        let mut done = false;
        while !done {
            let msg = self.read_message()?;
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = msg.get("error") {
                    return Err(CodexError::Protocol(err.to_string()));
                }
                // turn/start ack; keep reading for item notifications.
                continue;
            }
            let Some(method) = msg.get("method").and_then(Value::as_str) else {
                continue;
            };
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            match method {
                "turn/completed" => done = true,
                _ => {
                    if let Some(item) = translate(method, &params) {
                        emit(item);
                    }
                }
            }
        }
        Ok(())
    }
}

impl Drop for CodexAdapter {
    /// A1 second layer (Codex #11): the app-server child — AND everything it
    /// forked (real app-server, MCP servers, sandbox helpers) — must not
    /// outlive the daemon. We spawned the child into its own process group
    /// (pgid == child pid via `process_group(0)`), so SIGKILL to the
    /// negative pgid reaps the whole tree. `child.kill()` alone only hits
    /// the CLI wrapper and leaves orphans (the Step 2 e2e test proved this).
    fn drop(&mut self) {
        let pid = self.child.id() as i32;
        // Negative pid = "every process in the group whose pgid == pid".
        // Safe: we own this group; failure (already-dead) is ignored.
        unsafe {
            libc_kill(-pid, SIGKILL);
        }
        let _ = self.child.kill(); // belt-and-suspenders for the wrapper
        let _ = self.child.wait();
    }
}

// Minimal libc binding for group-kill. Avoids pulling the `libc` crate for
// one symbol; this is the only unsafe FFI in the daemon and it is contained
// here next to its sole caller.
const SIGKILL: i32 = 9;
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// Translate a Codex notification into a neutral AgentItem.
///
/// This is the ENTIRE Codex→neutral mapping surface. Unknown item types are
/// neutralized here (Eng E1 + Codex #19): they become `AgentItemKind::Raw`
/// with a short description — vendor JSON never crosses to Swift.
///
/// Step 2 maps the reasoning path (`item/agentMessage/delta`,
/// `item/started`, `item/completed` for agentMessage). Shell / file-edit
/// land in Step 3.
fn translate(method: &str, params: &Value) -> Option<AgentItem> {
    match method {
        "item/agentMessage/delta" => {
            let id = params.get("itemId").and_then(Value::as_str)?.to_string();
            let delta = params.get("delta").and_then(Value::as_str)?.to_string();
            Some(AgentItem {
                id,
                lifecycle: Lifecycle::Delta,
                kind: AgentItemKind::Reasoning { text: delta },
            })
        }
        "item/started" => {
            let item = params.get("item")?;
            let id = item.get("id").and_then(Value::as_str)?.to_string();
            match item.get("type").and_then(Value::as_str) {
                Some("agentMessage") => Some(AgentItem {
                    id,
                    lifecycle: Lifecycle::Started,
                    kind: AgentItemKind::Reasoning {
                        text: item
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    },
                }),
                // Unknown/other types neutralized (E1/#19): no vendor JSON
                // crosses to Swift; only a short description.
                Some(other) => Some(AgentItem {
                    id,
                    lifecycle: Lifecycle::Started,
                    kind: AgentItemKind::Raw {
                        description: format!("unsupported item type: {other}"),
                    },
                }),
                None => None,
            }
        }
        "item/completed" => {
            let item = params.get("item")?;
            let id = item.get("id").and_then(Value::as_str)?.to_string();
            match item.get("type").and_then(Value::as_str) {
                Some("agentMessage") => Some(AgentItem {
                    id,
                    lifecycle: Lifecycle::Completed,
                    kind: AgentItemKind::Reasoning {
                        text: item
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    },
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests drive the translate() surface with fixture-shaped Codex
    // notifications (Eng T1: fixture replay, no real Codex call). They are
    // the regression net for the neutral boundary.

    #[test]
    fn agent_message_delta_becomes_neutral_reasoning_delta() {
        let params = json!({
            "itemId": "item_1", "delta": "thinking...",
            "threadId": "t", "turnId": "u"
        });
        let item = translate("item/agentMessage/delta", &params).unwrap();
        assert_eq!(item.id, "item_1");
        assert!(matches!(item.lifecycle, Lifecycle::Delta));
        match item.kind {
            AgentItemKind::Reasoning { text } => assert_eq!(text, "thinking..."),
            _ => panic!("expected Reasoning"),
        }
    }

    #[test]
    fn unknown_item_type_is_neutralized_not_leaked() {
        // Codex #19 / E1: an unknown vendor item type must surface as Raw
        // with a description — never raw vendor JSON to Swift.
        let params = json!({
            "item": { "id": "x", "type": "someExperimentalCodexThing",
                      "secretVendorField": "should not cross" },
            "startedAtMs": 0, "threadId": "t", "turnId": "u"
        });
        let item = translate("item/started", &params).unwrap();
        match item.kind {
            AgentItemKind::Raw { description } => {
                assert!(description.contains("someExperimentalCodexThing"));
                assert!(!description.contains("should not cross"));
            }
            _ => panic!("expected Raw neutralization"),
        }
    }

    #[test]
    fn unrelated_notification_yields_no_item() {
        assert!(translate("turn/started", &json!({})).is_none());
        assert!(translate("thread/tokenUsage/updated", &json!({})).is_none());
    }
}
