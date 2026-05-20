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
//! / approval land in Step 3+. Render backpressure is handled by the Swift UI
//! layer so the daemon can forward Codex deltas faithfully.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

use crate::ipc::{
    AgentItem, AgentItemKind, HistoryThreadDetail, HistoryThreadList, HistoryThreadSummary,
    Lifecycle,
};

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
    if let Ok(out) = Command::new("/usr/bin/which").arg("codex").output()
        && out.status.success()
    {
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !p.is_empty() {
            return Some(p);
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

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| CodexError::SpawnFailed("no stdin pipe".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CodexError::SpawnFailed("no stdout pipe".into()))?;

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
        let mut line =
            serde_json::to_string(&req).map_err(|e| CodexError::Protocol(e.to_string()))?;
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

    /// List persisted historical threads through Codex app-server and map
    /// them immediately into AgentDeck's neutral history shape.
    pub fn thread_list(
        &mut self,
        cwd: Option<&str>,
        search_term: Option<&str>,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<HistoryThreadList, CodexError> {
        let mut params = serde_json::Map::new();
        params.insert("archived".into(), Value::Bool(false));
        if let Some(cwd) = cwd {
            params.insert("cwd".into(), Value::String(cwd.to_string()));
        }
        if let Some(search_term) = search_term {
            params.insert("searchTerm".into(), Value::String(search_term.to_string()));
        }
        if let Some(cursor) = cursor {
            params.insert("cursor".into(), Value::String(cursor.to_string()));
        }
        if let Some(limit) = limit {
            params.insert(
                "limit".into(),
                Value::Number(serde_json::Number::from(limit)),
            );
        }

        let id = self.send_request("thread/list", Value::Object(params))?;
        let result = self.await_response(id, |_, _| {})?;
        thread_list_to_history(&result)
    }

    /// Read a persisted thread with its turns/items for replay in AgentDeck's
    /// neutral stream.
    pub fn thread_read(&mut self, thread_id: &str) -> Result<HistoryThreadDetail, CodexError> {
        let id = self.send_request(
            "thread/read",
            json!({ "threadId": thread_id, "includeTurns": true }),
        )?;
        let result = self.await_response(id, |_, _| {})?;
        thread_read_to_history_detail(&result)
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

fn value_label(value: &Value) -> String {
    if let Some(s) = value.as_str() {
        return s.to_string();
    }
    if let Some(s) = value.get("type").and_then(Value::as_str) {
        return s.to_string();
    }
    if let Some(s) = value.get("kind").and_then(Value::as_str) {
        return s.to_string();
    }
    if let Some(s) = value.get("custom").and_then(Value::as_str) {
        return s.to_string();
    }
    if value.is_null() {
        return String::new();
    }
    serde_json::to_string(value).unwrap_or_default()
}

fn thread_summary_from_value(value: &Value) -> Result<HistoryThreadSummary, CodexError> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| CodexError::Protocol("thread/list: thread missing id".into()))?
        .to_string();
    let cwd = value
        .get("cwd")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(HistoryThreadSummary {
        id,
        name: value.get("name").and_then(Value::as_str).map(str::to_string),
        preview: value
            .get("preview")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        cwd,
        created_at: value.get("createdAt").and_then(Value::as_i64).unwrap_or(0),
        updated_at: value.get("updatedAt").and_then(Value::as_i64).unwrap_or(0),
        status: value.get("status").map(value_label).unwrap_or_default(),
        model_provider: value
            .get("modelProvider")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        source: value.get("source").map(value_label).unwrap_or_default(),
    })
}

fn thread_list_to_history(value: &Value) -> Result<HistoryThreadList, CodexError> {
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| CodexError::Protocol("thread/list: result missing data[]".into()))?;
    let mut threads = Vec::with_capacity(data.len());
    for item in data {
        threads.push(thread_summary_from_value(item)?);
    }
    Ok(HistoryThreadList {
        threads,
        next_cursor: value
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn user_message_text(item: &Value) -> String {
    item.get("content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .filter_map(|part| {
                    if part.get("type").and_then(Value::as_str) == Some("text") {
                        part.get("text").and_then(Value::as_str)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_default()
}

fn thread_item_to_agent_item(item: &Value) -> Option<AgentItem> {
    let id = item.get("id").and_then(Value::as_str)?.to_string();
    let kind = if item.get("type").and_then(Value::as_str) == Some("userMessage") {
        AgentItemKind::User {
            text: user_message_text(item),
        }
    } else {
        item_to_kind(item)?
    };
    Some(AgentItem {
        id,
        lifecycle: Lifecycle::Completed,
        kind,
    })
}

fn thread_read_to_history_detail(value: &Value) -> Result<HistoryThreadDetail, CodexError> {
    let thread = value
        .get("thread")
        .ok_or_else(|| CodexError::Protocol("thread/read: result missing thread".into()))?;
    let mut items = Vec::new();
    if let Some(turns) = thread.get("turns").and_then(Value::as_array) {
        for turn in turns {
            if let Some(turn_items) = turn.get("items").and_then(Value::as_array) {
                for item in turn_items {
                    if let Some(agent_item) = thread_item_to_agent_item(item) {
                        items.push(agent_item);
                    }
                }
            }
        }
    }
    Ok(HistoryThreadDetail {
        thread: thread_summary_from_value(thread)?,
        items,
    })
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
/// This is the ENTIRE Codex→neutral mapping surface — the whole vendor
/// coupling of AgentDeck lives in this one function. Unknown item types are
/// neutralized here (Eng E1 + Codex #19): they become `AgentItemKind::Raw`
/// with a short description; vendor JSON never crosses to Swift.
///
/// Verified Codex semantics (Step 2 e2e, not assumed):
/// - `agentMessage` = the user-facing answer → neutral `Reasoning` (this is
///   what the design doc's "reasoning layer" actually renders).
/// - `reasoning` = the model's internal chain-of-thought → neutralized to
///   `Raw` (correct: internal thinking is NOT shown verbatim).
/// - `commandExecution` → neutral `Shell` (command / aggregatedOutput /
///   exitCode), per-kind structured (D4).
/// - `fileChange` → neutral `FileEdit` (path + diff from changes[0]).
///
/// Reasoning text from a ThreadItem of type=reasoning.
/// Schema: `{ id, content: string[], summary: string[] }` (verified from
/// official schema, not assumed — the empty-blank-row bug was caused by
/// reading `.text` which doesn't exist on this item type).
/// Prefer `summary` (user-readable digest); fall back to `content` (full
/// chain-of-thought); double-newline between entries to preserve paragraph
/// breaks the model emitted.
fn reasoning_text(item: &Value) -> String {
    fn join_strings(arr: Option<&Value>) -> String {
        arr.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n\n")
            })
            .unwrap_or_default()
    }
    let summary = join_strings(item.get("summary"));
    if !summary.is_empty() {
        return summary;
    }
    join_strings(item.get("content"))
}

fn item_to_kind(item: &Value) -> Option<AgentItemKind> {
        match item.get("type").and_then(Value::as_str)? {
        "userMessage" => Some(AgentItemKind::User {
            text: user_message_text(item),
        }),
        // PRIMARY answer the user reads — NOT collapsed (the UX bug the user
        // hit: this was mis-named reasoning and the UI folded it away).
        "agentMessage" => Some(AgentItemKind::Message {
            text: item
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        // The model's chain-of-thought — genuinely secondary, the UI
        // collapses THIS (D3). No longer neutralized to Raw: it is a real,
        // distinct neutral kind so the UI can offer it collapsed instead of
        // showing meaningless "unsupported item type" noise.
        //
        // Wire shape verified (NOT assumed): the schema is
        // `{id, content[], summary[]}`, NOT `{text}`. Taking `.text` gave an
        // empty string — that's why the expanded Reasoning row was blank.
        // Concatenate `summary` first (the user-readable digest), then
        // `content` (the full chain-of-thought); both arrays of strings.
        "reasoning" => Some(AgentItemKind::Reasoning {
            text: reasoning_text(item),
        }),
        "commandExecution" => Some(AgentItemKind::Shell {
            command: item
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            output: item
                .get("aggregatedOutput")
                .and_then(Value::as_str)
                .map(str::to_string),
            exit_code: item.get("exitCode").and_then(Value::as_i64),
        }),
        "fileChange" => {
            // changes[] is an array of FileUpdateChange {path, diff, kind}.
            // v0.1 surfaces the first change's path + diff; multi-file edits
            // are a Step 5 refinement (the neutral shape already allows it).
            let first = item
                .get("changes")
                .and_then(Value::as_array)
                .and_then(|a| a.first());
            Some(AgentItemKind::FileEdit {
                path: first
                    .and_then(|c| c.get("path"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                diff: first
                    .and_then(|c| c.get("diff"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        }
        // Internal chain-of-thought and every other vendor type: neutralized.
        // No vendor JSON crosses (Codex #19); fails loud as a visible Raw
        // item, never a silent drop (Eng E1 / premise 9).
        other => Some(AgentItemKind::Raw {
            description: format!("unsupported item type: {other}"),
        }),
    }
}

fn translate(method: &str, params: &Value) -> Option<AgentItem> {
    match method {
        "item/agentMessage/delta" => {
            let id = params.get("itemId").and_then(Value::as_str)?.to_string();
            let delta = params.get("delta").and_then(Value::as_str)?.to_string();
            // agentMessage delta = the streaming primary answer → Message
            // (not Reasoning — that was the mis-mapping behind the UX bug).
            Some(AgentItem {
                id,
                lifecycle: Lifecycle::Delta,
                kind: AgentItemKind::Message { text: delta },
            })
        }
        // Reasoning streams via dedicated channels (NOT item/agentMessage/
        // delta). Two notification methods cover it:
        //   - item/reasoning/textDelta       → full chain-of-thought stream
        //   - item/reasoning/summaryTextDelta → user-readable digest stream
        // Both surface as Reasoning deltas; the UI renders them under the
        // (auto-expanded during turn) "Reasoning" disclosure.
        "item/reasoning/textDelta" | "item/reasoning/summaryTextDelta" => {
            let id = params.get("itemId").and_then(Value::as_str)?.to_string();
            let delta = params.get("delta").and_then(Value::as_str)?.to_string();
            Some(AgentItem {
                id,
                lifecycle: Lifecycle::Delta,
                kind: AgentItemKind::Reasoning { text: delta },
            })
        }
        "item/commandExecution/outputDelta" => {
            // Streaming shell output. base64-encoded chunk; we surface it as
            // a Shell delta carrying the decoded chunk in `output`. The Swift
            // render layer batches consecutive deltas before invalidating UI.
            let id = params.get("itemId").and_then(Value::as_str)?.to_string();
            let chunk = params
                .get("deltaBase64")
                .and_then(Value::as_str)
                .and_then(decode_base64)
                .unwrap_or_default();
            Some(AgentItem {
                id,
                lifecycle: Lifecycle::Delta,
                kind: AgentItemKind::Shell {
                    command: String::new(),
                    output: Some(chunk),
                    exit_code: None,
                },
            })
        }
        "item/started" => {
            let item = params.get("item")?;
            let id = item.get("id").and_then(Value::as_str)?.to_string();
            Some(AgentItem {
                id,
                lifecycle: Lifecycle::Started,
                kind: item_to_kind(item)?,
            })
        }
        "item/completed" => {
            let item = params.get("item")?;
            let id = item.get("id").and_then(Value::as_str)?.to_string();
            Some(AgentItem {
                id,
                lifecycle: Lifecycle::Completed,
                kind: item_to_kind(item)?,
            })
        }
        _ => None,
    }
}

/// Minimal standard-base64 decoder (no external crate — boring-by-default,
/// one tiny function next to its sole caller). Returns the decoded UTF-8
/// string, lossily; non-base64 input yields None so the caller falls back.
fn decode_base64(s: &str) -> Option<String> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rev = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        let mut n = 0;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                break;
            }
            let v = rev[b as usize];
            if v == 255 {
                return None;
            }
            buf[i] = v;
            n += 1;
        }
        if n >= 2 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if n >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if n >= 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests drive the translate() surface with fixture-shaped Codex
    // notifications (Eng T1: fixture replay, no real Codex call). They are
    // the regression net for the neutral boundary.

    #[test]
    fn agent_message_delta_becomes_neutral_message_delta() {
        // agentMessage = the user-facing answer → Message (NOT Reasoning;
        // that mis-mapping is what hid the reply behind a collapsed group).
        let params = json!({
            "itemId": "item_1", "delta": "the answer",
            "threadId": "t", "turnId": "u"
        });
        let item = translate("item/agentMessage/delta", &params).unwrap();
        assert_eq!(item.id, "item_1");
        assert!(matches!(item.lifecycle, Lifecycle::Delta));
        match item.kind {
            AgentItemKind::Message { text } => assert_eq!(text, "the answer"),
            _ => panic!("expected Message"),
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

    // --- Fixture replay (Eng T1) ---
    //
    // These drive translate() with notifications shaped exactly per the
    // official app-server schema (fields verified from
    // protocol/codex_app_server_protocol.v2.schemas.json and the Step 2
    // e2e run — NOT invented). This is the regression net for the neutral
    // boundary: it runs in CI with no real Codex call. If a future codex
    // version changes a field, these fail and point at the exact mapping.

    #[test]
    fn fixture_agent_message_lifecycle_maps_to_message() {
        // agentMessage is the user-facing answer → Message across the full
        // started → delta* → completed lifecycle.
        let started = translate(
            "item/started",
            &json!({"item":{"id":"msg1","type":"agentMessage","text":""},
                    "startedAtMs":0,"threadId":"t","turnId":"u"}),
        )
        .unwrap();
        assert!(matches!(started.lifecycle, Lifecycle::Started));
        assert!(matches!(started.kind, AgentItemKind::Message { .. }));

        let delta = translate(
            "item/agentMessage/delta",
            &json!({"itemId":"msg1","delta":"Hello","threadId":"t","turnId":"u"}),
        )
        .unwrap();
        match delta.kind {
            AgentItemKind::Message { text } => assert_eq!(text, "Hello"),
            _ => panic!(),
        }

        let done = translate(
            "item/completed",
            &json!({"item":{"id":"msg1","type":"agentMessage","text":"Hello world"},
                    "threadId":"t","turnId":"u"}),
        )
        .unwrap();
        match done.kind {
            AgentItemKind::Message { text } => assert_eq!(text, "Hello world"),
            _ => panic!(),
        }
    }

    #[test]
    fn fixture_internal_reasoning_maps_to_reasoning_not_raw() {
        // The chain-of-thought item is `{content[], summary[]}` (verified
        // schema), not `{text}`. Prefer summary (digest) over content.
        let item = translate(
            "item/started",
            &json!({"item":{"id":"rs1","type":"reasoning",
                            "summary":["step 1: think"],
                            "content":["full thought trace"]},
                    "startedAtMs":0,"threadId":"t","turnId":"u"}),
        )
        .unwrap();
        match item.kind {
            AgentItemKind::Reasoning { text } => assert_eq!(text, "step 1: think"),
            _ => panic!("internal reasoning must map to Reasoning, not Raw"),
        }
    }

    #[test]
    fn fixture_reasoning_text_delta_maps_to_reasoning_delta() {
        // Reasoning streams via dedicated channels, NOT item/agentMessage/
        // delta. textDelta is the full chain-of-thought stream.
        let item = translate(
            "item/reasoning/textDelta",
            &json!({"itemId":"rs1","delta":"step 1","contentIndex":0,
                    "threadId":"t","turnId":"u"}),
        )
        .unwrap();
        assert_eq!(item.id, "rs1");
        assert!(matches!(item.lifecycle, Lifecycle::Delta));
        match item.kind {
            AgentItemKind::Reasoning { text } => assert_eq!(text, "step 1"),
            _ => panic!("expected Reasoning delta"),
        }
    }

    #[test]
    fn fixture_reasoning_summary_text_delta_maps_to_reasoning_delta() {
        // summaryTextDelta is the user-readable digest stream — same neutral
        // shape (Reasoning), the UI doesn't need to distinguish.
        let item = translate(
            "item/reasoning/summaryTextDelta",
            &json!({"itemId":"rs2","delta":"digest","summaryIndex":0,
                    "threadId":"t","turnId":"u"}),
        )
        .unwrap();
        match item.kind {
            AgentItemKind::Reasoning { text } => assert_eq!(text, "digest"),
            _ => panic!("expected Reasoning delta"),
        }
    }

    #[test]
    fn fixture_command_execution_maps_to_shell_per_kind() {
        // commandExecution item shape from the official schema:
        // command / aggregatedOutput / exitCode / cwd / status.
        let item = translate(
            "item/completed",
            &json!({"item":{
                "id":"cmd1","type":"commandExecution","status":"completed",
                "command":"echo hello","aggregatedOutput":"hello\n",
                "exitCode":0,"cwd":"/tmp","commandActions":[]
            },"threadId":"t","turnId":"u"}),
        )
        .unwrap();
        match item.kind {
            AgentItemKind::Shell {
                command,
                output,
                exit_code,
            } => {
                assert_eq!(command, "echo hello");
                assert_eq!(output.as_deref(), Some("hello\n"));
                assert_eq!(exit_code, Some(0));
            }
            _ => panic!("expected per-kind Shell"),
        }
    }

    #[test]
    fn fixture_file_change_maps_to_file_edit() {
        // fileChange item: changes[] of FileUpdateChange {path,diff,kind}.
        let item = translate(
            "item/completed",
            &json!({"item":{
                "id":"fc1","type":"fileChange","status":"applied",
                "changes":[{"path":"src/main.rs",
                            "diff":"@@ -1 +1 @@\n-old\n+new","kind":"modified"}]
            },"threadId":"t","turnId":"u"}),
        )
        .unwrap();
        match item.kind {
            AgentItemKind::FileEdit { path, diff } => {
                assert_eq!(path, "src/main.rs");
                assert!(diff.unwrap().contains("+new"));
            }
            _ => panic!("expected FileEdit"),
        }
    }

    // (Superseded by fixture_internal_reasoning_maps_to_reasoning_not_raw:
    // internal reasoning is now a real collapsed Reasoning kind, not Raw.
    // Genuinely unknown types still neutralize to Raw — covered by
    // unknown_item_type_is_neutralized_not_leaked.)

    #[test]
    fn base64_decoder_roundtrips_shell_output_delta() {
        // item/commandExecution/outputDelta carries base64. "hello" =>
        // "aGVsbG8=".
        let item = translate(
            "item/commandExecution/outputDelta",
            &json!({"itemId":"cmd1","deltaBase64":"aGVsbG8=",
                    "stream":"stdout","processId":1,"capReached":false}),
        )
        .unwrap();
        match item.kind {
            AgentItemKind::Shell { output, .. } => {
                assert_eq!(output.as_deref(), Some("hello"));
            }
            _ => panic!("expected Shell delta"),
        }
    }

    #[test]
    fn thread_list_response_maps_to_history_summaries() {
        let value = json!({
            "data": [{
                "id": "thread_1",
                "name": "Fix tests",
                "preview": "please fix tests",
                "cwd": "/tmp/project",
                "createdAt": 10,
                "updatedAt": 20,
                "status": "ready",
                "modelProvider": "openai",
                "source": {"kind": "cli"},
                "cliVersion": "0.0.0",
                "ephemeral": false,
                "sessionId": "session_1",
                "turns": []
            }],
            "nextCursor": "cursor_2"
        });
        let list = thread_list_to_history(&value).unwrap();
        assert_eq!(list.threads[0].id, "thread_1");
        assert_eq!(list.threads[0].cwd, "/tmp/project");
        assert_eq!(list.threads[0].source, "cli");
        assert_eq!(list.next_cursor.as_deref(), Some("cursor_2"));
    }

    #[test]
    fn thread_read_response_maps_turn_items_to_history_detail() {
        let value = json!({
            "thread": {
                "id": "thread_1",
                "name": "Fix tests",
                "preview": "please fix tests",
                "cwd": "/tmp/project",
                "createdAt": 10,
                "updatedAt": 20,
                "status": {"type": "idle"},
                "modelProvider": "openai",
                "source": "cli",
                "cliVersion": "0.0.0",
                "ephemeral": false,
                "sessionId": "session_1",
                "turns": [{
                    "id": "turn_1",
                    "status": "completed",
                    "items": [
                        {"id": "u1", "type": "userMessage", "content": [{"type": "text", "text": "please fix tests"}]},
                        {"id": "a1", "type": "agentMessage", "text": "done"},
                        {"id": "cmd1", "type": "commandExecution", "status": "completed", "command": "swift test", "aggregatedOutput": "ok\\n", "exitCode": 0, "cwd": "/tmp/project", "commandActions": []}
                    ]
                }]
            }
        });
        let detail = thread_read_to_history_detail(&value).unwrap();
        assert_eq!(detail.thread.id, "thread_1");
        assert_eq!(detail.items.len(), 3);
        match &detail.items[0].kind {
            AgentItemKind::User { text } => assert_eq!(text, "please fix tests"),
            _ => panic!("expected user item"),
        }
        match &detail.items[1].kind {
            AgentItemKind::Message { text } => assert_eq!(text, "done"),
            _ => panic!("expected message item"),
        }
    }
}
