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

pub mod adapter;
pub mod capabilities;
pub mod translate;

pub use adapter::CodexAdapter;

// ── v1 implementation (gated) ───────────────────────────────────────────────
// The original `CodexAdapter` struct + `impl` + Drop + helpers below are kept
// as source material for Task 3B (which rewrites adapter.rs against the new
// `Agent` trait). They reference v1 IPC types (Lifecycle, AgentItemKind, …)
// that were deleted in T1.6, so they CANNOT compile in the v2 lib build.
//
// Solution per Phase 3 delta spec: gate the entire v1 body behind the
// `daemon-bin` feature. The lib build (no features) sees only the
// `pub mod adapter / capabilities / translate` declarations above —
// Task 3A's new code lives in `capabilities.rs` + `translate.rs`.
//
// Task 3B will incrementally migrate this body into `adapter.rs`; Task 3C
// finally deletes the gated block and drops the `daemon-bin` feature.
#[cfg(feature = "daemon-bin")]
mod v1_legacy {

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::ipc::{
    ActionDecision, ActionRequest, AgentItem, AgentItemKind, AgentReference, FileEditChange,
    HistoryThreadDetail, HistoryThreadList, HistoryThreadSummary, HookFragment, Lifecycle,
    ToolAction,
};
use crate::record::redact;

const CODEX_STDERR_TAIL_LINES: usize = 40;

#[derive(Debug)]
pub enum CodexError {
    NotFound,
    SpawnFailed(String),
    Handshake(String),
    Protocol(String),
    Disconnected(Option<String>),
}

impl std::fmt::Display for CodexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodexError::NotFound => write!(f, "codex binary not found on PATH or common locations"),
            CodexError::SpawnFailed(m) => write!(f, "failed to spawn codex app-server: {m}"),
            CodexError::Handshake(m) => write!(f, "codex initialize handshake failed: {m}"),
            CodexError::Protocol(m) => write!(f, "codex protocol error: {m}"),
            CodexError::Disconnected(Some(stderr)) if !stderr.is_empty() => write!(
                f,
                "codex app-server disconnected (EOF); recent stderr:\n{stderr}"
            ),
            CodexError::Disconnected(_) => write!(f, "codex app-server disconnected (EOF)"),
        }
    }
}

#[derive(Clone, Debug)]
struct StderrTail {
    lines: Arc<Mutex<VecDeque<String>>>,
    max_lines: usize,
}

impl StderrTail {
    fn new(max_lines: usize) -> Self {
        Self {
            lines: Arc::new(Mutex::new(VecDeque::new())),
            max_lines: max_lines.max(1),
        }
    }

    fn push(&self, line: impl AsRef<str>) {
        let Ok(mut lines) = self.lines.lock() else {
            return;
        };
        while lines.len() >= self.max_lines {
            lines.pop_front();
        }
        lines.push_back(redact(line.as_ref()));
    }

    fn summary(&self) -> Option<String> {
        let Ok(lines) = self.lines.lock() else {
            return None;
        };
        if lines.is_empty() {
            None
        } else {
            Some(lines.iter().cloned().collect::<Vec<_>>().join("\n"))
        }
    }
}

fn capture_stderr_tail(stderr: ChildStderr, tail: StderrTail) {
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(line) => tail.push(line),
                Err(_) => break,
            }
        }
    });
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

fn codex_child_path_env(base: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for path in [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ] {
        parts.push(path.into());
    }
    if let Some(base) = base {
        for path in base.split(':').filter(|p| !p.is_empty()) {
            if !parts.iter().any(|existing| existing == path) {
                parts.push(path.into());
            }
        }
    }
    parts.join(":")
}

pub struct CodexAdapter {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    stderr_tail: StderrTail,
    next_id: u64,
}

impl CodexAdapter {
    /// Spawn `codex app-server` as an owned child. A1 second layer: the child
    /// is in the daemon's process group; killed on daemon exit (Drop impl).
    pub fn spawn() -> Result<Self, CodexError> {
        let codex = locate_codex().ok_or(CodexError::NotFound)?;
        let child_path = codex_child_path_env(std::env::var("PATH").ok().as_deref());
        let mut child = Command::new(codex)
            .arg("app-server")
            // stdio:// is the default transport (verified Step 0).
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PATH", child_path)
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
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| CodexError::SpawnFailed("no stderr pipe".into()))?;
        let stderr_tail = StderrTail::new(CODEX_STDERR_TAIL_LINES);
        capture_stderr_tail(stderr, stderr_tail.clone());

        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
            stderr_tail,
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

    fn send_response(&mut self, id: u64, result: Value) -> Result<(), CodexError> {
        let response = json!({ "id": id, "result": result });
        let mut line =
            serde_json::to_string(&response).map_err(|e| CodexError::Protocol(e.to_string()))?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .map_err(|e| CodexError::Protocol(e.to_string()))?;
        self.stdin
            .flush()
            .map_err(|e| CodexError::Protocol(e.to_string()))
    }

    /// Read one newline-delimited JSON message (D7-confirmed framing).
    fn read_message(&mut self) -> Result<Value, CodexError> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| CodexError::Protocol(e.to_string()))?;
        if n == 0 {
            return Err(CodexError::Disconnected(self.stderr_tail.summary()));
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

    /// Resume an existing persisted thread so the next turn uses its model-
    /// visible history, not a newly-created thread.
    pub fn thread_resume(&mut self, thread_id: &str) -> Result<HistoryThreadSummary, CodexError> {
        let id = self.send_request("thread/resume", json!({ "threadId": thread_id }))?;
        let result = self.await_response(id, |_, _| {})?;
        thread_resume_to_history_summary(&result)
    }

    pub fn thread_archive(&mut self, thread_id: &str) -> Result<(), CodexError> {
        let id = self.send_request("thread/archive", json!({ "threadId": thread_id }))?;
        self.await_response(id, |_, _| {})?;
        Ok(())
    }

    pub fn thread_unarchive(&mut self, thread_id: &str) -> Result<(), CodexError> {
        let id = self.send_request("thread/unarchive", json!({ "threadId": thread_id }))?;
        self.await_response(id, |_, _| {})?;
        Ok(())
    }

    pub fn thread_set_name(&mut self, thread_id: &str, name: &str) -> Result<(), CodexError> {
        let id = self.send_request(
            "thread/name/set",
            json!({ "threadId": thread_id, "name": name }),
        )?;
        self.await_response(id, |_, _| {})?;
        Ok(())
    }

    /// turn/start with a text prompt. Emits neutral AgentItems via `emit` as
    /// item notifications arrive. Step 2 returns once turn/completed is seen.
    pub fn turn_start(
        &mut self,
        thread_id: &str,
        prompt: &str,
        mut emit: impl FnMut(AgentItem),
        mut request_decision: impl FnMut(ActionRequest) -> Result<ActionDecision, CodexError>,
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
            if let Some(request_id) = msg.get("id").and_then(Value::as_u64)
                && let Some(action_request) =
                    approval_request_to_action(request_id, method, &params)
            {
                let decision = request_decision(action_request)?;
                let result = approval_response_for_decision(method, &params, &decision.decision)?;
                self.send_response(request_id, result)?;
                continue;
            }
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

fn approval_request_to_action(
    request_id: u64,
    method: &str,
    params: &Value,
) -> Option<ActionRequest> {
    let item_id = params.get("itemId").and_then(Value::as_str)?.to_string();
    let approval_id = params
        .get("approvalId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let reason = params.get("reason").and_then(Value::as_str).unwrap_or("");
    let cwd = params.get("cwd").and_then(Value::as_str).unwrap_or("");
    match method {
        "item/commandExecution/requestApproval" => {
            let command = params.get("command").and_then(Value::as_str).unwrap_or("");
            Some(ActionRequest {
                request_id,
                item_id,
                approval_id,
                action_kind: "runCommand".into(),
                title: "Run command".into(),
                detail: approval_detail([
                    ("Command", command),
                    ("Directory", cwd),
                    ("Reason", reason),
                ]),
            })
        }
        "item/fileChange/requestApproval" => {
            let grant_root = params
                .get("grantRoot")
                .and_then(Value::as_str)
                .unwrap_or("");
            Some(ActionRequest {
                request_id,
                item_id,
                approval_id,
                action_kind: "applyChanges".into(),
                title: "Apply file changes".into(),
                detail: approval_detail([
                    ("Path", grant_root),
                    ("Reason", reason),
                    ("Directory", cwd),
                ]),
            })
        }
        "item/permissions/requestApproval" => {
            let permissions = params
                .get("permissions")
                .and_then(|v| serde_json::to_string(v).ok())
                .unwrap_or_default();
            Some(ActionRequest {
                request_id,
                item_id,
                approval_id,
                action_kind: "grantPermissions".into(),
                title: "Grant permissions".into(),
                detail: approval_detail([
                    ("Directory", cwd),
                    ("Reason", reason),
                    ("Permissions", permissions.as_str()),
                ]),
            })
        }
        _ => None,
    }
}

fn approval_detail<'a>(parts: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    parts
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(label, value)| format!("{label}: {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn approval_response_for_decision(
    method: &str,
    params: &Value,
    decision: &str,
) -> Result<Value, CodexError> {
    let decision = match decision {
        "approve" => "accept",
        "deny" => "decline",
        "cancel" => "cancel",
        other => {
            return Err(CodexError::Protocol(format!(
                "unsupported action decision: {other}"
            )));
        }
    };
    match method {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
            Ok(json!({ "decision": decision }))
        }
        "item/permissions/requestApproval" => {
            if decision == "accept" {
                Ok(json!({
                    "permissions": params.get("permissions").cloned().unwrap_or_else(|| json!({})),
                    "scope": "turn",
                    "strictAutoReview": Value::Null,
                }))
            } else {
                Ok(json!({
                    "permissions": {
                        "fileSystem": Value::Null,
                        "network": Value::Null,
                    },
                    "scope": "turn",
                    "strictAutoReview": true,
                }))
            }
        }
        other => Err(CodexError::Protocol(format!(
            "unsupported approval request method: {other}"
        ))),
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
        name: value
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
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

fn user_message_attachments(item: &Value) -> Vec<AgentReference> {
    item.get("content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .filter_map(|part| match part.get("type").and_then(Value::as_str) {
                    Some("image") => Some(AgentReference {
                        kind: "image".into(),
                        text: None,
                        url: part.get("url").and_then(Value::as_str).map(str::to_string),
                        path: None,
                        name: None,
                    }),
                    Some("localImage") => Some(AgentReference {
                        kind: "localImage".into(),
                        text: None,
                        url: None,
                        path: part.get("path").and_then(Value::as_str).map(str::to_string),
                        name: None,
                    }),
                    Some("skill") | Some("mention") => Some(AgentReference {
                        kind: part
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        text: None,
                        url: None,
                        path: part.get("path").and_then(Value::as_str).map(str::to_string),
                        name: part.get("name").and_then(Value::as_str).map(str::to_string),
                    }),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn value_to_label(value: Option<&Value>) -> Option<String> {
    value.map(value_label).filter(|s| !s.is_empty())
}

fn json_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(|v| serde_json::to_string(v).ok())
        .filter(|s| s != "null")
}

fn thread_item_to_agent_item(item: &Value) -> Option<AgentItem> {
    let id = item.get("id").and_then(Value::as_str)?.to_string();
    let kind = if item.get("type").and_then(Value::as_str) == Some("userMessage") {
        AgentItemKind::User {
            text: user_message_text(item),
            attachments: user_message_attachments(item),
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

fn thread_resume_to_history_summary(value: &Value) -> Result<HistoryThreadSummary, CodexError> {
    let thread = value
        .get("thread")
        .ok_or_else(|| CodexError::Protocol("thread/resume: result missing thread".into()))?;
    thread_summary_from_value(thread)
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

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn hook_fragments(item: &Value) -> Vec<HookFragment> {
    item.get("fragments")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|fragment| HookFragment {
                    hook_run_id: fragment
                        .get("hookRunId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    text: fragment
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn tool_actions(item: &Value) -> Vec<ToolAction> {
    item.get("commandActions")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|action| ToolAction {
                    kind: action
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    command: action
                        .get("command")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    path: action
                        .get("path")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    name: action
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    query: action
                        .get("query")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn file_changes(item: &Value) -> Vec<FileEditChange> {
    item.get("changes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|change| FileEditChange {
                    path: change
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    diff: change
                        .get("diff")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    change_kind: change.get("kind").map(value_label).unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn content_references(item: &Value) -> Vec<AgentReference> {
    item.get("contentItems")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(
                    |content| match content.get("type").and_then(Value::as_str) {
                        Some("inputText") => Some(AgentReference {
                            kind: "inputText".into(),
                            text: content
                                .get("text")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                            url: None,
                            path: None,
                            name: None,
                        }),
                        Some("inputImage") => Some(AgentReference {
                            kind: "inputImage".into(),
                            text: None,
                            url: content
                                .get("imageUrl")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                            path: None,
                            name: None,
                        }),
                        _ => None,
                    },
                )
                .collect()
        })
        .unwrap_or_default()
}

fn web_search_kind(item: &Value) -> AgentItemKind {
    let action = item.get("action");
    AgentItemKind::WebSearch {
        query: item
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        action: action
            .and_then(|a| a.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        action_query: action
            .and_then(|a| a.get("query"))
            .and_then(Value::as_str)
            .map(str::to_string),
        queries: string_array(action.and_then(|a| a.get("queries"))),
        url: action
            .and_then(|a| a.get("url"))
            .and_then(Value::as_str)
            .map(str::to_string),
        pattern: action
            .and_then(|a| a.get("pattern"))
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

fn item_to_kind(item: &Value) -> Option<AgentItemKind> {
    match item.get("type").and_then(Value::as_str)? {
        "userMessage" => Some(AgentItemKind::User {
            text: user_message_text(item),
            attachments: user_message_attachments(item),
        }),
        // PRIMARY answer the user reads — NOT collapsed (the UX bug the user
        // hit: this was mis-named reasoning and the UI folded it away).
        "agentMessage" => Some(AgentItemKind::Message {
            text: item
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            phase: value_to_label(item.get("phase")),
            memory_citation: json_string(item.get("memoryCitation")),
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
            cwd: item.get("cwd").and_then(Value::as_str).map(str::to_string),
            status: value_to_label(item.get("status")),
            duration_ms: item.get("durationMs").and_then(Value::as_i64),
            source: value_to_label(item.get("source")),
            process_id: item
                .get("processId")
                .and_then(Value::as_str)
                .map(str::to_string),
            actions: tool_actions(item),
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
                status: value_to_label(item.get("status")),
                changes: file_changes(item),
            })
        }
        "webSearch" => Some(web_search_kind(item)),
        "plan" => Some(AgentItemKind::Plan {
            text: item
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        "hookPrompt" => Some(AgentItemKind::HookPrompt {
            fragments: hook_fragments(item),
        }),
        "mcpToolCall" => Some(AgentItemKind::ToolCall {
            tool_kind: "mcp".into(),
            server: item
                .get("server")
                .and_then(Value::as_str)
                .map(str::to_string),
            namespace: None,
            tool: item
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            status: value_to_label(item.get("status")).unwrap_or_default(),
            arguments: json_string(item.get("arguments")).unwrap_or_default(),
            result: json_string(item.get("result")),
            error: json_string(item.get("error")),
            duration_ms: item.get("durationMs").and_then(Value::as_i64),
            success: None,
            resource_uri: item
                .get("mcpAppResourceUri")
                .and_then(Value::as_str)
                .map(str::to_string),
            content_items: Vec::new(),
        }),
        "dynamicToolCall" => Some(AgentItemKind::ToolCall {
            tool_kind: "dynamic".into(),
            server: None,
            namespace: item
                .get("namespace")
                .and_then(Value::as_str)
                .map(str::to_string),
            tool: item
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            status: value_to_label(item.get("status")).unwrap_or_default(),
            arguments: json_string(item.get("arguments")).unwrap_or_default(),
            result: None,
            error: None,
            duration_ms: item.get("durationMs").and_then(Value::as_i64),
            success: item.get("success").and_then(Value::as_bool),
            resource_uri: None,
            content_items: content_references(item),
        }),
        "collabAgentToolCall" => Some(AgentItemKind::CollabAgentToolCall {
            tool: value_to_label(item.get("tool")).unwrap_or_default(),
            status: value_to_label(item.get("status")).unwrap_or_default(),
            prompt: item
                .get("prompt")
                .and_then(Value::as_str)
                .map(str::to_string),
            model: item
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_string),
            reasoning_effort: value_to_label(item.get("reasoningEffort")),
            sender_thread_id: item
                .get("senderThreadId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            receiver_thread_ids: string_array(item.get("receiverThreadIds")),
            agents_states: json_string(item.get("agentsStates")),
        }),
        "imageView" => Some(AgentItemKind::Media {
            media_kind: "imageView".into(),
            path: item.get("path").and_then(Value::as_str).map(str::to_string),
            status: None,
            result: None,
            revised_prompt: None,
            saved_path: None,
        }),
        "imageGeneration" => Some(AgentItemKind::Media {
            media_kind: "imageGeneration".into(),
            path: None,
            status: item
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string),
            result: item
                .get("result")
                .and_then(Value::as_str)
                .map(str::to_string),
            revised_prompt: item
                .get("revisedPrompt")
                .and_then(Value::as_str)
                .map(str::to_string),
            saved_path: item
                .get("savedPath")
                .and_then(Value::as_str)
                .map(str::to_string),
        }),
        "enteredReviewMode" => Some(AgentItemKind::ReviewMode {
            action: "entered".into(),
            review: item
                .get("review")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        "exitedReviewMode" => Some(AgentItemKind::ReviewMode {
            action: "exited".into(),
            review: item
                .get("review")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        "contextCompaction" => Some(AgentItemKind::ContextCompaction),
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
                kind: AgentItemKind::Message {
                    text: delta,
                    phase: None,
                    memory_citation: None,
                },
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
                    cwd: None,
                    status: None,
                    duration_ms: None,
                    source: None,
                    process_id: None,
                    actions: Vec::new(),
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
        other if other.starts_with("item/") => {
            let item = params.get("item")?;
            let id = item.get("id").and_then(Value::as_str)?.to_string();
            let lifecycle = if other.ends_with("/completed") {
                Lifecycle::Completed
            } else if other.ends_with("/delta") {
                Lifecycle::Delta
            } else {
                Lifecycle::Started
            };
            let item_type = item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            Some(AgentItem {
                id,
                lifecycle,
                kind: AgentItemKind::Raw {
                    description: format!("unsupported item notification: {other} ({item_type})"),
                },
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
            AgentItemKind::Message { text, .. } => assert_eq!(text, "the answer"),
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
    fn unknown_notification_becomes_raw_agent_item() {
        let params = json!({
            "item": {
                "id": "unknown_1",
                "type": "newFutureItem",
                "payload": {"x": 1}
            }
        });

        let item = translate("item/newFutureItem/completed", &params).unwrap();

        assert_eq!(item.id, "unknown_1");
        assert_eq!(item.lifecycle, Lifecycle::Completed);
        assert!(matches!(item.kind, AgentItemKind::Raw { .. }));
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
            AgentItemKind::Message { text, .. } => assert_eq!(text, "Hello"),
            _ => panic!(),
        }

        let done = translate(
            "item/completed",
            &json!({"item":{"id":"msg1","type":"agentMessage","text":"Hello world"},
                    "threadId":"t","turnId":"u"}),
        )
        .unwrap();
        match done.kind {
            AgentItemKind::Message { text, .. } => assert_eq!(text, "Hello world"),
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
                ..
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
            AgentItemKind::FileEdit { path, diff, .. } => {
                assert_eq!(path, "src/main.rs");
                assert!(diff.unwrap().contains("+new"));
            }
            _ => panic!("expected FileEdit"),
        }
    }

    #[test]
    fn thread_read_web_search_item_maps_to_neutral_web_search() {
        let detail = thread_read_to_history_detail(&json!({
            "thread": {
                "id": "thread_1",
                "name": null,
                "preview": "search latest docs",
                "cwd": "/tmp/project",
                "createdAt": 10,
                "updatedAt": 20,
                "status": "ready",
                "modelProvider": "openai",
                "source": "cli",
                "turns": [{
                    "items": [{
                        "id": "ws1",
                        "type": "webSearch",
                        "query": "AgentDeck history web search",
                        "action": {
                            "type": "findInPage",
                            "url": "https://example.com/docs",
                            "pattern": "history"
                        }
                    }]
                }]
            }
        }))
        .unwrap();

        let item = serde_json::to_value(&detail.items[0]).unwrap();
        assert_eq!(item["kind"], "webSearch");
        assert_eq!(item["query"], "AgentDeck history web search");
        assert_eq!(item["action"], "findInPage");
        assert_eq!(item["url"], "https://example.com/docs");
        assert_eq!(item["pattern"], "history");
    }

    #[test]
    fn thread_read_maps_all_known_thread_item_types_without_raw_fallback() {
        let detail = thread_read_to_history_detail(&json!({
            "thread": {
                "id": "thread_1",
                "name": null,
                "preview": "all items",
                "cwd": "/tmp/project",
                "createdAt": 10,
                "updatedAt": 20,
                "status": "ready",
                "modelProvider": "openai",
                "source": "cli",
                "turns": [{
                    "items": [
                        {"id":"u1","type":"userMessage","content":[
                            {"type":"text","text":"prompt"},
                            {"type":"localImage","path":"/tmp/a.png"},
                            {"type":"skill","name":"browser","path":"/skills/browser"}
                        ]},
                        {"id":"a1","type":"agentMessage","text":"answer","phase":"final","memoryCitation":{"entries":[]}},
                        {"id":"p1","type":"plan","text":"1. Do it"},
                        {"id":"h1","type":"hookPrompt","fragments":[{"hookRunId":"hr1","text":"hook text"}]},
                        {"id":"r1","type":"reasoning","summary":["summary"],"content":["full"]},
                        {"id":"c1","type":"commandExecution","command":"rg foo","commandActions":[{"type":"search","command":"rg foo","path":"/tmp","query":"foo"}],"cwd":"/tmp","status":"completed","type":"commandExecution","aggregatedOutput":"out","exitCode":0,"durationMs":12,"processId":"p","source":"agent"},
                        {"id":"f1","type":"fileChange","status":"applied","changes":[{"path":"a.txt","diff":"+a","kind":"add"},{"path":"b.txt","diff":"-b","kind":"delete"}]},
                        {"id":"m1","type":"mcpToolCall","server":"github","tool":"list","arguments":{"q":"x"},"status":"completed","durationMs":3,"result":{"content":[{"type":"text","text":"ok"}]},"error":null,"mcpAppResourceUri":"app://github"},
                        {"id":"d1","type":"dynamicToolCall","namespace":"web","tool":"search","arguments":{"q":"x"},"status":"completed","success":true,"durationMs":4,"contentItems":[{"type":"inputText","text":"hit"},{"type":"inputImage","imageUrl":"https://example.com/a.png"}]},
                        {"id":"ca1","type":"collabAgentToolCall","tool":"spawn","status":"completed","prompt":"help","model":"gpt","reasoningEffort":"medium","senderThreadId":"s","receiverThreadIds":["r"],"agentsStates":{"r":{"status":"done"}}},
                        {"id":"ws1","type":"webSearch","query":"docs","action":{"type":"search","query":"docs","queries":["docs"]}},
                        {"id":"iv1","type":"imageView","path":"/tmp/a.png"},
                        {"id":"ig1","type":"imageGeneration","status":"completed","result":"ok","revisedPrompt":"better","savedPath":"/tmp/out.png"},
                        {"id":"er1","type":"enteredReviewMode","review":"review text"},
                        {"id":"xr1","type":"exitedReviewMode","review":"review text"},
                        {"id":"cc1","type":"contextCompaction"}
                    ]
                }]
            }
        }))
        .unwrap();

        let items = serde_json::to_value(&detail.items).unwrap();
        let kinds: Vec<String> = items
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["kind"].as_str().unwrap().to_string())
            .collect();
        assert!(!kinds.iter().any(|kind| kind == "raw"), "{kinds:?}");
        assert_eq!(items[0]["attachments"][0]["path"], "/tmp/a.png");
        assert_eq!(items[1]["phase"], "final");
        assert_eq!(items[3]["fragments"][0]["hookRunId"], "hr1");
        assert_eq!(items[5]["cwd"], "/tmp");
        assert_eq!(items[5]["actions"][0]["query"], "foo");
        assert_eq!(items[6]["changes"][1]["path"], "b.txt");
        assert_eq!(items[7]["toolKind"], "mcp");
        assert_eq!(
            items[8]["contentItems"][1]["url"],
            "https://example.com/a.png"
        );
        assert_eq!(items[9]["receiverThreadIds"][0], "r");
        assert_eq!(items[11]["mediaKind"], "imageView");
        assert_eq!(items[12]["savedPath"], "/tmp/out.png");
        assert_eq!(items[13]["action"], "entered");
        assert_eq!(items[15]["kind"], "contextCompaction");
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
            AgentItemKind::User { text, .. } => assert_eq!(text, "please fix tests"),
            _ => panic!("expected user item"),
        }
        match &detail.items[1].kind {
            AgentItemKind::Message { text, .. } => assert_eq!(text, "done"),
            _ => panic!("expected message item"),
        }
    }

    #[test]
    fn thread_resume_response_maps_to_history_summary() {
        let value = json!({
            "cwd": "/tmp/project",
            "model": "gpt",
            "modelProvider": "openai",
            "approvalPolicy": "never",
            "approvalsReviewer": "auto",
            "sandbox": {"mode": "workspace-write"},
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
                "turns": []
            }
        });
        let summary = thread_resume_to_history_summary(&value).unwrap();
        assert_eq!(summary.id, "thread_1");
        assert_eq!(summary.cwd, "/tmp/project");
    }

    #[test]
    fn approval_command_request_maps_to_neutral_action_request() {
        let request = approval_request_to_action(
            42,
            "item/commandExecution/requestApproval",
            &json!({
                "itemId": "cmd1",
                "approvalId": "approval-1",
                "threadId": "thread_1",
                "turnId": "turn_1",
                "command": "make test",
                "cwd": "/tmp/project",
                "reason": "needs to run tests",
                "startedAtMs": 1
            }),
        )
        .unwrap();

        assert_eq!(request.request_id, 42);
        assert_eq!(request.item_id, "cmd1");
        assert_eq!(request.approval_id.as_deref(), Some("approval-1"));
        assert_eq!(request.action_kind, "runCommand");
        assert!(request.detail.contains("make test"));
        assert!(request.detail.contains("/tmp/project"));
        assert!(request.detail.contains("needs to run tests"));
    }

    #[test]
    fn approval_file_and_permission_requests_map_to_neutral_action_requests() {
        let file = approval_request_to_action(
            43,
            "item/fileChange/requestApproval",
            &json!({
                "itemId": "file1",
                "threadId": "thread_1",
                "turnId": "turn_1",
                "grantRoot": "/tmp/project",
                "reason": "apply patch",
                "startedAtMs": 1
            }),
        )
        .unwrap();
        let permissions = approval_request_to_action(
            44,
            "item/permissions/requestApproval",
            &json!({
                "itemId": "perm1",
                "threadId": "thread_1",
                "turnId": "turn_1",
                "cwd": "/tmp/project",
                "permissions": {"fileSystem": {"write": ["/tmp/project"]}},
                "reason": "needs write access",
                "startedAtMs": 1
            }),
        )
        .unwrap();

        assert_eq!(file.action_kind, "applyChanges");
        assert_eq!(file.item_id, "file1");
        assert!(file.detail.contains("/tmp/project"));
        assert_eq!(permissions.action_kind, "grantPermissions");
        assert_eq!(permissions.item_id, "perm1");
        assert!(permissions.detail.contains("needs write access"));
    }

    #[test]
    fn approval_decision_builds_codex_response_result() {
        let command = approval_response_for_decision(
            "item/commandExecution/requestApproval",
            &json!({}),
            "approve",
        )
        .unwrap();
        let file =
            approval_response_for_decision("item/fileChange/requestApproval", &json!({}), "deny")
                .unwrap();
        let permissions = approval_response_for_decision(
            "item/permissions/requestApproval",
            &json!({
                "permissions": {"fileSystem": {"write": ["/tmp/project"]}}
            }),
            "approve",
        )
        .unwrap();

        assert_eq!(command, json!({"decision": "accept"}));
        assert_eq!(file, json!({"decision": "decline"}));
        assert_eq!(
            permissions["permissions"]["fileSystem"]["write"][0],
            "/tmp/project"
        );
        assert_eq!(permissions["scope"], "turn");
    }

    #[test]
    fn codex_child_path_includes_common_gui_missing_tool_dirs() {
        let path = codex_child_path_env(Some("/usr/bin:/bin"));
        let parts: Vec<&str> = path.split(':').collect();

        assert!(parts.contains(&"/usr/local/bin"));
        assert!(parts.contains(&"/opt/homebrew/bin"));
        assert!(parts.contains(&"/usr/bin"));
        assert!(parts.contains(&"/bin"));
    }

    #[test]
    fn stderr_tail_keeps_recent_lines_and_appears_in_disconnect_error() {
        let tail = StderrTail::new(2);
        tail.push("first line");
        tail.push("second line");
        tail.push("third line");

        let summary = tail.summary().unwrap();
        assert!(!summary.contains("first line"));
        assert!(summary.contains("second line"));
        assert!(summary.contains("third line"));

        let error = CodexError::Disconnected(Some(summary)).to_string();
        assert!(error.contains("recent stderr"));
        assert!(error.contains("third line"));
    }

    // --- C1: protocol error paths ---
    //
    // These pin the failure-mode contract for malformed / unexpected wire
    // frames. They exercise the same surfaces the live `await_response` /
    // `read_message` paths use (`translate`, `serde_json::from_str`,
    // `CodexError::Protocol`), so a regression in the parser or error
    // wrapping fails here rather than in a live e2e run.

    #[test]
    fn missing_required_field_event_returns_none_without_panic() {
        // `translate()` requires `itemId` and `delta` for delta methods, and
        // `item` for item lifecycle methods. Missing any of them must return
        // `None` (caller skips, turn continues) rather than panic. `threadId`
        // is informational at this layer — translate does not key off it.
        assert!(
            translate(
                "item/agentMessage/delta",
                &json!({"delta":"text","threadId":"t","turnId":"u"})
            )
            .is_none()
        );
        assert!(
            translate(
                "item/agentMessage/delta",
                &json!({"itemId":"x","threadId":"t","turnId":"u"})
            )
            .is_none()
        );
        assert!(
            translate(
                "item/started",
                &json!({"startedAtMs":0,"threadId":"t","turnId":"u"})
            )
            .is_none()
        );
    }

    #[test]
    fn unknown_event_type_falls_back_without_dropping_turn() {
        // A method that is not even in the `item/` namespace must return
        // `None` so the caller treats it as a no-op notification and keeps
        // the turn loop running (not a panic, not an error).
        assert!(
            translate(
                "totally_made_up_event_42",
                &json!({"itemId":"x","threadId":"t","turnId":"u"})
            )
            .is_none()
        );

        // An `item/<unknown>/<unknown lifecycle>` frame with a present
        // `item` object must surface as the Raw fallback so Swift sees a
        // neutralized placeholder rather than vendor JSON. This is the
        // "turn not lost" guarantee for unknown variants.
        let item = translate(
            "item/futureKind/started",
            &json!({"item":{"id":"u1","type":"futureKind","vendor":"hidden"},
                    "threadId":"t","turnId":"u"}),
        )
        .unwrap();
        assert!(matches!(item.kind, AgentItemKind::Raw { .. }));
    }

    #[test]
    fn jsonrpc_error_frame_surfaces_as_codex_protocol_error() {
        // When app-server returns a JSON-RPC error frame, `await_response`
        // and `turn_start` wrap `msg["error"].to_string()` into
        // `CodexError::Protocol`. Pin that: the displayed error must
        // contain both the original `code` and `message`, so logs at the
        // main.rs diag boundary remain debuggable.
        let frame = json!({
            "id": 1,
            "error": {"code": -32601, "message": "method not found"}
        });
        let err_value = frame.get("error").cloned().unwrap();
        let codex_err = CodexError::Protocol(err_value.to_string());
        let displayed = codex_err.to_string();
        assert!(displayed.contains("codex protocol error"));
        assert!(displayed.contains("method not found"));
        assert!(displayed.contains("-32601"));
    }

    #[test]
    fn newline_delimited_framing_rejects_partial_json_with_protocol_error() {
        // Wire framing is line-delimited JSON, not SSE (SPIKE_FINDINGS D7).
        // A half line cannot be "buffered until complete" — the parser sees
        // a single line and either it is a complete JSON value or it is
        // malformed. `read_message` formats malformed lines as
        // `CodexError::Protocol("malformed: {serde_err}: {line}")`; pin that.
        let partial = r#"{"id":1,"method":"item/started","params":{"item":{"id":"x"#;
        let parse_err = serde_json::from_str::<Value>(partial).unwrap_err();
        let codex_err =
            CodexError::Protocol(format!("malformed: {parse_err}: {}", partial.trim()));
        let displayed = codex_err.to_string();
        assert!(displayed.contains("codex protocol error"));
        assert!(displayed.contains("malformed"));

        // And a complete JSON value on a single line parses fine — proves
        // the rejection above is specific to truncation, not a blanket
        // failure of the same input shape.
        let complete = r#"{"id":1,"method":"item/started","params":{"item":{"id":"x","type":"agentMessage","text":""}}}"#;
        let value: Value = serde_json::from_str(complete).unwrap();
        assert_eq!(value["method"], "item/started");
    }

    #[test]
    fn invalid_utf8_in_event_payload_is_rejected_gracefully() {
        // `read_message` reads a UTF-8 line via `BufRead::read_line`, then
        // parses with `serde_json::from_str`. Invalid UTF-8 must fail at
        // parse time (when the upstream produced bytes that survived
        // `read_line` somehow — e.g. via `from_slice` on raw bytes) and
        // must not panic. We exercise the parse surface directly: a JSON
        // object whose value byte is invalid UTF-8 fails, and the error
        // wraps into `CodexError::Protocol` without panicking.
        let mut bad: Vec<u8> = br#"{"method":"item/started","params":{"item":{"id":""#.to_vec();
        bad.push(0xFF);
        bad.push(0xFE);
        bad.extend_from_slice(br#"","type":"agentMessage"}}}"#);

        let parse_err = serde_json::from_slice::<Value>(&bad).unwrap_err();
        let codex_err = CodexError::Protocol(format!("malformed: {parse_err}"));
        assert!(codex_err.to_string().contains("codex protocol error"));
    }

    // --- C2: approval 适配契约 ---
    //
    // 现状（与计划差异）：codex.rs 不持有 approval 状态机。
    // `approval_request_to_action` 和 `approval_response_for_decision` 都是
    // 无状态纯函数；turn_start 的循环在请求→响应之间只携带一次性的
    // `request_id`，没有 HashMap<approval_id, State>。计划里的
    // approval.requested/approved/applied 事件名不存在于 wire 协议
    // （实际是 item/<kind>/requestApproval 加 JSON-RPC response，
    // SPIKE_FINDINGS.md §approval）。这些测试钉死适配器实际暴露的
    // 契约：每个事件正确翻译、不同 approval_id 互不串、纯函数对
    // adapter 重建幂等。

    #[test]
    fn approval_pending_then_approved_then_applied_full_chain() {
        // Reshape: 没有 approval.requested/approved/applied 事件，也没有
        // 状态机终态。Codex 的"完整链路"是：requestApproval 请求被翻译为
        // ActionRequest → 调用方决策被翻译为 wire response → 命令实际执行
        // 的结果以 item/commandExecution/completed 形式回到 translate()。
        // 我们逐步走这三步并断言每步输出。
        let request_params = json!({
            "itemId": "cmd1",
            "approvalId": "approval-1",
            "threadId": "thread_1",
            "turnId": "turn_1",
            "command": "make test",
            "cwd": "/tmp/project",
            "reason": "needs to run tests",
            "startedAtMs": 1,
        });
        let action = approval_request_to_action(
            100,
            "item/commandExecution/requestApproval",
            &request_params,
        )
        .unwrap();
        assert_eq!(action.request_id, 100);
        assert_eq!(action.approval_id.as_deref(), Some("approval-1"));
        assert_eq!(action.action_kind, "runCommand");

        let response = approval_response_for_decision(
            "item/commandExecution/requestApproval",
            &request_params,
            "approve",
        )
        .unwrap();
        assert_eq!(response, json!({"decision": "accept"}));

        // 命令执行完成事件 — 这是计划里 "action.applied" 在真实 wire 上的
        // 等价物：item/completed 携带 type=commandExecution + exitCode + output。
        let applied = translate(
            "item/completed",
            &json!({
                "item": {
                    "id": "cmd1",
                    "type": "commandExecution",
                    "command": "make test",
                    "exitCode": 0,
                    "aggregatedOutput": "ok\n",
                    "cwd": "/tmp/project",
                    "status": "completed",
                    "commandActions": [],
                },
                "threadId": "thread_1",
                "turnId": "turn_1",
            }),
        )
        .unwrap();
        assert_eq!(applied.id, "cmd1");
        assert!(matches!(applied.lifecycle, Lifecycle::Completed));
        assert!(matches!(applied.kind, AgentItemKind::Shell { .. }));
    }

    #[test]
    fn approval_deny_to_decline_and_failed_completion_maps_to_shell() {
        // Reshape: codex.rs 没有"deny 后续 action_request 被拒绝"的逻辑
        // （这层不跟踪后续命令是否被尝试执行）。这里钉死适配器真正负责
        // 的两件事：(a) deny 决策翻译成 wire decline；(b) Codex 在收到
        // decline 后通常以 status="failed" 的 commandExecution/completed
        // 收尾，translate() 仍把它映射为 Shell 已完成项，让上层能展示
        // 拒绝结果而不是丢帧。
        let request_params = json!({
            "itemId": "cmd2",
            "approvalId": "approval-2",
            "command": "rm -rf /",
            "cwd": "/tmp/project",
            "reason": "dangerous",
            "startedAtMs": 1,
        });
        let action = approval_request_to_action(
            101,
            "item/commandExecution/requestApproval",
            &request_params,
        )
        .unwrap();
        assert_eq!(action.request_id, 101);
        assert_eq!(action.approval_id.as_deref(), Some("approval-2"));

        let response = approval_response_for_decision(
            "item/commandExecution/requestApproval",
            &request_params,
            "deny",
        )
        .unwrap();
        assert_eq!(response, json!({"decision": "decline"}));

        let failed = translate(
            "item/completed",
            &json!({
                "item": {
                    "id": "cmd2",
                    "type": "commandExecution",
                    "command": "rm -rf /",
                    "exitCode": 1,
                    "aggregatedOutput": "",
                    "status": "failed",
                    "commandActions": [],
                },
                "threadId": "thread_1",
                "turnId": "turn_1",
            }),
        )
        .unwrap();
        assert_eq!(failed.id, "cmd2");
        assert!(matches!(failed.lifecycle, Lifecycle::Completed));
        match failed.kind {
            AgentItemKind::Shell {
                status, exit_code, ..
            } => {
                assert_eq!(status.as_deref(), Some("failed"));
                assert_eq!(exit_code, Some(1));
            }
            other => panic!("expected Shell completed, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_approval_ids_do_not_collide() {
        // 同一 turn 里两个不同 approval_id 同时挂起：钉死适配器对
        // (request_id, approval_id, item_id, action_kind) 字段的隔离 —
        // 不会把字段串到对方的输出上。
        let req_a = approval_request_to_action(
            200,
            "item/commandExecution/requestApproval",
            &json!({
                "itemId": "cmdA",
                "approvalId": "approval-A",
                "command": "echo a",
                "cwd": "/tmp/a",
                "reason": "first",
                "startedAtMs": 1,
            }),
        )
        .unwrap();
        let req_b = approval_request_to_action(
            201,
            "item/fileChange/requestApproval",
            &json!({
                "itemId": "fileB",
                "approvalId": "approval-B",
                "grantRoot": "/tmp/b",
                "reason": "second",
                "startedAtMs": 1,
            }),
        )
        .unwrap();

        assert_ne!(req_a.request_id, req_b.request_id);
        assert_ne!(req_a.item_id, req_b.item_id);
        assert_ne!(req_a.approval_id, req_b.approval_id);
        assert_eq!(req_a.action_kind, "runCommand");
        assert_eq!(req_b.action_kind, "applyChanges");
        assert!(req_a.detail.contains("first"));
        assert!(!req_a.detail.contains("second"));
        assert!(req_b.detail.contains("second"));
        assert!(!req_b.detail.contains("first"));

        // 决策也独立：A approve、B deny，两个 response 互不污染。
        let resp_a = approval_response_for_decision(
            "item/commandExecution/requestApproval",
            &json!({}),
            "approve",
        )
        .unwrap();
        let resp_b = approval_response_for_decision(
            "item/fileChange/requestApproval",
            &json!({}),
            "deny",
        )
        .unwrap();
        assert_eq!(resp_a, json!({"decision": "accept"}));
        assert_eq!(resp_b, json!({"decision": "decline"}));
    }

    #[test]
    fn approval_state_recovers_after_daemon_restart() {
        // Reshape: codex.rs 的 approval 翻译是纯函数，CodexClient 不持有
        // approval 状态。"daemon 重启"在这一层等价于：丢弃任何隐含状态后
        // 重新喂同一序列，输出仍逐字段一致（幂等）。我们演示这一性质。
        let request_params = json!({
            "itemId": "cmd3",
            "approvalId": "approval-3",
            "command": "ls",
            "cwd": "/tmp/project",
            "reason": "list files",
            "startedAtMs": 1,
        });

        let before = approval_request_to_action(
            300,
            "item/commandExecution/requestApproval",
            &request_params,
        )
        .unwrap();
        let after = approval_request_to_action(
            300,
            "item/commandExecution/requestApproval",
            &request_params,
        )
        .unwrap();
        assert_eq!(before, after);

        // 同样的 deny 决策两次喂入也应得到同样的 wire response —
        // 不会因为"上次已经 applied"而错误地变成 accept 或 protocol error。
        let first = approval_response_for_decision(
            "item/commandExecution/requestApproval",
            &request_params,
            "deny",
        )
        .unwrap();
        let second = approval_response_for_decision(
            "item/commandExecution/requestApproval",
            &request_params,
            "deny",
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first, json!({"decision": "decline"}));

        // 同一 approved 命令的 completed 帧重放也幂等 — translate 不会
        // 因为重复就丢帧或变形。
        let completed_event = json!({
            "item": {
                "id": "cmd3",
                "type": "commandExecution",
                "command": "ls",
                "exitCode": 0,
                "aggregatedOutput": "",
                "status": "completed",
                "commandActions": [],
            },
            "threadId": "thread_1",
            "turnId": "turn_1",
        });
        let applied_first = translate("item/completed", &completed_event).unwrap();
        let applied_again = translate("item/completed", &completed_event).unwrap();
        assert_eq!(applied_first.id, applied_again.id);
        assert!(matches!(applied_first.kind, AgentItemKind::Shell { .. }));
        assert!(matches!(applied_again.kind, AgentItemKind::Shell { .. }));
    }

    // --- C3: turn 边界 ---
    //
    // codex.rs 是无状态 per-event 翻译层：`AgentItem` 不携带 `turn_id`，
    // `translate()` 不做 turn 聚合，也不发任何 diag。下面 4 个测试钉死
    // 该层真正负责的契约（"不串字段、不丢帧、不泄漏 wire 元数据、幂等"），
    // 把"turn 边界守卫 / once-per-turn 警告"的责任明确划到 main.rs 调用方
    // ——见 docs/plans/.../design.md 风险与权衡 C3 小节的记录。

    #[test]
    fn translate_preserves_item_id_per_event_across_same_turn() {
        // Reshape: 计划写的是"多 user_item 落到同 turn / turn 聚合正确"。
        // 此层不做聚合，契约改为：同一 turnId 下连续多个 item 事件，每个
        // 都独立翻译成 AgentItem 且 id 严格对齐 wire 的 itemId，turnId 本身
        // 不泄漏进 AgentItem（既不进 id 也不进 Raw description）。
        let turn_id = "turn_c3_1";
        let evts: [(&str, &str); 3] = [
            ("msg_a", "first"),
            ("msg_b", "second"),
            ("msg_c", "third"),
        ];

        let items: Vec<AgentItem> = evts
            .iter()
            .map(|(item_id, delta)| {
                translate(
                    "item/agentMessage/delta",
                    &json!({
                        "itemId": item_id,
                        "delta": delta,
                        "threadId": "thread_c3",
                        "turnId": turn_id,
                    }),
                )
                .expect("delta with required fields must translate")
            })
            .collect();

        assert_eq!(items.len(), 3);
        for (item, (expected_id, expected_text)) in items.iter().zip(evts.iter()) {
            assert_eq!(item.id, *expected_id);
            assert!(matches!(item.lifecycle, Lifecycle::Delta));
            match &item.kind {
                AgentItemKind::Message { text, .. } => assert_eq!(text, expected_text),
                other => panic!("expected Message kind, got {other:?}"),
            }
            // turnId 不泄漏：item.id 不能等于 turnId，也不能出现在序列化输出里。
            assert_ne!(item.id, turn_id);
            let wire = serde_json::to_string(item).unwrap();
            assert!(!wire.contains(turn_id), "turnId leaked into AgentItem wire: {wire}");
        }
    }

    #[test]
    fn turn_completed_method_is_not_an_agent_item_and_does_not_gate_translate() {
        // Reshape: 计划写的是"turn.completed 之后的 delta 被丢弃 + diag 警告"。
        // 此层无状态、无 diag，所以契约拆成两条可测断言：
        //   (a) "turn/completed" 本身不是 item 通知，translate 返回 None；
        //   (b) translate 不做"after completed"门禁——同一 turnId 后续 delta
        //       仍然会被正常翻译。门禁（丢弃 stale）归 main.rs / 调用方。
        let turn_id = "turn_c3_2";

        assert!(
            translate(
                "turn/completed",
                &json!({"threadId": "thread_c3", "turnId": turn_id}),
            )
            .is_none(),
            "turn/completed must not surface as an AgentItem"
        );

        let stale = translate(
            "item/agentMessage/delta",
            &json!({
                "itemId": "msg_late",
                "delta": "arrived after turn/completed",
                "threadId": "thread_c3",
                "turnId": turn_id,
            }),
        )
        .expect("translate is stateless: a late delta still produces an AgentItem");
        assert_eq!(stale.id, "msg_late");
        assert!(matches!(stale.lifecycle, Lifecycle::Delta));
        match stale.kind {
            AgentItemKind::Message { text, .. } => {
                assert_eq!(text, "arrived after turn/completed");
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn item_ids_from_different_turns_translate_to_distinct_agent_items() {
        // Reshape: 计划是"client_id 不在 turn 间串"，但此层不存在 clientItemId
        // 字段，AgentItem 也无 client_id（见 ipc.rs）。可观测的等价契约：两个
        // turnId 不同的 delta，itemId 也不同时，翻译后的 AgentItem.id 必须
        // assert_ne!（即上一 turn 的 id 不会被下一 turn 改写或串入）。
        let first = translate(
            "item/agentMessage/delta",
            &json!({
                "itemId": "msg_turn1",
                "delta": "from turn 1",
                "threadId": "thread_c3",
                "turnId": "turn_one",
            }),
        )
        .unwrap();
        let second = translate(
            "item/agentMessage/delta",
            &json!({
                "itemId": "msg_turn2",
                "delta": "from turn 2",
                "threadId": "thread_c3",
                "turnId": "turn_two",
            }),
        )
        .unwrap();

        assert_ne!(first.id, second.id);
        match (&first.kind, &second.kind) {
            (
                AgentItemKind::Message { text: t1, .. },
                AgentItemKind::Message { text: t2, .. },
            ) => {
                assert_eq!(t1, "from turn 1");
                assert_eq!(t2, "from turn 2");
                assert_ne!(t1, t2);
            }
            other => panic!("expected two Message kinds, got {other:?}"),
        }
    }

    #[test]
    fn repeated_stale_deltas_translate_identically_without_hidden_state() {
        // Reshape: 计划是"多次 stale delta 警告每 turn 只一次"。此层无 diag、
        // 无 per-turn 状态，"once per turn" 不在这一层。可测的等价契约是
        // 幂等性：连喂多次同 shape 的"stale"事件，translate 的输出每次都
        // 全等（同 id、同 lifecycle、同 text），即没有累计状态偷偷改变结果。
        let params = json!({
            "itemId": "msg_repeat",
            "delta": "stale",
            "threadId": "thread_c3",
            "turnId": "turn_c3_4",
        });

        let outputs: Vec<Value> = (0..4)
            .map(|_| {
                let item = translate("item/agentMessage/delta", &params).unwrap();
                serde_json::to_value(&item).unwrap()
            })
            .collect();

        let first = &outputs[0];
        for (i, out) in outputs.iter().enumerate().skip(1) {
            assert_eq!(out, first, "translate output drifted at call #{i}: {out}");
        }
        // 同时确认第一次的形状仍是预期的 Message delta（不是变成 Raw 或丢字段）。
        assert_eq!(first["id"], "msg_repeat");
        assert_eq!(first["lifecycle"], "delta");
        assert_eq!(first["kind"], "message");
        assert_eq!(first["text"], "stale");
    }

    // --- C4: session 边界 ---
    //
    // wire 协议里"session/connection 生命周期"事件是 `thread/started` 和
    // `thread/closed`（SPIKE_FINDINGS.md + protocol/codex_app_server_protocol
    // .v2.schemas.json）。codex.rs 本身无 session 状态，也不拥有 transport：
    // `AgentItem` 没有 session_id/thread_id 字段（session_id 在 IPC envelope，
    // 见 ipc.rs），`translate()` 是无状态 per-event 翻译。下面 3 个测试钉死
    // 该层真正负责的契约——"生命周期事件不变成 AgentItem"、"无门禁/无缓冲、
    // 无论顺序如何 item 事件都独立翻译"、"transport close 不归此层"——把
    // session 状态机 / transport 关闭 / 缓冲的责任明确划到 main.rs 调用方。
    // 见 docs/plans/.../design.md 风险与权衡 C4 小节的记录。

    #[test]
    fn translate_does_not_gate_item_events_on_thread_started_notification() {
        // Reshape: 计划写"session.started 前事件被缓冲"。wire 协议里既没有
        // `session.started` 也没有"缓冲"概念——连接生命周期通知是
        // `thread/started`（params: {thread}），codex.rs 是无状态翻译层。
        // 真实可测契约拆成两条：
        //   (a) `thread/started` 通知本身不是 item 通知，translate 返回 None
        //       （连接生命周期事件由 main.rs 边界消费，不变成 AgentItem）。
        //   (b) translate 不做"必须先看到 thread/started"门禁：item 事件
        //       即使在没有任何前导通知的情况下来到，依然被独立翻译输出。
        //       这证明"缓冲 / 丢弃"责任不在 codex.rs。
        assert!(
            translate(
                "thread/started",
                &json!({
                    "thread": {
                        "id": "thread_c4",
                        "sessionId": "session_c4",
                        "cwd": "/tmp/project",
                        "status": "ready",
                        "preview": "",
                        "createdAt": 0,
                        "updatedAt": 0,
                        "cliVersion": "0.0.0",
                        "ephemeral": false,
                        "modelProvider": "openai",
                        "source": "cli",
                        "turns": []
                    }
                }),
            )
            .is_none(),
            "thread/started is a connection-lifecycle notification, not an AgentItem"
        );

        // 没有任何前导 thread/started，item 事件依然被翻译为 AgentItem。
        let early = translate(
            "item/agentMessage/delta",
            &json!({
                "itemId": "msg_early",
                "delta": "arrived before any lifecycle event",
                "threadId": "thread_c4",
                "turnId": "turn_c4",
            }),
        )
        .expect("translate is stateless: no session gating");
        assert_eq!(early.id, "msg_early");
        assert!(matches!(early.lifecycle, Lifecycle::Delta));
        match early.kind {
            AgentItemKind::Message { text, .. } => {
                assert_eq!(text, "arrived before any lifecycle event");
            }
            other => panic!("expected Message delta, got {other:?}"),
        }
    }

    #[test]
    fn thread_closed_notification_does_not_translate_and_transport_close_is_not_this_layer() {
        // Reshape: 计划写"session.ended 触发 transport close signal"。codex.rs
        // 不拥有 transport（child / stdin / stdout / reader 都是 CodexAdapter
        // 的私有字段，关闭由 `Drop for CodexAdapter` 在外部进程结束时执行）。
        // wire 上的"session ended"等价物是 `thread/closed` 通知，schema 为
        // `{threadId}`。真实可测契约：
        //   (a) `thread/closed` 不变成 AgentItem（translate 返回 None）；
        //   (b) `thread/closed` 之后到达的 item 事件仍被翻译——"close 之后
        //       拒收"不是此层职责。
        // 这把"transport close signal"明确推到 main.rs / CodexAdapter::Drop。
        assert!(
            translate(
                "thread/closed",
                &json!({"threadId": "thread_c4"}),
            )
            .is_none(),
            "thread/closed is a lifecycle notification, not an AgentItem"
        );

        let after_close = translate(
            "item/agentMessage/delta",
            &json!({
                "itemId": "msg_after_close",
                "delta": "after thread/closed",
                "threadId": "thread_c4",
                "turnId": "turn_c4",
            }),
        )
        .expect("translate has no close-gating: stale items still translate");
        assert_eq!(after_close.id, "msg_after_close");
        assert!(matches!(after_close.lifecycle, Lifecycle::Delta));
    }

    #[test]
    fn repeated_thread_started_with_different_session_ids_do_not_contaminate_translate() {
        // Reshape: 计划写"重复 session_started，以最新为准、旧 session 状态
        // 被清理"。codex.rs 不持有 session 状态——`AgentItem` 没有 session_id
        // 字段（session_id 只存在于 IPC envelope，由 main.rs 在写出时填充，
        // 见 ipc.rs::IpcMessage）。可测的等价契约：translate 对多次
        // `thread/started`（即便 sessionId 不同）一致返回 None，并且其间到达
        // 的 item 事件的 AgentItem 输出与 sessionId 完全无关——序列化后不
        // 包含任何 sessionId 字符串。这证明 codex.rs 没有"旧 session 状态
        // 残留可被污染"的对象，"以最新 session 为准"的责任明确归 main.rs。
        for session_id in ["session_old", "session_new"] {
            assert!(
                translate(
                    "thread/started",
                    &json!({
                        "thread": {
                            "id": "thread_c4",
                            "sessionId": session_id,
                            "cwd": "/tmp/project",
                            "status": "ready",
                            "preview": "",
                            "createdAt": 0,
                            "updatedAt": 0,
                            "cliVersion": "0.0.0",
                            "ephemeral": false,
                            "modelProvider": "openai",
                            "source": "cli",
                            "turns": []
                        }
                    }),
                )
                .is_none(),
                "thread/started must never surface as an AgentItem, regardless of sessionId"
            );
        }

        // 同一 itemId 的 delta 在两次"重连"之间到达——AgentItem 输出与
        // sessionId 解耦：sessionId 既不进 id，也不进任何序列化字段。
        let between = translate(
            "item/agentMessage/delta",
            &json!({
                "itemId": "msg_between",
                "delta": "between reconnects",
                "threadId": "thread_c4",
                "turnId": "turn_c4",
                "sessionId": "session_new",
            }),
        )
        .expect("delta translates without referencing any session state");
        assert_eq!(between.id, "msg_between");
        let wire = serde_json::to_string(&between).unwrap();
        assert!(
            !wire.contains("session_old"),
            "stale sessionId leaked into AgentItem wire: {wire}"
        );
        assert!(
            !wire.contains("session_new"),
            "sessionId must live in the IPC envelope, not the AgentItem: {wire}"
        );
    }
}

} // end mod v1_legacy (cfg = daemon-bin)
