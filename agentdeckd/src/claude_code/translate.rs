//! Translates Claude Code stream-json output → v2 `ServerEvent`s.
//!
//! Phase 4 Task 4A. Pure per-line function; the translator owns no I/O,
//! the adapter (`adapter.rs`) drives the child process and feeds lines in.
//!
//! ## Wire shape (probed against `claude` 2.1.191)
//!
//! Top-level line `type` values observed:
//!   - `"system"` — `subtype` in {`"init"`, `"hook_started"`,
//!     `"hook_response"`, `"status"`, …}. `init` carries `session_id`
//!     (also embedded in every other line). `hook_started` / `hook_response`
//!     surface as `VendorPanelEvent::HookFired`.
//!   - `"stream_event"` — partial delta wrapper: `event.type` ∈
//!     {`message_start`, `content_block_start`, `content_block_delta`,
//!     `content_block_stop`, `message_delta`, `message_stop`}. We DROP
//!     these because the cumulative `assistant` / `user` snapshots arrive
//!     immediately after — emitting deltas would either duplicate or
//!     fragment the UI rendering. (Spec § 5.4 + 5.5 "cumulative
//!     semantics" decision; matches Phase 3 lifecycle-replacement.)
//!   - `"assistant"` — final snapshot of an assistant message; its
//!     `message.content` array is walked into AgentItem variants
//!     (text → AssistantMessage, thinking → Reasoning, tool_use → Shell /
//!     Diff / ToolCall depending on tool name).
//!   - `"user"` — final snapshot of a user message; in a CC `--print`
//!     stream this is how tool_result blocks come back from the model
//!     (CC echoes the tool_result content the user side "sent"). We
//!     correlate by `tool_use_id` against `in_flight_tools` and emit
//!     completion events (Shell completed / Diff finalized / ToolCall
//!     with result).
//!   - `"result"` — final turn summary with `usage`, `duration_ms`. We
//!     map to `TurnComplete`.
//!   - `"permission_request"` / `"permission"` / `"prompt"` — speculative
//!     permission-prompt envelopes. The actual wire name is unknown until
//!     Task 4B records a real fixture from `--permission-mode default`;
//!     for v0.2 we accept all three candidates and surface as
//!     `ActionRequest` with `ActionRequestVendor::ClaudeCode`.
//!
//! ## Cumulative semantics
//!
//! The CC CLI emits a `"stream_event"` per partial delta AND a single
//! `"assistant"` / `"user"` snapshot per fully-assembled message. We
//! emit AgentItems only on the snapshots: one event per content block
//! in the snapshot's `content` array.
//!
//! ## Tool_use → tool_result correlation
//!
//! When the assistant snapshot contains a `tool_use`, we
//!   1. emit a Shell{Running} / Diff / ToolCall snapshot,
//!   2. record `tool_use.id → (tool_name, input, started_ms)` in
//!      `in_flight_tools`.
//!
//! When the next `"user"` snapshot brings a `tool_result` with that
//! `tool_use_id`, we
//!   1. consume the in-flight record,
//!   2. emit a follow-up Shell{Completed|Failed} / Diff (no-op for now)
//!      / ToolCall{result populated} event.
//!
//! ## ThreadId
//!
//! CC's `session_id` is the ThreadId in v2 terms. Captured from
//! `system.subtype=init` (preferred) or any line's top-level `session_id`
//! field as fallback.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use agentdeck_protocol::{
    ActionKind, ActionRequest, ActionRequestVendor, AgentItem, AgentItemMeta, AgentKind,
    ClaudeCodePermissionMode, ClaudeCodeVendorPanelEvent, DiffFile, DiffStatus, ServerEvent,
    SessionId, ShellStatus, ThreadId, TurnSummary, VendorPanelPayload,
};

/// One translator-output batch: 0..N ServerEvents from one input line,
/// plus an optional permission-route hint the adapter records so it can
/// later route an `ActionDecision` back to CC.
#[derive(Debug, Default)]
pub struct TranslateOutput {
    pub events: Vec<ServerEvent>,
    /// If this batch contained an `ActionRequest`, the hint is the
    /// underlying `tool_use_id` so `adapter.rs` can map
    /// `request_id → tool_use_id` for response routing. Task 4B
    /// implements the wire format; 4A only records the hint.
    pub permission_route_hint: Option<String>,
}

/// Per-session CC translator. Owns the `tool_use_id → record` map used
/// to correlate `user.tool_result` blocks back to the originating
/// `assistant.tool_use`.
#[derive(Debug)]
pub struct ClaudeCodeTranslator {
    session_id: SessionId,
    thread_id: Option<ThreadId>,
    /// `tool_use.id` → snapshot of the originating tool_use; consumed
    /// when the matching `tool_result` arrives on a `user` snapshot.
    in_flight_tools: HashMap<String, ToolUseRecord>,
    /// Permission mode at session-start; stamped into every
    /// `ActionRequestVendor::ClaudeCode { permission_mode_at_decision }`.
    permission_mode: ClaudeCodePermissionMode,
}

#[derive(Debug, Clone)]
struct ToolUseRecord {
    name: String,
    started_at_ms: u64,
    input: Value,
}

impl ClaudeCodeTranslator {
    pub fn new(session_id: SessionId, permission_mode: ClaudeCodePermissionMode) -> Self {
        Self {
            session_id,
            thread_id: None,
            in_flight_tools: HashMap::new(),
            permission_mode,
        }
    }

    pub fn set_thread_id(&mut self, thread_id: ThreadId) {
        self.thread_id = Some(thread_id);
    }

    pub fn thread_id(&self) -> Option<&ThreadId> {
        self.thread_id.as_ref()
    }

    pub fn permission_mode(&self) -> ClaudeCodePermissionMode {
        self.permission_mode
    }

    /// Translate one stream-json line into 0..N ServerEvents.
    pub fn translate_line(&mut self, line: &str) -> TranslateOutput {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return TranslateOutput::default();
        }
        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return TranslateOutput::default(),
        };

        // Opportunistic threadId capture — every CC line carries
        // `session_id`, so we keep our cache fresh even if we missed
        // `system.subtype=init`.
        if self.thread_id.is_none()
            && let Some(sid) = parsed.get("session_id").and_then(Value::as_str)
        {
            self.thread_id = Some(ThreadId(sid.to_string()));
        }

        let kind = parsed.get("type").and_then(Value::as_str).unwrap_or("");
        match kind {
            "system" => self.handle_system(&parsed),
            "stream_event" => {
                // Cumulative semantics — drop partial deltas; snapshots
                // arrive on the next `assistant` / `user` line.
                TranslateOutput::default()
            }
            "assistant" => self.handle_assistant(&parsed),
            "user" => self.handle_user(&parsed),
            "result" => self.handle_result(&parsed),
            // Candidate permission-prompt envelopes. Real wire name TBD
            // when Task 4B records a `--permission-mode default` fixture.
            "permission_request" | "permission" | "prompt" => self.handle_permission(&parsed),
            _ => self.raw_event(kind, trimmed),
        }
    }

    // ── system ─────────────────────────────────────────────────────────────

    fn handle_system(&mut self, parsed: &Value) -> TranslateOutput {
        let subtype = parsed.get("subtype").and_then(Value::as_str).unwrap_or("");
        match subtype {
            "init" => {
                // Capture session_id authoritatively (overrides any
                // opportunistic capture above).
                if let Some(sid) = parsed.get("session_id").and_then(Value::as_str) {
                    self.thread_id = Some(ThreadId(sid.to_string()));
                }
                TranslateOutput::default()
            }
            "hook_started" | "hook_response" => {
                let matcher = parsed
                    .get("hook_event")
                    .or_else(|| parsed.get("hook_name"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let tool_use_id = parsed
                    .get("tool_use_id")
                    .and_then(Value::as_str)
                    .map(String::from);
                let elapsed_ms = parsed
                    .get("duration_ms")
                    .or_else(|| parsed.get("elapsed_ms"))
                    .and_then(Value::as_u64);
                let payload = ClaudeCodeVendorPanelEvent::HookFired {
                    matcher,
                    tool_use_id,
                    elapsed_ms,
                };
                TranslateOutput {
                    events: vec![ServerEvent::VendorPanelEvent {
                        session_id: self.session_id.clone(),
                        agent_kind: AgentKind::ClaudeCode,
                        payload: VendorPanelPayload::ClaudeCode(payload),
                    }],
                    permission_route_hint: None,
                }
            }
            _ => {
                let payload = ClaudeCodeVendorPanelEvent::SystemStatus {
                    subtype: subtype.to_string(),
                    status: parsed
                        .get("status")
                        .and_then(Value::as_str)
                        .map(String::from),
                    message: system_status_message(parsed),
                    attempt: parsed.get("attempt").and_then(Value::as_u64),
                    error: system_status_error(parsed),
                    error_status: parsed.get("error_status").and_then(Value::as_u64),
                    max_retries: parsed.get("max_retries").and_then(Value::as_u64),
                    retry_delay_ms: parsed.get("retry_delay_ms").and_then(Value::as_f64),
                };
                TranslateOutput {
                    events: vec![ServerEvent::VendorPanelEvent {
                        session_id: self.session_id.clone(),
                        agent_kind: AgentKind::ClaudeCode,
                        payload: VendorPanelPayload::ClaudeCode(payload),
                    }],
                    permission_route_hint: None,
                }
            }
        }
    }

    // ── assistant snapshot ─────────────────────────────────────────────────

    fn handle_assistant(&mut self, parsed: &Value) -> TranslateOutput {
        let content = parsed
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut events = Vec::new();
        for block in &content {
            let block_kind = block.get("type").and_then(Value::as_str).unwrap_or("");
            match block_kind {
                "text" => {
                    let text = block
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if text.is_empty() {
                        continue;
                    }
                    events.push(self.agent_item_event(AgentItem::AssistantMessage {
                        text,
                        meta: AgentItemMeta::default(),
                    }));
                }
                "thinking" => {
                    let text = block
                        .get("thinking")
                        .or_else(|| block.get("text"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if text.is_empty() {
                        continue;
                    }
                    events.push(self.agent_item_event(AgentItem::Reasoning {
                        text,
                        meta: AgentItemMeta::default(),
                    }));
                }
                "tool_use" => {
                    if let Some(ev) = self.handle_assistant_tool_use(block) {
                        events.push(ev);
                    }
                }
                "image" => {
                    let path = block
                        .get("source")
                        .and_then(|s| s.get("path").or_else(|| s.get("file_path")))
                        .and_then(Value::as_str)
                        .map(std::path::PathBuf::from);
                    events.push(self.agent_item_event(AgentItem::ImageReference {
                        saved_path: None,
                        original_path: path,
                        meta: AgentItemMeta::default(),
                    }));
                }
                _ => {
                    let raw_payload = serde_json::to_string(block).unwrap_or_default();
                    events.push(self.agent_item_event(AgentItem::Raw {
                        raw_kind: format!("assistant.{block_kind}"),
                        raw_payload,
                        meta: AgentItemMeta::default(),
                    }));
                }
            }
        }
        TranslateOutput {
            events,
            permission_route_hint: None,
        }
    }

    fn handle_assistant_tool_use(&mut self, block: &Value) -> Option<ServerEvent> {
        let id = block.get("id").and_then(Value::as_str)?.to_string();
        let name = block.get("name").and_then(Value::as_str)?.to_string();
        let input = block.get("input").cloned().unwrap_or(Value::Null);

        let event = match name.as_str() {
            "Bash" => {
                let command = input
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                self.agent_item_event(AgentItem::Shell {
                    command,
                    status: ShellStatus::Running,
                    exit_code: None,
                    duration_ms: None,
                    meta: AgentItemMeta::default(),
                })
            }
            "Edit" | "Write" | "MultiEdit" => {
                let files = diff_files_from_tool_use(&name, &input);
                self.agent_item_event(AgentItem::Diff {
                    files,
                    meta: AgentItemMeta::default(),
                })
            }
            _ => {
                let mut meta = AgentItemMeta::default();
                meta.vendor_extensions
                    .insert("toolUseId".into(), json!(id.clone()));
                self.agent_item_event(AgentItem::ToolCall {
                    name: name.clone(),
                    args: input.clone(),
                    result: None,
                    meta,
                })
            }
        };

        self.in_flight_tools.insert(
            id,
            ToolUseRecord {
                name,
                started_at_ms: now_ms(),
                input,
            },
        );
        Some(event)
    }

    // ── user snapshot (tool_result echo) ───────────────────────────────────

    fn handle_user(&mut self, parsed: &Value) -> TranslateOutput {
        let content = parsed
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut events = Vec::new();
        for block in &content {
            let block_kind = block.get("type").and_then(Value::as_str).unwrap_or("");
            if block_kind != "tool_result" {
                continue;
            }
            let Some(tool_use_id) = block.get("tool_use_id").and_then(Value::as_str) else {
                continue;
            };
            let Some(record) = self.in_flight_tools.remove(tool_use_id) else {
                // Tool_result without a matching tool_use — surface raw
                // so the trail isn't silently lost.
                let raw_payload = serde_json::to_string(block).unwrap_or_default();
                events.push(self.agent_item_event(AgentItem::Raw {
                    raw_kind: "user.tool_result_orphan".into(),
                    raw_payload,
                    meta: AgentItemMeta::default(),
                }));
                continue;
            };
            let is_error = block
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let duration_ms = now_ms().saturating_sub(record.started_at_ms);
            let result_text = extract_tool_result_text(block);

            let event = match record.name.as_str() {
                "Bash" => {
                    let command = record
                        .input
                        .get("command")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let status = if is_error {
                        ShellStatus::Failed
                    } else {
                        ShellStatus::Completed
                    };
                    let exit_code = if is_error { Some(1) } else { Some(0) };
                    self.agent_item_event(AgentItem::Shell {
                        command,
                        status,
                        exit_code,
                        duration_ms: Some(duration_ms),
                        meta: AgentItemMeta::default(),
                    })
                }
                "Edit" | "Write" | "MultiEdit" => {
                    // Diff already emitted on tool_use; emit a finalized
                    // snapshot so the UI can flip "pending" → "applied".
                    let files = diff_files_from_tool_use(&record.name, &record.input);
                    self.agent_item_event(AgentItem::Diff {
                        files,
                        meta: AgentItemMeta::default(),
                    })
                }
                _ => {
                    let mut meta = AgentItemMeta::default();
                    meta.vendor_extensions
                        .insert("toolUseId".into(), json!(tool_use_id));
                    if is_error {
                        meta.vendor_extensions.insert("isError".into(), json!(true));
                    }
                    self.agent_item_event(AgentItem::ToolCall {
                        name: record.name.clone(),
                        args: record.input.clone(),
                        result: Some(json!(result_text)),
                        meta,
                    })
                }
            };
            events.push(event);
        }
        TranslateOutput {
            events,
            permission_route_hint: None,
        }
    }

    // ── result (turn complete) ─────────────────────────────────────────────

    fn handle_result(&mut self, parsed: &Value) -> TranslateOutput {
        let usage = parsed.get("usage");
        let summary = TurnSummary {
            total_input_tokens: usage
                .and_then(|u| u.get("input_tokens"))
                .and_then(Value::as_u64),
            total_output_tokens: usage
                .and_then(|u| u.get("output_tokens"))
                .and_then(Value::as_u64),
            elapsed_ms: parsed
                .get("duration_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        };
        TranslateOutput {
            events: vec![ServerEvent::TurnComplete {
                session_id: self.session_id.clone(),
                thread_id: self.resolved_thread_id(),
                agent_kind: AgentKind::ClaudeCode,
                summary,
            }],
            permission_route_hint: None,
        }
    }

    // ── permission request → ActionRequest ─────────────────────────────────

    fn handle_permission(&mut self, parsed: &Value) -> TranslateOutput {
        let tool_use_id = parsed
            .get("tool_use_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tool_name = parsed
            .get("tool_name")
            .or_else(|| parsed.get("tool"))
            .and_then(Value::as_str)
            .unwrap_or("Unknown")
            .to_string();
        let summary = parsed
            .get("summary")
            .or_else(|| parsed.get("description"))
            .or_else(|| parsed.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("(no summary)")
            .to_string();
        let kind = match tool_name.as_str() {
            "Bash" => ActionKind::ExecuteCommand,
            "Edit" | "Write" | "MultiEdit" => ActionKind::EditFiles,
            _ => ActionKind::GrantExtraPermission,
        };
        let request = ActionRequest {
            request_id: tool_use_id.clone(),
            kind,
            summary,
            vendor: ActionRequestVendor::ClaudeCode {
                permission_mode_at_decision: self.permission_mode,
                tool_name,
            },
        };
        TranslateOutput {
            events: vec![ServerEvent::ActionRequest {
                session_id: self.session_id.clone(),
                thread_id: self.resolved_thread_id(),
                agent_kind: AgentKind::ClaudeCode,
                request,
            }],
            permission_route_hint: Some(tool_use_id),
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────

    fn agent_item_event(&self, item: AgentItem) -> ServerEvent {
        ServerEvent::AgentItem {
            session_id: self.session_id.clone(),
            thread_id: self.resolved_thread_id(),
            agent_kind: AgentKind::ClaudeCode,
            item,
        }
    }

    fn raw_event(&self, kind: &str, raw_payload: &str) -> TranslateOutput {
        TranslateOutput {
            events: vec![self.agent_item_event(AgentItem::Raw {
                raw_kind: kind.to_string(),
                raw_payload: raw_payload.to_string(),
                meta: AgentItemMeta::default(),
            })],
            permission_route_hint: None,
        }
    }

    fn resolved_thread_id(&self) -> ThreadId {
        self.thread_id
            .clone()
            .unwrap_or_else(|| ThreadId(String::new()))
    }
}

// ── field-extraction helpers ────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn system_status_message(parsed: &Value) -> Option<String> {
    parsed
        .get("message")
        .or_else(|| parsed.get("status"))
        .and_then(Value::as_str)
        .or_else(|| parsed.get("error").and_then(Value::as_str))
        .or_else(|| {
            parsed
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
        })
        .map(String::from)
}

fn system_status_error(parsed: &Value) -> Option<String> {
    let error = parsed.get("error")?;
    error
        .as_str()
        .or_else(|| error.get("type").and_then(Value::as_str))
        .or_else(|| error.get("code").and_then(Value::as_str))
        .or_else(|| error.get("message").and_then(Value::as_str))
        .map(String::from)
}

/// Build a `Vec<DiffFile>` from an Edit / Write / MultiEdit tool_use input.
/// For Edit we synthesize a minimal unified-diff-ish patch ("- old\n+ new")
/// since CC's snapshot does not include a server-side diff payload.
fn diff_files_from_tool_use(tool_name: &str, input: &Value) -> Vec<DiffFile> {
    match tool_name {
        "Write" => {
            let path = input
                .get("file_path")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let content = input.get("content").and_then(Value::as_str).unwrap_or("");
            vec![DiffFile {
                path: std::path::PathBuf::from(path),
                status: DiffStatus::Added,
                patch: Some(content.to_string()),
            }]
        }
        "Edit" => {
            let path = input
                .get("file_path")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let old = input
                .get("old_string")
                .and_then(Value::as_str)
                .unwrap_or("");
            let new = input
                .get("new_string")
                .and_then(Value::as_str)
                .unwrap_or("");
            let patch = synth_patch(old, new);
            vec![DiffFile {
                path: std::path::PathBuf::from(path),
                status: DiffStatus::Modified,
                patch: Some(patch),
            }]
        }
        "MultiEdit" => {
            let path = input
                .get("file_path")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let edits = input
                .get("edits")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut patch = String::new();
            for edit in &edits {
                let old = edit.get("old_string").and_then(Value::as_str).unwrap_or("");
                let new = edit.get("new_string").and_then(Value::as_str).unwrap_or("");
                patch.push_str(&synth_patch(old, new));
                patch.push('\n');
            }
            vec![DiffFile {
                path: std::path::PathBuf::from(path),
                status: DiffStatus::Modified,
                patch: Some(patch),
            }]
        }
        _ => Vec::new(),
    }
}

fn synth_patch(old: &str, new: &str) -> String {
    let mut out = String::new();
    for line in old.lines() {
        out.push('-');
        out.push_str(line);
        out.push('\n');
    }
    for line in new.lines() {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// CC tool_result `content` is either a string OR an array of
/// `{type:"text", text:"..."}` blocks. Normalize to a single string.
fn extract_tool_result_text(block: &Value) -> String {
    let c = block.get("content");
    if let Some(s) = c.and_then(Value::as_str) {
        return s.to_string();
    }
    if let Some(arr) = c.and_then(Value::as_array) {
        return arr
            .iter()
            .filter_map(|el| {
                if el.get("type").and_then(Value::as_str) == Some("text") {
                    el.get("text").and_then(Value::as_str)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    String::new()
}
