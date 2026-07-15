//! Codex JSON-RPC → v2 `ServerEvent` translation.
//!
//! Phase 3 Task 3A. This is the entire vendor-coupling surface for Codex on
//! the v2 protocol: a stateful translator owned per-session by Task 3B's
//! `CodexAdapter`. It consumes one newline-delimited JSON message from the
//! `codex app-server` stdout pipe at a time and produces 0..N neutral
//! `ServerEvent`s.
//!
//! ## Cumulative semantics (replaces v1 Lifecycle)
//!
//! v1 surfaced Codex's streaming pattern as three lifecycle phases
//! (`Started` / `Delta` / `Completed`) on every `AgentItem`. The UI was
//! responsible for accumulation (e.g. concatenating `agentMessage` deltas).
//!
//! v2 inverts that: the translator accumulates deltas internally in
//! `in_flight`, keyed by Codex's item id, and emits exactly ONE
//! `ServerEvent::AgentItem` when the corresponding `item/completed`
//! notification arrives. The UI sees only complete items — no fragmentary
//! state, no lifecycle bookkeeping (decision A in the SDD progress block
//! "Lifecycle 替代方案").
//!
//! Side effect: streaming `agentMessage` text no longer arrives token-by-token
//! at the UI. Codex emits a `text` snapshot on `item/agentMessage/started`
//! that's empty, accumulates via deltas, and ships the final string in the
//! `item/completed` payload. We use the completed payload's `text` as the
//! source of truth (Codex itself does the cumulative join), with a fallback
//! to our delta accumulator if the completed payload is missing.
//!
//! ## Approvals
//!
//! Approvals arrive as JSON-RPC **requests** (have an `id` AND a `method`).
//! The v1 codex/mod.rs handled them out-of-band in `turn_start`; in v2 the
//! translator surfaces them as `ServerEvent::ActionRequest`. Task 3B's
//! adapter is responsible for storing the original `id` (so it can route
//! the client's `ActionDecision` back to Codex as a JSON-RPC response) —
//! the translator only emits the neutral event.
//!
//! ## Thread id resolution
//!
//! `ServerEvent::AgentItem` requires a `thread_id`. The translator gets it
//! from one of three sources, in priority order:
//!   1. The current notification's `params.threadId`.
//!   2. The translator's stored `thread_id` (set via `set_thread_id` or
//!      auto-captured from `thread/started`).
//!   3. A synthetic empty `ThreadId("")` as last resort (never expected in
//!      practice — Codex always sends `thread/started` before items).
//!
//! ## Unknown methods
//!
//! Unknown `item/*` notifications: surface as `AgentItem::Raw` with the
//! method name and full JSON payload (so a future Codex version doesn't
//! silently drop data). Unknown non-`item/` lifecycle notifications
//! (`thread/tokenUsage/updated`, `turn/diff/updated`, etc.) yield no
//! events — Task 3B can wire those into vendor panel events later.

use std::collections::HashMap;

use serde_json::{Value, json};

use agentdeck_protocol::{
    ActionKind, ActionRequest, ActionRequestVendor, AgentItem, AgentItemMeta, AgentKind,
    CodexApprovalPolicy, CodexSandboxMode, DiffFile, DiffStatus, PlanStep, PlanStepStatus,
    ProtocolError, ServerEvent, SessionId, ShellStatus, ThreadId, TurnSummary,
};

/// One translator output. Carries the neutral `ServerEvent` plus an
/// optional `rpc_route_hint` the adapter uses to wire approval responses.
///
/// When the translator emits `ServerEvent::ActionRequest`, the underlying
/// Codex JSON-RPC request also has a numeric `id` the adapter must echo
/// back as the response correlation id. The translator surfaces both the
/// public `request_id` (which travels to the client and comes back on
/// `ActionDecision`) and the original codex `rpc_id`, so the adapter can
/// build a `{request_id → rpc_id}` routing table without re-parsing the
/// raw JSON.
#[derive(Debug, Clone)]
pub struct TranslateOutput {
    pub event: ServerEvent,
    pub rpc_route_hint: Option<RpcRouteHint>,
}

/// Pairing between the public `ActionRequest.request_id` (string, travels
/// the v2 protocol) and the underlying Codex JSON-RPC numeric id (the
/// frame-level `id` field the adapter must echo when writing the response).
#[derive(Debug, Clone)]
pub struct RpcRouteHint {
    pub request_id: String,
    pub rpc_id: u64,
    /// Original approval method (e.g. `item/commandExecution/requestApproval`)
    /// — the adapter needs it to build the correct response body shape.
    pub method: String,
    /// Original `params` block — the adapter passes it through to
    /// `permissions/requestApproval` responses (which echo `permissions`).
    pub params: Value,
}

/// Per-session Codex translator. Owns the in-flight item accumulators and
/// a monotonic counter for synthetic request ids.
#[derive(Debug)]
pub struct CodexTranslator {
    session_id: SessionId,
    thread_id: Option<ThreadId>,
    /// In-flight items keyed by Codex item id; updated by delta events,
    /// flushed to `ServerEvent::AgentItem` when Codex emits `item/completed`.
    in_flight: HashMap<String, InFlightItem>,
    /// Codex sometimes omits an approval id on `item/permissions/...`
    /// requests; we synthesize one off this counter so the daemon can
    /// route the matching decision back.
    next_request_id: u64,
    /// Snapshot of the session-level approval policy + sandbox the adapter
    /// negotiated at `newSession`. These are stamped into every
    /// `ActionRequest.vendor` so the UI can render the "at decision time"
    /// context faithfully without inferring it.
    approval_policy: CodexApprovalPolicy,
    sandbox: CodexSandboxMode,
    persist_supported: bool,
}

/// One in-flight item being accumulated. Fields populated based on the
/// item type — we keep them all on one struct (rather than an enum of
/// variants) because a single item can emit deltas spanning multiple
/// "fields" before completion (e.g. an `agentMessage` accumulates `text`,
/// a `commandExecution` accumulates aggregated output, a `fileChange`
/// accumulates `changes[]`).
#[derive(Debug, Clone)]
struct InFlightItem {
    kind: InFlightKind,
    accumulated_text: String,
    /// Snapshot of the most recent `item` payload, kept so `item/completed`
    /// can use authoritative final fields rather than reconstructed ones.
    /// Snapshot of the last `item` payload seen for this id; reserved for
    /// Task 3B (vendor extension extraction at completion time). Allow
    /// dead_code so the rustc warning doesn't fail CI before 3B lands.
    #[allow(dead_code)]
    last_payload: Value,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum InFlightKind {
    AssistantMessage,
    Reasoning,
    Shell,
    Diff,
    Plan,
    Image,
    ToolCall,
    UserMessage,
    /// Catch-all for Codex item types we don't recognize. Emitted as
    /// `AgentItem::Raw` on completion so future schema additions are
    /// surfaced (rather than silently dropped) without leaking vendor
    /// JSON typed-paths.
    Raw,
}

impl CodexTranslator {
    /// Construct a fresh translator. Callers should also call
    /// `set_thread_id` as soon as Codex's `thread/started` arrives (the
    /// translator auto-captures it but the adapter may prefer to override).
    pub fn new(session_id: SessionId, thread_id: Option<ThreadId>) -> Self {
        Self::with_policy(
            session_id,
            thread_id,
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            true,
        )
    }

    /// Like `new` but lets the adapter stamp the session-level approval
    /// policy + sandbox that will appear in every `ActionRequest.vendor`
    /// (matching the user's choice at `newSession` time).
    pub fn with_policy(
        session_id: SessionId,
        thread_id: Option<ThreadId>,
        approval_policy: CodexApprovalPolicy,
        sandbox: CodexSandboxMode,
        persist_supported: bool,
    ) -> Self {
        Self {
            session_id,
            thread_id,
            in_flight: HashMap::new(),
            next_request_id: 1,
            approval_policy,
            sandbox,
            persist_supported,
        }
    }

    pub fn set_thread_id(&mut self, thread_id: ThreadId) {
        self.thread_id = Some(thread_id);
    }

    pub fn thread_id(&self) -> Option<&ThreadId> {
        self.thread_id.as_ref()
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Translate one line of Codex app-server JSONL output.
    ///
    /// Returns 0..N `ServerEvent`s. Equivalent to `translate_line_with_routes`
    /// but drops the per-event `rpc_route_hint`; preserved as a convenience
    /// for tests that don't care about approval routing.
    pub fn translate_line(&mut self, line: &str) -> Vec<ServerEvent> {
        self.translate_line_with_routes(line)
            .into_iter()
            .map(|o| o.event)
            .collect()
    }

    /// Translate a pre-parsed JSON frame (test entry point + internal call).
    ///
    /// Equivalent to `translate_value_with_routes` but drops the per-event
    /// `rpc_route_hint`.
    pub fn translate_value(&mut self, frame: &Value) -> Vec<ServerEvent> {
        self.translate_value_with_routes(frame)
            .into_iter()
            .map(|o| o.event)
            .collect()
    }

    /// Translate one line, returning each `ServerEvent` together with an
    /// optional `RpcRouteHint`. Adapters use the hint to register approval
    /// routing entries before forwarding the event downstream.
    ///
    /// Returns 0..N `TranslateOutput`s. The shape is:
    /// - Empty for lifecycle-only frames (`thread/started`,
    ///   `item/*/delta` while accumulating, plain JSON-RPC responses to
    ///   our outbound requests).
    /// - One `AgentItem` for each `item/completed`.
    /// - One `ActionRequest` + populated `RpcRouteHint` for each Codex
    ///   approval request.
    /// - One `TurnComplete` for each `turn/completed`.
    /// - One `Error` for any malformed input or Codex-reported error frame.
    pub fn translate_line_with_routes(&mut self, line: &str) -> Vec<TranslateOutput> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        let frame: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                return vec![TranslateOutput {
                    event: self.error_event(
                        "codex-malformed-json",
                        format!("malformed codex frame: {e}"),
                    ),
                    rpc_route_hint: None,
                }];
            }
        };
        self.translate_value_with_routes(&frame)
    }

    /// Translate a pre-parsed JSON frame, returning route hints for any
    /// approval requests so the adapter can wire `request_id → rpc_id`.
    pub fn translate_value_with_routes(&mut self, frame: &Value) -> Vec<TranslateOutput> {
        // Error frame from Codex (response.error or notification with `error`).
        if let Some(err) = frame.get("error").filter(|v| !v.is_null()) {
            return vec![TranslateOutput {
                event: self.error_event(
                    "codex-protocol-error",
                    err.get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("codex returned error frame")
                        .to_string(),
                ),
                rpc_route_hint: None,
            }];
        }

        let method = frame.get("method").and_then(Value::as_str);
        let params = frame.get("params").cloned().unwrap_or_else(|| json!({}));

        // JSON-RPC **request** (has both `id` and `method`) = approval / user
        // input from Codex. Adapter responds with a JSON-RPC response keyed
        // off the original id.
        let is_request = frame.get("id").is_some() && method.is_some();
        if is_request {
            if let Some(m) = method {
                if let Some(req) = self.approval_to_action_request(m, &params, frame.get("id")) {
                    let rpc_id = frame.get("id").and_then(Value::as_u64);
                    let hint = rpc_id.map(|rpc_id| RpcRouteHint {
                        request_id: req.request_id.clone(),
                        rpc_id,
                        method: m.to_string(),
                        params: params.clone(),
                    });
                    return vec![TranslateOutput {
                        event: ServerEvent::ActionRequest {
                            session_id: self.session_id.clone(),
                            thread_id: self.resolve_thread_id(&params),
                            agent_kind: AgentKind::Codex,
                            request: req,
                        },
                        rpc_route_hint: hint,
                    }];
                }
                // Unknown server-request method — surface as Raw so it
                // doesn't disappear, but tag as Raw `AgentItem` (not
                // `Error`, since Codex might add benign future requests).
                return vec![TranslateOutput {
                    event: self.raw_event_for_unknown_method(m, frame),
                    rpc_route_hint: None,
                }];
            }
            return Vec::new();
        }

        // Pure JSON-RPC **response** (id but no method) = ack to our own
        // request. Caller (Task 3B's adapter) handles it; translator emits
        // nothing.
        if frame.get("id").is_some() && method.is_none() {
            return Vec::new();
        }

        // Notification (method only). Everything below this point produces
        // route-less events — map through `TranslateOutput { hint: None }`.
        let Some(m) = method else {
            return Vec::new();
        };

        let events: Vec<ServerEvent> = match m {
            "thread/started" => {
                if let Some(id) = thread_id_from_params(&params) {
                    let tid = ThreadId(id.to_string());
                    if self.thread_id.is_none() {
                        self.thread_id = Some(tid.clone());
                    }
                    vec![ServerEvent::SessionStarted {
                        session_id: self.session_id.clone(),
                        thread_id: Some(tid),
                        agent_kind: AgentKind::Codex,
                    }]
                } else {
                    Vec::new()
                }
            }
            "turn/started" => {
                // Pure lifecycle, no neutral counterpart in v2. Capture
                // the threadId opportunistically.
                if let Some(id) = thread_id_from_params(&params)
                    && self.thread_id.is_none()
                {
                    self.thread_id = Some(ThreadId(id.to_string()));
                }
                Vec::new()
            }
            "turn/completed" => vec![self.turn_complete_event(&params)],
            "thread/closed"
            | "thread/archived"
            | "thread/unarchived"
            | "thread/name/updated"
            | "thread/tokenUsage/updated"
            | "thread/status/changed"
            | "thread/goal/cleared"
            | "thread/goal/updated"
            | "thread/compacted"
            | "turn/diff/updated"
            | "turn/plan/updated" => {
                // Lifecycle / panel-only notifications. Task 3B may wire
                // some of these into VendorPanelEvent later; v0.2 ignores.
                Vec::new()
            }
            "item/started" => self.handle_item_started(&params),
            "item/completed" => self.handle_item_completed(&params),
            // Streaming deltas — accumulate, do not emit.
            "item/agentMessage/delta" => {
                self.accumulate_text_delta(&params, InFlightKind::AssistantMessage, "delta");
                Vec::new()
            }
            "item/reasoning/textDelta" | "item/reasoning/summaryTextDelta" => {
                self.accumulate_text_delta(&params, InFlightKind::Reasoning, "delta");
                Vec::new()
            }
            "item/reasoning/summaryPartAdded" => {
                // The summary stream uses discrete parts ({summary: string}).
                self.accumulate_text_delta(&params, InFlightKind::Reasoning, "summary");
                Vec::new()
            }
            "item/commandExecution/outputDelta" => {
                self.accumulate_command_output(&params);
                Vec::new()
            }
            "item/commandExecution/terminalInteraction" => Vec::new(),
            "item/fileChange/outputDelta" | "item/fileChange/patchUpdated" => {
                // We finalize the patch on item/completed; intermediate
                // updates are accumulator-only.
                Vec::new()
            }
            "item/plan/delta" => {
                self.accumulate_text_delta(&params, InFlightKind::Plan, "delta");
                Vec::new()
            }
            "item/mcpToolCall/progress" => Vec::new(),
            "item/autoApprovalReview/started" | "item/autoApprovalReview/completed" => Vec::new(),
            other if other.starts_with("item/") => {
                // Unknown item-level notification. Don't drop; produce a Raw
                // item carrying the method + payload so the issue is
                // visible end-to-end.
                vec![self.raw_event_for_unknown_method(other, &json!({"params": params}))]
            }
            _ => Vec::new(),
        };
        events
            .into_iter()
            .map(|event| TranslateOutput {
                event,
                rpc_route_hint: None,
            })
            .collect()
    }

    // ── item/started ────────────────────────────────────────────────────────

    fn handle_item_started(&mut self, params: &Value) -> Vec<ServerEvent> {
        let Some(item) = params.get("item") else {
            return Vec::new();
        };
        let Some(id) = item.get("id").and_then(Value::as_str).map(str::to_string) else {
            return Vec::new();
        };
        let kind = classify(item);
        let initial_text = match kind {
            InFlightKind::AssistantMessage | InFlightKind::Reasoning => {
                // Codex's `started` payload may carry a non-empty initial
                // snapshot (e.g. a pre-buffered prefix). Seed the
                // accumulator with it so the first delta appends correctly.
                if matches!(kind, InFlightKind::Reasoning) {
                    reasoning_text(item)
                } else {
                    item.get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                }
            }
            _ => String::new(),
        };
        self.in_flight.insert(
            id,
            InFlightItem {
                kind,
                accumulated_text: initial_text,
                last_payload: item.clone(),
            },
        );
        // For shell, emit a Running snapshot immediately so the UI can
        // surface "currently executing" feedback before completion.
        if matches!(kind, InFlightKind::Shell) {
            return vec![self.shell_event(item, ShellStatus::Running)];
        }
        Vec::new()
    }

    // ── item/completed ──────────────────────────────────────────────────────

    fn handle_item_completed(&mut self, params: &Value) -> Vec<ServerEvent> {
        let Some(item) = params.get("item") else {
            return Vec::new();
        };
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        // If we never saw `started`, classify on the fly so completed-only
        // streams (some panel-style items) still surface. Validate shell
        // status before removing state so a rejected terminal cannot turn a
        // later authoritative completion into a completed-only item.
        let completed_kind = classify(item);
        if self
            .in_flight
            .get(&id)
            .is_some_and(|prior| prior.kind != completed_kind)
        {
            return vec![self.error_event(
                "codex-item-kind-mismatch",
                "Codex changed an in-flight item kind".to_owned(),
            )];
        }
        let kind = self
            .in_flight
            .get(&id)
            .map(|p| p.kind)
            .unwrap_or(completed_kind);
        if matches!(kind, InFlightKind::Shell) {
            let status = match shell_status_from(item) {
                Ok(status) => status,
                Err(error) => {
                    return vec![ServerEvent::Error {
                        session_id: Some(self.session_id.clone()),
                        error,
                    }];
                }
            };
            self.in_flight.remove(&id);
            return vec![self.shell_event(item, status)];
        }
        let prior = self.in_flight.remove(&id);
        let accumulated = prior
            .as_ref()
            .map(|p| p.accumulated_text.clone())
            .unwrap_or_default();

        let agent_item = match kind {
            InFlightKind::AssistantMessage => {
                // Prefer Codex's authoritative final text; fall back to our
                // delta accumulator if the completed payload is missing it.
                let text = item
                    .get("text")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .unwrap_or(accumulated);
                AgentItem::AssistantMessage {
                    text,
                    meta: assistant_meta(item),
                }
            }
            InFlightKind::Reasoning => {
                let text = {
                    let final_text = reasoning_text(item);
                    if !final_text.is_empty() {
                        final_text
                    } else {
                        accumulated
                    }
                };
                AgentItem::Reasoning {
                    text,
                    meta: AgentItemMeta::default(),
                }
            }
            InFlightKind::Shell => unreachable!("shell completion returned above"),
            InFlightKind::Diff => {
                let files = diff_files(item);
                AgentItem::Diff {
                    files,
                    meta: AgentItemMeta::default(),
                }
            }
            InFlightKind::Plan => {
                let steps = plan_steps(item, &accumulated);
                AgentItem::Plan {
                    steps,
                    meta: AgentItemMeta::default(),
                }
            }
            InFlightKind::Image => AgentItem::ImageReference {
                saved_path: item
                    .get("savedPath")
                    .or_else(|| item.get("path"))
                    .and_then(Value::as_str)
                    .map(Into::into),
                original_path: item.get("path").and_then(Value::as_str).map(Into::into),
                meta: AgentItemMeta::default(),
            },
            InFlightKind::ToolCall => AgentItem::ToolCall {
                name: tool_name(item),
                args: item.get("arguments").cloned().unwrap_or(Value::Null),
                result: item.get("result").cloned(),
                meta: tool_meta(item),
            },
            InFlightKind::UserMessage => AgentItem::UserMessage {
                text: user_message_text(item),
                meta: AgentItemMeta::default(),
            },
            InFlightKind::Raw => AgentItem::Raw {
                raw_kind: item
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                raw_payload: serde_json::to_string(item).unwrap_or_default(),
                meta: AgentItemMeta::default(),
            },
        };

        vec![self.agent_item_event(agent_item, params)]
    }

    // ── shell event builder (used for both Running + Completed/Failed) ─────

    fn shell_event(&self, item: &Value, status: ShellStatus) -> ServerEvent {
        let cmd = item
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let exit_code = item
            .get("exitCode")
            .and_then(Value::as_i64)
            .map(|v| v as i32);
        let duration_ms = item
            .get("durationMs")
            .and_then(Value::as_i64)
            .and_then(|v| if v < 0 { None } else { Some(v as u64) });
        let item_payload = AgentItem::Shell {
            command: cmd,
            status,
            exit_code,
            duration_ms,
            meta: AgentItemMeta::default(),
        };
        ServerEvent::AgentItem {
            session_id: self.session_id.clone(),
            thread_id: self.resolve_thread_id(item),
            agent_kind: AgentKind::Codex,
            item: item_payload,
        }
    }

    fn agent_item_event(&self, item: AgentItem, params: &Value) -> ServerEvent {
        ServerEvent::AgentItem {
            session_id: self.session_id.clone(),
            thread_id: self.resolve_thread_id(params),
            agent_kind: AgentKind::Codex,
            item,
        }
    }

    // ── turn complete ──────────────────────────────────────────────────────

    fn turn_complete_event(&self, params: &Value) -> ServerEvent {
        let turn = params.get("turn");
        let usage = params.get("usage");
        let summary = TurnSummary {
            total_input_tokens: usage
                .and_then(|u| u.get("inputTokens"))
                .and_then(Value::as_u64),
            total_output_tokens: usage
                .and_then(|u| u.get("outputTokens"))
                .and_then(Value::as_u64),
            elapsed_ms: params
                .get("durationMs")
                .and_then(Value::as_u64)
                .or_else(|| {
                    turn.and_then(|value| value.get("durationMs"))
                        .and_then(Value::as_u64)
                })
                .unwrap_or(0),
        };
        ServerEvent::TurnComplete {
            session_id: self.session_id.clone(),
            thread_id: self.resolve_thread_id(params),
            agent_kind: AgentKind::Codex,
            summary,
        }
    }

    // ── delta accumulators ─────────────────────────────────────────────────

    fn accumulate_text_delta(&mut self, params: &Value, kind: InFlightKind, field: &str) {
        let Some(id) = params.get("itemId").and_then(Value::as_str) else {
            return;
        };
        let delta = params.get(field).and_then(Value::as_str).unwrap_or("");
        let slot = self
            .in_flight
            .entry(id.to_string())
            .or_insert_with(|| InFlightItem {
                kind,
                accumulated_text: String::new(),
                last_payload: json!({}),
            });
        // Keep the original kind if we already classified it on `started`.
        if matches!(slot.kind, InFlightKind::Raw) {
            slot.kind = kind;
        }
        slot.accumulated_text.push_str(delta);
    }

    fn accumulate_command_output(&mut self, params: &Value) {
        let Some(id) = params.get("itemId").and_then(Value::as_str) else {
            return;
        };
        let raw = params
            .get("deltaBase64")
            .and_then(Value::as_str)
            .and_then(decode_base64)
            .or_else(|| {
                params
                    .get("delta")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let slot = self
            .in_flight
            .entry(id.to_string())
            .or_insert_with(|| InFlightItem {
                kind: InFlightKind::Shell,
                accumulated_text: String::new(),
                last_payload: json!({}),
            });
        slot.accumulated_text.push_str(&raw);
    }

    // ── approval / action request ──────────────────────────────────────────

    fn approval_to_action_request(
        &mut self,
        method: &str,
        params: &Value,
        id_hint: Option<&Value>,
    ) -> Option<ActionRequest> {
        let (kind, summary) = match method {
            "item/commandExecution/requestApproval" => {
                let cmd = params.get("command").and_then(Value::as_str).unwrap_or("");
                let cwd = params.get("cwd").and_then(Value::as_str).unwrap_or("");
                let summary = if cwd.is_empty() {
                    format!("Run: {cmd}")
                } else {
                    format!("Run: {cmd} (cwd: {cwd})")
                };
                (ActionKind::ExecuteCommand, summary)
            }
            "item/fileChange/requestApproval" => {
                let root = params
                    .get("grantRoot")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let summary = if root.is_empty() {
                    "Apply file changes".to_string()
                } else {
                    format!("Apply file changes under {root}")
                };
                (ActionKind::EditFiles, summary)
            }
            "item/permissions/requestApproval" => {
                let cwd = params.get("cwd").and_then(Value::as_str).unwrap_or("");
                let summary = if cwd.is_empty() {
                    "Grant additional permissions".to_string()
                } else {
                    format!("Grant additional permissions (cwd: {cwd})")
                };
                (ActionKind::GrantExtraPermission, summary)
            }
            "item/tool/requestUserInput" => {
                let summary = params
                    .get("prompt")
                    .and_then(Value::as_str)
                    .unwrap_or("User input requested")
                    .to_string();
                // Treat as ExtraPermission (no closer fit; UI renders the
                // vendor block for context).
                (ActionKind::GrantExtraPermission, summary)
            }
            _ => return None,
        };

        let request_id = params
            .get("approvalId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| id_hint.and_then(|v| v.as_str().map(str::to_string)))
            .or_else(|| id_hint.and_then(|v| v.as_u64().map(|n| n.to_string())))
            .unwrap_or_else(|| {
                let n = self.next_request_id;
                self.next_request_id += 1;
                format!("codex-req-{n}")
            });

        Some(ActionRequest {
            request_id,
            kind,
            summary,
            vendor: ActionRequestVendor::Codex {
                approval_policy_at_decision: self.approval_policy,
                sandbox_at_decision: self.sandbox,
                can_persist: self.persist_supported,
            },
        })
    }

    // ── helpers ────────────────────────────────────────────────────────────

    fn resolve_thread_id(&self, params: &Value) -> ThreadId {
        if let Some(id) = thread_id_from_params(params) {
            return ThreadId(id.to_string());
        }
        self.thread_id
            .clone()
            .unwrap_or_else(|| ThreadId(String::new()))
    }

    fn error_event(&self, code: &str, message: String) -> ServerEvent {
        ServerEvent::Error {
            session_id: Some(self.session_id.clone()),
            error: ProtocolError {
                code: code.to_string(),
                message,
                diagnostic_ref: None,
            },
        }
    }

    fn raw_event_for_unknown_method(&self, method: &str, frame: &Value) -> ServerEvent {
        let raw_payload = serde_json::to_string(frame).unwrap_or_default();
        ServerEvent::AgentItem {
            session_id: self.session_id.clone(),
            thread_id: self.resolve_thread_id(frame),
            agent_kind: AgentKind::Codex,
            item: AgentItem::Raw {
                raw_kind: method.to_string(),
                raw_payload,
                meta: AgentItemMeta::default(),
            },
        }
    }
}

fn thread_id_from_params(params: &Value) -> Option<&str> {
    params
        .get("threadId")
        .and_then(Value::as_str)
        .or_else(|| {
            params
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            params
                .get("item")
                .and_then(|item| item.get("threadId"))
                .and_then(Value::as_str)
        })
}

// ── classification + field extraction helpers ───────────────────────────────

pub(super) fn classify(item: &Value) -> InFlightKind {
    match item.get("type").and_then(Value::as_str).unwrap_or("") {
        "agentMessage" => InFlightKind::AssistantMessage,
        "reasoning" => InFlightKind::Reasoning,
        "commandExecution" => InFlightKind::Shell,
        "fileChange" => InFlightKind::Diff,
        "plan" => InFlightKind::Plan,
        "imageView" | "imageGeneration" => InFlightKind::Image,
        "mcpToolCall" | "dynamicToolCall" | "collabAgentToolCall" | "webSearch" => {
            InFlightKind::ToolCall
        }
        "userMessage" => InFlightKind::UserMessage,
        _ => InFlightKind::Raw,
    }
}

pub(super) fn assistant_meta(item: &Value) -> AgentItemMeta {
    let mut meta = AgentItemMeta::default();
    if let Some(phase) = item.get("phase") {
        meta.vendor_extensions
            .insert("phase".to_string(), phase.clone());
    }
    if let Some(citation) = item.get("memoryCitation").filter(|value| !value.is_null()) {
        meta.vendor_extensions
            .insert("memoryCitation".to_string(), citation.clone());
    }
    meta
}

pub(super) fn tool_meta(item: &Value) -> AgentItemMeta {
    let mut meta = AgentItemMeta::default();
    for key in [
        "server",
        "tool",
        "namespace",
        "status",
        "durationMs",
        "mcpAppResourceUri",
    ] {
        if let Some(v) = item.get(key) {
            meta.vendor_extensions.insert(key.to_string(), v.clone());
        }
    }
    if let Some(kind) = item.get("type").and_then(Value::as_str) {
        meta.vendor_extensions
            .insert("codexToolKind".to_string(), json!(kind));
    }
    meta
}

pub(super) fn tool_name(item: &Value) -> String {
    item.get("tool")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| item.get("name").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| {
            item.get("type")
                .and_then(Value::as_str)
                .unwrap_or("tool")
                .to_string()
        })
}

pub(super) fn reasoning_text(item: &Value) -> String {
    fn join(arr: Option<&Value>) -> String {
        arr.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n\n")
            })
            .unwrap_or_default()
    }
    let summary = join(item.get("summary"));
    if !summary.is_empty() {
        return summary;
    }
    join(item.get("content"))
}

pub(super) fn user_message_text(item: &Value) -> String {
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

pub(super) fn shell_status_from(item: &Value) -> Result<ShellStatus, ProtocolError> {
    match item.get("status").and_then(Value::as_str) {
        Some("completed") => Ok(ShellStatus::Completed),
        Some("failed") => Ok(ShellStatus::Failed),
        Some("declined") => Ok(ShellStatus::Canceled),
        Some("inProgress") => Err(ProtocolError {
            code: "codex-shell-terminal-status-invalid".to_owned(),
            message: "Codex completed a command with a non-terminal status".to_owned(),
            diagnostic_ref: None,
        }),
        Some(_) | None => Err(ProtocolError {
            code: "codex-shell-terminal-status-invalid".to_owned(),
            message: "Codex completed a command without an authoritative terminal status"
                .to_owned(),
            diagnostic_ref: None,
        }),
    }
}

pub(super) fn diff_files(item: &Value) -> Vec<DiffFile> {
    item.get("changes")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|change| {
                    let path = change
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let status = match change.get("kind").and_then(Value::as_str).unwrap_or("") {
                        "add" | "added" | "create" => DiffStatus::Added,
                        "delete" | "deleted" | "remove" => DiffStatus::Deleted,
                        "rename" | "renamed" => DiffStatus::Renamed,
                        _ => DiffStatus::Modified,
                    };
                    DiffFile {
                        path: std::path::PathBuf::from(path),
                        status,
                        patch: change
                            .get("diff")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn plan_steps(item: &Value, accumulated: &str) -> Vec<PlanStep> {
    // Codex's `plan` item carries a single freeform `text` field. Split on
    // lines as a minimal v0.2 surface (UI can render the raw text via the
    // single-step title if that's all we get).
    let source = item
        .get("text")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| accumulated.to_string());
    if source.is_empty() {
        return Vec::new();
    }
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| PlanStep {
            title: line.to_string(),
            status: PlanStepStatus::Pending,
            detail: None,
        })
        .collect()
}

/// Minimal standard-base64 decoder (boring, no extra crate). Matches the v1
/// helper byte-for-byte so a future audit catches drift.
pub(super) fn decode_base64(s: &str) -> Option<String> {
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

    fn tr() -> CodexTranslator {
        let mut t = CodexTranslator::new(SessionId("s1".into()), None);
        t.set_thread_id(ThreadId("thread_1".into()));
        t
    }

    #[test]
    fn assistant_message_delta_does_not_emit_until_completed() {
        let mut t = tr();
        let started = json!({
            "method": "item/started",
            "params": {
                "item": {"id": "msg1", "type": "agentMessage", "text": ""},
                "threadId": "thread_1"
            }
        });
        let d1 = json!({
            "method": "item/agentMessage/delta",
            "params": {"itemId": "msg1", "delta": "Hel", "threadId": "thread_1"}
        });
        let d2 = json!({
            "method": "item/agentMessage/delta",
            "params": {"itemId": "msg1", "delta": "lo!", "threadId": "thread_1"}
        });
        // Started + deltas emit nothing.
        assert!(t.translate_value(&started).is_empty());
        assert!(t.translate_value(&d1).is_empty());
        assert!(t.translate_value(&d2).is_empty());
        // Completion emits exactly one AssistantMessage with cumulative text.
        let completed = json!({
            "method": "item/completed",
            "params": {
                "item": {"id": "msg1", "type": "agentMessage", "text": "Hello!"},
                "threadId": "thread_1"
            }
        });
        let events = t.translate_value(&completed);
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::AgentItem {
                item: AgentItem::AssistantMessage { text, .. },
                agent_kind,
                thread_id,
                ..
            } => {
                assert_eq!(text, "Hello!");
                assert_eq!(*agent_kind, AgentKind::Codex);
                assert_eq!(thread_id.0, "thread_1");
            }
            other => panic!("expected AssistantMessage, got {other:?}"),
        }
    }

    #[test]
    fn assistant_message_falls_back_to_delta_accumulator_when_complete_text_empty() {
        let mut t = tr();
        t.translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"id": "m", "type": "agentMessage", "text": ""}}
        }));
        t.translate_value(&json!({
            "method": "item/agentMessage/delta",
            "params": {"itemId": "m", "delta": "from-delta"}
        }));
        let events = t.translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {"id": "m", "type": "agentMessage", "text": ""}}
        }));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::AgentItem {
                item: AgentItem::AssistantMessage { text, .. },
                ..
            } => assert_eq!(text, "from-delta"),
            other => panic!("expected AssistantMessage, got {other:?}"),
        }
    }

    #[test]
    fn reasoning_stream_uses_summary_then_content() {
        let mut t = tr();
        t.translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"id": "r1", "type": "reasoning",
                                "summary": [], "content": []}}
        }));
        t.translate_value(&json!({
            "method": "item/reasoning/textDelta",
            "params": {"itemId": "r1", "delta": "thinking..."}
        }));
        // completed payload provides authoritative summary
        let events = t.translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {"id": "r1", "type": "reasoning",
                                "summary": ["A digest"], "content": ["full chain"]}}
        }));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::AgentItem {
                item: AgentItem::Reasoning { text, .. },
                ..
            } => assert_eq!(text, "A digest"),
            other => panic!("expected Reasoning, got {other:?}"),
        }
    }

    #[test]
    fn shell_execution_emits_running_then_completed() {
        let mut t = tr();
        let started = t.translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"id": "c1", "type": "commandExecution",
                                "command": "ls -la"}}
        }));
        // Running snapshot on `started`.
        assert_eq!(started.len(), 1);
        match &started[0] {
            ServerEvent::AgentItem {
                item: AgentItem::Shell {
                    command, status, ..
                },
                ..
            } => {
                assert_eq!(command, "ls -la");
                assert!(matches!(status, ShellStatus::Running));
            }
            other => panic!("expected Shell(Running), got {other:?}"),
        }
        let completed = t.translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "id": "c1", "type": "commandExecution",
                "command": "ls -la", "status": "completed",
                "exitCode": 0, "durationMs": 12
            }}
        }));
        assert_eq!(completed.len(), 1);
        match &completed[0] {
            ServerEvent::AgentItem {
                item:
                    AgentItem::Shell {
                        status,
                        exit_code,
                        duration_ms,
                        ..
                    },
                ..
            } => {
                assert!(matches!(status, ShellStatus::Completed));
                assert_eq!(*exit_code, Some(0));
                assert_eq!(*duration_ms, Some(12));
            }
            other => panic!("expected Shell(Completed), got {other:?}"),
        }
    }

    #[test]
    fn compatibility_shell_terminal_status_is_exact_and_rejection_keeps_state() {
        // 威胁场景：compatibility adapter 若继续把 declined/未知状态降级成成功，
        // 同一官方 frame 会在 canonical 与旧入口产生相反的用户可见结果。
        for (status, expected) in [
            ("completed", "completed"),
            ("failed", "failed"),
            ("declined", "canceled"),
        ] {
            let mut t = tr();
            t.translate_value(&json!({
                "method": "item/started",
                "params": {"item": {
                    "id": "compat-shell",
                    "type": "commandExecution",
                    "command": "pwd"
                }}
            }));
            let events = t.translate_value(&json!({
                "method": "item/completed",
                "params": {"item": {
                    "id": "compat-shell",
                    "type": "commandExecution",
                    "command": "pwd",
                    "status": status
                }}
            }));
            let [
                ServerEvent::AgentItem {
                    item: AgentItem::Shell { status, .. },
                    ..
                },
            ] = events.as_slice()
            else {
                panic!("expected compatibility shell terminal")
            };
            assert!(match expected {
                "completed" => matches!(status, ShellStatus::Completed),
                "failed" => matches!(status, ShellStatus::Failed),
                "canceled" => matches!(status, ShellStatus::Canceled),
                other => panic!("unmodeled expected shell status: {other}"),
            });
        }

        for status in [Some("inProgress"), Some("success"), None] {
            let mut t = tr();
            t.translate_value(&json!({
                "method": "item/started",
                "params": {"item": {
                    "id": "compat-invalid",
                    "type": "commandExecution",
                    "command": "pwd"
                }}
            }));
            let mut terminal = json!({
                "method": "item/completed",
                "params": {"item": {
                    "id": "compat-invalid",
                    "type": "commandExecution",
                    "command": "pwd"
                }}
            });
            if let Some(status) = status {
                terminal["params"]["item"]["status"] = json!(status);
            }
            let rejected = t.translate_value(&terminal);
            assert!(matches!(
                rejected.as_slice(),
                [ServerEvent::Error { error, .. }]
                    if error.code == "codex-shell-terminal-status-invalid"
            ));
            assert!(t.in_flight.contains_key("compat-invalid"));

            let recovered = t.translate_value(&json!({
                "method": "item/completed",
                "params": {"item": {
                    "id": "compat-invalid",
                    "type": "commandExecution",
                    "command": "pwd",
                    "status": "completed"
                }}
            }));
            assert!(matches!(
                recovered.as_slice(),
                [ServerEvent::AgentItem {
                    item: AgentItem::Shell {
                        status: ShellStatus::Completed,
                        ..
                    },
                    ..
                }]
            ));
        }
    }

    #[test]
    fn compatibility_completion_kind_mismatch_preserves_the_started_item() {
        let mut t = tr();
        t.translate_value(&json!({
            "method": "item/started",
            "params": {"item": {
                "id": "compat-kind",
                "type": "commandExecution",
                "command": "pwd"
            }}
        }));

        let rejected = t.translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "id": "compat-kind",
                "type": "agentMessage",
                "text": "fabricated type flip"
            }}
        }));
        assert!(matches!(
            rejected.as_slice(),
            [ServerEvent::Error { error, .. }] if error.code == "codex-item-kind-mismatch"
        ));
        assert!(t.in_flight.contains_key("compat-kind"));

        let recovered = t.translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "id": "compat-kind",
                "type": "commandExecution",
                "command": "pwd",
                "status": "declined"
            }}
        }));
        assert!(matches!(
            recovered.as_slice(),
            [ServerEvent::AgentItem {
                item: AgentItem::Shell {
                    status: ShellStatus::Canceled,
                    ..
                },
                ..
            }]
        ));
        assert!(!t.in_flight.contains_key("compat-kind"));
    }

    #[test]
    fn approval_request_emits_action_request_with_codex_vendor_block() {
        let mut t = CodexTranslator::with_policy(
            SessionId("s1".into()),
            Some(ThreadId("thread_1".into())),
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            true,
        );
        let req = json!({
            "id": 7,
            "method": "item/commandExecution/requestApproval",
            "params": {
                "itemId": "c1",
                "approvalId": "appr-1",
                "command": "rm -rf /tmp/x",
                "cwd": "/tmp",
                "reason": "test",
                "threadId": "thread_1"
            }
        });
        let events = t.translate_value(&req);
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::ActionRequest {
                request,
                agent_kind,
                ..
            } => {
                assert_eq!(*agent_kind, AgentKind::Codex);
                assert_eq!(request.request_id, "appr-1");
                assert!(matches!(request.kind, ActionKind::ExecuteCommand));
                assert!(request.summary.contains("rm -rf /tmp/x"));
                match request.vendor {
                    ActionRequestVendor::Codex {
                        approval_policy_at_decision,
                        sandbox_at_decision,
                        can_persist,
                    } => {
                        assert_eq!(approval_policy_at_decision, CodexApprovalPolicy::OnRequest);
                        assert_eq!(sandbox_at_decision, CodexSandboxMode::WorkspaceWrite);
                        assert!(can_persist);
                    }
                    _ => panic!("expected Codex vendor block"),
                }
            }
            other => panic!("expected ActionRequest, got {other:?}"),
        }
    }

    #[test]
    fn malformed_json_yields_error_event() {
        let mut t = tr();
        let events = t.translate_line("{not json");
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::Error { error, .. } => {
                assert_eq!(error.code, "codex-malformed-json");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_item_type_falls_back_to_raw_on_completion() {
        let mut t = tr();
        let events = t.translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {"id": "x", "type": "newFutureItem",
                                "vendorSecret": "do-not-care"}}
        }));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::AgentItem {
                item:
                    AgentItem::Raw {
                        raw_kind,
                        raw_payload,
                        ..
                    },
                ..
            } => {
                assert_eq!(raw_kind, "newFutureItem");
                assert!(raw_payload.contains("newFutureItem"));
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn thread_started_captures_thread_id_and_emits_session_started() {
        let mut t = CodexTranslator::new(SessionId("s1".into()), None);
        let events = t.translate_value(&json!({
            "method": "thread/started",
            "params": {"threadId": "thread_abc"}
        }));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::SessionStarted {
                thread_id,
                agent_kind,
                ..
            } => {
                assert_eq!(thread_id.as_ref().unwrap().0, "thread_abc");
                assert_eq!(*agent_kind, AgentKind::Codex);
            }
            other => panic!("expected SessionStarted, got {other:?}"),
        }
        assert_eq!(t.thread_id().unwrap().0, "thread_abc");
    }

    #[test]
    fn current_thread_started_nested_shape_captures_thread_id() {
        let mut t = CodexTranslator::new(SessionId("s-current".into()), None);
        let events = t.translate_value(&json!({
            "method": "thread/started",
            "params": {"thread": {"id": "thread_current", "status": "idle"}}
        }));
        assert!(matches!(
            events.as_slice(),
            [ServerEvent::SessionStarted { thread_id: Some(thread_id), .. }]
                if thread_id.0 == "thread_current"
        ));
        assert_eq!(
            t.thread_id().map(|thread| thread.0.as_str()),
            Some("thread_current")
        );
    }

    #[test]
    fn turn_completed_emits_turn_complete_with_usage() {
        let mut t = tr();
        let events = t.translate_value(&json!({
            "method": "turn/completed",
            "params": {
                "threadId": "thread_1",
                "durationMs": 1234,
                "usage": {"inputTokens": 100, "outputTokens": 50}
            }
        }));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::TurnComplete { summary, .. } => {
                assert_eq!(summary.elapsed_ms, 1234);
                assert_eq!(summary.total_input_tokens, Some(100));
                assert_eq!(summary.total_output_tokens, Some(50));
            }
            other => panic!("expected TurnComplete, got {other:?}"),
        }
    }

    #[test]
    fn current_turn_completed_nested_shape_preserves_recorded_duration_only() {
        let mut t = tr();
        let events = t.translate_value(&json!({
            "method": "turn/completed",
            "params": {
                "threadId": "thread_1",
                "turn": {
                    "id": "turn_1",
                    "status": "completed",
                    "durationMs": 123
                }
            }
        }));
        assert!(matches!(
            events.as_slice(),
            [ServerEvent::TurnComplete { summary, .. }]
                if summary.elapsed_ms == 123
                    && summary.total_input_tokens.is_none()
                    && summary.total_output_tokens.is_none()
        ));
    }

    #[test]
    fn error_frame_emits_error_event() {
        let mut t = tr();
        let events = t.translate_value(&json!({
            "id": 1,
            "error": {"code": -32601, "message": "method not found"}
        }));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::Error { error, .. } => {
                assert_eq!(error.code, "codex-protocol-error");
                assert_eq!(error.message, "method not found");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_notifications_yield_no_events() {
        let mut t = tr();
        assert!(
            t.translate_value(&json!({"method": "thread/tokenUsage/updated", "params": {}}))
                .is_empty()
        );
        assert!(
            t.translate_value(&json!({"method": "turn/started", "params": {}}))
                .is_empty()
        );
        assert!(
            t.translate_value(&json!({"method": "thread/closed", "params": {}}))
                .is_empty()
        );
    }

    #[test]
    fn file_change_completes_to_diff() {
        let mut t = tr();
        t.translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"id": "f1", "type": "fileChange"}}
        }));
        let events = t.translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "id": "f1", "type": "fileChange",
                "changes": [
                    {"path": "a.txt", "diff": "+a\n", "kind": "add"},
                    {"path": "b.txt", "diff": "-b\n", "kind": "delete"}
                ]
            }}
        }));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerEvent::AgentItem {
                item: AgentItem::Diff { files, .. },
                ..
            } => {
                assert_eq!(files.len(), 2);
                assert!(matches!(files[0].status, DiffStatus::Added));
                assert!(matches!(files[1].status, DiffStatus::Deleted));
            }
            other => panic!("expected Diff, got {other:?}"),
        }
    }

    #[test]
    fn base64_decoder_round_trips_ascii() {
        assert_eq!(decode_base64("aGVsbG8="), Some("hello".into()));
        assert_eq!(decode_base64("Zm9v"), Some("foo".into()));
        assert!(decode_base64("!!!not base64").is_none());
    }
}
