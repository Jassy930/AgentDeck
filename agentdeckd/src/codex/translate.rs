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
//! Unknown `item/*` notifications: surface as `AgentItem::Raw` with a bounded
//! method/type identifier and a fixed withheld placeholder. Vendor JSON stays
//! inside the adapter. Unknown non-`item/` lifecycle notifications
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

#[derive(Debug, Clone, Copy)]
enum InFlightKind {
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
                        format!("malformed codex frame: {e}: {trimmed}"),
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
                if let Some(id) = params.get("threadId").and_then(Value::as_str) {
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
                if let Some(id) = params.get("threadId").and_then(Value::as_str) {
                    if self.thread_id.is_none() {
                        self.thread_id = Some(ThreadId(id.to_string()));
                    }
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
                // item carrying only a bounded identifier and fixed withheld
                // placeholder so the issue stays visible without vendor JSON.
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
        // streams (some panel-style items) still surface.
        let prior = self.in_flight.remove(&id);
        let kind = prior
            .as_ref()
            .map(|p| p.kind)
            .unwrap_or_else(|| classify(item));
        let accumulated = prior
            .as_ref()
            .map(|p| p.accumulated_text.clone())
            .unwrap_or_default();
        if matches!(kind, InFlightKind::Shell) {
            return vec![self.shell_event(item, shell_status_from(item))];
        }
        let agent_item = completed_item_to_agent_item(item, kind, &accumulated);

        vec![self.agent_item_event(agent_item, params)]
    }

    // ── shell event builder (used for both Running + Completed/Failed) ─────

    fn shell_event(&self, item: &Value, status: ShellStatus) -> ServerEvent {
        ServerEvent::AgentItem {
            session_id: self.session_id.clone(),
            thread_id: self.resolve_thread_id(item),
            agent_kind: AgentKind::Codex,
            item: shell_agent_item(item, status),
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
        if let Some(id) = params.get("threadId").and_then(Value::as_str) {
            return ThreadId(id.to_string());
        }
        if let Some(id) = params
            .get("item")
            .and_then(|i| i.get("threadId"))
            .and_then(Value::as_str)
        {
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
        ServerEvent::AgentItem {
            session_id: self.session_id.clone(),
            thread_id: self.resolve_thread_id(frame),
            agent_kind: AgentKind::Codex,
            item: AgentItem::Raw {
                raw_kind: safe_vendor_identifier(method),
                raw_payload: WITHHELD_VENDOR_RAW_PAYLOAD.into(),
                meta: AgentItemMeta::default(),
            },
        }
    }
}

// ── classification + field extraction helpers ───────────────────────────────

const WITHHELD_VENDOR_RAW_PAYLOAD: &str = "[vendor payload withheld]";
const MAX_VENDOR_IDENTIFIER_BYTES: usize = 64;

fn safe_vendor_identifier(identifier: &str) -> String {
    if !identifier.is_empty()
        && identifier.len() <= MAX_VENDOR_IDENTIFIER_BYTES
        && identifier.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/')
        })
    {
        identifier.to_string()
    } else {
        "unknown".into()
    }
}

fn classify(item: &Value) -> InFlightKind {
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

/// Map one fully materialized `ThreadItem` from `thread/read` through the
/// same completed-item mapping used by the live notification stream.
pub(super) fn history_item_to_agent_item(item: &Value) -> AgentItem {
    completed_item_to_agent_item(item, classify(item), "")
}

fn completed_item_to_agent_item(item: &Value, kind: InFlightKind, accumulated: &str) -> AgentItem {
    match kind {
        InFlightKind::AssistantMessage => {
            // Prefer Codex's authoritative final text; fall back to the live
            // delta accumulator when an item/completed payload is sparse.
            let text = item
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .unwrap_or(accumulated)
                .to_string();
            AgentItem::AssistantMessage {
                text,
                meta: assistant_meta(item),
            }
        }
        InFlightKind::Reasoning => {
            let final_text = reasoning_text(item);
            AgentItem::Reasoning {
                text: if final_text.is_empty() {
                    accumulated.to_string()
                } else {
                    final_text
                },
                meta: AgentItemMeta::default(),
            }
        }
        InFlightKind::Shell => shell_agent_item(item, shell_status_from(item)),
        InFlightKind::Diff => AgentItem::Diff {
            files: diff_files(item),
            meta: AgentItemMeta::default(),
        },
        InFlightKind::Plan => AgentItem::Plan {
            steps: plan_steps(item, accumulated),
            meta: AgentItemMeta::default(),
        },
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
            args: tool_args(item),
            result: tool_result(item),
            meta: tool_meta(item),
        },
        InFlightKind::UserMessage => AgentItem::UserMessage {
            text: user_message_text(item),
            meta: AgentItemMeta::default(),
        },
        InFlightKind::Raw => AgentItem::Raw {
            raw_kind: safe_vendor_identifier(
                item.get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            ),
            raw_payload: WITHHELD_VENDOR_RAW_PAYLOAD.into(),
            meta: AgentItemMeta::default(),
        },
    }
}

fn shell_agent_item(item: &Value, status: ShellStatus) -> AgentItem {
    let command = item
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let exit_code = item
        .get("exitCode")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok());
    let duration_ms = item
        .get("durationMs")
        .and_then(Value::as_i64)
        .and_then(|value| u64::try_from(value).ok());
    AgentItem::Shell {
        command,
        status,
        exit_code,
        duration_ms,
        meta: AgentItemMeta::default(),
    }
}

fn assistant_meta(item: &Value) -> AgentItemMeta {
    let mut meta = AgentItemMeta::default();
    if let Some(phase) = item.get("phase") {
        meta.vendor_extensions
            .insert("phase".to_string(), phase.clone());
    }
    if let Some(citation) = item.get("memoryCitation") {
        meta.vendor_extensions
            .insert("memoryCitation".to_string(), citation.clone());
    }
    meta
}

fn tool_meta(item: &Value) -> AgentItemMeta {
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

fn tool_name(item: &Value) -> String {
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

fn object_with_present_fields(item: &Value, fields: &[&str]) -> Value {
    let mut object = serde_json::Map::new();
    for field in fields {
        if let Some(value) = item.get(*field) {
            object.insert((*field).to_string(), value.clone());
        }
    }
    Value::Object(object)
}

fn tool_args(item: &Value) -> Value {
    match item.get("type").and_then(Value::as_str).unwrap_or("") {
        "webSearch" => object_with_present_fields(item, &["query", "action"]),
        "collabAgentToolCall" => object_with_present_fields(
            item,
            &[
                "prompt",
                "model",
                "reasoningEffort",
                "receiverThreadIds",
                "senderThreadId",
            ],
        ),
        _ => item.get("arguments").cloned().unwrap_or(Value::Null),
    }
}

fn tool_result(item: &Value) -> Option<Value> {
    match item.get("type").and_then(Value::as_str).unwrap_or("") {
        "dynamicToolCall" => Some(object_with_present_fields(
            item,
            &["contentItems", "success"],
        )),
        "webSearch" => Some(object_with_present_fields(item, &["results"])),
        "collabAgentToolCall" => Some(object_with_present_fields(item, &["agentsStates"])),
        _ => item.get("result").cloned(),
    }
}

fn reasoning_text(item: &Value) -> String {
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

fn user_message_text(item: &Value) -> String {
    item.get("content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .filter_map(user_input_text)
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_default()
}

/// Keep every official `UserInput` variant visible in history replay. The
/// neutral protocol only has a text user-message today, so non-text inputs use
/// compact readable references instead of silently becoming an empty message.
fn user_input_text(part: &Value) -> Option<String> {
    let kind = part.get("type").and_then(Value::as_str)?;
    match kind {
        "text" => part.get("text").and_then(Value::as_str).map(str::to_string),
        "image" => part
            .get("url")
            .and_then(Value::as_str)
            .map(|value| format!("[image: {value}]")),
        "localImage" => part
            .get("path")
            .and_then(Value::as_str)
            .map(|value| format!("[local image: {value}]")),
        "audio" => part
            .get("url")
            .and_then(Value::as_str)
            .map(|value| format!("[audio: {value}]")),
        "localAudio" => part
            .get("path")
            .and_then(Value::as_str)
            .map(|value| format!("[local audio: {value}]")),
        "skill" | "mention" => {
            let name = part.get("name").and_then(Value::as_str).unwrap_or(kind);
            let path = part.get("path").and_then(Value::as_str).unwrap_or("");
            Some(if path.is_empty() {
                format!("[{kind}: {name}]")
            } else {
                format!("[{kind}: {name} ({path})]")
            })
        }
        other => Some(format!("[unsupported input: {other}]")),
    }
}

fn shell_status_from(item: &Value) -> ShellStatus {
    let status = item.get("status").and_then(Value::as_str).unwrap_or("");
    match status {
        "inProgress" => ShellStatus::Running,
        "completed" | "success" => ShellStatus::Completed,
        "failed" | "error" => ShellStatus::Failed,
        "canceled" | "cancelled" | "declined" => ShellStatus::Canceled,
        _ => {
            // Fall back to exit code when status is missing/unknown.
            match item.get("exitCode").and_then(Value::as_i64) {
                Some(0) => ShellStatus::Completed,
                Some(_) => ShellStatus::Failed,
                None => ShellStatus::Completed,
            }
        }
    }
}

fn diff_files(item: &Value) -> Vec<DiffFile> {
    item.get("changes")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|change| {
                    let original_path = change
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let kind_value = change.get("kind");
                    let kind = kind_value
                        .and_then(Value::as_str)
                        .or_else(|| {
                            kind_value
                                .and_then(Value::as_object)
                                .and_then(|object| object.get("type"))
                                .and_then(Value::as_str)
                        })
                        .unwrap_or("");
                    let move_path = kind_value
                        .and_then(Value::as_object)
                        .and_then(|object| object.get("move_path"))
                        .and_then(Value::as_str);
                    let status = match kind {
                        "add" | "added" | "create" => DiffStatus::Added,
                        "delete" | "deleted" | "remove" => DiffStatus::Deleted,
                        "rename" | "renamed" => DiffStatus::Renamed,
                        "update" if move_path.is_some() => DiffStatus::Renamed,
                        _ => DiffStatus::Modified,
                    };
                    DiffFile {
                        path: std::path::PathBuf::from(move_path.unwrap_or(&original_path)),
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

fn plan_steps(item: &Value, accumulated: &str) -> Vec<PlanStep> {
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
    fn completed_shell_mapping_preserves_in_progress_and_declined_statuses() {
        let in_progress = history_item_to_agent_item(&json!({
            "id": "shell-running",
            "type": "commandExecution",
            "command": "sleep 1",
            "status": "inProgress"
        }));
        assert!(matches!(
            in_progress,
            AgentItem::Shell {
                status: ShellStatus::Running,
                ..
            }
        ));

        let declined = history_item_to_agent_item(&json!({
            "id": "shell-declined",
            "type": "commandExecution",
            "command": "rm file",
            "status": "declined"
        }));
        assert!(matches!(
            declined,
            AgentItem::Shell {
                status: ShellStatus::Canceled,
                ..
            }
        ));
    }

    #[test]
    fn shared_tool_mapping_preserves_official_web_dynamic_and_collab_fields() {
        let web = history_item_to_agent_item(&json!({
            "id": "web-1",
            "type": "webSearch",
            "query": "rust app-server",
            "action": { "type": "search", "query": "rust app-server" },
            "results": [{ "url": "https://example.com" }]
        }));
        match web {
            AgentItem::ToolCall {
                name, args, result, ..
            } => {
                assert_eq!(name, "webSearch");
                assert_eq!(args["query"], "rust app-server");
                assert_eq!(args["action"]["type"], "search");
                assert_eq!(
                    result.expect("web result")["results"][0]["url"],
                    "https://example.com"
                );
            }
            other => panic!("expected web ToolCall, got {other:?}"),
        }

        let dynamic = history_item_to_agent_item(&json!({
            "id": "dynamic-1",
            "type": "dynamicToolCall",
            "tool": "lookup",
            "arguments": { "key": "value" },
            "contentItems": [{ "type": "inputText", "text": "found" }],
            "success": true,
            "status": "completed"
        }));
        match dynamic {
            AgentItem::ToolCall {
                name, args, result, ..
            } => {
                assert_eq!(name, "lookup");
                assert_eq!(args["key"], "value");
                let result = result.expect("dynamic result");
                assert_eq!(result["contentItems"][0]["text"], "found");
                assert_eq!(result["success"], true);
            }
            other => panic!("expected dynamic ToolCall, got {other:?}"),
        }

        let collab = history_item_to_agent_item(&json!({
            "id": "collab-1",
            "type": "collabAgentToolCall",
            "tool": "spawnAgent",
            "prompt": "review this",
            "receiverThreadIds": ["child-1"],
            "senderThreadId": "parent-1",
            "agentsStates": {
                "child-1": { "status": "completed", "message": null }
            },
            "status": "completed"
        }));
        match collab {
            AgentItem::ToolCall {
                name, args, result, ..
            } => {
                assert_eq!(name, "spawnAgent");
                assert_eq!(args["prompt"], "review this");
                assert_eq!(args["receiverThreadIds"][0], "child-1");
                assert_eq!(args["senderThreadId"], "parent-1");
                assert_eq!(
                    result.expect("collab result")["agentsStates"]["child-1"]["status"],
                    "completed"
                );
            }
            other => panic!("expected collab ToolCall, got {other:?}"),
        }
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
                                "vendorSecret": "sk-history-secret-must-not-cross-k9"}}
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
                assert_eq!(raw_payload, WITHHELD_VENDOR_RAW_PAYLOAD);
                assert!(!raw_payload.contains("sk-history-secret"));
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn unknown_history_item_keeps_only_safe_type_and_fixed_placeholder() {
        let item = history_item_to_agent_item(&json!({
            "id": "future-1",
            "type": "futureItemV2",
            "vendorSecret": "sk-history-secret-must-not-cross-k9",
            "nested": { "token": "vendor-token-value" }
        }));
        let AgentItem::Raw {
            raw_kind,
            raw_payload,
            ..
        } = item
        else {
            panic!("expected Raw history item");
        };

        assert_eq!(raw_kind, "futureItemV2");
        assert_eq!(raw_payload, WITHHELD_VENDOR_RAW_PAYLOAD);
        assert!(!raw_payload.contains("sk-history-secret"));
        assert!(!raw_payload.contains("vendor-token-value"));

        let unsafe_type = history_item_to_agent_item(&json!({
            "type": "future item: sk-type-secret",
            "vendorSecret": "still-hidden"
        }));
        assert!(matches!(
            unsafe_type,
            AgentItem::Raw { raw_kind, raw_payload, .. }
                if raw_kind == "unknown" && raw_payload == WITHHELD_VENDOR_RAW_PAYLOAD
        ));
    }

    #[test]
    fn history_user_message_keeps_every_official_input_variant_visible() {
        let item = history_item_to_agent_item(&json!({
            "id": "user-1",
            "type": "userMessage",
            "content": [
                { "type": "text", "text": "hello" },
                { "type": "image", "url": "https://example.test/a.png" },
                { "type": "localImage", "path": "/tmp/a.png" },
                { "type": "audio", "url": "https://example.test/a.wav" },
                { "type": "localAudio", "path": "/tmp/a.wav" },
                { "type": "skill", "name": "review", "path": "/skills/review" },
                { "type": "mention", "name": "README", "path": "/repo/README.md" }
            ]
        }));
        let AgentItem::UserMessage { text, .. } = item else {
            panic!("expected UserMessage");
        };
        for expected in [
            "hello",
            "[image: https://example.test/a.png]",
            "[local image: /tmp/a.png]",
            "[audio: https://example.test/a.wav]",
            "[local audio: /tmp/a.wav]",
            "[skill: review (/skills/review)]",
            "[mention: README (/repo/README.md)]",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text:?}");
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
