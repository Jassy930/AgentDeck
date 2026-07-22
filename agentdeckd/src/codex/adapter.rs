//! CodexAdapter — owns the codex app-server child process for a single
//! session lifecycle. Implements `Agent` against the v2 protocol.
//!
//! Phase 3 Task 3B. This module replaces the v1 CodexAdapter (kept under
//! `crate::codex::v1_legacy`, feature-gated, as source material) with a
//! clean `impl Agent for CodexAdapter` that:
//!
//!   - Spawns one `codex app-server` child per `start_session` /
//!     `continue_thread` call. The child runs in its own process group
//!     (`process_group(0)`) so dropping the `tokio::process::Child` (which
//!     uses `kill_on_drop(true)`) plus a best-effort group-kill in
//!     `cancel` / `Drop for CodexAdapter` reaps the entire codex subtree
//!     (MCP servers, sandbox helpers) with no zombies.
//!
//!   - Runs the protocol handshake (`initialize` → `thread/start` or
//!     `thread/resume` → optional `turn/start`) inline on the calling
//!     task before returning the `AgentSessionHandle`, so the public
//!     contract "SessionStarted + SessionCapabilities arrive before any
//!     AgentItem" (invariant N7) is enforced.
//!
//!   - Pumps stdout through Task 3A's `CodexTranslator` on a background
//!     tokio task. The translator returns `TranslateOutput` entries; for
//!     each one carrying an `RpcRouteHint` (an `ActionRequest`), the pump
//!     registers `request_id → rpc_id` in the session's
//!     `approval_routes` BEFORE forwarding the event downstream, so
//!     `submit_decision` can resolve the JSON-RPC id and echo the
//!     response onto codex stdin.
//!
//!   - Treats `submit_vendor_control` as a non-runtime operation:
//!     Codex's `thread/start` options (sandbox / approval policy /
//!     reasoning effort) are immutable per thread. We return a structured
//!     `ProtocolError` instead of silently dropping or pretending to
//!     succeed; clients route this back to the user as "restart the
//!     session to apply the new setting".

use crate::agent::{Agent, AgentEventSender, AgentSessionHandle};
use crate::codex::app_server::{
    StderrTail, drain_child_stderr, kill_process_group, request_response, spawn_child, write_frame,
};
use crate::codex::capabilities::{build_codex_capabilities, probe_codex_version};
use crate::codex::translate::CodexTranslator;
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentKind, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode, CodexSessionOptions, HistoryRequest, HistoryResponse, ProtocolError,
    ServerEvent, SessionCapabilities, SessionId, SessionStart, ThreadId, VendorControlPayload,
    VendorSessionOptions,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::Mutex;

/// One approval-routing entry. Carries everything `submit_decision` needs
/// to build the right JSON-RPC response body (the body shape differs by
/// approval method).
#[derive(Debug, Clone)]
struct ApprovalRoute {
    rpc_id: u64,
    method: String,
    params: Value,
}

/// Per-session state shared between the stdout pump and the public API
/// methods (`submit_decision`, `cancel`). Everything mutable is wrapped
/// in its own `Mutex` so the two callers don't contend on a coarse lock.
struct SessionState {
    /// Codex child process. Dropping it with `kill_on_drop(true)` set on
    /// the `Command` signals SIGKILL on the wrapper; we also explicitly
    /// `start_kill` on `cancel` and group-kill the MCP subtree.
    child: Mutex<Child>,
    /// stdin pipe (response writes + outbound requests). Held under its
    /// own mutex so multiple writes serialize cleanly.
    stdin: Mutex<ChildStdin>,
    /// Routing table: ActionRequest.request_id → underlying codex rpc id.
    /// Populated by the pump on every `ActionRequest`; consumed by
    /// `submit_decision`.
    approval_routes: Mutex<HashMap<String, ApprovalRoute>>,
    /// Continuously drained bounded stderr tail for structured failures.
    stderr_tail: StderrTail,
    /// Thread id captured from `thread/start` / `thread/resume`.
    #[allow(dead_code)]
    thread_id: ThreadId,
}

/// Handle the adapter keeps for each session: the shared state plus the
/// pump's abort handle. Kept off `SessionState` so the pump (which holds
/// an `Arc<SessionState>`) doesn't need to know about its own canceller.
struct SessionHandle {
    state: Arc<SessionState>,
    pump_abort: tokio::task::AbortHandle,
}

/// CodexAdapter — the v2 `Agent` implementation for the Codex CLI.
///
/// Cheap to construct; capability probe is cached behind `OnceLock` so
/// the `codex --version` shell-out happens at most once per process.
pub struct CodexAdapter {
    cli_version: OnceLock<String>,
    sessions: Arc<Mutex<HashMap<SessionId, SessionHandle>>>,
}

impl CodexAdapter {
    pub fn new() -> Self {
        Self {
            cli_version: OnceLock::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Convenience constructor used by tests to make their intent
    /// obvious. Functionally identical to `new`; the separate name
    /// signals "I'm not going to spawn a real codex unless this test
    /// guards on `which::which("codex")`."
    pub fn new_for_test() -> Self {
        Self::new()
    }

    fn capabilities_for_v2(&self) -> SessionCapabilities {
        let version = self.cli_version.get_or_init(probe_codex_version).clone();
        build_codex_capabilities(version)
    }

    /// Convert `CodexSessionOptions` into the params object for Codex's
    /// `thread/start`. Verified against protocol/ClientRequest.json's
    /// `ThreadStartParams` schema:
    ///
    ///   - `sandbox` is a flat enum string (`read-only | workspace-write
    ///     | danger-full-access`), NOT `{"mode": ...}` (v1_legacy's
    ///     fixture was wrong; the live error surfaced it).
    ///   - `approvalPolicy` is a flat `AskForApproval` enum string
    ///     (`untrusted | on-failure | on-request | never`).
    ///   - `reasoningEffort` does NOT live here — it's on `turn/start`
    ///     as `effort`. Same for `persistApproval` and `mcpOverrides`
    ///     which aren't part of Codex's wire shape at all (AgentDeck-
    ///     internal concepts; persist is signaled by the per-decision
    ///     `acceptForSession` decision, not a session-wide flag).
    fn thread_start_params(cwd: &Path, opts: &CodexSessionOptions) -> Value {
        let mut p = serde_json::Map::new();
        p.insert("cwd".into(), json!(cwd.display().to_string()));
        p.insert("sandbox".into(), json!(sandbox_mode_str(opts.sandbox)));
        p.insert(
            "approvalPolicy".into(),
            json!(approval_policy_str(opts.approval_policy)),
        );
        // `persist_approval` / `mcp_overrides` / `reasoning_effort` are
        // applied elsewhere (decision time, daemon-side config, turn/start).
        Value::Object(p)
    }

    /// Convert per-turn options into the params object for Codex's
    /// `turn/start`. The reasoning effort travels with each turn — it
    /// is NOT a thread-level property in Codex's protocol.
    fn turn_start_params(thread_id: &ThreadId, prompt: &str, opts: &CodexSessionOptions) -> Value {
        json!({
            "threadId": thread_id.0,
            "input": [ { "type": "text", "text": prompt } ],
            "effort": reasoning_effort_str(opts.reasoning_effort),
        })
    }

    /// Inner driver shared by `start_session` and `continue_thread`.
    async fn start_inner(
        &self,
        cwd: &Path,
        opts: &CodexSessionOptions,
        prompt: Option<String>,
        resume_thread_id: Option<ThreadId>,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        let session_id = SessionId(uuid::Uuid::new_v4().to_string());

        // N7: SessionStarted + SessionCapabilities BEFORE any AgentItem.
        // If the channel is closed, we drop silently — caller failures
        // shadow these but the public Err return still signals the
        // ultimate failure.
        let caps = self.capabilities_for_v2();
        let _ = events
            .send(ServerEvent::SessionStarted {
                session_id: session_id.clone(),
                thread_id: resume_thread_id.clone(),
                agent_kind: AgentKind::Codex,
            })
            .await;
        let _ = events
            .send(ServerEvent::SessionCapabilities {
                session_id: session_id.clone(),
                agent_kind: AgentKind::Codex,
                capabilities: caps,
            })
            .await;

        let mut child = spawn_child(cwd)?;
        let mut stdin = child.stdin.take().ok_or_else(|| ProtocolError {
            code: "codex-spawn-failed".into(),
            message: "codex child missing stdin pipe".into(),
            diagnostic_ref: None,
        })?;
        let stdout = child.stdout.take().ok_or_else(|| ProtocolError {
            code: "codex-spawn-failed".into(),
            message: "codex child missing stdout pipe".into(),
            diagnostic_ref: None,
        })?;
        let stderr_tail = drain_child_stderr(&mut child)?;

        let mut reader = BufReader::new(stdout);
        let mut next_rpc_id: u64 = 1;
        let mut line_buf = String::new();
        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

        // 1. initialize
        let init_id = next_rpc_id;
        next_rpc_id += 1;
        request_response(
            &mut stdin,
            &mut reader,
            &mut line_buf,
            init_id,
            "initialize",
            json!({ "clientInfo": { "name": "agentdeck", "version": "0.2.0" } }),
            HANDSHAKE_TIMEOUT,
            &stderr_tail,
        )
        .await?;

        // 2. thread/start (new) or thread/resume (continue).
        let thread_id = if let Some(tid) = resume_thread_id.clone() {
            let resume_id = next_rpc_id;
            next_rpc_id += 1;
            request_response(
                &mut stdin,
                &mut reader,
                &mut line_buf,
                resume_id,
                "thread/resume",
                json!({ "threadId": tid.0 }),
                HANDSHAKE_TIMEOUT,
                &stderr_tail,
            )
            .await?;
            tid
        } else {
            let start_id = next_rpc_id;
            next_rpc_id += 1;
            let result = request_response(
                &mut stdin,
                &mut reader,
                &mut line_buf,
                start_id,
                "thread/start",
                Self::thread_start_params(cwd, opts),
                HANDSHAKE_TIMEOUT,
                &stderr_tail,
            )
            .await?;
            // Wire shape verified by v1_legacy: thread id is at
            // result.thread.id, not result.threadId.
            let id = result
                .get("thread")
                .and_then(|t| t.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| ProtocolError {
                    code: "codex-protocol-error".into(),
                    message: "thread/start: no thread.id in result".into(),
                    diagnostic_ref: None,
                })
                .map_err(|error| stderr_tail.enrich_error(error))?;
            ThreadId(id)
        };

        // 3. Send initial turn/start if a prompt was provided. We do
        //    this BEFORE handing stdout to the pump so the request id is
        //    in flight by the time the translator starts seeing
        //    notifications. (Codex acks turn/start with a JSON-RPC
        //    response the translator drops.)
        if let Some(prompt) = &prompt {
            let turn_id = next_rpc_id;
            next_rpc_id += 1;
            write_frame(
                &mut stdin,
                &json!({
                    "id": turn_id,
                    "method": "turn/start",
                    "params": Self::turn_start_params(&thread_id, prompt, opts),
                }),
            )
            .await
            .map_err(|error| stderr_tail.enrich_error(error))?;
        }
        let _ = next_rpc_id; // counter no longer needed; pump takes over

        // 4. Build translator stamped with the session-level policy. The
        //    translator IS the vendor-coupling surface; the adapter and
        //    pump only call into it.
        let translator = Arc::new(Mutex::new(CodexTranslator::with_policy(
            session_id.clone(),
            Some(thread_id.clone()),
            opts.approval_policy,
            opts.sandbox,
            opts.persist_approval,
        )));

        // 5. Build the per-session shared state (Arc'd, so the pump can
        //    hold its own clone for routing-table updates without
        //    blocking the adapter's session map lookup).
        let state = Arc::new(SessionState {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            approval_routes: Mutex::new(HashMap::new()),
            stderr_tail,
            thread_id: thread_id.clone(),
        });

        // 6. Spawn the stdout pump. It owns the BufReader and writes
        //    routing-table updates + ServerEvents downstream.
        let pump_state = Arc::clone(&state);
        let pump_events = events.clone();
        let pump_session = session_id.clone();
        let pump_translator = Arc::clone(&translator);
        let pump_handle = tokio::spawn(async move {
            stdout_pump(
                reader,
                pump_translator,
                pump_state,
                pump_events,
                pump_session,
            )
            .await;
        });
        let pump_abort = pump_handle.abort_handle();

        // 7. Register the session.
        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(
                session_id.clone(),
                SessionHandle {
                    state: Arc::clone(&state),
                    pump_abort: pump_abort.clone(),
                },
            );
        }

        Ok(AgentSessionHandle {
            session_id,
            thread_id: Some(thread_id),
            agent_kind: AgentKind::Codex,
            abort_handle: pump_abort,
        })
    }
}

// ───────────────────────────────────────────────────────────────────────────
// stdout pump: reads codex stdout line-by-line, drives the translator,
// updates the per-session approval routing table on ActionRequests, and
// forwards every translated ServerEvent to the daemon's events channel.
//
// Lives outside `impl CodexAdapter` because tokio::spawn requires a
// 'static future and the pump needs to outlive any single method call.
// ───────────────────────────────────────────────────────────────────────────
async fn stdout_pump(
    mut reader: BufReader<tokio::process::ChildStdout>,
    translator: Arc<Mutex<CodexTranslator>>,
    state: Arc<SessionState>,
    events: AgentEventSender,
    session_id: SessionId,
) {
    let mut line_buf = String::new();
    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf).await {
            Ok(0) => break, // EOF: codex disconnected
            Ok(_) => {}
            Err(e) => {
                let error = state.stderr_tail.enrich_error(ProtocolError {
                    code: "codex-stdout-read-failed".into(),
                    message: format!("read codex stdout: {e}"),
                    diagnostic_ref: None,
                });
                let _ = events
                    .send(ServerEvent::Error {
                        session_id: Some(session_id.clone()),
                        error,
                    })
                    .await;
                break;
            }
        }
        let outputs = {
            let mut t = translator.lock().await;
            t.translate_line_with_routes(&line_buf)
        };
        for out in outputs {
            // Register routing entry BEFORE forwarding the event, so a
            // racing submit_decision sees the route by the time the
            // client could have responded.
            if let Some(hint) = out.rpc_route_hint {
                let mut routes = state.approval_routes.lock().await;
                routes.insert(
                    hint.request_id.clone(),
                    ApprovalRoute {
                        rpc_id: hint.rpc_id,
                        method: hint.method,
                        params: hint.params,
                    },
                );
            }
            if events.send(out.event).await.is_err() {
                // Receiver dropped: client disconnected. Stop pumping.
                return;
            }
        }
    }
}

#[async_trait::async_trait]
impl Agent for CodexAdapter {
    fn kind(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn capabilities(&self) -> SessionCapabilities {
        self.capabilities_for_v2()
    }

    async fn start_session(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        let codex_options = match start.vendor_options {
            VendorSessionOptions::Codex(o) => o,
            _ => {
                return Err(ProtocolError {
                    code: "wrong-vendor".into(),
                    message: "CodexAdapter received non-Codex vendor options".into(),
                    diagnostic_ref: None,
                });
            }
        };
        self.start_inner(&start.cwd, &codex_options, start.prompt, None, events)
            .await
    }

    async fn continue_thread(
        &self,
        thread_id: ThreadId,
        cwd: std::path::PathBuf,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        // continue_thread doesn't carry vendor options on the Agent
        // trait (intentional — Task 3C wires per-thread saved options).
        // For v0.2 we use safe defaults; sandbox + on-request approvals
        // are the conservative baseline when resuming an unknown thread.
        // `cwd` is carried by the client (Swift/CLI) so the resumed
        // child runs in the same directory as the original session,
        // matching tool_use expectations.
        let opts = CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::OnRequest,
            sandbox: CodexSandboxMode::WorkspaceWrite,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Medium,
            mcp_overrides: vec![],
        };
        self.start_inner(&cwd, &opts, Some(prompt), Some(thread_id), events)
            .await
    }

    async fn submit_decision(
        &self,
        session_id: &SessionId,
        decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        let state = {
            let map = self.sessions.lock().await;
            map.get(session_id)
                .map(|h| Arc::clone(&h.state))
                .ok_or_else(|| ProtocolError {
                    code: "session-not-found".into(),
                    message: format!("submit_decision: session {:?} unknown", session_id),
                    diagnostic_ref: None,
                })?
        };
        let route = {
            let routes = state.approval_routes.lock().await;
            routes
                .get(&decision.request_id)
                .cloned()
                .ok_or_else(|| ProtocolError {
                    code: "approval-route-not-found".into(),
                    message: format!("no pending approval for request_id={}", decision.request_id),
                    diagnostic_ref: None,
                })?
        };
        let result = approval_response_body(&route.method, &route.params, decision.decision)?;
        let frame = json!({ "id": route.rpc_id, "result": result });
        {
            let mut stdin = state.stdin.lock().await;
            write_frame(&mut stdin, &frame)
                .await
                .map_err(|error| state.stderr_tail.enrich_error(error))?;
        }
        // Drop the routing entry now that we responded; codex won't
        // send the same approval id again.
        state
            .approval_routes
            .lock()
            .await
            .remove(&decision.request_id);
        Ok(())
    }

    async fn submit_vendor_control(
        &self,
        _session_id: &SessionId,
        payload: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        match payload {
            VendorControlPayload::Codex(_) => Err(ProtocolError {
                code: "codex-vendor-control-requires-new-turn".into(),
                message: "Codex thread/start options (sandbox, approval policy, \
                          reasoning effort) are immutable per thread; start a \
                          new session to apply the new value"
                    .into(),
                diagnostic_ref: None,
            }),
            VendorControlPayload::ClaudeCode(_) => Err(ProtocolError {
                code: "wrong-vendor".into(),
                message: "CodexAdapter received non-Codex vendor control".into(),
                diagnostic_ref: None,
            }),
        }
    }

    /// Route neutral history requests through Codex's official app-server
    /// history APIs. List/read use a short-lived `codex app-server` child;
    /// mutating operations remain explicit not-supported responses until
    /// their product semantics are approved.
    async fn handle_history(
        &self,
        request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        use crate::codex::history;
        match request {
            HistoryRequest::List {
                cwd_filter, limit, ..
            } => {
                let items = history::list_history(cwd_filter.as_deref(), limit).await?;
                Ok(HistoryResponse::List(items))
            }
            HistoryRequest::Read { thread_id, .. } => {
                let resp = history::read_history(&thread_id).await?;
                Ok(HistoryResponse::Read(resp))
            }
            HistoryRequest::Archive { thread_id, .. } => {
                history::archive(&thread_id).await?;
                Ok(HistoryResponse::Ack)
            }
            HistoryRequest::Unarchive { thread_id, .. } => {
                history::unarchive(&thread_id).await?;
                Ok(HistoryResponse::Ack)
            }
            HistoryRequest::Rename {
                thread_id, title, ..
            } => {
                history::rename(&thread_id, &title).await?;
                Ok(HistoryResponse::Ack)
            }
        }
    }

    async fn cancel(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        let handle_opt = {
            let mut map = self.sessions.lock().await;
            map.remove(session_id)
        };
        if let Some(handle) = handle_opt {
            // Abort the stdout pump first so no further events race the
            // child kill.
            handle.pump_abort.abort();
            let mut child = handle.state.child.lock().await;
            kill_process_group(&mut child);
        }
        Ok(())
    }
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CodexAdapter {
    /// Last-resort cleanup: if any sessions are still alive when the
    /// adapter is dropped (shouldn't happen if the hub called `cancel`
    /// correctly, but defensive), kill them synchronously.
    fn drop(&mut self) {
        if let Ok(map) = self.sessions.try_lock() {
            for handle in map.values() {
                handle.pump_abort.abort();
                if let Ok(mut child) = handle.state.child.try_lock() {
                    kill_process_group(&mut child);
                }
            }
        }
    }
}

// ── Codex approval response builders ────────────────────────────────────────
//
// Mirrors v1_legacy::approval_response_for_decision (mod.rs ~1830).
// Body shape differs per approval method; centralised here so 3C can
// audit one place.

fn approval_response_body(
    method: &str,
    params: &Value,
    decision: ActionDecisionKind,
) -> Result<Value, ProtocolError> {
    let codex_decision = match decision {
        ActionDecisionKind::Approve => "accept",
        ActionDecisionKind::Deny => "decline",
    };
    match method {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
            Ok(json!({ "decision": codex_decision }))
        }
        "item/permissions/requestApproval" => {
            if decision == ActionDecisionKind::Approve {
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
        "item/tool/requestUserInput" => {
            // No closer-fit response shape; echo decision as a generic
            // accept/decline so codex doesn't hang.
            Ok(json!({ "decision": codex_decision }))
        }
        other => Err(ProtocolError {
            code: "codex-unsupported-approval-method".into(),
            message: format!("unsupported approval request method: {other}"),
            diagnostic_ref: None,
        }),
    }
}

// ── enum → wire string helpers ──────────────────────────────────────────────

fn sandbox_mode_str(m: CodexSandboxMode) -> &'static str {
    match m {
        CodexSandboxMode::ReadOnly => "read-only",
        CodexSandboxMode::WorkspaceWrite => "workspace-write",
        // Codex's wire enum spells this `danger-full-access`. AgentDeck's
        // neutral enum is `FullAccess`; the rename is the vendor mapping
        // surface and lives here.
        CodexSandboxMode::FullAccess => "danger-full-access",
    }
}

fn approval_policy_str(p: CodexApprovalPolicy) -> &'static str {
    match p {
        // The AgentDeck neutral enum has three variants but Codex's
        // `AskForApproval` has four (`untrusted | on-failure |
        // on-request | never`). We map `Always` → `untrusted` (codex's
        // most permissive prompting mode) since `always` is not a real
        // codex value; clients that ask for it get the closest
        // equivalent rather than a wire error.
        CodexApprovalPolicy::OnRequest => "on-request",
        CodexApprovalPolicy::Never => "never",
        CodexApprovalPolicy::Always => "untrusted",
    }
}

fn reasoning_effort_str(e: CodexReasoningEffort) -> &'static str {
    match e {
        CodexReasoningEffort::Minimal => "minimal",
        CodexReasoningEffort::Low => "low",
        CodexReasoningEffort::Medium => "medium",
        CodexReasoningEffort::High => "high",
    }
}
