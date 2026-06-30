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
use crate::codex::capabilities::{build_codex_capabilities, probe_codex_version};
use crate::codex::translate::CodexTranslator;
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentKind, CodexApprovalPolicy,
    CodexReasoningEffort, CodexSandboxMode, CodexSessionOptions, ProtocolError, ServerEvent,
    SessionCapabilities, SessionId, SessionStart, ThreadId, VendorControlPayload,
    VendorSessionOptions,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
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

    /// Locate the `codex` binary. Mirrors v1_legacy's `locate_codex`: GUI-
    /// launched macOS apps inherit a stripped PATH so we probe common
    /// install locations in addition to PATH.
    fn locate_codex() -> Result<String, ProtocolError> {
        if let Ok(out) = std::process::Command::new("/usr/bin/which")
            .arg("codex")
            .output()
        {
            if out.status.success() {
                let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !p.is_empty() {
                    return Ok(p);
                }
            }
        }
        for cand in [
            "/opt/homebrew/bin/codex",
            "/usr/local/bin/codex",
            "/usr/bin/codex",
        ] {
            if std::path::Path::new(cand).exists() {
                return Ok(cand.to_string());
            }
        }
        Err(ProtocolError {
            code: "codex-not-found".into(),
            message: "codex binary not found on PATH or common locations".into(),
            diagnostic_ref: None,
        })
    }

    /// Build the PATH env passed to the codex child. Matches v1_legacy
    /// behavior so MCP servers / sandbox helpers find their auxiliary
    /// tools even when the daemon was launched from a GUI app.
    fn child_path_env(base: Option<&str>) -> String {
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

    /// Spawn one `codex app-server` child. Pipes stdio; on Unix puts the
    /// child in its own process group so the whole subtree can be
    /// SIGKILLed via `kill(-pgid, SIGKILL)` on cancel/drop.
    fn spawn_child(cwd: &Path) -> Result<Child, ProtocolError> {
        let codex = Self::locate_codex()?;
        let child_path = Self::child_path_env(std::env::var("PATH").ok().as_deref());
        let mut cmd = Command::new(codex);
        cmd.arg("app-server")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PATH", child_path)
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }
        cmd.spawn().map_err(|e| ProtocolError {
            code: "codex-spawn-failed".into(),
            message: format!("failed to spawn codex app-server: {e}"),
            diagnostic_ref: None,
        })
    }

    /// Write one JSON-RPC frame as a newline-delimited line (Codex's
    /// wire framing — see protocol/SPIKE_FINDINGS.md).
    async fn write_frame(stdin: &mut ChildStdin, frame: &Value) -> Result<(), ProtocolError> {
        let mut line = serde_json::to_string(frame).map_err(|e| ProtocolError {
            code: "codex-encode-failed".into(),
            message: format!("serialize codex frame: {e}"),
            diagnostic_ref: None,
        })?;
        line.push('\n');
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| ProtocolError {
                code: "codex-stdin-write-failed".into(),
                message: format!("write to codex stdin: {e}"),
                diagnostic_ref: None,
            })?;
        stdin.flush().await.map_err(|e| ProtocolError {
            code: "codex-stdin-write-failed".into(),
            message: format!("flush codex stdin: {e}"),
            diagnostic_ref: None,
        })?;
        Ok(())
    }

    /// Read one JSON-RPC frame from the stdout reader. Returns Ok(None)
    /// on EOF so callers can distinguish disconnect from malformed JSON.
    async fn read_frame(
        reader: &mut BufReader<tokio::process::ChildStdout>,
        line_buf: &mut String,
    ) -> Result<Option<Value>, ProtocolError> {
        line_buf.clear();
        let n = reader
            .read_line(line_buf)
            .await
            .map_err(|e| ProtocolError {
                code: "codex-stdout-read-failed".into(),
                message: format!("read codex stdout: {e}"),
                diagnostic_ref: None,
            })?;
        if n == 0 {
            return Ok(None);
        }
        let v = serde_json::from_str(line_buf.trim()).map_err(|e| ProtocolError {
            code: "codex-malformed-json".into(),
            message: format!("malformed codex frame: {e}: {}", line_buf.trim()),
            diagnostic_ref: None,
        })?;
        Ok(Some(v))
    }

    /// Send a JSON-RPC request and wait (within a bounded timeout) for
    /// its matching response. Used only during the handshake — once the
    /// pump task takes over stdout, the adapter writes fire-and-forget
    /// requests and lets the translator surface results.
    async fn request_response(
        stdin: &mut ChildStdin,
        reader: &mut BufReader<tokio::process::ChildStdout>,
        line_buf: &mut String,
        id: u64,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, ProtocolError> {
        let req = json!({ "id": id, "method": method, "params": params });
        Self::write_frame(stdin, &req).await?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(ProtocolError {
                    code: "codex-handshake-timeout".into(),
                    message: format!("timed out waiting for {method} response"),
                    diagnostic_ref: None,
                });
            }
            let frame =
                match tokio::time::timeout(remaining, Self::read_frame(reader, line_buf)).await {
                    Ok(Ok(Some(v))) => v,
                    Ok(Ok(None)) => {
                        return Err(ProtocolError {
                            code: "codex-disconnected".into(),
                            message: format!("codex closed stdout before {method} response"),
                            diagnostic_ref: None,
                        });
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ProtocolError {
                            code: "codex-handshake-timeout".into(),
                            message: format!("timed out waiting for {method} response"),
                            diagnostic_ref: None,
                        });
                    }
                };
            if frame.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = frame.get("error").filter(|v| !v.is_null()) {
                    return Err(ProtocolError {
                        code: "codex-protocol-error".into(),
                        message: format!(
                            "codex {method} error: {}",
                            err.get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("(no message)")
                        ),
                        diagnostic_ref: None,
                    });
                }
                return Ok(frame.get("result").cloned().unwrap_or(Value::Null));
            }
            // Notifications received during handshake are intentionally
            // dropped: the adapter already emitted SessionStarted +
            // SessionCapabilities, and `thread/start` returns the
            // thread id authoritatively. We don't feed them into the
            // translator because the pump hasn't started and we'd
            // double-handle on its first tick.
        }
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

        let mut child = Self::spawn_child(cwd)?;
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
        // Drop stderr: v1_legacy mined it for disconnect diagnostics,
        // but the v2 surface routes errors through ServerEvent::Error.
        let _ = child.stderr.take();

        let mut reader = BufReader::new(stdout);
        let mut next_rpc_id: u64 = 1;
        let mut line_buf = String::new();
        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

        // 1. initialize
        let init_id = next_rpc_id;
        next_rpc_id += 1;
        Self::request_response(
            &mut stdin,
            &mut reader,
            &mut line_buf,
            init_id,
            "initialize",
            json!({ "clientInfo": { "name": "agentdeck", "version": "0.2.0" } }),
            HANDSHAKE_TIMEOUT,
        )
        .await?;

        // 2. thread/start (new) or thread/resume (continue).
        let thread_id = if let Some(tid) = resume_thread_id.clone() {
            let resume_id = next_rpc_id;
            next_rpc_id += 1;
            Self::request_response(
                &mut stdin,
                &mut reader,
                &mut line_buf,
                resume_id,
                "thread/resume",
                json!({ "threadId": tid.0 }),
                HANDSHAKE_TIMEOUT,
            )
            .await?;
            tid
        } else {
            let start_id = next_rpc_id;
            next_rpc_id += 1;
            let result = Self::request_response(
                &mut stdin,
                &mut reader,
                &mut line_buf,
                start_id,
                "thread/start",
                Self::thread_start_params(cwd, opts),
                HANDSHAKE_TIMEOUT,
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
                })?;
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
            Self::write_frame(
                &mut stdin,
                &json!({
                    "id": turn_id,
                    "method": "turn/start",
                    "params": Self::turn_start_params(&thread_id, prompt, opts),
                }),
            )
            .await?;
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
            thread_id: thread_id.clone(),
        });

        // 6. Spawn the stdout pump. It owns the BufReader and writes
        //    routing-table updates + ServerEvents downstream.
        let pump_state = Arc::clone(&state);
        let pump_events = events.clone();
        let pump_session = session_id.clone();
        let pump_translator = Arc::clone(&translator);
        let pump_handle = tokio::spawn(async move {
            stdout_pump(reader, pump_translator, pump_state, pump_events, pump_session).await;
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
                let _ = events
                    .send(ServerEvent::Error {
                        session_id: Some(session_id.clone()),
                        error: ProtocolError {
                            code: "codex-stdout-read-failed".into(),
                            message: format!("read codex stdout: {e}"),
                            diagnostic_ref: None,
                        },
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
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        // continue_thread doesn't carry vendor options on the Agent
        // trait (intentional — Task 3C wires per-thread saved options).
        // For v0.2 we use safe defaults; sandbox + on-request approvals
        // are the conservative baseline when resuming an unknown thread.
        let opts = CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::OnRequest,
            sandbox: CodexSandboxMode::WorkspaceWrite,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Medium,
            mcp_overrides: vec![],
        };
        // The hub layer (3C) should override cwd before calling.
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
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
                    message: format!(
                        "no pending approval for request_id={}",
                        decision.request_id
                    ),
                    diagnostic_ref: None,
                })?
        };
        let result = approval_response_body(&route.method, &route.params, decision.decision)?;
        let frame = json!({ "id": route.rpc_id, "result": result });
        {
            let mut stdin = state.stdin.lock().await;
            Self::write_frame(&mut stdin, &frame).await?;
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

    async fn cancel(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        let handle_opt = {
            let mut map = self.sessions.lock().await;
            map.remove(session_id)
        };
        if let Some(handle) = handle_opt {
            // Abort the stdout pump first so no further events race the
            // child kill.
            handle.pump_abort.abort();
            // Explicit child kill: belt-and-suspenders for kill_on_drop.
            let mut child = handle.state.child.lock().await;
            let _ = child.start_kill();
            // Best-effort group kill on Unix to catch the MCP subtree
            // (v1_legacy proved kill_on_drop alone leaves orphans —
            // codex re-execs into a forked app-server).
            #[cfg(unix)]
            {
                if let Some(pid) = child.id() {
                    unsafe {
                        libc_kill(-(pid as i32), SIGKILL);
                    }
                }
            }
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
                    let _ = child.start_kill();
                    #[cfg(unix)]
                    {
                        if let Some(pid) = child.id() {
                            unsafe {
                                libc_kill(-(pid as i32), SIGKILL);
                            }
                        }
                    }
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

// ── libc binding for group-kill (Unix only) ─────────────────────────────────
//
// Mirrors v1_legacy: one symbol, kept here to avoid pulling the `libc`
// crate. Negative pid = "every process in the group whose pgid == pid".
#[cfg(unix)]
const SIGKILL: i32 = 9;
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}
