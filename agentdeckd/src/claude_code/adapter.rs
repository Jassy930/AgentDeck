//! `ClaudeCodeAdapter` — spawns one `claude --print --output-format
//! stream-json` child per session (turn-scoped, matching the Codex
//! adapter shape, per spec § 5.2).
//!
//! Phase 4 Task 4B completes the v2 `Agent` trait surface scaffolded
//! in 4A:
//!
//!   - `capabilities()` — real probe via `claude --version` cached in
//!     a `OnceLock`; builds a typed `SessionCapabilities` covering
//!     every Shared CapabilityId Codex has (N5 对称约束) plus the
//!     CC-only ids the spec § 4.4 enumerated.
//!
//!   - `start_session()` / `continue_thread()` — unchanged from 4A;
//!     spawns CC, emits `SessionStarted` + `SessionCapabilities`
//!     synchronously before any AgentItem (N7), then pumps stdout
//!     through `ClaudeCodeTranslator` on a background task. The pump
//!     now also records `permission_route_hint`s into the per-session
//!     routing table BEFORE forwarding the `ActionRequest` event, so
//!     a racing `submit_decision` cannot miss the mapping.
//!
//!   - `submit_decision()` — wire-format speculative (spec § 5.5
//!     leaves the exact shape to live verification): writes one
//!     `{"type":"permission_response", "tool_use_id":<id>,
//!     "approved":<bool>}` JSON line to CC's stdin. Real-fixture
//!     verification deferred (4A could not capture a CC permission
//!     prompt under `bypassPermissions`; 4C records and revises if
//!     needed).
//!
//!   - `submit_vendor_control()` — CC has no in-place mutation of
//!     permission mode, output style or hooks. The adapter returns a
//!     structured `cc-vendor-control-requires-new-turn` error for the
//!     permission-mode case (symmetric with Codex's posture), and
//!     `cc-vendor-control-not-supported` for the style / hook edits
//!     (configure via `settings.json` or start-options instead).
//!
//!   - `cancel()` — aborts the pump and best-effort group-kills the
//!     child subprocess tree (unchanged from 4A).

use crate::agent::{Agent, AgentEventSender, AgentSessionHandle};
use crate::claude_code::translate::ClaudeCodeTranslator;
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentKind, ClaudeCodePermissionMode,
    ClaudeCodeSessionOptions, ClaudeCodeVendorControl, HistoryRequest, HistoryResponse,
    InitialTurn, ProtocolError, ServerEvent, SessionCapabilities, SessionId, SessionStart,
    ThreadId, TurnId, VendorControlPayload, VendorSessionOptions,
};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;

/// Shared routing table for permission responses. Cloned into both
/// the stdout pump (writer side) and `SessionEntry` (reader side
/// when `submit_decision` arrives).
type PermissionRoutes = Arc<Mutex<HashMap<String, String>>>;

/// Per-session bag of mutable state the adapter keeps alive for
/// `submit_decision` / `cancel`.
struct SessionEntry {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    /// `request_id` (= `tool_use_id` from the translator) → the
    /// underlying CC `tool_use_id` we must echo back in the
    /// permission response. Populated by the stdout pump immediately
    /// when an `ActionRequest` is translated; consumed by
    /// `submit_decision`.
    permission_routes: PermissionRoutes,
    pump_abort: tokio::task::AbortHandle,
}

/// Claude Code adapter — v2 `Agent` implementation.
pub struct ClaudeCodeAdapter {
    cli_version: OnceLock<String>,
    sessions: Arc<Mutex<HashMap<SessionId, Arc<SessionEntry>>>>,
}

impl ClaudeCodeAdapter {
    pub fn new() -> Self {
        Self {
            cli_version: OnceLock::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Constructor for deterministic tests. Seeds a fixed capability
    /// version so calling `capabilities()` never executes the user's
    /// `claude --version`.
    pub fn new_for_test() -> Self {
        let cli_version = OnceLock::new();
        let _ = cli_version.set("claude test".to_string());
        Self {
            cli_version,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build a `SessionCapabilities` payload, caching the
    /// `claude --version` probe behind a `OnceLock` (one shell-out
    /// per process).
    fn capabilities_for_v2(&self) -> SessionCapabilities {
        use crate::claude_code::capabilities::{
            build_claude_code_capabilities, probe_claude_code_version,
        };
        let version = self
            .cli_version
            .get_or_init(probe_claude_code_version)
            .clone();
        build_claude_code_capabilities(version)
    }

    /// Build the `claude` command line from a `SessionStart`. Wraps the
    /// vendor-options destructure + flag mapping in one place so
    /// `start_session` and `continue_thread` agree on encoding.
    fn build_command(
        start: &SessionStart,
    ) -> Result<(Command, ClaudeCodePermissionMode), ProtocolError> {
        let opts = match &start.vendor_options {
            VendorSessionOptions::ClaudeCode(o) => o.clone(),
            VendorSessionOptions::Codex(_) => {
                return Err(ProtocolError {
                    code: "wrong-vendor".into(),
                    message: "ClaudeCodeAdapter received non-ClaudeCode vendor options".into(),
                    diagnostic_ref: None,
                });
            }
        };

        let mut cmd = Command::new("claude");
        cmd.arg("--print")
            .arg("--output-format")
            .arg("stream-json")
            .arg("--input-format")
            .arg("stream-json")
            .arg("--include-partial-messages")
            .arg("--include-hook-events")
            .arg("--verbose")
            .arg("--permission-mode")
            .arg(permission_mode_to_cli(opts.permission_mode));

        if let Some(m) = &opts.model {
            cmd.arg("--model").arg(m);
        }
        if let Some(e) = &opts.effort {
            cmd.arg("--effort").arg(e);
        }
        if let Some(s) = &opts.output_style {
            cmd.arg("--output-style").arg(s);
        }
        if let Some(tools) = &opts.allowed_tools {
            if !tools.is_empty() {
                cmd.arg("--tools").arg(tools.join(","));
            }
        }
        if let Some(tools) = &opts.disallowed_tools {
            if !tools.is_empty() {
                cmd.arg("--disallowedTools").arg(tools.join(","));
            }
        }
        if let Some(p) = &opts.mcp_config_path {
            cmd.arg("--mcp-config").arg(p);
        }
        for d in &opts.plugin_dirs {
            cmd.arg("--plugin-dir").arg(d);
        }
        if let Some(w) = &opts.worktree {
            cmd.arg("--worktree").arg(w);
        }
        if let Some(n) = &opts.session_name {
            cmd.arg("--name").arg(n);
        }
        if let Some(id) = &start.resume_thread_id {
            cmd.arg("--resume").arg(&id.0);
        } else if let Some(id) = &opts.session_id {
            cmd.arg("--session-id").arg(id);
        }

        cmd.current_dir(&start.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }
        Ok((cmd, opts.permission_mode))
    }

    /// Run the spec § 5.8 preflight checks before spawning the CC
    /// child. Each failure is BOTH returned as a structured
    /// `ProtocolError` (so the caller's Result chain sees the error)
    /// AND surfaced on the events channel as a `ServerEvent::Error`
    /// (so a streaming client gets it through the same wire it would
    /// have seen other session errors on).
    ///
    /// Codes:
    ///   - `cc-not-installed`     — `claude` binary missing from PATH
    ///   - `cc-version-too-old`   — version probe failed / placeholder
    ///   - `cc-not-authenticated` — `claude auth status` explicit no
    ///
    /// `cc-not-authenticated` is NON-fatal in degraded mode (returns
    /// `AuthState::Unknown` → no error) because some valid setups
    /// (Bedrock, env-var keys) don't surface through `auth status`;
    /// only the unambiguous "NotAuthenticated" exit triggers a block.
    async fn preflight(
        &self,
        events: &AgentEventSender,
        session_id: Option<&SessionId>,
    ) -> Result<(), ProtocolError> {
        use crate::claude_code::auth::{AuthState, probe_auth_status};

        // 1. Binary on PATH?
        if which::which("claude").is_err() {
            let err = ProtocolError {
                code: "cc-not-installed".into(),
                message: "`claude` binary not in PATH. Install: \
                          npm install -g @anthropic-ai/claude-code"
                    .into(),
                diagnostic_ref: None,
            };
            let _ = events
                .send(ServerEvent::Error {
                    session_id: session_id.cloned(),
                    error: err.clone(),
                })
                .await;
            return Err(err);
        }

        // 2. Version probe. `probe_claude_code_version` returns
        //    "claude unknown" when the spawn fails OR when stdout is
        //    empty; either way it means we don't know the version, and
        //    spec § 5.8 wants a clear failure rather than silent guess.
        let version = self
            .cli_version
            .get_or_init(crate::claude_code::capabilities::probe_claude_code_version)
            .clone();
        if version.starts_with("claude unknown") {
            let err = ProtocolError {
                code: "cc-version-too-old".into(),
                message: format!(
                    "claude --version probe failed (got {:?}); \
                     ensure claude >= 2.1.x supporting --output-format stream-json",
                    version
                ),
                diagnostic_ref: None,
            };
            let _ = events
                .send(ServerEvent::Error {
                    session_id: session_id.cloned(),
                    error: err.clone(),
                })
                .await;
            return Err(err);
        }

        // 3. Auth status. Only the unambiguous "logged out" branch
        //    triggers an abort; "Unknown" is treated as degraded-OK
        //    because some legitimate setups (Bedrock, ANTHROPIC_API_KEY
        //    env) report opaque auth state.
        if matches!(probe_auth_status(), AuthState::NotAuthenticated) {
            let err = ProtocolError {
                code: "cc-not-authenticated".into(),
                message: "Not logged in to Claude. Run: claude login".into(),
                diagnostic_ref: None,
            };
            let _ = events
                .send(ServerEvent::Error {
                    session_id: session_id.cloned(),
                    error: err.clone(),
                })
                .await;
            return Err(err);
        }
        Ok(())
    }

    /// Shared driver behind `start_session` and `continue_thread`.
    async fn start_inner(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        // Preflight per spec § 5.8 — run before SessionStarted, so a
        // missing binary / bad version / logged-out user surfaces as a
        // single clean error attached to the caller-provided session id
        // rather than a half-started session.
        let session_id = start.session_id.clone();
        let resume_thread_id = start.resume_thread_id.clone();
        self.preflight(&events, Some(&session_id)).await?;

        let (mut cmd, permission_mode) = Self::build_command(&start)?;

        // N7: SessionStarted + SessionCapabilities BEFORE any AgentItem.
        let caps = self.capabilities_for_v2();
        let _ = events
            .send(ServerEvent::SessionStarted {
                session_id: session_id.clone(),
                thread_id: resume_thread_id.clone(),
                agent_kind: AgentKind::ClaudeCode,
            })
            .await;
        let _ = events
            .send(ServerEvent::SessionCapabilities {
                session_id: session_id.clone(),
                agent_kind: AgentKind::ClaudeCode,
                capabilities: caps,
            })
            .await;

        let mut child = cmd.spawn().map_err(|e| ProtocolError {
            code: "cc-spawn-failed".into(),
            message: format!("failed to spawn `claude`: {e}"),
            diagnostic_ref: None,
        })?;
        let mut stdin = child.stdin.take().ok_or_else(|| ProtocolError {
            code: "cc-spawn-failed".into(),
            message: "claude child missing stdin pipe".into(),
            diagnostic_ref: None,
        })?;
        let stdout = child.stdout.take().ok_or_else(|| ProtocolError {
            code: "cc-spawn-failed".into(),
            message: "claude child missing stdout pipe".into(),
            diagnostic_ref: None,
        })?;
        let _ = child.stderr.take();

        // Write the initial prompt (if any) as a stream-json user line.
        if let Some(initial_turn) = &start.initial_turn {
            let line = serde_json::to_string(&serde_json::json!({
                "type": "user",
                "message": { "role": "user", "content": initial_turn.prompt },
            }))
            .unwrap_or_default();
            if stdin.write_all(line.as_bytes()).await.is_err() {
                let _ = events
                    .send(ServerEvent::Error {
                        session_id: Some(session_id.clone()),
                        error: ProtocolError {
                            code: "cc-stdin-write-failed".into(),
                            message: "claude child closed stdin before initial prompt".into(),
                            diagnostic_ref: None,
                        },
                    })
                    .await;
            }
            let _ = stdin.write_all(b"\n").await;
            let _ = stdin.flush().await;
        }

        // Build the per-session shared routes up front so the pump
        // and the entry hold the same Arc.
        let permission_routes: PermissionRoutes = Arc::new(Mutex::new(HashMap::new()));

        let translator_thread_id = resume_thread_id.clone();
        let pump_session = session_id.clone();
        let pump_events = events.clone();
        let pump_routes = Arc::clone(&permission_routes);
        let pump_handle = tokio::spawn(async move {
            let mut translator = ClaudeCodeTranslator::new(pump_session.clone(), permission_mode);
            if let Some(tid) = translator_thread_id {
                translator.set_thread_id(tid);
            }
            let mut lines = BufReader::new(stdout).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let out = translator.translate_line(&line);
                        // Record permission routing BEFORE forwarding
                        // the event downstream so a racing
                        // submit_decision cannot miss the mapping.
                        if let Some(tool_use_id) = out.permission_route_hint.clone() {
                            // The translator stores `request_id =
                            // tool_use_id` for the ActionRequest, so
                            // the map key and value happen to
                            // coincide; we still record explicitly so
                            // a future request_id ↔ tool_use_id
                            // divergence doesn't silently break.
                            let mut routes = pump_routes.lock().await;
                            routes.insert(tool_use_id.clone(), tool_use_id);
                        }
                        for event in out.events {
                            if pump_events.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                    Ok(None) => return, // EOF
                    Err(e) => {
                        let _ = pump_events
                            .send(ServerEvent::Error {
                                session_id: Some(pump_session.clone()),
                                error: ProtocolError {
                                    code: "cc-stdout-read-failed".into(),
                                    message: format!("read claude stdout: {e}"),
                                    diagnostic_ref: None,
                                },
                            })
                            .await;
                        return;
                    }
                }
            }
        });
        let pump_abort = pump_handle.abort_handle();

        let entry = Arc::new(SessionEntry {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            permission_routes,
            pump_abort: pump_abort.clone(),
        });
        self.sessions
            .lock()
            .await
            .insert(session_id.clone(), Arc::clone(&entry));

        Ok(AgentSessionHandle {
            session_id,
            thread_id: resume_thread_id,
            agent_kind: AgentKind::ClaudeCode,
            abort_handle: pump_abort,
            exit: None,
        })
    }
}

impl Default for ClaudeCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ClaudeCodeAdapter {
    /// Defensive cleanup mirroring `CodexAdapter`: if the hub forgot to
    /// `cancel`, kill every session's child + abort its pump on drop.
    fn drop(&mut self) {
        if let Ok(map) = self.sessions.try_lock() {
            for entry in map.values() {
                entry.pump_abort.abort();
                if let Ok(mut child) = entry.child.try_lock() {
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

#[async_trait::async_trait]
impl Agent for ClaudeCodeAdapter {
    fn kind(&self) -> AgentKind {
        AgentKind::ClaudeCode
    }

    fn capabilities(&self) -> SessionCapabilities {
        self.capabilities_for_v2()
    }

    async fn start_session(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        if !matches!(start.vendor_options, VendorSessionOptions::ClaudeCode(_)) {
            return Err(ProtocolError {
                code: "wrong-vendor".into(),
                message: "ClaudeCodeAdapter received non-ClaudeCode vendor options".into(),
                diagnostic_ref: None,
            });
        }
        self.start_inner(start, events).await
    }

    async fn continue_thread(
        &self,
        thread_id: ThreadId,
        cwd: std::path::PathBuf,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        // continue_thread on the Agent trait doesn't carry vendor
        // options — Phase 4 hub plumbing will look up the saved
        // permission_mode for the resumed thread. For v0.2 we
        // default to BypassPermissions so the resumed turn flows
        // end-to-end without prompting (spec § 5.5 interim posture).
        // `cwd` is supplied by the client so `~/.claude/projects/
        // <encoded_cwd>/<id>.jsonl` resume lookup matches the
        // original session and tool_use runs in the right directory.
        let opts = ClaudeCodeSessionOptions {
            permission_mode: ClaudeCodePermissionMode::BypassPermissions,
            model: None,
            effort: None,
            hooks: vec![],
            output_style: None,
            allowed_tools: None,
            disallowed_tools: None,
            mcp_config_path: None,
            plugin_dirs: vec![],
            worktree: None,
            session_name: None,
            session_id: Some(thread_id.0.clone()),
        };
        let synth_start = SessionStart {
            session_id: SessionId(uuid::Uuid::new_v4().to_string()),
            agent_kind: AgentKind::ClaudeCode,
            cwd,
            resume_thread_id: Some(thread_id),
            initial_turn: Some(InitialTurn {
                turn_id: TurnId(uuid::Uuid::new_v4().to_string()),
                prompt,
            }),
            vendor_options: VendorSessionOptions::ClaudeCode(opts),
            runtime_options: Default::default(),
        };
        self.start_inner(synth_start, events).await
    }

    async fn submit_decision(
        &self,
        session_id: &SessionId,
        decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        let entry = {
            let map = self.sessions.lock().await;
            map.get(session_id).cloned().ok_or_else(|| ProtocolError {
                code: "session-not-found".into(),
                message: format!("submit_decision: session {:?} unknown", session_id),
                diagnostic_ref: None,
            })?
        };
        let tool_use_id = {
            let routes = entry.permission_routes.lock().await;
            routes
                .get(&decision.request_id)
                .cloned()
                .ok_or_else(|| ProtocolError {
                    code: "cc-decision-no-route".into(),
                    message: format!(
                        "no pending permission for request_id {}",
                        decision.request_id
                    ),
                    diagnostic_ref: None,
                })?
        };
        let approved = matches!(decision.decision, ActionDecisionKind::Approve);
        // Speculative wire shape — spec § 5.5 leaves this to live
        // verification. A Task 4C recorded fixture from
        // `--permission-mode default` will revise field names if
        // necessary. We pick `permission_response` / `tool_use_id` /
        // `approved` (snake_case) to match CC's existing stream-json
        // conventions (`tool_use`, `tool_result`, `session_id`).
        let line = serde_json::to_string(&serde_json::json!({
            "type": "permission_response",
            "tool_use_id": tool_use_id,
            "approved": approved,
        }))
        .unwrap_or_default();
        let mut stdin = entry.stdin.lock().await;
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| ProtocolError {
                code: "cc-decision-write".into(),
                message: format!("write permission_response to claude stdin: {e}"),
                diagnostic_ref: None,
            })?;
        let _ = stdin.write_all(b"\n").await;
        let _ = stdin.flush().await;
        // Drop the route — CC won't ask the same permission again
        // under the same tool_use_id.
        entry
            .permission_routes
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
        let ctrl = match payload {
            VendorControlPayload::ClaudeCode(c) => c,
            VendorControlPayload::Codex(_) => {
                return Err(ProtocolError {
                    code: "wrong-vendor".into(),
                    message: "ClaudeCodeAdapter received non-ClaudeCode vendor control".into(),
                    diagnostic_ref: None,
                });
            }
        };
        match ctrl {
            ClaudeCodeVendorControl::UpdatePermissionMode(_) => Err(ProtocolError {
                code: "cc-vendor-control-requires-new-turn".into(),
                message: "Claude Code permission mode change requires starting a \
                          new turn with the desired --permission-mode value"
                    .into(),
                diagnostic_ref: None,
            }),
            ClaudeCodeVendorControl::UpdateOutputStyle { .. }
            | ClaudeCodeVendorControl::AddHook(_)
            | ClaudeCodeVendorControl::RemoveHook { .. } => Err(ProtocolError {
                code: "cc-vendor-control-not-supported".into(),
                message: "Output style / hook editing via vendor control not \
                          supported in v0.2; configure via ~/.claude/settings.json \
                          or start-options"
                    .into(),
                diagnostic_ref: None,
            }),
        }
    }

    /// Task 4C — Phase 4 finalization: wire CC's history layer onto
    /// the trait. Delegates to the free functions in
    /// `crate::claude_code::history` (added in Task 4B). `Unarchive`
    /// is a no-op for CC because `claude rm` is soft and
    /// `claude --resume <id>` keeps working regardless of archived
    /// state (spec § 5.6).
    async fn handle_history(
        &self,
        request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        use crate::claude_code::history;
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
            HistoryRequest::Unarchive { .. } => {
                // CC: `claude rm` is soft; --resume always finds the
                // jsonl back. Unarchive is therefore a guaranteed
                // no-op — return Ack so the UI can fold the action
                // away without surfacing an error.
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
        let entry_opt = {
            let mut map = self.sessions.lock().await;
            map.remove(session_id)
        };
        if let Some(entry) = entry_opt {
            entry.pump_abort.abort();
            let mut child = entry.child.lock().await;
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
        Ok(())
    }
}

// ── CLI flag mapping ────────────────────────────────────────────────────────

fn permission_mode_to_cli(m: ClaudeCodePermissionMode) -> &'static str {
    match m {
        ClaudeCodePermissionMode::Default => "default",
        ClaudeCodePermissionMode::AcceptEdits => "acceptEdits",
        ClaudeCodePermissionMode::Plan => "plan",
        ClaudeCodePermissionMode::Auto => "auto",
        ClaudeCodePermissionMode::DontAsk => "dontAsk",
        ClaudeCodePermissionMode::BypassPermissions => "bypassPermissions",
    }
}

// ── libc binding for group-kill (Unix only) ─────────────────────────────────
#[cfg(unix)]
const SIGKILL: i32 = 9;
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

// Path-import sentinel — silences an unused-import lint when the host
// platform is not Unix.
#[allow(dead_code)]
fn _path_import_marker(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_mode_cli_strings_cover_all_six_variants() {
        let modes = [
            (ClaudeCodePermissionMode::Default, "default"),
            (ClaudeCodePermissionMode::AcceptEdits, "acceptEdits"),
            (ClaudeCodePermissionMode::Plan, "plan"),
            (ClaudeCodePermissionMode::Auto, "auto"),
            (ClaudeCodePermissionMode::DontAsk, "dontAsk"),
            (
                ClaudeCodePermissionMode::BypassPermissions,
                "bypassPermissions",
            ),
        ];
        for (m, expected) in modes {
            assert_eq!(permission_mode_to_cli(m), expected);
        }
    }
}
