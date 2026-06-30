//! `ClaudeCodeAdapter` — spawns one `claude --print --output-format
//! stream-json` child per session (turn-scoped, matching the Codex
//! adapter shape, per spec § 5.2).
//!
//! Phase 4 Task 4A. This file implements the v2 `Agent` trait surface
//! that 4A is responsible for:
//!
//!   - `kind()` / `capabilities()` — `capabilities` returns a
//!     **placeholder** SessionCapabilities (empty feature set, default
//!     vendor block, "claude pending" version) so the daemon can satisfy
//!     N7 ("SessionCapabilities before any AgentItem") for early
//!     end-to-end smoke. Task 4B replaces with a real probe
//!     (`claude --version`, `claude auth status`, plugin scan).
//!
//!   - `start_session()` — spawns the CLI, emits SessionStarted +
//!     placeholder SessionCapabilities synchronously, then pumps stdout
//!     through `ClaudeCodeTranslator` on a background task.
//!
//!   - `continue_thread()` — same but with `--resume <thread_id>`.
//!
//!   - `cancel()` — aborts the pump and best-effort group-kills the
//!     child subprocess tree.
//!
//!   - `submit_decision()` / `submit_vendor_control()` — return
//!     structured `pending-task-4b` errors so the hub surfaces them as
//!     diagnostics rather than silently dropping. The wire shape for
//!     CC's permission response and runtime control needs a real fixture,
//!     which 4B records.

use crate::agent::{Agent, AgentEventSender, AgentSessionHandle};
use crate::claude_code::translate::ClaudeCodeTranslator;
use agentdeck_protocol::{
    ActionDecision, AgentKind, ClaudeCodeCapabilities, ClaudeCodePermissionMode,
    ClaudeCodeSessionOptions, ProtocolError, ServerEvent, SessionCapabilities, SessionId,
    SessionStart, ThreadId, VendorCapabilities, VendorControlPayload, VendorSessionOptions,
};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;

/// Per-session bag of mutable state the adapter keeps alive for
/// `submit_decision` / `submit_vendor_control` / `cancel`. Task 4A only
/// populates `child` + `stdin` + `pump_abort`; `permission_routes` is
/// pre-allocated for 4B (when CC permission responses are wired).
struct SessionEntry {
    child: Mutex<Child>,
    #[allow(dead_code)] // Task 4B uses this when wiring permission responses
    stdin: Mutex<ChildStdin>,
    /// `request_id` (= `tool_use_id` from the prompt translator) →
    /// arbitrary route payload. Empty in 4A; Task 4B populates.
    #[allow(dead_code)]
    permission_routes: Mutex<HashMap<String, String>>,
    pump_abort: tokio::task::AbortHandle,
}

/// Claude Code adapter — v2 `Agent` implementation.
pub struct ClaudeCodeAdapter {
    sessions: Arc<Mutex<HashMap<SessionId, Arc<SessionEntry>>>>,
}

impl ClaudeCodeAdapter {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Test convenience constructor — functionally identical to `new`.
    pub fn new_for_test() -> Self {
        Self::new()
    }

    /// Placeholder capabilities. Task 4B replaces with a real probe.
    fn placeholder_capabilities() -> SessionCapabilities {
        SessionCapabilities {
            agent_kind: AgentKind::ClaudeCode,
            agent_version: "claude pending".to_string(),
            features: BTreeSet::new(),
            vendor: VendorCapabilities::ClaudeCode(ClaudeCodeCapabilities::default()),
        }
    }

    /// Build the `claude` command line from a `SessionStart`. Wraps the
    /// vendor-options destructure + flag mapping in one place so
    /// `start_session` and `continue_thread` agree on encoding.
    ///
    /// Returns `(Command, permission_mode)` — the permission mode is
    /// passed downstream to the translator so every `ActionRequest`
    /// stamps the correct value.
    fn build_command(
        start: &SessionStart,
        resume_thread_id: Option<&ThreadId>,
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
        if let Some(id) = resume_thread_id {
            // Continuing — both --resume <id> AND --session-id <id>
            // (CC uses the latter to bind a known UUID).
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

    /// Shared driver behind `start_session` and `continue_thread`.
    async fn start_inner(
        &self,
        start: SessionStart,
        events: AgentEventSender,
        resume_thread_id: Option<ThreadId>,
        prompt_override: Option<String>,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        let (mut cmd, permission_mode) =
            Self::build_command(&start, resume_thread_id.as_ref())?;
        let session_id = SessionId(uuid::Uuid::new_v4().to_string());

        // N7: SessionStarted + SessionCapabilities BEFORE any AgentItem.
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
                capabilities: Self::placeholder_capabilities(),
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
        let prompt = prompt_override.or(start.prompt.clone());
        if let Some(prompt) = prompt {
            let line = serde_json::to_string(&serde_json::json!({
                "type": "user",
                "message": { "role": "user", "content": prompt },
            }))
            .unwrap_or_default();
            if stdin.write_all(line.as_bytes()).await.is_err() {
                // child crashed before we could write — surface as
                // structured error so caller knows.
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

        // Stamp the resume thread id (if any) into the translator so
        // events have it populated even before `system.subtype=init`
        // arrives.
        let translator_thread_id = resume_thread_id.clone();
        let pump_session = session_id.clone();
        let pump_events = events.clone();
        let pump_handle = tokio::spawn(async move {
            let mut translator =
                ClaudeCodeTranslator::new(pump_session.clone(), permission_mode);
            if let Some(tid) = translator_thread_id {
                translator.set_thread_id(tid);
            }
            let mut lines = BufReader::new(stdout).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let out = translator.translate_line(&line);
                        for event in out.events {
                            if pump_events.send(event).await.is_err() {
                                return;
                            }
                        }
                        // permission_route_hint: Task 4B records.
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
            permission_routes: Mutex::new(HashMap::new()),
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
        Self::placeholder_capabilities()
    }

    async fn start_session(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        // Validate vendor options up front so we never spawn `claude`
        // with a wrong-vendor config. Mirrors CodexAdapter check.
        if !matches!(start.vendor_options, VendorSessionOptions::ClaudeCode(_)) {
            return Err(ProtocolError {
                code: "wrong-vendor".into(),
                message: "ClaudeCodeAdapter received non-ClaudeCode vendor options".into(),
                diagnostic_ref: None,
            });
        }
        self.start_inner(start, events, None, None).await
    }

    async fn continue_thread(
        &self,
        thread_id: ThreadId,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        // continue_thread on the Agent trait doesn't carry vendor
        // options — Task 4B + Phase 4 hub plumbing will look up the
        // saved permission_mode for the resumed thread. For 4A we
        // default to BypassPermissions so the resumed turn flows
        // end-to-end without prompting (matching v0.2 spec § 5.5
        // "approval double track" interim posture).
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
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let synth_start = SessionStart {
            agent_kind: AgentKind::ClaudeCode,
            cwd,
            prompt: Some(prompt.clone()),
            vendor_options: VendorSessionOptions::ClaudeCode(opts),
            runtime_options: Default::default(),
        };
        self.start_inner(synth_start, events, Some(thread_id), Some(prompt))
            .await
    }

    async fn submit_decision(
        &self,
        _session_id: &SessionId,
        _decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError {
            code: "cc-submit-decision-pending-task-4b".into(),
            message: "Claude Code permission-response wire format is captured \
                      by Task 4B (needs a real `--permission-mode default` \
                      fixture); v0.2 spec § 5.5"
                .into(),
            diagnostic_ref: None,
        })
    }

    async fn submit_vendor_control(
        &self,
        _session_id: &SessionId,
        payload: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        match payload {
            VendorControlPayload::ClaudeCode(_) => Err(ProtocolError {
                code: "cc-vendor-control-pending-task-4b".into(),
                message: "Claude Code vendor controls (permission mode, \
                          output style, hook add/remove) are implemented in \
                          Task 4B / Phase 4 hardening"
                    .into(),
                diagnostic_ref: None,
            }),
            VendorControlPayload::Codex(_) => Err(ProtocolError {
                code: "wrong-vendor".into(),
                message: "ClaudeCodeAdapter received non-ClaudeCode vendor control".into(),
                diagnostic_ref: None,
            }),
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
//
// Mirrors `codex::adapter` so the two adapters stay symmetric without
// taking a dependency on the `libc` crate. Negative pid = "every process
// in the group whose pgid == pid".
#[cfg(unix)]
const SIGKILL: i32 = 9;
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

// Path-import sentinel — silences an unused-import lint when the
// host platform is not Unix (the cwd PathBuf import is needed for both
// branches, but the lints differ).
#[allow(dead_code)]
fn _path_import_marker(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_mode_cli_strings_cover_all_six_variants() {
        // Hard-coded list so a future protocol addition forces a
        // compiler error here (match exhaustiveness above) AND a test
        // signal (this assertion).
        let modes = [
            (ClaudeCodePermissionMode::Default, "default"),
            (ClaudeCodePermissionMode::AcceptEdits, "acceptEdits"),
            (ClaudeCodePermissionMode::Plan, "plan"),
            (ClaudeCodePermissionMode::Auto, "auto"),
            (ClaudeCodePermissionMode::DontAsk, "dontAsk"),
            (ClaudeCodePermissionMode::BypassPermissions, "bypassPermissions"),
        ];
        for (m, expected) in modes {
            assert_eq!(permission_mode_to_cli(m), expected);
        }
    }
}
