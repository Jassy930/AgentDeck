//! `ClaudeCodeAdapter` — one long-lived `claude --print
//! --input-format stream-json --output-format stream-json
//! --permission-prompt-tool stdio` child per AgentDeck session.
//!
//! The adapter runs preflight, builds the command line, emits
//! `SessionStarted` + `SessionCapabilities` (N7) and hands the child to
//! the session owner in `session.rs`, which serializes turns, approvals,
//! interrupts and permission-mode changes over CC's stream-json control
//! protocol. The owner reports cleanup through `AgentSessionHandle::exit`
//! so RuntimeHub emits the unique `SessionClosed`.

use crate::agent::{Agent, AgentEventSender, AgentSessionHandle};
use crate::claude_code::session::{self, OwnerStart, SessionCommand, spawn_owner};
use agentdeck_protocol::{
    ActionDecision, AgentKind, ClaudeCodePermissionMode, ClaudeCodeSessionOptions,
    ClaudeCodeVendorControl, HistoryReply, HistoryRequest, HistoryResponse, ImageAttachment,
    InitialTurn, ProtocolError, ServerEvent, SessionCapabilities, SessionId, SessionStart,
    ThreadId, TurnId, VendorControlPayload, VendorSessionOptions,
};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc, oneshot};

/// Claude Code adapter — v2 `Agent` implementation.
pub struct ClaudeCodeAdapter {
    cli_version: OnceLock<String>,
    /// Live session owners' mailboxes.
    sessions: Arc<Mutex<HashMap<SessionId, mpsc::Sender<SessionCommand>>>>,
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
    /// The returned `ThreadId` is CC's session id: the resumed one, the
    /// caller's `session_id`, or a fresh UUID passed via `--session-id`, so
    /// every event can carry it before `system.init` arrives.
    fn build_command(
        start: &SessionStart,
    ) -> Result<(Command, ClaudeCodePermissionMode, ThreadId), ProtocolError> {
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
            .arg("--permission-prompt-tool")
            .arg("stdio")
            // Hidden in 2.1.304's --help: lets set_permission_mode switch to
            // bypassPermissions mid-session. It does not change the start mode.
            .arg("--allow-dangerously-skip-permissions")
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
        let thread_id = if let Some(id) = &start.resume_thread_id {
            cmd.arg("--resume").arg(&id.0);
            id.clone()
        } else {
            let id = opts
                .session_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            cmd.arg("--session-id").arg(&id);
            ThreadId(id)
        };

        cmd.current_dir(&start.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }
        Ok((cmd, opts.permission_mode, thread_id))
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
        let session_id = start.session_id.clone();
        self.preflight(&events, Some(&session_id)).await?;

        let (mut cmd, permission_mode, thread_id) = Self::build_command(&start)?;
        let child = cmd.spawn().map_err(|e| ProtocolError {
            code: "cc-spawn-failed".into(),
            message: format!("failed to spawn `claude`: {e}"),
            diagnostic_ref: None,
        })?;

        let _ = events
            .send(ServerEvent::SessionStarted {
                session_id: session_id.clone(),
                thread_id: Some(thread_id.clone()),
                agent_kind: AgentKind::ClaudeCode,
            })
            .await;
        let _ = events
            .send(ServerEvent::SessionCapabilities {
                session_id: session_id.clone(),
                agent_kind: AgentKind::ClaudeCode,
                capabilities: self.capabilities_for_v2(),
            })
            .await;

        let (exit_tx, exit_rx) = oneshot::channel();
        let (commands, abort_handle) = spawn_owner(
            child,
            OwnerStart {
                session_id: session_id.clone(),
                thread_id: thread_id.clone(),
                permission_mode,
                initial_turn: start.initial_turn,
            },
            events,
            exit_tx,
        )?;
        self.sessions
            .lock()
            .await
            .insert(session_id.clone(), commands);

        Ok(AgentSessionHandle {
            session_id,
            thread_id: Some(thread_id),
            agent_kind: AgentKind::ClaudeCode,
            abort_handle,
            exit: Some(exit_rx),
        })
    }

    /// Send one command to a live session owner and wait for its answer.
    async fn dispatch(
        &self,
        session_id: &SessionId,
        command: impl FnOnce(session::Reply) -> SessionCommand,
    ) -> Result<(), ProtocolError> {
        let sender = self
            .sessions
            .lock()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| ProtocolError {
                code: "session-not-found".into(),
                message: format!("Claude Code session {} is not live", session_id.0),
                diagnostic_ref: None,
            })?;
        let closed = || ProtocolError {
            code: "session-closing".into(),
            message: format!("Claude Code session {} is closing", session_id.0),
            diagnostic_ref: None,
        };
        let (reply, answer) = oneshot::channel();
        sender.send(command(reply)).await.map_err(|_| closed())?;
        answer.await.map_err(|_| closed())?
    }
}

impl Default for ClaudeCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Agent for ClaudeCodeAdapter {
    fn kind(&self) -> AgentKind {
        AgentKind::ClaudeCode
    }

    /// capabilities 的版本在进程内缓存；机器页（尤其更新之后）要现探。
    async fn detected_version(&self) -> String {
        tokio::task::spawn_blocking(crate::claude_code::capabilities::probe_claude_code_version)
            .await
            .unwrap_or_else(|_| "claude unknown".to_string())
    }

    async fn install_command(&self) -> Result<tokio::process::Command, ProtocolError> {
        let mut command = tokio::process::Command::new("bash");
        command.args([
            "-o",
            "pipefail",
            "-c",
            "curl -fsSL https://claude.ai/install.sh | bash",
        ]);
        Ok(command)
    }

    async fn update_command(&self) -> Result<tokio::process::Command, ProtocolError> {
        let mut command = tokio::process::Command::new("claude");
        command.arg("update");
        Ok(command)
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
                images: Vec::new(),
            }),
            vendor_options: VendorSessionOptions::ClaudeCode(opts),
            runtime_options: Default::default(),
        };
        self.start_inner(synth_start, events).await
    }

    async fn start_turn(
        &self,
        session_id: &SessionId,
        turn_id: TurnId,
        prompt: String,
        images: Vec<ImageAttachment>,
    ) -> Result<(), ProtocolError> {
        self.dispatch(session_id, |reply| SessionCommand::StartTurn {
            turn_id,
            prompt,
            images,
            reply,
        })
        .await
    }

    async fn cancel_turn(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
    ) -> Result<(), ProtocolError> {
        let turn_id = turn_id.clone();
        self.dispatch(session_id, |reply| SessionCommand::CancelTurn {
            turn_id,
            reply,
        })
        .await
    }

    async fn close_session(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        self.dispatch(session_id, |reply| SessionCommand::Close { reply })
            .await
    }

    async fn session_retired(&self, session_id: &SessionId, _cleanup_confirmed: bool) {
        self.sessions.lock().await.remove(session_id);
    }

    async fn submit_decision(
        &self,
        session_id: &SessionId,
        decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        self.dispatch(session_id, |reply| SessionCommand::Decision {
            decision,
            reply,
        })
        .await
    }

    async fn submit_vendor_control(
        &self,
        session_id: &SessionId,
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
            ClaudeCodeVendorControl::UpdatePermissionMode(mode) => {
                self.dispatch(session_id, |reply| SessionCommand::SetPermissionMode {
                    mode,
                    reply,
                })
                .await
            }
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
    async fn handle_history(&self, request: HistoryRequest) -> Result<HistoryReply, ProtocolError> {
        use crate::claude_code::history;
        match request {
            HistoryRequest::List {
                cwd_filter, limit, ..
            } => {
                let items = history::list_history(cwd_filter.as_deref(), limit).await?;
                Ok(HistoryResponse::List(items).into())
            }
            HistoryRequest::Read { thread_id, .. } => {
                let resp = history::read_history(&thread_id).await?;
                Ok(HistoryResponse::Read(resp).into())
            }
            HistoryRequest::Archive { thread_id, .. } => {
                history::archive(&thread_id).await?;
                Ok(HistoryResponse::Ack.into())
            }
            HistoryRequest::Unarchive { .. } => {
                // CC: `claude rm` is soft; --resume always finds the
                // jsonl back. Unarchive is therefore a guaranteed
                // no-op — return Ack so the UI can fold the action
                // away without surfacing an error.
                Ok(HistoryResponse::Ack.into())
            }
            HistoryRequest::Rename {
                thread_id, title, ..
            } => {
                history::rename(&thread_id, &title).await?;
                Ok(HistoryResponse::Ack.into())
            }
        }
    }

    /// Legacy teardown entry; the owner path is `close_session`. Unknown or
    /// already-closing sessions are fine: there is nothing left to stop.
    async fn cancel(&self, session_id: &SessionId) -> Result<(), ProtocolError> {
        match self.close_session(session_id).await {
            Err(e) if e.code == "session-not-found" || e.code == "session-closing" => Ok(()),
            result => result,
        }
    }
}

// ── CLI flag mapping ────────────────────────────────────────────────────────

pub(super) fn permission_mode_to_cli(m: ClaudeCodePermissionMode) -> &'static str {
    match m {
        ClaudeCodePermissionMode::Default => "default",
        ClaudeCodePermissionMode::AcceptEdits => "acceptEdits",
        ClaudeCodePermissionMode::Plan => "plan",
        ClaudeCodePermissionMode::Auto => "auto",
        ClaudeCodePermissionMode::DontAsk => "dontAsk",
        ClaudeCodePermissionMode::BypassPermissions => "bypassPermissions",
    }
}

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
