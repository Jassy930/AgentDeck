//! `ClaudeCodeAdapter` — spawns one `claude --print --output-format
//! stream-json` child per session (turn-scoped, matching the Codex
//! adapter shape, per spec § 5.2).
//!
//! Phase 4 Task 4B completes the v2 `Agent` trait surface scaffolded
//! in 4A:
//!
//!   - `capabilities()` — legacy compatibility 实例缓存一次真实 `claude --version`
//!     probe；canonical Runtime 实例固定使用预置 unknown 版本，避免 capability read
//!     绕过 exec gate。只有 state-vault canonical 实例广告已验证的 stdio Approval；
//!     legacy compatibility 实例仍隐藏 speculative legacy response wire。
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
//!     "approved":<bool>}` JSON line to CC's stdin. It reports success
//!     only after payload, newline and flush all complete. Real-fixture
//!     verification is still deferred, so this path is not advertised
//!     as a production Approval capability.
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

use crate::agent::{
    AdapterStateHandle, Agent, AgentEventSender, AgentSessionHandle, AgentTurnRequest,
    CanonicalAgentEvent, CanonicalAgentEventSender, CanonicalAgentSessionHandle,
    CanonicalHistoryRead, ExecSpec, PrepareAdapterTurnCapability, PreparedAgentTurn,
};
use crate::claude_code::driver::ClaudeCodePreparedTurn;
use crate::claude_code::state::ClaudeCodeStateRepository;
use crate::claude_code::translate::ClaudeCodeTranslator;
use crate::runtime::store::{
    ClaudeCodeAdapterStateVault, RuntimeId, RuntimeIdKind, RuntimeStoreError,
};
use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, ConfigurationError, ConversationConfiguration,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentItem, AgentKind, ClaudeCodePermissionMode,
    ClaudeCodeSessionOptions, ClaudeCodeVendorControl, HistoryListItem, HistoryRequest,
    HistoryResponse, ProtocolError, ServerEvent, SessionCapabilities, SessionId, SessionStart,
    ThreadId, VendorControlPayload, VendorSessionOptions,
};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{Mutex, mpsc};

const CANONICAL_CLAUDE_CODE_VERSION: &str = "claude unknown";

/// Shared routing table for permission responses. Cloned into both
/// the stdout pump (writer side) and `SessionEntry` (reader side
/// when `submit_decision` arrives).
type PermissionRoutes = Arc<Mutex<HashMap<String, String>>>;

/// Per-session bag of mutable state the adapter keeps alive for
/// `submit_decision` / `cancel`.
struct SessionEntry {
    child: Arc<Mutex<Child>>,
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
    state_repository: Option<ClaudeCodeStateRepository>,
}

impl ClaudeCodeAdapter {
    pub fn new() -> Self {
        Self {
            cli_version: OnceLock::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            state_repository: None,
        }
    }

    /// P3 canonical Runtime constructor。只有 `runtime::AgentRouter` 能从 singleton
    /// store 构造对应 vault；adapter 本身拿不到另一 vendor 的 capability。
    #[must_use]
    pub(crate) fn with_state_vault(vault: ClaudeCodeAdapterStateVault) -> Self {
        // 威胁场景：canonical snapshot 若在 Fence/release 外 lazy probe PATH 中的
        // vendor binary，恶意或有副作用的 binary 会绕过唯一 spawn owner。
        Self {
            cli_version: OnceLock::from(CANONICAL_CLAUDE_CODE_VERSION.to_owned()),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            state_repository: Some(ClaudeCodeStateRepository::new(vault)),
        }
    }

    /// 本机显式 import/reconciliation 入口。调用方只能提交 native history
    /// candidate；本模块会读回唯一 regular/non-memory JSONL 后才绑定，且不返回
    /// native session id。该入口不是 Runtime/Relay wire command。
    pub async fn rebuild_managed_index_from_native_history(
        &self,
        adapter_state_key: RuntimeId,
        native: &HistoryListItem,
    ) -> Result<(), ProtocolError> {
        ensure_adapter_state_key(adapter_state_key)?;
        let repository = self
            .state_repository
            .as_ref()
            .ok_or_else(|| ProtocolError {
                code: "adapter-state-not-configured".into(),
                message: "Claude Code private state repository is not configured".into(),
                diagnostic_ref: None,
            })?;
        crate::claude_code::history::rebuild_managed_index(repository, adapter_state_key, native)
            .await
    }

    /// Test convenience constructor — functionally identical to `new`.
    pub fn new_for_test() -> Self {
        Self::new()
    }

    /// Build a `SessionCapabilities` payload, caching the
    /// `claude --version` probe behind a `OnceLock` (one shell-out
    /// per process).
    fn capabilities_for_v2(&self) -> SessionCapabilities {
        use crate::claude_code::capabilities::{
            build_canonical_claude_code_capabilities, build_claude_code_capabilities,
            probe_claude_code_version,
        };
        let version = self
            .cli_version
            .get_or_init(probe_claude_code_version)
            .clone();
        if self.state_repository.is_some() {
            build_canonical_claude_code_capabilities(version)
        } else {
            build_claude_code_capabilities(version)
        }
    }

    /// Build the `claude` command line from a `SessionStart`. Wraps the
    /// vendor-options destructure + flag mapping in one place so
    /// `start_session` and `continue_thread` agree on encoding.
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
        if let Some(tools) = &opts.allowed_tools
            && !tools.is_empty()
        {
            cmd.arg("--tools").arg(tools.join(","));
        }
        if let Some(tools) = &opts.disallowed_tools
            && !tools.is_empty()
        {
            cmd.arg("--disallowedTools").arg(tools.join(","));
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
        resume_thread_id: Option<ThreadId>,
        prompt_override: Option<String>,
        canonical_expected_thread_id: Option<ThreadId>,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        // Preflight per spec § 5.8 — run BEFORE we mint a session id
        // or emit SessionStarted, so a missing binary / bad version /
        // logged-out user surfaces as a single clean error rather than
        // a half-started session.
        self.preflight(&events, None).await?;

        let (mut cmd, permission_mode) = Self::build_command(&start, resume_thread_id.as_ref())?;
        let session_id = SessionId(uuid::Uuid::new_v4().to_string());
        let compatibility_thread_id = resume_thread_id
            .clone()
            .or_else(|| canonical_expected_thread_id.clone());

        // N7: SessionStarted + SessionCapabilities BEFORE any AgentItem.
        let caps = self.capabilities_for_v2();
        let _ = events
            .send(ServerEvent::SessionStarted {
                session_id: session_id.clone(),
                thread_id: compatibility_thread_id.clone(),
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
        let mut reader = BufReader::new(stdout);
        let mut buffered_lines: Vec<String> = Vec::new();

        // clean/safe-mode CC 在首个 prompt 前不会发 frame，不能把用户 hooks 当作
        // identity handshake。canonical 路径先让 CLI 完成参数解析并确认进程没有
        // 早退；真正 authoritative `system.init` 在 prompt 后同步校验，校验前既不
        // 返回 handle，也不发布 canonical 事件。
        if canonical_expected_thread_id.is_some() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some(status) = child.try_wait().map_err(|error| ProtocolError {
                code: "cc-session-startup-status".into(),
                message: format!("inspect Claude Code startup status: {error}"),
                diagnostic_ref: None,
            })? {
                return Err(ProtocolError {
                    code: "cc-session-identity-eof".into(),
                    message: format!(
                        "Claude Code exited before accepting the persisted native session: {status}"
                    ),
                    diagnostic_ref: None,
                });
            }
        }

        // Write the initial prompt (if any) as a stream-json user line.
        let prompt = prompt_override.or(start.prompt.clone());
        if let Some(prompt) = prompt {
            let line = serde_json::to_string(&serde_json::json!({
                "type": "user",
                "message": { "role": "user", "content": prompt },
            }))
            .unwrap_or_default();
            let write_result = async {
                stdin.write_all(line.as_bytes()).await?;
                stdin.write_all(b"\n").await?;
                stdin.flush().await
            }
            .await;
            if let Err(error) = write_result {
                let protocol_error = ProtocolError {
                    code: "cc-stdin-write-failed".into(),
                    message: format!("claude child closed stdin before initial prompt: {error}"),
                    diagnostic_ref: None,
                };
                let _ = events
                    .send(ServerEvent::Error {
                        session_id: Some(session_id.clone()),
                        error: protocol_error.clone(),
                    })
                    .await;
                let _ = child.start_kill();
                return Err(protocol_error);
            }
        }

        // init 是 CC 对本次 native session 的 authoritative frame。canonical
        // start/continue 在它匹配前不返回 handle，也不向 Runtime 发布任何事件。
        if let Some(expected) = canonical_expected_thread_id.as_ref()
            && !buffered_lines
                .iter()
                .any(|line| is_authoritative_init(line, expected))
        {
            match read_authoritative_identity(&mut reader, expected).await {
                Ok(lines) => buffered_lines.extend(lines),
                Err(error) => {
                    let _ = child.start_kill();
                    return Err(error);
                }
            }
        }
        let child = Arc::new(Mutex::new(child));

        // Build the per-session shared routes up front so the pump
        // and the entry hold the same Arc.
        let permission_routes: PermissionRoutes = Arc::new(Mutex::new(HashMap::new()));

        let translator_thread_id = compatibility_thread_id.clone();
        let expected_native_session = compatibility_thread_id.clone();
        let pump_session = session_id.clone();
        let pump_events = events.clone();
        let pump_routes = Arc::clone(&permission_routes);
        let pump_child = Arc::clone(&child);
        let pump_handle = tokio::spawn(async move {
            let mut translator = ClaudeCodeTranslator::new(pump_session.clone(), permission_mode);
            if let Some(tid) = translator_thread_id {
                translator.set_thread_id(tid);
            }
            let mut buffered_lines = buffered_lines.into_iter();
            loop {
                let next_line = match buffered_lines.next() {
                    Some(line) => Ok(Some(line)),
                    None => {
                        let mut line = String::new();
                        match reader.read_line(&mut line).await {
                            Ok(0) => Ok(None),
                            Ok(_) => Ok(Some(line)),
                            Err(error) => Err(error),
                        }
                    }
                };
                match next_line {
                    Ok(Some(line)) => {
                        if let Some(expected) = expected_native_session.as_ref() {
                            let observed = observed_native_session_id(&line);
                            if observed
                                .as_deref()
                                .is_some_and(|observed| observed != expected.0.as_str())
                            {
                                let _ = pump_events
                                    .send(ServerEvent::Error {
                                        session_id: Some(pump_session.clone()),
                                        error: ProtocolError {
                                            code: "cc-session-id-mismatch".into(),
                                            message: "Claude Code reported a session id that does not match the persisted private mapping".into(),
                                            diagnostic_ref: None,
                                        },
                                    })
                                    .await;
                                let mut child = pump_child.lock().await;
                                let _ = child.start_kill();
                                return;
                            }
                        }
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
            child,
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
            thread_id: compatibility_thread_id,
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

fn ensure_adapter_state_key(adapter_state_key: RuntimeId) -> Result<(), ProtocolError> {
    if adapter_state_key.kind() != RuntimeIdKind::AdapterState {
        return Err(ProtocolError {
            code: "adapter-state-invalid-key".into(),
            message: "canonical Claude Code continue requires an adapterStateKey".into(),
            diagnostic_ref: None,
        });
    }
    Ok(())
}

fn adapter_state_error(error: RuntimeStoreError) -> ProtocolError {
    ProtocolError {
        code: error.code().into(),
        message: format!("Claude Code private state operation failed: {error}"),
        diagnostic_ref: None,
    }
}

async fn bind_and_verify_typed_state(
    repository: &ClaudeCodeStateRepository,
    adapter_state_key: RuntimeId,
    native_session: &ThreadId,
) -> Result<(), ProtocolError> {
    let first = repository
        .bind(adapter_state_key, native_session.clone())
        .await;
    let mut observed = repository
        .resolve(adapter_state_key)
        .await
        .map_err(|_| typed_prepare_error("cc-state-readback-failed"))?;
    if observed.as_ref() == Some(native_session) {
        return Ok(());
    }
    if observed.is_some() {
        return Err(typed_prepare_error("cc-state-readback-mismatch"));
    }
    if first.is_err() {
        repository
            .bind(adapter_state_key, native_session.clone())
            .await
            .map_err(|_| typed_prepare_error("cc-state-bind-failed"))?;
        observed = repository
            .resolve(adapter_state_key)
            .await
            .map_err(|_| typed_prepare_error("cc-state-readback-failed"))?;
    }
    if observed.as_ref() == Some(native_session) {
        Ok(())
    } else {
        Err(typed_prepare_error("cc-state-readback-mismatch"))
    }
}

fn typed_prepare_error(code: &str) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: "Claude Code typed execution preparation failed".to_owned(),
        diagnostic_ref: None,
    }
}

const CC_IDENTITY_TIMEOUT: Duration = Duration::from_secs(20);
const CC_IDENTITY_MAX_LINES: usize = 256;
const CC_IDENTITY_MAX_BYTES: usize = 2 * 1024 * 1024;

/// 同步读取 CC startup identity，整个 phase 共用一个 deadline 与固定 bytes/lines
/// 上界。任何观察到的不同 session id 都立即 fail-close；EOF/缺 init 不能被当作成功。
async fn read_authoritative_identity<R>(
    reader: &mut R,
    expected: &ThreadId,
) -> Result<Vec<String>, ProtocolError>
where
    R: AsyncBufRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + CC_IDENTITY_TIMEOUT;
    let mut lines = Vec::new();
    let mut bytes = 0_usize;
    loop {
        if lines.len() >= CC_IDENTITY_MAX_LINES || bytes >= CC_IDENTITY_MAX_BYTES {
            return Err(ProtocolError {
                code: "cc-session-identity-too-large".into(),
                message: "Claude Code session identity handshake exceeded its bounded buffer"
                    .into(),
                diagnostic_ref: None,
            });
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(identity_timeout_error());
        }
        let mut line = String::new();
        let read = tokio::time::timeout(remaining, reader.read_line(&mut line))
            .await
            .map_err(|_| identity_timeout_error())?
            .map_err(|error| ProtocolError {
                code: "cc-session-identity-read".into(),
                message: format!("read Claude Code session identity frame: {error}"),
                diagnostic_ref: None,
            })?;
        if read == 0 {
            return Err(ProtocolError {
                code: "cc-session-identity-eof".into(),
                message: "Claude Code exited before confirming the expected native session".into(),
                diagnostic_ref: None,
            });
        }
        bytes = bytes.checked_add(read).ok_or_else(|| ProtocolError {
            code: "cc-session-identity-too-large".into(),
            message: "Claude Code session identity handshake size overflow".into(),
            diagnostic_ref: None,
        })?;
        if bytes > CC_IDENTITY_MAX_BYTES {
            return Err(ProtocolError {
                code: "cc-session-identity-too-large".into(),
                message: "Claude Code session identity handshake exceeded its bounded buffer"
                    .into(),
                diagnostic_ref: None,
            });
        }

        let parsed = serde_json::from_str::<serde_json::Value>(&line).ok();
        let observed = parsed
            .as_ref()
            .and_then(|value| value.get("session_id"))
            .and_then(serde_json::Value::as_str);
        if observed.is_some_and(|observed| observed != expected.0.as_str()) {
            return Err(ProtocolError {
                code: "cc-session-id-mismatch".into(),
                message:
                    "Claude Code reported a session id that does not match the persisted private mapping"
                        .into(),
                diagnostic_ref: None,
            });
        }
        let is_system = parsed
            .as_ref()
            .and_then(|value| value.get("type"))
            .and_then(serde_json::Value::as_str)
            == Some("system");
        let subtype = parsed
            .as_ref()
            .and_then(|value| value.get("subtype"))
            .and_then(serde_json::Value::as_str);
        let qualifies =
            observed == Some(expected.0.as_str()) && is_system && subtype == Some("init");
        let init_missing_id = is_system && subtype == Some("init") && observed.is_none();
        lines.push(line);
        if init_missing_id {
            return Err(ProtocolError {
                code: "cc-session-id-missing".into(),
                message: "Claude Code init frame omitted the expected native session id".into(),
                diagnostic_ref: None,
            });
        }
        if qualifies {
            return Ok(lines);
        }
    }
}

fn identity_timeout_error() -> ProtocolError {
    ProtocolError {
        code: "cc-session-identity-timeout".into(),
        message: "Claude Code did not emit an authoritative init frame for the expected session"
            .into(),
        diagnostic_ref: None,
    }
}

fn observed_native_session_id(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn is_authoritative_init(line: &str, expected: &ThreadId) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .is_some_and(|value| {
            value.get("type").and_then(serde_json::Value::as_str) == Some("system")
                && value.get("subtype").and_then(serde_json::Value::as_str) == Some("init")
                && value.get("session_id").and_then(serde_json::Value::as_str)
                    == Some(expected.0.as_str())
        })
}

/// `ServerEvent` 属于 stdio compatibility wire，会反复附带 raw ThreadId。
/// canonical bridge 在 CC 私域剥离 routing identity，并拒绝可能包含 session id 的
/// unmodeled Raw payload。
fn canonicalize_event(event: ServerEvent) -> Option<CanonicalAgentEvent> {
    match event {
        ServerEvent::SessionStarted { .. } => None,
        ServerEvent::SessionCapabilities { capabilities, .. } => {
            Some(CanonicalAgentEvent::Capabilities(capabilities))
        }
        ServerEvent::AgentItem {
            item: AgentItem::Raw { .. },
            ..
        } => Some(CanonicalAgentEvent::Error(ProtocolError {
            code: "adapter-raw-event-blocked".into(),
            message:
                "Claude Code emitted an unmodeled frame that is unavailable on canonical Runtime"
                    .into(),
            diagnostic_ref: None,
        })),
        ServerEvent::AgentItem { item, .. } => Some(CanonicalAgentEvent::Item(item)),
        ServerEvent::ActionRequest { request, .. } => {
            Some(CanonicalAgentEvent::ActionRequest(request))
        }
        ServerEvent::TurnComplete { summary, .. } => {
            Some(CanonicalAgentEvent::TurnComplete(summary))
        }
        ServerEvent::Error { error, .. } => Some(CanonicalAgentEvent::Error(ProtocolError {
            code: error.code,
            message: "Claude Code adapter reported a private failure; see local diagnostics".into(),
            diagnostic_ref: None,
        })),
        ServerEvent::VendorControl { payload, .. } => {
            Some(CanonicalAgentEvent::VendorControl(payload))
        }
        ServerEvent::VendorPanelEvent { payload, .. } => {
            Some(CanonicalAgentEvent::VendorPanelEvent(payload))
        }
    }
}

fn spawn_canonical_event_bridge(
    mut compatibility_events: mpsc::Receiver<ServerEvent>,
    canonical_events: CanonicalAgentEventSender,
) {
    tokio::spawn(async move {
        while let Some(event) = compatibility_events.recv().await {
            let Some(event) = canonicalize_event(event) else {
                continue;
            };
            if canonical_events.send(event).await.is_err() {
                return;
            }
        }
    });
}

#[async_trait::async_trait]
impl Agent for ClaudeCodeAdapter {
    fn kind(&self) -> AgentKind {
        AgentKind::ClaudeCode
    }

    fn capabilities(&self) -> SessionCapabilities {
        self.capabilities_for_v2()
    }

    fn default_configuration(&self) -> Result<ConversationConfiguration, ConfigurationError> {
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .map(VendorConfigurationSnapshot::ClaudeCode)
        .map(ConversationConfiguration::new)
    }

    async fn prepare_adapter_turn(
        &self,
        _capability: &mut PrepareAdapterTurnCapability,
        request: AgentTurnRequest,
        state: AdapterStateHandle,
    ) -> Result<Box<dyn PreparedAgentTurn>, ProtocolError> {
        let configuration = match request.execution_configuration().vendor_control() {
            VendorConfigurationSnapshot::ClaudeCode(configuration) => configuration.clone(),
            VendorConfigurationSnapshot::Codex(_) => {
                return Err(typed_prepare_error("cc-configuration-mismatch"));
            }
        };
        let repository = self
            .state_repository
            .clone()
            .ok_or_else(|| typed_prepare_error("cc-state-vault-unavailable"))?;
        let existing = repository
            .resolve(state.key())
            .await
            .map_err(|_| typed_prepare_error("cc-state-resolve-failed"))?;
        let (native_session, was_already_bound) = match existing {
            Some(existing) => (existing, true),
            None => {
                let generated = ThreadId(uuid::Uuid::new_v4().to_string());
                bind_and_verify_typed_state(&repository, state.key(), &generated).await?;
                (generated, false)
            }
        };
        let use_resume = was_already_bound
            && crate::claude_code::history::native_session_is_materialized(&native_session).await?;

        // 威胁场景：typed prepare 若从 daemon 继承 PATH 选择 vendor，项目目录中的同名
        // 程序可在 gate 清空环境前被固化为绝对路径。解析必须与 gate 的固定 SAFE_PATH
        // 使用同一信任根，且 vendor 首次执行仍由 current-binary exec gate 独占。
        let program = crate::exec_gate::resolve_trusted_program("claude")
            .ok_or_else(|| typed_prepare_error("cc-binary-not-found"))?;
        let args = typed_execution_args(&configuration, &native_session, use_resume);
        let cwd = request.cwd().to_path_buf();
        let exec_spec = ExecSpec::new(&request, state, program, args, cwd)
            .map_err(|_| typed_prepare_error("cc-exec-spec-invalid"))?;
        let (_, _, prompt, _, _) = request.into_parts();
        Ok(Box::new(ClaudeCodePreparedTurn {
            exec_spec,
            repository,
            adapter_state_key: state.key(),
            expected_native_session: native_session,
            prompt: prompt.into_string(),
            permission_mode: configuration.permission_mode(),
        }))
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
        self.start_inner(start, events, None, None, None).await
    }

    async fn start_adapter_state(
        &self,
        adapter_state_key: RuntimeId,
        start: SessionStart,
        events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        ensure_adapter_state_key(adapter_state_key)?;
        if start.prompt.is_none() {
            return Err(ProtocolError {
                code: "adapter-state-initial-prompt-required".into(),
                message: "canonical Claude Code start requires the first prompt".into(),
                diagnostic_ref: None,
            });
        }
        let repository = self
            .state_repository
            .as_ref()
            .ok_or_else(|| ProtocolError {
                code: "adapter-state-not-configured".into(),
                message: "Claude Code private state repository is not configured".into(),
                diagnostic_ref: None,
            })?;
        let mut options = match start.vendor_options {
            VendorSessionOptions::ClaudeCode(options) => options,
            _ => {
                return Err(ProtocolError {
                    code: "wrong-vendor".into(),
                    message: "ClaudeCodeAdapter received non-ClaudeCode vendor options".into(),
                    diagnostic_ref: None,
                });
            }
        };
        if options.session_id.is_some() {
            return Err(ProtocolError {
                code: "adapter-state-vendor-id-forbidden".into(),
                message: "canonical Claude Code start does not accept a client-supplied session id"
                    .into(),
                diagnostic_ref: None,
            });
        }

        // CC supports caller-supplied --session-id, so bind the random native id
        // before spawn. A crash/retry reuses the exact persisted id instead of
        // creating an unaddressable native history row.
        let (native_session, was_already_bound) = match repository
            .resolve(adapter_state_key)
            .await
            .map_err(adapter_state_error)?
        {
            Some(existing) => (existing, true),
            None => {
                let generated = ThreadId(uuid::Uuid::new_v4().to_string());
                repository
                    .bind(adapter_state_key, generated.clone())
                    .await
                    .map_err(adapter_state_error)?;
                (generated, false)
            }
        };
        // A retry after the native JSONL was materialized must resume; a retry
        // after bind-but-before-spawn reuses the same --session-id. Never create
        // a second native identity for one adapterStateKey.
        let resume_thread_id = if was_already_bound
            && crate::claude_code::history::native_session_is_materialized(&native_session).await?
        {
            Some(native_session.clone())
        } else {
            None
        };
        options.session_id = resume_thread_id.is_none().then(|| native_session.0.clone());
        let canonical_start = SessionStart {
            agent_kind: AgentKind::ClaudeCode,
            cwd: start.cwd,
            prompt: start.prompt,
            vendor_options: VendorSessionOptions::ClaudeCode(options),
            runtime_options: start.runtime_options,
        };
        let (compatibility_events, compatibility_receiver) = mpsc::channel(512);
        let handle = self
            .start_inner(
                canonical_start,
                compatibility_events,
                resume_thread_id,
                None,
                Some(native_session),
            )
            .await?;
        spawn_canonical_event_bridge(compatibility_receiver, events);
        Ok(CanonicalAgentSessionHandle {
            session_id: handle.session_id,
            adapter_state_key,
            agent_kind: handle.agent_kind,
            abort_handle: handle.abort_handle,
        })
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
            agent_kind: AgentKind::ClaudeCode,
            cwd,
            prompt: Some(prompt.clone()),
            vendor_options: VendorSessionOptions::ClaudeCode(opts),
            runtime_options: Default::default(),
        };
        self.start_inner(synth_start, events, Some(thread_id), Some(prompt), None)
            .await
    }

    async fn continue_adapter_state(
        &self,
        adapter_state_key: RuntimeId,
        cwd: std::path::PathBuf,
        prompt: String,
        events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        ensure_adapter_state_key(adapter_state_key)?;
        let repository = self
            .state_repository
            .as_ref()
            .ok_or_else(|| ProtocolError {
                code: "adapter-state-not-configured".into(),
                message: "Claude Code private state repository is not configured".into(),
                diagnostic_ref: None,
            })?;
        let thread_id = repository
            .resolve(adapter_state_key)
            .await
            .map_err(adapter_state_error)?
            .ok_or_else(|| ProtocolError {
                code: "adapter-state-not-found".into(),
                message: "Claude Code resume mapping was not found".into(),
                diagnostic_ref: None,
            })?;
        if !crate::claude_code::history::native_session_is_materialized(&thread_id).await? {
            return Err(ProtocolError {
                code: "adapter-state-native-not-materialized".into(),
                message: "Claude Code private mapping has no unique native history session".into(),
                diagnostic_ref: None,
            });
        }
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
            session_id: None,
        };
        let synth_start = SessionStart {
            agent_kind: AgentKind::ClaudeCode,
            cwd,
            prompt: Some(prompt.clone()),
            vendor_options: VendorSessionOptions::ClaudeCode(opts),
            runtime_options: Default::default(),
        };
        let (compatibility_events, compatibility_receiver) = mpsc::channel(512);
        let handle = self
            .start_inner(
                synth_start,
                compatibility_events,
                Some(thread_id.clone()),
                Some(prompt),
                Some(thread_id),
            )
            .await?;
        spawn_canonical_event_bridge(compatibility_receiver, events);
        Ok(CanonicalAgentSessionHandle {
            session_id: handle.session_id,
            adapter_state_key,
            agent_kind: handle.agent_kind,
            abort_handle: handle.abort_handle,
        })
    }

    async fn read_adapter_history(
        &self,
        adapter_state_key: RuntimeId,
    ) -> Result<CanonicalHistoryRead, ProtocolError> {
        ensure_adapter_state_key(adapter_state_key)?;
        let repository = self
            .state_repository
            .as_ref()
            .ok_or_else(|| ProtocolError {
                code: "adapter-state-not-configured".into(),
                message: "Claude Code private state repository is not configured".into(),
                diagnostic_ref: None,
            })?;
        let response =
            crate::claude_code::history::read_managed_history(repository, adapter_state_key)
                .await?;
        if response
            .turns
            .iter()
            .flat_map(|turn| &turn.items)
            .any(|item| matches!(item, AgentItem::Raw { .. }))
        {
            return Err(ProtocolError {
                code: "adapter-raw-history-blocked".into(),
                message: "Claude Code history contains an unmodeled vendor frame".into(),
                diagnostic_ref: None,
            });
        }
        Ok(CanonicalHistoryRead {
            agent_kind: AgentKind::ClaudeCode,
            turns: response.turns,
        })
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
        deliver_permission_decision(entry.permission_routes.as_ref(), &entry.stdin, &decision).await
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

async fn write_permission_response_line<W>(writer: &mut W, line: &str) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| ProtocolError {
            code: "cc-decision-write".into(),
            message: format!("write permission_response payload to claude stdin: {e}"),
            diagnostic_ref: None,
        })?;
    writer.write_all(b"\n").await.map_err(|e| ProtocolError {
        code: "cc-decision-write".into(),
        message: format!("write permission_response newline to claude stdin: {e}"),
        diagnostic_ref: None,
    })?;
    writer.flush().await.map_err(|e| ProtocolError {
        code: "cc-decision-write".into(),
        message: format!("flush permission_response to claude stdin: {e}"),
        diagnostic_ref: None,
    })?;
    Ok(())
}

async fn deliver_permission_decision<W>(
    permission_routes: &Mutex<HashMap<String, String>>,
    stdin: &Mutex<W>,
    decision: &ActionDecision,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    // Serialize lookup, complete JSONL write+flush and route consumption
    // under one guard so concurrent decisions cannot duplicate delivery.
    let mut routes = permission_routes.lock().await;
    let tool_use_id = routes
        .get(&decision.request_id)
        .cloned()
        .ok_or_else(|| ProtocolError {
            code: "cc-decision-no-route".into(),
            message: format!(
                "no pending permission for request_id {}",
                decision.request_id
            ),
            diagnostic_ref: None,
        })?;
    let approved = matches!(decision.decision, ActionDecisionKind::Approve);
    // Speculative wire shape — keep production Approval hidden until a
    // recorded fixture or live gate verifies these field names.
    let line = serde_json::to_string(&serde_json::json!({
        "type": "permission_response",
        "tool_use_id": tool_use_id,
        "approved": approved,
    }))
    .map_err(|e| ProtocolError {
        code: "cc-decision-encode".into(),
        message: format!("encode permission_response for claude stdin: {e}"),
        diagnostic_ref: None,
    })?;
    let mut writer = stdin.lock().await;
    write_permission_response_line(&mut *writer, &line).await?;
    drop(writer);
    routes.remove(&decision.request_id);
    Ok(())
}

// ── CLI flag mapping ────────────────────────────────────────────────────────

pub(super) fn typed_execution_args(
    configuration: &ClaudeCodeConversationConfiguration,
    native_session: &ThreadId,
    use_resume: bool,
) -> Vec<OsString> {
    let mut args = [
        "--print",
        "--output-format",
        "stream-json",
        "--input-format",
        "stream-json",
        "--permission-prompt-tool",
        "stdio",
        "--verbose",
        "--permission-mode",
        permission_mode_to_cli(configuration.permission_mode()),
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    if let Some(model) = configuration.model() {
        args.push(OsString::from("--model"));
        args.push(OsString::from(model));
    }
    if let Some(effort) = configuration.effort() {
        args.push(OsString::from("--effort"));
        args.push(OsString::from(effort));
    }
    if let Some(output_style) = configuration.output_style() {
        args.push(OsString::from("--output-style"));
        args.push(OsString::from(output_style));
    }
    args.push(OsString::from(if use_resume {
        "--resume"
    } else {
        "--session-id"
    }));
    args.push(OsString::from(&native_session.0));
    args
}

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
    use crate::agent::CanonicalAgentEvent;
    use agentdeck_protocol::{AgentItem, AgentItemMeta, ServerEvent};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWriteExt;
    use tokio::io::{AsyncReadExt, AsyncWrite};

    #[derive(Clone, Copy)]
    enum WriteFault {
        None,
        Payload,
        PartialPayload,
        Newline,
        Flush,
    }

    struct FaultWriter {
        fault: WriteFault,
        write_calls: usize,
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl FaultWriter {
        fn new(fault: WriteFault) -> Self {
            Self {
                fault,
                write_calls: 0,
                bytes: Vec::new(),
                flushes: 0,
            }
        }
    }

    impl AsyncWrite for FaultWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let call = self.write_calls;
            self.write_calls += 1;
            match (self.fault, call) {
                (WriteFault::Payload, 0) | (WriteFault::Newline, 1) => {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected")))
                }
                (WriteFault::PartialPayload, 0) => {
                    let written = buf.len().max(2) / 2;
                    self.bytes.extend_from_slice(&buf[..written]);
                    Poll::Ready(Ok(written))
                }
                (WriteFault::PartialPayload, 1) => {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected")))
                }
                _ => {
                    self.bytes.extend_from_slice(buf);
                    Poll::Ready(Ok(buf.len()))
                }
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            if matches!(self.fault, WriteFault::Flush) {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected")))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn permission_response_requires_payload_newline_and_flush_before_success() {
        let mut writer = FaultWriter::new(WriteFault::None);
        write_permission_response_line(&mut writer, r#"{"approved":true}"#)
            .await
            .expect("complete JSONL delivery");
        assert_eq!(writer.bytes, b"{\"approved\":true}\n");
        assert_eq!(writer.flushes, 1);
    }

    #[tokio::test]
    async fn permission_response_propagates_every_write_and_flush_failure() {
        const LINE: &str = r#"{"approved":true}"#;
        for (fault, expected_stage) in [
            (WriteFault::Payload, "payload"),
            (WriteFault::PartialPayload, "payload"),
            (WriteFault::Newline, "newline"),
            (WriteFault::Flush, "flush"),
        ] {
            let mut writer = FaultWriter::new(fault);
            let error = write_permission_response_line(&mut writer, LINE)
                .await
                .expect_err("injected delivery failure must be visible");
            assert_eq!(error.code, "cc-decision-write");
            assert!(
                error.message.contains(expected_stage),
                "expected {expected_stage} failure, got {}",
                error.message
            );
            match fault {
                WriteFault::Payload => {
                    assert!(writer.bytes.is_empty());
                    assert_eq!(writer.flushes, 0);
                }
                WriteFault::PartialPayload => {
                    assert!(!writer.bytes.is_empty());
                    assert!(writer.bytes.len() < LINE.len());
                    assert_eq!(writer.flushes, 0);
                }
                WriteFault::Newline => {
                    assert_eq!(writer.bytes, LINE.as_bytes());
                    assert_eq!(writer.flushes, 0);
                }
                WriteFault::Flush => {
                    assert_eq!(writer.bytes, b"{\"approved\":true}\n");
                    assert_eq!(writer.flushes, 1);
                }
                WriteFault::None => unreachable!("success is covered separately"),
            }
        }
    }

    #[tokio::test]
    async fn permission_route_is_single_flight_and_written_once() {
        let routes = Arc::new(Mutex::new(HashMap::from([(
            "request-under-test".into(),
            "tool-use-7".into(),
        )])));
        let (writer, mut reader) = tokio::io::duplex(1);
        let stdin = Arc::new(Mutex::new(writer));

        let first = {
            let routes = Arc::clone(&routes);
            let stdin = Arc::clone(&stdin);
            tokio::spawn(async move {
                deliver_permission_decision(
                    routes.as_ref(),
                    stdin.as_ref(),
                    &ActionDecision {
                        request_id: "request-under-test".into(),
                        decision: ActionDecisionKind::Approve,
                        persist: false,
                    },
                )
                .await
            })
        };
        tokio::task::yield_now().await;
        let second = {
            let routes = Arc::clone(&routes);
            let stdin = Arc::clone(&stdin);
            tokio::spawn(async move {
                deliver_permission_decision(
                    routes.as_ref(),
                    stdin.as_ref(),
                    &ActionDecision {
                        request_id: "request-under-test".into(),
                        decision: ActionDecisionKind::Approve,
                        persist: false,
                    },
                )
                .await
            })
        };
        tokio::task::yield_now().await;
        let reader_task = tokio::spawn(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.expect("read wire");
            bytes
        });

        let (first, second) = tokio::join!(first, second);
        let results = [first.expect("first task"), second.expect("second task")];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results.iter().any(|result| {
            result
                .as_ref()
                .is_err_and(|error| error.code == "cc-decision-no-route")
        }));
        assert!(routes.lock().await.is_empty());
        drop(stdin);
        let wire = reader_task.await.expect("reader task");
        assert_eq!(wire.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&wire).expect("one JSONL frame"),
            serde_json::json!({
                "type": "permission_response",
                "tool_use_id": "tool-use-7",
                "approved": true,
            })
        );
    }

    #[tokio::test]
    async fn permission_route_is_retained_when_flush_fails() {
        let routes = Mutex::new(HashMap::from([(
            "request-under-test".into(),
            "tool-use-7".into(),
        )]));
        let stdin = Mutex::new(FaultWriter::new(WriteFault::Flush));
        let error = deliver_permission_decision(
            &routes,
            &stdin,
            &ActionDecision {
                request_id: "request-under-test".into(),
                decision: ActionDecisionKind::Approve,
                persist: false,
            },
        )
        .await
        .expect_err("flush failure is not an acknowledgement");
        assert_eq!(error.code, "cc-decision-write");
        assert!(routes.lock().await.contains_key("request-under-test"));
    }

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

    #[test]
    fn canonical_retry_uses_resume_only_after_private_native_materialization() {
        let native = ThreadId("10000000-0000-0000-0000-000000000001".into());
        let options = ClaudeCodeSessionOptions {
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
            session_id: Some(native.0.clone()),
        };
        let start = SessionStart {
            agent_kind: AgentKind::ClaudeCode,
            cwd: std::env::current_dir().unwrap(),
            prompt: Some("prompt".into()),
            vendor_options: VendorSessionOptions::ClaudeCode(options),
            runtime_options: Default::default(),
        };

        let (new_command, _) = ClaudeCodeAdapter::build_command(&start, None).unwrap();
        let new_args: Vec<_> = new_command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(new_args.iter().any(|arg| arg == "--session-id"));
        assert!(!new_args.iter().any(|arg| arg == "--resume"));

        let (resume_command, _) = ClaudeCodeAdapter::build_command(&start, Some(&native)).unwrap();
        let resume_args: Vec<_> = resume_command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(resume_args.iter().any(|arg| arg == "--resume"));
        assert!(!resume_args.iter().any(|arg| arg == "--session-id"));
    }

    #[test]
    fn native_session_id_extraction_is_strict_and_ignores_unrelated_lines() {
        assert_eq!(
            observed_native_session_id(r#"{"type":"system","session_id":"expected"}"#).as_deref(),
            Some("expected")
        );
        assert_eq!(
            observed_native_session_id(r#"{"type":"system","sessionId":"wrong-key"}"#),
            None
        );
        assert_eq!(observed_native_session_id("not-json"), None);
    }

    async fn identity_reader(input: &str) -> BufReader<tokio::io::DuplexStream> {
        let (mut writer, reader) = tokio::io::duplex(16 * 1024);
        writer
            .write_all(input.as_bytes())
            .await
            .expect("write identity fixture");
        drop(writer);
        BufReader::new(reader)
    }

    #[tokio::test]
    async fn canonical_identity_handshake_requires_authoritative_init_match() {
        let expected = ThreadId("10000000-0000-0000-0000-000000000001".into());
        let mut reader = identity_reader(
            r#"{"type":"system","subtype":"init","session_id":"10000000-0000-0000-0000-000000000001"}
"#,
        )
        .await;
        assert_eq!(
            read_authoritative_identity(&mut reader, &expected)
                .await
                .expect("matching authoritative init")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn canonical_identity_handshake_rejects_mismatch_missing_id_and_eof() {
        let expected = ThreadId("10000000-0000-0000-0000-000000000001".into());
        let mut mismatch = identity_reader(
            r#"{"type":"system","subtype":"hook_started","session_id":"20000000-0000-0000-0000-000000000002"}
"#,
        )
        .await;
        assert_eq!(
            read_authoritative_identity(&mut mismatch, &expected)
                .await
                .expect_err("mismatched session must fail")
                .code,
            "cc-session-id-mismatch"
        );

        let mut missing = identity_reader(
            r#"{"type":"system","subtype":"init"}
"#,
        )
        .await;
        assert_eq!(
            read_authoritative_identity(&mut missing, &expected)
                .await
                .expect_err("init without session id must fail")
                .code,
            "cc-session-id-missing"
        );

        let mut eof = identity_reader("").await;
        assert_eq!(
            read_authoritative_identity(&mut eof, &expected)
                .await
                .expect_err("EOF before evidence must fail")
                .code,
            "cc-session-identity-eof"
        );
    }

    #[test]
    fn canonical_boundary_drops_routing_ids_and_blocks_raw_vendor_frames() {
        assert!(
            canonicalize_event(ServerEvent::SessionStarted {
                session_id: SessionId("transient".into()),
                thread_id: Some(ThreadId("private-session".into())),
                agent_kind: AgentKind::ClaudeCode,
            })
            .is_none()
        );
        let event = canonicalize_event(ServerEvent::AgentItem {
            session_id: SessionId("transient".into()),
            thread_id: ThreadId("private-session".into()),
            agent_kind: AgentKind::ClaudeCode,
            item: AgentItem::Raw {
                raw_kind: "unknown".into(),
                raw_payload: r#"{"session_id":"private-session"}"#.into(),
                meta: AgentItemMeta::default(),
            },
        })
        .expect("raw frame becomes a typed failure");
        assert!(matches!(
            event,
            CanonicalAgentEvent::Error(error) if error.code == "adapter-raw-event-blocked"
        ));
        let error = canonicalize_event(ServerEvent::Error {
            session_id: Some(SessionId("transient".into())),
            error: ProtocolError {
                code: "cc-private-error".into(),
                message: "failed session_id=private-session".into(),
                diagnostic_ref: Some("private-session".into()),
            },
        })
        .expect("private error becomes canonical error");
        match error {
            CanonicalAgentEvent::Error(error) => {
                assert_eq!(error.code, "cc-private-error");
                assert!(!error.message.contains("private-session"));
                assert!(error.diagnostic_ref.is_none());
            }
            other => panic!("expected canonical error, got {other:?}"),
        }
    }
}
