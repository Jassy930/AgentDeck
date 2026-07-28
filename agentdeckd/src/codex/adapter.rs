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

use crate::agent::{
    AdapterStateHandle, Agent, AgentEventSender, AgentSessionHandle, AgentTurnRequest,
    CanonicalAgentEvent, CanonicalAgentEventSender, CanonicalAgentSessionHandle,
    CanonicalHistoryRead, ExecSpec, PrepareAdapterTurnCapability, PreparedAgentTurn,
};
use crate::codex::app_server::{
    StderrTail, drain_child_stderr, kill_process_group, request_response, spawn_child, write_frame,
};
use crate::codex::capabilities::{build_codex_capabilities, probe_codex_version};
use crate::codex::driver::CodexPreparedTurn;
use crate::codex::state::CodexStateRepository;
use crate::codex::translate::CodexTranslator;
use crate::runtime::store::{CodexAdapterStateVault, RuntimeId, RuntimeIdKind, RuntimeStoreError};
use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConfigurationError, ConversationConfiguration,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentItem, AgentKind, CodexApprovalPolicy,
    CodexReasoningEffort, CodexSandboxMode, CodexSessionOptions, HistoryRequest, HistoryResponse,
    ProtocolError, ServerEvent, SessionCapabilities, SessionId, SessionStart, ThreadId,
    VendorControlPayload, VendorSessionOptions,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::{Mutex, mpsc};

pub(super) const CANONICAL_CODEX_CLI_VERSION: &str = "0.145.0";
const CANONICAL_CODEX_VERSION: &str = "codex-cli 0.145.0";

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
/// Cheap to construct。Legacy compatibility 实例最多 probe 一次 `codex --version`；
/// canonical Runtime 实例预置与官方 schema 同步的固定版本，真实 app-server 在
/// release 后 initialize 响应中做 exact readback；capability read 禁止绕过 exec gate。
pub struct CodexAdapter {
    cli_version: OnceLock<String>,
    sessions: Arc<Mutex<HashMap<SessionId, SessionHandle>>>,
    state_repository: Option<CodexStateRepository>,
}

impl CodexAdapter {
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
    pub(crate) fn with_state_vault(vault: CodexAdapterStateVault) -> Self {
        // 威胁场景：canonical snapshot 若在 Fence/release 外 lazy probe PATH 中的
        // vendor binary，恶意或有副作用的 binary 会绕过唯一 spawn owner。
        Self {
            cli_version: OnceLock::from(CANONICAL_CODEX_VERSION.to_owned()),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            state_repository: Some(CodexStateRepository::new(vault)),
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
        bind_adapter_state: Option<(RuntimeId, CodexStateRepository)>,
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
            let result = request_response(
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
            validate_resume_result_thread_id(&result, &tid)?;
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

        // Canonical new-conversation path: persist the vendor ref after
        // thread/start returns it but before the first prompt/turn can cross the
        // side-effect boundary. Exact retry is handled by the private store row.
        if let Some((adapter_state_key, repository)) = bind_adapter_state {
            repository
                .bind(adapter_state_key, thread_id.clone())
                .await
                .map_err(adapter_state_error)?;
        }

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
        if observed_codex_thread_id(&line_buf)
            .as_deref()
            .is_some_and(|observed| observed != state.thread_id.0.as_str())
        {
            let _ = events
                .send(ServerEvent::Error {
                    session_id: Some(session_id.clone()),
                    error: ProtocolError {
                        code: "codex-thread-id-mismatch".into(),
                        message: "Codex reported a thread id that does not match the persisted private mapping".into(),
                        diagnostic_ref: None,
                    },
                })
                .await;
            let mut child = state.child.lock().await;
            let _ = child.start_kill();
            return;
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

fn observed_codex_thread_id(line: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(line).ok()?;
    let params = value.get("params");
    params
        .and_then(|params| params.get("threadId"))
        .or_else(|| params?.get("item")?.get("threadId"))
        .or_else(|| value.get("result")?.get("thread")?.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn validate_resume_result_thread_id(
    result: &Value,
    expected: &ThreadId,
) -> Result<(), ProtocolError> {
    let observed = result
        .get("thread")
        .and_then(|thread| thread.get("id"))
        .and_then(Value::as_str);
    if observed != Some(expected.0.as_str()) {
        return Err(ProtocolError {
            code: "codex-thread-id-mismatch".into(),
            message: "Codex resume result does not match the persisted private mapping".into(),
            diagnostic_ref: None,
        });
    }
    Ok(())
}

/// 把旧 translator 的 `ServerEvent` 收窄为 canonical adapter event。所有
/// session/thread/agent routing 字段都在 Codex 私域丢弃；未经建模的 Raw frame
/// 可能含 `threadId`，因此 fail-close 为 typed error，绝不透传 payload。
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
            message: "Codex emitted an unmodeled frame that is unavailable on canonical Runtime"
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
            message: "Codex adapter reported a private failure; see local diagnostics".into(),
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
impl Agent for CodexAdapter {
    fn kind(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn capabilities(&self) -> SessionCapabilities {
        self.capabilities_for_v2()
    }

    fn default_configuration(&self) -> Result<ConversationConfiguration, ConfigurationError> {
        Ok(ConversationConfiguration::new(
            VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                CodexApprovalPolicy::OnRequest,
                CodexSandboxMode::WorkspaceWrite,
                CodexReasoningEffort::Medium,
            )),
        ))
    }

    async fn prepare_adapter_turn(
        &self,
        _capability: &mut PrepareAdapterTurnCapability,
        request: AgentTurnRequest,
        state: AdapterStateHandle,
    ) -> Result<Box<dyn PreparedAgentTurn>, ProtocolError> {
        let configuration = match request.execution_configuration().vendor_control() {
            VendorConfigurationSnapshot::Codex(configuration) => configuration.clone(),
            VendorConfigurationSnapshot::ClaudeCode(_) => {
                return Err(typed_prepare_error("codex-configuration-mismatch"));
            }
        };
        let repository = self
            .state_repository
            .clone()
            .ok_or_else(|| typed_prepare_error("codex-state-vault-unavailable"))?;
        let resume_thread_id = repository
            .resolve(state.key())
            .await
            .map_err(|_| typed_prepare_error("codex-state-resolve-failed"))?;

        // 威胁场景：typed prepare 若从 daemon 继承 PATH 选择 vendor，项目目录中的同名
        // 程序可在 gate 清空环境前被固化为绝对路径。解析必须与 gate 的固定 SAFE_PATH
        // 使用同一信任根，且真正的 vendor process 仍只能由 exec gate 启动。
        let program = crate::exec_gate::resolve_trusted_program("codex")
            .ok_or_else(|| typed_prepare_error("codex-binary-not-found"))?;
        let cwd = request.cwd().to_path_buf();
        let exec_spec = ExecSpec::new(
            &request,
            state,
            program,
            [std::ffi::OsString::from("app-server")],
            cwd.clone(),
        )
        .map_err(|_| typed_prepare_error("codex-exec-spec-invalid"))?;
        let (_, _, prompt, _, _) = request.into_parts();
        Ok(Box::new(CodexPreparedTurn {
            exec_spec,
            repository,
            adapter_state_key: state.key(),
            resume_thread_id,
            cwd,
            prompt: prompt.into_string(),
            approval_policy: configuration.approval_policy(),
            sandbox: configuration.sandbox(),
            reasoning_effort: configuration.reasoning_effort(),
        }))
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
        self.start_inner(&start.cwd, &codex_options, start.prompt, None, events, None)
            .await
    }

    async fn start_adapter_state(
        &self,
        adapter_state_key: RuntimeId,
        start: SessionStart,
        events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        ensure_adapter_state_key(adapter_state_key)?;
        let repository = self.state_repository.clone().ok_or_else(|| ProtocolError {
            code: "adapter-state-not-configured".into(),
            message: "Codex private state repository is not configured".into(),
            diagnostic_ref: None,
        })?;
        let codex_options = match start.vendor_options {
            VendorSessionOptions::Codex(options) => options,
            _ => {
                return Err(ProtocolError {
                    code: "wrong-vendor".into(),
                    message: "CodexAdapter received non-Codex vendor options".into(),
                    diagnostic_ref: None,
                });
            }
        };
        let existing = repository
            .resolve(adapter_state_key)
            .await
            .map_err(adapter_state_error)?;
        let binding = if existing.is_some() {
            None
        } else {
            Some((adapter_state_key, repository))
        };
        // 旧 translator 仍产出带 ThreadId 的 ServerEvent；先在 adapter 私域
        // 有界缓冲，只有 private bind/handshake 全部成功后才启动净化 bridge。
        let (compatibility_events, compatibility_receiver) = mpsc::channel(512);
        let handle = self
            .start_inner(
                &start.cwd,
                &codex_options,
                start.prompt,
                existing,
                compatibility_events,
                binding,
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
        self.start_inner(&cwd, &opts, Some(prompt), Some(thread_id), events, None)
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
                message: "Codex private state repository is not configured".into(),
                diagnostic_ref: None,
            })?;
        let thread_id = repository
            .resolve(adapter_state_key)
            .await
            .map_err(adapter_state_error)?
            .ok_or_else(|| ProtocolError {
                code: "adapter-state-not-found".into(),
                message: "Codex resume mapping was not found".into(),
                diagnostic_ref: None,
            })?;
        let opts = CodexSessionOptions {
            sandbox: CodexSandboxMode::WorkspaceWrite,
            approval_policy: CodexApprovalPolicy::OnRequest,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Medium,
            mcp_overrides: vec![],
        };
        let (compatibility_events, compatibility_receiver) = mpsc::channel(512);
        let handle = self
            .start_inner(
                &cwd,
                &opts,
                Some(prompt),
                Some(thread_id),
                compatibility_events,
                None,
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
                message: "Codex private state repository is not configured".into(),
                diagnostic_ref: None,
            })?;
        let response =
            crate::codex::history::read_managed_history(repository, adapter_state_key).await?;
        if response
            .turns
            .iter()
            .flat_map(|turn| &turn.items)
            .any(|item| matches!(item, AgentItem::Raw { .. }))
        {
            return Err(ProtocolError {
                code: "adapter-raw-history-blocked".into(),
                message: "Codex history contains an unmodeled vendor frame".into(),
                diagnostic_ref: None,
            });
        }
        Ok(CanonicalHistoryRead {
            agent_kind: AgentKind::Codex,
            turns: response.turns,
        })
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
        deliver_approval_decision(&state.approval_routes, &state.stdin, &decision)
            .await
            .map_err(|error| state.stderr_tail.enrich_error(error))
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

fn ensure_adapter_state_key(adapter_state_key: RuntimeId) -> Result<(), ProtocolError> {
    if adapter_state_key.kind() != RuntimeIdKind::AdapterState {
        return Err(ProtocolError {
            code: "adapter-state-invalid-key".into(),
            message: "canonical Codex continue requires an adapterStateKey".into(),
            diagnostic_ref: None,
        });
    }
    Ok(())
}

fn adapter_state_error(error: RuntimeStoreError) -> ProtocolError {
    ProtocolError {
        code: error.code().into(),
        message: format!("Codex private state operation failed: {error}"),
        diagnostic_ref: None,
    }
}

fn typed_prepare_error(code: &str) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: "Codex typed execution preparation failed".to_owned(),
        diagnostic_ref: None,
    }
}

async fn deliver_approval_decision<W>(
    approval_routes: &Mutex<HashMap<String, ApprovalRoute>>,
    stdin: &Mutex<W>,
    decision: &ActionDecision,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    // Keep the route guard across the complete write+flush and consume it
    // only afterwards. This is the adapter-local single-flight boundary:
    // a concurrent decision cannot clone and write the same RPC route.
    let mut routes = approval_routes.lock().await;
    let route = routes
        .get(&decision.request_id)
        .cloned()
        .ok_or_else(|| ProtocolError {
            code: "approval-route-not-found".into(),
            message: format!("no pending approval for request_id={}", decision.request_id),
            diagnostic_ref: None,
        })?;
    let result = approval_response_body(&route.method, &route.params, decision)?;
    let frame = json!({ "id": route.rpc_id, "result": result });
    let mut writer = stdin.lock().await;
    write_decision_frame(&mut *writer, &frame).await?;
    drop(writer);
    routes.remove(&decision.request_id);
    Ok(())
}

async fn write_decision_frame<W>(writer: &mut W, frame: &Value) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_string(frame).map_err(|error| ProtocolError {
        code: "codex-encode-failed".into(),
        message: format!("serialize codex frame: {error}"),
        diagnostic_ref: None,
    })?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|error| ProtocolError {
            code: "codex-stdin-write-failed".into(),
            message: format!("write to codex stdin: {error}"),
            diagnostic_ref: None,
        })?;
    writer.flush().await.map_err(|error| ProtocolError {
        code: "codex-stdin-write-failed".into(),
        message: format!("flush codex stdin: {error}"),
        diagnostic_ref: None,
    })?;
    Ok(())
}

// ── Codex approval response builders ────────────────────────────────────────
//
// Mirrors the official generated app-server request/response schemas.
// Body shape and persistence representation differ per approval method;
// centralised here so the complete neutral decision is audited once.

pub(super) fn approval_response_body(
    method: &str,
    params: &Value,
    decision: &ActionDecision,
) -> Result<Value, ProtocolError> {
    match method {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
            let codex_decision = match (decision.decision, decision.persist) {
                (ActionDecisionKind::Approve, false) => "accept",
                (ActionDecisionKind::Approve, true) => "acceptForSession",
                (ActionDecisionKind::Deny, false) => "decline",
                (ActionDecisionKind::Deny, true) => {
                    return Err(ProtocolError {
                        code: "codex-invalid-persistent-decision".into(),
                        message: "Codex has no neutral persistent-deny approval response".into(),
                        diagnostic_ref: None,
                    });
                }
            };
            Ok(json!({ "decision": codex_decision }))
        }
        "item/permissions/requestApproval" => {
            let permissions = validated_permission_profile(params)?;
            match (decision.decision, decision.persist) {
                (ActionDecisionKind::Approve, persist) => Ok(json!({
                    "permissions": permissions,
                    "scope": if persist { "session" } else { "turn" },
                    "strictAutoReview": Value::Null,
                })),
                (ActionDecisionKind::Deny, false) => Ok(json!({
                    "permissions": {
                        "fileSystem": Value::Null,
                        "network": Value::Null,
                    },
                    "scope": "turn",
                    "strictAutoReview": true,
                })),
                (ActionDecisionKind::Deny, true) => Err(ProtocolError {
                    code: "codex-invalid-persistent-decision".into(),
                    message: "Codex has no neutral persistent-deny permission response".into(),
                    diagnostic_ref: None,
                }),
            }
        }
        // This method expects a typed answers map, not an approval
        // decision. Never fabricate an accept/decline response.
        "item/tool/requestUserInput" => Err(ProtocolError {
            code: "codex-unsupported-approval-method".into(),
            message: "item/tool/requestUserInput requires a typed answers response".into(),
            diagnostic_ref: None,
        }),
        other => Err(ProtocolError {
            code: "codex-unsupported-approval-method".into(),
            message: format!("unsupported approval request method: {other}"),
            diagnostic_ref: None,
        }),
    }
}

pub(super) fn validated_permission_profile(params: &Value) -> Result<Value, ProtocolError> {
    let profile = params
        .get("permissions")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_approval_params("permissions must be an object"))?;
    if let Some(unknown) = profile
        .keys()
        .find(|key| key.as_str() != "fileSystem" && key.as_str() != "network")
    {
        return Err(invalid_approval_params(&format!(
            "permissions contains unknown field {unknown}"
        )));
    }
    if let Some(file_system) = profile.get("fileSystem")
        && !file_system.is_null()
    {
        validate_file_system_permissions(file_system)?;
    }
    if let Some(network) = profile.get("network")
        && !network.is_null()
    {
        validate_network_permissions(network)?;
    }
    Ok(Value::Object(profile.clone()))
}

fn validate_file_system_permissions(value: &Value) -> Result<(), ProtocolError> {
    let permissions = value.as_object().ok_or_else(|| {
        invalid_approval_params("permissions.fileSystem must be an object or null")
    })?;
    reject_unknown_fields(
        permissions,
        &["entries", "globScanMaxDepth", "read", "write"],
        "permissions.fileSystem",
    )?;
    if let Some(depth) = permissions.get("globScanMaxDepth")
        && !depth.is_null()
        && depth.as_u64().is_none_or(|depth| depth == 0)
    {
        return Err(invalid_approval_params(
            "permissions.fileSystem.globScanMaxDepth must be a positive unsigned integer or null",
        ));
    }
    for field in ["read", "write"] {
        if let Some(paths) = permissions.get(field)
            && !paths.is_null()
        {
            let paths = paths.as_array().ok_or_else(|| {
                invalid_approval_params(&format!(
                    "permissions.fileSystem.{field} must be an array of absolute paths or null"
                ))
            })?;
            for path in paths {
                let path = path.as_str().ok_or_else(|| {
                    invalid_approval_params(&format!(
                        "permissions.fileSystem.{field} entries must be absolute path strings"
                    ))
                })?;
                validate_absolute_normal_path(path, &format!("permissions.fileSystem.{field}"))?;
            }
        }
    }
    if let Some(entries) = permissions.get("entries")
        && !entries.is_null()
    {
        let entries = entries.as_array().ok_or_else(|| {
            invalid_approval_params("permissions.fileSystem.entries must be an array or null")
        })?;
        for entry in entries {
            validate_file_system_entry(entry)?;
        }
    }
    Ok(())
}

fn validate_network_permissions(value: &Value) -> Result<(), ProtocolError> {
    let permissions = value
        .as_object()
        .ok_or_else(|| invalid_approval_params("permissions.network must be an object or null"))?;
    reject_unknown_fields(permissions, &["enabled"], "permissions.network")?;
    if let Some(enabled) = permissions.get("enabled")
        && !enabled.is_null()
        && !enabled.is_boolean()
    {
        return Err(invalid_approval_params(
            "permissions.network.enabled must be a boolean or null",
        ));
    }
    Ok(())
}

fn validate_file_system_entry(value: &Value) -> Result<(), ProtocolError> {
    let entry = value.as_object().ok_or_else(|| {
        invalid_approval_params("permissions.fileSystem.entries elements must be objects")
    })?;
    reject_unknown_fields(
        entry,
        &["access", "path"],
        "permissions.fileSystem.entries[]",
    )?;
    if !matches!(
        entry.get("access").and_then(Value::as_str),
        Some("read" | "write" | "none")
    ) {
        return Err(invalid_approval_params(
            "permissions.fileSystem.entries[].access must be read, write, or none",
        ));
    }
    validate_file_system_path(entry.get("path").ok_or_else(|| {
        invalid_approval_params("permissions.fileSystem.entries[].path is required")
    })?)
}

fn validate_file_system_path(value: &Value) -> Result<(), ProtocolError> {
    let path = value.as_object().ok_or_else(|| {
        invalid_approval_params("permissions.fileSystem.entries[].path must be an object")
    })?;
    match path.get("type").and_then(Value::as_str) {
        Some("path") => {
            reject_unknown_fields(path, &["type", "path"], "fileSystem path")?;
            let absolute = path.get("path").and_then(Value::as_str).ok_or_else(|| {
                invalid_approval_params("fileSystem path.path must be an absolute path string")
            })?;
            validate_absolute_normal_path(absolute, "fileSystem path.path")
        }
        Some("glob_pattern") => {
            reject_unknown_fields(path, &["type", "pattern"], "fileSystem glob path")?;
            if path.get("pattern").and_then(Value::as_str).is_none() {
                return Err(invalid_approval_params(
                    "fileSystem glob path.pattern must be a string",
                ));
            }
            Ok(())
        }
        Some("special") => {
            reject_unknown_fields(path, &["type", "value"], "fileSystem special path")?;
            validate_file_system_special_path(path.get("value").ok_or_else(|| {
                invalid_approval_params("fileSystem special path.value is required")
            })?)
        }
        _ => Err(invalid_approval_params(
            "fileSystem path.type must be path, glob_pattern, or special",
        )),
    }
}

fn validate_file_system_special_path(value: &Value) -> Result<(), ProtocolError> {
    let special = value.as_object().ok_or_else(|| {
        invalid_approval_params("fileSystem special path.value must be an object")
    })?;
    match special.get("kind").and_then(Value::as_str) {
        Some("root" | "minimal" | "tmpdir" | "slash_tmp") => {
            reject_unknown_fields(special, &["kind"], "fileSystem special path")
        }
        Some("project_roots") => {
            reject_unknown_fields(special, &["kind", "subpath"], "fileSystem special path")?;
            validate_optional_string(special.get("subpath"), "fileSystem special path.subpath")
        }
        Some("unknown") => {
            reject_unknown_fields(
                special,
                &["kind", "path", "subpath"],
                "fileSystem special path",
            )?;
            if special.get("path").and_then(Value::as_str).is_none() {
                return Err(invalid_approval_params(
                    "fileSystem unknown special path.path must be a string",
                ));
            }
            validate_optional_string(special.get("subpath"), "fileSystem special path.subpath")
        }
        _ => Err(invalid_approval_params(
            "fileSystem special path.kind is not a supported official value",
        )),
    }
}

fn validate_optional_string(value: Option<&Value>, field: &str) -> Result<(), ProtocolError> {
    if value.is_some_and(|value| !value.is_null() && !value.is_string()) {
        return Err(invalid_approval_params(&format!(
            "{field} must be a string or null"
        )));
    }
    Ok(())
}

pub(super) fn validate_absolute_normal_path(value: &str, field: &str) -> Result<(), ProtocolError> {
    use std::path::{Component, Path};

    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid_approval_params(&format!(
            "{field} must be absolute and normalized"
        )));
    }
    Ok(())
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), ProtocolError> {
    if let Some(unknown) = object
        .keys()
        .find(|candidate| !allowed.contains(&candidate.as_str()))
    {
        return Err(invalid_approval_params(&format!(
            "{field} contains unknown field {unknown}"
        )));
    }
    Ok(())
}

fn invalid_approval_params(reason: &str) -> ProtocolError {
    ProtocolError {
        code: "codex-invalid-approval-params".into(),
        message: format!("invalid Codex permission approval params: {reason}"),
        diagnostic_ref: None,
    }
}

// ── enum → wire string helpers ──────────────────────────────────────────────

pub(super) fn sandbox_mode_str(m: CodexSandboxMode) -> &'static str {
    match m {
        CodexSandboxMode::ReadOnly => "read-only",
        CodexSandboxMode::WorkspaceWrite => "workspace-write",
        // Codex's wire enum spells this `danger-full-access`. AgentDeck's
        // neutral enum is `FullAccess`; the rename is the vendor mapping
        // surface and lives here.
        CodexSandboxMode::FullAccess => "danger-full-access",
    }
}

pub(super) fn approval_policy_str(p: CodexApprovalPolicy) -> &'static str {
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

pub(super) fn reasoning_effort_str(e: CodexReasoningEffort) -> &'static str {
    match e {
        CodexReasoningEffort::Minimal => "minimal",
        CodexReasoningEffort::Low => "low",
        CodexReasoningEffort::Medium => "medium",
        CodexReasoningEffort::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalRoute, approval_response_body, canonicalize_event, deliver_approval_decision,
        observed_codex_thread_id, validate_resume_result_thread_id,
    };
    use crate::agent::CanonicalAgentEvent;
    use agentdeck_protocol::{
        ActionDecision, ActionDecisionKind, AgentItem, AgentItemMeta, AgentKind, ProtocolError,
        ServerEvent, SessionId, ThreadId,
    };
    use std::collections::HashMap;
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWrite};
    use tokio::sync::Mutex;

    struct FlushErrorWriter;

    struct WriteCountingWriter(Arc<AtomicUsize>);

    impl AsyncWrite for WriteCountingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FlushErrorWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected")))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn decision(kind: ActionDecisionKind, persist: bool) -> ActionDecision {
        ActionDecision {
            request_id: "request-under-test".into(),
            decision: kind,
            persist,
        }
    }

    #[test]
    fn command_and_file_approval_map_kind_and_persist_to_typed_codex_decisions() {
        for method in [
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
        ] {
            for (kind, persist, expected) in [
                (ActionDecisionKind::Approve, false, "accept"),
                (ActionDecisionKind::Approve, true, "acceptForSession"),
                (ActionDecisionKind::Deny, false, "decline"),
            ] {
                assert_eq!(
                    approval_response_body(
                        method,
                        &serde_json::json!({}),
                        &decision(kind, persist),
                    )
                    .expect("supported typed approval decision"),
                    serde_json::json!({"decision": expected}),
                );
            }

            let error = approval_response_body(
                method,
                &serde_json::json!({}),
                &decision(ActionDecisionKind::Deny, true),
            )
            .expect_err("Codex has no neutral persistent-deny decision");
            assert_eq!(error.code, "codex-invalid-persistent-decision");
        }
    }

    #[test]
    fn permission_approval_maps_persist_to_typed_scope_and_rejects_persistent_deny() {
        let params = serde_json::json!({
            "permissions": {
                "fileSystem": null,
                "network": {"enabled": true}
            }
        });
        for (persist, expected_scope) in [(false, "turn"), (true, "session")] {
            assert_eq!(
                approval_response_body(
                    "item/permissions/requestApproval",
                    &params,
                    &decision(ActionDecisionKind::Approve, persist),
                )
                .expect("typed permission approval"),
                serde_json::json!({
                    "permissions": params["permissions"],
                    "scope": expected_scope,
                    "strictAutoReview": null,
                }),
            );
        }

        assert_eq!(
            approval_response_body(
                "item/permissions/requestApproval",
                &params,
                &decision(ActionDecisionKind::Deny, false),
            )
            .expect("one-turn permission denial"),
            serde_json::json!({
                "permissions": {
                    "fileSystem": null,
                    "network": null,
                },
                "scope": "turn",
                "strictAutoReview": true,
            }),
        );

        let error = approval_response_body(
            "item/permissions/requestApproval",
            &params,
            &decision(ActionDecisionKind::Deny, true),
        )
        .expect_err("Codex has no neutral persistent-deny permission response");
        assert_eq!(error.code, "codex-invalid-persistent-decision");
    }

    #[test]
    fn permission_approval_rejects_malformed_required_typed_params() {
        for params in [
            serde_json::json!({}),
            serde_json::json!({"permissions": "all"}),
            serde_json::json!({"permissions": {"unknown": {}}}),
            serde_json::json!({"permissions": {"network": true}}),
            serde_json::json!({"permissions": {"network": {"enabled": "yes"}}}),
            serde_json::json!({"permissions": {"fileSystem": {"write": "not-an-array"}}}),
            serde_json::json!({"permissions": {"fileSystem": {"globScanMaxDepth": 0}}}),
            serde_json::json!({"permissions": {"fileSystem": {"entries": [{"path": "/tmp"}]}}}),
        ] {
            let error = approval_response_body(
                "item/permissions/requestApproval",
                &params,
                &decision(ActionDecisionKind::Approve, false),
            )
            .expect_err("malformed official permission params must fail closed");
            assert_eq!(error.code, "codex-invalid-approval-params");
        }
    }

    #[test]
    fn tool_user_input_is_not_misrepresented_as_an_approval_response() {
        let error = approval_response_body(
            "item/tool/requestUserInput",
            &serde_json::json!({}),
            &decision(ActionDecisionKind::Approve, false),
        )
        .expect_err("tool user input requires its typed answers response");
        assert_eq!(error.code, "codex-unsupported-approval-method");
    }

    #[tokio::test]
    async fn approval_route_is_single_flight_and_written_once() {
        let routes = Arc::new(Mutex::new(HashMap::from([(
            "request-under-test".into(),
            ApprovalRoute {
                rpc_id: 7,
                method: "item/commandExecution/requestApproval".into(),
                params: serde_json::json!({}),
            },
        )])));
        let (writer, mut reader) = tokio::io::duplex(1);
        let stdin = Arc::new(Mutex::new(writer));

        let first = {
            let routes = Arc::clone(&routes);
            let stdin = Arc::clone(&stdin);
            tokio::spawn(async move {
                deliver_approval_decision(
                    routes.as_ref(),
                    stdin.as_ref(),
                    &decision(ActionDecisionKind::Approve, false),
                )
                .await
            })
        };
        tokio::task::yield_now().await;
        let second = {
            let routes = Arc::clone(&routes);
            let stdin = Arc::clone(&stdin);
            tokio::spawn(async move {
                deliver_approval_decision(
                    routes.as_ref(),
                    stdin.as_ref(),
                    &decision(ActionDecisionKind::Approve, false),
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
                .is_err_and(|error| error.code == "approval-route-not-found")
        }));
        assert!(routes.lock().await.is_empty());
        drop(stdin);
        let wire = reader_task.await.expect("reader task");
        assert_eq!(wire.iter().filter(|byte| **byte == b'\n').count(), 1);
        let frame: serde_json::Value = serde_json::from_slice(&wire).expect("one JSON-RPC frame");
        assert_eq!(
            frame,
            serde_json::json!({"id": 7, "result": {"decision": "accept"}})
        );
    }

    #[tokio::test]
    async fn approval_route_is_retained_when_flush_fails() {
        let routes = Mutex::new(HashMap::from([(
            "request-under-test".into(),
            ApprovalRoute {
                rpc_id: 7,
                method: "item/fileChange/requestApproval".into(),
                params: serde_json::json!({}),
            },
        )]));
        let stdin = Mutex::new(FlushErrorWriter);
        let error = deliver_approval_decision(
            &routes,
            &stdin,
            &decision(ActionDecisionKind::Approve, false),
        )
        .await
        .expect_err("flush failure is not an acknowledgement");
        assert_eq!(error.code, "codex-stdin-write-failed");
        assert!(routes.lock().await.contains_key("request-under-test"));
    }

    #[tokio::test]
    async fn malformed_permission_params_are_rejected_before_write_and_retain_route() {
        let routes = Mutex::new(HashMap::from([(
            "request-under-test".into(),
            ApprovalRoute {
                rpc_id: 7,
                method: "item/permissions/requestApproval".into(),
                params: serde_json::json!({
                    "permissions": {"network": {"enabled": "yes"}}
                }),
            },
        )]));
        let writes = Arc::new(AtomicUsize::new(0));
        let stdin = Mutex::new(WriteCountingWriter(Arc::clone(&writes)));

        let error = deliver_approval_decision(
            &routes,
            &stdin,
            &decision(ActionDecisionKind::Approve, false),
        )
        .await
        .expect_err("malformed permission params must fail before adapter IO");

        assert_eq!(error.code, "codex-invalid-approval-params");
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        assert!(routes.lock().await.contains_key("request-under-test"));
    }

    #[test]
    fn thread_id_extraction_covers_notification_item_and_resume_result_shapes() {
        assert_eq!(
            observed_codex_thread_id(
                r#"{"method":"turn/started","params":{"threadId":"direct"}}"#,
            )
            .as_deref(),
            Some("direct")
        );
        assert_eq!(
            observed_codex_thread_id(
                r#"{"method":"item/started","params":{"item":{"threadId":"nested"}}}"#,
            )
            .as_deref(),
            Some("nested")
        );
        assert_eq!(
            observed_codex_thread_id(r#"{"id":2,"result":{"thread":{"id":"resume"}}}"#).as_deref(),
            Some("resume")
        );
        assert_eq!(observed_codex_thread_id("not-json"), None);
    }

    #[test]
    fn resume_result_requires_the_exact_persisted_thread_id() {
        let expected = ThreadId("persisted-private-thread".into());
        validate_resume_result_thread_id(
            &serde_json::json!({"thread": {"id": expected.0}}),
            &expected,
        )
        .expect("exact authoritative resume id");
        for result in [
            serde_json::json!({}),
            serde_json::json!({"thread": {}}),
            serde_json::json!({"thread": {"id": "different-thread"}}),
        ] {
            let error = validate_resume_result_thread_id(&result, &expected)
                .expect_err("missing or mismatched resume identity must fail closed");
            assert_eq!(error.code, "codex-thread-id-mismatch");
        }
    }

    #[test]
    fn canonical_boundary_drops_routing_ids_and_blocks_raw_vendor_frames() {
        assert!(
            canonicalize_event(ServerEvent::SessionStarted {
                session_id: SessionId("transient".into()),
                thread_id: Some(ThreadId("private-thread".into())),
                agent_kind: AgentKind::Codex,
            })
            .is_none()
        );
        let event = canonicalize_event(ServerEvent::AgentItem {
            session_id: SessionId("transient".into()),
            thread_id: ThreadId("private-thread".into()),
            agent_kind: AgentKind::Codex,
            item: AgentItem::Raw {
                raw_kind: "unknown".into(),
                raw_payload: r#"{"threadId":"private-thread"}"#.into(),
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
                code: "codex-malformed-json".into(),
                message: "malformed frame with threadId=private-thread".into(),
                diagnostic_ref: Some("private-thread".into()),
            },
        })
        .expect("private error becomes canonical error");
        match error {
            CanonicalAgentEvent::Error(error) => {
                assert_eq!(error.code, "codex-malformed-json");
                assert!(!error.message.contains("private-thread"));
                assert!(error.diagnostic_ref.is_none());
            }
            other => panic!("expected canonical error, got {other:?}"),
        }
    }
}
