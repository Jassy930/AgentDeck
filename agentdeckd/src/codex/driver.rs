//! Codex typed blocked-gate driver。
//!
//! `attach` 只组装 cold future；initialize、state bind、prompt write、translator pump
//! 都在 durable release 后由 RuntimeExecutionRelease 首次 poll completion 时发生。

use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionRequest, AgentKind, CodexApprovalPolicy,
    CodexReasoningEffort, CodexSandboxMode, ProtocolError, SessionCapabilities, ThreadId,
    TurnSummary,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use super::adapter::{
    CANONICAL_CODEX_CLI_VERSION, approval_policy_str, approval_response_body, reasoning_effort_str,
    sandbox_mode_str,
};
use super::capabilities::build_codex_capabilities;
use super::runtime_translate::{CodexApprovalRoute, CodexRuntimeOutput, CodexRuntimeTranslator};
use super::state::CodexStateRepository;
use crate::agent::{
    AdapterApprovalSink, AdapterCompletionFuture, AdapterEventSink, ExecSpec, PreparedAgentTurn,
};
use crate::exec_gate::GatedChildIo;
use crate::runtime::approval::{
    ApprovalAttemptKey, ApprovalDeliveryOutcome, ApprovalPolicySnapshot, BoundApprovalDelivery,
};
use crate::runtime::store::RuntimeId;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CODEX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_HANDSHAKE_BUFFERED_FRAMES: usize = 64;
const MAX_HANDSHAKE_BUFFERED_BYTES: usize = 8 * 1024 * 1024;
const CODEX_OPT_OUT_NOTIFICATIONS: &[&str] = &[
    "account/login/completed",
    "account/rateLimits/updated",
    "account/updated",
    "app/list/updated",
    "command/exec/outputDelta",
    "externalAgentConfig/import/completed",
    "externalAgentConfig/import/progress",
    "fs/changed",
    "fuzzyFileSearch/sessionCompleted",
    "fuzzyFileSearch/sessionUpdated",
    "mcpServer/oauthLogin/completed",
    "mcpServer/startupStatus/updated",
    "process/exited",
    "process/outputDelta",
    "remoteControl/status/changed",
    "skills/changed",
    "thread/realtime/closed",
    "thread/realtime/error",
    "thread/realtime/itemAdded",
    "thread/realtime/outputAudio/delta",
    "thread/realtime/sdp",
    "thread/realtime/started",
    "thread/realtime/transcript/delta",
    "thread/realtime/transcript/done",
    "windows/worldWritableWarning",
    "windowsSandbox/setupCompleted",
];

pub(super) type SharedCodexStdin = Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>;

pub(super) struct CodexPreparedTurn {
    pub(super) exec_spec: ExecSpec,
    pub(super) repository: CodexStateRepository,
    pub(super) adapter_state_key: RuntimeId,
    pub(super) resume_thread_id: Option<ThreadId>,
    pub(super) cwd: std::path::PathBuf,
    pub(super) prompt: String,
    pub(super) approval_policy: CodexApprovalPolicy,
    pub(super) sandbox: CodexSandboxMode,
    pub(super) reasoning_effort: CodexReasoningEffort,
}

impl PreparedAgentTurn for CodexPreparedTurn {
    fn exec_spec(&self) -> &ExecSpec {
        &self.exec_spec
    }

    fn attach(
        self: Box<Self>,
        io: GatedChildIo,
        events: AdapterEventSink,
        approvals: AdapterApprovalSink,
    ) -> Result<AdapterCompletionFuture, ProtocolError> {
        Ok(Box::pin(run_codex_turn(*self, io, events, approvals)))
    }
}

async fn run_codex_turn(
    prepared: CodexPreparedTurn,
    io: GatedChildIo,
    events: AdapterEventSink,
    approvals: AdapterApprovalSink,
) -> Result<TurnSummary, ProtocolError> {
    let GatedChildIo {
        stdin,
        stdout,
        mut stderr,
    } = io;
    let _stderr_drain = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        let _ = tokio::io::copy(&mut stderr, &mut sink).await;
    });
    let stdin: SharedCodexStdin = Arc::new(Mutex::new(Box::new(stdin)));
    let mut reader = BufReader::new(stdout);
    let mut buffered = Vec::new();
    let mut buffered_bytes = 0_usize;
    let initialize = request_response(
        &stdin,
        &mut reader,
        1,
        "initialize",
        json!({
            "clientInfo": {"name": "agentdeck", "version": "0.2.0"},
            "capabilities": {
                "experimentalApi": false,
                "requestAttestation": false,
                "optOutNotificationMethods": CODEX_OPT_OUT_NOTIFICATIONS
            }
        }),
        &mut buffered,
        &mut buffered_bytes,
    )
    .await?;
    validate_initialize_version(&initialize)?;
    let thread_id = match prepared.resume_thread_id.clone() {
        Some(expected) => {
            let result = request_response(
                &stdin,
                &mut reader,
                2,
                "thread/resume",
                json!({
                    "threadId": expected.0,
                    "cwd": prepared.cwd,
                    "sandbox": sandbox_mode_str(prepared.sandbox),
                    "approvalPolicy": approval_policy_str(prepared.approval_policy)
                }),
                &mut buffered,
                &mut buffered_bytes,
            )
            .await?;
            let observed = result
                .get("thread")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .ok_or_else(|| fixed_error("codex-resume-identity-missing"))?;
            if observed != expected.0 {
                return Err(fixed_error("codex-resume-identity-mismatch"));
            }
            let readback = prepared
                .repository
                .resolve(prepared.adapter_state_key)
                .await
                .map_err(|_| fixed_error("codex-state-readback-failed"))?;
            if readback.as_ref() != Some(&expected) {
                return Err(fixed_error("codex-state-readback-mismatch"));
            }
            expected
        }
        None => {
            let result = request_response(
                &stdin,
                &mut reader,
                2,
                "thread/start",
                json!({
                    "cwd": prepared.cwd,
                    "sandbox": sandbox_mode_str(prepared.sandbox),
                    "approvalPolicy": approval_policy_str(prepared.approval_policy)
                }),
                &mut buffered,
                &mut buffered_bytes,
            )
            .await?;
            let value = result
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| fixed_error("codex-start-identity-missing"))?;
            let thread_id = ThreadId(value.to_owned());
            bind_and_verify_state(&prepared.repository, prepared.adapter_state_key, &thread_id)
                .await?;
            thread_id
        }
    };
    let turn_result = request_response(
        &stdin,
        &mut reader,
        3,
        "turn/start",
        json!({
            "threadId": thread_id.0,
            "input": [{"type": "text", "text": prepared.prompt}],
            "effort": reasoning_effort_str(prepared.reasoning_effort)
        }),
        &mut buffered,
        &mut buffered_bytes,
    )
    .await?;
    let turn_id = turn_result
        .get("turn")
        .and_then(|turn| turn.get("id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| fixed_error("codex-turn-identity-missing"))?
        .to_owned();
    let mut translator =
        CodexRuntimeTranslator::with_configuration(prepared.approval_policy, prepared.sandbox);
    for frame in buffered {
        handle_frame(
            frame,
            &thread_id,
            &turn_id,
            &stdin,
            &events,
            &approvals,
            &mut translator,
        )
        .await?;
    }
    loop {
        let frame = read_json_frame(&mut reader)
            .await?
            .ok_or_else(|| fixed_error("codex-unexpected-eof"))?;
        if let Some(summary) = handle_frame(
            frame,
            &thread_id,
            &turn_id,
            &stdin,
            &events,
            &approvals,
            &mut translator,
        )
        .await?
        {
            return Ok(summary);
        }
    }
}

async fn handle_frame(
    frame: Value,
    thread_id: &ThreadId,
    turn_id: &str,
    stdin: &SharedCodexStdin,
    events: &AdapterEventSink,
    approvals: &AdapterApprovalSink,
    translator: &mut CodexRuntimeTranslator,
) -> Result<Option<TurnSummary>, ProtocolError> {
    validate_frame_identity(&frame, thread_id, turn_id)?;
    for output in translator.translate_value(&frame)? {
        match output {
            CodexRuntimeOutput::Event(event) => events.send(event).await?,
            CodexRuntimeOutput::Diagnostic { code, detail } => {
                crate::diag::log_event(
                    crate::diag::DiagnosticEvent::new("codex_notification")
                        .level("warn")
                        .code(code)
                        .agent_kind(AgentKind::Codex)
                        .detail(detail),
                );
            }
            CodexRuntimeOutput::Approval { request, route } => {
                let delivery = Arc::new(CodexBoundApprovalDelivery::new(
                    request.clone(),
                    route,
                    stdin.clone(),
                )?);
                approvals.register(request, delivery).await?;
            }
            CodexRuntimeOutput::TurnComplete(summary) => return Ok(Some(summary)),
        }
    }
    Ok(None)
}

pub(super) fn validate_initialize_version(result: &Value) -> Result<(), ProtocolError> {
    // 威胁场景：schema 生成于旧 CLI、PATH 却解析到新版 binary 时，新增的正常
    // method/item 会在执行中途 fail-close；必须在 thread/start 前拒绝版本漂移。
    let user_agent = result
        .get("userAgent")
        .and_then(Value::as_str)
        .ok_or_else(|| fixed_error("codex-version-missing"))?;
    let observed = user_agent
        .split_once('/')
        .filter(|(originator, _)| !originator.is_empty())
        .and_then(|(_, value)| value.split_once(' ').map(|(version, _)| version))
        .ok_or_else(|| fixed_error("codex-version-invalid"))?;
    if observed != CANONICAL_CODEX_CLI_VERSION {
        return Err(fixed_error("codex-version-mismatch"));
    }
    Ok(())
}

async fn bind_and_verify_state(
    repository: &CodexStateRepository,
    adapter_state_key: RuntimeId,
    thread_id: &ThreadId,
) -> Result<(), ProtocolError> {
    // COMMIT outcome unknown 不能直接改写或放行：先 exact readback；只有仍为 None
    // 时才幂等重试同一 binding，任何不同 identity 都 fail-close。
    let first = repository.bind(adapter_state_key, thread_id.clone()).await;
    let mut observed = repository
        .resolve(adapter_state_key)
        .await
        .map_err(|_| fixed_error("codex-state-readback-failed"))?;
    if observed.as_ref() == Some(thread_id) {
        return Ok(());
    }
    if observed.is_some() {
        return Err(fixed_error("codex-state-readback-mismatch"));
    }
    if first.is_err() {
        repository
            .bind(adapter_state_key, thread_id.clone())
            .await
            .map_err(|_| fixed_error("codex-state-bind-failed"))?;
        observed = repository
            .resolve(adapter_state_key)
            .await
            .map_err(|_| fixed_error("codex-state-readback-failed"))?;
    }
    if observed.as_ref() == Some(thread_id) {
        Ok(())
    } else {
        Err(fixed_error("codex-state-readback-mismatch"))
    }
}

async fn request_response(
    stdin: &SharedCodexStdin,
    reader: &mut BufReader<tokio::process::ChildStdout>,
    id: u64,
    method: &str,
    params: Value,
    buffered: &mut Vec<Value>,
    buffered_bytes: &mut usize,
) -> Result<Value, ProtocolError> {
    write_json_frame(
        stdin,
        &json!({"id": id, "method": method, "params": params}),
    )
    .await?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            let frame = read_json_frame(reader)
                .await?
                .ok_or_else(|| fixed_error("codex-handshake-eof"))?;
            if frame.get("id").and_then(Value::as_u64) == Some(id) && frame.get("method").is_none()
            {
                let result = frame.get("result");
                let error = frame.get("error").filter(|value| !value.is_null());
                return match (result, error) {
                    (Some(result), None) => Ok(result.clone()),
                    (None, Some(_)) => Err(fixed_error("codex-handshake-error")),
                    (Some(_), Some(_)) | (None, None) => {
                        Err(fixed_error("codex-handshake-response-invalid"))
                    }
                };
            }
            if buffered.len() >= MAX_HANDSHAKE_BUFFERED_FRAMES {
                return Err(fixed_error("codex-handshake-buffer-full"));
            }
            let retained = serde_json::to_vec(&frame)
                .map_err(|_| fixed_error("codex-encode-failed"))?
                .len();
            *buffered_bytes = buffered_bytes
                .checked_add(retained)
                .ok_or_else(|| fixed_error("codex-handshake-buffer-full"))?;
            if *buffered_bytes > MAX_HANDSHAKE_BUFFERED_BYTES {
                return Err(fixed_error("codex-handshake-buffer-full"));
            }
            buffered.push(frame);
        }
    })
    .await
    .map_err(|_| fixed_error("codex-handshake-timeout"))?
}

async fn write_json_frame(stdin: &SharedCodexStdin, frame: &Value) -> Result<(), ProtocolError> {
    let mut payload = serde_json::to_vec(frame).map_err(|_| fixed_error("codex-encode-failed"))?;
    if payload.len() >= MAX_CODEX_FRAME_BYTES {
        return Err(fixed_error("codex-frame-too-large"));
    }
    payload.push(b'\n');
    let mut writer = stdin.lock().await;
    writer
        .write_all(&payload)
        .await
        .map_err(|_| fixed_error("codex-stdin-write-failed"))?;
    writer
        .flush()
        .await
        .map_err(|_| fixed_error("codex-stdin-write-failed"))
}

async fn read_json_frame(
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> Result<Option<Value>, ProtocolError> {
    let mut line = Vec::with_capacity(4096);
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| fixed_error("codex-stdout-read-failed"))?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(fixed_error("codex-truncated-frame"))
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > MAX_CODEX_FRAME_BYTES {
            return Err(fixed_error("codex-frame-too-large"));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            line.pop();
            return serde_json::from_slice(&line)
                .map(Some)
                .map_err(|_| fixed_error("codex-malformed-json"));
        }
    }
}

pub(super) struct CodexBoundApprovalDelivery {
    request_id: String,
    route: CodexApprovalRoute,
    policy: ApprovalPolicySnapshot,
    stdin: SharedCodexStdin,
    state: Mutex<DeliveryState>,
}

enum DeliveryState {
    Ready {
        approval_id: Option<RuntimeId>,
    },
    Applied {
        approval_id: RuntimeId,
        decision: ActionDecisionKind,
        persist: bool,
    },
    Unknown,
}

impl CodexBoundApprovalDelivery {
    pub(super) fn new(
        request: ActionRequest,
        route: CodexApprovalRoute,
        stdin: SharedCodexStdin,
    ) -> Result<Self, ProtocolError> {
        let capabilities: SessionCapabilities = build_codex_capabilities("gated".to_owned());
        let policy = ApprovalPolicySnapshot::from_bound_capabilities(
            &request,
            &capabilities,
            true,
            true,
            None,
        )
        .map_err(|_| fixed_error("codex-approval-policy-invalid"))?;
        Ok(Self {
            request_id: request.request_id,
            route,
            policy,
            stdin,
            state: Mutex::new(DeliveryState::Ready { approval_id: None }),
        })
    }
}

#[async_trait::async_trait]
impl BoundApprovalDelivery for CodexBoundApprovalDelivery {
    fn policy(&self) -> &ApprovalPolicySnapshot {
        &self.policy
    }

    async fn deliver(
        &self,
        key: ApprovalAttemptKey,
        decision: &ActionDecision,
    ) -> ApprovalDeliveryOutcome {
        if decision.request_id != self.request_id {
            return ApprovalDeliveryOutcome::PermanentlyRejected;
        }
        let mut state = self.state.lock().await;
        match &*state {
            DeliveryState::Unknown => return ApprovalDeliveryOutcome::OutcomeUnknown,
            DeliveryState::Applied {
                approval_id,
                decision: applied,
                persist,
            } => {
                return if *approval_id == key.approval_id
                    && *applied == decision.decision
                    && *persist == decision.persist
                {
                    ApprovalDeliveryOutcome::AppliedAck
                } else {
                    ApprovalDeliveryOutcome::PermanentlyRejected
                };
            }
            DeliveryState::Ready {
                approval_id: Some(bound),
            } if *bound != key.approval_id => {
                return ApprovalDeliveryOutcome::PermanentlyRejected;
            }
            DeliveryState::Ready { .. } => {}
        }
        let body = match approval_response_body(&self.route.method, &self.route.params, decision) {
            Ok(body) => body,
            Err(_) => return ApprovalDeliveryOutcome::PermanentlyRejected,
        };
        if let DeliveryState::Ready { approval_id } = &mut *state {
            *approval_id = Some(key.approval_id);
        }
        let mut payload = match serde_json::to_vec(&json!({
            "id": self.route.rpc_id,
            "result": body,
        })) {
            Ok(payload) => payload,
            Err(_) => return ApprovalDeliveryOutcome::PermanentlyRejected,
        };
        if payload.len() >= MAX_CODEX_FRAME_BYTES {
            return ApprovalDeliveryOutcome::PermanentlyRejected;
        }
        payload.push(b'\n');
        let mut stdin = self.stdin.lock().await;
        if stdin.write_all(&payload).await.is_err() || stdin.flush().await.is_err() {
            *state = DeliveryState::Unknown;
            return ApprovalDeliveryOutcome::OutcomeUnknown;
        }
        *state = DeliveryState::Applied {
            approval_id: key.approval_id,
            decision: decision.decision,
            persist: decision.persist,
        };
        ApprovalDeliveryOutcome::AppliedAck
    }
}

fn validate_frame_identity(
    frame: &Value,
    expected_thread: &ThreadId,
    expected_turn: &str,
) -> Result<(), ProtocolError> {
    let params = frame.get("params");
    let thread_ids = [
        params
            .and_then(|value| value.get("threadId"))
            .and_then(Value::as_str),
        params
            .and_then(|value| value.get("thread"))
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str),
    ];
    if thread_ids
        .into_iter()
        .flatten()
        .any(|observed| observed != expected_thread.0)
    {
        return Err(fixed_error("codex-session-identity-mismatch"));
    }
    let turn_ids = [
        params
            .and_then(|value| value.get("turnId"))
            .and_then(Value::as_str),
        params
            .and_then(|value| value.get("turn"))
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str),
    ];
    if turn_ids
        .into_iter()
        .flatten()
        .any(|observed| observed != expected_turn)
    {
        return Err(fixed_error("codex-turn-identity-mismatch"));
    }
    let method = frame.get("method").and_then(Value::as_str);
    if method.is_some_and(|method| method.starts_with("item/") || method.starts_with("turn/"))
        && turn_ids.into_iter().flatten().next().is_none()
    {
        return Err(fixed_error("codex-turn-identity-missing"));
    }
    Ok(())
}

fn fixed_error(code: &str) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: "Codex typed execution failed".to_owned(),
        diagnostic_ref: None,
    }
}
