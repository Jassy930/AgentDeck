//! Claude Code typed blocked-gate driver。
//!
//! `attach` 只返回 cold future；private state readback、prompt JSONL、authoritative
//! `system.init` 与 typed event pump 都在 durable release 后首次 poll 才发生。

use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionRequest, ActionRequestVendor,
    ClaudeCodePermissionMode, ProtocolError, SessionCapabilities, ThreadId, TurnSummary,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use super::capabilities::build_canonical_claude_code_capabilities;
use super::runtime_translate::{
    ClaudeCodeApprovalRoute, ClaudeCodeRuntimeOutput, ClaudeCodeRuntimeTranslator,
};
use super::state::ClaudeCodeStateRepository;
use crate::agent::{
    AdapterApprovalSink, AdapterCompletionFuture, AdapterEventSink, ExecSpec, PreparedAgentTurn,
};
use crate::exec_gate::GatedChildIo;
use crate::runtime::approval::{
    ApprovalAttemptKey, ApprovalDeliveryOutcome, ApprovalPolicySnapshot, BoundApprovalDelivery,
};
use crate::runtime::store::RuntimeId;

const INIT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CC_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_INIT_BUFFERED_FRAMES: usize = 64;
const MAX_INIT_BUFFERED_BYTES: usize = 8 * 1024 * 1024;

pub(super) type SharedClaudeCodeStdin = Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>;

pub(super) struct ClaudeCodePreparedTurn {
    pub(super) exec_spec: ExecSpec,
    pub(super) repository: ClaudeCodeStateRepository,
    pub(super) adapter_state_key: RuntimeId,
    pub(super) expected_native_session: ThreadId,
    pub(super) prompt: String,
}

impl PreparedAgentTurn for ClaudeCodePreparedTurn {
    fn exec_spec(&self) -> &ExecSpec {
        &self.exec_spec
    }

    fn attach(
        self: Box<Self>,
        io: GatedChildIo,
        events: AdapterEventSink,
        approvals: AdapterApprovalSink,
    ) -> Result<AdapterCompletionFuture, ProtocolError> {
        Ok(Box::pin(run_claude_code_turn(*self, io, events, approvals)))
    }
}

async fn run_claude_code_turn(
    prepared: ClaudeCodePreparedTurn,
    io: GatedChildIo,
    events: AdapterEventSink,
    approvals: AdapterApprovalSink,
) -> Result<TurnSummary, ProtocolError> {
    let observed = prepared
        .repository
        .resolve(prepared.adapter_state_key)
        .await
        .map_err(|_| fixed_error("cc-state-readback-failed"))?;
    if observed.as_ref() != Some(&prepared.expected_native_session) {
        return Err(fixed_error("cc-state-readback-mismatch"));
    }

    let GatedChildIo {
        stdin,
        stdout,
        mut stderr,
    } = io;
    let _stderr_drain = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        let _ = tokio::io::copy(&mut stderr, &mut sink).await;
    });
    let stdin: SharedClaudeCodeStdin = Arc::new(Mutex::new(Box::new(stdin)));
    write_prompt(&stdin, &prepared.prompt).await?;

    let mut reader = BufReader::new(stdout);
    let mut buffered = Vec::new();
    let mut buffered_bytes = 0_usize;
    tokio::time::timeout(INIT_TIMEOUT, async {
        loop {
            let frame = read_json_frame(&mut reader)
                .await?
                .ok_or_else(|| fixed_error("cc-init-eof"))?;
            validate_session_identity(&frame, &prepared.expected_native_session)?;
            if frame.get("type").and_then(Value::as_str) == Some("system")
                && frame.get("subtype").and_then(Value::as_str) == Some("init")
            {
                return Ok::<(), ProtocolError>(());
            }
            if buffered.len() >= MAX_INIT_BUFFERED_FRAMES {
                return Err(fixed_error("cc-init-buffer-full"));
            }
            let retained = serde_json::to_vec(&frame)
                .map_err(|_| fixed_error("cc-encode-failed"))?
                .len();
            buffered_bytes = buffered_bytes
                .checked_add(retained)
                .ok_or_else(|| fixed_error("cc-init-buffer-full"))?;
            if buffered_bytes > MAX_INIT_BUFFERED_BYTES {
                return Err(fixed_error("cc-init-buffer-full"));
            }
            buffered.push(frame);
        }
    })
    .await
    .map_err(|_| fixed_error("cc-init-timeout"))??;

    let mut translator = ClaudeCodeRuntimeTranslator::new();
    for frame in buffered {
        if let Some(summary) =
            handle_frame(frame, &stdin, &events, &approvals, &mut translator).await?
        {
            return Ok(summary);
        }
    }
    loop {
        let frame = read_json_frame(&mut reader)
            .await?
            .ok_or_else(|| fixed_error("cc-unexpected-eof"))?;
        validate_session_identity(&frame, &prepared.expected_native_session)?;
        if let Some(summary) =
            handle_frame(frame, &stdin, &events, &approvals, &mut translator).await?
        {
            return Ok(summary);
        }
    }
}

async fn handle_frame(
    frame: Value,
    stdin: &SharedClaudeCodeStdin,
    events: &AdapterEventSink,
    approvals: &AdapterApprovalSink,
    translator: &mut ClaudeCodeRuntimeTranslator,
) -> Result<Option<TurnSummary>, ProtocolError> {
    for output in translator.translate_value(&frame)? {
        match output {
            ClaudeCodeRuntimeOutput::Event(event) => events.send(event).await?,
            ClaudeCodeRuntimeOutput::Approval { request, route } => {
                let delivery = Arc::new(ClaudeCodeBoundApprovalDelivery::new(
                    request.clone(),
                    route,
                    stdin.clone(),
                )?);
                approvals.register(request, delivery).await?;
            }
            ClaudeCodeRuntimeOutput::TurnComplete(summary) => return Ok(Some(summary)),
        }
    }
    Ok(None)
}

async fn write_prompt(stdin: &SharedClaudeCodeStdin, prompt: &str) -> Result<(), ProtocolError> {
    let mut payload = serde_json::to_vec(&json!({
        "type": "user",
        "message": {"role": "user", "content": prompt}
    }))
    .map_err(|_| fixed_error("cc-encode-failed"))?;
    if payload.len() >= MAX_CC_FRAME_BYTES {
        return Err(fixed_error("cc-frame-too-large"));
    }
    payload.push(b'\n');
    let mut stdin = stdin.lock().await;
    stdin
        .write_all(&payload)
        .await
        .map_err(|_| fixed_error("cc-stdin-write-failed"))?;
    stdin
        .flush()
        .await
        .map_err(|_| fixed_error("cc-stdin-write-failed"))
}

pub(super) struct ClaudeCodeBoundApprovalDelivery {
    request_id: String,
    route: ClaudeCodeApprovalRoute,
    policy: ApprovalPolicySnapshot,
    stdin: SharedClaudeCodeStdin,
    state: Mutex<ApprovalDeliveryState>,
}

enum ApprovalDeliveryState {
    Ready {
        approval_id: Option<RuntimeId>,
    },
    Applied {
        approval_id: RuntimeId,
        decision: ActionDecisionKind,
    },
    Unknown,
}

impl ClaudeCodeBoundApprovalDelivery {
    pub(super) fn new(
        request: ActionRequest,
        route: ClaudeCodeApprovalRoute,
        stdin: SharedClaudeCodeStdin,
    ) -> Result<Self, ProtocolError> {
        let request_tool_name = match &request.vendor {
            ActionRequestVendor::ClaudeCode {
                permission_mode_at_decision: ClaudeCodePermissionMode::Default,
                tool_name,
            } => tool_name,
            _ => return Err(fixed_error("cc-approval-route-invalid")),
        };
        if request.request_id != route.request_id || request_tool_name != &route.tool_name {
            return Err(fixed_error("cc-approval-route-invalid"));
        }
        let capabilities: SessionCapabilities =
            build_canonical_claude_code_capabilities("gated".to_owned());
        let policy = ApprovalPolicySnapshot::from_bound_capabilities(
            &request,
            &capabilities,
            true,
            true,
            None,
        )
        .map_err(|_| fixed_error("cc-approval-policy-invalid"))?;
        Ok(Self {
            request_id: request.request_id,
            route,
            policy,
            stdin,
            state: Mutex::new(ApprovalDeliveryState::Ready { approval_id: None }),
        })
    }
}

#[async_trait::async_trait]
impl BoundApprovalDelivery for ClaudeCodeBoundApprovalDelivery {
    fn policy(&self) -> &ApprovalPolicySnapshot {
        &self.policy
    }

    async fn deliver(
        &self,
        key: ApprovalAttemptKey,
        decision: &ActionDecision,
    ) -> ApprovalDeliveryOutcome {
        if decision.request_id != self.request_id || decision.persist {
            return ApprovalDeliveryOutcome::PermanentlyRejected;
        }
        let mut state = self.state.lock().await;
        match &*state {
            ApprovalDeliveryState::Unknown => return ApprovalDeliveryOutcome::OutcomeUnknown,
            ApprovalDeliveryState::Applied {
                approval_id,
                decision: applied,
            } => {
                return if *approval_id == key.approval_id && *applied == decision.decision {
                    ApprovalDeliveryOutcome::AppliedAck
                } else {
                    ApprovalDeliveryOutcome::PermanentlyRejected
                };
            }
            ApprovalDeliveryState::Ready {
                approval_id: Some(bound),
            } if *bound != key.approval_id => {
                return ApprovalDeliveryOutcome::PermanentlyRejected;
            }
            ApprovalDeliveryState::Ready { .. } => {}
        }
        let frame = control_response_frame(&self.route, decision.decision);
        let mut payload = match serde_json::to_vec(&frame) {
            Ok(payload) if payload.len() < MAX_CC_FRAME_BYTES => payload,
            Ok(_) | Err(_) => return ApprovalDeliveryOutcome::PermanentlyRejected,
        };
        if let ApprovalDeliveryState::Ready { approval_id } = &mut *state {
            *approval_id = Some(key.approval_id);
        }
        payload.push(b'\n');
        let mut stdin = self.stdin.lock().await;
        if stdin.write_all(&payload).await.is_err() || stdin.flush().await.is_err() {
            *state = ApprovalDeliveryState::Unknown;
            return ApprovalDeliveryOutcome::OutcomeUnknown;
        }
        *state = ApprovalDeliveryState::Applied {
            approval_id: key.approval_id,
            decision: decision.decision,
        };
        ApprovalDeliveryOutcome::AppliedAck
    }
}

fn control_response_frame(route: &ClaudeCodeApprovalRoute, decision: ActionDecisionKind) -> Value {
    let response = match decision {
        ActionDecisionKind::Approve => json!({"behavior": "allow"}),
        ActionDecisionKind::Deny => json!({
            "behavior": "deny",
            "message": "Denied by AgentDeck",
            "interrupt": false,
            "toolUseID": route.tool_use_id,
        }),
    };
    json!({
        "type": "control_response",
        "response": {
            "subtype": "success",
            "request_id": route.request_id,
            "response": response,
        }
    })
}

async fn read_json_frame(
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> Result<Option<Value>, ProtocolError> {
    let mut line = Vec::with_capacity(4096);
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| fixed_error("cc-stdout-read-failed"))?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(fixed_error("cc-truncated-frame"))
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > MAX_CC_FRAME_BYTES {
            return Err(fixed_error("cc-frame-too-large"));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            line.pop();
            return serde_json::from_slice(&line)
                .map(Some)
                .map_err(|_| fixed_error("cc-malformed-json"));
        }
    }
}

fn validate_session_identity(frame: &Value, expected: &ThreadId) -> Result<(), ProtocolError> {
    let observed = frame
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| fixed_error("cc-session-identity-missing"))?;
    if observed == expected.0 {
        Ok(())
    } else {
        Err(fixed_error("cc-session-identity-mismatch"))
    }
}

fn fixed_error(code: &str) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: "Claude Code typed execution failed".to_owned(),
        diagnostic_ref: None,
    }
}
