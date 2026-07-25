//! P4 automatic gate 的 debug-only synthetic canonical adapters。
//!
//! 本模块只向 crate 外提供一个同时注册 Codex / Claude Code 的
//! [`AgentRouter`] 构造器。adapter、exec spec、execution identity 与 approval delivery
//! 全部保持内部可见，避免测试夹具成为绕过 production execution gate 的能力面。

#![cfg(debug_assertions)]
#![doc(hidden)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, CodexConversationConfiguration, ConfigurationError,
    ConversationConfiguration, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor, AgentItem,
    AgentItemMeta, AgentKind, CapabilityId, ClaudeCodePermissionMode, CodexApprovalPolicy,
    CodexReasoningEffort, CodexSandboxMode, ProtocolError, SessionCapabilities, SessionId,
    SessionStart, ThreadId, TurnSummary, VendorControlPayload,
};
use tokio::sync::{Mutex, watch};

use crate::agent::{
    AdapterApprovalSink, AdapterCompletionFuture, AdapterEvent, AdapterEventSink, AdapterItemKey,
    AdapterStateHandle, Agent, AgentEventSender, AgentSessionHandle, AgentTurnRequest, ExecSpec,
    PrepareAdapterTurnCapability, PreparedAgentTurn,
};
use crate::exec_gate::GatedChildIo;
use crate::runtime::AgentRouter;
use crate::runtime::approval::{
    ApprovalAttemptKey, ApprovalDeliveryOutcome, ApprovalPolicySnapshot, BoundApprovalDelivery,
    SharedApprovalDelivery,
};
use crate::runtime::store::RuntimeId;

const SYNTHETIC_VERSION: &str = "agentdeck-synthetic-e2e/v1";
const SYNTHETIC_CODEX_ITEM: &str = "synthetic Codex response";
const SYNTHETIC_CLAUDE_CODE_ITEM: &str = "synthetic Claude Code response";

/// 构造 P4 automatic E2E 专用 router。
///
/// 返回的两个 adapter 仍只能由 `RuntimeCore::new_production` 通过 typed
/// prepare 边界使用；本 API 不暴露 adapter 实例或任何 gate 内部能力。
#[must_use]
pub fn agent_router() -> AgentRouter {
    let mut router = AgentRouter::new();
    router.register(Arc::new(SyntheticAgent::new(AgentKind::Codex)));
    router.register(Arc::new(SyntheticAgent::new(AgentKind::ClaudeCode)));
    router
}

struct SyntheticAgent {
    kind: AgentKind,
    next_turn: AtomicU64,
}

impl SyntheticAgent {
    const fn new(kind: AgentKind) -> Self {
        Self {
            kind,
            next_turn: AtomicU64::new(1),
        }
    }

    fn next_sequence(&self) -> u64 {
        self.next_turn.fetch_add(1, Ordering::Relaxed)
    }
}

#[async_trait::async_trait]
impl Agent for SyntheticAgent {
    fn kind(&self) -> AgentKind {
        self.kind
    }

    fn capabilities(&self) -> SessionCapabilities {
        synthetic_capabilities(self.kind)
    }

    fn default_configuration(&self) -> Result<ConversationConfiguration, ConfigurationError> {
        synthetic_default_configuration(self.kind)
    }

    async fn prepare_adapter_turn(
        &self,
        _capability: &mut PrepareAdapterTurnCapability,
        request: AgentTurnRequest,
        state: AdapterStateHandle,
    ) -> Result<Box<dyn PreparedAgentTurn>, ProtocolError> {
        let sequence = self.next_sequence();
        let prompt = request.prompt().to_owned();
        let action_request =
            synthetic_action_request(self.kind, sequence, request.execution_configuration())?;
        let (decision_sender, decision_receiver) = watch::channel(None);
        let delivery = SyntheticApprovalDelivery::new(
            action_request.clone(),
            synthetic_capabilities(self.kind),
            decision_sender,
        )?;
        let cwd = request.cwd().to_path_buf();
        let exec_spec = ExecSpec::new(
            &request,
            state,
            "/bin/sh",
            [
                OsString::from("-c"),
                OsString::from("exec /bin/sleep 3600"),
                OsString::from("agentdeck-synthetic-e2e"),
            ],
            cwd,
        )
        .map_err(|error| synthetic_error("synthetic-exec-spec", &error.to_string()))?;
        Ok(Box::new(SyntheticPreparedTurn {
            exec_spec,
            user_item_key: format!("synthetic-{}-user-{sequence}", agent_label(self.kind)),
            assistant_item_key: format!(
                "synthetic-{}-assistant-{sequence}",
                agent_label(self.kind)
            ),
            prompt,
            assistant_text: match self.kind {
                AgentKind::Codex => SYNTHETIC_CODEX_ITEM,
                AgentKind::ClaudeCode => SYNTHETIC_CLAUDE_CODE_ITEM,
            },
            action_request,
            delivery: Arc::new(delivery),
            decision_receiver,
        }))
    }

    async fn start_session(
        &self,
        _start: SessionStart,
        _events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        Err(legacy_disabled())
    }

    async fn continue_thread(
        &self,
        _thread_id: ThreadId,
        _cwd: PathBuf,
        _prompt: String,
        _events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        Err(legacy_disabled())
    }

    async fn submit_decision(
        &self,
        _session_id: &SessionId,
        _decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        Err(legacy_disabled())
    }

    async fn submit_vendor_control(
        &self,
        _session_id: &SessionId,
        _payload: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        Err(legacy_disabled())
    }

    async fn cancel(&self, _session_id: &SessionId) -> Result<(), ProtocolError> {
        Err(legacy_disabled())
    }
}

struct SyntheticPreparedTurn {
    exec_spec: ExecSpec,
    user_item_key: String,
    assistant_item_key: String,
    prompt: String,
    assistant_text: &'static str,
    action_request: ActionRequest,
    delivery: Arc<SyntheticApprovalDelivery>,
    decision_receiver: watch::Receiver<Option<ActionDecisionKind>>,
}

impl PreparedAgentTurn for SyntheticPreparedTurn {
    fn exec_spec(&self) -> &ExecSpec {
        &self.exec_spec
    }

    fn attach(
        self: Box<Self>,
        child: GatedChildIo,
        events: AdapterEventSink,
        approvals: AdapterApprovalSink,
    ) -> Result<AdapterCompletionFuture, ProtocolError> {
        let Self {
            user_item_key,
            assistant_item_key,
            prompt,
            assistant_text,
            action_request,
            delivery,
            mut decision_receiver,
            ..
        } = *self;
        drop(child);
        Ok(Box::pin(async move {
            events
                .send(AdapterEvent::Item {
                    key: AdapterItemKey::new(user_item_key)?,
                    item: AgentItem::UserMessage {
                        text: prompt,
                        meta: AgentItemMeta::default(),
                    },
                })
                .await?;
            events
                .send(AdapterEvent::Item {
                    key: AdapterItemKey::new(assistant_item_key)?,
                    item: AgentItem::AssistantMessage {
                        text: assistant_text.to_owned(),
                        meta: AgentItemMeta::default(),
                    },
                })
                .await?;
            let bound_delivery: SharedApprovalDelivery = delivery;
            approvals.register(action_request, bound_delivery).await?;
            wait_for_decision(&mut decision_receiver).await?;
            Ok(TurnSummary {
                total_input_tokens: Some(1),
                total_output_tokens: Some(1),
                elapsed_ms: 1,
            })
        }))
    }
}

async fn wait_for_decision(
    receiver: &mut watch::Receiver<Option<ActionDecisionKind>>,
) -> Result<ActionDecisionKind, ProtocolError> {
    loop {
        if let Some(decision) = *receiver.borrow_and_update() {
            return Ok(decision);
        }
        receiver
            .changed()
            .await
            .map_err(|_| synthetic_error("synthetic-approval-closed", "decision route closed"))?;
    }
}

struct SyntheticApprovalDelivery {
    request: ActionRequest,
    policy: ApprovalPolicySnapshot,
    decision_sender: watch::Sender<Option<ActionDecisionKind>>,
    state: Mutex<SyntheticApprovalState>,
}

enum SyntheticApprovalState {
    Ready {
        approval_id: Option<RuntimeId>,
    },
    Applied {
        approval_id: RuntimeId,
        decision: ActionDecisionKind,
    },
}

impl SyntheticApprovalDelivery {
    fn new(
        request: ActionRequest,
        capabilities: SessionCapabilities,
        decision_sender: watch::Sender<Option<ActionDecisionKind>>,
    ) -> Result<Self, ProtocolError> {
        let policy = ApprovalPolicySnapshot::from_bound_capabilities(
            &request,
            &capabilities,
            true,
            true,
            None,
        )
        .map_err(|error| synthetic_error("synthetic-approval-policy", &error.to_string()))?;
        Ok(Self {
            request,
            policy,
            decision_sender,
            state: Mutex::new(SyntheticApprovalState::Ready { approval_id: None }),
        })
    }
}

#[async_trait::async_trait]
impl BoundApprovalDelivery for SyntheticApprovalDelivery {
    fn policy(&self) -> &ApprovalPolicySnapshot {
        &self.policy
    }

    async fn deliver(
        &self,
        key: ApprovalAttemptKey,
        decision: &ActionDecision,
    ) -> ApprovalDeliveryOutcome {
        if self
            .policy
            .validate_decision(&self.request, decision)
            .is_err()
            || decision.persist
        {
            return ApprovalDeliveryOutcome::PermanentlyRejected;
        }
        let mut state = self.state.lock().await;
        match *state {
            SyntheticApprovalState::Applied {
                approval_id,
                decision: applied,
            } => {
                return if approval_id == key.approval_id && applied == decision.decision {
                    ApprovalDeliveryOutcome::AppliedAck
                } else {
                    ApprovalDeliveryOutcome::PermanentlyRejected
                };
            }
            SyntheticApprovalState::Ready {
                approval_id: Some(bound),
            } if bound != key.approval_id => {
                return ApprovalDeliveryOutcome::PermanentlyRejected;
            }
            SyntheticApprovalState::Ready { .. } => {}
        }
        if let SyntheticApprovalState::Ready { approval_id } = &mut *state {
            *approval_id = Some(key.approval_id);
        }
        if self.decision_sender.send(Some(decision.decision)).is_err() {
            return ApprovalDeliveryOutcome::DefinitelyNotDelivered { retryable: false };
        }
        *state = SyntheticApprovalState::Applied {
            approval_id: key.approval_id,
            decision: decision.decision,
        };
        ApprovalDeliveryOutcome::AppliedAck
    }
}

fn synthetic_capabilities(kind: AgentKind) -> SessionCapabilities {
    match kind {
        AgentKind::Codex => {
            crate::codex::capabilities::build_codex_capabilities(SYNTHETIC_VERSION.to_owned())
        }
        AgentKind::ClaudeCode => {
            let mut capabilities = crate::claude_code::capabilities::build_claude_code_capabilities(
                SYNTHETIC_VERSION.to_owned(),
            );
            capabilities.features.remove(&CapabilityId::ClaudeCodeHooks);
            capabilities.features.insert(CapabilityId::Approval);
            capabilities
        }
    }
}

fn synthetic_default_configuration(
    kind: AgentKind,
) -> Result<ConversationConfiguration, ConfigurationError> {
    match kind {
        AgentKind::Codex => Ok(ConversationConfiguration::new(
            VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                CodexApprovalPolicy::OnRequest,
                CodexSandboxMode::WorkspaceWrite,
                CodexReasoningEffort::Medium,
            )),
        )),
        AgentKind::ClaudeCode => ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .map(VendorConfigurationSnapshot::ClaudeCode)
        .map(ConversationConfiguration::new),
    }
}

fn synthetic_action_request(
    kind: AgentKind,
    sequence: u64,
    configuration: &ConversationConfiguration,
) -> Result<ActionRequest, ProtocolError> {
    let vendor = match (kind, configuration.vendor_control()) {
        (AgentKind::Codex, VendorConfigurationSnapshot::Codex(configuration)) => {
            ActionRequestVendor::Codex {
                approval_policy_at_decision: configuration.approval_policy(),
                sandbox_at_decision: configuration.sandbox(),
                can_persist: false,
            }
        }
        (AgentKind::ClaudeCode, VendorConfigurationSnapshot::ClaudeCode(configuration)) => {
            ActionRequestVendor::ClaudeCode {
                permission_mode_at_decision: configuration.permission_mode(),
                tool_name: "Bash".to_owned(),
            }
        }
        _ => {
            return Err(synthetic_error(
                "synthetic-configuration-mismatch",
                "synthetic adapter kind does not match frozen configuration",
            ));
        }
    };
    Ok(ActionRequest {
        request_id: format!("synthetic-approval-{}-{sequence}", agent_label(kind)),
        kind: ActionKind::ExecuteCommand,
        summary: format!("synthetic {} approval", agent_label(kind)),
        vendor,
    })
}

const fn agent_label(kind: AgentKind) -> &'static str {
    match kind {
        AgentKind::Codex => "codex",
        AgentKind::ClaudeCode => "claude-code",
    }
}

fn legacy_disabled() -> ProtocolError {
    synthetic_error(
        "synthetic-legacy-disabled",
        "synthetic E2E adapters only support canonical production execution",
    )
}

fn synthetic_error(code: &str, message: &str) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: message.to_owned(),
        diagnostic_ref: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::store::RuntimeIdKind;

    #[test]
    fn router_exposes_only_the_two_typed_synthetic_agents() {
        let router = agent_router();
        assert_eq!(
            router.list_agents(),
            vec![AgentKind::Codex, AgentKind::ClaudeCode]
        );
        for kind in [AgentKind::Codex, AgentKind::ClaudeCode] {
            let capabilities = router.capabilities(kind).expect("synthetic capabilities");
            assert_eq!(capabilities.agent_kind, kind);
            assert!(capabilities.features.contains(&CapabilityId::Approval));
        }
        let descriptions = router
            .agent_descriptions()
            .expect("synthetic descriptions remain typed");
        assert_eq!(descriptions.agents().len(), 2);
    }

    #[tokio::test]
    async fn bound_delivery_signals_one_exact_non_persistent_decision() {
        let configuration = synthetic_default_configuration(AgentKind::ClaudeCode)
            .expect("synthetic configuration");
        let request = synthetic_action_request(AgentKind::ClaudeCode, 1, &configuration)
            .expect("synthetic request");
        let (sender, mut receiver) = watch::channel(None);
        let delivery = SyntheticApprovalDelivery::new(
            request.clone(),
            synthetic_capabilities(AgentKind::ClaudeCode),
            sender,
        )
        .expect("bound synthetic delivery");
        let key = ApprovalAttemptKey {
            approval_id: RuntimeId::from_bytes(RuntimeIdKind::Approval, [0x51; 16])
                .expect("approval id"),
            delivery_round: 1,
            attempt: 0,
        };
        let decision = ActionDecision {
            request_id: request.request_id,
            decision: ActionDecisionKind::Approve,
            persist: false,
        };
        assert_eq!(
            delivery.deliver(key, &decision).await,
            ApprovalDeliveryOutcome::AppliedAck
        );
        assert_eq!(
            wait_for_decision(&mut receiver)
                .await
                .expect("decision signal"),
            ActionDecisionKind::Approve
        );
        assert_eq!(
            delivery.deliver(key, &decision).await,
            ApprovalDeliveryOutcome::AppliedAck
        );

        let wrong_key = ApprovalAttemptKey {
            approval_id: RuntimeId::from_bytes(RuntimeIdKind::Approval, [0x52; 16])
                .expect("other approval id"),
            delivery_round: 1,
            attempt: 0,
        };
        assert_eq!(
            delivery.deliver(wrong_key, &decision).await,
            ApprovalDeliveryOutcome::PermanentlyRejected
        );
    }
}
