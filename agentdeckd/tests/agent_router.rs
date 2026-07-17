use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, CodexConversationConfiguration, ConfigurationError,
    ConversationConfiguration, VendorConfigurationSnapshot,
};
use agentdeck_protocol::*;
use agentdeckd::agent::{Agent, AgentEventSender, AgentSessionHandle};
use agentdeckd::claude_code::ClaudeCodeAdapter;
use agentdeckd::codex::CodexAdapter;
use agentdeckd::runtime::router::AgentRouter;
use agentdeckd::runtime::store::{RuntimeId, RuntimeIdKind};
use std::sync::Arc;

struct StubAgent {
    kind: AgentKind,
    capability_kind: AgentKind,
    default_kind: AgentKind,
    fail_default: bool,
}

impl StubAgent {
    fn valid(kind: AgentKind) -> Self {
        Self {
            kind,
            capability_kind: kind,
            default_kind: kind,
            fail_default: false,
        }
    }
}

#[async_trait::async_trait]
impl Agent for StubAgent {
    fn kind(&self) -> AgentKind {
        self.kind
    }
    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            agent_kind: self.capability_kind,
            agent_version: "stub".into(),
            features: Default::default(),
            vendor: match self.capability_kind {
                AgentKind::Codex => VendorCapabilities::Codex(Default::default()),
                AgentKind::ClaudeCode => VendorCapabilities::ClaudeCode(Default::default()),
            },
        }
    }
    fn default_configuration(&self) -> Result<ConversationConfiguration, ConfigurationError> {
        if self.fail_default {
            return Err(ConfigurationError::InvalidText);
        }
        match self.default_kind {
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
    async fn start_session(
        &self,
        _: SessionStart,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unimplemented!()
    }
    async fn continue_thread(
        &self,
        _: ThreadId,
        _: std::path::PathBuf,
        _: String,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unimplemented!()
    }
    async fn submit_decision(&self, _: &SessionId, _: ActionDecision) -> Result<(), ProtocolError> {
        Ok(())
    }
    async fn submit_vendor_control(
        &self,
        _: &SessionId,
        _: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        Ok(())
    }
    async fn cancel(&self, _: &SessionId) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[test]
fn router_lists_registered_agents() {
    let mut r = AgentRouter::new();
    r.register(Arc::new(StubAgent::valid(AgentKind::Codex)));
    r.register(Arc::new(StubAgent::valid(AgentKind::ClaudeCode)));
    let mut listed = r.list_agents();
    listed.sort_by_key(|k| k.as_str());
    assert_eq!(listed.len(), 2);
}

#[test]
fn router_descriptions_are_stable_in_agent_kind_order() {
    let mut router = AgentRouter::new();
    router.register(Arc::new(StubAgent::valid(AgentKind::ClaudeCode)));
    router.register(Arc::new(StubAgent::valid(AgentKind::Codex)));

    let descriptions = router
        .agent_descriptions()
        .expect("matching adapters produce descriptions");
    assert_eq!(
        descriptions
            .agents()
            .iter()
            .map(|description| description.agent_kind())
            .collect::<Vec<_>>(),
        vec![AgentKind::Codex, AgentKind::ClaudeCode]
    );
}

#[test]
fn router_descriptions_fail_closed_on_adapter_error_or_kind_mismatch() {
    let mut error_router = AgentRouter::new();
    error_router.register(Arc::new(StubAgent {
        fail_default: true,
        ..StubAgent::valid(AgentKind::Codex)
    }));
    assert_eq!(
        error_router.agent_descriptions().unwrap_err(),
        ConfigurationError::InvalidText
    );

    let mut mismatch_router = AgentRouter::new();
    mismatch_router.register(Arc::new(StubAgent {
        default_kind: AgentKind::ClaudeCode,
        ..StubAgent::valid(AgentKind::Codex)
    }));
    assert_eq!(
        mismatch_router.agent_descriptions().unwrap_err(),
        ConfigurationError::AgentMismatch
    );
}

#[test]
fn production_adapters_publish_exact_frozen_defaults() {
    let codex = CodexAdapter::default()
        .default_configuration()
        .expect("Codex default is valid");
    match codex.vendor_control() {
        VendorConfigurationSnapshot::Codex(configuration) => {
            assert_eq!(
                configuration.approval_policy(),
                CodexApprovalPolicy::OnRequest
            );
            assert_eq!(configuration.sandbox(), CodexSandboxMode::WorkspaceWrite);
            assert_eq!(
                configuration.reasoning_effort(),
                CodexReasoningEffort::Medium
            );
        }
        VendorConfigurationSnapshot::ClaudeCode(_) => panic!("expected Codex default"),
    }

    let claude_code = ClaudeCodeAdapter::default()
        .default_configuration()
        .expect("Claude Code default is valid");
    match claude_code.vendor_control() {
        VendorConfigurationSnapshot::ClaudeCode(configuration) => {
            assert_eq!(
                configuration.permission_mode(),
                ClaudeCodePermissionMode::Default
            );
            assert_eq!(configuration.model(), None);
            assert_eq!(configuration.effort(), None);
            assert_eq!(configuration.output_style(), None);
        }
        VendorConfigurationSnapshot::Codex(_) => panic!("expected Claude Code default"),
    }
}

#[test]
fn router_returns_capabilities_for_known_kind() {
    let mut r = AgentRouter::new();
    r.register(Arc::new(StubAgent::valid(AgentKind::Codex)));
    let caps = r.capabilities(AgentKind::Codex).expect("codex registered");
    assert_eq!(caps.agent_kind, AgentKind::Codex);
}

#[test]
fn router_rejects_unregistered_kind() {
    let r = AgentRouter::new();
    assert!(r.capabilities(AgentKind::Codex).is_none());
}

#[tokio::test]
async fn release_unknown_session_is_idempotent_and_does_not_create_ownership() {
    let router = AgentRouter::new();
    let session_id = SessionId("missing-session".to_owned());
    assert!(!router.release_session(&session_id).await);
    assert_eq!(router.active_session_count().await, 0);
}

#[tokio::test]
async fn canonical_continue_routes_only_the_neutral_adapter_state_key() {
    let mut router = AgentRouter::new();
    router.register(Arc::new(StubAgent::valid(AgentKind::Codex)));
    let (events, _receiver) = tokio::sync::mpsc::channel(1);
    let key = RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x91; 16])
        .expect("neutral adapter state key");

    let result = router
        .continue_adapter_state(
            key,
            AgentKind::Codex,
            "/tmp".into(),
            "continue".to_owned(),
            events,
        )
        .await;
    let error = match result {
        Ok(_) => panic!("stub has no private repository"),
        Err(error) => error,
    };
    assert_eq!(error.code, "adapter-state-not-configured");
}
