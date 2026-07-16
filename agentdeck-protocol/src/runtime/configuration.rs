//! Runtime v2 conversation configuration 与 agent discovery contract。

use std::collections::BTreeSet;

use crate::capabilities::{SessionCapabilities, VendorCapabilities};
use crate::runtime::failure::RuntimeFailure;
use crate::runtime::identity::{ConversationId, IdempotencyKey};
use crate::runtime::schema::RequiredNullable;
use crate::trunk::AgentKind;
use crate::vendor::claude_code::ClaudeCodePermissionMode;
use crate::vendor::codex::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MAX_CONFIGURATION_TEXT_BYTES: usize = 1024;
pub const MAX_AGENT_DESCRIPTIONS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigurationError {
    #[error("configuration text must contain 1 to {MAX_CONFIGURATION_TEXT_BYTES} UTF-8 bytes")]
    InvalidText,
    #[error("configuration revision/state is invalid")]
    InvalidRevision,
    #[error("agent kind, capabilities and configuration do not match")]
    AgentMismatch,
    #[error("agent descriptions are duplicated or exceed the fixed bound")]
    InvalidAgentDescriptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexConversationConfiguration {
    approval_policy: CodexApprovalPolicy,
    sandbox: CodexSandboxMode,
    reasoning_effort: CodexReasoningEffort,
}

impl CodexConversationConfiguration {
    #[must_use]
    pub const fn new(
        approval_policy: CodexApprovalPolicy,
        sandbox: CodexSandboxMode,
        reasoning_effort: CodexReasoningEffort,
    ) -> Self {
        Self {
            approval_policy,
            sandbox,
            reasoning_effort,
        }
    }

    #[must_use]
    pub const fn approval_policy(&self) -> CodexApprovalPolicy {
        self.approval_policy
    }

    #[must_use]
    pub const fn sandbox(&self) -> CodexSandboxMode {
        self.sandbox
    }

    #[must_use]
    pub const fn reasoning_effort(&self) -> CodexReasoningEffort {
        self.reasoning_effort
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudeCodeConversationConfiguration {
    permission_mode: ClaudeCodePermissionMode,
    model: Option<String>,
    effort: Option<String>,
    output_style: Option<String>,
}

impl ClaudeCodeConversationConfiguration {
    pub fn new(
        permission_mode: ClaudeCodePermissionMode,
        model: Option<String>,
        effort: Option<String>,
        output_style: Option<String>,
    ) -> Result<Self, ConfigurationError> {
        for value in [&model, &effort, &output_style].into_iter().flatten() {
            validate_text(value)?;
        }
        Ok(Self {
            permission_mode,
            model,
            effort,
            output_style,
        })
    }

    #[must_use]
    pub const fn permission_mode(&self) -> ClaudeCodePermissionMode {
        self.permission_mode
    }

    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    #[must_use]
    pub fn effort(&self) -> Option<&str> {
        self.effort.as_deref()
    }

    #[must_use]
    pub fn output_style(&self) -> Option<&str> {
        self.output_style.as_deref()
    }
}

impl<'de> Deserialize<'de> for ClaudeCodeConversationConfiguration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            permission_mode: ClaudeCodePermissionMode,
            model: Option<String>,
            effort: Option<String>,
            output_style: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.permission_mode,
            wire.model,
            wire.effort,
            wire.output_style,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn validate_text(value: &str) -> Result<(), ConfigurationError> {
    if value.is_empty()
        || value.len() > MAX_CONFIGURATION_TEXT_BYTES
        || value.as_bytes().contains(&0)
    {
        return Err(ConfigurationError::InvalidText);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "agentKind",
    content = "configuration",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum VendorConfigurationSnapshot {
    #[serde(rename = "codex")]
    Codex(CodexConversationConfiguration),
    #[serde(rename = "claude_code")]
    ClaudeCode(ClaudeCodeConversationConfiguration),
}

impl VendorConfigurationSnapshot {
    #[must_use]
    pub const fn agent_kind(&self) -> AgentKind {
        match self {
            Self::Codex(_) => AgentKind::Codex,
            Self::ClaudeCode(_) => AgentKind::ClaudeCode,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationConfiguration {
    vendor_control: VendorConfigurationSnapshot,
}

impl ConversationConfiguration {
    #[must_use]
    pub const fn new(vendor_control: VendorConfigurationSnapshot) -> Self {
        Self { vendor_control }
    }

    #[must_use]
    pub const fn vendor_control(&self) -> &VendorConfigurationSnapshot {
        &self.vendor_control
    }

    #[must_use]
    pub const fn agent_kind(&self) -> AgentKind {
        self.vendor_control.agent_kind()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationConfigurationState {
    configuration_revision: u64,
    #[schemars(with = "RequiredNullable<ConversationConfiguration>")]
    configuration: Option<ConversationConfiguration>,
}

impl ConversationConfigurationState {
    pub fn new(
        configuration_revision: u64,
        configuration: Option<ConversationConfiguration>,
    ) -> Result<Self, ConfigurationError> {
        if (configuration_revision == 0) != configuration.is_none() {
            return Err(ConfigurationError::InvalidRevision);
        }
        Ok(Self {
            configuration_revision,
            configuration,
        })
    }

    #[must_use]
    pub const fn configuration_revision(&self) -> u64 {
        self.configuration_revision
    }

    #[must_use]
    pub const fn configuration(&self) -> Option<&ConversationConfiguration> {
        self.configuration.as_ref()
    }
}

impl<'de> Deserialize<'de> for ConversationConfigurationState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            configuration_revision: u64,
            #[serde(deserialize_with = "deserialize_required_optional_configuration")]
            configuration: Option<ConversationConfiguration>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.configuration_revision, wire.configuration).map_err(serde::de::Error::custom)
    }
}

fn deserialize_required_optional_configuration<'de, D>(
    deserializer: D,
) -> Result<Option<ConversationConfiguration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<ConversationConfiguration>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigureConversationRequest {
    pub conversation_id: ConversationId,
    pub idempotency_key: IdempotencyKey,
    pub expected_configuration_revision: u64,
    pub configuration: ConversationConfiguration,
}

impl ConfigureConversationRequest {
    #[must_use]
    pub fn new(
        conversation_id: ConversationId,
        idempotency_key: IdempotencyKey,
        expected_configuration_revision: u64,
        configuration: ConversationConfiguration,
    ) -> Self {
        Self {
            conversation_id,
            idempotency_key,
            expected_configuration_revision,
            configuration,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum ConfigurationReceipt {
    Applied {
        #[serde(rename = "conversationId")]
        #[schemars(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(
            rename = "configurationRevision",
            serialize_with = "serialize_nonzero_revision"
        )]
        #[schemars(rename = "configurationRevision", range(min = 1))]
        configuration_revision: u64,
    },
    Replayed {
        #[serde(rename = "conversationId")]
        #[schemars(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(
            rename = "configurationRevision",
            serialize_with = "serialize_nonzero_revision"
        )]
        #[schemars(rename = "configurationRevision", range(min = 1))]
        configuration_revision: u64,
    },
    Conflict {
        #[serde(rename = "conversationId")]
        #[schemars(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "currentConfigurationRevision")]
        #[schemars(rename = "currentConfigurationRevision")]
        current_configuration_revision: u64,
    },
    Failed {
        failure: RuntimeFailure,
    },
}

impl<'de> Deserialize<'de> for ConfigurationReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(
            tag = "status",
            rename_all = "camelCase",
            rename_all_fields = "camelCase",
            deny_unknown_fields
        )]
        enum Wire {
            Applied {
                conversation_id: ConversationId,
                configuration_revision: u64,
            },
            Replayed {
                conversation_id: ConversationId,
                configuration_revision: u64,
            },
            Conflict {
                conversation_id: ConversationId,
                current_configuration_revision: u64,
            },
            Failed {
                failure: RuntimeFailure,
            },
        }
        let receipt = match Wire::deserialize(deserializer)? {
            Wire::Applied {
                conversation_id,
                configuration_revision,
            } if configuration_revision > 0 => Self::Applied {
                conversation_id,
                configuration_revision,
            },
            Wire::Replayed {
                conversation_id,
                configuration_revision,
            } if configuration_revision > 0 => Self::Replayed {
                conversation_id,
                configuration_revision,
            },
            Wire::Conflict {
                conversation_id,
                current_configuration_revision,
            } => Self::Conflict {
                conversation_id,
                current_configuration_revision,
            },
            Wire::Failed { failure } => Self::Failed { failure },
            _ => {
                return Err(serde::de::Error::custom(
                    ConfigurationError::InvalidRevision,
                ));
            }
        };
        Ok(receipt)
    }
}

fn serialize_nonzero_revision<S>(revision: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if *revision == 0 {
        return Err(serde::ser::Error::custom(
            ConfigurationError::InvalidRevision,
        ));
    }
    revision.serialize(serializer)
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDescription {
    agent_kind: AgentKind,
    capabilities: SessionCapabilities,
    default_configuration: ConversationConfiguration,
}

impl AgentDescription {
    pub fn new(
        agent_kind: AgentKind,
        capabilities: SessionCapabilities,
        default_configuration: ConversationConfiguration,
    ) -> Result<Self, ConfigurationError> {
        if capabilities.agent_kind != agent_kind
            || default_configuration.agent_kind() != agent_kind
            || !capabilities_vendor_matches(&capabilities)
        {
            return Err(ConfigurationError::AgentMismatch);
        }
        Ok(Self {
            agent_kind,
            capabilities,
            default_configuration,
        })
    }

    #[must_use]
    pub const fn agent_kind(&self) -> AgentKind {
        self.agent_kind
    }

    #[must_use]
    pub const fn capabilities(&self) -> &SessionCapabilities {
        &self.capabilities
    }

    #[must_use]
    pub const fn default_configuration(&self) -> &ConversationConfiguration {
        &self.default_configuration
    }
}

impl<'de> Deserialize<'de> for AgentDescription {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            agent_kind: AgentKind,
            capabilities: SessionCapabilities,
            default_configuration: ConversationConfiguration,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.agent_kind,
            wire.capabilities,
            wire.default_configuration,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn capabilities_vendor_matches(capabilities: &SessionCapabilities) -> bool {
    matches!(
        (capabilities.agent_kind, &capabilities.vendor),
        (AgentKind::Codex, VendorCapabilities::Codex(_))
            | (AgentKind::ClaudeCode, VendorCapabilities::ClaudeCode(_))
    )
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDescriptions {
    agents: Vec<AgentDescription>,
}

impl AgentDescriptions {
    pub fn new(agents: Vec<AgentDescription>) -> Result<Self, ConfigurationError> {
        let kinds = agents
            .iter()
            .map(AgentDescription::agent_kind)
            .collect::<BTreeSet<_>>();
        if agents.len() > MAX_AGENT_DESCRIPTIONS || kinds.len() != agents.len() {
            return Err(ConfigurationError::InvalidAgentDescriptions);
        }
        Ok(Self { agents })
    }

    #[must_use]
    pub fn agents(&self) -> &[AgentDescription] {
        &self.agents
    }
}

impl<'de> Deserialize<'de> for AgentDescriptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            agents: Vec<AgentDescription>,
        }
        Self::new(Wire::deserialize(deserializer)?.agents).map_err(serde::de::Error::custom)
    }
}
