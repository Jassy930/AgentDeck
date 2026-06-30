//! Codex-specific vendor types. Populated in tasks T1.5, T1.7.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum CodexSandboxMode {
    ReadOnly,
    WorkspaceWrite,
    FullAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum CodexReasoningEffort {
    Minimal,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum CodexApprovalPolicy {
    OnRequest,
    Never,
    Always,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexCapabilities {
    pub sandbox_modes: Vec<CodexSandboxMode>,
    pub persistence_supported: bool,
    pub reasoning_effort_levels: Vec<CodexReasoningEffort>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpOverride {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexSessionOptions {
    pub approval_policy: CodexApprovalPolicy,
    pub sandbox: CodexSandboxMode,
    pub persist_approval: bool,
    pub reasoning_effort: CodexReasoningEffort,
    #[serde(default)]
    pub mcp_overrides: Vec<McpOverride>,
}

// ── T1.7: CodexVendorControl / CodexVendorPanelEvent ────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum CodexVendorControl {
    UpdateSandbox(CodexSandboxMode),
    UpdateApprovalPolicy(CodexApprovalPolicy),
    UpdateReasoningEffort(CodexReasoningEffort),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum CodexVendorPanelEvent {
    /// Vendor-specific events that don't fit the neutral trunk. v0.2 has
    /// no Codex panel events, but the enum exists so adapters can extend
    /// without breaking schema.
    Placeholder,
}
