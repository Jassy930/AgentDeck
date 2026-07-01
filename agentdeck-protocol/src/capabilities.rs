//! Layer A — capabilities handshake.

use crate::AgentKind;
use crate::vendor::claude_code::ClaudeCodeCapabilities;
use crate::vendor::codex::CodexCapabilities;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum CapabilityId {
    // —— Shared ——
    StreamingMessages,
    StreamingReasoning,
    Shell,
    Diff,
    Approval,
    Mcp,
    TokenCounters,
    AuthStatus,
    ReasoningEffort,
    ImageInput,
    Worktree,

    // —— Codex-only ——
    CodexSandboxMode,
    CodexApprovalPersistence,
    CodexSkills,
    CodexCustomPrompts,

    // —— Claude-Code-only ——
    ClaudeCodePermissionMode,
    ClaudeCodeHooks,
    ClaudeCodeOutputStyle,
    ClaudeCodeSlashCommands,
    ClaudeCodePlanMode,
    ClaudeCodeBackgroundAgents,
    ClaudeCodePluginDir,
    ClaudeCodeForkSession,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionCapabilities {
    pub agent_kind: AgentKind,
    pub agent_version: String,
    pub features: BTreeSet<CapabilityId>,
    pub vendor: VendorCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "agentKind", deny_unknown_fields)]
pub enum VendorCapabilities {
    #[serde(rename = "codex")]
    Codex(CodexCapabilities),
    #[serde(rename = "claude_code")]
    ClaudeCode(ClaudeCodeCapabilities),
}
