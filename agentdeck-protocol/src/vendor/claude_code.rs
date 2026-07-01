//! Claude Code-specific vendor types. Populated in tasks T1.5, T1.7.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ClaudeCodePermissionMode {
    Default,
    AcceptEdits,
    Plan,
    Auto,
    DontAsk,
    BypassPermissions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudeCodeCapabilities {
    pub permission_modes: Vec<ClaudeCodePermissionMode>,
    pub output_styles: Vec<String>,
    pub hooks_supported: Vec<String>,
    pub cli_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudeCodeHookConfig {
    pub matcher: String,
    pub command: String,
    pub timeout_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaudeCodeSessionOptions {
    pub permission_mode: ClaudeCodePermissionMode,
    pub model: Option<String>,
    pub effort: Option<String>,
    #[serde(default)]
    pub hooks: Vec<ClaudeCodeHookConfig>,
    pub output_style: Option<String>,
    pub allowed_tools: Option<Vec<String>>,
    pub disallowed_tools: Option<Vec<String>>,
    pub mcp_config_path: Option<PathBuf>,
    #[serde(default)]
    pub plugin_dirs: Vec<PathBuf>,
    pub worktree: Option<String>,
    pub session_name: Option<String>,
    pub session_id: Option<String>,
}

// ── T1.7: ClaudeCodeVendorControl / ClaudeCodeVendorPanelEvent ───────────────

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum ClaudeCodeVendorControl {
    UpdatePermissionMode(ClaudeCodePermissionMode),
    UpdateOutputStyle { name: Option<String> },
    AddHook(ClaudeCodeHookConfig),
    RemoveHook { matcher: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ClaudeCodeVendorPanelEvent {
    /// Hook fire events from `claude --include-hook-events`.
    HookFired {
        matcher: String,
        #[serde(rename = "toolUseId")]
        tool_use_id: Option<String>,
        #[serde(rename = "elapsedMs")]
        elapsed_ms: Option<u64>,
    },
    /// Diagnostic system events such as api_retry/status/thinking_tokens
    /// that are useful to clients but have no neutral trunk counterpart.
    SystemStatus {
        subtype: String,
        status: Option<String>,
        message: Option<String>,
        attempt: Option<u64>,
    },
}
