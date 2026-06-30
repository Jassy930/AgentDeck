//! Claude Code-specific vendor types. Populated in tasks T1.5, T1.7.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
