//! Layer A — neutral event trunk. Types here must NEVER contain
//! vendor names (Codex/OpenAI/Anthropic/Claude). Enforced by
//! `neutrality_tests.rs`.

// Populated in tasks T1.5, T1.6, T1.7, T1.8.

use std::path::PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::vendor::codex::CodexSessionOptions;
use crate::vendor::claude_code::ClaudeCodeSessionOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentKind {
    Codex,
    ClaudeCode,
}

impl AgentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentKind::Codex => "codex",
            AgentKind::ClaudeCode => "claude_code",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOptions {
    /// daemon-level idle timeout for the spawned adapter process; 0 = no timeout
    #[serde(default)]
    pub idle_timeout_secs: u32,
    /// adapter log verbosity passthrough
    pub log_verbosity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "agentKind", rename_all = "camelCase", deny_unknown_fields)]
pub enum VendorSessionOptions {
    #[serde(rename = "codex")]
    Codex(CodexSessionOptions),
    #[serde(rename = "claude_code")]
    ClaudeCode(ClaudeCodeSessionOptions),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionStart {
    pub agent_kind: AgentKind,
    pub cwd: PathBuf,
    pub prompt: Option<String>,
    pub vendor_options: VendorSessionOptions,
    #[serde(default)]
    pub runtime_options: RuntimeOptions,
}
