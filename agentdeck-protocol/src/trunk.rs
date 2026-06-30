//! Layer A — neutral event trunk. Types here must NEVER contain
//! vendor names (Codex/OpenAI/Anthropic/Claude). Enforced by
//! `neutrality_tests.rs`.

// Populated in tasks T1.5, T1.6, T1.7, T1.8.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
