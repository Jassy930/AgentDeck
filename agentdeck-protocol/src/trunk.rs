//! Layer A — neutral event trunk. Types here must NEVER contain
//! vendor names (Codex/OpenAI/Anthropic/Claude). Enforced by
//! `neutrality_tests.rs`.

// Populated in tasks T1.5, T1.6, T1.7, T1.8.

use std::collections::BTreeMap;
use std::path::PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::vendor::codex::CodexSessionOptions;
use crate::vendor::claude_code::ClaudeCodeSessionOptions;
use crate::capabilities::SessionCapabilities;

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

// ── T1.6: SessionId / ThreadId / AgentItem / ServerEvent ────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct SessionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ThreadId(pub String);

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentItemMeta {
    /// Vendor-specific extension fields. Allowed in main trunk because
    /// the keys carry no vendor name; consumers must opt-in.
    #[serde(default)]
    pub vendor_extensions: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum AgentItem {
    UserMessage { text: String, #[serde(default)] meta: AgentItemMeta },
    AssistantMessage { text: String, #[serde(default)] meta: AgentItemMeta },
    Reasoning { text: String, #[serde(default)] meta: AgentItemMeta },
    Shell {
        command: String,
        status: ShellStatus,
        #[serde(rename = "exitCode")]
        exit_code: Option<i32>,
        #[serde(rename = "durationMs")]
        duration_ms: Option<u64>,
        #[serde(default)] meta: AgentItemMeta,
    },
    Diff {
        files: Vec<DiffFile>,
        #[serde(default)] meta: AgentItemMeta,
    },
    Plan {
        steps: Vec<PlanStep>,
        #[serde(default)] meta: AgentItemMeta,
    },
    ImageReference {
        #[serde(rename = "savedPath")]
        saved_path: Option<PathBuf>,
        #[serde(rename = "originalPath")]
        original_path: Option<PathBuf>,
        #[serde(default)] meta: AgentItemMeta,
    },
    ToolCall {
        name: String,
        args: serde_json::Value,
        result: Option<serde_json::Value>,
        #[serde(default)] meta: AgentItemMeta,
    },
    Raw {
        #[serde(rename = "rawKind")]
        raw_kind: String,
        #[serde(rename = "rawPayload")]
        raw_payload: String,
        #[serde(default)] meta: AgentItemMeta,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ShellStatus {
    Running,
    Completed,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiffFile {
    pub path: PathBuf,
    pub status: DiffStatus,
    pub patch: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum DiffStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanStep {
    pub title: String,
    pub status: PlanStepStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum PlanStepStatus {
    Pending,
    InProgress,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TurnSummary {
    pub total_input_tokens: Option<u64>,
    pub total_output_tokens: Option<u64>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolError {
    pub code: String,
    pub message: String,
    pub diagnostic_ref: Option<String>,
}

// ── T1.7: ActionKind / ActionRequestVendor / ActionRequest / ActionDecision ──

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ActionKind {
    ExecuteCommand,
    EditFiles,
    GrantExtraPermission,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "agentKind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ActionRequestVendor {
    #[serde(rename = "codex")]
    Codex {
        #[serde(rename = "approvalPolicyAtDecision")]
        approval_policy_at_decision: crate::vendor::codex::CodexApprovalPolicy,
        #[serde(rename = "sandboxAtDecision")]
        sandbox_at_decision: crate::vendor::codex::CodexSandboxMode,
        #[serde(rename = "canPersist")]
        can_persist: bool,
    },
    #[serde(rename = "claude_code")]
    ClaudeCode {
        #[serde(rename = "permissionModeAtDecision")]
        permission_mode_at_decision: crate::vendor::claude_code::ClaudeCodePermissionMode,
        #[serde(rename = "toolName")]
        tool_name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionRequest {
    pub request_id: String,
    pub kind: ActionKind,
    pub summary: String,
    pub vendor: ActionRequestVendor,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionDecision {
    pub request_id: String,
    pub decision: ActionDecisionKind,
    pub persist: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ActionDecisionKind {
    Approve,
    Deny,
}

// ── T1.7: VendorControlPayload / VendorPanelPayload (real typed) ─────────────

use crate::vendor::codex::{CodexVendorControl, CodexVendorPanelEvent};
use crate::vendor::claude_code::{ClaudeCodeVendorControl, ClaudeCodeVendorPanelEvent};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "agentKind", content = "control", rename_all = "camelCase", deny_unknown_fields)]
pub enum VendorControlPayload {
    #[serde(rename = "codex")]
    Codex(CodexVendorControl),
    #[serde(rename = "claude_code")]
    ClaudeCode(ClaudeCodeVendorControl),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "agentKind", content = "event", rename_all = "camelCase", deny_unknown_fields)]
pub enum VendorPanelPayload {
    #[serde(rename = "codex")]
    Codex(CodexVendorPanelEvent),
    #[serde(rename = "claude_code")]
    ClaudeCode(ClaudeCodeVendorPanelEvent),
}

// ServerEvent — main trunk
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum ServerEvent {
    SessionStarted {
        #[serde(rename = "sessionId")]
        session_id: SessionId,
        #[serde(rename = "threadId")]
        thread_id: Option<ThreadId>,
        #[serde(rename = "agentKind")]
        agent_kind: AgentKind,
    },
    SessionCapabilities {
        #[serde(rename = "sessionId")]
        session_id: SessionId,
        #[serde(rename = "agentKind")]
        agent_kind: AgentKind,
        capabilities: SessionCapabilities,
    },
    AgentItem {
        #[serde(rename = "sessionId")]
        session_id: SessionId,
        #[serde(rename = "threadId")]
        thread_id: ThreadId,
        #[serde(rename = "agentKind")]
        agent_kind: AgentKind,
        item: AgentItem,
    },
    ActionRequest {
        #[serde(rename = "sessionId")]
        session_id: SessionId,
        #[serde(rename = "threadId")]
        thread_id: ThreadId,
        #[serde(rename = "agentKind")]
        agent_kind: AgentKind,
        request: ActionRequest,
    },
    TurnComplete {
        #[serde(rename = "sessionId")]
        session_id: SessionId,
        #[serde(rename = "threadId")]
        thread_id: ThreadId,
        #[serde(rename = "agentKind")]
        agent_kind: AgentKind,
        summary: TurnSummary,
    },
    Error {
        #[serde(rename = "sessionId")]
        session_id: Option<SessionId>,
        error: ProtocolError,
    },
    // Layer B forwarders — filled in T1.7
    VendorControl {
        #[serde(rename = "sessionId")]
        session_id: SessionId,
        #[serde(rename = "agentKind")]
        agent_kind: AgentKind,
        payload: VendorControlPayload,
    },
    VendorPanelEvent {
        #[serde(rename = "sessionId")]
        session_id: SessionId,
        #[serde(rename = "agentKind")]
        agent_kind: AgentKind,
        payload: VendorPanelPayload,
    },
}
