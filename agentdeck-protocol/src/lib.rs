//! The agent-neutral IPC protocol — v2.
//!
//! All v1 types (IpcMessage, SessionState, Lifecycle, LegacyAgentItem,
//! LegacyActionRequest, LegacyActionDecision, HistoryThreadSummary,
//! HistoryThreadList, HistoryThreadDetail, AgentItemKind, AgentReference,
//! HookFragment, FileEditChange, ToolAction) have been removed in T1.9.
//! Phase 2 / Phase 5 migrate downstream consumers.

pub mod trunk;
pub mod capabilities;
pub mod transport;
pub mod vendor;

pub use trunk::AgentKind;
pub use trunk::{RuntimeOptions, SessionStart, VendorSessionOptions};
pub use capabilities::{CapabilityId, SessionCapabilities, VendorCapabilities};
pub use vendor::codex::{CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort, CodexSandboxMode};
pub use vendor::codex::{CodexSessionOptions, McpOverride};
pub use vendor::claude_code::{ClaudeCodeCapabilities, ClaudeCodePermissionMode};
pub use vendor::claude_code::{ClaudeCodeHookConfig, ClaudeCodeSessionOptions};
pub use transport::{AuthContext, Transport, TransportConfig, TransportError};
pub use trunk::{
    AgentItem, AgentItemMeta, DiffFile, DiffStatus, PlanStep, PlanStepStatus,
    ProtocolError, ServerEvent, SessionId, ShellStatus, ThreadId, TurnSummary,
};
pub use trunk::{ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor, VendorControlPayload, VendorPanelPayload};
pub use vendor::codex::{CodexVendorControl, CodexVendorPanelEvent};
pub use vendor::claude_code::{ClaudeCodeVendorControl, ClaudeCodeVendorPanelEvent};
pub use trunk::{HistoryListItem, HistoryReadResponse, HistoryRequest, HistoryTurn};
pub use trunk::ClientCommand;

/// 契约产物版本。改动协议形态时手动 +1，并重生成快照。
pub const PROTOCOL_VERSION: u32 = 2;

/// Aggregate JSON Schema for all v2 wire types. Snapshot-tested against
/// `protocol/agentdeck/agentdeck-protocol.schema.json`.
pub fn protocol_schema() -> serde_json::Value {
    use schemars::schema_for;
    use serde_json::json;

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("AgentDeck Protocol v{}", PROTOCOL_VERSION),
        "type": "object",
        "properties": {
            "AgentKind": serde_json::to_value(schema_for!(trunk::AgentKind)).unwrap(),
            "SessionStart": serde_json::to_value(schema_for!(trunk::SessionStart)).unwrap(),
            "ServerEvent": serde_json::to_value(schema_for!(trunk::ServerEvent)).unwrap(),
            "ClientCommand": serde_json::to_value(schema_for!(trunk::ClientCommand)).unwrap(),
            "SessionCapabilities": serde_json::to_value(schema_for!(capabilities::SessionCapabilities)).unwrap(),
            "HistoryRequest": serde_json::to_value(schema_for!(trunk::HistoryRequest)).unwrap(),
            "HistoryListItem": serde_json::to_value(schema_for!(trunk::HistoryListItem)).unwrap(),
            "HistoryReadResponse": serde_json::to_value(schema_for!(trunk::HistoryReadResponse)).unwrap(),
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn protocol_version_is_positive() {
        assert!(super::PROTOCOL_VERSION >= 1);
    }

    #[test]
    fn schema_matches_committed_snapshot() {
        let generated = serde_json::to_string_pretty(&super::protocol_schema()).unwrap() + "\n";
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../protocol/agentdeck/agentdeck-protocol.schema.json");
        if std::env::var("UPDATE_SCHEMA").is_ok() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!("schema snapshot missing; run `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot`")
        });
        assert_eq!(
            generated, committed,
            "protocol schema drifted; run `UPDATE_SCHEMA=1 cargo test -p agentdeck-protocol schema_matches_committed_snapshot` to regenerate"
        );
    }
}
