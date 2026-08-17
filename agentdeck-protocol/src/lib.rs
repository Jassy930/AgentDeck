//! The agent-neutral IPC protocol — v2.
//!
//! All v1 types (IpcMessage, SessionState, Lifecycle, LegacyAgentItem,
//! LegacyActionRequest, LegacyActionDecision, HistoryThreadSummary,
//! HistoryThreadList, HistoryThreadDetail, AgentItemKind, AgentReference,
//! HookFragment, FileEditChange, ToolAction) have been removed in T1.9.
//! Phase 2 / Phase 5 migrate downstream consumers.

pub mod capabilities;
pub mod trunk;
pub mod vendor;

pub use capabilities::{CapabilityId, SessionCapabilities, VendorCapabilities};
pub use trunk::AgentKind;
pub use trunk::ClientCommand;
pub use trunk::{
    ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor,
    VendorControlPayload, VendorPanelPayload,
};
pub use trunk::{
    AgentItem, AgentItemMeta, DiffFile, DiffStatus, PlanStep, PlanStepStatus, ProtocolError,
    ServerEvent, SessionId, ShellStatus, ThreadId, TurnSummary,
};
pub use trunk::{DEFAULT_HISTORY_LIST_LIMIT, MAX_HISTORY_LIST_LIMIT, effective_history_list_limit};
pub use trunk::{
    HistoryListItem, HistoryReadResponse, HistoryRequest, HistoryResponse, HistoryTurn,
};
pub use trunk::{RuntimeOptions, SessionStart, VendorSessionOptions};
pub use vendor::claude_code::{ClaudeCodeCapabilities, ClaudeCodePermissionMode};
pub use vendor::claude_code::{ClaudeCodeHookConfig, ClaudeCodeSessionOptions};
pub use vendor::claude_code::{ClaudeCodeVendorControl, ClaudeCodeVendorPanelEvent};
pub use vendor::codex::{
    CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort, CodexSandboxMode,
};
pub use vendor::codex::{CodexSessionOptions, McpOverride};
pub use vendor::codex::{CodexVendorControl, CodexVendorPanelEvent};

/// 契约产物版本。改动协议形态时手动 +1，并重生成快照。
pub const PROTOCOL_VERSION: u32 = 2;

/// Aggregate JSON Schema for all v2 wire types. Snapshot-tested against
/// `protocol/agentdeck/agentdeck-protocol.schema.json`.
pub fn protocol_schema() -> serde_json::Value {
    use schemars::schema_for;
    use serde_json::json;

    canonicalize_json_object_order(json!({
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
            "HistoryResponse": serde_json::to_value(schema_for!(trunk::HistoryResponse)).unwrap(),
        }
    }))
}

/// Keep emitted schema text stable even when another workspace member enables
/// serde_json's `preserve_order` feature. JSON object order has no protocol
/// meaning, but the committed pretty-printed snapshot must stay reproducible.
fn canonicalize_json_object_order(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries = map
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json_object_order(value)))
                .collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            serde_json::Value::Object(entries.into_iter().collect())
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(canonicalize_json_object_order)
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod neutrality_tests;

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
