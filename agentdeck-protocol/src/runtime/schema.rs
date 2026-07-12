//! Runtime v1 聚合 JSON Schema（独立于 local IPC / Relay v2 / E2EE schema）。
//!
//! 通过 `runtime_schema()` 聚合所有 Runtime v1 公共类型，快照写到
//! `protocol/agentdeck/runtime-protocol.schema.json`，由 `runtime_schema_matches_committed_snapshot`
//! 守护，用 `UPDATE_RUNTIME_SCHEMA=1` 重生成（模式仿照 local IPC 的
//! `schema_matches_committed_snapshot`）。

use crate::runtime::{catalog, command, envelope, event, receipt, sync, transfer};
use schemars::schema_for;
use serde_json::json;

/// Runtime v1 所有公共 wire 类型的聚合 schema。
pub fn runtime_schema() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("AgentDeck Runtime Protocol v{}", super::RUNTIME_PROTOCOL_VERSION),
        "type": "object",
        "properties": {
            "RuntimeEnvelope": serde_json::to_value(schema_for!(envelope::RuntimeEnvelope)).unwrap(),
            "RuntimeMessage": serde_json::to_value(schema_for!(envelope::RuntimeMessage)).unwrap(),
            "RuntimeRequest": serde_json::to_value(schema_for!(command::RuntimeRequest)).unwrap(),
            "RuntimeReply": serde_json::to_value(schema_for!(envelope::RuntimeReply)).unwrap(),
            "RuntimeStreamItem": serde_json::to_value(schema_for!(envelope::RuntimeStreamItem)).unwrap(),
            "RuntimeEvent": serde_json::to_value(schema_for!(event::RuntimeEvent)).unwrap(),
            "RuntimeEventBody": serde_json::to_value(schema_for!(event::RuntimeEventBody)).unwrap(),
            "StreamCursor": serde_json::to_value(schema_for!(sync::StreamCursor)).unwrap(),
            "ConversationSnapshot": serde_json::to_value(schema_for!(sync::ConversationSnapshot)).unwrap(),
            "SnapshotItem": serde_json::to_value(schema_for!(sync::SnapshotItem)).unwrap(),
            "RuntimeSyncComplete": serde_json::to_value(schema_for!(sync::RuntimeSyncComplete)).unwrap(),
            "BackfillChunk": serde_json::to_value(schema_for!(sync::BackfillChunk)).unwrap(),
            "CatalogSnapshot": serde_json::to_value(schema_for!(catalog::CatalogSnapshot)).unwrap(),
            "CatalogDelta": serde_json::to_value(schema_for!(catalog::CatalogDelta)).unwrap(),
            "ConversationEntry": serde_json::to_value(schema_for!(catalog::ConversationEntry)).unwrap(),
            "CommandReceipt": serde_json::to_value(schema_for!(receipt::CommandReceipt)).unwrap(),
            "CommandStatus": serde_json::to_value(schema_for!(receipt::CommandStatus)).unwrap(),
            "CommandStatusReceipt": serde_json::to_value(schema_for!(receipt::CommandStatusReceipt)).unwrap(),
            "ConversationStartReceipt": serde_json::to_value(schema_for!(receipt::ConversationStartReceipt)).unwrap(),
            "CancellationReceipt": serde_json::to_value(schema_for!(receipt::CancellationReceipt)).unwrap(),
            "ApprovalReceipt": serde_json::to_value(schema_for!(receipt::ApprovalReceipt)).unwrap(),
            "ApprovalDeliveryState": serde_json::to_value(schema_for!(receipt::ApprovalDeliveryState)).unwrap(),
            "RevocationReceipt": serde_json::to_value(schema_for!(receipt::RevocationReceipt)).unwrap(),
            "TransferEnvelope": serde_json::to_value(schema_for!(transfer::TransferEnvelope)).unwrap(),
            "PromptPayload": serde_json::to_value(schema_for!(command::PromptPayload)).unwrap(),
            "ConversationStart": serde_json::to_value(schema_for!(command::ConversationStart)).unwrap(),
            "QueryReceiptSelector": serde_json::to_value(schema_for!(command::QueryReceiptSelector)).unwrap(),
            "LocalOnlyAdministration": serde_json::to_value(schema_for!(command::LocalOnlyAdministration)).unwrap(),
            "RuntimeFailure": serde_json::to_value(schema_for!(crate::runtime::failure::RuntimeFailure)).unwrap(),
            "PairInvite": serde_json::to_value(schema_for!(envelope::PairInvite)).unwrap(),
            "PendingPairing": serde_json::to_value(schema_for!(envelope::PendingPairing)).unwrap(),
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn runtime_schema_matches_committed_snapshot() {
        let generated = serde_json::to_string_pretty(&super::runtime_schema()).unwrap() + "\n";
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../protocol/agentdeck/runtime-protocol.schema.json");
        if std::env::var("UPDATE_RUNTIME_SCHEMA").is_ok() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "runtime schema snapshot missing; run `UPDATE_RUNTIME_SCHEMA=1 cargo test -p agentdeck-protocol runtime_schema_matches_committed_snapshot`"
            )
        });
        assert_eq!(
            generated, committed,
            "runtime schema drifted; run `UPDATE_RUNTIME_SCHEMA=1 cargo test -p agentdeck-protocol runtime_schema_matches_committed_snapshot` to regenerate"
        );
    }
}
