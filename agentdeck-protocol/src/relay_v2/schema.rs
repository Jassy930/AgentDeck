//! Relay v2 outer 聚合 JSON Schema（独立于 local IPC / Runtime / E2EE schema）。
//!
//! 通过 [`relay_v2_schema`] 聚合 Relay 可见的外层类型，快照写到
//! `protocol/agentdeck/relay-v2.schema.json`，由 `relay_v2_schema_matches_committed_snapshot`
//! 守护，用 `UPDATE_RELAY_SCHEMA=1` 重生成（模式仿照 local IPC / Runtime）。
//!
//! 该 schema 是严格最小可见外层——业务字段由 `relay_v2_neutrality` 扫描禁止。

use crate::relay_v2::{auth, cursor, enrollment, failure, frame};
use schemars::schema_for;
use serde_json::json;

/// Relay v2 所有外层 wire 类型的聚合 schema。
pub fn relay_v2_schema() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("AgentDeck Relay Protocol v{}", super::RELAY_PROTOCOL_VERSION),
        "type": "object",
        "properties": {
            "OpaqueRouteFrame": serde_json::to_value(schema_for!(frame::OpaqueRouteFrame)).unwrap(),
            "RelayFrameBody": serde_json::to_value(schema_for!(frame::RelayFrameBody)).unwrap(),
            "SealedBlob": serde_json::to_value(schema_for!(frame::SealedBlob)).unwrap(),
            "StreamCursor": serde_json::to_value(schema_for!(cursor::StreamCursor)).unwrap(),
            "RelayGrant": serde_json::to_value(schema_for!(auth::RelayGrant)).unwrap(),
            "SignedCertificate": serde_json::to_value(schema_for!(auth::SignedCertificate)).unwrap(),
            "DeviceRevocation": serde_json::to_value(schema_for!(auth::DeviceRevocation)).unwrap(),
            "MachineEnrollmentRequestV1": serde_json::to_value(schema_for!(enrollment::MachineEnrollmentRequestV1)).unwrap(),
            "MachineEnrollmentResponseV1": serde_json::to_value(schema_for!(enrollment::MachineEnrollmentResponseV1)).unwrap(),
            "RelayFailure": serde_json::to_value(schema_for!(failure::RelayFailure)).unwrap(),
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn relay_v2_schema_matches_committed_snapshot() {
        let generated = serde_json::to_string_pretty(&super::relay_v2_schema()).unwrap() + "\n";
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../protocol/agentdeck/relay-v2.schema.json");
        if std::env::var("UPDATE_RELAY_SCHEMA").is_ok() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "relay v2 schema snapshot missing; run `UPDATE_RELAY_SCHEMA=1 cargo test -p agentdeck-protocol relay_v2_schema_matches_committed_snapshot`"
            )
        });
        assert_eq!(
            generated, committed,
            "relay v2 schema drifted; run `UPDATE_RELAY_SCHEMA=1 cargo test -p agentdeck-protocol relay_v2_schema_matches_committed_snapshot` to regenerate"
        );
    }
}
