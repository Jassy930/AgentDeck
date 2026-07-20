//! E2EE endpoint 侧聚合 JSON Schema（独立于 local IPC / Runtime / Relay outer schema）。
//!
//! 通过 [`e2ee_schema`] 聚合 endpoint 契约类型，快照写到
//! `protocol/agentdeck/e2ee-v1.schema.json`，由 `e2ee_schema_matches_committed_snapshot`
//! 守护，用 `UPDATE_E2EE_SCHEMA=1` 重生成。
//!
//! 与 Relay outer schema **彼此独立**：本 schema 合法承载业务 payload 类型引用
//! （`SealedPayloadKind`，只出现在密文内），Relay outer schema 则严格禁止业务字段。

use crate::e2ee::{context, keys, pairing, pairing_control, payload, tbs};
use schemars::schema_for;
use serde_json::json;

/// E2EE v1 所有 endpoint 契约类型的聚合 schema。
pub fn e2ee_schema() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("AgentDeck E2EE Format v{}", super::E2EE_FORMAT_VERSION),
        "type": "object",
        "properties": {
            "SealedPayloadV1": serde_json::to_value(schema_for!(payload::SealedPayloadV1)).unwrap(),
            "SealedPayloadKind": serde_json::to_value(schema_for!(payload::SealedPayloadKind)).unwrap(),
            "UnsignedSealedBlobV1": serde_json::to_value(schema_for!(payload::UnsignedSealedBlobV1)).unwrap(),
            "SignedSealedBlobV1": serde_json::to_value(schema_for!(payload::SignedSealedBlobV1)).unwrap(),
            "VerifiedSealedBlobV1": serde_json::to_value(schema_for!(payload::VerifiedSealedBlobV1)).unwrap(),
            "ToBeSignedV1": serde_json::to_value(schema_for!(tbs::ToBeSignedV1)).unwrap(),
            "OuterContextV1": serde_json::to_value(schema_for!(context::OuterContextV1)).unwrap(),
            "PairInviteV1": serde_json::to_value(schema_for!(pairing::PairInviteV1)).unwrap(),
            "AuthorizationCapabilityV1": serde_json::to_value(schema_for!(pairing::AuthorizationCapabilityV1)).unwrap(),
            "AuthorizationPermissionV1": serde_json::to_value(schema_for!(pairing::AuthorizationPermissionV1)).unwrap(),
            "AuthorizationRequestV1": serde_json::to_value(schema_for!(pairing::AuthorizationRequestV1)).unwrap(),
            "PairRequestPlaintextV1": serde_json::to_value(schema_for!(pairing::PairRequestPlaintextV1)).unwrap(),
            "PairRequestV1": serde_json::to_value(schema_for!(pairing::PairRequestV1)).unwrap(),
            "PairPendingV1": serde_json::to_value(schema_for!(pairing::PairPendingV1)).unwrap(),
            "PairResponseV1": serde_json::to_value(schema_for!(pairing::PairResponseV1)).unwrap(),
            "PairResponsePlaintextV1": serde_json::to_value(schema_for!(pairing::PairResponsePlaintextV1)).unwrap(),
            "PairResponseReceivedV1": serde_json::to_value(schema_for!(pairing::PairResponseReceivedV1)).unwrap(),
            "DeviceAuthorizationV1": serde_json::to_value(schema_for!(pairing::DeviceAuthorizationV1)).unwrap(),
            "PairRequestInfoV1": serde_json::to_value(schema_for!(pairing::PairRequestInfoV1)).unwrap(),
            "PairResponseInfoV1": serde_json::to_value(schema_for!(pairing::PairResponseInfoV1)).unwrap(),
            "PairingEnvelopeTbsV1": serde_json::to_value(schema_for!(pairing::PairingEnvelopeTbsV1)).unwrap(),
            "MachineDataSignerBindingV1": serde_json::to_value(schema_for!(pairing::MachineDataSignerBindingV1)).unwrap(),
            "PairPendingTbsV1": serde_json::to_value(schema_for!(pairing_control::PairPendingTbsV1)).unwrap(),
            "PairResponseReceivedTbsV1": serde_json::to_value(schema_for!(pairing_control::PairResponseReceivedTbsV1)).unwrap(),
            "PairingControlEnvelopeV1": serde_json::to_value(schema_for!(pairing_control::PairingControlEnvelopeV1)).unwrap(),
            "KeyDirectoryV1": serde_json::to_value(schema_for!(keys::KeyDirectoryV1)).unwrap(),
            "KeyDirectorySignatureContextV1": serde_json::to_value(schema_for!(keys::KeyDirectorySignatureContextV1)).unwrap(),
            "KeyDirectoryTbsV1": serde_json::to_value(schema_for!(keys::KeyDirectoryTbsV1)).unwrap(),
            "KeyUpdateV1": serde_json::to_value(schema_for!(keys::KeyUpdateV1)).unwrap(),
            "EpochBarrierV1": serde_json::to_value(schema_for!(keys::EpochBarrierV1)).unwrap(),
            "KeyUpdateInfoV1": serde_json::to_value(schema_for!(keys::KeyUpdateInfoV1)).unwrap(),
            "KeyId": serde_json::to_value(schema_for!(keys::KeyId)).unwrap(),
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn e2ee_schema_matches_committed_snapshot() {
        let generated = serde_json::to_string_pretty(&super::e2ee_schema()).unwrap() + "\n";
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../protocol/agentdeck/e2ee-v1.schema.json");
        if std::env::var("UPDATE_E2EE_SCHEMA").is_ok() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "e2ee schema snapshot missing; run `UPDATE_E2EE_SCHEMA=1 cargo test -p agentdeck-protocol e2ee_schema_matches_committed_snapshot`"
            )
        });
        assert_eq!(
            generated, committed,
            "e2ee schema drifted; run `UPDATE_E2EE_SCHEMA=1 cargo test -p agentdeck-protocol e2ee_schema_matches_committed_snapshot` to regenerate"
        );
    }
}
