//! E2EE endpoint 侧聚合 JSON Schema（独立于 local IPC / Runtime / Relay outer schema）。
//!
//! 通过 [`e2ee_schema`] 聚合 endpoint 契约类型，快照写到
//! `protocol/agentdeck/e2ee-v1.schema.json`，由 `e2ee_schema_matches_committed_snapshot`
//! 守护，用 `UPDATE_E2EE_SCHEMA=1` 重生成。
//!
//! 与 Relay outer schema **彼此独立**：本 schema 合法承载业务 payload 类型引用
//! （`SealedPayloadKind`，只出现在密文内），Relay outer schema 则严格禁止业务字段。

use crate::e2ee::{
    context, key_control, key_recovery, keys, pairing, pairing_control, payload, tbs,
};
use schemars::schema_for;
use serde_json::json;

/// E2EE v1 所有 endpoint 契约类型的聚合 schema。
pub fn e2ee_schema() -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    macro_rules! insert_schema {
        ($name:literal, $type:path) => {
            properties.insert(
                $name.to_owned(),
                serde_json::to_value(schema_for!($type)).unwrap(),
            );
        };
    }
    insert_schema!("SealedPayloadV1", payload::SealedPayloadV1);
    insert_schema!("SealedPayloadKind", payload::SealedPayloadKind);
    insert_schema!("UnsignedSealedBlobV1", payload::UnsignedSealedBlobV1);
    insert_schema!("SignedSealedBlobV1", payload::SignedSealedBlobV1);
    insert_schema!("VerifiedSealedBlobV1", payload::VerifiedSealedBlobV1);
    insert_schema!("ToBeSignedV1", tbs::ToBeSignedV1);
    insert_schema!("OuterContextV1", context::OuterContextV1);
    insert_schema!("PairInviteV1", pairing::PairInviteV1);
    insert_schema!(
        "AuthorizationCapabilityV1",
        pairing::AuthorizationCapabilityV1
    );
    insert_schema!(
        "AuthorizationPermissionV1",
        pairing::AuthorizationPermissionV1
    );
    insert_schema!("AuthorizationRequestV1", pairing::AuthorizationRequestV1);
    insert_schema!("PairRequestPlaintextV1", pairing::PairRequestPlaintextV1);
    insert_schema!("PairRequestV1", pairing::PairRequestV1);
    insert_schema!("PairPendingV1", pairing::PairPendingV1);
    insert_schema!("PairResponseV1", pairing::PairResponseV1);
    insert_schema!("PairResponsePlaintextV1", pairing::PairResponsePlaintextV1);
    insert_schema!("PairResponseReceivedV1", pairing::PairResponseReceivedV1);
    insert_schema!("DeviceAuthorizationV1", pairing::DeviceAuthorizationV1);
    insert_schema!("PairRequestInfoV1", pairing::PairRequestInfoV1);
    insert_schema!("PairResponseInfoV1", pairing::PairResponseInfoV1);
    insert_schema!("PairingEnvelopeTbsV1", pairing::PairingEnvelopeTbsV1);
    insert_schema!(
        "MachineDataSignerBindingV1",
        pairing::MachineDataSignerBindingV1
    );
    insert_schema!("PairPendingTbsV1", pairing_control::PairPendingTbsV1);
    insert_schema!(
        "PairResponseReceivedTbsV1",
        pairing_control::PairResponseReceivedTbsV1
    );
    insert_schema!(
        "PairingControlEnvelopeV1",
        pairing_control::PairingControlEnvelopeV1
    );
    insert_schema!("KeyDirectoryV1", keys::KeyDirectoryV1);
    insert_schema!(
        "KeyDirectorySignatureContextV1",
        keys::KeyDirectorySignatureContextV1
    );
    insert_schema!("KeyDirectoryTbsV1", keys::KeyDirectoryTbsV1);
    insert_schema!("KeyUpdateV1", keys::KeyUpdateV1);
    insert_schema!("KeyUpdateTbsV1", keys::KeyUpdateTbsV1);
    insert_schema!("EpochBarrierV1", keys::EpochBarrierV1);
    insert_schema!("KeyUpdateInfoV1", keys::KeyUpdateInfoV1);
    insert_schema!("KeyControlV1", key_control::KeyControlV1);
    insert_schema!("KeyControlRequestV1", key_control::KeyControlRequestV1);
    insert_schema!(
        "DirectoryRevisionAdvanceV1",
        key_control::DirectoryRevisionAdvanceV1
    );
    insert_schema!("KeyUpdateSetV1", key_control::KeyUpdateSetV1);
    insert_schema!("KeySyncRequestV1", key_control::KeySyncRequestV1);
    insert_schema!("KeyUpdateAckV1", key_control::KeyUpdateAckV1);
    insert_schema!("StreamAppliedAckV1", key_control::StreamAppliedAckV1);
    insert_schema!("StreamBindingV1", key_control::StreamBindingV1);
    insert_schema!(
        "DeviceKeyRecoveryInfoV1",
        key_recovery::DeviceKeyRecoveryInfoV1
    );
    insert_schema!(
        "DeviceKeyRecoveryTbsV1",
        key_recovery::DeviceKeyRecoveryTbsV1
    );
    insert_schema!(
        "DeviceKeyRecoveryReplyV1",
        key_recovery::DeviceKeyRecoveryReplyV1
    );
    insert_schema!("KeyId", keys::KeyId);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("AgentDeck E2EE Format v{}", super::E2EE_FORMAT_VERSION),
        "type": "object",
        "properties": properties
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
