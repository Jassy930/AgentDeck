//! Runtime v3 聚合 JSON Schema（独立于 local IPC / Relay v2 / E2EE schema）。
//!
//! 通过 `runtime_schema()` 聚合所有 Runtime v3 公共类型，快照写到
//! `protocol/agentdeck/runtime-protocol.schema.json`，由 `runtime_schema_matches_committed_snapshot`
//! 守护，用 `UPDATE_RUNTIME_SCHEMA=1` 重生成（模式仿照 local IPC 的
//! `schema_matches_committed_snapshot`）。

use crate::runtime::{
    catalog, command, configuration, envelope, event, metadata, receipt, sync, transfer, upgrade,
};
use schemars::{JsonSchema, r#gen::SchemaGenerator, schema::Schema, schema_for};
use serde_json::json;
use std::borrow::Cow;
use std::marker::PhantomData;

/// 只用于 schemars derive：wire key 必须存在，但其值允许是 `null`。
///
/// 直接在 `Option<T>` 上写 `#[schemars(required)]` 会调用 schemars 的
/// non-optional schema，错误地把 `null` 从 schema 中删掉。这个 marker 对 derive
/// 表现为非 Option（因此 key 进入 `required`），实际 property schema 则仍委托
/// `Option<T>` 生成 nullable union。
pub(crate) struct RequiredNullable<T>(PhantomData<T>);

impl<T: JsonSchema> JsonSchema for RequiredNullable<T> {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        format!("RequiredNullable_{}", T::schema_name())
    }

    fn schema_id() -> Cow<'static, str> {
        Cow::Owned(format!("RequiredNullable<{}>", T::schema_id()))
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        <Option<T>>::json_schema(generator)
    }
}

/// Runtime v3 所有公共 wire 类型的聚合 schema。
pub fn runtime_schema() -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    macro_rules! add {
        ($name:literal, $ty:ty) => {
            properties.insert(
                $name.to_owned(),
                serde_json::to_value(schema_for!($ty)).unwrap(),
            );
        };
    }
    add!("RuntimeEnvelope", envelope::RuntimeEnvelope);
    add!("RuntimeMessage", envelope::RuntimeMessage);
    add!("RuntimeRequest", command::RuntimeRequest);
    add!("RuntimeReply", envelope::RuntimeReply);
    add!("RuntimeStreamItem", envelope::RuntimeStreamItem);
    add!("RuntimeEvent", event::RuntimeEvent);
    add!("RuntimeEventBody", event::RuntimeEventBody);
    add!("StreamCursor", sync::StreamCursor);
    add!("RuntimeInnerCursor", sync::RuntimeInnerCursor);
    add!("RuntimeSubscriptionTarget", sync::RuntimeSubscriptionTarget);
    add!("SubscriptionReceipt", sync::SubscriptionReceipt);
    add!("ConversationSnapshot", sync::ConversationSnapshot);
    add!("SnapshotItem", sync::SnapshotItem);
    add!("RuntimeSyncComplete", sync::RuntimeSyncComplete);
    add!("BackfillChunk", sync::BackfillChunk);
    add!("BackfillRequest", sync::BackfillRequest);
    add!("BackfillRange", sync::BackfillRange);
    add!("CatalogSnapshot", catalog::CatalogSnapshot);
    add!("CatalogDelta", catalog::CatalogDelta);
    add!("ConversationEntry", catalog::ConversationEntry);
    add!("AgentDescriptions", configuration::AgentDescriptions);
    add!("AgentDescription", configuration::AgentDescription);
    add!(
        "ConversationConfiguration",
        configuration::ConversationConfiguration
    );
    add!(
        "ConversationConfigurationState",
        configuration::ConversationConfigurationState
    );
    add!(
        "ConfigureConversationRequest",
        configuration::ConfigureConversationRequest
    );
    add!("ConfigurationReceipt", configuration::ConfigurationReceipt);
    add!(
        "ConversationMetadataMutationRequest",
        metadata::ConversationMetadataMutationRequest
    );
    add!(
        "ConversationMetadataReceipt",
        metadata::ConversationMetadataReceipt
    );
    add!("StageUpgradeRequest", upgrade::StageUpgradeRequest);
    add!("StageUpgradeReceipt", upgrade::StageUpgradeReceipt);
    add!("CommandReceipt", receipt::CommandReceipt);
    add!("CommandStatus", receipt::CommandStatus);
    add!("CommandStatusReceipt", receipt::CommandStatusReceipt);
    add!(
        "ConversationStartReceipt",
        receipt::ConversationStartReceipt
    );
    add!("CancellationReceipt", receipt::CancellationReceipt);
    add!("ApprovalReceipt", receipt::ApprovalReceipt);
    add!("ApprovalDeliveryState", receipt::ApprovalDeliveryState);
    add!("RevocationReceipt", receipt::RevocationReceipt);
    add!("TransferEnvelope", transfer::TransferEnvelope);
    add!("RuntimeTransferChannel", transfer::RuntimeTransferChannel);
    add!("PromptPayload", command::PromptPayload);
    add!("ConversationStart", command::ConversationStart);
    add!("QueryReceiptSelector", command::QueryReceiptSelector);
    add!("LocalOnlyAdministration", command::LocalOnlyAdministration);
    add!("MachineEnrollRequest", command::MachineEnrollRequest);
    add!("TrustResetRequest", command::TrustResetRequest);
    add!("UninstallPurgePlanV1", command::UninstallPurgePlanV1);
    add!(
        "RelayAdminPurgeReceiptV1",
        crate::relay_v2::RelayAdminPurgeReceiptV1
    );
    add!("RuntimeFailure", crate::runtime::failure::RuntimeFailure);
    add!("PairInvite", envelope::PairInvite);
    add!("PendingPairing", envelope::PendingPairing);
    add!("MachineRemoteLifecycle", envelope::MachineRemoteLifecycle);
    add!(
        "MachineRemoteFailureCode",
        envelope::MachineRemoteFailureCode
    );
    add!("MachineRootFingerprint", envelope::MachineRootFingerprint);
    add!("MachineRemoteStatus", envelope::MachineRemoteStatus);
    add!(
        "CatalogPageCursor",
        crate::runtime::identity::CatalogPageCursor
    );

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("AgentDeck Runtime Protocol v{}", super::RUNTIME_PROTOCOL_VERSION),
        "type": "object",
        "properties": serde_json::Value::Object(properties)
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
