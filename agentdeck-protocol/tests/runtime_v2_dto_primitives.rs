//! P3.9-C0-A1a1：不接入 production outer wire 的 Runtime v2 validated DTO 原语。

use std::collections::BTreeSet;

use agentdeck_protocol::runtime::configuration::{
    AgentDescription, AgentDescriptions, ClaudeCodeConversationConfiguration,
    CodexConversationConfiguration, ConfigurationReceipt, ConversationConfiguration,
    ConversationConfigurationState, VendorConfigurationSnapshot,
};
use agentdeck_protocol::runtime::metadata::{
    ConversationMetadataMutation, ConversationMetadataMutationRequest, ConversationMetadataReceipt,
};
use agentdeck_protocol::runtime::upgrade::{
    ArtifactSha256, StageUpgradeReceipt, StageUpgradeRequest,
};
use agentdeck_protocol::runtime::{IdempotencyKey, LocalOnlyAdministration};
use agentdeck_protocol::vendor::claude_code::{ClaudeCodeCapabilities, ClaudeCodePermissionMode};
use agentdeck_protocol::vendor::codex::{
    CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort, CodexSandboxMode,
};
use agentdeck_protocol::{AgentKind, SessionCapabilities, VendorCapabilities};
use schemars::schema_for;

fn codex_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::Never,
            CodexSandboxMode::ReadOnly,
            CodexReasoningEffort::High,
        ),
    ))
}

fn cc_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Plan,
            Some("opus".into()),
            Some("high".into()),
            Some("concise".into()),
        )
        .expect("bounded CC configuration"),
    ))
}

fn capabilities(kind: AgentKind) -> SessionCapabilities {
    let vendor = match kind {
        AgentKind::Codex => VendorCapabilities::Codex(CodexCapabilities::default()),
        AgentKind::ClaudeCode => VendorCapabilities::ClaudeCode(ClaudeCodeCapabilities::default()),
    };
    SessionCapabilities {
        agent_kind: kind,
        agent_version: "dto-fixture".into(),
        features: BTreeSet::new(),
        vendor,
    }
}

fn receipt_variant<'a>(schema: &'a serde_json::Value, status: &str) -> &'a serde_json::Value {
    schema["oneOf"]
        .as_array()
        .expect("receipt schema must contain oneOf variants")
        .iter()
        .find(|variant| variant["properties"]["status"]["enum"][0] == status)
        .expect("receipt schema must contain requested status")
}

#[test]
fn configuration_is_namespaced_bounded_and_agent_typed() {
    // 威胁场景：未验证的 vendor 配置会让错误 agent 或私有 session identity 进入共同
    // wire，daemon 随后可能以静默默认值执行。DTO ingress 必须在接线前先 fail-close。
    let codex = codex_configuration();
    let wire = serde_json::to_value(&codex).expect("encode Codex configuration");
    assert_eq!(wire["vendorControl"]["agentKind"], "codex");
    assert_eq!(
        wire["vendorControl"]["configuration"]["sandbox"],
        "read-only"
    );
    assert!(!wire.to_string().contains("sessionId"));
    assert_eq!(
        serde_json::from_value::<ConversationConfiguration>(wire)
            .expect("decode Codex configuration"),
        codex
    );

    let mut cc = serde_json::to_value(cc_configuration()).expect("encode CC configuration");
    cc["vendorControl"]["configuration"]["sessionId"] = serde_json::json!("forbidden");
    assert!(serde_json::from_value::<ConversationConfiguration>(cc).is_err());
    assert!(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            Some("x".repeat(1025)),
            None,
            None,
        )
        .is_err()
    );

    let codex = AgentDescription::new(
        AgentKind::Codex,
        capabilities(AgentKind::Codex),
        codex_configuration(),
    )
    .expect("matching Codex description");
    assert_eq!(codex.capabilities().agent_kind, AgentKind::Codex);
    assert_eq!(codex.default_configuration().agent_kind(), AgentKind::Codex);
    assert!(AgentDescriptions::new(vec![codex.clone(), codex]).is_err());
    assert!(
        AgentDescription::new(
            AgentKind::Codex,
            capabilities(AgentKind::ClaudeCode),
            cc_configuration(),
        )
        .is_err()
    );
}

#[test]
fn successful_receipts_reject_zero_in_memory_wire_and_schema() {
    // 威胁场景：若成功 receipt 可编码 revision 0、却不能再解码，客户端重放会遇到
    // 自相矛盾的合法 wire。构造后的 Serialize、Deserialize 与 schema 必须一致拒绝。
    assert!(ConversationConfigurationState::new(0, None).is_ok());
    assert!(ConversationConfigurationState::new(0, Some(codex_configuration())).is_err());
    assert!(ConversationConfigurationState::new(1, None).is_err());

    for invalid in [
        ConfigurationReceipt::Applied {
            conversation_id: "conversation-1".into(),
            configuration_revision: 0,
        },
        ConfigurationReceipt::Replayed {
            conversation_id: "conversation-1".into(),
            configuration_revision: 0,
        },
    ] {
        assert!(serde_json::to_value(invalid).is_err());
    }
    for status in ["applied", "replayed"] {
        assert!(
            serde_json::from_value::<ConfigurationReceipt>(serde_json::json!({
                "status": status,
                "conversationId": "conversation-1",
                "configurationRevision": 0
            }))
            .is_err()
        );
    }

    for invalid in [
        ConversationMetadataReceipt::Applied {
            conversation_id: "conversation-1".into(),
            entry_revision: 0,
        },
        ConversationMetadataReceipt::Replayed {
            conversation_id: "conversation-1".into(),
            entry_revision: 0,
        },
    ] {
        assert!(serde_json::to_value(invalid).is_err());
    }

    for (schema, revision_field) in [
        (
            serde_json::to_value(schema_for!(ConfigurationReceipt))
                .expect("configuration receipt schema"),
            "configurationRevision",
        ),
        (
            serde_json::to_value(schema_for!(ConversationMetadataReceipt))
                .expect("metadata receipt schema"),
            "entryRevision",
        ),
    ] {
        for status in ["applied", "replayed"] {
            let variant = receipt_variant(&schema, status);
            let properties = variant["properties"]
                .as_object()
                .expect("receipt variant properties");
            assert!(properties.keys().all(|name| !name.contains('_')));
            assert_eq!(
                variant["properties"][revision_field]["minimum"],
                serde_json::json!(1.0)
            );
        }
    }
}

#[test]
fn metadata_and_upgrade_validate_bounds_and_camel_case_wire() {
    let metadata = ConversationMetadataMutationRequest::new(
        "conversation-1".into(),
        IdempotencyKey::new("metadata-1"),
        7,
        ConversationMetadataMutation::rename(Some("renamed".into())).expect("bounded rename"),
    )
    .expect("validated metadata request");
    let metadata_wire = serde_json::to_value(metadata).expect("encode metadata request");
    assert_eq!(metadata_wire["expectedEntryRevision"], 7);
    assert!(
        serde_json::from_value::<ConversationMetadataMutation>(serde_json::json!({
            "kind": "rename"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<ConversationMetadataMutation>(serde_json::json!({
            "kind": "rename",
            "title": null
        }))
        .is_ok()
    );
    // 威胁场景：crate 调用方绕过构造器直接构造非法 metadata；若 egress 不复核，
    // 本端会发出自己无法再解码的 wire，并污染后续 CAS 重放。
    for invalid in [
        ConversationMetadataMutation::Rename {
            title: Some("x".repeat(4097)),
        },
        ConversationMetadataMutation::Rename {
            title: Some("contains\0nul".into()),
        },
    ] {
        assert!(serde_json::to_value(invalid).is_err());
    }
    let clear_title = ConversationMetadataMutation::rename(None).expect("clear title mutation");
    assert_eq!(
        serde_json::from_value::<ConversationMetadataMutation>(
            serde_json::to_value(&clear_title).expect("encode clear-title mutation")
        )
        .expect("decode clear-title mutation"),
        clear_title
    );

    let upgrade = StageUpgradeRequest::new(
        "1.2.3".into(),
        ArtifactSha256::new("ab".repeat(32)).expect("canonical artifact hash"),
        IdempotencyKey::new("upgrade-1"),
        LocalOnlyAdministration::LocalOnly,
    )
    .expect("validated upgrade request");
    let wire = serde_json::to_value(upgrade).expect("encode upgrade request");
    assert_eq!(wire["targetVersion"], "1.2.3");
    assert_eq!(wire["candidateSha256"], "ab".repeat(32));
    assert_eq!(wire["scope"], "localOnly");
    assert!(ArtifactSha256::new("AB".repeat(32)).is_err());
    for unsafe_version in ["", ".", "..", "nested/path", "../escape"] {
        assert!(
            StageUpgradeRequest::new(
                unsafe_version.into(),
                ArtifactSha256::new("ab".repeat(32)).expect("canonical artifact hash"),
                IdempotencyKey::new("upgrade-invalid"),
                LocalOnlyAdministration::LocalOnly,
            )
            .is_err()
        );
    }

    let schema =
        serde_json::to_value(schema_for!(StageUpgradeReceipt)).expect("upgrade receipt schema");
    for status in ["staged", "awaitingIdle", "replayed"] {
        assert!(
            receipt_variant(&schema, status)["properties"]
                .as_object()
                .expect("upgrade receipt properties")
                .keys()
                .all(|name| !name.contains('_'))
        );
    }

    let request_schema =
        serde_json::to_value(schema_for!(StageUpgradeRequest)).expect("upgrade request schema");
    let target_schema = &request_schema["properties"]["targetVersion"];
    assert_eq!(target_schema["minLength"], serde_json::json!(1));
    assert_eq!(target_schema["maxLength"], serde_json::json!(128));
    assert_eq!(
        target_schema["pattern"],
        serde_json::json!("^[A-Za-z0-9._+-]+$")
    );
    assert_eq!(target_schema["not"]["enum"], serde_json::json!([".", ".."]));

    // 威胁场景：伪造的升级回执若能携带路径穿越版本或零活跃 turn，客户端会把
    // 不可能的 daemon 状态当作可执行升级事实；wire 两端都必须拒绝。
    for invalid in [
        StageUpgradeReceipt::Staged {
            target_version: "../escape".into(),
        },
        StageUpgradeReceipt::AwaitingIdle {
            target_version: "1.2.3".into(),
            active_turns: 0,
        },
    ] {
        assert!(serde_json::to_value(invalid).is_err());
    }
    for invalid in [
        serde_json::json!({"status": "staged", "targetVersion": "../escape"}),
        serde_json::json!({
            "status": "awaitingIdle",
            "targetVersion": "1.2.3",
            "activeTurns": 0
        }),
    ] {
        assert!(serde_json::from_value::<StageUpgradeReceipt>(invalid).is_err());
    }
}
