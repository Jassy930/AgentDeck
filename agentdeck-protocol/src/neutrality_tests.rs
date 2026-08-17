//! N1 / N4 / K4 守护测试。
//!
//! N1 — Layer A 主干类型的属性名中不得出现 vendor 名称
//! N4 — Vendor 枚举变体必须是强类型的（不允许 additionalProperties:true）
//! K4 — ServerEvent 的每个变体（Error 除外）都必须携带 agentKind 字段

use crate::trunk::*;
use crate::vendor::claude_code::ClaudeCodeVendorControl;
use crate::vendor::codex::CodexVendorControl;
use schemars::schema_for;

/// N1：AgentItem、ActionRequest、TurnSummary、ProtocolError 的 JSON Schema
/// 属性名中不得出现 vendor 相关词汇（Codex/OpenAI/Anthropic/Claude 等）。
/// `ActionRequest.vendor` 是显式允许的 typed approval detail 插槽，
/// 其内部仍必须是强类型 enum，不能透传任意 JSON。
///
/// 实现策略：对每个变体的 `properties` 键进行结构化检查，而非脆弱的字符串扫描。
#[test]
fn protocol_neutrality_main_trunk() {
    // 禁止出现在属性名中的 vendor 前缀（全小写匹配）
    const FORBIDDEN_PREFIXES: &[&str] = &["codex", "openai", "anthropic", "claude"];

    // 检查 AgentItem 所有变体的属性名
    let schema_val = serde_json::to_value(schema_for!(AgentItem)).expect("serializable");
    let variants = schema_val["oneOf"]
        .as_array()
        .expect("AgentItem should be oneOf variants");
    for variant in variants {
        if let Some(props) = variant["properties"].as_object() {
            for key in props.keys() {
                let key_lower = key.to_lowercase();
                for prefix in FORBIDDEN_PREFIXES {
                    assert!(
                        !key_lower.starts_with(prefix),
                        "AgentItem property name `{}` starts with vendor prefix `{}`",
                        key,
                        prefix
                    );
                }
            }
        }
    }

    // 检查 TurnSummary 属性名
    let schema_val = serde_json::to_value(schema_for!(ActionRequest)).expect("serializable");
    if let Some(props) = schema_val["properties"].as_object() {
        for key in props.keys() {
            if key == "vendor" {
                continue;
            }
            let key_lower = key.to_lowercase();
            for prefix in FORBIDDEN_PREFIXES {
                assert!(
                    !key_lower.starts_with(prefix),
                    "ActionRequest property name `{}` starts with vendor prefix `{}`",
                    key,
                    prefix
                );
            }
        }
    }

    let schema =
        serde_json::to_string(&serde_json::to_value(schema_for!(ActionRequestVendor)).unwrap())
            .unwrap();
    assert!(
        !schema.contains(r#""additionalProperties":true"#),
        "ActionRequestVendor must be typed, not arbitrary JSON"
    );

    // 检查 TurnSummary 属性名
    let schema_val = serde_json::to_value(schema_for!(TurnSummary)).expect("serializable");
    if let Some(props) = schema_val["properties"].as_object() {
        for key in props.keys() {
            let key_lower = key.to_lowercase();
            for prefix in FORBIDDEN_PREFIXES {
                assert!(
                    !key_lower.starts_with(prefix),
                    "TurnSummary property name `{}` starts with vendor prefix `{}`",
                    key,
                    prefix
                );
            }
        }
    }

    // 检查 ProtocolError 属性名
    let schema_val = serde_json::to_value(schema_for!(ProtocolError)).expect("serializable");
    if let Some(props) = schema_val["properties"].as_object() {
        for key in props.keys() {
            let key_lower = key.to_lowercase();
            for prefix in FORBIDDEN_PREFIXES {
                assert!(
                    !key_lower.starts_with(prefix),
                    "ProtocolError property name `{}` starts with vendor prefix `{}`",
                    key,
                    prefix
                );
            }
        }
    }
}

/// N4：CodexVendorControl 和 ClaudeCodeVendorControl 的 schema 中
/// 不得出现 `"additionalProperties":true`，确保 vendor payload 是强类型的。
#[test]
fn capabilities_namespace_is_typed() {
    let schema =
        serde_json::to_string(&serde_json::to_value(schema_for!(CodexVendorControl)).unwrap())
            .unwrap();
    assert!(
        !schema.contains(r#""additionalProperties":true"#),
        "CodexVendorControl must not allow arbitrary additionalProperties — all variants must be typed"
    );

    let schema =
        serde_json::to_string(&serde_json::to_value(schema_for!(ClaudeCodeVendorControl)).unwrap())
            .unwrap();
    assert!(
        !schema.contains(r#""additionalProperties":true"#),
        "ClaudeCodeVendorControl must not allow arbitrary additionalProperties — all variants must be typed"
    );
}

/// K4：ServerEvent 的每个变体（Error 除外）都必须在 properties 中包含 agentKind 字段。
///
/// 实现策略：解析 oneOf 数组，对每个变体检查其 properties.type.enum[0]（变体标识符），
/// Error 变体跳过，其余变体断言 properties 中包含 agentKind。
#[test]
fn agent_kind_appears_on_every_trunk_event() {
    let schema_val = serde_json::to_value(schema_for!(ServerEvent)).expect("serializable");
    let variants = schema_val["oneOf"]
        .as_array()
        .expect("ServerEvent should be oneOf variants");

    assert!(
        !variants.is_empty(),
        "ServerEvent should have at least one variant"
    );

    for variant in variants {
        // 取变体的 type 标识符（来自 enum 数组的第一个元素）
        let tag = variant["properties"]["type"]["enum"][0]
            .as_str()
            .unwrap_or("");

        // Error 变体不要求 agentKind（可能在会话建立前触发）
        if tag == "error" {
            continue;
        }

        let has_agent_kind = variant["properties"]
            .as_object()
            .map(|p| p.contains_key("agentKind"))
            .unwrap_or(false);

        assert!(
            has_agent_kind,
            "ServerEvent variant `{}` is missing `agentKind` in properties — every non-Error \
             trunk event must carry agentKind (K4 constraint). Full variant: {}",
            tag,
            serde_json::to_string_pretty(variant).unwrap_or_default()
        );
    }
}
