//! P1.1 中立性守护 —— 参照现有 `neutrality_tests.rs` 的属性名扫描做法。
//!
//! RuntimeEnvelope v4 是稳定中立身份层（design RC-9）。守护点：
//! - 任何属性名都不得以 vendor 前缀开头（codex/openai/anthropic/claude）。
//! - 任何属性名都不得使用 vendor thread/session 身份词
//!   （threadId/sessionId/vendorThreadId/resumeReference 等）——稳定身份只能
//!   使用中立 newtype（conversationId/turnId/eventId/itemId/entityId/commandId）。
//! - pending pairing 的 list/confirm/cancel 请求必须被标为 local-only administration。
//!
//! 说明：与 Relay wire（RC-6，对 relay 完全不可见 vendor）不同，Runtime 契约是
//! 解密后的业务内容，合法携带 `agentKind`/capability 枚举值等业务语义；因此中立性
//! 以“属性名 + 稳定身份词”为准，而非对枚举值做裸字符串扫描（与既有 crate 惯例一致）。

use agentdeck_protocol::runtime::schema::runtime_schema;
use serde_json::Value;

const FORBIDDEN_PREFIXES: &[&str] = &["codex", "openai", "anthropic", "claude"];

/// vendor thread/session 身份词（小写精确匹配）——稳定身份禁止泄漏 vendor 身份。
const FORBIDDEN_IDENTITY_NAMES: &[&str] = &[
    "threadid",
    "sessionid",
    "vendorthreadid",
    "vendorsessionid",
    "resumereference",
    "vendorresumereference",
    "resumehandle",
    "adapterstatekey",
];

fn walk_property_names(schema: &Value, mut visit: impl FnMut(&str)) {
    fn go(schema: &Value, visit: &mut dyn FnMut(&str)) {
        match schema {
            Value::Object(map) => {
                if let Some(props) = map.get("properties").and_then(|p| p.as_object()) {
                    for key in props.keys() {
                        visit(key);
                    }
                }
                for v in map.values() {
                    go(v, visit);
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    go(v, visit);
                }
            }
            _ => {}
        }
    }
    go(schema, &mut visit);
}

#[test]
fn no_property_name_uses_vendor_prefix() {
    let schema = runtime_schema();
    walk_property_names(&schema, |key| {
        let lower = key.to_lowercase();
        for prefix in FORBIDDEN_PREFIXES {
            assert!(
                !lower.starts_with(prefix),
                "runtime property `{key}` starts with vendor prefix `{prefix}`"
            );
        }
    });
}

#[test]
fn no_property_name_leaks_vendor_thread_or_session_identity() {
    let schema = runtime_schema();
    walk_property_names(&schema, |key| {
        let lower = key.to_lowercase();
        for forbidden in FORBIDDEN_IDENTITY_NAMES {
            assert!(
                lower != *forbidden,
                "runtime property `{key}` leaks vendor thread/session identity; use a neutral \
                 stable-id newtype instead (design RC-9)"
            );
        }
    });
}

#[test]
fn neutral_stable_identity_names_are_present() {
    // 契约确实使用中立稳定身份词。
    let schema = runtime_schema();
    let text = serde_json::to_string(&schema).unwrap();
    for expected in ["conversationId", "eventId", "commandId"] {
        assert!(
            text.contains(expected),
            "runtime schema should carry neutral stable id `{expected}`"
        );
    }
}

#[test]
fn local_administration_requests_are_marked_local_only() {
    // list/confirm/cancel 的 pending pairing 请求必须携带 LocalOnlyAdministration 标记，
    // 且该标记类型在 schema 中带有 "local-only administration" 描述。
    let schema = runtime_schema();
    let text = serde_json::to_string(&schema).unwrap();
    assert!(
        text.to_lowercase().contains("local-only administration"),
        "LocalOnlyAdministration marker description must appear in the runtime schema"
    );

    // 结构化检查：所有 machine-wide admin 变体都带 `scope` 属性。
    let req_schema = serde_json::to_value(schemars::schema_for!(
        agentdeck_protocol::runtime::command::RuntimeRequest
    ))
    .unwrap();
    let variants = req_schema["oneOf"]
        .as_array()
        .expect("RuntimeRequest is a tagged oneOf");
    for tag in [
        "listPendingPairings",
        "confirmPairing",
        "cancelPairing",
        "machineEnroll",
        "machineRemoteStatus",
        "trustReset",
        "stageUpgrade",
    ] {
        let variant = variants
            .iter()
            .find(|v| v["properties"]["request"]["enum"][0] == tag)
            .unwrap_or_else(|| panic!("missing variant `{tag}`"));
        assert!(
            every_schema_branch_has_property(&req_schema, variant, "scope"),
            "admin variant `{tag}` must carry a local-only `scope` marker"
        );
    }
}

fn every_schema_branch_has_property(
    root: &serde_json::Value,
    schema: &serde_json::Value,
    property: &str,
) -> bool {
    if schema["properties"]
        .as_object()
        .is_some_and(|properties| properties.contains_key(property))
    {
        return true;
    }
    if let Some(reference) = schema["$ref"].as_str() {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer))
            .is_some_and(|target| every_schema_branch_has_property(root, target, property));
    }
    ["allOf", "anyOf", "oneOf"].into_iter().any(|keyword| {
        schema[keyword].as_array().is_some_and(|branches| {
            !branches.is_empty()
                && branches
                    .iter()
                    .all(|branch| every_schema_branch_has_property(root, branch, property))
        })
    })
}
