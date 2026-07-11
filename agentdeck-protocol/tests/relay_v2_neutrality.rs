//! P1.2 Relay v2 严格最小可见守护（design RC-6 / §10.2）。
//!
//! Relay v2 wire/schema 中禁止出现业务字段（机器名/session title/cwd/agent kind/
//! conversation/thread/turn/approval/vendor 词）与 `createdAt`（receivedAt/size 由
//! Relay 从实际接收计算，不进 wire）。e2ee schema 是 endpoint 侧契约、可承载业务
//! payload 类型引用，两份 schema 彼此独立——本测试证明 relay schema **不**包含
//! e2ee 的业务 payload kind 词。

use agentdeck_protocol::e2ee::schema::e2ee_schema;
use agentdeck_protocol::relay_v2::schema::relay_v2_schema;
use serde_json::Value;
use std::collections::BTreeSet;

/// 属性名里禁止出现的业务子串（小写包含匹配）。
const FORBIDDEN_PROPERTY_SUBSTR: &[&str] = &[
    "machinename",
    "sessiontitle",
    "cwd",
    "agentkind",
    "conversation",
    "thread",
    "turn",
    "approval",
    "vendor",
    "displayname",
    "prompt",
    "createdat",
    "receivedat",
];

/// 业务 payload kind 词只应出现在 e2ee schema（密文内），不得泄漏进 relay outer。
const E2EE_ONLY_BUSINESS_WORDS: &[&str] = &[
    "conversationEvent",
    "approvalDecision",
    "catalogSnapshot",
    "commandRequest",
];

fn walk_property_names(schema: &Value, visit: &mut dyn FnMut(&str)) {
    match schema {
        Value::Object(map) => {
            if let Some(props) = map.get("properties").and_then(|p| p.as_object()) {
                for key in props.keys() {
                    visit(key);
                }
            }
            for v in map.values() {
                walk_property_names(v, visit);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                walk_property_names(v, visit);
            }
        }
        _ => {}
    }
}

#[test]
fn relay_schema_property_names_carry_no_business_fields() {
    let schema = relay_v2_schema();
    walk_property_names(&schema, &mut |key| {
        let lower = key.to_lowercase();
        for forbidden in FORBIDDEN_PROPERTY_SUBSTR {
            assert!(
                !lower.contains(forbidden),
                "relay v2 property `{key}` leaks business/opaque-violating field `{forbidden}`"
            );
        }
    });
}

#[test]
fn relay_schema_full_text_carries_no_business_words() {
    // 整串 lowercase 扫描（review Minor #2）：覆盖 enum/const 判别值、`description` 与
    // 定义名等仅扫 properties key 会漏检的位置。当前禁词表与合法 schema 关键词无冲突
    // （已验证整串零命中）；若未来某禁词与合法词冲突（如英文 description 中的
    // "return" 含 "turn"），必须在此逐条显式排除并注释理由，不得直接放宽禁词表。
    let text = serde_json::to_string(&relay_v2_schema())
        .unwrap()
        .to_lowercase();
    for forbidden in FORBIDDEN_PROPERTY_SUBSTR {
        assert!(
            !text.contains(forbidden),
            "relay v2 schema full text contains business word `{forbidden}` \
             (check enum values / descriptions / definition names, not only property keys)"
        );
    }
}

#[test]
fn relay_schema_has_no_size_or_received_at_columns() {
    // §7.3：size / receivedAt 由 Relay 计算，不进 wire。
    let text = serde_json::to_string(&relay_v2_schema()).unwrap();
    let mut names: Vec<String> = Vec::new();
    walk_property_names(&relay_v2_schema(), &mut |k| names.push(k.to_lowercase()));
    assert!(
        !names
            .iter()
            .any(|n| n == "size" || n == "receivedat" || n == "createdat"),
        "relay wire must not declare size/receivedAt/createdAt fields"
    );
    // 断言基本存在：这是 relay v2 outer schema。
    assert!(text.contains("sealedBlob") || text.contains("SealedBlob"));
}

#[test]
fn relay_schema_uses_neutral_route_identity() {
    let text = serde_json::to_string(&relay_v2_schema()).unwrap();
    for expected in ["machineRoute", "streamRoute", "grantSerial"] {
        assert!(
            text.contains(expected),
            "relay v2 schema should carry neutral routing identity `{expected}`"
        );
    }
}

#[test]
fn relay_schema_does_not_leak_e2ee_business_payload_words() {
    // 两份 schema 独立：业务 payload kind 只在 e2ee（密文内），不在 relay outer。
    let relay_text = serde_json::to_string(&relay_v2_schema()).unwrap();
    let e2ee_text = serde_json::to_string(&e2ee_schema()).unwrap();
    for word in E2EE_ONLY_BUSINESS_WORDS {
        assert!(
            !relay_text.contains(word),
            "relay outer schema must not contain e2ee business payload word `{word}`"
        );
        assert!(
            e2ee_text.contains(word),
            "e2ee endpoint schema should legitimately carry business payload word `{word}`"
        );
    }
}

#[test]
fn retirement_terminal_schema_is_explicit_and_strictly_minimal() {
    let schema = relay_v2_schema();
    let relay_body = &schema["properties"]["RelayFrameBody"];
    let terminal = &relay_body["definitions"]["RetirementCommitted"];
    let fields = terminal["properties"]
        .as_object()
        .expect("RetirementCommitted must be a struct schema")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fields,
        BTreeSet::from(["machineRoute", "retireHash", "trustEpoch"]),
        "retirement ACK carries only routing identity, epoch and the verified RetireMachine canonical hash"
    );
    assert_eq!(terminal["additionalProperties"], Value::Bool(false));

    let variants = relay_body["oneOf"]
        .as_array()
        .expect("RelayFrameBody must expose tagged variants");
    assert!(variants.iter().any(|variant| {
        variant["properties"]["frameKind"]["enum"]
            .as_array()
            .is_some_and(|tags| tags == &[Value::String("retirementCommitted".into())])
    }));

    let retire_machine = &relay_body["definitions"]["RetireMachine"];
    let retire_fields = retire_machine["properties"]
        .as_object()
        .expect("RetireMachine must be a struct schema")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        retire_fields,
        BTreeSet::from(["machineRoute", "rootKeyId", "signature", "trustEpoch"]),
        "root-signed retirement must be self-describing without adding business metadata"
    );

    let text = serde_json::to_string(relay_body).unwrap();
    assert!(!text.contains("signedRetirement"));
    assert!(!text.contains("signedRetireMachine"));
}
