//! Relay admin 与 daemon/CLI 共用的 enrollment bundle wire 契约。

use agentdeck_protocol::relay_v2::{
    Digest32, ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, EnrollmentCode, PublicKeyBytes,
    RELAY_RECEIPT_FORMAT_VERSION, RELAY_RECEIPT_KEY_GENERATION_MVP, RelayReceiptKeyId,
    RelayReceiptVerifyKeyV1, RelayServerId, relay_v2_schema,
};

fn bundle() -> EnrollmentBundleV2 {
    let relay_server_id = RelayServerId::from_bytes([0x22; 16]);
    let public_key = PublicKeyBytes([0x33; 32]);
    EnrollmentBundleV2 {
        version: ENROLLMENT_BUNDLE_VERSION,
        public_wss_url: "wss://relay.example.test/".to_owned(),
        relay_server_id,
        receipt_verify_key: RelayReceiptVerifyKeyV1 {
            receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
            relay_server_id,
            key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
            key_id: RelayReceiptKeyId::from_public_key(&public_key),
            public_key,
        },
        code: EnrollmentCode([0x44; 32]),
        spki_pins: vec![Digest32([0xfb; 32])],
        expires_at_ms: 1_700_000_000_000,
    }
}

#[test]
fn enrollment_bundle_v2_has_byte_stable_admin_wire_shape() {
    let encoded = serde_json::to_string(&bundle()).expect("encode shared enrollment bundle");
    assert_eq!(
        encoded,
        r#"{"version":2,"publicWssUrl":"wss://relay.example.test/","relayServerId":"IiIiIiIiIiIiIiIiIiIiIg==","receiptVerifyKey":{"receiptFormatVersion":1,"relayServerId":"IiIiIiIiIiIiIiIiIiIiIg==","keyGeneration":1,"keyId":"9uiDt7VE9fLhOJ4F1EvvLCH5R+HGrCJpMfGxejtfq3M=","publicKey":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="},"code":"REREREREREREREREREREREREREREREREREREREREREQ=","spkiPins":["-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"],"expiresAtMs":1700000000000}"#
    );
    assert_eq!(
        serde_json::from_str::<EnrollmentBundleV2>(&encoded).expect("decode shared bundle"),
        bundle()
    );
}

#[test]
fn enrollment_bundle_and_digest_are_strict() {
    let mut value = serde_json::to_value(bundle()).expect("bundle JSON");
    value["version"] = serde_json::json!(1);
    assert!(serde_json::from_value::<EnrollmentBundleV2>(value).is_err());

    let mut value = serde_json::to_value(bundle()).expect("bundle JSON");
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<EnrollmentBundleV2>(value).is_err());

    let pin = serde_json::to_string(&Digest32([0xfb; 32])).expect("encode URL-safe pin");
    assert_eq!(pin, r#""-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s""#);
    assert!(
        serde_json::from_str::<Digest32>(r#""+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=""#)
            .is_err()
    );
    assert!(serde_json::from_str::<Digest32>(r#""AA""#).is_err());
}

#[test]
fn relay_schema_exposes_shared_enrollment_bundle_contract() {
    let schema = relay_v2_schema();
    for name in ["Digest32", "EnrollmentBundleV2"] {
        assert!(schema["properties"].get(name).is_some(), "missing {name}");
    }
}
