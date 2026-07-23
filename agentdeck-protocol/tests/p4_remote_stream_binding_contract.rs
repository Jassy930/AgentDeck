//! P4.6 remote watch 的 authenticated publication binding 契约。
//!
//! `StreamBindingV1` 只存在于 MachineDataSign + DeviceReplyTx 保护的 E2EE reply 内，
//! 为 endpoint 提供构造 Relay `Subscribe(route, generation, cursor)` 所需的精确轴；
//! Runtime DTO 保持 transport-neutral。

use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KEY_CONTROL_MAX_ID_BYTES, KeyControlV1, KeyId, KeyPurpose,
    STREAM_BINDING_MAX_CANONICAL_BYTES, SealedPayloadKind, StreamBindingV1,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::StreamCursor;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, StreamGenerationId,
    StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::sync::RuntimeInnerCursor;
use schemars::schema_for;
use sha2::{Digest, Sha256};

fn machine(byte: u8) -> MachineRouteId {
    MachineRouteId::from_bytes([byte; 16])
}

fn device(byte: u8) -> DeviceRouteId {
    DeviceRouteId::from_bytes([byte; 16])
}

fn stream(byte: u8) -> StreamRouteId {
    StreamRouteId::from_bytes([byte; 16])
}

fn generation(byte: u8) -> StreamGenerationId {
    StreamGenerationId::from_bytes([byte; 16])
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn catalog_binding() -> StreamBindingV1 {
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: machine(0x11),
        device_route: device(0x12),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(3),
        stream_route: stream(0x21),
        stream_generation: generation(0x22),
        stream_cursor: StreamCursor::At(41),
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(19),
        },
        key_directory_revision: KeyDirectoryRevision::new(9),
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 5,
        },
    }
}

fn conversation_binding() -> StreamBindingV1 {
    StreamBindingV1 {
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("conversation-7"),
            cursor: StreamCursor::At(23),
        },
        key_id: KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 6,
        },
        ..catalog_binding()
    }
}

#[test]
fn catalog_and_conversation_bindings_round_trip_with_append_only_key_control_tag() {
    let catalog = catalog_binding();
    assert_eq!(
        hex_sha256(&catalog.canonical_bytes().unwrap()),
        "1f18c1ea7d6b1ea9a5789907ceda61e9ad08f6650912d18965a05303d3d26616"
    );
    assert_eq!(
        hex_sha256(
            &KeyControlV1::stream_binding(catalog)
                .canonical_bytes()
                .unwrap()
        ),
        "a1daba2be1308f5a41a07d66ca70270345d13cb63dfde28105c9852693ae945d"
    );

    for binding in [catalog_binding(), conversation_binding()] {
        binding.validate().expect("valid stream binding");
        let bytes = binding.canonical_bytes().expect("canonical binding");
        assert_eq!(
            StreamBindingV1::from_canonical_bytes(&bytes).expect("decode binding"),
            binding
        );

        let control = KeyControlV1::stream_binding(binding.clone());
        assert_eq!(control.sealed_payload_kind(), SealedPayloadKind::KeyUpdate);
        let control_bytes = control.canonical_bytes().expect("canonical control");
        assert_eq!(
            KeyControlV1::from_canonical_bytes(&control_bytes).expect("decode control"),
            control
        );

        let kind_offset = b"AgentDeck/KeyControlV1\0".len();
        assert_eq!(
            control_bytes[kind_offset], 3,
            "new tag must append after 0..=2"
        );
    }
}

#[test]
fn binding_rejects_wrong_versions_zero_authority_and_zero_stream_axes() {
    let mut cases = Vec::new();

    let mut value = catalog_binding();
    value.format_version += 1;
    cases.push(value);
    let mut value = catalog_binding();
    value.runtime_protocol_version += 1;
    cases.push(value);
    let mut value = catalog_binding();
    value.relay_protocol_version += 1;
    cases.push(value);
    let mut value = catalog_binding();
    value.machine_route = machine(0);
    cases.push(value);
    let mut value = catalog_binding();
    value.device_route = device(0);
    cases.push(value);
    let mut value = catalog_binding();
    value.grant_serial = GrantSerial::ZERO;
    cases.push(value);
    let mut value = catalog_binding();
    value.root_trust_epoch = TrustEpoch::ZERO;
    cases.push(value);
    let mut value = catalog_binding();
    value.stream_route = stream(0);
    cases.push(value);
    let mut value = catalog_binding();
    value.stream_generation = generation(0);
    cases.push(value);
    let mut value = catalog_binding();
    value.key_directory_revision = KeyDirectoryRevision::ZERO;
    cases.push(value);
    let mut value = catalog_binding();
    value.key_id.epoch = 0;
    cases.push(value);
    let mut value = catalog_binding();
    value.stream_cursor = StreamCursor::At(u64::MAX);
    cases.push(value);
    let mut value = catalog_binding();
    value.inner_cursor = RuntimeInnerCursor::Catalog {
        cursor: StreamCursor::At(u64::MAX),
    };
    cases.push(value);

    for invalid in cases {
        assert!(invalid.validate().is_err());
        assert!(invalid.canonical_bytes().is_err());
        assert!(
            serde_json::to_value(&invalid).is_err(),
            "invalid binding must also fail closed on JSON egress"
        );
    }
}

#[test]
fn binding_requires_target_specific_catalog_or_conversation_key() {
    let mut catalog_with_conversation_key = catalog_binding();
    catalog_with_conversation_key.key_id.purpose = KeyPurpose::ConversationDek;
    assert!(catalog_with_conversation_key.validate().is_err());

    let mut conversation_with_catalog_key = conversation_binding();
    conversation_with_catalog_key.key_id.purpose = KeyPurpose::Catalog;
    assert!(conversation_with_catalog_key.validate().is_err());

    for purpose in [KeyPurpose::DeviceCommandTx, KeyPurpose::DeviceReplyTx] {
        let mut catalog = catalog_binding();
        catalog.key_id.purpose = purpose;
        assert!(catalog.validate().is_err());

        let mut conversation = conversation_binding();
        conversation.key_id.purpose = purpose;
        assert!(conversation.validate().is_err());
    }

    let mut empty_id = conversation_binding();
    empty_id.inner_cursor = RuntimeInnerCursor::Conversation {
        conversation_id: ConversationId::new(""),
        cursor: StreamCursor::BeforeFirst,
    };
    assert!(empty_id.validate().is_err());

    let mut oversized_id = conversation_binding();
    oversized_id.inner_cursor = RuntimeInnerCursor::Conversation {
        conversation_id: ConversationId::new("x".repeat(KEY_CONTROL_MAX_ID_BYTES + 1)),
        cursor: StreamCursor::BeforeFirst,
    };
    assert!(oversized_id.validate().is_err());
}

#[test]
fn every_subscription_authority_cursor_and_key_axis_is_canonically_bound() {
    let original = catalog_binding();
    let original_hash = original.canonical_sha256().unwrap();
    let mut changed = Vec::new();

    let mut value = original.clone();
    value.machine_route = machine(0x31);
    changed.push(value);
    let mut value = original.clone();
    value.device_route = device(0x32);
    changed.push(value);
    let mut value = original.clone();
    value.grant_serial = GrantSerial::new(8);
    changed.push(value);
    let mut value = original.clone();
    value.root_trust_epoch = TrustEpoch::new(4);
    changed.push(value);
    let mut value = original.clone();
    value.stream_route = stream(0x33);
    changed.push(value);
    let mut value = original.clone();
    value.stream_generation = generation(0x34);
    changed.push(value);
    let mut value = original.clone();
    value.stream_cursor = StreamCursor::At(42);
    changed.push(value);
    let mut value = original.clone();
    value.inner_cursor = RuntimeInnerCursor::Catalog {
        cursor: StreamCursor::At(20),
    };
    changed.push(value);
    let mut value = original.clone();
    value.key_directory_revision = KeyDirectoryRevision::new(10);
    changed.push(value);
    let mut value = original;
    value.key_id.epoch = 6;
    changed.push(value);

    for tampered in changed {
        assert_ne!(tampered.canonical_sha256().unwrap(), original_hash);
    }
}

#[test]
fn binary_and_json_decoders_fail_closed_on_noncanonical_or_unknown_input() {
    let binding = conversation_binding();
    let canonical = binding.canonical_bytes().unwrap();

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(StreamBindingV1::from_canonical_bytes(&trailing).is_err());

    let mut truncated = canonical.clone();
    truncated.pop();
    assert!(StreamBindingV1::from_canonical_bytes(&truncated).is_err());

    let mut bad_domain = canonical;
    bad_domain[0] ^= 0x01;
    assert!(StreamBindingV1::from_canonical_bytes(&bad_domain).is_err());

    assert!(
        StreamBindingV1::from_canonical_bytes(&vec![0; STREAM_BINDING_MAX_CANONICAL_BYTES + 1])
            .is_err()
    );

    let mut control = KeyControlV1::stream_binding(binding)
        .canonical_bytes()
        .unwrap();
    let kind_offset = b"AgentDeck/KeyControlV1\0".len();
    control[kind_offset] = u8::MAX;
    assert!(KeyControlV1::from_canonical_bytes(&control).is_err());

    let mut json = serde_json::to_value(conversation_binding()).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("unknownField".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<StreamBindingV1>(json).is_err());

    let mut invalid_semantics = serde_json::to_value(conversation_binding()).unwrap();
    invalid_semantics["keyDirectoryRevision"] = serde_json::json!(0);
    assert!(serde_json::from_value::<StreamBindingV1>(invalid_semantics).is_err());

    let mut exhausted = serde_json::to_value(conversation_binding()).unwrap();
    exhausted["streamCursor"] = serde_json::to_value(StreamCursor::At(u64::MAX)).unwrap();
    assert!(serde_json::from_value::<StreamBindingV1>(exhausted).is_err());

    let mut empty_id = serde_json::to_value(conversation_binding()).unwrap();
    empty_id["innerCursor"]["conversationId"] = serde_json::json!("");
    assert!(serde_json::from_value::<StreamBindingV1>(empty_id).is_err());

    let mut outer_mismatch =
        serde_json::to_value(KeyControlV1::stream_binding(conversation_binding())).unwrap();
    outer_mismatch["formatVersion"] = serde_json::json!(E2EE_FORMAT_VERSION + 1);
    assert!(serde_json::from_value::<KeyControlV1>(outer_mismatch).is_err());
}

#[test]
fn json_schema_matches_validated_camel_case_wire_and_numeric_bounds() {
    let schema = serde_json::to_value(schema_for!(KeyControlV1)).unwrap();
    let encoded = serde_json::to_string(&schema).unwrap();

    assert!(encoded.contains("\"formatVersion\""));
    assert!(encoded.contains("\"streamRoute\""));
    assert!(encoded.contains("\"updateSet\""));
    assert!(!encoded.contains("\"format_version\""));
    assert!(encoded.contains("\"minimum\":1.0") || encoded.contains("\"minimum\":1"));
    assert!(encoded.contains("\"x-maxUtf8Bytes\":1024"));
}
