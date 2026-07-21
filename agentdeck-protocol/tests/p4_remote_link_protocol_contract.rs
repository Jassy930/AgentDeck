//! P4.4 RemoteLink 协议 ingress 契约。
//!
//! 这些测试先冻结 RemoteLink 在进入 daemon 业务层前必须消费的严格协议入口：
//! - Relay `SealedBlob` 只能逆解码成逐字节 canonical 的 `SignedSealedBlobV1`；
//! - 解密后的 Runtime JSON 受 1 MiB hard cap，且 ingress 只接受 Request；
//! - UplinkSend AAD 精确绑定 machine/device/request route 与 command-key epoch。

use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, OuterContextV1, OuterFrameKind, SignedSealedBlobV1,
    UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::id::{DeviceRouteId, MachineRouteId, RequestRouteId};
use agentdeck_protocol::relay_v2::{Ed25519Signature, RELAY_PROTOCOL_VERSION};
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    CatalogDelta, MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope,
    RuntimeFailure, RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeStreamItem,
};

const SEALED_BLOB_DOMAIN: &[u8] = b"AgentDeck/SealedBlobV1\0";
const ED25519_SIGNATURE_BYTES: usize = 64;

fn signed_blob(
    ciphertext: Vec<u8>,
    signature: [u8; ED25519_SIGNATURE_BYTES],
) -> SignedSealedBlobV1 {
    UnsignedSealedBlobV1::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: 7,
        },
        7,
        11,
        [0x44; 12],
        ciphertext,
    )
    .attach_signature(Ed25519Signature(signature))
}

fn canonical_wire() -> Vec<u8> {
    signed_blob(vec![0x55; 32], [0x66; ED25519_SIGNATURE_BYTES]).to_wire_bytes()
}

fn assert_wire_rejected(wire: &[u8], reason: &str) {
    assert!(
        SignedSealedBlobV1::from_wire_bytes(wire).is_err(),
        "SignedSealedBlobV1 ingress must reject {reason}"
    );
}

#[test]
fn signed_sealed_blob_wire_roundtrip_is_byte_identical() {
    let expected = signed_blob(vec![0x55; 32], [0x66; ED25519_SIGNATURE_BYTES]);
    let wire = expected.to_wire_bytes();

    let decoded = SignedSealedBlobV1::from_wire_bytes(&wire).expect("canonical wire must decode");

    assert_eq!(decoded, expected);
    assert_eq!(decoded.to_wire_bytes(), wire);
}

#[test]
fn signed_sealed_blob_wire_rejects_bad_magic_version_and_purpose() {
    let mut bad_magic = canonical_wire();
    bad_magic[0] ^= 0xff;
    assert_wire_rejected(&bad_magic, "bad magic");

    let mut bad_version = canonical_wire();
    bad_version[SEALED_BLOB_DOMAIN.len()..SEALED_BLOB_DOMAIN.len() + 2]
        .copy_from_slice(&(E2EE_FORMAT_VERSION + 1).to_be_bytes());
    assert_wire_rejected(&bad_version, "unsupported format version");

    let mut bad_purpose = canonical_wire();
    bad_purpose[SEALED_BLOB_DOMAIN.len() + 2] = u8::MAX;
    assert_wire_rejected(&bad_purpose, "unknown key purpose");
}

#[test]
fn signed_sealed_blob_wire_rejects_bad_lengths_and_trailing_bytes() {
    // Layout: domain | version | purpose | key-id epoch | key epoch | revision |
    //         nonce length | nonce | ciphertext length | ciphertext | signature.
    let nonce_length_offset = SEALED_BLOB_DOMAIN.len() + 2 + 1 + 8 + 8 + 8;
    let ciphertext_length_offset = nonce_length_offset + 4 + 12;

    let mut bad_nonce_length = canonical_wire();
    bad_nonce_length[nonce_length_offset..nonce_length_offset + 4]
        .copy_from_slice(&11_u32.to_be_bytes());
    assert_wire_rejected(&bad_nonce_length, "non-canonical nonce length");

    let mut bad_ciphertext_length = canonical_wire();
    bad_ciphertext_length[ciphertext_length_offset..ciphertext_length_offset + 4]
        .copy_from_slice(&33_u32.to_be_bytes());
    assert_wire_rejected(&bad_ciphertext_length, "mismatched ciphertext length");

    let mut trailing = canonical_wire();
    trailing.push(0x77);
    assert_wire_rejected(&trailing, "trailing bytes after the signature");

    let mut truncated_signature = canonical_wire();
    truncated_signature.pop();
    assert_wire_rejected(&truncated_signature, "a short Ed25519 signature");
}

#[test]
fn signed_sealed_blob_wire_rejects_short_aead_tag_and_zero_signature() {
    let short_tag = signed_blob(vec![0x55; 15], [0x66; ED25519_SIGNATURE_BYTES]).to_wire_bytes();
    assert_wire_rejected(&short_tag, "ciphertext shorter than the 16-byte AEAD tag");

    let zero_signature = signed_blob(vec![0x55; 32], [0; ED25519_SIGNATURE_BYTES]).to_wire_bytes();
    assert_wire_rejected(&zero_signature, "an all-zero sender signature");
}

fn request_envelope() -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("remote-request-1"),
        body: RuntimeMessage::Request(RuntimeRequest::DescribeAgents),
    }
}

fn json_bytes(envelope: &RuntimeEnvelope) -> Vec<u8> {
    serde_json::to_vec(envelope).expect("test envelope must encode")
}

#[test]
fn runtime_checked_decode_accepts_only_a_strict_request_envelope() {
    let request = json_bytes(&request_envelope());
    let decoded = RuntimeEnvelope::from_json_bytes_checked(&request)
        .expect("a strict, current-version Request must decode");
    assert!(matches!(
        decoded.body,
        RuntimeMessage::Request(RuntimeRequest::DescribeAgents)
    ));

    let reply = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("remote-reply-1"),
        body: RuntimeMessage::Reply(RuntimeReply::Failure(RuntimeFailure::new(
            "test.reply",
            "reply is not a request",
        ))),
    };
    assert!(
        RuntimeEnvelope::from_json_bytes_checked(&json_bytes(&reply)).is_err(),
        "remote ingress must not decode a Reply as a Runtime request"
    );

    let stream = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("remote-stream-1"),
        body: RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(CatalogDelta {
            catalog_revision: 1,
            changes: Vec::new(),
        })),
    };
    assert!(
        RuntimeEnvelope::from_json_bytes_checked(&json_bytes(&stream)).is_err(),
        "remote ingress must not decode a Stream as a Runtime request"
    );
}

#[test]
fn runtime_checked_decode_rejects_unknown_and_duplicate_fields() {
    let mut unknown = serde_json::to_value(request_envelope()).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("transportAuthority".to_owned(), serde_json::json!(true));
    assert!(
        RuntimeEnvelope::from_json_bytes_checked(&serde_json::to_vec(&unknown).unwrap()).is_err(),
        "transport-only authority must not be smuggled into RuntimeEnvelope"
    );

    let canonical = String::from_utf8(json_bytes(&request_envelope())).unwrap();
    let duplicate = canonical.replacen(
        "\"messageId\":",
        "\"messageId\":\"shadow\",\"messageId\":",
        1,
    );
    assert!(
        RuntimeEnvelope::from_json_bytes_checked(duplicate.as_bytes()).is_err(),
        "duplicate top-level fields must fail closed"
    );
}

#[test]
fn runtime_checked_decode_enforces_the_one_mib_hard_cap_before_decode() {
    let normal = json_bytes(&request_envelope());
    assert!(normal.len() < MAX_RUNTIME_JSON_FRAME_BYTES);
    assert!(RuntimeEnvelope::from_json_bytes_checked(&normal).is_ok());

    // JSON grammar permits trailing whitespace. Use the same otherwise-valid Request on both
    // sides of the boundary so this test cannot pass merely because the input is malformed.
    let mut below_cap = normal.clone();
    below_cap.resize(MAX_RUNTIME_JSON_FRAME_BYTES - 1, b' ');
    assert!(
        RuntimeEnvelope::from_json_bytes_checked(&below_cap).is_ok(),
        "a valid frame one byte below the 1 MiB cap must decode"
    );

    let mut exact_cap = normal.clone();
    exact_cap.resize(MAX_RUNTIME_JSON_FRAME_BYTES, b' ');
    assert!(
        RuntimeEnvelope::from_json_bytes_checked(&exact_cap).is_err(),
        "a frame exactly at the 1 MiB cap must be rejected"
    );

    let mut over_cap = normal;
    over_cap.resize(MAX_RUNTIME_JSON_FRAME_BYTES + 1, b' ');
    assert!(
        RuntimeEnvelope::from_json_bytes_checked(&over_cap).is_err(),
        "a frame above the 1 MiB cap must be rejected"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn uplink_send_context_has_exact_shape_and_aad() {
    let machine_route = MachineRouteId::from_bytes([0x11; 16]);
    let device_route = DeviceRouteId::from_bytes([0x22; 16]);
    let request_route = RequestRouteId::from_bytes([0x33; 16]);

    let context = OuterContextV1::uplink_send(machine_route, device_route, request_route, 9);

    assert_eq!(
        context,
        OuterContextV1 {
            frame_kind: OuterFrameKind::UplinkSend,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: Some(machine_route),
            device_route: Some(device_route),
            stream_route: None,
            request_route: Some(request_route),
            pair_route: None,
            stream_generation: None,
            stream_cursor: None,
            stream_seq: None,
            message_key_epoch: 9,
        }
    );
    context.validate().expect("exact uplink context is valid");
    assert_eq!(
        hex(&context.encode_aad()),
        "4167656e744465636b2f4f75746572436f6e746578745631000300020001011111111111111111111111111111111101222222222222222222222222222222220001333333333333333333333333333333330000000000000000000009"
    );
}
