//! P1.2 E2EE canonical context 契约（design §6.6 / §7.2–§7.4）。
//!
//! 覆盖：
//! - type-state `Unsigned → Signed → Verified`（Publish/outbound 只接收 Signed；
//!   AEAD open 只接收 Verified；本 task 不实现真实密码学）。
//! - `ToBeSignedV1` 确定性长度前缀编码 + 固定字节 golden。
//! - `OuterContextV1` 与三种 HPKE info 的确定性编码 + golden（排除循环 preimage 字段）。
//! - 版本化 pairing / key DTO（PairResponseReceivedV1 结构绑定三个 hash + DeviceSign）。

use agentdeck_protocol::e2ee::context::{OuterContextV1, OuterFrameKind};
use agentdeck_protocol::e2ee::keys::{
    EpochBarrierV1, KeyDirectoryEntry, KeyDirectoryV1, KeyId, KeyPurpose, KeyUpdateInfoV1,
    KeyUpdateV1,
};
use agentdeck_protocol::e2ee::pairing::{
    DeviceAuthorizationV1, PairInviteV1, PairPendingV1, PairRequestInfoV1, PairRequestV1,
    PairResponseInfoV1, PairResponseReceivedV1, PairResponseV1,
};
use agentdeck_protocol::e2ee::payload::{
    SealedBlobSignatureVerifier, SealedPayloadKind, SealedPayloadV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::e2ee::tbs::{SignedObjectType, ToBeSignedV1};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, E2eeError};
use agentdeck_protocol::relay_v2::StreamCursor;
use agentdeck_protocol::relay_v2::auth::{
    CertRole, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId, PairRouteId,
    RelayServerId, RootKeyId, StreamGenerationId, StreamRouteId, TrustEpoch,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check_golden(name: &str, actual: &str, expected: &str) {
    if expected.is_empty() {
        println!("GOLDEN {name} = {actual}");
    } else {
        assert_eq!(actual, expected, "golden `{name}` drifted");
    }
}

fn pk() -> PublicKeyBytes {
    PublicKeyBytes([0xA0; 32])
}
fn sig() -> Ed25519Signature {
    Ed25519Signature([0xB0; 64])
}
fn mr() -> MachineRouteId {
    MachineRouteId::from_bytes([0x11; 16])
}
fn dr() -> DeviceRouteId {
    DeviceRouteId::from_bytes([0x22; 16])
}
fn pr() -> PairRouteId {
    PairRouteId::from_bytes([0x55; 16])
}
fn rs() -> RelayServerId {
    RelayServerId::from_bytes([0x88; 16])
}
fn rk() -> RootKeyId {
    RootKeyId::from_bytes([0x77; 16])
}

#[test]
fn e2ee_format_version_is_one() {
    assert_eq!(E2EE_FORMAT_VERSION, 1);
}

// —— type-state sealed blob ——

fn unsigned() -> UnsignedSealedBlobV1 {
    UnsignedSealedBlobV1::new(
        SealedPayloadKind::ConversationEvent,
        KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 4,
        },
        4,
        2,
        [0x03; 12],
        vec![0xCA, 0xFE],
    )
}

#[test]
fn type_state_progresses_unsigned_signed_verified() {
    let u = unsigned();
    // outbound path only accepts Signed → attach signature first.
    let signed = u.attach_signature(sig());
    let wire = signed.to_wire_bytes();
    assert!(
        !wire.is_empty(),
        "signed blob must serialize to canonical wire bytes"
    );

    // P1 fail-closed：verify 桩直接返回 CryptoNotAvailable —— VerifiedSealedBlobV1
    // 在 P1 无法经任何公共 API 构造（字段私有、无 Deserialize）。P4 必须显式实现
    // 真实 Ed25519 验签，链路才能跑通（RC-15）。`open_plaintext` 只在 Verified 上，
    // 因此 P1 也不可达（type-state compile_fail doctest 继续证明 Signed 不能 open）。
    assert_eq!(
        signed.verify(&pk()).unwrap_err(),
        E2eeError::CryptoNotAvailable
    );
}

// —— verify_with hook（P1.4 crypto 注入真实验签；protocol 侧计算 TBS bytes）——

struct OkVerifier;
impl SealedBlobSignatureVerifier for OkVerifier {
    fn verify_sealed_tbs(
        &self,
        _tbs: &[u8],
        _signature: &Ed25519Signature,
    ) -> Result<(), E2eeError> {
        Ok(())
    }
}

struct FailVerifier;
impl SealedBlobSignatureVerifier for FailVerifier {
    fn verify_sealed_tbs(
        &self,
        _tbs: &[u8],
        _signature: &Ed25519Signature,
    ) -> Result<(), E2eeError> {
        Err(E2eeError::BadSenderSignature)
    }
}

#[test]
fn verify_with_constructs_verified_only_when_verifier_ok() {
    let signed = unsigned().attach_signature(sig());
    let ctx = outer_sample();

    // TBS bytes 由 protocol 侧从 context + blob 计算，带独立 domain separator。
    let tbs = signed.inner.sealed_blob_tbs(&ctx);
    assert!(tbs.starts_with(b"AgentDeck/SealedBlobTbsV1"));

    // verifier Ok → 构造 Verified，且底层就是原 signed blob。
    let verified = signed.clone().verify_with(&OkVerifier, &ctx).unwrap();
    assert_eq!(verified.sealed(), &signed);

    // verifier 失败 → 透传 typed error，绝不构造 Verified。
    assert_eq!(
        signed.verify_with(&FailVerifier, &ctx).unwrap_err(),
        E2eeError::BadSenderSignature
    );
}

#[test]
fn sealed_blob_tbs_binds_context_and_ciphertext() {
    let signed = unsigned().attach_signature(sig());
    let base = signed.inner.sealed_blob_tbs(&outer_sample());

    // 不同 context（route 变化）→ 不同 TBS。
    let mut ctx2 = outer_sample();
    ctx2.machine_route = Some(MachineRouteId::from_bytes([0x99; 16]));
    assert_ne!(base, signed.inner.sealed_blob_tbs(&ctx2));

    // 不同 ciphertext → 不同 TBS（绑定 encrypted-section SHA-256）。
    let mut tampered = signed.inner.clone();
    tampered.ciphertext = vec![0xAB, 0xCD];
    assert_ne!(base, tampered.sealed_blob_tbs(&outer_sample()));
}

#[test]
fn sealed_payload_kind_names_business_payload_types() {
    // SealedPayloadV1 只出现在密文内，允许引用业务 payload 类型。
    let p = SealedPayloadV1 {
        format_version: E2EE_FORMAT_VERSION,
        payload_kind: SealedPayloadKind::ApprovalDecision,
    };
    let jv = serde_json::to_value(&p).unwrap();
    assert_eq!(jv["payloadKind"], "approvalDecision");
    let back: SealedPayloadV1 = serde_json::from_value(jv).unwrap();
    assert_eq!(back, p);
}

// —— ToBeSignedV1 确定性编码 + golden ——

fn tbs_sample() -> ToBeSignedV1 {
    ToBeSignedV1 {
        object_type: SignedObjectType::RelayGrant,
        signature_format_version: 1,
        relay_protocol_version: 2,
        runtime_protocol_version: 1,
        e2ee_format_version: 1,
        relay_server_id: rs(),
        machine_route: mr(),
        device_route: Some(dr()),
        stream_route: None,
        request_route: None,
        stream_generation: None,
        stream_cursor: None,
        role_scope: "device".into(),
        signing_key_fingerprint: [0x0F; 32],
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(3),
        serial_or_generation: 9,
        not_after_ms: None,
        signed_object_sha256: [0x0E; 32],
    }
}

#[test]
fn tbs_encoding_is_deterministic() {
    let a = tbs_sample().encode();
    let b = tbs_sample().encode();
    assert_eq!(a, b, "ToBeSignedV1 encoding must be byte-deterministic");
    // domain separator prefix present.
    assert!(a.starts_with(b"AgentDeck/ToBeSignedV1"));
}

#[test]
fn tbs_binds_object_type_and_route() {
    // 不同 object type 必须产生不同 preimage（避免跨对象重签）。
    let mut other = tbs_sample();
    other.object_type = SignedObjectType::DeviceRevocation;
    assert_ne!(tbs_sample().encode(), other.encode());
    // 不同 device route 必须产生不同 preimage。
    let mut other2 = tbs_sample();
    other2.device_route = Some(DeviceRouteId::from_bytes([0x23; 16]));
    assert_ne!(tbs_sample().encode(), other2.encode());
}

const GOLDEN_TBS: &str = "4167656e744465636b2f546f42655369676e65645631000200010002000100010000001088888888888888888888888888888888000000101111111111111111111111111111111101222222222222222222222222222222220000000000000006646576696365000000200f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f00000010777777777777777777777777777777770000000000000003000000000000000900000000200e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

#[test]
fn fixture_tbs_golden() {
    check_golden("tbs", &hex(&tbs_sample().encode()), GOLDEN_TBS);
}

// —— OuterContextV1（AAD）排除循环字段 + golden ——

fn outer_sample() -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::ConversationPublish,
        relay_protocol_version: 2,
        e2ee_format_version: 1,
        machine_route: Some(mr()),
        device_route: None,
        stream_route: Some(StreamRouteId::from_bytes([0x33; 16])),
        request_route: None,
        stream_generation: Some(StreamGenerationId::from_bytes([0x66; 16])),
        stream_cursor: Some(StreamCursor::At(7)),
        stream_seq: Some(7),
        message_key_epoch: 4,
    }
}

#[test]
fn outer_context_encoding_is_deterministic() {
    assert_eq!(outer_sample().encode_aad(), outer_sample().encode_aad());
    assert!(
        outer_sample()
            .encode_aad()
            .starts_with(b"AgentDeck/OuterContextV1")
    );
}

const GOLDEN_OUTER_CONTEXT: &str = "4167656e744465636b2f4f75746572436f6e7465787456310001000200010111111111111111111111111111111111000133333333333333333333333333333333000166666666666666666666666666666666010100000000000000070100000000000000070000000000000004";

#[test]
fn fixture_outer_context_golden() {
    check_golden(
        "outerContext",
        &hex(&outer_sample().encode_aad()),
        GOLDEN_OUTER_CONTEXT,
    );
}

// —— 三种 HPKE info：字段严格按 §7.4 + golden ——

#[test]
fn pair_request_info_excludes_unassigned_device_route_and_serial() {
    let info = PairRequestInfoV1 {
        e2ee_format_version: 1,
        runtime_protocol_version: 1,
        relay_server_id: rs(),
        pair_route: pr(),
        invite_hash: [0x01; 32],
        expiry_ms: 1_700_000_000_000,
    };
    // §7.4：PairRequestInfoV1 此时不包含尚未分配的 device route / grant serial。
    let jv = serde_json::to_value(&info).unwrap();
    assert!(jv.get("deviceRoute").is_none());
    assert!(jv.get("grantSerial").is_none());
    let _ = info.encode();
}

const GOLDEN_PAIR_REQUEST_INFO: &str = "4167656e744465636b2f5061697252657175657374496e666f56310000010001000000108888888888888888888888888888888800000010555555555555555555555555555555550000002001010101010101010101010101010101010101010101010101010101010101010000018bcfe56800";
const GOLDEN_PAIR_RESPONSE_INFO: &str = "4167656e744465636b2f50616972526573706f6e7365496e666f56310000010001000000108888888888888888888888888888888800000010555555555555555555555555555555550000002001010101010101010101010101010101010101010101010101010101010101010000002002020202020202020202020202020202020202020202020202020202020202020000001011111111111111111111111111111111000000102222222222222222222222222222222200000000000000090000000000000003";
const GOLDEN_KEY_UPDATE_INFO: &str = "4167656e744465636b2f4b6579557064617465496e666f5631000001000100000010111111111111111111111111111111110000001022222222222222222222222222222222000000000000000900000000000000030000000000000002010000000000000004";

#[test]
fn fixture_pair_request_info_golden() {
    let info = PairRequestInfoV1 {
        e2ee_format_version: 1,
        runtime_protocol_version: 1,
        relay_server_id: rs(),
        pair_route: pr(),
        invite_hash: [0x01; 32],
        expiry_ms: 1_700_000_000_000,
    };
    check_golden(
        "pairRequestInfo",
        &hex(&info.encode()),
        GOLDEN_PAIR_REQUEST_INFO,
    );
}

#[test]
fn fixture_pair_response_info_golden() {
    let info = PairResponseInfoV1 {
        e2ee_format_version: 1,
        runtime_protocol_version: 1,
        relay_server_id: rs(),
        pair_route: pr(),
        invite_hash: [0x01; 32],
        request_hash: [0x02; 32],
        machine_route: mr(),
        device_route: dr(),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
    };
    check_golden(
        "pairResponseInfo",
        &hex(&info.encode()),
        GOLDEN_PAIR_RESPONSE_INFO,
    );
}

#[test]
fn fixture_key_update_info_golden() {
    let info = KeyUpdateInfoV1 {
        e2ee_format_version: 1,
        runtime_protocol_version: 1,
        machine_route: mr(),
        device_route: dr(),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        key_directory_revision: KeyDirectoryRevision::new(2),
        key_purpose: KeyPurpose::ConversationDek,
        key_epoch: 4,
    };
    check_golden(
        "keyUpdateInfo",
        &hex(&info.encode()),
        GOLDEN_KEY_UPDATE_INFO,
    );
}

// —— 版本化 pairing / key DTO round-trip ——

fn cert() -> SignedCertificate {
    SignedCertificate {
        subject_pubkey: pk(),
        cert_role: CertRole::Data,
        generation: LinkGeneration::new(1),
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(3),
        not_after_ms: None,
        signature: sig(),
    }
}

fn relay_grant() -> RelayGrant {
    RelayGrant {
        machine_route: mr(),
        device_route: dr(),
        device_sign_pubkey: pk(),
        grant_serial: GrantSerial::new(9),
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(3),
        signature: sig(),
    }
}

fn key_directory() -> KeyDirectoryV1 {
    KeyDirectoryV1 {
        revision: KeyDirectoryRevision::new(2),
        entries: vec![KeyDirectoryEntry {
            key_id: KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 1,
            },
            device_route: dr(),
            enc: vec![0x01, 0x02],
            wrapped_key: vec![0x03, 0x04],
        }],
        signature: sig(),
    }
}

#[test]
fn pairing_dtos_round_trip() {
    let invite = PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: 2,
        pair_route: pr(),
        invite_secret: [0x10; 32],
        invite_hpke_pubkey: pk(),
        wss_url: "wss://relay.example/ws".into(),
        relay_server_id: rs(),
        current_spki_pin: [0x20; 32],
        next_spki_pin: [0x21; 32],
        expires_at_ms: 1_700_000_000_000,
        machine_root_pubkey: pk(),
        machine_root_fingerprint: [0x30; 32],
        data_sign_cert: cert(),
        machine_display_name: "Jassy MacBook".into(),
    };
    let back: PairInviteV1 =
        serde_json::from_value(serde_json::to_value(&invite).unwrap()).unwrap();
    assert_eq!(back, invite);

    let req = PairRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        invite_secret: [0x10; 32],
        device_sign_pubkey: pk(),
        device_hpke_pubkey: pk(),
        sealed_authorization_request: vec![0xAA, 0xBB],
        proof_signature: sig(),
    };
    let back: PairRequestV1 = serde_json::from_value(serde_json::to_value(&req).unwrap()).unwrap();
    assert_eq!(back, req);

    let pending = PairPendingV1 {
        request_hash: [0x02; 32],
        signature: sig(),
    };
    let back: PairPendingV1 =
        serde_json::from_value(serde_json::to_value(&pending).unwrap()).unwrap();
    assert_eq!(back, pending);

    let authz = DeviceAuthorizationV1 {
        grant_serial: GrantSerial::new(9),
        device_hpke_pubkey: pk(),
        capabilities: vec!["approval".into()],
        permissions: vec!["read".into(), "write".into()],
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(3),
        signature: sig(),
    };
    let back: DeviceAuthorizationV1 =
        serde_json::from_value(serde_json::to_value(&authz).unwrap()).unwrap();
    assert_eq!(back, authz);

    let resp = PairResponseV1 {
        request_hash: [0x02; 32],
        relay_grant: relay_grant(),
        sealed_device_authorization: vec![0xCC, 0xDD],
        key_directory: key_directory(),
        signature: sig(),
    };
    let back: PairResponseV1 =
        serde_json::from_value(serde_json::to_value(&resp).unwrap()).unwrap();
    assert_eq!(back, resp);
}

#[test]
fn pair_response_received_binds_three_hashes_and_device_sign() {
    let recv = PairResponseReceivedV1 {
        request_hash: [0x02; 32],
        grant_hash: [0x03; 32],
        response_hash: [0x04; 32],
        signature: sig(),
    };
    let jv = serde_json::to_value(&recv).unwrap();
    for key in ["requestHash", "grantHash", "responseHash", "signature"] {
        assert!(
            jv.get(key).is_some(),
            "PairResponseReceivedV1 must structurally bind `{key}`"
        );
    }
    let back: PairResponseReceivedV1 = serde_json::from_value(jv).unwrap();
    assert_eq!(back, recv);
}

#[test]
fn key_dtos_round_trip() {
    let back: KeyDirectoryV1 =
        serde_json::from_value(serde_json::to_value(key_directory()).unwrap()).unwrap();
    assert_eq!(back, key_directory());

    let update = KeyUpdateV1 {
        key_directory_revision: KeyDirectoryRevision::new(2),
        key_id: KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: 5,
        },
        device_route: dr(),
        enc: vec![0x01],
        wrapped_key: vec![0x02],
        signature: sig(),
    };
    let back: KeyUpdateV1 = serde_json::from_value(serde_json::to_value(&update).unwrap()).unwrap();
    assert_eq!(back, update);

    let barrier = EpochBarrierV1 {
        stream_generation: StreamGenerationId::from_bytes([0x66; 16]),
        stream_cursor: StreamCursor::At(9),
        event_seq: 9,
        old_epoch: 3,
        new_epoch: 4,
        key_directory_revision: KeyDirectoryRevision::new(2),
    };
    let jv = serde_json::to_value(&barrier).unwrap();
    for key in [
        "streamGeneration",
        "streamCursor",
        "eventSeq",
        "oldEpoch",
        "newEpoch",
        "keyDirectoryRevision",
    ] {
        assert!(jv.get(key).is_some(), "EpochBarrierV1 missing `{key}`");
    }
    let back: EpochBarrierV1 = serde_json::from_value(jv).unwrap();
    assert_eq!(back, barrier);
}
