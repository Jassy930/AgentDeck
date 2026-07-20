//! P1.2 Relay v2 opaque contract —— types / codec / monotonic-version / id 契约。
//!
//! Relay v2 是严格最小可见的唯一生产外层路由 wire（design §10）：
//! - 128-bit 随机 route/generation ID（不可比较、不可复用）。
//! - u64 单调值（trust epoch / link generation / grant serial / key revision）到 MAX 拒绝 wrap。
//! - 30 个通用 frame family variant 的 `ADRV2` 二进制 codec round-trip + 固定字节 fixture。
//! - 公开授权对象（RelayGrant / SignedCertificate / DeviceRevocation）与 enrollment DTO。

use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, DeviceAuthorizationV1,
    E2EE_FORMAT_VERSION, EpochBarrierV1, KeyDirectoryEntry, KeyDirectoryV1, KeyId, KeyPurpose,
    KeyUpdateV1, PairInviteV1, PairPendingV1, PairRequestV1, PairResponseInfoV1,
    PairResponseReceivedV1, PairResponseV1, PairingControlEnvelopeV1, SealedPayloadKind,
    SealedPayloadV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::auth::{
    CertRole, DeviceRevocation, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::codec::{self, CodecError, MAX_FRAME_BYTES, RELAY_FRAME_MAGIC};
use agentdeck_protocol::relay_v2::enrollment::{
    EnrollmentCode, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1,
};
use agentdeck_protocol::relay_v2::failure::RELAY_REPLAY_CURSOR_INVALID;
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Ack, AuthProof, Authenticate, Authenticated, Challenge, ClosePairRoute, Gap,
    GrantCommitted, Hello, InstallGrant, OpaqueRouteFrame, OpenPairRoute, PairData,
    PairRouteCloseOutcome, PairRouteClosed, PairRouteOpened, PairingHello, Ping, Pong, Publish,
    RegisterStream, RelayFrameBody, ReplayComplete, Reply, RetireMachine, RetirementCommitted,
    RevocationCommitted, RevokeDevice, RouteAccepted, SealedBlob, Send, ServerRestarting,
    Subscribe, Unsubscribe,
};
use agentdeck_protocol::relay_v2::id::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration,
    MachineRouteId, MonotonicError, PairRouteId, RelayServerId, RequestRouteId, RootKeyId,
    StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::relay_v2::{RELAY_PROTOCOL_VERSION, StreamCursor};
use agentdeck_protocol::runtime::identity::{ConversationId, MessageId, TransferId};
use agentdeck_protocol::runtime::{
    RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, RuntimeTransferCarrierV1, RuntimeTransferChannel,
    TransferEnvelope,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn replay_cursor_invalid_failure_code_is_stable() {
    assert_eq!(RELAY_REPLAY_CURSOR_INVALID, "relay.replay.cursor_invalid");
}

fn check_golden(name: &str, actual: &str, expected: &str) {
    if expected.is_empty() {
        println!("GOLDEN {name} = {actual}");
    } else {
        assert_eq!(actual, expected, "golden `{name}` drifted");
    }
}

fn mr() -> MachineRouteId {
    MachineRouteId::from_bytes([0x11; 16])
}
fn dr() -> DeviceRouteId {
    DeviceRouteId::from_bytes([0x22; 16])
}
fn sr() -> StreamRouteId {
    StreamRouteId::from_bytes([0x33; 16])
}
fn rr() -> RequestRouteId {
    RequestRouteId::from_bytes([0x44; 16])
}
fn pr() -> PairRouteId {
    PairRouteId::from_bytes([0x55; 16])
}
fn sg() -> StreamGenerationId {
    StreamGenerationId::from_bytes([0x66; 16])
}
fn rk() -> RootKeyId {
    RootKeyId::from_bytes([0x77; 16])
}
fn rs() -> RelayServerId {
    RelayServerId::from_bytes([0x88; 16])
}
fn pk() -> PublicKeyBytes {
    PublicKeyBytes([0xA0; 32])
}
fn sig() -> Ed25519Signature {
    Ed25519Signature([0xB0; 64])
}
fn cert() -> SignedCertificate {
    SignedCertificate {
        subject_pubkey: pk(),
        cert_role: CertRole::Link,
        generation: LinkGeneration::new(7),
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(3),
        not_after_ms: None,
        signature: sig(),
    }
}
fn grant() -> RelayGrant {
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
fn revocation() -> DeviceRevocation {
    DeviceRevocation {
        machine_route: mr(),
        device_route: dr(),
        grant_serial: GrantSerial::new(9),
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(3),
        signature: sig(),
    }
}
fn retirement() -> RetireMachine {
    RetireMachine {
        machine_route: mr(),
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(4),
        signature: sig(),
    }
}
fn blob() -> SealedBlob {
    SealedBlob(vec![0xDE, 0xAD, 0xBE, 0xEF])
}

fn data_cert() -> SignedCertificate {
    SignedCertificate {
        cert_role: CertRole::Data,
        ..cert()
    }
}

fn key_directory() -> KeyDirectoryV1 {
    KeyDirectoryV1 {
        revision: KeyDirectoryRevision::new(2),
        entries: vec![KeyDirectoryEntry {
            key_id: KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: 4,
            },
            device_route: dr(),
            stream_route: Some(sr()),
            enc: vec![0xC1, 0xC2],
            wrapped_key: vec![0xD1, 0xD2, 0xD3],
        }],
        signature: sig(),
    }
}

fn pair_response_info() -> PairResponseInfoV1 {
    PairResponseInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: rs(),
        pair_route: pr(),
        invite_hash: [0x01; 32],
        expiry_ms: 1_700_000_300_000,
        request_hash: [0x31; 32],
        machine_route: mr(),
        device_route: dr(),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
    }
}

/// 每个 frame family 至少一个代表帧，按 RelayFrameBody 定义顺序覆盖全部 30 variant。
fn all_bodies() -> Vec<RelayFrameBody> {
    vec![
        // Handshake
        RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        }),
        RelayFrameBody::Challenge(Challenge {
            relay_server_id: rs(),
            connection_instance: ConnectionInstanceId::from_bytes([0x99; 16]),
            challenge_nonce: [0x01; 32],
        }),
        RelayFrameBody::Authenticate(Authenticate {
            proof: AuthProof::Device {
                relay_grant: grant(),
            },
            signature: sig(),
        }),
        RelayFrameBody::Authenticated(Authenticated {
            heartbeat_interval_secs: 20,
        }),
        // Pairing
        RelayFrameBody::OpenPairRoute(OpenPairRoute {
            machine_route: mr(),
            pair_route: pr(),
            absolute_expiry_ms: 1_700_000_000_000,
        }),
        RelayFrameBody::PairRouteOpened(PairRouteOpened {
            machine_route: mr(),
            pair_route: pr(),
            absolute_expiry_ms: 1_700_000_000_000,
        }),
        RelayFrameBody::PairData(PairData {
            pair_route: pr(),
            sealed_blob: blob(),
        }),
        RelayFrameBody::ClosePairRoute(ClosePairRoute {
            machine_route: mr(),
            pair_route: pr(),
        }),
        RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route: pr(),
            outcome: PairRouteCloseOutcome::Closed,
        }),
        // Stream
        RelayFrameBody::RegisterStream(RegisterStream {
            machine_route: mr(),
            stream_route: sr(),
            generation: sg(),
        }),
        RelayFrameBody::Publish(Publish {
            stream_route: sr(),
            generation: sg(),
            stream_seq: 0,
            sealed_blob: blob(),
        }),
        RelayFrameBody::Subscribe(Subscribe {
            stream_route: sr(),
            generation: sg(),
            cursor: StreamCursor::BeforeFirst,
        }),
        RelayFrameBody::Unsubscribe(Unsubscribe {
            stream_route: sr(),
            generation: sg(),
        }),
        RelayFrameBody::Ack(Ack {
            stream_route: sr(),
            generation: sg(),
            up_to_seq: 5,
        }),
        RelayFrameBody::Gap(Gap {
            stream_route: sr(),
            generation: sg(),
            need_stream_seq: 3,
            oldest_stream_seq: 7,
        }),
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: sr(),
            generation: sg(),
            current_cursor: StreamCursor::At(42),
        }),
        // Request
        RelayFrameBody::Send(Send {
            device_route: dr(),
            request_route: rr(),
            sealed_blob: blob(),
        }),
        RelayFrameBody::Reply(Reply {
            device_route: dr(),
            request_route: rr(),
            sealed_blob: blob(),
        }),
        // Auth control
        RelayFrameBody::InstallGrant(InstallGrant { grant: grant() }),
        RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: dr(),
            grant_serial: GrantSerial::new(9),
            grant_hash: [0x0C; 32],
        }),
        RelayFrameBody::RevokeDevice(RevokeDevice {
            revocation: revocation(),
        }),
        RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: dr(),
            grant_serial: GrantSerial::new(9),
            signed_revocation: revocation(),
        }),
        RelayFrameBody::RetireMachine(retirement()),
        RelayFrameBody::RetirementCommitted(RetirementCommitted {
            machine_route: mr(),
            trust_epoch: TrustEpoch::new(4),
            retire_hash: retirement().canonical_sha256(),
        }),
        // Runtime
        RelayFrameBody::Ping(Ping {
            nonce: 0x0102030405060708,
        }),
        RelayFrameBody::Pong(Pong {
            nonce: 0x0102030405060708,
        }),
        RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::Request {
                request_route: rr(),
            },
        }),
        RelayFrameBody::Error(agentdeck_protocol::relay_v2::failure::RelayFailure::new(
            agentdeck_protocol::relay_v2::failure::RELAY_ROUTE_NOT_FOUND,
            "no such route",
        )),
        RelayFrameBody::ServerRestarting(ServerRestarting {
            drain_deadline_ms: 5000,
        }),
        // P2.6 追加，既有 0..=28 kind 不移动；TLS 后配对 route 不进入 URL/query。
        RelayFrameBody::PairingHello(PairingHello {
            relay_server_id: rs(),
            pair_route: pr(),
        }),
    ]
}

fn relay_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol/agentdeck/fixtures/relay-v2-wire-vectors.json")
}

fn outer_family(kind: u16) -> &'static str {
    match kind {
        0..=3 => "handshake",
        4..=8 | 29 => "pairing",
        9..=15 => "stream",
        16..=17 => "request",
        18..=22 | 28 => "authControl",
        23..=27 => "runtime",
        _ => unreachable!("all_bodies only contains known Relay v2 kinds"),
    }
}

fn endpoint_wire_vectors() -> Vec<serde_json::Value> {
    let pair_invite = PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        pair_route: pr(),
        invite_secret: [0x01; 32],
        invite_hpke_pubkey: PublicKeyBytes([0x02; 32]),
        wss_url: "wss://relay.example.test/".into(),
        relay_server_id: rs(),
        current_spki_pin: [0x03; 32],
        next_spki_pin: [0x04; 32],
        expires_at_ms: 1_700_000_300_000,
        machine_root_pubkey: PublicKeyBytes([0x05; 32]),
        machine_root_fingerprint: Sha256::digest([0x05; 32]).into(),
        data_sign_cert: data_cert(),
        machine_display_name: "Fixture Machine".into(),
    };
    let pair_request = PairRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        enc: vec![0x07; 32],
        ciphertext: vec![0x09, 0x0A, 0x0B],
        device_proof_signature: sig(),
    };
    let relay_grant = grant();
    let authorization = DeviceAuthorizationV1 {
        format_version: E2EE_FORMAT_VERSION,
        grant_hash: relay_grant.canonical_sha256(),
        machine_route: relay_grant.machine_route,
        device_route: relay_grant.device_route,
        device_sign_fingerprint: Sha256::digest(relay_grant.device_sign_pubkey.0).into(),
        grant_serial: GrantSerial::new(9),
        device_hpke_pubkey: PublicKeyBytes([0x08; 32]),
        capabilities: vec![AuthorizationCapabilityV1::Approval],
        permissions: vec![AuthorizationPermissionV1::ApprovalResolve],
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(3),
        signature: sig(),
    };
    let directory = key_directory();
    let pair_response = PairResponseV1 {
        format_version: E2EE_FORMAT_VERSION,
        info: pair_response_info(),
        enc: vec![0x0C; 32],
        ciphertext: vec![0x0D, 0x0E],
        machine_data_signature: sig(),
    };
    let pair_pending = PairPendingV1 {
        request_hash: [0x31; 32],
        signature: sig(),
    };
    let pair_response_received = PairResponseReceivedV1 {
        request_hash: [0x31; 32],
        grant_hash: [0x32; 32],
        response_hash: [0x33; 32],
        signature: sig(),
    };
    let pairing_control_envelope = PairingControlEnvelopeV1 {
        format_version: E2EE_FORMAT_VERSION,
        enc: vec![0x34; 32],
        ciphertext: vec![0x35; 80],
    };
    let key_update = KeyUpdateV1 {
        key_directory_revision: KeyDirectoryRevision::new(3),
        key_id: KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: 5,
        },
        device_route: dr(),
        stream_route: None,
        enc: vec![0x0F, 0x10],
        wrapped_key: vec![0x11, 0x12, 0x13],
        signature: sig(),
    };
    let barrier = EpochBarrierV1 {
        stream_generation: sg(),
        stream_cursor: StreamCursor::At(42),
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("conversation-epoch-barrier"),
            cursor: StreamCursor::At(41),
        },
        old_epoch: 4,
        new_epoch: 5,
        key_directory_revision: KeyDirectoryRevision::new(3),
    };
    let sealed_payload = SealedPayloadV1 {
        format_version: E2EE_FORMAT_VERSION,
        payload_kind: SealedPayloadKind::ConversationEvent,
        payload: vec![0xCA, 0xFE],
    };

    vec![
        serde_json::json!({
            "case": "pairInvite",
            "wireType": "PairInviteV1",
            "value": serde_json::to_value(pair_invite).unwrap(),
        }),
        serde_json::json!({
            "case": "pairRequest",
            "wireType": "PairRequestV1",
            "value": serde_json::to_value(pair_request).unwrap(),
        }),
        serde_json::json!({
            "case": "pairResponse",
            "wireType": "PairResponseV1",
            "value": serde_json::to_value(pair_response).unwrap(),
        }),
        serde_json::json!({
            "case": "pairPending",
            "wireType": "PairPendingV1",
            "value": serde_json::to_value(pair_pending).unwrap(),
        }),
        serde_json::json!({
            "case": "pairingControlEnvelope",
            "wireType": "PairingControlEnvelopeV1",
            "value": serde_json::to_value(pairing_control_envelope).unwrap(),
        }),
        serde_json::json!({
            "case": "pairResponseReceived",
            "wireType": "PairResponseReceivedV1",
            "value": serde_json::to_value(pair_response_received).unwrap(),
        }),
        serde_json::json!({
            "case": "deviceAuthorization",
            "wireType": "DeviceAuthorizationV1",
            "value": serde_json::to_value(authorization).unwrap(),
        }),
        serde_json::json!({
            "case": "keyDirectory",
            "wireType": "KeyDirectoryV1",
            "value": serde_json::to_value(directory).unwrap(),
        }),
        serde_json::json!({
            "case": "keyUpdate",
            "wireType": "KeyUpdateV1",
            "value": serde_json::to_value(key_update).unwrap(),
        }),
        serde_json::json!({
            "case": "epochBarrier",
            "wireType": "EpochBarrierV1",
            "value": serde_json::to_value(barrier).unwrap(),
        }),
        serde_json::json!({
            "case": "sealedPayload",
            "wireType": "SealedPayloadV1",
            "value": serde_json::to_value(sealed_payload).unwrap(),
        }),
        serde_json::json!({
            "case": "sealedPayloadTransferPart",
            "wireType": "SealedPayloadV1",
            "value": serde_json::to_value(SealedPayloadV1 {
                format_version: E2EE_FORMAT_VERSION,
                payload_kind: SealedPayloadKind::TransferPart,
                payload: b"ADRT1".to_vec(),
            }).unwrap(),
        }),
    ]
}

fn render_relay_v2_wire_vectors() -> String {
    let outer_frames = all_bodies()
        .into_iter()
        .map(|body| {
            let kind = body.kind();
            let frame = OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body,
            };
            let input = serde_json::to_value(&frame).expect("outer frame must serialize");
            let case = input["body"]["frameKind"]
                .as_str()
                .expect("RelayFrameBody must expose frameKind");
            serde_json::json!({
                "case": case,
                "family": outer_family(kind),
                "kind": kind,
                "input": input,
                "expectedHex": hex(&codec::encode(&frame)),
            })
        })
        .collect::<Vec<_>>();
    let document = serde_json::json!({
        "fixtureFormatVersion": 1,
        "relayProtocolVersion": RELAY_PROTOCOL_VERSION,
        "runtimeProtocolVersion": RUNTIME_PROTOCOL_VERSION,
        "outerFrames": outer_frames,
        "endpointTypes": endpoint_wire_vectors(),
    });
    let mut output = serde_json::to_string_pretty(&document).expect("fixture must serialize");
    output.push('\n');
    output
}

#[test]
fn relay_v2_wire_fixture_is_rust_produced_and_in_sync() {
    let expected = render_relay_v2_wire_vectors();
    let path = relay_fixture_path();
    if std::env::var("UPDATE_WIRE_FIXTURES").as_deref() == Ok("1") {
        fs::create_dir_all(path.parent().expect("relay fixture has parent directory"))
            .expect("create relay fixture directory");
        fs::write(&path, expected.as_bytes()).expect("write Relay v2 wire fixture");
    }
    let committed = fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "read committed relay fixture {}: {error}; run with UPDATE_WIRE_FIXTURES=1",
            path.display()
        )
    });
    assert_eq!(
        committed,
        expected.as_bytes(),
        "Relay v2 fixture drifted; review Rust DTO/codec changes and regenerate with UPDATE_WIRE_FIXTURES=1"
    );
}

#[test]
fn relay_protocol_version_is_two_and_independent() {
    assert_eq!(RELAY_PROTOCOL_VERSION, 2);
    assert_eq!(E2EE_FORMAT_VERSION, 1);
    // 版本轴彼此独立：local IPC=2、Relay=2、Runtime=4、E2EE=1。
    assert_eq!(agentdeck_protocol::PROTOCOL_VERSION, 2);
    assert_eq!(RUNTIME_PROTOCOL_VERSION, 4);
}

#[test]
fn all_thirty_variants_covered_with_unique_kinds() {
    let bodies = all_bodies();
    assert_eq!(
        bodies.len(),
        30,
        "P2.6 contract lists exactly 30 RelayFrameBody variants"
    );
    let kinds: BTreeSet<u16> = bodies.iter().map(|b| b.kind()).collect();
    assert_eq!(
        kinds.len(),
        30,
        "every variant must map to a distinct codec kind"
    );
    assert_eq!(
        RelayFrameBody::RetirementCommitted(RetirementCommitted {
            machine_route: mr(),
            trust_epoch: TrustEpoch::new(4),
            retire_hash: retirement().canonical_sha256(),
        })
        .kind(),
        28,
        "RetirementCommitted is appended so frozen kinds 0..=27 never move"
    );
    assert_eq!(RelayFrameBody::Ping(Ping { nonce: 1 }).kind(), 23);
    assert_eq!(
        RelayFrameBody::ServerRestarting(ServerRestarting {
            drain_deadline_ms: 1,
        })
        .kind(),
        27
    );
    assert_eq!(
        RelayFrameBody::PairingHello(PairingHello {
            relay_server_id: rs(),
            pair_route: pr(),
        })
        .kind(),
        29,
        "PairingHello is appended so frozen kinds 0..=28 never move"
    );
}

#[test]
fn every_variant_round_trips_through_binary_codec() {
    for body in all_bodies() {
        let frame = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body,
        };
        let bytes = codec::encode(&frame);
        assert!(
            bytes.starts_with(RELAY_FRAME_MAGIC),
            "frame must start with ADRV2 magic"
        );
        // version big-endian right after magic
        assert_eq!(&bytes[5..7], &2u16.to_be_bytes());
        let back = codec::decode(&bytes).expect("decode must succeed");
        assert_eq!(back, frame, "binary codec must be a lossless round trip");
    }
}

#[test]
fn codec_rejects_oversize_before_parsing_any_field() {
    // 4 MiB + 1 必须在读取 magic/version/kind 之前被拒绝。
    let too_big = vec![0u8; MAX_FRAME_BYTES + 1];
    let err = codec::decode(&too_big).unwrap_err();
    assert_eq!(err, CodecError::Oversize);
    // 注意：即便 magic 错误也应先命中 oversize（解析前）。
}

#[test]
fn full_frame_with_3_5_mib_part_stays_within_4_mib() {
    let part = vec![0x5A; 3_670_016]; // 3.5 MiB
    let transfer = TransferEnvelope::new(
        TransferId::new("transfer-max-remote"),
        0,
        1,
        Sha256::digest(&part).into(),
        part.len() as u64,
        part,
    )
    .expect("remote raw part is within 3.5 MiB limit");
    let carrier = RuntimeTransferCarrierV1::new(
        MessageId::new("message-max-remote"),
        RuntimeTransferChannel::Stream,
        transfer,
    )
    .encode()
    .expect("compact carrier must fit");
    let mut ciphertext = SealedPayloadV1::new(SealedPayloadKind::TransferPart, carrier)
        .to_plaintext_bytes()
        .expect("inner sealed payload must encode");
    ciphertext.extend_from_slice(&[0_u8; 16]); // AEAD tag overhead
    let sealed = UnsignedSealedBlobV1::new(
        KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 1,
        },
        1,
        1,
        [0_u8; 12],
        ciphertext,
    )
    .attach_signature(sig())
    .to_wire_bytes();
    let frame = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Publish(Publish {
            stream_route: sr(),
            generation: sg(),
            stream_seq: 1,
            sealed_blob: SealedBlob(sealed),
        }),
    };
    let bytes = codec::encode(&frame);
    assert!(
        bytes.len() <= MAX_FRAME_BYTES,
        "3.5 MiB part + outer overhead must fit in 4 MiB (got {})",
        bytes.len()
    );
    let back = codec::decode(&bytes).expect("must decode within limit");
    assert_eq!(back, frame);
}

#[test]
fn bad_frame_corpus_all_typed_no_panic() {
    let good = codec::encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Ping(Ping { nonce: 1 }),
    });

    // truncated
    assert!(codec::decode(&good[..good.len() - 1]).is_err());
    // wrong magic
    let mut bad_magic = good.clone();
    bad_magic[0] = b'X';
    assert_eq!(codec::decode(&bad_magic).unwrap_err(), CodecError::BadMagic);
    // unknown version
    let mut bad_ver = good.clone();
    bad_ver[5] = 0x00;
    bad_ver[6] = 0x09;
    assert_eq!(
        codec::decode(&bad_ver).unwrap_err(),
        CodecError::UnsupportedVersion(9)
    );
    // unknown kind
    let mut bad_kind = good.clone();
    bad_kind[7] = 0xFF;
    bad_kind[8] = 0xFF;
    assert_eq!(
        codec::decode(&bad_kind).unwrap_err(),
        CodecError::UnknownKind(0xFFFF)
    );
    // trailing bytes
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert_eq!(
        codec::decode(&trailing).unwrap_err(),
        CodecError::TrailingBytes
    );
    // length-prefix out of bounds: craft a PairData whose blob length prefix lies.
    let pd = codec::encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(PairData {
            pair_route: pr(),
            sealed_blob: SealedBlob(vec![1, 2, 3, 4]),
        }),
    });
    // last 4 payload bytes are blob content; corrupt the u32 length prefix to huge.
    let mut oob = pd.clone();
    let n = oob.len();
    // blob = 4-byte len prefix + 4 bytes content at the tail.
    oob[n - 8] = 0xFF;
    oob[n - 7] = 0xFF;
    oob[n - 6] = 0xFF;
    oob[n - 5] = 0xFF;
    assert_eq!(
        codec::decode(&oob).unwrap_err(),
        CodecError::LengthOutOfBounds
    );
}

#[test]
fn empty_input_is_short_input() {
    assert_eq!(codec::decode(&[]).unwrap_err(), CodecError::ShortInput);
}

// —— 128-bit 随机 ID：相等/哈希可用、随机不同、base64 wire round-trip ——

#[test]
fn random_route_ids_are_distinct_and_hashable() {
    let a = MachineRouteId::random();
    let b = MachineRouteId::random();
    assert_ne!(a, b, "two random 128-bit ids should not collide");
    let mut set = BTreeSet::new();
    // Eq + Hash 用于去重（不依赖 Ord 比较大小）。
    set.insert(hex(a.as_bytes()));
    set.insert(hex(b.as_bytes()));
    assert_eq!(set.len(), 2);
}

#[test]
fn route_id_json_wire_round_trips() {
    let id = StreamGenerationId::from_bytes([0xAB; 16]);
    let json = serde_json::to_value(id).unwrap();
    assert!(
        json.is_string(),
        "128-bit id encodes as a single wire string"
    );
    let back: StreamGenerationId = serde_json::from_value(json).unwrap();
    assert_eq!(back, id);
}

// —— u64 单调值：到 MAX 拒绝 wrap ——

#[test]
fn monotonic_values_reject_wrap_at_max() {
    for at_max_next in [
        TrustEpoch::new(u64::MAX).next().err(),
        LinkGeneration::new(u64::MAX).next().err(),
        GrantSerial::new(u64::MAX).next().err(),
        KeyDirectoryRevision::new(u64::MAX).next().err(),
    ] {
        assert_eq!(
            at_max_next,
            Some(MonotonicError::Exhausted),
            "monotonic counter must refuse to wrap and demand reset/rekey"
        );
    }
    assert_eq!(TrustEpoch::new(3).next().unwrap(), TrustEpoch::new(4));
    assert!(TrustEpoch::new(3).accepts_higher(&TrustEpoch::new(4)));
    assert!(!TrustEpoch::new(4).accepts_higher(&TrustEpoch::new(4)));
}

// —— 公开授权对象 & enrollment DTO ——

#[test]
fn public_grant_cert_revocation_round_trip_json() {
    for v in [
        serde_json::to_value(grant()).unwrap(),
        serde_json::to_value(cert()).unwrap(),
        serde_json::to_value(revocation()).unwrap(),
    ] {
        assert!(v.is_object());
    }
    let g: RelayGrant = serde_json::from_value(serde_json::to_value(grant()).unwrap()).unwrap();
    assert_eq!(g, grant());
    let c: SignedCertificate =
        serde_json::from_value(serde_json::to_value(cert()).unwrap()).unwrap();
    assert_eq!(c, cert());
    let r: DeviceRevocation =
        serde_json::from_value(serde_json::to_value(revocation()).unwrap()).unwrap();
    assert_eq!(r, revocation());
}

#[test]
fn enrollment_request_and_response_have_exact_fields() {
    let req = MachineEnrollmentRequestV1 {
        code: EnrollmentCode([0x01; 32]),
        machine_route: mr(),
        root_pubkey: pk(),
        link_cert: cert(),
        data_cert: SignedCertificate {
            cert_role: CertRole::Data,
            ..cert()
        },
    };
    let jv = serde_json::to_value(&req).unwrap();
    for key in ["code", "machineRoute", "rootPubkey", "linkCert", "dataCert"] {
        assert!(jv.get(key).is_some(), "enrollment request missing `{key}`");
    }
    let back: MachineEnrollmentRequestV1 = serde_json::from_value(jv).unwrap();
    assert_eq!(back, req);

    let resp = MachineEnrollmentResponseV1 {
        relay_server_id: rs(),
        machine_route: mr(),
        trust_epoch: 3,
        receipt_hash: [0x0D; 32],
    };
    let jv = serde_json::to_value(&resp).unwrap();
    for key in ["relayServerId", "machineRoute", "trustEpoch", "receiptHash"] {
        assert!(jv.get(key).is_some(), "enrollment response missing `{key}`");
    }
    let back: MachineEnrollmentResponseV1 = serde_json::from_value(jv).unwrap();
    assert_eq!(back, resp);
}

#[test]
fn enrollment_request_has_independent_canonical_bytes_and_redacted_debug() {
    let request = MachineEnrollmentRequestV1 {
        code: EnrollmentCode([0x01; 32]),
        machine_route: mr(),
        root_pubkey: pk(),
        link_cert: cert(),
        data_cert: SignedCertificate {
            cert_role: CertRole::Data,
            ..cert()
        },
    };
    let canonical = request.canonical_bytes();
    assert_eq!(canonical.len(), 565);
    assert_eq!(
        hex(&request.canonical_sha256()),
        "a863fa934c79e81f6e84a9376af41afb15983211d19651e0535c187fe19bae4c",
        "deterministic enrollment request hash golden drifted"
    );
    assert_eq!(request.canonical_sha256(), request.canonical_sha256());

    let mut changed = request.clone();
    changed.machine_route = MachineRouteId::from_bytes([0x12; 16]);
    assert_ne!(changed.canonical_sha256(), request.canonical_sha256());
    changed = request.clone();
    changed.code = EnrollmentCode([0x02; 32]);
    assert_ne!(changed.canonical_sha256(), request.canonical_sha256());
    changed = request.clone();
    changed.root_pubkey = PublicKeyBytes([0x03; 32]);
    assert_ne!(changed.canonical_sha256(), request.canonical_sha256());
    changed = request.clone();
    changed.link_cert.signature = Ed25519Signature([0x04; 64]);
    assert_ne!(changed.canonical_sha256(), request.canonical_sha256());
    changed = request.clone();
    changed.data_cert.signature = Ed25519Signature([0x05; 64]);
    assert_ne!(changed.canonical_sha256(), request.canonical_sha256());

    let debug = format!("{request:?}");
    assert!(!debug.contains("1, 1, 1"));
    assert!(!debug.contains("machine_route"));
    assert!(format!("{:?}", request.code).contains("redacted"));
}

// —— 每个 family 的固定字节 fixture（为 P1.7 Swift 逐字节镜像准备）——

const GOLDEN_HELLO: &str = "4144525632000200000002";
const GOLDEN_CHALLENGE: &str = "41445256320002000188888888888888888888888888888888999999999999999999999999999999990101010101010101010101010101010101010101010101010101010101010101";
const GOLDEN_PAIRDATA: &str = "4144525632000200065555555555555555555555555555555500000004deadbeef";
const GOLDEN_PUBLISH: &str = "41445256320002000a3333333333333333333333333333333366666666666666666666666666666666000000000000000000000004deadbeef";
const GOLDEN_SEND: &str = "414452563200020010222222222222222222222222222222224444444444444444444444444444444400000004deadbeef";
const GOLDEN_INSTALL_GRANT: &str = "4144525632000200121111111111111111111111111111111122222222222222222222222222222222a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000000000000009777777777777777777777777777777770000000000000003b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";
const GOLDEN_RETIREMENT_COMMITTED: &str = "41445256320002001c111111111111111111111111111111110000000000000004251660b89c346510f961d588109a333495af462064cb7557b35ed2ebecb5e9a4";
const GOLDEN_PAIRING_HELLO: &str =
    "41445256320002001d8888888888888888888888888888888855555555555555555555555555555555";
const GOLDEN_PING: &str = "4144525632000200170102030405060708";

fn encode_hex(body: RelayFrameBody) -> String {
    hex(&codec::encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    }))
}

#[test]
fn fixture_handshake_hello() {
    check_golden(
        "hello",
        &encode_hex(RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        })),
        GOLDEN_HELLO,
    );
}

#[test]
fn fixture_handshake_challenge() {
    check_golden(
        "challenge",
        &encode_hex(RelayFrameBody::Challenge(Challenge {
            relay_server_id: rs(),
            connection_instance: ConnectionInstanceId::from_bytes([0x99; 16]),
            challenge_nonce: [0x01; 32],
        })),
        GOLDEN_CHALLENGE,
    );
}

#[test]
fn fixture_pairing_pairdata() {
    check_golden(
        "pairData",
        &encode_hex(RelayFrameBody::PairData(PairData {
            pair_route: pr(),
            sealed_blob: blob(),
        })),
        GOLDEN_PAIRDATA,
    );
}

#[test]
fn fixture_pairing_hello() {
    check_golden(
        "pairingHello",
        &encode_hex(RelayFrameBody::PairingHello(PairingHello {
            relay_server_id: rs(),
            pair_route: pr(),
        })),
        GOLDEN_PAIRING_HELLO,
    );
}

#[test]
fn pairing_hello_debug_never_exposes_raw_route_or_server_id() {
    let rendered = format!(
        "{:?}",
        PairingHello {
            relay_server_id: rs(),
            pair_route: pr(),
        }
    );
    assert!(!rendered.contains(&format!("{:?}", [0x88_u8; 16])));
    assert!(!rendered.contains(&format!("{:?}", [0x55_u8; 16])));
    assert!(!rendered.contains("iIiIiIiIiIiIiIiIiIiIiA=="));
    assert!(!rendered.contains("VVVVVVVVVVVVVVVVVVVVVQ=="));
}

#[test]
fn fixture_stream_publish() {
    check_golden(
        "publish",
        &encode_hex(RelayFrameBody::Publish(Publish {
            stream_route: sr(),
            generation: sg(),
            stream_seq: 0,
            sealed_blob: blob(),
        })),
        GOLDEN_PUBLISH,
    );
}

#[test]
fn fixture_request_send() {
    check_golden(
        "send",
        &encode_hex(RelayFrameBody::Send(Send {
            device_route: dr(),
            request_route: rr(),
            sealed_blob: blob(),
        })),
        GOLDEN_SEND,
    );
}

#[test]
fn fixture_auth_control_install_grant() {
    check_golden(
        "installGrant",
        &encode_hex(RelayFrameBody::InstallGrant(InstallGrant {
            grant: grant(),
        })),
        GOLDEN_INSTALL_GRANT,
    );
}

#[test]
fn fixture_auth_control_retirement_committed() {
    check_golden(
        "retirementCommitted",
        &encode_hex(RelayFrameBody::RetirementCommitted(RetirementCommitted {
            machine_route: mr(),
            trust_epoch: TrustEpoch::new(4),
            retire_hash: retirement().canonical_sha256(),
        })),
        GOLDEN_RETIREMENT_COMMITTED,
    );
}

#[test]
fn fixture_runtime_ping() {
    check_golden(
        "ping",
        &encode_hex(RelayFrameBody::Ping(Ping {
            nonce: 0x0102030405060708,
        })),
        GOLDEN_PING,
    );
}
