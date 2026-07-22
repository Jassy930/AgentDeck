//! P4.5 key-control canonical wire 与 MachineDataSign 绑定契约。

use agentdeck_protocol::e2ee::{
    CanonicalKeyUpdateTbs, DirectoryCurrentV1, E2EE_FORMAT_VERSION, EpochBarrierV1,
    KEY_CONTROL_MAX_ID_BYTES, KEY_UPDATE_SET_MAX_KEYS, KeyControlRequestV1, KeyControlV1, KeyId,
    KeyPurpose, KeySyncRequestV1, KeyUpdateAckV1, KeyUpdateInfoV1, KeyUpdateSetV1,
    KeyUpdateSignatureSigner, KeyUpdateSignatureVerifier, KeyUpdateTbsV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairingError, SealedPayloadKind,
    StreamAppliedAckV1,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::StreamCursor;
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision as RelayKeyDirectoryRevision, LinkGeneration,
    MachineRouteId, RelayServerId, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::sync::RuntimeInnerCursor;
use sha2::{Digest, Sha256};

fn relay(byte: u8) -> RelayServerId {
    RelayServerId::from_bytes([byte; 16])
}

fn machine(byte: u8) -> MachineRouteId {
    MachineRouteId::from_bytes([byte; 16])
}

fn device(byte: u8) -> DeviceRouteId {
    DeviceRouteId::from_bytes([byte; 16])
}

fn stream_from_index(index: u16) -> StreamRouteId {
    let mut bytes = [0x31; 16];
    bytes[14..].copy_from_slice(&index.to_be_bytes());
    StreamRouteId::from_bytes(bytes)
}

fn generation(byte: u8) -> StreamGenerationId {
    StreamGenerationId::from_bytes([byte; 16])
}

fn signer_binding() -> MachineDataSignerBindingV1 {
    MachineDataSignerBindingV1 {
        signing_key_fingerprint: [0x41; 32],
        generation: LinkGeneration::new(7),
        certificate_sha256: [0x42; 32],
    }
}

fn info() -> KeyUpdateInfoV1 {
    KeyUpdateInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: relay(0x11),
        machine_route: machine(0x21),
        device_route: device(0x22),
        stream_route: Some(stream_from_index(1)),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
        key_purpose: KeyPurpose::ConversationDek,
        key_epoch: 4,
    }
}

fn context() -> OuterContextV1 {
    let info = info();
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(info.machine_route),
        device_route: Some(info.device_route),
        stream_route: info.stream_route,
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: info.key_epoch,
    }
}

fn unsigned_update() -> KeyUpdateV1 {
    KeyUpdateV1 {
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
        key_id: KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 4,
        },
        device_route: device(0x22),
        stream_route: Some(stream_from_index(1)),
        enc: vec![0x51; 32],
        wrapped_key: vec![0x52; 48],
        signature: Ed25519Signature([0; 64]),
    }
}

fn digest_signature(tbs: &[u8]) -> Ed25519Signature {
    let digest: [u8; 32] = Sha256::digest(tbs).into();
    let mut signature = [0_u8; 64];
    signature[..32].copy_from_slice(&digest);
    signature[32..].copy_from_slice(&digest);
    Ed25519Signature(signature)
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct CanonicalSigner {
    fingerprint: [u8; 32],
}

impl KeyUpdateSignatureSigner for CanonicalSigner {
    fn signing_key_fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn sign_key_update_tbs(
        &self,
        canonical_tbs: CanonicalKeyUpdateTbs<'_>,
    ) -> Result<Ed25519Signature, PairingError> {
        Ok(digest_signature(canonical_tbs.as_bytes()))
    }
}

struct CanonicalVerifier {
    fingerprint: [u8; 32],
}

impl KeyUpdateSignatureVerifier for CanonicalVerifier {
    fn verifying_key_fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn verify_key_update_tbs(
        &self,
        canonical_tbs: CanonicalKeyUpdateTbs<'_>,
        signature: &Ed25519Signature,
    ) -> Result<(), PairingError> {
        if *signature == digest_signature(canonical_tbs.as_bytes()) {
            Ok(())
        } else {
            Err(PairingError::InvalidField("key update signature"))
        }
    }
}

fn sign_update(update: KeyUpdateV1) -> KeyUpdateV1 {
    let binding = signer_binding();
    update
        .sign_with(
            &CanonicalSigner {
                fingerprint: binding.signing_key_fingerprint,
            },
            &info(),
            &context(),
            &binding,
        )
        .expect("fixture update must sign")
}

fn assert_verification_fails(
    update: &KeyUpdateV1,
    info: &KeyUpdateInfoV1,
    context: &OuterContextV1,
    binding: &MachineDataSignerBindingV1,
) {
    let verifier = CanonicalVerifier {
        fingerprint: signer_binding().signing_key_fingerprint,
    };
    assert!(
        update
            .verify_with(&verifier, info, context, binding)
            .is_err(),
        "tampered trust/content axis must fail verification"
    );
}

#[test]
fn key_update_canonical_tbs_sign_and_verify_bind_every_axis() {
    let update = sign_update(unsigned_update());
    let info = info();
    let context = context();
    let binding = signer_binding();
    let verifier = CanonicalVerifier {
        fingerprint: binding.signing_key_fingerprint,
    };

    update
        .verify_with(&verifier, &info, &context, &binding)
        .expect("exact canonical binding must verify");
    let tbs = update
        .signature_tbs(&info, &context, &binding)
        .expect("TBS must be constructible");
    let encoded = tbs.encode().expect("TBS must encode");
    assert!(encoded.starts_with(b"AgentDeck/KeyUpdateTbsV1\0"));
    assert_eq!(KeyUpdateTbsV1::from_canonical_bytes(&encoded).unwrap(), tbs);

    let canonical = update.canonical_bytes().unwrap();
    assert_eq!(
        hex_sha256(&encoded),
        "35fee2ea060104d4292645859b13b1572602baca6891e2d9690fcb0331a28b3f"
    );
    assert_eq!(
        hex_sha256(&canonical),
        "503764742a10f118ef08ccf85b2015f800279f8c1ade4febba75c646fb6d140d"
    );
    assert_eq!(
        KeyUpdateV1::from_canonical_bytes(&canonical).unwrap(),
        update
    );
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(KeyUpdateV1::from_canonical_bytes(&trailing).is_err());

    let mut changed = info.clone();
    changed.e2ee_format_version += 1;
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.runtime_protocol_version += 1;
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.relay_server_id = relay(0x12);
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.machine_route = machine(0x23);
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.device_route = device(0x24);
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.grant_serial = GrantSerial::new(10);
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.root_trust_epoch = TrustEpoch::new(4);
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.key_directory_revision = RelayKeyDirectoryRevision::new(13);
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.key_purpose = KeyPurpose::Catalog;
    changed.stream_route = None;
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.key_epoch = 5;
    assert_verification_fails(&update, &changed, &context, &binding);
    changed = info.clone();
    changed.stream_route = Some(stream_from_index(2));
    assert_verification_fails(&update, &changed, &context, &binding);

    let mut changed_context = context.clone();
    changed_context.relay_protocol_version += 1;
    assert_verification_fails(&update, &info, &changed_context, &binding);
    changed_context = context.clone();
    changed_context.stream_route = Some(stream_from_index(2));
    assert_verification_fails(&update, &info, &changed_context, &binding);

    let mut changed_update = update.clone();
    changed_update.key_directory_revision = RelayKeyDirectoryRevision::new(13);
    assert_verification_fails(&changed_update, &info, &context, &binding);
    changed_update = update.clone();
    changed_update.key_id.epoch = 5;
    assert_verification_fails(&changed_update, &info, &context, &binding);
    changed_update = update.clone();
    changed_update.device_route = device(0x24);
    assert_verification_fails(&changed_update, &info, &context, &binding);
    changed_update = update.clone();
    changed_update.stream_route = Some(stream_from_index(2));
    assert_verification_fails(&changed_update, &info, &context, &binding);
    changed_update = update.clone();
    changed_update.enc[0] ^= 1;
    assert_verification_fails(&changed_update, &info, &context, &binding);
    changed_update = update.clone();
    changed_update.wrapped_key[0] ^= 1;
    assert_verification_fails(&changed_update, &info, &context, &binding);
    changed_update = update.clone();
    changed_update.signature.0[0] ^= 1;
    assert_verification_fails(&changed_update, &info, &context, &binding);

    let mut changed_binding = binding.clone();
    changed_binding.generation = LinkGeneration::new(8);
    assert_verification_fails(&update, &info, &context, &changed_binding);
    changed_binding = binding.clone();
    changed_binding.certificate_sha256[0] ^= 1;
    assert_verification_fails(&update, &info, &context, &changed_binding);
    changed_binding = binding.clone();
    changed_binding.signing_key_fingerprint[0] ^= 1;
    assert_verification_fails(&update, &info, &context, &changed_binding);

    assert!(
        unsigned_update()
            .sign_with(
                &CanonicalSigner {
                    fingerprint: [0x99; 32],
                },
                &info,
                &context,
                &binding,
            )
            .is_err(),
        "signer fingerprint must match the root-certified MachineData credential"
    );
    assert!(
        update
            .clone()
            .sign_with(
                &CanonicalSigner {
                    fingerprint: binding.signing_key_fingerprint,
                },
                &info,
                &context,
                &binding,
            )
            .is_err(),
        "an already-signed update must not be re-signed"
    );
}

fn signed_placeholder_update(
    purpose: KeyPurpose,
    epoch: u64,
    stream_route: Option<StreamRouteId>,
) -> KeyUpdateV1 {
    KeyUpdateV1 {
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
        key_id: KeyId { purpose, epoch },
        device_route: device(0x22),
        stream_route,
        enc: vec![0x61; 32],
        wrapped_key: vec![0x62; 48],
        signature: Ed25519Signature([0x63; 64]),
    }
}

fn maximal_update_set() -> KeyUpdateSetV1 {
    let mut updates = Vec::with_capacity(1_027);
    updates.push(signed_placeholder_update(KeyPurpose::Catalog, 4, None));
    for index in 0..1_024_u16 {
        updates.push(signed_placeholder_update(
            KeyPurpose::ConversationDek,
            4,
            Some(stream_from_index(index)),
        ));
    }
    updates.push(signed_placeholder_update(
        KeyPurpose::DeviceCommandTx,
        4,
        None,
    ));
    updates.push(signed_placeholder_update(
        KeyPurpose::DeviceReplyTx,
        4,
        None,
    ));
    KeyUpdateSetV1 {
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
        device_route: device(0x22),
        updates,
    }
}

#[test]
fn key_update_set_carries_all_1024_conversations_and_rejects_bound_or_order_drift() {
    let set = maximal_update_set();
    assert_eq!(set.updates.len(), 1_024 + 3);
    assert!(set.updates.len() <= KEY_UPDATE_SET_MAX_KEYS);
    set.validate()
        .expect("MVP maximum must fit in one typed set");
    let bytes = set.canonical_bytes().unwrap();
    assert!(bytes.len() < agentdeck_protocol::relay_v2::MAX_FRAME_BYTES);
    assert_eq!(KeyUpdateSetV1::from_canonical_bytes(&bytes).unwrap(), set);

    let mut too_many = set.clone();
    too_many.updates.push(signed_placeholder_update(
        KeyPurpose::DeviceReplyTx,
        5,
        None,
    ));
    assert!(too_many.validate().is_err());

    let mut duplicate = set.clone();
    duplicate.updates[2] = duplicate.updates[1].clone();
    assert!(duplicate.validate().is_err());

    let mut out_of_order = set.clone();
    out_of_order.updates.swap(1, 2);
    assert!(out_of_order.validate().is_err());
}

fn barrier() -> EpochBarrierV1 {
    EpochBarrierV1 {
        stream_generation: generation(0x71),
        stream_cursor: StreamCursor::At(40),
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("conversation-key-control"),
            cursor: StreamCursor::At(39),
        },
        old_epoch: 3,
        new_epoch: 4,
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
    }
}

#[test]
fn key_control_update_set_and_epoch_barrier_have_strict_canonical_carriers() {
    let update_control = KeyControlV1::update_set(KeyUpdateSetV1 {
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
        device_route: device(0x22),
        updates: vec![signed_placeholder_update(KeyPurpose::Catalog, 4, None)],
    });
    let update_bytes = update_control.canonical_bytes().unwrap();
    assert_eq!(
        update_control.sealed_payload_kind(),
        SealedPayloadKind::KeyUpdate
    );
    assert_eq!(
        hex_sha256(&update_bytes),
        "cfbe703b14e67da6a820fbcca39832a6f7864a668276c6158248b89087441c3b"
    );
    assert_eq!(
        KeyControlV1::from_canonical_bytes(&update_bytes).unwrap(),
        update_control
    );

    let barrier_control = KeyControlV1::epoch_barrier(stream_from_index(7), barrier());
    let barrier_bytes = barrier_control.canonical_bytes().unwrap();
    assert_eq!(
        hex_sha256(&barrier_bytes),
        "73f848b39e0845c78c1081ed437f5892dca6a52e9865505c886875f14e1cd297"
    );
    assert_eq!(
        KeyControlV1::from_canonical_bytes(&barrier_bytes).unwrap(),
        barrier_control
    );
    assert_ne!(update_bytes, barrier_bytes);

    let mut wrong_kind = barrier_bytes.clone();
    let kind_offset = b"AgentDeck/KeyControlV1\0".len();
    wrong_kind[kind_offset] = 0xff;
    assert!(KeyControlV1::from_canonical_bytes(&wrong_kind).is_err());
    let mut trailing = barrier_bytes;
    trailing.push(0);
    assert!(KeyControlV1::from_canonical_bytes(&trailing).is_err());

    let mut exhausted = barrier();
    exhausted.stream_cursor = StreamCursor::At(u64::MAX - 1);
    assert!(exhausted.validate().is_err());
    let mut skipped_epoch = barrier();
    skipped_epoch.new_epoch += 1;
    assert!(skipped_epoch.validate().is_err());
    let mut exhausted_epoch = barrier();
    exhausted_epoch.old_epoch = u64::MAX;
    exhausted_epoch.new_epoch = u64::MAX;
    assert!(exhausted_epoch.validate().is_err());

    let json = serde_json::to_value(&barrier_control).unwrap();
    assert_eq!(json["kind"], "epochBarrier");
    assert!(json.get("formatVersion").is_some());
    assert!(json.get("streamRoute").is_some());
    let mut unknown = json;
    unknown["relayOuterFamily"] = serde_json::json!("keyUpdate");
    assert!(serde_json::from_value::<KeyControlV1>(unknown).is_err());
}

#[test]
fn directory_current_is_an_authenticated_exact_next_revision_status() {
    let status = DirectoryCurrentV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: machine(0x21),
        device_route: device(0x22),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        current_key_directory_revision: RelayKeyDirectoryRevision::new(12),
        requested_key_directory_revision: RelayKeyDirectoryRevision::new(13),
    };
    let control = KeyControlV1::directory_current(status.clone());
    let canonical = control.canonical_bytes().unwrap();
    assert_eq!(control.sealed_payload_kind(), SealedPayloadKind::KeyUpdate);
    assert_eq!(
        KeyControlV1::from_canonical_bytes(&canonical).unwrap(),
        control
    );

    let json = serde_json::to_value(&control).unwrap();
    assert_eq!(json["kind"], "directoryCurrent");
    assert_eq!(json["status"]["currentKeyDirectoryRevision"], 12);
    assert_eq!(json["status"]["requestedKeyDirectoryRevision"], 13);

    let mut skipped = status.clone();
    skipped.requested_key_directory_revision = RelayKeyDirectoryRevision::new(14);
    assert!(skipped.validate().is_err());
    let mut zero_current = status;
    zero_current.current_key_directory_revision = RelayKeyDirectoryRevision::new(0);
    assert!(zero_current.validate().is_err());
}

fn key_sync_request() -> KeySyncRequestV1 {
    KeySyncRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: machine(0x21),
        device_route: device(0x22),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        known_key_directory_revision: RelayKeyDirectoryRevision::new(11),
        requested_key_directory_revision: RelayKeyDirectoryRevision::new(12),
        key_id: KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 4,
        },
        stream_route: Some(stream_from_index(1)),
        attempt: 1,
    }
}

#[test]
fn key_sync_and_authenticated_ack_dtos_are_bounded_and_canonical() {
    let request = key_sync_request();
    request.validate().unwrap();
    let request_bytes = request.canonical_bytes().unwrap();
    assert_eq!(
        hex_sha256(&request_bytes),
        "e797a13e50ef2c1802184349703da7fc00a6cb626ced5131ca4d01ea9e737fc9"
    );
    assert_eq!(
        KeySyncRequestV1::from_canonical_bytes(&request_bytes).unwrap(),
        request
    );

    let mut lower_or_equal = request.clone();
    lower_or_equal.requested_key_directory_revision = lower_or_equal.known_key_directory_revision;
    assert!(lower_or_equal.validate().is_err());
    let mut zero_attempt = request.clone();
    zero_attempt.attempt = 0;
    assert!(zero_attempt.validate().is_err());
    let mut third_attempt = request.clone();
    third_attempt.attempt = 3;
    third_attempt.validate().unwrap();
    let mut fourth_attempt = request.clone();
    fourth_attempt.attempt = 4;
    assert!(fourth_attempt.validate().is_err());
    let mut wrong_stream_shape = request.clone();
    wrong_stream_shape.stream_route = None;
    assert!(wrong_stream_shape.validate().is_err());

    let update_set = maximal_update_set();
    let update_ack = KeyUpdateAckV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: machine(0x21),
        device_route: device(0x22),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
        update_set_sha256: update_set.canonical_sha256().unwrap(),
    };
    let update_ack_bytes = update_ack.canonical_bytes().unwrap();
    assert_eq!(
        hex_sha256(&update_ack_bytes),
        "af7408747c658d05e98464ac76e10d05aaf2731d0a56118a6974b3df8702d633"
    );
    assert_eq!(
        KeyUpdateAckV1::from_canonical_bytes(&update_ack_bytes).unwrap(),
        update_ack
    );
    let mut zero_hash = update_ack.clone();
    zero_hash.update_set_sha256 = [0; 32];
    assert!(zero_hash.validate().is_err());

    let barrier = barrier();
    let applied_ack = StreamAppliedAckV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: machine(0x21),
        device_route: device(0x22),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        stream_route: stream_from_index(7),
        stream_generation: barrier.stream_generation,
        applied_stream_seq: 41,
        inner_cursor: barrier.inner_cursor.clone(),
        key_directory_revision: barrier.key_directory_revision,
        key_epoch: barrier.new_epoch,
        epoch_barrier_sha256: barrier.canonical_sha256().unwrap(),
    };
    let applied_bytes = applied_ack.canonical_bytes().unwrap();
    assert_eq!(
        hex_sha256(&applied_bytes),
        "676f0b49f1350b7329745d83d047079389abc77df6c0659f3478fea545e5e33d"
    );
    assert_eq!(
        StreamAppliedAckV1::from_canonical_bytes(&applied_bytes).unwrap(),
        applied_ack
    );
    applied_ack
        .validate_for_barrier(stream_from_index(7), &barrier)
        .unwrap();

    let uplink = [
        KeyControlRequestV1::key_sync(request.clone()),
        KeyControlRequestV1::key_update_ack(update_ack.clone()),
        KeyControlRequestV1::stream_applied_ack(applied_ack.clone()),
    ];
    let mut encoded_uplink = Vec::new();
    for control in &uplink {
        assert_eq!(control.sealed_payload_kind(), SealedPayloadKind::KeyUpdate);
        let bytes = control.canonical_bytes().unwrap();
        assert_eq!(
            KeyControlRequestV1::from_canonical_bytes(&bytes).unwrap(),
            *control
        );
        encoded_uplink.push(bytes);
    }
    assert_ne!(encoded_uplink[0], encoded_uplink[1]);
    assert_ne!(encoded_uplink[1], encoded_uplink[2]);
    assert_eq!(
        encoded_uplink
            .iter()
            .map(|bytes| hex_sha256(bytes))
            .collect::<Vec<_>>(),
        vec![
            "5a3e6faff2caf359f5ee9785c9f44d8b26af13569f513fa4b4edcfaf7145637b",
            "6f6fa6db367692363017a4acf2d484c227d39c89bcfc8bdc7d34c7cb62585e0d",
            "96b785eadd5320167bd1914d50c5fc5efa210c452f9ea58788a35827865b319b",
        ]
    );
    let kind_offset = b"AgentDeck/KeyControlRequestV1\0".len();
    let mut unknown_kind = encoded_uplink[0].clone();
    unknown_kind[kind_offset] = 0xff;
    assert!(KeyControlRequestV1::from_canonical_bytes(&unknown_kind).is_err());
    let mut trailing = encoded_uplink[2].clone();
    trailing.push(0);
    assert!(KeyControlRequestV1::from_canonical_bytes(&trailing).is_err());
    assert!(KeyControlRequestV1::from_canonical_bytes(&vec![0; 8 * 1_024 + 1]).is_err());

    let mut wrong_applied_seq = applied_ack.clone();
    wrong_applied_seq.applied_stream_seq = 40;
    assert!(
        wrong_applied_seq
            .validate_for_barrier(stream_from_index(7), &barrier)
            .is_err()
    );

    let mut oversized_id = applied_ack;
    oversized_id.inner_cursor = RuntimeInnerCursor::Conversation {
        conversation_id: ConversationId::new("x".repeat(KEY_CONTROL_MAX_ID_BYTES + 1)),
        cursor: StreamCursor::At(39),
    };
    assert!(oversized_id.validate().is_err());
}
