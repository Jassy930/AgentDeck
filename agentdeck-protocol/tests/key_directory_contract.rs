//! P4.3 key-directory / key-update strict authority contract.

use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyDirectoryEntry, KeyDirectorySignatureContextV1, KeyDirectoryV1, KeyId,
    KeyPurpose, KeyUpdateInfoV1, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::StreamCursor;
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId, PairRouteId,
    RelayServerId, RequestRouteId, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

fn relay(byte: u8) -> RelayServerId {
    RelayServerId::from_bytes([byte; 16])
}

fn machine(byte: u8) -> MachineRouteId {
    MachineRouteId::from_bytes([byte; 16])
}

fn device(byte: u8) -> DeviceRouteId {
    DeviceRouteId::from_bytes([byte; 16])
}

fn stream(byte: u8) -> StreamRouteId {
    StreamRouteId::from_bytes([byte; 16])
}

fn ordered_stream(index: u16) -> StreamRouteId {
    assert_ne!(index, 0);
    let mut bytes = [0_u8; 16];
    bytes[14..].copy_from_slice(&index.to_be_bytes());
    StreamRouteId::from_bytes(bytes)
}

fn entry(
    purpose: KeyPurpose,
    epoch: u64,
    stream_route: Option<StreamRouteId>,
    material: u8,
) -> KeyDirectoryEntry {
    KeyDirectoryEntry {
        key_id: KeyId { purpose, epoch },
        device_route: device(0x22),
        stream_route,
        enc: vec![material; 32],
        wrapped_key: vec![material.wrapping_add(1); 48],
    }
}

fn bootstrap_directory() -> KeyDirectoryV1 {
    KeyDirectoryV1 {
        revision: KeyDirectoryRevision::new(1),
        entries: vec![
            entry(KeyPurpose::Catalog, 1, None, 0x31),
            entry(KeyPurpose::DeviceCommandTx, 1, None, 0x41),
            entry(KeyPurpose::DeviceReplyTx, 1, None, 0x51),
        ],
        signature: Ed25519Signature([0x61; 64]),
    }
}

fn directory_with_conversation() -> KeyDirectoryV1 {
    let mut directory = bootstrap_directory();
    directory.entries.insert(
        1,
        entry(KeyPurpose::ConversationDek, 1, Some(stream(0x33)), 0x71),
    );
    directory
}

fn initial_directory_with_conversations(count: u16) -> (KeyDirectoryV1, Vec<StreamRouteId>) {
    let routes = (1..=count).map(ordered_stream).collect::<Vec<_>>();
    let mut directory = bootstrap_directory();
    directory.entries.splice(
        1..1,
        routes
            .iter()
            .copied()
            .map(|route| entry(KeyPurpose::ConversationDek, 1, Some(route), 0x71)),
    );
    (directory, routes)
}

fn signature_context() -> KeyDirectorySignatureContextV1 {
    KeyDirectorySignatureContextV1 {
        relay_server_id: relay(0x11),
        machine_route: machine(0x12),
        device_route: device(0x22),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
    }
}

fn signer() -> MachineDataSignerBindingV1 {
    MachineDataSignerBindingV1 {
        signing_key_fingerprint: [0x81; 32],
        generation: LinkGeneration::new(3),
        certificate_sha256: [0x82; 32],
    }
}

fn key_update_info() -> KeyUpdateInfoV1 {
    KeyUpdateInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: relay(0x11),
        machine_route: machine(0x12),
        device_route: device(0x22),
        stream_route: Some(stream(0x33)),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        key_directory_revision: KeyDirectoryRevision::new(4),
        key_purpose: KeyPurpose::ConversationDek,
        key_epoch: 5,
    }
}

fn key_update_context() -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(machine(0x12)),
        device_route: Some(device(0x22)),
        stream_route: Some(stream(0x33)),
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 5,
    }
}

#[test]
fn key_directory_canonical_round_trip_and_hash_are_stable() {
    let directory = directory_with_conversation();
    directory.validate_for_device(device(0x22)).unwrap();
    let canonical = directory.canonical_bytes().unwrap();
    assert_eq!(
        KeyDirectoryV1::from_canonical_bytes(&canonical).unwrap(),
        directory
    );
    assert_eq!(
        directory.canonical_sha256().unwrap(),
        directory.canonical_sha256().unwrap()
    );
    assert_ne!(
        directory.canonical_sha256().unwrap(),
        directory.unsigned_canonical_sha256().unwrap()
    );
}

#[test]
fn bootstrap_requires_exactly_one_catalog_command_and_reply() {
    let base = bootstrap_directory();
    base.validate_bootstrap_for_device(device(0x22)).unwrap();

    for purpose in [
        KeyPurpose::Catalog,
        KeyPurpose::DeviceCommandTx,
        KeyPurpose::DeviceReplyTx,
    ] {
        let mut missing = base.clone();
        missing
            .entries
            .retain(|value| value.key_id.purpose != purpose);
        assert!(missing.validate_bootstrap_for_device(device(0x22)).is_err());

        let mut duplicate = base.clone();
        let position = duplicate
            .entries
            .iter()
            .position(|value| value.key_id.purpose == purpose)
            .unwrap();
        duplicate
            .entries
            .insert(position + 1, duplicate.entries[position].clone());
        assert!(
            duplicate
                .validate_bootstrap_for_device(device(0x22))
                .is_err()
        );
    }
}

#[test]
fn initial_directory_requires_exact_epoch_one_authenticated_conversation_routes() {
    let base = directory_with_conversation();
    base.validate_initial_directory_for_device(device(0x22), &[stream(0x33)])
        .unwrap();

    assert!(
        base.validate_initial_directory_for_device(device(0x22), &[])
            .is_err()
    );
    assert!(
        base.validate_initial_directory_for_device(device(0x22), &[stream(0x34)])
            .is_err()
    );
    assert!(
        base.validate_initial_directory_for_device(device(0x22), &[stream(0x33), stream(0x33)])
            .is_err()
    );

    let mut wrong_epoch = base.clone();
    wrong_epoch.entries[1].key_id.epoch = 2;
    assert!(
        wrong_epoch
            .validate_initial_directory_for_device(device(0x22), &[stream(0x33)])
            .is_err()
    );
    let mut wrong_command_epoch = base.clone();
    wrong_command_epoch.entries[2].key_id.epoch = 2;
    assert!(
        wrong_command_epoch
            .validate_initial_directory_for_device(device(0x22), &[stream(0x33)])
            .is_err()
    );
}

#[test]
fn initial_directory_accepts_1024_conversations_and_canonical_round_trip() {
    let (directory, routes) = initial_directory_with_conversations(1_024);
    assert_eq!(directory.entries.len(), 1_027);

    directory
        .validate_initial_directory_for_device(device(0x22), &routes)
        .unwrap();
    let canonical = directory.canonical_bytes().unwrap();
    let decoded = KeyDirectoryV1::from_canonical_bytes(&canonical).unwrap();
    assert_eq!(decoded, directory);
    decoded
        .validate_initial_directory_for_device(device(0x22), &routes)
        .unwrap();
}

#[test]
fn initial_directory_rejects_1025_conversations() {
    let (directory, routes) = initial_directory_with_conversations(1_025);
    assert_eq!(directory.entries.len(), 1_028);

    assert!(
        directory
            .validate_initial_directory_for_device(device(0x22), &routes)
            .is_err()
    );
    assert!(directory.canonical_bytes().is_err());
}

#[test]
fn directory_rejects_wrong_device_stream_semantics_order_and_lengths() {
    let mut wrong_device = bootstrap_directory();
    wrong_device.entries[1].device_route = device(0x23);
    assert!(wrong_device.validate_for_device(device(0x22)).is_err());

    let mut non_conversation_stream = bootstrap_directory();
    non_conversation_stream.entries[0].stream_route = Some(stream(0x33));
    assert!(
        non_conversation_stream
            .validate_for_device(device(0x22))
            .is_err()
    );

    let mut missing_conversation_stream = directory_with_conversation();
    missing_conversation_stream.entries[1].stream_route = None;
    assert!(
        missing_conversation_stream
            .validate_for_device(device(0x22))
            .is_err()
    );

    let mut zero_conversation_stream = directory_with_conversation();
    zero_conversation_stream.entries[1].stream_route = Some(stream(0));
    assert!(
        zero_conversation_stream
            .validate_for_device(device(0x22))
            .is_err()
    );

    let conversation_at_bootstrap = directory_with_conversation();
    assert!(
        conversation_at_bootstrap
            .validate_bootstrap_for_device(device(0x22))
            .is_err()
    );
    conversation_at_bootstrap
        .validate_for_device(device(0x22))
        .unwrap();

    let mut wrong_order = bootstrap_directory();
    wrong_order.entries.swap(0, 1);
    assert!(wrong_order.validate_for_device(device(0x22)).is_err());

    for enc_len in [0, 31, 33] {
        let mut wrong_enc = bootstrap_directory();
        wrong_enc.entries[0].enc = vec![0x31; enc_len];
        assert!(wrong_enc.validate_for_device(device(0x22)).is_err());
    }
    for wrapped_len in [0, 47, 49] {
        let mut wrong_wrapped = bootstrap_directory();
        wrong_wrapped.entries[0].wrapped_key = vec![0x32; wrapped_len];
        assert!(wrong_wrapped.validate_for_device(device(0x22)).is_err());
    }
}

#[test]
fn key_directory_tbs_binds_every_authority_axis_and_unsigned_content() {
    let directory = bootstrap_directory();
    let context = signature_context();
    let signer = signer();
    let base = directory
        .signature_tbs(&context, &signer)
        .unwrap()
        .encode()
        .unwrap();

    let mut changed_context = context.clone();
    changed_context.relay_server_id = relay(0x91);
    assert_ne!(
        base,
        directory
            .signature_tbs(&changed_context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    changed_context = context.clone();
    changed_context.machine_route = machine(0x92);
    assert_ne!(
        base,
        directory
            .signature_tbs(&changed_context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    changed_context = context.clone();
    changed_context.device_route = device(0x23);
    assert!(directory.signature_tbs(&changed_context, &signer).is_err());
    changed_context = context.clone();
    changed_context.grant_serial = GrantSerial::new(8);
    assert_ne!(
        base,
        directory
            .signature_tbs(&changed_context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    changed_context = context.clone();
    changed_context.root_trust_epoch = TrustEpoch::new(3);
    assert_ne!(
        base,
        directory
            .signature_tbs(&changed_context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );

    let mut changed_directory = directory.clone();
    changed_directory.revision = KeyDirectoryRevision::new(2);
    assert_ne!(
        base,
        changed_directory
            .signature_tbs(&context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    changed_directory = directory.clone();
    changed_directory.entries[0].wrapped_key[0] ^= 1;
    assert_ne!(
        base,
        changed_directory
            .signature_tbs(&context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );

    let mut changed_signer = signer.clone();
    changed_signer.signing_key_fingerprint[0] ^= 1;
    assert_ne!(
        base,
        directory
            .signature_tbs(&context, &changed_signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    changed_signer = signer.clone();
    changed_signer.generation = LinkGeneration::new(4);
    assert_ne!(
        base,
        directory
            .signature_tbs(&context, &changed_signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    changed_signer = signer;
    changed_signer.certificate_sha256[0] ^= 1;
    assert_ne!(
        base,
        directory
            .signature_tbs(&context, &changed_signer)
            .unwrap()
            .encode()
            .unwrap()
    );
}

#[test]
fn key_update_info_requires_exact_outer_context_and_stream_semantics() {
    let info = key_update_info();
    let context = key_update_context();
    info.validate_context(&context).unwrap();

    let mut variants = Vec::new();
    let mut value = context.clone();
    value.frame_kind = OuterFrameKind::ConversationPublish;
    variants.push(value);
    let mut value = context.clone();
    value.relay_protocol_version += 1;
    variants.push(value);
    let mut value = context.clone();
    value.e2ee_format_version += 1;
    variants.push(value);
    let mut value = context.clone();
    value.machine_route = Some(machine(0x91));
    variants.push(value);
    let mut value = context.clone();
    value.device_route = Some(device(0x92));
    variants.push(value);
    let mut value = context.clone();
    value.stream_route = Some(stream(0x93));
    variants.push(value);
    let mut value = context.clone();
    value.request_route = Some(RequestRouteId::from_bytes([0x94; 16]));
    variants.push(value);
    let mut value = context.clone();
    value.pair_route = Some(PairRouteId::from_bytes([0x95; 16]));
    variants.push(value);
    let mut value = context.clone();
    value.stream_generation = Some(StreamGenerationId::from_bytes([0x96; 16]));
    variants.push(value);
    let mut value = context.clone();
    value.stream_cursor = Some(StreamCursor::At(1));
    variants.push(value);
    let mut value = context.clone();
    value.stream_seq = Some(1);
    variants.push(value);
    let mut value = context;
    value.message_key_epoch += 1;
    variants.push(value);
    for variant in variants {
        assert!(info.validate_context(&variant).is_err());
    }

    let mut catalog = info.clone();
    catalog.key_purpose = KeyPurpose::Catalog;
    assert!(catalog.validate().is_err());
    catalog.stream_route = None;
    catalog.validate().unwrap();

    let mut conversation_without_stream = info;
    conversation_without_stream.stream_route = None;
    assert!(conversation_without_stream.validate().is_err());
}
