//! P4.5 DeviceReplyTx counter recovery 的独立 DeviceHPKE reply 契约。

use agentdeck_protocol::e2ee::{
    DeviceKeyRecoveryInfoV1, DeviceKeyRecoveryReplyV1, E2EE_FORMAT_VERSION, KeyId, KeyPurpose,
    KeyUpdateSetV1, KeyUpdateV1, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId,
    RelayServerId, RequestRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

fn machine() -> MachineRouteId {
    MachineRouteId::from_bytes([0x11; 16])
}

fn device() -> DeviceRouteId {
    DeviceRouteId::from_bytes([0x22; 16])
}

fn request() -> RequestRouteId {
    RequestRouteId::from_bytes([0x33; 16])
}

fn signer() -> MachineDataSignerBindingV1 {
    MachineDataSignerBindingV1 {
        signing_key_fingerprint: [0x41; 32],
        generation: LinkGeneration::new(7),
        certificate_sha256: [0x42; 32],
    }
}

fn update_set() -> KeyUpdateSetV1 {
    KeyUpdateSetV1 {
        key_directory_revision: KeyDirectoryRevision::new(6),
        device_route: device(),
        updates: vec![KeyUpdateV1 {
            key_directory_revision: KeyDirectoryRevision::new(6),
            key_id: KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: 2,
            },
            device_route: device(),
            stream_route: None,
            enc: vec![0x51; 32],
            wrapped_key: vec![0x52; 48],
            signature: Ed25519Signature([0x53; 64]),
        }],
    }
}

fn info() -> DeviceKeyRecoveryInfoV1 {
    let set = update_set();
    DeviceKeyRecoveryInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        relay_server_id: RelayServerId::from_bytes([0x44; 16]),
        machine_route: machine(),
        device_route: device(),
        request_route: request(),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        known_key_directory_revision: KeyDirectoryRevision::new(5),
        target_key_directory_revision: KeyDirectoryRevision::new(6),
        update_set_sha256: set.canonical_sha256().unwrap(),
        machine_data_signer: signer(),
    }
}

fn context() -> OuterContextV1 {
    OuterContextV1::device_key_recovery(machine(), device(), request())
}

fn reply() -> DeviceKeyRecoveryReplyV1 {
    DeviceKeyRecoveryReplyV1 {
        format_version: E2EE_FORMAT_VERSION,
        info: info(),
        enc: vec![0x61; 32],
        ciphertext: vec![0x62; 96],
        machine_data_signature: Ed25519Signature([0x63; 64]),
    }
}

#[test]
fn key_recovery_info_requires_exact_next_revision_set_and_recovery_context() {
    let info = info();
    let set = update_set();
    let context = context();

    info.validate_for_update_set(&set).unwrap();
    info.validate_context(&context).unwrap();
    assert_eq!(context.frame_kind, OuterFrameKind::DeviceKeyRecovery);
    assert_eq!(context.message_key_epoch, 0);
    assert!(context.stream_route.is_none());
    assert!(context.pair_route.is_none());
    assert!(context.stream_generation.is_none());
    assert!(context.stream_cursor.is_none());
    assert!(context.stream_seq.is_none());

    let encoded = info.canonical_bytes().unwrap();
    assert_eq!(
        DeviceKeyRecoveryInfoV1::from_canonical_bytes(&encoded).unwrap(),
        info
    );

    let mut changed = info.clone();
    changed.target_key_directory_revision = KeyDirectoryRevision::new(7);
    assert!(changed.validate_for_update_set(&set).is_err());

    changed = info.clone();
    changed.update_set_sha256[0] ^= 1;
    assert!(changed.validate_for_update_set(&set).is_err());

    let mut changed_set = set.clone();
    changed_set.device_route = DeviceRouteId::from_bytes([0x23; 16]);
    assert!(info.validate_for_update_set(&changed_set).is_err());

    let mut changed_context = context.clone();
    changed_context.request_route = Some(RequestRouteId::from_bytes([0x34; 16]));
    assert!(info.validate_context(&changed_context).is_err());

    changed_context = context;
    changed_context.message_key_epoch = 1;
    assert!(info.validate_context(&changed_context).is_err());
}

#[test]
fn key_recovery_reply_canonical_tbs_binds_every_clear_and_ciphertext_axis() {
    let reply = reply();
    let context = context();
    reply.validate().unwrap();
    let tbs = reply.signature_tbs(&context, &signer()).unwrap();

    assert_eq!(tbs.e2ee_format_version, E2EE_FORMAT_VERSION);
    assert_eq!(tbs.runtime_protocol_version, RUNTIME_PROTOCOL_VERSION);
    assert_eq!(tbs.relay_protocol_version, RELAY_PROTOCOL_VERSION);
    assert_eq!(tbs.relay_server_id, info().relay_server_id);
    assert_eq!(tbs.machine_route, machine());
    assert_eq!(tbs.device_route, device());
    assert_eq!(tbs.request_route, request());
    assert_eq!(tbs.grant_serial, GrantSerial::new(9));
    assert_eq!(tbs.root_trust_epoch, TrustEpoch::new(3));
    assert_eq!(
        tbs.known_key_directory_revision,
        KeyDirectoryRevision::new(5)
    );
    assert_eq!(
        tbs.target_key_directory_revision,
        KeyDirectoryRevision::new(6)
    );
    assert_eq!(tbs.update_set_sha256, info().update_set_sha256);
    assert_eq!(tbs.machine_data_signer, signer());
    assert_eq!(tbs.enc, reply.enc);
    assert_ne!(tbs.ciphertext_sha256, [0; 32]);
    assert_ne!(tbs.outer_context_aad_sha256, [0; 32]);

    let tbs_bytes = tbs.canonical_bytes().unwrap();
    assert_eq!(
        agentdeck_protocol::e2ee::DeviceKeyRecoveryTbsV1::from_canonical_bytes(&tbs_bytes).unwrap(),
        tbs
    );
    let mut changed_tbs = tbs.clone();
    changed_tbs.request_route = RequestRouteId::from_bytes([0x35; 16]);
    assert!(changed_tbs.validate().is_err());
    changed_tbs = tbs.clone();
    changed_tbs.info_sha256[0] ^= 1;
    assert!(changed_tbs.validate().is_err());
    let canonical = reply.canonical_bytes().unwrap();
    assert_eq!(
        DeviceKeyRecoveryReplyV1::from_canonical_bytes(&canonical).unwrap(),
        reply
    );
    let mut trailing = canonical;
    trailing.push(0);
    assert!(DeviceKeyRecoveryReplyV1::from_canonical_bytes(&trailing).is_err());
}
