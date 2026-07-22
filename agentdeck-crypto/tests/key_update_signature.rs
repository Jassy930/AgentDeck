//! P4.5 KeyUpdate canonical TBS 的真实 Ed25519 signer/verifier 接线。

use agentdeck_crypto::{
    CryptoError, Ed25519KeyUpdateSigner, Ed25519KeyUpdateVerifier, SigningKey, sha256,
    sign_key_update, verify_key_update,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, KeyUpdateInfoV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId,
    RelayServerId, StreamRouteId, TrustEpoch,
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

fn signer_for(key: &SigningKey) -> MachineDataSignerBindingV1 {
    MachineDataSignerBindingV1 {
        signing_key_fingerprint: sha256(&key.verifying_key().to_bytes()),
        generation: LinkGeneration::new(3),
        certificate_sha256: [0x71; 32],
    }
}

fn info() -> KeyUpdateInfoV1 {
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

fn context() -> OuterContextV1 {
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

fn unsigned_update() -> KeyUpdateV1 {
    KeyUpdateV1 {
        key_directory_revision: KeyDirectoryRevision::new(4),
        key_id: KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 5,
        },
        device_route: device(0x22),
        stream_route: Some(stream(0x33)),
        enc: vec![0x51; 32],
        wrapped_key: vec![0x52; 48],
        signature: Ed25519Signature([0; 64]),
    }
}

#[test]
fn key_update_uses_real_ed25519_and_rejects_tamper_or_wrong_credential() {
    let key = SigningKey::from_seed(&[0x81; 32]);
    let signer = signer_for(&key);
    let signed = sign_key_update(&key, &signer, &info(), &context(), unsigned_update()).unwrap();

    verify_key_update(&key.verifying_key(), &signer, &info(), &context(), &signed).unwrap();
    assert_ne!(signed.signature.0, [0; 64]);

    let mut tampered = signed.clone();
    tampered.wrapped_key[0] ^= 1;
    assert_eq!(
        verify_key_update(
            &key.verifying_key(),
            &signer,
            &info(),
            &context(),
            &tampered,
        ),
        Err(CryptoError::BadSignature)
    );

    let wrong_key = SigningKey::from_seed(&[0x82; 32]);
    assert!(matches!(
        verify_key_update(
            &wrong_key.verifying_key(),
            &signer,
            &info(),
            &context(),
            &signed,
        ),
        Err(CryptoError::InvalidKey(_))
    ));
    assert!(matches!(
        sign_key_update(&key, &signer, &info(), &context(), signed),
        Err(CryptoError::InvalidKey(_))
    ));
}

#[test]
fn protocol_hooks_are_bound_to_the_ed25519_key_fingerprint() {
    use agentdeck_protocol::e2ee::{KeyUpdateSignatureSigner, KeyUpdateSignatureVerifier};

    let key = SigningKey::from_seed(&[0x91; 32]);
    let signer = Ed25519KeyUpdateSigner::new(&key);
    let verifier_key = key.verifying_key();
    let verifier = Ed25519KeyUpdateVerifier::new(&verifier_key);
    let binding = signer_for(&key);
    let signed = unsigned_update()
        .sign_with(&signer, &info(), &context(), &binding)
        .unwrap();

    assert_eq!(
        signer.signing_key_fingerprint(),
        verifier.verifying_key_fingerprint()
    );
    signed
        .verify_with(&verifier, &info(), &context(), &binding)
        .unwrap();

    let mut tampered = signed;
    tampered.enc[0] ^= 1;
    assert!(
        tampered
            .verify_with(&verifier, &info(), &context(), &binding)
            .is_err()
    );
}
