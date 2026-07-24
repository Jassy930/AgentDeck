//! P4.5 KeyUpdate canonical TBS 的真实 Ed25519 signer/verifier 接线。

use std::convert::Infallible;

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    AeadSendingKey, CryptoError, Ed25519KeyUpdateSigner, Ed25519KeyUpdateVerifier, HpkeEnvelopeV1,
    HpkePrivateKey, SecretAeadKey, SenderCounter, SigningKey, hpke_seal_base, open_key_update,
    seal_symmetric, sha256, sign_key_update, verify_key_update,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, KeyUpdateInfoV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, SealedPayloadKind,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId,
    RelayServerId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

struct DeterministicRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    offset: usize,
}

impl DeterministicRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0; 32],
            offset: 32,
        }
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            if self.offset == self.block.len() {
                let mut input = b"AgentDeck/KeyUpdateOpenTestRng\0".to_vec();
                input.extend_from_slice(&self.seed);
                input.extend_from_slice(&self.counter.to_be_bytes());
                self.block = sha256(&input);
                self.counter += 1;
                self.offset = 0;
            }
            *byte = self.block[self.offset];
            self.offset += 1;
        }
    }
}

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(output);
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

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

fn sealed_unsigned_update(
    recipient: &agentdeck_crypto::HpkePublicKey,
    plaintext: &[u8],
) -> KeyUpdateV1 {
    let mut rng = DeterministicRng::new([0x53; 32]);
    let sealed = hpke_seal_base(
        recipient,
        &info().encode(),
        &context().encode_aad(),
        plaintext,
        &mut rng,
    )
    .unwrap();
    let HpkeEnvelopeV1 { enc, ciphertext } = sealed;
    KeyUpdateV1 {
        enc,
        wrapped_key: ciphertext,
        ..unsigned_update()
    }
}

#[test]
fn typed_key_update_open_verifies_then_opens_exact_bound_key() {
    let signing_key = SigningKey::from_seed(&[0x41; 32]);
    let signer = signer_for(&signing_key);
    let (recipient_private, recipient_public) = HpkePrivateKey::derive_keypair(&[0x42; 32]);
    let secret = SecretAeadKey::from_bytes([0x43; 32]);
    let signed = sign_key_update(
        &signing_key,
        &signer,
        &info(),
        &context(),
        sealed_unsigned_update(&recipient_public, &[0x43; 32]),
    )
    .unwrap();

    let opened = open_key_update(
        &recipient_private,
        &signing_key.verifying_key(),
        &signer,
        &info(),
        &context(),
        &signed,
    )
    .unwrap();

    assert_eq!(
        opened.key_directory_revision(),
        KeyDirectoryRevision::new(4)
    );
    assert_eq!(
        opened.key_id(),
        KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 5,
        }
    );
    assert_eq!(opened.stream_route(), Some(stream(0x33)));
    assert!(!format!("{opened:?}").contains("43434343"));
    let opened_key = AeadSendingKey::with_derived_nonce_prefix(
        opened.key_id(),
        opened.key_id().epoch,
        opened.key_directory_revision().value(),
        opened.into_key(),
    );
    let expected_key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 5,
        },
        5,
        4,
        secret,
    );
    assert!(opened_key.matches_secret(&SecretAeadKey::from_bytes([0x43; 32])));
    assert!(!opened_key.matches_secret(&SecretAeadKey::from_bytes([0x44; 32])));
    let opened_ciphertext = seal_symmetric(
        &opened_key,
        &context(),
        SealedPayloadKind::ConversationEvent,
        b"authenticated exact-key proof",
        SenderCounter(9),
    )
    .unwrap();
    let expected_ciphertext = seal_symmetric(
        &expected_key,
        &context(),
        SealedPayloadKind::ConversationEvent,
        b"authenticated exact-key proof",
        SenderCounter(9),
    )
    .unwrap();
    assert_eq!(opened_ciphertext, expected_ciphertext);
}

#[test]
fn typed_key_update_open_rejects_bad_signature_before_hpke_and_wrong_recipient() {
    let signing_key = SigningKey::from_seed(&[0x61; 32]);
    let signer = signer_for(&signing_key);
    let (recipient_private, recipient_public) = HpkePrivateKey::derive_keypair(&[0x62; 32]);
    let (wrong_recipient, _) = HpkePrivateKey::derive_keypair(&[0x63; 32]);
    let signed = sign_key_update(
        &signing_key,
        &signer,
        &info(),
        &context(),
        sealed_unsigned_update(&recipient_public, &[0x64; 32]),
    )
    .unwrap();

    let mut doubly_tampered = signed.clone();
    doubly_tampered.signature.0[0] ^= 1;
    doubly_tampered.wrapped_key[0] ^= 1;
    assert_eq!(
        open_key_update(
            &recipient_private,
            &signing_key.verifying_key(),
            &signer,
            &info(),
            &context(),
            &doubly_tampered,
        )
        .unwrap_err(),
        CryptoError::BadSignature,
        "MachineDataSign 必须在任何 HPKE open 之前失败",
    );

    assert_eq!(
        open_key_update(
            &wrong_recipient,
            &signing_key.verifying_key(),
            &signer,
            &info(),
            &context(),
            &signed,
        )
        .unwrap_err(),
        CryptoError::BadCiphertext,
    );
    let wrong_signing_key = SigningKey::from_seed(&[0x65; 32]);
    assert!(matches!(
        open_key_update(
            &recipient_private,
            &wrong_signing_key.verifying_key(),
            &signer,
            &info(),
            &context(),
            &signed,
        ),
        Err(CryptoError::InvalidKey(_))
    ));
}

#[test]
fn typed_key_update_open_binds_exact_info_aad_and_rejects_non_32_byte_material() {
    let signing_key = SigningKey::from_seed(&[0x71; 32]);
    let signer = signer_for(&signing_key);
    let (recipient_private, recipient_public) = HpkePrivateKey::derive_keypair(&[0x72; 32]);

    let mut wrong_info = info();
    wrong_info.machine_route = machine(0x73);
    let mut wrong_context = context();
    wrong_context.machine_route = Some(machine(0x73));
    let rebound = sign_key_update(
        &signing_key,
        &signer,
        &wrong_info,
        &wrong_context,
        sealed_unsigned_update(&recipient_public, &[0x74; 32]),
    )
    .unwrap();
    assert_eq!(
        open_key_update(
            &recipient_private,
            &signing_key.verifying_key(),
            &signer,
            &wrong_info,
            &wrong_context,
            &rebound,
        )
        .unwrap_err(),
        CryptoError::BadCiphertext,
        "即使对错误 authority 重新签名，也不能打开用原 info/AAD 封装的 key",
    );

    let short = sealed_unsigned_update(&recipient_public, &[0x75; 31]);
    assert!(matches!(
        sign_key_update(&signing_key, &signer, &info(), &context(), short,),
        Err(CryptoError::InvalidPairing(_))
    ));
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
