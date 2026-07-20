//! P4.3 key-directory typed signing and HPKE wrap authority tests.

use std::convert::Infallible;

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    CryptoError, HpkePrivateKey, SecretAeadKey, SigningKey, open_key_directory_entry,
    seal_key_directory_entry, sha256, sign_key_directory, verify_key_directory,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyDirectoryEntry, KeyDirectorySignatureContextV1, KeyDirectoryV1, KeyId,
    KeyPurpose, KeyUpdateInfoV1, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
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
                let mut input = b"AgentDeck/KeyDirectoryCryptoTestRng\0".to_vec();
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

fn entry(purpose: KeyPurpose, material: u8) -> KeyDirectoryEntry {
    KeyDirectoryEntry {
        key_id: KeyId { purpose, epoch: 1 },
        device_route: device(0x22),
        stream_route: None,
        enc: vec![material; 32],
        wrapped_key: vec![material.wrapping_add(1); 48],
    }
}

fn unsigned_bootstrap() -> KeyDirectoryV1 {
    KeyDirectoryV1 {
        revision: KeyDirectoryRevision::new(1),
        entries: vec![
            entry(KeyPurpose::Catalog, 0x31),
            entry(KeyPurpose::DeviceCommandTx, 0x41),
            entry(KeyPurpose::DeviceReplyTx, 0x51),
        ],
        signature: Ed25519Signature([0; 64]),
    }
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

fn signer_for(key: &SigningKey) -> MachineDataSignerBindingV1 {
    MachineDataSignerBindingV1 {
        signing_key_fingerprint: sha256(&key.verifying_key().to_bytes()),
        generation: LinkGeneration::new(3),
        certificate_sha256: [0x71; 32],
    }
}

fn update_info() -> KeyUpdateInfoV1 {
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

fn update_context() -> OuterContextV1 {
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
fn directory_signature_rejects_wrong_context_content_and_signer() {
    let key = SigningKey::from_seed(&[0x81; 32]);
    let signer = signer_for(&key);
    let context = signature_context();
    let signed = sign_key_directory(&key, &signer, &context, unsigned_bootstrap()).unwrap();
    verify_key_directory(&key.verifying_key(), &signer, &context, &signed).unwrap();

    let mut wrong_context = context.clone();
    wrong_context.grant_serial = GrantSerial::new(8);
    assert_eq!(
        verify_key_directory(&key.verifying_key(), &signer, &wrong_context, &signed,),
        Err(CryptoError::BadSignature)
    );

    let mut wrong_content = signed.clone();
    wrong_content.entries[0].wrapped_key[0] ^= 1;
    assert_eq!(
        verify_key_directory(&key.verifying_key(), &signer, &context, &wrong_content,),
        Err(CryptoError::BadSignature)
    );

    let other_key = SigningKey::from_seed(&[0x82; 32]);
    assert!(matches!(
        verify_key_directory(&other_key.verifying_key(), &signer, &context, &signed,),
        Err(CryptoError::InvalidKey(_))
    ));

    let mut wrong_signer = signer.clone();
    wrong_signer.certificate_sha256[0] ^= 1;
    assert_eq!(
        verify_key_directory(&key.verifying_key(), &wrong_signer, &context, &signed,),
        Err(CryptoError::BadSignature)
    );
    assert!(matches!(
        sign_key_directory(&key, &signer, &context, signed),
        Err(CryptoError::InvalidKey(_))
    ));
}

#[test]
fn typed_key_wrap_rejects_wrong_info_aad_recipient_stream_and_ciphertext() {
    let (recipient_private, recipient_public) = HpkePrivateKey::derive_keypair(&[0x91; 32]);
    let (wrong_recipient, _) = HpkePrivateKey::derive_keypair(&[0x92; 32]);
    let info = update_info();
    let context = update_context();
    let mut rng = DeterministicRng::new([0x93; 32]);
    let entry = seal_key_directory_entry(
        &recipient_public,
        &info,
        &context,
        &SecretAeadKey::from_bytes([0x94; 32]),
        &mut rng,
    )
    .unwrap();
    assert_eq!(entry.key_id.purpose, KeyPurpose::ConversationDek);
    assert_eq!(entry.key_id.epoch, 5);
    assert_eq!(entry.stream_route, Some(stream(0x33)));
    assert_eq!(entry.enc.len(), 32);
    assert_eq!(entry.wrapped_key.len(), 48);
    assert!(open_key_directory_entry(&recipient_private, &info, &context, &entry).is_ok());

    let mut wrong_info = info.clone();
    wrong_info.grant_serial = GrantSerial::new(8);
    assert!(matches!(
        open_key_directory_entry(&recipient_private, &wrong_info, &context, &entry),
        Err(CryptoError::BadCiphertext)
    ));

    let mut wrong_aad = context.clone();
    wrong_aad.message_key_epoch = 6;
    assert!(matches!(
        open_key_directory_entry(&recipient_private, &info, &wrong_aad, &entry),
        Err(CryptoError::InvalidPairing(_))
    ));

    assert!(matches!(
        open_key_directory_entry(&wrong_recipient, &info, &context, &entry),
        Err(CryptoError::BadCiphertext)
    ));

    let mut wrong_stream_info = info.clone();
    wrong_stream_info.stream_route = Some(stream(0x34));
    let mut wrong_stream_context = context.clone();
    wrong_stream_context.stream_route = Some(stream(0x34));
    assert!(matches!(
        open_key_directory_entry(
            &recipient_private,
            &wrong_stream_info,
            &wrong_stream_context,
            &entry,
        ),
        Err(CryptoError::InvalidPairing(_))
    ));

    let mut tampered = entry;
    tampered.wrapped_key[0] ^= 1;
    assert!(matches!(
        open_key_directory_entry(&recipient_private, &info, &context, &tampered),
        Err(CryptoError::BadCiphertext)
    ));
}
