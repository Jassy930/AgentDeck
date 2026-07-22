//! P4.5 DeviceReplyTx rollback recovery 必须完全绕过旧/新 reply AEAD key 与 counter。

use std::convert::Infallible;

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    CryptoError, DeviceKeyRecoveryOpenAuthority, DeviceKeyRecoverySealAuthority, HpkePrivateKey,
    SigningKey, open_device_key_recovery_reply, seal_device_key_recovery_reply, sha256,
};
use agentdeck_protocol::e2ee::{
    DeviceKeyRecoveryInfoV1, E2EE_FORMAT_VERSION, KeyId, KeyPurpose, KeyUpdateSetV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId,
    RelayServerId, RequestRouteId, TrustEpoch,
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
                let mut input = b"AgentDeck/KeyRecoveryTestRng\0".to_vec();
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

fn machine() -> MachineRouteId {
    MachineRouteId::from_bytes([0x11; 16])
}

fn device() -> DeviceRouteId {
    DeviceRouteId::from_bytes([0x22; 16])
}

fn request() -> RequestRouteId {
    RequestRouteId::from_bytes([0x33; 16])
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

fn signer_for(key: &SigningKey) -> MachineDataSignerBindingV1 {
    MachineDataSignerBindingV1 {
        signing_key_fingerprint: sha256(&key.verifying_key().to_bytes()),
        generation: LinkGeneration::new(7),
        certificate_sha256: [0x42; 32],
    }
}

fn info(signer: MachineDataSignerBindingV1) -> DeviceKeyRecoveryInfoV1 {
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
        update_set_sha256: update_set().canonical_sha256().unwrap(),
        machine_data_signer: signer,
    }
}

fn context() -> OuterContextV1 {
    OuterContextV1::device_key_recovery(machine(), device(), request())
}

#[test]
fn key_recovery_device_hpke_roundtrip_needs_no_device_reply_key_or_counter() {
    let signing_key = SigningKey::from_seed(&[0x71; 32]);
    let signer = signer_for(&signing_key);
    let (device_private, device_public) = HpkePrivateKey::derive_keypair(&[0x72; 32]);
    let info = info(signer.clone());
    let context = context();
    let set = update_set();
    let mut rng = DeterministicRng::new([0x73; 32]);

    // API 只接受 DeviceHPKE、MachineDataSign 与 RNG；不存在 DeviceReplyTx AEAD/counter 参数。
    let reply = seal_device_key_recovery_reply(
        DeviceKeyRecoverySealAuthority {
            device_hpke_public_key: &device_public,
            machine_data_signing_key: &signing_key,
            signer: &signer,
        },
        &info,
        &context,
        &set,
        &mut rng,
    )
    .unwrap();

    let opened = open_device_key_recovery_reply(
        DeviceKeyRecoveryOpenAuthority {
            device_hpke_private_key: &device_private,
            machine_data_verifying_key: &signing_key.verifying_key(),
            signer: &signer,
        },
        &info,
        &context,
        &reply,
    )
    .unwrap();
    assert_eq!(opened, set);
}

#[test]
fn key_recovery_rejects_wrong_hpke_and_every_signed_or_context_axis_tamper() {
    let signing_key = SigningKey::from_seed(&[0x81; 32]);
    let signer = signer_for(&signing_key);
    let verifying_key = signing_key.verifying_key();
    let (device_private, device_public) = HpkePrivateKey::derive_keypair(&[0x82; 32]);
    let (wrong_private, _) = HpkePrivateKey::derive_keypair(&[0x83; 32]);
    let info = info(signer.clone());
    let context = context();
    let set = update_set();
    let mut rng = DeterministicRng::new([0x84; 32]);
    let reply = seal_device_key_recovery_reply(
        DeviceKeyRecoverySealAuthority {
            device_hpke_public_key: &device_public,
            machine_data_signing_key: &signing_key,
            signer: &signer,
        },
        &info,
        &context,
        &set,
        &mut rng,
    )
    .unwrap();

    let open = |candidate_info: &DeviceKeyRecoveryInfoV1,
                candidate_context: &OuterContextV1,
                candidate: &agentdeck_protocol::e2ee::DeviceKeyRecoveryReplyV1|
     -> Result<KeyUpdateSetV1, CryptoError> {
        open_device_key_recovery_reply(
            DeviceKeyRecoveryOpenAuthority {
                device_hpke_private_key: &device_private,
                machine_data_verifying_key: &verifying_key,
                signer: &signer,
            },
            candidate_info,
            candidate_context,
            candidate,
        )
    };

    assert_eq!(
        open_device_key_recovery_reply(
            DeviceKeyRecoveryOpenAuthority {
                device_hpke_private_key: &wrong_private,
                machine_data_verifying_key: &verifying_key,
                signer: &signer,
            },
            &info,
            &context,
            &reply,
        ),
        Err(CryptoError::BadCiphertext)
    );

    let mut changed = reply.clone();
    changed.machine_data_signature.0[0] ^= 1;
    assert_eq!(
        open(&info, &context, &changed),
        Err(CryptoError::BadSignature)
    );

    changed = reply.clone();
    changed.enc[0] ^= 1;
    assert_eq!(
        open(&info, &context, &changed),
        Err(CryptoError::BadSignature)
    );

    changed = reply.clone();
    changed.ciphertext[0] ^= 1;
    assert_eq!(
        open(&info, &context, &changed),
        Err(CryptoError::BadSignature)
    );

    changed = reply.clone();
    changed.info.relay_server_id = RelayServerId::from_bytes([0x45; 16]);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.machine_route = MachineRouteId::from_bytes([0x12; 16]);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.request_route = RequestRouteId::from_bytes([0x34; 16]);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.device_route = DeviceRouteId::from_bytes([0x23; 16]);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.target_key_directory_revision = KeyDirectoryRevision::new(7);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.known_key_directory_revision = KeyDirectoryRevision::new(4);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.grant_serial = GrantSerial::new(10);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.root_trust_epoch = TrustEpoch::new(4);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.update_set_sha256[0] ^= 1;
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.machine_data_signer.generation = LinkGeneration::new(8);
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.machine_data_signer.certificate_sha256[0] ^= 1;
    assert!(open(&info, &context, &changed).is_err());

    changed = reply.clone();
    changed.info.machine_data_signer.signing_key_fingerprint[0] ^= 1;
    assert!(open(&info, &context, &changed).is_err());

    let mut changed_context = context.clone();
    changed_context.request_route = Some(RequestRouteId::from_bytes([0x34; 16]));
    assert!(open(&info, &changed_context, &reply).is_err());

    changed_context = context.clone();
    changed_context.device_route = Some(DeviceRouteId::from_bytes([0x23; 16]));
    assert!(open(&info, &changed_context, &reply).is_err());

    changed_context = context.clone();
    changed_context.machine_route = Some(MachineRouteId::from_bytes([0x12; 16]));
    assert!(open(&info, &changed_context, &reply).is_err());

    changed_context = context.clone();
    changed_context.relay_protocol_version += 1;
    assert!(open(&info, &changed_context, &reply).is_err());

    changed_context = context.clone();
    changed_context.message_key_epoch = 1;
    assert!(open(&info, &changed_context, &reply).is_err());

    let mut replay_info = info.clone();
    replay_info.request_route = RequestRouteId::from_bytes([0x35; 16]);
    let replay_context =
        OuterContextV1::device_key_recovery(machine(), device(), replay_info.request_route);
    assert!(open(&replay_info, &replay_context, &reply).is_err());

    let mut bad_info = info.clone();
    bad_info.update_set_sha256[0] ^= 1;
    let mut rng = DeterministicRng::new([0x85; 32]);
    assert!(
        seal_device_key_recovery_reply(
            DeviceKeyRecoverySealAuthority {
                device_hpke_public_key: &device_public,
                machine_data_signing_key: &signing_key,
                signer: &signer,
            },
            &bad_info,
            &context,
            &set,
            &mut rng,
        )
        .is_err()
    );
}
