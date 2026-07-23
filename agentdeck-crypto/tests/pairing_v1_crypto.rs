use std::convert::Infallible;

use ed25519_dalek::Signer;

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    CryptoError, HpkePrivateKey, PairResponseExpectedV1, PairResponseSealAuthority, SecretAeadKey,
    SigningKey, derive_nonce_prefix, hpke_seal_base, open_pair_pending, open_pair_request,
    open_pair_request_verified, open_pair_response, open_pair_response_received,
    open_pair_response_verified, seal_key_directory_entry, seal_pair_pending, seal_pair_request,
    seal_pair_response, seal_pair_response_received, sha256, sign_device_authorization,
    sign_key_directory, sign_pair_response_received, sign_tbs, verify_device_authorization,
    verify_pair_request_envelope, verify_pair_response_envelope, verify_pair_response_received,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    DeviceAuthorizationV1, E2EE_FORMAT_VERSION, KeyDirectoryEntry, KeyDirectorySignatureContextV1,
    KeyDirectoryV1, KeyId, KeyPurpose, KeyUpdateInfoV1, MachineDataSignerBindingV1, OuterContextV1,
    OuterFrameKind, PairInviteV1, PairRequestInfoV1, PairRequestPlaintextV1, PairResponseInfoV1,
    PairResponsePlaintextV1, PairResponseReceivedV1, PairResponseV1, PairingEnvelopeTbsV1,
    PairingError,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::{
    CertRole, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId, PairRouteId,
    RelayServerId, RootKeyId, StreamRouteId, TrustEpoch,
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
                let mut input = b"AgentDeck/PairingTestRng\0".to_vec();
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

fn machine_route() -> MachineRouteId {
    MachineRouteId::from_bytes([0x11; 16])
}

fn device_route() -> DeviceRouteId {
    DeviceRouteId::from_bytes([0x22; 16])
}

fn pair_route() -> PairRouteId {
    PairRouteId::from_bytes([0x33; 16])
}

fn relay_server() -> RelayServerId {
    RelayServerId::from_bytes([0x44; 16])
}

fn root_key_id() -> RootKeyId {
    RootKeyId::from_bytes([0x55; 16])
}

fn context(kind: OuterFrameKind) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: kind,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route()),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn request_info() -> PairRequestInfoV1 {
    PairRequestInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: relay_server(),
        pair_route: pair_route(),
        invite_hash: [0x61; 32],
        expiry_ms: 1_700_000_300_000,
    }
}

fn request_plaintext(device_signing_key: &SigningKey) -> PairRequestPlaintextV1 {
    PairRequestPlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        invite_secret: [0x62; 32],
        device_sign_pubkey: PublicKeyBytes(device_signing_key.verifying_key().to_bytes()),
        device_hpke_pubkey: PublicKeyBytes([0x63; 32]),
        authorization_request: AuthorizationRequestV1 {
            format_version: E2EE_FORMAT_VERSION,
            device_display_name: "Remote CLI".into(),
            capabilities: vec![
                AuthorizationCapabilityV1::Catalog,
                AuthorizationCapabilityV1::Conversation,
                AuthorizationCapabilityV1::Prompt,
                AuthorizationCapabilityV1::Command,
                AuthorizationCapabilityV1::Approval,
                AuthorizationCapabilityV1::Metadata,
                AuthorizationCapabilityV1::SelfRevocation,
            ],
            permissions: vec![
                AuthorizationPermissionV1::CatalogRead,
                AuthorizationPermissionV1::ConversationRead,
                AuthorizationPermissionV1::ConversationStart,
                AuthorizationPermissionV1::PromptSend,
                AuthorizationPermissionV1::CommandCancel,
                AuthorizationPermissionV1::ApprovalResolve,
                AuthorizationPermissionV1::ApprovalRetry,
                AuthorizationPermissionV1::MetadataWrite,
                AuthorizationPermissionV1::RevokeSelf,
            ],
        },
    }
}

fn signed_data_certificate(root: &SigningKey, data: &SigningKey) -> SignedCertificate {
    let root_fingerprint = sha256(&root.verifying_key().to_bytes());
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
        cert_role: CertRole::Data,
        generation: LinkGeneration::new(3),
        root_key_id: root_key_id(),
        trust_epoch: TrustEpoch::new(2),
        not_after_ms: None,
        signature: Ed25519Signature([0; 64]),
    };
    certificate.signature = sign_tbs(
        root,
        &certificate.to_be_signed_v1(relay_server(), machine_route(), root_fingerprint),
    )
    .into();
    certificate
}

fn signed_grant(root: &SigningKey, device: &SigningKey) -> RelayGrant {
    let root_fingerprint = sha256(&root.verifying_key().to_bytes());
    let mut grant = RelayGrant {
        machine_route: machine_route(),
        device_route: device_route(),
        device_sign_pubkey: PublicKeyBytes(device.verifying_key().to_bytes()),
        grant_serial: GrantSerial::new(7),
        root_key_id: root_key_id(),
        trust_epoch: TrustEpoch::new(2),
        signature: Ed25519Signature([0; 64]),
    };
    grant.signature = sign_tbs(
        root,
        &grant.to_be_signed_v1(relay_server(), root_fingerprint),
    )
    .into();
    grant
}

fn signed_authorization(
    root: &SigningKey,
    grant: &RelayGrant,
    device_hpke_public: &[u8],
) -> DeviceAuthorizationV1 {
    let request = request_plaintext(&SigningKey::from_seed(&[0x72; 32])).authorization_request;
    sign_device_authorization(
        root,
        relay_server(),
        grant,
        DeviceAuthorizationV1 {
            format_version: E2EE_FORMAT_VERSION,
            grant_hash: grant.canonical_sha256(),
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            device_sign_fingerprint: sha256(&grant.device_sign_pubkey.0),
            grant_serial: grant.grant_serial,
            device_hpke_pubkey: PublicKeyBytes(device_hpke_public.try_into().unwrap()),
            capabilities: request.capabilities,
            permissions: request.permissions,
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        },
    )
    .unwrap()
}

fn response_info(request_hash: [u8; 32]) -> PairResponseInfoV1 {
    PairResponseInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: relay_server(),
        pair_route: pair_route(),
        invite_hash: [0x61; 32],
        expiry_ms: 1_700_000_300_000,
        request_hash,
        machine_route: machine_route(),
        device_route: device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
    }
}

fn response_plaintext(
    root: &SigningKey,
    data: &SigningKey,
    signer: &MachineDataSignerBindingV1,
    device: &SigningKey,
    device_hpke_public: &[u8],
    request_hash: [u8; 32],
) -> PairResponsePlaintextV1 {
    let grant = signed_grant(root, device);
    let key_directory = sign_key_directory(
        data,
        signer,
        &KeyDirectorySignatureContextV1 {
            relay_server_id: relay_server(),
            machine_route: machine_route(),
            device_route: device_route(),
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
        },
        KeyDirectoryV1 {
            revision: KeyDirectoryRevision::new(1),
            entries: vec![
                KeyDirectoryEntry {
                    key_id: KeyId {
                        purpose: KeyPurpose::Catalog,
                        epoch: 1,
                    },
                    device_route: device_route(),
                    stream_route: None,
                    enc: vec![0x81; 32],
                    wrapped_key: vec![0x82; 48],
                },
                KeyDirectoryEntry {
                    key_id: KeyId {
                        purpose: KeyPurpose::DeviceCommandTx,
                        epoch: 1,
                    },
                    device_route: device_route(),
                    stream_route: None,
                    enc: vec![0x83; 32],
                    wrapped_key: vec![0x84; 48],
                },
                KeyDirectoryEntry {
                    key_id: KeyId {
                        purpose: KeyPurpose::DeviceReplyTx,
                        epoch: 1,
                    },
                    device_route: device_route(),
                    stream_route: None,
                    enc: vec![0x85; 32],
                    wrapped_key: vec![0x86; 48],
                },
            ],
            signature: Ed25519Signature([0; 64]),
        },
    )
    .unwrap();
    PairResponsePlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        request_hash,
        device_authorization: signed_authorization(root, &grant, device_hpke_public),
        relay_grant: grant,
        key_directory,
    }
}

struct VerifiedResponseFixture {
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
    device_hpke_private: HpkePrivateKey,
    device_sign_public: [u8; 32],
    device_hpke_public: [u8; 32],
    request_hash: [u8; 32],
    canonical_response: Vec<u8>,
    opened_key_prefixes: Vec<[u8; 4]>,
}

impl VerifiedResponseFixture {
    fn expected(&self) -> PairResponseExpectedV1<'_> {
        PairResponseExpectedV1::new(
            &self.invite,
            self.request_hash,
            self.device_sign_public,
            self.device_hpke_public,
            &self.authorization,
            1_700_000_000_000,
        )
    }
}

fn key_update_context(info: &KeyUpdateInfoV1) -> OuterContextV1 {
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

fn verified_response_fixture(
    certificate_machine_route: MachineRouteId,
    wrong_entry_revision: bool,
    duplicate_conversation_slot: bool,
    bad_directory_signature: bool,
) -> VerifiedResponseFixture {
    let root = SigningKey::from_seed(&[0xc1; 32]);
    let data = SigningKey::from_seed(&[0xc2; 32]);
    let device = SigningKey::from_seed(&[0xc3; 32]);
    let root_fingerprint = sha256(&root.verifying_key().to_bytes());
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
        cert_role: CertRole::Data,
        generation: LinkGeneration::new(4),
        root_key_id: root_key_id(),
        trust_epoch: TrustEpoch::new(2),
        not_after_ms: Some(1_700_000_400_000),
        signature: Ed25519Signature([0; 64]),
    };
    certificate.signature = sign_tbs(
        &root,
        &certificate.to_be_signed_v1(relay_server(), certificate_machine_route, root_fingerprint),
    )
    .into();
    let (_, invite_public) = HpkePrivateKey::derive_keypair(&[0xc4; 32]);
    let invite = PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        pair_route: pair_route(),
        invite_secret: [0xc5; 32],
        invite_hpke_pubkey: PublicKeyBytes(invite_public.to_bytes().try_into().unwrap()),
        wss_url: "wss://relay.example/".into(),
        relay_server_id: relay_server(),
        current_spki_pin: [0xc6; 32],
        next_spki_pin: [0xc7; 32],
        expires_at_ms: 1_700_000_299_000,
        machine_root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
        machine_root_fingerprint: root_fingerprint,
        data_sign_cert: certificate,
        machine_display_name: "Verified Machine".into(),
    };
    let authorization = AuthorizationRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        device_display_name: "Verified Remote".into(),
        capabilities: vec![
            AuthorizationCapabilityV1::Catalog,
            AuthorizationCapabilityV1::Conversation,
            AuthorizationCapabilityV1::Prompt,
        ],
        permissions: vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::ConversationRead,
        ],
    };
    let (device_hpke_private, device_hpke_public) = HpkePrivateKey::derive_keypair(&[0xc8; 32]);
    let device_hpke_public_bytes: [u8; 32] = device_hpke_public.to_bytes().try_into().unwrap();
    let request_hash = [0xc9; 32];
    let info = PairResponseInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: relay_server(),
        pair_route: pair_route(),
        invite_hash: invite.canonical_sha256().unwrap(),
        expiry_ms: invite.expires_at_ms,
        request_hash,
        machine_route: machine_route(),
        device_route: device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
    };
    let signer = MachineDataSignerBindingV1::from_certificate(&invite.data_sign_cert).unwrap();
    let grant = signed_grant(&root, &device);
    let device_authorization = sign_device_authorization(
        &root,
        relay_server(),
        &grant,
        DeviceAuthorizationV1 {
            format_version: E2EE_FORMAT_VERSION,
            grant_hash: grant.canonical_sha256(),
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            device_sign_fingerprint: sha256(&grant.device_sign_pubkey.0),
            grant_serial: grant.grant_serial,
            device_hpke_pubkey: PublicKeyBytes(device_hpke_public_bytes),
            capabilities: authorization.capabilities.clone(),
            permissions: authorization.permissions.clone(),
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        },
    )
    .unwrap();
    let directory_revision = KeyDirectoryRevision::new(9);
    let conversation_route = StreamRouteId::from_bytes([0xca; 16]);
    let mut entry_specs = vec![
        (KeyPurpose::Catalog, None, 3_u64, 0xd1_u8),
        (
            KeyPurpose::ConversationDek,
            Some(conversation_route),
            5,
            0xd2,
        ),
        (KeyPurpose::DeviceCommandTx, None, 7, 0xd3),
        (KeyPurpose::DeviceReplyTx, None, 11, 0xd4),
    ];
    if duplicate_conversation_slot {
        entry_specs.insert(
            2,
            (
                KeyPurpose::ConversationDek,
                Some(conversation_route),
                6,
                0xd5,
            ),
        );
    }
    let mut entry_rng = DeterministicRng::new([0xcb; 32]);
    let mut opened_key_prefixes = Vec::new();
    let mut entries = Vec::new();
    for (key_purpose, stream_route, key_epoch, key_byte) in entry_specs {
        let sealed_revision = if wrong_entry_revision && key_purpose == KeyPurpose::DeviceReplyTx {
            KeyDirectoryRevision::new(directory_revision.value() + 1)
        } else {
            directory_revision
        };
        let info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: relay_server(),
            machine_route: machine_route(),
            device_route: device_route(),
            stream_route,
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
            key_directory_revision: sealed_revision,
            key_purpose,
            key_epoch,
        };
        let key = SecretAeadKey::from_bytes([key_byte; 32]);
        opened_key_prefixes.push(derive_nonce_prefix(&key));
        entries.push(
            seal_key_directory_entry(
                &device_hpke_public,
                &info,
                &key_update_context(&info),
                &key,
                &mut entry_rng,
            )
            .unwrap(),
        );
    }
    let mut directory = sign_key_directory(
        &data,
        &signer,
        &KeyDirectorySignatureContextV1 {
            relay_server_id: relay_server(),
            machine_route: machine_route(),
            device_route: device_route(),
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
        },
        KeyDirectoryV1 {
            revision: directory_revision,
            entries,
            signature: Ed25519Signature([0; 64]),
        },
    )
    .unwrap();
    if bad_directory_signature {
        directory.signature.0[0] ^= 1;
    }
    let plaintext = PairResponsePlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        request_hash,
        relay_grant: grant,
        device_authorization,
        key_directory: directory,
    };
    let response_context = context(OuterFrameKind::PairResponse);
    let mut response_rng = DeterministicRng::new([0xcc; 32]);
    let response = if bad_directory_signature {
        let sealed = hpke_seal_base(
            &device_hpke_public,
            &info.encode(),
            &response_context.encode_aad(),
            &plaintext.canonical_bytes().unwrap(),
            &mut response_rng,
        )
        .unwrap();
        let tbs = PairingEnvelopeTbsV1::for_response_parts(
            E2EE_FORMAT_VERSION,
            sealed.enc.clone(),
            &sealed.ciphertext,
            &info,
            &response_context,
            &signer,
        )
        .unwrap();
        let signature = ed25519_dalek::SigningKey::from_bytes(&[0xc2; 32])
            .sign(&tbs.encode().unwrap())
            .to_bytes();
        PairResponseV1 {
            format_version: E2EE_FORMAT_VERSION,
            info: info.clone(),
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
            machine_data_signature: Ed25519Signature(signature),
        }
    } else {
        seal_pair_response(
            &device_hpke_public,
            &info,
            &response_context,
            &plaintext,
            PairResponseSealAuthority {
                machine_data_signing_key: &data,
                signer: &signer,
                machine_root_verifying_key: &root.verifying_key(),
            },
            &mut response_rng,
        )
        .unwrap()
    };
    VerifiedResponseFixture {
        invite,
        authorization,
        device_hpke_private,
        device_sign_public: device.verifying_key().to_bytes(),
        device_hpke_public: device_hpke_public_bytes,
        request_hash,
        canonical_response: response.canonical_bytes().unwrap(),
        opened_key_prefixes,
    }
}

#[test]
fn pair_request_seal_is_byte_stable_and_open_verifies_detached_device_proof() {
    let (invite_private, invite_public) = HpkePrivateKey::derive_keypair(&[0x91; 32]);
    let device = SigningKey::from_seed(&[0x72; 32]);
    let plaintext = request_plaintext(&device);
    let mut rng_a = DeterministicRng::new([0x92; 32]);
    let mut rng_b = DeterministicRng::new([0x92; 32]);
    let a = seal_pair_request(
        &invite_public,
        &request_info(),
        &context(OuterFrameKind::PairRequest),
        &plaintext,
        &device,
        &mut rng_a,
    )
    .unwrap();
    let b = seal_pair_request(
        &invite_public,
        &request_info(),
        &context(OuterFrameKind::PairRequest),
        &plaintext,
        &device,
        &mut rng_b,
    )
    .unwrap();
    assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
    assert_eq!(a.canonical_sha256().unwrap(), b.canonical_sha256().unwrap());
    verify_pair_request_envelope(
        &device.verifying_key(),
        &request_info(),
        &context(OuterFrameKind::PairRequest),
        &a,
    )
    .unwrap();
    assert_eq!(
        open_pair_request(
            &invite_private,
            &request_info(),
            &context(OuterFrameKind::PairRequest),
            &plaintext.invite_secret,
            &a,
        )
        .unwrap(),
        plaintext
    );

    let mut signature = a.clone();
    signature.device_proof_signature.0[0] ^= 1;
    assert_eq!(
        verify_pair_request_envelope(
            &device.verifying_key(),
            &request_info(),
            &context(OuterFrameKind::PairRequest),
            &signature,
        ),
        Err(CryptoError::BadSignature)
    );
    assert_eq!(
        open_pair_request(
            &invite_private,
            &request_info(),
            &context(OuterFrameKind::PairRequest),
            &plaintext.invite_secret,
            &signature,
        ),
        Err(CryptoError::BadSignature)
    );
    let mut ciphertext = a;
    ciphertext.ciphertext[0] ^= 1;
    assert_eq!(
        open_pair_request(
            &invite_private,
            &request_info(),
            &context(OuterFrameKind::PairRequest),
            &plaintext.invite_secret,
            &ciphertext,
        ),
        Err(CryptoError::BadCiphertext)
    );
}

#[test]
fn verified_pair_request_is_redacted_and_bound_to_exact_context() {
    let (invite_private, invite_public) = HpkePrivateKey::derive_keypair(&[0x93; 32]);
    let device = SigningKey::from_seed(&[0x94; 32]);
    let plaintext = request_plaintext(&device);
    let info = request_info();
    let context = context(OuterFrameKind::PairRequest);
    let mut rng = DeterministicRng::new([0x95; 32]);
    let envelope = seal_pair_request(
        &invite_public,
        &info,
        &context,
        &plaintext,
        &device,
        &mut rng,
    )
    .unwrap();
    let verified = open_pair_request_verified(
        &invite_private,
        &info,
        &context,
        &plaintext.invite_secret,
        &envelope,
    )
    .unwrap();
    assert_eq!(format!("{verified:?}"), "VerifiedPairRequestV1([REDACTED])");
    assert_eq!(
        verified.canonical_request(),
        envelope.canonical_bytes().unwrap()
    );
    assert_eq!(
        verified.request_hash(),
        envelope.canonical_sha256().unwrap()
    );
    assert_eq!(
        verified.canonical_plaintext(),
        plaintext.canonical_bytes().unwrap()
    );
    assert_eq!(verified.info(), &info);
    assert_eq!(verified.context(), &context);

    let mut wrong_context = context.clone();
    wrong_context.pair_route = Some(PairRouteId::from_bytes([0x96; 16]));
    assert_eq!(
        open_pair_request_verified(
            &invite_private,
            &info,
            &wrong_context,
            &plaintext.invite_secret,
            &envelope,
        )
        .unwrap_err(),
        CryptoError::BadCiphertext
    );
}

#[test]
fn pair_response_round_trip_verifies_machine_data_root_grant_and_authorization() {
    let root = SigningKey::from_seed(&[0xa1; 32]);
    let data = SigningKey::from_seed(&[0xa2; 32]);
    let device = SigningKey::from_seed(&[0xa3; 32]);
    let (device_hpke_private, device_hpke_public) = HpkePrivateKey::derive_keypair(&[0xa4; 32]);
    let signer =
        MachineDataSignerBindingV1::from_certificate(&signed_data_certificate(&root, &data))
            .unwrap();
    let request_hash = [0xa5; 32];
    let plaintext = response_plaintext(
        &root,
        &data,
        &signer,
        &device,
        &device_hpke_public.to_bytes(),
        request_hash,
    );
    let info = response_info(request_hash);

    let mut forged_directory = plaintext.clone();
    forged_directory.key_directory.signature.0[0] ^= 1;
    let mut rejected_rng = DeterministicRng::new([0xa7; 32]);
    assert_eq!(
        seal_pair_response(
            &device_hpke_public,
            &info,
            &context(OuterFrameKind::PairResponse),
            &forged_directory,
            PairResponseSealAuthority {
                machine_data_signing_key: &data,
                signer: &signer,
                machine_root_verifying_key: &root.verifying_key(),
            },
            &mut rejected_rng,
        ),
        Err(CryptoError::BadSignature)
    );

    let mut tampered_directory = plaintext.clone();
    tampered_directory.key_directory.entries[0].wrapped_key[0] ^= 1;
    let mut rejected_rng = DeterministicRng::new([0xa8; 32]);
    assert_eq!(
        seal_pair_response(
            &device_hpke_public,
            &info,
            &context(OuterFrameKind::PairResponse),
            &tampered_directory,
            PairResponseSealAuthority {
                machine_data_signing_key: &data,
                signer: &signer,
                machine_root_verifying_key: &root.verifying_key(),
            },
            &mut rejected_rng,
        ),
        Err(CryptoError::BadSignature)
    );

    let mut wrong_axis_directory = plaintext.clone();
    wrong_axis_directory.key_directory.signature = Ed25519Signature([0; 64]);
    let mut wrong_axis_context = KeyDirectorySignatureContextV1 {
        relay_server_id: relay_server(),
        machine_route: machine_route(),
        device_route: device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
    };
    wrong_axis_context.grant_serial = GrantSerial::new(8);
    wrong_axis_directory.key_directory = sign_key_directory(
        &data,
        &signer,
        &wrong_axis_context,
        wrong_axis_directory.key_directory,
    )
    .unwrap();
    let mut rejected_rng = DeterministicRng::new([0xa9; 32]);
    assert_eq!(
        seal_pair_response(
            &device_hpke_public,
            &info,
            &context(OuterFrameKind::PairResponse),
            &wrong_axis_directory,
            PairResponseSealAuthority {
                machine_data_signing_key: &data,
                signer: &signer,
                machine_root_verifying_key: &root.verifying_key(),
            },
            &mut rejected_rng,
        ),
        Err(CryptoError::BadSignature)
    );

    let mut conversation_directory = plaintext.clone();
    conversation_directory.key_directory.entries.insert(
        1,
        KeyDirectoryEntry {
            key_id: KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: 1,
            },
            device_route: device_route(),
            stream_route: Some(StreamRouteId::from_bytes([0xaa; 16])),
            enc: vec![0xab; 32],
            wrapped_key: vec![0xac; 48],
        },
    );
    let mut rejected_rng = DeterministicRng::new([0xad; 32]);
    assert_eq!(
        seal_pair_response(
            &device_hpke_public,
            &info,
            &context(OuterFrameKind::PairResponse),
            &conversation_directory,
            PairResponseSealAuthority {
                machine_data_signing_key: &data,
                signer: &signer,
                machine_root_verifying_key: &root.verifying_key(),
            },
            &mut rejected_rng,
        ),
        Err(CryptoError::BadSignature)
    );

    let mut rng = DeterministicRng::new([0xa6; 32]);
    let response = seal_pair_response(
        &device_hpke_public,
        &info,
        &context(OuterFrameKind::PairResponse),
        &plaintext,
        PairResponseSealAuthority {
            machine_data_signing_key: &data,
            signer: &signer,
            machine_root_verifying_key: &root.verifying_key(),
        },
        &mut rng,
    )
    .unwrap();
    assert_eq!(response.info, info, "seal must embed its exact HPKE info");
    verify_pair_response_envelope(
        &data.verifying_key(),
        &info,
        &context(OuterFrameKind::PairResponse),
        &response,
        &signer,
    )
    .unwrap();

    let mut wrong_info = info.clone();
    wrong_info.request_hash[0] ^= 1;
    assert_eq!(
        verify_pair_response_envelope(
            &data.verifying_key(),
            &wrong_info,
            &context(OuterFrameKind::PairResponse),
            &response,
            &signer,
        ),
        Err(CryptoError::InvalidPairing(
            PairingError::ContextBindingMismatch
        ))
    );

    let mut tampered_embedded_info = response.clone();
    tampered_embedded_info.info.request_hash[0] ^= 1;
    assert_eq!(
        verify_pair_response_envelope(
            &data.verifying_key(),
            &info,
            &context(OuterFrameKind::PairResponse),
            &tampered_embedded_info,
            &signer,
        ),
        Err(CryptoError::InvalidPairing(
            PairingError::ContextBindingMismatch
        )),
        "open/verify must reject caller info that differs from the envelope"
    );
    assert_eq!(
        verify_pair_response_envelope(
            &data.verifying_key(),
            &tampered_embedded_info.info,
            &context(OuterFrameKind::PairResponse),
            &tampered_embedded_info,
            &signer,
        ),
        Err(CryptoError::BadSignature),
        "tampering embedded info and matching the caller still invalidates MachineDataSign"
    );
    assert!(matches!(
        open_pair_response(
            &device_hpke_private,
            &info,
            &context(OuterFrameKind::PairResponse),
            &tampered_embedded_info,
            &data.verifying_key(),
            &signer,
            &root.verifying_key(),
        ),
        Err(CryptoError::InvalidPairing(
            PairingError::ContextBindingMismatch
        ))
    ));

    let mut wrong_context = context(OuterFrameKind::PairResponse);
    wrong_context.pair_route = Some(PairRouteId::from_bytes([0xae; 16]));
    assert!(matches!(
        verify_pair_response_envelope(
            &data.verifying_key(),
            &info,
            &wrong_context,
            &response,
            &signer,
        ),
        Err(CryptoError::InvalidPairing(_))
    ));

    let mut wrong_signer = signer.clone();
    wrong_signer.certificate_sha256[0] ^= 1;
    assert_eq!(
        verify_pair_response_envelope(
            &data.verifying_key(),
            &info,
            &context(OuterFrameKind::PairResponse),
            &response,
            &wrong_signer,
        ),
        Err(CryptoError::BadSignature)
    );

    wrong_signer = signer.clone();
    wrong_signer.signing_key_fingerprint[0] ^= 1;
    assert!(matches!(
        verify_pair_response_envelope(
            &data.verifying_key(),
            &info,
            &context(OuterFrameKind::PairResponse),
            &response,
            &wrong_signer,
        ),
        Err(CryptoError::InvalidKey(_))
    ));

    assert_eq!(
        open_pair_response(
            &device_hpke_private,
            &info,
            &context(OuterFrameKind::PairResponse),
            &response,
            &data.verifying_key(),
            &signer,
            &root.verifying_key(),
        )
        .unwrap(),
        plaintext
    );

    let mut tampered = response;
    tampered.machine_data_signature.0[0] ^= 1;
    assert_eq!(
        open_pair_response(
            &device_hpke_private,
            &info,
            &context(OuterFrameKind::PairResponse),
            &tampered,
            &data.verifying_key(),
            &signer,
            &root.verifying_key(),
        ),
        Err(CryptoError::BadSignature)
    );
}

#[test]
fn verified_pair_response_requires_full_root_pending_and_directory_key_chain() {
    let fixture = verified_response_fixture(machine_route(), false, false, false);
    let verified = open_pair_response_verified(
        &fixture.device_hpke_private,
        fixture.expected(),
        &fixture.canonical_response,
    )
    .expect("complete verified response chain");

    assert_eq!(
        format!("{verified:?}"),
        "VerifiedPairResponseV1([REDACTED])"
    );
    assert_eq!(verified.canonical_response(), fixture.canonical_response);
    assert_eq!(
        verified.response_hash(),
        sha256(&fixture.canonical_response)
    );
    assert_eq!(
        verified.relay_grant().device_sign_pubkey.0,
        fixture.device_sign_public
    );
    assert_eq!(verified.key_directory().revision.value(), 9);
    assert_eq!(verified.opened_keys().len(), 4);
    assert_eq!(
        verified
            .opened_keys()
            .iter()
            .map(|entry| entry.derived_nonce_prefix())
            .collect::<Vec<_>>(),
        fixture.opened_key_prefixes
    );
}

#[test]
fn verified_pair_response_rejects_unproven_data_cert_and_pending_identity_mismatch() {
    let wrong_certificate_route =
        verified_response_fixture(MachineRouteId::from_bytes([0xee; 16]), false, false, false);
    assert!(
        open_pair_response_verified(
            &wrong_certificate_route.device_hpke_private,
            wrong_certificate_route.expected(),
            &wrong_certificate_route.canonical_response,
        )
        .is_err(),
        "a shape-valid Data cert signed for another machine route must be rejected"
    );

    let fixture = verified_response_fixture(machine_route(), false, false, false);
    let alternate_device_sign = SigningKey::from_seed(&[0xef; 32]);
    let wrong_sign = PairResponseExpectedV1::new(
        &fixture.invite,
        fixture.request_hash,
        alternate_device_sign.verifying_key().to_bytes(),
        fixture.device_hpke_public,
        &fixture.authorization,
        1_700_000_000_000,
    );
    assert!(
        open_pair_response_verified(
            &fixture.device_hpke_private,
            wrong_sign,
            &fixture.canonical_response,
        )
        .is_err(),
        "grant DeviceSign must match the frozen pending request"
    );

    let (_, alternate_hpke_public) = HpkePrivateKey::derive_keypair(&[0xed; 32]);
    let wrong_hpke = PairResponseExpectedV1::new(
        &fixture.invite,
        fixture.request_hash,
        fixture.device_sign_public,
        alternate_hpke_public.to_bytes().try_into().unwrap(),
        &fixture.authorization,
        1_700_000_000_000,
    );
    assert!(
        open_pair_response_verified(
            &fixture.device_hpke_private,
            wrong_hpke,
            &fixture.canonical_response,
        )
        .is_err(),
        "authorization DeviceHPKE and recipient must match the frozen pending request"
    );

    let mut changed_capability = fixture.authorization.clone();
    changed_capability.capabilities.pop();
    changed_capability.validate().unwrap();
    let wrong_capability = PairResponseExpectedV1::new(
        &fixture.invite,
        fixture.request_hash,
        fixture.device_sign_public,
        fixture.device_hpke_public,
        &changed_capability,
        1_700_000_000_000,
    );
    assert!(
        open_pair_response_verified(
            &fixture.device_hpke_private,
            wrong_capability,
            &fixture.canonical_response,
        )
        .is_err(),
        "granted capabilities must equal the pending request"
    );

    let mut changed_permission = fixture.authorization.clone();
    changed_permission.permissions.pop();
    changed_permission.validate().unwrap();
    let wrong_permission = PairResponseExpectedV1::new(
        &fixture.invite,
        fixture.request_hash,
        fixture.device_sign_public,
        fixture.device_hpke_public,
        &changed_permission,
        1_700_000_000_000,
    );
    assert!(
        open_pair_response_verified(
            &fixture.device_hpke_private,
            wrong_permission,
            &fixture.canonical_response,
        )
        .is_err(),
        "granted permissions must equal the pending request"
    );
}

#[test]
fn verified_pair_response_derives_exact_entry_context_and_rejects_ambiguous_current_slots() {
    let wrong_entry_revision = verified_response_fixture(machine_route(), true, false, false);
    assert!(
        open_pair_response_verified(
            &wrong_entry_revision.device_hpke_private,
            wrong_entry_revision.expected(),
            &wrong_entry_revision.canonical_response,
        )
        .is_err(),
        "entry HPKE info must use the signed directory revision"
    );

    let duplicate_slot = verified_response_fixture(machine_route(), false, true, false);
    assert!(
        open_pair_response_verified(
            &duplicate_slot.device_hpke_private,
            duplicate_slot.expected(),
            &duplicate_slot.canonical_response,
        )
        .is_err(),
        "one current directory cannot carry two epochs for one semantic slot"
    );
}

#[test]
fn verified_pair_response_rejects_bad_inner_directory_signature_after_valid_outer_open() {
    let bad_directory = verified_response_fixture(machine_route(), false, false, true);
    assert_eq!(
        open_pair_response_verified(
            &bad_directory.device_hpke_private,
            bad_directory.expected(),
            &bad_directory.canonical_response,
        )
        .unwrap_err(),
        CryptoError::BadSignature,
        "receive-side verification must not trust a valid outer signature over a bad directory"
    );
}

#[test]
fn verified_pair_response_rejects_every_pending_clear_axis_before_promotion() {
    let fixture = verified_response_fixture(machine_route(), false, false, false);
    let mut invite_variants = Vec::new();

    let mut changed_relay = fixture.invite.clone();
    changed_relay.relay_server_id = RelayServerId::from_bytes([0xe1; 16]);
    invite_variants.push(("relayServerId", changed_relay));

    let mut changed_route = fixture.invite.clone();
    changed_route.pair_route = PairRouteId::from_bytes([0xe2; 16]);
    invite_variants.push(("pairRoute", changed_route));

    let mut changed_expiry = fixture.invite.clone();
    changed_expiry.expires_at_ms -= 1;
    invite_variants.push(("expiry", changed_expiry));

    let mut changed_hash_input = fixture.invite.clone();
    changed_hash_input.machine_display_name = "Another Machine".into();
    invite_variants.push(("inviteHash", changed_hash_input));

    for (axis, invite) in invite_variants {
        let expected = PairResponseExpectedV1::new(
            &invite,
            fixture.request_hash,
            fixture.device_sign_public,
            fixture.device_hpke_public,
            &fixture.authorization,
            1_700_000_000_000,
        );
        assert!(
            open_pair_response_verified(
                &fixture.device_hpke_private,
                expected,
                &fixture.canonical_response,
            )
            .is_err(),
            "changed {axis} must fail"
        );
    }

    let wrong_request = PairResponseExpectedV1::new(
        &fixture.invite,
        [0xe3; 32],
        fixture.device_sign_public,
        fixture.device_hpke_public,
        &fixture.authorization,
        1_700_000_000_000,
    );
    assert!(
        open_pair_response_verified(
            &fixture.device_hpke_private,
            wrong_request,
            &fixture.canonical_response,
        )
        .is_err(),
        "changed requestHash must fail"
    );

    let mut trailing = fixture.canonical_response.clone();
    trailing.push(0);
    assert!(
        open_pair_response_verified(&fixture.device_hpke_private, fixture.expected(), &trailing)
            .is_err(),
        "strict canonical parser must reject trailing bytes"
    );
}

#[test]
fn pair_pending_is_signed_then_hpke_encrypted_and_request_hash_is_not_relay_visible() {
    let data = SigningKey::from_seed(&[0xb1; 32]);
    let root = SigningKey::from_seed(&[0xb2; 32]);
    let signer =
        MachineDataSignerBindingV1::from_certificate(&signed_data_certificate(&root, &data))
            .unwrap();
    let (device_private, device_public) = HpkePrivateKey::derive_keypair(&[0xb3; 32]);
    let request_hash = [0xb4; 32];
    let mut rng = DeterministicRng::new([0xb5; 32]);
    let envelope = seal_pair_pending(
        &device_public,
        &request_info(),
        &context(OuterFrameKind::PairPending),
        request_hash,
        &data,
        &signer,
        &mut rng,
    )
    .unwrap();
    let json = serde_json::to_value(&envelope).unwrap();
    assert!(json.get("requestHash").is_none());
    assert_eq!(
        open_pair_pending(
            &device_private,
            &request_info(),
            &context(OuterFrameKind::PairPending),
            &envelope,
            &data.verifying_key(),
            &signer,
        )
        .unwrap()
        .request_hash,
        request_hash
    );

    let mut tampered = envelope;
    tampered.ciphertext[0] ^= 1;
    assert_eq!(
        open_pair_pending(
            &device_private,
            &request_info(),
            &context(OuterFrameKind::PairPending),
            &tampered,
            &data.verifying_key(),
            &signer,
        ),
        Err(CryptoError::BadCiphertext)
    );
}

#[test]
fn device_authorization_and_pair_response_received_use_typed_tbs() {
    let root = SigningKey::from_seed(&[0xc1; 32]);
    let device = SigningKey::from_seed(&[0xc2; 32]);
    let (_, hpke_public) = HpkePrivateKey::derive_keypair(&[0xc3; 32]);
    let grant = signed_grant(&root, &device);
    let authorization = signed_authorization(&root, &grant, &hpke_public.to_bytes());
    verify_device_authorization(
        &root.verifying_key(),
        relay_server(),
        &grant,
        &authorization,
    )
    .unwrap();

    let info = response_info([0xc4; 32]);
    let receipt = sign_pair_response_received(
        &device,
        &info,
        &context(OuterFrameKind::PairResponseReceived),
        PairResponseReceivedV1 {
            request_hash: info.request_hash,
            grant_hash: grant.canonical_sha256(),
            response_hash: [0xc5; 32],
            signature: Ed25519Signature([0; 64]),
        },
    )
    .unwrap();
    verify_pair_response_received(
        &device.verifying_key(),
        &info,
        &context(OuterFrameKind::PairResponseReceived),
        &receipt,
    )
    .unwrap();

    let mut tampered = receipt;
    tampered.response_hash[0] ^= 1;
    assert_eq!(
        verify_pair_response_received(
            &device.verifying_key(),
            &info,
            &context(OuterFrameKind::PairResponseReceived),
            &tampered,
        ),
        Err(CryptoError::BadSignature)
    );

    let (invite_private, invite_public) = HpkePrivateKey::derive_keypair(&[0xc6; 32]);
    let mut rng = DeterministicRng::new([0xc7; 32]);
    let envelope = seal_pair_response_received(
        &invite_public,
        &info,
        &context(OuterFrameKind::PairResponseReceived),
        PairResponseReceivedV1 {
            request_hash: info.request_hash,
            grant_hash: grant.canonical_sha256(),
            response_hash: [0xc5; 32],
            signature: Ed25519Signature([0; 64]),
        },
        &device,
        &mut rng,
    )
    .unwrap();
    let relay_visible = serde_json::to_value(&envelope).unwrap();
    for hidden in ["requestHash", "grantHash", "responseHash", "signature"] {
        assert!(relay_visible.get(hidden).is_none());
    }
    assert_eq!(
        open_pair_response_received(
            &invite_private,
            &info,
            &context(OuterFrameKind::PairResponseReceived),
            &envelope,
            &device.verifying_key(),
        )
        .unwrap()
        .response_hash,
        [0xc5; 32]
    );
}
