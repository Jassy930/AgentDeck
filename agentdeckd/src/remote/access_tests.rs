use agentdeck_crypto::rand_core::SeedableRng;
use agentdeck_crypto::{
    HpkePrivateKey, HpkePublicKey, PairResponseSealAuthority, SigningKey, seal_pair_response,
    seal_pair_response_received, sign_device_authorization, sign_key_directory,
    sign_pair_response_received, sign_tbs,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, DeviceAuthorizationV1, KeyDirectoryEntry,
    KeyDirectorySignatureContextV1, KeyDirectoryV1, KeyId, KeyPurpose, PairResponsePlaintextV1,
};
use agentdeck_protocol::relay_v2::{
    CertRole, KeyDirectoryRevision, LinkGeneration, SignedCertificate,
};
use rand_chacha::ChaCha20Rng;

use super::*;

const RELAY: RelayServerId = RelayServerId::from_bytes([0x11; 16]);
const MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x22; 16]);
const DEVICE: DeviceRouteId = DeviceRouteId::from_bytes([0x33; 16]);
const PAIR_ROUTE: PairRouteId = PairRouteId::from_bytes([0x44; 16]);
const ROOT_KEY_ID: RootKeyId = RootKeyId::from_bytes([0x55; 16]);
const TRUST_EPOCH: TrustEpoch = TrustEpoch::new(3);
const GRANT_SERIAL: GrantSerial = GrantSerial::new(7);
const REQUEST_HASH: [u8; 32] = [0x66; 32];
const ROOT_SEED: [u8; 32] = [0x71; 32];
const DATA_SEED: [u8; 32] = [0x72; 32];
const DEVICE_SEED: [u8; 32] = [0x73; 32];
const INVITE_HPKE_SEED: [u8; 32] = [0x74; 32];
const DEVICE_HPKE_SEED: [u8; 32] = [0x75; 32];

struct Fixture {
    invite: PairInviteV1,
    grant: RelayGrant,
    response: PairResponseV1,
    device_signing_key: SigningKey,
    invite_ephemeral_private_key: HpkePrivateKey,
}

impl Fixture {
    fn new() -> Self {
        let root = SigningKey::from_seed(&ROOT_SEED);
        let data = SigningKey::from_seed(&DATA_SEED);
        let device_signing_key = SigningKey::from_seed(&DEVICE_SEED);
        let (invite_ephemeral_private_key, invite_public) =
            HpkePrivateKey::derive_keypair(&INVITE_HPKE_SEED);
        let (_, device_hpke_public) = HpkePrivateKey::derive_keypair(&DEVICE_HPKE_SEED);
        let root_fingerprint = sha256(&root.verifying_key().to_bytes());

        let mut data_certificate = SignedCertificate {
            subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
            cert_role: CertRole::Data,
            generation: LinkGeneration::new(4),
            root_key_id: ROOT_KEY_ID,
            trust_epoch: TRUST_EPOCH,
            not_after_ms: None,
            signature: Ed25519Signature([0; 64]),
        };
        data_certificate.signature = sign_tbs(
            &root,
            &data_certificate.to_be_signed_v1(RELAY, MACHINE, root_fingerprint),
        )
        .into();

        let invite = PairInviteV1 {
            format_version: E2EE_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            pair_route: PAIR_ROUTE,
            invite_secret: [0x81; 32],
            invite_hpke_pubkey: PublicKeyBytes(
                invite_public
                    .to_bytes()
                    .try_into()
                    .expect("32-byte invite HPKE public key"),
            ),
            wss_url: "wss://relay.example.test/".into(),
            relay_server_id: RELAY,
            current_spki_pin: [0x82; 32],
            next_spki_pin: [0x83; 32],
            expires_at_ms: 1_900_000_300_000,
            machine_root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
            machine_root_fingerprint: root_fingerprint,
            data_sign_cert: data_certificate,
            machine_display_name: "Access Fixture".into(),
        };

        let mut grant = RelayGrant {
            machine_route: MACHINE,
            device_route: DEVICE,
            device_sign_pubkey: PublicKeyBytes(device_signing_key.verifying_key().to_bytes()),
            grant_serial: GRANT_SERIAL,
            root_key_id: ROOT_KEY_ID,
            trust_epoch: TRUST_EPOCH,
            signature: Ed25519Signature([0; 64]),
        };
        grant.signature = sign_tbs(&root, &grant.to_be_signed_v1(RELAY, root_fingerprint)).into();

        let authorization = sign_device_authorization(
            &root,
            RELAY,
            &grant,
            DeviceAuthorizationV1 {
                format_version: E2EE_FORMAT_VERSION,
                grant_hash: grant.canonical_sha256(),
                machine_route: MACHINE,
                device_route: DEVICE,
                device_sign_fingerprint: sha256(&grant.device_sign_pubkey.0),
                grant_serial: GRANT_SERIAL,
                device_hpke_pubkey: PublicKeyBytes(
                    device_hpke_public
                        .to_bytes()
                        .try_into()
                        .expect("32-byte device HPKE public key"),
                ),
                capabilities: vec![AuthorizationCapabilityV1::Catalog],
                permissions: vec![AuthorizationPermissionV1::CatalogRead],
                root_key_id: ROOT_KEY_ID,
                trust_epoch: TRUST_EPOCH,
                signature: Ed25519Signature([0; 64]),
            },
        )
        .expect("valid signed authorization");
        let signer = MachineDataSignerBindingV1::from_certificate(&invite.data_sign_cert)
            .expect("valid data signer binding");
        let directory = sign_key_directory(
            &data,
            &signer,
            &KeyDirectorySignatureContextV1 {
                relay_server_id: RELAY,
                machine_route: MACHINE,
                device_route: DEVICE,
                grant_serial: GRANT_SERIAL,
                root_trust_epoch: TRUST_EPOCH,
            },
            KeyDirectoryV1 {
                revision: KeyDirectoryRevision::new(1),
                entries: bootstrap_entries(),
                signature: Ed25519Signature([0; 64]),
            },
        )
        .expect("valid signed key directory");
        let info = response_info(&invite, &grant, REQUEST_HASH);
        let response_context = pairing_context(PAIR_ROUTE, OuterFrameKind::PairResponse);
        let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
        let response = seal_pair_response(
            &device_hpke_public,
            &info,
            &response_context,
            &PairResponsePlaintextV1 {
                format_version: E2EE_FORMAT_VERSION,
                request_hash: REQUEST_HASH,
                relay_grant: grant.clone(),
                device_authorization: authorization,
                key_directory: directory,
            },
            PairResponseSealAuthority {
                machine_data_signing_key: &data,
                signer: &signer,
                machine_root_verifying_key: &root.verifying_key(),
            },
            &mut rng,
        )
        .expect("valid frozen pair response");

        Self {
            invite,
            grant,
            response,
            device_signing_key,
            invite_ephemeral_private_key,
        }
    }

    fn binding(&self) -> PairResponseAccessBinding {
        PairResponseAccessBinding::from_frozen(
            &self.invite,
            REQUEST_HASH,
            &self.grant,
            &self.response,
        )
        .expect("valid access binding")
    }

    fn correct_receipt(&self) -> PairResponseReceivedV1 {
        let binding = self.binding();
        signed_receipt(
            &self.device_signing_key,
            binding.info(),
            binding.receipt_context(),
            self.grant.canonical_sha256(),
            self.response.canonical_sha256().expect("response hash"),
        )
    }

    fn invite_hpke_public_key(&self) -> HpkePublicKey {
        HpkePublicKey::from_bytes(&self.invite.invite_hpke_pubkey.0)
            .expect("valid invite HPKE public key")
    }
}

fn bootstrap_entries() -> Vec<KeyDirectoryEntry> {
    [
        (KeyPurpose::Catalog, 0xa1_u8, 0xb1_u8),
        (KeyPurpose::DeviceCommandTx, 0xa2, 0xb2),
        (KeyPurpose::DeviceReplyTx, 0xa3, 0xb3),
    ]
    .into_iter()
    .map(|(purpose, enc, wrapped)| KeyDirectoryEntry {
        key_id: KeyId { purpose, epoch: 1 },
        device_route: DEVICE,
        stream_route: None,
        enc: vec![enc; 32],
        wrapped_key: vec![wrapped; 48],
    })
    .collect()
}

fn response_info(
    invite: &PairInviteV1,
    grant: &RelayGrant,
    request_hash: [u8; 32],
) -> PairResponseInfoV1 {
    PairResponseInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: invite.pair_route,
        invite_hash: invite.canonical_sha256().expect("invite hash"),
        expiry_ms: invite.expires_at_ms,
        request_hash,
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: grant.grant_serial,
        root_trust_epoch: grant.trust_epoch,
    }
}

fn signed_receipt(
    device: &SigningKey,
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
) -> PairResponseReceivedV1 {
    sign_pair_response_received(
        device,
        info,
        context,
        PairResponseReceivedV1 {
            request_hash: info.request_hash,
            grant_hash,
            response_hash,
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign typed receipt")
}

fn assert_access_error<T: std::fmt::Debug>(
    result: Result<T, PairingAccessError>,
    expected: PairingAccessError,
) {
    assert_eq!(result.expect_err("operation must fail closed"), expected);
}

#[test]
fn signed_receipt_is_canonical_and_binds_all_frozen_proof_hashes() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let receipt = fixture.correct_receipt();
    let canonical = receipt.canonical_bytes().expect("canonical receipt");
    let proof = binding
        .verify_signed_receipt(&canonical)
        .expect("verified receipt");

    assert_eq!(proof.canonical_receipt(), canonical);
    assert_eq!(proof.request_hash(), REQUEST_HASH);
    assert_eq!(proof.grant_hash(), fixture.grant.canonical_sha256());
    assert_eq!(
        proof.response_hash(),
        fixture.response.canonical_sha256().expect("response hash")
    );
    assert_eq!(proof.relay_server_id(), RELAY);
    assert_eq!(proof.pair_route(), PAIR_ROUTE);
    assert_eq!(
        proof.invite_hash(),
        fixture.invite.canonical_sha256().expect("invite hash")
    );
    assert_eq!(proof.expiry_ms(), fixture.invite.expires_at_ms);
    assert_eq!(proof.machine_route(), MACHINE);
    assert_eq!(proof.device_route(), DEVICE);
    assert_eq!(proof.grant_serial(), GRANT_SERIAL);
    assert_eq!(proof.root_trust_epoch(), TRUST_EPOCH);
    assert_eq!(
        proof.device_sign_fingerprint(),
        sha256(&fixture.grant.device_sign_pubkey.0)
    );
    assert_eq!(proof.info_sha256(), sha256(&binding.info().encode()));
    assert_eq!(
        proof.aad_sha256(),
        sha256(&binding.receipt_context().encode_aad())
    );
    assert_ne!(proof.tbs_sha256(), [0; 32]);
    assert_eq!(
        format!("{binding:?}"),
        "PairResponseAccessBinding([REDACTED])"
    );
    assert_eq!(
        format!("{proof:?}"),
        "VerifiedPairResponseReceipt([REDACTED])"
    );

    let repeated = fixture.correct_receipt().canonical_bytes().expect("repeat");
    assert_eq!(canonical, repeated, "Ed25519 receipt retry must be exact");
    assert_eq!(sha256(&canonical), sha256(&repeated));
    let repeated_binding = fixture.binding();
    assert_eq!(binding.info().encode(), repeated_binding.info().encode());
    assert_eq!(
        binding.receipt_context().encode_aad(),
        repeated_binding.receipt_context().encode_aad()
    );
}

#[test]
fn encrypted_receipt_uses_invite_ephemeral_key_and_rejects_ciphertext_faults() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let mut rng = ChaCha20Rng::from_seed([0x92; 32]);
    let envelope = seal_pair_response_received(
        &fixture.invite_hpke_public_key(),
        binding.info(),
        binding.receipt_context(),
        PairResponseReceivedV1 {
            request_hash: REQUEST_HASH,
            grant_hash: fixture.grant.canonical_sha256(),
            response_hash: fixture.response.canonical_sha256().expect("response hash"),
            signature: Ed25519Signature([0; 64]),
        },
        &fixture.device_signing_key,
        &mut rng,
    )
    .expect("seal receipt");
    let canonical = envelope.canonical_bytes().expect("canonical envelope");
    let proof = binding
        .open_and_verify_receipt(&fixture.invite_ephemeral_private_key, &canonical)
        .expect("open receipt with invite ephemeral key");
    assert_eq!(proof.request_hash(), REQUEST_HASH);

    let (wrong_private, _) = HpkePrivateKey::derive_keypair(&[0xee; 32]);
    assert!(
        binding
            .open_and_verify_receipt(&wrong_private, &canonical)
            .is_err()
    );
    let mut tampered = envelope;
    tampered.ciphertext[0] ^= 1;
    assert!(
        binding
            .open_and_verify_receipt(
                &fixture.invite_ephemeral_private_key,
                &tampered
                    .canonical_bytes()
                    .expect("tampered canonical envelope"),
            )
            .is_err()
    );
    let mut wrong_response_hash = fixture.response.canonical_sha256().expect("response hash");
    wrong_response_hash[0] ^= 1;
    let mut wrong_hash_rng = ChaCha20Rng::from_seed([0x93; 32]);
    let wrong_hash_envelope = seal_pair_response_received(
        &fixture.invite_hpke_public_key(),
        binding.info(),
        binding.receipt_context(),
        PairResponseReceivedV1 {
            request_hash: REQUEST_HASH,
            grant_hash: fixture.grant.canonical_sha256(),
            response_hash: wrong_response_hash,
            signature: Ed25519Signature([0; 64]),
        },
        &fixture.device_signing_key,
        &mut wrong_hash_rng,
    )
    .expect("seal signed wrong-hash receipt");
    assert_access_error(
        binding.open_and_verify_receipt(
            &fixture.invite_ephemeral_private_key,
            &wrong_hash_envelope
                .canonical_bytes()
                .expect("canonical wrong-hash envelope"),
        ),
        PairingAccessError::ReceiptBindingMismatch,
    );
    let mut trailing = canonical;
    trailing.push(0);
    assert_access_error(
        binding.open_and_verify_receipt(&fixture.invite_ephemeral_private_key, &trailing),
        PairingAccessError::InvalidReceiptEncoding,
    );
}

#[test]
fn receipt_rejects_three_hashes_signature_wrong_key_and_noncanonical_bytes() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let correct_info = binding.info().clone();
    let correct_context = binding.receipt_context().clone();
    let expected_grant = fixture.grant.canonical_sha256();
    let expected_response = fixture.response.canonical_sha256().expect("response hash");

    let mut wrong_request_info = correct_info.clone();
    wrong_request_info.request_hash[0] ^= 1;
    let wrong_request = signed_receipt(
        &fixture.device_signing_key,
        &wrong_request_info,
        &correct_context,
        expected_grant,
        expected_response,
    );
    assert!(
        binding
            .verify_signed_receipt(&wrong_request.canonical_bytes().expect("wrong request"))
            .is_err()
    );

    let mut wrong_grant = expected_grant;
    wrong_grant[0] ^= 1;
    let receipt = signed_receipt(
        &fixture.device_signing_key,
        &correct_info,
        &correct_context,
        wrong_grant,
        expected_response,
    );
    assert_access_error(
        binding.verify_signed_receipt(&receipt.canonical_bytes().expect("wrong grant")),
        PairingAccessError::ReceiptBindingMismatch,
    );

    let mut wrong_response = expected_response;
    wrong_response[0] ^= 1;
    let receipt = signed_receipt(
        &fixture.device_signing_key,
        &correct_info,
        &correct_context,
        expected_grant,
        wrong_response,
    );
    assert_access_error(
        binding.verify_signed_receipt(&receipt.canonical_bytes().expect("wrong response")),
        PairingAccessError::ReceiptBindingMismatch,
    );

    let wrong_key = SigningKey::from_seed(&[0xa9; 32]);
    let receipt = signed_receipt(
        &wrong_key,
        &correct_info,
        &correct_context,
        expected_grant,
        expected_response,
    );
    assert_access_error(
        binding.verify_signed_receipt(&receipt.canonical_bytes().expect("wrong key")),
        PairingAccessError::InvalidReceiptSignature,
    );

    let mut receipt = fixture.correct_receipt();
    receipt.signature.0[0] ^= 1;
    assert_access_error(
        binding.verify_signed_receipt(&receipt.canonical_bytes().expect("bad signature")),
        PairingAccessError::InvalidReceiptSignature,
    );
    let mut trailing = fixture
        .correct_receipt()
        .canonical_bytes()
        .expect("canonical receipt");
    trailing.push(0);
    assert_access_error(
        binding.verify_signed_receipt(&trailing),
        PairingAccessError::InvalidReceiptEncoding,
    );
}

#[test]
fn receipt_rejects_each_info_axis_and_independent_info_aad_fingerprint_faults() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let base_info = binding.info().clone();
    let base_context = binding.receipt_context().clone();
    let grant_hash = fixture.grant.canonical_sha256();
    let response_hash = fixture.response.canonical_sha256().expect("response hash");
    let mut cases = Vec::new();

    let mut info = base_info.clone();
    info.relay_server_id = RelayServerId::from_bytes([0x12; 16]);
    cases.push(("relay server", info, base_context.clone()));
    let mut info = base_info.clone();
    info.invite_hash[0] ^= 1;
    cases.push(("invite hash", info, base_context.clone()));
    let mut info = base_info.clone();
    info.expiry_ms += 1;
    cases.push(("expiry", info, base_context.clone()));
    let mut info = base_info.clone();
    info.machine_route = MachineRouteId::from_bytes([0x23; 16]);
    cases.push(("machine route", info, base_context.clone()));
    let mut info = base_info.clone();
    info.device_route = DeviceRouteId::from_bytes([0x34; 16]);
    cases.push(("device route", info, base_context.clone()));
    let mut info = base_info.clone();
    info.grant_serial = GrantSerial::new(GRANT_SERIAL.value() + 1);
    cases.push(("grant serial", info, base_context.clone()));
    let mut info = base_info.clone();
    info.root_trust_epoch = TrustEpoch::new(TRUST_EPOCH.value() + 1);
    cases.push(("trust epoch", info, base_context.clone()));
    let mut info = base_info.clone();
    info.pair_route = PairRouteId::from_bytes([0x45; 16]);
    let context = pairing_context(info.pair_route, OuterFrameKind::PairResponseReceived);
    cases.push(("pair route and AAD", info, context));

    for (axis, info, context) in cases {
        let receipt = signed_receipt(
            &fixture.device_signing_key,
            &info,
            &context,
            grant_hash,
            response_hash,
        );
        assert!(
            binding
                .verify_signed_receipt(&receipt.canonical_bytes().expect("axis receipt"))
                .is_err(),
            "changed {axis} must fail closed"
        );
    }

    let canonical = fixture
        .correct_receipt()
        .canonical_bytes()
        .expect("canonical receipt");
    let mut wrong_info_binding = fixture.binding();
    wrong_info_binding.info.expiry_ms += 1;
    assert_access_error(
        wrong_info_binding.verify_signed_receipt(&canonical),
        PairingAccessError::InvalidReceiptSignature,
    );
    let mut wrong_aad_binding = fixture.binding();
    wrong_aad_binding.receipt_context.pair_route = Some(PairRouteId::from_bytes([0x46; 16]));
    assert_access_error(
        wrong_aad_binding.verify_signed_receipt(&canonical),
        PairingAccessError::ReceiptBindingMismatch,
    );
    let mut wrong_fingerprint_binding = fixture.binding();
    wrong_fingerprint_binding.device_sign_fingerprint[0] ^= 1;
    assert_access_error(
        wrong_fingerprint_binding.verify_signed_receipt(&canonical),
        PairingAccessError::ReceiptBindingMismatch,
    );
}

#[test]
fn binding_reaudits_frozen_root_data_grant_and_response_signatures() {
    let fixture = Fixture::new();
    let mut invite = fixture.invite.clone();
    invite.data_sign_cert.signature.0[0] ^= 1;
    assert_access_error(
        PairResponseAccessBinding::from_frozen(
            &invite,
            REQUEST_HASH,
            &fixture.grant,
            &fixture.response,
        ),
        PairingAccessError::InvalidFrozenResponse,
    );

    let mut grant = fixture.grant.clone();
    grant.signature.0[0] ^= 1;
    assert_access_error(
        PairResponseAccessBinding::from_frozen(
            &fixture.invite,
            REQUEST_HASH,
            &grant,
            &fixture.response,
        ),
        PairingAccessError::InvalidFrozenResponse,
    );

    let mut response = fixture.response.clone();
    response.machine_data_signature.0[0] ^= 1;
    assert_access_error(
        PairResponseAccessBinding::from_frozen(
            &fixture.invite,
            REQUEST_HASH,
            &fixture.grant,
            &response,
        ),
        PairingAccessError::InvalidFrozenResponse,
    );
}

#[derive(Clone, Copy)]
enum RevocationMutation {
    None,
    MachineRoute,
    DeviceRoute,
    GrantSerial,
    RootKeyId,
    TrustEpoch,
    Signature,
    WrongKey,
}

struct TestRevocationAuthority {
    root: SigningKey,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    bad_fingerprint: bool,
    mutation: RevocationMutation,
}

impl TestRevocationAuthority {
    fn valid(mutation: RevocationMutation) -> Self {
        Self {
            root: SigningKey::from_seed(&ROOT_SEED),
            relay_server_id: RELAY,
            machine_route: MACHINE,
            root_key_id: ROOT_KEY_ID,
            trust_epoch: TRUST_EPOCH,
            bad_fingerprint: false,
            mutation,
        }
    }
}

impl RevocationCryptographicAuthority for TestRevocationAuthority {
    fn active_binding(&self) -> Result<MachineAuthorityBinding, PairingAccessError> {
        let root_public_key = PublicKeyBytes(self.root.verifying_key().to_bytes());
        let mut root_fingerprint = sha256(&root_public_key.0);
        if self.bad_fingerprint {
            root_fingerprint[0] ^= 1;
        }
        Ok(MachineAuthorityBinding {
            relay_server_id: self.relay_server_id,
            machine_route: self.machine_route,
            root_public_key,
            root_fingerprint,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
        })
    }

    fn sign_device_revocation(
        &self,
        mut revocation: DeviceRevocation,
    ) -> Result<DeviceRevocation, PairingAccessError> {
        let root_fingerprint = sha256(&self.root.verifying_key().to_bytes());
        let signing_key = if matches!(self.mutation, RevocationMutation::WrongKey) {
            SigningKey::from_seed(&[0xf1; 32])
        } else {
            SigningKey::from_seed(&ROOT_SEED)
        };
        revocation.signature = sign_tbs(
            &signing_key,
            &revocation.to_be_signed_v1(self.relay_server_id, root_fingerprint),
        )
        .into();
        match self.mutation {
            RevocationMutation::None | RevocationMutation::WrongKey => {}
            RevocationMutation::MachineRoute => {
                revocation.machine_route = MachineRouteId::from_bytes([0x24; 16]);
            }
            RevocationMutation::DeviceRoute => {
                revocation.device_route = DeviceRouteId::from_bytes([0x35; 16]);
            }
            RevocationMutation::GrantSerial => {
                revocation.grant_serial = GrantSerial::new(GRANT_SERIAL.value() + 1);
            }
            RevocationMutation::RootKeyId => {
                revocation.root_key_id = RootKeyId::from_bytes([0x56; 16]);
            }
            RevocationMutation::TrustEpoch => {
                revocation.trust_epoch = TrustEpoch::new(TRUST_EPOCH.value() + 1);
            }
            RevocationMutation::Signature => revocation.signature.0[0] ^= 1,
        }
        Ok(revocation)
    }
}

#[test]
fn revocation_freeze_is_root_signed_self_verified_redacted_and_stable() {
    let fixture = Fixture::new();
    let first = freeze_device_revocation_with(
        RELAY,
        &fixture.grant,
        &TestRevocationAuthority::valid(RevocationMutation::None),
    )
    .expect("freeze revocation");
    let second = freeze_device_revocation_with(
        RELAY,
        &fixture.grant,
        &TestRevocationAuthority::valid(RevocationMutation::None),
    )
    .expect("repeat revocation");
    assert_eq!(first.revocation().machine_route, MACHINE);
    assert_eq!(first.revocation().device_route, DEVICE);
    assert_eq!(first.revocation().grant_serial, GRANT_SERIAL);
    assert_eq!(first.canonical_revocation(), second.canonical_revocation());
    assert_eq!(first.revocation_hash(), second.revocation_hash());
    assert_eq!(
        first.revocation_hash(),
        sha256(first.canonical_revocation())
    );
    assert_eq!(format!("{first:?}"), "FrozenDeviceRevocation([REDACTED])");
    let consumed = second.into_revocation();
    assert_ne!(consumed.signature.0, [0; 64]);
}

#[test]
fn revocation_rejects_every_returned_axis_signature_and_wrong_key() {
    let fixture = Fixture::new();
    for mutation in [
        RevocationMutation::MachineRoute,
        RevocationMutation::DeviceRoute,
        RevocationMutation::GrantSerial,
        RevocationMutation::RootKeyId,
        RevocationMutation::TrustEpoch,
        RevocationMutation::Signature,
        RevocationMutation::WrongKey,
    ] {
        assert_access_error(
            freeze_device_revocation_with(
                RELAY,
                &fixture.grant,
                &TestRevocationAuthority::valid(mutation),
            ),
            PairingAccessError::RevocationSelfVerificationFailed,
        );
    }
}

#[test]
fn revocation_rejects_authority_grant_and_root_fingerprint_mismatch() {
    let fixture = Fixture::new();
    let mut authority = TestRevocationAuthority::valid(RevocationMutation::None);
    authority.machine_route = MachineRouteId::from_bytes([0x25; 16]);
    assert_access_error(
        freeze_device_revocation_with(RELAY, &fixture.grant, &authority),
        PairingAccessError::AuthorityMismatch,
    );
    assert_access_error(
        freeze_device_revocation_with(
            RelayServerId::from_bytes([0x13; 16]),
            &fixture.grant,
            &TestRevocationAuthority::valid(RevocationMutation::None),
        ),
        PairingAccessError::AuthorityMismatch,
    );

    let mut grant = fixture.grant.clone();
    grant.signature.0[0] ^= 1;
    assert_access_error(
        freeze_device_revocation_with(
            RELAY,
            &grant,
            &TestRevocationAuthority::valid(RevocationMutation::None),
        ),
        PairingAccessError::InvalidRevocationGrant,
    );
    let mut bad_fingerprint = TestRevocationAuthority::valid(RevocationMutation::None);
    bad_fingerprint.bad_fingerprint = true;
    assert_access_error(
        freeze_device_revocation_with(RELAY, &fixture.grant, &bad_fingerprint),
        PairingAccessError::AuthorityMismatch,
    );
}

#[test]
fn failure_codes_are_stable_and_nonempty() {
    let errors = [
        PairingAccessError::InvalidFrozenResponse,
        PairingAccessError::InvalidReceiptEncoding,
        PairingAccessError::ReceiptBindingMismatch,
        PairingAccessError::InvalidReceiptSignature,
        PairingAccessError::AuthorityUnavailable,
        PairingAccessError::AuthorityMismatch,
        PairingAccessError::InvalidRevocationGrant,
        PairingAccessError::RevocationSigningFailed,
        PairingAccessError::RevocationSelfVerificationFailed,
    ];
    for error in errors {
        assert!(error.code().starts_with("daemon.pairing."));
        assert!(!error.to_string().contains("0x"));
    }
}
