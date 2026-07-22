use std::cell::RefCell;

use agentdeck_crypto::rand_core::{Rng, SeedableRng};
use agentdeck_crypto::{
    HpkePrivateKey, PairResponseSealAuthority, SigningKey, open_key_directory_entry,
    open_pair_response, seal_key_directory_entry, seal_pair_response, sign_device_authorization,
    sign_key_directory, sign_tbs, verify_pair_response_envelope,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    MachineDataSignerBindingV1,
};
use agentdeck_protocol::relay_v2::{CertRole, PairRouteId};
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::runtime::store::RuntimeIdKind;

const TEST_RELAY: RelayServerId = RelayServerId::from_bytes([0x11; 16]);
const TEST_MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x22; 16]);
const TEST_PAIR_ROUTE: PairRouteId = PairRouteId::from_bytes([0x33; 16]);
const TEST_ROOT_KEY_ID: RootKeyId = RootKeyId::from_bytes([0x44; 16]);
const TEST_TRUST_EPOCH: TrustEpoch = TrustEpoch::new(2);
const TEST_DATA_GENERATION: LinkGeneration = LinkGeneration::new(3);

struct TestAuthority {
    binding: AuthorityBinding,
    root: SigningKey,
    data: SigningKey,
    signer: MachineDataSignerBindingV1,
    rng: RefCell<ChaCha20Rng>,
    fail_wrap: bool,
}

impl TestAuthority {
    fn new(binding: AuthorityBinding, root: SigningKey, data: SigningKey, fail_wrap: bool) -> Self {
        let signer = MachineDataSignerBindingV1::from_certificate(&binding.data_certificate)
            .expect("valid data signer binding");
        Self {
            binding,
            root,
            data,
            signer,
            rng: RefCell::new(ChaCha20Rng::from_seed([0x91; 32])),
            fail_wrap,
        }
    }
}

impl GrantCryptographicAuthority for TestAuthority {
    fn active_binding(&self) -> Result<AuthorityBinding, GrantFreezeError> {
        Ok(self.binding.clone())
    }

    fn sign_relay_grant(&self, mut grant: RelayGrant) -> Result<RelayGrant, GrantFreezeError> {
        grant.signature = sign_tbs(
            &self.root,
            &grant.to_be_signed_v1(self.binding.relay_server_id, self.binding.root_fingerprint),
        )
        .into();
        Ok(grant)
    }

    fn sign_device_authorization(
        &self,
        grant: &RelayGrant,
        authorization: DeviceAuthorizationV1,
    ) -> Result<DeviceAuthorizationV1, GrantFreezeError> {
        sign_device_authorization(
            &self.root,
            self.binding.relay_server_id,
            grant,
            authorization,
        )
        .map_err(|_| GrantFreezeError::CryptoFailure)
    }

    fn seal_key_directory_entry(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
    ) -> Result<KeyDirectoryEntry, GrantFreezeError> {
        if self.fail_wrap {
            return Err(GrantFreezeError::CryptoFailure);
        }
        seal_key_directory_entry(recipient, info, context, key, &mut *self.rng.borrow_mut())
            .map_err(|_| GrantFreezeError::CryptoFailure)
    }

    fn sign_key_directory(
        &self,
        context: &KeyDirectorySignatureContextV1,
        directory: KeyDirectoryV1,
    ) -> Result<KeyDirectoryV1, GrantFreezeError> {
        sign_key_directory(&self.data, &self.signer, context, directory)
            .map_err(|_| GrantFreezeError::CryptoFailure)
    }

    fn seal_pair_response(
        &self,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
    ) -> Result<PairResponseV1, GrantFreezeError> {
        seal_pair_response(
            recipient,
            info,
            context,
            plaintext,
            PairResponseSealAuthority {
                machine_data_signing_key: &self.data,
                signer: &self.signer,
                machine_root_verifying_key: &self.root.verifying_key(),
            },
            &mut *self.rng.borrow_mut(),
        )
        .map_err(|_| GrantFreezeError::CryptoFailure)
    }
}

struct Fixture {
    pairing_id: RuntimeId,
    root: SigningKey,
    data: SigningKey,
    device_hpke_private: HpkePrivateKey,
    invite: PairInviteV1,
    request: PairRequestPlaintextV1,
    request_hash: [u8; 32],
    binding: AuthorityBinding,
}

impl Fixture {
    fn new() -> Self {
        let root = SigningKey::from_seed(&[0x51; 32]);
        let data = SigningKey::from_seed(&[0x52; 32]);
        let device_sign = SigningKey::from_seed(&[0x53; 32]);
        let (device_hpke_private, device_hpke_public) = HpkePrivateKey::derive_keypair(&[0x54; 32]);
        let root_fingerprint = sha256(&root.verifying_key().to_bytes());
        let mut data_certificate = SignedCertificate {
            subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
            cert_role: CertRole::Data,
            generation: TEST_DATA_GENERATION,
            root_key_id: TEST_ROOT_KEY_ID,
            trust_epoch: TEST_TRUST_EPOCH,
            not_after_ms: None,
            signature: Ed25519Signature([0; 64]),
        };
        data_certificate.signature = sign_tbs(
            &root,
            &data_certificate.to_be_signed_v1(TEST_RELAY, TEST_MACHINE, root_fingerprint),
        )
        .into();
        let binding = AuthorityBinding {
            relay_server_id: TEST_RELAY,
            machine_route: TEST_MACHINE,
            root_public_key: PublicKeyBytes(root.verifying_key().to_bytes()),
            root_fingerprint,
            root_key_id: TEST_ROOT_KEY_ID,
            trust_epoch: TEST_TRUST_EPOCH,
            data_generation: TEST_DATA_GENERATION,
            data_certificate: data_certificate.clone(),
        };
        let device_hpke_pubkey = PublicKeyBytes(
            device_hpke_public
                .to_bytes()
                .try_into()
                .expect("X25519 public key is 32 bytes"),
        );
        let invite = PairInviteV1 {
            format_version: E2EE_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            pair_route: TEST_PAIR_ROUTE,
            invite_secret: [0x61; 32],
            invite_hpke_pubkey: PublicKeyBytes([0x62; 32]),
            wss_url: "wss://relay.example/".to_owned(),
            relay_server_id: TEST_RELAY,
            current_spki_pin: [0x63; 32],
            next_spki_pin: [0x64; 32],
            expires_at_ms: 1_900_000_000_000,
            machine_root_pubkey: binding.root_public_key,
            machine_root_fingerprint: root_fingerprint,
            data_sign_cert: data_certificate,
            machine_display_name: "Test Machine".to_owned(),
        };
        let request = PairRequestPlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            invite_secret: invite.invite_secret,
            device_sign_pubkey: PublicKeyBytes(device_sign.verifying_key().to_bytes()),
            device_hpke_pubkey,
            authorization_request: full_authorization_request(),
        };
        Self {
            pairing_id: RuntimeId::from_bytes(RuntimeIdKind::Pairing, [0x65; 16])
                .expect("pairing id"),
            root,
            data,
            device_hpke_private,
            invite,
            request,
            request_hash: [0x66; 32],
            binding,
        }
    }

    fn material(&self) -> FrozenRequestMaterial<'_> {
        FrozenRequestMaterial {
            pairing_id: self.pairing_id,
            invite: &self.invite,
            request_hash: self.request_hash,
            request: &self.request,
        }
    }

    fn authority(&self) -> TestAuthority {
        TestAuthority::new(
            self.binding.clone(),
            SigningKey::from_seed(&[0x51; 32]),
            SigningKey::from_seed(&[0x52; 32]),
            false,
        )
    }

    fn authority_failing_wrap(&self) -> TestAuthority {
        TestAuthority::new(
            self.binding.clone(),
            SigningKey::from_seed(&[0x51; 32]),
            SigningKey::from_seed(&[0x52; 32]),
            true,
        )
    }

    fn with_device_sign_seed(mut self, seed: u8) -> Self {
        let device_sign = SigningKey::from_seed(&[seed; 32]);
        self.request.device_sign_pubkey = PublicKeyBytes(device_sign.verifying_key().to_bytes());
        self
    }

    fn device_sign_fingerprint(&self) -> [u8; 32] {
        sha256(&self.request.device_sign_pubkey.0)
    }
}

fn full_authorization_request() -> AuthorizationRequestV1 {
    AuthorizationRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        device_display_name: "Remote Device".to_owned(),
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
    }
}

fn deterministic_entropy(first: u8) -> impl FnMut(&mut [u8]) -> Result<(), GrantFreezeError> {
    let mut marker = first.max(1);
    move |output| {
        output.fill(marker);
        marker = marker.checked_add(1).unwrap_or(1).max(1);
        Ok(())
    }
}

fn seeded_entropy(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), GrantFreezeError> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    move |output| {
        rng.fill_bytes(output);
        Ok(())
    }
}

fn indexed_stream(index: u16) -> StreamRouteId {
    assert_ne!(index, 0);
    let mut bytes = [0_u8; 16];
    bytes[14..].copy_from_slice(&index.to_be_bytes());
    StreamRouteId::from_bytes(bytes)
}

fn freeze_fixture(
    fixture: &Fixture,
    current: Option<GlobalKeyStateV1>,
    revision: KeyDirectoryRevision,
    entropy_marker: u8,
) -> Result<FrozenGrantArtifacts, GrantFreezeError> {
    freeze_with(
        fixture.material(),
        fixture.binding.clone(),
        current,
        GrantSerial::new(1),
        revision,
        &fixture.authority(),
        deterministic_entropy(entropy_marker),
    )
}

#[test]
fn freezes_exact_bootstrap_directory_and_verifiable_outer_response() {
    let fixture = Fixture::new();
    let frozen = freeze_fixture(&fixture, None, KeyDirectoryRevision::new(1), 1)
        .expect("freeze first grant");

    assert_eq!(frozen.relay_grant().machine_route, TEST_MACHINE);
    assert_eq!(frozen.relay_grant().grant_serial, GrantSerial::new(1));
    assert_eq!(
        frozen.key_directory().revision,
        KeyDirectoryRevision::new(1)
    );
    assert_eq!(frozen.key_directory().entries.len(), 3);
    assert_eq!(
        frozen
            .key_directory()
            .entries
            .iter()
            .map(|entry| entry.key_id.purpose)
            .collect::<Vec<_>>(),
        vec![
            KeyPurpose::Catalog,
            KeyPurpose::DeviceCommandTx,
            KeyPurpose::DeviceReplyTx,
        ]
    );
    assert!(
        frozen
            .key_directory()
            .entries
            .iter()
            .all(|entry| entry.stream_route.is_none())
    );
    assert!(
        frozen
            .key_directory()
            .entries
            .iter()
            .all(|entry| entry.key_id.purpose != KeyPurpose::ConversationDek)
    );

    let signer = MachineDataSignerBindingV1::from_certificate(&fixture.invite.data_sign_cert)
        .expect("signer binding");
    verify_pair_response_envelope(
        &fixture.data.verifying_key(),
        frozen.response_info(),
        frozen.response_context(),
        frozen.pair_response(),
        &signer,
    )
    .expect("outer response signature");
    let opened = open_pair_response(
        &fixture.device_hpke_private,
        frozen.response_info(),
        frozen.response_context(),
        frozen.pair_response(),
        &fixture.data.verifying_key(),
        &signer,
        &fixture.root.verifying_key(),
    )
    .expect("open exact PairResponse");
    assert_eq!(opened.request_hash, fixture.request_hash);
    assert_eq!(opened.relay_grant, *frozen.relay_grant());
    assert_eq!(opened.device_authorization, *frozen.device_authorization());
    assert_eq!(opened.key_directory, *frozen.key_directory());
}

#[test]
fn every_bootstrap_entry_is_typed_hpke_bound_and_openable() {
    let fixture = Fixture::new();
    let frozen = freeze_fixture(&fixture, None, KeyDirectoryRevision::new(1), 11)
        .expect("freeze first grant");
    for entry in &frozen.key_directory().entries {
        let info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: TEST_RELAY,
            machine_route: TEST_MACHINE,
            device_route: frozen.relay_grant().device_route,
            stream_route: None,
            grant_serial: GrantSerial::new(1),
            root_trust_epoch: TEST_TRUST_EPOCH,
            key_directory_revision: KeyDirectoryRevision::new(1),
            key_purpose: entry.key_id.purpose,
            key_epoch: entry.key_id.epoch,
        };
        open_key_directory_entry(
            &fixture.device_hpke_private,
            &info,
            &key_update_context(&info),
            entry,
        )
        .expect("typed wrapped key must open on exact axes");
    }
}

#[test]
fn rejects_wrong_request_device_keys_authorization_and_anchor_before_entropy() {
    let mut cases = Vec::new();

    let mut wrong_secret = Fixture::new();
    wrong_secret.request.invite_secret = [0x99; 32];
    cases.push((wrong_secret, GrantFreezeError::InvalidFrozenRequest));

    let mut wrong_hash = Fixture::new();
    wrong_hash.request_hash = [0; 32];
    cases.push((wrong_hash, GrantFreezeError::InvalidFrozenRequest));

    let mut wrong_sign = Fixture::new();
    wrong_sign.request.device_sign_pubkey = PublicKeyBytes([0; 32]);
    cases.push((wrong_sign, GrantFreezeError::InvalidFrozenRequest));

    let mut wrong_hpke = Fixture::new();
    wrong_hpke.request.device_hpke_pubkey = PublicKeyBytes([0; 32]);
    cases.push((wrong_hpke, GrantFreezeError::InvalidFrozenRequest));

    let mut wrong_auth = Fixture::new();
    wrong_auth
        .request
        .authorization_request
        .capabilities
        .clear();
    cases.push((wrong_auth, GrantFreezeError::InvalidFrozenRequest));

    for (fixture, expected) in cases {
        let mut entropy_calls = 0;
        let error = freeze_with(
            fixture.material(),
            fixture.binding.clone(),
            None,
            GrantSerial::new(1),
            KeyDirectoryRevision::new(1),
            &fixture.authority(),
            |output| {
                entropy_calls += 1;
                output.fill(1);
                Ok(())
            },
        )
        .expect_err("invalid frozen request must fail");
        assert_eq!(error, expected);
        assert_eq!(entropy_calls, 0, "validation must precede entropy");
    }

    let fixture = Fixture::new();
    let mut wrong_anchor = fixture.binding.clone();
    wrong_anchor.machine_route = MachineRouteId::from_bytes([0xaa; 16]);
    let mut entropy_calls = 0;
    let error = freeze_with(
        fixture.material(),
        wrong_anchor,
        None,
        GrantSerial::new(1),
        KeyDirectoryRevision::new(1),
        &fixture.authority(),
        |output| {
            entropy_calls += 1;
            output.fill(1);
            Ok(())
        },
    )
    .expect_err("wrong active anchor must fail");
    assert_eq!(error, GrantFreezeError::AuthorityMismatch);
    assert_eq!(entropy_calls, 0);
}

#[test]
fn rejects_wrong_serial_and_revision_before_entropy() {
    let fixture = Fixture::new();
    for (serial, revision, expected) in [
        (
            GrantSerial::new(2),
            KeyDirectoryRevision::new(1),
            GrantFreezeError::InvalidGrantSerial,
        ),
        (
            GrantSerial::new(1),
            KeyDirectoryRevision::new(2),
            GrantFreezeError::InvalidKeyDirectoryRevision,
        ),
    ] {
        let mut entropy_calls = 0;
        let error = freeze_with(
            fixture.material(),
            fixture.binding.clone(),
            None,
            serial,
            revision,
            &fixture.authority(),
            |output| {
                entropy_calls += 1;
                output.fill(1);
                Ok(())
            },
        )
        .expect_err("wrong monotonic axis must fail");
        assert_eq!(error, expected);
        assert_eq!(entropy_calls, 0);
    }
}

#[test]
fn current_global_state_requires_checked_next_revision() {
    let first_fixture = Fixture::new();
    let first = freeze_fixture(&first_fixture, None, KeyDirectoryRevision::new(1), 21)
        .expect("first state");
    let state = first.global_key_state;
    let second_fixture = Fixture::new();
    let error = freeze_fixture(
        &second_fixture,
        Some(state),
        KeyDirectoryRevision::new(1),
        31,
    )
    .expect_err("revision rollback must fail");
    assert_eq!(error, GrantFreezeError::InvalidKeyDirectoryRevision);

    let first_fixture = Fixture::new();
    let first = freeze_fixture(&first_fixture, None, KeyDirectoryRevision::new(1), 21)
        .expect("fresh first state");
    let second_fixture = Fixture::new();
    let second = freeze_fixture(
        &second_fixture,
        Some(first.global_key_state),
        KeyDirectoryRevision::new(2),
        31,
    )
    .expect("checked next state");
    assert_eq!(
        second
            .key_directory()
            .entries
            .iter()
            .map(|entry| (entry.key_id.purpose, entry.key_id.epoch))
            .collect::<Vec<_>>(),
        vec![
            (KeyPurpose::Catalog, 2),
            (KeyPurpose::DeviceCommandTx, 1),
            (KeyPurpose::DeviceReplyTx, 1),
        ]
    );
}

#[test]
fn entropy_and_hpke_wrap_failures_return_without_artifacts() {
    let fixture = Fixture::new();
    let error = freeze_with(
        fixture.material(),
        fixture.binding.clone(),
        None,
        GrantSerial::new(1),
        KeyDirectoryRevision::new(1),
        &fixture.authority(),
        |_| Err(GrantFreezeError::EntropyUnavailable),
    )
    .expect_err("OS entropy failure must be typed");
    assert_eq!(error, GrantFreezeError::EntropyUnavailable);
    assert_eq!(error.code(), "daemon.pairing.entropy_unavailable");

    let mut zero_draws = 0;
    let error = freeze_with(
        fixture.material(),
        fixture.binding.clone(),
        None,
        GrantSerial::new(1),
        KeyDirectoryRevision::new(1),
        &fixture.authority(),
        |output| {
            zero_draws += 1;
            output.fill(0);
            Ok(())
        },
    )
    .expect_err("continuous all-zero entropy must not mint a route");
    assert_eq!(error, GrantFreezeError::EntropyUnavailable);
    assert_eq!(zero_draws, ENTROPY_ATTEMPTS);

    let error = freeze_with(
        fixture.material(),
        fixture.binding.clone(),
        None,
        GrantSerial::new(1),
        KeyDirectoryRevision::new(1),
        &fixture.authority_failing_wrap(),
        deterministic_entropy(41),
    )
    .expect_err("HPKE wrap failure must abort bundle");
    assert_eq!(error, GrantFreezeError::CryptoFailure);
}

#[test]
fn frozen_bundle_is_byte_stable_and_debug_is_redacted() {
    let left_fixture = Fixture::new();
    let left =
        freeze_fixture(&left_fixture, None, KeyDirectoryRevision::new(1), 51).expect("left freeze");
    let right_fixture = Fixture::new();
    let right = freeze_fixture(&right_fixture, None, KeyDirectoryRevision::new(1), 51)
        .expect("right freeze");

    assert_eq!(
        left.relay_grant().canonical_bytes(),
        right.relay_grant().canonical_bytes()
    );
    assert_eq!(
        left.device_authorization().canonical_bytes().unwrap(),
        right.device_authorization().canonical_bytes().unwrap()
    );
    assert_eq!(
        left.key_directory().canonical_bytes().unwrap(),
        right.key_directory().canonical_bytes().unwrap()
    );
    assert_eq!(
        left.pair_response().canonical_bytes().unwrap(),
        right.pair_response().canonical_bytes().unwrap()
    );
    assert_eq!(left.grant_hash(), left.relay_grant().canonical_sha256());
    assert_eq!(
        left.authorization_hash(),
        left.device_authorization().canonical_sha256().unwrap()
    );
    assert_eq!(
        left.key_directory_hash(),
        left.key_directory().canonical_sha256().unwrap()
    );
    assert_eq!(
        left.response_hash(),
        left.pair_response().canonical_sha256().unwrap()
    );

    let debug = format!("{left:?}");
    assert_eq!(debug, "FrozenGrantArtifacts([REDACTED])");
    assert!(
        !debug.contains(
            &left_fixture
                .request
                .authorization_request
                .device_display_name
        )
    );
    assert!(!debug.contains("Remote Device"));
    assert!(!debug.contains("515151"));

    let store_input = right.into_store_input();
    assert_eq!(
        format!("{store_input:?}"),
        "ConfirmPairingGrant([REDACTED])"
    );
}

#[test]
fn fresh_fingerprint_gets_serial_one_and_a_random_nonzero_route() {
    let fixture = Fixture::new();
    let fingerprint = fixture.device_sign_fingerprint();
    let projection = GrantAllocationProjection::New {
        device_sign_fingerprint: fingerprint,
        current_global_keys: None,
        active_conversation_routes: Vec::new(),
    };
    let (allocation, current_global_keys, active_conversation_routes) =
        GrantAllocation::from_projection(projection).expect("authenticated fresh allocation");
    assert!(active_conversation_routes.is_empty());
    assert_eq!(allocation.device_sign_fingerprint(), fingerprint);
    assert_eq!(allocation.device_route(), None);
    assert_eq!(allocation.grant_serial(), GrantSerial::new(1));

    let frozen = freeze_with_allocation(
        fixture.material(),
        fixture.binding.clone(),
        current_global_keys,
        allocation,
        KeyDirectoryRevision::new(1),
        &fixture.authority(),
        deterministic_entropy(71),
    )
    .expect("freeze fresh allocation");
    assert_ne!(frozen.relay_grant().device_route.as_bytes(), &[0; 16]);
    assert_eq!(frozen.relay_grant().grant_serial, GrantSerial::new(1));
    assert_eq!(
        frozen.device_authorization().device_sign_fingerprint,
        fingerprint
    );
}

#[test]
fn first_grant_bootstraps_authenticated_conversation_routes_in_single_revision() {
    let fixture = Fixture::new();
    let active_conversation_routes = vec![
        StreamRouteId::from_bytes([0x31; 16]),
        StreamRouteId::from_bytes([0x32; 16]),
    ];
    let projection = GrantAllocationProjection::New {
        device_sign_fingerprint: fixture.device_sign_fingerprint(),
        current_global_keys: None,
        active_conversation_routes: active_conversation_routes.clone(),
    };
    let (allocation, current_global_keys, authenticated_routes) =
        GrantAllocation::from_projection(projection).expect("authenticated initial allocation");
    let frozen = freeze_with_authenticated_allocation(
        fixture.material(),
        fixture.binding.clone(),
        current_global_keys,
        authenticated_routes,
        allocation,
        KeyDirectoryRevision::new(1),
        &fixture.authority(),
        deterministic_entropy(73),
    )
    .expect("freeze first grant with deferred conversation routes");

    assert_eq!(
        frozen.global_key_state.revision(),
        KeyDirectoryRevision::new(1),
        "all initial keys belong to the single 0 -> 1 revision"
    );
    assert_eq!(
        frozen.global_key_state.active_conversation_routes(),
        active_conversation_routes
    );
    assert_eq!(
        frozen.key_directory().revision,
        KeyDirectoryRevision::new(1)
    );
    frozen
        .key_directory()
        .validate_initial_directory_for_device(
            frozen.relay_grant().device_route,
            &active_conversation_routes,
        )
        .expect("initial directory exactly covers authenticated routes");
    let conversation_entries = frozen
        .key_directory()
        .entries
        .iter()
        .filter(|entry| entry.key_id.purpose == KeyPurpose::ConversationDek)
        .collect::<Vec<_>>();
    assert_eq!(conversation_entries.len(), 2);
    assert!(
        conversation_entries
            .iter()
            .all(|entry| entry.key_id.epoch == 1)
    );
}

#[test]
fn first_grant_supports_full_conversation_capacity_in_openable_pair_response() {
    let fixture = Fixture::new();
    let active_conversation_routes = (1_u16..=1_024).map(indexed_stream).collect::<Vec<_>>();
    let projection = GrantAllocationProjection::New {
        device_sign_fingerprint: fixture.device_sign_fingerprint(),
        current_global_keys: None,
        active_conversation_routes: active_conversation_routes.clone(),
    };
    let (allocation, current_global_keys, authenticated_routes) =
        GrantAllocation::from_projection(projection).expect("authenticated maximum allocation");
    let frozen = freeze_with_authenticated_allocation(
        fixture.material(),
        fixture.binding.clone(),
        current_global_keys,
        authenticated_routes,
        allocation,
        KeyDirectoryRevision::new(1),
        &fixture.authority(),
        seeded_entropy(0x75),
    )
    .expect("freeze first grant at the full conversation capacity");

    assert_eq!(
        frozen.global_key_state.active_conversation_routes(),
        active_conversation_routes
    );
    assert_eq!(frozen.key_directory().entries.len(), 1_027);
    frozen
        .key_directory()
        .validate_initial_directory_for_device(
            frozen.relay_grant().device_route,
            &active_conversation_routes,
        )
        .expect("maximum initial directory covers every authenticated route");
    assert!(
        frozen.pair_response().ciphertext.len() <= 256 * 1_024,
        "maximum initial directory must remain inside the PairResponse ciphertext cap"
    );

    let signer = MachineDataSignerBindingV1::from_certificate(&fixture.invite.data_sign_cert)
        .expect("signer binding");
    let opened = open_pair_response(
        &fixture.device_hpke_private,
        frozen.response_info(),
        frozen.response_context(),
        frozen.pair_response(),
        &fixture.data.verifying_key(),
        &signer,
        &fixture.root.verifying_key(),
    )
    .expect("open maximum PairResponse");
    assert_eq!(opened.key_directory, *frozen.key_directory());

    for entry in &opened.key_directory.entries {
        let info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: TEST_RELAY,
            machine_route: TEST_MACHINE,
            device_route: frozen.relay_grant().device_route,
            stream_route: entry.stream_route,
            grant_serial: GrantSerial::new(1),
            root_trust_epoch: TEST_TRUST_EPOCH,
            key_directory_revision: KeyDirectoryRevision::new(1),
            key_purpose: entry.key_id.purpose,
            key_epoch: entry.key_id.epoch,
        };
        open_key_directory_entry(
            &fixture.device_hpke_private,
            &info,
            &key_update_context(&info),
            entry,
        )
        .expect("every maximum-directory HPKE entry opens on its exact axes");
    }
}

#[test]
fn renewal_reuses_route_advances_serial_and_rotates_only_target_device_keys() {
    let first_fixture = Fixture::new();
    let first = freeze_fixture(&first_fixture, None, KeyDirectoryRevision::new(1), 81)
        .expect("first device state");
    let first_route = first.relay_grant().device_route;

    let second_fixture = Fixture::new().with_device_sign_seed(0x73);
    let second = freeze_fixture(
        &second_fixture,
        Some(first.global_key_state),
        KeyDirectoryRevision::new(2),
        91,
    )
    .expect("second device state");
    let second_route = second.relay_grant().device_route;
    assert_ne!(first_route, second_route);

    let first_before = second
        .global_key_state
        .key_axes_for_test(first_route)
        .expect("first device key axes before renewal");
    let second_before = second
        .global_key_state
        .key_axes_for_test(second_route)
        .expect("second device key axes before renewal");
    let projection = GrantAllocationProjection::Renew {
        device_sign_fingerprint: first_fixture.device_sign_fingerprint(),
        device_route: first_route,
        current_serial: GrantSerial::new(1),
        next_serial: GrantSerial::new(2),
        current_global_keys: second.global_key_state,
    };
    let (allocation, current_global_keys, _active_conversation_routes) =
        GrantAllocation::from_projection(projection).expect("authenticated renewal allocation");
    let renewed = freeze_with_allocation(
        first_fixture.material(),
        first_fixture.binding.clone(),
        current_global_keys,
        allocation,
        KeyDirectoryRevision::new(3),
        &first_fixture.authority(),
        deterministic_entropy(101),
    )
    .expect("freeze renewal");

    assert_eq!(renewed.relay_grant().device_route, first_route);
    assert_eq!(renewed.relay_grant().grant_serial, GrantSerial::new(2));
    assert_eq!(
        renewed.key_directory().revision,
        KeyDirectoryRevision::new(3)
    );
    assert_eq!(renewed.global_key_state.revision().value(), 3);
    assert_eq!(renewed.global_key_state.device_count(), 2);

    let first_after = renewed
        .global_key_state
        .key_axes_for_test(first_route)
        .expect("first device key axes after renewal");
    let second_after = renewed
        .global_key_state
        .key_axes_for_test(second_route)
        .expect("second device key axes after renewal");
    assert_eq!(first_after.catalog_epoch, first_before.catalog_epoch + 1);
    assert_ne!(first_after.catalog_hash, first_before.catalog_hash);
    assert_eq!(first_after.command_epoch, first_before.command_epoch + 1);
    assert_ne!(first_after.command_hash, first_before.command_hash);
    assert_eq!(first_after.reply_epoch, first_before.reply_epoch + 1);
    assert_ne!(first_after.reply_hash, first_before.reply_hash);
    assert_eq!(second_after.command_epoch, second_before.command_epoch);
    assert_eq!(second_after.command_hash, second_before.command_hash);
    assert_eq!(second_after.reply_epoch, second_before.reply_epoch);
    assert_eq!(second_after.reply_hash, second_before.reply_hash);
    assert_eq!(second_after.catalog_epoch, first_after.catalog_epoch);
    assert_eq!(second_after.catalog_hash, first_after.catalog_hash);

    assert_eq!(
        renewed
            .key_directory()
            .entries
            .iter()
            .map(|entry| (entry.key_id.purpose, entry.key_id.epoch))
            .collect::<Vec<_>>(),
        vec![
            (KeyPurpose::Catalog, 3),
            (KeyPurpose::DeviceCommandTx, 2),
            (KeyPurpose::DeviceReplyTx, 2),
        ]
    );
}

#[test]
fn max_serial_and_revoked_route_fail_before_entropy_or_artifacts() {
    let fixture = Fixture::new();
    let fingerprint = fixture.device_sign_fingerprint();
    let route = DeviceRouteId::from_bytes([0x7a; 16]);
    let mut max_entropy_calls = 0;

    let max_error = GrantAllocation::from_authenticated(
        fingerprint,
        GrantAllocationState::Active {
            device_route: route,
            current_serial: GrantSerial::new(u64::MAX),
        },
    )
    .and_then(|allocation| {
        freeze_with_allocation(
            fixture.material(),
            fixture.binding.clone(),
            None,
            allocation,
            KeyDirectoryRevision::new(1),
            &fixture.authority(),
            |output| {
                max_entropy_calls += 1;
                output.fill(1);
                Ok(())
            },
        )
    })
    .expect_err("MAX serial requires trust reset");
    assert_eq!(max_error, GrantFreezeError::GrantSerialTrustResetRequired);
    assert_eq!(
        max_error.code(),
        "daemon.pairing.grant_serial_trust_reset_required"
    );
    assert_eq!(max_entropy_calls, 0);

    let mut revoked_entropy_calls = 0;
    let revoked_error = GrantAllocation::from_authenticated(
        fingerprint,
        GrantAllocationState::Revoked {
            device_route: route,
            last_serial: GrantSerial::new(7),
        },
    )
    .and_then(|allocation| {
        freeze_with_allocation(
            fixture.material(),
            fixture.binding.clone(),
            None,
            allocation,
            KeyDirectoryRevision::new(1),
            &fixture.authority(),
            |output| {
                revoked_entropy_calls += 1;
                output.fill(1);
                Ok(())
            },
        )
    })
    .expect_err("revoked route cannot be renewed");
    assert_eq!(revoked_error, GrantFreezeError::GrantRouteRevoked);
    assert_eq!(revoked_error.code(), "daemon.pairing.grant_route_revoked");
    assert_eq!(revoked_entropy_calls, 0);
}

#[test]
fn malformed_allocation_shapes_fail_before_entropy() {
    let fixture = Fixture::new();
    let fingerprint = fixture.device_sign_fingerprint();
    let route = DeviceRouteId::from_bytes([0x7b; 16]);
    let cases = [
        (
            GrantAllocation {
                device_sign_fingerprint: [0x99; 32],
                device_route: None,
                previous_serial: None,
                grant_serial: GrantSerial::new(1),
            },
            GrantFreezeError::InvalidGrantAllocation,
        ),
        (
            GrantAllocation {
                device_sign_fingerprint: fingerprint,
                device_route: Some(DeviceRouteId::from_bytes([0; 16])),
                previous_serial: Some(GrantSerial::new(1)),
                grant_serial: GrantSerial::new(2),
            },
            GrantFreezeError::InvalidGrantAllocation,
        ),
        (
            GrantAllocation {
                device_sign_fingerprint: fingerprint,
                device_route: Some(route),
                previous_serial: Some(GrantSerial::new(1)),
                grant_serial: GrantSerial::new(3),
            },
            GrantFreezeError::InvalidGrantSerial,
        ),
        (
            GrantAllocation {
                device_sign_fingerprint: fingerprint,
                device_route: None,
                previous_serial: Some(GrantSerial::new(1)),
                grant_serial: GrantSerial::new(2),
            },
            GrantFreezeError::InvalidGrantAllocation,
        ),
        (
            GrantAllocation {
                device_sign_fingerprint: fingerprint,
                device_route: Some(route),
                previous_serial: None,
                grant_serial: GrantSerial::new(1),
            },
            GrantFreezeError::InvalidGrantAllocation,
        ),
        (
            GrantAllocation {
                device_sign_fingerprint: fingerprint,
                device_route: None,
                previous_serial: None,
                grant_serial: GrantSerial::new(2),
            },
            GrantFreezeError::InvalidGrantSerial,
        ),
    ];

    for (allocation, expected) in cases {
        let mut entropy_calls = 0;
        let error = freeze_with_allocation(
            fixture.material(),
            fixture.binding.clone(),
            None,
            allocation,
            KeyDirectoryRevision::new(1),
            &fixture.authority(),
            |output| {
                entropy_calls += 1;
                output.fill(1);
                Ok(())
            },
        )
        .expect_err("malformed allocation must fail");
        assert_eq!(error, expected);
        assert_eq!(
            entropy_calls, 0,
            "allocation validation must precede entropy"
        );
    }
}
