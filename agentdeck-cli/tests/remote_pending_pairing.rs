use std::convert::Infallible;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use agentdeck_cli::remote::crypto_state::{
    CryptoStateIdentity, DeviceStorageKek, FileCryptoStateStore,
};
use agentdeck_cli::remote::device_lock::{RemoteDeviceLease, RemoteDeviceLockKey};
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, ParsedPairedRemoteKeyAccount,
    PendingRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyPersistence, RemoteKeyStore,
    RemoteKeyStoreError, RemoteSecret,
};
use agentdeck_cli::remote::paired_machine::{
    PairedMachineIdentity, PairedMachineStore, PairedMutationObserver, PairedMutationStage,
    PairedPromotionCoordinator, PromotedPairedMachine,
};
use agentdeck_cli::remote::pending::{PendingPairingCoordinator, PreparedPairRequest};
use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    HpkePrivateKey, PairResponseSealAuthority, SecretAeadKey, SigningKey, VerifyingKey,
    open_pair_request, open_pair_response_received, seal_key_directory_entry, seal_pair_response,
    sha256, sign_device_authorization, sign_key_directory, sign_tbs,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    DeviceAuthorizationV1, E2EE_FORMAT_VERSION, KeyDirectorySignatureContextV1, KeyDirectoryV1,
    KeyPurpose, KeyUpdateInfoV1, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
    PairInviteV1, PairRequestInfoV1, PairRequestPlaintextV1, PairRequestV1, PairResponseInfoV1,
    PairResponsePlaintextV1, PairResponseV1, PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::{
    CertRole, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId, PairRouteId,
    RelayServerId, RootKeyId, TrustEpoch,
};
use agentdeck_protocol::runtime::{MachineRootFingerprint, RUNTIME_PROTOCOL_VERSION};
use uuid::Uuid;

const NOW_MS: u64 = 1_900_000_000_000;
const INSTALLATION_ID: Uuid = Uuid::from_bytes([0x11; 16]);
const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x21; 16]);
const DEVICE_ROUTE: DeviceRouteId = DeviceRouteId::from_bytes([0x25; 16]);
const PAIR_ROUTE: PairRouteId = PairRouteId::from_bytes([0x22; 16]);
const RELAY_SERVER: RelayServerId = RelayServerId::from_bytes([0x23; 16]);
const ROOT_KEY_ID: RootKeyId = RootKeyId::from_bytes([0x24; 16]);

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
                let mut input = b"AgentDeck/PendingPairingTestRng\0".to_vec();
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

struct PanicRng;

impl TryRng for PanicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("durable retry must not consume RNG")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("durable retry must not consume RNG")
    }

    fn try_fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), Self::Error> {
        panic!("durable retry must not consume RNG")
    }
}

impl TryCryptoRng for PanicRng {}

#[derive(Clone)]
struct Fixture {
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
    invite_private: Arc<[u8]>,
}

impl Fixture {
    fn root_signing_key() -> SigningKey {
        SigningKey::from_seed(&[0x31; 32])
    }

    fn data_signing_key() -> SigningKey {
        SigningKey::from_seed(&[0x32; 32])
    }

    fn new() -> Self {
        let root = Self::root_signing_key();
        let data = Self::data_signing_key();
        let root_fingerprint = sha256(&root.verifying_key().to_bytes());
        let mut data_certificate = SignedCertificate {
            subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
            cert_role: CertRole::Data,
            generation: LinkGeneration::new(3),
            root_key_id: ROOT_KEY_ID,
            trust_epoch: TrustEpoch::new(2),
            not_after_ms: Some(NOW_MS + 600_000),
            signature: Ed25519Signature([0; 64]),
        };
        data_certificate.signature = sign_tbs(
            &root,
            &data_certificate.to_be_signed_v1(RELAY_SERVER, MACHINE_ROUTE, root_fingerprint),
        )
        .into();
        let (invite_private, invite_public) = HpkePrivateKey::derive_keypair(&[0x33; 32]);
        Self {
            invite: PairInviteV1 {
                format_version: E2EE_FORMAT_VERSION,
                relay_protocol_version: RELAY_PROTOCOL_VERSION,
                pair_route: PAIR_ROUTE,
                invite_secret: [0x34; 32],
                invite_hpke_pubkey: PublicKeyBytes(
                    invite_public
                        .to_bytes()
                        .try_into()
                        .expect("X25519 public key"),
                ),
                wss_url: "wss://relay.example/".to_owned(),
                relay_server_id: RELAY_SERVER,
                current_spki_pin: [0x35; 32],
                next_spki_pin: [0x36; 32],
                expires_at_ms: NOW_MS + 300_000,
                machine_root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
                machine_root_fingerprint: root_fingerprint,
                data_sign_cert: data_certificate,
                machine_display_name: "Fixture Machine".to_owned(),
            },
            authorization: full_authorization("Persistent Remote CLI"),
            invite_private: Arc::from(invite_private.to_bytes()),
        }
    }

    fn request_info(&self) -> PairRequestInfoV1 {
        PairRequestInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: self.invite.relay_server_id,
            pair_route: self.invite.pair_route,
            invite_hash: self.invite.canonical_sha256().expect("canonical invite"),
            expiry_ms: self.invite.expires_at_ms,
        }
    }

    fn request_context(&self) -> OuterContextV1 {
        OuterContextV1 {
            frame_kind: OuterFrameKind::PairRequest,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: None,
            device_route: None,
            stream_route: None,
            request_route: None,
            pair_route: Some(self.invite.pair_route),
            stream_generation: None,
            stream_cursor: None,
            stream_seq: None,
            message_key_epoch: 0,
        }
    }

    fn response_for(&self, prepared: &PreparedPairRequest) -> Vec<u8> {
        self.response_for_seed(prepared, [0x38; 32])
    }

    fn response_for_seed(
        &self,
        prepared: &PreparedPairRequest,
        response_seed: [u8; 32],
    ) -> Vec<u8> {
        let root = Self::root_signing_key();
        let data = Self::data_signing_key();
        let root_fingerprint = self.invite.machine_root_fingerprint;
        let mut grant = RelayGrant {
            machine_route: MACHINE_ROUTE,
            device_route: DEVICE_ROUTE,
            device_sign_pubkey: PublicKeyBytes(prepared.device_sign_public_key()),
            grant_serial: GrantSerial::new(7),
            root_key_id: ROOT_KEY_ID,
            trust_epoch: TrustEpoch::new(2),
            signature: Ed25519Signature([0; 64]),
        };
        grant.signature = sign_tbs(
            &root,
            &grant.to_be_signed_v1(RELAY_SERVER, root_fingerprint),
        )
        .into();
        let authorization = sign_device_authorization(
            &root,
            RELAY_SERVER,
            &grant,
            DeviceAuthorizationV1 {
                format_version: E2EE_FORMAT_VERSION,
                grant_hash: grant.canonical_sha256(),
                machine_route: MACHINE_ROUTE,
                device_route: DEVICE_ROUTE,
                device_sign_fingerprint: sha256(&prepared.device_sign_public_key()),
                grant_serial: GrantSerial::new(7),
                device_hpke_pubkey: PublicKeyBytes(prepared.device_hpke_public_key()),
                capabilities: self.authorization.capabilities.clone(),
                permissions: self.authorization.permissions.clone(),
                root_key_id: ROOT_KEY_ID,
                trust_epoch: TrustEpoch::new(2),
                signature: Ed25519Signature([0; 64]),
            },
        )
        .unwrap();
        let info = PairResponseInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: RELAY_SERVER,
            pair_route: PAIR_ROUTE,
            invite_hash: self.invite.canonical_sha256().unwrap(),
            expiry_ms: self.invite.expires_at_ms,
            request_hash: prepared.request_hash(),
            machine_route: MACHINE_ROUTE,
            device_route: DEVICE_ROUTE,
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
        };
        let revision = KeyDirectoryRevision::new(4);
        let recipient =
            agentdeck_crypto::HpkePublicKey::from_bytes(&prepared.device_hpke_public_key())
                .unwrap();
        let mut entry_rng = DeterministicRng::new([0x37; 32]);
        let mut entries = Vec::new();
        for (purpose, epoch, key_byte) in [
            (KeyPurpose::Catalog, 3_u64, 0x71_u8),
            (KeyPurpose::DeviceCommandTx, 5, 0x72),
            (KeyPurpose::DeviceReplyTx, 7, 0x73),
        ] {
            let entry_info = KeyUpdateInfoV1 {
                e2ee_format_version: E2EE_FORMAT_VERSION,
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                relay_server_id: RELAY_SERVER,
                machine_route: MACHINE_ROUTE,
                device_route: DEVICE_ROUTE,
                stream_route: None,
                grant_serial: GrantSerial::new(7),
                root_trust_epoch: TrustEpoch::new(2),
                key_directory_revision: revision,
                key_purpose: purpose,
                key_epoch: epoch,
            };
            entries.push(
                seal_key_directory_entry(
                    &recipient,
                    &entry_info,
                    &key_update_context(&entry_info),
                    &SecretAeadKey::from_bytes([key_byte; 32]),
                    &mut entry_rng,
                )
                .unwrap(),
            );
        }
        let signer =
            MachineDataSignerBindingV1::from_certificate(&self.invite.data_sign_cert).unwrap();
        let directory = sign_key_directory(
            &data,
            &signer,
            &KeyDirectorySignatureContextV1 {
                relay_server_id: RELAY_SERVER,
                machine_route: MACHINE_ROUTE,
                device_route: DEVICE_ROUTE,
                grant_serial: GrantSerial::new(7),
                root_trust_epoch: TrustEpoch::new(2),
            },
            KeyDirectoryV1 {
                revision,
                entries,
                signature: Ed25519Signature([0; 64]),
            },
        )
        .unwrap();
        let plaintext = PairResponsePlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            request_hash: prepared.request_hash(),
            relay_grant: grant,
            device_authorization: authorization,
            key_directory: directory,
        };
        let mut response_rng = DeterministicRng::new(response_seed);
        seal_pair_response(
            &recipient,
            &info,
            &pairing_context(OuterFrameKind::PairResponse),
            &plaintext,
            PairResponseSealAuthority {
                machine_data_signing_key: &data,
                signer: &signer,
                machine_root_verifying_key: &root.verifying_key(),
            },
            &mut response_rng,
        )
        .unwrap()
        .canonical_bytes()
        .unwrap()
    }
}

fn pairing_context(frame_kind: OuterFrameKind) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(PAIR_ROUTE),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
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

fn full_authorization(display_name: &str) -> AuthorizationRequestV1 {
    AuthorizationRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        device_display_name: display_name.to_owned(),
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

fn assert_real_request(
    fixture: &Fixture,
    request_bytes: &[u8],
    device_sign_public: [u8; 32],
    device_hpke_public: [u8; 32],
) {
    let request = PairRequestV1::from_canonical_bytes(request_bytes).expect("strict request");
    let invite_private =
        HpkePrivateKey::from_bytes(&fixture.invite_private).expect("fixture invite private key");
    let opened = open_pair_request(
        &invite_private,
        &fixture.request_info(),
        &fixture.request_context(),
        &fixture.invite.invite_secret,
        &request,
    )
    .expect("real HPKE and DeviceSign proof must open");
    assert_eq!(
        opened,
        PairRequestPlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            invite_secret: fixture.invite.invite_secret,
            device_sign_pubkey: PublicKeyBytes(device_sign_public),
            device_hpke_pubkey: PublicKeyBytes(device_hpke_public),
            authorization_request: fixture.authorization.clone(),
        }
    );
}

#[test]
fn first_send_is_frozen_in_keychain_and_every_retry_reuses_exact_pair_request() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let coordinator = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut first_rng = DeterministicRng::new([0x41; 32]);
    let first = coordinator
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS,
            &mut first_rng,
        )
        .expect("first preparation");

    assert_eq!(
        first.request_hash(),
        sha256(first.canonical_request()),
        "requestHash must cover enc+ciphertext+proof"
    );
    assert_real_request(
        &fixture,
        first.canonical_request(),
        first.device_sign_public_key(),
        first.device_hpke_public_key(),
    );

    let invite_hash = fixture.invite.canonical_sha256().unwrap();
    for (purpose, expected_len) in [
        (PendingRemoteKeyPurpose::DeviceSignPrivateKey, 32),
        (PendingRemoteKeyPurpose::DeviceHpkePrivateKey, 32),
        (PendingRemoteKeyPurpose::PairingRecord, 0),
    ] {
        let account = RemoteKeyAccount::pending(INSTALLATION_ID, invite_hash, purpose);
        let value = store
            .load(&account)
            .expect("read persisted pending item")
            .expect("pending item exists");
        if expected_len != 0 {
            assert_eq!(value.expose_secret().len(), expected_len);
        } else {
            assert!(
                serde_json::from_slice::<serde_json::Value>(value.expose_secret()).is_err(),
                "pending bearer record must not use legacy credential JSON"
            );
            assert!(
                !value
                    .expose_secret()
                    .windows(fixture.invite.invite_secret.len())
                    .any(|window| window == fixture.invite.invite_secret),
                "pending record must not copy the raw invite bearer secret"
            );
            assert!(
                !value
                    .expose_secret()
                    .windows(fixture.authorization.device_display_name.len())
                    .any(|window| {
                        window == fixture.authorization.device_display_name.as_bytes()
                    }),
                "pending record must bind authorization by hash, not plaintext"
            );
        }
    }

    let first_bytes = first.canonical_request().to_vec();
    let first_hash = first.request_hash();
    drop(first);
    let mut retry_rng = PanicRng;
    let retry = coordinator
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &mut retry_rng,
        )
        .expect("durable retry");
    assert_eq!(retry.canonical_request(), first_bytes);
    assert_eq!(retry.request_hash(), first_hash);
}

#[test]
fn verified_response_is_read_only_and_bound_to_the_durable_pending_transaction() {
    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let coordinator = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut rng = DeterministicRng::new([0x42; 32]);
    let prepared = coordinator
        .prepare(&fixture.invite, &fixture.authorization, NOW_MS, &mut rng)
        .unwrap();
    let response = fixture.response_for(&prepared);
    drop(prepared);
    let writes_before_verify = store.writes.load(Ordering::SeqCst);

    let verified = coordinator
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &response,
        )
        .expect("response must verify from persisted pending keys");
    assert_eq!(
        format!("{verified:?}"),
        "VerifiedPendingPairResponse([REDACTED])"
    );
    assert_eq!(verified.response_hash(), sha256(&response));
    assert_eq!(verified.machine_route(), MACHINE_ROUTE);
    assert_eq!(verified.device_route(), DEVICE_ROUTE);
    assert_eq!(verified.opened_key_count(), 3);
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before_verify);

    let restarted = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    restarted
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 2,
            &response,
        )
        .expect("restart must verify the same response without generating state");
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before_verify);

    let changed = full_authorization("Changed Authorization");
    let error = restarted
        .verify_response(&fixture.invite, &changed, NOW_MS + 2, &response)
        .expect_err("a caller cannot replace pending expectations with response fields");
    assert_eq!(error.code(), "remote.pairing.pending_conflict");
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before_verify);
}

#[test]
fn response_verification_never_repairs_a_missing_pending_key() {
    for (index, missing_purpose) in [
        PendingRemoteKeyPurpose::PairingRecord,
        PendingRemoteKeyPurpose::DeviceSignPrivateKey,
        PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let store = UnknownCommitStore::new(usize::MAX);
        let coordinator = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
        let mut rng = DeterministicRng::new([0x43 + index as u8; 32]);
        let prepared = coordinator
            .prepare(&fixture.invite, &fixture.authorization, NOW_MS, &mut rng)
            .unwrap();
        let response = fixture.response_for(&prepared);
        drop(prepared);

        let missing_account = RemoteKeyAccount::pending(
            INSTALLATION_ID,
            fixture.invite.canonical_sha256().unwrap(),
            missing_purpose,
        );
        store.delete_exact(&missing_account).unwrap();
        let writes_before_verify = store.writes.load(Ordering::SeqCst);
        let error = coordinator
            .verify_response(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 1,
                &response,
            )
            .expect_err("missing committed pending item must fail closed");
        assert_eq!(error.code(), "remote.pairing.pending_incomplete");
        assert_eq!(store.writes.load(Ordering::SeqCst), writes_before_verify);
        assert!(store.load(&missing_account).unwrap().is_none());
    }
}

#[test]
fn invalid_or_expired_inputs_fail_before_any_keychain_mutation() {
    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let coordinator = PendingPairingCoordinator::new(&store, INSTALLATION_ID);

    let mut expired = fixture.invite.clone();
    expired.expires_at_ms = NOW_MS;
    let mut rng = PanicRng;
    let error = coordinator
        .prepare(&expired, &fixture.authorization, NOW_MS, &mut rng)
        .expect_err("expired invite");
    assert_eq!(error.code(), "remote.pairing.invite_invalid");
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);

    let mut invalid_authorization = fixture.authorization.clone();
    invalid_authorization.capabilities.clear();
    let mut rng = PanicRng;
    let error = coordinator
        .prepare(&fixture.invite, &invalid_authorization, NOW_MS, &mut rng)
        .expect_err("invalid authorization");
    assert_eq!(error.code(), "remote.pairing.authorization_invalid");
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn either_malformed_partial_private_item_is_not_repaired_or_extended() {
    let fixture = Fixture::new();
    let invite_hash = fixture.invite.canonical_sha256().unwrap();
    for malformed_purpose in [
        PendingRemoteKeyPurpose::DeviceSignPrivateKey,
        PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
    ] {
        let store = MemoryRemoteKeyStore::new();
        let malformed_account =
            RemoteKeyAccount::pending(INSTALLATION_ID, invite_hash, malformed_purpose);
        store
            .persist_immutable(&malformed_account, &RemoteSecret::new(vec![1, 2, 3]))
            .unwrap();

        let coordinator = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
        let mut rng = PanicRng;
        let error = coordinator
            .prepare(&fixture.invite, &fixture.authorization, NOW_MS, &mut rng)
            .expect_err("malformed pre-existing key must fail before another write");
        assert_eq!(error.code(), "remote.pairing.pending_invalid");
        for purpose in [
            PendingRemoteKeyPurpose::DeviceSignPrivateKey,
            PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
            PendingRemoteKeyPurpose::PairingRecord,
        ] {
            let account = RemoteKeyAccount::pending(INSTALLATION_ID, invite_hash, purpose);
            if purpose == malformed_purpose {
                assert_eq!(
                    store.load(&account).unwrap().unwrap().expose_secret(),
                    [1, 2, 3]
                );
            } else {
                assert!(store.load(&account).unwrap().is_none());
            }
        }
    }
}

#[derive(Clone, Copy)]
enum RecordMutation {
    BadMagic,
    Truncated,
    Trailing,
}

struct RecordMutationStore<'a> {
    inner: &'a MemoryRemoteKeyStore,
    mutation: RecordMutation,
    writes: AtomicUsize,
}

impl RemoteKeyStore for RecordMutationStore<'_> {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        let Some(value) = self.inner.load(account)? else {
            return Ok(None);
        };
        if !account.as_str().ends_with("/pending-pairing-record.v1") {
            return Ok(Some(value));
        }
        let mut bytes = value.expose_secret().to_vec();
        match self.mutation {
            RecordMutation::BadMagic => bytes[0] ^= 1,
            RecordMutation::Truncated => {
                bytes.pop();
            }
            RecordMutation::Trailing => bytes.push(0),
        }
        Ok(Some(RemoteSecret::new(bytes)))
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.persist_immutable(account, value)
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        self.inner.delete_exact(account)
    }
}

#[test]
fn malformed_noncanonical_or_trailing_record_fails_closed_without_mutation() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let coordinator = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut rng = DeterministicRng::new([0x59; 32]);
    coordinator
        .prepare(&fixture.invite, &fixture.authorization, NOW_MS, &mut rng)
        .unwrap();

    for mutation in [
        RecordMutation::BadMagic,
        RecordMutation::Truncated,
        RecordMutation::Trailing,
    ] {
        let tampered = RecordMutationStore {
            inner: &store,
            mutation,
            writes: AtomicUsize::new(0),
        };
        let coordinator = PendingPairingCoordinator::new(&tampered, INSTALLATION_ID);
        let mut retry_rng = PanicRng;
        let error = coordinator
            .prepare(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 1,
                &mut retry_rng,
            )
            .expect_err("malformed record");
        assert_eq!(error.code(), "remote.pairing.pending_invalid");
        assert_eq!(tampered.writes.load(Ordering::SeqCst), 0);
    }
}

struct UnknownCommitStore {
    inner: MemoryRemoteKeyStore,
    fail_after_write: Mutex<Option<usize>>,
    writes: AtomicUsize,
}

impl UnknownCommitStore {
    fn new(fail_after_write: usize) -> Self {
        Self {
            inner: MemoryRemoteKeyStore::new(),
            fail_after_write: Mutex::new(Some(fail_after_write)),
            writes: AtomicUsize::new(0),
        }
    }
}

impl RemoteKeyStore for UnknownCommitStore {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        self.inner.load(account)
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        let outcome = self.inner.persist_immutable(account, value)?;
        let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        let mut fail = self.fail_after_write.lock().unwrap();
        if *fail == Some(write) {
            *fail = None;
            return Err(RemoteKeyStoreError::PersistenceReadbackFailed {
                account: account.clone(),
            });
        }
        Ok(outcome)
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        self.inner.delete_exact(account)
    }

    fn list_paired_commit_markers(
        &self,
        installation_id: Uuid,
    ) -> Result<
        Vec<agentdeck_cli::remote::keychain::ParsedPairedRemoteKeyAccount>,
        RemoteKeyStoreError,
    > {
        self.inner.list_paired_commit_markers(installation_id)
    }
}

#[test]
fn every_pending_keychain_write_boundary_recovers_without_resealing_a_sent_request() {
    for fail_after_write in 1..=3 {
        let fixture = Fixture::new();
        let store = UnknownCommitStore::new(fail_after_write);
        let coordinator = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
        let mut crash_rng = DeterministicRng::new([fail_after_write as u8; 32]);
        let error = coordinator
            .prepare(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS,
                &mut crash_rng,
            )
            .expect_err("injected unknown commit");
        assert_eq!(error.code(), "remote.pairing.pending_persistence_failed");

        let mut restart_rng = DeterministicRng::new([0xa0 + fail_after_write as u8; 32]);
        let recovered = coordinator
            .prepare(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 1,
                &mut restart_rng,
            )
            .expect("restart must finish or read back the pending transaction");
        assert_real_request(
            &fixture,
            recovered.canonical_request(),
            recovered.device_sign_public_key(),
            recovered.device_hpke_public_key(),
        );

        let frozen = recovered.canonical_request().to_vec();
        drop(recovered);
        let mut second_retry_rng = DeterministicRng::new([0xf0; 32]);
        let second_retry = coordinator
            .prepare(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 2,
                &mut second_retry_rng,
            )
            .unwrap();
        assert_eq!(second_retry.canonical_request(), frozen);
    }
}

#[test]
fn committed_record_with_missing_private_item_fails_closed_without_regeneration() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let coordinator = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut rng = DeterministicRng::new([0x51; 32]);
    let prepared = coordinator
        .prepare(&fixture.invite, &fixture.authorization, NOW_MS, &mut rng)
        .unwrap();
    let frozen = prepared.canonical_request().to_vec();
    drop(prepared);

    let invite_hash = fixture.invite.canonical_sha256().unwrap();
    let hpke_account = RemoteKeyAccount::pending(
        INSTALLATION_ID,
        invite_hash,
        PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
    );
    store.delete_exact(&hpke_account).unwrap();

    let mut retry_rng = DeterministicRng::new([0x52; 32]);
    let error = coordinator
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &mut retry_rng,
        )
        .expect_err("marker without a private item is not repairable");
    assert_eq!(error.code(), "remote.pairing.pending_incomplete");
    assert!(store.load(&hpke_account).unwrap().is_none());

    let record_account = RemoteKeyAccount::pending(
        INSTALLATION_ID,
        invite_hash,
        PendingRemoteKeyPurpose::PairingRecord,
    );
    let record = store.load(&record_account).unwrap().unwrap();
    assert!(
        record
            .expose_secret()
            .windows(frozen.len())
            .any(|window| window == frozen)
    );

    let (replacement, _) = HpkePrivateKey::derive_keypair(&[0xee; 32]);
    store
        .persist_immutable(&hpke_account, &RemoteSecret::new(replacement.to_bytes()))
        .unwrap();
    let mut replacement_rng = PanicRng;
    let error = coordinator
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 2,
            &mut replacement_rng,
        )
        .expect_err("a different valid private key cannot repair committed state");
    assert_eq!(error.code(), "remote.pairing.pending_incomplete");
}

struct PairRecordRaceStore {
    inner: MemoryRemoteKeyStore,
    record_barrier: Barrier,
}

impl PairRecordRaceStore {
    fn new() -> Self {
        Self {
            inner: MemoryRemoteKeyStore::new(),
            record_barrier: Barrier::new(2),
        }
    }
}

impl RemoteKeyStore for PairRecordRaceStore {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        self.inner.load(account)
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        if account.as_str().ends_with("/pending-pairing-record.v1") {
            self.record_barrier.wait();
        }
        self.inner.persist_immutable(account, value)
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        self.inner.delete_exact(account)
    }
}

#[test]
fn changed_authorization_and_concurrent_initializers_never_replace_the_winner() {
    let fixture = Fixture::new();
    let store = Arc::new(PairRecordRaceStore::new());
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for seed in [0x61, 0x62] {
        let fixture = fixture.clone();
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let coordinator = PendingPairingCoordinator::new(store.as_ref(), INSTALLATION_ID);
            let mut rng = DeterministicRng::new([seed; 32]);
            barrier.wait();
            coordinator
                .prepare(&fixture.invite, &fixture.authorization, NOW_MS, &mut rng)
                .map(|prepared| prepared.canonical_request().to_vec())
        }));
    }
    let first = workers.remove(0).join().unwrap().unwrap();
    let second = workers.remove(0).join().unwrap().unwrap();
    assert_eq!(
        first, second,
        "concurrent callers must converge on one carrier"
    );

    let coordinator = PendingPairingCoordinator::new(store.as_ref(), INSTALLATION_ID);
    let changed = full_authorization("Different Device");
    let mut retry_rng = DeterministicRng::new([0x63; 32]);
    let error = coordinator
        .prepare(&fixture.invite, &changed, NOW_MS + 1, &mut retry_rng)
        .expect_err("an existing pending request cannot change requested authority");
    assert_eq!(error.code(), "remote.pairing.pending_conflict");

    let mut exact_rng = DeterministicRng::new([0x64; 32]);
    let exact = coordinator
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 2,
            &mut exact_rng,
        )
        .unwrap();
    assert_eq!(exact.canonical_request(), first);
}

fn paired_account(fixture: &Fixture, purpose: PairedRemoteKeyPurpose) -> RemoteKeyAccount {
    RemoteKeyAccount::paired(
        INSTALLATION_ID,
        MachineRootFingerprint::from_bytes(fixture.invite.machine_root_fingerprint),
        MACHINE_ROUTE,
        purpose,
    )
}

fn contains_crypto_state_file(root: &Path) -> bool {
    if !root.exists() {
        return false;
    }
    fs::read_dir(root).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        if path.is_dir() {
            contains_crypto_state_file(&path)
        } else {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".crypto-state.v1"))
        }
    })
}

fn open_frozen_receipt(
    fixture: &Fixture,
    response: &[u8],
    device_sign_public_key: [u8; 32],
    canonical_carrier: &[u8],
) -> agentdeck_protocol::e2ee::PairResponseReceivedV1 {
    let response = PairResponseV1::from_canonical_bytes(response).expect("strict response");
    let carrier = PairingControlEnvelopeV1::from_canonical_bytes(canonical_carrier)
        .expect("strict frozen receipt carrier");
    let invite_private =
        HpkePrivateKey::from_bytes(&fixture.invite_private).expect("fixture invite private key");
    let device_sign =
        VerifyingKey::from_bytes(&device_sign_public_key).expect("fixture DeviceSign key");
    open_pair_response_received(
        &invite_private,
        &response.info,
        &pairing_context(OuterFrameKind::PairResponseReceived),
        &carrier,
        &device_sign,
    )
    .expect("daemon invite key must open and verify the real receipt")
}

#[test]
fn paired_promotion_commits_all_final_items_then_freezes_one_real_receipt() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([0x81; 32]);
    let prepared = pending
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS,
            &mut request_rng,
        )
        .expect("freeze request");
    let request_hash = prepared.request_hash();
    let device_sign_public_key = prepared.device_sign_public_key();
    let response = fixture.response_for(&prepared);
    drop(prepared);
    let verified = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &response,
        )
        .expect("verify response");

    let temp = tempfile::tempdir().expect("paired state root");
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let coordinator = PairedPromotionCoordinator::new(&store, INSTALLATION_ID, &state_root);
    let mut promotion_rng = DeterministicRng::new([0x82; 32]);
    let promoted = coordinator
        .promote(verified, &mut promotion_rng)
        .expect("two-phase paired promotion");

    assert!(!promoted.was_already_committed());
    assert_eq!(promoted.machine_route(), MACHINE_ROUTE);
    assert_eq!(promoted.device_route(), DEVICE_ROUTE);
    assert_eq!(promoted.request_hash(), request_hash);
    assert_eq!(promoted.response_hash(), sha256(&response));
    let receipt = open_frozen_receipt(
        &fixture,
        &response,
        device_sign_public_key,
        promoted.canonical_receipt_carrier(),
    );
    assert_eq!(receipt.request_hash, request_hash);
    assert_eq!(receipt.grant_hash, promoted.grant_hash());
    assert_eq!(receipt.response_hash, sha256(&response));

    for purpose in [
        PairedRemoteKeyPurpose::DeviceStorageKek,
        PairedRemoteKeyPurpose::DeviceSignPrivateKey,
        PairedRemoteKeyPurpose::DeviceHpkePrivateKey,
        PairedRemoteKeyPurpose::DeviceGrant,
        PairedRemoteKeyPurpose::CounterGuard,
        PairedRemoteKeyPurpose::CommitMarker,
    ] {
        assert!(
            store
                .load(&paired_account(&fixture, purpose))
                .unwrap()
                .is_some(),
            "paired marker may only become visible after {purpose:?} exists"
        );
    }
    let sealed_state = fs::read(promoted.state_path()).expect("sealed paired CryptoState");
    assert!(
        !sealed_state
            .windows(fixture.invite.invite_secret.len())
            .any(|window| window == fixture.invite.invite_secret),
        "sealed state must not retain the invite bearer in plaintext"
    );
    assert!(
        !sealed_state
            .windows(response.len())
            .any(|window| window == response),
        "canonical response must be inside the authenticated encrypted state"
    );

    let kek_record = store
        .load(&paired_account(
            &fixture,
            PairedRemoteKeyPurpose::DeviceStorageKek,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(&kek_record.expose_secret()[..4], b"ADKK");
    let kek_bytes: [u8; 32] = kek_record.expose_secret()[40..72].try_into().unwrap();
    let inspect_store = FileCryptoStateStore::new_in(
        &state_root,
        CryptoStateIdentity::new(
            INSTALLATION_ID,
            MachineRootFingerprint::from_bytes(fixture.invite.machine_root_fingerprint),
            MACHINE_ROUTE,
        ),
        DeviceStorageKek::new(kek_bytes),
    )
    .unwrap();
    let plaintext_state = inspect_store.load().unwrap().unwrap();
    assert!(
        plaintext_state
            .expose_secret()
            .windows(response.len())
            .any(|window| window == response),
        "state must retain the exact encrypted PairResponse for duplicate detection"
    );
    let invite_hash = fixture.invite.canonical_sha256().unwrap();
    let pending_sign = store
        .load(&RemoteKeyAccount::pending(
            INSTALLATION_ID,
            invite_hash,
            PendingRemoteKeyPurpose::DeviceSignPrivateKey,
        ))
        .unwrap()
        .unwrap();
    let pending_hpke = store
        .load(&RemoteKeyAccount::pending(
            INSTALLATION_ID,
            invite_hash,
            PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
        ))
        .unwrap()
        .unwrap();
    for forbidden in [
        fixture.invite.invite_secret.as_slice(),
        pending_sign.expose_secret(),
        pending_hpke.expose_secret(),
        [0x71; 32].as_slice(),
        [0x72; 32].as_slice(),
        [0x73; 32].as_slice(),
        b"prompt/output transcript sentinel".as_slice(),
    ] {
        assert!(
            !plaintext_state
                .expose_secret()
                .windows(forbidden.len())
                .any(|window| window == forbidden),
            "CryptoState must not retain raw bearer/private/AEAD/transcript material"
        );
    }

    let frozen_receipt = promoted.canonical_receipt_carrier().to_vec();
    let frozen_state = fs::read(promoted.state_path()).unwrap();
    drop(promoted);
    let verified_retry = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 2,
            &response,
        )
        .expect("verify exact retry");
    let mut panic_rng = PanicRng;
    let retried = coordinator
        .promote(verified_retry, &mut panic_rng)
        .expect("committed retry must be read-only");
    assert!(retried.was_already_committed());
    assert_eq!(retried.canonical_receipt_carrier(), frozen_receipt);
    assert_eq!(fs::read(retried.state_path()).unwrap(), frozen_state);
}

#[test]
fn every_paired_keychain_unknown_commit_recovers_without_resealing_receipt() {
    // pending prepare 固定占用前 3 次 persist；promotion 依次写 KEK、Sign、HPKE、Grant、
    // CounterGuard、marker。第 5 次及以后失败时 sealed state 已经 durable，恢复不得再用 RNG。
    for fail_after_write in 4..=9 {
        let fixture = Fixture::new();
        let store = UnknownCommitStore::new(fail_after_write);
        let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
        let mut request_rng = DeterministicRng::new([fail_after_write as u8; 32]);
        let prepared = pending
            .prepare(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS,
                &mut request_rng,
            )
            .expect("pending prepare precedes paired fault");
        let response = fixture.response_for(&prepared);
        drop(prepared);
        let verified = pending
            .verify_response(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 1,
                &response,
            )
            .unwrap();
        let temp = tempfile::tempdir().expect("paired state root");
        let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
        let coordinator = PairedPromotionCoordinator::new(&store, INSTALLATION_ID, &state_root);
        let mut first_rng = DeterministicRng::new([0x90 + fail_after_write as u8; 32]);
        let error = coordinator
            .promote(verified, &mut first_rng)
            .expect_err("injected unknown paired commit");
        assert_eq!(error.code(), "remote.pairing.paired_persistence_failed");

        let marker = store
            .load(&paired_account(
                &fixture,
                PairedRemoteKeyPurpose::CommitMarker,
            ))
            .unwrap();
        assert_eq!(
            marker.is_some(),
            fail_after_write == 9,
            "paired marker must be the final Keychain publication"
        );

        let verified_restart = pending
            .verify_response(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 2,
                &response,
            )
            .unwrap();
        let recovered = if fail_after_write == 4 {
            let mut restart_rng = DeterministicRng::new([0xa4; 32]);
            coordinator.promote(verified_restart, &mut restart_rng)
        } else {
            let mut panic_rng = PanicRng;
            coordinator.promote(verified_restart, &mut panic_rng)
        }
        .expect("restart converges on exact provisional state");
        let receipt = recovered.canonical_receipt_carrier().to_vec();
        drop(recovered);

        let verified_retry = pending
            .verify_response(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 3,
                &response,
            )
            .unwrap();
        let mut panic_rng = PanicRng;
        let retried = coordinator
            .promote(verified_retry, &mut panic_rng)
            .expect("post-marker retry is read-only");
        assert!(retried.was_already_committed());
        assert_eq!(retried.canonical_receipt_carrier(), receipt);
    }
}

#[test]
fn committed_pair_rejects_a_second_valid_response_for_the_same_request() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([0xb1; 32]);
    let prepared = pending
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS,
            &mut request_rng,
        )
        .unwrap();
    let first_response = fixture.response_for_seed(&prepared, [0xb2; 32]);
    let second_response = fixture.response_for_seed(&prepared, [0xb3; 32]);
    assert_ne!(first_response, second_response);
    drop(prepared);

    let first_verified = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &first_response,
        )
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let coordinator = PairedPromotionCoordinator::new(&store, INSTALLATION_ID, &state_root);
    let mut first_rng = DeterministicRng::new([0xb4; 32]);
    coordinator.promote(first_verified, &mut first_rng).unwrap();

    let conflicting_verified = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 2,
            &second_response,
        )
        .expect("both responses are independently cryptographically valid");
    let mut panic_rng = PanicRng;
    let error = coordinator
        .promote(conflicting_verified, &mut panic_rng)
        .expect_err("same request with different response bytes must conflict");
    assert_eq!(error.code(), "remote.pairing.paired_conflict");
}

#[test]
fn promotion_takes_the_device_lease_before_rng_or_any_paired_write() {
    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([0xc1; 32]);
    let prepared = pending
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS,
            &mut request_rng,
        )
        .unwrap();
    let response = fixture.response_for(&prepared);
    drop(prepared);
    let verified = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &response,
        )
        .unwrap();

    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let holder = RemoteDeviceLease::acquire_in(
        &state_root,
        RemoteDeviceLockKey::new(
            INSTALLATION_ID,
            MachineRootFingerprint::from_bytes(fixture.invite.machine_root_fingerprint),
            MACHINE_ROUTE,
        ),
    )
    .unwrap();
    let writes_before = store.writes.load(Ordering::SeqCst);
    let coordinator = PairedPromotionCoordinator::new(&store, INSTALLATION_ID, &state_root);
    let mut panic_rng = PanicRng;
    let error = coordinator
        .promote(verified, &mut panic_rng)
        .expect_err("contending promoter must fail before touching paired state");
    assert_eq!(error.code(), "remote.device.already_in_use");
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before);
    for purpose in [
        PairedRemoteKeyPurpose::DeviceStorageKek,
        PairedRemoteKeyPurpose::DeviceSignPrivateKey,
        PairedRemoteKeyPurpose::DeviceHpkePrivateKey,
        PairedRemoteKeyPurpose::DeviceGrant,
        PairedRemoteKeyPurpose::CounterGuard,
        PairedRemoteKeyPurpose::CommitMarker,
    ] {
        assert!(
            store
                .load(&paired_account(&fixture, purpose))
                .unwrap()
                .is_none()
        );
    }
    assert!(!contains_crypto_state_file(&state_root));

    drop(holder);
    let verified_retry = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 2,
            &response,
        )
        .unwrap();
    let mut retry_rng = DeterministicRng::new([0xc2; 32]);
    coordinator
        .promote(verified_retry, &mut retry_rng)
        .expect("released promotion lease permits the exact retry");
}

#[test]
fn committed_marker_never_repairs_a_missing_final_item_or_state_file() {
    for (index, missing) in [
        PairedRemoteKeyPurpose::DeviceStorageKek,
        PairedRemoteKeyPurpose::DeviceSignPrivateKey,
        PairedRemoteKeyPurpose::DeviceHpkePrivateKey,
        PairedRemoteKeyPurpose::DeviceGrant,
        PairedRemoteKeyPurpose::CounterGuard,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let store = UnknownCommitStore::new(usize::MAX);
        let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
        let mut request_rng = DeterministicRng::new([0xd0 + index as u8; 32]);
        let prepared = pending
            .prepare(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS,
                &mut request_rng,
            )
            .unwrap();
        let response = fixture.response_for(&prepared);
        drop(prepared);
        let verified = pending
            .verify_response(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 1,
                &response,
            )
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
        let coordinator = PairedPromotionCoordinator::new(&store, INSTALLATION_ID, &state_root);
        let mut promotion_rng = DeterministicRng::new([0xe0 + index as u8; 32]);
        coordinator.promote(verified, &mut promotion_rng).unwrap();

        let missing_account = paired_account(&fixture, missing);
        store.delete_exact(&missing_account).unwrap();
        let writes_before = store.writes.load(Ordering::SeqCst);
        let verified_retry = pending
            .verify_response(
                &fixture.invite,
                &fixture.authorization,
                NOW_MS + 2,
                &response,
            )
            .unwrap();
        let mut panic_rng = PanicRng;
        let error = coordinator
            .promote(verified_retry, &mut panic_rng)
            .expect_err("committed state must never repair a final item");
        assert_eq!(error.code(), "remote.pairing.paired_incomplete");
        assert_eq!(store.writes.load(Ordering::SeqCst), writes_before);
        assert!(store.load(&missing_account).unwrap().is_none());
    }

    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([0xda; 32]);
    let prepared = pending
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS,
            &mut request_rng,
        )
        .unwrap();
    let response = fixture.response_for(&prepared);
    drop(prepared);
    let verified = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &response,
        )
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let coordinator = PairedPromotionCoordinator::new(&store, INSTALLATION_ID, &state_root);
    let mut promotion_rng = DeterministicRng::new([0xea; 32]);
    let promoted = coordinator.promote(verified, &mut promotion_rng).unwrap();
    fs::remove_file(promoted.state_path()).unwrap();
    drop(promoted);
    let writes_before = store.writes.load(Ordering::SeqCst);
    let verified_retry = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 2,
            &response,
        )
        .unwrap();
    let mut panic_rng = PanicRng;
    let error = coordinator
        .promote(verified_retry, &mut panic_rng)
        .expect_err("committed marker without sealed state is corrupt");
    assert_eq!(error.code(), "remote.pairing.paired_incomplete");
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before);
}

#[test]
fn orphaned_state_without_kek_fails_closed_without_generating_a_replacement() {
    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([0xf1; 32]);
    let prepared = pending
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS,
            &mut request_rng,
        )
        .unwrap();
    let response = fixture.response_for(&prepared);
    drop(prepared);
    let verified = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &response,
        )
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let coordinator = PairedPromotionCoordinator::new(&store, INSTALLATION_ID, &state_root);
    let mut promotion_rng = DeterministicRng::new([0xf2; 32]);
    coordinator.promote(verified, &mut promotion_rng).unwrap();

    let marker = paired_account(&fixture, PairedRemoteKeyPurpose::CommitMarker);
    let kek = paired_account(&fixture, PairedRemoteKeyPurpose::DeviceStorageKek);
    store.delete_exact(&marker).unwrap();
    store.delete_exact(&kek).unwrap();
    let writes_before = store.writes.load(Ordering::SeqCst);
    let verified_retry = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 2,
            &response,
        )
        .unwrap();
    let mut panic_rng = PanicRng;
    let error = coordinator
        .promote(verified_retry, &mut panic_rng)
        .expect_err("immutable state without its KEK is not repairable");
    assert_eq!(error.code(), "remote.pairing.paired_incomplete");
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before);
    assert!(store.load(&kek).unwrap().is_none());
    assert!(store.load(&marker).unwrap().is_none());
}

fn promote_for_paired_open(
    store: &dyn RemoteKeyStore,
    fixture: &Fixture,
    state_root: &Path,
    seed: u8,
) -> PromotedPairedMachine {
    let pending = PendingPairingCoordinator::new(store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([seed; 32]);
    let prepared = pending
        .prepare(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS,
            &mut request_rng,
        )
        .unwrap();
    let response = fixture.response_for_seed(&prepared, [seed.wrapping_add(1); 32]);
    drop(prepared);
    let verified = pending
        .verify_response(
            &fixture.invite,
            &fixture.authorization,
            NOW_MS + 1,
            &response,
        )
        .unwrap();
    let coordinator = PairedPromotionCoordinator::new(store, INSTALLATION_ID, state_root);
    let mut promotion_rng = DeterministicRng::new([seed.wrapping_add(2); 32]);
    coordinator.promote(verified, &mut promotion_rng).unwrap()
}

fn fixture_paired_identity(fixture: &Fixture) -> PairedMachineIdentity {
    PairedMachineIdentity::new(
        MachineRootFingerprint::from_bytes(fixture.invite.machine_root_fingerprint),
        MACHINE_ROUTE,
    )
}

#[test]
fn paired_machine_store_restarts_from_marker_without_any_pending_item() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");

    let before = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert!(before.list().unwrap().is_empty());
    promote_for_paired_open(&store, &fixture, &state_root, 0x41);

    let invite_hash = fixture.invite.canonical_sha256().unwrap();
    for purpose in [
        PendingRemoteKeyPurpose::PairingRecord,
        PendingRemoteKeyPurpose::DeviceSignPrivateKey,
        PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
    ] {
        store
            .delete_exact(&RemoteKeyAccount::pending(
                INSTALLATION_ID,
                invite_hash,
                purpose,
            ))
            .unwrap();
    }

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let listed = restarted
        .list()
        .expect("marker-backed list must fully audit without pending state");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].identity(), fixture_paired_identity(&fixture));
    assert_eq!(listed[0].machine_display_name(), "Fixture Machine");
    assert_eq!(listed[0].device_route(), DEVICE_ROUTE);
    assert_eq!(
        format!("{:?}", listed[0].identity()),
        "PairedMachineIdentity([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", listed[0]),
        "PairedMachineSummary([REDACTED])"
    );

    let opened = restarted
        .open_exact(listed[0].identity())
        .expect("exact open must re-audit and hold the device lease");
    assert_eq!(opened.identity(), fixture_paired_identity(&fixture));
    assert_eq!(opened.machine_display_name(), "Fixture Machine");
    assert_eq!(opened.wss_url(), "wss://relay.example/");
    assert_eq!(opened.device_route(), DEVICE_ROUTE);
    assert_eq!(opened.grant_serial(), GrantSerial::new(7));
    assert_eq!(opened.trust_epoch(), TrustEpoch::new(2));
    assert_eq!(opened.directory_revision(), KeyDirectoryRevision::new(4));
    assert_eq!(opened.opened_key_count(), 3);
    for purpose in [
        KeyPurpose::Catalog,
        KeyPurpose::DeviceCommandTx,
        KeyPurpose::DeviceReplyTx,
    ] {
        assert!(
            opened.has_opened_key_purpose(purpose),
            "restart audit must DeviceHPKE-open {purpose:?}"
        );
    }
    assert!(!opened.has_opened_key_purpose(KeyPurpose::ConversationDek));
    assert_eq!(format!("{opened:?}"), "OpenedPairedMachine([REDACTED])");

    let listed_while_open = restarted
        .list()
        .expect("read-only list must not contend with the active device lease");
    assert_eq!(listed_while_open.len(), 1);
    assert_eq!(listed_while_open[0].identity(), opened.identity());
}

#[test]
fn paired_machine_store_treats_marker_as_the_only_visibility_boundary() {
    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    promote_for_paired_open(&store, &fixture, &state_root, 0x51);

    let marker = paired_account(&fixture, PairedRemoteKeyPurpose::CommitMarker);
    store.delete_exact(&marker).unwrap();
    let writes_before = store.writes.load(Ordering::SeqCst);
    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert!(paired.list().unwrap().is_empty());
    let error = paired
        .open_exact(fixture_paired_identity(&fixture))
        .expect_err("final items and sealed state without marker are not visible");
    assert_eq!(error.code(), "remote.pairing.paired_incomplete");
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before);
    assert!(store.load(&marker).unwrap().is_none());
}

#[test]
fn paired_machine_store_binds_marker_account_body_and_state_identity_exactly() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    promote_for_paired_open(&store, &fixture, &state_root, 0x61);

    let marker = store
        .load(&paired_account(
            &fixture,
            PairedRemoteKeyPurpose::CommitMarker,
        ))
        .unwrap()
        .unwrap();
    let alias_identity = PairedMachineIdentity::new(
        MachineRootFingerprint::from_bytes([0xa7; 32]),
        MACHINE_ROUTE,
    );
    let alias_marker = RemoteKeyAccount::paired(
        INSTALLATION_ID,
        alias_identity.machine_root_fingerprint(),
        alias_identity.machine_route(),
        PairedRemoteKeyPurpose::CommitMarker,
    );
    store.persist_immutable(&alias_marker, &marker).unwrap();

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let error = paired
        .list()
        .expect_err("one aliased marker must fail the whole installation audit");
    assert_eq!(error.code(), "remote.pairing.paired_conflict");
    let error = paired
        .open_exact(alias_identity)
        .expect_err("marker body cannot be opened through a different account identity");
    assert_eq!(error.code(), "remote.pairing.paired_conflict");
}

#[test]
fn paired_machine_store_never_repairs_a_missing_final_item() {
    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    promote_for_paired_open(&store, &fixture, &state_root, 0x71);

    let grant = paired_account(&fixture, PairedRemoteKeyPurpose::DeviceGrant);
    store.delete_exact(&grant).unwrap();
    let writes_before = store.writes.load(Ordering::SeqCst);
    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let list_error = paired
        .list()
        .expect_err("list must audit every marker instead of omitting corrupt entries");
    assert_eq!(list_error.code(), "remote.pairing.paired_incomplete");
    let open_error = paired
        .open_exact(fixture_paired_identity(&fixture))
        .expect_err("exact open must fail closed on a missing final grant");
    assert_eq!(open_error.code(), "remote.pairing.paired_incomplete");
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before);
    assert!(store.load(&grant).unwrap().is_none());
}

#[test]
fn paired_machine_store_rejects_offline_counter_guard_tamper_without_writes() {
    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    promote_for_paired_open(&store, &fixture, &state_root, 0x81);

    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let mut tampered = store
        .load(&counter)
        .unwrap()
        .unwrap()
        .expose_secret()
        .to_vec();
    store.delete_exact(&counter).unwrap();
    tampered[0] ^= 1;
    store
        .persist_immutable(&counter, &RemoteSecret::new(tampered.clone()))
        .unwrap();
    let writes_before = store.writes.load(Ordering::SeqCst);

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let list_error = paired
        .list()
        .expect_err("full list audit must reject a noncanonical CounterGuard");
    assert_eq!(list_error.code(), "remote.pairing.paired_invalid");
    let open_error = paired
        .open_exact(fixture_paired_identity(&fixture))
        .expect_err("exact open must reject the same durable tamper");
    assert_eq!(open_error.code(), "remote.pairing.paired_invalid");
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        tampered
    );
}

#[test]
fn paired_machine_store_rejects_offline_sealed_state_tamper_without_rewriting_it() {
    let fixture = Fixture::new();
    let store = UnknownCommitStore::new(usize::MAX);
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0x91);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    let mut tampered = fs::read(&state_path).expect("read sealed paired state");
    *tampered
        .last_mut()
        .expect("sealed state includes an AEAD tag") ^= 1;
    fs::write(&state_path, &tampered).expect("apply offline sealed-state tamper");
    let writes_before = store.writes.load(Ordering::SeqCst);

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let list_error = paired
        .list()
        .expect_err("full list audit must reject sealed-state authentication failure");
    assert_eq!(
        list_error.code(),
        "remote.crypto_state.authentication_failed"
    );
    assert_eq!(fs::read(&state_path).unwrap(), tampered);

    let open_error = paired
        .open_exact(fixture_paired_identity(&fixture))
        .expect_err("exact open must reject the same sealed-state authentication failure");
    assert_eq!(
        open_error.code(),
        "remote.crypto_state.authentication_failed"
    );
    assert_eq!(store.writes.load(Ordering::SeqCst), writes_before);
    assert_eq!(fs::read(&state_path).unwrap(), tampered);
}

struct PanicAfterPairedMutationStage {
    stage: PairedMutationStage,
    hits: AtomicUsize,
}

struct MutationCountingRemoteKeyStore {
    inner: MemoryRemoteKeyStore,
    mutation_calls: AtomicUsize,
}

impl MutationCountingRemoteKeyStore {
    fn new() -> Self {
        Self {
            inner: MemoryRemoteKeyStore::new(),
            mutation_calls: AtomicUsize::new(0),
        }
    }

    fn mutation_calls(&self) -> usize {
        self.mutation_calls.load(Ordering::SeqCst)
    }
}

impl RemoteKeyStore for MutationCountingRemoteKeyStore {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        self.inner.load(account)
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.persist_immutable(account, value)
    }

    fn compare_and_replace_exact(
        &self,
        account: &RemoteKeyAccount,
        expected: &RemoteSecret,
        replacement: &RemoteSecret,
    ) -> Result<(), RemoteKeyStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .compare_and_replace_exact(account, expected, replacement)
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.delete_exact(account)
    }

    fn list_paired_commit_markers(
        &self,
        installation_id: Uuid,
    ) -> Result<Vec<ParsedPairedRemoteKeyAccount>, RemoteKeyStoreError> {
        self.inner.list_paired_commit_markers(installation_id)
    }
}

impl PairedMutationObserver for PanicAfterPairedMutationStage {
    fn after_stage(&self, stage: PairedMutationStage) {
        if stage == self.stage {
            let previous_hits = self.hits.fetch_add(1, Ordering::SeqCst);
            if previous_hits == 0 {
                panic!("injected crash after {stage:?}");
            }
        }
    }
}

fn crash_counter_reservation_after(
    store: &dyn RemoteKeyStore,
    fixture: &Fixture,
    state_root: &Path,
    stage: PairedMutationStage,
    seed: u8,
) {
    let observer = Arc::new(PanicAfterPairedMutationStage {
        stage,
        hits: AtomicUsize::new(0),
    });
    let observer_seam: Arc<dyn PairedMutationObserver> = observer.clone();
    let paired = PairedMachineStore::new_with_mutation_observer(
        store,
        INSTALLATION_ID,
        state_root,
        observer_seam,
    );
    let mut opened = paired
        .open_exact(fixture_paired_identity(fixture))
        .expect("open paired machine before injected mutation crash");
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let mut rng = DeterministicRng::new([seed; 32]);
        opened
            .reserve_command_counter_block(&mut rng)
            .expect("observer must panic after the durable stage");
    }));
    assert!(crashed.is_err(), "{stage:?} observer must inject a crash");
    assert_eq!(observer.hits.load(Ordering::SeqCst), 1);
}

#[test]
fn first_counter_reservation_upgrades_v1_without_rewriting_marker_and_restart_skips_the_block() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0xa1);
    drop(promoted);

    let marker = paired_account(&fixture, PairedRemoteKeyPurpose::CommitMarker);
    let marker_before = store.load(&marker).unwrap().unwrap();
    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = paired
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    let mut first_rng = DeterministicRng::new([0xa2; 32]);
    let first = opened
        .reserve_command_counter_block(&mut first_rng)
        .unwrap();
    assert_eq!(first.start(), 0);
    assert_eq!(first.end_exclusive(), 1_024);
    drop(opened);
    assert_eq!(
        store.load(&marker).unwrap().unwrap().expose_secret(),
        marker_before.expose_secret()
    );

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut reopened = restarted
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    let mut second_rng = DeterministicRng::new([0xa3; 32]);
    let second = reopened
        .reserve_command_counter_block(&mut second_rng)
        .unwrap();
    assert_eq!(second.start(), 1_024);
    assert_eq!(second.end_exclusive(), 2_048);
    assert_ne!(first.reservation_id(), second.reservation_id());
}

#[test]
fn every_counter_reservation_durable_stage_recovers_without_reusing_the_crashed_block() {
    for (index, stage) in [
        PairedMutationStage::GuardPendingDurable,
        PairedMutationStage::StateDurable,
        PairedMutationStage::GuardStableDurable,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().unwrap();
        let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
        let promoted =
            promote_for_paired_open(&store, &fixture, &state_root, 0xb1 + index as u8 * 4);
        let state_path = promoted.state_path().to_path_buf();
        drop(promoted);
        let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
        let guard_before = store.load(&counter).unwrap().unwrap();
        let state_before = fs::read(&state_path).unwrap();

        crash_counter_reservation_after(
            &store,
            &fixture,
            &state_root,
            stage,
            0xb2 + index as u8 * 4,
        );
        let guard_after_crash = store.load(&counter).unwrap().unwrap();
        let state_after_crash = fs::read(&state_path).unwrap();
        assert_ne!(
            guard_after_crash.expose_secret(),
            guard_before.expose_secret(),
            "{stage:?} must follow the pending-guard CAS"
        );
        if stage == PairedMutationStage::GuardPendingDurable {
            assert_eq!(state_after_crash, state_before);
        } else {
            assert_ne!(state_after_crash, state_before);
        }

        let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        let mut reopened = restarted
            .open_exact(fixture_paired_identity(&fixture))
            .expect("restart must reconcile an authenticated mutation boundary");
        let mut restart_rng = DeterministicRng::new([0xb3 + index as u8 * 4; 32]);
        let next = reopened
            .reserve_command_counter_block(&mut restart_rng)
            .expect("crashed block must be skipped, never reused");
        assert_eq!(next.start(), 1_024, "stage {stage:?}");
        assert_eq!(next.end_exclusive(), 2_048, "stage {stage:?}");
    }
}

#[test]
fn pending_second_counter_block_is_sealed_as_a_skipped_fence_before_later_reservations() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0xbb);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    let marker = paired_account(&fixture, PairedRemoteKeyPurpose::CommitMarker);
    let marker_before = store.load(&marker).unwrap().unwrap();
    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = paired
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    let mut first_rng = DeterministicRng::new([0xbc; 32]);
    let first = opened
        .reserve_command_counter_block(&mut first_rng)
        .unwrap();
    assert_eq!(first.start(), 0);
    assert_eq!(first.end_exclusive(), 1_024);
    drop(opened);
    let state_after_first = fs::read(&state_path).unwrap();

    crash_counter_reservation_after(
        &store,
        &fixture,
        &state_root,
        PairedMutationStage::GuardPendingDurable,
        0xbd,
    );
    assert_eq!(
        fs::read(&state_path).unwrap(),
        state_after_first,
        "guard-first crash must leave the previous sealed state durable"
    );

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut recovered = restarted
        .open_exact(fixture_paired_identity(&fixture))
        .expect("open must seal the frozen second block before finalizing its guard");
    assert_ne!(
        fs::read(&state_path).unwrap(),
        state_after_first,
        "recovery must persist the skipped [1024,2048) reservation as a sealed fence"
    );
    let mut third_rng = DeterministicRng::new([0xbe; 32]);
    let third = recovered
        .reserve_command_counter_block(&mut third_rng)
        .expect("the crashed second block must never be returned");
    assert_eq!(third.start(), 2_048);
    assert_eq!(third.end_exclusive(), 3_072);
    assert_ne!(first.reservation_id(), third.reservation_id());
    drop(recovered);

    assert_eq!(
        store.load(&marker).unwrap().unwrap().expose_secret(),
        marker_before.expose_secret(),
        "mutable reservations must never rewrite the initial commit marker"
    );
    let restarted_again = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut reopened = restarted_again
        .open_exact(fixture_paired_identity(&fixture))
        .expect("recovered guard and sealed state must remain coherent after another restart");
    let mut fourth_rng = DeterministicRng::new([0xbf; 32]);
    let fourth = reopened
        .reserve_command_counter_block(&mut fourth_rng)
        .unwrap();
    assert_eq!(fourth.start(), 3_072);
    assert_eq!(fourth.end_exclusive(), 4_096);
}

#[test]
fn recovery_state_commit_crash_reopens_pending_next_and_only_finalizes_the_guard() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0x61);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    let marker = paired_account(&fixture, PairedRemoteKeyPurpose::CommitMarker);
    let marker_before = store.load(&marker).unwrap().unwrap();
    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = paired
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    let mut first_rng = DeterministicRng::new([0x62; 32]);
    let first = opened
        .reserve_command_counter_block(&mut first_rng)
        .unwrap();
    assert_eq!(first.start(), 0);
    assert_eq!(first.end_exclusive(), 1_024);
    drop(opened);

    crash_counter_reservation_after(
        &store,
        &fixture,
        &state_root,
        PairedMutationStage::GuardPendingDurable,
        0x63,
    );
    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let pending_guard = store.load(&counter).unwrap().unwrap();
    let previous_state = fs::read(&state_path).unwrap();
    let mutations_before_recovery = store.mutation_calls();

    let observer = Arc::new(PanicAfterPairedMutationStage {
        stage: PairedMutationStage::RecoveryStateDurable,
        hits: AtomicUsize::new(0),
    });
    let observer_seam: Arc<dyn PairedMutationObserver> = observer.clone();
    let recovering = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        observer_seam,
    );
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        recovering
            .open_exact(fixture_paired_identity(&fixture))
            .expect("recovery observer must panic after its sealed-state CAS");
    }));
    assert!(crashed.is_err());
    assert_eq!(observer.hits.load(Ordering::SeqCst), 1);
    assert_ne!(fs::read(&state_path).unwrap(), previous_state);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        pending_guard.expose_secret(),
        "recovery crash must leave an authenticated pending+next pair"
    );
    assert_eq!(
        store.mutation_calls(),
        mutations_before_recovery,
        "state recovery must not touch any Keychain account before guard finalize"
    );

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut recovered = restarted
        .open_exact(fixture_paired_identity(&fixture))
        .expect("pending+next recovery must only finalize the frozen guard");
    assert_eq!(
        store.mutation_calls(),
        mutations_before_recovery + 1,
        "only the counter guard may change while finalizing pending+next"
    );
    let mut third_rng = DeterministicRng::new([0x64; 32]);
    let third = recovered
        .reserve_command_counter_block(&mut third_rng)
        .unwrap();
    assert_eq!(third.start(), 2_048);
    assert_eq!(third.end_exclusive(), 3_072);
    assert_eq!(
        store.load(&marker).unwrap().unwrap().expose_secret(),
        marker_before.expose_secret()
    );
}

#[test]
fn marker_inventory_list_is_read_only_while_counter_guard_is_pending() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0xc1);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    crash_counter_reservation_after(
        &store,
        &fixture,
        &state_root,
        PairedMutationStage::GuardPendingDurable,
        0xc2,
    );
    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let pending_guard = store.load(&counter).unwrap().unwrap();
    let previous_state = fs::read(&state_path).unwrap();
    let mutations_before = store.mutation_calls();

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let listed = paired
        .list()
        .expect("list may audit GuardPending but must not finalize recovery");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].identity(), fixture_paired_identity(&fixture));
    assert_eq!(store.mutation_calls(), mutations_before);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        pending_guard.expose_secret()
    );
    assert_eq!(fs::read(&state_path).unwrap(), previous_state);
}

#[test]
fn authenticated_old_state_rollback_under_stable_v2_guard_fails_without_repair() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0xd1);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);
    let authenticated_v1_state = fs::read(&state_path).unwrap();

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = paired
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    let mut rng = DeterministicRng::new([0xd2; 32]);
    let first = opened.reserve_command_counter_block(&mut rng).unwrap();
    assert_eq!(first.start(), 0);
    assert_eq!(first.end_exclusive(), 1_024);
    drop(opened);

    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let stable_guard = store.load(&counter).unwrap().unwrap();
    assert_ne!(fs::read(&state_path).unwrap(), authenticated_v1_state);
    fs::write(&state_path, &authenticated_v1_state).unwrap();
    let rolled_back_state = fs::read(&state_path).unwrap();
    let mutations_before = store.mutation_calls();

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let list_error = restarted
        .list()
        .expect_err("stable V2 guard must reject an authenticated old state");
    assert_eq!(list_error.code(), "remote.pairing.paired_conflict");
    let open_error = restarted
        .open_exact(fixture_paired_identity(&fixture))
        .expect_err("rollback must fail closed instead of repairing either side");
    assert_eq!(open_error.code(), "remote.pairing.paired_conflict");
    assert_eq!(store.mutation_calls(), mutations_before);
    assert_eq!(fs::read(&state_path).unwrap(), rolled_back_state);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        stable_guard.expose_secret()
    );
}

#[test]
fn state_commit_with_stale_handle_reloads_durable_previous_or_next_before_retrying() {
    let fixture = Fixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    drop(promote_for_paired_open(&store, &fixture, &state_root, 0xe1));

    let observer = Arc::new(PanicAfterPairedMutationStage {
        stage: PairedMutationStage::StateDurable,
        hits: AtomicUsize::new(0),
    });
    let observer_seam: Arc<dyn PairedMutationObserver> = observer.clone();
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        observer_seam,
    );
    let mut opened = paired
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    let first = catch_unwind(AssertUnwindSafe(|| {
        let mut rng = DeterministicRng::new([0xe2; 32]);
        opened.reserve_command_counter_block(&mut rng).unwrap();
    }));
    assert!(first.is_err());

    // File CAS 已 durable，但 observer 位于内存 cache 更新前；同一 handle 必须先重读
    // durable pending+next，绝不能用 stale previous hash finalize。
    let mut retry_rng = DeterministicRng::new([0xe3; 32]);
    let retry = opened
        .reserve_command_counter_block(&mut retry_rng)
        .expect("same handle must reload durable state before recovery");
    assert_eq!(retry.start(), 1_024);
    assert_eq!(retry.end_exclusive(), 2_048);
    assert_eq!(observer.hits.load(Ordering::SeqCst), 2);
    drop(opened);

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut reopened = restarted
        .open_exact(fixture_paired_identity(&fixture))
        .expect("stale-handle recovery must leave a coherent durable pair");
    let mut next_rng = DeterministicRng::new([0xe4; 32]);
    let next = reopened
        .reserve_command_counter_block(&mut next_rng)
        .unwrap();
    assert_eq!(next.start(), 2_048);
    assert_eq!(next.end_exclusive(), 3_072);
}

#[test]
fn parse_valid_stable_high_water_rollback_is_rejected_without_reusing_counters() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0xf1);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = paired
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    for seed in [0xf2, 0xf3] {
        let mut rng = DeterministicRng::new([seed; 32]);
        opened.reserve_command_counter_block(&mut rng).unwrap();
    }
    drop(opened);

    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let stable = store.load(&counter).unwrap().unwrap();
    let mut rolled_back_hwm = stable.expose_secret().to_vec();
    assert_eq!(
        u64::from_be_bytes(rolled_back_hwm[60..68].try_into().unwrap()),
        2_048
    );
    rolled_back_hwm[60..68].copy_from_slice(&1_024_u64.to_be_bytes());
    store
        .compare_and_replace_exact(
            &counter,
            &stable,
            &RemoteSecret::new(rolled_back_hwm.clone()),
        )
        .unwrap();
    let state_before = fs::read(&state_path).unwrap();
    let mutations_before = store.mutation_calls();

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let error = restarted
        .list()
        .expect_err("stable HWM below sealed reservation end must fail closed");
    assert_eq!(error.code(), "remote.pairing.paired_conflict");
    assert_eq!(store.mutation_calls(), mutations_before);
    assert_eq!(fs::read(&state_path).unwrap(), state_before);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        rolled_back_hwm
    );
}

#[test]
fn v1_state_rejects_parse_valid_pending_guard_with_nonzero_previous_high_water() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0x21);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    crash_counter_reservation_after(
        &store,
        &fixture,
        &state_root,
        PairedMutationStage::GuardPendingDurable,
        0x22,
    );
    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let pending = store.load(&counter).unwrap().unwrap();
    let mut impossible_pending = pending.expose_secret().to_vec();
    assert_eq!(impossible_pending.len(), 156);
    assert_eq!(impossible_pending[6], 1);
    assert_eq!(
        u64::from_be_bytes(impossible_pending[60..68].try_into().unwrap()),
        0
    );
    assert_eq!(
        u64::from_be_bytes(impossible_pending[68..76].try_into().unwrap()),
        1_024
    );
    impossible_pending[60..68].copy_from_slice(&1_024_u64.to_be_bytes());
    impossible_pending[68..76].copy_from_slice(&2_048_u64.to_be_bytes());
    store
        .compare_and_replace_exact(
            &counter,
            &pending,
            &RemoteSecret::new(impossible_pending.clone()),
        )
        .unwrap();
    let state_before = fs::read(&state_path).unwrap();
    let mutations_before = store.mutation_calls();

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert_eq!(
        restarted.list().unwrap_err().code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(
        restarted
            .open_exact(fixture_paired_identity(&fixture))
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(store.mutation_calls(), mutations_before);
    assert_eq!(fs::read(&state_path).unwrap(), state_before);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        impossible_pending
    );
}

#[test]
fn v1_state_rejects_parse_valid_stable_v2_guard_without_a_sealed_counter_fence() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0x25);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    crash_counter_reservation_after(
        &store,
        &fixture,
        &state_root,
        PairedMutationStage::GuardPendingDurable,
        0x26,
    );
    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let pending = store.load(&counter).unwrap().unwrap();
    let pending_bytes = pending.expose_secret();
    assert_eq!(pending_bytes.len(), 156);
    let mut impossible_stable = pending_bytes[..60].to_vec();
    impossible_stable[6] = 0;
    impossible_stable.extend_from_slice(&1_024_u64.to_be_bytes());
    // Pending 的 previous_state_hash 正是当前 authenticated V1 plaintext hash。
    impossible_stable.extend_from_slice(&pending_bytes[92..124]);
    assert_eq!(impossible_stable.len(), 100);
    store
        .compare_and_replace_exact(
            &counter,
            &pending,
            &RemoteSecret::new(impossible_stable.clone()),
        )
        .unwrap();
    let state_before = fs::read(&state_path).unwrap();
    let mutations_before = store.mutation_calls();

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert_eq!(
        restarted.list().unwrap_err().code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(
        restarted
            .open_exact(fixture_paired_identity(&fixture))
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(store.mutation_calls(), mutations_before);
    assert_eq!(fs::read(&state_path).unwrap(), state_before);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        impossible_stable
    );
}

#[test]
fn v1_guard_with_authenticated_v2_state_is_an_impossible_order_and_never_repaired() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0x31);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let initial_v1_guard = store.load(&counter).unwrap().unwrap();
    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = paired
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    let mut rng = DeterministicRng::new([0x32; 32]);
    opened.reserve_command_counter_block(&mut rng).unwrap();
    drop(opened);

    let stable_v2_guard = store.load(&counter).unwrap().unwrap();
    store
        .compare_and_replace_exact(&counter, &stable_v2_guard, &initial_v1_guard)
        .unwrap();
    let state_before = fs::read(&state_path).unwrap();
    let mutations_before = store.mutation_calls();

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert_eq!(
        restarted.list().unwrap_err().code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(
        restarted
            .open_exact(fixture_paired_identity(&fixture))
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(store.mutation_calls(), mutations_before);
    assert_eq!(fs::read(&state_path).unwrap(), state_before);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        initial_v1_guard.expose_secret()
    );
}

#[test]
fn pending_guard_with_authenticated_third_state_hash_fails_closed_without_repair() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0x35);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    crash_counter_reservation_after(
        &store,
        &fixture,
        &state_root,
        PairedMutationStage::GuardPendingDurable,
        0x36,
    );
    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    let pending_first_block = store.load(&counter).unwrap().unwrap();

    // 正常恢复会跳过第一块，再提交 [1024,2048)；该 state 对旧 pending 而言既不是
    // previous V1 hash，也不是其冻结的 [0,1024) next hash。
    let recovered = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let mut opened = recovered
        .open_exact(fixture_paired_identity(&fixture))
        .unwrap();
    let mut rng = DeterministicRng::new([0x37; 32]);
    opened.reserve_command_counter_block(&mut rng).unwrap();
    drop(opened);
    let stable_second_block = store.load(&counter).unwrap().unwrap();
    store
        .compare_and_replace_exact(&counter, &stable_second_block, &pending_first_block)
        .unwrap();
    let third_state = fs::read(&state_path).unwrap();
    let mutations_before = store.mutation_calls();

    let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert_eq!(
        restarted.list().unwrap_err().code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(
        restarted
            .open_exact(fixture_paired_identity(&fixture))
            .unwrap_err()
            .code(),
        "remote.pairing.paired_conflict"
    );
    assert_eq!(store.mutation_calls(), mutations_before);
    assert_eq!(fs::read(&state_path).unwrap(), third_state);
    assert_eq!(
        store.load(&counter).unwrap().unwrap().expose_secret(),
        pending_first_block.expose_secret()
    );
}

#[test]
fn pending_previous_state_audit_recomputes_the_frozen_next_transition_without_repairing() {
    for (index, tamper_label) in ["reservation-id", "next-state-hash"]
        .into_iter()
        .enumerate()
    {
        let fixture = Fixture::new();
        let store = MutationCountingRemoteKeyStore::new();
        let temp = tempfile::tempdir().unwrap();
        let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
        let promoted = promote_for_paired_open(
            &store,
            &fixture,
            &state_root,
            0x45 + u8::try_from(index).unwrap() * 4,
        );
        let state_path = promoted.state_path().to_path_buf();
        drop(promoted);

        crash_counter_reservation_after(
            &store,
            &fixture,
            &state_root,
            PairedMutationStage::GuardPendingDurable,
            0x46 + u8::try_from(index).unwrap() * 4,
        );
        let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
        let pending = store.load(&counter).unwrap().unwrap();
        let mut tampered = pending.expose_secret().to_vec();
        assert_eq!(tampered.len(), 156);
        match index {
            0 => tampered[76] ^= 1,
            1 => tampered[124] ^= 1,
            _ => unreachable!(),
        }
        store
            .compare_and_replace_exact(&counter, &pending, &RemoteSecret::new(tampered.clone()))
            .unwrap();
        let state_before = fs::read(&state_path).unwrap();
        let mutations_before = store.mutation_calls();

        let restarted = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        assert_eq!(
            restarted.list().unwrap_err().code(),
            "remote.pairing.paired_conflict",
            "{tamper_label} must be rejected by read-only inventory audit"
        );
        assert_eq!(
            restarted
                .open_exact(fixture_paired_identity(&fixture))
                .unwrap_err()
                .code(),
            "remote.pairing.paired_conflict",
            "{tamper_label} must be rejected before recovery mutation"
        );
        assert_eq!(store.mutation_calls(), mutations_before);
        assert_eq!(fs::read(&state_path).unwrap(), state_before);
        assert_eq!(
            store.load(&counter).unwrap().unwrap().expose_secret(),
            tampered
        );
    }
}

#[test]
fn marker_backed_open_with_missing_kek_fails_closed_without_generating_or_repairing() {
    let fixture = Fixture::new();
    let store = MutationCountingRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let state_root = fs::canonicalize(temp.path()).unwrap().join("paired-state");
    let promoted = promote_for_paired_open(&store, &fixture, &state_root, 0x39);
    let state_path = promoted.state_path().to_path_buf();
    drop(promoted);

    let kek = paired_account(&fixture, PairedRemoteKeyPurpose::DeviceStorageKek);
    store.delete_exact(&kek).unwrap();
    let state_before = fs::read(&state_path).unwrap();
    let mutations_before = store.mutation_calls();
    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    assert_eq!(
        paired.list().unwrap_err().code(),
        "remote.pairing.paired_incomplete"
    );
    assert_eq!(
        paired
            .open_exact(fixture_paired_identity(&fixture))
            .unwrap_err()
            .code(),
        "remote.pairing.paired_incomplete"
    );
    assert_eq!(store.mutation_calls(), mutations_before);
    assert!(store.load(&kek).unwrap().is_none());
    assert_eq!(fs::read(&state_path).unwrap(), state_before);
}
