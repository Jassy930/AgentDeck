use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PendingRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyPersistence,
    RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use agentdeck_cli::remote::pending::PendingPairingCoordinator;
use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{HpkePrivateKey, SigningKey, open_pair_request, sha256, sign_tbs};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    E2EE_FORMAT_VERSION, OuterContextV1, OuterFrameKind, PairInviteV1, PairRequestInfoV1,
    PairRequestPlaintextV1, PairRequestV1,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::{
    CertRole, Ed25519Signature, PublicKeyBytes, SignedCertificate,
};
use agentdeck_protocol::relay_v2::id::{
    LinkGeneration, MachineRouteId, PairRouteId, RelayServerId, RootKeyId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use uuid::Uuid;

const NOW_MS: u64 = 1_900_000_000_000;
const INSTALLATION_ID: Uuid = Uuid::from_bytes([0x11; 16]);
const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x21; 16]);
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
    fn new() -> Self {
        let root = SigningKey::from_seed(&[0x31; 32]);
        let data = SigningKey::from_seed(&[0x32; 32]);
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
