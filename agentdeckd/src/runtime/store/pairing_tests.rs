use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    HpkePrivateKey, SigningKey, ValidatedRelayReceiptSignerIdentityV1, VerifiedPairRequestV1,
    open_pair_request_verified, seal_pair_request, sha256, sign_tbs,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    E2EE_FORMAT_VERSION, OuterContextV1, OuterFrameKind, PairInviteV1, PairRequestInfoV1,
    PairRequestPlaintextV1, PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::frame::{
    OpaqueRouteFrame, PairData, PairRouteOpened, RelayFrameBody,
};
use agentdeck_protocol::relay_v2::{
    CertRole, Digest32, ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, EnrollmentCode,
    LinkGeneration, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, MachineRouteId,
    PairRouteId, PublicKeyBytes, RELAY_PROTOCOL_VERSION, RelayServerId, RootKeyId,
    SignedCertificate, TrustEpoch, decode, encode, enrollment_receipt_hash,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

use crate::runtime::model::{
    IdempotencyOwner, MachineIdentityBinding, RuntimeCapacityObservation, RuntimeCapacityProbe,
    RuntimeCapacityProbeError, RuntimeClock, RuntimeClockError, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, SecretBytes, StorageKek, load_or_create_storage_kek};

use super::admission::RUNTIME_DB_HARD_LIMIT_BYTES;
use super::cipher::{KeyWrapAad, RowAad, RuntimeKeyBundle};
use super::pairing::{
    AcceptPairRequest, AcceptPairRequestOutcome, CommitPairPending, CommitPairPendingOutcome,
    PairingInviteLifecycle, PairingInviteRecord, PreparePairingInvite, PreparePairingInviteOutcome,
    prepare_write,
};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::{RuntimeId, RuntimeStoreHandle};

pub(crate) const RELAY: RelayServerId = RelayServerId::from_bytes([0x31; 16]);
pub(super) const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const ROOT_SEED: [u8; 32] = [0x41; 32];
const LINK_SEED: [u8; 32] = [0x42; 32];
const DATA_SEED: [u8; 32] = [0x43; 32];
pub(super) const NOW_MS: u64 = 1_800_000_000_000;

pub(super) struct TestRoot(PathBuf);

impl TestRoot {
    pub(super) fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-pairing-store-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create pairing store test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure pairing store test root");
        }
        Self(path)
    }

    pub(super) fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn artifact_bytes(database: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            let path = PathBuf::from(format!("{}{suffix}", database.display()));
            let bytes = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("read artifact {}: {error}", path.display()),
            };
            (path, bytes)
        })
        .collect()
}

fn replace_pairing_payload_private_key(encoded: &[u8], replacement: &[u8; 32]) -> Vec<u8> {
    assert_eq!(encoded.get(..4), Some(&b"ADP1"[..]));
    let mut cursor = 4_usize;
    let mut fields = Vec::with_capacity(7);
    for _ in 0..7 {
        let length = u32::from_be_bytes(
            encoded[cursor..cursor + 4]
                .try_into()
                .expect("payload field length"),
        ) as usize;
        cursor += 4;
        fields.push(encoded[cursor..cursor + length].to_vec());
        cursor += length;
    }
    assert_eq!(cursor, encoded.len());
    fields[3] = replacement.to_vec();
    let mut rewritten = b"ADP1".to_vec();
    for field in fields {
        rewritten.extend_from_slice(
            &u32::try_from(field.len())
                .expect("test payload field length")
                .to_be_bytes(),
        );
        rewritten.extend_from_slice(&field);
    }
    rewritten
}

fn rewrite_sealed_pairing_private_key(
    database: &Path,
    storage_kek: &StorageKek,
    replacement: [u8; 32],
) {
    let connection = rusqlite::Connection::open(database).expect("open offline database");
    let (database_id, key_generation, wrapped): (Vec<u8>, i64, Vec<u8>) = connection
        .query_row(
            "SELECT database_id, key_generation, wrapped_key_bundle
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read runtime key metadata");
    let database_id: [u8; 16] = database_id.try_into().expect("database id shape");
    let key_bundle = RuntimeKeyBundle::unwrap(
        storage_kek,
        &KeyWrapAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
        },
        &wrapped,
    )
    .expect("unwrap runtime row keys");
    assert_eq!(i64::from(key_bundle.generation()), key_generation);
    #[allow(clippy::type_complexity)]
    let row: (
        Vec<u8>,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT pairing_id, lifecycle, relay_server_id, machine_route, pair_route,
                    expires_at_ms, created_at_ms, state_changed_at_ms, sealed_state
             FROM remote_pairings",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .expect("read sealed pairing row");
    assert_eq!(row.1, "routeOpening");
    let pairing_id: [u8; 16] = row.0.try_into().expect("pairing id shape");
    let relay_server_id: [u8; 16] = row.2.try_into().expect("relay id shape");
    let machine_route: [u8; 16] = row.3.try_into().expect("machine route shape");
    let pair_route: [u8; 16] = row.4.try_into().expect("pair route shape");
    let expires_at_ms = u64::try_from(row.5).expect("expiry shape");
    let created_at_ms = u64::try_from(row.6).expect("created time shape");
    let state_changed_at_ms = u64::try_from(row.7).expect("state time shape");
    let aad = RowAad {
        schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
        schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
        database_id: &database_id,
        table: b"remote_pairings",
        primary_key: &pairing_id,
        column: b"sealed_state",
    };
    let plaintext = key_bundle
        .row_cipher()
        .open_bounded(&aad, &row.8, 8 * 1024 * 1024)
        .expect("open pairing payload for mismatch fixture");
    let rewritten = replace_pairing_payload_private_key(plaintext.expose_secret(), &replacement);
    let sealed = key_bundle
        .row_cipher()
        .seal_bounded(&aad, &rewritten, 8 * 1024 * 1024)
        .expect("reseal mismatched pairing payload");
    assert_eq!(sealed.len(), row.8.len());
    let sealed_len = u64::try_from(sealed.len()).expect("sealed length");
    let sealed_hash = sha256(&sealed);
    let lifecycle = [0_u8];
    let metadata_token = super::stream::metadata_mac(
        &key_bundle,
        b"remote.pairing.metadata.v1",
        &[
            &database_id,
            &pairing_id,
            &lifecycle,
            &relay_server_id,
            &machine_route,
            &pair_route,
            &expires_at_ms.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
            &sealed_len.to_be_bytes(),
            &sealed_hash,
        ],
    )
    .expect("authenticate mismatched pairing fixture");
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_pairings
                 SET sealed_state = ?1, sealed_state_bytes = ?2, metadata_token = ?3",
                rusqlite::params![
                    &sealed,
                    i64::try_from(sealed_len).expect("sealed length fits i64"),
                    &metadata_token[..],
                ],
            )
            .expect("write mismatched pairing fixture"),
        1
    );
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint mismatched pairing fixture");
}

pub(super) struct GenerousCapacity;

impl RuntimeCapacityProbe for GenerousCapacity {
    fn observe(
        &self,
        database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        let bytes = |path: &Path| fs::metadata(path).map_or(0, |metadata| metadata.len());
        Ok(RuntimeCapacityObservation {
            main_bytes: bytes(database),
            wal_bytes: bytes(&PathBuf::from(format!("{}-wal", database.display()))),
            shm_bytes: bytes(&PathBuf::from(format!("{}-shm", database.display()))),
            filesystem_total_bytes: 1024 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 1024 * 1024 * 1024 * 1024,
        })
    }
}

struct FullCapacity;

impl RuntimeCapacityProbe for FullCapacity {
    fn observe(
        &self,
        _database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        Ok(RuntimeCapacityObservation {
            main_bytes: RUNTIME_DB_HARD_LIMIT_BYTES,
            wal_bytes: 0,
            shm_bytes: 0,
            filesystem_total_bytes: 16 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 16 * 1024 * 1024 * 1024,
        })
    }
}

pub(super) struct OneShotFault {
    pub(super) operation: RuntimeStoreOperation,
    pub(super) fired: AtomicBool,
}

impl RuntimeStoreFaultInjector for OneShotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

pub(super) struct DeterministicRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    offset: usize,
}

impl DeterministicRng {
    pub(super) fn new(seed: [u8; 32]) -> Self {
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
                let mut input = b"AgentDeck/PairingStoreTestRng\0".to_vec();
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

#[derive(Clone)]
pub(super) struct TestClock(pub(super) Arc<AtomicU64>);

impl RuntimeClock for TestClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

pub(super) fn owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x91; 32],
        uid: 501,
        client_installation_id: [0x92; 16],
    }
}

fn other_owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x91; 32],
        uid: 502,
        client_installation_id: [0x93; 16],
    }
}

pub(super) fn private_key(seed: u8) -> SecretBytes {
    SecretBytes::new(vec![seed; 32])
}

fn request_info(invite: &PairInviteV1) -> PairRequestInfoV1 {
    PairRequestInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: invite.pair_route,
        invite_hash: invite.canonical_sha256().expect("canonical invite hash"),
        expiry_ms: invite.expires_at_ms,
    }
}

fn pairing_context(invite: &PairInviteV1, frame_kind: OuterFrameKind) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(invite.pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

pub(super) fn verified_request(
    canonical_invite: &[u8],
    invite_private_seed: u8,
    device_sign_seed: u8,
    device_hpke_seed: u8,
    rng_seed: u8,
) -> VerifiedPairRequestV1 {
    verified_request_with_authorization(
        canonical_invite,
        invite_private_seed,
        device_sign_seed,
        device_hpke_seed,
        rng_seed,
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verified_request_with_authorization(
    canonical_invite: &[u8],
    invite_private_seed: u8,
    device_sign_seed: u8,
    device_hpke_seed: u8,
    rng_seed: u8,
    capabilities: Vec<AuthorizationCapabilityV1>,
    permissions: Vec<AuthorizationPermissionV1>,
) -> VerifiedPairRequestV1 {
    let invite = PairInviteV1::from_canonical_bytes(canonical_invite).expect("parse invite");
    let invite_private =
        HpkePrivateKey::from_bytes(&[invite_private_seed; 32]).expect("invite private key");
    let device_sign = SigningKey::from_seed(&[device_sign_seed; 32]);
    let (_, device_hpke_public) = HpkePrivateKey::derive_keypair(&[device_hpke_seed; 32]);
    let plaintext = PairRequestPlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        invite_secret: invite.invite_secret,
        device_sign_pubkey: PublicKeyBytes(device_sign.verifying_key().to_bytes()),
        device_hpke_pubkey: PublicKeyBytes(
            device_hpke_public
                .to_bytes()
                .try_into()
                .expect("device HPKE public key shape"),
        ),
        authorization_request: AuthorizationRequestV1 {
            format_version: E2EE_FORMAT_VERSION,
            device_display_name: "Remote CLI".to_owned(),
            capabilities,
            permissions,
        },
    };
    let info = request_info(&invite);
    let context = pairing_context(&invite, OuterFrameKind::PairRequest);
    let mut rng = DeterministicRng::new([rng_seed; 32]);
    let envelope = seal_pair_request(
        &invite_private.public_key(),
        &info,
        &context,
        &plaintext,
        &device_sign,
        &mut rng,
    )
    .expect("seal PairRequest");
    open_pair_request_verified(
        &invite_private,
        &info,
        &context,
        &invite.invite_secret,
        &envelope,
    )
    .expect("verify PairRequest")
}

pub(super) fn pending_envelope(seed: u8) -> PairingControlEnvelopeV1 {
    let envelope = PairingControlEnvelopeV1 {
        format_version: E2EE_FORMAT_VERSION,
        enc: vec![seed; 32],
        ciphertext: vec![seed.wrapping_add(1); 96],
    };
    envelope.validate().expect("valid pending envelope");
    envelope
}

fn consume_private_key(record: PairingInviteRecord) -> Vec<u8> {
    record
        .into_invite_hpke_private_key()
        .expect("authenticated invite private key")
        .to_bytes()
}

pub(super) fn binding() -> MachineIdentityBinding {
    let root_public_key = SigningKey::from_seed(&ROOT_SEED).verifying_key().to_bytes();
    let link_sign_public_key = SigningKey::from_seed(&LINK_SEED).verifying_key().to_bytes();
    let data_sign_public_key = SigningKey::from_seed(&DATA_SEED).verifying_key().to_bytes();
    let machine_hpke_public_key = [0x44; 32];
    MachineIdentityBinding {
        root_key_id: [0x45; 16],
        trust_epoch: 1,
        link_generation: 1,
        data_generation: 1,
        key_directory_revision: 0,
        root_public_key,
        root_fingerprint: sha256(&root_public_key),
        machine_hpke_public_key,
        machine_hpke_fingerprint: sha256(&machine_hpke_public_key),
        link_sign_public_key,
        link_sign_fingerprint: sha256(&link_sign_public_key),
        data_sign_public_key,
        data_sign_fingerprint: sha256(&data_sign_public_key),
    }
}

pub(super) fn certificate(binding: &MachineIdentityBinding, role: CertRole) -> SignedCertificate {
    let (subject, generation) = match role {
        CertRole::Link => (binding.link_sign_public_key, binding.link_generation),
        CertRole::Data => (binding.data_sign_public_key, binding.data_generation),
    };
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject),
        cert_role: role,
        generation: LinkGeneration::new(generation),
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        not_after_ms: None,
        signature: agentdeck_protocol::relay_v2::Ed25519Signature([0; 64]),
    };
    certificate.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SEED),
        &certificate.to_be_signed_v1(RELAY, MACHINE_ROUTE, binding.root_fingerprint),
    )
    .into();
    certificate
}

fn bundle() -> EnrollmentBundleV2 {
    let signer = SigningKey::from_seed(&[0x51; 32]);
    let receipt_verify_key = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signer)
        .expect("valid receipt signer")
        .bind_to_relay(RELAY)
        .expect("bind receipt signer")
        .wire_anchor()
        .clone();
    EnrollmentBundleV2 {
        version: ENROLLMENT_BUNDLE_VERSION,
        public_wss_url: "wss://relay.example.test:8443/".to_owned(),
        relay_server_id: RELAY,
        receipt_verify_key,
        code: EnrollmentCode([0x61; 32]),
        spki_pins: vec![Digest32([0x52; 32]), Digest32([0x53; 32])],
        expires_at_ms: NOW_MS + 60_000,
    }
}

fn enrollment_request(
    bundle: &EnrollmentBundleV2,
    binding: &MachineIdentityBinding,
    link: &SignedCertificate,
    data: &SignedCertificate,
) -> MachineEnrollmentRequestV1 {
    MachineEnrollmentRequestV1 {
        code: bundle.code.clone(),
        machine_route: MACHINE_ROUTE,
        root_pubkey: PublicKeyBytes(binding.root_public_key),
        link_cert: link.clone(),
        data_cert: data.clone(),
    }
}

pub(crate) async fn make_active(
    store: &RuntimeStoreHandle,
) -> (MachineIdentityBinding, SignedCertificate) {
    let binding = binding();
    store
        .prepare_machine_identity(binding.clone())
        .await
        .expect("prepare identity");
    store
        .activate_machine_identity(binding.clone())
        .await
        .expect("activate identity");
    let bundle = bundle();
    let link = certificate(&binding, CertRole::Link);
    let data = certificate(&binding, CertRole::Data);
    let request_hash = enrollment_request(&bundle, &binding, &link, &data).canonical_sha256();
    store
        .prepare_machine_enrollment(bundle, MACHINE_ROUTE, binding.clone(), link, data.clone())
        .await
        .expect("prepare enrollment");
    let response = MachineEnrollmentResponseV1::new(
        RELAY,
        MACHINE_ROUTE,
        1,
        enrollment_receipt_hash(RELAY, MACHINE_ROUTE, 1, request_hash),
    )
    .expect("valid enrollment response");
    let response_hash = response.canonical_sha256().expect("canonical response");
    store
        .record_validated_enrollment_response(request_hash, response)
        .await
        .expect("record response");
    store
        .activate_machine_enrollment(request_hash, response_hash)
        .await
        .expect("activate enrollment");
    (binding, data)
}

pub(super) fn canonical_invite(
    seed: u8,
    hpke_private_seed: u8,
    pair_route: PairRouteId,
    binding: &MachineIdentityBinding,
    data_cert: &SignedCertificate,
) -> Vec<u8> {
    canonical_invite_with(
        seed,
        hpke_private_seed,
        pair_route,
        binding,
        data_cert,
        NOW_MS + 300_000,
        "测试机器",
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn canonical_invite_with(
    seed: u8,
    hpke_private_seed: u8,
    pair_route: PairRouteId,
    binding: &MachineIdentityBinding,
    data_cert: &SignedCertificate,
    expires_at_ms: u64,
    machine_display_name: &str,
) -> Vec<u8> {
    let private = HpkePrivateKey::from_bytes(&[hpke_private_seed; 32])
        .expect("valid deterministic test HPKE private key");
    let public: [u8; 32] = private
        .public_key()
        .to_bytes()
        .try_into()
        .expect("X25519 public key is 32 bytes");
    PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        pair_route,
        invite_secret: [seed; 32],
        invite_hpke_pubkey: PublicKeyBytes(public),
        wss_url: "wss://relay.example.test:8443/".to_owned(),
        relay_server_id: RELAY,
        current_spki_pin: [0x52; 32],
        next_spki_pin: [0x53; 32],
        expires_at_ms,
        machine_root_pubkey: PublicKeyBytes(binding.root_public_key),
        machine_root_fingerprint: binding.root_fingerprint,
        data_sign_cert: data_cert.clone(),
        machine_display_name: machine_display_name.to_owned(),
    }
    .canonical_bytes()
    .expect("canonical invite")
}

pub(super) fn open_terminal(pair_route: PairRouteId, expiry_ms: u64) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteOpened(PairRouteOpened {
            machine_route: MACHINE_ROUTE,
            pair_route,
            absolute_expiry_ms: expiry_ms,
        }),
    })
}

pub(super) async fn prepare_unused_pairing(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
    data_cert: &SignedCertificate,
    pair_route: PairRouteId,
    invite_seed: u8,
    private_seed: u8,
    key: &str,
) -> (RuntimeId, Vec<u8>) {
    let canonical = canonical_invite(invite_seed, private_seed, pair_route, binding, data_cert);
    let prepared = store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            key.to_owned(),
            SecretBytes::new(canonical.clone()),
            private_key(private_seed),
        ))
        .await
        .expect("prepare pairing invite");
    let pairing_id = match prepared {
        PreparePairingInviteOutcome::Prepared { invite } => invite.pairing_id(),
        PreparePairingInviteOutcome::Replayed { .. } => panic!("fresh invite must prepare"),
        PreparePairingInviteOutcome::Terminal { .. } => panic!("fresh invite cannot be terminal"),
    };
    store
        .acknowledge_pair_route_open(pairing_id, open_terminal(pair_route, NOW_MS + 300_000))
        .await
        .expect("acknowledge pair route open");
    (pairing_id, canonical)
}

#[test]
fn invite_hpke_private_material_is_exact_nonzero_32_bytes() {
    let binding = binding();
    let data_cert = certificate(&binding, CertRole::Data);
    let invite = canonical_invite(
        0x70,
        1,
        PairRouteId::from_bytes([0x71; 16]),
        &binding,
        &data_cert,
    );
    for invalid in [vec![], vec![0; 32], vec![1; 31], vec![1; 33]] {
        assert!(matches!(
            prepare_write(PreparePairingInvite::new(
                owner(),
                "private-shape".to_owned(),
                SecretBytes::new(invite.clone()),
                SecretBytes::new(invalid),
            )),
            Err(RuntimeStoreError::PairingConflict)
        ));
    }
    prepare_write(PreparePairingInvite::new(
        owner(),
        "private-shape".to_owned(),
        SecretBytes::new(invite),
        private_key(1),
    ))
    .expect("exact nonzero private material");
    let mismatch = canonical_invite(
        0x70,
        2,
        PairRouteId::from_bytes([0x71; 16]),
        &binding,
        &data_cert,
    );
    assert!(matches!(
        prepare_write(PreparePairingInvite::new(
            owner(),
            "private-mismatch".to_owned(),
            SecretBytes::new(mismatch),
            private_key(1),
        )),
        Err(RuntimeStoreError::PairingConflict)
    ));
}

#[tokio::test]
async fn durable_prepare_replays_exact_invite_and_open_then_acknowledges_exact_terminal() {
    let root = TestRoot::new("prepare-replay-ack");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    let pair_route = PairRouteId::from_bytes([0x71; 16]);
    let invite = canonical_invite(0x72, 0xe1, pair_route, &binding, &data_cert);

    let prepared = store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            "invite-1".to_owned(),
            SecretBytes::new(invite.clone()),
            private_key(0xe1),
        ))
        .await
        .expect("prepare invite");
    let first = match prepared {
        PreparePairingInviteOutcome::Prepared { invite } => invite,
        PreparePairingInviteOutcome::Replayed { .. } => panic!("first write must prepare"),
        PreparePairingInviteOutcome::Terminal { .. } => panic!("first write cannot be terminal"),
    };
    assert_eq!(first.lifecycle(), PairingInviteLifecycle::RouteOpening);
    assert_eq!(first.pair_route().as_bytes(), pair_route.as_bytes());
    assert_eq!(first.canonical_invite(), invite);
    let pairing_id = first.pairing_id();
    let open_frame = first.canonical_open_frame().to_vec();
    assert!(matches!(
        first.into_invite_hpke_private_key(),
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert!(matches!(
        decode(&open_frame).expect("decode open frame").body,
        RelayFrameBody::OpenPairRoute(_)
    ));

    store.shutdown().await.expect("shutdown before retry");
    clock.store(NOW_MS + 1_000, Ordering::SeqCst);
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen store");
    let retry_route = PairRouteId::from_bytes([0x73; 16]);
    let retry_invite = canonical_invite_with(
        0x74,
        0xe2,
        retry_route,
        &binding,
        &data_cert,
        NOW_MS + 240_000,
        "测试机器",
    );
    let mut retry_invite =
        PairInviteV1::from_canonical_bytes(&retry_invite).expect("parse retry invite");
    retry_invite.wss_url = "wss://rotated-relay.example.test:9443/".to_owned();
    retry_invite.relay_server_id = RelayServerId::from_bytes([0x81; 16]);
    retry_invite.current_spki_pin = [0x82; 32];
    retry_invite.next_spki_pin = [0x83; 32];
    retry_invite.machine_root_pubkey = PublicKeyBytes([0x84; 32]);
    retry_invite.machine_root_fingerprint = sha256(&retry_invite.machine_root_pubkey.0);
    retry_invite.data_sign_cert.subject_pubkey = PublicKeyBytes([0x85; 32]);
    retry_invite.data_sign_cert.generation = LinkGeneration::new(2);
    retry_invite.data_sign_cert.signature =
        agentdeck_protocol::relay_v2::Ed25519Signature([0x86; 64]);
    let retry_invite = retry_invite
        .canonical_bytes()
        .expect("canonical rotated-binding retry invite");
    let replayed = store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            "invite-1".to_owned(),
            SecretBytes::new(retry_invite),
            private_key(0xe2),
        ))
        .await
        .expect("replay invite");
    let replayed = match replayed {
        PreparePairingInviteOutcome::Replayed { invite } => invite,
        PreparePairingInviteOutcome::Prepared { .. } => panic!("retry must replay"),
        PreparePairingInviteOutcome::Terminal { .. } => panic!("active retry cannot be terminal"),
    };
    assert_eq!(replayed.pairing_id(), pairing_id);
    assert_eq!(replayed.pair_route().as_bytes(), pair_route.as_bytes());
    assert_eq!(replayed.expires_at_ms(), NOW_MS + 300_000);
    assert_eq!(replayed.canonical_invite(), invite);
    assert_eq!(replayed.canonical_open_frame(), open_frame);
    assert!(matches!(
        replayed.into_invite_hpke_private_key(),
        Err(RuntimeStoreError::PairingConflict)
    ));

    let changed_display = canonical_invite_with(
        0x75,
        0xe3,
        PairRouteId::from_bytes([0x76; 16]),
        &binding,
        &data_cert,
        NOW_MS + 250_000,
        "另一台机器",
    );
    assert!(matches!(
        store
            .prepare_pairing_invite(PreparePairingInvite::new(
                owner(),
                "invite-1".to_owned(),
                SecretBytes::new(changed_display),
                private_key(0xe3),
            ))
            .await,
        Err(RuntimeStoreError::IdempotencyConflict)
    ));

    assert!(matches!(
        store
            .prepare_pairing_invite(PreparePairingInvite::new(
                other_owner(),
                "other-caller-same-route".to_owned(),
                SecretBytes::new(invite.clone()),
                private_key(0xe1),
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));

    assert!(matches!(
        store
            .acknowledge_pair_route_open(pairing_id, open_terminal(pair_route, NOW_MS + 299_999),)
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(
        store
            .load_pairing_invite(pairing_id)
            .await
            .expect("load routeOpening")
            .expect("invite exists")
            .lifecycle(),
        PairingInviteLifecycle::RouteOpening
    );

    let terminal = open_terminal(pair_route, NOW_MS + 300_000);
    let acknowledged = store
        .acknowledge_pair_route_open(pairing_id, terminal.clone())
        .await
        .expect("acknowledge open");
    assert_eq!(
        acknowledged.invite().lifecycle(),
        PairingInviteLifecycle::Unused
    );
    assert!(!acknowledged.replayed());
    let replayed_ack = store
        .acknowledge_pair_route_open(pairing_id, terminal)
        .await
        .expect("replay acknowledge open");
    assert!(replayed_ack.replayed());
    assert_eq!(replayed_ack.invite().pairing_id(), pairing_id);

    let loaded = store
        .load_pairing_invite(pairing_id)
        .await
        .expect("load invite")
        .expect("invite exists");
    assert_eq!(loaded.lifecycle(), PairingInviteLifecycle::Unused);
    assert_eq!(loaded.canonical_invite(), invite);
    assert_eq!(consume_private_key(loaded), [0xe1; 32]);
    assert_eq!(
        store
            .list_pairing_recovery()
            .await
            .expect("list recovery")
            .len(),
        1
    );
    store.shutdown().await.expect("shutdown store");
    let connection = rusqlite::Connection::open(root.database()).expect("open acked database");
    assert_eq!(
        connection
            .query_row(
                "SELECT remote_pairing_count FROM runtime_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("read pairing safety count after open ACK"),
        1,
        "Open ACK must retain the pairing terminal safety obligation"
    );
}

#[tokio::test]
async fn idempotency_key_is_scoped_by_canonical_owner() {
    let root = TestRoot::new("owner-scoped-idempotency");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock)),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    for (owner, seed, private_seed, route_seed) in [
        (owner(), 0x77, 0xe7, 0x78),
        (other_owner(), 0x79, 0xe8, 0x7a),
    ] {
        let outcome = store
            .prepare_pairing_invite(PreparePairingInvite::new(
                owner,
                "shared-key".to_owned(),
                SecretBytes::new(canonical_invite(
                    seed,
                    private_seed,
                    PairRouteId::from_bytes([route_seed; 16]),
                    &binding,
                    &data_cert,
                )),
                private_key(private_seed),
            ))
            .await
            .expect("different owner may reuse idempotency key");
        assert!(matches!(
            outcome,
            PreparePairingInviteOutcome::Prepared { .. }
        ));
    }
    assert_eq!(
        store
            .list_pairing_recovery()
            .await
            .expect("load owner-scoped invites")
            .len(),
        2
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn safety_only_rejects_fresh_invites_but_exact_replay_remains_zero_write() {
    let root = TestRoot::new("safety-only-replay");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let setup = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open setup store");
    let (binding, data_cert) = make_active(&setup).await;
    let original_route = PairRouteId::from_bytes([0x7b; 16]);
    let original = canonical_invite(0x7c, 0xe9, original_route, &binding, &data_cert);
    setup
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            "durable-before-full".to_owned(),
            SecretBytes::new(original.clone()),
            private_key(0xe9),
        ))
        .await
        .expect("prepare durable invite");
    setup.shutdown().await.expect("shutdown setup store");

    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(FullCapacity)
            .with_clock(TestClock(clock)),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen full store");
    let fresh = |key: &str, seed: u8, private_seed: u8, route: u8| {
        PreparePairingInvite::new(
            owner(),
            key.to_owned(),
            SecretBytes::new(canonical_invite(
                seed,
                private_seed,
                PairRouteId::from_bytes([route; 16]),
                &binding,
                &data_cert,
            )),
            private_key(private_seed),
        )
    };
    assert!(matches!(
        store
            .prepare_pairing_invite(fresh("must-latch", 0x7d, 0xea, 0x7e))
            .await,
        Err(RuntimeStoreError::StoreFull { .. })
    ));
    let before_replay = artifact_bytes(&root.database());
    let replayed = store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            "durable-before-full".to_owned(),
            SecretBytes::new(original.clone()),
            private_key(0xe9),
        ))
        .await
        .expect("exact replay bypasses ordinary admission");
    assert!(matches!(
        replayed,
        PreparePairingInviteOutcome::Replayed { .. }
    ));
    assert_eq!(artifact_bytes(&root.database()), before_replay);
    assert!(matches!(
        store
            .prepare_pairing_invite(fresh("safety-only", 0x7f, 0xeb, 0x80))
            .await,
        Err(RuntimeStoreError::SafetyOnly)
    ));
    assert_eq!(
        store
            .list_pairing_recovery()
            .await
            .expect("load unchanged pairing directory")
            .len(),
        1
    );
    store.shutdown().await.expect("shutdown full store");
}

#[tokio::test]
async fn pairing_directory_caps_eight_active_invites_and_reopens_with_exact_recovery_rows() {
    let root = TestRoot::new("capacity-recovery");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    for offset in 0_u8..8 {
        let route = PairRouteId::from_bytes([0x80 + offset; 16]);
        let outcome = store
            .prepare_pairing_invite(PreparePairingInvite::new(
                owner(),
                format!("invite-{offset}"),
                SecretBytes::new(canonical_invite(
                    0x90 + offset,
                    0xb0 + offset,
                    route,
                    &binding,
                    &data_cert,
                )),
                private_key(0xb0 + offset),
            ))
            .await
            .expect("prepare within limit");
        assert!(matches!(
            outcome,
            PreparePairingInviteOutcome::Prepared { .. }
        ));
    }
    assert!(matches!(
        store
            .prepare_pairing_invite(PreparePairingInvite::new(
                owner(),
                "invite-over-limit".to_owned(),
                SecretBytes::new(canonical_invite(
                    0xa1,
                    0xb9,
                    PairRouteId::from_bytes([0xa2; 16]),
                    &binding,
                    &data_cert,
                )),
                private_key(0xb9),
            ))
            .await,
        Err(RuntimeStoreError::PairingLimit)
    ));
    store.shutdown().await.expect("shutdown full store");

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen full store");
    let recovery = reopened
        .list_pairing_recovery()
        .await
        .expect("load recovery directory");
    assert_eq!(recovery.len(), 8);
    assert!(
        recovery
            .iter()
            .all(|invite| invite.lifecycle() == PairingInviteLifecycle::RouteOpening)
    );
    for invite in recovery {
        assert!(matches!(
            invite.into_invite_hpke_private_key(),
            Err(RuntimeStoreError::PairingConflict)
        ));
    }
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn prepare_pairing_before_commit_rolls_back_and_after_commit_unknown_replays_exact_row() {
    for (label, operation, committed) in [
        (
            "prepare-before-commit",
            RuntimeStoreOperation::PreparePairingInviteBeforeCommit,
            false,
        ),
        (
            "prepare-after-commit",
            RuntimeStoreOperation::PreparePairingInviteAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let base_config = || {
            RuntimeStoreConfig::new(root.database())
                .with_capacity_probe(GenerousCapacity)
                .with_clock(TestClock(clock.clone()))
        };
        let setup = RuntimeStoreHandle::open(
            base_config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open setup store");
        let (binding, data_cert) = make_active(&setup).await;
        setup.shutdown().await.expect("shutdown setup store");

        let store = RuntimeStoreHandle::open(
            base_config().with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted store");
        let pair_route = PairRouteId::from_bytes([0xb1; 16]);
        let invite = canonical_invite(0xb2, 0xe3, pair_route, &binding, &data_cert);
        let first = store
            .prepare_pairing_invite(PreparePairingInvite::new(
                owner(),
                "faulted-invite".to_owned(),
                SecretBytes::new(invite.clone()),
                private_key(0xe3),
            ))
            .await
            .expect_err("fault must surface");
        assert_eq!(
            matches!(first, RuntimeStoreError::CommitOutcomeUnknown { .. }),
            committed
        );
        assert_eq!(
            store
                .list_pairing_recovery()
                .await
                .expect("read after fault")
                .len(),
            usize::from(committed)
        );
        let retry = store
            .prepare_pairing_invite(PreparePairingInvite::new(
                owner(),
                "faulted-invite".to_owned(),
                SecretBytes::new(invite.clone()),
                private_key(0xe3),
            ))
            .await
            .expect("retry identical invite");
        match (committed, retry) {
            (true, PreparePairingInviteOutcome::Replayed { invite: record })
            | (false, PreparePairingInviteOutcome::Prepared { invite: record }) => {
                assert_eq!(record.canonical_invite(), invite);
                assert_eq!(record.pair_route().as_bytes(), pair_route.as_bytes());
            }
            (_, PreparePairingInviteOutcome::Terminal { .. }) => {
                panic!("pre-terminal retry cannot be terminal")
            }
            _ => panic!("retry outcome must converge with commit boundary"),
        }
        store.shutdown().await.expect("shutdown faulted store");
    }
}

#[tokio::test]
async fn open_ack_before_commit_rolls_back_and_after_commit_unknown_replays_exact_terminal() {
    for (label, operation, committed) in [
        (
            "ack-before-commit",
            RuntimeStoreOperation::AcknowledgePairRouteOpenBeforeCommit,
            false,
        ),
        (
            "ack-after-commit",
            RuntimeStoreOperation::AcknowledgePairRouteOpenAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let base_config = || {
            RuntimeStoreConfig::new(root.database())
                .with_capacity_probe(GenerousCapacity)
                .with_clock(TestClock(clock.clone()))
        };
        let setup = RuntimeStoreHandle::open(
            base_config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open setup store");
        let (binding, data_cert) = make_active(&setup).await;
        let pair_route = PairRouteId::from_bytes([0xd1; 16]);
        let canonical_invite = canonical_invite(0xd2, 0xe4, pair_route, &binding, &data_cert);
        let prepared = setup
            .prepare_pairing_invite(PreparePairingInvite::new(
                owner(),
                "ack-fault".to_owned(),
                SecretBytes::new(canonical_invite.clone()),
                private_key(0xe4),
            ))
            .await
            .expect("prepare invite before ack fault");
        let pairing_id = match prepared {
            PreparePairingInviteOutcome::Prepared { invite } => invite.pairing_id(),
            PreparePairingInviteOutcome::Replayed { .. } => panic!("first prepare must write"),
            PreparePairingInviteOutcome::Terminal { .. } => {
                panic!("first prepare cannot be terminal")
            }
        };
        setup.shutdown().await.expect("shutdown setup store");

        let store = RuntimeStoreHandle::open(
            base_config().with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted store");
        let terminal = open_terminal(pair_route, NOW_MS + 300_000);
        let first = store
            .acknowledge_pair_route_open(pairing_id, terminal.clone())
            .await
            .expect_err("ack fault must surface");
        assert_eq!(
            matches!(first, RuntimeStoreError::CommitOutcomeUnknown { .. }),
            committed
        );
        let observed = store
            .load_pairing_invite(pairing_id)
            .await
            .expect("load after ack fault")
            .expect("invite survives");
        assert_eq!(
            observed.lifecycle(),
            if committed {
                PairingInviteLifecycle::Unused
            } else {
                PairingInviteLifecycle::RouteOpening
            }
        );
        assert_eq!(observed.canonical_invite(), canonical_invite);
        let retried = store
            .acknowledge_pair_route_open(pairing_id, terminal)
            .await
            .expect("retry exact ack");
        assert_eq!(retried.replayed(), committed);
        assert_eq!(retried.invite().lifecycle(), PairingInviteLifecycle::Unused);
        store.shutdown().await.expect("shutdown faulted store");
    }
}

#[tokio::test]
async fn offline_pairing_ciphertext_tamper_fails_open_without_rewriting_store_artifacts() {
    let root = TestRoot::new("offline-tamper");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            "tamper-invite".to_owned(),
            SecretBytes::new(canonical_invite(
                0xc1,
                0xe5,
                PairRouteId::from_bytes([0xc2; 16]),
                &binding,
                &data_cert,
            )),
            private_key(0xe5),
        ))
        .await
        .expect("prepare invite");
    store.shutdown().await.expect("shutdown before tamper");

    let connection = rusqlite::Connection::open(root.database()).expect("open offline database");
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_pairings SET sealed_state = zeroblob(length(sealed_state))",
                [],
            )
            .expect("tamper sealed pairing state"),
        1
    );
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint offline tamper");
    drop(connection);
    let before = artifact_bytes(&root.database());

    let error = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect_err("offline pairing tamper must fail close");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), before);
}

#[tokio::test]
async fn offline_sealed_hpke_keypair_mismatch_fails_open_without_rewriting_store_artifacts() {
    let root = TestRoot::new("offline-hpke-mismatch");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            "hpke-mismatch".to_owned(),
            SecretBytes::new(canonical_invite(
                0xc3,
                0xe5,
                PairRouteId::from_bytes([0xc4; 16]),
                &binding,
                &data_cert,
            )),
            private_key(0xe5),
        ))
        .await
        .expect("prepare invite");
    store.shutdown().await.expect("shutdown before mismatch");

    let storage_kek =
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK");
    rewrite_sealed_pairing_private_key(&root.database(), &storage_kek, [0xe6; 32]);
    drop(storage_kek);
    let before = artifact_bytes(&root.database());

    let error = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect_err("sealed HPKE keypair mismatch must fail close");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), before);
}

#[tokio::test]
async fn verified_request_and_pending_frame_are_exact_durable_and_never_regress_to_unused() {
    let root = TestRoot::new("request-pending-recovery");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    let pair_route = PairRouteId::from_bytes([0xd5; 16]);
    let (pairing_id, canonical_invite) = prepare_unused_pairing(
        &store,
        &binding,
        &data_cert,
        pair_route,
        0xd6,
        0xe7,
        "request-pending",
    )
    .await;
    let verified = verified_request(&canonical_invite, 0xe7, 0xa1, 0xa2, 0xa3);
    let request_hash = verified.request_hash();
    let frozen_request = verified.canonical_request().to_vec();
    let fingerprint = sha256(
        &SigningKey::from_seed(&[0xa1; 32])
            .verifying_key()
            .to_bytes(),
    );
    let accepted = store
        .accept_pair_request(AcceptPairRequest::new(pairing_id, verified))
        .await
        .expect("accept verified request");
    let preparing = match accepted {
        AcceptPairRequestOutcome::Accepted { pairing } => pairing,
        AcceptPairRequestOutcome::Replayed { .. } => panic!("first request must commit"),
    };
    assert_eq!(preparing.lifecycle(), PairingInviteLifecycle::Preparing);
    assert_eq!(preparing.request_hash(), Some(request_hash));
    assert_eq!(preparing.device_sign_fingerprint(), Some(fingerprint));
    assert_eq!(preparing.request_received_at_ms(), Some(NOW_MS));
    let preparation = preparing
        .pair_pending_preparation()
        .expect("authenticated preparation")
        .expect("preparing projection");
    let parsed_invite =
        PairInviteV1::from_canonical_bytes(&canonical_invite).expect("parse invite");
    assert_eq!(preparation.request_hash(), request_hash);
    assert_eq!(preparation.info(), &request_info(&parsed_invite));
    assert_eq!(
        preparation.context(),
        &pairing_context(&parsed_invite, OuterFrameKind::PairPending)
    );
    let (_, expected_recipient) = HpkePrivateKey::derive_keypair(&[0xa2; 32]);
    assert_eq!(
        preparation.recipient().to_bytes(),
        expected_recipient.to_bytes()
    );
    assert!(
        store
            .list_pending_pairings()
            .await
            .expect("list before pending")
            .is_empty()
    );
    store.shutdown().await.expect("shutdown preparing store");

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen preparing store");
    let recovered = reopened
        .load_pairing_invite(pairing_id)
        .await
        .expect("load preparing")
        .expect("pairing survives");
    assert_eq!(recovered.lifecycle(), PairingInviteLifecycle::Preparing);
    assert!(
        recovered
            .pair_pending_preparation()
            .expect("recovered preparation")
            .is_some()
    );
    let before_preparing_ack = artifact_bytes(&root.database());
    let preparing_ack = reopened
        .acknowledge_pair_route_open(pairing_id, open_terminal(pair_route, NOW_MS + 300_000))
        .await
        .expect("preparing Open ACK replay");
    assert!(preparing_ack.replayed());
    assert_eq!(
        preparing_ack.invite().lifecycle(),
        PairingInviteLifecycle::Preparing
    );
    assert_eq!(artifact_bytes(&root.database()), before_preparing_ack);
    let before_read_replays = artifact_bytes(&root.database());
    assert_eq!(
        reopened
            .replay_pair_request(pairing_id, SecretBytes::new(frozen_request.clone()))
            .await
            .expect("exact read-lane replay")
            .lifecycle(),
        PairingInviteLifecycle::Preparing
    );
    let mut different_request = frozen_request.clone();
    different_request[0] ^= 1;
    assert!(matches!(
        reopened
            .replay_pair_request(pairing_id, SecretBytes::new(different_request))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_read_replays);
    let replayed = reopened
        .accept_pair_request(AcceptPairRequest::new(
            pairing_id,
            verified_request(&canonical_invite, 0xe7, 0xa1, 0xa2, 0xa3),
        ))
        .await
        .expect("replay exact request");
    assert!(matches!(
        replayed,
        AcceptPairRequestOutcome::Replayed { .. }
    ));
    assert!(matches!(
        reopened
            .accept_pair_request(AcceptPairRequest::new(
                pairing_id,
                verified_request(&canonical_invite, 0xe7, 0xa4, 0xa5, 0xa6),
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));

    clock.store(NOW_MS + 1, Ordering::SeqCst);
    let envelope = pending_envelope(0xb1);
    let canonical_envelope = envelope
        .canonical_bytes()
        .expect("canonical pending envelope");
    let committed = reopened
        .commit_pair_pending(CommitPairPending::new(
            pairing_id,
            request_hash,
            envelope.clone(),
        ))
        .await
        .expect("commit PairPending");
    let awaiting = match committed {
        CommitPairPendingOutcome::Committed { pairing } => pairing,
        CommitPairPendingOutcome::Replayed { .. } => panic!("first pending must commit"),
    };
    assert_eq!(
        awaiting.lifecycle(),
        PairingInviteLifecycle::AwaitingLocalConfirmation
    );
    assert!(
        awaiting
            .pair_pending_preparation()
            .expect("awaiting projection query")
            .is_none()
    );
    let pending_frame = awaiting
        .canonical_pending_frame()
        .expect("frozen pending frame");
    let decoded: OpaqueRouteFrame = decode(pending_frame).expect("decode pending frame");
    assert!(matches!(
        decoded.body,
        RelayFrameBody::PairData(PairData { pair_route: actual_route, sealed_blob })
            if actual_route == pair_route && sealed_blob.0 == canonical_envelope
    ));
    let pending = reopened
        .list_pending_pairings()
        .await
        .expect("list pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].pairing_id.as_str(),
        pairing_id.to_canonical_string()
    );
    assert_eq!(pending[0].request_hash, request_hash);
    assert_eq!(pending[0].device_sign_fingerprint, fingerprint);
    assert_eq!(pending[0].requested_at_ms, NOW_MS);
    assert_eq!(pending[0].expires_at_ms, NOW_MS + 300_000);

    let before_awaiting_ack = artifact_bytes(&root.database());
    let reopened_ack = reopened
        .acknowledge_pair_route_open(pairing_id, open_terminal(pair_route, NOW_MS + 300_000))
        .await
        .expect("replayed Open ACK");
    assert!(reopened_ack.replayed());
    assert_eq!(
        reopened_ack.invite().lifecycle(),
        PairingInviteLifecycle::AwaitingLocalConfirmation
    );
    assert_eq!(artifact_bytes(&root.database()), before_awaiting_ack);
    assert!(matches!(
        reopened
            .commit_pair_pending(CommitPairPending::new(
                pairing_id,
                request_hash,
                pending_envelope(0xb2),
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    clock.store(NOW_MS + 400_000, Ordering::SeqCst);
    let before_expired_replays = artifact_bytes(&root.database());
    assert!(matches!(
        reopened
            .acknowledge_pair_route_open(pairing_id, open_terminal(pair_route, NOW_MS + 300_000),)
            .await,
        Err(RuntimeStoreError::PairingExpired)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_expired_replays);
    let expired = reopened
        .replay_pair_request(pairing_id, SecretBytes::new(frozen_request))
        .await
        .expect_err("expired replay must fail");
    assert!(matches!(&expired, RuntimeStoreError::PairingExpired));
    assert_eq!(expired.code(), "daemon.pairing.expired");
    assert_eq!(artifact_bytes(&root.database()), before_expired_replays);
    assert!(matches!(
        reopened
            .accept_pair_request(AcceptPairRequest::new(
                pairing_id,
                verified_request(&canonical_invite, 0xe7, 0xa1, 0xa2, 0xa3),
            ))
            .await,
        Err(RuntimeStoreError::PairingExpired)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_expired_replays);
    assert!(matches!(
        reopened
            .commit_pair_pending(CommitPairPending::new(pairing_id, request_hash, envelope,))
            .await,
        Err(RuntimeStoreError::PairingExpired)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_expired_replays);
    reopened.shutdown().await.expect("shutdown awaiting store");

    let recovered = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen awaiting store");
    assert_eq!(
        recovered
            .list_pending_pairings()
            .await
            .expect("list recovered pending"),
        pending
    );
    recovered
        .shutdown()
        .await
        .expect("shutdown recovered store");
}

#[tokio::test]
async fn request_and_pending_commit_fault_boundaries_converge_by_exact_retry() {
    for (label, operation, committed) in [
        (
            "accept-before-commit",
            RuntimeStoreOperation::AcceptPairRequestBeforeCommit,
            false,
        ),
        (
            "accept-after-commit",
            RuntimeStoreOperation::AcceptPairRequestAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let base_config = || {
            RuntimeStoreConfig::new(root.database())
                .with_capacity_probe(GenerousCapacity)
                .with_clock(TestClock(clock.clone()))
        };
        let setup = RuntimeStoreHandle::open(
            base_config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open accept setup");
        let (binding, data_cert) = make_active(&setup).await;
        let pair_route = PairRouteId::from_bytes([0xc5; 16]);
        let (pairing_id, invite) = prepare_unused_pairing(
            &setup,
            &binding,
            &data_cert,
            pair_route,
            0xc6,
            0xe8,
            "accept-fault",
        )
        .await;
        setup.shutdown().await.expect("shutdown accept setup");

        let store = RuntimeStoreHandle::open(
            base_config().with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted accept store");
        let error = store
            .accept_pair_request(AcceptPairRequest::new(
                pairing_id,
                verified_request(&invite, 0xe8, 0xb3, 0xb4, 0xb5),
            ))
            .await
            .expect_err("accept fault must surface");
        assert_eq!(
            matches!(error, RuntimeStoreError::CommitOutcomeUnknown { .. }),
            committed
        );
        assert_eq!(
            store
                .load_pairing_invite(pairing_id)
                .await
                .expect("load after accept fault")
                .expect("pairing survives")
                .lifecycle(),
            if committed {
                PairingInviteLifecycle::Preparing
            } else {
                PairingInviteLifecycle::Unused
            }
        );
        let retry = store
            .accept_pair_request(AcceptPairRequest::new(
                pairing_id,
                verified_request(&invite, 0xe8, 0xb3, 0xb4, 0xb5),
            ))
            .await
            .expect("retry exact request");
        assert!(matches!(
            (committed, retry),
            (true, AcceptPairRequestOutcome::Replayed { .. })
                | (false, AcceptPairRequestOutcome::Accepted { .. })
        ));
        store.shutdown().await.expect("shutdown accept fault store");
    }

    for (label, operation, committed) in [
        (
            "pending-before-commit",
            RuntimeStoreOperation::CommitPairPendingBeforeCommit,
            false,
        ),
        (
            "pending-after-commit",
            RuntimeStoreOperation::CommitPairPendingAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let base_config = || {
            RuntimeStoreConfig::new(root.database())
                .with_capacity_probe(GenerousCapacity)
                .with_clock(TestClock(clock.clone()))
        };
        let setup = RuntimeStoreHandle::open(
            base_config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open pending setup");
        let (binding, data_cert) = make_active(&setup).await;
        let pair_route = PairRouteId::from_bytes([0xc7; 16]);
        let (pairing_id, invite) = prepare_unused_pairing(
            &setup,
            &binding,
            &data_cert,
            pair_route,
            0xc8,
            0xe9,
            "pending-fault",
        )
        .await;
        let verified = verified_request(&invite, 0xe9, 0xb6, 0xb7, 0xb8);
        let request_hash = verified.request_hash();
        setup
            .accept_pair_request(AcceptPairRequest::new(pairing_id, verified))
            .await
            .expect("prepare request before pending fault");
        setup.shutdown().await.expect("shutdown pending setup");

        let store = RuntimeStoreHandle::open(
            base_config().with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted pending store");
        let envelope = pending_envelope(0xb9);
        let error = store
            .commit_pair_pending(CommitPairPending::new(
                pairing_id,
                request_hash,
                envelope.clone(),
            ))
            .await
            .expect_err("pending fault must surface");
        assert_eq!(
            matches!(error, RuntimeStoreError::CommitOutcomeUnknown { .. }),
            committed
        );
        assert_eq!(
            store
                .load_pairing_invite(pairing_id)
                .await
                .expect("load after pending fault")
                .expect("pairing survives")
                .lifecycle(),
            if committed {
                PairingInviteLifecycle::AwaitingLocalConfirmation
            } else {
                PairingInviteLifecycle::Preparing
            }
        );
        let retry = store
            .commit_pair_pending(CommitPairPending::new(pairing_id, request_hash, envelope))
            .await
            .expect("retry exact pending");
        assert!(matches!(
            (committed, retry),
            (true, CommitPairPendingOutcome::Replayed { .. })
                | (false, CommitPairPendingOutcome::Committed { .. })
        ));
        store
            .shutdown()
            .await
            .expect("shutdown pending fault store");
    }
}

#[tokio::test]
async fn open_ack_at_or_after_absolute_expiry_is_typed_and_zero_write() {
    let root = TestRoot::new("open-ack-expiry");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    let pair_route = PairRouteId::from_bytes([0xcd; 16]);
    let invite = canonical_invite(0xce, 0xeb, pair_route, &binding, &data_cert);
    let pairing_id = match store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            "open-expiry".to_owned(),
            SecretBytes::new(invite),
            private_key(0xeb),
        ))
        .await
        .expect("prepare invite")
    {
        PreparePairingInviteOutcome::Prepared { invite } => invite.pairing_id(),
        PreparePairingInviteOutcome::Replayed { .. } => panic!("fresh invite must prepare"),
        PreparePairingInviteOutcome::Terminal { .. } => panic!("fresh invite cannot be terminal"),
    };
    let terminal = open_terminal(pair_route, NOW_MS + 300_000);
    clock.store(NOW_MS + 300_000, Ordering::SeqCst);
    let before = artifact_bytes(&root.database());
    for observed in [NOW_MS + 300_000, NOW_MS + 300_001] {
        clock.store(observed, Ordering::SeqCst);
        let error = store
            .acknowledge_pair_route_open(pairing_id, terminal.clone())
            .await
            .expect_err("expired Open ACK must fail");
        assert!(matches!(&error, RuntimeStoreError::PairingExpired));
        assert_eq!(error.code(), "daemon.pairing.expired");
        assert_eq!(artifact_bytes(&root.database()), before);
        assert_eq!(
            store
                .load_pairing_invite(pairing_id)
                .await
                .expect("load expired route")
                .expect("pairing survives")
                .lifecycle(),
            PairingInviteLifecycle::RouteOpening
        );
    }
    clock.store(NOW_MS + 299_999, Ordering::SeqCst);
    assert_eq!(
        store
            .acknowledge_pair_route_open(pairing_id, terminal)
            .await
            .expect("ACK before expiry")
            .invite()
            .lifecycle(),
        PairingInviteLifecycle::Unused
    );
    clock.store(NOW_MS + 300_000, Ordering::SeqCst);
    let before_expired_unused_ack = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_route_open(pairing_id, open_terminal(pair_route, NOW_MS + 300_000),)
            .await,
        Err(RuntimeStoreError::PairingExpired)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_expired_unused_ack);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn offline_pending_request_binding_tamper_fails_full_open_without_rewrite() {
    let root = TestRoot::new("pending-binding-tamper");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open store");
    let (binding, data_cert) = make_active(&store).await;
    let pair_route = PairRouteId::from_bytes([0xca; 16]);
    let (pairing_id, invite) = prepare_unused_pairing(
        &store,
        &binding,
        &data_cert,
        pair_route,
        0xcb,
        0xea,
        "pending-tamper",
    )
    .await;
    let verified = verified_request(&invite, 0xea, 0xbc, 0xbd, 0xbe);
    let request_hash = verified.request_hash();
    store
        .accept_pair_request(AcceptPairRequest::new(pairing_id, verified))
        .await
        .expect("accept request");
    store
        .commit_pair_pending(CommitPairPending::new(
            pairing_id,
            request_hash,
            pending_envelope(0xbf),
        ))
        .await
        .expect("commit pending");
    store.shutdown().await.expect("shutdown before tamper");

    let connection = rusqlite::Connection::open(root.database()).expect("open offline database");
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_pairings SET request_hash = ?1 WHERE pairing_id = ?2",
                rusqlite::params![&[0xcc_u8; 32][..], &pairing_id.as_bytes()[..]],
            )
            .expect("tamper request hash"),
        1
    );
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint request binding tamper");
    drop(connection);
    let before = artifact_bytes(&root.database());
    let error = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect_err("tampered request binding must fail full open");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), before);
}
