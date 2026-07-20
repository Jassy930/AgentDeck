use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_crypto::{
    SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256, sign_relay_admin_purge_receipt,
    sign_tbs,
};
use agentdeck_protocol::relay_v2::frame::{OpaqueRouteFrame, RetireMachine, RetirementCommitted};
use agentdeck_protocol::relay_v2::{
    CertRole, Digest32, ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, EnrollmentCode,
    LinkGeneration, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, MachineRouteId,
    PublicKeyBytes, RELAY_PROTOCOL_VERSION, RELAY_RECEIPT_FORMAT_VERSION,
    RELAY_RECEIPT_KEY_GENERATION_MVP, RelayAdminPurgeReadbackV1, RelayAdminPurgeReceiptTbsV1,
    RelayAdminPurgeReceiptV1, RelayAdminPurgeTombstoneV1, RelayFrameBody,
    RelayMachineTombstoneKindV1, RelayServerId, RootKeyId, SignedCertificate, TrustEpoch,
    admin_purge_tombstone_hash, encode, enrollment_receipt_hash, purge_request_hash,
};
use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    ConfirmMachinePurgeReadbackAbsentOutcome, MachineEnrollmentState, MachineIdentityBinding,
    MachinePurgeReadbackProof, MachineRemoteLifecycle, MachineTrustResetKind,
    PrepareMachineRetirementOutcome, RecordMachineRetirementTerminalOutcome,
    RecordRootLostMachinePurgeOutcome, RuntimeCommitOperation, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use rusqlite::{Connection, params};

const RELAY: RelayServerId = RelayServerId::from_bytes([0x31; 16]);
const ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const ROOT_SEED: [u8; 32] = [0x41; 32];
const LINK_SEED: [u8; 32] = [0x42; 32];
const DATA_SEED: [u8; 32] = [0x43; 32];
const RECEIPT_SEED: [u8; 32] = [0x51; 32];

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-machine-reset-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create machine reset test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure machine reset test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct GenerousCapacity;

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

struct OneShotFault {
    operation: RuntimeStoreOperation,
    fired: AtomicBool,
}

impl RuntimeStoreFaultInjector for OneShotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

fn binding() -> MachineIdentityBinding {
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

fn certificate(binding: &MachineIdentityBinding, role: CertRole) -> SignedCertificate {
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
        &certificate.to_be_signed_v1(RELAY, ROUTE, binding.root_fingerprint),
    )
    .into();
    certificate
}

fn bundle() -> EnrollmentBundleV2 {
    let signer = SigningKey::from_seed(&RECEIPT_SEED);
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
        spki_pins: vec![Digest32([0x52; 32])],
        expires_at_ms: 1_800_000_000_000,
    }
}

fn request(
    bundle: &EnrollmentBundleV2,
    binding: &MachineIdentityBinding,
    link: &SignedCertificate,
    data: &SignedCertificate,
) -> MachineEnrollmentRequestV1 {
    MachineEnrollmentRequestV1 {
        code: bundle.code.clone(),
        machine_route: ROUTE,
        root_pubkey: PublicKeyBytes(binding.root_public_key),
        link_cert: link.clone(),
        data_cert: data.clone(),
    }
}

async fn open_store(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    fault: Option<Arc<dyn RuntimeStoreFaultInjector>>,
) -> RuntimeStoreHandle {
    let mut config = RuntimeStoreConfig::new(root.database()).with_capacity_probe(GenerousCapacity);
    if let Some(fault) = fault {
        config = config.with_fault_injector(fault);
    }
    RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(keys, &root.database()).expect("load test StorageKEK"),
    )
    .await
    .expect("open machine reset store")
}

async fn make_active(store: &RuntimeStoreHandle, binding: &MachineIdentityBinding) -> [u8; 32] {
    store
        .prepare_machine_identity(binding.clone())
        .await
        .expect("prepare machine identity");
    store
        .activate_machine_identity(binding.clone())
        .await
        .expect("activate machine identity");
    let bundle = bundle();
    let link = certificate(binding, CertRole::Link);
    let data = certificate(binding, CertRole::Data);
    let request_hash = request(&bundle, binding, &link, &data).canonical_sha256();
    store
        .prepare_machine_enrollment(bundle, ROUTE, binding.clone(), link, data)
        .await
        .expect("prepare enrollment");
    let response = MachineEnrollmentResponseV1::new(
        RELAY,
        ROUTE,
        binding.trust_epoch,
        enrollment_receipt_hash(RELAY, ROUTE, binding.trust_epoch, request_hash),
    )
    .expect("valid response");
    let response_hash = response.canonical_sha256().expect("response hash");
    store
        .record_validated_enrollment_response(request_hash, response)
        .await
        .expect("record response");
    store
        .activate_machine_enrollment(request_hash, response_hash)
        .await
        .expect("activate enrollment");
    request_hash
}

fn retirement_with(
    binding: &MachineIdentityBinding,
    relay: RelayServerId,
    route: MachineRouteId,
    root_key_id: RootKeyId,
    epoch: TrustEpoch,
) -> RetireMachine {
    let mut retirement = RetireMachine {
        machine_route: route,
        root_key_id,
        trust_epoch: epoch,
        signature: agentdeck_protocol::relay_v2::Ed25519Signature([0; 64]),
    };
    retirement.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SEED),
        &retirement.to_be_signed_v1(relay, binding.root_fingerprint),
    )
    .into();
    retirement
}

fn retirement(binding: &MachineIdentityBinding) -> RetireMachine {
    retirement_with(
        binding,
        RELAY,
        ROUTE,
        RootKeyId::from_bytes(binding.root_key_id),
        TrustEpoch::new(binding.trust_epoch),
    )
}

fn terminal(retirement: &RetireMachine) -> (Vec<u8>, [u8; 32]) {
    let bytes = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RetirementCommitted(RetirementCommitted {
            machine_route: retirement.machine_route,
            trust_epoch: retirement.trust_epoch,
            retire_hash: retirement.canonical_sha256(),
        }),
    });
    let hash = sha256(&bytes);
    (bytes, hash)
}

fn root_lost_receipt(
    binding: &MachineIdentityBinding,
    enrollment_receipt_hash: [u8; 32],
    route: MachineRouteId,
) -> RelayAdminPurgeReceiptV1 {
    root_lost_receipt_with(
        RELAY,
        route,
        RootKeyId::from_bytes(binding.root_key_id),
        binding.root_fingerprint,
        TrustEpoch::new(binding.trust_epoch),
        enrollment_receipt_hash,
        RECEIPT_SEED,
    )
}

#[allow(clippy::too_many_arguments)]
fn root_lost_receipt_with(
    relay: RelayServerId,
    route: MachineRouteId,
    root_key_id: RootKeyId,
    root_fingerprint: [u8; 32],
    trust_epoch: TrustEpoch,
    enrollment_receipt_hash: [u8; 32],
    signer_seed: [u8; 32],
) -> RelayAdminPurgeReceiptV1 {
    let signer = SigningKey::from_seed(&signer_seed);
    let verify_key = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signer)
        .expect("valid receipt signer")
        .bind_to_relay(relay)
        .expect("bind receipt signer");
    let readback = RelayAdminPurgeReadbackV1 {
        active_machine_routes: 0,
        retired_tombstones: 1,
        consumed_enrollment_records: 0,
        device_grants: 0,
        revocations: 0,
        streams: 0,
        frames: 0,
        subscriptions: 0,
        retirement_hash: None,
        retirement_terminal_present: false,
    };
    let request_hash = purge_request_hash(route, root_fingerprint).expect("purge hash");
    let tombstone = RelayAdminPurgeTombstoneV1 {
        relay_server_id: relay,
        machine_route: route,
        root_key_id,
        root_fingerprint,
        trust_epoch,
        enrollment_receipt_hash,
        purge_request_hash: request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback: readback.clone(),
    };
    let anchor = verify_key.wire_anchor();
    let tbs = RelayAdminPurgeReceiptTbsV1 {
        receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        relay_server_id: relay,
        receipt_key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
        receipt_key_id: anchor.key_id,
        machine_route: route,
        root_key_id,
        root_fingerprint,
        trust_epoch,
        enrollment_receipt_hash,
        purge_request_hash: request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback,
        tombstone_hash: admin_purge_tombstone_hash(&tombstone).expect("tombstone hash"),
    };
    sign_relay_admin_purge_receipt(&signer, &verify_key, tbs).expect("sign root-lost proof")
}

fn state_record(
    state: &MachineEnrollmentState,
) -> &agentdeckd::runtime::store::MachineRemoteStateRecord {
    match state {
        MachineEnrollmentState::EnrollmentPrepared(state) => &state.record,
        MachineEnrollmentState::EnrollmentResponseValidated(state) => &state.record,
        MachineEnrollmentState::Active(state) => &state.record,
        MachineEnrollmentState::RetirePending(state) => &state.record,
        MachineEnrollmentState::RelayCommitted(state) => &state.record,
        MachineEnrollmentState::PurgeReadbackAbsent(state) => &state.record,
        MachineEnrollmentState::LocalDeleted(state) => &state.record,
    }
}

fn artifact_bytes(database: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
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

#[tokio::test]
async fn root_present_retirement_is_restart_safe_and_exact_through_purge_readback_absent() {
    let root = TestRoot::new("root-present");
    let keys = MemoryKeyStore::new();
    let binding = binding();
    let store = open_store(&root, &keys, None).await;
    make_active(&store, &binding).await;
    let retirement = retirement(&binding);
    let retirement_bytes = retirement.canonical_bytes();
    let retirement_hash = retirement.canonical_sha256();

    assert!(matches!(
        store
            .prepare_machine_retirement(retirement.clone())
            .await
            .expect("prepare retirement"),
        PrepareMachineRetirementOutcome::Prepared { .. }
    ));
    let replay = store
        .prepare_machine_retirement(retirement.clone())
        .await
        .expect("replay retirement");
    let PrepareMachineRetirementOutcome::Replayed { state } = replay else {
        panic!("expected retirement replay");
    };
    let MachineEnrollmentState::RetirePending(state) = state else {
        panic!("expected retire pending");
    };
    assert_eq!(state.retirement.canonical_bytes, retirement_bytes);
    assert_eq!(state.retirement.canonical_hash, retirement_hash);
    store.shutdown().await.expect("shutdown retire pending");

    let store = open_store(&root, &keys, None).await;
    assert!(matches!(
        store
            .load_machine_enrollment_state()
            .await
            .expect("load retire pending"),
        Some(MachineEnrollmentState::RetirePending(_))
    ));
    let (terminal_bytes, terminal_hash) = terminal(&retirement);
    assert!(matches!(
        store
            .record_machine_retirement_terminal(terminal_bytes.clone(), terminal_hash)
            .await
            .expect("record terminal"),
        RecordMachineRetirementTerminalOutcome::Recorded { .. }
    ));
    assert!(matches!(
        store
            .record_machine_retirement_terminal(terminal_bytes.clone(), terminal_hash)
            .await
            .expect("replay terminal"),
        RecordMachineRetirementTerminalOutcome::Replayed { .. }
    ));
    store.shutdown().await.expect("shutdown relay committed");

    let store = open_store(&root, &keys, None).await;
    assert!(matches!(
        store
            .load_machine_enrollment_state()
            .await
            .expect("load committed"),
        Some(MachineEnrollmentState::RelayCommitted(_))
    ));
    assert!(matches!(
        store
            .confirm_machine_purge_readback_absent(terminal_bytes.clone(), terminal_hash)
            .await
            .expect("confirm purge readback"),
        ConfirmMachinePurgeReadbackAbsentOutcome::Confirmed { .. }
    ));
    let replay = store
        .confirm_machine_purge_readback_absent(terminal_bytes.clone(), terminal_hash)
        .await
        .expect("replay purge readback");
    let ConfirmMachinePurgeReadbackAbsentOutcome::Replayed { state } = replay else {
        panic!("expected purge replay");
    };
    let MachineEnrollmentState::PurgeReadbackAbsent(state) = state else {
        panic!("expected purge readback absent");
    };
    assert_eq!(state.reset_kind, MachineTrustResetKind::RootPresent);
    let MachinePurgeReadbackProof::RootPresent {
        retirement,
        terminal,
    } = state.proof
    else {
        panic!("expected root-present proof");
    };
    assert_eq!(retirement.canonical_hash, retirement_hash);
    assert_eq!(terminal.canonical_frame_bytes, terminal_bytes);
    assert_eq!(terminal.canonical_frame_hash, terminal_hash);
    assert!(matches!(
        store
            .prepare_machine_retirement(retirement.retirement.clone())
            .await
            .expect("replay original retirement after purge"),
        PrepareMachineRetirementOutcome::Replayed { .. }
    ));
    assert!(matches!(
        store
            .record_machine_retirement_terminal(
                terminal.canonical_frame_bytes.clone(),
                terminal.canonical_frame_hash,
            )
            .await
            .expect("replay original terminal after purge"),
        RecordMachineRetirementTerminalOutcome::Replayed { .. }
    ));
    store.shutdown().await.expect("shutdown purge state");

    let store = open_store(&root, &keys, None).await;
    let state = store
        .load_machine_enrollment_state()
        .await
        .expect("restart purge load")
        .expect("purge state exists");
    assert_eq!(
        state_record(&state).lifecycle,
        MachineRemoteLifecycle::PurgeReadbackAbsent
    );
    store.shutdown().await.expect("final shutdown");
}

#[tokio::test]
async fn root_present_rejects_every_signed_request_and_terminal_binding_axis() {
    let root = TestRoot::new("root-present-reject");
    let keys = MemoryKeyStore::new();
    let binding = binding();
    let store = open_store(&root, &keys, None).await;
    make_active(&store, &binding).await;

    for invalid in [
        retirement_with(
            &binding,
            RELAY,
            MachineRouteId::from_bytes([0x71; 16]),
            RootKeyId::from_bytes(binding.root_key_id),
            TrustEpoch::new(binding.trust_epoch),
        ),
        retirement_with(
            &binding,
            RELAY,
            ROUTE,
            RootKeyId::from_bytes([0x72; 16]),
            TrustEpoch::new(binding.trust_epoch),
        ),
        retirement_with(
            &binding,
            RELAY,
            ROUTE,
            RootKeyId::from_bytes(binding.root_key_id),
            TrustEpoch::new(binding.trust_epoch + 1),
        ),
        retirement_with(
            &binding,
            RelayServerId::from_bytes([0x73; 16]),
            ROUTE,
            RootKeyId::from_bytes(binding.root_key_id),
            TrustEpoch::new(binding.trust_epoch),
        ),
    ] {
        assert!(matches!(
            store.prepare_machine_retirement(invalid).await,
            Err(RuntimeStoreError::MachineRemoteConflict)
        ));
    }
    let mut bad_signature = retirement(&binding);
    bad_signature.signature.0[0] ^= 1;
    assert!(matches!(
        store.prepare_machine_retirement(bad_signature).await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));

    let retirement = retirement(&binding);
    store
        .prepare_machine_retirement(retirement.clone())
        .await
        .expect("prepare valid retirement");
    let pending = store
        .load_machine_enrollment_state()
        .await
        .expect("load pending")
        .expect("pending exists");
    let enrollment_hash = state_record(&pending).enrollment_receipt_hash.unwrap();
    assert!(matches!(
        store
            .record_root_lost_machine_purge(root_lost_receipt(&binding, enrollment_hash, ROUTE))
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    for (route, epoch, retire_hash) in [
        (
            MachineRouteId::from_bytes([0x74; 16]),
            retirement.trust_epoch,
            retirement.canonical_sha256(),
        ),
        (
            retirement.machine_route,
            TrustEpoch::new(retirement.trust_epoch.value() + 1),
            retirement.canonical_sha256(),
        ),
        (retirement.machine_route, retirement.trust_epoch, [0x75; 32]),
    ] {
        let bytes = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RetirementCommitted(RetirementCommitted {
                machine_route: route,
                trust_epoch: epoch,
                retire_hash,
            }),
        });
        assert!(matches!(
            store
                .record_machine_retirement_terminal(bytes.clone(), sha256(&bytes))
                .await,
            Err(RuntimeStoreError::MachineRemoteConflict)
        ));
    }
    let wrong_body = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Ping(agentdeck_protocol::relay_v2::frame::Ping { nonce: 1 }),
    });
    assert!(matches!(
        store
            .record_machine_retirement_terminal(wrong_body.clone(), sha256(&wrong_body))
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let wrong_version = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION - 1,
        body: RelayFrameBody::RetirementCommitted(RetirementCommitted {
            machine_route: ROUTE,
            trust_epoch: retirement.trust_epoch,
            retire_hash: retirement.canonical_sha256(),
        }),
    });
    assert!(matches!(
        store
            .record_machine_retirement_terminal(wrong_version.clone(), sha256(&wrong_version))
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let (terminal_bytes, terminal_hash) = terminal(&retirement);
    let mut trailing = terminal_bytes.clone();
    trailing.push(0);
    assert!(matches!(
        store
            .record_machine_retirement_terminal(trailing.clone(), sha256(&trailing))
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    assert!(matches!(
        store
            .record_machine_retirement_terminal(terminal_bytes.clone(), [0x76; 32])
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    store
        .record_machine_retirement_terminal(terminal_bytes.clone(), terminal_hash)
        .await
        .expect("record valid terminal");
    let mut different = terminal_bytes.clone();
    different[6] ^= 1;
    assert!(matches!(
        store
            .confirm_machine_purge_readback_absent(different.clone(), sha256(&different))
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    store.shutdown().await.expect("shutdown reject store");
}

#[tokio::test]
async fn root_lost_portable_receipt_is_verified_restart_safe_and_exact() {
    let root = TestRoot::new("root-lost");
    let keys = MemoryKeyStore::new();
    let binding = binding();
    let store = open_store(&root, &keys, None).await;
    make_active(&store, &binding).await;
    let active = store
        .load_machine_enrollment_state()
        .await
        .expect("load active")
        .expect("active exists");
    let enrollment_hash = state_record(&active)
        .enrollment_receipt_hash
        .expect("active enrollment receipt hash");
    let receipt = root_lost_receipt(&binding, enrollment_hash, ROUTE);
    let canonical = receipt.canonical_bytes().expect("receipt canonical");
    let canonical_hash = receipt.canonical_sha256().expect("receipt hash");

    let mut bad_signature = receipt.clone();
    bad_signature.signature.0[0] ^= 1;
    assert!(matches!(
        store.record_root_lost_machine_purge(bad_signature).await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    for wrong in [
        root_lost_receipt_with(
            RelayServerId::from_bytes([0x80; 16]),
            ROUTE,
            RootKeyId::from_bytes(binding.root_key_id),
            binding.root_fingerprint,
            TrustEpoch::new(binding.trust_epoch),
            enrollment_hash,
            RECEIPT_SEED,
        ),
        root_lost_receipt_with(
            RELAY,
            MachineRouteId::from_bytes([0x81; 16]),
            RootKeyId::from_bytes(binding.root_key_id),
            binding.root_fingerprint,
            TrustEpoch::new(binding.trust_epoch),
            enrollment_hash,
            RECEIPT_SEED,
        ),
        root_lost_receipt_with(
            RELAY,
            ROUTE,
            RootKeyId::from_bytes([0x82; 16]),
            binding.root_fingerprint,
            TrustEpoch::new(binding.trust_epoch),
            enrollment_hash,
            RECEIPT_SEED,
        ),
        root_lost_receipt_with(
            RELAY,
            ROUTE,
            RootKeyId::from_bytes(binding.root_key_id),
            [0x83; 32],
            TrustEpoch::new(binding.trust_epoch),
            enrollment_hash,
            RECEIPT_SEED,
        ),
        root_lost_receipt_with(
            RELAY,
            ROUTE,
            RootKeyId::from_bytes(binding.root_key_id),
            binding.root_fingerprint,
            TrustEpoch::new(binding.trust_epoch + 1),
            enrollment_hash,
            RECEIPT_SEED,
        ),
        root_lost_receipt_with(
            RELAY,
            ROUTE,
            RootKeyId::from_bytes(binding.root_key_id),
            binding.root_fingerprint,
            TrustEpoch::new(binding.trust_epoch),
            [0x84; 32],
            RECEIPT_SEED,
        ),
        root_lost_receipt_with(
            RELAY,
            ROUTE,
            RootKeyId::from_bytes(binding.root_key_id),
            binding.root_fingerprint,
            TrustEpoch::new(binding.trust_epoch),
            enrollment_hash,
            [0x85; 32],
        ),
    ] {
        assert!(matches!(
            store.record_root_lost_machine_purge(wrong).await,
            Err(RuntimeStoreError::MachineRemoteConflict)
        ));
    }

    assert!(matches!(
        store
            .record_root_lost_machine_purge(receipt.clone())
            .await
            .expect("record root-lost proof"),
        RecordRootLostMachinePurgeOutcome::Recorded { .. }
    ));
    let replay = store
        .record_root_lost_machine_purge(receipt)
        .await
        .expect("replay root-lost proof");
    let RecordRootLostMachinePurgeOutcome::Replayed { state } = replay else {
        panic!("expected root-lost replay");
    };
    let MachineEnrollmentState::PurgeReadbackAbsent(state) = state else {
        panic!("expected purge state");
    };
    assert_eq!(state.reset_kind, MachineTrustResetKind::RootLost);
    let MachinePurgeReadbackProof::RootLost { purge } = state.proof else {
        panic!("expected root-lost proof");
    };
    assert_eq!(purge.canonical_bytes, canonical);
    assert_eq!(purge.canonical_hash, canonical_hash);
    store.shutdown().await.expect("shutdown root-lost store");

    let store = open_store(&root, &keys, None).await;
    assert!(matches!(
        store
            .load_machine_enrollment_state()
            .await
            .expect("restart root-lost load"),
        Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
    ));
    store.shutdown().await.expect("final root-lost shutdown");
}

fn is_after_commit(operation: RuntimeStoreOperation) -> bool {
    matches!(
        operation,
        RuntimeStoreOperation::PrepareMachineRetirementAfterCommit
            | RuntimeStoreOperation::RecordMachineRetirementTerminalAfterCommit
            | RuntimeStoreOperation::ConfirmMachinePurgeReadbackAbsentAfterCommit
            | RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit
    )
}

fn assert_fault(error: RuntimeStoreError, operation: RuntimeStoreOperation) {
    if is_after_commit(operation) {
        let expected = match operation {
            RuntimeStoreOperation::PrepareMachineRetirementAfterCommit => {
                RuntimeCommitOperation::PrepareMachineRetirement
            }
            RuntimeStoreOperation::RecordMachineRetirementTerminalAfterCommit => {
                RuntimeCommitOperation::RecordMachineRetirementTerminal
            }
            RuntimeStoreOperation::ConfirmMachinePurgeReadbackAbsentAfterCommit => {
                RuntimeCommitOperation::ConfirmMachinePurgeReadbackAbsent
            }
            RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit => {
                RuntimeCommitOperation::RecordRootLostMachinePurge
            }
            _ => unreachable!(),
        };
        assert!(matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown { operation } if operation == expected
        ));
    } else {
        assert!(matches!(error, RuntimeStoreError::WorkerStopped));
    }
}

async fn assert_lifecycle(store: &RuntimeStoreHandle, expected: MachineRemoteLifecycle) {
    let state = store
        .load_machine_enrollment_state()
        .await
        .expect("load lifecycle after fault")
        .expect("remote state after fault");
    assert_eq!(state_record(&state).lifecycle, expected);
}

#[tokio::test]
async fn every_reset_transition_before_and_after_commit_fault_retries_exactly() {
    for operation in [
        RuntimeStoreOperation::PrepareMachineRetirementBeforeCommit,
        RuntimeStoreOperation::PrepareMachineRetirementAfterCommit,
        RuntimeStoreOperation::RecordMachineRetirementTerminalBeforeCommit,
        RuntimeStoreOperation::RecordMachineRetirementTerminalAfterCommit,
        RuntimeStoreOperation::ConfirmMachinePurgeReadbackAbsentBeforeCommit,
        RuntimeStoreOperation::ConfirmMachinePurgeReadbackAbsentAfterCommit,
        RuntimeStoreOperation::RecordRootLostMachinePurgeBeforeCommit,
        RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit,
    ] {
        let root = TestRoot::new(&format!("fault-{operation:?}"));
        let keys = MemoryKeyStore::new();
        let binding = binding();
        let store = open_store(
            &root,
            &keys,
            Some(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
        )
        .await;
        make_active(&store, &binding).await;
        let active = store
            .load_machine_enrollment_state()
            .await
            .expect("load active")
            .expect("active exists");
        let enrollment_hash = state_record(&active)
            .enrollment_receipt_hash
            .expect("enrollment hash");

        if matches!(
            operation,
            RuntimeStoreOperation::RecordRootLostMachinePurgeBeforeCommit
                | RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit
        ) {
            let receipt = root_lost_receipt(&binding, enrollment_hash, ROUTE);
            let error = store
                .record_root_lost_machine_purge(receipt.clone())
                .await
                .expect_err("injected root-lost fault");
            assert_fault(error, operation);
            assert_lifecycle(
                &store,
                if is_after_commit(operation) {
                    MachineRemoteLifecycle::PurgeReadbackAbsent
                } else {
                    MachineRemoteLifecycle::Active
                },
            )
            .await;
            store
                .record_root_lost_machine_purge(receipt)
                .await
                .expect("retry root-lost proof");
        } else {
            let retirement = retirement(&binding);
            if matches!(
                operation,
                RuntimeStoreOperation::PrepareMachineRetirementBeforeCommit
                    | RuntimeStoreOperation::PrepareMachineRetirementAfterCommit
            ) {
                let error = store
                    .prepare_machine_retirement(retirement.clone())
                    .await
                    .expect_err("injected retirement fault");
                assert_fault(error, operation);
                assert_lifecycle(
                    &store,
                    if is_after_commit(operation) {
                        MachineRemoteLifecycle::RetirePending
                    } else {
                        MachineRemoteLifecycle::Active
                    },
                )
                .await;
            }
            store
                .prepare_machine_retirement(retirement.clone())
                .await
                .expect("retry retirement");
            let (terminal_bytes, terminal_hash) = terminal(&retirement);
            if matches!(
                operation,
                RuntimeStoreOperation::RecordMachineRetirementTerminalBeforeCommit
                    | RuntimeStoreOperation::RecordMachineRetirementTerminalAfterCommit
            ) {
                let error = store
                    .record_machine_retirement_terminal(terminal_bytes.clone(), terminal_hash)
                    .await
                    .expect_err("injected terminal fault");
                assert_fault(error, operation);
                assert_lifecycle(
                    &store,
                    if is_after_commit(operation) {
                        MachineRemoteLifecycle::RelayCommitted
                    } else {
                        MachineRemoteLifecycle::RetirePending
                    },
                )
                .await;
            }
            store
                .record_machine_retirement_terminal(terminal_bytes.clone(), terminal_hash)
                .await
                .expect("retry terminal");
            if matches!(
                operation,
                RuntimeStoreOperation::ConfirmMachinePurgeReadbackAbsentBeforeCommit
                    | RuntimeStoreOperation::ConfirmMachinePurgeReadbackAbsentAfterCommit
            ) {
                let error = store
                    .confirm_machine_purge_readback_absent(terminal_bytes.clone(), terminal_hash)
                    .await
                    .expect_err("injected purge confirmation fault");
                assert_fault(error, operation);
                assert_lifecycle(
                    &store,
                    if is_after_commit(operation) {
                        MachineRemoteLifecycle::PurgeReadbackAbsent
                    } else {
                        MachineRemoteLifecycle::RelayCommitted
                    },
                )
                .await;
            }
            store
                .confirm_machine_purge_readback_absent(terminal_bytes, terminal_hash)
                .await
                .expect("retry purge confirmation");
        }
        assert_eq!(
            state_record(
                &store
                    .load_machine_enrollment_state()
                    .await
                    .expect("load final")
                    .expect("final state")
            )
            .lifecycle,
            MachineRemoteLifecycle::PurgeReadbackAbsent
        );
        store.shutdown().await.expect("shutdown fault store");
    }
}

async fn build_tamper_fixture(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    stage: &str,
) -> MachineIdentityBinding {
    let binding = binding();
    let store = open_store(root, keys, None).await;
    make_active(&store, &binding).await;
    if stage != "active" {
        let retirement = retirement(&binding);
        if stage == "rootLost" {
            let active = store
                .load_machine_enrollment_state()
                .await
                .expect("load active")
                .expect("active exists");
            let enrollment_hash = state_record(&active).enrollment_receipt_hash.unwrap();
            store
                .record_root_lost_machine_purge(root_lost_receipt(&binding, enrollment_hash, ROUTE))
                .await
                .expect("build root-lost state");
        } else {
            store
                .prepare_machine_retirement(retirement.clone())
                .await
                .expect("build pending state");
            if stage != "pending" {
                let (bytes, hash) = terminal(&retirement);
                store
                    .record_machine_retirement_terminal(bytes.clone(), hash)
                    .await
                    .expect("build committed state");
                if stage == "rootPresent" {
                    store
                        .confirm_machine_purge_readback_absent(bytes, hash)
                        .await
                        .expect("build root-present purge state");
                }
            }
        }
    }
    store.shutdown().await.expect("shutdown tamper fixture");
    binding
}

async fn assert_tampered_open_fails_without_rewrite(root: &TestRoot, keys: &MemoryKeyStore) {
    let tampered = artifact_bytes(&root.database());
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_capacity_probe(GenerousCapacity),
        load_or_create_storage_kek(keys, &root.database()).expect("reload tampered KEK"),
    )
    .await
    .expect_err("tampered reset state must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), tampered);
}

#[tokio::test]
async fn every_reset_stage_locator_and_authenticated_proof_tamper_fail_closed_without_rewrite() {
    for stage in ["active", "pending", "committed", "rootPresent", "rootLost"] {
        let root = TestRoot::new(&format!("locator-{stage}"));
        let keys = MemoryKeyStore::new();
        build_tamper_fixture(&root, &keys, stage).await;
        let connection = Connection::open(root.database()).expect("open locator tamper writer");
        connection
            .execute(
                "DELETE FROM machine_enrollment_receipts
                 WHERE relay_server_id = ?1 AND machine_route = ?2",
                params![RELAY.as_bytes(), ROUTE.as_bytes()],
            )
            .expect("delete locator mirror");
        drop(connection);
        assert_tampered_open_fails_without_rewrite(&root, &keys).await;
    }

    for (stage, sql) in [
        (
            "pending",
            "UPDATE machine_remote_state SET reset_kind = 'rootLost' WHERE singleton = 1",
        ),
        (
            "committed",
            "UPDATE machine_remote_state SET lifecycle = 'retirePending' WHERE singleton = 1",
        ),
        (
            "rootPresent",
            "UPDATE machine_remote_state SET sealed_state = zeroblob(length(sealed_state)) WHERE singleton = 1",
        ),
        (
            "rootLost",
            "UPDATE machine_remote_state SET sealed_state = zeroblob(length(sealed_state)) WHERE singleton = 1",
        ),
    ] {
        let root = TestRoot::new(&format!("proof-{stage}"));
        let keys = MemoryKeyStore::new();
        build_tamper_fixture(&root, &keys, stage).await;
        let connection = Connection::open(root.database()).expect("open proof tamper writer");
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("allow raw offline tamper shape");
        connection.execute(sql, []).expect("tamper reset proof");
        drop(connection);
        assert_tampered_open_fails_without_rewrite(&root, &keys).await;
    }
}
