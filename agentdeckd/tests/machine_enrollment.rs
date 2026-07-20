use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_crypto::{SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256, sign_tbs};
use agentdeck_protocol::relay_v2::{
    CertRole, Digest32, ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, EnrollmentCode,
    LinkGeneration, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, MachineRouteId,
    PublicKeyBytes, RelayServerId, RootKeyId, SignedCertificate, TrustEpoch,
    enrollment_receipt_hash,
};
use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    ActivateMachineEnrollmentOutcome, MachineEnrollmentState, MachineIdentityBinding,
    MachineRemoteLifecycle, PrepareMachineEnrollmentOutcome,
    RecordValidatedEnrollmentResponseOutcome, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use rusqlite::{Connection, params};

const RELAY: RelayServerId = RelayServerId::from_bytes([0x31; 16]);
const ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const ROOT_SEED: [u8; 32] = [0x41; 32];
const LINK_SEED: [u8; 32] = [0x42; 32];
const DATA_SEED: [u8; 32] = [0x43; 32];

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-machine-enrollment-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create machine enrollment test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure machine enrollment test root");
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

fn certificate(
    binding: &MachineIdentityBinding,
    relay: RelayServerId,
    route: MachineRouteId,
    role: CertRole,
) -> SignedCertificate {
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
        &certificate.to_be_signed_v1(relay, route, binding.root_fingerprint),
    )
    .into();
    certificate
}

fn bundle(code: u8) -> EnrollmentBundleV2 {
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
        code: EnrollmentCode([code; 32]),
        spki_pins: vec![Digest32([0x52; 32]), Digest32([0x53; 32])],
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

fn response(request_hash: [u8; 32]) -> MachineEnrollmentResponseV1 {
    MachineEnrollmentResponseV1::new(
        RELAY,
        ROUTE,
        1,
        enrollment_receipt_hash(RELAY, ROUTE, 1, request_hash),
    )
    .expect("valid enrollment response")
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
    .expect("open machine enrollment store")
}

async fn activate_identity(store: &RuntimeStoreHandle, binding: &MachineIdentityBinding) {
    store
        .prepare_machine_identity(binding.clone())
        .await
        .expect("prepare machine identity");
    store
        .activate_machine_identity(binding.clone())
        .await
        .expect("activate machine identity");
}

fn record(state: &MachineEnrollmentState) -> &agentdeckd::runtime::store::MachineRemoteStateRecord {
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

async fn prepare_valid(
    store: &RuntimeStoreHandle,
    bundle: EnrollmentBundleV2,
    binding: &MachineIdentityBinding,
) -> ([u8; 32], SignedCertificate, SignedCertificate) {
    let link = certificate(binding, RELAY, ROUTE, CertRole::Link);
    let data = certificate(binding, RELAY, ROUTE, CertRole::Data);
    let request_hash = request(&bundle, binding, &link, &data).canonical_sha256();
    store
        .prepare_machine_enrollment(bundle, ROUTE, binding.clone(), link.clone(), data.clone())
        .await
        .expect("prepare machine enrollment");
    (request_hash, link, data)
}

async fn make_active(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
) -> ([u8; 32], [u8; 32]) {
    let (request_hash, _, _) = prepare_valid(store, bundle(0x61), binding).await;
    let response = response(request_hash);
    let response_hash = response.canonical_sha256().expect("canonical response");
    store
        .record_validated_enrollment_response(request_hash, response)
        .await
        .expect("record validated response");
    store
        .activate_machine_enrollment(request_hash, response_hash)
        .await
        .expect("activate enrollment");
    (request_hash, response_hash)
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
async fn prepared_validated_active_are_restart_safe_exact_and_erase_code_from_active() {
    let root = TestRoot::new("lifecycle");
    let keys = MemoryKeyStore::new();
    let binding = binding();
    let store = open_store(&root, &keys, None).await;
    activate_identity(&store, &binding).await;
    let enrollment_bundle = bundle(0x62);
    let link = certificate(&binding, RELAY, ROUTE, CertRole::Link);
    let data = certificate(&binding, RELAY, ROUTE, CertRole::Data);
    let request_hash = request(&enrollment_bundle, &binding, &link, &data).canonical_sha256();

    let first = store
        .prepare_machine_enrollment(
            enrollment_bundle.clone(),
            ROUTE,
            binding.clone(),
            link.clone(),
            data.clone(),
        )
        .await
        .expect("prepare enrollment");
    assert!(matches!(
        first,
        PrepareMachineEnrollmentOutcome::Prepared { .. }
    ));
    let replay = store
        .prepare_machine_enrollment(
            enrollment_bundle.clone(),
            ROUTE,
            binding.clone(),
            link.clone(),
            data.clone(),
        )
        .await
        .expect("replay prepared enrollment");
    assert!(matches!(
        replay,
        PrepareMachineEnrollmentOutcome::Replayed { .. }
    ));
    assert_eq!(
        record(
            store
                .load_machine_enrollment_state()
                .await
                .expect("load prepared")
                .as_ref()
                .expect("prepared state")
        )
        .request_hash,
        request_hash
    );
    store.shutdown().await.expect("shutdown prepared store");

    let store = open_store(&root, &keys, None).await;
    let loaded = store
        .load_machine_enrollment_state()
        .await
        .expect("restart load prepared")
        .expect("prepared state survives restart");
    assert!(matches!(
        loaded,
        MachineEnrollmentState::EnrollmentPrepared(_)
    ));
    let exact_response = response(request_hash);
    let response_hash = exact_response
        .canonical_sha256()
        .expect("canonical response hash");
    assert!(matches!(
        store
            .record_validated_enrollment_response(request_hash, exact_response.clone())
            .await
            .expect("record response"),
        RecordValidatedEnrollmentResponseOutcome::Recorded { .. }
    ));
    assert!(matches!(
        store
            .record_validated_enrollment_response(request_hash, exact_response)
            .await
            .expect("replay response"),
        RecordValidatedEnrollmentResponseOutcome::Replayed { .. }
    ));
    assert!(matches!(
        store
            .activate_machine_enrollment(request_hash, response_hash)
            .await
            .expect("activate enrollment"),
        ActivateMachineEnrollmentOutcome::Activated { .. }
    ));
    assert!(matches!(
        store
            .activate_machine_enrollment(request_hash, response_hash)
            .await
            .expect("replay active"),
        ActivateMachineEnrollmentOutcome::Replayed { .. }
    ));
    let loaded = store
        .load_machine_enrollment_state()
        .await
        .expect("load active")
        .expect("active exists");
    assert!(matches!(loaded, MachineEnrollmentState::Active(_)));
    store.shutdown().await.expect("shutdown active store");

    let encoded_code = serde_json::to_string(&enrollment_bundle.code)
        .expect("encode code oracle")
        .trim_matches('"')
        .as_bytes()
        .to_vec();
    for (path, bytes) in artifact_bytes(&root.database()) {
        if let Some(bytes) = bytes {
            assert!(
                !bytes
                    .windows(encoded_code.len())
                    .any(|window| window == encoded_code),
                "enrollment code leaked into {}",
                path.display()
            );
        }
    }
    let store = open_store(&root, &keys, None).await;
    let loaded = store
        .load_machine_enrollment_state()
        .await
        .expect("restart load active")
        .expect("active survives restart");
    assert!(matches!(loaded, MachineEnrollmentState::Active(_)));
    store.shutdown().await.expect("final shutdown");

    let connection = Connection::open(root.database()).expect("inspect locator mirror");
    let locator: (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT relay_server_id, machine_route, root_fingerprint
             FROM machine_enrollment_receipts WHERE relay_server_id = ?1 AND machine_route = ?2",
            params![RELAY.as_bytes(), ROUTE.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("active locator mirror");
    assert_eq!(locator.0, RELAY.as_bytes());
    assert_eq!(locator.1, ROUTE.as_bytes());
    assert_eq!(locator.2, binding.root_fingerprint);
}

#[tokio::test]
async fn prepare_and_response_reject_every_bound_axis_and_exact_cas_conflicts() {
    let root = TestRoot::new("bound-axes");
    let keys = MemoryKeyStore::new();
    let binding = binding();
    let store = open_store(&root, &keys, None).await;
    activate_identity(&store, &binding).await;
    let valid_bundle = bundle(0x63);
    let valid_link = certificate(&binding, RELAY, ROUTE, CertRole::Link);
    let valid_data = certificate(&binding, RELAY, ROUTE, CertRole::Data);

    for origin in [
        "relay.example.test",
        "ws://relay.example.test/",
        "https://relay.example.test/",
        "wss://@relay.example.test/",
        "wss://user@relay.example.test/",
        "wss://user:password@relay.example.test/",
        "wss://relay.example.test:0/",
        "wss://relay.example.test/v2",
        "wss://relay.example.test/?query=1",
        "wss://relay.example.test/#fragment",
        "wss://RELAY.example.test/",
        "wss://relay.example.test",
        "wss://relay.example.test:443/",
        "wss://relay.example.test/a/..",
    ] {
        let mut bad_bundle = valid_bundle.clone();
        bad_bundle.public_wss_url = origin.to_owned();
        assert!(matches!(
            store
                .prepare_machine_enrollment(
                    bad_bundle,
                    ROUTE,
                    binding.clone(),
                    valid_link.clone(),
                    valid_data.clone()
                )
                .await,
            Err(RuntimeStoreError::MachineRemoteConflict)
        ));
    }
    let mut bad_bundle = valid_bundle.clone();
    bad_bundle.code = EnrollmentCode([0; 32]);
    assert!(matches!(
        store
            .prepare_machine_enrollment(
                bad_bundle,
                ROUTE,
                binding.clone(),
                valid_link.clone(),
                valid_data.clone()
            )
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let mut bad_binding = binding.clone();
    bad_binding.root_fingerprint[0] ^= 1;
    assert!(matches!(
        store
            .prepare_machine_enrollment(
                valid_bundle.clone(),
                ROUTE,
                bad_binding,
                valid_link.clone(),
                valid_data.clone()
            )
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let mut bad_cert = valid_link.clone();
    bad_cert.cert_role = CertRole::Data;
    assert!(matches!(
        store
            .prepare_machine_enrollment(
                valid_bundle.clone(),
                ROUTE,
                binding.clone(),
                bad_cert,
                valid_data.clone()
            )
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let wrong_route_link = certificate(
        &binding,
        RELAY,
        MachineRouteId::from_bytes([0x77; 16]),
        CertRole::Link,
    );
    assert!(matches!(
        store
            .prepare_machine_enrollment(
                valid_bundle.clone(),
                ROUTE,
                binding.clone(),
                wrong_route_link,
                valid_data.clone()
            )
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    assert!(
        store
            .load_machine_enrollment_state()
            .await
            .expect("load empty remote state")
            .is_none()
    );

    let request_hash =
        request(&valid_bundle, &binding, &valid_link, &valid_data).canonical_sha256();
    store
        .prepare_machine_enrollment(
            valid_bundle.clone(),
            ROUTE,
            binding.clone(),
            valid_link.clone(),
            valid_data.clone(),
        )
        .await
        .expect("prepare valid enrollment");
    assert!(matches!(
        store
            .prepare_machine_enrollment(
                bundle(0x64),
                ROUTE,
                binding.clone(),
                valid_link,
                valid_data
            )
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let exact_response = response(request_hash);
    assert!(matches!(
        store
            .record_validated_enrollment_response([0x99; 32], exact_response.clone())
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let mut wrong_response = exact_response.clone();
    wrong_response.receipt_hash[0] ^= 1;
    assert!(matches!(
        store
            .record_validated_enrollment_response(request_hash, wrong_response)
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let response_hash = exact_response.canonical_sha256().expect("response hash");
    store
        .record_validated_enrollment_response(request_hash, exact_response)
        .await
        .expect("record exact response");
    assert!(matches!(
        store
            .activate_machine_enrollment([0x98; 32], response_hash)
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    assert!(matches!(
        store
            .activate_machine_enrollment(request_hash, [0x97; 32])
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    store.shutdown().await.expect("shutdown bound-axis store");
}

#[tokio::test]
async fn before_and_after_commit_faults_retry_exactly_across_all_three_transitions() {
    for operation in [
        RuntimeStoreOperation::PrepareMachineEnrollmentBeforeCommit,
        RuntimeStoreOperation::PrepareMachineEnrollmentAfterCommit,
        RuntimeStoreOperation::RecordValidatedEnrollmentResponseBeforeCommit,
        RuntimeStoreOperation::RecordValidatedEnrollmentResponseAfterCommit,
        RuntimeStoreOperation::ActivateMachineEnrollmentBeforeCommit,
        RuntimeStoreOperation::ActivateMachineEnrollmentAfterCommit,
    ] {
        let root = TestRoot::new(&format!("fault-{operation:?}"));
        let keys = MemoryKeyStore::new();
        let binding = binding();
        let fault = Arc::new(OneShotFault {
            operation,
            fired: AtomicBool::new(false),
        });
        let store = open_store(&root, &keys, Some(fault)).await;
        activate_identity(&store, &binding).await;
        let enrollment_bundle = bundle(0x65);
        let link = certificate(&binding, RELAY, ROUTE, CertRole::Link);
        let data = certificate(&binding, RELAY, ROUTE, CertRole::Data);
        let request_hash = request(&enrollment_bundle, &binding, &link, &data).canonical_sha256();

        let prepare = || {
            store.prepare_machine_enrollment(
                enrollment_bundle.clone(),
                ROUTE,
                binding.clone(),
                link.clone(),
                data.clone(),
            )
        };
        if matches!(
            operation,
            RuntimeStoreOperation::PrepareMachineEnrollmentBeforeCommit
                | RuntimeStoreOperation::PrepareMachineEnrollmentAfterCommit
        ) {
            let error = prepare().await.expect_err("injected prepare fault");
            assert_fault(error, operation);
        }
        prepare().await.expect("retry exact prepare");

        let exact_response = response(request_hash);
        let response_hash = exact_response.canonical_sha256().expect("response hash");
        if matches!(
            operation,
            RuntimeStoreOperation::RecordValidatedEnrollmentResponseBeforeCommit
                | RuntimeStoreOperation::RecordValidatedEnrollmentResponseAfterCommit
        ) {
            let error = store
                .record_validated_enrollment_response(request_hash, exact_response.clone())
                .await
                .expect_err("injected response fault");
            assert_fault(error, operation);
        }
        store
            .record_validated_enrollment_response(request_hash, exact_response)
            .await
            .expect("retry exact response");

        if matches!(
            operation,
            RuntimeStoreOperation::ActivateMachineEnrollmentBeforeCommit
                | RuntimeStoreOperation::ActivateMachineEnrollmentAfterCommit
        ) {
            let error = store
                .activate_machine_enrollment(request_hash, response_hash)
                .await
                .expect_err("injected active fault");
            assert_fault(error, operation);
        }
        store
            .activate_machine_enrollment(request_hash, response_hash)
            .await
            .expect("retry exact active");
        assert_eq!(
            record(
                store
                    .load_machine_enrollment_state()
                    .await
                    .expect("load final state")
                    .as_ref()
                    .expect("final state")
            )
            .lifecycle,
            MachineRemoteLifecycle::Active
        );
        store.shutdown().await.expect("shutdown fault store");
    }
}

fn assert_fault(error: RuntimeStoreError, operation: RuntimeStoreOperation) {
    if matches!(
        operation,
        RuntimeStoreOperation::PrepareMachineEnrollmentAfterCommit
            | RuntimeStoreOperation::RecordValidatedEnrollmentResponseAfterCommit
            | RuntimeStoreOperation::ActivateMachineEnrollmentAfterCommit
    ) {
        assert!(matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown { .. }
        ));
    } else {
        assert!(matches!(error, RuntimeStoreError::WorkerStopped));
    }
}

#[tokio::test]
async fn remote_row_mac_sealed_ledger_and_locator_tamper_fail_closed_without_rewrite() {
    for target in ["metadata", "sealed", "ledger", "locator"] {
        let root = TestRoot::new(&format!("tamper-{target}"));
        let keys = MemoryKeyStore::new();
        let binding = binding();
        let store = open_store(&root, &keys, None).await;
        activate_identity(&store, &binding).await;
        make_active(&store, &binding).await;
        store.shutdown().await.expect("shutdown tamper fixture");

        let connection = Connection::open(root.database()).expect("open tamper writer");
        match target {
            "metadata" => {
                connection
                    .execute(
                        "UPDATE machine_remote_state SET metadata_token = zeroblob(32)",
                        [],
                    )
                    .expect("tamper row MAC");
            }
            "sealed" => {
                connection
                    .execute(
                        "UPDATE machine_remote_state
                         SET sealed_state = zeroblob(length(sealed_state))",
                        [],
                    )
                    .expect("tamper sealed state");
            }
            "ledger" => {
                connection
                    .execute("UPDATE runtime_meta SET machine_remote_state_count = 0", [])
                    .expect("tamper remote ledger count");
            }
            "locator" => {
                connection
                    .execute(
                        "DELETE FROM machine_enrollment_receipts
                         WHERE relay_server_id = ?1 AND machine_route = ?2",
                        params![RELAY.as_bytes(), ROUTE.as_bytes()],
                    )
                    .expect("delete locator mirror");
            }
            _ => unreachable!(),
        }
        drop(connection);
        let tampered = artifact_bytes(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_capacity_probe(GenerousCapacity),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload tampered KEK"),
        )
        .await
        .expect_err("tampered remote state must fail closed");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(artifact_bytes(&root.database()), tampered);
    }
}
