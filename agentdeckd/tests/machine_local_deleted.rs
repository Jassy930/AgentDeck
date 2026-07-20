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
use agentdeckd::config::{DaemonConfig, DaemonStartupOptions};
use agentdeckd::remote::bootstrap::{RemoteBootstrapOutcome, reconcile_machine_identity};
use agentdeckd::remote::identity::{
    KEY_DIRECTORY_GUARD_ACCOUNT, MACHINE_DATA_SIGN_ACCOUNT, MACHINE_HPKE_ACCOUNT,
    MACHINE_LINK_SIGN_ACCOUNT, MACHINE_ROOT_SIGN_ACCOUNT,
};
use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    FinalizeMachineLocalDeletionOutcome, MachineCleanupWitnessV1, MachineEnrollmentState,
    MachineIdentityBinding, MachineIdentityLifecycle, MachinePurgeReadbackProof,
    MachineRemoteLifecycle, MachineTrustResetKind, PrepareMachineEnrollmentOutcome,
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreHandle, RuntimeStoreOperation,
};
use agentdeckd::security::{KeyStore, MemoryKeyStore, load_or_create_storage_kek};
use rusqlite::{Connection, params};

const RELAY: RelayServerId = RelayServerId::from_bytes([0x31; 16]);
const OLD_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const NEW_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x72; 16]);
const RECEIPT_SEED: [u8; 32] = [0x51; 32];

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-machine-local-deleted-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create local-deleted test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure local-deleted test root");
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

fn binding(seed: u8) -> MachineIdentityBinding {
    let root_public_key = SigningKey::from_seed(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let link_sign_public_key = SigningKey::from_seed(&[seed + 1; 32])
        .verifying_key()
        .to_bytes();
    let data_sign_public_key = SigningKey::from_seed(&[seed + 2; 32])
        .verifying_key()
        .to_bytes();
    let machine_hpke_public_key = [seed + 3; 32];
    MachineIdentityBinding {
        root_key_id: [seed + 4; 16],
        trust_epoch: u64::from(seed),
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
    seed: u8,
    binding: &MachineIdentityBinding,
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
        &SigningKey::from_seed(&[seed; 32]),
        &certificate.to_be_signed_v1(RELAY, route, binding.root_fingerprint),
    )
    .into();
    certificate
}

fn bundle(code: u8) -> EnrollmentBundleV2 {
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
        code: EnrollmentCode([code; 32]),
        spki_pins: vec![Digest32([code.wrapping_add(1); 32])],
        expires_at_ms: 1_800_000_000_000,
    }
}

fn request(
    bundle: &EnrollmentBundleV2,
    route: MachineRouteId,
    binding: &MachineIdentityBinding,
    link: &SignedCertificate,
    data: &SignedCertificate,
) -> MachineEnrollmentRequestV1 {
    MachineEnrollmentRequestV1 {
        code: bundle.code.clone(),
        machine_route: route,
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
    .expect("open local-deleted store")
}

async fn make_active(
    store: &RuntimeStoreHandle,
    seed: u8,
    route: MachineRouteId,
    binding: &MachineIdentityBinding,
    enrollment_bundle: EnrollmentBundleV2,
) {
    store
        .prepare_machine_identity(binding.clone())
        .await
        .expect("prepare identity");
    store
        .activate_machine_identity(binding.clone())
        .await
        .expect("activate identity");
    let link = certificate(seed, binding, route, CertRole::Link);
    let data = certificate(seed, binding, route, CertRole::Data);
    let request_hash = request(&enrollment_bundle, route, binding, &link, &data).canonical_sha256();
    store
        .prepare_machine_enrollment(enrollment_bundle, route, binding.clone(), link, data)
        .await
        .expect("prepare enrollment");
    let response = MachineEnrollmentResponseV1::new(
        RELAY,
        route,
        binding.trust_epoch,
        enrollment_receipt_hash(RELAY, route, binding.trust_epoch, request_hash),
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
}

fn retirement(seed: u8, binding: &MachineIdentityBinding) -> RetireMachine {
    let mut retirement = RetireMachine {
        machine_route: OLD_ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        signature: agentdeck_protocol::relay_v2::Ed25519Signature([0; 64]),
    };
    retirement.signature = sign_tbs(
        &SigningKey::from_seed(&[seed; 32]),
        &retirement.to_be_signed_v1(RELAY, binding.root_fingerprint),
    )
    .into();
    retirement
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
    enrollment_hash: [u8; 32],
) -> RelayAdminPurgeReceiptV1 {
    let signer = SigningKey::from_seed(&RECEIPT_SEED);
    let verify_key = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signer)
        .expect("valid receipt signer")
        .bind_to_relay(RELAY)
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
    let purge_request_hash =
        purge_request_hash(OLD_ROUTE, binding.root_fingerprint).expect("purge request hash");
    let tombstone = RelayAdminPurgeTombstoneV1 {
        relay_server_id: RELAY,
        machine_route: OLD_ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        root_fingerprint: binding.root_fingerprint,
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        enrollment_receipt_hash: enrollment_hash,
        purge_request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback: readback.clone(),
    };
    let anchor = verify_key.wire_anchor();
    let tbs = RelayAdminPurgeReceiptTbsV1 {
        receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        relay_server_id: RELAY,
        receipt_key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
        receipt_key_id: anchor.key_id,
        machine_route: OLD_ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        root_fingerprint: binding.root_fingerprint,
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        enrollment_receipt_hash: enrollment_hash,
        purge_request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback,
        tombstone_hash: admin_purge_tombstone_hash(&tombstone).expect("tombstone hash"),
    };
    sign_relay_admin_purge_receipt(&signer, &verify_key, tbs).expect("sign purge receipt")
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

async fn make_purge_readback_absent(
    store: &RuntimeStoreHandle,
    seed: u8,
    binding: &MachineIdentityBinding,
    reset_kind: MachineTrustResetKind,
) -> Box<agentdeckd::runtime::store::PurgeReadbackAbsentMachineEnrollmentState> {
    make_active(store, seed, OLD_ROUTE, binding, bundle(0x61)).await;
    match reset_kind {
        MachineTrustResetKind::RootPresent => {
            let retirement = retirement(seed, binding);
            store
                .prepare_machine_retirement(retirement.clone())
                .await
                .expect("prepare retirement");
            let (terminal_bytes, terminal_hash) = terminal(&retirement);
            store
                .record_machine_retirement_terminal(terminal_bytes.clone(), terminal_hash)
                .await
                .expect("record retirement terminal");
            store
                .confirm_machine_purge_readback_absent(terminal_bytes, terminal_hash)
                .await
                .expect("confirm purge readback absent");
        }
        MachineTrustResetKind::RootLost => {
            let active = store
                .load_machine_enrollment_state()
                .await
                .expect("load active")
                .expect("active exists");
            let enrollment_hash = state_record(&active)
                .enrollment_receipt_hash
                .expect("active enrollment receipt hash");
            store
                .record_root_lost_machine_purge(root_lost_receipt(binding, enrollment_hash))
                .await
                .expect("record root-lost purge");
        }
    }
    let state = store
        .load_machine_enrollment_state()
        .await
        .expect("load purge state")
        .expect("purge state exists");
    let MachineEnrollmentState::PurgeReadbackAbsent(purge) = state else {
        panic!("expected purge-readback-absent state");
    };
    assert_eq!(purge.reset_kind, reset_kind);
    assert_eq!(purge.binding, *binding);
    assert_ne!(purge.database_id, [0; 16]);
    purge
}

fn cleanup_witness(
    purge: &agentdeckd::runtime::store::PurgeReadbackAbsentMachineEnrollmentState,
) -> MachineCleanupWitnessV1 {
    let purge_proof_hash = match &purge.proof {
        MachinePurgeReadbackProof::RootPresent { terminal, .. } => terminal.canonical_frame_hash,
        MachinePurgeReadbackProof::RootLost { purge } => purge.canonical_hash,
    };
    MachineCleanupWitnessV1::new(
        purge.reset_kind,
        RelayServerId::from_bytes(purge.record.relay_server_id),
        MachineRouteId::from_bytes(purge.record.machine_route),
        RootKeyId::from_bytes(purge.record.root_key_id),
        purge.record.root_fingerprint,
        TrustEpoch::new(purge.record.trust_epoch),
        purge_proof_hash,
    )
    .expect("valid cleanup witness")
}

async fn finalize(
    store: &RuntimeStoreHandle,
    witness: &MachineCleanupWitnessV1,
) -> FinalizeMachineLocalDeletionOutcome {
    store
        .finalize_machine_local_deletion(
            witness.reset_kind(),
            witness.purge_proof_hash(),
            witness.canonical_sha256(),
        )
        .await
        .expect("finalize local deletion")
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

fn assert_local_deleted_physical_state(root: &TestRoot) {
    let connection = Connection::open(root.database()).expect("inspect physical state");
    let (lifecycle, reset_kind, identity_count, remote_count, locator_count): (
        String,
        Option<String>,
        i64,
        i64,
        i64,
    ) = connection
        .query_row(
            "SELECT
                (SELECT lifecycle FROM machine_remote_state WHERE singleton = 1),
                (SELECT reset_kind FROM machine_remote_state WHERE singleton = 1),
                machine_identity_count,
                machine_remote_state_count,
                (SELECT COUNT(*) FROM machine_enrollment_receipts)
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("read physical local-deleted state");
    assert_eq!(lifecycle, "localDeleted");
    assert!(matches!(
        reset_kind.as_deref(),
        Some("rootPresent" | "rootLost")
    ));
    assert_eq!(identity_count, 0);
    assert_eq!(remote_count, 1);
    assert_eq!(locator_count, 0);
    let physical_identity_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM machine_identity_state", [], |row| {
            row.get(0)
        })
        .expect("count machine identity rows");
    assert_eq!(physical_identity_count, 0);
}

#[tokio::test]
async fn both_reset_kinds_finalize_replay_restart_and_delete_atomically() {
    for reset_kind in [
        MachineTrustResetKind::RootPresent,
        MachineTrustResetKind::RootLost,
    ] {
        let root = TestRoot::new(&format!("finalize-{reset_kind:?}"));
        let keys = MemoryKeyStore::new();
        let old_binding = binding(0x41);
        let store = open_store(&root, &keys, None).await;
        let purge = make_purge_readback_absent(&store, 0x41, &old_binding, reset_kind).await;
        let witness = cleanup_witness(&purge);

        assert!(matches!(
            store
                .finalize_machine_local_deletion(
                    match reset_kind {
                        MachineTrustResetKind::RootPresent => MachineTrustResetKind::RootLost,
                        MachineTrustResetKind::RootLost => MachineTrustResetKind::RootPresent,
                    },
                    witness.purge_proof_hash(),
                    witness.canonical_sha256(),
                )
                .await,
            Err(RuntimeStoreError::MachineRemoteConflict)
        ));
        let mut wrong_proof = witness.purge_proof_hash();
        wrong_proof[0] ^= 1;
        assert!(matches!(
            store
                .finalize_machine_local_deletion(
                    witness.reset_kind(),
                    wrong_proof,
                    witness.canonical_sha256(),
                )
                .await,
            Err(RuntimeStoreError::MachineRemoteConflict)
        ));
        let mut wrong_witness = witness.canonical_sha256();
        wrong_witness[0] ^= 1;
        assert!(matches!(
            store
                .finalize_machine_local_deletion(
                    witness.reset_kind(),
                    witness.purge_proof_hash(),
                    wrong_witness,
                )
                .await,
            Err(RuntimeStoreError::MachineRemoteConflict)
        ));

        let FinalizeMachineLocalDeletionOutcome::Finalized { state } =
            finalize(&store, &witness).await
        else {
            panic!("expected first finalize");
        };
        let MachineEnrollmentState::LocalDeleted(deleted) = state else {
            panic!("expected local-deleted state");
        };
        assert_eq!(
            deleted.record.lifecycle,
            MachineRemoteLifecycle::LocalDeleted
        );
        assert_eq!(deleted.reset_kind, reset_kind);
        assert_eq!(deleted.purge_proof_hash, witness.purge_proof_hash());
        assert_eq!(deleted.cleanup_witness_hash, witness.canonical_sha256());
        assert!(
            store
                .load_machine_identity_state()
                .await
                .expect("load deleted identity")
                .is_none()
        );
        assert!(matches!(
            finalize(&store, &witness).await,
            FinalizeMachineLocalDeletionOutcome::Replayed { .. }
        ));
        store.shutdown().await.expect("shutdown finalized store");
        assert_local_deleted_physical_state(&root);

        let store = open_store(&root, &keys, None).await;
        assert!(matches!(
            store
                .load_machine_enrollment_state()
                .await
                .expect("restart local-deleted load"),
            Some(MachineEnrollmentState::LocalDeleted(_))
        ));
        assert!(matches!(
            finalize(&store, &witness).await,
            FinalizeMachineLocalDeletionOutcome::Replayed { .. }
        ));
        store.shutdown().await.expect("shutdown replay store");
    }
}

fn is_after_commit(operation: RuntimeStoreOperation) -> bool {
    matches!(
        operation,
        RuntimeStoreOperation::FinalizeMachineLocalDeletionAfterCommit
            | RuntimeStoreOperation::ReplaceLocalDeletedEnrollmentAfterCommit
    )
}

fn assert_fault(error: RuntimeStoreError, operation: RuntimeStoreOperation) {
    if is_after_commit(operation) {
        let expected = match operation {
            RuntimeStoreOperation::FinalizeMachineLocalDeletionAfterCommit => {
                RuntimeCommitOperation::FinalizeMachineLocalDeletion
            }
            RuntimeStoreOperation::ReplaceLocalDeletedEnrollmentAfterCommit => {
                RuntimeCommitOperation::ReplaceLocalDeletedEnrollment
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

async fn prepare_replacement(
    store: &RuntimeStoreHandle,
    bundle: EnrollmentBundleV2,
    binding: &MachineIdentityBinding,
    route: MachineRouteId,
) -> Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError> {
    store
        .prepare_machine_enrollment(
            bundle,
            route,
            binding.clone(),
            certificate(0x71, binding, route, CertRole::Link),
            certificate(0x71, binding, route, CertRole::Data),
        )
        .await
}

#[tokio::test]
async fn finalize_and_replacement_before_after_commit_faults_retry_exactly() {
    for operation in [
        RuntimeStoreOperation::FinalizeMachineLocalDeletionBeforeCommit,
        RuntimeStoreOperation::FinalizeMachineLocalDeletionAfterCommit,
        RuntimeStoreOperation::ReplaceLocalDeletedEnrollmentBeforeCommit,
        RuntimeStoreOperation::ReplaceLocalDeletedEnrollmentAfterCommit,
    ] {
        let root = TestRoot::new(&format!("fault-{operation:?}"));
        let keys = MemoryKeyStore::new();
        let store = open_store(
            &root,
            &keys,
            Some(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
        )
        .await;
        let old_binding = binding(0x41);
        let purge = make_purge_readback_absent(
            &store,
            0x41,
            &old_binding,
            MachineTrustResetKind::RootPresent,
        )
        .await;
        let witness = cleanup_witness(&purge);

        if matches!(
            operation,
            RuntimeStoreOperation::FinalizeMachineLocalDeletionBeforeCommit
                | RuntimeStoreOperation::FinalizeMachineLocalDeletionAfterCommit
        ) {
            let error = store
                .finalize_machine_local_deletion(
                    witness.reset_kind(),
                    witness.purge_proof_hash(),
                    witness.canonical_sha256(),
                )
                .await
                .expect_err("injected finalize fault");
            assert_fault(error, operation);
            let state = store
                .load_machine_enrollment_state()
                .await
                .expect("load post-fault finalize")
                .expect("remote state remains");
            assert_eq!(
                state_record(&state).lifecycle,
                if is_after_commit(operation) {
                    MachineRemoteLifecycle::LocalDeleted
                } else {
                    MachineRemoteLifecycle::PurgeReadbackAbsent
                }
            );
        }
        finalize(&store, &witness).await;

        let new_binding = binding(0x71);
        let replacement_bundle = bundle(0x81);
        if matches!(
            operation,
            RuntimeStoreOperation::ReplaceLocalDeletedEnrollmentBeforeCommit
                | RuntimeStoreOperation::ReplaceLocalDeletedEnrollmentAfterCommit
        ) {
            let error =
                prepare_replacement(&store, replacement_bundle.clone(), &new_binding, NEW_ROUTE)
                    .await
                    .expect_err("injected replacement fault");
            assert_fault(error, operation);
            let state = store
                .load_machine_enrollment_state()
                .await
                .expect("load post-fault replacement")
                .expect("remote state remains");
            assert_eq!(
                state_record(&state).lifecycle,
                if is_after_commit(operation) {
                    MachineRemoteLifecycle::EnrollmentPrepared
                } else {
                    MachineRemoteLifecycle::LocalDeleted
                }
            );
            assert_eq!(
                store
                    .load_machine_identity_state()
                    .await
                    .expect("load post-fault identity")
                    .is_some(),
                is_after_commit(operation)
            );
        }
        prepare_replacement(&store, replacement_bundle, &new_binding, NEW_ROUTE)
            .await
            .expect("retry exact replacement");
        let identity = store
            .load_machine_identity_state()
            .await
            .expect("load replacement identity")
            .expect("replacement identity exists");
        assert_eq!(identity.lifecycle, MachineIdentityLifecycle::Active);
        assert_eq!(identity.binding, new_binding);
        store.shutdown().await.expect("shutdown fault store");
    }
}

#[tokio::test]
async fn reenrollment_is_atomic_fresh_and_blocks_old_identity_or_route_revival() {
    let root = TestRoot::new("reenroll");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys, None).await;
    let old_binding = binding(0x41);
    let purge =
        make_purge_readback_absent(&store, 0x41, &old_binding, MachineTrustResetKind::RootLost)
            .await;
    let witness = cleanup_witness(&purge);
    finalize(&store, &witness).await;

    let new_binding = binding(0x71);
    assert!(matches!(
        store.prepare_machine_identity(new_binding.clone()).await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    assert!(matches!(
        prepare_replacement(&store, bundle(0x82), &new_binding, OLD_ROUTE).await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    let old_root_link = certificate(0x41, &old_binding, NEW_ROUTE, CertRole::Link);
    let old_root_data = certificate(0x41, &old_binding, NEW_ROUTE, CertRole::Data);
    assert!(matches!(
        store
            .prepare_machine_enrollment(
                bundle(0x83),
                NEW_ROUTE,
                old_binding.clone(),
                old_root_link,
                old_root_data,
            )
            .await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));

    let replacement_bundle = bundle(0x84);
    assert!(matches!(
        prepare_replacement(&store, replacement_bundle.clone(), &new_binding, NEW_ROUTE,)
            .await
            .expect("prepare fresh replacement"),
        PrepareMachineEnrollmentOutcome::Prepared { .. }
    ));
    assert!(matches!(
        prepare_replacement(&store, replacement_bundle, &new_binding, NEW_ROUTE)
            .await
            .expect("replay fresh replacement"),
        PrepareMachineEnrollmentOutcome::Replayed { .. }
    ));
    let identity = store
        .load_machine_identity_state()
        .await
        .expect("load replacement identity")
        .expect("replacement identity exists");
    assert_eq!(identity.lifecycle, MachineIdentityLifecycle::Active);
    assert_eq!(identity.binding, new_binding);
    let state = store
        .load_machine_enrollment_state()
        .await
        .expect("load replacement remote state")
        .expect("replacement remote state exists");
    let MachineEnrollmentState::EnrollmentPrepared(prepared) = state else {
        panic!("expected enrollment-prepared replacement");
    };
    assert_eq!(prepared.record.machine_route, *NEW_ROUTE.as_bytes());
    assert_eq!(prepared.record.root_key_id, new_binding.root_key_id);
    store.shutdown().await.expect("shutdown replacement store");

    let connection = Connection::open(root.database()).expect("inspect replacement transaction");
    let (identity_count, remote_count, reset_kind): (i64, i64, Option<String>) = connection
        .query_row(
            "SELECT machine_identity_count, machine_remote_state_count,
                    (SELECT reset_kind FROM machine_remote_state WHERE singleton = 1)
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read replacement ledger");
    assert_eq!((identity_count, remote_count), (1, 1));
    assert_eq!(reset_kind, None);
}

async fn build_local_deleted_fixture(root: &TestRoot, keys: &MemoryKeyStore) {
    let store = open_store(root, keys, None).await;
    let old_binding = binding(0x41);
    let purge = make_purge_readback_absent(
        &store,
        0x41,
        &old_binding,
        MachineTrustResetKind::RootPresent,
    )
    .await;
    let witness = cleanup_witness(&purge);
    finalize(&store, &witness).await;
    store.shutdown().await.expect("shutdown tamper fixture");
}

#[tokio::test]
async fn startup_local_deleted_waits_for_explicit_reenroll_without_creating_keys() {
    let root = TestRoot::new("startup-no-implicit-reenroll");
    let keys = MemoryKeyStore::new();
    build_local_deleted_fixture(&root, &keys).await;
    let store = open_store(&root, &keys, None).await;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let home = Path::new("/tmp").join(format!("adlh-{}", &suffix[..8]));
    fs::create_dir_all(home.join("Library/Application Support")).expect("create stable test home");
    let config = DaemonConfig::resolve_with_roots(
        DaemonStartupOptions {
            ephemeral: false,
            no_remote: false,
            stdio_compat: false,
            profile: None,
            stable_keychain_access_group: Some(
                "A1B2C3D4E5.com.agentdeck.agentdeckd.stable".to_owned(),
            ),
        },
        &home,
        &root.0,
    )
    .expect("resolve stable config");
    let outcome = reconcile_machine_identity(&config, &store, &keys)
        .await
        .expect("LocalDeleted bootstrap is remote-only blocked");
    let RemoteBootstrapOutcome::Blocked(block) = outcome else {
        panic!("LocalDeleted must wait for explicit re-enroll")
    };
    assert_eq!(block.code(), "daemon.remote.enrollment.local_deleted");
    for account in [
        MACHINE_ROOT_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_DATA_SIGN_ACCOUNT,
        KEY_DIRECTORY_GUARD_ACCOUNT,
    ] {
        assert!(
            keys.load(account).expect("read key account").is_none(),
            "startup unexpectedly created {account}"
        );
    }
    store.shutdown().await.expect("shutdown LocalDeleted store");
    let _ = fs::remove_dir_all(home);
}

fn apply_offline_tamper(root: &TestRoot, target: &str) {
    let connection = Connection::open(root.database()).expect("open offline tamper writer");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("allow raw offline tamper shape");
    match target {
        "lifecycle" => {
            connection
                .execute(
                    "UPDATE machine_remote_state SET lifecycle = 'purgeReadbackAbsent'
                     WHERE singleton = 1",
                    [],
                )
                .expect("tamper lifecycle");
        }
        "reset" => {
            connection
                .execute(
                    "UPDATE machine_remote_state SET reset_kind = 'rootLost' WHERE singleton = 1",
                    [],
                )
                .expect("tamper reset kind");
        }
        "sealed" => {
            connection
                .execute(
                    "UPDATE machine_remote_state
                     SET sealed_state = zeroblob(length(sealed_state)) WHERE singleton = 1",
                    [],
                )
                .expect("tamper sealed tombstone");
        }
        "hash" => {
            connection
                .execute(
                    "UPDATE machine_remote_state SET request_hash = ?1 WHERE singleton = 1",
                    params![&[0xaa_u8; 32][..]],
                )
                .expect("tamper authenticated hash");
        }
        "metadata" => {
            connection
                .execute(
                    "UPDATE machine_remote_state SET metadata_token = zeroblob(32)
                     WHERE singleton = 1",
                    [],
                )
                .expect("tamper row metadata token");
        }
        "locator" => {
            connection
                .execute(
                    "INSERT INTO machine_enrollment_receipts (
                        relay_server_id, machine_route, root_fingerprint
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        RELAY.as_bytes(),
                        OLD_ROUTE.as_bytes(),
                        &binding(0x41).root_fingerprint[..],
                    ],
                )
                .expect("restore forbidden locator");
        }
        "identity" => {
            let database_id: Vec<u8> = connection
                .query_row(
                    "SELECT database_id FROM machine_remote_state WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("read authenticated database id shape");
            connection
                .execute(
                    "INSERT INTO machine_identity_state (
                        singleton, identity_state, database_id, root_key_id, trust_epoch,
                        link_generation, data_generation, key_directory_revision,
                        root_public_key, root_fingerprint, machine_hpke_public_key,
                        machine_hpke_fingerprint, link_sign_public_key, link_sign_fingerprint,
                        data_sign_public_key, data_sign_fingerprint, metadata_token
                     ) VALUES (
                        1, 'active', ?1, ?2, '00000000000000000001',
                        '00000000000000000001', '00000000000000000001',
                        '00000000000000000000', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
                     )",
                    params![
                        database_id,
                        &[0x91_u8; 16][..],
                        &[0x92_u8; 32][..],
                        &[0x93_u8; 32][..],
                        &[0x94_u8; 32][..],
                        &[0x95_u8; 32][..],
                        &[0x96_u8; 32][..],
                        &[0x97_u8; 32][..],
                        &[0x98_u8; 32][..],
                        &[0x99_u8; 32][..],
                        &[0x9a_u8; 32][..],
                    ],
                )
                .expect("restore forbidden identity");
        }
        "ledger" => {
            connection
                .execute(
                    "UPDATE runtime_meta SET machine_remote_state_count = 0 WHERE singleton = 1",
                    [],
                )
                .expect("tamper authenticated ledger");
        }
        _ => panic!("unknown tamper target: {target}"),
    }
}

#[tokio::test]
async fn local_deleted_offline_tamper_fails_closed_without_rewriting_any_artifact() {
    for target in [
        "lifecycle",
        "reset",
        "sealed",
        "hash",
        "metadata",
        "locator",
        "identity",
        "ledger",
    ] {
        let root = TestRoot::new(&format!("tamper-{target}"));
        let keys = MemoryKeyStore::new();
        build_local_deleted_fixture(&root, &keys).await;
        apply_offline_tamper(&root, target);
        let tampered = artifact_bytes(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_capacity_probe(GenerousCapacity),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload tampered KEK"),
        )
        .await
        .expect_err("tampered local-deleted store must fail closed");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(
            artifact_bytes(&root.database()),
            tampered,
            "target={target}"
        );
    }
}
