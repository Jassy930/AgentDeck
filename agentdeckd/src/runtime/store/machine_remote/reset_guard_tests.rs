use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{
    HpkePrivateKey, SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256,
    sign_pair_response_received, sign_relay_admin_purge_receipt, sign_tbs,
};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, PairInviteV1, PairResponseReceivedV1};
use agentdeck_protocol::relay_v2::frame::{
    GrantCommitted, OpaqueRouteFrame, PairRouteCloseOutcome, PairRouteClosed, RelayFrameBody,
    RetireMachine, RevocationCommitted,
};
use agentdeck_protocol::relay_v2::{
    CertRole, DeviceRevocation, Digest32, ENROLLMENT_BUNDLE_VERSION, Ed25519Signature,
    EnrollmentBundleV2, EnrollmentCode, GrantSerial, LinkGeneration, MachineEnrollmentRequestV1,
    MachineEnrollmentResponseV1, MachineRouteId, PairRouteId, PublicKeyBytes,
    RELAY_PROTOCOL_VERSION, RELAY_RECEIPT_FORMAT_VERSION, RELAY_RECEIPT_KEY_GENERATION_MVP,
    RelayAdminPurgeReadbackV1, RelayAdminPurgeReceiptTbsV1, RelayAdminPurgeReceiptV1,
    RelayAdminPurgeTombstoneV1, RelayGrant, RelayMachineTombstoneKindV1, RelayServerId, RootKeyId,
    SignedCertificate, TrustEpoch, admin_purge_tombstone_hash, decode, encode,
    enrollment_receipt_hash, purge_request_hash,
};
use rusqlite::Connection;

use crate::remote::access::{PairResponseAccessBinding, VerifiedPairResponseReceipt};
use crate::runtime::model::{
    IdempotencyOwner, MachineEnrollmentState, MachineIdentityBinding, RuntimeCapacityObservation,
    RuntimeCapacityProbe, RuntimeCapacityProbeError, RuntimeCommitOperation, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

use super::super::pairing::{PreparePairingInvite, PreparePairingInviteOutcome};
use super::super::pairing_delivery::{
    AcknowledgePairResponseReceived, AcknowledgePairResponseReceivedOutcome,
};
use super::super::pairing_grant::PairingGrantPreparation;
use super::super::pairing_grant_allocation::GrantAllocationProjection;
use super::super::pairing_grant_commit::{
    AcknowledgeGrantCommitted, AcknowledgeGrantCommittedOutcome, GrantCommittedRecovery,
};
use super::super::pairing_grant_tests::{
    awaiting_pairing, awaiting_pairing_with, grant_input, grant_input_with, secret,
};
use super::super::pairing_grant_tx::{ConfirmPairingGrantOutcome, GrantPreparingRecovery};
use super::super::pairing_revocation::{BeginDeviceRevocation, BeginDeviceRevocationOutcome};
use super::super::pairing_revocation_ack::{
    AcknowledgeRevocationCommitted, AcknowledgeRevocationCommittedOutcome,
};
use super::super::pairing_terminal::PairingTerminalAction;
use super::super::pairing_tests::{NOW_MS, TestClock};
use super::super::{RuntimeId, RuntimeStoreHandle};

const RELAY: RelayServerId = RelayServerId::from_bytes([0x31; 16]);
const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const ROOT_SEED: [u8; 32] = [0x41; 32];
const LINK_SEED: [u8; 32] = [0x42; 32];
const DATA_SEED: [u8; 32] = [0x43; 32];
const RECEIPT_SEED: [u8; 32] = [0x51; 32];
const DEVICE_SIGN_SEED: [u8; 32] = [0xa4; 32];

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-machine-reset-pairing-guard-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create reset guard test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure reset guard test root");
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

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_millis(),
    )
    .expect("current time fits u64 milliseconds")
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
    let (subject_pubkey, generation) = match role {
        CertRole::Link => (binding.link_sign_public_key, binding.link_generation),
        CertRole::Data => (binding.data_sign_public_key, binding.data_generation),
    };
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject_pubkey),
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
        spki_pins: vec![Digest32([0x52; 32]), Digest32([0x53; 32])],
        expires_at_ms: now_ms() + 300_000,
    }
}

async fn open_store(root: &TestRoot, keys: &MemoryKeyStore) -> RuntimeStoreHandle {
    open_store_with_fault(root, keys, None).await
}

async fn open_store_with_fault(
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
    .expect("open reset guard store")
}

async fn open_store_with_clock_and_fault(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    clock: Arc<AtomicU64>,
    fault: Option<Arc<dyn RuntimeStoreFaultInjector>>,
) -> RuntimeStoreHandle {
    let mut config = RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock));
    if let Some(fault) = fault {
        config = config.with_fault_injector(fault);
    }
    RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(keys, &root.database()).expect("load test StorageKEK"),
    )
    .await
    .expect("open fixed-clock reset guard store")
}

struct OneShotFault {
    operation: RuntimeStoreOperation,
    fired: AtomicBool,
}

impl OneShotFault {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            fired: AtomicBool::new(false),
        }
    }
}

impl RuntimeStoreFaultInjector for OneShotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

async fn make_active(store: &RuntimeStoreHandle, binding: &MachineIdentityBinding) -> [u8; 32] {
    store
        .prepare_machine_identity(binding.clone())
        .await
        .expect("prepare identity");
    store
        .activate_machine_identity(binding.clone())
        .await
        .expect("activate identity");
    let bundle = bundle();
    let link = certificate(binding, CertRole::Link);
    let data = certificate(binding, CertRole::Data);
    let request = MachineEnrollmentRequestV1 {
        code: bundle.code.clone(),
        machine_route: MACHINE_ROUTE,
        root_pubkey: PublicKeyBytes(binding.root_public_key),
        link_cert: link.clone(),
        data_cert: data.clone(),
    };
    let request_hash = request.canonical_sha256();
    store
        .prepare_machine_enrollment(bundle, MACHINE_ROUTE, binding.clone(), link, data)
        .await
        .expect("prepare enrollment");
    let receipt_hash =
        enrollment_receipt_hash(RELAY, MACHINE_ROUTE, binding.trust_epoch, request_hash);
    let response =
        MachineEnrollmentResponseV1::new(RELAY, MACHINE_ROUTE, binding.trust_epoch, receipt_hash)
            .expect("valid enrollment response");
    let response_hash = response.canonical_sha256().expect("canonical response");
    store
        .record_validated_enrollment_response(request_hash, response)
        .await
        .expect("record enrollment response");
    store
        .activate_machine_enrollment(request_hash, response_hash)
        .await
        .expect("activate enrollment");
    receipt_hash
}

async fn prepare_active_pairing(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
) -> (RuntimeId, PairRouteId) {
    let hpke_private = [0x71; 32];
    let hpke_public: [u8; 32] = HpkePrivateKey::from_bytes(&hpke_private)
        .expect("valid test HPKE private key")
        .public_key()
        .to_bytes()
        .try_into()
        .expect("X25519 public key is 32 bytes");
    let pair_route = PairRouteId::from_bytes([0x72; 16]);
    let invite = PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        pair_route,
        invite_secret: [0x73; 32],
        invite_hpke_pubkey: PublicKeyBytes(hpke_public),
        wss_url: "wss://relay.example.test:8443/".to_owned(),
        relay_server_id: RELAY,
        current_spki_pin: [0x52; 32],
        next_spki_pin: [0x53; 32],
        expires_at_ms: now_ms() + 300_000,
        machine_root_pubkey: PublicKeyBytes(binding.root_public_key),
        machine_root_fingerprint: binding.root_fingerprint,
        data_sign_cert: certificate(binding, CertRole::Data),
        machine_display_name: "reset-guard-machine".to_owned(),
    }
    .canonical_bytes()
    .expect("canonical PairInvite");
    let outcome = store
        .prepare_pairing_invite(PreparePairingInvite::new(
            IdempotencyOwner::Local {
                machine_trust_domain: binding.root_fingerprint,
                uid: 501,
                client_installation_id: [0x74; 16],
            },
            "reset-guard-invite".to_owned(),
            SecretBytes::new(invite),
            SecretBytes::new(hpke_private.to_vec()),
        ))
        .await
        .expect("persist pairing secret and OpenPairRoute outbox");
    match outcome {
        PreparePairingInviteOutcome::Prepared { invite } => (invite.pairing_id(), pair_route),
        PreparePairingInviteOutcome::Replayed { .. } => panic!("fresh reset guard invite"),
        PreparePairingInviteOutcome::Terminal { .. } => panic!("fresh reset guard invite"),
    }
}

fn next_time(clock: &AtomicU64) {
    let _ = clock.fetch_add(1, Ordering::SeqCst);
}

fn grant_from_install(recovery: &GrantPreparingRecovery) -> RelayGrant {
    let frame: OpaqueRouteFrame =
        decode(recovery.canonical_install_frame()).expect("decode InstallGrant");
    match frame.body {
        RelayFrameBody::InstallGrant(install) => install.grant,
        other => panic!("expected InstallGrant, got {other:?}"),
    }
}

fn grant_committed_frame(grant: &RelayGrant) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
        }),
    })
}

fn pair_route_closed_frame(pair_route: PairRouteId) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route,
            outcome: PairRouteCloseOutcome::Closed,
        }),
    })
}

fn verified_receipt(recovery: &GrantCommittedRecovery) -> VerifiedPairResponseReceipt {
    let binding = PairResponseAccessBinding::from_frozen(
        recovery.invite(),
        recovery.request_hash(),
        recovery.relay_grant(),
        recovery.pair_response(),
    )
    .expect("rebuild response binding");
    let receipt = sign_pair_response_received(
        &SigningKey::from_seed(&DEVICE_SIGN_SEED),
        binding.info(),
        binding.receipt_context(),
        PairResponseReceivedV1 {
            request_hash: recovery.request_hash(),
            grant_hash: recovery.grant_hash(),
            response_hash: recovery.response_hash(),
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign PairResponseReceived");
    binding
        .verify_signed_receipt(
            &receipt
                .canonical_bytes()
                .expect("canonical PairResponseReceived"),
        )
        .expect("verify PairResponseReceived")
}

async fn confirm_commit_and_deliver(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    preparation: &PairingGrantPreparation,
    input: super::super::pairing_grant::ConfirmPairingGrant,
) -> RelayGrant {
    let confirmed = store
        .confirm_pairing_grant(input)
        .await
        .expect("confirm full-history grant");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("fresh full-history grant must confirm: {other:?}"),
    };
    let grant = grant_from_install(&installing);
    next_time(clock);
    let committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&grant),
        ))
        .await
        .expect("acknowledge full-history GrantCommitted");
    let committed = match committed {
        AcknowledgeGrantCommittedOutcome::Committed { recovery } => recovery,
        other => panic!("fresh full-history GrantCommitted must transition: {other:?}"),
    };
    let proof = verified_receipt(&committed);
    next_time(clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("acknowledge full-history PairResponseReceived")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh full-history delivery must transition: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            pair_route_closed_frame(close.pair_route()),
        )
        .await
        .expect("acknowledge full-history PairRouteClosed");
    grant
}

async fn prepare_full_grant_history(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
    clock: &AtomicU64,
) -> RelayGrant {
    let data_cert = certificate(binding, CertRole::Data);
    let first = awaiting_pairing(store, binding, &data_cert).await;
    let first_grant = confirm_commit_and_deliver(
        store,
        clock,
        &first,
        grant_input(&first, binding, &data_cert),
    )
    .await;

    let renewal = awaiting_pairing_with(
        store,
        binding,
        &data_cert,
        PairRouteId::from_bytes([0xb1; 16]),
        0xb2,
        0xb3,
        0xa4,
        0xb5,
        0xb6,
        0xb7,
        "reset-full-history-renewal",
    )
    .await;
    let device_sign_fingerprint = sha256(&renewal.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(renewal.pairing_id(), device_sign_fingerprint)
        .await
        .expect("load full-history renewal allocation");
    let GrantAllocationProjection::Renew {
        device_route,
        current_serial,
        next_serial,
        current_global_keys,
        ..
    } = projection
    else {
        panic!("same DeviceSign fingerprint must renew")
    };
    assert_eq!(device_route, first_grant.device_route);
    assert_eq!(current_serial, GrantSerial::new(1));
    assert_eq!(next_serial, GrantSerial::new(2));
    let next_global = current_global_keys
        .renew_for_device(device_route, secret(0xd1), secret(0xd2), secret(0xd3))
        .expect("renew full-history key directory");
    let renewed = confirm_commit_and_deliver(
        store,
        clock,
        &renewal,
        grant_input_with(
            &renewal,
            binding,
            &data_cert,
            device_route,
            next_serial,
            next_global,
            None,
            0xd4,
        ),
    )
    .await;
    assert_eq!(renewed.device_route, first_grant.device_route);
    assert_eq!(renewed.grant_serial, GrantSerial::new(2));
    renewed
}

fn signed_revocation(grant: &RelayGrant, binding: &MachineIdentityBinding) -> DeviceRevocation {
    let mut revocation = DeviceRevocation {
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: grant.grant_serial,
        root_key_id: grant.root_key_id,
        trust_epoch: grant.trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SEED),
        &revocation.to_be_signed_v1(RELAY, binding.root_fingerprint),
    )
    .into();
    revocation
}

fn revocation_committed_frame(revocation: &DeviceRevocation) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: revocation.device_route,
            grant_serial: revocation.grant_serial,
            signed_revocation: revocation.clone(),
        }),
    })
}

async fn revoke_current_grant(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
    clock: &AtomicU64,
    grant: &RelayGrant,
) {
    let revocation = signed_revocation(grant, binding);
    next_time(clock);
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::local(revocation.clone()))
            .await
            .expect("begin full-history revocation"),
        BeginDeviceRevocationOutcome::Prepared { .. }
    ));
    next_time(clock);
    assert!(matches!(
        store
            .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                revocation_committed_frame(&revocation),
            ))
            .await
            .expect("acknowledge full-history revocation"),
        AcknowledgeRevocationCommittedOutcome::Committed { .. }
    ));
}

fn retirement(binding: &MachineIdentityBinding) -> RetireMachine {
    let mut retirement = RetireMachine {
        machine_route: MACHINE_ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        signature: agentdeck_protocol::relay_v2::Ed25519Signature([0; 64]),
    };
    retirement.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SEED),
        &retirement.to_be_signed_v1(RELAY, binding.root_fingerprint),
    )
    .into();
    retirement
}

fn root_lost_receipt(
    binding: &MachineIdentityBinding,
    enrollment_receipt_hash: [u8; 32],
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
    let request_hash =
        purge_request_hash(MACHINE_ROUTE, binding.root_fingerprint).expect("purge request hash");
    let tombstone = RelayAdminPurgeTombstoneV1 {
        relay_server_id: RELAY,
        machine_route: MACHINE_ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        root_fingerprint: binding.root_fingerprint,
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        enrollment_receipt_hash,
        purge_request_hash: request_hash,
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
        machine_route: MACHINE_ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        root_fingerprint: binding.root_fingerprint,
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        enrollment_receipt_hash,
        purge_request_hash: request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback,
        tombstone_hash: admin_purge_tombstone_hash(&tombstone).expect("tombstone hash"),
    };
    sign_relay_admin_purge_receipt(&signer, &verify_key, tbs).expect("sign root-lost purge receipt")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemoteSecurityRows {
    pairing_count: i64,
    receipt_count: i64,
    authorization_count: i64,
    authorization_preparing_count: i64,
    authorization_active_count: i64,
    authorization_superseded_count: i64,
    authorization_revoking_count: i64,
    authorization_revoked_count: i64,
    key_directory_count: i64,
    outbox_count: i64,
    outbox_prepared_count: i64,
    outbox_acknowledged_count: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemoteSecurityLedger {
    pairing_count: i64,
    pairing_sealed_bytes: i64,
    receipt_count: i64,
    receipt_bytes: i64,
    authorization_count: i64,
    authorization_preparing_count: i64,
    authorization_active_count: i64,
    authorization_revoking_count: i64,
    authorization_revoked_count: i64,
    authorization_sealed_bytes: i64,
    key_directory_count: i64,
    key_directory_sealed_bytes: i64,
    outbox_count: i64,
    outbox_pending_count: i64,
    outbox_acknowledged_count: i64,
    outbox_sealed_bytes: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResetBoundaryEvidence {
    lifecycle: String,
    reset_kind: Option<String>,
    sealed_state: Vec<u8>,
    remote_metadata_token: Vec<u8>,
    ledger_metadata_token: Vec<u8>,
    rows: RemoteSecurityRows,
    ledger: RemoteSecurityLedger,
}

fn reset_boundary_evidence(database: &Path) -> ResetBoundaryEvidence {
    let connection = Connection::open(database).expect("open reset evidence database");
    let remote = connection
        .query_row(
            "SELECT lifecycle, reset_kind, sealed_state, metadata_token
             FROM machine_remote_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read machine remote evidence");
    let (meta_token, ledger) = connection
        .query_row(
            "SELECT metadata_token,
                    remote_pairing_count, remote_pairing_sealed_bytes,
                    remote_pairing_receipt_count, remote_pairing_receipt_bytes,
                    remote_authorization_count, remote_authorization_preparing_count,
                    remote_authorization_active_count, remote_authorization_revoking_count,
                    remote_authorization_revoked_count, remote_authorization_sealed_bytes,
                    remote_key_directory_count, remote_key_directory_sealed_bytes,
                    remote_control_outbox_count, remote_control_outbox_pending_count,
                    remote_control_outbox_acknowledged_count,
                    remote_control_outbox_sealed_bytes
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    RemoteSecurityLedger {
                        pairing_count: row.get(1)?,
                        pairing_sealed_bytes: row.get(2)?,
                        receipt_count: row.get(3)?,
                        receipt_bytes: row.get(4)?,
                        authorization_count: row.get(5)?,
                        authorization_preparing_count: row.get(6)?,
                        authorization_active_count: row.get(7)?,
                        authorization_revoking_count: row.get(8)?,
                        authorization_revoked_count: row.get(9)?,
                        authorization_sealed_bytes: row.get(10)?,
                        key_directory_count: row.get(11)?,
                        key_directory_sealed_bytes: row.get(12)?,
                        outbox_count: row.get(13)?,
                        outbox_pending_count: row.get(14)?,
                        outbox_acknowledged_count: row.get(15)?,
                        outbox_sealed_bytes: row.get(16)?,
                    },
                ))
            },
        )
        .expect("read runtime ledger token");
    let rows = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM remote_pairings),
                    (SELECT COUNT(*) FROM remote_pairing_receipts),
                    (SELECT COUNT(*) FROM remote_authorization_ledger),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'grantPreparing'),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'active'),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'superseded'),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'revoking'),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'revoked'),
                    (SELECT COUNT(*) FROM remote_key_directory),
                    (SELECT COUNT(*) FROM remote_control_outbox),
                    (SELECT COUNT(*) FROM remote_control_outbox
                        WHERE lifecycle = 'prepared'),
                    (SELECT COUNT(*) FROM remote_control_outbox
                        WHERE lifecycle = 'acknowledged')",
            [],
            |row| {
                Ok(RemoteSecurityRows {
                    pairing_count: row.get(0)?,
                    receipt_count: row.get(1)?,
                    authorization_count: row.get(2)?,
                    authorization_preparing_count: row.get(3)?,
                    authorization_active_count: row.get(4)?,
                    authorization_superseded_count: row.get(5)?,
                    authorization_revoking_count: row.get(6)?,
                    authorization_revoked_count: row.get(7)?,
                    key_directory_count: row.get(8)?,
                    outbox_count: row.get(9)?,
                    outbox_prepared_count: row.get(10)?,
                    outbox_acknowledged_count: row.get(11)?,
                })
            },
        )
        .expect("read remote security row counts");
    ResetBoundaryEvidence {
        lifecycle: remote.0,
        reset_kind: remote.1,
        sealed_state: remote.2,
        remote_metadata_token: remote.3,
        ledger_metadata_token: meta_token,
        rows,
        ledger,
    }
}

fn assert_full_history(
    evidence: &ResetBoundaryEvidence,
    expected_active: i64,
    expected_revoked: i64,
) {
    assert_eq!(evidence.lifecycle, "active");
    assert_eq!(evidence.reset_kind, None);
    assert_eq!(
        evidence.rows,
        RemoteSecurityRows {
            pairing_count: 0,
            receipt_count: 2,
            authorization_count: 2,
            authorization_preparing_count: 0,
            authorization_active_count: expected_active,
            authorization_superseded_count: 1,
            authorization_revoking_count: 0,
            authorization_revoked_count: expected_revoked,
            key_directory_count: 1,
            outbox_count: 0,
            outbox_prepared_count: 0,
            outbox_acknowledged_count: 0,
        }
    );
    assert_eq!(evidence.ledger.pairing_count, 0);
    assert_eq!(evidence.ledger.pairing_sealed_bytes, 0);
    assert_eq!(evidence.ledger.receipt_count, 2);
    assert!(evidence.ledger.receipt_bytes > 0);
    assert_eq!(evidence.ledger.authorization_count, 2);
    assert_eq!(evidence.ledger.authorization_preparing_count, 0);
    assert_eq!(evidence.ledger.authorization_active_count, expected_active);
    assert_eq!(evidence.ledger.authorization_revoking_count, 0);
    assert_eq!(
        evidence.ledger.authorization_revoked_count,
        expected_revoked
    );
    assert!(evidence.ledger.authorization_sealed_bytes > 0);
    assert_eq!(evidence.ledger.key_directory_count, 1);
    assert!(evidence.ledger.key_directory_sealed_bytes > 0);
    assert_eq!(evidence.ledger.outbox_count, 0);
    assert_eq!(evidence.ledger.outbox_pending_count, 0);
    assert_eq!(evidence.ledger.outbox_acknowledged_count, 0);
    assert_eq!(evidence.ledger.outbox_sealed_bytes, 0);
}

fn assert_remote_security_cleaned(
    evidence: &ResetBoundaryEvidence,
    before: &ResetBoundaryEvidence,
    lifecycle: &str,
    reset_kind: &str,
) {
    assert_eq!(evidence.lifecycle, lifecycle);
    assert_eq!(evidence.reset_kind.as_deref(), Some(reset_kind));
    assert_ne!(evidence.sealed_state, before.sealed_state);
    assert_ne!(evidence.remote_metadata_token, before.remote_metadata_token);
    assert_ne!(evidence.ledger_metadata_token, before.ledger_metadata_token);
    assert_eq!(
        evidence.rows,
        RemoteSecurityRows {
            pairing_count: 0,
            receipt_count: before.rows.receipt_count,
            authorization_count: 0,
            authorization_preparing_count: 0,
            authorization_active_count: 0,
            authorization_superseded_count: 0,
            authorization_revoking_count: 0,
            authorization_revoked_count: 0,
            key_directory_count: 0,
            outbox_count: 0,
            outbox_prepared_count: 0,
            outbox_acknowledged_count: 0,
        }
    );
    assert_eq!(evidence.ledger.pairing_count, 0);
    assert_eq!(evidence.ledger.pairing_sealed_bytes, 0);
    assert_eq!(evidence.ledger.receipt_count, before.ledger.receipt_count);
    assert_eq!(evidence.ledger.receipt_bytes, before.ledger.receipt_bytes);
    assert_eq!(evidence.ledger.authorization_count, 0);
    assert_eq!(evidence.ledger.authorization_preparing_count, 0);
    assert_eq!(evidence.ledger.authorization_active_count, 0);
    assert_eq!(evidence.ledger.authorization_revoking_count, 0);
    assert_eq!(evidence.ledger.authorization_revoked_count, 0);
    assert_eq!(evidence.ledger.authorization_sealed_bytes, 0);
    assert_eq!(evidence.ledger.key_directory_count, 0);
    assert_eq!(evidence.ledger.key_directory_sealed_bytes, 0);
    assert_eq!(evidence.ledger.outbox_count, 0);
    assert_eq!(evidence.ledger.outbox_pending_count, 0);
    assert_eq!(evidence.ledger.outbox_acknowledged_count, 0);
    assert_eq!(evidence.ledger.outbox_sealed_bytes, 0);
}

fn assert_cleanup_fault(error: RuntimeStoreError, operation: RuntimeStoreOperation) {
    let expected_commit = match operation {
        RuntimeStoreOperation::PrepareMachineRetirementAfterCommit => {
            RuntimeCommitOperation::PrepareMachineRetirement
        }
        RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit => {
            RuntimeCommitOperation::RecordRootLostMachinePurge
        }
        RuntimeStoreOperation::PrepareMachineRetirementBeforeCommit
        | RuntimeStoreOperation::RecordRootLostMachinePurgeBeforeCommit => {
            assert!(matches!(error, RuntimeStoreError::WorkerStopped));
            return;
        }
        other => panic!("unexpected reset cleanup fault operation: {other:?}"),
    };
    assert!(matches!(
        error,
        RuntimeStoreError::CommitOutcomeUnknown { operation }
            if operation == expected_commit
    ));
}

#[tokio::test]
async fn root_present_full_history_cleanup_restarts_before_exact_commit_retry() {
    for operation in [
        RuntimeStoreOperation::PrepareMachineRetirementBeforeCommit,
        RuntimeStoreOperation::PrepareMachineRetirementAfterCommit,
    ] {
        let root = TestRoot::new();
        let keys = Arc::new(MemoryKeyStore::new());
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let binding = binding();
        let setup = open_store_with_clock_and_fault(&root, &keys, clock.clone(), None).await;
        let _ = make_active(&setup, &binding).await;
        let current = prepare_full_grant_history(&setup, &binding, &clock).await;
        revoke_current_grant(&setup, &binding, &clock, &current).await;
        let before = reset_boundary_evidence(&root.database());
        assert_full_history(&before, 0, 1);
        let reset = retirement(&binding);
        setup.shutdown().await.expect("shutdown root-present setup");

        let faulted = open_store_with_clock_and_fault(
            &root,
            &keys,
            clock.clone(),
            Some(Arc::new(OneShotFault::new(operation))),
        )
        .await;
        let error = faulted
            .prepare_machine_retirement(reset.clone())
            .await
            .expect_err("inject root-present cleanup fault");
        assert_cleanup_fault(error, operation);
        faulted
            .shutdown()
            .await
            .expect("stop immediately after root-present fault");

        let restarted = open_store_with_clock_and_fault(&root, &keys, clock.clone(), None).await;
        let after_restart = reset_boundary_evidence(&root.database());
        let committed = operation == RuntimeStoreOperation::PrepareMachineRetirementAfterCommit;
        if committed {
            assert_remote_security_cleaned(&after_restart, &before, "retirePending", "rootPresent");
        } else {
            assert_eq!(after_restart, before);
        }
        restarted
            .prepare_machine_retirement(reset.clone())
            .await
            .expect("exact root-present retry after restart");
        let after_retry = reset_boundary_evidence(&root.database());
        assert_remote_security_cleaned(&after_retry, &before, "retirePending", "rootPresent");
        if committed {
            assert_eq!(after_retry, after_restart);
        }
        restarted
            .shutdown()
            .await
            .expect("shutdown root-present retry store");

        let final_reopen = open_store_with_clock_and_fault(&root, &keys, clock.clone(), None).await;
        let before_final_replay = reset_boundary_evidence(&root.database());
        final_reopen
            .prepare_machine_retirement(reset)
            .await
            .expect("replay root-present cleanup after second restart");
        assert_eq!(
            reset_boundary_evidence(&root.database()),
            before_final_replay
        );
        final_reopen
            .shutdown()
            .await
            .expect("shutdown final root-present reopen");
    }
}

#[tokio::test]
async fn root_lost_full_history_cleanup_restarts_before_exact_commit_retry() {
    for operation in [
        RuntimeStoreOperation::RecordRootLostMachinePurgeBeforeCommit,
        RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit,
    ] {
        let root = TestRoot::new();
        let keys = Arc::new(MemoryKeyStore::new());
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let binding = binding();
        let setup = open_store_with_clock_and_fault(&root, &keys, clock.clone(), None).await;
        let enrollment_receipt_hash = make_active(&setup, &binding).await;
        let _ = prepare_full_grant_history(&setup, &binding, &clock).await;
        let before = reset_boundary_evidence(&root.database());
        assert_full_history(&before, 1, 0);
        let receipt = root_lost_receipt(&binding, enrollment_receipt_hash);
        setup.shutdown().await.expect("shutdown root-lost setup");

        let faulted = open_store_with_clock_and_fault(
            &root,
            &keys,
            clock.clone(),
            Some(Arc::new(OneShotFault::new(operation))),
        )
        .await;
        let error = faulted
            .record_root_lost_machine_purge(receipt.clone())
            .await
            .expect_err("inject root-lost full-history cleanup fault");
        assert_cleanup_fault(error, operation);
        faulted
            .shutdown()
            .await
            .expect("stop immediately after root-lost fault");

        let restarted = open_store_with_clock_and_fault(&root, &keys, clock.clone(), None).await;
        let after_restart = reset_boundary_evidence(&root.database());
        let committed = operation == RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit;
        if committed {
            assert_remote_security_cleaned(
                &after_restart,
                &before,
                "purgeReadbackAbsent",
                "rootLost",
            );
        } else {
            assert_eq!(after_restart, before);
        }
        restarted
            .record_root_lost_machine_purge(receipt.clone())
            .await
            .expect("exact root-lost retry after restart");
        let after_retry = reset_boundary_evidence(&root.database());
        assert_remote_security_cleaned(&after_retry, &before, "purgeReadbackAbsent", "rootLost");
        if committed {
            assert_eq!(after_retry, after_restart);
        }
        restarted
            .shutdown()
            .await
            .expect("shutdown root-lost retry store");

        let final_reopen = open_store_with_clock_and_fault(&root, &keys, clock.clone(), None).await;
        let before_final_replay = reset_boundary_evidence(&root.database());
        final_reopen
            .record_root_lost_machine_purge(receipt)
            .await
            .expect("replay root-lost cleanup after second restart");
        assert_eq!(
            reset_boundary_evidence(&root.database()),
            before_final_replay
        );
        final_reopen
            .shutdown()
            .await
            .expect("shutdown final root-lost reopen");
    }
}

#[tokio::test]
async fn active_pairing_blocks_root_present_but_valid_root_lost_receipt_scrubs_it_atomically() {
    let root = TestRoot::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let binding = binding();
    let store = open_store(&root, &keys).await;
    let enrollment_receipt_hash = make_active(&store, &binding).await;
    let _ = prepare_active_pairing(&store, &binding).await;

    let before = reset_boundary_evidence(&root.database());
    assert_eq!(before.lifecycle, "active");
    assert_eq!(
        (before.rows.pairing_count, before.rows.outbox_count),
        (1, 1)
    );
    assert!(matches!(
        store.prepare_machine_retirement(retirement(&binding)).await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    assert_eq!(
        reset_boundary_evidence(&root.database()),
        before,
        "root-present rejection must be a zero-write boundary"
    );
    store
        .record_root_lost_machine_purge(root_lost_receipt(&binding, enrollment_receipt_hash))
        .await
        .expect("valid absent receipt atomically scrubs root-lost remote state");
    let after = reset_boundary_evidence(&root.database());
    assert_eq!(after.lifecycle, "purgeReadbackAbsent");
    assert_eq!((after.rows.pairing_count, after.rows.outbox_count), (0, 0));
    assert_ne!(after.remote_metadata_token, before.remote_metadata_token);
    assert_ne!(after.ledger_metadata_token, before.ledger_metadata_token);
    assert!(matches!(
        store
            .load_machine_enrollment_state()
            .await
            .expect("load state after root-lost cleanup"),
        Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
    ));
    store.shutdown().await.expect("shutdown guarded store");

    let reopened = open_store(&root, &keys).await;
    let recovery = reopened
        .list_pairing_recovery()
        .await
        .expect("load durable pairing cleanup material");
    assert!(recovery.is_empty());
    assert_eq!(reset_boundary_evidence(&root.database()), after);
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn root_lost_pairing_cleanup_is_atomic_across_commit_faults_and_exact_retry() {
    for operation in [
        RuntimeStoreOperation::RecordRootLostMachinePurgeBeforeCommit,
        RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit,
    ] {
        let root = TestRoot::new();
        let keys = Arc::new(MemoryKeyStore::new());
        let binding = binding();
        let store = open_store(&root, &keys).await;
        let enrollment_receipt_hash = make_active(&store, &binding).await;
        let _ = prepare_active_pairing(&store, &binding).await;
        let receipt = root_lost_receipt(&binding, enrollment_receipt_hash);
        let before = reset_boundary_evidence(&root.database());
        store
            .shutdown()
            .await
            .expect("shutdown before fault reopen");

        let fault = Arc::new(OneShotFault::new(operation));
        let store = open_store_with_fault(&root, &keys, Some(fault)).await;
        let error = store
            .record_root_lost_machine_purge(receipt.clone())
            .await
            .expect_err("injected root-lost cleanup fault");
        match operation {
            RuntimeStoreOperation::RecordRootLostMachinePurgeBeforeCommit => {
                assert!(matches!(error, RuntimeStoreError::WorkerStopped));
                assert_eq!(
                    reset_boundary_evidence(&root.database()),
                    before,
                    "before-COMMIT cleanup fault must roll back lifecycle, rows, and ledger"
                );
            }
            RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit => {
                assert!(matches!(
                    error,
                    RuntimeStoreError::CommitOutcomeUnknown {
                        operation: RuntimeCommitOperation::RecordRootLostMachinePurge
                    }
                ));
                let after_unknown = reset_boundary_evidence(&root.database());
                assert_eq!(after_unknown.lifecycle, "purgeReadbackAbsent");
                assert_eq!(
                    (
                        after_unknown.rows.pairing_count,
                        after_unknown.rows.outbox_count,
                    ),
                    (0, 0)
                );
            }
            _ => unreachable!("fixed root-lost fault matrix"),
        }

        store
            .record_root_lost_machine_purge(receipt)
            .await
            .expect("exact retry converges after either commit boundary");
        let after_retry = reset_boundary_evidence(&root.database());
        assert_eq!(after_retry.lifecycle, "purgeReadbackAbsent");
        assert_eq!(
            (
                after_retry.rows.pairing_count,
                after_retry.rows.outbox_count,
            ),
            (0, 0)
        );
        store.shutdown().await.expect("shutdown after exact retry");

        let reopened = open_store(&root, &keys).await;
        assert!(
            reopened
                .list_pairing_recovery()
                .await
                .expect("read post-reset recovery")
                .is_empty()
        );
        assert!(matches!(
            reopened
                .load_machine_enrollment_state()
                .await
                .expect("read post-reset lifecycle"),
            Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
        ));
        reopened.shutdown().await.expect("shutdown final reopen");
    }
}

#[tokio::test]
async fn terminal_pairing_blocks_root_present_but_root_lost_scrubs_and_retains_receipt() {
    let root = TestRoot::new();
    let keys = Arc::new(MemoryKeyStore::new());
    let binding = binding();
    let store = open_store(&root, &keys).await;
    let enrollment_receipt_hash = make_active(&store, &binding).await;
    let (pairing_id, _pair_route) = prepare_active_pairing(&store, &binding).await;
    store
        .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
        .await
        .expect("terminalize pairing before trust reset");

    let before_close_ack = reset_boundary_evidence(&root.database());
    assert_eq!(
        (
            before_close_ack.rows.pairing_count,
            before_close_ack.rows.outbox_count
        ),
        (1, 1)
    );
    assert!(matches!(
        store.prepare_machine_retirement(retirement(&binding)).await,
        Err(RuntimeStoreError::MachineRemoteConflict)
    ));
    assert_eq!(reset_boundary_evidence(&root.database()), before_close_ack);

    store
        .record_root_lost_machine_purge(root_lost_receipt(&binding, enrollment_receipt_hash))
        .await
        .expect("root-lost absent receipt supersedes pair-route close delivery");
    let after_cleanup = reset_boundary_evidence(&root.database());
    assert_eq!(
        (
            after_cleanup.rows.pairing_count,
            after_cleanup.rows.outbox_count,
        ),
        (0, 0)
    );
    let connection = Connection::open(root.database()).expect("open receipt evidence database");
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM remote_pairing_receipts", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("count receipt tombstone"),
        1
    );
    drop(connection);

    assert!(matches!(
        store
            .load_machine_enrollment_state()
            .await
            .expect("load reset state"),
        Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
    ));
    store
        .shutdown()
        .await
        .expect("shutdown reset-after-close store");
}
