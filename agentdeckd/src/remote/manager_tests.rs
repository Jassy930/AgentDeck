use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{
    HpkePrivateKey, SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256,
    sign_relay_admin_purge_receipt,
};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose, PairInviteV1};
use agentdeck_protocol::relay_v2::failure::RelayFailure;
use agentdeck_protocol::relay_v2::frame::{RelayFrameBody, RetirementCommitted};
use agentdeck_protocol::relay_v2::{
    Digest32, ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, EnrollmentCode,
    MachineEnrollmentResponseV1, MachineRouteId, OpaqueRouteFrame, PairRouteId, PublicKeyBytes,
    RELAY_PROTOCOL_VERSION, RELAY_RECEIPT_FORMAT_VERSION, RELAY_RECEIPT_KEY_GENERATION_MVP,
    RelayAdminPurgeReadbackV1, RelayAdminPurgeReceiptTbsV1, RelayAdminPurgeReceiptV1,
    RelayAdminPurgeTombstoneV1, RelayMachineTombstoneKindV1, RelayServerId, RootKeyId, TrustEpoch,
    admin_purge_tombstone_hash, encode, enrollment_receipt_hash, purge_request_hash,
};
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial};
use agentdeck_protocol::runtime::{
    ArtifactSha256, LocalOnlyAdministration, MachineEnrollRequest,
    MachineRemoteLifecycle as WireLifecycle, RevocationReceipt, TrustResetRequest,
    UninstallPurgePlanV1,
};
use agentdeck_relay_client::{RelayClientConfig, RelayClientError};

use crate::config::{DaemonConfig, DaemonStartupOptions};
use crate::local::listener::remote_start_permit_for_test;
use crate::purge_finalizer::AuthenticatedPurgeAuthorization;
use crate::remote::bootstrap::{
    RemoteBootstrapOutcome, machine_pairing_anchor_for_test, reconcile_machine_identity,
};
use crate::remote::cleanup::MachineCleanupWorkflow;
use crate::remote::config::ValidatedEnrollmentConfig;
use crate::remote::enrollment::FrozenMachineEnrollment;
use crate::remote::identity::{
    KEY_DIRECTORY_GUARD_ACCOUNT, MACHINE_DATA_SIGN_ACCOUNT, MACHINE_HPKE_ACCOUNT,
    MACHINE_LINK_SIGN_ACCOUNT, MACHINE_ROOT_SIGN_ACCOUNT,
};
use crate::remote::workflow::{EnrollmentEndpoint, MachineEnrollmentWorkflow};
use crate::runtime::remote_administration::RemoteAdministration;
use crate::runtime::store::IdempotencyOwner;
use crate::runtime::store::pairing::{PreparePairingInvite, PreparePairingInviteOutcome};
use crate::runtime::store::{
    ActiveMachineEnrollmentState, LocalDeletedMachineEnrollmentState, MachineEnrollmentState,
    MachineRemoteLifecycle, MachineRemoteStateRecord, MachineTrustResetKind,
    PublicationPayloadKind, PublicationScope, RuntimeStoreConfig, RuntimeStoreHandle,
    active_authorization_store_for_test,
};
use crate::runtime::{PairingAdministration, RevocationAdministration};
use crate::security::{KeyStore, MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

use super::{
    PurgePlanSink, PurgeReservationResume, REMOTE_DISABLED, REMOTE_SHUTTING_DOWN, RemoteManager,
    admin_error, record_pairing_start_failure, require_pairing_owner_after_enroll,
    status_from_state,
};

fn record(lifecycle: MachineRemoteLifecycle) -> MachineRemoteStateRecord {
    MachineRemoteStateRecord {
        lifecycle,
        relay_server_id: [0x11; 16],
        machine_route: [0x22; 16],
        root_key_id: [0x33; 16],
        root_fingerprint: [0x44; 32],
        trust_epoch: 1,
        request_hash: [0x55; 32],
        response_hash: Some([0x66; 32]),
        enrollment_receipt_hash: Some([0x77; 32]),
        receipt_verify_key_hash: [0x88; 32],
        sealed_state_bytes: 64,
    }
}

fn local_deleted() -> MachineEnrollmentState {
    MachineEnrollmentState::LocalDeleted(Box::new(LocalDeletedMachineEnrollmentState {
        record: record(MachineRemoteLifecycle::LocalDeleted),
        reset_kind: MachineTrustResetKind::RootPresent,
        previous_prepare_input_hash: [0x91; 32],
        purge_proof_hash: [0x92; 32],
        cleanup_witness_hash: [0x93; 32],
    }))
}

struct ManagerFixture {
    root: PathBuf,
    keys: Arc<MemoryKeyStore>,
    store: RuntimeStoreHandle,
    config: DaemonConfig,
    bundle: EnrollmentBundleV2,
    identity: Option<Box<crate::remote::bootstrap::ActiveMachineIdentity>>,
}

async fn active_fixture(label: &str) -> ManagerFixture {
    enrollment_fixture(label, FixtureEnrollmentStage::Active).await
}

async fn unenrolled_fixture(label: &str) -> ManagerFixture {
    enrollment_fixture(label, FixtureEnrollmentStage::Unenrolled).await
}

#[derive(Clone, Copy)]
enum FixtureEnrollmentStage {
    Unenrolled,
    Prepared,
    Validated,
    Active,
}

async fn enrollment_fixture(label: &str, stage: FixtureEnrollmentStage) -> ManagerFixture {
    enrollment_fixture_with_expiry(label, stage, u64::MAX).await
}

async fn enrollment_fixture_with_expiry(
    label: &str,
    stage: FixtureEnrollmentStage,
    expires_at_ms: u64,
) -> ManagerFixture {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let root = Path::new("/tmp").join(format!("adm-{}-{}", label, &suffix[..8]));
    fs::create_dir(&root).expect("create manager fixture root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure manager fixture root");
    }
    let keys = Arc::new(MemoryKeyStore::new());
    let database = root.join("runtime.db");
    let kek = load_or_create_storage_kek(keys.as_ref(), &database).expect("create fixture KEK");
    let store = RuntimeStoreHandle::open(RuntimeStoreConfig::new(database.clone()), kek)
        .await
        .expect("open manager fixture Store");
    let home = root.join("h");
    fs::create_dir_all(home.join("Library/Application Support"))
        .expect("create manager fixture home");
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
        &root,
    )
    .expect("resolve manager stable config");
    let identity = match reconcile_machine_identity(&config, &store, keys.as_ref())
        .await
        .expect("bootstrap manager identity")
    {
        RemoteBootstrapOutcome::Active(identity) => identity,
        other => panic!("expected active identity, got {other:?}"),
    };

    let relay = RelayServerId::from_bytes([0x31; 16]);
    let receipt_signer = SigningKey::from_seed(&[0x32; 32]);
    let receipt_verify_key =
        ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&receipt_signer)
            .expect("valid receipt signer")
            .bind_to_relay(relay)
            .expect("bind receipt signer")
            .wire_anchor()
            .clone();
    let bundle = EnrollmentBundleV2 {
        version: ENROLLMENT_BUNDLE_VERSION,
        public_wss_url: "wss://127.0.0.1:9/".to_owned(),
        relay_server_id: relay,
        receipt_verify_key,
        code: EnrollmentCode([0x33; 32]),
        spki_pins: vec![Digest32([0x34; 32])],
        expires_at_ms,
    };
    if !matches!(stage, FixtureEnrollmentStage::Unenrolled) {
        let enrollment = FrozenMachineEnrollment::new(
            ValidatedEnrollmentConfig::new(bundle.clone(), 1)
                .expect("validate manager enrollment config"),
            &identity,
        )
        .expect("freeze manager enrollment");
        let parts = enrollment.into_parts();
        let route = parts.machine_route;
        let trust_epoch = parts.trust_epoch;
        let request_hash = parts.request_hash;
        store
            .prepare_machine_enrollment(
                parts.bundle,
                route,
                parts.binding,
                parts.link_certificate,
                parts.data_certificate,
            )
            .await
            .expect("prepare manager enrollment");
        if matches!(
            stage,
            FixtureEnrollmentStage::Validated | FixtureEnrollmentStage::Active
        ) {
            let receipt_hash = enrollment_receipt_hash(relay, route, trust_epoch, request_hash);
            let response =
                MachineEnrollmentResponseV1::new(relay, route, trust_epoch, receipt_hash)
                    .expect("build manager enrollment response");
            let response_hash = response.canonical_sha256().expect("hash manager response");
            store
                .record_validated_enrollment_response(request_hash, response)
                .await
                .expect("record manager enrollment response");
            if matches!(stage, FixtureEnrollmentStage::Active) {
                store
                    .activate_machine_enrollment(request_hash, response_hash)
                    .await
                    .expect("activate manager enrollment");
            }
        }
    }

    ManagerFixture {
        root,
        keys,
        store,
        config,
        bundle,
        identity: Some(identity),
    }
}

#[derive(Clone, Default)]
struct CountingEnrollmentEndpoint {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl EnrollmentEndpoint for CountingEnrollmentEndpoint {
    async fn enroll(
        &self,
        _config: RelayClientConfig,
        _request: agentdeck_protocol::relay_v2::MachineEnrollmentRequestV1,
    ) -> Result<MachineEnrollmentResponseV1, RelayClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(RelayClientError::Failure {
            code: "test.enrollment.endpoint_called".to_owned(),
        })
    }
}

async fn active_state(store: &RuntimeStoreHandle) -> Box<ActiveMachineEnrollmentState> {
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load active manager state")
    else {
        panic!("expected active manager state")
    };
    active
}

async fn business_start_authority(
    fixture: &ManagerFixture,
) -> (
    crate::remote::transport::MachineDataAuthority,
    crate::remote::transport::tests::MachineDataAuthorityOwnerLease,
    MachineRouteId,
) {
    let active = active_state(&fixture.store).await;
    let secret = fixture
        .keys
        .load(MACHINE_DATA_SIGN_ACCOUNT)
        .expect("load manager MachineDataSign seed")
        .expect("manager fixture keeps MachineDataSign seed");
    let seed: [u8; 32] = secret
        .expose_secret()
        .try_into()
        .expect("MachineDataSign seed is exactly 32 bytes");
    let machine_route = MachineRouteId::from_bytes(active.record.machine_route);
    let (authority, owner) =
        crate::remote::transport::tests::machine_data_authority_for_transition_test(
            machine_pairing_anchor_for_test(
                active.connection.relay_server_id,
                machine_route,
                &active.binding,
                active.data_cert.clone(),
            ),
            seed,
        );
    (authority, owner, machine_route)
}

fn portable_admin_purge_receipt(active: &ActiveMachineEnrollmentState) -> RelayAdminPurgeReceiptV1 {
    let relay = active.connection.relay_server_id;
    let route = MachineRouteId::from_bytes(active.record.machine_route);
    let root_key_id = RootKeyId::from_bytes(active.binding.root_key_id);
    let trust_epoch = TrustEpoch::new(active.binding.trust_epoch);
    let enrollment_receipt_hash = active
        .record
        .enrollment_receipt_hash
        .expect("active enrollment receipt hash");
    let signer = SigningKey::from_seed(&[0x32; 32]);
    let verify_key = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signer)
        .expect("valid manager receipt signer")
        .bind_to_relay(relay)
        .expect("bind manager receipt signer");
    assert_eq!(
        verify_key.wire_anchor(),
        &active.connection.receipt_verify_key
    );
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
    let request_hash = purge_request_hash(route, active.binding.root_fingerprint)
        .expect("manager purge request hash");
    let tombstone = RelayAdminPurgeTombstoneV1 {
        relay_server_id: relay,
        machine_route: route,
        root_key_id,
        root_fingerprint: active.binding.root_fingerprint,
        trust_epoch,
        enrollment_receipt_hash,
        purge_request_hash: request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback: readback.clone(),
    };
    let tbs = RelayAdminPurgeReceiptTbsV1 {
        receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        relay_server_id: relay,
        receipt_key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
        receipt_key_id: verify_key.wire_anchor().key_id,
        machine_route: route,
        root_key_id,
        root_fingerprint: active.binding.root_fingerprint,
        trust_epoch,
        enrollment_receipt_hash,
        purge_request_hash: request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback,
        tombstone_hash: admin_purge_tombstone_hash(&tombstone)
            .expect("manager purge tombstone hash"),
    };
    sign_relay_admin_purge_receipt(&signer, &verify_key, tbs)
        .expect("sign manager portable purge receipt")
}

async fn seed_open_pairing_recovery(
    store: &RuntimeStoreHandle,
    active: &ActiveMachineEnrollmentState,
) {
    let private_bytes = [0x71; 32];
    let private = HpkePrivateKey::from_bytes(&private_bytes).expect("valid manager test HPKE key");
    let public: [u8; 32] = private
        .public_key()
        .to_bytes()
        .try_into()
        .expect("X25519 public key is 32 bytes");
    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("manager test clock after epoch")
            .as_millis(),
    )
    .expect("manager test clock fits u64");
    let current_pin = active
        .connection
        .spki_pins
        .first()
        .expect("active enrollment has a pin")
        .0;
    let next_pin = active
        .connection
        .spki_pins
        .get(1)
        .map_or(current_pin, |pin| pin.0);
    let invite = PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        pair_route: PairRouteId::from_bytes([0x72; 16]),
        invite_secret: [0x73; 32],
        invite_hpke_pubkey: PublicKeyBytes(public),
        wss_url: active.connection.public_wss_url.clone(),
        relay_server_id: active.connection.relay_server_id,
        current_spki_pin: current_pin,
        next_spki_pin: next_pin,
        expires_at_ms: now_ms + 300_000,
        machine_root_pubkey: PublicKeyBytes(active.binding.root_public_key),
        machine_root_fingerprint: active.binding.root_fingerprint,
        data_sign_cert: active.data_cert.clone(),
        machine_display_name: "root-lost-pairing".to_owned(),
    }
    .canonical_bytes()
    .expect("canonical manager PairInvite");
    let outcome = store
        .prepare_pairing_invite(PreparePairingInvite::new(
            IdempotencyOwner::Local {
                machine_trust_domain: active.binding.root_fingerprint,
                uid: 501,
                client_installation_id: [0x74; 16],
            },
            "root-lost-pairing".to_owned(),
            SecretBytes::new(invite),
            SecretBytes::new(private_bytes.to_vec()),
        ))
        .await
        .expect("seed durable PairRoute open recovery");
    assert!(matches!(
        outcome,
        PreparePairingInviteOutcome::Prepared { .. }
    ));
}

async fn prepare_retirement(fixture: &ManagerFixture) {
    let active = active_state(&fixture.store).await;
    let frozen = fixture
        .identity
        .as_ref()
        .expect("fixture identity")
        .freeze_retirement(
            active.connection.relay_server_id,
            agentdeck_protocol::relay_v2::MachineRouteId::from_bytes(active.record.machine_route),
            active.record.trust_epoch,
        )
        .expect("freeze fixture retirement");
    fixture
        .store
        .prepare_machine_retirement(frozen.retirement().clone())
        .await
        .expect("prepare fixture retirement");
}

async fn record_retirement_terminal(store: &RuntimeStoreHandle) -> (Vec<u8>, [u8; 32]) {
    let Some(MachineEnrollmentState::RetirePending(pending)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load pending retirement")
    else {
        panic!("expected pending retirement")
    };
    let committed = RetirementCommitted {
        machine_route: pending.retirement.retirement.machine_route,
        trust_epoch: pending.retirement.retirement.trust_epoch,
        retire_hash: pending.retirement.canonical_hash,
    };
    let bytes = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RetirementCommitted(committed),
    });
    let hash = sha256(&bytes);
    store
        .record_machine_retirement_terminal(bytes.clone(), hash)
        .await
        .expect("record retirement terminal");
    (bytes, hash)
}

async fn advance_to_purge_absent(fixture: &ManagerFixture) {
    prepare_retirement(fixture).await;
    let (bytes, hash) = record_retirement_terminal(&fixture.store).await;
    fixture
        .store
        .confirm_machine_purge_readback_absent(bytes, hash)
        .await
        .expect("confirm local Relay purge proof");
}

async fn advance_to_local_deleted(fixture: &mut ManagerFixture) {
    advance_to_purge_absent(fixture).await;
    drop(fixture.identity.take());
    MachineCleanupWorkflow::new()
        .run(&fixture.store, fixture.keys.as_ref(), None)
        .await
        .expect("finalize fixture LocalDeleted");
}

async fn finish_fixture(manager: RemoteManager, fixture: ManagerFixture) {
    manager.shutdown().await;
    drop(manager);
    fixture
        .store
        .shutdown()
        .await
        .expect("shutdown manager fixture Store");
    let _ = fs::remove_dir_all(fixture.root);
}

async fn install_yielded_test_transport(
    manager: &RemoteManager,
) -> (
    crate::remote::transport::PairingTransportLane,
    Arc<crate::remote::transport::RemoteTransportTestHarness>,
) {
    let durable = manager
        .store
        .load_machine_enrollment_state()
        .await
        .expect("load test transport route")
        .expect("test transport requires durable machine state");
    let machine_route = MachineRouteId::from_bytes(match durable {
        MachineEnrollmentState::Active(active) => active.record.machine_route,
        MachineEnrollmentState::RetirePending(pending) => pending.record.machine_route,
        _ => panic!("test transport requires Active or RetirePending"),
    });
    let (transport, mut lane, harness) =
        crate::remote::transport::active_pairing_transport_for_test(machine_route);
    lane.yield_shared_control()
        .expect("fake completed drain yields shared control before manager workflow");
    manager.state.lock().await.transport = Some(transport);
    (lane, harness)
}

async fn finish_split_store_fixture(
    manager: RemoteManager,
    authorization_store: RuntimeStoreHandle,
    fixture: ManagerFixture,
) {
    manager.shutdown().await;
    drop(manager);
    authorization_store
        .shutdown()
        .await
        .expect("shutdown authorization-only Store");
    fixture
        .store
        .shutdown()
        .await
        .expect("shutdown identity fixture Store");
    let _ = fs::remove_dir_all(fixture.root);
}

#[test]
fn recover_pending_offline_never_releases_remote_link_admission() {
    let mut admission = super::RemoteBusinessAdmission::new();
    admission
        .observe_counter_audit(Ok(()))
        .expect("sender counters audited");
    admission
        .observe_transition_readiness(Ok(
            crate::remote::transition_owner::TransitionReadiness::NoActiveTransition,
        ))
        .expect("transition is business-ready before pending recovery");
    let error = admission
        .observe_publication_recovery(Err(
            crate::remote::publication_transport::PublicationDriveError::RecoveryOffline,
        ))
        .expect_err("offline frozen outbox must keep link fenced");
    assert_eq!(error.code(), "daemon.remote.publication.recovery_offline");
    assert_eq!(
        admission.phase,
        super::RemoteBusinessAdmissionPhase::TransitionReady
    );
    assert_eq!(
        admission
            .into_permit()
            .expect_err("link permit stays absent")
            .code(),
        "daemon.remote.link.admission_fenced"
    );
}

#[test]
fn transition_failure_after_counter_audit_never_releases_remote_link_admission() {
    let mut admission = super::RemoteBusinessAdmission::new();
    admission
        .observe_counter_audit(Ok(()))
        .expect("sender counters audited");
    let error = admission
        .observe_transition_readiness(Err(admin_error(
            "daemon.remote.transition.advance_exhausted",
        )))
        .expect_err("non-ready transition keeps link fenced");
    assert_eq!(error.code(), "daemon.remote.transition.advance_exhausted");
    assert_eq!(
        admission.phase,
        super::RemoteBusinessAdmissionPhase::CounterAudited
    );
    assert_eq!(
        admission
            .into_permit()
            .expect_err("link permit stays absent")
            .code(),
        "daemon.remote.link.admission_fenced"
    );
}

#[test]
fn control_plane_readiness_never_mints_a_business_ready_link_permit() {
    let mut admission = super::RemoteBusinessAdmission::new();
    admission
        .observe_counter_audit(Ok(()))
        .expect("sender counters audited");
    admission
        .observe_transition_readiness(Ok(
            crate::remote::transition_owner::TransitionReadiness::ControlPlaneReady {
                barrier_count: 2,
            },
        ))
        .expect("control plane may proceed to exact pending recovery");
    admission
        .observe_publication_recovery(Ok(()))
        .expect("frozen publication directory is recovered before opening control ingress");
    let permit = admission
        .into_permit()
        .expect("control-plane RemoteLink still needs an explicit typed permit");
    assert_eq!(
        permit.mode,
        super::RemoteLinkAdmissionMode::ControlPlaneOnly,
        "BarriersCommitted without required ACK must not be mislabeled business-ready"
    );
}

#[test]
fn remote_link_admission_requires_counter_audit_transition_then_pending_recovery() {
    let mut admission = super::RemoteBusinessAdmission::new();
    assert_eq!(
        admission
            .observe_transition_readiness(Ok(
                crate::remote::transition_owner::TransitionReadiness::NoActiveTransition,
            ))
            .expect_err("transition cannot skip counter audit")
            .code(),
        super::REMOTE_STATE_CONFLICT
    );
    admission
        .observe_counter_audit(Ok(()))
        .expect("counter audit advances exact phase");
    assert_eq!(
        admission
            .observe_publication_recovery(Ok(()))
            .expect_err("publication recovery cannot skip transition readiness")
            .code(),
        super::REMOTE_STATE_CONFLICT
    );
    admission
        .observe_transition_readiness(Ok(
            crate::remote::transition_owner::TransitionReadiness::BusinessReady {
                barrier_count: 2,
            },
        ))
        .expect("business-ready transition advances exact phase");
    admission
        .observe_publication_recovery(Ok(()))
        .expect("pending recovery advances final admission phase");
    admission
        .into_permit()
        .expect("only exact ordered gates release link admission");
}

struct RecordingLinkOwner {
    order: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

struct FailedLinkOwner;

struct LifecycleRecordingLinkOwner {
    store: RuntimeStoreHandle,
    observed: Arc<std::sync::Mutex<Vec<(&'static str, &'static str)>>>,
}

#[async_trait::async_trait]
impl super::ManagedRemoteLinkOwner for RecordingLinkOwner {
    async fn shutdown(&mut self) -> Result<(), crate::remote::link::RemoteLinkError> {
        self.order
            .lock()
            .expect("record link shutdown")
            .push("link");
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::ManagedRemoteLinkOwner for FailedLinkOwner {
    async fn shutdown(&mut self) -> Result<(), crate::remote::link::RemoteLinkError> {
        Ok(())
    }

    fn observed_failure_code(&self) -> Option<String> {
        Some("daemon.remote.link.actor_exited".to_owned())
    }
}

#[async_trait::async_trait]
impl super::ManagedRemoteLinkOwner for LifecycleRecordingLinkOwner {
    async fn shutdown(&mut self) -> Result<(), crate::remote::link::RemoteLinkError> {
        let lifecycle = observed_machine_lifecycle(&self.store).await;
        self.observed
            .lock()
            .expect("record link lifecycle")
            .push(("link", lifecycle));
        Ok(())
    }
}

struct RecordingTransitionOwner {
    order: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

struct LifecycleRecordingTransitionOwner {
    store: RuntimeStoreHandle,
    observed: Arc<std::sync::Mutex<Vec<(&'static str, &'static str)>>>,
}

struct FailingTransitionShutdownOwner;

struct FailedTransitionHealthOwner;

struct RecordingMaintenanceOwner {
    order: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

struct LifecycleRecordingMaintenanceOwner {
    store: RuntimeStoreHandle,
    observed: Arc<std::sync::Mutex<Vec<(&'static str, &'static str)>>>,
}

#[derive(Default)]
struct ReadyTransitionHandle {
    calls: AtomicUsize,
}

struct FailingTransitionHandle;

#[derive(Default)]
struct PendingTransitionHandle {
    requests: AtomicUsize,
}

struct ControlThenReadyTransitionHandle {
    calls: AtomicUsize,
    progress_tx: tokio::sync::watch::Sender<crate::remote::transition_owner::TransitionProgress>,
}

struct ControlOnlyTransitionHandle {
    calls: AtomicUsize,
    progress_tx: tokio::sync::watch::Sender<crate::remote::transition_owner::TransitionProgress>,
}

struct ProgressPendingThenReadyTransitionHandle {
    calls: AtomicUsize,
    progress_tx: tokio::sync::watch::Sender<crate::remote::transition_owner::TransitionProgress>,
}

struct StaleReadyPendingTransitionHandle {
    calls: AtomicUsize,
    progress_tx: tokio::sync::watch::Sender<crate::remote::transition_owner::TransitionProgress>,
}

struct StaleReadyTerminalTransitionHandle {
    progress_tx: tokio::sync::watch::Sender<crate::remote::transition_owner::TransitionProgress>,
}

struct StaleReadyReconnectPendingTransitionHandle {
    calls: AtomicUsize,
    progress_tx: tokio::sync::watch::Sender<crate::remote::transition_owner::TransitionProgress>,
}

struct StaleReadyRetryableStoreTransitionHandle {
    calls: AtomicUsize,
    progress_tx: tokio::sync::watch::Sender<crate::remote::transition_owner::TransitionProgress>,
}

impl Default for ControlThenReadyTransitionHandle {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            progress_tx: tokio::sync::watch::channel(
                crate::remote::transition_owner::TransitionProgress::Idle,
            )
            .0,
        }
    }
}

impl ControlThenReadyTransitionHandle {
    fn publish_business_ready(&self) {
        self.progress_tx
            .send_replace(crate::remote::transition_owner::TransitionProgress::Ready(
                crate::remote::transition_owner::TransitionReadiness::BusinessReady {
                    barrier_count: 2,
                },
            ));
    }
}

impl Default for ControlOnlyTransitionHandle {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            progress_tx: tokio::sync::watch::channel(
                crate::remote::transition_owner::TransitionProgress::Idle,
            )
            .0,
        }
    }
}

impl Default for ProgressPendingThenReadyTransitionHandle {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            progress_tx: tokio::sync::watch::channel(
                crate::remote::transition_owner::TransitionProgress::Idle,
            )
            .0,
        }
    }
}

fn stale_business_ready_progress()
-> tokio::sync::watch::Sender<crate::remote::transition_owner::TransitionProgress> {
    tokio::sync::watch::channel(crate::remote::transition_owner::TransitionProgress::Ready(
        crate::remote::transition_owner::TransitionReadiness::BusinessReady { barrier_count: 1 },
    ))
    .0
}

impl Default for StaleReadyPendingTransitionHandle {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            progress_tx: stale_business_ready_progress(),
        }
    }
}

impl Default for StaleReadyTerminalTransitionHandle {
    fn default() -> Self {
        Self {
            progress_tx: stale_business_ready_progress(),
        }
    }
}

impl Default for StaleReadyReconnectPendingTransitionHandle {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            progress_tx: stale_business_ready_progress(),
        }
    }
}

impl Default for StaleReadyRetryableStoreTransitionHandle {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            progress_tx: stale_business_ready_progress(),
        }
    }
}

impl StaleReadyReconnectPendingTransitionHandle {
    fn publish_current_attempt_business_ready(&self) {
        self.progress_tx
            .send_replace(crate::remote::transition_owner::TransitionProgress::Ready(
                crate::remote::transition_owner::TransitionReadiness::BusinessReady {
                    barrier_count: 2,
                },
            ));
    }
}

impl StaleReadyRetryableStoreTransitionHandle {
    fn publish_current_attempt_business_ready(&self) {
        self.progress_tx
            .send_replace(crate::remote::transition_owner::TransitionProgress::Ready(
                crate::remote::transition_owner::TransitionReadiness::BusinessReady {
                    barrier_count: 3,
                },
            ));
    }
}

impl ProgressPendingThenReadyTransitionHandle {
    fn publish_control_plane_ready(&self) {
        self.progress_tx
            .send_replace(crate::remote::transition_owner::TransitionProgress::Ready(
                crate::remote::transition_owner::TransitionReadiness::ControlPlaneReady {
                    barrier_count: 1,
                },
            ));
    }
}

#[derive(Default)]
struct CountingStartupPublicationTransport {
    publish_calls: AtomicUsize,
}

#[derive(Default)]
struct OfflineOnceStartupPublicationTransport {
    publish_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl crate::runtime::publication::PublicationTransport for CountingStartupPublicationTransport {
    async fn publish(
        &self,
        publication: crate::runtime::store::FrozenPublication,
    ) -> crate::runtime::publication::PublicationTransportOutcome {
        self.publish_calls.fetch_add(1, Ordering::SeqCst);
        let key = crate::runtime::publication::PublicationDispatchKey::from(&publication);
        crate::runtime::publication::PublicationTransportOutcome::Committed(
            crate::runtime::publication::PublicationCommitReceipt { key },
        )
    }
}

#[async_trait::async_trait]
impl crate::runtime::publication::PublicationTransport for OfflineOnceStartupPublicationTransport {
    async fn publish(
        &self,
        publication: crate::runtime::store::FrozenPublication,
    ) -> crate::runtime::publication::PublicationTransportOutcome {
        let call = self.publish_calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            return crate::runtime::publication::PublicationTransportOutcome::Offline;
        }
        let key = crate::runtime::publication::PublicationDispatchKey::from(&publication);
        crate::runtime::publication::PublicationTransportOutcome::Committed(
            crate::runtime::publication::PublicationCommitReceipt { key },
        )
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for FailingTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Err(admin_error("daemon.remote.transition.test_blocked"))
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        Err(admin_error("daemon.remote.transition.test_blocked"))
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for PendingTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        std::future::pending().await
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for ReadyTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(
            crate::remote::transition_owner::TransitionReadiness::BusinessReady {
                barrier_count: 0,
            },
        )
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for ControlThenReadyTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(())
    }

    fn subscribe_progress(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<crate::remote::transition_owner::TransitionProgress>>
    {
        Some(self.progress_tx.subscribe())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let readiness = crate::remote::transition_owner::TransitionReadiness::ControlPlaneReady {
            barrier_count: 2,
        };
        self.progress_tx
            .send_replace(crate::remote::transition_owner::TransitionProgress::Ready(
                readiness,
            ));
        Ok(readiness)
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for ControlOnlyTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(())
    }

    fn subscribe_progress(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<crate::remote::transition_owner::TransitionProgress>>
    {
        Some(self.progress_tx.subscribe())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let readiness = crate::remote::transition_owner::TransitionReadiness::ControlPlaneReady {
            barrier_count: 2,
        };
        self.progress_tx
            .send_replace(crate::remote::transition_owner::TransitionProgress::Ready(
                readiness,
            ));
        Ok(readiness)
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for ProgressPendingThenReadyTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(())
    }

    fn subscribe_progress(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<crate::remote::transition_owner::TransitionProgress>>
    {
        Some(self.progress_tx.subscribe())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.progress_tx
            .send_replace(crate::remote::transition_owner::TransitionProgress::Pending);
        Err(admin_error("daemon.remote.transition.progress_pending"))
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for StaleReadyPendingTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(())
    }

    fn subscribe_progress(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<crate::remote::transition_owner::TransitionProgress>>
    {
        Some(self.progress_tx.subscribe())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for StaleReadyTerminalTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(())
    }

    fn subscribe_progress(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<crate::remote::transition_owner::TransitionProgress>>
    {
        Some(self.progress_tx.subscribe())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        Err(admin_error("daemon.remote.transition.test_blocked"))
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for StaleReadyReconnectPendingTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(())
    }

    fn subscribe_progress(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<crate::remote::transition_owner::TransitionProgress>>
    {
        Some(self.progress_tx.subscribe())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(admin_error("daemon.remote.transition.reconnect_pending"))
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionHandle for StaleReadyRetryableStoreTransitionHandle {
    fn request_control_plane_progress(
        &self,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(())
    }

    fn subscribe_progress(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<crate::remote::transition_owner::TransitionProgress>>
    {
        Some(self.progress_tx.subscribe())
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<
        crate::remote::transition_owner::TransitionReadiness,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.progress_tx
            .send_replace(crate::remote::transition_owner::TransitionProgress::Pending);
        Err(admin_error(
            "daemon.remote.transition.completion_store_failed",
        ))
    }
}

#[tokio::test]
async fn transition_readiness_uses_absolute_deadline_and_shutdown_cancellation() {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pending = PendingTransitionHandle::default();
    let timed_out = super::await_transition_readiness(
        &pending,
        tokio::time::Instant::now() + Duration::from_millis(20),
        shutdown_rx,
    )
    .await
    .expect_err("stalled Relay transition must hit the absolute deadline");
    assert_eq!(
        timed_out.code(),
        "daemon.remote.transition.recovery_timed_out"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    shutdown_tx.send_replace(true);
    let pending = PendingTransitionHandle::default();
    let cancelled = super::await_transition_readiness(
        &pending,
        tokio::time::Instant::now() + Duration::from_secs(60),
        shutdown_rx,
    )
    .await
    .expect_err("shutdown must cancel transition admission immediately");
    assert_eq!(cancelled.code(), "daemon.remote.shutting_down");
}

#[tokio::test]
async fn startup_progress_pending_keeps_the_unique_owner_waiter_until_progress_ready() {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let transition = Arc::new(ProgressPendingThenReadyTransitionHandle::default());
    let wait = tokio::spawn({
        let transition = Arc::clone(&transition);
        async move {
            super::await_transition_readiness(
                transition.as_ref(),
                tokio::time::Instant::now() + Duration::from_secs(1),
                shutdown_rx,
            )
            .await
        }
    });
    for _ in 0..1_000 {
        if transition.calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(transition.calls.load(Ordering::SeqCst), 1);
    assert!(
        !wait.is_finished(),
        "ProgressPending must stay attached to the existing owner instead of rolling startup back"
    );
    transition.publish_control_plane_ready();
    assert_eq!(
        wait.await
            .expect("join startup readiness waiter")
            .expect("owner progress releases startup control plane"),
        crate::remote::transition_owner::TransitionReadiness::ControlPlaneReady {
            barrier_count: 1
        }
    );
    assert_eq!(
        transition.calls.load(Ordering::SeqCst),
        1,
        "manager must not create a second transition drive owner"
    );
}

#[tokio::test(start_paused = true)]
async fn stale_business_ready_cannot_cover_a_new_drive_timeout() {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let transition = StaleReadyPendingTransitionHandle::default();
    let error = super::await_exact_business_readiness(
        &transition,
        tokio::time::Instant::now() + Duration::from_secs(30),
        shutdown_rx,
    )
    .await
    .expect_err("a prior Ready value must not cover a stalled current transition");
    assert_eq!(error.code(), "daemon.remote.transition.recovery_timed_out");
    assert_eq!(transition.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stale_business_ready_cannot_cover_a_terminal_drive_error() {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let error = super::await_exact_business_readiness(
        &StaleReadyTerminalTransitionHandle::default(),
        tokio::time::Instant::now() + Duration::from_secs(1),
        shutdown_rx,
    )
    .await
    .expect_err("a prior Ready value must not cover a terminal current-attempt error");
    assert_eq!(error.code(), "daemon.remote.transition.test_blocked");
}

#[tokio::test]
async fn stale_business_ready_waits_for_fresh_progress_after_reconnect_pending() {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let transition = Arc::new(StaleReadyReconnectPendingTransitionHandle::default());
    let wait = tokio::spawn({
        let transition = Arc::clone(&transition);
        async move {
            super::await_exact_business_readiness(
                transition.as_ref(),
                tokio::time::Instant::now() + Duration::from_secs(1),
                shutdown_rx,
            )
            .await
        }
    });
    for _ in 0..1_000 {
        if transition.calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(transition.calls.load(Ordering::SeqCst), 1);
    assert!(
        !wait.is_finished(),
        "ReconnectPending must not reuse a Ready value from an earlier transition"
    );
    transition.publish_current_attempt_business_ready();
    wait.await
        .expect("join fresh progress waiter")
        .expect("fresh current-attempt progress releases business readiness");
}

#[tokio::test]
async fn stale_business_ready_uses_fresh_pending_to_distinguish_retryable_store_progress() {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let transition = Arc::new(StaleReadyRetryableStoreTransitionHandle::default());
    let wait = tokio::spawn({
        let transition = Arc::clone(&transition);
        async move {
            super::await_exact_business_readiness(
                transition.as_ref(),
                tokio::time::Instant::now() + Duration::from_secs(1),
                shutdown_rx,
            )
            .await
        }
    });
    for _ in 0..1_000 {
        if transition.calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(transition.calls.load(Ordering::SeqCst), 1);
    assert!(
        !wait.is_finished(),
        "fresh Pending is the typed distinction between retryable and permanent Store errors"
    );
    transition.publish_current_attempt_business_ready();
    wait.await
        .expect("join retryable Store progress waiter")
        .expect("owner retry progress releases exact business readiness");
}

#[tokio::test]
async fn shutdown_wins_while_stale_ready_waits_on_reconnect_pending() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let transition = Arc::new(StaleReadyReconnectPendingTransitionHandle::default());
    let wait = tokio::spawn({
        let transition = Arc::clone(&transition);
        async move {
            super::await_exact_business_readiness(
                transition.as_ref(),
                tokio::time::Instant::now() + Duration::from_secs(60),
                shutdown_rx,
            )
            .await
        }
    });
    for _ in 0..1_000 {
        if transition.calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(transition.calls.load(Ordering::SeqCst), 1);
    assert!(!wait.is_finished());
    shutdown_tx.send_replace(true);
    let error = wait
        .await
        .expect("join shutdown-priority waiter")
        .expect_err("shutdown must beat stale and future Ready progress");
    assert_eq!(error.code(), REMOTE_SHUTTING_DOWN);
}

#[tokio::test]
async fn post_start_business_readiness_never_treats_control_plane_ready_as_success() {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let eventually_ready = Arc::new(ControlThenReadyTransitionHandle::default());
    let wait = tokio::spawn({
        let eventually_ready = Arc::clone(&eventually_ready);
        async move {
            super::await_exact_business_readiness(
                eventually_ready.as_ref(),
                tokio::time::Instant::now() + Duration::from_secs(1),
                shutdown_rx,
            )
            .await
        }
    });
    for _ in 0..1_000 {
        if eventually_ready.calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(eventually_ready.calls.load(Ordering::SeqCst), 1);
    assert!(
        !wait.is_finished(),
        "ControlPlaneReady must stay fenced until owner progress observes the ACK"
    );
    eventually_ready.publish_business_ready();
    wait.await
        .expect("join exact readiness waiter")
        .expect("owner progress releases exact business readiness");
    assert_eq!(
        eventually_ready.calls.load(Ordering::SeqCst),
        1,
        "manager must not issue a second full drive"
    );

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let never_ready = ControlOnlyTransitionHandle::default();
    let error = super::await_exact_business_readiness(
        &never_ready,
        tokio::time::Instant::now() + Duration::from_millis(40),
        shutdown_rx,
    )
    .await
    .expect_err("ControlPlaneReady without required ACK must never report business success");
    assert_eq!(error.code(), "daemon.remote.transition.recovery_timed_out");
    assert!(never_ready.calls.load(Ordering::SeqCst) >= 1);
    assert!(
        !super::transition_timeout_resolved(Some(error.code()), true),
        "timeout must remain a stable remote block while the durable transition is active"
    );
    assert!(
        super::transition_timeout_resolved(Some(error.code()), false),
        "status may clear only after Store proves the transition slot is empty"
    );
    assert!(
        !super::transition_timeout_resolved(
            Some("daemon.remote.transition.backend_rejected"),
            false
        ),
        "unrelated transition failures must not be cleared by the timeout rule"
    );
}

#[tokio::test(start_paused = true)]
async fn post_start_control_plane_wait_does_not_redrive_every_twenty_five_milliseconds() {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let never_ready = ControlOnlyTransitionHandle::default();
    let error = super::await_exact_business_readiness(
        &never_ready,
        tokio::time::Instant::now() + Duration::from_secs(30),
        shutdown_rx,
    )
    .await
    .expect_err("missing endpoint ACK must remain bounded by the original absolute deadline");
    assert_eq!(error.code(), "daemon.remote.transition.recovery_timed_out");
    assert!(
        never_ready.calls.load(Ordering::SeqCst) <= 8,
        "the manager must not bypass the owner 250ms -> 30s backoff with a 25ms drive loop"
    );
}

#[tokio::test]
async fn retired_active_sender_stages_one_counter_recovery_and_repeat_reuses_operation() {
    let root = tempfile::tempdir().expect("create manager counter recovery root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("secure manager counter recovery root");
    }
    let database = root.path().join("runtime.db");
    let store = active_authorization_store_for_test(&database).await;
    let keys = Arc::new(MemoryKeyStore::new());
    let authorization = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load authenticated sender inventory")
        .into_iter()
        .find_map(|binding| match binding {
            crate::runtime::store::ActiveSenderCounterBinding::DirectedReply { authorization } => {
                Some(authorization)
            }
            crate::runtime::store::ActiveSenderCounterBinding::SharedPublication { .. } => None,
        })
        .expect("active directed sender binding");
    let key_id = KeyId {
        purpose: KeyPurpose::DeviceReplyTx,
        epoch: authorization.reply_key_epoch(),
    };
    let scope = crate::remote::counter::CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        authorization.reply_key_epoch(),
    )
    .expect("derive active directed sender scope");
    let genesis = store
        .load_remote_counter_record(scope.token(), key_id)
        .await
        .expect("load counter genesis");
    store
        .retire_remote_counter(
            crate::runtime::store::remote_counter::RemoteCounterRetirementRequest {
                scope_token: scope.token(),
                key_id,
                expected_reserved_end: genesis.reserved_end,
                expected_db_anchor: genesis.db_anchor,
                retired_through: crate::remote::counter::COUNTER_BLOCK_SIZE,
            },
        )
        .await
        .expect("persist rollback retirement");

    let guard = crate::remote::identity::OwnedKeyStoreCounterGuardBackend::new(keys);
    let operation_id = super::reconcile_active_sender_counters(&store, &guard)
        .await
        .expect("stage canonical counter recovery")
        .expect("rollback requires a transition");
    assert_ne!(operation_id, [0; 16]);
    let transition = store
        .load_active_key_transition()
        .await
        .expect("load staged counter transition")
        .expect("counter transition remains active");
    assert_eq!(transition.transition.operation_id, operation_id);
    assert_eq!(
        transition.transition.operation,
        crate::runtime::store::key_transition::KeyTransitionOperation::CounterRecovery
    );
    assert!(
        store
            .has_retired_remote_counter()
            .await
            .expect("read recovery fence")
    );

    assert_eq!(
        super::reconcile_active_sender_counters(&store, &guard)
            .await
            .expect("resume the same durable recovery"),
        Some(operation_id),
        "repeat startup must not fork the durable recovery lineage"
    );
    store
        .shutdown()
        .await
        .expect("shutdown manager recovery Store");
}

#[tokio::test]
async fn startup_counter_audit_fences_retired_pending_blob_before_transport_publish() {
    let root = tempfile::tempdir().expect("create startup counter-order root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("secure startup counter-order root");
    }
    let store = active_authorization_store_for_test(&root.path().join("runtime.db")).await;
    let publication_stream_id = [0xc1; 16];
    let stream_route = [0xc2; 16];
    let generation = [0xc3; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            stream_route,
            generation,
        )
        .await
        .expect("create startup Catalog stream");
    let old_key_id = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load startup sender inventory")
        .into_iter()
        .find_map(|binding| match binding {
            crate::runtime::store::ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id: id,
                key_id,
            } if id == publication_stream_id => Some(key_id),
            _ => None,
        })
        .expect("load startup Catalog sender");
    let old_scope = crate::remote::counter::CounterScope::publication(
        store.machine_trust_domain().expect("startup trust domain"),
        old_key_id,
        publication_stream_id,
    )
    .expect("derive startup Catalog counter scope");
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load startup machine enrollment")
    else {
        panic!("startup authorization fixture must remain actively enrolled")
    };
    let key_directory_revision = store
        .load_global_key_state()
        .await
        .expect("load startup key directory")
        .expect("startup key directory exists")
        .revision()
        .value();
    let freeze_guard = crate::remote::identity::OwnedKeyStoreCounterGuardBackend::new(Arc::new(
        MemoryKeyStore::new(),
    ));
    let frozen = crate::remote::publisher::SignedPublicationCoordinator::new(&store, &freeze_guard)
        .freeze_signed(
            crate::remote::publisher::SignedPublicationRequest {
                publication_id: [0xc4; 16],
                publication_stream_id,
                machine_route: MachineRouteId::from_bytes(active.record.machine_route),
                generation: agentdeck_protocol::relay_v2::StreamGenerationId::from_bytes(
                    generation,
                ),
                key_directory_revision,
                key_id: old_key_id,
                counter_scope: old_scope,
                inner_after: None,
                inner_through: Some(0),
                payload_kind: PublicationPayloadKind::Catalog,
                sealer_retained_bytes: 0,
            },
            |_axes| Ok(b"retired-old-counter-blob".to_vec()),
        )
        .await
        .expect("transactionally freeze old-counter publication before rollback detection");
    assert!(
        frozen.counter_db_anchor.is_some(),
        "fixture must exercise the P4 transaction-bound counter path"
    );

    let transport = Arc::new(CountingStartupPublicationTransport::default());
    let publication_owner =
        crate::remote::publication_transport::tests::open_owner_with_transport_for_test(
            store.clone(),
            Arc::clone(&transport),
        )
        .await
        .expect("open startup publication owner");
    let guard = crate::remote::identity::OwnedKeyStoreCounterGuardBackend::new(Arc::new(
        MemoryKeyStore::new(),
    ));
    let transition = ReadyTransitionHandle::default();
    let mut admission = super::RemoteBusinessAdmission::new();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let error = super::drive_business_startup_gates(
        &store,
        &guard,
        &publication_owner.handle(),
        &transition,
        &mut admission,
        tokio::time::Instant::now() + Duration::from_secs(5),
        shutdown_rx,
        None,
    )
    .await
    .expect_err("retired pending scope must block startup before transport");
    assert_eq!(
        transport.publish_calls.load(Ordering::SeqCst),
        0,
        "CounterGuard/recovery audit must complete before any pending blob reaches transport"
    );
    assert_eq!(error.code(), super::COUNTER_RETIRED);
    assert_eq!(
        transition.calls.load(Ordering::SeqCst),
        0,
        "retired pending scope must fail before transition drive can rediscover it"
    );
    let staged = store
        .load_active_key_transition()
        .await
        .expect("read back startup counter reconciliation")
        .expect("rollback audit stages CounterRecovery before blocking transport");
    assert_eq!(
        staged.transition.operation,
        crate::runtime::store::key_transition::KeyTransitionOperation::CounterRecovery
    );
    let pending = store
        .load_pending_publications(publication_stream_id)
        .await
        .expect("reload fenced old-counter outbox");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].blob, b"retired-old-counter-blob");

    publication_owner
        .shutdown()
        .await
        .expect("shutdown startup publication owner");
    store.shutdown().await.expect("shutdown startup Store");
}

#[tokio::test]
async fn startup_offline_pending_recovery_keeps_owner_until_authenticated_reconnect() {
    let root = tempfile::tempdir().expect("create healthy startup-order root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("secure healthy startup-order root");
    }
    let store = active_authorization_store_for_test(&root.path().join("runtime.db")).await;
    let publication_stream_id = [0xd1; 16];
    let generation = [0xd3; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0xd2; 16],
            generation,
        )
        .await
        .expect("create healthy startup Catalog stream");
    let key_id = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load healthy startup sender inventory")
        .into_iter()
        .find_map(|binding| match binding {
            crate::runtime::store::ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id: id,
                key_id,
            } if id == publication_stream_id => Some(key_id),
            _ => None,
        })
        .expect("load healthy startup Catalog sender");
    let scope = crate::remote::counter::CounterScope::publication(
        store.machine_trust_domain().expect("healthy trust domain"),
        key_id,
        publication_stream_id,
    )
    .expect("derive healthy startup counter scope");
    store
        .freeze_publication(crate::runtime::store::FreezePublicationRequest {
            publication_id: [0xd4; 16],
            publication_stream_id,
            generation,
            counter_scope_token: scope.token(),
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"healthy-pending-blob".to_vec(),
        })
        .await
        .expect("freeze healthy startup publication");

    let transport = Arc::new(OfflineOnceStartupPublicationTransport::default());
    let publication_owner =
        crate::remote::publication_transport::tests::open_owner_with_transport_for_test(
            store.clone(),
            Arc::clone(&transport),
        )
        .await
        .expect("open healthy startup publication owner");
    let guard = crate::remote::identity::OwnedKeyStoreCounterGuardBackend::new(Arc::new(
        MemoryKeyStore::new(),
    ));
    let transition = Arc::new(ReadyTransitionHandle::default());
    let (mut reconnect_transport, _pairing_lane, reconnect_harness) =
        crate::remote::transport::active_pairing_transport_for_test(MachineRouteId::from_bytes(
            [0xd5; 16],
        ));
    let reconnect_lane = reconnect_transport
        .take_business_lane()
        .expect("claim startup reconnect observation lane");
    let reconnects = reconnect_lane
        .publication_handle()
        .subscribe_authenticated_reconnects();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let gate = tokio::spawn({
        let store = store.clone();
        let publication_drive = publication_owner.handle();
        let guard = guard;
        let transition = Arc::clone(&transition);
        async move {
            let mut admission = super::RemoteBusinessAdmission::new();
            super::drive_business_startup_gates(
                &store,
                &guard,
                &publication_drive,
                transition.as_ref(),
                &mut admission,
                tokio::time::Instant::now() + Duration::from_secs(5),
                shutdown_rx,
                Some(reconnects),
            )
            .await?;
            admission.into_permit()
        }
    });
    for _ in 0..10_000 {
        if transport.publish_calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(transport.publish_calls.load(Ordering::SeqCst), 1);
    assert!(
        !gate.is_finished(),
        "Relay Offline must retain the startup gate and its unique publication owner"
    );
    reconnect_transport
        .reconnect()
        .await
        .expect("authenticated replacement generation wakes startup recovery");
    assert_eq!(reconnect_harness.reconnect_count(), 1);
    tokio::time::timeout(Duration::from_secs(2), gate)
        .await
        .expect("startup recovery remains inside its original deadline")
        .expect("join startup gate")
        .expect("authenticated reconnect releases the RemoteLink admission permit");
    assert_eq!(transition.calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.publish_calls.load(Ordering::SeqCst), 2);

    publication_owner
        .shutdown()
        .await
        .expect("shutdown healthy startup publication owner");
    drop(reconnect_lane);
    reconnect_transport.shutdown().await;
    store
        .shutdown()
        .await
        .expect("shutdown healthy startup Store");
}

#[async_trait::async_trait]
impl super::ManagedTransitionOwner for RecordingTransitionOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        self.order
            .lock()
            .expect("record transition shutdown")
            .push("transition");
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionOwner for LifecycleRecordingTransitionOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        let lifecycle = observed_machine_lifecycle(&self.store).await;
        self.observed
            .lock()
            .expect("record transition lifecycle")
            .push(("transition", lifecycle));
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionOwner for FailingTransitionShutdownOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Err(admin_error("daemon.remote.transition.shutdown_timed_out"))
    }
}

#[async_trait::async_trait]
impl super::ManagedTransitionOwner for FailedTransitionHealthOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(())
    }

    fn observed_failure_code(&self) -> Option<String> {
        Some("daemon.remote.transition.business_fenced".to_owned())
    }
}

#[async_trait::async_trait]
impl super::ManagedMaintenanceOwner for RecordingMaintenanceOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        self.order
            .lock()
            .expect("record maintenance shutdown")
            .push("maintenance");
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::ManagedMaintenanceOwner for LifecycleRecordingMaintenanceOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        let lifecycle = observed_machine_lifecycle(&self.store).await;
        self.observed
            .lock()
            .expect("record maintenance lifecycle")
            .push(("maintenance", lifecycle));
        Ok(())
    }
}

struct RecordingPublicationOwner {
    order: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

struct LifecycleRecordingPublicationOwner {
    store: RuntimeStoreHandle,
    observed: Arc<std::sync::Mutex<Vec<(&'static str, &'static str)>>>,
}

struct FailingPublicationShutdownOwner;

#[async_trait::async_trait]
impl super::ManagedPublicationOwner for RecordingPublicationOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::remote::publication_transport::PublicationDriveError> {
        self.order
            .lock()
            .expect("record publication shutdown")
            .push("publication");
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::ManagedPublicationOwner for LifecycleRecordingPublicationOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::remote::publication_transport::PublicationDriveError> {
        let lifecycle = observed_machine_lifecycle(&self.store).await;
        self.observed
            .lock()
            .expect("record publication lifecycle")
            .push(("publication", lifecycle));
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::ManagedPublicationOwner for FailingPublicationShutdownOwner {
    async fn shutdown(
        self: Box<Self>,
    ) -> Result<(), crate::remote::publication_transport::PublicationDriveError> {
        Err(crate::remote::publication_transport::PublicationDriveError::ShutdownTimedOut)
    }
}

async fn observed_machine_lifecycle(store: &RuntimeStoreHandle) -> &'static str {
    match store
        .load_machine_enrollment_state()
        .await
        .expect("load lifecycle observed during owner shutdown")
        .expect("owner shutdown requires durable machine lifecycle")
    {
        MachineEnrollmentState::EnrollmentPrepared(_) => "enrollmentPrepared",
        MachineEnrollmentState::EnrollmentResponseValidated(_) => "enrollmentResponseValidated",
        MachineEnrollmentState::Active(_) => "active",
        MachineEnrollmentState::RetirePending(_) => "retirePending",
        MachineEnrollmentState::RelayCommitted(_) => "relayCommitted",
        MachineEnrollmentState::PurgeReadbackAbsent(_) => "purgeReadbackAbsent",
        MachineEnrollmentState::LocalDeleted(_) => "localDeleted",
    }
}

#[tokio::test]
async fn shutdown_reclaims_remote_link_then_maintenance_transition_and_publication() {
    let mut fixture = unenrolled_fixture("p45-owner-shutdown-order").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let mut state = manager.state.lock().await;
        state.link = Some(Box::new(RecordingLinkOwner {
            order: Arc::clone(&order),
        }));
        state.transition = Some(Box::new(RecordingTransitionOwner {
            order: Arc::clone(&order),
        }));
        state.transition_handle = Some(Arc::new(ReadyTransitionHandle::default()));
        state.maintenance = Some(Box::new(RecordingMaintenanceOwner {
            order: Arc::clone(&order),
        }));
        state.publication = Some(Box::new(RecordingPublicationOwner {
            order: Arc::clone(&order),
        }));
    }

    manager.shutdown().await;

    assert_eq!(
        *order.lock().expect("read shutdown order"),
        vec!["link", "maintenance", "transition", "publication"]
    );
    {
        let state = manager.state.lock().await;
        assert!(state.link.is_none());
        assert!(state.transition.is_none());
        assert!(state.transition_handle.is_none());
        assert!(state.maintenance.is_none());
        assert!(state.publication.is_none());
    }
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn failed_business_start_rolls_back_all_business_owners_but_keeps_pairing() {
    let mut fixture = unenrolled_fixture("p45-start-rollback-order").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (pairing, _health_tx) = crate::remote::pairing::PairingCoordinatorOwner::health_test_double(
        crate::remote::pairing::PairingCoordinatorHealth::Healthy,
    );
    {
        let mut state = manager.state.lock().await;
        state.pairing = Some(pairing);
        state.link = Some(Box::new(RecordingLinkOwner {
            order: Arc::clone(&order),
        }));
        state.transition = Some(Box::new(RecordingTransitionOwner {
            order: Arc::clone(&order),
        }));
        state.transition_handle = Some(Arc::new(ReadyTransitionHandle::default()));
        state.maintenance = Some(Box::new(RecordingMaintenanceOwner {
            order: Arc::clone(&order),
        }));
        state.publication = Some(Box::new(RecordingPublicationOwner {
            order: Arc::clone(&order),
        }));

        super::rollback_business_start(&mut state)
            .await
            .expect("all startup owners join before retry");

        assert!(state.link.is_none());
        assert!(state.transition.is_none());
        assert!(state.transition_handle.is_none());
        assert!(state.maintenance.is_none());
        assert!(state.publication.is_none());
        assert!(state.pairing.is_some(), "pairing control must remain live");
    }
    assert_eq!(
        *order.lock().expect("read startup rollback order"),
        vec!["link", "maintenance", "transition", "publication"]
    );
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn business_start_missing_runtime_core_preserves_same_process_retry_intent() {
    let mut fixture = active_fixture("p45-start-retry-intent").await;
    let (machine_data, _machine_data_owner, machine_route) =
        business_start_authority(&fixture).await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        super::stage_business_start(&mut state, *machine_route.as_bytes(), machine_data)
            .expect("stage exact active-machine business start");
    }

    let error = manager
        .start_business_stack_if_ready()
        .await
        .expect_err("missing RuntimeCore must keep business startup blocked");
    assert_eq!(error.code(), "daemon.remote.runtime_core_unavailable");
    let state = manager.state.lock().await;
    assert!(
        state.pending_business_start.is_some(),
        "a transient pre-lane failure must preserve the exact retry intent"
    );
    assert_eq!(
        state.blocked_code.as_deref(),
        Some("daemon.remote.runtime_core_unavailable")
    );
    drop(state);

    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn business_start_post_lane_failure_restores_lane_and_exact_retry_intent() {
    let mut fixture = active_fixture("p45-start-retry-lane").await;
    let (machine_data, _machine_data_owner, machine_route) =
        business_start_authority(&fixture).await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    let core = Arc::new(
        crate::runtime::RuntimeCore::new(
            fixture.store.clone(),
            Arc::new(crate::runtime::AgentRouter::with_runtime_store(
                fixture.store.clone(),
            )),
            fixture
                .store
                .machine_trust_domain()
                .expect("load manager fixture trust domain"),
        )
        .expect("construct manager startup RuntimeCore"),
    );
    assert!(manager.install_runtime_core(&core));
    let (transport, _pairing_lane, _harness) =
        crate::remote::transport::active_pairing_transport_for_test(machine_route);
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.transport = Some(transport);
        super::stage_business_start(&mut state, *machine_route.as_bytes(), machine_data)
            .expect("stage exact active-machine business start");
    }
    manager
        .install_business_start_failure_after_lane_for_test("daemon.remote.test_start_after_lane")
        .await;

    let error = manager
        .start_business_stack_if_ready()
        .await
        .expect_err("injected post-lane failure keeps startup blocked");
    assert_eq!(error.code(), "daemon.remote.test_start_after_lane");
    let mut state = manager.state.lock().await;
    assert!(state.pending_business_start.is_some());
    assert!(!state.quiescence_unknown);
    let retry_lane = state
        .transport
        .as_mut()
        .expect("transport remains owned by manager")
        .take_business_lane()
        .expect("joined rollback restores the unique business lane");
    state
        .transport
        .as_mut()
        .expect("transport remains owned by manager")
        .restore_business_lane(retry_lane)
        .await
        .expect("return test lane for manager shutdown");
    drop(state);

    drop(core);
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn failed_business_start_rollback_latches_unknown_quiescence_and_blocks_retry() {
    let mut fixture = active_fixture("p45-start-rollback-quiescence").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.transition = Some(Box::new(FailingTransitionShutdownOwner));
        let _ = super::rollback_business_start(&mut state).await;
        assert!(
            state.quiescence_unknown,
            "failed startup owner join must irreversibly latch this process"
        );
        assert_eq!(
            state.blocked_code.as_deref(),
            Some("daemon.remote.quiescence_unknown")
        );
    }

    let status = manager
        .status()
        .await
        .expect("blocked status remains readable");
    assert_eq!(status.lifecycle, WireLifecycle::Blocked);
    assert_eq!(
        status.failure_code.unwrap().as_str(),
        "daemon.remote.quiescence_unknown"
    );
    let retry = manager
        .enroll(MachineEnrollRequest {
            bundle: fixture.bundle.clone(),
            scope: LocalOnlyAdministration::LocalOnly,
        })
        .await
        .expect_err("same-process exact enroll retry must honor unknown quiescence");
    assert_eq!(retry.code(), "daemon.remote.quiescence_unknown");

    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn remote_link_actor_failure_is_visible_to_status_and_running_admission() {
    let mut fixture = active_fixture("p45-link-health").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.link = Some(Box::new(FailedLinkOwner));
        let error = super::require_running_armed(&state)
            .expect_err("an exited RemoteLink actor must fence administration");
        assert_eq!(error.code(), "daemon.remote.link.actor_exited");
    }

    let status = manager
        .status()
        .await
        .expect("failed link status remains readable");
    assert_eq!(status.lifecycle, WireLifecycle::Blocked);
    assert_eq!(
        status.failure_code.expect("link failure code").as_str(),
        "daemon.remote.link.actor_exited"
    );
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn transition_fence_is_visible_to_status_and_running_admission() {
    let mut fixture = active_fixture("p45-transition-health").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.transition = Some(Box::new(FailedTransitionHealthOwner));
        let error = super::require_running_armed(&state)
            .expect_err("control-plane-only transition must fence administration");
        assert_eq!(error.code(), "daemon.remote.transition.business_fenced");
    }

    let status = manager
        .status()
        .await
        .expect("transition-fenced status remains readable");
    assert_eq!(status.lifecycle, WireLifecycle::Blocked);
    assert_eq!(
        status
            .failure_code
            .expect("transition failure code")
            .as_str(),
        "daemon.remote.transition.business_fenced"
    );
    finish_fixture(manager, fixture).await;
}

#[derive(Default)]
struct RecordingPurgeSink {
    intent_calls: AtomicUsize,
    intent_present: AtomicBool,
    reserve_calls: AtomicUsize,
    calls: AtomicUsize,
    resume_calls: AtomicUsize,
    resume_ready: AtomicBool,
    reserve_plan_ids: std::sync::Mutex<Vec<[u8; 16]>>,
    plan_ids: std::sync::Mutex<Vec<[u8; 16]>>,
}

#[async_trait::async_trait]
impl PurgePlanSink for RecordingPurgeSink {
    async fn intent_readback(
        &self,
    ) -> Result<bool, crate::runtime::remote_administration::RemoteAdministrationError> {
        self.intent_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.intent_present.load(Ordering::SeqCst) || self.resume_ready.load(Ordering::SeqCst))
    }

    async fn reserve_and_readback(
        &self,
        plan: &UninstallPurgePlanV1,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        self.reserve_calls.fetch_add(1, Ordering::SeqCst);
        self.intent_present.store(true, Ordering::SeqCst);
        self.reserve_plan_ids
            .lock()
            .expect("lock recorded reserve plans")
            .push(*plan.plan_id());
        Ok(())
    }

    async fn authorize_and_readback(
        &self,
        plan: UninstallPurgePlanV1,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.plan_ids
            .lock()
            .expect("lock recorded plans")
            .push(*plan.plan_id());
        Ok(())
    }

    async fn resume_reserved_and_readback(
        &self,
    ) -> Result<
        PurgeReservationResume,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        self.resume_calls.fetch_add(1, Ordering::SeqCst);
        Ok(if self.resume_ready.load(Ordering::SeqCst) {
            PurgeReservationResume::Ready
        } else {
            PurgeReservationResume::Absent
        })
    }
}

#[tokio::test]
async fn root_present_terminal_quiesces_p45_owners_before_purge_scrub() {
    let mut fixture = active_fixture("p45-q-order").await;
    prepare_retirement(&fixture).await;
    record_retirement_terminal(&fixture.store).await;
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::RelayCommitted(_))
    ));

    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_purge_plan_sink(Arc::new(RecordingPurgeSink::default()));
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let result = {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.link = Some(Box::new(LifecycleRecordingLinkOwner {
            store: fixture.store.clone(),
            observed: Arc::clone(&observed),
        }));
        state.transition = Some(Box::new(LifecycleRecordingTransitionOwner {
            store: fixture.store.clone(),
            observed: Arc::clone(&observed),
        }));
        state.maintenance = Some(Box::new(LifecycleRecordingMaintenanceOwner {
            store: fixture.store.clone(),
            observed: Arc::clone(&observed),
        }));
        state.publication = Some(Box::new(LifecycleRecordingPublicationOwner {
            store: fixture.store.clone(),
            observed: Arc::clone(&observed),
        }));
        manager
            .trust_reset_locked(
                &mut state,
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    };
    result.expect("quiescent root-present reset completes");
    assert_eq!(
        *observed.lock().expect("read reset quiescence observations"),
        vec![
            ("link", "relayCommitted"),
            ("maintenance", "relayCommitted"),
            ("transition", "relayCommitted"),
            ("publication", "relayCommitted"),
        ]
    );
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::LocalDeleted(_))
    ));
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn shutdown_timeout_keeps_relay_committed_keys_and_latches_process() {
    let mut fixture = active_fixture("p45-q-timeout").await;
    prepare_retirement(&fixture).await;
    record_retirement_terminal(&fixture.store).await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_purge_plan_sink(Arc::new(RecordingPurgeSink::default()));
    let request = || {
        TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
            .expect("ordinary root-present reset")
    };

    let first = {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.transition = Some(Box::new(FailingTransitionShutdownOwner));
        manager
            .trust_reset_locked(&mut state, request())
            .await
            .expect_err("unknown transition quiescence must stop before scrub")
    };
    assert_eq!(first.code(), "daemon.remote.quiescence_unknown");
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::RelayCommitted(_))
    ));
    for account in [
        MACHINE_DATA_SIGN_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        KEY_DIRECTORY_GUARD_ACCOUNT,
        MACHINE_ROOT_SIGN_ACCOUNT,
    ] {
        assert!(
            fixture.keys.load(account).unwrap().is_some(),
            "quiescence timeout must retain {account}"
        );
    }

    let second = {
        let mut state = manager.state.lock().await;
        manager
            .trust_reset_locked(&mut state, request())
            .await
            .expect_err("same process cannot retry after unknown quiescence")
    };
    assert_eq!(second.code(), "daemon.remote.quiescence_unknown");
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::RelayCommitted(_))
    ));
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn purge_finalizer_shutdown_timeout_never_releases_ready_state() {
    let mut fixture = active_fixture("p45-final-q-timeout").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );

    let error = {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.purge_pending = true;
        state.publication = Some(Box::new(FailingPublicationShutdownOwner));
        manager
            .quiesce_for_purge_finalizer(&mut state)
            .await
            .expect_err("finalizer readiness requires proven publication quiescence")
    };
    assert_eq!(error.code(), "daemon.remote.quiescence_unknown");
    let state = manager.state.lock().await;
    assert!(state.identity.is_some());
    assert!(state.purge_pending);
    drop(state);
    finish_fixture(manager, fixture).await;
}

struct RejectingPurgeSink;

#[async_trait::async_trait]
impl PurgePlanSink for RejectingPurgeSink {
    async fn intent_readback(
        &self,
    ) -> Result<bool, crate::runtime::remote_administration::RemoteAdministrationError> {
        Ok(false)
    }

    async fn reserve_and_readback(
        &self,
        _plan: &UninstallPurgePlanV1,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        Err(admin_error("daemon.purge.preflight_failed"))
    }

    async fn authorize_and_readback(
        &self,
        _plan: UninstallPurgePlanV1,
    ) -> Result<(), crate::runtime::remote_administration::RemoteAdministrationError> {
        panic!("failed reservation must not reach marker authorization")
    }

    async fn resume_reserved_and_readback(
        &self,
    ) -> Result<
        PurgeReservationResume,
        crate::runtime::remote_administration::RemoteAdministrationError,
    > {
        Err(admin_error("daemon.purge.preflight_failed"))
    }
}

fn uninstall_plan() -> UninstallPurgePlanV1 {
    UninstallPurgePlanV1::new(
        PathBuf::from("/tmp/agentdeckd"),
        "0.1.0".to_owned(),
        ArtifactSha256::new("ab".repeat(32)).expect("valid helper digest"),
        "A1B2C3D4E5".to_owned(),
        "A1B2C3D4E5.com.agentdeck.agentdeckd.stable".to_owned(),
    )
    .expect("valid uninstall plan")
}

#[test]
fn status_maps_unenrolled_and_local_deleted_without_secret_fields() {
    let unenrolled = status_from_state(None, None, false).expect("unenrolled status");
    assert_eq!(unenrolled.lifecycle, WireLifecycle::Unenrolled);

    let durable = local_deleted();
    let deleted = status_from_state(Some(&durable), None, false).expect("deleted status");
    assert_eq!(deleted.lifecycle, WireLifecycle::LocalDeleted);
    assert_eq!(deleted.trust_epoch, Some(1));

    let json = serde_json::to_value(&deleted).expect("encode public status");
    for forbidden in [
        "code",
        "pin",
        "certificate",
        "proof",
        "receiptHash",
        "rootKeyId",
    ] {
        assert!(
            !json.to_string().contains(forbidden),
            "status must not leak {forbidden}: {json}"
        );
    }
}

#[test]
fn blocked_status_preserves_authenticated_old_axes_and_stable_code() {
    let durable = local_deleted();
    let blocked = status_from_state(
        Some(&durable),
        Some("daemon.remote.trust_reset.admin_receipt_required"),
        false,
    )
    .expect("blocked status");
    assert_eq!(blocked.lifecycle, WireLifecycle::Blocked);
    assert_eq!(blocked.relay_server_id.unwrap().as_bytes(), &[0x11; 16]);
    assert_eq!(blocked.machine_route.unwrap().as_bytes(), &[0x22; 16]);
    assert_eq!(blocked.root_fingerprint.unwrap().as_bytes(), &[0x44; 32]);
    assert_eq!(blocked.trust_epoch, Some(1));
    assert_eq!(
        blocked.failure_code.unwrap().as_str(),
        "daemon.remote.trust_reset.admin_receipt_required"
    );
}

#[test]
fn stopped_status_overrides_transient_failure_and_invalid_codes_are_sanitized() {
    let durable = local_deleted();
    let stopped = status_from_state(Some(&durable), Some("remote.transport.offline"), true)
        .expect("stopped status");
    assert_eq!(stopped.lifecycle, WireLifecycle::Blocked);
    assert_eq!(stopped.failure_code.unwrap().as_str(), REMOTE_SHUTTING_DOWN);

    let error = admin_error("UPPERCASE secret detail");
    assert_eq!(error.code(), REMOTE_DISABLED);
}

#[tokio::test]
async fn pairing_start_failure_before_owner_remains_stably_blocked() {
    let mut fixture = active_fixture("pairing-pre-owner").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        assert!(state.pairing.is_none());
        record_pairing_start_failure(&mut state, &admin_error("daemon.pairing.sink_unavailable"));
    }

    let blocked = manager.status().await.unwrap();
    assert_eq!(blocked.lifecycle, WireLifecycle::Blocked);
    assert_eq!(
        blocked.failure_code.unwrap().as_str(),
        "daemon.pairing.sink_unavailable"
    );
    let retry_error =
        require_pairing_owner_after_enroll(true, false, Some("daemon.pairing.sink_unavailable"))
            .expect_err("Active retry must not clear a pre-owner pairing block");
    assert_eq!(retry_error.code(), "daemon.pairing.sink_unavailable");
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn transient_pairing_store_health_clears_back_to_active_without_sticky_block() {
    let mut fixture = active_fixture("pairing-health").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    let (owner, health_tx) = crate::remote::pairing::PairingCoordinatorOwner::health_test_double(
        crate::remote::pairing::PairingCoordinatorHealth::LocalBlocked(
            "daemon.runtime.store_busy".to_owned(),
        ),
    );
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing = Some(owner);
        record_pairing_start_failure(&mut state, &admin_error("daemon.runtime.store_busy"));
        assert!(state.blocked_code.is_none());
    }

    let blocked = manager.status().await.unwrap();
    assert_eq!(blocked.lifecycle, WireLifecycle::Blocked);
    assert_eq!(
        blocked.failure_code.unwrap().as_str(),
        "daemon.runtime.store_busy"
    );
    let blocked_list = tokio::time::timeout(Duration::from_millis(100), manager.list())
        .await
        .expect("local pairing block must reject commands within a fixed bound")
        .expect_err("blocked manager list must fail closed");
    assert_eq!(blocked_list.code(), "daemon.runtime.store_busy");

    health_tx.send_replace(crate::remote::pairing::PairingCoordinatorHealth::Healthy);
    let recovered = manager.status().await.unwrap();
    assert_eq!(recovered.lifecycle, WireLifecycle::Active);
    assert!(recovered.failure_code.is_none());
    assert!(manager.list().await.unwrap().is_empty());

    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_pairing_startup_while_arm_holds_manager_mutex() {
    let mut fixture = unenrolled_fixture("cancel-pair-start").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let (owner, ready_rx) =
        crate::remote::pairing::PairingCoordinatorOwner::pending_startup_test_double();
    let startup_entered = manager
        .install_pairing_startup_test_hook(owner, ready_rx)
        .await;

    let arm_manager = Arc::clone(&manager);
    let arm = tokio::spawn(async move { arm_manager.arm(remote_start_permit_for_test()).await });
    tokio::time::timeout(Duration::from_secs(1), startup_entered)
        .await
        .expect("arm must reach the pending ready wait")
        .expect("startup hook remains installed");
    assert!(
        manager.state.try_lock().is_err(),
        "arm must hold manager state while waiting for startup ready"
    );

    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("shutdown watch must cancel startup before waiting for manager state");
    let arm_error = arm
        .await
        .expect("arm task joins")
        .expect_err("shutdown must fail pending startup closed");
    assert_eq!(arm_error.code(), "daemon.pairing.actor_stopped");
    {
        let state = manager.state.lock().await;
        assert!(state.stopped);
        assert!(state.pairing.is_none());
        assert!(state.transport.is_none());
        assert!(state.start_permit.is_none());
    }

    let manager = Arc::try_unwrap(manager).unwrap_or_else(|_| panic!("all manager tasks joined"));
    drop(manager);
    fixture.store.shutdown().await.unwrap();
    let _ = fs::remove_dir_all(fixture.root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_business_startup_without_waiting_for_manager_mutex() {
    let mut fixture = unenrolled_fixture("cancel-business-start").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let startup_entered = manager.install_business_startup_test_hook().await;

    let arm_manager = Arc::clone(&manager);
    let arm = tokio::spawn(async move { arm_manager.arm(remote_start_permit_for_test()).await });
    tokio::time::timeout(Duration::from_secs(1), startup_entered)
        .await
        .expect("arm must reach the pending business recovery wait")
        .expect("business startup hook remains installed");
    let state = manager
        .state
        .try_lock()
        .expect("business recovery must not retain the manager state mutex");
    drop(state);

    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("shutdown must cancel business recovery within a fixed bound");
    let arm_error = arm
        .await
        .expect("arm task joins")
        .expect_err("shutdown must cancel pending business startup");
    assert_eq!(arm_error.code(), REMOTE_SHUTTING_DOWN);
    assert!(manager.state.lock().await.stopped);

    let manager = Arc::try_unwrap(manager).unwrap_or_else(|_| panic!("all manager tasks joined"));
    drop(manager);
    fixture.store.shutdown().await.unwrap();
    let _ = fs::remove_dir_all(fixture.root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_offline_connect_keeps_exact_retry_owner_until_joined_shutdown() {
    let mut fixture = active_fixture("active-offline").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    let first = tokio::time::timeout(
        Duration::from_secs(5),
        manager.arm(remote_start_permit_for_test()),
    )
    .await
    .expect("offline connect is bounded")
    .expect_err("offline Relay must preserve retry owner");
    assert!(!first.code().is_empty());
    {
        let state = manager.state.lock().await;
        assert!(state.armed);
        assert!(state.connect_retry.is_some());
        assert!(state.identity.is_none());
        assert!(state.start_permit.is_none());
        assert!(state.transport.is_none());
    }
    let retry = {
        let mut state = manager.state.lock().await;
        tokio::time::timeout(Duration::from_secs(5), manager.retry_connect(&mut state))
            .await
            .expect("exact retry is bounded")
            .expect_err("offline exact retry remains retryable")
    };
    assert_eq!(retry.code(), first.code());
    {
        let state = manager.state.lock().await;
        assert!(state.connect_retry.is_some());
        assert!(state.identity.is_none());
        assert!(state.start_permit.is_none());
    }
    manager.shutdown().await;
    {
        let state = manager.state.lock().await;
        assert!(state.stopped);
        assert!(state.connect_retry.is_none());
        assert!(state.transport.is_none());
        assert!(state.identity.is_none());
        assert!(state.start_permit.is_none());
    }
    drop(manager);
    fixture.store.shutdown().await.unwrap();
    let _ = fs::remove_dir_all(fixture.root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_trust_reset_wait_before_taking_manager_mutex() {
    let mut fixture = unenrolled_fixture("shutdown-cancels-trust-reset").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let operation_manager = Arc::clone(&manager);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let operation = tokio::spawn(async move {
        let _state = operation_manager.state.lock().await;
        let _ = entered_tx.send(());
        operation_manager
            .await_trust_reset(std::future::pending::<
                Result<(), crate::remote::trust_reset::MachineTrustResetWorkflowError>,
            >())
            .await
            .expect_err("shutdown must cancel the in-flight terminal wait")
            .code()
            .to_owned()
    });
    entered_rx.await.expect("trust-reset wait entered");

    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("shutdown must preempt before waiting for the manager mutex");
    assert_eq!(
        operation.await.expect("join canceled trust-reset wait"),
        REMOTE_SHUTTING_DOWN
    );
    assert!(manager.state.lock().await.stopped);

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("all shutdown test owners must be joined"),
    };
    drop(manager);
    fixture.store.shutdown().await.unwrap();
    let _ = fs::remove_dir_all(fixture.root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_waits_for_actor_without_holding_manager_mutex() {
    let mut fixture = active_fixture("revocation-manager-mutex").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let device = DeviceHandle::new("device-11111111111111111111111111111111");
    let serial = GrantSerial::new(7);
    let expected = RevocationReceipt::Committed {
        grant_serial: serial,
    };
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let transition = Arc::new(PendingTransitionHandle::default());
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::revocation_test_double(
                entered_tx,
                release_rx,
                expected.clone(),
            ),
        );
        state.transition_handle = Some(transition.clone());
    }

    let operation_manager = Arc::clone(&manager);
    let operation_device = device.clone();
    let operation = tokio::spawn(async move {
        operation_manager
            .revoke_device(operation_device, serial)
            .await
    });
    let observed = entered_rx.await.expect("actor receives revocation command");
    assert_eq!(observed, (device, serial));
    let guard = tokio::time::timeout(Duration::from_millis(100), manager.state.lock())
        .await
        .expect("manager mutex must be free while Relay ACK is pending");
    drop(guard);
    release_tx.send(()).expect("release fake actor ACK");
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), operation)
            .await
            .expect("committed revocation must not wait for endpoint transition ACK")
            .unwrap()
            .unwrap(),
        expected
    );
    assert_eq!(transition.requests.load(Ordering::SeqCst), 1);

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("revocation test drops all manager owners"),
    };
    drop(manager);
    fixture.store.shutdown().await.unwrap();
    let _ = fs::remove_dir_all(fixture.root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_revocation_returns_receipt_and_latches_transition_enqueue_failure() {
    let mut fixture = active_fixture("revocation-transition-fence").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let device = DeviceHandle::new("device-22222222222222222222222222222222");
    let serial = GrantSerial::new(8);
    let committed = RevocationReceipt::Committed {
        grant_serial: serial,
    };
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::revocation_test_double(
                entered_tx, release_rx, committed,
            ),
        );
        state.transition_handle = Some(Arc::new(FailingTransitionHandle));
    }

    let operation = {
        let manager = Arc::clone(&manager);
        let device = device.clone();
        tokio::spawn(async move { manager.revoke_device(device, serial).await })
    };
    assert_eq!(
        entered_rx.await.expect("revocation reaches actor"),
        (device, serial)
    );
    release_tx
        .send(())
        .expect("release committed revocation receipt");
    assert_eq!(
        operation
            .await
            .expect("join committed revocation")
            .expect("durable receipt must survive transition enqueue failure"),
        RevocationReceipt::Committed {
            grant_serial: serial
        }
    );
    assert_eq!(
        manager.state.lock().await.blocked_code.as_deref(),
        Some("daemon.remote.transition.test_blocked")
    );

    let manager = Arc::try_unwrap(manager)
        .unwrap_or_else(|_| panic!("fenced revocation drops all manager owners"));
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_reset_drain_waits_for_actor_without_holding_manager_mutex_and_resumes_failure() {
    let mut fixture = active_fixture("drain-manager-mutex").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (resumed_tx, resumed_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::drain_test_double(
                entered_tx,
                release_rx,
                resumed_tx,
                Ok(()),
            ),
        );
    }

    let operation_manager = Arc::clone(&manager);
    let operation = tokio::spawn(async move {
        operation_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    entered_rx
        .await
        .expect("pairing actor receives drain command");
    let guard = tokio::time::timeout(Duration::from_millis(100), manager.state.lock())
        .await
        .expect("manager mutex must be free while pairing ACKs remain pending");
    drop(guard);

    release_tx
        .send(Err(
            crate::runtime::pairing_administration::PairingAdministrationError::new(
                "daemon.runtime.store_unavailable",
            ),
        ))
        .expect("release failed drain");
    resumed_rx
        .await
        .expect("failed drain must be resumed before returning");
    assert_eq!(
        operation.await.unwrap().unwrap_err().code(),
        "daemon.runtime.store_unavailable"
    );

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("all trust-reset mutex test owners must be joined"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_reset_propagates_failed_drain_resume_actor_error() {
    let mut fixture = active_fixture("failed-drain-resume-error").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (resumed_tx, resumed_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::drain_test_double(
                entered_tx,
                release_rx,
                resumed_tx,
                Err(
                    crate::runtime::pairing_administration::PairingAdministrationError::new(
                        "daemon.pairing.resume_state_invalid",
                    ),
                ),
            ),
        );
    }

    let operation_manager = Arc::clone(&manager);
    let operation = tokio::spawn(async move {
        operation_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    entered_rx.await.expect("actor receives BeginDrain");
    release_tx
        .send(Err(
            crate::runtime::pairing_administration::PairingAdministrationError::new(
                "daemon.runtime.store_unavailable",
            ),
        ))
        .expect("release actor drain failure");
    resumed_rx.await.expect("manager sends failed-drain Resume");
    assert_eq!(
        operation
            .await
            .expect("join failed-drain reset")
            .expect_err("Resume actor error must fail closed")
            .code(),
        "daemon.pairing.resume_state_invalid"
    );

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("resume error test drops all manager owners"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_reset_saturated_drain_returns_busy_without_stale_resume() {
    let mut fixture = active_fixture("saturated-drain").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (stale_tx, stale_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::saturated_drain_test_double(
                release_rx, stale_tx,
            ),
        );
    }

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        manager.trust_reset(
            TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                .expect("ordinary root-present reset"),
        ),
    )
    .await
    .expect("full pairing command queue must return immediately")
    .expect_err("saturated BeginDrain must fail closed");
    assert_eq!(error.code(), "daemon.pairing.actor_busy");
    release_tx.send(()).expect("release saturated queue");
    assert!(
        !stale_rx
            .await
            .expect("observe commands after releasing queue"),
        "BeginDrain that was never enqueued must not create a stale Resume"
    );
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::Active(_))
    ));

    finish_fixture(manager, fixture).await;
}

#[tokio::test(start_paused = true)]
async fn actor_failed_drain_resume_uses_original_absolute_deadline() {
    let mut fixture = active_fixture("failed-drain-resume-deadline").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let (begin_entered_tx, begin_entered_rx) = tokio::sync::oneshot::channel();
    let (begin_release_tx, begin_release_rx) = tokio::sync::oneshot::channel();
    let (saturated_tx, saturated_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (stale_tx, stale_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::blocked_resume_test_double(
                begin_entered_tx,
                begin_release_rx,
                saturated_tx,
                release_rx,
                stale_tx,
            ),
        );
    }

    let operation_manager = Arc::clone(&manager);
    let operation = tokio::spawn(async move {
        operation_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    begin_entered_rx.await.expect("actor receives BeginDrain");
    tokio::time::advance(Duration::from_secs(9)).await;
    begin_release_tx
        .send(Err(
            crate::runtime::pairing_administration::PairingAdministrationError::new(
                "daemon.runtime.store_unavailable",
            ),
        ))
        .expect("release actor failure near the absolute deadline");
    saturated_rx
        .await
        .expect("queue is saturated before manager Resume");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..10 {
        if operation.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        operation.is_finished(),
        "Resume must use the one second remaining on the original deadline"
    );
    assert_eq!(
        operation
            .await
            .expect("join failed-drain trust-reset")
            .expect_err("unconfirmed Resume must fail closed")
            .code(),
        "daemon.pairing.drain_pending"
    );
    tokio::time::resume();
    release_tx.send(()).expect("release blocked Resume queue");
    assert!(
        !stale_rx.await.expect("observe post-deadline queue"),
        "timed-out Resume send must be canceled before capacity returns"
    );

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("deadline test drops manager task"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_actor_failure_resume_before_it_is_enqueued() {
    let mut fixture = active_fixture("failed-drain-resume-shutdown").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let (begin_entered_tx, begin_entered_rx) = tokio::sync::oneshot::channel();
    let (begin_release_tx, begin_release_rx) = tokio::sync::oneshot::channel();
    let (saturated_tx, saturated_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (stale_tx, stale_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::blocked_resume_test_double(
                begin_entered_tx,
                begin_release_rx,
                saturated_tx,
                release_rx,
                stale_tx,
            ),
        );
    }

    let operation_manager = Arc::clone(&manager);
    let operation = tokio::spawn(async move {
        operation_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    begin_entered_rx.await.expect("actor receives BeginDrain");
    begin_release_tx
        .send(Err(
            crate::runtime::pairing_administration::PairingAdministrationError::new(
                "daemon.runtime.store_unavailable",
            ),
        ))
        .expect("release actor failure");
    saturated_rx
        .await
        .expect("queue is saturated before manager Resume");
    tokio::task::yield_now().await;
    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("shutdown must cancel blocked Resume");
    assert_eq!(
        operation
            .await
            .expect("join shutdown-canceled trust-reset")
            .expect_err("shutdown must win over actor failure")
            .code(),
        REMOTE_SHUTTING_DOWN
    );
    release_tx.send(()).expect("release blocked Resume queue");
    assert!(
        !stale_rx.await.expect("observe post-shutdown queue"),
        "shutdown-canceled Resume must not enqueue after capacity returns"
    );

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("shutdown test drops manager task"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(start_paused = true)]
async fn post_workflow_failure_resume_is_bounded_by_drain_deadline() {
    let mut fixture = active_fixture("post-resume-deadline").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let _pairing_lane = install_yielded_test_transport(&manager).await;
    let (begin_entered_tx, begin_entered_rx) = tokio::sync::oneshot::channel();
    let (begin_release_tx, begin_release_rx) = tokio::sync::oneshot::channel();
    let (saturated_tx, saturated_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (stale_tx, stale_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::blocked_resume_test_double(
                begin_entered_tx,
                begin_release_rx,
                saturated_tx,
                release_rx,
                stale_tx,
            ),
        );
    }

    let operation_manager = Arc::clone(&manager);
    let operation = tokio::spawn(async move {
        operation_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    begin_entered_rx.await.expect("actor receives BeginDrain");
    begin_release_tx.send(Ok(())).expect("complete drain");
    saturated_rx
        .await
        .expect("queue is saturated before post-workflow Resume");
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::time::resume();
    let result = tokio::time::timeout(Duration::from_secs(1), operation)
        .await
        .expect("post-workflow Resume must stop at the original drain deadline")
        .expect("join post-workflow trust-reset");
    assert_eq!(
        result
            .expect_err("unconfirmed post-workflow Resume must fail closed")
            .code(),
        "daemon.pairing.drain_pending"
    );
    release_tx.send(()).expect("release blocked Resume queue");
    assert!(
        !stale_rx.await.expect("observe post-deadline queue"),
        "timed-out post-workflow Resume must not enqueue later"
    );
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::Active(_))
    ));

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("deadline test drops manager task"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_post_workflow_failure_resume() {
    let mut fixture = active_fixture("post-workflow-resume-shutdown").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let _pairing_lane = install_yielded_test_transport(&manager).await;
    let (begin_entered_tx, begin_entered_rx) = tokio::sync::oneshot::channel();
    let (begin_release_tx, begin_release_rx) = tokio::sync::oneshot::channel();
    let (saturated_tx, saturated_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (stale_tx, stale_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::blocked_resume_test_double(
                begin_entered_tx,
                begin_release_rx,
                saturated_tx,
                release_rx,
                stale_tx,
            ),
        );
    }

    let operation_manager = Arc::clone(&manager);
    let operation = tokio::spawn(async move {
        operation_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    begin_entered_rx.await.expect("actor receives BeginDrain");
    begin_release_tx.send(Ok(())).expect("complete drain");
    saturated_rx
        .await
        .expect("queue is saturated before post-workflow Resume");
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("shutdown must cancel post-workflow Resume");
    assert_eq!(
        operation
            .await
            .expect("join shutdown-canceled post-workflow trust-reset")
            .expect_err("shutdown must win over workflow failure")
            .code(),
        REMOTE_SHUTTING_DOWN
    );
    release_tx.send(()).expect("release blocked Resume queue");
    assert!(
        !stale_rx.await.expect("observe post-shutdown queue"),
        "shutdown-canceled post-workflow Resume must not enqueue later"
    );

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("shutdown test drops manager task"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(start_paused = true)]
async fn trust_reset_pending_drain_is_bounded_without_resuming_and_retry_joins_running_drain() {
    let mut fixture = active_fixture("pending-drain-deadline").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let _pairing_lane = install_yielded_test_transport(&manager).await;
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let (resumed_tx, mut resumed_rx) = tokio::sync::mpsc::unbounded_channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::pending_drain_test_double(
                entered_tx, release_rx, resumed_tx, None,
            ),
        );
    }

    let first_manager = Arc::clone(&manager);
    let mut first = tokio::spawn(async move {
        first_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    entered_rx
        .recv()
        .await
        .expect("first trust-reset attaches a drain waiter");
    assert!(
        manager.state.try_lock().is_ok(),
        "manager mutex remains available while pairing drain is pending"
    );

    tokio::time::advance(Duration::from_secs(10)).await;
    let first_result = match tokio::time::timeout(Duration::from_secs(1), &mut first).await {
        Ok(result) => result.expect("join first trust-reset"),
        Err(_) => {
            first.abort();
            let _ = first.await;
            panic!("pending pairing drain must return at its deadline");
        }
    };
    assert_eq!(
        first_result
            .expect_err("pending drain must fail closed")
            .code(),
        "daemon.pairing.drain_pending"
    );
    assert!(matches!(
        resumed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        manager
            .status()
            .await
            .expect("status remains available after drain deadline")
            .lifecycle,
        WireLifecycle::Active
    );
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::Active(_))
    ));
    assert!(
        fixture
            .keys
            .load(MACHINE_ROOT_SIGN_ACCOUNT)
            .unwrap()
            .is_some(),
        "deadline must not clean up machine keys"
    );
    assert!(manager.state.lock().await.pairing_handle_for_test.is_some());

    // Store reply 跨独立 worker thread；retry watchdog 前恢复墙钟，避免 Tokio
    // paused-time 自动推进先于外部线程回复。
    tokio::time::resume();
    let retry_manager = Arc::clone(&manager);
    let mut retry = tokio::spawn(async move {
        retry_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present retry"),
            )
            .await
    });
    entered_rx
        .recv()
        .await
        .expect("retry attaches to the same running drain");
    assert!(matches!(
        resumed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    release_tx
        .send(true)
        .expect("complete all waiters on the running drain");
    let retry_result = match tokio::time::timeout(Duration::from_secs(1), &mut retry).await {
        Ok(result) => result.expect("join trust-reset retry"),
        Err(_) => {
            retry.abort();
            let _ = retry.await;
            panic!("completed pairing drain must unblock retry");
        }
    };
    assert_eq!(
        retry_result
            .expect_err("fixture transport has no retirement authenticator")
            .code(),
        "remote.transport.closed"
    );
    resumed_rx
        .recv()
        .await
        .expect("post-drain workflow failure may resume pairing");

    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("shutdown remains bounded after pending drain timeout");
    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("all pending-drain test owners must be joined"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_reset_singleflight_rejects_complete_drain_sharing_without_waiting_for_state() {
    let mut fixture = active_fixture("trust-reset-singleflight").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let _pairing_lane = install_yielded_test_transport(&manager).await;
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let (resumed_tx, mut resumed_rx) = tokio::sync::mpsc::unbounded_channel();
    let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::pending_drain_test_double(
                entered_tx,
                release_rx,
                resumed_tx,
                Some(completed_tx),
            ),
        );
    }

    let first_manager = Arc::clone(&manager);
    let first = tokio::spawn(async move {
        first_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    entered_rx
        .recv()
        .await
        .expect("first trust-reset attaches a drain waiter");

    let state_guard = manager.state.lock().await;
    release_tx.send(true).expect("complete the shared drain");
    completed_rx
        .await
        .expect("actor must publish Complete before the second request");
    assert!(!first.is_finished(), "first workflow is waiting for state");

    let second_error = tokio::time::timeout(
        Duration::from_millis(100),
        manager.trust_reset(
            TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                .expect("concurrent root-present reset"),
        ),
    )
    .await
    .expect("singleflight rejection must not wait for manager state")
    .expect_err("concurrent trust-reset must fail closed");
    assert_eq!(second_error.code(), "daemon.pairing.drain_pending");
    assert!(matches!(
        entered_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        resumed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    drop(state_guard);
    let first_error = tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .expect("first trust-reset must finish after state is released")
        .expect("join first trust-reset")
        .expect_err("fixture transport has no retirement authenticator");
    assert_eq!(first_error.code(), "remote.transport.closed");
    resumed_rx
        .recv()
        .await
        .expect("workflow failure must use completed-drain Resume");

    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("shutdown remains bounded after singleflight workflow");
    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("singleflight test drops all manager owners"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retire_pending_network_failure_keeps_control_owner_and_does_not_resume_pairing() {
    let mut fixture = active_fixture("retire-pending-no-reacquire").await;
    prepare_retirement(&fixture).await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let (mut pairing_lane, harness) = install_yielded_test_transport(&manager).await;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (resumed_tx, mut resumed_rx) = tokio::sync::oneshot::channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::drain_test_double(
                entered_tx,
                release_rx,
                resumed_tx,
                Ok(()),
            ),
        );
    }

    let operation_manager = Arc::clone(&manager);
    let operation = tokio::spawn(async move {
        operation_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present retry"),
            )
            .await
    });
    entered_rx.await.expect("pairing actor receives BeginDrain");
    release_tx.send(Ok(())).expect("complete pairing drain");
    tokio::time::timeout(Duration::from_secs(1), async {
        while harness.sent_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("RetirePending retry sends the frozen retirement");
    harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Error(RelayFailure::new(
                "relay.retirement.unavailable",
                "secret retirement detail",
            )),
        })
        .await;

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .expect("safe Relay failure returns without terminal timeout")
            .expect("join RetirePending retry")
            .expect_err("Relay failure keeps exact RetirePending retry")
            .code(),
        "relay.retirement.unavailable"
    );
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::RetirePending(_))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut resumed_rx)
            .await
            .is_err(),
        "RetirePending failure must not resume the Complete pairing fence"
    );

    harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Error(RelayFailure::new(
                "relay.control.retire_pending",
                "secret retained control detail",
            )),
        })
        .await;
    let control = {
        let mut state = manager.state.lock().await;
        tokio::time::timeout(
            Duration::from_millis(250),
            state
                .transport
                .as_mut()
                .expect("RetirePending transport remains owned")
                .next_control(),
        )
        .await
        .expect("control owner remains readable")
        .unwrap()
    };
    assert!(matches!(
        control,
        Some(crate::remote::transport::RemoteControl::SafeFailure(failure))
            if failure.code() == "relay.control.retire_pending"
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), pairing_lane.next_event())
            .await
            .is_err(),
        "RetirePending failure must not reacquire shared control for pairing"
    );

    drop(pairing_lane);
    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("RetirePending test drops operation owner"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_pending_pairing_drain_without_resuming_it() {
    let mut fixture = active_fixture("shutdown-pending-drain").await;
    let manager = Arc::new(RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    ));
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_release_tx, release_rx) = tokio::sync::watch::channel(false);
    let (resumed_tx, mut resumed_rx) = tokio::sync::mpsc::unbounded_channel();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.pairing_handle_for_test = Some(
            crate::remote::pairing::PairingCoordinatorHandle::pending_drain_test_double(
                entered_tx, release_rx, resumed_tx, None,
            ),
        );
    }

    let operation_manager = Arc::clone(&manager);
    let mut operation = tokio::spawn(async move {
        operation_manager
            .trust_reset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                    .expect("ordinary root-present reset"),
            )
            .await
    });
    entered_rx
        .recv()
        .await
        .expect("trust-reset enters pending pairing drain");

    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("shutdown must cancel pairing drain before taking manager mutex");
    let operation_result = match tokio::time::timeout(Duration::from_secs(1), &mut operation).await
    {
        Ok(result) => result.expect("join shutdown-canceled trust-reset"),
        Err(_) => {
            operation.abort();
            let _ = operation.await;
            panic!("shutdown-canceled pairing drain must return");
        }
    };
    assert_eq!(
        operation_result
            .expect_err("shutdown must fail the pending trust-reset")
            .code(),
        REMOTE_SHUTTING_DOWN
    );
    assert!(matches!(
        resumed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(manager.state.lock().await.stopped);
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::Active(_))
    ));
    assert!(
        fixture
            .keys
            .load(MACHINE_ROOT_SIGN_ACCOUNT)
            .unwrap()
            .is_some()
    );

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("all shutdown drain test owners must be joined"),
    };
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn manual_enroll_resume_requires_complete_identity_and_permit_before_endpoint() {
    for stage in [
        FixtureEnrollmentStage::Prepared,
        FixtureEnrollmentStage::Validated,
    ] {
        let label = match stage {
            FixtureEnrollmentStage::Prepared => "prepared-guard-blocked",
            FixtureEnrollmentStage::Validated => "validated-guard-blocked",
            FixtureEnrollmentStage::Unenrolled | FixtureEnrollmentStage::Active => unreachable!(),
        };
        let mut fixture = enrollment_fixture(label, stage).await;
        drop(fixture.identity.take());
        fixture
            .keys
            .delete(KEY_DIRECTORY_GUARD_ACCOUNT)
            .expect("simulate missing key-directory guard");
        let bootstrap =
            reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
                .await
                .expect("missing guard blocks remote only");
        let endpoint = CountingEnrollmentEndpoint::default();
        let endpoint_calls = Arc::clone(&endpoint.calls);
        let manager = RemoteManager::new(
            fixture.store.clone(),
            fixture.keys.clone(),
            fixture.config.clone(),
            bootstrap,
        )
        .with_enrollment_workflow(MachineEnrollmentWorkflow::with_endpoint(endpoint));

        let arm_error = manager
            .arm(remote_start_permit_for_test())
            .await
            .expect_err("incomplete identity cannot resume enrollment during arm");
        assert_eq!(arm_error.code(), "daemon.remote.identity.guard_missing");
        let enroll_error = manager
            .enroll(MachineEnrollRequest {
                bundle: fixture.bundle.clone(),
                scope: LocalOnlyAdministration::LocalOnly,
            })
            .await
            .expect_err("manual retry cannot bypass the identity and permit gate");
        assert_eq!(enroll_error.code(), "daemon.remote.identity.guard_missing");
        assert_eq!(
            endpoint_calls.load(Ordering::SeqCst),
            0,
            "blocked retry must not send enrollment code or contact the endpoint"
        );
        let durable = fixture
            .store
            .load_machine_enrollment_state()
            .await
            .expect("read blocked durable enrollment")
            .expect("durable enrollment remains present");
        assert!(matches!(
            (stage, durable),
            (
                FixtureEnrollmentStage::Prepared,
                MachineEnrollmentState::EnrollmentPrepared(_)
            ) | (
                FixtureEnrollmentStage::Validated,
                MachineEnrollmentState::EnrollmentResponseValidated(_)
            )
        ));
        finish_fixture(manager, fixture).await;
    }
}

#[tokio::test]
async fn nonactive_root_lost_states_reject_before_purge_marker_or_operator_receipt_prompt() {
    for stage in [
        FixtureEnrollmentStage::Prepared,
        FixtureEnrollmentStage::Validated,
    ] {
        let label = match stage {
            FixtureEnrollmentStage::Prepared => "prepared-root-lost-reset",
            FixtureEnrollmentStage::Validated => "validated-root-lost-reset",
            FixtureEnrollmentStage::Unenrolled | FixtureEnrollmentStage::Active => unreachable!(),
        };
        let mut fixture = enrollment_fixture(label, stage).await;
        drop(fixture.identity.take());
        fixture
            .keys
            .delete(MACHINE_ROOT_SIGN_ACCOUNT)
            .expect("simulate root loss");
        let bootstrap =
            reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
                .await
                .expect("root loss is a remote-only blocked bootstrap");
        let sink = Arc::new(RecordingPurgeSink::default());
        let manager = RemoteManager::new(
            fixture.store.clone(),
            fixture.keys.clone(),
            fixture.config.clone(),
            bootstrap,
        )
        .with_purge_plan_sink(sink.clone());
        manager
            .arm(remote_start_permit_for_test())
            .await
            .expect_err("non-Active root loss cannot resume enrollment");

        let error = manager
            .trust_reset(
                TrustResetRequest::for_uninstall_purge(
                    LocalOnlyAdministration::LocalOnly,
                    uninstall_plan(),
                    None,
                )
                .expect("typed uninstall purge request"),
            )
            .await
            .expect_err("non-Active root loss must not expose portable purge");
        assert_eq!(error.code(), "daemon.remote.enrollment.state_conflict");
        assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 0);
        assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
        let durable = fixture
            .store
            .load_machine_enrollment_state()
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            (stage, durable),
            (
                FixtureEnrollmentStage::Prepared,
                MachineEnrollmentState::EnrollmentPrepared(_)
            ) | (
                FixtureEnrollmentStage::Validated,
                MachineEnrollmentState::EnrollmentResponseValidated(_)
            )
        ));
        finish_fixture(manager, fixture).await;
    }

    let mut fixture = active_fixture("ret-pend-rootlost").await;
    prepare_retirement(&fixture).await;
    drop(fixture.identity.take());
    fixture
        .keys
        .delete(MACHINE_ROOT_SIGN_ACCOUNT)
        .expect("simulate root loss after durable retirement prepare");
    let bootstrap =
        reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
            .await
            .expect("retire-pending root loss remains remote-only blocked");
    let sink = Arc::new(RecordingPurgeSink::default());
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        bootstrap,
    )
    .with_purge_plan_sink(sink.clone());
    manager
        .arm(remote_start_permit_for_test())
        .await
        .expect_err("root-lost RetirePending cannot reconnect");
    let error = manager
        .trust_reset(
            TrustResetRequest::for_uninstall_purge(
                LocalOnlyAdministration::LocalOnly,
                uninstall_plan(),
                None,
            )
            .expect("typed pending uninstall purge request"),
        )
        .await
        .expect_err("RetirePending must not emit an unusable admin purge action");
    assert_eq!(error.code(), "daemon.remote.enrollment.state_conflict");
    assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::RetirePending(_))
    ));
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn enroll_retry_rejects_every_bundle_fork_before_network_in_all_replay_states() {
    for stage in [
        FixtureEnrollmentStage::Prepared,
        FixtureEnrollmentStage::Validated,
        FixtureEnrollmentStage::Active,
    ] {
        let mut fixture = enrollment_fixture("enroll-exact-input", stage).await;
        let endpoint = CountingEnrollmentEndpoint::default();
        let endpoint_calls = Arc::clone(&endpoint.calls);
        let manager = RemoteManager::new(
            fixture.store.clone(),
            fixture.keys.clone(),
            fixture.config.clone(),
            RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
        )
        .with_enrollment_workflow(MachineEnrollmentWorkflow::with_endpoint(endpoint));
        {
            let mut state = manager.state.lock().await;
            state.armed = true;
            state.start_permit = Some(remote_start_permit_for_test());
        }

        let mut forks = Vec::new();
        let mut code = fixture.bundle.clone();
        code.code.0[0] ^= 1;
        forks.push(code);
        let mut origin = fixture.bundle.clone();
        origin.public_wss_url = "wss://localhost:9/".to_owned();
        forks.push(origin);
        let mut pinset = fixture.bundle.clone();
        pinset.spki_pins[0].0[0] ^= 1;
        forks.push(pinset);
        let mut relay = fixture.bundle.clone();
        relay.relay_server_id = RelayServerId::from_bytes([0x99; 16]);
        forks.push(relay);
        let mut receipt_anchor = fixture.bundle.clone();
        receipt_anchor.receipt_verify_key.public_key.0[0] ^= 1;
        forks.push(receipt_anchor);
        let mut expiry = fixture.bundle.clone();
        expiry.expires_at_ms -= 1;
        forks.push(expiry);

        for fork in forks {
            let error = manager
                .enroll(MachineEnrollRequest {
                    bundle: fork,
                    scope: LocalOnlyAdministration::LocalOnly,
                })
                .await
                .expect_err("different enrollment input must not replay durable state");
            assert_eq!(error.code(), "daemon.remote.enrollment.state_conflict");
        }
        assert_eq!(endpoint_calls.load(Ordering::SeqCst), 0);
        let owner = manager.state.lock().await;
        assert!(owner.transport.is_none());
        assert!(owner.connect_retry.is_none());
        assert!(owner.start_permit.is_some());
        drop(owner);
        finish_fixture(manager, fixture).await;
    }
}

#[tokio::test]
async fn exact_prepared_retry_uses_frozen_expired_bundle_without_revalidation() {
    let mut fixture = enrollment_fixture_with_expiry(
        "enroll-expired-replay",
        FixtureEnrollmentStage::Prepared,
        2,
    )
    .await;
    let endpoint = CountingEnrollmentEndpoint::default();
    let endpoint_calls = Arc::clone(&endpoint.calls);
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_enrollment_workflow(MachineEnrollmentWorkflow::with_endpoint(endpoint));
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.start_permit = Some(remote_start_permit_for_test());
    }

    let error = manager
        .enroll(MachineEnrollRequest {
            bundle: fixture.bundle.clone(),
            scope: LocalOnlyAdministration::LocalOnly,
        })
        .await
        .expect_err("fixture endpoint proves exact frozen request was resumed");
    assert_eq!(error.code(), "test.enrollment.endpoint_called");
    assert_eq!(endpoint_calls.load(Ordering::SeqCst), 1);
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retire_pending_restart_connect_failure_preserves_exact_durable_retirement() {
    let mut fixture = active_fixture("retire-offline").await;
    prepare_retirement(&fixture).await;
    let before = fixture
        .store
        .load_machine_enrollment_state()
        .await
        .unwrap()
        .unwrap();
    let before_hash = match before {
        MachineEnrollmentState::RetirePending(value) => value.retirement.canonical_hash,
        _ => panic!("expected RetirePending"),
    };
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    tokio::time::timeout(
        Duration::from_secs(5),
        manager.arm(remote_start_permit_for_test()),
    )
    .await
    .expect("RetirePending reconnect is bounded")
    .expect_err("offline retirement reconnect remains blocked");
    let after = fixture
        .store
        .load_machine_enrollment_state()
        .await
        .unwrap()
        .unwrap();
    let MachineEnrollmentState::RetirePending(after) = after else {
        panic!("offline restart must preserve RetirePending")
    };
    assert_eq!(after.retirement.canonical_hash, before_hash);
    assert!(manager.state.lock().await.connect_retry.is_some());
    finish_fixture(manager, fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_committed_and_purge_absent_restart_finish_locally_without_transport() {
    for stage in ["relay-committed", "purge-absent"] {
        let mut fixture = active_fixture(stage).await;
        prepare_retirement(&fixture).await;
        let (bytes, hash) = record_retirement_terminal(&fixture.store).await;
        if stage == "purge-absent" {
            fixture
                .store
                .confirm_machine_purge_readback_absent(bytes, hash)
                .await
                .expect("prepare PurgeReadbackAbsent restart");
        }
        let manager = RemoteManager::new(
            fixture.store.clone(),
            fixture.keys.clone(),
            fixture.config.clone(),
            RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
        )
        .with_purge_plan_sink(Arc::new(RecordingPurgeSink::default()));
        manager
            .arm(remote_start_permit_for_test())
            .await
            .expect("post-Relay terminal recovery is local-only");
        let state = fixture
            .store
            .load_machine_enrollment_state()
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(state, MachineEnrollmentState::LocalDeleted(_)));
        let owner = manager.state.lock().await;
        assert!(owner.transport.is_none());
        assert!(owner.connect_retry.is_none());
        assert!(owner.start_permit.is_some());
        drop(owner);
        finish_fixture(manager, fixture).await;
    }
}

#[tokio::test]
async fn local_deleted_restart_keeps_ordinary_reset_and_authorizes_late_uninstall() {
    let mut fixture = active_fixture("deleted-marker").await;
    advance_to_local_deleted(&mut fixture).await;
    let Some(MachineEnrollmentState::LocalDeleted(local_deleted)) = fixture
        .store
        .load_machine_enrollment_state()
        .await
        .expect("load authenticated LocalDeleted")
    else {
        panic!("expected authenticated LocalDeleted")
    };
    AuthenticatedPurgeAuthorization::from_local_deleted(&fixture.store, &local_deleted)
        .expect("authenticated tombstone mints late purge authorization");
    let bootstrap =
        reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
            .await
            .expect("reconcile LocalDeleted");
    let sink = Arc::new(RecordingPurgeSink::default());
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        bootstrap,
    )
    .with_purge_plan_sink(sink.clone());
    manager
        .arm(remote_start_permit_for_test())
        .await
        .expect("LocalDeleted arm is network-free");
    {
        let mut state = manager.state.lock().await;
        let ordinary = TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
            .expect("ordinary reset request");
        let status = manager
            .trust_reset_locked(&mut state, ordinary)
            .await
            .expect("ordinary LocalDeleted reset replays");
        assert_eq!(status.lifecycle, WireLifecycle::LocalDeleted);
    }
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);

    let plan = uninstall_plan();
    for _ in 0..2 {
        let request = TrustResetRequest::for_uninstall_purge(
            LocalOnlyAdministration::LocalOnly,
            plan.clone(),
            None,
        )
        .expect("late uninstall purge request");
        let status = manager
            .trust_reset(request)
            .await
            .expect("authenticated LocalDeleted authorizes or replays late finalization");
        assert_eq!(status.lifecycle, WireLifecycle::LocalDeleted);
    }
    let enroll_error = manager
        .enroll(MachineEnrollRequest {
            bundle: fixture.bundle.clone(),
            scope: LocalOnlyAdministration::LocalOnly,
        })
        .await
        .expect_err("purge latch blocks LocalDeleted re-enrollment");
    assert_eq!(enroll_error.code(), "daemon.purge.recovery_required");
    assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 2);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        sink.reserve_plan_ids.lock().unwrap().as_slice(),
        &[*plan.plan_id(), *plan.plan_id()]
    );
    assert_eq!(
        sink.plan_ids.lock().unwrap().as_slice(),
        &[*plan.plan_id(), *plan.plan_id()]
    );
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn unenrolled_machine_authorizes_uninstall_without_remote_retirement() {
    let mut fixture = unenrolled_fixture("unenrolled-uninstall").await;
    let identity_state = fixture
        .store
        .load_machine_identity_state()
        .await
        .expect("load authenticated machine identity")
        .expect("unenrolled machine identity exists");
    AuthenticatedPurgeAuthorization::from_unenrolled_identity(&fixture.store, &identity_state)
        .expect("authenticated no-remote state mints purge authorization");
    let sink = Arc::new(RecordingPurgeSink::default());
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_purge_plan_sink(sink.clone());
    manager
        .arm(remote_start_permit_for_test())
        .await
        .expect("unenrolled manager arms without network");

    let plan = uninstall_plan();
    for _ in 0..2 {
        let request = TrustResetRequest::for_uninstall_purge(
            LocalOnlyAdministration::LocalOnly,
            plan.clone(),
            None,
        )
        .expect("unenrolled uninstall purge request");
        let status = manager
            .trust_reset(request)
            .await
            .expect("authenticated local identity authorizes or replays purge");
        assert_eq!(status.lifecycle, WireLifecycle::Unenrolled);
    }
    let enroll_error = manager
        .enroll(MachineEnrollRequest {
            bundle: fixture.bundle.clone(),
            scope: LocalOnlyAdministration::LocalOnly,
        })
        .await
        .expect_err("purge latch blocks a new enrollment after reply loss");
    assert_eq!(enroll_error.code(), "daemon.purge.recovery_required");
    assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 2);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        sink.reserve_plan_ids.lock().unwrap().as_slice(),
        &[*plan.plan_id(), *plan.plan_id()]
    );
    assert_eq!(
        sink.plan_ids.lock().unwrap().as_slice(),
        &[*plan.plan_id(), *plan.plan_id()]
    );
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn unenrolled_purge_rejects_incomplete_local_identity_before_reservation() {
    let mut fixture = unenrolled_fixture("unenrolled-purge-blocked").await;
    drop(fixture.identity.take());
    fixture
        .keys
        .delete(KEY_DIRECTORY_GUARD_ACCOUNT)
        .expect("simulate incomplete local identity");
    let bootstrap =
        reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
            .await
            .expect("reconcile incomplete unenrolled identity");
    let sink = Arc::new(RecordingPurgeSink::default());
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        bootstrap,
    )
    .with_purge_plan_sink(sink.clone());
    manager
        .arm(remote_start_permit_for_test())
        .await
        .expect("local listener remains available for blocked remote identity");

    let request = TrustResetRequest::for_uninstall_purge(
        LocalOnlyAdministration::LocalOnly,
        uninstall_plan(),
        None,
    )
    .expect("blocked unenrolled purge request");
    let error = manager
        .trust_reset(request)
        .await
        .expect_err("incomplete local identity cannot authorize purge");
    assert_eq!(error.code(), "daemon.remote.identity.guard_missing");
    assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn startup_purge_intent_fences_unenrolled_and_local_deleted_enrollment() {
    for local_deleted in [false, true] {
        let mut fixture = if local_deleted {
            let mut fixture = active_fixture("startup-local-deleted-purge").await;
            advance_to_local_deleted(&mut fixture).await;
            fixture
        } else {
            unenrolled_fixture("startup-unenrolled-purge").await
        };
        let bootstrap = if local_deleted {
            reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
                .await
                .expect("reconcile LocalDeleted restart")
        } else {
            RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap())
        };
        let sink = Arc::new(RecordingPurgeSink::default());
        sink.intent_present.store(true, Ordering::SeqCst);
        sink.resume_ready.store(true, Ordering::SeqCst);
        let manager = RemoteManager::new(
            fixture.store.clone(),
            fixture.keys.clone(),
            fixture.config.clone(),
            bootstrap,
        )
        .with_purge_plan_sink(sink.clone());
        manager
            .arm(remote_start_permit_for_test())
            .await
            .expect("startup resumes authenticated purge marker without enrollment");

        let error = manager
            .enroll(MachineEnrollRequest {
                bundle: fixture.bundle.clone(),
                scope: LocalOnlyAdministration::LocalOnly,
            })
            .await
            .expect_err("durable purge intent fences every enrollment mutation");
        assert_eq!(error.code(), "daemon.purge.recovery_required");
        assert_eq!(sink.intent_calls.load(Ordering::SeqCst), 1);
        assert_eq!(sink.resume_calls.load(Ordering::SeqCst), 1);
        let state = manager.state.lock().await;
        assert!(state.purge_pending);
        assert!(state.identity.is_none());
        assert!(state.transport.is_none());
        drop(state);
        finish_fixture(manager, fixture).await;
    }
}

#[tokio::test]
async fn uninstall_at_purge_absent_authorizes_marker_without_machine_cleanup() {
    let mut fixture = active_fixture("purge-absent-uninstall").await;
    advance_to_purge_absent(&fixture).await;
    let sink = Arc::new(RecordingPurgeSink::default());
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_purge_plan_sink(sink.clone());
    let plan = uninstall_plan();
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.start_permit = Some(remote_start_permit_for_test());
    }
    for _ in 0..2 {
        let request = TrustResetRequest::for_uninstall_purge(
            LocalOnlyAdministration::LocalOnly,
            plan.clone(),
            None,
        )
        .expect("uninstall purge request");
        let mut state = manager.state.lock().await;
        let status = manager
            .trust_reset_locked(&mut state, request)
            .await
            .expect("purge marker exact replay");
        assert_eq!(status.lifecycle, WireLifecycle::PurgeReadbackAbsent);
    }
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
    ));
    assert!(
        fixture
            .keys
            .load(MACHINE_ROOT_SIGN_ACCOUNT)
            .unwrap()
            .is_some()
    );
    assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 2);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn startup_reserved_marker_keeps_purge_absent_and_machine_keys_for_finalizer() {
    let mut fixture = active_fixture("reserved-startup").await;
    advance_to_purge_absent(&fixture).await;
    let sink = Arc::new(RecordingPurgeSink::default());
    sink.resume_ready.store(true, Ordering::SeqCst);
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_purge_plan_sink(sink.clone());
    manager
        .arm(remote_start_permit_for_test())
        .await
        .expect("reserved marker startup is purge-ready");
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
    ));
    assert!(
        fixture
            .keys
            .load(MACHINE_ROOT_SIGN_ACCOUNT)
            .unwrap()
            .is_some()
    );
    assert_eq!(sink.resume_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager.status().await.unwrap().lifecycle,
        WireLifecycle::PurgeReadbackAbsent
    );
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn prior_reserved_marker_cannot_be_bypassed_by_ordinary_trust_reset_retry() {
    let mut fixture = active_fixture("reserved-ordinary-retry").await;
    advance_to_purge_absent(&fixture).await;
    let sink = Arc::new(RecordingPurgeSink::default());
    sink.resume_ready.store(true, Ordering::SeqCst);
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_purge_plan_sink(sink.clone());
    let request = TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
        .expect("ordinary retry request");
    let status = {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.start_permit = Some(remote_start_permit_for_test());
        manager
            .trust_reset_locked(&mut state, request)
            .await
            .expect("durable uninstall intent wins over request shape")
    };

    assert_eq!(status.lifecycle, WireLifecycle::PurgeReadbackAbsent);
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
    ));
    assert!(
        fixture
            .keys
            .load(MACHINE_ROOT_SIGN_ACCOUNT)
            .unwrap()
            .is_some()
    );
    assert_eq!(sink.resume_calls.load(Ordering::SeqCst), 1);
    assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn uninstall_purge_preflight_failure_precedes_local_cleanup() {
    let mut fixture = active_fixture("purge-preflight").await;
    advance_to_purge_absent(&fixture).await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_purge_plan_sink(Arc::new(RejectingPurgeSink));
    let plan = uninstall_plan();
    let request =
        TrustResetRequest::for_uninstall_purge(LocalOnlyAdministration::LocalOnly, plan, None)
            .expect("uninstall purge request");
    let error = {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.start_permit = Some(remote_start_permit_for_test());
        manager
            .trust_reset_locked(&mut state, request)
            .await
            .expect_err("preflight failure must abort before cleanup")
    };
    assert_eq!(error.code(), "daemon.purge.preflight_failed");
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
    ));
    assert!(
        fixture
            .keys
            .load(MACHINE_ROOT_SIGN_ACCOUNT)
            .unwrap()
            .is_some(),
        "preflight failure must not delete machine identity"
    );
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn uninstall_reservation_failure_precedes_active_transport_or_trust_reset_mutation() {
    let mut fixture = active_fixture("purge-active-preflight").await;
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    )
    .with_purge_plan_sink(Arc::new(RejectingPurgeSink));
    let request = TrustResetRequest::for_uninstall_purge(
        LocalOnlyAdministration::LocalOnly,
        uninstall_plan(),
        None,
    )
    .expect("uninstall purge request");
    let error = {
        let mut state = manager.state.lock().await;
        state.armed = true;
        state.start_permit = Some(remote_start_permit_for_test());
        manager
            .trust_reset_locked(&mut state, request)
            .await
            .expect_err("reservation failure must precede transport and trust reset")
    };
    assert_eq!(error.code(), "daemon.purge.preflight_failed");
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::Active(_))
    ));
    assert!(
        fixture
            .keys
            .load(MACHINE_ROOT_SIGN_ACCOUNT)
            .unwrap()
            .is_some()
    );
    let state = manager.state.lock().await;
    assert!(state.identity.is_some());
    assert!(state.transport.is_none());
    assert!(state.connect_retry.is_none());
    drop(state);
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn root_lost_without_receipt_returns_blocked_old_axes_and_zero_network() {
    let mut fixture = active_fixture("root-lost-status").await;
    fixture
        .keys
        .delete(MACHINE_ROOT_SIGN_ACCOUNT)
        .expect("simulate missing root");
    drop(fixture.identity.take());
    let bootstrap =
        reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
            .await
            .expect("root-lost bootstrap is remote-only blocked");
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        bootstrap,
    );
    manager
        .arm(remote_start_permit_for_test())
        .await
        .expect_err("Active root-lost cannot start a transport");
    let request = TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
        .expect("root-lost status request");
    let status = {
        let mut state = manager.state.lock().await;
        manager
            .trust_reset_locked(&mut state, request)
            .await
            .expect("missing receipt is actionable Blocked status")
    };
    assert_eq!(status.lifecycle, WireLifecycle::Blocked);
    assert_eq!(
        status.failure_code.unwrap().as_str(),
        "daemon.remote.trust_reset.admin_receipt_required"
    );
    assert!(status.relay_server_id.is_some());
    assert!(status.machine_route.is_some());
    assert!(status.root_fingerprint.is_some());
    assert!(manager.state.lock().await.transport.is_none());
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::Active(_))
    ));
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn no_pairing_owner_rejects_active_authorization_before_retirement_or_network() {
    let mut fixture = active_fixture("ownerless-active").await;
    let authorization_store = crate::runtime::store::active_authorization_store_for_test(
        &fixture.root.join("authorization-active.db"),
    )
    .await;
    assert!(
        authorization_store
            .list_pairing_recovery()
            .await
            .expect("read ownerless pairing recovery")
            .is_empty(),
        "the regression fixture must contain no remote_pairings rows"
    );
    let before_targets = authorization_store
        .list_revocation_drain_targets()
        .await
        .expect("read active authorization target");
    assert_eq!(before_targets.len(), 1);
    let before_grant = before_targets[0].grant().clone();
    assert!(
        authorization_store
            .list_revocation_recovery()
            .await
            .expect("read active authorization recovery")
            .is_empty()
    );

    let manager = RemoteManager::new(
        authorization_store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        assert!(state.pairing.is_none());
        assert!(state.pairing_handle_for_test.is_none());
        assert!(state.transport.is_none());
        assert!(state.connect_retry.is_none());
        assert!(state.start_permit.is_none());
    }

    let error = manager
        .trust_reset(
            TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                .expect("ordinary root-present reset"),
        )
        .await
        .expect_err("ownerless active authorization must block retirement");
    assert_eq!(error.code(), "daemon.pairing.active");
    assert!(matches!(
        authorization_store
            .load_machine_enrollment_state()
            .await
            .expect("read post-preflight enrollment"),
        Some(MachineEnrollmentState::Active(_))
    ));
    let after_targets = authorization_store
        .list_revocation_drain_targets()
        .await
        .expect("read post-preflight authorization target");
    assert_eq!(after_targets.len(), 1);
    assert_eq!(after_targets[0].grant(), &before_grant);
    let state = manager.state.lock().await;
    assert!(state.transport.is_none());
    assert!(state.connect_retry.is_none());
    assert!(state.start_permit.is_none());
    drop(state);

    finish_split_store_fixture(manager, authorization_store, fixture).await;
}

#[tokio::test]
async fn no_pairing_owner_rejects_revoking_authorization_before_retirement_or_network() {
    let mut fixture = active_fixture("ownerless-revoking").await;
    let authorization_store = crate::runtime::store::revoking_authorization_store_for_test(
        &fixture.root.join("authorization-revoking.db"),
    )
    .await;
    assert!(
        authorization_store
            .list_pairing_recovery()
            .await
            .expect("read ownerless pairing recovery")
            .is_empty(),
        "the regression fixture must contain no remote_pairings rows"
    );
    assert!(
        authorization_store
            .list_revocation_drain_targets()
            .await
            .expect("read revoking drain targets")
            .is_empty()
    );
    let before_recovery = authorization_store
        .list_revocation_recovery()
        .await
        .expect("read ownerless revocation recovery");
    assert_eq!(before_recovery.len(), 1);
    let before_frame = before_recovery[0].canonical_next_frame().to_vec();
    let before_revocation = before_recovery[0].revocation().clone();

    let manager = RemoteManager::new(
        authorization_store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        RemoteBootstrapOutcome::Active(fixture.identity.take().unwrap()),
    );
    {
        let mut state = manager.state.lock().await;
        state.armed = true;
        assert!(state.pairing.is_none());
        assert!(state.pairing_handle_for_test.is_none());
        assert!(state.transport.is_none());
        assert!(state.connect_retry.is_none());
        assert!(state.start_permit.is_none());
    }

    let error = manager
        .trust_reset(
            TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
                .expect("ordinary root-present reset"),
        )
        .await
        .expect_err("ownerless revocation recovery must block retirement");
    assert_eq!(error.code(), "daemon.pairing.active");
    assert!(matches!(
        authorization_store
            .load_machine_enrollment_state()
            .await
            .expect("read post-preflight enrollment"),
        Some(MachineEnrollmentState::Active(_))
    ));
    let after_recovery = authorization_store
        .list_revocation_recovery()
        .await
        .expect("read post-preflight revocation recovery");
    assert_eq!(after_recovery.len(), 1);
    assert_eq!(after_recovery[0].canonical_next_frame(), before_frame);
    assert_eq!(after_recovery[0].revocation(), &before_revocation);
    let state = manager.state.lock().await;
    assert!(state.transport.is_none());
    assert!(state.connect_retry.is_none());
    assert!(state.start_permit.is_none());
    drop(state);

    finish_split_store_fixture(manager, authorization_store, fixture).await;
}

#[tokio::test]
async fn portable_root_lost_receipt_bypasses_pair_route_recovery_and_scrubs_before_cleanup() {
    let mut fixture = active_fixture("root-lost-pairing-recovery").await;
    let active = active_state(&fixture.store).await;
    seed_open_pairing_recovery(&fixture.store, &active).await;
    let receipt = portable_admin_purge_receipt(&active);
    assert_eq!(
        fixture
            .store
            .list_pairing_recovery()
            .await
            .expect("read seeded pairing recovery")
            .len(),
        1
    );

    fixture
        .keys
        .delete(MACHINE_ROOT_SIGN_ACCOUNT)
        .expect("simulate root loss with durable pairing recovery");
    drop(fixture.identity.take());
    let bootstrap =
        reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
            .await
            .expect("root-lost pairing bootstrap is remote-only blocked");
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        bootstrap,
    )
    .with_purge_plan_sink(Arc::new(RecordingPurgeSink::default()));
    manager
        .arm(remote_start_permit_for_test())
        .await
        .expect_err("root-lost state cannot start transport or pairing actor");

    let request =
        TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, Some(Box::new(receipt)))
            .expect("typed portable root-lost request");
    let status = manager
        .trust_reset(request)
        .await
        .expect("signed absent proof atomically supersedes pending PairRoute close");
    assert_eq!(status.lifecycle, WireLifecycle::LocalDeleted);
    assert!(
        fixture
            .store
            .list_pairing_recovery()
            .await
            .expect("read post-cleanup pairing recovery")
            .is_empty()
    );
    assert!(matches!(
        fixture.store.load_machine_enrollment_state().await.unwrap(),
        Some(MachineEnrollmentState::LocalDeleted(_))
    ));
    finish_fixture(manager, fixture).await;
}

#[tokio::test]
async fn partial_nonroot_identity_requires_portable_receipt_and_cleans_existing_items_only() {
    for missing in [
        MACHINE_HPKE_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_DATA_SIGN_ACCOUNT,
    ] {
        let mut fixture = active_fixture("partial-admin-purge").await;
        let active = active_state(&fixture.store).await;
        let receipt = portable_admin_purge_receipt(&active);
        drop(fixture.identity.take());
        fixture
            .keys
            .delete(missing)
            .expect("simulate missing non-root identity item");
        let bootstrap =
            reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
                .await
                .expect("partial identity bootstrap remains remote-only blocked");
        let sink = Arc::new(RecordingPurgeSink::default());
        let manager = RemoteManager::new(
            fixture.store.clone(),
            fixture.keys.clone(),
            fixture.config.clone(),
            bootstrap,
        )
        .with_purge_plan_sink(sink.clone());
        manager
            .arm(remote_start_permit_for_test())
            .await
            .expect_err("partial identity cannot arm online retirement");

        let ordinary = TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None)
            .expect("ordinary partial reset request");
        let status = {
            let mut state = manager.state.lock().await;
            manager
                .trust_reset_locked(&mut state, ordinary)
                .await
                .expect("partial identity must expose portable receipt requirement")
        };
        assert_eq!(status.lifecycle, WireLifecycle::Blocked);
        assert_eq!(
            status.failure_code.unwrap().as_str(),
            "daemon.remote.trust_reset.admin_receipt_required"
        );

        let portable =
            TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, Some(Box::new(receipt)))
                .expect("portable partial reset request");
        let status = {
            let mut state = manager.state.lock().await;
            manager
                .trust_reset_locked(&mut state, portable)
                .await
                .expect("authenticated portable receipt cleans remaining identity")
        };
        assert_eq!(status.lifecycle, WireLifecycle::LocalDeleted);
        for account in [
            MACHINE_ROOT_SIGN_ACCOUNT,
            MACHINE_HPKE_ACCOUNT,
            MACHINE_LINK_SIGN_ACCOUNT,
            MACHINE_DATA_SIGN_ACCOUNT,
            KEY_DIRECTORY_GUARD_ACCOUNT,
        ] {
            assert!(
                fixture.keys.load(account).unwrap().is_none(),
                "cleanup must leave {account} absent"
            );
        }

        let late = TrustResetRequest::for_uninstall_purge(
            LocalOnlyAdministration::LocalOnly,
            uninstall_plan(),
            None,
        )
        .expect("late root-lost uninstall request");
        let status = manager
            .trust_reset(late)
            .await
            .expect("root-lost LocalDeleted authorizes late full purge");
        assert_eq!(status.lifecycle, WireLifecycle::LocalDeleted);
        assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 1);
        assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
        finish_fixture(manager, fixture).await;
    }
}

#[tokio::test]
async fn ordinary_cleanup_crash_restart_reaches_local_deleted_without_purge_marker() {
    let mut fixture = active_fixture("cleanup-restart-status").await;
    advance_to_purge_absent(&fixture).await;
    drop(fixture.identity.take());
    fixture
        .keys
        .delete(MACHINE_DATA_SIGN_ACCOUNT)
        .expect("simulate cleanup crash after first deletion");
    let bootstrap =
        reconcile_machine_identity(&fixture.config, &fixture.store, fixture.keys.as_ref())
            .await
            .expect("cleanup prefix bootstrap remains remote-only blocked");
    let sink = Arc::new(RecordingPurgeSink::default());
    let manager = RemoteManager::new(
        fixture.store.clone(),
        fixture.keys.clone(),
        fixture.config.clone(),
        bootstrap,
    )
    .with_purge_plan_sink(sink.clone());
    manager
        .arm(remote_start_permit_for_test())
        .await
        .expect("restart resumes authenticated cleanup locally");

    let status = manager.status().await.expect("read recovered status");
    assert_eq!(status.lifecycle, WireLifecycle::LocalDeleted);
    assert!(status.failure_code.is_none());

    assert_eq!(sink.resume_calls.load(Ordering::SeqCst), 1);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink.reserve_calls.load(Ordering::SeqCst), 0);
    finish_fixture(manager, fixture).await;
}
