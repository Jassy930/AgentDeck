use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{
    HpkePrivateKey, SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256,
    sign_relay_admin_purge_receipt,
};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, PairInviteV1};
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
use crate::remote::bootstrap::{RemoteBootstrapOutcome, reconcile_machine_identity};
use crate::remote::cleanup::MachineCleanupWorkflow;
use crate::remote::config::ValidatedEnrollmentConfig;
use crate::remote::enrollment::FrozenMachineEnrollment;
use crate::remote::identity::{
    KEY_DIRECTORY_GUARD_ACCOUNT, MACHINE_DATA_SIGN_ACCOUNT, MACHINE_HPKE_ACCOUNT,
    MACHINE_LINK_SIGN_ACCOUNT, MACHINE_ROOT_SIGN_ACCOUNT,
};
use crate::remote::workflow::{EnrollmentEndpoint, MachineEnrollmentWorkflow};
use crate::runtime::RevocationAdministration;
use crate::runtime::remote_administration::RemoteAdministration;
use crate::runtime::store::IdempotencyOwner;
use crate::runtime::store::pairing::{PreparePairingInvite, PreparePairingInviteOutcome};
use crate::runtime::store::{
    ActiveMachineEnrollmentState, LocalDeletedMachineEnrollmentState, MachineEnrollmentState,
    MachineRemoteLifecycle, MachineRemoteStateRecord, MachineTrustResetKind, RuntimeStoreConfig,
    RuntimeStoreHandle,
};
use crate::security::{KeyStore, MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

use super::{
    PurgePlanSink, PurgeReservationResume, REMOTE_DISABLED, REMOTE_SHUTTING_DOWN, RemoteManager,
    admin_error, status_from_state,
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
async fn transient_pairing_transport_health_clears_back_to_active_without_sticky_block() {
    let fixture = active_fixture("pairing-health").await;
    let durable = fixture.store.load_machine_enrollment_state().await.unwrap();
    let blocked =
        status_from_state(durable.as_ref(), Some("remote.transport.closed"), false).unwrap();
    assert_eq!(blocked.lifecycle, WireLifecycle::Blocked);
    assert_eq!(
        blocked.failure_code.unwrap().as_str(),
        "remote.transport.closed"
    );

    let recovered = status_from_state(durable.as_ref(), None, false).unwrap();
    assert_eq!(recovered.lifecycle, WireLifecycle::Active);
    assert!(recovered.failure_code.is_none());

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
    assert_eq!(operation.await.unwrap().unwrap(), expected);

    let manager = match Arc::try_unwrap(manager) {
        Ok(manager) => manager,
        Err(_) => panic!("revocation test drops all manager owners"),
    };
    drop(manager);
    fixture.store.shutdown().await.unwrap();
    let _ = fs::remove_dir_all(fixture.root);
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
            .expect_err("fixture has no start permit after drain completes")
            .code(),
        "daemon.remote.start_not_armed"
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
        .expect_err("fixture has no start permit");
    assert_eq!(first_error.code(), "daemon.remote.start_not_armed");
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
