//! Relay v2 challenge / MachineLink / DeviceLink / PairingAccess 端到端契约。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use agentdeck_crypto::{
    SigningKey, VerifyingKey, sha256, sign_authentication_transcript, sign_tbs,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, CertRole,
};
use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_CHALLENGE_EXPIRED, RELAY_AUTH_INVALID_GRANT, RELAY_AUTH_REPLAY, RELAY_AUTH_REVOKED,
    RELAY_QUOTA_EXCEEDED, RELAY_ROUTE_FORBIDDEN, RELAY_ROUTE_NOT_FOUND, RELAY_STORE_UNAVAILABLE,
    RELAY_VERSION_UNSUPPORTED,
};
use agentdeck_protocol::relay_v2::frame::{
    AuthProof, Authenticate, ClosePairRoute, InstallGrant, OpenPairRoute, PairData, Publish,
    SealedBlob, Send, Subscribe,
};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial,
    LinkGeneration, MachineRouteId, OpaqueRouteFrame, PairRouteId, PublicKeyBytes,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayGrant, RelayServerId, RequestRouteId, RootKeyId,
    SignedCertificate, StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_relay::v2::auth::{
    AccessContext, ActivePairRoute, AuthenticationTrust, AuthenticationTrustView,
    AuthorizationCoordinator, AuthorizationLifecycleEvent, ChallengeLimits, ChallengeRegistry,
    ChallengeRoute, ChallengeSource, MonotonicClock, PairRouteView, PairingHello, PrincipalRoute,
    TokenBucketLimits, authorize_pairing_route, verify_authentication,
};
use agentdeck_relay::v2::store::{
    Clock, CommitMachineLinkAuth, ConfirmDeviceAuth, EnrollmentCodeSeed, FaultInjector, FaultPoint,
    InstallGrantRecord, MAX_CONTROL_BLOB_BYTES, PersistRevocation, PurgeMachine, RegisterMachine,
    RelayStoreHandle, RelayV2StoreConfig, StoreError,
};
use tempfile::TempDir;

const NOW_MS: u64 = 1_726_000_000_000;

#[derive(Default)]
struct ManualMonotonicClock(AtomicU64);

impl ManualMonotonicClock {
    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl MonotonicClock for ManualMonotonicClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct FixedStoreClock;

impl Clock for FixedStoreClock {
    fn now_ms(&self) -> Result<u64, StoreError> {
        Ok(NOW_MS)
    }
}

#[derive(Debug)]
struct ArmedLinkAuthFault {
    point: FaultPoint,
    remaining: AtomicU64,
}

impl ArmedLinkAuthFault {
    fn new(point: FaultPoint) -> Self {
        Self {
            point,
            remaining: AtomicU64::new(0),
        }
    }

    fn arm(&self) {
        self.arm_times(1);
    }

    fn arm_times(&self, count: u64) {
        self.remaining.store(count, Ordering::SeqCst);
    }
}

impl FaultInjector for ArmedLinkAuthFault {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point
            && self
                .remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            Err(StoreError::InjectedFault(point))
        } else {
            Ok(())
        }
    }
}

impl Default for ArmedLinkAuthFault {
    fn default() -> Self {
        Self::new(FaultPoint::MachineLinkAuthBeforeCommit)
    }
}

struct BlockingFault {
    point: FaultPoint,
    armed: AtomicBool,
    state: Mutex<BlockingFaultState>,
    changed: Condvar,
}

#[derive(Default)]
struct BlockingFaultState {
    entered: bool,
    released: bool,
}

struct BlockingReleaseGuard {
    fault: Arc<BlockingFault>,
    released: bool,
}

impl BlockingReleaseGuard {
    fn release(mut self) {
        self.fault.release_inner();
        self.released = true;
    }
}

impl Drop for BlockingReleaseGuard {
    fn drop(&mut self) {
        if !self.released {
            self.fault.release_inner();
        }
    }
}

impl BlockingFault {
    fn new(point: FaultPoint) -> Self {
        Self {
            point,
            armed: AtomicBool::new(false),
            state: Mutex::new(BlockingFaultState::default()),
            changed: Condvar::new(),
        }
    }

    fn arm(self: &Arc<Self>) -> BlockingReleaseGuard {
        let mut state = self.state.lock().expect("blocking fault state");
        state.entered = false;
        state.released = false;
        drop(state);
        self.armed.store(true, Ordering::SeqCst);
        BlockingReleaseGuard {
            fault: self.clone(),
            released: false,
        }
    }

    async fn wait_until_entered(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self.state.lock().expect("blocking fault state").entered {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking fault hook must be reached within 5 seconds");
    }

    fn release_inner(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.released = true;
            self.changed.notify_all();
        }
    }
}

impl FaultInjector for BlockingFault {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point && self.armed.swap(false, Ordering::SeqCst) {
            let mut state = self
                .state
                .lock()
                .map_err(|_| StoreError::InjectedFault(point))?;
            state.entered = true;
            self.changed.notify_all();
            let (state, timeout) = self
                .changed
                .wait_timeout_while(state, Duration::from_secs(5), |state| !state.released)
                .map_err(|_| StoreError::InjectedFault(point))?;
            if timeout.timed_out() && !state.released {
                return Err(StoreError::InjectedFault(point));
            }
        }
        Ok(())
    }
}

fn store_path(temp: &TempDir) -> PathBuf {
    temp.path().join("relay-private").join("relay.db")
}

fn store_config(path: &Path) -> RelayV2StoreConfig {
    RelayV2StoreConfig::new(path.to_path_buf()).with_clock(Arc::new(FixedStoreClock))
}

fn machine(seed: u8) -> MachineRouteId {
    MachineRouteId::from_bytes([seed; 16])
}

fn device(seed: u8) -> DeviceRouteId {
    DeviceRouteId::from_bytes([seed; 16])
}

fn connection(value: u128) -> ConnectionInstanceId {
    ConnectionInstanceId::from_bytes(value.to_be_bytes())
}

fn source(value: u64) -> ChallengeSource {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    ChallengeSource::from_bytes(bytes)
}

#[allow(clippy::too_many_arguments)]
fn signed_certificate(
    root: &SigningKey,
    subject: &SigningKey,
    server: RelayServerId,
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    generation: LinkGeneration,
    role: CertRole,
    not_after_ms: Option<u64>,
) -> SignedCertificate {
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
        cert_role: role,
        generation,
        root_key_id,
        trust_epoch,
        not_after_ms,
        signature: Ed25519Signature([0; 64]),
    };
    certificate.signature = sign_tbs(
        root,
        &certificate.to_be_signed_v1(
            server,
            machine_route,
            sha256(&root.verifying_key().to_bytes()),
        ),
    )
    .into();
    certificate
}

#[allow(clippy::too_many_arguments)]
fn signed_grant(
    root: &SigningKey,
    device_key: &SigningKey,
    server: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    serial: GrantSerial,
) -> RelayGrant {
    let mut grant = RelayGrant {
        machine_route,
        device_route,
        device_sign_pubkey: PublicKeyBytes(device_key.verifying_key().to_bytes()),
        grant_serial: serial,
        root_key_id,
        trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    grant.signature = sign_tbs(
        root,
        &grant.to_be_signed_v1(server, sha256(&root.verifying_key().to_bytes())),
    )
    .into();
    grant
}

struct Fixture {
    _temp: TempDir,
    path: PathBuf,
    store: RelayStoreHandle,
    server: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    root: SigningKey,
    link: SigningKey,
    device: SigningKey,
    link_cert: SignedCertificate,
    grant: RelayGrant,
    link_auth_fault: Option<Arc<ArmedLinkAuthFault>>,
}

impl Fixture {
    async fn new() -> Self {
        Self::new_inner(None, None).await
    }

    async fn with_link_auth_fault() -> Self {
        Self::new_inner(Some(Arc::new(ArmedLinkAuthFault::default())), None).await
    }

    async fn with_link_auth_after_commit_fault() -> Self {
        Self::new_inner(
            Some(Arc::new(ArmedLinkAuthFault::new(
                FaultPoint::MachineLinkAuthAfterCommit,
            ))),
            None,
        )
        .await
    }

    async fn with_blocking_fault(point: FaultPoint) -> (Self, Arc<BlockingFault>) {
        let fault = Arc::new(BlockingFault::new(point));
        let fixture = Self::new_inner(None, Some(fault.clone())).await;
        (fixture, fault)
    }

    async fn new_inner(
        link_auth_fault: Option<Arc<ArmedLinkAuthFault>>,
        injected_fault: Option<Arc<dyn FaultInjector>>,
    ) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = store_path(&temp);
        let mut config = store_config(&path);
        if let Some(fault) = &link_auth_fault {
            config = config.with_fault_injector(fault.clone());
        } else if let Some(fault) = injected_fault {
            config = config.with_fault_injector(fault);
        }
        let store = RelayStoreHandle::open(config).await.expect("open v2 store");
        let server = store.inspect().await.expect("inspect").relay_server_id;
        let machine_route = machine(0x11);
        let device_route = device(0x22);
        let root_key_id = RootKeyId::from_bytes([0x33; 16]);
        let trust_epoch = TrustEpoch::new(3);
        let root = SigningKey::from_seed(&[0x41; 32]);
        let link = SigningKey::from_seed(&[0x42; 32]);
        let data = SigningKey::from_seed(&[0x43; 32]);
        let device_key = SigningKey::from_seed(&[0x44; 32]);
        let link_cert = signed_certificate(
            &root,
            &link,
            server,
            machine_route,
            root_key_id,
            trust_epoch,
            LinkGeneration::new(1),
            CertRole::Link,
            Some(NOW_MS + 60_000),
        );
        let data_cert = signed_certificate(
            &root,
            &data,
            server,
            machine_route,
            root_key_id,
            trust_epoch,
            LinkGeneration::new(1),
            CertRole::Data,
            Some(NOW_MS + 60_000),
        );
        let code_hash = [0x51; 32];
        store
            .seed_enrollment_code(EnrollmentCodeSeed {
                code_hash,
                expires_at_ms: NOW_MS + 60_000,
            })
            .await
            .expect("seed enrollment");
        store
            .register_machine(RegisterMachine {
                code_hash,
                request_hash: [0x52; 32],
                response_blob: vec![0x53],
                receipt_hash: [0x54; 32],
                machine_route,
                root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
                link_cert: link_cert.clone(),
                data_cert: data_cert.clone(),
                link_cert_hash: link_cert.canonical_sha256(),
                data_cert_hash: data_cert.canonical_sha256(),
            })
            .await
            .expect("register machine");
        let grant = signed_grant(
            &root,
            &device_key,
            server,
            machine_route,
            device_route,
            root_key_id,
            trust_epoch,
            GrantSerial::new(1),
        );
        store
            .install_grant(InstallGrantRecord {
                grant: grant.clone(),
                grant_hash: grant.canonical_sha256(),
            })
            .await
            .expect("install grant");
        Self {
            _temp: temp,
            path,
            store,
            server,
            machine_route,
            device_route,
            root_key_id,
            trust_epoch,
            root,
            link,
            device: device_key,
            link_cert,
            grant,
            link_auth_fault,
        }
    }

    fn registry(&self) -> (Arc<ManualMonotonicClock>, ChallengeRegistry) {
        let clock = Arc::new(ManualMonotonicClock::default());
        let registry =
            ChallengeRegistry::new(self.server, clock.clone(), ChallengeLimits::default())
                .expect("challenge registry");
        (clock, registry)
    }

    fn machine_frame(
        &self,
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
        certificate: SignedCertificate,
        signer: &SigningKey,
    ) -> Authenticate {
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.machine_route,
            device_route: None,
            serial_or_generation: certificate.generation.value(),
            credential_sha256: certificate.canonical_sha256(),
        };
        Authenticate {
            proof: AuthProof::MachineLink {
                machine_route: self.machine_route,
                link_cert: certificate,
            },
            signature: sign_authentication_transcript(signer, &transcript).into(),
        }
    }

    fn device_frame(
        &self,
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
        grant: RelayGrant,
        signer: &SigningKey,
    ) -> Authenticate {
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::Device,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: grant.machine_route,
            device_route: Some(grant.device_route),
            serial_or_generation: grant.grant_serial.value(),
            credential_sha256: grant.canonical_sha256(),
        };
        Authenticate {
            proof: AuthProof::Device { relay_grant: grant },
            signature: sign_authentication_transcript(signer, &transcript).into(),
        }
    }

    fn signed_revocation(&self) -> DeviceRevocation {
        let mut revocation = DeviceRevocation {
            machine_route: self.machine_route,
            device_route: self.device_route,
            grant_serial: self.grant.grant_serial,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        revocation.signature = sign_tbs(
            &self.root,
            &revocation.to_be_signed_v1(self.server, sha256(&self.root.verifying_key().to_bytes())),
        )
        .into();
        revocation
    }
}

async fn authenticate_machine_access(
    fixture: &Fixture,
    registry: &ChallengeRegistry,
    coordinator: &AuthorizationCoordinator,
    instance: ConnectionInstanceId,
    source_id: u64,
) -> AccessContext {
    let challenge = registry
        .issue(instance, source(source_id))
        .expect("issue machine control challenge");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            instance,
            source(source_id),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume machine control challenge");
    coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("machine control origin authenticates")
        .access
}

#[test]
fn challenge_global_4096_bound_replay_expiry_and_capacity_release() {
    let clock = Arc::new(ManualMonotonicClock::default());
    let server = RelayServerId::from_bytes([0x90; 16]);
    let registry = ChallengeRegistry::new(server, clock.clone(), ChallengeLimits::default())
        .expect("registry");
    for value in 0..4_096_u64 {
        registry
            .issue(connection(u128::from(value) + 1), source(value))
            .expect("within global bound");
    }
    assert_eq!(
        registry
            .issue(connection(5_000), source(5_000))
            .expect_err("4,097th rejected")
            .code,
        RELAY_QUOTA_EXCEEDED
    );
    registry
        .consume(
            connection(1),
            source(0),
            ChallengeRoute::Machine(machine(1)),
        )
        .expect("first consume");
    assert_eq!(
        registry
            .consume(
                connection(1),
                source(0),
                ChallengeRoute::Machine(machine(1)),
            )
            .expect_err("one shot")
            .code,
        RELAY_AUTH_REPLAY
    );
    registry
        .issue(connection(5_001), source(0))
        .expect("consumed slot can be reused by existing bounded source");
    clock.set(30_000);
    assert_eq!(registry.stats().expect("stats").pending, 0);
    registry
        .issue(connection(6_000), source(0))
        .expect("expiry releases pending capacity while bucket map remains bounded");
    clock.set(60_000);
    assert_eq!(
        registry
            .consume(
                connection(6_000),
                source(0),
                ChallengeRoute::Machine(machine(1)),
            )
            .expect_err("exact 30 seconds expired")
            .code,
        RELAY_AUTH_CHALLENGE_EXPIRED
    );
}

#[tokio::test]
async fn machine_auth_commits_higher_generation_then_rejects_stale_after_restart() {
    let fixture = Fixture::new().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 32)
        .expect("authorization coordinator");

    let first_connection = connection(1);
    let challenge = registry
        .issue(first_connection, source(1))
        .expect("issue machine challenge");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            first_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume");
    let first = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("same cert reconnect");
    assert_eq!(first.activation.replaced, None);

    let higher = signed_certificate(
        &fixture.root,
        &fixture.link,
        fixture.server,
        fixture.machine_route,
        fixture.root_key_id,
        fixture.trust_epoch,
        LinkGeneration::new(2),
        CertRole::Link,
        Some(NOW_MS + 60_000),
    );
    let second_connection = connection(2);
    let challenge = registry
        .issue(second_connection, source(1))
        .expect("issue higher challenge");
    let frame = fixture.machine_frame(&challenge, higher.clone(), &fixture.link);
    let consumed = registry
        .consume(
            second_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume higher");
    let second = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("higher generation");
    assert_eq!(second.activation.replaced, Some(first_connection));
    assert!(coordinator.is_current(&second.access).expect("current"));
    assert!(
        !coordinator
            .disconnect(
                PrincipalRoute::Machine(fixture.machine_route),
                first_connection
            )
            .expect("stale cleanup")
    );
    assert!(
        coordinator
            .is_current(&second.access)
            .expect("replacement remains")
    );
    assert_eq!(
        fixture
            .store
            .machine_trust(fixture.machine_route)
            .await
            .expect("trust")
            .highest_link_generation,
        LinkGeneration::new(2)
    );

    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown");
    let reopened = RelayStoreHandle::open(store_config(&fixture.path))
        .await
        .expect("reopen");
    let trust = reopened
        .machine_trust(fixture.machine_route)
        .await
        .expect("persisted trust");
    assert_eq!(trust.highest_link_generation, LinkGeneration::new(2));
    assert_eq!(trust.link_cert_hash, higher.canonical_sha256());
    assert!(matches!(
        reopened
            .commit_machine_link_auth(CommitMachineLinkAuth {
                machine_route: fixture.machine_route,
                root_key_id: fixture.root_key_id,
                trust_epoch: fixture.trust_epoch,
                generation: LinkGeneration::new(1),
                cert_hash: fixture.link_cert.canonical_sha256(),
            })
            .await,
        Err(StoreError::MonotonicRollback { .. })
    ));
    reopened.shutdown().await.expect("shutdown reopened");
}

#[tokio::test]
async fn invalid_higher_signature_never_changes_store_or_active_connection() {
    let fixture = Fixture::new().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 32)
        .expect("authorization coordinator");

    let valid_connection = connection(10);
    let challenge = registry.issue(valid_connection, source(1)).expect("issue");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            valid_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume");
    let valid = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("valid auth");

    let mut forged = signed_certificate(
        &fixture.root,
        &fixture.link,
        fixture.server,
        fixture.machine_route,
        fixture.root_key_id,
        fixture.trust_epoch,
        LinkGeneration::new(2),
        CertRole::Link,
        Some(NOW_MS + 60_000),
    );
    forged.signature.0[0] ^= 1;
    let forged_connection = connection(11);
    let challenge = registry
        .issue(forged_connection, source(1))
        .expect("issue forged");
    let frame = fixture.machine_frame(&challenge, forged, &fixture.link);
    let consumed = registry
        .consume(
            forged_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume forged");
    assert_eq!(
        coordinator
            .authenticate(frame, consumed, NOW_MS)
            .await
            .expect_err("bad root signature")
            .code,
        RELAY_AUTH_INVALID_GRANT
    );
    assert!(coordinator.is_current(&valid.access).expect("old remains"));
    assert_eq!(
        fixture
            .store
            .machine_trust(fixture.machine_route)
            .await
            .expect("trust")
            .highest_link_generation,
        LinkGeneration::new(1)
    );
    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn link_cas_commit_fault_rolls_back_before_active_replacement() {
    let fixture = Fixture::with_link_auth_fault().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 32)
        .expect("authorization coordinator");

    let first_connection = connection(12);
    let challenge = registry
        .issue(first_connection, source(1))
        .expect("issue initial");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            first_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume initial");
    let first = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("initial active");

    let higher = signed_certificate(
        &fixture.root,
        &fixture.link,
        fixture.server,
        fixture.machine_route,
        fixture.root_key_id,
        fixture.trust_epoch,
        LinkGeneration::new(2),
        CertRole::Link,
        Some(NOW_MS + 60_000),
    );
    fixture
        .link_auth_fault
        .as_ref()
        .expect("fault fixture")
        .arm();
    let failed_connection = connection(13);
    let challenge = registry
        .issue(failed_connection, source(1))
        .expect("issue failed CAS");
    let frame = fixture.machine_frame(&challenge, higher, &fixture.link);
    let consumed = registry
        .consume(
            failed_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume failed CAS");
    assert_eq!(
        coordinator
            .authenticate(frame, consumed, NOW_MS)
            .await
            .expect_err("COMMIT fault")
            .code,
        RELAY_STORE_UNAVAILABLE
    );
    assert!(
        coordinator
            .is_current(&first.access)
            .expect("old active remains")
    );
    assert_eq!(
        fixture
            .store
            .machine_trust(fixture.machine_route)
            .await
            .expect("rolled back trust")
            .highest_link_generation,
        LinkGeneration::new(1)
    );
    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn link_cas_after_commit_loss_exactly_recovers_without_restoring_old_generation() {
    let fixture = Fixture::with_link_auth_after_commit_fault().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 32)
        .expect("authorization coordinator");

    let first_connection = connection(14);
    let challenge = registry
        .issue(first_connection, source(1))
        .expect("issue initial");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            first_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume initial");
    let first = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("initial active");

    let higher = signed_certificate(
        &fixture.root,
        &fixture.link,
        fixture.server,
        fixture.machine_route,
        fixture.root_key_id,
        fixture.trust_epoch,
        LinkGeneration::new(2),
        CertRole::Link,
        Some(NOW_MS + 60_000),
    );
    fixture
        .link_auth_fault
        .as_ref()
        .expect("fault fixture")
        .arm();
    let second_connection = connection(15);
    let challenge = registry
        .issue(second_connection, source(1))
        .expect("issue replacement");
    let frame = fixture.machine_frame(&challenge, higher.clone(), &fixture.link);
    let consumed = registry
        .consume(
            second_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume replacement");
    let second = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("exact retry recovers durable generation");
    assert_eq!(second.activation.replaced, Some(first_connection));
    assert!(!coordinator.is_current(&first.access).expect("old invalid"));
    assert!(coordinator.is_current(&second.access).expect("new current"));
    let trust = fixture
        .store
        .machine_trust(fixture.machine_route)
        .await
        .expect("persisted trust");
    assert_eq!(trust.highest_link_generation, LinkGeneration::new(2));
    assert_eq!(trust.link_cert_hash, higher.canonical_sha256());

    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn link_cas_unknown_retry_failure_invalidates_old_generation_instead_of_rollback() {
    let fixture = Fixture::with_link_auth_after_commit_fault().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 32)
        .expect("authorization coordinator");

    let first_connection = connection(16);
    let challenge = registry
        .issue(first_connection, source(1))
        .expect("issue initial");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            first_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume initial");
    let first = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("initial active");

    let higher = signed_certificate(
        &fixture.root,
        &fixture.link,
        fixture.server,
        fixture.machine_route,
        fixture.root_key_id,
        fixture.trust_epoch,
        LinkGeneration::new(2),
        CertRole::Link,
        Some(NOW_MS + 60_000),
    );
    fixture
        .link_auth_fault
        .as_ref()
        .expect("fault fixture")
        .arm_times(2);
    let second_connection = connection(17);
    let challenge = registry
        .issue(second_connection, source(1))
        .expect("issue replacement");
    let frame = fixture.machine_frame(&challenge, higher, &fixture.link);
    let consumed = registry
        .consume(
            second_connection,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume replacement");
    assert_eq!(
        coordinator
            .authenticate(frame, consumed, NOW_MS)
            .await
            .expect_err("two lost results remain commit-unknown")
            .code,
        RELAY_STORE_UNAVAILABLE
    );
    assert!(
        !coordinator.is_current(&first.access).expect("old invalid"),
        "commit-unknown must not restore the stale MachineLink"
    );
    assert_eq!(
        coordinator
            .current(PrincipalRoute::Machine(fixture.machine_route))
            .expect("current machine"),
        None
    );
    assert_eq!(
        fixture
            .store
            .machine_trust(fixture.machine_route)
            .await
            .expect("durable trust")
            .highest_link_generation,
        LinkGeneration::new(2),
        "the first COMMIT was durable even though both results were lost"
    );

    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn device_auth_requires_installed_exact_grant_and_revocation_survives_restart() {
    let fixture = Fixture::new().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 32)
        .expect("authorization coordinator");

    let valid_connection = connection(20);
    let challenge = registry
        .issue(valid_connection, source(2))
        .expect("issue device");
    let frame = fixture.device_frame(&challenge, fixture.grant.clone(), &fixture.device);
    let consumed = registry
        .consume(
            valid_connection,
            source(2),
            ChallengeRoute::Device {
                machine_route: fixture.machine_route,
                device_route: fixture.device_route,
            },
        )
        .expect("consume device");
    coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("installed grant authenticates");

    let uninstalled = signed_grant(
        &fixture.root,
        &fixture.device,
        fixture.server,
        fixture.machine_route,
        fixture.device_route,
        fixture.root_key_id,
        fixture.trust_epoch,
        GrantSerial::new(2),
    );
    let challenge = registry
        .issue(connection(21), source(2))
        .expect("issue uninstalled");
    let frame = fixture.device_frame(&challenge, uninstalled, &fixture.device);
    let consumed = registry
        .consume(
            connection(21),
            source(2),
            ChallengeRoute::Device {
                machine_route: fixture.machine_route,
                device_route: fixture.device_route,
            },
        )
        .expect("consume uninstalled");
    assert_eq!(
        coordinator
            .authenticate(frame, consumed, NOW_MS)
            .await
            .expect_err("Authenticate cannot install higher grant")
            .code,
        RELAY_AUTH_INVALID_GRANT
    );

    let machine_access =
        authenticate_machine_access(&fixture, &registry, &coordinator, connection(200), 3).await;
    let revocation = fixture.signed_revocation();
    coordinator
        .revoke_from(machine_access, revocation.clone())
        .await
        .expect("revoke");
    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown");
    let reopened = RelayStoreHandle::open(store_config(&fixture.path))
        .await
        .expect("reopen");
    let (coordinator, _lifecycle) =
        AuthorizationCoordinator::start(reopened.clone(), 32).expect("authorization coordinator");
    let challenge = registry
        .issue(connection(22), source(2))
        .expect("issue forged revoked proof");
    let mut forged_frame = fixture.device_frame(&challenge, fixture.grant.clone(), &fixture.device);
    forged_frame.signature.0[0] ^= 1;
    let consumed = registry
        .consume(
            connection(22),
            source(2),
            ChallengeRoute::Device {
                machine_route: fixture.machine_route,
                device_route: fixture.device_route,
            },
        )
        .expect("consume forged revoked proof");
    assert_eq!(
        coordinator
            .authenticate(forged_frame, consumed, NOW_MS)
            .await
            .expect_err("revoked oracle requires valid endpoint possession")
            .code,
        RELAY_AUTH_INVALID_GRANT
    );

    let challenge = registry
        .issue(connection(23), source(2))
        .expect("issue revoked");
    let frame = fixture.device_frame(&challenge, fixture.grant.clone(), &fixture.device);
    let consumed = registry
        .consume(
            connection(23),
            source(2),
            ChallengeRoute::Device {
                machine_route: fixture.machine_route,
                device_route: fixture.device_route,
            },
        )
        .expect("consume revoked");
    assert_eq!(
        coordinator
            .authenticate(frame, consumed, NOW_MS)
            .await
            .expect_err("revoked remains terminal")
            .code,
        RELAY_AUTH_REVOKED
    );
    coordinator.shutdown().await.expect("shutdown coordinator");
    reopened.shutdown().await.expect("shutdown reopened");
}

#[tokio::test]
async fn authorization_coordinator_serializes_revoke_and_invalidates_device_access() {
    let fixture = Fixture::new().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, mut lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 32)
        .expect("authorization coordinator");
    let instance = connection(24);
    let challenge = registry.issue(instance, source(2)).expect("issue device");
    let frame = fixture.device_frame(&challenge, fixture.grant.clone(), &fixture.device);
    let consumed = registry
        .consume(
            instance,
            source(2),
            ChallengeRoute::Device {
                machine_route: fixture.machine_route,
                device_route: fixture.device_route,
            },
        )
        .expect("consume device");
    let authenticated = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("device authenticates");
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Activated(_))
    ));
    assert!(
        coordinator
            .is_current(&authenticated.access)
            .expect("current")
    );

    let machine_access =
        authenticate_machine_access(&fixture, &registry, &coordinator, connection(240), 3).await;
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Activated(_))
    ));
    let committed = coordinator
        .revoke_from(machine_access, fixture.signed_revocation())
        .await
        .expect("revoke through coordinator");
    assert_eq!(committed.invalidated_connections(), &[instance]);
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Invalidated { connections })
            if connections == vec![instance]
    ));
    assert!(
        !coordinator
            .is_current(&authenticated.access)
            .expect("invalidated")
    );

    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn authorization_owner_is_singleton_and_blocks_raw_trust_mutators() {
    let fixture = Fixture::new().await;
    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 8)
        .expect("first coordinator owns store");
    assert_eq!(
        AuthorizationCoordinator::start(fixture.store.clone(), 8)
            .expect_err("second coordinator must fail")
            .code,
        RELAY_STORE_UNAVAILABLE
    );
    assert!(matches!(
        fixture
            .store
            .commit_machine_link_auth(CommitMachineLinkAuth {
                machine_route: fixture.machine_route,
                root_key_id: fixture.root_key_id,
                trust_epoch: fixture.trust_epoch,
                generation: LinkGeneration::new(1),
                cert_hash: fixture.link_cert.canonical_sha256(),
            })
            .await,
        Err(StoreError::AuthorizationOwned)
    ));
    assert!(matches!(
        fixture.store.shutdown().await,
        Err(StoreError::AuthorizationOwned)
    ));
    assert!(matches!(
        fixture
            .store
            .install_grant(InstallGrantRecord {
                grant: fixture.grant.clone(),
                grant_hash: fixture.grant.canonical_sha256(),
            })
            .await,
        Err(StoreError::AuthorizationOwned)
    ));
    let revocation = fixture.signed_revocation();
    assert!(matches!(
        fixture
            .store
            .revoke(PersistRevocation {
                revocation: revocation.clone(),
                revocation_hash: revocation.canonical_sha256(),
                signed_revocation_blob: vec![0x91],
            })
            .await,
        Err(StoreError::AuthorizationOwned)
    ));
    assert!(matches!(
        fixture
            .store
            .purge_machine(PurgeMachine {
                machine_route: fixture.machine_route,
            })
            .await,
        Err(StoreError::AuthorizationOwned)
    ));
    assert!(matches!(
        coordinator
            .register_machine(RegisterMachine {
                code_hash: [0x93; 32],
                request_hash: [0x94; 32],
                response_blob: vec![0_u8; MAX_CONTROL_BLOB_BYTES + 1],
                receipt_hash: [0x95; 32],
                machine_route: machine(0x96),
                root_pubkey: PublicKeyBytes(fixture.root.verifying_key().to_bytes()),
                link_cert: fixture.link_cert.clone(),
                data_cert: fixture.link_cert.clone(),
                link_cert_hash: fixture.link_cert.canonical_sha256(),
                data_cert_hash: fixture.link_cert.canonical_sha256(),
            })
            .await,
        Err(StoreError::InvalidValue {
            field: "register_machine.response_blob",
            ..
        })
    ));

    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture
        .store
        .commit_machine_link_auth(CommitMachineLinkAuth {
            machine_route: fixture.machine_route,
            root_key_id: fixture.root_key_id,
            trust_epoch: fixture.trust_epoch,
            generation: LinkGeneration::new(1),
            cert_hash: fixture.link_cert.canonical_sha256(),
        })
        .await
        .expect("raw fixture mutator is available only after owner shutdown");
    fixture.store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn same_normalized_store_path_rejects_a_second_live_worker() {
    let fixture = Fixture::new().await;
    assert!(matches!(
        RelayStoreHandle::open(store_config(&fixture.path)).await,
        Err(StoreError::StoreAlreadyOpen)
    ));

    #[cfg(target_os = "macos")]
    {
        let alias = match fixture.path.strip_prefix("/var") {
            Ok(suffix) => Path::new("/private/var").join(suffix),
            Err(_) => match fixture.path.strip_prefix("/private/var") {
                Ok(suffix) => Path::new("/var").join(suffix),
                Err(_) => fixture.path.clone(),
            },
        };
        assert!(matches!(
            RelayStoreHandle::open(store_config(&alias)).await,
            Err(StoreError::StoreAlreadyOpen)
        ));
    }

    fixture
        .store
        .shutdown()
        .await
        .expect("shutdown first worker");
    let reopened = RelayStoreHandle::open(store_config(&fixture.path))
        .await
        .expect("path lease is released only after worker shutdown");
    reopened.shutdown().await.expect("shutdown reopened worker");
}

#[tokio::test]
async fn raw_admission_before_claim_is_fifo_and_post_claim_admission_is_rejected() {
    let (fixture, fault) =
        Fixture::with_blocking_fault(FaultPoint::MachineLinkAuthBeforeCommit).await;
    let request = CommitMachineLinkAuth {
        machine_route: fixture.machine_route,
        root_key_id: fixture.root_key_id,
        trust_epoch: fixture.trust_epoch,
        generation: LinkGeneration::new(1),
        cert_hash: fixture.link_cert.canonical_sha256(),
    };
    let release = fault.arm();
    let raw_store = fixture.store.clone();
    let admitted_request = request.clone();
    let admitted =
        tokio::spawn(async move { raw_store.commit_machine_link_auth(admitted_request).await });
    fault.wait_until_entered().await;

    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 8)
        .expect("claim occurs after first raw admission");
    assert!(matches!(
        fixture.store.commit_machine_link_auth(request).await,
        Err(StoreError::AuthorizationOwned)
    ));
    release.release();
    admitted
        .await
        .expect("admitted raw task")
        .expect("pre-claim command remains FIFO-valid");

    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn transitioning_fences_device_before_revoke_commit() {
    let (fixture, fault) = Fixture::with_blocking_fault(FaultPoint::RevokeBeforeCommit).await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, mut lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 8)
        .expect("authorization coordinator");
    let instance = connection(25);
    let challenge = registry.issue(instance, source(2)).expect("issue device");
    let frame = fixture.device_frame(&challenge, fixture.grant.clone(), &fixture.device);
    let consumed = registry
        .consume(
            instance,
            source(2),
            ChallengeRoute::Device {
                machine_route: fixture.machine_route,
                device_route: fixture.device_route,
            },
        )
        .expect("consume device");
    let authenticated = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("device authenticates");
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Activated(_))
    ));
    let machine_access =
        authenticate_machine_access(&fixture, &registry, &coordinator, connection(250), 3).await;
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Activated(_))
    ));

    let release = fault.arm();
    let revocation = fixture.signed_revocation();
    let task_coordinator = coordinator.clone();
    let revoke_task = tokio::spawn(async move {
        task_coordinator
            .revoke_from(machine_access, revocation)
            .await
    });
    fault.wait_until_entered().await;
    assert!(
        !coordinator
            .is_current(&authenticated.access)
            .expect("transition is fail-closed before Store COMMIT")
    );
    assert_eq!(
        coordinator
            .current(PrincipalRoute::Device {
                machine_route: fixture.machine_route,
                device_route: fixture.device_route,
            })
            .expect("current"),
        None
    );
    release.release();
    let committed = revoke_task
        .await
        .expect("revoke task")
        .expect("revoke commit");
    assert_eq!(committed.invalidated_connections(), &[instance]);
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Invalidated { connections })
            if connections == vec![instance]
    ));

    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn cancelled_auth_cannot_late_activate_without_lifecycle_evidence() {
    let (fixture, fault) =
        Fixture::with_blocking_fault(FaultPoint::MachineLinkAuthBeforeCommit).await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, mut lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 8)
        .expect("authorization coordinator");

    let first_instance = connection(26);
    let challenge = registry
        .issue(first_instance, source(1))
        .expect("issue first");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            first_instance,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume first");
    let first = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("first auth");
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Activated(_))
    ));

    let higher_cert = signed_certificate(
        &fixture.root,
        &fixture.link,
        fixture.server,
        fixture.machine_route,
        fixture.root_key_id,
        fixture.trust_epoch,
        LinkGeneration::new(2),
        CertRole::Link,
        Some(NOW_MS + 60_000),
    );
    let higher_instance = connection(27);
    let challenge = registry
        .issue(higher_instance, source(1))
        .expect("issue higher");
    let frame = fixture.machine_frame(&challenge, higher_cert, &fixture.link);
    let consumed = registry
        .consume(
            higher_instance,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume higher");
    let release = fault.arm();
    let task_coordinator = coordinator.clone();
    let auth_task =
        tokio::spawn(async move { task_coordinator.authenticate(frame, consumed, NOW_MS).await });
    fault.wait_until_entered().await;
    assert!(!coordinator.is_current(&first.access).expect("fenced"));
    auth_task.abort();
    assert!(
        auth_task
            .await
            .expect_err("caller is cancelled")
            .is_cancelled()
    );
    release.release();

    let activation = match lifecycle.recv().await {
        Some(AuthorizationLifecycleEvent::Activated(activation)) => activation,
        event => panic!("expected activation lifecycle after caller cancellation, got {event:?}"),
    };
    assert_eq!(activation.connection_instance, higher_instance);
    assert_eq!(activation.replaced, Some(first_instance));
    assert_eq!(
        coordinator
            .current(PrincipalRoute::Machine(fixture.machine_route))
            .expect("current"),
        Some(higher_instance)
    );
    assert!(
        coordinator
            .disconnect(activation.route, activation.connection_instance)
            .expect("Core consumes lifecycle and closes orphaned writer")
    );
    assert_eq!(
        coordinator
            .current(PrincipalRoute::Machine(fixture.machine_route))
            .expect("current after lifecycle cleanup"),
        None
    );
    assert_eq!(
        fixture
            .store
            .machine_trust(fixture.machine_route)
            .await
            .expect("persisted higher HWM")
            .highest_link_generation,
        LinkGeneration::new(2)
    );

    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn coordinator_shutdown_clears_active_before_owner_release() {
    let fixture = Fixture::new().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, mut lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 8)
        .expect("authorization coordinator");
    let old = coordinator.clone();
    let instance = connection(29);
    let challenge = registry.issue(instance, source(1)).expect("issue");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            instance,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume");
    let authenticated = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("authenticate");
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Activated(_))
    ));

    coordinator.shutdown().await.expect("shutdown coordinator");
    assert!(matches!(
        lifecycle.recv().await,
        Some(AuthorizationLifecycleEvent::Invalidated { connections })
            if connections == vec![instance]
    ));
    assert!(
        !old.is_current(&authenticated.access)
            .expect("old clone fenced")
    );
    assert_eq!(
        old.current(PrincipalRoute::Machine(fixture.machine_route))
            .expect("old current"),
        None
    );

    let (replacement, _replacement_lifecycle) =
        AuthorizationCoordinator::start(fixture.store.clone(), 8)
            .expect("owner is released only after old active is cleared");
    replacement
        .shutdown()
        .await
        .expect("shutdown replacement coordinator");
    fixture.store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn missing_lifecycle_consumer_fails_auth_closed() {
    let fixture = Fixture::new().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 8)
        .expect("authorization coordinator");
    let instance = connection(28);
    let challenge = registry.issue(instance, source(1)).expect("issue");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            instance,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume");
    let authenticated = coordinator
        .authenticate(frame, consumed, NOW_MS)
        .await
        .expect("initial auth");
    assert!(
        coordinator
            .is_current(&authenticated.access)
            .expect("current")
    );
    drop(lifecycle);
    assert!(
        !coordinator
            .is_current(&authenticated.access)
            .expect("Lifecycle Drop clears active synchronously")
    );

    let rejected_instance = connection(30);
    let challenge = registry
        .issue(rejected_instance, source(1))
        .expect("issue rejected");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            rejected_instance,
            source(1),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume rejected");
    assert_eq!(
        coordinator
            .authenticate(frame, consumed, NOW_MS)
            .await
            .expect_err("lifecycle receiver is mandatory")
            .code,
        RELAY_STORE_UNAVAILABLE
    );
    assert_eq!(
        coordinator
            .current(PrincipalRoute::Machine(fixture.machine_route))
            .expect("fail closed current"),
        None
    );
    assert_eq!(
        coordinator
            .shutdown()
            .await
            .expect_err("dropped lifecycle already terminated coordinator")
            .code,
        RELAY_STORE_UNAVAILABLE
    );
    fixture.store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn lifecycle_overflow_uses_terminal_emergency_close_all_slot() {
    let fixture = Fixture::new().await;
    let clock = Arc::new(ManualMonotonicClock::default());
    let registry = ChallengeRegistry::new(
        fixture.server,
        clock,
        ChallengeLimits {
            max_pending: 1,
            source_bucket: TokenBucketLimits {
                capacity: 4_096,
                refill_tokens_per_second: 4_096,
            },
            route_bucket: TokenBucketLimits {
                capacity: 4_096,
                refill_tokens_per_second: 4_096,
            },
            max_source_buckets: 1,
            max_route_buckets: 1,
            bucket_idle_ttl_ms: 30_000,
        },
    )
    .expect("high-rate deterministic registry");
    let (coordinator, mut lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 8)
        .expect("authorization coordinator");

    for index in 0..=512_u128 {
        let instance = connection(10_000 + index);
        let challenge = registry.issue(instance, source(9)).expect("issue");
        let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
        let consumed = registry
            .consume(
                instance,
                source(9),
                ChallengeRoute::Machine(fixture.machine_route),
            )
            .expect("consume");
        let result = coordinator.authenticate(frame, consumed, NOW_MS).await;
        if index < 512 {
            result.expect("regular lifecycle queue still has capacity");
        } else {
            assert_eq!(
                result
                    .expect_err("513th event overflows regular queue")
                    .code,
                RELAY_STORE_UNAVAILABLE
            );
        }
    }

    match lifecycle.recv().await {
        Some(AuthorizationLifecycleEvent::FailClosedAll { connections }) => {
            assert_eq!(connections.len(), 513);
            for index in 0..=512_u128 {
                assert!(connections.contains(&connection(10_000 + index)));
            }
        }
        event => panic!("expected terminal emergency close-all event, got {event:?}"),
    }
    assert!(lifecycle.recv().await.is_none());
    assert_eq!(
        coordinator
            .current(PrincipalRoute::Machine(fixture.machine_route))
            .expect("fail-closed current"),
        None
    );
    assert_eq!(
        coordinator
            .shutdown()
            .await
            .expect_err("overflow terminated coordinator")
            .code,
        RELAY_STORE_UNAVAILABLE
    );
    fixture.store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn transcript_binding_rejects_each_tampered_field_and_wrong_proof_role() {
    let fixture = Fixture::new().await;
    let trust = AuthenticationTrustView {
        now_ms: NOW_MS,
        trust: AuthenticationTrust::Machine(
            fixture
                .store
                .machine_trust(fixture.machine_route)
                .await
                .expect("trust"),
        ),
    };
    let (_clock, registry) = fixture.registry();

    for case in 0..8_u8 {
        let instance = connection(100 + u128::from(case));
        let challenge = registry.issue(instance, source(3)).expect("issue");
        let mut transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: fixture.machine_route,
            device_route: None,
            serial_or_generation: fixture.link_cert.generation.value(),
            credential_sha256: fixture.link_cert.canonical_sha256(),
        };
        match case {
            0 => transcript.challenge_nonce[0] ^= 1,
            1 => transcript.connection_instance = connection(9_001),
            2 => transcript.relay_server_id = RelayServerId::from_bytes([0x91; 16]),
            3 => transcript.relay_protocol_version = 1,
            4 => transcript.machine_route = machine(0x92),
            5 => transcript.serial_or_generation += 1,
            6 => transcript.credential_sha256[0] ^= 1,
            7 => transcript.role = AuthenticationRole::Device,
            _ => unreachable!("bounded case"),
        }
        let frame = Authenticate {
            proof: AuthProof::MachineLink {
                machine_route: fixture.machine_route,
                link_cert: fixture.link_cert.clone(),
            },
            signature: sign_authentication_transcript(&fixture.link, &transcript).into(),
        };
        let consumed = registry
            .consume(
                instance,
                source(3),
                ChallengeRoute::Machine(fixture.machine_route),
            )
            .expect("consume");
        assert_eq!(
            verify_authentication(&frame, &consumed, &trust)
                .expect_err("tampered transcript")
                .code,
            RELAY_AUTH_INVALID_GRANT,
            "case {case}"
        );
    }
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn store_link_cas_and_device_confirm_are_exact_under_concurrency() {
    let fixture = Fixture::new().await;
    let same = fixture
        .store
        .commit_machine_link_auth(CommitMachineLinkAuth {
            machine_route: fixture.machine_route,
            root_key_id: fixture.root_key_id,
            trust_epoch: fixture.trust_epoch,
            generation: LinkGeneration::new(1),
            cert_hash: fixture.link_cert.canonical_sha256(),
        })
        .await
        .expect("same/same");
    assert!(same.duplicate);
    assert!(matches!(
        fixture
            .store
            .commit_machine_link_auth(CommitMachineLinkAuth {
                machine_route: fixture.machine_route,
                root_key_id: fixture.root_key_id,
                trust_epoch: fixture.trust_epoch,
                generation: LinkGeneration::new(1),
                cert_hash: [0xee; 32],
            })
            .await,
        Err(StoreError::IdempotencyConflict { .. })
    ));
    assert!(matches!(
        fixture
            .store
            .commit_machine_link_auth(CommitMachineLinkAuth {
                machine_route: fixture.machine_route,
                root_key_id: fixture.root_key_id,
                trust_epoch: fixture.trust_epoch,
                generation: LinkGeneration::new(0),
                cert_hash: [0; 32],
            })
            .await,
        Err(StoreError::MonotonicRollback { .. })
    ));

    let generation_two = fixture
        .store
        .commit_machine_link_auth(CommitMachineLinkAuth {
            machine_route: fixture.machine_route,
            root_key_id: fixture.root_key_id,
            trust_epoch: fixture.trust_epoch,
            generation: LinkGeneration::new(2),
            cert_hash: [2; 32],
        });
    let generation_three = fixture
        .store
        .commit_machine_link_auth(CommitMachineLinkAuth {
            machine_route: fixture.machine_route,
            root_key_id: fixture.root_key_id,
            trust_epoch: fixture.trust_epoch,
            generation: LinkGeneration::new(3),
            cert_hash: [3; 32],
        });
    let (_two, three) = tokio::join!(generation_two, generation_three);
    three.expect("highest generation must commit");
    let trust = fixture
        .store
        .machine_trust(fixture.machine_route)
        .await
        .expect("trust");
    assert_eq!(trust.highest_link_generation, LinkGeneration::new(3));
    assert_eq!(trust.link_cert_hash, [3; 32]);

    let device_trust = fixture
        .store
        .device_trust(fixture.machine_route, fixture.device_route)
        .await
        .expect("device trust");
    fixture
        .store
        .confirm_device_auth(ConfirmDeviceAuth {
            machine_route: fixture.machine_route,
            device_route: fixture.device_route,
            grant_serial: device_trust.grant_serial,
            grant_hash: device_trust.grant_hash,
            auth_pubkey: device_trust.auth_pubkey,
            auth_fingerprint: device_trust.auth_fingerprint,
        })
        .await
        .expect("exact device confirmation");
    for mismatch in 0..4 {
        let mut request = ConfirmDeviceAuth {
            machine_route: fixture.machine_route,
            device_route: fixture.device_route,
            grant_serial: device_trust.grant_serial,
            grant_hash: device_trust.grant_hash,
            auth_pubkey: device_trust.auth_pubkey,
            auth_fingerprint: device_trust.auth_fingerprint,
        };
        match mismatch {
            0 => request.grant_serial = GrantSerial::new(2),
            1 => request.grant_hash[0] ^= 1,
            2 => request.auth_pubkey.0[0] ^= 1,
            3 => request.auth_fingerprint[0] ^= 1,
            _ => unreachable!("bounded mismatch"),
        }
        assert!(matches!(
            fixture.store.confirm_device_auth(request).await,
            Err(StoreError::AuthenticationMismatch { .. })
        ));
    }
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn certificate_role_expiry_endpoint_signature_and_trust_domain_fail_closed() {
    let fixture = Fixture::new().await;
    let trust = AuthenticationTrustView {
        now_ms: NOW_MS,
        trust: AuthenticationTrust::Machine(
            fixture
                .store
                .machine_trust(fixture.machine_route)
                .await
                .expect("trust"),
        ),
    };
    let (_clock, registry) = fixture.registry();
    let data_key = SigningKey::from_seed(&[0x43; 32]);

    for case in 0..5_u8 {
        let instance = connection(300 + u128::from(case));
        let challenge = registry.issue(instance, source(4)).expect("issue");
        let (certificate, signer) = match case {
            0 => (
                signed_certificate(
                    &fixture.root,
                    &data_key,
                    fixture.server,
                    fixture.machine_route,
                    fixture.root_key_id,
                    fixture.trust_epoch,
                    LinkGeneration::new(1),
                    CertRole::Data,
                    Some(NOW_MS + 1),
                ),
                &data_key,
            ),
            1 => (
                signed_certificate(
                    &fixture.root,
                    &fixture.link,
                    fixture.server,
                    fixture.machine_route,
                    fixture.root_key_id,
                    fixture.trust_epoch,
                    LinkGeneration::new(1),
                    CertRole::Link,
                    Some(NOW_MS),
                ),
                &fixture.link,
            ),
            2 => (fixture.link_cert.clone(), &fixture.link),
            3 => (
                signed_certificate(
                    &fixture.root,
                    &fixture.link,
                    fixture.server,
                    fixture.machine_route,
                    RootKeyId::from_bytes([0x99; 16]),
                    fixture.trust_epoch,
                    LinkGeneration::new(1),
                    CertRole::Link,
                    Some(NOW_MS + 1),
                ),
                &fixture.link,
            ),
            4 => {
                let mut certificate = fixture.link_cert.clone();
                certificate.signature.0[0] ^= 1;
                (certificate, &fixture.link)
            }
            _ => unreachable!("bounded case"),
        };
        let mut frame = fixture.machine_frame(&challenge, certificate, signer);
        if case == 2 {
            frame.signature.0[0] ^= 1;
        }
        let consumed = registry
            .consume(
                instance,
                source(4),
                ChallengeRoute::Machine(fixture.machine_route),
            )
            .expect("consume");
        assert_eq!(
            verify_authentication(&frame, &consumed, &trust)
                .expect_err("credential case must fail")
                .code,
            RELAY_AUTH_INVALID_GRANT,
            "case {case}"
        );
    }
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn malformed_root_and_endpoint_public_keys_fail_closed() {
    let fixture = Fixture::new().await;
    let malformed = (0..10_000_u32)
        .find_map(|value| {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&value.to_be_bytes());
            VerifyingKey::from_bytes(&bytes).err().map(|_| bytes)
        })
        .expect("deterministically find an invalid compressed Ed25519 point");
    let machine_trust = fixture
        .store
        .machine_trust(fixture.machine_route)
        .await
        .expect("trust");
    let (_clock, registry) = fixture.registry();

    let instance = connection(350);
    registry.issue(instance, source(4)).expect("issue");
    let mut bad_subject = SignedCertificate {
        subject_pubkey: PublicKeyBytes(malformed),
        cert_role: CertRole::Link,
        generation: LinkGeneration::new(2),
        root_key_id: fixture.root_key_id,
        trust_epoch: fixture.trust_epoch,
        not_after_ms: Some(NOW_MS + 1),
        signature: Ed25519Signature([0; 64]),
    };
    bad_subject.signature = sign_tbs(
        &fixture.root,
        &bad_subject.to_be_signed_v1(
            fixture.server,
            fixture.machine_route,
            sha256(&fixture.root.verifying_key().to_bytes()),
        ),
    )
    .into();
    let frame = Authenticate {
        proof: AuthProof::MachineLink {
            machine_route: fixture.machine_route,
            link_cert: bad_subject,
        },
        signature: Ed25519Signature([0; 64]),
    };
    let consumed = registry
        .consume(
            instance,
            source(4),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume");
    assert_eq!(
        verify_authentication(
            &frame,
            &consumed,
            &AuthenticationTrustView {
                now_ms: NOW_MS,
                trust: AuthenticationTrust::Machine(machine_trust.clone()),
            },
        )
        .expect_err("malformed subject key")
        .code,
        RELAY_AUTH_INVALID_GRANT
    );

    let instance = connection(351);
    let challenge = registry.issue(instance, source(4)).expect("issue");
    let frame = fixture.machine_frame(&challenge, fixture.link_cert.clone(), &fixture.link);
    let consumed = registry
        .consume(
            instance,
            source(4),
            ChallengeRoute::Machine(fixture.machine_route),
        )
        .expect("consume");
    let mut invalid_root = machine_trust;
    invalid_root.root_pubkey = PublicKeyBytes(malformed);
    assert_eq!(
        verify_authentication(
            &frame,
            &consumed,
            &AuthenticationTrustView {
                now_ms: NOW_MS,
                trust: AuthenticationTrust::Machine(invalid_root),
            },
        )
        .expect_err("malformed root key")
        .code,
        RELAY_AUTH_INVALID_GRANT
    );
    fixture.store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn cross_machine_and_same_serial_different_device_grants_are_rejected() {
    let fixture = Fixture::new().await;
    let (_clock, registry) = fixture.registry();
    let (coordinator, _lifecycle) = AuthorizationCoordinator::start(fixture.store.clone(), 16)
        .expect("authorization coordinator");

    let other_key = SigningKey::from_seed(&[0x61; 32]);
    let variants = [
        signed_grant(
            &fixture.root,
            &fixture.device,
            fixture.server,
            machine(0x62),
            fixture.device_route,
            fixture.root_key_id,
            fixture.trust_epoch,
            GrantSerial::new(1),
        ),
        signed_grant(
            &fixture.root,
            &other_key,
            fixture.server,
            fixture.machine_route,
            fixture.device_route,
            fixture.root_key_id,
            fixture.trust_epoch,
            GrantSerial::new(1),
        ),
    ];
    for (index, grant) in variants.into_iter().enumerate() {
        let instance = connection(400 + index as u128);
        let challenge = registry.issue(instance, source(5)).expect("issue");
        let signer = if index == 0 {
            &fixture.device
        } else {
            &other_key
        };
        let frame = fixture.device_frame(&challenge, grant.clone(), signer);
        let consumed = registry
            .consume(
                instance,
                source(5),
                ChallengeRoute::Device {
                    machine_route: grant.machine_route,
                    device_route: grant.device_route,
                },
            )
            .expect("consume");
        assert_eq!(
            coordinator
                .authenticate(frame, consumed, NOW_MS)
                .await
                .expect_err("cross-domain or conflicting grant")
                .code,
            RELAY_AUTH_INVALID_GRANT
        );
    }
    coordinator.shutdown().await.expect("shutdown coordinator");
    fixture.store.shutdown().await.expect("shutdown");
}

#[test]
fn pairing_access_is_strictly_limited_to_its_active_route() {
    let server = RelayServerId::from_bytes([1; 16]);
    let machine_route = machine(2);
    let pair_route = PairRouteId::from_bytes([3; 16]);
    let hello = PairingHello {
        protocol_version: RELAY_PROTOCOL_VERSION,
        relay_server_id: server,
        connection_instance: connection(3),
        pair_route,
    };
    let view = PairRouteView {
        now_ms: 99,
        active_route: Some(ActivePairRoute {
            relay_server_id: server,
            machine_route,
            pair_route,
            absolute_expiry_ms: 100,
        }),
    };
    let access = authorize_pairing_route(hello, &view).expect("active route");
    let pair_data = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(PairData {
            pair_route,
            sealed_blob: SealedBlob(vec![1]),
        }),
    };
    access.authorize_frame(&pair_data, 99).expect("pair data");
    let close = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::ClosePairRoute(ClosePairRoute {
            machine_route,
            pair_route,
        }),
    };
    access.authorize_frame(&close, 99).expect("close own route");
    let forbidden = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Subscribe(Subscribe {
            stream_route: StreamRouteId::from_bytes([4; 16]),
            generation: StreamGenerationId::from_bytes([5; 16]),
            cursor: StreamCursor::BeforeFirst,
        }),
    };
    assert_eq!(
        access
            .authorize_frame(&forbidden, 99)
            .expect_err("pairing cannot subscribe")
            .code,
        RELAY_ROUTE_FORBIDDEN
    );
    let additional_forbidden = vec![
        RelayFrameBody::Publish(Publish {
            stream_route: StreamRouteId::from_bytes([6; 16]),
            generation: StreamGenerationId::from_bytes([7; 16]),
            stream_seq: 0,
            sealed_blob: SealedBlob(vec![1]),
        }),
        RelayFrameBody::Send(Send {
            device_route: device(8),
            request_route: RequestRouteId::from_bytes([9; 16]),
            sealed_blob: SealedBlob(vec![1]),
        }),
        RelayFrameBody::OpenPairRoute(OpenPairRoute {
            machine_route,
            pair_route,
            absolute_expiry_ms: 100,
        }),
        RelayFrameBody::InstallGrant(InstallGrant {
            grant: RelayGrant {
                machine_route,
                device_route: device(10),
                device_sign_pubkey: PublicKeyBytes([11; 32]),
                grant_serial: GrantSerial::new(1),
                root_key_id: RootKeyId::from_bytes([12; 16]),
                trust_epoch: TrustEpoch::new(1),
                signature: Ed25519Signature([13; 64]),
            },
        }),
    ];
    for body in additional_forbidden {
        assert_eq!(
            access
                .authorize_frame(
                    &OpaqueRouteFrame {
                        version: RELAY_PROTOCOL_VERSION,
                        body,
                    },
                    99,
                )
                .expect_err("pairing family allowlist")
                .code,
            RELAY_ROUTE_FORBIDDEN
        );
    }
    let wrong_route = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(PairData {
            pair_route: PairRouteId::from_bytes([0xfe; 16]),
            sealed_blob: SealedBlob(vec![1]),
        }),
    };
    assert_eq!(
        access
            .authorize_frame(&wrong_route, 99)
            .expect_err("wrong pair route")
            .code,
        RELAY_ROUTE_FORBIDDEN
    );
    assert_eq!(
        access
            .authorize_frame(&pair_data, 100)
            .expect_err("existing pairing access expires per frame")
            .code,
        RELAY_ROUTE_NOT_FOUND
    );
    assert_eq!(
        authorize_pairing_route(
            PairingHello {
                protocol_version: 1,
                ..hello
            },
            &view,
        )
        .expect_err("version")
        .code,
        RELAY_VERSION_UNSUPPORTED
    );
    assert_eq!(
        authorize_pairing_route(
            hello,
            &PairRouteView {
                now_ms: 100,
                active_route: view.active_route,
            },
        )
        .expect_err("expired")
        .code,
        RELAY_ROUTE_NOT_FOUND
    );
    assert_eq!(
        authorize_pairing_route(
            PairingHello {
                relay_server_id: RelayServerId::from_bytes([0xee; 16]),
                ..hello
            },
            &view,
        )
        .expect_err("wrong server")
        .code,
        RELAY_ROUTE_NOT_FOUND
    );
    assert_eq!(
        authorize_pairing_route(
            hello,
            &PairRouteView {
                now_ms: 0,
                active_route: None,
            },
        )
        .expect_err("unknown route")
        .code,
        RELAY_ROUTE_NOT_FOUND
    );
}

#[test]
fn access_and_pairing_debug_are_redacted() {
    let challenge = agentdeck_protocol::relay_v2::frame::Challenge {
        relay_server_id: RelayServerId::from_bytes([0xcc; 16]),
        connection_instance: connection(u128::MAX),
        challenge_nonce: [0xdd; 32],
    };
    let credential = RelayGrant {
        machine_route: machine(0xaa),
        device_route: device(0xee),
        device_sign_pubkey: PublicKeyBytes([0xab; 32]),
        grant_serial: GrantSerial::new(1),
        root_key_id: RootKeyId::from_bytes([0xac; 16]),
        trust_epoch: TrustEpoch::new(1),
        signature: Ed25519Signature([0xad; 64]),
    };
    let authenticate = Authenticate {
        proof: AuthProof::MachineLink {
            machine_route: machine(0xaa),
            link_cert: SignedCertificate {
                cert_role: CertRole::Link,
                subject_pubkey: PublicKeyBytes([0xae; 32]),
                generation: LinkGeneration::new(1),
                root_key_id: RootKeyId::from_bytes([0xaf; 16]),
                trust_epoch: TrustEpoch::new(1),
                not_after_ms: None,
                signature: Ed25519Signature([0xb0; 64]),
            },
        },
        signature: Ed25519Signature([0xb1; 64]),
    };
    let rendered = format!(
        "{challenge:?} {credential:?} {:?} {authenticate:?}",
        authenticate.proof
    );
    assert!(!rendered.contains(&"aa".repeat(16)));
    assert!(!rendered.contains(&format!("{:?}", [0xaa_u8; 16])));
    assert!(!rendered.contains(&format!("{:?}", [0xff_u8; 16])));
    for material in [
        "cc".repeat(16),
        "dd".repeat(32),
        "ab".repeat(32),
        "ad".repeat(64),
        "ae".repeat(32),
        "b0".repeat(64),
        "b1".repeat(64),
    ] {
        assert!(!rendered.contains(&material));
    }
}
