//! Relay v2 stream router / replay / ACK / bounded-writer 端到端契约。
//!
//! 所有 `AccessContext` 都由真实 challenge-response 与持久 trust state 产生；
//! 测试不构造伪 principal，也不绕过 `AuthorizationCoordinator`。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use agentdeck_crypto::{
    SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256, sign_authentication_transcript,
    sign_tbs,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, CertRole,
};
use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_INVALID_GRANT, RELAY_ROUTE_FORBIDDEN, RELAY_ROUTE_NOT_FOUND,
    RELAY_STORE_UNAVAILABLE, RELAY_STREAM_GENERATION_STALE, RELAY_STREAM_OUT_OF_ORDER,
};
use agentdeck_protocol::relay_v2::frame::{
    Ack, AuthProof, Authenticate, Ping, Pong, Publish, RegisterStream, ReplayComplete, SealedBlob,
    Subscribe, Unsubscribe,
};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial,
    LinkGeneration, MAX_FRAME_BYTES, MachineRouteId, OpaqueRouteFrame, PublicKeyBytes,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayGrant, RelayServerId, RootKeyId,
    SignedCertificate, StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};
use agentdeck_relay::v2::auth::{
    AccessContext, AuthorizationCoordinator, ChallengeLimits, ChallengeRegistry, ChallengeRoute,
    ChallengeSource, MonotonicClock,
};
use agentdeck_relay::v2::core::writer::{
    OutboundReceiver, OutboundWriter, OutboundWriterConfig, WriterBudget, WriterCloseReason,
};
use agentdeck_relay::v2::core::{CoreConfig, RelayCore, RouteOutcome};
use agentdeck_relay::v2::store::{
    Clock, DiskSpace, DiskSpaceProbe, EnrollmentCodeSeed, FaultInjector, FaultPoint,
    InstallGrantRecord, PersistSubscription, RegisterMachine, RelayStoreHandle, RelayV2StoreConfig,
    RetentionLimits, StoreError,
};
use tempfile::TempDir;

const NOW_MS: u64 = 1_726_000_000_000;

fn test_store_config(path: PathBuf) -> RelayV2StoreConfig {
    let identity = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&SigningKey::from_seed(
        &[0x71; 32],
    ))
    .expect("valid test receipt signer");
    RelayV2StoreConfig::new(path, identity)
}

#[derive(Default)]
struct ManualMonotonicClock(AtomicU64);

impl MonotonicClock for ManualMonotonicClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
struct FixedStoreClock;

impl Clock for FixedStoreClock {
    fn now_ms(&self) -> Result<u64, StoreError> {
        Ok(NOW_MS)
    }
}

#[derive(Debug)]
struct PlentyOfDisk;

impl DiskSpaceProbe for PlentyOfDisk {
    fn space(&self, _storage_path: &Path) -> Result<DiskSpace, StoreError> {
        Ok(DiskSpace {
            available_bytes: 16 * 1024 * 1024 * 1024,
            total_bytes: 32 * 1024 * 1024 * 1024,
        })
    }
}

#[derive(Debug)]
struct ArmedFault {
    point: FaultPoint,
    armed: AtomicBool,
}

#[derive(Debug)]
struct BlockingFault {
    point: FaultPoint,
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
}

#[derive(Debug)]
struct ReplayTransitionFault {
    replay: BlockingFault,
    revoke: BlockingFault,
}

impl ReplayTransitionFault {
    fn new() -> Self {
        Self {
            replay: BlockingFault::new(FaultPoint::ReplayAfterRead),
            revoke: BlockingFault::new(FaultPoint::RevokeBeforeCommit),
        }
    }

    fn arm(&self) {
        self.replay.arm();
        self.revoke.arm();
    }
}

impl FaultInjector for ReplayTransitionFault {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        self.replay.check(point)?;
        self.revoke.check(point)
    }
}

impl BlockingFault {
    fn new(point: FaultPoint) -> Self {
        Self {
            point,
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
        }
    }

    fn arm(&self) {
        self.entered.store(false, Ordering::SeqCst);
        self.released.store(false, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }

    async fn wait_until_entered(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Store worker must enter blocking fault");
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
    }
}

impl FaultInjector for BlockingFault {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point && self.armed.swap(false, Ordering::SeqCst) {
            self.entered.store(true, Ordering::SeqCst);
            while !self.released.load(Ordering::SeqCst) {
                std::thread::park_timeout(Duration::from_millis(1));
            }
        }
        Ok(())
    }
}

impl Drop for BlockingFault {
    fn drop(&mut self) {
        self.released.store(true, Ordering::SeqCst);
    }
}

impl ArmedFault {
    fn new(point: FaultPoint) -> Self {
        Self {
            point,
            armed: AtomicBool::new(true),
        }
    }
}

impl FaultInjector for ArmedFault {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point && self.armed.swap(false, Ordering::SeqCst) {
            Err(StoreError::InjectedFault(point))
        } else {
            Ok(())
        }
    }
}

fn test_retention(max_frames_per_stream: u64) -> RetentionLimits {
    RetentionLimits {
        max_frames_per_stream,
        disk_reserve_bytes: 0,
        disk_reserve_percent: 0,
        ..RetentionLimits::default()
    }
}

fn store_path(temp: &TempDir) -> PathBuf {
    temp.path().join("relay-private").join("relay.db")
}

fn connection(value: u128) -> ConnectionInstanceId {
    ConnectionInstanceId::from_bytes(value.to_be_bytes())
}

fn source(value: u64) -> ChallengeSource {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    ChallengeSource::from_bytes(bytes)
}

fn stream(value: u8) -> StreamRouteId {
    StreamRouteId::from_bytes([value; 16])
}

fn generation(value: u8) -> StreamGenerationId {
    StreamGenerationId::from_bytes([value; 16])
}

fn outer(body: RelayFrameBody) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    }
}

fn register_frame(
    machine_route: MachineRouteId,
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
) -> OpaqueRouteFrame {
    outer(RelayFrameBody::RegisterStream(RegisterStream {
        machine_route,
        stream_route,
        generation,
    }))
}

fn publish_frame(
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
    stream_seq: u64,
    byte: u8,
) -> OpaqueRouteFrame {
    outer(RelayFrameBody::Publish(Publish {
        stream_route,
        generation,
        stream_seq,
        sealed_blob: SealedBlob(vec![byte]),
    }))
}

fn subscribe_frame(
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
    cursor: StreamCursor,
) -> OpaqueRouteFrame {
    outer(RelayFrameBody::Subscribe(Subscribe {
        stream_route,
        generation,
        cursor,
    }))
}

fn unsubscribe_frame(
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
) -> OpaqueRouteFrame {
    outer(RelayFrameBody::Unsubscribe(Unsubscribe {
        stream_route,
        generation,
    }))
}

fn ack_frame(
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
    up_to_seq: u64,
) -> OpaqueRouteFrame {
    outer(RelayFrameBody::Ack(Ack {
        stream_route,
        generation,
        up_to_seq,
    }))
}

#[allow(clippy::too_many_arguments)]
fn signed_certificate(
    root: &SigningKey,
    subject: &SigningKey,
    server: RelayServerId,
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
) -> SignedCertificate {
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
        cert_role: CertRole::Link,
        generation: LinkGeneration::new(1),
        root_key_id,
        trust_epoch,
        not_after_ms: Some(NOW_MS + 60_000),
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

struct DeviceFixture {
    route: DeviceRouteId,
    key: SigningKey,
    grant: RelayGrant,
}

struct RealmFixture {
    server: RelayServerId,
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    root: SigningKey,
    link: SigningKey,
    link_cert: SignedCertificate,
    devices: Vec<DeviceFixture>,
}

impl RealmFixture {
    async fn install(
        store: &RelayStoreHandle,
        server: RelayServerId,
        seed: u8,
        device_count: usize,
    ) -> Self {
        let machine_route = MachineRouteId::from_bytes([seed; 16]);
        let root_key_id = RootKeyId::from_bytes([seed.wrapping_add(1); 16]);
        let trust_epoch = TrustEpoch::new(1);
        let root = SigningKey::from_seed(&[seed.wrapping_add(2); 32]);
        let link = SigningKey::from_seed(&[seed.wrapping_add(3); 32]);
        let data = SigningKey::from_seed(&[seed.wrapping_add(4); 32]);
        let link_cert = signed_certificate(
            &root,
            &link,
            server,
            machine_route,
            root_key_id,
            trust_epoch,
        );
        let data_cert = {
            let mut certificate = signed_certificate(
                &root,
                &data,
                server,
                machine_route,
                root_key_id,
                trust_epoch,
            );
            certificate.cert_role = CertRole::Data;
            certificate.signature = sign_tbs(
                &root,
                &certificate.to_be_signed_v1(
                    server,
                    machine_route,
                    sha256(&root.verifying_key().to_bytes()),
                ),
            )
            .into();
            certificate
        };
        let code_hash = [seed.wrapping_add(5); 32];
        store
            .seed_enrollment_code(EnrollmentCodeSeed {
                code_hash,
                expires_at_ms: NOW_MS + 60_000,
            })
            .await
            .expect("seed enrollment code");
        store
            .register_machine(RegisterMachine {
                code_hash,
                request_hash: [seed.wrapping_add(6); 32],
                machine_route,
                root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
                link_cert: link_cert.clone(),
                data_cert: data_cert.clone(),
                link_cert_hash: link_cert.canonical_sha256(),
                data_cert_hash: data_cert.canonical_sha256(),
            })
            .await
            .expect("register machine");

        let mut devices = Vec::with_capacity(device_count);
        for index in 0..device_count {
            let device_seed = seed.wrapping_add(0x20).wrapping_add(index as u8);
            let route = DeviceRouteId::from_bytes([device_seed; 16]);
            let key = SigningKey::from_seed(&[device_seed.wrapping_add(1); 32]);
            let grant = signed_grant(
                &root,
                &key,
                server,
                machine_route,
                route,
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
                .expect("install device grant");
            devices.push(DeviceFixture { route, key, grant });
        }
        Self {
            server,
            machine_route,
            root_key_id,
            trust_epoch,
            root,
            link,
            link_cert,
            devices,
        }
    }

    fn signed_revocation(&self, server: RelayServerId, device: usize) -> DeviceRevocation {
        let grant = &self.devices[device].grant;
        let mut revocation = DeviceRevocation {
            machine_route: self.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        revocation.signature = sign_tbs(
            &self.root,
            &revocation.to_be_signed_v1(server, sha256(&self.root.verifying_key().to_bytes())),
        )
        .into();
        revocation
    }

    fn machine_authenticate(
        &self,
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
    ) -> Authenticate {
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.machine_route,
            device_route: None,
            serial_or_generation: self.link_cert.generation.value(),
            credential_sha256: self.link_cert.canonical_sha256(),
        };
        Authenticate {
            proof: AuthProof::MachineLink {
                machine_route: self.machine_route,
                link_cert: self.link_cert.clone(),
            },
            signature: sign_authentication_transcript(&self.link, &transcript).into(),
        }
    }

    fn device_authenticate(
        &self,
        index: usize,
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
    ) -> Authenticate {
        let device = &self.devices[index];
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::Device,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.machine_route,
            device_route: Some(device.route),
            serial_or_generation: device.grant.grant_serial.value(),
            credential_sha256: device.grant.canonical_sha256(),
        };
        Authenticate {
            proof: AuthProof::Device {
                relay_grant: device.grant.clone(),
            },
            signature: sign_authentication_transcript(&device.key, &transcript).into(),
        }
    }
}

struct Fixture {
    _temp: TempDir,
    store: RelayStoreHandle,
    registry: ChallengeRegistry,
    auth: AuthorizationCoordinator,
    core: RelayCore,
    realms: Vec<RealmFixture>,
    next_connection: u128,
}

struct TestConnection {
    access: AccessContext,
    writer: OutboundWriter,
    receiver: OutboundReceiver,
}

impl Fixture {
    async fn new(max_frames_per_stream: u64, fault: Option<Arc<dyn FaultInjector>>) -> Self {
        Self::new_with_retention(test_retention(max_frames_per_stream), fault).await
    }

    async fn new_with_replay_page_frames(
        max_frames_per_stream: u64,
        replay_page_max_frames: u64,
    ) -> Self {
        let mut retention = test_retention(max_frames_per_stream);
        retention.replay_page_max_frames = replay_page_max_frames;
        Self::new_with_retention(retention, None).await
    }

    async fn new_with_retention(
        retention: RetentionLimits,
        fault: Option<Arc<dyn FaultInjector>>,
    ) -> Self {
        Self::new_with_retention_and_core(retention, fault, CoreConfig::default()).await
    }

    async fn new_with_core_config(
        max_frames_per_stream: u64,
        fault: Option<Arc<dyn FaultInjector>>,
        core_config: CoreConfig,
    ) -> Self {
        Self::new_with_retention_and_core(test_retention(max_frames_per_stream), fault, core_config)
            .await
    }

    async fn new_with_retention_and_core(
        retention: RetentionLimits,
        fault: Option<Arc<dyn FaultInjector>>,
        core_config: CoreConfig,
    ) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = test_store_config(store_path(&temp))
            .with_clock(Arc::new(FixedStoreClock))
            .with_disk_space_probe(Arc::new(PlentyOfDisk))
            .with_retention(retention);
        if let Some(fault) = fault {
            config = config.with_fault_injector(fault);
        }
        let store = RelayStoreHandle::open(config).await.expect("open v2 store");
        let server = store
            .inspect()
            .await
            .expect("inspect store")
            .relay_server_id;
        let realm_a = RealmFixture::install(&store, server, 0x11, 2).await;
        let realm_b = RealmFixture::install(&store, server, 0x61, 1).await;
        let registry = ChallengeRegistry::new(
            server,
            Arc::new(ManualMonotonicClock::default()),
            ChallengeLimits::default(),
        )
        .expect("challenge registry");
        let (auth, lifecycle) =
            AuthorizationCoordinator::start(store.clone(), 64).expect("authorization coordinator");
        let core = RelayCore::start(store.clone(), auth.clone(), lifecycle, core_config)
            .expect("start relay core");
        Self {
            _temp: temp,
            store,
            registry,
            auth,
            core,
            realms: vec![realm_a, realm_b],
            next_connection: 1,
        }
    }

    async fn connect_machine(&mut self, realm: usize) -> TestConnection {
        self.connect(realm, None, OutboundWriterConfig::default())
            .await
    }

    async fn connect_device(&mut self, realm: usize, device: usize) -> TestConnection {
        self.connect(realm, Some(device), OutboundWriterConfig::default())
            .await
    }

    async fn connect_device_with_writer(
        &mut self,
        realm: usize,
        device: usize,
        writer_config: OutboundWriterConfig,
    ) -> TestConnection {
        self.connect(realm, Some(device), writer_config).await
    }

    async fn connect(
        &mut self,
        realm: usize,
        device: Option<usize>,
        writer_config: OutboundWriterConfig,
    ) -> TestConnection {
        let connection_number = self.next_connection;
        self.next_connection += 1;
        let connection_id = connection(connection_number);
        let challenge_source = source(connection_number as u64);
        let (writer, receiver) = OutboundWriter::new(writer_config);
        self.core
            .attach_pending(connection_id, writer.clone())
            .await
            .expect("attach pending writer");
        let challenge = self
            .registry
            .issue(connection_id, challenge_source)
            .expect("issue challenge");
        let realm_fixture = &self.realms[realm];
        let (frame, route) = match device {
            Some(index) => (
                realm_fixture.device_authenticate(index, &challenge),
                ChallengeRoute::Device {
                    machine_route: realm_fixture.machine_route,
                    device_route: realm_fixture.devices[index].route,
                },
            ),
            None => (
                realm_fixture.machine_authenticate(&challenge),
                ChallengeRoute::Machine(realm_fixture.machine_route),
            ),
        };
        let consumed = self
            .registry
            .consume(connection_id, challenge_source, route)
            .expect("consume challenge");
        let authenticated = self
            .auth
            .authenticate(frame, consumed, NOW_MS)
            .await
            .expect("authenticate connection");
        self.core
            .activate(authenticated.access.clone())
            .await
            .expect("activate authenticated writer");
        TestConnection {
            access: authenticated.access,
            writer,
            receiver,
        }
    }

    async fn shutdown(self) {
        self.core.shutdown().await.expect("shutdown core");
        self.store.shutdown().await.expect("shutdown store");
    }
}

async fn recv_frame(connection: &mut TestConnection) -> OpaqueRouteFrame {
    let delivery = tokio::time::timeout(Duration::from_secs(5), connection.receiver.recv())
        .await
        .expect("writer receive must not hang")
        .expect("writer must remain open");
    let frame = decode(delivery.encoded()).expect("canonical Relay v2 frame");
    delivery.mark_flushed();
    frame
}

async fn assert_receiver_closed(connection: &mut TestConnection) {
    let received = tokio::time::timeout(Duration::from_secs(5), connection.receiver.recv())
        .await
        .expect("writer close must not hang");
    assert!(
        received.is_none(),
        "closed writer cannot yield another frame"
    );
}

fn assert_applied(outcome: RouteOutcome) {
    assert!(matches!(outcome, RouteOutcome::Applied));
}

fn assert_queued_publish(outcome: RouteOutcome, route: StreamRouteId, seq: u64) {
    let RouteOutcome::Queued(accepted) = outcome else {
        panic!("expected queued publish, got {outcome:?}");
    };
    assert_eq!(
        accepted.accepted,
        agentdeck_protocol::relay_v2::frame::AcceptedRef::StreamFrame {
            stream_route: route,
            stream_seq: seq,
        }
    );
}

#[test]
fn writer_default_count_and_byte_limits_are_exact_and_fail_closed() {
    let (count_writer, _count_receiver) = OutboundWriter::channel();
    for nonce in 0..512 {
        count_writer
            .try_enqueue_data(outer(RelayFrameBody::Ping(Ping { nonce })))
            .expect("first 512 frames fit");
    }
    assert!(
        count_writer
            .try_enqueue_data(outer(RelayFrameBody::Ping(Ping { nonce: 513 })))
            .is_err()
    );
    assert_eq!(count_writer.close_reason(), Some(WriterCloseReason::Lagged));

    let empty = publish_frame(stream(0xf1), generation(0xf2), 0, 0);
    let overhead = encode(&empty).len() - 1;
    let mut exact = empty;
    let RelayFrameBody::Publish(publish) = &mut exact.body else {
        unreachable!();
    };
    publish.sealed_blob = SealedBlob(vec![0xa5; MAX_FRAME_BYTES - overhead]);
    assert_eq!(encode(&exact).len(), MAX_FRAME_BYTES);

    let (byte_writer, _byte_receiver) = OutboundWriter::channel();
    for _ in 0..4 {
        byte_writer
            .try_enqueue_data(exact.clone())
            .expect("four 4 MiB frames fit exactly");
    }
    assert!(
        byte_writer
            .try_enqueue_data(outer(RelayFrameBody::Ping(Ping { nonce: 5 })))
            .is_err()
    );
    assert_eq!(byte_writer.close_reason(), Some(WriterCloseReason::Lagged));
}

#[test]
fn public_route_outcome_debug_is_redacted() {
    let stream_route = stream(0xf3);
    let outcome = RouteOutcome::Queued(agentdeck_protocol::relay_v2::frame::RouteAccepted {
        accepted: agentdeck_protocol::relay_v2::frame::AcceptedRef::StreamFrame {
            stream_route,
            stream_seq: 7,
        },
    });
    let debug = format!("{outcome:?}");
    assert!(debug.contains(&stream_route.redacted()));
    assert!(!debug.contains("StreamRouteId"));
}

#[tokio::test]
async fn role_ownership_generation_and_independent_sequence_gates_are_enforced() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine_a = fixture.connect_machine(0).await;
    let device_a = fixture.connect_device(0, 0).await;
    let machine_b = fixture.connect_machine(1).await;
    let device_b = fixture.connect_device(1, 0).await;
    let route_a = stream(0x91);
    let generation_a = generation(0xa1);
    let route_b = stream(0x92);
    let generation_b = generation(0xa2);

    let forbidden = fixture
        .core
        .handle(
            &device_a.access,
            register_frame(fixture.realms[0].machine_route, route_a, generation_a),
        )
        .await
        .expect_err("device cannot register a machine-owned stream");
    assert_eq!(forbidden.code, RELAY_ROUTE_FORBIDDEN);
    let forbidden = fixture
        .core
        .handle(
            &machine_a.access,
            subscribe_frame(route_a, generation_a, StreamCursor::BeforeFirst),
        )
        .await
        .expect_err("machine cannot create a device subscription");
    assert_eq!(forbidden.code, RELAY_ROUTE_FORBIDDEN);
    let forbidden = fixture
        .core
        .handle(
            &machine_a.access,
            outer(RelayFrameBody::Ping(Ping { nonce: 7 })),
        )
        .await
        .expect_err("heartbeat Ping is server-owned; endpoints only answer with Pong");
    assert_eq!(forbidden.code, RELAY_ROUTE_FORBIDDEN);

    assert_applied(
        fixture
            .core
            .handle(
                &machine_a.access,
                register_frame(fixture.realms[0].machine_route, route_a, generation_a),
            )
            .await
            .expect("register first stream"),
    );
    assert_applied(
        fixture
            .core
            .handle(
                &machine_a.access,
                register_frame(fixture.realms[0].machine_route, route_a, generation_a),
            )
            .await
            .expect("exact register retry is idempotent"),
    );

    let takeover = fixture
        .core
        .handle(
            &machine_b.access,
            register_frame(fixture.realms[1].machine_route, route_a, generation_a),
        )
        .await
        .expect_err("foreign machine cannot take over route or generation");
    assert_eq!(takeover.code, RELAY_ROUTE_NOT_FOUND);
    let stale_generation = fixture
        .core
        .handle(
            &machine_a.access,
            register_frame(fixture.realms[0].machine_route, route_a, generation(0xfe)),
        )
        .await
        .expect_err("a route cannot be rebound to a generation");
    assert_eq!(stale_generation.code, RELAY_STREAM_GENERATION_STALE);

    let out_of_order = fixture
        .core
        .handle(
            &machine_a.access,
            publish_frame(route_a, generation_a, 1, 0x01),
        )
        .await
        .expect_err("first stream frame must be zero");
    assert_eq!(out_of_order.code, RELAY_STREAM_OUT_OF_ORDER);
    let max_without_wrap = fixture
        .core
        .handle(
            &machine_a.access,
            publish_frame(route_a, generation_a, u64::MAX, 0xff),
        )
        .await
        .expect_err("u64::MAX cannot skip to the end or wrap a generation");
    assert_eq!(max_without_wrap.code, RELAY_STREAM_GENERATION_STALE);
    assert_queued_publish(
        fixture
            .core
            .handle(
                &machine_a.access,
                publish_frame(route_a, generation_a, 0, 0x10),
            )
            .await
            .expect("stream A starts at zero"),
        route_a,
        0,
    );

    assert_applied(
        fixture
            .core
            .handle(
                &machine_a.access,
                register_frame(fixture.realms[0].machine_route, route_b, generation_b),
            )
            .await
            .expect("register second stream"),
    );
    assert_queued_publish(
        fixture
            .core
            .handle(
                &machine_a.access,
                publish_frame(route_b, generation_b, 0, 0x20),
            )
            .await
            .expect("each stream generation owns an independent sequence"),
        route_b,
        0,
    );

    let foreign_subscribe = fixture
        .core
        .handle(
            &device_b.access,
            subscribe_frame(route_a, generation_a, StreamCursor::BeforeFirst),
        )
        .await
        .expect_err("foreign trust domain cannot discover stream ownership");
    assert_eq!(foreign_subscribe.code, RELAY_ROUTE_NOT_FOUND);
    let generation_mismatch = fixture
        .core
        .handle(
            &device_a.access,
            subscribe_frame(route_a, generation(0xfd), StreamCursor::BeforeFirst),
        )
        .await
        .expect_err("same machine still must match stream generation");
    assert_eq!(generation_mismatch.code, RELAY_STREAM_GENERATION_STALE);

    drop((machine_a, device_a, machine_b, device_b));
    fixture.shutdown().await;
}

#[tokio::test]
async fn before_first_at_zero_empty_and_multi_page_replay_are_ordered() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let empty_route = stream(0x93);
    let empty_generation = generation(0xa3);
    let route = stream(0x94);
    let stream_generation = generation(0xa4);

    for (route, generation) in [(empty_route, empty_generation), (route, stream_generation)] {
        assert_applied(
            fixture
                .core
                .handle(
                    &machine.access,
                    register_frame(fixture.realms[0].machine_route, route, generation),
                )
                .await
                .expect("register replay stream"),
        );
    }

    let empty = fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(empty_route, empty_generation, StreamCursor::BeforeFirst),
        )
        .await
        .expect("subscribe empty stream");
    let RouteOutcome::Replay(ticket) = empty else {
        panic!("empty stream must return a replay ticket: {empty:?}");
    };
    assert_eq!(ticket.next, StreamCursor::BeforeFirst);
    assert_eq!(ticket.terminal, StreamCursor::BeforeFirst);
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: empty_route,
            generation: empty_generation,
            current_cursor: StreamCursor::BeforeFirst,
        })
    );

    for seq in 0..70_u64 {
        assert_queued_publish(
            fixture
                .core
                .handle(
                    &machine.access,
                    publish_frame(route, stream_generation, seq, seq as u8),
                )
                .await
                .expect("publish replay fixture"),
            route,
            seq,
        );
    }

    let replay = fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(route, stream_generation, StreamCursor::At(0)),
        )
        .await
        .expect("subscribe from At(0)");
    let RouteOutcome::Replay(ticket) = replay else {
        panic!("non-empty stream must return replay ticket: {replay:?}");
    };
    assert_eq!(ticket.next, StreamCursor::At(0));
    assert_eq!(ticket.terminal, StreamCursor::At(69));

    for expected in 1..70_u64 {
        let frame = recv_frame(&mut device).await;
        let RelayFrameBody::Publish(publish) = frame.body else {
            panic!("replay must deliver Publish before terminal");
        };
        assert_eq!(publish.stream_seq, expected);
        assert_eq!(publish.sealed_blob.0, vec![expected as u8]);
    }
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: route,
            generation: stream_generation,
            current_cursor: StreamCursor::At(69),
        })
    );

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test]
async fn one_device_can_queue_multiple_stream_replays_without_cross_stream_reordering() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture
        .connect_device_with_writer(
            0,
            0,
            OutboundWriterConfig {
                normal: WriterBudget::new(64, 8 * 1024 * 1024),
                control: WriterBudget::new(16, 1024 * 1024),
            },
        )
        .await;
    let first_route = stream(0xb1);
    let first_generation = generation(0xc1);
    let second_route = stream(0xb2);
    let second_generation = generation(0xc2);

    for (route, generation) in [
        (first_route, first_generation),
        (second_route, second_generation),
    ] {
        assert_applied(
            fixture
                .core
                .handle(
                    &machine.access,
                    register_frame(fixture.realms[0].machine_route, route, generation),
                )
                .await
                .expect("register stream"),
        );
    }
    for seq in 0..70_u64 {
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(first_route, first_generation, seq, seq as u8),
            )
            .await
            .expect("seed first stream");
    }
    for seq in 0..2_u64 {
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(second_route, second_generation, seq, 0xe0 + seq as u8),
            )
            .await
            .expect("seed second stream");
    }

    assert!(matches!(
        fixture
            .core
            .handle(
                &device.access,
                subscribe_frame(first_route, first_generation, StreamCursor::BeforeFirst,),
            )
            .await
            .expect("start first replay"),
        RouteOutcome::Replay(_)
    ));
    assert!(matches!(
        fixture
            .core
            .handle(
                &device.access,
                subscribe_frame(second_route, second_generation, StreamCursor::BeforeFirst,),
            )
            .await
            .expect("queue second replay while first is blocked on writer budget"),
        RouteOutcome::Replay(_)
    ));

    for expected in 0..70_u64 {
        let RelayFrameBody::Publish(frame) = recv_frame(&mut device).await.body else {
            panic!("first replay must remain contiguous");
        };
        assert_eq!(frame.stream_route, first_route);
        assert_eq!(frame.stream_seq, expected);
    }
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: first_route,
            generation: first_generation,
            current_cursor: StreamCursor::At(69),
        })
    );
    for expected in 0..2_u64 {
        let RelayFrameBody::Publish(frame) = recv_frame(&mut device).await.body else {
            panic!("second replay must start after the first terminal");
        };
        assert_eq!(frame.stream_route, second_route);
        assert_eq!(frame.stream_seq, expected);
    }
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: second_route,
            generation: second_generation,
            current_cursor: StreamCursor::At(1),
        })
    );

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn queued_empty_replays_wait_for_control_budget_instead_of_disconnect() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture
        .connect_device_with_writer(
            0,
            0,
            OutboundWriterConfig {
                normal: WriterBudget::new(64, 8 * 1024 * 1024),
                control: WriterBudget::new(16, 1024 * 1024),
            },
        )
        .await;
    let active_route = stream(0xd0);
    let active_generation = generation(0xe0);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(
                    fixture.realms[0].machine_route,
                    active_route,
                    active_generation,
                ),
            )
            .await
            .expect("register active stream"),
    );
    for seq in 0..70_u64 {
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(active_route, active_generation, seq, seq as u8),
            )
            .await
            .expect("seed active replay");
    }
    assert!(matches!(
        fixture
            .core
            .handle(
                &device.access,
                subscribe_frame(active_route, active_generation, StreamCursor::BeforeFirst,),
            )
            .await
            .expect("start active replay"),
        RouteOutcome::Replay(_)
    ));

    let mut empty_streams = Vec::new();
    for index in 0..20_u8 {
        let route = stream(0x20 + index);
        let generation = generation(0x40 + index);
        assert_applied(
            fixture
                .core
                .handle(
                    &machine.access,
                    register_frame(fixture.realms[0].machine_route, route, generation),
                )
                .await
                .expect("register empty stream"),
        );
        assert!(matches!(
            fixture
                .core
                .handle(
                    &device.access,
                    subscribe_frame(route, generation, StreamCursor::BeforeFirst),
                )
                .await
                .expect("queue empty replay"),
            RouteOutcome::Replay(_)
        ));
        empty_streams.push((route, generation));
    }

    for expected in 0..70_u64 {
        let RelayFrameBody::Publish(frame) = recv_frame(&mut device).await.body else {
            panic!("active replay must remain connected");
        };
        assert_eq!(frame.stream_route, active_route);
        assert_eq!(frame.stream_seq, expected);
    }
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: active_route,
            generation: active_generation,
            current_cursor: StreamCursor::At(69),
        })
    );
    for (route, generation) in empty_streams {
        assert_eq!(
            recv_frame(&mut device).await.body,
            RelayFrameBody::ReplayComplete(ReplayComplete {
                stream_route: route,
                generation,
                current_cursor: StreamCursor::BeforeFirst,
            })
        );
    }
    assert_eq!(device.writer.close_reason(), None);

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test]
async fn tiny_writer_replays_nonempty_history_one_frame_at_a_time() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture
        .connect_device_with_writer(
            0,
            0,
            OutboundWriterConfig {
                normal: WriterBudget::new(1, 1024),
                control: WriterBudget::new(2, 1024),
            },
        )
        .await;
    let route = stream(0x71);
    let generation = generation(0x72);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, generation),
            )
            .await
            .expect("register tiny-writer stream"),
    );
    for seq in 0..2_u64 {
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(route, generation, seq, 0xa0 + seq as u8),
            )
            .await
            .expect("seed tiny-writer replay");
    }
    assert!(matches!(
        fixture
            .core
            .handle(
                &device.access,
                subscribe_frame(route, generation, StreamCursor::BeforeFirst),
            )
            .await
            .expect("subscribe with tiny writer"),
        RouteOutcome::Replay(_)
    ));
    for expected in 0..2_u64 {
        let RelayFrameBody::Publish(frame) = recv_frame(&mut device).await.body else {
            panic!("tiny writer must receive paginated history");
        };
        assert_eq!(frame.stream_seq, expected);
    }
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            current_cursor: StreamCursor::At(1),
            ..
        })
    ));
    assert_eq!(device.writer.close_reason(), None);

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test]
async fn core_clamps_default_writer_pages_to_a_smaller_store_page_limit() {
    let mut fixture = Fixture::new_with_replay_page_frames(2_000, 2).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let route = stream(0x77);
    let generation = generation(0x78);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, generation),
            )
            .await
            .expect("register clamped-page stream"),
    );
    for seq in 0..5_u64 {
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(route, generation, seq, 0xc0 + seq as u8),
            )
            .await
            .expect("seed clamped Store pages");
    }
    fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(route, generation, StreamCursor::BeforeFirst),
        )
        .await
        .expect("subscribe through smaller Store page max");
    for expected in 0..5_u64 {
        let RelayFrameBody::Publish(frame) = recv_frame(&mut device).await.body else {
            panic!("Store page clamp must still replay every frame");
        };
        assert_eq!(frame.stream_seq, expected);
    }
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            current_cursor: StreamCursor::At(4),
            ..
        })
    ));

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn replay_retries_transient_store_worker_busy_without_holding_writer_budget() {
    let blocker = Arc::new(BlockingFault::new(FaultPoint::PublishBeforeCommit));
    let fault: Arc<dyn FaultInjector> = blocker.clone();
    let mut fixture = Fixture::new_with_core_config(
        2_000,
        Some(fault),
        CoreConfig {
            replay_staging_pages: 1,
            ..CoreConfig::default()
        },
    )
    .await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture
        .connect_device_with_writer(
            0,
            0,
            OutboundWriterConfig {
                normal: WriterBudget::new(1, 1024),
                control: WriterBudget::new(4, 1024),
            },
        )
        .await;
    let route = stream(0x79);
    let generation = generation(0x7a);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, generation),
            )
            .await
            .expect("register busy-retry stream"),
    );
    fixture
        .core
        .handle(&machine.access, publish_frame(route, generation, 0, 0xd0))
        .await
        .expect("seed frozen replay frame");
    device
        .writer
        .try_enqueue_data(outer(RelayFrameBody::Ping(Ping { nonce: 0xbeef })))
        .expect("hold tiny writer budget before replay");
    fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(route, generation, StreamCursor::BeforeFirst),
        )
        .await
        .expect("start replay waiting on writer budget");

    blocker.arm();
    let core = fixture.core.clone();
    let machine_access = machine.access.clone();
    let blocked_publish = tokio::spawn(async move {
        core.handle(&machine_access, publish_frame(route, generation, 1, 0xd1))
            .await
    });
    blocker.wait_until_entered().await;

    let mut admitted = 0_usize;
    let mut observed_full = false;
    for _ in 0..5 {
        match tokio::time::timeout(Duration::from_millis(10), fixture.store.inspect()).await {
            Err(_) => admitted += 1,
            Ok(Err(StoreError::WorkerBusy)) => {
                observed_full = true;
                break;
            }
            Ok(other) => panic!("unexpected Store saturation result: {other:?}"),
        }
    }
    assert_eq!(admitted, 4, "four commands fill the bounded Store queue");
    assert!(observed_full);
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::Ping(Ping { nonce: 0xbeef })
    ));
    tokio::time::sleep(Duration::from_millis(10)).await;
    blocker.release();
    tokio::time::timeout(Duration::from_secs(5), blocked_publish)
        .await
        .expect("blocked publish must resume")
        .expect("publish task must not panic")
        .expect("publish must commit");

    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::Publish(Publish { stream_seq: 0, .. })
    ));
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            current_cursor: StreamCursor::At(0),
            ..
        })
    ));
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::Publish(Publish { stream_seq: 1, .. })
    ));
    assert_eq!(device.writer.close_reason(), None);

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_output_observes_auth_transition_fence_before_writer_enqueue() {
    let blocker = Arc::new(ReplayTransitionFault::new());
    let fault: Arc<dyn FaultInjector> = blocker.clone();
    let mut fixture = Fixture::new(2_000, Some(fault)).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let route = stream(0x7b);
    let stream_generation = generation(0x7c);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, stream_generation),
            )
            .await
            .expect("register transition-fence stream"),
    );
    fixture
        .core
        .handle(
            &machine.access,
            publish_frame(route, stream_generation, 0, 0xda),
        )
        .await
        .expect("seed replay frame");

    blocker.arm();
    assert!(matches!(
        fixture
            .core
            .handle(
                &device.access,
                subscribe_frame(route, stream_generation, StreamCursor::BeforeFirst),
            )
            .await
            .expect("start replay before transition"),
        RouteOutcome::Replay(_)
    ));
    blocker.replay.wait_until_entered().await;

    let revoke = fixture.realms[0].signed_revocation(fixture.realms[0].server, 0);
    let origin = machine.access.clone();
    let auth = fixture.auth.clone();
    let revoke_task = tokio::spawn(async move { auth.revoke_from(origin, revoke).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !fixture
                .auth
                .is_current(&device.access)
                .expect("read transition fence")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("revoke must fence the device before Store access");

    // 让已经完整读出的 replay page 返回；Store 随即在 revoke COMMIT 前再次阻塞，
    // 因而 Core 处理 ReplayReady 时授权必定仍是 Transitioning。
    blocker.replay.release();
    blocker.revoke.wait_until_entered().await;
    let reason = tokio::time::timeout(Duration::from_secs(5), device.writer.closed())
        .await
        .expect("replay enqueue must observe transition without hanging");
    assert_eq!(reason, WriterCloseReason::AuthorizationInvalidated);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), device.receiver.recv())
            .await
            .expect("closed receiver must resolve")
            .is_none(),
        "no replay Publish/Gap/ReplayComplete may cross the transition fence"
    );

    blocker.revoke.release();
    revoke_task
        .await
        .expect("revoke task")
        .expect("revoke commit");
    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn hot_stream_catchup_yields_to_another_queued_stream() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture
        .connect_device_with_writer(
            0,
            0,
            OutboundWriterConfig {
                normal: WriterBudget::new(1, 1024),
                control: WriterBudget::new(4, 1024),
            },
        )
        .await;
    let hot_route = stream(0x73);
    let hot_generation = generation(0x74);
    let other_route = stream(0x75);
    let other_generation = generation(0x76);
    for (route, generation) in [(hot_route, hot_generation), (other_route, other_generation)] {
        assert_applied(
            fixture
                .core
                .handle(
                    &machine.access,
                    register_frame(fixture.realms[0].machine_route, route, generation),
                )
                .await
                .expect("register fairness stream"),
        );
    }
    fixture
        .core
        .handle(
            &machine.access,
            publish_frame(hot_route, hot_generation, 0, 0xb0),
        )
        .await
        .expect("seed hot initial frame");
    device
        .writer
        .try_enqueue_data(outer(RelayFrameBody::Ping(Ping { nonce: 0xfeed })))
        .expect("occupy the one-frame normal budget");

    fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(hot_route, hot_generation, StreamCursor::BeforeFirst),
        )
        .await
        .expect("start blocked hot replay");
    fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(other_route, other_generation, StreamCursor::BeforeFirst),
        )
        .await
        .expect("queue other stream");
    fixture
        .core
        .handle(
            &machine.access,
            publish_frame(hot_route, hot_generation, 1, 0xb1),
        )
        .await
        .expect("publish behind frozen hot terminal");

    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::Ping(Ping { nonce: 0xfeed })
    ));
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::Publish(Publish {
            stream_route,
            stream_seq: 0,
            ..
        }) if stream_route == hot_route
    ));
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route,
            current_cursor: StreamCursor::At(0),
            ..
        }) if stream_route == hot_route
    ));
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: other_route,
            generation: other_generation,
            current_cursor: StreamCursor::BeforeFirst,
        })
    );
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::Publish(Publish {
            stream_route,
            stream_seq: 1,
            ..
        }) if stream_route == hot_route
    ));
    assert_eq!(device.writer.close_reason(), None);

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test]
async fn publish_during_replay_never_overtakes_replay_complete_or_disappears() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let route = stream(0x95);
    let stream_generation = generation(0xa5);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, stream_generation),
            )
            .await
            .expect("register stream"),
    );
    for seq in 0..70_u64 {
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(route, stream_generation, seq, seq as u8),
            )
            .await
            .expect("seed replay page boundary");
    }

    fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(route, stream_generation, StreamCursor::BeforeFirst),
        )
        .await
        .expect("begin replay");
    assert_queued_publish(
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(route, stream_generation, 70, 70),
            )
            .await
            .expect("publish while replay actor is active"),
        route,
        70,
    );

    for expected in 0..70_u64 {
        let RelayFrameBody::Publish(publish) = recv_frame(&mut device).await.body else {
            panic!("frozen replay must remain ordered through 69");
        };
        assert_eq!(publish.stream_seq, expected);
    }
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: route,
            generation: stream_generation,
            current_cursor: StreamCursor::At(69),
        })
    );
    let RelayFrameBody::Publish(live) = recv_frame(&mut device).await.body else {
        panic!("publish committed during replay must become live after terminal");
    };
    assert_eq!(live.stream_seq, 70);

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test]
async fn publish_is_invisible_before_commit_and_after_commit_retry_repairs_fanout() {
    for (fault_point, committed_on_error) in [
        (FaultPoint::PublishBeforeCommit, false),
        (FaultPoint::PublishAfterCommit, true),
    ] {
        let fault: Arc<dyn FaultInjector> = Arc::new(ArmedFault::new(fault_point));
        let mut fixture = Fixture::new(2_000, Some(fault)).await;
        let mut machine = fixture.connect_machine(0).await;
        let mut device = fixture.connect_device(0, 0).await;
        let route = stream(if committed_on_error { 0x97 } else { 0x96 });
        let stream_generation = generation(if committed_on_error { 0xa7 } else { 0xa6 });
        assert_applied(
            fixture
                .core
                .handle(
                    &machine.access,
                    register_frame(fixture.realms[0].machine_route, route, stream_generation),
                )
                .await
                .expect("register fault stream"),
        );
        fixture
            .core
            .handle(
                &device.access,
                subscribe_frame(route, stream_generation, StreamCursor::BeforeFirst),
            )
            .await
            .expect("subscribe before fault");
        assert!(matches!(
            recv_frame(&mut device).await.body,
            RelayFrameBody::ReplayComplete(_)
        ));

        let failure = fixture
            .core
            .handle(
                &machine.access,
                publish_frame(route, stream_generation, 0, 0xc0),
            )
            .await
            .expect_err("faulted publish must not report accepted");
        assert_eq!(failure.code, RELAY_STORE_UNAVAILABLE);

        // 用同 FIFO 的显式哨兵证明错误路径没有先行扇出，不依赖 sleep/负向超时。
        device
            .writer
            .try_enqueue_control(outer(RelayFrameBody::Ping(Ping { nonce: 0xfeed })))
            .expect("enqueue deterministic visibility sentinel");
        assert_eq!(
            recv_frame(&mut device).await.body,
            RelayFrameBody::Ping(Ping { nonce: 0xfeed })
        );
        machine
            .writer
            .try_enqueue_control(outer(RelayFrameBody::Ping(Ping { nonce: 0xf00d })))
            .expect("enqueue deterministic origin sentinel");
        assert_eq!(
            recv_frame(&mut machine).await.body,
            RelayFrameBody::Ping(Ping { nonce: 0xf00d }),
            "failed Publish must not enqueue a RouteAccepted at origin"
        );

        let retry = fixture
            .core
            .handle(
                &machine.access,
                publish_frame(route, stream_generation, 0, 0xc0),
            )
            .await
            .expect("retry must either insert or recognize committed duplicate");
        assert_queued_publish(retry, route, 0);
        let RelayFrameBody::Publish(delivered) = recv_frame(&mut device).await.body else {
            panic!("successful retry must fan out the durable frame");
        };
        assert_eq!(delivered.stream_seq, 0);
        assert_eq!(delivered.sealed_blob.0, vec![0xc0]);
        assert_eq!(
            recv_frame(&mut machine).await.body,
            RelayFrameBody::RouteAccepted(agentdeck_protocol::relay_v2::frame::RouteAccepted {
                accepted: agentdeck_protocol::relay_v2::frame::AcceptedRef::StreamFrame {
                    stream_route: route,
                    stream_seq: 0,
                },
            }),
            "Queued means RouteAccepted really entered the origin bounded FIFO"
        );

        drop((machine, device));
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn gap_pauses_live_until_explicit_valid_resubscribe() {
    let mut fixture = Fixture::new(2, None).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let route = stream(0x98);
    let stream_generation = generation(0xa8);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, stream_generation),
            )
            .await
            .expect("register gap stream"),
    );
    for seq in 0..3_u64 {
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(route, stream_generation, seq, seq as u8),
            )
            .await
            .expect("publish retained-window fixture");
    }

    let outcome = fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(route, stream_generation, StreamCursor::BeforeFirst),
        )
        .await
        .expect("gap is a typed route outcome");
    let RouteOutcome::Gap(gap) = outcome else {
        panic!("evicted prefix must produce Gap: {outcome:?}");
    };
    assert_eq!(gap.need_stream_seq, 0);
    assert_eq!(gap.oldest_stream_seq, 1);
    assert_eq!(recv_frame(&mut device).await.body, RelayFrameBody::Gap(gap));

    fixture
        .core
        .handle(
            &machine.access,
            publish_frame(route, stream_generation, 3, 3),
        )
        .await
        .expect("publish while subscriber is gap-paused");
    device
        .writer
        .try_enqueue_control(outer(RelayFrameBody::Ping(Ping { nonce: 0xbeef })))
        .expect("enqueue pause sentinel");
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::Ping(Ping { nonce: 0xbeef }),
        "gap-paused connection must not receive a higher live sequence"
    );

    let resumed = fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(route, stream_generation, StreamCursor::At(1)),
        )
        .await
        .expect("backfill/snapshot cursor explicitly resumes live");
    assert!(matches!(resumed, RouteOutcome::Replay(_)));
    for expected in 2..=3_u64 {
        let RelayFrameBody::Publish(publish) = recv_frame(&mut device).await.body else {
            panic!("resume must replay retained suffix");
        };
        assert_eq!(publish.stream_seq, expected);
    }
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            current_cursor: StreamCursor::At(3),
            ..
        })
    ));
    fixture
        .core
        .handle(
            &machine.access,
            publish_frame(route, stream_generation, 4, 4),
        )
        .await
        .expect("publish after resume");
    let RelayFrameBody::Publish(live) = recv_frame(&mut device).await.body else {
        panic!("valid re-Subscribe must release live delivery");
    };
    assert_eq!(live.stream_seq, 4);

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test]
async fn slow_writer_disconnects_only_itself_and_fast_writer_continues() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine = fixture.connect_machine(0).await;
    let tiny_writer = OutboundWriterConfig {
        normal: WriterBudget::new(1, 1_024),
        control: WriterBudget::new(4, 4_096),
    };
    let mut slow = fixture.connect_device_with_writer(0, 0, tiny_writer).await;
    let mut fast = fixture.connect_device(0, 1).await;
    let route = stream(0x99);
    let stream_generation = generation(0xa9);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, stream_generation),
            )
            .await
            .expect("register fanout stream"),
    );
    for connection in [&slow, &fast] {
        fixture
            .core
            .handle(
                &connection.access,
                subscribe_frame(route, stream_generation, StreamCursor::BeforeFirst),
            )
            .await
            .expect("subscribe fanout target");
    }
    assert!(matches!(
        recv_frame(&mut slow).await.body,
        RelayFrameBody::ReplayComplete(_)
    ));
    assert!(matches!(
        recv_frame(&mut fast).await.body,
        RelayFrameBody::ReplayComplete(_)
    ));

    for seq in 0..2_u64 {
        assert_queued_publish(
            fixture
                .core
                .handle(
                    &machine.access,
                    publish_frame(route, stream_generation, seq, seq as u8),
                )
                .await
                .expect("publisher succeeds despite one slow consumer"),
            route,
            seq,
        );
    }
    assert_eq!(slow.writer.close_reason(), Some(WriterCloseReason::Lagged));
    assert_receiver_closed(&mut slow).await;
    assert!(
        !fixture
            .auth
            .is_current(&slow.access)
            .expect("read slow authorization state"),
        "lagged writer must clean up its active generation"
    );

    for expected in 0..2_u64 {
        let RelayFrameBody::Publish(publish) = recv_frame(&mut fast).await.body else {
            panic!("fast writer must retain its own FIFO");
        };
        assert_eq!(publish.stream_seq, expected);
    }
    assert!(
        fixture
            .auth
            .is_current(&fast.access)
            .expect("read fast authorization state")
    );
    fixture
        .core
        .handle(
            &machine.access,
            publish_frame(route, stream_generation, 2, 2),
        )
        .await
        .expect("fast connection remains routable");
    let RelayFrameBody::Publish(live) = recv_frame(&mut fast).await.body else {
        panic!("fast connection must receive later live frames");
    };
    assert_eq!(live.stream_seq, 2);

    drop((machine, slow, fast));
    fixture.shutdown().await;
}

#[tokio::test]
async fn global_normal_budget_reserves_origin_acceptance_before_slow_reader_fanout() {
    let mut fixture = Fixture::new_with_core_config(
        2_000,
        None,
        CoreConfig {
            global_normal_max_frames: 1,
            ..CoreConfig::default()
        },
    )
    .await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let route = stream(0x88);
    let stream_generation = generation(0x89);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, stream_generation),
            )
            .await
            .expect("register globally bounded stream"),
    );
    assert!(matches!(
        fixture
            .core
            .handle(
                &device.access,
                subscribe_frame(route, stream_generation, StreamCursor::BeforeFirst),
            )
            .await
            .expect("subscribe empty stream"),
        RouteOutcome::Replay(_)
    ));
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(_)
    ));

    let outcome = fixture
        .core
        .handle(
            &machine.access,
            publish_frame(route, stream_generation, 0, 0xe1),
        )
        .await
        .expect("committed publish must still return an origin outcome");
    assert!(
        matches!(outcome, RouteOutcome::Queued(_)),
        "origin acceptance owns the first global normal permit"
    );
    assert_eq!(machine.writer.close_reason(), None);
    assert_eq!(
        device.writer.close_reason(),
        Some(WriterCloseReason::Lagged)
    );

    drop((machine, device));
    fixture.shutdown().await;
}

#[tokio::test]
async fn subscribe_unsubscribe_ack_and_disconnect_resume_are_idempotent_and_durable() {
    let mut fixture = Fixture::new(2_000, None).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let route = stream(0x9a);
    let stream_generation = generation(0xaa);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                register_frame(fixture.realms[0].machine_route, route, stream_generation),
            )
            .await
            .expect("register lifecycle stream"),
    );
    for seq in 0..3_u64 {
        fixture
            .core
            .handle(
                &machine.access,
                publish_frame(route, stream_generation, seq, seq as u8),
            )
            .await
            .expect("publish lifecycle fixture");
    }
    fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(route, stream_generation, StreamCursor::BeforeFirst),
        )
        .await
        .expect("initial subscribe");
    for expected in 0..3_u64 {
        let RelayFrameBody::Publish(publish) = recv_frame(&mut device).await.body else {
            panic!("initial replay frame expected");
        };
        assert_eq!(publish.stream_seq, expected);
    }
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(_)
    ));

    assert_applied(
        fixture
            .core
            .handle(&device.access, ack_frame(route, stream_generation, 1))
            .await
            .expect("advance ACK"),
    );
    assert_applied(
        fixture
            .core
            .handle(&device.access, ack_frame(route, stream_generation, 1))
            .await
            .expect("same ACK is idempotent"),
    );
    assert_applied(
        fixture
            .core
            .handle(&device.access, ack_frame(route, stream_generation, 0))
            .await
            .expect("lower ACK is an idempotent no-op"),
    );
    let future = fixture
        .core
        .handle(&device.access, ack_frame(route, stream_generation, 4))
        .await
        .expect_err("ACK cannot move beyond stream high-water");
    assert_eq!(future.code, RELAY_STREAM_OUT_OF_ORDER);

    assert_applied(
        fixture
            .core
            .handle(&device.access, unsubscribe_frame(route, stream_generation))
            .await
            .expect("unsubscribe"),
    );
    assert_applied(
        fixture
            .core
            .handle(&device.access, unsubscribe_frame(route, stream_generation))
            .await
            .expect("duplicate unsubscribe"),
    );
    fixture
        .core
        .handle(
            &machine.access,
            publish_frame(route, stream_generation, 3, 3),
        )
        .await
        .expect("publish after unsubscribe");
    device
        .writer
        .try_enqueue_control(outer(RelayFrameBody::Ping(Ping { nonce: 0xcafe })))
        .expect("enqueue unsubscribe sentinel");
    assert_eq!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::Ping(Ping { nonce: 0xcafe })
    );

    // Re-subscribe creates a new durable lease; disconnect only clears runtime state.
    fixture
        .core
        .handle(
            &device.access,
            subscribe_frame(route, stream_generation, StreamCursor::At(2)),
        )
        .await
        .expect("resubscribe after unsubscribe");
    let RelayFrameBody::Publish(replayed) = recv_frame(&mut device).await.body else {
        panic!("seq 3 must replay");
    };
    assert_eq!(replayed.stream_seq, 3);
    assert!(matches!(
        recv_frame(&mut device).await.body,
        RelayFrameBody::ReplayComplete(_)
    ));
    assert_applied(
        fixture
            .core
            .handle(&device.access, ack_frame(route, stream_generation, 3))
            .await
            .expect("ACK resumed cursor"),
    );

    let disconnected_id = device.access.connection_instance();
    fixture
        .core
        .disconnect(disconnected_id)
        .await
        .expect("disconnect device writer");
    assert_receiver_closed(&mut device).await;
    let persisted = fixture
        .store
        .subscribe(PersistSubscription {
            machine_route: fixture.realms[0].machine_route,
            device_route: fixture.realms[0].devices[0].route,
            grant_serial: fixture.realms[0].devices[0].grant.grant_serial,
            stream_route: route,
            generation: stream_generation,
            start: StreamCursor::At(3),
        })
        .await
        .expect("disconnect must preserve subscription row");
    assert!(persisted.duplicate);
    assert_eq!(persisted.ack, Some(3));

    fixture
        .core
        .handle(
            &machine.access,
            publish_frame(route, stream_generation, 4, 4),
        )
        .await
        .expect("publish while device is disconnected");
    let mut reconnected = fixture.connect_device(0, 0).await;
    fixture
        .core
        .handle(
            &reconnected.access,
            subscribe_frame(route, stream_generation, StreamCursor::At(3)),
        )
        .await
        .expect("reconnect resumes from caller cursor without re-pairing");
    let RelayFrameBody::Publish(resumed) = recv_frame(&mut reconnected).await.body else {
        panic!("reconnected device must receive missed durable frame");
    };
    assert_eq!(resumed.stream_seq, 4);
    assert!(matches!(
        recv_frame(&mut reconnected).await.body,
        RelayFrameBody::ReplayComplete(ReplayComplete {
            current_cursor: StreamCursor::At(4),
            ..
        })
    ));

    drop((machine, device, reconnected));
    fixture.shutdown().await;
}

#[tokio::test]
async fn heartbeat_requires_matching_nonce_and_times_out_at_sixty_seconds() {
    let mut fixture = Fixture::new(2_000, None).await;
    let mut stale = fixture.connect_device(0, 0).await;
    let mut healthy = fixture.connect_device(0, 1).await;

    fixture
        .core
        .tick(19_999)
        .await
        .expect("tick before interval");
    // 20 秒边界由下一次 tick 精确触发，不用 wall-clock sleep。
    fixture.core.tick(20_000).await.expect("heartbeat boundary");
    let RelayFrameBody::Ping(stale_ping) = recv_frame(&mut stale).await.body else {
        panic!("active connection must receive heartbeat Ping");
    };
    let RelayFrameBody::Ping(healthy_ping) = recv_frame(&mut healthy).await.body else {
        panic!("active connection must receive heartbeat Ping");
    };
    assert_ne!(stale_ping.nonce, healthy_ping.nonce);

    assert_applied(
        fixture
            .core
            .handle(
                &stale.access,
                outer(RelayFrameBody::Pong(Pong {
                    nonce: stale_ping.nonce.wrapping_add(1),
                })),
            )
            .await
            .expect("wrong Pong is consumed without becoming an oracle"),
    );
    assert_applied(
        fixture
            .core
            .handle(
                &healthy.access,
                outer(RelayFrameBody::Pong(Pong {
                    nonce: healthy_ping.nonce,
                })),
            )
            .await
            .expect("matching Pong refreshes liveness"),
    );

    fixture
        .core
        .tick(60_000)
        .await
        .expect("sixty-second timeout boundary");
    assert_receiver_closed(&mut stale).await;
    assert!(stale.writer.is_closed());
    assert!(
        !fixture
            .auth
            .is_current(&stale.access)
            .expect("read timed-out principal state")
    );
    assert!(!healthy.writer.is_closed());
    assert!(
        fixture
            .auth
            .is_current(&healthy.access)
            .expect("read healthy principal state")
    );

    let RelayFrameBody::Ping(second_ping) = recv_frame(&mut healthy).await.body else {
        panic!("healthy connection receives the next heartbeat");
    };
    assert_applied(
        fixture
            .core
            .handle(
                &healthy.access,
                outer(RelayFrameBody::Pong(Pong {
                    nonce: second_ping.nonce,
                })),
            )
            .await
            .expect("second matching Pong remains valid"),
    );

    drop((stale, healthy));
    fixture.shutdown().await;
}

#[tokio::test]
async fn machine_link_connection_expires_even_when_matching_pongs_keep_it_alive() {
    // 威胁场景：攻击者在短期 MachineLink 证书到期前建连并持续回复 Pong，若连接生命
    // 周期不复核 absolute expiry，就能在证书到期后继续保有完整 machine 权限。
    let core_config = CoreConfig {
        initial_now_ms: NOW_MS,
        ..CoreConfig::default()
    };
    let mut fixture = Fixture::new_with_core_config(2_000, None, core_config).await;
    let mut machine = fixture.connect_machine(0).await;

    for now_ms in [NOW_MS + 20_000, NOW_MS + 40_000] {
        fixture.core.tick(now_ms).await.expect("heartbeat tick");
        let RelayFrameBody::Ping(ping) = recv_frame(&mut machine).await.body else {
            panic!("active machine must receive heartbeat Ping");
        };
        assert_applied(
            fixture
                .core
                .handle(
                    &machine.access,
                    outer(RelayFrameBody::Pong(Pong { nonce: ping.nonce })),
                )
                .await
                .expect("matching Pong keeps only the heartbeat lease alive"),
        );
        assert!(!machine.writer.is_closed());
    }

    fixture
        .core
        .tick(NOW_MS + 60_000)
        .await
        .expect("certificate absolute-expiry boundary");
    assert_receiver_closed(&mut machine).await;
    assert!(machine.writer.is_closed());
    assert!(
        !fixture
            .auth
            .is_current(&machine.access)
            .expect("read expired principal state")
    );
    let rejected = fixture
        .core
        .handle(
            &machine.access,
            register_frame(
                fixture.realms[0].machine_route,
                stream(0xee),
                generation(0xef),
            ),
        )
        .await
        .expect_err("expired MachineAccess cannot authorize a later frame");
    assert_eq!(rejected.code, RELAY_AUTH_INVALID_GRANT);

    drop(machine);
    fixture.shutdown().await;
}

#[tokio::test]
async fn active_generation_replacement_closes_old_writer_and_rejects_stale_access() {
    let mut fixture = Fixture::new(2_000, None).await;
    let mut old = fixture.connect_machine(0).await;
    let replacement = fixture.connect_machine(0).await;

    assert_receiver_closed(&mut old).await;
    assert!(
        old.writer.is_closed(),
        "replacement must close the old writer"
    );
    assert!(
        !fixture
            .auth
            .is_current(&old.access)
            .expect("read stale access state")
    );
    assert!(
        fixture
            .auth
            .is_current(&replacement.access)
            .expect("read replacement access state")
    );

    let stale = fixture
        .core
        .handle(
            &old.access,
            register_frame(
                fixture.realms[0].machine_route,
                stream(0x9b),
                generation(0xab),
            ),
        )
        .await
        .expect_err("stale access must be checked again at actor dequeue");
    assert_eq!(stale.code, RELAY_AUTH_INVALID_GRANT);
    assert_applied(
        fixture
            .core
            .handle(
                &replacement.access,
                register_frame(
                    fixture.realms[0].machine_route,
                    stream(0x9b),
                    generation(0xab),
                ),
            )
            .await
            .expect("replacement remains routable"),
    );

    drop((old, replacement));
    fixture.shutdown().await;
}
