//! Relay v2 grant / revoke / machine retirement 安全链端到端契约。
//!
//! 本文件只使用真实 MachineRoot / MachineLink / DeviceSign key 和 challenge proof；
//! control mutation 必须从 current MachineAccess 进入 RelayCore，禁止用 raw store mutator
//! 冒充生产授权路径。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use agentdeck_crypto::{SigningKey, sha256, sign_authentication_transcript, sign_tbs};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, CertRole,
};
use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_INVALID_GRANT, RELAY_ROUTE_FORBIDDEN, RELAY_STORE_UNAVAILABLE,
};
use agentdeck_protocol::relay_v2::frame::{
    AuthProof, Authenticate, GrantCommitted, InstallGrant, OpenPairRoute, PairRouteOpened, Pong,
    Publish, RetireMachine, RetirementCommitted, RevocationCommitted, RevokeDevice, SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial,
    LinkGeneration, MachineRouteId, OpaqueRouteFrame, PairRouteId, PublicKeyBytes,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayGrant, RelayServerId, RootKeyId,
    SignedCertificate, StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch, decode,
};
use agentdeck_relay::v2::auth::{
    AccessContext, AuthenticationOutcome, AuthorizationCoordinator, ChallengeLimits,
    ChallengeRegistry, ChallengeRoute, ChallengeSource, MonotonicClock, PairingHello,
    authorize_pairing_route,
};
use agentdeck_relay::v2::core::writer::{
    OutboundDelivery, OutboundReceiver, OutboundWriter, OutboundWriterConfig, WriterBudget,
    WriterCloseReason,
};
use agentdeck_relay::v2::core::{CoreConfig, RelayCore};
use agentdeck_relay::v2::store::{
    Clock, DiskSpace, DiskSpaceProbe, EnrollmentCodeSeed, FaultInjector, FaultPoint,
    InstallGrantRecord, PersistPublish, PersistSubscription, RegisterMachine, RelayStoreHandle,
    RelayV2StoreConfig, RetentionLimits, StoreError, StreamRegistration,
};
use rusqlite::{Connection, OpenFlags, params};
use tempfile::TempDir;

const NOW_MS: u64 = 1_726_000_000_000;
const TERMINAL_DEADLINE: Duration = Duration::from_secs(2);

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

#[derive(Debug, Default)]
struct ArmedFault {
    point: Option<FaultPoint>,
    armed: AtomicBool,
    matching_checks: AtomicU64,
}

impl ArmedFault {
    fn new(point: FaultPoint) -> Self {
        Self {
            point: Some(point),
            armed: AtomicBool::new(false),
            matching_checks: AtomicU64::new(0),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn matching_checks(&self) -> u64 {
        self.matching_checks.load(Ordering::SeqCst)
    }
}

impl FaultInjector for ArmedFault {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if self.point == Some(point) {
            self.matching_checks.fetch_add(1, Ordering::SeqCst);
            if self.armed.swap(false, Ordering::SeqCst) {
                return Err(StoreError::InjectedFault(point));
            }
        }
        Ok(())
    }
}

fn store_path(temp: &TempDir) -> PathBuf {
    temp.path().join("relay-private").join("relay.db")
}

fn store_config(path: &Path, fault: Arc<ArmedFault>) -> RelayV2StoreConfig {
    let retention = RetentionLimits {
        disk_reserve_bytes: 0,
        disk_reserve_percent: 0,
        ..RetentionLimits::default()
    };
    RelayV2StoreConfig::new(path.to_path_buf())
        .with_clock(Arc::new(FixedStoreClock))
        .with_disk_space_probe(Arc::new(PlentyOfDisk))
        .with_retention(retention)
        .with_fault_injector(fault)
}

fn connection(value: u128) -> ConnectionInstanceId {
    ConnectionInstanceId::from_bytes(value.to_be_bytes())
}

fn source(value: u64) -> ChallengeSource {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    ChallengeSource::from_bytes(bytes)
}

fn outer(body: RelayFrameBody) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    }
}

fn pair_route(seed: u8) -> PairRouteId {
    PairRouteId::from_bytes([seed; 16])
}

fn stream_route(seed: u8) -> StreamRouteId {
    StreamRouteId::from_bytes([seed; 16])
}

fn stream_generation(seed: u8) -> StreamGenerationId {
    StreamGenerationId::from_bytes([seed; 16])
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
) -> SignedCertificate {
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
        cert_role: role,
        generation,
        root_key_id,
        trust_epoch,
        not_after_ms: Some(NOW_MS + 600_000),
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
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    root: SigningKey,
    link: SigningKey,
    link_cert: SignedCertificate,
    devices: Vec<DeviceFixture>,
}

impl RealmFixture {
    async fn install(store: &RelayStoreHandle, server: RelayServerId, seed: u8) -> Self {
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
            LinkGeneration::new(1),
            CertRole::Link,
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
        );
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
                response_blob: vec![seed],
                receipt_hash: [seed.wrapping_add(7); 32],
                machine_route,
                root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
                link_cert: link_cert.clone(),
                data_cert: data_cert.clone(),
                link_cert_hash: link_cert.canonical_sha256(),
                data_cert_hash: data_cert.canonical_sha256(),
            })
            .await
            .expect("register machine");

        let device = Self::make_device_with(
            &root,
            server,
            machine_route,
            root_key_id,
            trust_epoch,
            seed.wrapping_add(0x20),
            1,
        );
        store
            .install_grant(InstallGrantRecord {
                grant: device.grant.clone(),
                grant_hash: device.grant.canonical_sha256(),
            })
            .await
            .expect("install initial device grant");

        Self {
            machine_route,
            root_key_id,
            trust_epoch,
            root,
            link,
            link_cert,
            devices: vec![device],
        }
    }

    fn make_device(&self, server: RelayServerId, seed: u8, serial: u64) -> DeviceFixture {
        Self::make_device_with(
            &self.root,
            server,
            self.machine_route,
            self.root_key_id,
            self.trust_epoch,
            seed,
            serial,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_device_with(
        root: &SigningKey,
        server: RelayServerId,
        machine_route: MachineRouteId,
        root_key_id: RootKeyId,
        trust_epoch: TrustEpoch,
        seed: u8,
        serial: u64,
    ) -> DeviceFixture {
        let route = DeviceRouteId::from_bytes([seed; 16]);
        let key = SigningKey::from_seed(&[seed.wrapping_add(1); 32]);
        let grant = signed_grant(
            root,
            &key,
            server,
            machine_route,
            route,
            root_key_id,
            trust_epoch,
            GrantSerial::new(serial),
        );
        DeviceFixture { route, key, grant }
    }

    fn signed_revocation(&self, server: RelayServerId, device: usize) -> DeviceRevocation {
        let device = &self.devices[device];
        let mut revocation = DeviceRevocation {
            machine_route: self.machine_route,
            device_route: device.route,
            grant_serial: device.grant.grant_serial,
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

    fn signed_retirement(&self, server: RelayServerId) -> RetireMachine {
        let mut retirement = RetireMachine {
            machine_route: self.machine_route,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        retirement.signature = sign_tbs(
            &self.root,
            &retirement.to_be_signed_v1(server, sha256(&self.root.verifying_key().to_bytes())),
        )
        .into();
        retirement
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
        device: usize,
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
    ) -> Authenticate {
        let device = &self.devices[device];
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

struct TestConnection {
    access: AccessContext,
    writer: OutboundWriter,
    receiver: OutboundReceiver,
}

struct PendingOutcome {
    outcome: AuthenticationOutcome,
    writer: OutboundWriter,
    receiver: OutboundReceiver,
}

struct Fixture {
    _temp: TempDir,
    path: PathBuf,
    fault: Arc<ArmedFault>,
    store: RelayStoreHandle,
    registry: ChallengeRegistry,
    auth: AuthorizationCoordinator,
    core: RelayCore,
    realms: Vec<RealmFixture>,
    next_connection: u128,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_fault(None).await
    }

    async fn with_fault(point: Option<FaultPoint>) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = store_path(&temp);
        let fault = Arc::new(point.map_or_else(ArmedFault::default, ArmedFault::new));
        let store = RelayStoreHandle::open(store_config(&path, fault.clone()))
            .await
            .expect("open Relay v2 store");
        let server = store.relay_server_id();
        let realm_a = RealmFixture::install(&store, server, 0x11).await;
        let realm_b = RealmFixture::install(&store, server, 0x61).await;
        let (registry, auth, core) = Self::start_runtime(&store);
        Self {
            _temp: temp,
            path,
            fault,
            store,
            registry,
            auth,
            core,
            realms: vec![realm_a, realm_b],
            next_connection: 1,
        }
    }

    fn start_runtime(
        store: &RelayStoreHandle,
    ) -> (ChallengeRegistry, AuthorizationCoordinator, RelayCore) {
        let registry = ChallengeRegistry::new(
            store.relay_server_id(),
            Arc::new(ManualMonotonicClock::default()),
            ChallengeLimits::default(),
        )
        .expect("challenge registry");
        let (auth, lifecycle) =
            AuthorizationCoordinator::start(store.clone(), 64).expect("auth coordinator");
        let core = RelayCore::start(
            store.clone(),
            auth.clone(),
            lifecycle,
            CoreConfig {
                initial_now_ms: NOW_MS,
                ..CoreConfig::default()
            },
        )
        .expect("Relay Core");
        (registry, auth, core)
    }

    fn server(&self) -> RelayServerId {
        self.store.relay_server_id()
    }

    async fn connect_machine(&mut self, realm: usize) -> TestConnection {
        self.connect_active(realm, None, OutboundWriterConfig::default())
            .await
    }

    async fn connect_device(&mut self, realm: usize, device: usize) -> TestConnection {
        self.connect_active(realm, Some(device), OutboundWriterConfig::default())
            .await
    }

    async fn connect_device_with_writer(
        &mut self,
        realm: usize,
        device: usize,
        config: OutboundWriterConfig,
    ) -> TestConnection {
        self.connect_active(realm, Some(device), config).await
    }

    async fn connect_active(
        &mut self,
        realm: usize,
        device: Option<usize>,
        config: OutboundWriterConfig,
    ) -> TestConnection {
        let connection_number = self.next_connection;
        self.next_connection += 1;
        let connection_id = connection(connection_number);
        let challenge_source = source(connection_number as u64);
        let (writer, receiver) = OutboundWriter::new(config);
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
            .expect("authenticate active principal");
        self.core
            .activate(authenticated.access.clone())
            .await
            .expect("activate principal writer");
        TestConnection {
            access: authenticated.access,
            writer,
            receiver,
        }
    }

    async fn pending_outcome(&mut self, realm: usize, device: Option<usize>) -> PendingOutcome {
        let connection_number = self.next_connection;
        self.next_connection += 1;
        let connection_id = connection(connection_number);
        let challenge_source = source(connection_number as u64);
        let (writer, receiver) = OutboundWriter::channel();
        self.core
            .attach_pending(connection_id, writer.clone())
            .await
            .expect("attach reauthentication writer");
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
        let outcome = self
            .auth
            .authenticate_outcome(frame, consumed, NOW_MS)
            .await
            .expect("valid old proof returns a terminal authentication outcome");
        PendingOutcome {
            outcome,
            writer,
            receiver,
        }
    }

    async fn connect_pairing(&mut self, pair_route: PairRouteId) -> TestConnection {
        let connection_number = self.next_connection;
        self.next_connection += 1;
        let connection_id = connection(connection_number);
        let (writer, receiver) = OutboundWriter::channel();
        self.core
            .attach_pending(connection_id, writer.clone())
            .await
            .expect("attach pairing writer");
        let view = self
            .core
            .pair_route_view(pair_route)
            .await
            .expect("read active PairRoute");
        let access = AccessContext::Pairing(
            authorize_pairing_route(
                PairingHello {
                    protocol_version: RELAY_PROTOCOL_VERSION,
                    relay_server_id: self.server(),
                    connection_instance: connection_id,
                    pair_route,
                },
                &view,
            )
            .expect("authorize exact pairing route"),
        );
        self.core
            .activate(access.clone())
            .await
            .expect("activate pairing writer");
        TestConnection {
            access,
            writer,
            receiver,
        }
    }

    async fn assert_forged_device_cannot_observe_terminal(&mut self, realm: usize, device: usize) {
        let connection_number = self.next_connection;
        self.next_connection += 1;
        let connection_id = connection(connection_number);
        let challenge_source = source(connection_number as u64);
        let (writer, mut receiver) = OutboundWriter::channel();
        self.core
            .attach_pending(connection_id, writer.clone())
            .await
            .expect("attach forged-auth writer");
        let challenge = self
            .registry
            .issue(connection_id, challenge_source)
            .expect("issue challenge");
        let realm_fixture = &self.realms[realm];
        let mut frame = realm_fixture.device_authenticate(device, &challenge);
        frame.signature.0[0] ^= 0x80;
        let route = ChallengeRoute::Device {
            machine_route: realm_fixture.machine_route,
            device_route: realm_fixture.devices[device].route,
        };
        let consumed = self
            .registry
            .consume(connection_id, challenge_source, route)
            .expect("consume challenge");
        let error = self
            .auth
            .authenticate_outcome(frame, consumed, NOW_MS)
            .await
            .expect_err("forged DeviceSign proof cannot read a revocation terminal");
        assert_eq!(error.code, RELAY_AUTH_INVALID_GRANT);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receiver.recv())
                .await
                .is_err(),
            "invalid proof must not receive the persisted terminal bytes"
        );
        self.core
            .disconnect(connection_id)
            .await
            .expect("remove rejected pending connection");
        drop(writer);
    }

    async fn restart(mut self) -> Self {
        self.core.shutdown().await.expect("shutdown Relay Core");
        self.store.shutdown().await.expect("shutdown Relay store");
        self.store = RelayStoreHandle::open(store_config(&self.path, self.fault.clone()))
            .await
            .expect("reopen Relay store");
        (self.registry, self.auth, self.core) = Self::start_runtime(&self.store);
        self
    }

    async fn shutdown(self) {
        self.core.shutdown().await.expect("shutdown Relay Core");
        self.store.shutdown().await.expect("shutdown Relay store");
    }
}

async fn recv_delivery(receiver: &mut OutboundReceiver) -> OutboundDelivery {
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("writer receive must not hang")
        .expect("writer must remain open until terminal flush/deadline")
}

async fn recv_frame(connection: &mut TestConnection) -> OpaqueRouteFrame {
    let delivery = recv_delivery(&mut connection.receiver).await;
    let frame = decode(delivery.encoded()).expect("canonical Relay v2 frame");
    delivery.mark_flushed();
    frame
}

async fn assert_writer_closed(writer: &OutboundWriter, expected: WriterCloseReason) {
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), writer.closed())
            .await
            .expect("writer close must not hang"),
        expected
    );
}

fn open_readonly_db(path: &Path) -> Connection {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Relay DB read-only");
    db.busy_timeout(Duration::from_secs(5))
        .expect("set busy timeout");
    db
}

fn scoped_count(db: &Connection, table: &str, machine: MachineRouteId) -> u64 {
    db.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE machine_route = ?1"),
        params![machine.as_bytes().as_slice()],
        |row| row.get(0),
    )
    .expect("read scoped table count")
}

fn stream_frame_count(
    db: &Connection,
    stream: StreamRouteId,
    generation: StreamGenerationId,
) -> u64 {
    db.query_row(
        "SELECT COUNT(*) FROM frames WHERE stream_route = ?1 AND generation = ?2",
        params![
            stream.as_bytes().as_slice(),
            generation.as_bytes().as_slice()
        ],
        |row| row.get(0),
    )
    .expect("read frozen stream frame count")
}

fn global_frame_count(db: &Connection) -> u64 {
    db.query_row("SELECT COUNT(*) FROM frames", [], |row| row.get(0))
        .expect("read global frame count")
}

fn assert_foreign_keys_clean(db: &Connection) {
    let mut statement = db
        .prepare("PRAGMA foreign_key_check")
        .expect("prepare SQLite foreign key check");
    let mut rows = statement.query([]).expect("run SQLite foreign key check");
    assert!(
        rows.next()
            .expect("read SQLite foreign key check")
            .is_none(),
        "purge must not leave orphaned rows hidden by a JOIN through deleted streams"
    );
}

async fn seed_retained_data(
    fixture: &Fixture,
    realm: usize,
    seed: u8,
) -> (StreamRouteId, StreamGenerationId) {
    let realm = &fixture.realms[realm];
    let stream = stream_route(seed);
    let generation = stream_generation(seed.wrapping_add(1));
    fixture
        .store
        .register_stream(StreamRegistration {
            machine_route: realm.machine_route,
            stream_route: stream,
            generation,
        })
        .await
        .expect("register retained stream");
    fixture
        .store
        .publish(PersistPublish::from_publish(
            realm.machine_route,
            Publish {
                stream_route: stream,
                generation,
                stream_seq: 0,
                sealed_blob: SealedBlob(vec![seed; 32]),
            },
        ))
        .await
        .expect("persist retained frame");
    fixture
        .store
        .subscribe(PersistSubscription {
            machine_route: realm.machine_route,
            device_route: realm.devices[0].route,
            grant_serial: realm.devices[0].grant.grant_serial,
            stream_route: stream,
            generation,
            start: StreamCursor::BeforeFirst,
        })
        .await
        .expect("persist subscription");
    (stream, generation)
}

#[tokio::test]
async fn install_grant_requires_current_machine_and_verified_root_binding_then_retries_exactly() {
    let mut fixture = Fixture::new().await;
    let server = fixture.server();
    let mut machine_a = fixture.connect_machine(0).await;
    let device_a = fixture.connect_device(0, 0).await;
    let machine_b = fixture.connect_machine(1).await;

    let new_device = fixture.realms[0].make_device(server, 0x42, 2);
    let install = outer(RelayFrameBody::InstallGrant(InstallGrant {
        grant: new_device.grant.clone(),
    }));

    let role_error = fixture
        .core
        .handle(&device_a.access, install.clone())
        .await
        .expect_err("DeviceAccess cannot install grants");
    assert_eq!(role_error.code, RELAY_ROUTE_FORBIDDEN);

    let cross_machine = fixture
        .core
        .handle(&machine_b.access, install.clone())
        .await
        .expect_err("a different current machine cannot install this grant");
    assert_eq!(cross_machine.code, RELAY_ROUTE_FORBIDDEN);

    let mut forged = new_device.grant.clone();
    forged.signature.0[0] ^= 0x80;
    let forged_error = fixture
        .core
        .handle(
            &machine_a.access,
            outer(RelayFrameBody::InstallGrant(InstallGrant { grant: forged })),
        )
        .await
        .expect_err("forged MachineRoot signature must be rejected before Store mutation");
    assert_eq!(forged_error.code, RELAY_AUTH_INVALID_GRANT);

    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "device_grants",
            fixture.realms[0].machine_route,
        ),
        1,
        "all rejected paths must leave only the initial grant"
    );

    fixture
        .core
        .handle(&machine_a.access, install.clone())
        .await
        .expect("install a root-signed grant");
    let expected = GrantCommitted {
        device_route: new_device.route,
        grant_serial: new_device.grant.grant_serial,
        grant_hash: new_device.grant.canonical_sha256(),
    };
    assert_eq!(
        recv_frame(&mut machine_a).await.body,
        RelayFrameBody::GrantCommitted(expected.clone())
    );

    fixture
        .core
        .handle(&machine_a.access, install)
        .await
        .expect("same canonical grant retry is idempotent");
    assert_eq!(
        recv_frame(&mut machine_a).await.body,
        RelayFrameBody::GrantCommitted(expected)
    );

    let rollback = fixture.realms[0].make_device(server, 0x42, 1);
    let rollback_error = fixture
        .core
        .handle(
            &machine_a.access,
            outer(RelayFrameBody::InstallGrant(InstallGrant {
                grant: rollback.grant,
            })),
        )
        .await
        .expect_err("grant serial rollback must fail closed");
    assert_eq!(rollback_error.code, RELAY_AUTH_INVALID_GRANT);

    fixture.shutdown().await;
}

#[tokio::test]
async fn install_grant_commit_fault_is_zero_write_and_retry_uses_the_same_canonical_hash() {
    let mut fixture = Fixture::with_fault(Some(FaultPoint::InstallGrantBeforeCommit)).await;
    let server = fixture.server();
    let mut machine = fixture.connect_machine(0).await;
    let new_device = fixture.realms[0].make_device(server, 0x43, 2);
    let frame = outer(RelayFrameBody::InstallGrant(InstallGrant {
        grant: new_device.grant.clone(),
    }));

    fixture.fault.arm();
    let failed = fixture
        .core
        .handle(&machine.access, frame.clone())
        .await
        .expect_err("injected pre-COMMIT fault must roll back");
    assert_eq!(failed.code, RELAY_STORE_UNAVAILABLE);
    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "device_grants",
            fixture.realms[0].machine_route,
        ),
        1
    );
    assert!(
        fixture
            .auth
            .is_current(&machine.access)
            .expect("auth state"),
        "origin generation must be restored after rollback"
    );

    fixture
        .core
        .handle(&machine.access, frame)
        .await
        .expect("retry after rollback commits");
    assert_eq!(
        recv_frame(&mut machine).await.body,
        RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: new_device.route,
            grant_serial: new_device.grant.grant_serial,
            grant_hash: new_device.grant.canonical_sha256(),
        })
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn install_grant_after_commit_loss_recovers_ack_and_never_restores_old_device_generation() {
    let mut fixture = Fixture::with_fault(Some(FaultPoint::InstallGrantAfterCommit)).await;
    let server = fixture.server();
    let mut machine = fixture.connect_machine(0).await;
    let old_device = fixture.connect_device(0, 0).await;
    let replacement = fixture.realms[0].make_device(server, 0x31, 2);
    assert_eq!(
        replacement.route, fixture.realms[0].devices[0].route,
        "fixture must replace the same device route"
    );
    let command = outer(RelayFrameBody::InstallGrant(InstallGrant {
        grant: replacement.grant.clone(),
    }));
    let expected = outer(RelayFrameBody::GrantCommitted(GrantCommitted {
        device_route: replacement.route,
        grant_serial: replacement.grant.grant_serial,
        grant_hash: replacement.grant.canonical_sha256(),
    }));
    let fault_check_baseline = fixture.fault.matching_checks();

    fixture.fault.arm();
    fixture
        .core
        .handle(&machine.access, command.clone())
        .await
        .expect("after-COMMIT result loss must recover through exact store retry");
    let first_ack = recv_delivery(&mut machine.receiver).await;
    let frozen_ack = first_ack.encoded().to_vec();
    assert_eq!(decode(first_ack.encoded()).expect("grant ack"), expected);
    first_ack.mark_flushed();
    assert_eq!(
        fixture.fault.matching_checks(),
        fault_check_baseline + 2,
        "InstallGrant checks after COMMIT once for the mutation and once for the duplicate readback"
    );
    assert!(
        !fixture
            .auth
            .is_current(&old_device.access)
            .expect("old device auth state"),
        "a duplicate readback after unknown COMMIT must still invalidate the old generation"
    );
    assert_writer_closed(
        &old_device.writer,
        WriterCloseReason::AuthorizationInvalidated,
    )
    .await;
    let stale_error = fixture
        .core
        .handle(
            &old_device.access,
            outer(RelayFrameBody::Pong(Pong { nonce: 0xdead })),
        )
        .await
        .expect_err("old device access cannot return after recovered grant replacement");
    assert_eq!(stale_error.code, RELAY_AUTH_INVALID_GRANT);

    {
        let db = open_readonly_db(&fixture.path);
        let machine_route = fixture.realms[0].machine_route;
        let stored: (u64, Vec<u8>) = db
            .query_row(
                "SELECT COUNT(*), grant_hash FROM device_grants
                 WHERE machine_route = ?1 AND device_route = ?2",
                params![
                    machine_route.as_bytes().as_slice(),
                    replacement.route.as_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read replaced grant row");
        assert_eq!(stored.0, 1, "replacement mutates one row exactly once");
        assert_eq!(stored.1, replacement.grant.canonical_sha256());
        assert_foreign_keys_clean(&db);
    }

    fixture
        .core
        .handle(&machine.access, command)
        .await
        .expect("an explicit exact retry remains idempotent");
    let retry_ack = recv_delivery(&mut machine.receiver).await;
    assert_eq!(retry_ack.encoded(), frozen_ack);
    retry_ack.mark_flushed();
    assert_eq!(
        fixture.fault.matching_checks(),
        fault_check_baseline + 3,
        "an explicit retry executes one more duplicate readback transaction"
    );
    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "device_grants",
            fixture.realms[0].machine_route,
        ),
        1
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn revoke_commit_fault_restores_target_generation_and_does_not_consume_queued_data() {
    let mut fixture = Fixture::with_fault(Some(FaultPoint::RevokeBeforeCommit)).await;
    let machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let marker = outer(RelayFrameBody::Pong(Pong { nonce: 0xfeed }));
    device
        .writer
        .try_enqueue_data(marker.clone())
        .expect("queue pre-transition marker");
    let revocation = fixture.realms[0].signed_revocation(fixture.server(), 0);

    fixture.fault.arm();
    let failed = fixture
        .core
        .handle(
            &machine.access,
            outer(RelayFrameBody::RevokeDevice(RevokeDevice { revocation })),
        )
        .await
        .expect_err("revoke pre-COMMIT fault must roll back");
    assert_eq!(failed.code, RELAY_STORE_UNAVAILABLE);
    assert!(
        fixture.auth.is_current(&device.access).expect("auth state"),
        "target generation returns to active after rollback"
    );
    let queued = recv_delivery(&mut device.receiver).await;
    assert_eq!(decode(queued.encoded()).expect("marker frame"), marker);
    queued.mark_flushed();
    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "revocations",
            fixture.realms[0].machine_route,
        ),
        0
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn same_machine_replacement_and_revoke_have_two_fail_closed_linearization_orders() {
    let mut fixture = Fixture::new().await;
    let stale_machine = fixture.connect_machine(0).await;
    let device = fixture.connect_device(0, 0).await;
    let mut current_machine = fixture.connect_machine(0).await;
    assert_writer_closed(&stale_machine.writer, WriterCloseReason::Replaced).await;

    let revocation = fixture.realms[0].signed_revocation(fixture.server(), 0);
    let command = outer(RelayFrameBody::RevokeDevice(RevokeDevice {
        revocation: revocation.clone(),
    }));
    let stale_error = fixture
        .core
        .handle(&stale_machine.access, command.clone())
        .await
        .expect_err("replacement wins first: stale origin must be zero-write");
    assert_eq!(stale_error.code, RELAY_AUTH_INVALID_GRANT);
    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "revocations",
            fixture.realms[0].machine_route,
        ),
        0
    );
    assert!(
        fixture
            .auth
            .is_current(&device.access)
            .expect("device current")
    );

    fixture
        .core
        .handle(&current_machine.access, command)
        .await
        .expect("current replacement can commit revocation");
    assert!(matches!(
        recv_frame(&mut current_machine).await.body,
        RelayFrameBody::RevocationCommitted(_)
    ));
    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "revocations",
            fixture.realms[0].machine_route,
        ),
        1
    );

    let successor = fixture.connect_machine(0).await;
    assert_writer_closed(&current_machine.writer, WriterCloseReason::Replaced).await;
    assert!(
        fixture
            .auth
            .is_current(&successor.access)
            .expect("successor current")
    );
    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "revocations",
            fixture.realms[0].machine_route,
        ),
        1,
        "revoke wins first: later machine replacement cannot undo the tombstone"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn revoke_after_commit_loss_recovers_once_and_replays_the_identical_terminal_after_restart() {
    let mut fixture = Fixture::with_fault(Some(FaultPoint::RevokeAfterCommit)).await;
    let mut machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let revocation = fixture.realms[0].signed_revocation(fixture.server(), 0);
    let command = outer(RelayFrameBody::RevokeDevice(RevokeDevice {
        revocation: revocation.clone(),
    }));
    let expected = outer(RelayFrameBody::RevocationCommitted(RevocationCommitted {
        device_route: revocation.device_route,
        grant_serial: revocation.grant_serial,
        signed_revocation: revocation,
    }));

    fixture.fault.arm();
    fixture
        .core
        .handle(&machine.access, command.clone())
        .await
        .expect("after-COMMIT result loss must recover through exact revoke retry");

    let origin_delivery = recv_delivery(&mut machine.receiver).await;
    let frozen_terminal = origin_delivery.encoded().to_vec();
    assert_eq!(
        decode(origin_delivery.encoded()).expect("origin revocation terminal"),
        expected
    );
    origin_delivery.mark_flushed();
    let target_delivery = recv_delivery(&mut device.receiver).await;
    assert_eq!(
        target_delivery.encoded(),
        frozen_terminal,
        "origin and revoked target must receive byte-identical committed terminal bytes"
    );
    assert_eq!(
        fixture.fault.matching_checks(),
        1,
        "exact retry must read the committed revocation instead of mutating twice"
    );
    assert!(
        !fixture
            .auth
            .is_current(&device.access)
            .expect("revoked access state"),
        "unknown COMMIT recovery must never restore the revoked access"
    );
    let stale_error = fixture
        .core
        .handle(
            &device.access,
            outer(RelayFrameBody::Pong(Pong { nonce: 0xbeef })),
        )
        .await
        .expect_err("revoked access cannot route after recovered COMMIT");
    assert_eq!(stale_error.code, RELAY_AUTH_INVALID_GRANT);
    target_delivery.mark_flushed();
    assert_writer_closed(&device.writer, WriterCloseReason::Revoked).await;

    {
        let db = open_readonly_db(&fixture.path);
        let machine_route = fixture.realms[0].machine_route;
        assert_eq!(scoped_count(&db, "revocations", machine_route), 1);
        let stored_terminal: Vec<u8> = db
            .query_row(
                "SELECT signed_revocation_blob FROM revocations
                 WHERE machine_route = ?1 AND device_route = ?2",
                params![
                    machine_route.as_bytes().as_slice(),
                    fixture.realms[0].devices[0].route.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .expect("read committed revocation terminal");
        assert_eq!(stored_terminal, frozen_terminal);
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM device_grants
                 WHERE machine_route = ?1 AND device_route = ?2
                   AND tombstone = 1 AND revoked_at IS NOT NULL",
                params![
                    machine_route.as_bytes().as_slice(),
                    fixture.realms[0].devices[0].route.as_bytes().as_slice()
                ],
                |row| row.get::<_, u64>(0),
            )
            .expect("read revoked grant tombstone"),
            1
        );
        assert_foreign_keys_clean(&db);
    }

    fixture
        .core
        .handle(&machine.access, command)
        .await
        .expect("explicit exact revoke retry is idempotent");
    let retry_delivery = recv_delivery(&mut machine.receiver).await;
    assert_eq!(retry_delivery.encoded(), frozen_terminal);
    retry_delivery.mark_flushed();
    assert_eq!(fixture.fault.matching_checks(), 1);
    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "revocations",
            fixture.realms[0].machine_route,
        ),
        1
    );

    fixture = fixture.restart().await;
    let mut reauth = fixture.pending_outcome(0, Some(0)).await;
    assert!(matches!(
        reauth.outcome,
        AuthenticationOutcome::RevokedTerminal(_)
    ));
    fixture
        .core
        .activate_authentication(reauth.outcome)
        .await
        .expect("restart routes only the persisted revocation terminal");
    let replay = recv_delivery(&mut reauth.receiver).await;
    assert_eq!(replay.encoded(), frozen_terminal);
    assert!(
        fixture
            .auth
            .current(agentdeck_relay::v2::auth::PrincipalRoute::Device {
                machine_route: fixture.realms[0].machine_route,
                device_route: fixture.realms[0].devices[0].route,
            })
            .expect("active registry after restart")
            .is_none(),
        "restart terminal replay must not reactivate the revoked device"
    );
    replay.mark_flushed();
    assert_writer_closed(&reauth.writer, WriterCloseReason::Revoked).await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn revoke_commit_replaces_full_normal_and_control_queues_with_one_terminal_then_flush_closes()
{
    let mut fixture = Fixture::new().await;
    let mut machine = fixture.connect_machine(0).await;
    let other_machine = fixture.connect_machine(1).await;
    let tiny = OutboundWriterConfig {
        normal: WriterBudget::new(1, 4096),
        control: WriterBudget::new(1, 4096),
    };
    let mut device = fixture.connect_device_with_writer(0, 0, tiny).await;
    let revocation = fixture.realms[0].signed_revocation(fixture.server(), 0);

    let role_error = fixture
        .core
        .handle(
            &device.access,
            outer(RelayFrameBody::RevokeDevice(RevokeDevice {
                revocation: revocation.clone(),
            })),
        )
        .await
        .expect_err("DeviceAccess cannot revoke itself at the Relay control layer");
    assert_eq!(role_error.code, RELAY_ROUTE_FORBIDDEN);
    let cross_error = fixture
        .core
        .handle(
            &other_machine.access,
            outer(RelayFrameBody::RevokeDevice(RevokeDevice {
                revocation: revocation.clone(),
            })),
        )
        .await
        .expect_err("a different machine cannot revoke this device");
    assert_eq!(cross_error.code, RELAY_ROUTE_FORBIDDEN);
    let mut forged = revocation.clone();
    forged.signature.0[0] ^= 0x80;
    let forged_error = fixture
        .core
        .handle(
            &machine.access,
            outer(RelayFrameBody::RevokeDevice(RevokeDevice {
                revocation: forged,
            })),
        )
        .await
        .expect_err("forged revocation signature is rejected before COMMIT");
    assert_eq!(forged_error.code, RELAY_AUTH_INVALID_GRANT);
    assert_eq!(
        scoped_count(
            &open_readonly_db(&fixture.path),
            "revocations",
            fixture.realms[0].machine_route,
        ),
        0
    );

    device
        .writer
        .try_enqueue_data(outer(RelayFrameBody::Pong(Pong { nonce: 1 })))
        .expect("fill normal budget");
    device
        .writer
        .try_enqueue_control(outer(RelayFrameBody::Pong(Pong { nonce: 2 })))
        .expect("fill control budget");

    let expected = outer(RelayFrameBody::RevocationCommitted(RevocationCommitted {
        device_route: revocation.device_route,
        grant_serial: revocation.grant_serial,
        signed_revocation: revocation.clone(),
    }));
    fixture
        .core
        .handle(
            &machine.access,
            outer(RelayFrameBody::RevokeDevice(RevokeDevice { revocation })),
        )
        .await
        .expect("revoke commits despite target normal/control saturation");

    assert_eq!(recv_frame(&mut machine).await, expected);
    let terminal = recv_delivery(&mut device.receiver).await;
    assert_eq!(
        decode(terminal.encoded()).expect("terminal frame"),
        expected,
        "queued ordinary frames must be discarded before terminal"
    );
    assert!(
        !device.writer.is_closed(),
        "terminal connection stays open until socket flush or deadline"
    );
    terminal.mark_flushed();
    assert_writer_closed(&device.writer, WriterCloseReason::Revoked).await;

    let no_second = tokio::time::timeout(Duration::from_millis(100), device.receiver.recv())
        .await
        .expect("closed receiver returns immediately");
    assert!(no_second.is_none(), "terminal lane is exactly one frame");
    fixture.shutdown().await;
}

#[tokio::test]
async fn revoke_terminal_deadline_closes_and_sqlite_reopen_replays_identical_bytes_without_activation()
 {
    let mut fixture = Fixture::new().await;
    let mut machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let revocation = fixture.realms[0].signed_revocation(fixture.server(), 0);
    fixture
        .core
        .handle(
            &machine.access,
            outer(RelayFrameBody::RevokeDevice(RevokeDevice { revocation })),
        )
        .await
        .expect("commit revoke");
    let _ = recv_frame(&mut machine).await;
    let terminal = recv_delivery(&mut device.receiver).await;
    let frozen_bytes = terminal.encoded().to_vec();

    assert!(
        tokio::time::timeout(
            TERMINAL_DEADLINE - Duration::from_millis(250),
            device.writer.closed()
        )
        .await
        .is_err(),
        "deadline must not close early"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(750), device.writer.closed())
            .await
            .expect("terminal must force-close no later than two seconds"),
        WriterCloseReason::Revoked
    );
    drop(terminal);

    fixture = fixture.restart().await;
    fixture
        .assert_forged_device_cannot_observe_terminal(0, 0)
        .await;
    let mut reauth = fixture.pending_outcome(0, Some(0)).await;
    assert!(
        matches!(reauth.outcome, AuthenticationOutcome::RevokedTerminal(_)),
        "valid DeviceSign proof for a revoked grant returns terminal-only auth"
    );
    fixture
        .core
        .activate_authentication(reauth.outcome)
        .await
        .expect("attach frozen revocation terminal to pending writer");
    let replay = recv_delivery(&mut reauth.receiver).await;
    assert_eq!(
        replay.encoded(),
        frozen_bytes,
        "SQLite reopen must replay the exact committed terminal outer bytes"
    );
    assert!(
        fixture
            .auth
            .current(agentdeck_relay::v2::auth::PrincipalRoute::Device {
                machine_route: fixture.realms[0].machine_route,
                device_route: fixture.realms[0].devices[0].route,
            })
            .expect("active registry")
            .is_none(),
        "terminal authentication cannot activate a device generation"
    );
    replay.mark_flushed();
    assert_writer_closed(&reauth.writer, WriterCloseReason::Revoked).await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn retire_commit_fault_preserves_machine_grants_retained_data_and_pair_route() {
    let mut fixture = Fixture::with_fault(Some(FaultPoint::PurgeBeforeCommit)).await;
    let (target_stream, target_generation) = seed_retained_data(&fixture, 0, 0x31).await;
    let mut machine = fixture.connect_machine(0).await;
    let route = pair_route(0x31);
    fixture
        .core
        .handle(
            &machine.access,
            outer(RelayFrameBody::OpenPairRoute(OpenPairRoute {
                machine_route: fixture.realms[0].machine_route,
                pair_route: route,
                absolute_expiry_ms: NOW_MS + 60_000,
            })),
        )
        .await
        .expect("open route before retirement");
    assert!(matches!(
        recv_frame(&mut machine).await.body,
        RelayFrameBody::PairRouteOpened(PairRouteOpened { pair_route, .. }) if pair_route == route
    ));
    let retirement = fixture.realms[0].signed_retirement(fixture.server());

    fixture.fault.arm();
    let failed = fixture
        .core
        .handle(
            &machine.access,
            outer(RelayFrameBody::RetireMachine(retirement)),
        )
        .await
        .expect_err("purge pre-COMMIT fault must restore all state");
    assert_eq!(failed.code, RELAY_STORE_UNAVAILABLE);
    assert!(
        fixture
            .auth
            .is_current(&machine.access)
            .expect("auth state")
    );
    assert!(
        fixture
            .core
            .pair_route_view(route)
            .await
            .expect("pair route view")
            .active_route
            .is_some(),
        "PairRoute is removed only after purge COMMIT"
    );
    let db = open_readonly_db(&fixture.path);
    let machine_route = fixture.realms[0].machine_route;
    assert_eq!(scoped_count(&db, "device_grants", machine_route), 1);
    assert_eq!(scoped_count(&db, "streams", machine_route), 1);
    assert_eq!(stream_frame_count(&db, target_stream, target_generation), 1);
    assert_eq!(global_frame_count(&db), 1);
    assert_foreign_keys_clean(&db);
    assert_eq!(scoped_count(&db, "subscriptions", machine_route), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn purge_after_commit_loss_never_restores_machine_or_pair_route_and_replays_terminal() {
    let mut fixture = Fixture::with_fault(Some(FaultPoint::PurgeAfterCommit)).await;
    let (target_stream, target_generation) = seed_retained_data(&fixture, 0, 0x35).await;
    let (other_stream, other_generation) = seed_retained_data(&fixture, 1, 0x75).await;
    let mut machine = fixture.connect_machine(0).await;
    let device = fixture.connect_device(0, 0).await;
    let route = pair_route(0x35);
    fixture
        .core
        .handle(
            &machine.access,
            outer(RelayFrameBody::OpenPairRoute(OpenPairRoute {
                machine_route: fixture.realms[0].machine_route,
                pair_route: route,
                absolute_expiry_ms: NOW_MS + 60_000,
            })),
        )
        .await
        .expect("open PairRoute before after-COMMIT retirement");
    let _ = recv_frame(&mut machine).await;

    let retirement = fixture.realms[0].signed_retirement(fixture.server());
    let retire_hash = retirement.canonical_sha256();
    let command = outer(RelayFrameBody::RetireMachine(retirement.clone()));
    let expected = outer(RelayFrameBody::RetirementCommitted(RetirementCommitted {
        machine_route: retirement.machine_route,
        trust_epoch: retirement.trust_epoch,
        retire_hash,
    }));
    fixture.fault.arm();
    fixture
        .core
        .handle(&machine.access, command)
        .await
        .expect("after-COMMIT purge result loss must recover through exact retry");
    let terminal = recv_delivery(&mut machine.receiver).await;
    let frozen_terminal = terminal.encoded().to_vec();
    assert_eq!(
        decode(terminal.encoded()).expect("retirement terminal"),
        expected
    );
    assert_eq!(
        fixture.fault.matching_checks(),
        2,
        "exact retry reads the retired tombstone and crosses the same response-loss boundary once more"
    );
    assert!(
        !fixture
            .auth
            .is_current(&machine.access)
            .expect("retired machine auth state")
    );
    assert!(
        !fixture
            .auth
            .is_current(&device.access)
            .expect("retired device auth state")
    );
    assert!(
        fixture
            .core
            .pair_route_view(route)
            .await
            .expect("PairRoute after recovered purge")
            .active_route
            .is_none(),
        "PairRoute must stay removed after an unknown COMMIT recovery"
    );
    let stale_error = fixture
        .core
        .handle(
            &machine.access,
            outer(RelayFrameBody::Pong(Pong { nonce: 0xcafe })),
        )
        .await
        .expect_err("retired machine access cannot return after recovered purge");
    assert_eq!(stale_error.code, RELAY_AUTH_INVALID_GRANT);
    terminal.mark_flushed();
    assert_writer_closed(&machine.writer, WriterCloseReason::Retired).await;
    assert_writer_closed(&device.writer, WriterCloseReason::Retired).await;

    {
        let db = open_readonly_db(&fixture.path);
        let target = fixture.realms[0].machine_route;
        let other = fixture.realms[1].machine_route;
        assert_eq!(scoped_count(&db, "device_grants", target), 0);
        assert_eq!(scoped_count(&db, "streams", target), 0);
        assert_eq!(
            stream_frame_count(&db, target_stream, target_generation),
            0,
            "after-COMMIT recovery must not hide an orphaned target frame"
        );
        assert_eq!(scoped_count(&db, "subscriptions", target), 0);
        assert_eq!(scoped_count(&db, "device_grants", other), 1);
        assert_eq!(scoped_count(&db, "streams", other), 1);
        assert_eq!(stream_frame_count(&db, other_stream, other_generation), 1);
        assert_eq!(global_frame_count(&db), 1);
        assert_foreign_keys_clean(&db);

        let tombstone: (u64, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT COUNT(*), retirement_hash, retirement_terminal_blob
                 FROM machine_routes
                 WHERE machine_route = ?1 AND status = 'retired'",
                params![target.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read recovered retirement tombstone");
        assert_eq!(tombstone.0, 1, "retirement creates one tombstone exactly");
        assert_eq!(tombstone.1, retire_hash);
        assert_eq!(tombstone.2, frozen_terminal);
    }

    fixture = fixture.restart().await;
    assert!(
        fixture
            .core
            .pair_route_view(route)
            .await
            .expect("PairRoute after restart")
            .active_route
            .is_none(),
        "retired PairRoute cannot reappear after restart"
    );
    let mut reauth = fixture.pending_outcome(0, None).await;
    assert!(matches!(
        reauth.outcome,
        AuthenticationOutcome::RetiredTerminal(_)
    ));
    fixture
        .core
        .activate_authentication(reauth.outcome)
        .await
        .expect("restart routes only the persisted retirement terminal");
    let replay = recv_delivery(&mut reauth.receiver).await;
    assert_eq!(replay.encoded(), frozen_terminal);
    assert!(
        fixture
            .auth
            .current(agentdeck_relay::v2::auth::PrincipalRoute::Machine(
                fixture.realms[0].machine_route,
            ))
            .expect("active registry after restart")
            .is_none(),
        "restart terminal replay must not reactivate the retired machine"
    );
    replay.mark_flushed();
    assert_writer_closed(&reauth.writer, WriterCloseReason::Retired).await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn retire_machine_purges_only_target_and_reauth_replays_terminal_without_reactivation() {
    let mut fixture = Fixture::new().await;
    let (target_stream, target_generation) = seed_retained_data(&fixture, 0, 0x41).await;
    let (other_stream, other_generation) = seed_retained_data(&fixture, 1, 0x71).await;
    let mut retiring_machine = fixture.connect_machine(0).await;
    let retiring_device = fixture.connect_device(0, 0).await;
    let other_machine = fixture.connect_machine(1).await;
    let mut other_device = fixture.connect_device(1, 0).await;
    let route = pair_route(0x41);
    fixture
        .core
        .handle(
            &retiring_machine.access,
            outer(RelayFrameBody::OpenPairRoute(OpenPairRoute {
                machine_route: fixture.realms[0].machine_route,
                pair_route: route,
                absolute_expiry_ms: NOW_MS + 60_000,
            })),
        )
        .await
        .expect("open route before retirement");
    let _ = recv_frame(&mut retiring_machine).await;
    let pairing = fixture.connect_pairing(route).await;

    let retirement = fixture.realms[0].signed_retirement(fixture.server());
    let role_error = fixture
        .core
        .handle(
            &retiring_device.access,
            outer(RelayFrameBody::RetireMachine(retirement.clone())),
        )
        .await
        .expect_err("DeviceAccess cannot retire a machine");
    assert_eq!(role_error.code, RELAY_ROUTE_FORBIDDEN);
    let cross_error = fixture
        .core
        .handle(
            &other_machine.access,
            outer(RelayFrameBody::RetireMachine(retirement.clone())),
        )
        .await
        .expect_err("a different machine cannot submit this retirement");
    assert_eq!(cross_error.code, RELAY_ROUTE_FORBIDDEN);
    let mut forged = retirement.clone();
    forged.signature.0[0] ^= 0x80;
    let forged_error = fixture
        .core
        .handle(
            &retiring_machine.access,
            outer(RelayFrameBody::RetireMachine(forged)),
        )
        .await
        .expect_err("forged retirement signature is zero-write");
    assert_eq!(forged_error.code, RELAY_AUTH_INVALID_GRANT);
    let mut wrong_epoch = retirement.clone();
    wrong_epoch.trust_epoch = TrustEpoch::new(retirement.trust_epoch.value() + 1);
    wrong_epoch.signature = sign_tbs(
        &fixture.realms[0].root,
        &wrong_epoch.to_be_signed_v1(
            fixture.server(),
            sha256(&fixture.realms[0].root.verifying_key().to_bytes()),
        ),
    )
    .into();
    let epoch_error = fixture
        .core
        .handle(
            &retiring_machine.access,
            outer(RelayFrameBody::RetireMachine(wrong_epoch)),
        )
        .await
        .expect_err("valid signature over wrong trust epoch cannot purge");
    assert_eq!(epoch_error.code, RELAY_AUTH_INVALID_GRANT);
    assert_eq!(
        open_readonly_db(&fixture.path)
            .query_row(
                "SELECT COUNT(*) FROM machine_routes
                 WHERE machine_route = ?1 AND status = 'active'",
                params![fixture.realms[0].machine_route.as_bytes().as_slice()],
                |row| row.get::<_, u64>(0),
            )
            .expect("target remains active after rejected retirement frames"),
        1
    );

    let retire_hash = retirement.canonical_sha256();
    let expected = outer(RelayFrameBody::RetirementCommitted(RetirementCommitted {
        machine_route: retirement.machine_route,
        trust_epoch: retirement.trust_epoch,
        retire_hash,
    }));
    fixture
        .core
        .handle(
            &retiring_machine.access,
            outer(RelayFrameBody::RetireMachine(retirement)),
        )
        .await
        .expect("root-signed retirement commits purge");
    let terminal = recv_delivery(&mut retiring_machine.receiver).await;
    let frozen_bytes = terminal.encoded().to_vec();
    assert_eq!(
        decode(terminal.encoded()).expect("retirement terminal"),
        expected
    );
    terminal.mark_flushed();
    assert_writer_closed(&retiring_machine.writer, WriterCloseReason::Retired).await;
    assert_writer_closed(&retiring_device.writer, WriterCloseReason::Retired).await;
    assert_writer_closed(&pairing.writer, WriterCloseReason::Retired).await;
    assert!(
        fixture
            .core
            .pair_route_view(route)
            .await
            .expect("pair route view")
            .active_route
            .is_none(),
        "retirement COMMIT removes all in-memory PairRoutes for that machine"
    );

    fixture
        .core
        .tick(NOW_MS + 20_000)
        .await
        .expect("non-target machine remains routed");
    assert!(matches!(
        recv_frame(&mut other_device).await.body,
        RelayFrameBody::Ping(_)
    ));

    {
        let db = open_readonly_db(&fixture.path);
        let target = fixture.realms[0].machine_route;
        let other = fixture.realms[1].machine_route;
        assert_eq!(scoped_count(&db, "device_grants", target), 0);
        assert_eq!(scoped_count(&db, "revocations", target), 0);
        assert_eq!(scoped_count(&db, "streams", target), 0);
        assert_eq!(
            stream_frame_count(&db, target_stream, target_generation),
            0,
            "目标 stream key 上的 frame 必须真实删除，不能通过 JOIN 已删除 streams 假阳性"
        );
        assert_eq!(scoped_count(&db, "subscriptions", target), 0);
        assert_eq!(scoped_count(&db, "device_grants", other), 1);
        assert_eq!(scoped_count(&db, "streams", other), 1);
        assert_eq!(stream_frame_count(&db, other_stream, other_generation), 1);
        assert_eq!(global_frame_count(&db), 1);
        assert_foreign_keys_clean(&db);
        assert_eq!(scoped_count(&db, "subscriptions", other), 1);

        let tombstone: (u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT COUNT(*), retirement_hash, retirement_terminal_blob,
                        root_pubkey, link_cert_hash
                 FROM machine_routes
                 WHERE machine_route = ?1 AND status = 'retired'",
                params![target.as_bytes().as_slice()],
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
            .expect("read retired tombstone");
        assert_eq!(tombstone.0, 1);
        assert_eq!(tombstone.1, retire_hash);
        assert_eq!(tombstone.2, frozen_bytes);
        assert_eq!(
            tombstone.3,
            fixture.realms[0].root.verifying_key().to_bytes(),
            "root proof material is retained exactly"
        );
        assert_eq!(
            tombstone.4,
            fixture.realms[0].link_cert.canonical_sha256(),
            "MachineLink proof hash is retained exactly"
        );
    }

    fixture = fixture.restart().await;
    let mut reauth = fixture.pending_outcome(0, None).await;
    assert!(
        matches!(reauth.outcome, AuthenticationOutcome::RetiredTerminal(_)),
        "valid old MachineLink proof reads the frozen retirement terminal"
    );
    fixture
        .core
        .activate_authentication(reauth.outcome)
        .await
        .expect("route retirement terminal to pending writer only");
    let replay = recv_delivery(&mut reauth.receiver).await;
    assert_eq!(replay.encoded(), frozen_bytes);
    assert!(
        fixture
            .auth
            .current(agentdeck_relay::v2::auth::PrincipalRoute::Machine(
                fixture.realms[0].machine_route,
            ))
            .expect("active registry")
            .is_none(),
        "retired terminal proof must never reactivate the machine"
    );
    replay.mark_flushed();
    assert_writer_closed(&reauth.writer, WriterCloseReason::Retired).await;
    fixture.shutdown().await;
}
