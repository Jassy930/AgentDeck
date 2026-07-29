//! Relay v2 PairRoute 与在线 Send/Reply 端到端契约。
//!
//! machine/device principal 全部经过真实 challenge-response 与 SQLite trust state；
//! pairing connection 则严格走 `PairingHello -> route view -> authorize -> activate`。
//! 本文件不构造伪造的 MachineAccess/DeviceAccess，也不绕过 Core actor。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agentdeck_crypto::{
    SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256, sign_authentication_transcript,
    sign_relay_admin_purge_receipt, sign_tbs,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, CertRole,
};
use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_INVALID_GRANT, RELAY_QUOTA_EXCEEDED, RELAY_ROUTE_CONFLICT, RELAY_ROUTE_FORBIDDEN,
    RELAY_ROUTE_NOT_FOUND,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, AuthProof, Authenticate, ClosePairRoute, OpenPairRoute, PairData,
    PairRouteCloseOutcome, PairRouteOpened, Pong, Publish, RegisterStream, Reply, RouteAccepted,
    SealedBlob, Send, Subscribe,
};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, DeviceRouteId, Ed25519Signature, GrantSerial, LinkGeneration,
    MachineRouteId, OpaqueRouteFrame, PairRouteId, PublicKeyBytes, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RelayGrant, RelayServerId, RequestRouteId, RootKeyId, SignedCertificate,
    StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};
use agentdeck_relay::v2::auth::{
    AccessContext, AuthorizationCoordinator, ChallengeLimits, ChallengeRegistry, ChallengeRoute,
    ChallengeSource, MonotonicClock, PairingHello, authorize_pairing_route,
};
use agentdeck_relay::v2::core::writer::{
    OutboundReceiver, OutboundWriter, OutboundWriterConfig, WriterBudget, WriterCloseReason,
};
use agentdeck_relay::v2::core::{CoreConfig, RelayCore, RouteOutcome};
use agentdeck_relay::v2::store::{
    AdminPurgeCommitRequest, AdminPurgePreparation, Clock, DiskSpace, DiskSpaceProbe,
    EnrollmentCodeSeed, FaultInjector, FaultPoint, InstallGrantRecord, MachineInventoryQuery,
    MachineReadbackQuery, NoFaults, PurgeMachine, RegisterMachine, RelayStoreHandle,
    RelayV2StoreConfig, RetentionLimits, StoreError,
};
use rusqlite::{Connection, OpenFlags};
use tempfile::TempDir;

const NOW_MS: u64 = 1_726_000_000_000;
const PAIR_TTL_MS: u64 = 300_000;

fn test_store_config(path: PathBuf) -> RelayV2StoreConfig {
    let identity =
        ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&test_receipt_signing_key())
            .expect("valid test receipt signer");
    RelayV2StoreConfig::new(path, identity)
}

fn test_receipt_signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x71; 32])
}

async fn signed_admin_purge(
    store: &RelayStoreHandle,
    purge: PurgeMachine,
) -> AdminPurgeCommitRequest {
    let receipt = match store
        .prepare_admin_purge(purge.clone())
        .await
        .expect("prepare authoritative purge receipt")
    {
        AdminPurgePreparation::Sign { tbs } => {
            let signing_key = test_receipt_signing_key();
            let verify_key = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signing_key)
                .expect("test receipt identity")
                .bind_to_relay(tbs.relay_server_id)
                .expect("test receipt verify key");
            sign_relay_admin_purge_receipt(&signing_key, &verify_key, tbs)
                .expect("sign authoritative purge receipt")
        }
        AdminPurgePreparation::Committed { receipt } => receipt,
    };
    AdminPurgeCommitRequest { purge, receipt }
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

fn pair_route(value: u16) -> PairRouteId {
    let mut bytes = [0_u8; 16];
    bytes[..2].copy_from_slice(&value.to_be_bytes());
    bytes[2..].fill((value & 0xff) as u8);
    PairRouteId::from_bytes(bytes)
}

fn request_route(value: u8) -> RequestRouteId {
    RequestRouteId::from_bytes([value; 16])
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

fn open_pair_frame(
    machine_route: MachineRouteId,
    route: PairRouteId,
    absolute_expiry_ms: u64,
) -> OpaqueRouteFrame {
    outer(RelayFrameBody::OpenPairRoute(OpenPairRoute {
        machine_route,
        pair_route: route,
        absolute_expiry_ms,
    }))
}

fn close_pair_frame(machine_route: MachineRouteId, route: PairRouteId) -> OpaqueRouteFrame {
    outer(RelayFrameBody::ClosePairRoute(ClosePairRoute {
        machine_route,
        pair_route: route,
    }))
}

fn pair_data_frame(route: PairRouteId, bytes: Vec<u8>) -> OpaqueRouteFrame {
    outer(RelayFrameBody::PairData(PairData {
        pair_route: route,
        sealed_blob: SealedBlob(bytes),
    }))
}

fn send_frame(
    device_route: DeviceRouteId,
    route: RequestRouteId,
    bytes: Vec<u8>,
) -> OpaqueRouteFrame {
    outer(RelayFrameBody::Send(Send {
        device_route,
        request_route: route,
        sealed_blob: SealedBlob(bytes),
    }))
}

fn reply_frame(
    device_route: DeviceRouteId,
    route: RequestRouteId,
    bytes: Vec<u8>,
) -> OpaqueRouteFrame {
    outer(RelayFrameBody::Reply(Reply {
        device_route,
        request_route: route,
        sealed_blob: SealedBlob(bytes),
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
    role: CertRole,
) -> SignedCertificate {
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
        cert_role: role,
        generation: LinkGeneration::new(1),
        root_key_id,
        trust_epoch,
        // 路由测试会推进完整 5 分钟 PairRoute TTL 后重新认证；证书生命周期必须独立
        // 覆盖该窗口，不能用固定旧认证时钟掩盖已过期证书。
        not_after_ms: Some(NOW_MS + PAIR_TTL_MS * 3),
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
) -> RelayGrant {
    let mut grant = RelayGrant {
        machine_route,
        device_route,
        device_sign_pubkey: PublicKeyBytes(device_key.verifying_key().to_bytes()),
        grant_serial: GrantSerial::new(1),
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
    root_fingerprint: [u8; 32],
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
            CertRole::Link,
        );
        let data_cert = signed_certificate(
            &root,
            &data,
            server,
            machine_route,
            root_key_id,
            trust_epoch,
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
            machine_route,
            root_fingerprint: sha256(&root.verifying_key().to_bytes()),
            link,
            link_cert,
            devices,
        }
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

#[derive(Debug)]
struct PersistentPurgeAfterCommitFailure;

impl FaultInjector for PersistentPurgeAfterCommitFailure {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == FaultPoint::PurgeAfterCommit {
            Err(StoreError::InjectedFault(point))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn admin_purge_is_fenced_by_core_and_detaches_only_the_confirmed_machine_realm() {
    let mut fixture = Fixture::new().await;
    let machine_route = fixture.realms[0].machine_route;
    let root_fingerprint = fixture.realms[0].root_fingerprint;
    let route = pair_route(0x707);
    let mut machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let other_machine = fixture.connect_machine(1).await;

    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open pair route before purge"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let mut pairing = fixture
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;

    let mut wrong_request = signed_admin_purge(
        &fixture.store,
        PurgeMachine {
            machine_route,
            expected_root_fingerprint: root_fingerprint,
        },
    )
    .await;
    wrong_request.purge.expected_root_fingerprint = [0xff; 32];
    let wrong = fixture
        .core
        .purge_machine_admin(wrong_request)
        .await
        .expect_err("wrong fingerprint cannot purge");
    assert!(matches!(wrong, StoreError::RootFingerprintMismatch));
    assert!(!machine.writer.is_closed());
    assert!(!device.writer.is_closed());
    assert!(!pairing.writer.is_closed());
    assert!(!other_machine.writer.is_closed());
    assert!(
        fixture
            .core
            .pair_route_view(route)
            .await
            .expect("pair route remains after rejected purge")
            .active_route
            .is_some()
    );

    let request = signed_admin_purge(
        &fixture.store,
        PurgeMachine {
            machine_route,
            expected_root_fingerprint: root_fingerprint,
        },
    )
    .await;
    let commit = fixture
        .core
        .purge_machine_admin(request.clone())
        .await
        .expect("confirmed purge");
    assert_eq!(commit.receipt, request.receipt);
    assert!(!commit.duplicate);
    let readback = commit.readback;
    assert_eq!(readback.active_machine_routes, 0);
    assert_eq!(readback.retired_tombstones, 1);
    assert_eq!(readback.device_grants, 0);
    assert_eq!(readback.revocations, 0);
    assert_eq!(readback.streams, 0);
    assert_eq!(readback.frames, 0);
    assert_eq!(readback.subscriptions, 0);
    assert_eq!(readback.retirement_hash, None);
    assert_eq!(readback.retirement_terminal_blob, None);
    assert_eq!(
        machine.writer.close_reason(),
        Some(WriterCloseReason::Retired)
    );
    assert_eq!(
        device.writer.close_reason(),
        Some(WriterCloseReason::Retired)
    );
    assert_eq!(
        pairing.writer.close_reason(),
        Some(WriterCloseReason::Retired)
    );
    assert!(!other_machine.writer.is_closed());
    assert_receiver_closed(&mut machine).await;
    assert_receiver_closed(&mut device).await;
    assert_receiver_closed(&mut pairing).await;
    assert!(
        fixture
            .core
            .pair_route_view(route)
            .await
            .expect("pair route view after purge")
            .active_route
            .is_none()
    );
    let inventory = fixture
        .store
        .machine_inventory(MachineInventoryQuery {
            after: None,
            limit: 128,
        })
        .await
        .expect("inventory after purge");
    let retired = inventory
        .entries
        .iter()
        .find(|entry| entry.machine_route == machine_route)
        .expect("minimal retired tombstone remains visible to local admin");
    assert!(retired.retired);
    assert_eq!(retired.root_fingerprint, root_fingerprint);
    let store_readback = fixture
        .store
        .machine_readback(MachineReadbackQuery {
            machine_route,
            expected_root_fingerprint: root_fingerprint,
        })
        .await
        .expect("local admin readback after purge");
    assert_eq!(&store_readback.machine, retired);
    assert_eq!(store_readback.data, readback);

    fixture.shutdown().await;
}

#[tokio::test]
async fn uncertain_admin_purge_never_restores_old_generations_and_fails_the_whole_core_closed() {
    let mut fixture =
        Fixture::new_with_fault_injector(Arc::new(PersistentPurgeAfterCommitFailure)).await;
    let machine_route = fixture.realms[0].machine_route;
    let root_fingerprint = fixture.realms[0].root_fingerprint;
    let route = pair_route(0x708);
    let mut machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let mut other_machine = fixture.connect_machine(1).await;
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open pair route before uncertain purge"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let mut pairing = fixture
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;

    let request = signed_admin_purge(
        &fixture.store,
        PurgeMachine {
            machine_route,
            expected_root_fingerprint: root_fingerprint,
        },
    )
    .await;
    let error = fixture
        .core
        .purge_machine_admin(request)
        .await
        .expect_err("both exact recovery attempts report outcome unknown");
    assert!(matches!(error, StoreError::CommitOutcomeUnknown { .. }));

    assert_receiver_closed(&mut machine).await;
    assert_receiver_closed(&mut device).await;
    assert_receiver_closed(&mut pairing).await;
    assert_receiver_closed(&mut other_machine).await;
    for writer in [
        &machine.writer,
        &device.writer,
        &pairing.writer,
        &other_machine.writer,
    ] {
        assert_eq!(
            writer.close_reason(),
            Some(WriterCloseReason::AuthorizationInvalidated)
        );
    }
    assert!(
        fixture.core.pair_route_view(route).await.is_err(),
        "poisoned Core and its in-memory PairRoute registry must stop"
    );
    let committed = fixture
        .store
        .machine_readback(MachineReadbackQuery {
            machine_route,
            expected_root_fingerprint: root_fingerprint,
        })
        .await
        .expect("durable purge readback despite lost replies");
    assert_eq!(committed.data.active_machine_routes, 0);
    assert_eq!(committed.data.retired_tombstones, 1);
    assert_eq!(committed.data.device_grants, 0);
    assert_eq!(committed.data.frames, 0);

    fixture
        .store
        .shutdown()
        .await
        .expect("shutdown Store after fail-closed Core");
}

struct TestConnection {
    access: AccessContext,
    writer: OutboundWriter,
    receiver: OutboundReceiver,
}

struct PendingPairingConnection {
    access: AccessContext,
    writer: OutboundWriter,
    receiver: OutboundReceiver,
}

struct Fixture {
    _temp: TempDir,
    db_path: PathBuf,
    store: RelayStoreHandle,
    registry: ChallengeRegistry,
    auth: AuthorizationCoordinator,
    core: RelayCore,
    realms: Vec<RealmFixture>,
    next_connection: u128,
}

impl Fixture {
    async fn new() -> Self {
        Self::new_with_fault_injector(Arc::new(NoFaults)).await
    }

    async fn new_with_fault_injector(fault_injector: Arc<dyn FaultInjector>) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = store_path(&temp);
        let retention = RetentionLimits {
            disk_reserve_bytes: 0,
            disk_reserve_percent: 0,
            ..RetentionLimits::default()
        };
        let config = test_store_config(db_path.clone())
            .with_clock(Arc::new(FixedStoreClock))
            .with_disk_space_probe(Arc::new(PlentyOfDisk))
            .with_fault_injector(fault_injector)
            .with_retention(retention);
        let store = RelayStoreHandle::open(config).await.expect("open v2 store");
        let server = store.relay_server_id();
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
        let core = RelayCore::start(
            store.clone(),
            auth.clone(),
            lifecycle,
            CoreConfig {
                initial_now_ms: NOW_MS,
                ..CoreConfig::default()
            },
        )
        .expect("start relay core");
        Self {
            _temp: temp,
            db_path,
            store,
            registry,
            auth,
            core,
            realms: vec![realm_a, realm_b],
            next_connection: 1,
        }
    }

    async fn connect_machine(&mut self, realm: usize) -> TestConnection {
        self.connect_principal(realm, None, OutboundWriterConfig::default())
            .await
    }

    async fn connect_machine_at(&mut self, realm: usize, now_ms: u64) -> TestConnection {
        self.connect_principal_at(realm, None, OutboundWriterConfig::default(), now_ms)
            .await
    }

    async fn connect_machine_with_writer(
        &mut self,
        realm: usize,
        writer_config: OutboundWriterConfig,
    ) -> TestConnection {
        self.connect_principal(realm, None, writer_config).await
    }

    async fn connect_device(&mut self, realm: usize, device: usize) -> TestConnection {
        self.connect_principal(realm, Some(device), OutboundWriterConfig::default())
            .await
    }

    async fn connect_device_with_writer(
        &mut self,
        realm: usize,
        device: usize,
        writer_config: OutboundWriterConfig,
    ) -> TestConnection {
        self.connect_principal(realm, Some(device), writer_config)
            .await
    }

    async fn connect_principal(
        &mut self,
        realm: usize,
        device: Option<usize>,
        writer_config: OutboundWriterConfig,
    ) -> TestConnection {
        self.connect_principal_at(realm, device, writer_config, NOW_MS)
            .await
    }

    async fn connect_principal_at(
        &mut self,
        realm: usize,
        device: Option<usize>,
        writer_config: OutboundWriterConfig,
        now_ms: u64,
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
            .authenticate(frame, consumed, now_ms)
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

    async fn prepare_pairing(
        &mut self,
        route: PairRouteId,
        writer_config: OutboundWriterConfig,
    ) -> PendingPairingConnection {
        let connection_number = self.next_connection;
        self.next_connection += 1;
        let connection_id = connection(connection_number);
        let (writer, receiver) = OutboundWriter::new(writer_config);
        self.core
            .attach_pending(connection_id, writer.clone())
            .await
            .expect("attach pending pairing writer");
        let view = self
            .core
            .pair_route_view(route)
            .await
            .expect("read pair route view");
        let pairing = authorize_pairing_route(
            PairingHello {
                protocol_version: RELAY_PROTOCOL_VERSION,
                relay_server_id: self.store.relay_server_id(),
                connection_instance: connection_id,
                pair_route: route,
            },
            &view,
        )
        .expect("authorize active pair route");
        PendingPairingConnection {
            access: AccessContext::Pairing(pairing),
            writer,
            receiver,
        }
    }

    async fn connect_pairing(
        &mut self,
        route: PairRouteId,
        writer_config: OutboundWriterConfig,
    ) -> TestConnection {
        let pending = self.prepare_pairing(route, writer_config).await;
        self.core
            .activate(pending.access.clone())
            .await
            .expect("activate pairing writer");
        TestConnection {
            access: pending.access,
            writer: pending.writer,
            receiver: pending.receiver,
        }
    }

    async fn restart_core(&mut self) {
        self.core.shutdown().await.expect("shutdown old core");
        let (auth, lifecycle) = AuthorizationCoordinator::start(self.store.clone(), 64)
            .expect("restart authorization coordinator");
        let core = RelayCore::start(
            self.store.clone(),
            auth.clone(),
            lifecycle,
            CoreConfig {
                initial_now_ms: NOW_MS,
                ..CoreConfig::default()
            },
        )
        .expect("restart relay core");
        self.auth = auth;
        self.core = core;
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

fn assert_queued_pair(outcome: RouteOutcome, expected: PairRouteId) {
    let RouteOutcome::Queued(RouteAccepted {
        accepted: AcceptedRef::PairFrame { pair_route },
    }) = outcome
    else {
        panic!("expected PairFrame RouteAccepted, got {outcome:?}");
    };
    assert_eq!(pair_route, expected);
}

fn assert_queued_request(outcome: RouteOutcome, expected: RequestRouteId) {
    let RouteOutcome::Queued(RouteAccepted {
        accepted: AcceptedRef::Request { request_route },
    }) = outcome
    else {
        panic!("expected Request RouteAccepted, got {outcome:?}");
    };
    assert_eq!(request_route, expected);
}

async fn assert_opened(
    connection: &mut TestConnection,
    machine: MachineRouteId,
    route: PairRouteId,
    expiry: u64,
) {
    assert_eq!(
        recv_frame(connection).await.body,
        RelayFrameBody::PairRouteOpened(PairRouteOpened {
            machine_route: machine,
            pair_route: route,
            absolute_expiry_ms: expiry,
        })
    );
}

async fn assert_closed_ack(
    connection: &mut TestConnection,
    route: PairRouteId,
    expected: PairRouteCloseOutcome,
) {
    let frame = recv_frame(connection).await;
    let RelayFrameBody::PairRouteClosed(closed) = frame.body else {
        panic!("expected PairRouteClosed, got {frame:?}");
    };
    assert_eq!(closed.pair_route, route);
    assert_eq!(closed.outcome, expected);
}

fn open_readonly_db(path: &Path) -> Connection {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Relay SQLite read-only");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("set read-only busy timeout");
    conn
}

#[derive(Debug, PartialEq, Eq)]
struct SqliteRouteSnapshot {
    data_version: i64,
    table_counts: Vec<(&'static str, u64)>,
    stream_high_waters: Vec<String>,
    frame_count_and_bytes: (u64, u64),
}

fn sqlite_route_snapshot(conn: &Connection) -> SqliteRouteSnapshot {
    let table_counts = [
        "relay_meta",
        "machine_routes",
        "device_grants",
        "revocations",
        "streams",
        "frames",
        "subscriptions",
        "enrollment_codes",
    ]
    .into_iter()
    .map(|table| {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map(|count| (table, count))
        .expect("count Relay table")
    })
    .collect();
    let mut hwm_statement = conn
        .prepare("SELECT high_water_seq FROM streams ORDER BY stream_route, generation")
        .expect("prepare stream HWM snapshot");
    let stream_high_waters = hwm_statement
        .query_map([], |row| row.get(0))
        .expect("query stream HWM snapshot")
        .collect::<Result<Vec<String>, _>>()
        .expect("collect stream HWM snapshot");
    let frame_count_and_bytes = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM frames",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("snapshot frame count and bytes");
    SqliteRouteSnapshot {
        data_version: conn
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .expect("read SQLite data_version"),
        table_counts,
        stream_high_waters,
        frame_count_and_bytes,
    }
}

#[tokio::test]
async fn pair_route_open_close_idempotency_conflict_expiry_and_tombstone_are_exact() {
    let mut fixture = Fixture::new().await;
    let machine_route_a = fixture.realms[0].machine_route;
    let machine_route_b = fixture.realms[1].machine_route;
    let route = pair_route(1);
    let expiry = NOW_MS + PAIR_TTL_MS;
    let mut machine_a = fixture.connect_machine(0).await;
    let machine_b = fixture.connect_machine(1).await;
    let device_a = fixture.connect_device(0, 0).await;

    assert_applied(
        fixture
            .core
            .handle(
                &machine_a.access,
                close_pair_frame(machine_route_a, pair_route(999)),
            )
            .await
            .expect("closing an unknown route is idempotent"),
    );
    assert_closed_ack(
        &mut machine_a,
        pair_route(999),
        PairRouteCloseOutcome::AlreadyAbsent,
    )
    .await;

    let too_far = fixture
        .core
        .handle(
            &machine_a.access,
            open_pair_frame(machine_route_a, pair_route(998), expiry + 1),
        )
        .await
        .expect_err("pair route TTL cannot exceed five minutes");
    assert_eq!(too_far.code, RELAY_ROUTE_CONFLICT);

    let forbidden = fixture
        .core
        .handle(
            &device_a.access,
            open_pair_frame(machine_route_a, route, expiry),
        )
        .await
        .expect_err("only MachineAccess may open a pair route");
    assert_eq!(forbidden.code, RELAY_ROUTE_FORBIDDEN);

    assert_applied(
        fixture
            .core
            .handle(
                &machine_a.access,
                open_pair_frame(machine_route_a, route, expiry),
            )
            .await
            .expect("open pair route"),
    );
    assert_opened(&mut machine_a, machine_route_a, route, expiry).await;

    assert_applied(
        fixture
            .core
            .handle(
                &machine_a.access,
                open_pair_frame(machine_route_a, route, expiry),
            )
            .await
            .expect("byte-identical Open retry is idempotent"),
    );
    assert_opened(&mut machine_a, machine_route_a, route, expiry).await;

    let different_expiry = fixture
        .core
        .handle(
            &machine_a.access,
            open_pair_frame(machine_route_a, route, expiry - 1),
        )
        .await
        .expect_err("idempotent retry cannot mutate absolute expiry");
    assert_eq!(different_expiry.code, RELAY_ROUTE_CONFLICT);

    let different_owner = fixture
        .core
        .handle(
            &machine_b.access,
            open_pair_frame(machine_route_b, route, expiry),
        )
        .await
        .expect_err("same random route cannot be taken by another trust domain");
    assert_eq!(different_owner.code, RELAY_ROUTE_CONFLICT);

    let cross_owner_close = fixture
        .core
        .handle(&machine_b.access, close_pair_frame(machine_route_b, route))
        .await
        .expect_err("different active owner cannot close route");
    assert_eq!(cross_owner_close.code, RELAY_ROUTE_FORBIDDEN);

    assert_applied(
        fixture
            .core
            .handle(&machine_a.access, close_pair_frame(machine_route_a, route))
            .await
            .expect("owner closes route"),
    );
    assert_closed_ack(&mut machine_a, route, PairRouteCloseOutcome::Closed).await;

    assert_applied(
        fixture
            .core
            .handle(&machine_a.access, close_pair_frame(machine_route_a, route))
            .await
            .expect("duplicate close is idempotent"),
    );
    assert_closed_ack(&mut machine_a, route, PairRouteCloseOutcome::AlreadyAbsent).await;

    let tombstoned = fixture
        .core
        .handle(
            &machine_a.access,
            open_pair_frame(machine_route_a, route, expiry),
        )
        .await
        .expect_err("closed route cannot be resurrected by delayed Open retry");
    assert_eq!(tombstoned.code, RELAY_ROUTE_CONFLICT);

    fixture.core.tick(expiry).await.expect("expire tombstone");
    // 同一次 5 分钟 tick 也会按既有 heartbeat 契约关闭未回 Pong 的 principal；
    // PairRoute 重用应由重新认证后的同一 machine trust domain 验证。
    machine_a = fixture.connect_machine_at(0, expiry).await;
    let reopened_expiry = expiry + PAIR_TTL_MS;
    assert_applied(
        fixture
            .core
            .handle(
                &machine_a.access,
                open_pair_frame(machine_route_a, route, reopened_expiry),
            )
            .await
            .expect("route id may be reused only after old absolute expiry"),
    );
    assert_opened(&mut machine_a, machine_route_a, route, reopened_expiry).await;

    let invalid_expiry = fixture
        .core
        .handle(
            &machine_a.access,
            open_pair_frame(machine_route_a, pair_route(2), expiry),
        )
        .await
        .expect_err("Open requires now < absolute expiry");
    assert_eq!(invalid_expiry.code, RELAY_ROUTE_CONFLICT);

    fixture.shutdown().await;
}

#[tokio::test]
async fn pairing_view_activate_rechecks_route_binds_one_writer_and_allows_exact_pong() {
    let mut fixture = Fixture::new().await;
    let machine_route = fixture.realms[0].machine_route;
    let route = pair_route(10);
    let expiry = NOW_MS + PAIR_TTL_MS;
    let mut machine = fixture.connect_machine(0).await;
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, expiry),
            )
            .await
            .expect("open route"),
    );
    assert_opened(&mut machine, machine_route, route, expiry).await;

    let first = fixture
        .prepare_pairing(route, OutboundWriterConfig::default())
        .await;
    let second = fixture
        .prepare_pairing(route, OutboundWriterConfig::default())
        .await;
    fixture
        .core
        .activate(first.access.clone())
        .await
        .expect("first pairing writer wins");
    let conflict = fixture
        .core
        .activate(second.access.clone())
        .await
        .expect_err("route permits only one active pairing writer");
    assert_eq!(conflict.code, RELAY_ROUTE_CONFLICT);
    assert!(second.writer.is_closed());
    let mut pairing = TestConnection {
        access: first.access,
        writer: first.writer,
        receiver: first.receiver,
    };

    fixture
        .core
        .tick(NOW_MS + 20_000)
        .await
        .expect("heartbeat tick");
    let ping = recv_frame(&mut pairing).await;
    let RelayFrameBody::Ping(ping) = ping.body else {
        panic!("pairing connection must receive heartbeat Ping");
    };
    assert_applied(
        fixture
            .core
            .handle(
                &pairing.access,
                outer(RelayFrameBody::Pong(Pong { nonce: ping.nonce })),
            )
            .await
            .expect("exact outstanding Pong is a transport-control exception"),
    );
    let machine_ping = recv_frame(&mut machine).await;
    let RelayFrameBody::Ping(machine_ping) = machine_ping.body else {
        panic!("machine connection must receive heartbeat Ping");
    };
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                outer(RelayFrameBody::Pong(Pong {
                    nonce: machine_ping.nonce,
                })),
            )
            .await
            .expect("machine answers its own heartbeat"),
    );
    let stale_pong = fixture
        .core
        .handle(
            &pairing.access,
            outer(RelayFrameBody::Pong(Pong { nonce: ping.nonce })),
        )
        .await
        .expect_err("Pong exception applies only to the exact outstanding heartbeat");
    assert_eq!(stale_pong.code, RELAY_ROUTE_FORBIDDEN);

    let forbidden_subscribe = fixture
        .core
        .handle(
            &pairing.access,
            outer(RelayFrameBody::Subscribe(Subscribe {
                stream_route: stream(1),
                generation: generation(1),
                cursor: StreamCursor::BeforeFirst,
            })),
        )
        .await
        .expect_err("pairing connection cannot subscribe");
    assert_eq!(forbidden_subscribe.code, RELAY_ROUTE_FORBIDDEN);
    let forbidden_send = fixture
        .core
        .handle(
            &pairing.access,
            send_frame(
                fixture.realms[0].devices[0].route,
                request_route(1),
                vec![1],
            ),
        )
        .await
        .expect_err("pairing connection cannot Send");
    assert_eq!(forbidden_send.code, RELAY_ROUTE_FORBIDDEN);
    let wrong_route = fixture
        .core
        .handle(&pairing.access, pair_data_frame(pair_route(11), vec![1]))
        .await
        .expect_err("pairing access is bound to exactly one route");
    assert_eq!(wrong_route.code, RELAY_ROUTE_FORBIDDEN);

    let stale_route = pair_route(12);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, stale_route, expiry),
            )
            .await
            .expect("open route for TOCTOU test"),
    );
    assert_opened(&mut machine, machine_route, stale_route, expiry).await;
    let stale_pairing = fixture
        .prepare_pairing(stale_route, OutboundWriterConfig::default())
        .await;
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                close_pair_frame(machine_route, stale_route),
            )
            .await
            .expect("close between view and activation"),
    );
    assert_closed_ack(&mut machine, stale_route, PairRouteCloseOutcome::Closed).await;
    let stale = fixture
        .core
        .activate(stale_pairing.access)
        .await
        .expect_err("actor must recheck route at activation time");
    assert_eq!(stale.code, RELAY_ROUTE_NOT_FOUND);
    assert!(stale_pairing.writer.is_closed());

    fixture
        .core
        .disconnect(pairing.access.connection_instance())
        .await
        .expect("disconnect first pairing writer");
    let mut reconnected = fixture
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;
    assert!(!reconnected.writer.is_closed());
    assert_applied(
        fixture
            .core
            .handle(&reconnected.access, close_pair_frame(machine_route, route))
            .await
            .expect("pairing side may close its own route"),
    );
    assert_closed_ack(&mut reconnected, route, PairRouteCloseOutcome::Closed).await;
    assert_applied(
        fixture
            .core
            .handle(&reconnected.access, close_pair_frame(machine_route, route))
            .await
            .expect("pairing close retry after uncertain ACK is idempotent"),
    );
    assert_closed_ack(
        &mut reconnected,
        route,
        PairRouteCloseOutcome::AlreadyAbsent,
    )
    .await;

    fixture.shutdown().await;
}

#[tokio::test]
async fn pair_data_is_bidirectional_target_first_and_backpressure_closes_only_the_slow_side() {
    let mut fixture = Fixture::new().await;
    let machine_route = fixture.realms[0].machine_route;
    let route = pair_route(20);
    let mut machine = fixture.connect_machine(0).await;
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open pair route"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let mut pairing = fixture
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;

    let down = pair_data_frame(route, vec![0x31]);
    assert_queued_pair(
        fixture
            .core
            .handle(&machine.access, down.clone())
            .await
            .expect("machine -> pairing"),
        route,
    );
    assert_eq!(recv_frame(&mut pairing).await, down);
    assert_eq!(
        recv_frame(&mut machine).await.body,
        RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::PairFrame { pair_route: route },
        })
    );

    let up = pair_data_frame(route, vec![0x32]);
    assert_queued_pair(
        fixture
            .core
            .handle(&pairing.access, up.clone())
            .await
            .expect("pairing -> machine"),
        route,
    );
    assert_eq!(recv_frame(&mut machine).await, up);
    assert_eq!(
        recv_frame(&mut pairing).await.body,
        RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::PairFrame { pair_route: route },
        })
    );
    fixture.shutdown().await;

    let mut target_slow = Fixture::new().await;
    let machine_route = target_slow.realms[0].machine_route;
    let route = pair_route(21);
    let mut origin = target_slow.connect_machine(0).await;
    assert_applied(
        target_slow
            .core
            .handle(
                &origin.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open slow-target route"),
    );
    assert_opened(&mut origin, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let tiny = OutboundWriterConfig {
        normal: WriterBudget::new(1, 1024),
        ..OutboundWriterConfig::default()
    };
    let mut slow_pairing = target_slow.connect_pairing(route, tiny).await;
    assert_queued_pair(
        target_slow
            .core
            .handle(&origin.access, pair_data_frame(route, vec![1]))
            .await
            .expect("first target frame fits"),
        route,
    );
    let _ = recv_frame(&mut origin).await;
    let in_flight = tokio::time::timeout(Duration::from_secs(5), slow_pairing.receiver.recv())
        .await
        .expect("slow target receive must not hang")
        .expect("first target frame entered the writer");
    assert_eq!(
        decode(in_flight.encoded()).expect("canonical in-flight PairData"),
        pair_data_frame(route, vec![1])
    );
    let target_full = target_slow
        .core
        .handle(&origin.access, pair_data_frame(route, vec![2]))
        .await
        .expect_err("target backpressure returns typed quota to origin");
    assert_eq!(target_full.code, RELAY_QUOTA_EXCEEDED);
    assert_eq!(
        slow_pairing.writer.close_reason(),
        Some(WriterCloseReason::Lagged)
    );
    assert!(
        !origin.writer.is_closed(),
        "slow target must not close origin"
    );
    in_flight.mark_flushed();
    assert_receiver_closed(&mut slow_pairing).await;
    target_slow.shutdown().await;

    let mut origin_slow = Fixture::new().await;
    let machine_route = origin_slow.realms[0].machine_route;
    let route = pair_route(22);
    let tiny_origin = OutboundWriterConfig {
        normal: WriterBudget::new(1, 1024),
        ..OutboundWriterConfig::default()
    };
    let mut slow_machine = origin_slow
        .connect_machine_with_writer(0, tiny_origin)
        .await;
    assert_applied(
        origin_slow
            .core
            .handle(
                &slow_machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open slow-origin route"),
    );
    assert_opened(
        &mut slow_machine,
        machine_route,
        route,
        NOW_MS + PAIR_TTL_MS,
    )
    .await;
    let mut target = origin_slow
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;
    assert_queued_pair(
        origin_slow
            .core
            .handle(&slow_machine.access, pair_data_frame(route, vec![3]))
            .await
            .expect("first delivery and ACK fit"),
        route,
    );
    assert_eq!(
        recv_frame(&mut target).await,
        pair_data_frame(route, vec![3])
    );
    let second = origin_slow
        .core
        .handle(&slow_machine.access, pair_data_frame(route, vec![4]))
        .await
        .expect("target delivery is not rolled back when origin ACK cannot enqueue");
    assert!(matches!(second, RouteOutcome::Closed));
    assert_eq!(
        recv_frame(&mut target).await,
        pair_data_frame(route, vec![4])
    );
    assert_eq!(
        slow_machine.writer.close_reason(),
        Some(WriterCloseReason::Lagged)
    );
    origin_slow.shutdown().await;
}

#[tokio::test]
async fn machine_close_delivers_terminal_ack_to_the_bound_pairing_requester() {
    let mut fixture = Fixture::new().await;
    let machine_route = fixture.realms[0].machine_route;
    let route = pair_route(22);
    let mut machine = fixture.connect_machine(0).await;
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open route for machine terminal ACK"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let mut pairing = fixture
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;

    assert_applied(
        fixture
            .core
            .handle(&machine.access, close_pair_frame(machine_route, route))
            .await
            .expect("machine closes route after durable pairing receipt"),
    );
    assert_closed_ack(&mut machine, route, PairRouteCloseOutcome::Closed).await;
    assert_closed_ack(&mut pairing, route, PairRouteCloseOutcome::Closed).await;

    let stale = fixture
        .core
        .handle(&pairing.access, pair_data_frame(route, vec![0x22]))
        .await
        .expect_err("terminal ACK cannot leave the pairing route usable");
    assert_eq!(stale.code, RELAY_ROUTE_NOT_FOUND);
    fixture.shutdown().await;
}

#[tokio::test]
async fn pair_route_close_and_expiry_races_are_actor_serialized() {
    let mut close_race = Fixture::new().await;
    let machine_route = close_race.realms[0].machine_route;
    let mut machine = close_race.connect_machine(0).await;

    let machine_first_route = pair_route(23);
    assert_applied(
        close_race
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, machine_first_route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open machine-first close race route"),
    );
    assert_opened(
        &mut machine,
        machine_route,
        machine_first_route,
        NOW_MS + PAIR_TTL_MS,
    )
    .await;
    let mut pairing = close_race
        .connect_pairing(machine_first_route, OutboundWriterConfig::default())
        .await;
    let (machine_close, pairing_close) = tokio::join!(
        biased;
        close_race.core.handle(
            &machine.access,
            close_pair_frame(machine_route, machine_first_route),
        ),
        close_race.core.handle(
            &pairing.access,
            close_pair_frame(machine_route, machine_first_route),
        )
    );
    assert_applied(machine_close.expect("machine wins first serialized close"));
    assert_applied(pairing_close.expect("detached pairing close retry is idempotent"));
    assert_closed_ack(
        &mut machine,
        machine_first_route,
        PairRouteCloseOutcome::Closed,
    )
    .await;
    assert_closed_ack(
        &mut pairing,
        machine_first_route,
        PairRouteCloseOutcome::Closed,
    )
    .await;
    assert_closed_ack(
        &mut pairing,
        machine_first_route,
        PairRouteCloseOutcome::AlreadyAbsent,
    )
    .await;
    assert!(
        !pairing.writer.is_closed(),
        "machine close detaches pairing without clearing an already queued target fact"
    );
    close_race
        .core
        .disconnect(pairing.access.connection_instance())
        .await
        .expect("disconnect detached pairing");

    let pairing_first_route = pair_route(24);
    assert_applied(
        close_race
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, pairing_first_route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open pairing-first close race route"),
    );
    assert_opened(
        &mut machine,
        machine_route,
        pairing_first_route,
        NOW_MS + PAIR_TTL_MS,
    )
    .await;
    let mut pairing = close_race
        .connect_pairing(pairing_first_route, OutboundWriterConfig::default())
        .await;
    let (pairing_close, machine_close) = tokio::join!(
        biased;
        close_race.core.handle(
            &pairing.access,
            close_pair_frame(machine_route, pairing_first_route),
        ),
        close_race.core.handle(
            &machine.access,
            close_pair_frame(machine_route, pairing_first_route),
        )
    );
    assert_applied(pairing_close.expect("pairing wins first serialized close"));
    assert_applied(machine_close.expect("machine close retry is idempotent"));
    assert_closed_ack(
        &mut pairing,
        pairing_first_route,
        PairRouteCloseOutcome::Closed,
    )
    .await;
    assert_closed_ack(
        &mut machine,
        pairing_first_route,
        PairRouteCloseOutcome::AlreadyAbsent,
    )
    .await;
    close_race.shutdown().await;

    let mut expiry_first = Fixture::new().await;
    let machine_route = expiry_first.realms[0].machine_route;
    let route = pair_route(25);
    let mut machine = expiry_first.connect_machine(0).await;
    assert_applied(
        expiry_first
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open expiry-first route"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let pairing = expiry_first
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;
    let (tick, data) = tokio::join!(
        biased;
        expiry_first.core.tick(NOW_MS + PAIR_TTL_MS),
        expiry_first
            .core
            .handle(&pairing.access, pair_data_frame(route, vec![0x25]))
    );
    tick.expect("expiry command wins actor order");
    assert_eq!(
        data.expect_err("post-expiry PairData must be rejected")
            .code,
        RELAY_ROUTE_NOT_FOUND
    );
    assert!(pairing.writer.is_closed());
    expiry_first.shutdown().await;

    let mut data_first = Fixture::new().await;
    let machine_route = data_first.realms[0].machine_route;
    let route = pair_route(26);
    let mut machine = data_first.connect_machine(0).await;
    assert_applied(
        data_first
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open data-first route"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let pairing = data_first
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;
    let (data, tick) = tokio::join!(
        biased;
        data_first
            .core
            .handle(&pairing.access, pair_data_frame(route, vec![0x26])),
        data_first.core.tick(NOW_MS + PAIR_TTL_MS)
    );
    assert_queued_pair(data.expect("pre-expiry PairData wins actor order"), route);
    tick.expect("expiry follows accepted PairData");
    assert!(
        data_first
            .core
            .pair_route_view(route)
            .await
            .expect("view expired route")
            .active_route
            .is_none()
    );
    assert!(pairing.writer.is_closed());
    data_first.shutdown().await;
}

#[tokio::test]
async fn pair_route_default_capacity_lifetime_bytes_rate_and_ttl_are_hard_bounds() {
    let mut capacity = Fixture::new().await;
    let machine_route = capacity.realms[0].machine_route;
    let mut machine = capacity.connect_machine(0).await;
    for index in 0..8_u16 {
        let route = pair_route(100 + index);
        assert_applied(
            capacity
                .core
                .handle(
                    &machine.access,
                    open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
                )
                .await
                .expect("first eight routes fit per-machine capacity"),
        );
        assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    }
    let ninth = capacity
        .core
        .handle(
            &machine.access,
            open_pair_frame(machine_route, pair_route(108), NOW_MS + PAIR_TTL_MS),
        )
        .await
        .expect_err("ninth active/tombstoned route exceeds per-machine bound");
    assert_eq!(ninth.code, RELAY_QUOTA_EXCEEDED);
    assert_applied(
        capacity
            .core
            .handle(
                &machine.access,
                close_pair_frame(machine_route, pair_route(100)),
            )
            .await
            .expect("close one route into a bounded tombstone"),
    );
    assert_closed_ack(&mut machine, pair_route(100), PairRouteCloseOutcome::Closed).await;
    let tombstone_still_counts = capacity
        .core
        .handle(
            &machine.access,
            open_pair_frame(machine_route, pair_route(108), NOW_MS + PAIR_TTL_MS),
        )
        .await
        .expect_err("closed tombstone remains in capacity until absolute expiry");
    assert_eq!(tombstone_still_counts.code, RELAY_QUOTA_EXCEEDED);
    capacity.shutdown().await;

    let mut lifetime = Fixture::new().await;
    let machine_route = lifetime.realms[0].machine_route;
    let route = pair_route(200);
    let mut machine = lifetime.connect_machine(0).await;
    assert_applied(
        lifetime
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open lifetime route"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let mut pairing = lifetime
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;
    for index in 0..32_u64 {
        lifetime
            .core
            .tick(NOW_MS + index * 500)
            .await
            .expect("advance pair token bucket");
        assert_queued_pair(
            lifetime
                .core
                .handle(&pairing.access, pair_data_frame(route, vec![index as u8]))
                .await
                .expect("first 32 successfully enqueued frames fit lifetime bound"),
            route,
        );
        assert_eq!(
            recv_frame(&mut machine).await,
            pair_data_frame(route, vec![index as u8])
        );
        let _ = recv_frame(&mut pairing).await;
    }
    lifetime
        .core
        .tick(NOW_MS + 16_000)
        .await
        .expect("refill after frame bound");
    let frame_limit = lifetime
        .core
        .handle(&pairing.access, pair_data_frame(route, vec![0xff]))
        .await
        .expect_err("33rd successful delivery exceeds lifetime frame bound");
    assert_eq!(frame_limit.code, RELAY_QUOTA_EXCEEDED);
    lifetime.shutdown().await;

    let mut bytes = Fixture::new().await;
    let machine_route = bytes.realms[0].machine_route;
    let route = pair_route(201);
    let mut machine = bytes.connect_machine(0).await;
    assert_applied(
        bytes
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open byte-bound route"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let mut pairing = bytes
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;
    let empty = pair_data_frame(route, Vec::new());
    let overhead = encode(&empty).len();
    let exact_mib = pair_data_frame(route, vec![0xa5; 1024 * 1024 - overhead]);
    assert_eq!(encode(&exact_mib).len(), 1024 * 1024);
    assert_queued_pair(
        bytes
            .core
            .handle(&pairing.access, exact_mib.clone())
            .await
            .expect("exact 1 MiB canonical route lifetime fits"),
        route,
    );
    assert_eq!(recv_frame(&mut machine).await, exact_mib);
    let _ = recv_frame(&mut pairing).await;
    let byte_limit = bytes
        .core
        .handle(&pairing.access, pair_data_frame(route, vec![1]))
        .await
        .expect_err("route lifetime bytes count canonical outer frame bytes");
    assert_eq!(byte_limit.code, RELAY_QUOTA_EXCEEDED);
    bytes.shutdown().await;

    let mut bucket = Fixture::new().await;
    let machine_route = bucket.realms[0].machine_route;
    let route = pair_route(202);
    let mut machine = bucket.connect_machine(0).await;
    assert_applied(
        bucket
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open rate-bound route"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let mut pairing = bucket
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;
    for index in 0..8_u8 {
        assert_queued_pair(
            bucket
                .core
                .handle(&pairing.access, pair_data_frame(route, vec![index]))
                .await
                .expect("default burst admits eight frames"),
            route,
        );
        let _ = recv_frame(&mut machine).await;
        let _ = recv_frame(&mut pairing).await;
    }
    assert_applied(
        bucket
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("exact Open retry remains idempotent after traffic"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let rate_limited = bucket
        .core
        .handle(&pairing.access, pair_data_frame(route, vec![8]))
        .await
        .expect_err("ninth immediate forwarding attempt exhausts bucket");
    assert_eq!(rate_limited.code, RELAY_QUOTA_EXCEEDED);
    bucket
        .core
        .tick(NOW_MS + 500)
        .await
        .expect("refill one token at 2 frames/s");
    assert_queued_pair(
        bucket
            .core
            .handle(&pairing.access, pair_data_frame(route, vec![9]))
            .await
            .expect("one frame admitted after 500ms refill"),
        route,
    );
    let _ = recv_frame(&mut machine).await;
    let _ = recv_frame(&mut pairing).await;
    bucket
        .core
        .tick(NOW_MS + PAIR_TTL_MS)
        .await
        .expect("expire pair route");
    let expired = bucket
        .core
        .handle(&pairing.access, pair_data_frame(route, vec![10]))
        .await
        .expect_err("pairing access is revalidated after absolute expiry");
    assert_eq!(expired.code, RELAY_ROUTE_NOT_FOUND);
    bucket.shutdown().await;
}

#[tokio::test]
async fn send_reply_are_online_role_bound_trust_bound_and_do_not_require_a_seen_map() {
    let mut fixture = Fixture::new().await;
    let device_a_route = fixture.realms[0].devices[0].route;
    let device_a2_route = fixture.realms[0].devices[1].route;
    let device_b_route = fixture.realms[1].devices[0].route;
    let mut machine_a = fixture.connect_machine(0).await;
    let mut device_a = fixture.connect_device(0, 0).await;
    let machine_b = fixture.connect_machine(1).await;
    let mut device_b = fixture.connect_device(1, 0).await;

    let send_route = request_route(1);
    let send = send_frame(device_a_route, send_route, vec![0x41]);
    assert_queued_request(
        fixture
            .core
            .handle(&device_a.access, send.clone())
            .await
            .expect("device Send targets active machine in its trust domain"),
        send_route,
    );
    assert_eq!(recv_frame(&mut machine_a).await, send);
    assert_eq!(
        recv_frame(&mut device_a).await.body,
        RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::Request {
                request_route: send_route,
            },
        })
    );

    let forged_self = fixture
        .core
        .handle(
            &device_a.access,
            send_frame(device_a2_route, request_route(2), vec![0x42]),
        )
        .await
        .expect_err("device must declare its own device route");
    assert_eq!(forged_self.code, RELAY_ROUTE_FORBIDDEN);

    let arbitrary_unseen_route = request_route(0xf0);
    let reply = reply_frame(device_a_route, arbitrary_unseen_route, vec![0x43]);
    assert_queued_request(
        fixture
            .core
            .handle(&machine_a.access, reply.clone())
            .await
            .expect("Reply routes explicitly without any request-origin seen-map"),
        arbitrary_unseen_route,
    );
    assert_eq!(recv_frame(&mut device_a).await, reply);
    assert_eq!(
        recv_frame(&mut machine_a).await.body,
        RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::Request {
                request_route: arbitrary_unseen_route,
            },
        })
    );

    let cross_domain = fixture
        .core
        .handle(
            &machine_a.access,
            reply_frame(device_b_route, request_route(3), vec![0x44]),
        )
        .await
        .expect_err("machine cannot guess and target another trust domain device");
    assert_eq!(cross_domain.code, RELAY_ROUTE_NOT_FOUND);

    let machine_send = fixture
        .core
        .handle(
            &machine_b.access,
            send_frame(device_b_route, request_route(4), vec![0x45]),
        )
        .await
        .expect_err("MachineAccess cannot use Send");
    assert_eq!(machine_send.code, RELAY_ROUTE_FORBIDDEN);
    let device_reply = fixture
        .core
        .handle(
            &device_b.access,
            reply_frame(device_b_route, request_route(5), vec![0x46]),
        )
        .await
        .expect_err("DeviceAccess cannot use Reply");
    assert_eq!(device_reply.code, RELAY_ROUTE_FORBIDDEN);

    fixture
        .core
        .disconnect(machine_a.access.connection_instance())
        .await
        .expect("machine goes offline");
    assert_receiver_closed(&mut device_a).await;
    let machine_offline = fixture
        .core
        .handle(
            &device_a.access,
            send_frame(device_a_route, request_route(6), vec![0x47]),
        )
        .await
        .expect_err("machine generation loss invalidates the old device generation");
    assert_eq!(machine_offline.code, RELAY_AUTH_INVALID_GRANT);

    fixture
        .core
        .disconnect(device_b.access.connection_instance())
        .await
        .expect("device goes offline");
    let device_offline = fixture
        .core
        .handle(
            &machine_b.access,
            reply_frame(device_b_route, request_route(7), vec![0x48]),
        )
        .await
        .expect_err("Reply is online-only");
    assert_eq!(device_offline.code, RELAY_ROUTE_NOT_FOUND);
    assert_receiver_closed(&mut device_b).await;

    fixture.shutdown().await;
}

#[tokio::test]
async fn online_request_target_first_backpressure_and_stale_origin_are_fail_closed() {
    let tiny = OutboundWriterConfig {
        normal: WriterBudget::new(1, 1024),
        ..OutboundWriterConfig::default()
    };

    let mut target_slow = Fixture::new().await;
    let device_route = target_slow.realms[0].devices[0].route;
    let mut slow_machine = target_slow.connect_machine_with_writer(0, tiny).await;
    let mut device = target_slow.connect_device(0, 0).await;
    let first = send_frame(device_route, request_route(0x21), vec![1]);
    assert_queued_request(
        target_slow
            .core
            .handle(&device.access, first.clone())
            .await
            .expect("first request enters target writer"),
        request_route(0x21),
    );
    let in_flight = tokio::time::timeout(Duration::from_secs(5), slow_machine.receiver.recv())
        .await
        .expect("slow target receive must not hang")
        .expect("first request must enter target writer");
    assert_eq!(
        decode(in_flight.encoded()).expect("canonical in-flight Send"),
        first
    );
    let _ = recv_frame(&mut device).await;
    let target_full = target_slow
        .core
        .handle(
            &device.access,
            send_frame(device_route, request_route(0x22), vec![2]),
        )
        .await
        .expect_err("full target writer returns typed quota");
    assert_eq!(target_full.code, RELAY_QUOTA_EXCEEDED);
    assert_eq!(
        slow_machine.writer.close_reason(),
        Some(WriterCloseReason::Lagged)
    );
    assert!(
        !device.writer.is_closed(),
        "slow target cannot close origin"
    );
    in_flight.mark_flushed();
    assert_receiver_closed(&mut slow_machine).await;
    target_slow.shutdown().await;

    let mut origin_slow = Fixture::new().await;
    let device_route = origin_slow.realms[0].devices[0].route;
    let mut machine = origin_slow.connect_machine(0).await;
    let mut slow_device = origin_slow.connect_device_with_writer(0, 0, tiny).await;
    assert_queued_request(
        origin_slow
            .core
            .handle(
                &slow_device.access,
                send_frame(device_route, request_route(0x23), vec![3]),
            )
            .await
            .expect("first request and origin ACK fit"),
        request_route(0x23),
    );
    assert_eq!(
        recv_frame(&mut machine).await,
        send_frame(device_route, request_route(0x23), vec![3])
    );
    let second = origin_slow
        .core
        .handle(
            &slow_device.access,
            send_frame(device_route, request_route(0x24), vec![4]),
        )
        .await
        .expect("target delivery survives origin ACK backpressure");
    assert!(matches!(second, RouteOutcome::Closed));
    assert_eq!(
        recv_frame(&mut machine).await,
        send_frame(device_route, request_route(0x24), vec![4])
    );
    assert_eq!(
        slow_device.writer.close_reason(),
        Some(WriterCloseReason::Lagged)
    );
    assert_receiver_closed(&mut slow_device).await;
    origin_slow.shutdown().await;

    let mut replacement = Fixture::new().await;
    let device_route = replacement.realms[0].devices[0].route;
    let mut machine = replacement.connect_machine(0).await;
    let mut old_device = replacement.connect_device(0, 0).await;
    let mut current_device = replacement.connect_device(0, 0).await;
    tokio::time::timeout(Duration::from_secs(5), old_device.writer.closed())
        .await
        .expect("replacement must close old origin generation");
    let stale = replacement
        .core
        .handle(
            &old_device.access,
            send_frame(device_route, request_route(0x25), vec![5]),
        )
        .await
        .expect_err("old origin generation cannot cross transition fence");
    assert_eq!(stale.code, RELAY_AUTH_INVALID_GRANT);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), machine.receiver.recv())
            .await
            .is_err(),
        "stale origin must not enqueue any target frame"
    );
    assert_queued_request(
        replacement
            .core
            .handle(
                &current_device.access,
                send_frame(device_route, request_route(0x26), vec![6]),
            )
            .await
            .expect("current replacement remains healthy"),
        request_route(0x26),
    );
    let _ = recv_frame(&mut machine).await;
    let _ = recv_frame(&mut current_device).await;
    assert_receiver_closed(&mut old_device).await;
    replacement.shutdown().await;
}

#[tokio::test]
async fn accepted_reply_is_online_only_and_is_lost_if_target_disconnects_before_flush() {
    let mut fixture = Fixture::new().await;
    let device_route = fixture.realms[0].devices[0].route;
    let mut machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;
    let readonly = open_readonly_db(&fixture.db_path);
    let baseline = sqlite_route_snapshot(&readonly);
    let request_route = request_route(0x31);
    assert_queued_request(
        fixture
            .core
            .handle(
                &machine.access,
                reply_frame(device_route, request_route, vec![0x31]),
            )
            .await
            .expect("Reply enters current device writer"),
        request_route,
    );
    assert_eq!(
        recv_frame(&mut machine).await.body,
        RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::Request { request_route },
        })
    );
    fixture
        .core
        .disconnect(device.access.connection_instance())
        .await
        .expect("disconnect target before socket flush");
    assert_receiver_closed(&mut device).await;
    assert_eq!(
        sqlite_route_snapshot(&readonly),
        baseline,
        "RouteAccepted cannot turn Reply into an offline queue"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn route_frames_make_zero_sqlite_payload_writes_and_core_restart_clears_only_memory_routes() {
    let mut fixture = Fixture::new().await;
    let machine_route = fixture.realms[0].machine_route;
    let device_route = fixture.realms[0].devices[0].route;
    let route = pair_route(300);
    let expiry = NOW_MS + PAIR_TTL_MS;
    let mut machine = fixture.connect_machine(0).await;
    let mut device = fixture.connect_device(0, 0).await;

    // 先建立非空 stream/HWM sentinel，避免“空表行数仍为零”的假阳性；随后保持同一
    // read-only connection，用 PRAGMA data_version 捕获任意 Relay SQLite commit。
    let sentinel_stream = stream(0x91);
    let sentinel_generation = generation(0x92);
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                outer(RelayFrameBody::RegisterStream(RegisterStream {
                    machine_route,
                    stream_route: sentinel_stream,
                    generation: sentinel_generation,
                })),
            )
            .await
            .expect("register sentinel stream"),
    );
    for stream_seq in 0..=1 {
        assert!(matches!(
            fixture
                .core
                .handle(
                    &machine.access,
                    outer(RelayFrameBody::Publish(Publish {
                        stream_route: sentinel_stream,
                        generation: sentinel_generation,
                        stream_seq,
                        sealed_blob: SealedBlob(vec![0x90 + stream_seq as u8]),
                    })),
                )
                .await
                .expect("publish sentinel frame"),
            RouteOutcome::Queued(_)
        ));
        let _ = recv_frame(&mut machine).await;
    }
    let readonly = open_readonly_db(&fixture.db_path);
    let baseline = sqlite_route_snapshot(&readonly);
    assert_eq!(baseline.stream_high_waters, vec!["00000000000000000001"]);
    assert_eq!(baseline.frame_count_and_bytes.0, 2);

    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, expiry),
            )
            .await
            .expect("open memory-only route"),
    );
    assert_opened(&mut machine, machine_route, route, expiry).await;
    let mut pairing = fixture
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;

    assert_queued_pair(
        fixture
            .core
            .handle(&pairing.access, pair_data_frame(route, vec![0xde, 0xad]))
            .await
            .expect("online PairData"),
        route,
    );
    let _ = recv_frame(&mut machine).await;
    let _ = recv_frame(&mut pairing).await;
    assert_queued_request(
        fixture
            .core
            .handle(
                &device.access,
                send_frame(device_route, request_route(0xaa), vec![0xbe, 0xef]),
            )
            .await
            .expect("online Send"),
        request_route(0xaa),
    );
    let _ = recv_frame(&mut machine).await;
    let _ = recv_frame(&mut device).await;
    assert_queued_request(
        fixture
            .core
            .handle(
                &machine.access,
                reply_frame(device_route, request_route(0xbb), vec![0xca, 0xfe]),
            )
            .await
            .expect("online Reply"),
        request_route(0xbb),
    );
    let _ = recv_frame(&mut device).await;
    let _ = recv_frame(&mut machine).await;

    assert_eq!(
        sqlite_route_snapshot(&readonly),
        baseline,
        "PairRoute/PairData/Send/Reply must produce zero SQLite commits or semantic changes"
    );

    fixture.restart_core().await;
    let view = fixture
        .core
        .pair_route_view(route)
        .await
        .expect("view after Core restart");
    assert!(
        view.active_route.is_none(),
        "PairRoute registry is deliberately memory-only"
    );
    let mut reconnected_machine = fixture.connect_machine(0).await;
    let after_reconnect = sqlite_route_snapshot(&readonly);
    assert_applied(
        fixture
            .core
            .handle(
                &reconnected_machine.access,
                open_pair_frame(machine_route, route, expiry),
            )
            .await
            .expect("daemon may reopen exact durable route after Relay Core restart"),
    );
    assert_opened(&mut reconnected_machine, machine_route, route, expiry).await;
    assert_eq!(
        sqlite_route_snapshot(&readonly),
        after_reconnect,
        "reopening an in-memory PairRoute cannot commit to SQLite"
    );

    fixture.shutdown().await;
}

#[tokio::test]
async fn pairing_cannot_publish_or_register_even_with_well_formed_outer_frames() {
    let mut fixture = Fixture::new().await;
    let machine_route = fixture.realms[0].machine_route;
    let route = pair_route(400);
    let mut machine = fixture.connect_machine(0).await;
    assert_applied(
        fixture
            .core
            .handle(
                &machine.access,
                open_pair_frame(machine_route, route, NOW_MS + PAIR_TTL_MS),
            )
            .await
            .expect("open route"),
    );
    assert_opened(&mut machine, machine_route, route, NOW_MS + PAIR_TTL_MS).await;
    let pairing = fixture
        .connect_pairing(route, OutboundWriterConfig::default())
        .await;

    let register = fixture
        .core
        .handle(
            &pairing.access,
            outer(RelayFrameBody::RegisterStream(RegisterStream {
                machine_route,
                stream_route: stream(9),
                generation: generation(9),
            })),
        )
        .await
        .expect_err("pairing cannot register stream");
    assert_eq!(register.code, RELAY_ROUTE_FORBIDDEN);
    let publish = fixture
        .core
        .handle(
            &pairing.access,
            outer(RelayFrameBody::Publish(Publish {
                stream_route: stream(9),
                generation: generation(9),
                stream_seq: 0,
                sealed_blob: SealedBlob(vec![1]),
            })),
        )
        .await
        .expect_err("pairing cannot publish");
    assert_eq!(publish.code, RELAY_ROUTE_FORBIDDEN);

    fixture.shutdown().await;
}

#[tokio::test]
async fn drain_fence_rejects_later_mutations_attach_and_activate_without_state_change() {
    let mut fixture = Fixture::new().await;
    let machine_route = fixture.realms[0].machine_route;
    let route = pair_route(500);
    let expiry = NOW_MS + PAIR_TTL_MS;
    let machine = fixture.connect_machine(0).await;
    let readonly = open_readonly_db(&fixture.db_path);
    let sqlite_before = sqlite_route_snapshot(&readonly);
    let route_before = fixture
        .core
        .pair_route_view(route)
        .await
        .expect("route view before drain");
    let writer_before = format!("{:?}", machine.writer);

    fixture
        .core
        .begin_drain()
        .await
        .expect("install drain fence");
    let rejected = fixture
        .core
        .handle(
            &machine.access,
            open_pair_frame(machine_route, route, expiry),
        )
        .await
        .expect_err("post-fence route mutation must fail");
    assert_eq!(rejected.code, "relay.server.draining");
    let activate = fixture
        .core
        .activate(machine.access.clone())
        .await
        .expect_err("post-fence activation must fail");
    assert_eq!(activate.code, "relay.server.draining");

    let (rejected_writer, _rejected_receiver) =
        OutboundWriter::new(OutboundWriterConfig::default());
    let attach = fixture
        .core
        .attach_pending(connection(9_999), rejected_writer.clone())
        .await
        .expect_err("post-fence attach must fail");
    assert_eq!(attach.code, "relay.server.draining");
    assert_eq!(
        rejected_writer.close_reason(),
        Some(WriterCloseReason::Shutdown)
    );

    assert_eq!(
        fixture
            .core
            .pair_route_view(route)
            .await
            .expect("route view after rejected mutation"),
        route_before
    );
    assert_eq!(sqlite_route_snapshot(&readonly), sqlite_before);
    assert_eq!(format!("{:?}", machine.writer), writer_before);
    assert!(!machine.writer.is_closed());

    fixture.shutdown().await;
}

#[tokio::test]
async fn concurrent_drain_and_route_mutation_linearize_as_full_commit_or_full_rejection() {
    const ITERATIONS: u16 = 32;

    let mut fixture = Fixture::new().await;
    let mut committed = 0_u16;
    let mut rejected = 0_u16;
    for iteration in 0..ITERATIONS {
        if iteration != 0 {
            fixture.restart_core().await;
        }
        let machine_route = fixture.realms[0].machine_route;
        let route = pair_route(600 + iteration);
        let expiry = NOW_MS + PAIR_TTL_MS;
        let mut machine = fixture.connect_machine(0).await;
        let readonly = open_readonly_db(&fixture.db_path);
        let sqlite_before = sqlite_route_snapshot(&readonly);
        let writer_before = format!("{:?}", machine.writer);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let mutation_core = fixture.core.clone();
        let mutation_access = machine.access.clone();
        let mutation_barrier = Arc::clone(&barrier);
        let mutation = tokio::spawn(async move {
            mutation_barrier.wait().await;
            if iteration % 2 == 0 {
                tokio::task::yield_now().await;
            }
            mutation_core
                .handle(
                    &mutation_access,
                    open_pair_frame(machine_route, route, expiry),
                )
                .await
        });
        let drain_core = fixture.core.clone();
        let drain_barrier = Arc::clone(&barrier);
        let drain = tokio::spawn(async move {
            drain_barrier.wait().await;
            if iteration % 2 != 0 {
                tokio::task::yield_now().await;
            }
            drain_core.begin_drain().await
        });
        barrier.wait().await;

        let mutation = mutation.await.expect("join mutation race");
        drain
            .await
            .expect("join drain race")
            .expect("drain fence installs");
        let route_after = fixture
            .core
            .pair_route_view(route)
            .await
            .expect("route view after drain race");

        match mutation {
            Ok(outcome) => {
                committed += 1;
                assert_applied(outcome);
                assert_eq!(
                    route_after.active_route,
                    Some(agentdeck_relay::v2::auth::ActivePairRoute {
                        relay_server_id: fixture.store.relay_server_id(),
                        machine_route,
                        pair_route: route,
                        absolute_expiry_ms: expiry,
                    }),
                    "pre-fence winner must commit the complete in-memory route"
                );
                assert_opened(&mut machine, machine_route, route, expiry).await;
                assert_eq!(format!("{:?}", machine.writer), writer_before);
            }
            Err(error) => {
                rejected += 1;
                assert_eq!(error.code, "relay.server.draining");
                assert!(
                    route_after.active_route.is_none(),
                    "post-fence loser must not leave a half-created route"
                );
                assert_eq!(format!("{:?}", machine.writer), writer_before);
            }
        }
        assert_eq!(
            sqlite_route_snapshot(&readonly),
            sqlite_before,
            "PairRoute race must never produce a partial SQLite commit"
        );
        assert!(!machine.writer.is_closed());
    }

    assert!(committed > 0, "race matrix must cover a pre-fence winner");
    assert!(rejected > 0, "race matrix must cover a post-fence loser");

    fixture.shutdown().await;
}
