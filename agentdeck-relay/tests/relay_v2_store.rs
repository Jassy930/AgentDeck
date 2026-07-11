//! Relay v2 SQLite store 契约测试（Task P2.1 / design §11）。
//!
//! 本组锁定 actor 启动、事务、故障恢复与配额边界：
//! - fresh DB 必须创建带 family/version/signature/server-id marker 的 v2 schema 与八张表；
//! - reopen 保留 relay server id；higher/legacy/unknown/corrupt schema 必须 typed reject，
//!   且拒绝路径不能改写 DB 或创建 WAL/SHM sidecar；
//! - production storage 必须是绝对 regular-file path，拒绝 symlink 与过宽权限，新建目录/
//!   DB 分别为 0700/0600；
//! - worker 报 ready 前必须读回 WAL、FULL、foreign_keys=ON、busy_timeout=5000；
//! - enrollment/grant/stream/publish/subscription/revoke/purge 均在明确事务边界内；
//! - count/bytes/age/machine/global/disk、replay page 与 command queue 均有硬上界。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};

use agentdeck_protocol::relay_v2::frame::{Publish, SealedBlob};
use agentdeck_protocol::relay_v2::{
    CertRole, DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, LinkGeneration,
    MAX_FRAME_BYTES, MachineRouteId, PublicKeyBytes, RelayGrant, RootKeyId, SignedCertificate,
    StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_relay::v2::store::{
    Clock, DiskSpace, DiskSpaceProbe, EnrollmentCodeSeed, FaultInjector, FaultPoint,
    InstallGrantRecord, MetadataLimits, PersistAck, PersistPublish, PersistRevocation,
    PersistSubscription, PersistUnsubscribe, PublishDisposition, PurgeMachine, RegisterMachine,
    RelayStoreHandle, RelayV2StoreConfig, ReplayPageRequest, ReplayPosition, RetentionLimits,
    StoreError, StoreSnapshot, StreamRegistration,
};
#[cfg(unix)]
use fs2::FileExt;
use rusqlite::{Connection, OpenFlags, params};
#[cfg(unix)]
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const SCHEMA_FAMILY: &str = "agentdeck-relay-v2";
const SCHEMA_VERSION: u32 = 1;
const EXPECTED_TABLES: [&str; 8] = [
    "device_grants",
    "enrollment_codes",
    "frames",
    "machine_routes",
    "relay_meta",
    "revocations",
    "streams",
    "subscriptions",
];

fn store_path(temp: &TempDir) -> PathBuf {
    temp.path().join("relay-private").join("relay.db")
}

fn overwrite_retained_bytes_for_probe(
    path: &Path,
    stream_route: StreamRouteId,
    retained_bytes: i64,
) {
    let connection = Connection::open(path).expect("open maintenance probe connection");
    let changed = connection
        .execute(
            "UPDATE streams SET retained_bytes = ?2 WHERE stream_route = ?1",
            params![stream_route.as_bytes().as_slice(), retained_bytes],
        )
        .expect("write maintenance probe sentinel");
    assert_eq!(changed, 1, "probe stream must exist");
}

fn retained_bytes_for_probe(path: &Path, stream_route: StreamRouteId) -> i64 {
    Connection::open(path)
        .expect("open maintenance probe connection")
        .query_row(
            "SELECT retained_bytes FROM streams WHERE stream_route = ?1",
            params![stream_route.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("read maintenance probe sentinel")
}

#[cfg(unix)]
fn snapshot_marker_bytes(source_path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    let mut marker = b"agentdeck-relay-schema-snapshot-v1\0".to_vec();
    marker.extend_from_slice(&Sha256::digest(source_path.as_os_str().as_bytes()));
    marker
}

#[cfg(unix)]
fn create_crash_snapshot_fixture(
    parent: &Path,
    suffix: &str,
    marker_bytes: &[u8],
    extra_file: bool,
) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let directory = parent.join(format!(".agentdeck-relay-schema-inspect-{suffix}"));
    fs::create_dir(&directory).expect("create crash snapshot directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("secure crash snapshot directory");
    let marker = directory.join(".agentdeck-schema-snapshot-v1");
    fs::write(&marker, marker_bytes).expect("write crash snapshot marker");
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
        .expect("secure crash snapshot marker");
    let partial = directory.join("relay.db");
    fs::write(&partial, b"partial crash copy").expect("write partial crash snapshot");
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600))
        .expect("secure partial crash snapshot");
    if extra_file {
        fs::write(directory.join("keep.txt"), b"user data").expect("write unexpected user file");
    }
    directory
}

const NOW_MS: u64 = 1_726_000_000_000;

#[derive(Debug)]
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> Result<u64, StoreError> {
        Ok(self.0)
    }
}

#[derive(Debug)]
struct MutableClock(AtomicU64);

impl MutableClock {
    fn new(now_ms: u64) -> Self {
        Self(AtomicU64::new(now_ms))
    }

    fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl Clock for MutableClock {
    fn now_ms(&self) -> Result<u64, StoreError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Debug)]
struct FixedDiskProbe(DiskSpace);

impl DiskSpaceProbe for FixedDiskProbe {
    fn space(&self, _storage_path: &Path) -> Result<DiskSpace, StoreError> {
        Ok(self.0)
    }
}

#[derive(Debug)]
struct MutableDiskProbe {
    available_bytes: AtomicU64,
    total_bytes: u64,
}

impl MutableDiskProbe {
    fn new(available_bytes: u64, total_bytes: u64) -> Self {
        Self {
            available_bytes: AtomicU64::new(available_bytes),
            total_bytes,
        }
    }

    fn set_available(&self, available_bytes: u64) {
        self.available_bytes
            .store(available_bytes, Ordering::SeqCst);
    }
}

impl DiskSpaceProbe for MutableDiskProbe {
    fn space(&self, _storage_path: &Path) -> Result<DiskSpace, StoreError> {
        Ok(DiskSpace {
            available_bytes: self.available_bytes.load(Ordering::SeqCst),
            total_bytes: self.total_bytes,
        })
    }
}

#[derive(Debug)]
struct OneShotFaultInjector {
    point: FaultPoint,
    fired: AtomicBool,
}

#[derive(Debug)]
struct ArmedFaultInjector {
    point: FaultPoint,
    armed: AtomicBool,
    fired: AtomicBool,
}

impl ArmedFaultInjector {
    fn new(point: FaultPoint) -> Self {
        Self {
            point,
            armed: AtomicBool::new(false),
            fired: AtomicBool::new(false),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl FaultInjector for ArmedFaultInjector {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point
            && self.armed.load(Ordering::SeqCst)
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            return Err(StoreError::InjectedFault(point));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct BlockingFaultInjector {
    point: FaultPoint,
    entered: Mutex<Option<std_mpsc::Sender<()>>>,
    release: Mutex<std_mpsc::Receiver<()>>,
}

impl BlockingFaultInjector {
    fn new(
        point: FaultPoint,
        entered: std_mpsc::Sender<()>,
        release: std_mpsc::Receiver<()>,
    ) -> Self {
        Self {
            point,
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(release),
        }
    }
}

impl FaultInjector for BlockingFaultInjector {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point != self.point {
            return Ok(());
        }
        let sender = self
            .entered
            .lock()
            .map_err(|_| StoreError::InjectedFault(point))?
            .take();
        if let Some(sender) = sender {
            sender
                .send(())
                .map_err(|_| StoreError::InjectedFault(point))?;
            self.release
                .lock()
                .map_err(|_| StoreError::InjectedFault(point))?
                .recv()
                .map_err(|_| StoreError::InjectedFault(point))?;
        }
        Ok(())
    }
}

impl OneShotFaultInjector {
    fn new(point: FaultPoint) -> Self {
        Self {
            point,
            fired: AtomicBool::new(false),
        }
    }
}

impl FaultInjector for OneShotFaultInjector {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(StoreError::InjectedFault(point));
        }
        Ok(())
    }
}

fn fixed_config(path: &Path) -> RelayV2StoreConfig {
    RelayV2StoreConfig::new(path.to_path_buf()).with_clock(Arc::new(FixedClock(NOW_MS)))
}

fn limits_without_disk_gate() -> RetentionLimits {
    RetentionLimits {
        disk_reserve_bytes: 0,
        disk_reserve_percent: 0,
        ..RetentionLimits::default()
    }
}

fn config_with_limits(path: &Path, limits: RetentionLimits) -> RelayV2StoreConfig {
    fixed_config(path)
        .with_retention(limits)
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })))
}

fn config_with_fault(path: &Path, point: FaultPoint) -> RelayV2StoreConfig {
    fixed_config(path).with_fault_injector(Arc::new(OneShotFaultInjector::new(point)))
}

fn machine_route(seed: u8) -> MachineRouteId {
    MachineRouteId::from_bytes([seed; 16])
}

fn device_route(seed: u8) -> DeviceRouteId {
    DeviceRouteId::from_bytes([seed; 16])
}

fn stream_route(seed: u8) -> StreamRouteId {
    StreamRouteId::from_bytes([seed; 16])
}

fn stream_generation(seed: u8) -> StreamGenerationId {
    StreamGenerationId::from_bytes([seed; 16])
}

fn root_key_id(seed: u8) -> RootKeyId {
    RootKeyId::from_bytes([seed; 16])
}

fn certificate(role: CertRole, seed: u8, generation: u64) -> SignedCertificate {
    SignedCertificate {
        subject_pubkey: PublicKeyBytes([seed; 32]),
        cert_role: role,
        generation: LinkGeneration::new(generation),
        root_key_id: root_key_id(seed),
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: Some(NOW_MS + 60_000),
        signature: Ed25519Signature([seed.wrapping_add(1); 64]),
    }
}

fn enrollment_seed(seed: u8) -> EnrollmentCodeSeed {
    EnrollmentCodeSeed {
        code_hash: [seed; 32],
        expires_at_ms: NOW_MS + 30_000,
    }
}

fn register_machine_request(seed: u8) -> RegisterMachine {
    RegisterMachine {
        code_hash: [seed; 32],
        request_hash: [seed.wrapping_add(1); 32],
        response_blob: vec![seed, 0xad, 0x02],
        receipt_hash: [seed.wrapping_add(2); 32],
        machine_route: machine_route(seed),
        root_pubkey: PublicKeyBytes([seed.wrapping_add(3); 32]),
        link_cert: certificate(CertRole::Link, seed, 3),
        data_cert: certificate(CertRole::Data, seed, 3),
        link_cert_hash: [seed.wrapping_add(4); 32],
        data_cert_hash: [seed.wrapping_add(5); 32],
    }
}

fn relay_grant(machine_seed: u8, device_seed: u8, serial: u64) -> RelayGrant {
    RelayGrant {
        machine_route: machine_route(machine_seed),
        device_route: device_route(device_seed),
        device_sign_pubkey: PublicKeyBytes([device_seed.wrapping_add(1); 32]),
        grant_serial: GrantSerial::new(serial),
        root_key_id: root_key_id(machine_seed),
        trust_epoch: TrustEpoch::new(1),
        signature: Ed25519Signature([device_seed.wrapping_add(2); 64]),
    }
}

fn install_grant_request(machine_seed: u8, device_seed: u8, serial: u64) -> InstallGrantRecord {
    InstallGrantRecord {
        grant: relay_grant(machine_seed, device_seed, serial),
        grant_hash: [device_seed.wrapping_add(serial as u8); 32],
    }
}

fn stream_registration(machine_seed: u8, stream_seed: u8) -> StreamRegistration {
    StreamRegistration {
        machine_route: machine_route(machine_seed),
        stream_route: stream_route(stream_seed),
        generation: stream_generation(stream_seed.wrapping_add(1)),
    }
}

fn publish_request(
    machine_seed: u8,
    stream_seed: u8,
    stream_seq: u64,
    payload_seed: u8,
) -> PersistPublish {
    PersistPublish::from_publish(
        machine_route(machine_seed),
        Publish {
            stream_route: stream_route(stream_seed),
            generation: stream_generation(stream_seed.wrapping_add(1)),
            stream_seq,
            sealed_blob: SealedBlob(vec![payload_seed; 48]),
        },
    )
}

fn publish_request_with_len(
    machine_seed: u8,
    stream_seed: u8,
    stream_seq: u64,
    payload_seed: u8,
    payload_len: usize,
) -> PersistPublish {
    PersistPublish::from_publish(
        machine_route(machine_seed),
        Publish {
            stream_route: stream_route(stream_seed),
            generation: stream_generation(stream_seed.wrapping_add(1)),
            stream_seq,
            sealed_blob: SealedBlob(vec![payload_seed; payload_len]),
        },
    )
}

fn replay_request(
    machine_seed: u8,
    stream_seed: u8,
    position: ReplayPosition,
) -> ReplayPageRequest {
    ReplayPageRequest {
        machine_route: machine_route(machine_seed),
        stream_route: stream_route(stream_seed),
        generation: stream_generation(stream_seed.wrapping_add(1)),
        position,
        page_max_frames: 64,
        page_max_bytes: 8 * 1024 * 1024,
    }
}

fn subscription_request(
    machine_seed: u8,
    device_seed: u8,
    grant_serial: u64,
    stream_seed: u8,
    start: StreamCursor,
) -> PersistSubscription {
    PersistSubscription {
        machine_route: machine_route(machine_seed),
        device_route: device_route(device_seed),
        grant_serial: GrantSerial::new(grant_serial),
        stream_route: stream_route(stream_seed),
        generation: stream_generation(stream_seed.wrapping_add(1)),
        start,
    }
}

fn ack_request(
    machine_seed: u8,
    device_seed: u8,
    grant_serial: u64,
    stream_seed: u8,
    up_to_seq: u64,
) -> PersistAck {
    PersistAck {
        machine_route: machine_route(machine_seed),
        device_route: device_route(device_seed),
        grant_serial: GrantSerial::new(grant_serial),
        stream_route: stream_route(stream_seed),
        generation: stream_generation(stream_seed.wrapping_add(1)),
        up_to_seq,
    }
}

fn unsubscribe_request(
    machine_seed: u8,
    device_seed: u8,
    grant_serial: u64,
    stream_seed: u8,
) -> PersistUnsubscribe {
    PersistUnsubscribe {
        machine_route: machine_route(machine_seed),
        device_route: device_route(device_seed),
        grant_serial: GrantSerial::new(grant_serial),
        stream_route: stream_route(stream_seed),
        generation: stream_generation(stream_seed.wrapping_add(1)),
    }
}

fn revocation_request(machine_seed: u8, device_seed: u8, grant_serial: u64) -> PersistRevocation {
    PersistRevocation {
        revocation: DeviceRevocation {
            machine_route: machine_route(machine_seed),
            device_route: device_route(device_seed),
            grant_serial: GrantSerial::new(grant_serial),
            root_key_id: root_key_id(machine_seed),
            trust_epoch: TrustEpoch::new(1),
            signature: Ed25519Signature([0xd1; 64]),
        },
        revocation_hash: [0xd2; 32],
        signed_revocation_blob: vec![0xd3; 96],
    }
}

async fn seed_and_register(store: &RelayStoreHandle, seed: u8) -> RegisterMachine {
    let code = enrollment_seed(seed);
    store
        .seed_enrollment_code(code)
        .await
        .expect("seed enrollment code");
    let request = register_machine_request(seed);
    store
        .register_machine(request.clone())
        .await
        .expect("register fixture machine");
    request
}

async fn install_fixture_grant(
    store: &RelayStoreHandle,
    machine_seed: u8,
    device_seed: u8,
    serial: u64,
) -> InstallGrantRecord {
    let request = install_grant_request(machine_seed, device_seed, serial);
    store
        .install_grant(request.clone())
        .await
        .expect("install fixture grant");
    request
}

async fn register_fixture_stream(
    store: &RelayStoreHandle,
    machine_seed: u8,
    stream_seed: u8,
) -> StreamRegistration {
    let request = stream_registration(machine_seed, stream_seed);
    store
        .register_stream(request.clone())
        .await
        .expect("register fixture stream");
    request
}

async fn open_production(path: &Path) -> RelayStoreHandle {
    RelayStoreHandle::open(RelayV2StoreConfig::new(path.to_path_buf()))
        .await
        .expect("production v2 store should open")
}

fn table_set(snapshot: &StoreSnapshot) -> BTreeSet<&str> {
    snapshot.table_names.iter().map(String::as_str).collect()
}

#[derive(Debug, PartialEq, Eq)]
struct FileState {
    bytes: Vec<u8>,
    wal_exists: bool,
    shm_exists: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct FullSqliteState {
    database: Vec<u8>,
    wal: Option<Vec<u8>>,
    shm: Option<Vec<u8>>,
}

fn file_state(path: &Path) -> FileState {
    FileState {
        bytes: fs::read(path).expect("read sqlite fixture"),
        wal_exists: sidecar(path, "-wal").exists(),
        shm_exists: sidecar(path, "-shm").exists(),
    }
}

fn full_sqlite_state(path: &Path) -> FullSqliteState {
    FullSqliteState {
        database: fs::read(path).expect("read sqlite database"),
        wal: fs::read(sidecar(path, "-wal")).ok(),
        shm: fs::read(sidecar(path, "-shm")).ok(),
    }
}

fn assert_full_sqlite_state_unchanged(path: &Path, before: &FullSqliteState) {
    let after = full_sqlite_state(path);
    assert!(
        after.database == before.database,
        "source database bytes changed during inspection"
    );
    assert!(
        after.wal == before.wal,
        "source WAL bytes or existence changed during inspection"
    );
    assert!(
        after.shm == before.shm,
        "source SHM bytes or existence changed during inspection"
    );
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn create_parent(path: &Path) {
    fs::create_dir_all(path.parent().expect("fixture DB must have parent"))
        .expect("create fixture parent");
}

fn create_relay_meta_fixture(path: &Path, version: u32, signature: [u8; 32]) {
    create_parent(path);
    let conn = Connection::open(path).expect("open relay_meta fixture");
    conn.execute_batch(
        "CREATE TABLE relay_meta (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            schema_family TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            schema_signature BLOB NOT NULL CHECK(length(schema_signature) = 32),
            relay_server_id BLOB NOT NULL CHECK(length(relay_server_id) = 16)
         );",
    )
    .expect("create relay_meta fixture");
    conn.execute(
        "INSERT INTO relay_meta(
            singleton, schema_family, schema_version, schema_signature, relay_server_id
         ) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            SCHEMA_FAMILY,
            i64::from(version),
            signature.to_vec(),
            [0x5a_u8; 16].to_vec()
        ],
    )
    .expect("insert relay_meta fixture");
    conn.pragma_update(None, "user_version", version)
        .expect("set fixture user_version");
    drop(conn);
    secure_fixture_database(path);
}

fn create_higher_schema_only_in_wal(path: &Path) -> Connection {
    create_parent(path);
    let writer = Connection::open(path).expect("open schema-only WAL fixture");
    writer
        .pragma_update(None, "journal_mode", "WAL")
        .expect("enable schema-only WAL");
    writer
        .pragma_update(None, "wal_autocheckpoint", 0)
        .expect("disable schema-only WAL autocheckpoint");
    writer
        .execute_batch(
            "CREATE TABLE relay_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                schema_family TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                schema_signature BLOB NOT NULL,
                relay_server_id BLOB NOT NULL
             );
             INSERT INTO relay_meta(
                singleton, schema_family, schema_version, schema_signature, relay_server_id
             ) VALUES (
                1, 'agentdeck-relay-v2', 2,
                x'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
                x'5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'
             );
             PRAGMA user_version = 2;",
        )
        .expect("write higher schema only into WAL");
    secure_fixture_database(path);
    writer
}

fn create_exact_legacy_v1_fixture(path: &Path) {
    create_parent(path);
    let conn = Connection::open(path).expect("open legacy fixture");
    conn.execute_batch(
        "CREATE TABLE accounts (
            account_id TEXT PRIMARY KEY,
            owner_sign_pubkey TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL
         );
         CREATE TABLE devices (
            device_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts(account_id),
            role TEXT NOT NULL CHECK (role IN ('machine', 'device')),
            credential_hash TEXT NOT NULL UNIQUE,
            sign_pubkey TEXT NOT NULL,
            box_pubkey TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at_ms INTEGER NOT NULL
         );
         CREATE INDEX idx_devices_credential_hash ON devices(credential_hash);
         CREATE TABLE challenges (
            device_sign_pubkey TEXT PRIMARY KEY,
            nonce TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL
         );
         CREATE TABLE seq_high_water_marks (
            conversation_id TEXT PRIMARY KEY,
            next_seq INTEGER NOT NULL DEFAULT 0,
            acked_seq INTEGER NOT NULL DEFAULT -1
         );
         CREATE TABLE conv_events (
            conversation_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            turn_session_id TEXT NOT NULL,
            encryption_version INTEGER NOT NULL DEFAULT 0,
            payload BLOB,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (conversation_id, seq)
         );
         PRAGMA user_version = 1;",
    )
    .expect("create exact Relay v1 fixture");
    drop(conn);
    secure_fixture_database(path);
}

#[cfg(unix)]
fn secure_fixture_database(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(
        path.parent().expect("fixture database has parent"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("secure sqlite fixture parent mode");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("secure sqlite fixture mode");
}

#[cfg(not(unix))]
fn secure_fixture_database(_path: &Path) {}

#[tokio::test]
async fn fresh_migration_creates_marker_and_exact_eight_table_family() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);

    let store = open_production(&path).await;
    let snapshot = store.inspect().await.expect("inspect fresh store");

    assert_eq!(snapshot.schema_family, SCHEMA_FAMILY);
    assert_eq!(snapshot.schema_version, SCHEMA_VERSION);
    assert_ne!(snapshot.schema_signature, [0_u8; 32]);
    assert_ne!(snapshot.relay_server_id.as_bytes(), &[0_u8; 16]);
    assert_eq!(
        table_set(&snapshot),
        EXPECTED_TABLES.into_iter().collect::<BTreeSet<_>>()
    );

    store.shutdown().await.expect("shutdown fresh store");
}

#[tokio::test]
async fn reopen_preserves_relay_server_id_and_schema_marker() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);

    let first = open_production(&path).await;
    let before = first.inspect().await.expect("inspect first open");
    first.shutdown().await.expect("shutdown first open");

    let reopened = open_production(&path).await;
    let after = reopened.inspect().await.expect("inspect reopened store");

    assert_eq!(after.relay_server_id, before.relay_server_id);
    assert_eq!(after.schema_family, before.schema_family);
    assert_eq!(after.schema_version, before.schema_version);
    assert_eq!(after.schema_signature, before.schema_signature);
    assert_eq!(table_set(&after), table_set(&before));

    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn higher_schema_is_typed_reject_and_zero_write() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("higher.db");
    create_relay_meta_fixture(&path, SCHEMA_VERSION + 1, [0xa1; 32]);
    let before = file_state(&path);

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("higher schema must be rejected");

    assert!(matches!(
        error,
        StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION
        } if found == SCHEMA_VERSION + 1
    ));
    assert_eq!(file_state(&path), before);
}

#[tokio::test]
async fn exact_legacy_v1_schema_requires_explicit_reset_and_is_zero_write() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("legacy.db");
    create_exact_legacy_v1_fixture(&path);
    let before = file_state(&path);

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("legacy v1 schema must not be migrated in place");

    assert!(
        matches!(error, StoreError::LegacyV1ResetRequired),
        "unexpected exact legacy error: {error:?}"
    );
    assert_eq!(file_state(&path), before);
}

#[tokio::test]
async fn unknown_nonempty_schema_is_typed_reject_and_zero_write() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("unknown.db");
    let conn = Connection::open(&path).expect("open unknown fixture");
    conn.execute_batch(
        "CREATE TABLE mystery_state(id INTEGER PRIMARY KEY, value BLOB NOT NULL);
         INSERT INTO mystery_state(value) VALUES (x'010203');
         PRAGMA user_version = 7;",
    )
    .expect("create unknown fixture");
    drop(conn);
    secure_fixture_database(&path);
    let before = file_state(&path);

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("unknown schema must be rejected");

    assert!(matches!(error, StoreError::UnknownOrCorruptSchema));
    assert_eq!(file_state(&path), before);
}

#[tokio::test]
async fn corrupt_v2_signature_is_typed_reject_and_zero_write() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("corrupt-v2.db");
    create_relay_meta_fixture(&path, SCHEMA_VERSION, [0xff; 32]);
    let before = file_state(&path);

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("signature mismatch must be rejected");

    assert!(matches!(error, StoreError::UnknownOrCorruptSchema));
    assert_eq!(file_state(&path), before);
}

#[tokio::test]
async fn malformed_schema_marker_type_is_typed_reject_and_zero_write() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("malformed-marker.db");
    create_parent(&path);
    let conn = Connection::open(&path).expect("open malformed marker fixture");
    conn.execute_batch(
        "CREATE TABLE relay_meta (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            schema_family TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            schema_signature BLOB NOT NULL CHECK(length(schema_signature) = 32),
            relay_server_id BLOB NOT NULL CHECK(length(relay_server_id) = 16)
         );
         INSERT INTO relay_meta(
            singleton, schema_family, schema_version, schema_signature, relay_server_id
         ) VALUES (1, 'agentdeck-relay-v2', 'not-an-integer', zeroblob(32), zeroblob(16));
         PRAGMA user_version = 1;",
    )
    .expect("create malformed marker fixture");
    drop(conn);
    secure_fixture_database(&path);
    let before = file_state(&path);

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("malformed marker type must be rejected");

    assert!(matches!(error, StoreError::UnknownOrCorruptSchema));
    assert_eq!(file_state(&path), before);
}

#[tokio::test]
async fn non_database_and_truncated_database_are_typed_corrupt_and_zero_write() {
    let temp = TempDir::new().expect("tempdir");
    let random_path = temp.path().join("random-bytes.db");
    fs::write(&random_path, vec![0xa5; 4_096]).expect("write non-database fixture");
    secure_fixture_database(&random_path);

    let valid_path = temp.path().join("truncated.db");
    let conn = Connection::open(&valid_path).expect("open truncation fixture");
    conn.execute_batch(
        "CREATE TABLE relay_meta(id INTEGER PRIMARY KEY, payload BLOB NOT NULL);
         INSERT INTO relay_meta(payload) VALUES (zeroblob(8192));",
    )
    .expect("create valid database before truncation");
    drop(conn);
    fs::OpenOptions::new()
        .write(true)
        .open(&valid_path)
        .expect("open valid database for truncation")
        .set_len(100)
        .expect("truncate valid database");
    secure_fixture_database(&valid_path);

    for path in [random_path, valid_path] {
        let before = file_state(&path);
        let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
            .await
            .expect_err("invalid SQLite bytes must be typed corrupt");
        assert!(
            matches!(error, StoreError::UnknownOrCorruptSchema),
            "unexpected error for {}: {error:?}",
            path.display()
        );
        assert_eq!(file_state(&path), before);
    }
}

#[tokio::test]
async fn schema_literal_case_change_is_not_normalized_into_false_compatibility() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = open_production(&path).await;
    store.shutdown().await.expect("shutdown pristine store");

    let conn = Connection::open(&path).expect("open schema mutation fixture");
    let original: String = conn
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'machine_routes'",
            [],
            |row| row.get(0),
        )
        .expect("read machine_routes DDL");
    let changed = original.replace("'active'", "'ACTIVE'");
    assert_ne!(
        changed, original,
        "fixture must change a SQL string literal"
    );
    conn.pragma_update(None, "writable_schema", "ON")
        .expect("enable writable_schema fixture");
    conn.execute(
        "UPDATE sqlite_schema SET sql = ?1 WHERE type = 'table' AND name = 'machine_routes'",
        params![changed],
    )
    .expect("mutate SQL literal case");
    conn.pragma_update(None, "writable_schema", "OFF")
        .expect("disable writable_schema fixture");
    drop(conn);
    let before = file_state(&path);

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("semantic DDL difference must not normalize as compatible");
    assert!(matches!(error, StoreError::UnknownOrCorruptSchema));
    assert_eq!(file_state(&path), before);
}

#[tokio::test]
async fn relative_production_storage_path_is_rejected_before_creation() {
    let relative = PathBuf::from("relay-v2-relative-path-must-not-be-created.db");
    assert!(!relative.is_absolute());
    assert!(!relative.exists(), "fixture path unexpectedly exists");

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(relative.clone()))
        .await
        .expect_err("relative production path must be rejected");

    assert!(matches!(error, StoreError::PathNotAbsolute));
    assert!(!relative.exists());
}

#[tokio::test]
async fn noncanonical_absolute_storage_path_is_rejected_before_filesystem_changes() {
    let temp = TempDir::new().expect("tempdir");
    let noncanonical = temp
        .path()
        .join("never-created")
        .join("..")
        .join("relay.db");
    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(noncanonical))
        .await
        .expect_err("parent-dir alias must be rejected before path traversal");
    assert!(matches!(error, StoreError::PathNotCanonical));
    assert!(!temp.path().join("never-created").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_file_and_symlink_parent_are_both_rejected() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let real_dir = temp.path().join("real");
    fs::create_dir(&real_dir).expect("create real dir");
    let real_db = real_dir.join("relay.db");
    fs::write(&real_db, []).expect("create real db");

    let linked_file = temp.path().join("linked-file.db");
    symlink(&real_db, &linked_file).expect("create file symlink");
    let file_error = RelayStoreHandle::open(RelayV2StoreConfig::new(linked_file))
        .await
        .expect_err("symlink DB must be rejected");
    assert!(matches!(file_error, StoreError::SymlinkRejected { .. }));

    let linked_parent = temp.path().join("linked-parent");
    symlink(&real_dir, &linked_parent).expect("create parent symlink");
    let parent_error =
        RelayStoreHandle::open(RelayV2StoreConfig::new(linked_parent.join("another.db")))
            .await
            .expect_err("symlink parent must be rejected");
    assert!(matches!(parent_error, StoreError::SymlinkRejected { .. }));
}

#[cfg(unix)]
#[tokio::test]
async fn production_creation_uses_directory_0700_and_database_0600() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let parent = path.parent().expect("store parent");
    assert!(!parent.exists());

    let store = open_production(&path).await;

    assert_eq!(
        fs::metadata(parent)
            .expect("parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path)
            .expect("DB metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    store.shutdown().await.expect("shutdown permission store");
}

#[cfg(unix)]
#[tokio::test]
async fn existing_overbroad_directory_or_database_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().join("insecure");
    fs::create_dir(&parent).expect("create insecure parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))
        .expect("set insecure parent mode");
    let path = parent.join("relay.db");

    let directory_error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("overbroad parent mode must be rejected");
    assert!(matches!(
        directory_error,
        StoreError::InsecurePermissions { .. }
    ));
    assert!(!path.exists());

    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("secure parent mode");
    fs::write(&path, []).expect("create DB fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("set insecure DB mode");

    let database_error = RelayStoreHandle::open(RelayV2StoreConfig::new(path))
        .await
        .expect_err("overbroad DB mode must be rejected");
    assert!(matches!(
        database_error,
        StoreError::InsecurePermissions { .. }
    ));
}

#[tokio::test]
async fn ready_snapshot_reads_back_wal_full_foreign_keys_and_busy_timeout() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = open_production(&path).await;

    let snapshot = store.inspect().await.expect("inspect pragmas");

    assert_eq!(snapshot.journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(snapshot.synchronous, 2, "SQLite FULL must read back as 2");
    assert!(snapshot.foreign_keys);
    assert_eq!(snapshot.busy_timeout_ms, 5_000);

    store.shutdown().await.expect("shutdown pragma store");
}

// —— transaction/core contract（第二组 RED tests）——

#[tokio::test]
async fn enrollment_consumption_and_machine_insert_are_atomic_and_exact_retry_is_byte_identical() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    let seed = enrollment_seed(0x11);
    let request = register_machine_request(0x11);
    store
        .seed_enrollment_code(seed)
        .await
        .expect("seed enrollment code");

    let first = store
        .register_machine(request.clone())
        .await
        .expect("first registration");
    let retry = store
        .register_machine(request.clone())
        .await
        .expect("exact registration retry");

    assert!(!first.duplicate);
    assert!(retry.duplicate);
    assert_eq!(retry.machine_route, first.machine_route);
    assert_eq!(retry.response_blob, first.response_blob);
    assert_eq!(retry.receipt_hash, first.receipt_hash);
    assert_eq!(retry.response_blob, request.response_blob);
    assert_eq!(retry.receipt_hash, request.receipt_hash);

    let mut conflicting = request;
    conflicting.request_hash = [0xee; 32];
    let error = store
        .register_machine(conflicting)
        .await
        .expect_err("same code with a different request hash must conflict");
    assert!(matches!(error, StoreError::EnrollmentCodeConflict));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn enrollment_accepts_independent_link_and_data_certificate_generations() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    store
        .seed_enrollment_code(enrollment_seed(0x16))
        .await
        .expect("seed enrollment code");
    let mut request = register_machine_request(0x16);
    request.data_cert.generation = LinkGeneration::new(9);

    let record = store
        .register_machine(request)
        .await
        .expect("link and data certificates rotate on independent axes");
    assert_eq!(record.highest_link_generation, LinkGeneration::new(3));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn enrollment_and_revocation_control_blobs_have_hard_bounds() {
    const CONTROL_LIMIT: usize = 64 * 1024;

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    store
        .seed_enrollment_code(enrollment_seed(0x17))
        .await
        .expect("seed enrollment code");
    let mut oversized_enrollment = register_machine_request(0x17);
    oversized_enrollment.response_blob = vec![0xaa; CONTROL_LIMIT + 1];
    let enrollment_error = store
        .register_machine(oversized_enrollment)
        .await
        .expect_err("oversized frozen response must fail before consuming code");
    assert!(matches!(enrollment_error, StoreError::InvalidValue { .. }));

    store
        .register_machine(register_machine_request(0x17))
        .await
        .expect("valid retry proves code remained unconsumed");
    install_fixture_grant(&store, 0x17, 0x27, 1).await;
    let mut oversized_revocation = revocation_request(0x17, 0x27, 1);
    oversized_revocation.signed_revocation_blob = vec![0xbb; CONTROL_LIMIT + 1];
    let revocation_error = store
        .revoke(oversized_revocation)
        .await
        .expect_err("oversized signed revocation must be rejected");
    assert!(matches!(revocation_error, StoreError::InvalidValue { .. }));

    store
        .revoke(revocation_request(0x17, 0x27, 1))
        .await
        .expect("valid revocation remains possible");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn missing_or_expired_enrollment_code_cannot_create_machine() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");

    let missing = store
        .register_machine(register_machine_request(0x12))
        .await
        .expect_err("missing code must fail");
    assert!(matches!(missing, StoreError::EnrollmentCodeNotFound));

    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: [0x13; 32],
            expires_at_ms: NOW_MS - 1,
        })
        .await
        .expect("seed expired code fixture");
    let expired = store
        .register_machine(register_machine_request(0x13))
        .await
        .expect_err("expired code must fail");
    assert!(matches!(expired, StoreError::EnrollmentCodeExpired));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn register_machine_before_commit_fault_rolls_back_code_and_machine_row() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(
        &path,
        FaultPoint::RegisterMachineBeforeCommit,
    ))
    .await
    .expect("open fault-injected store");
    let request = register_machine_request(0x14);
    store
        .seed_enrollment_code(enrollment_seed(0x14))
        .await
        .expect("seed enrollment code");

    let injected = store
        .register_machine(request.clone())
        .await
        .expect_err("fault before COMMIT must surface");
    assert!(matches!(
        injected,
        StoreError::InjectedFault(FaultPoint::RegisterMachineBeforeCommit)
    ));

    let retry = store
        .register_machine(request)
        .await
        .expect("rolled-back code must remain consumable");
    assert!(!retry.duplicate);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn register_machine_after_commit_response_loss_recovers_frozen_response_after_restart() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(
        &path,
        FaultPoint::RegisterMachineAfterCommit,
    ))
    .await
    .expect("open fault-injected store");
    let request = register_machine_request(0x15);
    store
        .seed_enrollment_code(enrollment_seed(0x15))
        .await
        .expect("seed enrollment code");

    let injected = store
        .register_machine(request.clone())
        .await
        .expect_err("lost response after COMMIT must surface");
    assert!(matches!(
        injected,
        StoreError::InjectedFault(FaultPoint::RegisterMachineAfterCommit)
    ));
    store.shutdown().await.expect("shutdown first worker");

    let reopened = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("reopen committed store");
    let recovered = reopened
        .register_machine(request.clone())
        .await
        .expect("same request must recover frozen response");
    assert!(recovered.duplicate);
    assert_eq!(recovered.response_blob, request.response_blob);
    assert_eq!(recovered.receipt_hash, request.receipt_hash);
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn install_grant_is_hash_idempotent_conflicts_on_same_serial_and_accepts_higher_serial() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x21).await;

    let serial_one = install_grant_request(0x21, 0x31, 1);
    let first = store
        .install_grant(serial_one.clone())
        .await
        .expect("install first grant");
    let duplicate = store
        .install_grant(serial_one.clone())
        .await
        .expect("retry same grant");
    assert!(!first.duplicate);
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.grant_hash, first.grant_hash);

    let mut conflicting = serial_one;
    conflicting.grant_hash = [0xfa; 32];
    let conflict = store
        .install_grant(conflicting)
        .await
        .expect_err("same serial with different canonical hash must conflict");
    assert!(matches!(
        conflict,
        StoreError::IdempotencyConflict {
            field: "grant_serial"
        }
    ));

    let serial_two = install_grant_request(0x21, 0x31, 2);
    let renewed = store
        .install_grant(serial_two.clone())
        .await
        .expect("higher grant serial must replace active grant");
    assert_eq!(renewed.grant_serial, GrantSerial::new(2));
    assert_eq!(renewed.grant_hash, serial_two.grant_hash);
    assert!(!renewed.duplicate);

    let rollback = store
        .install_grant(install_grant_request(0x21, 0x31, 1))
        .await
        .expect_err("lower serial must remain rejected after renewal");
    assert!(matches!(
        rollback,
        StoreError::MonotonicRollback {
            field: "grant_serial"
        }
    ));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn install_grant_before_commit_fault_rolls_back_and_retry_inserts_once() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(
        &path,
        FaultPoint::InstallGrantBeforeCommit,
    ))
    .await
    .expect("open fault-injected store");
    seed_and_register(&store, 0x22).await;
    let request = install_grant_request(0x22, 0x32, 1);

    let injected = store
        .install_grant(request.clone())
        .await
        .expect_err("fault before grant COMMIT must surface");
    assert!(matches!(
        injected,
        StoreError::InjectedFault(FaultPoint::InstallGrantBeforeCommit)
    ));
    let retry = store
        .install_grant(request)
        .await
        .expect("rolled-back grant must insert on retry");
    assert!(!retry.duplicate);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn register_stream_starts_before_first_is_idempotent_and_rejects_route_rebinding() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x23).await;
    seed_and_register(&store, 0x24).await;
    let request = stream_registration(0x23, 0x41);

    let first = store
        .register_stream(request.clone())
        .await
        .expect("register stream");
    let duplicate = store
        .register_stream(request.clone())
        .await
        .expect("retry same stream binding");
    assert_eq!(first.high_water_seq, None, "SQLite -1 maps to BeforeFirst");
    assert_eq!(first.oldest_seq, None);
    assert_eq!(first.retained_bytes, 0);
    assert!(!first.duplicate);
    assert!(duplicate.duplicate);

    let mut generation_conflict = request.clone();
    generation_conflict.generation = stream_generation(0x99);
    let generation_error = store
        .register_stream(generation_conflict)
        .await
        .expect_err("stream route cannot change generation");
    assert!(matches!(
        generation_error,
        StoreError::StreamBindingConflict
    ));
    assert_eq!(generation_error.diagnostic_code(), "relay.store.conflict");

    let mut generation_collision = stream_registration(0x23, 0x40);
    generation_collision.generation = request.generation;
    let collision_error = store
        .register_stream(generation_collision)
        .await
        .expect_err("a generation cannot be reused by another opaque route");
    assert!(matches!(collision_error, StoreError::StreamOwnerConflict));
    assert_eq!(collision_error.diagnostic_code(), "relay.route.not_found");

    let mut owner_conflict = request;
    owner_conflict.machine_route = machine_route(0x24);
    let owner_error = store
        .register_stream(owner_conflict)
        .await
        .expect_err("stream route cannot change owner");
    assert!(matches!(owner_error, StoreError::StreamOwnerConflict));
    assert_eq!(owner_error.diagnostic_code(), "relay.route.not_found");

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn stream_and_subscription_metadata_have_principal_and_global_hard_counts() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let config = fixed_config(&path)
        .with_metadata_limits(MetadataLimits {
            max_streams_per_machine: 1,
            max_streams_global: 2,
            max_subscriptions_per_device: 2,
            max_subscriptions_global: 2,
        })
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let store = RelayStoreHandle::open(config).await.expect("open store");
    seed_and_register(&store, 0x31).await;
    let first = stream_registration(0x31, 0x50);
    store
        .register_stream(first.clone())
        .await
        .expect("first stream");
    assert!(
        store
            .register_stream(first)
            .await
            .expect("duplicate does not consume capacity")
            .duplicate
    );
    assert!(matches!(
        store.register_stream(stream_registration(0x31, 0x51)).await,
        Err(StoreError::QuotaExceeded {
            scope: "streams.machine"
        })
    ));
    store.shutdown().await.expect("shutdown store");

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let config = fixed_config(&path)
        .with_metadata_limits(MetadataLimits {
            max_streams_per_machine: 2,
            max_streams_global: 2,
            max_subscriptions_per_device: 2,
            max_subscriptions_global: 2,
        })
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let store = RelayStoreHandle::open(config).await.expect("open store");
    seed_and_register(&store, 0x32).await;
    seed_and_register(&store, 0x33).await;
    register_fixture_stream(&store, 0x32, 0x52).await;
    register_fixture_stream(&store, 0x32, 0x53).await;
    assert!(matches!(
        store.register_stream(stream_registration(0x33, 0x54)).await,
        Err(StoreError::QuotaExceeded {
            scope: "streams.global"
        })
    ));
    store.shutdown().await.expect("shutdown store");

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let config = fixed_config(&path)
        .with_metadata_limits(MetadataLimits {
            max_streams_per_machine: 3,
            max_streams_global: 3,
            max_subscriptions_per_device: 2,
            max_subscriptions_global: 2,
        })
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let store = RelayStoreHandle::open(config).await.expect("open store");
    seed_and_register(&store, 0x37).await;
    install_fixture_grant(&store, 0x37, 0x47, 1).await;
    install_fixture_grant(&store, 0x37, 0x48, 1).await;
    for stream_seed in [0x5a, 0x5b, 0x5c] {
        register_fixture_stream(&store, 0x37, stream_seed).await;
    }
    store
        .subscribe(subscription_request(
            0x37,
            0x47,
            1,
            0x5a,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("first global lease");
    store
        .subscribe(subscription_request(
            0x37,
            0x48,
            1,
            0x5b,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("second global lease");
    assert!(matches!(
        store
            .subscribe(subscription_request(
                0x37,
                0x47,
                1,
                0x5c,
                StreamCursor::BeforeFirst,
            ))
            .await,
        Err(StoreError::QuotaExceeded {
            scope: "subscriptions.global"
        })
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn disk_reserve_blocks_new_empty_stream_metadata() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let reserve = 512 * 1024 * 1024;
    let config = fixed_config(&path).with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
        available_bytes: reserve,
        total_bytes: 10 * 1024 * 1024 * 1024,
    })));
    let store = RelayStoreHandle::open(config).await.expect("open store");
    seed_and_register(&store, 0x34).await;
    assert!(matches!(
        store.register_stream(stream_registration(0x34, 0x55)).await,
        Err(StoreError::DiskSpaceLow)
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publish_requires_first_seq_zero_is_canonical_duplicate_and_rejects_conflicts() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x25).await;
    register_fixture_stream(&store, 0x25, 0x42).await;

    let out_of_order_first = store
        .publish(publish_request(0x25, 0x42, 1, 0xa0))
        .await
        .expect_err("first stream frame must be zero");
    assert!(matches!(
        out_of_order_first,
        StoreError::SequenceConflict {
            expected: 0,
            found: 1
        }
    ));

    let frame_zero = publish_request(0x25, 0x42, 0, 0xa1);
    let inserted = store
        .publish(frame_zero.clone())
        .await
        .expect("publish first frame");
    let duplicate = store
        .publish(frame_zero)
        .await
        .expect("retry canonical first frame");
    assert_eq!(inserted.disposition, PublishDisposition::Inserted);
    assert_eq!(duplicate.disposition, PublishDisposition::Duplicate);
    assert_eq!(duplicate.frame_hash, inserted.frame_hash);

    let same_seq_different_bytes = store
        .publish(publish_request(0x25, 0x42, 0, 0xa2))
        .await
        .expect_err("same seq with different canonical bytes must conflict");
    assert!(matches!(
        same_seq_different_bytes,
        StoreError::IdempotencyConflict {
            field: "stream_seq"
        }
    ));

    let gap = store
        .publish(publish_request(0x25, 0x42, 2, 0xa3))
        .await
        .expect_err("publish cannot skip seq one");
    assert!(matches!(
        gap,
        StoreError::SequenceConflict {
            expected: 1,
            found: 2
        }
    ));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn stream_operations_hide_owner_mismatch_but_preserve_generation_conflict() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open binding-classification store");
    seed_and_register(&store, 0x6d).await;
    seed_and_register(&store, 0x6e).await;
    install_fixture_grant(&store, 0x6d, 0x7d, 1).await;
    install_fixture_grant(&store, 0x6e, 0x7e, 1).await;
    register_fixture_stream(&store, 0x6d, 0x8d).await;
    store
        .publish(publish_request(0x6d, 0x8d, 0, 0x9d))
        .await
        .expect("publish binding fixture");

    let owner_publish = store
        .publish(publish_request(0x6e, 0x8d, 1, 0x9e))
        .await
        .expect_err("foreign owner cannot publish");
    let owner_subscribe = store
        .subscribe(subscription_request(
            0x6e,
            0x7e,
            1,
            0x8d,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect_err("foreign owner cannot subscribe");
    let owner_ack = store
        .ack(ack_request(0x6e, 0x7e, 1, 0x8d, 0))
        .await
        .expect_err("foreign owner cannot ACK");
    let owner_replay = store
        .replay_page(replay_request(
            0x6e,
            0x8d,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("foreign owner cannot replay");
    for error in [owner_publish, owner_subscribe, owner_ack, owner_replay] {
        assert!(matches!(error, StoreError::StreamOwnerConflict));
        assert_eq!(error.diagnostic_code(), "relay.route.not_found");
    }

    let stale_generation = stream_generation(0xfe);
    let mut generation_publish = publish_request(0x6d, 0x8d, 1, 0xae);
    match &mut generation_publish.frame.body {
        agentdeck_protocol::relay_v2::RelayFrameBody::Publish(frame) => {
            frame.generation = stale_generation;
        }
        _ => unreachable!("fixture builder always creates Publish"),
    }
    let mut generation_subscribe =
        subscription_request(0x6d, 0x7d, 1, 0x8d, StreamCursor::BeforeFirst);
    generation_subscribe.generation = stale_generation;
    let mut generation_ack = ack_request(0x6d, 0x7d, 1, 0x8d, 0);
    generation_ack.generation = stale_generation;
    let mut generation_replay =
        replay_request(0x6d, 0x8d, ReplayPosition::Start(StreamCursor::BeforeFirst));
    generation_replay.generation = stale_generation;

    let generation_errors = [
        store
            .publish(generation_publish)
            .await
            .expect_err("stale generation cannot publish"),
        store
            .subscribe(generation_subscribe)
            .await
            .expect_err("stale generation cannot subscribe"),
        store
            .ack(generation_ack)
            .await
            .expect_err("stale generation cannot ACK"),
        store
            .replay_page(generation_replay)
            .await
            .expect_err("stale generation cannot replay"),
    ];
    for error in generation_errors {
        assert!(matches!(error, StoreError::StreamBindingConflict));
        assert_eq!(error.diagnostic_code(), "relay.store.conflict");
    }

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publish_accepts_exact_four_mib_and_rejects_four_mib_plus_one_without_advancing_hwm() {
    const OUTER_OVERHEAD: usize = 53;

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open store");
    seed_and_register(&store, 0x26).await;
    register_fixture_stream(&store, 0x26, 0x43).await;

    let exact = store
        .publish(publish_request_with_len(
            0x26,
            0x43,
            0,
            0xa1,
            MAX_FRAME_BYTES - OUTER_OVERHEAD,
        ))
        .await
        .expect("exact 4 MiB canonical frame must fit");
    assert_eq!(exact.size, MAX_FRAME_BYTES as u64);
    let oversized = store
        .publish(publish_request_with_len(
            0x26,
            0x43,
            1,
            0xa2,
            MAX_FRAME_BYTES - OUTER_OVERHEAD + 1,
        ))
        .await
        .expect_err("4 MiB + 1 canonical frame must fail");
    assert!(matches!(oversized, StoreError::FrameTooLarge));
    let retry = store
        .publish(publish_request(0x26, 0x43, 1, 0xa3))
        .await
        .expect("oversized rejection must not advance HWM");
    assert_eq!(retry.stream_seq, 1);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publish_before_commit_fault_rolls_back_frame_and_high_water() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(&path, FaultPoint::PublishBeforeCommit))
        .await
        .expect("open fault-injected store");
    seed_and_register(&store, 0x26).await;
    register_fixture_stream(&store, 0x26, 0x43).await;
    let frame = publish_request(0x26, 0x43, 0, 0xb1);

    let injected = store
        .publish(frame.clone())
        .await
        .expect_err("fault before publish COMMIT must surface");
    assert!(matches!(
        injected,
        StoreError::InjectedFault(FaultPoint::PublishBeforeCommit)
    ));
    let retry = store
        .publish(frame)
        .await
        .expect("rolled-back seq zero must remain insertable");
    assert_eq!(retry.stream_seq, 0);
    assert_eq!(retry.disposition, PublishDisposition::Inserted);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn restart_replay_returns_byte_identical_sealed_blob() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x27).await;
    register_fixture_stream(&store, 0x27, 0x44).await;
    let frame = publish_request(0x27, 0x44, 0, 0xc1);
    let expected_sealed = match &frame.frame.body {
        agentdeck_protocol::relay_v2::RelayFrameBody::Publish(publish) => {
            publish.sealed_blob.0.clone()
        }
        _ => unreachable!("fixture builder always creates Publish"),
    };
    store.publish(frame).await.expect("publish retained frame");
    store.shutdown().await.expect("shutdown first worker");

    let reopened = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("reopen store");
    let page = reopened
        .replay_page(ReplayPageRequest {
            machine_route: machine_route(0x27),
            stream_route: stream_route(0x44),
            generation: stream_generation(0x45),
            position: ReplayPosition::Start(StreamCursor::BeforeFirst),
            page_max_frames: 64,
            page_max_bytes: 8 * 1024 * 1024,
        })
        .await
        .expect("replay after restart");
    assert_eq!(page.frames.len(), 1);
    assert_eq!(page.frames[0].stream_seq, 0);
    assert_eq!(page.frames[0].sealed_blob, expected_sealed);
    assert_eq!(page.replay_through, StreamCursor::At(0));
    assert!(page.next.is_none());

    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn subscription_preserves_before_first_vs_at_zero_and_ack_is_monotonic() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x28).await;
    install_fixture_grant(&store, 0x28, 0x38, 1).await;
    install_fixture_grant(&store, 0x28, 0x39, 1).await;
    register_fixture_stream(&store, 0x28, 0x45).await;
    store
        .publish(publish_request(0x28, 0x45, 0, 0xd0))
        .await
        .expect("publish seq zero");
    store
        .publish(publish_request(0x28, 0x45, 1, 0xd1))
        .await
        .expect("publish seq one");

    let before = store
        .subscribe(subscription_request(
            0x28,
            0x38,
            1,
            0x45,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("subscribe from BeforeFirst");
    let at_zero = store
        .subscribe(subscription_request(
            0x28,
            0x39,
            1,
            0x45,
            StreamCursor::At(0),
        ))
        .await
        .expect("subscribe from At(0)");
    assert_eq!(before.start, StreamCursor::BeforeFirst);
    assert_eq!(at_zero.start, StreamCursor::At(0));
    assert_eq!(before.replay_through, StreamCursor::At(1));
    assert_eq!(at_zero.replay_through, StreamCursor::At(1));

    store
        .ack(ack_request(0x28, 0x38, 1, 0x45, 1))
        .await
        .expect("advance ACK to one");
    store
        .ack(ack_request(0x28, 0x38, 1, 0x45, 0))
        .await
        .expect("lower duplicate ACK is a no-op");
    let readback = store
        .subscribe(subscription_request(
            0x28,
            0x38,
            1,
            0x45,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("read back existing lease");
    assert_eq!(readback.ack, Some(1));
    assert_eq!(readback.replay_through, StreamCursor::At(1));

    store.shutdown().await.expect("shutdown store");

    let conn = Connection::open(&path).expect("open subscription readback");
    let before_raw: Option<String> = conn
        .query_row(
            "SELECT start_cursor_seq FROM subscriptions WHERE device_route = ?1",
            params![device_route(0x38).as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("read BeforeFirst raw cursor");
    let at_zero_raw: Option<String> = conn
        .query_row(
            "SELECT start_cursor_seq FROM subscriptions WHERE device_route = ?1",
            params![device_route(0x39).as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("read At(0) raw cursor");
    assert_eq!(before_raw, None, "BeforeFirst must persist as SQL NULL");
    assert_eq!(
        at_zero_raw.as_deref(),
        Some("00000000000000000000"),
        "At(0) must remain canonical u64 text and not collapse into NULL"
    );
}

#[tokio::test]
async fn durable_subscription_rows_have_per_device_hard_count_and_duplicate_retry() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let config = fixed_config(&path)
        .with_metadata_limits(MetadataLimits {
            max_streams_per_machine: 2,
            max_streams_global: 2,
            max_subscriptions_per_device: 1,
            max_subscriptions_global: 2,
        })
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let store = RelayStoreHandle::open(config).await.expect("open store");
    seed_and_register(&store, 0x35).await;
    install_fixture_grant(&store, 0x35, 0x45, 1).await;
    register_fixture_stream(&store, 0x35, 0x56).await;
    register_fixture_stream(&store, 0x35, 0x57).await;
    let first = subscription_request(0x35, 0x45, 1, 0x56, StreamCursor::BeforeFirst);
    store
        .subscribe(first.clone())
        .await
        .expect("first durable lease");
    assert!(
        store
            .subscribe(first)
            .await
            .expect("duplicate lease at capacity remains idempotent")
            .duplicate
    );
    assert!(matches!(
        store
            .subscribe(subscription_request(
                0x35,
                0x45,
                1,
                0x57,
                StreamCursor::BeforeFirst,
            ))
            .await,
        Err(StoreError::QuotaExceeded {
            scope: "subscriptions.device"
        })
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn startup_rejects_existing_metadata_above_lowered_limits() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let healthy_disk = Arc::new(FixedDiskProbe(DiskSpace {
        available_bytes: u64::MAX,
        total_bytes: u64::MAX,
    }));
    let initial_limits = MetadataLimits {
        max_streams_per_machine: 2,
        max_streams_global: 2,
        max_subscriptions_per_device: 2,
        max_subscriptions_global: 2,
    };
    let store = RelayStoreHandle::open(
        fixed_config(&path)
            .with_metadata_limits(initial_limits)
            .with_disk_space_probe(healthy_disk.clone()),
    )
    .await
    .expect("open initial store");
    seed_and_register(&store, 0x3a).await;
    install_fixture_grant(&store, 0x3a, 0x4a, 1).await;
    register_fixture_stream(&store, 0x3a, 0x6a).await;
    register_fixture_stream(&store, 0x3a, 0x6b).await;
    for stream_seed in [0x6a, 0x6b] {
        store
            .subscribe(subscription_request(
                0x3a,
                0x4a,
                1,
                stream_seed,
                StreamCursor::BeforeFirst,
            ))
            .await
            .expect("create durable subscription");
    }
    store.shutdown().await.expect("shutdown initial store");

    let lowered_streams = MetadataLimits {
        max_streams_per_machine: 1,
        ..initial_limits
    };
    let stream_error = RelayStoreHandle::open(
        fixed_config(&path)
            .with_metadata_limits(lowered_streams)
            .with_disk_space_probe(healthy_disk.clone()),
    )
    .await
    .expect_err("existing per-machine streams must fail closed at startup");
    assert!(matches!(
        stream_error,
        StoreError::QuotaExceeded {
            scope: "streams.machine"
        }
    ));

    let lowered_subscriptions = MetadataLimits {
        max_subscriptions_per_device: 1,
        ..initial_limits
    };
    let subscription_error = RelayStoreHandle::open(
        fixed_config(&path)
            .with_metadata_limits(lowered_subscriptions)
            .with_disk_space_probe(healthy_disk),
    )
    .await
    .expect_err("existing per-device subscriptions must fail closed at startup");
    assert!(matches!(
        subscription_error,
        StoreError::QuotaExceeded {
            scope: "subscriptions.device"
        }
    ));
}

#[tokio::test]
async fn startup_rejects_existing_global_metadata_above_lowered_limits() {
    let healthy_disk = Arc::new(FixedDiskProbe(DiskSpace {
        available_bytes: u64::MAX,
        total_bytes: u64::MAX,
    }));
    let initial_limits = MetadataLimits {
        max_streams_per_machine: 2,
        max_streams_global: 2,
        max_subscriptions_per_device: 2,
        max_subscriptions_global: 2,
    };

    let stream_temp = TempDir::new().expect("tempdir");
    let stream_path = store_path(&stream_temp);
    let stream_store = RelayStoreHandle::open(
        fixed_config(&stream_path)
            .with_metadata_limits(initial_limits)
            .with_disk_space_probe(healthy_disk.clone()),
    )
    .await
    .expect("open initial stream store");
    for (machine_seed, stream_seed) in [(0x3b, 0x6c), (0x3c, 0x6d)] {
        seed_and_register(&stream_store, machine_seed).await;
        register_fixture_stream(&stream_store, machine_seed, stream_seed).await;
    }
    stream_store
        .shutdown()
        .await
        .expect("shutdown initial stream store");
    let lowered_streams = MetadataLimits {
        max_streams_per_machine: 1,
        max_streams_global: 1,
        ..initial_limits
    };
    let stream_error = RelayStoreHandle::open(
        fixed_config(&stream_path)
            .with_metadata_limits(lowered_streams)
            .with_disk_space_probe(healthy_disk.clone()),
    )
    .await
    .expect_err("existing global streams must fail closed at startup");
    assert!(matches!(
        stream_error,
        StoreError::QuotaExceeded {
            scope: "streams.global"
        }
    ));

    let subscription_temp = TempDir::new().expect("tempdir");
    let subscription_path = store_path(&subscription_temp);
    let subscription_store = RelayStoreHandle::open(
        fixed_config(&subscription_path)
            .with_metadata_limits(initial_limits)
            .with_disk_space_probe(healthy_disk.clone()),
    )
    .await
    .expect("open initial subscription store");
    seed_and_register(&subscription_store, 0x3d).await;
    for device_seed in [0x4b, 0x4c] {
        install_fixture_grant(&subscription_store, 0x3d, device_seed, 1).await;
    }
    for stream_seed in [0x6e, 0x6f] {
        register_fixture_stream(&subscription_store, 0x3d, stream_seed).await;
    }
    for (device_seed, stream_seed) in [(0x4b, 0x6e), (0x4c, 0x6f)] {
        subscription_store
            .subscribe(subscription_request(
                0x3d,
                device_seed,
                1,
                stream_seed,
                StreamCursor::BeforeFirst,
            ))
            .await
            .expect("create global durable subscription");
    }
    subscription_store
        .shutdown()
        .await
        .expect("shutdown initial subscription store");
    let lowered_subscriptions = MetadataLimits {
        max_subscriptions_per_device: 1,
        max_subscriptions_global: 1,
        ..initial_limits
    };
    let subscription_error = RelayStoreHandle::open(
        fixed_config(&subscription_path)
            .with_metadata_limits(lowered_subscriptions)
            .with_disk_space_probe(healthy_disk),
    )
    .await
    .expect_err("existing global subscriptions must fail closed at startup");
    assert!(matches!(
        subscription_error,
        StoreError::QuotaExceeded {
            scope: "subscriptions.global"
        }
    ));
}

#[tokio::test]
async fn disk_reserve_blocks_new_subscription_metadata_but_not_existing_retry() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let total = 10 * 1024 * 1024 * 1024;
    let reserve = 512 * 1024 * 1024;
    let disk = Arc::new(MutableDiskProbe::new(u64::MAX, total));
    let config = fixed_config(&path).with_disk_space_probe(disk.clone());
    let store = RelayStoreHandle::open(config).await.expect("open store");
    seed_and_register(&store, 0x36).await;
    install_fixture_grant(&store, 0x36, 0x46, 1).await;
    register_fixture_stream(&store, 0x36, 0x58).await;
    register_fixture_stream(&store, 0x36, 0x59).await;
    let existing = subscription_request(0x36, 0x46, 1, 0x58, StreamCursor::BeforeFirst);
    store
        .subscribe(existing.clone())
        .await
        .expect("create lease while disk is healthy");
    disk.set_available(reserve);
    assert!(
        store
            .subscribe(existing)
            .await
            .expect("existing lease retry consumes no metadata capacity")
            .duplicate
    );
    assert!(matches!(
        store
            .subscribe(subscription_request(
                0x36,
                0x46,
                1,
                0x59,
                StreamCursor::BeforeFirst,
            ))
            .await,
        Err(StoreError::DiskSpaceLow)
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn unsubscribe_is_exact_and_idempotent_and_releases_ack_lease() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x2c).await;
    install_fixture_grant(&store, 0x2c, 0x3d, 1).await;
    register_fixture_stream(&store, 0x2c, 0x49).await;
    store
        .publish(publish_request(0x2c, 0x49, 0, 0xa0))
        .await
        .expect("publish lease fixture");
    store
        .subscribe(subscription_request(
            0x2c,
            0x3d,
            1,
            0x49,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("create lease");
    store
        .ack(ack_request(0x2c, 0x3d, 1, 0x49, 0))
        .await
        .expect("persist lease ACK");

    let request = unsubscribe_request(0x2c, 0x3d, 1, 0x49);
    let first = store
        .unsubscribe(request.clone())
        .await
        .expect("remove exact lease");
    let duplicate = store
        .unsubscribe(request)
        .await
        .expect("repeat unsubscribe");
    assert!(first.removed);
    assert!(!duplicate.removed);

    let recreated = store
        .subscribe(subscription_request(
            0x2c,
            0x3d,
            1,
            0x49,
            StreamCursor::At(0),
        ))
        .await
        .expect("recreate lease after unsubscribe");
    assert_eq!(recreated.ack, None, "removed lease must not retain old ACK");

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn unsubscribe_immediately_stops_blocking_ack_safe_prefix_trim() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open store");
    seed_and_register(&store, 0x2d).await;
    install_fixture_grant(&store, 0x2d, 0x3e, 1).await;
    install_fixture_grant(&store, 0x2d, 0x3f, 1).await;
    register_fixture_stream(&store, 0x2d, 0x4a).await;
    store
        .publish(publish_request(0x2d, 0x4a, 0, 0xb0))
        .await
        .expect("publish seq zero");
    store
        .publish(publish_request(0x2d, 0x4a, 1, 0xb1))
        .await
        .expect("publish seq one");
    for device_seed in [0x3e, 0x3f] {
        store
            .subscribe(subscription_request(
                0x2d,
                device_seed,
                1,
                0x4a,
                StreamCursor::BeforeFirst,
            ))
            .await
            .expect("create subscription lease");
    }
    store
        .ack(ack_request(0x2d, 0x3e, 1, 0x4a, 0))
        .await
        .expect("first device ACKs seq zero");
    let still_blocked = store
        .replay_page(replay_request(
            0x2d,
            0x4a,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("unacked second lease keeps seq zero");
    assert_eq!(still_blocked.frames[0].stream_seq, 0);

    store
        .unsubscribe(unsubscribe_request(0x2d, 0x3f, 1, 0x4a))
        .await
        .expect("remove lagging lease");
    let gap = store
        .replay_page(replay_request(
            0x2d,
            0x4a,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("unsubscribe must immediately release ACK-safe prefix");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn ack_and_unsubscribe_only_maintain_the_affected_stream_and_skip_noops() {
    const UNRELATED_SENTINEL: i64 = 7_777_777;

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open scoped-maintenance store");
    seed_and_register(&store, 0x2e).await;
    install_fixture_grant(&store, 0x2e, 0x40, 1).await;
    install_fixture_grant(&store, 0x2e, 0x41, 1).await;
    register_fixture_stream(&store, 0x2e, 0x4b).await;
    register_fixture_stream(&store, 0x2e, 0x4c).await;
    store
        .publish(publish_request(0x2e, 0x4b, 0, 0xc0))
        .await
        .expect("publish target stream frame");
    store
        .publish(publish_request(0x2e, 0x4c, 0, 0xc1))
        .await
        .expect("publish unrelated stream frame");
    for device_seed in [0x40, 0x41] {
        store
            .subscribe(subscription_request(
                0x2e,
                device_seed,
                1,
                0x4b,
                StreamCursor::BeforeFirst,
            ))
            .await
            .expect("create target stream lease");
    }

    // retained_bytes sentinel 是一个确定性的路径探针：旧实现每次 ACK/Unsubscribe 都会
    // UPDATE 全部 streams，从而把这个无关 stream 恢复成真实值。scoped helper 不应触碰它。
    let unrelated = stream_route(0x4c);
    overwrite_retained_bytes_for_probe(&path, unrelated, UNRELATED_SENTINEL);

    store
        .ack(ack_request(0x2e, 0x40, 1, 0x4b, 0))
        .await
        .expect("advance target ACK");
    assert_eq!(
        retained_bytes_for_probe(&path, unrelated),
        UNRELATED_SENTINEL,
        "advancing ACK must not run global stream maintenance"
    );
    store
        .ack(ack_request(0x2e, 0x40, 1, 0x4b, 0))
        .await
        .expect("duplicate target ACK");
    assert_eq!(
        retained_bytes_for_probe(&path, unrelated),
        UNRELATED_SENTINEL,
        "duplicate ACK must skip maintenance entirely"
    );

    let request = unsubscribe_request(0x2e, 0x41, 1, 0x4b);
    assert!(
        store
            .unsubscribe(request.clone())
            .await
            .expect("remove blocking target lease")
            .removed
    );
    assert_eq!(
        retained_bytes_for_probe(&path, unrelated),
        UNRELATED_SENTINEL,
        "removed lease must only maintain its target stream"
    );
    assert!(
        !store
            .unsubscribe(request)
            .await
            .expect("repeat target unsubscribe")
            .removed
    );
    assert_eq!(
        retained_bytes_for_probe(&path, unrelated),
        UNRELATED_SENTINEL,
        "no-op unsubscribe must skip maintenance entirely"
    );

    let gap = store
        .replay_page(replay_request(
            0x2e,
            0x4b,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("removing the blocker still trims the target prefix");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));

    store
        .shutdown()
        .await
        .expect("shutdown scoped-maintenance store");
}

#[tokio::test]
async fn renewed_grant_serial_does_not_inherit_old_subscription_ack_lease() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x29).await;
    install_fixture_grant(&store, 0x29, 0x3a, 1).await;
    register_fixture_stream(&store, 0x29, 0x46).await;
    store
        .publish(publish_request(0x29, 0x46, 0, 0xe0))
        .await
        .expect("publish seq zero");
    store
        .subscribe(subscription_request(
            0x29,
            0x3a,
            1,
            0x46,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("subscribe old principal");
    store
        .ack(ack_request(0x29, 0x3a, 1, 0x46, 0))
        .await
        .expect("ack old principal");

    store
        .install_grant(install_grant_request(0x29, 0x3a, 2))
        .await
        .expect("renew grant serial");
    let renewed_lease = store
        .subscribe(subscription_request(
            0x29,
            0x3a,
            2,
            0x46,
            StreamCursor::At(0),
        ))
        .await
        .expect("subscribe renewed principal");
    assert_eq!(renewed_lease.ack, None);
    assert_eq!(renewed_lease.start, StreamCursor::At(0));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn revoke_is_idempotent_and_blocks_further_grant_scoped_operations() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x2a).await;
    install_fixture_grant(&store, 0x2a, 0x3b, 1).await;
    register_fixture_stream(&store, 0x2a, 0x47).await;
    let request = revocation_request(0x2a, 0x3b, 1);

    let first = store
        .revoke(request.clone())
        .await
        .expect("commit revocation");
    let duplicate = store
        .revoke(request.clone())
        .await
        .expect("retry same revocation");
    assert!(!first.duplicate);
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.revocation_hash, request.revocation_hash);
    assert_eq!(
        duplicate.signed_revocation_blob,
        request.signed_revocation_blob
    );

    let subscribe_error = store
        .subscribe(subscription_request(
            0x2a,
            0x3b,
            1,
            0x47,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect_err("revoked grant cannot create a lease");
    assert!(matches!(subscribe_error, StoreError::Revoked));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn revoked_device_route_cannot_be_reinstalled_with_same_or_higher_serial() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x2e).await;
    let original = install_fixture_grant(&store, 0x2e, 0x4e, 1).await;
    store
        .revoke(revocation_request(0x2e, 0x4e, 1))
        .await
        .expect("revoke device route");

    for request in [original, install_grant_request(0x2e, 0x4e, 2)] {
        let error = store
            .install_grant(request)
            .await
            .expect_err("revoked device route remains terminal until machine purge");
        assert!(matches!(error, StoreError::Revoked));
    }

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn empty_and_future_stream_cursors_are_rejected_in_subscribe_and_replay() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open store");
    seed_and_register(&store, 0x2f).await;
    install_fixture_grant(&store, 0x2f, 0x4f, 1).await;
    register_fixture_stream(&store, 0x2f, 0x50).await;

    let empty_subscribe = store
        .subscribe(subscription_request(
            0x2f,
            0x4f,
            1,
            0x50,
            StreamCursor::At(0),
        ))
        .await
        .expect_err("empty stream has no valid At cursor");
    assert!(matches!(empty_subscribe, StoreError::InvalidReplayCursor));
    let empty_replay = store
        .replay_page(replay_request(
            0x2f,
            0x50,
            ReplayPosition::Start(StreamCursor::At(0)),
        ))
        .await
        .expect_err("empty stream replay must reject future cursor");
    assert!(matches!(empty_replay, StoreError::InvalidReplayCursor));

    store
        .publish(publish_request(0x2f, 0x50, 0, 0xc0))
        .await
        .expect("publish seq zero");
    for cursor in [StreamCursor::At(1), StreamCursor::At(u64::MAX)] {
        let error = store
            .replay_page(replay_request(0x2f, 0x50, ReplayPosition::Start(cursor)))
            .await
            .expect_err("replay must not silently roll a future cursor backwards");
        assert!(matches!(error, StoreError::InvalidReplayCursor));
    }

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn purge_machine_retires_route_and_reads_back_all_active_data_empty() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("open store");
    seed_and_register(&store, 0x2b).await;
    install_fixture_grant(&store, 0x2b, 0x3c, 1).await;
    register_fixture_stream(&store, 0x2b, 0x48).await;
    store
        .publish(publish_request(0x2b, 0x48, 0, 0xf0))
        .await
        .expect("publish purge fixture");
    store
        .subscribe(subscription_request(
            0x2b,
            0x3c,
            1,
            0x48,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("subscribe purge fixture");
    store
        .revoke(revocation_request(0x2b, 0x3c, 1))
        .await
        .expect("revoke purge fixture");

    let readback = store
        .purge_machine(PurgeMachine {
            machine_route: machine_route(0x2b),
        })
        .await
        .expect("purge machine");
    assert_eq!(readback.active_machine_routes, 0);
    assert_eq!(readback.retired_tombstones, 1);
    assert_eq!(readback.device_grants, 0);
    assert_eq!(readback.revocations, 0);
    assert_eq!(readback.streams, 0);
    assert_eq!(readback.frames, 0);
    assert_eq!(readback.subscriptions, 0);

    store.shutdown().await.expect("shutdown store");
}

// —— quota / replay / full-u64 / immutable-WAL contract（第三组 RED tests）——

#[tokio::test]
async fn per_stream_count_limit_evicts_oldest_and_reports_gap() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let limits = RetentionLimits {
        max_frames_per_stream: 2,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits))
        .await
        .expect("open count-limited store");
    seed_and_register(&store, 0x51).await;
    register_fixture_stream(&store, 0x51, 0x61).await;

    for seq in 0..3 {
        store
            .publish(publish_request(0x51, 0x61, seq, seq as u8))
            .await
            .expect("publish count fixture");
    }

    let gap = store
        .replay_page(replay_request(
            0x51,
            0x61,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("evicted seq zero must produce a gap");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    let retained = store
        .replay_page(replay_request(
            0x51,
            0x61,
            ReplayPosition::Start(StreamCursor::At(0)),
        ))
        .await
        .expect("replay retained count window");
    assert_eq!(
        retained
            .frames
            .iter()
            .map(|frame| frame.stream_seq)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn per_stream_byte_limit_trims_oldest_but_rejects_single_frame_larger_than_cap_atomically() {
    let temp = TempDir::new().expect("tempdir");
    let trim_path = temp.path().join("trim").join("relay.db");
    let first = publish_request_with_len(0x52, 0x62, 0, 0x11, 256);
    let frame_size = u64::try_from(first.canonical_bytes().expect("encode fixture").len())
        .expect("fixture size fits u64");
    let trim_limits = RetentionLimits {
        max_bytes_per_stream: frame_size * 2 - 1,
        ..limits_without_disk_gate()
    };
    let trim_store = RelayStoreHandle::open(config_with_limits(&trim_path, trim_limits))
        .await
        .expect("open byte-limited store");
    seed_and_register(&trim_store, 0x52).await;
    register_fixture_stream(&trim_store, 0x52, 0x62).await;
    trim_store
        .publish(first)
        .await
        .expect("publish first frame");
    trim_store
        .publish(publish_request_with_len(0x52, 0x62, 1, 0x12, 256))
        .await
        .expect("publish second frame and trim first");
    let gap = trim_store
        .replay_page(replay_request(
            0x52,
            0x62,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("byte trim must expose gap");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    trim_store.shutdown().await.expect("shutdown trim store");

    let reject_path = temp.path().join("reject").join("relay.db");
    let oversized = publish_request_with_len(0x53, 0x63, 0, 0x21, 512);
    let oversized_size = u64::try_from(
        oversized
            .canonical_bytes()
            .expect("encode oversized fixture")
            .len(),
    )
    .expect("fixture size fits u64");
    let reject_limits = RetentionLimits {
        max_bytes_per_stream: oversized_size - 1,
        ..limits_without_disk_gate()
    };
    let reject_store = RelayStoreHandle::open(config_with_limits(&reject_path, reject_limits))
        .await
        .expect("open rejecting store");
    seed_and_register(&reject_store, 0x53).await;
    register_fixture_stream(&reject_store, 0x53, 0x63).await;
    let rejected = reject_store
        .publish(oversized.clone())
        .await
        .expect_err("single frame beyond stream cap must reject");
    assert!(matches!(rejected, StoreError::QuotaExceeded { .. }));
    reject_store
        .shutdown()
        .await
        .expect("shutdown rejecting store");

    let reopened =
        RelayStoreHandle::open(config_with_limits(&reject_path, limits_without_disk_gate()))
            .await
            .expect("reopen without tiny cap");
    let committed = reopened
        .publish(oversized)
        .await
        .expect("rejected frame must not advance high-water");
    assert_eq!(committed.stream_seq, 0);
    assert_eq!(committed.disposition, PublishDisposition::Inserted);
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn age_limit_is_applied_by_later_publish_and_exposes_gap() {
    const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let limits = RetentionLimits {
        max_age_ms: DAY_MS,
        ..limits_without_disk_gate()
    };
    let first = RelayStoreHandle::open(config_with_limits(&path, limits))
        .await
        .expect("open age-limited store");
    seed_and_register(&first, 0x54).await;
    register_fixture_stream(&first, 0x54, 0x64).await;
    first
        .publish(publish_request(0x54, 0x64, 0, 0x31))
        .await
        .expect("publish old frame");
    first.shutdown().await.expect("shutdown first worker");

    let aged_config = RelayV2StoreConfig::new(path.clone())
        .with_retention(limits)
        .with_clock(Arc::new(FixedClock(NOW_MS + DAY_MS + 1)))
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let aged = RelayStoreHandle::open(aged_config)
        .await
        .expect("reopen aged store");
    aged.publish(publish_request(0x54, 0x64, 1, 0x32))
        .await
        .expect("later publish triggers age retention");
    let gap = aged
        .replay_page(replay_request(
            0x54,
            0x64,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("expired frame must produce gap");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    aged.shutdown().await.expect("shutdown aged store");
}

#[tokio::test]
async fn per_machine_byte_limit_evicts_oldest_across_streams() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let sample = publish_request(0x55, 0x65, 0, 0x41);
    let frame_size = u64::try_from(sample.canonical_bytes().expect("encode sample").len())
        .expect("sample size fits u64");
    let limits = RetentionLimits {
        max_bytes_per_machine: frame_size * 2,
        ..limits_without_disk_gate()
    };
    let clock = Arc::new(MutableClock::new(NOW_MS));
    let config = RelayV2StoreConfig::new(path.clone())
        .with_retention(limits)
        .with_clock(clock.clone())
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let store = RelayStoreHandle::open(config)
        .await
        .expect("open machine-limited store");
    seed_and_register(&store, 0x55).await;
    register_fixture_stream(&store, 0x55, 0x65).await;
    register_fixture_stream(&store, 0x55, 0x66).await;

    store.publish(sample).await.expect("publish oldest frame");
    clock.set(NOW_MS + 1);
    store
        .publish(publish_request(0x55, 0x66, 0, 0x42))
        .await
        .expect("publish second stream frame");
    clock.set(NOW_MS + 2);
    store
        .publish(publish_request(0x55, 0x65, 1, 0x43))
        .await
        .expect("publish third machine frame");

    let first_stream_gap = store
        .replay_page(replay_request(
            0x55,
            0x65,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("oldest frame across machine must be evicted");
    assert!(matches!(
        first_stream_gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    let second_stream = store
        .replay_page(replay_request(
            0x55,
            0x66,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("newer other-stream frame remains");
    assert_eq!(second_stream.frames[0].stream_seq, 0);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn machine_quota_same_millisecond_keeps_new_low_route_frame() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let frame_size = publish_request(0x60, 0xf0, 0, 0x41)
        .canonical_bytes()
        .expect("encode sample")
        .len() as u64;
    let limits = RetentionLimits {
        max_bytes_per_machine: frame_size * 2,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits))
        .await
        .expect("open machine-limited store");
    seed_and_register(&store, 0x60).await;
    register_fixture_stream(&store, 0x60, 0xf0).await;
    register_fixture_stream(&store, 0x60, 0x01).await;
    store
        .publish(publish_request(0x60, 0xf0, 0, 0x41))
        .await
        .expect("publish oldest high-route frame");
    store
        .publish(publish_request(0x60, 0xf0, 1, 0x42))
        .await
        .expect("publish second high-route frame");
    store
        .publish(publish_request(0x60, 0x01, 0, 0x43))
        .await
        .expect("publish newest low-route frame");

    let new_route = store
        .replay_page(replay_request(
            0x60,
            0x01,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("newly inserted frame must survive quota transaction");
    assert_eq!(new_route.frames[0].stream_seq, 0);
    let old_gap = store
        .replay_page(replay_request(
            0x60,
            0xf0,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("oldest insertion must be evicted on timestamp tie");
    assert!(matches!(
        old_gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn global_byte_limit_evicts_oldest_across_machines() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let sample = publish_request(0x56, 0x67, 0, 0x51);
    let frame_size = u64::try_from(sample.canonical_bytes().expect("encode sample").len())
        .expect("sample size fits u64");
    let limits = RetentionLimits {
        max_bytes_global: frame_size * 2,
        ..limits_without_disk_gate()
    };
    let clock = Arc::new(MutableClock::new(NOW_MS));
    let config = RelayV2StoreConfig::new(path.clone())
        .with_retention(limits)
        .with_clock(clock.clone())
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let store = RelayStoreHandle::open(config)
        .await
        .expect("open global-limited store");
    seed_and_register(&store, 0x56).await;
    seed_and_register(&store, 0x57).await;
    register_fixture_stream(&store, 0x56, 0x67).await;
    register_fixture_stream(&store, 0x57, 0x68).await;

    store.publish(sample).await.expect("publish global oldest");
    clock.set(NOW_MS + 1);
    store
        .publish(publish_request(0x57, 0x68, 0, 0x52))
        .await
        .expect("publish second machine frame");
    clock.set(NOW_MS + 2);
    store
        .publish(publish_request(0x57, 0x68, 1, 0x53))
        .await
        .expect("publish third global frame");

    let evicted_machine = store
        .replay_page(replay_request(
            0x56,
            0x67,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("globally oldest frame must be evicted");
    assert!(matches!(
        evicted_machine,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    let retained_machine = store
        .replay_page(replay_request(
            0x57,
            0x68,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("newer machine frames remain");
    assert_eq!(retained_machine.frames.len(), 2);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn global_quota_same_millisecond_keeps_new_low_route_frame() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let frame_size = publish_request(0x61, 0xf2, 0, 0x51)
        .canonical_bytes()
        .expect("encode sample")
        .len() as u64;
    let limits = RetentionLimits {
        max_bytes_global: frame_size * 2,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits))
        .await
        .expect("open global-limited store");
    seed_and_register(&store, 0x61).await;
    seed_and_register(&store, 0x62).await;
    register_fixture_stream(&store, 0x61, 0xf2).await;
    register_fixture_stream(&store, 0x62, 0x02).await;
    store
        .publish(publish_request(0x61, 0xf2, 0, 0x51))
        .await
        .expect("publish globally oldest frame");
    store
        .publish(publish_request(0x61, 0xf2, 1, 0x52))
        .await
        .expect("publish global second frame");
    store
        .publish(publish_request(0x62, 0x02, 0, 0x53))
        .await
        .expect("publish newest low-route frame");

    let new_route = store
        .replay_page(replay_request(
            0x62,
            0x02,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("new globally inserted frame must survive quota transaction");
    assert_eq!(new_route.frames[0].stream_seq, 0);
    let old_gap = store
        .replay_page(replay_request(
            0x61,
            0xf2,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("globally oldest insertion must be evicted on timestamp tie");
    assert!(matches!(
        old_gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn projected_disk_reserve_uses_max_of_absolute_and_percent_but_control_writes_remain_available()
 {
    const GIB: u64 = 1024 * 1024 * 1024;

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let frame = publish_request(0x58, 0x69, 0, 0x61);
    let frame_size = u64::try_from(frame.canonical_bytes().expect("encode frame").len())
        .expect("frame size fits u64");
    let limits = RetentionLimits::default();
    assert_eq!(limits.disk_reserve_for(GIB), 512 * 1024 * 1024);
    assert_eq!(limits.disk_reserve_for(20 * GIB), GIB);
    let disk = Arc::new(MutableDiskProbe::new(u64::MAX, 20 * GIB));
    let config = RelayV2StoreConfig::new(path.clone())
        .with_clock(Arc::new(FixedClock(NOW_MS)))
        .with_disk_space_probe(disk.clone());
    let store = RelayStoreHandle::open(config)
        .await
        .expect("open disk-gated store");
    seed_and_register(&store, 0x58).await;
    install_fixture_grant(&store, 0x58, 0x39, 1).await;
    register_fixture_stream(&store, 0x58, 0x69).await;
    disk.set_available(GIB + frame_size - 1);

    let disk_low = store
        .publish(frame)
        .await
        .expect_err("projected post-write space below reserve must reject");
    assert!(matches!(disk_low, StoreError::DiskSpaceLow));
    let empty = store
        .replay_page(replay_request(
            0x58,
            0x69,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("read remains available under disk-low");
    assert!(empty.frames.is_empty());
    store
        .revoke(revocation_request(0x58, 0x39, 1))
        .await
        .expect("revocation control write remains available under disk-low");
    let purged = store
        .purge_machine(PurgeMachine {
            machine_route: machine_route(0x58),
        })
        .await
        .expect("purge remains available under disk-low");
    assert_eq!(purged.active_machine_routes, 0);
    assert_eq!(purged.retired_tombstones, 1);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn disk_low_allows_byte_identical_publish_retry_but_rejects_new_frame() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let frame = publish_request(0x5f, 0x70, 0, 0x81);
    let first = RelayStoreHandle::open(fixed_config(&path).with_disk_space_probe(Arc::new(
        FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        }),
    )))
    .await
    .expect("open initial store");
    seed_and_register(&first, 0x5f).await;
    register_fixture_stream(&first, 0x5f, 0x70).await;
    first
        .publish(frame.clone())
        .await
        .expect("persist original frame");
    first.shutdown().await.expect("shutdown initial store");

    let disk_low = RelayStoreHandle::open(fixed_config(&path).with_disk_space_probe(Arc::new(
        FixedDiskProbe(DiskSpace {
            available_bytes: 0,
            total_bytes: 0,
        }),
    )))
    .await
    .expect("reopen disk-low store");
    let duplicate = disk_low
        .publish(frame)
        .await
        .expect("already-persisted canonical frame consumes no new disk");
    assert_eq!(duplicate.disposition, PublishDisposition::Duplicate);
    let rejected = disk_low
        .publish(publish_request(0x5f, 0x70, 1, 0x82))
        .await
        .expect_err("new frame remains blocked under disk-low");
    assert!(matches!(rejected, StoreError::DiskSpaceLow));

    disk_low.shutdown().await.expect("shutdown disk-low store");
}

#[tokio::test]
async fn replay_sixty_five_small_frames_is_strictly_paginated_sixty_four_plus_one() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open replay store");
    seed_and_register(&store, 0x59).await;
    register_fixture_stream(&store, 0x59, 0x6a).await;

    for seq in 0..65 {
        store
            .publish(publish_request(0x59, 0x6a, seq, seq as u8))
            .await
            .expect("publish replay fixture");
    }

    let first = store
        .replay_page(replay_request(
            0x59,
            0x6a,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("first replay page");
    assert_eq!(first.frames.len(), 64);
    assert_eq!(first.frames.first().expect("first frame").stream_seq, 0);
    assert_eq!(first.frames.last().expect("last frame").stream_seq, 63);
    assert_eq!(first.replay_through, StreamCursor::At(64));
    let continuation = first.next.expect("65th frame requires continuation");

    let second = store
        .replay_page(replay_request(
            0x59,
            0x6a,
            ReplayPosition::Continue(continuation),
        ))
        .await
        .expect("second replay page");
    assert_eq!(second.frames.len(), 1);
    assert_eq!(second.frames[0].stream_seq, 64);
    assert_eq!(second.replay_through, StreamCursor::At(64));
    assert!(second.next.is_none());

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn replay_three_three_mib_frames_obeys_eight_mib_page_cap_as_two_plus_one() {
    const THREE_MIB: usize = 3 * 1024 * 1024;

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open replay byte-cap store");
    seed_and_register(&store, 0x5a).await;
    register_fixture_stream(&store, 0x5a, 0x6b).await;
    for seq in 0..3 {
        store
            .publish(publish_request_with_len(
                0x5a, 0x6b, seq, seq as u8, THREE_MIB,
            ))
            .await
            .expect("publish large replay fixture");
    }

    let first = store
        .replay_page(replay_request(
            0x5a,
            0x6b,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("first large replay page");
    assert_eq!(first.frames.len(), 2);
    assert!(first.frames.iter().map(|frame| frame.size).sum::<u64>() <= 8 * 1024 * 1024);
    let continuation = first.next.expect("third large frame requires continuation");
    let second = store
        .replay_page(replay_request(
            0x5a,
            0x6b,
            ReplayPosition::Continue(continuation),
        ))
        .await
        .expect("second large replay page");
    assert_eq!(second.frames.len(), 1);
    assert_eq!(second.frames[0].stream_seq, 2);
    assert!(second.frames[0].size <= 8 * 1024 * 1024);
    assert!(second.next.is_none());

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn replay_continuation_freezes_through_and_does_not_extend_to_new_publish() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let limits = RetentionLimits {
        replay_page_max_frames: 2,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits))
        .await
        .expect("open fixed-through replay store");
    seed_and_register(&store, 0x5b).await;
    register_fixture_stream(&store, 0x5b, 0x6c).await;
    for seq in 0..3 {
        store
            .publish(publish_request(0x5b, 0x6c, seq, seq as u8))
            .await
            .expect("publish initial snapshot frame");
    }

    let first = store
        .replay_page(replay_request(
            0x5b,
            0x6c,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("first snapshot page");
    assert_eq!(first.replay_through, StreamCursor::At(2));
    let continuation = first.next.expect("snapshot needs continuation");
    store
        .publish(publish_request(0x5b, 0x6c, 3, 0x73))
        .await
        .expect("publish after replay snapshot started");

    let second = store
        .replay_page(replay_request(
            0x5b,
            0x6c,
            ReplayPosition::Continue(continuation),
        ))
        .await
        .expect("continue frozen snapshot");
    assert_eq!(
        second
            .frames
            .iter()
            .map(|frame| frame.stream_seq)
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert_eq!(second.replay_through, StreamCursor::At(2));
    assert!(second.next.is_none());

    let live_tail = store
        .replay_page(replay_request(
            0x5b,
            0x6c,
            ReplayPosition::Start(StreamCursor::At(2)),
        ))
        .await
        .expect("new replay can observe later publish");
    assert_eq!(live_tail.frames[0].stream_seq, 3);
    assert_eq!(live_tail.replay_through, StreamCursor::At(3));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn replay_continuation_returns_gap_if_next_frame_is_evicted_between_pages() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let limits = RetentionLimits {
        max_frames_per_stream: 3,
        replay_page_max_frames: 2,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits))
        .await
        .expect("open eviction replay store");
    seed_and_register(&store, 0x5c).await;
    register_fixture_stream(&store, 0x5c, 0x6d).await;
    for seq in 0..3 {
        store
            .publish(publish_request(0x5c, 0x6d, seq, seq as u8))
            .await
            .expect("publish initial retention window");
    }
    let first = store
        .replay_page(replay_request(
            0x5c,
            0x6d,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("first replay page");
    let continuation = first.next.expect("first page has continuation at seq two");

    for seq in 3..6 {
        store
            .publish(publish_request(0x5c, 0x6d, seq, seq as u8))
            .await
            .expect("publish frames that evict continuation target");
    }
    let gap = store
        .replay_page(replay_request(
            0x5c,
            0x6d,
            ReplayPosition::Continue(continuation),
        ))
        .await
        .expect_err("evicted continuation target must return gap");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 2,
            oldest: 3
        }
    ));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn canonical_text_sequence_persists_u64_max_minus_one_and_refuses_max_without_wrap() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let first = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open u64 store");
    seed_and_register(&first, 0x5d).await;
    register_fixture_stream(&first, 0x5d, 0x6e).await;
    first.shutdown().await.expect("shutdown before raw fixture");

    let max_minus_two = u64::MAX - 2;
    let conn = Connection::open(&path).expect("open raw u64 fixture");
    let updated = conn
        .execute(
            "UPDATE streams SET high_water_seq = ?1
             WHERE stream_route = ?2 AND generation = ?3",
            params![
                format!("{max_minus_two:020}"),
                stream_route(0x6e).as_bytes().as_slice(),
                stream_generation(0x6f).as_bytes().as_slice()
            ],
        )
        .expect("seed canonical high-water text");
    assert_eq!(updated, 1);
    drop(conn);

    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("reopen u64 store");
    let max_minus_one = store
        .publish(publish_request(0x5d, 0x6e, u64::MAX - 1, 0x81))
        .await
        .expect("u64::MAX-1 must persist");
    assert_eq!(max_minus_one.stream_seq, u64::MAX - 1);
    let replay = store
        .replay_page(replay_request(
            0x5d,
            0x6e,
            ReplayPosition::Start(StreamCursor::At(u64::MAX - 2)),
        ))
        .await
        .expect("replay u64::MAX-1");
    assert_eq!(replay.frames[0].stream_seq, u64::MAX - 1);

    let exhausted = store
        .publish(publish_request(0x5d, 0x6e, u64::MAX, 0x82))
        .await
        .expect_err("u64::MAX must require a new random generation");
    assert!(matches!(
        exhausted,
        StoreError::InvalidValue {
            field: "stream_seq",
            ..
        }
    ));
    assert!(
        exhausted.to_string().contains("new stream generation"),
        "typed exhaustion must direct the caller to create a new generation"
    );
    store.shutdown().await.expect("shutdown u64 store");

    let conn = Connection::open(&path).expect("open u64 readback");
    let high_water: String = conn
        .query_row(
            "SELECT high_water_seq FROM streams WHERE stream_route = ?1",
            params![stream_route(0x6e).as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("read u64 high-water");
    assert_eq!(high_water, format!("{:020}", u64::MAX - 1));
}

#[tokio::test]
async fn hot_wal_higher_schema_inspection_is_typed_and_byte_immutable() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("hot-higher.db");
    create_relay_meta_fixture(&path, SCHEMA_VERSION + 1, [0xa1; 32]);
    let writer = Connection::open(&path).expect("open higher WAL writer");
    writer
        .pragma_update(None, "journal_mode", "WAL")
        .expect("enable higher WAL");
    writer
        .pragma_update(None, "wal_autocheckpoint", 0)
        .expect("disable higher autocheckpoint");
    writer
        .execute(
            "UPDATE relay_meta SET relay_server_id = ?1 WHERE singleton = 1",
            params![[0x5b_u8; 16].as_slice()],
        )
        .expect("write higher hot WAL frame");
    let before = full_sqlite_state(&path);
    assert!(before.wal.is_some(), "fixture must have a WAL sidecar");
    assert!(before.shm.is_some(), "fixture must have a SHM sidecar");

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("hot-WAL higher schema must be rejected");
    assert!(matches!(
        error,
        StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION
        } if found == SCHEMA_VERSION + 1
    ));
    assert_full_sqlite_state_unchanged(&path, &before);
    drop(writer);
}

#[tokio::test]
async fn schema_and_user_version_only_in_hot_wal_are_detected_without_source_write() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("schema-only-hot-wal.db");
    let writer = create_higher_schema_only_in_wal(&path);
    let before = full_sqlite_state(&path);
    assert!(before.wal.is_some(), "fixture must have a WAL sidecar");
    assert!(before.shm.is_some(), "fixture must have a SHM sidecar");

    let immutable_uri = format!("file:{}?mode=ro&immutable=1", path.display());
    let immutable = Connection::open_with_flags(
        immutable_uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open fixture main DB as immutable");
    let main_user_version: i64 = immutable
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read main-only user_version");
    let main_tables: i64 = immutable
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table'",
            [],
            |row| row.get(0),
        )
        .expect("read main-only table count");
    assert_eq!(
        main_user_version, 0,
        "schema version must exist only in WAL"
    );
    assert_eq!(main_tables, 0, "schema objects must exist only in WAL");
    drop(immutable);

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("schema-only higher WAL must be rejected before source RW open");
    assert!(
        matches!(
            &error,
            StoreError::SchemaTooNew {
                found: 2,
                supported: SCHEMA_VERSION
            }
        ),
        "unexpected schema-only WAL error: {error:?}"
    );
    assert_full_sqlite_state_unchanged(&path, &before);
    drop(writer);
}

#[tokio::test]
async fn hot_wal_snapshot_copy_preflight_fails_closed_without_source_write_or_residue() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("disk-low-hot-wal.db");
    let writer = create_higher_schema_only_in_wal(&path);
    let before = full_sqlite_state(&path);
    assert!(before.wal.is_some(), "fixture must have a WAL sidecar");
    assert!(before.shm.is_some(), "fixture must have a SHM sidecar");

    let config = RelayV2StoreConfig::new(path.clone()).with_disk_space_probe(Arc::new(
        FixedDiskProbe(DiskSpace {
            available_bytes: 0,
            total_bytes: 1,
        }),
    ));
    let error = RelayStoreHandle::open(config)
        .await
        .expect_err("snapshot copy must honor disk reserve before creating temp files");
    assert!(matches!(error, StoreError::DiskSpaceLow));
    assert_full_sqlite_state_unchanged(&path, &before);
    let residues = fs::read_dir(temp.path())
        .expect("list fixture directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".agentdeck-relay-schema-inspect-")
        })
        .count();
    assert_eq!(
        residues, 0,
        "failed preflight must leave no snapshot directory"
    );
    drop(writer);
}

#[cfg(unix)]
#[tokio::test]
async fn hot_wal_restart_cleans_only_unlocked_exactly_marked_snapshot_artifacts() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical temp root");
    let path = root.join("stale-cleanup-hot-wal.db");
    let writer = create_higher_schema_only_in_wal(&path);
    let source_before = full_sqlite_state(&path);
    let valid_marker = snapshot_marker_bytes(&path);

    let stale = create_crash_snapshot_fixture(&root, "stale", &valid_marker, false);
    let guarded = create_crash_snapshot_fixture(&root, "guarded", &valid_marker, true);
    let wrong = create_crash_snapshot_fixture(&root, "wrong", b"not-our-marker", false);
    let active = create_crash_snapshot_fixture(&root, "active", &valid_marker, false);
    let active_marker = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(active.join(".agentdeck-schema-snapshot-v1"))
        .expect("open active marker");
    active_marker
        .lock_exclusive()
        .expect("lock active snapshot marker");
    let symlink_target = root.join("user-snapshot-like-directory");
    fs::create_dir(&symlink_target).expect("create symlink target");
    let snapshot_symlink = root.join(".agentdeck-relay-schema-inspect-symlink");
    symlink(&symlink_target, &snapshot_symlink).expect("create snapshot-like symlink");

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("higher schema remains rejected after stale cleanup");
    assert!(
        matches!(error, StoreError::SchemaTooNew { .. }),
        "unexpected cleanup/open error: {error:?}"
    );
    assert!(
        !stale.exists(),
        "trusted unlocked crash artifact is reclaimed"
    );
    assert!(
        guarded.exists(),
        "unexpected child prevents any recursive cleanup"
    );
    assert!(wrong.exists(), "wrong marker is never treated as ours");
    assert!(active.exists(), "advisory lock protects an active snapshot");
    assert!(
        fs::symlink_metadata(&snapshot_symlink)
            .expect("snapshot-like symlink remains")
            .file_type()
            .is_symlink()
    );
    assert_full_sqlite_state_unchanged(&path, &source_before);

    drop(active_marker);
    drop(writer);
}

#[cfg(unix)]
#[tokio::test]
async fn restart_cleans_trusted_crash_snapshot_even_after_source_wal_disappears() {
    let temp = TempDir::new().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical temp root");
    let path = root.join("no-wal-stale-cleanup.db");
    create_relay_meta_fixture(&path, SCHEMA_VERSION + 1, [0xa1; 32]);
    assert!(!sidecar(&path, "-wal").exists());
    let stale =
        create_crash_snapshot_fixture(&root, "no-wal-stale", &snapshot_marker_bytes(&path), false);

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path))
        .await
        .expect_err("higher schema remains rejected after no-WAL cleanup");
    assert!(matches!(error, StoreError::SchemaTooNew { .. }));
    assert!(
        !stale.exists(),
        "cleanup must not depend on a live source WAL"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn fresh_store_start_also_cleans_trusted_crash_snapshot_for_same_path() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical temp root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("secure fresh-store parent");
    let path = root.join("fresh-after-crash.db");
    assert!(!path.exists());
    let stale = create_crash_snapshot_fixture(
        &root,
        "fresh-path-stale",
        &snapshot_marker_bytes(&path),
        false,
    );

    let store = RelayStoreHandle::open(RelayV2StoreConfig::new(path))
        .await
        .expect("fresh store starts after reclaiming its trusted artifact");
    assert!(!stale.exists());
    store.shutdown().await.expect("shutdown fresh store");
}

#[cfg(unix)]
#[tokio::test]
async fn insecure_parent_is_rejected_before_any_crash_snapshot_cleanup() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical temp root");
    let path = root.join("insecure-parent.db");
    create_relay_meta_fixture(&path, SCHEMA_VERSION + 1, [0xa1; 32]);
    let stale =
        create_crash_snapshot_fixture(&root, "must-remain", &snapshot_marker_bytes(&path), false);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770))
        .expect("make parent group-writable");

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path))
        .await
        .expect_err("unsafe parent must fail before cleanup");
    assert!(matches!(error, StoreError::InsecurePermissions { .. }));
    assert!(stale.exists(), "unsafe parent permits no cleanup mutation");

    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("restore temp parent for cleanup");
}

#[tokio::test]
async fn hot_wal_legacy_schema_inspection_requires_reset_and_is_byte_immutable() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("hot-legacy.db");
    create_exact_legacy_v1_fixture(&path);
    let writer = Connection::open(&path).expect("open legacy WAL writer");
    writer
        .pragma_update(None, "journal_mode", "WAL")
        .expect("enable legacy WAL");
    writer
        .pragma_update(None, "wal_autocheckpoint", 0)
        .expect("disable legacy autocheckpoint");
    writer
        .execute(
            "INSERT INTO accounts(account_id, owner_sign_pubkey, created_at_ms)
             VALUES ('hot-wal-account', 'public-fixture', 1)",
            [],
        )
        .expect("write legacy hot WAL frame");
    let before = full_sqlite_state(&path);
    assert!(before.wal.is_some(), "fixture must have a WAL sidecar");
    assert!(before.shm.is_some(), "fixture must have a SHM sidecar");

    let error = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone()))
        .await
        .expect_err("hot-WAL legacy schema must be rejected");
    assert!(matches!(error, StoreError::LegacyV1ResetRequired));
    assert_full_sqlite_state_unchanged(&path, &before);
    drop(writer);
}

#[tokio::test]
async fn schema_signature_matches_independent_canonical_ddl_digest_fixture() {
    const EXPECTED_CANONICAL_DDL_SHA256: [u8; 32] = [
        0x9d, 0xfb, 0xb4, 0x07, 0x3b, 0xac, 0xcb, 0xf8, 0x56, 0x1d, 0xa1, 0x8b, 0x02, 0x6b, 0x78,
        0x09, 0x70, 0x74, 0xed, 0x75, 0x9e, 0xf4, 0x93, 0x5b, 0x48, 0x80, 0x46, 0x7d, 0x12, 0xbb,
        0x9f, 0xe2,
    ];

    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = open_production(&path).await;
    let snapshot = store.inspect().await.expect("inspect schema signature");
    assert_eq!(snapshot.schema_signature, EXPECTED_CANONICAL_DDL_SHA256);
    store.shutdown().await.expect("shutdown signature store");
}

// —— crash matrix / maintenance / bounded-control hardening ——

#[tokio::test]
async fn register_stream_before_commit_fault_rolls_back_and_retry_is_not_duplicate() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(
        &path,
        FaultPoint::RegisterStreamBeforeCommit,
    ))
    .await
    .expect("open fault-injected store");
    seed_and_register(&store, 0x81).await;
    let request = stream_registration(0x81, 0x91);

    let error = store
        .register_stream(request.clone())
        .await
        .expect_err("fault before stream COMMIT must surface");
    assert!(matches!(
        error,
        StoreError::InjectedFault(FaultPoint::RegisterStreamBeforeCommit)
    ));
    let retry = store
        .register_stream(request)
        .await
        .expect("rolled-back stream must insert on retry");
    assert!(!retry.duplicate);
    assert_eq!(retry.high_water_seq, None);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publish_after_commit_response_loss_restarts_as_one_byte_identical_duplicate() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(&path, FaultPoint::PublishAfterCommit))
        .await
        .expect("open fault-injected store");
    seed_and_register(&store, 0x82).await;
    register_fixture_stream(&store, 0x82, 0x92).await;
    let request = publish_request(0x82, 0x92, 0, 0xa2);
    let expected = match &request.frame.body {
        agentdeck_protocol::relay_v2::RelayFrameBody::Publish(frame) => frame.sealed_blob.0.clone(),
        _ => unreachable!("fixture builder always creates Publish"),
    };

    let error = store
        .publish(request.clone())
        .await
        .expect_err("lost response after publish COMMIT must surface");
    assert!(matches!(
        error,
        StoreError::InjectedFault(FaultPoint::PublishAfterCommit)
    ));
    store.shutdown().await.expect("shutdown first worker");

    let reopened = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("reopen committed store");
    let retry = reopened
        .publish(request)
        .await
        .expect("same canonical publish must recover as duplicate");
    assert_eq!(retry.disposition, PublishDisposition::Duplicate);
    let page = reopened
        .replay_page(replay_request(
            0x82,
            0x92,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("replay committed publish");
    assert_eq!(page.frames.len(), 1);
    assert_eq!(page.frames[0].sealed_blob, expected);
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn subscribe_before_commit_fault_rolls_back_and_retry_creates_fresh_lease() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(&path, FaultPoint::SubscribeBeforeCommit))
        .await
        .expect("open fault-injected store");
    seed_and_register(&store, 0x83).await;
    install_fixture_grant(&store, 0x83, 0x93, 1).await;
    register_fixture_stream(&store, 0x83, 0xa3).await;
    let request = subscription_request(0x83, 0x93, 1, 0xa3, StreamCursor::BeforeFirst);

    let error = store
        .subscribe(request.clone())
        .await
        .expect_err("fault before subscription COMMIT must surface");
    assert!(matches!(
        error,
        StoreError::InjectedFault(FaultPoint::SubscribeBeforeCommit)
    ));
    let retry = store
        .subscribe(request)
        .await
        .expect("rolled-back subscription must insert on retry");
    assert!(!retry.duplicate);
    assert_eq!(retry.ack, None);
    assert_eq!(retry.replay_through, StreamCursor::BeforeFirst);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn subscribe_freezes_replay_through_before_a_later_publish_commits() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let (entered_tx, entered_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let injector = Arc::new(BlockingFaultInjector::new(
        FaultPoint::SubscribeBeforeCommit,
        entered_tx,
        release_rx,
    ));
    let store = RelayStoreHandle::open(fixed_config(&path).with_fault_injector(injector))
        .await
        .expect("open atomic-subscribe store");
    seed_and_register(&store, 0x8d).await;
    install_fixture_grant(&store, 0x8d, 0x9d, 1).await;
    register_fixture_stream(&store, 0x8d, 0xad).await;

    let subscribe_store = store.clone();
    let subscribe = tokio::spawn(async move {
        subscribe_store
            .subscribe(subscription_request(
                0x8d,
                0x9d,
                1,
                0xad,
                StreamCursor::BeforeFirst,
            ))
            .await
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(std::time::Duration::from_secs(5)))
        .await
        .expect("join subscribe transaction wait")
        .expect("subscribe reached its pre-COMMIT boundary");

    let publish_store = store.clone();
    let publish = tokio::spawn(async move {
        publish_store
            .publish(publish_request(0x8d, 0xad, 0, 0xbd))
            .await
    });
    tokio::task::yield_now().await;
    release_tx
        .send(())
        .expect("release subscribe transaction before queued publish");

    let lease = subscribe
        .await
        .expect("join subscribe")
        .expect("subscribe commits");
    publish
        .await
        .expect("join queued publish")
        .expect("later publish commits");
    assert_eq!(
        lease.replay_through,
        StreamCursor::BeforeFirst,
        "lease must expose the high-water frozen inside its own transaction"
    );

    let refreshed = store
        .subscribe(subscription_request(
            0x8d,
            0x9d,
            1,
            0xad,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("refresh lease after publish");
    assert_eq!(refreshed.replay_through, StreamCursor::At(0));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn ack_before_commit_fault_preserves_null_ack_and_frame_until_retry() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(&path, FaultPoint::AckBeforeCommit))
        .await
        .expect("open fault-injected store");
    seed_and_register(&store, 0x84).await;
    install_fixture_grant(&store, 0x84, 0x94, 1).await;
    register_fixture_stream(&store, 0x84, 0xa4).await;
    store
        .publish(publish_request(0x84, 0xa4, 0, 0xb4))
        .await
        .expect("publish ACK fixture");
    let lease_request = subscription_request(0x84, 0x94, 1, 0xa4, StreamCursor::BeforeFirst);
    store
        .subscribe(lease_request.clone())
        .await
        .expect("create subscription");

    let error = store
        .ack(ack_request(0x84, 0x94, 1, 0xa4, 0))
        .await
        .expect_err("fault before ACK COMMIT must surface");
    assert!(matches!(
        error,
        StoreError::InjectedFault(FaultPoint::AckBeforeCommit)
    ));
    let lease = store
        .subscribe(lease_request)
        .await
        .expect("read back rolled-back lease");
    assert!(lease.duplicate);
    assert_eq!(lease.ack, None);
    let retained = store
        .replay_page(replay_request(
            0x84,
            0xa4,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("rolled-back ACK must retain frame");
    assert_eq!(retained.frames.len(), 1);

    store
        .ack(ack_request(0x84, 0x94, 1, 0xa4, 0))
        .await
        .expect("retry ACK commits");
    let gap = store
        .replay_page(replay_request(
            0x84,
            0xa4,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("committed ACK trims the safe prefix");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn revoke_before_commit_fault_keeps_grant_active_then_restart_replays_terminal_blob() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(&path, FaultPoint::RevokeBeforeCommit))
        .await
        .expect("open fault-injected store");
    seed_and_register(&store, 0x85).await;
    let grant = install_fixture_grant(&store, 0x85, 0x95, 1).await;
    register_fixture_stream(&store, 0x85, 0xa5).await;
    let request = revocation_request(0x85, 0x95, 1);

    let error = store
        .revoke(request.clone())
        .await
        .expect_err("fault before revoke COMMIT must surface");
    assert!(matches!(
        error,
        StoreError::InjectedFault(FaultPoint::RevokeBeforeCommit)
    ));
    let duplicate_grant = store
        .install_grant(grant)
        .await
        .expect("rolled-back revoke leaves grant active");
    assert!(duplicate_grant.duplicate);
    let committed = store
        .revoke(request.clone())
        .await
        .expect("retry revoke commits once");
    assert!(!committed.duplicate);
    store.shutdown().await.expect("shutdown first worker");

    let reopened = RelayStoreHandle::open(fixed_config(&path))
        .await
        .expect("reopen revoked store");
    let duplicate = reopened
        .revoke(request.clone())
        .await
        .expect("restart must return frozen terminal revocation");
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.revocation_hash, request.revocation_hash);
    assert_eq!(
        duplicate.signed_revocation_blob,
        request.signed_revocation_blob
    );
    let mut conflict = request;
    conflict.signed_revocation_blob[0] ^= 0xff;
    let conflict_error = reopened
        .revoke(conflict)
        .await
        .expect_err("same serial with different terminal bytes must conflict");
    assert!(matches!(
        conflict_error,
        StoreError::IdempotencyConflict {
            field: "grant_serial"
        }
    ));
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn purge_before_commit_fault_preserves_machine_then_retry_removes_everything() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_fault(&path, FaultPoint::PurgeBeforeCommit))
        .await
        .expect("open fault-injected store");
    seed_and_register(&store, 0x86).await;
    register_fixture_stream(&store, 0x86, 0xa6).await;
    store
        .publish(publish_request(0x86, 0xa6, 0, 0xc6))
        .await
        .expect("publish purge fixture");
    let request = PurgeMachine {
        machine_route: machine_route(0x86),
    };

    let error = store
        .purge_machine(request.clone())
        .await
        .expect_err("fault before purge COMMIT must surface");
    assert!(matches!(
        error,
        StoreError::InjectedFault(FaultPoint::PurgeBeforeCommit)
    ));
    let retained = store
        .replay_page(replay_request(
            0x86,
            0xa6,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("rolled-back purge leaves data readable");
    assert_eq!(retained.frames.len(), 1);

    let readback = store
        .purge_machine(request)
        .await
        .expect("retry purge commits");
    assert_eq!(readback.active_machine_routes, 0);
    assert_eq!(readback.retired_tombstones, 1);
    assert_eq!(readback.streams, 0);
    assert_eq!(readback.frames, 0);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn maintenance_enforces_logical_age_expiry_without_a_later_publish() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let clock = Arc::new(MutableClock::new(NOW_MS));
    let limits = RetentionLimits {
        max_age_ms: 100,
        ..limits_without_disk_gate()
    };
    let config = RelayV2StoreConfig::new(path.clone())
        .with_retention(limits)
        .with_clock(clock.clone())
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let store = RelayStoreHandle::open(config)
        .await
        .expect("open age-limited store");
    seed_and_register(&store, 0x87).await;
    register_fixture_stream(&store, 0x87, 0xa7).await;
    store
        .publish(publish_request(0x87, 0xa7, 0, 0xd7))
        .await
        .expect("publish age fixture");

    clock.set(NOW_MS + 100);
    let exact = store
        .replay_page(replay_request(
            0x87,
            0xa7,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("exact max-age boundary remains retained");
    assert_eq!(exact.frames.len(), 1);

    clock.set(NOW_MS + 101);
    let gap = store
        .replay_page(replay_request(
            0x87,
            0xa7,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("logical expiry must apply before replay returns bytes");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    let report = store
        .run_maintenance()
        .await
        .expect("idempotent explicit maintenance");
    assert_eq!(report.expired_frames, 0);

    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn foreign_replay_cannot_trigger_target_stream_age_maintenance() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let clock = Arc::new(MutableClock::new(NOW_MS));
    let limits = RetentionLimits {
        max_age_ms: 100,
        ..limits_without_disk_gate()
    };
    let config = RelayV2StoreConfig::new(path.clone())
        .with_retention(limits)
        .with_clock(clock.clone())
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })));
    let store = RelayStoreHandle::open(config)
        .await
        .expect("open owner-gated maintenance store");
    seed_and_register(&store, 0xb7).await;
    seed_and_register(&store, 0xb8).await;
    register_fixture_stream(&store, 0xb7, 0xc7).await;
    store
        .publish(publish_request(0xb7, 0xc7, 0, 0xd7))
        .await
        .expect("publish owner-gated maintenance fixture");

    clock.set(NOW_MS + 101);
    let foreign = store
        .replay_page(replay_request(
            0xb8,
            0xc7,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("foreign replay must fail before target maintenance");
    assert!(matches!(foreign, StoreError::StreamOwnerConflict));

    let report = store
        .run_maintenance()
        .await
        .expect("owner-neutral maintenance still finds the expired frame");
    assert_eq!(
        report.expired_frames, 1,
        "foreign replay must not have physically removed the target frame"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn startup_maintenance_expires_frames_before_worker_reports_ready() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let limits = RetentionLimits {
        max_age_ms: 100,
        ..limits_without_disk_gate()
    };
    let first = RelayStoreHandle::open(
        config_with_limits(&path, limits).with_clock(Arc::new(FixedClock(NOW_MS))),
    )
    .await
    .expect("open initial store");
    seed_and_register(&first, 0x88).await;
    register_fixture_stream(&first, 0x88, 0xa8).await;
    first
        .publish(publish_request(0x88, 0xa8, 0, 0xe8))
        .await
        .expect("publish startup sweep fixture");
    first.shutdown().await.expect("shutdown initial worker");

    let reopened = RelayStoreHandle::open(
        config_with_limits(&path, limits).with_clock(Arc::new(FixedClock(NOW_MS + 101))),
    )
    .await
    .expect("startup maintenance completes before ready");
    let gap = reopened
        .replay_page(replay_request(
            0x88,
            0xa8,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("expired frame is already absent after open returns");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    reopened.shutdown().await.expect("shutdown reopened worker");
}

#[tokio::test]
async fn maintenance_gc_keeps_enrollment_retry_through_exact_expiry_then_deletes_all_expired_rows()
{
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let clock = Arc::new(MutableClock::new(NOW_MS));
    let config = RelayV2StoreConfig::new(path.clone()).with_clock(clock.clone());
    let store = RelayStoreHandle::open(config)
        .await
        .expect("open enrollment GC store");
    let consumed = EnrollmentCodeSeed {
        code_hash: [0x89; 32],
        expires_at_ms: NOW_MS + 100,
    };
    let unconsumed = EnrollmentCodeSeed {
        code_hash: [0x8a; 32],
        expires_at_ms: NOW_MS + 100,
    };
    let live = EnrollmentCodeSeed {
        code_hash: [0x8b; 32],
        expires_at_ms: NOW_MS + 1_000,
    };
    for seed in [consumed, unconsumed, live] {
        store
            .seed_enrollment_code(seed)
            .await
            .expect("seed enrollment GC fixture");
    }
    let consumed_request = register_machine_request(0x89);
    store
        .register_machine(consumed_request.clone())
        .await
        .expect("consume enrollment fixture");

    clock.set(NOW_MS + 100);
    let exact_report = store
        .run_maintenance()
        .await
        .expect("run exact-expiry maintenance");
    assert_eq!(exact_report.expired_enrollment_codes, 0);
    let exact_retry = store
        .register_machine(consumed_request.clone())
        .await
        .expect("exact expiry still permits frozen response retry");
    assert!(exact_retry.duplicate);
    assert_eq!(exact_retry.response_blob, consumed_request.response_blob);

    clock.set(NOW_MS + 101);
    let expired_report = store
        .run_maintenance()
        .await
        .expect("run post-expiry maintenance");
    assert_eq!(expired_report.expired_enrollment_codes, 2);
    let missing = store
        .register_machine(consumed_request)
        .await
        .expect_err("expired frozen response is physically removed");
    assert!(matches!(missing, StoreError::EnrollmentCodeNotFound));

    store
        .shutdown()
        .await
        .expect("shutdown enrollment GC store");
    let conn = Connection::open(&path).expect("open enrollment GC readback");
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM enrollment_codes", [], |row| {
            row.get(0)
        })
        .expect("count enrollment rows");
    assert_eq!(remaining, 1, "only the still-live code remains");
}

#[tokio::test]
async fn enrollment_code_count_is_bounded_and_expired_rows_release_capacity() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let clock = Arc::new(MutableClock::new(NOW_MS));
    let config = RelayV2StoreConfig::new(path.clone())
        .with_clock(clock.clone())
        .with_max_enrollment_codes(2);
    let store = RelayStoreHandle::open(config)
        .await
        .expect("open bounded enrollment store");
    for seed in [0x8c, 0x8d] {
        store
            .seed_enrollment_code(EnrollmentCodeSeed {
                code_hash: [seed; 32],
                expires_at_ms: NOW_MS + 100,
            })
            .await
            .expect("fill enrollment capacity");
    }
    let full = store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: [0x8e; 32],
            expires_at_ms: NOW_MS + 1_000,
        })
        .await
        .expect_err("active enrollment rows have a hard count bound");
    assert!(matches!(
        full,
        StoreError::QuotaExceeded {
            scope: "enrollment_codes"
        }
    ));

    clock.set(NOW_MS + 101);
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: [0x8e; 32],
            expires_at_ms: NOW_MS + 1_000,
        })
        .await
        .expect("seed transaction GC releases expired capacity");
    store.shutdown().await.expect("shutdown bounded store");
}

#[tokio::test]
async fn maintenance_before_commit_fault_rolls_back_frames_codes_and_stream_stats() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let clock = Arc::new(MutableClock::new(NOW_MS));
    let fault = Arc::new(ArmedFaultInjector::new(FaultPoint::MaintenanceBeforeCommit));
    let limits = RetentionLimits {
        max_age_ms: 100,
        ..limits_without_disk_gate()
    };
    let config = RelayV2StoreConfig::new(path.clone())
        .with_retention(limits)
        .with_clock(clock.clone())
        .with_disk_space_probe(Arc::new(FixedDiskProbe(DiskSpace {
            available_bytes: u64::MAX,
            total_bytes: u64::MAX,
        })))
        .with_fault_injector(fault.clone());
    let store = RelayStoreHandle::open(config)
        .await
        .expect("open maintenance fault store");
    seed_and_register(&store, 0x8f).await;
    register_fixture_stream(&store, 0x8f, 0xaf).await;
    store
        .publish(publish_request(0x8f, 0xaf, 0, 0xef))
        .await
        .expect("publish maintenance fixture");
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: [0x90; 32],
            expires_at_ms: NOW_MS + 100,
        })
        .await
        .expect("seed maintenance enrollment fixture");

    clock.set(NOW_MS + 101);
    fault.arm();
    let error = store
        .run_maintenance()
        .await
        .expect_err("fault before maintenance COMMIT must surface");
    assert!(matches!(
        error,
        StoreError::InjectedFault(FaultPoint::MaintenanceBeforeCommit)
    ));
    store.shutdown().await.expect("shutdown faulted worker");

    let conn = Connection::open(&path).expect("open maintenance rollback readback");
    let frames: i64 = conn
        .query_row("SELECT COUNT(*) FROM frames", [], |row| row.get(0))
        .expect("count rolled-back frames");
    let codes: i64 = conn
        .query_row("SELECT COUNT(*) FROM enrollment_codes", [], |row| {
            row.get(0)
        })
        .expect("count rolled-back enrollment codes");
    let retained_bytes: i64 = conn
        .query_row("SELECT retained_bytes FROM streams", [], |row| row.get(0))
        .expect("read rolled-back stream stats");
    assert_eq!(frames, 1);
    assert_eq!(
        codes, 2,
        "machine code plus explicit code both remain before GC"
    );
    assert!(retained_bytes > 0);
}

#[tokio::test]
async fn replay_page_byte_limit_cannot_be_configured_below_one_legal_frame() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let limits = RetentionLimits {
        replay_page_max_bytes: (MAX_FRAME_BYTES - 1) as u64,
        ..limits_without_disk_gate()
    };
    let error = RelayStoreHandle::open(config_with_limits(&path, limits))
        .await
        .expect_err("page byte cap below legal frame maximum must fail startup");
    assert!(matches!(error, StoreError::InvalidValue { .. }));
}

#[tokio::test]
async fn grant_renewal_immediately_releases_removed_principal_ack_blocker() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open renewal trim store");
    seed_and_register(&store, 0x91).await;
    install_fixture_grant(&store, 0x91, 0xa1, 1).await;
    install_fixture_grant(&store, 0x91, 0xa2, 1).await;
    register_fixture_stream(&store, 0x91, 0xb1).await;
    store
        .publish(publish_request(0x91, 0xb1, 0, 0xf1))
        .await
        .expect("publish trim fixture");
    for device in [0xa1, 0xa2] {
        store
            .subscribe(subscription_request(
                0x91,
                device,
                1,
                0xb1,
                StreamCursor::BeforeFirst,
            ))
            .await
            .expect("create trim lease");
    }
    store
        .ack(ack_request(0x91, 0xa1, 1, 0xb1, 0))
        .await
        .expect("first principal ACKs");

    store
        .install_grant(install_grant_request(0x91, 0xa2, 2))
        .await
        .expect("renew lagging principal");
    let gap = store
        .replay_page(replay_request(
            0x91,
            0xb1,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("renewal removal immediately releases ACK-safe prefix");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    store.shutdown().await.expect("shutdown renewal trim store");
}

#[tokio::test]
async fn revocation_immediately_releases_removed_principal_ack_blocker() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let store = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open revoke trim store");
    seed_and_register(&store, 0x92).await;
    install_fixture_grant(&store, 0x92, 0xa3, 1).await;
    install_fixture_grant(&store, 0x92, 0xa4, 1).await;
    register_fixture_stream(&store, 0x92, 0xb2).await;
    store
        .publish(publish_request(0x92, 0xb2, 0, 0xf2))
        .await
        .expect("publish trim fixture");
    for device in [0xa3, 0xa4] {
        store
            .subscribe(subscription_request(
                0x92,
                device,
                1,
                0xb2,
                StreamCursor::BeforeFirst,
            ))
            .await
            .expect("create trim lease");
    }
    store
        .ack(ack_request(0x92, 0xa3, 1, 0xb2, 0))
        .await
        .expect("first principal ACKs");

    store
        .revoke(revocation_request(0x92, 0xa4, 1))
        .await
        .expect("revoke lagging principal");
    let gap = store
        .replay_page(replay_request(
            0x92,
            0xb2,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("revocation removal immediately releases ACK-safe prefix");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    store.shutdown().await.expect("shutdown revoke trim store");
}

#[tokio::test]
async fn worker_queue_rejects_excess_command_without_retaining_waiting_requests() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let (entered_tx, entered_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let injector = Arc::new(BlockingFaultInjector::new(
        FaultPoint::PublishBeforeCommit,
        entered_tx,
        release_rx,
    ));
    let store = RelayStoreHandle::open(fixed_config(&path).with_fault_injector(injector))
        .await
        .expect("open queue-bound store");
    seed_and_register(&store, 0x93).await;
    register_fixture_stream(&store, 0x93, 0xb3).await;

    let active_store = store.clone();
    let active = tokio::spawn(async move {
        active_store
            .publish(publish_request(0x93, 0xb3, 0, 0xf3))
            .await
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(std::time::Duration::from_secs(5)))
        .await
        .expect("join worker-entry wait")
        .expect("worker reached blocking fault point");

    let mut queued = Vec::new();
    for _ in 0..4 {
        let queued_store = store.clone();
        queued.push(tokio::spawn(async move { queued_store.inspect().await }));
        tokio::task::yield_now().await;
    }
    let excess = store.inspect().await;
    let shutdown_busy = store.shutdown().await;
    release_tx.send(()).expect("release blocked worker");
    assert!(matches!(excess, Err(StoreError::WorkerBusy)));
    assert!(matches!(shutdown_busy, Err(StoreError::WorkerBusy)));

    active
        .await
        .expect("join active publish")
        .expect("active publish completes");
    for task in queued {
        task.await
            .expect("join queued command")
            .expect("admitted queued command completes");
    }
    store
        .shutdown()
        .await
        .expect("busy shutdown remains retryable after drain");
}

#[tokio::test]
async fn stream_count_eviction_keeps_new_frame_when_wall_clock_moves_backwards() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let clock = Arc::new(MutableClock::new(NOW_MS + 100));
    let limits = RetentionLimits {
        max_frames_per_stream: 1,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits).with_clock(clock.clone()))
        .await
        .expect("open rollback-clock stream store");
    seed_and_register(&store, 0x94).await;
    register_fixture_stream(&store, 0x94, 0xb4).await;
    store
        .publish(publish_request(0x94, 0xb4, 0, 0x10))
        .await
        .expect("publish first frame");
    clock.set(NOW_MS + 99);
    store
        .publish(publish_request(0x94, 0xb4, 1, 0x11))
        .await
        .expect("new frame must remain retained after clock rollback");

    let page = store
        .replay_page(replay_request(
            0x94,
            0xb4,
            ReplayPosition::Start(StreamCursor::At(0)),
        ))
        .await
        .expect("replay newest retained stream frame");
    assert_eq!(page.frames.len(), 1);
    assert_eq!(page.frames[0].stream_seq, 1);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn machine_eviction_keeps_new_frame_when_wall_clock_moves_backwards() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let sample = publish_request(0x95, 0xb5, 0, 0x20);
    let frame_size = u64::try_from(sample.canonical_bytes().expect("encode sample").len())
        .expect("sample size fits u64");
    let clock = Arc::new(MutableClock::new(NOW_MS + 100));
    let limits = RetentionLimits {
        max_bytes_per_machine: frame_size,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits).with_clock(clock.clone()))
        .await
        .expect("open rollback-clock machine store");
    seed_and_register(&store, 0x95).await;
    register_fixture_stream(&store, 0x95, 0xb5).await;
    register_fixture_stream(&store, 0x95, 0xb6).await;
    store
        .publish(sample)
        .await
        .expect("publish first machine frame");
    clock.set(NOW_MS + 99);
    store
        .publish(publish_request(0x95, 0xb6, 0, 0x21))
        .await
        .expect("new machine frame must remain after clock rollback");

    let newest = store
        .replay_page(replay_request(
            0x95,
            0xb6,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("new machine frame remains replayable");
    assert_eq!(newest.frames.len(), 1);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn global_eviction_keeps_new_frame_when_wall_clock_moves_backwards() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let sample = publish_request(0x96, 0xb7, 0, 0x30);
    let frame_size = u64::try_from(sample.canonical_bytes().expect("encode sample").len())
        .expect("sample size fits u64");
    let clock = Arc::new(MutableClock::new(NOW_MS + 100));
    let limits = RetentionLimits {
        max_bytes_global: frame_size,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits).with_clock(clock.clone()))
        .await
        .expect("open rollback-clock global store");
    seed_and_register(&store, 0x96).await;
    seed_and_register(&store, 0x97).await;
    register_fixture_stream(&store, 0x96, 0xb7).await;
    register_fixture_stream(&store, 0x97, 0xb8).await;
    store
        .publish(sample)
        .await
        .expect("publish first global frame");
    clock.set(NOW_MS + 99);
    store
        .publish(publish_request(0x97, 0xb8, 0, 0x31))
        .await
        .expect("new global frame must remain after clock rollback");

    let newest = store
        .replay_page(replay_request(
            0x97,
            0xb8,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("new global frame remains replayable");
    assert_eq!(newest.frames.len(), 1);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn subscribe_reports_gap_when_high_water_exists_but_all_frames_are_gone() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let clock = Arc::new(MutableClock::new(NOW_MS));
    let limits = RetentionLimits {
        max_age_ms: 100,
        ..limits_without_disk_gate()
    };
    let store = RelayStoreHandle::open(config_with_limits(&path, limits).with_clock(clock.clone()))
        .await
        .expect("open empty-retained-window store");
    seed_and_register(&store, 0x98).await;
    install_fixture_grant(&store, 0x98, 0xa8, 1).await;
    register_fixture_stream(&store, 0x98, 0xb9).await;
    store
        .publish(publish_request(0x98, 0xb9, 0, 0x40))
        .await
        .expect("publish expiring frame");
    clock.set(NOW_MS + 101);
    store
        .run_maintenance()
        .await
        .expect("expire entire retained window");

    let gap = store
        .subscribe(subscription_request(
            0x98,
            0xa8,
            1,
            0xb9,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect_err("subscription must surface the already-known gap");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    let caught_up = store
        .subscribe(subscription_request(
            0x98,
            0xa8,
            1,
            0xb9,
            StreamCursor::At(0),
        ))
        .await
        .expect("cursor at high-water needs no retained frame");
    assert_eq!(caught_up.start, StreamCursor::At(0));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn startup_maintenance_applies_lowered_stream_count_limit_before_ready() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let initial_limits = RetentionLimits {
        max_frames_per_stream: 3,
        ..limits_without_disk_gate()
    };
    let first = RelayStoreHandle::open(config_with_limits(&path, initial_limits))
        .await
        .expect("open initial count store");
    seed_and_register(&first, 0x99).await;
    register_fixture_stream(&first, 0x99, 0xba).await;
    for seq in 0..3 {
        first
            .publish(publish_request(0x99, 0xba, seq, seq as u8))
            .await
            .expect("publish pre-shrink frame");
    }
    first.shutdown().await.expect("shutdown initial store");

    let lowered = RetentionLimits {
        max_frames_per_stream: 1,
        ..limits_without_disk_gate()
    };
    let reopened = RelayStoreHandle::open(config_with_limits(&path, lowered))
        .await
        .expect("startup maintenance applies lowered count cap");
    let gap = reopened
        .replay_page(replay_request(
            0x99,
            0xba,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("startup shrink evicts the two oldest frames");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 2
        }
    ));
    let page = reopened
        .replay_page(replay_request(
            0x99,
            0xba,
            ReplayPosition::Start(StreamCursor::At(1)),
        ))
        .await
        .expect("only newest frame remains after startup shrink");
    assert_eq!(page.frames.len(), 1);
    assert_eq!(page.frames[0].stream_seq, 2);
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn startup_maintenance_applies_lowered_machine_and_global_byte_limits_before_ready() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let first = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open initial byte store");
    seed_and_register(&first, 0x9a).await;
    seed_and_register(&first, 0x9b).await;
    register_fixture_stream(&first, 0x9a, 0xbb).await;
    register_fixture_stream(&first, 0x9a, 0xbc).await;
    register_fixture_stream(&first, 0x9b, 0xbd).await;
    let sample = publish_request(0x9a, 0xbb, 0, 0x50);
    let frame_size = u64::try_from(sample.canonical_bytes().expect("encode sample").len())
        .expect("sample size fits u64");
    first.publish(sample).await.expect("publish first frame");
    first
        .publish(publish_request(0x9a, 0xbc, 0, 0x51))
        .await
        .expect("publish second machine frame");
    first
        .publish(publish_request(0x9b, 0xbd, 0, 0x52))
        .await
        .expect("publish second-machine frame");
    first.shutdown().await.expect("shutdown initial store");

    let lowered = RetentionLimits {
        max_bytes_per_machine: frame_size,
        max_bytes_global: frame_size * 2,
        ..limits_without_disk_gate()
    };
    let reopened = RelayStoreHandle::open(config_with_limits(&path, lowered))
        .await
        .expect("startup maintenance applies lowered byte caps");
    let old_machine_frame = reopened
        .replay_page(replay_request(
            0x9a,
            0xbb,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("lowered machine cap evicts its oldest frame");
    assert!(matches!(
        old_machine_frame,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    let machine_newest = reopened
        .replay_page(replay_request(
            0x9a,
            0xbc,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("newest frame for first machine remains");
    let second_machine = reopened
        .replay_page(replay_request(
            0x9b,
            0xbd,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("global cap retains newest second-machine frame");
    assert_eq!(machine_newest.frames.len(), 1);
    assert_eq!(second_machine.frames.len(), 1);
    reopened.shutdown().await.expect("shutdown reopened store");
    let conn = Connection::open(&path).expect("open lowered-byte readback");
    let retained: i64 = conn
        .query_row("SELECT COUNT(*) FROM frames", [], |row| row.get(0))
        .expect("count retained frames");
    assert_eq!(retained, 2);
}

#[tokio::test]
async fn startup_maintenance_applies_lowered_global_byte_limit_independently() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let first = RelayStoreHandle::open(config_with_limits(&path, limits_without_disk_gate()))
        .await
        .expect("open initial global-shrink store");
    seed_and_register(&first, 0x9c).await;
    seed_and_register(&first, 0x9d).await;
    register_fixture_stream(&first, 0x9c, 0xbe).await;
    register_fixture_stream(&first, 0x9d, 0xbf).await;
    let old = publish_request(0x9c, 0xbe, 0, 0x60);
    let frame_size = u64::try_from(old.canonical_bytes().expect("encode sample").len())
        .expect("sample size fits u64");
    first.publish(old).await.expect("publish old global frame");
    first
        .publish(publish_request(0x9d, 0xbf, 0, 0x61))
        .await
        .expect("publish new global frame");
    first.shutdown().await.expect("shutdown initial store");

    let lowered = RetentionLimits {
        max_bytes_global: frame_size,
        ..limits_without_disk_gate()
    };
    let reopened = RelayStoreHandle::open(config_with_limits(&path, lowered))
        .await
        .expect("startup maintenance applies independent global cap");
    let old_gap = reopened
        .replay_page(replay_request(
            0x9c,
            0xbe,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect_err("global shrink evicts oldest insertion");
    assert!(matches!(
        old_gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    let newest = reopened
        .replay_page(replay_request(
            0x9d,
            0xbf,
            ReplayPosition::Start(StreamCursor::BeforeFirst),
        ))
        .await
        .expect("newest global frame remains");
    assert_eq!(newest.frames.len(), 1);
    reopened.shutdown().await.expect("shutdown reopened store");
}
