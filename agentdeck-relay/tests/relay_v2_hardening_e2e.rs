//! Relay v2 阶段级故障组合测试（Task P2.10）。
//!
//! 这里不重复专项测试的全部矩阵，而是用公开 Store/server API 组合出三条独立证据链：
//! - SQLite 重启后逐字节回放，并在同一条流上经历 disk-low、恢复与配额裁剪 gap；
//! - Publish 的 COMMIT 前故障跨 worker 重启保持零业务写，同一 canonical 请求仍可提交；
//! - DirectTLS server 完整 shutdown 后可用同一 SQLite 重新启动，Relay server identity 不变。

#![cfg(all(feature = "server", feature = "tls"))]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::relay_v2::frame::{Publish, SealedBlob};
use agentdeck_protocol::relay_v2::{
    CertRole, Ed25519Signature, LinkGeneration, MachineRouteId, PublicKeyBytes, RelayFrameBody,
    RootKeyId, SignedCertificate, StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_relay::config::{
    RelayV2ServerConfig, RelayV2StoreSettings, RelayV2TlsPaths, RelayV2TransportMode,
};
use agentdeck_relay::v2::server::RelayV2ServerHandle;
use agentdeck_relay::v2::store::{
    Clock, DiskSpace, DiskSpaceProbe, EnrollmentCodeSeed, FaultInjector, FaultPoint,
    PersistPublish, PublishDisposition, RegisterMachine, RelayStoreHandle, RelayV2StoreConfig,
    ReplayPageRequest, ReplayPosition, RetentionLimits, StoreError, StreamRegistration,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const NOW_MS: u64 = 1_800_000_000_000;
const MACHINE_SEED: u8 = 0x41;
const STREAM_SEED: u8 = 0x51;

#[derive(Debug)]
struct FixedClock;

impl Clock for FixedClock {
    fn now_ms(&self) -> Result<u64, StoreError> {
        Ok(NOW_MS)
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
struct OneShotFault {
    point: FaultPoint,
    fired: AtomicBool,
}

impl OneShotFault {
    fn new(point: FaultPoint) -> Self {
        Self {
            point,
            fired: AtomicBool::new(false),
        }
    }
}

impl FaultInjector for OneShotFault {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(StoreError::InjectedFault(point));
        }
        Ok(())
    }
}

fn store_path(temp: &TempDir) -> PathBuf {
    temp.path().join("relay-hardening").join("relay.db")
}

fn retention(max_frames_per_stream: u64) -> RetentionLimits {
    RetentionLimits {
        max_frames_per_stream,
        disk_reserve_bytes: 100,
        disk_reserve_percent: 0,
        ..RetentionLimits::default()
    }
}

fn store_config(
    path: &Path,
    disk: Arc<MutableDiskProbe>,
    max_frames_per_stream: u64,
) -> RelayV2StoreConfig {
    RelayV2StoreConfig::new(path.to_path_buf())
        .with_clock(Arc::new(FixedClock))
        .with_disk_space_probe(disk)
        .with_retention(retention(max_frames_per_stream))
}

fn machine_route() -> MachineRouteId {
    MachineRouteId::from_bytes([MACHINE_SEED; 16])
}

fn stream_route() -> StreamRouteId {
    StreamRouteId::from_bytes([STREAM_SEED; 16])
}

fn stream_generation() -> StreamGenerationId {
    StreamGenerationId::from_bytes([STREAM_SEED.wrapping_add(1); 16])
}

fn certificate(role: CertRole) -> SignedCertificate {
    SignedCertificate {
        subject_pubkey: PublicKeyBytes([MACHINE_SEED.wrapping_add(role as u8); 32]),
        cert_role: role,
        generation: LinkGeneration::new(1),
        root_key_id: RootKeyId::from_bytes([MACHINE_SEED; 16]),
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: Some(NOW_MS + 60_000),
        signature: Ed25519Signature([MACHINE_SEED.wrapping_add(7); 64]),
    }
}

async fn seed_machine_and_stream(store: &RelayStoreHandle) {
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: [MACHINE_SEED; 32],
            expires_at_ms: NOW_MS + 30_000,
        })
        .await
        .expect("seed enrollment code");
    let root_pubkey = PublicKeyBytes([MACHINE_SEED.wrapping_add(3); 32]);
    store
        .register_machine(RegisterMachine {
            code_hash: [MACHINE_SEED; 32],
            request_hash: [MACHINE_SEED.wrapping_add(1); 32],
            response_blob: vec![MACHINE_SEED, 0xad, 0x02],
            receipt_hash: [MACHINE_SEED.wrapping_add(2); 32],
            machine_route: machine_route(),
            root_pubkey,
            link_cert: certificate(CertRole::Link),
            data_cert: certificate(CertRole::Data),
            link_cert_hash: [MACHINE_SEED.wrapping_add(4); 32],
            data_cert_hash: [MACHINE_SEED.wrapping_add(5); 32],
        })
        .await
        .expect("register machine fixture");
    store
        .register_stream(StreamRegistration {
            machine_route: machine_route(),
            stream_route: stream_route(),
            generation: stream_generation(),
        })
        .await
        .expect("register stream fixture");
}

fn publish(stream_seq: u64, payload: &[u8]) -> PersistPublish {
    PersistPublish::from_publish(
        machine_route(),
        Publish {
            stream_route: stream_route(),
            generation: stream_generation(),
            stream_seq,
            sealed_blob: SealedBlob(payload.to_vec()),
        },
    )
}

fn replay(start: StreamCursor) -> ReplayPageRequest {
    ReplayPageRequest {
        machine_route: machine_route(),
        stream_route: stream_route(),
        generation: stream_generation(),
        position: ReplayPosition::Start(start),
        page_max_frames: 64,
        page_max_bytes: 8 * 1024 * 1024,
    }
}

fn replay_blobs(page: &agentdeck_relay::v2::store::ReplayPage) -> Vec<Vec<u8>> {
    page.frames
        .iter()
        .map(|frame| frame.sealed_blob.clone())
        .collect()
}

#[tokio::test]
async fn restart_replay_survives_disk_low_then_quota_trim_surfaces_exact_gap() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let disk = Arc::new(MutableDiskProbe::new(1_000_000, 10_000_000));
    let config = store_config(&path, disk.clone(), 2);
    let first = RelayStoreHandle::open(config.clone())
        .await
        .expect("open first Store worker");
    seed_machine_and_stream(&first).await;
    let frozen = vec![
        b"opaque-ciphertext-page-zero".to_vec(),
        b"opaque-ciphertext-page-one".to_vec(),
    ];
    for (stream_seq, payload) in frozen.iter().enumerate() {
        first
            .publish(publish(stream_seq as u64, payload))
            .await
            .expect("publish frozen replay page");
    }
    let before_restart = first
        .replay_page(replay(StreamCursor::BeforeFirst))
        .await
        .expect("replay before restart");
    assert_eq!(replay_blobs(&before_restart), frozen);
    first.shutdown().await.expect("shutdown first Store worker");

    let reopened = RelayStoreHandle::open(config)
        .await
        .expect("reopen the same SQLite store");
    let after_restart = reopened
        .replay_page(replay(StreamCursor::BeforeFirst))
        .await
        .expect("replay after restart");
    assert_eq!(
        replay_blobs(&after_restart),
        frozen,
        "SQLite restart must preserve sealed blobs byte-for-byte"
    );

    disk.set_available(100);
    let disk_low = reopened
        .publish(publish(2, b"must-not-commit-while-disk-low"))
        .await
        .expect_err("new publish must fail below reserve");
    assert!(matches!(disk_low, StoreError::DiskSpaceLow));
    assert_eq!(
        replay_blobs(
            &reopened
                .replay_page(replay(StreamCursor::BeforeFirst))
                .await
                .expect("disk-low must not block existing replay")
        ),
        frozen,
        "disk-low rejection must not mutate retained bytes or advance HWM"
    );

    disk.set_available(1_000_000);
    let recovered_payload = b"opaque-ciphertext-page-two".to_vec();
    reopened
        .publish(publish(2, &recovered_payload))
        .await
        .expect("same sequence commits after disk recovery");
    let gap = reopened
        .replay_page(replay(StreamCursor::BeforeFirst))
        .await
        .expect_err("two-frame quota must trim sequence zero");
    assert!(matches!(
        gap,
        StoreError::ReplayGap {
            needed: 0,
            oldest: 1
        }
    ));
    let retained = reopened
        .replay_page(replay(StreamCursor::At(0)))
        .await
        .expect("resume immediately before oldest retained frame");
    assert_eq!(
        replay_blobs(&retained),
        vec![frozen[1].clone(), recovered_payload],
        "quota trimming may delete only the oldest frame"
    );
    reopened.shutdown().await.expect("shutdown reopened Store");
}

#[tokio::test]
async fn publish_before_commit_fault_is_zero_write_across_restart_and_retry() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let disk = Arc::new(MutableDiskProbe::new(1_000_000, 10_000_000));
    let faulted = store_config(&path, disk.clone(), 4)
        .with_fault_injector(Arc::new(OneShotFault::new(FaultPoint::PublishBeforeCommit)));
    let first = RelayStoreHandle::open(faulted)
        .await
        .expect("open fault-injected Store");
    seed_machine_and_stream(&first).await;
    let canonical = publish(0, b"frozen-retry-ciphertext");
    let injected = first
        .publish(canonical.clone())
        .await
        .expect_err("pre-COMMIT fault must surface");
    assert!(matches!(
        injected,
        StoreError::InjectedFault(FaultPoint::PublishBeforeCommit)
    ));
    first.shutdown().await.expect("shutdown faulted worker");

    let reopened = RelayStoreHandle::open(store_config(&path, disk, 4))
        .await
        .expect("reopen after pre-COMMIT fault");
    let empty = reopened
        .replay_page(replay(StreamCursor::BeforeFirst))
        .await
        .expect("rolled-back stream remains readable");
    assert!(empty.frames.is_empty(), "faulted frame must not be durable");
    assert_eq!(empty.replay_through, StreamCursor::BeforeFirst);
    let retry = reopened
        .publish(canonical.clone())
        .await
        .expect("same seq and canonical bytes must commit on retry");
    assert_eq!(retry.stream_seq, 0);
    assert_eq!(retry.disposition, PublishDisposition::Inserted);
    let replayed = reopened
        .replay_page(replay(StreamCursor::BeforeFirst))
        .await
        .expect("replay committed retry");
    let expected = match canonical.frame.body {
        RelayFrameBody::Publish(frame) => frame.sealed_blob.0,
        _ => unreachable!("PersistPublish fixture is always Publish"),
    };
    assert_eq!(replay_blobs(&replayed), vec![expected]);
    reopened.shutdown().await.expect("shutdown retry worker");
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn server_config(path: &Path) -> RelayV2ServerConfig {
    let mut store = RelayV2StoreSettings::new(path.to_path_buf());
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    RelayV2ServerConfig {
        bind: "127.0.0.1:0".parse().expect("public bind"),
        health_bind: "127.0.0.1:0".parse().expect("health bind"),
        store,
        transport: RelayV2TransportMode::DirectTls(RelayV2TlsPaths {
            cert: fixture("test_cert.pem"),
            key: fixture("test_key.pem"),
        }),
        admin: None,
        log_level: "info".to_owned(),
    }
}

async fn assert_ready(address: std::net::SocketAddr) {
    let mut socket = TcpStream::connect(address)
        .await
        .expect("connect real health listener");
    socket
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write readiness request");
    let mut response = Vec::new();
    socket
        .read_to_end(&mut response)
        .await
        .expect("read readiness response");
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "real server must report ready: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response
            .windows(b"\"status\":\"ready\"".len())
            .any(|window| { window == b"\"status\":\"ready\"" })
    );
}

#[tokio::test]
async fn direct_tls_server_shutdown_releases_store_and_same_database_reopens() {
    let temp = TempDir::new().expect("tempdir");
    let path = store_path(&temp);
    let config = server_config(&path);

    let first = RelayV2ServerHandle::start(config.clone())
        .await
        .expect("start first DirectTLS server");
    assert_ready(first.health_addr()).await;
    first.shutdown().await.expect("shutdown first server");

    let between = RelayStoreHandle::open(
        config
            .store
            .clone()
            .into_store_config()
            .expect("convert server Store config"),
    )
    .await
    .expect("server shutdown must release SQLite ownership");
    let relay_server_id = between.relay_server_id();
    between.shutdown().await.expect("release inspection Store");

    let restarted = RelayV2ServerHandle::start(config.clone())
        .await
        .expect("restart DirectTLS server on same database");
    assert_ready(restarted.health_addr()).await;
    restarted
        .shutdown()
        .await
        .expect("shutdown restarted server");

    let final_store = RelayStoreHandle::open(
        config
            .store
            .into_store_config()
            .expect("convert final Store config"),
    )
    .await
    .expect("reopen Store after second server shutdown");
    assert_eq!(
        final_store.relay_server_id(),
        relay_server_id,
        "server restart must retain the same persisted Relay identity"
    );
    final_store.shutdown().await.expect("shutdown final Store");
}
