//! Relay v2 strict-minimum-visibility security sentinel.
//!
//! 这不是源码字符串扫描或 Store-only 单测：测试预种两个 machine trust domain，启动真实
//! DirectTLS listener，经生产 WSS Challenge/Authenticate/Core 把 endpoint AEAD + sender
//! signature 的 opaque Publish 持久化。随后同时扫描 canonical outer、结构化日志、
//! health/metrics HTTP surface 以及 SQLite DB/WAL，并以 SQL/readback/replay 证明 ciphertext
//! 确实通过生产链路落盘；另一个已认证 machine 的 route takeover 必须在新增持久化行前失败。

#![cfg(all(feature = "server", feature = "tls"))]

mod support;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, open_symmetric,
    seal_symmetric, sha256, sign_authentication_transcript, sign_sealed, sign_tbs, verify_sealed,
};
use agentdeck_protocol::e2ee::E2EE_FORMAT_VERSION;
use agentdeck_protocol::e2ee::context::{OuterContextV1, OuterFrameKind};
use agentdeck_protocol::e2ee::keys::{KeyId, KeyPurpose};
use agentdeck_protocol::e2ee::payload::SealedPayloadKind;
use agentdeck_protocol::relay_v2::auth::{AuthenticationRole, AuthenticationTranscriptV1};
use agentdeck_protocol::relay_v2::failure::RELAY_ROUTE_NOT_FOUND;
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, AuthProof, Authenticate, Hello, Publish, RegisterStream, SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    CertRole, Ed25519Signature, LinkGeneration, MachineRouteId, OpaqueRouteFrame, PublicKeyBytes,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayServerId, RootKeyId, SignedCertificate,
    StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};
use agentdeck_relay::config::{
    RelayV2ServerConfig, RelayV2StoreSettings, RelayV2TlsPaths, RelayV2TransportMode,
};
use agentdeck_relay::v2::server::RelayV2ServerHandle;
use agentdeck_relay::v2::store::{
    EnrollmentCodeSeed, RegisterMachine, RelayStoreHandle, ReplayPageRequest, ReplayPosition,
};
use futures_util::{SinkExt, StreamExt};
use rusqlite::{Connection, OpenFlags};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};
use tracing_subscriber::fmt::MakeWriter;

use support::{test_receipt_identity, write_test_receipt_signing_key};

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const TEST_CERT_PEM: &[u8] = include_bytes!("fixtures/test_cert.pem");
const SENTINELS: [&str; 6] = [
    "S2C-MACHINE-PLAIN-9f6b0c",
    "S2C-SESSION-PLAIN-41d087",
    "S2C-PROMPT-PLAIN-a70e55",
    "S2C-OUTPUT-PLAIN-d6c923",
    "S2C-APPROVAL-PLAIN-18b4fe",
    "S2C-VENDOR-REF-PLAIN-7ad301",
];
const CONTENT_KEY: [u8; 32] = [0x5a; 32];

type TestSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct MachineRealm {
    machine_route: MachineRouteId,
    link: SigningKey,
    data: SigningKey,
    link_cert: SignedCertificate,
}

impl MachineRealm {
    fn authenticate(
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
}

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

struct LogCaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for LogCaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for LogCapture {
    type Writer = LogCaptureWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        LogCaptureWriter(Arc::clone(&self.0))
    }
}

impl LogCapture {
    fn bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[derive(Debug)]
struct ExactCertificateVerifier {
    expected_der: Vec<u8>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ExactCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_der {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "test exact-certificate pin mismatch".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn test_certificate_der() -> Vec<u8> {
    CertificateDer::from_pem_slice(TEST_CERT_PEM)
        .expect("parse exact-cert fixture")
        .as_ref()
        .to_vec()
}

fn exact_cert_connector() -> Connector {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    let algorithms = rustls::crypto::CryptoProvider::get_default()
        .expect("rustls crypto provider")
        .signature_verification_algorithms;
    let verifier = ExactCertificateVerifier {
        expected_der: test_certificate_der(),
        algorithms,
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

async fn connect(address: SocketAddr) -> TestSocket {
    let request = format!("wss://{address}/v2/connect")
        .into_client_request()
        .expect("valid WSS request");
    timeout(
        IO_TIMEOUT,
        connect_async_tls_with_config(request, None, false, Some(exact_cert_connector())),
    )
    .await
    .expect("WSS handshake timeout")
    .expect("WSS handshake with exact certificate pin")
    .0
}

fn outer(body: RelayFrameBody) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    }
}

async fn receive_frame(socket: &mut TestSocket) -> OpaqueRouteFrame {
    timeout(IO_TIMEOUT, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(bytes))) => {
                    return decode(&bytes).expect("canonical Relay v2 frame");
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                Some(Ok(other)) => panic!("unexpected WebSocket message: {other:?}"),
                Some(Err(error)) => panic!("WebSocket read failed: {error}"),
                None => panic!("WebSocket closed before Relay frame"),
            }
        }
    })
    .await
    .expect("Relay frame timeout")
}

async fn authenticate_machine(socket: &mut TestSocket, realm: &MachineRealm) {
    socket
        .send(Message::Binary(
            encode(&outer(RelayFrameBody::Hello(Hello {
                protocol_version: RELAY_PROTOCOL_VERSION,
            })))
            .into(),
        ))
        .await
        .expect("send binary Hello");
    let RelayFrameBody::Challenge(challenge) = receive_frame(socket).await.body else {
        panic!("Hello must yield Challenge");
    };
    socket
        .send(Message::Binary(
            encode(&outer(RelayFrameBody::Authenticate(
                realm.authenticate(&challenge),
            )))
            .into(),
        ))
        .await
        .expect("send MachineLink Authenticate");
    assert!(matches!(
        receive_frame(socket).await.body,
        RelayFrameBody::Authenticated(_)
    ));
}

async fn assert_rejected_without_application_binary(mut socket: TestSocket) {
    timeout(IO_TIMEOUT, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(Message::Binary(bytes))) => {
                    panic!("rejected plaintext produced application binary: {bytes:?}")
                }
                Some(Ok(Message::Text(text))) => {
                    panic!("Relay emitted forbidden text: {text}")
                }
                Some(Ok(Message::Frame(_))) => unreachable!("raw frames are not surfaced"),
            }
        }
    })
    .await
    .expect("rejected WebSocket did not close promptly");
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis()
        .try_into()
        .expect("unix millis fit u64")
}

fn server_config(temp: &TempDir) -> (RelayV2ServerConfig, PathBuf) {
    let storage_path = temp.path().join("relay-data").join("relay.db");
    let mut store = RelayV2StoreSettings::new(storage_path.clone());
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    (
        RelayV2ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            health_bind: "127.0.0.1:0".parse().unwrap(),
            store,
            transport: RelayV2TransportMode::DirectTls(RelayV2TlsPaths {
                cert: fixture("test_cert.pem"),
                key: fixture("test_key.pem"),
            }),
            admin: None,
            receipt_signing_key: write_test_receipt_signing_key(temp.path()),
            log_level: "info".to_owned(),
        },
        storage_path,
    )
}

fn signed_certificate(
    root: &SigningKey,
    subject: &SigningKey,
    role: CertRole,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
) -> SignedCertificate {
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
        cert_role: role,
        generation: LinkGeneration::new(1),
        root_key_id,
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: None,
        signature: Ed25519Signature([0; 64]),
    };
    certificate.signature = sign_tbs(
        root,
        &certificate.to_be_signed_v1(
            relay_server_id,
            machine_route,
            sha256(&root.verifying_key().to_bytes()),
        ),
    )
    .into();
    certificate
}

async fn seed_machine(
    store: &RelayStoreHandle,
    relay_server_id: RelayServerId,
    seed: u8,
) -> MachineRealm {
    let machine_route = MachineRouteId::from_bytes([seed; 16]);
    let root_key_id = RootKeyId::from_bytes([seed.wrapping_add(1); 16]);
    let root = SigningKey::from_seed(&[seed.wrapping_add(2); 32]);
    let link = SigningKey::from_seed(&[seed.wrapping_add(3); 32]);
    let data = SigningKey::from_seed(&[seed.wrapping_add(4); 32]);
    let link_cert = signed_certificate(
        &root,
        &link,
        CertRole::Link,
        relay_server_id,
        machine_route,
        root_key_id,
    );
    let data_cert = signed_certificate(
        &root,
        &data,
        CertRole::Data,
        relay_server_id,
        machine_route,
        root_key_id,
    );
    let code_hash = [seed.wrapping_add(5); 32];
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash,
            expires_at_ms: unix_now_ms().saturating_add(60_000),
        })
        .await
        .expect("seed one-use enrollment code");
    store
        .register_machine(RegisterMachine {
            code_hash,
            request_hash: sha256(&[seed, 0x01]),
            machine_route,
            root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
            link_cert_hash: link_cert.canonical_sha256(),
            data_cert_hash: data_cert.canonical_sha256(),
            link_cert: link_cert.clone(),
            data_cert,
        })
        .await
        .expect("register machine trust domain");
    MachineRealm {
        machine_route,
        link,
        data,
        link_cert,
    }
}

async fn http_get(url: String) -> (u16, Vec<u8>) {
    tokio::task::spawn_blocking(move || match ureq::get(&url).call() {
        Ok(response) => {
            let status = response.status();
            let mut reader = response.into_reader();
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut reader, &mut body).expect("read health response");
            (status, body)
        }
        Err(ureq::Error::Status(status, response)) => {
            let mut reader = response.into_reader();
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut reader, &mut body).expect("read health failure");
            (status, body)
        }
        Err(ureq::Error::Transport(error)) => panic!("health transport failed: {error}"),
    })
    .await
    .expect("join health request")
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn raw_sqlite_files(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    [
        path.to_path_buf(),
        sidecar(path, "-wal"),
        sidecar(path, "-shm"),
    ]
    .into_iter()
    .filter_map(|candidate| {
        candidate
            .is_file()
            .then(|| fs::read(&candidate).map(|bytes| (candidate, bytes)))
    })
    .collect::<Result<Vec<_>, _>>()
    .expect("read Relay SQLite files")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_no_plaintext(surface: &str, bytes: &[u8]) -> usize {
    let matches = SENTINELS
        .iter()
        .filter(|sentinel| contains(bytes, sentinel.as_bytes()))
        .count();
    assert_eq!(matches, 0, "plaintext sentinel leaked into {surface}");
    matches
}

#[tokio::test(flavor = "current_thread")]
async fn production_wss_keeps_endpoint_plaintext_out_of_relay_observable_surfaces() {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(capture.clone())
        .finish();
    tracing::dispatcher::set_global_default(tracing::Dispatch::new(subscriber))
        .expect("security E2E owns this test process tracing subscriber");

    let temp = TempDir::new().expect("security sentinel tempdir");
    let (config, db_path) = server_config(&temp);
    let store_settings = config.store.clone();
    let seed_store = RelayStoreHandle::open(
        store_settings
            .clone()
            .into_store_config(test_receipt_identity())
            .expect("seed Store config"),
    )
    .await
    .expect("open seed Store");
    let relay_server_id = seed_store.relay_server_id();
    let owner = seed_machine(&seed_store, relay_server_id, 0x21).await;
    let foreign = seed_machine(&seed_store, relay_server_id, 0x41).await;
    seed_store.shutdown().await.expect("shutdown seed Store");

    let handle = RelayV2ServerHandle::start(config)
        .await
        .expect("start real DirectTLS Relay v2 server");
    let mut owner_socket = connect(handle.public_addr()).await;
    authenticate_machine(&mut owner_socket, &owner).await;

    let route = StreamRouteId::from_bytes([0x51; 16]);
    let generation = StreamGenerationId::from_bytes([0x52; 16]);
    owner_socket
        .send(Message::Binary(
            encode(&outer(RelayFrameBody::RegisterStream(RegisterStream {
                machine_route: owner.machine_route,
                stream_route: route,
                generation,
            })))
            .into(),
        ))
        .await
        .expect("register stream through production WSS/Core");

    let plaintext = serde_json::to_vec(&json!({
        "machine": SENTINELS[0],
        "session": SENTINELS[1],
        "prompt": SENTINELS[2],
        "output": SENTINELS[3],
        "approval": SENTINELS[4],
        "vendorRef": SENTINELS[5],
    }))
    .expect("encode endpoint-only payload");
    for sentinel in SENTINELS {
        assert!(contains(&plaintext, sentinel.as_bytes()));
    }

    let context = OuterContextV1 {
        frame_kind: OuterFrameKind::ConversationPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(owner.machine_route),
        device_route: None,
        stream_route: Some(route),
        request_route: None,
        pair_route: None,
        stream_generation: Some(generation),
        stream_cursor: None,
        stream_seq: Some(0),
        message_key_epoch: 7,
    };
    let key_id = KeyId {
        purpose: KeyPurpose::ConversationDek,
        epoch: 7,
    };
    let sending_key = AeadSendingKey::new(
        key_id,
        7,
        9,
        [0xa1, 0xb2, 0xc3, 0xd4],
        SecretAeadKey::from_bytes(CONTENT_KEY),
    );
    let unsigned = seal_symmetric(
        &sending_key,
        &context,
        SealedPayloadKind::ConversationEvent,
        &plaintext,
        SenderCounter(0),
    )
    .expect("seal endpoint payload with real ChaCha20-Poly1305");
    let signed = sign_sealed(unsigned, &owner.data, &context);
    let sealed_wire = signed.to_wire_bytes();
    let verified = verify_sealed(signed, &owner.data.verifying_key(), &context)
        .expect("verify real MachineDataSign sender signature");
    assert_eq!(
        open_symmetric(
            &AeadReceivingKey::new(key_id, 7, SecretAeadKey::from_bytes(CONTENT_KEY)),
            &context,
            verified,
        )
        .expect("open real ChaCha20-Poly1305 payload"),
        plaintext
    );

    let publish_outer = outer(RelayFrameBody::Publish(Publish {
        stream_route: route,
        generation,
        stream_seq: 0,
        sealed_blob: SealedBlob(sealed_wire.clone()),
    }));
    let canonical_outer = encode(&publish_outer);
    assert_eq!(
        decode(&canonical_outer).expect("decode canonical publish"),
        publish_outer
    );
    assert!(contains(&canonical_outer, &sealed_wire));
    assert_eq!(
        assert_no_plaintext("canonical Relay outer", &canonical_outer),
        0
    );
    owner_socket
        .send(Message::Binary(canonical_outer.clone().into()))
        .await
        .expect("publish signed ciphertext through production WSS/Core");
    let accepted = receive_frame(&mut owner_socket).await;
    assert!(matches!(
        accepted.body,
        RelayFrameBody::RouteAccepted(ref accepted)
            if accepted.accepted == AcceptedRef::StreamFrame {
                stream_route: route,
                stream_seq: 0,
            }
    ));
    let accepted_wire = encode(&accepted);

    // 第二个真实 Challenge-authenticated machine 即使知道 route/generation，也不能写入。
    let mut foreign_socket = connect(handle.public_addr()).await;
    authenticate_machine(&mut foreign_socket, &foreign).await;
    foreign_socket
        .send(Message::Binary(
            encode(&outer(RelayFrameBody::Publish(Publish {
                stream_route: route,
                generation,
                stream_seq: 1,
                sealed_blob: SealedBlob(sealed_wire.clone()),
            })))
            .into(),
        ))
        .await
        .expect("send cross-machine takeover attempt");
    let rejection = receive_frame(&mut foreign_socket).await;
    let RelayFrameBody::Error(ref failure) = rejection.body else {
        panic!("foreign machine must receive typed Relay failure");
    };
    assert_eq!(failure.code, RELAY_ROUTE_NOT_FOUND);
    let rejection_wire = encode(&rejection);

    let (health_status, health_body) =
        http_get(format!("http://{}/healthz", handle.health_addr())).await;
    assert_eq!(health_status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&health_body).unwrap()["status"],
        "ok"
    );
    let (ready_status, ready_body) =
        http_get(format!("http://{}/readyz", handle.health_addr())).await;
    assert_eq!(ready_status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&ready_body).unwrap()["status"],
        "ready"
    );
    // 当前 Relay 没有 metrics exporter；固定 404 本身是 surface contract，不能伪造空指标。
    let (metrics_status, metrics_body) =
        http_get(format!("http://{}/metrics", handle.health_addr())).await;
    assert_eq!(metrics_status, 404);

    // 让生产拒绝路径产生一条正向结构化日志，再证明它只含 event/failure code。
    let mut plaintext_socket = connect(handle.public_addr()).await;
    plaintext_socket
        .send(Message::Text(
            String::from_utf8(plaintext.clone())
                .expect("endpoint JSON is UTF-8")
                .into(),
        ))
        .await
        .expect("send forbidden text frame");
    assert_rejected_without_application_binary(plaintext_socket).await;

    // SQL 行是 ciphertext 确实由 WSS/Core 持久化的正证据；COUNT=1 同时证明 takeover 零写。
    let connection = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open live Relay DB read-only");
    let (frame_count, persisted_blob): (u64, Vec<u8>) = connection
        .query_row("SELECT COUNT(*), sealed_blob FROM frames", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("read exact persisted ciphertext");
    assert_eq!(frame_count, 1);
    assert_eq!(persisted_blob, sealed_wire);
    drop(connection);

    let mut sqlite_files = raw_sqlite_files(&db_path);
    assert!(
        sqlite_files
            .iter()
            .any(|(_, bytes)| contains(bytes, &sealed_wire)),
        "positive evidence: exact signed ciphertext must exist in DB or WAL"
    );

    owner_socket.close(None).await.expect("close owner WSS");
    foreign_socket.close(None).await.expect("close foreign WSS");
    handle.shutdown().await.expect("shutdown security Relay");
    sqlite_files.extend(raw_sqlite_files(&db_path));

    // 关闭网络服务后重开同一真实 Store，以 byte-exact replay 证明 durability。
    let reopened = RelayStoreHandle::open(
        store_settings
            .into_store_config(test_receipt_identity())
            .expect("reopen Store config"),
    )
    .await
    .expect("reopen production Store");
    let replay = reopened
        .replay_page(ReplayPageRequest {
            machine_route: owner.machine_route,
            stream_route: route,
            generation,
            position: ReplayPosition::Start(StreamCursor::BeforeFirst),
            page_max_frames: 8,
            page_max_bytes: 8 * 1024 * 1024,
        })
        .await
        .expect("replay production-WSS persisted frame");
    assert_eq!(replay.frames.len(), 1);
    assert_eq!(replay.frames[0].sealed_blob, sealed_wire);
    assert_eq!(replay.frames[0].frame_hash, sha256(&canonical_outer));
    reopened.shutdown().await.expect("shutdown reopened Store");

    let logs = capture.bytes();
    let rendered_logs = String::from_utf8_lossy(&logs);
    assert!(rendered_logs.contains("relay.frame.rejected"));
    assert!(rendered_logs.contains("failure_code"));

    let http_surface = [health_body, ready_body, metrics_body].concat();
    let mut plaintext_matches = 0;
    for (name, bytes) in [
        ("canonical Relay outer", canonical_outer.as_slice()),
        ("RouteAccepted wire", accepted_wire.as_slice()),
        ("cross-machine failure wire", rejection_wire.as_slice()),
        ("structured logs", logs.as_slice()),
        ("health/ready/metrics HTTP", http_surface.as_slice()),
    ] {
        plaintext_matches += assert_no_plaintext(name, bytes);
    }
    for (path, bytes) in &sqlite_files {
        plaintext_matches += assert_no_plaintext(&path.display().to_string(), bytes);
    }
    assert_eq!(plaintext_matches, 0);
    eprintln!(
        "relay-v2-security-sentinel: 0 plaintext matches in outer + logs + HTTP/metrics + SQLite DB/WAL; production WSS ciphertext persisted and replayed"
    );
}
