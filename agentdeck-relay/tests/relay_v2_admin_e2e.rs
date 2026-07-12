#![cfg(all(feature = "server", feature = "tls", unix))]

use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{SigningKey, VerifyingKey, sha256, sign_tbs};
use agentdeck_protocol::relay_v2::{
    CertRole, Ed25519Signature, EnrollmentCode, LinkGeneration, MachineEnrollmentRequestV1,
    MachineEnrollmentResponseV1, MachineRouteId, PublicKeyBytes, RelayServerId, RootKeyId,
    SignedCertificate, TrustEpoch,
};
use agentdeck_relay::config::{
    RelayV2AdminConfig, RelayV2ServerConfig, RelayV2StoreSettings, RelayV2TlsPaths,
    RelayV2TransportMode,
};
use agentdeck_relay::v2::admin::AdminClient;
use agentdeck_relay::v2::admin::protocol::{
    AdminRequest, AdminResponse, AdminResult, Digest32, EnrollmentBundleV1, MAX_ADMIN_LINE_BYTES,
};
use agentdeck_relay::v2::server::tls::{TlsIdentityPaths, load_tls_identity};
use agentdeck_relay::v2::server::{RelayV2ServerError, RelayV2ServerHandle};
use rusqlite::{Connection, OpenFlags, params};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::TlsConnector;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_CERT_PEM: &[u8] = include_bytes!("fixtures/test_cert.pem");

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis()
        .try_into()
        .expect("timestamp fits u64")
}

fn ensure_crypto_provider() -> WebPkiSupportedAlgorithms {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    rustls::crypto::CryptoProvider::get_default()
        .expect("rustls crypto provider")
        .signature_verification_algorithms
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
                "test exact-certificate mismatch".to_owned(),
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

fn tls_connector() -> TlsConnector {
    let expected_der = CertificateDer::from_pem_slice(TEST_CERT_PEM)
        .expect("parse test certificate")
        .as_ref()
        .to_vec();
    let verifier = ExactCertificateVerifier {
        expected_der,
        algorithms: ensure_crypto_provider(),
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn https_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let tcp = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("TCP connect timeout")
        .expect("TCP connect");
    let server_name = ServerName::try_from("localhost")
        .expect("server name")
        .to_owned();
    let mut tls = tokio::time::timeout(IO_TIMEOUT, tls_connector().connect(server_name, tcp))
        .await
        .expect("TLS timeout")
        .expect("TLS handshake");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(request.as_bytes())
        .await
        .expect("write headers");
    tls.write_all(body).await.expect("write body");
    tls.flush().await.expect("flush request");
    let mut response = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, tls.read_to_end(&mut response))
        .await
        .expect("HTTP read timeout")
        .expect("read HTTP response");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response separator");
    let headers = std::str::from_utf8(&response[..split]).expect("HTTP headers UTF-8");
    let status = headers
        .lines()
        .next()
        .expect("status line")
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    (status, response[split + 4..].to_vec())
}

fn signed_certificate(
    root: &SigningKey,
    subject: &SigningKey,
    server: RelayServerId,
    route: MachineRouteId,
    role: CertRole,
    seed: u8,
) -> SignedCertificate {
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
        cert_role: role,
        generation: LinkGeneration::new(1),
        root_key_id: RootKeyId::from_bytes([seed; 16]),
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: Some(unix_now_ms() + 60_000),
        signature: Ed25519Signature([0; 64]),
    };
    certificate.signature = sign_tbs(
        root,
        &certificate.to_be_signed_v1(server, route, sha256(&root.verifying_key().to_bytes())),
    )
    .into();
    certificate
}

fn enrollment_request(
    code: EnrollmentCode,
    server: RelayServerId,
    route_seed: u8,
) -> (MachineEnrollmentRequestV1, [u8; 32]) {
    let route = MachineRouteId::from_bytes([route_seed; 16]);
    let root = SigningKey::from_seed(&[route_seed.wrapping_add(1); 32]);
    let link = SigningKey::from_seed(&[route_seed.wrapping_add(2); 32]);
    let data = SigningKey::from_seed(&[route_seed.wrapping_add(3); 32]);
    let root_pubkey = root.verifying_key().to_bytes();
    (
        MachineEnrollmentRequestV1 {
            code,
            machine_route: route,
            root_pubkey: PublicKeyBytes(root_pubkey),
            link_cert: signed_certificate(&root, &link, server, route, CertRole::Link, route_seed),
            data_cert: signed_certificate(&root, &data, server, route, CertRole::Data, route_seed),
        },
        sha256(&root_pubkey),
    )
}

async fn create_bundle(client: &AdminClient) -> EnrollmentBundleV1 {
    match client
        .request(&AdminRequest::MachineEnrollCreate {})
        .await
        .expect("admin create request")
    {
        AdminResponse::Ok {
            result: AdminResult::EnrollmentBundle { bundle },
        } => bundle,
        other => panic!("unexpected admin response: {other:?}"),
    }
}

async fn start_server(temp: &TempDir) -> (RelayV2ServerHandle, PathBuf, PathBuf, [u8; 32]) {
    let cert = fixture("test_cert.pem");
    let key = fixture("test_key.pem");
    let identity = load_tls_identity(&TlsIdentityPaths::new(&cert, &key))
        .await
        .expect("load test identity");
    let pin = identity.leaf_spki_sha256();
    let storage = temp.path().join("relay-private").join("relay.db");
    let admin_dir = temp.path().join("admin-private");
    std::fs::create_dir(&admin_dir).expect("create admin directory");
    std::fs::set_permissions(&admin_dir, std::fs::Permissions::from_mode(0o700))
        .expect("secure admin directory");
    let socket = admin_dir.join("relay.sock");
    let mut store = RelayV2StoreSettings::new(storage.clone());
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    let config = RelayV2ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        health_bind: "127.0.0.1:0".parse().unwrap(),
        store,
        transport: RelayV2TransportMode::DirectTls(RelayV2TlsPaths { cert, key }),
        admin: Some(RelayV2AdminConfig {
            socket_path: socket.clone(),
            public_wss_url: "wss://relay.example.test/".to_owned(),
            spki_pins: vec![pin],
        }),
        log_level: "info".to_owned(),
    };
    let handle = RelayV2ServerHandle::start(config)
        .await
        .expect("start Relay v2 admin server");
    (handle, storage, socket, pin)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_uds_and_tls_enrollment_are_one_shot_exact_and_fingerprint_bound() {
    let temp = TempDir::new().expect("tempdir");
    let (handle, storage, socket, pin) = start_server(&temp).await;
    let metadata = std::fs::symlink_metadata(&socket).expect("admin socket metadata");
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(handle.admin_socket_path(), Some(socket.as_path()));
    let client = AdminClient::new(&socket);

    let bundle = create_bundle(&client).await;
    assert_eq!(bundle.public_wss_url, "wss://relay.example.test/");
    assert_eq!(bundle.spki_pins, vec![Digest32(pin)]);
    assert!(bundle.expires_at_ms > unix_now_ms());
    assert!(bundle.expires_at_ms <= unix_now_ms() + 5 * 60 * 1_000);

    let readonly = Connection::open_with_flags(
        &storage,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open read-only Relay DB");
    let stored_hash: Vec<u8> = readonly
        .query_row(
            "SELECT code_hash FROM enrollment_codes WHERE code_hash = ?1",
            params![sha256(&bundle.code.0).as_slice()],
            |row| row.get(0),
        )
        .expect("stored enrollment code hash");
    assert_eq!(stored_hash, sha256(&bundle.code.0));
    assert_ne!(stored_hash, bundle.code.0);

    let (request, root_fingerprint) = enrollment_request(bundle.code, bundle.relay_server_id, 0x31);
    let encoded = serde_json::to_vec(&request).expect("encode enrollment request");
    let (status, first_body) =
        https_request(handle.public_addr(), "POST", "/v2/machine-enroll", &encoded).await;
    assert_eq!(status, 200);
    let response: MachineEnrollmentResponseV1 =
        serde_json::from_slice(&first_body).expect("decode enrollment response");
    assert_eq!(response.machine_route, request.machine_route);
    assert_eq!(response.relay_server_id, bundle.relay_server_id);

    let (status, replay_body) =
        https_request(handle.public_addr(), "POST", "/v2/machine-enroll", &encoded).await;
    assert_eq!(status, 200);
    assert_eq!(
        replay_body, first_body,
        "retry must replay exact frozen bytes"
    );

    let (different, _) = enrollment_request(bundle.code, bundle.relay_server_id, 0x32);
    let (status, _) = https_request(
        handle.public_addr(),
        "POST",
        "/v2/machine-enroll",
        &serde_json::to_vec(&different).unwrap(),
    )
    .await;
    assert_eq!(
        status, 403,
        "same code with a different canonical hash rejects"
    );

    let inventory = client
        .request(&AdminRequest::MachineInventory { after: None })
        .await
        .expect("inventory request");
    match inventory {
        AdminResponse::Ok {
            result: AdminResult::MachineInventory { page },
        } => {
            assert_eq!(page.entries.len(), 1);
            assert_eq!(page.entries[0].machine_route, request.machine_route);
            assert_eq!(page.entries[0].root_fingerprint, Digest32(root_fingerprint));
        }
        other => panic!("unexpected inventory response: {other:?}"),
    }
    let cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentdeck-relay"))
        .args([
            "--admin-socket",
            socket.to_str().expect("socket path UTF-8"),
            "machine",
            "inventory",
        ])
        .output()
        .await
        .expect("run same-binary admin CLI");
    assert!(cli.status.success(), "admin CLI stderr: {:?}", cli.stderr);
    assert!(cli.stderr.is_empty());
    assert!(matches!(
        serde_json::from_slice::<AdminResponse>(&cli.stdout)
            .expect("CLI stdout is one JSON object"),
        AdminResponse::Ok {
            result: AdminResult::MachineInventory { .. }
        }
    ));
    let route_wire = serde_json::to_string(&request.machine_route).expect("route wire");
    let fingerprint_wire =
        serde_json::to_string(&Digest32(root_fingerprint)).expect("fingerprint wire");
    let readback_cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentdeck-relay"))
        .args([
            "--admin-socket",
            socket.to_str().expect("socket path UTF-8"),
            "machine",
            "readback",
            route_wire.trim_matches('"'),
            "--confirm",
            fingerprint_wire.trim_matches('"'),
        ])
        .output()
        .await
        .expect("run same-binary readback CLI");
    assert!(
        readback_cli.status.success(),
        "readback CLI stderr: {:?}",
        readback_cli.stderr
    );
    assert!(matches!(
        serde_json::from_slice::<AdminResponse>(&readback_cli.stdout)
            .expect("readback CLI stdout JSON"),
        AdminResponse::Ok {
            result: AdminResult::MachineReadback { .. }
        }
    ));
    let invalid_cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentdeck-relay"))
        .args([
            "machine",
            "purge",
            "not-a-route",
            "--confirm",
            fingerprint_wire.trim_matches('"'),
            "--admin-socket",
            socket.to_str().expect("socket path UTF-8"),
        ])
        .output()
        .await
        .expect("run invalid admin CLI");
    assert_eq!(invalid_cli.status.code(), Some(2));
    assert!(invalid_cli.stdout.is_empty());
    assert_eq!(
        std::str::from_utf8(&invalid_cli.stderr).expect("stable CLI stderr"),
        "relay.admin.cli_value_invalid\n"
    );

    let wrong_readback = client
        .request(&AdminRequest::MachineReadback {
            machine_route: request.machine_route,
            confirm_root_fingerprint: Digest32([0xff; 32]),
        })
        .await
        .expect("wrong readback request");
    assert!(matches!(wrong_readback, AdminResponse::Error { .. }));
    let wrong_purge = client
        .request(&AdminRequest::MachinePurge {
            machine_route: request.machine_route,
            confirm_root_fingerprint: Digest32([0xff; 32]),
        })
        .await
        .expect("wrong purge request");
    assert!(matches!(wrong_purge, AdminResponse::Error { .. }));

    let purged = client
        .request(&AdminRequest::MachinePurge {
            machine_route: request.machine_route,
            confirm_root_fingerprint: Digest32(root_fingerprint),
        })
        .await
        .expect("confirmed purge");
    match purged {
        AdminResponse::Ok {
            result: AdminResult::MachinePurged { readback },
        } => {
            assert_eq!(readback.active_machine_routes, 0);
            assert_eq!(readback.retired_tombstones, 1);
            assert_eq!(readback.device_grants, 0);
            assert_eq!(readback.streams, 0);
            assert_eq!(readback.frames, 0);
        }
        other => panic!("unexpected purge response: {other:?}"),
    }
    let readback = client
        .request(&AdminRequest::MachineReadback {
            machine_route: request.machine_route,
            confirm_root_fingerprint: Digest32(root_fingerprint),
        })
        .await
        .expect("confirmed readback");
    assert!(matches!(
        readback,
        AdminResponse::Ok {
            result: AdminResult::MachineReadback { .. }
        }
    ));

    // 合法 MachineRoot 签入不可解析 endpoint key 时必须在消费 code 前拒绝；修复请求
    // 随后仍能用同一 code 成功登记，证明拒绝发生在 SQLite transaction 之前。
    let invalid_subject_bundle = create_bundle(&client).await;
    let (valid_after_subject_rejection, _) = enrollment_request(
        invalid_subject_bundle.code,
        invalid_subject_bundle.relay_server_id,
        0x41,
    );
    let mut invalid_subject = valid_after_subject_rejection.clone();
    let invalid_key = (0_u8..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
        .expect("at least one invalid compressed Edwards point");
    invalid_subject.link_cert.subject_pubkey = PublicKeyBytes(invalid_key);
    let root = SigningKey::from_seed(&[0x42; 32]);
    invalid_subject.link_cert.signature = sign_tbs(
        &root,
        &invalid_subject.link_cert.to_be_signed_v1(
            invalid_subject_bundle.relay_server_id,
            invalid_subject.machine_route,
            sha256(&root.verifying_key().to_bytes()),
        ),
    )
    .into();
    let (status, _) = https_request(
        handle.public_addr(),
        "POST",
        "/v2/machine-enroll",
        &serde_json::to_vec(&invalid_subject).unwrap(),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = https_request(
        handle.public_addr(),
        "POST",
        "/v2/machine-enroll",
        &serde_json::to_vec(&valid_after_subject_rejection).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "invalid endpoint key cannot consume the code");

    let bad_signature_bundle = create_bundle(&client).await;
    let (valid_after_signature_rejection, _) = enrollment_request(
        bad_signature_bundle.code,
        bad_signature_bundle.relay_server_id,
        0x51,
    );
    let mut bad_signature = valid_after_signature_rejection.clone();
    bad_signature.data_cert.signature.0[0] ^= 0x80;
    let (status, _) = https_request(
        handle.public_addr(),
        "POST",
        "/v2/machine-enroll",
        &serde_json::to_vec(&bad_signature).unwrap(),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = https_request(
        handle.public_addr(),
        "POST",
        "/v2/machine-enroll",
        &serde_json::to_vec(&valid_after_signature_rejection).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "invalid signature cannot consume the code");

    let raced_bundle = create_bundle(&client).await;
    let (raced_a, _) = enrollment_request(raced_bundle.code, raced_bundle.relay_server_id, 0x61);
    let (raced_b, _) = enrollment_request(raced_bundle.code, raced_bundle.relay_server_id, 0x62);
    let address = handle.public_addr();
    let encoded_a = serde_json::to_vec(&raced_a).unwrap();
    let encoded_b = serde_json::to_vec(&raced_b).unwrap();
    let (raced_a, raced_b) = tokio::join!(
        https_request(address, "POST", "/v2/machine-enroll", &encoded_a),
        https_request(address, "POST", "/v2/machine-enroll", &encoded_b),
    );
    let mut statuses = [raced_a.0, raced_b.0];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 403], "one-shot code race has one winner");

    let oversized = vec![b'x'; MAX_ADMIN_LINE_BYTES + 1];
    let mut raw = UnixStream::connect(&socket)
        .await
        .expect("raw admin connect");
    raw.write_all(&oversized)
        .await
        .expect("write oversized line");
    raw.write_all(b"\n").await.expect("finish oversized line");
    let mut rejection = Vec::new();
    raw.read_to_end(&mut rejection)
        .await
        .expect("read rejection");
    let rejection = std::str::from_utf8(&rejection).expect("JSONL rejection");
    assert!(
        rejection.contains("relay.admin.request_too_large"),
        "unexpected bounded rejection: {rejection:?}"
    );

    let huge_http = format!("{{\"padding\":\"{}\"}}", "x".repeat(64 * 1024));
    let (status, _) = https_request(
        handle.public_addr(),
        "POST",
        "/v2/machine-enroll",
        huge_http.as_bytes(),
    )
    .await;
    assert_eq!(status, 413);
    let (status, _) =
        https_request(handle.public_addr(), "POST", "/v2/machine-enroll/", b"{}").await;
    assert_eq!(status, 404, "enrollment endpoint never redirects");
    let (status, _) = https_request(handle.public_addr(), "POST", "/v2/machine-purge", b"{}").await;
    assert_eq!(
        status, 404,
        "purge is never exposed on the network listener"
    );
    let (status, _) =
        https_request(handle.public_addr(), "GET", "/v2/machine-inventory", b"").await;
    assert_eq!(status, 404, "inventory is local-UDS only");

    drop(readonly);
    handle.shutdown().await.expect("shutdown Relay");
    assert!(
        !socket.exists(),
        "admin socket is removed on clean shutdown"
    );
}

#[tokio::test]
async fn direct_tls_admin_pin_mismatch_fails_before_db_or_socket_side_effects() {
    let temp = TempDir::new().expect("tempdir");
    let admin_dir = temp.path().join("admin-private");
    std::fs::create_dir(&admin_dir).expect("create admin directory");
    std::fs::set_permissions(&admin_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let storage = temp.path().join("relay-private").join("relay.db");
    let socket = admin_dir.join("relay.sock");
    let config = RelayV2ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        health_bind: "127.0.0.1:0".parse().unwrap(),
        store: RelayV2StoreSettings::new(storage.clone()),
        transport: RelayV2TransportMode::DirectTls(RelayV2TlsPaths {
            cert: fixture("test_cert.pem"),
            key: fixture("test_key.pem"),
        }),
        admin: Some(RelayV2AdminConfig {
            socket_path: socket.clone(),
            public_wss_url: "wss://relay.example.test/".to_owned(),
            spki_pins: vec![[0xff; 32]],
        }),
        log_level: "info".to_owned(),
    };
    let error = match RelayV2ServerHandle::start(config).await {
        Ok(handle) => {
            let _ = handle.shutdown().await;
            panic!("wrong current pin must fail closed");
        }
        Err(error) => error,
    };
    assert!(matches!(
        error,
        RelayV2ServerError::Tls(agentdeck_relay::v2::server::tls::TlsIdentityError::PinMismatch)
    ));
    assert!(!storage.exists());
    assert!(!socket.exists());
}
