#![cfg(all(feature = "server", feature = "tls"))]

mod support;

use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{SigningKey, sha256, sign_authentication_transcript, sign_tbs};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, CertRole,
};
use agentdeck_protocol::relay_v2::failure::{RELAY_ROUTE_FORBIDDEN, RELAY_ROUTE_NOT_FOUND};
use agentdeck_protocol::relay_v2::frame::{
    AuthProof, Authenticate, ClosePairRoute, Hello, OpenPairRoute, PairData, PairRouteCloseOutcome,
    PairingHello, RevocationCommitted, SealedBlob, Subscribe,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, LinkGeneration,
    MAX_FRAME_BYTES, MachineRouteId, OpaqueRouteFrame, PairRouteId, PublicKeyBytes,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayGrant, RelayServerId, RootKeyId,
    SignedCertificate, StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
    relay_frame_reply_reference,
};
use agentdeck_relay::config::{
    RelayV2ServerConfig, RelayV2StoreSettings, RelayV2TlsPaths, RelayV2TransportMode,
};
use agentdeck_relay::v2::server::{self, RelayV2ServerHandle};
use agentdeck_relay::v2::store::{
    EnrollmentCodeSeed, InstallGrantRecord, PersistRevocation, RegisterMachine, RelayStoreHandle,
    StoreError,
};
use agentdeck_relay_client::{
    LinkAuthenticator, RelayClient as RelayV2Client, RelayClientConfig as RelayV2ClientConfig,
    RelayClientError as RelayV2ClientError, RelayTlsPolicy,
};
use async_trait::async_trait;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};
use tracing_subscriber::fmt::MakeWriter;
use x509_parser::prelude::{FromDer, X509Certificate};

use support::{test_receipt_identity, write_test_receipt_signing_key};

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const TEST_CERT_PEM: &[u8] = include_bytes!("fixtures/test_cert.pem");

type TestSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct SeededRealm {
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    link: SigningKey,
    device: SigningKey,
    link_cert: SignedCertificate,
    grant: RelayGrant,
    expected_revocation_terminal: Option<OpaqueRouteFrame>,
}

impl SeededRealm {
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
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
    ) -> Authenticate {
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::Device,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.machine_route,
            device_route: Some(self.device_route),
            serial_or_generation: self.grant.grant_serial.value(),
            credential_sha256: self.grant.canonical_sha256(),
        };
        Authenticate {
            proof: AuthProof::Device {
                relay_grant: self.grant.clone(),
            },
            signature: sign_authentication_transcript(&self.device, &transcript).into(),
        }
    }
}

struct ClientMachineAuthenticator {
    realm: Arc<SeededRealm>,
}

#[async_trait]
impl LinkAuthenticator for ClientMachineAuthenticator {
    fn proof(&self) -> AuthProof {
        AuthProof::MachineLink {
            machine_route: self.realm.machine_route,
            link_cert: self.realm.link_cert.clone(),
        }
    }

    async fn authenticate(
        &self,
        challenge: &agentdeck_protocol::relay_v2::frame::Challenge,
    ) -> Result<Authenticate, RelayV2ClientError> {
        Ok(self.realm.machine_authenticate(challenge))
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
    fn rendered(&self) -> String {
        String::from_utf8(
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .expect("captured tracing is UTF-8")
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

fn exact_cert_connector(expected_der: Vec<u8>) -> Connector {
    let verifier = ExactCertificateVerifier {
        expected_der,
        algorithms: ensure_crypto_provider(),
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

async fn connect_result(
    address: SocketAddr,
    path: &str,
    expected_der: Vec<u8>,
) -> Result<(TestSocket, Response), WsError> {
    let request = format!("wss://{address}{path}")
        .into_client_request()
        .expect("valid WSS request");
    connect_async_tls_with_config(
        request,
        None,
        false,
        Some(exact_cert_connector(expected_der)),
    )
    .await
}

async fn connect(address: SocketAddr) -> TestSocket {
    connect_path(address, "/v2/connect").await
}

async fn connect_path(address: SocketAddr, path: &str) -> TestSocket {
    timeout(
        IO_TIMEOUT,
        connect_result(address, path, test_certificate_der()),
    )
    .await
    .expect("WSS handshake timeout")
    .expect("WSS handshake with exact certificate pin")
    .0
}

fn hello() -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        }),
    }
}

async fn receive_binary(socket: &mut TestSocket) -> Vec<u8> {
    timeout(IO_TIMEOUT, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(bytes))) => {
                    return bytes.to_vec();
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

async fn receive_relay_frame(socket: &mut TestSocket) -> OpaqueRouteFrame {
    decode(&receive_binary(socket).await).expect("canonical Relay v2 binary frame")
}

async fn hello_challenge(
    socket: &mut TestSocket,
) -> agentdeck_protocol::relay_v2::frame::Challenge {
    socket
        .send(Message::Binary(encode(&hello()).into()))
        .await
        .expect("send binary Hello");
    let RelayFrameBody::Challenge(challenge) = receive_relay_frame(socket).await.body else {
        panic!("Hello must yield Challenge");
    };
    challenge
}

async fn authenticate_machine(socket: &mut TestSocket, realm: &SeededRealm) {
    let challenge = hello_challenge(socket).await;
    let authenticate = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Authenticate(realm.machine_authenticate(&challenge)),
    };
    socket
        .send(Message::Binary(encode(&authenticate).into()))
        .await
        .expect("send MachineLink Authenticate");
    assert!(matches!(
        receive_relay_frame(socket).await.body,
        RelayFrameBody::Authenticated(_)
    ));
}

async fn open_pair_route(
    socket: &mut TestSocket,
    realm: &SeededRealm,
    pair_route: PairRouteId,
    absolute_expiry_ms: u64,
) {
    socket
        .send(Message::Binary(
            encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::OpenPairRoute(OpenPairRoute {
                    machine_route: realm.machine_route,
                    pair_route,
                    absolute_expiry_ms,
                }),
            })
            .into(),
        ))
        .await
        .expect("send real Relay OpenPairRoute");
    let RelayFrameBody::PairRouteOpened(opened) = receive_relay_frame(socket).await.body else {
        panic!("real Relay must acknowledge OpenPairRoute");
    };
    assert_eq!(opened.machine_route, realm.machine_route);
    assert_eq!(opened.pair_route, pair_route);
    assert_eq!(opened.absolute_expiry_ms, absolute_expiry_ms);
}

async fn connect_pairing_route(
    address: SocketAddr,
    realm: &SeededRealm,
    pair_route: PairRouteId,
) -> TestSocket {
    let mut pairing = connect_path(address, "/v2/pair").await;
    pairing
        .send(Message::Binary(encode(&hello()).into()))
        .await
        .expect("send pairing Hello");
    pairing
        .send(Message::Binary(
            encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::PairingHello(PairingHello {
                    relay_server_id: realm.relay_server_id,
                    pair_route,
                }),
            })
            .into(),
        ))
        .await
        .expect("send PairingHello");
    assert!(matches!(
        receive_relay_frame(&mut pairing).await.body,
        RelayFrameBody::Authenticated(_)
    ));
    pairing
}

async fn assert_rejected_without_application_binary(mut socket: TestSocket) {
    timeout(IO_TIMEOUT, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(Message::Binary(bytes))) => {
                    panic!("rejected input produced application binary: {bytes:?}")
                }
                Some(Ok(Message::Text(text))) => {
                    panic!("Relay v2 emitted forbidden text: {text}")
                }
                Some(Ok(Message::Frame(_))) => unreachable!("raw frames are not surfaced"),
            }
        }
    })
    .await
    .expect("rejected WebSocket did not close promptly");
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

async fn start_server(temp: &TempDir) -> (RelayV2ServerHandle, PathBuf) {
    let (config, storage_path) = server_config(temp);
    let handle = RelayV2ServerHandle::start(config)
        .await
        .expect("start Relay v2 TLS server");
    (handle, storage_path)
}

async fn http_get(url: String) -> (u16, String) {
    tokio::task::spawn_blocking(move || match ureq::get(&url).call() {
        Ok(response) => {
            let status = response.status();
            let body = response.into_string().expect("health response body");
            (status, body)
        }
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().expect("health failure body");
            (status, body)
        }
        Err(ureq::Error::Transport(error)) => {
            panic!("loopback health transport failed: {error}")
        }
    })
    .await
    .expect("join loopback health request")
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis()
        .try_into()
        .expect("unix millis fit u64")
}

#[allow(clippy::too_many_arguments)]
fn signed_certificate(
    root: &SigningKey,
    subject: &SigningKey,
    relay_server_id: RelayServerId,
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

fn signed_grant(
    root: &SigningKey,
    device: &SigningKey,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
) -> RelayGrant {
    let mut grant = RelayGrant {
        machine_route,
        device_route,
        device_sign_pubkey: PublicKeyBytes(device.verifying_key().to_bytes()),
        grant_serial: GrantSerial::new(1),
        root_key_id,
        trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    grant.signature = sign_tbs(
        root,
        &grant.to_be_signed_v1(relay_server_id, sha256(&root.verifying_key().to_bytes())),
    )
    .into();
    grant
}

async fn seed_realm(config: &RelayV2ServerConfig, revoked: bool) -> SeededRealm {
    let store = RelayStoreHandle::open(
        config
            .store
            .clone()
            .into_store_config(test_receipt_identity())
            .expect("seed Store config"),
    )
    .await
    .expect("open seed Store");
    let relay_server_id = store.relay_server_id();
    let machine_route = MachineRouteId::from_bytes([0x31; 16]);
    let device_route = DeviceRouteId::from_bytes([0x32; 16]);
    let root_key_id = RootKeyId::from_bytes([0x33; 16]);
    let trust_epoch = TrustEpoch::new(1);
    let root = SigningKey::from_seed(&[0x41; 32]);
    let link = SigningKey::from_seed(&[0x42; 32]);
    let data = SigningKey::from_seed(&[0x43; 32]);
    let device = SigningKey::from_seed(&[0x44; 32]);
    let link_cert = signed_certificate(
        &root,
        &link,
        relay_server_id,
        machine_route,
        root_key_id,
        trust_epoch,
        CertRole::Link,
    );
    let data_cert = signed_certificate(
        &root,
        &data,
        relay_server_id,
        machine_route,
        root_key_id,
        trust_epoch,
        CertRole::Data,
    );
    let code_hash = [0x51; 32];
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash,
            expires_at_ms: unix_now_ms().saturating_add(60_000),
        })
        .await
        .expect("seed machine enrollment");
    store
        .register_machine(RegisterMachine {
            code_hash,
            request_hash: [0x52; 32],
            machine_route,
            root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
            link_cert: link_cert.clone(),
            data_cert: data_cert.clone(),
            link_cert_hash: link_cert.canonical_sha256(),
            data_cert_hash: data_cert.canonical_sha256(),
        })
        .await
        .expect("register machine trust");
    let grant = signed_grant(
        &root,
        &device,
        relay_server_id,
        machine_route,
        device_route,
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

    let expected_revocation_terminal = if revoked {
        let mut revocation = DeviceRevocation {
            machine_route,
            device_route,
            grant_serial: grant.grant_serial,
            root_key_id,
            trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        revocation.signature = sign_tbs(
            &root,
            &revocation.to_be_signed_v1(relay_server_id, sha256(&root.verifying_key().to_bytes())),
        )
        .into();
        let terminal = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
                device_route,
                grant_serial: grant.grant_serial,
                signed_revocation: revocation.clone(),
            }),
        };
        store
            .revoke(PersistRevocation {
                revocation: revocation.clone(),
                revocation_hash: revocation.canonical_sha256(),
                signed_revocation_blob: encode(&terminal),
            })
            .await
            .expect("persist signed revocation terminal");
        Some(terminal)
    } else {
        None
    };
    store.shutdown().await.expect("shutdown seed Store");

    SeededRealm {
        relay_server_id,
        machine_route,
        device_route,
        link,
        device,
        link_cert,
        grant,
        expected_revocation_terminal,
    }
}

#[tokio::test]
async fn wss_uses_the_exact_pinned_certificate_and_binary_hello_yields_challenge() {
    let temp = TempDir::new().expect("tempdir");
    let (handle, _) = start_server(&temp).await;

    let mut wrong_pin = test_certificate_der();
    wrong_pin[0] ^= 0x01;
    let rejected = timeout(
        IO_TIMEOUT,
        connect_result(handle.public_addr(), "/v2/connect", wrong_pin),
    )
    .await
    .expect("wrong-pin handshake timeout");
    assert!(rejected.is_err(), "wrong exact-cert pin must fail closed");

    let mut socket = connect(handle.public_addr()).await;
    socket
        .send(Message::Binary(encode(&hello()).into()))
        .await
        .expect("send binary Hello");
    let challenge = receive_relay_frame(&mut socket).await;
    assert!(matches!(challenge.body, RelayFrameBody::Challenge(_)));

    socket.close(None).await.expect("close WSS client");
    handle.shutdown().await.expect("shutdown TLS server");
}

#[tokio::test]
async fn production_v2_client_authenticates_against_the_real_relay_listener() {
    let temp = TempDir::new().expect("tempdir");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate localhost TLS certificate");
    let cert_path = temp.path().join("client-e2e-cert.pem");
    let key_path = temp.path().join("client-e2e-key.pem");
    std::fs::write(&cert_path, certified.cert.pem()).expect("write test certificate");
    std::fs::write(&key_path, certified.key_pair.serialize_pem()).expect("write test key");
    let certificate_der = certified.cert.der().to_vec();
    let (_, certificate) =
        X509Certificate::from_der(&certificate_der).expect("parse test certificate");
    let spki_pin: [u8; 32] = Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into();

    let (mut config, _) = server_config(&temp);
    config.transport = RelayV2TransportMode::DirectTls(RelayV2TlsPaths {
        cert: cert_path,
        key: key_path,
    });
    let realm = Arc::new(seed_realm(&config, false).await);
    let handle = RelayV2ServerHandle::start(config)
        .await
        .expect("start real Relay listener");
    let client_config = RelayV2ClientConfig::new(
        &format!("wss://localhost:{}/", handle.public_addr().port()),
        realm.relay_server_id,
        RelayTlsPolicy::pinned_spki(vec![spki_pin]).expect("pinned policy"),
    )
    .expect("client config");
    let authenticator: Arc<dyn LinkAuthenticator> = Arc::new(ClientMachineAuthenticator {
        realm: Arc::clone(&realm),
    });
    let mut client = RelayV2Client::connect(client_config, authenticator)
        .await
        .expect("authenticate production client");
    let pair_route = PairRouteId::from_bytes([0xa7; 16]);
    client
        .send(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::OpenPairRoute(OpenPairRoute {
                machine_route: realm.machine_route,
                pair_route,
                absolute_expiry_ms: unix_now_ms().saturating_add(60_000),
            }),
        })
        .await
        .expect("flush OpenPairRoute through production client");
    let opened = timeout(IO_TIMEOUT, client.recv())
        .await
        .expect("production client receive timeout")
        .expect("production client receive")
        .expect("production listener frame");
    let RelayFrameBody::PairRouteOpened(opened) = opened.body else {
        panic!("production client must decode PairRouteOpened");
    };
    assert_eq!(opened.machine_route, realm.machine_route);
    assert_eq!(opened.pair_route, pair_route);

    drop(client);
    handle
        .shutdown()
        .await
        .expect("shutdown real Relay listener");
}

#[tokio::test]
async fn real_relay_terminal_miss_then_close_converges_for_offline_and_lost_ack_replay() {
    let temp = TempDir::new().expect("tempdir");
    let (config, _) = server_config(&temp);
    let realm = seed_realm(&config, false).await;
    let handle = RelayV2ServerHandle::start(config)
        .await
        .expect("start seeded real Relay server");
    let mut machine = connect(handle.public_addr()).await;
    authenticate_machine(&mut machine, &realm).await;

    // Active route，但 pairing requester 已离线：terminal PairData 返回 exact-correlated
    // not_found，随后同一 machine Close 仍必须提交 Closed。
    let offline_route = PairRouteId::from_bytes([0xd1; 16]);
    let offline_expiry = unix_now_ms().saturating_add(60_000);
    open_pair_route(&mut machine, &realm, offline_route, offline_expiry).await;
    let offline_terminal = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(PairData {
            pair_route: offline_route,
            sealed_blob: SealedBlob(vec![0xd1; 96]),
        }),
    };
    machine
        .send(Message::Binary(encode(&offline_terminal).into()))
        .await
        .expect("flush terminal toward offline pairing requester");
    let RelayFrameBody::Error(offline_error) = receive_relay_frame(&mut machine).await.body else {
        panic!("offline terminal replay must return correlated route error");
    };
    assert_eq!(offline_error.code, RELAY_ROUTE_NOT_FOUND);
    let offline_reference = relay_frame_reply_reference(&offline_terminal);
    assert_eq!(
        offline_error.in_reply_to.as_deref(),
        Some(offline_reference.as_str())
    );
    machine
        .send(Message::Binary(
            encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::ClosePairRoute(ClosePairRoute {
                    machine_route: realm.machine_route,
                    pair_route: offline_route,
                }),
            })
            .into(),
        ))
        .await
        .expect("close active route after terminal miss");
    let RelayFrameBody::PairRouteClosed(offline_closed) =
        receive_relay_frame(&mut machine).await.body
    else {
        panic!("terminal miss must not prevent Closed");
    };
    assert_eq!(offline_closed.pair_route, offline_route);
    assert_eq!(offline_closed.outcome, PairRouteCloseOutcome::Closed);

    // 第二条 route 让 pairing peer 作为 Relay COMMIT witness。machine Close ACK 不读取便
    // 丢弃连接；新 generation 重放 exact terminal 后应得到 correlated not_found，再由
    // Close 的 AlreadyAbsent 收敛，证明 tombstone + ACK lost/restart cut。
    let replay_route = PairRouteId::from_bytes([0xd2; 16]);
    let replay_expiry = unix_now_ms().saturating_add(60_000);
    open_pair_route(&mut machine, &realm, replay_route, replay_expiry).await;
    let mut pairing = connect_pairing_route(handle.public_addr(), &realm, replay_route).await;
    let replay_terminal = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(PairData {
            pair_route: replay_route,
            sealed_blob: SealedBlob(vec![0xd2; 96]),
        }),
    };
    machine
        .send(Message::Binary(encode(&replay_terminal).into()))
        .await
        .expect("flush terminal before close cut");
    assert_eq!(
        receive_relay_frame(&mut pairing).await,
        replay_terminal,
        "pairing peer witnesses terminal flush"
    );
    assert!(matches!(
        receive_relay_frame(&mut machine).await.body,
        RelayFrameBody::RouteAccepted(_)
    ));
    machine
        .send(Message::Binary(
            encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::ClosePairRoute(ClosePairRoute {
                    machine_route: realm.machine_route,
                    pair_route: replay_route,
                }),
            })
            .into(),
        ))
        .await
        .expect("flush Close whose machine ACK will be lost");
    let RelayFrameBody::PairRouteClosed(commit_witness) =
        receive_relay_frame(&mut pairing).await.body
    else {
        panic!("pairing peer must witness committed Close");
    };
    assert_eq!(commit_witness.pair_route, replay_route);
    assert_eq!(commit_witness.outcome, PairRouteCloseOutcome::Closed);
    drop(machine);
    drop(pairing);

    // Pairing 侧也在 Close ACK 丢失后重连：只有持有 exact tombstoned route 的
    // PairingHello 得到 canonical correlated failure，且该 failure flush 后断链。
    let mut pairing_retry = connect_path(handle.public_addr(), "/v2/pair").await;
    pairing_retry
        .send(Message::Binary(encode(&hello()).into()))
        .await
        .expect("send retry pairing Hello");
    let tombstone_hello = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairingHello(PairingHello {
            relay_server_id: realm.relay_server_id,
            pair_route: replay_route,
        }),
    };
    pairing_retry
        .send(Message::Binary(encode(&tombstone_hello).into()))
        .await
        .expect("send PairingHello for exact tombstone");
    let RelayFrameBody::Error(tombstone_error) = receive_relay_frame(&mut pairing_retry).await.body
    else {
        panic!("exact tombstone handshake must return a correlated failure");
    };
    assert_eq!(tombstone_error.code, RELAY_ROUTE_NOT_FOUND);
    let tombstone_reference = relay_frame_reply_reference(&tombstone_hello);
    assert_eq!(
        tombstone_error.in_reply_to.as_deref(),
        Some(tombstone_reference.as_str())
    );
    assert_rejected_without_application_binary(pairing_retry).await;

    // 未曾存在的 route 继续静默 fail-close，不能借同一 endpoint 构造 existence oracle。
    let mut unknown_pairing = connect_path(handle.public_addr(), "/v2/pair").await;
    unknown_pairing
        .send(Message::Binary(encode(&hello()).into()))
        .await
        .expect("send unknown-route pairing Hello");
    unknown_pairing
        .send(Message::Binary(
            encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::PairingHello(PairingHello {
                    relay_server_id: realm.relay_server_id,
                    pair_route: PairRouteId::from_bytes([0xde; 16]),
                }),
            })
            .into(),
        ))
        .await
        .expect("send unknown PairingHello");
    assert_rejected_without_application_binary(unknown_pairing).await;

    let mut wrong_server_pairing = connect_path(handle.public_addr(), "/v2/pair").await;
    wrong_server_pairing
        .send(Message::Binary(encode(&hello()).into()))
        .await
        .expect("send wrong-server pairing Hello");
    wrong_server_pairing
        .send(Message::Binary(
            encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::PairingHello(PairingHello {
                    relay_server_id: RelayServerId::from_bytes([0xdf; 16]),
                    pair_route: replay_route,
                }),
            })
            .into(),
        ))
        .await
        .expect("send exact tombstone under wrong Relay identity");
    assert_rejected_without_application_binary(wrong_server_pairing).await;

    let mut replacement = connect(handle.public_addr()).await;
    authenticate_machine(&mut replacement, &realm).await;
    replacement
        .send(Message::Binary(encode(&replay_terminal).into()))
        .await
        .expect("restart replays exact durable terminal");
    let RelayFrameBody::Error(replay_error) = receive_relay_frame(&mut replacement).await.body
    else {
        panic!("tombstone terminal replay must return correlated route error");
    };
    assert_eq!(replay_error.code, RELAY_ROUTE_NOT_FOUND);
    let replay_reference = relay_frame_reply_reference(&replay_terminal);
    assert_eq!(
        replay_error.in_reply_to.as_deref(),
        Some(replay_reference.as_str())
    );
    replacement
        .send(Message::Binary(
            encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::ClosePairRoute(ClosePairRoute {
                    machine_route: realm.machine_route,
                    pair_route: replay_route,
                }),
            })
            .into(),
        ))
        .await
        .expect("retry Close against real tombstone");
    let RelayFrameBody::PairRouteClosed(replayed_close) =
        receive_relay_frame(&mut replacement).await.body
    else {
        panic!("restart Close must return AlreadyAbsent");
    };
    assert_eq!(replayed_close.pair_route, replay_route);
    assert_eq!(replayed_close.outcome, PairRouteCloseOutcome::AlreadyAbsent);

    drop(replacement);
    handle.shutdown().await.expect("shutdown real Relay server");
}

#[tokio::test]
async fn authenticated_machine_receives_typed_recoverable_error_and_connection_remains_usable() {
    let temp = TempDir::new().expect("tempdir");
    let (config, _) = server_config(&temp);
    let realm = seed_realm(&config, false).await;
    let handle = RelayV2ServerHandle::start(config)
        .await
        .expect("start seeded Relay server");
    let mut socket = connect(handle.public_addr()).await;
    authenticate_machine(&mut socket, &realm).await;

    let forbidden = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Subscribe(Subscribe {
            stream_route: StreamRouteId::from_bytes([0x61; 16]),
            generation: StreamGenerationId::from_bytes([0x62; 16]),
            cursor: StreamCursor::BeforeFirst,
        }),
    };
    socket
        .send(Message::Binary(encode(&forbidden).into()))
        .await
        .expect("send role-forbidden but canonical frame");
    let RelayFrameBody::Error(error) = receive_relay_frame(&mut socket).await.body else {
        panic!("recoverable Core failure must be returned as binary Error");
    };
    assert_eq!(error.code, RELAY_ROUTE_FORBIDDEN);

    let pair_route = PairRouteId::from_bytes([0x63; 16]);
    let expiry = unix_now_ms().saturating_add(60_000);
    let allowed = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::OpenPairRoute(OpenPairRoute {
            machine_route: realm.machine_route,
            pair_route,
            absolute_expiry_ms: expiry,
        }),
    };
    socket
        .send(Message::Binary(encode(&allowed).into()))
        .await
        .expect("send valid frame after recoverable error");
    let RelayFrameBody::PairRouteOpened(opened) = receive_relay_frame(&mut socket).await.body
    else {
        panic!("connection must remain usable after recoverable Error");
    };
    assert_eq!(opened.machine_route, realm.machine_route);
    assert_eq!(opened.pair_route, pair_route);
    assert_eq!(opened.absolute_expiry_ms, expiry);

    let mut pairing = connect_path(handle.public_addr(), "/v2/pair").await;
    pairing
        .send(Message::Binary(encode(&hello()).into()))
        .await
        .expect("send pairing Hello");
    let pairing_hello = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairingHello(PairingHello {
            relay_server_id: realm.relay_server_id,
            pair_route,
        }),
    };
    pairing
        .send(Message::Binary(encode(&pairing_hello).into()))
        .await
        .expect("send binary PairingHello after TLS");
    assert!(matches!(
        receive_relay_frame(&mut pairing).await.body,
        RelayFrameBody::Authenticated(_)
    ));

    let pair_data = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(PairData {
            pair_route,
            sealed_blob: SealedBlob(vec![0x64, 0x65]),
        }),
    };
    pairing
        .send(Message::Binary(encode(&pair_data).into()))
        .await
        .expect("send PairData through activated pairing route");
    assert_eq!(
        receive_relay_frame(&mut socket).await,
        pair_data,
        "PairingHello must activate only the selected in-memory route"
    );
    assert!(matches!(
        receive_relay_frame(&mut pairing).await.body,
        RelayFrameBody::RouteAccepted(_)
    ));

    pairing.close(None).await.expect("close pairing WSS");

    for rejected in [
        PairingHello {
            relay_server_id: RelayServerId::from_bytes([0xff; 16]),
            pair_route,
        },
        PairingHello {
            relay_server_id: realm.relay_server_id,
            pair_route: PairRouteId::from_bytes([0xfe; 16]),
        },
    ] {
        let mut rejected_socket = connect_path(handle.public_addr(), "/v2/pair").await;
        rejected_socket
            .send(Message::Binary(encode(&hello()).into()))
            .await
            .expect("send rejected pairing Hello");
        rejected_socket
            .send(Message::Binary(
                encode(&OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION,
                    body: RelayFrameBody::PairingHello(rejected),
                })
                .into(),
            ))
            .await
            .expect("send rejected PairingHello");
        assert_rejected_without_application_binary(rejected_socket).await;
    }

    socket.close(None).await.expect("close authenticated WSS");
    handle.shutdown().await.expect("shutdown seeded server");
}

#[tokio::test]
async fn revoked_device_reauthentication_flushes_exact_persisted_terminal_before_close() {
    let temp = TempDir::new().expect("tempdir");
    let (config, _) = server_config(&temp);
    let realm = seed_realm(&config, true).await;
    let expected = realm
        .expected_revocation_terminal
        .clone()
        .expect("revoked fixture terminal");
    let expected_bytes = encode(&expected);
    let handle = RelayV2ServerHandle::start(config)
        .await
        .expect("start revoked Relay server");
    let mut socket = connect(handle.public_addr()).await;
    let challenge = hello_challenge(&mut socket).await;
    let authenticate = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Authenticate(realm.device_authenticate(&challenge)),
    };
    socket
        .send(Message::Binary(encode(&authenticate).into()))
        .await
        .expect("send revoked but possession-valid Authenticate");

    let actual = receive_binary(&mut socket).await;
    assert_eq!(actual, expected_bytes, "terminal replay must be byte-exact");
    assert_eq!(decode(&actual).expect("decode terminal replay"), expected);
    assert_rejected_without_application_binary(socket).await;

    handle.shutdown().await.expect("shutdown revoked server");
}

#[tokio::test]
async fn text_and_oversize_websocket_messages_are_rejected_without_application_output() {
    let temp = TempDir::new().expect("tempdir");
    let (handle, _) = start_server(&temp).await;

    let mut text = connect(handle.public_addr()).await;
    text.send(Message::Text(
        r#"{"frameKind":"hello","sensitive":"must-not-be-parsed"}"#.into(),
    ))
    .await
    .expect("send forbidden text");
    assert_rejected_without_application_binary(text).await;

    let mut oversized = connect(handle.public_addr()).await;
    let sent = oversized
        .send(Message::Binary(vec![0xA5; MAX_FRAME_BYTES + 1].into()))
        .await;
    if sent.is_ok() {
        assert_rejected_without_application_binary(oversized).await;
    }

    handle.shutdown().await.expect("shutdown TLS server");
}

#[tokio::test]
async fn public_listener_has_no_health_or_redirect_and_loopback_health_is_ready() {
    let temp = TempDir::new().expect("tempdir");
    let (handle, _) = start_server(&temp).await;

    for path in ["/healthz", "/readyz", "/unknown"] {
        let result = timeout(
            IO_TIMEOUT,
            connect_result(handle.public_addr(), path, test_certificate_der()),
        )
        .await
        .expect("public rejection timeout");
        let WsError::Http(response) = result.expect_err("public path must not upgrade") else {
            panic!("public unknown path must return direct HTTP rejection");
        };
        assert_eq!(response.status().as_u16(), 404);
        assert!(!response.status().is_redirection());
        assert!(response.headers().get("location").is_none());
    }

    for path in ["/v2/connect?legacy=1", "/v2/pair?pair_route=secret"] {
        let result = timeout(
            IO_TIMEOUT,
            connect_result(handle.public_addr(), path, test_certificate_der()),
        )
        .await
        .expect("query-carrier rejection timeout");
        let WsError::Http(response) = result.expect_err("query carrier must not upgrade") else {
            panic!("query carrier must return direct HTTP rejection");
        };
        assert_eq!(response.status().as_u16(), 400);
        assert!(!response.status().is_redirection());
        assert!(response.headers().get("location").is_none());
    }

    let (health_status, health_body) =
        http_get(format!("http://{}/healthz", handle.health_addr())).await;
    assert_eq!(health_status, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&health_body).unwrap()["status"],
        "ok"
    );
    let (ready_status, ready_body) =
        http_get(format!("http://{}/readyz", handle.health_addr())).await;
    assert_eq!(ready_status, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&ready_body).unwrap()["status"],
        "ready"
    );

    handle.shutdown().await.expect("shutdown TLS server");
}

#[tokio::test]
async fn health_stays_live_while_disk_low_degrades_readiness_and_restart_recovers() {
    let temp = TempDir::new().expect("tempdir");
    let (mut low_config, _) = server_config(&temp);
    low_config.store.disk_reserve_bytes = u64::MAX;
    let low = RelayV2ServerHandle::start(low_config)
        .await
        .expect("start disk-low Relay server");

    let (health_status, health_body) =
        http_get(format!("http://{}/healthz", low.health_addr())).await;
    assert_eq!(health_status, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&health_body).unwrap()["status"],
        "ok"
    );
    let (ready_status, ready_body) = http_get(format!("http://{}/readyz", low.health_addr())).await;
    assert_eq!(ready_status, 503);
    let ready = serde_json::from_str::<serde_json::Value>(&ready_body).unwrap();
    assert_eq!(ready["status"], "notReady");
    assert_eq!(ready["code"], "relay.disk.low");
    low.shutdown().await.expect("shutdown disk-low server");

    let (recovered_config, _) = server_config(&temp);
    let recovered = RelayV2ServerHandle::start(recovered_config)
        .await
        .expect("restart after disk reserve recovers");
    let (ready_status, ready_body) =
        http_get(format!("http://{}/readyz", recovered.health_addr())).await;
    assert_eq!(ready_status, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&ready_body).unwrap()["status"],
        "ready"
    );
    recovered
        .shutdown()
        .await
        .expect("shutdown recovered server");
}

#[tokio::test(flavor = "current_thread")]
async fn rejection_log_keeps_a_positive_event_but_never_includes_sensitive_frame_material() {
    const SENTINEL: &str = "AGENTDECK_RELAY_LOG_SENTINEL_7F3B2A91";

    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(capture.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    tracing::dispatcher::set_global_default(dispatch)
        .expect("TLS E2E owns the process-global tracing subscriber");

    let temp = TempDir::new().expect("tempdir");
    let (handle, _) = start_server(&temp).await;
    let full_route = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5A; 16]);
    let sentinel_base64 = base64::engine::general_purpose::STANDARD.encode(SENTINEL);
    let sentinel_hex = SENTINEL
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut socket = connect(handle.public_addr()).await;
    socket
        .send(Message::Text(
            format!("{SENTINEL}:{full_route}:nonce:signature:ciphertext").into(),
        ))
        .await
        .expect("send log sentinel text");
    assert_rejected_without_application_binary(socket).await;
    handle
        .shutdown()
        .await
        .expect("shutdown log capture server");

    let logs = capture.rendered();
    assert!(
        logs.contains("relay.frame.rejected"),
        "sentinel test requires a positive structured rejection event: {logs}"
    );
    assert!(logs.contains("failure_code"));
    for forbidden in [SENTINEL, &sentinel_base64, &sentinel_hex, &full_route] {
        assert!(
            !logs.contains(forbidden),
            "Relay log leaked forbidden material {forbidden}: {logs}"
        );
    }
}

#[tokio::test]
async fn drain_sends_server_restarting_and_releases_the_store_for_reopen() {
    let temp = TempDir::new().expect("tempdir");
    let (handle, storage_path) = start_server(&temp).await;
    let mut socket = connect(handle.public_addr()).await;
    socket
        .send(Message::Binary(encode(&hello()).into()))
        .await
        .expect("send binary Hello");
    assert!(matches!(
        receive_relay_frame(&mut socket).await.body,
        RelayFrameBody::Challenge(_)
    ));

    let triggered_at = unix_now_ms();
    handle.trigger_shutdown();
    let restarting = receive_relay_frame(&mut socket).await;
    let RelayFrameBody::ServerRestarting(restarting) = restarting.body else {
        panic!("drain must send ServerRestarting before close");
    };
    assert!(restarting.drain_deadline_ms >= triggered_at.saturating_add(4_500));
    assert!(restarting.drain_deadline_ms <= unix_now_ms().saturating_add(5_500));
    socket.close(None).await.expect("close drained client");

    timeout(IO_TIMEOUT, handle.wait())
        .await
        .expect("server drain exceeded prompt-client budget")
        .expect("server drain succeeds");

    let mut reopened_settings = RelayV2StoreSettings::new(storage_path);
    reopened_settings.disk_reserve_bytes = 0;
    reopened_settings.disk_reserve_percent = 0;
    let reopened = RelayStoreHandle::open(
        reopened_settings
            .into_store_config(test_receipt_identity())
            .expect("reopen config"),
    )
    .await
    .expect("drain must release the Store worker and DB lease");
    reopened.inspect().await.expect("inspect reopened Store");
    reopened.shutdown().await.expect("shutdown reopened Store");
}

#[tokio::test]
async fn dropping_server_handle_cancels_and_reaps_the_service_instead_of_detaching_it() {
    let temp = TempDir::new().expect("tempdir");
    let (handle, storage_path) = start_server(&temp).await;
    drop(handle);

    let reopened = timeout(IO_TIMEOUT, async {
        loop {
            let mut settings = RelayV2StoreSettings::new(storage_path.clone());
            settings.disk_reserve_bytes = 0;
            settings.disk_reserve_percent = 0;
            match RelayStoreHandle::open(
                settings
                    .into_store_config(test_receipt_identity())
                    .expect("reopen config"),
            )
            .await
            {
                Ok(store) => break store,
                Err(StoreError::StoreAlreadyOpen) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("unexpected reopen failure after handle Drop: {error}"),
            }
        }
    })
    .await
    .expect("dropped handle must promptly release service resources");
    reopened.inspect().await.expect("inspect reaped store");
    reopened.shutdown().await.expect("shutdown reaped store");
}

#[tokio::test]
async fn library_selfcheck_loads_fixture_migrates_and_reopens_a_file_store() {
    let temp = TempDir::new().expect("tempdir");
    let storage_path = temp.path().join("selfcheck").join("relay.db");
    let receipt_signing_key = write_test_receipt_signing_key(temp.path());
    let config_fixture = fixture("relay-selfcheck.toml");
    let cwd = Path::new(env!("CARGO_MANIFEST_DIR"));
    let arguments = vec![
        "agentdeck-relay".to_owned(),
        "--config".to_owned(),
        config_fixture.display().to_string(),
        "--storage".to_owned(),
        storage_path.display().to_string(),
        "--receipt-signing-key".to_owned(),
        receipt_signing_key.as_path().display().to_string(),
    ];
    let mut config = RelayV2ServerConfig::load_from(arguments, &BTreeMap::new(), cwd)
        .expect("load selfcheck fixture");
    config.store.disk_reserve_bytes = 0;
    config.store.disk_reserve_percent = 0;

    server::selfcheck(config)
        .await
        .expect("library selfcheck must validate TLS, migration, readiness and Core");
    assert!(storage_path.is_file(), "selfcheck must use a real file DB");

    let mut reopened_settings = RelayV2StoreSettings::new(storage_path);
    reopened_settings.disk_reserve_bytes = 0;
    reopened_settings.disk_reserve_percent = 0;
    let reopened = RelayStoreHandle::open(
        reopened_settings
            .into_store_config(test_receipt_identity())
            .expect("selfcheck readback config"),
    )
    .await
    .expect("selfcheck must release DB ownership");
    let snapshot = reopened.inspect().await.expect("selfcheck schema readback");
    assert_eq!(snapshot.schema_family, "agentdeck-relay-v2");
    assert_eq!(snapshot.journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(snapshot.synchronous, 2);
    assert!(snapshot.foreign_keys);
    reopened
        .shutdown()
        .await
        .expect("shutdown selfcheck readback");
}
