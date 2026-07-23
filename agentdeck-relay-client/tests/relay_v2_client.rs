use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentdeck_protocol::relay_v2::auth::{CertRole, PublicKeyBytes};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, AuthProof, Authenticate, Authenticated, Challenge, ClosePairRoute, Hello,
    OpenPairRoute, PairData, PairRouteCloseOutcome, PairRouteClosed, Ping, Pong,
    RetirementCommitted, RouteAccepted, SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, Ed25519Signature, EnrollmentCode, LinkGeneration, MAX_FRAME_BYTES,
    MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, MachineRouteId, OpaqueRouteFrame,
    PairRouteId, PairingHello, RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayServerId, RootKeyId,
    SignedCertificate, TrustEpoch, decode, encode, enrollment_receipt_hash,
};
use agentdeck_relay_client::{
    EnrollmentClientConfig, LinkAuthenticator, PairingEvent, RelayClient, RelayClientConfig,
    RelayEnrollmentClient, RelayPairingClient, RelayTlsPolicy,
};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use x509_parser::prelude::{FromDer, X509Certificate};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn server_id() -> RelayServerId {
    RelayServerId::from_bytes([0x41; 16])
}

struct TestIdentity {
    certificate_der: Vec<u8>,
    server_config: Arc<ServerConfig>,
    spki_pin: [u8; 32],
}

fn test_identity() -> TestIdentity {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate localhost test certificate");
    let certificate_der = certified.cert.der().to_vec();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let server_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("test TLS protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], private_key)
    .expect("test TLS identity");
    let (_, certificate) =
        X509Certificate::from_der(&certificate_der).expect("parse generated certificate");
    let spki_pin: [u8; 32] = Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into();
    TestIdentity {
        certificate_der,
        server_config: Arc::new(server_config),
        spki_pin,
    }
}

fn client_config(port: u16, policy: RelayTlsPolicy) -> RelayClientConfig {
    RelayClientConfig::new(&format!("wss://localhost:{port}/"), server_id(), policy)
        .expect("test client config")
}

fn dummy_certificate() -> SignedCertificate {
    SignedCertificate {
        subject_pubkey: PublicKeyBytes([0x31; 32]),
        cert_role: CertRole::Link,
        generation: LinkGeneration::new(1),
        root_key_id: RootKeyId::from_bytes([0x32; 16]),
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: None,
        signature: Ed25519Signature([0x33; 64]),
    }
}

#[derive(Default)]
struct TestAuthenticator {
    calls: AtomicUsize,
    challenges: Mutex<Vec<ConnectionInstanceId>>,
}

impl TestAuthenticator {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn challenges(&self) -> Vec<ConnectionInstanceId> {
        self.challenges
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl LinkAuthenticator for TestAuthenticator {
    fn proof(&self) -> AuthProof {
        AuthProof::MachineLink {
            machine_route: MachineRouteId::from_bytes([0x34; 16]),
            link_cert: dummy_certificate(),
        }
    }

    async fn authenticate(
        &self,
        challenge: &Challenge,
    ) -> Result<Authenticate, agentdeck_relay_client::RelayClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.challenges
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(challenge.connection_instance);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&challenge.challenge_nonce);
        Ok(Authenticate {
            proof: self.proof(),
            signature: Ed25519Signature(signature),
        })
    }
}

fn wire(body: RelayFrameBody) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    }
}

async fn recv_wire<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>) -> OpaqueRouteFrame
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match tokio::time::timeout(TEST_TIMEOUT, socket.next())
            .await
            .expect("mock receive timeout")
        {
            Some(Ok(Message::Binary(bytes))) => return decode(&bytes).expect("Relay v2 frame"),
            Some(Ok(Message::Ping(bytes))) => socket
                .send(Message::Pong(bytes))
                .await
                .expect("mock WS pong"),
            Some(Ok(Message::Pong(_))) => {}
            other => panic!("unexpected mock message: {other:?}"),
        }
    }
}

async fn send_wire<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>, frame: &OpaqueRouteFrame)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    socket
        .send(Message::Binary(encode(frame).into()))
        .await
        .expect("mock send Relay v2 frame");
}

async fn accept_tls_ws(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
) -> tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    let (tcp, _) = listener.accept().await.expect("accept mock TCP");
    let tls = acceptor.accept(tcp).await.expect("accept mock TLS");
    accept_async(tls).await.expect("accept mock WSS")
}

async fn authenticate_principal<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
    connection_instance: u8,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    assert!(matches!(
        recv_wire(socket).await.body,
        RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION
        })
    ));
    send_wire(
        socket,
        &wire(RelayFrameBody::Challenge(Challenge {
            relay_server_id: server_id(),
            connection_instance: ConnectionInstanceId::from_bytes([connection_instance; 16]),
            challenge_nonce: [connection_instance.wrapping_add(0x51); 32],
        })),
    )
    .await;
    assert!(matches!(
        recv_wire(socket).await.body,
        RelayFrameBody::Authenticate(_)
    ));
    send_wire(
        socket,
        &wire(RelayFrameBody::Authenticated(Authenticated {
            heartbeat_interval_secs: 20,
        })),
    )
    .await;
}

async fn observe_client_close<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match tokio::time::timeout(TEST_TIMEOUT, socket.next())
            .await
            .expect("client normal-close timeout")
        {
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
            Some(Ok(Message::Ping(bytes))) => socket
                .send(Message::Pong(bytes))
                .await
                .expect("normal-close mock pong"),
            Some(Ok(Message::Pong(_))) => {}
            other => panic!("unexpected frame before client close: {other:?}"),
        }
    }
}

#[test]
fn config_freezes_a_strict_wss_origin_and_rejects_ambiguous_urls() {
    let policy = RelayTlsPolicy::pinned_spki(vec![[0x11; 32]]).expect("one pin");
    let config = RelayClientConfig::new("wss://relay.example:8443/", server_id(), policy.clone())
        .expect("strict origin");
    assert_eq!(config.origin(), "wss://relay.example:8443/");

    for invalid in [
        "ws://relay.example/",
        "https://relay.example/",
        "wss://user@relay.example/",
        "wss://relay.example:0/",
        "wss://relay.example/v2/connect",
        "wss://relay.example/?route=secret",
        "wss://relay.example/#fragment",
    ] {
        let error = RelayClientConfig::new(invalid, server_id(), policy.clone())
            .expect_err("ambiguous or downgrade origin must fail");
        assert_eq!(error.code(), "relay.client.origin_invalid");
    }
}

#[test]
fn pin_policy_requires_one_or_two_unique_spki_hashes() {
    for pins in [vec![], vec![[1; 32], [2; 32], [3; 32]]] {
        let error = RelayTlsPolicy::pinned_spki(pins).expect_err("invalid pin count");
        assert_eq!(error.code(), "relay.client.tls_policy_invalid");
    }
    let duplicate = RelayTlsPolicy::public_ca_and_pins(vec![[7; 32], [7; 32]])
        .expect_err("duplicate rotation pin");
    assert_eq!(duplicate.code(), "relay.client.tls_policy_invalid");

    RelayTlsPolicy::public_ca().expect("public roots policy");
    RelayTlsPolicy::public_ca_and_pins(vec![[7; 32], [8; 32]]).expect("current plus next pin");
    RelayTlsPolicy::pinned_spki(vec![[7; 32]]).expect("self-hosted pinned policy");
}

#[test]
fn client_config_debug_redacts_origin_and_pins() {
    let policy = RelayTlsPolicy::pinned_spki(vec![[0x99; 32]]).expect("pin policy");
    let config = RelayClientConfig::new("wss://secret-host.invalid/", server_id(), policy)
        .expect("valid config");
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("secret-host"));
    assert!(!rendered.contains("9999"));
    assert!(rendered.contains("<redacted>"));
}

async fn spawn_principal_server(
    identity: &TestIdentity,
    connections: usize,
    expect_application_on_first: bool,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock Relay");
    let port = listener.local_addr().expect("mock address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let task = tokio::spawn(async move {
        for index in 0..connections {
            let mut socket = accept_tls_ws(&listener, &acceptor).await;
            assert!(matches!(
                recv_wire(&mut socket).await.body,
                RelayFrameBody::Hello(Hello {
                    protocol_version: RELAY_PROTOCOL_VERSION
                })
            ));
            let challenge = Challenge {
                relay_server_id: server_id(),
                connection_instance: ConnectionInstanceId::from_bytes([index as u8 + 1; 16]),
                challenge_nonce: [index as u8 + 0x51; 32],
            };
            send_wire(&mut socket, &wire(RelayFrameBody::Challenge(challenge))).await;
            assert!(matches!(
                recv_wire(&mut socket).await.body,
                RelayFrameBody::Authenticate(_)
            ));
            send_wire(
                &mut socket,
                &wire(RelayFrameBody::Authenticated(Authenticated {
                    heartbeat_interval_secs: 20,
                })),
            )
            .await;
            let heartbeat_nonce = 0x7000 + index as u64;
            send_wire(
                &mut socket,
                &wire(RelayFrameBody::Ping(Ping {
                    nonce: heartbeat_nonce,
                })),
            )
            .await;
            let mut heartbeat_seen = false;
            let mut application = None;
            while !heartbeat_seen
                || (expect_application_on_first && index == 0 && application.is_none())
            {
                let frame = recv_wire(&mut socket).await;
                match frame.body {
                    RelayFrameBody::Pong(Pong { nonce }) if nonce == heartbeat_nonce => {
                        heartbeat_seen = true;
                    }
                    _ if expect_application_on_first && index == 0 => application = Some(frame),
                    _ => panic!("unexpected principal client frame"),
                }
            }
            if let Some(application) = application {
                send_wire(&mut socket, &application).await;
            }
        }
    });
    (port, task)
}

#[tokio::test]
async fn pinned_wss_is_binary_only_auto_pongs_and_reconnects_with_a_fresh_challenge() {
    let identity = test_identity();
    let (port, server) = spawn_principal_server(&identity, 2, true).await;
    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("pinned TLS");
    let authenticator = Arc::new(TestAuthenticator::default());
    let auth: Arc<dyn LinkAuthenticator> = authenticator.clone();
    let mut client = RelayClient::connect(client_config(port, policy), auth)
        .await
        .expect("connect principal");

    let application = wire(RelayFrameBody::OpenPairRoute(OpenPairRoute {
        machine_route: MachineRouteId::from_bytes([0x61; 16]),
        pair_route: PairRouteId::from_bytes([0x62; 16]),
        absolute_expiry_ms: 1234,
    }));
    client
        .send(application.clone())
        .await
        .expect("flush binary application frame");
    assert_eq!(
        client.recv().await.expect("receive echo"),
        Some(application)
    );

    client
        .reconnect_and_authenticate()
        .await
        .expect("fresh authenticated reconnect");
    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("mock server completion")
        .expect("mock server task");
    assert_eq!(authenticator.calls(), 2);
    let challenges = authenticator.challenges();
    assert_eq!(challenges.len(), 2);
    assert_ne!(challenges[0], challenges[1]);
}

#[tokio::test]
async fn principal_sends_frozen_codec_bytes_without_reencoding() {
    let identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind frozen-wire mock");
    let port = listener.local_addr().expect("frozen-wire address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let application = wire(RelayFrameBody::Ping(Ping {
        nonce: 0x0102_0304_0506_0708,
    }));
    let frozen = encode(&application);
    let expected = frozen.clone();
    let server = tokio::spawn(async move {
        let mut socket = accept_tls_ws(&listener, &acceptor).await;
        authenticate_principal(&mut socket, 0x70).await;
        match tokio::time::timeout(TEST_TIMEOUT, socket.next())
            .await
            .expect("frozen-wire receive timeout")
        {
            Some(Ok(Message::Binary(actual))) => assert_eq!(actual.as_ref(), expected.as_slice()),
            other => panic!("unexpected frozen-wire message: {other:?}"),
        }
    });

    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("frozen-wire pin");
    let authenticator = Arc::new(TestAuthenticator::default());
    let mut client = RelayClient::connect(client_config(port, policy), authenticator)
        .await
        .expect("connect frozen-wire principal");

    let mut trailing = frozen.clone();
    trailing.push(0);
    assert_eq!(
        client
            .send_encoded(trailing)
            .await
            .expect_err("trailing bytes must fail before the writer")
            .code(),
        "relay.client.frame_invalid"
    );
    client
        .send_encoded(frozen)
        .await
        .expect("flush exact frozen bytes");

    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("frozen-wire server completion")
        .expect("frozen-wire server task");
    client.shutdown().await;
}

#[tokio::test]
async fn shutdown_joins_connection_tasks_closes_the_socket_and_is_idempotent() {
    let identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind shutdown mock");
    let port = listener.local_addr().expect("shutdown address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let observed_connections = Arc::new(AtomicUsize::new(0));
    let server_active = Arc::clone(&active_connections);
    let server_observed = Arc::clone(&observed_connections);
    let server = tokio::spawn(async move {
        let mut socket = accept_tls_ws(&listener, &acceptor).await;
        server_observed.fetch_add(1, Ordering::SeqCst);
        server_active.fetch_add(1, Ordering::SeqCst);
        authenticate_principal(&mut socket, 0x71).await;
        observe_client_close(&mut socket).await;
        server_active.fetch_sub(1, Ordering::SeqCst);
    });

    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("shutdown pin");
    let authenticator = Arc::new(TestAuthenticator::default());
    let mut client = RelayClient::connect(client_config(port, policy), authenticator)
        .await
        .expect("connect shutdown principal");

    client.shutdown().await;
    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("shutdown server completion")
        .expect("shutdown server task");
    assert_eq!(active_connections.load(Ordering::SeqCst), 0);
    assert_eq!(observed_connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        client
            .send(wire(RelayFrameBody::Ping(Ping { nonce: 1 })))
            .await
            .expect_err("shutdown client must clear its connection")
            .code(),
        "relay.client.not_connected"
    );

    tokio::time::timeout(TEST_TIMEOUT, client.shutdown())
        .await
        .expect("second shutdown is a prompt no-op");
    assert_eq!(active_connections.load(Ordering::SeqCst), 0);
    assert_eq!(observed_connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reconnect_joins_and_closes_the_old_generation_before_accepting_the_new_one() {
    let identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind replacement-order mock");
    let port = listener
        .local_addr()
        .expect("replacement-order address")
        .port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let server = tokio::spawn(async move {
        let mut old_socket = accept_tls_ws(&listener, &acceptor).await;
        authenticate_principal(&mut old_socket, 0x72).await;

        let replacement_accept = listener.accept();
        tokio::pin!(replacement_accept);
        tokio::select! {
            biased;
            message = old_socket.next() => match message {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {}
                other => panic!("old generation was not normally closed: {other:?}"),
            },
            accepted = &mut replacement_accept => {
                let _ = accepted.expect("premature replacement accept");
                panic!("replacement connected before the old generation closed");
            }
        }

        let (tcp, _) = replacement_accept
            .await
            .expect("accept replacement after old close");
        let tls = acceptor.accept(tcp).await.expect("replacement TLS");
        let mut replacement = accept_async(tls).await.expect("replacement WSS");
        authenticate_principal(&mut replacement, 0x73).await;
        observe_client_close(&mut replacement).await;
    });

    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("replacement pin");
    let authenticator = Arc::new(TestAuthenticator::default());
    let auth: Arc<dyn LinkAuthenticator> = authenticator.clone();
    let mut client = RelayClient::connect(client_config(port, policy), auth)
        .await
        .expect("connect first generation");
    client
        .reconnect_and_authenticate()
        .await
        .expect("replace after old join");
    client.shutdown().await;

    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("replacement-order server completion")
        .expect("replacement-order server task");
    assert_eq!(authenticator.calls(), 2);
}

#[tokio::test]
async fn public_ca_and_explicit_pin_are_both_enforced() {
    let identity = test_identity();
    let (port, server) = spawn_principal_server(&identity, 1, false).await;
    let policy = RelayTlsPolicy::public_ca_and_pins(vec![[0xab; 32], identity.spki_pin])
        .expect("CA plus pin")
        .with_additional_root_der(identity.certificate_der.clone())
        .expect("private test CA");
    let authenticator = Arc::new(TestAuthenticator::default());
    let auth: Arc<dyn LinkAuthenticator> = authenticator.clone();
    let _client = RelayClient::connect(client_config(port, policy), auth)
        .await
        .expect("CA and matching pin");
    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("mock server completion")
        .expect("mock server task");
    assert_eq!(authenticator.calls(), 1);

    let wrong_identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wrong-pin mock");
    let wrong_port = listener.local_addr().expect("wrong-pin address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&wrong_identity.server_config));
    let rejected_server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept wrong-pin TCP");
        assert!(
            acceptor.accept(tcp).await.is_err(),
            "client must abort during TLS"
        );
    });
    let wrong_policy = RelayTlsPolicy::public_ca_and_pins(vec![[0xee; 32]])
        .expect("syntactically valid wrong pin")
        .with_additional_root_der(wrong_identity.certificate_der.clone())
        .expect("test root");
    let wrong_auth = Arc::new(TestAuthenticator::default());
    let result =
        RelayClient::connect(client_config(wrong_port, wrong_policy), wrong_auth.clone()).await;
    assert_eq!(
        result.expect_err("wrong pin must fail").code(),
        "remote.transport.tls_pin_mismatch"
    );
    assert_eq!(
        wrong_auth.calls(),
        0,
        "pin mismatch must happen before signing"
    );
    tokio::time::timeout(TEST_TIMEOUT, rejected_server)
        .await
        .expect("wrong-pin server completion")
        .expect("wrong-pin server task");

    let untrusted_identity = test_identity();
    let untrusted_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind untrusted-CA mock");
    let untrusted_port = untrusted_listener
        .local_addr()
        .expect("untrusted-CA address")
        .port();
    let untrusted_acceptor = TlsAcceptor::from(Arc::clone(&untrusted_identity.server_config));
    let untrusted_server = tokio::spawn(async move {
        let (tcp, _) = untrusted_listener
            .accept()
            .await
            .expect("accept untrusted-CA TCP");
        assert!(untrusted_acceptor.accept(tcp).await.is_err());
    });
    let untrusted_auth = Arc::new(TestAuthenticator::default());
    let untrusted_policy = RelayTlsPolicy::public_ca_and_pins(vec![untrusted_identity.spki_pin])
        .expect("matching pin without CA trust");
    let error = RelayClient::connect(
        client_config(untrusted_port, untrusted_policy),
        untrusted_auth.clone(),
    )
    .await
    .expect_err("matching pin must not bypass public CA validation");
    assert_eq!(error.code(), "relay.client.tls_verification_failed");
    assert_eq!(untrusted_auth.calls(), 0);
    tokio::time::timeout(TEST_TIMEOUT, untrusted_server)
        .await
        .expect("untrusted-CA server completion")
        .expect("untrusted-CA server task");

    let host_identity = test_identity();
    let host_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hostname-mismatch mock");
    let host_port = host_listener
        .local_addr()
        .expect("hostname-mismatch address")
        .port();
    let host_acceptor = TlsAcceptor::from(Arc::clone(&host_identity.server_config));
    let host_server = tokio::spawn(async move {
        let (tcp, _) = host_listener
            .accept()
            .await
            .expect("accept hostname-mismatch TCP");
        assert!(host_acceptor.accept(tcp).await.is_err());
    });
    let host_policy = RelayTlsPolicy::pinned_spki(vec![host_identity.spki_pin]).expect("host pin");
    let host_config = RelayClientConfig::new(
        &format!("wss://127.0.0.1:{host_port}/"),
        server_id(),
        host_policy,
    )
    .expect("IP origin");
    let host_auth = Arc::new(TestAuthenticator::default());
    let error = RelayClient::connect(host_config, host_auth.clone())
        .await
        .expect_err("SPKI pin must not bypass hostname verification");
    assert_eq!(error.code(), "relay.client.tls_verification_failed");
    assert_eq!(host_auth.calls(), 0);
    tokio::time::timeout(TEST_TIMEOUT, host_server)
        .await
        .expect("hostname-mismatch server completion")
        .expect("hostname-mismatch server task");
}

fn enrollment_request() -> MachineEnrollmentRequestV1 {
    let link_cert = dummy_certificate();
    let mut data_cert = dummy_certificate();
    data_cert.cert_role = CertRole::Data;
    data_cert.subject_pubkey = PublicKeyBytes([0x71; 32]);
    MachineEnrollmentRequestV1 {
        code: EnrollmentCode([0x72; 32]),
        machine_route: MachineRouteId::from_bytes([0x73; 16]),
        root_pubkey: PublicKeyBytes([0x74; 32]),
        link_cert,
        data_cert,
    }
}

async fn read_http_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut buffer))
            .await
            .expect("HTTP request timeout")
            .expect("read HTTP request");
        assert!(count > 0, "HTTP request closed before body completed");
        request.extend_from_slice(&buffer[..count]);
        let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let header = std::str::from_utf8(&request[..body_start]).expect("HTTP header UTF-8");
        let content_length = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .expect("Content-Length");
        if request.len() >= body_start + content_length {
            return request;
        }
    }
}

#[tokio::test]
async fn enrollment_sends_material_only_after_tls_and_validates_response_identity() {
    let identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind enrollment mock");
    let port = listener.local_addr().expect("enrollment address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let expected_request = enrollment_request();
    let expected_route = expected_request.machine_route;
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept enrollment TCP");
        let mut tls = acceptor.accept(tcp).await.expect("enrollment TLS");
        let request = read_http_request(&mut tls).await;
        let header_end = request
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .expect("HTTP header terminator")
            + 4;
        assert!(request.starts_with(b"POST /v2/machine-enroll HTTP/1.1\r\n"));
        let parsed: MachineEnrollmentRequestV1 =
            serde_json::from_slice(&request[header_end..]).expect("enrollment JSON");
        assert_eq!(parsed, expected_request);
        let receipt_hash = enrollment_receipt_hash(
            server_id(),
            expected_route,
            1,
            expected_request.canonical_sha256(),
        );
        let response = serde_json::to_vec(&MachineEnrollmentResponseV1 {
            relay_server_id: server_id(),
            machine_route: expected_route,
            trust_epoch: 1,
            receipt_hash,
        })
        .expect("response JSON");
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        );
        tls.write_all(headers.as_bytes())
            .await
            .expect("write response header");
        tls.write_all(&response).await.expect("write response body");
        tls.shutdown().await.expect("close enrollment TLS");
    });
    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("pin policy");
    let config = EnrollmentClientConfig::new(client_config(port, policy));
    let response = RelayEnrollmentClient::enroll_machine(config, enrollment_request())
        .await
        .expect("enroll after TLS");
    assert_eq!(response.relay_server_id, server_id());
    assert_eq!(response.machine_route, expected_route);
    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("enrollment server completion")
        .expect("enrollment server task");

    let forged_identity = test_identity();
    let forged_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind forged-receipt mock");
    let forged_port = forged_listener
        .local_addr()
        .expect("forged-receipt address")
        .port();
    let forged_acceptor = TlsAcceptor::from(Arc::clone(&forged_identity.server_config));
    let forged_server = tokio::spawn(async move {
        let (tcp, _) = forged_listener
            .accept()
            .await
            .expect("accept forged-receipt TCP");
        let mut tls = forged_acceptor.accept(tcp).await.expect("forged TLS");
        let _request = read_http_request(&mut tls).await;
        let response = serde_json::to_vec(&MachineEnrollmentResponseV1 {
            relay_server_id: server_id(),
            machine_route: expected_route,
            trust_epoch: 1,
            receipt_hash: [0xff; 32],
        })
        .expect("forged response JSON");
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        );
        tls.write_all(headers.as_bytes())
            .await
            .expect("write forged header");
        tls.write_all(&response).await.expect("write forged body");
        tls.shutdown().await.expect("close forged TLS");
    });
    let forged_policy =
        RelayTlsPolicy::pinned_spki(vec![forged_identity.spki_pin]).expect("forged pin policy");
    let error = RelayEnrollmentClient::enroll_machine(
        EnrollmentClientConfig::new(client_config(forged_port, forged_policy)),
        enrollment_request(),
    )
    .await
    .expect_err("forged receipt must fail client readback");
    assert_eq!(error.code(), "relay.client.enrollment_response_invalid");
    tokio::time::timeout(TEST_TIMEOUT, forged_server)
        .await
        .expect("forged-receipt completion")
        .expect("forged-receipt task");

    let wrong_identity = test_identity();
    let wrong_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind rejected enrollment mock");
    let wrong_port = wrong_listener
        .local_addr()
        .expect("rejected enrollment address")
        .port();
    let wrong_acceptor = TlsAcceptor::from(Arc::clone(&wrong_identity.server_config));
    let rejected = tokio::spawn(async move {
        let (tcp, _) = wrong_listener
            .accept()
            .await
            .expect("accept rejected enrollment TCP");
        assert!(
            wrong_acceptor.accept(tcp).await.is_err(),
            "wrong pin must abort before any HTTP/application bytes"
        );
    });
    let wrong_policy = RelayTlsPolicy::pinned_spki(vec![[0xfe; 32]]).expect("wrong pin policy");
    let error = RelayEnrollmentClient::enroll_machine(
        EnrollmentClientConfig::new(client_config(wrong_port, wrong_policy)),
        enrollment_request(),
    )
    .await
    .expect_err("wrong pin enrollment must fail closed");
    assert_eq!(error.code(), "remote.transport.tls_pin_mismatch");
    tokio::time::timeout(TEST_TIMEOUT, rejected)
        .await
        .expect("rejected enrollment completion")
        .expect("rejected enrollment task");
}

#[tokio::test]
async fn pairing_client_exposes_only_route_bound_typed_events_and_close_ack() {
    let identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind pairing mock");
    let port = listener.local_addr().expect("pairing address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let pair_route = PairRouteId::from_bytes([0x81; 16]);
    let machine_route = MachineRouteId::from_bytes([0x82; 16]);
    let server = tokio::spawn(async move {
        let mut socket = accept_tls_ws(&listener, &acceptor).await;
        assert!(matches!(
            recv_wire(&mut socket).await.body,
            RelayFrameBody::Hello(_)
        ));
        let RelayFrameBody::PairingHello(hello) = recv_wire(&mut socket).await.body else {
            panic!("expected PairingHello");
        };
        assert_eq!(hello.relay_server_id, server_id());
        assert_eq!(hello.pair_route, pair_route);
        send_wire(
            &mut socket,
            &wire(RelayFrameBody::Authenticated(Authenticated {
                heartbeat_interval_secs: 20,
            })),
        )
        .await;
        send_wire(
            &mut socket,
            &wire(RelayFrameBody::Ping(Ping { nonce: 0x8383 })),
        )
        .await;
        let mut data = None;
        let mut pong = false;
        while data.is_none() || !pong {
            let frame = recv_wire(&mut socket).await;
            match frame.body {
                RelayFrameBody::PairData(pair_data) => data = Some(pair_data),
                RelayFrameBody::Pong(Pong { nonce: 0x8383 }) => pong = true,
                _ => panic!("pairing API emitted forbidden frame"),
            }
        }
        let data = data.expect("pair data");
        assert_eq!(data.pair_route, pair_route);
        send_wire(
            &mut socket,
            &wire(RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::PairFrame { pair_route },
            })),
        )
        .await;
        send_wire(
            &mut socket,
            &wire(RelayFrameBody::PairData(PairData {
                pair_route,
                sealed_blob: SealedBlob(vec![0x84, 0x85]),
            })),
        )
        .await;
        let RelayFrameBody::ClosePairRoute(close) = recv_wire(&mut socket).await.body else {
            panic!("expected typed ClosePairRoute");
        };
        assert_eq!(close.machine_route, machine_route);
        assert_eq!(close.pair_route, pair_route);
        send_wire(
            &mut socket,
            &wire(RelayFrameBody::PairRouteClosed(PairRouteClosed {
                pair_route,
                outcome: PairRouteCloseOutcome::Closed,
            })),
        )
        .await;
    });
    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("pair pin");
    let mut client = RelayPairingClient::connect_pairing(
        client_config(port, policy),
        PairingHello {
            relay_server_id: server_id(),
            pair_route,
        },
    )
    .await
    .expect("connect pairing");
    let wrong = client
        .send_pair_data(PairData {
            pair_route: PairRouteId::from_bytes([0xff; 16]),
            sealed_blob: SealedBlob(vec![1]),
        })
        .await
        .expect_err("cross-route pair data cannot be expressed");
    assert_eq!(wrong.code(), "relay.client.pair_route_mismatch");
    let oversized = client
        .send_pair_data(PairData {
            pair_route,
            sealed_blob: SealedBlob(vec![0; MAX_FRAME_BYTES]),
        })
        .await
        .expect_err("encoded frame above 4 MiB must fail before socket write");
    assert_eq!(oversized.code(), "relay.client.frame_too_large");
    client
        .send_pair_data(PairData {
            pair_route,
            sealed_blob: SealedBlob(vec![0x86]),
        })
        .await
        .expect("send route-bound pair data");
    let pending = client
        .recv_pair_data()
        .await
        .expect_err("compat data helper must not swallow a control event");
    assert_eq!(pending.code(), "relay.client.pair_event_pending");
    assert!(matches!(
        client.next_event().await.expect("preserved accepted event"),
        Some(PairingEvent::RouteAccepted(_))
    ));
    assert_eq!(
        client.recv_pair_data().await.expect("pair response"),
        Some(PairData {
            pair_route,
            sealed_blob: SealedBlob(vec![0x84, 0x85]),
        })
    );
    client
        .request_close(ClosePairRoute {
            machine_route,
            pair_route,
        })
        .await
        .expect("flush close request");
    assert!(matches!(
        client.next_event().await.expect("close ACK event"),
        Some(PairingEvent::RouteClosed(PairRouteClosed {
            outcome: PairRouteCloseOutcome::Closed,
            ..
        }))
    ));
    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("pairing server completion")
        .expect("pairing server task");
}

#[tokio::test]
async fn pairing_client_sends_only_exact_canonical_route_bound_bytes_and_shuts_down() {
    let identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind exact pairing mock");
    let port = listener.local_addr().expect("exact pairing address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let pair_route = PairRouteId::from_bytes([0x87; 16]);
    let exact_frame = wire(RelayFrameBody::PairData(PairData {
        pair_route,
        sealed_blob: SealedBlob(vec![0x88, 0x89, 0x8a]),
    }));
    let frozen = encode(&exact_frame);
    let expected = frozen.clone();
    let server = tokio::spawn(async move {
        let mut socket = accept_tls_ws(&listener, &acceptor).await;
        assert!(matches!(
            recv_wire(&mut socket).await.body,
            RelayFrameBody::Hello(_)
        ));
        let RelayFrameBody::PairingHello(hello) = recv_wire(&mut socket).await.body else {
            panic!("expected PairingHello");
        };
        assert_eq!(hello.relay_server_id, server_id());
        assert_eq!(hello.pair_route, pair_route);
        send_wire(
            &mut socket,
            &wire(RelayFrameBody::Authenticated(Authenticated {
                heartbeat_interval_secs: 20,
            })),
        )
        .await;

        match tokio::time::timeout(TEST_TIMEOUT, socket.next())
            .await
            .expect("exact pairing receive timeout")
        {
            Some(Ok(Message::Binary(actual))) => assert_eq!(actual.as_ref(), expected.as_slice()),
            other => panic!("unexpected exact pairing message: {other:?}"),
        }
        observe_client_close(&mut socket).await;
    });

    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("exact pairing pin");
    let mut client = RelayPairingClient::connect_pairing(
        client_config(port, policy),
        PairingHello {
            relay_server_id: server_id(),
            pair_route,
        },
    )
    .await
    .expect("connect exact pairing client");

    let mut trailing = frozen.clone();
    trailing.push(0);
    assert_eq!(
        client
            .send_pair_data_encoded(trailing)
            .await
            .expect_err("trailing bytes must fail before the pairing writer")
            .code(),
        "relay.client.frame_invalid"
    );
    assert_eq!(
        client
            .send_pair_data_encoded(encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION - 1,
                body: exact_frame.body.clone(),
            }))
            .await
            .expect_err("old Relay version must fail before the pairing writer")
            .code(),
        "relay.client.version_unsupported"
    );
    assert_eq!(
        client
            .send_pair_data_encoded(encode(&wire(RelayFrameBody::Ping(Ping { nonce: 7 }))))
            .await
            .expect_err("non-PairData bytes must fail before the pairing writer")
            .code(),
        "relay.client.pair_frame_forbidden"
    );
    assert_eq!(
        client
            .send_pair_data_encoded(encode(&wire(RelayFrameBody::PairData(PairData {
                pair_route: PairRouteId::from_bytes([0xff; 16]),
                sealed_blob: SealedBlob(vec![1]),
            }))))
            .await
            .expect_err("cross-route frozen PairData must fail before the pairing writer")
            .code(),
        "relay.client.pair_route_mismatch"
    );
    client
        .send_pair_data_encoded(frozen)
        .await
        .expect("flush exact frozen pairing bytes");
    client.shutdown().await;
    client.shutdown().await;

    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("exact pairing server completion")
        .expect("exact pairing server task");
}

#[tokio::test]
async fn principal_returns_byte_exact_signed_terminal_and_never_signs_wrong_server_id() {
    let identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind terminal mock");
    let port = listener.local_addr().expect("terminal address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let terminal = wire(RelayFrameBody::RetirementCommitted(RetirementCommitted {
        machine_route: MachineRouteId::from_bytes([0x91; 16]),
        trust_epoch: TrustEpoch::new(9),
        retire_hash: [0x92; 32],
    }));
    let terminal_bytes = encode(&terminal);
    let expected_bytes = terminal_bytes.clone();
    let server = tokio::spawn(async move {
        let mut socket = accept_tls_ws(&listener, &acceptor).await;
        assert!(matches!(
            recv_wire(&mut socket).await.body,
            RelayFrameBody::Hello(_)
        ));
        send_wire(
            &mut socket,
            &wire(RelayFrameBody::Challenge(Challenge {
                relay_server_id: server_id(),
                connection_instance: ConnectionInstanceId::from_bytes([0x93; 16]),
                challenge_nonce: [0x94; 32],
            })),
        )
        .await;
        assert!(matches!(
            recv_wire(&mut socket).await.body,
            RelayFrameBody::Authenticate(_)
        ));
        socket
            .send(Message::Binary(expected_bytes.into()))
            .await
            .expect("send exact signed terminal");
        socket.close(None).await.expect("close terminal socket");
    });
    let authenticator = Arc::new(TestAuthenticator::default());
    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("terminal pin");
    let error = RelayClient::connect(client_config(port, policy), authenticator.clone())
        .await
        .expect_err("retired principal is terminal");
    assert_eq!(error.code(), "relay.client.authentication_terminal");
    assert_eq!(error.authentication_terminal_frame(), Some(&terminal));
    assert_eq!(
        error.authentication_terminal_bytes(),
        Some(terminal_bytes.as_slice())
    );
    assert_eq!(authenticator.calls(), 1);
    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("terminal server completion")
        .expect("terminal server task");

    let wrong_identity = test_identity();
    let wrong_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind server-id mock");
    let wrong_port = wrong_listener
        .local_addr()
        .expect("server-id address")
        .port();
    let wrong_acceptor = TlsAcceptor::from(Arc::clone(&wrong_identity.server_config));
    let wrong_server = tokio::spawn(async move {
        let mut socket = accept_tls_ws(&wrong_listener, &wrong_acceptor).await;
        assert!(matches!(
            recv_wire(&mut socket).await.body,
            RelayFrameBody::Hello(_)
        ));
        send_wire(
            &mut socket,
            &wire(RelayFrameBody::Challenge(Challenge {
                relay_server_id: RelayServerId::from_bytes([0xff; 16]),
                connection_instance: ConnectionInstanceId::from_bytes([0x95; 16]),
                challenge_nonce: [0x96; 32],
            })),
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(500), socket.next())
                .await
                .is_ok(),
            "client should close promptly without Authenticate"
        );
    });
    let wrong_auth = Arc::new(TestAuthenticator::default());
    let wrong_policy =
        RelayTlsPolicy::pinned_spki(vec![wrong_identity.spki_pin]).expect("server-id pin");
    let error = RelayClient::connect(client_config(wrong_port, wrong_policy), wrong_auth.clone())
        .await
        .expect_err("wrong relayServerId must fail before signing");
    assert_eq!(error.code(), "relay.client.server_identity_mismatch");
    assert_eq!(wrong_auth.calls(), 0);
    tokio::time::timeout(TEST_TIMEOUT, wrong_server)
        .await
        .expect("server-id mock completion")
        .expect("server-id mock task");
}

#[tokio::test]
async fn websocket_redirect_is_rejected_without_contacting_the_target_or_signing() {
    let identity = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect mock");
    let port = listener.local_addr().expect("redirect address").port();
    let acceptor = TlsAcceptor::from(Arc::clone(&identity.server_config));
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept redirect TCP");
        let mut tls = acceptor.accept(tcp).await.expect("redirect TLS");
        let mut request = [0u8; 4096];
        let count = tls.read(&mut request).await.expect("read WS upgrade");
        assert!(request[..count].starts_with(b"GET /v2/connect HTTP/1.1\r\n"));
        tls.write_all(
            b"HTTP/1.1 302 Found\r\nLocation: wss://redirect-target.invalid/v2/connect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write redirect");
        tls.shutdown().await.expect("close redirect TLS");
    });
    let policy = RelayTlsPolicy::pinned_spki(vec![identity.spki_pin]).expect("redirect pin");
    let authenticator = Arc::new(TestAuthenticator::default());
    let error = RelayClient::connect(client_config(port, policy), authenticator.clone())
        .await
        .expect_err("WS redirect must not be followed");
    assert_eq!(error.code(), "relay.client.handshake_rejected");
    assert_eq!(authenticator.calls(), 0);
    tokio::time::timeout(TEST_TIMEOUT, server)
        .await
        .expect("redirect server completion")
        .expect("redirect server task");
}
