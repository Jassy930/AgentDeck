//! P4.3 真实组合链路：Relay TLS/admin → stable daemon UDS → CLI transport →
//! RuntimeCore/RemoteManager/RemoteTransport/Pairing Store → 远端 pairing client。
//!
//! 这里刻意不使用 pairing actor/store test double。协议/crypto 的细粒度 crash 与
//! tamper corpus 留在各自 focused suite；本文件证明 production composition 可以完成
//! enrollment、pending、本机确认、grant commit、设备回执与 terminal close。

#![cfg(unix)]

use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentdeck_cli::unix_transport::{InjectedEndpoint, ReplySequenceItem, RuntimeUnixClient};
use agentdeck_crypto::rand_core::SeedableRng;
use agentdeck_crypto::{
    HpkePrivateKey, HpkePublicKey, SignatureBytes, SigningKey, VerifyingKey, open_pair_pending,
    open_pair_response, seal_pair_request, seal_pair_response_received, sha256, verify_tbs,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    E2EE_FORMAT_VERSION, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
    PairRequestInfoV1, PairRequestPlaintextV1, PairResponseReceivedV1, PairResponseV1,
    PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::frame::{
    ClosePairRoute, PairData, PairRouteCloseOutcome, PairingHello, SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    Ed25519Signature, RELAY_PROTOCOL_VERSION, RelayFrameBody, encode,
};
use agentdeck_protocol::runtime::{
    CreatePairInviteRequest, IdempotencyKey, LocalOnlyAdministration, MachineEnrollRequest,
    PairingReceipt, RUNTIME_PROTOCOL_VERSION, RuntimeReply, RuntimeRequest,
};
use agentdeck_relay::config::{
    RelayReceiptSigningKeyPath, RelayV2AdminConfig, RelayV2ServerConfig, RelayV2StoreSettings,
    RelayV2TlsPaths, RelayV2TransportMode,
};
use agentdeck_relay::v2::admin::{AdminClient, AdminRequest, AdminResponse, AdminResult};
use agentdeck_relay::v2::server::tls::{TlsIdentityPaths, load_tls_identity};
use agentdeck_relay::v2::server::{RelayV2ServerError, RelayV2ServerHandle};
use agentdeck_relay_client::{PairingEvent, RelayClientConfig, RelayPairingClient, RelayTlsPolicy};
use agentdeckd::config::{DaemonConfig, DaemonStartupOptions};
use agentdeckd::local::listener::BoundLocalListener;
use agentdeckd::remote::bootstrap::reconcile_machine_identity;
use agentdeckd::remote::manager::RemoteManager;
use agentdeckd::runtime::singleton::SingletonGuard;
use agentdeckd::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
use agentdeckd::runtime::{AgentRouter, RuntimeCore};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use rand_chacha::ChaCha20Rng;
use rusqlite::{Connection, OpenFlags};
use tempfile::Builder as TempDirBuilder;
use tokio::sync::oneshot;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const RECEIPT_SIGNER_SEED: [u8; 32] = [0x71; 32];

fn write_localhost_tls_identity(root: &Path) -> (PathBuf, PathBuf) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()])
        .expect("generate localhost TLS certificate");
    let directory = root.join("relay-tls");
    fs::create_dir(&directory).expect("create Relay TLS directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("secure Relay TLS directory");
    let cert = directory.join("localhost-cert.pem");
    let key = directory.join("localhost-key.pem");
    fs::write(&cert, certified.cert.pem()).expect("write localhost certificate");
    fs::write(&key, certified.key_pair.serialize_pem()).expect("write localhost private key");
    fs::set_permissions(&cert, fs::Permissions::from_mode(0o600))
        .expect("secure localhost certificate");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
        .expect("secure localhost private key");
    (cert, key)
}

fn reserve_loopback_ports() -> (SocketAddr, SocketAddr) {
    let public = StdTcpListener::bind("127.0.0.1:0").expect("reserve Relay public port");
    let health = StdTcpListener::bind("127.0.0.1:0").expect("reserve Relay health port");
    let public_addr = public.local_addr().expect("public address");
    let health_addr = health.local_addr().expect("health address");
    drop((public, health));
    (public_addr, health_addr)
}

fn write_receipt_signing_key(root: &Path) -> RelayReceiptSigningKeyPath {
    let directory = root.join("receipt-signer");
    fs::create_dir(&directory).expect("create receipt signer directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("secure receipt signer directory");
    let directory = fs::canonicalize(directory).expect("canonicalize receipt signer directory");
    let path = directory.join("receipt-signing-key.seed");
    fs::write(&path, RECEIPT_SIGNER_SEED).expect("write receipt signer seed");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("secure receipt signer seed");
    RelayReceiptSigningKeyPath::new(path)
}

async fn start_relay(
    root: &Path,
) -> Result<
    (
        RelayV2ServerHandle,
        agentdeck_protocol::relay_v2::EnrollmentBundleV2,
    ),
    RelayV2ServerError,
> {
    let (cert, key) = write_localhost_tls_identity(root);
    let identity = load_tls_identity(&TlsIdentityPaths::new(&cert, &key))
        .await
        .expect("load Relay test TLS identity");
    let (bind, health_bind) = reserve_loopback_ports();
    let admin_dir = root.join("relay-admin");
    fs::create_dir(&admin_dir).expect("create Relay admin directory");
    fs::set_permissions(&admin_dir, fs::Permissions::from_mode(0o700))
        .expect("secure Relay admin directory");
    let admin_socket = admin_dir.join("relay.sock");
    let mut store = RelayV2StoreSettings::new(root.join("relay-store/relay.db"));
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    let public_wss_url = format!("wss://localhost:{}/", bind.port());
    let handle = RelayV2ServerHandle::start(RelayV2ServerConfig {
        bind,
        health_bind,
        store,
        transport: RelayV2TransportMode::DirectTls(RelayV2TlsPaths { cert, key }),
        admin: Some(RelayV2AdminConfig {
            socket_path: admin_socket.clone(),
            public_wss_url,
            spki_pins: vec![identity.leaf_spki_sha256()],
        }),
        receipt_signing_key: write_receipt_signing_key(root),
        log_level: "info".to_owned(),
    })
    .await?;
    let response = AdminClient::new(admin_socket)
        .request(&AdminRequest::MachineEnrollCreate {})
        .await
        .expect("create one-shot machine enrollment bundle");
    let AdminResponse::Ok { result } = response else {
        panic!("Relay admin enrollment create failed: {response:?}");
    };
    let AdminResult::EnrollmentBundle { bundle } = *result else {
        panic!("Relay admin returned unrelated result");
    };
    Ok((handle, bundle))
}

fn stable_daemon_config(root: &Path) -> DaemonConfig {
    let home = root.join("home");
    fs::create_dir_all(home.join("Library/Application Support"))
        .expect("create isolated stable home parents");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
        .expect("secure isolated stable home");
    DaemonConfig::resolve_with_roots(
        DaemonStartupOptions {
            stable_keychain_access_group: Some("TESTTEAM.com.agentdeck.agentdeckd".to_owned()),
            ..DaemonStartupOptions::default()
        },
        &home,
        root,
    )
    .expect("resolve isolated stable daemon namespace")
}

async fn unary(client: &RuntimeUnixClient, request: RuntimeRequest) -> RuntimeReply {
    match tokio::time::timeout(IO_TIMEOUT, client.request(request))
        .await
        .expect("Runtime UDS request deadline")
        .expect("Runtime UDS request")
    {
        ReplySequenceItem::Reply(reply) => *reply,
        ReplySequenceItem::TransferComplete(_) => panic!("pairing administration is unary"),
    }
}

fn pair_context(
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
    kind: OuterFrameKind,
) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: kind,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

async fn next_pair_data(client: &mut RelayPairingClient) -> PairData {
    loop {
        match tokio::time::timeout(IO_TIMEOUT, client.next_event())
            .await
            .expect("pairing receive deadline")
            .expect("pairing receive")
            .expect("pairing connection remains open")
        {
            PairingEvent::Data(data) => return data,
            PairingEvent::RouteAccepted(_) => {}
            PairingEvent::Failure(failure) => panic!("Relay pairing failure: {}", failure.code),
            PairingEvent::RouteClosed(closed) => {
                panic!("PairRoute closed before response: {closed:?}")
            }
            PairingEvent::ServerRestarting(restarting) => {
                panic!("Relay restarted before response: {restarting:?}")
            }
        }
    }
}

async fn await_already_absent_route_close(client: &mut RelayPairingClient) {
    loop {
        match tokio::time::timeout(IO_TIMEOUT, client.next_event())
            .await
            .expect("PairRoute close deadline")
            .expect("PairRoute close receive")
            .expect("PairRoute close terminal")
        {
            PairingEvent::RouteClosed(closed) => {
                assert_eq!(closed.outcome, PairRouteCloseOutcome::AlreadyAbsent);
                return;
            }
            PairingEvent::RouteAccepted(_) => {}
            PairingEvent::Data(_) => panic!("unexpected PairData after delivery receipt"),
            PairingEvent::Failure(failure) => panic!("Relay close failure: {}", failure.code),
            PairingEvent::ServerRestarting(restarting) => {
                panic!("Relay restarted before close: {restarting:?}")
            }
        }
    }
}

fn assert_durable_delivery(database: &Path) -> bool {
    let Ok(connection) = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return false;
    };
    let counts = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM remote_pairings),
            (SELECT COUNT(*) FROM remote_pairing_receipts WHERE action = 'confirmed'),
            (SELECT COUNT(*) FROM remote_authorization_ledger WHERE lifecycle = 'active')",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    );
    matches!(counts, Ok((0, 1, 1)))
}

fn relay_device_grant_count(database: &Path) -> i64 {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Relay DB read-only")
    .query_row("SELECT COUNT(*) FROM device_grants", [], |row| row.get(0))
    .expect("read Relay device grant count")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_uds_real_relay_pairing_delivers_one_active_grant_and_closes_route() {
    let root = TempDirBuilder::new()
        .prefix("ad-p43-")
        .tempdir_in("/tmp")
        .expect("pairing state-machine temp root");
    let root_path = fs::canonicalize(root.path()).expect("canonicalize pairing temp root");
    let (relay, bundle) = start_relay(&root_path)
        .await
        .expect("start real Relay TLS server");
    let config = stable_daemon_config(&root_path);
    let singleton = SingletonGuard::acquire(config.paths()).expect("acquire isolated singleton");
    let key_store = Arc::new(MemoryKeyStore::new());
    let storage_kek = load_or_create_storage_kek(key_store.as_ref(), &config.paths().runtime_db)
        .expect("load isolated StorageKEK");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(config.paths().runtime_db.clone()),
        storage_kek,
    )
    .await
    .expect("open Runtime store");
    let bootstrap = reconcile_machine_identity(&config, &store, key_store.as_ref())
        .await
        .expect("bootstrap machine identity");
    let manager = Arc::new(RemoteManager::new(
        store.clone(),
        key_store,
        config.clone(),
        bootstrap,
    ));
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = RuntimeCore::new_production(store.clone(), router)
        .expect("construct RuntimeCore")
        .with_remote_administration(manager.clone())
        .with_pairing_administration(manager.clone())
        .with_revocation_administration(manager.clone());
    assert!(manager.install_pairing_pending_sink(core.pairing_pending_sink()));
    let core = Arc::new(core);
    let (_, recovery_ready) = core
        .recover_for_startup()
        .await
        .expect("recover RuntimeCore");
    let mut listener =
        BoundLocalListener::bind_after_recovery(recovery_ready, &config, &singleton, core.clone())
            .await
            .expect("bind stable Runtime UDS");
    let socket = listener.local_ready_permit().socket_path().to_path_buf();
    let remote_start = listener
        .take_remote_start_permit()
        .expect("stable listener yields remote start permit");
    let (stop_tx, stop_rx) = oneshot::channel();
    let manager_for_shutdown = manager.clone();
    let listener_task = tokio::spawn(async move {
        listener
            .serve_until(async move {
                let _ = stop_rx.await;
                manager_for_shutdown.shutdown().await;
                Ok(())
            })
            .await
    });
    manager.arm(remote_start).await.expect("arm remote manager");

    let cli = RuntimeUnixClient::connect_injected(InjectedEndpoint::for_test(socket))
        .await
        .expect("connect real CLI Runtime transport");
    let enrollment_reply = unary(
        &cli,
        RuntimeRequest::MachineEnroll(MachineEnrollRequest {
            bundle,
            scope: LocalOnlyAdministration::LocalOnly,
        }),
    )
    .await;
    assert!(
        matches!(enrollment_reply, RuntimeReply::MachineRemoteStatus(_)),
        "machine enrollment returned {enrollment_reply:?}"
    );

    let invite_reply = unary(
        &cli,
        RuntimeRequest::CreatePairInvite(CreatePairInviteRequest {
            display_name: "真实链路测试机器".to_owned(),
            idempotency_key: IdempotencyKey::new("p43-real-relay-pairing"),
            scope: LocalOnlyAdministration::LocalOnly,
        }),
    )
    .await;
    let RuntimeReply::PairInvite(invite_reply) = invite_reply else {
        panic!("create PairInvite returned unrelated Runtime reply: {invite_reply:?}");
    };
    let pairing_id = invite_reply.pairing_id.clone();
    let invite = invite_reply.invite;
    let pair_config = RelayClientConfig::new(
        &invite.wss_url,
        invite.relay_server_id,
        RelayTlsPolicy::pinned_spki(vec![invite.current_spki_pin])
            .expect("construct invite pin policy"),
    )
    .expect("construct pairing Relay client config");
    let mut device = RelayPairingClient::connect_pairing(
        pair_config,
        PairingHello {
            relay_server_id: invite.relay_server_id,
            pair_route: invite.pair_route,
        },
    )
    .await
    .expect("connect remote pairing client");

    let device_sign = SigningKey::from_seed(&[0x62; 32]);
    let (device_hpke, device_hpke_public) = HpkePrivateKey::derive_keypair(&[0x63; 32]);
    let plaintext = PairRequestPlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        invite_secret: invite.invite_secret,
        device_sign_pubkey: agentdeck_protocol::relay_v2::PublicKeyBytes(
            device_sign.verifying_key().to_bytes(),
        ),
        device_hpke_pubkey: agentdeck_protocol::relay_v2::PublicKeyBytes(
            device_hpke_public
                .to_bytes()
                .try_into()
                .expect("X25519 public key is 32 bytes"),
        ),
        authorization_request: AuthorizationRequestV1 {
            format_version: E2EE_FORMAT_VERSION,
            device_display_name: "真实链路测试设备".to_owned(),
            capabilities: vec![AuthorizationCapabilityV1::Catalog],
            permissions: vec![AuthorizationPermissionV1::CatalogRead],
        },
    };
    let request_info = PairRequestInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: invite.pair_route,
        invite_hash: invite.canonical_sha256().expect("canonical invite"),
        expiry_ms: invite.expires_at_ms,
    };
    let request_context = pair_context(invite.pair_route, OuterFrameKind::PairRequest);
    let request = seal_pair_request(
        &HpkePublicKey::from_bytes(&invite.invite_hpke_pubkey.0).expect("invite HPKE key"),
        &request_info,
        &request_context,
        &plaintext,
        &device_sign,
        &mut ChaCha20Rng::from_seed([0x64; 32]),
    )
    .expect("seal PairRequest");
    let request_hash = request.canonical_sha256().expect("PairRequest hash");
    device
        .send_pair_data(PairData {
            pair_route: invite.pair_route,
            sealed_blob: SealedBlob(request.canonical_bytes().expect("canonical PairRequest")),
        })
        .await
        .expect("send PairRequest through real Relay");

    let pending_data = next_pair_data(&mut device).await;
    let pending_envelope =
        PairingControlEnvelopeV1::from_canonical_bytes(&pending_data.sealed_blob.0)
            .expect("decode PairPending envelope");
    let data_verifier = VerifyingKey::from_bytes(&invite.data_sign_cert.subject_pubkey.0)
        .expect("MachineDataSign public key");
    let data_signer = MachineDataSignerBindingV1::from_certificate(&invite.data_sign_cert)
        .expect("MachineDataSign binding");
    let pending = open_pair_pending(
        &device_hpke,
        &request_info,
        &pair_context(invite.pair_route, OuterFrameKind::PairPending),
        &pending_envelope,
        &data_verifier,
        &data_signer,
    )
    .expect("open signed PairPending");
    assert_eq!(pending.request_hash, request_hash);

    let RuntimeReply::PendingPairings { pairings } = unary(
        &cli,
        RuntimeRequest::ListPendingPairings {
            scope: LocalOnlyAdministration::LocalOnly,
        },
    )
    .await
    else {
        panic!("list pending returned unrelated Runtime reply");
    };
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0].pairing_id, pairing_id);
    assert_eq!(pairings[0].request_hash, request_hash);
    assert_eq!(
        relay_device_grant_count(&root_path.join("relay-store/relay.db")),
        0,
        "本机确认前 Relay 不得存在 DeviceGrant"
    );

    assert!(matches!(
        unary(
            &cli,
            RuntimeRequest::ConfirmPairing {
                pairing_id,
                scope: LocalOnlyAdministration::LocalOnly,
            },
        )
        .await,
        RuntimeReply::Pairing(PairingReceipt::Confirmed { .. })
    ));

    let response_data = next_pair_data(&mut device).await;
    let response = PairResponseV1::from_canonical_bytes(&response_data.sealed_blob.0)
        .expect("decode PairResponse with authenticated clear info");
    let response_info = response.info.clone();
    assert_eq!(response_info.relay_server_id, request_info.relay_server_id);
    assert_eq!(response_info.pair_route, request_info.pair_route);
    assert_eq!(response_info.invite_hash, request_info.invite_hash);
    assert_eq!(response_info.expiry_ms, request_info.expiry_ms);
    assert_eq!(response_info.request_hash, request_hash);
    let root_verifier =
        VerifyingKey::from_bytes(&invite.machine_root_pubkey.0).expect("MachineRoot public key");
    verify_tbs(
        &root_verifier,
        &invite.data_sign_cert.to_be_signed_v1(
            invite.relay_server_id,
            response_info.machine_route,
            invite.machine_root_fingerprint,
        ),
        &SignatureBytes::from(invite.data_sign_cert.signature),
    )
    .expect("verify invite MachineDataSign certificate after clear response binding");
    let response_plaintext = open_pair_response(
        &device_hpke,
        &response_info,
        &pair_context(invite.pair_route, OuterFrameKind::PairResponse),
        &response,
        &data_verifier,
        &data_signer,
        &root_verifier,
    )
    .expect("open and verify PairResponse");
    assert_eq!(response_plaintext.request_hash, request_hash);
    assert_eq!(
        response_plaintext.relay_grant.machine_route,
        response_info.machine_route
    );
    assert_eq!(
        response_plaintext.relay_grant.device_route,
        response_info.device_route
    );
    assert_eq!(
        response_plaintext.relay_grant.grant_serial,
        response_info.grant_serial
    );

    device
        .send_pair_data(PairData {
            pair_route: invite.pair_route,
            sealed_blob: SealedBlob(request.canonical_bytes().expect("canonical replay request")),
        })
        .await
        .expect("replay exact PairRequest through real Relay");
    let replayed_response_data = next_pair_data(&mut device).await;
    assert_eq!(
        replayed_response_data.sealed_blob, response_data.sealed_blob,
        "exact PairRequest replay must return the byte-identical frozen PairResponse"
    );

    let response_hash = response.canonical_sha256().expect("PairResponse hash");
    let grant_hash = response_plaintext.relay_grant.canonical_sha256();
    let receipt_envelope = seal_pair_response_received(
        &HpkePublicKey::from_bytes(&invite.invite_hpke_pubkey.0).expect("invite receipt key"),
        &response_info,
        &pair_context(invite.pair_route, OuterFrameKind::PairResponseReceived),
        PairResponseReceivedV1 {
            request_hash,
            grant_hash,
            response_hash,
            signature: Ed25519Signature([0; 64]),
        },
        &device_sign,
        &mut ChaCha20Rng::from_seed([0x65; 32]),
    )
    .expect("seal DeviceSign PairResponseReceived");
    device
        .send_pair_data(PairData {
            pair_route: invite.pair_route,
            sealed_blob: SealedBlob(
                receipt_envelope
                    .canonical_bytes()
                    .expect("canonical PairResponseReceived envelope"),
            ),
        })
        .await
        .expect("send PairResponseReceived through real Relay");

    for _ in 0..100 {
        if assert_durable_delivery(&config.paths().runtime_db) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        assert_durable_delivery(&config.paths().runtime_db),
        "delivery must erase live pairing state, retain one confirmed receipt and activate one grant"
    );
    device
        .request_close(ClosePairRoute {
            machine_route: response_info.machine_route,
            pair_route: invite.pair_route,
        })
        .await
        .expect("request idempotent close after machine terminal ACK");
    await_already_absent_route_close(&mut device).await;
    drop(device);

    cli.close().await.expect("close CLI Runtime transport");
    stop_tx.send(()).expect("signal daemon listener shutdown");
    listener_task
        .await
        .expect("join daemon listener task")
        .expect("stop daemon listener");
    core.shutdown().await.expect("shutdown RuntimeCore");
    relay.shutdown().await.expect("shutdown Relay server");

    let readonly = Connection::open_with_flags(
        &config.paths().runtime_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("reopen final Runtime DB read-only");
    let active: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM remote_authorization_ledger WHERE lifecycle = 'active'",
            [],
            |row| row.get(0),
        )
        .expect("read final authorization count");
    assert_eq!(active, 1);
    let relay_frame = encode(&agentdeck_protocol::relay_v2::OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(response_data),
    });
    assert!(
        !relay_frame
            .windows("真实链路测试设备".len())
            .any(|window| { window == "真实链路测试设备".as_bytes() })
    );
    assert_ne!(sha256(&relay_frame), [0; 32]);
}
