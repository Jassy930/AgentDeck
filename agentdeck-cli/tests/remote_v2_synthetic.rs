#![cfg(unix)]

use std::net::TcpListener as StdTcpListener;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256};
use agentdeck_protocol::relay_v2::EnrollmentCode;
use agentdeck_relay::config::{
    RelayReceiptSigningKeyPath, RelayV2AdminConfig, RelayV2ServerConfig, RelayV2StoreSettings,
    RelayV2TlsPaths, RelayV2TransportMode,
};
use agentdeck_relay::v2::admin::protocol::{ADMIN_PROTOCOL_VERSION, Digest32, EnrollmentBundleV2};
use agentdeck_relay::v2::server::RelayV2ServerHandle;
use agentdeck_relay::v2::server::tls::{TlsIdentityPaths, load_tls_identity};
use agentdeck_relay::v2::store::{
    EnrollmentCodeSeed, MachineInventoryQuery, MachineReadbackQuery, RelayStoreHandle,
};
use rand::RngCore as _;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::timeout;

const SECRET_SENTINEL: &str = "relay-v1-secret-must-never-be-echoed";
const E2EE_SENTINEL: &[u8] = b"AGENTDECK_SYNTHETIC_E2EE_SENTINEL_9F4A7C21";
const CLI_TIMEOUT: Duration = Duration::from_secs(20);
const ZERO_DIAL_WINDOW: Duration = Duration::from_millis(150);

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

fn reserve_loopback_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let port = listener.local_addr().expect("reserved address").port();
    drop(listener);
    port
}

fn write_localhost_identity(temp: &TempDir) -> (PathBuf, PathBuf) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).expect("localhost identity");
    let cert_path = temp.path().join("relay-cert.pem");
    let key_path = temp.path().join("relay-key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write certificate");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write private key");
    (cert_path, key_path)
}

async fn prepare_real_relay(
    temp: &TempDir,
) -> (
    RelayV2ServerHandle,
    RelayV2StoreSettings,
    EnrollmentBundleV2,
    PathBuf,
) {
    let public_port = reserve_loopback_port();
    let (cert, key) = write_localhost_identity(temp);
    let identity = load_tls_identity(&TlsIdentityPaths::new(&cert, &key))
        .await
        .expect("load generated TLS identity");
    let pin = identity.leaf_spki_sha256();

    let admin_dir = temp.path().join("admin");
    std::fs::create_dir(&admin_dir).expect("create admin directory");
    std::fs::set_permissions(&admin_dir, std::fs::Permissions::from_mode(0o700))
        .expect("secure admin directory");
    let admin_socket = admin_dir.join("relay.sock");

    let store_dir = temp.path().join("relay-data");
    std::fs::create_dir(&store_dir).expect("create Relay data directory");
    std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700))
        .expect("secure Relay data directory");
    let mut store_settings = RelayV2StoreSettings::new(store_dir.join("relay.db"));
    store_settings.disk_reserve_bytes = 0;
    store_settings.disk_reserve_percent = 0;

    let mut code_bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut code_bytes);
    let code = EnrollmentCode(code_bytes);
    let expires_at_ms = unix_now_ms().saturating_add(5 * 60 * 1_000);
    let receipt_seed = [0x71_u8; 32];
    let canonical_temp =
        std::fs::canonicalize(temp.path()).expect("canonicalize temporary Relay directory");
    std::fs::set_permissions(&canonical_temp, std::fs::Permissions::from_mode(0o700))
        .expect("secure temporary Relay directory");
    let receipt_signing_key = canonical_temp.join("receipt-signing.seed");
    std::fs::write(&receipt_signing_key, receipt_seed).expect("write receipt signer seed");
    std::fs::set_permissions(&receipt_signing_key, std::fs::Permissions::from_mode(0o600))
        .expect("secure receipt signer seed");
    let receipt_signer_identity = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(
        &SigningKey::from_seed(&receipt_seed),
    )
    .expect("valid receipt signer identity");
    let seed_store = RelayStoreHandle::open(
        store_settings
            .clone()
            .into_store_config(receipt_signer_identity)
            .expect("store config"),
    )
    .await
    .expect("open seed store");
    let relay_server_id = seed_store.relay_server_id();
    seed_store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: sha256(&code_bytes),
            expires_at_ms,
        })
        .await
        .expect("seed one enrollment code");
    seed_store.shutdown().await.expect("close seed store");

    let public_wss_url = format!("wss://localhost:{public_port}/");
    let config = RelayV2ServerConfig {
        bind: format!("127.0.0.1:{public_port}")
            .parse()
            .expect("public bind"),
        health_bind: "127.0.0.1:0".parse().expect("health bind"),
        store: store_settings.clone(),
        transport: RelayV2TransportMode::DirectTls(RelayV2TlsPaths { cert, key }),
        admin: Some(RelayV2AdminConfig {
            socket_path: admin_socket,
            public_wss_url: public_wss_url.clone(),
            spki_pins: vec![pin],
        }),
        receipt_signing_key: RelayReceiptSigningKeyPath::new(receipt_signing_key),
        log_level: "warn".to_owned(),
    };
    let handle = RelayV2ServerHandle::start(config)
        .await
        .expect("start real DirectTLS Relay v2");
    let bundle = EnrollmentBundleV2 {
        version: ADMIN_PROTOCOL_VERSION,
        public_wss_url,
        relay_server_id,
        receipt_verify_key: receipt_signer_identity
            .bind_to_relay(relay_server_id)
            .expect("bind receipt signer to Relay")
            .wire_anchor()
            .clone(),
        code,
        spki_pins: vec![Digest32(pin)],
        expires_at_ms,
    };
    let bundle_path = temp.path().join("enrollment-bundle.json");
    std::fs::write(
        &bundle_path,
        serde_json::to_vec(&bundle).expect("serialize enrollment bundle"),
    )
    .expect("write enrollment bundle");
    std::fs::set_permissions(&bundle_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure enrollment bundle");
    std::fs::set_permissions(&bundle_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure enrollment bundle");
    (handle, store_settings, bundle, bundle_path)
}

async fn run_cli(arguments: &[&str]) -> std::process::Output {
    timeout(
        CLI_TIMEOUT,
        Command::new(env!("CARGO_BIN_EXE_agentdeck"))
            .args(arguments)
            .output(),
    )
    .await
    .expect("agentdeck CLI timed out")
    .expect("run agentdeck CLI")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_synthetic_drives_a_real_direct_tls_relay_and_persists_the_full_flow() {
    let temp = TempDir::new().expect("tempdir");
    let (handle, store_settings, bundle, bundle_path) = prepare_real_relay(&temp).await;

    let output = run_cli(&[
        "remote",
        "synthetic",
        "--bundle",
        bundle_path.to_str().expect("UTF-8 bundle path"),
    ])
    .await;
    assert!(
        output.status.success(),
        "synthetic v2 failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "successful synthetic must keep stderr clean"
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("synthetic emits one JSON report");
    assert_eq!(report["ok"], true);
    assert_eq!(report["relayProtocolVersion"], 2);
    assert_eq!(report["transport"], "wss+spki");
    assert_eq!(
        report["checks"],
        serde_json::json!([
            "challenge-auth",
            "register-publish-subscribe-replay",
            "send-reply",
            "signed-revoke-terminal",
            "opaque-relay-payload"
        ])
    );
    let rendered = String::from_utf8(output.stdout).expect("report UTF-8");
    let code_json = serde_json::to_string(&bundle.code).expect("code JSON");
    assert!(
        !rendered.contains(code_json.trim_matches('"')),
        "report must not echo the one-shot enrollment code"
    );
    assert!(
        !rendered
            .as_bytes()
            .windows(E2EE_SENTINEL.len())
            .any(|window| window == E2EE_SENTINEL),
        "report must not echo encrypted synthetic plaintext"
    );

    handle.shutdown().await.expect("shutdown real Relay");
    let readback_store = RelayStoreHandle::open(
        store_settings
            .clone()
            .into_store_config(
                ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&SigningKey::from_seed(
                    &[0x71; 32],
                ))
                .expect("valid readback receipt signer identity"),
            )
            .expect("readback config"),
    )
    .await
    .expect("reopen Relay store");
    let inventory = readback_store
        .machine_inventory(MachineInventoryQuery::default())
        .await
        .expect("machine inventory");
    assert_eq!(
        inventory.entries.len(),
        1,
        "CLI must enroll exactly one machine"
    );
    let machine = &inventory.entries[0];
    assert_eq!(machine.relay_server_id, bundle.relay_server_id);
    assert!(!machine.retired);
    let readback = readback_store
        .machine_readback(MachineReadbackQuery {
            machine_route: machine.machine_route,
            expected_root_fingerprint: machine.root_fingerprint,
        })
        .await
        .expect("machine readback");
    assert_eq!(readback.data.active_machine_routes, 1);
    assert_eq!(readback.data.device_grants, 1, "InstallGrant must commit");
    assert_eq!(readback.data.revocations, 1, "signed revoke must commit");
    assert_eq!(readback.data.streams, 1, "RegisterStream must commit");
    assert_eq!(
        readback.data.frames, 1,
        "Publish must persist before replay"
    );
    assert_eq!(
        readback.data.subscriptions, 0,
        "signed revoke must remove the device replay lease after it was exercised"
    );
    readback_store
        .shutdown()
        .await
        .expect("shutdown readback store");

    let database = std::fs::read(&store_settings.storage_path).expect("read Relay DB bytes");
    assert!(
        !database
            .windows(bundle.code.0.len())
            .any(|window| window == bundle.code.0),
        "Relay DB must contain only the enrollment code hash"
    );
    assert!(
        !database
            .windows(E2EE_SENTINEL.len())
            .any(|window| window == E2EE_SENTINEL),
        "Relay DB must persist only the AEAD sealed stream payload"
    );
}

async fn assert_no_connection(listener: &TcpListener) {
    assert!(
        timeout(ZERO_DIAL_WINDOW, listener.accept()).await.is_err(),
        "locally rejected legacy/persistent command must perform zero network dial"
    );
}

fn legacy_marker(data_dir: &Path, profile: &str) -> PathBuf {
    data_dir
        .join("relay")
        .join(format!("{profile}.credentials.json"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_credential_marker_is_byte_identical_and_rejected_before_network() {
    let temp = TempDir::new().expect("tempdir");
    let marker = legacy_marker(temp.path(), "stable");
    std::fs::create_dir(marker.parent().expect("marker parent")).expect("create relay dir");
    let original = format!(r#"{{"credential":"{SECRET_SENTINEL}"}}"#).into_bytes();
    std::fs::write(&marker, &original).expect("write legacy marker");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("dial sentinel");
    let relay = format!(
        "wss://{}/",
        listener.local_addr().expect("listener address")
    );

    let output = run_cli(&[
        "--data-dir",
        temp.path().to_str().expect("UTF-8 temp path"),
        "remote",
        "sessions",
        "--relay",
        &relay,
        "legacy-machine",
    ])
    .await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "remote.v1.reset_required"
    );
    assert_eq!(std::fs::read(&marker).expect("read marker"), original);
    assert_no_connection(&listener).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dangling_legacy_marker_symlink_is_still_reset_required_and_never_followed() {
    let temp = TempDir::new().expect("tempdir");
    let marker = legacy_marker(temp.path(), "stable");
    std::fs::create_dir(marker.parent().expect("marker parent")).expect("create relay dir");
    let missing = temp.path().join("missing-secret-target");
    symlink(&missing, &marker).expect("create dangling marker symlink");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("dial sentinel");
    let relay = format!(
        "wss://{}/",
        listener.local_addr().expect("listener address")
    );

    let output = run_cli(&[
        "--data-dir",
        temp.path().to_str().expect("UTF-8 temp path"),
        "remote",
        "sessions",
        "--relay",
        &relay,
        "legacy-machine",
    ])
    .await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "remote.v1.reset_required"
    );
    assert!(
        std::fs::symlink_metadata(&marker)
            .expect("marker metadata")
            .file_type()
            .is_symlink()
    );
    assert!(
        !missing.exists(),
        "CLI must not follow or create the symlink target"
    );
    assert_no_connection(&listener).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_remote_without_a_legacy_marker_is_typed_unsupported_and_never_dials() {
    let temp = TempDir::new().expect("tempdir");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("dial sentinel");
    let relay = format!(
        "wss://{}/",
        listener.local_addr().expect("listener address")
    );
    let output = run_cli(&[
        "--data-dir",
        temp.path().to_str().expect("UTF-8 temp path"),
        "remote",
        "sessions",
        "--relay",
        &relay,
        "legacy-machine",
    ])
    .await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "remote.persistent.unsupported"
    );
    assert_no_connection(&listener).await;
}

#[test]
fn forbidden_pair_argv_secrets_are_rejected_without_echo() {
    let raw_invite = format!("agentdeck-pair:v1:{SECRET_SENTINEL}");
    for args in [
        vec![
            "remote",
            "pair",
            "--relay",
            "wss://127.0.0.1:1",
            "--bootstrap-secret",
            SECRET_SENTINEL,
            "--role",
            "machine",
        ],
        vec![
            "remote",
            "pair",
            raw_invite.as_str(),
            "--confirm-root-fingerprint",
            "sha256:00",
        ],
        vec![
            "--data-dir",
            raw_invite.as_str(),
            "remote",
            "pair",
            "--invite-stdin",
            "--confirm-root-fingerprint",
            "sha256:00",
        ],
    ] {
        let output = StdCommand::new(env!("CARGO_BIN_EXE_agentdeck"))
            .args(args)
            .output()
            .expect("run rejected remote pair argv secret");

        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stdout.contains(r#""code":"usage""#));
        assert!(stdout.contains("only through --invite-file or --invite-stdin"));
        assert!(stderr.contains("only through --invite-file or --invite-stdin"));
        assert!(!stdout.contains(SECRET_SENTINEL));
        assert!(!stderr.contains(SECRET_SENTINEL));
    }
}

#[test]
fn production_identity_gate_runs_before_missing_invite_file_read() {
    let missing = format!("/tmp/agentdeck-missing-{SECRET_SENTINEL}");
    let output = StdCommand::new(env!("CARGO_BIN_EXE_agentdeck"))
        .args([
            "remote",
            "pair",
            "--invite-file",
            missing.as_str(),
            "--confirm-root-fingerprint",
            "sha256:00",
        ])
        .output()
        .expect("run production-gated remote pair");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert!(
        envelope["error"]["code"]
            .as_str()
            .is_some_and(|code| code.starts_with("remote.persistent."))
    );
    assert!(!stdout.contains("remote.pairing.input_unsafe"));
    assert!(!stdout.contains(SECRET_SENTINEL));
    assert!(!stderr.contains(SECRET_SENTINEL));
}
