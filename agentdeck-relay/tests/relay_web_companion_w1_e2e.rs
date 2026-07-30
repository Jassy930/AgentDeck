#![cfg(all(feature = "server", feature = "tls"))]

mod support;

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::e2ee::SignedSealedBlobV1;
use agentdeck_protocol::relay_v2::{RELAY_PROTOCOL_VERSION, RelayServerId};
use agentdeck_relay::config::{
    RelayV2ServerConfig, RelayV2StoreSettings, RelayV2TlsPaths, RelayV2TransportMode,
};
use agentdeck_relay::v2::server::RelayV2ServerHandle;
use agentdeck_relay::v2::store::{EnrollmentCodeSeed, RegisterMachine, RelayStoreHandle};
use agentdeck_web_core::{W1_SENTINEL, w1_test_identity};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::process::Command;
use x509_parser::prelude::{FromDer, X509Certificate};

use support::{test_receipt_identity, write_test_receipt_signing_key};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("agentdeck-relay has repository parent")
        .to_path_buf()
}

fn web_root() -> PathBuf {
    repository_root().join("web/relay-test-companion")
}

fn unix_now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_millis(),
    )
    .expect("current timestamp fits u64")
}

fn relay_server_id_hex(id: RelayServerId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unused_web_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve Web test port");
    listener.local_addr().expect("Web test address").port()
}

fn fresh_chrome_tls(temp: &TempDir) -> (RelayV2TlsPaths, String) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate W1 localhost certificate");
    let cert_path = temp.path().join("w1-cert.pem");
    let key_path = temp.path().join("w1-key.pem");
    fs::write(&cert_path, certified.cert.pem()).expect("write W1 certificate");
    fs::write(&key_path, certified.key_pair.serialize_pem()).expect("write W1 key");
    let (_, certificate) =
        X509Certificate::from_der(certified.cert.der().as_ref()).expect("parse W1 certificate");
    let spki_pin = STANDARD.encode(Sha256::digest(certificate.tbs_certificate.subject_pki.raw));
    (
        RelayV2TlsPaths {
            cert: cert_path,
            key: key_path,
        },
        spki_pin,
    )
}

fn server_config(temp: &TempDir) -> (RelayV2ServerConfig, PathBuf, String) {
    let storage_path = temp.path().join("relay-data").join("relay.db");
    let mut store = RelayV2StoreSettings::new(storage_path.clone());
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    let (tls, spki_pin) = fresh_chrome_tls(temp);
    (
        RelayV2ServerConfig {
            bind: "127.0.0.1:0".parse().expect("loopback bind"),
            health_bind: "127.0.0.1:0".parse().expect("loopback health bind"),
            store,
            transport: RelayV2TransportMode::DirectTls(tls),
            admin: None,
            receipt_signing_key: write_test_receipt_signing_key(temp.path()),
            log_level: "info".to_owned(),
        },
        storage_path,
        spki_pin,
    )
}

async fn seed_machine(config: &RelayV2ServerConfig) -> RelayServerId {
    let store = RelayStoreHandle::open(
        config
            .store
            .clone()
            .into_store_config(test_receipt_identity())
            .expect("W1 seed Store config"),
    )
    .await
    .expect("open W1 seed Store");
    let relay_server_id = store.relay_server_id();
    let identity = w1_test_identity(relay_server_id);
    let code_hash = [0x71; 32];
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash,
            expires_at_ms: unix_now_ms().saturating_add(60_000),
        })
        .await
        .expect("seed W1 enrollment code");
    store
        .register_machine(RegisterMachine {
            code_hash,
            request_hash: [0x72; 32],
            machine_route: identity.machine_route,
            root_pubkey: identity.root_pubkey,
            link_cert: identity.link_cert.clone(),
            data_cert: identity.data_cert.clone(),
            link_cert_hash: identity.link_cert.canonical_sha256(),
            data_cert_hash: identity.data_cert.canonical_sha256(),
        })
        .await
        .expect("register W1 machine principal");
    store.shutdown().await.expect("shutdown W1 seed Store");
    relay_server_id
}

async fn run_command(mut command: Command, stage: &str) -> Output {
    let output = command.output().await.expect("spawn W1 command");
    if !output.status.success() {
        panic!(
            "{stage} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output
}

async fn prepare_web_build() {
    let mut install = Command::new("bun");
    install
        .current_dir(web_root())
        .args(["install", "--frozen-lockfile"]);
    run_command(install, "bun install").await;

    let mut check = Command::new("bun");
    check.current_dir(web_root()).args(["run", "check"]);
    run_command(check, "Web ownership check").await;

    let mut build = Command::new("bun");
    build.current_dir(web_root()).args(["run", "build:w1"]);
    run_command(build, "W1 WASM build").await;
}

async fn run_browser_case(
    case_name: &str,
    origin: &str,
    relay_server_id_hex: &str,
    spki_pin: &str,
) -> Output {
    let mut command = Command::new("bun");
    command
        .current_dir(web_root())
        .args([
            "run",
            "test:browser:built",
            "--",
            "--grep",
            "W1 harness case",
        ])
        .env("AGENTDECK_W1_CASE", case_name)
        .env("AGENTDECK_W1_WSS_ORIGIN", origin)
        .env("AGENTDECK_W1_RELAY_SERVER_ID_HEX", relay_server_id_hex)
        .env("AGENTDECK_W1_TEST_SPKI_PIN", spki_pin)
        .env("RELAY_WEB_TEST_PORT", unused_web_port().to_string());
    let output = run_command(command, case_name).await;
    assert!(
        !output
            .stdout
            .windows(W1_SENTINEL.len())
            .any(|window| window == W1_SENTINEL)
    );
    assert!(
        !output
            .stderr
            .windows(W1_SENTINEL.len())
            .any(|window| window == W1_SENTINEL)
    );
    output
}

fn frame_count(storage_path: &Path) -> i64 {
    let connection = Connection::open_with_flags(storage_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open W1 Store read-only");
    connection
        .query_row("SELECT COUNT(*) FROM frames", [], |row| row.get(0))
        .expect("count W1 frames")
}

fn assert_persisted_sentinel_is_sealed(storage_path: &Path) {
    let connection = Connection::open_with_flags(storage_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open W1 Store read-only");
    let (count, sealed_blob): (i64, Vec<u8>) = connection
        .query_row("SELECT COUNT(*), sealed_blob FROM frames", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("read W1 sealed frame");
    assert_eq!(count, 1);
    assert_eq!(
        SignedSealedBlobV1::from_wire_bytes(&sealed_blob)
            .expect("persisted W1 blob is canonical E2EE")
            .inner
            .format_version,
        1
    );
    assert!(
        !sealed_blob
            .windows(W1_SENTINEL.len())
            .any(|window| window == W1_SENTINEL)
    );
}

fn assert_temp_root_has_no_plaintext(path: &Path) {
    let mut pending = vec![path.to_path_buf()];
    while let Some(candidate) = pending.pop() {
        for entry in fs::read_dir(&candidate).expect("scan W1 temp root") {
            let entry = entry.expect("read W1 temp entry");
            let file_type = entry.file_type().expect("read W1 file type");
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let bytes = fs::read(entry.path()).expect("read W1 temp artifact");
                assert!(
                    !bytes
                        .windows(W1_SENTINEL.len())
                        .any(|window| window == W1_SENTINEL),
                    "W1 plaintext sentinel leaked into temp artifact"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_chrome_authenticates_routes_sealed_sentinel_and_recovers_after_restart() {
    assert_eq!(RELAY_PROTOCOL_VERSION, 2);
    prepare_web_build().await;

    let temp = TempDir::new().expect("W1 temp root");
    let (config, storage_path, spki_pin) = server_config(&temp);
    let relay_server_id = seed_machine(&config).await;
    let correct_id = relay_server_id_hex(relay_server_id);
    let mut wrong_id = *relay_server_id.as_bytes();
    wrong_id[0] ^= 0x01;
    let wrong_id = wrong_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let server = RelayV2ServerHandle::start(config.clone())
        .await
        .expect("start W1 TLS Relay");
    let first_origin = format!("wss://localhost:{}/", server.public_addr().port());
    run_browser_case("positive", &first_origin, &correct_id, &spki_pin).await;
    assert_eq!(frame_count(&storage_path), 1);

    for (case_name, server_id) in [
        ("wrongServer", wrong_id.as_str()),
        ("tamperChallenge", correct_id.as_str()),
        ("tamperSignature", correct_id.as_str()),
        ("replayAuthenticate", correct_id.as_str()),
        ("textFrame", correct_id.as_str()),
        ("oversizeFrame", correct_id.as_str()),
        ("disconnect", correct_id.as_str()),
    ] {
        run_browser_case(case_name, &first_origin, server_id, &spki_pin).await;
        assert_eq!(
            frame_count(&storage_path),
            1,
            "{case_name} mutated business state"
        );
    }

    let stopped_origin = first_origin.clone();
    server.shutdown().await.expect("stop W1 TLS Relay");
    run_browser_case("unavailable", &stopped_origin, &correct_id, &spki_pin).await;
    assert_eq!(frame_count(&storage_path), 1);

    let restarted = RelayV2ServerHandle::start(config)
        .await
        .expect("restart W1 TLS Relay");
    let restarted_origin = format!("wss://localhost:{}/", restarted.public_addr().port());
    run_browser_case("positive", &restarted_origin, &correct_id, &spki_pin).await;
    assert_eq!(
        frame_count(&storage_path),
        1,
        "restart retry must stay idempotent"
    );
    restarted
        .shutdown()
        .await
        .expect("shutdown restarted W1 Relay");

    assert_persisted_sentinel_is_sealed(&storage_path);
    assert_temp_root_has_no_plaintext(temp.path());
    assert!(!web_root().join("test-results").exists());
}
