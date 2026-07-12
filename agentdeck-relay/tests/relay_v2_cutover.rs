#![cfg(all(feature = "server", feature = "tls"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use agentdeck_relay::config::{RelayV2ServerConfig, RelayV2StoreSettings, RelayV2TransportMode};
use agentdeck_relay::v2::server::RelayV2ServerHandle;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RESET_CODE: &str = "relay.v1.reset_required";
const VERSION_UNSUPPORTED_CODE: &str = "relay.version.unsupported";
const SENTINEL: &str = "v1-secret-must-never-be-reflected";
const IO_TIMEOUT: Duration = Duration::from_secs(3);

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn secure_temp_directory(temp: &TempDir) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure Relay temporary directory");
    }
}

fn loopback_config(temp: &TempDir) -> RelayV2ServerConfig {
    let mut store = RelayV2StoreSettings::new(temp.path().join("relay-v2.db"));
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    RelayV2ServerConfig {
        bind: "127.0.0.1:0".parse().expect("public loopback address"),
        health_bind: "127.0.0.1:0".parse().expect("health loopback address"),
        store,
        transport: RelayV2TransportMode::InsecureLoopback,
        admin: None,
        log_level: "info".to_owned(),
    }
}

fn relay_binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentdeck-relay"));
    // reset/cutover tests must not inherit a developer machine's Relay config,
    // credentials or logging settings.
    command.env_clear();
    command
}

fn assert_reset_only(output: &Output) {
    assert_eq!(output.status.code(), Some(2), "legacy input must exit 2");
    assert!(
        output.stdout.is_empty(),
        "legacy input must not write stdout"
    );
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("reset stderr is UTF-8"),
        format!("{RESET_CODE}\n")
    );
    assert!(
        !output
            .stdout
            .windows(SENTINEL.len())
            .any(|bytes| bytes == SENTINEL.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(SENTINEL.len())
            .any(|bytes| bytes == SENTINEL.as_bytes())
    );
}

#[tokio::test]
async fn legacy_v1_public_path_returns_stateless_closed_426_without_reflection() {
    let temp = TempDir::new().expect("tempdir");
    secure_temp_directory(&temp);
    let handle = RelayV2ServerHandle::start(loopback_config(&temp))
        .await
        .expect("start v2 public listener");
    let mut stream = tokio::net::TcpStream::connect(handle.public_addr())
        .await
        .expect("connect public listener");
    let request = format!(
        "GET /v1/connect?v=1 HTTP/1.1\r\nHost: relay.local\r\nAuthorization: Bearer {SENTINEL}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write legacy request");

    let mut response = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("legacy response must close promptly")
        .expect("read legacy response");
    handle.shutdown().await.expect("shutdown v2 Relay");

    assert!(
        !response
            .windows(SENTINEL.len())
            .any(|bytes| bytes == SENTINEL.as_bytes()),
        "Authorization value must never be reflected"
    );
    let rendered = std::str::from_utf8(&response).expect("HTTP response is UTF-8");
    let (head, body) = rendered
        .split_once("\r\n\r\n")
        .expect("complete HTTP response");
    assert!(
        head.starts_with("HTTP/1.1 426 "),
        "legacy tombstone must return 426: {head}"
    );
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("connection: close")),
        "legacy tombstone must disable keep-alive: {head}"
    );
    let payload: serde_json::Value = serde_json::from_str(body).expect("JSON rejection body");
    assert_eq!(
        payload,
        serde_json::json!({ "code": VERSION_UNSUPPORTED_CODE })
    );
}

#[test]
fn legacy_v1_cli_flag_fails_locally_without_echoing_the_secret() {
    let output = relay_binary()
        .args(["--bootstrap-secret", SENTINEL])
        .output()
        .expect("run Relay binary with legacy flag");
    assert_reset_only(&output);
}

#[cfg(unix)]
#[test]
fn legacy_v1_non_utf8_secret_is_rejected_without_decoding_or_panicking() {
    use std::os::unix::ffi::OsStringExt;

    let secret = std::ffi::OsString::from_vec(vec![0xff, 0xfe, 0xfd]);
    let output = relay_binary()
        .arg("--bootstrap-secret")
        .arg(secret)
        .output()
        .expect("run Relay binary with non-UTF-8 legacy secret");
    assert_reset_only(&output);
}

#[test]
fn legacy_v1_environment_fails_locally_without_echoing_the_secret() {
    let output = relay_binary()
        .env("AGENTDECK_RELAY_BOOTSTRAP_SECRET", SENTINEL)
        .output()
        .expect("run Relay binary with legacy environment");
    assert_reset_only(&output);
}

#[test]
fn legacy_v1_environment_preempts_admin_dispatch() {
    let output = relay_binary()
        .env("AGENTDECK_RELAY_BOOTSTRAP_SECRET", SENTINEL)
        .args(["machine", "inventory"])
        .output()
        .expect("run admin command with legacy environment");
    assert_reset_only(&output);
}

#[test]
fn v2_binary_selfcheck_accepts_a_temporary_direct_tls_configuration() {
    let temp = TempDir::new().expect("tempdir");
    secure_temp_directory(&temp);
    std::fs::copy(fixture("test_cert.pem"), temp.path().join("cert.pem"))
        .expect("copy TLS certificate fixture");
    std::fs::copy(fixture("test_key.pem"), temp.path().join("key.pem"))
        .expect("copy TLS key fixture");
    let storage = temp.path().join("relay-v2.db");
    let config = temp.path().join("relay-v2.toml");
    let storage = storage.to_str().expect("UTF-8 temporary storage path");
    std::fs::write(
        &config,
        format!(
            "bind = \"127.0.0.1:0\"\nhealth_bind = \"127.0.0.1:0\"\nstorage = {storage:?}\ntls_cert = \"cert.pem\"\ntls_key = \"key.pem\"\ndisk_reserve_bytes = 0\ndisk_reserve_percent = 0\n"
        ),
    )
    .expect("write temporary v2 TLS config");

    let output = relay_binary()
        .args(["--selfcheck", "--config"])
        .arg(&config)
        .output()
        .expect("run v2 TLS selfcheck");
    assert!(
        output.status.success(),
        "v2 TLS selfcheck failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        Path::new(storage).is_file(),
        "selfcheck must create the v2 Store"
    );
}
