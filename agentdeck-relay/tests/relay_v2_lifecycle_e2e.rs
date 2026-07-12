#![cfg(feature = "server")]

use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use agentdeck_protocol::relay_v2::frame::Hello;
use agentdeck_protocol::relay_v2::{
    OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, decode, encode,
};
use agentdeck_relay::config::{RelayV2ServerConfig, RelayV2StoreSettings, RelayV2TransportMode};
use agentdeck_relay::v2::server::{
    self, MAX_PUBLIC_CONNECTIONS, PUBLIC_UPGRADE_DEADLINE, RelayV2ServerError, RelayV2ServerHandle,
};
use agentdeck_relay::v2::store::RelayStoreHandle;
use futures_util::{SinkExt, StreamExt};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

#[cfg(unix)]
const SIGNAL_CHILD_ENV: &str = "AGENTDECK_RELAY_V2_SIGNAL_CHILD";
#[cfg(unix)]
const SIGNAL_STORAGE_ENV: &str = "AGENTDECK_RELAY_V2_SIGNAL_STORAGE";

fn signal_child_config(storage_path: PathBuf) -> RelayV2ServerConfig {
    let mut store = RelayV2StoreSettings::new(storage_path);
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    RelayV2ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        health_bind: "127.0.0.1:0".parse().unwrap(),
        store,
        transport: RelayV2TransportMode::InsecureLoopback,
        log_level: "info".to_owned(),
    }
}

fn proxy_config(storage_path: PathBuf) -> RelayV2ServerConfig {
    let mut config = signal_child_config(storage_path);
    config.transport = RelayV2TransportMode::ProxyLoopback;
    config
}

#[test]
#[cfg(unix)]
fn production_signal_adapter_drains_on_sigterm_and_releases_the_store() {
    if std::env::var_os(SIGNAL_CHILD_ENV).is_some() {
        let storage_path =
            PathBuf::from(std::env::var_os(SIGNAL_STORAGE_ENV).expect("signal child storage path"));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("signal child runtime");
        runtime
            .block_on(server::serve_until_signal(signal_child_config(
                storage_path,
            )))
            .expect("SIGTERM must use the normal Relay drain path");
        return;
    }

    let temp = TempDir::new().expect("tempdir");
    let storage_path = temp.path().join("signal").join("relay.db");
    let lock_path = storage_path.with_file_name("relay.db.agentdeck.lock");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("production_signal_adapter_drains_on_sigterm_and_releases_the_store")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(SIGNAL_CHILD_ENV, "1")
        .env(SIGNAL_STORAGE_ENV, &storage_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn signal child");

    let startup_deadline = Instant::now() + Duration::from_secs(10);
    while !lock_path.is_file() {
        if let Some(status) = child.try_wait().expect("poll signal child startup") {
            let output = child.wait_with_output().expect("read failed child output");
            panic!(
                "signal child exited before readiness ({status}): stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            Instant::now() < startup_deadline,
            "signal child did not acquire the Store process lock"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // 等待 child 的 Tokio select 同时 poll server 与 signal future，避免在 handler
    // 注册前送达 SIGTERM 形成测试自身的竞态。
    std::thread::sleep(Duration::from_millis(100));

    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM to Relay child");
    assert!(status.success(), "kill -TERM failed: {status}");

    let shutdown_deadline = Instant::now() + Duration::from_secs(10);
    let child_status = loop {
        if let Some(status) = child.try_wait().expect("poll signal child shutdown") {
            break status;
        }
        if Instant::now() >= shutdown_deadline {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .expect("read timed-out child output");
            panic!(
                "signal child exceeded shutdown deadline: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("read signal child output");
    assert!(
        child_status.success(),
        "signal child did not exit cleanly: {child_status}; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("reopen runtime");
    runtime.block_on(async {
        let reopened = RelayStoreHandle::open(
            signal_child_config(storage_path)
                .store
                .into_store_config()
                .expect("reopen Store config"),
        )
        .await
        .expect("SIGTERM drain must release the Store process lock");
        reopened.shutdown().await.expect("shutdown reopened Store");
    });
}

#[tokio::test]
async fn proxy_loopback_slow_http_cannot_extend_network_drain_past_five_seconds() {
    let temp = TempDir::new().expect("tempdir");
    let storage_path = temp.path().join("relay-private").join("relay.db");
    let mut store = RelayV2StoreSettings::new(storage_path.clone());
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    let handle = RelayV2ServerHandle::start(RelayV2ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        health_bind: "127.0.0.1:0".parse().unwrap(),
        store,
        transport: RelayV2TransportMode::ProxyLoopback,
        log_level: "info".to_owned(),
    })
    .await
    .expect("start proxy-loopback Relay");

    // 缺少 header terminator，Hyper 会把该 loopback HTTP connection 保持在 request parse。
    let mut slow = tokio::net::TcpStream::connect(handle.public_addr())
        .await
        .expect("connect slow HTTP peer");
    slow.write_all(b"GET /v2/connect HTTP/1.1\r\nHost: relay.local\r\n")
        .await
        .expect("write partial request");
    tokio::time::sleep(Duration::from_millis(25)).await;

    let started = tokio::time::Instant::now();
    handle.trigger_shutdown();
    let result = tokio::time::timeout(Duration::from_millis(5_750), handle.wait())
        .await
        .expect("network drain must have a hard upper bound");
    assert!(started.elapsed() <= Duration::from_millis(5_500));
    assert!(
        result.is_ok() || matches!(result, Err(RelayV2ServerError::DrainTimeout)),
        "forced listener reap may report only the typed drain timeout: {result:?}"
    );
    drop(slow);

    let mut reopened = RelayV2StoreSettings::new(storage_path);
    reopened.disk_reserve_bytes = 0;
    reopened.disk_reserve_percent = 0;
    let reopened = RelayStoreHandle::open(reopened.into_store_config().expect("reopen config"))
        .await
        .expect("handle wait must quiesce Core/Auth/Store and release DB lock");
    reopened.shutdown().await.expect("shutdown reopened Store");
}

#[tokio::test]
async fn partial_http_is_closed_by_the_runtime_upgrade_deadline_without_shutdown() {
    let temp = TempDir::new().expect("tempdir");
    let handle = RelayV2ServerHandle::start(proxy_config(
        temp.path().join("header-deadline").join("relay.db"),
    ))
    .await
    .expect("start header-deadline Relay");
    let mut slow = tokio::net::TcpStream::connect(handle.public_addr())
        .await
        .expect("connect partial HTTP peer");
    slow.write_all(b"GET /v2/connect HTTP/1.1\r\nHost: relay.local\r\n")
        .await
        .expect("write partial request");
    let mut byte = [0_u8; 1];
    let result = tokio::time::timeout(
        PUBLIC_UPGRADE_DEADLINE + Duration::from_secs(1),
        slow.read(&mut byte),
    )
    .await
    .expect("partial HTTP must be reaped by the running server");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "deadline must close the partial connection: {result:?}"
    );
    handle
        .shutdown()
        .await
        .expect("shutdown header-deadline Relay");
}

async fn read_http_response_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut response = Vec::with_capacity(256);
    let mut chunk = [0_u8; 512];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .expect("HTTP response head deadline")
            .expect("read HTTP response head");
        assert!(read > 0, "HTTP response closed before a complete head");
        response.extend_from_slice(&chunk[..read]);
        assert!(
            response.len() <= 16 * 1024,
            "unexpectedly large HTTP response head"
        );
    }
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_non_upgrade_requests_cannot_hold_all_public_connection_permits() {
    let temp = TempDir::new().expect("tempdir");
    let handle = RelayV2ServerHandle::start(signal_child_config(
        temp.path().join("non-upgrade-cap").join("relay.db"),
    ))
    .await
    .expect("start non-upgrade-cap Relay");
    let address = handle.public_addr();
    let mut rejected = Vec::with_capacity(MAX_PUBLIC_CONNECTIONS);

    // 填满真实 production 物理连接上界。每个请求都有完整 header，但不是 WebSocket upgrade；
    // server 必须在响应后主动 close，不能让 HTTP/1.1 keep-alive 长占 permit。
    for _ in 0..MAX_PUBLIC_CONNECTIONS {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect non-upgrade peer");
        stream
            .write_all(b"GET /does-not-exist HTTP/1.1\r\nHost: relay.local\r\n\r\n")
            .await
            .expect("write non-upgrade request");
        let response = read_http_response_head(&mut stream).await;
        assert!(response.starts_with(b"HTTP/1.1 404"));
        rejected.push((stream, response));
    }

    let url = format!("ws://{address}/v2/connect");
    let (mut socket, response) = tokio::time::timeout(Duration::from_secs(2), connect_async(url))
        .await
        .expect("non-upgrade responses must release permits for a valid WS")
        .expect("valid WS must still upgrade after a full non-upgrade wave");
    assert_eq!(response.status().as_u16(), 101);

    for (_, response) in &rejected {
        let response = String::from_utf8_lossy(response).to_ascii_lowercase();
        assert!(
            response.contains("\r\nconnection: close\r\n"),
            "every non-101 response must explicitly disable keep-alive"
        );
    }
    for index in [0, rejected.len() - 1] {
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), rejected[index].0.read(&mut byte))
            .await
            .expect("non-upgrade connection must close promptly")
            .expect("read non-upgrade EOF");
        assert_eq!(read, 0, "non-upgrade connection remained reusable");
    }

    socket.close(None).await.expect("close valid WS");
    handle
        .shutdown()
        .await
        .expect("shutdown non-upgrade-cap Relay");
}

#[tokio::test]
async fn proxy_mode_requires_one_canonical_source_header_on_the_real_ws_path() {
    let temp = TempDir::new().expect("tempdir");
    let handle = RelayV2ServerHandle::start(proxy_config(
        temp.path().join("proxy-source").join("relay.db"),
    ))
    .await
    .expect("start proxy-source Relay");
    let url = format!("ws://{}/v2/connect", handle.public_addr());

    for values in [
        vec![],
        vec!["203.0.113.10", "203.0.113.11"],
        vec!["203.0.113.10, 203.0.113.11"],
        vec!["not-an-ip"],
    ] {
        let mut request = url.clone().into_client_request().unwrap();
        for value in values {
            request.headers_mut().append(
                "x-agentdeck-client-ip",
                value.parse().expect("test header value"),
            );
        }
        let WsError::Http(response) = connect_async(request)
            .await
            .expect_err("invalid trusted-proxy source must not upgrade")
        else {
            panic!("proxy source rejection must be a direct HTTP response");
        };
        assert_eq!(response.status().as_u16(), 400);
        assert!(!response.status().is_redirection());
    }

    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-agentdeck-client-ip", "203.0.113.12".parse().unwrap());
    let (mut socket, _) = connect_async(request)
        .await
        .expect("trusted proxy overwrite header permits WS upgrade");
    let hello = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        }),
    };
    socket
        .send(Message::Binary(encode(&hello).into()))
        .await
        .expect("send proxy-mode Hello");
    let frame = socket
        .next()
        .await
        .expect("proxy-mode challenge")
        .expect("read proxy-mode challenge");
    let Message::Binary(bytes) = frame else {
        panic!("proxy-mode Hello must yield binary Challenge");
    };
    assert!(matches!(
        decode(&bytes).expect("decode Challenge").body,
        RelayFrameBody::Challenge(_)
    ));
    socket.close(None).await.expect("close proxy-mode WS");
    handle
        .shutdown()
        .await
        .expect("shutdown proxy-source Relay");
}
