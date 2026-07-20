//! P3.8-A 真实本机 UDS 样本。
//!
//! 测试自己持有 Tokio listener；production pathname bind/cleanup/permit 不在本阶段暴露。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agentdeck_protocol::runtime::command::HelloParams;
use agentdeck_protocol::runtime::failure::{
    DAEMON_RUNTIME_INVALID_REQUEST, DAEMON_RUNTIME_PROTOCOL_MISMATCH,
};
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage,
    RuntimeReply, RuntimeRequest,
};
use agentdeckd::local::unix::serve_accepted_stream;
use agentdeckd::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
use agentdeckd::runtime::{AgentRouter, RuntimeCore};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::{UnixListener, UnixStream};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-local-uds-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create local UDS test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure local UDS test root");
        }
        Self { path }
    }

    fn socket(&self) -> PathBuf {
        self.path.join("agentdeckd.sock")
    }

    async fn core(&self) -> Arc<RuntimeCore> {
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &self.path.join("key-state.db"))
            .expect("local UDS StorageKEK");
        let store =
            RuntimeStoreHandle::open(RuntimeStoreConfig::new(self.path.join("runtime.db")), kek)
                .await
                .expect("open local UDS runtime store");
        let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
        let core = Arc::new(
            RuntimeCore::new(store, router, [0xA8; 32]).expect("construct local UDS RuntimeCore"),
        );
        core.recover().await.expect("recover local UDS RuntimeCore");
        core
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Client {
    reader: BufReader<ReadHalf<UnixStream>>,
    writer: WriteHalf<UnixStream>,
}

impl Client {
    async fn connect(path: &Path, installation_id: &str) -> Self {
        let stream = UnixStream::connect(path).await.expect("connect real UDS");
        let (reader, mut writer) = tokio::io::split(stream);
        let preface = serde_json::json!({
            "localProtocolVersion": 1,
            "clientInstallationId": installation_id,
        });
        write_line(
            &mut writer,
            &serde_json::to_vec(&preface).expect("encode preface"),
        )
        .await;
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    async fn write_envelope(&mut self, envelope: &RuntimeEnvelope) {
        let bytes = envelope
            .to_json_bytes_checked()
            .expect("encode Runtime test envelope");
        write_line(&mut self.writer, &bytes).await;
    }

    async fn write_raw(&mut self, bytes: &[u8]) {
        write_line(&mut self.writer, bytes).await;
    }

    async fn read_envelope(&mut self) -> RuntimeEnvelope {
        let mut line = Vec::new();
        let count = tokio::time::timeout(IO_TIMEOUT, self.reader.read_until(b'\n', &mut line))
            .await
            .expect("Runtime reply timeout")
            .expect("read Runtime reply");
        assert!(count > 0, "expected Runtime reply before EOF");
        assert_eq!(line.pop(), Some(b'\n'));
        serde_json::from_slice(&line).expect("decode Runtime reply")
    }

    async fn assert_eof_without_reply(&mut self) {
        let mut byte = [0_u8; 1];
        let outcome = tokio::time::timeout(IO_TIMEOUT, self.reader.read(&mut byte))
            .await
            .expect("connection did not close");
        match outcome {
            Ok(0) => {}
            Ok(count) => panic!("expected zero reply bytes, received {count}"),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                ) => {}
            Err(error) => panic!("unexpected close error: {error}"),
        }
    }
}

async fn write_line(writer: &mut WriteHalf<UnixStream>, bytes: &[u8]) {
    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_all(bytes).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    })
    .await
    .expect("UDS write timeout")
    .expect("write UDS frame");
}

fn hello(message_id: &str, inner_version: u16) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message_id),
        body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
            runtime_protocol_version: inner_version,
        })),
    }
}

fn assert_hello_reply(envelope: RuntimeEnvelope, message_id: &str) {
    assert_eq!(envelope.message_id.as_str(), message_id);
    assert!(matches!(
        envelope.body,
        RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
}

fn assert_failure(envelope: RuntimeEnvelope, message_id: &str, expected_code: &str) {
    assert_eq!(envelope.version, RUNTIME_PROTOCOL_VERSION);
    assert_eq!(envelope.message_id.as_str(), message_id);
    let RuntimeMessage::Reply(RuntimeReply::Failure(failure)) = envelope.body else {
        panic!("expected typed Runtime failure");
    };
    assert_eq!(failure.code, expected_code);
}

fn serve_n(
    listener: UnixListener,
    core: Arc<RuntimeCore>,
    count: usize,
) -> tokio::task::JoinHandle<Vec<Result<(), String>>> {
    tokio::spawn(async move {
        let mut connections = Vec::with_capacity(count);
        for _ in 0..count {
            let (stream, _) = listener.accept().await.expect("accept real UDS client");
            let core = core.clone();
            connections.push(tokio::spawn(async move {
                serve_accepted_stream(stream, core)
                    .await
                    .map_err(|error| error.to_string())
            }));
        }
        let mut results = Vec::with_capacity(count);
        for connection in connections {
            results.push(
                connection
                    .await
                    .expect("local connection actor task must not panic"),
            );
        }
        results
    })
}

async fn finish_server(
    server: tokio::task::JoinHandle<Vec<Result<(), String>>>,
    core: &RuntimeCore,
) {
    let results = tokio::time::timeout(IO_TIMEOUT, server)
        .await
        .expect("local UDS server did not drain")
        .expect("local UDS accept task must not panic");
    assert!(
        results.iter().all(Result::is_ok),
        "connection actor failures: {results:?}"
    );
    core.shutdown()
        .await
        .expect("shutdown local UDS RuntimeCore");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_uds_two_connections_handshake_and_disconnect_isolation() {
    let root = TestRoot::new("two-connections");
    let core = root.core().await;
    let listener = UnixListener::bind(root.socket()).expect("bind test-owned UDS listener");
    let server = serve_n(listener, core.clone(), 2);

    let mut first = Client::connect(&root.socket(), "123e4567-e89b-12d3-a456-426614174001").await;
    let mut second = Client::connect(&root.socket(), "123e4567-e89b-12d3-a456-426614174002").await;

    first
        .write_envelope(&hello("hello-first", RUNTIME_PROTOCOL_VERSION))
        .await;
    second
        .write_envelope(&hello("hello-second", RUNTIME_PROTOCOL_VERSION))
        .await;
    assert_hello_reply(first.read_envelope().await, "hello-first");
    assert_hello_reply(second.read_envelope().await, "hello-second");

    drop(first);
    second
        .write_envelope(&hello(
            "hello-second-after-sibling-eof",
            RUNTIME_PROTOCOL_VERSION,
        ))
        .await;
    assert_hello_reply(
        second.read_envelope().await,
        "hello-second-after-sibling-eof",
    );
    drop(second);

    finish_server(server, &core).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outer_version_and_non_hello_flush_typed_failure_then_close() {
    let root = TestRoot::new("typed-close");
    let core = root.core().await;
    let listener = UnixListener::bind(root.socket()).expect("bind test-owned UDS listener");
    let server = serve_n(listener, core.clone(), 2);

    let mut wrong_version =
        Client::connect(&root.socket(), "123e4567-e89b-12d3-a456-426614174010").await;
    wrong_version
        .write_raw(br#"{"version":1,"messageId":"outer-mismatch","body":{"future":true}}"#)
        .await;
    assert_failure(
        wrong_version.read_envelope().await,
        "outer-mismatch",
        DAEMON_RUNTIME_PROTOCOL_MISMATCH,
    );
    wrong_version.assert_eof_without_reply().await;

    let mut non_hello =
        Client::connect(&root.socket(), "123e4567-e89b-12d3-a456-426614174011").await;
    let invalid_first = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("reply-is-not-hello-request"),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };
    non_hello.write_envelope(&invalid_first).await;
    assert_failure(
        non_hello.read_envelope().await,
        "reply-is-not-hello-request",
        DAEMON_RUNTIME_INVALID_REQUEST,
    );
    non_hello.assert_eof_without_reply().await;

    finish_server(server, &core).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inner_hello_mismatch_is_a_core_reply_and_connection_remains_usable() {
    let root = TestRoot::new("inner-mismatch");
    let core = root.core().await;
    let listener = UnixListener::bind(root.socket()).expect("bind test-owned UDS listener");
    let server = serve_n(listener, core.clone(), 1);
    let mut client = Client::connect(&root.socket(), "123e4567-e89b-12d3-a456-426614174020").await;

    client.write_envelope(&hello("inner-mismatch", 1)).await;
    assert_failure(
        client.read_envelope().await,
        "inner-mismatch",
        DAEMON_RUNTIME_PROTOCOL_MISMATCH,
    );
    client
        .write_envelope(&hello("inner-retry", RUNTIME_PROTOCOL_VERSION))
        .await;
    assert_hello_reply(client.read_envelope().await, "inner-retry");
    drop(client);

    finish_server(server, &core).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_duplicate_and_exact_cap_frames_close_without_reply() {
    let root = TestRoot::new("zero-reply-close");
    let core = root.core().await;
    let listener = UnixListener::bind(root.socket()).expect("bind test-owned UDS listener");
    let server = serve_n(listener, core.clone(), 3);

    let cases = [
        br#"{"version":2"#.to_vec(),
        br#"{"version":2,"version":2,"messageId":"duplicate","body":{}}"#.to_vec(),
        vec![b' '; MAX_RUNTIME_JSON_FRAME_BYTES],
    ];
    for (index, frame) in cases.into_iter().enumerate() {
        let installation_id = format!("123e4567-e89b-12d3-a456-4266141741{index:02}");
        let mut client = Client::connect(&root.socket(), &installation_id).await;
        // exact-cap case may observe BrokenPipe while the server fail-closes as soon as the cap
        // is reached; either way no response bytes are permitted.
        let _ = tokio::time::timeout(IO_TIMEOUT, async {
            let _ = client.writer.write_all(&frame).await;
            let _ = client.writer.write_all(b"\n").await;
            let _ = client.writer.flush().await;
        })
        .await;
        client.assert_eof_without_reply().await;
    }

    finish_server(server, &core).await;
}
