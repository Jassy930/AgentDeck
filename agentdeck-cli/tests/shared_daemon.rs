#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use agentdeck_cli::installation::{CliInstallationStore, InstallationError};
use agentdeck_cli::unix_transport::{
    InjectedEndpoint, ReplySequenceItem, RuntimeStreamFrame, RuntimeUnixClient,
};
use agentdeck_crypto::sha256;
use agentdeck_protocol::runtime::command::{CatalogRequest, HelloParams};
use agentdeck_protocol::runtime::failure::{DAEMON_RUNTIME_PROTOCOL_MISMATCH, RuntimeFailure};
use agentdeck_protocol::runtime::identity::{
    CommandId, ConversationId, EntityId, EventId, ItemId, MessageId, StreamGeneration, TransferId,
};
use agentdeck_protocol::runtime::{
    BackfillRequest, CatalogDelta, CatalogSnapshot, MAX_RUNTIME_JSON_FRAME_BYTES,
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeEvent, RuntimeEventBody, RuntimeInnerCursor,
    RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeStreamItem, RuntimeSyncComplete,
    StreamCursor, SubscriptionReceipt, TransferEnvelope,
};
use agentdeck_protocol::{AgentItem, AgentItemMeta};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn private_home() -> TempDir {
    let root = tempfile::tempdir().expect("create test home");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("secure test home");
    root
}

fn store(home: &Path) -> CliInstallationStore {
    CliInstallationStore::injected_for_test(home.to_path_buf())
}

#[test]
fn installation_record_is_stable_private_and_uses_the_os_account_home() {
    let home = private_home();
    let store = store(home.path());
    let first = store.load_or_create().expect("create installation record");
    let second = store.load_or_create().expect("read installation record");
    assert_eq!(first, second);
    assert_eq!(first.to_string().len(), 36);

    let path = store.record_path();
    let metadata = fs::symlink_metadata(&path).expect("stat installation record");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    let parent = fs::symlink_metadata(path.parent().expect("record parent")).unwrap();
    assert_eq!(parent.mode() & 0o777, 0o700);

    let system_path = CliInstallationStore::record_path_for_os_account().unwrap();
    assert!(system_path.is_absolute());
    let source = include_str!("../src/installation.rs");
    for forbidden in ["var_os(\"HOME\")", "var(\"HOME\")", "home_dir()"] {
        assert!(
            !source.contains(forbidden),
            "production installation store must not trust environment home lookup: {forbidden}"
        );
    }
}

#[test]
fn installation_record_symlink_hardlink_mode_and_corruption_fail_without_rotation() {
    let cases = [
        "symlink", "hardlink", "mode", "setuid", "setgid", "sticky", "corrupt",
    ];
    for case in cases {
        let home = private_home();
        let store = store(home.path());
        let original = store.load_or_create().expect("seed record");
        let path = store.record_path();
        match case {
            "symlink" => {
                let target = path.with_file_name("target");
                fs::write(&target, format!("{original}\n")).unwrap();
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(&target, &path).unwrap();
            }
            "hardlink" => {
                fs::hard_link(&path, path.with_file_name("second-link")).unwrap();
            }
            "mode" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "setuid" => fs::set_permissions(&path, fs::Permissions::from_mode(0o4600)).unwrap(),
            "setgid" => fs::set_permissions(&path, fs::Permissions::from_mode(0o2600)).unwrap(),
            "sticky" => fs::set_permissions(&path, fs::Permissions::from_mode(0o1600)).unwrap(),
            "corrupt" => fs::write(&path, b"not-a-canonical-installation-id\n").unwrap(),
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&path).unwrap();
        let result = store.load_or_create();
        assert!(result.is_err(), "{case} must fail closed");
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        if case == "corrupt" {
            assert_eq!(
                fs::read(&path).unwrap(),
                b"not-a-canonical-installation-id\n"
            );
            assert!(matches!(
                result,
                Err(InstallationError::CorruptRecord { .. })
            ));
        }
    }
}

#[test]
fn installation_parent_mode_tamper_fails_without_touching_the_record() {
    for mode in [0o1700, 0o2700, 0o4700] {
        let home = private_home();
        let store = store(home.path());
        store.load_or_create().expect("seed record");
        let path = store.record_path();
        let before_bytes = fs::read(&path).unwrap();
        let before = fs::symlink_metadata(&path).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(mode)).unwrap();

        let error = store.load_or_create().unwrap_err();
        assert!(matches!(error, InstallationError::UnsafeDirectory { .. }));
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(fs::read(&path).unwrap(), before_bytes);
    }
}

#[test]
fn concurrent_first_creation_has_one_winner_and_all_callers_read_it() {
    let home = private_home();
    let store = Arc::new(store(home.path()));
    let workers = 24;
    let barrier = Arc::new(Barrier::new(workers));
    let mut threads = Vec::new();
    for _ in 0..workers {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store.load_or_create().expect("concurrent load/create")
        }));
    }
    let ids = threads
        .into_iter()
        .map(|thread| thread.join().expect("worker did not panic"))
        .collect::<Vec<_>>();
    assert!(ids.iter().all(|id| id == &ids[0]));
    let entries = fs::read_dir(store.record_path().parent().unwrap())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1, "race temp files must be cleaned up");
}

struct TestServer {
    path: PathBuf,
    listener: UnixListener,
}

impl TestServer {
    fn bind(root: &Path) -> Self {
        let path = root.join("agentdeckd.sock");
        let listener = UnixListener::bind(&path).expect("bind test UDS");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Self { path, listener }
    }

    fn endpoint(&self) -> InjectedEndpoint {
        InjectedEndpoint::for_test(self.path.clone())
    }
}

async fn read_line(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> Vec<u8> {
    let mut line = Vec::new();
    let count = tokio::time::timeout(IO_TIMEOUT, reader.read_until(b'\n', &mut line))
        .await
        .expect("read timeout")
        .expect("read line");
    assert!(count > 0, "unexpected EOF");
    assert_eq!(line.pop(), Some(b'\n'));
    line
}

async fn write_envelope(writer: &mut tokio::net::unix::OwnedWriteHalf, envelope: &RuntimeEnvelope) {
    let bytes = envelope.to_json_bytes_checked().expect("encode envelope");
    writer.write_all(&bytes).await.unwrap();
    writer.write_all(b"\n").await.unwrap();
    writer.flush().await.unwrap();
}

fn reply(message_id: MessageId, body: RuntimeReply) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id,
        body: RuntimeMessage::Reply(body),
    }
}

fn transfer_parts(
    message_id: &MessageId,
    transfer_id: &str,
    payload: &[u8],
) -> Vec<RuntimeEnvelope> {
    let split = payload.len().div_ceil(2);
    let chunks = payload.chunks(split).collect::<Vec<_>>();
    chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            reply(
                message_id.clone(),
                RuntimeReply::TransferPart(
                    TransferEnvelope::new_json(
                        TransferId::new(transfer_id),
                        index as u32,
                        chunks.len() as u32,
                        sha256(payload),
                        payload.len() as u64,
                        chunk.to_vec(),
                    )
                    .unwrap(),
                ),
            )
        })
        .collect()
}

fn sync_complete() -> RuntimeReply {
    RuntimeReply::SyncComplete(RuntimeSyncComplete {
        stream_generation: StreamGeneration::new("test-generation"),
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: 0,
    })
}

async fn wait_fault(client: &RuntimeUnixClient, expected: &str) {
    tokio::time::timeout(IO_TIMEOUT, async {
        loop {
            if let Some(fault) = client.fault() {
                assert_eq!(fault.code, expected, "fault: {fault:?}");
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client fault timeout");
}

#[test]
fn reply_sequence_debug_redacts_reply_and_transfer_bodies() {
    let reply = ReplySequenceItem::Reply(Box::new(RuntimeReply::Failure(RuntimeFailure::new(
        "test.secret",
        "sensitive reply body",
    ))));
    let transfer = ReplySequenceItem::TransferComplete(b"sensitive transfer body".to_vec());
    let reply_debug = format!("{reply:?}");
    let transfer_debug = format!("{transfer:?}");
    assert!(!reply_debug.contains("sensitive"));
    assert!(!transfer_debug.contains("sensitive"));
    assert!(reply_debug.contains("<redacted>"));
    assert!(transfer_debug.contains("bytes: 23"));
}

#[test]
fn runtime_stream_frame_debug_redacts_user_and_transfer_payloads() {
    let user = RuntimeStreamFrame {
        message_id: MessageId::new("sensitive-message-id"),
        item: RuntimeStreamItem::Event(
            RuntimeEvent::new(
                ConversationId::new("conversation"),
                EventId::new("event"),
                0,
                Some(CommandId::new("command")),
                Some(ItemId::new("item")),
                Some(EntityId::new("entity")),
                RuntimeEventBody::Item {
                    item: AgentItem::UserMessage {
                        text: "sensitive user sentinel".into(),
                        meta: AgentItemMeta::default(),
                    },
                },
            )
            .unwrap(),
        ),
    };
    let transfer_bytes = b"sensitive transfer sentinel".to_vec();
    let transfer = RuntimeStreamFrame {
        message_id: MessageId::new("sensitive-transfer-id"),
        item: RuntimeStreamItem::TransferPart(
            TransferEnvelope::new_json(
                TransferId::new("transfer"),
                0,
                1,
                sha256(&transfer_bytes),
                transfer_bytes.len() as u64,
                transfer_bytes,
            )
            .unwrap(),
        ),
    };
    for debug in [format!("{user:?}"), format!("{transfer:?}")] {
        assert!(!debug.contains("sensitive"));
        assert!(debug.contains("<redacted>"));
    }
}

async fn accept_and_handshake(
    listener: &UnixListener,
) -> (
    BufReader<tokio::net::unix::OwnedReadHalf>,
    tokio::net::unix::OwnedWriteHalf,
) {
    let (stream, _) = listener.accept().await.expect("accept test client");
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let preface: serde_json::Value = serde_json::from_slice(&read_line(&mut read).await).unwrap();
    assert_eq!(preface["localProtocolVersion"], 1);
    let installation = preface["clientInstallationId"].as_str().unwrap();
    assert_eq!(
        uuid::Uuid::parse_str(installation).unwrap().to_string(),
        installation
    );
    assert_ne!(installation, uuid::Uuid::nil().to_string());

    let hello: RuntimeEnvelope = serde_json::from_slice(&read_line(&mut read).await).unwrap();
    assert!(uuid::Uuid::parse_str(hello.message_id.as_str()).is_ok());
    assert!(matches!(
        hello.body,
        RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
    write_envelope(
        &mut write,
        &RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: hello.message_id,
            body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            })),
        },
    )
    .await;
    (read, write)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_failure_preserves_the_daemon_protocol_mismatch_code() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (stream, _) = server.listener.accept().await.expect("accept test client");
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);
        let _: serde_json::Value =
            serde_json::from_slice(&read_line(&mut read).await).expect("decode preface");
        let hello: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut read).await).expect("decode Hello");
        write_envelope(
            &mut write,
            &reply(
                hello.message_id,
                RuntimeReply::Failure(RuntimeFailure::new(
                    DAEMON_RUNTIME_PROTOCOL_MISMATCH,
                    "unsupported Runtime protocol version",
                )),
            ),
        )
        .await;
    });

    let error = RuntimeUnixClient::connect_injected(endpoint)
        .await
        .expect_err("Hello protocol mismatch must reject the connection");
    assert_eq!(error.code(), DAEMON_RUNTIME_PROTOCOL_MISMATCH);
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_eof_is_a_typed_stream_failure_not_a_clean_end() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (_reader, writer) = accept_and_handshake(&server.listener).await;
        drop(writer);
    });

    let mut client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let error = client
        .next_stream()
        .await
        .expect_err("daemon EOF must not look like a normal stream terminator");
    assert_eq!(error.code(), "daemon.client.connection_closed");
    drop(client);
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_uds_sends_preface_hello_and_correlates_out_of_order_replies() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let first: RuntimeEnvelope = serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let second: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        for request in [second, first] {
            let code = match &request.body {
                RuntimeMessage::Request(RuntimeRequest::DescribeAgents) => "test.describe",
                RuntimeMessage::Request(RuntimeRequest::Catalog(_)) => "test.catalog",
                _ => panic!("unexpected request in correlation test"),
            };
            let message = format!("reply-for:{}", request.message_id.as_str());
            write_envelope(
                &mut writer,
                &RuntimeEnvelope {
                    version: RUNTIME_PROTOCOL_VERSION,
                    message_id: request.message_id,
                    body: RuntimeMessage::Reply(RuntimeReply::Failure(RuntimeFailure::new(
                        code, message,
                    ))),
                },
            )
            .await;
        }
    });

    let client = RuntimeUnixClient::connect_injected(endpoint)
        .await
        .expect("connect injected client");
    let (describe, catalog) = tokio::join!(
        client.request(RuntimeRequest::DescribeAgents),
        client.request(RuntimeRequest::Catalog(CatalogRequest {
            page_cursor: None
        }))
    );
    let ReplySequenceItem::Reply(describe) = describe.unwrap() else {
        panic!("expected correlated describe reply")
    };
    let RuntimeReply::Failure(describe) = *describe else {
        panic!("expected correlated describe failure")
    };
    let ReplySequenceItem::Reply(catalog) = catalog.unwrap() else {
        panic!("expected correlated catalog reply")
    };
    let RuntimeReply::Failure(catalog) = *catalog else {
        panic!("expected correlated catalog failure")
    };
    assert_eq!(describe.code, "test.describe");
    assert_eq!(catalog.code, "test.catalog");
    assert!(describe.message.starts_with("reply-for:"));
    assert!(catalog.message.starts_with("reply-for:"));
    client.close().await.expect("close only the client fd");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_keeps_same_message_id_sequence_until_sync_complete() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let id = request.message_id;
        let replies = [
            RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                stream_generation: StreamGeneration::new("subscribe-generation"),
            }),
            RuntimeReply::Catalog(
                CatalogSnapshot::new(StreamCursor::BeforeFirst, Vec::new(), None).unwrap(),
            ),
            sync_complete(),
        ];
        for body in replies {
            write_envelope(&mut writer, &reply(id.clone(), body)).await;
        }
        let mut tail = Vec::new();
        let _ = reader.read_to_end(&mut tail).await;
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let mut sequence = client
        .begin_request(RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .unwrap();
    assert!(matches!(
        sequence.next().await.unwrap(),
        Some(ReplySequenceItem::Reply(reply))
            if matches!(reply.as_ref(), RuntimeReply::Subscription(_))
    ));
    assert!(matches!(
        sequence.next().await.unwrap(),
        Some(ReplySequenceItem::Reply(reply))
            if matches!(reply.as_ref(), RuntimeReply::Catalog(_))
    ));
    assert!(matches!(
        sequence.next().await.unwrap(),
        Some(ReplySequenceItem::Reply(reply))
            if matches!(reply.as_ref(), RuntimeReply::SyncComplete(_))
    ));
    assert!(sequence.next().await.unwrap().is_none());
    drop(sequence);
    client.close().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_close_before_sequence_terminal_is_typed_failure_not_clean_end() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, _writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        assert!(matches!(
            request.body,
            RuntimeMessage::Request(RuntimeRequest::Subscribe { .. })
        ));
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).await.unwrap();
        assert!(
            tail.is_empty(),
            "close-only must not synthesize a terminal frame"
        );
    });

    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let mut sequence = client
        .begin_request(RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .unwrap();
    client.close().await.unwrap();

    let error = sequence
        .next()
        .await
        .expect_err("sequence without SyncComplete/Failure must not end cleanly");
    assert_eq!(error.code(), "daemon.client.connection_closed");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_sent_sequence_drains_late_transfer_and_terminal_without_harming_sibling() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let (sent, sent_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let cancelled: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let sibling: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let parts = transfer_parts(
            &cancelled.message_id,
            "cancelled-sequence-transfer",
            b"validated but discarded payload",
        );
        write_envelope(&mut writer, &parts[0]).await;
        write_envelope(
            &mut writer,
            &reply(
                sibling.message_id,
                RuntimeReply::Failure(RuntimeFailure::new("test.sibling", "sibling reply")),
            ),
        )
        .await;
        write_envelope(&mut writer, &parts[1]).await;
        write_envelope(&mut writer, &reply(cancelled.message_id, sync_complete())).await;
        let _ = sent.send(());
        let mut tail = Vec::new();
        let _ = reader.read_to_end(&mut tail).await;
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let cancelled = client
        .begin_request(RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .unwrap();
    drop(cancelled);
    assert!(matches!(
        client.request(RuntimeRequest::DescribeAgents).await.unwrap(),
        ReplySequenceItem::Reply(reply)
            if matches!(reply.as_ref(), RuntimeReply::Failure(failure) if failure.code == "test.sibling")
    ));
    sent_rx.await.unwrap();
    tokio::task::yield_now().await;
    assert!(client.fault().is_none());
    client.close().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backfill_reassembles_same_id_transfer_before_sync_terminal() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let payload = b"canonical backfill payload split across parts".to_vec();
    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        for part in transfer_parts(&request.message_id, "backfill-transfer", &payload) {
            write_envelope(&mut writer, &part).await;
        }
        write_envelope(&mut writer, &reply(request.message_id, sync_complete())).await;
        let mut tail = Vec::new();
        let _ = reader.read_to_end(&mut tail).await;
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let mut sequence = client
        .begin_request(RuntimeRequest::Backfill(BackfillRequest::Catalog {
            after: StreamCursor::BeforeFirst,
        }))
        .await
        .unwrap();
    let Some(ReplySequenceItem::TransferComplete(bytes)) = sequence.next().await.unwrap() else {
        panic!("backfill transfer must complete before terminal")
    };
    assert_eq!(bytes, expected);
    assert!(matches!(
        sequence.next().await.unwrap(),
        Some(ReplySequenceItem::Reply(reply))
            if matches!(reply.as_ref(), RuntimeReply::SyncComplete(_))
    ));
    assert!(sequence.next().await.unwrap().is_none());
    drop(sequence);
    client.close().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_transfer_id_reuse_by_another_message_fail_closes() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let payload = b"completed transfer remains bound to request".to_vec();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let first: RuntimeEnvelope = serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        for part in transfer_parts(&first.message_id, "bound-transfer", &payload) {
            write_envelope(&mut writer, &part).await;
        }
        write_envelope(&mut writer, &reply(first.message_id, sync_complete())).await;

        let second: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let reused = transfer_parts(&second.message_id, "bound-transfer", &payload).remove(0);
        write_envelope(&mut writer, &reused).await;
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let mut first = client
        .begin_request(RuntimeRequest::Backfill(BackfillRequest::Catalog {
            after: StreamCursor::BeforeFirst,
        }))
        .await
        .unwrap();
    assert!(matches!(
        first.next().await.unwrap(),
        Some(ReplySequenceItem::TransferComplete(_))
    ));
    assert!(matches!(
        first.next().await.unwrap(),
        Some(ReplySequenceItem::Reply(reply))
            if matches!(reply.as_ref(), RuntimeReply::SyncComplete(_))
    ));
    drop(first);
    let mut second = client
        .begin_request(RuntimeRequest::Backfill(BackfillRequest::Catalog {
            after: StreamCursor::BeforeFirst,
        }))
        .await
        .unwrap();
    let error = second.next().await.unwrap_err();
    assert_eq!(error.code(), "daemon.client.transfer_binding_mismatch");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unary_transfer_ignores_exact_duplicate_part_and_returns_complete_bytes() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let payload = b"two-part unary catalog payload".to_vec();
    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let parts = transfer_parts(&request.message_id, "unary-transfer", &payload);
        write_envelope(&mut writer, &parts[0]).await;
        write_envelope(&mut writer, &parts[0]).await;
        write_envelope(&mut writer, &parts[1]).await;
        let mut tail = Vec::new();
        let _ = reader.read_to_end(&mut tail).await;
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let ReplySequenceItem::TransferComplete(bytes) = client
        .request(RuntimeRequest::Catalog(CatalogRequest {
            page_cursor: None,
        }))
        .await
        .unwrap()
    else {
        panic!("unary transfer must return complete bytes")
    };
    assert_eq!(bytes, expected);
    client.close().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_duplicate_transfer_part_fail_closes() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let parts = transfer_parts(
            &request.message_id,
            "conflicting-transfer",
            b"conflict payload",
        );
        let mut conflict = parts[0].clone();
        let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = &mut conflict.body else {
            unreachable!()
        };
        part.part[0] ^= 1;
        write_envelope(&mut writer, &parts[0]).await;
        write_envelope(&mut writer, &conflict).await;
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let error = client
        .request(RuntimeRequest::Catalog(CatalogRequest {
            page_cursor: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "daemon.client.transfer_invalid");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_transfer_hash_mismatch_fail_closes() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let mut parts = transfer_parts(&request.message_id, "bad-hash-transfer", b"hash payload");
        for envelope in &mut parts {
            let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = &mut envelope.body else {
                unreachable!()
            };
            part.total_sha256[0] ^= 1;
        }
        for part in parts {
            write_envelope(&mut writer, &part).await;
        }
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let error = client
        .request(RuntimeRequest::Catalog(CatalogRequest {
            page_cursor: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "daemon.client.transfer_invalid");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfer_part_count_above_json_limit_is_rejected() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        let part = transfer_parts(&request.message_id, "oversize-transfer", b"oversize").remove(0);
        let mut raw = serde_json::to_value(part).unwrap();
        raw.pointer_mut("/body/payload/partCount")
            .unwrap()
            .clone_from(&serde_json::json!(95));
        writer
            .write_all(&serde_json::to_vec(&raw).unwrap())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let error = client
        .request(RuntimeRequest::Catalog(CatalogRequest {
            page_cursor: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "daemon.client.frame_invalid");
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_unary_reply_after_terminal_fail_closes() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        for message in ["first", "second"] {
            write_envelope(
                &mut writer,
                &reply(
                    request.message_id.clone(),
                    RuntimeReply::Failure(RuntimeFailure::new("test.unary", message)),
                ),
            )
            .await;
        }
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    assert!(matches!(
        client
            .request(RuntimeRequest::DescribeAgents)
            .await
            .unwrap(),
        ReplySequenceItem::Reply(reply) if matches!(reply.as_ref(), RuntimeReply::Failure(_))
    ));
    wait_fault(&client, "daemon.client.reply_uncorrelated").await;
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_request_reply_sequence_backpressure_fail_closes() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let request: RuntimeEnvelope =
            serde_json::from_slice(&read_line(&mut reader).await).unwrap();
        for index in 0..=RuntimeUnixClient::REPLY_SEQUENCE_CAPACITY {
            let body = RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                stream_generation: StreamGeneration::new(format!("generation-{index}")),
            });
            if write_envelope_result(&mut writer, &reply(request.message_id.clone(), body))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let _sequence = client
        .begin_request(RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .unwrap();
    wait_fault(&client, "daemon.client.reply_sequence_backpressure").await;
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_wide_reply_frame_budget_fail_closes() {
    const REQUESTS: usize = 17;
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (mut reader, mut writer) = accept_and_handshake(&server.listener).await;
        let mut ids = Vec::new();
        for _ in 0..REQUESTS {
            let request: RuntimeEnvelope =
                serde_json::from_slice(&read_line(&mut reader).await).unwrap();
            ids.push(request.message_id);
        }
        for id in ids {
            for index in 0..RuntimeUnixClient::REPLY_SEQUENCE_CAPACITY {
                let body = RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                    stream_generation: StreamGeneration::new(format!("global-{index}")),
                });
                if write_envelope_result(&mut writer, &reply(id.clone(), body))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    });
    let client = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    let mut sequences = Vec::new();
    for _ in 0..REQUESTS {
        sequences.push(
            client
                .begin_request(RuntimeRequest::Subscribe {
                    inner_cursor: RuntimeInnerCursor::Catalog {
                        cursor: StreamCursor::BeforeFirst,
                    },
                })
                .await
                .unwrap(),
        );
    }
    wait_fault(&client, "daemon.client.reply_sequence_backpressure").await;
    drop(sequences);
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_pump_is_bounded_and_overflow_fail_closes_the_connection() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (_reader, mut writer) = accept_and_handshake(&server.listener).await;
        for index in 0..=RuntimeUnixClient::STREAM_CAPACITY {
            let frame = RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id: MessageId::new(format!("stream-{index}")),
                body: RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(CatalogDelta {
                    catalog_revision: index as u64 + 1,
                    changes: Vec::new(),
                })),
            };
            if write_envelope_result(&mut writer, &frame).await.is_err() {
                break;
            }
        }
    });

    let client = RuntimeUnixClient::connect_injected(endpoint)
        .await
        .expect("connect injected client");
    tokio::time::timeout(IO_TIMEOUT, async {
        loop {
            if let Some(fault) = client.fault() {
                assert_eq!(fault.code, "daemon.client.stream_backpressure");
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded stream overflow must close promptly");
    drop(client);
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_one_mib_jsonl_frame_is_rejected_without_unbounded_buffering() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let (_reader, mut writer) = accept_and_handshake(&server.listener).await;
        let frame = vec![b' '; MAX_RUNTIME_JSON_FRAME_BYTES];
        let _ = writer.write_all(&frame).await;
        let _ = writer.write_all(b"\n").await;
        let _ = writer.flush().await;
    });

    let client = RuntimeUnixClient::connect_injected(endpoint)
        .await
        .expect("connect injected client");
    tokio::time::timeout(IO_TIMEOUT, async {
        loop {
            if let Some(fault) = client.fault() {
                assert_eq!(fault.code, "daemon.client.frame_too_large");
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exact cap must fail close promptly");
    drop(client);
    server_task.await.unwrap();
}

async fn write_envelope_result(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    envelope: &RuntimeEnvelope,
) -> std::io::Result<()> {
    let bytes = envelope.to_json_bytes_checked().unwrap();
    writer.write_all(&bytes).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

#[tokio::test]
async fn missing_canonical_socket_is_typed_and_transport_source_cannot_spawn() {
    let home = private_home();
    let store = store(home.path());
    let error = RuntimeUnixClient::connect_stable_with_store_for_test(&store)
        .await
        .expect_err("missing canonical socket must fail");
    assert_eq!(error.code(), "daemon.client.socket_missing");

    let source = include_str!("../src/unix_transport.rs");
    for forbidden in [
        "Command::new",
        "std::process",
        "tokio::process",
        "agentdeckd",
    ] {
        assert!(
            !source.contains(forbidden),
            "shared-daemon transport must not contain spawn/fallback token {forbidden}"
        );
    }
}

#[tokio::test]
async fn injected_socket_rejects_unsafe_parent_symlink_and_regular_file_before_connect() {
    for mode in [0o755, 0o1700, 0o2700, 0o4700] {
        let root = private_home();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(mode)).unwrap();
        let error = RuntimeUnixClient::connect_injected(InjectedEndpoint::for_test(
            root.path().join("agentdeckd.sock"),
        ))
        .await
        .expect_err("unsafe socket parent must fail before connect");
        assert_eq!(error.code(), "daemon.client.socket_unsafe", "mode {mode:o}");
    }

    let root = private_home();
    let real_parent = root.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let server = TestServer::bind(&real_parent);
    let linked_parent = root.path().join("linked-parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
    let error = RuntimeUnixClient::connect_injected(InjectedEndpoint::for_test(
        linked_parent.join("agentdeckd.sock"),
    ))
    .await
    .expect_err("symlinked socket parent must fail before connect");
    assert_eq!(error.code(), "daemon.client.socket_unsafe");
    drop(server);

    for entry in ["symlink", "regular"] {
        let root = private_home();
        let path = root.path().join("agentdeckd.sock");
        match entry {
            "symlink" => {
                let target = root.path().join("socket-target");
                fs::write(&target, b"not a socket").unwrap();
                std::os::unix::fs::symlink(&target, &path).unwrap();
            }
            "regular" => fs::write(&path, b"not a socket").unwrap(),
            _ => unreachable!(),
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = RuntimeUnixClient::connect_injected(InjectedEndpoint::for_test(path))
            .await
            .expect_err("non-socket entry must fail before connect");
        assert_eq!(error.code(), "daemon.client.socket_unsafe", "{entry}");
    }
}

#[tokio::test]
async fn injected_socket_rejects_non_private_and_special_mode_bits_before_connect() {
    for mode in [0o644, 0o1600, 0o2600, 0o4600] {
        let root = private_home();
        let server = TestServer::bind(root.path());
        fs::set_permissions(&server.path, fs::Permissions::from_mode(mode)).unwrap();
        let error = RuntimeUnixClient::connect_injected(server.endpoint())
            .await
            .expect_err("unsafe socket mode must fail before connect");
        assert_eq!(error.code(), "daemon.client.socket_unsafe", "mode {mode:o}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_only_does_not_send_daemon_shutdown_or_prevent_a_second_client() {
    let root = private_home();
    let server = TestServer::bind(root.path());
    let endpoint = server.endpoint();
    let endpoint2 = endpoint.clone();
    let server_task = tokio::spawn(async move {
        let (mut first_reader, _first_writer) = accept_and_handshake(&server.listener).await;
        let mut byte = Vec::new();
        let count = tokio::time::timeout(IO_TIMEOUT, first_reader.read_until(b'\n', &mut byte))
            .await
            .expect("first client close timeout")
            .expect("read first close");
        assert_eq!(count, 0, "close-only must not send a shutdown request");

        let (_second_reader, _second_writer) = accept_and_handshake(&server.listener).await;
    });

    let first = RuntimeUnixClient::connect_injected(endpoint).await.unwrap();
    first.close().await.unwrap();
    let second = RuntimeUnixClient::connect_injected(endpoint2)
        .await
        .unwrap();
    second.close().await.unwrap();
    server_task.await.unwrap();
}
