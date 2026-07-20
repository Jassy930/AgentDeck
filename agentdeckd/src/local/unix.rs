//! 已 accept 的 same-UID Unix stream connection actor。
//!
//! 威胁场景：一个慢写或协议错误的本地客户端若能阻塞 RuntimeCore、在 Core 取消后
//! 继续写帧，或把自身断线扩散到 sibling connection，就会让本机恢复/审批控制面失联；
//! 因此每条连接拥有独立 reader/writer，且 socket flush 与 Core cancellation 必须竞争。
//!
//! P3.8-A 只接收调用方已经 accept 的 stream。本模块刻意不提供 pathname bind/listen
//! API；production secure bind、readback 与 permit 链属于 P3.8-B。

use std::io;
use std::sync::Arc;

use agentdeck_protocol::runtime::RuntimeEnvelope;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot, watch};

use crate::runtime::{ConnectionSink, ConnectionWrite, RuntimeCore};

use super::framing::{
    JsonlReadError, LocalClientPrefaceV1, LocalPrefaceError, MAX_LOCAL_PREFACE_LINE_BYTES,
    RuntimeFrameDecision, decode_first_runtime_frame, decode_runtime_frame, read_jsonl_frame,
};
use super::peer::{PeerUidError, PeerUidSource, after_same_effective_uid};

const TRANSPORT_WRITER_QUEUE_FRAMES: usize = 64;

/// 单连接 actor 的本地失败；所有 variant 都只关闭当前 socket，不代表 RuntimeCore
/// 或 listener 必须退出。
#[derive(Debug, thiserror::Error)]
pub enum LocalConnectionError {
    #[error("local peer credential lookup failed: {0}")]
    PeerCredential(#[source] io::Error),
    #[error("local peer uid {peer_uid} does not match daemon effective uid {effective_uid}")]
    PeerUidMismatch { effective_uid: u32, peer_uid: u32 },
    #[error("local client closed before sending its preface")]
    MissingPreface,
    #[error("invalid local client preface: {0}")]
    InvalidPreface(String),
    #[error("local Runtime frame read failed: {0}")]
    FrameRead(String),
    #[error("RuntimeCore rejected local connection: {0}")]
    Runtime(String),
    #[error("local socket write failed: {0}")]
    Write(#[source] io::Error),
    #[error("local writer task failed: {0}")]
    WriterTask(String),
    #[error("local writer task was cancelled")]
    WriterTaskCancelled,
    #[error("local Hello reply was not flushed")]
    HelloNotFlushed,
}

impl LocalConnectionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PeerCredential(_) => "daemon.local.peer_credential_failed",
            Self::PeerUidMismatch { .. } => "daemon.local.peer_uid_mismatch",
            Self::MissingPreface => "daemon.local.preface_missing",
            Self::InvalidPreface(_) => "daemon.local.preface_invalid",
            Self::FrameRead(_) => "daemon.local.frame_read_failed",
            Self::Runtime(_) => "daemon.local.runtime_rejected",
            Self::Write(_) => "daemon.local.write_failed",
            Self::WriterTask(_) => "daemon.local.writer_failed",
            Self::WriterTaskCancelled => "daemon.local.writer_cancelled",
            Self::HelloNotFlushed => "daemon.local.hello_not_flushed",
        }
    }
}

impl PeerUidSource for UnixStream {
    fn peer_uid(&self) -> io::Result<u32> {
        self.peer_cred().map(|credential| credential.uid())
    }
}

struct TerminalWrite {
    envelope: RuntimeEnvelope,
    completion: oneshot::Sender<Result<(), String>>,
}

enum ReaderOutcome {
    Reader(Result<(), LocalConnectionError>),
    Writer(Result<Result<(), LocalConnectionError>, tokio::task::JoinError>),
}

/// 服务一条已 accept 的本地 Unix stream，直到 client/Core 断开或该连接协议失败。
///
/// 调用顺序固定为 kernel peer credential → preface → Core principal/connect → Hello。
/// 本函数不 bind pathname，也不会在断线时停止共享 RuntimeCore。
pub async fn serve_accepted_stream(
    stream: UnixStream,
    core: Arc<RuntimeCore>,
) -> Result<(), LocalConnectionError> {
    let (_shutdown, receiver) = watch::channel(false);
    serve_accepted_stream_with_shutdown(stream, core, receiver).await
}

/// P3.8-B listener supervisor 使用的 graceful cancellation 入口。shutdown 会唤醒
/// stalled preface/read 与 backpressured writer；本 future 仍会 disconnect Core 并
/// join writer，调用方不得任意 abort connection task。
pub(crate) async fn serve_accepted_stream_with_shutdown(
    stream: UnixStream,
    core: Arc<RuntimeCore>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), LocalConnectionError> {
    // SAFETY: geteuid has no preconditions and only reads the current process credential.
    let effective_uid = unsafe { libc::geteuid() };
    after_same_effective_uid(stream, effective_uid, move |stream, verified| async move {
        serve_verified_stream(stream, core, verified, shutdown).await
    })
    .await
    .map_err(map_peer_error)?
}

async fn serve_verified_stream(
    stream: UnixStream,
    core: Arc<RuntimeCore>,
    verified: super::peer::VerifiedSameUidPeer,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), LocalConnectionError> {
    // peer credential 已验证后才取得 reader 并读取第一个 client byte。
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let raw_preface = tokio::select! {
        biased;
        () = wait_for_shutdown(&mut shutdown) => return Ok(()),
        frame = read_jsonl_frame(&mut reader, MAX_LOCAL_PREFACE_LINE_BYTES) => {
            frame
                .map_err(map_frame_read_error)?
                .ok_or(LocalConnectionError::MissingPreface)?
        }
    };
    let preface = LocalClientPrefaceV1::decode(&raw_preface).map_err(map_preface_error)?;

    let principal = core
        .issue_verified_local_control_principal(verified.uid(), preface.client_installation_id())
        .map_err(|error| LocalConnectionError::Runtime(error.to_string()))?;

    let (core_writes, core_write_receiver) = mpsc::channel(TRANSPORT_WRITER_QUEUE_FRAMES);
    let connection_id = core
        .connect(principal, ConnectionSink::new(core_writes))
        .map_err(map_runtime_failure)?;
    let (terminal_writes, terminal_write_receiver) = mpsc::channel(1);
    let (hello_flushed, hello_flushed_receiver) = oneshot::channel();
    let writer_shutdown = shutdown.clone();
    let mut writer_task = tokio::spawn(run_writer(
        writer,
        core_write_receiver,
        terminal_write_receiver,
        hello_flushed,
        writer_shutdown,
    ));
    let reader_outcome = run_reader(
        &mut reader,
        &core,
        connection_id,
        &terminal_writes,
        hello_flushed_receiver,
        &mut writer_task,
        &mut shutdown,
    )
    .await;

    // 只清理当前 connection/subscription/writer。RuntimeCore 和 sibling connections
    // 的生命周期由更外层 bootstrap 拥有。
    core.disconnect(connection_id).await;
    drop(terminal_writes);

    match reader_outcome {
        ReaderOutcome::Writer(result) => map_writer_join(result),
        ReaderOutcome::Reader(reader_result) => {
            let writer_result = map_writer_join(writer_task.await);
            match reader_result {
                Err(error) => Err(error),
                Ok(()) => writer_result,
            }
        }
    }
}

async fn run_reader(
    reader: &mut BufReader<OwnedReadHalf>,
    core: &RuntimeCore,
    connection_id: crate::runtime::ConnectionId,
    terminal_writes: &mpsc::Sender<TerminalWrite>,
    hello_flushed: oneshot::Receiver<()>,
    writer_task: &mut tokio::task::JoinHandle<Result<(), LocalConnectionError>>,
    shutdown: &mut watch::Receiver<bool>,
) -> ReaderOutcome {
    let first_frame = match read_runtime_frame(reader, writer_task, shutdown).await {
        Ok(Some(frame)) => frame,
        Ok(None) => return ReaderOutcome::Reader(Ok(())),
        Err(outcome) => return outcome,
    };
    match decode_first_runtime_frame(&first_frame) {
        RuntimeFrameDecision::Accept(envelope) => {
            if let Err(failure) = core.handle_envelope(connection_id, envelope).await {
                return ReaderOutcome::Reader(Err(map_runtime_failure(failure)));
            }
            let hello_flushed = tokio::select! {
                biased;
                () = wait_for_shutdown(shutdown) => return ReaderOutcome::Reader(Ok(())),
                result = hello_flushed => result,
            };
            if hello_flushed.is_err() {
                return ReaderOutcome::Reader(Err(LocalConnectionError::HelloNotFlushed));
            }
        }
        RuntimeFrameDecision::ReplyThenClose(envelope) => {
            return ReaderOutcome::Reader(
                write_terminal_and_close(terminal_writes, envelope, shutdown).await,
            );
        }
        RuntimeFrameDecision::Close => return ReaderOutcome::Reader(Ok(())),
    }

    loop {
        let frame = match read_runtime_frame(reader, writer_task, shutdown).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return ReaderOutcome::Reader(Ok(())),
            Err(outcome) => return outcome,
        };
        match decode_runtime_frame(&frame) {
            RuntimeFrameDecision::Accept(envelope) => {
                if let Err(failure) = core.handle_envelope(connection_id, envelope).await {
                    return ReaderOutcome::Reader(Err(map_runtime_failure(failure)));
                }
            }
            RuntimeFrameDecision::ReplyThenClose(envelope) => {
                return ReaderOutcome::Reader(
                    write_terminal_and_close(terminal_writes, envelope, shutdown).await,
                );
            }
            RuntimeFrameDecision::Close => return ReaderOutcome::Reader(Ok(())),
        }
    }
}

async fn read_runtime_frame(
    reader: &mut BufReader<OwnedReadHalf>,
    writer_task: &mut tokio::task::JoinHandle<Result<(), LocalConnectionError>>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<Vec<u8>>, ReaderOutcome> {
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => {
            Err(ReaderOutcome::Reader(Ok(())))
        }
        writer = writer_task => Err(ReaderOutcome::Writer(writer)),
        frame = read_jsonl_frame(
            reader,
            agentdeck_protocol::runtime::MAX_RUNTIME_JSON_FRAME_BYTES,
        ) => match frame {
            Ok(frame) => Ok(frame),
            Err(error) if is_client_frame_error(&error) => Ok(None),
            Err(error) => Err(ReaderOutcome::Reader(Err(map_frame_read_error(error)))),
        },
    }
}

async fn write_terminal_and_close(
    sender: &mpsc::Sender<TerminalWrite>,
    envelope: RuntimeEnvelope,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), LocalConnectionError> {
    let (completion, flushed) = oneshot::channel();
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => return Ok(()),
        result = sender.send(TerminalWrite { envelope, completion }) => {
            result.map_err(|_| LocalConnectionError::WriterTaskCancelled)?;
        }
    }
    let flushed = tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => return Ok(()),
        result = flushed => result,
    };
    match flushed {
        Ok(Ok(())) => Ok(()),
        Ok(Err(message)) => Err(LocalConnectionError::WriterTask(message)),
        Err(_) => Err(LocalConnectionError::WriterTaskCancelled),
    }
}

async fn run_writer(
    mut writer: OwnedWriteHalf,
    mut core_writes: mpsc::Receiver<ConnectionWrite>,
    mut terminal_writes: mpsc::Receiver<TerminalWrite>,
    hello_flushed: oneshot::Sender<()>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), LocalConnectionError> {
    let mut hello_flushed = Some(hello_flushed);
    loop {
        tokio::select! {
            biased;
            () = wait_for_shutdown(&mut shutdown) => return Ok(()),
            terminal = terminal_writes.recv() => {
                let Some(terminal) = terminal else {
                    return Ok(());
                };
                let result = tokio::select! {
                    biased;
                    () = wait_for_shutdown(&mut shutdown) => return Ok(()),
                    result = write_envelope(&mut writer, &terminal.envelope) => result,
                };
                let completion = result.as_ref().map(|_| ()).map_err(ToString::to_string);
                let _ = terminal.completion.send(completion);
                result?;
                return Ok(());
            }
            write = core_writes.recv() => {
                let Some(write) = write else {
                    return Ok(());
                };
                if !write_core_frame(&mut writer, write, &mut shutdown).await? {
                    return Ok(());
                }
                if let Some(flushed) = hello_flushed.take() {
                    let _ = flushed.send(());
                }
            }
        }
    }
}

async fn write_core_frame(
    writer: &mut OwnedWriteHalf,
    mut write: ConnectionWrite,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<bool, LocalConnectionError> {
    let bytes = write.shared_bytes();
    let socket_write = async {
        writer.write_all(&bytes).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    };
    tokio::pin!(socket_write);
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => Ok(false),
        () = write.cancelled() => Ok(false),
        result = &mut socket_write => {
            result.map_err(LocalConnectionError::Write)?;
            write.acknowledge().map_err(|error| {
                LocalConnectionError::WriterTask(error.to_string())
            })?;
            Ok(true)
        }
    }
}

async fn wait_for_shutdown(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn write_envelope(
    writer: &mut OwnedWriteHalf,
    envelope: &RuntimeEnvelope,
) -> Result<(), LocalConnectionError> {
    let bytes = envelope.to_json_bytes_checked().map_err(|error| {
        LocalConnectionError::WriterTask(format!("failed to encode terminal frame: {error}"))
    })?;
    writer
        .write_all(&bytes)
        .await
        .map_err(LocalConnectionError::Write)?;
    writer
        .write_all(b"\n")
        .await
        .map_err(LocalConnectionError::Write)?;
    writer.flush().await.map_err(LocalConnectionError::Write)
}

fn map_peer_error(error: PeerUidError) -> LocalConnectionError {
    match error {
        PeerUidError::Lookup(source) => LocalConnectionError::PeerCredential(source),
        PeerUidError::Mismatch {
            effective_uid,
            peer_uid,
        } => LocalConnectionError::PeerUidMismatch {
            effective_uid,
            peer_uid,
        },
    }
}

fn map_preface_error(error: LocalPrefaceError) -> LocalConnectionError {
    LocalConnectionError::InvalidPreface(error.to_string())
}

fn map_frame_read_error(error: JsonlReadError) -> LocalConnectionError {
    LocalConnectionError::FrameRead(error.to_string())
}

fn is_client_frame_error(error: &JsonlReadError) -> bool {
    matches!(
        error,
        JsonlReadError::TooLarge { .. } | JsonlReadError::Unterminated
    )
}

fn map_runtime_failure(
    failure: agentdeck_protocol::runtime::RuntimeFailure,
) -> LocalConnectionError {
    LocalConnectionError::Runtime(format!("[{}] {}", failure.code, failure.message))
}

fn map_writer_join(
    result: Result<Result<(), LocalConnectionError>, tokio::task::JoinError>,
) -> Result<(), LocalConnectionError> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Err(LocalConnectionError::WriterTaskCancelled),
        Err(error) => Err(LocalConnectionError::WriterTask(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use agentdeck_protocol::runtime::command::{HelloParams, MachineEnrollRequest};
    use agentdeck_protocol::runtime::identity::MessageId;
    use agentdeck_protocol::runtime::{
        LocalOnlyAdministration, MachineRemoteLifecycle, MachineRemoteStatus,
        RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeReply, RuntimeRequest,
        TrustResetRequest,
    };
    use async_trait::async_trait;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    use super::*;
    use crate::runtime::remote_administration::{RemoteAdministration, RemoteAdministrationError};
    use crate::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
    use crate::runtime::{AgentRouter, RuntimeCore};
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    #[derive(Default)]
    struct UdsRemoteAdministration {
        status_calls: AtomicUsize,
    }

    #[async_trait]
    impl RemoteAdministration for UdsRemoteAdministration {
        async fn enroll(
            &self,
            _request: MachineEnrollRequest,
        ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
            unreachable!("UDS status test never enrolls")
        }

        async fn status(&self) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            MachineRemoteStatus::new(
                MachineRemoteLifecycle::Unenrolled,
                None,
                None,
                None,
                None,
                None,
            )
            .map_err(|_| RemoteAdministrationError::new("daemon.remote.test.invalid_status"))
        }

        async fn trust_reset(
            &self,
            _request: TrustResetRequest,
        ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
            unreachable!("UDS status test never resets trust")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_same_uid_uds_dispatches_machine_status_through_neutral_service() {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        let root = Path::new("/tmp").join(format!(
            "agentdeck-remote-admin-uds-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create UDS test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("secure UDS test root");
        }
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
            .expect("create UDS test StorageKEK");
        let store = RuntimeStoreHandle::open(RuntimeStoreConfig::new(root.join("runtime.db")), kek)
            .await
            .expect("open UDS test Store");
        let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
        let administration = Arc::new(UdsRemoteAdministration::default());
        let core = Arc::new(
            RuntimeCore::new(store, router, [0xA9; 32])
                .expect("construct UDS test Core")
                .with_remote_administration(administration.clone()),
        );
        core.recover().await.expect("recover UDS test Core");

        let socket = root.join("runtime.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind real UDS");
        let server_core = core.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept real UDS");
            serve_accepted_stream(stream, server_core).await
        });
        let stream = UnixStream::connect(&socket)
            .await
            .expect("connect real UDS");
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let preface = serde_json::json!({
            "localProtocolVersion": 1,
            "clientInstallationId": "123e4567-e89b-12d3-a456-426614174099"
        });
        writer
            .write_all(&serde_json::to_vec(&preface).unwrap())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        let hello = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("remote-admin-hello"),
            body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            })),
        };
        writer
            .write_all(&hello.to_json_bytes_checked().unwrap())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).await.unwrap();
        let reply: RuntimeEnvelope = serde_json::from_slice(&line).expect("decode Hello reply");
        assert!(matches!(
            reply.body,
            RuntimeMessage::Reply(RuntimeReply::Hello(_))
        ));

        let status = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("remote-admin-status"),
            body: RuntimeMessage::Request(RuntimeRequest::MachineRemoteStatus {
                scope: LocalOnlyAdministration::LocalOnly,
            }),
        };
        writer
            .write_all(&status.to_json_bytes_checked().unwrap())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();
        line.clear();
        reader.read_until(b'\n', &mut line).await.unwrap();
        let reply: RuntimeEnvelope = serde_json::from_slice(&line).expect("decode status reply");
        assert!(matches!(
            reply.body,
            RuntimeMessage::Reply(RuntimeReply::MachineRemoteStatus(MachineRemoteStatus {
                lifecycle: MachineRemoteLifecycle::Unenrolled,
                ..
            }))
        ));
        assert_eq!(administration.status_calls.load(Ordering::SeqCst), 1);

        drop((writer, reader));
        server
            .await
            .expect("join real UDS actor")
            .expect("serve real UDS actor");
        core.shutdown().await.expect("shutdown UDS test Core");
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn core_cancellation_exits_writer_without_ack_or_hello_ready() {
        let (server, mut peer) = UnixStream::pair().expect("create Unix stream pair");
        let (_server_reader, server_writer) = server.into_split();
        let (core_sender, core_receiver) = mpsc::channel(1);
        let (terminal_sender, terminal_receiver) = mpsc::channel(1);
        let (hello_flushed, hello_flushed_receiver) = oneshot::channel();
        let (_shutdown_sender, shutdown) = watch::channel(false);
        let (write, acknowledgement) = ConnectionWrite::for_transport_test(&b"cancelled"[..]);
        core_sender
            .send(write)
            .await
            .expect("queue transport write");
        drop(acknowledgement);

        run_writer(
            server_writer,
            core_receiver,
            terminal_receiver,
            hello_flushed,
            shutdown,
        )
        .await
        .expect("Core cancellation cleanly exits local writer");

        assert!(
            hello_flushed_receiver.await.is_err(),
            "cancelled first write must not publish Hello readiness"
        );
        assert!(core_sender.is_closed(), "Core write receiver must close");
        assert!(
            terminal_sender.is_closed(),
            "terminal frames cannot be written after Core cancellation"
        );
        let mut byte = [0_u8; 1];
        let count = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
            .await
            .expect("cancelled writer must close its socket half")
            .expect("read cancelled writer EOF");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn core_cancellation_interrupts_an_inflight_backpressured_socket_write() {
        // 威胁场景：client 停止读取后 write_all 已进入内核 backpressure；若 transport
        // 只在写前检查取消，Core fail-close 会永久卡住该连接与 frame budget。
        use std::os::fd::AsRawFd;

        let (server, mut peer) = UnixStream::pair().expect("create Unix stream pair");
        let send_buffer: libc::c_int = 4096;
        // SAFETY: server owns a valid AF_UNIX fd; the pointer and length describe send_buffer.
        let set_result = unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&send_buffer as *const libc::c_int).cast(),
                std::mem::size_of_val(&send_buffer) as libc::socklen_t,
            )
        };
        assert_eq!(set_result, 0, "shrink Unix socket send buffer");

        let (_server_reader, server_writer) = server.into_split();
        let (core_sender, core_receiver) = mpsc::channel(1);
        let (_terminal_sender, terminal_receiver) = mpsc::channel(1);
        let (hello_flushed, hello_flushed_receiver) = oneshot::channel();
        let (_shutdown_sender, shutdown) = watch::channel(false);
        let (write, mut acknowledgement) =
            ConnectionWrite::for_transport_test(vec![b'x'; 512 * 1024]);
        core_sender
            .send(write)
            .await
            .expect("queue backpressured transport write");

        let writer = tokio::spawn(run_writer(
            server_writer,
            core_receiver,
            terminal_receiver,
            hello_flushed,
            shutdown,
        ));
        let mut first_byte = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut first_byte))
            .await
            .expect("writer must enter the socket write")
            .expect("read first backpressured byte");
        assert_eq!(first_byte, [b'x']);
        assert!(
            matches!(
                acknowledgement.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "partial socket write must not ACK before flush"
        );

        drop(acknowledgement);
        tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("Core cancellation must interrupt blocked write")
            .expect("join backpressured writer")
            .expect("cancelled write closes cleanly");
        assert!(
            hello_flushed_receiver.await.is_err(),
            "cancelled partial Hello write must not publish readiness"
        );
    }

    #[tokio::test]
    async fn supervisor_shutdown_interrupts_an_inflight_backpressured_socket_write() {
        // 威胁场景：daemon shutdown 时 client 卡住读取；listener supervisor 必须
        // graceful cancel 并 join writer，不能靠 abort accepted actor 留下 Core work。
        use std::os::fd::AsRawFd;

        let (server, mut peer) = UnixStream::pair().expect("create Unix stream pair");
        let send_buffer: libc::c_int = 4096;
        // SAFETY: server owns a valid AF_UNIX fd; pointer/length describe send_buffer.
        let set_result = unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&send_buffer as *const libc::c_int).cast(),
                std::mem::size_of_val(&send_buffer) as libc::socklen_t,
            )
        };
        assert_eq!(set_result, 0, "shrink Unix socket send buffer");

        let (_server_reader, server_writer) = server.into_split();
        let (core_sender, core_receiver) = mpsc::channel(1);
        let (_terminal_sender, terminal_receiver) = mpsc::channel(1);
        let (hello_flushed, hello_flushed_receiver) = oneshot::channel();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let (write, mut acknowledgement) =
            ConnectionWrite::for_transport_test(vec![b'x'; 512 * 1024]);
        core_sender.send(write).await.expect("queue blocked write");

        let writer = tokio::spawn(run_writer(
            server_writer,
            core_receiver,
            terminal_receiver,
            hello_flushed,
            shutdown,
        ));
        let mut first_byte = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut first_byte))
            .await
            .expect("writer must enter socket write")
            .expect("read first byte");
        assert!(matches!(
            acknowledgement.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        shutdown_sender
            .send(true)
            .expect("publish graceful shutdown");
        tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("shutdown must wake blocked writer")
            .expect("join writer")
            .expect("writer exits cleanly");
        assert!(acknowledgement.await.is_err(), "partial write must not ACK");
        assert!(hello_flushed_receiver.await.is_err());
    }
}
