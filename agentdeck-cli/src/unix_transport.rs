//! RuntimeEnvelope v2 over canonical local Unix domain socket。
//!
//! 生产 default 只从 [`CliInstallationStore`] 派生 stable `DaemonPaths.socket`；本模块
//! 不含任何 daemon 查找、spawn 或 fallback。关闭 client 只关闭自身 fd，不发送
//! daemon shutdown。

#![cfg(unix)]

use std::collections::{HashMap, HashSet, VecDeque, hash_map::Entry};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_protocol::runtime::command::HelloParams;
use agentdeck_protocol::runtime::identity::{MessageId, TransferId};
use agentdeck_protocol::runtime::{
    MAX_COMPLETED_TRANSFER_TOMBSTONES, MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION,
    RuntimeEnvelope, RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeStreamItem,
    RuntimeTransferChannel, TRANSFER_TTL_MS, TransferEnvelope, TransferProgress,
    TransferReassembler,
};
use serde::Serialize;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc, watch};

use crate::installation::{CliInstallationStore, InstallationError, InstallationId};

const LOCAL_PROTOCOL_VERSION: u16 = 1;
const PREFACE_MAX_BYTES: usize = 4096;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const SEQUENCE_QUEUE_CAPACITY: usize = 8;
const QUEUED_REPLY_FRAMES: usize = 128;
const QUEUED_REPLY_BYTES: usize = 128 * 1024 * 1024;
const ACTIVE_TRANSFER_PART_FRAMES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientFault {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UnixClientError {
    #[error("installation identity unavailable: {0}")]
    Installation(#[from] InstallationError),
    #[error("canonical daemon socket is missing: {path}")]
    SocketMissing { path: PathBuf },
    #[error("unsafe daemon socket {path}: {reason}")]
    SocketUnsafe { path: PathBuf, reason: &'static str },
    #[error("connect daemon socket {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("local client preface failed: {0}")]
    Preface(String),
    #[error("runtime envelope encoding failed: {0}")]
    Encode(String),
    #[error("runtime reply pump is full")]
    ReplyCapacity,
    #[error("runtime reply timed out")]
    ReplyTimeout,
    #[error("runtime protocol failure [{code}]: {message}")]
    Protocol { code: String, message: String },
    #[error("runtime connection failed: {0:?}")]
    Connection(ClientFault),
    #[error("close local runtime connection failed: {0}")]
    Close(#[source] std::io::Error),
}

impl UnixClientError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Installation(error) => error.code(),
            Self::SocketMissing { .. } => "daemon.client.socket_missing",
            Self::SocketUnsafe { .. } => "daemon.client.socket_unsafe",
            Self::Connect { .. } => "daemon.client.connect_failed",
            Self::Preface(_) => "daemon.client.preface_failed",
            Self::Encode(_) => "daemon.client.encode_failed",
            Self::ReplyCapacity => "daemon.client.reply_backpressure",
            Self::ReplyTimeout => "daemon.client.reply_timeout",
            Self::Protocol { code, .. } => code,
            Self::Connection(fault) => fault.code,
            Self::Close(_) => "daemon.client.close_failed",
        }
    }
}

/// 仅 dev/test harness 能显式构造的 endpoint 注入。CLI 参数/环境不提供该入口。
#[derive(Clone, Debug)]
pub struct InjectedEndpoint {
    path: PathBuf,
}

impl InjectedEndpoint {
    #[doc(hidden)]
    pub fn for_test(path: PathBuf) -> Self {
        Self { path }
    }
}

pub struct RuntimeStreamFrame {
    pub message_id: MessageId,
    pub item: RuntimeStreamItem,
}

impl std::fmt::Debug for RuntimeStreamFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeStreamFrame")
            .field("message_id", &"<redacted>")
            .field("item", &"<redacted>")
            .finish()
    }
}

pub enum ReplySequenceItem {
    Reply(Box<RuntimeReply>),
    TransferComplete(Vec<u8>),
}

impl std::fmt::Debug for ReplySequenceItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reply(_) => formatter.write_str("ReplySequenceItem::Reply(<redacted>)"),
            Self::TransferComplete(bytes) => formatter
                .debug_struct("ReplySequenceItem::TransferComplete")
                .field("bytes", &bytes.len())
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReplyMode {
    Unary,
    Sync,
}

impl ReplyMode {
    fn for_request(request: &RuntimeRequest) -> Self {
        match request {
            RuntimeRequest::Subscribe { .. } | RuntimeRequest::Backfill(_) => Self::Sync,
            _ => Self::Unary,
        }
    }
}

struct QueuedReply {
    item: ReplySequenceItem,
    _frame: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
}

struct PendingReply {
    mode: ReplyMode,
    sender: Option<mpsc::Sender<QueuedReply>>,
    draining_since_ms: Option<u64>,
}

type PendingReplies = Arc<Mutex<HashMap<String, PendingReply>>>;

#[cfg(test)]
type DropBeforeDrainingHook = Box<dyn FnOnce(&PendingReplies) + Send>;

struct SharedConnection {
    writer: AsyncMutex<Option<OwnedWriteHalf>>,
    pending: PendingReplies,
    queued_frames: Arc<Semaphore>,
    queued_bytes: Arc<Semaphore>,
    fault: Mutex<Option<ClientFault>>,
    close: watch::Sender<bool>,
}

/// 一个 request 的有界 reply sequence。Drop 会取消该 messageId 的本地等待，不影响 daemon。
pub struct RuntimeReplySequence {
    message_id: MessageId,
    receiver: mpsc::Receiver<QueuedReply>,
    _registration: PendingRegistration,
    shared: Arc<SharedConnection>,
    mode: ReplyMode,
    deadline: tokio::time::Instant,
    terminal_seen: bool,
    #[cfg(test)]
    drop_before_draining: Option<DropBeforeDrainingHook>,
}

impl RuntimeReplySequence {
    #[must_use]
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }

    pub async fn next(&mut self) -> Result<Option<ReplySequenceItem>, UnixClientError> {
        if self.terminal_seen {
            return Ok(None);
        }
        match tokio::time::timeout_at(self.deadline, self.receiver.recv()).await {
            Ok(Some(queued)) => {
                self.terminal_seen = self.mode == ReplyMode::Unary
                    || matches!(
                            &queued.item,
                            ReplySequenceItem::Reply(reply)
                                if matches!(reply.as_ref(), RuntimeReply::SyncComplete(_) | RuntimeReply::Failure(_))
                    );
                Ok(Some(queued.item))
            }
            Ok(None) => Err(UnixClientError::Connection(self.shared.fault().unwrap_or(
                ClientFault {
                    code: "daemon.client.connection_closed",
                    message: "local Runtime connection closed before terminal reply".to_owned(),
                },
            ))),
            Err(_) => {
                set_fault(
                    &self.shared,
                    ClientFault {
                        code: "daemon.client.reply_timeout",
                        message: "correlated Runtime reply sequence timed out".to_owned(),
                    },
                );
                Err(UnixClientError::ReplyTimeout)
            }
        }
    }
}

impl Drop for RuntimeReplySequence {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(hook) = self.drop_before_draining.take() {
            hook(&self._registration.pending);
        }
        self._registration.mark_draining();
    }
}

impl SharedConnection {
    fn fault(&self) -> Option<ClientFault> {
        self.fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// 可并发发起 request 的 shared-daemon client。reply 按 exact messageId 相关，stream
/// 进入独立有界 pump。
pub struct RuntimeUnixClient {
    shared: Arc<SharedConnection>,
    streams: mpsc::Receiver<RuntimeStreamFrame>,
    reader_task: Option<tokio::task::JoinHandle<()>>,
    installation_id: InstallationId,
    socket_path: PathBuf,
}

impl std::fmt::Debug for RuntimeUnixClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeUnixClient")
            .field("socket_path", &self.socket_path)
            .field("installation_id", &self.installation_id)
            .field("fault", &self.fault())
            .finish_non_exhaustive()
    }
}

impl RuntimeUnixClient {
    pub const REPLY_CAPACITY: usize = 128;
    pub const REPLY_SEQUENCE_CAPACITY: usize = SEQUENCE_QUEUE_CAPACITY;
    pub const STREAM_CAPACITY: usize = 64;

    /// 生产 default：OS account home 下的 CLI installation record + canonical stable socket。
    pub async fn connect_stable() -> Result<Self, UnixClientError> {
        let store = CliInstallationStore::for_os_account()?;
        Self::connect_stable_store(&store).await
    }

    /// 测试 stable 路径派生和 socket-missing 语义；endpoint 仍不能任意改写。
    #[doc(hidden)]
    pub async fn connect_stable_with_store_for_test(
        store: &CliInstallationStore,
    ) -> Result<Self, UnixClientError> {
        Self::connect_stable_store(store).await
    }

    async fn connect_stable_store(store: &CliInstallationStore) -> Result<Self, UnixClientError> {
        let installation_id = store.load_or_create()?;
        Self::connect_path(store.daemon_socket_path(), installation_id).await
    }

    /// 显式 test endpoint；默认不从环境或 CLI flag 取 path。
    #[doc(hidden)]
    pub async fn connect_injected(endpoint: InjectedEndpoint) -> Result<Self, UnixClientError> {
        Self::connect_path(endpoint.path, InstallationId::random_for_test()).await
    }

    /// P3.9-D 跨进程 smoke 可显式注入已持久化的 installation identity。
    #[doc(hidden)]
    pub async fn connect_injected_with_installation(
        endpoint: InjectedEndpoint,
        installation_id: InstallationId,
    ) -> Result<Self, UnixClientError> {
        Self::connect_path(endpoint.path, installation_id).await
    }

    async fn connect_path(
        socket_path: PathBuf,
        installation_id: InstallationId,
    ) -> Result<Self, UnixClientError> {
        validate_socket(&socket_path)?;
        let stream = UnixStream::connect(&socket_path)
            .await
            .map_err(|source| map_connect_error(&socket_path, source))?;
        let (reader, mut writer) = stream.into_split();
        write_preface(&mut writer, installation_id).await?;

        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (streams_tx, streams) = mpsc::channel(Self::STREAM_CAPACITY);
        let (close, close_rx) = watch::channel(false);
        let shared = Arc::new(SharedConnection {
            writer: AsyncMutex::new(Some(writer)),
            pending: Arc::clone(&pending),
            queued_frames: Arc::new(Semaphore::new(QUEUED_REPLY_FRAMES)),
            queued_bytes: Arc::new(Semaphore::new(QUEUED_REPLY_BYTES)),
            fault: Mutex::new(None),
            close,
        });
        let hello_message_id = MessageId::new(uuid::Uuid::new_v4().hyphenated().to_string());
        let pump_shared = Arc::clone(&shared);
        let expected_first_reply = hello_message_id.as_str().to_owned();
        let reader_task = tokio::spawn(async move {
            run_reader(
                reader,
                pump_shared,
                streams_tx,
                close_rx,
                expected_first_reply,
            )
            .await;
        });
        let mut client = Self {
            shared,
            streams,
            reader_task: Some(reader_task),
            installation_id,
            socket_path,
        };
        let hello = tokio::time::timeout(
            HELLO_TIMEOUT,
            client.request_with_message_id(
                RuntimeRequest::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                }),
                hello_message_id,
                HELLO_TIMEOUT,
            ),
        )
        .await
        .map_err(|_| UnixClientError::ReplyTimeout)??;
        match hello {
            ReplySequenceItem::Reply(reply) => match *reply {
                RuntimeReply::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                }) => Ok(client),
                RuntimeReply::Failure(failure) => {
                    let error = UnixClientError::Protocol {
                        code: failure.code,
                        message: failure.message,
                    };
                    let _ = client.close_inner().await;
                    Err(error)
                }
                _ => {
                    let _ = client.close_inner().await;
                    Err(UnixClientError::Protocol {
                        code: "daemon.client.hello_invalid".to_owned(),
                        message: "first correlated reply is not Hello".to_owned(),
                    })
                }
            },
            _ => {
                let error = UnixClientError::Protocol {
                    code: "daemon.client.hello_invalid".to_owned(),
                    message: "first correlated reply is not Hello".to_owned(),
                };
                let _ = client.close_inner().await;
                Err(error)
            }
        }
    }

    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn fault(&self) -> Option<ClientFault> {
        self.shared.fault()
    }

    /// 只用于唯一 reply 或完整 transfer 的 unary 请求。Subscribe/Backfill 必须用
    /// [`Self::begin_request`] 逐项消费到 SyncComplete/Failure。
    pub async fn request(
        &self,
        request: RuntimeRequest,
    ) -> Result<ReplySequenceItem, UnixClientError> {
        self.request_with_timeout(request, REPLY_TIMEOUT).await
    }

    async fn request_with_timeout(
        &self,
        request: RuntimeRequest,
        timeout: Duration,
    ) -> Result<ReplySequenceItem, UnixClientError> {
        self.request_with_message_id(
            request,
            MessageId::new(uuid::Uuid::new_v4().hyphenated().to_string()),
            timeout,
        )
        .await
    }

    async fn request_with_message_id(
        &self,
        request: RuntimeRequest,
        message_id: MessageId,
        timeout: Duration,
    ) -> Result<ReplySequenceItem, UnixClientError> {
        if ReplyMode::for_request(&request) != ReplyMode::Unary {
            return Err(UnixClientError::Protocol {
                code: "daemon.client.sequence_required".to_owned(),
                message: "Subscribe/Backfill must use the reply-sequence API".to_owned(),
            });
        }
        let mut sequence = self
            .begin_with_message_id(request, message_id, timeout)
            .await?;
        match sequence.next().await {
            Ok(Some(item)) => Ok(item),
            Ok(None) => Err(UnixClientError::Connection(self.fault().unwrap_or(
                ClientFault {
                    code: "daemon.client.connection_closed",
                    message: "local Runtime connection closed before reply".to_owned(),
                },
            ))),
            Err(error) => Err(error),
        }
    }

    /// 发起有界 reply sequence；调用方必须持续 `next()`，直到 terminal 后返回 `None`。
    pub async fn begin_request(
        &self,
        request: RuntimeRequest,
    ) -> Result<RuntimeReplySequence, UnixClientError> {
        self.begin_with_message_id(
            request,
            MessageId::new(uuid::Uuid::new_v4().hyphenated().to_string()),
            REPLY_TIMEOUT,
        )
        .await
    }

    async fn begin_with_message_id(
        &self,
        request: RuntimeRequest,
        message_id: MessageId,
        timeout: Duration,
    ) -> Result<RuntimeReplySequence, UnixClientError> {
        if let Some(fault) = self.fault() {
            return Err(UnixClientError::Connection(fault));
        }
        let mode = ReplyMode::for_request(&request);
        let deadline = tokio::time::Instant::now() + timeout;
        let (sender, receiver) = mpsc::channel(SEQUENCE_QUEUE_CAPACITY);
        let mut registration = PendingRegistration::insert(
            Arc::clone(&self.shared.pending),
            message_id.as_str(),
            PendingReply {
                mode,
                sender: Some(sender),
                draining_since_ms: None,
            },
            Self::REPLY_CAPACITY,
        )?;
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: message_id.clone(),
            body: RuntimeMessage::Request(request),
        };
        let bytes = envelope
            .to_json_bytes_checked()
            .map_err(|error| UnixClientError::Encode(error.to_string()))?;
        let write_result = tokio::time::timeout(WRITE_TIMEOUT, async {
            write_frame_locked(&self.shared.writer, &self.shared, &bytes).await?;
            registration.mark_sent();
            Ok::<(), UnixClientError>(())
        })
        .await;
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                let fault = ClientFault {
                    code: "daemon.client.write_timeout",
                    message: "local Runtime write timed out".to_owned(),
                };
                set_fault(&self.shared, fault.clone());
                return Err(UnixClientError::Connection(
                    self.shared.fault().unwrap_or(fault),
                ));
            }
        }

        Ok(RuntimeReplySequence {
            message_id,
            receiver,
            _registration: registration,
            shared: Arc::clone(&self.shared),
            mode,
            deadline,
            terminal_seen: false,
            #[cfg(test)]
            drop_before_draining: None,
        })
    }

    pub async fn next_stream(&mut self) -> Result<RuntimeStreamFrame, UnixClientError> {
        self.streams.recv().await.ok_or_else(|| {
            UnixClientError::Connection(self.fault().unwrap_or(ClientFault {
                code: "daemon.client.connection_closed",
                message: "local Runtime connection closed before the next stream frame".to_owned(),
            }))
        })
    }

    /// 只关闭当前 client fd/pumps；不会向 daemon 发 shutdown request。
    pub async fn close(mut self) -> Result<(), UnixClientError> {
        self.close_inner().await
    }

    async fn close_inner(&mut self) -> Result<(), UnixClientError> {
        let _ = self.shared.close.send(true);
        let mut writer = self.shared.writer.lock().await;
        if let Some(mut writer) = writer.take()
            && let Err(error) = writer.shutdown().await
            && !matches!(
                error.kind(),
                std::io::ErrorKind::NotConnected | std::io::ErrorKind::BrokenPipe
            )
        {
            return Err(UnixClientError::Close(error));
        }
        drop(writer);
        if let Some(task) = self.reader_task.take() {
            let _ = task.await;
        }
        self.shared
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        Ok(())
    }
}

impl Drop for RuntimeUnixClient {
    fn drop(&mut self) {
        let _ = self.shared.close.send(true);
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
        if let Ok(mut writer) = self.shared.writer.try_lock() {
            writer.take();
        }
        self.shared
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

struct PendingRegistration {
    pending: PendingReplies,
    message_id: String,
    sent: bool,
    draining: bool,
}

impl PendingRegistration {
    fn insert(
        pending: PendingReplies,
        message_id: &str,
        reply: PendingReply,
        capacity: usize,
    ) -> Result<Self, UnixClientError> {
        let mut entries = pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.len() >= capacity {
            return Err(UnixClientError::ReplyCapacity);
        }
        match entries.entry(message_id.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(reply);
            }
            Entry::Occupied(_) => {
                return Err(UnixClientError::Protocol {
                    code: "daemon.client.message_id_duplicate".to_owned(),
                    message: "generated Runtime messageId was duplicated".to_owned(),
                });
            }
        }
        drop(entries);
        Ok(Self {
            pending,
            message_id: message_id.to_owned(),
            sent: false,
            draining: false,
        })
    }

    fn mark_sent(&mut self) {
        self.sent = true;
    }

    fn mark_draining(&mut self) {
        if !self.sent || self.draining {
            return;
        }
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(reply) = pending.get_mut(&self.message_id) {
            reply.sender = None;
            reply.draining_since_ms.get_or_insert_with(epoch_ms);
        }
        self.draining = true;
    }
}

impl Drop for PendingRegistration {
    fn drop(&mut self) {
        if self.sent {
            self.mark_draining();
        } else {
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.message_id);
        }
    }
}

enum WriteHandoffState {
    Writing,
    Failed,
    Complete,
}

struct WriteHandoffGuard {
    shared: Arc<SharedConnection>,
    state: WriteHandoffState,
}

impl WriteHandoffGuard {
    fn new(shared: Arc<SharedConnection>) -> Self {
        Self {
            shared,
            state: WriteHandoffState::Writing,
        }
    }

    fn fail(&mut self, fault: ClientFault) {
        if matches!(self.state, WriteHandoffState::Writing) {
            set_fault(&self.shared, fault);
            self.state = WriteHandoffState::Failed;
        }
    }
}

impl Drop for WriteHandoffGuard {
    fn drop(&mut self) {
        if matches!(self.state, WriteHandoffState::Writing) {
            set_fault(
                &self.shared,
                fault(
                    "daemon.client.write_handoff_incomplete",
                    "request write was cancelled before frame, LF and flush completed",
                ),
            );
        }
    }
}

async fn write_request_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    handoff: &mut WriteHandoffGuard,
) -> std::io::Result<()> {
    writer.write_all(bytes).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    handoff.state = WriteHandoffState::Complete;
    Ok(())
}

async fn write_frame_locked<W>(
    writer: &AsyncMutex<Option<W>>,
    shared: &Arc<SharedConnection>,
    bytes: &[u8],
) -> Result<(), UnixClientError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = writer.lock().await;
    if let Some(fault) = shared.fault() {
        return Err(UnixClientError::Connection(fault));
    }
    let Some(writer) = writer.as_mut() else {
        let fault = fault(
            "daemon.client.connection_closed",
            "local Runtime writer is already closed",
        );
        set_fault(shared, fault.clone());
        return Err(UnixClientError::Connection(fault));
    };
    // Declared after the writer mutex guard so cancellation drops this poison guard and records
    // the fault before the mutex can admit another writer.
    let mut handoff = WriteHandoffGuard::new(Arc::clone(shared));
    if let Err(error) = write_request_frame(writer, bytes, &mut handoff).await {
        let fault = fault("daemon.client.write_failed", &error.to_string());
        handoff.fail(fault.clone());
        return Err(UnixClientError::Connection(fault));
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalClientPreface {
    local_protocol_version: u16,
    client_installation_id: String,
}

async fn write_preface(
    writer: &mut OwnedWriteHalf,
    installation_id: InstallationId,
) -> Result<(), UnixClientError> {
    let bytes = serde_json::to_vec(&LocalClientPreface {
        local_protocol_version: LOCAL_PROTOCOL_VERSION,
        client_installation_id: installation_id.to_string(),
    })
    .map_err(|error| UnixClientError::Preface(error.to_string()))?;
    if bytes.len() >= PREFACE_MAX_BYTES {
        return Err(UnixClientError::Preface(
            "local preface reached the exclusive 4 KiB cap".to_owned(),
        ));
    }
    tokio::time::timeout(WRITE_TIMEOUT, async {
        writer.write_all(&bytes).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    })
    .await
    .map_err(|_| UnixClientError::Preface("local preface write timed out".to_owned()))?
    .map_err(|error| UnixClientError::Preface(error.to_string()))
}

struct TransferBinding {
    message_id: String,
    parts: HashSet<u32>,
    started_at_ms: u64,
}

struct CompletedBinding {
    message_id: String,
    completed_at_ms: u64,
}

struct ReplyPumpState {
    reassembler: TransferReassembler,
    bindings: HashMap<TransferId, TransferBinding>,
    active_parts: usize,
    completed: HashMap<TransferId, CompletedBinding>,
    completed_order: VecDeque<(u64, TransferId)>,
}

impl ReplyPumpState {
    fn new() -> Self {
        Self {
            reassembler: TransferReassembler::new(),
            bindings: HashMap::new(),
            active_parts: 0,
            completed: HashMap::new(),
            completed_order: VecDeque::new(),
        }
    }

    fn dispatch(
        &mut self,
        shared: &SharedConnection,
        message_id: MessageId,
        reply: RuntimeReply,
        frame_bytes: usize,
    ) -> Result<(), ClientFault> {
        self.dispatch_with_before_enqueue(shared, message_id, reply, frame_bytes, || {})
    }

    fn dispatch_with_before_enqueue<F>(
        &mut self,
        shared: &SharedConnection,
        message_id: MessageId,
        reply: RuntimeReply,
        frame_bytes: usize,
        before_enqueue: F,
    ) -> Result<(), ClientFault>
    where
        F: FnOnce(),
    {
        let mode = shared
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(message_id.as_str())
            .map(|pending| pending.mode)
            .ok_or_else(|| {
                fault(
                    "daemon.client.reply_uncorrelated",
                    "reply has no pending request",
                )
            })?;
        let (item, terminal, charge) = match reply {
            RuntimeReply::TransferPart(part) => {
                let Some(bytes) = self.accept_transfer(message_id.as_str(), part)? else {
                    return Ok(());
                };
                let charge = bytes.len();
                (
                    ReplySequenceItem::TransferComplete(bytes),
                    mode == ReplyMode::Unary,
                    charge,
                )
            }
            reply => {
                if self.has_active(message_id.as_str()) {
                    return Err(fault(
                        "daemon.client.transfer_incomplete",
                        "a reply overtook an incomplete transfer",
                    ));
                }
                let terminal = mode == ReplyMode::Unary
                    || matches!(
                        reply,
                        RuntimeReply::SyncComplete(_) | RuntimeReply::Failure(_)
                    );
                (
                    ReplySequenceItem::Reply(Box::new(reply)),
                    terminal,
                    frame_bytes,
                )
            }
        };
        let mut pending = shared
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let reply = pending.get(message_id.as_str()).ok_or_else(|| {
                fault(
                    "daemon.client.reply_uncorrelated",
                    "reply terminal raced a completed pending request",
                )
            })?;
            before_enqueue();
            if let Some(sender) = reply.sender.as_ref() {
                enqueue_reply(shared, sender, item, charge)?;
            }
        }
        if terminal {
            pending.remove(message_id.as_str());
        }
        Ok(())
    }

    fn accept_transfer(
        &mut self,
        message_id: &str,
        part: TransferEnvelope,
    ) -> Result<Option<Vec<u8>>, ClientFault> {
        let transfer_id = part.transfer_id.clone();
        let now_ms = epoch_ms();
        if let Some(completed) = self.completed.get(&transfer_id) {
            if completed.message_id != message_id {
                return Err(fault(
                    "daemon.client.transfer_binding_mismatch",
                    "completed transferId was reused by another messageId",
                ));
            }
            return match self
                .reassembler
                .accept_json(RuntimeTransferChannel::Reply, part, now_ms)
            {
                Ok(TransferProgress::AlreadyComplete) => Ok(None),
                Ok(_) => Err(fault(
                    "daemon.client.transfer_invalid",
                    "completed transfer unexpectedly became active",
                )),
                Err(error) => Err(fault("daemon.client.transfer_invalid", &error.to_string())),
            };
        }
        let binding = self
            .bindings
            .entry(transfer_id.clone())
            .or_insert_with(|| TransferBinding {
                message_id: message_id.to_owned(),
                parts: HashSet::new(),
                started_at_ms: now_ms,
            });
        if binding.message_id != message_id {
            return Err(fault(
                "daemon.client.transfer_binding_mismatch",
                "transferId was reused by another messageId",
            ));
        }
        if !binding.parts.contains(&part.part_index) {
            if self.active_parts >= ACTIVE_TRANSFER_PART_FRAMES {
                return Err(fault(
                    "daemon.client.transfer_backpressure",
                    "connection active transfer-part frame budget is full",
                ));
            }
            binding.parts.insert(part.part_index);
            self.active_parts += 1;
        }
        let progress = self
            .reassembler
            .accept_json(RuntimeTransferChannel::Reply, part, now_ms)
            .map_err(|error| {
                self.remove_transfer(&transfer_id);
                fault("daemon.client.transfer_invalid", &error.to_string())
            })?;
        match progress {
            TransferProgress::InProgress { .. } => Ok(None),
            TransferProgress::Complete(bytes) => {
                self.remove_transfer(&transfer_id);
                self.remember_completed(transfer_id, message_id, now_ms);
                Ok(Some(bytes))
            }
            TransferProgress::AlreadyComplete => {
                self.remove_transfer(&transfer_id);
                Err(fault(
                    "daemon.client.transfer_tombstone_desync",
                    "transfer reassembler retained a completed id without its message binding",
                ))
            }
        }
    }

    fn remove_transfer(&mut self, transfer_id: &TransferId) {
        if let Some(binding) = self.bindings.remove(transfer_id) {
            self.active_parts = self.active_parts.saturating_sub(binding.parts.len());
        }
    }

    fn has_active(&self, message_id: &str) -> bool {
        self.bindings
            .values()
            .any(|binding| binding.message_id == message_id)
    }

    fn remember_completed(&mut self, transfer_id: TransferId, message_id: &str, now_ms: u64) {
        if self.completed.len() >= MAX_COMPLETED_TRANSFER_TOMBSTONES
            && let Some((_, oldest)) = self.completed_order.pop_front()
        {
            self.completed.remove(&oldest);
        }
        self.completed.insert(
            transfer_id.clone(),
            CompletedBinding {
                message_id: message_id.to_owned(),
                completed_at_ms: now_ms,
            },
        );
        self.completed_order.push_back((now_ms, transfer_id));
    }

    fn housekeep(&mut self, shared: &SharedConnection, now_ms: u64) -> Result<(), ClientFault> {
        if self
            .bindings
            .values()
            .any(|binding| now_ms.saturating_sub(binding.started_at_ms) >= TRANSFER_TTL_MS)
        {
            self.bindings.clear();
            self.active_parts = 0;
            return Err(fault(
                "daemon.client.transfer_expired",
                "active reply transfer exceeded its five-minute TTL",
            ));
        }
        while self
            .completed_order
            .front()
            .is_some_and(|(completed, _)| now_ms.saturating_sub(*completed) >= TRANSFER_TTL_MS)
        {
            if let Some((_, transfer_id)) = self.completed_order.pop_front() {
                self.completed.remove(&transfer_id);
            }
        }
        self.completed
            .retain(|_, binding| now_ms.saturating_sub(binding.completed_at_ms) < TRANSFER_TTL_MS);
        let draining_expired = shared
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .any(|reply| {
                reply
                    .draining_since_ms
                    .is_some_and(|started| now_ms.saturating_sub(started) >= TRANSFER_TTL_MS)
            });
        if draining_expired {
            return Err(fault(
                "daemon.client.reply_drain_expired",
                "a dropped reply sequence did not reach its terminal frame within five minutes",
            ));
        }
        Ok(())
    }
}

fn run_housekeeping_tick(
    replies: &mut ReplyPumpState,
    shared: &SharedConnection,
    now_ms: u64,
) -> bool {
    if let Err(fault) = replies.housekeep(shared, now_ms) {
        set_fault(shared, fault);
        true
    } else {
        false
    }
}

fn enqueue_reply(
    shared: &SharedConnection,
    sender: &mpsc::Sender<QueuedReply>,
    item: ReplySequenceItem,
    bytes: usize,
) -> Result<(), ClientFault> {
    let frame = Arc::clone(&shared.queued_frames)
        .try_acquire_owned()
        .map_err(|_| {
            fault(
                "daemon.client.reply_sequence_backpressure",
                "reply frame budget is full",
            )
        })?;
    let count = u32::try_from(bytes.max(1)).map_err(|_| {
        fault(
            "daemon.client.reply_sequence_backpressure",
            "reply byte charge overflow",
        )
    })?;
    let bytes = Arc::clone(&shared.queued_bytes)
        .try_acquire_many_owned(count)
        .map_err(|_| {
            fault(
                "daemon.client.reply_sequence_backpressure",
                "reply byte budget is full",
            )
        })?;
    sender
        .try_send(QueuedReply {
            item,
            _frame: frame,
            _bytes: bytes,
        })
        .map_err(|_| {
            fault(
                "daemon.client.reply_sequence_backpressure",
                "per-request reply queue is full",
            )
        })
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn fault(code: &'static str, message: &str) -> ClientFault {
    ClientFault {
        code,
        message: message.to_owned(),
    }
}

async fn run_reader(
    reader: OwnedReadHalf,
    shared: Arc<SharedConnection>,
    streams: mpsc::Sender<RuntimeStreamFrame>,
    mut close: watch::Receiver<bool>,
    expected_first_reply: String,
) {
    let mut reader = BufReader::new(reader);
    let mut expected_first_reply = Some(expected_first_reply);
    let mut replies = ReplyPumpState::new();
    let mut housekeeping = tokio::time::interval(Duration::from_secs(1));
    housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    housekeeping.tick().await;
    let outcome = loop {
        let frame = tokio::select! {
            biased;
            _ = wait_for_close(&mut close) => break None,
            _ = housekeeping.tick() => {
                if run_housekeeping_tick(&mut replies, &shared, epoch_ms()) {
                    break None;
                }
                continue;
            }
            frame = read_jsonl_frame(&mut reader) => frame,
        };
        let frame = match frame {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                break Some(ClientFault {
                    code: "daemon.client.connection_closed",
                    message: "local Runtime socket reached EOF".to_owned(),
                });
            }
            Err(fault) => break Some(fault),
        };
        let envelope: RuntimeEnvelope = match serde_json::from_slice(&frame) {
            Ok(envelope) => envelope,
            Err(error) => {
                break Some(ClientFault {
                    code: "daemon.client.frame_invalid",
                    message: error.to_string(),
                });
            }
        };
        if let Some(expected) = expected_first_reply.take()
            && (envelope.message_id.as_str() != expected
                || !matches!(
                    &envelope.body,
                    RuntimeMessage::Reply(RuntimeReply::Hello(_) | RuntimeReply::Failure(_))
                ))
        {
            break Some(ClientFault {
                code: "daemon.client.hello_order_invalid",
                message: "the first daemon frame is not the correlated Hello reply".to_owned(),
            });
        }
        match envelope.body {
            RuntimeMessage::Reply(reply) => {
                if let Err(fault) =
                    replies.dispatch(&shared, envelope.message_id, reply, frame.len())
                {
                    break Some(fault);
                }
            }
            RuntimeMessage::Stream(item) => {
                let frame = RuntimeStreamFrame {
                    message_id: envelope.message_id,
                    item,
                };
                if streams.try_send(frame).is_err() {
                    break Some(ClientFault {
                        code: "daemon.client.stream_backpressure",
                        message: "bounded Runtime stream pump overflowed".to_owned(),
                    });
                }
            }
            RuntimeMessage::Request(_) => {
                break Some(ClientFault {
                    code: "daemon.client.server_request_forbidden",
                    message: "daemon sent a request on the client receive path".to_owned(),
                });
            }
        }
    };
    if let Some(fault) = outcome {
        set_fault(&shared, fault);
    }
    shared
        .pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    shared.writer.lock().await.take();
}

async fn wait_for_close(close: &mut watch::Receiver<bool>) {
    loop {
        if *close.borrow() {
            return;
        }
        if close.changed().await.is_err() {
            return;
        }
    }
}

async fn read_jsonl_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>, ClientFault>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    let mut frame = Vec::with_capacity(8192);
    loop {
        let available = reader.fill_buf().await.map_err(|error| ClientFault {
            code: "daemon.client.read_failed",
            message: error.to_string(),
        })?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(ClientFault {
                    code: "daemon.client.frame_unterminated",
                    message: "Runtime JSONL frame ended before LF".to_owned(),
                })
            };
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if frame.len().saturating_add(newline) >= MAX_RUNTIME_JSON_FRAME_BYTES {
                return Err(frame_too_large());
            }
            frame.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            return Ok(Some(frame));
        }
        let length = available.len();
        if frame.len().saturating_add(length) >= MAX_RUNTIME_JSON_FRAME_BYTES {
            return Err(frame_too_large());
        }
        frame.extend_from_slice(available);
        reader.consume(length);
    }
}

fn frame_too_large() -> ClientFault {
    ClientFault {
        code: "daemon.client.frame_too_large",
        message: "Runtime JSONL frame reached the exclusive 1 MiB cap".to_owned(),
    }
}

fn set_fault(shared: &SharedConnection, fault: ClientFault) {
    let mut current = shared
        .fault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if current.is_none() {
        *current = Some(fault);
        let _ = shared.close.send(true);
    }
}

fn validate_socket(path: &Path) -> Result<(), UnixClientError> {
    let parent = path.parent().ok_or_else(|| UnixClientError::SocketUnsafe {
        path: path.to_path_buf(),
        reason: "socket has no parent directory",
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| UnixClientError::SocketUnsafe {
            path: path.to_path_buf(),
            reason: "socket has no basename",
        })?;
    use std::os::unix::fs::OpenOptionsExt;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                UnixClientError::SocketMissing {
                    path: path.to_path_buf(),
                }
            } else {
                UnixClientError::SocketUnsafe {
                    path: path.to_path_buf(),
                    reason: "socket parent cannot be opened without following links",
                }
            }
        })?;
    let directory_stat =
        stat_fd(directory.as_raw_fd()).map_err(|_| UnixClientError::SocketUnsafe {
            path: path.to_path_buf(),
            reason: "socket parent metadata is unavailable",
        })?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    validate_socket_parent_stat(path, &directory_stat, uid)?;
    let name = CString::new(name.as_bytes()).map_err(|_| UnixClientError::SocketUnsafe {
        path: path.to_path_buf(),
        reason: "socket basename contains NUL",
    })?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: retained directory fd, valid basename and writable stat storage.
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        let source = std::io::Error::last_os_error();
        return if source.kind() == std::io::ErrorKind::NotFound {
            Err(UnixClientError::SocketMissing {
                path: path.to_path_buf(),
            })
        } else {
            Err(UnixClientError::SocketUnsafe {
                path: path.to_path_buf(),
                reason: "socket entry metadata is unavailable",
            })
        };
    }
    // SAFETY: successful fstatat initialized stat.
    let stat = unsafe { stat.assume_init() };
    validate_socket_entry_stat(path, &stat, uid)?;
    Ok(())
}

fn validate_socket_parent_stat(
    path: &Path,
    stat: &libc::stat,
    uid: libc::uid_t,
) -> Result<(), UnixClientError> {
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || stat.st_uid != uid
        || (stat.st_mode & 0o7777) != 0o700
    {
        return Err(UnixClientError::SocketUnsafe {
            path: path.to_path_buf(),
            reason: "socket parent must be current-EUID exact 0700 directory",
        });
    }
    Ok(())
}

fn validate_socket_entry_stat(
    path: &Path,
    stat: &libc::stat,
    uid: libc::uid_t,
) -> Result<(), UnixClientError> {
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK
        || stat.st_uid != uid
        || (stat.st_mode & 0o7777) != 0o600
        || stat.st_nlink != 1
    {
        return Err(UnixClientError::SocketUnsafe {
            path: path.to_path_buf(),
            reason: "socket must be current-EUID exact 0600 single-link socket",
        });
    }
    Ok(())
}

fn stat_fd(fd: libc::c_int) -> std::io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is retained by caller and stat is writable storage.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized stat.
    Ok(unsafe { stat.assume_init() })
}

fn map_connect_error(path: &Path, source: std::io::Error) -> UnixClientError {
    if source.kind() == std::io::ErrorKind::NotFound {
        UnixClientError::SocketMissing {
            path: path.to_path_buf(),
        }
    } else {
        UnixClientError::Connect {
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;

    fn shared() -> Arc<SharedConnection> {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let (_reader, writer) = stream.into_split();
        let (close, _) = watch::channel(false);
        Arc::new(SharedConnection {
            writer: AsyncMutex::new(Some(writer)),
            pending: Arc::new(Mutex::new(HashMap::new())),
            queued_frames: Arc::new(Semaphore::new(QUEUED_REPLY_FRAMES)),
            queued_bytes: Arc::new(Semaphore::new(QUEUED_REPLY_BYTES)),
            fault: Mutex::new(None),
            close,
        })
    }

    fn pending_reply() -> PendingReply {
        let (sender, _) = mpsc::channel(1);
        PendingReply {
            mode: ReplyMode::Unary,
            sender: Some(sender),
            draining_since_ms: None,
        }
    }

    fn socket_stat(uid: libc::uid_t) -> libc::stat {
        // SAFETY: an all-zero stat is valid initialized test storage; the validator only
        // reads the explicitly assigned mode/uid/nlink fields below.
        let mut stat = unsafe { MaybeUninit::<libc::stat>::zeroed().assume_init() };
        stat.st_mode = libc::S_IFSOCK | 0o600;
        stat.st_uid = uid;
        stat.st_nlink = 1;
        stat
    }

    #[test]
    fn socket_metadata_validator_rejects_wrong_owner_and_link_count() {
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let path = Path::new("/private/test/runtime.sock");

        let mut wrong_owner = socket_stat(uid);
        wrong_owner.st_uid = uid.wrapping_add(1);
        assert_eq!(
            validate_socket_entry_stat(path, &wrong_owner, uid)
                .unwrap_err()
                .code(),
            "daemon.client.socket_unsafe"
        );

        let mut multiple_links = socket_stat(uid);
        multiple_links.st_nlink = 2;
        assert_eq!(
            validate_socket_entry_stat(path, &multiple_links, uid)
                .unwrap_err()
                .code(),
            "daemon.client.socket_unsafe"
        );
    }

    #[test]
    fn socket_parent_metadata_validator_rejects_wrong_owner() {
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let path = Path::new("/private/test/runtime.sock");
        let mut stat = socket_stat(uid);
        stat.st_mode = libc::S_IFDIR | 0o700;
        stat.st_uid = uid.wrapping_add(1);
        assert_eq!(
            validate_socket_parent_stat(path, &stat, uid)
                .unwrap_err()
                .code(),
            "daemon.client.socket_unsafe"
        );
    }

    #[test]
    fn duplicate_pending_insert_preserves_the_original_entry() {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let first =
            PendingRegistration::insert(Arc::clone(&pending), "duplicate-id", pending_reply(), 2)
                .unwrap();
        let original = pending
            .lock()
            .unwrap()
            .get("duplicate-id")
            .unwrap()
            .sender
            .clone()
            .unwrap();
        let error = match PendingRegistration::insert(
            Arc::clone(&pending),
            "duplicate-id",
            pending_reply(),
            2,
        ) {
            Ok(_) => panic!("duplicate must fail"),
            Err(error) => error,
        };
        let current = pending
            .lock()
            .unwrap()
            .get("duplicate-id")
            .unwrap()
            .sender
            .clone()
            .unwrap();
        assert_eq!(error.code(), "daemon.client.message_id_duplicate");
        assert!(original.same_channel(&current));
        drop(first);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reply_sequence_deadline_is_not_extended_by_nonterminal_frames() {
        let shared = shared();
        let message_id = MessageId::new("absolute-sequence-deadline");
        let (sender, receiver) = mpsc::channel(SEQUENCE_QUEUE_CAPACITY);
        let mut registration = PendingRegistration::insert(
            Arc::clone(&shared.pending),
            message_id.as_str(),
            PendingReply {
                mode: ReplyMode::Sync,
                sender: Some(sender),
                draining_since_ms: None,
            },
            RuntimeUnixClient::REPLY_CAPACITY,
        )
        .unwrap();
        registration.mark_sent();
        let mut sequence = RuntimeReplySequence {
            message_id: message_id.clone(),
            receiver,
            _registration: registration,
            shared: Arc::clone(&shared),
            mode: ReplyMode::Sync,
            deadline: tokio::time::Instant::now() + Duration::from_millis(100),
            terminal_seen: false,
            drop_before_draining: None,
        };

        ReplyPumpState::new()
            .dispatch(
                &shared,
                message_id,
                RuntimeReply::Subscription(
                    agentdeck_protocol::runtime::SubscriptionReceipt::Subscribed {
                        stream_generation:
                            agentdeck_protocol::runtime::identity::StreamGeneration::new(
                                "absolute-deadline-generation",
                            ),
                    },
                ),
                1,
            )
            .unwrap();
        assert!(matches!(
            sequence.next().await.unwrap(),
            Some(ReplySequenceItem::Reply(_))
        ));
        tokio::time::sleep(Duration::from_millis(125)).await;
        assert!(matches!(
            sequence.next().await,
            Err(UnixClientError::ReplyTimeout)
        ));
        assert_eq!(shared.fault().unwrap().code, "daemon.client.reply_timeout");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sequence_drop_and_terminal_enqueue_are_linearized_under_pending_lock() {
        let shared = shared();
        let message_id = MessageId::new("drop-race");
        let (sender, receiver) = mpsc::channel(SEQUENCE_QUEUE_CAPACITY);
        let mut registration = PendingRegistration::insert(
            Arc::clone(&shared.pending),
            message_id.as_str(),
            PendingReply {
                mode: ReplyMode::Unary,
                sender: Some(sender),
                draining_since_ms: None,
            },
            RuntimeUnixClient::REPLY_CAPACITY,
        )
        .unwrap();
        registration.mark_sent();

        let (drop_attempted_tx, drop_attempted_rx) = std::sync::mpsc::sync_channel(0);
        let sequence = RuntimeReplySequence {
            message_id: message_id.clone(),
            receiver,
            _registration: registration,
            shared: Arc::clone(&shared),
            mode: ReplyMode::Unary,
            deadline: tokio::time::Instant::now() + REPLY_TIMEOUT,
            terminal_seen: false,
            drop_before_draining: Some(Box::new(move |pending| {
                assert!(pending.try_lock().is_err());
                drop_attempted_tx.send(()).unwrap();
            })),
        };

        let (enqueue_entered_tx, enqueue_entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_enqueue_tx, release_enqueue_rx) = std::sync::mpsc::sync_channel(0);
        let dispatch_shared = Arc::clone(&shared);
        let dispatch_message_id = message_id.clone();
        let dispatch = std::thread::spawn(move || {
            ReplyPumpState::new().dispatch_with_before_enqueue(
                &dispatch_shared,
                dispatch_message_id,
                RuntimeReply::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                }),
                1,
                move || {
                    enqueue_entered_tx.send(()).unwrap();
                    release_enqueue_rx.recv().unwrap();
                },
            )
        });
        enqueue_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let dropper = std::thread::spawn(move || drop(sequence));
        drop_attempted_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        release_enqueue_tx.send(()).unwrap();
        dispatch.join().unwrap().unwrap();
        dropper.join().unwrap();

        assert!(!shared.pending.lock().unwrap().contains_key("drop-race"));
        assert!(shared.fault().is_none());

        let (sibling_sender, mut sibling_receiver) = mpsc::channel(1);
        let mut sibling_registration = PendingRegistration::insert(
            Arc::clone(&shared.pending),
            "sibling",
            PendingReply {
                mode: ReplyMode::Unary,
                sender: Some(sibling_sender),
                draining_since_ms: None,
            },
            RuntimeUnixClient::REPLY_CAPACITY,
        )
        .unwrap();
        sibling_registration.mark_sent();
        ReplyPumpState::new()
            .dispatch(
                &shared,
                MessageId::new("sibling"),
                RuntimeReply::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                }),
                1,
            )
            .unwrap();
        assert!(sibling_receiver.try_recv().is_ok());
        assert!(!shared.pending.lock().unwrap().contains_key("sibling"));
        assert!(shared.fault().is_none());
    }

    enum BlockAt {
        Frame,
        Lf,
        Flush,
    }

    struct ControlledWriter {
        block: BlockAt,
        writes: usize,
    }

    impl AsyncWrite for ControlledWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let blocked = matches!(self.block, BlockAt::Frame) && self.writes == 0
                || matches!(self.block, BlockAt::Lf) && self.writes == 1;
            if blocked {
                Poll::Pending
            } else {
                self.writes += 1;
                Poll::Ready(Ok(bytes.len()))
            }
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if matches!(self.block, BlockAt::Flush) {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PartialThenOpenWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        blocked: Option<tokio::sync::oneshot::Sender<()>>,
        writes: usize,
    }

    impl AsyncWrite for PartialThenOpenWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            match self.writes {
                0 => {
                    let length = bytes.len().min(3);
                    self.bytes
                        .lock()
                        .unwrap()
                        .extend_from_slice(&bytes[..length]);
                    self.writes = 1;
                    Poll::Ready(Ok(length))
                }
                1 => {
                    self.writes = 2;
                    if let Some(blocked) = self.blocked.take() {
                        let _ = blocked.send(());
                    }
                    Poll::Pending
                }
                _ => {
                    self.bytes.lock().unwrap().extend_from_slice(bytes);
                    Poll::Ready(Ok(bytes.len()))
                }
            }
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn cancellation_during_frame_lf_or_flush_is_connection_fatal() {
        for block in [BlockAt::Frame, BlockAt::Lf, BlockAt::Flush] {
            let shared = shared();
            let task_shared = Arc::clone(&shared);
            let task = tokio::spawn(async move {
                let mut writer = ControlledWriter { block, writes: 0 };
                let mut guard = WriteHandoffGuard::new(task_shared);
                let _ = write_request_frame(&mut writer, b"frame", &mut guard).await;
            });
            tokio::task::yield_now().await;
            task.abort();
            let _ = task.await;
            assert_eq!(
                shared.fault().unwrap().code,
                "daemon.client.write_handoff_incomplete"
            );
        }
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_writer_lock_is_safe_and_removes_unsent_pending() {
        let shared = shared();
        let held = shared.writer.lock().await;
        let task_shared = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            let mut registration = PendingRegistration::insert(
                Arc::clone(&task_shared.pending),
                "lock-wait",
                pending_reply(),
                2,
            )
            .unwrap();
            write_frame_locked(&task_shared.writer, &task_shared, b"frame")
                .await
                .unwrap();
            registration.mark_sent();
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        drop(held);
        assert!(shared.fault().is_none());
        assert!(shared.pending.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_writer_cancel_poison_precedes_an_already_waiting_sibling() {
        let shared = shared();
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (blocked_tx, blocked_rx) = tokio::sync::oneshot::channel();
        let writer = Arc::new(AsyncMutex::new(Some(PartialThenOpenWriter {
            bytes: Arc::clone(&bytes),
            blocked: Some(blocked_tx),
            writes: 0,
        })));

        let task_writer = Arc::clone(&writer);
        let task_shared = Arc::clone(&shared);
        let partial = tokio::spawn(async move {
            write_frame_locked(&task_writer, &task_shared, b"partial-a").await
        });
        blocked_rx.await.unwrap();
        assert_eq!(bytes.lock().unwrap().as_slice(), b"par");

        let mut sibling = Box::pin(write_frame_locked(&writer, &shared, b"sibling-b"));
        tokio::select! {
            result = &mut sibling => panic!("sibling bypassed the held writer lock: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        partial.abort();
        let _ = partial.await;
        let error = match sibling.await {
            Ok(()) => panic!("poisoned writer admitted a sibling frame"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "daemon.client.write_handoff_incomplete");
        assert_eq!(
            shared.fault().unwrap().code,
            "daemon.client.write_handoff_incomplete"
        );
        assert_eq!(bytes.lock().unwrap().as_slice(), b"par");
    }

    #[tokio::test]
    async fn completed_flush_then_registration_drop_enters_draining_without_fault() {
        let shared = shared();
        let mut registration =
            PendingRegistration::insert(Arc::clone(&shared.pending), "sent", pending_reply(), 2)
                .unwrap();
        let mut writer = ControlledWriter {
            block: BlockAt::Frame,
            writes: 1,
        };
        let mut guard = WriteHandoffGuard::new(Arc::clone(&shared));
        write_request_frame(&mut writer, b"frame", &mut guard)
            .await
            .unwrap();
        registration.mark_sent();
        drop(guard);
        drop(registration);
        assert!(shared.fault().is_none());
        let pending = shared.pending.lock().unwrap();
        let sent = pending.get("sent").unwrap();
        assert!(sent.sender.is_none());
        assert!(sent.draining_since_ms.is_some());
    }

    #[tokio::test]
    async fn housekeeping_expires_completed_and_active_transfer_state() {
        let shared = shared();
        let mut state = ReplyPumpState::new();
        state.remember_completed(TransferId::new("done"), "message", 10);
        state.housekeep(&shared, 10 + TRANSFER_TTL_MS).unwrap();
        assert!(state.completed.is_empty());

        state.bindings.insert(
            TransferId::new("active"),
            TransferBinding {
                message_id: "message".into(),
                parts: HashSet::from([0]),
                started_at_ms: 10,
            },
        );
        state.active_parts = 1;
        let error = state.housekeep(&shared, 10 + TRANSFER_TTL_MS).unwrap_err();
        assert_eq!(error.code, "daemon.client.transfer_expired");
        assert!(state.bindings.is_empty());
        assert_eq!(state.active_parts, 0);
    }

    #[tokio::test]
    async fn draining_ttl_faults_connection_before_a_new_sibling_can_start() {
        let shared = shared();
        let close = shared.close.subscribe();
        shared.pending.lock().unwrap().insert(
            "draining".into(),
            PendingReply {
                mode: ReplyMode::Sync,
                sender: None,
                draining_since_ms: Some(10),
            },
        );
        let mut state = ReplyPumpState::new();
        assert!(run_housekeeping_tick(
            &mut state,
            &shared,
            10 + TRANSFER_TTL_MS
        ));
        assert_eq!(
            shared.fault().unwrap().code,
            "daemon.client.reply_drain_expired"
        );
        assert!(*close.borrow());

        let (_streams_tx, streams) = mpsc::channel(1);
        let client = RuntimeUnixClient {
            shared: Arc::clone(&shared),
            streams,
            reader_task: None,
            installation_id: InstallationId::random_for_test(),
            socket_path: PathBuf::from("/unused/test.sock"),
        };
        let error = match client
            .begin_request(RuntimeRequest::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            }))
            .await
        {
            Ok(_) => panic!("faulted connection must reject a new sibling request"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "daemon.client.reply_drain_expired");
        assert_eq!(shared.pending.lock().unwrap().len(), 1);
    }

    #[test]
    fn completed_tombstone_same_timestamp_eviction_desync_fails_closed() {
        let mut state = ReplyPumpState::new();
        let now_ms = epoch_ms();
        let bytes = b"one-part".to_vec();
        let hash = agentdeck_crypto::sha256(&bytes);
        let retained_id = TransferId::new("zzzz-retained-by-inner");
        let retained_part = TransferEnvelope::new_json(
            retained_id.clone(),
            0,
            1,
            hash,
            bytes.len() as u64,
            bytes.clone(),
        )
        .unwrap();

        for index in 0..=MAX_COMPLETED_TRANSFER_TOMBSTONES {
            let transfer_id = if index == 0 {
                retained_id.clone()
            } else {
                TransferId::new(format!("a{index:03}"))
            };
            let part = TransferEnvelope::new_json(
                transfer_id.clone(),
                0,
                1,
                hash,
                bytes.len() as u64,
                bytes.clone(),
            )
            .unwrap();
            let progress = state
                .reassembler
                .accept_json(RuntimeTransferChannel::Reply, part, now_ms)
                .unwrap();
            assert!(matches!(progress, TransferProgress::Complete(_)));
            state.remember_completed(transfer_id, "original-message", now_ms);
        }
        assert_eq!(state.completed.len(), MAX_COMPLETED_TRANSFER_TOMBSTONES);
        assert!(!state.completed.contains_key(&retained_id));

        let error = state
            .accept_transfer("different-message", retained_part)
            .unwrap_err();
        assert_eq!(error.code, "daemon.client.transfer_tombstone_desync");
        assert!(state.bindings.is_empty());
        assert_eq!(state.active_parts, 0);
    }
}
