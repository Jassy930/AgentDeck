//! Recovery 后才可建立的本机 Runtime UDS listener。
//!
//! 威胁场景：旧 socket、pathname/inode 替换或被替换的数据目录若能通过 bind
//! readback，daemon 会在错误的本机入口开放控制面，并可能误删另一个进程的
//! socket。这里把 retained dirfd、stale probe、bind/readback 与 typed permit
//! 固定为同一条 fail-closed 链；关闭时只删除自己记录的 pathname inode。

use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::future::Future;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::config::{DaemonConfig, LocalIngressMode};
use crate::diag;
use crate::runtime::RuntimeCore;
use crate::runtime::namespace::{DaemonMode, DaemonPaths};
use crate::runtime::recovery::RecoveryReadyPermit;
use crate::runtime::singleton::{SingletonError, SingletonGuard};

use super::unix::{LocalConnectionError, serve_accepted_stream_with_shutdown};

const STALE_PROBE_TIMEOUT: Duration = Duration::from_millis(250);
const LOCAL_CONNECTION_CAPACITY: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum LocalListenerError {
    #[error("recovery readiness permit does not belong to this RuntimeCore")]
    RecoveryPermitMismatch,
    #[error("stdio compatibility does not select a local Runtime socket")]
    StdioSelected,
    #[error("daemon singleton/data directory validation failed: {0}")]
    Singleton(#[from] SingletonError),
    #[error("unsafe local Runtime socket {path}: {reason}")]
    UnsafeSocket { path: PathBuf, reason: &'static str },
    #[error("local Runtime socket is already active: {path}")]
    SocketInUse { path: PathBuf },
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("local Runtime connection actor did not exit normally")]
    ConnectionTask,
    #[error("local Runtime shutdown signal failed: {0}")]
    Signal(#[source] io::Error),
}

impl LocalListenerError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RecoveryPermitMismatch => "daemon.local.recovery_permit_mismatch",
            Self::StdioSelected => "daemon.local.stdio_selected",
            Self::Singleton(error) => error.code(),
            Self::UnsafeSocket { .. } => "daemon.local.socket_unsafe",
            Self::SocketInUse { .. } => "daemon.local.socket_in_use",
            Self::Io { .. } => "daemon.local.socket_io_failed",
            Self::ConnectionTask => "daemon.local.connection_task_failed",
            Self::Signal(_) => "daemon.local.signal_failed",
        }
    }
}

#[derive(Clone, Copy)]
struct EntryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
}

impl EntryIdentity {
    fn is_owned_single_link_socket(self, uid: u32) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFSOCK as u32
            && self.uid == uid
            && self.links == 1
    }

    fn is_private_socket(self, uid: u32) -> bool {
        self.is_owned_single_link_socket(uid) && self.mode & 0o7777 == 0o600
    }

    fn same_inode(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[derive(Clone, Copy)]
struct ListenerFdIdentity {
    _device: u64,
    _inode: u64,
    _links: u64,
}

/// 完整 recovery 与 UDS bind/readback 后产生的本地 readiness capability。
/// 字段与构造器保持私有；本类型刻意不实现 `Clone` / `Copy`。
pub struct LocalReadyPermit {
    socket_path: PathBuf,
    _entry: EntryIdentity,
    _listener_fd: ListenerFdIdentity,
    remote_start: Option<RemoteStartPermit>,
}

impl std::fmt::Debug for LocalReadyPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalReadyPermit")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl LocalReadyPermit {
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn take_remote_start_permit(&mut self) -> Option<RemoteStartPermit> {
        self.remote_start.take()
    }
}

/// P4 RemoteTransport 的单次启动 capability。
///
/// 它只可由 stable、remote-enabled、canonical socket 的 bound listener 产生，
/// 并刻意不实现 `Clone` / `Copy`。
pub struct RemoteStartPermit {
    _entry: EntryIdentity,
    _listener_fd: ListenerFdIdentity,
}

impl std::fmt::Debug for RemoteStartPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RemoteStartPermit(..)")
    }
}

struct SocketPathGuard {
    directory: File,
    name: CString,
    path: PathBuf,
    identity: EntryIdentity,
}

impl SocketPathGuard {
    fn capture(directory: File, name: CString, path: PathBuf) -> Result<Self, LocalListenerError> {
        let entry = stat_entry_at(&directory, &name, &path)?.ok_or_else(|| {
            unsafe_socket(&path, "bound socket pathname disappeared before readback")
        })?;
        let visible = stat_visible_entry(&path)?.ok_or_else(|| {
            unsafe_socket(&path, "bound socket pathname disappeared before readback")
        })?;
        // 初次 capture 发生在 chmod 前；这里只固定 owner/type/inode，最终 mode
        // 与 nlink 在 typed permit 构造前完整复核。
        // SAFETY: geteuid has no preconditions and reads only process credentials.
        let uid = unsafe { libc::geteuid() };
        if entry.mode & libc::S_IFMT as u32 != libc::S_IFSOCK as u32
            || entry.uid != uid
            || entry.links != 1
            || !entry.same_inode(visible)
        {
            return Err(unsafe_socket(
                &path,
                "bound dirfd/path entries are not the same owned socket inode",
            ));
        }
        Ok(Self {
            directory,
            name,
            path,
            identity: entry,
        })
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let Ok(Some(current)) = stat_entry_at(&self.directory, &self.name, &self.path) else {
            return;
        };
        if current.mode & libc::S_IFMT as u32 != libc::S_IFSOCK as u32
            || current.links != 1
            || !current.same_inode(self.identity)
        {
            return;
        }
        // SAFETY: directory/name are retained owned values. The immediately preceding
        // inode check prevents ordinary replacement cleanup; same-UID mutation is outside
        // the authentication boundary and cannot make us follow a symlink via unlinkat.
        let status = unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) };
        if status != 0 {
            let source = io::Error::last_os_error();
            diag::log(
                "daemon_local_socket_cleanup_failed",
                &format!("kind={:?} errno={:?}", source.kind(), source.raw_os_error()),
            );
        }
    }
}

/// 已安全绑定、尚未接入 production main 的 listener owner。
pub struct BoundLocalListener {
    listener: UnixListener,
    socket_guard: SocketPathGuard,
    local_ready: LocalReadyPermit,
    core: Arc<RuntimeCore>,
}

impl std::fmt::Debug for BoundLocalListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundLocalListener")
            .field("socket_path", &self.local_ready.socket_path)
            .finish_non_exhaustive()
    }
}

impl BoundLocalListener {
    /// 唯一 production bind 入口。没有 path 参数：stable 与 ephemeral 都只能使用
    /// `DaemonConfig` 已冻结的 canonical `DaemonPaths.socket`。
    pub async fn bind_after_recovery(
        recovery_ready: RecoveryReadyPermit,
        config: &DaemonConfig,
        singleton: &SingletonGuard,
        core: Arc<RuntimeCore>,
    ) -> Result<Self, LocalListenerError> {
        if !core.owns_recovery_ready_permit(&recovery_ready) {
            return Err(LocalListenerError::RecoveryPermitMismatch);
        }
        if config.local_ingress_mode() != LocalIngressMode::Uds {
            return Err(LocalListenerError::StdioSelected);
        }
        let paths = config.paths();
        singleton.revalidate_data_dir(paths)?;
        let directory = singleton.clone_data_dir(paths)?;
        let name = socket_name(paths)?;
        remove_stale_socket(paths, singleton, &directory, &name).await?;
        singleton.revalidate_data_dir(paths)?;

        let listener = UnixListener::bind(&paths.socket)
            .map_err(|source| map_bind_error(&paths.socket, source))?;
        let socket_guard = SocketPathGuard::capture(directory, name, paths.socket.clone())?;
        chmod_socket(&socket_guard)?;
        let (entry, listener_fd) =
            read_back_bound_socket(&listener, &socket_guard, paths, singleton)?;
        let remote_start = (matches!(config.mode(), DaemonMode::Stable)
            && config.remote_enabled()
            && paths.is_stable_namespace())
        .then_some(RemoteStartPermit {
            _entry: entry,
            _listener_fd: listener_fd,
        });
        let local_ready = LocalReadyPermit {
            socket_path: paths.socket.clone(),
            _entry: entry,
            _listener_fd: listener_fd,
            remote_start,
        };
        Ok(Self {
            listener,
            socket_guard,
            local_ready,
            core,
        })
    }

    #[must_use]
    pub fn local_ready_permit(&self) -> &LocalReadyPermit {
        &self.local_ready
    }

    /// stable listener 至多派生一次；ephemeral/no-remote 永远返回 `None`。
    pub fn take_remote_start_permit(&mut self) -> Option<RemoteStartPermit> {
        self.local_ready.take_remote_start_permit()
    }

    /// 接受连接直到 shutdown future 完成。停止顺序固定为：停止 accept → 向所有
    /// accepted actor 广播 graceful cancellation → poll/join 全部 actor → 删除 exact socket。
    /// 调用方必须持续 poll 本 future，不能 abort 后依赖 detached cleanup。
    pub async fn serve_until<F>(self, shutdown: F) -> Result<(), LocalListenerError>
    where
        F: Future<Output = Result<(), LocalListenerError>>,
    {
        let Self {
            listener,
            socket_guard,
            local_ready,
            core,
        } = self;
        let permits = Arc::new(Semaphore::new(LOCAL_CONNECTION_CAPACITY));
        let (connection_shutdown, _) = watch::channel(false);
        let mut connections: JoinSet<Result<(), LocalConnectionError>> = JoinSet::new();
        let mut terminal_error = None;
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                result = &mut shutdown => {
                    if let Err(error) = result {
                        terminal_error = Some(error);
                    }
                    break;
                },
                joined = connections.join_next(), if !connections.is_empty() => {
                    match joined {
                        Some(Ok(Ok(()))) | None => {}
                        Some(Ok(Err(error))) => {
                            diag::log(
                                "daemon_local_connection_closed",
                                &format!("code={}", error.code()),
                            );
                        }
                        Some(Err(_)) => {
                            terminal_error = Some(LocalListenerError::ConnectionTask);
                            break;
                        }
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(source) => {
                            terminal_error = Some(io_error(
                                "accept local Runtime connection",
                                local_ready.socket_path(),
                                source,
                            ));
                            break;
                        }
                    };
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let core = core.clone();
                    let shutdown = connection_shutdown.subscribe();
                    connections.spawn(async move {
                        let _permit = permit;
                        serve_accepted_stream_with_shutdown(stream, core, shutdown).await
                    });
                }
            }
        }

        drop(listener);
        let _ = connection_shutdown.send(true);
        while let Some(joined) = connections.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    diag::log(
                        "daemon_local_connection_closed",
                        &format!("code={}", error.code()),
                    );
                }
                Err(_) if terminal_error.is_none() => {
                    terminal_error = Some(LocalListenerError::ConnectionTask);
                }
                Err(_) => {}
            }
        }
        drop(socket_guard);
        terminal_error.map_or(Ok(()), Err)
    }
}

fn socket_name(paths: &DaemonPaths) -> Result<CString, LocalListenerError> {
    if paths.socket.parent() != Some(paths.data_dir.as_path()) {
        return Err(unsafe_socket(
            &paths.socket,
            "socket is not an immediate child of the retained data directory",
        ));
    }
    let name = paths
        .socket
        .file_name()
        .ok_or_else(|| unsafe_socket(&paths.socket, "socket pathname has no basename"))?;
    CString::new(name.as_bytes())
        .map_err(|_| unsafe_socket(&paths.socket, "socket basename contains NUL"))
}

async fn remove_stale_socket(
    paths: &DaemonPaths,
    singleton: &SingletonGuard,
    directory: &File,
    name: &CStr,
) -> Result<(), LocalListenerError> {
    remove_stale_socket_with_hook(paths, singleton, directory, name, || {}).await
}

async fn remove_stale_socket_with_hook<F>(
    paths: &DaemonPaths,
    singleton: &SingletonGuard,
    directory: &File,
    name: &CStr,
    before_second_read: F,
) -> Result<(), LocalListenerError>
where
    F: FnOnce(),
{
    let Some(original) = validated_owned_socket(directory, name, &paths.socket)? else {
        return Ok(());
    };
    match tokio::time::timeout(STALE_PROBE_TIMEOUT, UnixStream::connect(&paths.socket)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            Err(LocalListenerError::SocketInUse {
                path: paths.socket.clone(),
            })
        }
        Ok(Err(source)) if source.kind() == io::ErrorKind::ConnectionRefused => {
            before_second_read();
            singleton.revalidate_data_dir(paths)?;
            let current =
                validated_owned_socket(directory, name, &paths.socket)?.ok_or_else(|| {
                    LocalListenerError::SocketInUse {
                        path: paths.socket.clone(),
                    }
                })?;
            if !current.same_inode(original) {
                return Err(LocalListenerError::SocketInUse {
                    path: paths.socket.clone(),
                });
            }
            // SAFETY: retained dirfd/name are valid and a second exact inode readback just
            // completed. unlinkat cannot follow a symlink.
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io_error(
                    "remove stale local Runtime socket",
                    &paths.socket,
                    io::Error::last_os_error(),
                ));
            }
            singleton.revalidate_data_dir(paths)?;
            Ok(())
        }
        Ok(Err(source)) if source.kind() == io::ErrorKind::NotFound => {
            singleton.revalidate_data_dir(paths)?;
            if stat_entry_at(directory, name, &paths.socket)?.is_none()
                && stat_visible_entry(&paths.socket)?.is_none()
            {
                Ok(())
            } else {
                Err(LocalListenerError::SocketInUse {
                    path: paths.socket.clone(),
                })
            }
        }
        Ok(Err(source)) => Err(io_error(
            "probe existing local Runtime socket",
            &paths.socket,
            source,
        )),
        Err(_) => Err(LocalListenerError::SocketInUse {
            path: paths.socket.clone(),
        }),
    }
}

fn chmod_socket(guard: &SocketPathGuard) -> Result<(), LocalListenerError> {
    // SAFETY: guard retains the validated directory fd and NUL-terminated basename.
    if unsafe { libc::fchmodat(guard.directory.as_raw_fd(), guard.name.as_ptr(), 0o600, 0) } != 0 {
        return Err(io_error(
            "set local Runtime socket permissions",
            &guard.path,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn read_back_bound_socket(
    listener: &UnixListener,
    guard: &SocketPathGuard,
    paths: &DaemonPaths,
    singleton: &SingletonGuard,
) -> Result<(EntryIdentity, ListenerFdIdentity), LocalListenerError> {
    singleton.revalidate_data_dir(paths)?;
    let entry = validated_private_socket(&guard.directory, &guard.name, &guard.path)?
        .ok_or_else(|| unsafe_socket(&guard.path, "bound socket disappeared during readback"))?;
    if !entry.same_inode(guard.identity) {
        return Err(unsafe_socket(
            &guard.path,
            "bound socket inode changed during permission readback",
        ));
    }
    let local_path = listener
        .local_addr()
        .map_err(|source| io_error("read local Runtime listener address", &guard.path, source))?
        .as_pathname()
        .map(Path::to_path_buf);
    if local_path.as_deref() != Some(guard.path.as_path()) {
        return Err(unsafe_socket(
            &guard.path,
            "listener FD is not bound to the canonical pathname",
        ));
    }
    let listener_fd = stat_listener_fd(listener.as_raw_fd(), &guard.path)?;
    singleton.revalidate_data_dir(paths)?;
    Ok((entry, listener_fd))
}

fn validated_owned_socket(
    directory: &File,
    name: &CStr,
    path: &Path,
) -> Result<Option<EntryIdentity>, LocalListenerError> {
    validated_socket_entry(directory, name, path, false)
}

fn validated_private_socket(
    directory: &File,
    name: &CStr,
    path: &Path,
) -> Result<Option<EntryIdentity>, LocalListenerError> {
    validated_socket_entry(directory, name, path, true)
}

fn validated_socket_entry(
    directory: &File,
    name: &CStr,
    path: &Path,
    require_private_mode: bool,
) -> Result<Option<EntryIdentity>, LocalListenerError> {
    let entry = stat_entry_at(directory, name, path)?;
    let visible = stat_visible_entry(path)?;
    match (entry, visible) {
        (None, None) => Ok(None),
        (Some(entry), Some(visible)) if entry.same_inode(visible) => {
            // SAFETY: geteuid has no preconditions and reads only process credentials.
            let uid = unsafe { libc::geteuid() };
            let entry_valid = if require_private_mode {
                entry.is_private_socket(uid)
            } else {
                entry.is_owned_single_link_socket(uid)
            };
            let visible_valid = if require_private_mode {
                visible.is_private_socket(uid)
            } else {
                visible.is_owned_single_link_socket(uid)
            };
            if entry_valid && visible_valid {
                Ok(Some(entry))
            } else {
                Err(unsafe_socket(
                    path,
                    if require_private_mode {
                        "entry is not an owned exact-0600 single-link Unix socket"
                    } else {
                        "entry is not an owned single-link Unix socket"
                    },
                ))
            }
        }
        _ => Err(unsafe_socket(
            path,
            "retained dirfd and visible pathname do not name the same socket inode",
        )),
    }
}

fn stat_visible_entry(path: &Path) -> Result<Option<EntryIdentity>, LocalListenerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(EntryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
        })),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("inspect local Runtime socket path", path, source)),
    }
}

fn stat_entry_at(
    directory: &File,
    name: &CStr,
    path: &Path,
) -> Result<Option<EntryIdentity>, LocalListenerError> {
    let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: retained dirfd/name are live and entry is writable stat storage.
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            entry.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(io_error(
            "inspect local Runtime socket through retained directory",
            path,
            source,
        ));
    }
    // SAFETY: successful fstatat initialized entry.
    let entry = unsafe { entry.assume_init() };
    Ok(Some(EntryIdentity {
        device: entry.st_dev as u64,
        inode: entry.st_ino,
        uid: entry.st_uid,
        mode: entry.st_mode as u32,
        links: entry.st_nlink as u64,
    }))
}

fn stat_listener_fd(fd: RawFd, path: &Path) -> Result<ListenerFdIdentity, LocalListenerError> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is owned by listener and status points to writable stat storage.
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return Err(io_error(
            "inspect local Runtime listener FD",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful fstat initialized status.
    let status = unsafe { status.assume_init() };
    // macOS AF_UNIX listener FD and pathname are distinct kernel/fs inodes (FD nlink=0),
    // so they must be validated separately rather than compared for dev/ino equality.
    // SAFETY: geteuid has no preconditions and reads only process credentials.
    let uid = unsafe { libc::geteuid() };
    if status.st_mode & libc::S_IFMT != libc::S_IFSOCK || status.st_uid != uid {
        return Err(unsafe_socket(
            path,
            "listener FD is not an owned Unix socket",
        ));
    }
    Ok(ListenerFdIdentity {
        _device: status.st_dev as u64,
        _inode: status.st_ino,
        _links: status.st_nlink as u64,
    })
}

fn map_bind_error(path: &Path, source: io::Error) -> LocalListenerError {
    if source.kind() == io::ErrorKind::AddrInUse {
        LocalListenerError::SocketInUse {
            path: path.to_path_buf(),
        }
    } else {
        io_error("bind local Runtime socket", path, source)
    }
}

fn unsafe_socket(path: &Path, reason: &'static str) -> LocalListenerError {
    LocalListenerError::UnsafeSocket {
        path: path.to_path_buf(),
        reason,
    }
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> LocalListenerError {
    LocalListenerError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    use agentdeck_protocol::runtime::command::{
        CatalogRequest, ConversationStart, HelloParams, QueryReceiptSelector, SendPromptRequest,
    };
    use agentdeck_protocol::runtime::identity::{IdempotencyKey, MessageId};
    use agentdeck_protocol::runtime::{
        CodexConversationConfiguration, CommandReceipt, CommandStatus, ConfigurationReceipt,
        ConfigureConversationRequest, ConversationConfiguration, MAX_RUNTIME_JSON_FRAME_BYTES,
        PromptPayload, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeReply,
        RuntimeRequest, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{
        AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::config::DaemonStartupOptions;
    use crate::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
    use crate::runtime::{AgentRouter, FakeCoordinator, RuntimeCore};
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);
    const IO_TIMEOUT: Duration = Duration::from_secs(5);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = Path::new("/tmp").join(format!(
                "adl-unit-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create listener unit root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure listener unit root");
            Self(path)
        }

        fn config(&self) -> DaemonConfig {
            DaemonConfig::resolve_with_roots(
                DaemonStartupOptions {
                    ephemeral: true,
                    no_remote: true,
                    stdio_compat: false,
                    profile: None,
                    stable_keychain_access_group: None,
                },
                &self.0,
                &self.0,
            )
            .expect("resolve listener unit config")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn recovered_fake_core(
        config: &DaemonConfig,
    ) -> (Arc<RuntimeCore>, FakeCoordinator, RecoveryReadyPermit) {
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &config.paths().runtime_db)
            .expect("create active-turn StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(config.paths().runtime_db.clone()),
            kek,
        )
        .await
        .expect("open active-turn Runtime store");
        let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
        let fake = FakeCoordinator::held();
        let core = Arc::new(
            RuntimeCore::new_with_test_execution_coordinator(
                store,
                router,
                [0xA5; 32],
                Arc::new(fake.clone()),
            )
            .expect("construct active-turn RuntimeCore"),
        );
        let (_, permit) = core
            .recover_for_startup()
            .await
            .expect("recover active-turn RuntimeCore");
        (core, fake, permit)
    }

    async fn write_envelope(stream: &mut UnixStream, envelope: &RuntimeEnvelope) {
        let bytes = envelope
            .to_json_bytes_checked()
            .expect("encode listener Runtime envelope");
        stream
            .write_all(&bytes)
            .await
            .expect("write listener Runtime envelope");
        stream
            .write_all(b"\n")
            .await
            .expect("terminate listener Runtime envelope");
        stream
            .flush()
            .await
            .expect("flush listener Runtime envelope");
    }

    async fn read_envelope(stream: &mut UnixStream) -> RuntimeEnvelope {
        let mut line = Vec::new();
        tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                let byte = stream.read_u8().await.expect("read listener reply byte");
                if byte == b'\n' {
                    break;
                }
                line.push(byte);
            }
        })
        .await
        .expect("listener Runtime reply timeout");
        serde_json::from_slice(&line).expect("decode listener Runtime reply")
    }

    async fn request(
        stream: &mut UnixStream,
        message_id: &str,
        request: RuntimeRequest,
    ) -> RuntimeReply {
        write_envelope(
            stream,
            &RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id: MessageId::new(message_id),
                body: RuntimeMessage::Request(request),
            },
        )
        .await;
        let reply = read_envelope(stream).await;
        assert_eq!(reply.message_id.as_str(), message_id);
        let RuntimeMessage::Reply(reply) = reply.body else {
            panic!("expected directed Runtime reply")
        };
        reply
    }

    async fn connect_ready(path: &Path, installation_id: &str) -> UnixStream {
        let mut stream = UnixStream::connect(path)
            .await
            .expect("connect production listener sample");
        let preface = serde_json::to_vec(&serde_json::json!({
            "localProtocolVersion": 1,
            "clientInstallationId": installation_id,
        }))
        .expect("encode production listener preface");
        stream.write_all(&preface).await.expect("write preface");
        stream.write_all(b"\n").await.expect("terminate preface");
        stream.flush().await.expect("flush preface");
        assert!(matches!(
            request(
                &mut stream,
                "listener-hello",
                RuntimeRequest::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                }),
            )
            .await,
            RuntimeReply::Hello(_)
        ));
        stream
    }

    async fn assert_closed_without_reply(stream: &mut UnixStream) {
        let mut byte = [0_u8; 1];
        let result = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut byte))
            .await
            .expect("faulted production connection did not close");
        match result {
            Ok(0) => {}
            Ok(count) => panic!("faulted production connection emitted {count} bytes"),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) => {}
            Err(error) => panic!("unexpected production connection close error: {error}"),
        }
    }

    fn set_small_receive_buffer(stream: &UnixStream) {
        let size: libc::c_int = 4_096;
        // SAFETY: stream owns a live socket fd and size points to a valid c_int.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&raw const size).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
    }

    fn readable_bytes(stream: &UnixStream) -> libc::c_int {
        let mut available: libc::c_int = 0;
        // SAFETY: stream owns a live socket fd and available is writable ioctl storage.
        assert_eq!(
            unsafe { libc::ioctl(stream.as_raw_fd(), libc::FIONREAD, &raw mut available) },
            0
        );
        available
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_backpressure_and_bad_clients_preserve_sibling_active_turn() {
        // 威胁场景：production listener 的慢 egress、malformed/oversize frame 或
        // stalled preface 若升级为全局关闭，会取消 sibling 持有的 durable Started
        // turn，破坏同一 daemon 内多客户端隔离。
        let root = TestRoot::new("active-isolation");
        let config = root.config();
        let singleton = SingletonGuard::acquire(config.paths()).expect("acquire active singleton");
        let (core, fake, permit) = recovered_fake_core(&config).await;
        let bound =
            BoundLocalListener::bind_after_recovery(permit, &config, &singleton, core.clone())
                .await
                .expect("bind active-turn listener");
        let socket = config.paths().socket.clone();
        let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(bound.serve_until(async move {
            let _ = shutdown_receiver.await;
            Ok(())
        }));

        let mut sibling = connect_ready(&socket, "123e4567-e89b-12d3-a456-426614174301").await;
        let start = request(
            &mut sibling,
            "listener-start",
            RuntimeRequest::Start(ConversationStart {
                agent_kind: AgentKind::Codex,
                idempotency_key: IdempotencyKey::new("listener-active-conversation"),
                cwd: PathBuf::from("/tmp/agentdeck-listener-active"),
                title: Some("x".repeat(700 * 1024)),
            }),
        )
        .await;
        let RuntimeReply::ConversationStart(start) = start else {
            panic!("expected listener conversation start")
        };
        let configured = request(
            &mut sibling,
            "listener-configure",
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                start.conversation_id.clone(),
                IdempotencyKey::new("listener-active-configuration"),
                0,
                ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                    CodexConversationConfiguration::new(
                        CodexApprovalPolicy::OnRequest,
                        CodexSandboxMode::WorkspaceWrite,
                        CodexReasoningEffort::Medium,
                    ),
                )),
            )),
        )
        .await;
        assert!(matches!(
            configured,
            RuntimeReply::Configuration(ConfigurationReceipt::Applied {
                conversation_id,
                configuration_revision: 1,
            }) if conversation_id == start.conversation_id
        ));
        let prompt = request(
            &mut sibling,
            "listener-prompt",
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id: start.conversation_id.clone(),
                idempotency_key: IdempotencyKey::new("listener-active-prompt"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("hold active execution").expect("valid listener prompt"),
            }),
        )
        .await;
        let RuntimeReply::Command(CommandReceipt::Accepted {
            command_id,
            configuration_revision: 1,
            ..
        }) = prompt
        else {
            panic!("expected accepted listener prompt")
        };
        tokio::time::timeout(IO_TIMEOUT, fake.wait_for_starts(1))
            .await
            .expect("active listener turn did not start");

        let status = request(
            &mut sibling,
            "listener-status-before",
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                conversation_id: start.conversation_id.clone(),
                command_id: command_id.clone(),
            }),
        )
        .await;
        let RuntimeReply::CommandStatus(before) = status else {
            panic!("expected listener command status")
        };
        assert_eq!(before.configuration_revision, 1);
        assert_eq!(before.status, CommandStatus::Started);
        let turn_id = before.turn_id.clone().expect("active listener turn id");

        let mut slow = connect_ready(&socket, "123e4567-e89b-12d3-a456-426614174302").await;
        set_small_receive_buffer(&slow);
        write_envelope(
            &mut slow,
            &RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id: MessageId::new("listener-slow-catalog"),
                body: RuntimeMessage::Request(RuntimeRequest::Catalog(CatalogRequest {
                    page_cursor: None,
                })),
            },
        )
        .await;
        tokio::time::timeout(IO_TIMEOUT, async {
            while readable_bytes(&slow) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("slow catalog never reached the real socket");

        let mut malformed = connect_ready(&socket, "123e4567-e89b-12d3-a456-426614174303").await;
        malformed
            .write_all(b"{\"version\":1\n")
            .await
            .expect("write malformed production frame");
        malformed.flush().await.expect("flush malformed frame");
        assert_closed_without_reply(&mut malformed).await;

        let mut oversized = connect_ready(&socket, "123e4567-e89b-12d3-a456-426614174304").await;
        let oversized_frame = vec![b' '; MAX_RUNTIME_JSON_FRAME_BYTES];
        let _ = tokio::time::timeout(IO_TIMEOUT, async {
            oversized.write_all(&oversized_frame).await?;
            oversized.write_all(b"\n").await?;
            oversized.flush().await
        })
        .await;
        assert_closed_without_reply(&mut oversized).await;
        let stalled = UnixStream::connect(&socket)
            .await
            .expect("connect stalled production preface");

        assert!(matches!(
            request(
                &mut sibling,
                "listener-hello-after-faults",
                RuntimeRequest::Hello(HelloParams {
                    runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                }),
            )
            .await,
            RuntimeReply::Hello(_)
        ));
        let status = request(
            &mut sibling,
            "listener-status-after",
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                conversation_id: start.conversation_id.clone(),
                command_id: command_id.clone(),
            }),
        )
        .await;
        let RuntimeReply::CommandStatus(after) = status else {
            panic!("expected post-backpressure command status")
        };
        assert_eq!(after.configuration_revision, 1);
        assert_eq!(after.status, CommandStatus::Started);
        assert_eq!(after.command_id, command_id);
        assert_eq!(after.turn_id.as_ref(), Some(&turn_id));
        assert_eq!(fake.active(), 1);

        assert!(matches!(
            request(
                &mut sibling,
                "listener-cancel-active",
                RuntimeRequest::CancelActive {
                    conversation_id: start.conversation_id,
                    turn_id,
                },
            )
            .await,
            RuntimeReply::Cancellation(_)
        ));
        tokio::time::timeout(IO_TIMEOUT, async {
            while fake.active() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("active listener turn did not fence on cancel");

        drop((stalled, oversized, malformed, slow, sibling));
        shutdown.send(()).expect("request active listener shutdown");
        tokio::time::timeout(IO_TIMEOUT, server)
            .await
            .expect("active listener shutdown timed out")
            .expect("join active listener")
            .expect("active listener shutdown");
        core.shutdown()
            .await
            .expect("shutdown active listener Core");
    }

    #[tokio::test]
    async fn stale_probe_inode_replacement_is_preserved_and_rejected() {
        // 威胁场景：connect(refused) 后 pathname 被换成另一个 socket；第二次
        // dirfd/path identity readback 必须拒绝，不能 unlink replacement。
        let root = TestRoot::new("swap");
        let config = root.config();
        let singleton = SingletonGuard::acquire(config.paths()).expect("acquire unit singleton");
        let path = config.paths().socket.clone();
        let stale = tokio::net::UnixListener::bind(&path).expect("bind stale socket");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure stale socket");
        let stale_inode = fs::symlink_metadata(&path)
            .expect("stale socket metadata")
            .ino();
        drop(stale);

        let directory = singleton
            .clone_data_dir(config.paths())
            .expect("clone retained data dir");
        let name = socket_name(config.paths()).expect("socket basename");
        let mut replacement = None;
        let error =
            remove_stale_socket_with_hook(config.paths(), &singleton, &directory, &name, || {
                fs::remove_file(&path).expect("remove stale socket in hook");
                let listener =
                    tokio::net::UnixListener::bind(&path).expect("bind replacement socket");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("secure replacement socket");
                replacement = Some(listener);
            })
            .await
            .expect_err("inode replacement must fail closed");
        assert!(matches!(error, LocalListenerError::SocketInUse { .. }));
        assert_ne!(
            fs::symlink_metadata(&path)
                .expect("replacement metadata")
                .ino(),
            stale_inode
        );
        drop(replacement.take());
        fs::remove_file(path).expect("remove preserved replacement");
    }

    #[test]
    fn private_socket_identity_rejects_multiple_links() {
        // pathname readback 的 exact nlink=1 是 permit 前置条件。
        // SAFETY: geteuid has no preconditions and reads only process credentials.
        let uid = unsafe { libc::geteuid() };
        let identity = EntryIdentity {
            device: 1,
            inode: 2,
            uid,
            mode: libc::S_IFSOCK as u32 | 0o600,
            links: 2,
        };
        assert!(!identity.is_private_socket(uid));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn darwin_listener_fd_and_pathname_have_independent_real_identities() {
        let root = TestRoot::new("darwin");
        let config = root.config();
        let _singleton =
            SingletonGuard::acquire(config.paths()).expect("acquire Darwin sample singleton");
        let path = config.paths().socket.clone();
        let listener = UnixListener::bind(&path).expect("bind Darwin identity sample");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure Darwin identity sample");
        let fd = stat_listener_fd(listener.as_raw_fd(), &path).expect("stat listener FD");
        let pathname = fs::symlink_metadata(&path).expect("stat listener pathname");

        assert_eq!(fd._links, 0, "Darwin AF_UNIX listener FD is anonymous");
        assert_eq!(pathname.nlink(), 1);
        assert_ne!(
            (fd._device, fd._inode),
            (pathname.dev(), pathname.ino()),
            "FD and pathname must not be treated as the same inode on Darwin"
        );
        drop(listener);
        fs::remove_file(path).expect("remove Darwin identity sample");
    }
}
