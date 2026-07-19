//! P3.10 versioned daemon 的 deferred idle upgrade coordinator。

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_FEATURE_UNAVAILABLE;
use agentdeck_protocol::runtime::upgrade::MAX_TARGET_VERSION_BYTES;
use agentdeck_protocol::runtime::{
    ArtifactSha256, RuntimeFailure, StageUpgradeReceipt, StageUpgradeRequest,
};
use async_trait::async_trait;
use getrandom::fill as fill_random;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::conversation::ConversationRegistry;
use super::store::{
    AcceptAdminUpgradeOutcome, AdminUpgradeCommand, AdminUpgradeStatus,
    AdminUpgradeTerminalOutcome, RuntimeCommitOperation, RuntimeStoreError, RuntimeStoreHandle,
};

const DAEMON_BASENAME: &str = "agentdeckd";
const CURRENT_BASENAME: &str = "current";
const DEFAULT_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Core envelope path 与具体 durable ledger/action 的窄接口。只有该接口返回的
/// `DeferredUpgrade` 才能在 reply flush ACK 后被 arm。
#[async_trait]
pub(crate) trait UpgradeService: Send + Sync {
    async fn prepare(
        &self,
        request: StageUpgradeRequest,
    ) -> Result<PreparedUpgrade, RuntimeFailure>;
}

pub(crate) struct PreparedUpgrade {
    receipt: StageUpgradeReceipt,
    deferred: Option<DeferredUpgrade>,
}

impl PreparedUpgrade {
    pub(crate) fn with_deferred(receipt: StageUpgradeReceipt, deferred: DeferredUpgrade) -> Self {
        Self {
            receipt,
            deferred: Some(deferred),
        }
    }

    pub(crate) fn failed(failure: RuntimeFailure) -> Self {
        Self {
            receipt: StageUpgradeReceipt::Failed { failure },
            deferred: None,
        }
    }

    pub(crate) fn reply_only(receipt: StageUpgradeReceipt) -> Self {
        Self {
            receipt,
            deferred: None,
        }
    }

    pub(crate) fn into_parts(self) -> (StageUpgradeReceipt, Option<DeferredUpgrade>) {
        (self.receipt, self.deferred)
    }
}

/// 已完成 durable stage、但尚未取得 transport flush ACK 的一次性 action。
/// Drop 是取消；`arm` 只做同步 task ownership transfer，不在 caller 栈内 shutdown。
pub(crate) struct DeferredUpgrade {
    arm: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl DeferredUpgrade {
    pub(crate) fn new(arm: impl FnOnce() + Send + 'static) -> Self {
        Self {
            arm: Some(Box::new(arm)),
        }
    }

    pub(crate) fn arm(mut self) {
        if let Some(arm) = self.arm.take() {
            arm();
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DisabledUpgradeService;

#[async_trait]
impl UpgradeService for DisabledUpgradeService {
    async fn prepare(
        &self,
        _request: StageUpgradeRequest,
    ) -> Result<PreparedUpgrade, RuntimeFailure> {
        Err(RuntimeFailure::new(
            DAEMON_RUNTIME_FEATURE_UNAVAILABLE,
            "daemon upgrade execution is unavailable",
        ))
    }
}

/// production RuntimeCore 使用的 durable upgrade service。每个 deferred task 都先
/// 取得 ConversationRegistry 的独占可逆 pause，再从 authenticated Store 读回状态；
/// 文件切换成功并 durable finalize 后只发送 main-loop exit signal，不直接 shutdown。
#[derive(Clone)]
pub(crate) struct DurableUpgradeService {
    store: RuntimeStoreHandle,
    conversations: Arc<ConversationRegistry>,
    switcher: VersionedDaemonSwitcher,
    exit: mpsc::UnboundedSender<()>,
    exit_armed: Arc<AtomicBool>,
    idle_poll_interval: Duration,
}

impl DurableUpgradeService {
    pub(crate) fn new(
        store: RuntimeStoreHandle,
        conversations: Arc<ConversationRegistry>,
        bin_root: PathBuf,
        exit: mpsc::UnboundedSender<()>,
    ) -> Result<Self, UpgradeSwitchError> {
        Ok(Self {
            store,
            conversations,
            switcher: VersionedDaemonSwitcher::new(bin_root)?,
            exit,
            exit_armed: Arc::new(AtomicBool::new(false)),
            idle_poll_interval: DEFAULT_IDLE_POLL_INTERVAL,
        })
    }

    fn arm(self, command: AdminUpgradeCommand) {
        tokio::spawn(async move {
            self.run(command).await;
        });
    }

    async fn run(self, command: AdminUpgradeCommand) {
        if self.exit_armed.load(Ordering::Acquire) {
            return;
        }
        let request = command.request().clone();
        let Ok(mut pause) = self.conversations.pause_starts_for_upgrade().await else {
            return;
        };
        // 多个已 ACK deferred task 可能在第一个 action 释放 serial guard 前都读到
        // `exit_armed=false`。取得 upgrade serial ownership 后必须重新判定；已有赢家时
        // 保持 scheduling 关闭并退出，不能切第二个 current 或重新开放 start admission。
        if self.exit_armed.load(Ordering::Acquire) {
            pause.commit_for_exit();
            return;
        }

        // `upgrade_transition` 已串行化所有 deferred actions；在 fence 内重新读回，
        // 关闭 stale Pending capability 导致重复 switch/finalize 的窗口。
        let Ok(Some(current)) = self.store.query_admin_upgrade(request).await else {
            return;
        };
        if current.status() != AdminUpgradeStatus::Pending {
            return;
        }

        loop {
            let Ok(active) = self.store.active_started_command_count().await else {
                return;
            };
            if active == 0 {
                break;
            }
            pause.release_fence_while_waiting();
            tokio::time::sleep(self.idle_poll_interval).await;
            if pause.refence().await.is_err() {
                return;
            }
        }

        let switcher = self.switcher.clone();
        let target_version = current.target_version().to_owned();
        let candidate_sha256 = current.candidate_sha256().clone();
        let switched = tokio::task::spawn_blocking(move || {
            switcher.switch(&target_version, &candidate_sha256)
        })
        .await;
        match switched {
            Ok(Ok(())) => {
                if !self
                    .finalize_exact(current, AdminUpgradeTerminalOutcome::Completed)
                    .await
                {
                    return;
                }
                // send 是同步 ownership transfer；成功后先发布 exit_armed，再释放
                // upgrade serial guard，后继 replay task 不可能切第二个 version。
                if self.exit.send(()).is_ok() {
                    self.exit_armed.store(true, Ordering::Release);
                    pause.commit_for_exit();
                }
            }
            Ok(Err(error)) => {
                let failure = RuntimeFailure::new(
                    error.code(),
                    "staged daemon artifact could not be activated",
                );
                let _ = self
                    .finalize_exact(current, AdminUpgradeTerminalOutcome::Failed { failure })
                    .await;
            }
            Err(_) => {
                let failure = RuntimeFailure::new(
                    "daemon.upgrade.worker_failed",
                    "daemon upgrade filesystem worker failed",
                );
                let _ = self
                    .finalize_exact(current, AdminUpgradeTerminalOutcome::Failed { failure })
                    .await;
            }
        }
    }

    async fn finalize_exact(
        &self,
        command: AdminUpgradeCommand,
        terminal: AdminUpgradeTerminalOutcome,
    ) -> bool {
        let request = command.request().clone();
        match self
            .store
            .finalize_admin_upgrade(command.clone(), terminal.clone())
            .await
        {
            Ok(_) => true,
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::FinalizeAdminUpgrade,
            }) => {
                if self
                    .store
                    .finalize_admin_upgrade(command, terminal.clone())
                    .await
                    .is_ok()
                {
                    return true;
                }
                let Ok(Some(current)) = self.store.query_admin_upgrade(request).await else {
                    return false;
                };
                match terminal {
                    AdminUpgradeTerminalOutcome::Completed => {
                        current.status() == AdminUpgradeStatus::Completed
                    }
                    AdminUpgradeTerminalOutcome::Failed { failure } => {
                        current.status() == AdminUpgradeStatus::Failed
                            && current.terminal_failure() == Some(&failure)
                    }
                }
            }
            Err(_) => false,
        }
    }
}

#[async_trait]
impl UpgradeService for DurableUpgradeService {
    async fn prepare(
        &self,
        request: StageUpgradeRequest,
    ) -> Result<PreparedUpgrade, RuntimeFailure> {
        let outcome = self
            .store
            .accept_admin_upgrade(request)
            .await
            .map_err(store_failure)?;
        let (command, active_started_commands, accepted) = match outcome {
            AcceptAdminUpgradeOutcome::Accepted {
                command,
                active_started_commands,
            } => (command, active_started_commands, true),
            AcceptAdminUpgradeOutcome::Replayed {
                command,
                active_started_commands,
            } => (command, active_started_commands, false),
        };
        match command.status() {
            AdminUpgradeStatus::Pending => {
                let receipt = if accepted {
                    if active_started_commands == 0 {
                        StageUpgradeReceipt::Staged {
                            target_version: command.target_version().to_owned(),
                        }
                    } else {
                        StageUpgradeReceipt::AwaitingIdle {
                            target_version: command.target_version().to_owned(),
                            active_turns: active_started_commands,
                        }
                    }
                } else {
                    StageUpgradeReceipt::Replayed {
                        target_version: command.target_version().to_owned(),
                    }
                };
                let runner = self.clone();
                Ok(PreparedUpgrade::with_deferred(
                    receipt,
                    DeferredUpgrade::new(move || runner.arm(command)),
                ))
            }
            AdminUpgradeStatus::Completed => {
                Ok(PreparedUpgrade::reply_only(StageUpgradeReceipt::Replayed {
                    target_version: command.target_version().to_owned(),
                }))
            }
            AdminUpgradeStatus::Failed => {
                let failure = command.terminal_failure().cloned().ok_or_else(|| {
                    RuntimeFailure::new(
                        RuntimeStoreError::UnknownOrCorruptSchema.code(),
                        "durable upgrade failure is invalid",
                    )
                })?;
                Ok(PreparedUpgrade::reply_only(StageUpgradeReceipt::Failed {
                    failure,
                }))
            }
        }
    }
}

fn store_failure(error: RuntimeStoreError) -> RuntimeFailure {
    RuntimeFailure::new(
        error.code(),
        "daemon upgrade durable store operation failed",
    )
}

/// 已由 CLI stage 到固定 versioned layout 的 daemon artifact 切换器。
///
/// 本类型只接受 `bin/<version>/agentdeckd`，重新从 retained fd 计算请求绑定的
/// SHA-256，再以相对 symlink + rename 原子替换 `bin/current`。签名/entitlement 的
/// 双重验证属于 CLI artifact installer；这里不执行候选 binary。
#[derive(Clone, Debug)]
pub(crate) struct VersionedDaemonSwitcher {
    bin_root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpgradeSwitchError {
    #[error("daemon bin root must be a clean absolute path: {0}")]
    InvalidBinRoot(PathBuf),
    #[error("upgrade target version is invalid")]
    InvalidVersion,
    #[error("unsafe upgrade path {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: &'static str },
    #[error("staged daemon hash does not match StageUpgrade request")]
    HashMismatch,
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl UpgradeSwitchError {
    #[must_use]
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::InvalidBinRoot(_) => "daemon.upgrade.bin_root_invalid",
            Self::InvalidVersion => "daemon.upgrade.version_invalid",
            Self::UnsafePath { .. } => "daemon.upgrade.artifact_unsafe",
            Self::HashMismatch => "daemon.upgrade.hash_mismatch",
            Self::Io { .. } => "daemon.upgrade.io_failed",
        }
    }
}

impl VersionedDaemonSwitcher {
    pub(crate) fn new(bin_root: PathBuf) -> Result<Self, UpgradeSwitchError> {
        if !is_clean_absolute(&bin_root) {
            return Err(UpgradeSwitchError::InvalidBinRoot(bin_root));
        }
        Ok(Self { bin_root })
    }

    pub(crate) fn switch(
        &self,
        target_version: &str,
        expected_sha256: &ArtifactSha256,
    ) -> Result<(), UpgradeSwitchError> {
        validate_version(target_version)?;
        let bin = open_directory(&self.bin_root)?;
        validate_private_directory(&bin, &self.bin_root)?;

        let version_name =
            cstring(target_version).map_err(|_| UpgradeSwitchError::InvalidVersion)?;
        let version_path = self.bin_root.join(target_version);
        let version = openat_directory(&bin, &version_name, &version_path)?;
        validate_private_directory(&version, &version_path)?;

        let daemon_name = CString::new(DAEMON_BASENAME).expect("fixed basename has no NUL");
        let daemon_path = version_path.join(DAEMON_BASENAME);
        let mut daemon = openat_file(&version, &daemon_name, &daemon_path)?;
        validate_candidate(&daemon, &daemon_path)?;
        if hash_hex(&mut daemon, &daemon_path)? != expected_sha256.as_str() {
            return Err(UpgradeSwitchError::HashMismatch);
        }

        let mut temporary = TemporaryCurrentLink::create(&bin, target_version, &self.bin_root)?;
        temporary.publish(&bin, &self.bin_root)?;
        bin.sync_all()
            .map_err(|source| io("sync daemon bin directory", &self.bin_root, source))?;
        Ok(())
    }
}

fn is_clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn validate_version(value: &str) -> Result<(), UpgradeSwitchError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > MAX_TARGET_VERSION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(UpgradeSwitchError::InvalidVersion);
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<File, UpgradeSwitchError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|source| io("open daemon bin directory", path, source))
}

fn openat_directory(
    parent: &File,
    name: &CString,
    path: &Path,
) -> Result<File, UpgradeSwitchError> {
    // SAFETY: parent is a retained directory fd and name is one validated component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io(
            "open staged version directory",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful openat returns one newly-owned fd.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn openat_file(parent: &File, name: &CString, path: &Path) -> Result<File, UpgradeSwitchError> {
    // SAFETY: parent is a retained directory fd and name is a fixed component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io(
            "open staged daemon",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful openat returns one newly-owned fd.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn validate_private_directory(file: &File, path: &Path) -> Result<(), UpgradeSwitchError> {
    let metadata = file
        .metadata()
        .map_err(|source| io("inspect upgrade directory", path, source))?;
    // SAFETY: geteuid has no preconditions and only reads current process credentials.
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir() {
        return Err(unsafe_path(path, "entry is not a directory"));
    }
    if metadata.uid() != uid {
        return Err(unsafe_path(
            path,
            "directory owner differs from current account",
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(unsafe_path(path, "directory is group/world writable"));
    }
    Ok(())
}

fn validate_candidate(file: &File, path: &Path) -> Result<(), UpgradeSwitchError> {
    let metadata = file
        .metadata()
        .map_err(|source| io("inspect staged daemon", path, source))?;
    // SAFETY: geteuid has no preconditions and only reads current process credentials.
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_type().is_fifo()
        || metadata.file_type().is_socket()
    {
        return Err(unsafe_path(path, "candidate is not a regular file"));
    }
    if metadata.uid() != uid || metadata.nlink() != 1 {
        return Err(unsafe_path(
            path,
            "candidate owner or hard-link count is invalid",
        ));
    }
    if metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & u32::from(libc::S_ISUID | libc::S_ISGID) != 0
    {
        return Err(unsafe_path(path, "candidate executable mode is invalid"));
    }
    Ok(())
}

fn hash_hex(file: &mut File, path: &Path) -> Result<String, UpgradeSwitchError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| io("hash staged daemon", path, source))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

struct TemporaryCurrentLink {
    parent_fd: i32,
    name: CString,
    published: bool,
}

impl TemporaryCurrentLink {
    fn create(
        bin: &File,
        target_version: &str,
        bin_path: &Path,
    ) -> Result<Self, UpgradeSwitchError> {
        let target = cstring(target_version).map_err(|_| UpgradeSwitchError::InvalidVersion)?;
        for _ in 0..32 {
            let mut nonce = [0_u8; 16];
            fill_random(&mut nonce).map_err(|source| UpgradeSwitchError::Io {
                operation: "generate current-link nonce",
                path: bin_path.to_path_buf(),
                source: std::io::Error::other(source.to_string()),
            })?;
            let basename = format!(
                ".current-{}",
                nonce
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let name = cstring(&basename).expect("generated basename has no NUL");
            // SAFETY: target/name are NUL-terminated components and bin is a retained dirfd.
            if unsafe { libc::symlinkat(target.as_ptr(), bin.as_raw_fd(), name.as_ptr()) } == 0 {
                return Ok(Self {
                    parent_fd: bin.as_raw_fd(),
                    name,
                    published: false,
                });
            }
            let source = std::io::Error::last_os_error();
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(io(
                "create temporary current link",
                &bin_path.join(basename),
                source,
            ));
        }
        Err(UpgradeSwitchError::Io {
            operation: "allocate temporary current link",
            path: bin_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "temporary current-link name collision budget exhausted",
            ),
        })
    }

    fn publish(&mut self, bin: &File, bin_path: &Path) -> Result<(), UpgradeSwitchError> {
        let current = CString::new(CURRENT_BASENAME).expect("fixed basename has no NUL");
        // SAFETY: both names are single components under the retained bin dirfd.
        if unsafe {
            libc::renameat(
                bin.as_raw_fd(),
                self.name.as_ptr(),
                bin.as_raw_fd(),
                current.as_ptr(),
            )
        } != 0
        {
            return Err(io(
                "publish current daemon link",
                &bin_path.join(CURRENT_BASENAME),
                std::io::Error::last_os_error(),
            ));
        }
        self.published = true;
        Ok(())
    }
}

impl Drop for TemporaryCurrentLink {
    fn drop(&mut self) {
        if !self.published {
            // SAFETY: parent fd outlives this guard inside switch; name is the exact symlink made.
            unsafe { libc::unlinkat(self.parent_fd, self.name.as_ptr(), 0) };
        }
    }
}

fn cstring(value: &str) -> Result<CString, std::ffi::NulError> {
    CString::new(value.as_bytes())
}

fn unsafe_path(path: &Path, reason: &'static str) -> UpgradeSwitchError {
    UpgradeSwitchError::UnsafePath {
        path: path.to_path_buf(),
        reason,
    }
}

fn io(operation: &'static str, path: &Path, source: std::io::Error) -> UpgradeSwitchError {
    UpgradeSwitchError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use agentdeck_protocol::runtime::{
        ArtifactSha256, IdempotencyKey, LocalOnlyAdministration, StageUpgradeRequest,
    };
    use sha2::{Digest, Sha256};
    use tokio::sync::mpsc;

    use super::{DurableUpgradeService, VersionedDaemonSwitcher};
    use crate::runtime::conversation::ConversationRegistry;
    use crate::runtime::execution::DisabledExecutionCoordinator;
    use crate::runtime::model::{
        RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
    };
    use crate::runtime::store::{
        AcceptAdminUpgradeOutcome, AdminUpgradeStatus, RuntimeId, RuntimeIdKind,
        RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle,
        RuntimeStoreOperation,
    };
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = Path::new("/tmp").join(format!(
                "agentdeck-upgrade-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("test root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("root mode");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hash_hex(bytes: &[u8]) -> ArtifactSha256 {
        ArtifactSha256::new(
            <[u8; 32]>::from(Sha256::digest(bytes))
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .expect("canonical hash")
    }

    #[derive(Clone)]
    struct RejectCapacityAfterFinalizeCommit {
        rejected: Arc<AtomicBool>,
    }

    impl RejectCapacityAfterFinalizeCommit {
        fn new() -> Self {
            Self {
                rejected: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl RuntimeStoreFaultInjector for RejectCapacityAfterFinalizeCommit {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::FinalizeAdminUpgradeAfterCommit
                && !self.rejected.swap(true, Ordering::AcqRel)
            {
                Err(RuntimeStoreError::WorkerStopped)
            } else {
                Ok(())
            }
        }
    }

    impl RuntimeCapacityProbe for RejectCapacityAfterFinalizeCommit {
        fn observe(
            &self,
            _database: &Path,
        ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
            if self.rejected.load(Ordering::Acquire) {
                return Ok(RuntimeCapacityObservation {
                    main_bytes: 2 * 1024 * 1024 * 1024 + 1,
                    wal_bytes: 0,
                    shm_bytes: 0,
                    filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
                    filesystem_available_bytes: 8 * 1024 * 1024 * 1024,
                });
            }
            Ok(RuntimeCapacityObservation {
                main_bytes: 8 * 1024 * 1024,
                wal_bytes: 2 * 1024 * 1024,
                shm_bytes: 32 * 1024,
                filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
                filesystem_available_bytes: 4 * 1024 * 1024 * 1024,
            })
        }
    }

    #[test]
    fn version_switch_verifies_candidate_and_atomically_replaces_relative_current_link() {
        let root = TestRoot::new("success");
        let bin = root.path().join("bin");
        let version = bin.join("1.2.3");
        fs::create_dir_all(&version).expect("version directory");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).expect("bin mode");
        fs::set_permissions(&version, fs::Permissions::from_mode(0o700)).expect("version mode");
        let daemon = version.join("agentdeckd");
        fs::write(&daemon, b"candidate daemon").expect("candidate");
        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o500)).expect("candidate mode");
        symlink("old", bin.join("current")).expect("old current");

        let switcher = VersionedDaemonSwitcher::new(bin.clone()).expect("switcher");
        switcher
            .switch("1.2.3", &hash_hex(b"candidate daemon"))
            .expect("switch current");

        assert_eq!(
            fs::read_link(bin.join("current")).expect("current"),
            Path::new("1.2.3")
        );
        assert_eq!(
            fs::read(&daemon).expect("candidate remains"),
            b"candidate daemon"
        );
        assert_eq!(
            fs::read_dir(&bin)
                .expect("bin entries")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".current-"))
                .count(),
            0,
            "successful switch leaves no temporary link"
        );
    }

    #[test]
    fn hash_mismatch_writable_and_linked_candidate_leave_current_unchanged() {
        let root = TestRoot::new("reject");
        let bin = root.path().join("bin");
        let version = bin.join("2.0.0");
        fs::create_dir_all(&version).expect("version directory");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).expect("bin mode");
        fs::set_permissions(&version, fs::Permissions::from_mode(0o700)).expect("version mode");
        let daemon = version.join("agentdeckd");
        fs::write(&daemon, b"candidate daemon").expect("candidate");
        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o500)).expect("candidate mode");
        symlink("old", bin.join("current")).expect("old current");

        let switcher = VersionedDaemonSwitcher::new(bin.clone()).expect("switcher");
        assert!(switcher.switch("2.0.0", &hash_hex(b"different")).is_err());
        assert_eq!(
            fs::read_link(bin.join("current")).expect("current"),
            Path::new("old")
        );

        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o777))
            .expect("make candidate unsafe");
        assert!(
            switcher
                .switch("2.0.0", &hash_hex(b"candidate daemon"))
                .is_err()
        );
        assert_eq!(
            fs::read_link(bin.join("current")).expect("current"),
            Path::new("old")
        );
        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o500))
            .expect("restore candidate mode");

        let real = version.join("real");
        fs::rename(&daemon, &real).expect("move real candidate");
        fs::hard_link(&real, &daemon).expect("candidate hard link");
        assert!(
            switcher
                .switch("2.0.0", &hash_hex(b"candidate daemon"))
                .is_err()
        );
        assert_eq!(
            fs::read_link(bin.join("current")).expect("current"),
            Path::new("old")
        );

        fs::remove_file(&daemon).expect("remove candidate hard link");
        symlink(&real, &daemon).expect("candidate symlink");
        assert!(
            switcher
                .switch("2.0.0", &hash_hex(b"candidate daemon"))
                .is_err()
        );
        assert_eq!(
            fs::read_link(bin.join("current")).expect("current"),
            Path::new("old")
        );
    }

    #[tokio::test]
    async fn switched_upgrade_uses_authenticated_finalize_readback_before_exit() {
        let root = TestRoot::new("finalize-readback-exit");
        let bin = root.path().join("bin");
        let version_name = "3.1.4";
        let version = bin.join(version_name);
        fs::create_dir_all(&version).expect("version directory");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).expect("bin mode");
        fs::set_permissions(&version, fs::Permissions::from_mode(0o700)).expect("version mode");
        let candidate_bytes = b"finalize readback daemon";
        let daemon = version.join("agentdeckd");
        fs::write(&daemon, candidate_bytes).expect("candidate");
        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o500)).expect("candidate mode");

        let database = root.path().join("runtime.db");
        let keys = MemoryKeyStore::new();
        let fault = RejectCapacityAfterFinalizeCommit::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone())
                .with_capacity_probe(fault.clone())
                .with_fault_injector(Arc::new(fault)),
            load_or_create_storage_kek(&keys, &database).expect("create upgrade Store KEK"),
        )
        .await
        .expect("open upgrade Store");
        let request = StageUpgradeRequest::new(
            version_name.to_owned(),
            hash_hex(candidate_bytes),
            IdempotencyKey::new("finalize-readback-exit"),
            LocalOnlyAdministration::LocalOnly,
        )
        .expect("valid upgrade request");
        let command = match store
            .accept_admin_upgrade(request.clone())
            .await
            .expect("accept upgrade")
        {
            AcceptAdminUpgradeOutcome::Accepted { command, .. } => command,
            AcceptAdminUpgradeOutcome::Replayed { .. } => panic!("fresh upgrade replayed"),
        };
        let conversations = Arc::new(
            ConversationRegistry::new(
                store.clone(),
                Arc::new(DisabledExecutionCoordinator),
                RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0xD4; 16])
                    .expect("daemon boot id"),
                1,
            )
            .expect("conversation registry"),
        );
        let (exit, mut exit_receiver) = mpsc::unbounded_channel();
        let upgrade =
            DurableUpgradeService::new(store.clone(), conversations.clone(), bin.clone(), exit)
                .expect("durable upgrade service");

        upgrade.run(command).await;

        assert_eq!(
            fs::read_link(bin.join("current")).expect("switched current"),
            Path::new(version_name)
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), exit_receiver.recv())
                .await
                .expect("upgrade exit deadline"),
            Some(()),
            "authenticated Completed readback must permit exit after COMMIT-unknown"
        );
        assert_eq!(
            store
                .query_admin_upgrade(request)
                .await
                .expect("query finalized upgrade")
                .expect("finalized upgrade exists")
                .status(),
            AdminUpgradeStatus::Completed
        );
        drop(conversations);
        store.shutdown().await.expect("shutdown upgrade Store");
    }
}
