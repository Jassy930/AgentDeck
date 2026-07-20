//! daemon 进程级 singleton guard。
//!
//! 数据目录在打开并校验后以 directory fd 固定；lock 只通过该 fd 的 `openat`
//! 创建/打开，避免完整路径在检查和打开之间被替换。

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use super::namespace::{DaemonPaths, NamespaceError};

#[derive(Debug)]
pub enum SingletonError {
    Namespace(NamespaceError),
    AlreadyRunning {
        path: PathBuf,
    },
    UnsafeLockFile {
        path: PathBuf,
        reason: &'static str,
    },
    UnsupportedPlatform,
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for SingletonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Namespace(error) => error.fmt(formatter),
            Self::AlreadyRunning { path } => {
                write!(
                    formatter,
                    "daemon is already running for lock {}",
                    path.display()
                )
            }
            Self::UnsafeLockFile { path, reason } => {
                write!(
                    formatter,
                    "unsafe daemon lock file {}: {reason}",
                    path.display()
                )
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("daemon singleton locks require a Unix platform")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for SingletonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Namespace(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl SingletonError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Namespace(error) => error.code(),
            Self::AlreadyRunning { .. } => "daemon.singleton.already_running",
            Self::UnsafeLockFile { .. } => "daemon.singleton.unsafe_lock",
            Self::UnsupportedPlatform => "daemon.singleton.unsupported_platform",
            Self::Io { .. } => "daemon.singleton.io_failed",
        }
    }
}

impl From<NamespaceError> for SingletonError {
    fn from(error: NamespaceError) -> Self {
        Self::Namespace(error)
    }
}

pub struct SingletonGuard {
    lock_path: PathBuf,
    file: File,
    /// 固定通过验证的数据目录 inode，并确保 lock openat 的父目录 fd 活到退出。
    data_dir: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SingletonAcquireMode {
    CreateOrOpen,
    ExistingOnly,
}

impl fmt::Debug for SingletonGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SingletonGuard")
            .field("lock_path", &self.lock_path)
            .finish_non_exhaustive()
    }
}

impl SingletonGuard {
    pub fn acquire(paths: &DaemonPaths) -> Result<Self, SingletonError> {
        Self::acquire_with_mode(paths, SingletonAcquireMode::CreateOrOpen)
    }

    /// one-shot recovery/finalizer 专用。这里只观察安装期已经存在的 data-dir 与
    /// singleton lock；拒绝路径不得 mkdir、O_CREAT 或收紧旧目录权限。
    pub(crate) fn acquire_existing(paths: &DaemonPaths) -> Result<Self, SingletonError> {
        Self::acquire_with_mode(paths, SingletonAcquireMode::ExistingOnly)
    }

    fn acquire_with_mode(
        paths: &DaemonPaths,
        mode: SingletonAcquireMode,
    ) -> Result<Self, SingletonError> {
        #[cfg(not(unix))]
        {
            let _ = (paths, mode);
            return Err(SingletonError::UnsupportedPlatform);
        }

        #[cfg(unix)]
        {
            if mode == SingletonAcquireMode::CreateOrOpen {
                paths.prepare_data_dir_entry()?;
            }
            let data_dir = open_data_dir(paths, mode)?;
            let (file, lock_name) = open_lock_file_at(paths, &data_dir, mode)?;
            validate_open_lock(paths, &data_dir, &file, &lock_name)?;

            // SAFETY: flock accepts a live file descriptor. LOCK_NB makes startup bounded;
            // the owned fd remains live until guard drop.
            let result = unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            };
            if result != 0 {
                let source = io::Error::last_os_error();
                if source.kind() == io::ErrorKind::WouldBlock {
                    return Err(SingletonError::AlreadyRunning {
                        path: paths.lock.clone(),
                    });
                }
                return Err(SingletonError::Io {
                    operation: "acquire daemon singleton lock",
                    path: paths.lock.clone(),
                    source,
                });
            }

            // 锁定后再次同时核对 dirfd、目录路径与 dirfd 下的 lock entry；路径替换
            // 不能让 guard 锁住一个后续进程不会打开的孤立 inode。
            if let Err(error) = validate_open_lock(paths, &data_dir, &file, &lock_name) {
                // SAFETY: best-effort release of the lock just acquired on this live fd.
                unsafe {
                    libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_UN);
                }
                return Err(error);
            }
            Ok(Self {
                lock_path: paths.lock.clone(),
                file,
                data_dir,
            })
        }
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// 在后续安全边界前重新核对 retained dirfd、当前 pathname 与固定 namespace。
    ///
    /// singleton acquire 时的检查不能覆盖 daemon 长生命周期内的目录 rename/swap；
    /// listener bind 等后续入口必须在产生 typed readiness 前再次调用本方法。
    pub(crate) fn revalidate_data_dir(&self, paths: &DaemonPaths) -> Result<(), SingletonError> {
        #[cfg(not(unix))]
        {
            let _ = paths;
            Err(SingletonError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        validate_data_dir(paths, &self.data_dir)
    }

    /// 为需要 `*at` 操作的后续边界复制 retained data-dir fd。复制前后都复核
    /// pathname 与 inode，避免把路径替换窗口转交给调用方。
    pub(crate) fn clone_data_dir(&self, paths: &DaemonPaths) -> Result<File, SingletonError> {
        self.revalidate_data_dir(paths)?;
        let data_dir = self
            .data_dir
            .try_clone()
            .map_err(|source| SingletonError::Io {
                operation: "clone retained daemon data directory",
                path: paths.data_dir.clone(),
                source,
            })?;
        #[cfg(unix)]
        validate_data_dir(paths, &data_dir)?;
        Ok(data_dir)
    }
}

#[cfg(unix)]
fn open_data_dir(paths: &DaemonPaths, mode: SingletonAcquireMode) -> Result<File, SingletonError> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(paths.data_dir.as_os_str().as_bytes()).map_err(|_| {
        SingletonError::UnsafeLockFile {
            path: paths.data_dir.clone(),
            reason: "data directory path contains NUL",
        }
    })?;
    // SAFETY: path is NUL-terminated; returned fd is either negative or uniquely owned below.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(SingletonError::Io {
            operation: "open daemon data directory",
            path: paths.data_dir.clone(),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: fd was returned uniquely by open and is transferred to File exactly once.
    let file = unsafe { File::from_raw_fd(fd) };
    if mode == SingletonAcquireMode::CreateOrOpen {
        harden_stable_data_dir(paths, &file)?;
    }
    validate_data_dir(paths, &file)?;
    Ok(file)
}

#[cfg(unix)]
fn harden_stable_data_dir(paths: &DaemonPaths, directory: &File) -> Result<(), SingletonError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = directory.metadata().map_err(|source| SingletonError::Io {
        operation: "inspect opened daemon data directory",
        path: paths.data_dir.clone(),
        source,
    })?;
    // SAFETY: geteuid has no preconditions and only reads process identity.
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir() || metadata.uid() != uid {
        return Err(SingletonError::UnsafeLockFile {
            path: paths.data_dir.clone(),
            reason: "data directory is not an owned real directory",
        });
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode == 0o700 {
        return Ok(());
    }
    if !paths.is_stable_namespace() || mode != 0o755 {
        return Err(SingletonError::UnsafeLockFile {
            path: paths.data_dir.clone(),
            reason: "data directory permissions are not private 0700 or exact legacy stable 0755",
        });
    }
    // 旧版 AgentDeck 曾创建 0755 Application Support 目录。只对固定 stable
    // service、已 O_NOFOLLOW 打开且属于当前 UID 的 directory fd 收紧权限；绝不
    // 对路径名 chmod，也不放宽 ephemeral namespace。
    // SAFETY: directory is a live owned directory fd; fchmod operates on that inode.
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(SingletonError::Io {
            operation: "tighten stable daemon data directory permissions",
            path: paths.data_dir.clone(),
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_data_dir(paths: &DaemonPaths, directory: &File) -> Result<(), SingletonError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let opened = directory.metadata().map_err(|source| SingletonError::Io {
        operation: "inspect opened daemon data directory",
        path: paths.data_dir.clone(),
        source,
    })?;
    let entry = fs::symlink_metadata(&paths.data_dir).map_err(|source| SingletonError::Io {
        operation: "inspect daemon data directory path",
        path: paths.data_dir.clone(),
        source,
    })?;
    // SAFETY: geteuid has no preconditions and only reads process identity.
    let uid = unsafe { libc::geteuid() };
    if !opened.file_type().is_dir()
        || entry.file_type().is_symlink()
        || !entry.file_type().is_dir()
        || opened.uid() != uid
        || entry.uid() != uid
        || opened.permissions().mode() & 0o7777 != 0o700
        || entry.permissions().mode() & 0o7777 != 0o700
        || opened.dev() != entry.dev()
        || opened.ino() != entry.ino()
    {
        return Err(SingletonError::UnsafeLockFile {
            path: paths.data_dir.clone(),
            reason: "data directory fd and path are not the same private owned directory",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn lock_name(paths: &DaemonPaths) -> Result<std::ffi::CString, SingletonError> {
    use std::os::unix::ffi::OsStrExt;

    if paths.lock.parent() != Some(paths.data_dir.as_path()) {
        return Err(SingletonError::UnsafeLockFile {
            path: paths.lock.clone(),
            reason: "lock is not an immediate child of the daemon data directory",
        });
    }
    let name = paths
        .lock
        .file_name()
        .ok_or_else(|| SingletonError::UnsafeLockFile {
            path: paths.lock.clone(),
            reason: "lock has no basename",
        })?;
    std::ffi::CString::new(name.as_bytes()).map_err(|_| SingletonError::UnsafeLockFile {
        path: paths.lock.clone(),
        reason: "lock basename contains NUL",
    })
}

#[cfg(unix)]
fn open_lock_file_at(
    paths: &DaemonPaths,
    directory: &File,
    mode: SingletonAcquireMode,
) -> Result<(File, std::ffi::CString), SingletonError> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = lock_name(paths)?;
    let base_flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if mode == SingletonAcquireMode::ExistingOnly {
        // SAFETY: validated directory/name are live; deliberately no O_CREAT/fchmod.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), base_flags) };
        if fd < 0 {
            return Err(map_open_error(&paths.lock, io::Error::last_os_error()));
        }
        // SAFETY: fd is live and transferred to File exactly once.
        return Ok((unsafe { File::from_raw_fd(fd) }, name));
    }
    // SAFETY: directory and name are live; mode is used only with O_CREAT.
    let mut fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            base_flags | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    };
    let newly_created = fd >= 0;
    if fd < 0 {
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EEXIST) {
            return Err(map_open_error(&paths.lock, source));
        }
        // SAFETY: same validated directory/name; no O_CREAT on existing entry.
        fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), base_flags) };
        if fd < 0 {
            return Err(map_open_error(&paths.lock, io::Error::last_os_error()));
        }
    }
    if newly_created {
        // A restrictive umask may remove bits; restoring exactly 0600 on the already-open
        // inode never creates a broader pre-open window because the containing dir is 0700.
        // SAFETY: fd is live and owned by this function.
        if unsafe { libc::fchmod(fd, 0o600) } != 0 {
            let source = io::Error::last_os_error();
            // SAFETY: error path still owns fd.
            unsafe { libc::close(fd) };
            return Err(SingletonError::Io {
                operation: "set daemon lock permissions",
                path: paths.lock.clone(),
                source,
            });
        }
    }
    // SAFETY: fd is live and transferred to File exactly once.
    Ok((unsafe { File::from_raw_fd(fd) }, name))
}

#[cfg(unix)]
fn map_open_error(path: &Path, source: io::Error) -> SingletonError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        SingletonError::UnsafeLockFile {
            path: path.to_path_buf(),
            reason: "symlinks are forbidden",
        }
    } else {
        SingletonError::Io {
            operation: "open daemon singleton lock",
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(unix)]
fn validate_open_lock(
    paths: &DaemonPaths,
    directory: &File,
    file: &File,
    name: &std::ffi::CStr,
) -> Result<(), SingletonError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    validate_data_dir(paths, directory)?;
    let opened = file.metadata().map_err(|source| SingletonError::Io {
        operation: "inspect opened daemon singleton lock",
        path: paths.lock.clone(),
        source,
    })?;
    let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory/name are live and entry points to writable stat storage.
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            entry.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        return Err(SingletonError::Io {
            operation: "inspect daemon singleton lock entry",
            path: paths.lock.clone(),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: successful fstatat initialized entry.
    let entry = unsafe { entry.assume_init() };
    // SAFETY: geteuid has no preconditions and only reads process identity.
    let uid = unsafe { libc::geteuid() };
    let entry_kind = entry.st_mode & libc::S_IFMT;
    if !opened.file_type().is_file()
        || entry_kind != libc::S_IFREG
        || opened.uid() != uid
        || entry.st_uid != uid
        || opened.permissions().mode() & 0o777 != 0o600
        || entry.st_mode & 0o777 != 0o600
        || opened.nlink() != 1
        || entry.st_nlink != 1
        || opened.dev() != entry.st_dev as u64
        || opened.ino() != entry.st_ino
    {
        return Err(SingletonError::UnsafeLockFile {
            path: paths.lock.clone(),
            reason: "lock fd and dirfd entry are not the same private owned regular file",
        });
    }
    Ok(())
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for SingletonGuard {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.file)
    }
}

impl Drop for SingletonGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // SAFETY: the guard owns a live fd and unlock is idempotent for this open file.
            unsafe {
                libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
            }
        }
    }
}
