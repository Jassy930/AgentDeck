//! Persistent remote device 的跨进程独占 lease。
//!
//! 同一 installation / machine identity 在任一时刻只能有一个 active runtime。
//! 锁只保存为无内容的私有文件；identity 仅参与带域哈希，不写入文件名或文件内容。

#![cfg(unix)]

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use agentdeck_protocol::relay_v2::MachineRouteId;
use agentdeck_protocol::runtime::MachineRootFingerprint;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DEVICE_DIRECTORY: &str = "devices";
const LOCK_HASH_DOMAIN: &[u8] = b"agentdeck.remote.device-lock.v1\0";

/// 一条 persistent remote device lease 的完整 identity。
#[derive(Clone, Copy)]
pub struct RemoteDeviceLockKey {
    installation_id: Uuid,
    machine_root_fingerprint: MachineRootFingerprint,
    machine_route: MachineRouteId,
}

impl RemoteDeviceLockKey {
    #[must_use]
    pub const fn new(
        installation_id: Uuid,
        machine_root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
    ) -> Self {
        Self {
            installation_id,
            machine_root_fingerprint,
            machine_route,
        }
    }

    fn installation_component(&self) -> String {
        self.installation_id.hyphenated().to_string()
    }

    fn lock_component(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(LOCK_HASH_DOMAIN);
        hasher.update(self.installation_id.as_bytes());
        hasher.update(self.machine_root_fingerprint.as_bytes());
        hasher.update(self.machine_route.as_bytes());
        let digest = hasher.finalize();
        let mut component = String::with_capacity(digest.len() * 2 + ".lock".len());
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut component, "{byte:02x}").expect("writing to String cannot fail");
        }
        component.push_str(".lock");
        component
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteDeviceLockError {
    #[error("remote device is already active for lock {path}")]
    AlreadyInUse { path: PathBuf },
    #[error("unsafe remote device lock directory {path}: {reason}")]
    UnsafeDirectory { path: PathBuf, reason: &'static str },
    #[error("unsafe remote device lock file {path}: {reason}")]
    UnsafeLockFile { path: PathBuf, reason: &'static str },
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl RemoteDeviceLockError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AlreadyInUse { .. } => "remote.device.already_in_use",
            Self::UnsafeDirectory { .. } => "remote.device.lock_directory_unsafe",
            Self::UnsafeLockFile { .. } => "remote.device.lock_file_unsafe",
            Self::Io { .. } => "remote.device.lock_io_failed",
        }
    }
}

/// 持有底层 `flock` fd 的唯一 lease；故意不实现 `Clone`。
///
/// 最终 `RemoteMachineRuntime` 必须让本值晚于 Relay connection 与 counter allocator
/// 销毁，确保另一个进程不能在旧 owner 仍可分配 counter 时进入。
pub struct RemoteDeviceLease {
    lock_path: PathBuf,
    lock_file: File,
    // 固定已验证的目录 inode，避免 lease 生命周期内退化为 path-only 锁。
    _directories: [File; 3],
}

impl std::fmt::Debug for RemoteDeviceLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteDeviceLease")
            .field("lock_path", &self.lock_path)
            .finish_non_exhaustive()
    }
}

impl RemoteDeviceLease {
    /// 在显式 state root 下取得 nonblocking device lease。
    ///
    /// `root` 是 library/test harness 的依赖注入边界；production caller 后续必须从
    /// passwd-derived AgentDeck state root 构造，不能使用环境变量或 CLI data-dir。
    pub fn acquire_in(
        root: &Path,
        key: RemoteDeviceLockKey,
    ) -> Result<Self, RemoteDeviceLockError> {
        if !root.is_absolute() {
            return Err(unsafe_directory(root, "lock root is not absolute"));
        }
        let uid = current_euid();
        let root_dir = open_or_create_root_without_symlinks(root, uid)?;

        let installation_component = key.installation_component();
        let installation_path = root.join(&installation_component);
        let installation_dir = open_or_create_directory_at(
            &root_dir,
            OsStr::new(&installation_component),
            &installation_path,
            uid,
        )?;

        let devices_path = installation_path.join(DEVICE_DIRECTORY);
        let devices_dir = open_or_create_directory_at(
            &installation_dir,
            OsStr::new(DEVICE_DIRECTORY),
            &devices_path,
            uid,
        )?;

        let lock_component = key.lock_component();
        let lock_path = devices_path.join(&lock_component);
        let lock_file = open_lock_file_at(&devices_dir, &lock_component, &lock_path, uid)?;
        validate_lock_entry(&devices_dir, &lock_component, &lock_path, &lock_file, uid)?;

        // SAFETY: flock receives a live owned fd; LOCK_NB keeps contention bounded.
        let result = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::WouldBlock {
                return Err(RemoteDeviceLockError::AlreadyInUse { path: lock_path });
            }
            return Err(io_error("acquire remote device lock", &lock_path, source));
        }

        // 锁后复核所有 retained fd 与目录 entry。失败时显式解锁，再由 File drop 关 fd。
        let post_lock = validate_directory(&root_dir, root, uid)
            .and_then(|()| validate_directory(&installation_dir, &installation_path, uid))
            .and_then(|()| validate_directory(&devices_dir, &devices_path, uid))
            .and_then(|()| {
                validate_lock_entry(&devices_dir, &lock_component, &lock_path, &lock_file, uid)
            });
        if let Err(error) = post_lock {
            // SAFETY: best-effort unlock of the live fd acquired above.
            unsafe {
                libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN);
            }
            return Err(error);
        }

        Ok(Self {
            lock_path,
            lock_file,
            _directories: [root_dir, installation_dir, devices_dir],
        })
    }

    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

impl AsRawFd for RemoteDeviceLease {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.lock_file.as_raw_fd()
    }
}

fn open_or_create_root_without_symlinks(
    path: &Path,
    uid: libc::uid_t,
) -> Result<File, RemoteDeviceLockError> {
    let components = absolute_normal_components(path)?;
    let root_name = CString::new("/").expect("root path has no NUL");
    // SAFETY: root_name is a valid absolute directory path; returned fd is owned below.
    let fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error(
            "open filesystem root for remote device lock",
            Path::new("/"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful open returned a uniquely owned descriptor.
    let mut directory = unsafe { File::from_raw_fd(fd) };
    let mut traversed = PathBuf::from("/");
    for (index, component) in components.iter().enumerate() {
        traversed.push(component);
        if index + 1 == components.len() {
            return open_or_create_directory_at(&directory, component, &traversed, uid);
        }
        directory = open_existing_directory_at(&directory, component, &traversed)?;
    }
    unreachable!("absolute lock root has at least one normal component")
}

fn absolute_normal_components(path: &Path) -> Result<Vec<OsString>, RemoteDeviceLockError> {
    if !path.is_absolute() {
        return Err(unsafe_directory(path, "lock root is not absolute"));
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(component) => components.push(component.to_os_string()),
            Component::ParentDir => {
                return Err(unsafe_directory(
                    path,
                    "lock root contains a parent traversal",
                ));
            }
            Component::Prefix(_) => {
                return Err(unsafe_directory(
                    path,
                    "lock root has an unsupported prefix",
                ));
            }
        }
    }
    if components.is_empty() {
        return Err(unsafe_directory(
            path,
            "filesystem root cannot be a device lock root",
        ));
    }
    Ok(components)
}

fn open_existing_directory_at(
    parent: &File,
    component: &OsStr,
    path: &Path,
) -> Result<File, RemoteDeviceLockError> {
    let component = os_component_c_string(component, path)?;
    // SAFETY: retained parent fd + NUL-free basename; O_NOFOLLOW rejects an ancestor symlink.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let source = io::Error::last_os_error();
        return Err(if source.raw_os_error() == Some(libc::ELOOP) {
            unsafe_directory(path, "lock root ancestor is a symlink")
        } else {
            io_error("open remote device lock root ancestor", path, source)
        });
    }
    // SAFETY: successful openat returned a uniquely owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    validate_directory_entry(parent, &component, path, &directory)?;
    Ok(directory)
}

fn open_or_create_directory_at(
    parent: &File,
    component: &OsStr,
    path: &Path,
    uid: libc::uid_t,
) -> Result<File, RemoteDeviceLockError> {
    let component = os_component_c_string(component, path)?;
    // SAFETY: parent is a retained directory fd; component is a NUL-free basename.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) } == 0;
    if !created {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(io_error(
                "create remote device lock directory",
                path,
                source,
            ));
        }
    } else {
        set_created_mode_at(
            parent,
            &component,
            path,
            0o700,
            "set fresh remote device lock directory mode",
        )?;
    }

    // SAFETY: openat returns a new owned fd or a negative error; O_NOFOLLOW rejects symlinks.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error(
            "open remote device lock directory component",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful openat returned one uniquely owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    if created {
        set_created_mode(
            &directory,
            path,
            0o700,
            "set remote device lock directory mode",
        )?;
        directory
            .sync_all()
            .map_err(|source| io_error("sync remote device lock directory", path, source))?;
        parent
            .sync_all()
            .map_err(|source| io_error("sync remote device lock directory parent", path, source))?;
    }
    validate_directory_entry(parent, &component, path, &directory)?;
    validate_directory(&directory, path, uid)?;
    Ok(directory)
}

fn open_lock_file_at(
    directory: &File,
    component: &str,
    path: &Path,
    uid: libc::uid_t,
) -> Result<File, RemoteDeviceLockError> {
    let component = component_c_string(component, path)?;
    // Exclusive create lets us distinguish a fresh 0600 inode from an existing entry.
    // SAFETY: retained directory fd + NUL-free basename; returned fd is owned below.
    let mut fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
    };
    let created = fd >= 0;
    if fd < 0 {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(lock_open_error(path, source));
        }
        // SAFETY: same retained parent and fixed basename; no create and no symlink follow.
        fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(lock_open_error(path, io::Error::last_os_error()));
        }
    }
    // SAFETY: successful openat returned one uniquely owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    if created {
        set_created_mode(&file, path, 0o600, "set remote device lock file mode")?;
        file.sync_all()
            .map_err(|source| io_error("sync remote device lock file", path, source))?;
    }
    validate_lock_entry(
        directory,
        component.to_str().unwrap_or_default(),
        path,
        &file,
        uid,
    )?;
    if created {
        directory
            .sync_all()
            .map_err(|source| io_error("sync remote device lock parent", path, source))?;
    }
    Ok(file)
}

fn validate_directory(
    directory: &File,
    path: &Path,
    uid: libc::uid_t,
) -> Result<(), RemoteDeviceLockError> {
    let stat = descriptor_stat(directory, "stat remote device lock directory", path)?;
    let reason = if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        Some("entry is not a directory")
    } else if stat.st_uid != uid {
        Some("directory owner is not current EUID")
    } else if (stat.st_mode & 0o7777) != 0o700 {
        Some("directory mode is not exactly 0700")
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| Err(unsafe_directory(path, reason)))
}

fn validate_directory_entry(
    parent: &File,
    component: &CString,
    path: &Path,
    directory: &File,
) -> Result<(), RemoteDeviceLockError> {
    let descriptor = descriptor_stat(directory, "stat opened remote device lock directory", path)?;
    if (descriptor.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(unsafe_directory(path, "opened entry is not a directory"));
    }

    let mut entry = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: entry points to writable stat storage; parent/component are live and valid.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            component.as_ptr(),
            entry.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io_error(
            "stat remote device lock directory entry",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful fstatat initialized entry.
    let entry = unsafe { entry.assume_init() };
    if (entry.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(unsafe_directory(
            path,
            "directory entry is not a no-follow directory",
        ));
    }
    if descriptor.st_dev != entry.st_dev || descriptor.st_ino != entry.st_ino {
        return Err(unsafe_directory(
            path,
            "opened directory inode does not match parent entry",
        ));
    }
    Ok(())
}

fn validate_lock_entry(
    directory: &File,
    component: &str,
    path: &Path,
    file: &File,
    uid: libc::uid_t,
) -> Result<(), RemoteDeviceLockError> {
    let descriptor = descriptor_stat(file, "stat remote device lock file", path)?;
    validate_lock_stat(&descriptor, path, uid)?;

    let component = component_c_string(component, path)?;
    let mut entry = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: entry points to writable stat storage; parent/component are live and valid.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            component.as_ptr(),
            entry.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io_error(
            "stat remote device lock directory entry",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful fstatat initialized entry.
    let entry = unsafe { entry.assume_init() };
    validate_lock_stat(&entry, path, uid)?;
    if descriptor.st_dev != entry.st_dev || descriptor.st_ino != entry.st_ino {
        return Err(RemoteDeviceLockError::UnsafeLockFile {
            path: path.to_path_buf(),
            reason: "opened lock inode does not match directory entry",
        });
    }
    Ok(())
}

fn validate_lock_stat(
    stat: &libc::stat,
    path: &Path,
    uid: libc::uid_t,
) -> Result<(), RemoteDeviceLockError> {
    let reason = if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        Some("entry is not a regular file")
    } else if stat.st_uid != uid {
        Some("lock owner is not current EUID")
    } else if (stat.st_mode & 0o7777) != 0o600 {
        Some("lock mode is not exactly 0600")
    } else if stat.st_nlink != 1 {
        Some("lock must have exactly one hard link")
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| {
        Err(RemoteDeviceLockError::UnsafeLockFile {
            path: path.to_path_buf(),
            reason,
        })
    })
}

fn descriptor_stat(
    file: &File,
    operation: &'static str,
    path: &Path,
) -> Result<libc::stat, RemoteDeviceLockError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage and file owns a live descriptor.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io_error(operation, path, io::Error::last_os_error()));
    }
    // SAFETY: successful fstat initialized stat.
    Ok(unsafe { stat.assume_init() })
}

fn component_c_string(component: &str, path: &Path) -> Result<CString, RemoteDeviceLockError> {
    CString::new(component).map_err(|_| RemoteDeviceLockError::UnsafeLockFile {
        path: path.to_path_buf(),
        reason: "lock component contains NUL",
    })
}

fn os_component_c_string(component: &OsStr, path: &Path) -> Result<CString, RemoteDeviceLockError> {
    CString::new(component.as_bytes())
        .map_err(|_| unsafe_directory(path, "lock directory component contains NUL"))
}

fn set_created_mode(
    file: &File,
    path: &Path,
    mode: libc::mode_t,
    operation: &'static str,
) -> Result<(), RemoteDeviceLockError> {
    // SAFETY: fchmod mutates only the freshly-created inode owned by this live fd.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(io_error(operation, path, io::Error::last_os_error()));
    }
    Ok(())
}

fn set_created_mode_at(
    parent: &File,
    component: &CString,
    path: &Path,
    mode: libc::mode_t,
    operation: &'static str,
) -> Result<(), RemoteDeviceLockError> {
    // A restrictive umask can create a directory with mode 000, which cannot be opened for
    // fchmod. This path is used only immediately after our successful mkdirat under the retained
    // parent; existing entries are never repaired.
    // SAFETY: parent/component identify the freshly-created directory entry above.
    if unsafe { libc::fchmodat(parent.as_raw_fd(), component.as_ptr(), mode, 0) } != 0 {
        return Err(io_error(operation, path, io::Error::last_os_error()));
    }
    Ok(())
}

fn lock_open_error(path: &Path, source: io::Error) -> RemoteDeviceLockError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        RemoteDeviceLockError::UnsafeLockFile {
            path: path.to_path_buf(),
            reason: "lock entry is a symlink",
        }
    } else {
        io_error("open remote device lock file", path, source)
    }
}

fn current_euid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    unsafe { libc::geteuid() }
}

fn unsafe_directory(path: &Path, reason: &'static str) -> RemoteDeviceLockError {
    RemoteDeviceLockError::UnsafeDirectory {
        path: path.to_path_buf(),
        reason,
    }
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> RemoteDeviceLockError {
    RemoteDeviceLockError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
