//! CLI installation identity 的独立、fail-close 持久化。
//!
//! installation UUID 只用于审计、配额和幂等 owner namespace，不是认证
//! secret；本地认证信任根始终是 UDS peer credential。本模块不读 `HOME`，
//! 也不会在损坏或不安全记录上自动轮换 identity。

#![cfg(unix)]

use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use uuid::Uuid;

const RECORD_COMPONENTS: [(&str, bool); 5] = [
    ("Library", false),
    ("Application Support", false),
    ("AgentDeck", true),
    ("clients", true),
    ("cli", true),
];
const RECORD_NAME: &str = "installation-id.v1";
const RECORD_BYTES: usize = 37;

/// Canonical lowercase、non-nil installation UUID。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InstallationId(Uuid);

impl InstallationId {
    fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    fn parse(value: &str) -> Option<Self> {
        let parsed = Uuid::parse_str(value).ok()?;
        (!parsed.is_nil() && parsed.hyphenated().to_string() == value).then_some(Self(parsed))
    }

    #[must_use]
    pub fn as_uuid(self) -> Uuid {
        self.0
    }

    /// 仅用于显式注入的 dev/test endpoint。stable 路径必须从 store 读回。
    #[doc(hidden)]
    pub fn random_for_test() -> Self {
        Self::generate()
    }
}

impl std::fmt::Display for InstallationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

/// installation record 打开/创建失败。
#[derive(Debug, thiserror::Error)]
pub enum InstallationError {
    #[error("getpwuid_r failed with status {status}")]
    HomeLookup { status: i32 },
    #[error("the current OS account has no absolute home directory")]
    HomeUnavailable,
    #[error("unsafe installation directory {path}: {reason}")]
    UnsafeDirectory { path: PathBuf, reason: &'static str },
    #[error("unsafe installation record {path}: {reason}")]
    UnsafeRecord { path: PathBuf, reason: &'static str },
    #[error("corrupt installation record {path}")]
    CorruptRecord { path: PathBuf },
    #[error("atomic no-replace publication is unsupported on this platform")]
    NoReplaceUnsupported,
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl InstallationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::HomeLookup { .. } | Self::HomeUnavailable => {
                "daemon.client.installation_home_failed"
            }
            Self::UnsafeDirectory { .. } => "daemon.client.installation_parent_unsafe",
            Self::UnsafeRecord { .. } => "daemon.client.installation_record_unsafe",
            Self::CorruptRecord { .. } => "daemon.client.installation_record_corrupt",
            Self::NoReplaceUnsupported => "daemon.client.installation_publish_unsupported",
            Self::Io { .. } => "daemon.client.installation_io_failed",
        }
    }
}

/// CLI 自有 installation store。生产构造器只从当前 EUID 的 passwd record 取 home。
#[derive(Clone, Debug)]
pub struct CliInstallationStore {
    home: PathBuf,
    uid: libc::uid_t,
}

impl CliInstallationStore {
    pub fn for_os_account() -> Result<Self, InstallationError> {
        let (home, uid) = os_account_home()?;
        Ok(Self { home, uid })
    }

    /// 仅供测试/harness 显式注入隔离 home；生产 default 不读环境覆盖。
    #[doc(hidden)]
    pub fn injected_for_test(home: PathBuf) -> Self {
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::geteuid() };
        Self { home, uid }
    }

    #[must_use]
    pub fn record_path(&self) -> PathBuf {
        record_path(&self.home)
    }

    pub fn record_path_for_os_account() -> Result<PathBuf, InstallationError> {
        Ok(Self::for_os_account()?.record_path())
    }

    /// stable daemon install layout 与 CLI identity 共用同一 passwd-derived home。
    /// 不读取 `HOME`，也不提供 production runtime override。
    #[doc(hidden)]
    pub fn os_account_home_path() -> Result<PathBuf, InstallationError> {
        Ok(Self::for_os_account()?.home)
    }

    /// 以 retained dirfd + `O_NOFOLLOW` 创建/验证 daemon version dir 与 LaunchAgents。
    /// `version` 必须已由调用方验证为单一安全 path component。
    #[doc(hidden)]
    pub fn prepare_daemon_install_directories(
        &self,
        version: &str,
    ) -> Result<(), InstallationError> {
        let home = open_directory(&self.home, self.uid, false)?;
        let library_path = self.home.join("Library");
        let library =
            open_or_create_directory_at(&home, "Library", &library_path, self.uid, false)?;
        let support_path = library_path.join("Application Support");
        let support = open_or_create_directory_at(
            &library,
            "Application Support",
            &support_path,
            self.uid,
            false,
        )?;
        let data_path = support_path.join("AgentDeck");
        let data = open_or_create_directory_at(&support, "AgentDeck", &data_path, self.uid, false)?;
        let bin_path = data_path.join("bin");
        let bin = open_or_create_directory_at(&data, "bin", &bin_path, self.uid, true)?;
        open_or_create_directory_at(&bin, version, &bin_path.join(version), self.uid, true)?;
        open_or_create_directory_at(
            &library,
            "LaunchAgents",
            &library_path.join("LaunchAgents"),
            self.uid,
            true,
        )?;
        Ok(())
    }

    #[must_use]
    pub fn daemon_socket_path(&self) -> PathBuf {
        self.home
            .join("Library")
            .join("Application Support")
            .join("AgentDeck")
            .join("agentdeckd.sock")
    }

    /// 读回或首次原子创建。任何已存在的损坏/异常 entry 都直接拒绝，不改写。
    pub fn load_or_create(&self) -> Result<InstallationId, InstallationError> {
        if !self.home.is_absolute() {
            return Err(InstallationError::HomeUnavailable);
        }
        let (directory, directory_path) = self.open_record_directory()?;
        if let Some(existing) = read_record(&directory, &directory_path, self.uid)? {
            return Ok(existing);
        }
        create_record(&directory, &directory_path, self.uid)
    }

    fn open_record_directory(&self) -> Result<(File, PathBuf), InstallationError> {
        let mut directory = open_directory(&self.home, self.uid, false)?;
        let mut path = self.home.clone();
        for (component, private) in RECORD_COMPONENTS {
            path.push(component);
            directory =
                open_or_create_directory_at(&directory, component, &path, self.uid, private)?;
        }
        Ok((directory, path))
    }
}

fn record_path(home: &Path) -> PathBuf {
    RECORD_COMPONENTS
        .iter()
        .fold(home.to_path_buf(), |path, (component, _)| {
            path.join(component)
        })
        .join(RECORD_NAME)
}

fn os_account_home() -> Result<(PathBuf, libc::uid_t), InstallationError> {
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: sysconf only reads a process-global limit.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut capacity = if suggested > 0 {
        usize::try_from(suggested).unwrap_or(16 * 1024)
    } else {
        16 * 1024
    }
    .clamp(1024, 1024 * 1024);

    loop {
        let mut record = MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; capacity];
        // SAFETY: record, buffer and result are valid writable storage. Returned pointers
        // are consumed before buffer is dropped.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && capacity < 1024 * 1024 {
            capacity = (capacity * 2).min(1024 * 1024);
            continue;
        }
        if status != 0 {
            return Err(InstallationError::HomeLookup { status });
        }
        if result.is_null() {
            return Err(InstallationError::HomeUnavailable);
        }
        // SAFETY: successful getpwuid_r initialized record; pw_dir points into buffer.
        let record = unsafe { record.assume_init() };
        if record.pw_dir.is_null() {
            return Err(InstallationError::HomeUnavailable);
        }
        // SAFETY: pw_dir is a NUL-terminated C string owned by buffer in this scope.
        let bytes = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
        if bytes.is_empty() {
            return Err(InstallationError::HomeUnavailable);
        }
        let home = PathBuf::from(OsString::from_vec(bytes.to_vec()));
        if !home.is_absolute() {
            return Err(InstallationError::HomeUnavailable);
        }
        return Ok((home, uid));
    }
}

fn open_directory(path: &Path, uid: libc::uid_t, private: bool) -> Result<File, InstallationError> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io("open installation directory", path, source))?;
    validate_directory(&file, path, uid, private)?;
    Ok(file)
}

fn open_or_create_directory_at(
    parent: &File,
    component: &str,
    path: &Path,
    uid: libc::uid_t,
    private: bool,
) -> Result<File, InstallationError> {
    let name = c_string(component, path)?;
    // SAFETY: parent is a retained directory fd; name is a valid NUL-terminated basename.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0;
    if !created {
        let source = std::io::Error::last_os_error();
        if source.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(io("create installation directory", path, source));
        }
    } else {
        parent
            .sync_all()
            .map_err(|source| io("sync installation directory parent", path, source))?;
    }
    // SAFETY: flags request an owned, no-follow directory descriptor under retained parent.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io(
            "open installation directory component",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful openat returned a newly owned fd.
    let directory = unsafe { File::from_raw_fd(fd) };
    validate_directory(&directory, path, uid, private)?;
    Ok(directory)
}

fn validate_directory(
    directory: &File,
    path: &Path,
    uid: libc::uid_t,
    private: bool,
) -> Result<(), InstallationError> {
    let stat = fstat(directory.as_raw_fd(), "stat installation directory", path)?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(unsafe_directory(path, "entry is not a directory"));
    }
    if stat.st_uid != uid {
        return Err(unsafe_directory(
            path,
            "directory owner is not current EUID",
        ));
    }
    if private && (stat.st_mode & 0o7777) != 0o700 {
        return Err(unsafe_directory(path, "directory mode is not exactly 0700"));
    }
    Ok(())
}

fn read_record(
    directory: &File,
    directory_path: &Path,
    uid: libc::uid_t,
) -> Result<Option<InstallationId>, InstallationError> {
    let path = directory_path.join(RECORD_NAME);
    let name = c_string(RECORD_NAME, &path)?;
    // SAFETY: retained directory fd + fixed basename; O_NOFOLLOW refuses symlinks.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let source = std::io::Error::last_os_error();
        if source.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        if source.raw_os_error() == Some(libc::ELOOP) {
            return Err(InstallationError::UnsafeRecord {
                path,
                reason: "record is a symlink",
            });
        }
        return Err(io("open installation record", &path, source));
    }
    // SAFETY: successful openat returned a newly owned fd.
    let mut file = unsafe { File::from_raw_fd(fd) };
    validate_record_file(&file, &path, uid)?;
    let mut bytes = Vec::with_capacity(RECORD_BYTES + 1);
    Read::by_ref(&mut file)
        .take((RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| io("read installation record", &path, source))?;
    if bytes.len() != RECORD_BYTES || bytes.last() != Some(&b'\n') {
        return Err(InstallationError::CorruptRecord { path });
    }
    let text = std::str::from_utf8(&bytes[..RECORD_BYTES - 1])
        .ok()
        .and_then(InstallationId::parse)
        .ok_or_else(|| InstallationError::CorruptRecord { path: path.clone() })?;
    Ok(Some(text))
}

fn validate_record_file(
    file: &File,
    path: &Path,
    uid: libc::uid_t,
) -> Result<(), InstallationError> {
    let stat = fstat(file.as_raw_fd(), "stat installation record", path)?;
    let reason = if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        Some("record is not a regular file")
    } else if stat.st_uid != uid {
        Some("record owner is not current EUID")
    } else if (stat.st_mode & 0o7777) != 0o600 {
        Some("record mode is not exactly 0600")
    } else if stat.st_nlink != 1 {
        Some("record must have exactly one hard link")
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| {
        Err(InstallationError::UnsafeRecord {
            path: path.to_path_buf(),
            reason,
        })
    })
}

fn create_record(
    directory: &File,
    directory_path: &Path,
    uid: libc::uid_t,
) -> Result<InstallationId, InstallationError> {
    let candidate = InstallationId::generate();
    let content = format!("{candidate}\n");
    let temp_name = format!(".installation-id.v1.{}.tmp", Uuid::new_v4());
    let temp_path = directory_path.join(&temp_name);
    let name = c_string(&temp_name, &temp_path)?;
    // SAFETY: retained private dirfd, fresh random basename, no-follow exclusive create.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io(
            "create installation record temp",
            &temp_path,
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful openat returned a newly owned fd.
    let mut temp = unsafe { File::from_raw_fd(fd) };
    let mut guard = TempEntry::new(directory.as_raw_fd(), name, temp_path.clone());
    validate_record_file(&temp, &temp_path, uid)?;
    temp.write_all(content.as_bytes())
        .map_err(|source| io("write installation record temp", &temp_path, source))?;
    temp.sync_all()
        .map_err(|source| io("sync installation record temp", &temp_path, source))?;
    temp.seek(SeekFrom::Start(0))
        .map_err(|source| io("rewind installation record temp", &temp_path, source))?;
    let mut readback = String::new();
    temp.read_to_string(&mut readback)
        .map_err(|source| io("read back installation record temp", &temp_path, source))?;
    if readback != content {
        return Err(InstallationError::CorruptRecord { path: temp_path });
    }
    validate_record_file(&temp, guard.path(), uid)?;

    let final_path = directory_path.join(RECORD_NAME);
    match rename_no_replace(directory.as_raw_fd(), guard.name(), &final_path)? {
        PublishOutcome::Published => {
            guard.disarm();
            directory
                .sync_all()
                .map_err(|source| io("sync installation record parent", directory_path, source))?;
            read_record(directory, directory_path, uid)?.ok_or_else(|| {
                InstallationError::CorruptRecord {
                    path: final_path.clone(),
                }
            })
        }
        PublishOutcome::LostRace => {
            guard.remove_now();
            directory
                .sync_all()
                .map_err(|source| io("sync installation race cleanup", directory_path, source))?;
            read_record(directory, directory_path, uid)?.ok_or_else(|| {
                InstallationError::CorruptRecord {
                    path: final_path.clone(),
                }
            })
        }
    }
}

enum PublishOutcome {
    Published,
    LostRace,
}

fn rename_no_replace(
    directory_fd: RawFd,
    source: &CStr,
    target_path: &Path,
) -> Result<PublishOutcome, InstallationError> {
    let target = c_string(RECORD_NAME, target_path)?;
    #[cfg(target_os = "macos")]
    // SAFETY: both basenames are NUL-terminated and resolved beneath the same retained dirfd.
    let result = unsafe {
        libc::renameatx_np(
            directory_fd,
            source.as_ptr(),
            directory_fd,
            target.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(target_os = "linux")]
    // SAFETY: both basenames are NUL-terminated and resolved beneath the same retained dirfd.
    let result = unsafe {
        libc::renameat2(
            directory_fd,
            source.as_ptr(),
            directory_fd,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err(InstallationError::NoReplaceUnsupported);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if result == 0 {
        Ok(PublishOutcome::Published)
    } else {
        let source = std::io::Error::last_os_error();
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(PublishOutcome::LostRace)
        } else {
            Err(io("publish installation record", target_path, source))
        }
    }
}

struct TempEntry {
    directory_fd: RawFd,
    name: CString,
    path: PathBuf,
    active: bool,
}

impl TempEntry {
    fn new(directory_fd: RawFd, name: CString, path: PathBuf) -> Self {
        Self {
            directory_fd,
            name,
            path,
            active: true,
        }
    }

    fn name(&self) -> &CStr {
        &self.name
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.active = false;
    }

    fn remove_now(&mut self) {
        if self.active {
            // SAFETY: dirfd outlives guard and name is the exact temp basename; unlinkat does
            // not follow symlinks.
            let _ = unsafe { libc::unlinkat(self.directory_fd, self.name.as_ptr(), 0) };
            self.active = false;
        }
    }
}

impl Drop for TempEntry {
    fn drop(&mut self) {
        self.remove_now();
    }
}

fn fstat(fd: RawFd, operation: &'static str, path: &Path) -> Result<libc::stat, InstallationError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage and fd is retained by caller.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io(operation, path, std::io::Error::last_os_error()));
    }
    // SAFETY: successful fstat initialized stat.
    Ok(unsafe { stat.assume_init() })
}

fn c_string(value: &str, path: &Path) -> Result<CString, InstallationError> {
    CString::new(value).map_err(|_| InstallationError::UnsafeRecord {
        path: path.to_path_buf(),
        reason: "path component contains NUL",
    })
}

fn unsafe_directory(path: &Path, reason: &'static str) -> InstallationError {
    InstallationError::UnsafeDirectory {
        path: path.to_path_buf(),
        reason,
    }
}

fn io(operation: &'static str, path: &Path, source: std::io::Error) -> InstallationError {
    InstallationError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn record_owner_mismatch_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = CliInstallationStore::injected_for_test(root.path().to_path_buf());
        store.load_or_create().unwrap();
        let file = std::fs::File::open(store.record_path()).unwrap();
        // No privilege-dependent chown: validate the real inode against a deliberately wrong
        // expected uid to exercise the exact owner branch.
        let wrong_uid = store.uid.wrapping_add(1);
        let error = validate_record_file(&file, &store.record_path(), wrong_uid).unwrap_err();
        assert!(matches!(error, InstallationError::UnsafeRecord { .. }));
    }
}
