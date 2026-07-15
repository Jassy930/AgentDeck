//! daemon 的稳定/临时资源命名空间。
//!
//! 这里仅负责决定路径与建立私有数据目录；任何会打开 Runtime DB、绑定 UDS
//! 或访问 Keychain 的代码都必须使用同一个 [`DaemonPaths`]，避免测试实例误碰
//! stable 数据或信任材料。

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// stable daemon 的 Keychain service。account 由上层安全模块进一步细分。
pub const STABLE_KEYCHAIN_SERVICE: &str = "com.agentdeck.agentdeckd.stable";

/// `sockaddr_un.sun_path` 可容纳的最大路径字节数（不含末尾 NUL）。
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const UNIX_SOCKET_PATH_MAX_BYTES: usize = 103;
#[cfg(target_os = "linux")]
pub const UNIX_SOCKET_PATH_MAX_BYTES: usize = 107;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
pub const UNIX_SOCKET_PATH_MAX_BYTES: usize = 103;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonMode {
    Stable,
    Ephemeral { instance_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonPaths {
    pub data_dir: PathBuf,
    pub runtime_db: PathBuf,
    pub socket: PathBuf,
    pub lock: PathBuf,
    pub keychain_service: String,
    pub keychain_access_group: Option<String>,
    /// 防止调用方仅伪造公开 service/path 字符串就获得 stable 迁移权限。
    namespace_kind: DaemonNamespaceKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonNamespaceKind {
    Stable,
    Ephemeral,
}

#[derive(Debug)]
pub enum NamespaceError {
    RootNotAbsolute {
        path: PathBuf,
    },
    InvalidInstanceId,
    SocketPathTooLong {
        path: PathBuf,
        actual_bytes: usize,
        max_bytes: usize,
    },
    SocketPathContainsNul {
        path: PathBuf,
    },
    UnsafeTempRoot {
        path: PathBuf,
        reason: &'static str,
    },
    UnsafeDataDirectory {
        path: PathBuf,
        reason: &'static str,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootNotAbsolute { path } => {
                write!(
                    formatter,
                    "daemon namespace root {} is not absolute",
                    path.display()
                )
            }
            Self::InvalidInstanceId => formatter.write_str(
                "ephemeral instance id must be 1..=64 ASCII letters, digits, '-' or '_'",
            ),
            Self::SocketPathTooLong {
                path,
                actual_bytes,
                max_bytes,
            } => write!(
                formatter,
                "daemon socket path {} is {actual_bytes} bytes; maximum is {max_bytes}",
                path.display()
            ),
            Self::SocketPathContainsNul { path } => {
                write!(
                    formatter,
                    "daemon socket path {} contains NUL",
                    path.display()
                )
            }
            Self::UnsafeTempRoot { path, reason } => {
                write!(
                    formatter,
                    "unsafe ephemeral temp root {}: {reason}",
                    path.display()
                )
            }
            Self::UnsafeDataDirectory { path, reason } => {
                write!(
                    formatter,
                    "unsafe daemon data directory {}: {reason}",
                    path.display()
                )
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for NamespaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl NamespaceError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RootNotAbsolute { .. } => "daemon.namespace.root_not_absolute",
            Self::InvalidInstanceId => "daemon.namespace.invalid_instance",
            Self::SocketPathTooLong { .. } => "daemon.namespace.socket_path_too_long",
            Self::SocketPathContainsNul { .. } => "daemon.namespace.socket_path_invalid",
            Self::UnsafeTempRoot { .. } => "daemon.namespace.unsafe_temp_root",
            Self::UnsafeDataDirectory { .. } => "daemon.namespace.unsafe_data_directory",
            Self::Io { .. } => "daemon.namespace.io_failed",
        }
    }
}

impl DaemonPaths {
    /// 构造唯一生产 daemon 的固定路径。`home` 是当前登录用户的 home，而不是
    /// 任意 data-dir override；P3 stable ownership 不允许改名规避 singleton。
    pub fn stable(
        home: impl AsRef<Path>,
        keychain_access_group: Option<String>,
    ) -> Result<Self, NamespaceError> {
        if !home.as_ref().is_absolute() {
            return Err(NamespaceError::RootNotAbsolute {
                path: home.as_ref().to_path_buf(),
            });
        }
        let data_dir = home
            .as_ref()
            .join("Library")
            .join("Application Support")
            .join("AgentDeck");
        let paths = Self {
            runtime_db: data_dir.join("runtime.db"),
            socket: data_dir.join("agentdeckd.sock"),
            lock: data_dir.join("agentdeckd.lock"),
            data_dir,
            keychain_service: STABLE_KEYCHAIN_SERVICE.to_owned(),
            keychain_access_group,
            namespace_kind: DaemonNamespaceKind::Stable,
        };
        paths.validate_socket_path()?;
        Ok(paths)
    }

    /// 生成测试专用 namespace。instance id 同时进入 data root、DB、socket、lock
    /// 和 Keychain service，便于从任一资源名审计隔离是否完整。
    pub fn ephemeral_with_instance_id(
        temp_root: impl AsRef<Path>,
        instance_id: &str,
    ) -> Result<Self, NamespaceError> {
        if !temp_root.as_ref().is_absolute() {
            return Err(NamespaceError::RootNotAbsolute {
                path: temp_root.as_ref().to_path_buf(),
            });
        }
        validate_instance_id(instance_id)?;
        // 先在调用方提供的字节路径上执行内核 path-shape 校验。这样恶意 NUL 或
        // 超长 sun_path 不会被后续 metadata/canonicalize 折叠成泛化 I/O 错误。
        let untrusted_paths = Self::ephemeral_from_root(temp_root.as_ref(), instance_id);
        untrusted_paths.validate_socket_path()?;

        // 威胁场景：环境可控的 TMPDIR 指向 symlink、共享目录或其他用户目录时，
        // daemon 会在攻击者可替换的父目录下创建 DB、lock 与控制 socket。
        let canonical_temp_root = canonical_private_temp_root(temp_root.as_ref())?;
        let paths = Self::ephemeral_from_root(&canonical_temp_root, instance_id);
        // canonical path 可能比输入路径更长，最终交给 bind 的路径也必须独立通过。
        paths.validate_socket_path()?;
        Ok(paths)
    }

    fn ephemeral_from_root(temp_root: &Path, instance_id: &str) -> Self {
        // macOS `sun_path` 只有 104 bytes；TMPDIR 本身常已接近 50 bytes，因此
        // 临时目录与 socket basename 都保持紧凑。socket 仍放在 0700 namespace
        // 内，不能为了缩短路径而暴露到 world-writable temp root。
        let data_dir = temp_root.join(format!("ad-{instance_id}"));
        Self {
            runtime_db: data_dir.join("runtime.db"),
            socket: data_dir.join("s"),
            lock: data_dir.join("agentdeckd.lock"),
            data_dir,
            keychain_service: format!("com.agentdeck.agentdeckd.ephemeral.{instance_id}"),
            // 临时实例使用独立 memory/test keystore，不持有 daemon release entitlement。
            keychain_access_group: None,
            namespace_kind: DaemonNamespaceKind::Ephemeral,
        }
    }

    pub fn validate_socket_path(&self) -> Result<(), NamespaceError> {
        let bytes = path_bytes(&self.socket);
        if bytes.contains(&0) {
            return Err(NamespaceError::SocketPathContainsNul {
                path: self.socket.clone(),
            });
        }
        if bytes.len() > UNIX_SOCKET_PATH_MAX_BYTES {
            return Err(NamespaceError::SocketPathTooLong {
                path: self.socket.clone(),
                actual_bytes: bytes.len(),
                max_bytes: UNIX_SOCKET_PATH_MAX_BYTES,
            });
        }
        Ok(())
    }

    /// 仅用于 namespace/singleton 安全迁移判断；private constructor marker 防止
    /// 调用方用公开路径/service 字符串伪造 stable 权限。
    pub(crate) fn is_stable_namespace(&self) -> bool {
        self.namespace_kind == DaemonNamespaceKind::Stable
    }

    /// 为 singleton 打开 directory fd 前建立/初验路径 entry。ephemeral 宽权限
    /// 立即拒绝；固定 stable entry 可暂时接受当前 UID 的旧版宽权限，随后只能由
    /// singleton 在 O_NOFOLLOW directory fd 上收紧并复核 inode。
    pub(crate) fn prepare_data_dir_entry(&self) -> Result<(), NamespaceError> {
        match fs::symlink_metadata(&self.data_dir) {
            Ok(metadata) => {
                validate_existing_data_dir(&self.data_dir, &metadata, self.is_stable_namespace())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                #[cfg(unix)]
                let create_result = {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder.create(&self.data_dir)
                };
                #[cfg(not(unix))]
                let create_result = fs::create_dir(&self.data_dir);

                // 两个进程可同时观察到 NotFound。目录创建本身是原子的；loser
                // 遇到 EEXIST 后重新校验 winner 的 entry，再继续进入 dirfd/openat
                // singleton，而不是把正常并发误报为 namespace IO failure。
                if let Err(source) = create_result
                    && source.kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(NamespaceError::Io {
                        operation: "create daemon data directory",
                        path: self.data_dir.clone(),
                        source,
                    });
                }
                let metadata =
                    fs::symlink_metadata(&self.data_dir).map_err(|source| NamespaceError::Io {
                        operation: "inspect daemon data directory",
                        path: self.data_dir.clone(),
                        source,
                    })?;
                validate_existing_data_dir(&self.data_dir, &metadata, self.is_stable_namespace())
            }
            Err(source) => Err(NamespaceError::Io {
                operation: "inspect daemon data directory",
                path: self.data_dir.clone(),
                source,
            }),
        }
    }
}

fn validate_instance_id(instance_id: &str) -> Result<(), NamespaceError> {
    if instance_id.is_empty()
        || instance_id.len() > 64
        || !instance_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(NamespaceError::InvalidInstanceId);
    }
    Ok(())
}

fn canonical_private_temp_root(path: &Path) -> Result<PathBuf, NamespaceError> {
    let initial_metadata = fs::symlink_metadata(path).map_err(|source| NamespaceError::Io {
        operation: "inspect ephemeral temp root",
        path: path.to_path_buf(),
        source,
    })?;
    validate_temp_root_metadata(path, &initial_metadata)?;

    let canonical = fs::canonicalize(path).map_err(|source| NamespaceError::Io {
        operation: "canonicalize ephemeral temp root",
        path: path.to_path_buf(),
        source,
    })?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical).map_err(|source| NamespaceError::Io {
            operation: "inspect canonical ephemeral temp root",
            path: canonical.clone(),
            source,
        })?;
    validate_temp_root_metadata(&canonical, &canonical_metadata)?;
    validate_same_temp_root(path, &initial_metadata, &canonical_metadata)?;
    Ok(canonical)
}

#[cfg(unix)]
fn validate_temp_root_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), NamespaceError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(NamespaceError::UnsafeTempRoot {
            path: path.to_path_buf(),
            reason: "path is not a real directory",
        });
    }
    // SAFETY: geteuid has no preconditions and only reads process identity.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(NamespaceError::UnsafeTempRoot {
            path: path.to_path_buf(),
            reason: "directory is not owned by the current user",
        });
    }
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(NamespaceError::UnsafeTempRoot {
            path: path.to_path_buf(),
            reason: "directory permissions are not exact 0700",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_temp_root_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), NamespaceError> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(NamespaceError::UnsafeTempRoot {
            path: path.to_path_buf(),
            reason: "path is not a real directory",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_same_temp_root(
    path: &Path,
    initial: &fs::Metadata,
    canonical: &fs::Metadata,
) -> Result<(), NamespaceError> {
    use std::os::unix::fs::MetadataExt;

    if initial.dev() != canonical.dev() || initial.ino() != canonical.ino() {
        return Err(NamespaceError::UnsafeTempRoot {
            path: path.to_path_buf(),
            reason: "directory identity changed during canonicalization",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_temp_root(
    _path: &Path,
    _initial: &fs::Metadata,
    _canonical: &fs::Metadata,
) -> Result<(), NamespaceError> {
    Ok(())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn validate_existing_data_dir(
    path: &Path,
    metadata: &fs::Metadata,
    allow_stable_permission_migration: bool,
) -> Result<(), NamespaceError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(NamespaceError::UnsafeDataDirectory {
            path: path.to_path_buf(),
            reason: "path is not a real directory",
        });
    }
    // SAFETY: geteuid has no preconditions and only reads process identity.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(NamespaceError::UnsafeDataDirectory {
            path: path.to_path_buf(),
            reason: "directory is not owned by the current user",
        });
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != 0o700 && !(allow_stable_permission_migration && mode == 0o755) {
        return Err(NamespaceError::UnsafeDataDirectory {
            path: path.to_path_buf(),
            reason: "directory permissions are neither private 0700 nor exact legacy stable 0755",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_existing_data_dir(
    path: &Path,
    metadata: &fs::Metadata,
    _allow_stable_permission_migration: bool,
) -> Result<(), NamespaceError> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(NamespaceError::UnsafeDataDirectory {
            path: path.to_path_buf(),
            reason: "path is not a real directory",
        });
    }
    Ok(())
}
