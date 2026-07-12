//! daemon 启动模式解析。
//!
//! stable 是唯一 remote-enabled 生产模式；测试模式必须显式同时给出
//! `--ephemeral --no-remote`。单独给任一 flag 都拒绝，避免“临时路径连接生产
//! Relay”或“stable 信任域被当测试夹具”这两种半隔离状态。

use std::env;
#[cfg(target_os = "macos")]
use std::ffi::CStr;
use std::fmt;
#[cfg(target_os = "macos")]
use std::mem::MaybeUninit;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

use uuid::Uuid;

use crate::runtime::namespace::{DaemonMode, DaemonPaths, NamespaceError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonProfile {
    Stable,
    Dev,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaemonStartupOptions {
    pub ephemeral: bool,
    pub no_remote: bool,
    pub profile: Option<DaemonProfile>,
    /// 构建/签名流程注入已经展开 TeamIdentifier 的 daemon-only access group。
    /// namespace 只携带它；安全模块负责验证 entitlement 并 fail-closed。
    pub stable_keychain_access_group: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    mode: DaemonMode,
    paths: DaemonPaths,
    remote_enabled: bool,
}

#[derive(Debug)]
pub enum DaemonConfigError {
    EphemeralRequiresNoRemote,
    NoRemoteRequiresEphemeral,
    StableAccessGroupNotAllowedForEphemeral,
    DevProfileRequiresEphemeral,
    StableProfileForbidsEphemeral,
    StableAccessGroupMissing,
    StableUnsupportedPlatform,
    HomeDirectoryUnavailable,
    HomeLookupFailed { status: i32 },
    Namespace(NamespaceError),
}

impl fmt::Display for DaemonConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EphemeralRequiresNoRemote => {
                formatter.write_str("--ephemeral requires --no-remote")
            }
            Self::NoRemoteRequiresEphemeral => {
                formatter.write_str("--no-remote is only valid with --ephemeral")
            }
            Self::StableAccessGroupNotAllowedForEphemeral => formatter
                .write_str("stable Keychain access group cannot be used by an ephemeral daemon"),
            Self::DevProfileRequiresEphemeral => {
                formatter.write_str("dev profile requires --ephemeral --no-remote")
            }
            Self::StableProfileForbidsEphemeral => {
                formatter.write_str("stable profile cannot use --ephemeral")
            }
            Self::StableAccessGroupMissing => formatter
                .write_str("stable daemon Keychain access group is not compiled into this helper"),
            Self::StableUnsupportedPlatform => {
                formatter.write_str("stable daemon secret storage requires macOS")
            }
            Self::HomeDirectoryUnavailable => formatter
                .write_str("OS account home is unavailable for the stable daemon namespace"),
            Self::HomeLookupFailed { status } => {
                write!(
                    formatter,
                    "OS account home lookup failed with status {status}"
                )
            }
            Self::Namespace(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DaemonConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Namespace(error) => Some(error),
            _ => None,
        }
    }
}

impl DaemonConfigError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EphemeralRequiresNoRemote => "daemon.config.ephemeral_requires_no_remote",
            Self::NoRemoteRequiresEphemeral => "daemon.config.no_remote_requires_ephemeral",
            Self::StableAccessGroupNotAllowedForEphemeral => {
                "daemon.config.ephemeral_access_group_forbidden"
            }
            Self::DevProfileRequiresEphemeral => "daemon.config.dev_requires_ephemeral",
            Self::StableProfileForbidsEphemeral => "daemon.config.stable_forbids_ephemeral",
            Self::StableAccessGroupMissing => "daemon.keystore.access_group_unconfigured",
            Self::StableUnsupportedPlatform => "daemon.keystore.unsupported_platform",
            Self::HomeDirectoryUnavailable => "daemon.config.home_unavailable",
            Self::HomeLookupFailed { .. } => "daemon.config.home_lookup_failed",
            Self::Namespace(error) => error.code(),
        }
    }
}

impl From<NamespaceError> for DaemonConfigError {
    fn from(error: NamespaceError) -> Self {
        Self::Namespace(error)
    }
}

impl DaemonConfig {
    pub fn resolve(options: DaemonStartupOptions) -> Result<Self, DaemonConfigError> {
        validate_mode_matrix(&options)?;
        if options.ephemeral {
            return Self::resolve_with_roots(options, Path::new("/"), env::temp_dir());
        }
        #[cfg(not(target_os = "macos"))]
        return Err(DaemonConfigError::StableUnsupportedPlatform);
        #[cfg(target_os = "macos")]
        {
            let home = current_user_home()?;
            Self::resolve_with_roots(options, home, env::temp_dir())
        }
    }

    /// 带显式 roots 的入口用于 hermetic tests；生产路径应调用 [`Self::resolve`]。
    pub fn resolve_with_roots(
        options: DaemonStartupOptions,
        home: impl AsRef<Path>,
        temp_root: impl AsRef<Path>,
    ) -> Result<Self, DaemonConfigError> {
        validate_mode_matrix(&options)?;
        if options.ephemeral {
            if options.stable_keychain_access_group.is_some() {
                return Err(DaemonConfigError::StableAccessGroupNotAllowedForEphemeral);
            }
            let instance_id = Uuid::new_v4().to_string();
            let paths = DaemonPaths::ephemeral_with_instance_id(temp_root.as_ref(), &instance_id)?;
            Ok(Self {
                mode: DaemonMode::Ephemeral { instance_id },
                paths,
                remote_enabled: false,
            })
        } else {
            if options.stable_keychain_access_group.is_none() {
                return Err(DaemonConfigError::StableAccessGroupMissing);
            }
            let paths = DaemonPaths::stable(home, options.stable_keychain_access_group)?;
            Ok(Self {
                mode: DaemonMode::Stable,
                paths,
                remote_enabled: true,
            })
        }
    }

    pub fn mode(&self) -> &DaemonMode {
        &self.mode
    }

    pub fn paths(&self) -> &DaemonPaths {
        &self.paths
    }

    pub fn remote_enabled(&self) -> bool {
        self.remote_enabled
    }
}

/// 只接受构建/签名流水线在编译时注入的展开后 access group；运行时环境变量不能
/// 替换 stable daemon 的 Keychain 信任域。
#[must_use]
pub fn compiled_stable_keychain_access_group() -> Option<String> {
    option_env!("AGENTDECK_DAEMON_KEYCHAIN_ACCESS_GROUP").map(ToOwned::to_owned)
}

#[cfg(target_os = "macos")]
fn current_user_home() -> Result<PathBuf, DaemonConfigError> {
    use std::os::unix::ffi::OsStringExt;

    // SAFETY: geteuid has no preconditions and only reads process identity.
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
        // SAFETY: record, buffer and result are valid writable storage for getpwuid_r;
        // the returned pointers are consumed before buffer is dropped.
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
            return Err(DaemonConfigError::HomeLookupFailed { status });
        }
        if result.is_null() {
            return Err(DaemonConfigError::HomeDirectoryUnavailable);
        }
        // SAFETY: successful getpwuid_r initialized record and pw_dir points inside buffer.
        let record = unsafe { record.assume_init() };
        if record.pw_dir.is_null() {
            return Err(DaemonConfigError::HomeDirectoryUnavailable);
        }
        // SAFETY: pw_dir is a NUL-terminated C string owned by buffer for this scope.
        let bytes = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
        if bytes.is_empty() {
            return Err(DaemonConfigError::HomeDirectoryUnavailable);
        }
        let home = PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec()));
        if !home.is_absolute() {
            return Err(DaemonConfigError::HomeDirectoryUnavailable);
        }
        return Ok(home);
    }
}

fn validate_mode_matrix(options: &DaemonStartupOptions) -> Result<(), DaemonConfigError> {
    match (options.ephemeral, options.no_remote) {
        (false, false) | (true, true) => Ok(()),
        (true, false) => Err(DaemonConfigError::EphemeralRequiresNoRemote),
        (false, true) => Err(DaemonConfigError::NoRemoteRequiresEphemeral),
    }?;
    match (options.profile, options.ephemeral) {
        (Some(DaemonProfile::Dev), false) => Err(DaemonConfigError::DevProfileRequiresEphemeral),
        (Some(DaemonProfile::Stable), true) => {
            Err(DaemonConfigError::StableProfileForbidsEphemeral)
        }
        _ => Ok(()),
    }
}
