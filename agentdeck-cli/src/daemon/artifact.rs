//! daemon helper artifact 的安全校验与原子安装。
//!
//! production 入口只从当前 `AgentDeck.app/Contents/Helpers/agentdeck` 的同目录 sibling
//! 取得 `agentdeckd`。source 先以 `O_NOFOLLOW` 打开并保留 fd，后续复制不再按路径重开；
//! source 与同目录 temp 分别通过 verifier，且 version/protocol/hash/Team/access-group 必须
//! 完全一致。发布顺序固定为 temp file fsync、atomic rename、parent directory fsync。

#![cfg(unix)]

use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Child, Command, Output, Stdio};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

const CLI_BASENAME: &str = "agentdeck";
const DAEMON_BASENAME: &str = "agentdeckd";
const APP_BASENAME: &str = "AgentDeck.app";
const HELPERS_COMPONENT: &str = "Helpers";
const CONTENTS_COMPONENT: &str = "Contents";
#[cfg(target_os = "macos")]
const DAEMON_IDENTIFIER: &str = "com.agentdeck.agentdeckd";
const ACCESS_GROUP_SUFFIX: &str = ".com.agentdeck.agentdeckd.stable";
const MAX_VERSION_BYTES: usize = 128;
const TEMP_BASENAME_PREFIX: &str = ".agentdeckd.install-";
const TEMP_NONCE_HEX_BYTES: usize = 32;
#[cfg(target_os = "macos")]
const MAX_VERIFIER_OUTPUT_BYTES: usize = 256 * 1024;
#[cfg(target_os = "macos")]
const VERIFIER_DEADLINE: Duration = Duration::from_secs(10);
#[cfg(target_os = "macos")]
const VERIFIER_PIPE_CHUNK_BYTES: usize = 8 * 1024;
#[cfg(target_os = "macos")]
const VERIFIER_POLL_SLICE: Duration = Duration::from_millis(25);

/// verifier 对一个具体路径中 artifact 的完整 attestation。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactAttestation {
    pub signature: ArtifactSignature,
    pub version: String,
    pub protocol_version: u32,
    pub sha256: [u8; 32],
    pub team_identifier: String,
    pub keychain_access_groups: Vec<String>,
}

/// production verifier 只会产生 `Production`；`AdHoc` 仅用于注入的 fail-close 测试。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactSignature {
    Production,
    AdHoc,
}

/// 安装时必须固定的 identity 与 wire 兼容条件。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactExpectation {
    version: String,
    protocol_version: u32,
    expected_sha256: Option<[u8; 32]>,
    team_identifier: String,
    keychain_access_group: String,
}

impl ArtifactExpectation {
    pub fn new(
        version: impl Into<String>,
        protocol_version: u32,
        expected_sha256: Option<[u8; 32]>,
        team_identifier: impl Into<String>,
        keychain_access_group: impl Into<String>,
    ) -> Result<Self, InstallError> {
        let version = version.into();
        let team_identifier = team_identifier.into();
        let keychain_access_group = keychain_access_group.into();
        validate_version(&version)?;
        if protocol_version == 0 {
            return Err(InstallError::InvalidExpectation {
                reason: "protocol version must be non-zero",
            });
        }
        validate_team_identifier(&team_identifier)?;
        let required_group = format!("{team_identifier}{ACCESS_GROUP_SUFFIX}");
        if keychain_access_group != required_group {
            return Err(InstallError::InvalidExpectation {
                reason: "Keychain access group does not match TeamIdentifier",
            });
        }
        Ok(Self {
            version,
            protocol_version,
            expected_sha256,
            team_identifier,
            keychain_access_group,
        })
    }

    fn production(expected_sha256: Option<[u8; 32]>) -> Result<Self, InstallError> {
        let team_identifier = option_env!("AGENTDECK_DAEMON_TEAM_IDENTIFIER")
            .ok_or(InstallError::ProductionIdentityUnavailable)?;
        let access_group = option_env!("AGENTDECK_DAEMON_KEYCHAIN_ACCESS_GROUP")
            .ok_or(InstallError::ProductionIdentityUnavailable)?;
        Self::new(
            env!("CARGO_PKG_VERSION"),
            agentdeck_protocol::PROTOCOL_VERSION,
            expected_sha256,
            team_identifier,
            access_group,
        )
    }
}

/// 签名与 helper 自描述信息的可注入边界。
pub trait ArtifactVerifier: Send + Sync {
    fn verify(&self, path: &Path) -> Result<ArtifactAttestation, InstallError>;
}

/// 只用于 hermetic harness 观察已成功完成的 durability 边界；production 使用 no-op。
#[doc(hidden)]
pub trait InstallObserver: Send + Sync {
    fn observe(&self, event: InstallDurabilityEvent);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum InstallDurabilityEvent {
    CopiedFileSynced,
    VerifiedFileSynced,
    Renamed,
    ParentSynced,
}

#[derive(Clone, Copy, Debug, Default)]
#[doc(hidden)]
pub struct NoopInstallObserver;

impl InstallObserver for NoopInstallObserver {
    fn observe(&self, _event: InstallDurabilityEvent) {}
}

/// macOS production verifier。designated requirement 和 TeamIdentifier 均来自编译时身份，
/// 不接受运行时环境覆盖。
#[derive(Clone, Debug)]
pub struct ProductionSignatureVerifier {
    #[cfg(target_os = "macos")]
    team_identifier: String,
    #[cfg(target_os = "macos")]
    designated_requirement: String,
}

impl ProductionSignatureVerifier {
    fn new(team_identifier: String) -> Result<Self, InstallError> {
        validate_team_identifier(&team_identifier)?;
        #[cfg(target_os = "macos")]
        let designated_requirement = format!(
            "anchor apple generic and identifier \"{DAEMON_IDENTIFIER}\" and certificate leaf[subject.OU] = \"{team_identifier}\""
        );
        Ok(Self {
            #[cfg(target_os = "macos")]
            team_identifier,
            #[cfg(target_os = "macos")]
            designated_requirement,
        })
    }
}

impl ArtifactVerifier for ProductionSignatureVerifier {
    fn verify(&self, path: &Path) -> Result<ArtifactAttestation, InstallError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = path;
            Err(InstallError::UnsupportedPlatform)
        }
        #[cfg(target_os = "macos")]
        {
            verify_macos_artifact(path, self)
        }
    }
}

/// 成功 publication 的稳定读回信息。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledArtifact {
    pub path: PathBuf,
    pub version: String,
    pub protocol_version: u32,
    pub sha256: [u8; 32],
    pub team_identifier: String,
    pub keychain_access_group: String,
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("production daemon signing identity is not compiled into this CLI")]
    ProductionIdentityUnavailable,
    #[error("production daemon installation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("invalid artifact expectation: {reason}")]
    InvalidExpectation { reason: &'static str },
    #[error("CLI is not in the fixed AgentDeck.app helper layout: {path}")]
    InvalidBundleLayout { path: PathBuf },
    #[error("unsafe artifact {path}: {reason}")]
    UnsafeArtifact { path: PathBuf, reason: &'static str },
    #[error("unsafe destination directory {path}: {reason}")]
    UnsafeDestination { path: PathBuf, reason: &'static str },
    #[error("another daemon artifact installation owns {path}")]
    InstallBusy { path: PathBuf },
    #[error("artifact signature does not satisfy the production designated requirement")]
    SignatureRejected,
    #[error("ad-hoc signed daemon artifacts are forbidden")]
    AdHocSignatureRejected,
    #[error("artifact version mismatch: expected {expected}, observed {observed}")]
    VersionMismatch { expected: String, observed: String },
    #[error("artifact protocol mismatch: expected {expected}, observed {observed}")]
    ProtocolMismatch { expected: u32, observed: u32 },
    #[error("artifact hash mismatch")]
    HashMismatch,
    #[error("artifact TeamIdentifier mismatch")]
    TeamIdentifierMismatch,
    #[error("artifact Keychain access group mismatch")]
    AccessGroupMismatch,
    #[error("source and copied artifact attestations differ")]
    SourceTempMismatch,
    #[error("invalid verifier output: {reason}")]
    InvalidVerifierOutput { reason: &'static str },
    #[error("{operation} timed out for {path}")]
    VerifierTimedOut {
        operation: &'static str,
        path: PathBuf,
    },
    #[error("{operation} output exceeded the fixed bound for {path}")]
    VerifierOutputTooLarge {
        operation: &'static str,
        path: PathBuf,
    },
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl InstallError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ProductionIdentityUnavailable => "daemon.install.signing_identity_unavailable",
            Self::UnsupportedPlatform => "daemon.install.unsupported_platform",
            Self::InvalidExpectation { .. } => "daemon.install.expectation_invalid",
            Self::InvalidBundleLayout { .. } => "daemon.install.bundle_layout_invalid",
            Self::UnsafeArtifact { .. } => "daemon.install.artifact_unsafe",
            Self::UnsafeDestination { .. } => "daemon.install.destination_unsafe",
            Self::InstallBusy { .. } => "daemon.install.busy",
            Self::SignatureRejected | Self::AdHocSignatureRejected => {
                "daemon.install.signature_invalid"
            }
            Self::VersionMismatch { .. } => "daemon.install.version_mismatch",
            Self::ProtocolMismatch { .. } => "daemon.install.protocol_mismatch",
            Self::HashMismatch => "daemon.install.hash_mismatch",
            Self::TeamIdentifierMismatch => "daemon.install.team_identifier_mismatch",
            Self::AccessGroupMismatch => "daemon.install.access_group_mismatch",
            Self::SourceTempMismatch => "daemon.install.attestation_changed",
            Self::InvalidVerifierOutput { .. } => "daemon.install.verifier_output_invalid",
            Self::VerifierTimedOut { .. } => "daemon.install.verifier_timeout",
            Self::VerifierOutputTooLarge { .. } => "daemon.install.verifier_output_too_large",
            Self::Io { .. } => "daemon.install.io_failed",
        }
    }
}

/// 一个 verifier + 一份冻结 expectation。调用方不能在 source/temp 两次验证间改 policy。
#[derive(Clone, Debug)]
pub struct ArtifactInstaller<V, O = NoopInstallObserver> {
    verifier: V,
    expectation: ArtifactExpectation,
    observer: O,
}

impl<V, O> ArtifactInstaller<V, O> {
    #[must_use]
    pub fn expected_version(&self) -> &str {
        &self.expectation.version
    }
}

impl ArtifactInstaller<ProductionSignatureVerifier, NoopInstallObserver> {
    /// 创建 production installer。缺少编译时 Team/access-group 时直接拒绝，符合 P3.1 gated
    /// 边界，不会降级为 ad-hoc 或 ephemeral verifier。
    pub fn production(expected_sha256: Option<[u8; 32]>) -> Result<Self, InstallError> {
        let expectation = ArtifactExpectation::production(expected_sha256)?;
        let verifier = ProductionSignatureVerifier::new(expectation.team_identifier.clone())?;
        Ok(Self::new(verifier, expectation))
    }
}

impl<V> ArtifactInstaller<V, NoopInstallObserver> {
    pub fn new(verifier: V, expectation: ArtifactExpectation) -> Self {
        Self {
            verifier,
            expectation,
            observer: NoopInstallObserver,
        }
    }

    /// 为 automatic harness 注入 durability 观察器；不会改变任一文件系统操作结果。
    #[doc(hidden)]
    pub fn with_observer_for_test<O: InstallObserver>(
        self,
        observer: O,
    ) -> ArtifactInstaller<V, O> {
        ArtifactInstaller {
            verifier: self.verifier,
            expectation: self.expectation,
            observer,
        }
    }
}

impl<V: ArtifactVerifier, O: InstallObserver> ArtifactInstaller<V, O> {
    /// production 唯一来源入口：读取当前 executable，并要求 exact bundle layout。
    pub fn install_bundled_daemon(
        &self,
        destination_directory: &Path,
    ) -> Result<InstalledArtifact, InstallError> {
        let cli = std::env::current_exe().map_err(|source| InstallError::Io {
            operation: "resolve current executable",
            path: PathBuf::from(CLI_BASENAME),
            source,
        })?;
        let source = bundled_daemon_source(&cli)?;
        self.install_from_source(&source, destination_directory)
    }

    /// 仅供 hermetic automatic harness 注入 bundle/source；CLI routing 不得暴露 source path。
    #[doc(hidden)]
    pub fn install_from_source_for_test(
        &self,
        source: &Path,
        destination_directory: &Path,
    ) -> Result<InstalledArtifact, InstallError> {
        self.install_from_source(source, destination_directory)
    }

    fn install_from_source(
        &self,
        source_path: &Path,
        destination_directory: &Path,
    ) -> Result<InstalledArtifact, InstallError> {
        let mut source = open_artifact(source_path)?;
        let source_attestation = self.verifier.verify(source_path)?;

        let directory = open_destination_directory(destination_directory)?;
        lock_destination_directory(&directory, destination_directory)?;
        cleanup_stale_temps(&directory, destination_directory)?;
        let mut temp = TempArtifact::create(&directory, destination_directory)?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|source| io("rewind source artifact", source_path, source))?;
        let copied_hash = copy_and_hash(&mut source, &mut temp.file, &temp.path)?;
        temp.file
            .sync_all()
            .map_err(|source| io("sync copied artifact", &temp.path, source))?;
        self.observer
            .observe(InstallDurabilityEvent::CopiedFileSynced);

        validate_attestation(&source_attestation, &self.expectation, copied_hash)?;
        validate_open_artifact(&temp.file, &temp.path)?;
        let temp_attestation = self.verifier.verify(&temp.path)?;
        let temp_hash = hash_open_file(&mut temp.file, &temp.path)?;
        validate_attestation(&temp_attestation, &self.expectation, temp_hash)?;
        if source_attestation != temp_attestation || copied_hash != temp_hash {
            return Err(InstallError::SourceTempMismatch);
        }
        temp.file
            .sync_all()
            .map_err(|source| io("sync verified artifact", &temp.path, source))?;
        self.observer
            .observe(InstallDurabilityEvent::VerifiedFileSynced);

        temp.publish(&directory, destination_directory)?;
        self.observer.observe(InstallDurabilityEvent::Renamed);
        directory.sync_all().map_err(|source| {
            io(
                "sync artifact parent directory",
                destination_directory,
                source,
            )
        })?;
        self.observer.observe(InstallDurabilityEvent::ParentSynced);

        Ok(InstalledArtifact {
            path: destination_directory.join(DAEMON_BASENAME),
            version: temp_attestation.version,
            protocol_version: temp_attestation.protocol_version,
            sha256: temp_hash,
            team_identifier: temp_attestation.team_identifier,
            keychain_access_group: self.expectation.keychain_access_group.clone(),
        })
    }
}

/// 从一个 CLI path 推导固定 sibling。该函数不 canonicalize/follow；真实 source 随后由
/// `open_artifact` 以 `O_NOFOLLOW` 打开。
#[doc(hidden)]
pub fn bundled_daemon_source(cli_path: &Path) -> Result<PathBuf, InstallError> {
    let clean_absolute = cli_path.is_absolute()
        && !cli_path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir));
    let helpers = cli_path.parent();
    let contents = helpers.and_then(Path::parent);
    let app = contents.and_then(Path::parent);
    let valid = clean_absolute
        && cli_path.file_name() == Some(OsStr::new(CLI_BASENAME))
        && helpers.and_then(Path::file_name) == Some(OsStr::new(HELPERS_COMPONENT))
        && contents.and_then(Path::file_name) == Some(OsStr::new(CONTENTS_COMPONENT))
        && app.and_then(Path::file_name) == Some(OsStr::new(APP_BASENAME));
    if !valid {
        return Err(InstallError::InvalidBundleLayout {
            path: cli_path.to_path_buf(),
        });
    }
    Ok(helpers
        .expect("validated helper parent")
        .join(DAEMON_BASENAME))
}

fn validate_version(version: &str) -> Result<(), InstallError> {
    let valid = !version.is_empty()
        && !matches!(version, "." | "..")
        && version.len() <= MAX_VERSION_BYTES
        && version.trim() == version
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'));
    if valid {
        Ok(())
    } else {
        Err(InstallError::InvalidExpectation {
            reason: "version is empty, oversized, or non-canonical",
        })
    }
}

fn validate_team_identifier(team: &str) -> Result<(), InstallError> {
    let valid = !team.is_empty()
        && team.len() <= 64
        && team != "TEAMID"
        && team.bytes().all(|byte| byte.is_ascii_alphanumeric());
    if valid {
        Ok(())
    } else {
        Err(InstallError::InvalidExpectation {
            reason: "TeamIdentifier is empty, placeholder, oversized, or non-alphanumeric",
        })
    }
}

fn validate_attestation(
    observed: &ArtifactAttestation,
    expected: &ArtifactExpectation,
    fd_hash: [u8; 32],
) -> Result<(), InstallError> {
    if observed.signature != ArtifactSignature::Production {
        return Err(InstallError::AdHocSignatureRejected);
    }
    if observed.version != expected.version {
        return Err(InstallError::VersionMismatch {
            expected: expected.version.clone(),
            observed: observed.version.clone(),
        });
    }
    if observed.protocol_version != expected.protocol_version {
        return Err(InstallError::ProtocolMismatch {
            expected: expected.protocol_version,
            observed: observed.protocol_version,
        });
    }
    if observed.sha256 != fd_hash
        || expected
            .expected_sha256
            .is_some_and(|expected_hash| expected_hash != fd_hash)
    {
        return Err(InstallError::HashMismatch);
    }
    if observed.team_identifier != expected.team_identifier {
        return Err(InstallError::TeamIdentifierMismatch);
    }
    if observed.keychain_access_groups.as_slice() != [expected.keychain_access_group.as_str()] {
        return Err(InstallError::AccessGroupMismatch);
    }
    Ok(())
}

fn open_artifact(path: &Path) -> Result<File, InstallError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path).map_err(|source| {
        if source.raw_os_error() == Some(libc::ELOOP) {
            InstallError::UnsafeArtifact {
                path: path.to_path_buf(),
                reason: "symbolic links are forbidden",
            }
        } else {
            io("open source artifact", path, source)
        }
    })?;
    validate_open_artifact(&file, path)?;
    Ok(file)
}

fn validate_open_artifact(file: &File, path: &Path) -> Result<(), InstallError> {
    let metadata = file
        .metadata()
        .map_err(|source| io("inspect artifact", path, source))?;
    let mode = metadata.mode();
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_type().is_fifo()
        || metadata.file_type().is_socket()
    {
        return Err(InstallError::UnsafeArtifact {
            path: path.to_path_buf(),
            reason: "artifact is not a regular file",
        });
    }
    if metadata.nlink() != 1 {
        return Err(InstallError::UnsafeArtifact {
            path: path.to_path_buf(),
            reason: "artifact must have exactly one hard link",
        });
    }
    if mode & 0o111 == 0 {
        return Err(InstallError::UnsafeArtifact {
            path: path.to_path_buf(),
            reason: "artifact is not executable",
        });
    }
    if mode & u32::from(libc::S_ISUID | libc::S_ISGID) != 0 {
        return Err(InstallError::UnsafeArtifact {
            path: path.to_path_buf(),
            reason: "setuid/setgid artifact is forbidden",
        });
    }
    Ok(())
}

fn open_destination_directory(path: &Path) -> Result<File, InstallError> {
    if !path.is_absolute() {
        return Err(InstallError::UnsafeDestination {
            path: path.to_path_buf(),
            reason: "destination must be absolute",
        });
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = options.open(path).map_err(|source| {
        if source.raw_os_error() == Some(libc::ELOOP) {
            InstallError::UnsafeDestination {
                path: path.to_path_buf(),
                reason: "destination symlink is forbidden",
            }
        } else {
            io("open artifact destination", path, source)
        }
    })?;
    let metadata = directory
        .metadata()
        .map_err(|source| io("inspect artifact destination", path, source))?;
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir() {
        return Err(InstallError::UnsafeDestination {
            path: path.to_path_buf(),
            reason: "destination is not a directory",
        });
    }
    if metadata.uid() != uid {
        return Err(InstallError::UnsafeDestination {
            path: path.to_path_buf(),
            reason: "destination is not owned by the current account",
        });
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(InstallError::UnsafeDestination {
            path: path.to_path_buf(),
            reason: "destination is group/world writable",
        });
    }
    Ok(directory)
}

fn lock_destination_directory(directory: &File, path: &Path) -> Result<(), InstallError> {
    // The lock is attached to this open directory description and is released when `directory`
    // drops. Non-blocking acquisition keeps a wedged installer from hanging CLI callers.
    // SAFETY: directory is a retained directory fd; flock does not access user pointers.
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(());
    }
    let source = std::io::Error::last_os_error();
    if source.kind() == std::io::ErrorKind::WouldBlock {
        Err(InstallError::InstallBusy {
            path: path.to_path_buf(),
        })
    } else {
        Err(io("lock artifact destination", path, source))
    }
}

fn cleanup_stale_temps(directory: &File, path: &Path) -> Result<(), InstallError> {
    let mut removed = false;
    let entries =
        std::fs::read_dir(path).map_err(|source| io("scan stale artifact temps", path, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io("read stale artifact temp entry", path, source))?;
        let name = entry.file_name();
        let Some(bytes) = stale_temp_basename(&name) else {
            continue;
        };
        let c_name = CString::new(bytes).map_err(|_| InstallError::UnsafeDestination {
            path: path.join(&name),
            reason: "stale temp basename contains NUL",
        })?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: retained directory fd, validated basename and writable stat storage are valid.
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io(
                "inspect stale artifact temp",
                &path.join(&name),
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: successful fstatat initialized stat.
        let stat = unsafe { stat.assume_init() };
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::geteuid() };
        let regular = (stat.st_mode & libc::S_IFMT) == libc::S_IFREG;
        if !regular
            || stat.st_uid != uid
            || stat.st_nlink != 1
            || stat.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0
        {
            return Err(InstallError::UnsafeDestination {
                path: path.join(&name),
                reason: "reserved stale temp entry is not a single-link owned regular file",
            });
        }
        // SAFETY: same retained parent/name just inspected without following links. The exclusive
        // directory lock serializes all conforming installers; same-UID hostile races are outside
        // the declared MVP threat boundary.
        if unsafe { libc::unlinkat(directory.as_raw_fd(), c_name.as_ptr(), 0) } != 0 {
            return Err(io(
                "remove stale artifact temp",
                &path.join(&name),
                std::io::Error::last_os_error(),
            ));
        }
        removed = true;
    }
    if removed {
        directory
            .sync_all()
            .map_err(|source| io("sync stale artifact cleanup", path, source))?;
    }
    Ok(())
}

fn stale_temp_basename(name: &OsStr) -> Option<&[u8]> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = name.as_bytes();
    let suffix = bytes.strip_prefix(TEMP_BASENAME_PREFIX.as_bytes())?;
    (suffix.len() == TEMP_NONCE_HEX_BYTES && suffix.iter().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(bytes)
}

fn copy_and_hash(
    source: &mut File,
    destination: &mut File,
    destination_path: &Path,
) -> Result<[u8; 32], InstallError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|source| io("read opened source artifact", destination_path, source))?;
        if count == 0 {
            break;
        }
        destination
            .write_all(&buffer[..count])
            .map_err(|source| io("write temporary artifact", destination_path, source))?;
        digest.update(&buffer[..count]);
        copied = copied.saturating_add(count as u64);
    }
    if copied == 0 {
        return Err(InstallError::UnsafeArtifact {
            path: destination_path.to_path_buf(),
            reason: "artifact is empty",
        });
    }
    Ok(digest.finalize().into())
}

fn hash_open_file(file: &mut File, path: &Path) -> Result<[u8; 32], InstallError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io("rewind verified artifact", path, source))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| io("read verified artifact", path, source))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

struct TempArtifact {
    directory_fd: i32,
    name: CString,
    path: PathBuf,
    file: File,
    published: bool,
}

impl TempArtifact {
    fn create(directory: &File, directory_path: &Path) -> Result<Self, InstallError> {
        for _ in 0..32 {
            let mut nonce = [0_u8; 16];
            OsRng.fill_bytes(&mut nonce);
            let suffix = nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let basename = format!("{TEMP_BASENAME_PREFIX}{suffix}");
            let name = CString::new(basename.as_bytes()).expect("generated basename has no NUL");
            // SAFETY: retained directory fd and generated single-component C string are valid.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o500,
                )
            };
            if fd < 0 {
                let source = std::io::Error::last_os_error();
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(io(
                    "create temporary artifact",
                    &directory_path.join(&basename),
                    source,
                ));
            }
            // SAFETY: successful openat returns one newly-owned fd.
            let file = unsafe { File::from_raw_fd(fd) };
            // Enforce the exact executable mode even under a restrictive caller umask.
            // SAFETY: file is an owned regular fd and fchmod only changes its mode.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o500) } != 0 {
                let source = std::io::Error::last_os_error();
                // unlink is handled by the guard after it is constructed below; here it is not.
                // SAFETY: same retained parent and generated name used for creation.
                unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
                return Err(io(
                    "set temporary artifact mode",
                    &directory_path.join(&basename),
                    source,
                ));
            }
            return Ok(Self {
                directory_fd: directory.as_raw_fd(),
                name,
                path: directory_path.join(basename),
                file,
                published: false,
            });
        }
        Err(InstallError::Io {
            operation: "allocate temporary artifact name",
            path: directory_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "temporary artifact name collision budget exhausted",
            ),
        })
    }

    fn publish(&mut self, directory: &File, directory_path: &Path) -> Result<(), InstallError> {
        let destination = CString::new(DAEMON_BASENAME).expect("fixed basename has no NUL");
        // SAFETY: both basenames are NUL-terminated single components under the retained parent.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                self.name.as_ptr(),
                directory.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(io(
                "publish verified artifact",
                &directory_path.join(DAEMON_BASENAME),
                std::io::Error::last_os_error(),
            ));
        }
        self.published = true;
        Ok(())
    }
}

impl Drop for TempArtifact {
    fn drop(&mut self) {
        if !self.published {
            // SAFETY: directory_fd outlives this guard in install_from_source; name is the exact
            // single component created by openat. Cleanup is best effort on the error path.
            unsafe { libc::unlinkat(self.directory_fd, self.name.as_ptr(), 0) };
        }
    }
}

#[cfg(target_os = "macos")]
fn verify_macos_artifact(
    path: &Path,
    verifier: &ProductionSignatureVerifier,
) -> Result<ArtifactAttestation, InstallError> {
    let requirement = format!("-R={}", verifier.designated_requirement);
    bounded_command_output(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict=all"])
            .arg(requirement)
            .arg(path),
        path,
        "run codesign verification",
    )?;

    let display = bounded_command_output(
        Command::new("/usr/bin/codesign")
            .args(["--display", "--verbose=4"])
            .arg(path),
        path,
        "read codesign identity",
    )?;
    let display =
        String::from_utf8(display.stderr).map_err(|_| InstallError::InvalidVerifierOutput {
            reason: "codesign identity output is not UTF-8",
        })?;
    if display.lines().any(|line| line == "Signature=adhoc") {
        return Err(InstallError::AdHocSignatureRejected);
    }
    let identifier = parse_codesign_value(&display, "Identifier=")?;
    let team_identifier = parse_codesign_value(&display, "TeamIdentifier=")?;
    if identifier != DAEMON_IDENTIFIER || team_identifier != verifier.team_identifier {
        return Err(InstallError::SignatureRejected);
    }

    let entitlement_output = bounded_command_output(
        Command::new("/usr/bin/codesign")
            .args(["--display", "--entitlements", "-", "--xml"])
            .arg(path),
        path,
        "read codesign entitlements",
    )?;
    let entitlement_json = plutil_json(path, &entitlement_output.stdout)?;
    let access_groups = entitlement_json
        .get("keychain-access-groups")
        .and_then(serde_json::Value::as_array)
        .ok_or(InstallError::InvalidVerifierOutput {
            reason: "keychain-access-groups entitlement is missing or not an array",
        })?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or(InstallError::InvalidVerifierOutput {
                    reason: "keychain-access-groups contains a non-string value",
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let version_output = bounded_command_output(
        Command::new(path).arg("--version").env_clear(),
        path,
        "read daemon version",
    )?;
    let (version, protocol_version) = parse_daemon_version(&version_output.stdout)?;
    let sha256 = hash_path_for_verifier(path)?;
    Ok(ArtifactAttestation {
        signature: ArtifactSignature::Production,
        version,
        protocol_version,
        sha256,
        team_identifier: team_identifier.to_owned(),
        keychain_access_groups: access_groups,
    })
}

#[cfg(target_os = "macos")]
fn bounded_command_output(
    command: &mut Command,
    path: &Path,
    operation: &'static str,
) -> Result<Output, InstallError> {
    let output = run_bounded_command(
        command,
        path,
        operation,
        None,
        VERIFIER_DEADLINE,
        MAX_VERIFIER_OUTPUT_BYTES,
    )?;
    if !output.status.success() {
        return Err(InstallError::SignatureRejected);
    }
    Ok(output)
}

#[cfg(target_os = "macos")]
fn run_bounded_command(
    command: &mut Command,
    path: &Path,
    operation: &'static str,
    input: Option<&[u8]>,
    deadline: Duration,
    max_output_bytes: usize,
) -> Result<Output, InstallError> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut spawned = command
        .spawn()
        .map_err(|source| io(operation, path, source))?;
    let process_group_id = match libc::pid_t::try_from(spawned.id()) {
        Ok(process_group_id) if process_group_id > 1 => process_group_id,
        _ => {
            let _ = spawned.kill();
            let _ = spawned.wait();
            return Err(InstallError::InvalidVerifierOutput {
                reason: "verifier process group id is invalid",
            });
        }
    };
    let mut child = VerifierChild::new(spawned, process_group_id);
    let mut stdin = child.child.stdin.take();
    let stdout_pipe = child
        .child
        .stdout
        .take()
        .ok_or(InstallError::InvalidVerifierOutput {
            reason: "verifier stdout pipe is unavailable",
        })?;
    let stderr_pipe = child
        .child
        .stderr
        .take()
        .ok_or(InstallError::InvalidVerifierOutput {
            reason: "verifier stderr pipe is unavailable",
        })?;
    set_nonblocking(stdout_pipe.as_raw_fd()).map_err(|source| io(operation, path, source))?;
    set_nonblocking(stderr_pipe.as_raw_fd()).map_err(|source| io(operation, path, source))?;
    let mut stdout = Some(stdout_pipe);
    let mut stderr = Some(stderr_pipe);
    if let Some(pipe) = stdin.as_ref() {
        set_nonblocking(pipe.as_raw_fd()).map_err(|source| io(operation, path, source))?;
    }

    let started = Instant::now();
    let input = input.unwrap_or_default();
    let mut input_offset = 0_usize;
    if input.is_empty() {
        stdin = None;
    }
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut leader_exited = false;

    loop {
        if started.elapsed() >= deadline {
            child.terminate_and_reap();
            return Err(InstallError::VerifierTimedOut {
                operation,
                path: path.to_path_buf(),
            });
        }

        let mut made_progress = false;
        if let Some(pipe) = stdout.as_mut() {
            match read_pipe_once(pipe, &mut stdout_bytes, &stderr_bytes, max_output_bytes) {
                Ok(PipeRead::Bytes) => made_progress = true,
                Ok(PipeRead::WouldBlock) => {}
                Ok(PipeRead::Eof) => stdout = None,
                Err(PipeReadError::OutputTooLarge) => {
                    child.terminate_and_reap();
                    return Err(InstallError::VerifierOutputTooLarge {
                        operation,
                        path: path.to_path_buf(),
                    });
                }
                Err(PipeReadError::Io(source)) => return Err(io(operation, path, source)),
            }
        }
        if let Some(pipe) = stderr.as_mut() {
            match read_pipe_once(pipe, &mut stderr_bytes, &stdout_bytes, max_output_bytes) {
                Ok(PipeRead::Bytes) => made_progress = true,
                Ok(PipeRead::WouldBlock) => {}
                Ok(PipeRead::Eof) => stderr = None,
                Err(PipeReadError::OutputTooLarge) => {
                    child.terminate_and_reap();
                    return Err(InstallError::VerifierOutputTooLarge {
                        operation,
                        path: path.to_path_buf(),
                    });
                }
                Err(PipeReadError::Io(source)) => return Err(io(operation, path, source)),
            }
        }

        if let Some(pipe) = stdin.as_mut() {
            let end = input_offset
                .saturating_add(VERIFIER_PIPE_CHUNK_BYTES)
                .min(input.len());
            match pipe.write(&input[input_offset..end]) {
                Ok(0) => {
                    return Err(io(
                        operation,
                        path,
                        std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "verifier stdin closed before input completed",
                        ),
                    ));
                }
                Ok(written) => {
                    input_offset = input_offset.saturating_add(written);
                    made_progress = true;
                    if input_offset == input.len() {
                        stdin = None;
                    }
                }
                Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(source) if source.kind() == std::io::ErrorKind::Interrupted => {}
                Err(source) if source.kind() == std::io::ErrorKind::BrokenPipe => {
                    return Err(io(operation, path, source));
                }
                Err(source) => return Err(io(operation, path, source)),
            }
        }

        if !leader_exited {
            leader_exited = child
                .has_exited_without_reaping()
                .map_err(|source| io(operation, path, source))?;
            if leader_exited {
                if input_offset != input.len() {
                    return Err(InstallError::InvalidVerifierOutput {
                        reason: "verifier exited before consuming its bounded input",
                    });
                }
                stdin = None;
            }
        }
        let stdout_closed = stdout.is_none();
        let stderr_closed = stderr.is_none();
        if leader_exited && stdout_closed && stderr_closed {
            let process_group_id = child.process_group_id;
            let status = child
                .terminate_group_and_wait()
                .map_err(|source| io(operation, path, source))?;
            if !wait_for_process_group_exit(process_group_id, started, deadline)
                .map_err(|source| io(operation, path, source))?
            {
                return Err(InstallError::VerifierTimedOut {
                    operation,
                    path: path.to_path_buf(),
                });
            }
            return Ok(Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            });
        }
        if made_progress {
            continue;
        }

        let mut poll_fds = Vec::with_capacity(3);
        if let Some(pipe) = stdout.as_ref() {
            poll_fds.push(libc::pollfd {
                fd: pipe.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if let Some(pipe) = stderr.as_ref() {
            poll_fds.push(libc::pollfd {
                fd: pipe.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if let Some(pipe) = stdin.as_ref() {
            poll_fds.push(libc::pollfd {
                fd: pipe.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            });
        }
        let remaining = deadline.saturating_sub(started.elapsed());
        let poll_for = remaining.min(VERIFIER_POLL_SLICE);
        let timeout_ms = i32::try_from(poll_for.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: poll_fds points to initialized pollfd values for the duration of this call.
        let result = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if result == -1 {
            let source = std::io::Error::last_os_error();
            if source.kind() != std::io::ErrorKind::Interrupted {
                return Err(io(operation, path, source));
            }
        }
    }
}

#[cfg(target_os = "macos")]
struct VerifierChild {
    child: Child,
    process_group_id: libc::pid_t,
    armed: bool,
}

#[cfg(target_os = "macos")]
impl VerifierChild {
    fn new(child: Child, process_group_id: libc::pid_t) -> Self {
        Self {
            process_group_id,
            child,
            armed: true,
        }
    }

    fn terminate_and_reap(&mut self) {
        if !self.armed {
            return;
        }
        // SAFETY: the child was spawned into its own positive PGID; negation targets only that
        // verifier process group. SIGKILL is required because verifier output is untrusted.
        unsafe { libc::kill(-self.process_group_id, libc::SIGKILL) };
        let _ = self.child.wait();
        self.armed = false;
    }

    fn has_exited_without_reaping(&self) -> std::io::Result<bool> {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        loop {
            // SAFETY: info points to writable siginfo storage. WNOWAIT observes only this owned
            // child and deliberately retains its zombie identity until group cleanup is signaled.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.process_group_id as libc::id_t,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                // SAFETY: successful waitid initialized the zeroed siginfo storage. With WNOHANG,
                // si_pid == 0 means the child has not exited; P_PID cannot report another child.
                return Ok(unsafe { info.assume_init().si_pid() } != 0);
            }
            let source = std::io::Error::last_os_error();
            if source.kind() != std::io::ErrorKind::Interrupted {
                return Err(source);
            }
        }
    }

    fn terminate_group_and_wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        // The leader is intentionally still waitable here, so its PID/PGID cannot be reused by an
        // unrelated process before this exact isolated group receives SIGKILL.
        let result = unsafe { libc::kill(-self.process_group_id, libc::SIGKILL) };
        if result == -1 {
            let source = std::io::Error::last_os_error();
            if !matches!(source.raw_os_error(), Some(libc::ESRCH) | Some(libc::EPERM)) {
                return Err(source);
            }
        }
        let status = self.child.wait()?;
        self.armed = false;
        Ok(status)
    }
}

#[cfg(target_os = "macos")]
impl Drop for VerifierChild {
    fn drop(&mut self) {
        self.terminate_and_reap();
    }
}

#[cfg(target_os = "macos")]
fn wait_for_process_group_exit(
    process_group_id: libc::pid_t,
    started: Instant,
    deadline: Duration,
) -> std::io::Result<bool> {
    loop {
        if started.elapsed() >= deadline {
            return Ok(false);
        }
        // SAFETY: signal 0 is a read-only presence probe for the exact positive verifier PGID.
        if unsafe { libc::kill(-process_group_id, 0) } == -1 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::ESRCH) {
                return Ok(true);
            }
            return Err(source);
        }
        std::thread::sleep(
            deadline
                .saturating_sub(started.elapsed())
                .min(VERIFIER_POLL_SLICE),
        );
    }
}

#[cfg(target_os = "macos")]
fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: fd is an owned live child pipe and fcntl does not retain pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same live pipe fd; flags preserves existing status flags and adds O_NONBLOCK.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
enum PipeRead {
    Bytes,
    WouldBlock,
    Eof,
}

#[cfg(target_os = "macos")]
enum PipeReadError {
    OutputTooLarge,
    Io(std::io::Error),
}

#[cfg(target_os = "macos")]
fn read_pipe_once(
    pipe: &mut impl Read,
    destination: &mut Vec<u8>,
    other: &[u8],
    max_output_bytes: usize,
) -> Result<PipeRead, PipeReadError> {
    let mut buffer = [0_u8; VERIFIER_PIPE_CHUNK_BYTES];
    match pipe.read(&mut buffer) {
        Ok(0) => Ok(PipeRead::Eof),
        Ok(read) => {
            if destination
                .len()
                .saturating_add(other.len())
                .saturating_add(read)
                > max_output_bytes
            {
                return Err(PipeReadError::OutputTooLarge);
            }
            destination.extend_from_slice(&buffer[..read]);
            Ok(PipeRead::Bytes)
        }
        Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => Ok(PipeRead::WouldBlock),
        Err(source) if source.kind() == std::io::ErrorKind::Interrupted => Ok(PipeRead::WouldBlock),
        Err(source) => Err(PipeReadError::Io(source)),
    }
}

#[cfg(target_os = "macos")]
fn parse_codesign_value<'a>(text: &'a str, prefix: &str) -> Result<&'a str, InstallError> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = values.next().ok_or(InstallError::InvalidVerifierOutput {
        reason: "codesign identity field is missing",
    })?;
    if value.is_empty() || values.next().is_some() {
        return Err(InstallError::InvalidVerifierOutput {
            reason: "codesign identity field is empty or duplicated",
        });
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
fn plutil_json(path: &Path, xml: &[u8]) -> Result<serde_json::Value, InstallError> {
    if xml.len() > MAX_VERIFIER_OUTPUT_BYTES {
        return Err(InstallError::InvalidVerifierOutput {
            reason: "entitlement plist exceeds the fixed bound",
        });
    }
    let output = run_bounded_command(
        Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-", "-"]),
        path,
        "parse entitlement plist",
        Some(xml),
        VERIFIER_DEADLINE,
        MAX_VERIFIER_OUTPUT_BYTES,
    )?;
    if !output.status.success() {
        return Err(InstallError::InvalidVerifierOutput {
            reason: "entitlement plist is invalid",
        });
    }
    serde_json::from_slice(&output.stdout).map_err(|_| InstallError::InvalidVerifierOutput {
        reason: "entitlement parser output is invalid JSON",
    })
}

#[cfg(target_os = "macos")]
fn parse_daemon_version(stdout: &[u8]) -> Result<(String, u32), InstallError> {
    if stdout.len() > MAX_VERIFIER_OUTPUT_BYTES {
        return Err(InstallError::InvalidVerifierOutput {
            reason: "daemon version output exceeds the fixed bound",
        });
    }
    let text = std::str::from_utf8(stdout).map_err(|_| InstallError::InvalidVerifierOutput {
        reason: "daemon version output is not UTF-8",
    })?;
    let mut lines = text.lines();
    let version = lines
        .next()
        .and_then(|line| line.strip_prefix("agentdeckd "))
        .ok_or(InstallError::InvalidVerifierOutput {
            reason: "daemon version line is missing",
        })?;
    let protocol_version = lines
        .next()
        .and_then(|line| line.strip_prefix("protocolVersion "))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(InstallError::InvalidVerifierOutput {
            reason: "daemon protocol version line is missing or invalid",
        })?;
    if lines.next().is_some() {
        return Err(InstallError::InvalidVerifierOutput {
            reason: "daemon version output contains extra lines",
        });
    }
    validate_version(version)?;
    Ok((version.to_owned(), protocol_version))
}

#[cfg(target_os = "macos")]
fn hash_path_for_verifier(path: &Path) -> Result<[u8; 32], InstallError> {
    let mut file = open_artifact(path)?;
    hash_open_file(&mut file, path)
}

fn io(operation: &'static str, path: &Path, source: std::io::Error) -> InstallError {
    InstallError::Io {
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
    #[cfg(target_os = "macos")]
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    #[cfg(target_os = "macos")]
    use std::time::{Duration, Instant};

    use agentdeck_crypto::sha256;
    use tempfile::TempDir;

    use super::{
        ArtifactAttestation, ArtifactExpectation, ArtifactInstaller, ArtifactSignature,
        ArtifactVerifier, InstallError, bundled_daemon_source,
    };

    const VERSION: &str = "0.2.0";
    const PROTOCOL: u32 = 2;
    const TEAM: &str = "REALTEAM42";
    const ACCESS_GROUP: &str = "REALTEAM42.com.agentdeck.agentdeckd.stable";

    type VerifyFn = dyn Fn(&Path, usize) -> Result<ArtifactAttestation, InstallError> + Send + Sync;

    #[derive(Clone)]
    struct FakeVerifier {
        calls: Arc<Mutex<Vec<PathBuf>>>,
        verify: Arc<VerifyFn>,
    }

    impl FakeVerifier {
        fn new(
            verify: impl Fn(&Path, usize) -> Result<ArtifactAttestation, InstallError>
            + Send
            + Sync
            + 'static,
        ) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                verify: Arc::new(verify),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().expect("calls lock").len()
        }
    }

    impl ArtifactVerifier for FakeVerifier {
        fn verify(&self, path: &Path) -> Result<ArtifactAttestation, InstallError> {
            let index = {
                let mut calls = self.calls.lock().expect("calls lock");
                let index = calls.len();
                calls.push(path.to_path_buf());
                index
            };
            (self.verify)(path, index)
        }
    }

    fn attestation(bytes: &[u8]) -> ArtifactAttestation {
        ArtifactAttestation {
            signature: ArtifactSignature::Production,
            version: VERSION.to_owned(),
            protocol_version: PROTOCOL,
            sha256: sha256(bytes),
            team_identifier: TEAM.to_owned(),
            keychain_access_groups: vec![ACCESS_GROUP.to_owned()],
        }
    }

    fn expectation(expected_hash: Option<[u8; 32]>) -> ArtifactExpectation {
        ArtifactExpectation::new(VERSION, PROTOCOL, expected_hash, TEAM, ACCESS_GROUP)
            .expect("valid expectation")
    }

    fn write_executable(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod fixture");
    }

    #[cfg(target_os = "macos")]
    fn process_is_gone(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only probes whether this test-owned pid still exists.
        let result = unsafe { libc::kill(pid, 0) };
        result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[cfg(target_os = "macos")]
    fn assert_processes_reaped(pid_file: &Path) {
        let pids = fs::read_to_string(pid_file)
            .expect("verifier fixture records its process group")
            .lines()
            .map(|line| line.parse::<libc::pid_t>().expect("fixture pid"))
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 2, "fixture must record leader and child");
        let deadline = Instant::now() + Duration::from_secs(2);
        while pids.iter().any(|pid| !process_is_gone(*pid)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            pids.into_iter().all(process_is_gone),
            "timed-out/overflowed verifier process group was not fully killed and reaped"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verifier_timeout_is_typed_and_reaps_the_process_group() {
        let root = TempDir::new().expect("tempdir");
        let pid_file = root.path().join("timeout-pids");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "echo $$ > \"$1\"; sleep 30 & echo $! >> \"$1\"; wait",
                "artifact-verifier-timeout",
            ])
            .arg(&pid_file);

        let started = Instant::now();
        let error = super::run_bounded_command(
            &mut command,
            root.path(),
            "test verifier timeout",
            None,
            Duration::from_millis(250),
            4 * 1024,
        )
        .expect_err("hung verifier must time out");

        assert!(matches!(error, InstallError::VerifierTimedOut { .. }));
        assert_eq!(error.code(), "daemon.install.verifier_timeout");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_processes_reaped(&pid_file);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verifier_aggregate_output_cap_is_enforced_while_child_is_running() {
        let root = TempDir::new().expect("tempdir");
        let pid_file = root.path().join("overflow-pids");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "echo $$ > \"$1\"; sleep 30 & echo $! >> \"$1\"; \
                 while :; do printf 1234567890; printf 1234567890 >&2; done",
                "artifact-verifier-overflow",
            ])
            .arg(&pid_file);

        let started = Instant::now();
        let error = super::run_bounded_command(
            &mut command,
            root.path(),
            "test verifier overflow",
            None,
            Duration::from_secs(2),
            4 * 1024,
        )
        .expect_err("streaming verifier output must be bounded");

        assert!(matches!(error, InstallError::VerifierOutputTooLarge { .. }));
        assert_eq!(error.code(), "daemon.install.verifier_output_too_large");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_processes_reaped(&pid_file);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verifier_success_reaps_silent_process_group_descendant() {
        let root = TempDir::new().expect("tempdir");
        let candidate = root.path().join("agentdeckd-candidate");
        let pid_file = root.path().join("agentdeckd-candidate.pids");
        write_executable(
            &candidate,
            br#"#!/bin/sh
test "$1" = "--version" || exit 64
printf '%s\n' "$$" > "${0}.pids"
/bin/sleep 30 </dev/null >/dev/null 2>&1 &
printf '%s\n' "$!" >> "${0}.pids"
printf 'agentdeckd 0.1.0\nprotocol 2\n'
"#,
        );
        let mut command = Command::new(&candidate);
        command.arg("--version").env_clear();

        let output = super::run_bounded_command(
            &mut command,
            &candidate,
            "test successful verifier cleanup",
            None,
            Duration::from_secs(2),
            4 * 1024,
        )
        .expect("successful candidate version probe must complete");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"agentdeckd 0.1.0\nprotocol 2\n");
        let pids = fs::read_to_string(&pid_file)
            .expect("candidate records its process group")
            .lines()
            .map(|line| line.parse::<libc::pid_t>().expect("fixture pid"))
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 2, "fixture must record leader and child");
        assert!(process_is_gone(pids[0]), "successful leader must be reaped");

        let descendant = pids[1];
        let deadline = Instant::now() + Duration::from_secs(2);
        while !process_is_gone(descendant) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let descendant_was_reaped = process_is_gone(descendant);
        if !descendant_was_reaped {
            // SAFETY: this PID belongs to the test-owned 30-second sleep recorded immediately
            // before the successful verifier leader exited. Cleanup keeps the RED test hermetic.
            unsafe { libc::kill(descendant, libc::SIGKILL) };
        }
        assert!(
            descendant_was_reaped,
            "successful verifier left a silent same-group descendant running"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verifier_pumps_bounded_stdin_and_output_without_pipe_deadlock() {
        let root = TempDir::new().expect("tempdir");
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "/bin/dd if=/dev/zero bs=65536 count=1 2>/dev/null; /bin/cat >/dev/null; printf done >&2",
            "artifact-verifier-pipes",
        ]);
        let input = vec![b'x'; 128 * 1024];

        let output = super::run_bounded_command(
            &mut command,
            root.path(),
            "test verifier pipe pump",
            Some(&input),
            Duration::from_secs(2),
            128 * 1024,
        )
        .expect("bounded bidirectional pipe pump must complete");

        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 65_536);
        assert_eq!(output.stderr, b"done");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verifier_cannot_succeed_after_closing_unconsumed_input() {
        let root = TempDir::new().expect("tempdir");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0", "artifact-verifier-input"]);
        let input = vec![b'x'; 1024 * 1024];

        assert!(
            super::run_bounded_command(
                &mut command,
                root.path(),
                "test verifier incomplete input",
                Some(&input),
                Duration::from_secs(2),
                4 * 1024,
            )
            .is_err(),
            "successful exit must not hide unconsumed bounded input"
        );
    }

    #[test]
    fn verifier_resource_failure_never_publishes_the_temp_artifact() {
        for timeout in [true, false] {
            let root = TempDir::new().expect("tempdir");
            let source = root.path().join("agentdeckd");
            let destination = root.path().join("version");
            write_executable(&source, b"daemon");
            fs::create_dir(&destination).expect("destination");
            let verifier = FakeVerifier::new(move |path, index| {
                if index == 0 {
                    return Ok(attestation(&fs::read(path).expect("source fixture")));
                }
                if timeout {
                    Err(InstallError::VerifierTimedOut {
                        operation: "test verifier",
                        path: path.to_path_buf(),
                    })
                } else {
                    Err(InstallError::VerifierOutputTooLarge {
                        operation: "test verifier",
                        path: path.to_path_buf(),
                    })
                }
            });
            let installer = ArtifactInstaller::new(verifier, expectation(None));

            assert!(
                installer
                    .install_from_source_for_test(&source, &destination)
                    .is_err()
            );
            assert!(!destination.join("agentdeckd").exists());
            assert!(
                fs::read_dir(&destination)
                    .expect("read destination")
                    .next()
                    .is_none(),
                "resource failure must remove the unverified temp artifact"
            );
        }
    }

    #[test]
    fn bundled_source_accepts_only_exact_agentdeck_app_helpers_layout() {
        let root = TempDir::new().expect("tempdir");
        let helpers = root
            .path()
            .join("AgentDeck.app")
            .join("Contents")
            .join("Helpers");
        fs::create_dir_all(&helpers).expect("helpers");
        let cli = helpers.join("agentdeck");
        let daemon = helpers.join("agentdeckd");
        write_executable(&cli, b"cli");
        write_executable(&daemon, b"daemon");

        assert_eq!(bundled_daemon_source(&cli).expect("valid layout"), daemon);

        for invalid in [
            helpers.join("renamed-agentdeck"),
            root.path()
                .join("Renamed.app")
                .join("Contents/Helpers/agentdeck"),
            root.path()
                .join("AgentDeck.app")
                .join("Contents/MacOS/agentdeck"),
            root.path().join("standalone/agentdeck"),
        ] {
            assert!(
                matches!(
                    bundled_daemon_source(&invalid),
                    Err(InstallError::InvalidBundleLayout { .. })
                ),
                "unexpectedly accepted {}",
                invalid.display()
            );
        }
    }

    #[test]
    fn symlink_hardlink_and_non_regular_source_fail_before_verification() {
        let root = TempDir::new().expect("tempdir");
        let destination = root.path().join("version");
        fs::create_dir(&destination).expect("destination");
        let verifier = FakeVerifier::new(|path, _| {
            let bytes = fs::read(path).expect("fixture exists");
            Ok(attestation(&bytes))
        });
        let installer = ArtifactInstaller::new(verifier.clone(), expectation(None));

        let regular = root.path().join("regular");
        write_executable(&regular, b"daemon");
        let link = root.path().join("symlink");
        symlink(&regular, &link).expect("symlink");
        assert!(matches!(
            installer.install_from_source_for_test(&link, &destination),
            Err(InstallError::UnsafeArtifact { .. })
        ));

        let hardlink = root.path().join("hardlink");
        fs::hard_link(&regular, &hardlink).expect("hardlink");
        assert!(matches!(
            installer.install_from_source_for_test(&regular, &destination),
            Err(InstallError::UnsafeArtifact { .. })
        ));

        let directory = root.path().join("directory-source");
        fs::create_dir(&directory).expect("directory source");
        assert!(matches!(
            installer.install_from_source_for_test(&directory, &destination),
            Err(InstallError::UnsafeArtifact { .. })
        ));

        assert_eq!(verifier.call_count(), 0);
        assert!(!destination.join("agentdeckd").exists());
    }

    #[test]
    fn every_attested_field_and_adhoc_signature_fail_closed() {
        let root = TempDir::new().expect("tempdir");
        let source = root.path().join("agentdeckd");
        write_executable(&source, b"daemon");

        let mut cases: Vec<(&str, ArtifactAttestation)> = Vec::new();
        let mut value = attestation(b"daemon");
        value.signature = ArtifactSignature::AdHoc;
        cases.push(("ad-hoc", value));
        let mut value = attestation(b"daemon");
        value.version = "9.9.9".to_owned();
        cases.push(("version", value));
        let mut value = attestation(b"daemon");
        value.protocol_version += 1;
        cases.push(("protocol", value));
        let mut value = attestation(b"daemon");
        value.sha256[0] ^= 1;
        cases.push(("hash", value));
        let mut value = attestation(b"daemon");
        value.team_identifier = "OTHERTEAM".to_owned();
        cases.push(("team", value));
        let mut value = attestation(b"daemon");
        value.keychain_access_groups = vec!["OTHERTEAM.group".to_owned()];
        cases.push(("access-group", value));

        for (name, invalid) in cases {
            let destination = root.path().join(format!("dest-{name}"));
            fs::create_dir(&destination).expect("destination");
            let verifier = FakeVerifier::new(move |_, _| Ok(invalid.clone()));
            let installer = ArtifactInstaller::new(verifier, expectation(Some(sha256(b"daemon"))));
            assert!(
                installer
                    .install_from_source_for_test(&source, &destination)
                    .is_err(),
                "{name} mismatch must fail"
            );
            assert!(!destination.join("agentdeckd").exists());
            assert!(
                fs::read_dir(&destination)
                    .expect("read destination")
                    .next()
                    .is_none()
            );
        }
    }

    #[test]
    fn every_field_is_reverified_on_temp_before_publish() {
        let root = TempDir::new().expect("tempdir");
        let source = root.path().join("agentdeckd");
        write_executable(&source, b"daemon");

        for name in [
            "ad-hoc",
            "version",
            "protocol",
            "hash",
            "team",
            "access-group",
        ] {
            let destination = root.path().join(format!("temp-mismatch-{name}"));
            fs::create_dir(&destination).expect("destination");
            let verifier = FakeVerifier::new(move |path, index| {
                let bytes = fs::read(path).expect("read artifact");
                let mut result = attestation(&bytes);
                if index == 1 {
                    match name {
                        "ad-hoc" => result.signature = ArtifactSignature::AdHoc,
                        "version" => result.version = "9.9.9".to_owned(),
                        "protocol" => result.protocol_version += 1,
                        "hash" => result.sha256[0] ^= 1,
                        "team" => result.team_identifier = "OTHERTEAM".to_owned(),
                        "access-group" => {
                            result.keychain_access_groups = vec!["OTHERTEAM.group".to_owned()];
                        }
                        _ => unreachable!(),
                    }
                }
                Ok(result)
            });
            let installer = ArtifactInstaller::new(verifier.clone(), expectation(None));

            assert!(
                installer
                    .install_from_source_for_test(&source, &destination)
                    .is_err(),
                "temp {name} mismatch must fail"
            );
            assert_eq!(verifier.call_count(), 2);
            assert!(
                fs::read_dir(&destination)
                    .expect("read destination")
                    .next()
                    .is_none()
            );
        }
    }
}
