//! LaunchAgent 生命周期、versioned install layout 与保留数据卸载。

#![cfg(unix)]

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

use crate::daemon::artifact::{
    ArtifactInstaller, ArtifactVerifier, InstallError, InstallObserver, InstalledArtifact,
    ProductionSignatureVerifier,
};
use crate::installation::{CliInstallationStore, InstallationError};

pub const LAUNCH_AGENT_LABEL: &str = "com.agentdeck.agentdeckd";
const PLIST_BASENAME: &str = "com.agentdeck.agentdeckd.plist";
const CURRENT_BASENAME: &str = "current";
const DAEMON_BASENAME: &str = "agentdeckd";
const LAUNCH_AGENT_PLIST_TEMPLATE: &str =
    include_str!("../../../packaging/com.agentdeck.agentdeckd.plist.in");

/// daemon 与 CLI/B coordinator 共享的固定 install layout。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonInstallPaths {
    home: PathBuf,
    data_root: PathBuf,
    bin_root: PathBuf,
    plist: PathBuf,
}

impl DaemonInstallPaths {
    pub fn for_os_account() -> Result<Self, LifecycleError> {
        Self::from_home(CliInstallationStore::os_account_home_path()?)
    }

    /// 仅供 hermetic harness 显式注入隔离 home。
    #[doc(hidden)]
    pub fn injected_for_test(home: PathBuf) -> Result<Self, LifecycleError> {
        Self::from_home(home)
    }

    fn from_home(home: PathBuf) -> Result<Self, LifecycleError> {
        if !home.is_absolute()
            || home
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(LifecycleError::UnsafePath {
                path: home,
                reason: "home must be a clean absolute path",
            });
        }
        let data_root = home
            .join("Library")
            .join("Application Support")
            .join("AgentDeck");
        Ok(Self {
            bin_root: data_root.join("bin"),
            plist: home
                .join("Library")
                .join("LaunchAgents")
                .join(PLIST_BASENAME),
            home,
            data_root,
        })
    }

    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    #[must_use]
    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    #[must_use]
    pub fn bin_root(&self) -> &Path {
        &self.bin_root
    }

    #[must_use]
    pub fn current_link(&self) -> PathBuf {
        self.bin_root.join(CURRENT_BASENAME)
    }

    #[must_use]
    pub fn current_daemon(&self) -> PathBuf {
        self.current_link().join(DAEMON_BASENAME)
    }

    #[must_use]
    pub fn plist(&self) -> &Path {
        &self.plist
    }

    #[must_use]
    pub fn version_directory(&self, version: &str) -> PathBuf {
        self.bin_root.join(version)
    }

    #[must_use]
    pub fn version_daemon(&self, version: &str) -> PathBuf {
        self.version_directory(version).join(DAEMON_BASENAME)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonStatus {
    pub plist_installed: bool,
    pub current_version: Option<String>,
    pub launchd_loaded: bool,
    pub pid: Option<u32>,
    pub running_program: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonInstallOutcome {
    Activated {
        artifact: InstalledArtifact,
    },
    /// active daemon 的 `current` 未改变；调用方必须经 UDS StageUpgrade 续做。
    Staged {
        artifact: InstalledArtifact,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchAgentReadback {
    pub pid: Option<u32>,
    pub program: PathBuf,
    pub plist: PathBuf,
}

pub trait LaunchctlRunner: Send + Sync {
    fn readback(&self, uid: u32) -> Result<Option<LaunchAgentReadback>, LifecycleError>;
    fn bootstrap(&self, uid: u32, plist: &Path) -> Result<(), LifecycleError>;
    fn kickstart(&self, uid: u32) -> Result<(), LifecycleError>;
    fn bootout(&self, uid: u32) -> Result<(), LifecycleError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessLaunchctlRunner;

impl LaunchctlRunner for ProcessLaunchctlRunner {
    fn readback(&self, uid: u32) -> Result<Option<LaunchAgentReadback>, LifecycleError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = uid;
            Err(LifecycleError::UnsupportedPlatform)
        }
        #[cfg(target_os = "macos")]
        {
            let output = launchctl_output(["print", &service_target(uid)])?;
            if output.status.success() {
                return parse_launchctl_readback(&output.stdout).map(Some);
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Could not find service") || stderr.contains("service not found") {
                Ok(None)
            } else {
                Err(LifecycleError::Launchctl {
                    operation: "print",
                    detail: bounded_detail(&output.stderr),
                })
            }
        }
    }

    fn bootstrap(&self, uid: u32, plist: &Path) -> Result<(), LifecycleError> {
        run_launchctl("bootstrap", ["bootstrap", &domain_target(uid)], Some(plist))
    }

    fn kickstart(&self, uid: u32) -> Result<(), LifecycleError> {
        run_launchctl("kickstart", ["kickstart", "-k", &service_target(uid)], None)
    }

    fn bootout(&self, uid: u32) -> Result<(), LifecycleError> {
        run_launchctl("bootout", ["bootout", &service_target(uid)], None)
    }
}

#[derive(Clone, Debug)]
pub struct DaemonLifecycle<R> {
    paths: DaemonInstallPaths,
    runner: R,
}

impl DaemonLifecycle<ProcessLaunchctlRunner> {
    pub fn production() -> Result<Self, LifecycleError> {
        Ok(Self {
            paths: DaemonInstallPaths::for_os_account()?,
            runner: ProcessLaunchctlRunner,
        })
    }

    pub fn production_installer(
        expected_sha256: Option<[u8; 32]>,
    ) -> Result<ArtifactInstaller<ProductionSignatureVerifier>, LifecycleError> {
        Ok(ArtifactInstaller::production(expected_sha256)?)
    }
}

impl<R> DaemonLifecycle<R> {
    /// 测试入口与 production 构造器分离，避免 production 接受 home/runner override。
    #[doc(hidden)]
    pub fn injected_for_test(paths: DaemonInstallPaths, runner: R) -> Self {
        Self { paths, runner }
    }

    #[must_use]
    pub fn paths(&self) -> &DaemonInstallPaths {
        &self.paths
    }
}

impl<R: LaunchctlRunner> DaemonLifecycle<R> {
    pub fn install_bundled<V: ArtifactVerifier, O: InstallObserver>(
        &self,
        installer: &ArtifactInstaller<V, O>,
    ) -> Result<DaemonInstallOutcome, LifecycleError> {
        self.install(installer, None)
    }

    #[doc(hidden)]
    pub fn install_from_source_for_test<V: ArtifactVerifier, O: InstallObserver>(
        &self,
        installer: &ArtifactInstaller<V, O>,
        source: &Path,
    ) -> Result<DaemonInstallOutcome, LifecycleError> {
        self.install(installer, Some(source))
    }

    fn install<V: ArtifactVerifier, O: InstallObserver>(
        &self,
        installer: &ArtifactInstaller<V, O>,
        injected_source: Option<&Path>,
    ) -> Result<DaemonInstallOutcome, LifecycleError> {
        let version = installer.expected_version();
        validate_version_component(version)?;
        self.prepare_install_directories(version)?;
        let version_directory = self.paths.version_directory(version);
        let artifact = match injected_source {
            Some(source) => installer.install_from_source_for_test(source, &version_directory)?,
            None => installer.install_bundled_daemon(&version_directory)?,
        };
        publish_plist(&self.paths)?;
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::geteuid() };
        if let Some(mut readback) = self.runner.readback(uid)? {
            validate_loaded_service(&self.paths, &readback)?;
            if !matches!(readback.pid, Some(pid) if pid != 0) {
                self.runner.kickstart(uid)?;
                readback = self
                    .runner
                    .readback(uid)?
                    .ok_or(LifecycleError::LaunchAgentMissingAfterBootstrap)?;
                validate_loaded_service(&self.paths, &readback)?;
                if !matches!(readback.pid, Some(pid) if pid != 0) {
                    return Err(LifecycleError::LoadedServiceMismatch);
                }
            }
            return Ok(DaemonInstallOutcome::Staged { artifact });
        }
        set_current(&self.paths, version)?;
        self.runner.bootstrap(uid, self.paths.plist())?;
        self.runner.kickstart(uid)?;
        let readback = self
            .runner
            .readback(uid)?
            .ok_or(LifecycleError::LaunchAgentMissingAfterBootstrap)?;
        validate_loaded_service(&self.paths, &readback)?;
        if !matches!(readback.pid, Some(pid) if pid != 0) {
            return Err(LifecycleError::LoadedServiceMismatch);
        }
        Ok(DaemonInstallOutcome::Activated { artifact })
    }

    pub fn status(&self) -> Result<DaemonStatus, LifecycleError> {
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::geteuid() };
        let plist_installed = regular_file_if_present(self.paths.plist())?;
        let current_version = read_current_version(&self.paths)?;
        let readback = self.runner.readback(uid)?;
        if let Some(readback) = &readback {
            validate_loaded_service(&self.paths, readback)?;
        }
        Ok(DaemonStatus {
            plist_installed,
            current_version,
            launchd_loaded: readback.is_some(),
            pid: readback.as_ref().and_then(|value| value.pid),
            running_program: readback.map(|value| value.program),
        })
    }

    /// 默认只卸载 LaunchAgent 与 binaries；Runtime DB/Keychain/data root 始终保留。
    /// `--purge` 在 P4 trust-reset 完成前必须零副作用拒绝。
    pub fn uninstall(&self, purge: bool) -> Result<(), LifecycleError> {
        if purge {
            return Err(LifecycleError::PurgeRemoteNotReady);
        }
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::geteuid() };
        if let Some(readback) = self.runner.readback(uid)? {
            validate_loaded_service(&self.paths, &readback)?;
            self.runner.bootout(uid)?;
        }
        if self.runner.readback(uid)?.is_some() {
            return Err(LifecycleError::StillLoaded);
        }
        remove_file_if_present(self.paths.plist())?;
        if self.paths.bin_root.exists() {
            let metadata = std::fs::symlink_metadata(&self.paths.bin_root)
                .map_err(|source| io("inspect daemon bin root", &self.paths.bin_root, source))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(LifecycleError::UnsafePath {
                    path: self.paths.bin_root.clone(),
                    reason: "bin root is not a directory",
                });
            }
            std::fs::remove_dir_all(&self.paths.bin_root)
                .map_err(|source| io("remove daemon binaries", &self.paths.bin_root, source))?;
            sync_parent(&self.paths.bin_root)?;
        }
        sync_parent(self.paths.plist())?;
        Ok(())
    }

    fn prepare_install_directories(&self, version: &str) -> Result<(), LifecycleError> {
        CliInstallationStore::injected_for_test(self.paths.home.clone())
            .prepare_daemon_install_directories(version)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error(transparent)]
    Artifact(#[from] InstallError),
    #[error(transparent)]
    Installation(#[from] InstallationError),
    #[error("daemon LaunchAgent lifecycle is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("unsafe daemon install path {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: &'static str },
    #[error("launchctl {operation} failed: {detail}")]
    Launchctl {
        operation: &'static str,
        detail: String,
    },
    #[error("daemon remains loaded after launchctl bootout")]
    StillLoaded,
    #[error("loaded LaunchAgent does not match the fixed plist/current executable")]
    LoadedServiceMismatch,
    #[error("LaunchAgent is absent after bootstrap/kickstart")]
    LaunchAgentMissingAfterBootstrap,
    #[error("purge requires P4 remote trust reset and readback")]
    PurgeRemoteNotReady,
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl LifecycleError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Artifact(error) => error.code(),
            Self::Installation(error) => error.code(),
            Self::UnsupportedPlatform => "daemon.install.unsupported_platform",
            Self::UnsafePath { .. } => "daemon.install.path_unsafe",
            Self::Launchctl { .. } => "daemon.launchctl.failed",
            Self::StillLoaded => "daemon.uninstall.still_loaded",
            Self::LoadedServiceMismatch => "daemon.launchctl.loaded_service_mismatch",
            Self::LaunchAgentMissingAfterBootstrap => "daemon.launchctl.bootstrap_readback_failed",
            Self::PurgeRemoteNotReady => "daemon.purge.remote_not_ready",
            Self::Io { .. } => "daemon.install.io_failed",
        }
    }
}

pub fn render_launch_agent_plist(program: &Path) -> Result<String, LifecycleError> {
    if !program.is_absolute() {
        return Err(LifecycleError::UnsafePath {
            path: program.to_path_buf(),
            reason: "ProgramArguments executable must be absolute",
        });
    }
    let program = program.to_str().ok_or_else(|| LifecycleError::UnsafePath {
        path: program.to_path_buf(),
        reason: "ProgramArguments executable must be UTF-8",
    })?;
    if LAUNCH_AGENT_PLIST_TEMPLATE
        .matches("@DAEMON_PROGRAM_XML@")
        .count()
        != 1
        || LAUNCH_AGENT_PLIST_TEMPLATE
            .matches("@LAUNCH_AGENT_LABEL_XML@")
            .count()
            != 1
    {
        return Err(LifecycleError::UnsafePath {
            path: PathBuf::from("packaging/com.agentdeck.agentdeckd.plist.in"),
            reason: "LaunchAgent template placeholders are missing or duplicated",
        });
    }
    Ok(LAUNCH_AGENT_PLIST_TEMPLATE
        .replace("@LAUNCH_AGENT_LABEL_XML@", &xml_escape(LAUNCH_AGENT_LABEL))
        .replace("@DAEMON_PROGRAM_XML@", &xml_escape(program)))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn publish_plist(paths: &DaemonInstallPaths) -> Result<(), LifecycleError> {
    let parent_path = paths.plist.parent().expect("plist parent");
    let parent = open_locked_directory(parent_path)?;
    let temp_name = CString::new(format!(".{PLIST_BASENAME}.next")).expect("fixed name");
    // SAFETY: retained private dirfd and fixed basename; unlink never follows the entry.
    unsafe { libc::unlinkat(parent.as_raw_fd(), temp_name.as_ptr(), 0) };
    let file = openat_new(&parent, &temp_name, 0o600, paths.plist())?;
    let mut temp = TempFile::new(parent.as_raw_fd(), temp_name, file);
    let contents = render_launch_agent_plist(&paths.current_daemon())?;
    temp.file
        .write_all(contents.as_bytes())
        .map_err(|source| io("write LaunchAgent plist", paths.plist(), source))?;
    temp.file
        .sync_all()
        .map_err(|source| io("sync LaunchAgent plist", paths.plist(), source))?;
    let final_name = CString::new(PLIST_BASENAME).expect("fixed name");
    temp.rename_to(&parent, &final_name, paths.plist())?;
    parent
        .sync_all()
        .map_err(|source| io("sync LaunchAgents directory", parent_path, source))
}

fn set_current(paths: &DaemonInstallPaths, version: &str) -> Result<(), LifecycleError> {
    validate_version_component(version)?;
    let parent = open_locked_directory(&paths.bin_root)?;
    let temp = CString::new(".current.next").expect("fixed name");
    let target = CString::new(version).expect("validated version");
    let current = CString::new(CURRENT_BASENAME).expect("fixed name");
    // SAFETY: retained private dirfd; fixed temp name is a reserved installer entry.
    unsafe { libc::unlinkat(parent.as_raw_fd(), temp.as_ptr(), 0) };
    // SAFETY: validated single-component relative target and fixed link basename.
    if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), temp.as_ptr()) } != 0 {
        return Err(io(
            "create current symlink temp",
            &paths.current_link(),
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: both names are single components under retained parent; rename replaces entry only.
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            temp.as_ptr(),
            parent.as_raw_fd(),
            current.as_ptr(),
        )
    } != 0
    {
        // SAFETY: best-effort cleanup of the exact reserved temp entry.
        unsafe { libc::unlinkat(parent.as_raw_fd(), temp.as_ptr(), 0) };
        return Err(io(
            "publish current symlink",
            &paths.current_link(),
            std::io::Error::last_os_error(),
        ));
    }
    parent
        .sync_all()
        .map_err(|source| io("sync daemon bin root", &paths.bin_root, source))
}

fn read_current_version(paths: &DaemonInstallPaths) -> Result<Option<String>, LifecycleError> {
    let link = paths.current_link();
    let metadata = match std::fs::symlink_metadata(&link) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io("inspect current symlink", &link, source)),
    };
    if !metadata.file_type().is_symlink() {
        return Err(LifecycleError::UnsafePath {
            path: link,
            reason: "current is not a symlink",
        });
    }
    let target =
        std::fs::read_link(&link).map_err(|source| io("read current symlink", &link, source))?;
    let version = target.to_str().ok_or_else(|| LifecycleError::UnsafePath {
        path: link.clone(),
        reason: "current target is not UTF-8",
    })?;
    validate_version_component(version)?;
    if target.components().count() != 1 {
        return Err(LifecycleError::UnsafePath {
            path: link,
            reason: "current target is not one relative version component",
        });
    }
    Ok(Some(version.to_owned()))
}

fn validate_loaded_service(
    paths: &DaemonInstallPaths,
    readback: &LaunchAgentReadback,
) -> Result<(), LifecycleError> {
    let has_current = read_current_version(paths)?.is_some();
    let has_plist = regular_file_if_present(paths.plist())?;
    if !has_current
        || !has_plist
        || readback.program != paths.current_daemon()
        || readback.plist != paths.plist()
    {
        return Err(LifecycleError::LoadedServiceMismatch);
    }
    Ok(())
}

fn validate_version_component(version: &str) -> Result<(), LifecycleError> {
    if version.is_empty()
        || matches!(version, "." | "..")
        || version.len() > 128
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(LifecycleError::UnsafePath {
            path: PathBuf::from(version),
            reason: "version is not a safe path component",
        });
    }
    Ok(())
}

fn open_locked_directory(path: &Path) -> Result<File, LifecycleError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io("open install directory", path, source))?;
    // SAFETY: retained directory fd; flock does not access pointers.
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io(
            "lock install directory",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(directory)
}

fn openat_new(
    parent: &File,
    name: &CString,
    mode: libc::mode_t,
    path: &Path,
) -> Result<File, LifecycleError> {
    // SAFETY: retained dirfd, fixed basename, no-follow/exclusive create.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(io(
            "create install temp",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful openat returned one owned fd.
    let file = unsafe { File::from_raw_fd(fd) };
    // SAFETY: retained newly-created regular fd; enforce mode independently of caller umask.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(io(
            "set install temp mode",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(file)
}

struct TempFile {
    parent_fd: i32,
    name: CString,
    file: File,
    active: bool,
}

impl TempFile {
    fn new(parent_fd: i32, name: CString, file: File) -> Self {
        Self {
            parent_fd,
            name,
            file,
            active: true,
        }
    }

    fn rename_to(
        &mut self,
        parent: &File,
        destination: &CString,
        path: &Path,
    ) -> Result<(), LifecycleError> {
        // SAFETY: both basenames are beneath the same retained directory.
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                self.name.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(io(
                "publish install temp",
                path,
                std::io::Error::last_os_error(),
            ));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: exact reserved temp basename; unlinkat does not follow it.
            unsafe { libc::unlinkat(self.parent_fd, self.name.as_ptr(), 0) };
        }
    }
}

fn regular_file_if_present(path: &Path) -> Result<bool, LifecycleError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(LifecycleError::UnsafePath {
            path: path.to_path_buf(),
            reason: "expected regular file",
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io("inspect installed file", path, source)),
    }
}

fn remove_file_if_present(path: &Path) -> Result<(), LifecycleError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            std::fs::remove_file(path).map_err(|source| io("remove installed file", path, source))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io("inspect installed file", path, source)),
    }
}

fn sync_parent(path: &Path) -> Result<(), LifecycleError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|source| io("open parent for sync", parent, source))?;
    directory
        .sync_all()
        .map_err(|source| io("sync parent", parent, source))
}

#[cfg(target_os = "macos")]
fn launchctl_output<const N: usize>(
    args: [&str; N],
) -> Result<std::process::Output, LifecycleError> {
    Command::new("/bin/launchctl")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|source| io("run launchctl", Path::new("/bin/launchctl"), source))
}

fn run_launchctl<const N: usize>(
    operation: &'static str,
    args: [&str; N],
    path: Option<&Path>,
) -> Result<(), LifecycleError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (operation, args, path);
        Err(LifecycleError::UnsupportedPlatform)
    }
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("/bin/launchctl");
        command.args(args);
        if let Some(path) = path {
            command.arg(path);
        }
        let output = command
            .stdin(Stdio::null())
            .output()
            .map_err(|source| io("run launchctl", Path::new("/bin/launchctl"), source))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(LifecycleError::Launchctl {
                operation,
                detail: bounded_detail(&output.stderr),
            })
        }
    }
}

#[cfg(target_os = "macos")]
fn bounded_detail(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(4096)])
        .trim()
        .to_owned()
}

#[cfg(target_os = "macos")]
fn parse_launchctl_readback(bytes: &[u8]) -> Result<LaunchAgentReadback, LifecycleError> {
    let text = std::str::from_utf8(bytes).map_err(|_| LifecycleError::Launchctl {
        operation: "print",
        detail: "launchctl print output is not UTF-8".to_owned(),
    })?;
    let field = |prefix: &str| -> Result<&str, LifecycleError> {
        let mut values = text
            .lines()
            .filter_map(|line| line.trim().strip_prefix(prefix));
        let value = values.next().ok_or_else(|| LifecycleError::Launchctl {
            operation: "print",
            detail: format!("missing {prefix} readback"),
        })?;
        if value.is_empty() || values.next().is_some() {
            return Err(LifecycleError::Launchctl {
                operation: "print",
                detail: format!("ambiguous {prefix} readback"),
            });
        }
        Ok(value)
    };
    let mut pid_values = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pid ="));
    let pid = match pid_values.next() {
        None => None,
        Some(value) if pid_values.next().is_none() => Some(
            value
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|pid| *pid != 0)
                .ok_or_else(|| LifecycleError::Launchctl {
                    operation: "print",
                    detail: "invalid pid readback".to_owned(),
                })?,
        ),
        Some(_) => {
            return Err(LifecycleError::Launchctl {
                operation: "print",
                detail: "ambiguous pid readback".to_owned(),
            });
        }
    };
    Ok(LaunchAgentReadback {
        pid,
        program: PathBuf::from(field("program = ")?),
        plist: PathBuf::from(field("path = ")?),
    })
}

fn domain_target(uid: u32) -> String {
    format!("gui/{uid}")
}

fn service_target(uid: u32) -> String {
    format!("{}/{LAUNCH_AGENT_LABEL}", domain_target(uid))
}

fn io(operation: &'static str, path: &Path, source: std::io::Error) -> LifecycleError {
    LifecycleError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use agentdeck_crypto::sha256;

    use super::{
        DaemonInstallOutcome, DaemonInstallPaths, DaemonLifecycle, LaunchAgentReadback,
        LaunchctlRunner, LifecycleError, render_launch_agent_plist, validate_version_component,
    };
    use crate::daemon::artifact::{
        ArtifactAttestation, ArtifactExpectation, ArtifactInstaller, ArtifactSignature,
        ArtifactVerifier, InstallError,
    };

    const TEAM: &str = "REALTEAM42";
    const GROUP: &str = "REALTEAM42.com.agentdeck.agentdeckd.stable";

    #[derive(Clone)]
    struct FakeVerifier {
        version: &'static str,
    }

    impl ArtifactVerifier for FakeVerifier {
        fn verify(&self, path: &Path) -> Result<ArtifactAttestation, InstallError> {
            let bytes = fs::read(path).expect("read artifact");
            Ok(ArtifactAttestation {
                signature: ArtifactSignature::Production,
                version: self.version.to_owned(),
                protocol_version: 2,
                sha256: sha256(&bytes),
                team_identifier: TEAM.to_owned(),
                keychain_access_groups: vec![GROUP.to_owned()],
            })
        }
    }

    #[derive(Clone)]
    struct FakeLaunchctl {
        state: Arc<Mutex<FakeLaunchctlState>>,
    }

    struct FakeLaunchctlState {
        loaded: bool,
        calls: Vec<&'static str>,
        readback: LaunchAgentReadback,
        kickstart_pid: Option<u32>,
    }

    impl FakeLaunchctl {
        fn for_paths(paths: &DaemonInstallPaths) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeLaunchctlState {
                    loaded: false,
                    calls: Vec::new(),
                    readback: LaunchAgentReadback {
                        pid: Some(4242),
                        program: paths.current_daemon(),
                        plist: paths.plist().to_path_buf(),
                    },
                    kickstart_pid: None,
                })),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.state.lock().expect("state").calls.clone()
        }

        fn set_program(&self, program: impl Into<PathBuf>) {
            self.state.lock().expect("state").readback.program = program.into();
        }

        fn set_pid(&self, pid: Option<u32>) {
            self.state.lock().expect("state").readback.pid = pid;
        }

        fn set_kickstart_pid(&self, pid: u32) {
            self.state.lock().expect("state").kickstart_pid = Some(pid);
        }
    }

    impl LaunchctlRunner for FakeLaunchctl {
        fn readback(&self, _uid: u32) -> Result<Option<LaunchAgentReadback>, LifecycleError> {
            let mut state = self.state.lock().expect("state");
            state.calls.push("print");
            Ok(state.loaded.then(|| state.readback.clone()))
        }

        fn bootstrap(&self, _uid: u32, _plist: &Path) -> Result<(), LifecycleError> {
            let mut state = self.state.lock().expect("state");
            state.calls.push("bootstrap");
            state.loaded = true;
            Ok(())
        }

        fn kickstart(&self, _uid: u32) -> Result<(), LifecycleError> {
            let mut state = self.state.lock().expect("state");
            state.calls.push("kickstart");
            if let Some(pid) = state.kickstart_pid {
                state.readback.pid = Some(pid);
            }
            Ok(())
        }

        fn bootout(&self, _uid: u32) -> Result<(), LifecycleError> {
            let mut state = self.state.lock().expect("state");
            state.calls.push("bootout");
            state.loaded = false;
            Ok(())
        }
    }

    fn installer(version: &'static str) -> ArtifactInstaller<FakeVerifier> {
        ArtifactInstaller::new(
            FakeVerifier { version },
            ArtifactExpectation::new(version, 2, None, TEAM, GROUP).expect("expectation"),
        )
    }

    fn source(root: &Path) -> std::path::PathBuf {
        let source = root.join("source-agentdeckd");
        fs::write(&source, b"signed daemon").expect("source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).expect("chmod");
        source
    }

    #[test]
    fn plist_escapes_absolute_program_argument() {
        let plist = render_launch_agent_plist(Path::new("/Users/A&B/AgentDeck/current/agentdeckd"))
            .expect("render");
        assert!(plist.contains("/Users/A&amp;B/AgentDeck/current/agentdeckd"));
        assert!(!plist.contains("/Users/A&B/"));
        assert!(render_launch_agent_plist(Path::new("relative/agentdeckd")).is_err());
        assert!(validate_version_component("v_1+build").is_ok());
        assert!(validate_version_component(".").is_err());
        assert!(validate_version_component("..").is_err());
    }

    #[test]
    fn initial_install_activates_but_loaded_daemon_only_stages() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let source = source(root.path());
        let paths = DaemonInstallPaths::injected_for_test(home.clone()).expect("paths");
        let runner = FakeLaunchctl::for_paths(&paths);
        let lifecycle = DaemonLifecycle::injected_for_test(paths.clone(), runner.clone());

        let outcome = lifecycle
            .install_from_source_for_test(&installer("1.2.3"), &source)
            .expect("initial install");
        assert!(matches!(outcome, DaemonInstallOutcome::Activated { .. }));
        assert_eq!(
            fs::read_link(paths.current_link()).expect("current"),
            Path::new("1.2.3")
        );
        assert!(paths.version_daemon("1.2.3").exists());
        assert_eq!(
            fs::read_to_string(paths.plist()).expect("plist readback"),
            render_launch_agent_plist(&paths.current_daemon()).expect("golden plist")
        );
        assert_eq!(
            fs::metadata(paths.plist()).expect("plist metadata").mode() & 0o777,
            0o600
        );
        assert_eq!(runner.calls(), ["print", "bootstrap", "kickstart", "print"]);

        let outcome = lifecycle
            .install_from_source_for_test(&installer("2.0.0"), &source)
            .expect("loaded stage");
        assert!(matches!(outcome, DaemonInstallOutcome::Staged { .. }));
        assert_eq!(
            fs::read_link(paths.current_link()).expect("current"),
            Path::new("1.2.3")
        );
        assert!(paths.version_daemon("2.0.0").exists());
        assert_eq!(
            runner.calls(),
            ["print", "bootstrap", "kickstart", "print", "print"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchctl_readback_accepts_absent_pid_but_rejects_invalid_or_ambiguous_pid() {
        let base = "path = /Users/test/Library/LaunchAgents/com.agentdeck.agentdeckd.plist\n\
                    program = /Users/test/Library/Application Support/AgentDeck/bin/current/agentdeckd\n";

        let stopped = super::parse_launchctl_readback(base.as_bytes()).expect("loaded stopped job");
        assert_eq!(stopped.pid, None);

        let running = super::parse_launchctl_readback(format!("{base}pid = 42\n").as_bytes())
            .expect("loaded running job");
        assert_eq!(running.pid, Some(42));

        for invalid in [
            format!("{base}pid = 0\n"),
            format!("{base}pid = invalid\n"),
            format!("{base}pid =\n"),
            format!("{base}pid = 42\npid = 43\n"),
        ] {
            assert!(
                super::parse_launchctl_readback(invalid.as_bytes()).is_err(),
                "invalid pid readback must fail closed: {invalid:?}"
            );
        }
    }

    #[test]
    fn initial_bootstrap_requires_a_live_nonzero_pid() {
        for pid in [None, Some(0)] {
            let root = tempfile::tempdir().expect("tempdir");
            let home = root.path().join("home");
            fs::create_dir(&home).expect("home");
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            let source = source(root.path());
            let paths = DaemonInstallPaths::injected_for_test(home).expect("paths");
            let runner = FakeLaunchctl::for_paths(&paths);
            runner.set_pid(pid);
            let lifecycle = DaemonLifecycle::injected_for_test(paths, runner.clone());

            assert!(matches!(
                lifecycle.install_from_source_for_test(&installer("1.2.3"), &source),
                Err(LifecycleError::LoadedServiceMismatch)
            ));
            assert_eq!(runner.calls(), ["print", "bootstrap", "kickstart", "print"]);
        }
    }

    #[test]
    fn loaded_but_stopped_job_reports_status_stages_and_uninstalls() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let source = source(root.path());
        let paths = DaemonInstallPaths::injected_for_test(home).expect("paths");
        let runner = FakeLaunchctl::for_paths(&paths);
        let lifecycle = DaemonLifecycle::injected_for_test(paths.clone(), runner.clone());
        lifecycle
            .install_from_source_for_test(&installer("1.2.3"), &source)
            .expect("initial install");
        runner.set_pid(None);
        runner.set_kickstart_pid(5252);

        let status = lifecycle.status().expect("loaded stopped status");
        assert!(status.launchd_loaded);
        assert_eq!(status.pid, None);
        assert_eq!(status.running_program, Some(paths.current_daemon()));

        let outcome = lifecycle
            .install_from_source_for_test(&installer("2.0.0"), &source)
            .expect("loaded stopped stage");
        assert!(matches!(outcome, DaemonInstallOutcome::Staged { .. }));
        assert_eq!(
            fs::read_link(paths.current_link()).expect("current"),
            Path::new("1.2.3")
        );
        assert_eq!(
            runner.calls(),
            [
                "print",
                "bootstrap",
                "kickstart",
                "print",
                "print",
                "print",
                "kickstart",
                "print",
            ]
        );

        lifecycle.uninstall(false).expect("uninstall stopped job");
        assert!(runner.calls().contains(&"bootout"));
        assert!(!paths.bin_root().exists());
        assert!(!paths.plist().exists());
    }

    #[test]
    fn loaded_but_stopped_job_never_stages_without_live_kickstart_readback() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let source = source(root.path());
        let paths = DaemonInstallPaths::injected_for_test(home).expect("paths");
        let runner = FakeLaunchctl::for_paths(&paths);
        let lifecycle = DaemonLifecycle::injected_for_test(paths, runner.clone());
        lifecycle
            .install_from_source_for_test(&installer("1.2.3"), &source)
            .expect("initial install");
        runner.set_pid(None);

        assert!(matches!(
            lifecycle.install_from_source_for_test(&installer("2.0.0"), &source),
            Err(LifecycleError::LoadedServiceMismatch)
        ));
        assert_eq!(
            runner.calls(),
            [
                "print",
                "bootstrap",
                "kickstart",
                "print",
                "print",
                "kickstart",
                "print",
            ]
        );
    }

    #[test]
    fn purge_rejects_without_mutation_and_default_uninstall_preserves_data() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let source = source(root.path());
        let paths = DaemonInstallPaths::injected_for_test(home).expect("paths");
        let runner = FakeLaunchctl::for_paths(&paths);
        let lifecycle = DaemonLifecycle::injected_for_test(paths.clone(), runner.clone());
        lifecycle
            .install_from_source_for_test(&installer("1.2.3"), &source)
            .expect("install");
        let runtime_db = paths.data_root().join("runtime.db");
        fs::write(&runtime_db, b"keep").expect("runtime db");
        let calls_before = runner.calls();

        let error = lifecycle.uninstall(true).expect_err("purge blocked");
        assert_eq!(error.code(), "daemon.purge.remote_not_ready");
        assert_eq!(runner.calls(), calls_before);
        assert!(paths.current_link().exists());
        assert_eq!(fs::read(&runtime_db).expect("preserved"), b"keep");

        lifecycle.uninstall(false).expect("uninstall");
        assert!(!paths.bin_root().exists());
        assert!(!paths.plist().exists());
        assert_eq!(fs::read(&runtime_db).expect("preserved"), b"keep");
        assert_eq!(
            runner.calls().as_slice(),
            [
                "print",
                "bootstrap",
                "kickstart",
                "print",
                "print",
                "bootout",
                "print"
            ]
        );
    }

    #[test]
    fn injected_install_rejects_symlinked_layout_ancestor() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        let outside = root.path().join("outside");
        fs::create_dir(&home).expect("home");
        fs::create_dir(&outside).expect("outside");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        symlink(&outside, home.join("Library")).expect("Library symlink");
        let source = source(root.path());
        let paths = DaemonInstallPaths::injected_for_test(home).expect("paths");
        let runner = FakeLaunchctl::for_paths(&paths);
        let lifecycle = DaemonLifecycle::injected_for_test(paths, runner);

        assert!(
            lifecycle
                .install_from_source_for_test(&installer("1.2.3"), &source)
                .is_err()
        );
        assert!(!outside.join("Application Support/AgentDeck").exists());
    }

    #[test]
    fn status_and_uninstall_fail_closed_on_loaded_program_mismatch() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let source = source(root.path());
        let paths = DaemonInstallPaths::injected_for_test(home).expect("paths");
        let runner = FakeLaunchctl::for_paths(&paths);
        let lifecycle = DaemonLifecycle::injected_for_test(paths.clone(), runner.clone());
        lifecycle
            .install_from_source_for_test(&installer("1.2.3"), &source)
            .expect("install");
        runner.set_program("/tmp/wrong-agentdeckd");

        assert!(matches!(
            lifecycle.status(),
            Err(LifecycleError::LoadedServiceMismatch)
        ));
        assert!(matches!(
            lifecycle.uninstall(false),
            Err(LifecycleError::LoadedServiceMismatch)
        ));
        assert!(paths.bin_root().exists());
        assert!(paths.plist().exists());
        assert!(!runner.calls().contains(&"bootout"));
    }
}
