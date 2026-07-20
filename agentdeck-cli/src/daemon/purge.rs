//! `daemon uninstall --purge` 的 CLI 两阶段编排 substrate。
//!
//! CLI 先冻结 installed helper attestation 与 live launchd PID，再请求运行中 daemon
//! 完成 trust-reset/PurgeReadbackAbsent/marker readback。bootout 后必须同时读回 launchd 与 UDS
//! absent，才启动同一个 exact helper one-shot finalizer。helper 成功退出代表 marker 已
//! 删除并 readback；CLI 最后只清理无 secret 的 retained install artifact。

#![cfg(unix)]

use std::fmt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use agentdeck_protocol::runtime::{
    ArtifactSha256, LocalOnlyAdministration, MachineRemoteLifecycle, RuntimeReply, RuntimeRequest,
    TrustResetRequest, UninstallPurgePlanV1,
};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use thiserror::Error;

use super::artifact::{
    ArtifactInstaller, ArtifactVerifier, InstallError, InstallObserver, InstalledArtifact,
};
use super::launchd::{
    DaemonInstallPaths, LaunchctlRunner, LifecycleError, finish_purge_retained_cleanup_exact,
    publish_purge_retained_helper, read_current_version, sync_purge_data_root_exact,
    validate_loaded_service, validate_purge_retained_anchor_layout,
};
use crate::unix_transport::{ReplySequenceItem, RuntimeUnixClient};

const STOP_READBACK_ATTEMPTS: usize = 600;
const STOP_READBACK_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PurgeRuntimeReadback {
    pub purge_ready: bool,
    pub marker_prepared: bool,
    pub marker_plan_id: [u8; 16],
}

#[async_trait]
pub trait PurgeRuntimeClient: Send + Sync {
    async fn trust_reset_for_uninstall(
        &self,
        plan: UninstallPurgePlanV1,
    ) -> Result<PurgeRuntimeReadback, PurgeCliError>;
}

/// production stable UDS adapter。连接也延迟到 coordinator 完成 launchd/helper
/// 预检之后，避免无效安装布局触发任何 trust-reset 请求。
#[derive(Clone, Copy, Default)]
pub struct StablePurgeRuntimeClient;

#[async_trait]
impl PurgeRuntimeClient for StablePurgeRuntimeClient {
    async fn trust_reset_for_uninstall(
        &self,
        plan: UninstallPurgePlanV1,
    ) -> Result<PurgeRuntimeReadback, PurgeCliError> {
        let client = RuntimeUnixClient::connect_stable()
            .await
            .map_err(|error| PurgeCliError::runtime(error.code()))?;
        let request = TrustResetRequest::for_uninstall_purge(
            LocalOnlyAdministration::LocalOnly,
            plan.clone(),
            None,
        )
        .map_err(|_| PurgeCliError::runtime("daemon.purge.runtime_request_invalid"))?;
        let item = client
            .request(RuntimeRequest::TrustReset(request))
            .await
            .map_err(|error| PurgeCliError::runtime(error.code()))?;
        decode_runtime_readback(&plan, item)
    }
}

fn decode_runtime_readback(
    plan: &UninstallPurgePlanV1,
    item: ReplySequenceItem,
) -> Result<PurgeRuntimeReadback, PurgeCliError> {
    let status = match item {
        ReplySequenceItem::Reply(reply) => match *reply {
            RuntimeReply::MachineRemoteStatus(status) => status,
            RuntimeReply::Failure(failure) => return Err(PurgeCliError::runtime(failure.code)),
            _ => return Err(PurgeCliError::runtime("daemon.purge.runtime_reply_invalid")),
        },
        ReplySequenceItem::TransferComplete(_) => {
            return Err(PurgeCliError::runtime("daemon.purge.runtime_reply_invalid"));
        }
    };
    if !matches!(
        status.lifecycle,
        MachineRemoteLifecycle::PurgeReadbackAbsent
            | MachineRemoteLifecycle::LocalDeleted
            | MachineRemoteLifecycle::Unenrolled
    ) {
        return Err(PurgeCliError::runtime(status.failure_code.map_or_else(
            || "daemon.purge.runtime_readback_mismatch".to_owned(),
            |failure| failure.as_str().to_owned(),
        )));
    }
    Ok(PurgeRuntimeReadback {
        purge_ready: true,
        marker_prepared: true,
        marker_plan_id: *plan.plan_id(),
    })
}

pub trait PurgeArtifactVerifier: Send + Sync {
    fn verify_existing(&self, path: &Path) -> Result<InstalledArtifact, PurgeCliError>;

    fn verify_bundled_recovery_source(&self) -> Result<InstalledArtifact, PurgeCliError>;
}

impl<V: ArtifactVerifier, O: InstallObserver> PurgeArtifactVerifier for ArtifactInstaller<V, O> {
    fn verify_existing(&self, path: &Path) -> Result<InstalledArtifact, PurgeCliError> {
        self.verify_existing_artifact(path).map_err(Into::into)
    }

    fn verify_bundled_recovery_source(&self) -> Result<InstalledArtifact, PurgeCliError> {
        self.verify_bundled_daemon_recovery_source()
            .map_err(Into::into)
    }
}

pub trait PurgeSocketProbe: Send + Sync {
    fn is_absent(&self, path: &Path) -> Result<bool, PurgeCliError>;
}

pub trait PurgeProcessProbe: Send + Sync {
    fn is_absent(&self, pid: u32) -> Result<bool, PurgeCliError>;
}

#[derive(Clone, Copy, Default)]
pub struct SystemProcessProbe;

impl PurgeProcessProbe for SystemProcessProbe {
    fn is_absent(&self, pid: u32) -> Result<bool, PurgeCliError> {
        // SAFETY: signal 0 probes existence/permission without sending a signal.
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(true),
            Some(libc::EPERM) => Ok(false),
            _ => Err(PurgeCliError::Io(error)),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct FilesystemSocketProbe;

impl PurgeSocketProbe for FilesystemSocketProbe {
    fn is_absent(&self, path: &Path) -> Result<bool, PurgeCliError> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Ok(metadata) if metadata.file_type().is_socket() => Ok(false),
            Ok(_) => Err(PurgeCliError::SocketUnsafe),
            Err(error) => Err(PurgeCliError::Io(error)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeHelperCompletion {
    MarkerDeleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeTerminalProofCompletion {
    Proven,
}

#[async_trait]
pub trait PurgeHelperRunner: Send + Sync {
    async fn run(
        &self,
        helper: &Path,
        plan: &UninstallPurgePlanV1,
    ) -> Result<PurgeHelperCompletion, PurgeCliError>;

    async fn prove_terminal(
        &self,
        helper: &Path,
    ) -> Result<PurgeTerminalProofCompletion, PurgeCliError>;
}

#[derive(Clone, Copy, Default)]
pub struct ProcessPurgeHelperRunner;

#[async_trait]
impl PurgeHelperRunner for ProcessPurgeHelperRunner {
    async fn run(
        &self,
        helper: &Path,
        plan: &UninstallPurgePlanV1,
    ) -> Result<PurgeHelperCompletion, PurgeCliError> {
        let plan_id = STANDARD.encode(plan.plan_id());
        let status = tokio::process::Command::new(helper)
            .arg("--purge-finalizer")
            .arg("--purge-plan-id")
            .arg(plan_id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(PurgeCliError::Io)?;
        if !status.success() {
            return Err(PurgeCliError::HelperFailed);
        }
        Ok(PurgeHelperCompletion::MarkerDeleted)
    }

    async fn prove_terminal(
        &self,
        helper: &Path,
    ) -> Result<PurgeTerminalProofCompletion, PurgeCliError> {
        let status = tokio::process::Command::new(helper)
            .arg("--purge-terminal-proof")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(PurgeCliError::Io)?;
        if !status.success() {
            return Err(PurgeCliError::HelperFailed);
        }
        Ok(PurgeTerminalProofCompletion::Proven)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HelperFileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
}

enum DiscoveredPurgeTarget {
    Helper {
        execution_path: PathBuf,
        version_hint: Option<String>,
        anchored: bool,
    },
    AlreadyAbsent,
}

pub struct PurgeCoordinator<'a, L, A, R, S, P, H> {
    paths: &'a DaemonInstallPaths,
    launchctl: &'a L,
    artifacts: &'a A,
    runtime: &'a R,
    sockets: &'a S,
    processes: &'a P,
    helper: &'a H,
    stop_readback_attempts: usize,
}

impl<'a, L, A, R, S, P, H> PurgeCoordinator<'a, L, A, R, S, P, H> {
    pub fn new(
        paths: &'a DaemonInstallPaths,
        launchctl: &'a L,
        artifacts: &'a A,
        runtime: &'a R,
        sockets: &'a S,
        processes: &'a P,
        helper: &'a H,
    ) -> Self {
        Self {
            paths,
            launchctl,
            artifacts,
            runtime,
            sockets,
            processes,
            helper,
            stop_readback_attempts: STOP_READBACK_ATTEMPTS,
        }
    }

    #[doc(hidden)]
    pub fn with_stop_readback_attempts_for_test(mut self, attempts: usize) -> Self {
        self.stop_readback_attempts = attempts.max(1);
        self
    }
}

impl<L, A, R, S, P, H> PurgeCoordinator<'_, L, A, R, S, P, H>
where
    L: LaunchctlRunner,
    A: PurgeArtifactVerifier,
    R: PurgeRuntimeClient,
    S: PurgeSocketProbe,
    P: PurgeProcessProbe,
    H: PurgeHelperRunner,
{
    pub async fn run(&self) -> Result<(), PurgeCliError> {
        // SAFETY: geteuid reads only the current process credential.
        let uid = unsafe { libc::geteuid() };
        let live = self.launchctl.readback(uid)?;
        let target = match live.as_ref() {
            Some(live) => {
                validate_loaded_service(self.paths, live)?;
                require_purge_anchor_absent(self.paths)?;
                let version =
                    read_current_version_exact(self.paths)?.ok_or(PurgeCliError::HelperMissing)?;
                DiscoveredPurgeTarget::Helper {
                    execution_path: self.paths.version_daemon(&version),
                    version_hint: Some(version),
                    anchored: false,
                }
            }
            None => discover_stopped_recovery_target(self.paths)?,
        };
        let DiscoveredPurgeTarget::Helper {
            execution_path,
            version_hint,
            anchored,
        } = target
        else {
            if live.is_some()
                || !self
                    .sockets
                    .is_absent(&self.paths.data_root().join("agentdeckd.sock"))?
            {
                return Err(PurgeCliError::DaemonStillRunning);
            }
            require_runtime_artifacts_absent(self.paths)?;
            return self.prove_fully_absent_terminal(uid).await;
        };
        let artifact = self.artifacts.verify_existing(&execution_path)?;
        let identity = helper_identity(&execution_path)?;
        let version = version_hint.unwrap_or_else(|| artifact.version.clone());
        if artifact.path != execution_path || artifact.version != version {
            return Err(PurgeCliError::AttestationMismatch);
        }
        if anchored {
            validate_purge_retained_anchor_layout(self.paths, &version)?;
        }
        let plan_helper_path = self.paths.version_daemon(&version);
        let plan = UninstallPurgePlanV1::new(
            plan_helper_path,
            artifact.version.clone(),
            ArtifactSha256::new(hex(&artifact.sha256))
                .map_err(|_| PurgeCliError::AttestationMismatch)?,
            artifact.team_identifier.clone(),
            artifact.keychain_access_group.clone(),
        )
        .map_err(|_| PurgeCliError::AttestationMismatch)?;

        if let Some(live) = live {
            let live_pid = live
                .pid
                .filter(|pid| *pid != 0)
                .ok_or(PurgeCliError::PidMissing)?;
            let readback = self.runtime.trust_reset_for_uninstall(plan.clone()).await?;
            if !readback.purge_ready
                || !readback.marker_prepared
                || readback.marker_plan_id != *plan.plan_id()
            {
                return Err(PurgeCliError::RuntimeReadbackMismatch);
            }

            self.launchctl.bootout(uid)?;
            let mut stopped = false;
            for _ in 0..self.stop_readback_attempts {
                match self.launchctl.readback(uid)? {
                    None if self.processes.is_absent(live_pid)?
                        && self
                            .sockets
                            .is_absent(&self.paths.data_root().join("agentdeckd.sock"))? =>
                    {
                        stopped = true;
                        break;
                    }
                    Some(readback) => {
                        validate_loaded_service(self.paths, &readback)?;
                        if readback.pid.is_some_and(|pid| pid != live_pid) {
                            return Err(PurgeCliError::PidChanged);
                        }
                    }
                    None => {}
                }
                tokio::time::sleep(STOP_READBACK_INTERVAL).await;
            }
            if !stopped {
                return Err(PurgeCliError::DaemonStillRunning);
            }
        } else if !self
            .sockets
            .is_absent(&self.paths.data_root().join("agentdeckd.sock"))?
        {
            return Err(PurgeCliError::DaemonStillRunning);
        }

        let second = self.artifacts.verify_existing(&execution_path)?;
        if second != artifact || helper_identity(&execution_path)? != identity {
            return Err(PurgeCliError::AttestationChanged);
        }
        let completion = self.helper.run(&execution_path, &plan).await?;
        if completion != PurgeHelperCompletion::MarkerDeleted {
            return Err(PurgeCliError::HelperFailed);
        }
        let final_readback = self.artifacts.verify_existing(&execution_path)?;
        if final_readback != artifact || helper_identity(&execution_path)? != identity {
            return Err(PurgeCliError::AttestationChanged);
        }
        if anchored {
            validate_purge_retained_anchor_layout(self.paths, &version)?;
        } else {
            validate_retained_cleanup_layout(self.paths, &execution_path, identity)?;
            let anchor = publish_purge_retained_helper(self.paths, &version)?;
            let relocated = self.artifacts.verify_existing(&anchor)?;
            let mut expected = artifact.clone();
            expected.path = anchor.clone();
            if relocated != expected || helper_identity(&anchor)? != identity {
                return Err(PurgeCliError::AttestationChanged);
            }
            validate_purge_retained_anchor_layout(self.paths, &version)?;
        }
        finish_purge_retained_cleanup_exact(self.paths, &version)?;
        if self.paths.purge_retained_helper().exists() || self.paths.bin_root().exists() {
            return Err(PurgeCliError::CleanupReadbackFailed);
        }
        Ok(())
    }

    async fn prove_fully_absent_terminal(&self, uid: u32) -> Result<(), PurgeCliError> {
        let artifact = self.artifacts.verify_bundled_recovery_source()?;
        let identity = recovery_helper_identity(&artifact.path)?;
        if self.helper.prove_terminal(&artifact.path).await? != PurgeTerminalProofCompletion::Proven
        {
            return Err(PurgeCliError::HelperFailed);
        }

        if self.launchctl.readback(uid)?.is_some()
            || !self
                .sockets
                .is_absent(&self.paths.data_root().join("agentdeckd.sock"))?
            || !matches!(
                discover_stopped_recovery_target(self.paths)?,
                DiscoveredPurgeTarget::AlreadyAbsent
            )
        {
            return Err(PurgeCliError::DaemonStillRunning);
        }
        require_runtime_artifacts_absent(self.paths)?;
        sync_purge_data_root_exact(self.paths)?;
        if self.launchctl.readback(uid)?.is_some()
            || !self
                .sockets
                .is_absent(&self.paths.data_root().join("agentdeckd.sock"))?
            || !matches!(
                discover_stopped_recovery_target(self.paths)?,
                DiscoveredPurgeTarget::AlreadyAbsent
            )
        {
            return Err(PurgeCliError::DaemonStillRunning);
        }
        require_runtime_artifacts_absent(self.paths)?;
        let second = self.artifacts.verify_bundled_recovery_source()?;
        if second != artifact || recovery_helper_identity(&artifact.path)? != identity {
            return Err(PurgeCliError::AttestationChanged);
        }
        Ok(())
    }
}

fn read_current_version_exact(paths: &DaemonInstallPaths) -> Result<Option<String>, PurgeCliError> {
    let Some(version) = read_current_version(paths)? else {
        return Ok(None);
    };
    let metadata = std::fs::symlink_metadata(paths.current_link()).map_err(PurgeCliError::Io)?;
    if !metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
    {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    Ok(Some(version))
}

fn discover_stopped_recovery_target(
    paths: &DaemonInstallPaths,
) -> Result<DiscoveredPurgeTarget, PurgeCliError> {
    let current = read_current_version_exact(paths)?;
    let anchor_present = purge_anchor_present(paths)?;
    if current.is_some() && anchor_present {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    if let Some(version) = current {
        return Ok(DiscoveredPurgeTarget::Helper {
            execution_path: paths.version_daemon(&version),
            version_hint: Some(version),
            anchored: false,
        });
    }
    require_absent_for_recovery(paths.plist())?;
    if anchor_present {
        validate_stopped_anchor_prefix(paths)?;
        return Ok(DiscoveredPurgeTarget::Helper {
            execution_path: paths.purge_retained_helper(),
            version_hint: None,
            anchored: true,
        });
    }
    let bin = match std::fs::symlink_metadata(paths.bin_root()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DiscoveredPurgeTarget::AlreadyAbsent);
        }
        Err(error) => return Err(PurgeCliError::Io(error)),
    };
    if !bin.file_type().is_dir()
        || bin.file_type().is_symlink()
        || bin.uid() != unsafe { libc::geteuid() }
        || bin.permissions().mode() & 0o7777 != 0o700
    {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    let entries = std::fs::read_dir(paths.bin_root())
        .map_err(PurgeCliError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(PurgeCliError::Io)?;
    if entries.len() != 1 {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    let version = entries[0]
        .file_name()
        .into_string()
        .map_err(|_| PurgeCliError::StoppedRecoveryUnsafe)?;
    if !valid_version_component(&version) {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    validate_single_helper_directory(&entries[0].path(), paths.version_daemon(&version).as_path())?;
    Ok(DiscoveredPurgeTarget::Helper {
        execution_path: paths.version_daemon(&version),
        version_hint: Some(version),
        anchored: false,
    })
}

fn require_purge_anchor_absent(paths: &DaemonInstallPaths) -> Result<(), PurgeCliError> {
    if purge_anchor_present(paths)? {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    Ok(())
}

fn purge_anchor_present(paths: &DaemonInstallPaths) -> Result<bool, PurgeCliError> {
    match std::fs::symlink_metadata(paths.purge_retained_helper()) {
        Ok(_) => {
            helper_identity(&paths.purge_retained_helper())?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(PurgeCliError::Io(error)),
    }
}

fn validate_stopped_anchor_prefix(paths: &DaemonInstallPaths) -> Result<(), PurgeCliError> {
    let bin = match std::fs::symlink_metadata(paths.bin_root()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(PurgeCliError::Io(error)),
    };
    if !bin.file_type().is_dir()
        || bin.file_type().is_symlink()
        || bin.uid() != unsafe { libc::geteuid() }
        || bin.nlink() == 0
        || bin.permissions().mode() & 0o7777 != 0o700
    {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    let entries = std::fs::read_dir(paths.bin_root())
        .map_err(PurgeCliError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(PurgeCliError::Io)?;
    if entries.is_empty() {
        return Ok(());
    }
    if entries.len() != 1 {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    let version = entries[0]
        .file_name()
        .into_string()
        .map_err(|_| PurgeCliError::StoppedRecoveryUnsafe)?;
    if !valid_version_component(&version) {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    let directory = entries[0].path();
    let metadata = std::fs::symlink_metadata(&directory).map_err(PurgeCliError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() == 0
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    if std::fs::read_dir(&directory)
        .map_err(PurgeCliError::Io)?
        .next()
        .transpose()
        .map_err(PurgeCliError::Io)?
        .is_some()
    {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    Ok(())
}

fn validate_retained_cleanup_layout(
    paths: &DaemonInstallPaths,
    helper: &Path,
    expected_identity: HelperFileIdentity,
) -> Result<(), PurgeCliError> {
    require_absent_for_recovery(paths.plist())?;
    require_absent_for_recovery(&paths.current_link())?;
    let entries = std::fs::read_dir(paths.bin_root())
        .map_err(PurgeCliError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(PurgeCliError::Io)?;
    if entries.len() != 1 || entries[0].path() != helper.parent().unwrap_or(Path::new("")) {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    validate_single_helper_directory(&entries[0].path(), helper)?;
    if helper_identity(helper)? != expected_identity {
        return Err(PurgeCliError::AttestationChanged);
    }
    Ok(())
}

fn validate_single_helper_directory(directory: &Path, helper: &Path) -> Result<(), PurgeCliError> {
    let metadata = std::fs::symlink_metadata(directory).map_err(PurgeCliError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    let children = std::fs::read_dir(directory)
        .map_err(PurgeCliError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(PurgeCliError::Io)?;
    if children.len() != 1 || children[0].path() != helper {
        return Err(PurgeCliError::StoppedRecoveryUnsafe);
    }
    helper_identity(helper)?;
    Ok(())
}

fn require_absent_for_recovery(path: &Path) -> Result<(), PurgeCliError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(PurgeCliError::StoppedRecoveryUnsafe),
        Err(error) => Err(PurgeCliError::Io(error)),
    }
}

fn require_runtime_artifacts_absent(paths: &DaemonInstallPaths) -> Result<(), PurgeCliError> {
    let runtime_db = paths.data_root().join("runtime.db");
    let mut wal = runtime_db.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = runtime_db.as_os_str().to_os_string();
    shm.push("-shm");
    for artifact in [runtime_db, PathBuf::from(wal), PathBuf::from(shm)] {
        require_absent_for_recovery(&artifact)?;
    }
    Ok(())
}

fn valid_version_component(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !matches!(version, "." | "..")
        && PathBuf::from(version).components().count() == 1
        && Path::new(version)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn helper_identity(path: &Path) -> Result<HelperFileIdentity, PurgeCliError> {
    let metadata = std::fs::symlink_metadata(path).map_err(PurgeCliError::Io)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o500
    {
        return Err(PurgeCliError::HelperUnsafe);
    }
    Ok(HelperFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o7777,
        links: metadata.nlink(),
    })
}

fn recovery_helper_identity(path: &Path) -> Result<HelperFileIdentity, PurgeCliError> {
    let metadata = std::fs::symlink_metadata(path).map_err(PurgeCliError::Io)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || mode & 0o111 == 0
        || mode & u32::from(libc::S_ISUID | libc::S_ISGID) != 0
    {
        return Err(PurgeCliError::HelperUnsafe);
    }
    Ok(HelperFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode,
        links: metadata.nlink(),
    })
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Error)]
pub enum PurgeCliError {
    #[error("daemon purge artifact verification failed")]
    Artifact(#[from] InstallError),
    #[error("daemon purge launchd lifecycle failed")]
    Lifecycle(#[from] LifecycleError),
    #[error("daemon purge requires a running installed daemon")]
    DaemonNotRunning,
    #[error("daemon purge live PID is unavailable")]
    PidMissing,
    #[error("daemon purge live PID changed during stop readback")]
    PidChanged,
    #[error("daemon purge helper is missing")]
    HelperMissing,
    #[error("daemon purge helper is unsafe")]
    HelperUnsafe,
    #[error("daemon purge helper attestation is invalid")]
    AttestationMismatch,
    #[error("daemon purge helper attestation changed")]
    AttestationChanged,
    #[error("daemon purge Runtime readback does not confirm PurgeReadbackAbsent and marker")]
    RuntimeReadbackMismatch,
    #[error("daemon purge Runtime request failed")]
    Runtime { code: String },
    #[error("daemon purge socket entry is unsafe")]
    SocketUnsafe,
    #[error("daemon purge stop readback did not converge")]
    DaemonStillRunning,
    #[error("daemon purge helper finalizer failed")]
    HelperFailed,
    #[error("daemon purge retained helper cleanup readback failed")]
    CleanupReadbackFailed,
    #[error("daemon purge stopped recovery layout is unsafe or ambiguous")]
    StoppedRecoveryUnsafe,
    #[error("daemon purge IO failed")]
    Io(#[source] std::io::Error),
}

impl PurgeCliError {
    fn runtime(code: impl Into<String>) -> Self {
        Self::Runtime { code: code.into() }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Artifact(error) => error.code(),
            Self::Lifecycle(error) => error.code(),
            Self::DaemonNotRunning => "daemon.purge.daemon_not_running",
            Self::PidMissing => "daemon.purge.pid_missing",
            Self::PidChanged => "daemon.purge.pid_changed",
            Self::HelperMissing => "daemon.purge.helper_missing",
            Self::HelperUnsafe => "daemon.purge.helper_unsafe",
            Self::AttestationMismatch => "daemon.purge.attestation_mismatch",
            Self::AttestationChanged => "daemon.purge.attestation_changed",
            Self::RuntimeReadbackMismatch => "daemon.purge.runtime_readback_mismatch",
            Self::Runtime { code } => code,
            Self::SocketUnsafe => "daemon.purge.socket_unsafe",
            Self::DaemonStillRunning => "daemon.purge.daemon_still_running",
            Self::HelperFailed => "daemon.purge.helper_failed",
            Self::CleanupReadbackFailed => "daemon.purge.cleanup_readback_failed",
            Self::StoppedRecoveryUnsafe => "daemon.purge.stopped_recovery_unsafe",
            Self::Io(_) => "daemon.purge.io_failed",
        }
    }
}

impl fmt::Debug for PurgeCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PurgeCliError")
            .field("code", &self.code())
            .finish()
    }
}

#[cfg(test)]
#[path = "purge_tests.rs"]
mod tests;
