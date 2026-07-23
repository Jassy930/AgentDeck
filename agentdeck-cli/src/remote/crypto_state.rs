//! Persistent remote client 的本地 sealed CryptoState 文件。
//!
//! 本层使用独立 `DeviceStorageKek` 与随机 nonce 的 ChaCha20-Poly1305；不会复用
//! Relay transport counter/nonce 或 HPKE。首次发布固定为 private temp → backup exclusion
//! readback → file fsync → no-replace rename → parent fsync；后续 existing-only CAS 使用相同
//! durable temp 流程再 atomic replace。既有文件异常或 expected 不匹配时零修复拒绝。

#![cfg(unix)]

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use agentdeck_protocol::relay_v2::MachineRouteId;
use agentdeck_protocol::runtime::MachineRootFingerprint;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CRYPTO_STATE_PLAINTEXT_LEN: usize = 128 * 1024 * 1024;
pub const CRYPTO_STATE_V1_HEADER_LEN: usize = 24;
pub const CRYPTO_STATE_V1_OVERHEAD_LEN: usize = CRYPTO_STATE_V1_HEADER_LEN + 16;

const MAGIC: &[u8; 4] = b"ADCS";
const FORMAT_VERSION: u8 = 1;
const ALGORITHM_CHACHA20_POLY1305: u8 = 1;
const NONCE_LEN: usize = 12;
const DEVICES_DIRECTORY: &str = "devices";
const STATE_FILE_SUFFIX: &str = ".crypto-state.v1";
const PREPARED_STAGE_FILE_SUFFIX: &str = ".crypto-state-stage.v1";
const STATE_FILE_HASH_DOMAIN: &[u8] = b"agentdeck.remote.crypto-state-file.v1\0";
const AAD_DOMAIN: &[u8] = b"AgentDeck/CryptoStateFileV1\0";
const AAD_CLIENT_KIND: &[u8] = b"cli";
const AAD_PURPOSE: &[u8] = b"crypto-state.v1";
const PREPARED_STAGE_AAD_PURPOSE: &[u8] = b"crypto-state-prepared-stage.v1";
const PREPARED_STAGE_MAGIC: &[u8; 4] = b"ADST";
const PREPARED_STAGE_VERSION: u16 = 1;
const PREPARED_STAGE_FIXED_LEN: usize = 4 + 2 + 2 + 16 + 32 + 32 + 32 + 4;
const MAX_PREPARED_STAGE_PLAINTEXT_LEN: usize =
    MAX_CRYPTO_STATE_PLAINTEXT_LEN + PREPARED_STAGE_FIXED_LEN;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CryptoStateIdentity {
    installation_id: Uuid,
    machine_root_fingerprint: MachineRootFingerprint,
    machine_route: MachineRouteId,
}

impl CryptoStateIdentity {
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

    fn installation_component(self) -> String {
        self.installation_id.hyphenated().to_string()
    }

    fn file_component(self, suffix: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(STATE_FILE_HASH_DOMAIN);
        hasher.update(self.installation_id.as_bytes());
        hasher.update(self.machine_root_fingerprint.as_bytes());
        hasher.update(self.machine_route.as_bytes());
        let digest = hasher.finalize();
        let mut component = String::with_capacity(digest.len() * 2 + suffix.len());
        for byte in digest {
            use fmt::Write as _;
            write!(&mut component, "{byte:02x}").expect("writing to String cannot fail");
        }
        component.push_str(suffix);
        component
    }

    fn state_file_component(self) -> String {
        self.file_component(STATE_FILE_SUFFIX)
    }

    fn prepared_stage_file_component(self) -> String {
        self.file_component(PREPARED_STAGE_FILE_SUFFIX)
    }
}

impl fmt::Debug for CryptoStateIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CryptoStateIdentity([REDACTED])")
    }
}

/// CLI device-scoped CryptoState AEAD key；不实现 `Clone`/`Serialize`。
pub struct DeviceStorageKek([u8; 32]);

impl DeviceStorageKek {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DeviceStorageKek {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceStorageKek([REDACTED])")
    }
}

impl Drop for DeviceStorageKek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 上层 canonical CryptoState 的 opaque bytes；语义 decoder 由后续 paired state 层负责。
pub struct CryptoStateSnapshot(Vec<u8>);

impl CryptoStateSnapshot {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CryptoStateSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CryptoStateSnapshot([REDACTED])")
    }
}

impl Drop for CryptoStateSnapshot {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 已用独立 AAD purpose 认证的 prepared exact-next sidecar。
///
/// 字段仅供 paired state 层完成 guard/state 一致性审计；不会暴露 StorageKEK。
pub(crate) struct PreparedCryptoStateStage {
    mutation_id: [u8; 16],
    previous_guard_hash: [u8; 32],
    previous_state_hash: [u8; 32],
    next_state_hash: [u8; 32],
    snapshot: CryptoStateSnapshot,
    sealed_commitment: [u8; 32],
}

struct DecodedPreparedStage {
    mutation_id: [u8; 16],
    previous_guard_hash: [u8; 32],
    previous_state_hash: [u8; 32],
    next_state_hash: [u8; 32],
    snapshot: Vec<u8>,
}

impl fmt::Debug for PreparedCryptoStateStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedCryptoStateStage([REDACTED])")
    }
}

impl PreparedCryptoStateStage {
    pub(crate) const fn mutation_id(&self) -> [u8; 16] {
        self.mutation_id
    }

    pub(crate) const fn previous_state_hash(&self) -> [u8; 32] {
        self.previous_state_hash
    }

    pub(crate) const fn previous_guard_hash(&self) -> [u8; 32] {
        self.previous_guard_hash
    }

    pub(crate) const fn next_state_hash(&self) -> [u8; 32] {
        self.next_state_hash
    }

    pub(crate) const fn sealed_commitment(&self) -> [u8; 32] {
        self.sealed_commitment
    }

    pub(crate) const fn snapshot(&self) -> &CryptoStateSnapshot {
        &self.snapshot
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoStateCommit {
    Created,
    AlreadyPresent,
}

/// 只供 library automatic harness 把 honest first-create 竞态固定在 preflight 之后。
/// production CLI 不构造该 observer，也没有环境变量或配置入口。
#[doc(hidden)]
pub trait InitialCryptoStateCommitObserver: Send + Sync {
    fn after_preflight_absent(&self);
}

/// 只供 library automatic harness 在 durable replace 的逐边界终止子进程。
/// production CLI 不构造该 observer，也没有环境变量或配置入口。
#[doc(hidden)]
pub trait CryptoStateReplaceObserver: Send + Sync {
    fn after_stage(&self, stage: CryptoStateReplaceStage);
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoStateReplaceStage {
    TempCreated,
    TempWritten,
    BackupExcluded,
    FileSynced,
    Renamed,
    ParentSynced,
}

#[derive(Debug, Error)]
pub enum CryptoStateError {
    #[error("crypto-state root is invalid")]
    InvalidRoot,
    #[error("unsafe crypto-state directory: {reason}")]
    UnsafeDirectory { reason: &'static str },
    #[error("unsafe crypto-state file: {reason}")]
    UnsafeFile { reason: &'static str },
    #[error("crypto-state input exceeds the 128 MiB limit")]
    InputTooLarge,
    #[error("crypto-state file has an invalid format")]
    InvalidFormat,
    #[error("crypto-state authentication failed")]
    AuthenticationFailed,
    #[error("crypto-state entropy source is unavailable")]
    EntropyUnavailable,
    #[error("crypto-state backup exclusion is missing or unavailable")]
    BackupExclusion,
    #[error("crypto-state immutable initial value conflicts with durable state")]
    ImmutableConflict,
    #[error("crypto-state existing value is missing")]
    Missing,
    #[error("crypto-state compare-and-swap expected value conflicts with durable state")]
    CompareAndSwapConflict,
    #[error("crypto-state exact readback failed after publication")]
    PersistenceReadbackFailed,
    #[error("crypto-state atomic no-replace publication is unsupported")]
    NoReplaceUnsupported,
    #[error("crypto-state {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

impl CryptoStateError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InputTooLarge => "remote.crypto_state.input_too_large",
            Self::ImmutableConflict => "remote.crypto_state.immutable_conflict",
            Self::Missing => "remote.crypto_state.missing",
            Self::CompareAndSwapConflict => "remote.crypto_state.cas_conflict",
            Self::InvalidRoot | Self::UnsafeDirectory { .. } => {
                "remote.crypto_state.directory_unsafe"
            }
            Self::UnsafeFile { .. } => "remote.crypto_state.file_unsafe",
            Self::InvalidFormat => "remote.crypto_state.invalid_format",
            Self::AuthenticationFailed => "remote.crypto_state.authentication_failed",
            Self::EntropyUnavailable => "remote.crypto_state.entropy_unavailable",
            Self::BackupExclusion => "remote.crypto_state.backup_exclusion_failed",
            Self::PersistenceReadbackFailed => "remote.crypto_state.persistence_failed",
            Self::NoReplaceUnsupported => "remote.crypto_state.platform_unsupported",
            Self::Io { .. } => "remote.crypto_state.io_failed",
        }
    }
}

pub struct FileCryptoStateStore {
    root: PathBuf,
    state_path: PathBuf,
    prepared_stage_path: PathBuf,
    identity: CryptoStateIdentity,
    kek: DeviceStorageKek,
    initial_commit_observer: Option<Arc<dyn InitialCryptoStateCommitObserver>>,
    replace_observer: Option<Arc<dyn CryptoStateReplaceObserver>>,
}

impl fmt::Debug for FileCryptoStateStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileCryptoStateStore")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl FileCryptoStateStore {
    /// Library/automatic constructor。production CLI 后续只会从 passwd-derived root 调用。
    pub fn new_in(
        root: &Path,
        identity: CryptoStateIdentity,
        kek: DeviceStorageKek,
    ) -> Result<Self, CryptoStateError> {
        Self::new_in_inner(root, identity, kek, None, None)
    }

    /// 仅供 automatic library harness 确定性覆盖 no-replace lost-race 分支。
    #[doc(hidden)]
    pub fn new_in_with_initial_commit_observer(
        root: &Path,
        identity: CryptoStateIdentity,
        kek: DeviceStorageKek,
        observer: Arc<dyn InitialCryptoStateCommitObserver>,
    ) -> Result<Self, CryptoStateError> {
        Self::new_in_inner(root, identity, kek, Some(observer), None)
    }

    /// 仅供 automatic library harness 逐边界终止 replace 子进程。
    #[doc(hidden)]
    pub fn new_in_with_replace_observer(
        root: &Path,
        identity: CryptoStateIdentity,
        kek: DeviceStorageKek,
        observer: Arc<dyn CryptoStateReplaceObserver>,
    ) -> Result<Self, CryptoStateError> {
        Self::new_in_inner(root, identity, kek, None, Some(observer))
    }

    fn new_in_inner(
        root: &Path,
        identity: CryptoStateIdentity,
        kek: DeviceStorageKek,
        initial_commit_observer: Option<Arc<dyn InitialCryptoStateCommitObserver>>,
        replace_observer: Option<Arc<dyn CryptoStateReplaceObserver>>,
    ) -> Result<Self, CryptoStateError> {
        absolute_normal_components(root)?;
        let state_path = root
            .join(identity.installation_component())
            .join(DEVICES_DIRECTORY)
            .join(identity.state_file_component());
        let prepared_stage_path = root
            .join(identity.installation_component())
            .join(DEVICES_DIRECTORY)
            .join(identity.prepared_stage_file_component());
        Ok(Self {
            root: root.to_path_buf(),
            state_path,
            prepared_stage_path,
            identity,
            kek,
            initial_commit_observer,
            replace_observer,
        })
    }

    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    #[must_use]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// 仅供 automatic harness 检查 prepared sidecar 的文件安全属性与 crash 生命周期。
    #[doc(hidden)]
    #[must_use]
    pub fn prepared_stage_path(&self) -> &Path {
        &self.prepared_stage_path
    }

    pub fn load(&self) -> Result<Option<CryptoStateSnapshot>, CryptoStateError> {
        let uid = current_euid();
        let Some(directories) = self.open_existing_directories(uid)? else {
            return Ok(None);
        };
        let state_component = self.identity.state_file_component();
        let Some(mut file) = open_state_file(
            &directories.devices,
            &state_component,
            &self.state_path,
            uid,
        )?
        else {
            return Ok(None);
        };

        if !read_backup_excluded(&file, &self.state_path)? {
            return Err(CryptoStateError::BackupExclusion);
        }
        validate_state_entry(&directories.devices, &state_component, &file, uid)?;
        let sealed = read_sealed_file(&mut file)?;
        let snapshot = CryptoStateSnapshot::new(open_snapshot(&self.identity, &self.kek, &sealed)?);
        validate_state_entry(&directories.devices, &state_component, &file, uid)?;
        Ok(Some(snapshot))
    }

    pub fn backup_excluded(&self) -> Result<bool, CryptoStateError> {
        let uid = current_euid();
        let Some(directories) = self.open_existing_directories(uid)? else {
            return Ok(false);
        };
        let state_component = self.identity.state_file_component();
        let Some(file) = open_state_file(
            &directories.devices,
            &state_component,
            &self.state_path,
            uid,
        )?
        else {
            return Ok(false);
        };
        let excluded = read_backup_excluded(&file, &self.state_path)?;
        validate_state_entry(&directories.devices, &state_component, &file, uid)?;
        Ok(excluded)
    }

    /// 仅供 automatic harness 读取 sidecar backup-exclusion 属性，不创建或修复文件。
    #[doc(hidden)]
    pub fn prepared_stage_backup_excluded(&self) -> Result<bool, CryptoStateError> {
        let uid = current_euid();
        let Some(directories) = self.open_existing_directories(uid)? else {
            return Ok(false);
        };
        let component = self.identity.prepared_stage_file_component();
        let Some(file) = open_state_file(
            &directories.devices,
            &component,
            &self.prepared_stage_path,
            uid,
        )?
        else {
            return Ok(false);
        };
        let excluded = read_backup_excluded(&file, &self.prepared_stage_path)?;
        validate_state_entry(&directories.devices, &component, &file, uid)?;
        Ok(excluded)
    }

    pub fn commit_initial(
        &self,
        snapshot: &CryptoStateSnapshot,
    ) -> Result<CryptoStateCommit, CryptoStateError> {
        if snapshot.expose_secret().len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN {
            return Err(CryptoStateError::InputTooLarge);
        }
        if let Some(existing) = self.load()? {
            return if existing.expose_secret() == snapshot.expose_secret() {
                Ok(CryptoStateCommit::AlreadyPresent)
            } else {
                Err(CryptoStateError::ImmutableConflict)
            };
        }
        if let Some(observer) = &self.initial_commit_observer {
            observer.after_preflight_absent();
        }

        let uid = current_euid();
        let directories = self.open_or_create_directories(uid)?;
        let sealed = seal_snapshot(&self.identity, &self.kek, snapshot.expose_secret())?;
        let (mut temp, mut guard) = create_temp_file(&directories.devices, &self.state_path, uid)?;
        temp.write_all(&sealed)
            .map_err(|source| io_error("write temp", source))?;
        mark_backup_excluded(&temp, guard.path())?;
        if !read_backup_excluded(&temp, guard.path())? {
            return Err(CryptoStateError::BackupExclusion);
        }
        validate_state_entry(&directories.devices, guard.component_str(), &temp, uid)?;
        temp.sync_all()
            .map_err(|source| io_error("sync temp", source))?;
        validate_state_entry(&directories.devices, guard.component_str(), &temp, uid)?;

        let state_component = self.identity.state_file_component();
        match rename_no_replace(
            directories.devices.as_raw_fd(),
            guard.name(),
            &state_component,
        )? {
            PublishOutcome::Published => {
                guard.disarm();
                directories
                    .devices
                    .sync_all()
                    .map_err(|source| io_error("sync state parent", source))?;
                self.readback_commit(snapshot, CryptoStateCommit::Created)
            }
            PublishOutcome::LostRace => {
                guard.remove_now()?;
                directories
                    .devices
                    .sync_all()
                    .map_err(|source| io_error("sync lost-race cleanup", source))?;
                self.readback_commit(snapshot, CryptoStateCommit::AlreadyPresent)
            }
        }
    }

    /// 用已认证旧 plaintext 作为 expected，对既有 CryptoState 做 durable atomic replace。
    ///
    /// 缺文件、旧文件认证失败、或 SHA-256 与 exact bytes 任一不等时均在创建 temp 前拒绝；
    /// 本方法不会创建首个 state，也不会修复异常的目录、文件或 crash artifact。
    pub fn compare_and_replace(
        &self,
        expected: &CryptoStateSnapshot,
        replacement: &CryptoStateSnapshot,
    ) -> Result<(), CryptoStateError> {
        if expected.expose_secret().len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN
            || replacement.expose_secret().len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN
        {
            return Err(CryptoStateError::InputTooLarge);
        }

        let uid = current_euid();
        let directories = self
            .open_existing_directories(uid)?
            .ok_or(CryptoStateError::Missing)?;
        let state_component = self.identity.state_file_component();
        let mut current = open_state_file(
            &directories.devices,
            &state_component,
            &self.state_path,
            uid,
        )?
        .ok_or(CryptoStateError::Missing)?;
        if !read_backup_excluded(&current, &self.state_path)? {
            return Err(CryptoStateError::BackupExclusion);
        }
        validate_state_entry(&directories.devices, &state_component, &current, uid)?;
        let current_sealed = read_sealed_file(&mut current)?;
        let current_plaintext =
            Zeroizing::new(open_snapshot(&self.identity, &self.kek, &current_sealed)?);
        validate_state_entry(&directories.devices, &state_component, &current, uid)?;
        if !snapshot_hash_and_bytes_match(&current_plaintext, expected.expose_secret()) {
            return Err(CryptoStateError::CompareAndSwapConflict);
        }
        drop(current_plaintext);
        drop(current);

        let sealed = seal_snapshot(&self.identity, &self.kek, replacement.expose_secret())?;
        let (mut temp, mut guard) = create_temp_file(&directories.devices, &self.state_path, uid)?;
        self.observe_replace_stage(CryptoStateReplaceStage::TempCreated);
        temp.write_all(&sealed)
            .map_err(|source| io_error("write replacement temp", source))?;
        self.observe_replace_stage(CryptoStateReplaceStage::TempWritten);
        mark_backup_excluded(&temp, guard.path())?;
        if !read_backup_excluded(&temp, guard.path())? {
            return Err(CryptoStateError::BackupExclusion);
        }
        self.observe_replace_stage(CryptoStateReplaceStage::BackupExcluded);
        validate_state_entry(&directories.devices, guard.component_str(), &temp, uid)?;
        temp.sync_all()
            .map_err(|source| io_error("sync replacement temp", source))?;
        validate_state_entry(&directories.devices, guard.component_str(), &temp, uid)?;
        self.observe_replace_stage(CryptoStateReplaceStage::FileSynced);

        rename_replace(
            directories.devices.as_raw_fd(),
            guard.name(),
            &state_component,
        )?;
        guard.disarm();
        self.observe_replace_stage(CryptoStateReplaceStage::Renamed);
        directories
            .devices
            .sync_all()
            .map_err(|source| io_error("sync replacement parent", source))?;
        self.observe_replace_stage(CryptoStateReplaceStage::ParentSynced);

        match self.load()? {
            Some(actual)
                if snapshot_hash_and_bytes_match(
                    actual.expose_secret(),
                    replacement.expose_secret(),
                ) =>
            {
                Ok(())
            }
            Some(_) | None => Err(CryptoStateError::PersistenceReadbackFailed),
        }
    }

    /// 在 active state 仍精确等于 `expected_active` 时，durable 发布唯一 prepared sidecar。
    ///
    /// sidecar 使用同一 StorageKEK、独立 AAD purpose，并冻结 mutation id、previous/next
    /// hash 与 exact next snapshot。既有 sidecar（包括损坏项）一律在创建 temp 前拒绝。
    pub(crate) fn prepare_stage(
        &self,
        expected_active: &CryptoStateSnapshot,
        previous_guard_hash: [u8; 32],
        mutation_id: [u8; 16],
        next_snapshot: &CryptoStateSnapshot,
    ) -> Result<PreparedCryptoStateStage, CryptoStateError> {
        validate_prepared_stage_fields(
            mutation_id,
            previous_guard_hash,
            sha256_bytes(expected_active.expose_secret()),
            sha256_bytes(next_snapshot.expose_secret()),
            next_snapshot.expose_secret(),
        )?;
        if self.load_prepared_stage()?.is_some() {
            return Err(CryptoStateError::ImmutableConflict);
        }
        let active = self.load()?.ok_or(CryptoStateError::Missing)?;
        if !snapshot_hash_and_bytes_match(active.expose_secret(), expected_active.expose_secret()) {
            return Err(CryptoStateError::CompareAndSwapConflict);
        }

        let plaintext = Zeroizing::new(encode_prepared_stage(
            mutation_id,
            previous_guard_hash,
            expected_active.expose_secret(),
            next_snapshot.expose_secret(),
        )?);
        let sealed = seal_snapshot_with_purpose(
            &self.identity,
            &self.kek,
            PREPARED_STAGE_AAD_PURPOSE,
            plaintext.as_slice(),
            MAX_PREPARED_STAGE_PLAINTEXT_LEN,
        )?;
        let sealed_commitment = sha256_bytes(&sealed);
        let uid = current_euid();
        let directories = self
            .open_existing_directories(uid)?
            .ok_or(CryptoStateError::Missing)?;
        let (mut temp, mut guard) =
            create_temp_file(&directories.devices, &self.prepared_stage_path, uid)?;
        temp.write_all(&sealed)
            .map_err(|source| io_error("write prepared stage temp", source))?;
        mark_backup_excluded(&temp, guard.path())?;
        if !read_backup_excluded(&temp, guard.path())? {
            return Err(CryptoStateError::BackupExclusion);
        }
        validate_state_entry(&directories.devices, guard.component_str(), &temp, uid)?;
        temp.sync_all()
            .map_err(|source| io_error("sync prepared stage temp", source))?;
        validate_state_entry(&directories.devices, guard.component_str(), &temp, uid)?;

        let component = self.identity.prepared_stage_file_component();
        match rename_no_replace(directories.devices.as_raw_fd(), guard.name(), &component)? {
            PublishOutcome::Published => guard.disarm(),
            PublishOutcome::LostRace => {
                guard.remove_now()?;
                directories
                    .devices
                    .sync_all()
                    .map_err(|source| io_error("sync prepared stage lost-race cleanup", source))?;
                return Err(CryptoStateError::ImmutableConflict);
            }
        }
        directories
            .devices
            .sync_all()
            .map_err(|source| io_error("sync prepared stage parent", source))?;

        let prepared = self
            .load_prepared_stage()?
            .ok_or(CryptoStateError::PersistenceReadbackFailed)?;
        if prepared.mutation_id == mutation_id
            && prepared.previous_guard_hash == previous_guard_hash
            && prepared.previous_state_hash == sha256_bytes(expected_active.expose_secret())
            && prepared.next_state_hash == sha256_bytes(next_snapshot.expose_secret())
            && prepared.sealed_commitment == sealed_commitment
            && snapshot_hash_and_bytes_match(
                prepared.snapshot.expose_secret(),
                next_snapshot.expose_secret(),
            )
        {
            Ok(prepared)
        } else {
            Err(CryptoStateError::PersistenceReadbackFailed)
        }
    }

    /// 只读打开 prepared sidecar；缺失返回 `None`，异常项不修复。
    pub(crate) fn load_prepared_stage(
        &self,
    ) -> Result<Option<PreparedCryptoStateStage>, CryptoStateError> {
        let uid = current_euid();
        let Some(directories) = self.open_existing_directories(uid)? else {
            return Ok(None);
        };
        let component = self.identity.prepared_stage_file_component();
        let Some(mut file) = open_state_file(
            &directories.devices,
            &component,
            &self.prepared_stage_path,
            uid,
        )?
        else {
            return Ok(None);
        };
        if !read_backup_excluded(&file, &self.prepared_stage_path)? {
            return Err(CryptoStateError::BackupExclusion);
        }
        validate_state_entry(&directories.devices, &component, &file, uid)?;
        let sealed = read_sealed_file_with_limit(&mut file, MAX_PREPARED_STAGE_PLAINTEXT_LEN)?;
        let sealed_commitment = sha256_bytes(&sealed);
        let plaintext = Zeroizing::new(open_snapshot_with_purpose(
            &self.identity,
            &self.kek,
            PREPARED_STAGE_AAD_PURPOSE,
            &sealed,
            MAX_PREPARED_STAGE_PLAINTEXT_LEN,
        )?);
        let decoded = decode_prepared_stage(plaintext.as_slice())?;
        validate_state_entry(&directories.devices, &component, &file, uid)?;
        Ok(Some(PreparedCryptoStateStage {
            mutation_id: decoded.mutation_id,
            previous_guard_hash: decoded.previous_guard_hash,
            previous_state_hash: decoded.previous_state_hash,
            next_state_hash: decoded.next_state_hash,
            snapshot: CryptoStateSnapshot::new(decoded.snapshot),
            sealed_commitment,
        }))
    }

    /// 对已经完整认证的 exact sidecar 做 unlink + parent fsync。
    ///
    /// 删除前再次打开并逐字验证，缺失、替换、篡改均零写拒绝。
    pub(crate) fn clear_prepared_stage_exact(
        &self,
        expected: &PreparedCryptoStateStage,
    ) -> Result<(), CryptoStateError> {
        let uid = current_euid();
        let directories = self
            .open_existing_directories(uid)?
            .ok_or(CryptoStateError::Missing)?;
        let component = self.identity.prepared_stage_file_component();
        let mut file = open_state_file(
            &directories.devices,
            &component,
            &self.prepared_stage_path,
            uid,
        )?
        .ok_or(CryptoStateError::Missing)?;
        if !read_backup_excluded(&file, &self.prepared_stage_path)? {
            return Err(CryptoStateError::BackupExclusion);
        }
        validate_state_entry(&directories.devices, &component, &file, uid)?;
        let sealed = read_sealed_file_with_limit(&mut file, MAX_PREPARED_STAGE_PLAINTEXT_LEN)?;
        if sha256_bytes(&sealed) != expected.sealed_commitment {
            return Err(CryptoStateError::CompareAndSwapConflict);
        }
        let plaintext = Zeroizing::new(open_snapshot_with_purpose(
            &self.identity,
            &self.kek,
            PREPARED_STAGE_AAD_PURPOSE,
            &sealed,
            MAX_PREPARED_STAGE_PLAINTEXT_LEN,
        )?);
        let decoded = decode_prepared_stage(plaintext.as_slice())?;
        if decoded.mutation_id != expected.mutation_id
            || decoded.previous_guard_hash != expected.previous_guard_hash
            || decoded.previous_state_hash != expected.previous_state_hash
            || decoded.next_state_hash != expected.next_state_hash
            || !snapshot_hash_and_bytes_match(&decoded.snapshot, expected.snapshot.expose_secret())
        {
            return Err(CryptoStateError::CompareAndSwapConflict);
        }
        validate_state_entry(&directories.devices, &component, &file, uid)?;
        drop(file);
        let name = c_string(OsStr::new(&component))?;
        // SAFETY: retained private directory and the exact authenticated basename above.
        if unsafe { libc::unlinkat(directories.devices.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io_error(
                "remove prepared stage",
                io::Error::last_os_error(),
            ));
        }
        directories
            .devices
            .sync_all()
            .map_err(|source| io_error("sync prepared stage removal", source))?;
        Ok(())
    }

    /// 只读审计 revocation cleanup 即将删除的 exact active state。
    ///
    /// prepared sidecar 必须缺失；active state 缺失返回 `false`。既有 state 会完成
    /// no-follow/private inode、backup exclusion、AEAD 与 plaintext SHA-256 全链认证，
    /// 任一失败均零写拒绝。
    pub(crate) fn audit_revocation_cleanup_state(
        &self,
        expected_plaintext_sha256: [u8; 32],
    ) -> Result<bool, CryptoStateError> {
        self.audit_revocation_cleanup_state_entry(expected_plaintext_sha256)
            .map(|entry| entry.is_some())
    }

    /// 删除已经全链认证、plaintext hash 精确匹配的 revocation cleanup state。
    ///
    /// 缺失幂等成功。删除前保留 parent dirfd 与已认证文件 fd，并做最终 inode 对照；
    /// `unlinkat` 后 fsync parent，最后在不依赖 KEK 的 absent 视图中读回 state 与
    /// prepared sidecar 均缺失。
    pub(crate) fn delete_revocation_cleanup_state(
        &self,
        expected_plaintext_sha256: [u8; 32],
    ) -> Result<(), CryptoStateError> {
        let Some(audited) = self.audit_revocation_cleanup_state_entry(expected_plaintext_sha256)?
        else {
            return Ok(());
        };

        validate_state_entry(
            &audited.directories.devices,
            &audited.component,
            &audited.file,
            audited.uid,
        )?;
        let name = c_string(OsStr::new(&audited.component))?;
        // SAFETY: the retained private dirfd still names the parent, and the immediately preceding
        // fstat/fstatat comparison proved this basename is the exact authenticated inode.
        if unsafe { libc::unlinkat(audited.directories.devices.as_raw_fd(), name.as_ptr(), 0) } != 0
        {
            return Err(io_error(
                "remove revocation cleanup state",
                io::Error::last_os_error(),
            ));
        }
        audited
            .directories
            .devices
            .sync_all()
            .map_err(|source| io_error("sync revocation cleanup state removal", source))?;

        if revocation_cleanup_entries_absent_in(&self.root, self.identity)? {
            Ok(())
        } else {
            Err(CryptoStateError::PersistenceReadbackFailed)
        }
    }

    fn audit_revocation_cleanup_state_entry(
        &self,
        expected_plaintext_sha256: [u8; 32],
    ) -> Result<Option<AuditedRevocationCleanupState>, CryptoStateError> {
        let uid = current_euid();
        let Some(directories) = self.open_existing_directories(uid)? else {
            return Ok(None);
        };
        let prepared_component = self.identity.prepared_stage_file_component();
        let prepared = open_state_file(
            &directories.devices,
            &prepared_component,
            &self.prepared_stage_path,
            uid,
        )?;
        let state_component = self.identity.state_file_component();
        let state = open_state_file(
            &directories.devices,
            &state_component,
            &self.state_path,
            uid,
        )?;
        if prepared.is_some() {
            return Err(CryptoStateError::ImmutableConflict);
        }
        let Some(mut file) = state else {
            return Ok(None);
        };
        if !read_backup_excluded(&file, &self.state_path)? {
            return Err(CryptoStateError::BackupExclusion);
        }
        validate_state_entry(&directories.devices, &state_component, &file, uid)?;
        let sealed = read_sealed_file(&mut file)?;
        let plaintext = Zeroizing::new(open_snapshot(&self.identity, &self.kek, &sealed)?);
        if sha256_bytes(plaintext.as_slice()) != expected_plaintext_sha256 {
            return Err(CryptoStateError::CompareAndSwapConflict);
        }
        validate_state_entry(&directories.devices, &state_component, &file, uid)?;
        Ok(Some(AuditedRevocationCleanupState {
            directories,
            file,
            component: state_component,
            uid,
        }))
    }

    fn observe_replace_stage(&self, stage: CryptoStateReplaceStage) {
        if let Some(observer) = &self.replace_observer {
            observer.after_stage(stage);
        }
    }

    fn readback_commit(
        &self,
        expected: &CryptoStateSnapshot,
        outcome: CryptoStateCommit,
    ) -> Result<CryptoStateCommit, CryptoStateError> {
        match self.load()? {
            Some(actual) if actual.expose_secret() == expected.expose_secret() => Ok(outcome),
            Some(_) if outcome == CryptoStateCommit::AlreadyPresent => {
                Err(CryptoStateError::ImmutableConflict)
            }
            Some(_) | None => Err(CryptoStateError::PersistenceReadbackFailed),
        }
    }

    fn open_existing_directories(
        &self,
        uid: libc::uid_t,
    ) -> Result<Option<StateDirectories>, CryptoStateError> {
        open_existing_state_directories(&self.root, self.identity, uid)
    }

    fn open_or_create_directories(
        &self,
        uid: libc::uid_t,
    ) -> Result<StateDirectories, CryptoStateError> {
        let root = open_or_create_root_without_symlinks(&self.root, uid)?;
        let installation_component = self.identity.installation_component();
        let installation =
            open_or_create_private_directory_at(&root, OsStr::new(&installation_component), uid)?;
        let devices =
            open_or_create_private_directory_at(&installation, OsStr::new(DEVICES_DIRECTORY), uid)?;
        Ok(StateDirectories {
            _root: root,
            _installation: installation,
            devices,
        })
    }
}

struct StateDirectories {
    _root: File,
    _installation: File,
    devices: File,
}

struct AuditedRevocationCleanupState {
    directories: StateDirectories,
    file: File,
    component: String,
    uid: libc::uid_t,
}

fn open_existing_state_directories(
    root_path: &Path,
    identity: CryptoStateIdentity,
    uid: libc::uid_t,
) -> Result<Option<StateDirectories>, CryptoStateError> {
    let Some(root) = open_existing_root_without_symlinks(root_path, uid)? else {
        return Ok(None);
    };
    let installation_component = identity.installation_component();
    let Some(installation) =
        open_existing_private_directory_at(&root, OsStr::new(&installation_component), uid)?
    else {
        return Ok(None);
    };
    let Some(devices) =
        open_existing_private_directory_at(&installation, OsStr::new(DEVICES_DIRECTORY), uid)?
    else {
        return Ok(None);
    };
    Ok(Some(StateDirectories {
        _root: root,
        _installation: installation,
        devices,
    }))
}

/// 在 StorageKEK 已删除的 cleanup 尾段，只读确认 active state 与 prepared sidecar
/// 都安全缺失。安全的既有项返回 `false`；symlink、错误 owner/mode/hardlink 等异常项
/// 返回 typed error，且本函数从不创建、修复或删除任何目录/文件。
pub(crate) fn revocation_cleanup_entries_absent_in(
    root: &Path,
    identity: CryptoStateIdentity,
) -> Result<bool, CryptoStateError> {
    absolute_normal_components(root)?;
    let uid = current_euid();
    let Some(directories) = open_existing_state_directories(root, identity, uid)? else {
        return Ok(true);
    };
    let devices_path = root
        .join(identity.installation_component())
        .join(DEVICES_DIRECTORY);
    let state_component = identity.state_file_component();
    let state_path = devices_path.join(&state_component);
    let state = open_state_file(&directories.devices, &state_component, &state_path, uid)?;
    let prepared_component = identity.prepared_stage_file_component();
    let prepared_path = devices_path.join(&prepared_component);
    let prepared = open_state_file(
        &directories.devices,
        &prepared_component,
        &prepared_path,
        uid,
    )?;
    Ok(state.is_none() && prepared.is_none())
}

fn seal_snapshot(
    identity: &CryptoStateIdentity,
    kek: &DeviceStorageKek,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoStateError> {
    seal_snapshot_with_purpose(
        identity,
        kek,
        AAD_PURPOSE,
        plaintext,
        MAX_CRYPTO_STATE_PLAINTEXT_LEN,
    )
}

fn seal_snapshot_with_purpose(
    identity: &CryptoStateIdentity,
    kek: &DeviceStorageKek,
    purpose: &[u8],
    plaintext: &[u8],
    max_plaintext_len: usize,
) -> Result<Vec<u8>, CryptoStateError> {
    if plaintext.len() > max_plaintext_len {
        return Err(CryptoStateError::InputTooLarge);
    }
    let plaintext_len =
        u32::try_from(plaintext.len()).map_err(|_| CryptoStateError::InputTooLarge)?;
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoStateError::EntropyUnavailable)?;
    let header = encode_header(plaintext_len, nonce);
    let aad = encode_aad(identity, purpose, &header);
    let cipher = ChaCha20Poly1305::new_from_slice(kek.as_bytes())
        .map_err(|_| CryptoStateError::AuthenticationFailed)?;
    let encrypted = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoStateError::AuthenticationFailed)?;
    let mut sealed = Vec::with_capacity(CRYPTO_STATE_V1_HEADER_LEN + encrypted.len());
    sealed.extend_from_slice(&header);
    sealed.extend_from_slice(&encrypted);
    Ok(sealed)
}

fn open_snapshot(
    identity: &CryptoStateIdentity,
    kek: &DeviceStorageKek,
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoStateError> {
    open_snapshot_with_purpose(
        identity,
        kek,
        AAD_PURPOSE,
        sealed,
        MAX_CRYPTO_STATE_PLAINTEXT_LEN,
    )
}

fn open_snapshot_with_purpose(
    identity: &CryptoStateIdentity,
    kek: &DeviceStorageKek,
    purpose: &[u8],
    sealed: &[u8],
    max_plaintext_len: usize,
) -> Result<Vec<u8>, CryptoStateError> {
    if sealed.len() < CRYPTO_STATE_V1_OVERHEAD_LEN {
        return Err(CryptoStateError::InvalidFormat);
    }
    if sealed.len() > max_plaintext_len + CRYPTO_STATE_V1_OVERHEAD_LEN {
        return Err(CryptoStateError::InputTooLarge);
    }
    let header: [u8; CRYPTO_STATE_V1_HEADER_LEN] = sealed[..CRYPTO_STATE_V1_HEADER_LEN]
        .try_into()
        .map_err(|_| CryptoStateError::InvalidFormat)?;
    let (plaintext_len, nonce) = decode_header(&header)?;
    if plaintext_len > max_plaintext_len {
        return Err(CryptoStateError::InputTooLarge);
    }
    let expected = plaintext_len
        .checked_add(CRYPTO_STATE_V1_OVERHEAD_LEN)
        .ok_or(CryptoStateError::InputTooLarge)?;
    if sealed.len() != expected {
        return Err(CryptoStateError::InvalidFormat);
    }
    let aad = encode_aad(identity, purpose, &header);
    let cipher = ChaCha20Poly1305::new_from_slice(kek.as_bytes())
        .map_err(|_| CryptoStateError::AuthenticationFailed)?;
    cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &sealed[CRYPTO_STATE_V1_HEADER_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoStateError::AuthenticationFailed)
}

fn snapshot_hash_and_bytes_match(actual: &[u8], expected: &[u8]) -> bool {
    let actual_hash = sha256_bytes(actual);
    let expected_hash = sha256_bytes(expected);
    actual_hash == expected_hash && actual == expected
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode_header(plaintext_len: u32, nonce: [u8; NONCE_LEN]) -> [u8; CRYPTO_STATE_V1_HEADER_LEN] {
    let mut header = [0_u8; CRYPTO_STATE_V1_HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = FORMAT_VERSION;
    header[5] = ALGORITHM_CHACHA20_POLY1305;
    header[8..12].copy_from_slice(&plaintext_len.to_be_bytes());
    header[12..].copy_from_slice(&nonce);
    header
}

fn decode_header(
    header: &[u8; CRYPTO_STATE_V1_HEADER_LEN],
) -> Result<(usize, [u8; NONCE_LEN]), CryptoStateError> {
    if &header[..4] != MAGIC
        || header[4] != FORMAT_VERSION
        || header[5] != ALGORITHM_CHACHA20_POLY1305
        || header[6..8] != [0, 0]
    {
        return Err(CryptoStateError::InvalidFormat);
    }
    let plaintext_len = usize::try_from(u32::from_be_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| CryptoStateError::InvalidFormat)?,
    ))
    .map_err(|_| CryptoStateError::InputTooLarge)?;
    let nonce = header[12..]
        .try_into()
        .map_err(|_| CryptoStateError::InvalidFormat)?;
    Ok((plaintext_len, nonce))
}

fn encode_aad(
    identity: &CryptoStateIdentity,
    purpose: &[u8],
    header: &[u8; CRYPTO_STATE_V1_HEADER_LEN],
) -> Vec<u8> {
    let fields: [&[u8]; 7] = [
        AAD_DOMAIN,
        AAD_CLIENT_KIND,
        identity.installation_id.as_bytes(),
        identity.machine_root_fingerprint.as_bytes(),
        identity.machine_route.as_bytes(),
        purpose,
        header,
    ];
    let capacity = fields.iter().map(|field| 4 + field.len()).sum();
    let mut aad = Vec::with_capacity(capacity);
    for field in fields {
        let len = u32::try_from(field.len()).expect("fixed CryptoState AAD field fits u32");
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(field);
    }
    aad
}

fn encode_prepared_stage(
    mutation_id: [u8; 16],
    previous_guard_hash: [u8; 32],
    previous_snapshot: &[u8],
    next_snapshot: &[u8],
) -> Result<Vec<u8>, CryptoStateError> {
    let previous_state_hash = sha256_bytes(previous_snapshot);
    let next_state_hash = sha256_bytes(next_snapshot);
    validate_prepared_stage_fields(
        mutation_id,
        previous_guard_hash,
        previous_state_hash,
        next_state_hash,
        next_snapshot,
    )?;
    let snapshot_len =
        u32::try_from(next_snapshot.len()).map_err(|_| CryptoStateError::InputTooLarge)?;
    let total_len = PREPARED_STAGE_FIXED_LEN
        .checked_add(next_snapshot.len())
        .ok_or(CryptoStateError::InputTooLarge)?;
    if total_len > MAX_PREPARED_STAGE_PLAINTEXT_LEN {
        return Err(CryptoStateError::InputTooLarge);
    }
    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(PREPARED_STAGE_MAGIC);
    encoded.extend_from_slice(&PREPARED_STAGE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&[0, 0]);
    encoded.extend_from_slice(&mutation_id);
    encoded.extend_from_slice(&previous_guard_hash);
    encoded.extend_from_slice(&previous_state_hash);
    encoded.extend_from_slice(&next_state_hash);
    encoded.extend_from_slice(&snapshot_len.to_be_bytes());
    encoded.extend_from_slice(next_snapshot);
    Ok(encoded)
}

fn decode_prepared_stage(plaintext: &[u8]) -> Result<DecodedPreparedStage, CryptoStateError> {
    if plaintext.len() < PREPARED_STAGE_FIXED_LEN
        || plaintext.len() > MAX_PREPARED_STAGE_PLAINTEXT_LEN
        || &plaintext[..4] != PREPARED_STAGE_MAGIC
        || u16::from_be_bytes([plaintext[4], plaintext[5]]) != PREPARED_STAGE_VERSION
        || plaintext[6..8] != [0, 0]
    {
        return Err(CryptoStateError::InvalidFormat);
    }
    let mutation_id = plaintext[8..24]
        .try_into()
        .map_err(|_| CryptoStateError::InvalidFormat)?;
    let previous_guard_hash = plaintext[24..56]
        .try_into()
        .map_err(|_| CryptoStateError::InvalidFormat)?;
    let previous_state_hash = plaintext[56..88]
        .try_into()
        .map_err(|_| CryptoStateError::InvalidFormat)?;
    let next_state_hash = plaintext[88..120]
        .try_into()
        .map_err(|_| CryptoStateError::InvalidFormat)?;
    let snapshot_len = usize::try_from(u32::from_be_bytes(
        plaintext[120..124]
            .try_into()
            .map_err(|_| CryptoStateError::InvalidFormat)?,
    ))
    .map_err(|_| CryptoStateError::InputTooLarge)?;
    if snapshot_len != plaintext.len() - PREPARED_STAGE_FIXED_LEN {
        return Err(CryptoStateError::InvalidFormat);
    }
    let snapshot = plaintext[PREPARED_STAGE_FIXED_LEN..].to_vec();
    validate_prepared_stage_fields(
        mutation_id,
        previous_guard_hash,
        previous_state_hash,
        next_state_hash,
        &snapshot,
    )?;
    Ok(DecodedPreparedStage {
        mutation_id,
        previous_guard_hash,
        previous_state_hash,
        next_state_hash,
        snapshot,
    })
}

fn validate_prepared_stage_fields(
    mutation_id: [u8; 16],
    previous_guard_hash: [u8; 32],
    previous_state_hash: [u8; 32],
    next_state_hash: [u8; 32],
    next_snapshot: &[u8],
) -> Result<(), CryptoStateError> {
    if mutation_id.iter().all(|byte| *byte == 0)
        || previous_guard_hash.iter().all(|byte| *byte == 0)
        || previous_state_hash.iter().all(|byte| *byte == 0)
        || next_state_hash.iter().all(|byte| *byte == 0)
        || previous_state_hash == next_state_hash
        || next_state_hash != sha256_bytes(next_snapshot)
        || next_snapshot.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN
    {
        return Err(CryptoStateError::InvalidFormat);
    }
    Ok(())
}

fn read_sealed_file(file: &mut File) -> Result<Vec<u8>, CryptoStateError> {
    read_sealed_file_with_limit(file, MAX_CRYPTO_STATE_PLAINTEXT_LEN)
}

fn read_sealed_file_with_limit(
    file: &mut File,
    max_plaintext_len: usize,
) -> Result<Vec<u8>, CryptoStateError> {
    let stat = fstat(file.as_raw_fd(), "stat state file")?;
    let size = usize::try_from(stat.st_size).map_err(|_| CryptoStateError::InputTooLarge)?;
    if size > max_plaintext_len + CRYPTO_STATE_V1_OVERHEAD_LEN {
        return Err(CryptoStateError::InputTooLarge);
    }
    if size < CRYPTO_STATE_V1_OVERHEAD_LEN {
        return Err(CryptoStateError::InvalidFormat);
    }

    let mut header = [0_u8; CRYPTO_STATE_V1_HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(map_bounded_read_error)?;
    let (plaintext_len, _) = decode_header(&header)?;
    if plaintext_len > max_plaintext_len {
        return Err(CryptoStateError::InputTooLarge);
    }
    let expected = plaintext_len
        .checked_add(CRYPTO_STATE_V1_OVERHEAD_LEN)
        .ok_or(CryptoStateError::InputTooLarge)?;
    if size != expected {
        return Err(CryptoStateError::InvalidFormat);
    }

    let tail_len = plaintext_len + 16;
    let mut sealed = Vec::with_capacity(expected);
    sealed.extend_from_slice(&header);
    sealed.resize(expected, 0);
    file.read_exact(&mut sealed[CRYPTO_STATE_V1_HEADER_LEN..])
        .map_err(map_bounded_read_error)?;
    debug_assert_eq!(sealed.len() - CRYPTO_STATE_V1_HEADER_LEN, tail_len);
    let mut extra = [0_u8; 1];
    match file.read(&mut extra) {
        Ok(0) => Ok(sealed),
        Ok(_) => Err(CryptoStateError::InvalidFormat),
        Err(source) => Err(io_error("verify state EOF", source)),
    }
}

fn map_bounded_read_error(source: io::Error) -> CryptoStateError {
    if source.kind() == io::ErrorKind::UnexpectedEof {
        CryptoStateError::InvalidFormat
    } else {
        io_error("read state", source)
    }
}

fn current_euid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions and no side effects.
    unsafe { libc::geteuid() }
}

fn absolute_normal_components(path: &Path) -> Result<Vec<OsString>, CryptoStateError> {
    if !path.is_absolute() {
        return Err(CryptoStateError::InvalidRoot);
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(component) => components.push(component.to_os_string()),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(CryptoStateError::InvalidRoot);
            }
        }
    }
    if components.is_empty() {
        return Err(CryptoStateError::InvalidRoot);
    }
    Ok(components)
}

fn open_filesystem_root() -> Result<File, CryptoStateError> {
    let root = CString::new("/").expect("filesystem root contains no NUL");
    // SAFETY: fixed NUL-terminated root path; successful fd is uniquely owned below.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error("open filesystem root", io::Error::last_os_error()));
    }
    // SAFETY: successful open returned a uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_existing_root_without_symlinks(
    path: &Path,
    uid: libc::uid_t,
) -> Result<Option<File>, CryptoStateError> {
    let components = absolute_normal_components(path)?;
    let mut directory = open_filesystem_root()?;
    for (index, component) in components.iter().enumerate() {
        let Some(next) = open_existing_directory_component(&directory, component)? else {
            return Ok(None);
        };
        directory = next;
        if index + 1 == components.len() {
            validate_private_directory(&directory, uid)?;
        }
    }
    Ok(Some(directory))
}

fn open_or_create_root_without_symlinks(
    path: &Path,
    uid: libc::uid_t,
) -> Result<File, CryptoStateError> {
    let components = absolute_normal_components(path)?;
    let mut directory = open_filesystem_root()?;
    for (index, component) in components.iter().enumerate() {
        if index + 1 == components.len() {
            return open_or_create_private_directory_at(&directory, component, uid);
        }
        directory = open_existing_directory_component(&directory, component)?.ok_or(
            CryptoStateError::UnsafeDirectory {
                reason: "state root ancestor is missing",
            },
        )?;
    }
    Err(CryptoStateError::InvalidRoot)
}

fn open_existing_directory_component(
    parent: &File,
    component: &OsStr,
) -> Result<Option<File>, CryptoStateError> {
    let name = c_string(component)?;
    // SAFETY: retained parent dirfd and NUL-free basename; O_NOFOLLOW refuses symlinks.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(CryptoStateError::UnsafeDirectory {
            reason: "state directory component could not be opened without following links",
        });
    }
    // SAFETY: successful openat returned a uniquely owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    validate_directory_entry(parent, &name, &directory)?;
    Ok(Some(directory))
}

fn open_existing_private_directory_at(
    parent: &File,
    component: &OsStr,
    uid: libc::uid_t,
) -> Result<Option<File>, CryptoStateError> {
    let Some(directory) = open_existing_directory_component(parent, component)? else {
        return Ok(None);
    };
    validate_private_directory(&directory, uid)?;
    Ok(Some(directory))
}

fn open_or_create_private_directory_at(
    parent: &File,
    component: &OsStr,
    uid: libc::uid_t,
) -> Result<File, CryptoStateError> {
    let name = c_string(component)?;
    // SAFETY: retained parent directory and NUL-free basename.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0;
    if !created {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(io_error("create state directory", source));
        }
    } else {
        // restrictive umask may have removed owner bits; only a fresh inode may be repaired.
        // SAFETY: this name was created successfully in the retained parent immediately above.
        if unsafe { libc::fchmodat(parent.as_raw_fd(), name.as_ptr(), 0o700, 0) } != 0 {
            return Err(io_error(
                "set fresh state directory mode",
                io::Error::last_os_error(),
            ));
        }
        parent
            .sync_all()
            .map_err(|source| io_error("sync state directory parent", source))?;
    }

    let directory = open_existing_directory_component(parent, component)?.ok_or(
        CryptoStateError::UnsafeDirectory {
            reason: "fresh state directory disappeared",
        },
    )?;
    validate_private_directory(&directory, uid)?;
    Ok(directory)
}

fn validate_private_directory(directory: &File, uid: libc::uid_t) -> Result<(), CryptoStateError> {
    let stat = fstat(directory.as_raw_fd(), "stat state directory")?;
    let reason = if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        Some("entry is not a directory")
    } else if stat.st_uid != uid {
        Some("directory owner is not current EUID")
    } else if (stat.st_mode & 0o7777) != 0o700 {
        Some("directory mode is not exactly 0700")
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| {
        Err(CryptoStateError::UnsafeDirectory { reason })
    })
}

fn validate_directory_entry(
    parent: &File,
    component: &CStr,
    directory: &File,
) -> Result<(), CryptoStateError> {
    let opened = fstat(directory.as_raw_fd(), "stat opened state directory")?;
    let entry = fstatat(parent.as_raw_fd(), component, "stat state directory entry")?;
    if (entry.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || opened.st_dev != entry.st_dev
        || opened.st_ino != entry.st_ino
    {
        return Err(CryptoStateError::UnsafeDirectory {
            reason: "directory entry does not match retained descriptor",
        });
    }
    Ok(())
}

fn open_state_file(
    directory: &File,
    component: &str,
    _path: &Path,
    uid: libc::uid_t,
) -> Result<Option<File>, CryptoStateError> {
    let name = c_string(OsStr::new(component))?;
    // SAFETY: retained private directory and NUL-free basename; nonblocking prevents FIFO hangs.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        if source.raw_os_error() == Some(libc::ELOOP) {
            return Err(CryptoStateError::UnsafeFile {
                reason: "state entry is a symlink",
            });
        }
        return Err(io_error("open state file", source));
    }
    // SAFETY: successful openat returned a uniquely owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    validate_state_entry(directory, component, &file, uid)?;
    Ok(Some(file))
}

fn validate_state_entry(
    directory: &File,
    component: &str,
    file: &File,
    uid: libc::uid_t,
) -> Result<(), CryptoStateError> {
    let name = c_string(OsStr::new(component))?;
    let opened = fstat(file.as_raw_fd(), "stat opened state file")?;
    let entry = fstatat(directory.as_raw_fd(), &name, "stat state file entry")?;
    let reason = if (opened.st_mode & libc::S_IFMT) != libc::S_IFREG
        || (entry.st_mode & libc::S_IFMT) != libc::S_IFREG
    {
        Some("state entry is not a regular file")
    } else if opened.st_dev != entry.st_dev || opened.st_ino != entry.st_ino {
        Some("state entry does not match retained descriptor")
    } else if opened.st_uid != uid || entry.st_uid != uid {
        Some("state file owner is not current EUID")
    } else if (opened.st_mode & 0o7777) != 0o600 || (entry.st_mode & 0o7777) != 0o600 {
        Some("state file mode is not exactly 0600")
    } else if opened.st_nlink != 1 || entry.st_nlink != 1 {
        Some("state file must have exactly one hard link")
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| {
        Err(CryptoStateError::UnsafeFile { reason })
    })
}

fn create_temp_file(
    directory: &File,
    state_path: &Path,
    uid: libc::uid_t,
) -> Result<(File, TempEntry), CryptoStateError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| CryptoStateError::EntropyUnavailable)?;
    let mut component = String::from(".crypto-state.");
    for byte in random {
        use fmt::Write as _;
        write!(&mut component, "{byte:02x}").expect("writing to String cannot fail");
    }
    component.push_str(".tmp");
    let name = c_string(OsStr::new(&component))?;
    let path = state_path.with_file_name(&component);
    // SAFETY: retained private directory, random NUL-free basename, exclusive no-follow create.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io_error("create state temp", io::Error::last_os_error()));
    }
    // SAFETY: successful openat returned a uniquely owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let guard = TempEntry {
        directory_fd: directory.as_raw_fd(),
        name,
        component,
        path,
        active: true,
    };
    // SAFETY: the descriptor names the fresh inode created immediately above.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(io_error(
            "set fresh state temp mode",
            io::Error::last_os_error(),
        ));
    }
    validate_state_entry(directory, guard.component_str(), &file, uid)?;
    Ok((file, guard))
}

enum PublishOutcome {
    Published,
    LostRace,
}

fn rename_no_replace(
    directory_fd: RawFd,
    source: &CStr,
    target: &str,
) -> Result<PublishOutcome, CryptoStateError> {
    let target = c_string(OsStr::new(target))?;
    #[cfg(target_os = "macos")]
    // SAFETY: both basenames are NUL-terminated beneath the same retained directory fd.
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
    // SAFETY: both basenames are NUL-terminated beneath the same retained directory fd.
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
    return Err(CryptoStateError::NoReplaceUnsupported);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if result == 0 {
        Ok(PublishOutcome::Published)
    } else {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::AlreadyExists {
            Ok(PublishOutcome::LostRace)
        } else {
            Err(io_error("publish state", source))
        }
    }
}

fn rename_replace(
    directory_fd: RawFd,
    source: &CStr,
    target: &str,
) -> Result<(), CryptoStateError> {
    let target = c_string(OsStr::new(target))?;
    // SAFETY: both basenames are NUL-terminated beneath the same retained private directory fd;
    // the target was opened, authenticated, and matched against expected before temp creation.
    if unsafe { libc::renameat(directory_fd, source.as_ptr(), directory_fd, target.as_ptr()) } == 0
    {
        Ok(())
    } else {
        Err(io_error("replace state", io::Error::last_os_error()))
    }
}

struct TempEntry {
    directory_fd: RawFd,
    name: CString,
    component: String,
    path: PathBuf,
    active: bool,
}

impl TempEntry {
    fn name(&self) -> &CStr {
        &self.name
    }

    fn component_str(&self) -> &str {
        &self.component
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.active = false;
    }

    fn remove_now(&mut self) -> Result<(), CryptoStateError> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: retained parent fd and the exact temp basename created by this guard.
        if unsafe { libc::unlinkat(self.directory_fd, self.name.as_ptr(), 0) } != 0 {
            return Err(io_error(
                "remove lost-race state temp",
                io::Error::last_os_error(),
            ));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for TempEntry {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: best-effort cleanup of this guard's private temp basename.
            unsafe {
                libc::unlinkat(self.directory_fd, self.name.as_ptr(), 0);
            }
        }
    }
}

fn c_string(value: &OsStr) -> Result<CString, CryptoStateError> {
    if value.as_bytes().is_empty() || value.as_bytes().contains(&b'/') {
        return Err(CryptoStateError::InvalidRoot);
    }
    CString::new(value.as_bytes()).map_err(|_| CryptoStateError::InvalidRoot)
}

fn fstat(fd: RawFd, operation: &'static str) -> Result<libc::stat, CryptoStateError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to valid writable storage and fd is live for this call.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io_error(operation, io::Error::last_os_error()));
    }
    // SAFETY: successful fstat initialized the full structure.
    Ok(unsafe { stat.assume_init() })
}

fn fstatat(
    directory_fd: RawFd,
    component: &CStr,
    operation: &'static str,
) -> Result<libc::stat, CryptoStateError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: retained dirfd, NUL-terminated basename and valid writable result storage.
    if unsafe {
        libc::fstatat(
            directory_fd,
            component.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io_error(operation, io::Error::last_os_error()));
    }
    // SAFETY: successful fstatat initialized the full structure.
    Ok(unsafe { stat.assume_init() })
}

fn io_error(operation: &'static str, source: io::Error) -> CryptoStateError {
    CryptoStateError::Io { operation, source }
}

#[cfg(target_os = "macos")]
fn mark_backup_excluded(_file: &File, path: &Path) -> Result<(), CryptoStateError> {
    use core_foundation_sys::base::CFTypeRef;
    use core_foundation_sys::error::CFErrorRef;
    use core_foundation_sys::number::kCFBooleanTrue;
    use core_foundation_sys::url::{CFURLSetResourcePropertyForKey, kCFURLIsExcludedFromBackupKey};

    let url = create_cf_file_url(path)?;
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: url/key/value are live CoreFoundation objects; error is writable storage.
    let success = unsafe {
        CFURLSetResourcePropertyForKey(
            url,
            kCFURLIsExcludedFromBackupKey,
            kCFBooleanTrue.cast::<std::ffi::c_void>() as CFTypeRef,
            &mut error,
        )
    } != 0;
    release_cf(url.cast());
    release_optional_cf(error.cast());
    if success {
        Ok(())
    } else {
        Err(CryptoStateError::BackupExclusion)
    }
}

#[cfg(target_os = "macos")]
fn read_backup_excluded(_file: &File, path: &Path) -> Result<bool, CryptoStateError> {
    use core_foundation_sys::base::{CFGetTypeID, CFTypeRef};
    use core_foundation_sys::error::CFErrorRef;
    use core_foundation_sys::number::{CFBooleanGetTypeID, CFBooleanGetValue};
    use core_foundation_sys::url::kCFURLIsExcludedFromBackupKey;

    let url = create_cf_file_url(path)?;
    let mut property: CFTypeRef = std::ptr::null();
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: url/key are live; property/error point to writable result storage.
    let success = unsafe {
        CFURLCopyResourcePropertyForKey(
            url,
            kCFURLIsExcludedFromBackupKey,
            (&mut property as *mut CFTypeRef).cast(),
            &mut error,
        )
    } != 0;
    release_cf(url.cast());
    release_optional_cf(error.cast());
    if !success || property.is_null() {
        release_optional_cf(property);
        return Ok(false);
    }
    // SAFETY: successful copy returned a retained CF object; type is checked before bool access.
    let excluded = unsafe {
        CFGetTypeID(property) == CFBooleanGetTypeID()
            && CFBooleanGetValue(property.cast::<core_foundation_sys::number::__CFBoolean>())
    };
    release_cf(property);
    Ok(excluded)
}

#[cfg(target_os = "macos")]
fn create_cf_file_url(path: &Path) -> Result<core_foundation_sys::url::CFURLRef, CryptoStateError> {
    use core_foundation_sys::base::CFIndex;
    use core_foundation_sys::url::CFURLCreateFromFileSystemRepresentation;

    let bytes = path.as_os_str().as_bytes();
    let length = CFIndex::try_from(bytes.len()).map_err(|_| CryptoStateError::InvalidRoot)?;
    // SAFETY: path bytes are live for the call; null allocator selects the default allocator.
    let url = unsafe {
        CFURLCreateFromFileSystemRepresentation(std::ptr::null(), bytes.as_ptr(), length, 0)
    };
    if url.is_null() {
        Err(CryptoStateError::BackupExclusion)
    } else {
        Ok(url)
    }
}

#[cfg(target_os = "macos")]
fn release_cf(value: core_foundation_sys::base::CFTypeRef) {
    // SAFETY: caller passes a non-null retained CoreFoundation object.
    unsafe { core_foundation_sys::base::CFRelease(value) };
}

#[cfg(target_os = "macos")]
fn release_optional_cf(value: core_foundation_sys::base::CFTypeRef) {
    if !value.is_null() {
        release_cf(value);
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn CFURLCopyResourcePropertyForKey(
        url: core_foundation_sys::url::CFURLRef,
        key: core_foundation_sys::string::CFStringRef,
        property_value: *mut std::ffi::c_void,
        error: *mut core_foundation_sys::error::CFErrorRef,
    ) -> core_foundation_sys::base::Boolean;
}

#[cfg(target_os = "linux")]
const HARNESS_BACKUP_XATTR: &str = "user.agentdeck.backup-excluded.v1";

#[cfg(target_os = "linux")]
fn mark_backup_excluded(file: &File, _path: &Path) -> Result<(), CryptoStateError> {
    let name = CString::new(HARNESS_BACKUP_XATTR).expect("fixed xattr name contains no NUL");
    let value = [1_u8];
    // SAFETY: live fd, NUL-terminated name and one-byte readable value buffer.
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(CryptoStateError::BackupExclusion)
    }
}

#[cfg(target_os = "linux")]
fn read_backup_excluded(file: &File, _path: &Path) -> Result<bool, CryptoStateError> {
    let name = CString::new(HARNESS_BACKUP_XATTR).expect("fixed xattr name contains no NUL");
    let mut value = [0_u8; 2];
    // SAFETY: live fd, NUL-terminated name and valid writable output buffer.
    let length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if length < 0 {
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::ENODATA) {
            return Ok(false);
        }
        return Err(CryptoStateError::BackupExclusion);
    }
    Ok(length == 1 && value[0] == 1)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn mark_backup_excluded(_file: &File, _path: &Path) -> Result<(), CryptoStateError> {
    Err(CryptoStateError::NoReplaceUnsupported)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_backup_excluded(_file: &File, _path: &Path) -> Result<bool, CryptoStateError> {
    Err(CryptoStateError::NoReplaceUnsupported)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn cleanup_identity() -> CryptoStateIdentity {
        CryptoStateIdentity::new(
            Uuid::from_bytes([0x11; 16]),
            MachineRootFingerprint::from_bytes([0x22; 32]),
            MachineRouteId::from_bytes([0x33; 16]),
        )
    }

    fn cleanup_store(root: &Path, identity: CryptoStateIdentity) -> FileCryptoStateStore {
        FileCryptoStateStore::new_in(root, identity, DeviceStorageKek::new([0x44; 32]))
            .expect("create cleanup crypto-state store")
    }

    #[test]
    fn revocation_cleanup_audits_exact_plaintext_and_deletes_idempotently() {
        let temp = tempfile::tempdir().expect("create cleanup tempdir");
        let root = fs::canonicalize(temp.path())
            .expect("canonicalize cleanup tempdir")
            .join("remote-state");
        let identity = cleanup_identity();
        let store = cleanup_store(&root, identity);
        let snapshot = CryptoStateSnapshot::new(b"authenticated cleanup state".to_vec());
        let expected_hash = sha256_bytes(snapshot.expose_secret());

        assert_eq!(store.root(), root);
        assert!(revocation_cleanup_entries_absent_in(&root, identity).expect("audit absence"));
        assert!(
            !store
                .audit_revocation_cleanup_state(expected_hash)
                .expect("missing state is not cleanup work")
        );
        store
            .commit_initial(&snapshot)
            .expect("commit cleanup fixture state");
        assert!(
            !revocation_cleanup_entries_absent_in(&root, identity)
                .expect("detect safe state presence")
        );
        assert!(
            store
                .audit_revocation_cleanup_state(expected_hash)
                .expect("authenticate exact cleanup state")
        );

        store
            .delete_revocation_cleanup_state(expected_hash)
            .expect("delete authenticated cleanup state");
        assert!(
            revocation_cleanup_entries_absent_in(&root, identity).expect("read back exact absence")
        );
        assert!(
            !store
                .audit_revocation_cleanup_state(expected_hash)
                .expect("deleted state remains absent")
        );
        store
            .delete_revocation_cleanup_state(expected_hash)
            .expect("missing cleanup state is idempotent");
    }

    #[test]
    fn revocation_cleanup_rejects_hash_conflict_and_prepared_sidecar_without_writes() {
        let temp = tempfile::tempdir().expect("create cleanup tempdir");
        let root = fs::canonicalize(temp.path())
            .expect("canonicalize cleanup tempdir")
            .join("remote-state");
        let identity = cleanup_identity();
        let store = cleanup_store(&root, identity);
        let active = CryptoStateSnapshot::new(b"active cleanup state".to_vec());
        let expected_hash = sha256_bytes(active.expose_secret());
        store
            .commit_initial(&active)
            .expect("commit cleanup fixture state");
        let before = fs::read(store.state_path()).expect("read state before rejected cleanup");

        assert!(matches!(
            store.audit_revocation_cleanup_state([0x99; 32]),
            Err(CryptoStateError::CompareAndSwapConflict)
        ));
        assert!(matches!(
            store.delete_revocation_cleanup_state([0x99; 32]),
            Err(CryptoStateError::CompareAndSwapConflict)
        ));
        assert_eq!(
            fs::read(store.state_path()).expect("read state after hash conflict"),
            before
        );

        let next = CryptoStateSnapshot::new(b"prepared cleanup successor".to_vec());
        store
            .prepare_stage(&active, [0x55; 32], [0x66; 16], &next)
            .expect("publish prepared cleanup fixture");
        assert!(matches!(
            store.audit_revocation_cleanup_state(expected_hash),
            Err(CryptoStateError::ImmutableConflict)
        ));
        assert!(matches!(
            store.delete_revocation_cleanup_state(expected_hash),
            Err(CryptoStateError::ImmutableConflict)
        ));
        assert_eq!(
            fs::read(store.state_path()).expect("read state after prepared conflict"),
            before
        );
        assert!(store.prepared_stage_path().exists());
        assert!(
            !revocation_cleanup_entries_absent_in(&root, identity)
                .expect("safe prepared entry is present")
        );
    }

    #[test]
    fn revocation_cleanup_absence_check_rejects_unsafe_entries_without_repair() {
        let temp = tempfile::tempdir().expect("create cleanup tempdir");
        let root = fs::canonicalize(temp.path())
            .expect("canonicalize cleanup tempdir")
            .join("remote-state");
        let identity = cleanup_identity();
        let store = cleanup_store(&root, identity);
        store
            .commit_initial(&CryptoStateSnapshot::new(b"unsafe fixture".to_vec()))
            .expect("commit cleanup fixture state");
        let path = store.state_path();
        let before = fs::read(path).expect("read unsafe fixture before audit");
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
            .expect("make cleanup fixture unsafe");

        assert!(matches!(
            revocation_cleanup_entries_absent_in(&root, identity),
            Err(CryptoStateError::UnsafeFile { .. })
        ));
        assert_eq!(
            fs::symlink_metadata(path)
                .expect("read unsafe fixture mode")
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
        assert_eq!(
            fs::read(path).expect("read unsafe fixture after audit"),
            before
        );
    }
}
