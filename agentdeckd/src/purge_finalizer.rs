//! `daemon uninstall --purge` 的 daemon-only 两阶段 finalizer。
//!
//! Runtime DB 从不单独充当删除授权。运行中 daemon 只从 Store-authenticated
//! `PurgeReadbackAbsent`、`LocalDeleted` tombstone 或明确未登记的本机 identity 铸造
//! 窄授权，再把独立 Keychain marker 冻结并 exact readback；one-shot helper
//! existing-only 加载该 marker，按单调 phase 删除。正在运行的 helper/version 是
//! crash recovery anchor，不由本模块自删；marker 成功删除并 readback 后，由 CLI
//! 清理该无 secret artifact。

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use agentdeck_crypto::sha256;
use agentdeck_protocol::runtime::{ArtifactSha256, UninstallPurgePlanV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::compiled_stable_keychain_access_group;
use crate::remote::identity::{
    KEY_DIRECTORY_GUARD_ACCOUNT, MACHINE_DATA_SIGN_ACCOUNT, MACHINE_HPKE_ACCOUNT,
    MACHINE_LINK_SIGN_ACCOUNT, MACHINE_ROOT_SIGN_ACCOUNT,
};
use crate::runtime::namespace::DaemonPaths;
use crate::runtime::singleton::{SingletonError, SingletonGuard};
use crate::runtime::store::{
    LocalDeletedMachineEnrollmentState, MachineCleanupWitnessV1, MachineIdentityBinding,
    MachineIdentityLifecycle, MachineIdentityStateRecord, MachinePurgeReadbackProof,
    MachineRemoteLifecycle, MachineTrustResetKind, PurgeReadbackAbsentMachineEnrollmentState,
    RuntimeStoreHandle,
};
use crate::security::{KeyStore, KeyStoreError, STORAGE_KEK_ACCOUNT, SecretBytes};

pub const PURGE_FINALIZER_MARKER_ACCOUNT: &str = "purge-finalizer-phase.v1";

const MARKER_VERSION: u16 = 1;
const MAX_MARKER_BYTES: usize = 64 * 1024;
const MAX_VERSION_ENTRIES: usize = 32;
const DATA_DIR_MODE: u32 = 0o700;
const INSTALL_DIR_MODE: u32 = 0o700;
const HELPER_MODE: u32 = 0o500;
const PLIST_MODE: u32 = 0o600;
const RUNTIME_FILE_MODE: u32 = 0o600;
const DAEMON_BASENAME: &str = "agentdeckd";
const CURRENT_BASENAME: &str = "current";
const PLIST_BASENAME: &str = "com.agentdeck.agentdeckd.plist";
const PURGE_RETAINED_HELPER_BASENAME: &str = "purge-retained-agentdeckd-v1";

static FINALIZER_IO: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PurgeFinalizerPhase {
    Prepared,
    InstallDetached,
    RuntimeRemoved,
    MachineSecretsRemoved,
    StorageKekRemoved,
}

impl PurgeFinalizerPhase {
    const fn next(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::InstallDetached),
            Self::InstallDetached => Some(Self::RuntimeRemoved),
            Self::RuntimeRemoved => Some(Self::MachineSecretsRemoved),
            Self::MachineSecretsRemoved => Some(Self::StorageKekRemoved),
            Self::StorageKekRemoved => None,
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Prepared => 0,
            Self::InstallDetached => 1,
            Self::RuntimeRemoved => 2,
            Self::MachineSecretsRemoved => 3,
            Self::StorageKekRemoved => 4,
        }
    }
}

/// 只能由当前 open Store 的 authenticated state 构造；字段私有、不可由 wire/CLI
/// 直接构造。`LocalDeleted` 额外绑定 cleanup witness；未登记路径绑定完整 machine
/// identity 摘要，避免把“没有 remote row”误当成裸删除授权。
pub struct AuthenticatedPurgeAuthorization {
    binding: PurgeAuthorizationBinding,
}

impl AuthenticatedPurgeAuthorization {
    pub fn from_purge_readback_absent(
        store: &RuntimeStoreHandle,
        state: &PurgeReadbackAbsentMachineEnrollmentState,
    ) -> Result<Self, PurgeFinalizerError> {
        let database_id = store.authenticated_database_id();
        let purge_proof_hash = match (&state.reset_kind, &state.proof) {
            (
                MachineTrustResetKind::RootPresent,
                MachinePurgeReadbackProof::RootPresent { terminal, .. },
            ) => terminal.canonical_frame_hash,
            (MachineTrustResetKind::RootLost, MachinePurgeReadbackProof::RootLost { purge }) => {
                purge.canonical_hash
            }
            _ => return Err(PurgeFinalizerError::AuthorizationInvalid),
        };
        let record = &state.record;
        let required_nonzero = [
            &database_id[..],
            &record.relay_server_id[..],
            &record.machine_route[..],
            &record.root_key_id[..],
            &record.root_fingerprint[..],
            &purge_proof_hash[..],
        ];
        if state.database_id != database_id
            || record.lifecycle != MachineRemoteLifecycle::PurgeReadbackAbsent
            || record.trust_epoch == 0
            || record.root_key_id != state.binding.root_key_id
            || record.root_fingerprint != state.binding.root_fingerprint
            || record.trust_epoch != state.binding.trust_epoch
            || required_nonzero
                .iter()
                .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(PurgeFinalizerError::AuthorizationInvalid);
        }
        Ok(Self {
            binding: remote_authorization_binding(
                database_id,
                record,
                state.reset_kind,
                purge_proof_hash,
                None,
            )?,
        })
    }

    pub fn from_local_deleted(
        store: &RuntimeStoreHandle,
        state: &LocalDeletedMachineEnrollmentState,
    ) -> Result<Self, PurgeFinalizerError> {
        let database_id = store.authenticated_database_id();
        let record = &state.record;
        let witness = MachineCleanupWitnessV1::new(
            state.reset_kind,
            agentdeck_protocol::relay_v2::RelayServerId::from_bytes(record.relay_server_id),
            agentdeck_protocol::relay_v2::MachineRouteId::from_bytes(record.machine_route),
            agentdeck_protocol::relay_v2::RootKeyId::from_bytes(record.root_key_id),
            record.root_fingerprint,
            agentdeck_protocol::relay_v2::TrustEpoch::new(record.trust_epoch),
            state.purge_proof_hash,
        )
        .map_err(|_| PurgeFinalizerError::AuthorizationInvalid)?;
        if record.lifecycle != MachineRemoteLifecycle::LocalDeleted
            || state.previous_prepare_input_hash == [0; 32]
            || state.cleanup_witness_hash == [0; 32]
            || witness.canonical_sha256() != state.cleanup_witness_hash
        {
            return Err(PurgeFinalizerError::AuthorizationInvalid);
        }
        Ok(Self {
            binding: remote_authorization_binding(
                database_id,
                record,
                state.reset_kind,
                state.purge_proof_hash,
                Some(state.cleanup_witness_hash),
            )?,
        })
    }

    pub fn from_unenrolled_identity(
        store: &RuntimeStoreHandle,
        state: &MachineIdentityStateRecord,
    ) -> Result<Self, PurgeFinalizerError> {
        let database_id = store.authenticated_database_id();
        let binding_hash = machine_identity_binding_hash(&state.binding);
        if state.database_id != database_id
            || state.lifecycle != MachineIdentityLifecycle::Active
            || database_id == [0; 16]
            || state.binding.root_key_id == [0; 16]
            || state.binding.root_fingerprint == [0; 32]
            || state.binding.trust_epoch == 0
            || binding_hash == [0; 32]
        {
            return Err(PurgeFinalizerError::AuthorizationInvalid);
        }
        Ok(Self {
            binding: PurgeAuthorizationBinding::Unenrolled {
                database_id,
                root_key_id: state.binding.root_key_id,
                root_fingerprint: state.binding.root_fingerprint,
                trust_epoch: state.binding.trust_epoch,
                key_directory_revision: state.binding.key_directory_revision,
                identity_binding_hash: binding_hash,
            },
        })
    }

    fn requires_machine_items_absent(&self) -> bool {
        matches!(
            self.binding,
            PurgeAuthorizationBinding::Remote {
                cleanup_witness_hash: Some(_),
                ..
            }
        )
    }

    fn requires_machine_items_present(&self) -> bool {
        matches!(self.binding, PurgeAuthorizationBinding::Unenrolled { .. })
    }
}

impl fmt::Debug for AuthenticatedPurgeAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPurgeAuthorization([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "camelCase")]
enum PurgeAuthorizationBinding {
    Unenrolled {
        database_id: [u8; 16],
        root_key_id: [u8; 16],
        root_fingerprint: [u8; 32],
        trust_epoch: u64,
        key_directory_revision: u64,
        identity_binding_hash: [u8; 32],
    },
    Remote {
        database_id: [u8; 16],
        relay_server_id: [u8; 16],
        machine_route: [u8; 16],
        root_key_id: [u8; 16],
        root_fingerprint: [u8; 32],
        trust_epoch: u64,
        reset_kind: u8,
        purge_proof_hash: [u8; 32],
        cleanup_witness_hash: Option<[u8; 32]>,
    },
}

fn remote_authorization_binding(
    database_id: [u8; 16],
    record: &crate::runtime::store::MachineRemoteStateRecord,
    reset_kind: MachineTrustResetKind,
    purge_proof_hash: [u8; 32],
    cleanup_witness_hash: Option<[u8; 32]>,
) -> Result<PurgeAuthorizationBinding, PurgeFinalizerError> {
    let required_nonzero = [
        &database_id[..],
        &record.relay_server_id[..],
        &record.machine_route[..],
        &record.root_key_id[..],
        &record.root_fingerprint[..],
        &purge_proof_hash[..],
    ];
    if record.trust_epoch == 0
        || required_nonzero
            .iter()
            .any(|value| value.iter().all(|byte| *byte == 0))
        || cleanup_witness_hash.is_some_and(|hash| hash == [0; 32])
    {
        return Err(PurgeFinalizerError::AuthorizationInvalid);
    }
    Ok(PurgeAuthorizationBinding::Remote {
        database_id,
        relay_server_id: record.relay_server_id,
        machine_route: record.machine_route,
        root_key_id: record.root_key_id,
        root_fingerprint: record.root_fingerprint,
        trust_epoch: record.trust_epoch,
        reset_kind: match reset_kind {
            MachineTrustResetKind::RootPresent => 1,
            MachineTrustResetKind::RootLost => 2,
        },
        purge_proof_hash,
        cleanup_witness_hash,
    })
}

fn machine_identity_binding_hash(binding: &MachineIdentityBinding) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(32 + 16 + 5 * 8 + 8 * 32);
    bytes.extend_from_slice(b"AgentDeck/PurgeUnenrolledIdentityV1\0");
    bytes.extend_from_slice(&binding.root_key_id);
    bytes.extend_from_slice(&binding.trust_epoch.to_be_bytes());
    bytes.extend_from_slice(&binding.link_generation.to_be_bytes());
    bytes.extend_from_slice(&binding.data_generation.to_be_bytes());
    bytes.extend_from_slice(&binding.key_directory_revision.to_be_bytes());
    bytes.extend_from_slice(&binding.root_public_key);
    bytes.extend_from_slice(&binding.root_fingerprint);
    bytes.extend_from_slice(&binding.machine_hpke_public_key);
    bytes.extend_from_slice(&binding.machine_hpke_fingerprint);
    bytes.extend_from_slice(&binding.link_sign_public_key);
    bytes.extend_from_slice(&binding.link_sign_fingerprint);
    bytes.extend_from_slice(&binding.data_sign_public_key);
    bytes.extend_from_slice(&binding.data_sign_fingerprint);
    sha256(&bytes)
}

/// 正在运行或 one-shot 重启的 daemon helper 自身身份。
#[derive(Clone)]
pub struct RunningFinalizerIdentity {
    observed_executable: PathBuf,
    observed_identity: FsIdentity,
    version: String,
    team_identifier: String,
    keychain_access_group: String,
}

/// 由 stable singleton lock 成功 acquire 产生的 stopped-daemon capability。
/// 仅观察 UDS absent 不能构造本类型；guard 在整个 finalizer 期间保持独占。
pub struct PurgeStoppedPermit {
    guard: SingletonGuard,
    data_dir: String,
}

impl PurgeStoppedPermit {
    pub fn acquire(paths: &DaemonPaths) -> Result<Self, PurgeFinalizerError> {
        if !paths.is_stable_namespace() {
            return Err(PurgeFinalizerError::NamespaceInvalid);
        }
        let guard = SingletonGuard::acquire_existing(paths)?;
        guard.revalidate_data_dir(paths)?;
        require_socket_absent(&paths.socket)?;
        Ok(Self {
            guard,
            data_dir: path_string(&paths.data_dir)?,
        })
    }

    fn revalidate(&self, paths: &DaemonPaths) -> Result<(), PurgeFinalizerError> {
        if self.data_dir != path_string(&paths.data_dir)? {
            return Err(PurgeFinalizerError::StoppedPermitMismatch);
        }
        self.guard.revalidate_data_dir(paths)?;
        require_socket_absent(&paths.socket)
    }
}

impl fmt::Debug for PurgeStoppedPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PurgeStoppedPermit([REDACTED])")
    }
}

impl RunningFinalizerIdentity {
    pub fn production() -> Result<Self, PurgeFinalizerError> {
        let executable = std::env::current_exe().map_err(PurgeFinalizerError::io)?;
        let team_identifier = option_env!("AGENTDECK_DAEMON_TEAM_IDENTIFIER")
            .ok_or(PurgeFinalizerError::IdentityUnavailable)?;
        let keychain_access_group = compiled_stable_keychain_access_group()
            .ok_or(PurgeFinalizerError::IdentityUnavailable)?;
        Self::new(
            executable,
            env!("CARGO_PKG_VERSION").to_owned(),
            team_identifier.to_owned(),
            keychain_access_group,
        )
    }

    #[doc(hidden)]
    pub fn injected_for_test(
        executable: PathBuf,
        version: String,
        team_identifier: String,
        keychain_access_group: String,
    ) -> Result<Self, PurgeFinalizerError> {
        Self::new(executable, version, team_identifier, keychain_access_group)
    }

    fn new(
        executable: PathBuf,
        version: String,
        team_identifier: String,
        keychain_access_group: String,
    ) -> Result<Self, PurgeFinalizerError> {
        if !is_clean_absolute(&executable)
            || version.is_empty()
            || team_identifier.is_empty()
            || keychain_access_group.is_empty()
        {
            return Err(PurgeFinalizerError::IdentityUnavailable);
        }
        let observed_identity = required_regular_identity(&executable, HELPER_MODE)
            .map_err(|_| PurgeFinalizerError::IdentityUnavailable)?;
        Ok(Self {
            observed_executable: executable,
            observed_identity,
            version,
            team_identifier,
            keychain_access_group,
        })
    }

    fn matches_attestation(&self, plan: &UninstallPurgePlanV1) -> bool {
        self.version == plan.helper_version()
            && self.team_identifier == plan.team_identifier()
            && self.keychain_access_group == plan.keychain_access_group()
    }
}

impl fmt::Debug for RunningFinalizerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunningFinalizerIdentity([REDACTED])")
    }
}

pub enum PurgeMarkerRequest<'a> {
    NotRequested,
    Uninstall {
        authorization: AuthenticatedPurgeAuthorization,
        plan: &'a UninstallPurgePlanV1,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparePurgeMarkerOutcome {
    NotRequested,
    Prepared { phase: PurgeFinalizerPhase },
    Replayed { phase: PurgeFinalizerPhase },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeReservedPurgeMarkerOutcome {
    Absent,
    Authorized { phase: PurgeFinalizerPhase },
    Replayed { phase: PurgeFinalizerPhase },
}

/// 已 exact readback 的 purge marker 预留。字段私有，不能由 Runtime wire/CLI 伪造。
#[derive(Clone)]
pub struct PurgeMarkerReservation {
    plan_id: [u8; 16],
    data_dir: String,
}

impl fmt::Debug for PurgeMarkerReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PurgeMarkerReservation([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeFinalizerOutcome {
    Completed,
    AlreadyCompleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeTerminalAbsenceOutcome {
    Proven,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PurgeFinalizerEvent {
    BeforePhase(PurgeFinalizerPhase),
    AfterPhaseAction(PurgeFinalizerPhase),
    AfterPhaseCommit(PurgeFinalizerPhase),
    AfterMarkerDelete,
    AfterPlistDetach,
    AfterRemovableVersionDetach(usize),
    AfterCurrentDetach,
}

#[doc(hidden)]
pub trait PurgeFinalizerObserver: Send + Sync {
    fn observe(&self, event: PurgeFinalizerEvent) -> Result<(), PurgeFinalizerError>;
}

#[derive(Clone, Copy, Default)]
struct NoopObserver;

impl PurgeFinalizerObserver for NoopObserver {
    fn observe(&self, _event: PurgeFinalizerEvent) -> Result<(), PurgeFinalizerError> {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PurgeMarkerV1 {
    marker_version: u16,
    phase: PurgeFinalizerPhase,
    plan: UninstallPurgePlanV1,
    authorization: PurgeMarkerAuthorization,
    data_dir: String,
    data_identity: FsIdentity,
    bin_root_identity: FsIdentity,
    plist: EntryBinding,
    current_link: SymlinkBinding,
    retained_version: VersionBinding,
    removable_versions: Vec<VersionBinding>,
    runtime_artifacts: Vec<EntryBinding>,
    machine_items: Vec<KeyItemBinding>,
    storage_kek_hash: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
enum PurgeMarkerAuthorization {
    Reserved,
    Authorized { binding: PurgeAuthorizationBinding },
}

impl PurgeMarkerV1 {
    fn same_plan(&self, plan: &UninstallPurgePlanV1, paths: &DaemonPaths) -> bool {
        self.marker_version == MARKER_VERSION
            && &self.plan == plan
            && self.data_dir == path_string(&paths.data_dir).unwrap_or_default()
    }

    fn same_authorization(&self, authorization: &AuthenticatedPurgeAuthorization) -> bool {
        matches!(
            &self.authorization,
            PurgeMarkerAuthorization::Authorized { binding }
                if binding == &authorization.binding
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct FsIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    kind: EntryKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum EntryKind {
    File,
    Directory,
    Symlink,
    Socket,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EntryBinding {
    path: String,
    identity: Option<FsIdentity>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SymlinkBinding {
    entry: EntryBinding,
    target: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionBinding {
    version: String,
    directory: EntryBinding,
    helper: EntryBinding,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeyItemBinding {
    account: String,
    secret_hash: Option<[u8; 32]>,
}

struct StableLayout {
    data_dir: PathBuf,
    runtime_db: PathBuf,
    socket: PathBuf,
    bin_root: PathBuf,
    current_link: PathBuf,
    plist: PathBuf,
}

pub fn prepare_purge_marker(
    key_store: &dyn KeyStore,
    paths: &DaemonPaths,
    identity: &RunningFinalizerIdentity,
    request: PurgeMarkerRequest<'_>,
) -> Result<PreparePurgeMarkerOutcome, PurgeFinalizerError> {
    let PurgeMarkerRequest::Uninstall {
        authorization,
        plan,
    } = request
    else {
        return Ok(PreparePurgeMarkerOutcome::NotRequested);
    };
    let reservation = reserve_purge_marker(key_store, paths, identity, plan)?;
    authorize_reserved_purge_marker(key_store, paths, identity, &reservation, authorization)
}

/// 在任何 trust reset 之前冻结 existing-only purge substrate，并对 Keychain 写入做
/// exact readback。相同 plan 的 retry 幂等，异 plan 一律冲突。
pub fn reserve_purge_marker(
    key_store: &dyn KeyStore,
    paths: &DaemonPaths,
    identity: &RunningFinalizerIdentity,
    plan: &UninstallPurgePlanV1,
) -> Result<PurgeMarkerReservation, PurgeFinalizerError> {
    let _guard = lock_finalizer()?;
    let layout = stable_layout(paths, plan)?;
    require_purge_anchor_absent(&layout)?;
    if let Some(existing) = load_marker(key_store)? {
        if !existing.same_plan(plan, paths) {
            return Err(PurgeFinalizerError::MarkerConflict);
        }
        validate_plan_identity(paths, identity, plan, CurrentLinkPolicy::Optional)?;
        return Ok(PurgeMarkerReservation {
            plan_id: *plan.plan_id(),
            data_dir: path_string(&paths.data_dir)?,
        });
    }

    validate_plan_identity(paths, identity, plan, CurrentLinkPolicy::Required)?;
    let marker = snapshot_marker(key_store, &layout, plan.clone())?;
    store_marker_exact(key_store, &marker)?;
    Ok(PurgeMarkerReservation {
        plan_id: *plan.plan_id(),
        data_dir: path_string(&paths.data_dir)?,
    })
}

/// 只接受 store-authenticated `PurgeReadbackAbsent` authorization，并单调提升已预留
/// marker。
pub fn authorize_reserved_purge_marker(
    key_store: &dyn KeyStore,
    paths: &DaemonPaths,
    identity: &RunningFinalizerIdentity,
    reservation: &PurgeMarkerReservation,
    authorization: AuthenticatedPurgeAuthorization,
) -> Result<PreparePurgeMarkerOutcome, PurgeFinalizerError> {
    let _guard = lock_finalizer()?;
    if reservation.plan_id == [0; 16] || reservation.data_dir != path_string(&paths.data_dir)? {
        return Err(PurgeFinalizerError::MarkerConflict);
    }
    let mut marker = load_marker(key_store)?.ok_or(PurgeFinalizerError::MarkerMissing)?;
    if marker.plan.plan_id() != &reservation.plan_id || !marker.same_plan(&marker.plan, paths) {
        return Err(PurgeFinalizerError::MarkerConflict);
    }
    validate_plan_identity(paths, identity, &marker.plan, CurrentLinkPolicy::Required)?;
    let layout = stable_layout(paths, &marker.plan)?;
    validate_namespace(&marker, &layout)?;
    preflight_remaining(key_store, &marker, &layout)?;
    validate_authorization_machine_items(&marker, &authorization)?;
    match &marker.authorization {
        PurgeMarkerAuthorization::Reserved => {
            marker.authorization = PurgeMarkerAuthorization::Authorized {
                binding: authorization.binding,
            };
            store_marker_exact(key_store, &marker)?;
            Ok(PreparePurgeMarkerOutcome::Prepared {
                phase: PurgeFinalizerPhase::Prepared,
            })
        }
        PurgeMarkerAuthorization::Authorized { .. }
            if marker.same_authorization(&authorization) =>
        {
            Ok(PreparePurgeMarkerOutcome::Replayed {
                phase: marker.phase,
            })
        }
        PurgeMarkerAuthorization::Authorized { .. } => Err(PurgeFinalizerError::MarkerConflict),
    }
}

/// daemon crash recovery 专用：不让 manager 读取 marker payload 或依赖 CLI plan。
/// marker absent 是 ordinary trust reset 的只读结果；Reserved 只在 frozen plan、安装
/// layout 与 authenticated PurgeReadbackAbsent 全部精确匹配后单调授权。
pub fn resume_reserved_purge_marker(
    key_store: &dyn KeyStore,
    paths: &DaemonPaths,
    identity: &RunningFinalizerIdentity,
    authorization: AuthenticatedPurgeAuthorization,
) -> Result<ResumeReservedPurgeMarkerOutcome, PurgeFinalizerError> {
    let _guard = lock_finalizer()?;
    let Some(mut marker) = load_marker(key_store)? else {
        return Ok(ResumeReservedPurgeMarkerOutcome::Absent);
    };
    if !marker.same_plan(&marker.plan, paths) {
        return Err(PurgeFinalizerError::MarkerConflict);
    }
    validate_plan_identity(paths, identity, &marker.plan, CurrentLinkPolicy::Required)?;
    let layout = stable_layout(paths, &marker.plan)?;
    validate_namespace(&marker, &layout)?;
    preflight_remaining(key_store, &marker, &layout)?;
    validate_authorization_machine_items(&marker, &authorization)?;
    match &marker.authorization {
        PurgeMarkerAuthorization::Reserved => {
            marker.authorization = PurgeMarkerAuthorization::Authorized {
                binding: authorization.binding,
            };
            store_marker_exact(key_store, &marker)?;
            Ok(ResumeReservedPurgeMarkerOutcome::Authorized {
                phase: marker.phase,
            })
        }
        PurgeMarkerAuthorization::Authorized { .. }
            if marker.same_authorization(&authorization) =>
        {
            Ok(ResumeReservedPurgeMarkerOutcome::Replayed {
                phase: marker.phase,
            })
        }
        PurgeMarkerAuthorization::Authorized { .. } => Err(PurgeFinalizerError::MarkerConflict),
    }
}

/// manager startup 的只读 durable-intent probe。canonical marker 缺失才返回 false；
/// malformed marker 必须 fail-close，不能让 enroll 绕过既有 purge intent。
pub fn purge_marker_intent_present(key_store: &dyn KeyStore) -> Result<bool, PurgeFinalizerError> {
    let _guard = lock_finalizer()?;
    Ok(load_marker(key_store)?.is_some())
}

pub fn run_purge_finalizer(
    key_store: &dyn KeyStore,
    paths: &DaemonPaths,
    identity: &RunningFinalizerIdentity,
    stopped: &PurgeStoppedPermit,
    expected_plan_id: [u8; 16],
) -> Result<PurgeFinalizerOutcome, PurgeFinalizerError> {
    run_purge_finalizer_with_observer(
        key_store,
        paths,
        identity,
        stopped,
        expected_plan_id,
        &NoopObserver,
    )
}

/// production-attested bundled helper 专用的全-absent 只读证明。不接受 plan，也不
/// 复用 destructive phase runner；调用方必须先取得 existing-only stopped permit。
pub fn prove_purge_terminal_absence(
    key_store: &dyn KeyStore,
    paths: &DaemonPaths,
    stopped: &PurgeStoppedPermit,
) -> Result<PurgeTerminalAbsenceOutcome, PurgeFinalizerError> {
    let _guard = lock_finalizer()?;
    stopped.revalidate(paths)?;
    require_socket_absent(&paths.socket)?;
    if load_marker(key_store)?.is_some() {
        return Err(PurgeFinalizerError::TerminalProofFailed);
    }

    let layout = stable_namespace_layout(paths)?;
    for path in [
        layout.plist.clone(),
        layout.current_link.clone(),
        layout.bin_root.clone(),
        layout.data_dir.join(PURGE_RETAINED_HELPER_BASENAME),
    ]
    .into_iter()
    .chain(runtime_artifact_paths(&layout.runtime_db))
    {
        require_absent(&path)?;
    }
    for account in machine_accounts()
        .into_iter()
        .chain([STORAGE_KEK_ACCOUNT, PURGE_FINALIZER_MARKER_ACCOUNT])
    {
        if key_store.load(account)?.is_some() {
            return Err(PurgeFinalizerError::TerminalProofFailed);
        }
    }
    Ok(PurgeTerminalAbsenceOutcome::Proven)
}

#[doc(hidden)]
pub fn run_purge_finalizer_with_observer(
    key_store: &dyn KeyStore,
    paths: &DaemonPaths,
    identity: &RunningFinalizerIdentity,
    stopped: &PurgeStoppedPermit,
    expected_plan_id: [u8; 16],
    observer: &dyn PurgeFinalizerObserver,
) -> Result<PurgeFinalizerOutcome, PurgeFinalizerError> {
    let _guard = lock_finalizer()?;
    let Some(mut marker) = load_marker(key_store)? else {
        return prove_already_completed(key_store, paths, identity, stopped, expected_plan_id);
    };
    if expected_plan_id == [0; 16] || marker.plan.plan_id() != &expected_plan_id {
        return Err(PurgeFinalizerError::PlanMismatch);
    }
    if matches!(marker.authorization, PurgeMarkerAuthorization::Reserved) {
        return Err(PurgeFinalizerError::MarkerUnauthorized);
    }
    stopped.revalidate(paths)?;
    validate_marker(&marker)?;
    validate_plan_identity(paths, identity, &marker.plan, CurrentLinkPolicy::Optional)?;
    let layout = stable_layout(paths, &marker.plan)?;
    validate_namespace(&marker, &layout)?;
    require_socket_absent(&layout.socket)?;
    preflight_remaining(key_store, &marker, &layout)?;
    replay_completed_prefix(key_store, &marker, &layout)?;

    loop {
        let phase = marker.phase;
        observer.observe(PurgeFinalizerEvent::BeforePhase(phase))?;
        match phase {
            PurgeFinalizerPhase::Prepared => {
                detach_install_artifacts(&marker, &layout, observer)?;
            }
            PurgeFinalizerPhase::InstallDetached => remove_runtime_artifacts(&marker)?,
            PurgeFinalizerPhase::RuntimeRemoved => {
                remove_bound_key_items(key_store, &marker.machine_items)?;
            }
            PurgeFinalizerPhase::MachineSecretsRemoved => {
                remove_storage_kek(key_store, marker.storage_kek_hash)?;
            }
            PurgeFinalizerPhase::StorageKekRemoved => {
                delete_marker_exact(key_store)?;
                observer.observe(PurgeFinalizerEvent::AfterMarkerDelete)?;
                return Ok(PurgeFinalizerOutcome::Completed);
            }
        }
        observer.observe(PurgeFinalizerEvent::AfterPhaseAction(phase))?;
        marker.phase = phase.next().ok_or(PurgeFinalizerError::MarkerInvalid)?;
        store_marker_exact(key_store, &marker)?;
        observer.observe(PurgeFinalizerEvent::AfterPhaseCommit(marker.phase))?;
    }
}

fn prove_already_completed(
    key_store: &dyn KeyStore,
    paths: &DaemonPaths,
    identity: &RunningFinalizerIdentity,
    stopped: &PurgeStoppedPermit,
    expected_plan_id: [u8; 16],
) -> Result<PurgeFinalizerOutcome, PurgeFinalizerError> {
    if expected_plan_id == [0; 16] {
        return Err(PurgeFinalizerError::PlanMismatch);
    }
    stopped.revalidate(paths)?;
    require_socket_absent(&paths.socket)?;

    let original_helper_path = paths
        .data_dir
        .join("bin")
        .join(&identity.version)
        .join(DAEMON_BASENAME);
    let anchor_path = paths.data_dir.join(PURGE_RETAINED_HELPER_BASENAME);
    let anchored = identity.observed_executable == anchor_path;
    let observed_helper_path = if anchored {
        &anchor_path
    } else {
        &original_helper_path
    };
    let helper_identity = required_regular_identity(observed_helper_path, HELPER_MODE)?;
    compare_file_identity(helper_identity, identity.observed_identity)?;
    let helper_hash = hash_regular_file(observed_helper_path, Some(helper_identity))?;
    let plan = UninstallPurgePlanV1::new(
        original_helper_path,
        identity.version.clone(),
        ArtifactSha256::new(hex(&helper_hash)).map_err(|_| PurgeFinalizerError::PlanMismatch)?,
        identity.team_identifier.clone(),
        identity.keychain_access_group.clone(),
    )
    .map_err(|_| PurgeFinalizerError::PlanMismatch)?;
    if plan.plan_id() != &expected_plan_id {
        return Err(PurgeFinalizerError::PlanMismatch);
    }
    let layout = stable_layout(paths, &plan)?;
    if anchored {
        if !identity.matches_attestation(&plan)
            || paths.keychain_access_group.as_deref() != Some(plan.keychain_access_group())
        {
            return Err(PurgeFinalizerError::PlanMismatch);
        }
        validate_anchor_terminal_install_layout(&layout, identity, &anchor_path)?;
    } else {
        require_absent(&anchor_path)?;
        validate_plan_identity(paths, identity, &plan, CurrentLinkPolicy::Absent)?;
        validate_terminal_install_layout(&layout, identity)?;
    }
    require_absent(&layout.plist)?;
    for artifact in runtime_artifact_paths(&layout.runtime_db) {
        require_absent(&artifact)?;
    }
    for account in machine_accounts()
        .into_iter()
        .chain([STORAGE_KEK_ACCOUNT, PURGE_FINALIZER_MARKER_ACCOUNT])
    {
        if key_store.load(account)?.is_some() {
            return Err(PurgeFinalizerError::TerminalProofFailed);
        }
    }
    Ok(PurgeFinalizerOutcome::AlreadyCompleted)
}

fn validate_terminal_install_layout(
    layout: &StableLayout,
    identity: &RunningFinalizerIdentity,
) -> Result<(), PurgeFinalizerError> {
    required_directory(&layout.bin_root, INSTALL_DIR_MODE)?;
    let entries = std::fs::read_dir(&layout.bin_root)
        .map_err(PurgeFinalizerError::io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(PurgeFinalizerError::io)?;
    if entries.len() != 1 || entries[0].file_name() != identity.version.as_str() {
        return Err(PurgeFinalizerError::TerminalProofFailed);
    }
    let version_dir = entries[0].path();
    required_directory(&version_dir, INSTALL_DIR_MODE)?;
    let children = std::fs::read_dir(&version_dir)
        .map_err(PurgeFinalizerError::io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(PurgeFinalizerError::io)?;
    if children.len() != 1 || children[0].file_name() != DAEMON_BASENAME {
        return Err(PurgeFinalizerError::TerminalProofFailed);
    }
    let helper_identity = required_regular_identity(&children[0].path(), HELPER_MODE)?;
    compare_file_identity(helper_identity, identity.observed_identity)
}

fn validate_anchor_terminal_install_layout(
    layout: &StableLayout,
    identity: &RunningFinalizerIdentity,
    anchor_path: &Path,
) -> Result<(), PurgeFinalizerError> {
    if identity.observed_executable != anchor_path {
        return Err(PurgeFinalizerError::TerminalProofFailed);
    }
    let anchor_identity = required_regular_identity(anchor_path, HELPER_MODE)?;
    compare_file_identity(anchor_identity, identity.observed_identity)?;
    require_absent(&layout.current_link)?;

    let Some(_) = capture_identity(&layout.bin_root)? else {
        return Ok(());
    };
    required_directory(&layout.bin_root, INSTALL_DIR_MODE)?;
    let entries = std::fs::read_dir(&layout.bin_root)
        .map_err(PurgeFinalizerError::io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(PurgeFinalizerError::io)?;
    if entries.is_empty() {
        return Ok(());
    }
    if entries.len() != 1 || entries[0].file_name() != identity.version.as_str() {
        return Err(PurgeFinalizerError::TerminalProofFailed);
    }
    let version_dir = entries[0].path();
    required_directory(&version_dir, INSTALL_DIR_MODE)?;
    if std::fs::read_dir(&version_dir)
        .map_err(PurgeFinalizerError::io)?
        .next()
        .transpose()
        .map_err(PurgeFinalizerError::io)?
        .is_some()
    {
        return Err(PurgeFinalizerError::TerminalProofFailed);
    }
    Ok(())
}

fn snapshot_marker(
    key_store: &dyn KeyStore,
    layout: &StableLayout,
    plan: UninstallPurgePlanV1,
) -> Result<PurgeMarkerV1, PurgeFinalizerError> {
    let data_identity = required_directory(&layout.data_dir, DATA_DIR_MODE)?;
    let bin_root_identity = required_directory(&layout.bin_root, INSTALL_DIR_MODE)?;
    let plist = required_regular_binding(&layout.plist, PLIST_MODE)?;
    let current_link = required_current_link(&layout.current_link)?;
    if current_link.target.as_deref() != Some(plan.helper_version()) {
        return Err(PurgeFinalizerError::PlanMismatch);
    }
    let (retained_version, removable_versions) = snapshot_versions(layout, &plan)?;
    let runtime_artifacts = runtime_artifact_paths(&layout.runtime_db)
        .iter()
        .map(|path| optional_regular_binding(path, RUNTIME_FILE_MODE))
        .collect::<Result<Vec<_>, _>>()?;
    let machine_items = machine_accounts()
        .iter()
        .map(|account| {
            Ok(KeyItemBinding {
                account: (*account).to_owned(),
                secret_hash: load_secret_hash(key_store, account)?,
            })
        })
        .collect::<Result<Vec<_>, PurgeFinalizerError>>()?;
    let storage_kek_hash = load_secret_hash(key_store, STORAGE_KEK_ACCOUNT)?
        .ok_or(PurgeFinalizerError::StorageKekMissing)?;
    Ok(PurgeMarkerV1 {
        marker_version: MARKER_VERSION,
        phase: PurgeFinalizerPhase::Prepared,
        plan,
        authorization: PurgeMarkerAuthorization::Reserved,
        data_dir: path_string(&layout.data_dir)?,
        data_identity,
        bin_root_identity,
        plist,
        current_link,
        retained_version,
        removable_versions,
        runtime_artifacts,
        machine_items,
        storage_kek_hash,
    })
}

fn stable_layout(
    paths: &DaemonPaths,
    plan: &UninstallPurgePlanV1,
) -> Result<StableLayout, PurgeFinalizerError> {
    let layout = stable_namespace_layout(paths)?;
    let expected_helper = layout
        .bin_root
        .join(plan.helper_version())
        .join(DAEMON_BASENAME);
    if plan.helper_path() != expected_helper {
        return Err(PurgeFinalizerError::PlanMismatch);
    }
    Ok(layout)
}

fn stable_namespace_layout(paths: &DaemonPaths) -> Result<StableLayout, PurgeFinalizerError> {
    if !paths.is_stable_namespace() || !is_clean_absolute(&paths.data_dir) {
        return Err(PurgeFinalizerError::NamespaceInvalid);
    }
    let application_support = paths
        .data_dir
        .parent()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name == "Application Support")
        })
        .ok_or(PurgeFinalizerError::NamespaceInvalid)?;
    let library = application_support
        .parent()
        .filter(|path| path.file_name().is_some_and(|name| name == "Library"))
        .ok_or(PurgeFinalizerError::NamespaceInvalid)?;
    let home = library
        .parent()
        .ok_or(PurgeFinalizerError::NamespaceInvalid)?;
    let bin_root = paths.data_dir.join("bin");
    if paths.runtime_db != paths.data_dir.join("runtime.db")
        || paths.socket != paths.data_dir.join("agentdeckd.sock")
    {
        return Err(PurgeFinalizerError::NamespaceInvalid);
    }
    Ok(StableLayout {
        data_dir: paths.data_dir.clone(),
        runtime_db: paths.runtime_db.clone(),
        socket: paths.socket.clone(),
        current_link: bin_root.join(CURRENT_BASENAME),
        bin_root,
        plist: home
            .join("Library")
            .join("LaunchAgents")
            .join(PLIST_BASENAME),
    })
}

#[derive(Clone, Copy)]
enum CurrentLinkPolicy {
    Required,
    Optional,
    Absent,
}

fn validate_plan_identity(
    paths: &DaemonPaths,
    identity: &RunningFinalizerIdentity,
    plan: &UninstallPurgePlanV1,
    current_policy: CurrentLinkPolicy,
) -> Result<(), PurgeFinalizerError> {
    let expected_plan_id = UninstallPurgePlanV1::derive_plan_id(
        plan.helper_path(),
        plan.helper_version(),
        plan.helper_sha256(),
        plan.team_identifier(),
        plan.keychain_access_group(),
    )
    .map_err(|_| PurgeFinalizerError::PlanMismatch)?;
    if expected_plan_id != *plan.plan_id()
        || !identity.matches_attestation(plan)
        || paths.keychain_access_group.as_deref() != Some(plan.keychain_access_group())
    {
        return Err(PurgeFinalizerError::PlanMismatch);
    }
    let layout = stable_layout(paths, plan)?;
    let helper_identity = required_regular_identity(plan.helper_path(), HELPER_MODE)?;
    let current_executable = layout.current_link.join(DAEMON_BASENAME);
    if identity.observed_executable != plan.helper_path()
        && identity.observed_executable != current_executable
    {
        return Err(PurgeFinalizerError::PlanMismatch);
    }
    compare_file_identity(helper_identity, identity.observed_identity)?;

    let current = capture_identity(&layout.current_link)?;
    match (current_policy, current) {
        (CurrentLinkPolicy::Required, None) => {
            return Err(PurgeFinalizerError::InstallLayoutInvalid);
        }
        (CurrentLinkPolicy::Absent, Some(_)) => {
            return Err(PurgeFinalizerError::InstallLayoutInvalid);
        }
        (_, Some(_)) => {
            let binding = required_current_link(&layout.current_link)?;
            if binding.target.as_deref() != Some(plan.helper_version()) {
                return Err(PurgeFinalizerError::PlanMismatch);
            }
            let alias_identity = required_regular_identity(&current_executable, HELPER_MODE)?;
            compare_file_identity(alias_identity, helper_identity)?;
            compare_file_identity(alias_identity, identity.observed_identity)?;
        }
        (CurrentLinkPolicy::Optional | CurrentLinkPolicy::Absent, None) => {}
    }

    let hash = hash_regular_file(plan.helper_path(), Some(helper_identity))?;
    if hex(&hash) != plan.helper_sha256().as_str() {
        return Err(PurgeFinalizerError::HelperMismatch);
    }
    Ok(())
}

fn snapshot_versions(
    layout: &StableLayout,
    plan: &UninstallPurgePlanV1,
) -> Result<(VersionBinding, Vec<VersionBinding>), PurgeFinalizerError> {
    required_directory(&layout.bin_root, INSTALL_DIR_MODE)?;
    let mut versions = BTreeMap::new();
    let entries = std::fs::read_dir(&layout.bin_root).map_err(PurgeFinalizerError::io)?;
    for entry in entries {
        let entry = entry.map_err(PurgeFinalizerError::io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PurgeFinalizerError::InstallLayoutInvalid)?;
        if name == CURRENT_BASENAME {
            continue;
        }
        if !valid_version(&name) || versions.len() >= MAX_VERSION_ENTRIES {
            return Err(PurgeFinalizerError::InstallLayoutInvalid);
        }
        let directory_path = layout.bin_root.join(&name);
        let directory = EntryBinding {
            path: path_string(&directory_path)?,
            identity: Some(required_directory(&directory_path, INSTALL_DIR_MODE)?),
        };
        let helper_path = directory_path.join(DAEMON_BASENAME);
        let helper = required_regular_binding(&helper_path, HELPER_MODE)?;
        let mut children = std::fs::read_dir(&directory_path)
            .map_err(PurgeFinalizerError::io)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(PurgeFinalizerError::io)?;
        if children.len() != 1
            || children
                .pop()
                .is_none_or(|child| child.file_name() != DAEMON_BASENAME)
        {
            return Err(PurgeFinalizerError::InstallLayoutInvalid);
        }
        versions.insert(
            name.clone(),
            VersionBinding {
                version: name,
                directory,
                helper,
            },
        );
    }
    let retained = versions
        .remove(plan.helper_version())
        .ok_or(PurgeFinalizerError::InstallLayoutInvalid)?;
    if retained.helper.path != path_string(plan.helper_path())? {
        return Err(PurgeFinalizerError::PlanMismatch);
    }
    Ok((retained, versions.into_values().collect()))
}

fn detach_install_artifacts(
    marker: &PurgeMarkerV1,
    layout: &StableLayout,
    observer: &dyn PurgeFinalizerObserver,
) -> Result<(), PurgeFinalizerError> {
    validate_install_snapshot(marker, layout)?;
    remove_bound_entry(&marker.plist)?;
    observer.observe(PurgeFinalizerEvent::AfterPlistDetach)?;
    for (index, version) in marker.removable_versions.iter().enumerate() {
        remove_bound_entry(&version.helper)?;
        remove_bound_directory(&version.directory)?;
        observer.observe(PurgeFinalizerEvent::AfterRemovableVersionDetach(index))?;
    }
    remove_bound_symlink(&marker.current_link)?;
    observer.observe(PurgeFinalizerEvent::AfterCurrentDetach)?;
    validate_retained_version(&marker.retained_version)?;
    Ok(())
}

fn validate_install_snapshot(
    marker: &PurgeMarkerV1,
    layout: &StableLayout,
) -> Result<(), PurgeFinalizerError> {
    compare_directory_identity(
        required_directory(&layout.bin_root, INSTALL_DIR_MODE)?,
        marker.bin_root_identity,
    )?;
    validate_optional_bound_entry(&marker.plist)?;
    validate_optional_bound_symlink(&marker.current_link)?;
    validate_retained_version(&marker.retained_version)?;
    validate_exact_version_children(&marker.retained_version)?;
    for version in &marker.removable_versions {
        validate_optional_bound_entry(&version.helper)?;
        validate_optional_bound_directory(&version.directory)?;
        validate_exact_version_children(version)?;
    }
    let expected = std::iter::once(CURRENT_BASENAME.to_owned())
        .chain(std::iter::once(marker.retained_version.version.clone()))
        .chain(
            marker
                .removable_versions
                .iter()
                .map(|version| version.version.clone()),
        )
        .collect::<std::collections::BTreeSet<_>>();
    for entry in std::fs::read_dir(&layout.bin_root).map_err(PurgeFinalizerError::io)? {
        let name = entry
            .map_err(PurgeFinalizerError::io)?
            .file_name()
            .into_string()
            .map_err(|_| PurgeFinalizerError::InstallLayoutInvalid)?;
        if !expected.contains(&name) {
            return Err(PurgeFinalizerError::InstallLayoutInvalid);
        }
    }
    Ok(())
}

/// marker 冻结时每个 version 目录只有 `agentdeckd`。Prepared phase 可能在上次
/// crash 中已经删掉某个 removable helper/空目录，因此 retry 接受相同绑定的
/// `agentdeckd`、空目录或整个目录已 absent；任何额外 child 都必须在第一笔新删除
/// 之前 fail-close。
fn validate_exact_version_children(version: &VersionBinding) -> Result<(), PurgeFinalizerError> {
    let directory = Path::new(&version.directory.path);
    if capture_identity(directory)?.is_none() {
        return Ok(());
    }
    let helper_present = capture_identity(Path::new(&version.helper.path))?.is_some();
    let mut child_count = 0_usize;
    for child in std::fs::read_dir(directory).map_err(PurgeFinalizerError::io)? {
        let child = child.map_err(PurgeFinalizerError::io)?;
        child_count = child_count.saturating_add(1);
        if child.file_name() != DAEMON_BASENAME || child_count != 1 {
            return Err(PurgeFinalizerError::InstallLayoutInvalid);
        }
    }
    if child_count != usize::from(helper_present) {
        return Err(PurgeFinalizerError::InstallLayoutInvalid);
    }
    Ok(())
}

fn remove_runtime_artifacts(marker: &PurgeMarkerV1) -> Result<(), PurgeFinalizerError> {
    validate_runtime_artifacts(marker)?;
    for artifact in &marker.runtime_artifacts {
        remove_bound_entry(artifact)?;
    }
    Ok(())
}

fn remove_bound_key_items(
    key_store: &dyn KeyStore,
    bindings: &[KeyItemBinding],
) -> Result<(), PurgeFinalizerError> {
    let current = validate_bound_key_items(key_store, bindings)?;
    for (binding, present) in bindings.iter().zip(current) {
        if present {
            delete_key_exact(key_store, &binding.account)?;
        }
    }
    Ok(())
}

fn remove_storage_kek(
    key_store: &dyn KeyStore,
    expected_hash: [u8; 32],
) -> Result<(), PurgeFinalizerError> {
    if let Some(actual) = load_secret_hash(key_store, STORAGE_KEK_ACCOUNT)? {
        if actual != expected_hash {
            return Err(PurgeFinalizerError::StorageKekConflict);
        }
        delete_key_exact(key_store, STORAGE_KEK_ACCOUNT)?;
    }
    Ok(())
}

fn validate_marker(marker: &PurgeMarkerV1) -> Result<(), PurgeFinalizerError> {
    if marker.marker_version != MARKER_VERSION
        || marker.machine_items.len() != machine_accounts().len()
    {
        return Err(PurgeFinalizerError::MarkerInvalid);
    }
    if let PurgeMarkerAuthorization::Authorized { binding } = &marker.authorization {
        let valid = match binding {
            PurgeAuthorizationBinding::Unenrolled {
                database_id,
                root_key_id,
                root_fingerprint,
                trust_epoch,
                key_directory_revision: _,
                identity_binding_hash,
            } => {
                *database_id != [0; 16]
                    && *root_key_id != [0; 16]
                    && *root_fingerprint != [0; 32]
                    && *trust_epoch != 0
                    && *identity_binding_hash != [0; 32]
            }
            PurgeAuthorizationBinding::Remote {
                database_id,
                relay_server_id,
                machine_route,
                root_key_id,
                root_fingerprint,
                trust_epoch,
                reset_kind,
                purge_proof_hash,
                cleanup_witness_hash,
            } => {
                *database_id != [0; 16]
                    && *relay_server_id != [0; 16]
                    && *machine_route != [0; 16]
                    && *root_key_id != [0; 16]
                    && *root_fingerprint != [0; 32]
                    && *trust_epoch != 0
                    && matches!(*reset_kind, 1 | 2)
                    && *purge_proof_hash != [0; 32]
                    && cleanup_witness_hash.is_none_or(|hash| hash != [0; 32])
            }
        };
        if !valid {
            return Err(PurgeFinalizerError::MarkerInvalid);
        }
    }
    Ok(())
}

fn validate_namespace(
    marker: &PurgeMarkerV1,
    layout: &StableLayout,
) -> Result<(), PurgeFinalizerError> {
    if marker.data_dir != path_string(&layout.data_dir)? {
        return Err(PurgeFinalizerError::NamespaceInvalid);
    }
    let actual = required_directory(&layout.data_dir, DATA_DIR_MODE)?;
    compare_directory_identity(actual, marker.data_identity)?;
    compare_directory_identity(
        required_directory(&layout.bin_root, INSTALL_DIR_MODE)?,
        marker.bin_root_identity,
    )
}

fn preflight_remaining(
    key_store: &dyn KeyStore,
    marker: &PurgeMarkerV1,
    layout: &StableLayout,
) -> Result<(), PurgeFinalizerError> {
    // flat anchor 只属于 marker 已删除后的 CLI 收尾窗口；marker 生命周期内出现即是
    // 离线注入，必须在任何后续删除或 marker 授权写入前拒绝。
    require_purge_anchor_absent(layout)?;
    // retained helper/version 是所有 phase 的恢复锚点；每次进程重启后的第一笔新删除
    // 前都要重新证明其 exact-child layout，不能只在初始 Prepared phase 检查。
    validate_install_snapshot(marker, layout)?;
    // completed prefix 也可能因 filesystem durability rollback 再次出现。任何写入前
    // 先全局认证所有 frozen binding；exact present 可在后续 replay 删除，冲突项则
    // 零写 fail-close。
    validate_runtime_artifacts(marker)?;
    validate_bound_key_items(key_store, &marker.machine_items)?;
    validate_storage_kek(key_store, marker.storage_kek_hash)?;
    Ok(())
}

fn validate_authorization_machine_items(
    marker: &PurgeMarkerV1,
    authorization: &AuthenticatedPurgeAuthorization,
) -> Result<(), PurgeFinalizerError> {
    if authorization.requires_machine_items_absent()
        && marker
            .machine_items
            .iter()
            .any(|binding| binding.secret_hash.is_some())
    {
        return Err(PurgeFinalizerError::AuthorizationInvalid);
    }
    if authorization.requires_machine_items_present()
        && marker
            .machine_items
            .iter()
            .any(|binding| binding.secret_hash.is_none())
    {
        return Err(PurgeFinalizerError::AuthorizationInvalid);
    }
    Ok(())
}

fn replay_completed_prefix(
    key_store: &dyn KeyStore,
    marker: &PurgeMarkerV1,
    layout: &StableLayout,
) -> Result<(), PurgeFinalizerError> {
    if marker.phase.rank() >= PurgeFinalizerPhase::InstallDetached.rank() {
        detach_install_artifacts(marker, layout, &NoopObserver)?;
    }
    if marker.phase.rank() >= PurgeFinalizerPhase::RuntimeRemoved.rank() {
        remove_runtime_artifacts(marker)?;
    }
    if marker.phase.rank() >= PurgeFinalizerPhase::MachineSecretsRemoved.rank() {
        remove_bound_key_items(key_store, &marker.machine_items)?;
    }
    if marker.phase.rank() >= PurgeFinalizerPhase::StorageKekRemoved.rank() {
        remove_storage_kek(key_store, marker.storage_kek_hash)?;
    }
    Ok(())
}

fn require_purge_anchor_absent(layout: &StableLayout) -> Result<(), PurgeFinalizerError> {
    if capture_identity(&layout.data_dir.join(PURGE_RETAINED_HELPER_BASENAME))?.is_some() {
        return Err(PurgeFinalizerError::InstallLayoutInvalid);
    }
    Ok(())
}

fn validate_runtime_artifacts(marker: &PurgeMarkerV1) -> Result<(), PurgeFinalizerError> {
    for artifact in &marker.runtime_artifacts {
        validate_optional_bound_entry(artifact)?;
    }
    Ok(())
}

fn validate_bound_key_items(
    key_store: &dyn KeyStore,
    bindings: &[KeyItemBinding],
) -> Result<Vec<bool>, PurgeFinalizerError> {
    bindings
        .iter()
        .map(|binding| {
            let hash = load_secret_hash(key_store, &binding.account)?;
            if hash.is_some() && hash != binding.secret_hash {
                return Err(PurgeFinalizerError::KeyItemConflict);
            }
            if binding.secret_hash.is_none() && hash.is_some() {
                return Err(PurgeFinalizerError::KeyItemConflict);
            }
            Ok(hash.is_some())
        })
        .collect()
}

fn validate_storage_kek(
    key_store: &dyn KeyStore,
    expected_hash: [u8; 32],
) -> Result<(), PurgeFinalizerError> {
    if load_secret_hash(key_store, STORAGE_KEK_ACCOUNT)?
        .is_some_and(|actual| actual != expected_hash)
    {
        return Err(PurgeFinalizerError::StorageKekConflict);
    }
    Ok(())
}

fn validate_retained_version(version: &VersionBinding) -> Result<(), PurgeFinalizerError> {
    validate_required_bound_directory(&version.directory)?;
    validate_required_bound_entry(&version.helper)
}

fn required_current_link(path: &Path) -> Result<SymlinkBinding, PurgeFinalizerError> {
    let identity = capture_identity(path)?.ok_or(PurgeFinalizerError::InstallLayoutInvalid)?;
    if identity.kind != EntryKind::Symlink || identity.links != 1 {
        return Err(PurgeFinalizerError::InstallLayoutInvalid);
    }
    let target = std::fs::read_link(path).map_err(PurgeFinalizerError::io)?;
    let target = target
        .to_str()
        .filter(|target| valid_version(target) && Path::new(target).components().count() == 1)
        .ok_or(PurgeFinalizerError::InstallLayoutInvalid)?;
    Ok(SymlinkBinding {
        entry: EntryBinding {
            path: path_string(path)?,
            identity: Some(identity),
        },
        target: Some(target.to_owned()),
    })
}

fn required_regular_binding(path: &Path, mode: u32) -> Result<EntryBinding, PurgeFinalizerError> {
    let identity = required_regular_identity(path, mode)?;
    Ok(EntryBinding {
        path: path_string(path)?,
        identity: Some(identity),
    })
}

fn required_regular_identity(path: &Path, mode: u32) -> Result<FsIdentity, PurgeFinalizerError> {
    let identity = capture_identity(path)?.ok_or(PurgeFinalizerError::FilesystemUnsafe)?;
    if identity.kind != EntryKind::File || identity.mode != mode || identity.links != 1 {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    Ok(identity)
}

fn optional_regular_binding(path: &Path, mode: u32) -> Result<EntryBinding, PurgeFinalizerError> {
    let identity = capture_identity(path)?;
    if identity.is_some_and(|identity| {
        identity.kind != EntryKind::File || identity.mode != mode || identity.links != 1
    }) {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    Ok(EntryBinding {
        path: path_string(path)?,
        identity,
    })
}

fn required_directory(path: &Path, mode: u32) -> Result<FsIdentity, PurgeFinalizerError> {
    let identity = capture_identity(path)?.ok_or(PurgeFinalizerError::FilesystemUnsafe)?;
    if identity.kind != EntryKind::Directory || identity.mode != mode || identity.links == 0 {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    Ok(identity)
}

fn capture_identity(path: &Path) -> Result<Option<FsIdentity>, PurgeFinalizerError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PurgeFinalizerError::io(error)),
    };
    // SAFETY: geteuid reads process credentials without preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    let file_type = metadata.file_type();
    let kind = if file_type.is_file() {
        EntryKind::File
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_socket() {
        EntryKind::Socket
    } else {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    };
    Ok(Some(FsIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o7777,
        links: metadata.nlink(),
        kind,
    }))
}

fn validate_required_bound_entry(binding: &EntryBinding) -> Result<(), PurgeFinalizerError> {
    let expected = required_identity(binding)?;
    let actual =
        capture_identity(Path::new(&binding.path))?.ok_or(PurgeFinalizerError::FilesystemUnsafe)?;
    compare_file_identity(actual, expected)
}

fn validate_optional_bound_entry(binding: &EntryBinding) -> Result<(), PurgeFinalizerError> {
    let Some(actual) = capture_identity(Path::new(&binding.path))? else {
        return Ok(());
    };
    let expected = binding
        .identity
        .ok_or(PurgeFinalizerError::FilesystemUnsafe)?;
    compare_file_identity(actual, expected)
}

fn validate_required_bound_directory(binding: &EntryBinding) -> Result<(), PurgeFinalizerError> {
    let expected = required_identity(binding)?;
    let actual =
        capture_identity(Path::new(&binding.path))?.ok_or(PurgeFinalizerError::FilesystemUnsafe)?;
    compare_directory_identity(actual, expected)
}

fn validate_optional_bound_directory(binding: &EntryBinding) -> Result<(), PurgeFinalizerError> {
    let Some(actual) = capture_identity(Path::new(&binding.path))? else {
        return Ok(());
    };
    compare_directory_identity(actual, required_identity(binding)?)
}

fn validate_optional_bound_symlink(binding: &SymlinkBinding) -> Result<(), PurgeFinalizerError> {
    let path = Path::new(&binding.entry.path);
    let Some(actual) = capture_identity(path)? else {
        return Ok(());
    };
    compare_file_identity(actual, required_identity(&binding.entry)?)?;
    let target = std::fs::read_link(path).map_err(PurgeFinalizerError::io)?;
    if target.to_str() != binding.target.as_deref() {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    Ok(())
}

fn compare_file_identity(
    actual: FsIdentity,
    expected: FsIdentity,
) -> Result<(), PurgeFinalizerError> {
    if actual != expected || actual.links != 1 {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    Ok(())
}

fn compare_directory_identity(
    actual: FsIdentity,
    expected: FsIdentity,
) -> Result<(), PurgeFinalizerError> {
    if actual.kind != EntryKind::Directory
        || actual.device != expected.device
        || actual.inode != expected.inode
        || actual.uid != expected.uid
        || actual.mode != expected.mode
        || actual.links == 0
    {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    Ok(())
}

fn required_identity(binding: &EntryBinding) -> Result<FsIdentity, PurgeFinalizerError> {
    binding.identity.ok_or(PurgeFinalizerError::MarkerInvalid)
}

fn remove_bound_entry(binding: &EntryBinding) -> Result<(), PurgeFinalizerError> {
    let path = Path::new(&binding.path);
    if capture_identity(path)?.is_some() {
        validate_optional_bound_entry(binding)?;
        std::fs::remove_file(path).map_err(PurgeFinalizerError::io)?;
    }
    require_absent(path)?;
    sync_parent_directory(path)
}

fn remove_bound_symlink(binding: &SymlinkBinding) -> Result<(), PurgeFinalizerError> {
    let path = Path::new(&binding.entry.path);
    if capture_identity(path)?.is_some() {
        validate_optional_bound_symlink(binding)?;
        std::fs::remove_file(path).map_err(PurgeFinalizerError::io)?;
    }
    require_absent(path)?;
    sync_parent_directory(path)
}

fn remove_bound_directory(binding: &EntryBinding) -> Result<(), PurgeFinalizerError> {
    let path = Path::new(&binding.path);
    if capture_identity(path)?.is_some() {
        validate_optional_bound_directory(binding)?;
        std::fs::remove_dir(path).map_err(PurgeFinalizerError::io)?;
    }
    require_absent(path)?;
    sync_parent_directory(path)
}

fn require_absent(path: &Path) -> Result<(), PurgeFinalizerError> {
    if capture_identity(path)?.is_some() {
        return Err(PurgeFinalizerError::DeleteReadbackFailed);
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), PurgeFinalizerError> {
    let parent = path.parent().ok_or(PurgeFinalizerError::FilesystemUnsafe)?;
    let Some(expected) = capture_identity(parent)? else {
        // Nested helper 的 parent version directory 可能已在上一次尝试中连同空目录
        // 删除；随后对该 directory binding 的 replay 会 fsync 仍存在的 bin parent。
        return Ok(());
    };
    if expected.kind != EntryKind::Directory || expected.links == 0 {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(PurgeFinalizerError::io)?;
    let metadata = directory.metadata().map_err(PurgeFinalizerError::io)?;
    let actual = FsIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o7777,
        links: metadata.nlink(),
        kind: if metadata.file_type().is_dir() {
            EntryKind::Directory
        } else {
            return Err(PurgeFinalizerError::FilesystemUnsafe);
        },
    };
    compare_directory_identity(actual, expected)?;
    directory.sync_all().map_err(PurgeFinalizerError::io)
}

fn require_socket_absent(path: &Path) -> Result<(), PurgeFinalizerError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(PurgeFinalizerError::DaemonStillRunning),
        Err(error) => Err(PurgeFinalizerError::io(error)),
    }
}

fn hash_regular_file(
    path: &Path,
    expected_identity: Option<FsIdentity>,
) -> Result<[u8; 32], PurgeFinalizerError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(PurgeFinalizerError::io)?;
    let metadata = file.metadata().map_err(PurgeFinalizerError::io)?;
    let actual = FsIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o7777,
        links: metadata.nlink(),
        kind: EntryKind::File,
    };
    if metadata.uid() != unsafe { libc::geteuid() }
        || !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || expected_identity.is_some_and(|expected| expected != actual)
    {
        return Err(PurgeFinalizerError::FilesystemUnsafe);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(PurgeFinalizerError::io)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn machine_accounts() -> [&'static str; 5] {
    [
        MACHINE_DATA_SIGN_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        KEY_DIRECTORY_GUARD_ACCOUNT,
        MACHINE_ROOT_SIGN_ACCOUNT,
    ]
}

fn load_secret_hash(
    key_store: &dyn KeyStore,
    account: &str,
) -> Result<Option<[u8; 32]>, PurgeFinalizerError> {
    Ok(key_store
        .load(account)?
        .map(|secret| sha256(secret.expose_secret())))
}

fn delete_key_exact(key_store: &dyn KeyStore, account: &str) -> Result<(), PurgeFinalizerError> {
    key_store.delete(account)?;
    if key_store.load(account)?.is_some() {
        return Err(PurgeFinalizerError::DeleteReadbackFailed);
    }
    Ok(())
}

fn load_marker(key_store: &dyn KeyStore) -> Result<Option<PurgeMarkerV1>, PurgeFinalizerError> {
    let Some(secret) = key_store.load(PURGE_FINALIZER_MARKER_ACCOUNT)? else {
        return Ok(None);
    };
    let bytes = secret.expose_secret();
    if bytes.is_empty() || bytes.len() > MAX_MARKER_BYTES {
        return Err(PurgeFinalizerError::MarkerInvalid);
    }
    let marker: PurgeMarkerV1 =
        serde_json::from_slice(bytes).map_err(|_| PurgeFinalizerError::MarkerInvalid)?;
    let canonical = encode_marker(&marker)?;
    if canonical != bytes {
        return Err(PurgeFinalizerError::MarkerInvalid);
    }
    validate_marker(&marker)?;
    Ok(Some(marker))
}

fn store_marker_exact(
    key_store: &dyn KeyStore,
    marker: &PurgeMarkerV1,
) -> Result<(), PurgeFinalizerError> {
    let bytes = encode_marker(marker)?;
    key_store.store(
        PURGE_FINALIZER_MARKER_ACCOUNT,
        &SecretBytes::new(bytes.clone()),
    )?;
    let persisted = key_store
        .load(PURGE_FINALIZER_MARKER_ACCOUNT)?
        .ok_or(PurgeFinalizerError::MarkerPersistence)?;
    if persisted.expose_secret() != bytes {
        return Err(PurgeFinalizerError::MarkerPersistence);
    }
    Ok(())
}

fn delete_marker_exact(key_store: &dyn KeyStore) -> Result<(), PurgeFinalizerError> {
    key_store.delete(PURGE_FINALIZER_MARKER_ACCOUNT)?;
    if key_store.load(PURGE_FINALIZER_MARKER_ACCOUNT)?.is_some() {
        return Err(PurgeFinalizerError::MarkerPersistence);
    }
    Ok(())
}

fn encode_marker(marker: &PurgeMarkerV1) -> Result<Vec<u8>, PurgeFinalizerError> {
    let bytes = serde_json::to_vec(marker).map_err(|_| PurgeFinalizerError::MarkerInvalid)?;
    if bytes.is_empty() || bytes.len() > MAX_MARKER_BYTES {
        return Err(PurgeFinalizerError::MarkerInvalid);
    }
    Ok(bytes)
}

fn runtime_artifact_paths(runtime_db: &Path) -> [PathBuf; 3] {
    [
        runtime_db.to_path_buf(),
        sidecar(runtime_db, "-wal"),
        sidecar(runtime_db, "-shm"),
    ]
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn path_string(path: &Path) -> Result<String, PurgeFinalizerError> {
    path.to_str()
        .filter(|value| !value.is_empty() && value.len() <= 4096 && !value.contains('\0'))
        .map(ToOwned::to_owned)
        .ok_or(PurgeFinalizerError::NamespaceInvalid)
}

fn is_clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        && path_string(path).is_ok()
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !matches!(version, "." | "..")
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn lock_finalizer() -> Result<MutexGuard<'static, ()>, PurgeFinalizerError> {
    FINALIZER_IO
        .lock()
        .map_err(|_| PurgeFinalizerError::Synchronization)
}

#[derive(Error)]
pub enum PurgeFinalizerError {
    #[error("purge finalizer authorization is invalid")]
    AuthorizationInvalid,
    #[error("purge finalizer running identity is unavailable")]
    IdentityUnavailable,
    #[error("purge finalizer plan does not match this stable daemon")]
    PlanMismatch,
    #[error("purge finalizer marker is missing")]
    MarkerMissing,
    #[error("purge finalizer marker is invalid")]
    MarkerInvalid,
    #[error("purge finalizer marker conflicts with another plan")]
    MarkerConflict,
    #[error("purge finalizer marker is reserved but not authorized")]
    MarkerUnauthorized,
    #[error("purge finalizer marker exact readback failed")]
    MarkerPersistence,
    #[error("purge finalizer stable namespace is invalid")]
    NamespaceInvalid,
    #[error("purge finalizer installed helper does not match its attestation")]
    HelperMismatch,
    #[error("purge finalizer install layout is invalid")]
    InstallLayoutInvalid,
    #[error("purge finalizer encountered an unsafe filesystem entry")]
    FilesystemUnsafe,
    #[error("purge finalizer daemon socket is still present")]
    DaemonStillRunning,
    #[error("purge finalizer stopped-daemon permit does not match the stable namespace")]
    StoppedPermitMismatch,
    #[error("purge finalizer key item conflicts with its frozen binding")]
    KeyItemConflict,
    #[error("purge finalizer StorageKEK was absent before marker creation")]
    StorageKekMissing,
    #[error("purge finalizer StorageKEK conflicts with its frozen binding")]
    StorageKekConflict,
    #[error("purge finalizer deletion readback failed")]
    DeleteReadbackFailed,
    #[error("purge finalizer marker-missing terminal proof failed")]
    TerminalProofFailed,
    #[error("purge finalizer synchronization failed")]
    Synchronization,
    #[error("purge finalizer keystore failed: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("purge finalizer singleton validation failed")]
    Singleton(#[from] SingletonError),
    #[error("purge finalizer filesystem operation failed")]
    Io(#[source] io::Error),
    #[error("purge finalizer injected crash")]
    InjectedCrash,
}

impl PurgeFinalizerError {
    fn io(source: io::Error) -> Self {
        Self::Io(source)
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthorizationInvalid => "daemon.purge.authorization_invalid",
            Self::IdentityUnavailable => "daemon.purge.identity_unavailable",
            Self::PlanMismatch => "daemon.purge.plan_mismatch",
            Self::MarkerMissing => "daemon.purge.marker_missing",
            Self::MarkerInvalid => "daemon.purge.marker_invalid",
            Self::MarkerConflict => "daemon.purge.marker_conflict",
            Self::MarkerUnauthorized => "daemon.purge.marker_unauthorized",
            Self::MarkerPersistence => "daemon.purge.marker_persistence_failed",
            Self::NamespaceInvalid => "daemon.purge.namespace_invalid",
            Self::HelperMismatch => "daemon.purge.helper_mismatch",
            Self::InstallLayoutInvalid => "daemon.purge.install_layout_invalid",
            Self::FilesystemUnsafe => "daemon.purge.filesystem_unsafe",
            Self::DaemonStillRunning => "daemon.purge.daemon_still_running",
            Self::StoppedPermitMismatch => "daemon.purge.stopped_permit_mismatch",
            Self::KeyItemConflict => "daemon.purge.key_item_conflict",
            Self::StorageKekMissing => "daemon.purge.storage_kek_missing",
            Self::StorageKekConflict => "daemon.purge.storage_kek_conflict",
            Self::DeleteReadbackFailed => "daemon.purge.delete_readback_failed",
            Self::TerminalProofFailed => "daemon.purge.terminal_proof_failed",
            Self::Synchronization => "daemon.purge.synchronization_failed",
            Self::KeyStore(error) => error.code(),
            Self::Singleton(error) => error.code(),
            Self::Io(_) => "daemon.purge.io_failed",
            Self::InjectedCrash => "daemon.purge.injected_crash",
        }
    }
}

impl fmt::Debug for PurgeFinalizerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PurgeFinalizerError")
            .field("code", &self.code())
            .finish()
    }
}

#[cfg(test)]
#[path = "purge_finalizer_tests.rs"]
mod tests;
