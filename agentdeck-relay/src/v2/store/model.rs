//! Relay v2 store 的平台无关数据模型、配额与测试注入点。

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::frame::{Publish, RetireMachine};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, GrantSerial, LinkGeneration, MAX_FRAME_BYTES, MachineRouteId,
    OpaqueRouteFrame, PublicKeyBytes, RelayFrameBody, RelayGrant, RelayServerId, RootKeyId,
    SignedCertificate, StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch, encode,
};
use thiserror::Error;

pub const MAX_CONTROL_BLOB_BYTES: usize = 64 * 1024;
pub const REPLAY_PAGE_HARD_MAX_FRAMES: u64 = 64;
pub const REPLAY_PAGE_HARD_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const PUBLISH_OUTER_OVERHEAD_BYTES: usize = 53;
pub const MAX_ENROLLMENT_CODES: u64 = 4_096;
pub const MAX_STREAMS_PER_MACHINE: u64 = 4_096;
pub const MAX_STREAMS_GLOBAL: u64 = 65_536;
pub const MAX_SUBSCRIPTIONS_PER_DEVICE: u64 = 4_096;
pub const MAX_SUBSCRIPTIONS_GLOBAL: u64 = 262_144;
pub const MAX_DEVICE_ROUTES_PER_MACHINE: u64 = 256;
pub const MAX_DEVICE_ROUTES_GLOBAL: u64 = 65_536;
pub const MAX_TERMINAL_BLOB_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataLimits {
    pub max_device_routes_per_machine: u64,
    pub max_device_routes_global: u64,
    pub max_streams_per_machine: u64,
    pub max_streams_global: u64,
    pub max_subscriptions_per_device: u64,
    pub max_subscriptions_global: u64,
}

impl Default for MetadataLimits {
    fn default() -> Self {
        Self {
            max_device_routes_per_machine: MAX_DEVICE_ROUTES_PER_MACHINE,
            max_device_routes_global: MAX_DEVICE_ROUTES_GLOBAL,
            max_streams_per_machine: MAX_STREAMS_PER_MACHINE,
            max_streams_global: MAX_STREAMS_GLOBAL,
            max_subscriptions_per_device: MAX_SUBSCRIPTIONS_PER_DEVICE,
            max_subscriptions_global: MAX_SUBSCRIPTIONS_GLOBAL,
        }
    }
}

impl MetadataLimits {
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.max_device_routes_per_machine == 0
            || self.max_device_routes_per_machine > MAX_DEVICE_ROUTES_PER_MACHINE
            || self.max_device_routes_global == 0
            || self.max_device_routes_global > MAX_DEVICE_ROUTES_GLOBAL
            || self.max_device_routes_per_machine > self.max_device_routes_global
            || self.max_streams_per_machine == 0
            || self.max_streams_per_machine > MAX_STREAMS_PER_MACHINE
            || self.max_streams_global == 0
            || self.max_streams_global > MAX_STREAMS_GLOBAL
            || self.max_streams_per_machine > self.max_streams_global
            || self.max_subscriptions_per_device == 0
            || self.max_subscriptions_per_device > MAX_SUBSCRIPTIONS_PER_DEVICE
            || self.max_subscriptions_global == 0
            || self.max_subscriptions_global > MAX_SUBSCRIPTIONS_GLOBAL
            || self.max_subscriptions_per_device > self.max_subscriptions_global
        {
            return Err(StoreError::InvalidValue {
                field: "metadata_limits",
                reason: "metadata counts must be non-zero, ordered, and within hard maxima",
            });
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RelayV2StoreConfig {
    pub storage_path: PathBuf,
    pub retention: RetentionLimits,
    pub max_enrollment_codes: u64,
    pub metadata_limits: MetadataLimits,
    pub clock: Arc<dyn Clock>,
    pub disk_space_probe: Arc<dyn DiskSpaceProbe>,
    pub fault_injector: Arc<dyn FaultInjector>,
}

impl RelayV2StoreConfig {
    pub fn new(storage_path: PathBuf) -> Self {
        Self {
            storage_path,
            retention: RetentionLimits::default(),
            max_enrollment_codes: MAX_ENROLLMENT_CODES,
            metadata_limits: MetadataLimits::default(),
            clock: Arc::new(SystemClock),
            disk_space_probe: Arc::new(SystemDiskSpaceProbe),
            fault_injector: Arc::new(NoFaults),
        }
    }

    pub fn with_retention(mut self, retention: RetentionLimits) -> Self {
        self.retention = retention;
        self
    }

    pub fn with_max_enrollment_codes(mut self, max_enrollment_codes: u64) -> Self {
        self.max_enrollment_codes = max_enrollment_codes;
        self
    }

    pub fn with_metadata_limits(mut self, limits: MetadataLimits) -> Self {
        self.metadata_limits = limits;
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_disk_space_probe(mut self, probe: Arc<dyn DiskSpaceProbe>) -> Self {
        self.disk_space_probe = probe;
        self
    }

    pub fn with_fault_injector(mut self, injector: Arc<dyn FaultInjector>) -> Self {
        self.fault_injector = injector;
        self
    }
}

impl fmt::Debug for RelayV2StoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayV2StoreConfig")
            .field("storage_path", &self.storage_path)
            .field("retention", &self.retention)
            .field("max_enrollment_codes", &self.max_enrollment_codes)
            .field("metadata_limits", &self.metadata_limits)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSnapshot {
    pub schema_family: String,
    pub schema_version: u32,
    pub schema_signature: [u8; 32],
    pub relay_server_id: RelayServerId,
    pub table_names: Vec<String>,
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: bool,
    pub busy_timeout_ms: u64,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("production storage path must be absolute")]
    PathNotAbsolute,
    #[error("production storage path must be lexically canonical")]
    PathNotCanonical,
    #[error("symbolic link is not allowed for Relay storage: {path}")]
    SymlinkRejected { path: PathBuf },
    #[error("insecure permissions on {path}: expected at most {expected:o}, found {actual:o}")]
    InsecurePermissions {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("unexpected owner on {path}: expected uid {expected}, found {actual}")]
    UnexpectedOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("Relay storage path is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("relay schema version {found} is newer than supported version {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("legacy Relay v1 schema requires an explicit reset")]
    LegacyV1ResetRequired,
    #[error("unknown or corrupt relay schema")]
    UnknownOrCorruptSchema,
    #[error("Relay store changed while its schema was being inspected")]
    SchemaInspectionRaced,
    #[error("SQLite pragma {name} read back {actual}, expected {expected}")]
    PragmaMismatch {
        name: &'static str,
        expected: String,
        actual: String,
    },
    #[error("Relay store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Relay store SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Relay store worker is unavailable")]
    WorkerUnavailable,
    #[error("Relay store worker command queue is full")]
    WorkerBusy,
    #[error("Relay store worker stopped before replying")]
    WorkerStopped,
    #[error("Relay trust mutation {operation} may have committed before its result was lost")]
    CommitOutcomeUnknown { operation: &'static str },
    #[error("Relay store path is already open in this process")]
    StoreAlreadyOpen,
    #[error("Relay trust mutations are owned by the authorization coordinator")]
    AuthorizationOwned,
    #[error("invalid store value for {field}: {reason}")]
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    #[error("injected Relay store fault at {0:?}")]
    InjectedFault(FaultPoint),
    #[error("machine route was not found")]
    MachineNotFound,
    #[error("device grant was not found")]
    GrantNotFound,
    #[error("stream route was not found")]
    StreamNotFound,
    #[error("stream route is not owned by the authenticated machine")]
    StreamOwnerConflict,
    #[error("stream route is already bound to a different generation")]
    StreamBindingConflict,
    #[error("monotonic value for {field} would roll back")]
    MonotonicRollback { field: &'static str },
    #[error("same monotonic value for {field} has different canonical bytes")]
    IdempotencyConflict { field: &'static str },
    #[error("stream sequence mismatch: expected {expected}, found {found}")]
    SequenceConflict { expected: u64, found: u64 },
    #[error("enrollment code was not found")]
    EnrollmentCodeNotFound,
    #[error("enrollment code expired")]
    EnrollmentCodeExpired,
    #[error("enrollment code was already consumed by a different request")]
    EnrollmentCodeConflict,
    #[error("machine root fingerprint confirmation does not match")]
    RootFingerprintMismatch,
    #[error("device grant has been revoked")]
    Revoked,
    #[error("authentication state does not match the persisted {field}")]
    AuthenticationMismatch { field: &'static str },
    #[error("retention quota exceeded: {scope}")]
    QuotaExceeded { scope: &'static str },
    #[error("available disk space is below the configured safety reserve")]
    DiskSpaceLow,
    #[error("Relay frame exceeds the 4 MiB limit")]
    FrameTooLarge,
    #[error("replay gap: needed sequence {needed}, oldest retained sequence {oldest}")]
    ReplayGap { needed: u64, oldest: u64 },
    #[error("invalid replay continuation")]
    InvalidReplayCursor,
    #[error("next replay frame exceeds the caller page budget")]
    ReplayPageLimitExceeded,
}

impl StoreError {
    /// Store 内部诊断码；network router 必须按操作上下文映射到 Relay v2 固定 failure code。
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::PathNotAbsolute
            | Self::PathNotCanonical
            | Self::SymlinkRejected { .. }
            | Self::InsecurePermissions { .. }
            | Self::UnexpectedOwner { .. }
            | Self::NotRegularFile { .. } => "relay.store.path_invalid",
            Self::SchemaTooNew { .. } => "relay.store.schema_too_new",
            Self::LegacyV1ResetRequired => "relay.store.legacy_reset_required",
            Self::UnknownOrCorruptSchema => "relay.store.schema_corrupt",
            Self::PragmaMismatch { .. } => "relay.store.pragma_mismatch",
            Self::Io(_)
            | Self::Sqlite(_)
            | Self::SchemaInspectionRaced
            | Self::WorkerUnavailable
            | Self::StoreAlreadyOpen
            | Self::AuthorizationOwned
            | Self::WorkerStopped
            | Self::CommitOutcomeUnknown { .. } => "relay.store.unavailable",
            Self::WorkerBusy => "relay.store.busy",
            Self::InvalidValue { .. } => "relay.store.invalid_value",
            Self::InjectedFault(_) => "relay.store.injected_fault",
            Self::MachineNotFound | Self::GrantNotFound | Self::StreamNotFound => {
                "relay.store.not_found"
            }
            Self::StreamOwnerConflict => "relay.route.not_found",
            Self::StreamBindingConflict
            | Self::IdempotencyConflict { .. }
            | Self::EnrollmentCodeConflict => "relay.store.conflict",
            Self::MonotonicRollback { .. } => "relay.store.stale",
            Self::SequenceConflict { .. } => "relay.stream.out_of_order",
            Self::EnrollmentCodeNotFound => "relay.store.enrollment_not_found",
            Self::EnrollmentCodeExpired => "relay.store.enrollment_expired",
            Self::RootFingerprintMismatch => "relay.store.confirmation_mismatch",
            Self::Revoked => "relay.auth.revoked",
            Self::AuthenticationMismatch { .. } => "relay.auth.invalid_grant",
            Self::QuotaExceeded { .. } => "relay.quota.exceeded",
            Self::DiskSpaceLow => "relay.disk.low",
            Self::FrameTooLarge => "relay.frame.too_large",
            Self::ReplayGap { .. } => "relay.replay.gap",
            Self::InvalidReplayCursor => "relay.replay.cursor_invalid",
            Self::ReplayPageLimitExceeded => "relay.quota.exceeded",
        }
    }
}

pub fn validate_store_path(path: &Path) -> Result<(), StoreError> {
    if !path.is_absolute() {
        return Err(StoreError::PathNotAbsolute);
    }
    let normalized = path.components().collect::<PathBuf>();
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || normalized.as_os_str() != path.as_os_str()
    {
        return Err(StoreError::PathNotCanonical);
    }
    Ok(())
}

/// macOS 的 `/var` 是系统提供且不可由普通用户替换的 `/private/var` alias。Store 打开、
/// process-local ownership key 与后续路径检查必须共用这一规范化，避免同一 DB 双 owner。
#[cfg(target_os = "macos")]
pub(crate) fn normalize_platform_root_alias(path: &Path) -> PathBuf {
    match path.strip_prefix("/var") {
        Ok(suffix) => Path::new("/private/var").join(suffix),
        Err(_) => path.to_path_buf(),
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn normalize_platform_root_alias(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionLimits {
    pub max_frames_per_stream: u64,
    pub max_bytes_per_stream: u64,
    pub max_age_ms: u64,
    pub max_bytes_per_machine: u64,
    pub max_bytes_global: u64,
    pub replay_page_max_frames: u64,
    pub replay_page_max_bytes: u64,
    pub disk_reserve_bytes: u64,
    pub disk_reserve_percent: u8,
}

impl Default for RetentionLimits {
    fn default() -> Self {
        Self {
            max_frames_per_stream: 2_000,
            max_bytes_per_stream: 64 * 1024 * 1024,
            max_age_ms: 24 * 60 * 60 * 1_000,
            max_bytes_per_machine: 512 * 1024 * 1024,
            max_bytes_global: 4 * 1024 * 1024 * 1024,
            replay_page_max_frames: REPLAY_PAGE_HARD_MAX_FRAMES,
            replay_page_max_bytes: REPLAY_PAGE_HARD_MAX_BYTES,
            disk_reserve_bytes: 512 * 1024 * 1024,
            disk_reserve_percent: 5,
        }
    }
}

impl RetentionLimits {
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.disk_reserve_percent > 100 {
            return Err(StoreError::InvalidValue {
                field: "retention.disk_reserve_percent",
                reason: "percentage must be in 0...100",
            });
        }
        if self.max_frames_per_stream == 0
            || self.max_bytes_per_stream == 0
            || self.max_age_ms == 0
            || self.max_bytes_per_machine == 0
            || self.max_bytes_global == 0
            || self.replay_page_max_frames == 0
            || self.replay_page_max_frames > REPLAY_PAGE_HARD_MAX_FRAMES
            || self.replay_page_max_bytes < MAX_FRAME_BYTES as u64
            || self.replay_page_max_bytes > REPLAY_PAGE_HARD_MAX_BYTES
        {
            return Err(StoreError::InvalidValue {
                field: "retention",
                reason: "retention and replay limits must be non-zero and within hard maxima",
            });
        }
        Ok(())
    }

    pub fn disk_reserve_for(&self, total_bytes: u64) -> u64 {
        let percentage = ((u128::from(total_bytes) * u128::from(self.disk_reserve_percent)) / 100)
            .min(u128::from(u64::MAX)) as u64;
        self.disk_reserve_bytes.max(percentage)
    }
}

pub trait Clock: Send + Sync + 'static {
    fn now_ms(&self) -> Result<u64, StoreError>;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> Result<u64, StoreError> {
        let elapsed =
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| StoreError::InvalidValue {
                    field: "clock",
                    reason: "system clock is before Unix epoch",
                })?;
        u64::try_from(elapsed.as_millis()).map_err(|_| StoreError::InvalidValue {
            field: "clock",
            reason: "Unix timestamp does not fit u64 milliseconds",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpace {
    pub available_bytes: u64,
    pub total_bytes: u64,
}

pub trait DiskSpaceProbe: Send + Sync + 'static {
    fn space(&self, storage_path: &std::path::Path) -> Result<DiskSpace, StoreError>;
}

#[derive(Debug, Default)]
pub struct SystemDiskSpaceProbe;

impl DiskSpaceProbe for SystemDiskSpaceProbe {
    fn space(&self, storage_path: &std::path::Path) -> Result<DiskSpace, StoreError> {
        Ok(DiskSpace {
            available_bytes: fs2::available_space(storage_path)?,
            total_bytes: fs2::total_space(storage_path)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    RegisterMachineBeforeCommit,
    RegisterMachineAfterCommit,
    InstallGrantBeforeCommit,
    MachineLinkAuthBeforeCommit,
    MachineLinkAuthAfterCommit,
    DeviceAuthBeforeConfirm,
    RegisterStreamBeforeCommit,
    PublishBeforeCommit,
    PublishAfterCommit,
    SubscribeBeforeCommit,
    AckBeforeCommit,
    ReplayAfterRead,
    RevokeBeforeCommit,
    RevokeAfterCommit,
    PurgeBeforeCommit,
    PurgeAfterCommit,
    InstallGrantAfterCommit,
    MaintenanceBeforeCommit,
    /// 测试专用生命周期栅栏：shutdown reply 已发送、worker 函数尚未返回。
    ShutdownAfterReply,
}

pub trait FaultInjector: Send + Sync + 'static {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError>;
}

#[derive(Debug, Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn check(&self, _point: FaultPoint) -> Result<(), StoreError> {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentCodeSeed {
    pub code_hash: [u8; 32],
    pub expires_at_ms: u64,
}

impl fmt::Debug for EnrollmentCodeSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentCodeSeed")
            .field("code_hash", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RegisterMachine {
    pub code_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub response_blob: Vec<u8>,
    pub receipt_hash: [u8; 32],
    pub machine_route: MachineRouteId,
    pub root_pubkey: PublicKeyBytes,
    pub link_cert: SignedCertificate,
    pub data_cert: SignedCertificate,
    pub link_cert_hash: [u8; 32],
    pub data_cert_hash: [u8; 32],
}

impl fmt::Debug for RegisterMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisterMachine")
            .field("machine", &self.machine_route.redacted())
            .field("enrollment_material", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MachineRecord {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    pub highest_link_generation: LinkGeneration,
    pub response_blob: Vec<u8>,
    pub receipt_hash: [u8; 32],
    pub duplicate: bool,
}

impl fmt::Debug for MachineRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineRecord")
            .field("relay_server", &self.relay_server_id.redacted())
            .field("machine", &self.machine_route.redacted())
            .field("trust_epoch", &self.trust_epoch.value())
            .field(
                "highest_link_generation",
                &self.highest_link_generation.value(),
            )
            .field("duplicate", &self.duplicate)
            .field("receipt", &"<redacted>")
            .finish()
    }
}

/// Relay 鉴权所需的最小 machine trust 快照。只包含公开验签材料与单调状态，
/// 不包含任何 endpoint 私钥、业务权限或对称 key。
#[derive(Clone, PartialEq, Eq)]
pub struct MachineTrustView {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub root_key_id: RootKeyId,
    pub root_pubkey: PublicKeyBytes,
    pub trust_epoch: TrustEpoch,
    pub highest_link_generation: LinkGeneration,
    pub link_cert_hash: [u8; 32],
    pub retired: bool,
    pub retirement_terminal: Option<RetirementTerminalView>,
}

impl fmt::Debug for MachineTrustView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineTrustView")
            .field("machine", &self.machine_route.redacted())
            .field("trust_epoch", &self.trust_epoch.value())
            .field(
                "highest_link_generation",
                &self.highest_link_generation.value(),
            )
            .field("retired", &self.retired)
            .field("trust_material", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RetirementTerminalView {
    pub retirement_hash: [u8; 32],
    pub retirement_terminal_blob: Vec<u8>,
}

impl fmt::Debug for RetirementTerminalView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetirementTerminalView")
            .field("terminal_bytes", &self.retirement_terminal_blob.len())
            .field("terminal", &"<redacted>")
            .finish()
    }
}

/// 当前 device grant 与其 machine trust domain 的同一 worker 快照。
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceTrustView {
    pub machine: MachineTrustView,
    pub device_route: DeviceRouteId,
    pub auth_pubkey: PublicKeyBytes,
    pub auth_fingerprint: [u8; 32],
    pub grant_serial: GrantSerial,
    pub grant_hash: [u8; 32],
    pub revoked: bool,
    pub revocation_terminal: Option<RevocationTerminalView>,
}

impl fmt::Debug for DeviceTrustView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceTrustView")
            .field("machine", &self.machine.machine_route.redacted())
            .field("device", &self.device_route.redacted())
            .field("grant_serial", &self.grant_serial.value())
            .field("revoked", &self.revoked)
            .field("trust_material", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RevocationTerminalView {
    pub revocation_hash: [u8; 32],
    pub signed_revocation_blob: Vec<u8>,
}

impl fmt::Debug for RevocationTerminalView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevocationTerminalView")
            .field("terminal_bytes", &self.signed_revocation_blob.len())
            .field("terminal", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CommitMachineLinkAuth {
    pub machine_route: MachineRouteId,
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    pub generation: LinkGeneration,
    pub cert_hash: [u8; 32],
}

impl fmt::Debug for CommitMachineLinkAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitMachineLinkAuth")
            .field("machine", &self.machine_route.redacted())
            .field("generation", &self.generation.value())
            .field("trust_material", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MachineLinkAuthCommit {
    pub machine_route: MachineRouteId,
    pub generation: LinkGeneration,
    pub cert_hash: [u8; 32],
    pub duplicate: bool,
}

impl fmt::Debug for MachineLinkAuthCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineLinkAuthCommit")
            .field("machine", &self.machine_route.redacted())
            .field("generation", &self.generation.value())
            .field("duplicate", &self.duplicate)
            .field("cert_hash", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConfirmDeviceAuth {
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub grant_hash: [u8; 32],
    pub auth_pubkey: PublicKeyBytes,
    pub auth_fingerprint: [u8; 32],
}

impl fmt::Debug for ConfirmDeviceAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmDeviceAuth")
            .field("machine", &self.machine_route.redacted())
            .field("device", &self.device_route.redacted())
            .field("grant_serial", &self.grant_serial.value())
            .field("trust_material", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallGrantRecord {
    pub grant: RelayGrant,
    pub grant_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantCommit {
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub grant_hash: [u8; 32],
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRegistration {
    pub machine_route: MachineRouteId,
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRecord {
    pub machine_route: MachineRouteId,
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub high_water_seq: Option<u64>,
    pub oldest_seq: Option<u64>,
    pub retained_bytes: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistPublish {
    pub machine_route: MachineRouteId,
    pub frame: OpaqueRouteFrame,
}

impl PersistPublish {
    pub fn from_publish(machine_route: MachineRouteId, publish: Publish) -> Self {
        Self {
            machine_route,
            frame: OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Publish(publish),
            },
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StoreError> {
        if self.frame.version != RELAY_PROTOCOL_VERSION
            || !matches!(&self.frame.body, RelayFrameBody::Publish(_))
        {
            return Err(StoreError::InvalidValue {
                field: "publish.frame",
                reason: "expected a Relay v2 Publish outer frame",
            });
        }
        let encoded = encode(&self.frame);
        if encoded.len() > MAX_FRAME_BYTES {
            Err(StoreError::FrameTooLarge)
        } else {
            Ok(encoded)
        }
    }

    pub fn validate_queue_payload(&self) -> Result<(), StoreError> {
        if self.frame.version != RELAY_PROTOCOL_VERSION {
            return Err(StoreError::InvalidValue {
                field: "publish.frame",
                reason: "expected Relay v2 protocol version",
            });
        }
        let RelayFrameBody::Publish(publish) = &self.frame.body else {
            return Err(StoreError::InvalidValue {
                field: "publish.frame",
                reason: "expected a Relay v2 Publish outer frame",
            });
        };
        let encoded_size = publish
            .sealed_blob
            .0
            .len()
            .checked_add(PUBLISH_OUTER_OVERHEAD_BYTES)
            .ok_or(StoreError::FrameTooLarge)?;
        if encoded_size > MAX_FRAME_BYTES {
            Err(StoreError::FrameTooLarge)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishDisposition {
    Inserted,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishCommit {
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub stream_seq: u64,
    pub frame_hash: [u8; 32],
    pub size: u64,
    pub disposition: PublishDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistSubscription {
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub start: StreamCursor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionLease {
    pub start: StreamCursor,
    /// 与 subscription upsert 在同一 SQLite transaction 内读取并冻结的 high-water。
    /// Core 只能重放到该边界，避免随后提交的 live publish 越过 ReplayComplete。
    pub replay_through: StreamCursor,
    pub ack: Option<u64>,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistUnsubscribe {
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsubscribeCommit {
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayPosition {
    Start(StreamCursor),
    Continue(ReplayCursor),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPageRequest {
    pub machine_route: MachineRouteId,
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub position: ReplayPosition,
    /// 本次调用方可原子接纳的 page 上限；必须非零且不超过 Store hard maximum。
    pub page_max_frames: u64,
    pub page_max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayFrame {
    pub stream_seq: u64,
    pub frame_hash: [u8; 32],
    pub sealed_blob: Vec<u8>,
    pub size: u64,
    pub received_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPage {
    pub frames: Vec<ReplayFrame>,
    pub replay_through: StreamCursor,
    pub next: Option<ReplayCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCursor {
    pub(crate) stream_route: StreamRouteId,
    pub(crate) generation: StreamGenerationId,
    pub(crate) next_seq: u64,
    pub(crate) through_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistAck {
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub up_to_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistRevocation {
    pub revocation: DeviceRevocation,
    pub revocation_hash: [u8; 32],
    pub signed_revocation_blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCommit {
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub revocation_hash: [u8; 32],
    pub signed_revocation_blob: Vec<u8>,
    pub duplicate: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PurgeMachine {
    pub machine_route: MachineRouteId,
    pub expected_root_fingerprint: [u8; 32],
}

impl fmt::Debug for PurgeMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PurgeMachine")
            .field("machine", &self.machine_route.redacted())
            .field("root_fingerprint", &"<redacted>")
            .finish()
    }
}

pub const MAX_MACHINE_INVENTORY_PAGE: usize = 128;

#[derive(Clone, PartialEq, Eq)]
pub struct MachineInventoryQuery {
    pub after: Option<MachineRouteId>,
    pub limit: usize,
}

impl fmt::Debug for MachineInventoryQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineInventoryQuery")
            .field("has_cursor", &self.after.is_some())
            .field("limit", &self.limit)
            .finish()
    }
}

impl Default for MachineInventoryQuery {
    fn default() -> Self {
        Self {
            after: None,
            limit: MAX_MACHINE_INVENTORY_PAGE,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MachineInventoryEntry {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub root_fingerprint: [u8; 32],
    pub trust_epoch: TrustEpoch,
    pub retired: bool,
}

impl fmt::Debug for MachineInventoryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineInventoryEntry")
            .field("relay_server", &self.relay_server_id.redacted())
            .field("machine", &self.machine_route.redacted())
            .field("root_fingerprint", &"<redacted>")
            .field("trust_epoch", &self.trust_epoch.value())
            .field("retired", &self.retired)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct MachineInventoryPage {
    pub entries: Vec<MachineInventoryEntry>,
    pub next_after: Option<MachineRouteId>,
}

impl fmt::Debug for MachineInventoryPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineInventoryPage")
            .field("entry_count", &self.entries.len())
            .field("has_next", &self.next_after.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MachineReadback {
    pub machine: MachineInventoryEntry,
    pub data: PurgeReadback,
}

impl fmt::Debug for MachineReadback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineReadback")
            .field("machine", &self.machine)
            .field("data", &self.data)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MachineReadbackQuery {
    pub machine_route: MachineRouteId,
    pub expected_root_fingerprint: [u8; 32],
}

impl fmt::Debug for MachineReadbackQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineReadbackQuery")
            .field("machine", &self.machine_route.redacted())
            .field("root_fingerprint", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistRetirement {
    pub retirement: RetireMachine,
    pub retirement_hash: [u8; 32],
    pub retirement_terminal_blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetirementCommit {
    pub machine_route: MachineRouteId,
    pub trust_epoch: TrustEpoch,
    pub retirement_hash: [u8; 32],
    pub retirement_terminal_blob: Vec<u8>,
    pub readback: PurgeReadback,
    pub duplicate: bool,
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct PurgeReadback {
    pub active_machine_routes: u64,
    pub retired_tombstones: u64,
    pub device_grants: u64,
    pub revocations: u64,
    pub streams: u64,
    pub frames: u64,
    pub subscriptions: u64,
    pub retirement_hash: Option<[u8; 32]>,
    pub retirement_terminal_blob: Option<Vec<u8>>,
}

impl fmt::Debug for PurgeReadback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PurgeReadback")
            .field("active_machine_routes", &self.active_machine_routes)
            .field("retired_tombstones", &self.retired_tombstones)
            .field("device_grants", &self.device_grants)
            .field("revocations", &self.revocations)
            .field("streams", &self.streams)
            .field("frames", &self.frames)
            .field("subscriptions", &self.subscriptions)
            .field("has_retirement_hash", &self.retirement_hash.is_some())
            .field(
                "has_retirement_terminal",
                &self.retirement_terminal_blob.is_some(),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaintenanceReport {
    pub expired_frames: u64,
    pub expired_enrollment_codes: u64,
    pub ack_trimmed_frames: u64,
    pub quota_evicted_frames: u64,
}

pub fn sql_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidValue {
        field,
        reason: "value exceeds SQLite INTEGER range",
    })
}

pub const EMPTY_HIGH_WATER_TEXT: &str = "-1";

pub fn stream_seq_text(value: u64) -> String {
    format!("{value:020}")
}

pub fn stream_seq_from_text(value: String, field: &'static str) -> Result<u64, StoreError> {
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StoreError::InvalidValue {
            field,
            reason: "expected canonical zero-padded u64 text",
        });
    }
    value.parse::<u64>().map_err(|_| StoreError::InvalidValue {
        field,
        reason: "canonical sequence text exceeds u64",
    })
}

pub fn high_water_text(value: Option<u64>) -> String {
    value.map_or_else(|| EMPTY_HIGH_WATER_TEXT.to_owned(), stream_seq_text)
}

pub fn high_water_from_text(value: String, field: &'static str) -> Result<Option<u64>, StoreError> {
    if value == EMPTY_HIGH_WATER_TEXT {
        Ok(None)
    } else {
        stream_seq_from_text(value, field).map(Some)
    }
}

pub const fn monotonic_blob(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn monotonic_from_blob(bytes: Vec<u8>, field: &'static str) -> Result<u64, StoreError> {
    let value: [u8; 8] = bytes.try_into().map_err(|_| StoreError::InvalidValue {
        field,
        reason: "expected an 8-byte monotonic value",
    })?;
    Ok(u64::from_be_bytes(value))
}
